"""Bounded cohort archives and disk-backed exact reduction.

Schema2 indexes are small; each stream has a streamed JSONL shard index and
bounded JSON pages. No aggregate ledger byte cap. SQLite uses a fixed cache and
file-backed temporary sorting; retained protocol state inside replicas is still
linear in workload/state history and is not made constant-memory by this tool.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import stat

from cohort_metrics import ENDPOINT, SCHEMA, _request_key, _validate_request, identity, number, window_stability

FORMAT = "delugi-cohort-pages-v2"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_INDEX_LINE_BYTES = 4096
MAX_PAGE_ENTRIES = 1024
MAX_ROW_BYTES = 16 * 1024
STREAMS = ("requests", "outputs", "batches")


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(root, relative):
    if not isinstance(relative, str) or any(p in ("", ".", "..") for p in relative.split("/")):
        raise ValueError("archive path must be a confined relative file")
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in ("..", ".") for part in path.parts):
        raise ValueError("archive path must be a confined relative file")
    current = Path(root).resolve()
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("archive symlinks are forbidden")
    if not current.is_file():
        raise ValueError("archive entry is not a regular file")
    return current


def confined_open(root, relative):
    """Follow directory descriptors, never archive symlinks (including races)."""
    if not isinstance(relative, str) or relative.startswith("/") or any(p in ("", ".", "..") for p in relative.split("/")):
        raise ValueError("archive path must be a confined relative file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(Path(root).resolve(), flags | os.O_DIRECTORY)
    try:
        parts = relative.split("/")
        for position, part in enumerate(parts):
            next_descriptor = os.open(part, flags | (os.O_DIRECTORY if position < len(parts)-1 else 0), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("archive entry is not a regular file")
        result = os.fdopen(descriptor, "rb")
        descriptor = None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_bounded(source, limit):
    with source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("archive entry is not a regular file")
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ValueError("archive component exceeds bounded read limit")
    return data


def bounded_read(path, limit):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    return read_bounded(os.fdopen(descriptor, "rb"), limit)


class ShardedArchive:
    def __init__(self, index_path):
        self.path = Path(index_path)
        self.root = self.path.parent.resolve()
        raw_index = bounded_read(self.path, MAX_MANIFEST_BYTES)
        self.index_sha256 = hashlib.sha256(raw_index).hexdigest()
        self.index = json.loads(raw_index)
        if self.index.get("schema") != 2 or self.index.get("format") != FORMAT:
            raise ValueError("unknown sharded cohort schema")
        self.ledgers = {int(k): v for k, v in self.index["replicas"].items()}
        if not self.ledgers or len(self.ledgers) > 31 or len(self.ledgers) != len(self.index["replicas"]):
            raise ValueError("invalid archive replica population")

    def rows(self, replica, stream):
        descriptor = self.ledgers[replica]["streams"][stream]
        digest = hashlib.sha256()
        total = pages = byte_count = 0
        with confined_open(self.root, descriptor["path"]) as index:
            while True:
                line = index.readline(MAX_INDEX_LINE_BYTES + 1)
                if not line:
                    break
                if pages and total == descriptor["entries"]:
                    raise ValueError("page follows terminal shard")
                if len(line) > MAX_INDEX_LINE_BYTES or not line.endswith(b"\n"):
                    raise ValueError("oversized or truncated shard index line")
                digest.update(line)
                byte_count += len(line)
                shard = json.loads(line)
                if shard["offset"] != total:
                    raise ValueError("noncontiguous shard offsets")
                raw = read_bounded(confined_open(self.root, shard["path"]), MAX_PAGE_BYTES)
                if len(raw) != shard["bytes"] or hashlib.sha256(raw).hexdigest() != shard["sha256"]:
                    raise ValueError("cohort page digest/size differs")
                page = json.loads(raw)
                entries = page["entries"]
                if (page["replica"] != replica or page["total"] != descriptor["entries"]
                        or len(entries) != shard["entries"] or len(entries) > MAX_PAGE_ENTRIES
                        or page.get("manifest") != self.ledgers[replica].get("manifest")):
                    raise ValueError("page population or manifest differs")
                total += len(entries)
                pages += 1
                expected_next = total if total < descriptor["entries"] else None
                if (page["next_offset"] != expected_next or total > descriptor["entries"]
                        or (expected_next is not None and not entries)):
                    raise ValueError("page continuation differs from exact population")
                for row in entries:
                    if not isinstance(row, dict) or len(json.dumps(row, separators=(",", ":")).encode()) > MAX_ROW_BYTES:
                        raise ValueError("ledger row exceeds bounded object envelope")
                    yield row
        if (not pages or total != descriptor["entries"] or pages != descriptor["pages"] or byte_count != descriptor["bytes"]
                or digest.hexdigest() != descriptor["sha256"]):
            raise ValueError("stream index digest or population differs")


def collect_sharded(controller, snapshots, directory, warmup_seconds, measurement_seconds, frozen_at=None):
    """Archive one page at a time, replacing retained control bodies with refs."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=False)
    replicas = {}
    for replica, snapshot in sorted(snapshots.items()):
        destination = root / f"replica-{replica}"
        destination.mkdir()
        start = snapshot["load"]["start_elapsed_us"]
        metadata = {"batch_ready_precedes_materialization": False,
                    "batch_ready_boundary": "own-origin signed batch production; independently admitted request may materialize in another producer batch first",
                    "output_index_base": 1, "output_prefix_count": snapshot["executed_count"],
                    "window_start_us": start + round(warmup_seconds * 1_000_000),
                    "window_end_us": start + round((warmup_seconds + measurement_seconds) * 1_000_000),
                    "observed_us": (frozen_at or {}).get(replica) or snapshot["elapsed_us"],
                    "censor_boundary": "protocol quiescence", "streams": {}}
        for command, stream in (("cohort", "requests"), ("outputs", "outputs"), ("batches", "batches")):
            index_path = destination / (stream + ".index.jsonl")
            offset = pages = index_bytes = 0
            total = None
            index_hash = hashlib.sha256()
            with index_path.open("xb") as index:
                while True:
                    record = controller.request(replica, command, offset=offset, limit=MAX_PAGE_ENTRIES)
                    page = record["reply"]["data"]
                    entries = page["entries"]
                    if page["replica"] != replica or (total is not None and page["total"] != total):
                        raise AssertionError("ledger changed during frozen collection")
                    total = page["total"]
                    if len(entries) > MAX_PAGE_ENTRIES or offset + len(entries) > total:
                        raise AssertionError("page exceeds population or entry bound")
                    if command == "cohort" and offset == 0:
                        metadata["manifest"] = page.get("manifest")
                    if page.get("manifest") != metadata["manifest"]:
                        raise AssertionError("page manifest changed")
                    expected_next = offset + len(entries) if offset + len(entries) < total else None
                    if page["next_offset"] != expected_next or (expected_next is not None and not entries):
                        raise AssertionError("invalid ledger pagination")
                    if any(not isinstance(row, dict) or len(json.dumps(row, separators=(",", ":")).encode()) > MAX_ROW_BYTES for row in entries):
                        raise AssertionError("ledger row exceeds archive object envelope")
                    raw = (json.dumps(page, separators=(",", ":")) + "\n").encode()
                    if len(raw) > MAX_PAGE_BYTES:
                        raise AssertionError("ledger page exceeds archive byte envelope")
                    path = destination / f"{stream}-{pages:08d}.json"
                    with path.open("xb") as target:
                        target.write(raw)
                    descriptor = {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(),
                                  "bytes": len(raw), "entries": len(entries), "offset": offset}
                    line = (json.dumps(descriptor, separators=(",", ":")) + "\n").encode()
                    if len(line) > MAX_INDEX_LINE_BYTES:
                        raise AssertionError("shard index line exceeds bound")
                    index.write(line)
                    index_hash.update(line)
                    index_bytes += len(line)
                    pages += 1
                    offset += len(entries)
                    metadata["collected_us"] = max(metadata.get("collected_us", 0), page["elapsed_us"])
                    # Controller.commands holds this exact record object. It must
                    # retain a verifiable external reference, not another page copy.
                    record["reply"]["data"] = {"external_cohort_page": descriptor,
                                                 "archive": str(root), "replica": replica, "stream": stream}
                    controller.archive_record(record)
                    if expected_next is None:
                        break
            metadata["streams"][stream] = {"path": str(index_path.relative_to(root)),
                "sha256": index_hash.hexdigest(), "bytes": index_bytes, "pages": pages, "entries": total}
        replicas[str(replica)] = metadata
    manifest = {"schema": 2, "format": FORMAT, "replicas": replicas,
        "resource_contract": {"max_page_bytes": MAX_PAGE_BYTES, "max_page_entries": MAX_PAGE_ENTRIES,
            "max_index_line_bytes": MAX_INDEX_LINE_BYTES, "max_row_bytes": MAX_ROW_BYTES, "aggregate_byte_limit": None,
            "replica_retained_state": "runtime timing maps, protocol custody and output retain O(N) state; this archive bounds controller/verifier working memory"}}
    path = root / "index.json"
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("archive manifest exceeds bounded metadata size")
    path.write_bytes(raw)
    return ShardedArchive(path)


class CohortDatabase:
    """Exact reducer with a 16MiB SQLite page cache and disk-backed sorting."""
    def __init__(self, path, ledgers):
        self.path = Path(path)
        if self.path.exists():
            raise ValueError("derived cohort database must be new")
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA cache_size=-16384")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA mmap_size=0")
        self.db.executescript('''
          CREATE TABLE requests(id TEXT PRIMARY KEY, origin INTEGER, sequence INTEGER, useful INTEGER,
            scheduled INTEGER, admitted INTEGER, batch_ready INTEGER, done INTEGER, rejected INTEGER,
            observed INTEGER, observed_present INTEGER, UNIQUE(origin,sequence));
          CREATE TABLE outputs(replica INTEGER,id TEXT,origin INTEGER,useful INTEGER,ordinal INTEGER,done INTEGER,
            PRIMARY KEY(replica,id));
          CREATE TABLE batches(replica INTEGER,id TEXT,payload INTEGER,done INTEGER,PRIMARY KEY(replica,id));
          CREATE TABLE latency(endpoint TEXT,completed INTEGER,value INTEGER);
        ''')
        self.ledgers = {int(k): v for k, v in ledgers.items()}
        self.max_ordinal = {}

    def scalar(self, query, parameters=()):
        return self.db.execute(query, parameters).fetchone()[0]

    def ingest(self, reader):
        for replica, ledger in sorted(self.ledgers.items()):
            start, end, observed = (number(ledger[k], k) for k in ("window_start_us", "window_end_us", "observed_us"))
            if end <= start or observed < end:
                raise ValueError("ledger must cover a positive finished measurement window")
            collected = number(ledger.get("collected_us", observed), "collected_us")
            if collected < observed:
                raise ValueError("collection precedes materialization freeze")
            for row in reader(replica, "requests"):
                _validate_request(row, replica, observed, collected, batch_ready_available=ledger.get("batch_ready_available", True), batch_ready_precedes_materialization=ledger.get("batch_ready_precedes_materialization", True))
                try:
                    self.db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?)", (
                        _request_key(row), replica, row["sequence"], row["useful_bytes"], row["scheduled_us"],
                        row.get("admitted_us"), row.get("batch_ready_us"), row.get("materialized_us"),
                        row.get("rejected_us"), row.get("all_correct_observed_us"), int("all_correct_observed_us" in row)))
                except sqlite3.IntegrityError as error:
                    raise ValueError("duplicate request identity or origin sequence") from error
            prior = -1
            for row in reader(replica, "outputs"):
                ordinal = number(row["output_index"], "output_index")
                timestamp = number(row["materialized_us"], "materialized_us")
                if int(ordinal) != ordinal or ordinal <= prior or timestamp > observed:
                    raise ValueError("output entries must have increasing exact ordinals and valid times")
                published = row.get("post_handler_published_us")
                if published is not None and not timestamp <= number(published, "post_handler_published_us") <= collected:
                    raise ValueError("output publication precedes materialization or exceeds collection")
                prior = ordinal
                self.db.execute("INSERT OR IGNORE INTO outputs VALUES(?,?,?,?,?,?)", (
                    replica, _request_key(row), row["origin"], row["useful_bytes"], ordinal, timestamp))
            self.max_ordinal[replica] = max(0, prior + 1 - ledger.get("output_index_base", 1))
            for row in reader(replica, "batches"):
                timestamp = number(row["materialized_us"], "materialized_us")
                published = row.get("post_handler_published_us")
                if timestamp > observed or (published is not None and not timestamp <= number(published, "post_handler_published_us") <= collected):
                    raise ValueError("batch publication or materialization exceeds its boundary")
                try:
                    self.db.execute("INSERT INTO batches VALUES(?,?,?,?)", (replica, identity(row["exact_batch_id"]),
                        number(row["payload_bytes"], "payload_bytes"), number(row["materialized_us"], "materialized_us")))
                except sqlite3.IntegrityError as error:
                    raise ValueError("duplicate exact batch identity") from error
            self.db.commit()
        if self.scalar("SELECT count(*) FROM outputs o JOIN requests r USING(id) WHERE o.origin!=r.origin OR o.useful!=r.useful"):
            raise ValueError("output identity content disagrees with admitted manifest")
        if self.scalar("SELECT count(*) FROM requests r LEFT JOIN outputs o ON o.replica=r.origin AND o.id=r.id WHERE r.done IS NOT NULL AND (o.id IS NULL OR o.done!=r.done)"):
            raise ValueError("local completion does not reconcile with exact output ledger")
        self.output_exclusions = {"boundary": "distinct IDs per replica; replicated diagnostic counts are not useful output",
            "by_replica": {replica: {"unknown_request_ids": self.scalar("SELECT count(*) FROM outputs o LEFT JOIN requests r USING(id) WHERE o.replica=? AND r.id IS NULL", (replica,)),
                "unadmitted_request_ids": self.scalar("SELECT count(*) FROM outputs o JOIN requests r USING(id) WHERE o.replica=? AND r.admitted IS NULL", (replica,))}
                for replica in self.ledgers}, "useful_credit": "unknown or unadmitted requests receive zero U_out credit; raw outputs and M_out remain retained"}
        self.db.execute("CREATE INDEX request_origin ON requests(origin,scheduled)")
        self.db.execute("CREATE INDEX output_identity ON outputs(id,replica)")
        self.db.commit()

    def quantiles(self, endpoint):
        total = self.scalar("SELECT count(*) FROM latency WHERE endpoint=?", (endpoint,))
        complete = self.scalar("SELECT count(*) FROM latency WHERE endpoint=? AND completed=1", (endpoint,))
        earliest_censor = self.scalar("SELECT min(value) FROM latency WHERE endpoint=? AND completed=0", (endpoint,))
        result = {"population": total, "completed": complete, "unfinished": total-complete}
        for percentile in (50,95,99):
            rank = math.ceil(total*percentile/100)
            lower = self.scalar("SELECT value FROM latency WHERE endpoint=? ORDER BY value LIMIT 1 OFFSET ?", (endpoint,rank-1)) if rank else None
            candidate = self.scalar("SELECT value FROM latency WHERE endpoint=? AND completed=1 ORDER BY value LIMIT 1 OFFSET ?", (endpoint,rank-1)) if rank and rank<=complete else None
            exact = candidate is not None and (earliest_censor is None or candidate<=earliest_censor)
            result[f"p{percentile}"] = {"value_ms": candidate/1000 if exact else None,
                "lower_bound_ms": lower/1000 if lower is not None else None,
                "status": "observed" if exact else "censored" if rank else "empty"}
        return result

    def summarize(self, *, correct_replicas=None, deadline_ms=1000, output_replica=None):
        number(deadline_ms, "deadline_ms")
        correct = sorted(self.ledgers if correct_replicas is None else correct_replicas)
        if not correct or len(correct)!=len(set(correct)) or not set(correct)<=set(self.ledgers):
            raise ValueError("nonempty unique correct replica set required")
        reference_id = correct[0] if output_replica is None else output_replica
        if reference_id not in correct:
            raise ValueError("reference output replica must be correct")
        self.db.execute("CREATE TABLE windows(replica INTEGER PRIMARY KEY,start INTEGER,end INTEGER,observed INTEGER,correct INTEGER)")
        for replica, ledger in self.ledgers.items():
            self.db.execute("INSERT INTO windows VALUES(?,?,?,?,?)", (replica,ledger["window_start_us"],ledger["window_end_us"],ledger["observed_us"],int(replica in correct)))
        origins = []
        totals = {key:0 for key in ("completion_count","u_out_bytes","carried_in_completion_count","admission_count","admission_tps","unique_completion_tps","useful_goodput_bytes_per_second","pending_at_start","pending_at_end")}
        observed_origins = {}
        observed_complete = observed_unresolved = observation_missing = 0
        for replica in correct:
            ledger = self.ledgers[replica]
            start,end,until = (ledger[k] for k in ("window_start_us","window_end_us","observed_us"))
            receipt_until = ledger.get("collected_us", until)
            duration = (end-start)/1_000_000
            tally = dict.fromkeys(("scheduled","admitted","rejected","completed","pending","deadline_completed","deadline_unresolved"),0)
            oldest = 0
            origin_seen = {"scheduled":0,"observed_by_deadline":0}
            for scheduled,admitted,done,rejected,observed,present in self.db.execute(
                    "SELECT scheduled,admitted,done,rejected,observed,observed_present FROM requests WHERE origin=? AND scheduled>=? AND scheduled<?", (replica,start,end)):
                tally["scheduled"] += 1
                origin_seen["scheduled"] += 1
                deadline = scheduled+deadline_ms*1000
                if admitted is not None:
                    tally["admitted"] += 1
                    self.db.execute("INSERT INTO latency VALUES('admission',?,?)", (int(done is not None),(done if done is not None else until)-admitted))
                tally["rejected"] += rejected is not None
                if done is not None:
                    tally["completed"] += 1
                    tally["deadline_completed"] += done<=deadline
                else:
                    oldest = max(oldest,until-scheduled)
                    tally["pending"] += rejected is None
                    tally["deadline_unresolved"] += rejected is None and until<deadline
                self.db.execute("INSERT INTO latency VALUES('scheduled',?,?)", (int(done is not None),(done if done is not None else until)-scheduled))
                observation_missing += not present
                if observed is not None:
                    observed_complete += observed<=deadline
                    origin_seen["observed_by_deadline"] += observed<=deadline
                else:
                    observed_unresolved += receipt_until<deadline
                self.db.execute("INSERT INTO latency VALUES('observed',?,?)", (int(observed is not None),(observed if observed is not None else receipt_until)-scheduled))
            observed_origins[replica] = origin_seen
            count,volume,carried = self.db.execute('''SELECT count(*),coalesce(sum(o.useful),0),coalesce(sum(r.scheduled<?),0)
                FROM outputs o JOIN requests r USING(id)
                WHERE o.replica=? AND o.origin=? AND r.origin=? AND r.admitted IS NOT NULL AND r.done IS NOT NULL
                  AND r.admitted<=o.done AND o.done>=? AND o.done<?''', (start,replica,replica,replica,start,end)).fetchone()
            admissions = self.scalar("SELECT count(*) FROM requests WHERE origin=? AND admitted>=? AND admitted<?", (replica,start,end))
            totals["completion_count"] += count
            totals["u_out_bytes"] += volume
            totals["carried_in_completion_count"] += carried
            totals["admission_count"] += admissions
            totals["admission_tps"] += admissions/duration
            totals["unique_completion_tps"] += count/duration
            totals["useful_goodput_bytes_per_second"] += volume/duration
            for field,boundary in (("pending_at_start",start),("pending_at_end",end)):
                totals[field] += self.scalar("SELECT count(*) FROM requests WHERE origin=? AND admitted<? AND (done IS NULL OR done>=?)", (replica,boundary,boundary))
            origins.append({"origin":replica,**tally,"unfinished":tally["scheduled"]-tally["completed"],
                "deadline_missed":tally["scheduled"]-tally["deadline_completed"]-tally["deadline_unresolved"],
                "deadline_completion_fraction":tally["deadline_completed"]/tally["scheduled"] if tally["scheduled"] else None,
                "deadline_completion_fraction_upper_bound":(tally["deadline_completed"]+tally["deadline_unresolved"])/tally["scheduled"] if tally["scheduled"] else None,
                "oldest_outstanding_ms":oldest/1000,"window_completion_count":count,"window_u_out_bytes":volume,"window_seconds":duration})
            self.db.commit()
        self.db.execute("CREATE INDEX latency_rank ON latency(endpoint,value)")
        self.db.execute("CREATE INDEX completed_rank ON latency(endpoint,completed,value)")
        self.db.commit()
        selected = sum(row["scheduled"] for row in origins)
        everywhere = self.scalar('''SELECT count(*) FROM requests r JOIN windows w ON w.replica=r.origin
            WHERE w.correct=1 AND r.scheduled>=w.start AND r.scheduled<w.end AND r.admitted IS NOT NULL AND r.done IS NOT NULL
              AND (SELECT count(*) FROM outputs o JOIN windows ow ON ow.replica=o.replica WHERE o.id=r.id AND ow.correct=1)=?''', (len(correct),))
        reference = self.ledgers[reference_id]
        total_batch = self.scalar("SELECT coalesce(sum(payload),0) FROM batches WHERE replica=?", (reference_id,))
        window_batch = self.scalar("SELECT coalesce(sum(payload),0) FROM batches WHERE replica=? AND done>=? AND done<?", (reference_id,reference["window_start_us"],reference["window_end_us"]))
        useful_count,useful_volume = self.db.execute('''SELECT count(*),coalesce(sum(r.useful),0) FROM outputs o JOIN requests r USING(id)
            JOIN windows w ON w.replica=r.origin WHERE o.replica=? AND w.correct=1 AND r.admitted IS NOT NULL AND r.done IS NOT NULL''', (reference_id,)).fetchone()
        prefix = reference.get("output_prefix_count",self.max_ordinal[reference_id])
        if type(prefix) is not int or prefix<self.max_ordinal[reference_id]:
            raise ValueError("declared output prefix is smaller than an exact output ordinal")
        fractions = [row["deadline_completion_fraction"] for row in origins if row["scheduled"]]
        deadline_count = sum(row["deadline_completed"] for row in origins)
        unresolved = sum(row["deadline_unresolved"] for row in origins)
        result = {"schema":SCHEMA,"endpoint_contract":ENDPOINT,
            "clock":"per-origin monotonic; remote membership has no cross-clock latency",
            "cohort":"honest-origin intended arrivals in each half-open measurement window",
            "deadline_ms":deadline_ms,"deadline_start":"intended_submission","origins":origins,
            **{key:sum(row[key] for row in origins) for key in ("scheduled","admitted","rejected","completed","unfinished","deadline_unresolved","deadline_missed")},
            "deadline_completion_fraction":deadline_count/selected if selected else None,
            "deadline_fraction_status":"lower_bound" if unresolved else "observed",
            "deadline_completion_fraction_upper_bound":(deadline_count+unresolved)/selected if selected else None,
            "worst_origin_deadline_completion_fraction":min(fractions) if fractions else None,
            "admission_to_output":self.quantiles("admission"),"scheduled_to_output":self.quantiles("scheduled"),
            "all_correct_collection":{"completed":everywhere,"unfinished":selected-everywhere,
                "fraction":everywhere/selected if selected else None,"boundary":"final exact output collection; not remote event latency"},
            "window":{**totals,"pending_boundary":"honest own-origin admitted requests without exact local materialization at each half-open window boundary",
                "stability":window_stability(self.ledgers, correct, lambda origin: self.db.execute(
                    "SELECT scheduled,admitted,done,rejected FROM requests WHERE origin=?", (origin,))),
                "m_out_bytes":window_batch,"m_out_replica":reference_id,
                "m_out_boundary":"distinct exact batch payloads in selected replica measurement window"},
            "finite_run":{"m_out_bytes":total_batch,"u_out_bytes":useful_volume,"unique_honest_completion_count":useful_count,
                "output_replica":reference_id,"output_prefix_count":prefix,
                "boundary":"selected final output prefix intersected with honest origin admission-to-output completions; setup/warmup/drain retained"}}
        if selected and not observation_missing:
            fractions = [row["observed_by_deadline"]/row["scheduled"] for row in observed_origins.values() if row["scheduled"]]
            result["all_correct_origin_observed"] = {
                "endpoint":"notification of verified common output prefix received on origin's own monotonic clock; includes polling/controller/return delay",
                "scheduled_to_observation":self.quantiles("observed"),"deadline_unresolved":observed_unresolved,
                "deadline_completion_fraction_lower_bound":observed_complete/selected,
                "worst_origin_deadline_completion_fraction_lower_bound":min(fractions) if fractions else None,
                "origins":observed_origins}
        self.completed_mean_ms = self.scalar("SELECT avg(value)/1000.0 FROM latency WHERE endpoint='admission' AND completed=1")
        return result

    def close(self):
        self.db.commit()
        self.db.close()
