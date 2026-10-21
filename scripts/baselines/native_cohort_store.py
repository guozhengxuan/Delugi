"""Bounded native journals, sharded cohorts and exact disk-backed reduction.

This replaces full-file postprocessing, not native custody or an application's
live materializer. Original native journals remain evidence. Legacy replay APIs
can still return dictionaries; new campaign paths use the archive API here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cohort_store import (FORMAT, MAX_MANIFEST_BYTES, MAX_PAGE_BYTES, MAX_PAGE_ENTRIES,
                          MAX_ROW_BYTES, MAX_INDEX_LINE_BYTES, STREAMS, ShardedArchive,
                          CohortDatabase, sha_file, bounded_read, safe_path)
from cohort_metrics import _request_key, identity

MAX_JOURNAL_RECORD = 4 * 1024 * 1024
READ_CHUNK = 16 * 1024


def journal_rows(path, limit=MAX_JOURNAL_RECORD):
    """One bounded complete JSON object per native journal record."""
    with Path(path).open("rb") as stream:
        while True:
            line = stream.readline(limit + 1)
            if not line:
                break
            if len(line) > limit or not line.endswith(b"\n"):
                raise ValueError("oversized or truncated native journal record")
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError("native journal record must be an object")
            yield row


class JsonStream:
    """Small recursive JSON reader; ignored diagnostics never become objects.

    Used only to replay existing monolithic native ledgers. Materialized values
    have a byte bound; skipped arrays/strings can be arbitrarily long on disk.
    Even skipped values are parsed, so malformed trailing evidence is rejected.
    """
    def __init__(self, source):
        self.source, self.buffer, self.position = source, "", 0
        self.bytes = 0

    def peek(self):
        if self.position == len(self.buffer):
            self.buffer, self.position = self.source.read(READ_CHUNK), 0
        return self.buffer[self.position:self.position + 1]

    def take(self):
        value = self.peek()
        self.position += bool(value)
        self.bytes += len(value.encode("utf-8"))
        return value

    def whitespace(self):
        while self.peek() and self.peek() in " \t\r\n":
            self.take()

    def expect(self, value):
        self.whitespace()
        if self.take() != value:
            raise ValueError("malformed streamed native JSON")

    def string(self, keep, limit):
        self.expect('"')
        chunks = ['"'] if keep else None
        start = self.bytes
        while True:
            char = self.take()
            if not char or ord(char) < 32:
                raise ValueError("truncated or invalid native JSON string")
            if keep:
                chunks.append(char)
                if self.bytes - start > limit:
                    raise ValueError("native JSON value exceeds bounded object envelope")
            if char == '"':
                break
            if char == "\\":
                escaped = self.take()
                if escaped not in '"\\/bfnrtu' or not escaped:
                    raise ValueError("invalid native JSON escape")
                if keep: chunks.append(escaped)
                if escaped == "u":
                    digits = "".join(self.take() for _ in range(4))
                    if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                        raise ValueError("invalid native JSON Unicode escape")
                    if keep: chunks.append(digits)
        return json.loads("".join(chunks)) if keep else None

    def value(self, keep=True, limit=MAX_ROW_BYTES, depth=0):
        if depth > 64:
            raise ValueError("native JSON nesting exceeds envelope")
        self.whitespace()
        start, char = self.bytes, self.peek()
        if char == '"':
            return self.string(keep, limit)
        if char in ("[", "{"):
            self.take()
            end = "]" if char == "[" else "}"
            result = ([] if char == "[" else {}) if keep else None
            self.whitespace()
            if self.peek() == end:
                self.take()
                return result
            while True:
                key = None
                if char == "{":
                    key = self.string(keep, limit)
                    self.expect(":")
                item = self.value(keep, limit, depth + 1)
                if keep:
                    if self.bytes - start > limit:
                        raise ValueError("native JSON value exceeds bounded object envelope")
                    if char == "[": result.append(item)
                    else: result[key] = item
                self.whitespace()
                separator = self.take()
                if separator == end: return result
                if separator != ",": raise ValueError("malformed native JSON container")
        token = ""
        while self.peek() and self.peek() not in ",]} \r\n\t":
            token += self.take()
            if len(token) > 128:
                raise ValueError("native JSON numeric token exceeds envelope")
        if not token or token in ("NaN", "Infinity", "-Infinity"):
            raise ValueError("invalid native JSON value")
        result = json.loads(token)
        return result if keep else None

    def ledger_items(self):
        """Yield (field,row) for streams and small required metadata only."""
        metadata = {"window_start_us", "window_end_us", "observed_us", "collected_us",
                    "output_index_base", "output_prefix_count", "batch_ready_available",
                    "clock", "cohort_observer"}
        self.expect("{")
        seen = set()
        while True:
            self.whitespace()
            if self.peek() == "}":
                self.take()
                break
            key = self.string(True, MAX_ROW_BYTES)
            if key in seen: raise ValueError("duplicate native ledger field")
            seen.add(key)
            if len(seen) > 128: raise ValueError("native ledger metadata field envelope exceeded")
            self.expect(":")
            if key in STREAMS:
                self.expect("[")
                self.whitespace()
                if self.peek() != "]":
                    while True:
                        row = self.value()
                        if not isinstance(row, dict): raise ValueError("native ledger row must be an object")
                        yield key, row
                        self.whitespace()
                        separator = self.take()
                        if separator == "]": break
                        if separator != ",": raise ValueError("malformed native ledger array")
                else: self.take()
            elif key == "compact_receipt":
                self.expect("{")
                while True:
                    name = self.string(True, MAX_ROW_BYTES); self.expect(":")
                    selected = name in ("schema", "planned_counts", "useful_bytes", "output_count", "output_sha256")
                    row = self.value(selected)
                    if selected: yield "receipt." + name, row
                    self.whitespace(); separator = self.take()
                    if separator == "}": break
                    if separator != ",": raise ValueError("malformed native receipt")
            else:
                row = self.value(key in metadata)
                if key in metadata: yield key, row
            self.whitespace()
            separator = self.take()
            if separator == "}": break
            if separator != ",": raise ValueError("malformed native ledger object")
            self.whitespace()
            if self.peek() == "}": raise ValueError("native ledger trailing comma")
        self.whitespace()
        if self.peek(): raise ValueError("native ledger trailing data")
        if not set(STREAMS) <= seen: raise ValueError("native ledger lacks exact output streams")


class NativeStore:
    """On-disk staging: fixed SQLite cache, no request/output Python population."""
    def __init__(self, path):
        self.path = Path(path)
        if self.path.exists(): raise ValueError("native staging database must be new")
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA cache_size=-16384")
        self.db.execute("PRAGMA temp_store=FILE")
        self.db.execute("PRAGMA mmap_size=0")
        self.db.executescript("""
          CREATE TABLE rows(replica INTEGER,stream TEXT,id TEXT,ordinal INTEGER,body TEXT,
            PRIMARY KEY(replica,stream,id),UNIQUE(replica,stream,ordinal));
        """)
        self.metadata, self.serial, self.last_output = {}, {}, {}
        self.operations = 0

    def put(self, replica, stream, row):
        raw = json.dumps(row, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > MAX_ROW_BYTES: raise ValueError("native cohort row exceeds archive envelope")
        ordinal = row["sequence"] if stream == "requests" else row["output_index"] if stream == "outputs" else self.serial.get((replica, stream), 0)
        key = _request_key(row) if stream == "requests" else str(ordinal) if stream == "outputs" else identity(row["exact_batch_id"])
        if type(ordinal) is not int or ordinal < 0: raise ValueError("native ordinal must be a nonnegative integer")
        if stream == "outputs":
            if ordinal <= self.last_output.get(replica, -1):
                raise ValueError("native output journal ordinal regressed")
            self.last_output[replica] = ordinal
        try:
            self.db.execute("INSERT INTO rows VALUES(?,?,?,?,?)", (replica, stream, key, ordinal, raw))
        except sqlite3.IntegrityError as error:
            raise ValueError("duplicate native identity or exact ordinal") from error
        self.serial[(replica, stream)] = self.serial.get((replica, stream), 0) + 1
        self.operations += 1
        if self.operations % 1024 == 0: self.db.commit()

    def stage(self, replica, request, field, timestamp, *, first=False):
        found = self.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' AND id=?", (replica, request)).fetchone()
        if found is None: raise ValueError("native ingress/output identity absent from finite own-origin workload")
        row = json.loads(found[0])
        if row.get(field) is not None:
            if first: return
            raise ValueError("duplicate native ingress stage")
        row[field] = timestamp
        self.db.execute("UPDATE rows SET body=? WHERE replica=? AND stream='requests' AND id=?",
                        (json.dumps(row, separators=(",", ":")), replica, request))
        self.operations += 1
        if self.operations % 1024 == 0: self.db.commit()

    def legacy(self, path, replica):
        source_hash = sha_file(path)
        metadata = {"output_index_base": 0}
        with Path(path).open("r", encoding="utf-8") as source:
            for field, row in JsonStream(source).ledger_items():
                if field in STREAMS: self.put(replica, field, row)
                elif field.startswith("receipt."): metadata.setdefault("native_receipt", {})[field[8:]] = row
                else: metadata[field] = row
        if sha_file(path) != source_hash: raise ValueError("native ledger changed during bounded ingestion")
        metadata["native_evidence"] = {"path": str(Path(path).resolve()), "sha256": source_hash,
            "verification": "native materializer's original identity/payload checks preserved; full source journal retained"}
        self.metadata[replica] = metadata

    def mysticeti(self, path, replica, request_id, observed_us=None):
        source_hash = sha_file(path)
        start = None
        for row in journal_rows(path):
            if row.get("event") == "start":
                if start is not None: raise ValueError("duplicate native monotonic cohort start")
                start = row
        if start is None or start["origin"] != replica:
            raise ValueError("exactly one matching native monotonic cohort start required")
        if type(start["count"]) is not int or start["count"] < 0 or (start["count"] and start["rate"] <= 0):
            raise ValueError("invalid finite native workload population")
        metadata = {key: start[key] for key in ("window_start_us", "window_end_us", "observed_us")}
        if observed_us is not None:
            if type(observed_us) is not int or not start["observed_us"] <= observed_us <= 2**64-1:
                raise ValueError("invalid native observer prefix-freeze endpoint")
            metadata.update(declared_observed_us=start["observed_us"], observed_us=observed_us,
                observation_endpoint="actual complete-block observer prefix freeze; declared deadline remains separate")
        metadata.update(output_index_base=0, allow_sparse_output_ordinals=True,
            batch_ready_precedes_materialization=False,
            output_sequence_scope="authenticated workload observations at actual native ordinals; full native-order fidelity requires signed WAL replay",
            native_terminal_output_count=None, native_evidence={"path": str(Path(path).resolve()), "sha256": source_hash,
            "verification": "deterministic payload identity checked here; native signed block validation remains in the native implementation/WAL verifier"})
        self.metadata[replica] = metadata
        for sequence in range(start["count"]):
            self.put(replica, "requests", {"request_id": request_id(replica, sequence, start["useful_bytes"]),
                "origin": replica, "sequence": sequence, "useful_bytes": start["useful_bytes"],
                "scheduled_us": start["elapsed_us"] + sequence * 1_000_000 // start["rate"],
                "admitted_us": None, "batch_ready_us": None, "materialized_us": None})
        for row in journal_rows(path):
            if row.get("elapsed_us", 0) > metadata["observed_us"]: continue
            event = row["event"]
            if event in ("admitted", "batch_ready"):
                self.stage(replica, row["request_id"], event + "_us", row["elapsed_us"])
            elif event == "materialized":
                if row["request_id"] != request_id(row["origin"], row["sequence"], row["useful_bytes"]):
                    raise ValueError("materialized native content differs from workload identity")
                self.put(replica, "outputs", {**row, "materialized_us": row["elapsed_us"]})
                if row.get("origin_eligible") is not None and type(row["origin_eligible"]) is not bool:
                    raise ValueError("invalid native append-time eligibility")
                if observed_us is not None and row["origin"] == replica and type(row.get("origin_eligible")) is not bool:
                    raise ValueError("receipt-bound native output requires explicit append-time eligibility")
                if row["origin"] == replica and row.get("origin_eligible", True):
                    self.stage(replica, row["request_id"], "materialized_us", row["elapsed_us"], first=True)
            elif event == "batch": self.put(replica, "batches", {**row, "materialized_us": row["elapsed_us"]})
            elif event == "native_enqueued":
                self.stage(replica, row["request_id"], "native_enqueued_us", row["elapsed_us"])
            elif event in ("not_admitted", "arrivals_finished"):
                # Native not_admitted means channel enqueue missed the native
                # deadline after application admission; it is not an ingress
                # rejection. Raw diagnostics remain in the authenticated file.
                continue
            elif event != "start": raise ValueError("unknown native cohort event")
        if sha_file(path) != source_hash: raise ValueError("native journal changed during bounded ingestion")

    def rows(self, replica, stream):
        for body, in self.db.execute("SELECT body FROM rows WHERE replica=? AND stream=? ORDER BY ordinal", (replica, stream)):
            yield json.loads(body)

    def archive(self, root):
        self.db.commit()
        root = Path(root); root.mkdir(parents=True, exist_ok=False)
        replicas = {}
        for replica, source in sorted(self.metadata.items()):
            count, first, last = self.db.execute("SELECT count(*),min(ordinal),max(ordinal) FROM rows WHERE replica=? AND stream='requests'", (replica,)).fetchone()
            if count and (first != 0 or last != count - 1):
                raise ValueError("finite native request sequence has a gap")
            receipt = source.get("native_receipt")
            if receipt is not None and (replica >= len(receipt["planned_counts"]) or receipt["planned_counts"][replica] != count):
                raise ValueError("native request population differs from materializer receipt")
            for row in self.rows(replica, "outputs"):
                if not self.db.execute("SELECT 1 FROM rows WHERE replica=? AND stream='batches' AND id=?", (replica, identity(row["exact_batch_id"]))).fetchone():
                    raise ValueError("native output lacks its exact materialized batch")
            metadata = {**source, "streams": {}}
            directory = root / f"replica-{replica}"; directory.mkdir()
            for stream in STREAMS:
                total = self.serial.get((replica, stream), 0)
                rows = self.rows(replica, stream)
                index_path = directory / (stream + ".index.jsonl")
                offset = pages = byte_count = 0; digest = hashlib.sha256()
                with index_path.open("xb") as index:
                    while True:
                        entries = []
                        # Reserve bounded page overhead even when every row
                        # occupies the maximum accepted row envelope.
                        page_rows = min(MAX_PAGE_ENTRIES, (MAX_PAGE_BYTES - 4096) // (MAX_ROW_BYTES + 2))
                        for _ in range(min(page_rows, total - offset)):
                            entries.append(next(rows))
                        following = offset + len(entries) if offset + len(entries) < total else None
                        page = {"replica": replica, "total": total, "entries": entries, "next_offset": following,
                                "manifest": metadata.get("manifest"), "elapsed_us": metadata["observed_us"]}
                        raw = (json.dumps(page, separators=(",", ":"), allow_nan=False) + "\n").encode()
                        if len(raw) > MAX_PAGE_BYTES: raise ValueError("native shard exceeds page envelope")
                        path = directory / f"{stream}-{pages:08d}.json"; path.write_bytes(raw)
                        descriptor = {"path": str(path.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(),
                                      "bytes": len(raw), "entries": len(entries), "offset": offset}
                        line = (json.dumps(descriptor, separators=(",", ":")) + "\n").encode()
                        if len(line) > MAX_INDEX_LINE_BYTES: raise ValueError("native shard index line exceeds envelope")
                        index.write(line); digest.update(line); byte_count += len(line); pages += 1
                        offset += len(entries)
                        if following is None: break
                metadata["streams"][stream] = {"path": str(index_path.relative_to(root)), "sha256": digest.hexdigest(),
                                                "bytes": byte_count, "pages": pages, "entries": total}
            last = self.db.execute("SELECT max(ordinal) FROM rows WHERE replica=? AND stream='outputs'", (replica,)).fetchone()[0]
            metadata.setdefault("output_prefix_count", 0 if last is None else last + 1 - metadata.get("output_index_base", 0))
            if metadata.get("allow_sparse_output_ordinals"):
                metadata["output_prefix_count_scope"] = "prefix through last authenticated workload observation; unseen native tail is unavailable"
            replicas[str(replica)] = metadata
        manifest = {"schema": 2, "format": FORMAT, "replicas": replicas,
            "resource_contract": {"aggregate_byte_limit": None, "max_page_bytes": MAX_PAGE_BYTES,
                "max_page_entries": MAX_PAGE_ENTRIES, "max_row_bytes": MAX_ROW_BYTES,
                "staging_sqlite_cache_bytes": 16 * 1024**2,
                "scope": "bounded offline ingestion/reduction; original native custody and live materializer state may still grow with workload"}}
        raw = (json.dumps(manifest, indent=2, allow_nan=False) + "\n").encode()
        if len(raw) > MAX_MANIFEST_BYTES: raise ValueError("native archive metadata exceeds envelope")
        path = root / "index.json"; path.write_bytes(raw)
        return ShardedArchive(path)

    def close(self):
        self.db.commit(); self.db.close()


class ArchiveCollection:
    """A bounded host-index manifest over separately verified schema2 archives."""
    def __init__(self, path):
        self.path = Path(path)
        raw = bounded_read(self.path, MAX_MANIFEST_BYTES)
        self.index_sha256 = hashlib.sha256(raw).hexdigest()
        manifest = json.loads(raw)
        if manifest.get("format") != "native-cohort-collection-v1" or not 1 <= len(manifest["archives"]) <= 31:
            raise ValueError("invalid native cohort collection")
        self.archives, self.ledgers = {}, {}
        for descriptor in manifest["archives"]:
            archive = ShardedArchive(safe_path(self.path.parent, descriptor["path"]))
            if archive.index_sha256 != descriptor["sha256"]:
                raise ValueError("native host archive index hash changed")
            for replica, metadata in archive.ledgers.items():
                if replica in self.ledgers: raise ValueError("duplicate native archive replica")
                self.archives[replica], self.ledgers[replica] = archive, metadata
        if len(self.ledgers) > 31: raise ValueError("native archive population exceeds envelope")

    def rows(self, replica, stream):
        yield from self.archives[replica].rows(replica, stream)


def combine_archives(archives, path):
    path = Path(path)
    entries = [{"path": str(archive.path.resolve().relative_to(path.parent.resolve())), "sha256": archive.index_sha256}
               for archive in archives]
    if path.exists(): raise ValueError("native archive collection must be new")
    path.write_text(json.dumps({"schema": 1, "format": "native-cohort-collection-v1", "archives": entries}, indent=2) + "\n")
    return ArchiveCollection(path)


def prefix_agreement(archive, correct):
    """Compare every overlap to the longest stream, including stalled replicas."""
    counts = {i: archive.ledgers[i]["streams"]["outputs"]["entries"] for i in correct}
    reference = max(correct, key=lambda i: counts[i])
    common = min(counts.values())
    def sequence(replica):
        base = archive.ledgers[replica].get("output_index_base", 0)
        previous = base - 1
        for ordinal, row in enumerate(archive.rows(replica, "outputs"), base):
            actual = row["output_index"]
            if actual <= previous or (not archive.ledgers[replica].get("allow_sparse_output_ordinals") and actual != ordinal):
                raise ValueError("native materialized output ordinals violate declared sequence scope")
            previous = actual
            yield [actual, _request_key(row), identity(row["exact_batch_id"])]
    digest = hashlib.sha256(b"[")
    for count, row in enumerate(sequence(reference)):
        if count < common:
            if count: digest.update(b", ")
            digest.update(json.dumps(row).encode())
    digest.update(b"]")
    for replica in correct:
        if replica == reference: continue
        # Validate both stream hashes completely, even beyond the shorter prefix.
        current = iter(sequence(replica))
        for offset, row in enumerate(sequence(reference)):
            if offset < counts[replica] and next(current) != row:
                raise ValueError("native exact transaction and batch output prefixes disagree")
        if next(current, None) is not None: raise ValueError("native output population changed")
    # The optional independent materializer receipt includes native duplicates
    # and order. Check its final rolling fingerprint without loading bitmaps or
    # checkpoint arrays; original diagnostics remain in the hashed raw ledger.
    for replica in correct:
        receipt = archive.ledgers[replica].get("native_receipt")
        if receipt is None: continue
        receipt_hash = hashlib.sha256()
        for row in sequence(replica):
            raw = json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode()
            receipt_hash.update(struct.pack("<Q", len(raw))); receipt_hash.update(raw)
        if receipt["output_count"] != counts[replica] or receipt["output_sha256"] != receipt_hash.hexdigest():
            raise ValueError("native materializer receipt differs from exact output journal")
    batch_counts = {i: archive.ledgers[i]["streams"]["batches"]["entries"] for i in correct}
    batch_reference = max(correct, key=lambda i: batch_counts[i])
    for replica in correct:
        if replica == batch_reference: continue
        current = iter(archive.rows(replica, "batches"))
        for offset, row in enumerate(archive.rows(batch_reference, "batches")):
            if offset < batch_counts[replica]:
                observed = next(current)
                if (row["exact_batch_id"], row["payload_bytes"]) != (observed["exact_batch_id"], observed["payload_bytes"]):
                    raise ValueError("native exact batch payload prefixes disagree")
        if next(current, None) is not None: raise ValueError("native batch population changed")
    sparse = any(archive.ledgers[i].get("allow_sparse_output_ordinals") for i in correct)
    return {"replicas_agree_on_common_prefix": True, "common_prefix_length": common,
            "sequence_lengths": [counts[i] for i in correct], "common_prefix_sha256": digest.hexdigest(),
            "scope": "every correct-replica exact observed ordinal/request/batch overlapping prefix; streamed bounded pages",
            "native_order_scope": {i: archive.ledgers[i].get("output_sequence_scope", "complete native output journal") for i in correct},
            "native_order_fidelity": {"status": "incomplete" if sparse else "complete_observer_sequence",
                "reason": "filtered journal cannot authenticate unseen leading/trailing native payload order; independent signed WAL proof required" if sparse else "complete native journal ordinals checked"},
            "native_terminal_prefix": {i: {"count": archive.ledgers[i]["output_prefix_count"],
                "kind": "lower_bound" if archive.ledgers[i].get("allow_sparse_output_ordinals") else "exact"} for i in correct}}


def reduce_archive(archive, database_path, correct, deadline_ms):
    agreement = prefix_agreement(archive, correct)
    database = CohortDatabase(database_path, archive.ledgers)
    try:
        database.ingest(archive.rows)
        cohort = database.summarize(correct_replicas=correct, deadline_ms=deadline_ms)
        placeholders = ",".join("?" for _ in correct)
        origins = []
        for origin in correct:
            completed = database.scalar(f"SELECT count(*) FROM requests r WHERE origin=? AND admitted IS NOT NULL AND r.done IS NOT NULL AND (SELECT count(*) FROM outputs o WHERE o.id=r.id AND replica IN ({placeholders}))=?", (origin, *correct, len(correct)))
            origins.append({"origin": origin, "planned": database.scalar("SELECT count(*) FROM requests WHERE origin=?", (origin,)),
                            "admitted": database.scalar("SELECT count(*) FROM requests WHERE origin=? AND admitted IS NOT NULL", (origin,)),
                            "all_correct_completed": completed})
        return {"cohort": cohort, "agreement": agreement, "mean_latency_ms": database.completed_mean_ms,
            "cohort_archive": {"path": str(archive.path.resolve()), "sha256": archive.index_sha256,
                "schema": 1 if isinstance(archive, ArchiveCollection) else 2,
                "format": "native-cohort-collection-v1" if isinstance(archive, ArchiveCollection) else FORMAT},
            "output_exclusions": database.output_exclusions,
            "finite_output_receipt": {"planned": sum(row["planned"] for row in origins),
                "admitted": sum(row["admitted"] for row in origins), "all_correct_completed": sum(row["all_correct_completed"] for row in origins),
                "origins": origins, "scope": "disk-backed exact finite identity/output join with eligible own-origin completion; original native receipt final fingerprints checked when present"}}
    finally:
        database.close()
