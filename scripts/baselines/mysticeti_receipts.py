"""Bounded finite receipts for Mysticeti's detailed-observer control.

These are source-bound native-hook observations, not independent authenticated WAL
proofs. Raw native output and complete block prefixes include unknown payloads;
only the own-origin append-time eligibility latch supplies useful-work credit.
"""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import hashlib
import itertools
import json
import os
import stat

FORMAT = "mysticeti-native-receipt-v1"
CHUNK = 4096
HEADER_LIMIT = 256 * 1024
FILE_LIMIT = 128 * 1024**3
LOCAL = ("admitted", "ready", "eligible", "seen", "window_admitted", "window_completed")
EMPTY_HASH = hashlib.blake2b().hexdigest()


def digest(raw):
    return hashlib.blake2b(raw).hexdigest()


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum or value > 2**64 - 1:
        raise ValueError("invalid finite native receipt integer")
    return value


def _hash(value):
    if not isinstance(value, str) or len(value) != 128 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("invalid full native receipt hash")
    return value


@contextmanager
def opened(path, expected_bytes=None):
    path = Path(path)
    if path.parent.is_symlink() or path.is_symlink():
        raise ValueError("native receipt symlink is forbidden")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > FILE_LIMIT or (expected_bytes is not None and info.st_size != expected_bytes):
            raise ValueError("native receipt file size or type differs")
        yield stream


def load(directory, replica, counts, useful_bytes, mode, start, *, population_profile=None):
    """Bind all populations and paths to trusted configuration before bitmap IO."""
    directory = Path(directory)
    with opened(directory / "header.json") as stream:
        raw = stream.read(HEADER_LIMIT + 1)
    if len(raw) > HEADER_LIMIT:
        raise ValueError("native receipt header exceeds bound")
    header = json.loads(raw)
    if population_profile not in (None,'compact-n10-n50-v1'):raise ValueError('unknown native population profile')
    maximum=50 if population_profile=='compact-n10-n50-v1' else 31
    if population_profile and start.get('population_profile')!=population_profile:raise ValueError('native population profile differs')
    if (type(header) is not dict or type(header.get("schema")) is not int or header.get("schema") != 1 or header.get("format") != FORMAT or header.get("mode") != mode
            or type(header.get("origin")) is not int or header.get("origin") != replica or header.get("counts") != counts
            or type(header.get("counts")) is not list or any(type(n) is not int for n in header["counts"])
            or type(header.get("useful_bytes")) is not int or header.get("useful_bytes") != useful_bytes or mode not in ("full", "compact")
            or not 0 <= replica < len(counts) <= maximum
            or any(type(n) is not int or not 0 <= n <= 5_000_000 for n in counts)):
        raise ValueError("native receipt differs from finite configuration")
    for key in ("requested_us", "frozen_us", "output_count", "batch_count", "payload_bytes", "checkpoint_bytes"):
        _integer(header[key])
    if header["checkpoint_bytes"] > FILE_LIMIT:
        raise ValueError("native checkpoint file exceeds disk envelope")
    if (start["origin"] != replica or start["count"] != counts[replica] or start["useful_bytes"] != useful_bytes
            or _integer(header["window_start_us"]) != start["window_start_us"] or _integer(header["window_end_us"]) != start["window_end_us"]
            or not start["observed_us"] <= header["requested_us"] <= header["frozen_us"] <= header["requested_us"] + 10_000_000):
        raise ValueError("native receipt cutoff differs from declared start/deadline")
    for name in ("output_hash", "batch_hash", "checkpoint_hash"):
        _hash(header[name])
    expected = {(name, replica) for name in LOCAL} | {("materialized", i) for i in range(len(counts))}
    descriptors = {}
    for row in header["streams"]:
        key = (row["name"], _integer(row["origin"]))
        if key not in expected or key in descriptors or row.get("path") != f"{key[0]}-{key[1]}.bits":
            raise ValueError("unknown, duplicate or unconfined native bitmap stream")
        if (_integer(row["count"]) != counts[key[1]] or _integer(row["bytes"]) != (row["count"] + 7) // 8
                or _integer(row["ones"]) > row["count"]):
            raise ValueError("native bitmap population mismatch")
        _hash(row["hash"]); descriptors[key] = row
    if set(descriptors) != expected:
        raise ValueError("missing native receipt bitmap")
    return {"root": directory, "header": header, "descriptors": descriptors,
            "header_sha256": hashlib.sha256(raw).hexdigest(), "declared_observed_us": start["observed_us"]}


@contextmanager
def bitmap(receipt, name, origin):
    row = receipt["descriptors"][(name, origin)]
    with opened(receipt["root"] / row["path"], row["bytes"]) as stream:
        class Reader:
            def __init__(self):
                self.hash = hashlib.blake2b(); self.bytes = self.ones = self.last = 0
            def read(self, n):
                if not 0 <= n <= CHUNK or self.bytes+n > row["bytes"]:
                    raise ValueError("native bitmap read exceeds bound")
                raw = stream.read(n)
                if len(raw) != n: raise ValueError("truncated native bitmap")
                self.hash.update(raw); self.bytes += n; self.ones += sum(v.bit_count() for v in raw)
                if raw: self.last = raw[-1]
                return raw
            def finish(self):
                if (self.bytes != row["bytes"] or stream.read(1) or self.hash.hexdigest() != row["hash"]
                        or self.ones != row["ones"] or (row["count"] % 8 and self.last >> (row["count"] % 8))):
                    raise ValueError("native bitmap length, hash, count or padding mismatch")
        reader = Reader()
        yield reader
        reader.finish()


def checkpoints(receipt, path=None):
    header = receipt["header"]
    total = count = outputs = payload = 0
    last_output = last_batch = EMPTY_HASH
    h = hashlib.blake2b()
    with opened(path or receipt["root"] / "checkpoints.jsonl", header["checkpoint_bytes"]) as stream:
        while True:
            raw = stream.readline(CHUNK + 1)
            if not raw: break
            if len(raw) > CHUNK or not raw.endswith(b"\n"):
                raise ValueError("oversized or truncated native prefix checkpoint")
            total += len(raw); h.update(raw); row = json.loads(raw); count += 1
            if (set(row) != {"batch_count", "output_count", "payload_bytes", "output_hash", "batch_hash"}
                    or row["batch_count"] != count or _integer(row["output_count"]) < outputs
                    or _integer(row["payload_bytes"]) < payload):
                raise ValueError("native prefix ordinal/counter mismatch")
            outputs, payload = row["output_count"], row["payload_bytes"]
            last_output, last_batch = _hash(row["output_hash"]), _hash(row["batch_hash"])
            yield row
    if (total != header["checkpoint_bytes"] or h.hexdigest() != header["checkpoint_hash"]
            or (count, outputs, payload, last_output, last_batch) != tuple(header[k] for k in
                ("batch_count", "output_count", "payload_bytes", "output_hash", "batch_hash"))):
        raise ValueError("native terminal receipt differs from consumed checkpoints")


def summarize(receipts, correct):
    """O(n*4096) bitmap memory; checkpoints streamed, never loaded as a list."""
    if not correct or len(set(correct)) != len(correct) or any(type(i) is not int or i not in receipts for i in correct):
        raise ValueError("invalid correct receipt set")
    first = receipts[correct[0]]["header"]; counts = first["counts"]
    if any(r["header"]["counts"] != counts or r["header"]["useful_bytes"] != first["useful_bytes"] for r in receipts.values()):
        raise ValueError("mixed native receipt populations")
    # Validate every receipt, including fixed faulty-node diagnostics, before credit.
    for replica, receipt in receipts.items():
        with ExitStack() as stack:
            local = {name: stack.enter_context(bitmap(receipt, name, replica)) for name in LOCAL}
            own = stack.enter_context(bitmap(receipt, "materialized", replica))
            for offset in range(0, (counts[replica]+7)//8, CHUNK):
                n = min(CHUNK, (counts[replica]+7)//8-offset)
                pieces = {key: f.read(n) for key, f in local.items()}; seen = own.read(n)
                for i in range(n):
                    a, ready, done, observed, wa, wc = (pieces[k][i] for k in LOCAL)
                    if ready & ~a or done & ~(a & observed) or wa & ~a or wc & ~done or observed != seen[i]:
                        raise ValueError("native admission/append-time eligibility relation mismatch")
        # Consume other origins even if faulty and therefore never useful.
        for origin in range(len(counts)):
            if origin == replica: continue
            with bitmap(receipt, "materialized", origin) as f:
                for offset in range(0, (counts[origin]+7)//8, CHUNK):
                    f.read(min(CHUNK, (counts[origin]+7)//8-offset))
    longest = max(correct, key=lambda i: receipts[i]["header"]["batch_count"])
    for replica in receipts:
        if replica in correct:
            for a, b in itertools.zip_longest(checkpoints(receipts[longest]), checkpoints(receipts[replica])):
                if b is not None and a != b: raise ValueError("correct native complete-block prefixes disagree")
        else:
            for _ in checkpoints(receipts[replica]): pass
    admitted = completed = everywhere = planned = window_admitted = window_done = 0
    credited = dict.fromkeys(correct, 0); origins = []
    for origin in correct:
        header = receipts[origin]["header"]; planned += counts[origin]
        desc = receipts[origin]["descriptors"]
        admitted += desc[("admitted", origin)]["ones"]; completed += desc[("eligible", origin)]["ones"]
        origins.append({"origin":origin, "planned":counts[origin], "admitted":desc[("admitted", origin)]["ones"],
            "completed":desc[("eligible", origin)]["ones"],
            "pending_admitted":desc[("admitted", origin)]["ones"]-desc[("eligible", origin)]["ones"],
            "not_admitted":counts[origin]-desc[("admitted", origin)]["ones"]})
        window_admitted += desc[("window_admitted", origin)]["ones"]; window_done += desc[("window_completed", origin)]["ones"]
        with ExitStack() as stack:
            own = stack.enter_context(bitmap(receipts[origin], "eligible", origin))
            peers = {i: stack.enter_context(bitmap(receipts[i], "materialized", origin)) for i in correct}
            for offset in range(0, (counts[origin]+7)//8, CHUNK):
                n = min(CHUNK, (counts[origin]+7)//8-offset); eligible = own.read(n)
                out = {i: f.read(n) for i, f in peers.items()}
                for j, value in enumerate(eligible):
                    shared = value
                    for i in correct:
                        credited[i] += (value & out[i][j]).bit_count(); shared &= out[i][j]
                    everywhere += shared.bit_count()
    reference = correct[0]; window_us = first["window_end_us"] - first["window_start_us"]; window_seconds = window_us / 1e6
    if window_us <= 0 or any(r["header"]["window_end_us"] - r["header"]["window_start_us"] != window_us for r in receipts.values()):
        raise ValueError("native receipt window durations differ")
    return {"planned": planned, "admitted": admitted, "not_admitted": planned-admitted, "origins":origins,
        "local_completed": completed, "unfinished": planned-completed,
        "all_correct_completed": everywhere, "all_correct_unfinished": planned-everywhere,
        "reference_replica": reference, "reference_m_out_bytes": receipts[reference]["header"]["payload_bytes"],
        "reference_unique_eligible_u_out_bytes": credited[reference]*first["useful_bytes"],
        "unique_eligible_output_by_replica": credited, "latency_available": False,
        "latency_quantiles": None, "deadline_misses": None,
        "window": {"completion_count": window_done, "unique_completion_tps": window_done/window_seconds,
            "admission_count": window_admitted, "admission_tps": window_admitted/window_seconds,
            "measurement_seconds": window_seconds,
            "boundary": "eligible own-origin events within each configured local monotonic window; actual traffic/CPU sample endpoints reported separately"},
        "agreement": {"replicas_agree_on_common_prefix": True, "complete_block_prefixes_verified": True,
            "batch_counts": {i: receipts[i]["header"]["batch_count"] for i in correct},
            "native_output_counts": {i: receipts[i]["header"]["output_count"] for i in correct},
            "scope": "source-bound native hook fingerprints over every raw native transaction and full block reference, including unknown/foreign/empty blocks",
            "native_order_fidelity": {"status": "incomplete", "reason": "independent signed native WAL-tail replay remains required; hook receipts do not establish it"}}}



def bind_wal_fidelity(receipts, proofs, correct):
    """Bind independent replay results to these exact source-bound receipts.

    This closes output-prefix byte/order fidelity only. Admission clocks and
    eligibility remain native-observer evidence; formal eligibility is separate.
    """
    if not correct or len(set(correct)) != len(correct) or any(type(i) is not int or i not in receipts or i not in proofs for i in correct):
        raise ValueError("missing correct-replica independent WAL proof")
    for replica in correct:
        proof = proofs[replica]; receipt = receipts[replica]; header = receipt["header"]
        if (proof.get("status") != "verified" or proof.get("receipt_header_sha256") != receipt["header_sha256"]
                or proof.get("exact_checkpoint_sequence_equal") is not True or proof.get("materialized_membership_equal") is not True
                or (header["mode"] == "full" and proof.get("full_journal_equal") is not True)
                or any(proof.get(a) != header[b] for a,b in (("batch_count","batch_count"),("native_output_count","output_count"),
                    ("payload_bytes","payload_bytes"),("output_hash","output_hash"),("batch_hash","batch_hash")))):
            raise ValueError("independent WAL proof differs from frozen native receipt")
    return {"status":"verified", "scope":"exact complete-block frozen native output prefix, including unknown and empty blocks, independently joined to signature-verified native WAL block bytes and locally persisted CommitData order",
        "not_established":["independent consensus commit certificate", "durable fsync", "admission or latency timestamps", "later native WAL suffix output"],
        "per_replica":{i:{k:proofs[i][k] for k in ("wal_sha256","receipt_header_sha256","batch_count","native_output_count","output_hash","batch_hash","covered_wal_record_end","later_wal_bytes_outside_prefix_claim","commit_subdag_blocks_after_frozen_prefix")} for i in correct},
        "formal_comparison_eligibility_changed":False}


def resource_window(receipts):
    rows = []
    for replica, receipt in sorted(receipts.items()):
        samples = receipt["header"].get("process_window", [])
        if type(samples) is not list or len(samples) > 2:
            raise ValueError("native process sample population differs")
        if len(samples) != 2:
            rows.append({"replica": replica, "available": False, "reason": "two common native process samples unavailable"})
            continue
        a, b = samples
        for row in samples:
            for key in ("elapsed_us", "user_cpu_us", "system_cpu_us", "peak_rss_bytes"):
                _integer(row[key])
        if (a["elapsed_us"] < receipt["header"]["window_start_us"]
                or b["elapsed_us"] < receipt["header"]["window_end_us"]
                or b["elapsed_us"] > receipt["header"]["frozen_us"]
                or b["elapsed_us"] <= a["elapsed_us"] or b["user_cpu_us"] < a["user_cpu_us"]
                or b["system_cpu_us"] < a["system_cpu_us"]):
            raise ValueError("native process samples moved backwards or outside observer boundaries")
        rows.append({"replica": replica, "available": True, "before": a, "after": b,
            "cpu_seconds": (b["user_cpu_us"]+b["system_cpu_us"]-a["user_cpu_us"]-a["system_cpu_us"])/1e6,
            "sampled_seconds": (b["elapsed_us"]-a["elapsed_us"])/1e6,
            "start_offset_us": a["elapsed_us"]-receipt["header"]["window_start_us"],
            "end_offset_us": b["elapsed_us"]-receipt["header"]["window_end_us"],
            "peak_rss_bytes": b["peak_rss_bytes"]})
    return {"per_replica": rows, "cpu_seconds": sum(r["cpu_seconds"] for r in rows) if all(r["available"] for r in rows) else None,
        "boundary": "native getrusage samples taken by the shared observer thread after configured local window boundaries; actual offsets retained; peak RSS is process high water"}
