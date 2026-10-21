"""Bounded Raptr application-materializer receipts, separate from consensus proof.

Every checkpoint ends a complete canonical section. Both observer modes retain
native validation, section FIFO, raw output fingerprints and finite bitmaps;
compact omits per-request timing and is ineligible for latency comparison.
"""
from contextlib import closing, contextmanager
import hashlib
from itertools import zip_longest
import json
import mmap
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import time

from native_cohort_store import journal_rows
from raptr_cohort import configuration

MAGIC = b"RAPAD001"
HEADER_BYTES = 72
FORMAT = "raptr-native-receipt-v1"
INITIAL = hashlib.sha3_256(b"Raptr-native-prefix-v1").digest()
MAX_CHECKPOINT_BYTES = 4 * 1024 * 1024
MAX_SECTION_BATCHES = 8192
MAX_EVIDENCE_BYTES = 128 * 1024**3


def digest(raw):
    return hashlib.sha3_256(raw).hexdigest()


def _uint(value, label):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"invalid Raptr {label}")
    return value


def _hex(value, size, label):
    if not isinstance(value, str) or len(value) != size * 2 or not re.fullmatch(r"[0-9a-f]*", value):
        raise ValueError(f"invalid Raptr {label}")
    return bytes.fromhex(value)


@contextmanager
def regular(path):
    path = Path(path)
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("Raptr receipt symlink")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Raptr receipt is not regular")
        yield stream
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError("Raptr receipt changed during collection")


def file_digest(path):
    value = hashlib.sha3_256()
    with regular(path) as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def prepare_plan(store, output, run_id, counts, useful_bytes):
    configuration(run_id, counts, useful_bytes)
    path = Path(output) / "observer-plan.json"
    with path.open("x") as stream:
        stream.write(json.dumps({"schema": 1, "run_id": run_id, "counts": list(counts), "useful_bytes": useful_bytes}, separators=(",", ":"))[:-1] + ',"identities":[')
        for origin, count in enumerate(counts):
            if origin:
                stream.write(",")
            stream.write("[")
            seen = 0
            for identity, sequence in store.db.execute("SELECT id,sequence FROM raptr_plan WHERE origin=? ORDER BY sequence", (origin,)):
                if sequence != seen:
                    raise ValueError("noncontiguous authenticated Raptr plan")
                _hex(identity, 32, "finite identity")
                if seen:
                    stream.write(",")
                stream.write(json.dumps(identity)); seen += 1
            if seen != count:
                raise ValueError("Raptr observer plan population differs")
            stream.write("]")
        stream.write("]}\n")
    return {"path": str(path), "sha3_256": file_digest(path), "run_id": run_id,
            "counts": list(counts), "useful_bytes": useful_bytes}


def admission_header(plan, origin):
    configuration(plan["run_id"], plan["counts"], plan["useful_bytes"])
    if type(origin) is not int or not 0 <= origin < len(plan["counts"]):
        raise ValueError("invalid Raptr admission origin")
    return MAGIC + bytes.fromhex(plan["run_id"]) + struct.pack("<QQ", origin, plan["counts"][origin]) + _hex(plan["sha3_256"], 32, "plan digest")


def prepare_admission(output, plan, origin):
    with (Path(output) / f"admission-{origin}.bits").open("xb") as stream:
        stream.write(admission_header(plan, origin))
        stream.write(bytes((plan["counts"][origin] + 7) // 8))


def prepare_admissions(output, plan):
    for origin in range(len(plan["counts"])):
        prepare_admission(output, plan, origin)


class AdmissionPublisher:
    """One origin writer; call while reserved ingress capacity is still locked."""
    def __init__(self, path, plan, origin):
        self.count = plan["counts"][origin]
        path = Path(path)
        if any(parent.is_symlink() for parent in (path, *path.parents)):
            raise ValueError("Raptr admission symlink")
        self.file = os.fdopen(os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)), "r+b")
        try:
            if self.file.read(HEADER_BYTES) != admission_header(plan, origin) or os.fstat(self.file.fileno()).st_size != HEADER_BYTES + (self.count + 7) // 8:
                raise ValueError("Raptr admission map differs from configuration")
            self.mapping = mmap.mmap(self.file.fileno(), 0)
        except Exception:
            self.file.close()
            raise

    def admit(self, sequence):
        if type(sequence) is not int or not 0 <= sequence < self.count:
            raise ValueError("Raptr admission sequence outside finite plan")
        offset = HEADER_BYTES + sequence // 8
        self.mapping[offset] = self.mapping[offset] | (1 << (sequence % 8))

    def close(self):
        self.mapping.close(); self.file.close()


def environment(output, plan, origin, mode):
    if mode not in ("full", "compact"):
        raise ValueError("unknown Raptr observer mode")
    output = Path(output)
    return {"RAPTR_OBSERVER_MODE": mode, "RAPTR_OBSERVER_PLAN": plan["path"],
            "RAPTR_OBSERVER_ORIGIN": str(origin), "RAPTR_RUN_ID": plan["run_id"],
            "RAPTR_OBSERVER_ADMISSION_PATH": str(output / f"admission-{origin}.bits"),
            "RAPTR_OBSERVER_RECEIPT_DIR": str(output / f"receipt-{origin}"),
            "RAPTR_OBSERVER_FREEZE_PATH": str(output / f"freeze-{origin}.json"),
            "RAPTR_OBSERVER_OUTPUT_PATH": str(output / f"output-{origin}.jsonl"),
            "RAPTR_OBSERVER_STAGES_PATH": str(output / f"stages-{origin}.jsonl")}


def arm_origin(output, plan, origin, requested_us):
    _uint(requested_us, "requested cutoff")
    path = Path(output) / f"freeze-{origin}.json"
    temporary = path.with_suffix(".tmp")
    with temporary.open("x") as stream:
        json.dump({"run_id": plan["run_id"], "requested_us": requested_us}, stream)
        stream.write("\n")
    os.replace(temporary, path)


def arm(output, plan, requested_us):
    for origin in range(len(plan["counts"])):
        arm_origin(output, plan, origin, requested_us)


def await_headers(output, nodes, processes, timeout=10, origins=None):
    origins = list(range(nodes) if origins is None else origins)
    deadline = time.monotonic() + timeout
    while True:
        if all((Path(output) / f"receipt-{index}/header.json").exists() for index in origins):
            return
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("Raptr validator exited before finite receipt")
        if time.monotonic() >= deadline:
            raise RuntimeError("Raptr complete-section receipt timed out")
        time.sleep(0.01)


def counters(output, nodes):
    result = {}
    for index in range(nodes):
        path = Path(output) / f"receipt-{index}/counters.json"
        if path.exists():
            with regular(path) as stream:
                raw = stream.read(128 * 1024 + 1)
            if len(raw) > 128 * 1024:
                raise ValueError("Raptr observer counters too large")
            result[index] = json.loads(raw)
    return result


def batch_info(value):
    """Decode the pinned native BatchInfo BCS, never its Display digest."""
    raw = _hex(value, 120, "BatchInfo BCS")
    author = raw[:32]
    batch_id, nonce, epoch, expiration = struct.unpack_from("<QQQQ", raw, 32)
    payload_digest = raw[64:96]
    count, size, gas = struct.unpack_from("<QQQ", raw, 96)
    exact = struct.pack("<Q", epoch) + author + struct.pack("<QQ", nonce, batch_id) + payload_digest
    return {"raw": raw, "exact_batch_id": exact.hex(), "epoch": epoch,
            "count": count, "bytes": size, "expiration": expiration, "gas": gas}


def section_payload_hash(infos):
    value = hashlib.sha3_256(struct.pack("<Q", len(infos)))
    for info in infos:
        value.update(struct.pack("<Q", len(info["raw"]))); value.update(info["raw"])
    return value.digest()


def section_hash(previous, section_id, payload_hash, first_index):
    raw = _hex(section_id, 33, "section identity")
    return hashlib.sha3_256(b"S" + previous + struct.pack("<Q", len(raw)) + raw + payload_hash + struct.pack("<Q", first_index)).digest()


def batch_hash(previous, exact_id, size, first_index):
    return hashlib.sha3_256(b"B" + previous + _hex(exact_id, 88, "exact batch identity") + struct.pack("<QQ", size, first_index)).digest()


def transaction_step(previous, index, request):
    return hashlib.sha3_256(b"T" + previous + struct.pack("<Q", index) + _hex(request, 32, "native transaction hash")).digest()


def load(output, plan, origin, mode, requested_us):
    admission_header(plan, origin)  # Validate trusted counts before reading files.
    if mode not in ("full", "compact"):
        raise ValueError("unknown Raptr observer mode")
    root = Path(output) / f"receipt-{origin}"
    with regular(root / "header.json") as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("Raptr receipt header too large")
    header = json.loads(raw)
    expected = {"schema": 1, "format": FORMAT, "run_id": plan["run_id"], "plan_sha3_256": plan["sha3_256"],
                "origin": origin, "counts": plan["counts"], "useful_bytes": plan["useful_bytes"],
                "mode": mode, "requested_us": requested_us}
    if not isinstance(header, dict) or any(header.get(key) != value for key, value in expected.items()):
        raise ValueError("Raptr receipt differs from finite configuration")
    for key in ("schema", "origin", "useful_bytes", "requested_us", "frozen_us", "checkpoint_count", "section_count", "batch_count", "unique_batch_count", "payload_bytes", "output_count", "checkpoint_bytes"):
        _uint(header.get(key), key)
    if any(type(value) is not int for value in header["counts"]):
        raise ValueError("Raptr count encoding differs")
    if header.get("failure") not in (None, ""):
        raise ValueError("Raptr observer failed: " + str(header["failure"])[:512])
    if not requested_us <= header["frozen_us"] <= requested_us + 10_000_000:
        raise ValueError("Raptr freeze endpoint outside declared envelope")
    if header["checkpoint_bytes"] > MAX_EVIDENCE_BYTES:
        raise ValueError("Raptr checkpoint evidence exceeds disk envelope")
    _hex(header["prefix_sha3_256"], 32, "terminal prefix")
    _hex(header["checkpoint_sha3_256"], 32, "checkpoint digest")
    streams = header.get("streams")
    if not isinstance(streams, list) or len(streams) != len(plan["counts"]) + 2:
        raise ValueError("Raptr bitmap streams differ")
    descriptors = {}
    for row in streams:
        if not isinstance(row, dict) or type(row.get("origin")) is not int or (row.get("name"), row["origin"]) in descriptors:
            raise ValueError("Raptr bitmap stream identity invalid")
        descriptors[(row.get("name"), row["origin"])] = row
    expected_keys = {("materialized", index) for index in range(len(plan["counts"]))} | {("own_seen", origin), ("own_eligible", origin)}
    if set(descriptors) != expected_keys:
        raise ValueError("Raptr bitmap streams differ")
    result = {"root": root, "header": header, "bits": {}, "header_sha256": hashlib.sha256(raw).hexdigest()}
    for (name, who), row in descriptors.items():
        count = plan["counts"][who]; size = (count + 7) // 8
        if row.get("path") != f"{name}-{who}.bits" or type(row.get("bytes")) is not int or row["bytes"] != size:
            raise ValueError("Raptr bitmap path/size differs")
        _uint(row.get("ones"), "bitmap popcount")
        with regular(root / row["path"]) as stream:
            bits = stream.read(size + 1)
        if len(bits) != size or (count % 8 and bits[-1] >> (count % 8)):
            raise ValueError("Raptr bitmap population/padding differs")
        if digest(bits) != row.get("sha3_256") or sum(byte.bit_count() for byte in bits) != row["ones"]:
            raise ValueError("Raptr bitmap fingerprint differs")
        result["bits"][(name, who)] = bits
    own = result["bits"][("materialized", origin)]
    seen, eligible = result["bits"][("own_seen", origin)], result["bits"][("own_eligible", origin)]
    if seen != own or any(e & ~s for e, s in zip(eligible, seen)):
        raise ValueError("Raptr eligible identity was not first seen/materialized")
    size = (plan["counts"][origin] + 7) // 8
    with regular(Path(output) / f"admission-{origin}.bits") as stream:
        admitted = stream.read(HEADER_BYTES + size + 1)
    if admitted[:HEADER_BYTES] != admission_header(plan, origin) or len(admitted) != HEADER_BYTES + size:
        raise ValueError("Raptr final admission map differs")
    result["admitted"] = admitted[HEADER_BYTES:]
    if plan["counts"][origin] % 8 and result["admitted"][-1] >> (plan["counts"][origin] % 8):
        raise ValueError("Raptr admission map padding differs")
    if any(e & ~a for e, a in zip(eligible, result["admitted"])):
        raise ValueError("Raptr eligible completion lacks application admission")
    for _ in checkpoints(result):
        pass
    return result


def checkpoints(receipt):
    """Same consumed bytes bind all structure, batch identities and final hash."""
    header = receipt["header"]
    value = hashlib.sha3_256(); size = checkpoint_count = sections = batches = unique = payload = output = 0
    prefix = INITIAL; section = None; pending = []; batch_offset = 0
    with closing(sqlite3.connect("")) as db, regular(receipt["root"] / "checkpoints.jsonl") as stream:
        db.execute("PRAGMA cache_size=-1024"); db.execute("PRAGMA temp_store=FILE"); db.execute("PRAGMA journal_mode=OFF")
        db.execute("CREATE TABLE batches(id TEXT PRIMARY KEY,bytes TEXT,count TEXT)")
        db.execute("CREATE TABLE slots(id TEXT PRIMARY KEY,next_subblock INTEGER)")
        while raw := stream.readline(MAX_CHECKPOINT_BYTES + 1):
            if len(raw) > MAX_CHECKPOINT_BYTES or not raw.endswith(b"\n"):
                raise ValueError("oversized or truncated Raptr checkpoint")
            value.update(raw); size += len(raw)
            if size > header["checkpoint_bytes"]:
                raise ValueError("Raptr checkpoint bytes exceed declared bound")
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError("Raptr checkpoint must be an object")
            for key in ("checkpoint_index", "first_index", "output_count"):
                _uint(row.get(key), key)
            if row["checkpoint_index"] != checkpoint_count or row["first_index"] != output:
                raise ValueError("Raptr checkpoint/output ordinal gap")
            after = _hex(row.get("prefix_sha3_256"), 32, "checkpoint prefix")
            if row.get("kind") == "section":
                if batch_offset != len(pending):
                    raise ValueError("Raptr section skips an unresolved batch head")
                if _uint(row.get("section_index"), "section ordinal") != sections or row["output_count"] != output:
                    raise ValueError("Raptr section ordinal/output differs")
                raw_id = _hex(row.get("section_id"), 33, "section identity")
                epoch, round_number, leader = struct.unpack_from("<QQQ", raw_id)
                kind = raw_id[24]; index = struct.unpack_from("<Q", raw_id, 25)[0]
                if leader >= len(header["counts"]) or kind not in (0, 1) or (kind == 0 and index != 0) or (kind == 1 and index >= 8):
                    raise ValueError("Raptr canonical section identity invalid")
                slot = raw_id[:24].hex()
                previous = db.execute("SELECT next_subblock FROM slots WHERE id=?", (slot,)).fetchone()
                if kind == 0:
                    if previous is not None:
                        raise ValueError("Raptr proofs section repeated")
                    db.execute("INSERT INTO slots VALUES(?,0)", (slot,))
                else:
                    if previous is None or previous[0] != index:
                        raise ValueError("Raptr subblock is not a contiguous prefix refinement")
                    db.execute("UPDATE slots SET next_subblock=? WHERE id=?", (index + 1, slot))
                infos = row.get("batch_infos_bcs_hex")
                if not isinstance(infos, list) or len(infos) > MAX_SECTION_BATCHES:
                    raise ValueError("Raptr section batch population exceeds envelope")
                pending = [batch_info(info) for info in infos]; batch_offset = 0
                if any(info["epoch"] != epoch for info in pending):
                    raise ValueError("Raptr section BatchInfo epoch differs")
                claimed = _hex(row.get("section_payload_sha3_256"), 32, "section payload digest")
                if claimed != section_payload_hash(pending):
                    raise ValueError("Raptr section payload fingerprint differs")
                if after != section_hash(prefix, row["section_id"], claimed, output):
                    raise ValueError("Raptr section rolling prefix differs")
                section = row["section_id"]; sections += 1
            elif row.get("kind") == "batch":
                if section is None or row.get("section_id") != section or batch_offset >= len(pending):
                    raise ValueError("Raptr batch lacks its canonical section")
                if _uint(row.get("batch_index"), "batch ordinal") != batches:
                    raise ValueError("Raptr batch ordinal gap")
                info = batch_info(row.get("batch_info_bcs_hex"))
                if info["raw"] != pending[batch_offset]["raw"] or row.get("exact_batch_id") != info["exact_batch_id"]:
                    raise ValueError("Raptr batch differs from canonical section order/identity")
                if _uint(row.get("payload_bytes"), "batch payload size") != info["bytes"] or row["output_count"] - output != info["count"]:
                    raise ValueError("Raptr native batch size/count differs")
                if type(row.get("unique_batch")) is not bool:
                    raise ValueError("Raptr batch uniqueness must be Boolean")
                previous = db.execute("SELECT bytes,count FROM batches WHERE id=?", (info["exact_batch_id"],)).fetchone()
                if row["unique_batch"] != (previous is None):
                    raise ValueError("Raptr batch uniqueness differs from first occurrence")
                if previous is not None and previous != (str(info["bytes"]), str(info["count"])):
                    raise ValueError("repeated Raptr batch payload size/count differs")
                if previous is None:
                    db.execute("INSERT INTO batches VALUES(?,?,?)", (info["exact_batch_id"], str(info["bytes"]), str(info["count"])))
                    unique += 1; payload += info["bytes"]
                if info["count"] == 0 and after != batch_hash(prefix, info["exact_batch_id"], info["bytes"], output):
                    raise ValueError("Raptr empty batch prefix differs")
                output = row["output_count"]; batches += 1; batch_offset += 1
            else:
                raise ValueError("unknown Raptr checkpoint kind")
            prefix = after; checkpoint_count += 1
            yield row
        if batch_offset != len(pending):
            raise ValueError("Raptr terminal prefix contains an unresolved section head")
    expected = (header["checkpoint_count"], header["section_count"], header["batch_count"], header["unique_batch_count"], header["payload_bytes"], header["output_count"], header["prefix_sha3_256"])
    if (checkpoint_count, sections, batches, unique, payload, output, prefix.hex()) != expected:
        raise ValueError("Raptr terminal receipt differs from complete checkpoints")
    if size != header["checkpoint_bytes"] or value.hexdigest() != header["checkpoint_sha3_256"]:
        raise ValueError("Raptr consumed checkpoint bytes differ from receipt")


def compare(receipts, correct):
    if not correct or len(set(correct)) != len(correct) or any(index not in receipts for index in correct):
        raise ValueError("invalid correct Raptr replica set")
    reference = max(correct, key=lambda index: receipts[index]["header"]["checkpoint_count"])
    reference_header = receipts[reference]["header"]
    for index in correct:
        if any(receipts[index]["header"][key] != reference_header[key] for key in ("run_id", "plan_sha3_256", "counts", "useful_bytes")):
            raise ValueError("Raptr replicas describe different finite plans")
        with closing(checkpoints(receipts[reference])) as longest, closing(checkpoints(receipts[index])) as candidate:
            for expected, row in zip_longest(longest, candidate):
                if row is not None and row != expected:
                    raise ValueError("Raptr canonical materialized prefixes disagree")
    return {"replicas_agree_on_common_prefix": True,
            "sequence_lengths": [receipts[index]["header"]["output_count"] for index in correct],
            "complete_section_lengths": [receipts[index]["header"]["section_count"] for index in correct],
            "scope": "Every correct complete canonical section prefix, exact QS batches and raw transaction ordinals, including unknown/empty/repeated outputs; source-bound receipt, not independent consensus proof"}


def summarize(receipts, correct):
    rows = []
    for origin in correct:
        receipt = receipts[origin]
        completed = bytearray(receipt["bits"][("own_eligible", origin)])
        for replica in correct:
            for offset, value in enumerate(receipts[replica]["bits"][("materialized", origin)]):
                completed[offset] &= value
        planned = receipt["header"]["counts"][origin]
        admitted = sum(byte.bit_count() for byte in receipt["admitted"])
        local = sum(byte.bit_count() for byte in receipt["bits"][("own_eligible", origin)])
        all_correct = sum(byte.bit_count() for byte in completed)
        rows.append({"origin": origin, "planned": planned, "admitted": admitted,
                     "origin_local_completed": local, "all_correct_completed": all_correct,
                     "unfinished": admitted - all_correct, "unadmitted": planned - admitted,
                     "all_correct_completed_bits": completed.hex()})
    keys = ("planned", "admitted", "origin_local_completed", "all_correct_completed", "unfinished", "unadmitted")
    return {**{key: sum(row[key] for row in rows) for key in keys}, "origins": rows,
            "latency_available": False, "comparison_eligible": False,
            "scope": "Exact signed finite identities, first-output application-admission eligibility and all-correct frozen materialization; compact has no request latency"}


def verify_full(receipt, path):
    prefix = INITIAL; ordinal = 0; previous_time = 0
    def events():
        nonlocal previous_time
        for row in journal_rows(path):
            timestamp = _uint(row.get("materialized_us"), "detailed materialization time")
            if not previous_time <= timestamp <= receipt["header"]["frozen_us"]:
                raise ValueError("Raptr detailed event outside monotonic frozen prefix")
            previous_time = timestamp
            yield row
    rows = events()
    with closing(rows), closing(checkpoints(receipt)) as boundaries:
        for checkpoint in boundaries:
            event = next(rows, None)
            fields = ("section_index", "section_id", "section_payload_sha3_256", "batch_infos_bcs_hex", "first_index") if checkpoint["kind"] == "section" else ("batch_index", "section_id", "exact_batch_id", "batch_info_bcs_hex", "payload_bytes", "unique_batch", "first_index")
            if event is None or event.get("event") != checkpoint["kind"] or any(event.get(key) != checkpoint[key] for key in fields):
                raise ValueError("Raptr detailed section/batch boundary differs")
            if checkpoint["kind"] == "section":
                prefix = section_hash(prefix, checkpoint["section_id"], bytes.fromhex(checkpoint["section_payload_sha3_256"]), ordinal)
            else:
                prefix = batch_hash(prefix, checkpoint["exact_batch_id"], checkpoint["payload_bytes"], ordinal)
                while ordinal < checkpoint["output_count"]:
                    event = next(rows, None)
                    if event is None or event.get("event") not in ("output", "uncredited_output") or event.get("output_index") != ordinal or event.get("exact_batch_id") != checkpoint["exact_batch_id"]:
                        raise ValueError("Raptr detailed raw output ordinal/batch differs")
                    if type(event.get("origin_eligible")) is not bool:
                        raise ValueError("Raptr detailed output lacks Boolean eligibility")
                    native_hash = event.get("native_txn_hash", event.get("request_id"))
                    if event.get("request_id") != native_hash:
                        raise ValueError("Raptr detailed request differs from native transaction hash")
                    prefix = transaction_step(prefix, ordinal, native_hash); ordinal += 1
            if prefix.hex() != checkpoint["prefix_sha3_256"]:
                raise ValueError("Raptr detailed raw output fingerprint differs")
        if next(rows, None) is not None or ordinal != receipt["header"]["output_count"] or prefix.hex() != receipt["header"]["prefix_sha3_256"]:
            raise ValueError("Raptr detailed output differs from terminal receipt")
    return {"verified": True, "output_count": ordinal, "prefix_sha3_256": prefix.hex(),
            "scope": "Detailed raw native transaction hashes match common observer; native payload validation remains in the unchanged native path/common materializer"}


def verify_local_eligibility(store, receipt):
    replica = receipt["header"]["origin"]
    for origin, count in enumerate(receipt["header"]["counts"]):
        bits = bytearray((count + 7) // 8)
        for body, in store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='outputs' ORDER BY ordinal", (replica,)):
            row = json.loads(body)
            if row["origin"] == origin:
                if not 0 <= row["sequence"] < count:
                    raise ValueError("Raptr detailed finite sequence outside plan")
                bits[row["sequence"] // 8] |= 1 << (row["sequence"] % 8)
        if bytes(bits) != receipt["bits"][("materialized", origin)]:
            raise ValueError("Raptr detailed materialized identities differ from receipt")
    count = receipt["header"]["counts"][replica]
    eligible = bytearray((count + 7) // 8)
    for body, in store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' ORDER BY ordinal", (replica,)):
        row = json.loads(body)
        if row["materialized_us"] is not None:
            eligible[row["sequence"] // 8] |= 1 << (row["sequence"] % 8)
    if bytes(eligible) != receipt["bits"][("own_eligible", replica)]:
        raise ValueError("Raptr detailed first-output eligibility differs from receipt")
    payload = sum(json.loads(body)["payload_bytes"] for body, in store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='batches'", (replica,)))
    if payload != receipt["header"]["payload_bytes"] or store.serial.get((replica, "batches"), 0) != receipt["header"]["unique_batch_count"] or store.serial.get((replica, "outputs"), 0) != receipt["header"]["output_count"]:
        raise ValueError("Raptr detailed output population/cost differs from receipt")
    return {"verified": True, "origin": replica, "eligible_identity_sha3_256": digest(eligible)}


def verify_admissions(path, receipt):
    origin = receipt["header"]["origin"]; count = receipt["header"]["counts"][origin]
    bits = bytearray((count + 7) // 8); seen = 0
    for row in journal_rows(path):
        if seen >= count or type(row.get("origin")) is not int or type(row.get("sequence")) is not int or row["origin"] != origin or row["sequence"] != seen:
            raise ValueError("Raptr ingress lost finite origin order")
        if row["admitted_us"] is not None:
            admitted = _uint(row["admitted_us"], "application admission time")
            if not row["scheduled_us"] <= admitted <= receipt["header"]["frozen_us"]:
                raise ValueError("Raptr application admission outside finite observation")
            bits[seen // 8] |= 1 << (seen % 8)
        seen += 1
    if seen != count or bytes(bits) != receipt["admitted"]:
        raise ValueError("Raptr admission publication differs from ingress journal")
    return {"verified": True, "admitted_identity_sha3_256": digest(bits)}
