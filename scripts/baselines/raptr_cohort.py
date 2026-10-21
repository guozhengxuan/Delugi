"""Bounded authenticated Raptr workload and detailed application-output join.

This is the paper artifact's consensus-only application materializer, not VM
execution. Application admission is the common endpoint; native mempool
insertion and own batch readiness are separate, optional diagnostics.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct

from mysticeti_wal import Ed25519Verifier, Reader
from native_cohort_store import journal_rows

MAGIC = b"RAPCOH01"
MAX_POPULATION = 5_000_000
MAX_TRANSACTION_BYTES = 1024 * 1024


class BCSReader(Reader):
    def uleb(self):
        value = 0
        for index in range(5):
            byte = self.integer(1)
            value |= (byte & 127) << (7 * index)
            if not byte & 128:
                if (index and byte == 0) or value > 0xffffffff:
                    raise ValueError("noncanonical Raptr BCS ULEB128")
                return value
        raise ValueError("Raptr BCS ULEB128 exceeds u32")

    def vector(self):
        return self.take(self.uleb())


def transaction_hash(serialized):
    return hashlib.sha3_256(hashlib.sha3_256(b"APTOS::Transaction").digest() + b"\0" + serialized).hexdigest()


def configuration(run_id, counts, useful_bytes):
    if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("invalid Raptr finite run identity")
    if not isinstance(counts, (list, tuple)) or not 1 <= len(counts) <= 31 or any(type(n) is not int or n < 0 for n in counts) or sum(counts) > MAX_POPULATION:
        raise ValueError("Raptr finite population exceeds declared envelope")
    if type(useful_bytes) is not int or not 0 < useful_bytes <= MAX_TRANSACTION_BYTES - 1024:
        raise ValueError("invalid Raptr useful payload size")


def decode_signed_workload(serialized, verifier=None):
    if len(serialized) > MAX_TRANSACTION_BYTES:
        raise ValueError("Raptr transaction exceeds bounded decoding envelope")
    reader = BCSReader(serialized)
    sender, native_sequence = reader.take(32), reader.integer(8)
    if reader.uleb() != 0:
        raise ValueError("expected Raptr native Script payload")
    code = reader.vector()
    if reader.uleb() != 0 or reader.uleb() != 0:
        raise ValueError("expected empty Raptr fixture script arguments")
    reader.integer(8); reader.integer(8); reader.integer(8)
    if reader.integer(1) != 4:
        raise ValueError("expected Raptr native test ChainId")
    signed_message = hashlib.sha3_256(b"APTOS::RawTransaction").digest() + serialized[:reader.pos]
    if reader.uleb() != 0:
        raise ValueError("expected Raptr native Ed25519 authenticator")
    public_key, signature = reader.vector(), reader.vector()
    reader.finish()
    (verifier or Ed25519Verifier()).verify(public_key, signature, signed_message)
    if sender != hashlib.sha3_256(public_key + b"\0").digest():
        raise ValueError("Raptr native signer does not bind sender")
    if len(code) < 48 or code[:8] != MAGIC:
        raise ValueError("expected Raptr finite workload marker")
    origin, sequence, useful = struct.unpack_from("<QQQ", code, 24)
    if origin >= 31 or sequence != native_sequence or useful != len(code) - 48 or useful == 0:
        raise ValueError("Raptr signed finite metadata differs")
    if any(byte != (origin + sequence + index) % 251 for index, byte in enumerate(code[48:])):
        raise ValueError("Raptr signed useful content differs")
    return {"request_id": transaction_hash(serialized), "run_id": code[8:24].hex(),
            "origin": origin, "sequence": sequence, "useful_bytes": useful,
            "serialized_bytes": len(serialized), "sender": sender.hex(), "public_key": public_key.hex()}


def iter_plan(path, run_id, origin, count, useful_bytes):
    configuration(run_id, [count], useful_bytes)
    if type(origin) is not int or not 0 <= origin < 31:
        raise ValueError("invalid Raptr origin")
    seen, signer = 0, None
    verifier = Ed25519Verifier()
    for row in journal_rows(path):
        if seen >= count:
            raise ValueError("Raptr finite plan count mismatch")
        raw = row.get("bcs_hex")
        if not isinstance(raw, str) or len(raw) > MAX_TRANSACTION_BYTES * 2 or not re.fullmatch(r"(?:[0-9a-f]{2})+", raw):
            raise ValueError("invalid bounded native BCS hex")
        identity = decode_signed_workload(bytes.fromhex(raw), verifier)
        for key in ("request_id", "run_id", "origin", "sequence", "useful_bytes", "serialized_bytes"):
            if row.get(key) != identity[key] or (key in ("origin", "sequence", "useful_bytes", "serialized_bytes") and type(row.get(key)) is not int):
                raise ValueError(f"Raptr plan differs from authenticated BCS: {key}")
        if identity["run_id"] != run_id or identity["origin"] != origin or identity["sequence"] != seen or identity["useful_bytes"] != useful_bytes:
            raise ValueError("Raptr plan differs from finite configuration")
        if signer is not None and signer != identity["public_key"]:
            raise ValueError("Raptr origin changed signed sender")
        signer = identity["public_key"]
        seen += 1
        yield row | {"sender": identity["sender"], "public_key": signer}
    if seen != count:
        raise ValueError("Raptr finite plan count mismatch")


def prepare_plan_store(store, plan_paths, run_id, counts, useful_bytes):
    configuration(run_id, counts, useful_bytes)
    if len(plan_paths) != len(counts):
        raise ValueError("Raptr finite plan origin count differs")
    store.db.execute("CREATE TABLE raptr_plan(id TEXT PRIMARY KEY, origin INTEGER, sequence INTEGER, useful INTEGER, UNIQUE(origin,sequence))")
    encoded, keys = set(), {}
    for origin, path in enumerate(plan_paths):
        for row in iter_plan(path, run_id, origin, counts[origin], useful_bytes):
            encoded.add(row["serialized_bytes"])
            keys[origin] = row["public_key"]
            store.db.execute("INSERT INTO raptr_plan VALUES(?,?,?,?)", (row["request_id"], origin, row["sequence"], useful_bytes))
            if row["sequence"] % 1024 == 0:
                store.db.commit()
    if len(set(keys.values())) != len(keys):
        raise ValueError("Raptr finite origins share a signer")
    store.db.commit()
    return {"native_serialized_transaction_bytes": sorted(encoded), "origin_public_keys": keys,
            "source": "independently verified Raptr finite Ed25519 signed native BCS"}


def _uint(value, name):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError(f"invalid Raptr {name}")
    return value


def collect_store(store, replica, admitted, events, epoch_us, warmup_us, duration_us,
                  drain_us, observed_us=None, stages=()):
    """Stream exact raw ordinals and finite admission eligibility into schema2.

    Unknown/repeated native transactions remain outputs, with distinct actual
    ordinals. Only the first eligible own-origin observation sets completion.
    Detailed journals must already be bound to complete receipt checkpoints.
    """
    declared = epoch_us + warmup_us + duration_us + drain_us
    deadline = declared if observed_us is None else _uint(observed_us, "freeze time")
    if deadline < declared:
        raise ValueError("Raptr freeze precedes declared cutoff")
    store.metadata[replica] = {
        "output_index_base": 0, "window_start_us": epoch_us + warmup_us,
        "window_end_us": epoch_us + warmup_us + duration_us, "observed_us": deadline,
        "declared_observed_us": declared, "batch_ready_available": False,
        "batch_ready_precedes_materialization": False,
        "output_sequence_scope": "complete canonical Raptr application materializer output, including unknown and repeated native identities; source-bound observer, not independent consensus proof",
    }
    next_request = 0
    for original in admitted:
        row = dict(original)
        known = store.db.execute("SELECT origin,sequence,useful FROM raptr_plan WHERE id=?", (row["request_id"],)).fetchone()
        if known != (replica, next_request, row["useful_bytes"]) or row["origin"] != replica or row["sequence"] != next_request:
            raise ValueError("Raptr ingress differs from authenticated finite origin plan")
        if row.get("materialized_us") is not None or row.get("batch_ready_us") is not None:
            raise ValueError("Raptr ingress must not fabricate native output stages")
        store.put(replica, "requests", row)
        next_request += 1
    planned = store.db.execute("SELECT count(*) FROM raptr_plan WHERE origin=?", (replica,)).fetchone()[0]
    if next_request != planned:
        raise ValueError("Raptr ingress lost finite planned requests")
    store.db.execute("CREATE TABLE IF NOT EXISTS raptr_seen(replica INTEGER,id TEXT,eligible INTEGER,PRIMARY KEY(replica,id))")
    next_output = 0
    for event in events:
        kind = event.get("event")
        timestamp = _uint(event.get("materialized_us"), "materialization time")
        if timestamp > deadline:
            raise ValueError("Raptr detailed output exceeds frozen prefix")
        if kind == "section":
            continue
        if kind == "batch":
            if type(event.get("unique_batch")) is not bool:
                raise ValueError("Raptr batch uniqueness must be Boolean")
            if event["unique_batch"]:
                store.put(replica, "batches", {key: event[key] for key in ("exact_batch_id", "payload_bytes", "materialized_us")})
            continue
        if kind not in ("output", "uncredited_output"):
            raise ValueError("unknown Raptr detailed output event")
        if type(event.get("origin_eligible")) is not bool:
            raise ValueError("Raptr output requires Boolean first-output eligibility")
        if _uint(event.get("output_index"), "output ordinal") != next_output:
            raise ValueError("Raptr output ordinal gap")
        next_output += 1
        if store.db.execute("SELECT 1 FROM rows WHERE replica=? AND stream='batches' AND id=?", (replica, event["exact_batch_id"])).fetchone() is None:
            raise ValueError("Raptr output precedes its exact materialized batch")
        row = {key: event[key] for key in ("request_id", "origin", "sequence", "useful_bytes", "output_index", "exact_batch_id", "materialized_us")}
        known = store.db.execute("SELECT origin,sequence,useful FROM raptr_plan WHERE id=?", (row["request_id"],)).fetchone()
        if known is not None:
            if kind != "output" or known != (row["origin"], row["sequence"], row["useful_bytes"]):
                raise ValueError("Raptr native output differs from signed finite identity")
            if row["origin"] == replica:
                previous = store.db.execute("SELECT eligible FROM raptr_seen WHERE replica=? AND id=?", (replica, row["request_id"])).fetchone()
                eligible = event["origin_eligible"]
                if previous is not None and not previous[0] and eligible:
                    raise ValueError("Raptr pre-admission output gained retroactive eligibility")
                if previous is None:
                    store.db.execute("INSERT INTO raptr_seen VALUES(?,?,?)", (replica, row["request_id"], int(eligible)))
                    if eligible:
                        own = store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' AND id=?", (replica, row["request_id"])).fetchone()
                        admitted_at = json.loads(own[0])["admitted_us"]
                        if admitted_at is None or timestamp < admitted_at:
                            raise ValueError("Raptr eligible output precedes application admission")
                        store.stage(replica, row["request_id"], "materialized_us", timestamp, first=True)
            elif event["origin_eligible"]:
                raise ValueError("Raptr foreign output claims local eligibility")
        else:
            if kind != "uncredited_output" or event["origin_eligible"]:
                raise ValueError("Raptr unknown native output claims finite eligibility")
            row.update(origin=-1, sequence=0, useful_bytes=0)
        store.put(replica, "outputs", row)
    for event in stages:
        if event.get("event") not in ("native_admitted", "batch_ready"):
            raise ValueError("unknown Raptr native stage event")
        timestamp = _uint(event.get("observed_us"), "native stage time")
        if timestamp > deadline:
            # Native processing continues after observer freeze; preserve its raw
            # journal but do not turn later work into earlier completion evidence.
            continue
        known = store.db.execute("SELECT origin FROM raptr_plan WHERE id=?", (event["request_id"],)).fetchone()
        if known != (replica,):
            continue
        own = store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' AND id=?", (replica, event["request_id"])).fetchone()
        row = json.loads(own[0])
        if row["admitted_us"] is None or timestamp < row["admitted_us"]:
            # An independently replayed signed request can be natively inserted
            # before application admission; keep it diagnostic, not own-ready.
            continue
        field = "batch_ready_us" if event["event"] == "batch_ready" else "native_admitted_us"
        store.stage(replica, event["request_id"], field, timestamp, first=True)
    store.db.commit()
