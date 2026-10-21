"""Explicit faulty-sender schedules and native synchronous crypto meter snapshots."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_OMISSION_RECORD_BYTES = 64 * 1024
MAX_OMISSION_JOURNALS = 128
MAX_OMISSION_KINDS = 32


def add_arguments(parser):
    parser.add_argument("--omit-replica", type=int, help="Faulty sender omits its native payload/publication unit; must belong to the fixed faulty set")
    parser.add_argument("--omission-after", type=float, default=1)
    parser.add_argument("--omission-seconds", type=float, default=0.5)
    parser.add_argument("--publish-to-replica", type=int, action="append", default=[], help="Recipients still receiving the faulty source's publications")
    parser.add_argument("--omit-repair", action="store_true", help="Also suppress this faulty worker's payload repair replies (Autobahn only)")
    parser.add_argument("--attacker-rate", type=int, default=100, help="Extra tx/s from the omission source, excluded from all honest useful-work cohorts")
    parser.add_argument("--crypto-meter", choices=["off", "on"], default="off")


def validate(args, *, protocol):
    if args.attacker_rate < 0:
        raise ValueError("attacker rate must be nonnegative")
    if args.omit_replica is None:
        if args.publish_to_replica or args.omit_repair:
            raise ValueError("publication scope requires --omit-replica")
        return
    if args.omit_replica not in args.faulty_replica:
        raise ValueError("omission source must belong to the explicitly fixed faulty set")
    if not 0 <= args.omission_after < args.duration or not 0 < args.omission_seconds <= args.duration - args.omission_after:
        raise ValueError("finite omission interval must fit the measurement window")
    if any(i < 0 or i >= args.nodes or i == args.omit_replica for i in args.publish_to_replica):
        raise ValueError("publication recipients must be other committee identities")
    if protocol != "autobahn" and args.omit_repair:
        raise ValueError("native block publications and block repairs are inseparable in this adapter")
    if args.omit_replica == args.pause_replica:
        raise ValueError("use separate runs for semantic omission and whole-process pause")


def environment(args, output, index, peers, *, role="validator"):
    result = {}
    if args.crypto_meter == "on":
        result["BENCHMARK_CPU_PATH"] = str(output / f"crypto-{index}-{role}.json")
    if index == args.omit_replica:
        result.update(BENCHMARK_FAULT_CONTROL=str(output / "omission-interval.txt"),
                      BENCHMARK_FAULT_LOG=str(output / f"omissions-{index}-{role}.jsonl"),
                      BENCHMARK_FAULT_ALLOWED=",".join(str(peers[i]) for i in args.publish_to_replica),
                      BENCHMARK_FAULT_REPAIR="1" if args.omit_repair else "0",
                      BENCHMARK_FAULT_AUTHOR=str(index))
    return result


def arm(args, output, epoch_ns):
    if args.omit_replica is None:
        return None
    start = epoch_ns + round((args.warmup + args.omission_after) * 1e9)
    end = start + round(args.omission_seconds * 1e9)
    path = output / "omission-interval.txt"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(f"{start} {end}\n")
    os.replace(temporary, path)
    return {"faulty_source": args.omit_replica, "allowed_recipients": args.publish_to_replica,
            "start_monotonic_ns": start, "end_monotonic_ns": end,
            "attacker_rate": args.attacker_rate, "honest_offered_rate": args.rate,
            "attacker_useful_credit": 0, "omit_repair": args.omit_repair}


def collect_omissions(output):
    messages = volume = 0
    kinds, journals = {}, []
    for path in Path(output).glob("omissions-*.jsonl"):
        if len(journals) == MAX_OMISSION_JOURNALS:
            raise ValueError("native omission journal population exceeds the committee/role envelope")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("native omission journal must be a regular file")
            digest, count, size = hashlib.sha256(), 0, 0
            while True:
                raw = source.readline(MAX_OMISSION_RECORD_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_OMISSION_RECORD_BYTES or not raw.endswith(b"\n"):
                    raise ValueError("oversized or truncated native omission event")
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError("native omission event must be an object")
                kind, amount = row.get("kind"), row.get("serialized_bytes_omitted")
                if not isinstance(kind, str) or not 1 <= len(kind) <= 128:
                    raise ValueError("invalid native omission unit")
                if type(amount) is not int or not 0 <= amount < 2**64:
                    raise ValueError("native omission byte count must be a nonnegative u64")
                if kind not in kinds and len(kinds) == MAX_OMISSION_KINDS:
                    raise ValueError("native omission unit population exceeds the envelope")
                kinds[kind] = kinds.get(kind, 0) + 1
                volume += amount
                count += 1
                size += len(raw)
                digest.update(raw)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
                raise ValueError("native omission journal changed during collection")
            messages += count
            journals.append({"path": path.name, "events": count, "bytes": size, "sha256": digest.hexdigest()})
    return {"messages_omitted": messages, "serialized_bytes_omitted": volume,
            "by_native_unit": dict(sorted(kinds.items())), "journals": sorted(journals, key=lambda row: row["path"]),
            "note": "Omitted bytes are attempted publications, excluded from actual network transmissions. All actual traffic and retained attacker outputs remain charged."}


def cpu_snapshot(output):
    return {path.name: json.loads(path.read_text()) for path in sorted(output.glob("crypto-*.json"))}


def cpu_ledger(before, after, final):
    categories = ("ordinary_sign", "ordinary_verify", "ordinary_verify_batch", "ordinary_verify_batch_multi")
    def sum_fields(rows):
        return {kind: {field: sum(row["operations"][kind][field] for row in rows.values()) for field in ("calls", "thread_cpu_ns")} for kind in categories}
    start, end, whole = map(sum_fields, (before, after, final))
    delta = {kind: {field: end[kind][field] - start[kind][field] for field in start[kind]} for kind in categories}
    if any(value < 0 for row in delta.values() for value in row.values()):
        raise ValueError("native crypto CPU counters regressed")
    return {"schema": 1, "measurement": delta, "whole_run": whole,
            "sampling": "20 ms native snapshots; actual per-process sample boundaries retained, no wall-time reinterpretation as CPU",
            "before": before, "after": after, "final": final,
            "scope": "ordinary native protocol authentication, including signature preimage hashing/decoding; failed attempts charged",
            "transport_authentication": "separate from these ordinary protocol counters",
            "mmr_proof_cpu": {"status": "not_applicable", "reason": "these native baselines have no Delugi MMR proof operation"}}


def dependency_hashes(paths):
    return {str(path): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in paths}
