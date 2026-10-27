#!/usr/bin/env python3
"""Build and measure the pinned official Mysticeti paper artifact on localhost.

The benchmark uses native validator processes, benchmark-genesis and internal
synthetic transaction generators. It does not replace the protocol or disable
cryptography. Prometheus commit metrics are measured after a warmup, separately
at each replica; their counts must never be added as unique system throughput.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
import traceback
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import network_delay
import cohort_metrics
sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_faults
import native_cohort_store
import mysticeti_receipts
import mysticeti_wal

SOURCE = ROOT / "benchmarks/baselines/mysticeti"
COMMIT = "96fd83154bb5e168def9a81ee8f3e90e94e46a2e"
REMOTE = "https://github.com/asonnino/mysticeti.git"
CACHE = ROOT / "benchmarks/.cache"
RUSTUP_HOME = ROOT / "benchmarks/toolchains/mysticeti"
CARGO_HOME = CACHE / "mysticeti-cargo"
TARGET = CACHE / "mysticeti-target"
BINARY = TARGET / "release/mysticeti"
TOOLCHAIN = "1.78"
PATCH = ROOT / "benchmarks/patches/mysticeti-local.patch"
TRANSACTION_ENCODING_OVERHEAD = 8  # bincode Vec<u8> length


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run_logged(command, output, manifest, *, cwd=ROOT, env=None):
    manifest["commands"].append({"argv": list(map(str, command)), "cwd": str(cwd), "log": str(output)})
    with open(output, "wb") as stream:
        subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)


def ensure_patch():
    expected = PATCH.read_bytes()
    current = subprocess.check_output(["git", "-C", str(SOURCE), "diff", "HEAD"])
    if current == expected:
        return
    if current:
        raise RuntimeError("Mysticeti checkout differs from the recorded instrumentation patch")
    subprocess.run(["git", "-C", str(SOURCE), "apply", "--check", str(PATCH)], check=True)
    subprocess.run(["git", "-C", str(SOURCE), "apply", str(PATCH)], check=True)
    if subprocess.check_output(["git", "-C", str(SOURCE), "diff", "HEAD"]) != expected:
        raise RuntimeError("Applied Mysticeti patch differs from the recorded patch")


def build(output, manifest):
    CACHE.mkdir(parents=True, exist_ok=True)
    if not SOURCE.exists():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        run_logged(["git", "clone", REMOTE, str(SOURCE)], output / "clone.log", manifest)
        run_logged(["git", "-C", str(SOURCE), "checkout", "--detach", COMMIT], output / "checkout.log", manifest)
    actual = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip()
    if actual != COMMIT:
        raise RuntimeError(f"Expected source {COMMIT}, found {actual}; refusing to change an existing checkout")
    ensure_patch()
    env = os.environ.copy()
    env.update(RUSTUP_HOME=str(RUSTUP_HOME), CARGO_HOME=str(CARGO_HOME), CARGO_TARGET_DIR=str(TARGET),
               CARGO_INCREMENTAL="0", CARGO_PROFILE_RELEASE_DEBUG="0")
    installed = subprocess.run(["rustup", "toolchain", "list"], env=env, capture_output=True, text=True)
    if not any(line.startswith("1.78-") for line in installed.stdout.splitlines()):
        run_logged(["rustup", "toolchain", "install", TOOLCHAIN, "--profile", "minimal"], output / "toolchain.log", manifest, env=env)
    run_logged(["cargo", "+" + TOOLCHAIN, "build", "--release", "--locked", "-p", "mysticeti", "--jobs", "1"], output / "build.log", manifest, cwd=SOURCE, env=env)
    manifest["toolchain"] = subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], env=env, text=True)
    manifest["build_environment"] = {name: env[name] for name in ("RUSTUP_HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "CARGO_PROFILE_RELEASE_DEBUG")}
    write_json(TARGET / "build-provenance.json", {"source_commit": COMMIT, "binary_sha256": sha256(BINARY),
        "cargo_lock_sha256": sha256(SOURCE / "Cargo.lock"), "source_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "-C", str(SOURCE), "diff", "HEAD"])).hexdigest(), "toolchain": manifest["toolchain"],
        "environment": manifest["build_environment"], "commands": manifest["commands"], "build_directory": str(output),
        "abi": {"platform":platform.platform(),"machine":platform.machine(),"libc":list(platform.libc_ver())}})


def parse_metrics(raw):
    values = {}
    for line in raw.splitlines():
        if line and not line.startswith("#"):
            key, value, *_ = line.split()
            values[key] = float(value)
    return values


def snapshot(port):
    started = time.monotonic_ns()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/metrics", timeout=3) as response:
        raw = response.read().decode()
    ended = time.monotonic_ns()
    return {"request_started_monotonic_ns": started, "response_received_monotonic_ns": ended,
            "midpoint_monotonic_ns": (started + ended) // 2, "raw": raw, "values": parse_metrics(raw)}


def snapshots(ports):
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as executor:
        return list(executor.map(snapshot, ports))


def allocate_ports(count):
    # The pinned transport identifies peers by outgoing_source_port / 10.
    # Thus advertised TCP ports must be <=6553, and their 10x ports must be free.
    if count < 8 or count % 2:
        raise ValueError("Expected network and metrics ports for n >=4 replicas")
    replicas = count // 2
    listeners, network_ports = [], []
    try:
        candidates = list(range(2000, 6000))
        random.SystemRandom().shuffle(candidates)
        for candidate in candidates:
            pair = []
            try:
                for port in (candidate, candidate * 10):
                    listener = socket.socket()
                    pair.append(listener)
                    listener.bind(("0.0.0.0", port))
            except OSError:
                for listener in pair:
                    listener.close()
                continue
            listeners.extend(pair)
            network_ports.append(candidate)
            if len(network_ports) == replicas:
                break
        if len(network_ports) != replicas:
            raise RuntimeError("Cannot find enough free native network/source port pairs")
        metrics_ports = []
        for _ in range(replicas):
            listener = socket.socket()
            listener.bind(("0.0.0.0", 0))
            listeners.append(listener)
            metrics_ports.append(listener.getsockname()[1])
        return network_ports + metrics_ports
    finally:
        for listener in listeners:
            listener.close()


def check_running(processes):
    for index, process in enumerate(processes):
        if process.poll() is not None:
            raise RuntimeError(f"Validator {index} exited early with {process.returncode}; see validator-{index}.log")


def wait_alive(processes, duration):
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        check_running(processes)
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))


def cleanup_owned_children(processes, streams):
    """Use the retained Popen handles; an exit race must not skip cleanup."""
    errors = []
    for index, process in enumerate(processes):
        try:
            if process.poll() is not None:
                continue
            try:
                process.send_signal(signal.SIGCONT)
            except ProcessLookupError:
                continue  # It exited after poll; the wait pass still reaps it.
            process.terminate()
        except ProcessLookupError:
            pass
        except Exception as error:
            errors.append({"replica": index, "stage": "continue/terminate", "error": f"{type(error).__name__}: {error}"})
    for index, process in enumerate(processes):
        try:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        except Exception as error:
            errors.append({"replica": index, "stage": "wait/kill", "error": f"{type(error).__name__}: {error}"})
    for index, stream in enumerate(streams):
        try:
            stream.close()
        except Exception as error:
            errors.append({"stream": index, "stage": "close", "error": f"{type(error).__name__}: {error}"})
    return errors


def metric_delta(before, after, key):
    if key not in before["values"] or key not in after["values"]:
        raise RuntimeError(f"Required metric missing from a snapshot: {key}")
    start, end = before["values"][key], after["values"][key]
    if not math.isfinite(start) or not math.isfinite(end) or start < 0 or end < start:
        raise RuntimeError(f"Counter is invalid or regressed: {key}")
    return end - start


def summarize(before, after, index, *, own_origin=False):
    prefix = "benchmark_origin_latency_s" if own_origin else "latency_s"
    label = f'origin="{index}"' if own_origin else 'workload="shared"'
    count = metric_delta(before, after, f"{prefix}_count{{{label}}}")
    elapsed = (after["midpoint_monotonic_ns"] - before["midpoint_monotonic_ns"]) / 1e9
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise RuntimeError("Measurement interval must be finite and positive")
    latency_sum = metric_delta(before, after, f"{prefix}_sum{{{label}}}")
    buckets = []
    for key in after["values"]:
        match = re.fullmatch(rf'{prefix}_bucket\{{(?:{label},le="([^"]+)"|le="([^"]+)",{label})\}}', key)
        if match:
            upper = float(match[1] or match[2])
            buckets.append((upper, metric_delta(before, after, key)))
    bounds = {}
    for percentile in (50, 95, 99):
        threshold = count * percentile / 100
        bound = next((upper for upper, cumulative in sorted(buckets) if count and cumulative >= threshold), math.inf)
        bounds[f"p{percentile}_histogram_upper_bound_ms"] = bound * 1000 if math.isfinite(bound) else None
    return {"authority": index, "measurement_seconds": elapsed, "committed_transaction_observations": int(count),
            "commit_throughput_tx_s": count / elapsed, "mean_generation_to_commit_latency_ms": latency_sum / count * 1000 if count else None,
            **bounds, "histogram_delta": [{"upper_bound_seconds": upper if math.isfinite(upper) else "+Inf", "count": int(count)} for upper, count in sorted(buckets)]}


def summarize_instrumentation(before, after, index, transaction_size):
    elapsed = (after["midpoint_monotonic_ns"] - before["midpoint_monotonic_ns"]) / 1e9
    if not math.isfinite(elapsed) or elapsed <= 0:
        raise RuntimeError("Measurement interval must be finite and positive")
    keys = {
        "replica_tcp_written_bytes": "benchmark_tcp_written_bytes",
        "replica_tcp_read_bytes": "benchmark_tcp_read_bytes",
        "enqueued_transactions": "benchmark_enqueued_transactions",
        "enqueued_opaque_transaction_bytes": "benchmark_enqueued_transaction_bytes",
        "enqueued_encoded_transaction_bytes": "benchmark_enqueued_encoded_transaction_bytes",
    }
    result = {name: metric_delta(before, after, key) for name, key in keys.items()}
    if any(value != int(value) for value in result.values()):
        raise RuntimeError("Instrumented byte and transaction counters must be integers")
    result = {name: int(value) for name, value in result.items()}
    for snap in (before, after):
        if snap["values"].get("benchmark_transaction_encoded_size_bytes") != transaction_size:
            raise RuntimeError("Runtime canonical transaction size differs from requested size")
    result.update(authority=index, measurement_seconds=elapsed,
                  measured_enqueued_tx_s=result["enqueued_transactions"] / elapsed,
                  replica_tcp_written_bytes_per_second=result["replica_tcp_written_bytes"] / elapsed,
                  encoded_byte_count_matches_transaction_count=(result["enqueued_encoded_transaction_bytes"] == result["enqueued_transactions"] * transaction_size))
    return result


def comparison_summary(metrics, own_origin_metrics, instrumentation, args):
    elapsed = statistics.mean(node["measurement_seconds"] for node in instrumentation)
    completed = sum(node["committed_transaction_observations"] for node in own_origin_metrics)
    generated = sum(node["enqueued_transactions"] for node in instrumentation)
    written = sum(node["replica_tcp_written_bytes"] for node in instrumentation)
    return {
        "protocol": "mysticeti", "replicas": getattr(args, "nodes", 4), "offered_tx_s": args.rate,
        "bound_ms": args.bound_ms, "leader_timeout_ms": args.bound_ms,
        "bound_mapping": "Experiment mapping: native leader-readiness timeout T = 1 * Delta; quorum-clock gating remains unchanged.",
        "transaction_bytes": args.transaction_size, "ingress_batch_ms": args.ingress_batch_ms, "warmup_seconds": args.warmup,
        "measurement_seconds": elapsed, "unique_completion_tps": completed / elapsed,
        "mean_latency_ms": sum((node["mean_generation_to_commit_latency_ms"] or 0) * node["committed_transaction_observations"] for node in own_origin_metrics) / completed if completed else None,
        "latency_endpoint": "Generation UTC timestamp (millisecond resolution) to linearized payload traversal at the transaction's originating replica, after sub-DAG linearization and payload availability, before subsequent WAL commit-state processing; no application execution.",
        "traffic_boundary": "successful_replica_tcp_stream_writes",
        "replica_tcp_written_bytes": written,
        "replica_tcp_read_bytes": sum(node["replica_tcp_read_bytes"] for node in instrumentation),
        "replica_tcp_written_bytes_per_second": written / elapsed,
        "completion_count": completed, "generated_count": generated,
        "generation_tps": generated / elapsed,
        "completion_count_scope": "Sum of disjoint own-origin transaction commit counts, one origin at each replica, over that replica's scrape interval.",
        "all_replica_commit_tps_min": min(node["commit_throughput_tx_s"] for node in metrics),
        "all_replica_commit_tps_max": max(node["commit_throughput_tx_s"] for node in metrics),
        "end_pending_generated_transactions_at_origins": None,
    }



def audit_native_frozen_prefix(output, receipts, correct):
    """Offline fidelity gate after every owned native child has been reaped."""
    keys = mysticeti_wal.committee_keys(output / "genesis/committee.yaml")
    proofs = {}
    for replica, receipt in sorted(receipts.items()):
        database = output / f"wal-prefix-{replica}.sqlite"
        proof = mysticeti_wal.verify_receipt_prefix(output / f"genesis/storage-{replica}/wal", keys, receipt, database,
            journal=output / f"cohort-{replica}.jsonl" if receipt["header"]["mode"] == "full" else None)
        proof["derived_index_sha256"] = sha256(database)
        proof["derived_index_bytes"] = database.stat().st_size
        database.unlink()
        proof["derived_index_removed"] = True
        write_json(output / f"wal-prefix-{replica}.json", proof)
        proofs[replica] = proof
    return mysticeti_receipts.bind_wal_fidelity(receipts, proofs, correct)


def finite_window_summary(finite):
    """Replace legacy scrape populations with event-latched finite membership."""
    return {**finite["window"],
        "completion_count_scope":"Eligible own-origin native outputs in each configured local monotonic window; one origin per replica, excluding pre-admission and foreign-origin output",
        "generated_count":finite["window"]["admission_count"], "generation_tps":finite["window"]["admission_tps"],
        "end_pending_generated_transactions_at_origins":[row["pending_admitted"] for row in finite["origins"]],
        "end_pending_scope":"Admitted minus first eligible output at each origin's actual complete-block observer prefix freeze",
        "end_not_admitted_transactions_at_origins":[row["not_admitted"] for row in finite["origins"]]}


def check_leader_prefixes(output, replicas=4):
    sequences = []
    for index in range(replicas):
        sequence = []
        for line in (output / f"validator-{index}.log").read_text().splitlines():
            match = re.search(r'Committed (\[.*\])', line)
            if match:
                sequence.extend(re.sub(r"\(\d+ms\)$", "", item) for item in json.loads(match[1]))
        sequences.append(sequence)
    minimum = min(map(len, sequences))
    if minimum <= 0:
        raise RuntimeError("No committed leader references found in native debug logs")
    prefixes = [sequence[:minimum] for sequence in sequences]
    if any(prefix != prefixes[0] for prefix in prefixes):
        raise RuntimeError("Committed leader authority/round sequences disagree")
    write_json(output / "committed-leader-sequences.json", sequences)
    return {"common_prefix_length": minimum, "sequence_lengths": list(map(len, sequences)),
            "common_prefix_sha256": hashlib.sha256(json.dumps(prefixes[0]).encode()).hexdigest(),
            "scope": "Native debug references contain only leader authority and round, not block digest or transaction order."}


def cohort_request_id(origin, sequence, useful_bytes):
    payload = (b"DLGCOH01" + origin.to_bytes(8, "little") + sequence.to_bytes(8, "little")
               + useful_bytes.to_bytes(8, "little")
               + bytes((origin + sequence + i) % 251 for i in range(useful_bytes)))
    return f"{origin}:{sequence}:{hashlib.blake2b(payload).digest()[:32].hex()}"


def read_cohort(path, replica):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    starts = [row for row in events if row["event"] == "start"]
    if len(starts) != 1:
        raise RuntimeError("Exactly one native monotonic cohort start is required")
    start = starts[0]
    if start["origin"] != replica:
        raise RuntimeError("Native cohort origin disagrees with validator identity")
    requests = {}
    for sequence in range(start["count"]):
        key = cohort_request_id(replica, sequence, start["useful_bytes"])
        requests[key] = {"request_id": key, "origin": replica, "sequence": sequence,
                         "useful_bytes": start["useful_bytes"],
                         "scheduled_us": start["elapsed_us"] + native_cohort_store.native_arrival_offset(start,sequence),
                         "admitted_us": None, "batch_ready_us": None, "materialized_us": None}
    ledger = {key: start[key] for key in ("window_start_us", "window_end_us", "observed_us")}
    ledger.update(requests=list(requests.values()), outputs=[], batches=[], output_index_base=0,
                  batch_ready_precedes_materialization=False)
    for row in events:
        if row.get("elapsed_us", 0) > ledger["observed_us"]:
            continue
        event = row["event"]
        if event in ("admitted", "batch_ready"):
            request = requests.get(row["request_id"])
            if request is None:
                raise RuntimeError("Native ingress identity is absent from finite workload")
            field = event + "_us"
            if request[field] is not None:
                raise RuntimeError("Duplicate native ingress stage")
            request[field] = row["elapsed_us"]
        elif event == "materialized":
            expected = cohort_request_id(row["origin"], row["sequence"], row["useful_bytes"])
            if row["request_id"] != expected:
                raise RuntimeError("Materialized native request content does not match workload identity")
            ledger["outputs"].append({**row, "materialized_us": row["elapsed_us"]})
            if row["origin"] == replica and row.get("origin_eligible", True):
                if row["request_id"] not in requests:
                    raise RuntimeError("Native output is outside finite own-origin workload")
                requests[row["request_id"]]["materialized_us"] = row["elapsed_us"]
        elif event == "batch":
            ledger["batches"].append({**row, "materialized_us": row["elapsed_us"]})
    return ledger


def check_output_prefixes(ledgers):
    sequences = [[(row["output_index"], row["request_id"], row["exact_batch_id"])
                  for row in ledger["outputs"]] for _, ledger in sorted(ledgers.items())]
    for sequence in sequences:
        if [row[0] for row in sequence] != list(range(len(sequence))):
            raise RuntimeError("Native materialized output ordinals are not contiguous")
    common = min(map(len, sequences))
    longest = max(sequences, key=len)
    if any(sequence != longest[:len(sequence)] for sequence in sequences):
        raise RuntimeError("Native exact transaction and block output prefixes disagree")
    return {"common_prefix_length": common, "sequence_lengths": list(map(len, sequences)),
            "common_prefix_sha256": hashlib.sha256(json.dumps(sequences[0][:common]).encode()).hexdigest(),
            "scope": "Exact native linearized transaction order and complete block reference (including digest); zero output remains an accounted outcome."}


def node_parameters_text(bound_ms):
    if not 1 <= bound_ms <= 60_000:
        raise ValueError("bound-ms must be between1 and60000")
    seconds, milliseconds = divmod(bound_ms, 1000)
    return (f"leader_timeout:\n  secs: {seconds}\n  nanos: {milliseconds * 1_000_000}\n"
            "consensus_only: true\nenable_pipelining: true\nnumber_of_leaders: 2\n")


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--build", action="store_true", help="Build the pinned artifact even if the binary exists")
    parser.add_argument("--build-only", action="store_true", help="Build and record provenance without starting validators")
    parser.add_argument("--nodes", type=int, default=4, help="Committee size n=3f+1; native port profile currently n<=31")
    parser.add_argument('--population-profile',choices=('compact-n10-n50-v1',))
    parser.add_argument("--faulty-replica", type=int, action="append", default=[], help="Excluded honest-ingress identity; no client workload is assigned to this replica")
    parser.add_argument("--warmup", type=float, default=10, help="Warmup seconds after all metrics endpoints are ready (default:10)")
    parser.add_argument("--duration", type=float, default=30, help="Measurement seconds (default:30)")
    parser.add_argument("--rate", type=int, default=1000, help="Total configured offered tx/s; must be a positive multiple of40")
    parser.add_argument("--ingress-batch-ms", type=int, default=100, help="Pinned native generator cadence is100ms")
    parser.add_argument("--bound-ms", type=int, default=1000, help="Experiment bound Delta mapped to native leader-readiness timeout T=Delta; default1000 preserves historical runtime behavior")
    parser.add_argument("--transaction-size", type=int, default=None, help="Exact bincode-encoded Transaction size, including its 8-byte vector length")
    parser.add_argument("--useful-bytes", type=int, default=472, help="Useful application bytes, excluding native vector encoding and cohort metadata")
    parser.add_argument("--drain", type=float, default=2, help="Stop arrivals then observe unfinished cohorts for this many seconds")
    parser.add_argument("--deadline-ms", type=int, default=1000)
    parser.add_argument("--cohort-observer", choices=("full", "compact"), default="full", help="Detailed cohort timing or common finite receipts only; compact has no request latency")
    parser.add_argument("--legacy-window", action="store_true", help="Use historical generator/scrape metrics; excluded from formal cohort comparison")
    parser.add_argument("--pause-replica", type=int, help="Finite whole-process disruption; native leadership remains unchanged")
    parser.add_argument("--pause-after", type=float, default=1)
    parser.add_argument("--pause-seconds", type=float, default=0.5)
    native_faults.add_arguments(parser)
    parser.add_argument("--tokio-workers", type=int, default=2, help="Tokio workers per validator; consensus has its own thread")
    parser.add_argument("--output", type=Path, help="New output directory; default results/local/baseline-mysticeti-UUID")
    return parser


def main():
    parser = argument_parser()
    args = parser.parse_args()
    try:
        native_faults.validate(args, protocol="mysticeti")
    except ValueError as error:
        parser.error(str(error))
    if args.legacy_window and args.cohort_observer != "full":
        parser.error("compact observer requires finite cohort mode")
    if args.legacy_window and args.omit_replica is not None:
        parser.error("native omission experiments require the common finite cohort")
    compact=args.population_profile=='compact-n10-n50-v1'
    if compact and (args.legacy_window or args.nodes not in (4,10,50) or args.warmup!=0 or not 0<args.duration<=60 or not 0<=args.drain<=15 or args.rate>80000 or args.useful_bytes>4096):
        parser.error('compact native workload envelope exceeded')
    if (not compact and (args.nodes < 4 or args.nodes > 31 or (args.nodes - 1) % 3)) or len(set(args.faulty_replica)) > (args.nodes - 1) // 3 or any(i < 0 or i >= args.nodes for i in args.faulty_replica) or (args.pause_replica is not None and not 0 <= args.pause_replica < args.nodes):
        parser.error("invalid native committee or faulty identity budget")
    correct = [i for i in range(args.nodes) if i not in args.faulty_replica]
    rates = [0 if i not in correct else args.rate // len(correct) + (correct.index(i) < args.rate % len(correct)) for i in range(args.nodes)]
    if args.omit_replica is not None: rates[args.omit_replica] = args.attacker_rate
    counts = [(int(args.warmup*1e6)+int(args.duration*1e6))*rate//1_000_000 for rate in rates]
    if compact:
        from compact_campaign import origin_plan
        counts=origin_plan(args.rate,round(args.duration*1e6),args.nodes,correct)['counts']
        if args.omit_replica is not None:counts[args.omit_replica]=round(args.duration*1e6)*args.attacker_rate//1000000
    if not args.legacy_window and any(count > 5_000_000 for count in counts):
        parser.error("finite native receipt population exceeds 5,000,000 requests per origin")
    if args.transaction_size is None:
        args.transaction_size = 512 if args.legacy_window else args.useful_bytes + 40 + TRANSACTION_ENCODING_OVERHEAD
    elif not args.legacy_window and args.transaction_size != args.useful_bytes + 48:
        parser.error("cohort transaction-size must equal useful-bytes +40 metadata +8 native vector encoding")
    if args.rate <= 0 or args.useful_bytes <= 0 or args.drain < 0 or args.deadline_ms <= 0 or args.ingress_batch_ms <= 0 or args.transaction_size <= 16 + TRANSACTION_ENCODING_OVERHEAD or args.duration <= 0 or args.warmup < 0 or args.tokio_workers <= 0 or not 1 <= args.bound_ms <= 60_000:
        parser.error("rate must be a positive multiple of40, transaction-size >24, duration >0, warmup >=0, tokio-workers >0 and bound-ms within1..60000")
    output = (args.output or ROOT / "results/local" / ("baseline-mysticeti-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 2, "baseline": "mysticeti", "source_commit": COMMIT, "source_remote": REMOTE, "status": "running",
                "started_unix_ns": time.time_ns(), "commands": [], "patches": [], "raw_logs": [], "output_directory": str(output),
                "machine": {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(), "logical_cpus": os.cpu_count(), "python": sys.version},
                "settings": {"replicas": args.nodes, "warmup_seconds": args.warmup, "measurement_seconds": args.duration, "configured_total_offered_tx_s": args.rate,
                             "configured_per_replica_offered_tx_s": args.rate // len(correct), "ingress_batch_ms": args.ingress_batch_ms, "transaction_bytes": args.transaction_size, "native_opaque_transaction_bytes": args.transaction_size - TRANSACTION_ENCODING_OVERHEAD, "transaction_size_scope": "Exact bincode serialization of Transaction, including u64 vector length; block/message framing measured separately.", "tokio_workers_per_replica": args.tokio_workers,
                             "mode": "consensus-only", "pipelining": True, "leaders_per_round": 2, "leader_timeout_seconds": args.bound_ms / 1000, "bound_ms": args.bound_ms, "bound_mapping": "Native leader-readiness timeout T=Delta; quorum-clock gating unchanged. This is not a minimum block-production interval.", "transport": "native TCP on localhost", "faults": 0, "logging": "info,mysticeti_core::syncer=debug (leader trace logging overhead included)",
                             "generator_initial_delay_seconds": 1, "benchmark_keys": "upstream deterministic test keys; not suitable for production"},
                "measurement_boundaries": {"throughput": "Delta of each replica latency_s_count{workload=shared} over that replica's two Prometheus scrape midpoint times; replicas observe the same system workload and are not summed.",
                    "latency": "Upstream transaction generation UTC timestamp (millisecond resolution) to current_timestamp captured immediately before that transaction's native materialization observer, after sub-DAG linearization and payload availability, before subsequent WAL commit-state processing. Mean uses delta histogram sum/count, pooled per-transaction observations within each replica; no application execution.",
                    "percentiles": "Only upper bounds from upstream coarse Prometheus histogram buckets; not exact percentiles or estimates.",
                    "traffic": "Deltas of successful AsyncWrite/AsyncRead bytes on replica TCP streams, summed across validators. Includes native handshake, message length framing and ping/pong; excludes Prometheus/client/control traffic, TCP/IP headers and kernel retransmits. Independent scrape endpoints may leave a small in-flight byte difference.",
                    "offered_load": "Native generator at 100ms intervals. Instrumentation counts every transaction successfully enqueued to the local block handler, with actual opaque and bincode-encoded sizes. Independent Prometheus counter reads may straddle a batch update; canonical size is separately asserted for every generated transaction.",
                    "comparison_latency": "Origin-labeled native commit observations, selecting origin i only at replica i. These disjoint counts are summed for unique throughput and pooled latency; start uses generator UTC milliseconds and end is captured immediately before each transaction's native materialization observer, after sub-DAG linearization and payload availability, before subsequent WAL commit-state processing.",
                    "transaction_size": "CLI size includes the bincode u64 Vec length; the native generator opaque-data size is CLI size minus8. Runtime size gauge and per-transaction serialization assertions validate this.",
                    "agreement": "Progress at all four validators is checked. Full transaction order agreement is not exposed by the native metrics and is not inferred from throughput counts.",
                    "durability": "Native WAL enabled with background fsync every1s (AsyncWalSyncer); no synchronous fsync per commit. This benchmark does not test crash recovery.",
                    "shutdown": "Validators are deliberately terminated after end-of-window scrape, so the benchmark is a steady-state observation window, not a drain-to-zero test."}}
    if platform.system() == "Darwin":
        for name in ("hw.memsize", "hw.physicalcpu", "hw.logicalcpu", "machdep.cpu.brand_string", "hw.model"):
            query = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
            manifest["machine"][name] = query.stdout.strip() if query.returncode == 0 else {"unavailable": query.stderr.strip()}
    manifest["settings"].update(useful_transaction_bytes=args.useful_bytes, drain_seconds=args.drain, deadline_ms=args.deadline_ms, cohort_mode=not args.legacy_window, correct_replicas=correct)
    manifest["observer_control"] = {"mode": args.cohort_observer, "per_request_timestamps_and_rows": args.cohort_observer == "full",
        "latency_available": args.cohort_observer == "full", "scope": "Detailed journal work above common finite identity bitmaps, exact raw-native prefix fingerprints and process-window samples; upstream native metrics remain enabled in both modes"}
    if not args.legacy_window:
        manifest["comparison_eligible"] = False
        manifest["formal_comparison_limitation"] = "Native-hook timing and admission remain source-bound observer evidence; independent signed WAL prefix verification is required before successful completion, and endpoint validation remains separate."
    processes, streams = [], []
    shaping_configured = False
    exit_status = 0
    try:
        if args.build or args.build_only or not BINARY.exists():
            build(output, manifest)
        if not BINARY.exists():
            raise RuntimeError(f"Missing binary {BINARY}")
        actual = subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip()
        if actual != COMMIT:
            raise RuntimeError(f"Unexpected source commit {actual}")
        ensure_patch()
        manifest["instrumentation_patch"] = {"path": str(PATCH.relative_to(ROOT)), "sha256": sha256(PATCH)}
        diff = subprocess.check_output(["git", "-C", str(SOURCE), "diff", "HEAD"], text=True)
        (output / "source.patch").write_text(diff)
        manifest["source_diff_sha256"] = sha256(output / "source.patch")
        if diff:
            manifest["patches"].append({"path": "source.patch", "sha256": manifest["source_diff_sha256"]})
        manifest["binary"] = {"path": str(BINARY), "sha256": sha256(BINARY), "bytes": BINARY.stat().st_size}
        provenance_path = TARGET / "build-provenance.json"
        if not provenance_path.exists():
            raise RuntimeError("Missing build provenance; run with --build to establish binary/source binding")
        provenance = json.loads(provenance_path.read_text())
        expected = {"source_commit": COMMIT, "binary_sha256": manifest["binary"]["sha256"],
                    "cargo_lock_sha256": sha256(SOURCE / "Cargo.lock"), "source_diff_sha256": manifest["source_diff_sha256"]}
        if any(provenance.get(key) != value for key, value in expected.items()):
            raise RuntimeError("Recorded build provenance disagrees with binary/source/lock; rebuild required")
        manifest["build_provenance"] = provenance
        manifest["cargo_lock_sha256"] = sha256(SOURCE / "Cargo.lock")
        manifest["runner_sha256"] = sha256(Path(__file__))
        shutil.copy2(__file__, output / "runner.py")
        if args.build_only:
            manifest["status"] = "built"
            return 0
        genesis = output / "genesis"
        node_parameters = output / "node-parameters.yaml"
        node_parameters.write_text(node_parameters_text(args.bound_ms))
        client_parameters = output / "client-parameters.yaml"
        client_parameters.write_text(f"load: {args.rate // len(correct)}\ntransaction_size: {args.transaction_size - TRANSACTION_ENCODING_OVERHEAD}\ninitial_delay:\n  secs: 1\n  nanos: 0\n")
        run_logged([str(BINARY), "benchmark-genesis", "--ips", *(["127.0.0.1"] * args.nodes), "--working-directory", str(genesis), "--node-parameters-path", str(node_parameters)], output / "genesis.log", manifest)
        ports = allocate_ports(args.nodes * 2)
        public_path = genesis / "public-config.yaml"
        public = public_path.read_text()
        for index in range(args.nodes):
            public = public.replace(f"127.0.0.1:{1500+index}\n", f"127.0.0.1:{ports[index]}\n")
            public = public.replace(f"127.0.0.1:{1500+args.nodes+index}\n", f"127.0.0.1:{ports[args.nodes+index]}\n")
        public_path.write_text(public)
        manifest["settings"]["network_ports"] = ports[:args.nodes]
        manifest["settings"]["metrics_ports"] = ports[args.nodes:]
        env = os.environ.copy()
        env.update(RUST_LOG="info,mysticeti_core::syncer=debug", CONSENSUS_ONLY="1", TOKIO_WORKER_THREADS=str(args.tokio_workers), RUST_BACKTRACE="1")
        if compact:
            env.update(BENCHMARK_POPULATION_PROFILE=args.population_profile,BENCHMARK_GLOBAL_RATE=str(args.rate),
                BENCHMARK_HONEST_ORIGINS=','.join(map(str,correct)),BENCHMARK_MEMBER_COUNT=str(args.nodes))
        for index in range(args.nodes):
            if not args.legacy_window:
                env.update(BENCHMARK_COHORT_PATH=str(output / f"cohort-{index}.jsonl"), BENCHMARK_COHORT_START=str(output / "start-arrivals"), BENCHMARK_WARMUP_US=str(int(args.warmup * 1e6)), BENCHMARK_DURATION_US=str(int(args.duration * 1e6)), BENCHMARK_DRAIN_US=str(int(args.drain * 1e6)), BENCHMARK_INGRESS_US=str(args.ingress_batch_ms * 1000))
                env.update(BENCHMARK_COHORT_OBSERVER=args.cohort_observer, BENCHMARK_RECEIPT_DIR=str(output / f"receipt-{index}"),
                    BENCHMARK_RECEIPT_REQUEST=str(output / "receipt-request"), BENCHMARK_RECEIPT_COUNTS=",".join(map(str, counts)),
                    BENCHMARK_RECEIPT_ORIGIN=str(index), BENCHMARK_RECEIPT_USEFUL_BYTES=str(args.useful_bytes))
            if not args.legacy_window:
                local_rate = rates[index]
                client_parameters = output / f"client-parameters-{index}.yaml"
                client_parameters.write_text(f"load: {local_rate}\ntransaction_size: {args.transaction_size - TRANSACTION_ENCODING_OVERHEAD}\ninitial_delay:\n  secs: 1\n  nanos: 0\n")
            private = genesis / f"private-config-{index}.yaml"
            private.chmod(0o600)
            log = output / f"validator-{index}.log"
            command = [str(BINARY), "run", "--authority", str(index), "--committee-path", str(genesis / "committee.yaml"), "--public-config-path", str(public_path), "--private-config-path", str(private), "--client-parameters-path", str(client_parameters)]
            manifest["commands"].append({"argv": command, "cwd": str(output), "env": {name: env[name] for name in ("RUST_LOG", "CONSENSUS_ONLY", "TOKIO_WORKER_THREADS", "RUST_BACKTRACE")}, "log": log.name})
            stream = open(log, "wb")
            streams.append(stream)
            process_env = env | native_faults.environment(args, output, index, {i:i for i in range(args.nodes)})
            processes.append(subprocess.Popen(command, cwd=output, env=process_env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True))
        manifest["process_ids"] = [process.pid for process in processes]
        deadline = time.monotonic() + 30
        while True:
            check_running(processes)
            try:
                ready = snapshots(ports[args.nodes:])
                if not args.legacy_window or all(snap["values"].get('latency_s_count{workload="shared"}', 0) > 0 and snap["values"].get(f'benchmark_origin_latency_s_count{{origin="{index}"}}', 0) > 0 for index, snap in enumerate(ready)):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Timed out waiting for transaction progress at all validators")
                time.sleep(0.1)
            except (OSError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Timed out waiting for validator metrics endpoints")
                time.sleep(0.1)
        shaping = network_delay.configure_from_environment("mysticeti", ports[:args.nodes])
        if shaping is not None:
            shaping_configured = True
            manifest["network_shaping"] = shaping
        if not args.legacy_window:
            manifest["omission_schedule"] = native_faults.arm(args, output, time.clock_gettime_ns(time.CLOCK_MONOTONIC))
            (output / "start-arrivals").touch()
        print(f"Mysticeti: {args.nodes} validators ready; warming up {args.warmup:g}s", flush=True)
        wait_alive(processes, args.warmup)
        before = snapshots(ports[args.nodes:])
        cpu_before = native_faults.cpu_snapshot(output)
        print(f"Mysticeti: measuring {args.duration:g}s at configured {args.rate} tx/s", flush=True)
        if args.pause_replica is None:
            wait_alive(processes, args.duration)
        else:
            if not 0 <= args.pause_after < args.duration or not 0 < args.pause_seconds <= args.duration - args.pause_after:
                raise ValueError("finite disruption must fit the measurement interval")
            wait_alive(processes, args.pause_after)
            os.kill(processes[args.pause_replica].pid, signal.SIGSTOP)
            manifest["disruption"] = {"replica": args.pause_replica, "kind": "whole_process_pause", "after_seconds": args.pause_after, "duration_seconds": args.pause_seconds}
            try:
                wait_alive(processes, args.pause_seconds)
            finally:
                os.kill(processes[args.pause_replica].pid, signal.SIGCONT)
            wait_alive(processes, args.duration - args.pause_after - args.pause_seconds)
        after = snapshots(ports[args.nodes:])
        cpu_after = native_faults.cpu_snapshot(output)
        metrics, own_origin_metrics, instrumentation = [], [], []
        for index, (start, end) in enumerate(zip(before, after)):
            for label, snap in (("before", start), ("after", end)):
                (output / f"metrics-{index}-{label}.prom").write_text(snap["raw"])
                write_json(output / f"metrics-{index}-{label}.json", {key: value for key, value in snap.items() if key != "raw"})
            metrics.append(summarize(start, end, index))
            own_origin_metrics.append(summarize(start, end, index, own_origin=True))
            instrumentation.append(summarize_instrumentation(start, end, index, args.transaction_size))
        if not args.legacy_window:
            wait_alive(processes, args.drain + 0.05)
            final = snapshots(ports[args.nodes:])
            for index, snap in enumerate(final):
                (output / f"metrics-{index}-drained.prom").write_text(snap["raw"])
            manifest["traffic_ledger"] = {
                "boundary": "successful replica TCP stream writes; each transmission counted at sender once",
                "whole_run_written_bytes": sum(int(snap["values"]["benchmark_tcp_written_bytes"]) for snap in final),
                "setup_and_warmup_written_bytes": sum(int(snap["values"]["benchmark_tcp_written_bytes"]) for snap in before),
                "measurement_written_bytes": sum(int(metric_delta(a,b,"benchmark_tcp_written_bytes")) for a,b in zip(before,after)),
                "drain_written_bytes": sum(int(metric_delta(a,b,"benchmark_tcp_written_bytes")) for a,b in zip(after,final)),
                "per_replica_whole_run_written_bytes": [int(snap["values"]["benchmark_tcp_written_bytes"]) for snap in final],
                "protocol_payload_evidence_repair_split": "unavailable; native aggregate IO only",
            }
            ledger=manifest["traffic_ledger"]
            assert ledger["whole_run_written_bytes"] == sum(ledger[key] for key in ("setup_and_warmup_written_bytes", "measurement_written_bytes", "drain_written_bytes"))
        throughputs = [node["commit_throughput_tx_s"] for node in metrics]
        latencies = [node["mean_generation_to_commit_latency_ms"] for node in metrics if node["mean_generation_to_commit_latency_ms"] is not None]
        manifest["metrics"] = {"per_replica": metrics, "commit_throughput_tx_s_median_across_replicas": statistics.median(throughputs),
                               "commit_throughput_tx_s_min_across_replicas": min(throughputs), "commit_throughput_tx_s_max_across_replicas": max(throughputs),
                               "mean_latency_ms_median_across_replicas": statistics.median(latencies) if latencies else None,
                               "own_origin_per_replica": own_origin_metrics, "instrumentation_per_replica": instrumentation,
                               "network_bytes": sum(node["replica_tcp_written_bytes"] for node in instrumentation)}
        manifest["comparison"] = comparison_summary(metrics, own_origin_metrics, instrumentation, args)
        pending = []
        for index, snap in enumerate(after):
            pending.append(int(snap["values"]["benchmark_enqueued_transactions"] - snap["values"][f'benchmark_origin_latency_s_count{{origin="{index}"}}']))
        manifest["comparison"]["end_pending_generated_transactions_at_origins"] = pending
        manifest["checks"] = {"independent_processes_live_through_measurement": args.nodes, "all_replicas_committed_transactions": all(node["committed_transaction_observations"] > 0 for node in metrics), "all_replicas_committing_before_warmup": args.legacy_window,
                              "runtime_encoded_transaction_size_matches_request": True, "instrumented_replica_traffic_present": all(node["replica_tcp_written_bytes"] > 0 for node in instrumentation),
                              "signature_verification_enabled": True, "native_wal_enabled": True, "exact_transaction_order_agreement": "not_checked"}
        if not args.legacy_window:
            manifest["observer_freeze_request_controller_monotonic_ns"] = time.monotonic_ns()
            (output / "receipt-request").touch(exist_ok=False)
            export_deadline = time.monotonic() + 12
            while not all((output / f"receipt-{i}/header.json").is_file() for i in range(args.nodes)):
                check_running(processes)
                if time.monotonic() >= export_deadline:
                    raise TimeoutError("native complete-block receipt export did not finish within 12 seconds")
                time.sleep(.005)
            manifest["observer_export_ready_controller_monotonic_ns"] = time.monotonic_ns()
            # Charge native traffic continuing during the observer-prefix freeze/export wait.
            post_export = snapshots(ports[args.nodes:])
            for i, snap in enumerate(post_export):
                (output / f"metrics-{i}-post-export.prom").write_text(snap["raw"])
                write_json(output / f"metrics-{i}-post-export.json", {k:v for k,v in snap.items() if k != "raw"})
            manifest["traffic_ledger"]["observer_freeze_wait_written_bytes"] = sum(int(metric_delta(a,b,"benchmark_tcp_written_bytes")) for a,b in zip(final,post_export))
            manifest["traffic_ledger"]["whole_run_written_bytes"] = sum(int(v["values"]["benchmark_tcp_written_bytes"]) for v in post_export)
            manifest["traffic_ledger"]["per_replica_whole_run_written_bytes"] = [int(v["values"]["benchmark_tcp_written_bytes"]) for v in post_export]
            assert manifest["traffic_ledger"]["whole_run_written_bytes"] == sum(manifest["traffic_ledger"][k] for k in ("setup_and_warmup_written_bytes","measurement_written_bytes","drain_written_bytes","observer_freeze_wait_written_bytes"))
            manifest["observer_stop_controller_monotonic_ns"] = time.monotonic_ns()
            # The last native counters were sampled above. Freeze producers only
            # after that endpoint so bounded multi-pass archival sees immutable
            # journal bytes. Shutdown traffic is outside the last counter sample.
            for process in processes:
                if process.poll() is None: os.kill(process.pid, signal.SIGSTOP)
            manifest["archive_freeze"] = {"after_final_counter_sample": True,
                "cost_boundary": "post-export sampled native counters include freeze-wait traffic; subsequent unsampled writes and shutdown excluded; raw observer output is censored at its actual complete-block prefix freeze"}
            receipts = {}
            for i in range(args.nodes):
                starts = (row for row in native_cohort_store.journal_rows(output / f"cohort-{i}.jsonl") if row.get("event") == "start")
                start = next(starts, None)
                if start is None or next(starts, None) is not None: raise ValueError("exactly one native finite start required")
                receipts[i] = mysticeti_receipts.load(output / f"receipt-{i}", i, counts, args.useful_bytes, args.cohort_observer, start,population_profile=args.population_profile)
            finite = mysticeti_receipts.summarize(receipts, correct)
            manifest["finite_output_receipt"] = finite
            manifest["compact_output_agreement"] = finite["agreement"]
            manifest["observer_process_resources"] = mysticeti_receipts.resource_window(receipts)
            manifest["observer_prefix_endpoints"] = {i:{key:receipts[i]["header"][key] for key in ("requested_us","frozen_us","output_count","batch_count")} | {"declared_observed_us":receipts[i]["declared_observed_us"], "header_sha256":receipts[i]["header_sha256"]} for i in receipts}
            manifest["observer_window_metrics"] = {**manifest["comparison"], **finite_window_summary(finite), "mean_latency_ms":None,
                "latency_available":False, "process_cpu_seconds":manifest["observer_process_resources"]["cpu_seconds"],
                "latency_endpoint":"unavailable in common finite membership receipts", "comparison_eligible":False,
                "generated_count":finite["window"]["admission_count"], "generation_tps":finite["window"]["admission_tps"],
                "traffic_measurement_seconds":manifest["comparison"]["measurement_seconds"],
                "window_boundary_note":"Finite eligible completions use configured local windows; traffic uses native scrape intervals and CPU uses recorded getrusage intervals. These boundaries are shared across observer modes, not asserted identical."}
            manifest["observer_finite_cost"] = {"written_bytes":manifest["traffic_ledger"]["whole_run_written_bytes"],
                "m_out_bytes":finite["reference_m_out_bytes"], "u_out_bytes":finite["reference_unique_eligible_u_out_bytes"],
                "reference_replica":finite["reference_replica"],
                "boundary":"one complete native observer prefix; whole-committee traffic through later post-export scrape, including native work after observer freeze; trailing scrape-to-STOP bytes are not sampled"}
            if args.cohort_observer == "full":
                staging = native_cohort_store.NativeStore(output / "native-cohort-stage.sqlite",population_profile=args.population_profile)
                try:
                    for i in range(args.nodes):
                        staging.mysticeti(output / f"cohort-{i}.jsonl", i, cohort_request_id, observed_us=receipts[i]["header"]["frozen_us"])
                    archive = staging.archive(output / "cohorts")
                finally:
                    staging.close()
                reduced = native_cohort_store.reduce_archive(archive, output / "cohort-reduction.sqlite", correct, args.deadline_ms)
                manifest.update({key: reduced[key] for key in ("cohort", "agreement", "cohort_archive", "output_exclusions")})
                manifest["checks"]["exact_transaction_order_agreement"] = reduced["agreement"]
                manifest["comparison"].update(accounting_schema=1, endpoint_contract=cohort_metrics.ENDPOINT,
                    useful_transaction_bytes=args.useful_bytes, cohort=manifest["cohort"],
                    unique_completion_tps=manifest["cohort"]["window"]["unique_completion_tps"],
                    completion_count=manifest["cohort"]["window"]["completion_count"],
                    latency_endpoint="Admission at independent ingress thread to origin-local payload-verified native linearized output, measured by one monotonic clock; no VM execution or durable-fsync claim.")
                manifest["comparison"]["latency_available"] = True
                manifest["comparison"]["mean_latency_ms"] = reduced["mean_latency_ms"]
                manifest["comparison"]["mean_latency_scope"] = "Completed measurement-cohort members only; censored cohort quantiles and unfinished count are authoritative."
                manifest["comparison"]["generated_count"] = manifest["cohort"]["window"]["admission_count"]
                manifest["comparison"]["generation_tps"] = manifest["cohort"]["window"]["admission_tps"]
                manifest["comparison"]["end_pending_generated_transactions_at_origins"] = [node["pending"] for node in manifest["cohort"]["origins"]]
                manifest["measurement_boundaries"].update(latency=manifest["comparison"]["latency_endpoint"], agreement="Authenticated workload observations agree at actual native ordinals; filtered journals do not establish complete native-order fidelity or an unseen terminal prefix. Independent signed WAL replay supplies that separate gate.", shutdown="Finite independent arrivals stop; observer prefix freezes after declared drain at a recorded complete native block boundary. Late completions do not meet an earlier deadline; unfinished cohorts remain retained.")
                manifest["comparison"]["resource_cost"] = cohort_metrics.cost_ratios(manifest["comparison"]["replica_tcp_written_bytes"], manifest["cohort"])
                manifest["comparison"]["finite_run_resource_cost"] = cohort_metrics.cost_ratios(manifest["traffic_ledger"]["whole_run_written_bytes"], manifest["cohort"], boundary="finite_run")
                assert manifest["cohort"]["finite_run"]["u_out_bytes"] == finite["reference_unique_eligible_u_out_bytes"]
                assert manifest["cohort"]["finite_run"]["m_out_bytes"] == finite["reference_m_out_bytes"]
            else:
                manifest["agreement"] = finite["agreement"]
                manifest["checks"]["exact_transaction_order_agreement"] = finite["agreement"]
                manifest["comparison"].update(finite["window"])
                manifest["comparison"].update(cohort=None, mean_latency_ms=None, latency_available=False,
                    endpoint_contract=None, compact_receipt=finite, latency_quantiles=None, deadline_misses=None,
                    generated_count=finite["window"]["admission_count"], generation_tps=finite["window"]["admission_tps"],
                    latency_endpoint="unavailable: compact observer retains no per-request timing records")
                manifest["measurement_boundaries"]["latency"] = "unavailable in compact mode; unchanged upstream histograms are raw native diagnostics only"
            manifest["comparison"]["comparison_eligible"] = False
            manifest["comparison"].update(finite_window_summary(finite))
            manifest["measurement_boundaries"]["observer_prefix"] = "Actual complete-block observer freeze can follow the declared drain deadline; its local timestamp is retained. Deadline classification still uses original intended arrival and configured deadline. Independent signed WAL-tail proof remains incomplete."
        manifest["omission_observation"] = native_faults.collect_omissions(output)
        manifest["native_fault_scope"] = "Faulty author's own signed blocks, including responses carrying those blocks; native blocks couple payload with consensus. Control requests and relayed honest blocks remain enabled. Extra attacker-origin input has no honest useful credit."
        if args.crypto_meter == "on":
            manifest["crypto_cpu_ledger"] = native_faults.cpu_ledger(cpu_before, cpu_after, native_faults.cpu_snapshot(output))
        manifest["runner_dependencies"] = native_faults.dependency_hashes([Path(__file__), Path(native_faults.__file__), Path(cohort_metrics.__file__), Path(native_cohort_store.__file__), Path(mysticeti_receipts.__file__), Path(mysticeti_wal.__file__), ROOT / "scripts/cohort_store.py", ROOT / "scripts/network_delay.py", ROOT / "scripts/timing_calibration.py"])
        manifest["status"] = "completed"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(error).__name__}: {error}"
        (output / "error.txt").write_text(traceback.format_exc())
        print(manifest["error"], file=sys.stderr)
        exit_status = 1
    finally:
        cleanup_errors = cleanup_owned_children(processes, streams)
        if cleanup_errors:
            manifest["cleanup_errors"] = cleanup_errors
            manifest["status"] = "failed"
            exit_status = 1
        if shaping_configured:
            try:
                manifest["network_shaping_cleanup"] = network_delay.clear_from_environment()
            except Exception as error:
                manifest["status"] = "failed"
                manifest["network_shaping_cleanup_error"] = f"{type(error).__name__}: {error}"
                exit_status = 1
        manifest["shutdown_exit_codes"] = [process.returncode for process in processes]
        if manifest["status"] == "completed":
            try:
                if args.legacy_window:
                    manifest["checks"]["committed_leader_authority_round_common_prefix"] = check_leader_prefixes(output,args.nodes)
                else:
                    fidelity = audit_native_frozen_prefix(output, receipts, correct)
                    manifest["finite_output_receipt"]["agreement"]["native_order_fidelity"] = fidelity
                    manifest["agreement"]["native_order_fidelity"] = fidelity
                    manifest["agreement"]["exact_frozen_native_prefix"] = {i:{"kind":"exact_complete_block_observer_freeze","count":receipts[i]["header"]["output_count"],"batch_count":receipts[i]["header"]["batch_count"]} for i in correct}
                    manifest["native_wal_prefix_fidelity"] = fidelity
                    manifest["measurement_boundaries"]["observer_prefix"] = "Exact native output/block prefix at the recorded complete-block observer freeze independently joins signed WAL blocks and locally persisted CommitData order; later WAL suffix, fsync, consensus certificates and admission timestamps are outside this proof. Freeze may follow the original deadline."
            except Exception as error:
                manifest["status"] = "failed"
                manifest["error"] = str(error)
                exit_status = 1
        manifest["finished_unix_ns"] = time.time_ns()
        manifest["raw_logs"] = [path.name for path in sorted(output.glob("*.log"))]
        manifest["files"] = [{"path": str(path.relative_to(output)), "bytes": path.stat().st_size, "sha256": sha256(path)} for path in sorted(output.rglob("*")) if path.is_file() and path.name != "manifest.json"]
        write_json(output / "manifest.json", manifest)
        print(output, flush=True)
    return exit_status


if __name__ == "__main__":
    sys.exit(main())
