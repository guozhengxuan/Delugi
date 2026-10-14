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
    env.update(RUSTUP_HOME=str(RUSTUP_HOME), CARGO_HOME=str(CARGO_HOME), CARGO_TARGET_DIR=str(TARGET))
    installed = subprocess.run(["rustup", "toolchain", "list"], env=env, capture_output=True, text=True)
    if not any(line.startswith("1.78-") for line in installed.stdout.splitlines()):
        run_logged(["rustup", "toolchain", "install", TOOLCHAIN, "--profile", "minimal"], output / "toolchain.log", manifest, env=env)
    run_logged(["cargo", "+" + TOOLCHAIN, "build", "--release", "--locked", "-p", "mysticeti", "--jobs", "2"], output / "build.log", manifest, cwd=SOURCE, env=env)
    manifest["toolchain"] = subprocess.check_output(["rustc", "+" + TOOLCHAIN, "--version", "--verbose"], env=env, text=True)
    manifest["build_environment"] = {name: env[name] for name in ("RUSTUP_HOME", "CARGO_HOME", "CARGO_TARGET_DIR")}
    write_json(TARGET / "build-provenance.json", {"source_commit": COMMIT, "binary_sha256": sha256(BINARY),
        "cargo_lock_sha256": sha256(SOURCE / "Cargo.lock"), "source_diff_sha256": hashlib.sha256(subprocess.check_output(["git", "-C", str(SOURCE), "diff", "HEAD"])).hexdigest(), "toolchain": manifest["toolchain"],
        "environment": manifest["build_environment"], "commands": manifest["commands"], "build_directory": str(output)})


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
    if count != 8:
        raise ValueError("This runner supports four validators")
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
            if len(network_ports) == 4:
                break
        if len(network_ports) != 4:
            raise RuntimeError("Cannot find four free native network/source port pairs")
        metrics_ports = []
        for _ in range(4):
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
    if count <= 0:
        raise RuntimeError(f"Validator {index} committed no transaction observations during the measurement window")
    buckets = []
    for key in after["values"]:
        match = re.fullmatch(rf'{prefix}_bucket\{{(?:{label},le="([^"]+)"|le="([^"]+)",{label})\}}', key)
        if match:
            upper = float(match[1] or match[2])
            buckets.append((upper, metric_delta(before, after, key)))
    bounds = {}
    for percentile in (50, 95, 99):
        threshold = count * percentile / 100
        bound = next((upper for upper, cumulative in sorted(buckets) if cumulative >= threshold), math.inf)
        bounds[f"p{percentile}_histogram_upper_bound_ms"] = bound * 1000 if math.isfinite(bound) else None
    return {"authority": index, "measurement_seconds": elapsed, "committed_transaction_observations": int(count),
            "commit_throughput_tx_s": count / elapsed, "mean_generation_to_commit_latency_ms": latency_sum / count * 1000,
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
    if result["enqueued_transactions"] <= 0 or result["replica_tcp_written_bytes"] <= 0 or result["replica_tcp_read_bytes"] <= 0:
        raise RuntimeError(f"Validator {index} did not generate transactions or exchange replica traffic")
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
        "protocol": "mysticeti", "replicas": 4, "offered_tx_s": args.rate,
        "bound_ms": args.bound_ms, "leader_timeout_ms": args.bound_ms,
        "bound_mapping": "Experiment mapping: native leader-readiness timeout T = 1 * Delta; quorum-clock gating remains unchanged.",
        "transaction_bytes": args.transaction_size, "ingress_batch_ms": args.ingress_batch_ms, "warmup_seconds": args.warmup,
        "measurement_seconds": elapsed, "unique_completion_tps": completed / elapsed,
        "mean_latency_ms": sum(node["mean_generation_to_commit_latency_ms"] * node["committed_transaction_observations"] for node in own_origin_metrics) / completed,
        "latency_endpoint": "Generation UTC timestamp (millisecond resolution) to commit-handler entry at the transaction's originating replica, before sub-DAG linearization and subsequent committed-sub-DAG processing; no application execution.",
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


def check_leader_prefixes(output):
    sequences = []
    for index in range(4):
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
    parser.add_argument("--warmup", type=float, default=10, help="Warmup seconds after all metrics endpoints are ready (default:10)")
    parser.add_argument("--duration", type=float, default=30, help="Measurement seconds (default:30)")
    parser.add_argument("--rate", type=int, default=1000, help="Total configured offered tx/s; must be a positive multiple of40")
    parser.add_argument("--ingress-batch-ms", type=int, choices=[100], default=100, help="Pinned native generator cadence is100ms")
    parser.add_argument("--bound-ms", type=int, default=1000, help="Experiment bound Delta mapped to native leader-readiness timeout T=Delta; default1000 preserves historical runtime behavior")
    parser.add_argument("--transaction-size", type=int, default=512, help="Exact bincode-encoded Transaction size, including its 8-byte vector length")
    parser.add_argument("--tokio-workers", type=int, default=2, help="Tokio workers per validator; consensus has its own thread")
    parser.add_argument("--output", type=Path, help="New output directory; default results/local/baseline-mysticeti-UUID")
    return parser


def main():
    parser = argument_parser()
    args = parser.parse_args()
    if args.rate <= 0 or args.rate % 40 or args.transaction_size <= 16 + TRANSACTION_ENCODING_OVERHEAD or args.duration <= 0 or args.warmup < 0 or args.tokio_workers <= 0 or not 1 <= args.bound_ms <= 60_000:
        parser.error("rate must be a positive multiple of40, transaction-size >24, duration >0, warmup >=0, tokio-workers >0 and bound-ms within1..60000")
    output = (args.output or ROOT / "results/local" / ("baseline-mysticeti-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 2, "baseline": "mysticeti", "source_commit": COMMIT, "source_remote": REMOTE, "status": "running",
                "started_unix_ns": time.time_ns(), "commands": [], "patches": [], "raw_logs": [], "output_directory": str(output),
                "machine": {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(), "logical_cpus": os.cpu_count(), "python": sys.version},
                "settings": {"replicas": 4, "warmup_seconds": args.warmup, "measurement_seconds": args.duration, "configured_total_offered_tx_s": args.rate,
                             "configured_per_replica_offered_tx_s": args.rate // 4, "ingress_batch_ms": args.ingress_batch_ms, "transaction_bytes": args.transaction_size, "native_opaque_transaction_bytes": args.transaction_size - TRANSACTION_ENCODING_OVERHEAD, "transaction_size_scope": "Exact bincode serialization of Transaction, including u64 vector length; block/message framing measured separately.", "tokio_workers_per_replica": args.tokio_workers,
                             "mode": "consensus-only", "pipelining": True, "leaders_per_round": 2, "leader_timeout_seconds": args.bound_ms / 1000, "bound_ms": args.bound_ms, "bound_mapping": "Native leader-readiness timeout T=Delta; quorum-clock gating unchanged. This is not a minimum block-production interval.", "transport": "native TCP on localhost", "faults": 0, "logging": "info,mysticeti_core::syncer=debug (leader trace logging overhead included)",
                             "generator_initial_delay_seconds": 1, "benchmark_keys": "upstream deterministic test keys; not suitable for production"},
                "measurement_boundaries": {"throughput": "Delta of each replica latency_s_count{workload=shared} over that replica's two Prometheus scrape midpoint times; replicas observe the same system workload and are not summed.",
                    "latency": "Upstream transaction generation UTC timestamp (millisecond resolution) to current_timestamp captured at commit-handler entry, before sub-DAG linearization and subsequent committed-sub-DAG processing. Mean uses delta histogram sum/count, pooled per-transaction observations within each replica; no application execution.",
                    "percentiles": "Only upper bounds from upstream coarse Prometheus histogram buckets; not exact percentiles or estimates.",
                    "traffic": "Deltas of successful AsyncWrite/AsyncRead bytes on replica TCP streams, summed across validators. Includes native handshake, message length framing and ping/pong; excludes Prometheus/client/control traffic, TCP/IP headers and kernel retransmits. Independent scrape endpoints may leave a small in-flight byte difference.",
                    "offered_load": "Native generator at 100ms intervals. Instrumentation counts every transaction successfully enqueued to the local block handler, with actual opaque and bincode-encoded sizes. Independent Prometheus counter reads may straddle a batch update; canonical size is separately asserted for every generated transaction.",
                    "comparison_latency": "Origin-labeled native commit observations, selecting origin i only at replica i. These four disjoint counts are summed for unique throughput and pooled latency; start uses generator UTC milliseconds and end is captured at commit-handler entry before sub-DAG linearization and subsequent committed-sub-DAG processing.",
                    "transaction_size": "CLI size includes the bincode u64 Vec length; the native generator opaque-data size is CLI size minus8. Runtime size gauge and per-transaction serialization assertions validate this.",
                    "agreement": "Progress at all four validators is checked. Full transaction order agreement is not exposed by the native metrics and is not inferred from throughput counts.",
                    "durability": "Native WAL enabled with background fsync every1s (AsyncWalSyncer); no synchronous fsync per commit. This benchmark does not test crash recovery.",
                    "shutdown": "Validators are deliberately terminated after end-of-window scrape, so the benchmark is a steady-state observation window, not a drain-to-zero test."}}
    if platform.system() == "Darwin":
        for name in ("hw.memsize", "hw.physicalcpu", "hw.logicalcpu", "machdep.cpu.brand_string", "hw.model"):
            query = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
            manifest["machine"][name] = query.stdout.strip() if query.returncode == 0 else {"unavailable": query.stderr.strip()}
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
        client_parameters.write_text(f"load: {args.rate // 4}\ntransaction_size: {args.transaction_size - TRANSACTION_ENCODING_OVERHEAD}\ninitial_delay:\n  secs: 1\n  nanos: 0\n")
        run_logged([str(BINARY), "benchmark-genesis", "--ips", *(["127.0.0.1"] * 4), "--working-directory", str(genesis), "--node-parameters-path", str(node_parameters)], output / "genesis.log", manifest)
        ports = allocate_ports(8)
        public_path = genesis / "public-config.yaml"
        public = public_path.read_text()
        for index in range(4):
            public = public.replace(f"127.0.0.1:{1500+index}\n", f"127.0.0.1:{ports[index]}\n")
            public = public.replace(f"127.0.0.1:{1504+index}\n", f"127.0.0.1:{ports[4+index]}\n")
        public_path.write_text(public)
        manifest["settings"]["network_ports"] = ports[:4]
        manifest["settings"]["metrics_ports"] = ports[4:]
        env = os.environ.copy()
        env.update(RUST_LOG="info,mysticeti_core::syncer=debug", CONSENSUS_ONLY="1", TOKIO_WORKER_THREADS=str(args.tokio_workers), RUST_BACKTRACE="1")
        for index in range(4):
            private = genesis / f"private-config-{index}.yaml"
            private.chmod(0o600)
            log = output / f"validator-{index}.log"
            command = [str(BINARY), "run", "--authority", str(index), "--committee-path", str(genesis / "committee.yaml"), "--public-config-path", str(public_path), "--private-config-path", str(private), "--client-parameters-path", str(client_parameters)]
            manifest["commands"].append({"argv": command, "cwd": str(output), "env": {name: env[name] for name in ("RUST_LOG", "CONSENSUS_ONLY", "TOKIO_WORKER_THREADS", "RUST_BACKTRACE")}, "log": log.name})
            stream = open(log, "wb")
            streams.append(stream)
            processes.append(subprocess.Popen(command, cwd=output, env=env, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True))
        manifest["process_ids"] = [process.pid for process in processes]
        deadline = time.monotonic() + 30
        while True:
            check_running(processes)
            try:
                ready = snapshots(ports[4:])
                if all(snap["values"].get('latency_s_count{workload="shared"}', 0) > 0 and snap["values"].get(f'benchmark_origin_latency_s_count{{origin="{index}"}}', 0) > 0 for index, snap in enumerate(ready)):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("Timed out waiting for transaction progress at all validators")
                time.sleep(0.1)
            except (OSError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Timed out waiting for validator metrics endpoints")
                time.sleep(0.1)
        shaping = network_delay.configure_from_environment("mysticeti", ports[:4])
        if shaping is not None:
            shaping_configured = True
            manifest["network_shaping"] = shaping
        print(f"Mysticeti: four validators committing; warming up {args.warmup:g}s", flush=True)
        wait_alive(processes, args.warmup)
        before = snapshots(ports[4:])
        print(f"Mysticeti: measuring {args.duration:g}s at configured {args.rate} tx/s", flush=True)
        wait_alive(processes, args.duration)
        after = snapshots(ports[4:])
        metrics, own_origin_metrics, instrumentation = [], [], []
        for index, (start, end) in enumerate(zip(before, after)):
            for label, snap in (("before", start), ("after", end)):
                (output / f"metrics-{index}-{label}.prom").write_text(snap["raw"])
                write_json(output / f"metrics-{index}-{label}.json", {key: value for key, value in snap.items() if key != "raw"})
            metrics.append(summarize(start, end, index))
            own_origin_metrics.append(summarize(start, end, index, own_origin=True))
            instrumentation.append(summarize_instrumentation(start, end, index, args.transaction_size))
        throughputs = [node["commit_throughput_tx_s"] for node in metrics]
        latencies = [node["mean_generation_to_commit_latency_ms"] for node in metrics]
        manifest["metrics"] = {"per_replica": metrics, "commit_throughput_tx_s_median_across_replicas": statistics.median(throughputs),
                               "commit_throughput_tx_s_min_across_replicas": min(throughputs), "commit_throughput_tx_s_max_across_replicas": max(throughputs),
                               "mean_latency_ms_median_across_replicas": statistics.median(latencies),
                               "own_origin_per_replica": own_origin_metrics, "instrumentation_per_replica": instrumentation,
                               "network_bytes": sum(node["replica_tcp_written_bytes"] for node in instrumentation)}
        manifest["comparison"] = comparison_summary(metrics, own_origin_metrics, instrumentation, args)
        pending = []
        for index, snap in enumerate(after):
            pending.append(int(snap["values"]["benchmark_enqueued_transactions"] - snap["values"][f'benchmark_origin_latency_s_count{{origin="{index}"}}']))
        manifest["comparison"]["end_pending_generated_transactions_at_origins"] = pending
        manifest["checks"] = {"four_independent_processes_live_through_measurement": True, "all_replicas_committed_transactions": True, "all_replicas_committing_before_warmup": True,
                              "runtime_encoded_transaction_size_matches_request": True, "instrumented_replica_traffic_present": True,
                              "signature_verification_enabled": True, "native_wal_enabled": True, "exact_transaction_order_agreement": "not_checked"}
        manifest["status"] = "completed"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = f"{type(error).__name__}: {error}"
        (output / "error.txt").write_text(traceback.format_exc())
        print(manifest["error"], file=sys.stderr)
        exit_status = 1
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for stream in streams:
            stream.close()
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
                manifest["checks"]["committed_leader_authority_round_common_prefix"] = check_leader_prefixes(output)
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
