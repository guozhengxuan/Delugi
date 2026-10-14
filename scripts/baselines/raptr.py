#!/usr/bin/env python3
"""Build and run the pinned Raptr/Aptos consensus-only localhost artifact.

This uses the actual Aptos node, Quorum Store and native Forge workload. It is
not the stale standalone simulator. Local adapter changes are an explicit patch.
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
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
PIN = "a4c98047cf8aeae3571168d02fb7e343140d2948"
URL = "https://github.com/aptos-labs/aptos-core.git"
PATCH = ROOT / "benchmarks/patches/raptr-local.patch"
sys.path.insert(0, str(ROOT / "scripts"))


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command(args, cwd, env, archive, manifest, name):
    entry = {"argv": [str(x) for x in args], "cwd": str(cwd),
             "log": name + ".log", "start_unix": time.time()}
    manifest["commands"].append(entry)
    with (archive / entry["log"]).open("w") as log:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=log,
                                stderr=subprocess.STDOUT)
    entry.update(returncode=result.returncode, end_unix=time.time())
    if result.returncode:
        raise RuntimeError(f"{name} failed: see {archive / entry['log']}")


def build_identity(args, env):
    source_diff = subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=args.source)
    compiler = subprocess.check_output([str(args.toolchain.resolve() / "rustc"), "--version", "--verbose"], text=True)
    return {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip(),
            "source_diff_sha256": hashlib.sha256(source_diff).hexdigest(),
            "patch_sha256": sha256(PATCH), "lock_sha256": sha256(args.source / "Cargo.lock"),
            "rustc_verbose": compiler, "profile": "release",
            "node_features": "consensus-only-perf-test,failpoints,smoke-test",
            "build_environment": {key: env.get(key) for key in ["CFLAGS", "CXXFLAGS", "RUSTFLAGS", "CONSENSUS_ONLY_PERF_TEST"]}}


def write_build_stamp(args, env, expected_identity=None):
    stamp = build_identity(args, env)
    if expected_identity is not None and stamp != expected_identity:
        raise RuntimeError("Source or build settings changed during compilation; rebuild before measurement")
    stamp["forge_sha256"] = sha256(args.source / "target/release/forge")
    path = args.source / "target/delugi-baseline-build.json"
    path.write_text(json.dumps(stamp, indent=2) + "\n")
    return stamp


def verify_build_stamp(args, env):
    path = args.source / "target/delugi-baseline-build.json"
    if not path.is_file():
        raise RuntimeError("Missing verified Forge build stamp; run with --build")
    stamp = json.loads(path.read_text())
    for key, value in build_identity(args, env).items():
        if stamp.get(key) != value:
            raise RuntimeError(f"Forge build provenance changed ({key}); run with --build")
    if stamp.get("forge_sha256") != sha256(args.source / "target/release/forge"):
        raise RuntimeError("Forge executable changed; run with --build")
    return stamp


def metric_rows(text):
    result = []
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        match = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})?\s+(\S+)(?:\s+\S+)?', line)
        if match:
            labels = dict(re.findall(r'(\w+)="([^"\\]*(?:\\.[^"\\]*)*)"', match[2] or ""))
            result.append((match[1], labels, float(match[3])))
    return result


def total(rows, name, **labels):
    return sum(v for n, ls, v in rows if n == name and all(ls.get(k) == x for k, x in labels.items()))


def summarize(start, end, seconds, transaction_bytes=512):
    if not math.isfinite(seconds) or seconds <= 0 or not start or len(start) != len(end):
        raise ValueError("Need matching nonempty snapshots and a positive finite measurement interval")
    per_node = []
    completed = 0.0
    completion_duration = 0.0
    for first, last in zip(start, end):
        a, b = metric_rows(first), metric_rows(last)
        required = ["quorum_store_num_txns_per_block_sum", "raikou_block_commit_rate",
                    "raikou_mempool_insert_to_commit_latency_count",
                    "raikou_mempool_insert_to_commit_latency_sum",
                    "raptr_baseline_ingress_transactions", "raptr_baseline_ingress_transaction_bytes", "raptr_baseline_transaction_bytes",
                    "raptr_baseline_tcp_written_bytes", "raptr_baseline_tcp_read_bytes"]
        for name in required:
            if not any(n == name for n, _, _ in a) or not any(n == name for n, _, _ in b):
                raise ValueError(f"Missing required native metric {name}")
            if any(not math.isfinite(v) or v < 0
                   for rows in (a, b) for n, _, v in rows if n == name):
                raise ValueError(f"Native cumulative metric is negative or nonfinite: {name}")
        count = total(b, "quorum_store_num_txns_per_block_sum") - total(a, "quorum_store_num_txns_per_block_sum")
        blocks = total(b, "raikou_block_commit_rate") - total(a, "raikou_block_commit_rate")
        locally_completed = total(b, "raikou_mempool_insert_to_commit_latency_count") - total(a, "raikou_mempool_insert_to_commit_latency_count")
        local_duration = total(b, "raikou_mempool_insert_to_commit_latency_sum") - total(a, "raikou_mempool_insert_to_commit_latency_sum")
        ingress = total(b, "raptr_baseline_ingress_transactions") - total(a, "raptr_baseline_ingress_transactions")
        ingress_bytes = total(b, "raptr_baseline_ingress_transaction_bytes") - total(a, "raptr_baseline_ingress_transaction_bytes")
        written = total(b, "raptr_baseline_tcp_written_bytes") - total(a, "raptr_baseline_tcp_written_bytes")
        read = total(b, "raptr_baseline_tcp_read_bytes") - total(a, "raptr_baseline_tcp_read_bytes")
        pending_start = total(a, "raptr_baseline_ingress_transactions") - total(a, "raikou_mempool_insert_to_commit_latency_count")
        pending_end = total(b, "raptr_baseline_ingress_transactions") - total(b, "raikou_mempool_insert_to_commit_latency_count")
        if not all(math.isfinite(v) and v >= 0 for v in [count, blocks, locally_completed, local_duration,
                                                       ingress, ingress_bytes, written, read]):
            raise ValueError("Native completion counters regressed or became nonfinite")
        if any(total(rows, "raptr_baseline_transaction_bytes") != transaction_bytes for rows in (a, b)):
            raise ValueError("Native runtime transaction size assertion does not match requested serialized size")
        # Prometheus reads these independent atomics at different moments.
        # Pending estimates may also be negative when completion and admission
        # counters are sampled on different sides of a batch. Preserve the signed
        # differences and flag observed skew; they are not atomic queue gauges.
        # Exact size is enforced per admitted transaction in the native node;
        # retain the inter-counter scrape skew rather than inventing atomicity.
        ingress_byte_counter_skew = ingress_bytes - ingress * transaction_bytes
        if written <= 0 or read <= 0 or ingress <= 0:
            raise ValueError("Every replica must show native ingress and TCP traffic during measurement")
        if count <= 0 or locally_completed <= 0:
            raise ValueError("Every replica must commit payloads and complete local ingress transactions")
        completed += locally_completed
        completion_duration += local_duration
        per_node.append({"committed_transaction_inclusions": count,
                         "committed_transaction_inclusions_per_second": count / seconds,
                         "committed_blocks": blocks,
                         "local_ingress_completions": locally_completed,
                         "admitted_transactions": ingress,
                         "admitted_transaction_bytes": ingress_bytes,
                         "admitted_byte_counter_skew": ingress_byte_counter_skew,
                         "admitted_tx_s": ingress / seconds,
                         "pending_local_transactions_start": pending_start,
                         "pending_local_transactions_end": pending_end,
                         "pending_snapshot_negative_start": pending_start < 0,
                         "pending_snapshot_negative_end": pending_end < 0,
                         "pending_counter_snapshots": {
                             "start": {"admitted": total(a, "raptr_baseline_ingress_transactions"),
                                       "completed": total(a, "raikou_mempool_insert_to_commit_latency_count")},
                             "end": {"admitted": total(b, "raptr_baseline_ingress_transactions"),
                                     "completed": total(b, "raikou_mempool_insert_to_commit_latency_count")}},
                         "replica_tcp_written_bytes": written,
                         "replica_tcp_read_bytes": read,
                         "local_ingress_completion_mean_ms": local_duration * 1000 / locally_completed if locally_completed else None})
    latency = {}
    for stage in ["BATCHCOMMIT", "COMMITBLOCK"]:
        count = 0.0
        duration = 0.0
        for first, last in zip(start, end):
            a, b = metric_rows(first), metric_rows(last)
            count += total(b, "aptos_consensus_block_tracing_count", stage=stage) - total(a, "aptos_consensus_block_tracing_count", stage=stage)
            duration += total(b, "aptos_consensus_block_tracing_sum", stage=stage) - total(a, "aptos_consensus_block_tracing_sum", stage=stage)
        latency[stage] = {"samples": count, "mean_ms": duration * 1000 / count if count else None}
    written = sum(row["replica_tcp_written_bytes"] for row in per_node)
    read = sum(row["replica_tcp_read_bytes"] for row in per_node)
    ingress = sum(row["admitted_transactions"] for row in per_node)
    return {"measurement_seconds": seconds, "replicas": per_node, "latency": latency,
            "admitted_transactions": ingress, "admitted_tx_s": ingress / seconds,
            "pending_local_transactions_start": sum(row["pending_local_transactions_start"] for row in per_node),
            "pending_local_transactions_end": sum(row["pending_local_transactions_end"] for row in per_node),
            "pending_snapshot_skew_detected": any(row["pending_snapshot_negative_start"] or row["pending_snapshot_negative_end"] for row in per_node),
            "pending_estimate_scope": "Signed differences of independently scraped cumulative admission and completion counters; not atomic queue gauges. Negative estimates are preserved and flagged, never clamped.",
            "replica_tcp_written_bytes": written, "replica_tcp_read_bytes": read,
            "replica_tcp_written_bytes_per_second": written / seconds,
            "replica_tcp_written_bytes_per_unique_completion": written / completed if completed else None,
            "median_replica_inclusion_tps": statistics.median(r["committed_transaction_inclusions_per_second"] for r in per_node),
            "unique_ingress_completions": completed,
            "unique_ingress_completion_tps": completed / seconds,
            "ingress_to_materialized_commit_mean_ms": completion_duration * 1000 / completed if completed else None}



def analyze_measurement(archive, manifest, first, last, start, end, start_skew, end_skew, transaction_bytes):
    # Save timing before validation so a parser failure retains the exact window.
    window = {"start_midpoint_monotonic_seconds": start,
              "end_midpoint_monotonic_seconds": end,
              "measurement_seconds": end - start,
              "snapshot_spread_seconds": {"start": start_skew, "end": end_skew}}
    manifest["measurement_window"] = window
    (archive / "measurement-window.json").write_text(json.dumps(window, indent=2) + "\n")
    metrics = summarize(first, last, end - start, transaction_bytes)
    metrics["snapshot_spread_seconds"] = window["snapshot_spread_seconds"]
    return metrics




def ingress_shape(rate, nodes, batch_ms):
    if nodes <= 0 or rate < nodes or rate % nodes or batch_ms < 0:
        raise ValueError("Need a positive integral per-origin rate and nonnegative ingress batch cadence")
    per_origin = rate // nodes
    if batch_ms == 0:
        return {"transactions_per_request": 1, "staggered_slots_per_origin": per_origin,
                "request_interval_ms": 1000 / per_origin, "mode": "native_one_transaction_requests"}
    if batch_ms > 1000 or 1000 % batch_ms or (per_origin * batch_ms) % 1000:
        raise ValueError("Ingress cadence must divide one second and produce an integral transaction batch")
    batch_size = per_origin * batch_ms // 1000
    if batch_size <= 0:
        raise ValueError("Ingress batch must contain at least one transaction")
    return {"transactions_per_request": batch_size, "staggered_slots_per_origin": 1000 // batch_ms,
            "request_interval_ms": batch_ms, "mode": "matched_batch_requests"}


def native_wire_samples(log, args):
    samples = re.findall(r"RAPTR_BASELINE_WIRE client=(\d+) txns=(\d+) batch_bytes=(\d+) transaction_bytes=(\d+)", log)
    if len(samples) != args.nodes or {int(c) for c, _, _, _ in samples} != set(range(args.nodes)):
        raise RuntimeError("Expected one native serialized transaction size sample from every client")
    expected = ingress_shape(args.rate, args.nodes, args.ingress_batch_ms)["transactions_per_request"]
    prefix_bytes = max(1, (expected.bit_length() + 6) // 7)
    if any(int(n) != expected or int(t) != args.transaction_bytes
           or int(b) != expected * args.transaction_bytes + prefix_bytes for _, n, b, t in samples):
        raise RuntimeError("Native transaction size or ingress batch differs from matched workload request")
    return [dict(client=int(c), transactions=int(n), bcs_batch_bytes=int(b), bcs_transaction_bytes=int(t))
            for c, n, b, t in samples]

def comparison(args, metrics):
    return {"protocol": "raptr", "replicas": args.nodes, "offered_tx_s": args.rate,
            "transaction_bytes": args.transaction_bytes, "warmup_seconds": args.warmup,
            "ingress_batch_ms": args.ingress_batch_ms,
            "protocol_bound_ms": args.delta_ms,
            "ingress_mode": ingress_shape(args.rate, args.nodes, args.ingress_batch_ms)["mode"],
            "measurement_seconds": metrics["measurement_seconds"],
            "unique_completion_tps": metrics["unique_ingress_completion_tps"],
            "mean_latency_ms": metrics["ingress_to_materialized_commit_mean_ms"],
            "latency_endpoint": "Native API mempool insertion to payload-ready commit notification at the transaction's ingress replica; transaction weighted completion-window mean, excludes client generation and HTTP ingress",
            "traffic_boundary": "successful_replica_tcp_stream_writes",
            "replica_tcp_written_bytes": metrics["replica_tcp_written_bytes"],
            "replica_tcp_read_bytes": metrics["replica_tcp_read_bytes"],
            "replica_tcp_written_bytes_per_second": metrics["replica_tcp_written_bytes_per_second"],
            "completion_count": metrics["unique_ingress_completions"],
            "generated_count": None, "generation_tps": None,
            "admitted_count": metrics["admitted_transactions"],
            "admission_tps": metrics["admitted_tx_s"],
            "pending_local_transactions_start": metrics["pending_local_transactions_start"],
            "pending_local_transactions_end": metrics["pending_local_transactions_end"],
            "pending_snapshot_skew_detected": metrics["pending_snapshot_skew_detected"],
            "pending_estimate_scope": metrics["pending_estimate_scope"]}

def config_metrics_address(path):
    text = path.read_text()
    match = re.search(r"(?m)^inspection_service:\s*\n((?:[ \t].*\n|\n)+)", text)
    if not match:
        raise RuntimeError(f"Missing inspection service configuration in {path}")
    port = re.search(r"(?m)^\s+port:\s*(\d+)", match[1])
    if not port:
        raise RuntimeError(f"Missing metrics port in {path}")
    return "http://127.0.0.1:" + port[1] + "/metrics"


def config_replica_ports(path):
    """All three native validator transports; excludes fullnode, API and metrics."""
    text = path.read_text()
    ports = []
    for section in ("validator_network", "validator_network2", "validator_network3"):
        blocks = re.findall(r"(?m)^" + section + r":\s*\n((?:[ \t].*\n|\n)+)", text)
        if len(blocks) != 1:
            raise RuntimeError(f"Expected one {section} configuration in {path}")
        matches = re.findall(r'(?m)^\s+listen_address:\s*[\"\']?/ip4/127\.0\.0\.1/tcp/(\d+)[\"\']?\s*$', blocks[0])
        if len(matches) != 1 or not 1 <= int(matches[0]) <= 65535:
            raise RuntimeError(f"Expected one loopback TCP listener for {section} in {path}")
        ports.append(int(matches[0]))
    if len(set(ports)) != 3:
        raise RuntimeError(f"Native validator listeners overlap in {path}")
    return ports


def timing_profile(delta_ms):
    if not isinstance(delta_ms, int) or isinstance(delta_ms, bool) or not 1 <= delta_ms <= 60000:
        raise ValueError("Raptr protocol bound must be an integer from 1 through 60000 milliseconds")
    return {"delta_ms": delta_ms, "leader_timeout_ms": 4 * delta_ms,
            "partial_qc_wait_ms": .1 * delta_ms, "block_fetch_interval_ms": 2 * delta_ms,
            "round_sync_interval_ms": 15 * delta_ms, "status_interval_ms": 10 * delta_ms,
            "quorum_store_batch_poll_ms": 150, "quorum_store_min_nonempty_batch_ms": 80,
            "quorum_store_max_batch_interval_ms": 300, "payload_wait_budget_ms": 1500,
            "scope": "Native Raptr timer multipliers; Quorum Store batching and payload retrieval budgets preserved independently"}


def verify_native_timing(configs, delta_ms):
    observations = []
    for config in configs:
        path = config.parent / "log"
        values = [int(value) for value in re.findall(r"RAPTR_BASELINE_TIMING delta_ms=(\d+)", path.read_text(errors="replace"))]
        if not values or any(value != delta_ms for value in values):
            raise RuntimeError(f"Missing or mismatched native Raptr timing diagnostic in {path}")
        observations.append({"node": config.parent.name, "log": str(path), "delta_ms": values})
    return observations


def configure_network_shaping(configs, archive, manifest):
    from network_delay import configure_from_environment
    ports = sorted(port for config in configs for port in config_replica_ports(config))
    if len(set(ports)) != 3 * len(configs):
        raise RuntimeError("Native validator transport ports overlap across replicas")
    manifest["replica_network_ports"] = ports
    helper = ROOT / "scripts/network_delay.py"
    shutil.copy2(helper, archive / helper.name)
    manifest["network_shaping_helper_sha256"] = sha256(helper)
    shaping = configure_from_environment("raptr", ports)
    manifest["network_shaping"] = shaping
    return shaping


def clear_network_shaping():
    from network_delay import clear_from_environment
    return clear_from_environment()


def snapshot(urls, archive, phase):
    # Bypass ambient public-network proxies for local replica metrics.
    def fetch(pair):
        index, url = pair
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=10) as response:
            text = response.read().decode()
        (archive / f"metrics-{phase}-{index}.prom").write_text(text)
        return text
    before = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(urls)) as pool:
        data = list(pool.map(fetch, enumerate(urls)))
    after = time.monotonic()
    return data, (before + after) / 2, after - before


def check_ports(base, nodes):
    held = []
    try:
        for node in range(nodes):
            for offset in [0, 1, 3]:
                sock = socket.socket()
                # Match the native listener: completed prior runs may leave TCP TIME_WAIT.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", base + node * 10 + offset))
                held.append(sock)
    finally:
        for sock in held:
            sock.close()


def process_group_members(group_id):
    members = []
    for line in subprocess.check_output(["ps", "-axo", "pid=,pgid=,comm="], text=True).splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) == 3 and int(fields[1]) == group_id:
            members.append({"pid": int(fields[0]), "executable": fields[2]})
    return members


def signal_owned_group(process, sig):
    # macOS may return EPERM for an already-empty group. Only signal a group
    # with current members, and preserve real cleanup errors if any remain.
    if not process_group_members(process.pid):
        return
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        members = process_group_members(process.pid)
        for member in members:
            try:
                os.kill(member["pid"], sig)
            except ProcessLookupError:
                pass


def run_benchmark(args, env, archive, manifest):
    manifest["build_stamp"] = verify_build_stamp(args, env)
    check_ports(args.base_port, args.nodes)
    binary = args.source / "target/release/forge"
    node_binary = args.source / "target/release/aptos-node"
    for path in [binary, node_binary]:
        if not path.is_file():
            raise RuntimeError(f"Missing executable: {path}; run with --build")
    manifest["native_forge_rebuild"] = {"argv": ["cargo", "build", "--features=failpoints,smoke-test", "--features=consensus-only-perf-test", "--release", "--locked", "--package=aptos-node"], "cwd": str(args.source), "CARGO_TARGET_DIR": str(args.source / "target"), "phase": "Forge setup, before client startup and measurements", "note": "The pinned Forge builds aptos-node separately to isolate Cargo features; successful compiler output is suppressed by Forge."}
    duration = args.startup + args.readiness_timeout + args.warmup + args.duration + 5
    manifest["settings"]["native_test_lifetime_seconds"] = duration
    argv = [str(binary), "--suite", "multiregion_benchmark_test",
            "--num-validators", str(args.nodes), "--num-validator-fullnodes", str(args.rate),
            "--duration-secs", str(duration), "test", "local-swarm", "--swarmdir", str(archive / "swarm")]
    manifest["commands"].append({"argv": argv, "cwd": str(args.source), "log": "forge.log"})
    env = dict(env, RAPTR_LOCAL_BASE_PORT=str(args.base_port),
               RAPTR_CLIENT_STARTUP_SECONDS=str(args.startup), RAPTR_TRANSACTION_BYTES=str(args.transaction_bytes),
               RAPTR_INGRESS_BATCH_MS=str(args.ingress_batch_ms),
               RAPTR_DELTA_MS=str(args.delta_ms),
               FORGE_BUILD_WITHOUT_INDEXER="1",
               APTOS_DISABLE_TELEMETRY="true",
               NO_PROXY=",".join(filter(None, [env.get("NO_PROXY", ""), "127.0.0.1,localhost,::1,0.0.0.0"])),
               no_proxy=",".join(filter(None, [env.get("no_proxy", ""), "127.0.0.1,localhost,::1,0.0.0.0"])))
    manifest["runtime_environment"] = {k: env[k] for k in ["RAPTR_LOCAL_BASE_PORT", "RAPTR_CLIENT_STARTUP_SECONDS", "RAPTR_TRANSACTION_BYTES", "RAPTR_INGRESS_BATCH_MS", "RAPTR_DELTA_MS", "FORGE_BUILD_WITHOUT_INDEXER", "APTOS_DISABLE_TELEMETRY", "NO_PROXY", "no_proxy"]}
    shaping = None
    with (archive / "forge.log").open("w") as log:
        process = subprocess.Popen(argv, cwd=args.source, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + args.setup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"Forge exited during setup: {process.returncode}")
                if "num_clients " in (archive / "forge.log").read_text(errors="replace"):
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError("Timed out waiting for native workload startup")
            configs = sorted((archive / "swarm").glob("*/node.yaml"))
            if len(configs) != args.nodes:
                raise RuntimeError(f"Expected {args.nodes} node configs, found {len(configs)}")
            urls = [config_metrics_address(path) for path in configs]
            manifest["metrics_endpoints"] = urls
            members = process_group_members(process.pid)
            manifest["process_group_members_at_workload_start"] = members
            if sum(Path(member["executable"]).name == "aptos-node" for member in members) != args.nodes:
                raise RuntimeError("Native workload did not start the requested independent Aptos node processes")
            readiness_start = time.monotonic()
            readiness_deadline = readiness_start + args.startup + args.readiness_timeout
            while time.monotonic() < readiness_deadline:
                if process.poll() is not None:
                    raise RuntimeError("Forge exited before all native ingress nodes made progress")
                ready, ready_time, ready_skew = snapshot(urls, archive, "ready")
                if time.monotonic() > readiness_deadline:
                    raise RuntimeError("Native readiness scrape exceeded its bounded deadline")
                counts = [total(metric_rows(body), "raikou_mempool_insert_to_commit_latency_count") for body in ready]
                if all(math.isfinite(count) and count > 0 for count in counts):
                    manifest["workload_readiness"] = {"seconds_after_native_client_spawn": ready_time - readiness_start, "ingress_completion_counts": counts, "snapshot_spread_seconds": ready_skew, "condition": "Every ingress node has materialized at least one committed local transaction before warmup starts"}
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Timed out waiting for materialized native ingress completions before warmup")
            manifest["native_timing_observations"] = verify_native_timing(configs, args.delta_ms)
            shaping = configure_network_shaping(configs, archive, manifest)
            time.sleep(args.warmup)
            first, start, start_skew = snapshot(urls, archive, "start")
            time.sleep(args.duration)
            last, end, end_skew = snapshot(urls, archive, "end")
            manifest["metrics"] = analyze_measurement(
                archive, manifest, first, last, start, end, start_skew, end_skew, args.transaction_bytes)
            manifest["comparison"] = comparison(args, manifest["metrics"])
            rc = process.wait(timeout=args.startup + args.readiness_timeout + 15)
            manifest["shutdown"] = {"mode": "natural native benchmark duration elapsed", "returncode": rc}
            manifest["commands"][-1]["returncode"] = rc
            manifest["settings"]["native_wire_samples"] = native_wire_samples(
                (archive / "forge.log").read_text(errors="replace"), args)
            if rc:
                raise RuntimeError(f"Native Forge benchmark exited with status {rc}")
            if any(r["committed_transaction_inclusions"] <= 0 or r["local_ingress_completions"] <= 0 for r in manifest["metrics"]["replicas"]):
                raise RuntimeError("At least one replica reported zero committed transaction inclusions or zero local ingress completions")
            manifest["status"] = "passed"
        finally:
            try:
                manifest.setdefault("shutdown", {"mode": "cleanup after runner error", "returncode_before_cleanup": process.poll()})
                signal_owned_group(process, signal.SIGTERM)
                if process.poll() is None:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        signal_owned_group(process, signal.SIGKILL)
                        process.wait()
                signal_owned_group(process, signal.SIGKILL)
                manifest["commands"][-1].setdefault("returncode", process.poll())
                manifest["remaining_owned_processes_after_cleanup"] = process_group_members(process.pid)
                # Hash after the timed interval: Forge may have rebuilt this node,
                # and hashing large release binaries must not consume workload time.
                manifest["binaries"] = {p.name: {"path": str(p), "sha256": sha256(p)} for p in [binary, node_binary]}
                manifest["binary_hash_phase"] = "after measurement and Forge exit/cleanup"
            finally:
                if shaping is not None:
                    manifest["network_shaping_cleanup"] = clear_network_shaping()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "benchmarks/baselines/raptr")
    parser.add_argument("--toolchain", type=Path, default=ROOT / "benchmarks/toolchains/mysticeti/toolchains/1.78-aarch64-apple-darwin/bin")
    parser.add_argument("--build", action="store_true", help="Build release node and Forge before running")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--nodes", type=int, default=4)
    parser.add_argument("--rate", type=int, default=1000, help="Aggregate native offered transactions per second")
    parser.add_argument("--transaction-bytes", "--transaction-size", dest="transaction_bytes", type=int, default=512, help="Exact BCS SignedTransaction size, including native metadata/authenticator")
    parser.add_argument("--ingress-batch-ms", type=int, default=0, help="Optional matched ingress request cadence; 0 preserves native one-transaction requests, 100 batches every 100 ms")
    parser.add_argument("--delta-ms", "--bound-ms", dest="delta_ms", type=int, default=200, help="Raptr protocol bound in ms; preserves native timer multipliers and independent Quorum Store batching")
    parser.add_argument("--startup", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--readiness-timeout", type=int, default=45, help="Allowance for native client preparation before transaction progress and warmup")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--base-port", type=int, default=24000)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--setup-timeout", type=int, default=600)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.transaction_bytes < 256 or args.transaction_bytes > 4096 or args.nodes < 4 or args.rate < args.nodes or args.rate % args.nodes or min(args.duration, args.jobs, args.readiness_timeout) <= 0 or min(args.startup, args.warmup) < 0:
        parser.error("Use at least four nodes, a positive rate divisible by nodes, and positive duration/jobs")
    try:
        configured_ingress = ingress_shape(args.rate, args.nodes, args.ingress_batch_ms)
        configured_timing = timing_profile(args.delta_ms)
    except ValueError as error:
        parser.error(str(error))
    args.source = args.source.resolve()
    archive = (args.output or ROOT / "results/local" / ("baseline-raptr-" + uuid.uuid4().hex)).resolve()
    archive.mkdir(parents=True, exist_ok=False)
    shutil.copy2(Path(__file__), archive / "runner.py")
    manifest = {"baseline": "raptr", "source_url": URL, "source_commit": PIN,
                "status": "running", "settings": dict(vars(args), ingress=configured_ingress, timing=configured_timing), "commands": [], "metrics": {},
                "runner_sha256": sha256(Path(__file__)), "python_version": platform.python_version(),
                "machine": {"platform": platform.platform(), "cpu_count": os.cpu_count()},
                "workload": {"transaction": "Native synthetic SignedTransaction with unique random sender per slot and increasing sequence, padded to exact requested BCS bytes using an opaque extra entry-function argument; consensus-only payload, no VM execution", "client_authenticator": "NoAccountAuthenticator, as in pinned consensus-only benchmark", "consensus_authentication": "Pinned native BLS signatures and authenticated Aptos networking", "vm_execution": False, "native_delta_ms": args.delta_ms, "native_optimistic_dissemination": True, "storage": "Real AptosDB genesis with native FakeAptosDB wrapper; steady-state transaction execution/ledger commit is bypassed. Quorum Store payloads and batch IDs use RocksDB writes (upstream does not explicitly sync each write). Raptr protocol state is in memory and restart recovery is not exercised. Generated node configurations retained in swarm/."},
                "measurement_boundaries": {
                    "throughput": "Sum of native raikou_mempool_insert_to_commit_latency_count deltas across ingress nodes. Native PendingTracker removes each locally submitted (sender,sequence) once, after real payload retrieval and commit notification. Distinct senders across ingress nodes; no VM execution. The separate per-replica inclusion rates are never added together.",
                    "completion_latency": "Native mempool insertion to committed transaction payload retrieval and notification at its ingress node, transaction weighted mean over completions observed inside the snapshot interval (not an arrival cohort). Excludes client-side generation, scheduling and HTTP ingress time. This is not an all-replica completion barrier.",
                    "BATCHCOMMIT": "Native batch creation timestamp to commit notification, observed only at batch creator; arithmetic mean across creators, batch weighted, excludes client queueing.",
                    "COMMITBLOCK": "Native proposal timestamp to leader-local commit, observed only at that block's leader; block weighted mean.",
                    "traffic": "Sum of native replica TcpSocket successful write-byte deltas below Noise authentication/encryption and Aptos framing. Reads retained separately, not added to writes. Includes protocol/control/peer monitoring/state-sync on validator transports; excludes client HTTP, metrics, TCP/IP headers, kernel retransmissions, and pre-window handshakes. Snapshot boundary skew is retained; written/read equality is not required across live cuts.",
                    "offered_load": "Native clients are paced at configured aggregate rate. Optional matched mode sends one multi-transaction HTTP request every configured ingress interval per origin, preserving native consensus and Quorum Store batching. Actual mempool insertion counts, inserted BCS bytes, and pending insertion-minus-completion counts are measured. Every native insertion asserts the configured serialized size; byte/count metric scrape skew is retained separately. Pending values are signed admission-minus-completion estimates from non-atomic scrapes; negative estimates remain visible with flags rather than being interpreted as counter regressions. Client pre-generation counts are not measured and not presented as achieved load."}}
    env = os.environ.copy()
    env.update(PATH=str(args.toolchain.resolve()) + os.pathsep + env["PATH"],
               CARGO_HOME=str(ROOT / "benchmarks/.cache/raptr-cargo"),
               CARGO_NET_GIT_FETCH_WITH_CLI="true", CARGO_BUILD_JOBS=str(args.jobs),
               CONSENSUS_ONLY_PERF_TEST="1", FORGE_BUILD_WITHOUT_INDEXER="1")
    if platform.system() == "Darwin":
        # Old bundled zlib mistakes modern TARGET_OS_MAC for classic Mac OS and
        # defines fdopen as NULL. Preserve the SDK's real fdopen declaration.
        env["CFLAGS"] = (env.get("CFLAGS", "") + " -Dfdopen=fdopen").strip()
    manifest["build_environment"] = {k: env[k] for k in ["CARGO_HOME", "CARGO_BUILD_JOBS", "CONSENSUS_ONLY_PERF_TEST", "CFLAGS"] if k in env}
    try:
        if not (args.toolchain / "rustc").is_file():
            raise RuntimeError(f"Rust 1.78 toolchain missing at {args.toolchain}; provide --toolchain with its bin directory")
        command([str(args.toolchain.resolve() / "rustc"), "--version", "--verbose"], ROOT, env, archive, manifest, "rustc-version")
        if not args.source.exists():
            args.source.parent.mkdir(parents=True, exist_ok=True)
            command(["git", "clone", "--filter=blob:none", "--no-checkout", "--single-branch", "--branch", "raptr-public", URL, str(args.source)], ROOT, env, archive, manifest, "clone")
            command(["git", "checkout", "--detach", PIN], args.source, env, archive, manifest, "checkout")
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=args.source, text=True).strip()
        if actual != PIN:
            raise RuntimeError(f"Source is {actual}, expected {PIN}; refusing to change an existing checkout")
        if subprocess.run(["git", "apply", "--reverse", "--check", str(PATCH)], cwd=args.source, capture_output=True).returncode:
            command(["git", "apply", "--check", str(PATCH)], args.source, env, archive, manifest, "patch-check")
            command(["git", "apply", str(PATCH)], args.source, env, archive, manifest, "patch")
        shutil.copy2(PATCH, archive / PATCH.name)
        manifest["patches"] = [{"file": PATCH.name, "sha256": sha256(PATCH)}]
        (archive / "source.diff").write_bytes(subprocess.check_output(["git", "diff", "HEAD", "--binary"], cwd=args.source))
        if args.build or args.build_only:
            identity_before_build = build_identity(args, env)
            command(["cargo", "build", "--release", "--locked", "-p", "aptos-node", "--features", "consensus-only-perf-test,failpoints,smoke-test", "-p", "aptos-forge-cli"], args.source, env, archive, manifest, "build")
            manifest["build_stamp"] = write_build_stamp(args, env, identity_before_build)
        if args.build_only:
            manifest["status"] = "built"
        else:
            run_benchmark(args, env, archive, manifest)
    except BaseException as error:
        manifest.update(status="failed", error=str(error))
        raise
    finally:
        for path in [args.source / "Cargo.lock", args.source / "rust-toolchain.toml"]:
            if path.exists():
                shutil.copy2(path, archive / path.name)
        (archive / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str) + "\n")
        print(archive)


if __name__ == "__main__":
    main()
