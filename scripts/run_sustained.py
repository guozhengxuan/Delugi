#!/usr/bin/env python3
"""Sustained four-replica Delugi load over authenticated loopback TCP.

Each producer paces unique canonical transactions on its protocol thread. The
measurement window is captured inside each replica after a separate warmup;
completion is counted only at the originating producer, once per transaction.
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import math
import os
import subprocess
import sys
import time
import uuid

from run_network import add_ordering_arguments, Child, Controller, ROOT, machine_metadata, sha, unused_addresses, queued_frames, ordering_options
from network_delay import configure_from_environment, clear_from_environment


def tcp_counters(snapshot):
    transport = snapshot["transport"]
    peers = list(transport["peers"].values())
    return {
        "written_bytes": sum(peer["ack_bytes_written"] + sum(layer["data_bytes_written"]
                             for layer in peer["layers"].values()) for peer in peers),
        "read_bytes": transport["data_bytes_read"] + sum(peer["ack_bytes_read"] for peer in peers),
    }


def counter_delta(start, end, key):
    value = end[key] - start[key]
    if value < 0:
        raise AssertionError(f"counter decreased: {key}")
    return value


def summarize_windows(snapshots, offered_rate, transaction_size, warmup, ingress_batch_ms=10):
    rows, histogram = [], {}
    for replica, snapshot in sorted(snapshots.items()):
        start, end = snapshot["measurement_start"], snapshot["measurement_end"]
        duration = counter_delta(start, end, "elapsed_us") / 1_000_000
        if duration <= 0:
            raise AssertionError("measurement interval must be positive")
        load_start, load_end = start["load"], end["load"]
        completed = counter_delta(load_start, load_end, "completed")
        generated = counter_delta(load_start, load_end, "inserted")
        latency_sum = counter_delta(load_start, load_end, "latency_sum_us")
        for bucket in set(load_start["latency_histogram_ms"]) | set(load_end["latency_histogram_ms"]):
            count = load_end["latency_histogram_ms"].get(bucket, 0) - load_start["latency_histogram_ms"].get(bucket, 0)
            if count < 0:
                raise AssertionError("latency histogram counter decreased")
            histogram[int(bucket)] = histogram.get(int(bucket), 0) + count
        before, after = tcp_counters(start), tcp_counters(end)
        rows.append({"replica": replica, "seconds": duration, "completion_count": completed,
                     "generated_count": generated, "unique_completion_tps": completed / duration,
                     "generation_tps": generated / duration, "latency_sum_us": latency_sum,
                     "pending_at_start": load_start["pending"], "pending_at_end": load_end["pending"],
                     "maximum_schedule_lag_us": load_end["maximum_schedule_lag_us"],
                     "written_bytes": counter_delta(before, after, "written_bytes"),
                     "read_bytes": counter_delta(before, after, "read_bytes"),
                     "start_unix_us": start["observed_unix_us"], "end_unix_us": end["observed_unix_us"]})
    completed = sum(row["completion_count"] for row in rows)
    if sum(histogram.values()) != completed:
        raise AssertionError("histogram must count every origin-local completion exactly once")
    duration = sum(row["seconds"] for row in rows) / len(rows)
    written = sum(row["written_bytes"] for row in rows)
    read = sum(row["read_bytes"] for row in rows)
    comparison = {"protocol": "delugi", "replicas": len(rows), "offered_tx_s": offered_rate,
                  "transaction_bytes": transaction_size, "warmup_seconds": warmup, "ingress_batch_ms": ingress_batch_ms,
                  "measurement_seconds": duration,
                  "unique_completion_tps": sum(row["unique_completion_tps"] for row in rows),
                  "mean_latency_ms": sum(row["latency_sum_us"] for row in rows) / completed / 1000 if completed else None,
                  "latency_endpoint": "local producer insertion immediately before signed batch production to post-handler local materialization; completed-in-window population",
                  "traffic_boundary": "successful_replica_tcp_stream_writes",
                  "replica_tcp_written_bytes": written, "replica_tcp_read_bytes": read,
                  "replica_tcp_written_bytes_per_second": sum(row["written_bytes"] / row["seconds"] for row in rows),
                  "completion_count": completed, "generated_count": sum(row["generated_count"] for row in rows),
                  "generation_tps": sum(row["generation_tps"] for row in rows),
                  "pending_at_start": sum(row["pending_at_start"] for row in rows),
                  "pending_at_end": sum(row["pending_at_end"] for row in rows)}
    comparison["generation_target_met"] = comparison["generation_tps"] >= .95 * offered_rate
    comparison["completion_target_met"] = comparison["unique_completion_tps"] >= .95 * offered_rate
    tails = {}
    for percentile in (50, 95, 99):
        target, count = math.ceil(completed * percentile / 100), 0
        tails[f"p{percentile}_upper_bound_ms"] = None
        for bucket, amount in sorted(histogram.items()):
            count += amount
            if count >= target and completed:
                tails[f"p{percentile}_upper_bound_ms"] = bucket
                break
    return {"comparison": comparison, "per_replica": rows,
            "latency_histogram_ms": histogram, "latency_quantiles": tails,
            "measurement_start_skew_us": max(r["start_unix_us"] for r in rows) - min(r["start_unix_us"] for r in rows),
            "measurement_end_skew_us": max(r["end_unix_us"] for r in rows) - min(r["end_unix_us"] for r in rows),
            "offered_load_fraction": comparison["generation_tps"] / offered_rate}


def assert_healthy(snapshots):
    for replica, snapshot in snapshots.items():
        if snapshot["rejected_protocol_messages"] or snapshot["transport"]["queue_full_failures"] or snapshot["transport"]["rejected_frames"]:
            raise AssertionError(f"replica {replica}: invalid protocol frame or transport overload")


def assert_agreement(snapshots):
    generated = sum(s["load"]["inserted"] for s in snapshots.values())
    hashes = {tuple(s["state_hash"]) for s in snapshots.values()}
    if len(hashes) != 1 or any(s["executed_count"] != generated or s["load"]["pending"] for s in snapshots.values()):
        raise AssertionError("replicas did not materialize all distinct generated transactions with identical output state")
    return {"unique_generated_transactions": generated, "executed_per_replica": generated,
            "state_hash": next(iter(hashes)), "replicas_agree": True}


def assert_common_prefix(replies, count):
    hashes = {tuple(reply["reply"]["data"]["state_hash"]) for reply in replies}
    if len(replies) != 4 or len(hashes) != 1 or any(reply["reply"]["data"]["count"] != count for reply in replies):
        raise AssertionError("replicas disagree on their common executed prefix")
    return {"common_prefix_count": count, "common_prefix_state_hash": next(iter(hashes)),
            "replicas_agree_on_common_prefix": True}


def replica_network_ports(config):
    addresses = config["addresses"]
    if len(addresses) != 4 or any(not address.startswith("127.0.0.1:") for address in addresses):
        raise ValueError("Shaping expects exactly four loopback replica addresses")
    ports = [int(address.rsplit(":", 1)[1]) for address in addresses]
    if len(set(ports)) != 4 or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Replica TCP ports must be distinct and valid")
    return ports


def run_trial(binary, directory, total_rate, warmup_seconds, measurement_seconds,
              transaction_size=512, batch_ms=10, bound_ms=250, drain_seconds=30,
              ordering_batch=True, round_barrier_ms=None, progress_pacing_ms=None, ordering_mode=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if total_rate <= 0 or total_rate % 4 or warmup_seconds <= 0 or measurement_seconds <= 0:
        raise ValueError("rate must be positive and divisible by four, and intervals positive")
    keys = subprocess.run([str(binary), "--keygen", str(directory / "keys"), "--nodes", "4"],
                          cwd=ROOT, text=True, capture_output=True, check=True)
    keys = json.loads(keys.stdout)
    addresses = unused_addresses(8)
    config = {"instance": list(os.urandom(32)), "addresses": addresses[:4], "control_addresses": addresses[4:],
              "control_token": os.urandom(32).hex(), **keys, "bound_ms": bound_ms,
              "chunk_capacity": 64, "workload_rounds": 4, "silent": None,
              "max_runtime_ms": int((warmup_seconds + measurement_seconds + drain_seconds + 25) * 1000),
              "sustained": {"rate_per_replica": total_rate // 4, "transaction_bytes": transaction_size,
                            "batch_ms": batch_ms, "warmup_ms": round(warmup_seconds * 1000),
                            "measurement_ms": round(measurement_seconds * 1000)},
              **ordering_options(bound_ms, ordering_batch, round_barrier_ms, progress_pacing_ms, ordering_mode)}
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    children, controller, shaping = [], None, None
    result = {"status": "failed", "config": str(config_path), "settings": config["sustained"],
              "protocol_bound_ms": bound_ms, "children": [],
              "ordering_options": {k: config[k] for k in ("ordering_batch", "ordering_mode", "round_barrier_ms", "progress_pacing_ms") if k in config}}
    try:
        helper_source = (ROOT / "scripts/network_delay.py").read_bytes()
        (directory / "network_delay.py").write_bytes(helper_source)
        result["network_shaping_helper_sha256"] = sha(helper_source)
        for i in range(4):
            children.append(Child(binary, config_path, i, directory))
        controller = Controller(config, directory, children)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            controller.check()
            if all(any(event.get("event") == "ready" for event in child.events) for child in children):
                break
            time.sleep(.01)
        else:
            raise TimeoutError("replicas did not become ready")
        ports = replica_network_ports(config)
        result["replica_network_ports"] = ports
        shaping = configure_from_environment("delugi", ports)
        result["network_shaping"] = shaping
        controller.many(list(range(4)), "start")
        start_unix_us = time.time_ns() // 1000 + 1_000_000
        controller.many(list(range(4)), "load", start_unix_us=start_unix_us)
        deadline = time.monotonic() + warmup_seconds + measurement_seconds + 10
        while time.monotonic() < deadline:
            controller.check()
            snapshots = controller.snapshots()
            assert_healthy(snapshots)
            if all(s["measurement_end"] is not None for s in snapshots.values()):
                break
            time.sleep(.5)
        else:
            raise TimeoutError("replicas did not finish their measurement windows")
        result.update(summarize_windows(snapshots, total_rate, transaction_size, warmup_seconds, batch_ms))
        result["comparison"]["protocol_bound_ms"] = bound_ms
        if any(row["completion_count"] <= 0 for row in result["per_replica"]):
            raise AssertionError("all four replicas must make origin-local output progress during the window")
        drain_started = time.monotonic()
        deadline = drain_started + drain_seconds
        while time.monotonic() < deadline:
            controller.check()
            snapshots = controller.snapshots()
            assert_healthy(snapshots)
            generated = sum(s["load"]["inserted"] for s in snapshots.values())
            if all(s["executed_count"] == generated and s["load"]["pending"] == 0 for s in snapshots.values()):
                break
            time.sleep(.1)
        result["drain_seconds"] = time.monotonic() - drain_started
        controller.many(list(range(4)), "quiesce")
        deadline, previous, stable_at = time.monotonic() + 10, None, None
        while time.monotonic() < deadline:
            snapshots = controller.snapshots()
            signature = [tcp_counters(s) for s in snapshots.values()]
            if all(queued_frames(s) == 0 for s in snapshots.values()) and signature == previous:
                if stable_at is None:
                    stable_at = time.monotonic()
                if time.monotonic() - stable_at >= .1:
                    break
            else:
                stable_at = None
            previous = signature
            time.sleep(.05)
        else:
            raise TimeoutError("transport did not drain after quiescence")
        assert_healthy(snapshots)
        generated = sum(s["load"]["inserted"] for s in snapshots.values())
        result["drain_complete"] = all(s["executed_count"] == generated and s["load"]["pending"] == 0 for s in snapshots.values())
        if any(s["executed_count"] > generated for s in snapshots.values()):
            raise AssertionError("replica executed more transactions than were generated")
        minimum_output = min(s["executed_count"] for s in snapshots.values())
        result["agreement"] = assert_common_prefix(controller.many(list(range(4)), "prefix", count=minimum_output), minimum_output)
        result["agreement"]["executed_counts"] = {i:s["executed_count"] for i,s in snapshots.items()}
        result["agreement"]["unique_generated_transactions"] = generated
        if result["drain_complete"]:
            result["agreement"].update(assert_agreement(snapshots))
        result["global_pending_by_replica"] = {i:generated-s["executed_count"] for i,s in snapshots.items()}
        final_traffic = [tcp_counters(s) for s in snapshots.values()]
        if sum(t["written_bytes"] for t in final_traffic) != sum(t["read_bytes"] for t in final_traffic):
            raise AssertionError("drained TCP reads and writes differ")
        result["final_tcp"] = final_traffic
        result["final_backlog"] = [s["load"]["pending"] for s in snapshots.values()]
        controller.many(list(range(4)), "stop")
        for child in children:
            child.process.wait(timeout=5)
        result["generation_target_met"] = result["comparison"]["generation_target_met"]
        result["completion_target_met"] = result["comparison"]["completion_target_met"]
        result["comparison"]["drain_complete"] = result["drain_complete"]
        result["status"] = "passed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors = []
        if controller:
            try:
                controller.save()
            except Exception as error:
                cleanup_errors.append(f"controller save: {type(error).__name__}: {error}")
        for child in children:
            try:
                result["children"].append(child.finish())
            except Exception as error:
                cleanup_errors.append(f"child cleanup: {type(error).__name__}: {error}")
        if shaping is not None:
            try:
                result["network_shaping_cleanup"] = clear_from_environment()
            except Exception as error:
                result["network_shaping_cleanup_error"] = f"{type(error).__name__}: {error}"
                cleanup_errors.append(f"network shaping cleanup: {type(error).__name__}: {error}")
        if cleanup_errors:
            result["status"] = "failed"
            result["cleanup_errors"] = cleanup_errors
            result["error"] = "; ".join(filter(None, [result.get("error"), *cleanup_errors]))
        if result["status"] == "passed" and any(c["exit_code"] != 0 or c["telemetry_errors"] for c in result["children"]):
            result["status"], result["error"] = "failed", "replica exit or telemetry failure"
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def build_inputs(compiler):
    sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"] + sorted((ROOT / "src").rglob("*.rs"))
    return {"compiler": compiler, "sources": {str(p.relative_to(ROOT)): sha(p.read_bytes()) for p in sources}}


def verify_build_stamp(binary, compiler):
    stamp_path = Path(str(binary) + ".build.json")
    stamp = json.loads(stamp_path.read_text())
    if stamp.get("inputs") != build_inputs(compiler) or stamp.get("binary_sha256") != sha(binary.read_bytes()):
        raise RuntimeError("release build stamp does not match current source, compiler and binary; rebuild without --skip-build")
    return stamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--transaction-size", type=int, default=512)
    parser.add_argument("--warmup", type=float, default=10)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--batch-ms", "--ingress-batch-ms", dest="batch_ms", type=int, default=10)
    parser.add_argument("--bound-ms", type=int, default=250)
    add_ordering_arguments(parser)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/delugi-replica")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--build-only", action="store_true", help="compile, stamp and archive without launching a trial")
    args = parser.parse_args()
    output = (args.output or ROOT / "results/local" / ("sustained-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema": 1, "status": "incomplete", "protocol": "delugi", "replicas": 4,
                "started_utc": datetime.now(timezone.utc).isoformat(), "machine": machine_metadata(),
                "method": {"workload": "independent native generators, disjoint deterministic IDs, fixed canonical transaction bytes including 32-byte ID and 8-byte Bincode length; 8-byte vector length per batch is additional protocol traffic",
                           "load": "per-producer monotonic 10 ms pacing by default; never drops an inserted transaction; catches up bounded batches; actual generation and completion target flags expose under-delivery and overload",
                           "completion": "unique origin-local materialization in measurement window, excludes duplicate execution at other replicas; local insertion clock also measures latency",
                           "windows": "replicas capture their own counter boundaries on the protocol thread around a shared future start; actual interval and inter-replica skew retained",
                           "latency_quantiles": "one-millisecond upper-bound histogram; mean is exact microsecond accumulation",
                           "traffic": "successful authenticated replica TCP stream writes including data framing, signatures and ACKs; separate reads; excludes client/control traffic, TCP/IP headers and kernel retransmissions",
                           "storage": "independent in-memory custody/order/output; all protocol signatures and validation enabled; no durability",
                           "trace": "sparse process telemetry; compact counter snapshots retain no serialized full transaction log; consensus state itself remains retained",
                           "shutdown": "stop generation automatically after window, allow bounded30s application drain, quiesce, verify identical hashes at the common executed prefix (full agreement when completely drained), drain transport and stop; a valid overloaded window is retained even if application backlog remains"},
                "source_files": []}
    try:
        sources = [ROOT / p for p in ("Cargo.toml", "Cargo.lock", "scripts/run_sustained.py", "scripts/run_network.py", "scripts/network_delay.py", "tests/sustained_runner_test.py", "provenance/spec-2026-10-13.json")]
        sources += sorted((ROOT / "src").rglob("*.rs"))
        for source in sources:
            relative, data = source.relative_to(ROOT), source.read_bytes()
            destination = output / "snapshot" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            manifest["source_files"].append({"path": str(relative), "sha256": sha(data)})
        for command, label in ((["rustc", "--version", "--verbose"], "rustc"),
                               (["git", "rev-parse", "HEAD"], "git_head"),
                               (["git", "status", "--porcelain"], "git_status")):
            process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
            manifest[label] = process.stdout.strip()
        if not args.skip_build:
            if args.binary.resolve() != (ROOT / "target/release/delugi-replica").resolve():
                raise ValueError("custom --binary requires --skip-build and a matching build stamp")
            inputs = build_inputs(manifest["rustc"])
            build = subprocess.run(["cargo", "build", "--release", "--offline", "--locked", "--bin", "delugi-replica"], cwd=ROOT, capture_output=True, text=True)
            (output / "build.stdout").write_text(build.stdout)
            (output / "build.stderr").write_text(build.stderr)
            if build.returncode:
                raise RuntimeError("release build failed")
            if inputs != build_inputs(manifest["rustc"]):
                raise RuntimeError("protocol source changed during release build")
            stamp = {"inputs": inputs, "binary_sha256": sha(args.binary.read_bytes()),
                     "built_utc": datetime.now(timezone.utc).isoformat()}
            Path(str(args.binary) + ".build.json").write_text(json.dumps(stamp, indent=2) + "\n")
        manifest["build_stamp"] = verify_build_stamp(args.binary, manifest["rustc"])
        manifest["binary_sha256"] = sha(args.binary.read_bytes())
        if args.build_only:
            manifest["status"] = "built"
        else:
            result = run_trial(args.binary.resolve(), output / "trial", args.rate, args.warmup,
                               args.duration, args.transaction_size, args.batch_ms, args.bound_ms,
                               ordering_batch=args.ordering_batch, round_barrier_ms=args.round_barrier_ms,
                               progress_pacing_ms=args.progress_pacing_ms, ordering_mode=args.ordering_mode)
            manifest["trial"] = result
            manifest["status"] = result["status"]
            for key in ("network_shaping", "network_shaping_cleanup", "network_shaping_cleanup_error",
                        "network_shaping_helper_sha256", "replica_network_ports", "protocol_bound_ms"):
                if key in result:
                    manifest[key] = result[key]
            if "comparison" in result:
                manifest["comparison"] = result["comparison"]
            if "error" in result:
                manifest["error"] = result["error"]
        for source in manifest["source_files"]:
            if sha((ROOT / source["path"]).read_bytes()) != source["sha256"]:
                raise RuntimeError(f"benchmark source changed during run: {source['path']}")
    except Exception as error:
        manifest["status"], manifest["error"] = "failed", f"{type(error).__name__}: {error}"
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(output / "manifest.json"), "status": manifest["status"], "comparison": manifest.get("comparison"), "error": manifest.get("error")}), flush=True)
    return 0 if manifest["status"] in ("passed", "built") else 1


if __name__ == "__main__":
    sys.exit(main())
