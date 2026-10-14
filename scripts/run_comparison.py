#!/usr/bin/env python3
"""Run sequential, matched four-replica sustained workloads and retain every trial.

Build each implementation first. This driver never compiles during a timed trial.
Individual adapters own readiness, warmup, measurement, and process cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUNNERS = {
    "delugi": ROOT / "scripts/run_sustained.py",
    "raptr": ROOT / "scripts/baselines/raptr.py",
    "mysticeti": ROOT / "scripts/baselines/mysticeti.py",
}
TRAFFIC_BOUNDARY = "successful_replica_tcp_stream_writes"
PINS = {
    "raptr": "a4c98047cf8aeae3571168d02fb7e343140d2948",
    "mysticeti": "96fd83154bb5e168def9a81ee8f3e90e94e46a2e",
}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def write_json(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def finite(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError(f"{name} must be finite and {'positive' if positive else 'nonnegative'}")
    return value


def artifact_identity(manifest, protocol):
    """Require pinned sources and unchanged measured artifacts across repetitions."""
    if protocol == "delugi":
        return {"binary": manifest["binary_sha256"],
                "sources": {entry["path"]: entry["sha256"] for entry in manifest["source_files"]}}
    if manifest["source_commit"] != PINS[protocol]:
        raise ValueError(f"{protocol} source is not the pinned paper implementation")
    if protocol == "mysticeti":
        return {"source_commit": manifest["source_commit"], "source_diff": manifest["source_diff_sha256"],
                "binary": manifest["binary"]["sha256"], "runner": manifest["runner_sha256"]}
    return {"source_commit": manifest["source_commit"], "build_stamp": manifest["build_stamp"],
            "binaries": {name: entry["sha256"] for name, entry in manifest["binaries"].items()},
            "runner": manifest["runner_sha256"]}


def validate_comparison(manifest, protocol, rate, transaction_size, warmup, duration, ingress_batch_ms=100):
    if manifest.get("status") not in ("passed", "completed"):
        raise ValueError(f"{protocol} trial failed: {manifest.get('error', manifest.get('status'))}")
    result = dict(manifest["comparison"])
    for field, expected in {
        "protocol": protocol, "replicas": 4, "offered_tx_s": rate,
        "transaction_bytes": transaction_size, "warmup_seconds": warmup,
        "ingress_batch_ms": ingress_batch_ms,
        "traffic_boundary": TRAFFIC_BOUNDARY,
    }.items():
        if result.get(field) != expected:
            raise ValueError(f"Mismatched {field}: {result.get(field)!r}, expected {expected!r}")
    seconds = finite(result["measurement_seconds"], "measurement_seconds", positive=True)
    # Scraping consumes time; reject a short window or an unrelated long interval.
    if not duration * 0.98 <= seconds <= duration + max(5, duration * 0.1):
        raise ValueError(f"Measurement window {seconds:g}s differs from requested {duration:g}s")
    tps = finite(result["unique_completion_tps"], "unique_completion_tps", positive=True)
    completed = finite(result["completion_count"], "completion_count", positive=True)
    finite(result["mean_latency_ms"], "mean_latency_ms")
    written = finite(result["replica_tcp_written_bytes"], "replica_tcp_written_bytes", positive=True)
    finite(result["replica_tcp_read_bytes"], "replica_tcp_read_bytes", positive=True)
    byte_rate = finite(result["replica_tcp_written_bytes_per_second"], "replica_tcp_written_bytes_per_second", positive=True)
    if not math.isclose(byte_rate, written / seconds, rel_tol=0.02):
        raise ValueError("Traffic rate and byte/window counters disagree")
    if not math.isclose(tps, completed / seconds, rel_tol=0.02):
        raise ValueError("Completion rate and count/window counters disagree")
    if not isinstance(result.get("latency_endpoint"), str) or not result["latency_endpoint"].strip():
        raise ValueError("A precise latency endpoint is required")
    for name in ("generated_count", "generation_tps"):
        if result.get(name) is not None:
            finite(result[name], name)
    result["tcp_written_bytes_per_completion"] = byte_rate / tps
    result["offered_load_completion_fraction"] = tps / rate
    result["achieved_generation_fraction"] = (
        result["generation_tps"] / rate if result.get("generation_tps") is not None else None
    )
    # This describes observed output, not a maximum-capacity or stability claim.
    result["completion_rate_at_least_95_percent_of_target"] = tps >= rate * 0.95
    return result


def validate_timing(manifest, protocol, delay_ms, bound_ms, helper_sha256):
    shaping = manifest.get("network_shaping", {})
    if (shaping.get("one_way_delay_ms") != delay_ms
            or shaping.get("protocol") != protocol
            or shaping.get("helper_sha256") != helper_sha256
            or shaping.get("backend") != "macOS_dummynet"):
        raise ValueError("Trial kernel delay does not match the calibrated shaper")
    if "network_shaping_cleanup" not in manifest or manifest.get("network_shaping_cleanup_error"):
        raise ValueError("Kernel shaping cleanup was not confirmed")
    if protocol == "raptr":
        actual = manifest["workload"]["native_delta_ms"]
        observations = manifest.get("native_timing_observations", [])
        if len(observations) != 4 or any(not row["delta_ms"] or any(v != bound_ms for v in row["delta_ms"]) for row in observations):
            raise ValueError("Missing native Raptr bound evidence from all four replicas")
    elif protocol == "mysticeti":
        actual = manifest["settings"]["bound_ms"]
    else:
        actual = manifest["protocol_bound_ms"]
    if actual != bound_ms:
        raise ValueError(f"{protocol} bound {actual} differs from requested {bound_ms}")
    return {"one_way_network_delay_ms": delay_ms, "bound_ms": bound_ms,
            "shaping": shaping, "cleanup": manifest["network_shaping_cleanup"]}


def aggregate(trials):
    groups = {}
    for trial in trials:
        if trial.get("status") == "passed":
            groups.setdefault((trial["protocol"], trial["rate"]), []).append(trial["comparison"])
    output = []
    for (protocol, rate), rows in sorted(groups.items(), key=lambda pair: (pair[0][1], pair[0][0])):
        record = {"protocol": protocol, "offered_tx_s": rate, "successful_trials": len(rows)}
        for field in (
            "unique_completion_tps", "mean_latency_ms", "replica_tcp_written_bytes_per_second",
            "tcp_written_bytes_per_completion", "offered_load_completion_fraction", "generation_tps",
        ):
            values = [row[field] for row in rows if row.get(field) is not None]
            record[field] = ({"median": statistics.median(values), "min": min(values), "max": max(values)}
                             if values else None)
        record["latency_endpoints"] = sorted({row["latency_endpoint"] for row in rows})
        record["all_trials_reached_95_percent_of_offered_rate"] = all(
            row["completion_rate_at_least_95_percent_of_target"] for row in rows
        )
        output.append(record)
    return output


def trial_plan(protocols, rates, repeats):
    for rate in rates:
        for repeat in range(repeats):
            offset = repeat % len(protocols)
            for protocol in protocols[offset:] + protocols[:offset]:
                yield protocol, rate, repeat


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rates", type=int, nargs="+", default=[1000, 4000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--transaction-size", type=int, default=512)
    parser.add_argument("--ingress-batch-ms", type=int, default=100)
    parser.add_argument("--protocols", choices=list(RUNNERS), nargs="+", default=list(RUNNERS))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--network-delay-ms", type=int, help="Calibrate and require the scoped kernel shaper")
    parser.add_argument("--bound-ms", type=int, help="Shared protocol-bound preset; native timer multipliers are preserved")
    args = parser.parse_args()
    if (args.network_delay_ms is None) != (args.bound_ms is None):
        parser.error("Provide both --network-delay-ms and --bound-ms for a timing-controlled matrix")
    if args.network_delay_ms is not None and (not 1 <= args.network_delay_ms <= 100 or not 1 <= args.bound_ms <= 60000):
        parser.error("Network delay must be1..100ms and protocol bound1..60000ms")
    if args.network_delay_ms is None and (os.environ.get("DELUGI_SHAPER_CONTROL") or os.environ.get("DELUGI_NETWORK_DELAY_MS")):
        parser.error("Shaper environment requires explicit timing-controlled matrix flags")
    if (any(rate <= 0 or rate % 40 for rate in args.rates) or args.repeats <= 0
            or args.warmup < 0 or args.duration <= 0 or args.transaction_size != 512 or args.ingress_batch_ms != 100
            or len(args.protocols) != len(set(args.protocols)) or len(args.rates) != len(set(args.rates))):
        parser.error("Use distinct positive rates divisible by 40, distinct protocols, positive repeats/duration, warmup >= 0, 512-byte transactions and 100ms ingress cadence")
    output = (args.output or ROOT / "results/local" / ("comparison-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(__file__, output / "runner.py")
    manifest_path = output / "manifest.json"
    manifest = {
        "schema": 1, "classification": "matched_four_replica_sustained_localhost_comparison",
        "status": "running", "started_unix_ns": time.time_ns(), "trials": [], "artifact_identities": {},
        "settings": {"rates": args.rates, "repeats": args.repeats, "warmup_seconds": args.warmup,
                     "measurement_seconds": args.duration, "serialized_transaction_bytes": args.transaction_size,
                     "ingress_batch_ms": args.ingress_batch_ms,
                     "replicas": 4, "faults": 0, "network": "localhost TCP", "execution": "sequential; no overlapping protocol trials",
                     "order": "rate, repeat, protocol; protocol order rotates by repeat"},
        "machine": {"platform": platform.platform(), "cpu_count": os.cpu_count(), "python": sys.version},
        "runner_sha256": sha256(__file__), "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "measurement_boundaries": {
            "throughput": "Unique origin-node completions per second, using disjoint origin observations; replicas are not summed as replicated system output.",
            "latency": "Transaction-weighted mean origin-node payload-ready consensus completion latency in a steady-state completion window. Each adapter records its precise start point; client ingress differs.",
            "traffic": "Sum of successful replica TCP stream writes, including protocol data, authentication, framing and application ACKs. Excludes metrics/client control, TCP/IP headers and kernel retransmissions. Reads recorded separately, never added to writes.",
            "conditions": "Matched node count, hardware, offered rate, serialized transaction size,100ms origin ingress cadence, warmup and measurement duration. Native internal consensus batching, worker counts, timeouts, cryptography and storage are retained and recorded per implementation.",
            "capacity": "Two offered-load points measure sustained delivery under these conditions; no maximum capacity is inferred.",
        },
    }
    write_json(manifest_path, manifest)
    try:
        if args.network_delay_ms is not None:
            from network_delay import calibration
            os.environ["DELUGI_NETWORK_DELAY_MS"] = str(args.network_delay_ms)
            calibration_result = calibration(output / "calibration-before", args.network_delay_ms)
            manifest["calibration_before"] = calibration_result
            manifest["settings"].update(one_way_network_delay_ms=args.network_delay_ms, bound_ms=args.bound_ms)
            manifest["classification"] = "timing_controlled_four_replica_sustained_localhost_comparison"
            manifest["measurement_boundaries"]["conditions"] += " Configured one-way kernel delay and protocol bound are matched; native timer multipliers and independent batching remain implementation-specific. Mysticeti maps its leader-readiness timeout to the requested bound."
            write_json(manifest_path, manifest)
            if calibration_result["status"] != "passed":
                raise ValueError("Kernel delay calibration failed; no protocol trials started")
        for protocol, rate, repeat in trial_plan(args.protocols, args.rates, args.repeats):
            label = f"{protocol}-{rate}-repeat-{repeat}"
            directory = output / label
            command = [sys.executable, str(RUNNERS[protocol]), "--rate", str(rate),
                       "--transaction-size", str(args.transaction_size), "--warmup", str(args.warmup),
                       "--duration", str(args.duration), "--ingress-batch-ms", str(args.ingress_batch_ms),
                       "--output", str(directory)]
            if protocol == "delugi":
                command.append("--skip-build")
            if args.bound_ms is not None:
                command.extend(["--bound-ms", str(args.bound_ms)])
            trial = {"protocol": protocol, "rate": rate, "repeat": repeat, "label": label,
                     "command": command, "status": "running", "started_unix_ns": time.time_ns()}
            manifest["trials"].append(trial)
            write_json(manifest_path, manifest)
            print(f"Starting {label}", flush=True)
            with (output / (label + ".log")).open("w") as log:
                process = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            trial.update(returncode=process.returncode, finished_unix_ns=time.time_ns())
            child_manifest = directory / "manifest.json"
            try:
                trial["manifest"] = {"path": str(child_manifest.relative_to(ROOT)), "sha256": sha256(child_manifest)}
                data = json.loads(child_manifest.read_text())
                if process.returncode:
                    raise ValueError(f"Adapter exited {process.returncode}: {data.get('error', 'see raw log')}")
                trial["comparison"] = validate_comparison(data, protocol, rate, args.transaction_size, args.warmup, args.duration, args.ingress_batch_ms)
                if args.network_delay_ms is not None:
                    trial["timing"] = validate_timing(data, protocol, args.network_delay_ms, args.bound_ms,
                                                      calibration_result["shaping"]["helper_sha256"])
                identity = artifact_identity(data, protocol)
                if protocol in manifest["artifact_identities"] and identity != manifest["artifact_identities"][protocol]:
                    raise ValueError(f"{protocol} source or binary changed between matrix trials")
                manifest["artifact_identities"][protocol] = identity
                trial["status"] = "passed"
                result = trial["comparison"]
                print(f"Completed {label}: {result['unique_completion_tps']:.1f}tx/s, "
                      f"{result['mean_latency_ms']:.3f}ms, {result['replica_tcp_written_bytes_per_second'] / 1e6:.3f}MB/s", flush=True)
            except (ValueError, KeyError, OSError) as error:
                trial.update(status="failed", error=str(error))
                print(f"Failed {label}: {error}", flush=True)
            manifest["aggregate"] = aggregate(manifest["trials"])
            write_json(manifest_path, manifest)
        manifest["status"] = "passed" if all(trial["status"] == "passed" for trial in manifest["trials"]) else "failed"
        if args.network_delay_ms is not None:
            manifest["calibration_after"] = calibration(output / "calibration-after", args.network_delay_ms)
            if manifest["calibration_after"]["status"] != "passed":
                manifest["status"] = "failed"
    except BaseException as error:
        manifest.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        manifest["finished_unix_ns"] = time.time_ns()
        write_json(manifest_path, manifest)
        print(manifest_path, flush=True)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
