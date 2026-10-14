#!/usr/bin/env python3
"""Build/test pinned Vantage upstream and smoke its five native CLI protocols.

Upstream local-benchmark runs four authorities and their workers as Tokio tasks
in one OS process with separate stores and loopback networking. These are native
functional smokes, not independent-process comparisons or maximum-throughput tests.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import signal
import socket
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "benchmarks/baselines/vantage"
COMMIT = "199098c4978e4a97a7d3707ec9aac6de086969db"
REMOTE = "https://github.com/polinikita/vantage-bft.git"
TOOLCHAIN = "1.95.0"
RUSTUP_HOME = ROOT / "benchmarks/toolchains/vantage"
CARGO_HOME = ROOT / "benchmarks/.cache/vantage-cargo"
TARGET = ROOT / "benchmarks/.cache/vantage-target"
BINARY = TARGET / "release/node"
WORKSPACE_CRATES = ("primary", "node", "store", "crypto", "worker", "network", "config", "metrics")
PROTOCOLS = ("vantage", "autobahn-optimistic", "autobahn-seamless", "simple-it", "simple-it-bracha")


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(*arguments):
    return subprocess.check_output(["git", "-C", str(SOURCE), *arguments], text=True).strip()


def pinned_source():
    actual = git("rev-parse", "HEAD")
    if actual != COMMIT:
        raise RuntimeError(f"Vantage HEAD {actual} differs from pinned {COMMIT}")
    if git("status", "--porcelain"):
        raise RuntimeError("Vantage checkout is dirty; this native runner requires exact upstream source and lock")
    return {"commit": actual, "remote": git("remote", "get-url", "origin"),
            "cargo_lock_sha256": sha256(SOURCE / "Cargo.lock"), "source_patch": None,
            "tree": git("rev-parse", "HEAD^{tree}")}


def run_logged(command, output, manifest, *, env, timeout=None):
    record = {"argv": list(map(str, command)), "cwd": str(SOURCE), "log": str(output),
              "started_utc": datetime.now(timezone.utc).isoformat()}
    manifest["commands"].append(record)
    started = time.monotonic()
    with Path(output).open("wb") as stream:
        result = subprocess.run(command, cwd=SOURCE, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout)
    record.update(exit_code=result.returncode, elapsed_seconds=time.monotonic() - started)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {output}")


def environment(output, manifest):
    env = os.environ.copy()
    env.update(RUSTUP_HOME=str(RUSTUP_HOME), CARGO_HOME=str(CARGO_HOME), CARGO_TARGET_DIR=str(TARGET),
               CARGO_BUILD_JOBS="4", CMAKE_BUILD_PARALLEL_LEVEL="4")
    host = "aarch64-apple-darwin" if platform.system() == "Darwin" and platform.machine() == "arm64" else None
    if host is None:
        raise RuntimeError("This reproducibility profile currently targets the local Apple Silicon host")
    toolchain_bin = RUSTUP_HOME / "toolchains" / f"{TOOLCHAIN}-{host}" / "bin"
    if not (toolchain_bin / "cargo").exists():
        rustup = shutil.which("rustup")
        if not rustup:
            raise RuntimeError("rustup is required to provision the isolated local toolchain")
        run_logged([rustup, "toolchain", "install", TOOLCHAIN, "--profile", "minimal", "--no-self-update"],
                   output / "toolchain-install.log", manifest, env=env)
    env["PATH"] = str(toolchain_bin) + os.pathsep + env.get("PATH", "")
    # Use installed Apple developer tools and Homebrew OpenSSL, without installing
    # or modifying system dependencies or the global Rust toolchain.
    libclang = Path("/Library/Developer/CommandLineTools/usr/lib")
    if (libclang / "libclang.dylib").exists():
        env["LIBCLANG_PATH"] = str(libclang)
    openssl = Path("/opt/homebrew/opt/openssl@3")
    if openssl.exists():
        env["OPENSSL_DIR"] = str(openssl)
    env["SDKROOT"] = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
    manifest["toolchain"] = subprocess.check_output([str(toolchain_bin / "rustc"), "--version", "--verbose"], env=env, text=True).strip()
    manifest["build_environment"] = {key: env[key] for key in
                                    ("RUSTUP_HOME", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
                                     "CMAKE_BUILD_PARALLEL_LEVEL", "LIBCLANG_PATH", "OPENSSL_DIR", "SDKROOT") if key in env}
    return env, toolchain_bin / "cargo"


def build_and_test(output, manifest, env, cargo, skip_build, skip_tests, test_filters):
    stamp_path = TARGET / "build-provenance.json"
    if not skip_build:
        run_logged([str(cargo), "build", "--release", "--workspace", "--features", "benchmark", "--locked", "--jobs", "4"],
                   output / "build.log", manifest, env=env)
        stamp = {"source": pinned_source(), "binary_sha256": sha256(BINARY),
                 "toolchain": manifest["toolchain"], "build_environment": manifest["build_environment"],
                 "build_command": manifest["commands"][-1], "created_utc": datetime.now(timezone.utc).isoformat()}
        write_json(stamp_path, stamp)
    stamp = json.loads(stamp_path.read_text())
    if stamp["source"] != pinned_source() or stamp["binary_sha256"] != sha256(BINARY) or stamp["toolchain"] != manifest["toolchain"]:
        raise RuntimeError("Vantage binary/source/compiler differ from the native build stamp")
    manifest["build_provenance"] = stamp
    if not skip_tests:
        # Follow upstream's workspace test configuration, reusing release native
        # dependencies. A single test thread avoids fixture-port conflicts.
        command = [str(cargo), "test", "--release", "--workspace", "--locked", "--jobs", "4"]
        # Upstream has an expected-panic test for a debug_assert. Preserve those
        # test semantics while reusing expensive release RocksDB dependencies.
        for crate in WORKSPACE_CRATES:
            command.extend(["--config", f"profile.release.package.{crate}.debug-assertions=true"])
        command.extend(["--", "--test-threads=1"])
        for name in test_filters:
            command.extend(["--skip", name])
        run_logged(command, output / "tests.log", manifest, env=env)
        manifest["tests"] = parse_test_results((output / "tests.log").read_text())
        manifest["tests"]["explicit_test_filters"] = test_filters
        manifest["tests"]["workspace_debug_assertions"] = True
    else:
        manifest["tests"] = {"status": "not_run"}
    manifest["binary_sha256"] = sha256(BINARY)
    # A feature-disabled node test target must not replace the benchmark binary.
    if manifest["binary_sha256"] != stamp["binary_sha256"]:
        raise RuntimeError("workspace tests replaced the benchmark executable")


def parse_test_results(raw):
    rows = [dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), map(int, match)))
            for match in re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", raw)]
    if not rows:
        raise RuntimeError("workspace test log lacks successful test summaries")
    return {"status": "passed", "test_suites": len(rows),
            **{name: sum(row[name] for row in rows) for name in rows[0]}}


def allocate_base_port(nodes=4, workers=1):
    count = nodes * (4 + 4 * workers)
    candidates = list(range(20_000, 55_000 - count))
    random.SystemRandom().shuffle(candidates)
    for base in candidates[:200]:
        sockets = []
        try:
            for port in range(base, base + count):
                listener = socket.socket()
                sockets.append(listener)
                listener.bind(("127.0.0.1", port))
            return base
        except OSError:
            pass
        finally:
            for listener in sockets:
                listener.close()
    raise RuntimeError("cannot reserve a complete consecutive native port range")


def parse_result(raw, protocol, rate):
    lines = [line for line in raw.splitlines() if line.startswith("BENCHMARK_RESULT ")]
    if len(lines) != 1:
        raise RuntimeError(f"expected one native measurement result, found {len(lines)}")
    fields = dict(token.split("=", 1) for token in lines[0].split()[1:])
    if fields.get("protocol") != protocol or int(fields["offered_tps"]) != rate:
        raise RuntimeError("native result protocol or offered rate differs from request")
    result = {}
    for key, value in fields.items():
        if key == "protocol":
            result[key] = value
        else:
            result[key] = float(value) if "." in value else int(value)
    if result["panics"] or result["committed"] <= 0 or result["submitted"] <= 0 or result["network_bytes"] <= 0:
        raise RuntimeError("native run reports a panic or no useful workload/network progress")
    first_summary = raw.split(" -- STEADY-STATE", 1)[0]
    match = re.search(r"Materialised transaction latency: avg ([\d.]+) ms .*?p50/p90/p99 ([\d.]+)/([\d.]+)/([\d.]+) ms \((\d+) txs\)", first_summary)
    if match:
        result["materialized_mean_ms"] = float(match[1])
        result["materialized_observations"] = int(match[5])
    return result


def smoke(protocol, directory, manifest, env, args):
    directory.mkdir()
    base_port = allocate_base_port()
    data_dir = directory / "native-data"
    # Upstream clears data-dir on startup; this path is new and run-owned.
    if data_dir.exists():
        raise RuntimeError("refusing to pass an existing data directory to the native launcher")
    command = [str(BINARY), "local-benchmark", "--nodes", "4", "--workers", "1", "--rate", str(args.rate),
               "--tx-size", str(args.transaction_size), "--protocol", protocol, "--mode", "random",
               "--warmup", str(args.warmup), "--duration", str(args.duration), "--mimic-latency-ms", "0",
               "--delta-ms", str(args.delta_ms), "--fast-path-timeout-ms", "500",
               "--max-batch-delay-ms", "20", "--max-header-delay-ms", "100",
               "--consensus-signature-scheme", "ed25519", "--base-port", str(base_port), "--data-dir", str(data_dir)]
    result = {"protocol": protocol, "status": "failed", "command": command,
              "execution_model": "four authorities and four workers in one native process; separate stores and loopback TCP",
              "started_utc": datetime.now(timezone.utc).isoformat()}
    process = None
    started = time.monotonic()
    try:
        with (directory / "native.log").open("wb") as log:
            process = subprocess.Popen(command, cwd=SOURCE, env=env, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            result["pid"] = process.pid
            process.wait(timeout=args.warmup + args.duration + 60)
        result["exit_code"] = process.returncode
        if process.returncode:
            raise RuntimeError(f"native process exited {process.returncode}")
        result["native_metrics"] = parse_result((directory / "native.log").read_text(), protocol, args.rate)
        result["parameters"] = json.loads((data_dir / "parameters.json").read_text())
        result["status"] = "passed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        if process and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        result["exit_code"] = process.returncode if process else None
        result["elapsed_seconds"] = time.monotonic() - started
        result["log_sha256"] = sha256(directory / "native.log") if (directory / "native.log").exists() else None
        write_json(directory / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-test", action="append", default=[], help="explicit native test filter, retained in provenance")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--protocol", choices=("all", *PROTOCOLS), default="all")
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--transaction-size", type=int, default=512)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--delta-ms", type=int, default=200)
    args = parser.parse_args()
    if min(args.rate, args.transaction_size, args.duration, args.delta_ms) <= 0 or args.warmup < 0:
        parser.error("rate, size, duration and delta must be positive; warmup nonnegative")
    output = (args.output or ROOT / "results/local" / ("vantage-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 1, "status": "incomplete", "classification": "pinned_upstream_build_test_and_single_process_native_functional_smokes",
                "started_utc": datetime.now(timezone.utc).isoformat(), "machine": {"system":platform.system(),"architecture":platform.machine(),"logical_cpus":os.cpu_count()},
                "method": {"replicas":4,"workers_per_replica":1,"independent_replica_processes":False,
                           "storage":"upstream per-authority primary/worker RocksDB stores",
                           "latency":"upstream native real/materialized transaction metrics; raw summary retained",
                           "traffic":"upstream native network counters, not claimed to equal successful replica TCP stream writes",
                           "duration":"separate requested warmup and measurement, followed by native diagnostic drain",
                           "scope":"fault-free functional smoke of each CLI variant, no cloud deployment or throughput superiority claim"},
                "commands":[],"smokes":[]}
    try:
        manifest["source"] = pinned_source()
        snapshot = output / "source"
        snapshot.mkdir()
        for item in ("README.md","Cargo.toml","Cargo.lock","rust-toolchain.toml"):
            shutil.copy2(SOURCE / item, snapshot / item)
        shutil.copy2(__file__, output / "runner.py")
        env, cargo = environment(output, manifest)
        build_and_test(output, manifest, env, cargo, args.skip_build, args.skip_tests, args.skip_test)
        help_result = subprocess.run([str(BINARY),"local-benchmark","--help"],env=env,text=True,capture_output=True,check=True)
        (output / "local-benchmark-help.txt").write_text(help_result.stdout)
        if not args.build_only:
            for protocol in PROTOCOLS if args.protocol == "all" else (args.protocol,):
                row = smoke(protocol, output / protocol, manifest, env, args)
                manifest["smokes"].append(row)
                write_json(output / "manifest.json",manifest)
                print(json.dumps({"protocol":protocol,"status":row["status"],"error":row.get("error")}),flush=True)
            if any(row["status"] != "passed" for row in manifest["smokes"]):
                raise RuntimeError("one or more native functional smokes failed; see retained logs")
        if pinned_source() != manifest["source"] or sha256(BINARY) != manifest["binary_sha256"]:
            raise RuntimeError("upstream source or measured binary changed during the run")
        manifest["status"] = "passed"
    except Exception as error:
        manifest["status"], manifest["error"] = "failed", f"{type(error).__name__}: {error}"
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "manifest.json",manifest)
    print(json.dumps({"manifest":str(output / "manifest.json"),"status":manifest["status"],"error":manifest.get("error")}),flush=True)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
