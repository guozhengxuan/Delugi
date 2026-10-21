#!/usr/bin/env python3
"""Bounded local native-core check. No validator/benchmark process is launched."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
GIB = 1024 ** 3


def hash_tree(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and "target" not in path.relative_to(root).parts:
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def allocated(root):
    return sum(p.stat().st_blocks * 512 for p in root.rglob("*") if p.is_file()) if root.exists() else 0


def source_snapshot(source, dependency):
    return {"native": hash_tree(source), "dependency": hash_tree(dependency),
            "shared_crypto_aptos": hash_tree(REPOSITORY / "shared/crypto-aptos"),
            "shared_metrics": hash_tree(REPOSITORY / "shared/metrics"),
            "shared_output": hash_tree(REPOSITORY / "shared/output"),
            "output_policy": hash_tree(ROOT / "src"),
            "output_manifest": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ("Cargo.toml", "Cargo.lock")}}


def run(output, target, command):
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "native"
    dependency = ROOT / ".native-deps/a4c98047cf8aeae3571168d02fb7e343140d2948"
    before = source_snapshot(source, dependency)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    env = os.environ.copy()
    for key in list(env):
        if key.startswith(("CARGO_PROFILE_", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")):
            env.pop(key)
    env.update(CARGO_HOME=str(REPOSITORY / "benchmarks/.cache/raptr-cargo"),
               CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_INCREMENTAL="0",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_TEST_DEBUG="0",
               CFLAGS="-Dfdopen=fdopen")
    argv = ["cargo", "+1.78.0", "--config", str(source / ".cargo/config.toml"), command,
            "--lib", "--locked", "--offline", "--manifest-path", str(source / "Cargo.toml")]
    record = {"schema": 1, "status": "starting", "argv": argv, "target": str(target),
              "limits": {"target_bytes": 20 * GIB, "minimum_free_bytes": 30 * GIB, "jobs": 2,
                         "sample_seconds": 15, "incremental": False, "debug_info": False},
              "samples": [], "scope": "native types/core conformance; no live protocol or shared-service claim",
              "toolchain": subprocess.check_output(["rustc", "+1.78.0", "--version", "--verbose"], text=True),
              "environment": {key: env[key] for key in ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CFLAGS")}}
    def save():
        temporary = output / "guard.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n")
        temporary.replace(output / "guard.json")
    if shutil.disk_usage(target.parent).free < 30 * GIB or allocated(target) > 20 * GIB:
        record["status"] = "preflight_resource_rejected"; save(); return 2
    start = time.monotonic()
    process = None
    failure = None
    try:
        with (output / "cargo.log").open("xb") as log:
            process = subprocess.Popen(argv, cwd=REPOSITORY, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            record.update(status="running", pid=process.pid, pgid=process.pid)
            save()
            while process.poll() is None:
                sample = {"elapsed_seconds": time.monotonic() - start, "target_bytes": allocated(target),
                          "free_bytes": shutil.disk_usage(target.parent).free}
                record["samples"].append(sample); save()
                if sample["target_bytes"] > 20 * GIB or sample["free_bytes"] < 30 * GIB:
                    failure = "resource_guard"; break
                time.sleep(15)
    except BaseException as error:
        failure = repr(error)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
        after = source_snapshot(source, dependency)
        (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
        record.update(exit_code=process.returncode if process else None, failure=failure,
                      elapsed_seconds=time.monotonic()-start, source_unchanged=before == after,
                      final_target_bytes=allocated(target), final_free_bytes=shutil.disk_usage(target.parent).free)
        record["status"] = "passed" if process and process.returncode == 0 and not failure and before == after else "failed"
        save()
    print(json.dumps({key: value for key, value in record.items() if key not in ("samples", "toolchain", "environment")}))
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, default=ROOT / ".native-deps/target")
    parser.add_argument("--command", choices=("check", "test"), default="check")
    args = parser.parse_args()
    raise SystemExit(run(args.output.resolve(), args.target.resolve(), args.command))
