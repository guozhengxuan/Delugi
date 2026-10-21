#!/usr/bin/env python3
"""Prepare pinned published artifacts and record native build provenance.

This does not claim benchmark endpoint equivalence. It never invokes upstream
cloud/tmux cleanup helpers, and build outputs live in the selected cache only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "provenance/baselines.json"


def sha256(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda:source.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def selection(protocol, disruption=False):
    data = json.loads(MANIFEST.read_text())["baselines"][protocol]
    selected = dict(data)
    if disruption:
        if protocol != "autobahn":
            raise ValueError("Only Autobahn has a separately published disruption branch")
        selected.update(data["disruption_artifact"])
    return selected


def prepare(protocol, disruption=False):
    pin = selection(protocol, disruption)
    source = ROOT / pin["checkout"]
    if not source.exists():
        source.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth", "1", "--single-branch", "--branch", pin["reference"], pin["repository"], str(source)], check=True)
    commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if commit != pin["commit"]:
        raise RuntimeError(f"Existing {source} is {commit}, expected {pin['commit']}; refusing to reset it")
    if pin.get("instrumentation_patch"):
        patch = ROOT / pin["instrumentation_patch"]
        expected = patch.read_bytes()
        current = subprocess.check_output(["git", "-C", str(source), "diff", "HEAD"])
        if current != expected:
            if current: raise RuntimeError("Native checkout differs from recorded instrumentation patch")
            subprocess.run(["git", "-C", str(source), "apply", "--check", str(patch)],check=True)
            subprocess.run(["git", "-C", str(source), "apply", "--intent-to-add", str(patch)],check=True)
    if pin.get("dependency_lock"):
        recorded = ROOT / pin["dependency_lock"]
        local = source / "Cargo.lock"
        if local.exists() and local.read_bytes() != recorded.read_bytes():
            raise RuntimeError("Native dependency lock differs from reviewed archived lock")
        if not local.exists(): local.write_bytes(recorded.read_bytes())
    return source, pin


def build(protocol, *, disruption=False, jobs=2, output, toolchain=None):
    source, pin = prepare(protocol, disruption)
    suffix = "-blips" if disruption else ""
    target = ROOT / "benchmarks/.cache" / f"{protocol}{suffix}-target"
    cargo_home = ROOT / "benchmarks/.cache" / f"{protocol}-cargo"
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), CARGO_HOME=str(cargo_home), CARGO_BUILD_JOBS=str(jobs), CARGO_INCREMENTAL="0")
    if platform.system() == "Darwin":
        env.setdefault("LIBCLANG_PATH", "/opt/homebrew/opt/llvm@14/lib")
        sdk = subprocess.check_output(["xcrun", "--show-sdk-path"], text=True).strip()
        # Bundled old zlib mistakes modern TARGET_OS_MAC for classic Mac OS.
        # Use the platform's ABI-compatible zlib, without altering protocol/store code.
        env.setdefault("Z_LIB_DIR", str(Path(sdk) / "usr/lib"))
    toolchain = toolchain or pin.get("build_toolchain", "1.75.0")
    native = ["cargo", f"+{toolchain}", "build", "--release", "--jobs", str(jobs)]
    native += ["-p", "node", "--features", "benchmark"] if protocol == "autobahn" else ["-p", "aptos-node", "--features", "consensus-only-perf-test"]
    if protocol == "shoal":
        # Upstream release enables full debug information. Exclude that build-only
        # disk overhead explicitly; retain overflow checks and upstream rustflags.
        env["CARGO_PROFILE_RELEASE_DEBUG"] = "0"
    lock = source / "Cargo.lock"
    record = {"protocol": protocol, "source_commit": pin["commit"], "source_remote": pin["repository"],
              "reference": pin["reference"], "status": "building", "started_unix_ns": time.time_ns(),
              "native_crypto_and_storage": True, "target": str(target), "commands": [],
              "environment": {k: env[k] for k in ("CARGO_TARGET_DIR", "CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_PROFILE_RELEASE_DEBUG", "LIBCLANG_PATH", "Z_LIB_DIR") if k in env}}
    if pin.get('observer_contract'):record['observer_contract']=pin['observer_contract']
    try:
        record["rustc"] = subprocess.check_output(["rustc", f"+{toolchain}", "--version", "--verbose"], env=env, text=True)
        if not lock.exists():
            # Original Autobahn has no tracked lock. Preserve the first resolved
            # lock as a reproducibility artifact; later builds must use it.
            command = ["cargo", f"+{toolchain}", "generate-lockfile"]
            record["commands"].append(command)
            with (output / "resolve.log").open("wb") as log:
                subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        record["cargo_lock_sha256"] = sha256(lock)
        (output / "Cargo.lock").write_bytes(lock.read_bytes())
        native.append("--locked")
        record["commands"].append(native)
        with (output / "build.log").open("wb") as log:
            subprocess.run(native, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            if protocol == "shoal":
                fixture = ["cargo", f"+{toolchain}", "build", "--release", "--jobs", str(jobs), "--locked", "-p", "aptos-genesis", "--bin", "shoal-fixture"]
                record["commands"].append(fixture)
                subprocess.run(fixture, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        names = ["node", "benchmark_client"] if protocol == "autobahn" else ["aptos-node", "shoal-fixture"]
        record["binaries"] = [{"path": str(target / "release" / name), "sha256": sha256(target / "release" / name), "bytes": (target / "release" / name).stat().st_size} for name in names]
        diff = subprocess.check_output(["git", "-C", str(source), "diff", "HEAD"])
        record["source_diff_sha256"] = hashlib.sha256(diff).hexdigest()
        record["abi"] = {"platform": platform.platform(), "machine": platform.machine(), "libc": list(platform.libc_ver())}
        if platform.system() == "Linux":
            record["abi"]["dynamic_libraries"] = {entry["path"]: subprocess.run(["ldd", entry["path"]], capture_output=True, text=True).stdout for entry in record["binaries"]}
        (output / "source.patch").write_bytes(diff)
        record["runner_sha256"] = sha256(__file__)
        record["status"] = "built"
        (target / "build-provenance.json").write_text(json.dumps(record, indent=2)+"\n")
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        record["finished_unix_ns"] = time.time_ns()
        (output / "manifest.json").write_text(json.dumps(record, indent=2)+"\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("protocol", choices=("autobahn", "shoal"))
    parser.add_argument("--disruption", action="store_true")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--toolchain")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("jobs must be positive")
    if args.build:
        if args.output is None: parser.error("--build requires a new --output directory")
        result = build(args.protocol, disruption=args.disruption, jobs=args.jobs, output=args.output.resolve(), toolchain=args.toolchain)
    else:
        source, pin = prepare(args.protocol, args.disruption)
        result = {"status":"source_pinned", "source":str(source), "pin":pin}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
