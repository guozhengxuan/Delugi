#!/usr/bin/env python3
"""Build and verify the pinned Raptr cohort artifact, without launching a trial.

The reviewed patch must already be applied. This helper never clones, resets,
patches, or invokes Forge. Resource limits are sampled build guards, not kernel
quotas; a successful build is not native benchmark acceptance.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "benchmarks/baselines/raptr"
PATCH = ROOT / "benchmarks/patches/raptr-cohort-2026-10-21.patch"
TARGET = ROOT / "benchmarks/.cache/raptr-cohort-target"
CARGO_HOME = ROOT / "benchmarks/.cache/raptr-cargo"
TOOLCHAIN = ROOT / "benchmarks/toolchains/mysticeti/toolchains/1.78-aarch64-apple-darwin/bin"
PIN = "a4c98047cf8aeae3571168d02fb7e343140d2948"
URL = "https://github.com/aptos-labs/aptos-core.git"
CONTRACT = "raptr-native-receipt-v1"
ROLES = ("aptos-node", "raptr-fixture")
STAMP = "raptr-cohort-build-provenance.json"
GIB = 1024 ** 3
# Only this explicit environment reaches Cargo/native build scripts. In
# particular, ambient wrappers, target overrides and feature flags do not leak.
ENV_KEYS = ("HOME", "PATH", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL",
            "CC", "CXX", "AR", "LD", "CFLAGS", "CXXFLAGS", "CPPFLAGS",
            "LDFLAGS", "RUSTFLAGS", "SDKROOT", "DEVELOPER_DIR",
            "MACOSX_DEPLOYMENT_TARGET", "LIBCLANG_PATH", "Z_LIB_DIR",
            "Z_INCLUDE_DIR", "PROTOC", "PKG_CONFIG", "PKG_CONFIG_PATH",
            "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR")


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular(path, *, executable=False):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or (executable and not info.st_mode & 0o111):
        raise ValueError(f"Expected regular {'executable' if executable else 'file'}: {path}")
    return info


def output(argv, **kwargs):
    return subprocess.check_output([str(arg) for arg in argv], timeout=30, **kwargs)


def validate_source(source=SOURCE, patch=PATCH):
    source, patch = Path(source).resolve(), Path(patch).absolute()
    regular(patch)  # A missing new patch is never replaced with the legacy one.
    expected = patch.read_bytes()
    if not expected or b"diff --git " not in expected:
        raise ValueError("Reviewed cohort patch is empty or malformed")
    commit = output(["git", "-C", source, "rev-parse", "HEAD"], text=True).strip()
    if commit != PIN:
        raise ValueError(f"Raptr commit {commit} differs from pinned {PIN}")
    untracked = output(["git", "-C", source, "ls-files", "--others", "--exclude-standard"])
    if untracked:
        raise ValueError("Untracked native sources are not bound by the reviewed patch")
    diff = output(["git", "-C", source, "diff", "HEAD", "--binary"])
    if diff != expected:
        raise ValueError("Raptr source diff differs from the reviewed cohort patch")
    for path in (source / "Cargo.lock", source / "rust-toolchain.toml"):
        regular(path)
    return {"source_commit": commit, "source_remote": URL, "reference": "raptr-public",
            "source_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "patch_sha256": sha256(patch), "cargo_lock_sha256": sha256(source / "Cargo.lock"),
            "rust_toolchain_sha256": sha256(source / "rust-toolchain.toml")}


def environment(toolchain, target, cargo_home, base=None):
    base = os.environ if base is None else base
    toolchain = Path(toolchain).resolve()
    env = {key: base[key] for key in ENV_KEYS if key in base}
    env.update(PATH=str(toolchain) + os.pathsep + base.get("PATH", "/usr/bin:/bin"),
               RUSTC=str(toolchain / "rustc"), CARGO=str(toolchain / "cargo"),
               CARGO_HOME=str(Path(cargo_home).resolve()),
               CARGO_TARGET_DIR=str(Path(target).resolve()), CARGO_BUILD_JOBS="1",
               CARGO_INCREMENTAL="0", CARGO_PROFILE_RELEASE_DEBUG="0",
               CONSENSUS_ONLY_PERF_TEST="1")
    if platform.system() == "Darwin":
        # Same compatibility flag used by the historical native Raptr build.
        env["CFLAGS"] = (env.get("CFLAGS", "") + " -Dfdopen=fdopen").strip()
    return env


def recipe(toolchain, *, offline=False):
    cargo = str(Path(toolchain).resolve() / "cargo")
    common = [cargo, "build", "--release", "--locked", "--jobs", "1"]
    if offline:
        common.append("--offline")
    return [common + ["-p", "aptos-node", "--features", "consensus-only-perf-test,failpoints,smoke-test"],
            common + ["-p", "aptos-genesis", "--bin", "raptr-fixture"]]


def cargo_configs(source, cargo_home):
    """Bind Cargo's ancestor/home config search, including previously absent files."""
    source = Path(source).resolve()
    candidates = [ancestor / ".cargo" / name for ancestor in (source, *source.parents)
                  for name in ("config", "config.toml")]
    candidates.extend(Path(cargo_home) / name for name in ("config", "config.toml"))
    records = {}
    for path in candidates:
        if path.exists() or path.is_symlink():
            regular(path)
            records[str(path)] = sha256(path)
        else:
            records[str(path)] = None
    return records


def build_identity(source, patch, toolchain, env, *, offline=False):
    identity = validate_source(source, patch)
    toolchain = Path(toolchain).resolve()
    for name in ("rustc", "cargo", "rustfmt"):
        regular(toolchain / name, executable=True)
    rustc = output([toolchain / "rustc", "--version", "--verbose"], env=env, text=True)
    cargo = output([toolchain / "cargo", "--version", "--verbose"], env=env, text=True)
    rustfmt = output([toolchain / "rustfmt", "--version"], env=env, text=True)
    if "\nrelease: 1.78.0\n" not in "\n" + rustc or not cargo.startswith("cargo 1.78.0 "):
        raise ValueError("Raptr cohort artifact requires native Rust/Cargo 1.78.0")
    compiler_commit = re.search(r"(?m)^commit-hash: ([0-9a-f]{40})$", rustc)
    formatter_commit = re.search(r"^rustfmt [^\n]+ \(([0-9a-f]{7,40}) ", rustfmt)
    if not compiler_commit or not formatter_commit or not compiler_commit[1].startswith(formatter_commit[1]):
        raise ValueError("Pinned toolchain rustfmt must match the Rust 1.78 compiler commit")
    identity.update(observer_contract=CONTRACT, rustc_verbose=rustc, cargo_verbose=cargo, rustfmt_version=rustfmt,
                    compiler_executables={name: sha256(toolchain / name) for name in ("rustc", "cargo", "rustfmt")},
                    environment=dict(sorted(env.items())), commands=recipe(toolchain, offline=offline),
                    cargo_configs=cargo_configs(source, env["CARGO_HOME"]),
                    builder_sha256=sha256(__file__), profile="release", roles=list(ROLES),
                    abi_host={"system": platform.system(), "platform": platform.platform(),
                              "machine": platform.machine(), "libc": list(platform.libc_ver())})
    return identity


def binary_records(target):
    records = {}
    for name in ROLES:
        path = Path(target) / "release" / name
        info = regular(path, executable=True)
        if info.st_size == 0:
            raise ValueError(f"Empty native role executable: {name}")
        kind = output(["file", "-b", path], text=True).strip()
        if platform.system() == "Darwin":
            links = output(["otool", "-L", path], text=True)
        elif platform.system() == "Linux":
            links = output(["readelf", "-d", path], text=True)
        else:
            raise ValueError("Only native macOS/Linux artifact ABI inspection is supported")
        records[name] = {"path": str(path.resolve()), "sha256": sha256(path),
                         "bytes": info.st_size, "file": kind, "dynamic_libraries": links}
    return records


def validate_limits(limits):
    required = {"target_bytes", "free_bytes", "rss_bytes", "seconds", "poll_seconds", "cleanup_seconds"}
    if set(limits) != required:
        raise ValueError("Exact build resource limits required")
    for name, value in limits.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"Positive finite build limit required: {name}")
    if not .05 <= limits["poll_seconds"] <= 10 or limits["cleanup_seconds"] > 30:
        raise ValueError("Build polling and cleanup intervals must remain bounded")
    return dict(limits)


def process_table():
    # lstart is retained with PID to detect replacement before signalling.
    raw = output(["ps", "-axo", "pid=,ppid=,pgid=,rss=,stat=,lstart="], text=True)
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 10:
            raise ValueError("Cannot parse owned build process identity/RSS")
        pid, parent, group, rss = map(int, fields[:4])
        rows.append({"pid": pid, "parent_pid": parent, "group": group,
                     "rss_bytes": rss * 1024, "state": fields[4], "start": " ".join(fields[5:])})
    return rows


class OwnershipError(RuntimeError):
    pass


class OwnedGroup:
    def __init__(self, process):
        self.process = process
        self.group = process.pid
        self.seen = {}
        self.empty = False
        self.isolated = False

    def verify_start(self):
        try:
            group = os.getpgid(self.process.pid)
        except ProcessLookupError:
            # A fast-exiting leader can leave children in its established group.
            group = self.group
        if group != self.group:
            raise OwnershipError("Build child did not establish its isolated process group")
        self.isolated = True

    def members(self):
        rows = [row for row in process_table() if row["group"] == self.group]
        if self.empty and rows:
            raise OwnershipError("Previously empty build process group was reused")
        for row in rows:
            old = self.seen.get(row["pid"])
            if old is not None and old != row["start"]:
                raise OwnershipError("Owned build PID identity changed; refusing signal")
            self.seen[row["pid"]] = row["start"]
        if not rows:
            self.empty = True
        return rows

    def send(self, sig):
        if not self.isolated:
            raise OwnershipError("Refusing to signal a build group without established ownership")
        if self.members():
            try:
                os.killpg(self.group, sig)
            except ProcessLookupError:
                pass

    def cleanup(self, timeout):
        record = {"group": self.group, "status": "pending", "signals": []}
        try:
            if self.members():
                for sig in (signal.SIGCONT, signal.SIGTERM):
                    self.send(sig)
                    record["signals"].append(sig.name)
                deadline = time.monotonic() + timeout
                while self.members() and time.monotonic() < deadline:
                    self.process.poll()  # Reap the owned leader if it has exited.
                    time.sleep(.05)
                if self.members():
                    self.send(signal.SIGKILL)
                    record["signals"].append("SIGKILL")
            deadline = time.monotonic() + timeout
            while self.members() and time.monotonic() < deadline:
                self.process.poll()
                time.sleep(.05)
            self.process.poll()
            record["remaining"] = self.members()
            if record["remaining"]:
                raise RuntimeError("Owned build process group survived bounded cleanup")
            record["status"] = "completed"
        except BaseException as error:
            record.update(status="failed", error=f"{type(error).__name__}: {error}")
            # If ps itself failed, terminate the group while its unreaped leader
            # still pins the original PID/group identity. Do not turn an
            # unconfirmed cleanup into success, or signal an identity refusal.
            if not isinstance(error, OwnershipError) and self.isolated and not self.empty and self.process.returncode is None:
                try:
                    if os.getpgid(self.process.pid) != self.group:
                        raise OwnershipError("Emergency cleanup cannot establish owned group")
                    for sig in (signal.SIGCONT, signal.SIGTERM):
                        os.killpg(self.group, sig)
                        record["signals"].append(sig.name)
                    time.sleep(min(timeout, 1))
                    # No poll()/wait() until KILL: the unreaped leader prevents
                    # PID/group reuse during this fallback interval.
                    os.killpg(self.group, signal.SIGKILL)
                    record["signals"].append("SIGKILL")
                    self.process.wait(timeout=timeout)
                except ProcessLookupError:
                    self.process.poll()
                except BaseException as cleanup_error:
                    record["emergency_error"] = f"{type(cleanup_error).__name__}: {cleanup_error}"
        return record


def disk_sample(target):
    # Native configure scripts create and unlink probes while this sample runs.
    # Count allocated POSIX blocks without treating ENOENT as a build failure.
    # Other read failures propagate. Directory descriptors prevent symlink
    # traversal, and inode identities avoid counting hard links twice.
    seen = set()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    def charge(info):
        identity = (info.st_dev, info.st_ino)
        if identity in seen:
            return 0
        seen.add(identity)
        return info.st_blocks * 512
    def scan(descriptor):
        allocated = charge(os.fstat(descriptor))
        with os.scandir(descriptor) as entries:
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, flags, dir_fd=descriptor)
                        try:
                            allocated += scan(child)
                        finally:
                            os.close(child)
                    else:
                        allocated += charge(info)
                except FileNotFoundError:
                    continue
        return allocated
    descriptor = os.open(target, flags)
    try:
        allocated = scan(descriptor)
    finally:
        os.close(descriptor)
    return {"target_allocated_bytes": allocated,
            "filesystem_free_bytes": shutil.disk_usage(target).free}


def stop_reason(sample, limits):
    for field, maximum in (("target_allocated_bytes", "target_bytes"),
                           ("owned_group_rss_bytes", "rss_bytes"), ("elapsed_seconds", "seconds")):
        if sample[field] >= limits[maximum]:
            return f"{field} reached {maximum} guard"
    if sample["filesystem_free_bytes"] < limits["free_bytes"]:
        return "filesystem free-space floor crossed"
    return None


def guarded_command(argv, source, env, target, log_path, resource_path, limits, receipt):
    validate_limits(limits)
    before = {**disk_sample(target), "owned_group_rss_bytes": 0, "elapsed_seconds": 0}
    reason = stop_reason(before, limits)
    if reason:
        receipt.update(status="failed", stop_reason=reason, preflight=before,
                       cleanup={"status": "not_started", "remaining": []})
        raise RuntimeError(reason)
    process_table()  # Observation permission/parser must work before spawning.
    receipt.update(argv=list(argv), status="running", limits=limits, samples=0,
                   peak_owned_group_rss_bytes=0, peak_target_allocated_bytes=0)
    started = time.monotonic()
    with Path(log_path).open("xb") as log, Path(resource_path).open("x") as samples:
        process = subprocess.Popen(argv, cwd=source, env=env, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        owned = OwnedGroup(process)
        receipt["pid"] = process.pid
        try:
            owned.verify_start()
            while True:
                members = owned.members()
                sample = {**disk_sample(target), "elapsed_seconds": time.monotonic() - started,
                          "owned_group_rss_bytes": sum(row["rss_bytes"] for row in members),
                          "processes": len(members)}
                samples.write(json.dumps(sample, sort_keys=True) + "\n")
                samples.flush()
                receipt["samples"] += 1
                for key in ("owned_group_rss_bytes", "target_allocated_bytes"):
                    receipt["peak_" + key] = max(receipt["peak_" + key], sample[key])
                reason = stop_reason(sample, limits)
                if reason:
                    receipt["stop_reason"] = reason
                    raise RuntimeError(reason)
                code = process.poll()
                if code is not None:
                    receipt["returncode"] = code
                    if code:
                        raise RuntimeError(f"Native build exited with status {code}")
                    break
                time.sleep(limits["poll_seconds"])
        except BaseException as error:
            receipt.update(status="failed", error=f"{type(error).__name__}: {error}")
            raise
        finally:
            receipt["cleanup"] = owned.cleanup(limits["cleanup_seconds"])
            receipt["returncode"] = process.poll()
            receipt["elapsed_seconds"] = time.monotonic() - started
            if receipt["cleanup"]["status"] != "completed":
                receipt["status"] = "failed"
                raise RuntimeError("Build cleanup failed; artifact cannot be accepted")
        receipt["status"] = "completed"


@contextlib.contextmanager
def target_lock(target):
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    with (target / ".raptr-build.lock").open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another build/verification owns the Raptr target") from error
        yield


def write_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("x") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def verify(*, source=SOURCE, patch=PATCH, target=TARGET, cargo_home=CARGO_HOME,
           toolchain=TOOLCHAIN, offline=False, base_environment=None):
    target = Path(target).resolve()
    with target_lock(target):
        regular(target / STAMP)
        stamp = json.loads((target / STAMP).read_text())
        env = environment(toolchain, target, cargo_home, base_environment)
        if (stamp.get("schema") != 1 or stamp.get("status") != "built" or stamp.get("protocol") != "raptr"
                or stamp.get("observer_contract") != CONTRACT or stamp.get("acceptance") != "build_only_not_runtime_validated"):
            raise ValueError("Verified Raptr cohort build stamp required")
        current = build_identity(source, patch, toolchain, env, offline=offline)
        if stamp.get("identity") != current or stamp.get("identity_after") != current:
            raise ValueError("Raptr source/compiler/environment/recipe changed after build")
        if stamp.get("binaries") != binary_records(target):
            raise ValueError("Raptr role binary or ABI differs from build stamp")
        if len(stamp.get("build_commands", [])) != 2 or any(
                command.get("status") != "completed" or command.get("returncode") != 0 or
                command.get("cleanup", {}).get("status") != "completed" or
                command["cleanup"].get("remaining") != [] or command.get("argv") != argv
                for command, argv in zip(stamp["build_commands"], current["commands"])):
            raise ValueError("Raptr build/owned-cleanup receipts are incomplete")
        return stamp


def build(*, output_dir, source=SOURCE, patch=PATCH, target=TARGET, cargo_home=CARGO_HOME,
          toolchain=TOOLCHAIN, offline=False, limits=None, base_environment=None):
    limits = validate_limits(limits or {"target_bytes": 60 * GIB, "free_bytes": 20 * GIB,
                             "rss_bytes": 12 * GIB, "seconds": 10800,
                             "poll_seconds": 1, "cleanup_seconds": 5})
    source, target, output_dir = map(lambda p: Path(p).resolve(), (source, target, output_dir))
    patch = Path(patch).absolute()
    output_dir.mkdir(parents=True, exist_ok=False)
    record = {"schema": 1, "protocol": "raptr", "status": "building",
              "observer_contract": CONTRACT, "acceptance": "build_only_not_runtime_validated",
              "started_unix_ns": time.time_ns(), "source": str(source), "target": str(target),
              "build_commands": [], "resource_guard": {"limits": limits,
              "scope": "Sampled allocated target bytes/free disk and summed owned process-group RSS; not kernel-enforced quotas"}}
    try:
        with target_lock(target):
            build_started = time.monotonic()
            env = environment(toolchain, target, cargo_home, base_environment)
            identity = build_identity(source, patch, toolchain, env, offline=offline)
            record["identity"] = identity
            # Invalidate an older success before the first mutating build step.
            (target / STAMP).unlink(missing_ok=True)
            shutil.copyfile(patch, output_dir / "source.patch")
            shutil.copyfile(__file__, output_dir / "raptr_artifacts.py")
            shutil.copyfile(source / "Cargo.lock", output_dir / "Cargo.lock")
            shutil.copyfile(source / "rust-toolchain.toml", output_dir / "rust-toolchain.toml")
            for index, argv in enumerate(identity["commands"]):
                remaining_seconds = limits["seconds"] - (time.monotonic() - build_started)
                if remaining_seconds <= 0:
                    raise RuntimeError("Whole-build elapsed time guard reached before next role")
                command_limits = dict(limits, seconds=remaining_seconds)
                receipt = {}
                record["build_commands"].append(receipt)
                guarded_command(argv, source, env, target, output_dir / f"build-{index}.log",
                                output_dir / f"resources-{index}.jsonl", command_limits, receipt)
                if build_identity(source, patch, toolchain, env, offline=offline) != identity:
                    raise ValueError("Raptr source/compiler/environment changed during native build")
            record["binaries"] = binary_records(target)
            record["identity_after"] = build_identity(source, patch, toolchain, env, offline=offline)
            if record["identity_after"] != identity:
                raise ValueError("Raptr provenance changed during artifact finalization")
            record.update(status="built", finished_unix_ns=time.time_ns())
            write_json(target / STAMP, record)
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        record.setdefault("finished_unix_ns", time.time_ns())
        write_json(output_dir / "manifest.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "build", "verify"))
    for name, default in (("source", SOURCE), ("patch", PATCH), ("target", TARGET),
                          ("cargo-home", CARGO_HOME), ("toolchain", TOOLCHAIN)):
        parser.add_argument("--" + name, type=Path, default=default)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--target-gib", type=float, default=60)
    parser.add_argument("--free-gib", type=float, default=20)
    parser.add_argument("--rss-gib", type=float, default=12)
    parser.add_argument("--timeout-seconds", type=float, default=10800)
    args = parser.parse_args()
    options = {key: getattr(args, key) for key in ("source", "patch", "target", "cargo_home", "toolchain", "offline")}
    if args.action == "inspect":
        result = {"status": "source_verified_not_built", "identity": build_identity(
            args.source, args.patch, args.toolchain, environment(args.toolchain, args.target, args.cargo_home), offline=args.offline)}
    elif args.action == "verify":
        result = verify(**options)
    else:
        if args.output is None:
            parser.error("build requires a new --output evidence directory")
        limits = {"target_bytes": args.target_gib * GIB, "free_bytes": args.free_gib * GIB,
                  "rss_bytes": args.rss_gib * GIB, "seconds": args.timeout_seconds,
                  "poll_seconds": 1, "cleanup_seconds": 5}
        result = build(output_dir=args.output, limits=limits, **options)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
