#!/usr/bin/env python3
"""Supervise a finite four-process Raptr shared-service fixture on localhost.

An already built, source-bound native executable is required. This driver never
builds, invokes Forge, shapes the host network, or substitutes protocol evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/baselines"))
import raptr_artifacts as ownership

PIN = "a4c98047cf8aeae3571168d02fb7e343140d2948"
PROFILE = "raptr-shared-consensus-only-v1"
BUILD_FORMAT = "raptr-shared-build-v1"
CASES = ("healthy", "empty", "unfinished", "silent-first-leader", "materializer-delay", "missing-payload-recovery")
MAX_JSON = 4 * 1024 * 1024
MAX_LINE = 4 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_ARCHIVE = 2 * 1024**3
MAX_METADATA = 64 * 1024 * 1024
MAX_LOG = 64 * 1024 * 1024
NODES = 4
DEFAULT_LIMITS = {"max_wire_bytes": 1048576, "inbox_frames": 4096, "inbox_bytes": 33554432,
                  "maximum_rpcs": 1024, "ingress_capacity": 4096, "max_pending_transactions": 100000,
                  "max_pending_payload_bytes": 134217728, "output_capacity": 4096, "max_journal_bytes": 134217728}
EXECUTOR_LIMITS = {"max_async_tasks": 100_000, "max_blocking_tasks": 1024}
LIMIT_CEILINGS = {"max_wire_bytes": 1048576, "inbox_frames": 100000, "inbox_bytes": 134217728,
                  "maximum_rpcs": 100000, "ingress_capacity": 100000, "max_pending_transactions": 1000000,
                  "max_pending_payload_bytes": 1073741824, "output_capacity": 100000, "max_journal_bytes": 536870912,
                  "max_async_tasks": 1_000_000, "max_blocking_tasks": 100_000}
CONTROLLER_FILES = ("scripts/run_raptr_shared_local.py", "scripts/baselines/raptr_artifacts.py", "scripts/build_raptr_shared.py")


def clock_us():
    """Match shared_runtime::monotonic_us, including macOS clock origins."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def uint(value, name, maximum=2**64 - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"invalid unsigned {name}")
    return value


def hex_hash(value, name="hash"):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"invalid {name}")
    return value


def bounded_json(path, limit=MAX_JSON):
    path = Path(path)
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > limit:
        raise ValueError(f"expected bounded regular JSON: {path}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON grew beyond declared bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def safe_file(root, name):
    root = Path(root).resolve()
    if not isinstance(name, str) or "\\" in name:
        raise ValueError("expected relative evidence path")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != name or name == ".":
        raise ValueError("path escapes evidence root")
    path = root / name
    if not path.resolve().is_relative_to(root) or any(p.is_symlink() for p in (path, *path.parents) if p != root and p.is_relative_to(root)):
        raise ValueError("symlinked or escaping evidence path")
    if not path.is_file():
        raise ValueError("evidence file absent")
    return path


def file_record(path):
    path = Path(path)
    return {"bytes": path.stat().st_size, "sha256": sha256(path)}


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".pending-" + secrets.token_hex(8))
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def copy_verified(source, destination, expected, limit=MAX_FILE):
    source, destination = Path(source), Path(destination)
    if source.is_symlink() or not stat.S_ISREG(source.stat().st_mode) or source.stat().st_size > limit:
        raise ValueError("artifact is not a bounded regular file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        h, size = hashlib.sha256(), 0
        for chunk in iter(lambda: incoming.read(1024 * 1024), b""):
            size += len(chunk)
            if size > limit:
                raise ValueError("artifact grew beyond archive envelope")
            h.update(chunk)
            outgoing.write(chunk)
    if h.hexdigest() != expected or sha256(source) != expected:
        raise ValueError("artifact changed while archived")
    return {"bytes": size, "sha256": expected}


def validate_native_dependencies(record, source_root=ROOT):
    """The binary's immutable Aptos dependencies cannot be an uninspected path."""
    source_root = Path(source_root).resolve()
    metadata = bounded_json(source_root / "core/raptr/native-source.json")
    if (not isinstance(record, dict) or record.get("commit") != PIN
            or metadata.get("source_commit") != PIN
            or record.get("archive_sha256") != metadata.get("source_archive_sha256")
            or record.get("directory") != f"core/raptr/.native-deps/{PIN}"):
        raise ValueError("native dependency archive/tree identity differs")
    archive = safe_file(source_root, record.get("archive_path"))
    if sha256(archive) != record["archive_sha256"]:
        raise ValueError("native source archive differs from the pinned build")
    tree = source_root / record["directory"]
    entries = record.get("files")
    if not isinstance(entries, dict) or not entries or digest(entries) != record.get("tree_sha256"):
        raise ValueError("checked native dependency manifest is absent or changed")
    observed = set()
    for directory, dirs, files in os.walk(tree, followlinks=False):
        links = [name for name in dirs if (Path(directory) / name).is_symlink()]
        dirs[:] = [name for name in dirs if name not in links]
        for name in files + links:
            path = Path(directory) / name
            relative = path.relative_to(tree).as_posix()
            observed.add(relative)
            expected = entries.get(relative)
            if not isinstance(expected, dict):
                raise ValueError(f"unbound native dependency file: {relative}")
            if expected.get("kind") == "symlink":
                if not path.is_symlink() or os.readlink(path) != expected.get("target"):
                    raise ValueError(f"native dependency link changed: {relative}")
            elif (expected.get("kind") != "file" or path.is_symlink() or not path.is_file()
                  or file_record(path) != {key: expected.get(key) for key in ("bytes", "sha256")}
                  or bool(path.stat().st_mode & 0o111) != expected.get("executable")):
                raise ValueError(f"native dependency source changed: {relative}")
    if observed != set(entries):
        raise ValueError("native dependency source manifest has missing files")
    return {"files": len(entries), "tree_sha256": record["tree_sha256"], "archive_sha256": record["archive_sha256"]}


def resolved_capabilities(metadata, source_root=ROOT, build_root=None):
    """Derive capabilities from the fixed target and Cargo's resolved graph.

    These fields describe the compiled assembly, not completed protocol tests.
    The executable's historical filename does not imply a selected protocol.
    """
    root = Path(source_root).resolve()
    declared_root = Path(build_root).resolve() if build_root is not None else root
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if metadata.get("version") != 1 or not isinstance(packages, list) or not isinstance(resolve, dict):
        raise ValueError("complete Cargo metadata graph required for capabilities")
    by_id = {package["id"]: package for package in packages}
    if len(by_id) != len(packages):
        raise ValueError("duplicate Cargo package identity")
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}
    if len(nodes) != len(resolve.get("nodes", [])):
        raise ValueError("duplicate Cargo resolution node")
    assembly = by_id.get(resolve.get("root"), {})
    manifest_path = root / "core/raptr/node/Cargo.toml"
    if assembly.get("manifest_path") != str(declared_root / "core/raptr/node/Cargo.toml") or assembly.get("name") != "raptr-shared-node":
        raise ValueError("Cargo root is not the pinned common-node assembly")
    manifest = tomllib.loads(manifest_path.read_text())
    targets = [target for target in assembly.get("targets", []) if target.get("name") == "raptr-shared-node" and target.get("kind") == ["bin"]]
    bins = [target for target in manifest.get("bin", []) if target.get("name") == "raptr-shared-node"]
    if (len(targets) != 1 or len(bins) != 1 or manifest.get("package", {}).get("autobins") is not False
            or bins[0].get("path") != "../../../node/src/shared_main.rs"
            or not isinstance(targets[0].get("src_path"), str)
            or Path(targets[0]["src_path"]).resolve() != declared_root / "node/src/shared_main.rs"):
        raise ValueError("common executable target/entry point differs from reviewed assembly")
    root_node = nodes.get(assembly.get("id"), {})
    direct = set(root_node.get("dependencies", []))
    required = {"delugi-core": ("core/delugi", "rocksdb-records"),
                "raptr-qs": ("core/raptr/qs", "rocksdb-backend"),
                "raptr": ("core/raptr/native", None),
                "common-node": ("node", None)}
    features = {}
    for name, (directory, required_feature) in required.items():
        matching = [package for package in packages if package.get("name") == name and package.get("manifest_path") == str(declared_root / directory / "Cargo.toml")]
        if len(matching) != 1 or matching[0]["id"] not in direct:
            raise ValueError(f"common assembly is missing direct core/service dependency: {name}")
        package = matching[0]
        dependency = manifest.get("dependencies", {}).get(name, {})
        if (not isinstance(dependency, dict) or dependency.get("optional", False)
                or (manifest_path.parent / dependency.get("path", "")).resolve() != root / directory):
            raise ValueError(f"common assembly dependency path/activation differs: {name}")
        actual = nodes.get(package["id"], {}).get("features")
        if (not isinstance(actual, list) or any(not isinstance(value, str) for value in actual)
                or len(set(actual)) != len(actual)):
            raise ValueError(f"resolved Cargo features absent or malformed: {name}")
        if required_feature is not None and (required_feature not in actual or required_feature not in dependency.get("features", [])):
            raise ValueError(f"required compiled feature absent: {name}/{required_feature}")
        declared = dependency.get("features", [])
        if (not isinstance(declared, list) or any(not isinstance(value, str) for value in declared)
                or not set(declared).issubset(actual)):
            raise ValueError(f"explicit binary dependency features differ from resolution: {name}")
        # Metadata also includes features needed by test/dev targets. Only the
        # explicit unconditional binary dependency features are asserted here.
        features[name] = sorted(set(declared))
    return {"protocols": ["delugi", "raptr"], "compiled_features": features,
            "entry_point": "node/src/shared_main.rs"}


def validate_capabilities(stamp, source_root=ROOT):
    proof = stamp.get("cargo_metadata")
    if proof is None:
        if any(key in stamp for key in ("protocols", "compiled_features", "entry_point")):
            raise ValueError("declared capabilities require resolved Cargo metadata proof")
        # Historical Raptr-only receipts remain readable and cannot gain Delugi
        # capability by adding a field to the archived JSON.
        return {"protocols": ["raptr"], "compiled_features": {}, "entry_point": None,
                "capability_evidence": "legacy_raptr_only_no_feature_promotion"}
    root = Path(source_root).resolve()
    declared_root = receipt_build_root(stamp, root)
    path = safe_file(root, proof.get("path"))
    if file_record(path) != {key: proof.get(key) for key in ("bytes", "sha256")} or path.stat().st_size > MAX_METADATA:
        raise ValueError("resolved Cargo metadata bytes changed")
    cargo = stamp.get("toolchain", {}).get("executables", {}).get("cargo", {}).get("path")
    expected = [cargo, "--config", str(declared_root / "core/raptr/native/.cargo/config.toml"), "metadata",
                "--manifest-path", str(declared_root / "core/raptr/node/Cargo.toml"), "--locked", "--offline", "--format-version", "1"]
    if (proof.get("argv") != expected or proof.get("returncode") != 0
            or proof.get("cleanup", {}).get("status") != "completed" or proof["cleanup"].get("remaining") != []):
        raise ValueError("Cargo capability proof used a different resolution recipe")
    value = resolved_capabilities(bounded_json(path, MAX_METADATA), root, declared_root)
    if any(stamp.get(key) != expected for key, expected in value.items()):
        raise ValueError("declared capabilities differ from the compiled assembly graph")
    for required in ("node/src/shared_main.rs", "core/delugi/Cargo.toml", "Cargo.toml", "Cargo.lock"):
        if required not in stamp.get("sources", {}):
            raise ValueError(f"common assembly source closure omits {required}")
    return {**value, "capability_evidence": "locked_offline_metadata_and_bound_common_entry"}


def receipt_build_root(stamp, source_root):
    """Relocation never rewrites the original command or Cargo metadata bytes."""
    value = stamp.get("build_root", str(source_root))
    if not isinstance(value, str) or not Path(value).is_absolute() or ".." in Path(value).parts:
        raise ValueError("invalid producer build root")
    return Path(value)


def validate_build_jobs(value):
    if type(value) is not int or not 1 <= value <= 4:
        raise ValueError("explicit build parallelism must be an integer from1 through4")
    return value


def validate_build(binary, stamp, source_root=ROOT):
    """A successful compiler exit alone is not an artifact/source binding."""
    source_root, binary = Path(source_root).resolve(), Path(binary).resolve()
    build_root = receipt_build_root(stamp, source_root)
    if stamp.get("schema") != 1 or stamp.get("format") != BUILD_FORMAT or stamp.get("status") != "completed":
        raise ValueError("completed Raptr shared build receipt required")
    if stamp.get("native_commit") != PIN or stamp.get("source_before_after_equal") is not True:
        raise ValueError("native pin or build source guard differs")
    command = stamp.get("command", {})
    if (stamp.get("action") != "build" or stamp.get("profile") not in ("dev", "release")
            or command.get("status") != "completed" or command.get("returncode") != 0
            or command.get("cleanup", {}).get("status") != "completed" or command["cleanup"].get("remaining") != []):
        raise ValueError("successful explicit binary build and owned cleanup receipt required")
    cargo = stamp.get("toolchain", {}).get("executables", {}).get("cargo", {}).get("path")
    jobs = validate_build_jobs(stamp.get("build_jobs", 1))
    if "build_jobs" in stamp and stamp.get("environment", {}).get("CARGO_BUILD_JOBS") != str(jobs):
        raise ValueError("build parallelism differs between receipt and environment")
    expected_command = [cargo, "--config", str(build_root / "core/raptr/native/.cargo/config.toml"), "build",
                        "--manifest-path", str(build_root / "core/raptr/node/Cargo.toml"), "--locked", "--offline", "--jobs", str(jobs)]
    if stamp["profile"] == "release":
        expected_command.append("--release")
    expected_command += ["--bin", "raptr-shared-node"]
    if not isinstance(cargo, str) or command.get("argv") != expected_command:
        raise ValueError("binary build recipe differs from the fixed native shared-node command")
    role = stamp.get("binary", {})
    if role.get("role") != "raptr-shared-node" or role.get("sha256") != sha256(binary) or role.get("bytes") != binary.stat().st_size:
        raise ValueError("executable differs from built role")
    if not stat.S_ISREG(binary.stat().st_mode) or not os.access(binary, os.X_OK):
        raise ValueError("native role is not executable")
    if stamp.get("toolchain", {}).get("rustc_version") != "1.78.0":
        raise ValueError("pinned Rust1.78 build identity required")
    sources, profiles = stamp.get("sources"), stamp.get("profiles")
    if not isinstance(sources, dict) or not sources or not isinstance(profiles, dict) or not profiles:
        raise ValueError("complete source and service profile maps required")
    if any(profiles[name] != expected for name, expected in sources.items() if name in profiles):
        raise ValueError("source/profile maps disagree on one path")
    for name, expected in {**sources, **profiles}.items():
        hex_hash(expected)
        if sha256(safe_file(source_root, name)) != expected:
            raise ValueError(f"source/profile drift: {name}")
    for required in ("core/raptr/node/Cargo.toml", "core/raptr/node/Cargo.lock", "core/raptr/native-source.json",
                     "core/raptr/Cargo.toml", "core/raptr/Cargo.lock", "core/raptr/native/.cargo/config.toml",
                     "shared/store-rocksdb/Cargo.lock", "shared/network-async/src/lib.rs"):
        if required not in sources:
            raise ValueError(f"build source closure omits {required}")
    if "shared/store-rocksdb/native-profile.json" not in profiles:
        raise ValueError("native RocksDB effective options profile is unbound")
    capabilities = validate_capabilities(stamp, source_root)
    dependencies = validate_native_dependencies(stamp.get("native_dependencies"), source_root)
    # New source files in the mutable rehost service/core trees cannot disappear
    # merely because an older build stamp still names the files it knew about.
    roots = ("core/raptr/node", "core/raptr/native", "core/raptr/qs", "core/raptr/transport",
             "core/raptr/src", "core-api", "node", "shared")
    if "delugi" in capabilities["protocols"]:
        roots += ("core/delugi",)
    for name in roots:
        directory = source_root / name
        if not directory.exists():
            raise ValueError(f"source closure root missing: {name}")
        for current, directories, files in os.walk(directory, followlinks=False):
            directories[:] = [name for name in directories if name not in ("target", ".native-deps", ".git")]
            for filename in files:
                path = Path(current) / filename
                if path.suffix in (".rs", ".toml") or path.name == "Cargo.lock":
                    relative = str(path.relative_to(source_root))
                    if relative not in sources:
                        raise ValueError(f"unbound mutable source: {relative}")
    return {"binary": role, "build_sha256": digest(stamp), "source_files": len(sources), "profile_files": len(profiles),
            "native_dependencies": dependencies, **capabilities}


def archive_build(binary, stamp_path, directory, source_root=ROOT):
    stamp = bounded_json(stamp_path, 16 * 1024 * 1024)
    result = validate_build(binary, stamp, source_root)
    directory = Path(directory)
    directory.mkdir()
    archived = directory / "raptr-shared-node"
    copy_verified(binary, archived, stamp["binary"]["sha256"])
    archived.chmod(0o700)
    total = archived.stat().st_size
    native = stamp["native_dependencies"]
    archive = safe_file(source_root, native["archive_path"])
    total += archive.stat().st_size
    if total > MAX_ARCHIVE:
        raise ValueError("native source/archive exceeds declared disk envelope")
    copy_verified(archive, directory / "native-source.tar", native["archive_sha256"], MAX_ARCHIVE)
    if "cargo_metadata" in stamp:
        proof = stamp["cargo_metadata"]
        total += proof["bytes"]
        if total > MAX_ARCHIVE:
            raise ValueError("source/artifact archive exceeds declared disk envelope")
        copy_verified(safe_file(source_root, proof["path"]), directory / "cargo-metadata.json", proof["sha256"], MAX_METADATA)
    for name, expected in sorted({**stamp["sources"], **stamp["profiles"]}.items()):
        source = safe_file(source_root, name)
        total += source.stat().st_size
        if total > MAX_ARCHIVE:
            raise ValueError("source/artifact archive exceeds declared disk envelope")
        copy_verified(source, directory / "source" / name, expected)
    atomic_json(directory / "build-receipt.json", stamp)
    result.update(archived_bytes=total, executable=str(archived), source_root=str(Path(source_root).resolve()))
    return stamp, result


def unused_addresses(count):
    sockets = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind(("127.0.0.1", 0))
        return [f"127.0.0.1:{sock.getsockname()[1]}" for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


class Child:
    """One owned session; logs go to disk, not unbounded reader-thread lists."""
    def __init__(self, binary, config, node_id, directory, *, popen=subprocess.Popen):
        self.id = node_id
        self.directory = Path(directory)
        self.stdout = (self.directory / f"process-{node_id}.stdout").open("xb")
        self.stderr = (self.directory / f"process-{node_id}.stderr").open("xb")
        self.process = None
        self.owned = None
        try:
            self.process = popen([str(binary), "--protocol", "raptr", "--config", str(config), "--id", str(node_id)],
                                 cwd=ROOT, stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr,
                                 start_new_session=True, env=child_environment())
            self.owned = ownership.OwnedGroup(self.process)
            self.owned.verify_start()
            self.identity = self._leader()
        except BaseException:
            if self.owned is not None:
                self.owned.cleanup(2)
            self.stdout.close()
            self.stderr.close()
            raise

    def _leader(self):
        rows = [row for row in self.owned.members() if row["pid"] == self.process.pid]
        if len(rows) != 1 or rows[0]["group"] != self.process.pid:
            raise RuntimeError("owned native process identity absent")
        return rows[0]

    def pause(self, timeout=1):
        before = self._leader()
        if before["state"].startswith(("T", "t", "Z")):
            raise RuntimeError("silent leader is not running before stop")
        sent = clock_us()
        self.owned.send(signal.SIGSTOP)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self._leader()
            if row["state"].startswith(("T", "t")):
                return {"replica": self.id, "pid": self.process.pid, "clock": "CLOCK_MONOTONIC_us",
                        "stop_sent_us": sent, "stop_observed_us": clock_us(),
                        "before_identity": before, "stop_identity": row, "status": "stopped_observed"}
            time.sleep(.005)
        raise TimeoutError("silent leader stop acknowledgement missing")

    def resume(self, observation, timeout=1):
        """Observe recovery before cleanup; a configured interval is not evidence."""
        before = self._leader()
        if not before["state"].startswith(("T", "t")):
            raise RuntimeError("silent leader did not remain stopped through observation")
        observation["resume_sent_us"] = clock_us()
        self.owned.send(signal.SIGCONT)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self._leader()
            if not row["state"].startswith(("T", "t", "Z")):
                observation.update(resume_observed_us=clock_us(),
                                   resume_identity=row, status="completed")
                observation["observed_paused_lower_bound_us"] = observation["resume_sent_us"] - observation["stop_observed_us"]
                observation["observed_paused_upper_bound_us"] = observation["resume_observed_us"] - observation["stop_sent_us"]
                if observation["observed_paused_lower_bound_us"] <= 0:
                    raise ValueError("pause did not span a positive observed interval")
                return observation
            time.sleep(.005)
        raise TimeoutError("silent leader resume acknowledgement missing")

    def check(self, allow_exit=False):
        members = self.owned.members()
        for path in (Path(self.stdout.name), Path(self.stderr.name)):
            if path.stat().st_size > MAX_LOG:
                raise RuntimeError("native process log exceeds declared envelope")
        code = self.process.poll()
        if code is not None and (not allow_exit or code != 0):
            raise RuntimeError(f"replica {self.id} exited with status {code}")
        return sum(row["rss_bytes"] for row in members)

    def finish(self):
        result = {"id": self.id, "pid": self.process.pid, "identity": self.identity}
        try:
            # A resumed silent replica may exit immediately on its expired arm.
            # Reap that owned leader before signalling; macOS can reject signals
            # to an exited leader that is still present in the process table.
            # Group cleanup still checks for, and terminates, any living children.
            self.process.poll()
            result["cleanup"] = self.owned.cleanup(2)
            result["exit_code"] = self.process.poll()
        finally:
            self.stdout.close()
            self.stderr.close()
        return result


def child_environment():
    # Native local sockets and control files must not inherit HTTP proxy routes.
    env = {key: value for key, value in os.environ.items()
           if key.lower() not in ("http_proxy", "https_proxy", "all_proxy")
           and not key.startswith(("RAPTR_", "BENCHMARK_"))}
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"
    return env


def validate_config(config, case):
    if case not in CASES or config.get("schema") != 1:
        raise ValueError("unknown local Raptr fixture/schema")
    hex_hash(config.get("run_id"), "run_id")
    if config.get("epoch") != 1:
        raise ValueError("this fixture requires the fixed signed epoch1 genesis anchor")
    if config.get("delta_ms") != 100:
        raise ValueError("this local gate requires protocol Delta100ms")
    addresses = config.get("addresses")
    if not isinstance(addresses, list) or len(addresses) != NODES or len(set(addresses)) != NODES:
        raise ValueError("four distinct localhost peers required")
    for address in addresses:
        if not isinstance(address, str) or not address.startswith("127.0.0.1:"):
            raise ValueError("remote peer addresses are outside this local runner")
        uint(int(address.rsplit(":", 1)[1]), "TCP port", 65535)
        if address.endswith(":0"):
            raise ValueError("bound TCP ports required")
    workload = config.get("finite_workload", {})
    counts = workload.get("counts")
    if not isinstance(counts, list) or len(counts) != NODES:
        raise ValueError("four finite origin counts required")
    for count in counts:
        uint(count, "finite count", 5000)
    if not 1 <= uint(workload.get("useful_bytes"), "useful_bytes", 65536):
        raise ValueError("positive useful request bytes required")
    uint(workload.get("interval_us"), "interval_us", 1_000_000)
    uint(workload.get("start_delay_ms"), "start_delay_ms", 10_000)
    duration = uint(config.get("measurement_duration_ms"), "measurement duration", 60_000)
    drain = uint(config.get("drain_ms"), "drain duration", 30_000)
    if duration == 0 or duration + drain + workload["start_delay_ms"] > 90_000:
        raise ValueError("finite run must fit local 90s envelope")
    if case == "empty" and any(counts):
        raise ValueError("empty gate requires zero input")
    if case != "empty" and not sum(counts):
        raise ValueError("nonempty gate requires finite input")
    if case == "silent-first-leader" and counts[1] != 0:
        raise ValueError("native first leader1 must have no honest ingress credit")
    for count in counts:
        if count and (count - 1) * workload["interval_us"] + workload["start_delay_ms"] * 1000 >= duration * 1000:
            raise ValueError("finite arrival falls outside measurement interval")
    delay = uint(config.get("materialization_delay_ms", 0), "materialization delay", 60_000)
    if case == "materializer-delay" and not delay:
        raise ValueError("materializer-delay requires a positive application-boundary delay")
    if delay and case not in ("materializer-delay", "unfinished"):
        raise ValueError("application delay is not an implicit protocol fault")
    fault = config.get("payload_fault")
    if case == "missing-payload-recovery":
        if (not isinstance(fault, dict) or set(fault) != {"node", "drop_initial_batch_messages"}
                or fault["node"] != 0 or counts[0] != 0
                or not uint(fault["drop_initial_batch_messages"], "initial payload omissions", 1000)):
            raise ValueError("native payload fixture requires bounded original-batch omission at zero-input node0")
    elif fault is not None:
        raise ValueError("native custody omission is enabled outside its explicit fixture")
    limits = dict(DEFAULT_LIMITS, **config.get("limits", {}))
    if set(limits) not in (set(DEFAULT_LIMITS), set(DEFAULT_LIMITS) | set(EXECUTOR_LIMITS)):
        raise ValueError("unknown finite resource limit")
    for name, value in limits.items():
        if not uint(value, name, LIMIT_CEILINGS[name]):
            raise ValueError("resource limits must be positive")
    if limits["inbox_bytes"] < limits["max_wire_bytes"]:
        raise ValueError("inbox must fit one maximum wire frame")
    return [0, 2, 3] if case == "silent-first-leader" else list(range(NODES))


def validate_ready(value, config, config_hash, child):
    expected = {"schema": 1, "profile": PROFILE, "run_id": config["run_id"],
                "configuration_sha256": config_hash, "id": child.id, "pid": child.process.pid}
    if any(value.get(key) != wanted for key, wanted in expected.items()):
        raise ValueError("ready receipt differs from owned process/run/configuration")
    uint(value.get("ready_us"), "ready timestamp")
    return value


def wait_ready(children, config, config_hash, deadline, output):
    ready = {}
    while len(ready) != len(children):
        if time.monotonic() >= deadline:
            raise TimeoutError("native replicas did not all become ready")
        for child in children:
            child.check()
            path = Path(config["output_directory"]) / f"node-{child.id}" / "ready.json"
            if child.id not in ready and path.exists():
                ready[child.id] = validate_ready(bounded_json(path), config, config_hash, child)
        time.sleep(.005)
    atomic_json(Path(output) / "readiness.json", {"schema": 1, "all_prepared_observed_us": clock_us(),
                                                "replicas": ready})
    return ready


def arm(config, config_hash, ready):
    if set(ready) != set(range(NODES)):
        raise ValueError("all native replicas must prepare before arm")
    path = Path(config["arm_path"])
    if path.exists():
        raise ValueError("arm file already exists")
    epoch = clock_us() + 250_000
    if any(value["ready_us"] >= epoch for value in ready.values()):
        raise ValueError("native ready timestamp is not before future arm epoch")
    value = {"schema": 1, "run_id": config["run_id"], "configuration_sha256": config_hash, "epoch_us": epoch}
    atomic_json(path, value)
    return value


def run_command(binary, arguments, directory, name, deadline):
    """Only fixed keygen/offline-verifier commands use this bounded lifecycle."""
    directory = Path(directory)
    stdout, stderr = directory / f"{name}.stdout", directory / f"{name}.stderr"
    receipt = {"argv": [str(binary), *arguments], "status": "running"}
    process = owned = None
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            process = subprocess.Popen(receipt["argv"], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       cwd=ROOT, env=child_environment(), start_new_session=True)
            owned = ownership.OwnedGroup(process)
            owned.verify_start()
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{name} exceeded the whole-run deadline")
                owned.members()
                if max(stdout.stat().st_size, stderr.stat().st_size) > MAX_LOG:
                    raise ValueError(f"{name} exceeded its log envelope")
                time.sleep(.01)
            if process.returncode != 0:
                raise RuntimeError(f"{name} exited with status {process.returncode}")
        receipt["status"] = "completed"
    except BaseException as error:
        receipt.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        if owned is not None:
            receipt["cleanup"] = owned.cleanup(2)
        receipt["exit_code"] = process.poll() if process else None
        receipt["stdout"] = file_record(stdout) if stdout.exists() else None
        receipt["stderr"] = file_record(stderr) if stderr.exists() else None
        if receipt.get("cleanup", {}).get("status") != "completed":
            receipt["status"] = "failed"
        atomic_json(directory / f"{name}.command.json", receipt)
    if receipt["status"] != "completed":
        raise RuntimeError(f"{name} cleanup could not be confirmed")
    return bounded_json(stdout)


def resource_sample(children, output, rss_limit, disk_limit):
    rss = sum(child.check(allow_exit=True) for child in children)
    size = 0
    for path in Path(output).rglob("*"):
        if path.is_symlink():
            raise ValueError("run directory contains an unexpected symlink")
        if path.is_file():
            size += path.stat().st_size
            if size > disk_limit:
                raise RuntimeError("run exceeded sampled disk envelope")
    if rss > rss_limit:
        raise RuntimeError("owned children exceeded sampled aggregate RSS envelope")
    return {"observed_us": clock_us(), "owned_rss_bytes": rss, "run_bytes": size}


def await_completion(children, correct, deadline, output, *, rss_limit, disk_limit):
    with (Path(output) / "resources.jsonl").open("xb") as stream:
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("correct replicas did not finish before the whole-run deadline")
            sample = resource_sample(children, output, rss_limit, disk_limit)
            stream.write(json.dumps(sample, separators=(",", ":")).encode() + b"\n")
            stream.flush()
            if all(child.process.poll() == 0 for child in children if child.id in correct):
                return {"observed_us": clock_us(),
                        "exit_codes": {str(child.id): child.process.poll() for child in children}}
            time.sleep(.05)


def journal(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("expected bounded regular journal")
    with path.open("rb") as stream:
        for ordinal in range(100_001):
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                return
            if ordinal == 100_000 or len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                raise ValueError("journal exceeds row/line envelope or has a partial tail")
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError("journal row must be an object")
            yield row


def compare_prefixes(prefixes):
    """All correct ledgers must prefix the longest, including a stalled empty one."""
    if not prefixes:
        raise ValueError("no correct output ledgers")
    longest = max(prefixes.values(), key=len)
    for replica, rows in prefixes.items():
        if rows != longest[:len(rows)]:
            raise ValueError(f"correct replica {replica} diverges from canonical native output")
    return {"status": "passed", "sections": {str(key): len(value) for key, value in prefixes.items()},
            "longest_sections": len(longest), "scope": "exact canonical native section and batch/transaction order"}


def validate_requests(path, config, replica, epoch, freeze):
    expected = config["finite_workload"]["counts"][replica]
    counts = dict(planned=expected, offered=0, admitted=0, rejected=0, completed=0, unfinished=0, unoffered=0)
    latencies, ids, admission_events = [], set(), set()
    rows = 0
    for sequence, row in enumerate(journal(path)):
        rows += 1
        if sequence >= expected or row.get("sequence") != sequence:
            raise ValueError("request journal is not the complete finite sequence")
        request_id = hex_hash(row.get("request_id"), "signed transaction identity")
        if request_id in ids:
            raise ValueError("duplicate finite transaction identity")
        ids.add(request_id)
        if row.get("useful_bytes") != config["finite_workload"]["useful_bytes"]:
            raise ValueError("finite request useful bytes differ from configured plan")
        planned = epoch + config["finite_workload"]["start_delay_ms"] * 1000 + sequence * config["finite_workload"]["interval_us"]
        if row.get("planned_us") != planned:
            raise ValueError("request schedule differs from armed finite plan")
        admitted, rejected = row.get("admitted_us"), row.get("rejected_us")
        if admitted is not None and rejected is not None:
            raise ValueError("one request cannot be both admitted and rejected")
        for name in ("admitted_us", "rejected_us", "own_batch_ready_us", "first_materialized_us"):
            stamp = row.get(name)
            if stamp is not None and not planned <= uint(stamp, name) < freeze:
                raise ValueError("request timestamp lies outside its planned/frozen interval")
        for timestamp, event_name in (("admitted_us", "admission_event"), ("rejected_us", "rejection_event"),
                                      ("first_materialized_us", "first_materialized_event")):
            event = row.get(event_name)
            if (event is None) != (row.get(timestamp) is None):
                raise ValueError("request timestamp/event evidence differs")
            if event is not None and not uint(event, event_name):
                raise ValueError("local event sequence starts at one")
            if event is not None and event_name != "first_materialized_event":
                if event in admission_events:
                    raise ValueError("duplicate independent admission/rejection event")
                admission_events.add(event)
        materialized, ready = row.get("first_materialized_us"), row.get("own_batch_ready_us")
        if admitted is None:
            if ready is not None or materialized is not None:
                raise ValueError("unadmitted request received application credit")
            counts["rejected" if rejected is not None else "unoffered"] += 1
        else:
            counts["admitted"] += 1
            if ready is not None and ready < admitted:
                raise ValueError("own batch readiness predates admission")
            if materialized is not None:
                if materialized < admitted or row["first_materialized_event"] <= row["admission_event"]:
                    raise ValueError("materialization credit predates admission")
                counts["completed"] += 1
                latencies.append(materialized - admitted)
            else:
                counts["unfinished"] += 1
    if rows != expected:
        raise ValueError("request journal omitted finite input tail")
    counts["offered"] = counts["admitted"] + counts["rejected"]
    if counts["offered"] + counts["unoffered"] != expected or counts["completed"] + counts["unfinished"] != counts["admitted"]:
        raise ValueError("finite admission conservation failed")
    return counts, latencies


def validate_output(path, epoch, freeze, committee, replica):
    hashes, rounds, own_first, materialized_batches = [], {}, {}, {}
    previous_append = epoch
    previous_event, seen = 0, set()
    authors = {member["author"]: member["id"] for member in committee["members"]}
    for ordinal, row in enumerate(journal(path)):
        if row.get("schema") != 1 or row.get("ordinal") != ordinal:
            raise ValueError("output omitted/reordered a native canonical section")
        append = uint(row.get("append_us"), "append timestamp")
        if not previous_append <= append < freeze:
            raise ValueError("output timestamps are not monotonic inside the armed interval")
        previous_append = append
        event = uint(row.get("event"), "append event")
        if event <= previous_event:
            raise ValueError("local append events are not strictly increasing")
        previous_event = event
        block = row.get("block", {})
        if block.get("epoch") != 1 or block.get("author") not in authors:
            raise ValueError("output block membership/epoch differs")
        hex_hash(block.get("digest"), "native block hash")
        round_number = uint(block.get("round"), "native round")
        if round_number in rounds and rounds[round_number] != authors[block["author"]]:
            raise ValueError("one native round has conflicting committed authors")
        rounds[round_number] = authors[block["author"]]
        section = row.get("section", {})
        if section not in ({"kind": "proofs"},) and not (
                set(section) == {"kind", "index"} and section["kind"] == "sub_block"
                and type(section["index"]) is int and 0 <= section["index"] < 8):
            raise ValueError("native section selector differs from proofs/original subblock index")
        batches = row.get("batches")
        if not isinstance(batches, list):
            raise ValueError("native batch occurrences must remain an ordered list")
        for batch in batches:
            if type(batch.get("first_occurrence")) is not bool or not isinstance(batch.get("transactions"), list):
                raise ValueError("native batch occurrence metadata missing")
            # The typed offline verifier checks native descriptors and signatures.
            # This pass binds exact bytes/order and reconciles local credit.
            for tx in batch["transactions"]:
                request = hex_hash(tx.get("request_id"), "output transaction identity")
                if type(tx.get("eligible")) is not bool:
                    raise ValueError("explicit finite identity eligibility required")
                if type(tx.get("first_seen")) is not bool or type(tx.get("own_credit")) is not bool:
                    raise ValueError("explicit append-time first-seen and own-credit evidence required")
                if tx["eligible"]:
                    origin = uint(tx.get("origin"), "origin", NODES - 1)
                    sequence = uint(tx.get("sequence"), "sequence", 4999)
                    first = request not in seen
                    if first != tx["first_seen"] or (tx["own_credit"] and (not first or origin != replica)):
                        raise ValueError("first append or own-origin credit is inconsistent")
                    seen.add(request)
                    own_first.setdefault((origin, sequence), (request, append, event, tx["own_credit"]))
                elif tx["first_seen"] or tx["own_credit"]:
                    raise ValueError("foreign output received finite workload credit")
            batch_key = digest({"key": batch.get("key"), "native_info_bcs_hex": batch.get("native_info_bcs_hex")})
            materialized_batches.setdefault(batch_key, {"append_us": append, "ordinal": ordinal, "transactions": batch["transactions"]})
        canonical = json.loads(json.dumps(row))
        canonical.pop("append_us")
        canonical.pop("event")
        for field in ('timing_contract', 'app_processing_start_us', 'journal_constructed_us'):
            canonical.pop(field, None)
        for batch in canonical["batches"]:
            for tx in batch["transactions"]:
                tx.pop("first_seen")
                tx.pop("own_credit")
        hashes.append(digest(canonical))
    return hashes, rounds, own_first, materialized_batches


def verify_archive(binary, config_path, config, correct, output, deadline):
    output = Path(output)
    index = {"schema": 1, "run_id": config["run_id"], "configuration_sha256": sha256(config_path),
             "receipts": [f"replicas/node-{replica}/final.json" for replica in correct]}
    path = output / "archive-index.json"
    atomic_json(path, index)
    result = run_command(binary, ["--protocol", "raptr", "--config", str(config_path),
                                  "--verify-workload-archive", str(path)], output, "verify", deadline)
    if (result.get("schema") != 1 or result.get("verified") is not True
            or result.get("verified_signers") != sorted(correct) or result.get("index_sha256") != sha256(path)):
        raise ValueError("typed native offline verifier did not authenticate the exact signer/archive set")
    return result


def evidence_snapshot(config, correct):
    """Bind bytes across offline authentication and the later reduction pass."""
    paths = [Path(config["key_directory"]) / name for name in ("committee.json", "genesis-ledger.bcs")]
    for replica in correct:
        directory = Path(config["output_directory"]) / f"node-{replica}"
        paths.extend(safe_file(directory, name) for name in ("final.json", "workload-manifest.json", "effective-profile.json", "requests.jsonl", "output.jsonl"))
        if config.get('latency_trace') is not None:
            paths.append(safe_file(directory, 'latency-trace.json'))
    return {str(path): file_record(path) for path in paths}


def validate_effective_profile(value, config, committee_hash, genesis_hash):
    expected = {"schema": 1, "profile": PROFILE, "native_policy_commit": PIN,
                "configured_delta_ms": 100, "injected_delay_ms": 0,
                "materialization_delay_ms": config["materialization_delay_ms"],
                "payload_fault": config.get("payload_fault"),
                "committee_sha256": committee_hash, "genesis_ledger_sha256": genesis_hash,
                "limits": dict(DEFAULT_LIMITS, **config.get("limits", {})),
                "tokio_workers": 2, "maximum_blocking_threads": 32,
                "native_timer_multipliers": {"leader": 4.0, "partial_qc": 0.1, "fetch": 2.0, "round_sync": 15.0}}
    if any(value.get(key) != wanted for key, wanted in expected.items()):
        raise ValueError("effective native/shared service profile differs from requested local fixture")
    if not isinstance(value.get("consensus"), dict) or not isinstance(value.get("quorum_store"), dict):
        raise ValueError("serialized native policy defaults are absent")
    # The transport entry is a per-peer runtime snapshot, not a tunable setting.
    # Retain it verbatim in the signed file; compare the remaining static policy.
    return digest({key: item for key, item in value.items() if key != "transport"})


def fault_batch_identity(witness):
    if not isinstance(witness, dict):
        raise ValueError("native fault descriptor missing")
    key = {name: witness.get(name) for name in ("epoch", "author", "nonce", "id", "digest")}
    for name in ("epoch", "nonce", "id"):
        uint(key[name], "native batch " + name)
    for name in ("author", "digest"):
        hex_hash(key[name], "native batch " + name)
    text = witness.get("native_info_bcs_hex")
    if not isinstance(text, str) or len(text) != 240 or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("native batch descriptor must retain exact120-byte BCS")
    raw = bytes.fromhex(text)
    actual = {"author": raw[:32].hex(), "id": int.from_bytes(raw[32:40], "little"),
              "nonce": int.from_bytes(raw[40:48], "little"), "epoch": int.from_bytes(raw[48:56], "little"),
              "digest": raw[64:96].hex()}
    if actual != key or witness.get("num_txns") != int.from_bytes(raw[96:104], "little") or witness.get("num_bytes") != int.from_bytes(raw[104:112], "little"):
        raise ValueError("fault witness differs from exact native BCS descriptor")
    return digest({"key": key, "native_info_bcs_hex": text})


def validate_payload_recovery(snapshot, config, committee, epoch, deadline, materialized, admissions):
    """Join real authenticated omission, native repair, and verified app output."""
    configured = config["payload_fault"]["drop_initial_batch_messages"]
    if not isinstance(snapshot, dict) or snapshot.get("configured_drop_messages") != configured:
        raise ValueError("native payload fault snapshot/configuration differs")
    records, requests = snapshot.get("drop_records"), snapshot.get("repair_requests")
    if not isinstance(records, list) or not isinstance(requests, list) or not 1 <= len(records) <= configured or len(requests) > 16384:
        raise ValueError("native payload fault evidence missing or exceeds finite envelope")
    if snapshot.get("dropped_messages") != len(records):
        raise ValueError("native payload omission message accounting differs")
    authors = {member["author"] for member in committee["members"]}
    dropped, batch_count = {}, 0
    for index, record in enumerate(records):
        stamp = uint(record.get("observed_us"), "native omission timestamp")
        if (record.get("message_index") != index or record.get("native_payload_verified") is not True
                or record.get("sender") not in authors or not epoch <= stamp < deadline):
            raise ValueError("native omission was not authenticated inside the observed interval")
        batches = record.get("batches")
        if not isinstance(batches, list):
            raise ValueError("native omission batch descriptors missing")
        batch_count += len(batches)
        if batch_count > 16384:
            raise ValueError("native payload omission batch envelope exceeded")
        for batch in batches:
            identity = fault_batch_identity(batch)
            if batch["epoch"] != config["epoch"] or batch["author"] != record["sender"]:
                raise ValueError("omitted native descriptor author/epoch differs")
            dropped.setdefault(identity, (stamp, batch))
    if snapshot.get("dropped_batches") != batch_count:
        raise ValueError("native payload omission batch accounting differs")
    rpc_ids, matches = set(), []
    for request in requests:
        rpc = uint(request.get("rpc_id"), "native repair RPC")
        started = uint(request.get("started_us"), "native repair start")
        if rpc in rpc_ids or request.get("recipient") not in authors or not epoch <= started < deadline:
            raise ValueError("native repair correlation/recipient/start differs")
        rpc_ids.add(rpc)
        requested_digest = hex_hash(request.get("digest"), "native requested digest")
        outcome, finished = request.get("outcome"), request.get("finished_us")
        if outcome == "pending":
            if finished is not None or request.get("received_batch") is not None:
                raise ValueError("pending repair has completed evidence")
            continue
        if outcome not in ("received_batch", "not_found", "failed") or not started <= uint(finished, "native repair finish") < deadline:
            raise ValueError("native repair outcome lies outside the observed interval")
        if outcome != "received_batch":
            if request.get("received_batch") is not None:
                raise ValueError("failed repair contains successful payload evidence")
            continue
        received = request.get("received_batch")
        identity = fault_batch_identity(received)
        if request.get("error") is not None or received["digest"] != requested_digest:
            raise ValueError("native repair response differs from correlated request")
        if identity not in dropped or identity not in materialized:
            continue
        drop_time, batch = dropped[identity]
        output = materialized[identity]
        known = [tx for tx in output["transactions"] if tx.get("eligible") is True
                 and (tx.get("origin"), tx.get("sequence")) in admissions
                 and admissions[(tx["origin"], tx["sequence"])][0] == tx.get("request_id")
                 and admissions[(tx["origin"], tx["sequence"])][1] <= output["append_us"]]
        if (drop_time <= started <= finished <= output["append_us"] < deadline
                and batch["num_txns"] > 0 and known):
            matches.append({"rpc_id": rpc, "digest": batch["digest"], "descriptor_sha256": identity,
                            "dropped_us": drop_time, "request_started_us": started, "received_us": finished,
                            "materialized_us": output["append_us"], "output_ordinal": output["ordinal"],
                            "admitted_request_ids": [tx["request_id"] for tx in known]})
    if not matches:
        raise ValueError("no nonempty admitted batch joins authenticated drop, native repair and offline-verified materialization")
    return {"status": "passed", "target": config["payload_fault"]["node"], "matched_repairs": matches,
            "scope": "authenticated original QS batch omission followed by real native request/response and independently verified materialization"}


def validate_executor_lifecycle(body, *, required=False, expected_limits=None):
    before, after = body.get("executor_at_freeze"), body.get("executor_at_cleanup")
    if before is None and after is None and not required:
        return {"status": "unavailable_historical_receipt"}
    counters = ("admitted_async", "admitted_blocking", "started_async", "started_blocking",
                "body_finished_async", "body_finished_blocking", "joined_async", "joined_blocking",
                "cancelled_async", "cancelled_blocking", "panicked", "rejected_capacity", "rejected_closed",
                "maximum_retained_async", "maximum_retained_blocking")
    for phase, value in (("freeze", before), ("cleanup", after)):
        if not isinstance(value, dict):
            raise ValueError("common build requires both signed executor lifecycle snapshots")
        limits = value.get("limits")
        if not isinstance(limits, dict) or set(limits) != set(EXECUTOR_LIMITS):
            raise ValueError("shared executor capacity evidence is absent")
        for name, capacity in limits.items():
            if not uint(capacity, f"executor {name}", LIMIT_CEILINGS[name]):
                raise ValueError("shared executor capacity must be positive")
        if expected_limits is not None and limits != expected_limits:
            raise ValueError("shared executor capacity differs from configured envelope")
        for key in counters:
            uint(value.get(key), f"executor {phase} {key}")
        if value.get("failure", "missing") is not None or value["panicked"] or value["rejected_capacity"]:
            raise ValueError("shared executor reports a failure, panic, or capacity rejection")
        retained = 0
        for kind in ("async", "blocking"):
            admitted, joined = value[f"admitted_{kind}"], value[f"joined_{kind}"]
            current = uint(value.get(f"retained_{kind}"), f"executor retained {kind}")
            queued = uint(value.get(f"queued_{kind}"), f"executor queued {kind}")
            active = uint(value.get(f"active_{kind}"), f"executor active {kind}")
            if (admitted != joined + current or queued + active > current
                    or not value[f"body_finished_{kind}"] <= value[f"started_{kind}"] <= admitted
                    or value[f"cancelled_{kind}"] > joined
                    or not current <= value[f"maximum_retained_{kind}"] <= limits[f"max_{kind}_tasks"]):
                raise ValueError("shared executor task conservation differs")
            if phase == "cleanup" and (current or queued or active or admitted != joined):
                raise ValueError("shared executor cleanup retains unfinished tasks")
            retained += current
        groups = value.get("groups")
        if not isinstance(groups, list) or not groups:
            raise ValueError("shared executor group ownership evidence is absent")
        identities, group_retained = set(), 0
        for group in groups:
            if not isinstance(group, dict):
                raise ValueError("invalid shared executor group")
            identity = uint(group.get("id"), "executor group id")
            if identity in identities or not isinstance(group.get("label"), str) or type(group.get("closed")) is not bool:
                raise ValueError("invalid or duplicate shared executor group")
            identities.add(identity)
            count = uint(group.get("retained"), "executor group retained")
            group_retained += count
            if phase == "cleanup" and (not group["closed"] or count):
                raise ValueError("shared executor group remains open or retains work")
        if group_retained != retained:
            raise ValueError("shared executor per-group task counts differ")
    if not after["admitted_async"] + after["admitted_blocking"]:
        raise ValueError("common executable did not admit work through the shared executor")
    if any(after[name] < before[name] for name in counters):
        raise ValueError("shared executor cumulative counters decreased after freeze")
    if after["limits"] != before["limits"]:
        raise ValueError("shared executor capacity changed after freeze")
    if not {group["id"] for group in before["groups"]}.issubset({group["id"] for group in after["groups"]}):
        raise ValueError("shared executor discarded group ownership evidence")
    return {"status": "passed", "at_freeze": before, "at_cleanup": after,
            "scope": "signed shared task ownership; explicit abort cancellations are allowed"}


def validate_results(config, correct, output, config_hash, epoch, case, *, require_executor=False,
                     host_epochs=None, public_directory=None, replica_directory=None):
    output = Path(output)
    public_directory = Path(public_directory or config["key_directory"])
    replica_directory = Path(replica_directory or config["output_directory"])
    if host_epochs is not None and (set(host_epochs) != set(correct)
                                   or any(type(v) is not int or v < 0 for v in host_epochs.values())):
        raise ValueError("explicit host-local epoch required for every correct replica")
    if host_epochs is not None and case not in ("healthy", "silent-first-leader"):
        raise ValueError("distributed reduction currently supports healthy and silent-first-leader cases")
    committee = bounded_json(public_directory / "committee.json")
    if committee.get("schema") != 1 or committee.get("epoch") != 1:
        raise ValueError("public committee identity differs")
    members = committee.get("members")
    if not isinstance(members, list) or [member.get("id") for member in members] != list(range(NODES)):
        raise ValueError("public committee member mapping differs")
    prefixes, round_maps, replicas, materializer, profiles, first_outputs, admissions = {}, {}, {}, {}, {}, {}, {}
    materialized_batches, fault_snapshots = {}, {}
    all_latency = []
    for replica in correct:
        if host_epochs is not None:
            epoch = host_epochs[replica]
        directory = replica_directory / f"node-{replica}"
        receipt = bounded_json(directory / "final.json", 16 * 1024 * 1024)
        if receipt.get("schema") != 1 or receipt.get("signer") != replica:
            raise ValueError("final receipt belongs to another signer/schema")
        body = receipt.get("body", {})
        expected = {"schema": 1, "profile": PROFILE, "run_id": config["run_id"], "configuration_sha256": config_hash,
                    "id": replica, "epoch_us": epoch, "committee_sha256": sha256(public_directory / "committee.json")}
        if any(body.get(key) != value for key, value in expected.items()):
            raise ValueError("signed receipt run/configuration/epoch differs")
        if body.get("failure") is not None or body.get("status", "completed") != "completed":
            raise ValueError("native replica reported a failure")
        executor = validate_executor_lifecycle(body, required=require_executor,
                    expected_limits={key: config.get("limits", {}).get(key, default) for key, default in EXECUTOR_LIMITS.items()})
        freeze = uint(body.get("freeze_us"), "freeze timestamp")
        if freeze < epoch or (host_epochs is None and freeze > clock_us()):
            raise ValueError("invalid receipt freeze timestamp")
        deadline = epoch + (config["measurement_duration_ms"] + config["drain_ms"]) * 1000
        if body.get("deadline_us") != deadline or freeze < deadline:
            raise ValueError("signed observation endpoint differs from the configured deadline")
        files = body.get("files")
        expected_files = {"workload-manifest.json", "effective-profile.json", "requests.jsonl", "output.jsonl"}
        if config.get('latency_trace') is not None:
            expected_files.add('latency-trace.json')
        if not isinstance(files, list) or len(files) != len(expected_files):
            raise ValueError("signed receipt must bind finite workload/output and effective-profile files")
        descriptors = {item.get("name"): item for item in files}
        if set(descriptors) != expected_files:
            raise ValueError("signed evidence file set differs")
        for name, entry in descriptors.items():
            path = safe_file(directory, name)
            if sha256(path) != hex_hash(entry.get("sha256")) or path.stat().st_size > MAX_FILE:
                raise ValueError("signed journal bytes changed before reduction")
        profiles[replica] = validate_effective_profile(bounded_json(directory / "effective-profile.json"), config,
                                                     expected["committee_sha256"], sha256(public_directory / "genesis-ledger.bcs"))
        counts, latency = validate_requests(directory / "requests.jsonl", config, replica, epoch, deadline)
        if any(body.get("counts", {}).get(key) != value for key, value in counts.items()):
            raise ValueError("signed finite counts differ from authenticated request rows")
        prefixes[replica], round_maps[replica], first, materialized_batches[replica] = validate_output(directory / "output.jsonl", epoch, deadline, committee, replica)
        first_outputs[replica] = first
        for row in journal(directory / "requests.jsonl"):
            actual = first.get((replica, row["sequence"]))
            observed = row.get("first_materialized_us")
            if observed is not None and actual != (row["request_id"], observed, row["first_materialized_event"], True):
                raise ValueError("origin completion differs from actual first native append")
            if actual is not None:
                eligible = row.get("admission_event") is not None and row["admission_event"] < actual[2]
                if actual[3] != eligible or (actual[3] and observed is None):
                    raise ValueError("own credit differs from admission at the first output event")
            if row.get("admitted_us") is not None:
                admissions[(replica, row["sequence"])] = (row["request_id"], row["admitted_us"], observed is not None)
        if descriptors["requests.jsonl"].get("rows") != counts["planned"] or descriptors["output.jsonl"].get("rows") != len(prefixes[replica]):
            raise ValueError("signed journal row counts differ")
        for name, entry in descriptors.items():
            if sha256(safe_file(directory, name)) != entry["sha256"]:
                raise ValueError("signed journal bytes changed during reduction")
        replicas[str(replica)] = {"counts": counts, "freeze_us": freeze, "transport": body.get("transport"),
                                  "executor_lifecycle": executor,
                                  "traffic_scope": "actual shared transport counters sampled before shutdown; shutdown writes excluded",
                                  "effective_profile_sha256": descriptors["effective-profile.json"]["sha256"],
                                  "receipt": file_record(directory / "final.json")}
        materializer[str(replica)] = body.get("materializer")
        fault_snapshots[replica] = body.get("payload_fault")
        all_latency.extend(latency)
    agreement = compare_prefixes(prefixes)
    if len(set(profiles.values())) != 1:
        raise ValueError("correct replicas used different effective native/service policies")
    total = {key: sum(replica["counts"][key] for replica in replicas.values()) for key in next(iter(replicas.values()))["counts"]}
    all_correct_latencies = []
    all_correct_members = 0
    for identity, (request, admitted, own_completed) in admissions.items():
        observations = [first_outputs[replica].get(identity) for replica in correct]
        if own_completed and all(value is not None and value[0] == request
                                 and (host_epochs is not None or value[1] >= admitted) for value in observations):
            all_correct_members += 1
            if host_epochs is None:
                all_correct_latencies.append(max(value[1] for value in observations) - admitted)
    all_correct = {"admitted": len(admissions), "completed": all_correct_members,
                   "unfinished": len(admissions) - all_correct_members,
                   "clock": "unavailable across hosts" if host_epochs is not None else "same-host CLOCK_MONOTONIC microseconds across independent processes",
                   "endpoint": "origin admission to the latest first actual append across every correct replica",
                   "mean_us": sum(all_correct_latencies) / len(all_correct_latencies) if all_correct_latencies else None,
                   "scope": "final membership only; no cross-host clock subtraction" if host_epochs is not None else "secondary local-host finite cohort; cross-host clock subtraction is unsupported"}
    if case in ("healthy", "materializer-delay", "silent-first-leader", "missing-payload-recovery") and total["completed"] != total["planned"]:
        raise ValueError("local completion gate left planned honest requests unfinished/rejected/unoffered")
    if case in ("healthy", "materializer-delay", "silent-first-leader", "missing-payload-recovery") and all_correct["unfinished"]:
        raise ValueError("all-correct finite cohort has an admitted request missing or ineligible at a correct replica")
    if case == "unfinished" and not total["unfinished"]:
        raise ValueError("unfinished fixture did not leave an admitted request pending")
    if case != "unfinished" and any(not rounds or max(rounds) < 4 for rounds in round_maps.values()):
        raise ValueError("correct replicas did not materialize native output through round4")
    if case == "silent-first-leader":
        for rounds in round_maps.values():
            if any(rounds.get(round_number) != leader for round_number, leader in ((2, 2), (3, 3), (4, 0))):
                raise ValueError("silent-leader fixture lacks three subsequent native honest anchors")
    if case == "materializer-delay":
        for value in materializer.values():
            if not isinstance(value, dict) or not value.get("delay_started_count") or not value.get("delay_finished_count"):
                raise ValueError("application-delay fixture lacks a signed exercised-delay witness")
            started = uint(value["delay_started_count"], "started delays")
            finished = uint(value["delay_finished_count"], "finished delays")
            if (finished > started or not epoch <= uint(value.get("first_delay_start_us"), "delay start")
                    <= uint(value.get("first_delay_finish_us"), "delay finish")
                    or value["first_delay_finish_us"] - value["first_delay_start_us"] < config["materialization_delay_ms"] * 1000):
                raise ValueError("application-delay witness did not exercise the configured hold")
    recovery = None
    if case == "missing-payload-recovery":
        target = config["payload_fault"]["node"]
        if host_epochs is not None:
            epoch = host_epochs[target]
        if any(snapshot is not None for replica, snapshot in fault_snapshots.items() if replica != target):
            raise ValueError("payload omission applied at an unconfigured replica")
        recovery = validate_payload_recovery(fault_snapshots[target], config, committee, epoch,
                                            epoch + (config["measurement_duration_ms"] + config["drain_ms"]) * 1000,
                                            materialized_batches[target], admissions)
    elif any(value is not None for value in fault_snapshots.values()):
        raise ValueError("native payload omission was enabled outside its fixture")
    return {"agreement": agreement, "replicas": replicas, "totals": total, "all_correct_completion": all_correct,
            "payload_recovery": recovery,
            "round_authors": {str(replica): rounds for replica, rounds in round_maps.items()},
            "materializer": materializer,
            "latency": {"clock": "origin-local CLOCK_MONOTONIC" if host_epochs is not None else "same-host CLOCK_MONOTONIC", "endpoint": "bounded ingress admission to actual first application append",
                        "count": len(all_latency), "mean_us": sum(all_latency) / len(all_latency) if all_latency else None,
                        "population": "completed own-origin admitted honest requests; unfinished remain censored"}}


def make_config(output, case, *, counts=None, useful_bytes=128, interval_us=1000,
                start_delay_ms=100, duration_ms=2000, drain_ms=2000, materialization_delay_ms=0,
                drop_initial_batch_messages=3):
    output = Path(output).resolve()
    if counts is None:
        counts = [0] * NODES if case == "empty" else [16] * NODES
        if case == "silent-first-leader":
            counts[1] = 0
        if case == "missing-payload-recovery":
            counts[0] = 0
    config = {"schema": 1, "epoch": 1, "run_id": secrets.token_hex(32),
              "key_directory": str(output / "private-keys"), "addresses": unused_addresses(NODES),
              "output_directory": str(output / "replicas"), "arm_path": str(output / "arm.json"),
              "delta_ms": 100, "measurement_duration_ms": duration_ms, "drain_ms": drain_ms,
              "finite_workload": {"counts": counts, "useful_bytes": useful_bytes, "interval_us": interval_us,
                                  "start_delay_ms": start_delay_ms},
              "limits": dict(DEFAULT_LIMITS, **EXECUTOR_LIMITS), "materialization_delay_ms": materialization_delay_ms,
              "payload_fault": {"node": 0, "drop_initial_batch_messages": drop_initial_batch_messages} if case == "missing-payload-recovery" else None}
    validate_config(config, case)
    return config


def execute(binary, stamp_path, output, case, *, counts=None, useful_bytes=128, interval_us=1000,
            start_delay_ms=100, duration_ms=2000, drain_ms=2000, materialization_delay_ms=0,
            drop_initial_batch_messages=3, wall_seconds=120, rss_bytes=8 * 1024**3, disk_bytes=4 * 1024**3):
    if not 1 <= wall_seconds <= 120 or not 1 <= rss_bytes <= 16 * 1024**3 or not 1 <= disk_bytes <= 8 * 1024**3:
        raise ValueError("local fixture resource guard exceeds bounded acceptance envelope")
    output = Path(output).resolve()
    config = make_config(output, case, counts=counts, useful_bytes=useful_bytes, interval_us=interval_us,
                         start_delay_ms=start_delay_ms, duration_ms=duration_ms, drain_ms=drain_ms,
                         materialization_delay_ms=materialization_delay_ms, drop_initial_batch_messages=drop_initial_batch_messages)
    correct = validate_config(config, case)
    output.mkdir(parents=True, exist_ok=False)
    started, deadline = time.monotonic(), time.monotonic() + wall_seconds
    children, pause = [], None
    record = {"schema": 1, "protocol": "raptr", "profile": PROFILE, "case": case, "status": "running",
              "comparison_eligible": False, "acceptance_scope": "four independent localhost processes, finite functional fixture",
              "added_delta_ms": 0, "configured_Delta_ms": 100, "correct_replicas": correct,
              "run_id": config["run_id"], "cleanup": [], "started_unix_ns": time.time_ns(),
              "resource_guard": {"rss_bytes": rss_bytes, "disk_bytes": disk_bytes, "wall_seconds": wall_seconds,
                                 "scope": "sampled owned-process aggregate RSS/disk and bounded wall deadline; not kernel-enforced quotas"}}
    try:
        stamp, record["artifact"] = archive_build(binary, stamp_path, output / "artifact")
        executable = Path(record["artifact"]["executable"])
        controllers = {name: sha256(ROOT / name) for name in CONTROLLER_FILES}
        for name, expected in controllers.items():
            copy_verified(ROOT / name, output / "controller" / name, expected)
        record["controller_sources"] = controllers
        config_path = output / "config.json"
        atomic_json(config_path, config)
        config_hash = sha256(config_path)
        record["configuration_sha256"] = config_hash
        key_result = run_command(executable, ["--protocol", "raptr", "--keygen", config["key_directory"],
                                              "--nodes", str(NODES)], output, "keygen", deadline)
        if key_result.get("schema") != 1 or key_result.get("nodes") != NODES or key_result.get("profile") != PROFILE:
            raise ValueError("keygen returned a different native profile/membership")
        keys = Path(config["key_directory"])
        keys.chmod(0o700)
        for replica in range(NODES):
            key = safe_file(keys, f"key-{replica}.json")
            if key.stat().st_mode & 0o077:
                raise ValueError("generated private key permissions are too broad")
        for name in ("committee.json", "genesis-ledger.bcs"):
            source = safe_file(keys, name)
            copy_verified(source, output / "public" / name, sha256(source))
        Path(config["output_directory"]).mkdir()
        for replica in range(NODES):
            children.append(Child(executable, config_path, replica, output))
        ready = wait_ready(children, config, config_hash, min(deadline, time.monotonic() + 30), output)
        if case == "silent-first-leader":
            pause = children[1].pause()
            record["pause_observation"] = pause
        armed = arm(config, config_hash, ready)
        record["arm"] = armed
        record["completion"] = await_completion(children, correct, deadline - 5, output,
                                                  rss_limit=rss_bytes, disk_limit=disk_bytes)
        if pause is not None:
            pause["observation_ended_us"] = record["completion"]["observed_us"]
            children[1].resume(pause)
        bound_evidence = evidence_snapshot(config, correct)
        record["offline_verification"] = verify_archive(executable, config_path, config, correct, output, deadline)
        record["validation"] = validate_results(config, correct, output, config_hash, armed["epoch_us"], case,
                                               require_executor="delugi" in record["artifact"].get("protocols", []))
        if evidence_snapshot(config, correct) != bound_evidence or sha256(config_path) != config_hash:
            raise ValueError("authenticated evidence changed across verification/reduction")
        record["authenticated_files"] = bound_evidence
        validate_build(binary, stamp)
        if any(sha256(ROOT / name) != expected for name, expected in controllers.items()) or sha256(executable) != stamp["binary"]["sha256"]:
            raise ValueError("controller/source/executable drifted during the fixture")
        if time.monotonic() >= deadline:
            raise TimeoutError("verification exceeded the whole-run deadline")
        record["status"] = "completed"
    except BaseException as error:
        record.update(status="failed", error=f"{type(error).__name__}: {error}")
    finally:
        for child in reversed(children):
            try:
                result = child.finish()
            except BaseException as error:
                result = {"id": child.id, "cleanup": {"status": "failed", "error": f"{type(error).__name__}: {error}"}}
            record["cleanup"].append(result)
            if result.get("cleanup", {}).get("status") != "completed" or result["cleanup"].get("remaining") != []:
                record["status"] = "failed"
                record.setdefault("error", "owned-process cleanup could not be confirmed")
        record["elapsed_seconds"] = time.monotonic() - started
        record["finished_unix_ns"] = time.time_ns()
        atomic_json(output / "manifest.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, default="healthy")
    parser.add_argument("--counts", type=lambda value: [int(item) for item in value.split(",")])
    parser.add_argument("--useful-bytes", type=int, default=128)
    parser.add_argument("--interval-us", type=int, default=1000)
    parser.add_argument("--start-delay-ms", type=int, default=100)
    parser.add_argument("--duration-ms", type=int, default=2000)
    parser.add_argument("--drain-ms", type=int, default=2000)
    parser.add_argument("--materialization-delay-ms", type=int, default=0)
    parser.add_argument("--drop-initial-batch-messages", type=int, default=3)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    options = {name: getattr(args, name) for name in ("counts", "useful_bytes", "interval_us", "start_delay_ms", "duration_ms", "drain_ms", "materialization_delay_ms", "drop_initial_batch_messages")}
    if args.plan_only:
        stamp = bounded_json(args.build_receipt, 16 * 1024 * 1024)
        result = {"status": "planned_not_executed", "artifact": validate_build(args.binary, stamp),
                  "config": make_config(args.output, args.case, **options), "comparison_eligible": False}
    else:
        result = execute(args.binary, args.build_receipt, args.output, args.case, **options)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] in ("completed", "planned_not_executed") else 1


if __name__ == "__main__":
    raise SystemExit(main())

