#!/usr/bin/env python3
"""Prepare exact artifacts and existing hosts; remote actions require --execute.

Loom-style inventory/install/build/upload/download/cleanup, with immutable source
bundles and nonce-owned directories. No cloud API or arbitrary shell command is
available here. Published native artifacts run through the separate fixed
remote_native.py / native_campaign.py placement entry points.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = ("delugi", "mysticeti", "autobahn", "autobahn-blips", "shoal", "simpleit-mempool", "simpleit-dispersed")
MAX_FILES, MAX_BYTES, MAX_FILE = 100000, 4 * 1024**3, 1024**3
PACKAGES = ["build-essential", "clang", "libclang-dev", "llvm", "lld", "cmake", "pkg-config",
            "libssl-dev", "libudev-dev", "libdw-dev", "curl", "ca-certificates", "git", "unzip", "python3", "time"]
CONTROLLER_COMMON = ("scripts/deployment_prepare.py", "scripts/remote_deployment.py", "scripts/remote_worker.py",
                     "scripts/linux_netem.py", "scripts/run_network.py", "scripts/run_sustained.py",
                     "scripts/network_delay.py", "scripts/timing_calibration.py",
                     "scripts/spec_provenance.py", "scripts/cohort_metrics.py", "scripts/cohort_store.py", "scripts/observer_receipts.py",
                     "scripts/shared_core_conformance.py",
                     "scripts/compact_campaign.py", "scripts/evaluation_parameters.py",
                     "provenance/spec-2026-10-19.json", "provenance/baselines.json")
CONTROLLER_NATIVE = ("scripts/baselines/native_artifacts.py", "scripts/baselines/native_faults.py",
                     "scripts/baselines/native_receipts.py", "scripts/baselines/mysticeti_wal.py",
                     "scripts/baselines/mysticeti_receipts.py", "scripts/baselines/shoal_receipts.py")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def relative(name):
    path = PurePosixPath(name)
    if not path.parts or len(name) > 4096 or path.is_absolute() or ".." in path.parts or str(path) != name or "\\" in name:
        raise ValueError("noncanonical relative archive path")
    return path


def recipe(protocol, jobs=1, toolchain=None):
    if protocol not in PROTOCOLS or type(jobs) is not int or not 1 <= jobs <= 8:
        raise ValueError("unknown protocol or build job limit")
    fixed = {"delugi": "1.92.0", "mysticeti": "1.78.0", "autobahn": "1.92.0",
             "autobahn-blips": "1.92.0", "shoal": "1.75.0",
             "simpleit-mempool":"1.92.0", "simpleit-dispersed":"1.92.0"}
    toolchain = toolchain or fixed[protocol]
    if not re.fullmatch(r"\d+\.\d+\.\d+", toolchain) or (protocol != "delugi" and toolchain != fixed[protocol]):
        raise ValueError("exact reviewed Rust version required")
    command = ["cargo", "+" + toolchain, "build", "--release", "--locked", "--jobs", str(jobs)]
    if protocol == "delugi":
        commands, binaries = [command + ["--bin", "delugi-replica"]], ["delugi-replica"]
    elif protocol == "mysticeti":
        commands, binaries = [command + ["-p", "mysticeti"]], ["mysticeti"]
    elif protocol.startswith("autobahn"):
        commands, binaries = [command + ["-p", "node", "--features", "benchmark"]], ["node", "benchmark_client"]
    elif protocol.startswith('simpleit'):
        commands, binaries = [command + ['-p','node','--features','benchmark']], ['node']
    else:
        commands = [command + ["-p", "aptos-node", "--features", "consensus-only-perf-test"],
                    command + ["-p", "aptos-genesis", "--bin", "shoal-fixture"]]
        binaries = ["aptos-node", "shoal-fixture"]
    selected = {"protocol": protocol, "toolchain": toolchain, "jobs": jobs, "commands": commands,
            "binaries": binaries, "release_debug": "0" if protocol in ("shoal", "mysticeti") or protocol.startswith('simpleit') else None,
            "packages": PACKAGES, "native_remote_runner_supported": protocol == "delugi"}
    if protocol.startswith('autobahn'):
        # Upstream RocksDB6.20 uses bindgen0.59, which rejects the anonymous-enum
        # names emitted by Clang16+. Keep native sources/lock unchanged and pin
        # the binding generator's compiler separately from the Rust toolchain.
        # Its old C++ headers also rely on transitive includes removed in GCC13.
        selected['packages'] = PACKAGES + ['libclang-14-dev', 'g++-11']
        selected['environment'] = {'LIBCLANG_PATH': '/usr/lib/llvm-14/lib',
                                   'CC': 'gcc-11', 'CXX': 'g++-11'}
    if protocol == "shoal":
        # Native framework generation invokes rustfmt while rewriting tracked
        # SDK sources. The minimal Rust profile does not install this component.
        selected["toolchain_components"] = ["rustfmt"]
    return selected


def install_recipe_components(plan, rustup, root, env, commands):
    for component in plan.get("toolchain_components", []):
        run_logged([rustup, "component", "add", "--toolchain", plan["toolchain"], component],
                   root, env, root / ("logs/component-%s.log" % component), commands)
        run_logged([component, "+" + plan["toolchain"], "--version"],
                   root, env, root / ("logs/component-%s-version.log" % component), commands)


def validate_receipt(receipt, selected_recipe, source_hash):
    if (not isinstance(selected_recipe, dict) or selected_recipe !=
            recipe(selected_recipe.get("protocol"), selected_recipe.get("jobs"), selected_recipe.get("toolchain"))):
        raise ValueError("artifact recipe differs from fixed reviewed commands")
    protocol = selected_recipe["protocol"]
    if (receipt.get("protocol") != protocol or receipt.get("recipe") != selected_recipe
            or receipt.get("source_bundle_sha256") != source_hash
            or receipt.get("native_remote_runner_supported") != (protocol == "delugi")
            or [row.get("name") for row in receipt.get("binaries", [])] != selected_recipe["binaries"]):
        raise ValueError("artifact receipt differs from selected protocol, recipe, source or binary names")
    for row in receipt["binaries"]:
        if not re.fullmatch("[0-9a-f]{64}", row.get("sha256", "")) or type(row.get("bytes")) is not int or row["bytes"] <= 0:
            raise ValueError("invalid binary identity in receipt")


def validate_stamp(stamp, output, receipt):
    if (stamp.get("binary_sha256") != output["sha256"]
            or stamp.get("source_bundle_sha256") != receipt["source_bundle_sha256"]
            or stamp.get("recipe") != receipt["recipe"]
            or stamp.get("provenance", {}).get("protocol") != receipt["protocol"]
            or not stamp.get("inputs", {}).get("sources")):
        raise ValueError("artifact build stamp differs from receipt binary/source/recipe")


def archived_manifest(path):
    with tarfile.open(path, "r:") as archive:
        members, total = {}, 0
        for member in archive:
            relative(member.name)
            if (len(members) >= MAX_FILES + 1 or member.name in members
                    or not (member.isfile() or member.issym()) or member.size > MAX_FILE):
                raise ValueError("archive member count, type, size or duplicate-path violation")
            members[member.name] = member
            total += member.size
            if total > MAX_BYTES + 32 * 1024**2:
                raise ValueError("archive exceeds complete resource envelope")
        header = members["manifest.json"]
        if not header.isfile() or header.size > 32 * 1024**2:
            raise ValueError("invalid archive manifest")
        raw = archive.extractfile(header).read()
        manifest = json.loads(raw)
        selected = manifest.get("recipe") if manifest.get("kind") == "delugi-source-bundle" else manifest.get("receipt", {}).get("recipe")
        if not selected or selected != recipe(selected["protocol"], selected["jobs"], selected["toolchain"]):
            raise ValueError("archive recipe differs from fixed reviewed commands")
        if manifest.get("kind") == "delugi-source-bundle":
            if manifest.get("provenance", {}).get("protocol") != selected["protocol"]:
                raise ValueError("source provenance protocol differs from recipe")
        elif manifest.get("kind") == "delugi-built-artifacts":
            receipt = manifest["receipt"]
            validate_receipt(receipt, selected, receipt["source_bundle_sha256"])
            for output in receipt["binaries"]:
                name = "artifacts/" + output["name"]
                if manifest["files"][name]["sha256"] != output["sha256"] or manifest["files"][name]["bytes"] != output["bytes"]:
                    raise ValueError("artifact archive inventory differs from receipt")
                sidecar = members[name + ".build.json"]
                if not sidecar.isfile() or sidecar.size > 32 * 1024**2:
                    raise ValueError("invalid archived build stamp")
                validate_stamp(json.load(archive.extractfile(sidecar)), output, receipt)
        else:
            raise ValueError("unsupported archive kind")
        return manifest, hashlib.sha256(raw).hexdigest()


def source_selection(root, protocol):
    root = Path(root)
    if protocol == "delugi":
        source = root
        paths = [Path("Cargo.toml"), Path("Cargo.lock")] + sorted(p.relative_to(root) for p in (root / "src").rglob("*.rs"))
        provenance = {"protocol": protocol, "selection": "exact current Rust sources"}
    else:
        pins = json.loads((root / "provenance/baselines.json").read_text())["baselines"]
        pin = dict(pins["autobahn" if protocol == "autobahn-blips" else protocol])
        if protocol == "autobahn-blips":
            pin.update(pin["disruption_artifact"])
        source = root / pin["checkout"]
        commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        if commit != pin["commit"]:
            raise ValueError("native checkout differs from reviewed exact commit")
        patch = (root / pin["instrumentation_patch"]).read_bytes()
        if protocol.startswith('simpleit'):
            from baselines import simpleit
            identity=simpleit.source_identity(protocol)
            if identity['patch_sha256']!=hashlib.sha256(patch).hexdigest():raise ValueError('Simple-IT patch differs')
        else:
            diff = subprocess.check_output(["git", "-C", str(source), "diff", "HEAD"])
            if diff != patch:
                raise ValueError("native checkout differs from recorded instrumentation patch")
        if pin.get("dependency_lock") and (source / "Cargo.lock").read_bytes() != (root / pin["dependency_lock"]).read_bytes():
            raise ValueError("native dependency lock differs from reviewed lock")
        paths = [Path(p.decode()) for p in subprocess.check_output(["git", "-C", str(source), "ls-files", "-z"]).split(b"\0") if p]
        if protocol.startswith('simpleit'):paths += list(map(Path,simpleit.NEW_FILES))
        if Path("Cargo.lock") not in paths:
            paths.append(Path("Cargo.lock"))
        provenance = {"protocol": protocol, "repository": pin["repository"], "commit": commit,
                      "patch_sha256": hashlib.sha256(patch).hexdigest(), "pin": pin}
    if not (source / "Cargo.lock").is_file():
        raise ValueError("bundles require a resolved, immutable Cargo.lock")
    return source, sorted(set(paths)), provenance


def file_entry(path, base):
    path, base = Path(path), Path(base).resolve()
    if path.is_symlink():
        target = path.resolve(strict=True)
        if base not in target.parents or not target.is_file():
            raise ValueError("source symlink must resolve to a file inside selected checkout")
        link = os.readlink(path)
        if PurePosixPath(link).is_absolute():
            raise ValueError("source symlink must be relative")
        return {"type": "symlink", "target": link, "sha256": hashlib.sha256(link.encode()).hexdigest(), "bytes": len(link.encode()), "mode": 0o777}
    if not path.is_file() or path.stat().st_size > MAX_FILE:
        raise ValueError("source entry is missing, special, a submodule, or exceeds per-file bound")
    return {"type": "file", "sha256": sha(path), "bytes": path.stat().st_size,
            "mode": 0o755 if path.stat().st_mode & 0o111 else 0o644}


def archive_files(path, entries):
    """Deterministic tar: normalized modes/owners/times, no implicit directories."""
    with tarfile.open(path, "w") as archive:
        for name, (source, entry) in sorted(entries.items()):
            relative(name)
            item = tarfile.TarInfo(name)
            item.mode, item.mtime = entry["mode"], 0
            if entry["type"] == "symlink":
                item.type, item.linkname = tarfile.SYMTYPE, entry["target"]
                archive.addfile(item)
            else:
                item.size = entry["bytes"]
                with Path(source).open("rb") as stream:
                    archive.addfile(item, stream)


def bundle(root, protocol, output, jobs=1, toolchain=None, assets=None):
    source, paths, provenance = source_selection(root, protocol)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    entries = {"source/" + p.as_posix(): (source / p, file_entry(source / p, source)) for p in paths}
    # Explicit controller evidence only: never sweep arbitrary untracked files.
    # These files are archived for reproducibility, not executed by the worker.
    controller = list(CONTROLLER_COMMON)
    if protocol != "delugi":
        selected = "simpleit" if protocol.startswith('simpleit') else "autobahn" if protocol == "autobahn-blips" else protocol
        controller += list(CONTROLLER_NATIVE) + ["scripts/baselines/" + selected + ".py"]
        if selected in ("autobahn", "shoal"):
            controller.append("scripts/baselines/" + selected + "_cohort.py")
    controller_hashes = {}
    for name in controller:
        path = ROOT / name
        entry = file_entry(path, ROOT)
        entries["controller/" + name] = (path, entry)
        controller_hashes[name] = entry["sha256"]
    for field in ("instrumentation_patch", "dependency_lock"):
        name = provenance.get("pin", {}).get(field)
        if name:
            relative(name)
            path = Path(root) / name
            entry = file_entry(path, root)
            entries["controller/" + name] = (path, entry)
            controller_hashes[name] = entry["sha256"]
    for name, asset in (assets or {}).items():
        if name not in ("rustup-init", "protoc.zip"):
            raise ValueError("unknown toolchain bootstrap asset")
        entries["assets/" + name] = (Path(asset), file_entry(Path(asset), Path(asset).parent))
    if len(entries) > MAX_FILES or sum(e["bytes"] for _, e in entries.values()) > MAX_BYTES:
        raise ValueError("source bundle exceeds resource envelope")
    manifest = {"schema": 1, "kind": "delugi-source-bundle", "provenance": provenance,
                "recipe": recipe(protocol, jobs, toolchain), "files": {k: v for k, (_, v) in entries.items()},
                "cargo_lock_sha256": sha(source / "Cargo.lock"),
                "controller_sources": controller_hashes,
                "dependency_policy": "exact Cargo.lock; locked downloads permitted at build time; OS package versions recorded"}
    json_file(output / "manifest.json", manifest)
    entries["manifest.json"] = (output / "manifest.json", file_entry(output / "manifest.json", output))
    archive_files(output / "bundle.tar", entries)
    result = {"schema": 1, "bundle_sha256": sha(output / "bundle.tar"), "manifest_sha256": sha(output / "manifest.json"),
              "protocol": protocol, "files": len(manifest["files"]), "source_bytes": sum(v["bytes"] for v in manifest["files"].values())}
    json_file(output / "bundle.json", result)
    return result


def unpack_verified(archive_path, destination, expected_hash):
    """Verify complete inventory before writing; never use tar.extractall."""
    if sha(archive_path) != expected_hash:
        raise ValueError("archive hash mismatch")
    destination = Path(destination)
    with tarfile.open(archive_path, "r:") as archive:
        members, names = [], set()
        for member in archive:
            if len(members) >= MAX_FILES + 1 or member.name in names:
                raise ValueError("archive count or duplicate-path violation")
            members.append(member)
            names.add(member.name)
            relative(member.name)
            if not (member.isfile() or member.issym()) or member.size > MAX_FILE:
                raise ValueError("unsafe archive entry")
        header = archive.getmember("manifest.json")
        if not header.isfile() or header.size > 32 * 1024**2:
            raise ValueError("invalid manifest size/type")
        manifest = json.load(archive.extractfile(header))
        files = manifest["files"]
        if (set(files) != {m.name for m in members} - {"manifest.json"}
                or any(type(v.get("bytes")) is not int or not 0 <= v["bytes"] <= MAX_FILE
                       or v.get("type") not in ("file", "symlink")
                       or v.get("mode") not in (0o644, 0o755, 0o777)
                       or not re.fullmatch("[0-9a-f]{64}", v.get("sha256", "")) for v in files.values())
                or sum(v["bytes"] for v in files.values()) > MAX_BYTES):
            raise ValueError("archive does not match bounded manifest inventory")
        for member in members:
            if member.name == "manifest.json":
                continue
            entry = files[member.name]
            if entry["type"] == "symlink":
                if not member.issym() or member.linkname != entry["target"] or hashlib.sha256(member.linkname.encode()).hexdigest() != entry["sha256"]:
                    raise ValueError("symlink identity mismatch")
                target = (destination / member.name).parent / member.linkname
                if not str(target.resolve()).startswith(str((destination / "source").resolve()) + os.sep):
                    raise ValueError("symlink escapes source directory")
            elif not member.isfile() or member.size != entry["bytes"]:
                raise ValueError("file shape mismatch")
            else:
                digest = hashlib.sha256()
                stream = archive.extractfile(member)
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                if digest.hexdigest() != entry["sha256"]:
                    raise ValueError("file digest mismatch")
        links = {name for name, entry in files.items() if entry["type"] == "symlink"}
        if any(any(parent.as_posix() in links for parent in PurePosixPath(name).parents) for name in files):
            raise ValueError("archive entry traverses a symlink")
        for member in members:
            if member.issym():
                continue
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                shutil.copyfileobj(archive.extractfile(member), stream, 1024 * 1024)
            target.chmod(files.get(member.name, {}).get("mode", 0o644))
        for member in members:
            if member.issym():
                target = destination / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.symlink_to(member.linkname)
    return manifest


def hosts_from_loom(settings_path, saved_path, selected, known_hosts, *, user="root", cpus=(0, 1, 2, 3), memory_bytes=16 * 1024**3, network_interface=None, python_executable=None):
    """Read saved inventory/lease only. The access-key path is never opened."""
    settings_path = Path(settings_path).resolve()
    settings, saved = json.loads(settings_path.read_text()), json.loads(Path(saved_path).read_text())
    identity = Path(settings["key"]["path"]).expanduser()
    if not identity.is_absolute():
        identity = settings_path.parent / identity
    records = {}
    if "regions" in saved:
        for region in saved["regions"]:
            for row in region.get("instances", []):
                records[row["id"]] = (region["region"], row)
    else:
        for row in saved.get("instances", []):
            tags = {t["TagKey"]: t["TagValue"] for t in row.get("Tags", {}).get("Tag", [])}
            if tags.get("DelugiRun") != saved.get("run_id"):
                raise ValueError("saved lease instance ownership tag mismatch")
            records[row["InstanceId"]] = (saved["plan"]["region"], {
                "id": row["InstanceId"], "status": row["Status"], "public_ips": row.get("PublicIpAddress", {}).get("IpAddress", []),
                "private_ips": row.get("VpcAttributes", {}).get("PrivateIpAddress", {}).get("IpAddress", []),
                "cpu": row["Cpu"], "memory_mib": row["Memory"]})
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("explicit unique instance IDs required in replica order")
    port, hosts = settings["ports"]["consensus"], []
    for replica, instance in enumerate(selected):
        region, row = records[instance]
        if row["status"] != "Running" or region not in settings["instances"]["regions"]:
            raise ValueError("selected saved instance is not running in Loom's configured regions")
        if len(row["public_ips"]) != 1 or len(row["private_ips"]) != 1:
            raise ValueError("exactly one public SSH and private protocol address required")
        public, private = map(ipaddress.IPv4Address, (row["public_ips"][0], row["private_ips"][0]))
        if not cpus or any(type(cpu) is not int or cpu < 0 for cpu in cpus) or max(cpus) >= row["cpu"] or memory_bytes != row["memory_mib"] * 1024**2:
            raise ValueError("dedicated-host memory must name saved whole-machine RAM; CPU affinity must fit")
        hosts.append({"replica": replica, "instance_id": instance, "region": region, "ssh": user + "@" + str(public),
            "identity_file": str(identity.resolve()), "known_hosts_file": str(Path(known_hosts).resolve()),
            "advertised": str(private) + ":" + str(port), "control_port": port + 1,
            "budget": {"enforcement": "dedicated_host", "cpus": list(cpus), "memory_bytes": memory_bytes, "swap_bytes": 0}})
        if network_interface:
            hosts[-1]["network_interface"] = network_interface
        if python_executable:
            if not Path(python_executable).is_absolute() or ".." in Path(python_executable).parts:
                raise ValueError("selected Python executable must have an absolute canonical path")
            hosts[-1]["python_executable"] = python_executable
    result = {"schema": 1, "kind": "deployment-preparation-hosts", "hosts": hosts,
              "selection": {"settings_sha256": sha(settings_path), "saved_inventory_sha256": sha(saved_path), "instance_ids": selected}}
    validate_hosts(result)
    return result


def validate_hosts(data):
    # Reuse the runner's SSH/address/resource validation with a temporary artifact
    # placeholder; prepared inventory intentionally has no claimed binary yet.
    from remote_deployment import validate_inventory
    copy = json.loads(json.dumps(data))
    copy.pop("protocol", None)
    copy.pop("remote_runner_supported", None)
    for host in copy["hosts"]:
        host["binary"] = {"path": "/unused/preparation-only", "sha256": "0" * 64}
    validate_inventory(copy)
    return data


def create_plan(hosts, bundle_dir=None, artifacts=None):
    validate_hosts(hosts)
    if (bundle_dir is None) == (artifacts is None):
        raise ValueError("choose exactly one source bundle or built artifact archive")
    if bundle_dir is not None:
        bundle_dir = Path(bundle_dir).resolve()
        archive = bundle_dir / "bundle.tar"
        info = json.loads((bundle_dir / "bundle.json").read_text())
        if info["bundle_sha256"] != sha(archive):
            raise ValueError("source bundle changed")
        manifest = json.loads((bundle_dir / "manifest.json").read_text())
        archived, archived_hash = archived_manifest(archive)
        if (info["manifest_sha256"] != sha(bundle_dir / "manifest.json")
                or archived_hash != info["manifest_sha256"] or archived != manifest
                or info["protocol"] != manifest["recipe"]["protocol"]):
            raise ValueError("external source metadata differs from immutable archive")
        selected_recipe, protocol, phase = manifest["recipe"], info["protocol"], "build"
    else:
        archive = Path(artifacts).resolve()
        manifest, _ = archived_manifest(archive)
        if manifest.get("kind") != "delugi-built-artifacts":
            raise ValueError("publish plan requires built artifacts")
        selected_recipe, protocol, phase = manifest["receipt"]["recipe"], manifest["receipt"]["protocol"], "publish"
    return {"schema": 1, "kind": "deployment-build-plan", "nonce": uuid.uuid4().hex,
            "hosts": hosts["hosts"], "builder_replica": 0, "archive": str(archive),
            "archive_sha256": sha(archive), "helper_sha256": sha(__file__),
            "phase": phase, "protocol": protocol, "recipe": selected_recipe,
            "source_bundle_sha256": sha(archive) if phase == "build" else manifest["receipt"]["source_bundle_sha256"],
            "execution": "requires explicit --execute; no resources created by planning"}


def owned_root(request):
    nonce = request["nonce"]
    if not re.fullmatch("[0-9a-f]{32}", nonce):
        raise ValueError("invalid ownership nonce")
    root = Path("/tmp") / ("delugi-build-" + nonce)
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid != os.getuid():
        raise ValueError("build root must be an owned real directory")
    return root


def run_logged(argv, cwd, env, output, records):
    with Path(output).open("wb") as log:
        subprocess.run(argv, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    records.append({"arguments": argv, "log": Path(output).name, "log_sha256": sha(output)})


def worker(request):
    root = owned_root(request)
    with (root / "action.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = root / "owner.json"
        if marker.exists():
            state = json.loads(marker.read_text())
            if state["nonce"] != request["nonce"] or state["archive_sha256"] != request["archive_sha256"]:
                raise ValueError("owned build identity changed")
        else:
            if request["action"] not in ("build", "publish"):
                raise ValueError("unknown owned build")
            state = {"nonce": request["nonce"], "archive_sha256": request["archive_sha256"], "phase": "prepared"}
            json_file(marker, state)
        if request["action"] == "clean":
            for name in ("target", "cargo", "rustup", "source", "assets", "protoc"):
                path = root / name
                if path.is_symlink():
                    raise ValueError("owned build component replaced by symlink")
                if path.exists():
                    shutil.rmtree(path)
            state["phase"] = "build-intermediates-cleaned; artifacts and logs retained"
            json_file(marker, state)
            return state
        if request["action"] not in ("build", "publish"):
            raise ValueError("unsupported fixed worker action")
        if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
            raise ValueError("selected build/deploy profile requires Linux x86_64")
        if state["phase"] == "complete":
            receipt = json.loads((root / "receipt.json").read_text())
            for output in receipt["binaries"]:
                if sha(output["path"]) != output["sha256"]:
                    raise ValueError("completed artifact changed")
                validate_stamp(json.loads(Path(output["path"] + ".build.json").read_text()), output, receipt)
            return receipt
        if state["phase"] != "prepared":
            raise ValueError("interrupted build retained for inspection; use a new nonce to retry")
        state["phase"] = "extracting"
        json_file(marker, state)
        manifest = unpack_verified(root / "bundle.tar", root, request["archive_sha256"])
        if request["action"] == "publish":
            if manifest.get("kind") != "delugi-built-artifacts":
                raise ValueError("publish requires a built artifact archive")
            receipt = manifest["receipt"]
            validate_receipt(receipt, recipe(receipt["protocol"], receipt["recipe"]["jobs"], receipt["recipe"]["toolchain"]), receipt["source_bundle_sha256"])
            if receipt["abi"]["machine"] != platform.machine():
                raise ValueError("artifact machine ABI mismatch")
            receipt["binaries"] = [{**item, "path": str(root / "artifacts" / item["name"])} for item in receipt["binaries"]]
            for item in receipt["binaries"]:
                if Path(item["name"]).name != item["name"] or sha(item["path"]) != item["sha256"]:
                    raise ValueError("published binary does not match receipt")
                validate_stamp(json.loads(Path(item["path"] + ".build.json").read_text()), item, receipt)
                linked = subprocess.run(["ldd", item["path"]], capture_output=True, text=True)
                if linked.returncode != 0 or "not found" in linked.stdout + linked.stderr:
                    raise ValueError("published binary dynamic-library check failed")
        else:
            if manifest.get("kind") != "delugi-source-bundle":
                raise ValueError("build requires a source bundle")
            plan = manifest["recipe"]
            if plan != recipe(plan["protocol"], plan["jobs"], plan["toolchain"]):
                raise ValueError("build recipe differs from fixed reviewed command set")
            (root / "logs").mkdir()
            commands = []
            env = os.environ.copy()
            env.update(CARGO_TARGET_DIR=str(root / "target"), CARGO_HOME=str(root / "cargo"),
                       RUSTUP_HOME=str(root / "rustup"), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS=str(plan["jobs"]))
            env.update(plan.get('environment', {}))
            if plan["release_debug"] is not None:
                env["CARGO_PROFILE_RELEASE_DEBUG"] = plan["release_debug"]
            if request.get("install_system_packages"):
                prefix = [] if os.getuid() == 0 else ["sudo", "-n"]
                run_logged(prefix + ["apt-get", "update"], root, env, root / "logs/apt-update.log", commands)
                env["DEBIAN_FRONTEND"] = "noninteractive"
                run_logged(prefix + ["apt-get", "install", "-y"] + plan['packages'], root, env, root / "logs/apt-install.log", commands)
            rustup = shutil.which("rustup")
            if rustup is None:
                installer = root / "assets/rustup-init"
                if not installer.is_file():
                    raise ValueError("rustup missing: provide a checksummed rustup-init bundle asset")
                installer.chmod(0o700)
                run_logged([str(installer), "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "none"], root, env, root / "logs/rustup-bootstrap.log", commands)
                rustup = str(root / "cargo/bin/rustup")
            env["PATH"] = str(Path(rustup).parent) + os.pathsep + env.get("PATH", "")
            run_logged([rustup, "toolchain", "install", plan["toolchain"], "--profile", "minimal"], root, env, root / "logs/toolchain.log", commands)
            install_recipe_components(plan, rustup, root, env, commands)
            if plan["protocol"] == "shoal":
                asset = root / "assets/protoc.zip"
                if not asset.is_file():
                    raise ValueError("Shoal requires the checksummed protoc21.4 Linux x86_64 archive asset")
                with zipfile.ZipFile(asset) as archive:
                    if len(archive.infolist()) > MAX_FILES or sum(entry.file_size for entry in archive.infolist()) > MAX_BYTES:
                        raise ValueError("protoc archive exceeds resource envelope")
                    for entry in archive.infolist():
                        relative(entry.filename.rstrip("/"))
                        if entry.file_size > MAX_FILE or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                            raise ValueError("unsafe protoc archive")
                        if entry.is_dir():
                            continue
                        target = root / "protoc" / entry.filename
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open("xb") as stream:
                            shutil.copyfileobj(archive.open(entry), stream)
                (root / "protoc/bin/protoc").chmod(0o700)
                env["PATH"] = str(root / "protoc/bin") + os.pathsep + env["PATH"]
                if subprocess.check_output([str(root / "protoc/bin/protoc"), "--version"], env=env, text=True).strip() != "libprotoc 3.21.4":
                    raise ValueError("unexpected protoc version")
            compiler = subprocess.check_output(["rustc", "+" + plan["toolchain"], "--version", "--verbose"], env=env, text=True).strip()
            start = time.monotonic()
            for index, command in enumerate(plan["commands"]):
                run_logged(command, root / "source", env, root / ("logs/build-%d.log" % index), commands)
            sources = {name[len("source/"):]: entry["sha256"] for name, entry in manifest["files"].items() if name.startswith("source/")}
            for name, digest in sources.items():
                path = root / "source" / name
                actual = hashlib.sha256(os.readlink(path).encode()).hexdigest() if path.is_symlink() else sha(path)
                if actual != digest:
                    raise ValueError("source changed during locked build")
            artifacts = root / "artifacts"
            artifacts.mkdir()
            outputs = []
            dynamic_libraries = {}
            for name in plan["binaries"]:
                target = artifacts / name
                shutil.copy2(root / "target/release" / name, target)
                digest = sha(target)
                stamp = {"binary_sha256": digest, "inputs": {"compiler": compiler, "sources": sources},
                         "source_bundle_sha256": request["archive_sha256"], "recipe": plan,
                         "provenance": manifest["provenance"], "cargo_lock_sha256": manifest["cargo_lock_sha256"],
                         "controller_sources": manifest.get("controller_sources", {})}
                json_file(str(target) + ".build.json", stamp)
                outputs.append({"name": name, "path": str(target), "sha256": digest, "bytes": target.stat().st_size})
                linked = subprocess.run(["ldd", str(target)], capture_output=True, text=True)
                if linked.returncode != 0 or "not found" in linked.stdout + linked.stderr:
                    raise ValueError("built binary dynamic-library check failed")
                dynamic_libraries[name] = linked.stdout
            packages = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"] + plan['packages'],
                                      capture_output=True, text=True)
            receipt = {"schema": 1, "protocol": plan["protocol"], "native_remote_runner_supported": plan["native_remote_runner_supported"],
                       "source_bundle_sha256": request["archive_sha256"], "binaries": outputs, "compiler": compiler,
                       "recipe": plan, "commands": commands, "elapsed_seconds": time.monotonic() - start,
                       "peak_child_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
                       "abi": {"system": platform.system(), "machine": platform.machine(), "libc": list(platform.libc_ver()),
                               "dynamic_libraries": dynamic_libraries},
                       "installed_packages": packages.stdout, "package_query_returncode": packages.returncode}
            export = {"artifacts/" + p.name: (p, file_entry(p, artifacts)) for p in artifacts.iterdir()}
            for p in (root / "logs").iterdir():
                export["logs/" + p.name] = (p, file_entry(p, root / "logs"))
            for name in manifest.get("controller_sources", {}):
                path = root / "controller" / name
                export["controller/" + name] = (path, file_entry(path, root / "controller"))
            json_file(root / "artifact-manifest.json", {"schema": 1, "kind": "delugi-built-artifacts", "receipt": receipt,
                       "files": {name: entry for name, (_, entry) in export.items()}})
            export["manifest.json"] = (root / "artifact-manifest.json", file_entry(root / "artifact-manifest.json", root))
            archive_files(root / "artifacts.tar", export)
            receipt["artifact_archive_sha256"] = sha(root / "artifacts.tar")
        json_file(root / "receipt.json", receipt)
        state["phase"] = "complete"
        json_file(marker, state)
        return receipt


class Connection:
    def __init__(self, host, control_path=None):
        self.host = host
        self.control_path = control_path

    def python(self):
        return self.host.get("python_executable", "python3")

    def command(self, arguments, **kwargs):
        from remote_deployment import ssh_arguments
        options = ([] if self.control_path is None else
                   ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=60',
                    '-o', 'ControlPath='+str(self.control_path)])
        kwargs.setdefault('check', True)
        return subprocess.run(ssh_arguments(self.host) + options + [self.host["ssh"], shlex.join(arguments)], **kwargs)

    def upload(self, source, remote):
        code = """import hashlib,os,shutil,sys,uuid
from pathlib import Path
p=Path(sys.argv[1]); expected=sys.argv[2]
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as s:
  for block in iter(lambda:s.read(1048576),b''): h.update(block)
 return h.hexdigest()
if p.is_symlink(): raise ValueError('upload destination is a symlink')
if p.exists():
 if digest(p)!=expected: raise ValueError('existing upload differs')
else:
 temporary=p.with_name(p.name+'.upload-'+uuid.uuid4().hex)
 try:
  with os.fdopen(os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as s: shutil.copyfileobj(sys.stdin.buffer,s,1048576)
  if digest(temporary)!=expected: raise ValueError('upload checksum mismatch')
  try: os.link(temporary,p)
  except FileExistsError:
   if p.is_symlink() or digest(p)!=expected: raise ValueError('concurrent destination differs')
 finally: temporary.unlink(missing_ok=True)
"""
        with Path(source).open("rb") as stream:
            self.command([self.python(), "-c", code, remote, sha(source)], stdin=stream,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=900)

    def prepare(self, nonce, archive_hash):
        code = """import json,os,re,sys
from pathlib import Path
n,h=sys.argv[1:]
if not re.fullmatch('[0-9a-f]{32}',n) or not re.fullmatch('[0-9a-f]{64}',h): raise ValueError('bad ownership identity')
p=Path('/tmp')/('delugi-build-'+n); marker=p/'owner.json'
if p.exists():
 if p.is_symlink() or p.stat().st_uid!=os.getuid() or not marker.is_file(): raise ValueError('unowned build directory')
 s=json.loads(marker.read_text())
 if s.get('nonce')!=n or s.get('archive_sha256')!=h: raise ValueError('changed ownership identity')
else:
 p.mkdir(mode=0o700)
 marker.write_text(json.dumps({'nonce':n,'archive_sha256':h,'phase':'prepared'}))
"""
        self.command([self.python(), "-c", code, nonce, archive_hash], capture_output=True)

    def rpc(self, nonce, request):
        return json.loads(self.command([self.python(), "/tmp/delugi-build-" + nonce + "/deployment_prepare.py", "_worker"],
            input=json.dumps(request), text=True, capture_output=True).stdout)


def execute_plan(plan, output, *, install_system_packages=False, connection_factory=Connection):
    validate_hosts({"schema": 1, "hosts": plan["hosts"]})
    if plan["helper_sha256"] != sha(__file__) or not re.fullmatch("[0-9a-f]{32}", plan["nonce"]):
        raise ValueError("helper changed since reviewed plan or invalid nonce")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    json_file(output / "plan.json", plan)
    remote = "/tmp/delugi-build-" + plan["nonce"]
    publish = plan["phase"] == "publish"
    if plan["phase"] not in ("build", "publish"):
        raise ValueError("unsupported plan phase")
    archive = Path(plan["archive"])
    expected = sha(archive)
    if expected != plan["archive_sha256"]:
        raise ValueError("planned archive changed")
    packed, _ = archived_manifest(archive)
    packed_recipe = packed["receipt"]["recipe"] if publish else packed["recipe"]
    expected_source = packed["receipt"]["source_bundle_sha256"] if publish else expected
    if (plan["recipe"] != packed_recipe or plan["protocol"] != packed_recipe["protocol"]
            or plan["source_bundle_sha256"] != expected_source):
        raise ValueError("plan differs from immutable archive protocol/recipe/source")
    hosts = plan["hosts"] if publish else [plan["hosts"][plan["builder_replica"]]]
    receipts, inventory = {}, []
    for host in hosts:
        connection = connection_factory(host)
        connection.prepare(plan["nonce"], expected)
        connection.upload(__file__, remote + "/deployment_prepare.py")
        connection.upload(archive, remote + "/bundle.tar")
        request = {"action": "publish" if publish else "build", "nonce": plan["nonce"],
                   "archive_sha256": expected, "install_system_packages": install_system_packages}
        receipt = connection.rpc(plan["nonce"], request)
        validate_receipt(receipt, plan["recipe"], plan["source_bundle_sha256"])
        if any(row["path"] != remote + "/artifacts/" + row["name"] for row in receipt["binaries"]):
            raise ValueError("receipt binary is outside this owned deployment")
        receipts[host["replica"]] = receipt
        json_file(output / ("receipt-%d.json" % host["replica"]), receipt)
        if not publish:
            with (output / "artifacts.tar").open("xb") as stream:
                connection.command(["cat", remote + "/artifacts.tar"], stdout=stream, stderr=subprocess.PIPE)
            if sha(output / "artifacts.tar") != receipt["artifact_archive_sha256"]:
                raise ValueError("downloaded artifact archive changed")
            downloaded, _ = archived_manifest(output / "artifacts.tar")
            if downloaded["receipt"] != {k: v for k, v in receipt.items() if k != "artifact_archive_sha256"}:
                raise ValueError("downloaded artifact manifest differs from build receipt")
        else:
            primary = receipt["binaries"][0]
            inventory.append({**host, "binary": {"path": primary["path"], "sha256": primary["sha256"]}})
    result = {"schema": 1, "nonce": plan["nonce"], "protocol": plan["protocol"], "receipts": receipts,
              "archive_sha256": expected, "intermediates_cleanup": "clean preserves binaries, receipts, source bundle and logs"}
    if publish:
        runnable = plan["protocol"] == "delugi"
        result["inventory"] = {"schema": 1, "hosts": inventory, "protocol": plan["protocol"],
                               "remote_runner_supported": runnable,
                               "scope": "ready for Delugi runner" if runnable else "native artifacts installed; a separate remote_native.py placement plan is required"}
        json_file(output / "inventory.json", result["inventory"])
    json_file(output / "deployment.json", result)
    return result


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "_worker":
        print(json.dumps(worker(json.load(sys.stdin))))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    make = commands.add_parser("bundle")
    make.add_argument("--protocol", choices=PROTOCOLS, required=True)
    make.add_argument("--output", type=Path, required=True)
    make.add_argument("--root", type=Path, default=ROOT)
    make.add_argument("--jobs", type=int, default=1)
    make.add_argument("--toolchain")
    make.add_argument("--rustup-init", type=Path)
    make.add_argument("--protoc-archive", type=Path)
    hosts = commands.add_parser("inventory-from-loom")
    hosts.add_argument("--settings", type=Path, required=True)
    hosts.add_argument("--saved-inventory", type=Path, required=True)
    hosts.add_argument("--instance-ids", nargs="+", required=True)
    hosts.add_argument("--known-hosts", type=Path, required=True)
    hosts.add_argument("--user", default="root")
    hosts.add_argument("--cpus", default="0,1,2,3")
    hosts.add_argument("--memory-bytes", type=int, required=True)
    hosts.add_argument("--network-interface")
    hosts.add_argument("--python-executable", help="declared preinstalled Python>=3.11 for native placement; packaged controllers require tomllib")
    hosts.add_argument("--output", type=Path, required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--hosts", type=Path, required=True)
    selection = plan.add_mutually_exclusive_group(required=True)
    selection.add_argument("--bundle", type=Path)
    selection.add_argument("--artifacts", type=Path)
    plan.add_argument("--output", type=Path, required=True)
    for name in ("build", "publish", "clean"):
        action = commands.add_parser(name)
        action.add_argument("--plan", type=Path, required=True)
        action.add_argument("--execute", action="store_true")
        action.add_argument("--output", type=Path)
        if name == "build": action.add_argument("--install-system-packages", action="store_true")
    args = parser.parse_args()
    if args.action == "bundle":
        assets = {name: path for name, path in (("rustup-init", args.rustup_init), ("protoc.zip", args.protoc_archive)) if path}
        result = bundle(args.root, args.protocol, args.output, args.jobs, args.toolchain, assets)
    elif args.action == "inventory-from-loom":
        result = hosts_from_loom(args.settings, args.saved_inventory, args.instance_ids, args.known_hosts,
            user=args.user, cpus=tuple(map(int, args.cpus.split(","))), memory_bytes=args.memory_bytes,
            network_interface=args.network_interface, python_executable=args.python_executable)
        json_file(args.output, result)
    elif args.action == "plan":
        result = create_plan(json.loads(args.hosts.read_text()), args.bundle, args.artifacts)
        json_file(args.output, result)
    else:
        plan = json.loads(args.plan.read_text())
        if args.action != "clean" and args.action != plan["phase"]:
            parser.error("command differs from planned build/publish phase")
        if not args.execute:
            result = {"status": "dry-run; no SSH or host changes", "action": args.action, "plan": plan}
        elif args.action == "clean":
            selected_hosts = plan["hosts"] if plan["phase"] == "publish" else [plan["hosts"][plan["builder_replica"]]]
            result = {"hosts": {host["replica"]: Connection(host).rpc(plan["nonce"], {"action": "clean",
                "nonce": plan["nonce"], "archive_sha256": plan["archive_sha256"]}) for host in selected_hosts}}
        else:
            if args.output is None: parser.error("execution requires a new --output directory")
            result = execute_plan(plan, args.output,
                install_system_packages=getattr(args, "install_system_packages", False))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
