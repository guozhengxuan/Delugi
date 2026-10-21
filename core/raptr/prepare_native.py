#!/usr/bin/env python3
"""Reproduce pinned native source without reading the modified baseline files."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

PIN = "a4c98047cf8aeae3571168d02fb7e343140d2948"
ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(repository):
    destination = ROOT / ".native-deps" / PIN
    native = ROOT / "native"
    if destination.exists():
        raise SystemExit("Refusing to replace existing dependency source; inspect its manifest first")
    destination.parent.mkdir(parents=True, exist_ok=True)
    archive = destination.parent / "pinned-source.tar"
    with archive.open("xb") as output:
        subprocess.run(["git", "archive", "--format=tar", PIN], cwd=repository, stdout=output, check=True)
    archive_sha = sha(archive)
    destination.mkdir()
    with tarfile.open(archive) as source:
        source.extractall(destination, filter="data")
    archive.unlink()
    if native.exists():
        print(json.dumps({"dependency_source_restored": str(destination), "source_archive_sha256": archive_sha,
                          "native_source_preserved": str(native)}))
        return
    shutil.copytree(destination / "raptr", native)
    original_manifest = (native / "Cargo.toml").read_text()
    root_manifest = (destination / "Cargo.toml").read_text()
    inherited = root_manifest[root_manifest.index("[workspace.package]"):]
    inherited = inherited[:inherited.index("[profile.")]
    inherited = re.sub(r'path\s*=\s*"([^"]+)"', lambda m: 'path = "../.native-deps/' + PIN + '/' + m[1] + '"', inherited)
    patches = root_manifest[root_manifest.index("[patch.crates-io]"):]
    manifest = original_manifest + "\n[workspace]\nresolver = \"2\"\nmembers = [\".\"]\n\n" + inherited + "\n" + patches
    manifest += "\n[profile.dev]\ndebug = 0\nincremental = false\n\n[profile.test]\ndebug = 0\nincremental = false\n"
    (native / "Cargo.toml").write_text(manifest)
    shutil.copyfile(destination / "Cargo.lock", native / "Cargo.lock")
    shutil.copyfile(destination / "LICENSE", native / "LICENSE")
    (native / ".cargo").mkdir()
    shutil.copyfile(destination / ".cargo/config.toml", native / ".cargo/config.toml")
    source_files = []
    for path in sorted(native.rglob("*")):
        if path.is_file() and path.name != "Cargo.lock":
            original = destination / "raptr" / path.relative_to(native)
            source_files.append({"path": str(path.relative_to(ROOT)), "sha256": sha(path),
                                 "original_sha256": sha(original) if original.is_file() else None,
                                 "unchanged": original.is_file() and path.read_bytes() == original.read_bytes()})
    record = {"schema": 1, "source_commit": PIN, "source_archive_sha256": archive_sha,
              "upstream_repository": subprocess.check_output(["git", "remote", "get-url", "origin"], cwd=repository, text=True).strip(),
              "dependency_source": str(destination.relative_to(ROOT)), "native_source": "native",
              "original_lock_sha256": sha(destination / "Cargo.lock"),
              "compiler": "1.78.0", "mode": "native types, conformance only until shared services/QS are wired",
              "manifest_adjustments": ["standalone workspace rooted at extracted native crate", "native workspace dependency paths point to immutable local archive", "debug info and incremental disabled"],
              "source_files": source_files}
    (ROOT / "native-source.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"native": str(native), "dependency_archive_bytes": sum(p.stat().st_size for p in destination.rglob('*') if p.is_file()), "source_manifest_sha256": sha(ROOT / "native-source.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=ROOT.parents[1] / "benchmarks/baselines/raptr")
    prepare(parser.parse_args().repository)
