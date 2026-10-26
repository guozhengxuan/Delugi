#!/usr/bin/env python3
"""Portable, source-bound common-node publication. No instance creation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tarfile

import run_raptr_shared_local as contract

FORMAT = 'delugi-common-artifact-v1'
MAX_BYTES = 2 * 1024**3
MAX_FILES = 2048


def elf_machine(path):
    with Path(path).open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x02\x01':
        raise ValueError('cloud publication requires a little-endian 64-bit Linux ELF executable')
    return {62: 'x86_64', 183: 'aarch64'}.get(struct.unpack('<H', header[18:20])[0], 'unsupported')


def create(binary, receipt, destination, source_root):
    binary, receipt, destination, root = map(lambda p: Path(p).resolve(), (binary, receipt, destination, source_root))
    stamp = contract.bounded_json(receipt, 16 * 1024**2)
    verified = contract.validate_build(binary, stamp, root)
    if verified['protocols'] != ['delugi', 'raptr'] or stamp.get('profile') != 'release' or not stamp.get('build_root'):
        raise ValueError('portable publication requires a new explicit-root release common build')
    machine = elf_machine(binary)
    if machine == 'unsupported':
        raise ValueError('unsupported ELF architecture')
    destination.mkdir(parents=True, exist_ok=False)
    stage = destination / 'bundle'
    stage.mkdir(mode=0o700)
    shutil.copy2(binary, stage / 'node')
    shutil.copy2(receipt, stage / 'build-receipt.json')
    names = set(stamp['sources']) | set(stamp['profiles'])
    names.update((stamp['cargo_metadata']['path'], stamp['native_dependencies']['archive_path']))
    # Archive the complete Python runtime, independently bound by publication.
    # No cache, credentials, keys, databases or benchmark results are swept in.
    names.update(p.relative_to(root).as_posix() for p in (root / 'scripts').rglob('*.py')
                 if '__pycache__' not in p.parts)
    for name in sorted(names):
        source = contract.safe_file(root, name)
        target = stage / 'source' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    files = {p.relative_to(stage).as_posix(): contract.file_record(p)
             for p in sorted(stage.rglob('*')) if p.is_file()}
    if len(files) > MAX_FILES or sum(v['bytes'] for v in files.values()) > MAX_BYTES:
        raise ValueError('publication exceeds its file/byte envelope')
    manifest = {'schema': 1, 'format': FORMAT, 'files': files, 'machine': machine,
                'binary_sha256': verified['binary']['sha256'], 'protocols': verified['protocols'],
                'profile': 'release', 'comparison_eligible': False,
                'scope': 'build publication only; requires separate functional and distributed acceptance'}
    contract.atomic_json(stage / 'manifest.json', manifest)
    archive = destination / 'common-node.tar.gz'
    with tarfile.open(archive, 'w:gz') as out:
        for name in sorted([*files, 'manifest.json']):
            out.add(stage / name, arcname=name, recursive=False)
    record = {'archive': str(archive), **contract.file_record(archive),
              'binary_sha256': manifest['binary_sha256'], 'machine': machine}
    contract.atomic_json(destination / 'publication.json', record)
    return record


def extract(archive, destination, expected_sha256):
    if contract.sha256(archive) != expected_sha256:
        raise ValueError('publication archive hash differs')
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    names = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            name = member.name
            # No links or directories: the publisher emits regular files only.
            if (not member.isfile() or name in names or not name or '\\' in name
                    or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/'))):
                raise ValueError('unsafe or duplicate publication member')
            names.add(name)
            total += member.size
            if len(names) > MAX_FILES + 1 or total > MAX_BYTES:
                raise ValueError('publication extraction exceeds bound')
            path = destination / name
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            with source.extractfile(member) as incoming, path.open('xb') as out:
                shutil.copyfileobj(incoming, out, 1024 * 1024)
            path.chmod(0o700 if member.mode & 0o111 else 0o600)
    manifest = contract.bounded_json(destination / 'manifest.json', 4 * 1024**2)
    if manifest.get('format') != FORMAT or set(manifest.get('files', {})) | {'manifest.json'} != names:
        raise ValueError('publication member manifest differs')
    for name, record in manifest['files'].items():
        if contract.file_record(contract.safe_file(destination, name)) != record:
            raise ValueError('publication member hash differs: ' + name)
    return manifest


def verify(directory, *, host=False, original_archive=None, archive_sha256=None):
    directory = Path(directory).resolve()
    if (original_archive is None) != (archive_sha256 is None):
        raise ValueError('archive path and trusted archive SHA256 must be supplied together')
    if original_archive is not None:
        if contract.sha256(original_archive) != contract.hex_hash(archive_sha256):
            raise ValueError('installed publication archive differs from the plan')
        with tarfile.open(original_archive) as incoming:
            member = incoming.getmember('manifest.json')
            if not member.isfile() or member.size > 4*1024**2:
                raise ValueError('invalid original publication manifest')
            original = incoming.extractfile(member).read()
        if original != (directory/'manifest.json').read_bytes():
            raise ValueError('installed manifest differs from the original publication')
    manifest = contract.bounded_json(directory / 'manifest.json', 4 * 1024**2)
    if (manifest.get('format') != FORMAT or manifest.get('profile') != 'release'
            or manifest.get('protocols') != ['delugi','raptr']):
        raise ValueError('wrong publication format')
    for name, record in manifest['files'].items():
        if contract.file_record(contract.safe_file(directory, name)) != record:
            raise ValueError('publication member changed: ' + name)
    stamp = contract.bounded_json(directory / 'build-receipt.json', 16 * 1024**2)
    source = directory / 'source'
    native = stamp['native_dependencies']
    tree = source / native['directory']
    if not tree.exists():
        tree.mkdir(parents=True)
        archive = contract.safe_file(source, native['archive_path'])
        if contract.sha256(archive) != native['archive_sha256']:
            raise ValueError('native archive changed')
        with tarfile.open(archive) as incoming:
            incoming.extractall(tree, filter='data')
    result = contract.validate_build(directory / 'node', stamp, source)
    if stamp.get('profile') != 'release' or result['protocols'] != ['delugi','raptr']:
        raise ValueError('cloud publication requires both protocols in a common release build')
    machine = elf_machine(directory / 'node')
    if machine != manifest['machine'] or result['binary']['sha256'] != manifest['binary_sha256']:
        raise ValueError('publication role or architecture differs')
    if host:
        if platform.system() != 'Linux' or platform.machine() != machine:
            raise ValueError('Linux artifact architecture does not match this host')
        if machine == 'x86_64' and 'sse4_2' not in Path('/proc/cpuinfo').read_text():
            raise ValueError('native Linux build requires SSE4.2')
        dynamic = subprocess.run(['ldd', str(directory / 'node')], capture_output=True, text=True, timeout=15)
        if dynamic.returncode or 'not found' in dynamic.stdout:
            raise ValueError('Linux dynamic loader dependencies are unavailable')
        result['dynamic_libraries_on_host'] = dynamic.stdout
        result['host'] = {'system': platform.system(), 'machine': machine, 'libc': platform.libc_ver()}
    return {'status': 'verified', 'binary_sha256': manifest['binary_sha256'], 'machine': machine,
            'build': result, 'comparison_eligible': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    pack = sub.add_parser('pack')
    for name in ('binary', 'receipt', 'output', 'source-root'):
        pack.add_argument('--' + name, required=True, type=Path)
    check = sub.add_parser('verify')
    check.add_argument('--directory', type=Path, required=True)
    check.add_argument('--host', action='store_true')
    check.add_argument('--archive', type=Path)
    check.add_argument('--archive-sha256')
    args = parser.parse_args()
    result = (create(args.binary, args.receipt, args.output, args.source_root) if args.action == 'pack'
              else verify(args.directory, host=args.host, original_archive=args.archive, archive_sha256=args.archive_sha256))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
