#!/usr/bin/env python3
"""Bounded Linux common-node builder, dispatched by aliyun_bench.py.

Only a fresh nonce-owned directory and a full Git commit are accepted. The
compiler is Rust1.78.0; dependency fetching precedes the offline guarded build.
Build targets are removed after publication (also after a failed build).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request

import remote_worker

REPOSITORY = 'https://github.com/guozhengxuan/Delugi.git'
NATIVE_REPOSITORY = 'https://github.com/aptos-labs/aptos-core.git'
PIN = 'a4c98047cf8aeae3571168d02fb7e343140d2948'
PACKAGES = ['build-essential', 'clang', 'libclang-dev', 'llvm', 'lld', 'cmake', 'pkg-config',
            'libssl-dev', 'libudev-dev', 'libdw-dev', 'protobuf-compiler', 'git', 'ca-certificates', 'xz-utils']
PREFIX = '/tmp/delugi-linux-build-'
MAX_EXPORT = 2*1024**3


def root_for(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('128-bit build nonce required')
    root = Path(PREFIX+nonce)
    if root.is_symlink(): raise ValueError('build root cannot be a symlink')
    return root


def revision(value):
    if not re.fullmatch('[0-9a-f]{40}', value): raise ValueError('full source commit required')
    return value


def digest(path):
    with Path(path).open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    temporary = Path(str(path)+'.pending')
    with os.fdopen(os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600), 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')
    temporary.replace(path)


def download(url, destination, maximum):
    total = 0
    deadline = time.monotonic()+1200
    with urllib.request.urlopen(url, timeout=60) as response, Path(destination).open('xb') as out:
        while data := response.read(1024**2):
            total += len(data)
            if total > maximum or time.monotonic()>deadline: raise ValueError('compiler download exceeds byte/time bound')
            out.write(data)


def run_build(nonce, commit, install_packages=False):
    revision(commit); root = root_for(nonce)
    owner = json.loads((root/'owner.json').read_text())
    if owner != {'nonce': nonce, 'revision': commit, 'worker_sha256': digest(__file__),
                 'runtime_sha256': digest(remote_worker.__file__), 'install_packages': install_packages}:
        raise ValueError('build request differs from dispatched ownership record')
    if (root/'status.json').exists(): raise ValueError('build already attempted; use a fresh build plan')
    state = {'schema': 1, **owner, 'status': 'running', 'started_unix_ns': time.time_ns(),
             'comparison_eligible': False, 'commands': [], 'cleanup_confirmed': False}
    source = root/'source'; target = source/'core/raptr/.native-deps/target'
    logs = root/'logs'; logs.mkdir(mode=0o700)
    environment = {k:v for k,v in os.environ.items() if k in ('HOME', 'LANG', 'LC_ALL', 'TMPDIR')}
    environment.update(PATH='/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', GIT_TERMINAL_PROMPT='0')
    def command(label, argv, cwd=root, timeout=600, env=None):
        row = {'label': label, 'argv': list(map(str, argv)), 'status': 'running'}
        state['phase'] = label; state['commands'].append(row); save(root/'status.json', state)
        with (logs/(label+'.log')).open('xb') as output:
            child = None
            try:
                child = subprocess.Popen(row['argv'], cwd=cwd, env=env or environment,
                                         stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
                code = child.wait(timeout=timeout)
                row['returncode'] = code
                if code: raise RuntimeError(label+' failed; inspect its saved log')
                row['status'] = 'completed'
            except BaseException:
                row['status'] = 'failed'
                raise
            finally:
                if child is None:
                    row['cleanup'] = {'group_empty': True, 'not_started': True}
                else:
                    row['cleanup'] = remote_worker.finish_owned_group(child)
                    child.wait(timeout=5)
        save(root/'status.json', state)
    try:
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64') or sys.version_info < (3,12):
            raise ValueError('builder needs Linux x86_64/aarch64 and Python3.12+')
        if shutil.disk_usage(root).free < 60*1024**3:
            raise ValueError('builder requires at least60GiB free space')
        if install_packages:
            if os.geteuid() != 0 or not Path('/usr/bin/apt-get').is_file():
                raise ValueError('explicit package installation requires a root Ubuntu/Debian builder')
            command('apt-update', ['apt-get', 'update'])
            command('apt-install', ['apt-get', 'install', '-y', '--no-install-recommends', *PACKAGES], timeout=1200,
                    env=dict(environment, DEBIAN_FRONTEND='noninteractive'))
        missing = [name for name in ('git','clang','ld.lld','cmake','pkg-config','protoc') if shutil.which(name, path=environment['PATH']) is None]
        if missing: raise ValueError('missing build tools: '+', '.join(missing))
        for name in ('git','clang','ld.lld','cmake','protoc'):
            command('version-'+name, [name,'--version'], timeout=30)
        command('source-init', ['git','init',str(source)])
        command('source-remote', ['git','remote','add','origin',REPOSITORY], source)
        command('source-fetch', ['git','fetch','--depth','1','origin',commit], source, timeout=1200)
        command('source-checkout', ['git','checkout','--detach',commit], source)
        command('linux-supervisor-tests', [sys.executable,'-m','unittest','discover','-s','tests',
                '-p','common_cloud_worker_linux_test.py'], source, timeout=120)
        native = source/'benchmarks/baselines/raptr'
        native.parent.mkdir(parents=True, exist_ok=True)
        command('native-init', ['git','init',str(native)])
        command('native-remote', ['git','remote','add','origin',NATIVE_REPOSITORY], native)
        command('native-fetch', ['git','fetch','--depth','1','origin',PIN], native, timeout=1200)
        # git archive reads the exact pinned object; no modified baseline worktree.
        command('native-extract', [sys.executable, str(source/'core/raptr/prepare_native.py'), '--repository', str(native)], source)
        triple = platform.machine()+'-unknown-linux-gnu'
        name = 'rust-1.78.0-'+triple
        url = 'https://static.rust-lang.org/dist/'+name+'.tar.xz'
        state['phase'] = 'compiler-download'; save(root/'status.json',state)
        archive = root/(name+'.tar.xz'); checksum = root/(name+'.sha256')
        download(url+'.sha256', checksum, 4096); download(url, archive, 512*1024**2)
        expected = checksum.read_text().split()[0]
        if not re.fullmatch('[0-9a-f]{64}', expected) or digest(archive) != expected:
            raise ValueError('official compiler distribution checksum mismatch')
        state['compiler_archive'] = {'url':url, 'sha256':expected}
        with tarfile.open(archive) as incoming: incoming.extractall(root/'compiler-source', filter='data')
        toolchain = root/'toolchain'
        command('compiler-install', [str(root/'compiler-source'/name/'install.sh'), '--prefix='+str(toolchain),
                '--components=rustc,cargo,rustfmt-preview,rust-std-'+triple, '--disable-ldconfig'])
        shutil.rmtree(root/'compiler-source'); archive.unlink()
        cargo_home = root/'cargo'
        build_env = dict(environment, PATH=str(toolchain/'bin')+':'+environment['PATH'], CARGO_HOME=str(cargo_home),
                         RUSTC=str(toolchain/'bin/rustc'), RUSTDOC=str(toolchain/'bin/rustdoc'), CARGO_TARGET_DIR=str(target))
        command('fetch-locked', [str(toolchain/'bin/cargo'),'--config',str(source/'core/raptr/native/.cargo/config.toml'),
                'fetch','--manifest-path',str(source/'core/raptr/node/Cargo.toml'),'--locked'], source, timeout=1200, env=build_env)
        for action in ('test','build'):
            command('guarded-'+action, [sys.executable,str(source/'scripts/build_raptr_shared.py'),action,
                    '--profile','release','--toolchain',str(toolchain/'bin'),'--cargo-home',str(cargo_home),
                    '--target',str(target),'--output',str(source/'results/cloud-build'/action)], source, timeout=2100)
        command('publish', [sys.executable,str(source/'scripts/common_artifact.py'),'pack',
                '--binary',str(target/'release/raptr-shared-node'),
                '--receipt',str(source/'results/cloud-build/build/build-receipt.json'),
                '--source-root',str(source),'--output',str(root/'publication')], source)
        command('verify-publication', [sys.executable,str(source/'scripts/common_artifact.py'),'verify',
                '--directory',str(root/'publication/bundle'),'--host'], source)
        state['publication'] = json.loads((root/'publication/publication.json').read_text())
        state['status'] = 'completed'
    except BaseException as error:
        state.update(status='failed', error=f'{type(error).__name__}: {error}')
    finally:
        # Keep source/receipts/logs and the published executable. Remove only the
        # disposable target belonging to this nonce; never a shared target cache.
        commands_stopped = all(c.get('cleanup', {}).get('group_empty') for c in state['commands'])
        if commands_stopped and target.exists() and not target.is_symlink(): shutil.rmtree(target)
        state['target_removed'] = not target.exists()
        state['cleanup_confirmed'] = state['target_removed'] and commands_stopped
        state['finished_unix_ns'] = time.time_ns(); save(root/'status.json',state)
    return state


def export(nonce):
    root = root_for(nonce)
    state = json.loads((root/'status.json').read_text())
    if state['status'] == 'running' or not state.get('cleanup_confirmed'):
        raise ValueError('build must finish cleanup before collection')
    names = ['owner.json','status.json','launcher.json','build.stdout','build.stderr']
    names += [p.relative_to(root).as_posix() for p in (root/'logs').glob('*.log')]
    names += ['publication/common-node.tar.gz','publication/publication.json']
    names += [p.relative_to(root).as_posix() for p in (root/'source/results/cloud-build').rglob('*') if p.is_file()]
    paths = [root/name for name in sorted(set(names)) if (root/name).is_file()]
    if any(p.is_symlink() for p in paths) or sum(p.stat().st_size for p in paths)>MAX_EXPORT:
        raise ValueError('build export exceeds file envelope')
    with tarfile.open(fileobj=sys.stdout.buffer, mode='w|') as outgoing:
        for path in paths: outgoing.add(path, arcname=path.relative_to(root).as_posix(), recursive=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nonce', required=True); parser.add_argument('--revision')
    parser.add_argument('--install-system-packages', action='store_true')
    parser.add_argument('--export', action='store_true'); args = parser.parse_args()
    if args.export: export(args.nonce); return 0
    state = run_build(args.nonce,args.revision,args.install_system_packages)
    print(json.dumps(state)); return 0 if state['status']=='completed' else 1


if __name__ == '__main__': raise SystemExit(main())
