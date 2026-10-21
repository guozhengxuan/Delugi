#!/usr/bin/env python3
"""Guard a pinned local Raptr shared-node check/build; never run a benchmark.

This requires the native source extraction and cached dependencies already to
exist. Cargo is offline and locked. A check cannot issue an executable receipt.
The shared target is retained for reuse; owned child cleanup is mandatory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import run_raptr_shared_local as contract

GUARD = contract.ownership
PIN = contract.PIN
ARCHIVE_SHA256 = 'a3da363be4fe6e93eef27c81e5ba30cc8182e73cd468ea72792d5215ad437932'
TARGET = ROOT / 'core/raptr/.native-deps/target'
CARGO_HOME = ROOT / 'benchmarks/.cache/raptr-cargo'
TOOLCHAIN = ROOT / 'benchmarks/toolchains/mysticeti/toolchains/1.78-aarch64-apple-darwin/bin'
NATIVE = ROOT / f'core/raptr/.native-deps/{PIN}'
SOURCE_GIT = ROOT / 'benchmarks/baselines/raptr'
MANIFEST = ROOT / 'core/raptr/node/Cargo.toml'
CONFIG = ROOT / 'core/raptr/native/.cargo/config.toml'
SOURCE_ROOTS = ('core/raptr/node', 'core/raptr/native', 'core/raptr/qs', 'core/raptr/transport',
                'core/raptr/src', 'core-api', 'node', 'shared')
SOURCE_EXTRAS = ('core/raptr/Cargo.toml', 'core/raptr/Cargo.lock', 'core/raptr/native-source.json',
                 'scripts/build_raptr_shared.py', 'scripts/run_raptr_shared_local.py',
                 'scripts/baselines/raptr_artifacts.py')
PROFILE_FILES = ('provenance/shared-services-v1.json', 'shared/store-rocksdb/native-profile.json')
DEFAULT_LIMITS = {'target_bytes':20*1024**3, 'free_bytes':30*1024**3, 'rss_bytes':8*1024**3,
                  'seconds':1800, 'poll_seconds':2, 'cleanup_seconds':10}


def source_snapshot(root=ROOT):
    root=Path(root).resolve(); names=set(SOURCE_EXTRAS)
    for name in SOURCE_ROOTS:
        directory=root/name
        if not directory.is_dir(): raise ValueError(f'missing mutable source root: {name}')
        for current,dirs,files in os.walk(directory,followlinks=False):
            dirs[:]=[name for name in dirs if name not in ('target','.native-deps','.git')]
            for filename in files:
                path=Path(current)/filename
                if path.suffix in ('.rs','.toml') or filename=='Cargo.lock':
                    names.add(path.relative_to(root).as_posix())
    return {name:contract.sha256(contract.safe_file(root,name)) for name in sorted(names)}


def profile_snapshot(root=ROOT):
    return {name:contract.sha256(contract.safe_file(root,name)) for name in PROFILE_FILES}


def archive_manifest(archive, tree, expected_hash):
    """Compare every original archive entry with the dependency checkout bytes."""
    archive,tree=Path(archive),Path(tree).resolve()
    if contract.sha256(archive)!=expected_hash:
        raise ValueError('native archive differs from reviewed exact git-archive SHA256')
    entries={}; total=0
    with tarfile.open(archive,'r:') as incoming:
        for member in incoming:
            relative=PurePosixPath(member.name)
            if relative.is_absolute() or '..' in relative.parts or str(relative)!=member.name.rstrip('/'):
                raise ValueError('invalid native archive path')
            if member.isdir(): continue
            name=relative.as_posix();path=tree/name
            if name in entries: raise ValueError('duplicate native archive entry')
            if any(parent.is_symlink() for parent in path.parents if parent!=tree and parent.is_relative_to(tree)):
                raise ValueError('native archive file traverses a symlink directory')
            if member.issym():
                # prepare_native.py extracted this exact archive with the
                # standard data filter, which normalizes directory-link targets
                # (including a trailing slash). Retain both representations.
                filtered=tarfile.data_filter(member,str(tree))
                target=filtered.linkname
                if not path.is_symlink() or os.readlink(path)!=target:
                    raise ValueError(f'native archived link differs: {name}')
                entries[name]={'kind':'symlink','target':target,'archive_target':member.linkname,
                               'extraction_filter':'tarfile.data_filter'}
            elif member.isfile():
                if path.is_symlink() or not path.is_file(): raise ValueError(f'native archived file missing: {name}')
                digest=hashlib.sha256()
                with incoming.extractfile(member) as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
                expected={'kind':'file','bytes':member.size,'sha256':digest.hexdigest(),'executable':bool(member.mode&0o111)}
                if (contract.file_record(path)!={key:expected[key] for key in ('bytes','sha256')}
                        or bool(path.stat().st_mode&0o111)!=expected['executable']):
                    raise ValueError(f'native dependency differs from original git object: {name}')
                entries[name]=expected;total+=member.size
            else: raise ValueError('unsupported native source archive entry')
    observed=set()
    for current,dirs,files in os.walk(tree,followlinks=False):
        links=[name for name in dirs if (Path(current)/name).is_symlink()]
        dirs[:]=[name for name in dirs if name not in links]
        observed.update((Path(current)/name).relative_to(tree).as_posix() for name in files+links)
    if observed!=set(entries): raise ValueError('native dependency checkout contains missing or unarchived files')
    return {'files':entries,'tree_sha256':contract.digest(entries),'source_bytes':total}


def prepare_native_archive(output, root=ROOT):
    root=Path(root).resolve();output=Path(output)
    metadata=contract.bounded_json(root/'core/raptr/native-source.json')
    if metadata.get('source_commit')!=PIN or metadata.get('source_archive_sha256')!=ARCHIVE_SHA256:
        raise ValueError('reviewed native dependency source metadata differs')
    archive=output/'native-source.tar'
    with archive.open('xb') as stream:
        subprocess.run(['git','-C',str(root/'benchmarks/baselines/raptr'),'archive','--format=tar',PIN],
                       stdout=stream,stderr=subprocess.PIPE,check=True,timeout=60)
    record=archive_manifest(archive,root/f'core/raptr/.native-deps/{PIN}',ARCHIVE_SHA256)
    return dict(record,commit=PIN,archive_sha256=ARCHIVE_SHA256,
                archive_path=archive.relative_to(root).as_posix(),directory=f'core/raptr/.native-deps/{PIN}')


def environment(toolchain,target,cargo_home,base=None):
    base=os.environ if base is None else base;toolchain=Path(toolchain).resolve()
    env={key:base[key] for key in ('HOME','TMPDIR','LANG','LC_ALL') if key in base}
    env.update(PATH=str(toolchain)+':/usr/bin:/bin:/usr/sbin:/sbin:/Library/Developer/CommandLineTools/usr/bin',
               RUSTC=str(toolchain/'rustc'),RUSTDOC=str(toolchain/'rustdoc'),CARGO_HOME=str(Path(cargo_home).resolve()),
               CARGO_TARGET_DIR=str(Path(target).resolve()),CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',
               CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG='0')
    if platform.system()=='Darwin':
        env.update(CFLAGS='-Dfdopen=fdopen',LIBCLANG_PATH='/Library/Developer/CommandLineTools/usr/lib')
    return env


def toolchain_identity(toolchain,env):
    toolchain=Path(toolchain).resolve();records={}
    for name in ('rustc','cargo','rustfmt','rustdoc'):
        path=toolchain/name;GUARD.regular(path,executable=True)
        version=GUARD.output([path,'--version',*(['--verbose'] if name in ('rustc','cargo') else [])],env=env,text=True)
        records[name]={'path':str(path),'sha256':contract.sha256(path),'version':version}
    rustc=records['rustc']['version'];cargo=records['cargo']['version'];rustfmt=records['rustfmt']['version']
    if '\nrelease: 1.78.0\n' not in '\n'+rustc or not cargo.startswith('cargo 1.78.0 '):
        raise ValueError('shared Raptr native build requires exact Rust/Cargo1.78.0')
    compiler=re.search(r'(?m)^commit-hash: ([0-9a-f]{40})$',rustc)
    formatter=re.search(r'^rustfmt [^\n]+ \(([0-9a-f]{7,40}) ',rustfmt)
    if not compiler or not formatter or not compiler[1].startswith(formatter[1]):
        raise ValueError('rustfmt must match the pinned compiler commit')
    return {'rustc_version':'1.78.0','executables':records,'host':{'system':platform.system(),'machine':platform.machine()}}


def recipe(action,toolchain,profile='dev',root=ROOT):
    if action not in ('check','build') or profile not in ('dev','release'):
        raise ValueError('fixed check/build recipe and dev/release profile required')
    argv=[str(Path(toolchain).resolve()/'cargo'),'--config',str(Path(root)/'core/raptr/native/.cargo/config.toml'),action,
          '--manifest-path',str(Path(root)/'core/raptr/node/Cargo.toml'),'--locked','--offline','--jobs','1']
    if profile=='release': argv.append('--release')
    argv += ['--all-targets'] if action=='check' else ['--bin','raptr-shared-node']
    return argv


def checked_git_tree(path, revision):
    """Read Git object identities; do not trust index assume-unchanged flags."""
    path=Path(path); raw=GUARD.output(['git','-C',path,'ls-tree','-rz','--full-tree',revision])
    expected=set();h=hashlib.sha256();count=0
    for entry in raw.split(b'\0'):
        if not entry:continue
        metadata,name=entry.split(b'\t',1);mode,kind,oid=metadata.split()
        relative=name.decode();parts=PurePosixPath(relative)
        if parts.is_absolute() or '..' in parts.parts:raise ValueError('invalid locked Git path')
        file=path/relative
        if kind==b'commit':
            if file.exists() and (not file.is_dir() or any(file.iterdir())):
                raise ValueError('unbound initialized Git dependency submodule')
            h.update(entry+b'\0');continue
        expected.add(relative)
        if mode==b'120000':
            if not file.is_symlink():raise ValueError('cached Git symlink changed')
            data=os.fsencode(os.readlink(file));blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        elif mode in (b'100644',b'100755'):
            GUARD.regular(file)
            if bool(file.stat().st_mode&0o111)!=(mode==b'100755'):raise ValueError('cached Git executable mode changed')
            value=hashlib.sha1(b'blob '+str(file.stat().st_size).encode()+b'\0')
            with file.open('rb') as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b''):value.update(chunk)
            blob=value.hexdigest()
        else:raise ValueError('unsupported locked Git file type')
        if blob!=oid.decode():raise ValueError('cached Git source differs from locked object')
        h.update(entry+b'\0');count+=1
    actual=set()
    for current,dirs,files in os.walk(path,followlinks=False):
        links=[name for name in dirs if (Path(current)/name).is_symlink()]
        dirs[:]=[name for name in dirs if name not in links and name!='.git']
        actual.update((Path(current)/name).relative_to(path).as_posix() for name in files+links if name!='.git')
    if actual-expected-{'.cargo-ok'} or expected-actual:raise ValueError('unbound or missing cached Git build input')
    return {'path':str(path),'files':count,'tracked_tree_sha256':h.hexdigest()}


def cache_identity(lock,cargo_home):
    """Bound the cached registry and Git code Cargo may actually compile offline."""
    cargo_home=Path(cargo_home);packages=tomllib.loads(Path(lock).read_text())['package'];records=[]
    git_checked={}
    for package in packages:
        source=package.get('source','')
        if source.startswith('registry+'):
            stem=package['name']+'-'+package['version'];checksum=package['checksum']
            archives=list((cargo_home/'registry/cache').glob('*/'+stem+'.crate'))
            if not archives:
                records.append({'package':stem,'checksum':checksum,'status':'not_cached_not_available_to_offline_build'})
                continue
            if len(archives)!=1: raise ValueError('ambiguous registry cache source')
            archive=archives[0];tree=cargo_home/'registry/src'/archive.parent.name/stem
            if contract.sha256(archive)!=checksum: raise ValueError('registry package archive differs from Cargo.lock')
            h=hashlib.sha256();count=0;expected=set()
            with tarfile.open(archive) as incoming:
                for member in incoming:
                    if member.isdir():continue
                    prefix=stem+'/'
                    if not member.isfile() or not member.name.startswith(prefix): raise ValueError('unsupported registry package entry')
                    name=member.name[len(prefix):];path=contract.safe_file(tree,name)
                    with incoming.extractfile(member) as stream:
                        value=hashlib.file_digest(stream,'sha256').hexdigest()
                    if contract.sha256(path)!=value: raise ValueError('cached registry source differs from original package')
                    h.update((name+'\0'+value+'\n').encode());expected.add(name);count+=1
            actual={path.relative_to(tree).as_posix() for path in tree.rglob('*') if path.is_file()}
            if actual-expected-{'.cargo-ok','.cargo-checksum.json'}: raise ValueError('unbound extra registry build input')
            records.append({'package':stem,'checksum':checksum,'files':count,'source_tree_sha256':h.hexdigest()})
        elif source.startswith('git+') and source not in git_checked:
            revision=source.rsplit('#',1)[-1]
            if not re.fullmatch('[0-9a-f]{40}',revision): raise ValueError('unlocked native Git dependency')
            candidates=[]
            for path in (cargo_home/'git/checkouts').glob('*/*'):
                if not (path/'.git').exists():continue
                head=GUARD.output(['git','-C',path,'rev-parse','HEAD'],text=True).strip()
                if head==revision:candidates.append(path)
            if not candidates:
                git_checked[source]={'source':source,'status':'not_cached_not_available_to_offline_build'}
                continue
            # Same immutable revision can be cached under more than one URL;
            # each actual checkout must be clean before accepting the identity.
            trees=[]
            for path in sorted(candidates):
                trees.append(checked_git_tree(path,revision))
            git_checked[source]={'source':source,'checkouts':trees}
    return {'registry':records,'git':list(git_checked.values()),'lock_sha256':contract.sha256(lock)}


def binary_identity(path):
    GUARD.regular(path,executable=True)
    if not Path(path).stat().st_size:raise ValueError('empty node executable')
    command=['otool','-L',path] if platform.system()=='Darwin' else ['readelf','-d',path]
    return {'role':'raptr-shared-node','path':str(Path(path).resolve()),**contract.file_record(path),
            'file':GUARD.output(['file','-b',path],text=True).strip(),'dynamic_libraries':GUARD.output(command,text=True)}


def build(action,output,*,toolchain=TOOLCHAIN,target=TARGET,cargo_home=CARGO_HOME,profile='dev',limits=None):
    output=Path(output).resolve();target=Path(target).resolve()
    if not output.is_relative_to(ROOT): raise ValueError('build evidence must be inside the project for reproducible artifact references')
    output.mkdir(parents=True,exist_ok=False)
    limits=GUARD.validate_limits(dict(DEFAULT_LIMITS,**(limits or {})))
    if limits['target_bytes']>20*1024**3 or limits['free_bytes']<30*1024**3 or limits['rss_bytes']>8*1024**3 or limits['seconds']>1800:
        raise ValueError('build resource guard exceeds the approved local envelope')
    receipt={'schema':1,'format':contract.BUILD_FORMAT if action=='build' else 'raptr-shared-check-v1','status':'preparing',
             'action':action,'profile':profile,'native_commit':PIN,'started_unix_ns':time.time_ns(),
             'comparison_eligible':False,'shared_target_retained':True,'source_before_after_equal':False,
             'resource_guard':{'limits':limits,'scope':'sampled owned process RSS/allocated target/free space; not kernel-enforced quotas'}}
    env=environment(toolchain,target,cargo_home);command={}
    try:
        with GUARD.target_lock(target):
            receipt['sources']=source_snapshot();receipt['profiles']=profile_snapshot()
            receipt['native_dependencies']=prepare_native_archive(output)
            receipt['toolchain']=toolchain_identity(toolchain,env)
            receipt['environment']=env
            receipt['cargo_configs']=GUARD.cargo_configs(ROOT,cargo_home)
            receipt['cache_before']=cache_identity(ROOT/'core/raptr/node/Cargo.lock',cargo_home)
            receipt['command']=command
            contract.atomic_json(output/'source-before.json',receipt)
            GUARD.guarded_command(recipe(action,toolchain,profile),ROOT,env,target,
                                  output/'cargo.log',output/'resources.jsonl',limits,command)
            receipt['source_before_after_equal']=(receipt['sources']==source_snapshot() and receipt['profiles']==profile_snapshot())
            if not receipt['source_before_after_equal']:raise ValueError('mutable node/shared source changed during build')
            contract.validate_native_dependencies(receipt['native_dependencies'])
            if toolchain_identity(toolchain,env)!=receipt['toolchain'] or GUARD.cargo_configs(ROOT,cargo_home)!=receipt['cargo_configs']:
                raise ValueError('native compiler/formatter/Cargo configuration changed during build')
            receipt['cache_after']=cache_identity(ROOT/'core/raptr/node/Cargo.lock',cargo_home)
            if receipt['cache_before']!=receipt['cache_after']:raise ValueError('native registry/Git inputs changed during build')
            if command.get('status')!='completed' or command.get('returncode')!=0 or command.get('cleanup',{}).get('status')!='completed' or command['cleanup'].get('remaining')!=[]:
                raise ValueError('successful compiler and confirmed owned cleanup are required')
            if action=='build':
                receipt['binary']=binary_identity(target/('release' if profile=='release' else 'debug')/'raptr-shared-node')
            receipt['status']='completed' if action=='build' else 'checked_not_built'
    except BaseException as error:
        receipt.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        receipt['finished_unix_ns']=time.time_ns()
        for name in ('cargo.log','resources.jsonl','source-before.json'):
            if (output/name).exists():receipt.setdefault('evidence',{})[name]=contract.file_record(output/name)
        contract.atomic_json(output/'build-receipt.json',receipt)
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('check','build'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--toolchain',type=Path,default=TOOLCHAIN)
    parser.add_argument('--target',type=Path,default=TARGET)
    parser.add_argument('--cargo-home',type=Path,default=CARGO_HOME)
    parser.add_argument('--profile',choices=('dev','release'),default='dev')
    args=parser.parse_args()
    result=build(args.action,args.output,toolchain=args.toolchain,target=args.target,cargo_home=args.cargo_home,profile=args.profile)
    print(json.dumps({'status':result['status'],'receipt':str(args.output/'build-receipt.json'),'error':result.get('error')},indent=2))
    return 0 if result['status'] in ('completed','checked_not_built') else 1


if __name__=='__main__':raise SystemExit(main())
