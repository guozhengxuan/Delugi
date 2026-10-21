#!/usr/bin/env python3
"""Bounded build inside the owned local Linux container after bootstrap.

No VM provisioning or cloud calls. Uses the pinned native helper, jobs=1,
incremental=0/debug=0, and stops at70GiB filesystem allocation. Container swap
is build-only; the VM owner must disable it before any benchmark.
"""
import json
import argparse
import os
from pathlib import Path
import signal
import subprocess
import time


def resource_sample(elapsed, root=Path('/sys/fs/cgroup'), work='/work'):
    fs=os.statvfs(work)
    events={key:int(value) for key,value in (line.split() for line in (root/'memory.events').read_text().splitlines())}
    return {'elapsed_seconds':elapsed,'filesystem_used_bytes':(fs.f_blocks-fs.f_bfree)*fs.f_frsize,
            'memory_current_bytes':int((root/'memory.current').read_text()),
            'memory_peak_bytes':int((root/'memory.peak').read_text()),
            'swap_current_bytes':int((root/'memory.swap.current').read_text()),'memory_events':events}


def stop_reason(sample, initial, pressure_since, disk_limit, swap_limit):
    if any(sample['memory_events'].get(field,0)>initial.get(field,0) for field in ('oom','oom_kill')):
        return 'cgroup OOM event observed',pressure_since
    if sample['filesystem_used_bytes']>=disk_limit:return '70GiB allocated filesystem ceiling reached',pressure_since
    pressure_since=(sample['elapsed_seconds'] if pressure_since is None else pressure_since) if sample['swap_current_bytes']>=swap_limit else None
    if pressure_since is not None and sample['elapsed_seconds']-pressure_since>=60:
        return 'at least3GiB swap continuously for60seconds',pressure_since
    return None,pressure_since


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt',type=int,default=1)
    args=parser.parse_args()
    if args.attempt<1:parser.error('attempt must be positive')
    if not Path('/run/.containerenv').exists() or os.uname().machine!='aarch64':
        raise SystemExit('Only the owned local ARM64 Linux build container is supported')
    suffix='' if args.attempt==1 else f'-attempt-{args.attempt}'
    root=Path('/work/repo');output=root/('results/local/shoal-build-20261019'+suffix)
    env=os.environ|{'RUSTUP_HOME':'/work/toolchain/rustup','CARGO_HOME':'/work/toolchain/cargo',
                    'PATH':'/work/toolchain/cargo/bin:/work/toolchain/protoc/bin:'+os.environ['PATH'],
                    'CARGO_INCREMENTAL':'0','CARGO_BUILD_JOBS':'1','CARGO_PROFILE_RELEASE_DEBUG':'0'}
    command=['/usr/bin/time','-v','python3',str(root/'scripts/baselines/native_artifacts.py'),
             'shoal','--build','--jobs','1','--output',str(output)]
    samples=[];limit=70*1024**3;swap_limit=3*1024**3;started=time.monotonic();reason=None;pressure_since=None
    initial=resource_sample(0)['memory_events']
    with Path('/work/evidence/build-driver'+suffix+'.log').open('xb') as log:
        process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            while True:
                sample=resource_sample(time.monotonic()-started);samples.append(sample)
                reason,pressure_since=stop_reason(sample,initial,pressure_since,limit,swap_limit)
                if reason:
                    if process.poll() is None:os.killpg(process.pid,signal.SIGTERM)
                    break
                if process.poll() is not None:break
                time.sleep(1)
            try:code=process.wait(timeout=30)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);code=process.wait()
        finally:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGTERM)
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait()
            Path('/work/evidence/build-resource-bound'+suffix+'.json').write_text(json.dumps({
                'command':command,'scratch_ceiling_bytes':limit,'samples':samples,
                'exit_code':process.returncode,'stop_reason':reason,
                'swap_pressure_abort':{'bytes':swap_limit,'continuous_seconds':60},
                'peak_cgroup_memory_bytes':max((row['memory_peak_bytes'] for row in samples),default=0),
                'peak_cgroup_swap_bytes':max((row['swap_current_bytes'] for row in samples),default=0),
                'swap_policy':'build-only; must disable before native timing tests'},indent=2)+'\n')
    return code or (1 if reason else 0)


if __name__=='__main__':raise SystemExit(main())
