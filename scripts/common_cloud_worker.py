#!/usr/bin/env python3
"""Finite Linux replica lifecycle over authenticated SSH; JSON RPC on stdin.

Each nonce owns one directory, one supervisor and one native process group.
Abort tombstones close the prepare/start race. Evidence export excludes keys/DBs.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import resource
import signal
import shutil
import socket
import subprocess
import sys
import time

import remote_worker as resources
import runtime_evidence

MAX_JSON = 16 * 1024**2
MAX_LOG = 64 * 1024**2
PREFIX = '/tmp/delugi-cloud-'
COMPACT = 'compact-sustained-v1'


def envelope(request):
    """Version the larger workload without widening historical pilot requests."""
    profile = request.get('evaluation_profile')
    if profile not in (None, COMPACT):
        raise ValueError('unknown evaluation lifecycle profile')
    return ({'nodes':(4,10,50), 'seconds':600, 'file_bytes':16*1024**3,
             'export_bytes':16*1024**3, 'disk_bytes':64*1024**3} if profile == COMPACT else
            {'nodes':(4,), 'seconds':240, 'file_bytes':512*1024**2,
             'export_bytes':512*1024**2, 'disk_bytes':4*1024**3})


def digest(path):
    return resources.sha(path)


def write(path, value, *, exclusive=False):
    path = Path(path)
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    if exclusive:
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
            stream.write(raw)
    else:
        temporary = path.with_suffix('.pending')
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(raw)
        temporary.replace(path)


def read(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_JSON:
        raise ValueError('unsafe or oversized control file')
    return json.loads(path.read_text())


def root_for(nonce):
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('a 128-bit run nonce is required')
    root = Path(PREFIX + nonce)
    if root.is_symlink():
        raise ValueError('run directory cannot be a symlink')
    return root


@contextmanager
def locked(root):
    root.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(root / 'lifecycle.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def active(root):
    if (root / 'aborted.json').exists():
        raise ValueError('run is aborted; a late worker cannot prepare/start/arm it')


def clock_us():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


def process_matches(pid, start):
    try:
        return resources.pid_start(pid) == start
    except (FileNotFoundError, ProcessLookupError):
        return False


def prepare(request):
    root = root_for(request['nonce'])
    with locked(root):
        active(root)
        if (root / 'request.json').exists():
            raise ValueError('prepared run cannot be overwritten')
        limits = envelope(request)
        if request.get('protocol') not in ('delugi', 'raptr') or type(request.get('replica')) is not int:
            raise ValueError('explicit protocol and replica required')
        if type(request.get('timeout_seconds')) is not int or not 10 <= request['timeout_seconds'] <= limits['seconds']:
            raise ValueError('process deadline exceeds the selected lifecycle profile')
        if type(request.get('disk_bytes', limits['disk_bytes'])) is not int or not 0 < request.get('disk_bytes', limits['disk_bytes']) <= limits['disk_bytes']:
            raise ValueError('disk envelope exceeds the selected lifecycle profile')
        artifact = Path(request['artifact']).resolve()
        manifest = read(artifact / 'manifest.json')
        if (manifest.get('format') != 'delugi-common-artifact-v1'
                or manifest.get('protocols') != ['delugi', 'raptr']
                or manifest.get('profile') != 'release'
                or manifest.get('binary_sha256') != request['binary_sha256']
                or digest(artifact / 'node') != request['binary_sha256']):
            raise ValueError('explicit common release artifact identity differs')
        config_text = request['config_text']
        if hashlib.sha256(config_text.encode()).hexdigest() != request['configuration_sha256']:
            raise ValueError('configuration hash differs')
        config = json.loads(config_text)
        members = len(config['addresses'])
        if members not in limits['nodes'] or request['replica'] not in range(members):
            raise ValueError('committee/replica exceeds the selected lifecycle profile')
        if request.get('evaluation_profile') == COMPACT:
            if request['protocol'] == 'raptr':
                if config.get('schema') != 2 or config.get('sustained_workload') is None:
                    raise ValueError('compact Raptr requires bounded sustained schema2')
                if not 0 < config['measurement_duration_ms'] <= 60_000 or not 0 <= config['drain_ms'] <= 15_000:
                    raise ValueError('compact Raptr window exceeds60s plus15s drain')
            else:
                load = config.get('sustained', {})
                if not load.get('global_arrivals') or load.get('warmup_ms') != 0 or not 0 < load.get('measurement_ms', 0) <= 60_000:
                    raise ValueError('compact Delugi requires the shared global schedule and finite window')
        allowed = ({f'replica-{request["replica"]}.key'} if request['protocol'] == 'delugi'
                   else {f'key-{request["replica"]}.json', 'committee.json', 'genesis-ledger.bcs'})
        if set(request.get('keys_hex', {})) != allowed:
            raise ValueError('distribute only this replica secret and public committee material')
        (root / 'keys').mkdir(mode=0o700)
        for name, encoded in request['keys_hex'].items():
            payload = bytes.fromhex(encoded)
            if len(payload) > 256 * 1024:
                raise ValueError('key material exceeds pilot envelope')
            with os.fdopen(os.open(root / 'keys' / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
                out.write(payload)
        if request['protocol'] == 'raptr':
            expected_profile = 'private-ipv4-n4-v1' if members==4 else 'private-ipv4-n10-n50-v1'
            if (config.get('deployment_profile') != expected_profile
                    or config['key_directory'] != str(root / 'keys')
                    or config['output_directory'] != str(root / 'replicas')
                    or config['arm_path'] != str(root / 'arm.json')):
                raise ValueError('Raptr deployment paths/profile differ')
            (root / 'replicas').mkdir(mode=0o700)
        else:
            if config['key_files'] != [str(root / 'keys' / f'replica-{i}.key') for i in range(members)]:
                raise ValueError('Delugi key paths differ')
            if any(not a.startswith('127.0.0.1:') for a in config['control_addresses']):
                raise ValueError('control sockets must remain loopback-only')
            if config.get('storage_directory') not in (None, str(root / 'records')):
                raise ValueError('database must be inside the owned run')
            if config.get('storage_directory'):
                (root / 'records').mkdir(mode=0o700)
        with os.fdopen(os.open(root / 'config.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as out:
            out.write(config_text)
        saved = {k: v for k, v in request.items() if k not in ('keys_hex', 'config_text', 'action')}
        saved['artifact'] = str(artifact)
        write(root / 'request.json', saved, exclusive=True)
        return {'prepared': True, 'nonce': request['nonce'], 'replica': request['replica'],
                'configuration_sha256': request['configuration_sha256']}


def start(request):
    root = root_for(request['nonce'])
    with locked(root):
        active(root)
        saved = read(root / 'request.json')
        if (root / 'supervisor.json').exists():
            raise ValueError('run already started; inspect instead of launching twice')
        with (root / 'supervisor.stdout').open('xb') as out, (root / 'supervisor.stderr').open('xb') as err:
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--supervise', request['nonce']],
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
        value = {'pid': child.pid, 'pid_start': resources.pid_start(child.pid), 'nonce': saved['nonce']}
        write(root / 'supervisor.json', value, exclusive=True)
        return value


def supervise(nonce):
    root = root_for(nonce)
    child = cgroup = None
    summary = {'nonce': nonce, 'status': 'failed', 'cleanup_confirmed': False}
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    try:
        with locked(root):
            active(root)
            request = read(root / 'request.json')
            budget = request['budget']
            effective = resources.validate_resource_budget(budget, os.sched_getaffinity(0),
                os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES'), resources.host_swap_bytes())
            summary['effective_budget'] = effective
            cgroup = resources.make_cgroup(budget, nonce)
            binary = Path(request['artifact']) / 'node'
            if digest(binary) != request['binary_sha256'] or digest(root / 'config.json') != request['configuration_sha256']:
                raise ValueError('artifact/configuration changed before launch')
            def limits():
                os.sched_setaffinity(0, set(budget['cpus']))
                # This limit covers every regular file, including RocksDB SSTs.
                # Keep the file bound above the core's maximum journal size.
                maximum = envelope(request)['file_bytes']
                resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
                if cgroup is not None:
                    (cgroup / 'cgroup.procs').write_text(str(os.getpid()))
            env = {k: v for k, v in os.environ.items() if k.lower() not in ('http_proxy', 'https_proxy', 'all_proxy')
                   and not k.startswith(('RAPTR_', 'BENCHMARK_'))}
            with (root / 'node.stdout').open('xb') as out, (root / 'node.stderr').open('xb') as err:
                child = subprocess.Popen([str(binary), '--protocol', request['protocol'], '--config', str(root / 'config.json'),
                                          '--id', str(request['replica'])], cwd=root, env=env,
                                         stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         start_new_session=True, preexec_fn=limits)
            write(root / 'process.json', {'pid': child.pid, 'pid_start': resources.pid_start(child.pid),
                  'nonce': nonce, 'configuration_sha256': request['configuration_sha256'], 'started_us': clock_us()}, exclusive=True)
        deadline = time.monotonic() + request['timeout_seconds']
        while child.poll() is None:
            if time.monotonic() >= deadline:
                raise TimeoutError('finite pilot process deadline expired')
            size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file() and not p.is_symlink())
            if size > request.get('disk_bytes', envelope(request)['disk_bytes']):
                raise ValueError('owned run exceeded sampled disk envelope')
            if any(p.stat().st_size > MAX_LOG for p in (root/'node.stdout', root/'node.stderr')):
                raise ValueError('owned process log exceeded sampled log envelope')
            time.sleep(.25)
        summary.update(exit_code=child.returncode, status='completed' if child.returncode == 0 else 'failed',
                       effective_budget=effective)
    except BaseException as error:
        summary['error'] = f'{type(error).__name__}: {error}'
    finally:
        if child is not None:
            try:
                summary['owned_group_cleanup'] = resources.finish_owned_group(child)
                child.wait(timeout=5)
                summary['cleanup_confirmed'] = summary['owned_group_cleanup']['group_empty']
                summary.setdefault('exit_code', child.returncode)
            except Exception as error:
                summary['cleanup_error'] = str(error)
        else:
            summary['cleanup_confirmed'] = True
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        summary.update(finished_us=clock_us(), child_user_seconds=after.ru_utime-before.ru_utime,
                       child_system_seconds=after.ru_stime-before.ru_stime, child_peak_rss_bytes=after.ru_maxrss*1024,
                       aborted=(root / 'aborted.json').exists())
        if cgroup is not None:
            try:
                summary['cgroup'] = {name: (cgroup/name).read_text() for name in ('cpu.stat', 'memory.peak', 'memory.events', 'io.stat') if (cgroup/name).exists()}
                cgroup.rmdir()
            except Exception as error:
                summary['cleanup_confirmed'] = False
                summary['cleanup_error'] = str(error)
        write(root / 'resource-summary.json', summary)
    return 0 if summary['status'] == 'completed' and summary['cleanup_confirmed'] else 1


def control(root, kind, fields=None):
    config, request = read(root / 'config.json'), read(root / 'request.json')
    if request['protocol'] != 'delugi' or kind not in ('snapshot', 'prepare', 'submit', 'start', 'load', 'cohort', 'outputs', 'batches', 'quiesce', 'stop'):
        raise ValueError('unsupported finite Delugi control')
    replica = request['replica']
    identity = 'cloud-' + str(time.time_ns())
    value = dict(fields or {}, token=config['control_token'], type=kind, request_id=identity)
    host, port = config['control_addresses'][replica].rsplit(':', 1)
    start_us = clock_us()
    with socket.create_connection((host, int(port)), timeout=3) as sock:
        sock.settimeout(5)
        sock.sendall(json.dumps(value).encode() + b'\n')
        with sock.makefile('rb') as stream:
            raw = stream.readline(MAX_JSON + 1)
    if len(raw) > MAX_JSON or not raw.endswith(b'\n'):
        raise ValueError('oversized/truncated control reply')
    reply = json.loads(raw)
    if reply.get('request_id') != identity or reply.get('id') != replica or reply.get('ok') is not True:
        raise ValueError('native control rejected request')
    record = {'replica': replica, 'type': kind, 'start_us': start_us, 'end_us': clock_us(), 'reply': reply}
    with (root / 'control.jsonl').open('a') as stream:
        stream.write(json.dumps(record) + '\n')
    return record


def status(request):
    root = root_for(request['nonce'])
    result = {'nonce': request['nonce'], 'aborted': (root / 'aborted.json').exists()}
    for name in ('supervisor', 'process', 'resource-summary', 'arm'):
        path = root / (name + '.json')
        if path.exists():
            result[name] = read(path)
    if 'process' in result:
        p = result['process']
        result['process_alive'] = process_matches(p['pid'], p['pid_start'])
    return result


def ready(root):
    saved = read(root / 'request.json')
    p = read(root / 'process.json')
    if not process_matches(p['pid'], p['pid_start']):
        raise ValueError('native process is no longer alive')
    if saved['protocol'] == 'delugi':
        control(root, 'snapshot')
        return {'id': saved['replica'], 'pid': p['pid'], 'ready_us': clock_us(),
                'configuration_sha256': saved['configuration_sha256']}
    r = read(root / 'replicas' / f'node-{saved["replica"]}' / 'ready.json')
    if r.get('id') != saved['replica'] or r.get('pid') != p['pid'] or r.get('configuration_sha256') != saved['configuration_sha256']:
        raise ValueError('native readiness does not bind this process/configuration')
    return r


def arm(request):
    root = root_for(request['nonce'])
    with locked(root):
        active(root)
        r = ready(root)
        saved = read(root / 'request.json')
        if saved['protocol'] != 'raptr':
            raise ValueError('Delugi finite fixture is explicitly prepared/submitted/started')
        config = read(root / 'config.json')
        if (root / 'arm.json').exists():
            return read(root / 'arm.json')  # Lost reply: do not move the epoch.
        value = {'schema': 1, 'run_id': config['run_id'], 'configuration_sha256': saved['configuration_sha256'],
                 'epoch_us': clock_us() + 1_000_000}
        write(root / 'arm.json', value, exclusive=True)
        return value


def stop(request):
    root = root_for(request['nonce'])
    with locked(root):
        write(root / 'aborted.json', {'nonce': request['nonce'], 'aborted_us': clock_us()})
        if not (root / 'process.json').exists():
            if not (root/'supervisor.json').exists():
                summary = {'status': 'not_started', 'nonce': request['nonce'],
                           'closed_before_launch': True, 'cleanup_confirmed': True}
                write(root/'resource-summary.json', summary)
                return summary
            process = None
        else:
            process = read(root / 'process.json')
        if process is not None and process_matches(process['pid'], process['pid_start']):
            for sig in (signal.SIGCONT, signal.SIGTERM):
                try:
                    os.killpg(process['pid'], sig)
                except ProcessLookupError:
                    break
    for attempt in range(160):
        if (root / 'resource-summary.json').exists():
            return read(root / 'resource-summary.json')
        if attempt == 30 and process is not None and process_matches(process['pid'], process['pid_start']):
            try:
                os.killpg(process['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(.1)
    raise RuntimeError('owned supervisor cleanup was not confirmed; remote evidence retained')


def export(request):
    root = root_for(request['nonce'])
    summary = read(root / 'resource-summary.json')
    if not summary.get('cleanup_confirmed'):
        raise ValueError('freeze and confirmed cleanup required before evidence export')
    names = [name for name in ('config.json', 'request.json', 'process.json', 'supervisor.json', 'resource-summary.json',
             'arm.json', 'aborted.json', 'node.stdout', 'node.stderr', 'supervisor.stdout', 'supervisor.stderr', 'control.jsonl', 'verification.json')
             if (root / name).is_file()]
    # Abort may win the prepare race, leaving only a tombstone and a confirmed
    # cleanup receipt. Export that bounded diagnostic without requiring a run.
    saved = read(root / 'request.json') if (root / 'request.json').exists() else {}
    allowed = {'ready.json', 'final.json', 'requests.jsonl', 'output.jsonl', 'effective-profile.json', 'workload-manifest.json', 'latency-trace.json'}
    if saved.get('evaluation_profile') == COMPACT: allowed.add('planned.jsonl')
    if (root / 'replicas').exists():
        names += [p.relative_to(root).as_posix() for p in sorted((root / 'replicas').glob('node-*/*'))
                  if p.name in allowed and p.is_file()]
    if request.get('compression') not in (None,'gzip'):raise ValueError('unsupported evidence compression')
    stream=gzip.GzipFile(fileobj=sys.stdout.buffer,mode='wb',compresslevel=1,mtime=0) if request.get('compression')=='gzip' else sys.stdout.buffer
    try:runtime_evidence.pack(root, names, stream, {'nonce': request['nonce'],
                          'format': 'common-sustained-evidence-v1' if saved.get('evaluation_profile') == COMPACT else 'common-pilot-evidence-v1'},
                          max_payload_bytes=envelope(saved)['export_bytes'], max_files=100)
    finally:
        if stream is not sys.stdout.buffer:stream.close()


def rpc(request):
    action = request['action']
    if action == 'keygen':
        root = root_for(request['nonce'])
        with locked(root):
            active(root)
            binary = Path(request['artifact']) / 'node'
            if request['protocol'] not in ('delugi', 'raptr') or digest(binary) != request['binary_sha256']:
                raise ValueError('key generation artifact/protocol differs')
            path = root / 'generated-keys'
            nodes = request.get('nodes',4)
            if type(nodes) is not int or nodes not in envelope(request)['nodes']:
                raise ValueError('key generation committee exceeds lifecycle profile')
            try:
                result = subprocess.run([str(binary), '--protocol', request['protocol'], '--keygen', str(path), '--nodes', str(nodes)],
                                        capture_output=True, text=True, timeout=30)
                if result.returncode: raise ValueError('key generation failed')
                return {'public': json.loads(result.stdout), 'files_hex': {p.name: p.read_bytes().hex() for p in path.iterdir() if p.is_file()}}
            finally:
                if path.exists():shutil.rmtree(path)
    if action == 'prepare': return prepare(request)
    if action == 'start': return start(request)
    if action == 'status': return status(request)
    if action == 'abort': return stop(request)
    if action == 'arm': return arm(request)
    root = root_for(request['nonce'])
    if action == 'ready': return ready(root)
    if action == 'control':
        with locked(root):
            active(root)
            return control(root, request['kind'], request.get('fields'))
    if action == 'pause':
        with locked(root):
            active(root)
            process = read(root / 'process.json')
            if not process_matches(process['pid'], process['pid_start']):
                raise ValueError('cannot pause an unrelated/exited process')
            os.killpg(process['pid'], signal.SIGSTOP)
            for _ in range(100):
                if not process_matches(process['pid'], process['pid_start']):
                    raise ValueError('native process exited before pause confirmation')
                state = Path(f'/proc/{process["pid"]}/stat').read_text().rsplit(')', 1)[1].split()[0]
                if state in ('T', 't'):
                    return {'paused': True, 'observed_state': state, **process}
                time.sleep(.01)
            raise ValueError('native process did not enter stopped state')
    if action == 'verify':
        saved = read(root / 'request.json')
        if saved['protocol'] != 'raptr': raise ValueError('Delugi verification uses collected snapshots and events')
        summary = read(root/'resource-summary.json')
        if summary.get('status') != 'completed' or not summary.get('cleanup_confirmed'):
            raise ValueError('native receipt verification requires completed owned cleanup')
        if digest(Path(saved['artifact'])/'node') != saved['binary_sha256']:
            raise ValueError('native verifier executable changed')
        final = root / 'replicas' / f'node-{saved["replica"]}' / 'final.json'
        result = subprocess.run([str(Path(saved['artifact'])/'node'), '--protocol', 'raptr', '--config', str(root/'config.json'),
                                 '--verify-workload-ledger', str(final)], capture_output=True, text=True,
                                 timeout=300 if saved.get('evaluation_profile') == COMPACT else 30)
        if result.returncode: raise ValueError('native signed-receipt verifier failed')
        value = json.loads(result.stdout)
        write(root/'verification.json', value)
        return value
    raise ValueError('unsupported lifecycle action')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--supervise')
    args = parser.parse_args()
    if args.supervise: return supervise(args.supervise)
    raw = sys.stdin.buffer.read(MAX_JSON+1)
    if len(raw) > MAX_JSON: raise ValueError('RPC exceeds bound')
    request = json.loads(raw)
    if request['action'] == 'export':
        export(request)
    else:
        print(json.dumps(rpc(request)), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
