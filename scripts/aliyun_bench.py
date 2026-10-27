#!/usr/bin/env python3
"""Loom-style commands for the Delugi/Raptr four-host Aliyun engineering pilot.

Planning is offline. Remote operations require --execute. Paid instances use
the separate reviewed lease contract. This finite runner never claims sustained
capacity or calibrated delay; it does not turn build success into acceptance.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import alibaba_deployment as cloud
import common_cloud_worker as worker
import common_cloud_controller as builder
import deployment_prepare as placement
import run_network as delugi
import run_raptr_shared_local as raptr
import runtime_evidence
from remote_deployment import ssh_arguments

ROOT = Path(__file__).resolve().parents[1]
KIND = 'delugi-raptr-aliyun-pilot-v1'
CASES = ('healthy', 'silent-first-leader')


def save(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.pending')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as out:
        json.dump(value, out, indent=2)
        out.write('\n')
    temporary.replace(path)


def sha(path):
    return placement.sha(path)


def hash_json(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def parallel(items, function):
    """Wait for and inspect EVERY action, including after the first failure."""
    values, errors = {}, {}
    with ThreadPoolExecutor(max_workers=min(len(items), 4)) as pool:
        futures = {pool.submit(function, item): item['replica'] for item in items}
        for future in as_completed(futures):
            key = futures[future]
            try:
                values[key] = future.result()
            except Exception as error:
                errors[key] = f'{type(error).__name__}: {error}'
    return values, errors


def require_all(result, label):
    values, errors = result
    if errors:
        raise RuntimeError(f'{label}: {errors}')
    return values


def private_ip(text):
    address = ipaddress.IPv4Address(text)
    return any(address in ipaddress.ip_network(cidr) for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def validate_hosts(value):
    placement.validate_hosts(value)
    hosts = value['hosts']
    if len(hosts) != 4 or any(h['replica'] != i for i, h in enumerate(hosts)):
        raise ValueError('pilot requires four dedicated hosts in replica order0..3')
    ips = [h['advertised'].rsplit(':', 1)[0] for h in hosts]
    if len(set(ips)) != 4 or not all(private_ip(ip) for ip in ips):
        raise ValueError('four distinct RFC1918 peer addresses required')
    if len({h.get('region') for h in hosts}) != 1 or not hosts[0].get('region'):
        raise ValueError('initial pilot requires one explicitly named Alibaba region')
    if value.get('netem') is not None:
        raise ValueError('first pilot is unshaped; calibrated netem is a separate qualification gate')
    for host in hosts:
        if host['budget'].get('swap_bytes') != 0:
            raise ValueError('declare and verify swap_bytes=0 for every pilot host')
    return value


def create_plan(inventory, *, protocols=('delugi', 'raptr'), cases=CASES, repeats=1,
                bound_ms=100, transaction_bytes=128, timeout_seconds=120):
    validate_hosts(inventory)
    if (not protocols or len(set(protocols)) != len(protocols) or set(protocols) - {'delugi', 'raptr'}
            or not cases or len(set(cases)) != len(cases) or set(cases) - set(CASES)):
        raise ValueError('choose distinct implemented protocols and supported pilot cases')
    if type(repeats) is not int or not 1 <= repeats <= 3 or bound_ms != 100:
        raise ValueError('initial pilot requires1..3 repeats and Delta100ms')
    if type(transaction_bytes) is not int or not 1 <= transaction_bytes <= 4096 or not 30 <= timeout_seconds <= 180:
        raise ValueError('finite payload/runtime outside pilot envelope')
    identities = {(h.get('artifact', {}).get('binary_sha256'), h.get('artifact', {}).get('archive_sha256')) for h in inventory['hosts']}
    if len(identities) != 1 or any(None in pair for pair in identities):
        raise ValueError('every host must name the same published common artifact')
    for h in inventory['hosts']:
        a = h['artifact']
        if a['directory'] != '/tmp/delugi-common-' + a['archive_sha256']:
            raise ValueError('artifact directory must be content-addressed')
        raptr.hex_hash(a['archive_sha256']); raptr.hex_hash(a['binary_sha256'])
    result = {'schema': 1, 'kind': KIND, 'inventory': copy.deepcopy(inventory), 'protocols': list(protocols),
              'cases': list(cases), 'repeats': repeats, 'bound_ms': bound_ms, 'transaction_bytes': transaction_bytes,
              'timeout_seconds': timeout_seconds, 'added_delay_ms': 0, 'comparison_eligible': False,
              'storage_profile': 'shared-rocksdb-written-v1',
              'scope': 'finite distributed functional/lifecycle pilot; workload shapes differ; no throughput ranking',
              'ssh_inputs': {str(i): {name: sha(Path(h[name]).expanduser()) for name in ('identity_file', 'known_hosts_file')}
                             for i, h in enumerate(inventory['hosts'])}}
    result['plan_sha256'] = hash_json(result)
    return result


def validate_plan(plan):
    if plan.get('kind') != KIND:
        raise ValueError('unsupported campaign plan')
    expected = create_plan(plan['inventory'], protocols=plan['protocols'], cases=plan['cases'], repeats=plan['repeats'],
                           bound_ms=plan['bound_ms'], transaction_bytes=plan['transaction_bytes'], timeout_seconds=plan['timeout_seconds'])
    if expected != plan:
        raise ValueError('saved plan, placement or SSH inputs changed')
    return plan


class Connection(placement.Connection):
    def __init__(self, host, control_path=None):
        super().__init__(host)
        self.control_path = control_path

    def command(self, arguments, **kwargs):
        kwargs.setdefault('timeout', 60)
        if self.control_path is not None:
            options = ['-o', 'ControlMaster=auto', '-o', 'ControlPersist=60',
                       '-o', 'ControlPath='+str(self.control_path)]
            return subprocess.run(ssh_arguments(self.host)+options+[self.host['ssh'], shlex.join(arguments)],
                                  check=True, **kwargs)
        return super().command(arguments, **kwargs)

    def rpc(self, request):
        helper = self.host['artifact']['directory'] + '/source/scripts/common_cloud_worker.py'
        result = self.command([self.python(), helper], input=json.dumps(request), text=True, capture_output=True, timeout=40)
        if len(result.stdout) > 16*1024**2:
            raise ValueError('RPC reply exceeds bound')
        return json.loads(result.stdout)

    def preflight(self):
        artifact = self.host['artifact']['directory']
        result = self.command([self.python(), artifact + '/source/scripts/common_artifact.py', 'verify', '--directory', artifact, '--host',
                               '--archive',artifact+'.tar.gz','--archive-sha256',self.host['artifact']['archive_sha256']],
                              text=True, capture_output=True, timeout=180)
        value = json.loads(result.stdout)
        if value.get('binary_sha256') != self.host['artifact']['binary_sha256']:
            raise ValueError('installed artifact differs from plan')
        return value

    def collect(self, nonce, directory):
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        archive = directory / 'evidence.stream'
        helper = self.host['artifact']['directory'] + '/source/scripts/common_cloud_worker.py'
        with archive.open('xb') as stream:
            self.command([self.python(), helper], input=json.dumps({'action': 'export', 'nonce': nonce}).encode(),
                         stdout=stream, stderr=subprocess.PIPE, timeout=180)
        if archive.stat().st_size > 520*1024**2:
            raise ValueError('collected evidence exceeds pilot bound')
        extracted = directory / 'files'; extracted.mkdir(mode=0o700)
        with archive.open('rb') as stream:
            record = runtime_evidence.unpack(stream, extracted, expected_metadata={'nonce': nonce, 'format': 'common-pilot-evidence-v1'},
                                               max_files=100, max_payload_bytes=512*1024**2)
        save(directory / 'collection.json', record)
        return record


def configurations(plan, protocol, case, nonce, keys):
    root = worker.root_for(nonce)
    hosts = plan['inventory']['hosts']
    addresses = [h['advertised'] for h in hosts]
    if protocol == 'delugi':
        config = {'instance': list(bytes.fromhex(nonce + nonce)), 'addresses': addresses,
                  'control_addresses': ['127.0.0.1:' + str(h['control_port']) for h in hosts],
                  'control_token': secrets.token_hex(32), 'public_keys': keys['public']['public_keys'],
                  'key_files': [str(root/'keys'/f'replica-{i}.key') for i in range(4)],
                  'bound_ms': plan['bound_ms'], 'chunk_capacity': 4, 'workload_rounds': 4,
                  'silent': 0 if case == 'silent-first-leader' else None,
                  'max_runtime_ms': plan['timeout_seconds']*1000,
                  **delugi.ordering_options(plan['bound_ms']),
                  'storage_profile': plan['storage_profile'], 'storage_directory': str(root/'records')}
    else:
        counts = [16]*4
        if case == 'silent-first-leader': counts[1] = 0
        config = {'schema': 1, 'epoch': 1, 'run_id': nonce+nonce, 'addresses': addresses,
                  'deployment_profile': 'private-ipv4-n4-v1', 'key_directory': str(root/'keys'),
                  'output_directory': str(root/'replicas'), 'arm_path': str(root/'arm.json'),
                  'delta_ms': plan['bound_ms'], 'measurement_duration_ms': 5000, 'drain_ms': 5000,
                  'finite_workload': {'counts': counts, 'useful_bytes': plan['transaction_bytes'], 'interval_us': 1000, 'start_delay_ms': 100},
                  'limits': dict(raptr.DEFAULT_LIMITS, **raptr.EXECUTOR_LIMITS), 'materialization_delay_ms': 0, 'payload_fault': None}
    return config


def wait_for(function, predicate, deadline, label):
    while time.monotonic() < deadline:
        value = function()
        if predicate(value): return value
        time.sleep(.2)
    raise TimeoutError(label)


def finite_delugi(plan, config, hosts, rpc, directory, deadline):
    silent = config['silent']
    correct = [i for i in range(4) if i != silent]
    def many(kind, ids=range(4), **fields):
        return require_all(parallel([h for h in hosts if h['replica'] in ids],
                    lambda h: rpc(h, 'control', kind=kind, fields=fields)), 'Delugi '+kind)
    many('prepare')
    submitted = []
    def snapshots(): return {i: r['reply']['data'] for i, r in many('snapshot').items()}
    for round_number in range(1, 5):
        rows = many('submit', correct, round=round_number, count=2, size=plan['transaction_bytes'])
        submitted += [{'replica': i, 'round': round_number, 'transactions': r['reply']['data']['transactions']} for i, r in rows.items()]
        wait_for(snapshots, lambda rows: all(all(rows[i]['holding_heights'][p] >= round_number for p in correct) for i in correct),
                 deadline, 'Delugi payload preload did not complete')
    many('start')
    expected = [r for r in range(1, 5) if (r-1)%4 != silent]
    wait_for(snapshots, lambda rows: all(rows[i]['executed_rounds'] == expected and len(rows[i]['executed']) == 8*len(correct)
              and rows[i]['pending_materialization'] == 0 for i in correct), deadline, 'Delugi round4/recovery did not complete')
    many('quiesce')
    previous = None; stable = time.monotonic()
    while time.monotonic() < deadline:
        rows = snapshots()
        signature = hash_json({i:r['transport'] for i,r in rows.items()})
        if signature == previous and all(delugi.queued_frames(r) == 0 for r in rows.values()):
            if time.monotonic()-stable >= .2: break
        else: stable = time.monotonic()
        previous = signature
        time.sleep(.1)
    else: raise TimeoutError('Delugi transport drain did not complete')
    save(directory/'snapshots.json', rows); save(directory/'submitted.json', submitted)
    storage = delugi.validate_storage_snapshots(rows, plan['storage_profile'])
    traffic = delugi.aggregate_traffic(rows, silent)
    many('stop')
    return {'correct': correct, 'snapshots': rows, 'submitted': submitted, 'storage': storage, 'traffic': traffic,
            'latency': {'available': False, 'reason': 'preloaded finite fixture; cross-host wall-clock subtraction is not used'}}


def run_trial(plan, protocol, case, directory, connection_factory=Connection):
    directory = Path(directory); directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    hosts = plan['inventory']['hosts']; nonce = uuid.uuid4().hex
    connections = {h['replica']: connection_factory(h) for h in hosts}
    result = {'schema': 1, 'nonce': nonce, 'protocol': protocol, 'case': case, 'status': 'failed',
              'plan_sha256': plan['plan_sha256'], 'comparison_eligible': False}
    save(directory/'trial.json', result)
    def rpc(host, action, **fields):
        begin = time.monotonic_ns()
        try:
            value = connections[host['replica']].rpc(dict(action=action, nonce=nonce, **fields))
            return value
        finally:
            # No request body: key material and control tokens never enter command logs.
            record = {'replica': host['replica'], 'action': action, 'duration_ns': time.monotonic_ns()-begin}
            with (directory/f'controller-{host["replica"]}.jsonl').open('a') as out: out.write(json.dumps(record)+'\n')
    complete = False; correct = list(range(4)); config = None; epochs = None; finite = None
    try:
        result['preflight'] = require_all(parallel(hosts, lambda h: connections[h['replica']].preflight()), 'host preflight')
        keys = rpc(hosts[0], 'keygen', protocol=protocol, artifact=hosts[0]['artifact']['directory'], binary_sha256=hosts[0]['artifact']['binary_sha256'])
        public = directory/'public'; public.mkdir(mode=0o700)
        if protocol == 'raptr':
            for name in ('committee.json', 'genesis-ledger.bcs'):
                (public/name).write_bytes(bytes.fromhex(keys['files_hex'][name]))
        config = configurations(plan, protocol, case, nonce, keys)
        config_text = json.dumps(config, sort_keys=True, indent=2)+'\n'
        config_hash = hashlib.sha256(config_text.encode()).hexdigest()
        with os.fdopen(os.open(directory/'config.json', os.O_CREAT|os.O_EXCL|os.O_WRONLY, 0o600), 'w') as out: out.write(config_text)
        def prepare(h):
            i = h['replica']
            names = [f'replica-{i}.key'] if protocol == 'delugi' else [f'key-{i}.json', 'committee.json', 'genesis-ledger.bcs']
            return rpc(h, 'prepare', protocol=protocol, replica=i, artifact=h['artifact']['directory'],
                       binary_sha256=h['artifact']['binary_sha256'], configuration_sha256=config_hash,
                       config_text=config_text, keys_hex={name:keys['files_hex'][name] for name in names},
                       timeout_seconds=plan['timeout_seconds'], budget=h['budget'])
        result['prepared'] = require_all(parallel(hosts, prepare), 'all-host prepare')
        del keys
        result['started'] = require_all(parallel(hosts, lambda h: rpc(h,'start')), 'all-host start')
        deadline = time.monotonic()+plan['timeout_seconds']
        def readiness(): return parallel(hosts, lambda h: rpc(h,'ready'))
        result['ready'] = wait_for(readiness, lambda pair: not pair[1], min(deadline,time.monotonic()+30), 'all-host readiness expired')[0]
        if protocol == 'delugi':
            finite = finite_delugi(plan,config,hosts,rpc,directory,deadline)
            correct = finite['correct']
        else:
            if case == 'silent-first-leader':
                result['fault'] = rpc(hosts[1],'pause'); correct = [0,2,3]
            armed = require_all(parallel([h for h in hosts if h['replica'] in correct], lambda h: rpc(h,'arm')), 'all-host local arm')
            epochs = {i:r['epoch_us'] for i,r in armed.items()}
            result['host_epochs'] = epochs
        def statuses(): return require_all(parallel([h for h in hosts if h['replica'] in correct],lambda h:rpc(h,'status')), 'status')
        final = wait_for(statuses, lambda rows: all('resource-summary' in r for r in rows.values()), deadline, 'native processes did not finish')
        for row in final.values():
            summary = row['resource-summary']
            if summary.get('status') != 'completed' or not summary.get('cleanup_confirmed'):
                raise ValueError('native process or owned cleanup failed')
        result['native_finish'] = final
        if protocol == 'raptr':
            result['native_verification'] = require_all(parallel([h for h in hosts if h['replica'] in correct], lambda h: rpc(h,'verify')), 'signed receipt verification')
            if any(row.get('verified') is not True for row in result['native_verification'].values()):
                raise ValueError('native verifier did not confirm receipts')
        complete = True
    except BaseException as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        # Close every host, including failed/late prepares. No broad pkill/tmux kill.
        cleanup, errors = parallel(hosts,lambda h:rpc(h,'abort'))
        result['cleanup'], result['cleanup_errors'] = cleanup, errors
        if errors or any(not row.get('cleanup_confirmed') for row in cleanup.values()): complete = False
        collected, errors = parallel(hosts,lambda h:connections[h['replica']].collect(nonce,directory/f'host-{h["replica"]}'))
        result['collection'], result['collection_errors'] = collected, errors
        if errors: complete = False
    if complete:
        try:
            if protocol == 'delugi':
                events = {i:[json.loads(line) for line in (directory/f'host-{i}/files/node.stdout').read_text().splitlines() if line.strip()] for i in range(4)}
                result['correctness'] = delugi.verify_outputs(finite['snapshots'],correct,4,config['silent'],finite['submitted'],events)
                result.update(storage=finite['storage'],traffic=finite['traffic'],latency=finite['latency'])
            else:
                merged = directory/'replicas'; merged.mkdir()
                for i in correct:
                    shutil.copytree(directory/f'host-{i}/files/replicas/node-{i}',merged/f'node-{i}')
                result['validation'] = raptr.validate_results(config,correct,directory,config_hash,0,case,
                    require_executor=True, host_epochs=epochs, public_directory=directory/'public',replica_directory=merged)
            result['status'] = 'passed'
        except BaseException as error:
            result['error'] = f'collected evidence validation: {type(error).__name__}: {error}'
    save(directory/'trial.json',result)
    return result


@contextmanager
def campaign_connections():
    """Reuse authenticated SSH sessions in a private, campaign-owned directory.

    A fresh authentication for every polling/control action can exhaust a local
    signing agent or trigger connection throttling. No mutating RPC is retried:
    only its transport is reused. The strict host-key and identity options stay
    in force. Masters are closed on success and failure, with a bounded idle
    lifetime if the controller itself is killed.
    """
    with tempfile.TemporaryDirectory(prefix='delugi-ssh-', dir='/tmp') as temporary:
        root = Path(temporary)
        hosts = {}; lock = threading.Lock()
        def factory(host):
            identity = {key: host[key] for key in ('ssh', 'identity_file', 'known_hosts_file')}
            key = hash_json(identity)[:24]
            path = root/key
            with lock:
                hosts[key] = (copy.deepcopy(host), path)
            return Connection(host, path)
        try:
            yield factory
        finally:
            errors = []
            for host, path in hosts.values():
                if not path.exists():
                    continue
                try:
                    closed = subprocess.run(ssh_arguments(host)+['-S', str(path), '-O', 'exit', host['ssh']],
                                            capture_output=True, text=True, timeout=10)
                    if closed.returncode and path.exists():
                        errors.append(host['replica'])
                except Exception:
                    errors.append(host['replica'])
            if errors:
                raise RuntimeError(f'owned SSH session cleanup failed for replicas {errors}')


def campaign(plan, output, connection_factory=Connection):
    if connection_factory is Connection:
        with campaign_connections() as factory:
            return campaign(plan, output, factory)
    validate_plan(plan)
    output=Path(output).resolve();output.mkdir(mode=0o700,parents=True,exist_ok=False)
    save(output/'plan.json',plan)
    result={'schema':1,'kind':KIND,'plan_sha256':plan['plan_sha256'],'status':'running','trials':[], 'comparison_eligible':False}
    try:
        for repeat in range(plan['repeats']):
            for case in plan['cases']:
                # Alternate protocol order between repeats.
                protocols=plan['protocols'] if repeat%2==0 else list(reversed(plan['protocols']))
                for protocol in protocols:
                    validate_plan(plan)
                    directory=output/f'{repeat+1}-{protocol}-{case}'
                    row=run_trial(plan,protocol,case,directory,connection_factory)
                    result['trials'].append({'protocol':protocol,'case':case,'status':row['status'],'path':str(directory/'trial.json')})
                    save(output/'campaign.json',result)
                    if row['status']!='passed': raise RuntimeError('pilot case failed; remaining cases were not launched')
        result['status']='passed'
    except BaseException as error:
        result.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        save(output/'campaign.json',result)
    return result


def publish(inventory, archive, expected_sha, binary_sha, output, connection_factory=Connection):
    validate_hosts(inventory)
    if sha(archive)!=expected_sha: raise ValueError('publication archive changed')
    raptr.hex_hash(binary_sha)
    root='/tmp/delugi-common-'+expected_sha
    output=Path(output);output.mkdir(mode=0o700,parents=True,exist_ok=False)
    # Bootstrap is stdlib only; full source/receipt verification follows extraction.
    bootstrap='''import hashlib,os,sys,tarfile
from pathlib import Path
archive,root,expected=sys.argv[1:];root=Path(root)
with open(archive,'rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!=expected: raise ValueError('archive hash differs')
if root.exists():
 if root.is_symlink() or (root/'archive.sha256').read_text()!=expected: raise ValueError('publication path belongs to another upload')
 sys.exit(0)
root.mkdir(mode=0o700)
with tarfile.open(archive,'r:gz') as t:
 seen=set();total=0
 for m in t:
  if not m.isfile() or m.name in seen or m.name.startswith('/') or '\\\\' in m.name or any(p in ('','.','..') for p in m.name.split('/')): raise ValueError('unsafe publication')
  seen.add(m.name);total+=m.size
  if len(seen)>2049 or total>2*1024**3: raise ValueError('publication exceeds bounds')
  t.extract(m,root,filter='data')
os.chmod(root/'node',0o700)
(root/'archive.sha256').write_text(expected)
'''
    def one(host):
        connection=connection_factory(host)
        incoming=root+'.tar.gz'
        connection.upload(archive,incoming)
        connection.command([connection.python(),'-c',bootstrap,incoming,root,expected_sha],capture_output=True,timeout=180)
        h=copy.deepcopy(host);h['artifact']={'directory':root,'archive_sha256':expected_sha,'binary_sha256':binary_sha}
        check=connection_factory(h).preflight()
        save(output/f'host-{h["replica"]}.json',check)
        return h
    hosts, errors=parallel(inventory['hosts'],one)
    result={'schema':1,'status':'failed' if errors else 'published','hosts':[hosts[i] for i in sorted(hosts)],'errors':errors,
            'comparison_eligible':False}
    save(output/'inventory.json',result)
    if errors: raise RuntimeError(f'publication incomplete; successful copies retained: {errors}')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    campaign=commands.add_parser('campaign',help='resolve the compact one-minute campaign without cloud operations')
    campaign.add_argument('--config',type=Path,required=True)
    campaign.add_argument('--plan',action='store_true',required=True)
    campaign.add_argument('--output',type=Path)
    lease=commands.add_parser('instances',help='exact-ID lease create/status/start/stop/delete')
    lease.add_argument('action',choices=('initialize','launch','refresh','peers','start','stop','destroy'))
    lease.add_argument('--state',type=Path,required=True);lease.add_argument('--plan',type=Path)
    lease.add_argument('--amount',type=int);lease.add_argument('--execute',action='store_true')
    hosts=commands.add_parser('inventory',help='import exact instance IDs from a saved Loom-format inventory')
    hosts.add_argument('--settings',type=Path,required=True);hosts.add_argument('--saved-inventory',type=Path,required=True)
    hosts.add_argument('--instance-ids',nargs='+',required=True);hosts.add_argument('--known-hosts',type=Path,required=True)
    hosts.add_argument('--memory-bytes',type=int,required=True);hosts.add_argument('--cpus',default='0,1,2,3')
    hosts.add_argument('--python-executable',default='/usr/bin/python3');hosts.add_argument('--output',type=Path,required=True)
    build_plan=commands.add_parser('build-plan',help='prepare a pinned Linux build on one existing host; no SSH')
    build_plan.add_argument('--inventory',type=Path,required=True);build_plan.add_argument('--revision',required=True)
    build_plan.add_argument('--replica',type=int,default=0);build_plan.add_argument('--output',type=Path,required=True)
    build_plan.add_argument('--install-system-packages',action='store_true')
    for name in ('build','build-status','build-collect'):
        command=commands.add_parser(name)
        command.add_argument('--plan',type=Path,required=True);command.add_argument('--execute',action='store_true')
        command.add_argument('--output',type=Path)
    pub=commands.add_parser('publish',help='upload and verify one Linux common artifact on all four hosts')
    pub.add_argument('--inventory',type=Path,required=True);pub.add_argument('--publication',type=Path,required=True)
    pub.add_argument('--output',type=Path,required=True);pub.add_argument('--execute',action='store_true')
    configure=commands.add_parser('configure',help='freeze a finite protocol/case/repeat matrix; no SSH')
    configure.add_argument('--inventory',type=Path,required=True);configure.add_argument('--output',type=Path,required=True)
    configure.add_argument('--protocols',nargs='+',default=['delugi','raptr']);configure.add_argument('--cases',nargs='+',default=list(CASES))
    configure.add_argument('--repeats',type=int,default=1);configure.add_argument('--transaction-bytes',type=int,default=128)
    run=commands.add_parser('run');run.add_argument('--plan',type=Path,required=True);run.add_argument('--output',type=Path,required=True)
    run.add_argument('--execute',action='store_true')
    for name in ('status','stop','collect'):
        action=commands.add_parser(name)
        action.add_argument('--plan',type=Path,required=True);action.add_argument('--trial',type=Path,required=True)
        action.add_argument('--execute',action='store_true');action.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.command=='campaign':
        import compact_campaign
        result=compact_campaign.create_plan(json.loads(args.config.read_text()))
        if args.output is not None:
            if args.output.exists(): raise ValueError('choose a new immutable campaign plan path')
            save(args.output,result)
    elif args.command=='instances':
        if not args.execute:
            result={'status':'dry-run','action':args.action,'state':str(args.state),'no_cloud_api_called':True}
        elif args.action=='initialize':
            with cloud.lease_lock(args.state):
                if args.state.exists() or args.plan is None: raise ValueError('new state and reviewed plan required')
                cloud.save(args.state,{'run_id':uuid.uuid4().hex[:16],'plan':cloud.validate_plan(json.loads(args.plan.read_text()))})
            result={'status':'initialized; no resources created'}
        else:
            value=cloud.Lease(args.state)
            result=value.launch(args.amount) if args.action=='launch' else getattr(value,args.action)()
    elif args.command=='inventory':
        result=placement.hosts_from_loom(args.settings,args.saved_inventory,args.instance_ids,args.known_hosts,
                    cpus=tuple(map(int,args.cpus.split(','))),memory_bytes=args.memory_bytes,python_executable=args.python_executable)
        for host in result['hosts']: host['budget']['swap_bytes']=0
        validate_hosts(result);save(args.output,result)
    elif args.command=='build-plan':
        if args.output.exists(): raise ValueError('choose a new immutable build plan path')
        result=builder.make_plan(json.loads(args.inventory.read_text()),args.revision,args.replica,args.install_system_packages)
        save(args.output,result)
    elif args.command in ('build','build-status','build-collect'):
        plan=builder.validate(json.loads(args.plan.read_text()),dispatch=args.command=='build')
        if not args.execute:
            result={'status':'dry-run','action':args.command,'plan':plan,'no_ssh':True}
        else:
            connection=Connection(plan['host'])
            if args.command=='build': result=builder.dispatch(plan,connection)
            elif args.command=='build-status': result=builder.status(plan,connection)
            else:
                if args.output is None: raise ValueError('new local output directory required')
                result=builder.collect(plan,connection,args.output)
    elif args.command=='publish':
        record=json.loads(args.publication.read_text());inventory=json.loads(args.inventory.read_text())
        validate_hosts(inventory)
        result=(publish(inventory,record['archive'],record['sha256'],record['binary_sha256'],args.output) if args.execute
                else {'status':'dry-run','hosts':len(inventory['hosts']),'publication':record,'no_ssh':True})
    elif args.command=='configure':
        if args.output.exists(): raise ValueError('choose a new immutable plan path')
        result=create_plan(json.loads(args.inventory.read_text()),protocols=args.protocols,cases=args.cases,repeats=args.repeats,
                           transaction_bytes=args.transaction_bytes)
        save(args.output,result)
    elif args.command=='run':
        plan=validate_plan(json.loads(args.plan.read_text()))
        result=campaign(plan,args.output) if args.execute else {'status':'dry-run','plan':plan,'no_ssh':True}
    else:
        plan=validate_plan(json.loads(args.plan.read_text()));trial=json.loads(args.trial.read_text())
        if trial['plan_sha256']!=plan['plan_sha256']:raise ValueError('trial belongs to another plan')
        if not args.execute: result={'status':'dry-run','action':args.command,'nonce':trial['nonce'],'no_ssh':True}
        else:
            if args.command=='collect' and (args.output is None or args.output.exists()): raise ValueError('collection requires a new output directory')
            def action(h):
                connection=Connection(h)
                return (connection.collect(trial['nonce'],args.output/f'host-{h["replica"]}') if args.command=='collect'
                        else connection.rpc({'action':'abort' if args.command=='stop' else 'status','nonce':trial['nonce']}))
            values,errors=parallel(plan['inventory']['hosts'],action)
            result={'hosts':values,'errors':errors,'status':'failed' if errors else 'completed'}
    print(json.dumps(result,indent=2))
    return 1 if isinstance(result,dict) and result.get('status')=='failed' else 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # SDK errors can contain signed credential-bearing request details.
        print(json.dumps({'status':'failed','error_type':type(error).__name__,
                          'error_code':getattr(error,'code',None),
                          'message':str(error) if isinstance(error,(ValueError,RuntimeError)) else 'operation failed; retained evidence/state must be inspected'}))
        raise SystemExit(1)
