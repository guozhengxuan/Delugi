"""Shared-service sustained adapters on published, independently owned hosts.

Uses the same workload/verifiers as local runs. Each Raptr host chooses its own
monotonic epoch after the whole committee is ready. Signed configuration files
are never rewritten to make remote evidence look like a local run.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
import json
from pathlib import Path
import shutil
import time
import uuid

import aliyun_bench as cloud
import common_cloud_worker as worker
import deployment_prepare as prep
import run_raptr_sustained as raptr
import run_sustained as delugi
from remote_deployment import RemoteDeployment
from native_network import NativeNetwork, observed_wan


def network_settings(effective, mode='controlled'):
    result = {'delay_ms': effective['network']['added_one_way_delay_ms'],
              'rate_mbps': effective['network']['validator_egress_mbps']}
    if mode != 'controlled':
        result['mode'] = mode
    observed_wan(result)  # Reject unknown modes or a silently ignored delay.
    return result


def every(hosts, function):
    """Dispatch the whole committee concurrently and inspect every completion."""
    values, errors = {}, {}
    with ThreadPoolExecutor(max_workers=len(hosts)) as pool:
        futures={pool.submit(function,h):h['replica'] for h in hosts}
        for future in as_completed(futures):
            i=futures[future]
            try:values[i]=future.result()
            except Exception as error:errors[i]=f'{type(error).__name__}: {error}'
    return values,errors


def all_ok(hosts, function, label):
    values,errors=every(hosts,function)
    if errors:raise RuntimeError(f'{label}: {errors}')
    return values


class DelugiDeployment(RemoteDeployment):
    """Existing Delugi streaming control plus the shared aggregate egress tree."""
    def __init__(self, inventory):
        super().__init__(inventory)
        self.aggregate=self.inventory['netem']['rate_mbps']
        self.shared_storage=True
    egress_rpc=NativeNetwork.egress_rpc
    configure_network=NativeNetwork.configure_network
    clear_network=NativeNetwork.clear_network


def run_delugi(resolved, inventory, verifier, output, *, network_mode='controlled'):
    from run_network import verify_shared_delugi_build, archive_shared_delugi_build
    from spec_provenance import archive_spec, verify_spec_unchanged
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    binary=Path(verifier['binary']);receipt=Path(verifier['build_receipt'])
    verify_shared_delugi_build(binary,receipt,delugi.STORAGE_PROFILES[1])
    artifact=archive_shared_delugi_build(binary,receipt,output/'artifact',delugi.STORAGE_PROFILES[1])
    spec=resolved['requested']['specification']
    # This is the selected archived specification, not the current paper draft.
    selected=archive_spec(prep.ROOT/spec['manifest'],output/'specification',prep.ROOT/spec['paper_repository'])
    e=resolved['effective'];hosts=copy.deepcopy(inventory)
    hosts['netem']=network_settings(e, network_mode)
    for h in hosts['hosts']:
        h['binary']={'path':h['artifact']['directory']+'/node','sha256':h['artifact']['binary_sha256']}
    case=resolved['case'];fault={}
    if case=='missing-data':fault=dict(fault_replica=0,fault_after=0,fault_duration=e['duration']['measure_s'],fault_peers=[1],
        fault_batches=3,fault_batch_transactions=1,fault_payload_bytes=e['useful_transaction_bytes'])
    result=delugi.run_trial(binary,output/'trial',e['total_honest_input_tps'],0,e['duration']['measure_s'],
        useful_bytes=e['useful_transaction_bytes'],batch_ms=e['batching']['max_wait_ms'],
        max_batch_transactions=e['batching']['max_transactions'],bound_ms=e['timing']['Delta_ms'],
        drain_seconds=e['duration']['drain_s'],nodes=resolved['nodes'],resource_profile=e['resource_profile'],
        global_arrivals=True,silent_first_leader=case=='silent-first-leader',
        report_schedule=e.get('report_schedule','history_ready'),causal_trace=e.get('causal_trace'),
        storage_profile=delugi.STORAGE_PROFILES[1],
        deployment=DelugiDeployment(hosts),transport=e.get("transport"),
        arrival_queue_capacity=e.get("arrival_queue_capacity",65536),**fault)
    result['artifact']=artifact;result['specification']=selected
    verify_shared_delugi_build(binary,receipt,delugi.STORAGE_PROFILES[1])
    verify_spec_unchanged(selected)
    # archive_spec records its source identities; the campaign also revalidates
    # the selected snapshot before every trial.
    prep.json_file(output/'result.json',result)
    return result


def run_raptr(resolved, inventory, output, connection_factory=cloud.Connection, *, network_mode='controlled'):
    if connection_factory is cloud.Connection:
        with cloud.campaign_connections() as factory:
            return run_raptr(resolved, inventory, output, factory, network_mode=network_mode)
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    hosts=copy.deepcopy(inventory['hosts']);n=resolved['nodes'];e=resolved['effective']
    if len(hosts)!=n or n not in (4,10,50):raise ValueError('exact sustained committee required')
    nonce=uuid.uuid4().hex;root=worker.root_for(nonce)
    case={'missing-data':'missing-payload-recovery'}.get(resolved['case'],resolved['case'])
    config=raptr.make_config(root,nodes=n,rate=e['total_honest_input_tps'],duration_ms=e['duration']['measure_s']*1000,
        drain_ms=e['duration']['drain_s']*1000,useful_bytes=e['useful_transaction_bytes'],
        delta_ms=e['timing']['Delta_ms'],case=case,addresses=[h['advertised'] for h in hosts],
        transport=e.get('transport'),node_options=e.get('node_options'))
    config.update(run_id=nonce+nonce,key_directory=str(root/'keys'),output_directory=str(root/'replicas'),
        arm_path=str(root/'arm.json'),addresses=[h['advertised'] for h in hosts],
        deployment_profile='private-ipv4-n4-v1' if n==4 else 'private-ipv4-n10-n50-v1')
    raw=json.dumps(config,sort_keys=True)+'\n';config_hash=cloud.hashlib.sha256(raw.encode()).hexdigest()
    (output/'config.json').write_text(raw)
    correct=[i for i in range(n) if not (case=='silent-first-leader' and i==1)]
    connections={h['replica']:connection_factory(h) for h in hosts}
    selected=[h for h in hosts if h['replica'] in correct]
    result={'schema':1,'status':'failed','nonce':nonce,'correct_replicas':correct,
        'configuration_sha256':config_hash,'comparison_eligible':False,'cleanup':{}}
    requests={};network=None
    def rpc(h,action,**fields):return connections[h['replica']].rpc({'action':action,'nonce':nonce,**fields})
    try:
        result['preflight']=all_ok(hosts,lambda h:connections[h['replica']].preflight(),'common publication')
        keys=rpc(hosts[0],'keygen',protocol='raptr',artifact=hosts[0]['artifact']['directory'],
            binary_sha256=hosts[0]['artifact']['binary_sha256'],nodes=n,evaluation_profile=worker.COMPACT)
        public=output/'public';public.mkdir(mode=0o700)
        for name in ('committee.json','genesis-ledger.bcs'):(public/name).write_bytes(bytes.fromhex(keys['files_hex'][name]))
        for h in hosts:
            i=h['replica'];a=h['artifact']
            requests[i]={'evaluation_profile':worker.COMPACT,'protocol':'raptr','replica':i,
                'artifact':a['directory'],'binary_sha256':a['binary_sha256'],'config_text':raw,
                'configuration_sha256':config_hash,'budget':h['budget'],'timeout_seconds':600,
                'keys_hex':{name:keys['files_hex'][name] for name in (f'key-{i}.json','committee.json','genesis-ledger.bcs')}}
        # Upload exactly the source-bound helper runtime from the publication;
        # NativeNetwork uses its fixed relative location for calibration tools.
        for h in hosts:
            c=connections[h['replica']]
            c.command([c.python(),'-c',
                'import os,sys;from pathlib import Path;p=Path(sys.argv[1]);p.mkdir(exist_ok=True,mode=0o700);os.symlink(sys.argv[2],p/"controller")',
                str(root),h['artifact']['directory']+'/source'],capture_output=True)
        endpoints=[{'replica':h['replica'],'peer':[{'ip':h['advertised'].rsplit(':',1)[0],
            'port':int(h['advertised'].rsplit(':',1)[1])}]} for h in hosts]
        # NativeNetwork requires declared binary metadata for inventory validation.
        for h in hosts:h['binary']={'path':h['artifact']['directory']+'/node','sha256':h['artifact']['binary_sha256']}
        network=NativeNetwork({'hosts':hosts,'nonce':nonce,'endpoints':endpoints,
            'network':network_settings(e, network_mode)},root,connections)
        result['network']=network.configure_network()
        result['prepared']=all_ok(hosts,lambda h:rpc(h,'prepare',**requests[h['replica']]),'prepare')
        # Do not retain controller copies of private ceremony keys in any receipt.
        for request in requests.values():request.pop('keys_hex',None)
        keys=None
        result['started']=all_ok(hosts,lambda h:rpc(h,'start'),'start')
        def wait_ready(h):
            deadline=time.monotonic()+240
            while time.monotonic()<deadline:
                try:return rpc(h,'ready')
                except Exception:
                    state=rpc(h,'status')
                    if 'resource-summary' in state:raise RuntimeError('replica exited before ready')
                    time.sleep(.2)
            raise TimeoutError('native preparation deadline')
        result['ready']=all_ok(hosts,wait_ready,'committee readiness')
        if case=='silent-first-leader':result['pause']=rpc(hosts[1],'pause')
        result['arm']=all_ok(selected,lambda h:rpc(h,'arm'),'arm')
        def completion(h):
            deadline=time.monotonic()+100
            while time.monotonic()<deadline:
                state=rpc(h,'status');summary=state.get('resource-summary')
                if summary:
                    if summary.get('status')!='completed' or not summary.get('cleanup_confirmed'):
                        raise RuntimeError('native sustained completion/cleanup failed')
                    return summary
                time.sleep(.5)
            raise TimeoutError('native measurement/drain did not finish')
        result['completion']=all_ok(selected,completion,'finite completion')
        result['authentication']=all_ok(selected,lambda h:rpc(h,'verify'),'typed receipt verification')
        if case=='silent-first-leader':
            # Reconfirm exact stopped process identity before waking it for cleanup.
            result['pause_at_end']=rpc(hosts[1],'pause')
            result['cleanup'][1]=rpc(hosts[1],'abort')
        result['collection']=all_ok(selected,lambda h:connections[h['replica']].collect(nonce,output/f'host-{h["replica"]}',compact=True),'evidence export')
        replicas=output/'replicas';replicas.mkdir()
        for i in correct:
            collected=output/f'host-{i}'/'files'
            if (collected/'config.json').read_bytes()!=raw.encode():raise ValueError('remote signed configuration differs')
            if json.loads((collected/'verification.json').read_text())!=result['authentication'][i]:raise ValueError('verification reply differs from frozen host evidence')
            shutil.copytree(collected/'replicas'/f'node-{i}',replicas/f'node-{i}')
        before=raptr.bound_files(config,correct,replica_directory=replicas)
        result['reduction']=raptr.normalize(config,correct,output,case,replica_directory=replicas,public_directory=public)
        if config.get('latency_trace') is not None:
            from raptr_latency_decomposition import analyze
            result['latency_decomposition']=analyze(output/'config.json',replicas,correct,
                authentication=result['authentication'])
        if before!=raptr.bound_files(config,correct,replica_directory=replicas):raise ValueError('evidence changed during reduction')
        result['evidence']=before;result['status']='completed'
    except BaseException as error:result.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        clean,errors=every(hosts,lambda h:rpc(h,'abort'))
        result['cleanup'].update(clean)
        if errors or any(not row.get('cleanup_confirmed') for row in clean.values()):
            result.update(status='failed',cleanup_errors=errors or {'confirmation':'owned group cleanup missing'})
        if network:
            try:network.clear_network()
            except Exception as error:result.update(status='failed',network_cleanup_error=str(error))
            result['network']=network.network_evidence
        prep.json_file(output/'result.json',result)
    return result
