"""Restartable compact campaign: owned fleet -> publication -> runs -> cleanup.

Paid operations occur only in Backend.acquire, after every configuration,
artifact and lease has been checked. A recorded in-flight run is never silently
rerun. Failed and zero-output runs stay in the common table.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import copy
import csv
import hashlib
import json
import os
import subprocess
import tarfile
import time
import uuid

import alibaba_deployment as cloud
import aliyun_bench
import campaign_adapters as adapters
import compact_campaign as contract
import deployment_prepare as prep
import remote_native

KIND='delugi-compact-execution-v1'
NATIVE={'mysticeti-c':'mysticeti','autobahn':'autobahn','simpleit-mempool':'simpleit-mempool','simpleit-dispersed':'simpleit-dispersed'}


def read(path):
    path=Path(path).expanduser().resolve()
    if not path.is_file() or path.stat().st_size>16*1024**2:raise ValueError('bounded configuration file required')
    return json.loads(path.read_text())


def file_binding(path):
    path=Path(path).expanduser().resolve()
    return {'path':str(path),'sha256':prep.sha(path)}


def native_settings(resolved):
    e=resolved['effective'];p=resolved['protocol'];case=resolved['case'];n=resolved['nodes']
    result={'rate':e['total_honest_input_tps'],'useful_bytes':e['useful_transaction_bytes'],
        'warmup':0,'duration':60,'drain':e['duration']['drain_s'],'bound_ms':e['timing']['Delta_ms'],
        'population_profile':adapters.NATIVE,'faulty':e['faulty_identities'],
        'network':{'delay_ms':e['network']['added_one_way_delay_ms'],'rate_mbps':e['network']['validator_egress_mbps']}}
    if p.startswith('simpleit'):
        result.update(case=case,batch_bytes=e['batching']['useful_bytes_target'])
    elif p=='autobahn':result.update(batch_bytes=e['batching']['native_batch_bytes'],batch_ms=e['batching']['max_wait_ms'])
    else:result['batch_ms']=e['batching']['ingress_wakeup_ms']
    if case=='silent-first-leader':result['case']=case
    elif case=='missing-data' and not p.startswith('simpleit'):
        result.update(omit_replica=0,omission_after=0,omission_seconds=60,publish_to_replica=list(range(2,n)))
    remote_native.native.settings({k:v for k,v in result.items() if k!='network'},n,NATIVE[p])
    return result


def validate_artifacts(config,catalog):
    needed=({'common'} if set(config['protocols'])&{'delugi','raptr'} else set())|{p for p in config['protocols'] if p in NATIVE}
    if set(catalog)!=needed:raise ValueError('artifact catalog must cover exactly the selected implementations')
    bindings={}
    for p,item in catalog.items():
        if p=='common':
            if set(item)!= {'publication','local_verifier'}:raise ValueError('common publication and local Delugi verifier required')
            publication=read(item['publication']);archive=Path(publication['archive'])
            if prep.sha(archive)!=publication['sha256']:raise ValueError('common artifact archive changed')
            # Bounded source/role check before cloud APIs. Full binary, receipt,
            # loader and archived dependency verification also runs on each host.
            with tarfile.open(archive,'r:gz') as incoming:
                m=incoming.getmember('manifest.json')
                if not m.isfile() or m.size>4*1024**2:raise ValueError('invalid common publication manifest')
                manifest=json.load(incoming.extractfile(m))
                if manifest.get('profile')!='release' or manifest.get('protocols')!=['delugi','raptr'] or manifest.get('machine')!='x86_64':
                    raise ValueError('Alibaba g9i requires the common x86_64 Linux release artifact')
                if manifest['binary_sha256']!=publication['binary_sha256']:raise ValueError('publication node hash differs')
                native_stamp=json.load(incoming.extractfile('build-receipt.json'))
                if 'rocksdb-records' not in native_stamp.get('compiled_features',{}).get('delugi-core',[]):
                    raise ValueError('common Linux publication must include Delugi shared RocksDB records')
                for name in remote_native.RUNTIME_FILES:
                    if not name.endswith('.py'):continue
                    if manifest['files'].get('source/'+name,{}).get('sha256')!=prep.sha(prep.ROOT/name):
                        raise ValueError('common publication predates the selected campaign runtime: '+name)
            from run_network import verify_shared_delugi_build
            verifier=item['local_verifier']
            if set(verifier)!= {'binary','build_receipt'}:raise ValueError('explicit local verifier binary/receipt required')
            stamp,_=verify_shared_delugi_build(Path(verifier['binary']),Path(verifier['build_receipt']),'shared-rocksdb-written-v1')
            for name,sha in stamp['sources'].items():
                if manifest['files'].get('source/'+name,{}).get('sha256')!=sha:raise ValueError('local verifier and Linux core sources differ')
            bindings[p]={'publication':file_binding(item['publication']),'archive':file_binding(archive),
                'local_verifier':{key:file_binding(value) for key,value in verifier.items()}}
        else:
            if set(item)!= {'archive'}:raise ValueError('native artifact requires one built archive')
            manifest,_=prep.archived_manifest(item['archive'])
            if manifest.get('kind')!='delugi-built-artifacts' or manifest['receipt']['protocol']!=NATIVE[p]:
                raise ValueError('native publication role differs')
            pin=remote_native.pin_for(NATIVE[p])
            with tarfile.open(item['archive']) as incoming:
                for binary in manifest['receipt']['binaries']:
                    name='artifacts/'+binary['name']
                    with incoming.extractfile(name) as stream:header=stream.read(20)
                    if header[:6]!=b'\x7fELF\x02\x01' or header[18:20]!=b'\x3e\x00':
                        raise ValueError('native publication must be Linux x86_64')
                    stamp=json.load(incoming.extractfile(name+'.build.json'))
                    provenance=stamp.get('provenance',{})
                    if any(provenance.get(k)!=pin[k] for k in ('commit','patch_sha256')):
                        raise ValueError('native publication source pin/patch differs from this campaign')
            # Native runtime is installed independently for each run; source pins
            # and patch hashes are additionally checked by remote_native preflight.
            bindings[p]={'archive':file_binding(item['archive'])}
    return bindings


def validate_authorization(plan,authorization):
    contract.fields(authorization,('schema','kind','plan_sha256','catalog','fleets'),'execution authorization')
    if authorization['schema']!=1 or authorization['kind']!=KIND or authorization['plan_sha256']!=plan['plan_sha256']:
        raise ValueError('execution authorization must bind this exact campaign plan')
    if set(authorization['fleets'])!={str(n) for n in plan['config']['committees']}:raise ValueError('one owned fleet lease per selected committee required')
    bindings=validate_artifacts(plan['config'],read(authorization['catalog']))
    leases={}
    for key,fleet in authorization['fleets'].items():
        contract.fields(fleet,('lease_plan','lease_state','ssh'),'fleet')
        selected=cloud.validate_plan(read(fleet['lease_plan']))
        if selected.get('profile')!=adapters.NATIVE or selected['maximum_instances']!=int(key):
            raise ValueError('lease must bind the exact compact committee')
        if selected['region']!='ap-southeast-1':raise ValueError('first compact deployment is Singapore')
        ssh=fleet['ssh']
        contract.fields(ssh,('user','identity_file','known_hosts_file','python_executable','network_interface','host_key_policy'),'SSH placement')
        if ssh['host_key_policy'] not in ('pretrusted','first-use-owned-address'):
            raise ValueError('declare pretrusted host keys or first-use trust at exact provider-owned addresses')
        if ssh['user']!='root' or not Path(ssh['identity_file']).expanduser().is_file():raise ValueError('reviewed root SSH identity required')
        if not Path(ssh['python_executable']).is_absolute() or not ssh['network_interface']:raise ValueError('explicit interpreter/interface required')
        if Path(fleet['lease_state']).exists():
            state=read(fleet['lease_state'])
            if state['plan']!=selected:raise ValueError('existing lease state belongs to another plan')
        # Read and validate the aggregate ledger before an SDK is instantiated.
        from campaign_budget import Ledger
        ledger=Ledger(selected['campaign_budget']['path'])
        with ledger.locked():
            state=ledger._load()
            if state['authorization_sha256']!=selected['campaign_budget']['authorization_sha256']:raise ValueError('campaign spending evidence differs')
        leases[key]=file_binding(fleet['lease_plan'])
    adapters.resolve_plan(plan)
    for p in NATIVE:
        if p in plan['config']['protocols']:
            for n in plan['config']['committees']:
                for case in ['healthy',*plan['config']['fault_cases']]:native_settings(adapters.resolve(plan['config'],p,n,plan['config']['total_honest_input_tps'][0],case))
    return {'catalog':file_binding(authorization['catalog']),'artifacts':bindings,'leases':leases,
        'runtime':{p:prep.sha(prep.ROOT/p) for p in remote_native.RUNTIME_FILES}}


def metrics(result, protocol=None):
    import campaign_traffic
    reduced=result.get('reduction',result)
    cohort=reduced.get('cohort')
    if cohort is None:return None
    w=cohort['window'];scheduled=cohort['scheduled'];admitted=cohort['admitted'];completed=cohort['completed']
    lat=cohort['admission_to_output']
    return {'scheduled':scheduled,'admitted':admitted,'completed':completed,'unfinished':cohort['unfinished'],
        'admission_fraction':admitted/scheduled if scheduled else 0,'completion_fraction':completed/scheduled if scheduled else 0,
        'goodput_tps':w['unique_completion_tps'],'pending_at_end':w['pending_at_end'],
        'p50_ms':lat['p50']['value_ms'],'p95_ms':lat['p95']['value_ms'],'p99_ms':lat['p99']['value_ms'],
        'p95_status':lat['p95']['status'],'stability':w.get('stability'),
        **campaign_traffic.normalize(protocol,result)}


def accepted(row):
    m=row.get('metrics')
    if row['status'] not in ('completed','passed') or not m or m['admission_fraction']<.99 or m['completion_fraction']<.99:return False
    samples=(m.get('stability') or {}).get('samples',[])
    if len(samples)!=11:return False
    # At most1% of the thirty-second offered population accumulating during the
    # second half. Fixed startup backlog is not interpreted as sustained growth.
    return samples[-1]['pending_admitted']-samples[5]['pending_admitted']<=row['rate']*30*.01


def fault_rate(rows,config,nodes):
    common=[]
    for rate in config['total_honest_input_tps']:
        selected=[r for r in rows if r['nodes']==nodes and r['case']=='healthy' and r['rate']==rate]
        if {r['protocol'] for r in selected}==set(config['protocols']) and all(accepted(r) for r in selected):common.append(rate)
    if not common:return None
    # Choose one common accepted point below the largest accepted point when
    # possible. No per-protocol load tuning is hidden in fault comparisons.
    return common[-2] if len(common)>1 else common[0]


def table(rows,path):
    fields=['trial_id','protocol','nodes','case','rate','status','scheduled','admitted','completed','unfinished',
        'admission_fraction','completion_fraction','goodput_tps','pending_at_end','p50_ms','p95_ms','p99_ms','p95_status',
        'traffic_measurement_written_bytes','traffic_sampled_total_written_bytes','traffic_window_quality','traffic_boundary','error']
    with Path(path).open('w',newline='') as out:
        writer=csv.DictWriter(out,fieldnames=fields,extrasaction='ignore');writer.writeheader()
        for row in rows:writer.writerow({**row,**(row.get('metrics') or {})})


def retain_unrun(state, plan):
    """Keep every selected cell visible when a bounded campaign stops early."""
    done={row['trial_id'] for row in state['rows']}
    for trial in plan['trials']:
        if trial['id'] not in done:
            state['rows'].append({'trial_id':trial['id'],'protocol':trial['protocol'],
                'nodes':trial['nodes'],'case':trial['case'],'rate':trial['total_honest_input_tps'],
                'status':'not_run','error':'campaign stopped before dispatch'})


class Backend:
    def __init__(self,authorization,root):
        self.authorization=authorization;self.root=Path(root);self.catalog=read(authorization['catalog'])
        self.leases={};self.inventories={};self.publications={}

    def acquire(self,nodes):
        fleet=self.authorization['fleets'][str(nodes)];path=Path(fleet['lease_state']).expanduser().resolve()
        with cloud.lease_lock(path):
            if not path.exists():cloud.save(path,{'run_id':uuid.uuid4().hex[:16],'plan':cloud.validate_plan(read(fleet['lease_plan']))})
        lease=cloud.Lease(path);self.leases[nodes]=lease
        if lease.state.get('closed'):raise ValueError('closed fleet cannot be reopened; authorize a new lease identity')
        if not lease.state.get('batches') or any('ids' not in b for b in lease.state['batches']):lease.launch(nodes)
        deadline=time.monotonic()+600
        while time.monotonic()<deadline:
            instances=lease.refresh()
            if len(instances)==nodes and all(i['Status']=='Running' and i.get('PublicIpAddress',{}).get('IpAddress') for i in instances):break
            time.sleep(5)
        else:raise TimeoutError('owned fleet did not become ready')
        lease.peers();ssh=fleet['ssh'];known=Path(ssh['known_hosts_file']).expanduser().resolve()
        hosts=[]
        for i,item in enumerate(sorted(instances,key=lambda r:r['InstanceId'])):
            public=item['PublicIpAddress']['IpAddress'][0];private=item['VpcAttributes']['PrivateIpAddress']['IpAddress'][0]
            host={'replica':i,'instance_id':item['InstanceId'],'region':lease.plan['region'],
                'ssh':ssh['user']+'@'+public,'advertised':private+':8000','control_port':8001,
                'identity_file':str(Path(ssh['identity_file']).expanduser().resolve()),'known_hosts_file':str(known),
                'python_executable':ssh['python_executable'],'network_interface':ssh['network_interface'],
                'budget':{'cpus':[0,1,2,3],'memory_bytes':16*1024**3,'swap_bytes':0,'enforcement':'dedicated_host'}}
            hosts.append(host)
        if ssh['host_key_policy']=='first-use-owned-address':
            known.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if not known.exists():known.touch(mode=0o600)
            for h in hosts:
                ip=h['ssh'].split('@')[1]
                present=subprocess.run(['ssh-keygen','-F',ip,'-f',str(known)],capture_output=True).returncode==0
                if not present:
                    scan=subprocess.run(['ssh-keyscan','-T','10','-t','ed25519',ip],capture_output=True,text=True,timeout=15,check=True)
                    lines=[line for line in scan.stdout.splitlines() if line.startswith(ip+' ssh-ed25519 ')]
                    if len(lines)!=1:raise ValueError('owned host key capture failed')
                    with known.open('a') as stream:stream.write(lines[0]+'\n')
        inventory={'schema':1,'hosts':hosts};prep.validate_hosts(inventory)
        self.inventories[nodes]=inventory
        prep.json_file(self.root/f'fleet-{nodes}.json',{'inventory':inventory,'known_hosts_sha256':prep.sha(known),
            'host_key_policy':ssh['host_key_policy'],'expires_at':lease.state['expires_at']})
        return inventory

    def remaining(self,nodes):
        lease=self.leases[nodes]
        return (datetime.fromisoformat(lease.state['expires_at'].replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()

    def publish(self,nodes,protocol):
        key=(nodes,'common' if protocol in ('delugi','raptr') else protocol)
        if key in self.publications:return self.publications[key]
        selected=self.catalog[key[1]];out=self.root/f'publication-{nodes}-{key[1]}'
        if out.exists():
            record=read(out/('inventory.json' if key[1]=='common' else 'deployment.json'))
            if record.get('status')=='failed':raise ValueError('publication was interrupted; inspect retained evidence before retry')
        elif key[1]=='common':
            r=read(selected['publication'])
            record=aliyun_bench.publish(self.inventories[nodes],r['archive'],r['sha256'],r['binary_sha256'],out,compact=True)
        else:
            plan=prep.create_plan(self.inventories[nodes],artifacts=selected['archive'])
            record=prep.execute_plan(plan,out)
        self.publications[key]=record
        return record

    def run(self,resolved,output):
        protocol=resolved['protocol'];published=self.publish(resolved['nodes'],protocol)
        if protocol in ('delugi','raptr'):
            import common_sustained_remote as shared
            return (shared.run_delugi(resolved,published,self.catalog['common']['local_verifier'],output) if protocol=='delugi'
                    else shared.run_raptr(resolved,published,output))
        return remote_native.execute(remote_native.plan(published,native_settings(resolved)),output)

    def release(self,nodes):
        fleet=self.authorization['fleets'][str(nodes)];path=Path(fleet['lease_state'])
        if not path.exists():return {'closed':True,'never_initialized':True}
        lease=self.leases.get(nodes) or cloud.Lease(path)
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            record=lease.destroy()
            if record.get('closed'):return record
            time.sleep(5)
        raise TimeoutError('owned instance deletion is not confirmed; auto-release lease remains in force')


def execute(plan,authorization,output,*,backend_factory=Backend,validate=validate_authorization):
    contract.validate_plan(plan);bindings=validate(plan,authorization)
    output=Path(output).resolve();output.mkdir(parents=True,exist_ok=True,mode=0o700)
    identity={'plan_sha256':plan['plan_sha256'],'authorization_sha256':contract.digest(authorization),'bindings':bindings}
    with cloud.lease_lock(output/'campaign'):
        state_path=output/'state.json'
        if state_path.exists():
            state=read(state_path)
            if state['identity']!=identity:raise ValueError('campaign configuration, runtime, artifacts or authorization changed')
        else:
            state={'schema':1,'identity':identity,'status':'prepared','rows':[],'fleets':{},'active_trial':None,'comparison_eligible':False}
            aliyun_bench.save(output/'plan.json',plan);aliyun_bench.save(state_path,state)
        backend=backend_factory(authorization,output)
        if state['active_trial']:
            # Cleanup is retryable; do not duplicate paid trials after an
            # ambiguous controller failure or reuse a partially collected store.
            active=state['active_trial'];n=active['nodes']
            try:state['fleets'][str(n)]=backend.release(n)
            finally:
                if not any(row['trial_id']==active['trial_id'] for row in state['rows']):
                    state['rows'].append({**active,'status':'interrupted','error':'ambiguous controller exit; no implicit rerun'})
                retain_unrun(state,plan);state['status']='interrupted'
                table(state['rows'],output/'results.csv');aliyun_bench.save(state_path,state)
            raise RuntimeError('previous trial was in flight; fleet cleaned, evidence retained; no implicit rerun')
        if state['status'] in ('failed','interrupted'):
            return state
        try:
            done={r['trial_id'] for r in state['rows']}
            for n in plan['config']['committees']:
                pending=[t for t in plan['trials'] if t['nodes']==n and t['id'] not in done]
                if not pending:continue
                state['fleets'][str(n)]={'state':'acquiring'};aliyun_bench.save(state_path,state)
                try:
                    backend.acquire(n)
                    state['fleets'][str(n)]={'state':'active'};aliyun_bench.save(state_path,state)
                    # Publish once, before any measurement, then reuse artifacts.
                    for p in plan['config']['protocols']:backend.publish(n,p)
                    for trial in pending:
                        if backend.remaining(n)<1800:raise TimeoutError('lease has less than30minutes for preparation, verification, export and cleanup')
                        rate=trial['total_honest_input_tps'] or fault_rate(state['rows'],plan['config'],n)
                        row={'trial_id':trial['id'],'protocol':trial['protocol'],'nodes':n,'case':trial['case'],'rate':rate}
                        if rate is None:
                            row.update(status='not_run',error='no shared accepted healthy input rate; fault cell retained')
                        else:
                            contract.validate_plan(plan)
                            resolved=adapters.resolve(plan['config'],trial['protocol'],n,rate,trial['case'])
                            selected=output/'resolved'/f'{trial["id"]}.json';aliyun_bench.save(selected,resolved)
                            state['active_trial']=row;state['status']='running';aliyun_bench.save(state_path,state)
                            result=backend.run(resolved,output/'trials'/trial['id'])
                            row.update(status=result['status'],metrics=metrics(result,row['protocol']),error=result.get('error'))
                            path=output/'trials'/trial['id']/'result.json'
                            if path.is_file():row['result']=file_binding(path)
                        state['rows'].append(row);state['active_trial']=None
                        aliyun_bench.save(state_path,state);table(state['rows'],output/'results.csv')
                        if row['status']=='failed':raise RuntimeError('trial failed; bounded sweep stopped and evidence retained')
                finally:
                    state['fleets'][str(n)]=backend.release(n);aliyun_bench.save(state_path,state)
            state['status']='completed' if all(r['status'] in ('passed','completed') for r in state['rows']) else 'completed_with_unrun_cells'
        except BaseException as error:
            state.update(status='failed',error=f'{type(error).__name__}: {error}')
            if state['active_trial'] and not any(row['trial_id']==state['active_trial']['trial_id'] for row in state['rows']):
                state['rows'].append({**state['active_trial'],'status':'failed','error':state['error']})
            retain_unrun(state,plan)
        finally:
            table(state['rows'],output/'results.csv')
            try:
                from campaign_plot import render
                state['plots']=render(state,output/'figures')
            except ImportError:
                state['plots']={'status':'dependency_missing','next':'install benchmarks/requirements-campaign.txt and run scripts/campaign_plot.py on state.json'}
            except Exception as error:state['plots']={'status':'failed','error':str(error)}
            aliyun_bench.save(state_path,state)
        return state
