#!/usr/bin/env python3
"""Bounded independent-process qualification for the two pinned Simple-IT variants.

Uses the native protocol with disclosed TLS, independent ingress and complete
application output adapters. Local measurements are diagnostic, not cloud data.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import sqlite3
import subprocess
import time

import compact_campaign
import cohort_store
from baselines import simpleit, simpleit_auth, raptr_artifacts as owned
from run_raptr_sustained import journal
from run_raptr_shared_local import atomic_json, unused_addresses, clock_us


def parameters(variant,nodes,useful_bytes,batch_bytes,delta_ms):
    if variant not in ('simpleit-mempool','simpleit-dispersed') or nodes not in (4,10,50):
        raise ValueError('explicit supported Simple-IT variant and committee required')
    for v,lo,hi,name in ((useful_bytes,1,4096,'useful bytes'),(batch_bytes,useful_bytes,16*1024**2,'batch bytes'),(delta_ms,1,60000,'Delta ms')):
        compact_campaign.integer(v,lo,hi,name)
    wire_size=useful_bytes+52
    cfg={'header_size':(batch_bytes//useful_bytes)*wire_size,'max_header_delay':delta_ms,
         'gc_depth':10000,'sync_retry_delay':delta_ms,'sync_retry_nodes':min(3,nodes-1),
         'batch_size':(batch_bytes//useful_bytes)*wire_size,'tx_size':wire_size,
         'max_batch_delay':5,'f_num':(nodes-1)//3}
    if variant=='simpleit-mempool':
        cfg.update(timeout_delay=delta_ms,use_optimistic_tips=True,use_parallel_proposals=True,k=4,
            use_fast_path=True,fast_path_timeout=max(1,delta_ms//2),use_ride_share=False,
            car_timeout=2*delta_ms,simulate_asynchrony=False,asynchrony_start=20000,
            asynchrony_duration=10000,crash_on_proposal=0,crash_duration=0)
    else:cfg.update(consensus_only=True,rs_block_size=16384,rs_block_threads=2,crash_on_proposal=0)
    return cfg


def prepare(binary,variant,directory,*,nodes=4,rate=1000,duration_ms=2000,drain_ms=2000,
            useful_bytes=128,batch_bytes=65536,delta_ms=100,case='healthy',addresses=None,run_id=None):
    directory=Path(directory).resolve()
    compact_campaign.integer(duration_ms,1,60000,'measurement ms')
    compact_campaign.integer(drain_ms,0,15000,'drain ms')
    if case not in ('healthy','empty','silent-first-leader','missing-data'):raise ValueError('unsupported qualification case')
    params=parameters(variant,nodes,useful_bytes,batch_bytes,delta_ms)
    keys=directory/'private-keys';keys.mkdir(mode=0o700)
    members=[]
    for i in range(nodes):
        path=keys/f'node-{i}.json'
        subprocess.run([str(binary),'generate_keys','--filename',str(path)],check=True,capture_output=True,timeout=30)
        path.chmod(0o600);members.append((json.loads(path.read_text())['name'],path))
    # Native Dispersed leader selection sorts keys; the configured IDs follow
    # exactly that same order, including the selected first-round leader (1).
    members.sort(key=lambda entry:base64.b64decode(entry[0],validate=True))
    public=[base64.b64decode(name,validate=True).hex() for name,_ in members]
    addresses=addresses or unused_addresses(nodes*6)
    if len(addresses)!=nodes*6 or len(set(addresses))!=nodes*6:raise ValueError('six distinct role addresses per validator required')
    bls=[]
    if variant=='simpleit-dispersed':
        subprocess.run([str(binary),'generate_bls_keys','--nodes',str(nodes),'--threshold',str((nodes-1)//3),'--path','bls-x.json'],cwd=keys,check=True,capture_output=True,timeout=60)
        for path in sorted(keys.glob('bls-*')):path.chmod(0o600)
        for i in range(nodes):bls.append(json.loads((keys/f'bls-{i}.json').read_text())['nameg2'])
    authorities={};destinations={}
    for i,(name,_) in enumerate(members):
        a=addresses[i*6:(i+1)*6];destinations[i]=a
        authority={'node_id':i,'stake':1,'consensus':{'consensus_to_consensus':a[0]},
            'primary':{'primary_to_primary':a[1],'worker_to_primary':a[2]},
            'workers':{'0':{'primary_to_worker':a[3],'transactions':a[4],'worker_to_worker':a[5]}}}
        if bls:authority['bls_pubkey_g2']=bls[i]
        authorities[name]=authority
    atomic_json(directory/'committee.json',{'authorities':authorities})
    atomic_json(directory/'parameters.json',params)
    tls=simpleit_auth.certificates(directory/'private-tls',public,destinations)
    faulty=1 if case=='silent-first-leader' else 0 if case=='missing-data' else None
    correct=[i for i in range(nodes) if i!=faulty]
    allocation=compact_campaign.origin_plan(0 if case=='empty' else rate,duration_ms*1000,nodes,correct)
    run_id=run_id or secrets.token_hex(32);configs=[]
    for i in range(nodes):
        cfg={'schema':1,'run_id':run_id,'id':i,'members':public,'honest_origins':correct,
             'total_rate':allocation['rate_tps'],'duration_ms':duration_ms,'drain_ms':drain_ms,
             'useful_bytes':useful_bytes,'queue_capacity':4096,'journal_limit_bytes':4*1024**3,
             'directory':str(directory/f'observer-{i}'),'arm_path':str(directory/'arm.json'),
             'native_key':str(members[i][1])}
        if case=='missing-data':cfg['payload_fault']={'source':0,'recipient':1,'initial_headers':3}
        path=directory/f'workload-{i}.json';atomic_json(path,cfg);configs.append(path)
    return {'schema':1,'variant':variant,'run_id':run_id,'nodes':nodes,'correct':correct,
            'case':case,'parameters':params,'allocation':allocation,'configurations':list(map(str,configs)),
            'tls_configurations':{str(k):str(v) for k,v in tls['configs'].items()},
            'ca_sha256':tls['ca_sha256'],'native_keys':[str(path) for _,path in members],
            'timer_mapping':{'Delta_ms':delta_ms,'native_round_timeout_ms':delta_ms},
            'wire_transaction_bytes':useful_bytes+52,'useful_transaction_bytes':useful_bytes}


def verify_and_reduce(binary,run,directory):
    directory=Path(directory);correct=run['correct'];bodies={};verification={};ledgers={}
    fingerprints={}
    observed=correct if run['case']=='silent-first-leader' else list(range(run['nodes']))
    for i in observed:
        root=directory/f'observer-{i}';cfg=json.loads((directory/f'workload-{i}.json').read_text())
        p=subprocess.run([str(binary),'verify_evaluation','--configuration',str(directory/f'workload-{i}.json'),
                          '--directory',str(root)],capture_output=True,text=True,timeout=300)
        (directory/f'verify-{i}.stdout').write_text(p.stdout);(directory/f'verify-{i}.stderr').write_text(p.stderr)
        if p.returncode:raise ValueError(f'native typed evidence verification failed at replica {i}')
        verified=json.loads(p.stdout);verification[str(i)]=verified
        if not verified.get('verified') or verified['last_round']<4:raise ValueError('round-4 application progress not observed')
        body=json.loads((root/'final.json').read_text())['body'];bodies[i]=body
        for name in ('final.json','requests.jsonl','output.jsonl'):
            fingerprints[str((root/name).relative_to(directory))]=owned.sha256(root/name)
        ledgers[i]={'window_start_us':body['epoch_us'],'window_end_us':body['epoch_us']+cfg['duration_ms']*1000,
            'observed_us':body['deadline_us'],'batch_ready_available':True,'batch_ready_precedes_materialization':True,
            'output_index_base':0}
    # Compare the exact application sequence, never a sorted observer view.
    db=sqlite3.connect(directory/'native-prefix.sqlite');db.execute('PRAGMA cache_size=-8192')
    db.execute('CREATE TABLE output(replica INTEGER, ordinal INTEGER, identity TEXT, PRIMARY KEY(replica,ordinal))')
    for i in correct:
        for row in journal(directory/f'observer-{i}'/'output.jsonl'):
            key=hashlib.sha256(json.dumps([row['round'],row['header'],row['native_header_bincode_hex']],separators=(',',':')).encode()).hexdigest()
            db.execute('INSERT INTO output VALUES (?,?,?)',(i,row['ordinal'],key))
    mismatch=db.execute('SELECT ordinal FROM output GROUP BY ordinal HAVING count(DISTINCT identity)>1 LIMIT 1').fetchone()
    db.commit();db.close()
    if mismatch:raise ValueError(f'raw application prefixes diverge at ordinal {mismatch[0]}')
    def rows(i,stream):
        if stream=='requests':
            for row in journal(directory/f'observer-{i}'/'requests.jsonl',max_line=16384):
                yield {k:row[k] for k in ('origin','sequence','request_id','useful_bytes','scheduled_us','admitted_us','batch_ready_us','materialized_us')} | {'rejected_us':row['rejected_us'] or row['cancelled_us']}
        elif stream=='outputs':
            ordinal=0
            for row in journal(directory/f'observer-{i}'/'output.jsonl'):
                for tx in row['transactions']:
                    if tx['first_seen']:
                        yield {'request_id':tx['request_id'],'origin':tx['origin'],'sequence':tx['sequence'],
                            'useful_bytes':run['useful_transaction_bytes'],'output_index':ordinal,'materialized_us':row['materialized_us']}
                        ordinal+=1
        elif stream!='batches':raise ValueError('unknown cohort stream')
    database=cohort_store.CohortDatabase(directory/'cohorts.sqlite',ledgers)
    try:
        database.ingest(rows);metrics=database.summarize(correct_replicas=correct,deadline_ms=1000)
    finally:database.close()
    if any(owned.sha256(directory/path)!=digest for path,digest in fingerprints.items()):raise ValueError('evidence changed during reduction')
    recovery=None
    if run['case']=='missing-data':
        omitted={e['header']:e for e in bodies[0]['payload_fault']['events'] if e['kind']=='initial_header_withheld'}
        if not omitted:raise ValueError('payload omission hook did not fire')
        repaired={e['header']:e for e in bodies[1]['payload_fault']['events'] if e['kind'] in ('repair_received','reconstructed') and e['header'] in omitted}
        delivered={row['header']:row['materialized_us'] for row in journal(directory/'observer-1/output.jsonl') if row['header'] in omitted}
        if not set(omitted)<=set(repaired)&set(delivered):raise ValueError('omitted native payloads lack repair/materialization evidence')
        recovery={'omitted':omitted,'native_repair':repaired,'target_materialized_us':delivered}
    result={'schema':1,'typed_native_verification':verification,'prefix_agreement':True,'payload_recovery':recovery,
        'population':{str(i):bodies[i]['populations'] for i in correct},'metrics':metrics,'evidence':fingerprints,
        'comparison_eligible':False,'boundary':'origin monotonic independent scheduled arrival to complete native-header materialization',
        'remaining_gates':['native certificate/fallback adversarial qualification','Linux release/resource/network/observer qualification']}
    if all('traffic' in body for body in bodies.values()):
        result['traffic']={'replicas':{str(i):body['traffic'] for i,body in bodies.items()},
            'measurement_written_bytes':sum(body['traffic']['counters']['window_written_bytes'] for body in bodies.values()),
            'measurement_read_bytes':sum(body['traffic']['counters']['window_read_bytes'] for body in bodies.values()),
            'scope':'successful underlying TCP bytes in exact origin-local measurement windows; includes TLS and native ACKs',
            'shutdown_tail_included':False}
    atomic_json(directory/'reduction.json',result);return result


def execute(receipt,variant,directory,**options):
    binary,build=simpleit.verify_build(receipt,variant)
    directory=Path(directory).resolve();directory.mkdir(parents=True,exist_ok=False)
    record={'schema':1,'status':'preparing','build':build,'cleanup':[],'comparison_eligible':False}
    children=[];started=time.monotonic()
    try:
        run=prepare(binary,variant,directory,**options);record['run']=run
        atomic_json(directory/'resolved.json',run)
        for i in range(run['nodes']):
            env={k:v for k,v in os.environ.items() if k in owned.ENV_KEYS}
            env.update(DELUGI_SIMPLEIT_TLS=run['tls_configurations'][str(i)],DELUGI_SIMPLEIT_WORKLOAD=run['configurations'][i],TOKIO_WORKER_THREADS='2')
            log=(directory/f'node-{i}.log').open('xb')
            command=[str(binary),'-vv','run','--edkeys',run['native_keys'][i],'--committee',str(directory/'committee.json'),
                     '--parameters',str(directory/'parameters.json'),'--store',str(directory/f'store-{i}'),'primary']
            process=subprocess.Popen(command,cwd=directory,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            group=owned.OwnedGroup(process);children.append((i,process,group,log));group.verify_start()
        def check():
            rss=0
            for i,p,g,log in children:
                if p.poll() is not None:raise RuntimeError(f'replica {i} exited before freeze: {p.returncode}')
                rss+=sum(row['rss_bytes'] for row in g.members())
                if Path(log.name).stat().st_size>256*1024**2:raise RuntimeError('process log guard reached')
            if rss>12*1024**3 or time.monotonic()-started>600:raise RuntimeError('local resource guard reached')
            return rss
        ready_deadline=time.monotonic()+60
        while not all((directory/f'observer-{i}'/'ready.json').is_file() for i in range(run['nodes'])):
            check()
            if time.monotonic()>ready_deadline:raise TimeoutError('native readiness timeout')
            time.sleep(.05)
        if run['case']=='silent-first-leader':
            children[1][2].send(signal.SIGSTOP);time.sleep(.02)
            if not any(r['pid']==children[1][1].pid and r['state'].startswith(('T','t')) for r in children[1][2].members()):raise ValueError('silent leader stop unconfirmed')
            record['silent_leader']={'replica':1,'stopped_us':clock_us()}
        epoch=clock_us()+500000
        atomic_json(directory/'arm.json',{'run_id':run['run_id'],'epoch_us':epoch})
        run_deadline=time.monotonic()+(options.get('duration_ms',2000)+options.get('drain_ms',2000))/1000+30
        observed=run['correct'] if run['case']=='silent-first-leader' else list(range(run['nodes']))
        with (directory/'resources.jsonl').open('x') as log:
            while not all((directory/f'observer-{i}'/'final.json').is_file() for i in observed):
                rss=check();log.write(json.dumps({'sample_us':clock_us(),'owned_rss_bytes':rss})+'\n');log.flush()
                if time.monotonic()>run_deadline:raise TimeoutError('native final receipts timeout')
                time.sleep(.2)
        if 'silent_leader' in record:
            if not any(r['pid']==children[1][1].pid and r['state'].startswith(('T','t')) for r in children[1][2].members()):raise ValueError('leader resumed during observation')
            record['silent_leader']['observation_end_us']=clock_us()
        record['status']='frozen'
    except BaseException as error:record.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        for i,p,g,log in reversed(children):
            clean=g.cleanup(3);log.close();record['cleanup'].append({'replica':i,**clean})
            if clean['status']!='completed':record.update(status='failed',error='owned process cleanup failed')
    try:
        if record['status']=='frozen':
            record['reduction']=verify_and_reduce(binary,record['run'],directory)
            simpleit.verify_build(receipt,variant);record['status']='completed'
    except BaseException as error:record.update(status='failed',error=f'{type(error).__name__}: {error}')
    record['elapsed_seconds']=time.monotonic()-started;atomic_json(directory/'manifest.json',record)
    return record


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--variant',required=True,choices=('simpleit-mempool','simpleit-dispersed'))
    p.add_argument('--build-receipt',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--nodes',type=int,choices=(4,10,50),default=4);p.add_argument('--rate',type=int,default=1000)
    p.add_argument('--duration-ms',type=int,default=2000);p.add_argument('--drain-ms',type=int,default=2000)
    p.add_argument('--useful-bytes',type=int,default=128);p.add_argument('--batch-bytes',type=int,default=65536)
    p.add_argument('--delta-ms',type=int,default=100);p.add_argument('--case',choices=('healthy','empty','silent-first-leader','missing-data'),default='healthy')
    a=vars(p.parse_args());receipt=a.pop('build_receipt');variant=a.pop('variant');directory=a.pop('output')
    result=execute(receipt,variant,directory,**a)
    print(json.dumps({'status':result['status'],'error':result.get('error'),'manifest':str(directory/'manifest.json')}))
    return 0 if result['status']=='completed' else 1


if __name__=='__main__':raise SystemExit(main())
