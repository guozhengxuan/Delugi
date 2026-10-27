"""Fixed Simple-IT placement through the existing owned native supervisor."""
from __future__ import annotations
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def generate(protocol,root,ips,binaries,cfg,run_id):
    from run_simpleit_local import prepare
    from run_raptr_shared_local import atomic_json
    root=Path(root);fixture=root/'fixture';fixture.mkdir(mode=0o700)
    addresses=[f'{ip}:{9000+6*i+j}' for i,ip in enumerate(ips) for j in range(6)]
    run=prepare(Path(binaries['node']),protocol,fixture,nodes=len(ips),rate=cfg['rate'],
        duration_ms=round(cfg['duration']*1000),drain_ms=round(cfg['drain']*1000),
        useful_bytes=cfg['useful_bytes'],batch_bytes=cfg['batch_bytes'],delta_ms=cfg['bound_ms'],
        case=cfg['case'],addresses=addresses,run_id=run_id+run_id)
    atomic_json(fixture/'remote-run.json',run)
    selected=[]
    for i in range(len(ips)):
        tls=fixture/'private-tls'/f'node-{i}'
        selected.append([fixture/'committee.json',fixture/'parameters.json',fixture/'remote-run.json',
            Path(run['native_keys'][i]),Path(run['configurations'][i]),
            *[tls/name for name in ('tls.json','ca.pem','certificate.pem','key.pem')]])
    return selected


def run_host(request,root,preflight):
    import remote_native as remote
    from baselines import native_cohort_store
    from run_raptr_sustained import journal
    root=Path(root);fixture=root/'fixture';cfg=request['settings'];i=request['host']['replica']
    run=json.loads((fixture/'remote-run.json').read_text());config=fixture/f'workload-{i}.json'
    binary=request['host']['native_binaries']['node']['path'];observer=fixture/f'observer-{i}'
    env={k:v for k,v in os.environ.items() if not k.startswith(('DELUGI_SIMPLEIT_','BENCHMARK_'))
         and k.lower() not in ('http_proxy','https_proxy','all_proxy')}
    env.update(DELUGI_SIMPLEIT_TLS=run['tls_configurations'][str(i)],DELUGI_SIMPLEIT_WORKLOAD=str(config),TOKIO_WORKER_THREADS=str(cfg['tokio_workers']))
    result={'status':'failed','replica':i,'preflight':preflight,'comparison_eligible':False}
    process=None;events=[];started=time.monotonic();(root/'logs').mkdir()
    try:
        with (root/'logs/validator.log').open('xb') as log:
            argv=[binary,'-vv','run','--edkeys',run['native_keys'][i],'--committee',str(fixture/'committee.json'),
                '--parameters',str(fixture/'parameters.json'),'--store',str(root/'store'),'primary']
            # Inherit the resource wrapper's group; it owns every descendant.
            process=subprocess.Popen(argv,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
            def alive():
                remote.check_startup_abort(root,request)
                if process.poll() is not None:raise RuntimeError('Simple-IT exited before evidence freeze')
                if time.monotonic()-started>2*cfg['startup_seconds']+cfg['duration']+cfg['drain']+10:
                    raise TimeoutError('Simple-IT host lifecycle deadline')
            while not (observer/'ready.json').exists():alive();time.sleep(.02)
            ready=remote.bounded_json(observer/'ready.json')
            if ready.get('pid')!=process.pid or ready.get('id')!=i or ready.get('configuration_sha256')!=remote.prep.sha(config):
                raise ValueError('native readiness process/configuration binding differs')
            stopped=cfg['case']=='silent-first-leader' and i==1
            if stopped:
                os.kill(process.pid,signal.SIGSTOP)
                for _ in range(100):
                    state=Path(f'/proc/{process.pid}/stat').read_text().rsplit(')',1)[1].split()[0]
                    if state in ('T','t'):break
                    time.sleep(.01)
                else:raise RuntimeError('silent leader stop unconfirmed')
                events.append({'event':'leader_stopped_before_arm','replica':i,'monotonic_ns':time.monotonic_ns()})
            remote.publish_startup(root,'readiness.json',remote.startup_identity(request)|{
                'state':'prepared','readiness':{'ready':True,'native':ready,'silent_leader_stopped':stopped}})
            while not (root/'arm.json').exists():alive();time.sleep(.02)
            intent=remote.startup_record(root,'arm.json',request)
            if intent.get('readiness_sha256')!=remote.prep.sha(root/'readiness.json'):raise ValueError('committee arm does not bind readiness')
            epoch=time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000+1_000_000
            remote.publish_startup(fixture,'arm.json',{'run_id':run['run_id'],'epoch_us':epoch})
            result['epoch_monotonic_ns']=epoch*1000
            deadline=epoch+(round(cfg['duration']*1000)+round(cfg['drain']*1000))*1000
            if stopped:
                while time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000<deadline:alive();time.sleep(.1)
                result.update(status='completed',silent_leader=True,cohort_excluded=True)
            else:
                while not (observer/'final.json').exists():alive();time.sleep(.05)
                # The atomic final file denotes frozen observer state. Stop the
                # native process before offline work; its cleanup is still owned.
                os.kill(process.pid,signal.SIGSTOP)
                verified=subprocess.run([binary,'verify_evaluation','--configuration',str(config),'--directory',str(observer)],
                    capture_output=True,text=True,timeout=300)
                (root/'verification.stdout').write_text(verified.stdout);(root/'verification.stderr').write_text(verified.stderr)
                if verified.returncode:raise ValueError('typed native Simple-IT verification failed')
                result['native_verification']=json.loads(verified.stdout)
                if not result['native_verification'].get('verified') or result['native_verification']['last_round']<4:raise ValueError('native round-4 progress absent')
                body=json.loads((observer/'final.json').read_text())['body']
                store=native_cohort_store.NativeStore(root/'native-cohort-stage.sqlite',population_profile=cfg.get('population_profile'))
                try:
                    store.metadata[i]={'window_start_us':epoch,'window_end_us':epoch+round(cfg['duration']*1e6),
                        'observed_us':deadline,'batch_ready_available':True,'batch_ready_precedes_materialization':True,'output_index_base':0}
                    for row in journal(observer/'requests.jsonl',max_line=16384):
                        store.put(i,'requests',{k:row[k] for k in ('origin','sequence','request_id','useful_bytes','scheduled_us','admitted_us','batch_ready_us','materialized_us')}|{'rejected_us':row['rejected_us'] or row['cancelled_us']})
                    ordinal=0
                    for row in journal(observer/'output.jsonl'):
                        seen=[tx for tx in row['transactions'] if tx['first_seen']]
                        if seen:
                            store.put(i,'batches',{'exact_batch_id':row['header'],'payload_bytes':len(bytes.fromhex(row['native_header_bincode_hex'])),'materialized_us':row['materialized_us']})
                        for tx in seen:
                            store.put(i,'outputs',{'request_id':tx['request_id'],'origin':tx['origin'],'sequence':tx['sequence'],
                                'useful_bytes':cfg['useful_bytes'],'output_index':ordinal,'exact_batch_id':row['header'],'materialized_us':row['materialized_us']});ordinal+=1
                    archive=store.archive(root/'cohorts')
                finally:store.close()
                result.update(status='completed',traffic=body['traffic'],payload_fault=body['payload_fault'],
                    cohort_archive={'path':'cohorts/index.json','sha256':archive.index_sha256,'schema':2},
                    evidence_sha256={str((observer/name).relative_to(root)):remote.prep.sha(observer/name)
                        for name in ('final.json','requests.jsonl','output.jsonl')})
    except BaseException as error:result.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        if process is not None and process.poll() is None:
            os.kill(process.pid,signal.SIGCONT);process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        (root/'host-events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
        remote.prep.json_file(root/'result.json',result)
    return 0 if result['status']=='completed' else 1


def evidence_files(root,replica):
    root=Path(root);observer=root/'fixture'/f'observer-{replica}'
    return [str(p.relative_to(root)) for p in [root/'fixture'/f'workload-{replica}.json',
        root/'fixture/remote-run.json',root/'fixture/parameters.json',root/'fixture/committee.json',
        *[observer/name for name in ('ready.json','final.json','requests.jsonl','output.jsonl')]] if p.is_file()]


def verify_collected(output,cfg,expected):
    import sqlite3
    import deployment_prepare as prep
    from run_raptr_sustained import journal
    output=Path(output);db=sqlite3.connect(output/'native-prefix.sqlite')
    db.execute('PRAGMA cache_size=-8192');db.execute('CREATE TABLE output(replica,ordinal,identity,PRIMARY KEY(replica,ordinal))')
    bodies={}
    try:
        for i in sorted(expected):
            root=output/f'host-{i}';result=json.loads((root/'result.json').read_text())
            for name,digest in result['evidence_sha256'].items():
                if prep.sha(root/name)!=digest:raise ValueError('collected typed native evidence changed')
            observer=root/'fixture'/f'observer-{i}';bodies[i]=json.loads((observer/'final.json').read_text())['body']
            for row in journal(observer/'output.jsonl'):
                db.execute('INSERT INTO output VALUES (?,?,?)',(i,row['ordinal'],json.dumps([row['round'],row['header'],row['native_header_bincode_hex']],separators=(',',':'))))
        if db.execute('SELECT ordinal FROM output GROUP BY ordinal HAVING count(DISTINCT identity)>1 LIMIT 1').fetchone():
            raise ValueError('native Simple-IT application prefixes disagree')
        recovery=None
        if cfg['case']=='missing-data':
            missing={e['header'] for e in bodies[0]['payload_fault']['events'] if e['kind']=='initial_header_withheld'}
            repaired={e['header'] for e in bodies[1]['payload_fault']['events'] if e['kind'] in ('repair_received','reconstructed')}
            delivered={r['header'] for r in journal(output/'host-1/fixture/observer-1/output.jsonl') if r['header'] in missing}
            if not missing or not missing<=repaired&delivered:raise ValueError('native omitted payload recovery is incomplete')
            recovery={'headers':sorted(missing),'native_repair_and_materialization':True}
        return {'exact_native_prefix_agreement':True,'payload_recovery':recovery,'comparison_eligible':False}
    finally:db.commit();db.close()
