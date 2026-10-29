#!/usr/bin/env python3
"""Independent-process sustained Raptr qualification and bounded cohort reduction.

Uses the common executable, native signed archive verification and disk-backed
reduction. Local performance is diagnostic; cloud eligibility requires separate
placement, network, resource, fault and observer qualifications.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import secrets
import time

import compact_campaign as contract
import cohort_store
import run_raptr_shared_local as native

ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'raptr-shared-sustained-v1'
CASES = ('healthy', 'empty', 'silent-first-leader', 'missing-payload-recovery')


def make_config(output, *, nodes=4, rate=1000, duration_ms=60_000, drain_ms=15_000,
                useful_bytes=128, case='healthy', delta_ms=100, ingress_capacity=4096, addresses=None, transport=None, node_options=None):
    if nodes not in (4, 10, 50) or case not in CASES:
        raise ValueError('choose a supported committee and qualification case')
    contract.integer(duration_ms, 1, 60_000, 'measurement ms')
    contract.integer(drain_ms, 0, 15_000, 'drain ms')
    contract.integer(useful_bytes, 1, 4096, 'useful bytes')
    contract.integer(delta_ms, 1, 60_000, 'Delta ms')
    contract.integer(ingress_capacity, 1, 100_000, 'ingress capacity')
    faulty = 1 if case == 'silent-first-leader' else 0 if case == 'missing-payload-recovery' else None
    origins = [i for i in range(nodes) if i != faulty]
    allocation = contract.origin_plan(0 if case == 'empty' else rate, duration_ms*1000, nodes, origins)
    output = Path(output).resolve()
    if addresses is not None and (not isinstance(addresses,list) or len(addresses)!=nodes or len(set(addresses))!=nodes):
        raise ValueError('explicit remote addresses must cover every replica once')
    # File allocation is bounded before any replica starts. Includes the native
    # transaction spool, fixed row slots and planned identity journal.
    spool = max(64*1024**2, max(allocation['counts'])*(3*useful_bytes+8192))
    if spool > 16*1024**3:
        raise ValueError('requested preparation exceeds the per-origin spool envelope')
    from evaluation_parameters import transport as validate_transport, raptr_options
    result = {'schema':2, 'epoch':1, 'run_id':secrets.token_hex(32),
            'key_directory':str(output/'private-keys'), 'addresses':list(addresses) if addresses is not None else native.unused_addresses(nodes),
            'output_directory':str(output/'replicas'), 'arm_path':str(output/'arm.json'),
            'delta_ms':delta_ms, 'measurement_duration_ms':duration_ms, 'drain_ms':drain_ms,
            'finite_workload':{'counts':allocation['counts'], 'useful_bytes':useful_bytes,
                               'interval_us':0, 'start_delay_ms':0},
            'sustained_workload':{'total_honest_input_tps':allocation['rate_tps'],
                                  'honest_origins':origins, 'spool_limit_bytes':spool},
            'limits':dict(native.DEFAULT_LIMITS, **native.EXECUTOR_LIMITS,
                          ingress_capacity=ingress_capacity, max_journal_bytes=4*1024**3),
            'materialization_delay_ms':0,
            'payload_fault':{'node':0,'drop_initial_batch_messages':3} if case == 'missing-payload-recovery' else None}
    result['transport']=validate_transport(transport or {})
    for k,v in raptr_options(node_options or {}).items():
        result[k]=dict(result.get(k) or {},**v)
    return result



def journal(path, *, max_bytes=4*1024**3, max_rows=4_800_000, max_line=64*1024**2):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError('journal is absent, linked or oversized')
    size = count = 0
    with path.open('rb') as stream:
        while True:
            raw = stream.readline(max_line+1)
            if not raw: break
            size += len(raw); count += 1
            if len(raw)>max_line or not raw.endswith(b'\n') or size>max_bytes or count>max_rows:
                raise ValueError('journal is oversized or truncated')
            row = json.loads(raw)
            if not isinstance(row, dict): raise ValueError('journal object required')
            yield row


def bound_files(config, correct, *, replica_directory=None):
    files = {}
    for i in correct:
        directory = Path(replica_directory or config['output_directory'])/f'node-{i}'
        receipt = native.bounded_json(directory/'final.json')
        body = receipt['body']
        descriptors = body['files']
        expected = {'workload-manifest.json','planned.jsonl','requests.jsonl','output.jsonl','effective-profile.json'}
        if config.get('latency_trace') is not None:
            expected.add('latency-trace.json')
        if len(descriptors)!=len(expected) or {d['name'] for d in descriptors} != expected:
            raise ValueError('sustained receipt must bind the configured evidence files')
        files[str(directory/'final.json')] = native.file_record(directory/'final.json')
        for descriptor in descriptors:
            path = native.safe_file(directory, descriptor['name'])
            record = native.file_record(path)
            if record['sha256']!=descriptor['sha256'] or record['bytes']>4*1024**3:
                raise ValueError('signed sustained evidence changed')
            if 'bytes' in descriptor and record['bytes']!=descriptor['bytes']:
                raise ValueError('signed sustained byte count differs')
            files[str(path)] = record
    return files


def traffic_windows(body, config):
    from run_sustained import tcp_counters
    windows=body.get('traffic_windows')
    if windows is None:return {'available':False,'reason':'archive predates window snapshots'}
    if set(windows)!= {'before','after','after_shutdown'}:
        raise ValueError('incomplete traffic window snapshots')
    expected={'before':body['epoch_us'],'after':body['epoch_us']+config['measurement_duration_ms']*1000,
              'after_shutdown':body['deadline_us']}
    counters={};offsets={}
    previous=0
    for phase in ('before','after','after_shutdown'):
        row=windows[phase]
        if (row['target_us']!=expected[phase] or not previous<=row['sample_start_us']<=row['sample_end_us']
                or row['sample_start_us']<row['target_us']):
            raise ValueError('traffic snapshot clock/window mismatch')
        previous=row['sample_end_us']
        counters[phase]=tcp_counters({'transport':row['counters']})
        offsets[phase]={'sample_duration_us':row['sample_end_us']-row['sample_start_us'],
                        'endpoint_lateness_us':row['sample_start_us']-row['target_us']}
    for key in ('written_bytes','read_bytes'):
        if not counters['before'][key]<=counters['after'][key]<=counters['after_shutdown'][key]:
            raise ValueError('traffic counters regressed')
    tolerance_us=max(5000,min(100_000,config['measurement_duration_ms']*20))
    return {'available':True,'measurement':{k:counters['after'][k]-counters['before'][k] for k in counters['before']},
            'through_shutdown':counters['after_shutdown'],'sample_offsets':offsets,
            'window_aligned':all(offsets[p]['endpoint_lateness_us']+offsets[p]['sample_duration_us']<=tolerance_us for p in ('before','after')),
            'maximum_endpoint_error_us':tolerance_us,
            'boundary':'successful replica TCP stream writes including protocol framing, authentication and ACK bytes'}


def normalize(config, correct, output, case='healthy', *, replica_directory=None, public_directory=None):
    """Run only after typed offline signature/native-payload verification.

    No cross-host clock subtraction. Each origin's local first materialization
    determines useful credit; all replicas' raw output is retained separately.
    """
    output = Path(output)
    directories = {i:Path(replica_directory or config['output_directory'])/f'node-{i}' for i in correct}
    bodies = {i:native.bounded_json(d/'final.json')['body'] for i,d in directories.items()}
    ledgers, populations = {}, {}
    committee=native.bounded_json(Path(public_directory or config['key_directory'])/'committee.json')
    authors={m['author']:m['id'] for m in committee['members']}
    rounds={i:{} for i in correct}
    target=config['payload_fault']['node'] if config.get('payload_fault') else None
    wanted=set()
    if target is not None:
        for record in bodies[target].get('payload_fault',{}).get('drop_records',[]):
            for batch in record['batches']:wanted.add(native.fault_batch_identity(batch))
    repaired={}
    for i, body in bodies.items():
        if body.get('status','completed')!='completed' or body.get('failure') is not None:
            raise ValueError('native process reported a failure')
        native.validate_executor_lifecycle(body,required=True,expected_limits={
            k:config['limits'][k] for k in native.EXECUTOR_LIMITS})
        epoch = body['epoch_us']; end = epoch+config['measurement_duration_ms']*1000
        if body['freeze_us']<end or body['deadline_us']!=end+config['drain_ms']*1000:
            raise ValueError('incorrect finite observation boundary')
        ledgers[i] = {'window_start_us':epoch,'window_end_us':end,'observed_us':body['deadline_us'],
                      'collected_us':body['freeze_us'],'batch_ready_available':False,
                      'batch_ready_precedes_materialization':False,'output_index_base':0}
        populations[str(i)] = body['counts']

    def rows(i, stream):
        if stream=='requests':
            for row in journal(directories[i]/'requests.jsonl',max_line=16384):
                yield {'origin':i,'sequence':row['sequence'],'request_id':row['request_id'],
                       'useful_bytes':row['useful_bytes'],'scheduled_us':row['planned_us'],
                       'admitted_us':row['admitted_us'],'batch_ready_us':row['own_batch_ready_us'],
                       'materialized_us':row['first_materialized_us'],
                       'rejected_us':row['rejected_us'] or row.get('cancelled_us')}
        elif stream=='outputs':
            ordinal = 0
            for section in journal(directories[i]/'output.jsonl',max_rows=900_000):
                rounds[i][section['block']['round']]=authors[section['block']['author']]
                for batch in section['batches']:
                    key=native.digest({'key':batch['key'],'native_info_bcs_hex':batch['native_info_bcs_hex']})
                    if i==target and key in wanted and key not in repaired:
                        repaired[key]={'append_us':section['append_us'],'ordinal':section['ordinal'],
                                       'transactions':batch['transactions']}
                    for tx in batch['transactions']:
                        if tx['eligible'] and tx['first_seen']:
                            yield {'origin':tx['origin'],'request_id':tx['request_id'],
                                   'useful_bytes':config['finite_workload']['useful_bytes'],
                                   'output_index':ordinal,'materialized_us':section['append_us']}
                        ordinal += 1
        elif stream=='batches':
            for section in journal(directories[i]/'output.jsonl',max_rows=900_000):
                for batch in section['batches']:
                    if batch['first_occurrence']:
                        yield {'exact_batch_id':contract.digest(batch['key']),
                               'payload_bytes':sum(len(tx['native_transaction_bcs_hex'])//2 for tx in batch['transactions']),
                               'materialized_us':section['append_us']}
        else: raise ValueError('unknown cohort stream')

    db = cohort_store.CohortDatabase(output/'cohorts.sqlite',ledgers)
    try:
        db.ingest(rows)
        cohort = db.summarize(correct_replicas=correct)
        recovery=None
        if target is not None:
            admissions={}
            for batch in repaired.values():
                for tx in batch['transactions']:
                    for origin,seq,key,admitted,done in db.db.execute(
                        'SELECT origin,sequence,id,admitted,done FROM requests WHERE id=? AND admitted IS NOT NULL',
                        (tx['request_id'],)):
                        admissions[(origin,seq)]=(key,admitted,done is not None)
            recovery=native.validate_payload_recovery(bodies[target]['payload_fault'],config,committee,
                bodies[target]['epoch_us'],bodies[target]['deadline_us'],repaired,admissions)
    finally:
        db.db.close()
    total = {key:sum(v[key] for v in populations.values()) for key in
             ('planned','offered','admitted','rejected','cancelled','completed','unfinished','unoffered')}
    if (total['planned']!=total['offered']+total['unoffered'] or
        total['offered']!=total['admitted']+total['rejected']+total['cancelled'] or
        total['admitted']!=total['completed']+total['unfinished']):
        raise ValueError('sustained population conservation failed')
    if any(not values or max(values)<4 for values in rounds.values()):
        raise ValueError('a correct replica did not materialize native output through round4')
    if case=='silent-first-leader' and any(any(values.get(r)!=r%len(config['addresses']) for r in (2,3,4)) for values in rounds.values()):
        raise ValueError('missing three honest anchors after the silent first leader')
    return {'cohort':cohort,'populations':total,'per_origin':populations,
            'round_authors':rounds,'payload_recovery':recovery,
            'completion_endpoint':'own-origin admission to first verified contiguous application append',
            'traffic':{str(i):traffic_windows(b,config) for i,b in bodies.items()},
            'traffic_scope':'signed per-origin measurement-window and post-shutdown counters; actual sample offsets retained',
            'comparison_eligible':False}


def execute(binary, receipt, output, **settings):
    output = Path(output).resolve()
    config = make_config(output,**settings)
    nodes = len(config['addresses']); case = settings.get('case','healthy')
    correct = [i for i in range(nodes) if not (case=='silent-first-leader' and i==1)]
    output.mkdir(parents=True,exist_ok=False)
    started = time.monotonic(); deadline = started+600
    record = {'schema':1,'kind':FORMAT,'status':'running','comparison_eligible':False,
              'case':case,'correct_replicas':correct,'cleanup':[]}
    children=[]; pause=None
    try:
        stamp, record['artifact'] = native.archive_build(binary,receipt,output/'artifact')
        executable = Path(record['artifact']['executable'])
        path = output/'config.json'; native.atomic_json(path,config)
        config_hash=native.sha256(path)
        record['configuration_sha256']=config_hash
        native.run_command(executable,['--protocol','raptr','--keygen',config['key_directory'],
                                       '--nodes',str(nodes)],output,'keygen',deadline)
        Path(config['output_directory']).mkdir()
        for i in range(nodes): children.append(native.Child(executable,path,i,output))
        ready=native.wait_ready(children,config,config_hash,min(deadline,time.monotonic()+240),output)
        if case=='silent-first-leader':
            pause=children[1].pause();record['pause']=pause
        epoch=native.clock_us()+500_000
        if any(r['ready_us']>=epoch for r in ready.values()):raise ValueError('arm before readiness')
        native.atomic_json(config['arm_path'],{'schema':1,'run_id':config['run_id'],
            'configuration_sha256':config_hash,'epoch_us':epoch})
        record['completion']=native.await_completion(children,correct,deadline-120,output,
            rss_limit=12*1024**3,disk_limit=32*1024**3)
        if pause is not None:
            observed=children[1]._leader()
            if not observed['state'].startswith(('T','t')):
                raise ValueError('silent leader did not remain stopped through observation')
            pause.update(observation_ended_us=native.clock_us(),end_identity=observed,
                         status='stopped_through_observation')
            # Cleanup sends CONT/TERM to the owned group. A replica waking after
            # its expired arm may exit immediately; that is not a recovery fault.
        before=bound_files(config,correct)
        record['authentication']=native.verify_archive(executable,path,config,correct,output,deadline)
        record['reduction']=normalize(config,correct,output,case)
        if config.get('latency_trace') is not None:
            from raptr_latency_decomposition import analyze
            record['latency_decomposition']=analyze(path,Path(config['output_directory']),correct,
                authentication=record['authentication'])
            native.atomic_json(output/'latency-decomposition.json',record['latency_decomposition'])
        if before!=bound_files(config,correct) or native.sha256(path)!=config_hash:
            raise ValueError('evidence changed across authentication and reduction')
        record['evidence']=before
        native.validate_build(binary,stamp)
        record['status']='completed'
    except BaseException as error:
        record.update(status='failed',error=f'{type(error).__name__}: {error}')
    finally:
        for child in reversed(children):
            try:clean=child.finish()
            except BaseException as error:clean={'id':child.id,'error':str(error)}
            record['cleanup'].append(clean)
            if clean.get('cleanup',{}).get('status')!='completed' or clean['cleanup'].get('remaining')!=[]:
                record.update(status='failed',cleanup_error='owned process cleanup unconfirmed')
        record['elapsed_seconds']=time.monotonic()-started
        native.atomic_json(output/'manifest.json',record)
    return record


def main():
    p=argparse.ArgumentParser(description=__doc__)
    tg=p.add_mutually_exclusive_group();tg.add_argument('--transport-config',type=Path);tg.add_argument('--transport-json',type=json.loads)
    ng=p.add_mutually_exclusive_group();ng.add_argument('--node-options',type=Path);ng.add_argument('--node-options-json',type=json.loads)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--build-receipt',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--case',choices=CASES,default='healthy')
    p.add_argument('--nodes',type=int,choices=(4,10,50),default=4)
    p.add_argument('--rate',type=int,default=1000);p.add_argument('--duration-ms',type=int,default=60_000)
    p.add_argument('--drain-ms',type=int,default=15_000);p.add_argument('--useful-bytes',type=int,default=128)
    p.add_argument('--delta-ms',type=int,default=100);p.add_argument('--ingress-capacity',type=int,default=4096)
    a=vars(p.parse_args());binary=a.pop('binary');receipt=a.pop('build_receipt');output=a.pop('output')
    from evaluation_parameters import load_transport,raptr_options
    tj=a.pop('transport_json');tp=a.pop('transport_config');a['transport']=load_transport(tp) if tj is None else tj
    options=a.pop('node_options');nj=a.pop('node_options_json');a['node_options']=raptr_options(nj if nj is not None else json.loads(options.read_text()) if options else {})
    r=execute(binary,receipt,output,**a)
    print(json.dumps({'status':r['status'],'manifest':str(output/'manifest.json'),'error':r.get('error')}))
    return 0 if r['status']=='completed' else 1


if __name__=='__main__':raise SystemExit(main())
