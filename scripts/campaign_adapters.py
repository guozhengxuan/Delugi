"""Principal adapter registry and strict requested/effective configuration resolution.

Common workload and network budgets do not imply identical native services.
Unimplemented knobs are rejected before a build, SSH connection or paid call.
"""
from __future__ import annotations
import copy
from pathlib import Path
import compact_campaign as contract

ROOT=Path(__file__).resolve().parents[1]
NATIVE='compact-n10-n50-v1'


def capabilities(protocol):
    if protocol not in contract.PROTOCOLS:raise ValueError('unknown principal adapter')
    return {'protocol':protocol,'committee_sizes':[4,10,50],
        'independent_global_arrivals':True,'measurement_admission_cutoff':True,
        'useful_transaction_bytes':True,'native_timer_mapping':True,
        'batch_byte_target':protocol in ('delugi','simpleit-mempool','simpleit-dispersed','autobahn'),
        'batch_wait':protocol in ('delugi','autobahn'),
        'proposal_useful_byte_cap':False,'proposal_reference_cap':False,
        'local_runner':{'delugi':'scripts/run_sustained.py','raptr':'scripts/run_raptr_sustained.py',
            'simpleit-mempool':'scripts/run_simpleit_local.py','simpleit-dispersed':'scripts/run_simpleit_local.py',
            'autobahn':'scripts/baselines/autobahn.py','mysticeti-c':'scripts/baselines/mysticeti.py'}[protocol]}


def resolve(config,protocol,nodes,rate,case='healthy'):
    contract.validate(config)
    if protocol not in config['protocols'] or nodes not in (4,*config['committees']):
        raise ValueError('adapter/committee is outside the selected campaign')
    if case not in ('healthy',*config['fault_cases']):raise ValueError('case is outside the campaign')
    contract.integer(rate,1,80000,'total honest tx/s')
    cap=capabilities(protocol);batch=config['batching'];proposal=config['proposal_budget']
    unsupported=[]
    for value,supported,name in ((batch['useful_bytes_target'],cap['batch_byte_target'],'batch useful-byte target'),
        (batch['max_wait_ms'],cap['batch_wait'],'batch maximum wait'),
        (proposal['useful_bytes'],cap['proposal_useful_byte_cap'],'proposal useful-byte cap'),
        (proposal['max_payload_refs'],cap['proposal_reference_cap'],'proposal reference cap')):
        if value is not None and not supported:unsupported.append(name)
    if unsupported:raise ValueError(protocol+' does not enforce '+', '.join(unsupported)+'; select explicit null for native defaults')
    if config['protocol_options'][protocol]:raise ValueError('unreviewed protocol option; no opaque settings are ignored')
    useful=config['useful_transaction_bytes'];delta=config['timing']['Delta_ms']
    # A missing-data sender and a stopped leader contribute no honest arrivals.
    faulty=None if case=='healthy' else (0 if case=='missing-data' or protocol=='delugi' else 1)
    origins=[i for i in range(nodes) if i!=faulty]
    effective={'useful_transaction_bytes':useful,'total_honest_input_tps':rate,
        'duration':copy.deepcopy(config['duration']),'network':copy.deepcopy(config['network']),
        'batching':{},'proposal_budget':{'policy':'native; no common cap claimed'},
        'timing':{'Delta_ms':delta},'faulty_identities':[] if faulty is None else [faulty]}
    if protocol=='delugi':
        count=(batch['useful_bytes_target']//useful if batch['useful_bytes_target'] is not None else 128)
        if not 1<=count<=128:raise ValueError('Delugi batch target exceeds the current128-transaction ingress envelope')
        effective['batching']={'max_transactions':count,'useful_bytes_target':count*useful,'max_wait_ms':batch['max_wait_ms'] or 10}
        effective['timing'].update(catchup_ms=7*delta,proposal_wait_ms=3*delta)
        effective['resource_profile']='complete-64mib-n50-v1' if nodes==50 else 'complete-32mib-n31-v1'
        effective['storage']='shared-rocksdb-written-v1; WAL enabled, sync=false; fresh database'
    elif protocol=='raptr':
        effective['storage']='native Quorum Store and consensus storage through shared RocksDB; fresh databases'
        effective['batching']={'policy':'native Quorum Store defaults; effective-profile.json is authoritative'}
        effective['timing']['policy']='native Raptr relationships; effective-profile.json is authoritative'
    elif protocol.startswith('simpleit'):
        effective['storage']='native RocksDB; fresh database'
        from run_simpleit_local import parameters
        target=batch['useful_bytes_target'] or 65536
        native=parameters(protocol,nodes,useful,target,delta)
        effective['batching']={'useful_bytes_target':target//useful*useful,'native_header_bytes':native['header_size'],
            'max_wait_ms':None,'policy':'native proposal production; header timer is a round timeout'}
        effective['native_parameters']=native
        effective['timing'].update(round_timeout_ms=delta,repair_retry_ms=delta)
        if protocol=='simpleit-mempool':effective['timing'].update(fast_path_ms=max(1,delta//2),car_ms=2*delta)
    elif protocol=='autobahn':
        effective['storage']='native primary and worker RocksDB; fresh databases'
        # Native worker counts serialized transaction bytes, including ID metadata.
        count=(batch['useful_bytes_target']//useful if batch['useful_bytes_target'] is not None else None)
        if count==0:raise ValueError('batch target cannot hold a useful transaction')
        effective['batching']={'native_batch_bytes':count*(useful+40) if count else 500000,
            'useful_bytes_target':count*useful if count else None,'max_wait_ms':batch['max_wait_ms'] or 10}
        effective['timing'].update(timeout_ms=delta,fast_path_ms=delta,car_ms=delta,repair_retry_ms=delta)
    else:
        effective['storage']='native WAL; fresh directory'
        effective['batching']={'policy':'native blocks with two leaders; ingress wakeup5ms','ingress_wakeup_ms':5}
        effective['timing']['leader_timeout_ms']=delta
    return {'schema':1,'protocol':protocol,'nodes':nodes,'case':case,'requested':copy.deepcopy(config),
        'effective':effective,'allocation':contract.origin_plan(rate,60_000_000,nodes,origins),
        'source':contract.UPSTREAMS[protocol],'comparison_eligible':False}


def resolve_plan(plan):
    """Resolve every adapter before provisioning, including deferred fault cells."""
    result=[]
    for cell in plan['trials']:
        rate=cell['total_honest_input_tps'] or plan['config']['total_honest_input_tps'][0]
        row=resolve(plan['config'],cell['protocol'],cell['nodes'],rate,cell['case'])
        if cell['total_honest_input_tps'] is None:row['fault_rate_provisional']=True
        row['trial_id']=cell['id'];result.append(row)
    return result


def local_command(resolved,artifacts,output,*,nodes=None,seconds=60,drain=15,rate=None):
    """Fixed real runner commands. Overrides are diagnostic and recorded by caller."""
    import sys
    p=resolved['protocol'];e=resolved['effective'];n=nodes or resolved['nodes']
    contract.integer(seconds,1,60,'diagnostic seconds');contract.integer(drain,0,15,'diagnostic drain')
    r=rate or e['total_honest_input_tps'];u=e['useful_transaction_bytes'];d=e['timing']['Delta_ms']
    if n not in (4,10,50):raise ValueError('unsupported diagnostic committee')
    out=str(Path(output).resolve());base=[sys.executable,str(ROOT/capabilities(p)['local_runner'])]
    case=resolved['case']
    if p in ('delugi','raptr'):
        if set(artifacts)!= {'binary','build_receipt'}:raise ValueError('common binary and exact build receipt required')
        if p=='raptr':
            return base+['--binary',artifacts['binary'],'--build-receipt',artifacts['build_receipt'],
                '--nodes',str(n),'--rate',str(r),'--duration-ms',str(seconds*1000),'--drain-ms',str(drain*1000),
                '--useful-bytes',str(u),'--delta-ms',str(d),'--case',{'missing-data':'missing-payload-recovery'}.get(case,case),'--output',out]
        args=base+['--binary',artifacts['binary'],'--shared-build-receipt',artifacts['build_receipt'],'--skip-build',
            '--global-arrivals','--nodes',str(n),'--rate',str(r),'--warmup','0','--duration',str(seconds),'--drain',str(drain),
            '--useful-bytes',str(u),'--batch-ms',str(e['batching']['max_wait_ms']),
            '--max-batch-transactions',str(e['batching']['max_transactions']),'--bound-ms',str(d),'--output',out,
            '--spec-snapshot',str(ROOT/resolved['requested']['specification']['manifest']),
            '--storage-profile','shared-rocksdb-written-v1',
            '--paper-repository',str(ROOT/resolved['requested']['specification']['paper_repository'])]
        if case=='silent-first-leader':args+=['--silent-first-leader']
        elif case=='missing-data':args+=['--fault-replica','0','--fault-after','0','--fault-duration',str(seconds),
            '--fault-peers','1','--fault-batches','3','--fault-payload-bytes',str(u)]
        return args
    if p.startswith('simpleit'):
        if set(artifacts)!= {'build_receipt'}:raise ValueError('exact Simple-IT build receipt required')
        return base+['--variant',p,'--build-receipt',artifacts['build_receipt'],'--output',out,'--case',case,
            '--nodes',str(n),'--rate',str(r),'--duration-ms',str(seconds*1000),'--drain-ms',str(drain*1000),
            '--useful-bytes',str(u),'--batch-bytes',str(e['batching']['useful_bytes_target']),'--delta-ms',str(d)]
    if artifacts:raise ValueError('native runner verifies its pinned cache build provenance; no artifact overrides')
    args=base+['--population-profile',NATIVE,'--nodes',str(n),'--rate',str(r),'--warmup','0','--duration',str(seconds),
        '--drain',str(drain),'--useful-bytes',str(u),'--bound-ms',str(d),'--output',out]
    if p=='autobahn':args+=['--batch-bytes',str(e['batching']['native_batch_bytes']),'--ingress-batch-ms',str(e['batching']['max_wait_ms'])]
    else:args+=['--ingress-batch-ms','5']
    if case=='silent-first-leader':
        raise ValueError(p+' currently exposes a timed process pause, not an authenticated first-leader startup gate')
    elif case=='missing-data':
        args+=['--faulty-replica','0','--omit-replica','0','--omission-after','0','--omission-seconds',str(seconds)]
        for i in range(2,n):args+=['--publish-to-replica',str(i)]
    return args
