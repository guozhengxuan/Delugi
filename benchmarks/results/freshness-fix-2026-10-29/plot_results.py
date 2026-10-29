#!/usr/bin/env python3
"""Reduce a finished, source-bound local before/after diagnostic; never run nodes."""
from __future__ import annotations
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
import analyze_pipeline as pipeline
from cohort_store import ShardedArchive
import latency_decomposition as latency
from run_tcp_delay import verify_proxy

CELLS = [(topology, case, version) for topology in ('uniform', 'wan-like')
         for case in ('healthy', 'silent') for version in ('before', 'after')]
PLOT_STAGES = ('Batch formation', 'Await execution proposal', 'Agreement',
               'Contiguous prefix wait', 'Payload + append')


def read(path):
    return json.loads(Path(path).read_text())


def bound(path, expected=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'absent/linked evidence: {path}')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected is not None and digest != expected:
        raise ValueError(f'evidence changed: {path}')
    return {'path': str(path.resolve()), 'sha256': digest, 'bytes': path.stat().st_size}


def verify_binding(binding):
    value = bound(binding['path'], binding['sha256'])
    if value['bytes'] != binding['bytes']:
        raise ValueError('bound byte count differs')
    return value


def stats(values):
    return pipeline.stats(values)


def guards(trace, config, version):
    n, owner = len(config['addresses']), trace['replica']
    f = (n-1)//3
    proposals = {}
    report_counts = Counter()
    branches = Counter()
    for event in sorted(trace['events'], key=lambda e: e['at_us']):
        r, detail = event['round'], event['detail']
        if event['event'] == 'proposal_validated':
            proposals.setdefault(r, event['at_us'])
        if event['event'] != 'dissemination_outbox' or detail.get('kind') != 'REPORT':
            continue
        report_counts[r] += 1
        if (detail['signer'] != owner or (r-1)%n != owner or detail['admitted'] < r
                or detail['schedule'] != 'pipeline' or report_counts[r] != 1):
            raise ValueError('REPORT leader, admission or once-only invariant failed')
        closed = detail['closed_signers']
        if len(set(closed)) != len(closed) or any(type(i) is not int or not 0 <= i < n for i in closed):
            raise ValueError('CLOSED evidence does not use distinct committee identities')
        horizon = detail['local_report_horizon']
        if version == 'before':
            evidence = {'initial_four': r <= 4,
                        'old_prefix_plus_four': r > 4 and horizon >= r-4,
                        'closed_fallback': len(closed) >= f+1,
                        'history_fallback': detail['exact_history_ready']}
        else:
            predecessor = detail['predecessor_proposal_validated']
            if type(predecessor) is not bool or predecessor != (r > 3 and r-3 in proposals):
                raise ValueError('predecessor flag differs from prior full-validation trace')
            evidence = {'initial_three': r <= 3,
                        'resolved_local_prefix': r > 3 and horizon >= r-3,
                        'validated_wave': r > 3 and (r == 4 or horizon >= r-4) and predecessor,
                        'closed_fallback': len(closed) >= f+1,
                        'history_fallback': detail['exact_history_ready']}
        if not any(evidence.values()):
            raise ValueError('REPORT did not satisfy its versioned preparation guard')
        branches.update(name for name, yes in evidence.items() if yes)
    return {'report_count': sum(report_counts.values()), 'satisfied_branches': dict(branches),
            'branch_counts_overlap': True}


def proxy_summary(report):
    verify_proxy(report)
    result = {'delay_matrix_ms': report['delay_matrix_ms'], 'scalar_delay_ms': report['delay_ms_per_direction'],
              'all_connections_closed': True, 'no_discarded_bytes': True, 'no_queue_saturation': True,
              'scope': 'proxy chunk read to forwarding; not measured network end-to-end latency', 'edges': []}
    for record in report['connections']:
        for direction in ('client_to_replica', 'replica_to_client'):
            row = record[direction]
            if not row['forwarded_chunks']:
                continue
            result['edges'].append({'source_replica': record['source_replica'],
                'destination_replica': record['destination_replica'], 'direction': direction,
                'requested_ms': record['requested_delay_ms'][direction],
                'chunks': row['forwarded_chunks'], 'bytes': row['forwarded_bytes'],
                'mean_hold_ms': row['forward_delay_sum_us']/row['forwarded_chunks']/1000,
                'min_hold_ms': row['forward_delay_min_us']/1000,
                'max_hold_ms': row['forward_delay_max_us']/1000})
    return result


def reduce_row(row, model):
    result_binding = verify_binding(row['result'])
    reduced_binding = verify_binding(row['decomposition'])
    result = read(result_binding['path'])
    root = Path(result_binding['path']).parent
    config = read(root/'config.json')
    if (result['status'] != 'passed' or row['status'] != 'passed'
            or not result['agreement']['all_correct_overlap_prefixes_verified']
            or not result['causal_trace']['complete']):
        raise ValueError('run or output/trace checks did not pass')
    if (len(config['addresses']) != 4 or config['bound_ms'] != row['bound_ms']
            or config['ordering_mode'] != 'canonical' or config['report_schedule'] != 'pipeline'
            or config['ordering_batch'] is not True
            or config['sustained']['warmup_ms'] != 2000 or config['sustained']['measurement_ms'] != 10000):
        raise ValueError('actual run configuration differs from matched preset')
    actual_settings = config['sustained']
    expected_settings = {'total_rate': 100, 'transaction_bytes': 61, 'useful_bytes': 1,
                         'max_batch_transactions': 128, 'batch_ms': 10}
    if (any(actual_settings[k] != value for k, value in expected_settings.items())
            or result['settings'] != actual_settings
            or config['silent'] != (0 if row['case'] == 'silent' else None)
            or config['causal_trace'] != {'detail_stride': 1, 'max_events': 500000}
            or {c['id'] for c in result['children']} != set(range(4))
            or len({c['pid'] for c in result['children']}) != 4
            or any(c['exit_code'] != 0 or c['telemetry_errors'] for c in result['children'])
            or set(result['storage']) != {'0', '1', '2', '3'}
            or any(s['profile'] != 'memory-visible-v1' for s in result['storage'].values())):
        raise ValueError('actual workload, process, trace or storage settings differ')
    archive = ShardedArchive(root/'cohorts/index.json')
    auth = result['cohort_authentication']
    if not auth['verified'] or auth['index_sha256'] != archive.index_sha256:
        raise ValueError('cohort lacks matching successful signature verification')
    sources = [result_binding, reduced_binding, bound(root/'config.json'),
               bound(root/'cohorts/index.json', auth['index_sha256'])]
    proxy_binding = bound(root/'proxy.json', result['proxy']['sha256'])
    sources.append(proxy_binding)
    proxy = proxy_summary(read(proxy_binding['path']))
    expected_matrix = model['matrix_ms'] if row['topology'] == 'wan-like' else None
    if proxy['delay_matrix_ms'] != expected_matrix or proxy['scalar_delay_ms'] != (None if expected_matrix else 10):
        raise ValueError('actual proxy delay topology differs')
    leaders, guard_counts, timer_counts = [], [], Counter()
    for entry in result['causal_trace']['files']:
        replica = entry['replica'];path = root/'causal-traces'/f'replica-{replica}.json'
        sources.append(bound(path, entry['sha256']));trace = read(path)
        if (trace['replica'] != replica or trace['dropped'] or trace['run_error'] is not None
                or trace['total'] != len(trace['events']) or trace['detail_stride'] != 1
                or dict(Counter(e['event'] for e in trace['events'])) != trace['counts']):
            raise ValueError('trace is incomplete or sampled differently')
        context = pipeline.first(trace['events'], 'run_context')
        if context is None or context['detail']['instance'] != config['instance']:
            raise ValueError('trace run identity differs')
        ledger = archive.ledgers[replica]
        for stream in ('requests', 'outputs', 'batches'):
            for _ in archive.rows(replica, stream):
                pass
        leaders.extend(pipeline.leader_rows(replica, trace, ledger))
        guard_counts.append({'replica': replica, **guards(trace, config, row['version'])})
        timer_counts.update({name: trace['counts'].get(name, 0) for name in
                             ('main_timer_expiry', 'catchup_timer_expiry', 'no_cer')})
    fresh = latency.analyze(root/'cohorts/index.json', root/'causal-traces')
    saved = read(reduced_binding['path'])
    for key in ('scheduled', 'completed', 'covered', 'excluded', 'stages', 'mean_admission_to_append_ms'):
        if fresh[key] != saved[key]:
            raise ValueError('reduced stages differ from frozen run reduction: '+key)
    cohort = result['cohort']
    if (fresh['scheduled'] != 1000 or fresh['completed'] != cohort['completed']
            or fresh['covered'] != fresh['completed'] or fresh['excluded']):
        raise ValueError('completed-request stage coverage differs')
    complete = [r for r in leaders if r['in_measurement_window'] and not r['missing_spans']]
    intervals = pipeline.normalized_cadence(leaders)
    stage_values = [s['mean_ms'] for s in fresh['stages']]
    if abs(sum(stage_values)-fresh['mean_admission_to_append_ms']) > 1e-6:
        raise ValueError('stages do not sum to the complete-cohort total')
    return {'name': row['name'], 'topology': row['topology'], 'case': row['case'], 'version': row['version'],
        'bound_ms': row['bound_ms'], 'binary': row['binary'], 'sources': sources,
        'cohort': {k: cohort[k] for k in ('scheduled', 'admitted', 'completed', 'unfinished')},
        'stage_coverage': {k: fresh[k] for k in ('covered', 'excluded')},
        'mean_ms': fresh['mean_admission_to_append_ms'], 'stages': fresh['stages'],
        'plot_stages': [{'stage': k, 'mean_ms': v} for k,v in zip(PLOT_STAGES, stage_values[:4]+[sum(stage_values[4:])])],
        'window_goodput_tps': cohort['window']['unique_completion_tps'],
        'all_correct_collection': cohort['all_correct_collection'],
        'drain_complete': result['drain_complete'], 'agreement_verified': True,
        'leader_rounds_in_window': len(complete),
        'leader_stage_ms': {name: stats([r[name] for r in complete]) for name in pipeline.SPANS},
        'cadence_ms_per_round': stats([r['normalized_ms_per_round'] for r in intervals]),
        'cadence_scope': 'successive own-leader proposals both inside own input window, divided by round-number gap; includes recovery in silent cases',
        'guard_checks': guard_counts, 'timer_callbacks_whole_trace': dict(timer_counts), 'proxy': proxy,
        'measurement_tcp_written_bytes': result['comparison']['replica_tcp_written_bytes']}


def render(rows, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    plt.rcParams.update({'font.family':'DejaVu Sans', 'font.size':11,
                         'svg.fonttype':'none', 'svg.hashsalt':'delugi-freshness-20261029'})
    colors = ('#6BA5C8', '#3578A7', '#83A746', '#D39846', '#818899')
    labels = ('Batching', 'Await proposal', 'Agreement', 'Prefix wait', 'Payload + append')
    fig, axes = plt.subplots(2,2,figsize=(12.8,8.6))
    fig.subplots_adjust(left=.10,right=.96,top=.77,bottom=.19,hspace=.62,wspace=.30)
    for a, topology in enumerate(('uniform','wan-like')):
        for b, case in enumerate(('healthy','silent')):
            ax = axes[a,b]
            selected = [next(r for r in rows if (r['topology'],r['case'],r['version'])==(topology,case,v))
                        for v in ('before','after')]
            maximum = max(r['mean_ms'] for r in selected)
            for y,row in enumerate(selected):
                left = 0
                for stage,color in zip(row['plot_stages'],colors):
                    ax.barh(y,stage['mean_ms'],left=left,height=.38,color=color)
                    left += stage['mean_ms']
                ax.text(left+maximum*.025,y,f"{row['mean_ms']:,.1f} ms",va='center',fontweight='bold',fontsize=10)
                ax.text(0,y+.29,f"{row['cohort']['completed']:,}/{row['cohort']['scheduled']:,} completed; all completed covered",
                        va='center',fontsize=8.5,color='#617082')
            title = ('Uniform delay' if topology=='uniform' else 'Synthetic WAN-like delays')
            ax.set_title(title+' · '+('healthy' if case=='healthy' else 'silent replica 0'),fontweight='bold',pad=12)
            ax.set(yticks=[0,1],yticklabels=['Before','Corrected'],xlim=(0,maximum*1.28),ylim=(1.55,-.55),
                   xlabel='Mean admission → verified output (ms)')
            ax.set_axisbelow(True);ax.grid(axis='x',alpha=.17)
            ax.spines[['top','right','left','bottom']].set_visible(False);ax.tick_params(axis='both',length=0)
    fig.suptitle('Delugi freshness correction: matched local processes',x=.04,ha='left',y=.98,fontsize=20,fontweight='bold')
    fig.text(.04,.91,'4 independent release processes · 100 tx/s · 2 s warmup + 10 s input · 1 useful byte/tx',fontsize=11)
    fig.legend(handles=[Patch(color=c,label=l) for c,l in zip(colors,labels)],loc='upper left',
               bbox_to_anchor=(.035,.885),ncol=5,frameon=False,columnspacing=1.6,handlelength=1.5)
    fig.text(.04,.11,'Uniform: δ = 10 ms, Δ = 100 ms. Synthetic WAN-like matrix: Δ = 1,000 ms; two edges are estimates.',fontsize=10)
    fig.text(.04,.075,'Origin-local proposal acceptance separates await-proposal and agreement. Panel scales differ.',fontsize=10)
    fig.text(.04,.04,'Userspace TCP delay and memory records; no bandwidth cap. These are local diagnostics, not another cloud evaluation.',fontsize=10,color='#617082')
    for ext in ('png','pdf','svg'):
        fig.savefig(output/f'latency-before-after.{ext}',dpi=180,bbox_inches='tight')
    plt.close(fig)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();index=read(args.index)
    if index['status']!='completed' or len(index['runs'])!=8:
        raise ValueError('wait for all eight completed runs; never analyze during measurement')
    actual=[(r['topology'],r['case'],r['version']) for r in index['runs']]
    if actual!=CELLS:raise ValueError('expected exact matched run order and cells')
    if any(r['binary'] != index['binary_bindings'][r['version']] for r in index['runs']):
        raise ValueError('run executable differs from version binding')
    expected={'nodes':4,'rate':100,'useful_bytes':1,'encoded_bytes':61,'warmup_s':2,'duration_s':10,'drain_s':15,
              'batch_ms':10,'batch_max_transactions':128,'trace_stride':1,'trace_max_events':500000}
    if index['settings']!=expected:raise ValueError('matched settings differ')
    provenance=[bound(args.index)]
    for group in ('binary_bindings','build_manifests'):
        provenance.extend(verify_binding(v) for v in index[group].values())
    provenance.extend(verify_binding(v) for v in index['controller_sources'])
    rows=[reduce_row(row,index['delay_model']) for row in index['runs']]
    args.output.mkdir(parents=True,exist_ok=True)
    document={'schema':1,'scope':index['scope'],'settings':index['settings'],'delay_model':index['delay_model'],
              'calibration_added_rtt_ms':index['scalar_calibration']['median_added_rtt_ms'],
              'sources':provenance,'analysis_script':bound(__file__),'runs':rows}
    (args.output/'comparison.json').write_text(json.dumps(document,indent=2,allow_nan=False)+'\n')
    csvrows=[]
    for row in rows:
        csvrows.append({**{k:row[k] for k in ('topology','case','version','mean_ms','window_goodput_tps')},
            **row['cohort'],**{s['stage']:s['mean_ms'] for s in row['stages']},
            'cadence_ms_per_round':row['cadence_ms_per_round']['mean'],
            'cadence_intervals':row['cadence_ms_per_round']['count'],
            'leader_propose_to_direct_ms':row['leader_stage_ms']['proposal_to_direct_commit_ms']['mean'],
            'leader_rounds':row['leader_rounds_in_window']})
    with (args.output/'stages.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(csvrows[0]));writer.writeheader();writer.writerows(csvrows)
    render(rows,args.output)
    print(json.dumps({'status':'verified','runs':len(rows),'output':str(args.output),
                      'totals_ms':{r['name']:r['mean_ms'] for r in rows}},indent=2))


if __name__=='__main__':
    main()
