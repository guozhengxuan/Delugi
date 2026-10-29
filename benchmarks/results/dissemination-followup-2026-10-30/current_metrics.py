#!/usr/bin/env python3
"""Offline current WAN audit; no execution, networking, or cross-host clock joins."""
from collections import Counter, defaultdict
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
from cohort_store import ShardedArchive
from cohort_metrics import identity
import latency_decomposition as latency

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent)
OUT = parser.parse_args().output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
TRIAL = ROOT/'benchmark/.state/runs/delugi-freshness-wan-20261030/trials/b02e64f55f4e7fa0598860f6/trial'
REGIONS = ['Singapore', 'Frankfurt', 'London', 'Seoul']

def read(p):
    return json.loads(p.read_bytes())

def binding(p):
    return {'path': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}

def mean(rows, key):
    values = [r[key] for r in rows]
    return statistics.mean(values) if values else None

def summarize(rows, keys):
    return {'n': len(rows), **{key: mean(rows, key) for key in keys}}

def first(es, kind):
    return next((e for e in es if e['event'] == kind), None)

def outbox(es, layer, kind):
    return next((e for e in es if e['event'] == layer+'_outbox' and e['detail']['kind'] == kind), None)

archive = ShardedArchive(TRIAL/'cohorts/index.json')
trace_paths = [TRIAL/f'causal-traces/replica-{i}.json' for i in range(4)]
traces = {i: read(p) for i, p in enumerate(trace_paths)}
rounds = {}
for i, t in traces.items():
    assert t['replica'] == i and t['dropped'] == 0
    rounds[i] = defaultdict(list)
    for e in t['events']:
        rounds[i][e['round']].append(e)

keys = ['batch_ms', 'seal_to_report_ms', 'report_to_pool_ms', 'pool_to_input_ms',
        'input_to_outbox_ms', 'outbox_to_local_accept_ms', 'admission_to_outbox_ms',
        'admission_to_local_accept_ms']
self_requests = []
first_outputs = Counter()
first_output_rounds = defaultdict(set)
for i, ledger in archive.ledgers.items():
    events = traces[i]['events']
    seals = {identity(e['detail']['exact_batch_id']): e for e in events if e['event'] == 'batch_sealed'}
    mats = {}
    for e in events:
        if e['event'] == 'batch_materialized':
            mats.setdefault(identity(e['detail']['exact_batch_id']), e)
    outputs = {identity(o['id']): o for o in archive.rows(i, 'outputs') if o['origin'] == i}
    for q in archive.rows(i, 'requests'):
        if not ledger['window_start_us'] <= q['scheduled_us'] < ledger['window_end_us']:
            continue
        o = outputs[identity(q['id'])]
        b = identity(o['exact_batch_id'])
        r = mats[b]['round']
        leader = (r-1)%4
        first_outputs[leader] += 1
        first_output_rounds[leader].add(r)
        if leader != i:
            continue
        es = rounds[i][r]
        report = outbox(es, 'dissemination', 'REPORT')['at_us']
        pool = first(es, 'observation_pool_fixed')['at_us']
        inp = first(es, 'input_fixed')['at_us']
        sent = outbox(es, 'ordering', 'PROPOSE')['at_us']
        accepted = first(es, 'proposal_validated')['at_us']
        seal = seals[b]['at_us']
        row = {'origin': i, 'round': r, 'batch': b, 'sequence': q['sequence'],
               'batch_ms': (seal-q['admitted_us'])/1000,
               'seal_to_report_ms': (report-seal)/1000,
               'report_to_pool_ms': (pool-report)/1000,
               'pool_to_input_ms': (inp-pool)/1000,
               'input_to_outbox_ms': (sent-inp)/1000,
               'outbox_to_local_accept_ms': (accepted-sent)/1000,
               'admission_to_outbox_ms': (sent-q['admitted_us'])/1000,
               'admission_to_local_accept_ms': (accepted-q['admitted_us'])/1000}
        assert all(row[k] >= 0 for k in keys)
        assert abs(sum(row[k] for k in keys[:6])-row['admission_to_local_accept_ms']) < 1e-8
        self_requests.append(row)

leaders, inversions = [], []
snapshots = read(TRIAL/'snapshots.json')
for i, ledger in archive.ledgers.items():
    lo, hi = ledger['window_start_us'], ledger['window_end_us']
    leader_rounds = []
    for r, es in sorted(rounds[i].items()):
        sent = outbox(es, 'ordering', 'PROPOSE')
        if sent is not None:
            report = outbox(es, 'dissemination', 'REPORT')
            pool = first(es, 'observation_pool_fixed')
            inp = first(es, 'input_fixed')
            leader_rounds.append({'round': r, 'in_window': lo <= sent['at_us'] < hi,
                'report_us': report['at_us'], 'pool_us': pool['at_us'], 'input_us': inp['at_us'],
                'outbox_us': sent['at_us'], 'pool_signers': pool['detail']['signers'],
                'report_to_pool_ms': (pool['at_us']-report['at_us'])/1000,
                'pool_to_input_ms': (inp['at_us']-pool['at_us'])/1000,
                'input_to_outbox_ms': (sent['at_us']-inp['at_us'])/1000})
    start = snapshots[str(i)]['measurement_start']['construction']
    end = snapshots[str(i)]['measurement_end']['construction']
    construction_delta = {k: end[k]-start[k] for k in end}
    sampled = [e for e in traces[i]['events'] if e['event'] == 'input_construct' and lo <= e['at_us'] < hi]
    classifications = Counter()
    for es in rounds[0].values():
        for e in es:
            if e['event'] == 'classified' and (e['round']-1)%4 == i:
                status = e['detail']['status']
                classifications[next(iter(status)) if isinstance(status, dict) else status] += 1
    leaders.append({'leader': i, 'region': REGIONS[i], 'first_output_requests': first_outputs[i],
        'distinct_first_output_rounds': len(first_output_rounds[i]), 'full_trace_proposals': len(leader_rounds),
        'classified_at_replica_0': dict(classifications),
        'proposal_window': summarize([r for r in leader_rounds if r['in_window']],
            ['report_to_pool_ms', 'pool_to_input_ms', 'input_to_outbox_ms']),
        'construction_during_window': construction_delta,
        'sampled_window_constructions': [{'round': e['round'], **e['detail']['construction']} for e in sampled],
        'rounds': leader_rounds})
    for kind in ['observation_fixed', 'proposal_validated']:
        # Adjacent round r-1 (Seoul) versus r (Singapore); same observer clock.
        rows = []
        for r, es in sorted(rounds[i].items()):
            if r <= 1 or (r-1)%4 != 0:
                continue
            current = first(es, kind)
            previous = first(rounds[i].get(r-1, []), kind)
            if current is None or previous is None:
                continue
            if not (lo <= current['at_us'] < hi and lo <= previous['at_us'] < hi):
                continue
            rows.append({'round': r, 'previous_round': r-1,
                'later_round_precedes_ms': (previous['at_us']-current['at_us'])/1000,
                'current_detail': current['detail'] if kind == 'observation_fixed' else None,
                'previous_detail': previous['detail'] if kind == 'observation_fixed' else None})
        inverted = [r for r in rows if r['later_round_precedes_ms'] > 0]
        inversions.append({'observer': i, 'kind': kind, 'pairs': len(rows),
            'inverted': len(inverted), 'mean_signed_lead_ms': mean(rows, 'later_round_precedes_ms'),
            'mean_inverted_lead_ms': mean(inverted, 'later_round_precedes_ms'), 'rows': rows})

report = {'kind': 'corrected-delugi-healthy-wan-same-clock-audit',
    'self_leader_requests': summarize(self_requests, keys),
    'self_leader_by_region': {REGIONS[i]: summarize([r for r in self_requests if r['origin'] == i], keys) for i in range(4)},
    'leaders': leaders, 'adjacent_round_inversions': inversions,
    'limits': ['Full request stages bind to first execution, not earliest proposal containing a batch.',
               'OBS signer IDs are present but checkpoint contents and selected WA targets are absent.',
               'No cross-host timestamp subtraction. Only same observer comparisons or identities across hosts.',
               'No separate measurement of eligible-but-excluded batches; cutoffs/inversions are diagnostics.',
               'Sustained log filtering omits Effect::Trace observation_snapshot heights.'],
    'sources': [binding(p) for p in trace_paths+[TRIAL/'cohorts/index.json', TRIAL/'snapshots.json']]}
(OUT/'current-metrics.json').write_text(json.dumps(report, indent=2)+'\n')
(OUT/'self-leader-requests.json').write_text(json.dumps(self_requests, indent=2)+'\n')
print(json.dumps({'self_leader_requests': report['self_leader_requests'],
    'leaders': [{k:v for k,v in r.items() if k not in ['rounds','sampled_window_constructions']} for r in leaders],
    'inversions': [{k:v for k,v in r.items() if k != 'rows'} for r in inversions]}, indent=2))
