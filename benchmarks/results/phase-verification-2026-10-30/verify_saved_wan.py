#!/usr/bin/env python3
"""Bounds and phase diagnostics from saved WAN archives; no protocol execution.

The midpoint bound concerns first LOCAL VALIDATED proposal acceptance, not
cross-host leader emission. The phase calculation is an OBS event-process
diagnostic, not proof that the origin's OBS is required by its selected pool.
"""
import argparse
import bisect
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
from cohort_store import ShardedArchive
from cohort_metrics import identity
import latency_decomposition as delugi
import raptr_latency_decomposition as raptr

D = ROOT/'benchmark/.state/runs/delugi-freshness-wan-20261030/trials/b02e64f55f4e7fa0598860f6/trial'
R = ROOT/'benchmark/.state/runs/raptr-wan-stages-20261029/trials/9b65f5c790b85b8186317c0f'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parent)
OUT = parser.parse_args().output.resolve()
OUT.mkdir(parents=True, exist_ok=True)

def read(path): return json.loads(path.read_bytes())
def bind(path): return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
def mean(rows, key): return statistics.mean(row[key] for row in rows)

dv = delugi.analyze(D/'cohorts/index.json', D/'causal-traces')
rr = read(R/'result.json')
rv = raptr.analyze(R/'config.json', R/'replicas', rr['correct_replicas'], authentication=rr['authentication'])
assert dv['covered'] == rv['covered'] == 3000
assert dv['excluded'] == rv['excluded'] == {}

archive = ShardedArchive(D/'cohorts/index.json')
traces = {i: read(D/f'causal-traces/replica-{i}.json') for i in range(4)}
rows, phases = [], []
for i, ledger in archive.ledgers.items():
    events = traces[i]['events']
    assert traces[i]['dropped'] == 0
    proposals = {e['round']: e for e in events if e['event'] == 'proposal_validated'}
    assert len(proposals) == sum(e['event'] == 'proposal_validated' for e in events)
    seals = {identity(e['detail']['exact_batch_id']): e for e in events if e['event'] == 'batch_sealed'}
    materialized = {}
    for e in events:
        if e['event'] == 'batch_materialized':
            materialized.setdefault(identity(e['detail']['exact_batch_id']), e)
    classified = {e['round']: e for e in events if e['event'] == 'classified'}
    ready = {e['round']: e for e in events if e['event'] == 'payload_ready'}
    outputs = {identity(x['id']): x for x in archive.rows(i, 'outputs') if x['origin'] == i}
    own_seal_times = []
    for request in archive.rows(i, 'requests'):
        if not ledger['window_start_us'] <= request['scheduled_us'] < ledger['window_end_us']:
            continue
        output = outputs[identity(request['id'])]
        batch = identity(output['exact_batch_id'])
        r = materialized[batch]['round']
        seal = seals[batch]['at_us']
        associated = proposals[r]['at_us']
        # The exact-batch materializer expands descriptor suffixes FIFO by
        # strictly increasing committed round and records the first insertion.
        # Since every round up to r committed and materialized, no earlier-round
        # descriptor's expanded suffix contained this not-yet-inserted batch.
        assert all('Commit' in classified[k]['detail']['status'] for k in range(1, r+1))
        assert all(k in ready for k in range(1, r+1))
        assert all(identity(classified[k]['detail']['status']['Commit']) == identity(proposals[k]['detail']['digest']) for k in range(1, r+1))
        assert all(ready[k]['at_us'] <= materialized[batch]['at_us'] for k in range(1, r+1))
        candidates = [e for k, e in proposals.items() if k > r and seal <= e['at_us'] < associated]
        first_possible = min(candidates, key=lambda e: e['at_us']) if candidates else proposals[r]
        shift = (associated-first_possible['at_us'])/1000
        rows.append({'origin': i, 'execution_round': r, 'execution_leader': (r-1)%4,
            'batch': batch, 'seal_us': seal, 'associated_proposal_us': associated,
            'admission_us': request['admitted_us'],
            'earliest_candidate_round': first_possible['round'],
            'earliest_candidate_accept_us': first_possible['at_us'],
            'candidate_count': len(candidates), 'max_midpoint_shift_ms': shift,
            'associated_preproposal_ms': (associated-request['admitted_us'])/1000,
            'first_local_acceptance_lower_bound_ms': (first_possible['at_us']-request['admitted_us'])/1000})
        own_seal_times.append(seal)
    obs = sorted(e['at_us'] for e in events if e['event'] == 'observation_fixed')
    lo, hi = min(own_seal_times), max(own_seal_times)
    gaps = [b-a for a,b in zip(obs, obs[1:]) if lo <= a < b <= hi]
    area = 0
    for a,b in zip(obs, obs[1:]):
        x,y = max(a,lo), min(b,hi)
        if y > x:
            area += ((b-x)**2-(b-y)**2)/2
    actual = [obs[bisect.bisect_left(obs,s)]-s for s in own_seal_times]
    phases.append({'origin': i, 'samples': len(actual), 'complete_intervals': len(gaps),
        'mean_gap_ms': statistics.mean(gaps)/1000,
        'half_mean_gap_ms': statistics.mean(gaps)/2000,
        'renewal_residual_ms': sum(g*g for g in gaps)/sum(gaps)/2000,
        'uniform_time_residual_ms': area/(hi-lo)/1000,
        'actual_seal_to_next_own_obs_ms': statistics.mean(actual)/1000,
        'minimum_gap_ms': min(gaps)/1000, 'maximum_gap_ms': max(gaps)/1000,
        'variance_gap_ms2': statistics.pvariance(gaps)/1e6,
        'integration_interval_us': [lo, hi]})

def summarize(rs):
    return {'n': len(rs), 'potentially_affected': sum(r['candidate_count'] > 0 for r in rs),
        'mean_max_midpoint_shift_ms': mean(rs,'max_midpoint_shift_ms'),
        'maximum_shift_ms': max(r['max_midpoint_shift_ms'] for r in rs),
        'associated_preproposal_ms': mean(rs,'associated_preproposal_ms'),
        'first_local_acceptance_lower_bound_ms': mean(rs,'first_local_acceptance_lower_bound_ms')}

# The earlier fully revalidated reduction uses the same Raptr request stages.
baseline_path = ROOT/'benchmarks/results/dissemination-followup-2026-10-30/summary.json'
baseline = read(baseline_path)
raptr_associated = baseline['raptr']['all']['to_proposal_ms']
assert abs(mean(rows,'associated_preproposal_ms')-baseline['delugi']['all']['to_proposal_ms']) < 1e-9
bound = {'kind':'first-local-validated-inclusion-midpoint-bound-v1',
    'all': summarize(rows),
    'by_origin': {str(i):summarize([r for r in rows if r['origin']==i]) for i in range(4)},
    'by_execution_leader': {str(i):summarize([r for r in rows if r['execution_leader']==i]) for i in sorted({r['execution_leader'] for r in rows})},
    'round_gap': dict(Counter(r['earliest_candidate_round']-r['execution_round'] for r in rows)),
    'raptr_first_local_acceptance_upper_bound_ms': raptr_associated,
    'minimum_remaining_delugi_minus_raptr_gap_ms': mean(rows,'first_local_acceptance_lower_bound_ms')-raptr_associated,
    'limits': ['All candidates conservatively treated as containing the batch, although membership is not retained.',
               'First local validated acceptance, not first leader emission or pure dissemination.',
               'No cross-replica clock subtraction.',
               'Healthy all-Commit output-prefix evidence is essential; this argument does not transfer to Raptr partial-prefix semantics.']}
validation = {'covered': {'delugi':dv['covered'],'raptr':rv['covered']},
    'excluded': {'delugi':dv['excluded'],'raptr':rv['excluded']},
    'sources': [bind(D/'cohorts/index.json'), bind(R/'result.json'), bind(baseline_path)]
        +[bind(D/f'causal-traces/replica-{i}.json') for i in range(4)]
        +[bind(ROOT/'core/delugi/src/composed.rs'), bind(ROOT/'core/delugi/src/scanner.rs')],
    'delugi_validation_sources':dv['sources'], 'raptr_validation_sources':rv['sources']}
for name,value in [('midpoint-bound',bound),('midpoint-bound-rows',rows),('observation-phase',phases),('validation',validation)]:
    (OUT/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
print(json.dumps({'bound':bound['all'], 'minimum_remaining_gap_ms':bound['minimum_remaining_delugi_minus_raptr_gap_ms'],
    'phase':{'actual_own_obs_wait_ms':mean(phases,'actual_seal_to_next_own_obs_ms'),
             'uniform_time_own_obs_wait_ms':mean(phases,'uniform_time_residual_ms'),
             'half_mean_own_obs_gap_ms':mean(phases,'half_mean_gap_ms')}},indent=2))
