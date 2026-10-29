#!/usr/bin/env python3
"""Audit frozen WAN evidence; never start nodes or contact cloud services."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
import analyze_pipeline as pipeline
from cohort_metrics import identity
from cohort_store import ShardedArchive
import latency_decomposition as latency


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


FAULT_SCRIPT = ROOT/'benchmarks/results/delugi-pipeline-wan-2026-10-29/audit_fault.py'
GUARD_SCRIPT = ROOT/'benchmarks/results/freshness-fix-2026-10-29/plot_results.py'
fault = module('preceding_wan_fault_audit', FAULT_SCRIPT)
guard = module('local_freshness_guard_audit', GUARD_SCRIPT)


def read(path):
    return json.loads(Path(path).read_bytes())


def bound(path, expected=None):
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected is not None and digest != expected:
        raise ValueError(f'evidence changed: {path}')
    return {'path': str(path.resolve()), 'sha256': digest}


def trial_for(run, case):
    state = read(run/'state.json')
    rows = [r for r in state.get('rows', []) if r.get('protocol') == 'delugi']
    if len(rows) != 2 or any(r['status'] not in ('passed', 'completed') for r in rows):
        raise ValueError('both requested Delugi WAN runs must be complete')
    row = next(r for r in rows if r['case'] == case)
    trial = run/'trials'/row['trial_id']
    result_path = trial/'result.json'
    binding = bound(result_path, row['result']['sha256'])
    return trial/'trial', read(result_path), [bound(run/'state.json'), binding]


def same_anchor_example(archive, traces, leaders):
    """Use only replica 3's clock: its own third-anchor proposal includes request."""
    ledger = archive.ledgers[3]
    events = traces[3]['events']
    by_round = defaultdict(list)
    materialized = {}
    for event in events:
        by_round[event['round']].append(event)
        if event['event'] == 'batch_materialized':
            materialized.setdefault(identity(event['detail']['exact_batch_id']), event)
    outputs = {identity(o['id']): o for o in archive.rows(3, 'outputs') if o['origin'] == 3}
    own = {r['round']: r for r in leaders if r['replica'] == 3}
    candidates = []
    for request in archive.rows(3, 'requests'):
        if not ledger['window_start_us'] <= request['scheduled_us'] < ledger['window_end_us']:
            continue
        output = outputs.get(identity(request['id']))
        if output is None or request['admitted_us'] is None:
            continue
        mat = materialized.get(identity(output['exact_batch_id']))
        if mat is None or mat['round'] % 4:
            continue
        r = mat['round']; leader = own.get(r)
        admission = pipeline.first(by_round[r-3], 'admission')
        no_cer = pipeline.first(by_round[r-3], 'no_cer')
        if (leader is None or admission is None or no_cer is None or
                not admission['at_us'] <= request['admitted_us'] < no_cer['at_us']):
            continue
        candidates.append({'origin': 3, 'request_id': identity(request['id']),
            'sequence': request['sequence'], 'exact_batch_id': identity(output['exact_batch_id']),
            'execution_round': r, 'admitted_us': request['admitted_us'],
            'output_us': output['materialized_us'], 'leader': leader,
            'total_ms': (output['materialized_us']-request['admitted_us'])/1000})
    example = None
    if candidates:
        candidates.sort(key=lambda q: q['admitted_us'])
        example = candidates[len(candidates)//2]
        r = example['execution_round']
        names = {'admission', 'main_timer_arm', 'no_cer', 'history_ready', 'history_quorum',
                 'input_fixed', 'observation_pool_fixed', 'proposal_validated', 'classified',
                 'prefix_release', 'payload_ready', 'batch_sealed', 'batch_materialized'}
        selected = []
        for event in events:
            if event['event'] in ('batch_sealed', 'batch_materialized'):
                if identity(event['detail']['exact_batch_id']) == example['exact_batch_id']:
                    selected.append(event)
            elif event['round'] in (r-3, r):
                if (event['event'] in names or
                        event['event'] == 'dissemination_outbox' and event['detail'].get('kind') == 'REPORT' or
                        event['event'] == 'ordering_outbox' and event['detail'].get('kind') == 'PROPOSE'):
                    selected.append(event)
        example['same_clock_events'] = selected
        example['selection'] = 'median admission among origin-3 measurement requests admitted while its silent predecessor was unresolved and executed in the same third anchor'
    return {'matching_requests': len(candidates), 'representative_request': example,
            'scope': 'origin 3 only; all timestamps from replica 3; admission(s) <= request admission < NoCER(s), execution=s+3'}


def residual_cutoff_example(archive, traces, leaders):
    """Identify later arrivals that miss an already fixed own observation."""
    ledger = archive.ledgers[3];by_round = defaultdict(list);materialized = {};sealed = {}
    for event in traces[3]['events']:
        by_round[event['round']].append(event)
        if event['event'] == 'batch_materialized':
            materialized.setdefault(identity(event['detail']['exact_batch_id']), event)
        if event['event'] == 'batch_sealed':
            sealed.setdefault(identity(event['detail']['exact_batch_id']), event)
    outputs = {identity(o['id']): o for o in archive.rows(3, 'outputs') if o['origin'] == 3}
    own = {r['round']: r for r in leaders if r['replica'] == 3}
    candidates = []
    for request in archive.rows(3, 'requests'):
        if not ledger['window_start_us'] <= request['scheduled_us'] < ledger['window_end_us']:
            continue
        output = outputs.get(identity(request['id']))
        if output is None or request['admitted_us'] is None:
            continue
        batch = identity(output['exact_batch_id']);mat = materialized.get(batch)
        if mat is None or mat['round'] % 4 != 3:
            continue
        r = mat['round'];previous = own.get(r-3)
        observation = pipeline.first(by_round[r-3], 'observation_fixed')
        if (previous is None or observation is None or
                not observation['at_us'] < request['admitted_us'] < previous['proposal_us']):
            continue
        spans = latency.request_stages(request, output, sealed[batch], mat, by_round)
        candidates.append({'origin': 3, 'request_id': identity(request['id']),
            'sequence': request['sequence'], 'exact_batch_id': batch,
            'execution_round': r, 'previous_anchor_round': r-3,
            'previous_own_observation_us': observation['at_us'],
            'admitted_us': request['admitted_us'], 'batch_sealed_us': sealed[batch]['at_us'],
            'previous_input_us': previous['input_us'], 'previous_proposal_us': previous['proposal_us'],
            'output_us': output['materialized_us'],
            'stages_ms': dict(zip(latency.STAGES, [v/1000 for v in spans]))})
    candidates.sort(key=lambda q: q['admitted_us'])
    return {'matching_requests': len(candidates),
            'representative_request': candidates[0] if candidates else None,
            'selection': 'earliest origin-3 measurement request admitted after own previous-third-anchor observation fixed but before its proposal, then executing in a subsequent second anchor',
            'scope': 'all timestamps from replica 3; a selected residual boundary case, not attribution of every remaining request'}


def analyze_case(run, case, version):
    root, result, sources = trial_for(run, case)
    config = read(root/'config.json')
    archive = ShardedArchive(root/'cohorts/index.json')
    authentication = result['cohort_authentication']
    if (result['status'] != 'passed' or len(config['addresses']) != 4 or
            config['silent'] != (0 if case == 'silent-first-leader' else None) or
            not result['agreement']['all_correct_overlap_prefixes_verified'] or
            not authentication['verified'] or authentication['index_sha256'] != archive.index_sha256):
        raise ValueError('result/configuration/cohort verification failed')
    sources += [bound(root/'config.json'), bound(root/'cohorts/index.json', archive.index_sha256)]
    leaders, traces, reports, event_counts = [], {}, [], Counter()
    for entry in result['causal_trace']['files']:
        replica = entry['replica']
        path = root/'causal-traces'/f'replica-{replica}.json'
        sources.append(bound(path, entry['sha256']));trace = read(path)
        if (trace['replica'] != replica or trace['dropped'] or trace['run_error'] is not None or
                trace['total'] != len(trace['events']) or
                dict(Counter(e['event'] for e in trace['events'])) != trace['counts']):
            raise ValueError('trace incomplete or wrong replica')
        context = pipeline.first(trace['events'], 'run_context')
        if context is None or context['detail']['instance'] != config['instance']:
            raise ValueError('trace has wrong run identity')
        traces[replica] = trace
        for stream in ('requests', 'outputs', 'batches'):
            for _ in archive.rows(replica, stream):
                pass
        leaders.extend(pipeline.leader_rows(replica, trace, archive.ledgers[replica]))
        reports.append({'replica': replica, **guard.guards(trace, config, version)})
        event_counts.update({name: trace['counts'].get(name, 0) for name in
                             ('main_timer_expiry', 'catchup_timer_expiry', 'no_cer')})
    if set(traces) != set(range(4)):
        raise ValueError('trace replica set is incomplete')
    decomposition = latency.analyze(root/'cohorts/index.json', root/'causal-traces')
    if decomposition['completed'] != result['cohort']['completed']:
        raise ValueError('completed cohort disagrees with run result')
    groups = {'full_trace': leaders,
              'measurement_window': [r for r in leaders if r['in_measurement_window']]}
    timing = {}
    for population, rows in groups.items():
        timing[population] = {'proposals': len(rows),
            'spans_ms': {name: pipeline.stats([r[name] for r in rows if r[name] is not None]) for name in pipeline.SPANS},
            'input_age_by_round_mod_four': {str(k): pipeline.stats([r['input_to_proposal_ms'] for r in rows
                    if r['round'] % 4 == k and r['input_to_proposal_ms'] is not None]) for k in range(4)}}
    cadence = pipeline.normalized_cadence(leaders)
    full_cadence = pipeline.normalized_cadence([{**r, 'in_measurement_window': True} for r in leaders])
    out = {'case': case, 'sources': sources,
        'configuration': {k: config[k] for k in ('bound_ms', 'silent', 'ordering_mode', 'report_schedule')},
        'cohort': {k: result['cohort'][k] for k in ('scheduled', 'admitted', 'completed', 'unfinished', 'all_correct_collection')},
        'coverage': {k: decomposition[k] for k in ('covered', 'excluded')},
        'stage_means_ms': {v['stage']: v['mean_ms'] for v in decomposition['stages']},
        'mean_total_ms': decomposition['mean_admission_to_append_ms'], 'leader_timing': timing,
        'trace_detail_stride_by_replica': {str(i): t['detail_stride'] for i,t in traces.items()},
        'normalized_cadence_ms_per_round': pipeline.stats([r['normalized_ms_per_round'] for r in cadence]),
        'full_trace_normalized_cadence_ms_per_round': pipeline.stats([r['normalized_ms_per_round'] for r in full_cadence]),
        'cadence_intervals': cadence, 'leader_rounds': leaders,
        'guard_checks': reports, 'timer_callbacks_full_trace': dict(event_counts)}
    if case == 'silent-first-leader':
        # Retain the established exact-request join and validate it independently.
        diagnostic = fault.analyze(run)
        if (diagnostic['population']['covered'] != decomposition['covered'] or
                any(abs(v-diagnostic['stage_means_ms'][k]) > 1e-8 for k,v in out['stage_means_ms'].items())):
            raise ValueError('independent silent-cohort decomposition differs')
        out['execution_positions'] = diagnostic['by_execution_position_mod_four']
        out['missed_previous_third_anchor_origin_three'] = {
            'matching_requests': diagnostic['matching_origin_three_missed_anchor_requests'],
            'representative_request': diagnostic['representative_request']}
        out['same_recovery_anchor_origin_three'] = same_anchor_example(archive, traces, leaders)
        out['residual_observation_cutoff_origin_three'] = residual_cutoff_example(archive, traces, leaders)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    document = {'schema': 'delugi-wan-freshness-mechanism-v1',
        'scripts': [bound(__file__), bound(FAULT_SCRIPT), bound(GUARD_SCRIPT),
                    bound(ROOT/'scripts/analyze_pipeline.py'), bound(ROOT/'scripts/latency_decomposition.py')],
        'runs': {version: {case: analyze_case(run, case, version) for case in ('healthy', 'silent-first-leader')}
                 for version, run in (('before', args.before), ('after', args.after))},
        'contracts': [
            'Every event-duration subtraction uses one replica monotonic clock.',
            'Request stages are weighted over the same complete traced measurement cohort; missing and unfinished requests remain explicit.',
            'Leader timing is round-weighted; full-trace and proposal-in-window populations are reported separately.',
            'Cadence uses consecutive own-leader proposals both inside the same local input window, divided by the round-number gap.',
            'Round modulo four: 1 silent replica zero; 2 first honest anchor; 3 second honest anchor; 0 third honest anchor.',
            'Critical outbox/input/proposal/classification markers are retained even when handler details are sampled; no sampled handler duration is treated as complete coverage.',
            'Before and after are separate real WAN runs; no identical network realization or universal Byzantine freshness bound is claimed.']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, allow_nan=False)+'\n')
    print(json.dumps({v: {c: {'total_ms': r['mean_total_ms'], 'prefix_ms': r['stage_means_ms']['Contiguous prefix wait'],
        'input_age_ms': r['leader_timing']['measurement_window']['spans_ms']['input_to_proposal_ms'],
        'cadence_ms': r['normalized_cadence_ms_per_round'],
        'positions': {k: g['requests'] for k,g in r.get('execution_positions', {}).items()}}
        for c,r in cases.items()} for v,cases in document['runs'].items()}, indent=2))


if __name__ == '__main__':
    main()
