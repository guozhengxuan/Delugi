#!/usr/bin/env python3
"""Offline request/round joins for the persistent-silence pipeline experiment."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT / 'scripts'))
from cohort_metrics import identity
from cohort_store import ShardedArchive
from latency_decomposition import request_stages, STAGES


def read(path):
    return json.loads(Path(path).read_bytes())


def bound(path):
    path = Path(path)
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def stats(values):
    values = sorted(values)
    if not values:
        return {'count': 0, 'mean': None, 'median': None, 'min': None, 'max': None}
    return {'count': len(values), 'mean': statistics.fmean(values),
            'median': statistics.median(values), 'min': values[0], 'max': values[-1]}


def first(events, name, kind=None):
    return next((e for e in events if e['event'] == name and
                 (kind is None or e['detail'].get('kind') == kind)), None)


def analyze(run):
    state = read(run / 'state.json')
    rows = [r for r in state.get('rows', []) if r.get('protocol') == 'delugi']
    if len(rows) != 2 or any(r['status'] not in ('passed', 'completed') for r in rows):
        raise ValueError('both requested Delugi runs must be completed')
    row = next(r for r in rows if r['case'] == 'silent-first-leader')
    trial = run / 'trials' / row['trial_id']
    result_path = trial / 'result.json'
    if bound(result_path)['sha256'] != row['result']['sha256']:
        raise ValueError('trial result changed')
    result = read(result_path)
    if result['status'] != 'passed':
        raise ValueError('silent run did not pass')
    root = trial / 'trial'
    config = read(root / 'config.json')
    if config['silent'] != 0 or len(config['addresses']) != 4:
        raise ValueError('this placement interpretation requires silent replica zero and n=4')
    a = ShardedArchive(root / 'cohorts/index.json')
    sources = [bound(run / 'state.json'), bound(result_path), bound(root / 'config.json'),
               bound(root / 'cohorts/index.json')]
    traces, rounds, sealed, materialized, leader_rounds = {}, {}, {}, {}, {}
    for id in a.ledgers:
        path = root / f'causal-traces/replica-{id}.json'
        trace = read(path)
        if trace['dropped'] != 0 or trace['run_error'] is not None or trace['replica'] != id:
            raise ValueError('incomplete or wrong replica trace')
        expected = next(e['sha256'] for e in result['causal_trace']['files'] if e['replica'] == id)
        if bound(path)['sha256'] != expected:
            raise ValueError('trace changed')
        sources.append(bound(path)); traces[id] = trace
        rounds[id], sealed[id], materialized[id] = defaultdict(list), {}, {}
        for event in trace['events']:
            rounds[id][event['round']].append(event)
            if event['event'] == 'batch_sealed':
                sealed[id].setdefault(identity(event['detail']['exact_batch_id']), event)
            if event['event'] == 'batch_materialized':
                materialized[id].setdefault(identity(event['detail']['exact_batch_id']), event)
        for r, events in rounds[id].items():
            proposal = first(events, 'ordering_outbox', 'PROPOSE')
            if proposal:
                if id != (r - 1) % 4:
                    raise ValueError('proposal outbox leader mismatch')
                inp, report = first(events, 'input_fixed'), first(events, 'dissemination_outbox', 'REPORT')
                history = first(events, 'history_quorum')
                leader_rounds[r] = {
                    'leader': id, 'round': r, 'proposal_us': proposal['at_us'],
                    'input_us': inp['at_us'] if inp else None,
                    'report_us': report['at_us'] if report else None,
                    'history_us': history['at_us'] if history else None,
                    'frozen_age_ms': (proposal['at_us'] - inp['at_us']) / 1000 if inp else None,
                }
    count = Counter(); groups = defaultdict(list); requests = []; excluded = Counter()
    for id, ledger in a.ledgers.items():
        outputs = {identity(o['id']): o for o in a.rows(id, 'outputs') if o['origin'] == id}
        for request in a.rows(id, 'requests'):
            if not ledger['window_start_us'] <= request['scheduled_us'] < ledger['window_end_us']:
                continue
            count['scheduled'] += 1
            if request['admitted_us'] is not None:
                count['admitted'] += 1
            output = outputs.get(identity(request['id']))
            if output is None or request['admitted_us'] is None or request.get('rejected_us') is not None:
                excluded['unfinished_or_unadmitted_or_rejected'] += 1
                continue
            count['completed'] += 1
            batch = identity(output['exact_batch_id'])
            try:
                mat, seal = materialized[id][batch], sealed[id][batch]
                spans = request_stages(request, output, seal, mat, rounds[id])
            except (KeyError, ValueError) as error:
                excluded[str(error)] += 1
                continue
            count['covered'] += 1
            r = mat['round']; leader = leader_rounds.get(r)
            record = {'origin': id, 'request_id': identity(request['id']),
                      'sequence': request['sequence'], 'exact_batch_id': batch,
                      'admitted_us': request['admitted_us'], 'batch_sealed_us': seal['at_us'],
                      'execution_round': r, 'output_us': output['materialized_us'],
                      'stages_ms': dict(zip(STAGES, [v / 1000 for v in spans])),
                      'total_ms': sum(spans) / 1000,
                      'execution_input_frozen_age_ms': leader['frozen_age_ms'] if leader else None}
            requests.append(record); groups[r % 4].append(record)
    candidates = []
    for record in requests:
        if record['origin'] != 3 or record['execution_round'] % 4 != 2:
            continue
        r = record['execution_round']; previous_anchor = leader_rounds.get(r - 2)
        if (previous_anchor and previous_anchor['input_us'] is not None and
                previous_anchor['input_us'] < record['admitted_us'] < previous_anchor['proposal_us']):
            candidates.append(record)
    example = None
    if candidates:
        candidates.sort(key=lambda r: r['admitted_us'])
        example = dict(candidates[len(candidates) // 2]); r = example['execution_round']
        example['previous_third_anchor'] = leader_rounds[r - 2]
        example['selection'] = 'median admitted time among origin-3 completed requests that missed a frozen prior third anchor'
        wanted = {(r - 2, 'dissemination_outbox', 'REPORT'), (r - 2, 'input_fixed', None),
                  (r - 5, 'no_cer', None), (r - 2, 'history_quorum', None),
                  (r - 2, 'ordering_outbox', 'PROPOSE'), (r, 'proposal_validated', None),
                  (r, 'classified', None), (r - 1, 'no_cer', None),
                  (r + 2, 'ordering_outbox', 'PROPOSE'), (r - 1, 'classified', None),
                  (r, 'prefix_release', None)}
        example['same_clock_events'] = [e for e in traces[3]['events'] if
            (e['round'], e['event'], e['detail'].get('kind')) in wanted]
    return {
        'schema': 'delugi-wan-frozen-anchor-audit-v1', 'run': str(run.resolve()),
        'case': 'silent-first-leader', 'sources': sources,
        'source_script_sha256': bound(__file__)['sha256'],
        'configuration': {k: config[k] for k in ('bound_ms', 'ordering_mode', 'report_schedule', 'silent')},
        'population': dict(count), 'excluded': dict(excluded),
        'all_correct_collection': result['cohort']['all_correct_collection'],
        'stage_means_ms': {stage: statistics.fmean(q['stages_ms'][stage] for q in requests) for stage in STAGES},
        'mean_total_ms': statistics.fmean(q['total_ms'] for q in requests),
        'by_execution_position_mod_four': {str(k): {
            'requests': len(v), 'prefix_wait_ms': stats([q['stages_ms']['Contiguous prefix wait'] for q in v]),
            'total_ms': stats([q['total_ms'] for q in v]),
            'execution_input_age_ms_request_weighted': stats([q['execution_input_frozen_age_ms'] for q in v
                                                           if q['execution_input_frozen_age_ms'] is not None])}
            for k, v in sorted(groups.items())},
        'third_anchor_frozen_age_ms_round_weighted': stats([v['frozen_age_ms'] for r,v in leader_rounds.items()
                                                          if r % 4 == 0 and v['frozen_age_ms'] is not None]),
        'matching_origin_three_missed_anchor_requests': len(candidates),
        'representative_request': example,
        'leader_rounds': list(leader_rounds.values()),
        'contracts': ['Every event-duration subtraction uses one replica monotonic clock.',
                      'Leader input-freeze age is a same-leader duration; transaction weighting assigns that duration to requests first executed in its round.',
                      'Execution position 0 is the third honest anchor; 2 the first, 3 the second; position 1 is the silent leader.',
                      'The representative request is selected only if its own third-anchor input froze before its admission and that anchor proposed afterward.',
                      'Missing or unfinished requests remain counted and excluded from completed stage means, never zero-filled.']}


if __name__ == '__main__':
    run, output = map(Path, sys.argv[1:3])
    result = analyze(run)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('population', 'excluded', 'stage_means_ms',
                     'by_execution_position_mod_four', 'matching_origin_three_missed_anchor_requests')}))
