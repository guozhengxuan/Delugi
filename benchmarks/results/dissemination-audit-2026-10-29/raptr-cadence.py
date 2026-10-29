#!/usr/bin/env python3
"""Offline same-clock cadence audit of the recorded healthy Raptr WAN trial.

This is a trace analysis, not a protocol workload or a fresh signature check.
The existing analyzer binds sources to previously verified signed receipts.
"""
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
import raptr_latency_decomposition as decomposition

TRIAL = ROOT / 'benchmark/.state/runs/raptr-wan-stages-20261029/trials/9b65f5c790b85b8186317c0f'


def stats(values):
    return {'count': len(values), 'mean_ms': statistics.mean(values) if values else None,
            'min_ms': min(values) if values else None,
            'max_ms': max(values) if values else None}


def main():
    config = json.loads((TRIAL / 'config.json').read_text())
    result = json.loads((TRIAL / 'result.json').read_text())
    validated = decomposition.analyze(TRIAL / 'config.json', TRIAL / 'replicas',
                                     result['correct_replicas'],
                                     authentication=result['authentication'])
    duration_us = config['measurement_duration_ms'] * 1000
    rows = []
    for origin in result['correct_replicas']:
        directory = TRIAL / f'replicas/node-{origin}'
        receipt = json.loads((directory / 'final.json').read_text())
        trace_path = directory / 'latency-trace.json'
        trace = json.loads(trace_path.read_text())
        start = receipt['body']['epoch_us']
        stop = start + duration_us
        first = {}
        for event in sorted(trace['events'], key=lambda e: e['at_us']):
            if event['event'] == 'proposal_validated':
                first.setdefault(event['round'], event['at_us'])
        rounds = sorted((r, t) for r, t in first.items() if start <= t < stop)
        adjacent = [(b[1] - a[1]) / 1000 for a, b in zip(rounds, rounds[1:])
                    if b[0] == a[0] + 1]
        # Native Config::leader(round) = round % n. Both observations below
        # therefore occur at the same leader on that leader's monotonic clock.
        own = [(r, t) for r, t in rounds if r % len(config['addresses']) == origin]
        cycles = [{'start_round': a[0], 'end_round': b[0],
                   'start_at_us': a[1], 'end_at_us': b[1],
                   'four_round_cycle_ms': (b[1] - a[1]) / 1000,
                   'per_round_ms': (b[1] - a[1]) / 4000}
                  for a, b in zip(own, own[1:]) if b[0] == a[0] + 4]
        by_transition = {}
        for prev in range(4):
            gaps = [(b[1] - a[1]) / 1000 for a, b in zip(rounds, rounds[1:])
                    if b[0] == a[0] + 1 and a[0] % 4 == prev]
            by_transition[f'{prev}->{(prev + 1) % 4}'] = stats(gaps)
        rows.append({'replica': origin, 'window_start_us': start,
                     'window_end_us_exclusive': stop,
                     'proposal_event_count_in_window': len(rounds),
                     'first_round': rounds[0][0], 'last_round': rounds[-1][0],
                     'consecutive_round_gaps': stats(adjacent),
                     'own_leader_four_round_cycles_divided_by_four': stats([c['per_round_ms'] for c in cycles]),
                     'own_leader_four_round_cycle_rows': cycles,
                     'by_previous_leader': by_transition,
                     'trace_sha256': hashlib.sha256(trace_path.read_bytes()).hexdigest()})
    summary = {
        'schema': 1,
        'trial': str(TRIAL),
        'run_id': config['run_id'],
        'measurement_duration_ms': config['measurement_duration_ms'],
        'event': 'first proposal_validated per round; after native proposal verification and inbox processing',
        'window': 'each replica signed receipt epoch_us <= local CLOCK_MONOTONIC event at_us < epoch_us + measurement_duration_ms*1000',
        'leader_rule': 'native Config::leader(round) = round % 4',
        'four_round_cycle': 'two consecutive in-window proposal_validated events for that replica as leader; round difference exactly 4; local timestamp difference divided by 4',
        'interpretation': 'Cadence proxy, not an exact proposal-send timestamp. Same-leader comparisons avoid alternating leader-to-observer route offsets; self-dispatch and validation jitter remains.',
        'cross_host_subtraction': False,
        'validation': 'Existing decomposition analyzer rechecked receipt and source hashes against the previously native-verified archive authentication map; no new native-signature verification.',
        'decomposition_covered': validated.get('covered'),
        'replicas': rows,
    }
    destination = Path(__file__).with_name('raptr-cadence-summary.json')
    destination.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({**{k: v for k, v in summary.items() if k != 'replicas'},
                      'replicas': [{k: v for k, v in row.items() if k != 'own_leader_four_round_cycle_rows'} for row in rows]}, indent=2))


if __name__ == '__main__':
    main()
