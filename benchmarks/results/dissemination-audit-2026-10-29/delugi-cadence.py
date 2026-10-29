#!/usr/bin/env python3
"""Offline, exact-window, same-clock cadence audit of the saved Delugi trial.

No network, protocol execution, source edits, or cross-host clock subtraction.
The cohort index supplies each replica's original 30-second measurement window.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import sys

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'core/delugi/src/composed.rs').is_file())
sys.path.insert(0, str(ROOT / 'scripts'))
from cohort_store import ShardedArchive

DEFAULT_TRIAL = ROOT / 'benchmark/.state/runs/delugi-raptr-wan-30s-20261028/trials/5e2250ff5121e8d986930b2e/trial'


def bind(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'expected regular evidence file: {path}')
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def stats(values):
    return {'count': len(values),
            'mean_ms': statistics.mean(values) if values else None,
            'min_ms': min(values) if values else None,
            'max_ms': max(values) if values else None}


def cycles(events, origin, start, stop):
    first = {}
    for event in sorted(events, key=lambda e: e['at_us']):
        first.setdefault(event['round'], event['at_us'])
    own = sorted((r, t) for r, t in first.items()
                 if (r - 1) % 4 == origin and start <= t < stop)
    rows = [{'start_round': a[0], 'end_round': b[0],
             'start_at_us': a[1], 'end_at_us': b[1],
             'four_round_cycle_ms': (b[1] - a[1]) / 1000,
             'per_round_ms': (b[1] - a[1]) / 4000}
            for a, b in zip(own, own[1:]) if b[0] == a[0] + 4]
    return {'own_proposals_in_window': len(own),
            'first_round': own[0][0] if own else None,
            'last_round': own[-1][0] if own else None,
            'own_leader_four_round_cycles_divided_by_four': stats([r['per_round_ms'] for r in rows]),
            'own_leader_four_round_cycle_rows': rows}


def analyze(trial):
    index = trial / 'cohorts/index.json'
    archive = ShardedArchive(index)
    if set(archive.ledgers) != {0, 1, 2, 3}:
        raise ValueError('expected four replica ledgers')
    sources = [bind(index)]
    rows = []
    for origin, ledger in sorted(archive.ledgers.items()):
        start, stop = ledger['window_start_us'], ledger['window_end_us']
        if stop - start != 30_000_000:
            raise ValueError('expected original 30-second window')
        path = trial / f'causal-traces/replica-{origin}.json'
        source = bind(path)
        sources.append(source)
        trace = json.loads(path.read_text())
        if (trace['schema'] != 'delugi-causal-trace-v1' or trace['replica'] != origin
                or trace['dropped'] != 0
                or trace['clock'] != "microseconds from this replica's monotonic Runtime origin"):
            raise ValueError('unexpected identity, clock, or trace drops')
        outboxes = [e for e in trace['events'] if e['event'] == 'ordering_outbox'
                    and e['detail']['kind'] == 'PROPOSE']
        validated = [e for e in trace['events'] if e['event'] == 'proposal_validated']
        rows.append({'replica': origin, 'window_start_us': start,
                     'window_end_us_exclusive': stop, 'trace_sha256': source['sha256'],
                     'logical_proposal_outbox': cycles(outboxes, origin, start, stop),
                     'proposal_validated_proxy': cycles(validated, origin, start, stop)})
    return {'schema': 1, 'trial': str(trial.resolve()),
            'kind': 'offline-same-clock-trace-audit',
            'measurement_duration_ms': 30_000,
            'window': 'Each replica ShardedArchive ledger window_start_us <= event at_us < window_end_us; both cycle endpoints must lie inside the window.',
            'leader_rule': 'Delugi leader(round) = (round - 1) % 4',
            'cycle_definition': 'Successive own-leader events with round difference exactly four; same-replica timestamp difference divided by four.',
            'events': {'logical_proposal_outbox': 'ordering_outbox with kind PROPOSE; logical emission, before transport writes',
                       'proposal_validated_proxy': 'first proposal_validated per own-leader round; comparable event class to Raptr cadence proxy'},
            'cross_host_subtraction': False,
            'validation': 'Read original cohort index with ShardedArchive and bind it plus each trace by SHA-256. No new signature verification or protocol execution.',
            'sources': sources, 'replicas': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trial', type=Path, default=DEFAULT_TRIAL)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('delugi-cadence-summary.json'))
    args = parser.parse_args()
    summary = analyze(args.trial)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'replicas': [
        {'replica': row['replica'], **{key: row[key]['own_leader_four_round_cycles_divided_by_four']
                                     for key in ('logical_proposal_outbox', 'proposal_validated_proxy')}}
        for row in summary['replicas']]}, indent=2))


if __name__ == '__main__':
    main()
