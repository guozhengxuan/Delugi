#!/usr/bin/env python3
"""Audit sampled leader-local OBS arrival order in already downloaded Delugi traces.

Offline only: no network, protocol execution, source edits, or clock alignment.
The observed first-to-second remote-response gap is not a valid protocol with a
lower pool threshold and does not establish per-transaction latency savings.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import statistics

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'core/delugi/src/composed.rs').is_file())
DEFAULT_TRACES = (ROOT / 'benchmark/.state/runs/delugi-freshness-wan-20261030'
                  / 'trials/b02e64f55f4e7fa0598860f6/trial/causal-traces')
REGIONS = {0: 'Singapore', 1: 'Frankfurt', 2: 'London', 3: 'Seoul'}


def bind(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'expected regular evidence file: {path}')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path.resolve()), 'bytes': path.stat().st_size,
            'sha256': digest}


def message_key(event):
    d = event['detail']
    return d['peer'], d['sequence'], d['member_index'], d['member_count']


def summarize(rows):
    if not rows:
        raise ValueError('empty sampled cohort')
    columns = ('report_to_first_remote_us', 'first_to_second_remote_us',
               'report_to_pool_fixed_us')
    return {
        'rounds': len(rows),
        'mean_ms': {key.removesuffix('_us'): statistics.mean(r[key] for r in rows) / 1000
                    for key in columns},
        'ordered_peer_pairs': [
            {'first_peer': first, 'second_peer': second, 'rounds': count}
            for (first, second), count in sorted(Counter(
                (r['first_remote_peer'], r['second_remote_peer']) for r in rows).items())],
    }


def analyze(directory):
    rows, sources, sampling, exclusions = [], [], [], Counter()
    eligible = 0
    for replica in range(4):
        path = directory / f'replica-{replica}.json'
        sources.append(bind(path))
        document = json.loads(path.read_text())
        if (document['schema'] != 'delugi-causal-trace-v1'
                or document['replica'] != replica or document['dropped'] != 0
                or document['clock'] != "microseconds from this replica's monotonic Runtime origin"):
            raise ValueError('unexpected trace identity, clock, or dropped events')
        sampling.append({key: document[key] for key in
                         ('replica', 'detail_stride', 'detail_width', 'dropped')})
        rounds = defaultdict(list)
        for event in document['events']:
            rounds[event['round']].append(event)
        for round_number, events in sorted(rounds.items()):
            reports = [e for e in events if e['event'] == 'dissemination_outbox'
                       and e['detail']['kind'] == 'REPORT']
            if not reports:
                continue
            if len(reports) != 1 or (round_number - 1) % 4 != replica:
                raise ValueError('expected one REPORT from the scheduled leader')
            if round_number <= 3:
                exclusions['startup_rounds_1_to_3'] += 1
                continue
            eligible += 1
            pools = [e for e in events if e['event'] == 'observation_pool_fixed']
            own = [e for e in events if e['event'] == 'observation_fixed']
            if len(pools) > 1 or len(own) > 1:
                raise ValueError('duplicate leader pool/self observation')
            if not pools or not own:
                exclusions['report_without_completed_pool_or_self_observation'] += 1
                continue
            report, pool, own = reports[0], pools[0], own[0]
            accepted = {message_key(e): e for e in events
                        if e['event'] == 'handler' and e['detail']['kind'] == 'OBS'
                        and e['detail']['accepted'] is True}
            arrivals = {}
            for event in events:
                if event['event'] != 'dispatch' or event['detail']['kind'] != 'OBS':
                    continue
                key = message_key(event)
                if key not in accepted:
                    continue
                peer = event['detail']['peer']
                if peer == replica or event['detail']['signer'] != peer:
                    raise ValueError('unexpected OBS signer/peer identity')
                if event['at_us'] > pool['at_us']:
                    continue
                arrivals.setdefault(peer, event)
            arrivals = sorted(arrivals.values(), key=lambda e: e['at_us'])
            if len(arrivals) < 2:
                exclusions['no_two_sampled_accepted_remote_dispatches_before_pool'] += 1
                continue
            first, second = arrivals[:2]
            points = [report['at_us'], own['at_us'], first['at_us'], second['at_us'], pool['at_us']]
            if any(a > b for a, b in zip(points, points[1:])):
                raise ValueError('nonsequential local REPORT/self/remote/pool markers')
            rows.append({
                'replica': replica, 'region': REGIONS[replica], 'round': round_number,
                'report_at_us': report['at_us'], 'self_observation_at_us': own['at_us'],
                'first_remote_at_us': first['at_us'], 'first_remote_peer': first['detail']['peer'],
                'second_remote_at_us': second['at_us'], 'second_remote_peer': second['detail']['peer'],
                'pool_fixed_at_us': pool['at_us'],
                'report_to_first_remote_us': first['at_us'] - report['at_us'],
                'first_to_second_remote_us': second['at_us'] - first['at_us'],
                'report_to_pool_fixed_us': pool['at_us'] - report['at_us'],
            })
    rows.sort(key=lambda r: (r['replica'], r['round']))
    # Scheduling references from the historical audit are intentionally omitted:
    # this run uses the corrected pipeline-preparation guard, not HistoryReady.
    return {
        'schema': 1, 'kind': 'delugi-sampled-obs-order-statistics-v1',
        'method': {
            'population': 'Healthy saved four-region run; per-leader REPORT opportunities after round3.',
            'eligibility': 'Exactly one leader REPORT, local observation_fixed and observation_pool_fixed; at least two distinct remote OBS dispatches with matching accepted handler records at or before pool fixation.',
            'start': 'Leader-local dissemination_outbox event with kind REPORT.',
            'arrivals': 'Leader-local dispatch.at_us, not mailbox arrival, for first accepted OBS from each distinct remote peer. Records matched by peer/sequence/member_index/member_count.',
            'end': 'Leader-local observation_pool_fixed.at_us.',
            'weighting': 'Unweighted mean across sampled leader rounds, not transaction-weighted.',
            'clock': 'All subtraction within one replica monotonic clock. No cross-host subtraction or wall-clock alignment.',
            'interpretation': 'Observed extra wait for the second remote response in an n-f=3 pool containing self. This is an arrival-order diagnostic, not a safe lower-threshold protocol or a per-transaction latency saving. WA target feasibility and the n-f pool invariant are unchanged.',
            'sampling_limit': 'Detailed dispatch/handler records are sampled by round; included and excluded counts are explicit. Startup rounds1–3 excluded.',
        },
        'eligible_post_startup_leader_rounds': eligible,
        'included_rounds': len(rows), 'excluded': dict(exclusions),
        'sampling': sampling,
        'overall': summarize(rows),
        'by_replica': {str(replica): {'region': REGIONS[replica],
                       **summarize([r for r in rows if r['replica'] == replica])}
                       for replica in range(4)},
        'rounds': rows, 'trace_sources': sources,
        'source_references': [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--traces', type=Path, default=DEFAULT_TRACES)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_suffix('.json'))
    args = parser.parse_args()
    report = analyze(args.traces.resolve())
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'output': str(args.output.resolve()),
                      'included_rounds': report['included_rounds'],
                      'overall': report['overall'], 'by_replica': report['by_replica']}, indent=2))


if __name__ == '__main__':
    main()
