#!/usr/bin/env python3
"""Analyze full proposal contents from verify_phase_local.py, using local clocks."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from statistics import mean


def read(path):
    return json.loads(path.read_text())


def analyze(path):
    result = read(path/'result.json')
    assert result['status'] == 'passed'
    config = read(path/'config.json')
    assert config.get('silent') is None and config.get('fault') is None
    traces = {i: read(path/f'trace-{i}.json') for i in range(4)}
    logs = {i: [json.loads(line) for line in (path/f'replica-{i}.stdout.jsonl').read_text().splitlines()]
            for i in range(4)}
    proposals = {}
    for i, events in logs.items():
        for event in events:
            if event['event'] == 'proposal':
                r = event['round']
                assert r not in proposals and (r-1)%4 == i
                header = event['message']['Propose']['header']
                assert header['signer'] == i and header['body']['round'] == r
                pool = event['availability_proof']['pool']
                assert len(pool) == 3 and len({o['signer'] for o in pool}) == 3
                assert all(o['body']['opportunity'] == r and
                           o['body']['base'] == event['descriptor']['base'] for o in pool)
                for j, target in enumerate(event['descriptor']['targets']):
                    assert target['producer'] == j
                    assert all(o['body']['coordinates'][j]['checkpoint']['producer'] == j and
                               o['body']['coordinates'][j]['checkpoint']['context'] == target['context']
                               for o in pool)
                proposals[r] = event
    order = [s['executed'] for s in result['snapshots'].values()]
    assert all(x == order[0] for x in order)
    rows, excluded_opportunities = [], Counter()
    accepted_digests = {}
    for i, trace in traces.items():
        assert trace['replica'] == i and trace['dropped'] == 0 and trace['run_error'] is None
        assert trace['schema'] == 'delugi-causal-trace-v1'
        assert trace['clock'] == "microseconds from this replica's monotonic Runtime origin"
        events = trace['events']
        accepted_events = [e for e in events if e['event'] == 'proposal_validated']
        accepts = {e['round']: e['at_us'] for e in accepted_events}
        assert len(accepts) == len(accepted_events) and set(accepts) <= set(proposals)
        for e in accepted_events:
            r = e['round']
            digest = tuple(e['detail']['digest'])
            assert accepted_digests.setdefault(r, digest) == digest
            emitted = proposals[r]['message']['Propose']
            assert e['detail']['value_bytes'] == len(emitted['value'])
            assert e['detail']['witness_bytes'] == len(emitted['witness'])
        mats = {tuple(e['detail']['exact_batch_id']): e for e in events
                if e['event'] == 'batch_materialized' and e['detail']['producer'] == i}
        seals = [e for e in events if e['event'] == 'batch_sealed']
        assert [e['detail']['height'] for e in seals] == list(range(1, len(seals)+1))
        assert len({tuple(e['detail']['exact_batch_id']) for e in seals}) == len(seals)
        for sealed in seals:
            h = sealed['detail']['height']
            digest = tuple(sealed['detail']['exact_batch_id'])
            emitted_candidates = [r for r in accepts if r in proposals and
                                  proposals[r]['descriptor']['targets'][i]['height'] >= h]
            assert emitted_candidates
            first = min(emitted_candidates, key=accepts.get)
            m = mats[digest]
            executing = m['round']
            assert executing in emitted_candidates
            assert accepts[first] >= sealed['at_us']
            for r, at in accepts.items():
                if not sealed['at_us'] <= at < accepts[first]:
                    continue
                p = proposals[r]
                assert p['descriptor']['targets'][i]['height'] < h
                covering = sum(o['body']['coordinates'][i]['checkpoint']['height'] >= h
                               for o in p['availability_proof']['pool'])
                assert len(p['availability_proof']['pool']) == 3
                excluded_opportunities['insufficient_covering_snapshots' if covering < 2
                                       else 'covering_but_source_readiness_unobserved'] += 1
            p = proposals[first]
            covering = sum(o['body']['coordinates'][i]['checkpoint']['height'] >= h
                           for o in p['availability_proof']['pool'])
            assert covering >= 2
            rows.append({'origin': i, 'height': h, 'first_local_round': first,
                         'execution_round': executing, 'covering_pool_sources': covering,
                         'seal_to_first_local_proposal_ms': (accepts[first]-sealed['at_us'])/1000,
                         'seal_to_execution_proposal_ms': (accepts[executing]-sealed['at_us'])/1000,
                         'midpoint_reassignment_ms': (accepts[executing]-accepts[first])/1000,
                         'seal_to_materialization_ms': (m['at_us']-sealed['at_us'])/1000})
    assert len(rows) == result['settings']['count']
    keys = ['seal_to_first_local_proposal_ms', 'seal_to_execution_proposal_ms',
            'midpoint_reassignment_ms', 'seal_to_materialization_ms']
    return {'scope': 'Finite four-process same-source local diagnostic with full signed proposal proofs; not a WAN performance rerun. All durations use one origin clock. Pool support counts do not establish leader source readiness.',
            'count': len(rows), 'settings': result['settings'],
            'means_ms': {k: mean(r[k] for r in rows) for k in keys},
            'first_execution_leaders': dict(Counter((r['execution_round']-1)%4 for r in rows)),
            'first_local_inclusion_leaders': dict(Counter((r['first_local_round']-1)%4 for r in rows)),
            'earlier_excluded_batch_opportunities': dict(excluded_opportunities),
            'timer_expiries_by_replica': {str(i): dict(Counter(e['event'] for e in trace['events']
                if e['event'] in ('main_timer_expiry', 'catchup_timer_expiry')))
                for i, trace in traces.items()},
            'membership_assumption': 'All honest, one checked consecutive nonforking producer chain per origin. Descriptor target heights establish inclusion; OBS witness mentions alone never count as proposal inclusion.',
            'timing_limit': 'Native debug binary, full JSON proposal logging and finite startup. Timer expiries are reported. These durations are not an ideal delta model or a WAN performance estimate.',
            'no_dropped_traces': True, 'matching_output_order': True,
            'binary_sha256': result['binary_sha256'],
            'sources': [{'path': str(p.resolve()), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                        for p in [path/'result.json']+[path/f'trace-{i}.json' for i in range(4)]
                        +[path/f'replica-{i}.stdout.jsonl' for i in range(4)]],
            'rows': rows}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    args = p.parse_args()
    result = analyze(args.directory)
    (args.directory/'analysis.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','sources')}, indent=2))
