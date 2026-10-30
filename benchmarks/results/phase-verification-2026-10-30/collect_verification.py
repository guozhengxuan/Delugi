#!/usr/bin/env python3
"""Freeze compact, hash-bound summaries of local phase verification evidence."""
from collections import Counter
import hashlib
import json
from pathlib import Path
from statistics import mean

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'core/delugi').is_dir())
SOURCE = ROOT/'results/local/phase-verification-20261030'
OUT = Path(__file__).resolve().parent


def read(p):
    return json.loads(p.read_text())


def binding(p):
    return {'path': str(p.relative_to(ROOT)), 'bytes': p.stat().st_size,
            'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}


core_path = SOURCE/'core/signed-core.json'
core = read(core_path)
record = read(SOURCE/'core/build-record.json')
assert binding(core_path)['sha256'] == record['files']['signed-core.json']
assert binding(ROOT/record['harness']['path'])['sha256'] == record['harness']['sha256']
assert binding(ROOT/record['executable']['path'])['sha256'] == record['executable']['sha256']
for name, expected in record['production_sources'].items():
    assert binding(ROOT/name)['sha256'] == expected

runs = []
for run in core['runs']:
    exclusions = Counter()
    for row in run['batches']:
        exclusions.update(row['missed_inputs'])
        assert row['broadcast_to_first_proposal_ms'] >= 0
        assert row['broadcast_to_first_acceptance_ms'] <= row['broadcast_to_execution_acceptance_ms']
    assert exclusions['eligible_but_omitted'] == 0
    assert len(run['batches']) == run['n']
    changed = [row for row in run['batches'] if
               row['broadcast_to_first_acceptance_ms'] < row['broadcast_to_execution_acceptance_ms']]
    example = next((row for row in changed if row['first_proposal_leader'] == 0), None)
    examples = []
    if example:
        rs = {example['first_proposal_round'], example['execution_round']}
        examples.append({'batch': example, 'opportunities': [o for o in run['opportunities'] if o['round'] in rs]})
    runs.append({k:v for k,v in run.items() if k not in ('batches', 'opportunities')} | {
        'batch_opportunity_exclusion_counts': dict(exclusions),
        'first_proposer_counts': dict(Counter(row['first_proposal_leader'] for row in run['batches'])),
        'first_execution_counts': dict(Counter(row['execution_leader'] for row in run['batches'])),
        'midpoint_reassigned_requests': len(changed),
        'mean_midpoint_reassignment_ms': mean(row['broadcast_to_execution_acceptance_ms']-
            row['broadcast_to_first_acceptance_ms'] for row in run['batches']),
        'examples': examples})
summary = {'scope': core['scope'], 'checks': core['checks'], 'runs': runs,
           'source': binding(core_path), 'build_record': binding(SOURCE/'core/build-record.json')}
(OUT/'core-summary.json').write_text(json.dumps(summary, indent=2)+'\n')

processes = []
for label in ('uniform10', 'wan-symmetric'):
    p = SOURCE/'process'/label/'analysis.json'
    d = read(p)
    processes.append({'label': label, **{k:v for k,v in d.items() if k != 'rows'},
                      'source': binding(p)})
(OUT/'process-summary.json').write_text(json.dumps(processes, indent=2)+'\n')
print(json.dumps({'core_runs': len(runs), 'core_batches': sum(r['n'] for r in runs),
                  'process_batches': sum(r['count'] for r in processes),
                  'eligible_but_omitted': 0}, indent=2))
