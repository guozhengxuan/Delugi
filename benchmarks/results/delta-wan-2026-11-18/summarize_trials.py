"""Recompute four verified same-origin latency measurements and the trial ledger."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'benchmark')]
from bench.logs import LogParser
from campaign_execute import metrics
from latency_decomposition import analyze as delugi_stages
from raptr_latency_decomposition import analyze as raptr_stages

run = ROOT/'benchmark/.state/runs/delta-wan-20261118'
summary = json.loads(Path(LogParser(run).export()['summary']).read_text())
if len(summary['rows']) != 4:
    raise ValueError('expected four planned cells')
rows = []
for item in summary['rows']:
    root = run/'trials'/item['trial_id']
    if item['status'] == 'failed':
        if (item['protocol'], item['case']) != ('delugi','silent-first-leader'):
            raise ValueError('unexpected failed trial')
        if (root/'trial/control.jsonl').stat().st_size or 'Connection reset by peer' not in (root/'trial/replica-3.stderr').read_text():
            raise ValueError('initial attempt reached the workload or failed differently')
        root = ROOT/'results/local/delta-wan-20261118/silent-retry/workload'
        retried = json.loads((root/'result.json').read_text())
        if retried['status'] != 'passed':
            raise ValueError('retry did not pass')
        item = item | metrics(retried,item['protocol']) | {'status':'passed'}
    raw = (root/'result.json').read_bytes()
    data = json.loads(raw)
    if item['protocol'] == 'delugi':
        trace = root/'trial/causal-traces'
        result = delugi_stages(root/'trial/cohorts/index.json', trace)
        if not data['causal_trace']['complete']:
            raise ValueError('incomplete Delugi trace')
    else:
        result = raptr_stages(root/'config.json', root/'replicas', data['correct_replicas'],
                              authentication=data['authentication'])
    if result['covered'] != item['completed'] or result['scheduled'] != item['scheduled']:
        raise ValueError('raw trace and verified workload differ')
    rows.append({k:item[k] for k in ('protocol','case','trial_id','status','scheduled','admitted',
                                      'completed','unfinished','goodput_tps','p50_ms','p95_ms')} |
                {'raw_result_sha256':hashlib.sha256(raw).hexdigest(),'stage_coverage': result['covered'],
                 'mean_admission_to_output_ms': result['mean_admission_to_append_ms'],
                 'stages':result['stages'], 'traffic_measurement_written_bytes':item.get('traffic_measurement_written_bytes')})
(HERE/'trials.json').write_text(json.dumps(rows, indent=2)+'\n')
