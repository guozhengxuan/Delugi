#!/usr/bin/env python3
"""Compare a completed pipeline-Delugi WAN rerun with frozen Raptr/Delugi evidence.

Offline only: no remote calls, compilation or protocol execution. Every bar is
reconstructed from the retained trace/cohort reducers and bound result files.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
import latency_decomposition as delugi

BASE = ROOT/'benchmarks/results/raptr-wan-stages-2026-10-29'
RAPTR_RUN = ROOT/'benchmark/.state/runs/raptr-wan-stages-20261029'
PINS = {
    'plot_comparison.py': '836e6a8f3ceb662de417a25be0e3aec7ec2842af83017d4c61d107de33a6ef4d',
    'record.json': 'd3e1f72437ba43f2b5e534cb5dca17e678e6260e2aad83daeccba98e86d7aef5',
    'comparison.json': '1efafd854dfd5c3d7b2de119b9c5e9b257a821d61d5c5fd71ae2536a62bf58cc',
}
CASES = ('healthy', 'silent-first-leader')
REGIONS = ['ap-southeast-1', 'eu-central-1', 'eu-west-1', 'ap-northeast-2']
COMMON = ('Batch formation', 'Dissemination / inclusion', 'Consensus', 'Output processing')
ORDER = ('delugi_previous', 'raptr_saved', 'delugi_pipeline')
LABELS = ('Delugi · previous', 'Raptr · saved', 'Delugi · pipeline')


def load(path):
    return json.loads(Path(path).read_text())


def bound(path, expected=None):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'missing/linked evidence: {path}')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if expected is not None and digest != expected:
        raise ValueError(f'changed evidence: {path}')
    return {'path': str(path.resolve()), 'sha256': digest, 'bytes': path.stat().st_size}


def baseline_module():
    provenance = [bound(BASE/name, digest) for name, digest in PINS.items()]
    spec = importlib.util.spec_from_file_location('frozen_wan_comparison', BASE/'plot_comparison.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, provenance


def mean(values):
    values = [v for v in values if v is not None]
    return {'count': len(values), 'mean_ms': statistics.fmean(values) if values else None,
            'median_ms': statistics.median(values) if values else None}


def metrics_from_cohort(result):
    cohort = result['cohort']
    return {
        **{key: cohort[key] for key in ('scheduled', 'admitted', 'completed', 'unfinished')},
        'goodput_tps': cohort['window']['unique_completion_tps'],
        'pending_at_end': cohort['window']['pending_at_end'],
        **{f'{label}_{q}_{key}': value for endpoint, label in
           (('scheduled_to_output', 'end_to_end'), ('admission_to_output', 'admission'))
           for q in ('p50', 'p95', 'p99') for key, value in cohort[endpoint][q].items()},
        'observed_rtt': result['network_shaping'].get('observed_rtt'),
        'drain_complete': result['drain_complete'],
        'correct_replicas': result['comparison']['correct_replicas'],
        'all_correct_collection': cohort['all_correct_collection'],
        'tcp_written_bytes': result['comparison']['replica_tcp_written_bytes'],
        'load_start_alignment': result['load_start_alignment'],
    }


def current_delugi(run):
    state, plan = load(run/'state.json'), load(run/'plan.json')
    if state['identity']['plan_sha256'] != plan['plan_sha256']:
        raise ValueError('Delugi run and plan identities differ')
    config = plan['config']
    if (config['protocols'] != ['delugi'] or config['committees'] != [4]
            or config['total_honest_input_tps'] != [100] or config['useful_transaction_bytes'] != 1
            or config['duration'] != {'warmup_s': 0, 'measure_s': 30, 'drain_s': 15}
            or config['timing']['Delta_ms'] != 1000 or config['repeats'] != 1
            or config['network'] != {'added_one_way_delay_ms': 0, 'validator_egress_mbps': 20}):
        raise ValueError('Delugi rerun differs from requested 30 s / 100 tx/s / four-region preset')
    selected = state['rows']
    if (len(selected) != 2 or {r['protocol'] for r in selected} != {'delugi'}
            or {r['case'] for r in selected} != set(CASES)):
        raise ValueError('expected exactly one healthy and one silent-leader Delugi run')
    provenance = [bound(run/'state.json'), bound(run/'plan.json')]
    reports, metrics, diagnostics = {}, {}, {}
    for row in selected:
        if row['status'] != 'passed':
            raise ValueError(f'Delugi trial did not pass: {row["case"]}')
        trial = run/'trials'/row['trial_id']
        provenance.append(bound(trial/'result.json', row['result']['sha256']))
        result = load(trial/'result.json')
        if (result['status'] != 'passed' or not result['agreement']['all_correct_overlap_prefixes_verified']
                or not result['causal_trace']['complete']):
            raise ValueError('Delugi execution, agreement or trace collection did not pass')
        if result['network_shaping']['settings'] != {'delay_ms': 0, 'mode': 'observed-wan-v1', 'rate_mbps': 20}:
            raise ValueError('actual Delugi WAN preset differs')
        hosts = sorted(result['deployment']['inventory']['hosts'], key=lambda h: h['replica'])
        if [host['region'] for host in hosts] != REGIONS:
            raise ValueError('actual Delugi replica placement differs')
        schedule = result['scheduling']
        if (schedule['ordering_mode'] != 'canonical' or schedule['report_schedule'] != 'pipeline'
                or schedule['bundling'] != 'immediate_no_fill_timer'):
            raise ValueError('Delugi run did not use the modified pipeline')
        if result.get('load_start_alignment', {}).get('method') != 'remote_start_reply_midpoint_to_common_controller_monotonic_epoch_v1':
            raise ValueError('Delugi retry lacks the recorded controller clock alignment')
        cohort_index = trial/'trial/cohorts/index.json'
        authentication = result['cohort_authentication']
        if not authentication['verified']:
            raise ValueError('Delugi cohorts lack successful signature verification')
        provenance.append(bound(cohort_index, authentication['index_sha256']))
        for entry in result['causal_trace']['files']:
            provenance.append(bound(trial/'trial/causal-traces'/f'replica-{entry["replica"]}.json', entry['sha256']))
        report = delugi.analyze(cohort_index, trial/'trial/causal-traces')
        cohort = result['cohort']
        if (report['scheduled'] != 3000 or report['completed'] != cohort['completed']
                or report['covered'] != report['completed'] or report['excluded']):
            raise ValueError('Delugi stage coverage differs from completed intended cohort')
        reports[row['case']] = {k: v for k, v in report.items()
                               if k not in ('leader_rounds', 'timer_events', 'history_generation')}
        metrics[row['case']] = {**metrics_from_cohort(result), 'trial_id': row['trial_id'],
                               'result_sha256': row['result']['sha256'], 'scheduling': schedule}
        leaders = report['leader_rounds']
        diagnostics[row['case']] = {key: mean(r.get(key) for r in leaders) for key in
                                   ('frozen_input_age_ms', 'admission_to_proposal_ms', 'report_to_input_ms',
                                    'history_assembly_ms', 'leader_outbox_to_direct_ms',
                                    'first_history_report_to_quorum_ms')}
        diagnostics[row['case']]['population'] = 'all retained sampled leader rounds, not transaction weighted or restricted to the input window; each metric retains its own count'
        diagnostics[row['case']]['report_before_history_count'] = sum(
            r['report_us'] is not None and r['history_quorum_us'] is not None
            and r['report_us'] < r['history_quorum_us'] for r in leaders)
    return reports, metrics, diagnostics, provenance


def frozen_baselines():
    legacy, sources = baseline_module()
    previous, previous_metrics, previous_sources = legacy.original_delugi()
    saved_raptr, raptr_metrics, raptr_sources = legacy.current_raptr(RAPTR_RUN)
    published = load(BASE/'comparison.json')['comparison']
    for case in CASES:
        for protocol, report in [('delugi', previous[case]), ('raptr', saved_raptr[case])]:
            expected = published[case][protocol]
            for key in ('scheduled', 'completed', 'covered', 'excluded'):
                if report[key] != expected[key]:
                    raise ValueError('frozen baseline population changed')
            legacy.equal_mean(report['mean_admission_to_append_ms'], expected['mean_admission_to_append_ms'])
            for actual, old in zip(legacy.grouped(protocol, report), expected['common_stages']):
                legacy.equal_mean(actual['mean_ms'], old['mean_ms'])
    return legacy, previous, previous_metrics, saved_raptr, raptr_metrics, sources+previous_sources+raptr_sources


def render(comparison, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    colors = ('#62A3CD', '#397CB2', '#86AB4C', '#D39949')
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                         'svg.fonttype': 'none', 'svg.hashsalt': 'delugi-pipeline-wan-20261029'})
    fig, axes = plt.subplots(1, 2, figsize=(13.3, 7.4), sharey=True)
    fig.subplots_adjust(left=.17, right=.98, top=.73, bottom=.23, wspace=.26)
    for ax, case in zip(axes, CASES):
        entries = comparison[case]
        maximum = max(e['mean_admission_to_append_ms'] for e in entries.values())
        for position, name in enumerate(ORDER):
            entry, left = entries[name], 0
            for stage, color in zip(entry['common_stages'], colors):
                ax.barh(position, stage['mean_ms'], left=left, height=.42, color=color)
                left += stage['mean_ms']
            ax.text(left+maximum*.025, position, f'{left:,.1f} ms', va='center', weight='bold', fontsize=10)
            ax.text(0, position+.28, f"{entry['covered']:,}/{entry['completed']:,} completed covered; "
                    f"{entry['scheduled']:,} scheduled", fontsize=8.5, color='#536476')
        ax.set_title('Healthy' if case == 'healthy' else 'Persistent silent leader', weight='bold', pad=15)
        ax.set_xlim(0, maximum*1.24)
        ax.set_ylim(2.58, -.6)
        ax.set_yticks(range(3), LABELS)
        ax.set_xlabel('Mean admission → verified output (ms)', fontsize=10)
        ax.grid(axis='x', color='#E6EBEF'); ax.set_axisbelow(True)
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.tick_params(axis='both', length=0)
    fig.text(.045, .945, 'Four-region WAN: pipeline Delugi versus saved Raptr', fontsize=18, weight='bold', color='#20344B')
    fig.text(.045, .897, '30 s input · 100 tx/s · 1 useful byte/tx · Δ = 1,000 ms · 20 Mbps public egress · natural WAN', fontsize=10.5)
    fig.legend(handles=[Patch(color=c, label=n) for c, n in zip(colors, COMMON)],
               loc='upper left', bbox_to_anchor=(.04, .867), ncol=4, frameon=False, fontsize=10)
    fig.text(.045, .145, 'Consensus starts at origin-local proposal acceptance. Stages sum over the same fully traced completed-request cohort.', fontsize=9)
    fig.text(.045, .105, 'Fault placement differs: Delugi silences Singapore replica 0; saved Raptr pauses Frankfurt replica 1. Native batching/timers differ.', fontsize=9)
    fig.text(.045, .065, 'Independent WAN runs; panel scales differ. Only pipeline Delugi was rerun; baseline traces were revalidated offline.', fontsize=9, color='#536476')
    for extension in ('png', 'pdf', 'svg'):
        target = output/f'latency-decomposition-comparison.{extension}'
        fig.savefig(target, dpi=180, **({'metadata': {'Date': None}} if extension == 'svg' else {}))
        if extension == 'svg':
            target.write_text('\n'.join(line.rstrip() for line in target.read_text().splitlines())+'\n')
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='completed two-trial pipeline-Delugi Fabric run')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    legacy, old, old_metrics, saved, saved_metrics, baseline_sources = frozen_baselines()
    new, new_metrics, diagnostics, new_sources = current_delugi(args.run.resolve())
    comparison = {}
    for case in CASES:
        comparison[case] = {}
        for name, protocol, report in [('delugi_previous', 'delugi', old[case]),
                                       ('raptr_saved', 'raptr', saved[case]),
                                       ('delugi_pipeline', 'delugi', new[case])]:
            comparison[case][name] = {
                **{k: report[k] for k in ('scheduled', 'completed', 'covered', 'excluded',
                                         'mean_admission_to_append_ms', 'mean_schedule_to_admission_ms')},
                'common_stages': legacy.grouped(protocol, report), 'native_stages': report['stages'],
            }
    summary = {
        'schema': 1, 'comparison': comparison,
        'metrics': {'delugi_previous': old_metrics, 'raptr_saved': saved_metrics, 'delugi_pipeline': new_metrics},
        'delugi_pipeline_leader_diagnostics': diagnostics,
        'source_files': baseline_sources+new_sources+[bound(__file__)],
        'metric_populations': 'Stage means use covered completed intended requests. Full scheduled-cohort quantiles retain unfinished requests. Stage means are additive; quantiles are not.',
        'limitations': [
            'Only pipeline Delugi was rerun; Raptr is from 29 October and previous Delugi from 28 October. Host/WAN conditions are independent.',
            'Both endpoints precede diagnostic journaling. Consensus starts at origin-local valid proposal acceptance, not leader emission; proposal transit belongs to the preceding stage.',
            'Different native batching remains: Delugi maximum wait 10 ms; Raptr Quorum Store 150 ms polling with 80 ms minimum nonempty / 300 ms maximum.',
            'Equal Delta does not imply equal native failure timers: Raptr uses 4Delta from round entry; Delugi uses eligible 7Delta main and independent 3Delta catch-up.',
            'Delugi silences protocol participation at replica0/Singapore while transport ACKs remain active; Raptr pauses replica1/Frankfurt. Faulty identities retain repeated leadership slots.',
            'Output groups different internal phase orderings: Delugi releases descriptors before payload materialization; Raptr validates payloads before FIFO release.',
            'Saved Raptr silent run has eight requests cancelled before admission. They remain in scheduled-cohort statistics but not completed stage means.',
            'One run per case, one low offered load and unqualified observer overhead; this is deployment/pipeline validation, not a full throughput study.',
            'The initial Delugi attempt rejected every load command before input because controller and server wall clocks differed. The retry maps one common controller monotonic epoch to each server wall clock, records RTT uncertainty, and changes no origin-local latency endpoint; its setup lead differs from the previous controller-wall-time assumption.',
        ],
    }
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    (output/'comparison.json').write_text(json.dumps(summary, indent=2)+'\n')
    for case in CASES:
        (output/f'delugi-{case}-decomposition.json').write_text(json.dumps(new[case], indent=2)+'\n')
    with (output/'common-stages.csv').open('w', newline='') as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(['case', 'protocol', 'scheduled', 'completed', 'covered', *COMMON, 'total_ms'])
        for case, entries in comparison.items():
            for name in ORDER:
                report = entries[name]
                writer.writerow([case, name, report['scheduled'], report['completed'], report['covered'],
                                 *[s['mean_ms'] for s in report['common_stages']], report['mean_admission_to_append_ms']])
    render(comparison, output)
    print(json.dumps({'output': str(output), 'comparison': comparison}, indent=2))


if __name__ == '__main__':
    main()
