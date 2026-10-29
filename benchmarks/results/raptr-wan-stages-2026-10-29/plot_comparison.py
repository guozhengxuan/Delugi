#!/usr/bin/env python3
"""Offline WAN stage comparison: fresh Raptr against the frozen 28 October Delugi runs.

Never deploys, executes a protocol, or contacts a remote host. Both stage reducers
re-read their original local evidence. Published baseline hashes are pinned here.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/latency_decomposition.py').is_file())
sys.path.insert(0, str(ROOT/'scripts'))
import latency_decomposition as delugi
import raptr_latency_decomposition as raptr

CASES = ('healthy', 'silent-first-leader')
COMMON = ('Batch formation', 'Dissemination / inclusion', 'Consensus', 'Output processing')
BASE = ROOT/'benchmarks/results/fabric-wan-30s-2026-10-28'
BASE_RUN = ROOT/'benchmark/.state/runs/delugi-raptr-wan-30s-20261028'
BASE_HASHES = {
    'decomposition-summary.json': 'cbcb79c517becf084d9731bea33fc99751871a39b51c55137a5f3faf11a5486c',
    'record.json': '32084b1c3d9e7f1a8f6e2c590b968a8c75d7b93719cc6e204e9262f8a04a6a1b',
    'summary.json': '9f6526b436b1d39c2e2f24ede4fbcf54073c4c3f8f610f0e6f4c95619219d2e8',
}
TRIALS = {'healthy': '5e2250ff5121e8d986930b2e',
          'silent-first-leader': 'b5619611ae844d5a1d749182'}


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


def equal_mean(actual, expected):
    if not (isinstance(actual, (int, float)) and isinstance(expected, (int, float))
            and math.isfinite(actual) and math.isfinite(expected)
            and math.isclose(actual, expected, abs_tol=1e-8, rel_tol=1e-10)):
        raise ValueError(f'reconstructed stage differs: {actual} != {expected}')


def grouped(protocol, report):
    expected = delugi.STAGES if protocol == 'delugi' else raptr.STAGES
    if tuple(s['stage'] for s in report['stages']) != expected:
        raise ValueError('unexpected stage names or order')
    values = [s['mean_ms'] for s in report['stages']]
    if report['covered'] <= 0 or any(v is None or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('empty or invalid stage cohort')
    result = [*values[:3], sum(values[3:])]
    equal_mean(sum(result), report['mean_admission_to_append_ms'])
    return [dict(stage=name, mean_ms=value) for name, value in zip(COMMON, result)]


def original_delugi():
    provenance = [bound(BASE/name, digest) for name, digest in BASE_HASHES.items()]
    record = load(BASE/'record.json')
    provenance.append(bound(ROOT/'scripts/latency_decomposition.py',
        record['artifact']['postprocessor_sources']['scripts/latency_decomposition.py']))
    saved = load(BASE/'decomposition-summary.json')
    published = {r['trial_id']: r for r in load(BASE/'summary.json')['rows']}
    reports, metrics = {}, {}
    for case, trial_id in TRIALS.items():
        trial = BASE_RUN/'trials'/trial_id
        provenance.append(bound(trial/'result.json', published[trial_id]['result_sha256']))
        result = load(trial/'result.json')
        if result['status'] != 'passed':
            raise ValueError('reference Delugi run did not pass')
        for source in saved[case]['trace_sources']:
            provenance.append(bound(source['path'], source['sha256']))
        report = delugi.analyze(trial/'trial/cohorts/index.json', trial/'trial/causal-traces')
        for key in ('scheduled', 'completed', 'covered', 'excluded'):
            if report[key] != saved[case][key]:
                raise ValueError('reference Delugi cohort differs from frozen summary')
        equal_mean(report['mean_admission_to_append_ms'], saved[case]['mean_admission_to_append_ms'])
        for actual, expected in zip(report['stages'], saved[case]['stages']):
            if actual['stage'] != expected['stage']:
                raise ValueError('reference stage schema changed')
            equal_mean(actual['mean_ms'], expected['mean_ms'])
        # Long round/timer diagnostics are retained in their original archives.
        reports[case] = {k: v for k, v in report.items()
                         if k not in ('leader_rounds', 'timer_events', 'history_generation')}
        metrics[case] = published[trial_id]
    return reports, metrics, provenance


def current_raptr(run):
    state, plan = load(run/'state.json'), load(run/'plan.json')
    if state['identity']['plan_sha256'] != plan['plan_sha256']:
        raise ValueError('new run and plan identities differ')
    config = plan['config']
    if (config['protocols'] != ['raptr'] or config['committees'] != [4]
            or config['total_honest_input_tps'] != [100] or config['useful_transaction_bytes'] != 1
            or config['duration'] != {'warmup_s': 0, 'measure_s': 30, 'drain_s': 15}
            or config['timing']['Delta_ms'] != 1000 or config['repeats'] != 1
            or config['network'] != {'added_one_way_delay_ms': 0, 'validator_egress_mbps': 20}):
        raise ValueError('new run differs from the requested 30 s / 100 tx/s / four-region preset')
    selected = state['rows']
    if (len(selected) != 2 or {r['protocol'] for r in selected} != {'raptr'}
            or {r['case'] for r in selected} != set(CASES)):
        raise ValueError('expected exactly one healthy and one silent-leader Raptr run')
    provenance = [bound(run/'state.json'), bound(run/'plan.json')]
    reports, metrics = {}, {}
    for row in selected:
        if row['status'] != 'completed':
            raise ValueError(f'Raptr trial did not complete: {row["case"]}')
        trial = run/'trials'/row['trial_id']
        provenance.append(bound(trial/'result.json', row['result']['sha256']))
        result = load(trial/'result.json')
        if result['status'] != 'completed':
            raise ValueError('Raptr result did not complete')
        settings = result['network']['settings']
        if settings != {'delay_ms': 0, 'mode': 'observed-wan-v1', 'rate_mbps': 20}:
            raise ValueError('actual Raptr network settings differ from saved WAN reference')
        report = raptr.analyze(trial/'config.json', trial/'replicas', result['correct_replicas'],
                               authentication=result['authentication'])
        if report['scheduled'] != 3000:
            raise ValueError('expected exactly 3,000 intended requests in each run')
        embedded = result.get('latency_decomposition')
        if embedded is not None and embedded != report:
            raise ValueError('reconstructed Raptr decomposition differs from frozen result')
        reports[row['case']] = report
        cohort = result['reduction']['cohort']
        metrics[row['case']] = {
            'trial_id': row['trial_id'], 'result_sha256': row['result']['sha256'],
            'scheduled': cohort['scheduled'], 'admitted': cohort['admitted'], 'completed': cohort['completed'],
            'goodput_tps': cohort['window']['unique_completion_tps'],
            **{f'{label}_{q}_{key}': value for endpoint, label in
               (('scheduled_to_output', 'end_to_end'), ('admission_to_output', 'admission'))
               for q in ('p50', 'p95', 'p99') for key, value in cohort[endpoint][q].items()},
            'observed_rtt': result['network'].get('observed_rtt'),
        }
    return reports, metrics, provenance


def render(comparison, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    colors = ('#62A3CD', '#397CB2', '#86AB4C', '#D39949')
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                         'svg.fonttype': 'none', 'svg.hashsalt': 'delugi-raptr-wan-20261029'})
    fig, axes = plt.subplots(1, 2, figsize=(12.8, 6), sharey=True)
    fig.subplots_adjust(left=.17, right=.97, top=.73, bottom=.25, wspace=.27)
    for ax, case in zip(axes, CASES):
        entries = comparison[case]
        maximum = max(e['mean_admission_to_append_ms'] for e in entries.values())
        for position, (protocol, entry) in enumerate(entries.items()):
            left = 0
            for stage, color in zip(entry['common_stages'], colors):
                ax.barh(position, stage['mean_ms'], left=left, height=.42, color=color)
                left += stage['mean_ms']
            ax.text(left+maximum*.025, position, f'{left:,.1f} ms', va='center', weight='bold', fontsize=10)
            ax.text(0, position+.30, f"{entry['covered']:,}/{entry['completed']:,} completed requests covered; "
                    f"{entry['scheduled']:,} scheduled", fontsize=8.5, color='#536476')
        ax.set_title('Healthy' if case == 'healthy' else 'Silent leader', weight='bold', pad=15)
        ax.set_xlim(0, maximum*1.24)
        ax.set_ylim(1.65, -.6)
        ax.set_yticks([0, 1], ['Delugi\n28 Oct · saved', 'Raptr\n29 Oct · new'])
        ax.set_xlabel('Mean admission → verified output (ms)', fontsize=10)
        ax.grid(axis='x', color='#E6EBEF'); ax.set_axisbelow(True)
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.tick_params(axis='both', length=0)
    fig.text(.045, .94, 'Four-region WAN: where latency accumulates', fontsize=20, weight='bold', color='#20344B')
    fig.text(.045, .885, '30 s input · 100 tx/s · 1 useful byte/tx · Δ = 1,000 ms · 20 Mbps provider egress · natural WAN', fontsize=10.5)
    fig.legend(handles=[Patch(color=c, label=n) for c, n in zip(colors, COMMON)],
               loc='upper left', bbox_to_anchor=(.04, .855), ncol=4, frameon=False, fontsize=10)
    fig.text(.045, .13, 'Each bar uses one completed, fully instrumented cohort. Output is verified and contiguous, before diagnostic journaling.', fontsize=9)
    fig.text(.045, .09, 'Fault: Delugi silences replica 0 in Singapore; Raptr pauses replica 1 in Frankfurt. The fault mechanisms and placement differ.', fontsize=9)
    fig.text(.045, .05, 'Independent WAN runs on different dates; observer overhead is unquantified. Stage boundaries describe each implementation’s local observations.', fontsize=9, color='#536476')
    fig.savefig(output/'latency-decomposition-comparison.png', dpi=180)
    svg = output/'latency-decomposition-comparison.svg'
    fig.savefig(svg, metadata={'Date': None})
    svg.write_text('\n'.join(line.rstrip() for line in svg.read_text().splitlines())+'\n')
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True, help='completed two-trial Raptr Fabric run directory')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    new, new_metrics, new_sources = current_raptr(args.run.resolve())
    old, old_metrics, old_sources = original_delugi()
    comparison = {}
    for case in CASES:
        comparison[case] = {}
        for protocol, report in [('delugi', old[case]), ('raptr', new[case])]:
            comparison[case][protocol] = {
                **{k: report[k] for k in ('scheduled', 'completed', 'covered', 'excluded',
                                         'mean_admission_to_append_ms', 'mean_schedule_to_admission_ms')},
                'common_stages': grouped(protocol, report), 'native_stages': report['stages'],
            }
        comparison[case]['raptr'].update(
            availability_quorum=new[case]['availability_quorum'],
            serial_quorum_cohort=new[case]['serial_quorum_cohort'],
            journal_construction_after_endpoint=new[case]['journal_construction_after_endpoint'])
    summary = {
        'schema': 1, 'comparison': comparison,
        'metric_populations': 'Stage means use covered completed requests. Separate full-cohort quantiles retain unfinished scheduled requests; quantiles are never added across stages.',
        'metrics': {'delugi_saved_2026_10_28': old_metrics, 'raptr_new_2026_10_29': new_metrics},
        'source_files': old_sources+new_sources,
        'limitations': [
            'Delugi is reused from 28 October; Raptr is a new run. WAN and host conditions are not contemporaneous.',
            'Both endpoints precede diagnostic journaling; protocol-specific synthetic application work and execution granularity remain different.',
            'Delugi awaiting-proposal includes dissemination, REPORT/history and proposal waiting; Raptr includes dissemination and native proposal inclusion.',
            'Consensus starts at locally accepted verified proposal, excluding prior proposal transit. Raptr includes verified-inbox queue delay in the preceding stage.',
            'Output groups prefix/payload/application phases; Delugi releases descriptors before payload materialization, while Raptr payload validation precedes FIFO output.',
            'Availability quorum can overlap proposal/consensus. Its optional serial split is a separate cohort, not a protocol gate.',
            'Silent-leader fault differs: Delugi replica 0/Singapore protocol silence with ACKs; Raptr replica 1/Frankfurt whole-process pause.',
            'The configured delay bound is the same (Delta = 1,000 ms), but native leader timers are not equal: Raptr uses a 4-Delta leader timeout from round entry; Delugi uses a 7-Delta main timer after eligibility and a 3-Delta catch-up timer. These native policies are preserved.',
            'Native batching defaults remain: Raptr Quorum Store polls every 150 ms (80 ms minimum nonempty, 300 ms maximum); Delugi maximum batch wait is 10 ms. Common overrides were unset.',
            'One run per case at one input rate; instrumentation overhead and aggregate bandwidth remain unqualified.',
        ],
    }
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    (output/'comparison.json').write_text(json.dumps(summary, indent=2)+'\n')
    for case in CASES:
        (output/f'raptr-{case}-decomposition.json').write_text(json.dumps(new[case], indent=2)+'\n')
    with (output/'common-stages.csv').open('w', newline='') as stream:
        writer = csv.writer(stream, lineterminator='\n')
        writer.writerow(['case', 'protocol', 'scheduled', 'completed', 'covered', *COMMON, 'total_ms'])
        for case, entries in comparison.items():
            for protocol, report in entries.items():
                writer.writerow([case, protocol, report['scheduled'], report['completed'], report['covered'],
                                 *[s['mean_ms'] for s in report['common_stages']], report['mean_admission_to_append_ms']])
    render(comparison, output)
    raptr.render({'Healthy': new['healthy'], 'Silent leader': new['silent-first-leader']}, output/'raptr-detailed-stages.png')
    serial = {label: report for label, report in [('Healthy', new['healthy']), ('Silent leader', new['silent-first-leader'])]
              if report['serial_quorum_cohort']['covered'] > 0}
    if serial:
        raptr.render(serial, output/'raptr-quorum-stages.png', serial_quorum=True)
    print(json.dumps({'output': str(output), 'comparison': comparison}, indent=2))


if __name__ == '__main__':
    main()
