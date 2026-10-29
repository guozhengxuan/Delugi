#!/usr/bin/env python3
"""Offline comparison of corrected Delugi with frozen Raptr and pipeline Delugi.

No deployment, compilation or protocol execution. Read and validate the original
cohort/trace evidence before producing any comparison figure.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import json
from pathlib import Path

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p/'scripts/latency_decomposition.py').is_file())
PREVIOUS = ROOT/'benchmarks/results/delugi-pipeline-wan-2026-10-29'
PREVIOUS_RUN = ROOT/'benchmark/.state/runs/delugi-pipeline-wan-20261029-clock-aligned'
PINS = {
    'plot_comparison.py': 'de6fc9312aedeee1ff3f241222aee9f3b1db5b09cee830155393f3d589c9da87',
    'comparison.json': '72ea098c561530643b0044ea32e8a9f73da1bed7df5e39eb5243c0686a1ec615',
    'record.json': 'a2f0d208e00dc866bce86d5b97fa803708ace778550704722aee60e395f968a3',
}
CASES = ('healthy', 'silent-first-leader')
COMMON = ('Batch formation', 'Dissemination / inclusion', 'Consensus', 'Output processing')
ORDER = ('delugi_freshness', 'raptr_saved', 'delugi_pipeline_saved')
LABELS = ('Delugi · corrected', 'Raptr · saved', 'Delugi · prior pipeline')


def load(path):
    return json.loads(Path(path).read_text())


def frozen_reader():
    # Hash before importing the historical executable analysis code.
    import hashlib
    for name, expected in PINS.items():
        p = PREVIOUS/name
        if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest() != expected:
            raise ValueError(f'changed historical analysis: {p}')
    spec = importlib.util.spec_from_file_location('frozen_pipeline_comparison', PREVIOUS/'plot_comparison.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def baselines(reader):
    sources = [reader.bound(PREVIOUS/name, digest) for name, digest in PINS.items()]
    # The Raptr record also binds both endpoint reducers.
    raptr_record = load(reader.BASE/'record.json')
    sources.extend(reader.bound(ROOT/name, digest)
                   for name, digest in raptr_record['postprocessors'].items())
    legacy, _, _, raptr, raptr_metrics, inherited = reader.frozen_baselines()
    pipeline, pipeline_metrics, pipeline_diagnostics, pipeline_sources = reader.current_delugi(PREVIOUS_RUN)
    published = load(PREVIOUS/'comparison.json')['comparison']
    for case in CASES:
        for key, protocol, report in [('delugi_pipeline', 'delugi', pipeline[case]),
                                      ('raptr_saved', 'raptr', raptr[case])]:
            expected = published[case][key]
            for field in ('scheduled', 'completed', 'covered', 'excluded'):
                if report[field] != expected[field]:
                    raise ValueError(f'changed historical cohort: {case}/{key}/{field}')
            legacy.equal_mean(report['mean_admission_to_append_ms'], expected['mean_admission_to_append_ms'])
            for actual, saved in zip(legacy.grouped(protocol, report), expected['common_stages']):
                legacy.equal_mean(actual['mean_ms'], saved['mean_ms'])
    return legacy, pipeline, pipeline_metrics, pipeline_diagnostics, raptr, raptr_metrics, sources+inherited+pipeline_sources


def freshness_markers(reader, run):
    """Require the added release marker; summarize its recorded trigger inputs.

    This confirms the new trace schema is present. It is not a substitute for
    core safety tests or a proof reconstructed from complete message contents.
    """
    answer = {}
    for row in load(run/'state.json')['rows']:
        trial = run/'trials'/row['trial_id']
        result = load(trial/'result.json')
        markers = []
        for entry in result['causal_trace']['files']:
            trace = load(trial/'trial/causal-traces'/f'replica-{entry["replica"]}.json')
            for event in trace['events']:
                if event['event'] != 'dissemination_outbox' or event['detail'].get('kind') != 'REPORT':
                    continue
                detail = event['detail']
                if type(detail.get('predecessor_proposal_validated')) is not bool:
                    raise ValueError('new run lacks corrected predecessor-validation REPORT marker')
                markers.append({'replica': trace['replica'], 'round': event['round'], 'at_us': event['at_us'],
                                **{k: detail[k] for k in ('admitted', 'local_report_horizon',
                                   'predecessor_proposal_validated', 'closed_signers', 'exact_history_ready')}})
        if not markers:
            raise ValueError('new run has no corrected REPORT markers')
        answer[row['case']] = {
            'count': len(markers),
            'with_validated_predecessor': sum(m['predecessor_proposal_validated'] for m in markers),
            'population': 'all retained leader REPORT markers, including setup and drain; not request weighted',
            'markers': markers,
        }
    return answer


def render(comparison, output):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    colors = ('#62A3CD', '#397CB2', '#86AB4C', '#D39949')
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 11,
                         'svg.fonttype': 'none', 'svg.hashsalt': 'delugi-freshness-wan-20261030'})
    fig, axes = plt.subplots(1, 2, figsize=(13.3, 7.4), sharey=True)
    fig.subplots_adjust(left=.185, right=.98, top=.73, bottom=.23, wspace=.26)
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
        ax.set_xlim(0, maximum*1.24); ax.set_ylim(2.58, -.6)
        ax.set_yticks(range(3), LABELS)
        ax.set_xlabel('Mean admission → verified output (ms)', fontsize=10)
        ax.grid(axis='x', color='#E6EBEF'); ax.set_axisbelow(True)
        for spine in ax.spines.values(): spine.set_visible(False)
        ax.tick_params(axis='both', length=0)
    fig.text(.045, .945, 'Four-region WAN: corrected Delugi versus saved Raptr', fontsize=18, weight='bold', color='#20344B')
    fig.text(.045, .897, '30 s input · 100 tx/s · 1 useful byte/tx · Δ = 1,000 ms · 20 Mbps public egress · natural WAN', fontsize=10.5)
    fig.legend(handles=[Patch(color=c, label=n) for c, n in zip(colors, COMMON)],
               loc='upper left', bbox_to_anchor=(.04, .867), ncol=4, frameon=False, fontsize=10)
    fig.text(.045, .145, 'Consensus starts at origin-local proposal acceptance. Stages sum over the same fully traced completed-request cohort.', fontsize=9)
    fig.text(.045, .105, 'Fault placement differs: Delugi silences Singapore replica 0; saved Raptr pauses Frankfurt replica 1. Native batching/timers differ.', fontsize=9)
    fig.text(.045, .065, 'Independent WAN runs; panel scales differ. Only corrected Delugi was rerun; baseline traces were revalidated offline.', fontsize=9, color='#536476')
    for extension in ('png', 'pdf', 'svg'):
        target = output/f'latency-decomposition-comparison.{extension}'
        fig.savefig(target, dpi=180, **({'metadata': {'Date': None}} if extension == 'svg' else {}))
        if extension == 'svg':
            target.write_text('\n'.join(line.rstrip() for line in target.read_text().splitlines())+'\n')
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, help='completed two-trial corrected-Delugi Fabric run')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--validate-baselines', action='store_true', help='verify frozen evidence without creating figures')
    args = parser.parse_args()
    if not args.validate_baselines and (args.run is None or args.output is None):
        parser.error('--run and --output are required unless --validate-baselines is used')
    reader = frozen_reader()
    legacy, previous, previous_metrics, previous_diag, raptr, raptr_metrics, baseline_sources = baselines(reader)
    if args.validate_baselines:
        print(json.dumps({'status': 'verified', 'means_ms': {
            case: {'delugi_pipeline_saved': previous[case]['mean_admission_to_append_ms'],
                   'raptr_saved': raptr[case]['mean_admission_to_append_ms']} for case in CASES}}, indent=2))
        return
    run = args.run.resolve()
    if run == PREVIOUS_RUN or run == reader.RAPTR_RUN:
        raise ValueError('new run must not alias a saved baseline')
    new, new_metrics, new_diag, new_sources = reader.current_delugi(run)
    markers = freshness_markers(reader, run)
    comparison = {}
    for case in CASES:
        comparison[case] = {}
        for name, protocol, report in [('delugi_pipeline_saved', 'delugi', previous[case]),
                                       ('raptr_saved', 'raptr', raptr[case]),
                                       ('delugi_freshness', 'delugi', new[case])]:
            comparison[case][name] = {
                **{k: report[k] for k in ('scheduled', 'completed', 'covered', 'excluded',
                                         'mean_admission_to_append_ms', 'mean_schedule_to_admission_ms')},
                'common_stages': legacy.grouped(protocol, report), 'native_stages': report['stages'],
            }
    unique_sources = {}
    for source in baseline_sources+new_sources+[reader.bound(__file__)]:
        old = unique_sources.setdefault(source['path'], source)
        if old != source:
            raise ValueError('inconsistent source binding')
    summary = {
        'schema': 1, 'comparison': comparison,
        'metrics': {'delugi_pipeline_saved': previous_metrics, 'raptr_saved': raptr_metrics,
                    'delugi_freshness': new_metrics},
        'leader_diagnostics': {'delugi_pipeline_saved': previous_diag, 'delugi_freshness': new_diag},
        'report_preparation_markers': markers,
        'source_files': list(unique_sources.values()),
        'metric_populations': 'Stage means use covered completed intended requests. Full scheduled-cohort quantiles retain unfinished requests. Stage means are additive; quantiles are not.',
        'limitations': [
            'Only corrected Delugi was rerun. Raptr and previous-pipeline Delugi are saved independent WAN runs; host and network conditions are not contemporaneous.',
            'Start is successful origin-local admission; end is origin-local verified contiguous application output before diagnostic journaling. Consensus starts at origin-local valid proposal acceptance; proposal transit belongs to the preceding stage.',
            'Native batching remains: Delugi maximum wait 10 ms; Raptr Quorum Store 150 ms polling with 80 ms minimum nonempty and 300 ms maximum.',
            'Equal Delta does not equalize recovery: Raptr uses 4Delta from round entry; Delugi uses eligible 7Delta main and independent 3Delta catch-up timers.',
            'Delugi silences protocol participation at replica0/Singapore with transport ACKs active; Raptr pauses replica1/Frankfurt. Faulty identities keep repeated leadership slots.',
            'Output groups different internal phase orderings: Delugi releases descriptors before payload materialization; Raptr validates payloads before FIFO release.',
            'Saved Raptr silent case has eight requests cancelled before admission, retained in scheduled-cohort statistics but absent from completed-stage means.',
            'One run per case at one low offered load, with unquantified observer overhead; this is deployment and latency verification, not a full throughput study.',
            'Remote load starts use one controller monotonic epoch mapped into each replica wall clock, with measured RTT uncertainty retained; all transaction latency intervals use only one origin monotonic clock.',
            'Retained REPORT markers confirm the predecessor-validation field is present, not a full proof reconstructed from complete authenticated messages. Detailed handler spans remain sampled.',
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
