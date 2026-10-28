#!/usr/bin/env python3
"""Origin-local, transaction-weighted latency bars from causal events and cohorts.

Every bar uses the same completed, fully instrumented request population. Parallel
leader history/report spans are a separate table, never added to request bars.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path

from cohort_metrics import identity
from cohort_store import ShardedArchive

STAGES = ("Batch formation", "Await execution proposal", "Agreement",
          "Contiguous prefix wait", "Payload wait", "Application append")


def collect(controller, replicas, directory):
    """Same bounded control channel for local and SSH-tunneled replicas."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    files = []
    for replica in replicas:
        document, offset, metadata = None, 0, None
        while True:
            page = controller.request(replica, 'causal_trace', offset=offset, limit=1024)['reply']['data']
            fixed = {k: v for k, v in page.items() if k not in ('events', 'offset', 'next_offset')}
            if (page['replica'] != replica or page['offset'] != offset or
                    (metadata is not None and fixed != metadata)):
                raise ValueError('causal trace changed during frozen collection')
            metadata = fixed
            if document is None:
                document = {**fixed, 'events': []}
            document['events'].extend(page['events'])
            end = offset+len(page['events'])
            expected_next = end if end < page['total'] else None
            if end > page['total'] or page['next_offset'] != expected_next or (expected_next is not None and end == offset):
                raise ValueError('noncontiguous trace page')
            if expected_next is None:
                break
            offset = expected_next
        path = directory/f'replica-{replica}.json'
        raw = json.dumps(document, separators=(',', ':')).encode()+b'\n'
        path.write_bytes(raw)
        files.append({'replica': replica, 'path': str(path.resolve()),
                      'sha256': hashlib.sha256(raw).hexdigest(), 'events': len(document['events']),
                      'dropped': document['dropped']})
    return {'files': files, 'complete': all(f['dropped'] == 0 for f in files),
            'collection_boundary': 'protocol quiescence, after the measured endpoint'}


def first(events, name, round=None):
    return next((e for e in events if e['event'] == name and
                 (round is None or e['round'] == round)), None)


def request_stages(request, output, sealed, materialized, rounds):
    """Return disjoint intervals; missing/late observations are not zero-filled."""
    round = materialized['round']
    events = rounds.get(round, [])
    release = first(events, 'prefix_release')
    if release is None:
        raise ValueError('missing_prefix_release')
    digest = identity(release['detail']['digest'])
    proposal = next((e for e in events if e['event'] == 'proposal_validated'
                     and identity(e['detail']['digest']) == digest), None)
    decision = next((e for e in events if e['event'] == 'classified'
                     and isinstance(e['detail']['status'], dict)
                     and identity(e['detail']['status'].get('Commit', 'missing')) == digest), None)
    payload = first(events, 'payload_ready')
    if proposal is None or decision is None or payload is None:
        raise ValueError('missing_proposal_decision_or_payload')
    points = [request['admitted_us'], sealed['at_us'], proposal['at_us'],
              decision['at_us'], release['at_us'], payload['at_us'], output['materialized_us']]
    if any(type(t) is not int for t in points) or any(a > b for a, b in zip(points, points[1:])):
        raise ValueError('nonsequential_local_boundaries')
    stages = [b-a for a, b in zip(points, points[1:])]
    assert sum(stages) == output['materialized_us']-request['admitted_us']
    return stages


def leader_rows(replica, rounds):
    rows = []
    for r, events in sorted(rounds.items()):
        sent = next((e for e in events if e['event'] == 'ordering_outbox'
                     and e['detail'].get('kind') == 'PROPOSE'), None)
        if sent is None:
            continue
        markers = {'admission': first(events, 'admission'),
                   'history_quorum': first(events, 'history_quorum'),
                   'input_fixed': first(events, 'input_fixed'), 'proposal': sent}
        report = next((e for e in events if e['event'] == 'dissemination_outbox'
                       and e['detail'].get('kind') == 'REPORT'), None)
        markers['report'] = report
        times = {k: v['at_us'] if v else None for k, v in markers.items()}
        row = {'replica': replica, 'round': r, **{k+'_us': v for k, v in times.items()}}
        for key, start, end in [('frozen_input_age_ms', 'input_fixed', 'proposal'),
                                ('admission_to_proposal_ms', 'admission', 'proposal'),
                                ('report_to_input_ms', 'report', 'input_fixed')]:
            row[key] = None if times[start] is None else (times[end]-times[start])/1000
        history = first(events, 'history_build')
        row['history_assembly_ms'] = (history['at_us']-history['start_us'])/1000 if history else None
        row['history_detail'] = history['detail'] if history else None
        direct = first(events, 'direct_commit')
        row['leader_outbox_to_direct_ms'] = (direct['at_us']-sent['at_us'])/1000 if direct else None
        first_report = first(events, 'history_report_received')
        row['first_history_report_to_quorum_ms'] = (
            (markers['history_quorum']['at_us']-first_report['at_us'])/1000
            if first_report and markers['history_quorum'] else None)
        rows.append(row)
    return rows


def analyze(cohorts, traces, *, allow_unbound_legacy=False):
    archive = ShardedArchive(cohorts)
    sums = [0]*len(STAGES)
    scheduled = completed = covered = 0
    excluded = Counter()
    by_replica, leaders, timers, source_files, history_generation = {}, [], [], [], []
    schedule_sum = 0
    for replica, ledger in archive.ledgers.items():
        requests = list(archive.rows(replica, 'requests'))
        # Fully consume shard iterators: their terminal hash checks must execute.
        outputs = list(archive.rows(replica, 'outputs'))
        if not requests:
            continue
        file = Path(traces)/f'replica-{replica}.json'
        raw = file.read_bytes()
        trace = json.loads(raw)
        if trace.get('schema') != 'delugi-causal-trace-v1' or trace.get('replica') != replica:
            raise ValueError('trace schema/replica mismatch')
        if trace.get('dropped') != 0 or trace.get('run_error') is not None:
            raise ValueError('incomplete or failed causal trace')
        context = first(trace['events'], 'run_context')
        if context is None and not allow_unbound_legacy:
            raise ValueError('trace lacks run binding; legacy traces require an explicit override')
        if context is not None and context['detail']['instance'] != ledger['manifest']['body']['instance']:
            raise ValueError('trace and request cohort belong to different runs')
        source_files.append({'path': str(file.resolve()), 'sha256': hashlib.sha256(raw).hexdigest(),
                             'events': len(trace['events']), 'dropped': trace['dropped'],
                             'run_bound': context is not None})
        rounds, sealed, materialized = {}, {}, {}
        for event in sorted(trace['events'], key=lambda e: e['at_us']):
            rounds.setdefault(event['round'], []).append(event)
            if event['event'] == 'batch_sealed':
                sealed.setdefault(identity(event['detail']['exact_batch_id']), event)
            if event['event'] == 'batch_materialized':
                materialized.setdefault(identity(event['detail']['exact_batch_id']), event)
            if event['event'] in ('main_timer_arm', 'main_timer_expiry', 'catchup_timer_arm',
                                   'catchup_timer_expiry', 'no_cer', 'history_ready', 'prefix_advance'):
                timers.append({'replica': replica, **event})
        leaders.extend(leader_rows(replica, rounds))
        for r, events in rounds.items():
            ready = first(events, 'history_ready')
            sent = next((e for e in events if e['event'] == 'ordering_outbox'
                         and e['detail'].get('kind') == 'HISTORY3'), None)
            if ready and sent:
                history_generation.append({'replica':replica,'horizon':r,
                    'generation_ms':(sent['at_us']-ready['at_us'])/1000,
                    'encoded_message_bytes':sent['detail'].get('encoded_message_bytes')})
        own = {identity(o['id']): o for o in outputs if o['origin'] == replica}
        counts = Counter()
        for request in requests:
            if not ledger['window_start_us'] <= request['scheduled_us'] < ledger['window_end_us']:
                continue
            scheduled += 1
            counts['scheduled'] += 1
            output = own.get(identity(request['id']))
            if output is None or request['admitted_us'] is None or request.get('rejected_us') is not None:
                excluded['unfinished_or_rejected'] += 1
                continue
            completed += 1
            counts['completed'] += 1
            batch = identity(output['exact_batch_id'])
            if batch not in sealed or batch not in materialized:
                excluded['missing_exact_batch_boundary'] += 1
                continue
            try:
                stages = request_stages(request, output, sealed[batch], materialized[batch], rounds)
            except ValueError as error:
                excluded[str(error)] += 1
                continue
            covered += 1
            counts['covered'] += 1
            sums = [a+b for a, b in zip(sums, stages)]
            schedule_sum += request['admitted_us']-request['scheduled_us']
        by_replica[str(replica)] = dict(counts)
    return {'schema': 'delugi-latency-decomposition-v1', 'scheduled': scheduled,
            'completed': completed, 'covered': covered, 'excluded': dict(excluded),
            'by_replica': by_replica, 'stages': [{'stage': name, 'mean_ms': total/covered/1000 if covered else None}
                                               for name, total in zip(STAGES, sums)],
            'mean_admission_to_append_ms': sum(sums)/covered/1000 if covered else None,
            'mean_schedule_to_admission_ms': schedule_sum/covered/1000 if covered else None,
            'leader_rounds': leaders, 'history_generation':history_generation,
            'timer_events': timers, 'sources': source_files,
            'cohort_index_sha256': archive.index_sha256,
            'contract': ['Origin-local monotonic timestamps only; no subtraction across replicas.',
                         'Arithmetic transaction-weighted means on one identical completed and instrumented cohort.',
                         'Await execution proposal includes dissemination and inclusion waits, which run in parallel.',
                         'Proposal boundary is local full validation of the exact proposal whose round releases the batch.',
                         'Agreement ends at the first final scanner classification; indirect commits remain identifiable in raw traces.',
                         'The agreement bar starts after local full validation, so proposal transit belongs to the preceding stage; leader outbox-to-direct spans separately measure the complete logical PROPOSE-to-CER-quorum cycle.',
                         'Unfinished or missing boundaries are counted separately, never converted to zero latency.',
                         'Leader history/report spans are diagnostics and overlap the request stages.']}


def render(reports, output):
    if not reports or any(r.get('covered',0) <= 0 for r in reports.values()):
        raise ValueError('cannot plot an empty instrumented cohort')
    for report in reports.values():
        means=[stage['mean_ms'] for stage in report['stages']]
        if len(means) != len(STAGES) or any(v is None or not math.isfinite(v) or v < 0 for v in means):
            raise ValueError('missing or invalid stage mean')
        if not math.isclose(sum(means),report['mean_admission_to_append_ms'],rel_tol=1e-9,abs_tol=1e-9):
            raise ValueError('stage means do not sum to the endpoint')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(figsize=(10, 4.8), layout='constrained')
    labels = list(reports)
    bottom = [0.0]*len(labels)
    colors = ['#8cb9de', '#487fb2', '#83b83e', '#df9343', '#c779a7', '#e4d96a']
    for i, name in enumerate(STAGES):
        values = [reports[label]['stages'][i]['mean_ms'] for label in labels]
        axes.bar(labels, values, bottom=bottom, label=name, color=colors[i], width=.55)
        bottom = [a+b for a, b in zip(bottom, values)]
    for x, label, height in zip(range(len(labels)), labels, bottom):
        r = reports[label]
        axes.annotate(f"{height:,.0f} ms\n{r['covered']}/{r['scheduled']} requests", (x, height),
                      xytext=(0, 6), textcoords='offset points', ha='center', fontsize=9)
    axes.set_ylabel('Mean admission → append latency (ms)')
    axes.set_title('Local Delugi latency decomposition · completed, instrumented requests')
    axes.set_ylim(0, max(bottom, default=1)*1.3 or 1)
    axes.legend(loc='upper left', bbox_to_anchor=(1, 1), frameon=False)
    axes.spines[['right', 'top']].set_visible(False)
    axes.set_axisbelow(True)
    axes.grid(axis='y', alpha=.2)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=180)
    plt.close(figure)
    return str(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohorts', type=Path, required=True)
    parser.add_argument('--traces', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-unbound-legacy', action='store_true')
    args = parser.parse_args()
    report = analyze(args.cohorts, args.traces, allow_unbound_legacy=args.allow_unbound_legacy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: report[k] for k in ('scheduled', 'completed', 'covered', 'stages', 'excluded')}))


if __name__ == '__main__':
    main()
