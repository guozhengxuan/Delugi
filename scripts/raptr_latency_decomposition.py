#!/usr/bin/env python3
"""Decompose receipt-bound Raptr journals using only origin-local timestamps.

Run after the native archive verifier. This reader rechecks its receipt/file hash
bindings; it does not claim to reverify native signatures or consensus proofs.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path

import run_raptr_shared_local as native

ENDPOINT = 'verified_contiguous_application_acceptance_v2'
STAGES = ('Batch formation', 'Dissemination / inclusion', 'Consensus',
          'Payload retrieval / validation', 'Contiguous output wait',
          'Output consumer wait', 'Application acceptance')
COMMON_STAGES = ('Batch formation', 'Dissemination / inclusion', 'Consensus', 'Output processing')
SERIAL_STAGES = ('Batch formation', 'Dissemination to availability quorum', 'Quorum → inclusion',
                 *STAGES[2:])
EVENTS = {'batch_stored', 'availability_quorum', 'proposal_validated',
          'committed', 'payload_ready', 'prefix_released'}


def timestamp(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError('invalid_monotonic_timestamp')
    return value


def batch_key(batch):
    """Do not join a native batch by its short ID, height, or expiration."""
    return (native.uint(batch['epoch'], 'epoch'), native.hex_hash(batch['author'], 'author'),
            native.uint(batch['nonce'], 'nonce'), native.uint(batch['id'], 'batch id'),
            native.hex_hash(batch['digest'], 'batch digest'))


def block_key(block):
    if type(block['round']) is not int or not -(2**63) <= block['round'] < 2**63:
        raise ValueError('invalid native round')
    return block['round'], native.hex_hash(block['digest'], 'block digest')


def section_key(section):
    if section == {'kind': 'proofs'}:
        return -1
    if (set(section) == {'kind', 'index'} and section['kind'] == 'sub_block'
            and type(section['index']) is int and 0 <= section['index'] < 8):
        return section['index']
    raise ValueError('invalid native output section')


def indexes(events):
    batches, proposals, commits, payloads, prefixes = {}, {}, {}, {}, {}
    for event in sorted(events, key=lambda e: timestamp(e['at_us'])):
        name = event.get('event')
        if name not in EVENTS:
            raise ValueError('unknown latency event')
        if name in ('batch_stored', 'availability_quorum'):
            batches.setdefault((name, batch_key(event['batch'])), event['at_us'])
        elif name == 'proposal_validated':
            proposals.setdefault(block_key(event), event['at_us'])
        elif name == 'committed':
            first, last = event['from_prefix'], event['to_prefix']
            if (type(first) is not int or type(last) is not int or not 0 <= first <= last <= 8
                    or type(event['include_proofs']) is not bool):
                raise ValueError('invalid committed slice')
            sections = list(range(first, last))
            if event['include_proofs']:
                sections.insert(0, -1)
            for section in sections:
                commits.setdefault((*block_key(event), section), event['at_us'])
        else:
            target = payloads if name == 'payload_ready' else prefixes
            target.setdefault((*block_key(event), section_key(event['section'])), event['at_us'])
    return batches, proposals, commits, payloads, prefixes


def request_stages(request, output, batch, indexed):
    batches, proposals, commits, payloads, prefixes = indexed
    key = batch_key(batch['key'])
    block = block_key(output['block'])
    section = (*block, section_key(output['section']))
    try:
        stored = batches['batch_stored', key]
    except KeyError as error:
        raise ValueError('missing_exact_batch_stored') from error
    try:
        proposal, commit = proposals[block], commits[section]
    except KeyError as error:
        raise ValueError('missing_execution_proposal_or_commit_slice') from error
    try:
        payload, prefix = payloads[section], prefixes[section]
    except KeyError as error:
        raise ValueError('missing_payload_or_contiguous_release') from error
    if (output.get('timing_contract') != ENDPOINT
            or output.get('app_processing_start_us') is None
            or output.get('journal_constructed_us') is None):
        raise ValueError('missing_minimal_application_boundary')
    points = [request['admitted_us'], stored, proposal, commit, payload, prefix,
              output['app_processing_start_us'], output['append_us']]
    points = [timestamp(point) for point in points]
    if timestamp(request['planned_us']) > points[0] or any(a > b for a, b in zip(points, points[1:])):
        raise ValueError('nonsequential_local_boundaries')
    journal_done = timestamp(output['journal_constructed_us'])
    if journal_done < points[-1]:
        raise ValueError('nonsequential_journal_boundary')
    stages = [b-a for a, b in zip(points, points[1:])]
    if sum(stages) != output['append_us']-request['admitted_us']:
        raise ValueError('stage_sum_mismatch')
    available = batches.get(('availability_quorum', key))
    availability = {'status': 'missing'}
    if available is not None:
        if available < stored:
            availability = {'status': 'nonsequential'}
        else:
            availability = {'status': 'observed', 'duration_us': available-stored,
                            'relative_to_proposal_us': available-proposal,
                            'after_proposal': available > proposal}
    return stages, journal_done-points[-1], availability


def _bound(path, descriptor):
    record = native.file_record(path)
    if (record['sha256'] != descriptor['sha256']
            or ('bytes' in descriptor and record['bytes'] != descriptor['bytes'])):
        raise ValueError('receipt-bound source changed')
    return {'path': str(path.resolve()), **record}


def authentication_map(authentication, correct_replicas):
    """Accept both local aggregate verifier output and the remote signer map."""
    if not isinstance(authentication, dict):
        raise ValueError('native archive verification is required')
    if 'replicas' in authentication:
        if (authentication.get('verified') is not True
                or authentication.get('verified_signers') != sorted(correct_replicas)):
            raise ValueError('native archive verification signer set differs')
        rows = authentication['replicas']
        if not isinstance(rows, list) or len({row['signer'] for row in rows}) != len(rows):
            raise ValueError('duplicate native archive verification signer')
        authentication = {str(row['signer']): row for row in rows}
    if set(map(str, authentication)) != set(map(str, correct_replicas)):
        raise ValueError('native archive verification signer set differs')
    return authentication


def analyze(config_path, replica_directory, correct_replicas, *, authentication):
    """Use the native verifier's per-replica result, then bind all parsed bytes."""
    from run_raptr_sustained import journal
    config_path, replica_directory = Path(config_path), Path(replica_directory)
    config = native.bounded_json(config_path)
    config_hash = native.sha256(config_path)
    options = config.get('latency_trace')
    if not isinstance(options, dict) or type(options.get('max_events')) is not int or options['max_events'] <= 0:
        raise ValueError('configuration did not enable bounded latency tracing')
    if (not correct_replicas or len(set(correct_replicas)) != len(correct_replicas)
            or any(type(i) is not int or not 0 <= i < len(config['addresses']) for i in correct_replicas)):
        raise ValueError('invalid correct-replica population')
    authentication = authentication_map(authentication, correct_replicas)
    scheduled = admitted = completed = covered = 0
    sums = [0]*len(STAGES)
    schedule_sum = journal_sum = 0
    excluded, availability_counts = Counter(), Counter()
    availability_sum = availability_after = 0
    serial_sums = [0]*len(SERIAL_STAGES)
    serial_covered = serial_schedule_sum = 0
    serial_excluded = Counter()
    per_origin, sources = {}, []
    for origin in correct_replicas:
        directory = replica_directory/f'node-{origin}'
        receipt_path = native.safe_file(directory, 'final.json')
        verified = authentication.get(str(origin), authentication.get(origin))
        if not isinstance(verified, dict) or verified.get('verified') is not True:
            raise ValueError('native archive verification is required')
        if verified.get('signer', origin) != origin:
            raise ValueError('native archive verification signer differs')
        sources.append(_bound(receipt_path, {'sha256': verified['receipt_sha256']}))
        receipt = native.bounded_json(receipt_path, limit=64*1024**2)
        body = receipt['body']
        if (receipt['signer'] != origin or body['id'] != origin or body['run_id'] != config['run_id']
                or body['configuration_sha256'] != config_hash or body.get('status') != 'completed'
                or body.get('error') is not None):
            raise ValueError('failed or mismatched signed receipt')
        files = {}
        for descriptor in body['files']:
            if descriptor['name'] in files:
                raise ValueError('duplicate evidence file descriptor')
            files[descriptor['name']] = descriptor
        needed = ('latency-trace.json', 'effective-profile.json', 'requests.jsonl', 'output.jsonl')
        if any(name not in files for name in needed):
            raise ValueError('missing receipt-bound timing evidence')
        for name in needed:
            sources.append(_bound(native.safe_file(directory, name), files[name]))
        profile = native.bounded_json(directory/'effective-profile.json')
        if profile.get('output_endpoint') != ENDPOINT:
            raise ValueError('archive uses a different application endpoint')
        trace = native.bounded_json(directory/'latency-trace.json',
                                    limit=min(1024**3, options['max_events']*1024+4096))
        if (trace.get('schema') != 'raptr-latency-trace-v1' or trace.get('replica') != origin
                or trace.get('run_id') != config['run_id'] or trace.get('configuration_sha256') != config_hash
                or trace.get('clock') != 'CLOCK_MONOTONIC' or trace.get('max_events') != options['max_events']):
            raise ValueError('trace and request cohort belong to different runs or clocks')
        if trace.get('dropped') != 0 or len(trace['events']) > options['max_events']:
            raise ValueError('incomplete or oversized latency trace')
        indexed = indexes(trace['events'])
        own = {}
        for output in journal(directory/'output.jsonl', max_rows=900_000):
            for batch in output['batches']:
                for tx in batch['transactions']:
                    if tx['own_credit']:
                        if (tx['origin'] != origin or not tx['eligible'] or not tx['first_seen']
                                or tx['request_id'] in own):
                            raise ValueError('invalid or duplicate credited output')
                        own[tx['request_id']] = (output, batch)
        counts = Counter()
        epoch = timestamp(body['epoch_us'])
        end = epoch+config['measurement_duration_ms']*1000
        for request in journal(directory/'requests.jsonl', max_line=16384):
            if not epoch <= timestamp(request['planned_us']) < end:
                continue
            scheduled += 1; counts['scheduled'] += 1
            admitted += request['admitted_us'] is not None
            materialized = request['first_materialized_us']
            if materialized is None:
                if request['request_id'] in own:
                    raise ValueError('credited output missing from request ledger')
                excluded['unfinished_or_not_admitted'] += 1
                continue
            if (request['admitted_us'] is None or request.get('rejected_us') is not None
                    or request.get('cancelled_us') is not None):
                raise ValueError('unadmitted request received output credit')
            try:
                output, batch = own.pop(request['request_id'])
            except KeyError as error:
                raise ValueError('completed request lacks credited output') from error
            if (output['append_us'] != materialized or output['event'] != request['first_materialized_event']):
                raise ValueError('request and output endpoints disagree')
            completed += 1; counts['completed'] += 1
            try:
                stages, diagnostic_journal, availability = request_stages(request, output, batch, indexed)
            except ValueError as error:
                excluded[str(error)] += 1
                continue
            covered += 1; counts['covered'] += 1
            sums = [a+b for a, b in zip(sums, stages)]
            schedule_sum += request['admitted_us']-request['planned_us']
            journal_sum += diagnostic_journal
            availability_counts[availability['status']] += 1
            if availability['status'] == 'observed':
                availability_sum += availability['duration_us']
                availability_after += availability['after_proposal']
            if availability['status'] != 'observed':
                serial_excluded['availability_'+availability['status']] += 1
            elif availability['after_proposal']:
                serial_excluded['availability_after_execution_proposal'] += 1
            else:
                dissemination = availability['duration_us']
                split = [stages[0], dissemination, stages[1]-dissemination, *stages[2:]]
                if any(value < 0 for value in split) or sum(split) != sum(stages):
                    raise ValueError('serial quorum stage sum mismatch')
                serial_sums = [a+b for a, b in zip(serial_sums, split)]
                serial_schedule_sum += request['admitted_us']-request['planned_us']
                serial_covered += 1
        if own:
            raise ValueError('credited output outside scheduled cohort')
        per_origin[str(origin)] = dict(counts)
    # Reject a source change during parsing, as well as changes since native verification.
    if native.sha256(config_path) != config_hash:
        raise ValueError('configuration changed during reduction')
    for source in sources:
        _bound(Path(source['path']), source)
    mean = lambda value: value/covered/1000 if covered else None
    observed = availability_counts['observed']
    return {
        'schema': 'raptr-latency-decomposition-v1', 'run_id': config['run_id'],
        'configuration_sha256': config_hash, 'endpoint_contract': ENDPOINT,
        'scheduled': scheduled, 'admitted': admitted, 'completed': completed, 'covered': covered,
        'excluded': dict(excluded), 'by_replica': per_origin,
        'stages': [{'stage': name, 'sum_us': total, 'mean_ms': mean(total)} for name, total in zip(STAGES, sums)],
        'common_stages': [{'stage': name, 'mean_ms': mean(total)}
                          for name, total in zip(COMMON_STAGES, [*sums[:3], sum(sums[3:])])],
        'mean_admission_to_append_ms': mean(sum(sums)),
        'mean_schedule_to_admission_ms': mean(schedule_sum),
        'mean_schedule_to_append_ms': mean(schedule_sum+sum(sums)),
        'journal_construction_after_endpoint': {'covered': covered, 'mean_ms': mean(journal_sum)},
        'availability_quorum': {
            'population': 'same covered requests; observed subset stated separately',
            'counts': dict(availability_counts), 'after_execution_proposal': availability_after,
            'mean_stored_to_quorum_ms': availability_sum/observed/1000 if observed else None,
            'additive': False,
        },
        'serial_quorum_cohort': {
            'scheduled': scheduled, 'completed': completed, 'primary_covered': covered,
            'covered': serial_covered, 'excluded': dict(excluded+serial_excluded),
            'excluded_from_primary_covered': dict(serial_excluded),
            'stages': [{'stage': name, 'sum_us': total,
                        'mean_ms': total/serial_covered/1000 if serial_covered else None}
                       for name, total in zip(SERIAL_STAGES, serial_sums)],
            'mean_admission_to_append_ms': sum(serial_sums)/serial_covered/1000 if serial_covered else None,
            'mean_schedule_to_append_ms': (serial_schedule_sum+sum(serial_sums))/serial_covered/1000 if serial_covered else None,
            'contract': 'Separate same-request cohort satisfying stored <= availability quorum <= proposal; this observed order is not a protocol quorum gate. Do not compare these means to primary-cohort stage means as if their populations were identical.',
        },
        'sources': sources,
        'verification': 'Source hashes rechecked against the saved native verifier receipt hashes and signed file descriptors; signatures are not reverified by this reducer.',
        'contract': [
            'Origin-local CLOCK_MONOTONIC only; no cross-host subtraction.',
            'Arithmetic transaction-weighted means on one identical completed and instrumented cohort.',
            'Join exact batch identity and the block/section that first credits the request.',
            'Dissemination / inclusion includes availability and proposal waiting; quorum duration is a separate overlapping diagnostic.',
            'Consensus starts when the locally verified full execution proposal is accepted by the core, including prior verified-inbox queue delay in dissemination/inclusion, and ends at its exact committed output slice.',
            'Output includes native payload validation, contiguous FIFO release, consumer scheduling, mutex wait and application identity/dedup validation.',
            'Application acceptance is measured before diagnostic journal construction; failed publication invalidates the run.',
            'Missing and nonsequential boundaries exclude requests from stage means but retain cohort counts.',
        ],
    }


def render(reports, output, *, serial_quorum=False):
    if serial_quorum:
        reports = {label: report['serial_quorum_cohort'] for label, report in reports.items()}
    names = SERIAL_STAGES if serial_quorum else STAGES
    if not reports or any(report.get('covered', 0) <= 0 for report in reports.values()):
        raise ValueError('cannot plot an empty instrumented cohort')
    for report in reports.values():
        means = [stage['mean_ms'] for stage in report['stages']]
        if (len(means) != len(names) or any(value is None or not math.isfinite(value) or value < 0 for value in means)
                or not math.isclose(sum(means), report['mean_admission_to_append_ms'], rel_tol=1e-9, abs_tol=1e-9)):
            raise ValueError('stage means do not sum to the endpoint')
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(figsize=(11, 5), layout='constrained')
    bottom = [0.0]*len(reports)
    colors = ('#81B9DF', '#3980B5', '#7BAE40', '#DDA64F', '#AD86BC', '#75B9A6', '#D97E6C', '#668A99')
    for index, name in enumerate(names):
        values = [report['stages'][index]['mean_ms'] for report in reports.values()]
        axes.bar(list(reports), values, bottom=bottom, label=name, color=colors[index], width=.55)
        bottom = [a+b for a, b in zip(bottom, values)]
    for position, (report, height) in enumerate(zip(reports.values(), bottom)):
        axes.annotate(f"{height:,.2f} ms\n{report['covered']}/{report['scheduled']} requests", (position, height),
                      xytext=(0, 6), textcoords='offset points', ha='center', fontsize=9)
    axes.set_ylabel('Mean admission → application acceptance (ms)')
    axes.set_title('Raptr stage latency · '+('serial-quorum subset' if serial_quorum else 'completed, instrumented requests'))
    axes.set_ylim(0, max(bottom)*1.3 or 1)
    axes.legend(loc='upper left', bbox_to_anchor=(1, 1), frameon=False)
    axes.spines[['right', 'top']].set_visible(False)
    axes.set_axisbelow(True); axes.grid(axis='y', alpha=.2)
    output = Path(output); output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=180); plt.close(figure)
    return str(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--replicas', type=Path, required=True)
    parser.add_argument('--verification', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--figure', type=Path)
    parser.add_argument('--serial-quorum-figure', type=Path)
    args = parser.parse_args()
    verified = native.bounded_json(args.verification, limit=64*1024**2)
    if verified.get('status') not in ('completed', 'passed'):
        raise ValueError('verification manifest must describe a completed run')
    report = analyze(args.config, args.replicas, verified['correct_replicas'],
                     authentication=verified.get('authentication', verified.get('offline_verification', {})))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    if args.figure:
        render({'Raptr': report}, args.figure)
    if args.serial_quorum_figure:
        render({'Raptr': report}, args.serial_quorum_figure, serial_quorum=True)
    print(json.dumps({key: report[key] for key in ('scheduled', 'completed', 'covered', 'excluded', 'stages')}))


if __name__ == '__main__':
    main()
