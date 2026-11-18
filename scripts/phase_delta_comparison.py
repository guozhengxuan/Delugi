#!/usr/bin/env python3
"""Compare healthy four-node Delugi and Raptr trials at first origin-local proposal acceptance."""
import argparse
import bisect
from collections import Counter, defaultdict
import json
from pathlib import Path
from statistics import fmean

import latency_decomposition as delugi
import raptr_latency_decomposition as raptr
from cohort_metrics import identity
from cohort_store import ShardedArchive
from run_raptr_sustained import journal


def read(path):
    return json.loads(path.read_bytes())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique(mapping, key, value, label):
    require(key not in mapping, f'duplicate {label}: {key}')
    mapping[key] = value


def mean_ms(rows, key):
    values = [row[key] for row in rows if row.get(key) is not None]
    return {'samples': len(values), 'mean_ms': fmean(values)/1000 if values else None}


def summarize(rows, keys):
    return {key.removesuffix('_us'): mean_ms(rows, key) for key in keys}


def validate_cohort(report):
    require(report['covered'] == report['scheduled'] > 0 and not report['excluded'],
            'comparison requires a fully completed, instrumented healthy cohort')


def observation_phase(times, seals):
    """Time-weighted residual on the actual irregular schedule, clipped to offered batches."""
    times = sorted(times)
    lo, hi = min(seals), max(seals)
    require(times[0] <= lo < hi <= times[-1], 'observation schedule does not cover load')
    area = 0
    gaps = []
    for left, right in zip(times, times[1:]):
        start, end = max(lo, left), min(hi, right)
        if end > start:
            area += ((right-start)**2-(right-end)**2)/2
        if lo <= left < right <= hi:
            gaps.append(right-left)
    return {'samples': len(seals), 'complete_intervals': len(gaps),
            'half_mean_interval_ms': fmean(gaps)/2000 if gaps else None,
            'uniform_time_residual_ms': area/(hi-lo)/1000,
            'actual_seal_to_next_own_obs_ms': fmean(times[bisect.bisect_left(times, t)]-t for t in seals)/1000}


def check_input(detail, signers, snapshots, round_number):
    frontier, targets, local = (detail[k] for k in ('frontier_heights', 'target_heights', 'local_heights'))
    require(len(frontier) == len(targets) == len(local) == 4, 'invalid descriptor dimensions')
    pool = detail['pool']
    require(len(pool) == len(set(signers)) == 3 and [o['signer'] for o in pool] == signers,
            'frozen pool and construction differ')
    for obs in pool:
        fixed = snapshots[obs['signer'], round_number]
        require(fixed['heights'] == obs['heights'] and fixed['base'] == detail['base'],
                'frozen observations differ from their producers')
    for k in range(4):
        require(frontier[k] <= targets[k] <= local[k], 'invalid local/selected frontier')
    for c in detail['candidates']:
        k, h, usable = c['producer'], c['height'], c['usable_signers']
        require(frontier[k] < h <= local[k] and len(set(usable)) == len(usable), 'invalid candidate')
        covering = {o['signer'] for o in pool if o['heights'][k] >= h}
        require(set(usable) <= covering, 'usable witness does not cover target')
        require((len(usable) >= 2) == (targets[k] == h and c['base_proof']),
                'actual chosen target differs from traced selection')


def inspect_cutoff(accepted, proposals, producer, height, start, execution_round):
    """Replay selection only, at observed origin acceptance times; no clock synchronization."""
    excluded = Counter()
    observed = Counter()
    relaxed = narrow = None
    for at, r, digest in accepted:
        if at < start:
            continue
        p = proposals[r]
        require(digest == p['digest'], 'accepted proposal differs from leader emission')
        data = p['input']
        if data['target_heights'][producer] >= height:
            require(execution_round in proposals and proposals[execution_round]['input']['target_heights'][producer] >= height,
                    'executing proposal lacks batch')
            return at, r, at if relaxed is None else relaxed, at if narrow is None else narrow, excluded, observed
        covering = sum(o['heights'][producer] >= height for o in data['pool'])
        if covering < 2:
            full = p.get('all_reporters', [])
            if len(full) < 4:
                observed['missing_fourth_signed_snapshot'] += 1
            elif sum(o['heights'][producer] >= height for o in full) >= 2:
                observed['two_covering_with_unselected_fourth'] += 1
            else:
                observed['fewer_than_two_even_across_all_four'] += 1
        else:
            observed['at_least_two_covering_in_frozen_pool'] += 1
        # All candidates above the selected height were actually examined in this
        # fork-free run. A higher target includes the same authenticated prefix.
        local_proof = any(c['producer'] == producer and c['height'] >= height and c['base_proof']
                          for c in data['candidates'])
        if not local_proof:
            excluded['local_target_or_base_proof_missing'] += 1
        elif covering < 2:
            excluded['leader_can_prove_target_but_fewer_than_two_observations'] += 1
            if narrow is None:
                narrow = at
        else:
            excluded['leader_can_prove_target_but_witness_proof_missing'] += 1
        if local_proof and relaxed is None:
            relaxed = at
    raise ValueError('no accepted proposal includes batch')


def delugi_trial(root):
    cfg, result = read(root/'config.json'), read(root/'result.json')
    require(result['status'] == 'passed' and result['fault']['kind'] == 'none' and len(cfg['addresses']) == 4,
            'Delugi trial must be a successful healthy four-validator run')
    archive = ShardedArchive(root/'cohorts/index.json')
    validated = delugi.analyze(archive.path, root/'causal-traces')
    validate_cohort(validated)
    traces = [read(root/f'causal-traces/replica-{i}.json')['events'] for i in range(4)]
    data = [e for trace in traces for e in trace if e['event'] == 'input_membership']
    summary = {'validation': {k: validated[k] for k in ('covered', 'excluded','cohort_index_sha256','sources')},
               'execution_associated_admission_to_accept_ms': sum(x['mean_ms'] for x in validated['stages'][:2]),
               'workload': (cfg['sustained']['total_rate'], cfg['sustained']['useful_bytes'],
                            cfg['sustained']['measurement_ms'], cfg['bound_ms'])}
    if not data:
        summary['instrumented'] = False
        return summary, []
    proposals, snapshots, ledger_by_height = {}, {}, {}
    for i, events in enumerate(traces):
        for e in events:
            if e['event'] == 'observation_fixed':
                unique(snapshots, (i,e['round']), e['detail'], 'reporter snapshot')
            elif e['event'] == 'batch_sealed':
                d = e['detail']
                require(d['producer'] == i, 'nonlocal seal')
                unique(ledger_by_height, (i, d['height']), identity(d['exact_batch_id']), 'honest-chain slot')
    for i, events in enumerate(traces):
        rounds = defaultdict(dict)
        for e in events:
            name, r, d = e['event'], e['round'], e['detail']
            if name == 'dissemination_outbox' and d['kind'] == 'REPORT':
                name = 'report'
            elif name == 'ordering_outbox' and d['kind'] == 'PROPOSE':
                name = 'emit'
            elif name not in ('input_membership', 'observation_pool_fixed'):
                continue
            unique(rounds[r], name, e, f'Delugi round {r} breakpoint')
        for r, events_by_kind in rounds.items():
            if 'emit' not in events_by_kind:
                continue
            inp, pool, send = (events_by_kind[k] for k in ('input_membership','observation_pool_fixed','emit'))
            d = inp['detail']
            require(i == (r-1)%4 and d['value_hash'] == send['detail']['value_hash'], 'emitted value differs from observed input')
            check_input(d, pool['detail']['signers'], snapshots, r)
            unique(proposals, r, {'leader':i, 'input':d, 'digest':identity(send['detail']['digest']),
                                  'all_reporters':[snapshots[j,r] for j in range(4) if (j,r) in snapshots],
                                  'emit':send['at_us'], 'report':events_by_kind['report']['at_us'],
                                  'pool':pool['at_us'], 'construct':inp['at_us']}, 'emitted round')
    rows, phases, counts, support = [], [], Counter(), Counter()
    for i, ledger in archive.ledgers.items():
        seals, mats, accepted = {}, {}, []
        for e in traces[i]:
            d = e['detail']
            if e['event'] == 'batch_sealed':
                seals[identity(d['exact_batch_id'])] = e
            elif e['event'] == 'proposal_validated':
                accepted.append((e['at_us'], e['round'], identity(d['digest'])))
            elif e['event'] == 'batch_materialized':
                mats.setdefault(identity(d['exact_batch_id']), e)
        accepted.sort()
        accept_by_round = {r:t for t,r,_ in accepted}
        require(len(accept_by_round) == len(accepted), 'duplicate healthy proposal acceptance')
        outputs = {identity(o['id']):o for o in archive.rows(i,'outputs') if o['origin'] == i}
        batch_results = {}
        origin_seals = []
        for req in archive.rows(i,'requests'):
            if not ledger['window_start_us'] <= req['scheduled_us'] < ledger['window_end_us']:
                continue
            out = outputs[identity(req['id'])]
            key = identity(out['exact_batch_id'])
            h, seal = seals[key]['detail']['height'], seals[key]['at_us']
            require(ledger_by_height[i,h] == key, 'producer chain differs from verified output')
            execution = mats[key]['round']
            if key not in batch_results:
                batch_results[key] = inspect_cutoff(accepted, proposals, i, h, seal, execution)
                counts.update(batch_results[key][4])
                support.update(batch_results[key][5])
            first, r, relax, narrow, _, _ = batch_results[key]
            p = proposals[r]
            associated, admitted = accept_by_round[execution], req['admitted_us']
            require(admitted <= seal <= relax <= narrow <= first <= associated, 'nonmonotonic origin intervals')
            rows.append({'protocol':'delugi', 'origin':i, 'sequence':req['sequence'], 'batch':key, 'height':h,
                         'execution_round':execution, 'first_local_round':r, 'leader':p['leader'],
                         'admitted_us':admitted, 'seal_us':seal, 'first_accept_us':first, 'output_us':out['materialized_us'],
                         'first_local_emit_leader_us':p['emit'], 'batching_us':seal-admitted,
                         'admit_to_first_local_us':first-admitted, 'seal_to_first_local_us':first-seal,
                         'execution_midpoint_shift_us':associated-first,
                         'fixed_schedule_base_proof_shift_us':first-relax,
                         'fixed_schedule_insufficient_observations_shift_us':first-narrow,
                         'report_to_pool_leader_us':p['pool']-p['report'],
                         'pool_to_constructed_leader_us':p['construct']-p['pool'],
                         'constructed_to_emit_leader_us':p['emit']-p['construct'],
                         'seal_to_report_self_leader_us':p['report']-seal if i == p['leader'] else None})
            origin_seals.append(seal)
        phases.append({'origin': i, **observation_phase(
            [e['at_us'] for e in traces[i] if e['event']=='observation_fixed'], origin_seals)})
    return {**summary, 'instrumented': True, 'own_obs_phases':phases,
            'excluded_earlier_distinct_batch_proposal_pairs':dict(counts),
            'pool_support_on_same_pairs':dict(support)}, rows


def raptr_trial(root):
    cfg = read(root/'config.json')
    result = read(root/('result.json' if (root/'result.json').is_file() else 'manifest.json'))
    require(result['status'] == 'completed' and result['correct_replicas'] == list(range(4))
            and cfg.get('payload_fault') is None, 'Raptr trial must be healthy and have four validators')
    validated = raptr.analyze(root/'config.json', root/'replicas', result['correct_replicas'],
                              authentication=result['authentication'])
    validate_cohort(validated)
    summary = {'validation': {k: validated[k] for k in ('covered','excluded','configuration_sha256','sources')},
               'execution_associated_admission_to_accept_ms': sum(x['mean_ms'] for x in validated['stages'][:2]),
               'workload':(cfg['sustained_workload']['total_honest_input_tps'],cfg['finite_workload']['useful_bytes'],
                           cfg['measurement_duration_ms'],cfg['delta_ms'])}
    traces = [read(root/f'replicas/node-{i}/latency-trace.json')['events'] for i in range(4)]
    if not any(e['event']=='proposal_emitted' for es in traces for e in es):
        return {**summary, 'instrumented':False}, []
    proposals, batch_events, membership = {}, {}, defaultdict(list)
    for i, events in enumerate(traces):
        selected, started = {}, {}
        for e in sorted(events, key=lambda x:x['at_us']):
            name = e['event']
            if name in ('batch_stored','batch_broadcast','batch_received','batch_queued','proof_queued'):
                batch_events.setdefault((i,raptr.batch_key(e['batch']),name),e)
            elif name == 'proposal_pull_started':
                unique(started, e['round'], e, 'leader pull')
            elif name == 'proposal_payload_selected':
                unique(selected, e['round'], e, 'leader payload')
            elif name == 'proposal_emitted':
                block = raptr.block_key(e)
                s, p = selected[e['round']], started[e['round']]
                require(p['at_us'] <= s['at_us'] <= e['at_us'], 'reversed leader timestamps')
                unique(proposals, block, (i,p,s,e), 'emitted block')
                keys = [raptr.batch_key(b) for b in s['batches']]
                require(0 <= s['proof_count'] <= len(keys) and len(set(keys)) == len(keys),
                        'invalid proposal membership')
                for index,key in enumerate(keys):
                    membership[key].append((block,index < s['proof_count']))
    rows = []
    for i,events in enumerate(traces):
        directory = root/f'replicas/node-{i}'
        accepts = raptr.indexes(events)[1]
        # If any earlier accepted digest lacks its author's emitted membership,
        # earliest-inclusion attribution cannot be made safely for a later request.
        unknown = min((t for block,t in accepts.items() if block not in proposals), default=float('inf'))
        own = {}
        for out in journal(directory/'output.jsonl'):
            for batch in out['batches']:
                for tx in batch['transactions']:
                    if tx['own_credit']:
                        unique(own,tx['request_id'],(raptr.block_key(out['block']),raptr.batch_key(batch['key'])),
                               'credited request')
        receipt=read(directory/'final.json')['body']
        epoch, duration = receipt['epoch_us'], cfg['measurement_duration_ms']*1000
        for req in journal(directory/'requests.jsonl',max_line=16384):
            if not epoch <= req['planned_us'] < epoch+duration:
                continue
            execution,key = own[req['request_id']]
            require(execution in {b for b,_ in membership[key]}, 'executed batch lacks emitted block membership')
            first,block,proof = min((accepts[b],b,isproof) for b,isproof in membership[key] if b in accepts)
            require(first < unknown, 'earlier accepted block lacks membership')
            leader,pull,selection,emit = proposals[block]
            get = lambda label: batch_events.get((leader,key,label))
            received, queued, poa = get('batch_received'), get('batch_queued'), get('proof_queued')
            eligible = None
            if proof and poa:
                eligible = poa['at_us']
            elif not proof and queued and pull['minimum_batch_age_us'] is not None:
                # Native QS age uses real-time creation age. Remaining age when
                # queued is converted to a local duration on the monotonic clock.
                age = queued['observer_wall_us'] - queued['creation_wall_us']
                eligible = queued['at_us'] + max(0,pull['minimum_batch_age_us']-age)
            admitted = req['admitted_us']
            stored = batch_events[i,key,'batch_stored']['at_us']
            broadcast = batch_events[i,key,'batch_broadcast']['at_us']
            require(admitted <= stored <= first <= accepts[execution] and admitted <= broadcast <= first,
                    'Raptr origin timing differs from its inclusion data')
            rows.append({'protocol':'raptr','origin':i,'sequence':req['sequence'],'batch':key,
                         'execution_round':execution[0],'first_local_round':block[0],'leader':leader,
                         'admitted_us':admitted,'seal_us':stored,'broadcast_us':broadcast,'first_accept_us':first,
                         'output_us':req['first_materialized_us'],
                         'first_local_emit_leader_us':emit['at_us'],'batching_us':stored-admitted,
                         'admit_to_first_local_us':first-admitted, 'seal_to_first_local_us':first-stored,
                         'broadcast_to_first_local_us':first-broadcast,
                         'execution_midpoint_shift_us':accepts[execution]-first,
                         'selection_mode':'proof' if proof else 'optimistic',
                         'received_to_queued_leader_us':queued['at_us']-received['at_us'] if queued and received else None,
                         'eligible_to_selected_leader_us':selection['at_us']-eligible if eligible is not None else None,
                         'pull_to_selected_leader_us':selection['at_us']-pull['at_us'],
                         'selected_to_emit_leader_us':emit['at_us']-selection['at_us']})
    return {**summary, 'instrumented':True}, rows


COMMON = ('batching_us','admit_to_first_local_us','seal_to_first_local_us','execution_midpoint_shift_us')
DELUGI = ('fixed_schedule_base_proof_shift_us','fixed_schedule_insufficient_observations_shift_us',
          'report_to_pool_leader_us','pool_to_constructed_leader_us','constructed_to_emit_leader_us',
          'seal_to_report_self_leader_us')
RAPTR = ('broadcast_to_first_local_us','received_to_queued_leader_us','eligible_to_selected_leader_us',
         'pull_to_selected_leader_us','selected_to_emit_leader_us')


def compare(droot, rroot):
    d, dr = delugi_trial(droot)
    r, rr = raptr_trial(rroot)
    require(d['workload'] == r['workload'], 'offered rate/useful bytes/duration/configured bound differ')
    for result, rows, fields in [(d,dr,DELUGI),(r,rr,RAPTR)]:
        if result['instrumented']:
            require(len(rows) == result['validation']['covered'], 'request cohort differs from verified cohort')
            result['stages'] = summarize(rows, COMMON+fields)
            result['by_origin'] = {str(i):summarize([x for x in rows if x['origin']==i],COMMON+fields)
                                   for i in range(4)}
    report = {'delugi':d,'raptr':r,'comparison':{
        'execution_associated_admission_to_accept_gap_ms':d['execution_associated_admission_to_accept_ms']-r['execution_associated_admission_to_accept_ms']},
        'clock':'All differences use timestamps from a single process. Locally accepted inclusion includes proposal transit.',
        'population':'Healthy four-validator runs, one request-weighted cohort per protocol. Workload order: aggregate tx/s, useful bytes, measured ms, configured delay-bound ms.',
        'interpretation':[
            'Only producer-as-leader requests contribute to seal-to-REPORT on a single clock. Signed times can be negative when the productive REPORT opens before the batch. This subset need not represent all origins or leaders.',
            'A Delugi proposal includes a batch if the selected target covers its unique producer height on this healthy, fork-free chain. The earliest locally accepted such proposal can differ from the first one to execute.',
            'The base-proof counterfactual asks for the earliest actually accepted proposal whose leader could prove a local candidate covering the batch at construction, waiving witness requirements. It freezes actual proposal times, bases and origin acceptance times.',
            'The insufficient-observations variant allows substitution only when a covering candidate had a base proof and fewer than two frozen observations reached the batch height. These paired weights measure timing on the fixed observed schedule and do not predict a changed protocol or establish causal attribution.',
            'Own-observation residuals measure the opportunity schedule; the origin need not be a selected witness. Leader-local spans are diagnostics that can overlap the origin intervals.',
            'Raptr eligibility time is the observed queue time of the selected proof or optimistic batch, with native minimum creation age applied for optimistic selection. Exclusions, author limits and work deadlines may delay selection further.']}
    if dr and rr:
        c=report['comparison']
        gap = d['stages']['admit_to_first_local']['mean_ms']-r['stages']['admit_to_first_local']['mean_ms']
        c['first_local_admission_to_accept_gap_ms'] = gap
        c['batching_gap_ms'] = d['stages']['batching']['mean_ms']-r['stages']['batching']['mean_ms']
        for field in DELUGI[:2]:
            shift=d['stages'][field.removesuffix('_us')]['mean_ms']
            c[field.removesuffix('_us')+'_ms']=shift
            c['gap_after_'+field.removesuffix('_us')+'_ms'] = gap-shift
        r['selection_modes'] = dict(Counter(x['selection_mode'] for x in rr))
    return report, dr+rr


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--delugi',type=Path,required=True)
    p.add_argument('--raptr',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--rows',type=Path)
    args=p.parse_args()
    report,rows=compare(args.delugi,args.raptr)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    if args.rows:
        args.rows.parent.mkdir(parents=True,exist_ok=True)
        with args.rows.open('w') as out:
            for row in rows:
                out.write(json.dumps(row,separators=(',',':'))+'\n')
    print(json.dumps(report['comparison'],indent=2))


if __name__=='__main__':
    main()
