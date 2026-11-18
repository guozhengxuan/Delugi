#!/usr/bin/env python3
"""Clock-calibrated WAN phase measurements for the healthy four-replica trial pair."""
import argparse
from bisect import bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from functools import lru_cache
from math import fsum
import hashlib
import json
from pathlib import Path
from statistics import fmean

import phase_delta_comparison as phase

# Linux's NTP frequency correction range. This also states the assumed maximum
# UTC rate error between probes. The intervals are conditional on the kernel's
# reported maximum error, bounded drift and absence of undetected clock steps.
PPM = 500
MAX_GAP_US = 30_000_000
STEP_TOL_US = 50


@dataclass(frozen=True)
class Span:
    lo: float
    est: float
    hi: float

    def minus(self, other):
        return Span(self.lo-other.hi, self.est-other.est, self.hi-other.lo)

    def millis(self):
        return [round(v/1000, 6) for v in (self.lo, self.est, self.hi)]


@dataclass(frozen=True)
class Point:
    host: int
    tick: int
    utc: Span


def elapsed(start, end):
    if start.host == end.host:
        value = end.tick-start.tick
        return Span(value, value, value)
    return end.utc.minus(start.utc)


class HostClock:
    def __init__(self, host, samples, anchor=None):
        self.host = host
        self.anchor = (0, 0)
        if anchor:
            b, e, a = (anchor[k] for k in ('before_us','elapsed_us','after_us'))
            phase.require(0 <= b <= a and e >= 0, 'invalid Delugi clock anchor')
            # Each of the native readings was truncated to an integer microsecond.
            self.anchor = (b-e-1, a-e+1)
        self.samples = []
        self.ticks = []
        segment = 0
        for row in samples:
            if ('error' in row or row.get('ntp_state') != 0 or row.get('kernel_maxerror_us', -1) < 0
                    or row['after_ns'] < row['before_ns']):
                segment += 1
                continue
            b, a, wall = (row[k]/1000 for k in ('before_ns','after_ns','wall_ns'))
            tick = (b+a)/2
            phase.require(not self.ticks or tick > self.ticks[-1], 'nonmonotonic clock probes')
            self.ticks.append(tick)
            self.samples.append((tick,wall-a,wall-b,row['kernel_maxerror_us'],segment))

    @lru_cache(maxsize=131072)
    def point(self, tick):
        # tick is either process elapsed time (Delugi) or CLOCK_MONOTONIC (Raptr).
        lo, hi = tick+self.anchor[0], tick+self.anchor[1]+1
        i = bisect_right(self.ticks, lo)-1
        phase.require(0 <= i and i+1 < len(self.ticks), f'host {self.host}: event lacks bracketing UTC probes')
        j = bisect_right(self.ticks, hi-1e-6)
        phase.require(j < len(self.samples), 'event beyond last synchronized probe')
        left, right = self.samples[i], self.samples[j]
        for p, q in zip(self.samples[i:j], self.samples[i+1:j+1]):
            phase.require(p[4] == q[4] and q[0]-p[0] <= MAX_GAP_US,
                          f'host {self.host}: failed, unsynchronized or missing clock probe')
            # Linux MONOTONIC and REALTIME receive the same slew adjustments.
            phase.require(p[1] <= q[2]+STEP_TOL_US and q[1] <= p[2]+STEP_TOL_US,
                          f'host {self.host}: wall/monotonic step between probes')
        # Project both sampled UTC tolerances to this event with independent
        # maximum drift, then intersect the two conservative envelopes.
        olo, ohi = float('-inf'),float('inf')
        for t, low, high, error, _ in (left, right):
            drift = max(abs(t-lo),abs(t-hi))*PPM/1e6+STEP_TOL_US
            olo = max(olo,low-error-drift)
            ohi = min(ohi,high+error+drift)
        phase.require(olo <= ohi,'inconsistent NTP error envelopes')
        center = (lo+hi)/2
        weight = (center-left[0])/(right[0]-left[0])
        estimate = (1-weight)*(left[1]+left[2])/2 + weight*(right[1]+right[2])/2
        offset = min(ohi,max(olo,estimate))
        return Point(self.host,tick,Span(lo+olo,center+offset,hi+ohi))


def earliest(candidates, field='emit'):
    # Later events on the same node cannot win even when UTC intervals overlap.
    by_host = {}
    for candidate in candidates:
        p = candidate[field]
        if p.host not in by_host or p.tick < by_host[p.host][field].tick:
            by_host[p.host] = candidate
    possible = list(by_host.values())
    earliest_upper = min(c[field].utc.hi for c in possible)
    possible = [c for c in possible if c[field].utc.lo <= earliest_upper]
    return min(possible,key=lambda c:(c[field].utc.est,c['round'])), possible


def envelope(metrics, best):
    return Span(min(m.lo for m in metrics), best.est, max(m.hi for m in metrics))


def to_first(start, candidates, key='emit'):
    spans = [elapsed(start,c[key]) for c in candidates]
    return Span(min(s.lo for s in spans), min(s.est for s in spans), min(s.hi for s in spans))


def next_launch(start, reports):
    durations = [elapsed(start, r) for r in reports]
    possible = [s for s in durations if s.hi >= 0]
    certain = [s for s in possible if s.lo >= 0]
    phase.require(certain, 'no subsequent REPORT captured')
    return Span(min(max(0,s.lo) for s in possible), min(s.est for s in possible if s.est >= 0),
                min(s.hi for s in certain))


class Trial:
    def __init__(self, root, protocol, samples, rows):
        self.root = root
        self.protocol = protocol
        self.rows = rows
        self.props = {}
        self.launches = []
        self.batch_recv = {}
        self.batch_queues = {}
        self.first_batch_enqueue = {}
        self.sends = {}
        self.receives = {}
        self.clocks = []
        self.by_key = defaultdict(list)
        docs = [phase.read(root/(f'causal-traces/replica-{i}.json' if protocol == 'delugi'
                           else f'replicas/node-{i}/latency-trace.json')) for i in range(4)]
        for i,d in enumerate(docs):
            phase.require(d['replica'] == i and d['dropped'] == 0,'incomplete trace')
            anchor = d['host_clock_anchor'] if protocol == 'delugi' else None
            self.clocks.append(HostClock(i,[s for s in samples if s['replica']==i],anchor))
        for i,d in enumerate(docs):
            if protocol == 'delugi':
                self.read_delugi(i, d['events'])
            else:
                self.read_raptr(i, d['events'])

    def read_delugi(self, host, events):
        pieces = defaultdict(dict)
        point = self.clocks[host].point
        for e in events:
            kind, t, r, d = e['event'], e['at_us'], e['round'], e['detail']
            if kind == 'dissemination_outbox' and d['kind'] == 'REPORT':
                pieces[r]['report'] = point(t)
                self.launches.append(point(t))
            elif kind in ('input_membership','observation_pool_fixed'):
                if kind == 'input_membership':
                    pieces[r]['input'] = d
                pieces[r]['construct' if kind == 'input_membership' else 'pool'] = point(t)
            elif kind == 'ordering_outbox' and d['kind']=='PROPOSE':
                pieces[r].update(emit=point(t), round=r)
            elif kind in ('transport_enqueue','transport_deferred_accept') and d['kind'] in (
                    'REPORT','OBS','BATCH','PROPOSE','VOTE','CER'):
                k=(d['kind'],host,d['peer'],d['sequence'],d['member_index'],r)
                if d['kind']=='BATCH':
                    k=k+(d['producer'],d['height'])
                    batch=(d['producer'],d['height'])
                    prior=self.first_batch_enqueue.get(batch,e['start_us'])
                    self.first_batch_enqueue[batch]=min(prior,e['start_us'])
                phase.unique(self.sends,k,(host,e['start_us']),'transport send')
            elif kind=='dispatch' and d['kind'] in ('REPORT','OBS','BATCH','PROPOSE','VOTE','CER') and d['mailbox_us'] is not None:
                k=(d['kind'],d['peer'],host,d['sequence'],d['member_index'],r)
                if d['kind']=='BATCH':
                    k=k+(d['producer'],d['height'])
                self.receives.setdefault((k,host),d['mailbox_us'])
        for r,c in pieces.items():
            if 'emit' in c:
                phase.unique(self.props,r,c,'Delugi round')

    def read_raptr(self, host, events):
        point = self.clocks[host].point
        pieces = defaultdict(dict)
        for e in sorted(events,key=lambda e:e['at_us']):
            n,t = e['event'],e['at_us']
            if n.startswith('batch_') or n=='proof_queued':
                key=phase.raptr.batch_key(e['batch'])
                if n in ('batch_queued','proof_queued'):
                    self.batch_queues.setdefault((host,key,n),e)
                if n=='batch_broadcast':
                    self.sends.setdefault(('BATCH',key),(host,t))
                if n=='batch_received':
                    self.batch_recv.setdefault((host,key),t)
                    self.receives.setdefault((('BATCH',key),host),t)
            elif n=='proposal_pull_started':
                pieces[e['round']].update(pull=point(t), minimum_age=e['minimum_batch_age_us'])
            elif n=='proposal_payload_selected':
                keys=[phase.raptr.batch_key(b) for b in e['batches']]
                pieces[e['round']].update(select=point(t), batches=keys, proof_keys=set(keys[:e['proof_count']]))
            elif n=='proposal_emitted':
                r, digest = phase.raptr.block_key(e)
                c=pieces[r]
                c.update(emit=point(t),round=r)
                phase.unique(self.props,r,c,'Raptr round')
                for k in c['batches']:
                    self.by_key[k].append(c)
                self.sends['PROPOSE',r,digest]=(host,t)
            elif n=='proposal_validated':
                r,digest=phase.raptr.block_key(e)
                self.receives.setdefault((('PROPOSE',r,digest),host),t)
            elif n in phase.raptr.VOTE_BOUNDARIES:
                k=(n.split('_')[0].upper()+'_VOTE',e['round'],e['digest'],e['prefix'],e['peer'])
                if n.endswith('sent'):
                    phase.require(e['peer']==host,'vote sender identity mismatch')
                    self.sends.setdefault(k,(host,t))
                else:
                    self.receives.setdefault((k,host),t)

    def request(self, row):
        i, key = row['origin'], row['batch']
        clock = self.clocks[i]
        admission = clock.point(row['admitted_us'])
        broadcast = clock.point(row.get('broadcast_us',row['seal_us']))
        first_accept=clock.point(row['first_accept_us'])
        output = clock.point(row['output_us'])
        if self.protocol=='delugi':
            h=row['height']
            options=[c for c in self.props.values() if c['input']['target_heights'][i]>=h]
        else:
            key=tuple(key)
            options=self.by_key[key]
        winner, candidates=earliest(options)
        first=to_first(broadcast,candidates)
        # Additional metrics of a specific winner vary with the cross-clock
        # rank. Preserve the widest compatible boundaries if identity is tied.
        def chosen(f):
            return envelope([f(c) for c in candidates], f(winner))
        d={'admit_to_broadcast':elapsed(admission,broadcast),
           'broadcast_to_first_emission':first,
           'admit_to_first_emission':to_first(admission,candidates),
           'first_emission_to_first_local_accept':chosen(lambda c:elapsed(c['emit'],first_accept)),
           'first_local_accept_to_output':elapsed(first_accept,output),
           'first_emission_to_output':chosen(lambda c:elapsed(c['emit'],output)),
           'admit_to_output':elapsed(admission,output)}
        if self.protocol=='delugi':
            first_send=self.first_batch_enqueue[i,h]
            phase.require(first_send>=row['seal_us'],'transport send precedes seal')
            d['seal_to_first_transport_enqueue_start']=elapsed(broadcast,clock.point(first_send))
            d.update(broadcast_to_winning_report=chosen(lambda c:elapsed(broadcast,c['report'])),
                     winning_report_to_emit=chosen(lambda c:elapsed(c['report'],c['emit'])),
                     winning_report_to_pool=chosen(lambda c:elapsed(c['report'],c['pool'])),
                     pool_to_construct=chosen(lambda c:elapsed(c['pool'],c['construct'])),
                     construct_to_emit=chosen(lambda c:elapsed(c['construct'],c['emit'])),
                     broadcast_to_next_any_report=next_launch(broadcast,self.launches))
            # A batch may inherit membership through the authenticated base.
            # Existing observed proposal times remain fixed in this calculation.
            relaxed=[c for c in self.props.values() if c['input']['target_heights'][i]<h
                     and sum(obs['heights'][i]>=h for obs in c['input']['pool'])<2
                     and any(x['producer']==i and x['height']>=h and x['base_proof']
                             for x in c['input']['candidates'])]
            d['admit_to_emit_if_insufficient_obs_waived']=to_first(admission,options+relaxed)
            if relaxed:
                waived_winner, waived_candidates=earliest(options+relaxed)
                # The common batch timestamp cancels exactly. Bound reassignment
                # directly between possible proposal emissions, preserving
                # same-replica clock correlation and the zero-shift alternative.
                shifts=[elapsed(a['emit'],b['emit']) for a in waived_candidates for b in candidates]
                shifts=[v for v in shifts if v.hi >= 0]
                phase.require(shifts, 'waived membership cannot delay earliest inclusion')
                estimate=elapsed(waived_winner['emit'],winner['emit']).est
                d['shift_if_insufficient_obs_waived']=Span(max(0,min(v.lo for v in shifts)),
                                                          max(0,estimate),max(v.hi for v in shifts))
            else:
                d['shift_if_insufficient_obs_waived']=Span(0,0,0)
        else:
            d.update(broadcast_to_winning_pull=chosen(lambda c:elapsed(broadcast,c['pull'])),
                     winning_pull_to_select=chosen(lambda c:elapsed(c['pull'],c['select'])),
                     select_to_emit=chosen(lambda c:elapsed(c['select'],c['emit'])))
            def received(c):
                host=c['emit'].host
                if host==i:
                    # Origin retained payload before multicast; this is the
                    # local zero-network path, not QS loopback consumption.
                    return broadcast
                tick=self.batch_recv.get((host,key))
                return self.clocks[host].point(tick) if tick is not None else None
            def queue_ready(c):
                host=c['emit'].host
                if key in c['proof_keys']:
                    q=self.batch_queues.get((host,key,'proof_queued'))
                    return self.clocks[host].point(q['at_us']) if q else None
                q=self.batch_queues.get((host,key,'batch_queued'))
                if not q or c['minimum_age'] is None:
                    return None
                remaining=max(0,c['minimum_age']-(q['observer_wall_us']-q['creation_wall_us']))
                return self.clocks[host].point(q['at_us']+remaining)
            if all(queue_ready(c) is not None for c in candidates):
                d.update(broadcast_to_winner_queue_age_ready=chosen(lambda c:elapsed(broadcast,queue_ready(c))),
                         winner_queue_age_ready_to_select=chosen(lambda c:elapsed(queue_ready(c),c['select'])))
            if all(received(c) is not None for c in candidates):
                d.update(broadcast_to_winner_payload=chosen(lambda c:elapsed(broadcast,received(c))),
                         winner_payload_to_pull=chosen(lambda c:elapsed(received(c),c['pull'])))
        phase.require(first.hi>=0,'inclusion before broadcast outside calibration uncertainty')
        return {'origin':i,'sequence':row['sequence'],'batch':key,'winner_estimate':winner['round'],
                'possible_rounds':[c['round'] for c in candidates]}, d

    def links(self, keep_pairs=False):
        pairs=[]
        out=defaultdict(list)
        missing=Counter()
        for (key,dest),tick in self.receives.items():
            if key not in self.sends:
                missing[key[0]]+=1
                continue
            host,t=self.sends[key]
            if host==dest:
                continue
            span=elapsed(self.clocks[host].point(t),self.clocks[dest].point(tick))
            phase.require(span.hi>=0,f'{key[0]} arrival predates send outside clock bounds')
            out[key[0],host,dest].append(span)
            if keep_pairs:
                pairs.append({'protocol':self.protocol,'kind':key[0],'join_key':key,
                              'sender':host,'sender_tick_us':t,'recipient':dest,
                              'recipient_tick_us':tick,'duration_ms':span.millis()})
        return {f'{k}/{a}->{b}':summarize(v) for (k,a,b),v in sorted(out.items())},dict(missing),pairs


def summarize(spans):
    return {'count':len(spans),'mean_ms':Span(*(fmean(getattr(s,k) for s in spans)
                                              for k in ('lo','est','hi'))).millis()}


def paired_clock_mean(pairs):
    """Bound the mean cross-host elapsed time without treating clock offsets as independent.

    A sum is invariant under reordering. Pair a positive endpoint with a negative
    endpoint from the same host, even if they belong to different requests.
    The unknown common UTC offset cancels. The remaining difference between UTC
    elapsed and host monotonic elapsed is bounded by our rate assumption over the
    matched time span. Unmatched endpoints retain their full NTP envelopes.
    """
    plus, minus = defaultdict(list), defaultdict(list)
    terms = []
    matched_cross_host_endpoints = {}
    for sent, emitted in pairs:
        if sent.host == emitted.host:
            direct = elapsed(sent, emitted)
            rate_error = abs(direct.est)*PPM/1e6 + 2
            terms.append(Span(direct.lo-rate_error, direct.est, direct.hi+rate_error))
        else:
            plus[emitted.host].append(emitted)
            minus[sent.host].append(sent)
    # Subtract one arbitrary constant before summing UTC values. There are
    # equally many positive and negative endpoints overall.
    ref = pairs[0][0].utc.est
    reference = Span(ref, ref, ref)
    for host in sorted(set(plus) | set(minus)):
        positive = sorted(plus[host], key=lambda p: p.tick)
        negative = sorted(minus[host], key=lambda p: p.tick)
        n = min(len(positive), len(negative))
        matched_positive, matched_negative = set(), set()
        for k in range(n):
            # Match by empirical time quantile. This minimizes the temporal
            # separation when the two populations have similar time coverage.
            a = (2*k+1)*len(positive)//(2*n)
            b = (2*k+1)*len(negative)//(2*n)
            matched_positive.add(a)
            matched_negative.add(b)
            end, start = positive[a], negative[b]
            delta = end.tick - start.tick
            tolerance = abs(delta)*PPM/1e6 + 2  # two integer microsecond readings
            individual = end.utc.minus(start.utc)
            lower = max(individual.lo, delta-tolerance)
            upper = min(individual.hi, delta+tolerance)
            phase.require(lower <= upper, 'paired UTC and rate envelopes disagree')
            terms.append(Span(lower, individual.est, upper))
        phase.require(len(matched_positive) == len(matched_negative) == n, 'duplicate endpoint pairing')
        terms.extend(p.utc.minus(reference) for j,p in enumerate(positive) if j not in matched_positive)
        terms.extend(reference.minus(p.utc) for j,p in enumerate(negative) if j not in matched_negative)
        matched_cross_host_endpoints[host] = {'paired': n, 'unpaired_positive': len(positive)-n,
                                               'unpaired_negative': len(negative)-n}
    result = Span(*(fsum(getattr(s,k) for s in terms)/len(pairs) for k in ('lo','est','hi')))
    independent = Span(*(fmean(getattr(elapsed(a,b),k) for a,b in pairs) for k in ('lo','est','hi')))
    phase.require(abs(result.est-independent.est)<1, 'mean changed under reassociation')
    return {'count':len(pairs), 'mean_ms':result.millis(),
            'endpoints_by_host':matched_cross_host_endpoints}


def launch_residual(launches, loads):
    # Irregular-interval renewal expectation for the observed schedule, clipped
    # exactly to the load period. Calendar values here are calibrated centers.
    times=sorted(p.utc.est for p in launches)
    a,b=min(loads),max(loads)
    phase.require(times[0] <= a < b <= times[-1], 'REPORT schedule does not cover measurements')
    area=0
    gaps=[]
    for x,y in zip(times,times[1:]):
        left,right=max(a,x),min(b,y)
        if right<=left:
            continue
        area+=((y-left)**2-(y-right)**2)/2
        if a<=x<y<=b:
            gaps.append(y-x)
    return {'uniform_time_residual_ms_at_estimated_utc':area/(b-a)/1000,
            'half_mean_gap_ms_at_estimated_utc':fmean(gaps)/2000 if gaps else None,
            'complete_intervals':len(gaps)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('delugi','raptr','clock_samples','output'):
        p.add_argument('--'+name.replace('_','-'),dest=name,type=Path,required=True)
    p.add_argument('--rows',type=Path)
    p.add_argument('--message-rows',type=Path)
    args=p.parse_args()
    sample_bytes=args.clock_samples.read_bytes()
    samples=[json.loads(l) for l in sample_bytes.splitlines()]
    report, all_rows, message_rows={},[],[]
    source_report,rows=phase.compare(args.delugi,args.raptr)
    for protocol in ('delugi','raptr'):
        cohort=[r for r in rows if r['protocol']==protocol]
        phase.require(cohort and len(cohort)==source_report[protocol]['validation']['covered'],'healthy cohort validation failed')
        trial=Trial(getattr(args,protocol),protocol,samples,cohort)
        metrics=defaultdict(list)
        ambiguous=0
        raptr_pairs=[]
        residuals=defaultdict(list)
        for row in cohort:
            header, stages=trial.request(row)
            if protocol=='raptr' and len(header['possible_rounds'])==1:
                broadcast=trial.clocks[row['origin']].point(row['broadcast_us'])
                raptr_pairs.append((broadcast,trial.props[header['winner_estimate']]['emit']))
            # Same-host legs use exact monotonic differences while calibrated
            # centers interpolate UTC. Record the sub-probe conversion residual
            # and verify the propagated bounds cover each independently joined sum.
            groups={
                'admit_to_output':('admit_to_broadcast','broadcast_to_first_emission',
                                   'first_emission_to_first_local_accept','first_local_accept_to_output'),
                'broadcast_to_first_emission':(
                    ('broadcast_to_winning_report','winning_report_to_pool','pool_to_construct','construct_to_emit')
                    if protocol=='delugi' else
                    ('broadcast_to_winning_pull','winning_pull_to_select','select_to_emit'))}
            for whole,parts in groups.items():
                if not all(k in stages for k in parts):
                    continue
                low=sum(stages[k].lo for k in parts)
                high=sum(stages[k].hi for k in parts)
                total=stages[whole]
                phase.require(low <= total.hi+2 and high >= total.lo-2,'decomposition bounds inconsistent')
                residuals[whole].append(sum(stages[k].est for k in parts)-total.est)
            ambiguous+=len(header['possible_rounds'])>1
            for k,v in stages.items():
                metrics[k].append(v)
            all_rows.append(dict(protocol=protocol,**header,stages_ms={k:v.millis() for k,v in stages.items()}))
        links,missing,pairs=trial.links(keep_pairs=args.message_rows is not None)
        message_rows.extend(pairs)
        report[protocol]={'requests':len(cohort),'ambiguous_first_proposer_requests':ambiguous,
                          'stages':{k:summarize(v) for k,v in metrics.items()},
                          'paired_remote_message_legs':links,'unpaired_receives':missing,
                          'center_closure_residual_us':{
                              k:{'mean':fmean(v),'max_abs':max(map(abs,v))} for k,v in residuals.items()}}
        if protocol=='raptr' and len(raptr_pairs)==len(cohort):
            report[protocol]['broadcast_to_first_emission_paired_clock_mean']=paired_clock_mean(raptr_pairs)
        if protocol=='delugi':
            starts=[trial.clocks[r['origin']].point(r['seal_us']).utc for r in cohort]
            # All these launches lie in the load interval under every admissible
            # ordering. Total covered time divided by at least n-1 gaps bounds
            # the mean duration of a complete inter-launch gap.
            certain=sum(min(s.hi for s in starts)<=p.utc.lo and p.utc.hi<=max(s.lo for s in starts)
                        for p in trial.launches)
            window_upper=max(s.hi for s in starts)-min(s.lo for s in starts)
            phase.require(certain>1,'too few in-window launches for cadence bound')
            loads=[trial.clocks[r['origin']].point(r['seal_us']).utc.est for r in cohort]
            report[protocol]['report_schedule']=launch_residual(trial.launches,loads)
            report[protocol]['report_schedule'].update(certainly_in_window_launches=certain,
                window_duration_upper_ms=window_upper/1000,
                half_mean_complete_interval_upper_ms=window_upper/(2*(certain-1))/1000)
            waits=metrics['broadcast_to_winning_report']
            report[protocol]['winning_report_vs_broadcast']={
                'definitely_before':sum(x.hi<0 for x in waits),
                'definitely_after':sum(x.lo>0 for x in waits),
                'uncertain_or_simultaneous':sum(x.lo<=0<=x.hi for x in waits),
                'before_at_center_estimate':sum(x.est<0 for x in waits)}
    report['comparison_ms']={}
    for k in ('admit_to_broadcast','broadcast_to_first_emission','admit_to_first_emission','first_emission_to_output','admit_to_output'):
        d=Span(*report['delugi']['stages'][k]['mean_ms'])
        r=Span(*report['raptr']['stages'][k]['mean_ms'])
        report['comparison_ms'][k]=list(vars(d.minus(r)).values())
    # Cancel the shared Delugi broadcast and winning REPORT boundaries before
    # computing uncertainty. The remaining Delugi interval is on one leader.
    report_emit=Span(*report['delugi']['stages']['winning_report_to_emit']['mean_ms'])
    raptr_emit=Span(*report['raptr']['stages']['broadcast_to_first_emission']['mean_ms'])
    residual=report_emit.minus(raptr_emit)
    report['comparison_ms']['broadcast_to_emit_gap_minus_winning_report_phase']=list(vars(residual).values())
    batching=Span(*report['comparison_ms']['admit_to_broadcast'])
    report['comparison_ms']['admit_to_emit_gap_minus_winning_report_phase']=[
        residual.lo+batching.lo,residual.est+batching.est,residual.hi+batching.hi]
    if 'broadcast_to_first_emission_paired_clock_mean' in report['raptr']:
        rpaired=Span(*report['raptr']['broadcast_to_first_emission_paired_clock_mean']['mean_ms'])
        # Subtracting two remote intervals leaves a within-leader elapsed
        # time in UTC. Allow rate uncertainty when replacing it with the
        # leader's measured MONOTONIC duration (milliseconds here). Apply
        # the same conservative allowance to both batching intervals.
        lead_error_ms=max(abs(report_emit.lo),abs(report_emit.hi))*PPM/1e6+.002
        lead_utc=Span(report_emit.lo-lead_error_ms, report_emit.est, report_emit.hi+lead_error_ms)
        tighter=lead_utc.minus(rpaired)
        batching_error_ms=sum(report[n]['stages']['admit_to_broadcast']['mean_ms'][2]*PPM/1e6+.002
                              for n in ('delugi','raptr'))
        report['comparison_ms']['broadcast_to_emit_gap_minus_winning_report_phase_paired_clocks']=list(vars(tighter).values())
        report['comparison_ms']['admit_to_emit_gap_minus_winning_report_phase_paired_clocks']=[
            tighter.lo+batching.lo-batching_error_ms,tighter.est+batching.est,tighter.hi+batching.hi+batching_error_ms]
        report['local_duration_to_utc_allowance_ms']={'report_to_emit':lead_error_ms,'both_batching_legs':batching_error_ms}
    observed_phase=Span(*report['delugi']['stages']['broadcast_to_winning_report']['mean_ms'])
    raw_gap=Span(*report['comparison_ms']['broadcast_to_first_emission'])
    report['cancellation_estimate_residual_us']=(raw_gap.est-observed_phase.est-residual.est)*1000
    adjusted=Span(*report['delugi']['stages']['admit_to_emit_if_insufficient_obs_waived']['mean_ms'])
    observed_raptr=Span(*report['raptr']['stages']['admit_to_first_emission']['mean_ms'])
    report['comparison_ms']['admit_to_first_emission_if_insufficient_obs_waived']=list(vars(adjusted.minus(observed_raptr)).values())
    report['calibration']={'samples_sha256':hashlib.sha256(sample_bytes).hexdigest(),
                           'max_probe_gap_us':MAX_GAP_US,'maximum_assumed_drift_ppm':PPM,
                           'per_probe_step_tolerance_us':STEP_TOL_US,'hosts':{}}
    for i in range(4):
        host_samples=[x for x in samples if x['replica']==i and x.get('ntp_state')==0]
        errors=[x['kernel_maxerror_us'] for x in host_samples]
        report['calibration']['hosts'][i]={'synchronized_samples':len(host_samples),
                                          'kernel_maxerror_us_min':min(errors),
                                          'kernel_maxerror_us_max':max(errors)}
    report['bounds']='All three-valued durations are [lower, central estimate, upper]. Signed cross-host intervals include kernel maxerror, probe read width, per-process anchor uncertainty and assumed <=500 ppm drift. Bounds condition on synchronized Linux kernel time and no unseen clock steps. Same-host differences use the original monotonic clock. Message legs include protocol processing up to their recorded endpoints.'
    report['endpoints']={'delugi':'BATCH transport send start to peer mailbox (all), REPORT/OBS/PROPOSE/VOTE/CER transport send start to matching peer mailbox (sampled) by frame sequence/member. Request broadcast boundary is batch seal immediately before core BATCH effect.',
                         'raptr':'Native batch multicast call to validated QS receipt; consensus multicast call to verified protocol receive/retention. Winner-local payload arrival is the broadcast timestamp for an originating leader; for foreign payloads it is the native QS receipt if observed.'}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    for path, records in ((args.rows, all_rows), (args.message_rows, message_rows)):
        if path:
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('w') as f:
                for row in records:
                    f.write(json.dumps(row,separators=(',',':'))+'\n')


if __name__=='__main__':
    main()
