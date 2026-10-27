"""Expose native traffic boundaries without equating different service stacks."""
from __future__ import annotations


def count(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or int(value) != value:
        raise ValueError('nonnegative integral byte counter required')
    return int(value)


def normalize(protocol, result):
    missing={'traffic_measurement_written_bytes':None,'traffic_sampled_total_written_bytes':None,
             'traffic_window_quality':'unavailable','traffic_boundary':'not supplied by this result'}
    if protocol=='delugi':
        c=result.get('comparison',{})
        if c.get('replica_tcp_written_bytes') is None:return missing
        return {'traffic_measurement_written_bytes':count(c['replica_tcp_written_bytes']),
                'traffic_sampled_total_written_bytes':count(result['total_run_tcp_written_bytes']) if 'total_run_tcp_written_bytes' in result else None,
                'traffic_window_quality':'sampled host-local boundaries; inspect per-replica timestamps',
                'traffic_boundary':c['traffic_boundary']}
    if protocol=='raptr':
        rows=list(result.get('reduction',result).get('traffic',{}).values())
        if not rows or not all(r.get('available') for r in rows):return missing
        return {'traffic_measurement_written_bytes':sum(count(r['measurement']['written_bytes']) for r in rows),
                'traffic_sampled_total_written_bytes':sum(count(r['through_shutdown']['written_bytes']) for r in rows),
                'traffic_window_quality':'within native sample tolerance' if all(r['window_aligned'] for r in rows) else 'late native boundary samples',
                'traffic_boundary':'successful replica TCP writes; correct replicas, paused leader contributes no measurement-window writes'}
    states=[r['result'] for r in result.get('hosts',{}).values() if 'result' in r]
    if not states:return missing
    active=[r for r in states if not r.get('cohort_excluded')]
    if not active or any('traffic' not in r for r in active):return missing
    measured=total=0
    for state in active:
        t=state['traffic']
        if protocol=='mysticeti-c':
            if not t.get('before') or not t.get('after'):return missing
            before=count(t['before']['values']['benchmark_tcp_written_bytes'])
            after=count(t['after']['values']['benchmark_tcp_written_bytes'])
            final=count(t['final']['values']['benchmark_tcp_written_bytes'])
            if not before<=after<=final:raise ValueError('native traffic counters regressed')
            measured+=after-before;total+=final
        elif protocol=='autobahn' or protocol.startswith('simpleit-'):
            counters=t['processes'] if protocol=='autobahn' else [t['counters']]
            for row in counters:
                window=count(row['window_written_bytes']);final=count(row['written_bytes'])
                if window>final:raise ValueError('window traffic exceeds sampled total')
                measured+=window;total+=final
        else:return missing
    return {'traffic_measurement_written_bytes':measured,'traffic_sampled_total_written_bytes':total,
            'traffic_window_quality':('sampled host-local scrape boundaries' if protocol=='mysticeti-c'
                                      else 'native per-operation window filtering'),
            'traffic_boundary':active[0]['traffic']['boundary']}
