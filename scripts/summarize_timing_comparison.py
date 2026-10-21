#!/usr/bin/env python3
"""Archive a finished timing matrix without selecting or dropping attempts."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from run_comparison import ROOT, aggregate, sha256, validate_comparison, validate_timing, configured_bound


def summarize(path):
    path = path.resolve()
    matrix = json.loads(path.read_text())
    if matrix['status'] not in {'passed', 'failed'}:
        raise ValueError('The matrix must be finished before summarizing')
    settings = matrix['settings']
    trials = []
    for row in matrix['trials']:
        trial = dict(row)
        if 'manifest' in row:
            raw = ROOT / row['manifest']['path']
            if sha256(raw) != row['manifest']['sha256']:
                raise ValueError(f'Raw manifest hash changed: {raw}')
            data = json.loads(raw.read_text())
            if row['status'] == 'passed':
                formal = row['comparison'].get('comparison_contract') == 'exact_materialization_cohorts_v1'
                expected = validate_comparison(data, row['protocol'], row['rate'],
                    settings.get('serialized_transaction_bytes'), settings['warmup_seconds'],
                    settings['measurement_seconds'], settings['ingress_batch_ms'],
                    useful_bytes=settings.get('useful_transaction_bytes') if formal else None,
                    require_cohorts=formal, replicas=settings['replicas'])
                if any(expected.get(key) != value for key, value in row['comparison'].items()):
                    raise ValueError('Stored matrix metrics differ from raw manifest')
                if matrix.get('calibration_before'):
                    validate_timing(data, row['protocol'], settings['one_way_network_delay_ms'],
                        settings['bound_ms'], matrix['calibration_before']['shaping']['helper_sha256'])
                elif settings.get('bound_ms') is not None and configured_bound(data, row['protocol']) != settings['bound_ms']:
                    raise ValueError('Stored configured bound differs from native manifest')
                if row['protocol'] == 'delugi':
                    trial['agreement'] = data['trial']['agreement']
                    trial['drain_seconds'] = data['trial']['drain_seconds']
                    trial['global_pending_by_replica'] = data['trial']['global_pending_by_replica']
                trial['raw_manifest_verified'] = True
        trials.append(trial)
    actual = aggregate(trials)
    if len(actual) != len(matrix['aggregate']) or any(
            any(new.get(key) != value for key, value in old.items())
            for old, new in zip(matrix['aggregate'], actual)):
        # Older aggregate schemas did not normalize native resource_cost keys.
        old_without_cost = [{k:v for k,v in row.items() if k != 'window_resource_ratios'} for row in matrix['aggregate']]
        if len(actual) != len(old_without_cost) or any(any(new.get(k) != v for k,v in old.items()) for old,new in zip(old_without_cost,actual)):
            raise ValueError('Aggregate differs from recomputation across all successful trials')
    return {
        'schema': 1, 'date': datetime.fromtimestamp(matrix['started_unix_ns'] / 1e9, timezone.utc).date().isoformat(), 'status': matrix['status'],
        'classification': matrix['classification'], 'settings': settings,
        'machine': matrix['machine'], 'measurement_boundaries': matrix['measurement_boundaries'],
        'artifact_identities': matrix['artifact_identities'],
        'source_manifest': {'path': str(path.relative_to(ROOT)), 'sha256': sha256(path)},
        'calibration_before': matrix.get('calibration_before'),
        'calibration_after': matrix.get('calibration_after'),
        'trials': trials, 'aggregate': actual,
        'valid_trials': sum(row['status'] == 'passed' for row in trials),
        'failed_attempts': sum(row['status'] == 'failed' for row in trials),
        'network_scope': (f"Nominal {settings['one_way_network_delay_ms']} ms scoped outbound kernel delay; before/after echo RTT calibration retained. Stream-write traffic excludes kernel retransmissions and TCP/IP headers."
                          if matrix.get('calibration_before') else "Unshaped localhost TCP; added delay 0, physical/queue delay is measured rather than assumed zero. This is not a delta=10ms experiment."),
        'counterpart_scope': 'Four independent replica processes. Native internal batching, worker counts, cryptography, storage and latency start/end semantics remain recorded implementation differences. Mysticeti uses explicit leader-readiness timeout T=Delta.',
        'validation': 'Every raw child-manifest SHA verified; successful trial metrics and timing evidence revalidated; aggregate recomputed without omitting failed attempts.',
    }

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = summarize(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(json.dumps({'output': str(args.output), 'valid_trials': result['valid_trials'], 'failed_attempts': result['failed_attempts']}))
