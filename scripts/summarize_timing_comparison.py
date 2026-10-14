#!/usr/bin/env python3
"""Archive a finished timing matrix without selecting or dropping attempts."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from run_comparison import ROOT, aggregate, sha256, validate_comparison, validate_timing


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
                expected = validate_comparison(data, row['protocol'], row['rate'],
                    settings['serialized_transaction_bytes'], settings['warmup_seconds'],
                    settings['measurement_seconds'], settings['ingress_batch_ms'])
                if expected != row['comparison']:
                    raise ValueError('Stored matrix metrics differ from raw manifest')
                validate_timing(data, row['protocol'], settings['one_way_network_delay_ms'],
                    settings['bound_ms'], matrix['calibration_before']['shaping']['helper_sha256'])
                if row['protocol'] == 'delugi':
                    trial['agreement'] = data['trial']['agreement']
                    trial['drain_seconds'] = data['trial']['drain_seconds']
                    trial['global_pending_by_replica'] = data['trial']['global_pending_by_replica']
                trial['raw_manifest_verified'] = True
        trials.append(trial)
    actual = aggregate(trials)
    if actual != matrix['aggregate']:
        raise ValueError('Aggregate differs from recomputation across all successful trials')
    return {
        'schema': 1, 'date': datetime.fromtimestamp(matrix['started_unix_ns'] / 1e9, timezone.utc).date().isoformat(), 'status': matrix['status'],
        'classification': matrix['classification'], 'settings': settings,
        'machine': matrix['machine'], 'measurement_boundaries': matrix['measurement_boundaries'],
        'artifact_identities': matrix['artifact_identities'],
        'source_manifest': {'path': str(path.relative_to(ROOT)), 'sha256': sha256(path)},
        'calibration_before': matrix['calibration_before'],
        'calibration_after': matrix.get('calibration_after'),
        'trials': trials, 'aggregate': actual,
        'valid_trials': sum(row['status'] == 'passed' for row in trials),
        'failed_attempts': sum(row['status'] == 'failed' for row in trials),
        'network_scope': f"Nominal {settings['one_way_network_delay_ms']} ms outbound lo0 dummynet delay on both directions of selected replica TCP connections; no bandwidth cap;100-slot per-flow droptail queues. Echo RTT calibrated before/after. Native dnctl flow statistics are malformed on this host and do not establish zero drops. Application stream-write traffic excludes kernel retransmissions and TCP/IP headers.",
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
