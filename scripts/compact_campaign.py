"""Strict, offline contract for the author-selected one-minute campaign.

The plan describes workloads and source identities. It is not a qualification
receipt, and never imports an SDK, contacts hosts, or provisions resources.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import random

import spec_provenance

KIND = 'delugi-compact-campaign-v1'
PROTOCOLS = ('delugi', 'raptr', 'simpleit-mempool', 'simpleit-dispersed', 'autobahn', 'mysticeti-c')
UPSTREAMS = {
    'delugi': None,
    'raptr': ('https://github.com/aptos-labs/aptos-core.git', 'a4c98047cf8aeae3571168d02fb7e343140d2948'),
    'simpleit-mempool': ('https://github.com/qyu100/Simple-IT.git', 'e9235246880486439265cf86f13fae0ed99e62c0'),
    'simpleit-dispersed': ('https://github.com/qyu100/Simple-IT.git', 'ad8935a9e989bdfd113a8c136f9b5d0011038931'),
    'autobahn': ('https://github.com/neilgiri/autobahn-artifact.git', '6d77e0307e9dc09cc8def2c846a20523646ab4de'),
    'mysticeti-c': ('https://github.com/asonnino/mysticeti.git', '96fd83154bb5e168def9a81ee8f3e90e94e46a2e'),
}
FIELDS = {'schema', 'kind', 'protocols', 'committees', 'useful_transaction_bytes',
          'total_honest_input_tps', 'duration', 'network', 'timing', 'batching',
          'proposal_budget', 'repeats', 'supplemental_points_or_reruns_per_curve',
          'seed', 'fault_cases', 'specification', 'protocol_options'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def fields(value, required, label):
    if not isinstance(value, dict) or set(value) != set(required):
        raise ValueError(f'{label} requires exactly {sorted(required)}')


def integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{label} must be an integer in {low}..{high}')
    return value


def validate(config):
    fields(config, FIELDS, 'campaign')
    if config['schema'] != 1 or type(config['schema']) is not int or config['kind'] != KIND:
        raise ValueError('unsupported compact campaign schema/kind')
    protocols = config['protocols']
    if (not isinstance(protocols, list) or not protocols or
            any(not isinstance(p, str) or p not in PROTOCOLS for p in protocols) or
            len(set(protocols)) != len(protocols)):
        raise ValueError('choose distinct principal protocol implementations')
    committees = config['committees']
    if (not isinstance(committees, list) or not committees or
            any(type(n) is not int or n not in (10, 50) for n in committees) or
            len(set(committees)) != len(committees)):
        raise ValueError('formal committee sizes are exactly 10 and/or 50')
    rates = config['total_honest_input_tps']
    if not isinstance(rates, list) or not 1 <= len(rates) <= 6:
        raise ValueError('initial coarse sweep contains at most six rates')
    for rate in rates:
        integer(rate, 1, 80_000, 'total honest tx/s')
    if rates != sorted(set(rates)):
        raise ValueError('load rates must be unique and increasing')
    integer(config['useful_transaction_bytes'], 1, 4096, 'useful transaction bytes')
    fields(config['duration'], ('warmup_s', 'measure_s', 'drain_s'), 'duration')
    for key, value in config['duration'].items():
        integer(value, 0, 60, key)
    if config['duration']['warmup_s'] != 0 or config['duration']['measure_s'] != 60 or config['duration']['drain_s'] > 15:
        raise ValueError('compact run requires 60s measurement, no offered warmup, and at most 15s drain')
    integer(config['repeats'], 1, 1, 'default repeats')
    integer(config['supplemental_points_or_reruns_per_curve'], 0, 2, 'supplemental allowance')
    integer(config['seed'], 0, 2**32 - 1, 'seed')
    fields(config['network'], ('added_one_way_delay_ms', 'validator_egress_mbps'), 'network')
    integer(config['network']['added_one_way_delay_ms'], 0, 1000, 'added one-way delay')
    integer(config['network']['validator_egress_mbps'], 1, 1000, 'aggregate validator egress')
    fields(config['timing'], ('Delta_ms', 'mapping'), 'timing')
    integer(config['timing']['Delta_ms'], 1, 60_000, 'Delta')
    if config['timing']['mapping'] != 'native_reviewed':
        raise ValueError('native timeout relationships must be retained')
    fields(config['batching'], ('useful_bytes_target', 'max_wait_ms'), 'batching')
    if config['batching']['useful_bytes_target'] is not None:
        integer(config['batching']['useful_bytes_target'], 1, 16*1024**2, 'batch useful bytes')
    if config['batching']['max_wait_ms'] is not None:
        integer(config['batching']['max_wait_ms'], 1, 60_000, 'batch maximum wait')
    fields(config['proposal_budget'], ('useful_bytes', 'max_payload_refs'), 'proposal budget')
    if config['proposal_budget']['useful_bytes'] is not None:
        integer(config['proposal_budget']['useful_bytes'], 1, 64*1024**2, 'proposal useful bytes')
    if config['proposal_budget']['max_payload_refs'] is not None:
        integer(config['proposal_budget']['max_payload_refs'], 1, 4096, 'proposal references')
    faults = config['fault_cases']
    if (not isinstance(faults, list) or any(not isinstance(f, str) or f not in
            ('missing-data', 'silent-first-leader') for f in faults) or len(set(faults)) != len(faults)):
        raise ValueError('compact campaign permits the two selected fault cases')
    fields(config['specification'], ('manifest', 'paper_repository'), 'specification')
    if any(not isinstance(v, str) or not v for v in config['specification'].values()):
        raise ValueError('select explicit specification manifest and source tree')
    # Protocol options are opaque to the campaign, but must belong to a selected
    # adapter. Its resolve step must reject unsupported names or ineffective knobs.
    if (not isinstance(config['protocol_options'], dict) or
            set(config['protocol_options']) != set(protocols) or
            any(not isinstance(v, dict) for v in config['protocol_options'].values())):
        raise ValueError('protocol options must match the selected adapters')
    return config


def origin_plan(rate, duration_us, members, honest_origins):
    """Compact exact integer allocation, matching shared_mempool::RatePlan."""
    integer(rate, 0, 80_000, 'total honest tx/s')
    integer(duration_us, 1, 60_000_000, 'duration us')
    integer(members, 4, 50, 'members')
    if (not isinstance(honest_origins, list) or not honest_origins or
            any(type(i) is not int or not 0 <= i < members for i in honest_origins) or
            honest_origins != sorted(set(honest_origins))):
        raise ValueError('explicit ordered distinct honest origins required')
    total, k = rate * duration_us // 1_000_000, len(honest_origins)
    return {'rate_tps': rate, 'duration_us': duration_us, 'members': members,
            'honest_origins': list(honest_origins), 'total_requests': total,
            'counts': [0 if i not in honest_origins else max(0, (total + k - 1 - honest_origins.index(i)) // k)
                       for i in range(members)],
            'schedule': 'floor((sequence*honest_origin_count+origin_rank)*1000000/rate_tps)'}


def arrival_offset_us(plan, origin, sequence):
    """Exact intended time; independent of batching, admission and completion."""
    if (type(origin) is not int or origin not in plan['honest_origins'] or
            type(sequence) is not int or not 0 <= sequence < plan['counts'][origin]):
        raise ValueError('request is outside the selected honest-origin population')
    ordinal=sequence*len(plan['honest_origins'])+plan['honest_origins'].index(origin)
    return ordinal*1_000_000//plan['rate_tps']


def create_plan(config, *, root=spec_provenance.ROOT):
    config = copy.deepcopy(validate(config))
    root = Path(root).resolve()
    spec = config['specification']
    path, raw, manifest, repository, verified = spec_provenance.validate_spec(
        root / spec['manifest'], root / spec['paper_repository'])
    trials = []
    rng = random.Random(config['seed'])
    # Interleave protocols at each common load; all use a fresh store and one
    # complete window. Fault load selection awaits accepted healthy results.
    for n in config['committees']:
        for rate in config['total_honest_input_tps']:
            protocols = list(config['protocols']); rng.shuffle(protocols)
            for protocol in protocols:
                trials.append({'protocol': protocol, 'nodes': n, 'case': 'healthy',
                               'total_honest_input_tps': rate, 'repeat': 0})
        for case in config['fault_cases']:
            protocols = list(config['protocols']); rng.shuffle(protocols)
            for protocol in protocols:
                trials.append({'protocol': protocol, 'nodes': n, 'case': case,
                               'total_honest_input_tps': None, 'repeat': 0,
                               'load_selection': 'common accepted rate below all selected healthy frontiers'})
    for ordinal, trial in enumerate(trials):
        trial['ordinal'] = ordinal
        trial['id'] = digest(trial)[:24]
    result = {'schema': 1, 'kind': KIND, 'status': 'planned', 'config': config,
              'specification': {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
                                'review_status': manifest.get('review_status'),
                                'files': [{'path': name, 'sha256': sha, 'bytes': len(data)} for name, data, sha in verified]},
              'upstreams': {p: list(UPSTREAMS[p]) if UPSTREAMS[p] else None for p in config['protocols']},
              'trials': trials, 'trial_count': len(trials),
              'supplemental_limit': len(config['protocols']) * len(config['committees']) * config['supplemental_points_or_reruns_per_curve'],
              'requested_values_are_not_effective_adapter_values': True,
              'comparison_eligible': False}
    result['plan_sha256'] = digest(result)
    return result


def validate_plan(plan, *, root=spec_provenance.ROOT):
    expected = create_plan(plan['config'], root=root)
    if json.loads(json.dumps(expected)) != plan:
        raise ValueError('campaign plan or selected specification changed')
    return plan
