#!/usr/bin/env python3
"""Read-only-core local diagnostic: signed proposal contents over delayed TCP.

Uses the retained shared binary in finite diagnostic mode, which already logs
full proposal availability proofs. No production code or protocol rule changes.
This is a small local mechanism check, not a replay of observed WAN one-way times.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time

import run_network as network
from run_tcp_delay import ProxiedChildren

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    receipt_path = args.receipt.resolve()
    receipt = json.loads(receipt_path.read_text())
    # Additional diagnostic test files do not alter the already-bound runtime.
    checked = {name: expected for name, expected in receipt['sources'].items()}
    for name, expected in checked.items():
        assert sha(ROOT / name) == expected, name
    assert sha(binary) == receipt['binary']['sha256']
    matrix = json.loads(args.matrix.read_text())['matrix_ms'] if args.matrix else None
    factory = ProxiedChildren(args.delay_ms, matrix)
    children, controller = [], None
    result = {'status': 'incomplete', 'binary_sha256': sha(binary),
              'receipt_sha256': sha(receipt_path), 'runtime_sources_checked': len(checked),
              'scope': 'Local four-process diagnostic; preexisting finite logging; no core changes.',
              'settings': {'delay_ms': args.delay_ms if matrix is None else None,
                           'matrix_ms': matrix, 'bound_ms': args.bound_ms,
                           'rate': args.rate, 'count': args.count,
                           'warmup_s': args.warmup, 'opportunity_limit': 32}}
    try:
        keys = subprocess.run([str(binary), '--keygen', str(out/'keys'), '--nodes', '4'],
                              cwd=ROOT, text=True, capture_output=True, check=True)
        kd = json.loads(keys.stdout)
        addresses = network.unused_addresses(8)
        config = {'instance': list(secrets.token_bytes(32)), 'addresses': addresses[:4],
                  'control_addresses': addresses[4:], 'control_token': secrets.token_hex(32),
                  'public_keys': kd['public_keys'], 'key_files': kd['key_files'],
                  'bound_ms': args.bound_ms, 'chunk_capacity': 64, 'workload_rounds': 32,
                  'silent': None, 'max_runtime_ms': 30000,
                  'ordering_mode': 'canonical', 'ordering_batch': True,
                  'report_schedule': 'pipeline',
                  'causal_trace': {'detail_stride': 1, 'max_events': 100000}}
        config.update(network.storage_options(out, 'shared-rocksdb-written-v1'))
        path = out/'config.json'
        path.write_text(json.dumps(config, indent=2)+'\n')
        path.chmod(0o600)
        children = [factory.child(binary, path, i, out) for i in range(4)]
        controller = network.Controller(config, out, children)
        deadline = time.monotonic()+20
        while not all(any(e.get('event') == 'ready' for e in c.events) for c in children):
            controller.check()
            if time.monotonic() > deadline:
                raise TimeoutError('ready')
            time.sleep(.005)
        controller.many(range(4), 'start')
        epoch = time.monotonic()+args.warmup
        for k in range(args.count):
            time.sleep(max(0, epoch+k/args.rate-time.monotonic()))
            controller.request(k%4, 'submit', round=k//4+1, count=1, size=1)
        controller.wait(lambda ss: all(len(s['executed']) == args.count for s in ss.values()),
                        deadline, 'all tagged batches execute')
        controller.many(range(4), 'quiesce')
        result['snapshots'] = controller.snapshots()
        traces = {}
        for i in range(4):
            offset, events, meta = 0, [], None
            while True:
                page = controller.request(i, 'causal_trace', offset=offset, limit=1024)['reply']['data']
                meta = page
                events.extend(page['events'])
                if page['next_offset'] is None:
                    break
                offset = page['next_offset']
            traces[i] = {**meta, 'events': events}
            (out/f'trace-{i}.json').write_text(json.dumps(traces[i])+'\n')
        result['status'] = 'passed'
    except Exception as error:
        result.update(status='failed', error=f'{type(error).__name__}: {error}')
    finally:
        cleanup_errors = []
        try:
            if controller is not None:
                controller.save()
        except Exception as error:
            cleanup_errors.append(f'archive: {error}')
        finally:
            result['processes'] = []
            for child in children:
                try:
                    record = child.finish()
                    result['processes'].append(record)
                    if record['telemetry_errors']:
                        cleanup_errors.append(f'replica {child.id}: invalid telemetry')
                except Exception as error:
                    cleanup_errors.append(f'replica {child.id} cleanup: {error}')
            try:
                factory.close()
            except Exception as error:
                cleanup_errors.append(f'proxy cleanup: {error}')
        if factory.proxy is not None and factory.proxy.closed:
            result['proxy'] = factory.proxy.report()
        if cleanup_errors:
            result.update(status='failed', cleanup_errors=cleanup_errors)
        for name, expected in checked.items():
            assert sha(ROOT/name) == expected, name
        assert sha(binary) == result['binary_sha256']
        (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(out), 'status': result['status'], 'error': result.get('error')}))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, default=ROOT/'core/raptr/.native-deps/target/debug/raptr-shared-node')
    p.add_argument('--receipt', type=Path, default=ROOT/'results/local/delugi-freshness-wan-local-build-20261029/build-receipt.json')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--delay-ms', type=float, default=10)
    p.add_argument('--matrix', type=Path)
    p.add_argument('--bound-ms', type=int, default=100)
    p.add_argument('--warmup', type=float, default=.06)
    p.add_argument('--rate', type=int, default=100)
    p.add_argument('--count', type=int, default=16)
    raise SystemExit(run(p.parse_args()))
