#!/usr/bin/env python3
"""Bounded independent application arrivals for tiny native Raptr validation.

Application admission precedes publication to a separate HTTP sender. Native
queue/commit responses never pace the finite arrival schedule. This first local
envelope retains at most 5,000 planned records per origin; it is not the large
campaign generator.
"""
from __future__ import annotations

from collections import deque
import json
import math
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request

MAX_PLANNED = 5000
MAX_TRANSACTION_BYTES = 8192
MAX_BATCH_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 65536


def monotonic_us():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


def encode_batch(transactions):
    """BCS Vec<SignedTransaction>; each transaction is already canonical BCS."""
    count = len(transactions)
    if not 0 < count <= 1024:
        raise ValueError('native submission batch must contain 1..1024 transactions')
    prefix = bytearray()
    while count >= 128:
        prefix.append((count & 127) | 128)
        count >>= 7
    prefix.append(count)
    if any(not isinstance(value, bytes) or not 0 < len(value) <= MAX_TRANSACTION_BYTES
           for value in transactions):
        raise ValueError('native signed transaction exceeds the tiny ingress envelope')
    if len(prefix) + sum(map(len, transactions)) > MAX_BATCH_BYTES:
        raise ValueError('native submission exceeds the 4 MiB API body bound')
    return bytes(prefix) + b''.join(transactions)


def submit_batch(address, transactions, timeout):
    request = urllib.request.Request(
        address.rstrip('/') + '/delugi_finite_batch',
        data=encode_batch(transactions),
        headers={'Content-Type': 'application/x.aptos.signed_transaction+bcs'},
        method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(MAX_RESPONSE_BYTES).decode(errors='replace')
    except urllib.error.HTTPError as error:
        return error.code, error.read(MAX_RESPONSE_BYTES).decode(errors='replace')


def run_origin(plan, requests_path, events_path, address, rate, epoch_us,
               warmup_us, duration_us, drain_us, *, ingress_batch_ms=10,
               queue_capacity=1024, max_batch_transactions=128,
               http_timeout_seconds=1.0, on_admit, submit=submit_batch,
               now=monotonic_us, sleep=time.sleep):
    """Return journals and exact scheduled/admitted/backpressure populations.

    The caller authenticates the immutable plan before launch. The producer
    keeps every planned row, including queue rejections and unadmitted tail.
    The sender alone updates downstream submission outcomes. Live events remain
    on error, while a complete requests journal is published only after join.
    """
    if (type(rate) is not int or rate < 0 or
            any(type(v) is not int or v < 0 for v in (epoch_us, warmup_us, duration_us, drain_us)) or
            type(queue_capacity) is not int or not 1 <= queue_capacity <= 4096 or
            type(max_batch_transactions) is not int or not 1 <= max_batch_transactions <= 1024 or
            type(ingress_batch_ms) is not int or not 1 <= ingress_batch_ms <= 1000 or
            isinstance(http_timeout_seconds, bool) or not isinstance(http_timeout_seconds, (int, float)) or
            not math.isfinite(http_timeout_seconds) or not 0 < http_timeout_seconds <= 30):
        raise ValueError('invalid bounded native ingress settings')
    plan = iter(plan)
    if rate == 0:
        if next(plan, None) is not None:
            raise ValueError('a zero-rate origin must have an empty finite plan')
    deadline = epoch_us + warmup_us + duration_us + drain_us
    condition = threading.Condition()
    events_lock = threading.Lock()
    queue = deque()
    records = []
    done = threading.Event()
    abort = threading.Event()
    failures = []
    stats = {'maximum_queued': 0, 'submission_batches': 0, 'native_queued': 0,
             'native_rejected': 0, 'ambiguous_submission': 0}
    requests_path, events_path = Path(requests_path), Path(events_path)
    if requests_path.exists():
        raise FileExistsError(requests_path)

    with events_path.open('x', buffering=1) as events:
        def record(event):
            with events_lock:
                events.write(json.dumps(event, separators=(',', ':')) + '\n')

        def sender():
            next_flush = epoch_us + ingress_batch_ms * 1000
            try:
                while not abort.is_set():
                    batch = []
                    with condition:
                        while not abort.is_set():
                            current = now()
                            if current >= deadline:
                                for row, _ in queue:
                                    row['submission_not_started_by_cutoff'] = True
                                queue.clear()
                                return
                            if queue and (current >= next_flush or len(queue) >= max_batch_transactions):
                                for _ in range(min(len(queue), max_batch_transactions)):
                                    batch.append(queue.popleft())
                                break
                            if done.is_set() and not queue:
                                return
                            condition.wait(timeout=min(.001, max(1, deadline - current) / 1e6))
                    if not batch:
                        continue
                    sent = now()
                    if sent >= deadline:
                        for row, _ in batch:
                            row['submission_not_started_by_cutoff'] = True
                        return
                    event = {'event': 'submission', 'sequences': [r['sequence'] for r, _ in batch],
                             'sent_us': sent}
                    for row, _ in batch:
                        row['native_submission_started_us'] = sent
                    stats['submission_batches'] += 1
                    try:
                        status, body = submit(address, [raw for _, raw in batch],
                                              min(http_timeout_seconds, max(.001, (deadline - sent) / 1e6)))
                        returned = now()
                        event.update(returned_us=returned, status=status, body=str(body)[:1024])
                        for row, _ in batch:
                            row['native_submission_status'] = status
                            if status == 202:
                                row['native_queued_us'] = returned
                                stats['native_queued'] += 1
                            else:
                                row.update(native_rejected_us=returned,
                                           native_rejection_reason=f'native HTTP {status}: {str(body)[:1024]}')
                                stats['native_rejected'] += 1
                    except (OSError, TimeoutError) as error:
                        event.update(returned_us=now(), transport_error=str(error)[:1024])
                        for row, _ in batch:
                            row['submission_transport_error'] = str(error)[:1024]
                            stats['ambiguous_submission'] += 1
                    record(event)
                    next_flush = max(next_flush + ingress_batch_ms * 1000, now())
            except BaseException as error:
                failures.append(error)
                abort.set()
                with condition:
                    condition.notify_all()

        worker = threading.Thread(target=sender, name='raptr-origin-publisher', daemon=False)
        worker.start()
        try:
            for index, planned in enumerate(plan):
                if index >= MAX_PLANNED or planned['sequence'] != index:
                    raise ValueError('finite native plan exceeds envelope or has an ordinal gap')
                raw = bytes.fromhex(planned['bcs_hex'])
                if not 0 < len(raw) <= MAX_TRANSACTION_BYTES:
                    raise ValueError('signed native transaction exceeds tiny ingress bound')
                scheduled = epoch_us + index * 1_000_000 // rate
                row = {key: planned[key] for key in ('request_id', 'origin', 'sequence', 'useful_bytes')}
                row.update(scheduled_us=scheduled, admitted_us=None, batch_ready_us=None,
                           materialized_us=None, rejected_us=None, rejection_reason=None)
                while now() < scheduled and not abort.is_set():
                    sleep(min(.001, max(1, scheduled - now()) / 1e6))
                if abort.is_set():
                    raise RuntimeError('native publisher failed') from (failures[0] if failures else None)
                with condition:
                    current = now()
                    if current >= deadline:
                        row['unadmitted_at_cutoff'] = True
                    elif len(queue) >= queue_capacity:
                        row.update(rejected_us=current, rejection_reason='origin_application_queue_full')
                    else:
                        row['admitted_us'] = current
                        # This publication precedes any visibility to the sender.
                        on_admit(index)
                        queue.append((row, raw))
                        stats['maximum_queued'] = max(stats['maximum_queued'], len(queue))
                        condition.notify()
                    records.append(row)
                    record({'event': 'arrival', **row})
        except BaseException:
            abort.set()
            raise
        finally:
            done.set()
            with condition:
                condition.notify_all()
            remaining = 0 if abort.is_set() else max(0, (deadline - now()) / 1e6)
            worker.join(timeout=remaining + http_timeout_seconds + 2)
            if worker.is_alive():
                abort.set()
                # Real urllib has the bounded timeout above; a broken injected
                # publisher is a failed harness, never a successful cutoff.
                raise RuntimeError('owned native publisher did not stop within its timeout')
        if failures:
            raise RuntimeError('native publisher failed') from failures[0]

    for row in records:
        if row['admitted_us'] is not None and 'native_submission_started_us' not in row:
            row['submission_not_started_by_cutoff'] = True
    with requests_path.open('x') as output:
        for row in records:
            output.write(json.dumps(row, separators=(',', ':')) + '\n')
    stats.update(planned=len(records), admitted=sum(r['admitted_us'] is not None for r in records),
                 rejected=sum(r['rejected_us'] is not None for r in records),
                 unadmitted_at_cutoff=sum(r.get('unadmitted_at_cutoff', False) for r in records),
                 queued_without_submission=sum(r.get('submission_not_started_by_cutoff', False) for r in records),
                 requests_path=str(requests_path), events_path=str(events_path),
                 endpoint='origin application admission precedes HTTP; HTTP202 means native API queued, not native mempool insertion or commit')
    return stats
