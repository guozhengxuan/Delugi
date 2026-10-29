"""Units and validation shared by configuration, adapters and node launchers."""
from __future__ import annotations
import copy
import json
from pathlib import Path

TRANSPORT_COUNTS = ('inbox_capacity','outbox_capacity','max_deferred_frames_per_peer',
    'max_inflight_frames','max_inflight_bytes','max_outstanding_bytes','max_inbox_bytes',
    'max_read_buffer_bytes','max_reader_connections')
TRANSPORT_TIMERS = ('connect_timeout_ms','ack_timeout_ms','io_timeout_ms',
    'frame_read_timeout_ms','reconnect_delay_ms')
# Overrides preserve each core's selected frame/queue resource profile.
WAN_TRANSPORT = {'connect_timeout_ms':5000,'ack_timeout_ms':30000,
    'io_timeout_ms':1000,'frame_read_timeout_ms':30000,'reconnect_delay_ms':100}

def transport(value):
    if not isinstance(value,dict) or set(value)-set(TRANSPORT_COUNTS+TRANSPORT_TIMERS):
        raise ValueError('unknown shared transport parameter; use explicit *_ms timer names')
    for name,v in value.items():
        high=300000 if name in TRANSPORT_TIMERS else 16*1024**3
        if type(v) is not int or not 1<=v<=high:
            raise ValueError(f'transport.{name} must be an integer in 1..{high}')
    return copy.deepcopy(value)

def load_transport(path):
    return transport(json.loads(Path(path).read_text())) if path else {}

# These are fields consumed by the pinned native factory, not invented aliases.
# Protocol-selection switches and unused Aptos settings are intentionally absent.
RAPTR_FIELDS = {
    'latency_trace': {'max_events':1_000_000},
    'limits': {'max_wire_bytes':2**20, 'inbox_frames':100000, 'inbox_bytes':128*2**20,
        'maximum_rpcs':100000, 'ingress_capacity':100000, 'output_capacity':100000,
        'max_journal_bytes':4*2**30, 'max_async_tasks':1000000, 'max_blocking_tasks':100000,
        'max_pending_transactions':1000000, 'max_pending_payload_bytes':2**30},
    'consensus': {k:2**30 for k in ('max_sending_block_txns',
        'max_sending_block_bytes','max_sending_inline_txns','max_sending_inline_bytes',
        'quorum_store_poll_time_ms','mempool_txn_pull_timeout_ms',
        'quorum_store_pull_timeout_ms','wait_for_full_blocks_above_pending_blocks')},
    'quorum_store': {k:2**30 for k in ('channel_size','proof_timeout_ms',
        'batch_generation_poll_interval_ms','batch_generation_min_non_empty_interval_ms',
        'batch_generation_max_interval_ms','sender_max_batch_txns','sender_max_batch_bytes',
        'sender_max_num_batches','sender_max_total_txns','sender_max_total_bytes',
        'receiver_max_batch_txns','receiver_max_batch_bytes','receiver_max_num_batches',
        'receiver_max_total_txns','receiver_max_total_bytes','batch_request_num_peers',
        'batch_request_retry_limit','batch_request_retry_interval_ms','batch_request_rpc_timeout_ms',
        'memory_quota','db_quota','batch_quota','num_workers_for_remote_batches','max_batches_per_pull')},
}

def raptr_options(value):
    if not isinstance(value,dict) or set(value)-RAPTR_FIELDS.keys():
        raise ValueError('unsupported Raptr node option')
    for group, fields in value.items():
        if not isinstance(fields,dict) or set(fields)-RAPTR_FIELDS[group].keys():
            raise ValueError('unsupported Raptr '+group+' parameter')
        for name,v in fields.items():
            high=min(RAPTR_FIELDS[group][name],300000) if name.endswith('_ms') else RAPTR_FIELDS[group][name]
            if type(v) is not int or not 1<=v<=high:
                raise ValueError(f'Raptr {group}.{name} must be an integer in 1..{high}')
    return copy.deepcopy(value)
