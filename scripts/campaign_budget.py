"""Durable aggregate budget reservations across finite cloud leases.

Reserve before dispatch, and record dispatch before making a paid API call.
An ambiguous dispatch keeps its whole reservation until resources and billing
are reconciled. Cleanup alone is not settlement of delayed cloud charges.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

KIND = 'delugi-campaign-budget-v1'
MAX_BYTES = 4*1024**2


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def money(value):
    if type(value) is not int or not 0 <= value <= 100_000_000:
        raise ValueError('CNY amounts must be bounded integer fen')
    return value


def identity(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('explicit SHA256 evidence identity required')
    return value


class Ledger:
    def __init__(self, path):
        path = Path(path).expanduser()
        if path.is_symlink():
            raise ValueError('budget ledger cannot be a symlink')
        self.path = path.parent.resolve() / path.name

    @contextmanager
    def locked(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(self.path)+'.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise ValueError('another campaign budget operation is running') from error
            yield
        finally:
            os.close(fd)

    def _load(self):
        with os.fdopen(os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError('invalid or oversized budget ledger')
            value = json.load(stream)
        expected = value.pop('state_sha256', None)
        if expected != digest(value) or value.get('kind') != KIND:
            raise ValueError('budget state changed or has the wrong format')
        money(value['ceiling_fen']); identity(value['authorization_sha256'])
        for entry in value['leases'].values():
            money(entry['reserved_fen'])
            if entry['status'] not in ('reserved', 'dispatching', 'active', 'cancelled', 'settled'):
                raise ValueError('unknown budget reservation state')
            if entry['status'] == 'settled':
                money(entry['actual_fen']); identity(entry['settlement_sha256'])
        return value

    def _save(self, value):
        result = value | {'state_sha256': digest(value)}
        encoded = (json.dumps(result, sort_keys=True, indent=2)+'\n').encode()
        if len(encoded) > MAX_BYTES:
            raise ValueError('budget ledger exceeds its bounded envelope')
        fd, name = tempfile.mkstemp(prefix=self.path.name+'.', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.path)
            parent = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        finally:
            if os.path.exists(name): os.unlink(name)
        return self.summary(value)

    @staticmethod
    def summary(value):
        spent = sum(e['actual_fen'] for e in value['leases'].values() if e['status'] == 'settled')
        reserved = sum(e['reserved_fen'] for e in value['leases'].values()
                       if e['status'] in ('reserved', 'dispatching', 'active'))
        return {'ceiling_fen': value['ceiling_fen'], 'settled_fen': spent,
                'reserved_fen': reserved, 'available_fen': value['ceiling_fen'] - spent - reserved,
                'overspent': spent + reserved > value['ceiling_fen'], 'leases': value['leases']}

    def initialize(self, ceiling_fen, authorization_sha256):
        money(ceiling_fen); identity(authorization_sha256)
        if ceiling_fen == 0: raise ValueError('positive authorized ceiling required')
        with self.locked():
            if self.path.exists(): raise ValueError('budget already initialized; cannot reset spending')
            return self._save({'kind': KIND, 'ceiling_fen': ceiling_fen,
                               'authorization_sha256': authorization_sha256, 'leases': {}})

    def snapshot(self):
        with self.locked(): return self.summary(self._load())

    def reserve(self, lease_id, upper_cost_fen, plan_sha256):
        if not isinstance(lease_id, str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', lease_id):
            raise ValueError('invalid owned lease identity')
        money(upper_cost_fen); identity(plan_sha256)
        if upper_cost_fen == 0: raise ValueError('reserve positive worst-case lease cost')
        with self.locked():
            value = self._load()
            old = value['leases'].get(lease_id)
            if old is not None:
                if old['reserved_fen'] != upper_cost_fen or old['plan_sha256'] != plan_sha256:
                    raise ValueError('lease identity reused with a different quote/plan')
                return self.summary(value)
            if upper_cost_fen > self.summary(value)['available_fen']:
                raise ValueError('lease exceeds remaining aggregate campaign budget')
            value['leases'][lease_id] = {'status': 'reserved', 'reserved_fen': upper_cost_fen,
                                         'plan_sha256': plan_sha256, 'instance_ids': []}
            return self._save(value)

    def dispatch(self, lease_id):
        with self.locked():
            value = self._load(); entry = value['leases'][lease_id]
            if entry['status'] != 'reserved':
                raise ValueError('lease already dispatched; reconcile instead of repeating creation')
            entry['status'] = 'dispatching'
            return self._save(value)

    def launched(self, lease_id, instance_ids):
        if (not isinstance(instance_ids, list) or not instance_ids or len(instance_ids) > 50 or
                any(not isinstance(i, str) or not re.fullmatch('i-[a-zA-Z0-9]+', i) for i in instance_ids) or
                len(set(instance_ids)) != len(instance_ids)):
            raise ValueError('exact distinct allocated instance IDs required')
        with self.locked():
            value = self._load(); entry = value['leases'][lease_id]
            if entry['status'] == 'active' and entry['instance_ids'] == instance_ids:
                return self.summary(value)
            if entry['status'] != 'dispatching': raise ValueError('lease is not awaiting dispatch reconciliation')
            entry.update(status='active', instance_ids=list(instance_ids))
            return self._save(value)

    def cancel(self, lease_id):
        with self.locked():
            value = self._load(); entry = value['leases'][lease_id]
            if entry['status'] != 'reserved':
                raise ValueError('a possibly paid dispatch cannot release its reservation without settlement')
            entry['status'] = 'cancelled'
            return self._save(value)

    def settle(self, lease_id, actual_fen, settlement_sha256, *, resources_deleted, billing_final):
        money(actual_fen); identity(settlement_sha256)
        if resources_deleted is not True or billing_final is not True:
            raise ValueError('retain reservation until deletion and final billed cost are verified')
        with self.locked():
            value = self._load(); entry = value['leases'][lease_id]
            if entry['status'] == 'settled':
                if entry['actual_fen'] != actual_fen or entry['settlement_sha256'] != settlement_sha256:
                    raise ValueError('settlement cannot be rewritten')
                return self.summary(value)
            if entry['status'] not in ('dispatching', 'active'):
                raise ValueError('only a dispatched lease can have billed charges')
            # Persist overruns too: rejecting this write would hide money already
            # charged. Negative remaining balance then prevents further leases.
            entry.update(status='settled', actual_fen=actual_fen, settlement_sha256=settlement_sha256)
            return self._save(value)
