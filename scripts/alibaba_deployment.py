#!/usr/bin/env python3
"""Bounded, explicitly named Alibaba lease. Credentials remain controller-local.

Use only after the user supplies a spending/scale authorization. A saved request
token is reused after an uncertain create result; never substitute a new token.
Cleanup verifies live ownership tags and deletes exact saved IDs only.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
from functools import wraps
import ipaddress
import json
import math
import os
from pathlib import Path
import uuid


def utcnow():
    return datetime.now(timezone.utc)


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.pending.json')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


@contextmanager
def lease_lock(path):
    """Serialize every state transition, including uncertain provider calls.

    Resolve aliases before deriving the lock name. A second process fails
    promptly instead of loading stale caps/tokens while an action is active.
    The lock file remains in place: unlinking it would split concurrent locks.
    """
    path = Path(path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError('another lease action is running; retry after it completes') from error
        yield
    finally:
        os.close(descriptor)


def serialized_action(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with lease_lock(self.path):
            state = json.loads(self.path.read_text())
            plan = validate_plan(state['plan'])
            if plan != self.plan:
                raise ValueError('lease plan changed after client initialization; reopen the reviewed lease')
            self.state = state
            return method(self, *args, **kwargs)
    return locked


def validate_plan(plan):
    if (plan.get('schema') != 1 or type(plan.get('maximum_instances')) is not int
            or not 1 <= plan['maximum_instances'] <= 31):
        raise ValueError('explicit maximum of 1..31 instances required')
    if not all(type(plan.get(k)) in (int, float) and math.isfinite(plan[k]) for k in
               ('lifetime_hours', 'budget_cny', 'hourly_quote_cny', 'cost_margin_cny')):
        raise ValueError('finite numeric budget limits required')
    if not 0 < plan['lifetime_hours'] <= 7 or not 0 < plan['budget_cny'] <= 500:
        raise ValueError('positive budget at most CNY500 and at most seven-hour lease required')
    if plan['hourly_quote_cny'] <= 0 or not 0 < plan['cost_margin_cny'] < plan['budget_cny']:
        raise ValueError('positive live quote and cost margin required')
    if plan.get('internet_charge_type') != 'PayByBandwidth' or plan.get('internet_max_bandwidth_out') != 5:
        raise ValueError('reviewed profile requires fixed PayByBandwidth public egress at 5 Mbps')
    maximum_compute = plan['maximum_instances'] * plan['lifetime_hours'] * plan['hourly_quote_cny']
    if maximum_compute + plan['cost_margin_cny'] > plan['budget_cny']:
        raise ValueError('worst-case instance/disk/fixed-bandwidth quote exceeds budget after margin')
    controller = ipaddress.ip_network(plan['controller_cidr'])
    if controller.version != 4 or controller.prefixlen != 32:
        raise ValueError('SSH must be restricted to the controller IPv4 /32')
    if plan['instance_type'] != 'ecs.g9i.xlarge' or plan['system_disk_gib'] != 200:
        raise ValueError('this reviewed profile requires Loom type and quoted 200 GiB ESSD')
    if not plan.get('user_authorization'):
        raise ValueError('user spending authorization must be recorded before provisioning')
    return plan


def owned_instances(items, run_id, expected_ids):
    expected_ids = set(expected_ids)
    for item in items:
        tags = {tag['TagKey']: tag['TagValue'] for tag in item.get('Tags', {}).get('Tag', [])}
        if item['InstanceId'] not in expected_ids or tags.get('DelugiRun') != run_id:
            raise ValueError('live instance ownership does not match exact lease IDs')
    return items


def owned_security_group(items, run_id, expected_id):
    if len(items) != 1:
        raise ValueError('exact saved security group is missing or ambiguous; reconcile before cleanup')
    item = items[0]
    tags = {tag['TagKey']: tag['TagValue'] for tag in item.get('Tags', {}).get('Tag', [])}
    if (item.get('SecurityGroupId') != expected_id or item.get('SecurityGroupName') != 'Delugi-' + run_id
            or tags.get('DelugiRun') != run_id):
        raise ValueError('security-group live ownership does not match saved ID and run tag')
    return item


class Lease:
    def __init__(self, path):
        from alibabacloud_ecs20140526.client import Client
        from alibabacloud_ecs20140526 import models
        from alibabacloud_tea_openapi.models import Config
        from alibabacloud_tea_util.models import RuntimeOptions
        self.path, self.models, self.options = Path(path).expanduser().resolve(), models, RuntimeOptions()
        self.state = json.loads(self.path.read_text())
        self.plan = validate_plan(self.state['plan'])
        settings_path = Path(self.plan['settings']).expanduser()
        settings = json.loads(settings_path.read_text())
        if (self.plan['region'] not in settings['instances']['regions'] or
                self.plan['instance_type'] != settings['instances']['type'] or
                self.plan['key_pair'] != settings['key']['name']):
            raise ValueError('lease differs from selected Loom cloud settings')
        credentials_path = Path(settings['key']['accesskey']).expanduser()
        if not credentials_path.is_absolute():
            credentials_path = settings_path.parent / credentials_path
        credentials = json.loads(credentials_path.read_text())
        self.client = Client(Config(access_key_id=credentials['AccessKey ID'],
            access_key_secret=credentials['AccessKey Secret'], region_id=self.plan['region'],
            endpoint=f"ecs.{self.plan['region']}.aliyuncs.com", read_timeout=20000, connect_timeout=20000))

    def call(self, method, request):
        response = getattr(self.client, method + '_with_options')(request, self.options).to_map()['body']
        self.state.setdefault('requests', []).append({'operation': method, 'at': utcnow().isoformat(),
                                                     'request_id': response.get('RequestId')})
        save(self.path, self.state)
        return response

    def _verify_fresh_price(self):
        """Price check precedes resource creation; it is not a billing-account cap."""
        m, p = self.models, self.plan
        response = self.call('describe_price', m.DescribePriceRequest(
            region_id=p['region'], image_id=p['image_id'], instance_type=p['instance_type'],
            resource_type='instance', price_unit='Hour', period=1, amount=1,
            instance_network_type='vpc', internet_charge_type=p['internet_charge_type'],
            internet_max_bandwidth_out=p['internet_max_bandwidth_out'],
            system_disk=m.DescribePriceRequestSystemDisk(category='cloud_essd', size=p['system_disk_gib'])))
        price = response.get('PriceInfo', {}).get('Price', {})
        trade = price.get('TradePrice')
        accepted = (price.get('Currency') == 'CNY' and type(trade) in (int, float)
                    and math.isfinite(trade) and 0 <= trade <= p['hourly_quote_cny'])
        self.state['latest_price_check'] = {'at': utcnow().isoformat(), 'price': price,
                                          'authorized_hourly_quote_cny': p['hourly_quote_cny'],
                                          'accepted': accepted}
        save(self.path, self.state)
        if not accepted:
            raise ValueError('fresh full-profile hourly quote is missing, non-CNY, or above the authorized bound')

    @serialized_action
    def launch(self, amount):
        if type(amount) is not int or amount <= 0:
            raise ValueError('positive instance count required')
        if self.state.get('closed'):
            raise ValueError('closed lease cannot be reopened')
        batches = self.state.setdefault('batches', [])
        pending = [batch for batch in batches if 'ids' not in batch]
        if pending:
            if len(pending) != 1 or pending[0]['amount'] != amount:
                raise ValueError('resolve the original uncertain create request before another launch')
            batch = pending[0]
        else:
            if sum(batch['amount'] for batch in batches) + amount > self.plan['maximum_instances']:
                raise ValueError('lease instance cap reached')
            batch = {'amount': amount, 'client_token': str(uuid.uuid4())}
        if 'expires_at' not in self.state:
            self.state['expires_at'] = (utcnow() + timedelta(hours=self.plan['lifetime_hours'])).strftime('%Y-%m-%dT%H:%M:%SZ')
        expiry = datetime.fromisoformat(self.state['expires_at'].replace('Z', '+00:00'))
        if expiry - utcnow() < timedelta(minutes=35):
            raise ValueError('insufficient lease time left to safely launch')
        self._verify_fresh_price()
        m, p, run = self.models, self.plan, self.state['run_id']
        if 'security_group' not in self.state:
            # Save exact intent and token before mutation. After an uncertain
            # result, only an identical request with this token may be retried.
            if self.state.get('security_group_pending') and not self.state.get('security_group_client_token'):
                raise ValueError('reconcile uncertain legacy security-group creation by its saved unique name')
            self.state['security_group_pending'] = 'Delugi-' + run
            self.state.setdefault('security_group_client_token', str(uuid.uuid4()))
            save(self.path, self.state)
            response = self.call('create_security_group', m.CreateSecurityGroupRequest(
                region_id=p['region'], vpc_id=p['vpc_id'], security_group_name='Delugi-' + run,
                description='Owned temporary Delugi evaluation lease ' + run,
                client_token=self.state['security_group_client_token'],
                tag=[m.CreateSecurityGroupRequestTag(key='DelugiRun', value=run),
                     m.CreateSecurityGroupRequestTag(key='Purpose', value='evaluation-migration')]))
            self.state['security_group'] = response['SecurityGroupId']
            save(self.path, self.state)
        group = self.state['security_group']
        if not self.state.get('rules_installed'):
            self.call('authorize_security_group', m.AuthorizeSecurityGroupRequest(
                region_id=p['region'], security_group_id=group, permissions=[
                    m.AuthorizeSecurityGroupRequestPermissions(ip_protocol='TCP', port_range='22/22',
                        source_cidr_ip=p['controller_cidr'], description='Delugi controller SSH'),
                    m.AuthorizeSecurityGroupRequestPermissions(ip_protocol='TCP', port_range='8000/8099',
                        source_group_id=group, description='Delugi lease peer traffic'),
                ]))
            self.state['rules_installed'] = True
        if not pending:
            batches.append(batch)
        save(self.path, self.state)
        response = self.call('run_instances', m.RunInstancesRequest(
            region_id=p['region'], image_id=p['image_id'], instance_type=p['instance_type'],
            v_switch_id=p['vswitch_id'], security_group_id=group, key_pair_name=p['key_pair'],
            instance_charge_type='PostPaid', internet_charge_type=p['internet_charge_type'],
            internet_max_bandwidth_out=p['internet_max_bandwidth_out'], internet_max_bandwidth_in=100,
            system_disk=m.RunInstancesRequestSystemDisk(category='cloud_essd', size=p['system_disk_gib']),
            amount=amount, min_amount=amount, client_token=batch['client_token'],
            auto_release_time=self.state['expires_at'], instance_name='Delugi-' + run,
            tag=[m.RunInstancesRequestTag(key='DelugiRun', value=run),
                 m.RunInstancesRequestTag(key='Purpose', value='evaluation-migration')]))
        batch['ids'] = response['InstanceIdSets']['InstanceIdSet']
        save(self.path, self.state)
        if len(batch['ids']) != amount:
            raise RuntimeError('provider returned unexpected instance count; retain state and reconcile')
        return {'ids': batch['ids'], 'expires_at': self.state['expires_at']}

    def _refresh(self):
        ids = [item for batch in self.state.get('batches', []) for item in batch.get('ids', [])]
        if not ids:
            return []
        response = self.call('describe_instances', self.models.DescribeInstancesRequest(
            region_id=self.plan['region'], instance_ids=json.dumps(ids), page_size=100))
        instances = owned_instances(response['Instances']['Instance'], self.state['run_id'], ids)
        self.state['instances'] = [{k: item.get(k) for k in ('InstanceId', 'Status', 'PublicIpAddress',
            'VpcAttributes', 'Cpu', 'Memory', 'ZoneId', 'CreationTime', 'AutoReleaseTime', 'Tags')}
            for item in instances]
        save(self.path, self.state)
        return self.state['instances']

    @serialized_action
    def refresh(self):
        return self._refresh()

    @serialized_action
    def destroy(self):
        if self.state.get('security_group_pending') and not self.state.get('security_group'):
            raise ValueError('resolve uncertain security-group creation before cleanup; lease remains open')
        if any('ids' not in batch for batch in self.state.get('batches', [])):
            raise ValueError('resolve uncertain create result before cleanup')
        if self.state.get('closed'):
            return {'closed': True}
        instances = self._refresh()
        if instances:
            self.call('delete_instances', self.models.DeleteInstancesRequest(region_id=self.plan['region'],
                instance_id=[item['InstanceId'] for item in instances], force=True))
            return {'deletion_requested': len(instances), 'next': 'refresh and destroy again after instance deletion completes'}
        group = self.state.get('security_group')
        if group and not self.state.get('group_deleted'):
            response = self.call('describe_security_groups', self.models.DescribeSecurityGroupsRequest(
                region_id=self.plan['region'], security_group_id=group, page_size=100))
            groups = response['SecurityGroups']['SecurityGroup']
            if groups or not self.state.get('group_delete_requested'):
                owned_security_group(groups, self.state['run_id'], group)
                self.state['group_delete_requested'] = True
                save(self.path, self.state)
                self.call('delete_security_group', self.models.DeleteSecurityGroupRequest(
                    region_id=self.plan['region'], security_group_id=group))
            self.state['group_deleted'] = True
        self.state['closed'] = True
        save(self.path, self.state)
        return {'closed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('initialize', 'launch', 'refresh', 'destroy'))
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--amount', type=int)
    args = parser.parse_args()
    if args.action == 'initialize':
        with lease_lock(args.state):
            if args.state.exists() or args.plan is None:
                raise ValueError('new state path and reviewed plan required')
            state = {'run_id': uuid.uuid4().hex[:16], 'plan': validate_plan(json.loads(args.plan.read_text()))}
            save(args.state, state)
            result = {'run_id': state['run_id'], 'status': 'prepared; no resources created'}
    else:
        lease = Lease(args.state)
        result = lease.launch(args.amount) if args.action == 'launch' else getattr(lease, args.action)()
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never serialize provider requests or credential-bearing exception data.
        print(json.dumps({'error_type': type(error).__name__, 'error_code': getattr(error, 'code', None),
                          'message': str(error) if isinstance(error, ValueError) else 'operation failed; saved state retained'}))
        raise SystemExit(1)
