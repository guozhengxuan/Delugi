import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from alibaba_deployment import (Lease, lease_lock, owned_instances, owned_security_group,
                               save, serialized_action, validate_plan)


class LeaseBoundTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'schema': 1, 'maximum_instances': 31, 'lifetime_hours': 7,
            'budget_cny': 500, 'hourly_quote_cny': 2.0833, 'cost_margin_cny': 45,
            'internet_charge_type': 'PayByBandwidth', 'internet_max_bandwidth_out': 5,
            'controller_cidr': '192.0.2.10/32', 'instance_type': 'ecs.g9i.xlarge',
            'system_disk_gib': 200, 'user_authorization': 'test fixture only'}

    def test_finite_worst_case_compute_stays_inside_reserved_budget(self):
        self.assertIs(validate_plan(self.plan), self.plan)
        for changes in ({'budget_cny': 450}, {'lifetime_hours': 8}, {'maximum_instances': 32},
                        {'maximum_instances': 1.5}, {'maximum_instances': True}, {'budget_cny': 501},
                        {'hourly_quote_cny': float('nan')}, {'budget_cny': float('inf')},
                        {'cost_margin_cny': 0}, {'user_authorization': ''},
                        {'internet_charge_type': 'PayByTraffic'}, {'internet_max_bandwidth_out': 100},
                        {'controller_cidr': '192.0.2.0/24'}, {'controller_cidr': '2001:db8::/32'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_plan(dict(self.plan, **changes))

    def test_cleanup_requires_exact_id_and_live_run_tag(self):
        item = {'InstanceId': 'i-owned', 'Tags': {'Tag': [{'TagKey': 'DelugiRun', 'TagValue': 'run1'}]}}
        self.assertEqual(owned_instances([item], 'run1', ['i-owned']), [item])
        for run, ids in (('run2', ['i-owned']), ('run1', ['i-unrelated'])):
            with self.assertRaises(ValueError):
                owned_instances([item], run, ids)
        changed = copy.deepcopy(item)
        changed['Tags']['Tag'].clear()
        with self.assertRaises(ValueError):
            owned_instances([changed], 'run1', ['i-owned'])

    def test_security_group_cleanup_requires_exact_id_name_and_tag(self):
        item = {'SecurityGroupId': 'sg-owned', 'SecurityGroupName': 'Delugi-run1',
                'Tags': {'Tag': [{'TagKey': 'DelugiRun', 'TagValue': 'run1'}]}}
        self.assertEqual(owned_security_group([item], 'run1', 'sg-owned'), item)
        for changes in ({'SecurityGroupId': 'sg-unrelated'}, {'SecurityGroupName': 'other'},
                        {'Tags': {'Tag': []}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                owned_security_group([dict(item, **changes)], 'run1', 'sg-owned')
        with self.assertRaises(ValueError):
            owned_security_group([], 'run1', 'sg-owned')

    def test_lock_rejects_concurrent_action_through_path_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            with lease_lock(path):
                with self.assertRaisesRegex(ValueError, 'another lease action'):
                    with lease_lock(path.parent / '.' / path.name):
                        self.fail('second action entered locked lease')
            with lease_lock(path):
                self.assertTrue(Path(str(path) + '.lock').exists())

    def test_serialized_action_reloads_current_caps_and_holds_lock_across_call(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            save(path, {'plan': self.plan, 'generation': 1})
            class FakeLease:
                @serialized_action
                def probe(self):
                    with self_test.assertRaisesRegex(ValueError, 'another lease action'):
                        with lease_lock(self.path):
                            pass
                    return self.state['generation']
            self_test = self
            lease = FakeLease()
            lease.path, lease.plan = path, self.plan
            lease.state = {'generation': 0}
            self.assertEqual(lease.probe(), 1)
            save(path, {'plan': self.plan, 'generation': 2})
            self.assertEqual(lease.probe(), 2)
            changed = dict(self.plan, lifetime_hours=6)
            save(path, {'plan': changed, 'generation': 3})
            with self.assertRaisesRegex(ValueError, 'plan changed'):
                lease.probe()

    def test_uncertain_security_group_prevents_cleanup_or_closed_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            state = {'run_id': 'run1', 'plan': self.plan, 'security_group_pending': 'Delugi-run1'}
            save(path, state)
            lease = object.__new__(Lease)
            lease.path, lease.plan, lease.state = path, self.plan, state
            lease._refresh = lambda: self.fail('must not query/delete instances with unresolved group creation')
            with self.assertRaisesRegex(ValueError, 'uncertain security-group'):
                lease.destroy()
            self.assertFalse(json.loads(path.read_text()).get('closed', False))

    def test_uncertain_group_delete_reconciles_absence_without_another_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'lease.json'
            state = {'run_id': 'run1', 'plan': dict(self.plan, region='ap-southeast-1'),
                     'security_group': 'sg-owned', 'group_delete_requested': True}
            save(path, state)
            lease = object.__new__(Lease)
            lease.path, lease.plan, lease.state = path, state['plan'], state
            lease._refresh = lambda: []
            lease.models = SimpleNamespace(DescribeSecurityGroupsRequest=lambda **kwargs: kwargs)
            calls = []
            def call(method, request):
                calls.append((method, request))
                return {'SecurityGroups': {'SecurityGroup': []}}
            lease.call = call
            self.assertEqual(lease.destroy(), {'closed': True})
            self.assertEqual([method for method, _ in calls], ['describe_security_groups'])
            self.assertTrue(json.loads(path.read_text())['group_deleted'])
            self.assertEqual(lease.destroy(), {'closed': True})
            self.assertEqual(len(calls), 1)

    def test_fresh_price_gate_checks_full_fixed_profile_and_rejects_unbounded_quote(self):
        with tempfile.TemporaryDirectory() as directory:
            lease = object.__new__(Lease)
            lease.path = Path(directory) / 'lease.json'
            lease.plan = dict(self.plan, region='ap-southeast-1', image_id='reviewed-image')
            lease.state = {'plan': lease.plan}
            lease.models = SimpleNamespace(DescribePriceRequest=lambda **kwargs: kwargs,
                                           DescribePriceRequestSystemDisk=lambda **kwargs: kwargs)
            requests = []
            for currency, price, okay in [('CNY', 2.0833, True), ('CNY', 2.09, False),
                                          ('USD', 1.0, False), ('CNY', float('nan'), False),
                                          ('CNY', None, False), ('CNY', True, False)]:
                def call(method, request):
                    requests.append((method, request))
                    return {'PriceInfo': {'Price': {'Currency': currency, 'TradePrice': price}}}
                lease.call = call
                if okay:
                    lease._verify_fresh_price()
                else:
                    with self.assertRaisesRegex(ValueError, 'fresh full-profile'):
                        lease._verify_fresh_price()
                self.assertEqual(lease.state['latest_price_check']['accepted'], okay)
            method, query = requests[0]
            self.assertEqual(method, 'describe_price')
            self.assertEqual(query['internet_charge_type'], 'PayByBandwidth')
            self.assertEqual(query['internet_max_bandwidth_out'], 5)
            self.assertEqual(query['system_disk'], {'category': 'cloud_essd', 'size': 200})
            self.assertEqual(query['image_id'], 'reviewed-image')

    def test_start_stop_use_only_owned_saved_ids_and_preserve_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lease.json'
            state={'run_id':'run1','plan':dict(self.plan,region='ap-southeast-1'),
                   'expires_at':'2099-01-01T00:00:00Z','batches':[{'ids':['i-a','i-b']} ]}
            save(path,state);lease=object.__new__(Lease)
            lease.path,lease.plan,lease.state=path,state['plan'],state
            lease.models=SimpleNamespace(StartInstancesRequest=lambda **kw:kw,StopInstancesRequest=lambda **kw:kw)
            lease._refresh=lambda:[{'InstanceId':'i-a','Status':'Stopped'},{'InstanceId':'i-b','Status':'Running'}]
            calls=[];lease.call=lambda name,request:calls.append((name,request))
            with patch.object(lease,'_verify_fresh_price') as price:
                self.assertEqual(lease.start()['start_requested'],['i-a']);price.assert_called_once()
            self.assertEqual(lease.stop()['stop_requested'],['i-b'])
            self.assertEqual(calls[1][1]['stopped_mode'],'KeepCharging')
            self.assertFalse(calls[1][1]['force_stop'])
            self.assertEqual(json.loads(path.read_text())['expires_at'],state['expires_at'])

    def test_expired_or_uncertain_lease_cannot_start(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lease.json';lease=object.__new__(Lease)
            lease.path,lease.plan=path,self.plan
            for expiry,batches in [('2000-01-01T00:00:00Z',[]),('2099-01-01T00:00:00Z',[{'amount':4}])]:
                save(path,{'plan':self.plan,'expires_at':expiry,'batches':batches})
                with patch.object(lease,'_refresh',side_effect=AssertionError('must not call provider')):
                    with self.assertRaises(ValueError):lease.start()

    def test_peer_rules_allow_exact_owned_private_addresses_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lease.json';plan=dict(self.plan,region='ap-southeast-1',vpc_id='vpc-owned')
            save(path,{'plan':plan,'inner_policy_drop':True,'security_group':'sg-owned',
                       'batches':[{'ids':['i-a','i-b']} ]})
            lease=object.__new__(Lease);lease.path,lease.plan=path,plan
            instances=[{'InstanceId':f'i-{name}','VpcAttributes':{'VpcId':'vpc-owned','PrivateIpAddress':{'IpAddress':[ip]}}}
                       for name,ip in [('a','10.0.0.2'),('b','10.0.0.3')]]
            lease._refresh=lambda:instances
            lease.models=SimpleNamespace(AuthorizeSecurityGroupRequest=lambda **kw:kw,
                                          AuthorizeSecurityGroupRequestPermissions=lambda **kw:kw)
            calls=[];lease.call=lambda name,request:calls.append((name,request))
            self.assertEqual(lease.peers()['peer_ips'],['10.0.0.2','10.0.0.3'])
            permissions=calls[0][1]['permissions']
            self.assertEqual([p['source_cidr_ip'] for p in permissions],['10.0.0.2/32','10.0.0.3/32'])
            self.assertTrue(all(p['port_range']=='8000/8099' and 'source_group_id' not in p for p in permissions))
            lease.peers();self.assertEqual(len(calls),1)
            instances[0]['VpcAttributes']['PrivateIpAddress']['IpAddress']=['10.0.0.4']
            with self.assertRaisesRegex(ValueError,'placement changed'):lease.peers()

    def test_peer_authorization_rejects_missing_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'lease.json';plan=dict(self.plan,region='ap-southeast-1',vpc_id='vpc-owned')
            save(path,{'plan':plan,'inner_policy_drop':True,'security_group':'sg-owned','batches':[{'ids':['i-a']} ]})
            lease=object.__new__(Lease);lease.path,lease.plan=path,plan;lease._refresh=lambda:[]
            with self.assertRaisesRegex(ValueError,'every saved owned instance'):lease.peers()


if __name__ == '__main__':
    unittest.main()
