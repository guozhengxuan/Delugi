from pathlib import Path
from types import SimpleNamespace as N
from unittest.mock import patch
import tempfile
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmark'))
from bench.access import update

class FabricAccess(unittest.TestCase):
    def test_access_is_single_ip_owned_group_only_and_preserves_price_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);events=[];plan={'region':'test','controller_cidr':'192.0.2.1/32'}
            lease=N(plan=plan,state={'run_id':'run','security_group':'sg-one'},path=root/'lease')
            lease.models=N(**{k:N for k in ('DescribeSecurityGroupsRequest','AuthorizeSecurityGroupRequest','AuthorizeSecurityGroupRequestPermissions','RevokeSecurityGroupRequest','RevokeSecurityGroupRequestPermissions')})
            def call(method,args):
                events.append((method,args))
                return {'SecurityGroups':{'SecurityGroup':[{'SecurityGroupId':'sg-one','SecurityGroupName':'Delugi-run','Tags':{'Tag':[{'TagKey':'DelugiRun','TagValue':'run'}]}}]}}
            lease.call=call
            manager=N(base=root,load=lambda:{'leases':[str(root/'lease')]})
            with patch('bench.access.Settings',return_value=N(root=root)),patch('bench.access.InstanceManager',return_value=manager),patch('bench.access.cloud.Lease',return_value=lease),patch('bench.access.cloud.save'):
                result=update('settings','192.0.2.2/32')
            self.assertEqual(lease.plan['controller_cidr'],'192.0.2.1/32')
            self.assertEqual(result[0]['controller_cidr'],'192.0.2.2/32')
            self.assertEqual([e[0] for e in events],['describe_security_groups','authorize_security_group','revoke_security_group'])
            for _,args in events[1:]:
                self.assertEqual(args.security_group_id,'sg-one');self.assertEqual(args.permissions[0].port_range,'22/22')

    def test_broad_or_ipv6_rule_rejected_before_api(self):
        for cidr in ('0.0.0.0/0','192.0.2.0/24','::1/128'):
            with self.assertRaises(ValueError):update('missing',cidr)

if __name__=='__main__':unittest.main()
