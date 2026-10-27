"""Command scope, aggregate budget and owned cleanup without privileged IO."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import linux_egress as e


def request(n=4):
    return {'action':'configure','nonce':'ab'*16,'interface':'eth0',
            'peers':[{'ip':f'10.0.0.{i+1}','port':9000} for i in range(n-1)],
            'local_ports':[9000,9001], 'delay_ms':10,'rate_mbps':100}


class Kernel:
    def __init__(self):
        self.before=[{'kind':'fq_codel','handle':'0:','root':True}]
        self.q=copy.deepcopy(self.before);self.classes=[];self.filters=[];self.log=[];self.index=2
    def run(self,a):
        self.log.append(a)
        if a[:3]==['ip','-j','-d']:return json.dumps([{'ifname':'eth0','ifindex':self.index}])
        if a[:3]==['tc','-s','-j']:
            return json.dumps({'qdisc':self.q,'class':self.classes,'filter':self.filters}[a[3]])
        if a[:3]==['tc','qdisc','replace']:
            self.q=[{'kind':'htb','handle':a[a.index('handle')+1],'root':True}]
        elif a[:3]==['tc','class','add']:
            self.classes.append({'kind':'htb','handle':a[a.index('classid')+1],'options':{'rate':a[a.index('rate')+1]}})
        elif a[:3]==['tc','qdisc','add']:
            self.q.append({'kind':'netem','handle':a[a.index('handle')+1],'parent':a[a.index('parent')+1],'options':{'delay':a[a.index('delay')+1]}})
        elif a[:3]==['tc','filter','add']:
            self.filters.append({'kind':'flower','pref':int(a[a.index('pref')+1]),'options':{'keys':a[a.index('dst_ip'):], 'classid':a[-1]}})
        elif a[:3]==['tc','qdisc','del']:
            self.q=copy.deepcopy(self.before);self.classes=[];self.filters=[]
        else:raise AssertionError(a)
        return ''


class EgressTests(unittest.TestCase):
    def test_one_aggregate_rate_class_and_ack_scope_at_fifty(self):
        for n in (4,10,50):
            c=e.commands(e.validate_request(request(n)),0x8000)
            rates=[r for r in c if r[:3]==['tc','class','add'] and '100mbit' in r]
            self.assertEqual(len(rates),1)
            filters=[r for r in c if 'flower' in r]
            self.assertEqual(len(filters),3*(n-1))
            self.assertTrue(all(r[-1]=='8000:10' for r in filters))
            self.assertTrue(all('22' not in r for r in filters))
            self.assertTrue(any('src_port' in r for r in filters))
            self.assertTrue(any('dst_port' in r for r in filters))
    def test_validation_rejects_injection_bad_rates_and_management_ports(self):
        for changes in ({'rate_mbps':0},{'rate_mbps':True},{'interface':'eth0;whoami'},
                        {'local_ports':[22]},{'queue_packets':10001},{'burst_bytes':1},
                        {'action':'clear','rate_mbps':100}):
            with self.subTest(changes=changes),self.assertRaises(e.base.NetemError):
                e.validate_request(dict(request(),**changes))
    def test_idempotent_install_counter_changes_and_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            kernel=Kernel();controller=e.Controller(Path(d)/'state',kernel.run)
            self.assertEqual(controller.dispatch(request())['phase'],'active')
            self.assertEqual(controller.dispatch(request())['phase'],'active')
            kernel.q[0]['bytes']=9000
            self.assertEqual(controller.dispatch({'action':'status','nonce':'ab'*16})['phase'],'active')
            self.assertEqual(controller.dispatch({'action':'clear','nonce':'ab'*16})['phase'],'cleared')
            self.assertEqual(kernel.q,kernel.before)
            self.assertEqual(controller.dispatch({'action':'clear','nonce':'ab'*16})['phase'],'cleared')
    def test_other_root_and_interface_reuse_are_never_deleted(self):
        for mutation in ('root','configuration','interface'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as d:
                k=Kernel();c=e.Controller(Path(d)/'state',k.run);c.dispatch(request())
                if mutation=='root':k.q[0]['handle']='1234:'
                elif mutation=='configuration':k.classes[-1]['options']['rate']='200mbit'
                else:k.index=3
                with self.assertRaises(e.base.NetemError):c.dispatch({'action':'clear','nonce':'ab'*16})
                self.assertFalse(any(r[:3]==['tc','qdisc','del'] for r in k.log))
    def test_custom_existing_root_is_refused_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            k=Kernel();k.q[0]['handle']='1:'
            with self.assertRaises(e.base.NetemError):e.Controller(Path(d)/'state',k.run).dispatch(request())
            self.assertFalse(any(r[:3]==['tc','qdisc','replace'] for r in k.log))

    def test_failed_install_retains_confirmed_prefix_and_can_clean_it(self):
        with tempfile.TemporaryDirectory() as d:
            k=Kernel()
            def run(a):
                if a[:3]==['tc','filter','add']:raise e.base.NetemError('injected install failure')
                return k.run(a)
            c=e.Controller(Path(d)/'state',run)
            with self.assertRaisesRegex(e.base.NetemError,'injected'):c.dispatch(request())
            self.assertEqual(c.dispatch({'action':'clear','nonce':'ab'*16})['phase'],'cleared')
            self.assertEqual(k.q,k.before)

if __name__=='__main__':unittest.main()
