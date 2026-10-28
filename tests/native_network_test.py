import sys
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from native_network import NativeNetwork, observed_wan


class AggregateController(unittest.TestCase):
    def fixture(self,fail=False):
        n=object.__new__(NativeNetwork);n.aggregate=100;n.nonce='a'*32
        n.inventory={'netem':{'delay_ms':10,'rate_mbps':100}}
        n.hosts={i:{'replica':i,'network_interface':'eth0'} for i in range(4)}
        n.netem_hosts=[];n.network_evidence={};n.events=[]
        n.protocol_endpoints=lambda h:[{'ip':f'10.0.0.{h["replica"]+1}','port':9000+j} for j in (0,1,5)]
        n.start_echoes=lambda phase:n.events.append(('echo',phase)) or [phase]
        n.stop_echoes=lambda items:n.events.append(('stop_echo',items))
        calls=[]
        def calibrate():
            calls.append(1);return {(0,1,0):{'median':22 if len(calls)==2 else 2}}
        n.calibrate_ring=calibrate;n.calibration_records=lambda rows:rows
        def rpc(h,r):
            n.events.append((r['action'],h['replica'],r))
            if fail and r['action']=='configure' and h['replica']==1:raise ValueError('failed second install')
            if r['action']=='configure':return {'phase':'active','tree':{'owned':True}}
            if r['action']=='clear':return {'phase':'cleared','cleanup':{'restored_default':True}}
            return {'phase':'active'}
        n.egress_rpc=rpc
        return n
    def test_one_shared_rate_class_covers_every_peer_role_and_ack_port(self):
        n=self.fixture();result=n.configure_network()
        calls=[e for e in n.events if e[0]=='configure'];self.assertEqual(len(calls),4)
        for _,i,r in calls:
            self.assertEqual(r['rate_mbps'],100);self.assertEqual(r['local_ports'],[9000,9001,9005])
            self.assertEqual(len(r['peers']),9);self.assertFalse(any(p['ip']==f'10.0.0.{i+1}' for p in r['peers']))
        self.assertFalse(result['bandwidth_calibrated']);self.assertFalse(result['loaded_delay_calibrated'])
        n.clear_network();self.assertEqual(n.netem_hosts,[])
        self.assertTrue(all(r['restored'] for r in n.network_evidence['cleanup_calibration']))
    def test_partial_install_clears_attempted_hosts_and_always_stops_echoes(self):
        n=self.fixture(fail=True)
        with self.assertRaisesRegex(ValueError,'second install'):n.configure_network()
        self.assertEqual([e[1] for e in n.events if e[0]=='clear'],[0,1])
        self.assertEqual(n.netem_hosts,[]);self.assertEqual(n.events[-1][0],'stop_echo')
    def test_unconfirmed_clear_is_an_error_and_retains_retry_targets(self):
        n=self.fixture();n.configure_network();old=n.egress_rpc
        n.egress_rpc=lambda h,r:({'phase':'cleared','cleanup':{'restored_default':False}} if r['action']=='clear' else old(h,r))
        with self.assertRaisesRegex(RuntimeError,'restoration unconfirmed'):n.clear_network()
        self.assertEqual(len(n.netem_hosts),4)

    def test_observed_wan_records_rtt_without_mutating_queues_or_demanding_fixed_delay(self):
        n=self.fixture();n.inventory['netem']={'mode':'observed-wan-v1','delay_ms':0,'rate_mbps':20}
        n.calibrate_ring=lambda:{(0,1,0):{'median':317.8}}
        result=n.configure_network();self.assertEqual(result['backend'],'observed-provider-wan-v1')
        self.assertFalse(result['synthetic_network_changes'])
        self.assertEqual([e[0] for e in n.events],['echo','stop_echo'])
        n.clear_network();self.assertEqual(n.netem_hosts,[])
        self.assertFalse(n.network_evidence['cleanup']['synthetic_network_changes'])

    def test_wan_mode_never_silently_ignores_requested_impairments(self):
        for settings in ({'mode':'unknown'}, {'mode':'observed-wan-v1','delay_ms':10,'rate_mbps':20},
                         {'mode':'observed-wan-v1','loss_percent':1,'rate_mbps':20},
                         {'mode':'observed-wan-v1'}):
            with self.subTest(settings=settings),self.assertRaises(ValueError):observed_wan(settings)

if __name__=='__main__':unittest.main()
