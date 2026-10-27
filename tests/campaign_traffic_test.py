from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import campaign_traffic as traffic


class Traffic(unittest.TestCase):
    def test_missing_window_is_not_replaced_with_total_run_traffic(self):
        r=traffic.normalize('delugi',{'total_run_tcp_written_bytes':500})
        self.assertIsNone(r['traffic_measurement_written_bytes'])
    def test_native_roles_counted_once_and_absent_leader_excluded(self):
        r={'hosts':{'0':{'result':{'traffic':{'boundary':'native worker links included','processes':[
            {'written_bytes':400,'window_written_bytes':200},{'written_bytes':300,'window_written_bytes':100}]}}},
                    '1':{'result':{'cohort_excluded':True}}}}
        out=traffic.normalize('autobahn',r)
        self.assertEqual(out['traffic_measurement_written_bytes'],300)
        self.assertEqual(out['traffic_sampled_total_written_bytes'],700)
        self.assertIn('worker links included',out['traffic_boundary'])
        r['hosts']['0']['result']['traffic']['processes'][0]['window_written_bytes']=401
        with self.assertRaisesRegex(ValueError,'exceeds'):traffic.normalize('autobahn',r)
    def test_mysticeti_keeps_scrape_window_and_retains_regression_failure(self):
        t={'boundary':'native streams',**{k:{'values':{'benchmark_tcp_written_bytes':v}} for k,v in [('before',100),('after',350),('final',500)]}}
        r={'hosts':{'0':{'result':{'traffic':t}}}}
        self.assertEqual(traffic.normalize('mysticeti-c',r)['traffic_measurement_written_bytes'],250)
        t['after']['values']['benchmark_tcp_written_bytes']=50
        with self.assertRaisesRegex(ValueError,'regressed'):traffic.normalize('mysticeti-c',r)
    def test_raptr_late_boundary_is_visible(self):
        r={'reduction':{'traffic':{'0':{'available':True,'measurement':{'written_bytes':10},
            'through_shutdown':{'written_bytes':30},'window_aligned':False}}}}
        self.assertEqual(traffic.normalize('raptr',r)['traffic_window_quality'],'late native boundary samples')
    def test_simpleit_uses_tls_inclusive_window_counters(self):
        r={'hosts':{'0':{'result':{'traffic':{'counters':{'written_bytes':100,'window_written_bytes':60},'boundary':'includes TLS'}}}}}
        out=traffic.normalize('simpleit-dispersed',r)
        self.assertEqual(out['traffic_measurement_written_bytes'],60);self.assertEqual(out['traffic_boundary'],'includes TLS')

if __name__=='__main__':unittest.main()
