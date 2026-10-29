import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import compact_campaign
import run_raptr_sustained as runner


class SustainedTests(unittest.TestCase):
    def test_window_traffic_excludes_drain_and_keeps_shutdown_cost(self):
        def row(target,bytes):
            return {'target_us':target,'sample_start_us':target,'sample_end_us':target+1,
                    'counters':{'data_bytes_read':bytes,'peers':{'1':{'ack_bytes_read':2,
                        'ack_bytes_written':3,'layers':{'ordering':{'data_bytes_written':bytes}}}}}}
        body={'epoch_us':100,'deadline_us':2100,'traffic_windows':{
            'before':row(100,10),'after':row(1100,30),'after_shutdown':row(2100,50)}}
        cfg={'measurement_duration_ms':1}
        result=runner.traffic_windows(body,cfg)
        self.assertEqual(result['measurement']['written_bytes'],20)
        self.assertEqual(result['through_shutdown']['written_bytes'],53)
        body['traffic_windows']['after']['counters']['data_bytes_read']=0
        with self.assertRaises(ValueError):runner.traffic_windows(body,cfg)
    def config(self,**kwargs):
        with patch.object(runner.native,'unused_addresses',side_effect=lambda n:[f'127.0.0.1:{8000+i}' for i in range(n)]):
            return runner.make_config('/tmp/sustained-test',**kwargs)

    def test_exact_global_population_including_fifty_and_silent_origin(self):
        for n in (4,10,50):
            cfg=self.config(nodes=n,rate=7,duration_ms=1000,case='silent-first-leader')
            self.assertEqual(sum(cfg['finite_workload']['counts']),7)
            self.assertEqual(cfg['finite_workload']['counts'][1],0)
            self.assertNotIn(1,cfg['sustained_workload']['honest_origins'])
            self.assertEqual(cfg['schema'],2)
            self.assertEqual(cfg['finite_workload']['interval_us'],0)

    def test_finite_envelopes_reject_before_launch(self):
        for kw in ({'nodes':49},{'rate':80001},{'duration_ms':60001},{'drain_ms':15001},
                   {'useful_bytes':4097},{'case':'unreviewed-fault'},{'ingress_capacity':0}):
            with self.assertRaises(ValueError):self.config(**kw)
        self.assertEqual(sum(self.config(case='empty')['finite_workload']['counts']),0)

    def test_bounded_complete_journal_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'rows';p.write_text('{"sequence":0}\n{"sequence":1}\n')
            self.assertEqual(len(list(runner.journal(p))),2)
            with self.assertRaises(ValueError):list(runner.journal(p,max_rows=1))
            with self.assertRaises(ValueError):list(runner.journal(p,max_line=4))
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(ValueError):list(runner.journal(link))
            p.write_text('{"sequence":0}')
            with self.assertRaises(ValueError):list(runner.journal(p))

    def test_bound_files_rejects_mutated_planned_identities(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);node=root/'node-0';node.mkdir()
            files=[]
            for name in ('planned.jsonl','requests.jsonl','output.jsonl','effective-profile.json','workload-manifest.json'):
                p=node/name;p.write_text('{}\n');files.append({'name':name,**runner.native.file_record(p)})
            (node/'final.json').write_text(json.dumps({'body':{'files':files}}))
            cfg={'output_directory':str(root)}
            self.assertEqual(len(runner.bound_files(cfg,[0])),6)
            (node/'planned.jsonl').write_text('{"foreign":1}\n')
            with self.assertRaises(ValueError):runner.bound_files(cfg,[0])

    def test_latency_trace_is_explicit_bounded_and_receipt_bound(self):
        self.assertNotIn('latency_trace', self.config())
        cfg=self.config(node_options={'latency_trace':{'max_events':100000}})
        self.assertEqual(cfg['latency_trace'], {'max_events':100000})
        for value in (0,1000001,True):
            with self.assertRaises(ValueError):
                self.config(node_options={'latency_trace':{'max_events':value}})
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);node=root/'node-0';node.mkdir()
            files=[]
            for name in ('planned.jsonl','requests.jsonl','output.jsonl','effective-profile.json',
                         'workload-manifest.json','latency-trace.json'):
                path=node/name;path.write_text('{}\n')
                files.append({'name':name,**runner.native.file_record(path)})
            (node/'final.json').write_text(json.dumps({'body':{'files':files}}))
            cfg['output_directory']=str(root)
            self.assertEqual(len(runner.bound_files(cfg,[0])),7)
            (node/'latency-trace.json').write_text('{"changed":true}\n')
            with self.assertRaises(ValueError):runner.bound_files(cfg,[0])


if __name__=='__main__':unittest.main()
