from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import latency_decomposition as d


def event(name, at, round=4, **detail):
    return {'event':name, 'at_us':at, 'round':round, 'detail':detail}


class Decomposition(unittest.TestCase):
    def setUp(self):
        self.events = [event('proposal_validated', 5, digest='d'),
                       event('classified', 10, status={'Commit':'d'}, direct=True),
                       event('prefix_release', 14, digest='d'), event('payload_ready',18)]
        self.request = {'id':'tx','origin':1,'scheduled_us':0,'admitted_us':1,'rejected_us':None}
        self.output = {'id':'tx','origin':1,'exact_batch_id':'batch','materialized_us':20}
        self.sealed = event('batch_sealed',3, exact_batch_id='batch')
        self.batch = event('batch_materialized',19,exact_batch_id='batch')

    def test_disjoint_intervals_sum_to_the_same_request_endpoint(self):
        stages=d.request_stages(self.request,self.output,self.sealed,self.batch,{4:self.events})
        self.assertEqual(stages,[2,2,5,4,4,2])
        self.assertEqual(sum(stages),19)

    def test_forked_proposal_is_not_used_and_missing_events_are_not_zero_filled(self):
        events=[event('proposal_validated',4,digest='other'),*self.events]
        self.assertEqual(d.request_stages(self.request,self.output,self.sealed,self.batch,{4:events})[1],2)
        with self.assertRaisesRegex(ValueError,'missing_proposal'):
            d.request_stages(self.request,self.output,self.sealed,self.batch,{4:self.events[1:]})
        with self.assertRaisesRegex(ValueError,'nonsequential'):
            d.request_stages(self.request,self.output,event('batch_sealed',8),self.batch,{4:self.events})

    def archive(self):
        outer=self
        class Archive:
            index_sha256='pin'
            ledgers={1:{'window_start_us':0,'window_end_us':100,'manifest':{'body':{'instance':[1]*32}}}}
            def rows(self,replica,stream):
                if stream=='requests':return iter([outer.request,{**outer.request,'id':'unfinished'},
                                                   {**outer.request,'id':'missing'}])
                return iter([outer.output,{**outer.output,'id':'missing','exact_batch_id':'unknown'}])
        return Archive()

    def test_incomplete_cohort_coverage_and_run_binding(self):
        with tempfile.TemporaryDirectory() as root, patch.object(d,'ShardedArchive',return_value=self.archive()):
            path=Path(root)/'replica-1.json'
            data={'schema':'delugi-causal-trace-v1','replica':1,'dropped':0,'run_error':None,
                  'events':[event('run_context',0,0,instance=[1]*32),self.sealed,*self.events,self.batch]}
            path.write_text(json.dumps(data))
            report=d.analyze('index',root)
            self.assertEqual((report['scheduled'],report['completed'],report['covered']),(3,2,1))
            self.assertEqual(report['excluded'],{'unfinished_or_rejected':1,'missing_exact_batch_boundary':1})
            self.assertAlmostEqual(sum(s['mean_ms'] for s in report['stages']),.019)
            data['events'][0]['detail']['instance']=[2]*32;path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'different runs'):d.analyze('index',root)
            data['dropped']=1;path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'incomplete'):d.analyze('index',root)

    def test_collector_checks_page_identity_and_stability(self):
        class Controller:
            corrupt=False
            def request(self,replica,kind,offset,limit):
                return {'reply':{'data':{'replica':replica,'total':2,'offset':offset,
                    'dropped':int(self.corrupt and offset>0),'events':[{'at_us':offset}],
                    'next_offset':offset+1 if offset==0 else None}}}
        with tempfile.TemporaryDirectory() as root:
            controller=Controller()
            result=d.collect(controller,[1],Path(root)/'good')
            self.assertTrue(result['complete'])
            self.assertEqual(result['files'][0]['events'],2)
            controller.corrupt=True
            with self.assertRaisesRegex(ValueError,'changed'):
                d.collect(controller,[1],Path(root)/'bad')

    def test_missing_coverage_is_not_drawn_as_a_zero_latency_bar(self):
        with self.assertRaisesRegex(ValueError,'empty instrumented cohort'):
            d.render({'empty':{'covered':0}},'/unused/figure.png')


if __name__=='__main__':unittest.main()
