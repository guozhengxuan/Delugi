from pathlib import Path
import hashlib
import json
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'benchmark'))
from bench.logs import LogParser,ParseError
from bench.plot import render
from bench import build


class FabricLogs(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.plan={'plan_sha256':'a'*64,'config':{'duration':{'measure_s':60,'drain_s':15},'useful_transaction_bytes':1},'trials':[{'id':'one'},{'id':'two'}]}
        q={'value_ms':None,'lower_bound_ms':500,'status':'censored'}
        result={'cohort':{'endpoint_contract':'local clock','scheduled_to_output':dict.fromkeys(('p50','p95','p99'),q),
                'admission_to_output':dict.fromkeys(('p50','p95','p99'),q),'window':{'completion_count':30},'scheduled':100,'completed':30}}
        self.metrics={'scheduled':100,'completed':30,'goodput_tps':.5}
        p=self.root/'trials/one/result.json';p.parent.mkdir(parents=True);p.write_text(json.dumps(result))
        self.state={'identity':{'plan_sha256':'a'*64},'status':'completed','rows':[
            {'trial_id':'one','protocol':'delugi','nodes':4,'case':'healthy','rate':100,'status':'completed','result':{'sha256':hashlib.sha256(p.read_bytes()).hexdigest()},'metrics':self.metrics},
            {'trial_id':'two','protocol':'raptr','nodes':4,'case':'silent-first-leader','rate':100,'status':'failed','error':'retained failure'}]}
        self.save()
        self.mock=patch('campaign_execute.metrics',return_value=self.metrics);self.mock.start();self.addCleanup(self.mock.stop)

    def save(self):
        (self.root/'state.json').write_text(json.dumps(self.state));(self.root/'plan.json').write_text(json.dumps(self.plan))

    def test_censored_and_failed_runs_are_retained_and_rendered(self):
        parser=LogParser(self.root);out=parser.export()
        self.assertIn('>=500.00',out['text']);self.assertIn('latency',out['text'])
        self.assertEqual(len(parser.rows),2)
        self.assertIsNone(parser.rows[0]['end_to_end_p50_ms'])
        result=render(out['summary'],self.root/'figures')
        self.assertEqual(result['rate_points'],1)
        self.assertTrue(all(Path(p).stat().st_size>100 for p in result['files']))

    def test_tampered_result_and_cached_metrics_are_rejected(self):
        self.state['rows'][0]['metrics']={};self.save()
        with self.assertRaisesRegex(ParseError,'metrics'):LogParser(self.root)
        self.state['rows'][0]['metrics']=self.metrics;self.save()
        (self.root/'trials/one/result.json').write_text('{}')
        with self.assertRaisesRegex(ParseError,'changed'):LogParser(self.root)

    def test_download_keeps_raw_logs_excludes_keys_and_refuses_overwrite(self):
        for name in ('keys/secret.json','artifact/build.json','trials/one/node.stdout'):
            p=self.root/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_text('data')
        parser=LogParser(self.root);out=parser.download()
        with tarfile.open(out['archive']) as archive:
            names=archive.getnames()
        self.assertIn('trials/one/node.stdout',names);self.assertNotIn('keys/secret.json',names);self.assertNotIn('artifact/build.json',names)
        with self.assertRaisesRegex(ParseError,'new log archive'):parser.download()

    def test_duplicate_and_unplanned_trial_rejected(self):
        self.state['rows'].append(self.state['rows'][1]);self.save()
        with self.assertRaisesRegex(ParseError,'duplicate'):LogParser(self.root)


if __name__=='__main__':unittest.main()
