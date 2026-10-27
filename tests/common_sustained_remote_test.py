import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import common_sustained_remote as remote
import campaign_adapters


class CommonLifecycle(unittest.TestCase):
    def run_fixture(self,case='healthy',fail_verify=False):
        c=json.loads((ROOT/'benchmarks/configs/compact-campaign.native-services.json').read_text())
        selected=campaign_adapters.resolve(c,'raptr',4,1001,case)
        prepared={};ready=set();events=[];verified={};parent=self
        hosts=[{'replica':i,'advertised':f'10.0.0.{i+1}:8000','artifact':{'directory':'/publication','binary_sha256':'a'*64},'budget':{}} for i in range(4)]
        class Connection:
            def __init__(self,h):self.i=h['replica']
            def preflight(self):return {'verified':True}
            def python(self):return '/usr/bin/python3'
            def command(self,*a,**k):return SimpleNamespace(returncode=0)
            def rpc(self,r):
                events.append((self.i,r['action']))
                if r['action']=='keygen':return {'files_hex':{'committee.json':'7b7d','genesis-ledger.bcs':'00',**{f'key-{i}.json':'01' for i in range(4)}}}
                if r['action']=='prepare':
                    parent.assertEqual(set(r['keys_hex']),{f'key-{self.i}.json','committee.json','genesis-ledger.bcs'})
                    prepared[self.i]=copy.deepcopy(r);return {'prepared':True}
                if r['action']=='ready':ready.add(self.i);return {'id':self.i,'configuration_sha256':prepared[self.i]['configuration_sha256']}
                if r['action']=='arm':
                    parent.assertEqual(ready,set(range(4)))
                    return {'epoch_us':(self.i+1)*10**12}
                if r['action']=='pause':return {'paused':True,'observed_state':'T'}
                if r['action']=='status':return {'resource-summary':{'status':'completed','cleanup_confirmed':True}}
                if r['action']=='verify':
                    if fail_verify and self.i==2:raise ValueError('invalid native certificate')
                    verified[self.i]={'verified':True};return verified[self.i]
                if r['action']=='abort':return {'cleanup_confirmed':True}
                return {'started':True}
            def collect(self,nonce,path,compact=False):
                parent.assertTrue(compact);files=Path(path)/'files';files.mkdir(parents=True)
                (files/'config.json').write_text(prepared[self.i]['config_text'])
                (files/'verification.json').write_text(json.dumps(verified[self.i]))
                (files/'replicas'/f'node-{self.i}').mkdir(parents=True)
                return {'collected':True}
        class Network:
            def __init__(self,*a):self.network_evidence={'test':'no network operations'}
            def configure_network(self):return self.network_evidence
            def clear_network(self):self.network_evidence['cleared']=True
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'run'
            with patch.object(remote,'NativeNetwork',Network),patch.object(remote.raptr,'bound_files',return_value={}),patch.object(remote.raptr,'normalize',return_value={'verified_test_reduction':True}) as normal:
                result=remote.run_raptr(selected,{'hosts':hosts},out,Connection)
                if not fail_verify:
                    cfg=normal.call_args.args[0]
                    self.assertEqual(cfg,json.loads((out/'config.json').read_text()))
                    self.assertTrue(cfg['output_directory'].startswith('/tmp/delugi-cloud-'))
                    self.assertEqual(normal.call_args.kwargs['replica_directory'],out/'replicas')
                    self.assertFalse(list(out.rglob('key-*.json')))
            return result,events
    def test_prepare_all_before_host_local_arm_and_collect_without_rewriting_config(self):
        result,events=self.run_fixture();self.assertEqual(result['status'],'completed')
        self.assertEqual(len(result['arm']),4)
        self.assertEqual(len({r['epoch_us'] for r in result['arm'].values()}),4)
        self.assertTrue(result['network']['cleared'])
    def test_native_verification_failure_still_aborts_every_owned_host(self):
        result,events=self.run_fixture(fail_verify=True)
        self.assertEqual(result['status'],'failed');self.assertIn('invalid native certificate',result['error'])
        self.assertEqual({i for i,a in events if a=='abort'},set(range(4)))
        self.assertNotIn('collection',result)
    def test_silent_native_leader_is_paused_before_arm_and_excluded_from_credit(self):
        result,events=self.run_fixture('silent-first-leader');self.assertEqual(result['status'],'completed')
        self.assertEqual(result['correct_replicas'],[0,2,3]);self.assertNotIn(1,result['arm'])
        first_arm=min(i for i,(_,action) in enumerate(events) if action=='arm')
        self.assertLess(events.index((1,'pause')),first_arm)
        self.assertEqual(events.count((1,'pause')),2)

if __name__=='__main__':unittest.main()
