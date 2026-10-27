"""Real Linux process-lifecycle tests using a small fake node, not consensus runs."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import common_cloud_worker as worker


@unittest.skipUnless(platform.system()=='Linux','requires Linux /proc and CPU affinity')
class LinuxWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.supervisors=[]
        original=worker.subprocess.Popen
        def remember(*args,**kwargs):
            child=original(*args,**kwargs);self.supervisors.append(child);return child
        patcher=patch.object(worker.subprocess,'Popen',side_effect=remember)
        patcher.start();self.addCleanup(patcher.stop)
        self.artifact=Path(self.temp.name);self.nonce=uuid.uuid4().hex;self.root=worker.root_for(self.nonce)
        # No networking, crypto or protocol acceptance is claimed by this fixture.
        binary=self.artifact/'node'
        binary.write_text('#!'+sys.executable+'\n'+'''import argparse,hashlib,json,os,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--protocol');p.add_argument('--config');p.add_argument('--id',type=int);a=p.parse_args()
raw=Path(a.config).read_bytes();cfg=json.loads(raw);d=Path(cfg['output_directory'])/f'node-{a.id}';d.mkdir(parents=True)
(d/'ready.json').write_text(json.dumps({'id':a.id,'pid':os.getpid(),'configuration_sha256':hashlib.sha256(raw).hexdigest()}))
print('owned fixture started',flush=True)
while True: time.sleep(.1)
''');binary.chmod(0o700)
        digest=worker.digest(binary)
        worker.write(self.artifact/'manifest.json',{'format':'delugi-common-artifact-v1','protocols':['delugi','raptr'],
                     'profile':'release','binary_sha256':digest})
        config={'addresses':[f'10.0.0.{i+1}:8000' for i in range(4)],'deployment_profile':'private-ipv4-n4-v1',
                'key_directory':str(self.root/'keys'),'output_directory':str(self.root/'replicas'),
                'arm_path':str(self.root/'arm.json'),'run_id':self.nonce*2}
        raw=json.dumps(config)
        self.request={'nonce':self.nonce,'protocol':'raptr','replica':0,'artifact':str(self.artifact),
            'binary_sha256':digest,'configuration_sha256':hashlib.sha256(raw.encode()).hexdigest(),
            'config_text':raw,'keys_hex':{'key-0.json':'01','committee.json':'02','genesis-ledger.bcs':'03'},
            'timeout_seconds':10,'budget':{'enforcement':'dedicated_host','cpus':[min(os.sched_getaffinity(0))],
                'memory_bytes':os.sysconf('SC_PAGE_SIZE')*os.sysconf('SC_PHYS_PAGES'),
                'swap_bytes':worker.resources.host_swap_bytes()}}
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.root.exists():
            report=worker.stop({'nonce':self.nonce})
            if report.get('cleanup_confirmed'):shutil.rmtree(self.root)
            else:self.fail('owned test process cleanup was not confirmed')
        for child in self.supervisors:child.wait(timeout=5)

    def wait(self,predicate,seconds=25):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            try:
                value=predicate()
                if value:return value
            except (ValueError,FileNotFoundError):pass
            time.sleep(.05)
        self.fail('Linux fixture did not reach its expected lifecycle state')

    def launch(self):
        worker.prepare(self.request);worker.start({'nonce':self.nonce})
        return self.wait(lambda:worker.ready(self.root))

    def test_confirmed_pause_is_released_and_owned_group_reaped(self):
        ready=self.launch();self.assertEqual(ready['id'],0)
        paused=worker.rpc({'action':'pause','nonce':self.nonce})
        self.assertTrue(paused['paused']);self.assertIn(paused['observed_state'],('T','t'))
        result=worker.stop({'nonce':self.nonce})
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(worker.status({'nonce':self.nonce})['process_alive'])
        self.assertIn('owned fixture started',(self.root/'node.stdout').read_text())
        with self.assertRaisesRegex(ValueError,'aborted'):worker.start({'nonce':self.nonce})

    def test_process_timeout_preserves_logs_and_resource_receipt(self):
        self.launch()
        result=self.wait(lambda:worker.status({'nonce':self.nonce}).get('resource-summary'))
        self.assertEqual(result['status'],'failed');self.assertIn('deadline expired',result['error'])
        self.assertTrue(result['cleanup_confirmed']);self.assertIn('effective_budget',result)
        self.assertGreater(result['child_peak_rss_bytes'],0)

    def test_abort_then_late_prepare_cannot_launch(self):
        worker.stop({'nonce':self.nonce})
        with self.assertRaisesRegex(ValueError,'late worker'):worker.prepare(self.request)
        self.assertFalse((self.root/'process.json').exists())

    def test_compact_membership_and_secret_isolation(self):
        cfg=json.loads(self.request['config_text'])
        cfg.update(schema=2,addresses=[f'10.0.0.{i+1}:8000' for i in range(50)],
                   deployment_profile='private-ipv4-n10-n50-v1',sustained_workload={},
                   measurement_duration_ms=60000,drain_ms=15000)
        raw=json.dumps(cfg)
        self.request.update(evaluation_profile=worker.COMPACT,config_text=raw,
                            configuration_sha256=hashlib.sha256(raw.encode()).hexdigest())
        bad=dict(self.request,keys_hex=self.request['keys_hex']|{'key-1.json':'04'})
        with self.assertRaisesRegex(ValueError,'only this replica'):worker.prepare(bad)
        self.assertFalse((self.root/'keys').exists())
        worker.prepare(self.request)
        self.assertEqual(sorted(p.name for p in (self.root/'keys').iterdir()),
                         ['committee.json','genesis-ledger.bcs','key-0.json'])

    def test_legacy_profile_cannot_silently_expand_to_fifty(self):
        cfg=json.loads(self.request['config_text']);cfg['addresses']*=12
        raw=json.dumps(cfg);self.request.update(config_text=raw,configuration_sha256=hashlib.sha256(raw.encode()).hexdigest())
        with self.assertRaisesRegex(ValueError,'committee'):worker.prepare(self.request)


if __name__=='__main__':unittest.main()
