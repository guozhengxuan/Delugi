import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import remote_native as remote
from baselines import simpleit, simpleit_remote


@unittest.skipUnless(os.environ.get('SIMPLEIT_REMOTE_RECEIPT') and os.environ.get('SIMPLEIT_REMOTE_VARIANT'),
    'requires a pinned native Simple-IT executable')
class NativeRemoteLifecycle(unittest.TestCase):
    def test_real_native_prepare_arm_freeze_verify_export_and_secret_sealing(self):
        variant=os.environ['SIMPLEIT_REMOTE_VARIANT']
        binary,build=simpleit.verify_build(os.environ['SIMPLEIT_REMOTE_RECEIPT'],variant)
        output=os.environ.get('SIMPLEIT_REMOTE_OUTPUT')
        if output:
            base=Path(output).resolve();base.mkdir(parents=True,exist_ok=False)
        else:
            tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);base=Path(tmp.name)
        # These are the exact remote port assignments. Refuse an occupied port.
        sockets=[]
        try:
            for port in range(9000,9024):
                s=socket.socket();s.bind(('127.0.0.1',port));sockets.append(s)
        finally:
            for s in sockets:s.close()
        cfg=remote.native.settings({'population_profile':'compact-n10-n50-v1','rate':1001,'duration':2,
            'drain':1,'warmup':0,'batch_bytes':65536,'useful_bytes':128},4,variant)
        ceremony=base/'ceremony';ceremony.mkdir()
        nonce='a'*32
        selected=simpleit_remote.generate(variant,ceremony,['127.0.0.1']*4,{'node':str(binary)},cfg,nonce)
        roots=[];requests=[]
        for i in range(4):
            root=base/f'host-{i}';root.mkdir();roots.append(root)
            for path in selected[i]:
                dest=root/path.relative_to(ceremony);dest.parent.mkdir(parents=True,exist_ok=True)
                raw=path.read_bytes()
                if path.suffix=='.json':raw=raw.replace(str(ceremony).encode(),str(root).encode())
                dest.write_bytes(raw);dest.chmod(0o600)
            self.assertEqual(len(list((root/'fixture/private-keys').glob('*.json'))),1)
            self.assertFalse((root/'fixture/private-tls/controller-ca.key').exists())
            requests.append({'protocol':variant,'nonce':nonce,'plan_sha256':'b'*64,'settings':cfg,
                'host':{'replica':i,'native_binaries':{'node':{'path':str(binary)}}}})
        archive=remote.archive_selected(ceremony,[str(p.relative_to(ceremony)) for p in selected[0]],
            ceremony/'configuration-0.tar','native-configuration',{'replica':0,'nonce':nonce})
        with patch.object(remote,'checked_root',return_value=ceremony):
            sealed=remote.rpc(requests[0]|{'action':'seal_configuration','sha256':archive['sha256']})
            self.assertTrue(sealed['sealed'])
            self.assertEqual(remote.rpc(requests[0]|{'action':'seal_configuration','sha256':archive['sha256']}),sealed)
        self.assertEqual(len(list((ceremony/'fixture/private-keys').glob('*.json'))),1)
        self.assertFalse((ceremony/'fixture/private-tls/controller-ca.key').exists())
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures=[pool.submit(simpleit_remote.run_host,r,root,{'test':'native macOS lifecycle; Linux resource wrapper separately tested'}) for r,root in zip(requests,roots)]
            try:
                deadline=time.monotonic()+20
                while not all((root/'readiness.json').exists() for root in roots):
                    self.assertFalse(any(f.done() for f in futures),'worker exited before readiness')
                    self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                for request,root in zip(requests,roots):
                    remote.publish_startup(root,'arm.json',remote.startup_identity(request)|{'state':'arm_requested',
                        'readiness_sha256':remote.prep.sha(root/'readiness.json')})
                self.assertEqual([f.result(timeout=300) for f in futures],[0]*4)
            finally:
                for request,root in zip(requests,roots):
                    if not (root/'abort.json').exists():remote.publish_startup(root,'abort.json',remote.startup_identity(request)|{'state':'abort_requested'})
        checked=simpleit_remote.verify_collected(base,cfg,set(range(4)))
        self.assertTrue(checked['exact_native_prefix_agreement'])
        archives=[]
        for i,root in enumerate(roots):
            names=simpleit_remote.evidence_files(root,i)
            self.assertTrue(any(name.endswith('final.json') for name in names))
            self.assertFalse(any('/private-' in name for name in names))
            archives.append(remote.native.native_cohort_store.ShardedArchive(root/'cohorts/index.json'))
        result=remote.native.reduce_archives(archives,cfg,base)
        self.assertEqual(result['cohort']['scheduled'],2002)
        (base/'acceptance.json').write_text(json.dumps({'status':'passed','build':build['identity'],
            'binary_sha256':build['binary']['sha256'],'scheduled':2002,'native_output':checked,'comparison_eligible':False},indent=2)+'\n')

if __name__=='__main__':unittest.main()
