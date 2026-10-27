"""Opt-in real native lifecycle test; no SSH, provider or Linux shaper claim."""
import concurrent.futures
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import remote_native as remote


@unittest.skipUnless(os.environ.get('NATIVE_ABSENT_PROTOCOL'),'requires explicitly selected local native executable')
class AbsentLeader(unittest.TestCase):
    def test_real_native_first_leader_absence_and_verified_output(self):
        p=os.environ['NATIVE_ABSENT_PROTOCOL'];self.assertIn(p,('autobahn','mysticeti'))
        base=Path(os.environ['NATIVE_ABSENT_OUTPUT']).resolve();base.mkdir(parents=True,exist_ok=False)
        binary=ROOT/'benchmarks/.cache'/f'{p}-target/release'/('node' if p=='autobahn' else 'mysticeti')
        if p=='autobahn':
            stamp=json.loads((binary.parent.parent/'build-provenance.json').read_text())
            node=next(r for r in stamp['binaries'] if Path(r['path']).name=='node')
            self.assertEqual(remote.prep.sha(binary),node['sha256'])
        else:
            stamp=json.loads((binary.parent.parent/'build-provenance.json').read_text())
            self.assertEqual(remote.prep.sha(binary),stamp['binary_sha256'])
        seconds=int(os.environ.get('NATIVE_ABSENT_SECONDS','3'))
        cfg=remote.native.settings({'population_profile':'compact-n10-n50-v1','case':'silent-first-leader',
            'faulty':[1],'rate':1001,'duration':seconds,'drain':3,'warmup':0,'useful_bytes':128,'startup_seconds':3},4,p)
        ceremony=base/'ceremony';ceremony.mkdir();ips=['127.0.0.1']*4
        selected=remote.native.generate(p,ceremony,ips,{binary.name:str(binary)},cfg,'a'*32)
        roots=[];requests=[];endpoints=remote.native.endpoints(p,ips)
        for i in range(4):
            root=base/f'host-{i}';root.mkdir();roots.append(root)
            for source in selected[i]:
                destination=root/source.relative_to(ceremony);destination.parent.mkdir(parents=True,exist_ok=True)
                raw=source.read_bytes().replace(str(ceremony).encode(),str(root).encode());destination.write_bytes(raw)
            requests.append({'protocol':p,'nonce':'a'*32,'plan_sha256':'b'*64,'settings':cfg,'ips':ips,
                'endpoint':endpoints[i],'host':{'replica':i,'native_binaries':{binary.name:{'path':str(binary)}}}})
        with patch.object(remote,'checked_root',side_effect=lambda r:roots[r['host']['replica']]),patch.object(remote,'check_artifacts',return_value={'scope':'actual macOS native lifecycle; Linux source publication separately checked'}):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures=[pool.submit(remote.run_host,r) for r in requests]
                statuses=[f.result(timeout=180) for f in futures]
        self.assertEqual(statuses,[0]*4,[json.loads((r/'result.json').read_text()) for r in roots])
        absent=json.loads((roots[1]/'result.json').read_text());self.assertEqual(absent['native_processes_started'],0)
        correct=[0,2,3]
        archives=[remote.native.native_cohort_store.ShardedArchive(roots[i]/'cohorts/index.json') for i in correct]
        r=remote.native.reduce_archives(archives,cfg,base)
        self.assertEqual(r['cohort']['scheduled'],1001*seconds)
        if p=='mysticeti':self.assertGreater(r['cohort']['completed'],0)
        # An unchanged counterpart may stall. Preserve the observed failure as a
        # zero-output benchmark; this test checks correct capture, not fabricated
        # success. Its receipt explicitly distinguishes lifecycle from progress.
        self.assertTrue(r['agreement']['replicas_agree_on_common_prefix'])
        remote.prep.json_file(base/'acceptance.json',{'status':'passed','protocol':p,'binary_sha256':remote.prep.sha(binary),
            'scheduled':r['cohort']['scheduled'],'completed':r['cohort']['completed'],'absent':absent,
            'measurement_seconds':seconds,'liveness_observed':r['cohort']['completed']>0,
            'agreement':r['agreement'],'comparison_eligible':False})

if __name__=='__main__':unittest.main()
