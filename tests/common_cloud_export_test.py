import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import common_cloud_worker as worker


class FrozenEvidence(unittest.TestCase):
    def test_compressed_export_roundtrips_exact_files_and_excludes_private_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);run=root/'run';run.mkdir();out=root/'collected';out.mkdir()
            worker.write(run/'request.json',{'evaluation_profile':worker.COMPACT,'protocol':'raptr'})
            worker.write(run/'resource-summary.json',{'cleanup_confirmed':True})
            (run/'keys').mkdir();(run/'keys/key-0.json').write_text('must never be exported')
            node=run/'replicas/node-0';node.mkdir(parents=True)
            (node/'planned.jsonl').write_bytes(b'{"ordinal":0}\n');(node/'final.json').write_bytes(b'{}\n')
            stream=io.BytesIO()
            with patch.object(worker,'root_for',return_value=run),patch.object(worker.sys,'stdout',SimpleNamespace(buffer=stream)):
                worker.export({'nonce':'a'*32,'compression':'gzip'})
            with gzip.GzipFile(fileobj=io.BytesIO(stream.getvalue())) as incoming:
                worker.runtime_evidence.unpack(incoming,out,expected_metadata={'nonce':'a'*32,'format':'common-sustained-evidence-v1'})
            self.assertEqual((out/'replicas/node-0/planned.jsonl').read_bytes(),b'{"ordinal":0}\n')
            self.assertFalse((out/'keys').exists())
    def test_export_requires_confirmed_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker.write(root/'resource-summary.json',{'cleanup_confirmed':False})
            with patch.object(worker,'root_for',return_value=root),self.assertRaisesRegex(ValueError,'confirmed cleanup'):
                worker.export({'nonce':'a'*32})
    def test_failed_key_ceremony_removes_temporary_all_member_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);artifact=root/'artifact';artifact.mkdir();(artifact/'node').write_text('fixture')
            run=root/'run';run.mkdir();(run/'retained-public.txt').write_text('keep')
            def failure(*a,**k):
                keys=run/'generated-keys';keys.mkdir();(keys/'private').write_text('fixture secret')
                raise RuntimeError('keygen failed')
            with patch.object(worker,'root_for',return_value=run),patch.object(worker.subprocess,'run',side_effect=failure):
                with self.assertRaisesRegex(RuntimeError,'keygen failed'):
                    worker.rpc({'action':'keygen','nonce':'a'*32,'protocol':'raptr','artifact':str(artifact),
                        'binary_sha256':worker.digest(artifact/'node'),'evaluation_profile':worker.COMPACT,'nodes':50})
            self.assertFalse((run/'generated-keys').exists());self.assertTrue((run/'retained-public.txt').is_file())

if __name__=='__main__':unittest.main()
