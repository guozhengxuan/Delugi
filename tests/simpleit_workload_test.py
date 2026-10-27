import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import run_simpleit_local as runner


class ConfigurationTests(unittest.TestCase):
    def test_exact_committee_and_payload_budget_mapping(self):
        for variant in ('simpleit-mempool','simpleit-dispersed'):
            for n,f,q in ((4,1,3),(10,3,7),(50,16,34)):
                cfg=runner.parameters(variant,n,512,65536,100)
                self.assertEqual(cfg['f_num'],f)
                self.assertEqual(n-cfg['f_num'],q)
                self.assertEqual(cfg['header_size'],128*(512+52))
                self.assertEqual(cfg['max_header_delay'],100)
        with self.assertRaises(ValueError):runner.parameters('simpleit',50,512,65536,100)
        with self.assertRaises(ValueError):runner.parameters('simpleit-mempool',49,512,65536,100)
        with self.assertRaises(ValueError):runner.parameters('simpleit-mempool',50,512,511,100)


@unittest.skipUnless(os.environ.get('SIMPLEIT_ARCHIVE') and os.environ.get('SIMPLEIT_BINARY'),
                     'requires a real signed native Simple-IT archive')
class NativeArchiveTests(unittest.TestCase):
    def setUp(self):
        self.archive=Path(os.environ['SIMPLEIT_ARCHIVE']).resolve()
        self.binary=Path(os.environ['SIMPLEIT_BINARY']).resolve()
        self.config=self.archive/'workload-0.json'
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'observer';self.root.mkdir()
        for name in ('requests.jsonl','output.jsonl','final.json'):
            shutil.copyfile(self.archive/'observer-0'/name,self.root/name)

    def verify(self):
        return subprocess.run([str(self.binary),'verify_evaluation','--configuration',str(self.config),
            '--directory',str(self.root)],capture_output=True,timeout=60).returncode==0

    def resign(self,change=None):
        receipt=json.loads((self.root/'final.json').read_text());body=receipt['body']
        for entry in body['files']:
            path=self.root/entry['name'];entry.update(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        if change:change(body)
        raw=json.dumps(body,sort_keys=True,separators=(',',':')).encode()
        secret=json.loads(Path(json.loads(self.config.read_text())['native_key']).read_text())['secret']
        seed=base64.b64decode(secret,validate=True)[:32]
        key=Path(self.tmp.name)/'test-key.der';key.write_bytes(bytes.fromhex('302e020100300506032b657004220420')+seed);key.chmod(0o600)
        message=Path(self.tmp.name)/'digest';message.write_bytes(hashlib.sha256(raw).digest())
        signature=subprocess.check_output(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(key),'-in',str(message)],stderr=subprocess.DEVNULL)
        receipt.update(body=body,body_hex=raw.hex(),signature={'part1':list(signature[:32]),'part2':list(signature[32:])})
        (self.root/'final.json').write_text(json.dumps(receipt))

    def test_valid_and_truncated_signed_evidence(self):
        self.assertTrue(self.verify())
        path=self.root/'output.jsonl';path.write_bytes(path.read_bytes()[:-1]);self.resign()
        self.assertFalse(self.verify())

    def test_native_content_corruption_survives_file_resigning_but_is_rejected(self):
        path=self.root/'output.jsonl';lines=path.read_text().splitlines();row=json.loads(lines[0])
        raw=bytearray.fromhex(row['native_header_bincode_hex']);raw[-1]^=1
        row['native_header_bincode_hex']=raw.hex();lines[0]=json.dumps(row)
        path.write_text('\n'.join(lines)+'\n');self.resign();self.assertFalse(self.verify())

    def test_impossible_endpoint_and_false_population_are_rejected(self):
        path=self.root/'requests.jsonl';lines=path.read_text().splitlines()
        for index,line in enumerate(lines):
            row=json.loads(line)
            if row['materialized_us'] is not None:
                row['materialized_us']=row['admitted_us']-1;lines[index]=json.dumps(row);break
        else:self.fail('live fixture must have completed requests')
        path.write_text('\n'.join(lines)+'\n');self.resign();self.assertFalse(self.verify())

    def test_signature_and_signed_count_mismatch(self):
        receipt=json.loads((self.root/'final.json').read_text());receipt['signature']['part1'][0]^=1
        (self.root/'final.json').write_text(json.dumps(receipt));self.assertFalse(self.verify())
        self.resign(lambda body:body['populations'].update(completed=body['populations']['completed']+1))
        self.assertFalse(self.verify())


if __name__=='__main__':unittest.main()
