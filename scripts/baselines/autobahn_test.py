#!/usr/bin/env python3
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import struct
import tempfile
import time
import unittest

spec=importlib.util.spec_from_file_location('autobahn_cohort',Path(__file__).with_name('autobahn_cohort.py'))
cohort=importlib.util.module_from_spec(spec);spec.loader.exec_module(cohort)
spec2=importlib.util.spec_from_file_location('autobahn_runner',Path(__file__).with_name('autobahn.py'))
runner=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(runner)


def encoded(transactions):
    return struct.pack('<IQ',0,len(transactions))+b''.join(struct.pack('<Q',len(tx))+tx for tx in transactions)


class NativeBatchTests(unittest.TestCase):
    def test_native_bincode_batch_and_payload_identity(self):
        payload=cohort.application_payload(2,17,472);raw=encoded([payload]);digest=hashlib.sha512(raw).digest()[:32].hex()
        self.assertEqual(cohort.decode_batch(raw,digest),[payload])
        self.assertEqual(cohort.request_identity(payload)[:3],(2,17,472))

    def test_content_corruption_and_native_digest_mismatch_rejected(self):
        payload=cohort.application_payload(2,17,8);raw=encoded([payload])
        with self.assertRaises(ValueError):cohort.decode_batch(raw,'00'*32)
        with self.assertRaises(ValueError):cohort.request_identity(payload[:-1]+b'\xff')

    def test_malformed_batch_lengths_and_trailing_bytes_rejected(self):
        for raw in (struct.pack('<IQ',0,2),struct.pack('<IQQ',0,1,100),encoded([])+b'extra'):
            digest=hashlib.sha512(raw).digest()[:32].hex()
            with self.assertRaises(ValueError):cohort.decode_batch(raw,digest)

    def test_exact_digest_prefix_mismatch_rejected(self):
        rows={i:{'outputs':[{'output_index':0,'request_id':'id','exact_batch_id':'batch'+str(i)}]} for i in range(2)}
        with self.assertRaises(RuntimeError):runner.prefix_agreement(rows,[0,1])

    def test_zero_output_prefix_is_valid(self):
        self.assertEqual(runner.prefix_agreement({0:{'outputs':[]},1:{'outputs':[]}},[0,1])['common_prefix_length'],0)

    def test_stalled_replica_does_not_hide_longer_prefix_conflict(self):
        def row(identity):return {'output_index':0,'request_id':identity,'exact_batch_id':'batch'}
        ledgers={0:{'outputs':[]},1:{'outputs':[row('one')]},2:{'outputs':[row('two')]}}
        with self.assertRaises(RuntimeError):runner.prefix_agreement(ledgers,[0,1,2])

    def test_saved_native_upcall_fixture_really_disagrees(self):
        path=Path(__file__).resolve().parents[2]/'benchmarks/fixtures/autobahn-raw-output-order-2026-10-19.json'
        fixture=json.loads(path.read_text())
        ledgers={int(k):{'outputs':v} for k,v in fixture['first_outputs'].items()}
        with self.assertRaises(RuntimeError):runner.prefix_agreement(ledgers,[0,1,2,3])

    def test_completed_slot_zipper_is_deterministic_and_parent_ordered(self):
        rows=[{'height':2,'author':'a','header_id':'a2','parent_id':'a1'},
              {'height':1,'author':'b','header_id':'b1','parent_id':'gen-b'},
              {'height':1,'author':'a','header_id':'a1','parent_id':'gen-a'}]
        self.assertEqual(cohort.canonical_slot(rows,{}),cohort.canonical_slot(list(reversed(rows)),{}))
        self.assertEqual([r['header_id'] for r in cohort.canonical_slot(rows,{})],['a1','b1','a2'])
        with self.assertRaises(ValueError):cohort.canonical_slot([rows[0]],{})
        with self.assertRaises(ValueError):cohort.canonical_slot([dict(rows[0],parent_id='fork')],{'a':rows[2]})

    def test_missing_first_payload_blocks_later_available_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'primary').mkdir();(root/'worker-0').mkdir()
            payload=cohort.application_payload(1,0,8);raw=encoded([payload]);digest=hashlib.sha512(raw).digest()[:32].hex()
            (root/'worker-0'/f'batch-{digest}.bin').write_bytes(raw)
            (root/'worker-0'/'available.jsonl').write_text(json.dumps({'digest':digest,'available_us':0})+'\n')
            (root/'primary'/'slots.jsonl').write_text('\n'.join(json.dumps(row) for row in [
                {'event':'header','slot':1,'height':1,'author':'a','header_id':'first','batches':['missing'],'ordered_us':0},
                {'event':'header','slot':1,'height':2,'author':'a','header_id':'second','parent_id':'first','batches':[digest],'ordered_us':0}, {'event':'complete','slot':1,'ordered_us':0}])+'\n')
            args=SimpleNamespace(origin=0,rate=0,useful_bytes=8,epoch_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC),warmup_us=0,duration_us=20000,drain_us=0,workers=1,address='127.0.0.1:1',observer_dir=root,output=root/'ledger.json')
            ledger=cohort.collect(args)
            self.assertEqual(ledger['outputs'],[])
            self.assertEqual(ledger['payload_blocked_headers'],2)
            self.assertEqual(ledger['contiguous_headers_materialized'],0)

if __name__=='__main__':unittest.main()
