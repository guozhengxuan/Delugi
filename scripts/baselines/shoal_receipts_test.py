import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import shoal_receipts as receipts
import shoal_cohort


class NativeReceiptTests(unittest.TestCase):
    def setup_plan(self,root,counts=(2,1)):
        plan={'path':str(root/'observer-plan.json'),'sha3_256':'12'*32,'run_id':'11'*16,'counts':list(counts),'useful_bytes':8}
        receipts.prepare_admissions(root,plan)
        for origin,count in enumerate(counts):
            publisher=receipts.AdmissionPublisher(root/f'admission-{origin}.bits',plan,origin)
            for sequence in range(count):publisher.admit(sequence)
            publisher.close()
        return plan

    def fixture(self,root,plan,origin,outputs,empty=False,eligible=None,batches=None):
        directory=root/f'receipt-{origin}';directory.mkdir()
        bits=[bytearray((count+7)//8) for count in plan['counts']];seen=bytearray(len(bits[origin]))
        own=bytearray(len(bits[origin]));current=bytes.fromhex(receipts.digest(b'Shoal-native-prefix-v1'));checkpoints=[];events=[];ordinal=0
        if batches is None:
            batches=[('0:'+'34'*32,[])] if empty else []
            batches.append(('1:'+'56'*32,outputs))
        batch_ids=set()
        for batch_id,entries in batches:
            size=len(entries)*16;first=ordinal
            current=hashlib.sha3_256(b'B'+current+hashlib.sha3_256(batch_id.encode()).digest()+struct.pack('<QQ',size,ordinal)).digest()
            unique=batch_id not in batch_ids;batch_ids.add(batch_id)
            events.append({'event':'batch','batch_index':len(checkpoints),'first_index':first,'unique_batch':unique,'exact_batch_id':batch_id,'payload_bytes':size,'materialized_us':100})
            for who,sequence,identity in entries:
                current=hashlib.sha3_256(b'T'+current+struct.pack('<Q',ordinal)+bytes.fromhex(identity)).digest()
                if who>=0:
                    bits[who][sequence//8]|=1<<(sequence%8)
                    if who==origin:
                        seen[sequence//8]|=1<<(sequence%8)
                        if eligible is None or sequence in eligible:own[sequence//8]|=1<<(sequence%8)
                events.append({'event':'output' if who>=0 else 'uncredited_output','request_id':identity,'origin':who,'sequence':sequence,'useful_bytes':8 if who>=0 else 0,'output_index':ordinal,'exact_batch_id':batch_id,'materialized_us':100})
                ordinal+=1
            checkpoints.append({'batch_index':len(checkpoints),'exact_batch_id':batch_id,'payload_bytes':size,'unique_batch':unique,'first_index':first,'output_count':ordinal,'prefix_sha3_256':current.hex()})
        streams=[]
        for name,who,data in [('materialized',index,data) for index,data in enumerate(bits)]+[('own_seen',origin,seen),('own_eligible',origin,own)]:
            path=f'{name}-{who}.bits';(directory/path).write_bytes(data)
            streams.append({'name':name,'origin':who,'path':path,'bytes':len(data),'ones':sum(byte.bit_count() for byte in data),'sha3_256':receipts.digest(data)})
        header={'schema':1,'format':'shoal-native-receipt-v1','run_id':plan['run_id'],'plan_sha3_256':plan['sha3_256'],'origin':origin,'counts':plan['counts'],'useful_bytes':8,'mode':'full','requested_us':100,'frozen_us':110,'output_count':ordinal,'batch_count':len(checkpoints),'payload_bytes':sum(row['payload_bytes'] for row in checkpoints if row['unique_batch']),'prefix_sha3_256':current.hex(),'streams':streams}
        (directory/'header.json').write_text(json.dumps(header))
        (directory/'checkpoints.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in checkpoints))
        (root/f'output-{origin}.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in events))
        return receipts.load(root,plan,origin,'full',100)

    def test_complete_native_receipt_includes_empty_unknown_and_repeated_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root)
            outputs=[(0,0,'01'*32),(-1,0,'ff'*32),(0,0,'01'*32),(1,0,'02'*32)]
            values={index:self.fixture(root,plan,index,outputs,empty=True) for index in range(2)}
            self.assertEqual(receipts.compare(values,[0,1])['sequence_lengths'],[4,4])
            self.assertEqual(receipts.summarize(values,[0,1])['all_correct_completed'],2)
            self.assertEqual(receipts.verify_full(values[0],root/'output-0.jsonl')['output_count'],4)
            self.assertFalse(receipts.summarize(values,[0,1])['latency_available'])

    def test_preplay_cannot_gain_credit_after_origin_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root)
            outputs=[(0,0,'01'*32),(0,0,'01'*32)]
            values={index:self.fixture(root,plan,index,outputs,eligible=set()) for index in range(2)}
            self.assertEqual(receipts.summarize(values,[0,1])['admitted'],3)
            self.assertEqual(receipts.summarize(values,[0,1])['all_correct_completed'],0)

    def test_detailed_tail_after_terminal_freeze_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);value=self.fixture(root,plan,0,[(0,0,'01'*32)])
            path=root/'output-0.jsonl';events=[json.loads(row) for row in path.read_text().splitlines()]
            events[-1]['materialized_us']=111;path.write_text(''.join(json.dumps(row)+'\n' for row in events))
            with self.assertRaisesRegex(ValueError,'frozen prefix'):receipts.verify_full(value,path)

    def test_full_empty_batch_mutation_drop_and_reorder_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);value=self.fixture(root,plan,0,[],empty=True)
            path=root/'output-0.jsonl';original=[json.loads(row) for row in path.read_text().splitlines()]
            mutated=[dict(row) for row in original];mutated[0]['payload_bytes']=1
            for rows in (mutated,original[1:],list(reversed(original))):
                path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
                with self.assertRaisesRegex(ValueError,'batch boundary'):receipts.verify_full(value,path)

    def test_checkpoint_mutation_after_load_cannot_rewrite_frozen_empty_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);value=self.fixture(root,plan,0,[],empty=True)
            path=root/'receipt-0/checkpoints.jsonl';rows=[json.loads(line) for line in path.read_text().splitlines()]
            rows[0]['exact_batch_id']='0:'+'ab'*32
            current=bytes.fromhex(receipts.digest(b'Shoal-native-prefix-v1'))
            for row in rows:
                current=hashlib.sha3_256(b'B'+current+hashlib.sha3_256(row['exact_batch_id'].encode()).digest()+struct.pack('<QQ',row['payload_bytes'],row['first_index'])).digest()
                row['prefix_sha3_256']=current.hex()
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            detailed=root/'output-0.jsonl';events=[json.loads(line) for line in detailed.read_text().splitlines()]
            events[0]['exact_batch_id']=rows[0]['exact_batch_id'];detailed.write_text(''.join(json.dumps(row)+'\n' for row in events))
            with self.assertRaisesRegex(ValueError,'terminal receipt'):receipts.verify_full(value,detailed)

    def test_checkpoint_same_semantics_different_bytes_rejected_after_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);value=self.fixture(root,plan,0,[])
            path=root/'receipt-0/checkpoints.jsonl';path.write_bytes(path.read_bytes().replace(b'\n',b' \n'))
            with self.assertRaisesRegex(ValueError,'bytes changed'):list(receipts.checkpoints(value))

    def test_compare_exhausts_every_longer_stream_even_for_empty_correct_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root)
            values={0:self.fixture(root,plan,0,[],empty=True),1:self.fixture(root,plan,1,[],batches=[])}
            original=receipts.checkpoints;opened=[];completed=[]
            def tracked(receipt):
                marker=len(opened);opened.append(marker)
                yield from original(receipt)
                completed.append(marker)
            with mock.patch.object(receipts,'checkpoints',tracked):receipts.compare(values,[0,1])
            self.assertEqual(sorted(completed),opened)

    def test_load_binds_same_pass_and_derives_batch_uniqueness_and_repeated_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);batch='1:'+'56'*32
            with mock.patch.object(receipts,'file_digest',side_effect=AssertionError('separate hash pass')):
                value=self.fixture(root,plan,0,[],batches=[(batch,[]),(batch,[])])
            path=root/'receipt-0/checkpoints.jsonl';original=[json.loads(line) for line in path.read_text().splitlines()]
            mutated=[dict(row) for row in original];mutated[0]['unique_batch']=False;mutated[1]['unique_batch']=True
            path.write_text(''.join(json.dumps(row)+'\n' for row in mutated))
            with self.assertRaisesRegex(ValueError,'first occurrence'):receipts.load(root,plan,0,'full',100)
            mutated=[dict(row) for row in original];mutated[1]['payload_bytes']=1
            path.write_text(''.join(json.dumps(row)+'\n' for row in mutated))
            with self.assertRaisesRegex(ValueError,'payload bytes differ'):receipts.load(root,plan,0,'full',100)

    def test_exact_prefix_conflict_is_not_hidden_by_shorter_correct_replica(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root,(1,1,1))
            values={0:self.fixture(root,plan,0,[]),1:self.fixture(root,plan,1,[(0,0,'01'*32)]),2:self.fixture(root,plan,2,[(0,0,'02'*32)])}
            # A third stalled correct replica has no complete batches at all.
            path=root/'receipt-0/header.json';header=json.loads(path.read_text())
            header.update(batch_count=0,prefix_sha3_256=receipts.digest(b'Shoal-native-prefix-v1'))
            path.write_text(json.dumps(header));(root/'receipt-0/checkpoints.jsonl').write_text('')
            values[0]=receipts.load(root,plan,0,'full',100)
            with self.assertRaisesRegex(ValueError,'prefixes disagree'):receipts.compare(values,[0,1,2])

    def test_bitmap_padding_and_run_binding_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=self.setup_plan(root);self.fixture(root,plan,0,[])
            with self.assertRaisesRegex(ValueError,'configuration'):receipts.load(root,plan|{'run_id':'22'*16},0,'full',100)
            (root/'receipt-0/materialized-0.bits').write_bytes(b'\x80')
            with self.assertRaisesRegex(ValueError,'padding'):receipts.load(root,plan,0,'full',100)

    def test_admission_callback_is_between_application_admission_and_submission(self):
        events=[];clock=iter([100,100,100,101,102,103])
        def now():return next(clock,104)
        def publish(sequence):events.append(('admit',sequence))
        def submit(*args):events.append(('submit',None));return 202,'{}'
        plan=[{'request_id':'11'*32,'origin':0,'sequence':0,'useful_bytes':8,'bcs_hex':'00'}]
        rows=list(shoal_cohort.ingress_iter(plan,'unused',1,100,0,100,100,now=now,submit=submit,on_admit=publish))
        self.assertIsNotNone(rows[0]['admitted_us']);self.assertEqual(events,[('admit',0),('submit',None)])


if __name__=='__main__':unittest.main()
