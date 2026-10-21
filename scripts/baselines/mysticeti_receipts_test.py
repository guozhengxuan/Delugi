from pathlib import Path
import hashlib
import json
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mysticeti_receipts as receipt


def field(h, b): h.update(struct.pack('<Q', len(b))); h.update(b)


class Fixture:
    def __init__(self, root, replica=0, mode='full', count=1, admitted=1, eligible=1, ready=1, seen=1):
        self.root=root;root.mkdir();self.replica=replica;self.mode=mode;self.counts=[count]*2
        self.header={'schema':1,'format':receipt.FORMAT,'mode':mode,'origin':replica,'counts':self.counts,'useful_bytes':8,
            'window_start_us':0,'window_end_us':1000,'requested_us':5000,'frozen_us':5001,'output_count':0,'batch_count':0,
            'payload_bytes':0,'output_hash':receipt.EMPTY_HASH,'batch_hash':receipt.EMPTY_HASH,'streams':[],'process_window':[]}
        self.start={'origin':replica,'count':count,'useful_bytes':8,'window_start_us':0,'window_end_us':1000,'observed_us':5000}
        values={'admitted':admitted,'eligible':eligible,'ready':ready,'seen':seen,'window_admitted':admitted,'window_completed':eligible}
        for name in receipt.LOCAL:
            self.bits(name,replica,values[name])
        for origin in range(2):self.bits('materialized',origin,seen)
        self.oh=hashlib.blake2b();self.bh=hashlib.blake2b();self.rows=[]

    def bits(self,name,origin,value):
        count=self.counts[origin];raw=value.to_bytes((count+7)//8,'little');path=f'{name}-{origin}.bits';(self.root/path).write_bytes(raw)
        self.header['streams'].append({'name':name,'origin':origin,'path':path,'count':count,'bytes':len(raw),'ones':value.bit_count(),'hash':receipt.digest(raw)})

    def batch(self, identifier, transactions):
        for author,raw in transactions:
            index=self.header['output_count'];self.oh.update(b'mysticeti-native-output-v1\0');self.oh.update(struct.pack('<QQ',index,author));field(self.oh,bytes.fromhex(identifier));field(self.oh,raw);self.header['output_count']+=1
        size=sum(len(raw) for _,raw in transactions);self.bh.update(b'mysticeti-native-batch-v1\0');self.bh.update(struct.pack('<Q',self.header['batch_count']));field(self.bh,bytes.fromhex(identifier));self.bh.update(struct.pack('<QQ',size,self.header['output_count']));field(self.bh,self.oh.digest())
        self.header['batch_count']+=1;self.header['payload_bytes']+=size
        self.header['output_hash']=self.oh.hexdigest();self.header['batch_hash']=self.bh.hexdigest()
        self.rows.append({k:self.header[k] for k in ('batch_count','output_count','payload_bytes','output_hash','batch_hash')})
        return self

    def save(self):
        raw=b''.join(json.dumps(r,separators=(',',':')).encode()+b'\n' for r in self.rows)
        (self.root/'checkpoints.jsonl').write_bytes(raw);self.header.update(checkpoint_bytes=len(raw),checkpoint_hash=receipt.digest(raw))
        (self.root/'header.json').write_text(json.dumps(self.header)+'\n')
        return receipt.load(self.root,self.replica,self.counts,8,self.mode,self.start)


class ReceiptTests(unittest.TestCase):
    def test_full_compact_same_raw_native_output_with_unfinished_and_missing_ready(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);values=[]
            for mode in ('full','compact'):
                r={i:Fixture(root/f'{mode}-{i}',i,mode,ready=0).batch('abcdef0001',[(0,b'known'),(1,b'unknown')]).batch('abcdef0002',[]).save() for i in (0,1)}
                result=receipt.summarize(r,[0,1]);values.append(result)
                self.assertEqual(result['all_correct_completed'],2)
                self.assertEqual(result['agreement']['native_output_counts'],{0:2,1:2})
                self.assertEqual(result['agreement']['batch_counts'],{0:2,1:2})
                self.assertFalse(result['latency_available'])
                self.assertEqual(result['agreement']['native_order_fidelity']['status'],'incomplete')
            self.assertEqual(values[0],values[1])

    def test_preplay_is_not_retroactively_credited_despite_later_admission(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            r={i:Fixture(root/str(i),i,admitted=1,eligible=0,ready=1,seen=1).batch('aa00',[(0,b'preplay'),(1,b'foreign')]).save() for i in (0,1)}
            result=receipt.summarize(r,[0,1]);self.assertEqual(result['admitted'],2);self.assertEqual(result['local_completed'],0)
            self.assertEqual(result['unfinished'],2);self.assertEqual(result['reference_unique_eligible_u_out_bytes'],0)

    def test_empty_population_and_nonempty_zero_output_remain_visible(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for count in (0,1):
                r={i:Fixture(root/f'{count}-{i}',i,count=count,admitted=count,eligible=0,ready=0,seen=0).save() for i in (0,1)}
                result=receipt.summarize(r,[0,1]);self.assertEqual(result['planned'],2*count);self.assertEqual(result['unfinished'],2*count)

    def test_unknown_leading_trailing_and_empty_batches_are_not_full_WAL_proof(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            r={i:Fixture(root/str(i),i,admitted=0,eligible=0,ready=0,seen=0).batch('12340001',[(7,b'unknown-leading'),(7,b'unknown-trailing')]).batch('12340002',[]).save() for i in (0,1)}
            result=receipt.summarize(r,[0,1]);self.assertEqual(result['all_correct_completed'],0)
            self.assertEqual(result['agreement']['native_output_counts'],{0:2,1:2});self.assertEqual(result['agreement']['native_order_fidelity']['status'],'incomplete')

    def test_full_digest_collision_and_stalled_replica_cannot_hide_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            r={0:Fixture(root/'0',0,eligible=0,ready=0,seen=0).save(),1:Fixture(root/'1',1).batch('abcdef0011',[]).save()}
            self.assertTrue(receipt.summarize(r,[0,1])['agreement']['replicas_agree_on_common_prefix'])
            r[0]=Fixture(root/'other',0).batch('abcdef0022',[]).save()
            with self.assertRaisesRegex(ValueError,'prefixes disagree'):receipt.summarize(r,[0,1])

    def test_header_population_cutoff_and_path_rejected_before_bitmap_reads(self):
        with tempfile.TemporaryDirectory() as d:
            f=Fixture(Path(d)/'r');f.save()
            original=json.loads(json.dumps(f.header))
            for change in ('counts','boolean_count','boolean_schema','path','cutoff'):
                f.header=json.loads(json.dumps(original))
                if change=='counts':f.header['counts']=[999999999,999999999]
                elif change=='boolean_count':f.header['counts']=[True,True]
                elif change=='boolean_schema':f.header['schema']=True
                elif change=='path':f.header['streams'][0]['path']='../escape.bits'
                else:f.header['frozen_us']=4999
                (f.root/'header.json').write_text(json.dumps(f.header))
                with self.assertRaises(ValueError):receipt.load(f.root,0,[1,1],8,'full',f.start)

    def test_consumed_bitmap_hash_population_padding_and_symlink_are_verified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for case in ('hash','padding','count','symlink'):
                f=Fixture(root/case);r=f.save();path=f.root/'admitted-0.bits';row=r['descriptors'][('admitted',0)]
                if case=='hash':path.write_bytes(b'\0')
                elif case=='padding':path.write_bytes(b'\x81');row.update(hash=receipt.digest(b'\x81'),ones=2)
                elif case=='count':row['ones']=0
                else:path.unlink();path.symlink_to(f.root/'ready-0.bits')
                with self.assertRaises(ValueError):receipt.summarize({0:r},[0])

    def test_checkpoint_tamper_or_missing_unknown_tail_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            f=Fixture(Path(d)/'r').batch('aa00',[(9,b'unknown')]);r=f.save()
            (f.root/'checkpoints.jsonl').write_bytes(b'')
            with self.assertRaises(ValueError):receipt.summarize({0:r},[0])

    def test_actual_process_sample_intervals_and_backward_counters(self):
        with tempfile.TemporaryDirectory() as d:
            f=Fixture(Path(d)/'r');r=f.save();f.header['process_window']=[{'elapsed_us':5,'user_cpu_us':10,'system_cpu_us':5,'peak_rss_bytes':100},{'elapsed_us':1007,'user_cpu_us':30,'system_cpu_us':9,'peak_rss_bytes':150}]
            r['header']=f.header;result=receipt.resource_window({0:r});self.assertEqual(result['cpu_seconds'],.000024)
            self.assertEqual(result['per_replica'][0]['end_offset_us'],7)
            f.header['process_window'][1]['user_cpu_us']=9
            with self.assertRaises(ValueError):receipt.resource_window({0:r})

    def test_resource_samples_cannot_precede_boundaries_or_follow_freeze(self):
        with tempfile.TemporaryDirectory() as d:
            f=Fixture(Path(d)/'r');r=f.save()
            good=[{'elapsed_us':5,'user_cpu_us':10,'system_cpu_us':5,'peak_rss_bytes':100},{'elapsed_us':1007,'user_cpu_us':30,'system_cpu_us':9,'peak_rss_bytes':150}]
            for case in ('early_start','early_end','late_end','extra_sample'):
                r['header']['process_window']=json.loads(json.dumps(good))
                r['header']['window_start_us']=4
                if case=='early_start':r['header']['process_window'][0]['elapsed_us']=3
                elif case=='early_end':r['header']['process_window'][1]['elapsed_us']=999
                elif case=='late_end':r['header']['process_window'][1]['elapsed_us']=5002
                else:r['header']['process_window'].append(good[1])
                with self.assertRaises(ValueError):receipt.resource_window({0:r})

    def test_correct_set_must_name_present_finite_replicas(self):
        with tempfile.TemporaryDirectory() as d:
            r=Fixture(Path(d)/'r').save()
            for correct in ([1],[False],[0,0],[]):
                with self.assertRaises(ValueError):receipt.summarize({0:r},correct)


    def test_wal_fidelity_requires_exact_header_terminal_and_full_journal(self):
        with tempfile.TemporaryDirectory() as d:
            r=Fixture(Path(d)/'r').save();h=r['header']
            proof={'status':'verified','receipt_header_sha256':r['header_sha256'], 'wal_sha256':'a'*64,
                'exact_checkpoint_sequence_equal':True,'materialized_membership_equal':True,'full_journal_equal':True,
                'covered_wal_record_end':0,'later_wal_bytes_outside_prefix_claim':10,'commit_subdag_blocks_after_frozen_prefix':0,
                **{a:h[b] for a,b in (('batch_count','batch_count'),('native_output_count','output_count'),('payload_bytes','payload_bytes'),('output_hash','output_hash'),('batch_hash','batch_hash'))}}
            result=receipt.bind_wal_fidelity({0:r},{0:proof},[0])
            self.assertEqual(result['status'],'verified');self.assertFalse(result['formal_comparison_eligibility_changed'])
            for field,value in [('receipt_header_sha256','b'*64),('native_output_count',1),('batch_hash','f'*128),('full_journal_equal',None),('exact_checkpoint_sequence_equal',False)]:
                with self.assertRaisesRegex(ValueError,'differs'):
                    receipt.bind_wal_fidelity({0:r},{0:proof|{field:value}},[0])
            with self.assertRaisesRegex(ValueError,'missing'):
                receipt.bind_wal_fidelity({0:r},{},[0])


if __name__=='__main__':unittest.main()
