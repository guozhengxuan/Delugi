import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib
sys.path.insert(0,str(Path(__file__).resolve().parent))
import mysticeti_wal as wal


class NativeWalAuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture=json.loads((Path(__file__).with_name("fixtures")/"mysticeti-signed-native-block.json").read_text())
        self.raw=bytes.fromhex(self.fixture["raw_block_hex"])
        self.keys=[bytes.fromhex(value) for value in self.fixture["public_keys_hex"]]
        self.verifier=wal.Ed25519Verifier()

    def test_real_signed_native_block_authenticates_and_matches_exact_requests(self):
        reference,_,transactions=wal.decode_block(self.raw,self.keys,self.verifier)
        self.assertEqual(reference["id"],self.fixture["expected_reference"])
        self.assertEqual([wal.workload_identity(tx,reference["author"]) for tx in transactions],self.fixture["expected_requests"])

    def test_wrong_author_key_and_tampered_payload_rejected(self):
        keys=list(self.keys);keys[0],keys[1]=keys[1],keys[0]
        with self.assertRaisesRegex(ValueError,"signature"):
            wal.decode_block(self.raw,keys,self.verifier)
        changed=bytearray(self.raw);changed[-1]^=1
        with self.assertRaisesRegex(ValueError,"digest mismatch"):
            wal.decode_block(changed,self.keys,self.verifier)

    def test_foreign_origin_malformed_size_and_unknown_application_uncredited(self):
        reference,_,transactions=wal.decode_block(self.raw,self.keys,self.verifier)
        payload=transactions[0]
        self.assertIsNone(wal.workload_identity(payload,reference["author"]+1))
        changed=bytearray(payload);changed[32:40]=struct.pack("<Q",2**64-1)
        self.assertIsNone(wal.workload_identity(changed,reference["author"]))
        self.assertIsNone(wal.workload_identity(b"other application",0))

    def test_complete_boundary_and_crc_enforced(self):
        entry=struct.pack("<QII",zlib.crc32(self.raw),len(self.raw)+16,1)+self.raw
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"wal";path.write_bytes(entry+entry)
            self.assertEqual(len(list(wal.wal_entries(path,len(entry)))),1)
            with self.assertRaisesRegex(ValueError,"incomplete WAL"):
                list(wal.wal_entries(path,len(entry)+1))
            changed=bytearray(entry);changed[-1]^=1;path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError,"CRC"):
                list(wal.wal_entries(path))

    def test_native_commit_order_replay_and_missing_payload_rejection(self):
        ref=bytes.fromhex(self.fixture["expected_reference"])
        commit=struct.pack("<Q",1)+ref+struct.pack("<Q",1)+ref+struct.pack("<Q",0)
        def record(tag,payload):return struct.pack("<QII",zlib.crc32(payload),len(payload)+16,tag)+payload
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"wal";path.write_bytes(record(5,commit))
            with self.assertRaisesRegex(ValueError,"payload absent"):
                wal.replay(path,self.keys)
            # This real block has non-genesis ancestors, so a synthetic file
            # containing only it cannot pretend to be a complete native output.
            path.write_bytes(record(1,self.raw)+record(5,commit))
            with self.assertRaisesRegex(ValueError,"retained ancestor"):
                wal.replay(path,self.keys)




class PrefixFixture:
    """Small signed WAL independent of the native observer implementation."""
    def __init__(self, root, mode='full'):
        import ctypes
        from mysticeti_receipts_test import Fixture
        self.root=root;self.ctypes=ctypes;self.verifier=wal.Ed25519Verifier();lib=self.verifier.lib;p=ctypes.c_void_p;s=ctypes.c_size_t
        for name,args,res in [('EVP_PKEY_new_raw_private_key_ex',[p,ctypes.c_char_p,ctypes.c_char_p,p,s],p),
            ('EVP_PKEY_get_raw_public_key',[p,p,ctypes.POINTER(s)],ctypes.c_int),
            ('EVP_DigestSignInit',[p,p,p,p,p],ctypes.c_int),('EVP_DigestSign',[p,p,ctypes.POINTER(s),p,s],ctypes.c_int)]:
            f=getattr(lib,name);f.argtypes=args;f.restype=res
        self.key=lib.EVP_PKEY_new_raw_private_key_ex(None,b'ED25519',None,b'\x03'*32,32)
        public=ctypes.create_string_buffer(32);length=s(32)
        assert lib.EVP_PKEY_get_raw_public_key(self.key,public,ctypes.byref(length))==1
        self.keys=[public.raw,public.raw]
        self.fixture=Fixture(root/'receipt',mode=mode)
        # The fixture has one actual own request and no origin1 output.
        row=next(r for r in self.fixture.header['streams'] if r['name']=='materialized' and r['origin']==1)
        (self.fixture.root/row['path']).write_bytes(b'\0');row.update(hash=hashlib.blake2b(b'\0').hexdigest(),ones=0)
        self.records=[];self.journal=[];self.ordinal=0

    def close(self):self.verifier.lib.EVP_PKEY_free(self.key)

    def block(self, round_number, transactions, includes=()):
        c=self.ctypes;lib=self.verifier.lib
        unsigned=struct.pack('>QQ',0,round_number)+b''.join(struct.pack('>QQ',r['author'],r['round'])+r['digest'] for r in includes)
        unsigned+=b''.join(b'\0'+tx for tx in transactions)+b'\0'*17
        digest=hashlib.blake2b(unsigned,digest_size=32).digest();context=lib.EVP_MD_CTX_new();signature=c.create_string_buffer(64);length=c.c_size_t(64)
        try:
            assert lib.EVP_DigestSignInit(context,None,None,None,self.key)==1
            assert lib.EVP_DigestSign(context,signature,c.byref(length),digest,len(digest))==1
        finally:lib.EVP_MD_CTX_free(context)
        block_digest=hashlib.blake2b(unsigned+signature.raw,digest_size=32).digest()
        ref={'author':0,'round':round_number,'digest':block_digest,'raw':struct.pack('<QQQ',0,round_number,32)+block_digest}
        ref['id']=ref['raw'].hex()
        raw=ref['raw']+struct.pack('<Q',len(includes))+b''.join(r['raw'] for r in includes)
        raw+=struct.pack('<Q',len(transactions))+b''.join(struct.pack('<IQ',0,len(tx))+tx for tx in transactions)+b'\0'*17+struct.pack('<Q',64)+signature.raw
        return ref,raw

    @staticmethod
    def record(tag,raw):return struct.pack('<QII',zlib.crc32(raw),len(raw)+16,tag)+raw

    def append(self, ref, raw, transactions, *, commit=True):
        self.records.append(self.record(1,raw))
        if commit:self.records.append(self.record(5,struct.pack('<Q',1)+ref['raw']+struct.pack('<Q',1)+ref['raw']+struct.pack('<Q',0)))
        self.fixture.batch(ref['id'],[(0,tx) for tx in transactions])
        self.journal.append({'event':'batch','exact_batch_id':ref['id'],'payload_bytes':sum(map(len,transactions))})
        for tx in transactions:
            identity=wal.workload_identity(tx,0)
            if identity is not None:self.journal.append({'event':'materialized',**identity,'output_index':self.ordinal,'exact_batch_id':ref['id']})
            self.ordinal+=1

    def save(self):
        self.path=self.root/'wal';self.path.write_bytes(b''.join(self.records));self.receipt=self.fixture.save()
        self.journal_path=self.root/'journal.jsonl';self.journal_path.write_text(''.join(json.dumps(r)+'\n' for r in self.journal))
        return self

    def verify(self, name='index.sqlite', full=True):
        return wal.verify_receipt_prefix(self.path,self.keys,self.receipt,self.root/name,
            journal=self.journal_path if full else None,expected_wal_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest())


class BoundedWalPrefixTests(unittest.TestCase):
    def fixture(self, root, mode='full', tail=True):
        f=PrefixFixture(root,mode)
        known=b'\0'*8+b'DLGCOH01'+struct.pack('<QQQ',0,0,8)+bytes(range(8))
        foreign=b'\0'*8+b'DLGCOH01'+struct.pack('<QQQ',1,0,8)+bytes(range(1,9))
        parent,raw=f.block(1,[b'unknown-leading',known]);f.append(parent,raw,[b'unknown-leading',known])
        empty,raw=f.block(2,[],[parent]);f.append(empty,raw,[])
        last,raw=f.block(3,[foreign,b'unknown-trailing'],[empty]);f.append(last,raw,[foreign,b'unknown-trailing'])
        f.save()
        if tail:f.path.write_bytes(f.path.read_bytes()+b'incomplete later native work')
        self.addCleanup(f.close)
        return f

    def test_full_compact_exact_unknown_empty_and_terminal_prefix_with_later_wal_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            for mode in ('full','compact'):
                root=Path(tmp)/mode;root.mkdir();f=self.fixture(root,mode)
                result=f.verify(full=mode=='full')
                self.assertEqual(result['status'],'verified');self.assertEqual(result['batch_count'],3)
                self.assertEqual(result['native_output_count'],4);self.assertEqual(result['unknown_or_foreign_outputs'],3)
                self.assertEqual(result['later_wal_bytes_outside_prefix_claim'],len(b'incomplete later native work'))
                self.assertTrue(result['materialized_membership_equal']);self.assertEqual(result['output_hash'],f.receipt['header']['output_hash'])

    def test_missing_reordered_and_altered_checkpoint_cannot_hide_behind_same_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            for case in ('missing','reorder','alter'):
                root=Path(tmp)/case;root.mkdir();f=self.fixture(root)
                rows=f.fixture.rows
                if case=='missing':rows.pop()
                elif case=='reorder':rows[0],rows[1]=rows[1],rows[0]
                else:rows[0]['output_hash']='a'*128
                f.receipt=f.fixture.save()
                with self.assertRaisesRegex(ValueError,'checkpoint|ordinal'):f.verify()

    def test_wal_missing_frozen_tail_and_lost_empty_block_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            for case in ('tail','empty'):
                root=Path(tmp)/case;root.mkdir();f=self.fixture(root,tail=False)
                records=list(f.records)
                if case=='tail':records.pop()
                else:records.pop(3) # drop empty block's persisted commit
                f.path.write_bytes(b''.join(records))
                with self.assertRaisesRegex(ValueError,'terminal block|checkpoint'):f.verify(full=False)

    def test_signature_and_payload_tamper_rejected_even_with_valid_wal_crc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f=self.fixture(root,tail=False)
            record=bytearray(f.records[0]);record[-1]^=1;record[:8]=struct.pack('<Q',zlib.crc32(record[16:]));f.path.write_bytes(bytes(record)+b''.join(f.records[1:]))
            with self.assertRaisesRegex(ValueError,'digest mismatch'):f.verify()
            f.path.write_bytes(b''.join(f.records));f.keys=[b'\x01'*32,b'\x01'*32]
            with self.assertRaisesRegex(ValueError,'signature'):f.verify('wrong-key.sqlite')

    def test_materialized_membership_and_full_journal_are_independently_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f=self.fixture(root)
            f.journal[1]['output_index']=0;f.journal_path.write_text(''.join(json.dumps(r)+'\n' for r in f.journal))
            with self.assertRaisesRegex(ValueError,'full journal'):f.verify('journal.sqlite')
            row=next(r for r in f.fixture.header['streams'] if r['name']=='materialized' and r['origin']==1)
            (f.fixture.root/row['path']).write_bytes(b'\1');row.update(ones=1,hash=hashlib.blake2b(b'\1').hexdigest());f.receipt=f.fixture.save()
            with self.assertRaisesRegex(ValueError,'membership'):f.verify('bits.sqlite',False)

    def test_large_native_record_is_streamed_without_record_sized_allocation(self):
        import io
        class Bounded(io.BytesIO):
            def read(self,n=-1):
                if not 0<=n<=wal.STREAM_CHUNK:raise AssertionError('unbounded WAL read')
                return super().read(n)
        payload=b'x'*(2*wal.STREAM_CHUNK+13);raw=PrefixFixture.record(4,payload)
        records=list(wal.stream_records(Bounded(raw),len(raw)))
        self.assertEqual(len(records),1)
        reader=records[0][2]
        self.assertEqual(sum(len(chunk) for chunk in reader.chunks(len(payload))),len(payload));reader.finish()

    def test_complete_block_freeze_inside_one_commit_data_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=self.fixture(Path(tmp),tail=False)
            # The receipt freezes after the empty second block, while native
            # CommitData persists a subdag containing one later unknown block.
            f.fixture.rows.pop(); f.fixture.output_count=2
            f.fixture.payload_bytes=sum(map(len,[b'unknown-leading',b'\0'*8+b'DLGCOH01'+struct.pack('<QQQ',0,0,8)+bytes(range(8))]))
            last=f.fixture.rows[-1]
            for key in ('output_count','batch_count','payload_bytes','output_hash','batch_hash'):
                f.fixture.header[key]=last[key]
            # save() updates the terminal from its rows directly.
            f.receipt=f.fixture.save()
            blocks=[f.records[i] for i in (0,2,4)]
            refs=[record[16:72] for record in blocks]
            commit=struct.pack('<Q',1)+refs[-1]+struct.pack('<Q',3)+b''.join(refs)+struct.pack('<Q',0)
            f.path.write_bytes(b''.join(blocks)+f.record(5,commit))
            result=f.verify(full=False)
            self.assertEqual(result['batch_count'],2)
            self.assertEqual(result['native_output_count'],2)
            self.assertEqual(result['commit_subdag_blocks_after_frozen_prefix'],1)
            self.assertEqual(result['later_wal_bytes_outside_prefix_claim'],0)

    def test_missing_ancestor_duplicate_commit_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=self.fixture(Path(tmp),tail=False)
            # Leave first commit absent too, so the next commit detects its
            # cryptographically bound but unavailable non-genesis ancestor.
            f.path.write_bytes(b''.join(f.records[2:]))
            with self.assertRaisesRegex(ValueError,'retained ancestor'):f.verify('ancestor.sqlite',False)
            f.path.write_bytes(b''.join(f.records[:2]+[f.records[1]]+f.records[2:]))
            with self.assertRaisesRegex(ValueError,'committed twice'):f.verify('duplicate.sqlite',False)
            link=f.root/'link';link.symlink_to(f.path)
            with self.assertRaisesRegex(ValueError,'symlink'):
                wal.verify_receipt_prefix(link,f.keys,f.receipt,f.root/'link.sqlite')


    def test_adapter_offline_gate_retains_proof_and_removes_only_derived_index(self):
        import mysticeti
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);f=self.fixture(root,tail=False)
            genesis=root/'genesis';(genesis/'storage-0').mkdir(parents=True)
            (genesis/'storage-0/wal').write_bytes(f.path.read_bytes())
            (root/'cohort-0.jsonl').write_bytes(f.journal_path.read_bytes())
            (genesis/'committee.yaml').write_text(''.join('  public_key:\n'+''.join(f'  - {v}\n' for v in key) for key in f.keys))
            result=mysticeti.audit_native_frozen_prefix(root,{0:f.receipt},[0])
            self.assertEqual(result['status'],'verified');self.assertFalse(result['formal_comparison_eligibility_changed'])
            proof=json.loads((root/'wal-prefix-0.json').read_text())
            self.assertTrue(proof['derived_index_removed']);self.assertEqual(len(proof['derived_index_sha256']),64)
            self.assertFalse((root/'wal-prefix-0.sqlite').exists())
            self.assertTrue((genesis/'storage-0/wal').exists());self.assertTrue((root/'cohort-0.jsonl').exists())


    def test_zero_frozen_prefix_does_not_claim_unobserved_native_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=PrefixFixture(Path(tmp),'compact');self.addCleanup(f.close)
            for row in f.fixture.header['streams']:
                if row['name'] in ('seen','eligible','window_completed','materialized'):
                    (f.fixture.root/row['path']).write_bytes(b'\0');row.update(ones=0,hash=hashlib.blake2b(b'\0').hexdigest())
            f.save();f.path.write_bytes(b'not part of the frozen empty prefix')
            result=f.verify(full=False)
            self.assertEqual(result['batch_count'],0);self.assertEqual(result['native_output_count'],0)
            self.assertEqual(result['native_blocks_verified'],0)
            self.assertEqual(result['later_wal_bytes_outside_prefix_claim'],f.path.stat().st_size)


if __name__=='__main__':unittest.main()
