import ctypes
import hashlib
import json
import http.server
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parent))
import shoal
import shoal_cohort as cohort
from native_cohort_store import NativeStore, journal_rows, reduce_archive
from mysticeti_wal import Ed25519Verifier


class ProxyIsolationTests(unittest.TestCase):
    def test_zero_drain_uses_actual_frozen_cpu_sample_not_zero(self):
        kinds=('ordinary_sign','ordinary_verify','ordinary_verify_batch','ordinary_verify_batch_multi')
        def sample(n):return {'replica':{'operations':{kind:{'calls':n,'thread_cpu_ns':n*100} for kind in kinds}}}
        with mock.patch.object(shoal.native_faults,'cpu_snapshot',return_value=sample(3)):
            ledger=shoal.frozen_crypto_ledger(Path('.'),sample(2),None)
            self.assertEqual(ledger['measurement']['ordinary_sign'],{'calls':1,'thread_cpu_ns':100})
            self.assertEqual(ledger['after'],sample(3))
            with self.assertRaisesRegex(ValueError,'regressed'):
                shoal.frozen_crypto_ledger(Path('.'),sample(2),sample(1))

    def test_api_readiness_is_insufficient_until_bootstrap_and_counters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for index in range(2):(root/f'validator-{index}.log').write_bytes(b'REST listening\n')
            readiness=shoal.NativeReadiness(root,2)
            self.assertFalse(readiness.observe()['ready'])
            marker=shoal.NativeReadiness.marker
            for index in range(2):
                with (root/f'validator-{index}.log').open('ab') as stream:stream.write(marker[:15])
            self.assertEqual(readiness.observe()['bootstrapped'],[])
            for index in range(2):
                with (root/f'validator-{index}.log').open('ab') as stream:stream.write(marker[15:]+b'\n')
            self.assertEqual(readiness.observe()['bootstrapped'],[0,1])
            (root/'io-0.json').write_text('{}')
            self.assertFalse(readiness.observe()['ready'])
            (root/'io-1.json').write_text('{}')
            self.assertTrue(readiness.observe()['ready'])

    def test_swap_guard_reports_enabled_even_when_unused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'swaps'
            path.write_text('Filename Type Size Used Priority\n')
            self.assertFalse(shoal.runtime_swap_snapshot(path)['enabled'])
            path.write_text('Filename Type Size Used Priority\n/dev/zram0 partition 4096 0 100\n')
            self.assertTrue(shoal.runtime_swap_snapshot(path)['enabled'])
            path.write_text('unexpected\n')
            with self.assertRaises(ValueError):shoal.runtime_swap_snapshot(path)

    def test_validator_environment_strips_all_proxy_case_variants(self):
        environment={'KEEP':'yes'} | {key:'http://127.0.0.1:1' for key in (
            'HTTP_PROXY','http_proxy','HTTPS_PROXY','https_proxy','ALL_PROXY','all_proxy','HtTp_PrOxY')}
        result=shoal.direct_protocol_environment(environment)
        self.assertEqual(result,{'KEEP':'yes','NO_PROXY':'*','no_proxy':'*'})
        self.assertIn('HTTP_PROXY',environment)

    def test_local_rest_bypasses_inherited_download_proxies(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'{}')
            def do_POST(self):self.rfile.read(int(self.headers['Content-Length']));self.send_response(202);self.end_headers();self.wfile.write(b'{}')
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
        try:
            poisoned={key:'http://127.0.0.1:1' for key in ('http_proxy','https_proxy','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','all_proxy')}
            with mock.patch.dict(os.environ,poisoned|{'NO_PROXY':'example.invalid','no_proxy':'example.invalid'}):
                address=f'http://127.0.0.1:{server.server_port}'
                with cohort.direct_urlopen(address,timeout=1) as reply:self.assertEqual(reply.status,200)
                self.assertEqual(cohort.submit_bcs(address,b'test',1),(202,'{}'))
        finally:server.shutdown();server.server_close();worker.join()


def uleb(value):
    output=bytearray()
    while value>=128:output.append((value&127)|128);value>>=7
    return bytes(output)+bytes([value])


def signed_fixture(origin=0, sequence=0, useful=8, run="11"*16):
    """Synthetic signed BCS fixture, not a claimed native Shoal execution."""
    verifier=Ed25519Verifier();lib=verifier.lib;pointer=ctypes.c_void_p
    for name,args,result in [
        ("EVP_PKEY_new_raw_private_key_ex",[pointer,ctypes.c_char_p,ctypes.c_char_p,pointer,ctypes.c_size_t],pointer),
        ("EVP_PKEY_get_raw_public_key",[pointer,pointer,pointer],ctypes.c_int),
        ("EVP_DigestSignInit",[pointer,pointer,pointer,pointer,pointer],ctypes.c_int),
        ("EVP_DigestSign",[pointer,pointer,pointer,pointer,ctypes.c_size_t],ctypes.c_int),
    ]:
        function=getattr(lib,name);function.argtypes=args;function.restype=result
    private=lib.EVP_PKEY_new_raw_private_key_ex(None,b"ED25519",None,b"\x42"*32,32)
    public=ctypes.create_string_buffer(32);size=ctypes.c_size_t(32)
    assert lib.EVP_PKEY_get_raw_public_key(private,public,ctypes.byref(size))==1
    key=public.raw
    code=b"DLGCOH02"+bytes.fromhex(run)+struct.pack("<QQQ",origin,sequence,useful)+bytes((origin+sequence+index)%251 for index in range(useful))
    raw=(hashlib.sha3_256(key+b"\0").digest()+struct.pack("<Q",sequence)+b"\0"+uleb(len(code))+code+b"\0\0"+struct.pack("<QQQ",1000000,1,4000000000)+b"\x04")
    message=hashlib.sha3_256(b"APTOS::RawTransaction").digest()+raw
    context=lib.EVP_MD_CTX_new();signature=ctypes.create_string_buffer(64);size=ctypes.c_size_t(64)
    try:
        assert lib.EVP_DigestSignInit(context,None,None,None,private)==1
        assert lib.EVP_DigestSign(context,signature,ctypes.byref(size),message,len(message))==1
    finally:lib.EVP_MD_CTX_free(context);lib.EVP_PKEY_free(private)
    return raw+b"\0\x20"+key+b"\x40"+signature.raw


class ShoalContractTests(unittest.TestCase):
    def row(self,sequence=0):
        bcs=signed_fixture(sequence=sequence)
        return cohort.decode_signed_workload(bcs)|{"bcs_hex":bcs.hex()}

    def test_signed_bcs_content_and_native_transaction_hash(self):
        row=self.row()
        self.assertEqual((row["origin"],row["sequence"],row["useful_bytes"]),(0,0,8))
        changed=bytearray.fromhex(row["bcs_hex"]);changed[-1]^=1
        with self.assertRaisesRegex(ValueError,"signature"):cohort.decode_signed_workload(changed)
        with self.assertRaises(ValueError):cohort.decode_signed_workload(bytes.fromhex(row["bcs_hex"])+b"extra")

    def test_noncanonical_bcs_lengths_rejected(self):
        for raw in (b"\x80\0",b"\xff"*6):
            with self.assertRaises(ValueError):cohort.BCSReader(raw).uleb()

    def test_plan_identity_bound_to_signed_content_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"plan";row=self.row();path.write_text(json.dumps(row)+"\n")
            self.assertEqual(len(cohort.load_plan(path,"11"*16,0,1,8)),1)
            with self.assertRaisesRegex(ValueError,"selected finite"):cohort.load_plan(path,"22"*16,0,1,8)
            row["origin"]=1;path.write_text(json.dumps(row)+"\n")
            with self.assertRaisesRegex(ValueError,"authenticated BCS"):cohort.load_plan(path,"11"*16,0,1,8)

    def test_fixed_schedule_survives_native_admission_backpressure(self):
        clock=[1000000]
        def submit(address,payload,timeout):clock[0]+=300000;return 202,"{}"
        rows=cohort.ingress([self.row(i) for i in range(3)],"http://127.0.0.1:1",10,1000000,0,1000000,0,submit=submit,now=lambda:clock[0],sleep=lambda secs:clock.__setitem__(0,clock[0]+int(secs*1e6)))
        self.assertEqual([row["scheduled_us"] for row in rows],[1000000,1100000,1200000])
        self.assertEqual([row["admitted_us"] for row in rows],[1000000,1300000,1600000])

    def test_native_rejection_distinct_from_ambiguous_transport(self):
        row=self.row()
        rejected=cohort.ingress([row],"http://127.0.0.1:1",1,0,0,1000000,0,submit=lambda *args:(429,"full"),now=lambda:10)
        self.assertEqual(rejected[0]["native_submission_status"],429)
        self.assertEqual(rejected[0]["native_rejected_us"],10)
        self.assertIsNone(rejected[0]["rejected_us"])
        def timeout(*args):raise TimeoutError("timeout")
        unknown=cohort.ingress([row],"http://127.0.0.1:1",1,0,0,1000000,0,submit=timeout,now=lambda:10)
        self.assertIsNone(unknown[0]["rejected_us"])

    def test_exact_collector_unfinished_foreign_and_ordinal_checks(self):
        plan=[self.row(0),self.row(1)]
        requests=[{key:row[key] for key in ("request_id","origin","sequence","useful_bytes")}|{"admitted_us":10,"scheduled_us":0,"batch_ready_us":None,"materialized_us":None} for row in plan]
        batch={"event":"batch","exact_batch_id":"0:native","payload_bytes":600,"materialized_us":20}
        event={key:plan[0][key] for key in ("request_id","origin","sequence","useful_bytes")}|{"event":"output","output_index":0,"exact_batch_id":"0:native","materialized_us":20}
        result=cohort.collect(plan,requests,[batch,event],0,0,100,0)
        self.assertEqual(result["requests"][0]["materialized_us"],20);self.assertIsNone(result["requests"][1]["materialized_us"])
        with self.assertRaisesRegex(ValueError,"ordinal"):cohort.collect(plan,requests,[batch,event|{"output_index":1}],0,0,100,0)
        other=cohort.collect(plan,requests,[batch,event|{"request_id":"ff"*32}],0,0,100,0)
        self.assertEqual(other["outputs"][0]["useful_bytes"],0)
        self.assertIsNone(other["requests"][0]["materialized_us"])

    def test_plan_uses_native_dag_fixture_and_fixed_fault_ingress(self):
        args=shoal.options().parse_args(["--output","/private/tmp/shoal-test","--nodes","7","--rate","701","--faulty-replica","0"])
        plan=shoal.command_plan(args,"11"*16)
        self.assertEqual(sum(plan["rates"]),701);self.assertEqual(plan["rates"][0],0)
        self.assertIn("shoal-fixture",plan["genesis"][0]);self.assertFalse(plan["native_execution_verified"])
        args.pause_replica=1
        with self.assertRaisesRegex(ValueError,"fixed faulty"):shoal.command_plan(args,"11"*16)

    def test_local_fixture_endpoints_and_longer_prefix_conflict(self):
        root=Path("/private/tmp/genesis")
        text="\n".join(f"{i} {root}/{i}/node.yaml 127.0.0.1:{8001+i}" for i in range(4))
        self.assertEqual(len(shoal.parse_fixture(text,root,4)),4)
        with self.assertRaises(ValueError):shoal.parse_fixture(text.replace("127.0.0.1","0.0.0.0"),root,4)
        output=lambda identity:{"outputs":[{"output_index":0,"request_id":identity,"exact_batch_id":"batch"}]}
        with self.assertRaisesRegex(RuntimeError,"prefixes disagree"):shoal.output_agreement({0:{"outputs":[]},1:output("a"),2:output("b")},[0,1,2])

    def test_fault_plan_keeps_honest_load_and_native_author_whitelist(self):
        args=shoal.options().parse_args(["--output","/private/tmp/shoal-test","--rate","701","--faulty-replica","0","--omit-replica","0","--attacker-rate","11","--publish-to-replica","1"])
        plan=shoal.command_plan(args,"11"*16)
        self.assertEqual(sum(plan["rates"][i] for i in plan["correct_replicas"]),701)
        self.assertEqual(plan["rates"][0],11)
        peers={i:f"{i+1:064x}" for i in range(4)}
        env=shoal.native_faults.environment(args,Path("/tmp/test"),0,peers)
        self.assertEqual(env["BENCHMARK_FAULT_ALLOWED"],peers[1])
        self.assertEqual(shoal.native_faults.environment(args,Path("/tmp/test"),1,peers),{})
        root=Path("/private/tmp/genesis")
        text="\n".join(f"{i} {root}/{i}/node.yaml 127.0.0.1:{8001+i} {peers[i]}" for i in range(4))
        self.assertEqual(shoal.parse_fixture(text,root,4)[0]["author"],peers[0])

    def test_native_tcp_ledger_counts_actual_writes_and_rejects_missing_samples(self):
        before={i:{"written_bytes":100,"read_bytes":90,"observed_us":1000+i} for i in range(4)}
        after={i:{"written_bytes":150,"read_bytes":130,"observed_us":2000+i} for i in range(4)}
        final={i:{"written_bytes":200,"read_bytes":180,"observed_us":3000+i} for i in range(4)}
        ledger=shoal.tcp_ledger(before,after,final,4)
        self.assertEqual(ledger["measurement_written_bytes"],200)
        self.assertEqual(ledger["finite_run_written_bytes"],800)
        self.assertEqual(ledger["before"][2]["observed_us"],1002)
        with self.assertRaisesRegex(ValueError,"missing"):shoal.tcp_ledger(before,{},final,4)
        with self.assertRaisesRegex(ValueError,"regressed"):shoal.tcp_ledger(after,before,final,4)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'io-0.counters';path.write_bytes(struct.pack('=QQQ',0x444c47494f563031,149,45))
            frozen=shoal.exact_io_snapshot(Path(tmp),{0:5000})
            self.assertEqual(frozen[0]['written_bytes'],149)
            self.assertEqual(frozen[0]['observed_us'],5000)
            path.write_bytes(path.read_bytes()+b'extra')
            with self.assertRaisesRegex(ValueError,'size'):shoal.exact_io_snapshot(Path(tmp),{0:5000})

    def test_streamed_signed_plan_and_collector_match_legacy_with_unfinished(self):
        plan=[self.row(0),self.row(1)]
        requests=[{key:row[key] for key in ('request_id','origin','sequence','useful_bytes')}|
            {'scheduled_us':0,'admitted_us':10,'batch_ready_us':None,'materialized_us':None} for row in plan]
        events=[{'event':'batch','exact_batch_id':'batch','payload_bytes':600,'materialized_us':20},
            {key:plan[0][key] for key in ('request_id','origin','sequence','useful_bytes')}|
            {'event':'output','exact_batch_id':'batch','materialized_us':20,'output_index':0}]
        legacy=cohort.collect(plan,requests,events,0,0,100,0)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'plan.jsonl';path.write_text(''.join(json.dumps(row)+'\n' for row in plan))
            store=NativeStore(root/'stage.sqlite')
            try:
                encoding=cohort.prepare_plan_store(store,[path],'11'*16,[2],8)
                self.assertEqual(encoding['native_serialized_transaction_bytes'],[len(bytes.fromhex(plan[0]['bcs_hex']))])
                cohort.collect_store(store,0,iter(requests),iter(events),0,0,100,0)
                for stream in ('requests','outputs','batches'):self.assertEqual(list(store.rows(0,stream)),legacy[stream])
                archive=store.archive(root/'pages')
                reduced=reduce_archive(archive,root/'reduce.sqlite',[0],1000)
                self.assertEqual(reduced['finite_output_receipt']['planned'],2)
                self.assertEqual(reduced['finite_output_receipt']['all_correct_completed'],1)
                args=shoal.options().parse_args(['--output',str(root/'unused'),'--useful-bytes','8',
                    '--warmup','0','--duration','0.0001','--rate','20000'])
                args.nodes=1
                traffic=shoal.tcp_ledger({0:{'written_bytes':0,'read_bytes':0}},
                    {0:{'written_bytes':100,'read_bytes':90}},
                    {0:{'written_bytes':150,'read_bytes':130}},1)
                summary=shoal.comparison_summary(args,reduced,traffic,encoding['native_serialized_transaction_bytes'])
                sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
                import run_comparison
                checked=run_comparison.validate_comparison({'status':'completed','comparison':summary,
                    'agreement':reduced['agreement'],'comparison_eligible':False},'shoal',20000,None,0,.0001,
                    ingress_batch_ms=10,useful_bytes=8,require_cohorts=True,replicas=1)
                self.assertEqual(checked['cohort']['unfinished'],1)
                self.assertFalse(checked['formal_comparison_eligible'])
                self.assertEqual(checked['transaction_bytes'],len(bytes.fromhex(plan[0]['bcs_hex'])))
            finally:store.close()

    def test_receipt_bound_collector_requires_eligibility_and_legacy_honors_preplay(self):
        plan=[self.row(0)]
        requests=[{key:plan[0][key] for key in ('request_id','origin','sequence','useful_bytes')}|
            {'scheduled_us':0,'admitted_us':20,'batch_ready_us':None,'materialized_us':None}]
        events=[{'event':'batch','exact_batch_id':'batch','payload_bytes':600,'materialized_us':20},
            {key:plan[0][key] for key in ('request_id','origin','sequence','useful_bytes')}|
            {'event':'output','exact_batch_id':'batch','materialized_us':20,'output_index':0}]
        # Legacy archives without the new flag remain readable.
        self.assertEqual(cohort.collect(plan,requests,events,0,0,100,0)['requests'][0]['materialized_us'],20)
        for eligibility in (False,True,None,'true',0):
            with self.subTest(eligibility=eligibility),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);path=root/'plan.jsonl';path.write_text(json.dumps(plan[0])+'\n')
                store=NativeStore(root/'stage.sqlite')
                try:
                    cohort.prepare_plan_store(store,[path],'11'*16,[1],8)
                    current=[dict(row) for row in events]
                    if eligibility is not None:current[-1]['origin_eligible']=eligibility
                    if type(eligibility)is not bool:
                        with self.assertRaisesRegex(ValueError,'eligibility flag'):
                            cohort.collect_store(store,0,requests,current,0,0,100,0,observed_us=100)
                    else:
                        cohort.collect_store(store,0,requests,current,0,0,100,0,observed_us=100)
                        expected=20 if eligibility else None
                        self.assertEqual(list(store.rows(0,'requests'))[0]['materialized_us'],expected)
                        self.assertEqual(cohort.collect(plan,requests,current,0,0,100,0)['requests'][0]['materialized_us'],expected)
                finally:store.close()

    def test_streamed_ingress_retains_unadmitted_tail_and_rejects_truncated_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'plan.jsonl';path.write_text(''.join(json.dumps(self.row(i))+'\n' for i in range(3)))
            clock=[10]
            def submit(*args):clock[0]=1001;return 202,'{}'
            output=root/'ingress.jsonl'
            cohort.ingress_to_journal(output,path,'http://127.0.0.1:1',10000,0,0,1000,0,submit=submit,now=lambda:clock[0])
            rows=list(journal_rows(output));self.assertEqual(len(rows),3)
            self.assertEqual([row['admitted_us'] for row in rows],[10,None,None])
            store=NativeStore(root/'stage.sqlite')
            try:
                cohort.prepare_plan_store(store,[path],'11'*16,[3],8)
                with self.assertRaisesRegex(ValueError,'lost finite'):cohort.collect_store(store,0,iter(rows[:1]),iter(()),0,0,1000,0)
            finally:store.close()
            path.write_text(path.read_text().rstrip('\n'))
            with self.assertRaisesRegex(ValueError,'truncated'):list(cohort.iter_plan(path,'11'*16,0,3,8))


if __name__=="__main__":unittest.main()
