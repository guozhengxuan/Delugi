import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import aliyun_bench as bench
import common_artifact as artifact
import common_cloud_controller as build
import common_cloud_worker as worker
import run_raptr_shared_local as raptr
import raptr_shared_local_test as fixtures


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ('identity','known_hosts'): (self.root/name).write_text('test fixture')
        self.inventory = {'schema':1,'hosts':[{
            'replica':i,'region':'ap-southeast-1','ssh':f'root@192.0.2.{i+1}',
            'identity_file':str(self.root/'identity'),'known_hosts_file':str(self.root/'known_hosts'),
            'advertised':f'10.0.0.{i+1}:8000','control_port':8001,
            'budget':{'enforcement':'dedicated_host','cpus':[0,1,2,3],'memory_bytes':16*1024**3,'swap_bytes':0},
            'artifact':{'directory':'/tmp/delugi-common-'+'a'*64,'archive_sha256':'a'*64,'binary_sha256':'b'*64}
        } for i in range(4)]}

    def test_plan_rejects_public_same_host_cross_region_or_mismatched_artifact(self):
        plan = bench.create_plan(self.inventory)
        self.assertEqual(bench.validate_plan(plan),plan)
        for field,value in [('advertised','8.8.8.8:8000'),('advertised','10.0.0.1:8001'),
                            ('region','eu-west-1'),('artifact',dict(self.inventory['hosts'][0]['artifact'],binary_sha256='c'*64))]:
            data = copy.deepcopy(self.inventory); data['hosts'][1][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError): bench.create_plan(data)

    def test_changed_plan_or_ssh_identity_requires_new_plan(self):
        plan=bench.create_plan(self.inventory)
        plan['transaction_bytes']=1024
        with self.assertRaisesRegex(ValueError,'changed'): bench.validate_plan(plan)
        plan=bench.create_plan(self.inventory); (self.root/'known_hosts').write_text('changed key')
        with self.assertRaisesRegex(ValueError,'changed'): bench.validate_plan(plan)

    def test_initial_pilot_cannot_claim_shaping_or_performance(self):
        plan=bench.create_plan(self.inventory)
        self.assertFalse(plan['comparison_eligible']); self.assertEqual(plan['added_delay_ms'],0)
        with self.assertRaises(ValueError): bench.create_plan(self.inventory,bound_ms=10)
        with self.assertRaises(ValueError): bench.create_plan(self.inventory,repeats=0)
        with self.assertRaises(ValueError): bench.create_plan(self.inventory,protocols=['mysticeti'])
        with self.assertRaises(ValueError): bench.create_plan(dict(self.inventory,netem={'delay_ms':10}))

    def test_all_futures_are_observed_after_failure(self):
        seen=[]
        def act(host):
            seen.append(host['replica'])
            if host['replica']==1: raise RuntimeError('fixture')
            return host['replica']
        values, errors=bench.parallel(self.inventory['hosts'],act)
        self.assertEqual(set(seen),{0,1,2,3}); self.assertEqual(set(values),{0,2,3}); self.assertEqual(set(errors),{1})

    def test_failed_prepare_or_start_closes_and_collects_every_host(self):
        for failure in ('prepare','start'):
            calls=[]
            class Fake:
                def __init__(self,h): self.id=h['replica']
                def preflight(self): return {'verified':True}
                def rpc(self,r):
                    calls.append((self.id,r['action']))
                    if r['action']=='keygen':
                        return {'public':{},'files_hex':{n:'01' for n in ('committee.json','genesis-ledger.bcs',*[f'key-{i}.json' for i in range(4)])}}
                    if r['action']==failure and self.id==2: raise RuntimeError('injected SSH loss')
                    if r['action']=='abort': return {'cleanup_confirmed':True}
                    return {}
                def collect(self,nonce,directory): calls.append((self.id,'collect')); return {'recorded':True}
            result=bench.run_trial(bench.create_plan(self.inventory),'raptr','healthy',self.root/failure,Fake)
            self.assertEqual(result['status'],'failed')
            for action in ('abort','collect'): self.assertEqual({i for i,a in calls if a==action},{0,1,2,3})
            if failure=='prepare': self.assertFalse(any(a=='start' for _,a in calls))

    def test_configurations_preserve_protocol_policy_and_fault_identity(self):
        plan=bench.create_plan(self.inventory);nonce='1'*32
        d=bench.configurations(plan,'delugi','silent-first-leader',nonce,{'public':{'public_keys':[[0]*32]*4}})
        r=bench.configurations(plan,'raptr','silent-first-leader',nonce,{})
        self.assertEqual(d['silent'],0); self.assertEqual(r['finite_workload']['counts'],[16,0,16,16])
        self.assertEqual(d['bound_ms'],r['delta_ms'])
        self.assertEqual(r['deployment_profile'],'private-ipv4-n4-v1')
        self.assertTrue(all(a.startswith('127.0.0.1:') for a in d['control_addresses']))
        self.assertEqual(d['storage_profile'],'shared-rocksdb-written-v1')

    def test_build_plan_pins_revision_and_helpers(self):
        plan=build.make_plan(self.inventory,'a'*40)
        self.assertEqual(build.validate(plan,dispatch=True),plan)
        self.assertEqual(plan['build_jobs'],2)
        changed=dict(plan,worker_sha256='0'*64)
        with self.assertRaisesRegex(ValueError,'changed'): build.validate(changed,dispatch=True)
        with self.assertRaises(ValueError): build.make_plan(self.inventory,'main')

    def test_build_dispatch_rejects_inaccurate_parallelism_even_with_valid_plan_hash(self):
        plan=build.make_plan(self.inventory,'a'*40)
        plan['build_jobs']=1
        plan['plan_sha256']=bench.hash_json({k:v for k,v in plan.items() if k!='plan_sha256'})
        self.assertEqual(build.validate(plan),plan)
        with self.assertRaisesRegex(ValueError,'parallelism differs'):
            build.validate(plan,dispatch=True)

    def test_instance_dry_run_does_not_construct_a_client(self):
        argv=['aliyun_bench.py','instances','launch','--state',str(self.root/'missing'),'--amount','4']
        with patch.object(sys,'argv',argv),patch.object(bench.cloud,'Lease',side_effect=AssertionError('cloud API')),patch('sys.stdout',io.StringIO()) as output:
            self.assertEqual(bench.main(),0)
            self.assertTrue(json.loads(output.getvalue())['no_cloud_api_called'])


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.nonce='2'*32
        patcher=patch.object(worker,'PREFIX',str(self.root/'run-'));patcher.start();self.addCleanup(patcher.stop)

    def test_abort_before_prepare_is_persistent_and_exportable(self):
        result=worker.stop({'nonce':self.nonce})
        self.assertTrue(result['cleanup_confirmed'])
        with self.assertRaisesRegex(ValueError,'late worker'): worker.prepare({'nonce':self.nonce})
        stream=io.BytesIO()
        with patch.object(worker.sys,'stdout',SimpleNamespace(buffer=stream)): worker.export({'nonce':self.nonce})
        dest=self.root/'collected';dest.mkdir();stream.seek(0)
        record=bench.runtime_evidence.unpack(stream,dest,expected_metadata={'nonce':self.nonce,'format':'common-pilot-evidence-v1'})
        self.assertTrue((dest/'resource-summary.json').exists())
        self.assertFalse((dest/'keys').exists())

    def test_export_excludes_secret_keys_and_database_files(self):
        root=worker.root_for(self.nonce);root.mkdir()
        worker.write(root/'resource-summary.json',{'cleanup_confirmed':True})
        for name in ('keys/key-0.json','generated-keys/key-1.json','records/db','replicas/node-0/private.key'):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('SECRET_KEY_TEST')
        (root/'node.stdout').write_text('public event\n')
        stream=io.BytesIO()
        with patch.object(worker.sys,'stdout',SimpleNamespace(buffer=stream)):worker.export({'nonce':self.nonce})
        self.assertNotIn(b'SECRET_KEY_TEST',stream.getvalue())
        self.assertIn(b'public event',stream.getvalue())

    def test_nonce_paths_cannot_escape_owned_root(self):
        for nonce in ('../x','A'*32,'1'*31,None):
            with self.assertRaises(ValueError):worker.root_for(nonce)
        worker.root_for(self.nonce).symlink_to(self.root)
        with self.assertRaises(ValueError):worker.root_for(self.nonce)

    def test_pause_requires_matching_start_time(self):
        root=worker.root_for(self.nonce);root.mkdir();worker.write(root/'process.json',{'pid':123,'pid_start':'old'})
        with patch.object(worker,'process_matches',return_value=False),patch.object(worker.os,'killpg') as kill:
            with self.assertRaises(ValueError):worker.rpc({'action':'pause','nonce':self.nonce})
            kill.assert_not_called()


class PortableTests(unittest.TestCase):
    # Reuse fixture construction without duplicating the historical test suite.
    setUp = fixtures.RunnerTests.setUp
    config = fixtures.RunnerTests.config
    rows = fixtures.RunnerTests.rows
    request = fixtures.RunnerTests.request
    build_fixture = fixtures.RunnerTests.build_fixture
    common_build_fixture = fixtures.RunnerTests.common_build_fixture
    result_fixture = fixtures.RunnerTests.result_fixture
    mutate_signed_file = fixtures.RunnerTests.mutate_signed_file
    def test_receipt_relocation_keeps_original_metadata_and_build_arguments(self):
        binary,stamp,_=self.common_build_fixture();stamp['build_root']=str(self.root)
        with tempfile.TemporaryDirectory() as temp:
            relocated=Path(temp)/'checkout';shutil.copytree(self.root,relocated)
            self.assertEqual(raptr.validate_build(relocated/'binary',stamp,relocated)['protocols'],['delugi','raptr'])
            self.assertEqual(raptr.sha256(relocated/'cargo-metadata.json'),stamp['cargo_metadata']['sha256'])
            wrong=dict(stamp,build_root='/another/build')
            with self.assertRaises(ValueError):raptr.validate_build(relocated/'binary',wrong,relocated)

    def test_distributed_latency_is_invariant_to_host_clock_origins(self):
        config=self.result_fixture();epochs={i:1_000_000+i*10**15 for i in range(4)}
        for i in range(4):
            offset=epochs[i]-1_000_000
            def requests(rows):
                for r in rows:
                    for k in ('planned_us','admitted_us','first_materialized_us'):
                        if r[k] is not None:r[k]+=offset
            def outputs(rows):
                for r in rows:r['append_us']+=offset
            self.mutate_signed_file(config,i,'requests.jsonl',requests)
            self.mutate_signed_file(config,i,'output.jsonl',outputs)
            path=Path(config['output_directory'])/f'node-{i}/final.json';body=raptr.bounded_json(path)
            for key in ('epoch_us','freeze_us','deadline_us'):body['body'][key]+=offset
            raptr.atomic_json(path,body)
        result=raptr.validate_results(config,[0,1,2,3],self.root,'a'*64,0,'healthy',host_epochs=epochs)
        self.assertEqual(result['latency']['mean_us'],100000)
        self.assertEqual(result['all_correct_completion']['completed'],4)
        self.assertIsNone(result['all_correct_completion']['mean_us'])
        with self.assertRaises(ValueError):raptr.validate_results(config,[0,1,2,3],self.root,'a'*64,0,'healthy',host_epochs={0:1})

    def test_linux_publication_round_trip_and_tamper_rejection(self):
        binary,stamp,_=self.common_build_fixture()
        for directory in ('core/raptr/qs','core/raptr/transport','core/raptr/src','core-api'):
            path=self.root/directory/'lib.rs';path.write_text('// fixture\n')
            stamp['sources'][path.relative_to(self.root).as_posix()]=raptr.sha256(path)
        binary.write_bytes(b'\x7fELF\x02\x01'+b'\0'*12+struct.pack('<H',62))
        stamp['binary'].update(raptr.file_record(binary));stamp.update(profile='release',build_root=str(self.root))
        stamp['command']['argv'].insert(-2,'--release')
        archive=self.root/'native.tar'
        with tarfile.open(archive,'w') as t:t.add(self.root/stamp['native_dependencies']['directory']/'lib.rs',arcname='lib.rs')
        stamp['native_dependencies']['archive_sha256']=raptr.sha256(archive)
        metadata=self.root/'core/raptr/native-source.json'
        raptr.atomic_json(metadata,{'source_commit':raptr.PIN,'source_archive_sha256':raptr.sha256(archive)})
        stamp['sources']['core/raptr/native-source.json']=raptr.sha256(metadata)
        receipt=self.root/'receipt.json';raptr.atomic_json(receipt,stamp)
        with tempfile.TemporaryDirectory() as temp:
            temp=Path(temp)
            publication=artifact.create(binary,receipt,temp/'publication',self.root)
            artifact.extract(publication['archive'],temp/'installed',publication['sha256'])
            original={'original_archive':publication['archive'],'archive_sha256':publication['sha256']}
            self.assertEqual(artifact.verify(temp/'installed',**original)['status'],'verified')
            manifest_path=temp/'installed/manifest.json';raw=manifest_path.read_bytes()
            manifest=json.loads(raw);manifest['scope']='tampered';raptr.atomic_json(manifest_path,manifest)
            with self.assertRaisesRegex(ValueError,'original publication'):artifact.verify(temp/'installed',**original)
            manifest_path.write_bytes(raw)
            (temp/'installed/node').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'changed'):artifact.verify(temp/'installed')

    def test_archive_rejects_traversal_duplicate_and_links(self):
        for name,kind in [('../escape','file'),('node','duplicate'),('node','symlink')]:
            archive=self.root/'unsafe.tar.gz'
            with tarfile.open(archive,'w:gz') as t:
                member=tarfile.TarInfo(name);member.size=1
                if kind=='symlink':member.type=tarfile.SYMTYPE;member.linkname='/etc/passwd';member.size=0
                t.addfile(member,io.BytesIO(b'x'))
                if kind=='duplicate':t.addfile(member,io.BytesIO(b'y'))
            with tempfile.TemporaryDirectory() as temp,self.assertRaises(ValueError):
                artifact.extract(archive,Path(temp)/'installed',raptr.sha256(archive))


if __name__=='__main__':unittest.main()
