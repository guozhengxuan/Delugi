#!/usr/bin/env python3
"""Adversarial local lifecycle/receipt contracts; no native compile or benchmark."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import run_raptr_shared_local as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def config(self, case='healthy', **options):
        with patch.object(runner, 'unused_addresses', return_value=[f'127.0.0.1:{9000+i}' for i in range(4)]):
            return runner.make_config(self.root, case, **options)

    def rows(self, name, values):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join(json.dumps(value) + '\n' for value in values))
        return path

    def test_configuration_enforces_local_finite_native_profile(self):
        config = self.config()
        self.assertEqual(runner.validate_config(config, 'healthy'), [0, 1, 2, 3])
        for key, value in [('epoch', 2), ('delta_ms', 10), ('addresses', ['10.0.0.1:9000'] * 4)]:
            changed = dict(config, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_config(changed, 'healthy')

    def test_fault_identity_is_explicit_and_has_zero_input(self):
        config = self.config('silent-first-leader')
        self.assertEqual(config['finite_workload']['counts'], [16, 0, 16, 16])
        self.assertEqual(runner.validate_config(config, 'silent-first-leader'), [0, 2, 3])
        missing=self.config('missing-payload-recovery')
        self.assertEqual(missing['finite_workload']['counts'][0],0)
        self.assertEqual(missing['payload_fault'],{'node':0,'drop_initial_batch_messages':3})
        with self.assertRaisesRegex(ValueError,'zero-input node0'):
            self.config('missing-payload-recovery',counts=[1]*4)
        with self.assertRaisesRegex(ValueError, 'positive application'):
            self.config('materializer-delay')

    def test_declared_limits_and_arrival_tail_fail_before_launch(self):
        config = self.config()
        config['limits']['inbox_bytes'] = 1
        with self.assertRaisesRegex(ValueError, 'one maximum'):
            runner.validate_config(config, 'healthy')
        with self.assertRaisesRegex(ValueError, 'arrival falls'):
            self.config(counts=[5000]*4, interval_us=1000, duration_ms=2000)
        with self.assertRaises(ValueError):
            self.config(counts=[True, 1, 1, 1])

    def test_arm_requires_all_ready_and_future_local_epoch(self):
        config = self.config()
        with self.assertRaisesRegex(ValueError, 'all native'):
            runner.arm(config, 'a'*64, {0: {'ready_us': 1}})
        ready = {i: {'ready_us': 1} for i in range(4)}
        result = runner.arm(config, 'a'*64, ready)
        self.assertEqual(result['configuration_sha256'], 'a'*64)
        self.assertGreater(result['epoch_us'], 1)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            runner.arm(config, 'a'*64, ready)

    def test_arm_uses_native_clock_gettime_domain_not_python_mach_origin(self):
        config = self.config()
        ready = {i: {'ready_us': 40_000_000} for i in range(4)}
        with patch.object(runner.time, 'monotonic_ns', return_value=1_000_000_000), \
             patch.object(runner.time, 'clock_gettime_ns', return_value=40_100_000_000) as clock:
            result = runner.arm(config, 'a'*64, ready)
        self.assertEqual(result['epoch_us'], 40_350_000)
        clock.assert_called_once_with(runner.time.CLOCK_MONOTONIC)

    def test_readiness_binds_owned_pid_configuration_and_profile(self):
        config = self.config()
        child = SimpleNamespace(id=2, process=SimpleNamespace(pid=999))
        row = dict(schema=1, profile=runner.PROFILE, run_id=config['run_id'], configuration_sha256='a'*64,
                   id=2, pid=999, ready_us=1)
        self.assertEqual(runner.validate_ready(row, config, 'a'*64, child), row)
        for key in ('pid', 'id', 'configuration_sha256', 'profile'):
            changed = dict(row, **{key: 'wrong'})
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.validate_ready(changed, config, 'a'*64, child)

    def test_prefix_check_cannot_use_empty_replica_to_hide_fork(self):
        runner.compare_prefixes({0: [], 1: ['a'], 2: ['a', 'b']})
        with self.assertRaisesRegex(ValueError, 'diverges'):
            runner.compare_prefixes({0: [], 1: ['a', 'c'], 2: ['a', 'b']})

    def request(self, sequence=0, **changes):
        value = dict(sequence=sequence, request_id=f'{sequence+1:064x}', useful_bytes=128,
                     planned_us=1100000 + sequence*1000, admitted_us=None, rejected_us=None,
                     own_batch_ready_us=None, first_materialized_us=None)
        value.update(changes)
        value.setdefault('admission_event',sequence+1 if value['admitted_us'] is not None else None)
        value.setdefault('rejection_event',sequence+1 if value['rejected_us'] is not None else None)
        value.setdefault('first_materialized_event',100 if value['first_materialized_us'] is not None else None)
        return value

    def test_admission_conservation_keeps_rejection_unoffered_and_censoring(self):
        config = self.config(counts=[4]*4)
        rows = [self.request(0, admitted_us=1100000, first_materialized_us=1200000),
                self.request(1, admitted_us=1101000), self.request(2, rejected_us=1102000), self.request(3)]
        counts, latency = runner.validate_requests(self.rows('requests.jsonl', rows), config, 0, 1000000, 2000000)
        self.assertEqual(counts, dict(planned=4,offered=3,admitted=2,rejected=1,completed=1,unfinished=1,unoffered=1))
        self.assertEqual(latency, [100000])

    def test_batch_readiness_can_follow_actual_materialization(self):
        config = self.config(counts=[1]*4)
        row = self.request(admitted_us=1100000, first_materialized_us=1200000, own_batch_ready_us=1300000)
        self.assertEqual(runner.validate_requests(self.rows('late.jsonl',[row]), config, 0,1000000,2000000)[0]['completed'],1)

    def test_credit_before_admission_and_missing_input_tail_rejected(self):
        config = self.config(counts=[1]*4)
        for row in [self.request(first_materialized_us=1200000),
                    self.request(admitted_us=1300000, first_materialized_us=1200000),
                    self.request(admitted_us=1100000,rejected_us=1100000)]:
            with self.assertRaises(ValueError):
                runner.validate_requests(self.rows('bad.jsonl',[row]),config,0,1000000,2000000)
        with self.assertRaisesRegex(ValueError,'omitted finite input tail'):
            runner.validate_requests(self.rows('tail.jsonl',[]),config,0,1000000,2000000)

    def test_journal_partial_tail_and_symlink_rejected(self):
        path = self.root/'partial.jsonl'
        path.write_text('{}')
        with self.assertRaises(ValueError): list(runner.journal(path))
        (self.root/'link').symlink_to(path)
        with self.assertRaises(ValueError): runner.safe_file(self.root,'link')
        with self.assertRaises(ValueError): runner.safe_file(self.root,'../partial.jsonl')

    def build_fixture(self):
        roots = ('core/raptr/node','core/raptr/native','core/raptr/qs','core/raptr/transport',
                 'core/raptr/src','core-api','node','shared')
        for name in roots: (self.root/name).mkdir(parents=True,exist_ok=True)
        names = ('core/raptr/node/Cargo.toml','core/raptr/node/Cargo.lock','core/raptr/native-source.json',
                 'core/raptr/Cargo.toml','core/raptr/Cargo.lock','core/raptr/native/.cargo/config.toml',
                 'shared/store-rocksdb/Cargo.lock','shared/network-async/src/lib.rs')
        for name in (*names,'shared/store-rocksdb/native-profile.json'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
        archive=self.root/'native.tar';archive.write_bytes(b'checked native archive fixture')
        tree=self.root/f'core/raptr/.native-deps/{runner.PIN}';tree.mkdir(parents=True)
        (tree/'lib.rs').write_text('native dependency')
        native_files={'lib.rs':{'kind':'file','executable':False,**runner.file_record(tree/'lib.rs')}}
        native={'commit':runner.PIN,'directory':str(tree.relative_to(self.root)),
                'archive_path':'native.tar','archive_sha256':runner.sha256(archive),
                'files':native_files,'tree_sha256':runner.digest(native_files)}
        runner.atomic_json(self.root/'core/raptr/native-source.json',{'source_commit':runner.PIN,'source_archive_sha256':runner.sha256(archive)})
        binary=self.root/'binary';binary.write_bytes(b'native fixture');binary.chmod(0o700)
        stamp=dict(schema=1,format=runner.BUILD_FORMAT,status='completed',native_commit=runner.PIN,
                   source_before_after_equal=True,native_dependencies=native,action='build',profile='dev',binary=dict(role='raptr-shared-node',**runner.file_record(binary)),
                   toolchain=dict(rustc_version='1.78.0',executables={'cargo':{'path':'/test/cargo'}}),
                   command={'status':'completed','returncode':0,'cleanup':{'status':'completed','remaining':[]},
                            'argv':['/test/cargo','--config',str(self.root/'core/raptr/native/.cargo/config.toml'),'build',
                                    '--manifest-path',str(self.root/'core/raptr/node/Cargo.toml'),'--locked','--offline','--jobs','1','--bin','raptr-shared-node']},sources={name:runner.sha256(self.root/name) for name in names},
                   profiles={'shared/store-rocksdb/native-profile.json':runner.sha256(self.root/'shared/store-rocksdb/native-profile.json')})
        return binary,stamp

    def test_build_guard_rejects_source_binary_and_new_file_drift(self):
        binary,stamp=self.build_fixture()
        runner.validate_build(binary,stamp,self.root)
        (self.root/'core/raptr/src/new.rs').write_text('new')
        with self.assertRaisesRegex(ValueError,'unbound mutable'):
            runner.validate_build(binary,stamp,self.root)
        (self.root/'core/raptr/src/new.rs').unlink()
        binary.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'built role'):
            runner.validate_build(binary,stamp,self.root)

    def common_build_fixture(self):
        binary,stamp=self.build_fixture()
        root_manifest=self.root/'core/raptr/node/Cargo.toml'
        root_manifest.write_text('''[package]
name="raptr-shared-node"
autobins=false
[[bin]]
name="raptr-shared-node"
path="../../../node/src/shared_main.rs"
[dependencies]
delugi-core={path="../../delugi",features=["rocksdb-records"]}
raptr-qs={path="../qs",features=["rocksdb-backend"]}
raptr={path="../native"}
common-node={path="../../../node"}
''')
        for name in ('Cargo.toml','Cargo.lock','core/delugi/Cargo.toml','core/delugi/src/lib.rs','node/src/shared_main.rs'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name)
            stamp['sources'][name]=runner.sha256(path)
        stamp['sources']['core/raptr/node/Cargo.toml']=runner.sha256(root_manifest)
        packages=[{'id':'assembly','name':'raptr-shared-node','manifest_path':str(root_manifest),
                   'targets':[{'name':'raptr-shared-node','kind':['bin'],'src_path':str(self.root/'node/src/shared_main.rs')}]}]
        nodes=[{'id':'assembly','dependencies':['delugi-core','raptr-qs','raptr','common-node'],'features':[]}]
        for name,directory,features in [('delugi-core','core/delugi',['rocksdb-records']),('raptr-qs','core/raptr/qs',['rocksdb-backend']),('raptr','core/raptr/native',[]),('common-node','node',[])]:
            packages.append({'id':name,'name':name,'manifest_path':str(self.root/directory/'Cargo.toml')})
            nodes.append({'id':name,'features':features,'dependencies':[]})
        metadata={'version':1,'packages':packages,'resolve':{'root':'assembly','nodes':nodes}}
        proof_path=self.root/'cargo-metadata.json';runner.atomic_json(proof_path,metadata)
        stamp.update(runner.resolved_capabilities(metadata,self.root))
        stamp['cargo_metadata']={'path':'cargo-metadata.json',**runner.file_record(proof_path),
                                'argv':['/test/cargo','--config',str(self.root/'core/raptr/native/.cargo/config.toml'),'metadata',
                                        '--manifest-path',str(root_manifest),'--locked','--offline','--format-version','1'],
                                'returncode':0,'cleanup':{'status':'completed','remaining':[]}}
        return binary,stamp,metadata

    def test_common_capabilities_are_resolved_and_preserved_in_archive(self):
        binary,stamp,_=self.common_build_fixture()
        result=runner.validate_build(binary,stamp,self.root)
        self.assertEqual(result['protocols'],['delugi','raptr'])
        self.assertEqual(result['compiled_features']['delugi-core'],['rocksdb-records'])
        receipt=self.root/'receipt.json';runner.atomic_json(receipt,stamp)
        runner.archive_build(binary,receipt,self.root/'archive',self.root)
        self.assertEqual(runner.sha256(self.root/'archive/cargo-metadata.json'),stamp['cargo_metadata']['sha256'])

    def test_legacy_receipt_cannot_gain_capabilities_from_asserted_fields(self):
        binary,stamp=self.build_fixture()
        self.assertEqual(runner.validate_build(binary,stamp,self.root)['protocols'],['raptr'])
        stamp.update(protocols=['delugi','raptr'],compiled_features={'delugi-core':['rocksdb-records']})
        with self.assertRaisesRegex(ValueError,'metadata proof'):
            runner.validate_build(binary,stamp,self.root)

    def test_common_metadata_cannot_hide_missing_feature_or_changed_target(self):
        binary,stamp,metadata=self.common_build_fixture()
        metadata['resolve']['nodes'][1]['features']=[]
        runner.atomic_json(self.root/'cargo-metadata.json',metadata)
        stamp['cargo_metadata'].update(runner.file_record(self.root/'cargo-metadata.json'))
        with self.assertRaisesRegex(ValueError,'compiled feature absent'):
            runner.validate_build(binary,stamp,self.root)
        metadata['resolve']['nodes'][1]['features']=['rocksdb-records']
        metadata['packages'][0]['targets'][0]['src_path']=str(self.root/'core/raptr/node/src/main.rs')
        with self.assertRaisesRegex(ValueError,'entry point'):
            runner.resolved_capabilities(metadata,self.root)

    def test_common_capability_metadata_and_delugi_source_are_hash_bound(self):
        binary,stamp,_=self.common_build_fixture()
        (self.root/'core/delugi/src/new.rs').write_text('unbound')
        with self.assertRaisesRegex(ValueError,'unbound mutable'):
            runner.validate_build(binary,stamp,self.root)
        (self.root/'core/delugi/src/new.rs').unlink()
        (self.root/'cargo-metadata.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'metadata bytes changed'):
            runner.validate_build(binary,stamp,self.root)

    def test_resolved_dev_features_are_not_claimed_as_binary_features(self):
        _,_,metadata=self.common_build_fixture()
        metadata['resolve']['nodes'][1]['features'].append('test-only-feature')
        self.assertEqual(runner.resolved_capabilities(metadata,self.root)['compiled_features']['delugi-core'],['rocksdb-records'])
        metadata['packages'][0]['targets'][0]['src_path']=str(self.root/'core/raptr/node/../../../node/src/shared_main.rs')
        self.assertEqual(runner.resolved_capabilities(metadata,self.root)['entry_point'],'node/src/shared_main.rs')

    def executor_fixture(self):
        before={'limits':dict(runner.EXECUTOR_LIMITS),'admitted_async':3,'admitted_blocking':1,'started_async':2,'started_blocking':1,
                'body_finished_async':1,'body_finished_blocking':1,'joined_async':1,'joined_blocking':1,
                'cancelled_async':0,'cancelled_blocking':0,'panicked':0,'rejected_capacity':0,'rejected_closed':0,
                'retained_async':2,'retained_blocking':0,'queued_async':1,'queued_blocking':0,
                'active_async':1,'active_blocking':0,'maximum_retained_async':3,'maximum_retained_blocking':1,
                'groups':[{'id':1,'label':'native','closed':False,'retained':2}],'failure':None}
        after=copy.deepcopy(before)
        after.update(joined_async=3,cancelled_async=2,retained_async=0,queued_async=0,active_async=0)
        after['groups'][0].update(closed=True,retained=0)
        return {'executor_at_freeze':before,'executor_at_cleanup':after}

    def test_executor_accepts_explicit_cancellation_with_complete_join(self):
        result=runner.validate_executor_lifecycle(self.executor_fixture(),required=True)
        self.assertEqual(result['status'],'passed')
        self.assertEqual(result['at_cleanup']['cancelled_async'],2)

    def test_common_executor_evidence_is_mandatory_but_legacy_is_readable(self):
        self.assertEqual(runner.validate_executor_lifecycle({})['status'],'unavailable_historical_receipt')
        with self.assertRaisesRegex(ValueError,'requires both'):
            runner.validate_executor_lifecycle({},required=True)
        config=self.result_fixture()
        with self.assertRaisesRegex(ValueError,'requires both'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy',require_executor=True)

    def test_executor_rejects_leaks_failed_capacity_and_unclosed_groups(self):
        for field,value in [('joined_async',2),('retained_async',1),('active_async',1),
                            ('rejected_capacity',1),('panicked',1),('failure','error')]:
            body=self.executor_fixture();body['executor_at_cleanup'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                runner.validate_executor_lifecycle(body,required=True)
        body=self.executor_fixture();body['executor_at_cleanup']['groups'][0]['closed']=False
        with self.assertRaisesRegex(ValueError,'remains open'):
            runner.validate_executor_lifecycle(body,required=True)

    def test_executor_rejects_counter_reset_or_group_disappearance(self):
        body=self.executor_fixture();body['executor_at_cleanup'].update(admitted_blocking=0,joined_blocking=0,started_blocking=0,body_finished_blocking=0)
        with self.assertRaisesRegex(ValueError,'counters decreased'):
            runner.validate_executor_lifecycle(body,required=True)
        body=self.executor_fixture();body['executor_at_cleanup']['groups'][0]['id']=2
        with self.assertRaisesRegex(ValueError,'discarded group'):
            runner.validate_executor_lifecycle(body,required=True)

    def test_executor_capacity_is_explicit_bound_and_constant(self):
        config=self.config()
        for key,value in runner.EXECUTOR_LIMITS.items():self.assertEqual(config['limits'][key],value)
        body=self.executor_fixture()
        with self.assertRaisesRegex(ValueError,'configured envelope'):
            runner.validate_executor_lifecycle(body,required=True,expected_limits={'max_async_tasks':99,'max_blocking_tasks':1024})
        body['executor_at_cleanup']['limits']['max_async_tasks']=4
        with self.assertRaisesRegex(ValueError,'capacity changed'):
            runner.validate_executor_lifecycle(body,required=True)
        body=self.executor_fixture();body['executor_at_freeze']['maximum_retained_async']=100001
        with self.assertRaisesRegex(ValueError,'conservation differs'):
            runner.validate_executor_lifecycle(body,required=True)

    def test_legacy_limits_profile_remains_readable_without_executor_fields(self):
        config=self.result_fixture()
        for key in runner.EXECUTOR_LIMITS:config['limits'].pop(key)
        value={'schema':1,'profile':runner.PROFILE,'native_policy_commit':runner.PIN,
               'configured_delta_ms':100,'injected_delay_ms':0,'materialization_delay_ms':0,'payload_fault':None,
               'committee_sha256':'a'*64,'genesis_ledger_sha256':'b'*64,'limits':dict(runner.DEFAULT_LIMITS),
               'tokio_workers':2,'maximum_blocking_threads':32,'native_timer_multipliers':{'leader':4.0,'partial_qc':0.1,'fetch':2.0,'round_sync':15.0},
               'consensus':{},'quorum_store':{}}
        runner.validate_effective_profile(value,config,'a'*64,'b'*64)
        self.assertEqual(runner.validate_config(config,'healthy'),[0,1,2,3])

    def test_failed_or_unpinned_build_cannot_be_used(self):
        binary,stamp=self.build_fixture()
        for field,value in [('status','failed'),('native_commit','0'*40),('source_before_after_equal',False)]:
            with self.subTest(field=field),self.assertRaises(ValueError):
                runner.validate_build(binary,dict(stamp,**{field:value}),self.root)

    def test_check_receipt_and_changed_pinned_dependency_cannot_launch(self):
        binary,stamp=self.build_fixture()
        with self.assertRaisesRegex(ValueError,'explicit binary build'):
            runner.validate_build(binary,dict(stamp,action='check'),self.root)
        (self.root/stamp['native_dependencies']['directory']/'lib.rs').write_text('changed dependency')
        with self.assertRaisesRegex(ValueError,'dependency source changed'):
            runner.validate_build(binary,stamp,self.root)

    def test_archive_copies_only_bound_source_and_public_build_receipt(self):
        binary,stamp=self.build_fixture()
        (self.root/'unrelated-secret').write_text('not an artifact')
        receipt=self.root/'receipt.json';runner.atomic_json(receipt,stamp)
        _,result=runner.archive_build(binary,receipt,self.root/'archive',self.root)
        self.assertEqual(runner.sha256(result['executable']),stamp['binary']['sha256'])
        self.assertFalse((self.root/'archive/source/unrelated-secret').exists())

    def test_offline_verifier_must_bind_exact_index_and_signers(self):
        config=self.config();path=self.root/'config.json';runner.atomic_json(path,config)
        with patch.object(runner,'run_command',return_value=dict(schema=1,verified=True,verified_signers=[0],index_sha256='a'*64)):
            with self.assertRaisesRegex(ValueError,'exact signer/archive'):
                runner.verify_archive('binary',path,config,[0,1,2,3],self.root,999999999)

    def result_fixture(self, correct=(0,1,2,3), case='healthy'):
        counts=[1]*4
        if case=='silent-first-leader': counts[1]=0
        config=self.config(case,counts=counts)
        keys=Path(config['key_directory']);keys.mkdir()
        committee={'schema':1,'epoch':1,'members':[{'id':i,'author':f'{i+10:064x}'} for i in range(4)]}
        runner.atomic_json(keys/'committee.json',committee)
        (keys/'genesis-ledger.bcs').write_bytes(b'signed-genesis-fixture')
        for replica in correct:
            directory=Path(config['output_directory'])/f'node-{replica}';directory.mkdir(parents=True)
            request=self.request(request_id=f'{replica+1:064x}',admitted_us=1100000,first_materialized_us=1200000)
            self.rows(str((directory/'requests.jsonl').relative_to(self.root)),[request])
            transactions=[{'native_transaction_bcs_hex':f'{i:02x}','request_id':f'{i+1:064x}',
                           'origin':i,'sequence':0,'eligible':True,'first_seen':True,'own_credit':i==replica} for i in correct]
            sections=[]
            for ordinal,round_number in enumerate((1,2,3,4)):
                sections.append({'schema':1,'ordinal':ordinal,'append_us':1200000+ordinal,'event':100+ordinal,
                    'block':{'epoch':1,'round':round_number,'author':committee['members'][round_number%4]['author'],'digest':f'{round_number:064x}'},
                    'section':{'kind':'proofs'},'batches':[{'key':{},'native_info_bcs_hex':'00','first_occurrence':True,'transactions':transactions}] if ordinal==0 else []})
            self.rows(str((directory/'output.jsonl').relative_to(self.root)),sections)
            runner.atomic_json(directory/'workload-manifest.json',{'schema':1})
            runner.atomic_json(directory/'effective-profile.json',{'schema':1,'profile':runner.PROFILE,'native_policy_commit':runner.PIN,
                'configured_delta_ms':100,'injected_delay_ms':0,'materialization_delay_ms':config['materialization_delay_ms'],
                'committee_sha256':runner.sha256(keys/'committee.json'),'genesis_ledger_sha256':runner.sha256(keys/'genesis-ledger.bcs'),
                'limits':dict(config['limits']),'tokio_workers':2,'maximum_blocking_threads':32,
                'native_timer_multipliers':{'leader':4.0,'partial_qc':0.1,'fetch':2.0,'round_sync':15.0},'consensus':{},'quorum_store':{}})
            finite=dict(planned=1,offered=1,admitted=1,rejected=0,completed=1,unfinished=0,unoffered=0)
            body={'schema':1,'profile':runner.PROFILE,'committee_sha256':runner.sha256(keys/'committee.json'),'run_id':config['run_id'],'configuration_sha256':'a'*64,'id':replica,'epoch_us':1000000,'freeze_us':5000000,'deadline_us':5000000,
                  'counts':finite,'files':[{'name':name,'sha256':runner.sha256(directory/name),'rows':rows} for name,rows in
                                         [('requests.jsonl',1),('output.jsonl',4),('workload-manifest.json',1),('effective-profile.json',1)]]}
            runner.atomic_json(directory/'final.json',{'schema':1,'signer':replica,'body':body,'body_bcs_hex':'00','signature_hex':'00'})
        return config

    def mutate_signed_file(self,config,replica,name,mutate):
        directory=Path(config['output_directory'])/f'node-{replica}'
        path=directory/name
        rows=list(runner.journal(path));mutate(rows)
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
        receipt=runner.bounded_json(directory/'final.json')
        entry=next(item for item in receipt['body']['files'] if item['name']==name)
        entry.update(sha256=runner.sha256(path),rows=len(rows))
        runner.atomic_json(directory/'final.json',receipt)

    def test_reducer_accepts_exact_authenticated_rows_and_native_empty_markers(self):
        # Signature-shaped fixture alone is never execute() acceptance; execute
        # separately requires the actual native offline verifier success.
        config=self.result_fixture()
        result=runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')
        self.assertEqual(result['totals']['completed'],4)
        self.assertEqual(result['agreement']['longest_sections'],4)
        self.assertEqual(result['latency']['mean_us'],100000)

    def test_reducer_detects_signed_credit_drift_and_native_prefix_divergence(self):
        config=self.result_fixture()
        self.mutate_signed_file(config,2,'output.jsonl',lambda rows:rows[3]['block'].update(digest='f'*64))
        with self.assertRaisesRegex(ValueError,'diverges'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def test_reducer_rejects_forged_first_materialization_endpoint(self):
        config=self.result_fixture()
        self.mutate_signed_file(config,0,'requests.jsonl',lambda rows:rows[0].update(first_materialized_us=1200001))
        with self.assertRaisesRegex(ValueError,'actual first native append'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def test_reducer_rehashes_consumed_bytes_against_signed_descriptor(self):
        config=self.result_fixture()
        path=Path(config['output_directory'])/'node-0/output.jsonl'
        path.write_text(path.read_text()+'{}\n')
        with self.assertRaisesRegex(ValueError,'changed before reduction'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def test_silent_acceptance_needs_three_native_anchor_authors(self):
        config=self.result_fixture(correct=(0,2,3),case='silent-first-leader')
        result=runner.validate_results(config,[0,2,3],self.root,'a'*64,1000000,'silent-first-leader')
        self.assertEqual(result['totals']['completed'],3)
        for replica in (0,2,3):
            self.mutate_signed_file(config,replica,'output.jsonl',lambda rows:rows[1]['block'].update(round=5))
        with self.assertRaisesRegex(ValueError,'three subsequent'):
            runner.validate_results(config,[0,2,3],self.root,'a'*64,1000000,'silent-first-leader')

    def test_materializer_delay_cannot_masquerade_as_exercised_without_witness(self):
        config=self.result_fixture()
        with self.assertRaisesRegex(ValueError,'exercised-delay witness'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'materializer-delay')

    def test_receipt_metadata_mutation_changes_offline_reduction_binding(self):
        config=self.result_fixture();before=runner.evidence_snapshot(config,[0,1,2,3])
        receipt=Path(config['output_directory'])/'node-0/final.json'
        value=runner.bounded_json(receipt);value['signature_hex']='ff';runner.atomic_json(receipt,value)
        self.assertNotEqual(before,runner.evidence_snapshot(config,[0,1,2,3]))

    def test_equal_clock_preplay_does_not_gain_credit_from_later_admission_event(self):
        config=self.result_fixture()
        self.mutate_signed_file(config,0,'requests.jsonl',lambda rows:rows[0].update(
            admitted_us=1200000,admission_event=101,first_materialized_us=None,first_materialized_event=None))
        self.mutate_signed_file(config,0,'output.jsonl',lambda rows:rows[0]['batches'][0]['transactions'][0].update(own_credit=False))
        receipt_path=Path(config['output_directory'])/'node-0/final.json'
        receipt=runner.bounded_json(receipt_path);receipt['body']['counts'].update(completed=0,unfinished=1)
        runner.atomic_json(receipt_path,receipt)
        result=runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'unfinished')
        self.assertEqual(result['totals']['completed'],3)
        self.assertEqual(result['totals']['unfinished'],1)
        self.assertEqual(result['agreement']['status'],'passed')

    def test_observer_late_freeze_cannot_extend_actual_cohort_endpoint(self):
        config=self.result_fixture()
        self.mutate_signed_file(config,0,'requests.jsonl',lambda rows:rows[0].update(first_materialized_us=5000001))
        receipt_path=Path(config['output_directory'])/'node-0/final.json'
        receipt=runner.bounded_json(receipt_path);receipt['body']['freeze_us']=6000000
        runner.atomic_json(receipt_path,receipt)
        with self.assertRaisesRegex(ValueError,'planned/frozen interval'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def test_effective_native_policy_drift_between_replicas_rejected(self):
        config=self.result_fixture()
        self.mutate_signed_file(config,2,'effective-profile.json',lambda rows:rows[0]['quorum_store'].update(unexpected_override=10))
        with self.assertRaisesRegex(ValueError,'different effective native/service'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def test_own_completion_and_prefix_overlap_do_not_hide_missing_other_origin_tail(self):
        config=self.result_fixture()
        for replica in range(4):
            def move_late(rows):
                tx=rows[0]['batches'][0]['transactions'].pop(1)
                late=copy.deepcopy(rows[-1]);late.update(ordinal=4,event=104,append_us=1200004)
                late['block'].update(round=5,author=f'{11:064x}',digest=f'{5:064x}')
                late['batches']=[{'key':{},'native_info_bcs_hex':'01','first_occurrence':True,'transactions':[tx]}]
                if replica!=0:rows.append(late)
            self.mutate_signed_file(config,replica,'output.jsonl',move_late)
        self.mutate_signed_file(config,1,'requests.jsonl',lambda rows:rows[0].update(first_materialized_us=1200004,first_materialized_event=104))
        # Each origin has its own credited completion; replica0 still lacks the
        # later origin1 request while its round4 prefix agrees exactly.
        with self.assertRaisesRegex(ValueError,'all-correct finite cohort'):
            runner.validate_results(config,[0,1,2,3],self.root,'a'*64,1000000,'healthy')

    def recovery_fixture(self):
        config=self.config('missing-payload-recovery')
        committee={'members':[{'id':i,'author':f'{i+10:064x}'} for i in range(4)]}
        info=bytearray(120);info[:32]=bytes.fromhex(committee['members'][1]['author'])
        for offset,value in ((32,3),(40,2),(48,1),(96,1),(104,99)):
            info[offset:offset+8]=value.to_bytes(8,'little')
        info[64:96]=bytes.fromhex('e'*64)
        witness={'epoch':1,'author':committee['members'][1]['author'],'id':3,'nonce':2,
                 'digest':'e'*64,'num_txns':1,'num_bytes':99,'native_info_bcs_hex':info.hex()}
        identity=runner.fault_batch_identity(witness)
        snapshot={'configured_drop_messages':3,'dropped_messages':1,'dropped_batches':1,
                  'drop_records':[{'message_index':0,'sender':witness['author'],'observed_us':1150,'native_payload_verified':True,'batches':[witness]}],
                  'repair_requests':[{'rpc_id':7,'digest':witness['digest'],'recipient':committee['members'][2]['author'],
                                      'started_us':1200,'finished_us':1300,'outcome':'received_batch','received_batch':copy.deepcopy(witness),'error':None}]}
        outputs={identity:{'append_us':1400,'ordinal':2,'transactions':[{'eligible':True,'origin':1,'sequence':0,'request_id':'b'*64}]}}
        admissions={(1,0):('b'*64,1100,True)}
        return snapshot,config,committee,outputs,admissions

    def test_payload_recovery_joins_exact_dropped_descriptor_native_rpc_and_known_output(self):
        snapshot,config,committee,outputs,admissions=self.recovery_fixture()
        result=runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,admissions)
        self.assertEqual(result['status'],'passed')
        self.assertEqual(result['matched_repairs'][0]['admitted_request_ids'],['b'*64])

    def test_payload_receive_without_verified_materialization_cannot_pass(self):
        snapshot,config,committee,outputs,admissions=self.recovery_fixture()
        with self.assertRaisesRegex(ValueError,'no nonempty admitted batch'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,{},admissions)
        with self.assertRaisesRegex(ValueError,'no nonempty admitted batch'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,{})

    def test_payload_recovery_rejects_descriptor_alias_or_digest_only_match(self):
        snapshot,config,committee,outputs,admissions=self.recovery_fixture()
        snapshot['repair_requests'][0]['received_batch']['nonce']=99
        with self.assertRaisesRegex(ValueError,'exact native BCS'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,admissions)

    def test_payload_repair_after_deadline_and_pre_drop_response_do_not_pass(self):
        snapshot,config,committee,outputs,admissions=self.recovery_fixture()
        snapshot['repair_requests'][0]['finished_us']=2001
        with self.assertRaisesRegex(ValueError,'outside the observed interval'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,admissions)
        snapshot['repair_requests'][0].update(started_us=1100,finished_us=1120)
        with self.assertRaisesRegex(ValueError,'no nonempty admitted batch'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,admissions)

    def test_empty_native_repair_is_not_useful_payload_recovery(self):
        snapshot,config,committee,outputs,admissions=self.recovery_fixture()
        old_identity=next(iter(outputs))
        for witness in (snapshot['drop_records'][0]['batches'][0],snapshot['repair_requests'][0]['received_batch']):
            raw=bytearray.fromhex(witness['native_info_bcs_hex']);raw[96:104]=bytes(8)
            witness.update(num_txns=0,native_info_bcs_hex=raw.hex())
        identity=runner.fault_batch_identity(snapshot['drop_records'][0]['batches'][0]);outputs[identity]=outputs.pop(old_identity)
        with self.assertRaisesRegex(ValueError,'no nonempty admitted batch'):
            runner.validate_payload_recovery(snapshot,config,committee,1000,2000,outputs,admissions)

    def test_proxy_and_foreign_benchmark_environment_removed(self):
        with patch.dict(runner.os.environ,{'HTTPS_PROXY':'external','BENCHMARK_FAULT':'bad','RAPTR_DELTA_MS':'999','KEEP':'yes'},clear=True):
            env=runner.child_environment()
        self.assertEqual(env,{'KEEP':'yes','NO_PROXY':'127.0.0.1,localhost,::1'})

    def test_pause_and_resume_require_observed_owned_states(self):
        child=object.__new__(runner.Child);child.id=1;child.process=SimpleNamespace(pid=123)
        signals=[];child.owned=SimpleNamespace(send=signals.append)
        identity={'pid':123,'parent_pid':99,'group':123,'start':'fixed-start','rss_bytes':10}
        states=[dict(identity,state=state) for state in ('R','T','T','R')]
        with patch.object(child,'_leader',side_effect=states),patch.object(runner.time,'clock_gettime_ns',side_effect=[1000000000,1100000000,1200000000,1300000000]):
            observation=child.pause();child.resume(observation)
        self.assertEqual(signals,[runner.signal.SIGSTOP,runner.signal.SIGCONT])
        self.assertEqual(observation['status'],'completed')
        self.assertEqual(observation['observed_paused_lower_bound_us'],100000)
        self.assertEqual(observation['observed_paused_upper_bound_us'],300000)
        self.assertEqual(observation['stop_identity']['start'],observation['resume_identity']['start'])

    def test_missing_pause_acknowledgement_fails(self):
        child=object.__new__(runner.Child);child.id=1;child.process=SimpleNamespace(pid=123)
        child.owned=SimpleNamespace(send=lambda _:None)
        with patch.object(child,'_leader',return_value={'state':'R'}):
            with self.assertRaisesRegex(TimeoutError,'stop acknowledgement'):
                child.pause(timeout=0)

    def test_finish_reaps_exited_leader_before_checking_remaining_group(self):
        child=object.__new__(runner.Child);child.id=1;child.identity={'pid':123}
        events=[]
        def poll():
            events.append('poll')
            return 1
        def cleanup(timeout):
            self.assertEqual(events,['poll'])
            events.append('group_cleanup')
            return {'status':'completed','remaining':[]}
        child.process=SimpleNamespace(pid=123,poll=poll)
        child.owned=SimpleNamespace(cleanup=cleanup)
        child.stdout=SimpleNamespace(close=lambda:events.append('stdout_closed'))
        child.stderr=SimpleNamespace(close=lambda:events.append('stderr_closed'))
        result=child.finish()
        self.assertEqual(result['exit_code'],1)
        self.assertEqual(result['cleanup']['status'],'completed')
        self.assertEqual(events,['poll','group_cleanup','poll','stdout_closed','stderr_closed'])

    def test_success_cannot_survive_unconfirmed_final_cleanup(self):
        output=self.root/'run';binary=self.root/'executable';binary.write_bytes(b'fixed')
        class FakeChild:
            def __init__(self,binary,config,replica,directory):
                self.id=replica;self.process=SimpleNamespace(pid=100+replica)
            def finish(self):
                return {'id':self.id,'cleanup':{'status':'failed' if self.id==2 else 'completed','remaining':[]}}
        def keygen(binary,arguments,directory,name,deadline):
            keys=Path(arguments[3]);keys.mkdir()
            for i in range(4):
                key=keys/f'key-{i}.json';key.write_text('{}');key.chmod(0o600)
            (keys/'committee.json').write_text('{}');(keys/'genesis-ledger.bcs').write_bytes(b'genesis')
            return {'schema':1,'nodes':4,'profile':runner.PROFILE}
        with patch.object(runner,'unused_addresses',return_value=[f'127.0.0.1:{9000+i}' for i in range(4)]),\
             patch.object(runner,'archive_build',return_value=({'binary':{'sha256':runner.sha256(binary)}},{'executable':str(binary)})),\
             patch.object(runner,'run_command',side_effect=keygen),patch.object(runner,'Child',FakeChild),\
             patch.object(runner,'wait_ready',return_value={i:{'ready_us':1} for i in range(4)}),\
             patch.object(runner,'await_completion',return_value={'observed_us':1}),\
             patch.object(runner,'evidence_snapshot',return_value={}),patch.object(runner,'verify_archive',return_value={}),\
             patch.object(runner,'validate_results',return_value={'passed':True}),patch.object(runner,'validate_build',return_value={}):
            result=runner.execute(binary,'stamp',output,'healthy')
        self.assertTrue(result['validation']['passed'])
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['error'],'owned-process cleanup could not be confirmed')

    def test_partial_ready_or_arm_failure_cleans_every_owned_child(self):
        output=self.root/'run';closed=[]
        class FakeChild:
            def __init__(self,binary,config,replica,directory): self.id=replica
            def finish(self):
                closed.append(self.id)
                return {'id':self.id,'cleanup':{'status':'completed','remaining':[]}}
        def keygen(binary,arguments,directory,name,deadline):
            keys=Path(arguments[3]);keys.mkdir()
            for i in range(4):
                key=keys/f'key-{i}.json';key.write_text('{}');key.chmod(0o600)
            (keys/'committee.json').write_text('{}');(keys/'genesis-ledger.bcs').write_bytes(b'genesis')
            return {'schema':1,'nodes':4,'profile':runner.PROFILE}
        with patch.object(runner,'unused_addresses',return_value=[f'127.0.0.1:{9000+i}' for i in range(4)]),\
             patch.object(runner,'archive_build',return_value=({}, {'executable':'unused'})),\
             patch.object(runner,'run_command',side_effect=keygen),patch.object(runner,'Child',FakeChild),\
             patch.object(runner,'wait_ready',side_effect=RuntimeError('readiness failed')):
            result=runner.execute('binary','stamp',output,'healthy')
        self.assertEqual(result['status'],'failed')
        self.assertIn('readiness failed',result['error'])
        self.assertEqual(closed,[3,2,1,0])
        self.assertEqual(json.loads((output/'manifest.json').read_text())['status'],'failed')

    def test_cleanup_failure_cannot_leave_success_status(self):
        # Direct lifecycle failure exercises a cleanup exception after partial launch.
        output=self.root/'run';closed=[]
        class FakeChild:
            def __init__(self,binary,config,replica,directory):
                if replica==1: raise RuntimeError('spawn failed')
                self.id=replica
            def finish(self):
                closed.append(self.id);return {'id':self.id,'cleanup':{'status':'failed','remaining':[123]}}
        def keygen(binary,arguments,directory,name,deadline):
            keys=Path(arguments[3]);keys.mkdir()
            for i in range(4):
                key=keys/f'key-{i}.json';key.write_text('{}');key.chmod(0o600)
            (keys/'committee.json').write_text('{}');(keys/'genesis-ledger.bcs').write_bytes(b'genesis')
            return {'schema':1,'nodes':4,'profile':runner.PROFILE}
        with patch.object(runner,'unused_addresses',return_value=[f'127.0.0.1:{9000+i}' for i in range(4)]),\
             patch.object(runner,'archive_build',return_value=({}, {'executable':'unused'})),\
             patch.object(runner,'run_command',side_effect=keygen),patch.object(runner,'Child',FakeChild):
            result=runner.execute('binary','stamp',output,'healthy')
        self.assertEqual(closed,[0]);self.assertEqual(result['status'],'failed')
        self.assertEqual(result['cleanup'][0]['cleanup']['status'],'failed')


if __name__=='__main__': unittest.main()
