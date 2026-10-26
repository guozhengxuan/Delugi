#!/usr/bin/env python3
"""Pinned source/build contract tests; they never execute Cargo."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import build_raptr_shared as builder


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name).resolve()

    def tar(self,path,members):
        with tarfile.open(path,'w') as out:
            for name,data,mode in members:
                entry=tarfile.TarInfo(name);entry.mode=mode
                if isinstance(data,tuple):entry.type=tarfile.SYMTYPE;entry.linkname=data[0];out.addfile(entry)
                else:entry.size=len(data);out.addfile(entry,io.BytesIO(data))
        return builder.contract.sha256(path)

    def source_archive(self):
        tree=self.root/'native';tree.mkdir();(tree/'lib.rs').write_bytes(b'original');(tree/'alias').symlink_to('lib.rs')
        archive=self.root/'source.tar';digest=self.tar(archive,[('lib.rs',b'original',0o644),('alias',('lib.rs',),0o777)])
        return archive,tree,digest

    def test_native_archive_matches_bytes_links_and_full_tree(self):
        archive,tree,digest=self.source_archive();record=builder.archive_manifest(archive,tree,digest)
        self.assertEqual(record['files']['alias'],{'kind':'symlink','target':'lib.rs','archive_target':'lib.rs','extraction_filter':'tarfile.data_filter'})
        self.assertEqual(record['files']['lib.rs']['sha256'],hashlib.sha256(b'original').hexdigest())
        (tree/'unreviewed.rs').write_text('unreviewed')
        with self.assertRaisesRegex(ValueError,'unarchived'):builder.archive_manifest(archive,tree,digest)

    def test_changed_extracted_dependency_cannot_pass_archive_check(self):
        archive,tree,digest=self.source_archive();(tree/'lib.rs').write_text('changed')
        with self.assertRaisesRegex(ValueError,'original git object'):builder.archive_manifest(archive,tree,digest)

    def test_archive_hash_and_missing_original_file_fail_closed(self):
        archive,tree,digest=self.source_archive()
        with self.assertRaisesRegex(ValueError,'exact git-archive'):builder.archive_manifest(archive,tree,'0'*64)
        (tree/'lib.rs').unlink()
        with self.assertRaisesRegex(ValueError,'missing'):builder.archive_manifest(archive,tree,digest)

    def test_original_data_filter_link_normalization_is_explicitly_bound(self):
        tree=self.root/'native';tree.mkdir();(tree/'sources').mkdir();(tree/'alias').symlink_to('sources')
        archive=self.root/'source.tar';digest=self.tar(archive,[('alias',('sources/',),0o777)])
        result=builder.archive_manifest(archive,tree,digest)
        self.assertEqual(result['files']['alias']['target'],'sources')
        self.assertEqual(result['files']['alias']['archive_target'],'sources/')

    def test_archive_rejects_traversal_and_links_used_as_parent(self):
        tree=self.root/'native';tree.mkdir();archive=self.root/'bad.tar'
        digest=self.tar(archive,[('../escape',b'x',0o644)])
        with self.assertRaisesRegex(ValueError,'path'):builder.archive_manifest(archive,tree,digest)
        elsewhere=self.root/'elsewhere';elsewhere.mkdir();(elsewhere/'x.rs').write_text('x');(tree/'inside').symlink_to(elsewhere)
        digest=self.tar(archive,[('inside/x.rs',b'x',0o644)])
        with self.assertRaisesRegex(ValueError,'symlink directory'):builder.archive_manifest(archive,tree,digest)

    def test_locked_git_objects_ignore_assume_unchanged_index_shortcuts(self):
        tree=self.root/'git';tree.mkdir();(tree/'lib.rs').write_bytes(b'original')
        blob=hashlib.sha1(b'blob 8\0original').hexdigest()
        listing=f'100644 blob {blob}\tlib.rs\0'.encode()
        with patch.object(builder.GUARD,'output',return_value=listing):
            self.assertEqual(builder.checked_git_tree(tree,'a'*40)['files'],1)
            (tree/'lib.rs').write_bytes(b'changed!')
            with self.assertRaisesRegex(ValueError,'locked object'):builder.checked_git_tree(tree,'a'*40)

    def test_git_tree_rejects_ignored_untracked_build_input(self):
        tree=self.root/'git';tree.mkdir();(tree/'lib.rs').write_bytes(b'original');(tree/'ignored.rs').write_bytes(b'hidden')
        blob=hashlib.sha1(b'blob 8\0original').hexdigest()
        with patch.object(builder.GUARD,'output',return_value=f'100644 blob {blob}\tlib.rs\0'.encode()):
            with self.assertRaisesRegex(ValueError,'unbound'):builder.checked_git_tree(tree,'a'*40)

    def test_registry_source_must_equal_package_with_locked_checksum(self):
        cache=self.root/'cargo';archive=cache/'registry/cache/index/demo-1.0.0.crate';archive.parent.mkdir(parents=True)
        digest=self.tar(archive,[('demo-1.0.0/src/lib.rs',b'pub fn original(){}',0o644)])
        source=cache/'registry/src/index/demo-1.0.0/src/lib.rs';source.parent.mkdir(parents=True);source.write_bytes(b'pub fn original(){}')
        lock=self.root/'Cargo.lock';lock.write_text(f'''version=3
[[package]]
name="demo"
version="1.0.0"
source="registry+https://github.com/rust-lang/crates.io-index"
checksum="{digest}"
''')
        self.assertEqual(builder.cache_identity(lock,cache)['registry'][0]['files'],1)
        source.write_bytes(b'pub fn changed(){}')
        with self.assertRaisesRegex(ValueError,'original package'):builder.cache_identity(lock,cache)

    def test_recipe_has_only_pinned_offline_native_node_role(self):
        command=builder.recipe('build',self.root/'toolchain',root=self.root)
        self.assertIn('--locked',command);self.assertIn('--offline',command)
        self.assertEqual(command[-2:],['--bin','raptr-shared-node'])
        self.assertNotIn('forge',' '.join(command));self.assertNotIn('--release',command)
        self.assertEqual(builder.recipe('check',self.root,root=self.root)[-1],'--all-targets')
        self.assertEqual(builder.recipe('test',self.root,root=self.root)[-1],'--all-targets')
        self.assertIn('--release',builder.recipe('build',self.root,'release',self.root))
        with self.assertRaises(ValueError):builder.recipe('run',self.root)

    def test_environment_does_not_inherit_unrecorded_native_flags_or_wrappers(self):
        with patch.object(builder.platform,'system',return_value='Darwin'):
            env=builder.environment(self.root,self.root/'target',self.root/'cargo',{'HOME':'home','RUSTFLAGS':'evil','RUSTC_WRAPPER':'evil','CFLAGS':'changed','PATH':'untrusted'})
        self.assertNotIn('RUSTFLAGS',env);self.assertNotIn('RUSTC_WRAPPER',env)
        self.assertEqual(env['CFLAGS'],'-Dfdopen=fdopen');self.assertEqual(env['CARGO_INCREMENTAL'],'0')
        self.assertEqual(env['CARGO_BUILD_JOBS'],'1');self.assertNotIn('untrusted',env['PATH'])

    def test_parallel_jobs_are_bounded_and_bound_to_command_and_environment(self):
        command=builder.recipe('build',self.root/'toolchain',jobs=2)
        self.assertEqual(command[command.index('--jobs')+1],'2')
        self.assertEqual(builder.environment(self.root,self.root/'target',self.root/'cargo',jobs=2)['CARGO_BUILD_JOBS'],'2')
        for value in (0,5,True,'2',2.5):
            with self.subTest(jobs=value):
                with self.assertRaises(ValueError):builder.recipe('build',self.root,jobs=value)
                with self.assertRaises(ValueError):builder.environment(self.root,self.root/'target',self.root/'cargo',jobs=value)

    def test_source_inventory_binds_new_shared_inputs_but_skips_build_targets(self):
        for name in builder.SOURCE_ROOTS:(self.root/name).mkdir(parents=True,exist_ok=True)
        for name in builder.SOURCE_EXTRAS:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixed')
        (self.root/'shared/new').mkdir();(self.root/'shared/new/lib.rs').write_text('new')
        (self.root/'shared/target').mkdir();(self.root/'shared/target/generated.rs').write_text('build')
        result=builder.source_snapshot(self.root)
        self.assertIn('shared/new/lib.rs',result);self.assertNotIn('shared/target/generated.rs',result)
        (self.root/'core/delugi/new.rs').write_text('Delugi service consumer')
        self.assertIn('core/delugi/new.rs',builder.source_snapshot(self.root))
        self.assertIn('Cargo.toml',result);self.assertIn('Cargo.lock',result)

    def test_failed_metadata_cleanup_cannot_issue_capability_proof(self):
        output=self.root/'metadata';output.mkdir()
        process=SimpleNamespace(returncode=0,poll=lambda:0)
        owned=SimpleNamespace(verify_start=lambda:None,cleanup=lambda _: {'status':'failed','remaining':[123]})
        with patch.object(builder,'ROOT',self.root), \
             patch.object(builder.subprocess,'Popen',return_value=process), \
             patch.object(builder.GUARD,'OwnedGroup',return_value=owned), \
             patch.object(builder.contract,'resolved_capabilities') as derive:
            with self.assertRaisesRegex(ValueError,'cleanup is unconfirmed'):
                builder.capability_metadata(output,self.root/'toolchain',{})
            derive.assert_not_called()

    def mock_build(self,action='build',command_status='completed',cleanup='completed',source_drift=False,jobs=1):
        output=self.root/'evidence';target=self.root/'target'
        def command(argv,cwd,env,target,log,resources,limits,receipt):
            log.write_text('compiler fixture\n');resources.write_text('{}\n')
            receipt.update(argv=argv,status=command_status,returncode=0,cleanup={'status':cleanup,'remaining':[]})
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(builder,'ROOT',self.root))
            stack.enter_context(patch.object(builder,'source_snapshot',side_effect=[{'a':'before'},{'a':'after' if source_drift else 'before'}]))
            stack.enter_context(patch.object(builder,'profile_snapshot',return_value={'p':'fixed'}))
            stack.enter_context(patch.object(builder,'prepare_native_archive',return_value={'checked':True}))
            stack.enter_context(patch.object(builder,'toolchain_identity',return_value={'rustc_version':'1.78.0'}))
            stack.enter_context(patch.object(builder,'capability_metadata',return_value={'protocols':['delugi','raptr'],'compiled_features':{'delugi-core':['rocksdb-records']}}))
            stack.enter_context(patch.object(builder.contract,'validate_capabilities',return_value={}))
            stack.enter_context(patch.object(builder,'cache_identity',return_value={'fixed':True}))
            stack.enter_context(patch.object(builder.GUARD,'cargo_configs',return_value={}))
            stack.enter_context(patch.object(builder.GUARD,'guarded_command',side_effect=command))
            stack.enter_context(patch.object(builder.contract,'validate_native_dependencies',return_value={}))
            binary=stack.enter_context(patch.object(builder,'binary_identity',return_value={'role':'raptr-shared-node'}))
            result=builder.build(action,output,toolchain=self.root/'toolchain',target=target,cargo_home=self.root/'cargo',jobs=jobs)
            return result,binary.call_count

    def test_selected_parallelism_survives_into_the_build_receipt(self):
        result,_=self.mock_build(jobs=2)
        self.assertEqual(result['status'],'completed')
        self.assertEqual(result['build_jobs'],2)
        self.assertEqual(result['environment']['CARGO_BUILD_JOBS'],'2')
        argv=result['command']['argv']
        self.assertEqual(argv[argv.index('--jobs')+1],'2')

    def test_check_cannot_issue_stale_executable_receipt(self):
        result,calls=self.mock_build('check')
        self.assertEqual(result['status'],'checked_not_built');self.assertNotIn('binary',result);self.assertEqual(calls,0)
        self.assertNotEqual(result['format'],builder.contract.BUILD_FORMAT)

    def test_test_run_cannot_issue_an_executable_receipt(self):
        result,calls=self.mock_build('test')
        self.assertEqual(result['status'],'tested_not_built');self.assertNotIn('binary',result);self.assertEqual(calls,0)
        self.assertEqual(result['format'],'raptr-shared-test-v1')

    def test_build_requires_compiler_success_and_confirmed_owned_cleanup(self):
        result,calls=self.mock_build(cleanup='failed')
        self.assertEqual(result['status'],'failed');self.assertNotIn('binary',result);self.assertEqual(calls,0)
        self.assertIn('confirmed owned cleanup',result['error'])

    def test_source_drift_prevents_binary_stamp_even_after_compiler_success(self):
        result,calls=self.mock_build(source_drift=True)
        self.assertEqual(result['status'],'failed');self.assertFalse(result['source_before_after_equal']);self.assertEqual(calls,0)

    def test_successful_guarded_build_has_separate_local_not_performance_scope(self):
        result,calls=self.mock_build()
        self.assertEqual(result['status'],'completed');self.assertEqual(calls,1)
        self.assertFalse(result['comparison_eligible']);self.assertTrue(result['shared_target_retained'])
        self.assertEqual(result['protocols'],['delugi','raptr'])
        self.assertEqual(result['compiled_features']['delugi-core'],['rocksdb-records'])


if __name__=='__main__':unittest.main()
