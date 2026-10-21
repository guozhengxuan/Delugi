"""Raptr artifact provenance and owned build guards; no native compilation."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("raptr_artifacts", ROOT / "scripts/baselines/raptr_artifacts.py")
ART = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ART)
LIMITS = {"target_bytes": 10000, "free_bytes": 100, "rss_bytes": 20000,
          "seconds": 60, "poll_seconds": .05, "cleanup_seconds": .05}


class ArtifactFixture(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "Cargo.lock").write_text("reviewed lock")
        (self.source / "rust-toolchain.toml").write_text('channel = "1.78.0"')
        self.patch = self.root / "cohort.patch"
        self.diff = b"diff --git a/test b/test\nreviewed cohort integration\n"
        self.patch.write_bytes(self.diff)
        self.toolchain = self.root / "toolchain"
        self.toolchain.mkdir()
        for name in ("rustc", "cargo", "rustfmt"):
            path = self.toolchain / name
            path.write_bytes(b"pinned " + name.encode())
            path.chmod(0o700)
        self.target = self.root / "target"
        self.target.mkdir()
        self.options = dict(source=self.source, patch=self.patch, target=self.target,
                            toolchain=self.toolchain, cargo_home=self.root / "cargo",
                            base_environment={"PATH": "/usr/bin:/bin"})
        self.untracked = b""
        self.commit = ART.PIN
        self.rustc = "rustc 1.78.0 (test)\nbinary: rustc\ncommit-hash: 9b00956e56009bab2aa15d7bff10916599e3d6d6\nhost: test-native\nrelease: 1.78.0\n"
        self.rustfmt = "rustfmt 1.7.0-stable (9b00956e56 2024-04-29)\n"
        self.runner = mock.patch.object(ART, "output", side_effect=self.native_output)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def native_output(self, argv, **kwargs):
        argv = [str(arg) for arg in argv]
        if "rev-parse" in argv:
            return self.commit + "\n"
        if "ls-files" in argv:
            return self.untracked
        if "diff" in argv:
            return self.diff
        if Path(argv[0]).name == "rustc":
            return self.rustc
        if Path(argv[0]).name == "cargo":
            return "cargo 1.78.0 (test)\nrelease: 1.78.0\n"
        if Path(argv[0]).name == "rustfmt":
            return self.rustfmt
        if argv[0] == "file":
            return "native test executable\n"
        if argv[0] in ("otool", "readelf"):
            return "native dynamic libraries\n"
        raise AssertionError(f"Unexpected command: {argv}")

    def identity(self):
        env = ART.environment(self.toolchain, self.target, self.root / "cargo", self.options["base_environment"])
        return ART.build_identity(self.source, self.patch, self.toolchain, env)

    def fake_compile(self, argv, source, env, target, log, resource, limits, receipt):
        self.assertNotIn("forge", " ".join(argv))
        (target / "release").mkdir(exist_ok=True)
        name = "raptr-fixture" if "raptr-fixture" in argv else "aptos-node"
        path = target / "release" / name
        path.write_bytes(("compiled role " + name).encode())
        path.chmod(0o700)
        receipt.update(argv=list(argv), status="completed", returncode=0,
                       cleanup={"status": "completed", "remaining": []})

    def build(self):
        with mock.patch.object(ART, "guarded_command", side_effect=self.fake_compile):
            return ART.build(output_dir=self.root / "evidence", limits=LIMITS, **self.options)


class ProvenanceTests(ArtifactFixture):
    def test_source_matches_exact_pin_and_patch(self):
        result = ART.validate_source(self.source, self.patch)
        self.assertEqual(result["source_commit"], ART.PIN)
        self.assertEqual(result["source_diff_sha256"], ART.sha256(self.patch))

    def test_missing_new_patch_fails_without_legacy_fallback(self):
        with self.assertRaises(FileNotFoundError):
            ART.validate_source(self.source, self.root / "missing.patch")

    def test_source_drift_and_wrong_commit_fail(self):
        self.diff += b"unreviewed"
        with self.assertRaisesRegex(ValueError, "source diff"):
            ART.validate_source(self.source, self.patch)
        self.diff = self.patch.read_bytes()
        self.commit = "0" * 40
        with self.assertRaisesRegex(ValueError, "commit"):
            ART.validate_source(self.source, self.patch)

    def test_untracked_native_module_is_rejected(self):
        self.untracked = b"observer.rs\n"
        with self.assertRaisesRegex(ValueError, "Untracked"):
            ART.validate_source(self.source, self.patch)

    def test_wrong_compiler_is_rejected(self):
        self.rustc = self.rustc.replace("1.78.0", "1.79.0")
        with self.assertRaisesRegex(ValueError, "1.78.0"):
            self.identity()

    def test_missing_or_mismatched_formatter_fails_before_build(self):
        self.rustfmt = self.rustfmt.replace("9b00956e56", "0000000000")
        with self.assertRaisesRegex(ValueError, "rustfmt must match"):
            self.identity()
        (self.toolchain / "rustfmt").unlink()
        with self.assertRaises(FileNotFoundError):
            self.identity()

    def test_environment_is_explicit_and_fixed_limits_win(self):
        env = ART.environment(self.toolchain, self.target, self.root / "cargo", {
            "PATH": "/native/bin", "CARGO_BUILD_JOBS": "64", "CARGO_INCREMENTAL": "1",
            "CARGO_PROFILE_RELEASE_DEBUG": "2", "RUSTC_WRAPPER": "/unreviewed",
            "CARGO_ENCODED_RUSTFLAGS": "unreviewed", "AWS_SECRET_ACCESS_KEY": "secret",
            "RUSTFLAGS": "-C target-cpu=generic"})
        self.assertEqual(env["CARGO_BUILD_JOBS"], "1")
        self.assertEqual(env["CARGO_INCREMENTAL"], "0")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_DEBUG"], "0")
        self.assertEqual(env["RUSTFLAGS"], "-C target-cpu=generic")
        self.assertFalse(set(env) & {"RUSTC_WRAPPER", "CARGO_ENCODED_RUSTFLAGS", "AWS_SECRET_ACCESS_KEY"})

    def test_direct_role_recipe_has_no_forge_or_hidden_build(self):
        commands = ART.recipe(self.toolchain, offline=True)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0][-4:], ["-p", "aptos-node", "--features", "consensus-only-perf-test,failpoints,smoke-test"])
        self.assertEqual(commands[1][-4:], ["-p", "aptos-genesis", "--bin", "raptr-fixture"])
        for argv in commands:
            self.assertIn("--locked", argv)
            self.assertIn("--offline", argv)
            self.assertNotIn("forge", " ".join(argv))

    def test_complete_build_and_verify_never_compile_again(self):
        stamp = self.build()
        self.assertEqual(set(stamp["binaries"]), set(ART.ROLES))
        self.assertEqual(stamp["identity"], stamp["identity_after"])
        self.assertEqual(stamp["observer_contract"], "raptr-native-receipt-v1")
        self.assertEqual(stamp["acceptance"], "build_only_not_runtime_validated")
        with mock.patch.object(ART, "guarded_command", side_effect=AssertionError("verification compiled")):
            self.assertEqual(ART.verify(**self.options), stamp)

    def test_binary_missing_or_changed_fails_verification(self):
        self.build()
        node = self.target / "release/aptos-node"
        node.write_bytes(b"unreviewed node")
        with self.assertRaisesRegex(ValueError, "binary or ABI"):
            ART.verify(**self.options)
        node.unlink()
        with self.assertRaises(FileNotFoundError):
            ART.verify(**self.options)

    def test_stamp_cannot_omit_second_role_or_cleanup(self):
        stamp = self.build()
        for change in (lambda s: s["binaries"].pop("raptr-fixture"),
                       lambda s: s["build_commands"][1]["cleanup"].update(status="failed"),
                       lambda s: s["build_commands"].pop()):
            edited = copy.deepcopy(stamp)
            change(edited)
            (self.target / ART.STAMP).write_text(json.dumps(edited))
            with self.assertRaises(ValueError):
                ART.verify(**self.options)

    def test_environment_lock_and_recipe_drift_rejected(self):
        self.build()
        changed = dict(self.options, base_environment={"PATH": "/changed"})
        with self.assertRaisesRegex(ValueError, "changed after build"):
            ART.verify(**changed)
        with self.assertRaisesRegex(ValueError, "changed after build"):
            ART.verify(offline=True, **self.options)
        (self.source / "Cargo.lock").write_text("changed lock")
        with self.assertRaisesRegex(ValueError, "changed after build"):
            ART.verify(**self.options)

    def test_new_ancestor_cargo_config_is_provenance_drift(self):
        self.build()
        config = self.root / ".cargo/config.toml"
        config.parent.mkdir()
        config.write_text('[build]\nrustflags=["-C", "opt-level=1"]\n')
        with self.assertRaisesRegex(ValueError, "changed after build"):
            ART.verify(**self.options)

    def test_source_drift_during_first_command_stops_second_and_invalidates_stamp(self):
        (self.target / ART.STAMP).write_text("old success")
        def drift(*args):
            self.fake_compile(*args)
            self.diff += b"generated source mutation"
        with mock.patch.object(ART, "guarded_command", side_effect=drift) as compile_call:
            with self.assertRaisesRegex(ValueError, "source diff"):
                ART.build(output_dir=self.root / "failed", limits=LIMITS, **self.options)
        self.assertEqual(compile_call.call_count, 1)
        self.assertFalse((self.target / ART.STAMP).exists())
        self.assertEqual(json.loads((self.root / "failed/manifest.json").read_text())["status"], "failed")

    def test_missing_role_never_produces_success_stamp(self):
        def absent(*args):
            self.fake_compile(*args)
            (self.target / "release/aptos-node").unlink(missing_ok=True)
        with mock.patch.object(ART, "guarded_command", side_effect=absent):
            with self.assertRaises(FileNotFoundError):
                ART.build(output_dir=self.root / "failed", limits=LIMITS, **self.options)
        self.assertFalse((self.target / ART.STAMP).exists())

    def test_concurrent_target_owner_is_rejected(self):
        with ART.target_lock(self.target):
            with self.assertRaisesRegex(RuntimeError, "Another build"):
                with ART.target_lock(self.target):
                    self.fail("duplicate lock acquired")

    def test_time_budget_covers_both_build_roles(self):
        with mock.patch.object(ART, "guarded_command", side_effect=self.fake_compile) as compile_call, mock.patch.object(ART.time, "monotonic", side_effect=[0, 1, 61]):
            with self.assertRaisesRegex(RuntimeError, "Whole-build"):
                ART.build(output_dir=self.root / "timed-out", limits=LIMITS, **self.options)
        self.assertEqual(compile_call.call_count, 1)
        self.assertEqual(compile_call.call_args.args[-2]["seconds"], 59)
        self.assertFalse((self.target / ART.STAMP).exists())


class GuardTests(unittest.TestCase):
    def row(self, pid=123, state="S", start="Mon Oct 21 00:00:00 2026"):
        return {"pid": pid, "parent_pid": 1, "group": 123, "rss_bytes": 1024, "state": state, "start": start}

    def process(self):
        child = mock.Mock(pid=123)
        child.poll.return_value = None
        return child

    def test_each_resource_guard_and_boundary(self):
        sample = {"target_allocated_bytes": 9999, "filesystem_free_bytes": 100,
                  "owned_group_rss_bytes": 19999, "elapsed_seconds": 59}
        self.assertIsNone(ART.stop_reason(sample, LIMITS))
        for field, value in (("target_allocated_bytes", 10000), ("filesystem_free_bytes", 99),
                             ("owned_group_rss_bytes", 20000), ("elapsed_seconds", 60)):
            self.assertIsNotNone(ART.stop_reason(dict(sample, **{field: value}), LIMITS))

    def test_nonfinite_or_unbounded_guard_rejected(self):
        for key, value in (("seconds", float("nan")), ("rss_bytes", True),
                           ("poll_seconds", 60), ("cleanup_seconds", 60)):
            with self.assertRaises(ValueError):
                ART.validate_limits(dict(LIMITS, **{key: value}))

    def test_macos_process_sample_parses_rss_and_identity(self):
        text = " 123 1 123 1000 T Mon Oct 21 12:03:05 2026\n 456 123 123 200 S Mon Oct 21 12:03:06 2026\n"
        with mock.patch.object(ART, "output", return_value=text):
            rows = ART.process_table()
        self.assertEqual(sum(row["rss_bytes"] for row in rows), 1200 * 1024)
        self.assertEqual(rows[1]["start"], "Mon Oct 21 12:03:06 2026")

    def test_guard_preflight_does_not_launch_with_low_disk(self):
        receipt = {}
        with mock.patch.object(ART, "disk_sample", return_value={"target_allocated_bytes": 0, "filesystem_free_bytes": 99}), mock.patch.object(ART.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(RuntimeError, "free-space"):
                ART.guarded_command(["cargo"], ".", {}, ".", "unused", "unused", LIMITS, receipt)
        launch.assert_not_called()
        self.assertEqual(receipt["cleanup"]["status"], "not_started")

    def test_owned_cleanup_continues_paused_group_before_term(self):
        group = ART.OwnedGroup(self.process())
        group.isolated = True
        with mock.patch.object(group, "members", side_effect=[[self.row(state="T")], [], [], [], []]), mock.patch.object(group, "send") as send:
            record = group.cleanup(.05)
        self.assertEqual(record["status"], "completed")
        self.assertEqual([x.args[0] for x in send.call_args_list], [signal.SIGCONT, signal.SIGTERM])

    def test_owned_cleanup_escalates_and_rejects_survivor(self):
        group = ART.OwnedGroup(self.process())
        group.isolated = True
        with mock.patch.object(group, "members", return_value=[self.row()]), mock.patch.object(group, "send") as send, mock.patch.object(ART.time, "monotonic", side_effect=range(20)):
            record = group.cleanup(.05)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(send.call_args_list[-1].args[0], signal.SIGKILL)
        self.assertTrue(record["remaining"])

    def test_reused_pid_or_empty_group_is_not_signalled(self):
        group = ART.OwnedGroup(self.process())
        group.isolated = True
        with mock.patch.object(ART, "process_table", side_effect=[[self.row()], [self.row(start="replacement")]]), mock.patch.object(ART.os, "killpg") as kill:
            group.members()
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                group.send(signal.SIGTERM)
        kill.assert_not_called()
        group = ART.OwnedGroup(self.process())
        group.isolated = True
        with mock.patch.object(ART, "process_table", side_effect=[[], [self.row()]]), mock.patch.object(ART.os, "killpg") as kill:
            group.members()
            with self.assertRaisesRegex(RuntimeError, "reused"):
                group.send(signal.SIGTERM)
        kill.assert_not_called()

    def test_rss_failure_still_cleans_and_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {}
            child = self.process()
            owned = mock.Mock()
            owned.members.return_value = [dict(self.row(), rss_bytes=20000)]
            owned.cleanup.return_value = {"status": "completed", "remaining": []}
            with mock.patch.object(ART, "disk_sample", return_value={"target_allocated_bytes": 0, "filesystem_free_bytes": 1000}), mock.patch.object(ART, "process_table", return_value=[]), mock.patch.object(ART.subprocess, "Popen", return_value=child), mock.patch.object(ART, "OwnedGroup", return_value=owned):
                with self.assertRaisesRegex(RuntimeError, "RSS|rss"):
                    ART.guarded_command(["cargo"], root, {}, root, root / "log", root / "resources", LIMITS, receipt)
            self.assertEqual(receipt["status"], "failed")
            owned.cleanup.assert_called_once()

    def test_successful_compiler_with_cleanup_failure_still_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = {}
            child = self.process()
            child.poll.return_value = 0
            owned = mock.Mock()
            owned.members.return_value = []
            owned.cleanup.return_value = {"status": "failed", "remaining": [self.row()]}
            with mock.patch.object(ART, "disk_sample", return_value={"target_allocated_bytes": 0, "filesystem_free_bytes": 1000}), mock.patch.object(ART, "process_table", return_value=[]), mock.patch.object(ART.subprocess, "Popen", return_value=child), mock.patch.object(ART, "OwnedGroup", return_value=owned):
                with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                    ART.guarded_command(["cargo"], root, {}, root, root / "log", root / "resources", LIMITS, receipt)
            self.assertEqual(receipt["status"], "failed")

    def test_sampler_failure_does_not_leave_running_group_unterminated(self):
        child = self.process()
        child.returncode = None
        group = ART.OwnedGroup(child)
        group.isolated = True
        with mock.patch.object(group, "members", side_effect=OSError("ps unavailable")), mock.patch.object(ART.os, "getpgid", return_value=123), mock.patch.object(ART.os, "killpg") as kill, mock.patch.object(ART.time, "sleep"):
            record = group.cleanup(.05)
        self.assertEqual(record["status"], "failed")
        self.assertEqual([call.args for call in kill.call_args_list],
                         [(123, signal.SIGCONT), (123, signal.SIGTERM), (123, signal.SIGKILL)])
        child.wait.assert_called_once()

    def test_process_observation_failure_prevents_build_launch(self):
        with mock.patch.object(ART, "disk_sample", return_value={"target_allocated_bytes": 0, "filesystem_free_bytes": 1000}), mock.patch.object(ART, "process_table", side_effect=PermissionError("ps denied")), mock.patch.object(ART.subprocess, "Popen") as launch:
            with self.assertRaises(PermissionError):
                ART.guarded_command(["cargo"], ".", {}, ".", "unused", "unused", LIMITS, {})
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
