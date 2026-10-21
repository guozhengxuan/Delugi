"""Shared-executable Delugi gates; no Cargo, sockets or native processes."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_network as network
import run_sustained as sustained
import run_raptr_shared_local as contract


class SharedArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / "common-node"
        self.binary.write_bytes(b"explicitly mocked built executable")
        self.binary.chmod(0o700)
        names = ("core/delugi/Cargo.toml", "core/delugi/src/lib.rs", "profile.json")
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        self.stamp = {"protocols": ["raptr", "delugi"], "compiled_features": {"delugi-core": ["rocksdb-records"]},
                      "sources": {name: contract.sha256(self.root / name) for name in names[:2]},
                      "profiles": {names[2]: contract.sha256(self.root / names[2])},
                      "native_dependencies": {"archive_path": "retained-native.tar"}}
        self.receipt = self.root / "receipt.json"
        self.save()

    def save(self):
        self.receipt.write_text(json.dumps(self.stamp))

    def verify(self, profile=network.STORAGE_PROFILES[0]):
        return network.verify_shared_delugi_build(self.binary, self.receipt, profile, self.root)

    def test_reuses_native_contract_and_never_accepts_raptr_only_receipt(self):
        with patch.object(contract, "validate_build", side_effect=lambda *a, **k: {"protocols": self.stamp["protocols"], "compiled_features": self.stamp["compiled_features"]}) as validate:
            self.verify()
            validate.assert_called_once_with(self.binary, self.stamp, source_root=self.root)
            self.stamp["protocols"] = ["raptr"]
            self.save()
            with self.assertRaisesRegex(ValueError, "compiled Delugi"):
                self.verify()
        with patch.object(contract, "validate_build", side_effect=ValueError("binary changed")):
            with self.assertRaisesRegex(ValueError, "binary changed"):
                self.verify()

    def test_disk_requires_feature_and_metadata_types_are_not_string_aliases(self):
        with patch.object(contract, "validate_build", side_effect=lambda *a, **k: {"protocols": self.stamp["protocols"], "compiled_features": self.stamp["compiled_features"]}):
            self.verify(network.STORAGE_PROFILES[1])
            self.stamp["compiled_features"]["delugi-core"] = []
            self.save()
            self.verify()
            with self.assertRaisesRegex(ValueError, "rocksdb-records"):
                self.verify(network.STORAGE_PROFILES[1])
            self.stamp["compiled_features"]["delugi-core"] = "rocksdb-records"
            self.save()
            with self.assertRaisesRegex(ValueError, "feature identity"):
                self.verify()
            self.stamp["protocols"] = "delugi"
            self.save()
            with self.assertRaisesRegex(ValueError, "compiled Delugi"):
                self.verify()

    def test_unvalidated_capability_assertions_cannot_promote_old_binary(self):
        # The old validator can validate its Raptr artifact, but does not prove
        # that caller-appended Delugi capability fields came from its recipe.
        with patch.object(contract, "validate_build", return_value={}):
            with self.assertRaisesRegex(ValueError, "compiled Delugi"):
                self.verify()

    def test_new_missing_and_changed_delugi_sources_fail_before_launch(self):
        source = self.root / "core/delugi/src/lib.rs"
        with patch.object(contract, "validate_build", side_effect=lambda *a, **k: {"protocols": self.stamp["protocols"], "compiled_features": self.stamp["compiled_features"]}):
            source.write_text("changed")
            with self.assertRaisesRegex(ValueError, "differs from Delugi"):
                self.verify()
            source.write_text("core/delugi/src/lib.rs")
            new = source.with_name("new.rs")
            new.write_text("unbound")
            with self.assertRaisesRegex(ValueError, "omits or differs"):
                self.verify()
            new.unlink()
            del self.stamp["sources"]["core/delugi/Cargo.toml"]
            self.save()
            with self.assertRaisesRegex(ValueError, "source closure"):
                self.verify()

    def test_shared_archive_preserves_receipt_and_does_not_forge_root_stamp(self):
        before = self.receipt.read_bytes()
        legacy = Path(str(self.binary) + ".build.json")
        legacy.write_text("immutable legacy stamp")
        with patch.object(contract, "validate_build", side_effect=lambda *a, **k: {"protocols": self.stamp["protocols"], "compiled_features": self.stamp["compiled_features"]}):
            out = network.archive_shared_delugi_build(self.binary, self.receipt, self.root / "archive",
                                                       network.STORAGE_PROFILES[1], self.root)
        self.assertEqual((self.root / "archive/build-receipt.json").read_bytes(), before)
        self.assertEqual(out["receipt_sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(legacy.read_text(), "immutable legacy stamp")
        self.assertFalse((self.root / "archive/raptr-shared-node").exists())
        self.assertEqual(out["retained_binary"], str(self.binary))
        self.assertTrue((self.root / "archive/source/core/delugi/src/lib.rs").is_file())

    def test_storage_parent_is_exclusive_and_default_configuration_unchanged(self):
        self.assertEqual(network.storage_options(self.root, network.STORAGE_PROFILES[0]), {})
        self.assertFalse((self.root / "record-storage").exists())
        options = network.storage_options(self.root, network.STORAGE_PROFILES[1])
        self.assertEqual(Path(options["storage_directory"]), self.root / "record-storage")
        with self.assertRaises(FileExistsError):
            network.storage_options(self.root, network.STORAGE_PROFILES[1])

    def disk(self, count=2):
        return {0: {"retained_state": {"batch_records": count}, "storage": {
            "profile": network.STORAGE_PROFILES[1], "core_restart_recovery": False,
            "core_required_completion": "Visible", "actual_write_completion": "Written (WAL enabled, sync=false)",
            "native_backend_profile": "blob-lz4-pipelined-v1", "fresh_database_only": True,
            "writes": {"attempts": count, "completed_writes": count, "failures": 0,
                       "key_bytes": count * 36, "record_bytes": count * 200,
                       "encoded_write_batch_bytes": count * 250, "last_error": None}}}}

    def test_disk_counts_reconcile_even_zero_output_and_partial_write_failures_reject(self):
        for count in (0, 2):
            network.validate_storage_snapshots(self.disk(count), network.STORAGE_PROFILES[1])
        for field, value in (("completed_writes", 1), ("attempts", 3), ("record_bytes", 0), ("failures", 1)):
            rows = self.disk()
            rows[0]["storage"]["writes"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                network.validate_storage_snapshots(rows, network.STORAGE_PROFILES[1])
        for field, value in (("completed_writes", False), ("record_bytes", 1)):
            rows = self.disk(0)
            rows[0]["storage"]["writes"][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                network.validate_storage_snapshots(rows, network.STORAGE_PROFILES[1])
        with self.assertRaises(AssertionError):
            network.validate_storage_snapshots({0: {}}, network.STORAGE_PROFILES[1])
        self.assertFalse(network.validate_storage_snapshots({0: {}}, network.STORAGE_PROFILES[0])[0]["counters_available"])

    def test_network_shared_path_never_invokes_cargo_and_rechecks_after_trial(self):
        for name in ("Cargo.toml", "Cargo.lock", "README.md", "IMPLEMENTATION_PLAN.md", "scripts/run_network.py",
                     "scripts/spec_provenance.py", "scripts/shared_core_conformance.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
        validation = {"binary": {"sha256": "a" * 64}, "receipt_sha256": "b" * 64}
        def trial(*args, **kwargs):
            return {"scenario": args[2], "pass": True, "status": "passed",
                    "latency": {"all_correct_completion_from_first_submission_us": 1,
                                "finite_workload_transactions_per_second": 1}}
        argv = ["run_network.py", "--repeats", "1", "--scenario", "honest", "--binary", str(self.binary),
                "--shared-build-receipt", str(self.receipt), "--spec-snapshot", "fixture.json"]
        with patch.object(sys, "argv", argv), patch.object(network, "ROOT", self.root), \
             patch.object(network, "source_inventory", return_value={}), \
             patch.object(network, "machine_metadata", return_value={}), \
             patch.object(network, "archive_spec", return_value={"paper_head": "fixture"}), \
             patch.object(network, "verify_spec_unchanged"), \
             patch.object(network, "archive_shared_delugi_build", return_value=validation), \
             patch.object(network, "verify_shared_delugi_build", return_value=({}, validation)) as recheck, \
             patch.object(network, "run_trial", side_effect=trial), \
             patch.object(network.subprocess, "run", side_effect=AssertionError("unexpected process launch")):
            self.assertEqual(network.main(), 0)
            recheck.assert_called_once()

    def test_sustained_shared_path_preserves_stamp_and_post_run_drift_fails(self):
        validation = {"binary": {"sha256": "a" * 64}, "receipt_sha256": "b" * 64}
        legacy = Path(str(self.binary) + ".build.json")
        legacy.write_text("legacy unchanged")
        argv = ["run_sustained.py", "--skip-build", "--binary", str(self.binary),
                "--shared-build-receipt", str(self.receipt), "--spec-snapshot", "fixture.json",
                "--output", str(self.root / "run"), "--storage-profile", network.STORAGE_PROFILES[1]]
        with patch.object(sys, "argv", argv), patch.object(sustained, "machine_metadata", return_value={}), \
             patch.object(sustained, "archive_spec", return_value={}), \
             patch.object(sustained, "verify_spec_unchanged"), \
             patch.object(sustained, "archive_shared_delugi_build", return_value=validation), \
             patch.object(sustained, "verify_shared_delugi_build", side_effect=ValueError("source/profile drift")), \
             patch.object(sustained, "verify_build_stamp", side_effect=AssertionError("root stamp path used")), \
             patch.object(sustained, "run_trial", return_value={"status": "passed"}) as trial, \
             patch.object(sustained.subprocess, "run", return_value=SimpleNamespace(stdout="fixture", returncode=0)) as run:
            self.assertEqual(sustained.main(), 1)
            self.assertEqual(trial.call_args.kwargs["storage_profile"], network.STORAGE_PROFILES[1])
            self.assertEqual([call.args[0][0] for call in run.call_args_list], ["git", "git"])
        manifest = json.loads((self.root / "run/manifest.json").read_text())
        self.assertEqual(manifest["status"], "failed")
        self.assertIn("post-run verification", manifest["error"])
        self.assertNotIn("build_stamp", manifest)
        self.assertEqual(legacy.read_text(), "legacy unchanged")

    def test_unsafe_cli_combinations_fail_before_build_or_launch(self):
        for extra in (["--shared-build-receipt", str(self.receipt)],
                      ["--storage-profile", network.STORAGE_PROFILES[1]],
                      ["--shared-build-receipt", str(self.receipt), "--skip-build", "--inventory", "hosts.json"]):
            with self.subTest(extra=extra), patch.object(sys, "argv", ["run_sustained.py", "--spec-snapshot", "fixture", *extra]), \
                 patch.object(sustained.subprocess, "run") as run, self.assertRaises(SystemExit):
                sustained.main()
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
