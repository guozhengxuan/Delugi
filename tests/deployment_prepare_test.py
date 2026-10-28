import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deployment_prepare as prepare


class DeploymentPreparation(unittest.TestCase):
    def test_autobahn_pins_compatible_binding_compiler_only_in_its_recipe(self):
        recipe = prepare.recipe('autobahn')
        self.assertEqual(recipe['environment'], {'LIBCLANG_PATH': '/usr/lib/llvm-14/lib'})
        self.assertIn('libclang-14-dev', recipe['packages'])
        self.assertNotIn('environment', prepare.recipe('simpleit-mempool'))
        self.assertNotIn('libclang-14-dev', prepare.recipe('mysticeti')['packages'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.owned = []

    def tearDown(self):
        for path in self.owned:
            shutil.rmtree(path, ignore_errors=True)
        self.temp.cleanup()

    def source(self):
        path = self.root / "checkout"
        path.mkdir()
        (path / "Cargo.toml").write_text('[package]\nname="fixture"\nversion="0.1.0"\n')
        (path / "Cargo.lock").write_text("# exact fixture lock\n")
        (path / "src").mkdir()
        (path / "src/main.rs").write_text('fn main() {}\n')
        (path / "private-key.json").write_text("must never be bundled")
        (path / "results").mkdir()
        (path / "results/raw.log").write_text("must never be bundled")
        return path

    def hosts(self):
        key, known = self.root / "identity", self.root / "known_hosts"
        key.write_text("fixture: never opened by preparation")
        known.write_text("fixture: never used to connect")
        return {"schema": 1, "hosts": [{"replica": 0, "ssh": "root@192.0.2.1",
            "identity_file": str(key), "known_hosts_file": str(known), "advertised": "10.0.0.1:9000",
            "control_port": 9001, "budget": {"cpus": [0, 1, 2, 3], "memory_bytes": 16 * 1024**3,
            "enforcement": "dedicated_host"}}]}

    def owned_root(self, archive):
        nonce = uuid.uuid4().hex
        root = Path("/tmp") / ("delugi-build-" + nonce)
        root.mkdir(mode=0o700)
        self.owned.append(root)
        shutil.copyfile(archive, root / "bundle.tar")
        return root, {"nonce": nonce, "archive_sha256": prepare.sha(archive)}

    def test_exact_bundle_is_deterministic_and_excludes_credentials_results_and_builds(self):
        root = self.source()
        a = prepare.bundle(root, "delugi", self.root / "a")
        b = prepare.bundle(root, "delugi", self.root / "b")
        self.assertEqual(a["bundle_sha256"], b["bundle_sha256"])
        unpacked = self.root / "unpacked"
        unpacked.mkdir()
        manifest = prepare.unpack_verified(self.root / "a/bundle.tar", unpacked, a["bundle_sha256"])
        self.assertEqual({p for p in manifest["files"] if p.startswith("source/")},
                         {"source/Cargo.toml", "source/Cargo.lock", "source/src/main.rs"})
        self.assertEqual(manifest["controller_sources"]["scripts/deployment_prepare.py"], prepare.sha(prepare.__file__))
        self.assertEqual(manifest["controller_sources"]["scripts/observer_receipts.py"],
                         prepare.sha(prepare.ROOT / "scripts/observer_receipts.py"))
        self.assertEqual(manifest["controller_sources"]["scripts/shared_core_conformance.py"],
                         prepare.sha(unpacked / "controller/scripts/shared_core_conformance.py"))
        self.assertNotIn("private-key.json", str(manifest))
        self.assertEqual((unpacked / "source/src/main.rs").read_text(), 'fn main() {}\n')

    def test_recipe_names_exact_toolchains_locked_commands_and_native_limit(self):
        for protocol in prepare.PROTOCOLS:
            recipe = prepare.recipe(protocol)
            self.assertTrue(all("--locked" in argv for argv in recipe["commands"]))
            self.assertEqual(recipe["native_remote_runner_supported"], protocol == "delugi")
        shoal = prepare.recipe("shoal")
        self.assertEqual(shoal["toolchain_components"], ["rustfmt"])
        self.assertEqual(len(shoal["commands"]), 2)
        self.assertIn("consensus-only-perf-test", shoal["commands"][0])
        self.assertIn("shoal-fixture", shoal["commands"][1])
        for kwargs in ({"jobs": 0}, {"jobs": 9}, {"toolchain": "stable"}, {"toolchain": "1.99.0"}):
            with self.assertRaises(ValueError):
                prepare.recipe("shoal", **kwargs)

    def test_shoal_installs_and_records_the_pinned_native_generator_formatter(self):
        commands=[]
        with patch.object(prepare, "run_logged") as logged:
            prepare.install_recipe_components(prepare.recipe("shoal"), "/owned/rustup", self.root, {}, commands)
        self.assertEqual([call.args[0] for call in logged.call_args_list], [
            ["/owned/rustup", "component", "add", "--toolchain", "1.75.0", "rustfmt"],
            ["rustfmt", "+1.75.0", "--version"]])
        self.assertEqual(logged.call_args_list[1].args[3], self.root / "logs/component-rustfmt-version.log")
        with patch.object(prepare, "run_logged") as logged:
            prepare.install_recipe_components(prepare.recipe("mysticeti"), "/owned/rustup", self.root, {}, commands)
        logged.assert_not_called()

    def test_archive_rejects_traversal_duplicate_paths_and_content_tampering(self):
        root = self.source()
        prepare.bundle(root, "delugi", self.root / "bundle")
        original = self.root / "bundle/bundle.tar"
        for attack in ("traversal", "duplicate", "content"):
            altered = self.root / (attack + ".tar")
            with tarfile.open(original) as source, tarfile.open(altered, "w") as output:
                for item in source:
                    data = source.extractfile(item).read()
                    if attack == "content" and item.name.endswith("main.rs"):
                        data = b"x" * len(data)
                    output.addfile(item, io.BytesIO(data))
                if attack != "content":
                    entry = tarfile.TarInfo("../escaped" if attack == "traversal" else "source/src/main.rs")
                    entry.size = 1
                    output.addfile(entry, io.BytesIO(b"x"))
            destination = self.root / (attack + "-out")
            destination.mkdir()
            with self.assertRaises((ValueError, FileExistsError)):
                prepare.unpack_verified(altered, destination, prepare.sha(altered))
            self.assertEqual(list(destination.iterdir()), [])
        self.assertFalse((self.root / "escaped").exists())

    def test_symlink_escape_is_rejected_before_packaging(self):
        root = self.source()
        external = self.root / "external-secret"
        external.write_text("never bundle")
        (root / "src/leak.rs").symlink_to(external)
        with self.assertRaisesRegex(ValueError, "inside selected checkout"):
            prepare.bundle(root, "delugi", self.root / "bundle")

    def test_saved_loom_inventory_import_does_not_open_access_credentials(self):
        hosts = self.hosts()
        settings = {"key": {"path": hosts["hosts"][0]["identity_file"], "name": "Loom", "accesskey": "/does/not/exist/private.json"},
                    "ports": {"consensus": 9000}, "instances": {"regions": ["ap-southeast-1"], "type": "fixture"}}
        saved = {"regions": [{"region": "ap-southeast-1", "instances": [{"id": "i-one", "status": "Running",
            "public_ips": ["192.0.2.1"], "private_ips": ["10.0.0.1"], "cpu": 4, "memory_mib": 16384}]}]}
        prepare.json_file(self.root / "settings.json", settings)
        prepare.json_file(self.root / "saved.json", saved)
        result = prepare.hosts_from_loom(self.root / "settings.json", self.root / "saved.json", ["i-one"], hosts["hosts"][0]["known_hosts_file"])
        self.assertEqual(result["hosts"][0]["advertised"], "10.0.0.1:9000")
        self.assertNotIn("accesskey", json.dumps(result))
        self.assertNotIn("network_interface", result["hosts"][0])
        with self.assertRaisesRegex(ValueError, "whole-machine"):
            prepare.hosts_from_loom(self.root / "settings.json", self.root / "saved.json", ["i-one"], hosts["hosts"][0]["known_hosts_file"], memory_bytes=2**30)

    def test_plan_and_cli_dry_run_never_start_ssh_or_package_install(self):
        root = self.source()
        prepare.bundle(root, "delugi", self.root / "bundle")
        with patch.object(prepare.subprocess, "run", side_effect=AssertionError("no network commands")):
            plan = prepare.create_plan(self.hosts(), self.root / "bundle")
            prepare.json_file(self.root / "plan.json", plan)
            with patch.object(sys, "argv", ["deployment_prepare.py", "build", "--plan", str(self.root / "plan.json")]), patch("builtins.print") as output:
                prepare.main()
                self.assertIn("dry-run", output.call_args.args[0])

    def test_source_metadata_is_bound_to_archived_manifest_even_when_external_hash_is_replaced(self):
        root = self.source()
        prepare.bundle(root, "delugi", self.root / "bundle")
        manifest_path, info_path = self.root / "bundle/manifest.json", self.root / "bundle/bundle.json"
        manifest, info = json.loads(manifest_path.read_text()), json.loads(info_path.read_text())
        for attack in ("recipe", "protocol", "manifest_hash"):
            changed_manifest, changed_info = copy.deepcopy(manifest), copy.deepcopy(info)
            if attack == "recipe":
                changed_manifest["recipe"] = prepare.recipe("delugi", jobs=2)
            if attack == "protocol":
                changed_info["protocol"] = "shoal"
            prepare.json_file(manifest_path, changed_manifest)
            changed_info["manifest_sha256"] = "0" * 64 if attack == "manifest_hash" else prepare.sha(manifest_path)
            prepare.json_file(info_path, changed_info)
            with self.assertRaisesRegex(ValueError, "external source metadata"):
                prepare.create_plan(self.hosts(), self.root / "bundle")

    def test_native_source_selection_checks_pin_patch_and_lock_and_includes_added_files(self):
        root = self.source()
        (root / "provenance").mkdir()
        patch_path, lock_path = root / "instrumentation.patch", root / "reviewed.lock"
        patch_path.write_bytes(b"exact instrumentation patch\n")
        lock_path.write_bytes((root / "Cargo.lock").read_bytes())
        pin = {"commit": "a" * 40, "checkout": ".", "instrumentation_patch": patch_path.name,
               "dependency_lock": lock_path.name, "repository": "https://example.test/native.git"}
        prepare.json_file(root / "provenance/baselines.json", {"baselines": {"autobahn": pin}})
        native_output = [(pin["commit"] + "\n"), patch_path.read_bytes(), b"Cargo.toml\0src/main.rs\0"]
        with patch.object(prepare.subprocess, "check_output", side_effect=native_output):
            source, paths, provenance = prepare.source_selection(root, "autobahn")
        self.assertIn(Path("src/main.rs"), paths)
        self.assertIn(Path("Cargo.lock"), paths)
        self.assertEqual(provenance["commit"], pin["commit"])
        with patch.object(prepare.subprocess, "check_output", return_value="wrong-head\n"):
            with self.assertRaisesRegex(ValueError, "exact commit"):
                prepare.source_selection(root, "autobahn")
        with patch.object(prepare.subprocess, "check_output", side_effect=[pin["commit"], b"unexpected patch"]):
            with self.assertRaisesRegex(ValueError, "instrumentation patch"):
                prepare.source_selection(root, "autobahn")
        lock_path.write_text("different lock")
        with patch.object(prepare.subprocess, "check_output", side_effect=native_output[:2]):
            with self.assertRaisesRegex(ValueError, "dependency lock"):
                prepare.source_selection(root, "autobahn")

    def test_preparation_is_protocol_neutral_but_actual_runner_rejects_native_inventory(self):
        from remote_deployment import validate_inventory
        hosts = self.hosts()
        hosts.update(protocol="shoal", remote_runner_supported=False)
        self.assertEqual(prepare.validate_hosts(hosts), hosts)
        with self.assertRaisesRegex(ValueError, "native remote workload adapter"):
            validate_inventory(hosts)

    def test_receipt_cannot_change_selected_protocol_recipe_binary_or_source(self):
        root = self.source()
        prepare.bundle(root, "delugi", self.root / "bundle")
        plan = prepare.create_plan(self.hosts(), self.root / "bundle")
        selected = plan["recipe"]
        receipt = {"protocol": "delugi", "recipe": selected, "native_remote_runner_supported": True,
                   "source_bundle_sha256": plan["archive_sha256"], "binaries": [{"name": "delugi-replica",
                   "path": "/tmp/delugi-build-" + plan["nonce"] + "/artifacts/delugi-replica",
                   "sha256": "1" * 64, "bytes": 10}]}
        for attack in ("protocol", "recipe", "binary", "source", "path"):
            changed = copy.deepcopy(receipt)
            if attack == "protocol": changed["protocol"] = "shoal"
            if attack == "recipe": changed["recipe"] = prepare.recipe("delugi", jobs=2)
            if attack == "binary": changed["binaries"][0]["name"] = "aptos-node"
            if attack == "source": changed["source_bundle_sha256"] = "0" * 64
            if attack == "path": changed["binaries"][0]["path"] = "/tmp/unowned-binary"
            connection = Mock()
            connection.rpc.return_value = changed
            with self.assertRaisesRegex(ValueError, "receipt"):
                prepare.execute_plan(plan, self.root / ("result-" + attack), connection_factory=lambda host: connection)
            connection.command.assert_not_called()

    def test_build_stamp_binds_binary_hash_source_and_recipe(self):
        selected = prepare.recipe("delugi")
        receipt = {"protocol": "delugi", "recipe": selected, "source_bundle_sha256": "0" * 64}
        output = {"sha256": "1" * 64}
        stamp = {"binary_sha256": output["sha256"], "source_bundle_sha256": receipt["source_bundle_sha256"],
                 "recipe": selected, "provenance": {"protocol": "delugi"}, "inputs": {"sources": {"main.rs": "2" * 64}}}
        prepare.validate_stamp(stamp, output, receipt)
        for field in ("binary_sha256", "source_bundle_sha256", "recipe", "provenance"):
            changed = copy.deepcopy(stamp)
            changed[field] = {} if field in ("recipe", "provenance") else "3" * 64
            with self.assertRaisesRegex(ValueError, "build stamp"):
                prepare.validate_stamp(changed, output, receipt)

    def test_local_mock_build_publish_clean_contract_preserves_source_identity_and_artifacts(self):
        root = self.source()
        bundle_info = prepare.bundle(root, "delugi", self.root / "bundle")
        build_root, identity = self.owned_root(self.root / "bundle/bundle.tar")
        def logged(argv, cwd, env, output, records):
            self.assertNotIn("shell", argv)
            Path(output).write_text("fixture build log")
            records.append({"arguments": argv})
            if argv[0] == "cargo":
                artifact = Path(env["CARGO_TARGET_DIR"]) / "release/delugi-replica"
                artifact.parent.mkdir(parents=True)
                artifact.write_bytes(b"local fixture binary; never executed")
                artifact.chmod(0o755)
        with patch.object(prepare.platform, "system", return_value="Linux"), patch.object(prepare.platform, "machine", return_value="x86_64"), \
             patch.object(prepare.platform, "libc_ver", return_value=("glibc", "2.31")), \
             patch.object(prepare.shutil, "which", return_value="/usr/bin/rustup"), \
             patch.object(prepare, "run_logged", side_effect=logged), \
             patch.object(prepare.subprocess, "check_output", return_value="rustc 1.92.0 fixture"), \
             patch.object(prepare.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "fixture libraries/packages", "")):
            receipt = prepare.worker({**identity, "action": "build"})
            self.assertEqual(receipt["source_bundle_sha256"], bundle_info["bundle_sha256"])
            sidecar = json.loads(Path(receipt["binaries"][0]["path"] + ".build.json").read_text())
            self.assertEqual(sidecar["inputs"]["sources"]["src/main.rs"], prepare.sha(root / "src/main.rs"))
            self.assertEqual(prepare.worker({**identity, "action": "build"}), receipt)
            publish_plan = prepare.create_plan(self.hosts(), artifacts=build_root / "artifacts.tar")
            self.assertEqual(publish_plan["phase"], "publish")
            destination, publish_identity = self.owned_root(build_root / "artifacts.tar")
            published = prepare.worker({**publish_identity, "action": "publish"})
            self.assertEqual(prepare.sha(published["binaries"][0]["path"]), receipt["binaries"][0]["sha256"])
            self.assertTrue(published["binaries"][0]["path"].startswith(str(destination)))
            prepare.worker({**identity, "action": "clean"})
            self.assertFalse((build_root / "source").exists())
            self.assertFalse((build_root / "target").exists())
            self.assertTrue((build_root / "artifacts.tar").exists())
            self.assertTrue((build_root / "receipt.json").exists())
            self.assertTrue(Path(receipt["binaries"][0]["path"]).exists())

    def test_clean_rejects_ownership_changes_and_never_follows_replaced_directory(self):
        source = self.root / "file"
        source.write_bytes(b"x")
        root, identity = self.owned_root(source)
        prepare.json_file(root / "owner.json", {**identity, "phase": "prepared"})
        unrelated = self.root / "unrelated"
        unrelated.mkdir()
        (unrelated / "keep").write_text("keep")
        (root / "target").symlink_to(unrelated, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            prepare.worker({**identity, "action": "clean"})
        with self.assertRaisesRegex(ValueError, "identity changed"):
            prepare.worker({**identity, "archive_sha256": "0" * 64, "action": "clean"})
        self.assertEqual((unrelated / "keep").read_text(), "keep")

    def test_upload_is_streamed_and_never_embeds_binary_or_key_contents_in_command(self):
        path = self.root / "binary"
        path.write_bytes(b"fixture-binary" * 100)
        connection = prepare.Connection(self.hosts()["hosts"][0])
        with patch.object(connection, "command", return_value=None) as command:
            connection.upload(path, "/tmp/delugi-build-" + "1" * 32 + "/bundle.tar")
            self.assertNotIn("fixture-binary", str(command.call_args.args))
            self.assertIn("stdin", command.call_args.kwargs)
            self.assertEqual(command.call_args.args[0][-1], prepare.sha(path))

    def test_declared_interpreter_is_used_for_every_preparation_host_operation(self):
        host = dict(self.hosts()["hosts"][0], python_executable="/opt/python3.11/bin/python3")
        connection = prepare.Connection(host)
        path = self.root / "bundle"
        path.write_bytes(b"bounded fixture")
        with patch.object(connection, "command", return_value=subprocess.CompletedProcess([], 0, "{}", "")) as command:
            connection.prepare("1" * 32, "2" * 64)
            connection.upload(path, "/tmp/owned/bundle")
            connection.rpc("1" * 32, {"action": "clean"})
        self.assertEqual(len(command.call_args_list), 3)
        self.assertTrue(all(call.args[0][0] == host["python_executable"] for call in command.call_args_list))

    def test_runtime_upload_also_streams_and_records_digest_not_file_content(self):
        import remote_deployment
        path = self.root / "runtime-config"
        path.write_bytes(b"owned-workload-config" * 100)
        hosts = self.hosts()
        hosts["hosts"][0]["binary"] = {"path": "/tmp/artifact", "sha256": "1" * 64}
        hosts["hosts"][0]["python_executable"] = "/opt/python3.11/bin/python3"
        deployment = remote_deployment.RemoteDeployment(hosts)
        with patch.object(remote_deployment.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as call:
            deployment.upload(hosts["hosts"][0], path, deployment.remote_directory + "/config.json")
            self.assertIn("stdin", call.call_args.kwargs)
            self.assertNotIn("owned-workload-config", str(call.call_args.args))
            self.assertEqual(deployment.commands[-1]["arguments"][-1], prepare.sha(path))
            self.assertEqual(deployment.commands[-1]["arguments"][0], hosts["hosts"][0]["python_executable"])


if __name__ == "__main__":
    unittest.main()
