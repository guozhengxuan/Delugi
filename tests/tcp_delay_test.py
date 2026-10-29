"""Focused checks for the userspace delay diagnostic (no TCP sockets needed)."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_tcp_delay as runner


class Reader:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.reads = 0

    async def read(self, _limit):
        self.reads += 1
        return self.chunks.pop(0) if self.chunks else b""


class Writer:
    def __init__(self, reader):
        self.reader, self.writes, self.eof = reader, [], False

    def write(self, data):
        self.writes.append((data, self.reader.reads, asyncio.get_running_loop().time()))

    async def drain(self):
        pass

    def can_write_eof(self):
        return True

    def write_eof(self):
        self.eof = True


class Pipeline(unittest.IsolatedAsyncioTestCase):
    async def test_ingests_future_chunks_before_first_delayed_write_and_preserves_bytes(self):
        reader = Reader([b"first", b"second", b"third"])
        writer = Writer(reader)
        counters = runner.stream_counters()
        started = asyncio.get_running_loop().time()
        await runner.delayed_stream(reader, writer, .03, counters)
        self.assertEqual(b"".join(item[0] for item in writer.writes), b"firstsecondthird")
        self.assertEqual(writer.writes[0][1], 4)  # All chunks and EOF ingested first.
        self.assertGreaterEqual(writer.writes[0][2] - started, .029)
        self.assertLess(writer.writes[-1][2] - writer.writes[0][2], .025)
        self.assertTrue(writer.eof)
        self.assertEqual(counters["read_bytes"], counters["forwarded_bytes"])
        self.assertEqual(counters["forwarded_chunks"], 3)
        self.assertEqual(counters["queue_capacity_waits"], 0)

    async def test_bounded_queue_backpressure_is_explicit(self):
        reader = Reader([b"a"] * 5)
        writer = Writer(reader)
        counters = runner.stream_counters()
        with patch.object(runner, "QUEUE_CHUNKS", 2):
            await runner.delayed_stream(reader, writer, .005, counters)
        self.assertGreater(counters["queue_capacity_waits"], 0)
        self.assertLessEqual(counters["peak_queued_chunks"], 2)
        self.assertEqual(counters["read_bytes"], counters["forwarded_bytes"])


class Harness(unittest.TestCase):
    def test_source_snapshot_covers_modular_binary_inputs(self):
        stamp = {"inputs": runner.run_sustained.build_inputs("test compiler")}
        paths = {str(path.relative_to(runner.ROOT)) for path in runner.current_source_paths(stamp)}
        self.assertIn("core/delugi/src/composed.rs", paths)
        self.assertIn("shared/network/src/lib.rs", paths)
        self.assertIn("core/delugi/Cargo.toml", paths)
        self.assertIn("Cargo.lock", paths)

    def test_both_real_runner_adapters_forward_composed_pipeline_schedule(self):
        args = SimpleNamespace(bound_ms=100, ordering_batch=True, round_barrier_ms=None,
                               progress_pacing_ms=None, ordering_mode="canonical", report_schedule="pipeline",
                               rate=100, warmup=2, duration=20, transaction_size=64, ingress_batch_ms=1,
                               drain=30, silent_first_leader=True, causal_trace=True,
                               trace_stride=1, trace_max_events=200000)
        with patch.object(runner.run_network, "run_trial") as finite, \
                patch.object(runner.run_sustained, "run_trial") as sustained:
            runner.run_finite(Path("binary"), Path("finite"), 0, args)
            runner.run_load(Path("binary"), Path("sustained"), args)
        for trial in (finite, sustained):
            self.assertEqual(trial.call_args.kwargs["ordering_mode"], "canonical")
            self.assertEqual(trial.call_args.kwargs["report_schedule"], "pipeline")
        self.assertEqual(finite.call_args.args[2], {"silent": 0})
        self.assertTrue(sustained.call_args.kwargs["silent_first_leader"])
        self.assertEqual(sustained.call_args.kwargs["causal_trace"],
                         {"detail_stride": 1, "max_events": 200000})
        args.causal_trace = False
        args.silent_first_leader = False
        with patch.object(runner.run_sustained, "run_trial") as sustained:
            runner.run_load(Path("binary"), Path("healthy"), args)
        self.assertIsNone(sustained.call_args.kwargs["causal_trace"])
        self.assertFalse(sustained.call_args.kwargs["silent_first_leader"])

    def test_old_archive_requires_original_harness_without_silent_default_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            source = output / "binary-source/src/process.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub struct Config { pub ordering_batch: bool }")
            with self.assertRaisesRegex(RuntimeError, "original archived harness"):
                runner.verify_archived_ordering_config(output)
            source.write_text("pub struct Config { pub ordering_mode: Option<OrderingMode> }")
            runner.verify_archived_ordering_config(output)

    def test_archived_binary_binds_original_source_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, output = root / "original", root / "output"
            original.mkdir()
            output.mkdir()
            binary = root / "binary"
            binary.write_bytes(b"old binary")
            files = {}
            for name in ("Cargo.toml", "Cargo.lock", "src/transport.rs", "src/process.rs"):
                path = original / "snapshot" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
                files[name] = runner.run_network.sha(path.read_bytes())
            digest = runner.run_network.sha(binary.read_bytes())
            manifest = {"status": "passed", "rustc": "original compiler", "git_head": "old commit",
                        "binary_sha256": digest, "source_files": [{"path": k, "sha256": v} for k, v in files.items()],
                        "build_stamp": {"inputs": {"compiler": "original compiler", "sources": files}, "binary_sha256": digest}}
            path = original / "manifest.json"
            path.write_text(json.dumps(manifest))
            verified = runner.archived_build(binary, path, output)
            self.assertEqual(verified["binary_git_head"], "old commit")
            self.assertEqual((output / "binary-source/src/transport.rs").read_bytes(), b"src/transport.rs")
            manifest["status"] = "built"
            path.write_text(json.dumps(manifest))
            self.assertEqual(runner.archived_build(binary, path, output)["build_stamp"], manifest["build_stamp"])
            (original / "snapshot/src/transport.rs").write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "archived source disagrees"):
                runner.archived_build(binary, path, output)
            binary.write_bytes(b"different binary")
            with self.assertRaisesRegex(RuntimeError, "archived binary does not match"):
                runner.archived_build(binary, path, output)

    def test_address_wiring_retains_own_listener_and_control_ports(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = {"addresses": [f"127.0.0.1:{31000+i}" for i in range(4)],
                        "control_addresses": [f"127.0.0.1:{32000+i}" for i in range(4)],
                        "control_token": "fixture"}
            config_path = directory / "config.json"
            config_path.write_text(json.dumps(original))
            fake_proxy = Mock(addresses=[f"127.0.0.1:{33000+i}" for i in range(4)])
            fake_proxy.start.return_value = fake_proxy
            factory = runner.ProxiedChildren(10)
            factory.original_child = Mock()
            with patch.object(runner, "DelayProxy", return_value=fake_proxy):
                for node_id in range(4):
                    factory.child(Path("binary"), config_path, node_id, directory)
                    mapped = json.loads((directory / f"config-replica-{node_id}.json").read_text())
                    expected = list(fake_proxy.addresses)
                    expected[node_id] = original["addresses"][node_id]
                    self.assertEqual(mapped["addresses"], expected)
                    self.assertEqual(mapped["control_addresses"], original["control_addresses"])
            self.assertEqual(json.loads(config_path.read_text()), original)
            fake_proxy.start.assert_called_once()

    def test_directed_matrix_uses_source_specific_routes_and_preserves_bindings(self):
        matrix = [[0, 7, 31, 80], [11, 0, 85, 120], [33, 90, 0, 115], [81, 125, 117, 0]]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            config = {"addresses": [f"127.0.0.1:{31000+i}" for i in range(4)],
                      "control_addresses": [f"127.0.0.1:{32000+i}" for i in range(4)]}
            path = directory / "config.json"
            path.write_text(json.dumps(config))
            rows = [[f"127.0.0.1:{33000+i*4+j}" for j in range(4)] for i in range(4)]
            proxy = Mock(addresses_by_source=rows)
            proxy.start.return_value = proxy
            factory = runner.ProxiedChildren(10, matrix)
            factory.original_child = Mock()
            with patch.object(runner, "DelayProxy", return_value=proxy) as create:
                for source in range(4):
                    factory.child(Path("binary"), path, source, directory)
                    actual = json.loads((directory / f"config-replica-{source}.json").read_text())
                    expected = list(rows[source]); expected[source] = config["addresses"][source]
                    self.assertEqual(actual["addresses"], expected)
                    self.assertEqual(actual["control_addresses"], config["control_addresses"])
                create.assert_called_once_with(config["addresses"], 10, matrix)
            self.assertEqual(json.loads(path.read_text()), config)

    def test_matrix_shape_values_and_provenance_are_validated(self):
        matrix = [[0, 7], [11, 0]]
        copied = runner.validate_delay_matrix(matrix, 2)
        matrix[0][1] = 99
        self.assertEqual(copied[0][1], 7)
        for invalid in ([[0]], [[1, 7], [11, 0]], [[0, float("nan")], [11, 0]],
                        [[0, True], [11, 0]], [[0, -1], [11, 0]], [[0, 1001], [11, 0]]):
            with self.subTest(matrix=invalid), self.assertRaises(ValueError):
                runner.validate_delay_matrix(invalid, 2)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix.json"
            path.write_text(json.dumps({"description": "Synthetic directed timing test", "matrix_ms": copied}))
            model = runner.read_delay_model(path, 2)
            self.assertEqual(model["matrix_ms"], copied)
            self.assertEqual(model["sha256"], runner.run_network.sha(path.read_bytes()))
            path.write_text(json.dumps({"matrix_ms": copied}))
            with self.assertRaisesRegex(ValueError, "description"):
                runner.read_delay_model(path, 2)

    def test_each_direction_is_checked_against_its_own_matrix_entry(self):
        def counter(milliseconds):
            value = runner.stream_counters()
            value.update(read_bytes=4, forwarded_bytes=4, forwarded_chunks=1,
                         forward_delay_min_us=milliseconds*1000)
            return value
        report = {"thread_stopped": True, "delay_ms_per_direction": None,
                  "delay_matrix_ms": [[0, 7], [31, 0]],
                  "connections": [{"closed": True, "source_replica": 0, "destination_replica": 1,
                    "requested_delay_ms": {"client_to_replica": 7, "replica_to_client": 31},
                    "client_to_replica": counter(7), "replica_to_client": counter(31)}]}
        runner.verify_proxy(report)
        report["connections"][0]["replica_to_client"]["forward_delay_min_us"] = 7000
        with self.assertRaisesRegex(AssertionError, "earlier"):
            runner.verify_proxy(report)
        report["connections"][0]["replica_to_client"]["forward_delay_min_us"] = 31000
        report["connections"][0]["requested_delay_ms"]["replica_to_client"] = 7
        with self.assertRaisesRegex(AssertionError, "matrix"):
            runner.verify_proxy(report)

    def test_spawn_failure_cleanup_retains_already_started_children(self):
        factory = runner.ProxiedChildren(10)
        alive, exited = Mock(), Mock()
        alive.process.poll.return_value = None
        exited.process.poll.return_value = 0
        factory.children = [alive, exited]
        factory.proxy = Mock()
        factory.close()
        alive.finish.assert_called_once()
        exited.finish.assert_not_called()
        factory.proxy.close.assert_called_once()

    def test_operation_and_cleanup_errors_both_survive_in_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            factory = Mock(children=[])
            factory.close.side_effect = RuntimeError("cleanup failed")
            factory.proxy.report.return_value = {"thread_stopped": True, "connections": []}
            with patch.object(runner, "ProxiedChildren", return_value=factory):
                result = runner.run_proxied(Path("binary"), directory, 10,
                                           Mock(side_effect=RuntimeError("operation failed")))
            self.assertEqual(result["status"], "failed")
            self.assertIn("operation failed", result["error"])
            self.assertIn("cleanup failed", result["diagnostic_cleanup_errors"][0])
            self.assertTrue((directory / "proxy.json").is_file())
            self.assertTrue((directory / "diagnostic-result.json").is_file())

    def test_proxy_rejects_discarded_bytes_and_delay_queue_saturation(self):
        counter = runner.stream_counters()
        counter.update(read_bytes=5, forwarded_bytes=5, forwarded_chunks=1, forward_delay_min_us=10000)
        report = {"thread_stopped": True, "delay_ms_per_direction": 10,
                  "connections": [{"closed": True, "client_to_replica": dict(counter),
                                   "replica_to_client": dict(counter)}]}
        runner.verify_proxy(report)
        report["connections"][0]["client_to_replica"]["forwarded_bytes"] = 4
        with self.assertRaisesRegex(AssertionError, "discarded"):
            runner.verify_proxy(report)
        report["connections"][0]["client_to_replica"]["forwarded_bytes"] = 5
        report["connections"][0]["replica_to_client"]["queue_capacity_waits"] = 1
        with self.assertRaisesRegex(AssertionError, "saturated"):
            runner.verify_proxy(report)

    def test_only_loopback_targets_are_accepted(self):
        self.assertEqual(runner.address_tuple("127.0.0.1:10000"), ("127.0.0.1", 10000))
        for address in ("example.com:10000", "127.0.0.1:0", "127.0.0.1:65536"):
            with self.assertRaises(ValueError):
                runner.address_tuple(address)


if __name__ == "__main__":
    unittest.main()
