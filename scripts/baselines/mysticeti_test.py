#!/usr/bin/env python3
"""Checks for counter interpretation and native leader-log validation."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location("mysticeti_baseline", Path(__file__).with_name("mysticeti.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class MetricsTests(unittest.TestCase):
    def snapshot(self, seconds, count, total):
        text = f'''# TYPE latency_s histogram
latency_s_bucket{{workload="shared",le="0.1"}} {count}
latency_s_bucket{{workload="shared",le="+Inf"}} {count}
latency_s_count{{workload="shared"}} {count}
latency_s_sum{{workload="shared"}} {total}
'''
        return {"midpoint_monotonic_ns": seconds * 1_000_000_000, "values": runner.parse_metrics(text)}

    def test_interval_deltas_exclude_warmup(self):
        result = runner.summarize(self.snapshot(10, 5000, 500), self.snapshot(40, 35000, 560), 0)
        self.assertEqual(result["committed_transaction_observations"], 30000)
        self.assertEqual(result["commit_throughput_tx_s"], 1000)
        self.assertEqual(result["mean_generation_to_commit_latency_ms"], 2)
        self.assertEqual(result["p95_histogram_upper_bound_ms"], 100)

    def test_reversed_prometheus_label_order(self):
        before = self.snapshot(10, 0, 0)
        after = self.snapshot(40, 30000, 60)
        before["values"]['latency_s_bucket{le="0.1",workload="shared"}'] = before["values"].pop('latency_s_bucket{workload="shared",le="0.1"}')
        after["values"]['latency_s_bucket{le="0.1",workload="shared"}'] = after["values"].pop('latency_s_bucket{workload="shared",le="0.1"}')
        result = runner.summarize(before, after, 0)
        self.assertEqual(result["p95_histogram_upper_bound_ms"], 100)

    def test_counter_reset_is_failure(self):
        with self.assertRaises(RuntimeError):
            runner.summarize(self.snapshot(10, 5, 1), self.snapshot(40, 3, 0.5), 0)

    def test_no_progress_is_failure(self):
        with self.assertRaises(RuntimeError):
            runner.summarize(self.snapshot(10, 5, 1), self.snapshot(40, 5, 1), 0)

    def test_native_log_common_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            for index in range(4):
                suffix = ', "C3(8ms)"' if index == 0 else ''
                (output / f"validator-{index}.log").write_text('2020 DEBUG Committed ["A1(20ms)", "B2(4ms)"' + suffix + ']\n')
            result = runner.check_leader_prefixes(output)
            self.assertEqual(result["common_prefix_length"], 2)
            self.assertEqual(result["sequence_lengths"], [3, 2, 2, 2])
            (output / "validator-1.log").write_text('DEBUG Committed ["A2(20ms)"]\n')
            with self.assertRaises(RuntimeError):
                runner.check_leader_prefixes(output)


class InstrumentationTests(unittest.TestCase):
    def snapshots(self):
        values = {
            "benchmark_tcp_written_bytes": 100,
            "benchmark_tcp_read_bytes": 90,
            "benchmark_enqueued_transactions": 1,
            "benchmark_enqueued_transaction_bytes": 504,
            "benchmark_enqueued_encoded_transaction_bytes": 512,
            "benchmark_transaction_encoded_size_bytes": 512,
        }
        before = {"midpoint_monotonic_ns": 0, "values": values}
        after = {"midpoint_monotonic_ns": 10_000_000_000, "values": {key: value * 11 for key, value in values.items()}}
        after["values"]["benchmark_transaction_encoded_size_bytes"] = 512
        return before, after

    def test_successful_replica_io_deltas_and_exact_canonical_size(self):
        result = runner.summarize_instrumentation(*self.snapshots(), 0, 512)
        self.assertEqual(result["replica_tcp_written_bytes"], 1000)
        self.assertEqual(result["replica_tcp_read_bytes"], 900)
        self.assertEqual(result["enqueued_encoded_transaction_bytes"], 5120)
        self.assertEqual(result["enqueued_opaque_transaction_bytes"], 5040)
        self.assertEqual(result["measured_enqueued_tx_s"], 1)
        self.assertTrue(result["encoded_byte_count_matches_transaction_count"])

    def test_missing_traffic_counter_rejected(self):
        before, after = self.snapshots()
        del before["values"]["benchmark_tcp_written_bytes"]
        with self.assertRaises(RuntimeError):
            runner.summarize_instrumentation(before, after, 0, 512)

    def test_different_transaction_size_rejected(self):
        with self.assertRaises(RuntimeError):
            runner.summarize_instrumentation(*self.snapshots(), 0, 520)

    def test_counter_reset_rejected(self):
        before, after = self.snapshots()
        after["values"]["benchmark_tcp_read_bytes"] = 1
        with self.assertRaises(RuntimeError):
            runner.summarize_instrumentation(before, after, 0, 512)

    def test_nonatomic_size_counter_snapshot_is_reported(self):
        before, after = self.snapshots()
        after["values"]["benchmark_enqueued_encoded_transaction_bytes"] += 512
        result = runner.summarize_instrumentation(before, after, 0, 512)
        self.assertFalse(result["encoded_byte_count_matches_transaction_count"])

    def test_own_origin_latency_uses_disjoint_transaction_population(self):
        before = {"midpoint_monotonic_ns": 0, "values": runner.parse_metrics('benchmark_origin_latency_s_count{origin="2"} 100\nbenchmark_origin_latency_s_sum{origin="2"} 1\nbenchmark_origin_latency_s_bucket{origin="2",le="0.002"} 100')}
        after = {"midpoint_monotonic_ns": 10_000_000_000, "values": runner.parse_metrics('benchmark_origin_latency_s_count{origin="2"} 2600\nbenchmark_origin_latency_s_sum{origin="2"} 6\nbenchmark_origin_latency_s_bucket{origin="2",le="0.002"} 2600')}
        result = runner.summarize(before, after, 2, own_origin=True)
        self.assertEqual(result["commit_throughput_tx_s"], 250)
        self.assertEqual(result["mean_generation_to_commit_latency_ms"], 2)
        self.assertEqual(result["p95_histogram_upper_bound_ms"], 2)

    def test_comparison_sums_disjoint_origins_not_replicated_workload(self):
        metrics = [{"commit_throughput_tx_s": 1000}] * 4
        own = [{"committed_transaction_observations": 2500, "mean_generation_to_commit_latency_ms": 2}] * 4
        io = [runner.summarize_instrumentation(*self.snapshots(), index, 512) for index in range(4)]
        result = runner.comparison_summary(metrics, own, io, SimpleNamespace(rate=1000, transaction_size=512, warmup=10, ingress_batch_ms=100, bound_ms=100))
        self.assertEqual(result["ingress_batch_ms"], 100)
        self.assertEqual(result["leader_timeout_ms"], 100)
        self.assertEqual(result["bound_ms"], 100)
        self.assertEqual(result["completion_count"], 10000)
        self.assertEqual(result["unique_completion_tps"], 1000)
        self.assertEqual(result["replica_tcp_written_bytes"], 4000)
        self.assertEqual(result["mean_latency_ms"], 2)


class TimeoutConfigurationTests(unittest.TestCase):
    def test_cli_default_preserves_actual_one_second_timeout(self):
        args = runner.argument_parser().parse_args([])
        self.assertEqual(args.bound_ms, 1000)
        self.assertIn("leader_timeout:\n  secs: 1\n  nanos: 0\n", runner.node_parameters_text(args.bound_ms))

    def test_selected_bound_is_exact_native_duration(self):
        args = runner.argument_parser().parse_args(["--bound-ms", "100"])
        text = runner.node_parameters_text(args.bound_ms)
        self.assertIn("leader_timeout:\n  secs: 0\n  nanos: 100000000\n", text)
        self.assertIn("enable_pipelining: true", text)
        self.assertIn("number_of_leaders: 2", text)
        self.assertIn("leader_timeout:\n  secs: 1\n  nanos: 250000000\n", runner.node_parameters_text(1250))

    def test_zero_negative_and_unbounded_timeouts_rejected(self):
        for value in (0, -1, 60001):
            with self.assertRaises(ValueError):
                runner.node_parameters_text(value)


class ShapingLifecycleTests(unittest.TestCase):
    def test_shaping_after_progress_and_cleanup_after_warmup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source, target, output = directory / "source", directory / "target", directory / "trial"
            source.mkdir()
            target.mkdir()
            binary = target / "mysticeti"
            binary.write_bytes(b"mock native executable")
            (source / "Cargo.lock").write_bytes(b"mock lock")
            runner.write_json(target / "build-provenance.json", {
                "source_commit": runner.COMMIT, "binary_sha256": runner.sha256(binary),
                "cargo_lock_sha256": runner.sha256(source / "Cargo.lock"),
                "source_diff_sha256": runner.hashlib.sha256(b"").hexdigest(),
            })
            events, processes = [], []

            def genesis(command, *_args, **_kwargs):
                path = Path(command[command.index("--working-directory") + 1])
                path.mkdir()
                (path / "public-config.yaml").write_text("".join(f"127.0.0.1:{1500+i}\n" for i in range(8)))
                for index in range(4):
                    (path / f"private-config-{index}.yaml").write_text("test key")

            def spawn(*_args, **_kwargs):
                process = mock.Mock(pid=100 + len(processes), returncode=None)
                process.poll.return_value = None
                def terminate():
                    events.append("terminate")
                    process.returncode = -15
                    process.poll.return_value = -15
                process.terminate.side_effect = terminate
                processes.append(process)
                return process

            def ready(_ports):
                events.append("ready")
                return [{"values": {'latency_s_count{workload="shared"}': 1,
                    f'benchmark_origin_latency_s_count{{origin="{index}"}}': 1}} for index in range(4)]

            def configure(protocol, ports):
                self.assertEqual(protocol, "mysticeti")
                self.assertEqual(ports, [2100, 2101, 2102, 2103])
                events.append("configure")
                return {"delay_ms": 10}

            def warmup(*_args):
                events.append("warmup")
                raise RuntimeError("simulated warmup failure")

            def clear():
                events.append("clear")
                self.assertTrue(all(process.returncode == -15 for process in processes))
                return {"cleared": True}

            with mock.patch.multiple(runner, SOURCE=source, TARGET=target, BINARY=binary), \
                    mock.patch.object(runner.sys, "argv", ["mysticeti.py", "--bound-ms", "100", "--output", str(output)]), \
                    mock.patch.object(runner.platform, "system", return_value="test"), \
                    mock.patch.object(runner, "ensure_patch"), \
                    mock.patch.object(runner.subprocess, "check_output", side_effect=lambda command, **_: runner.COMMIT if "rev-parse" in command else ""), \
                    mock.patch.object(runner, "run_logged", side_effect=genesis), \
                    mock.patch.object(runner, "allocate_ports", return_value=list(range(2100, 2104)) + list(range(9100, 9104))), \
                    mock.patch.object(runner.subprocess, "Popen", side_effect=spawn), \
                    mock.patch.object(runner, "snapshots", side_effect=ready), \
                    mock.patch.object(runner, "wait_alive", side_effect=warmup), \
                    mock.patch.object(runner.network_delay, "configure_from_environment", side_effect=configure), \
                    mock.patch.object(runner.network_delay, "clear_from_environment", side_effect=clear):
                self.assertEqual(runner.main(), 1)
            self.assertEqual(events, ["ready", "configure", "warmup", *(["terminate"] * 4), "clear"])
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["network_shaping"], {"delay_ms": 10})
            self.assertEqual(manifest["network_shaping_cleanup"], {"cleared": True})
            self.assertEqual(manifest["status"], "failed")
            self.assertIn("simulated warmup failure", manifest["error"])
            self.assertEqual(manifest["settings"]["leader_timeout_seconds"], 0.1)


if __name__ == "__main__":
    unittest.main()
