#!/usr/bin/env python3
"""Checks for counter interpretation and native leader-log validation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

spec = importlib.util.spec_from_file_location("mysticeti_baseline", Path(__file__).with_name("mysticeti.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class NativeMaterializationGuard(unittest.TestCase):
    def test_foreign_application_origin_does_not_receive_useful_credit(self):
        # Compile only the exact pure identity/author guard. Native crate/state
        # integration remains a separately coordinated Cargo gate.
        patch = runner.PATCH.read_text()
        added = "\n".join(line[1:] for line in patch.splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
        function = "    pub fn credited_identity(" + added.split("    pub fn credited_identity(", 1)[1].split("    pub fn stage(", 1)[0]
        source = function + r'''
fn main() {
    let identity=(1u64,0u64,1usize,String::from("fixture-identity"));
    assert!(!credited_identity(Some(&identity),0));
    assert!(credited_identity(Some(&identity),1));
    assert!(!credited_identity(None,0));
}
'''
        with tempfile.TemporaryDirectory(prefix="delugi-native-guard-") as directory:
            path = Path(directory)
            (path / "guard.rs").write_text(source)
            subprocess.run(["rustc", "--edition=2021", str(path / "guard.rs"), "-o", str(path / "guard")],
                           check=True, capture_output=True)
            subprocess.run([str(path / "guard")], check=True, capture_output=True)

    def test_compact_requires_finite_mode_and_full_remains_default(self):
        self.assertEqual(runner.argument_parser().parse_args([]).cohort_observer,"full")
        self.assertEqual(runner.argument_parser().parse_args(["--cohort-observer","compact"]).cohort_observer,"compact")
        with mock.patch.object(sys,"argv",["mysticeti.py","--legacy-window","--cohort-observer","compact"]):
            with self.assertRaises(SystemExit):runner.main()


class MetricsTests(unittest.TestCase):
    def test_finite_window_replaces_legacy_population_and_backlog_labels(self):
        finite={"window":{"completion_count":2,"admission_count":3,"admission_tps":3,"unique_completion_tps":2,"measurement_seconds":1},
                "origins":[{"pending_admitted":0,"not_admitted":1},{"pending_admitted":1,"not_admitted":2}]}
        result=runner.finite_window_summary(finite)
        self.assertEqual(result["completion_count"],2)
        self.assertEqual(result["generated_count"],3)
        self.assertEqual(result["end_pending_generated_transactions_at_origins"],[0,1])
        self.assertEqual(result["end_not_admitted_transactions_at_origins"],[1,2])
        self.assertIn("Eligible own-origin",result["completion_count_scope"])
        self.assertIn("observer prefix freeze",result["end_pending_scope"])

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

    def test_zero_output_is_accounted_with_undefined_latency(self):
        result = runner.summarize(self.snapshot(10, 5, 1), self.snapshot(40, 5, 1), 0)
        self.assertEqual(result["commit_throughput_tx_s"], 0)
        self.assertIsNone(result["mean_generation_to_commit_latency_ms"])
        self.assertIsNone(result["p99_histogram_upper_bound_ms"])

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
            events, processes, streams = [], [], []

            def genesis(command, *_args, **_kwargs):
                path = Path(command[command.index("--working-directory") + 1])
                path.mkdir()
                (path / "public-config.yaml").write_text("".join(f"127.0.0.1:{1500+i}\n" for i in range(8)))
                for index in range(4):
                    (path / f"private-config-{index}.yaml").write_text("test key")

            def spawn(*_args, **_kwargs):
                process = mock.Mock(pid=100 + len(processes), returncode=None)
                process.poll.return_value = None
                streams.append(_kwargs["stdout"])
                if not processes:
                    def exited_before_continue(_signal):
                        events.append("exit_race")
                        process.returncode = 0
                        process.poll.return_value = 0
                        raise ProcessLookupError("owned child already exited")
                    process.send_signal.side_effect = exited_before_continue
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
                self.assertEqual([process.returncode for process in processes], [0, -15, -15, -15])
                self.assertTrue(all(stream.closed for stream in streams))
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
            self.assertEqual(events, ["ready", "configure", "warmup", "exit_race", *(["terminate"] * 3), "clear"])
            processes[0].terminate.assert_not_called()
            for process in processes:
                process.wait.assert_called_once_with(timeout=5)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["network_shaping"], {"delay_ms": 10})
            self.assertEqual(manifest["network_shaping_cleanup"], {"cleared": True})
            self.assertEqual(manifest["status"], "failed")
            self.assertIn("simulated warmup failure", manifest["error"])
            self.assertEqual(manifest["settings"]["leader_timeout_seconds"], 0.1)

    def test_cleanup_failure_does_not_skip_other_children_or_streams(self):
        first, second = mock.Mock(), mock.Mock()
        first.poll.return_value = None
        first.send_signal.side_effect = PermissionError("fixture signal failure")
        first.wait.side_effect = [subprocess.TimeoutExpired("owned", 5), subprocess.TimeoutExpired("owned", 5)]
        second.poll.return_value = 0
        streams = [mock.Mock(), mock.Mock()]
        streams[0].close.side_effect = OSError("fixture close failure")
        errors = runner.cleanup_owned_children([first, second], streams)
        first.kill.assert_called_once()
        second.send_signal.assert_not_called()
        second.wait.assert_called_once_with(timeout=5)
        for stream in streams: stream.close.assert_called_once()
        self.assertEqual([row["stage"] for row in errors], ["continue/terminate", "wait/kill", "close"])


class CohortTests(unittest.TestCase):
    def journal(self, output, *, materialized=True):
        key = runner.cohort_request_id(0, 0, 4)
        events = [{"event":"start", "origin":0, "elapsed_us":0, "window_start_us":0,
                   "window_end_us":1000000, "observed_us":2000000, "rate":1,"count":1,"useful_bytes":4},
                  {"event":"admitted","request_id":key,"elapsed_us":100},
                  {"event":"batch_ready","request_id":key,"elapsed_us":1000}]
        if materialized:
            events += [{"event":"batch","exact_batch_id":"complete-native-digest","payload_bytes":44,"elapsed_us":1200},
                       {"event":"materialized","request_id":key,"origin":0,"sequence":0,"useful_bytes":4,
                        "elapsed_us":1201,"output_index":0,"exact_batch_id":"complete-native-digest"}]
        output.write_text("\n".join(json.dumps(event) for event in events)+"\n")
        return runner.read_cohort(output,0)

    def test_exact_materialization_and_same_clock_latency(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger=self.journal(Path(tmp)/"events.jsonl")
            summary=runner.cohort_metrics.summarize_cohorts({0:ledger})
            self.assertEqual(summary["completed"],1)
            self.assertEqual(summary["admission_to_output"]["p50"]["value_ms"],1.101)
            self.assertEqual(summary["window"]["u_out_bytes"],4)
            self.assertEqual(summary["window"]["m_out_bytes"],44)

    def test_unfinished_native_cohort_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger=self.journal(Path(tmp)/"events.jsonl",materialized=False)
            summary=runner.cohort_metrics.summarize_cohorts({0:ledger})
            self.assertEqual(summary["unfinished"],1)
            self.assertEqual(summary["window"]["unique_completion_tps"],0)
            self.assertEqual(summary["admission_to_output"]["p99"]["status"],"censored")
            self.assertEqual(runner.check_output_prefixes({0:ledger})["common_prefix_length"],0)

    def test_digest_mismatch_rejects_equal_leader_reference(self):
        a={"outputs":[{"output_index":0,"request_id":"same-request","exact_batch_id":"digest-a"}]}
        b={"outputs":[{"output_index":0,"request_id":"same-request","exact_batch_id":"digest-b"}]}
        with self.assertRaises(RuntimeError): runner.check_output_prefixes({0:a,1:b})

    def test_empty_replica_does_not_hide_divergent_longer_outputs(self):
        a={"outputs":[{"output_index":0,"request_id":"a","exact_batch_id":"batch"}]}
        b={"outputs":[{"output_index":0,"request_id":"b","exact_batch_id":"batch"}]}
        with self.assertRaises(RuntimeError):runner.check_output_prefixes({0:{"outputs":[]},1:a,2:b})

    def test_content_identity_covers_origin_sequence_and_payload(self):
        self.assertNotEqual(runner.cohort_request_id(0,0,4),runner.cohort_request_id(1,0,4))
        self.assertNotEqual(runner.cohort_request_id(0,0,4),runner.cohort_request_id(0,1,4))
        self.assertNotEqual(runner.cohort_request_id(0,0,4),runner.cohort_request_id(0,0,5))


if __name__ == "__main__":
    unittest.main()
