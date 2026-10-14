"""Sustained-window accounting regression checks."""
import copy
from contextlib import ExitStack
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, Mock
import tempfile
import json
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_sustained as runner


def snapshot(elapsed, completed, inserted, latency, histogram, written, read):
    return {"elapsed_us": elapsed, "observed_unix_us": elapsed + 1_000_000,
            "load": {"completed": completed, "inserted": inserted, "latency_sum_us": latency,
                     "latency_histogram_ms": histogram, "pending": inserted - completed,
                     "maximum_schedule_lag_us": 123},
            "transport": {"data_bytes_read": read - 5, "queue_full_failures": 0, "rejected_frames": 0,
                          "peers": {"1": {"ack_bytes_written": 10, "ack_bytes_read": 5,
                                          "layers": {"Ordering": {"data_bytes_written": written - 10}}}}},
            "rejected_protocol_messages": 0, "executed_count": 400, "state_hash": [1, 2, 3]}


def windows():
    start = snapshot(1_000_000, 10, 15, 20_000, {"2": 10}, 100, 100)
    end = snapshot(3_000_000, 30, 40, 100_000, {"2": 10, "4": 20}, 1100, 900)
    return {i: {"measurement_start": copy.deepcopy(start), "measurement_end": copy.deepcopy(end)} for i in range(4)}


class WindowAccounting(unittest.TestCase):
    def test_excludes_warmup_and_counts_each_transaction_only_at_origin(self):
        result = runner.summarize_windows(windows(), 50, 512, 1)
        actual = result["comparison"]
        self.assertEqual(actual["completion_count"], 80)
        self.assertEqual(actual["unique_completion_tps"], 40)
        self.assertEqual(actual["generated_count"], 100)
        self.assertEqual(actual["generation_tps"], 50)
        self.assertEqual(actual["mean_latency_ms"], 4)
        self.assertEqual(actual["replica_tcp_written_bytes"], 4000)
        self.assertEqual(actual["replica_tcp_read_bytes"], 3200)
        self.assertEqual(actual["replica_tcp_written_bytes_per_second"], 2000)
        self.assertEqual(result["latency_quantiles"]["p99_upper_bound_ms"], 4)
        self.assertEqual(result["offered_load_fraction"], 1)
        self.assertEqual(actual["ingress_batch_ms"], 10)
        self.assertEqual(runner.summarize_windows(windows(), 50, 512, 1, 100)["comparison"]["ingress_batch_ms"], 100)

    def test_actual_per_replica_intervals_control_rates(self):
        data = windows()
        data[0]["measurement_end"]["elapsed_us"] = 5_000_000
        result = runner.summarize_windows(data, 50, 512, 1)["comparison"]
        self.assertEqual(result["unique_completion_tps"], 35)
        self.assertEqual(result["measurement_seconds"], 2.5)

    def test_rejects_counter_regression_and_missing_latency_samples(self):
        data = windows()
        data[0]["measurement_end"]["load"]["completed"] = 9
        with self.assertRaisesRegex(AssertionError, "decreased"):
            runner.summarize_windows(data, 50, 512, 1)
        data = windows()
        data[0]["measurement_end"]["load"]["latency_histogram_ms"]["4"] = 19
        with self.assertRaisesRegex(AssertionError, "histogram"):
            runner.summarize_windows(data, 50, 512, 1)

    def test_successful_socket_counters_include_ack_but_not_logical_queue(self):
        data = snapshot(1, 0, 0, 0, {}, 500, 600)
        data["transport"]["peers"]["1"]["layers"]["Ordering"]["enqueued_payload_bytes"] = 9999
        self.assertEqual(runner.tcp_counters(data), {"written_bytes": 500, "read_bytes": 600})

    def test_final_agreement_rejects_missing_or_divergent_output(self):
        data = {i: snapshot(1, 100, 100, 0, {}, 100, 100) for i in range(4)}
        self.assertEqual(runner.assert_agreement(data)["unique_generated_transactions"], 400)
        data[0]["executed_count"] = 399
        with self.assertRaises(AssertionError):
            runner.assert_agreement(data)
        data[0]["executed_count"] = 400
        data[1]["state_hash"] = [3]
        with self.assertRaises(AssertionError):
            runner.assert_agreement(data)

    def test_overloaded_window_retains_rates_and_explicit_target_flags(self):
        result = runner.summarize_windows(windows(), 100, 512, 1)["comparison"]
        self.assertEqual(result["generation_tps"],50)
        self.assertEqual(result["unique_completion_tps"],40)
        self.assertFalse(result["generation_target_met"])
        self.assertFalse(result["completion_target_met"])
        self.assertEqual(result["pending_at_start"],20)
        self.assertEqual(result["pending_at_end"],40)

    def test_common_prefix_verifies_all_four_exact_boundaries(self):
        replies = [{"reply":{"data":{"state_hash":[1,2,3],"count":17}}} for _ in range(4)]
        self.assertTrue(runner.assert_common_prefix(replies,17)["replicas_agree_on_common_prefix"])
        with self.assertRaises(AssertionError):
            runner.assert_common_prefix(replies[:3],17)
        with self.assertRaises(AssertionError):
            runner.assert_common_prefix(replies,18)
        replies[3]["reply"]["data"]["state_hash"] = [4]
        with self.assertRaises(AssertionError):
            runner.assert_common_prefix(replies,17)

    def test_partial_process_launch_reaps_children_already_started(self):
        child = Mock()
        child.finish.return_value = {"id":0,"exit_code":-15,"telemetry_errors":[]}
        keygen = Mock(stdout=json.dumps({"public_keys":[],"key_files":[]}))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(runner.subprocess,"run",return_value=keygen), \
             patch.object(runner,"unused_addresses",return_value=[f"127.0.0.1:{9000+i}" for i in range(8)]), \
             patch.object(runner,"Child",side_effect=[child,RuntimeError("second spawn failed")]):
            result = runner.run_trial(Path("/unused/binary"),Path(directory),1000,1,1)
        self.assertEqual(result["status"],"failed")
        self.assertIn("second spawn failed",result["error"])
        child.finish.assert_called_once_with()
        self.assertEqual(len(result["children"]),1)

    def test_skip_build_stamp_binds_source_compiler_and_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text("manifest")
            (root / "Cargo.lock").write_text("lock")
            source = root / "src/lib.rs"
            source.write_text("source-one")
            binary = root / "binary"
            binary.write_bytes(b"compiled")
            with patch.object(runner, "ROOT", root):
                stamp = {"inputs": runner.build_inputs("compiler-one"), "binary_sha256": runner.sha(binary.read_bytes())}
                Path(str(binary) + ".build.json").write_text(json.dumps(stamp))
                runner.verify_build_stamp(binary, "compiler-one")
                with self.assertRaises(RuntimeError):
                    runner.verify_build_stamp(binary, "compiler-two")
                source.write_text("source-two")
                with self.assertRaises(RuntimeError):
                    runner.verify_build_stamp(binary, "compiler-one")
                source.write_text("source-one")
                binary.write_bytes(b"different-binary")
                with self.assertRaises(RuntimeError):
                    runner.verify_build_stamp(binary, "compiler-one")

    def test_overloaded_or_invalid_transport_fails(self):
        data = {0: snapshot(1, 0, 0, 0, {}, 100, 100)}
        runner.assert_healthy(data)
        data[0]["transport"]["queue_full_failures"] = 1
        with self.assertRaises(AssertionError):
            runner.assert_healthy(data)


class NetworkShapingLifecycle(unittest.TestCase):
    def fake_trial(self, shaping=True, configure_error=None, clear_error=None,
                   save_error=None, start_error=None, child_error=None):
        events, children = [], []
        for node in range(4):
            child = Mock()
            child.events = [{"event": "ready"}]
            def finish(node=node):
                events.append(f"finish{node}")
                if child_error == node:
                    raise RuntimeError("owned child cleanup failed")
                return {"id": node, "exit_code": 0, "telemetry_errors": []}
            child.finish.side_effect = finish
            children.append(child)
        controller = Mock()
        controller.check.side_effect = lambda: events.append("ready-or-health-check")
        data = {i: snapshot(1, 100, 100, 0, {}, 100, 100) for i in range(4)}
        for node, window in windows().items():
            data[node].update(window)
        controller.snapshots.return_value = data
        def many(nodes, command, **kwargs):
            events.append(command)
            if command == "start" and start_error:
                raise start_error
            return [{"reply": {"data": {"state_hash": [1, 2, 3], "count": 400}}} for _ in range(4)]
        controller.many.side_effect = many
        def save():
            events.append("save")
            if save_error:
                raise save_error
        controller.save.side_effect = save
        def configure(protocol, ports):
            events.append("configure")
            self.assertEqual(protocol, "delugi")
            self.assertEqual(ports, [9000, 9001, 9002, 9003])
            if configure_error:
                raise configure_error
            return {"delay_ms": 10, "ports": ports} if shaping else None
        def clear():
            events.append("clear")
            if clear_error:
                raise clear_error
            return {"cleared": True}
        keygen = Mock(stdout=json.dumps({"public_keys": [], "key_files": []}))
        with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
            for owner, name, replacement in [
                (runner.subprocess, "run", Mock(return_value=keygen)),
                (runner, "unused_addresses", Mock(return_value=[f"127.0.0.1:{9000+i}" for i in range(8)])),
                (runner, "Child", Mock(side_effect=children)),
                (runner, "Controller", Mock(return_value=controller)),
                (runner, "configure_from_environment", Mock(side_effect=configure)),
                (runner, "clear_from_environment", Mock(side_effect=clear)),
                (runner, "queued_frames", Mock(return_value=0)),
                (runner.time, "monotonic", Mock(side_effect=itertools.count(100))),
                (runner.time, "sleep", Mock()),
            ]:
                stack.enter_context(patch.object(owner, name, replacement))
            result = runner.run_trial(Path("/unused/binary"), Path(directory), 1000, 1, 1,
                                      batch_ms=100, bound_ms=100)
            self.assertEqual(json.loads((Path(directory) / "result.json").read_text()),
                             json.loads(json.dumps(result)))
            self.assertEqual((Path(directory) / "network_delay.py").read_bytes(),
                             (runner.ROOT / "scripts/network_delay.py").read_bytes())
        return result, events, children

    def test_shaping_after_readiness_before_start_load_and_clear_after_children(self):
        result, events, _ = self.fake_trial()
        self.assertEqual(result["status"], "passed")
        self.assertLess(events.index("ready-or-health-check"), events.index("configure"))
        self.assertLess(events.index("configure"), events.index("start"))
        self.assertLess(events.index("start"), events.index("load"))
        self.assertGreater(events.index("clear"), events.index("finish3"))
        self.assertEqual(result["network_shaping"]["ports"], [9000, 9001, 9002, 9003])
        self.assertEqual(result["network_shaping_cleanup"], {"cleared": True})
        self.assertEqual(result["protocol_bound_ms"], 100)
        self.assertEqual(result["comparison"]["protocol_bound_ms"], 100)

    def test_unshaped_run_never_calls_clear(self):
        result, events, _ = self.fake_trial(shaping=False)
        self.assertEqual(result["status"], "passed")
        self.assertIsNone(result["network_shaping"])
        self.assertNotIn("clear", events)

    def test_unavailable_requested_helper_fails_before_workload_and_reaps_children(self):
        result, events, children = self.fake_trial(configure_error=RuntimeError("helper unavailable"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("helper unavailable", result["error"])
        self.assertNotIn("start", events)
        self.assertNotIn("load", events)
        self.assertNotIn("clear", events)
        for child in children:
            child.finish.assert_called_once_with()

    def test_shaping_clear_failure_invalidates_successful_trial_and_retains_evidence(self):
        result, events, _ = self.fake_trial(clear_error=RuntimeError("clear refused"))
        self.assertEqual(result["status"], "failed")
        self.assertIn("clear refused", result["network_shaping_cleanup_error"])
        self.assertTrue(result["cleanup_errors"])
        self.assertIn("stop", events)

    def test_trial_save_and_child_cleanup_failures_do_not_skip_other_cleanup(self):
        result, events, children = self.fake_trial(start_error=RuntimeError("start failed"),
                save_error=RuntimeError("save failed"), child_error=1)
        self.assertEqual(result["status"], "failed")
        self.assertIn("start failed", result["error"])
        self.assertIn("save failed", result["error"])
        self.assertIn("owned child cleanup failed", result["error"])
        self.assertEqual(events[-1], "clear")
        for child in children:
            child.finish.assert_called_once_with()

    def test_control_ports_and_invalid_replica_sets_cannot_enter_shaping(self):
        config = {"addresses": [f"127.0.0.1:{9000+i}" for i in range(4)],
                  "control_addresses": [f"127.0.0.1:{9500+i}" for i in range(4)]}
        self.assertEqual(runner.replica_network_ports(config), [9000, 9001, 9002, 9003])
        for bad in (["127.0.0.1:9000"] * 4, ["127.0.0.1:9000"],
                    ["0.0.0.0:9000"] * 4, ["127.0.0.1:99999"] * 4):
            with self.assertRaises(ValueError):
                runner.replica_network_ports({"addresses": bad})


if __name__ == "__main__":
    unittest.main()
