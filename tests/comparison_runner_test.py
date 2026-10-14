import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("comparison", Path(__file__).resolve().parents[1] / "scripts/run_comparison.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def fixture():
    return {"status": "passed", "comparison": {
        "protocol": "delugi", "replicas": 4, "offered_tx_s": 1000, "transaction_bytes": 512,
        "ingress_batch_ms": 100,
        "warmup_seconds": 10, "measurement_seconds": 30, "unique_completion_tps": 990,
        "completion_count": 29700, "mean_latency_ms": 4,
        "latency_endpoint": "Local insertion to materialized consensus output",
        "traffic_boundary": RUNNER.TRAFFIC_BOUNDARY, "replica_tcp_written_bytes": 900000,
        "replica_tcp_read_bytes": 899900, "replica_tcp_written_bytes_per_second": 30000,
        "generated_count": 30000, "generation_tps": 1000,
    }}


class MatchedComparisonTests(unittest.TestCase):
    def test_timing_preset_requires_actual_shape_bound_and_cleanup(self):
        for protocol in ("delugi", "raptr", "mysticeti"):
            data = {"network_shaping": {"one_way_delay_ms": 10, "protocol": protocol,
                                      "helper_sha256": "helper", "backend": "macOS_dummynet"},
                    "network_shaping_cleanup": {}, "protocol_bound_ms": 100,
                    "settings": {"bound_ms": 100}, "workload": {"native_delta_ms": 100},
                    "native_timing_observations": [{"delta_ms": [100]} for _ in range(4)]}
            self.assertEqual(RUNNER.validate_timing(data, protocol, 10, 100, "helper")["bound_ms"], 100)
            with self.assertRaises(ValueError):
                RUNNER.validate_timing(data, protocol, 10, 200, "helper")
            with self.assertRaises(ValueError):
                RUNNER.validate_timing(data, protocol, 20, 100, "helper")
            with self.assertRaises(ValueError):
                RUNNER.validate_timing(data, protocol, 10, 100, "changed-helper")
            del data["network_shaping_cleanup"]
            with self.assertRaises(ValueError):
                RUNNER.validate_timing(data, protocol, 10, 100, "helper")

    def validate(self, manifest):
        return RUNNER.validate_comparison(manifest, "delugi", 1000, 512, 10, 30)

    def test_outbound_traffic_is_not_doubled_by_receives(self):
        row = self.validate(fixture())
        self.assertAlmostEqual(row["tcp_written_bytes_per_completion"], 30000 / 990)

    def test_missing_or_different_match_dimensions_rejected(self):
        for key, value in (("replicas", 7), ("transaction_bytes", 520), ("offered_tx_s", 4000),
                           ("warmup_seconds", 0), ("ingress_batch_ms", 10), ("traffic_boundary", "payload_bytes")):
            with self.subTest(key=key):
                data = fixture()
                data["comparison"][key] = value
                with self.assertRaises(ValueError):
                    self.validate(data)

    def test_invalid_counter_or_window_rejected(self):
        for key, value in (("measurement_seconds", 0), ("measurement_seconds", 20),
                           ("mean_latency_ms", float("nan")), ("replica_tcp_written_bytes", -1),
                           ("replica_tcp_read_bytes", 0), ("unique_completion_tps", float("inf")),
                           ("generated_count", True)):
            with self.subTest(key=key):
                data = fixture()
                data["comparison"][key] = value
                with self.assertRaises(ValueError):
                    self.validate(data)

    def test_rate_counter_mismatch_rejected(self):
        for key in ("unique_completion_tps", "replica_tcp_written_bytes_per_second"):
            data = fixture()
            data["comparison"][key] *= 4
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(data)

    def test_failed_trial_cannot_enter_success_aggregate(self):
        data = fixture()
        data["status"] = "failed"
        with self.assertRaises(ValueError):
            self.validate(data)
        trials = [{"status": "failed", "protocol": "delugi", "rate": 1000, "comparison": data["comparison"]}]
        self.assertEqual(RUNNER.aggregate(trials), [])

    def test_median_groups_keep_protocol_and_rate_separate(self):
        rows = []
        for rate, tps in ((1000, 950), (1000, 990), (1000, 980), (4000, 3500)):
            data = fixture()
            data["comparison"].update(offered_tx_s=rate, unique_completion_tps=tps, completion_count=tps * 30)
            comparison = RUNNER.validate_comparison(data, "delugi", rate, 512, 10, 30)
            rows.append({"status": "passed", "protocol": "delugi", "rate": rate, "comparison": comparison})
        groups = RUNNER.aggregate(rows)
        self.assertEqual([group["successful_trials"] for group in groups], [3, 1])
        self.assertEqual(groups[0]["unique_completion_tps"]["median"], 980)
        self.assertFalse(groups[1]["all_trials_reached_95_percent_of_offered_rate"])

    def test_order_rotates_without_running_multiple_protocols_together(self):
        plan = list(RUNNER.trial_plan(["delugi", "raptr", "mysticeti"], [1000, 4000], 3))
        self.assertEqual(len(set(plan)), 18)
        self.assertEqual([p[0] for p in plan[:3]], ["delugi", "raptr", "mysticeti"])
        self.assertEqual([p[0] for p in plan[3:6]], ["raptr", "mysticeti", "delugi"])

    def test_source_pin_and_measured_binary_both_bound_to_identity(self):
        data = {"source_commit": RUNNER.PINS["mysticeti"], "source_diff_sha256": "patch",
                "binary": {"sha256": "first"}, "runner_sha256": "runner"}
        first = RUNNER.artifact_identity(data, "mysticeti")
        data["binary"]["sha256"] = "second"
        self.assertNotEqual(first, RUNNER.artifact_identity(data, "mysticeti"))
        data["source_commit"] = "current-main"
        with self.assertRaises(ValueError):
            RUNNER.artifact_identity(data, "mysticeti")


if __name__ == "__main__":
    unittest.main()
