"""Guard baseline measurement boundaries and reject incomplete telemetry."""
import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mysticeti_baseline", ROOT / "scripts/baselines/mysticeti.py"
)
MYSTICETI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MYSTICETI)


def snapshots():
    count = 'latency_s_count{workload="shared"}'
    total = 'latency_s_sum{workload="shared"}'
    bucket = 'latency_s_bucket{workload="shared",le="0.1"}'
    return (
        {"midpoint_monotonic_ns": 1_000_000_000,
         "values": {count: 100, total: 0.3, bucket: 100}},
        {"midpoint_monotonic_ns": 2_000_000_000,
         "values": {count: 120, total: 0.34, bucket: 120}},
    )


class MysticetiMeasurementTests(unittest.TestCase):
    def test_warmup_is_subtracted_and_histogram_is_only_an_upper_bound(self):
        before, after = snapshots()
        result = MYSTICETI.summarize(before, after, 2)
        self.assertEqual(result["authority"], 2)
        self.assertEqual(result["committed_transaction_observations"], 20)
        self.assertAlmostEqual(result["commit_throughput_tx_s"], 20)
        self.assertAlmostEqual(result["mean_generation_to_commit_latency_ms"], 2)
        self.assertEqual(result["p95_histogram_upper_bound_ms"], 100)

    def test_missing_start_counter_cannot_be_treated_as_zero(self):
        before, after = snapshots()
        del before["values"]['latency_s_count{workload="shared"}']
        with self.assertRaises((RuntimeError, ValueError)):
            MYSTICETI.summarize(before, after, 0)

    def test_missing_latency_sum_cannot_produce_a_zero_latency(self):
        before, after = snapshots()
        for snap in (before, after):
            del snap["values"]['latency_s_sum{workload="shared"}']
        with self.assertRaises((RuntimeError, ValueError)):
            MYSTICETI.summarize(before, after, 0)

    def test_counter_reset_is_rejected(self):
        before, after = snapshots()
        after["values"]['latency_s_count{workload="shared"}'] = 99
        with self.assertRaises((RuntimeError, ValueError)):
            MYSTICETI.summarize(before, after, 0)

    def test_nonpositive_window_is_rejected(self):
        before, after = snapshots()
        after["midpoint_monotonic_ns"] = before["midpoint_monotonic_ns"]
        with self.assertRaises((RuntimeError, ValueError)):
            MYSTICETI.summarize(before, after, 0)

    def test_nonfinite_latency_is_rejected(self):
        before, after = snapshots()
        for invalid in (float("nan"), float("inf")):
            with self.subTest(invalid=invalid):
                broken = copy.deepcopy(after)
                broken["values"]['latency_s_sum{workload="shared"}'] = invalid
                with self.assertRaises((RuntimeError, ValueError)):
                    MYSTICETI.summarize(before, broken, 0)

    def test_zero_output_retains_window_and_undefined_latency(self):
        before, after = snapshots()
        after["values"] = copy.deepcopy(before["values"])
        result = MYSTICETI.summarize(before, after, 0)
        self.assertEqual(result["measurement_seconds"], 1)
        self.assertEqual(result["committed_transaction_observations"], 0)
        self.assertEqual(result["commit_throughput_tx_s"], 0)
        self.assertIsNone(result["mean_generation_to_commit_latency_ms"])
        for percentile in (50, 95, 99):
            self.assertIsNone(result[f"p{percentile}_histogram_upper_bound_ms"])


if __name__ == "__main__":
    unittest.main()
