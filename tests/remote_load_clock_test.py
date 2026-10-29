"""Remote load alignment must not require controller and server UTC equality."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_sustained import remote_load_schedule


class RemoteLoadEpoch(unittest.TestCase):
    def sample(self, replica, rtt_us, offset_us, remote_fraction=.5):
        begin_ns = 100_000_000_000
        remote_wall_us = begin_ns // 1000 + round(rtt_us * remote_fraction) + offset_us
        return {"replica": replica, "type": "start", "request_id": f"start-{replica}",
                "start_monotonic_ns": begin_ns, "duration_us": rtt_us,
                "reply": {"id": replica, "ok": True, "observed_unix_us": remote_wall_us}}

    def test_arbitrary_independent_clock_offsets_map_to_one_monotonic_epoch(self):
        # A replica 2.1 s ahead rejects the previous controller-now+1 s policy.
        offsets = [2_100_000, -5_000_000, 90_000_000, 0]
        records = [self.sample(i, [100_000, 600_000, 400_000, 200_000][i], offset)
                   for i, offset in enumerate(offsets)]
        now_ns = 100_700_000_000
        self.assertLess(now_ns // 1000 + 1_000_000, now_ns // 1000 + offsets[0])
        result = remote_load_schedule(records, list(range(4)), now_ns)
        target_us = result["controller_target_monotonic_ns"] // 1000
        self.assertEqual(result["lead_us"], 2_200_000)
        self.assertEqual(result["maximum_pairwise_start_uncertainty_us"], 500_000)
        for row, offset in zip(result["replicas"], offsets):
            requested = row["requested_start_unix_us"]
            self.assertEqual(requested - offset, target_us)
            self.assertTrue(0 < requested - (now_ns // 1000 + offset) <= 10_000_000)
            # Every origin retains its exact 30-second local schedule.
            self.assertEqual((requested + 30_000_000 - offset) - target_us, 30_000_000)
        shifted = copy.deepcopy(records)
        for i, record in enumerate(shifted):
            record["reply"]["observed_unix_us"] += (i + 1) * 20_000_000
        shifted_result = remote_load_schedule(shifted, list(range(4)), now_ns)
        self.assertEqual(shifted_result["controller_target_monotonic_ns"], result["controller_target_monotonic_ns"])

    def test_asymmetric_request_reply_paths_stay_within_recorded_uncertainty(self):
        records = [self.sample(0, 600_000, 3_000_000, 0),
                   self.sample(1, 400_000, -8_000_000, 1)]
        result = remote_load_schedule(records, [0, 1], 100_700_000_000)
        target = result["controller_target_monotonic_ns"] // 1000
        actual_starts = []
        for row, offset in zip(result["replicas"], [3_000_000, -8_000_000]):
            actual = row["requested_start_unix_us"] - offset
            actual_starts.append(actual)
            self.assertLessEqual(abs(actual - target), row["uncertainty_us"])
        self.assertLessEqual(abs(actual_starts[0] - actual_starts[1]),
                             result["maximum_pairwise_start_uncertainty_us"])

    def test_slow_stale_missing_duplicate_or_invalid_samples_fail_before_load(self):
        good = [self.sample(0, 100_000, 2_100_000), self.sample(1, 200_000, 2_100_000)]
        for records, now in (([self.sample(0, 2_000_001, 0), good[1]], 103_000_000_000),
                             (good, 106_000_000_000), (good[:1], 100_300_000_000),
                             ([good[0], good[0]], 100_300_000_000),
                             (good, 99_000_000_000)):
            with self.subTest(records=records, now=now), self.assertRaises(ValueError):
                remote_load_schedule(records, [0, 1], now)
        invalid = copy.deepcopy(good)
        invalid[0]["reply"]["ok"] = False
        with self.assertRaises(ValueError):
            remote_load_schedule(invalid, [0, 1], 100_300_000_000)

    def test_maximum_accepted_rtt_keeps_future_window_below_native_ten_second_limit(self):
        result = remote_load_schedule([self.sample(0, 2_000_000, 0)], [0], 102_000_000_000)
        self.assertEqual(result["lead_us"], 5_000_000)
        uncertainty = result["replicas"][0]["uncertainty_us"]
        self.assertGreater(result["lead_us"] - uncertainty, 0)
        self.assertLess(result["lead_us"] + uncertainty, 10_000_000)


if __name__ == "__main__":
    unittest.main()
