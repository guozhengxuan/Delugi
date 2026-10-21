"""Common timing acceptance; no sockets or administrator operations."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import timing_calibration as timing


def record():
    return {"requested_one_way_delay_ms": 10, "baseline_rtt_ms": [.1] * 20,
            "shaped_rtt_ms": [20.1] * 30, "after_cleanup_rtt_ms": [.1] * 20,
            "control_baseline_rtt_ms": [.1] * 20, "control_rtt_ms": [.1] * 20,
            "control_after_cleanup_rtt_ms": [.1] * 20}


class TimingAcceptance(unittest.TestCase):
    def test_raw_peer_samples_cannot_be_relabelled_by_forged_median(self):
        row = {"source": 0, "destination": 1, "protocol_role_index": 0,
               "samples_ms": [100]*20, "median_rtt_ms": 21}
        with self.assertRaisesRegex(ValueError, "median differs"):
            timing.edge_records([row])
        row["samples_ms"] = [21]*20
        self.assertEqual(timing.edge_records([row])[(0, 1, 0)]["median"], 21)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            timing.edge_records([row, row])
        with self.assertRaisesRegex(ValueError, "exact committee ring"):
            timing.edge_records([row], {(0, 1, 0), (1, 0, 0)})
        row.pop("protocol_role_index")
        with self.assertRaisesRegex(ValueError, "identity"):
            timing.edge_records([row], require_roles=True)

    def test_rejects_all_four_previously_failed_vm_delay_observations(self):
        for observed in (29.374141, 26.709096, 25.7837155, 27.6349395):
            result = timing.addition(.1, observed + .1, 10)
            self.assertEqual(result["acceptance_tolerance_ms"], 5)
            self.assertFalse(result["addition_matches"])

    def test_inclusive_bounds_and_other_delay_scales(self):
        for configured in (15, 20, 25):
            self.assertTrue(timing.addition(0, configured, 10)["addition_matches"])
        for configured in (14.999, 25.001):
            self.assertFalse(timing.addition(0, configured, 10)["addition_matches"])
        self.assertEqual(timing.addition(0, 2, 1)["acceptance_tolerance_ms"], 2)
        self.assertEqual(timing.addition(0, 200, 100)["acceptance_tolerance_ms"], 50)
        self.assertFalse(timing.restored(100, 103))

    def test_raw_record_rejects_wrong_delay_control_or_cleanup(self):
        self.assertTrue(timing.local_record(record(), 10)["passed"])
        with self.assertRaisesRegex(ValueError, "preset"):
            timing.local_record(record(), 20)
        for key in ("control_rtt_ms", "after_cleanup_rtt_ms", "control_after_cleanup_rtt_ms"):
            value = record(); value[key] = [3.1] * 20
            self.assertFalse(timing.local_record(value, 10)["passed"])
        value = record(); value.pop("after_cleanup_rtt_ms")
        with self.assertRaisesRegex(ValueError, "missing raw"):
            timing.local_record(value, 10)

    def test_bad_numeric_samples_fail_instead_of_becoming_a_median(self):
        for number in (True, -1, float("nan"), float("inf"), "20"):
            value = record(); value["shaped_rtt_ms"][0] = number
            with self.subTest(number=number), self.assertRaises(ValueError):
                timing.local_record(value, 10)
        for size in (0, 19, 10001):
            with self.assertRaises(ValueError): timing.sample_median([1] * size)


if __name__ == "__main__": unittest.main()
