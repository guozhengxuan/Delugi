import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from cohort_metrics import cost_ratios, observed_all_correct_deadlines, quantiles, summarize_cohorts


def fixture():
    request = {"request_id": "a", "origin": 0, "sequence": 0, "useful_bytes": 100,
               "scheduled_us": 1000, "admitted_us": 2000, "batch_ready_us": 3000,
               "materialized_us": 5000, "rejected_us": None}
    output = {"request_id": "a", "origin": 0, "useful_bytes": 100,
              "output_index": 1, "materialized_us": 5000, "exact_batch_id": "batch-a"}
    ledgers = {}
    for i in range(4):
        ledgers[i] = {"requests": [request.copy()] if i == 0 else [], "outputs": [output.copy()],
                      "batches": [{"exact_batch_id": "batch-a", "payload_bytes": 168, "materialized_us": 5000}],
                      "window_start_us": 0, "window_end_us": 10000, "observed_us": 20000}
    return ledgers


class ExactCohortAccounting(unittest.TestCase):
    def test_same_microsecond_requires_latched_local_completion(self):
        for eligible in (False, True):
            with self.subTest(eligible=eligible):
                data = fixture()
                data[0]["requests"][0].update(admitted_us=5000, batch_ready_us=5000,
                    materialized_us=5000 if eligible else None)
                result = summarize_cohorts(data)
                self.assertEqual(result["window"]["completion_count"], int(eligible))
                self.assertEqual(result["window"]["u_out_bytes"], 100 * eligible)
                self.assertEqual(result["window"]["m_out_bytes"], 168)
                self.assertEqual(result["finite_run"]["u_out_bytes"], 100 * eligible)
                self.assertEqual(result["completed"], int(eligible))
                self.assertEqual(result["unfinished"], int(not eligible))

    def test_replication_does_not_multiply_useful_output(self):
        result = summarize_cohorts(fixture(), deadline_ms=10)
        self.assertEqual(result["window"]["completion_count"], 1)
        self.assertEqual(result["window"]["u_out_bytes"], 100)
        self.assertEqual(result["window"]["m_out_bytes"], 168)
        self.assertEqual(result["all_correct_collection"]["fraction"], 1)
        self.assertEqual(result["admission_to_output"]["p99"]["value_ms"], 3)
        self.assertEqual(result["scheduled_to_output"]["p99"]["value_ms"], 4)

    def test_zero_based_native_ordinal_reports_actual_prefix_count(self):
        data = fixture()
        for ledger in data.values():
            ledger["output_index_base"] = 0
            ledger["outputs"][0]["output_index"] = 2
        result = summarize_cohorts(data)
        self.assertEqual(result["finite_run"]["output_prefix_count"], 3)

    def test_boundary_backlog_uses_admission_and_exact_output_on_origin_clock(self):
        data = fixture()
        for ledger in data.values():
            ledger["window_start_us"] = 3500
        data[0]["requests"].append(dict(data[0]["requests"][0], request_id="pending", sequence=1,
            scheduled_us=8500, admitted_us=9000, batch_ready_us=9500, materialized_us=None))
        window = summarize_cohorts(data)["window"]
        self.assertEqual(window["pending_at_start"], 1)
        self.assertEqual(window["pending_at_end"], 1)
        self.assertEqual(window["admission_count"], 1)

    def test_declared_full_prefix_includes_unrecognized_nonuseful_tail(self):
        data = fixture()
        for ledger in data.values():
            ledger["output_prefix_count"] = 3
        result = summarize_cohorts(data)
        self.assertEqual(result["finite_run"]["output_prefix_count"], 3)
        self.assertEqual(result["finite_run"]["u_out_bytes"], 100)
        data[0]["output_prefix_count"] = 0
        with self.assertRaisesRegex(ValueError, "prefix"):
            summarize_cohorts(data)

    def test_fork_replay_only_increases_exact_batch_denominator(self):
        data = fixture()
        for ledger in data.values():
            replay = dict(ledger["outputs"][0], output_index=2, materialized_us=6000, exact_batch_id="fork")
            ledger["outputs"].append(replay)
            ledger["batches"].append({"exact_batch_id": "fork", "payload_bytes": 168, "materialized_us": 6000})
        result = summarize_cohorts(data)
        self.assertEqual(result["window"]["u_out_bytes"], 100)
        self.assertEqual(result["window"]["m_out_bytes"], 336)

    def test_unfinished_and_rejected_requests_remain_in_cohort(self):
        data = fixture()
        for sequence in (1, 2):
            row = dict(data[0]["requests"][0], request_id=str(sequence), sequence=sequence,
                       materialized_us=None, scheduled_us=2000, admitted_us=2500, batch_ready_us=None)
            if sequence == 2:
                row.update(admitted_us=None, rejected_us=2600)
            data[0]["requests"].append(row)
        result = summarize_cohorts(data, deadline_ms=10)
        self.assertEqual(result["scheduled"], 3)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["unfinished"], 2)
        self.assertEqual(result["deadline_completion_fraction"], 1 / 3)
        self.assertIsNone(result["scheduled_to_output"]["p99"]["value_ms"])
        self.assertEqual(result["scheduled_to_output"]["p99"]["lower_bound_ms"], 18)

    def test_zero_output_keeps_absolute_cost_and_undefined_ratios(self):
        data = fixture()
        data[0]["requests"][0]["materialized_us"] = None
        for ledger in data.values():
            ledger["outputs"] = []
            ledger["batches"] = []
        result = summarize_cohorts(data)
        ratios = cost_ratios(1234, result)
        self.assertEqual(result["window"]["unique_completion_tps"], 0)
        self.assertEqual(ratios["written_bytes"], 1234)
        self.assertIsNone(ratios["written_bytes_per_u_out_byte"])
        self.assertIsNone(result["scheduled_to_output"]["p50"]["value_ms"])

    def test_remote_clock_offsets_do_not_change_local_latency(self):
        data = fixture()
        for key in ("window_start_us", "window_end_us", "observed_us"):
            data[1][key] += 1_000_000
        data[1]["outputs"][0]["materialized_us"] += 1_000_000
        data[1]["batches"][0]["materialized_us"] += 1_000_000
        result = summarize_cohorts(data)
        self.assertEqual(result["admission_to_output"]["p99"]["value_ms"], 3)
        self.assertEqual(result["all_correct_collection"]["fraction"], 1)

    def test_nonuniform_missing_censor_times_cannot_fake_a_quantile(self):
        result = quantiles([10, 100], [1])
        self.assertIsNone(result["p50"]["value_ms"])
        self.assertEqual(result["p50"]["lower_bound_ms"], .01)

    def test_missing_exact_output_or_inconsistent_identity_fails(self):
        data = fixture()
        data[0]["outputs"] = []
        with self.assertRaisesRegex(ValueError, "reconcile"):
            summarize_cohorts(data)
        data = fixture()
        data[1]["outputs"][0]["useful_bytes"] = 200
        with self.assertRaisesRegex(ValueError, "identity content"):
            summarize_cohorts(data)

    def test_faulty_origin_is_excluded_without_excluding_cost(self):
        data = fixture()
        result = summarize_cohorts(data, correct_replicas=[1, 2, 3])
        self.assertEqual(result["scheduled"], 0)
        self.assertEqual(result["window"]["u_out_bytes"], 0)
        self.assertEqual(result["window"]["m_out_bytes"], 168)
        self.assertEqual(cost_ratios(1000, result)["written_bytes"], 1000)

    def test_observed_all_correct_deadline_includes_poll_delay_and_bounds(self):
        data = fixture()
        observations = [{"replica": i, "start_monotonic_us": 105000,
                         "received_monotonic_us": 106000, "elapsed_us": 5000,
                         "executed_count": 1} for i in range(4)]
        result = observed_all_correct_deadlines(data, observations, correct_replicas=range(4), deadline_ms=10)
        self.assertEqual(result["completion_fraction_lower_bound"], 1)
        result = observed_all_correct_deadlines(data, observations, correct_replicas=range(4), deadline_ms=4.5)
        self.assertEqual(result["clock_boundary_uncertain"], 1)
        self.assertEqual(result["completion_fraction_lower_bound"], 0)
        observations[3]["executed_count"] = 0
        result = observed_all_correct_deadlines(data, observations, correct_replicas=range(4), deadline_ms=10)
        self.assertEqual(result["unfinished_at_collection"], 1)

    def test_inconsistent_clock_bridge_is_not_silently_synchronized(self):
        observations = [{"replica": 0, "start_monotonic_us": 100, "received_monotonic_us": 101,
                         "elapsed_us": 1, "executed_count": 1},
                        {"replica": 0, "start_monotonic_us": 200, "received_monotonic_us": 201,
                         "elapsed_us": 1, "executed_count": 1}]
        with self.assertRaisesRegex(ValueError, "clock bridges"):
            observed_all_correct_deadlines(fixture(), observations, correct_replicas=[0], deadline_ms=10)

    def test_filtered_output_uses_native_ordinal_for_observed_prefix(self):
        data = fixture()
        for ledger in data.values():
            ledger["outputs"][0]["output_index"] = 9  # Eight unrecognized application outputs preceded this request.
        observations = [{"replica": i, "start_monotonic_us": 105000, "received_monotonic_us": 106000,
                         "elapsed_us": 5000, "executed_count": 1} for i in range(4)]
        result = observed_all_correct_deadlines(data, observations, correct_replicas=range(4), deadline_ms=10)
        self.assertEqual(result["unfinished_at_collection"], 1)

    def test_future_manifest_identity_without_admission_does_not_earn_goodput(self):
        data = fixture()
        data[0]["requests"][0].update(admitted_us=None, batch_ready_us=None, materialized_us=None)
        result = summarize_cohorts(data)
        self.assertEqual(result["window"]["u_out_bytes"], 0)
        self.assertEqual(result["finite_run"]["u_out_bytes"], 0)
        self.assertEqual(result["window"]["m_out_bytes"], 168)

    def test_origin_observed_notifications_include_return_delay(self):
        data = fixture()
        data[0]["requests"][0]["all_correct_observed_us"] = 9000
        result = summarize_cohorts(data, deadline_ms=6)
        self.assertEqual(result["deadline_completion_fraction"], 1)
        observed = result["all_correct_origin_observed"]
        self.assertEqual(observed["deadline_completion_fraction_lower_bound"], 0)
        self.assertEqual(observed["scheduled_to_observation"]["p99"]["value_ms"], 8)


if __name__ == "__main__":
    unittest.main()
