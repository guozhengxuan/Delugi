"""Tests for fail-closed experiment validation and measured endpoint accounting."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("run_network", Path(__file__).resolve().parents[1] / "scripts/run_network.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def fixture(silent=None):
    live = [i for i in range(4) if i != silent]
    rounds = [r for r in range(1, 5) if r - 1 != silent]
    submitted = [{"replica": i, "round": r, "transactions": [[r, i]],
                  "submission_start_unix_us": 1000, "submission_start_monotonic_ns": 1000000,
                  "accepted_unix_us": 1010} for r in range(1, 5) for i in live]
    executed = [{"round": rounds[0], "producer": i, "height": r, "batch_digest": [r, i],
                 "transaction": [r, i]} for i in live for r in range(1, 5)]
    base = {"executed_rounds": rounds, "executed": executed, "state_hash": [1, 2, 3],
            "pending_materialization": 0,
            "materialized_batches": [{"round": rounds[0], "header": {"producer": i, "height": r},
                                       "payload": [r, i]} for i in live for r in range(1, 5)],
            "cumulative_heights": [4 if i in live else 0 for i in range(4)],
            "observation_evidence": {},
            "ordering": {"deliveries": [{"round": r, "digest": [r], "value": [r]} for r in rounds],
                         "statuses": {str(r): {"Commit": [r]} if r in rounds else "Skip" for r in range(1, 5)}}}
    snapshots = {i: copy.deepcopy(base) for i in range(4)}
    events = {i: [{"event": "direct_commit", "round": r, "observed_unix_us": 1300} for r in rounds] for i in range(4)}
    if silent is not None:
        snapshots[silent]["executed"] = []
        snapshots[silent]["materialized_batches"] = []
        events[silent] = []
    frontier = [{"producer": i, "height": 0} for i in range(4)]
    targets = [{"producer": i, "height": 4 if i in live else 0} for i in range(4)]
    for i in live:
        snapshots[i]["observation_evidence"] = {
            str(r): {"signer": i, "signature": [i + 1] * 64,
                     "body": {"opportunity": r, "base": 0}} for r in rounds}
    for i in live:
        for r in rounds:
            if i == (r - 1) % 4:
                pool = [copy.deepcopy(snapshots[j]["observation_evidence"][str(r)]) for j in live[:3]]
                witnesses = [{"reporter": pool[index]["signer"], "source": {"Current": index}}
                             for index in range(2)]
                events[i] += [{"event": "input_ready", "round": r, "observed_unix_us": 1050},
                              {"event": "report_broadcast", "round": r,
                               "report": {"signer": i, "signature": [i + 1] * 64,
                                          "body": {"opportunity": r, "base": 0}}},
                              {"event": "proposal", "round": r, "observed_unix_us": 1100,
                               "descriptor": {"base": 0, "frontier": frontier, "targets": targets},
                               "availability_proof": {"pool": pool, "sources": [],
                                                      "coordinates": [{"Witnesses": {"witnesses": copy.deepcopy(witnesses)}}
                                                                      for _ in range(4)]}}]
            events[i] += [{"event": "ordered_descriptor", "round": r, "observed_unix_us": 1400, "_controller_received_monotonic_ns": 1450000},
                          {"event": "materialized", "round": r, "observed_unix_us": 1500},
                          {"event": "observation_snapshot", "round": r}]
        events[i] += [{"event": "transaction_materialized", "round": item["round"],
                       "transaction": item["transaction"], "observed_unix_us": 1500,
                       "_controller_received_monotonic_ns": 1600000} for item in executed]
    pivot = 0 if silent == 0 else 1
    evidence = {"reports": [{"signer": i, "body": {"horizon": 1, "positives": [] if pivot == 0 else [[1, [1]]]}}
                            for i in live[:3]],
                "pivot": pivot, "proof": None if pivot == 0 else {"cer": {"body": {"round": 1, "digest": [1]}}}}
    proposal = next(event for event in events[3] if event.get("event") == "proposal" and event["round"] == 4)
    proposal["message"] = {"Propose": {"history": {"Evidence": evidence},
                           "header": {"body": {"entries": {"horizon": 1, "pivot": pivot, "digest": None if pivot == 0 else [1]}}}}}
    return snapshots, live, submitted, events


class OutputValidation(unittest.TestCase):
    def test_bundled_progress_is_default_and_comparison_modes_are_explicit(self):
        self.assertEqual(runner.ordering_options(100),
                         {"ordering_batch": True, "ordering_mode": "progress", "progress_pacing_ms": 100})
        self.assertEqual(runner.ordering_options(250),
                         {"ordering_batch": True, "ordering_mode": "progress", "progress_pacing_ms": 250})
        self.assertEqual(runner.ordering_options(100, True, 100),
                         {"ordering_batch": True, "ordering_mode": "barrier", "round_barrier_ms": 100})
        self.assertEqual(runner.ordering_options(100, False, 50),
                         {"ordering_batch": False, "ordering_mode": "barrier", "round_barrier_ms": 50})
        self.assertEqual(runner.ordering_options(100, False, ordering_mode="canonical"),
                         {"ordering_batch": False, "ordering_mode": "canonical"})
        for deadline in (0, -1, 101):
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.ordering_options(100, True, deadline)
            with self.assertRaisesRegex(ValueError, "deadline"):
                runner.ordering_options(100, True, progress_pacing_ms=deadline)
        self.assertEqual(runner.ordering_options(100, True, progress_pacing_ms=50),
                         {"ordering_batch": True, "ordering_mode": "progress", "progress_pacing_ms": 50})
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            runner.ordering_options(100, True, 100, 100)
        for mode, barrier, progress in [("canonical", 50, None), ("canonical", None, 50),
                                        ("progress", 50, None), ("barrier", None, 50),
                                        ("unknown", None, None)]:
            with self.assertRaisesRegex(ValueError, "conflict"):
                runner.ordering_options(100, True, barrier, progress, mode)

    def test_shared_cli_selects_default_and_can_disable_bundling_for_comparisons(self):
        import argparse
        parser = argparse.ArgumentParser()
        runner.add_ordering_arguments(parser)
        defaults = parser.parse_args([])
        self.assertTrue(defaults.ordering_batch)
        self.assertIsNone(defaults.ordering_mode)
        reference = parser.parse_args(["--ordering-mode", "canonical", "--no-ordering-batch"])
        self.assertEqual(reference.ordering_mode, "canonical")
        self.assertFalse(reference.ordering_batch)

    def test_honest_output_is_complete(self):
        snapshots, live, submitted, events = fixture()
        result = runner.verify_outputs(snapshots, live, 4, None, submitted, events)
        self.assertEqual(result["transactions_per_correct_replica"], 16)
        self.assertEqual(result["composition"]["signed_reports"], 4)
        self.assertEqual(result["composition"]["signed_observations"], 16)

    def test_silent_recovery_has_three_signed_reports_and_nine_observations(self):
        snapshots, live, submitted, events = fixture(0)
        result = runner.verify_outputs(snapshots, live, 4, 0, submitted, events)
        self.assertEqual(result["composition"]["signed_reports"], 3)
        self.assertEqual(result["composition"]["signed_observations"], 9)
        self.assertEqual(result["composition"]["empty_coordinates"], 3)

    def test_missing_report_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        events[0] = [event for event in events[0] if event.get("event") != "report_broadcast"]
        with self.assertRaisesRegex(AssertionError, "missing automatic signed REPORT"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_unsigned_report_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        report = next(event for event in events[0] if event.get("event") == "report_broadcast")
        report["report"]["signature"] = []
        with self.assertRaisesRegex(AssertionError, "leader signature"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_missing_observation_evidence_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        del snapshots[2]["observation_evidence"]["1"]
        with self.assertRaisesRegex(AssertionError, "reporter signature"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_reference_input_cannot_use_historical_sources(self):
        snapshots, live, submitted, events = fixture()
        proposal = next(event for event in events[0] if event.get("event") == "proposal")
        proposal["availability_proof"]["sources"] = [[1, {}]]
        with self.assertRaisesRegex(AssertionError, "historical sources"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_reference_input_cannot_use_noncurrent_equality(self):
        snapshots, live, submitted, events = fixture(0)
        proposal = next(event for event in events[1] if event.get("event") == "proposal")
        proposal["availability_proof"]["coordinates"][0] = "Base"
        with self.assertRaisesRegex(AssertionError, "noncurrent coordinate"):
            runner.verify_outputs(snapshots, live, 4, 0, submitted, events)

    def test_current_witness_must_count_actual_signers(self):
        snapshots, live, submitted, events = fixture()
        proposal = next(event for event in events[0] if event.get("event") == "proposal")
        proposal["availability_proof"]["coordinates"][0]["Witnesses"]["witnesses"][1]["source"] = {"Current": 0}
        with self.assertRaisesRegex(AssertionError, "actual signer"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_empty_batch_output_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        for snapshot in snapshots.values():
            snapshot["materialized_batches"] = []
        with self.assertRaisesRegex(AssertionError, "exact batch output"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_same_transactions_cannot_hide_duplicate_batch_output(self):
        snapshots, live, submitted, events = fixture()
        for snapshot in snapshots.values():
            snapshot["materialized_batches"].append(copy.deepcopy(snapshot["materialized_batches"][-1]))
        with self.assertRaisesRegex(AssertionError, "duplicate, or misordered"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_silent_slot_must_be_skipped(self):
        snapshots, live, submitted, events = fixture(0)
        runner.verify_outputs(snapshots, live, 4, 0, submitted, events)
        snapshots[1]["ordering"]["statuses"]["1"] = "Undecided"
        with self.assertRaisesRegex(AssertionError, "not skipped"):
            runner.verify_outputs(snapshots, live, 4, 0, submitted, events)

    def test_equal_but_incomplete_output_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        for snapshot in snapshots.values():
            snapshot["executed"] = snapshot["executed"][:-1]
        with self.assertRaisesRegex(AssertionError, "missing, unexpected"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_same_final_hash_does_not_hide_different_order(self):
        snapshots, live, submitted, events = fixture()
        snapshots[2]["executed"].reverse()
        with self.assertRaisesRegex(AssertionError, "execution or state differs"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_missing_direct_anchor_is_rejected(self):
        snapshots, live, submitted, events = fixture(0)
        events[2] = [event for event in events[2] if event.get("event") != "direct_commit"]
        with self.assertRaisesRegex(AssertionError, "lacks direct-commit"):
            runner.verify_outputs(snapshots, live, 4, 0, submitted, events)

    def test_round_four_cannot_use_empty_history_shortcut(self):
        snapshots, live, submitted, events = fixture()
        proposal = next(event for event in events[3] if event.get("event") == "proposal" and event["round"] == 4)
        proposal["message"]["Propose"]["history"] = "Empty"
        with self.assertRaisesRegex(AssertionError, "real HISTORY3"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_duplicate_fixture_id_is_rejected(self):
        snapshots, live, submitted, events = fixture()
        submitted[1]["transactions"] = submitted[0]["transactions"]
        with self.assertRaisesRegex(AssertionError, "distinct"):
            runner.verify_outputs(snapshots, live, 4, None, submitted, events)

    def test_silent_protocol_event_is_rejected(self):
        snapshots, live, submitted, events = fixture(0)
        events[0].append({"event": "proposal", "round": 1})
        with self.assertRaisesRegex(AssertionError, "performed protocol work"):
            runner.verify_outputs(snapshots, live, 4, 0, submitted, events)


class LatencyValidation(unittest.TestCase):
    def test_post_handler_and_controller_latencies_are_separate(self):
        _, live, submitted, events = fixture()
        result = runner.collect_latency(live, submitted, events, 1000, 900, 4)
        self.assertEqual(result["all_correct_completion_from_first_submission_us"], 600)
        self.assertEqual(result["all_correct_server_completion_from_first_submission_us"], 500)
        self.assertEqual(result["all_correct_ordered_from_first_submission_us"], 450)
        self.assertEqual(result["client_observed_ordered_release"]["median_ms"], .45)
        self.assertEqual(result["client_submission_to_ordered_release"]["median_ms"], .4)
        self.assertEqual(result["producer_acceptance_to_materialization"]["median_ms"], .49)

    def test_missing_completion_telemetry_is_rejected(self):
        _, live, submitted, events = fixture()
        events[0] = [event for event in events[0] if event.get("event") != "transaction_materialized"]
        with self.assertRaisesRegex(AssertionError, "missing transaction completion"):
            runner.collect_latency(live, submitted, events, 1000, 900, 4)

    def test_duplicate_completion_telemetry_is_rejected(self):
        _, live, submitted, events = fixture()
        events[0].append(events[0][-1])
        with self.assertRaisesRegex(AssertionError, "duplicate transaction"):
            runner.collect_latency(live, submitted, events, 1000, 900, 4)


def transport_fixture():
    layer = {"enqueued_payload_bytes": 100, "payload_bytes_written": 100,
             "data_bytes_written": 130, "enqueued_frames": 1, "acknowledged_frames": 1,
             "accepted_frames": 1}
    peer = {"layers": {"Ordering": layer}, "outstanding_frames": 0, "ack_bytes_written": 20,
            "ack_bytes_read": 20, "retries": 0, "partial_frame_bytes_written": 0,
            "connection_failures": 0}
    return {0: {"transport": {"peers": {"1": peer}, "data_bytes_read": 130,
                              "rejected_frames": 0, "queue_full_failures": 0},
                "protocol": {"by_index": {"4": {"encoded_bytes": 80, "messages": 1},
                                            "6": {"encoded_bytes": 20, "messages": 0}}}}}


class TrafficValidation(unittest.TestCase):
    def test_bundle_members_and_envelope_are_separate_from_physical_frames(self):
        snapshots = transport_fixture()
        node = snapshots[0]
        layers = node["transport"]["peers"]["1"]["layers"]
        bundle = layers.pop("Ordering")
        layers["OrderingBundle"] = bundle
        bundle.update(enqueued_payload_bytes=112, payload_bytes_written=112, data_bytes_written=142)
        node["transport"]["data_bytes_read"] = 142
        node["protocol"]["by_index"]["6"]["messages"] = 1
        row = runner.aggregate_traffic(snapshots, None)["total"]
        self.assertEqual(row["protocol_enqueued_bytes"], 100)
        self.assertEqual(row["protocol_enqueued_messages"], 2)
        self.assertEqual(row["enqueued_frames"], 1)
        self.assertEqual(row["bundle_enqueued_envelope_bytes"], 12)
        self.assertEqual(row["socket_written_bytes"], 162)
        node["protocol"]["by_index"]["6"]["messages"] = 0
        with self.assertRaisesRegex(AssertionError, "bounded transport bundles"):
            runner.aggregate_traffic(snapshots, None)
        node["protocol"]["by_index"]["6"]["messages"] = 2
        with self.assertRaisesRegex(AssertionError, "index counters disagree"):
            runner.aggregate_traffic(snapshots, None)

    def test_actual_socket_bytes_include_auth_and_ack(self):
        result = runner.aggregate_traffic(transport_fixture(), None)
        self.assertEqual(result["total"]["socket_written_bytes"], 150)
        self.assertEqual(result["total"]["protocol_enqueued_bytes"], 100)
        self.assertEqual(result["total"]["auth_and_framing_written_bytes"], 30)
        self.assertEqual(result["total"]["workload_index_enqueued_bytes"], 80)
        self.assertEqual(result["total"]["beyond_workload_enqueued_bytes"], 20)

    def test_outstanding_send_invalidates_measurement(self):
        snapshots = transport_fixture()
        snapshots[0]["transport"]["peers"]["1"]["outstanding_frames"] = 1
        with self.assertRaisesRegex(AssertionError, "unacknowledged"):
            runner.aggregate_traffic(snapshots, None)

    def test_unread_stream_byte_invalidates_measurement(self):
        snapshots = transport_fixture()
        snapshots[0]["transport"]["data_bytes_read"] -= 1
        with self.assertRaisesRegex(AssertionError, "do not balance"):
            runner.aggregate_traffic(snapshots, None)

    def test_silent_replica_cannot_enqueue_protocol_bytes(self):
        with self.assertRaisesRegex(AssertionError, "silent replica"):
            runner.aggregate_traffic(transport_fixture(), 0)


if __name__ == "__main__":
    unittest.main()
