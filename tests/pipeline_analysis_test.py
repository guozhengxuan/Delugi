"""Measurement-boundary regressions for the saved-run pipeline audit."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import analyze_pipeline as audit


class MeasurementBoundaries(unittest.TestCase):
    def test_cadence_ignores_unrelated_clock_offsets_and_requires_both_window_endpoints(self):
        rows = [dict(replica=0, round=1, proposal_us=1000000, in_measurement_window=True),
                dict(replica=0, round=5, proposal_us=1040000, in_measurement_window=True),
                dict(replica=1, round=2, proposal_us=5000000, in_measurement_window=True),
                dict(replica=1, round=6, proposal_us=5044000, in_measurement_window=True)]
        baseline = audit.normalized_cadence(rows)
        self.assertEqual([row["normalized_ms_per_round"] for row in baseline], [10, 11])
        shifted = copy.deepcopy(rows)
        for row in shifted:
            row["proposal_us"] += 900000000 if row["replica"] else 37000000
        self.assertEqual(audit.normalized_cadence(shifted), baseline)
        shifted[-1]["in_measurement_window"] = False
        self.assertEqual(len(audit.normalized_cadence(shifted)), 1)

    def test_final_cohort_is_not_the_window_completion_count(self):
        result = {"comparison": {"completion_count": 998}, "drain_complete": True,
                  "agreement": {"all_correct_overlap_prefixes_verified": True},
                  "cohort": {"scheduled": 1000, "completed": 1000, "unfinished": 0,
                             "all_correct_collection": {"completed": 1000}}}
        decomposition = {"covered": 1000, "excluded": {}}
        self.assertTrue(all(audit.completion_checks(result, decomposition).values()))
        result["comparison"]["completion_count"] = 1000
        result["cohort"].update(completed=999, unfinished=1)
        self.assertFalse(audit.completion_checks(result, decomposition)["intended_cohort_complete"])

    def test_a_different_direct_commit_digest_cannot_be_joined_to_the_proposal(self):
        events = [dict(event="ordering_outbox", round=1, at_us=10,
                       detail={"kind": "PROPOSE", "signer": 0}),
                  dict(event="proposal_validated", round=1, at_us=11, detail={"digest": [1] * 32}),
                  dict(event="direct_commit", round=1, at_us=30, detail={"digest": [2] * 32})]
        with self.assertRaisesRegex(ValueError, "different digests"):
            audit.leader_rows(0, {"events": events}, {"window_start_us": 0, "window_end_us": 100})

    def test_duplicate_signers_and_unjustified_preparation_are_rejected(self):
        config = {"addresses": ["loopback"] * 4, "report_schedule": "pipeline"}
        progress = dict(event="progress_quorum", round=1, detail={"admit": 2, "signers": [0, 1, 1]})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit.guard_evidence(0, {"events": [progress]}, config)
        report = dict(event="dissemination_outbox", round=9,
                      detail={"kind": "REPORT", "signer": 0, "admitted": 9, "schedule": "pipeline",
                              "local_report_horizon": 4, "closed_signers": [1], "exact_history_ready": False})
        with self.assertRaisesRegex(ValueError, "no justified"):
            audit.guard_evidence(0, {"events": [report]}, config)
        report["detail"]["closed_signers"] = [1, 2]
        counts = audit.guard_evidence(0, {"events": [report]}, config)
        self.assertEqual(counts["pipeline_reports_with_satisfied_guard"], 1)
        self.assertEqual(counts["report_branch_true_f_plus_one_closed"], 1)


if __name__ == "__main__":
    unittest.main()
