import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import campaign_frontier as frontier
import campaign_resources as resources
import run_campaign as campaign


def configuration():
    return {"purpose": "formal", "repeats": 3, "deadline_ms": 1000,
            "measurement_seconds": 120, "frontier": {"tail_target_ms": 100},
            "native_tuning_grid": {"delugi": [{"ingress_batch_ms": 5}, {"ingress_batch_ms": 10}]}}


def trial(rate=1000, repeat=0, tuning=0):
    option = frontier.tuning_options(configuration(), "delugi")[tuning]
    population = rate * 120
    intervals = [{"interval": i, "scheduled": population//10, "admitted": population//10,
                  "completed": population//10, "rejected": 0} for i in range(10)]
    samples = [{"boundary": i, "pending_admitted": 0, "scheduled_not_output": 0} for i in range(11)]
    quantile = {"p99": {"value_ms": 30, "status": "observed"}}
    cohort = {"scheduled": population, "unfinished": 0, "rejected": 0,
              "origins": [{"origin": i} for i in range(4)],
              "admission_to_output": copy.deepcopy(quantile), "scheduled_to_output": copy.deepcopy(quantile),
              "window": {"pending_at_start": 0, "pending_at_end": 0, "completion_count": population,
                         "admission_count": population,
                         "stability": {"schema": 1, "subwindows": 10, "samples": samples,
                                       "intervals": intervals, "origin_duration_us": {str(i): 120000000 for i in range(4)}}}}
    budget = {"enforcement":"dedicated_host","cpus":[0,1,2,3],"memory_bytes":16*1024**3,"swap_bytes":0}
    effective = {"cpus":budget["cpus"],"memory_limit_bytes":16*1024**3,"memory_enforcement":"physical_host",
                 "cpu_enforcement":"inherited_process_affinity","swap_policy_verified":True,
                 "swap_limit_bytes":0,"swap_enforcement":"observed_host_swap","host_swap_bytes":0,"host_swap_bytes_at_end":0}
    contract = {"schema":resources.CONTRACT_SCHEMA,"validation": resources.VERIFIED, "protocol": "delugi", "nodes": 4,
                "inventory_source_sha256":"a"*64,
                "placement":[{"replica":i,"ssh":f"user@host{i}","advertised":f"10.0.0.{i+1}:9000","control_port":9001,
                    "identity_file":"/fixture/key","known_hosts_file":"/fixture/known","known_hosts_sha256":"b"*64,
                    "python_executable":"/usr/bin/python3","budget":copy.deepcopy(budget)} for i in range(4)],
                "effective_budgets":{str(i):copy.deepcopy(effective) for i in range(4)},
                "matched_budget_equivalence":[resources.budget_equivalence(budget,effective) for _ in range(4)]}
    digest = hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return {"label": f"{rate}-{repeat}-{tuning}", "status": "passed",
            "resource_contract": contract, "resource_contract_sha256": digest,
            "case": {"family": "healthy", "protocol": "delugi", "nodes": 4, "rate": rate,
                     "repeat": repeat, "fault": "none", "added_delay_ms": 0, "bound_ms": 100,
                     "tuning_id": option["id"], "tuning": option["parameters"]},
            "comparison": {"unique_completion_tps": rate, "cohort": cohort}}


class FrontierAcceptance(unittest.TestCase):
    def test_formal_resource_identity_is_required_and_cannot_drift_between_rates(self):
        rows=[trial(1000,i) for i in range(3)]+[trial(2000,i) for i in range(3)]
        for key in ("resource_contract","resource_contract_sha256"):
            bad=copy.deepcopy(rows);bad[0].pop(key)
            with self.assertRaisesRegex(ValueError,"resource contract"):
                frontier.select_frontier(bad,rows[0]["case"],configuration())
        bad=copy.deepcopy(rows);contract=bad[-1]["resource_contract"]
        contract["placement"][0]["ssh"]="user@replacement-host"
        bad[-1]["resource_contract_sha256"]=hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        with self.assertRaisesRegex(ValueError,"changed across"):
            frontier.select_frontier(bad,rows[0]["case"],configuration())
        bad=copy.deepcopy(rows);bad[0]["resource_contract"]["validation"]="machine_metadata_only"
        with self.assertRaisesRegex(ValueError,"enforced whole-worker"):
            frontier.select_frontier(bad,rows[0]["case"],configuration())

    def test_hash_valid_old_verified_label_is_diagnostic_not_formal_evidence(self):
        rows=[trial(1000,i) for i in range(3)]
        old={"validation":resources.VERIFIED,"protocol":"delugi","nodes":4,
             "host_budget":{"cpus":[0,1,2,3],"memory_bytes":16*1024**3}}
        for row in rows:
            row["resource_contract"]=copy.deepcopy(old)
            row["resource_contract_sha256"]=resources.canonical_hash(old)
        with self.assertRaisesRegex(ValueError,"legacy contracts are diagnostic"):
            frontier.select_frontier(rows,rows[0]["case"],configuration())
        # Legacy source records stay readable for diagnostic replay without
        # inventing missing resource or swap evidence.
        development=dict(configuration(),purpose="development")
        replay=frontier.select_frontier(rows,rows[0]["case"],development)
        self.assertEqual(replay["selected"]["rate"],1000)
        self.assertEqual(replay["resource_validation"],"legacy_or_unverified_diagnostic")
        for row in rows:
            row["resource_contract"]["schema"]=resources.CONTRACT_SCHEMA
            row["resource_contract_sha256"]=resources.canonical_hash(row["resource_contract"])
        with self.assertRaisesRegex(ValueError,"resource contract"):
            frontier.select_frontier(rows,rows[0]["case"],configuration())

    def test_selects_same_tuning_and_load_only_after_every_repeat(self):
        rows = [trial(1000, i, 0) for i in range(3)] + [trial(2000, i, 1) for i in range(3)]
        selected = frontier.select_frontier(rows, rows[0]["case"], configuration())
        self.assertEqual(selected["selected"]["rate"], 2000)
        rows[-1]["status"] = "incomplete"
        self.assertEqual(frontier.select_frontier(rows, rows[0]["case"], configuration())["selected"]["rate"], 1000)
        for incomplete in ([trial(1000, 0), trial(2000, 1), trial(3000, 2)],
                           [trial(1000, 0), trial(1000, 1), trial(1000, 2, 1)],
                           [trial(1000, i) for i in (0, 1, 1, 2)]):
            with self.assertRaisesRegex(ValueError, "lacks a repeated"):
                frontier.select_frontier(incomplete, rows[0]["case"], configuration())

    def test_recovery_by_end_cannot_hide_overload_between_boundaries(self):
        row = trial(); cohort = row["comparison"]["cohort"]
        stability = cohort["window"]["stability"]
        stability["intervals"][3]["completed"] -= 500
        stability["intervals"][4]["completed"] += 500
        stability["samples"][4].update(pending_admitted=500, scheduled_not_output=500)
        check = frontier.stability_evidence(row["comparison"], row["case"], configuration())
        self.assertFalse(check["eligible"])
        self.assertIn("pending_admitted exceeds the allowed subwindow excursion", check["reasons"])

    def test_admission_throttling_and_censored_latency_cannot_claim_capacity(self):
        for mutate in (lambda c: c.update(unfinished=1), lambda c: c.update(rejected=1),
                       lambda c: c["scheduled_to_output"]["p99"].update(value_ms=101),
                       lambda c: c["admission_to_output"]["p99"].update(value_ms=None, status="censored")):
            row = trial(); mutate(row["comparison"]["cohort"])
            self.assertFalse(frontier.stability_evidence(row["comparison"], row["case"], configuration())["eligible"])
        row = trial(); data = row["comparison"]["cohort"]["window"]["stability"]
        data["intervals"][2]["admitted"] -= 500; data["intervals"][2]["completed"] -= 500
        data["intervals"][3]["admitted"] += 500; data["intervals"][3]["completed"] += 500
        data["samples"][3]["scheduled_not_output"] = 500
        check = frontier.stability_evidence(row["comparison"], row["case"], configuration())
        self.assertFalse(check["eligible"])
        self.assertEqual(check["backlog"]["pending_admitted"]["peak_excursion"], 0)

    def test_malformed_or_inconsistent_subwindow_evidence_rejected(self):
        for mutate in (lambda w: w.pop("stability"),
                       lambda w: w["stability"]["samples"].pop(),
                       lambda w: w["stability"]["origin_duration_us"].update({"0": 1}),
                       lambda w: w["stability"]["intervals"][3].update(completed=0),
                       lambda w: w["stability"]["samples"][3].update(pending_admitted=True),
                       lambda w: w["stability"]["samples"][3].update(pending_admitted=1)):
            row = trial(); mutate(row["comparison"]["cohort"]["window"])
            with self.assertRaises(ValueError): frontier.stability_evidence(row["comparison"], row["case"], configuration())

    def test_matched_utilization_binds_tuning_without_erasing_unsupported_fault(self):
        rows = [trial(2000, i, 1) for i in range(3)]
        case = {**rows[0]["case"], "family": "recovery", "rate": None,
                "load_policy": {"kind": "matched_utilization", "fraction": .4},
                "execution_requirement": "Unsupported matched-utilization cell",
                "scenario_execution_requirement": "Unsupported reviewed scenario: native leader witness"}
        resolved, selected = frontier.resolve_case(rows, case, configuration())
        self.assertEqual(resolved["rate"], 800)
        self.assertEqual(resolved["tuning"], {"ingress_batch_ms": 10})
        self.assertIn("native leader witness", resolved["execution_requirement"])
        case["scenario_execution_requirement"] = None
        resolved, _ = frontier.resolve_case(rows, case, configuration())
        self.assertNotIn("execution_requirement", resolved)
        self.assertEqual(len(selected["selected"]["evidence"]), 3)

    def test_common_rate_must_be_strictly_below_all_accepted_frontiers(self):
        rows = [trial(1000, i) for i in range(3)]
        cfg = {**configuration(), "protocols": ["delugi"]}
        case = {**rows[0]["case"], "family": "recovery", "rate": 1000}
        with self.assertRaisesRegex(ValueError, "strictly below"):
            campaign.below_capacity_evidence(rows, case, cfg)
        case["rate"] = 900
        self.assertEqual(len(campaign.below_capacity_evidence(rows, case, cfg)), 3)

    def test_native_grid_rejects_duplicates_unknown_knobs_and_invalid_values(self):
        for grid in ([{}, {"ingress_batch_ms": 10}], [{"invented_certified_unit": 100}],
                     [{"ingress_batch_ms": True}], [], [{"batch_bytes": 5000}],
                     [{"ordering_mode": "canonical"}], [{"arrival_queue_capacity": 4096}]):
            cfg = configuration(); cfg["native_tuning_grid"]["delugi"] = grid
            with self.assertRaises(ValueError): frontier.tuning_options(cfg, "delugi")


if __name__ == "__main__":
    unittest.main()
