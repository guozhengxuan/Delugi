import copy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import run_campaign as campaign


def config():
    return {"schema": 1, "purpose": "development", "spec_snapshot": "provenance/spec-2026-10-19.json",
            "protocols": ["delugi", "mysticeti"], "nodes": [4], "repeats": 2,
            "measurement_seconds": 3, "warmup_seconds": 1, "drain_seconds": 3,
            "deadline_ms": 1000, "useful_transaction_bytes": 472, "healthy_rates": [1200],
            "common_below_capacity_rate": 1200, "bounds_ms": [50, 100], "added_delays_ms": [0, 10]}


def accepted_result():
    from cohort_metrics import summarize_cohorts, ENDPOINT
    from cohort_metrics_test import fixture
    ledgers=fixture()
    cohort=summarize_cohorts(ledgers)
    return {"status":"passed","protocol_bound_ms":100,"binary_sha256":"a"*64,
            "source_files":[{"path":"src/lib.rs","sha256":"b"*64}],
            "agreement":{"replicas_agree_on_common_prefix":True},
            "comparison":{"protocol":"delugi","replicas":4,"offered_tx_s":1200,
                "useful_transaction_bytes":472,"warmup_seconds":1,"ingress_batch_ms":10,
                "measurement_seconds":3,"unique_completion_tps":1/3,"completion_count":1,
                "mean_latency_ms":3,"latency_endpoint":"exact origin-local output",
                "traffic_boundary":"successful_replica_tcp_stream_writes",
                "replica_tcp_written_bytes":9000,"replica_tcp_read_bytes":9000,
                "replica_tcp_written_bytes_per_second":3000,"generated_count":1,"generation_tps":1/3,
                "endpoint_contract":ENDPOINT,"accounting_schema":1,"cohort":cohort}}


def healthy_case(delay=0):
    return {"family":"healthy","protocol":"delugi","nodes":4,"rate":1200,
            "added_delay_ms":delay,"bound_ms":100,"fault":"none","repeat":0}


def formal_config():
    result=config()
    result.update(purpose="formal",protocols=["delugi","mysticeti","autobahn","shoal"],
                  repeats=3,measurement_seconds=120,added_delays_ms=[0],bounds_ms=[100])
    return result


class ReviewedCampaign(unittest.TestCase):
    def test_shoal_only_routes_runtime_accepted_local_committee_fault_pairs(self):
        cfg = config()
        for nodes, faults in ((4, ("none", "process_pause", "payload_omission")), (7, ("none",))):
            for fault in faults:
                case = dict(healthy_case(), protocol="shoal", nodes=nodes, fault=fault)
                command = campaign.adapter_command(case, cfg, Path("/tmp/shoal-trial"))
                self.assertTrue(command[1].endswith("scripts/baselines/shoal.py"))
                self.assertEqual(command[command.index("--nodes") + 1], str(nodes))
                self.assertNotIn("--execute", command)
        for change, reason in (({"nodes": 31}, "committee size"),
                               ({"nodes": 7, "fault": "payload_omission"}, "committee/fault"),
                               ({"nodes": 7, "fault": "process_pause"}, "committee/fault"),
                               ({"added_delay_ms": 10}, "added-delay"),
                               ({"fault": "all_message_omission"}, "implemented native adapter")):
            case = dict(healthy_case(), protocol="shoal") | change
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, reason):
                campaign.adapter_command(case, cfg, Path("/tmp/shoal-trial"))

    def test_native_tuning_grid_expands_healthy_trials_and_command_flags(self):
        cfg=config();cfg.update(families=["healthy"],native_tuning_grid={"delugi":[
            {"ingress_batch_ms":5,"max_batch_transactions":64},
            {"ingress_batch_ms":10,"max_batch_transactions":256}]})
        cases=list(campaign.trial_plan(cfg))
        delugi=[case for case in cases if case["protocol"]=="delugi"]
        self.assertEqual(len(delugi),16)
        self.assertEqual(len({case["tuning_id"] for case in delugi}),2)
        for case in delugi:
            cmd=campaign.adapter_command(case,cfg,Path("/tmp/trial"))
            self.assertEqual(int(cmd[cmd.index("--ingress-batch-ms")+1]),case["tuning"]["ingress_batch_ms"])
            self.assertEqual(int(cmd[cmd.index("--max-batch-transactions")+1]),case["tuning"]["max_batch_transactions"])

    def test_three_families_and_all_healthy_repetitions_before_faults(self):
        cases = list(campaign.trial_plan(config()))
        self.assertEqual({c["family"] for c in cases}, set(campaign.FAMILIES))
        first_fault_family = next(i for i, c in enumerate(cases) if c["family"] != "healthy")
        self.assertTrue(all(c["family"] != "healthy" for c in cases[first_fault_family:]))
        self.assertEqual({c["repeat"] for c in cases[:first_fault_family]}, {0, 1})
        self.assertEqual({(c["added_delay_ms"], c["bound_ms"]) for c in cases}, {(0, 50), (0, 100), (10, 50), (10, 100)})

    def test_native_unavailable_fault_is_retained_as_explicit_error(self):
        case = next(c for c in campaign.trial_plan(config()) if c["fault"] == "tcp_packet_loss")
        with self.assertRaisesRegex(ValueError, "cannot substitute"):
            campaign.adapter_command(case, config(), Path("/tmp/trial"))

    def test_distinct_payload_and_all_message_omission_commands(self):
        cases = [c for c in campaign.trial_plan(config()) if c["protocol"] == "delugi"]
        for fault, scope in (("payload_omission", "payload"), ("all_message_omission", "all")):
            case = next(c for c in cases if c["fault"] == fault)
            command = campaign.adapter_command(case, config(), Path("/tmp/trial"))
            self.assertEqual(command[command.index("--fault-scope") + 1], scope)
            self.assertIn("--spec-snapshot", command)

    def test_rational_arrivals_preserve_common_load_under_faults(self):
        case = next(c for c in campaign.trial_plan(config()) if c["fault"] == "process_pause" and c["protocol"] == "delugi")
        case["rate"] = 1000
        command = campaign.adapter_command(case, config(), Path("/tmp/trial"))
        self.assertEqual(command[command.index("--rate") + 1], "1000")

    def test_payload_case_requires_observed_omission(self):
        case = {"protocol": "delugi", "fault": "payload_omission"}
        with self.assertRaisesRegex(ValueError, "no-op fault smoke"):
            campaign.validate_fault_effect(case, {"trial": {"fault_accounting": {"0": {}}, "fault": {}}})
        observed = campaign.validate_fault_effect(case, {"trial": {"fault_accounting": {"0": {"BATCH": {"messages": 2}}}, "fault": {"scope": "payload"}}})
        self.assertEqual(observed["omitted_messages"], 2)

    def test_empty_or_duplicate_load_grid_cannot_pass_vacuously(self):
        for rates in ([],[1200,1200]):
            data=config();data["healthy_rates"]=rates
            with self.assertRaises(ValueError):campaign.validate_config(data)

    def test_short_pilot_cannot_claim_formal_capacity(self):
        data = config()
        data["purpose"] = "formal"
        with self.assertRaises(ValueError):
            campaign.validate_config(data)
        data["protocols"] += ["autobahn", "shoal"]
        with self.assertRaisesRegex(ValueError, "multi-minute"):
            campaign.validate_config(data)

    def test_formal_inventory_contains_required_recovery_and_secondary_load_cells(self):
        cfg=formal_config();cases=list(campaign.trial_plan(cfg))
        for family,scenarios in campaign.REVIEWED_SCENARIOS.items():
            for protocol in cfg["protocols"]:
                selected=[c for c in cases if c["family"]==family and c["protocol"]==protocol]
                for name,_,_ in scenarios:
                    rows=[c for c in selected if c["scenario"]==name]
                    self.assertEqual({c["load_policy"]["kind"] for c in rows},{"common_offered_load","matched_utilization"})
                    self.assertEqual({c["repeat"] for c in rows},{0,1,2})
                    self.assertTrue(all(c["execution_requirement"] for c in rows))
                    for case in rows:
                        if case["load_policy"]["kind"]=="matched_utilization":self.assertIsNone(case["rate"])
                        with self.assertRaisesRegex(ValueError,"Unsupported"):
                            campaign.adapter_command(case,cfg,Path("/tmp/trial"))
        burst=next(c for c in cases if c.get("scenario")=="fault_bursts")
        self.assertEqual(len(burst["fault_schedule"]),3)
        sustained=next(c for c in cases if c.get("scenario")=="sustained_attack")
        withdrawn=next(c for c in cases if c.get("scenario")=="withdrawn_attack")
        self.assertNotIn("duration_seconds",sustained["fault_schedule"][0])
        self.assertIn("duration_seconds",withdrawn["fault_schedule"][0])
        silent=next(c for c in cases if c.get("scenario")=="silent_leader_then_honest")
        self.assertIn("native leadership",silent["fault_schedule"][0]["trigger"])

    def test_development_matrix_stays_compatible_and_formal_omissions_fail(self):
        self.assertFalse(any("scenario" in c for c in campaign.trial_plan(config())))
        for change in ({"include_reviewed_scenarios":False},{"matched_utilizations":[]},
                       {"matched_utilizations":[1]},{"burst_count":1},{"burst_gap_seconds":200}):
            cfg=formal_config();cfg.update(change)
            with self.assertRaises(ValueError):list(campaign.trial_plan(cfg))

    def test_fixed_fault_budget_bounds_union_across_bursts_and_cases(self):
        cfg=formal_config();cfg.update(nodes=[4,7,31],fixed_faulty_replicas={"4":[0],"7":[0,1],"31":list(range(10))})
        for case in campaign.trial_plan(cfg):
            campaign.validate_case_fault_budget(case,cfg)
            self.assertLessEqual(len(case["faulty_replicas"]),(case["nodes"]-1)//3)
        burst=next(c for c in campaign.trial_plan(cfg) if c.get("scenario")=="fault_bursts" and c["nodes"]==7)
        burst["fault_schedule"][1]["identities"]=[2]
        with self.assertRaisesRegex(ValueError,"outside the fixed"):
            campaign.validate_case_fault_budget(burst,cfg)
        for ids in ([0,1,2],[0,0],[0,7],[0,True]):
            bad=copy.deepcopy(cfg);bad["fixed_faulty_replicas"]["7"]=ids
            with self.assertRaisesRegex(ValueError,"<= f"):campaign.validate_config(bad)

    def test_plan_only_retains_unimplemented_formal_cases_as_incomplete(self):
        cfg=formal_config()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/"config.json";source.write_text(json.dumps(cfg));output=root/"plan"
            with mock.patch.object(sys,"argv",["campaign","--config",str(source),"--output",str(output),"--plan-only"]), \
                 mock.patch.object(campaign,"archive_spec",return_value={}), \
                 mock.patch.object(campaign,"verify_spec_unchanged"),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(campaign.main(),1)
            result=json.loads((output/"manifest.json").read_text())
            self.assertEqual(len(result["trials"]),len(list(campaign.trial_plan(cfg))))
            required=[row for row in result["trials"] if row["case"].get("execution_requirement")]
            self.assertTrue(required)
            self.assertTrue(all(row["status"]=="incomplete" and row["reason"].startswith("Unsupported") for row in required))
            self.assertTrue(all("command" not in row for row in required))


class CampaignResultGates(unittest.TestCase):
    def test_local_shoal_requires_complete_readiness_cleanup_and_zero_swap(self):
        value = {"settings": {"nodes": 4}, "epoch_us": 30,
                 "startup_readiness": {"started_us": 10, "completed_us": 20, "ready": True,
                                       "api_replicas": list(range(4)), "bootstrapped": list(range(4)),
                                       "counter_replicas": list(range(4))},
                 "swap_before": {"enabled": False}, "swap_after": {"enabled": False},
                 "owned_process_cleanup": {"all_reaped": True,
                     "processes": [{"pid": 100 + i, "returncode": -15} for i in range(4)]}}
        campaign.validate_local_native_cleanup("shoal", value)
        mutations = (
            lambda d: d["owned_process_cleanup"].update(all_reaped=False),
            lambda d: d["owned_process_cleanup"]["processes"].pop(),
            lambda d: d["owned_process_cleanup"]["processes"][0].update(returncode=-9),
            lambda d: d["owned_process_cleanup"]["processes"][0].update(pid=101),
            lambda d: d["swap_before"].update(enabled=True),
            lambda d: d.pop("swap_after"),
            lambda d: d["startup_readiness"]["bootstrapped"].pop(),
            lambda d: d["startup_readiness"].update(counter_replicas=[0, 1, 2, True]),
            lambda d: d.update(epoch_us=20),
        )
        for mutation in mutations:
            bad = copy.deepcopy(value); mutation(bad)
            with self.subTest(value=bad), self.assertRaises(ValueError):
                campaign.validate_local_native_cleanup("shoal", bad)

    def test_incomplete_native_fidelity_remains_visible_and_blocks_formal_acceptance(self):
        data=accepted_result();data["agreement"]["native_order_fidelity"]={"status":"incomplete","reason":"filtered native tail"}
        result=campaign.validate_result(healthy_case(),config(),data)
        self.assertEqual(result["comparison"]["native_order_fidelity"]["status"],"incomplete")
        cfg={**config(),"purpose":"formal"}
        with self.assertRaisesRegex(ValueError,"output-order fidelity"):
            campaign.validate_result(healthy_case(),cfg,data)
        data["agreement"].pop("native_order_fidelity");data["comparison_eligible"]=False
        with self.assertRaisesRegex(ValueError,"explicitly lacks"):
            campaign.validate_result(healthy_case(),cfg,data)

    def test_zero_delay_checks_bound_and_rejects_unexpected_shaping(self):
        data=accepted_result()
        self.assertFalse(campaign.validate_result(healthy_case(),config(),data)["timing"]["kernel_shaping"])
        data["protocol_bound_ms"]=200
        with self.assertRaisesRegex(ValueError,"configured bound"):campaign.validate_result(healthy_case(),config(),data)
        data["protocol_bound_ms"]=100;data["network_shaping"]={"backend":"unexpected"}
        with self.assertRaisesRegex(ValueError,"unexpectedly"):campaign.validate_result(healthy_case(),config(),data)

    def test_delay_reuses_native_shape_helper_and_cleanup_checks(self):
        data=accepted_result();case=healthy_case(10)
        calibration={"status":"passed","requested_one_way_delay_ms":10,"shaping":{"helper_sha256":"helper"}}
        calibration.update(baseline_rtt_ms=[.1]*20, shaped_rtt_ms=[20.1]*30,
                           after_cleanup_rtt_ms=[.1]*20, control_baseline_rtt_ms=[.1]*20,
                           control_rtt_ms=[.1]*20, control_after_cleanup_rtt_ms=[.1]*20)
        data["network_shaping"]={"one_way_delay_ms":10,"protocol":"delugi","helper_sha256":"helper","backend":"macOS_dummynet"}
        data["network_shaping_cleanup"]={"active":data["network_shaping"],"pipes":{}}
        self.assertEqual(campaign.validate_result(case,config(),data,calibration=calibration,after_calibration=calibration)["timing"]["bound_ms"],100)
        for mutate in (lambda d:d["network_shaping"].update(one_way_delay_ms=20),
                       lambda d:d["network_shaping"].update(helper_sha256="different"),
                       lambda d:d.update(network_shaping_cleanup=None),
                       lambda d:d.update(network_shaping_cleanup_error="pipe survived")):
            bad=copy.deepcopy(data);mutate(bad)
            with self.assertRaises(ValueError):campaign.validate_result(case,config(),bad,calibration=calibration,after_calibration=calibration)
        with self.assertRaisesRegex(ValueError,"calibration"):campaign.validate_result(case,config(),data)
        with self.assertRaisesRegex(ValueError,"post-trial"):
            campaign.validate_result(case,config(),data,calibration=calibration,after_calibration={**calibration,"status":"failed"})
        # A declared success cannot promote RTTs rejected by the standalone
        # calibration or hide delay that survives cleanup.
        for changes in ({"shaped_rtt_ms": [29.474141]*30},
                        {"after_cleanup_rtt_ms": [3.1]*20},
                        {"control_rtt_ms": [3.1]*20}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError,"raw RTT calibration"):
                campaign.validate_result(case,config(),data,calibration=calibration,
                                         after_calibration={**calibration, **changes})

    def test_changed_artifact_and_malformed_results_cannot_pass(self):
        data=accepted_result();case=healthy_case()
        identity=campaign.validate_result(case,config(),data)["artifact_identity"]
        data["binary_sha256"]="c"*64
        with self.assertRaisesRegex(ValueError,"changed between"):campaign.validate_result(case,config(),data,identities={"delugi":identity})
        for mutation in (lambda d:d.pop("binary_sha256"),lambda d:d.update(comparison=None),
                         lambda d:d["comparison"]["cohort"].update(admission_to_output=None),
                         lambda d:d["comparison"]["cohort"].update(unfinished=5)):
            bad=accepted_result();mutation(bad)
            with self.assertRaises(ValueError):campaign.validate_result(case,config(),bad)

    def test_helper_dependency_drift_is_part_of_artifact_identity(self):
        data=accepted_result();data["runner_dependencies"]={"cohort_metrics.py":"f"*64}
        identity=campaign.validate_result(healthy_case(),config(),data)["artifact_identity"]
        data["runner_dependencies"]={"cohort_metrics.py":"e"*64}
        with self.assertRaisesRegex(ValueError,"changed between"):
            campaign.validate_result(healthy_case(),config(),data,identities={"delugi":identity})

    def test_backlog_comes_from_exact_window_and_contradictions_fail(self):
        data=accepted_result()
        result=campaign.validate_result(healthy_case(),config(),data)["comparison"]
        self.assertEqual(result["pending_at_start"],data["comparison"]["cohort"]["window"]["pending_at_start"])
        data["comparison"]["pending_at_end"]=999
        with self.assertRaisesRegex(ValueError,"contradicts"):campaign.validate_result(healthy_case(),config(),data)

    def test_capacity_evidence_requires_repeated_same_rate_and_nested_backlog(self):
        # Legacy development acceptance remains compatible. Formal frontiers
        # now require subwindow evidence (covered in campaign_frontier_test).
        cfg=config();cfg.update(protocols=["delugi"],repeats=3)
        fault=healthy_case();fault.update(family="recovery",fault="process_pause")
        def trial(rate,repeat):
            case=healthy_case();case.update(rate=rate,repeat=repeat)
            row=accepted_result()["comparison"]
            row.update(unique_completion_tps=rate)
            row["cohort"]["window"].update(pending_at_start=0,pending_at_end=0)
            return {"status":"passed","case":case,"comparison":row,"label":f"{rate}-{repeat}"}
        rows=[trial(1200,i) for i in range(3)]
        self.assertEqual(len(campaign.below_capacity_evidence(rows,fault,cfg)),3)
        rows[0]["comparison"]["pending_at_end"]=2
        with self.assertRaisesRegex(ValueError,"contradicts"):campaign.below_capacity_evidence(rows,fault,cfg)

    def test_linux_ring_setup_cleanup_and_remote_artifact_population(self):
        case=healthy_case(10);data=accepted_result();ids=range(4)
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        known=Path(temporary.name)/"known";known.write_text("fixture only; never contacted")
        budget={"enforcement":"dedicated_host","cpus":[0,1],"memory_bytes":2**30,"swap_bytes":0}
        inventory={"inventory_source_sha256":"e"*64,"netem":{"delay_ms":10,"loss_percent":0},"hosts":[{
            "replica":i,"binary":{"sha256":"c"*64},"ssh":f"user@host{i}","advertised":f"10.0.0.{i+1}:9000",
            "control_port":9001,"identity_file":str(known),"known_hosts_file":str(known),"budget":budget} for i in ids]}
        samples=lambda delta:[{"source":i,"destination":(i+1)%4,"median_rtt_ms":1+delta,"samples_ms":[1+delta]*20} for i in ids]
        data["network_shaping"]={"backend":"Linux_tc_netem_scoped_ingress","settings":inventory["netem"],
            "configuration":{str(i):{"active_objects_complete":True,"physical_qdisc_configuration_unchanged":True} for i in ids},
            "before":samples(0),"configured":samples(20),"after_cleanup":samples(0)}
        data["network_shaping_cleanup"]={str(i):{"phase":"cleared","physical_qdisc_configuration_unchanged":True} for i in ids}
        summary={"nonce":"owned","budget":budget,"exit_code":0,"native_exit_code":0,"timed_out":False,
            "owned_group_cleanup":{"group_empty":True},"effective_budget":{"cpus":[0,1],"memory_limit_bytes":2**30,
                "memory_enforcement":"physical_host","cpu_enforcement":"inherited_process_affinity",
                "swap_policy_verified":True,"swap_enforcement":"observed_host_swap","swap_limit_bytes":0,"host_swap_bytes":0,"host_swap_bytes_at_end":0}}
        data["trial"]={"deployment":{"nonce":"owned","inventory":copy.deepcopy(inventory),
            "machines":{str(i):{"binary_sha256":"c"*64,"resource_summary":summary} for i in ids}}}
        self.assertTrue(campaign.validate_result(case,config(),data,inventory=inventory)["timing"]["cleanup_verified"])
        for settings in ({"delay_ms":11,"loss_percent":0},{"delay_ms":10,"loss_percent":1}):
            bad_inventory={**inventory,"netem":settings}
            bad=copy.deepcopy(data);bad["network_shaping"]["settings"]=settings
            with self.assertRaises(ValueError):campaign.validate_result(case,config(),bad,inventory=bad_inventory)
        for mutate in (lambda d:d["network_shaping"]["configuration"].pop("3"),
                       lambda d:d["network_shaping_cleanup"]["3"].update(phase="active"),
                       lambda d:d["network_shaping"]["configured"][0].update(median_rtt_ms=1),
                       lambda d:d["network_shaping"]["after_cleanup"][0].update(median_rtt_ms=21),
                       lambda d:d["trial"]["deployment"]["machines"]["0"].update(binary_sha256="d"*64),
                       lambda d:d["trial"]["deployment"]["inventory"]["hosts"][0].update(ssh="user@substituted"),
                       lambda d:d["trial"]["deployment"]["machines"]["0"]["resource_summary"]["effective_budget"].update(cpus=[2,3])):
            bad=copy.deepcopy(data);mutate(bad)
            with self.assertRaises(ValueError):campaign.validate_result(case,config(),bad,inventory=inventory)

    def test_local_formal_result_cannot_replace_resource_enforcement_with_machine_metadata(self):
        cfg=config();cfg["purpose"]="formal"
        with self.assertRaisesRegex(ValueError,"whole-worker resource enforcement"):
            campaign.validate_result(healthy_case(),cfg,accepted_result())


if __name__ == "__main__":
    unittest.main()
