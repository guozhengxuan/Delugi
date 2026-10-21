import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deployment_prepare as prep
import native_campaign as adapter
import remote_native
import run_campaign as campaign
import remote_native_test as placement_fixture


class NativeCampaignContract(unittest.TestCase):
    def setUp(self):
        self.fixture = placement_fixture.NativePlacement(); self.fixture.setUp()
        self.root = self.fixture.root

    def tearDown(self): self.fixture.tearDown()

    def setup_case(self, protocol="mysticeti"):
        publication = self.fixture.publication(protocol)
        for host in publication["inventory"]["hosts"]: host["network_interface"] = "ens5"
        value = adapter.inventory(publication, protocol, 4, "a" * 64)
        value["netem"] = {"delay_ms": 10, "loss_percent": 0,
                          "application_interval": "setup through declared drain; before/configured/after RTT calibration retained"}
        selected = adapter.build_plan(value, {"rate": 4, "useful_bytes": 8, "warmup": 0, "duration": 1, "drain": 1,
                                             "network": {"delay_ms": 10, "loss_percent": 0}})
        reduced = remote_native.native.reduce({i: self.fixture.ledger(i) for i in range(4)}, selected["settings"])
        reduced["agreement"]["native_order_fidelity"] = {"status": "complete_observer_sequence"}
        reduced["agreement"]["replicas_agree_on_common_prefix"] = True
        raw = {**reduced, "status": "completed", "nonce": selected["nonce"], "hosts": {}, "dispatch": {"failures": {}},
               "cleanup": {str(i): {"state": "finished", "exit_code": 0} for i in range(4)}}
        for host in selected["hosts"]:
            i = str(host["replica"])
            epoch=100_000_000_000+int(i)*1_000_000_000_000
            if protocol == "autobahn":
                traffic = {"processes": [{"window_written_bytes": 50, "window_read_bytes": 60, "written_bytes": 70,"observed_us":2_000_000}] * 2}
            else:
                def sample(written, read, phase):
                    row = {"written_bytes": written, "read_bytes": read}
                    instant=epoch+phase*1_000_000_000
                    return {"values": {"benchmark_tcp_" + key: v for key, v in row.items()},
                        "request_started_monotonic_ns":instant,"midpoint_monotonic_ns":instant,"response_received_monotonic_ns":instant} if protocol == "mysticeti" else dict(row,observed_us=instant//1000)
                traffic = {"before": sample(10, 20,0), "after": sample(110, 140,1), "final": sample(140, 160,2)}
            raw["hosts"][i] = {"artifacts": {name: {"sha256": row["sha256"], "stamp_sha256": "b" * 64} for name, row in host["native_binaries"].items()},
                "python": sys.executable, "python_realpath": sys.executable, "python_version": [3, 11, 0], "python_sha256": "c" * 64,
                "result": {"status": "completed", "epoch_monotonic_ns":epoch,"traffic": traffic, "cost_scope": {"complete_setup_through_shutdown_cost": False}}}
            budget = host["budget"]
            resource = {"event": "deployment_resource_summary", "nonce": selected["nonce"], "budget": budget,
                "effective_budget": {"cpus": budget["cpus"], "cpu_enforcement": "inherited_process_affinity", "memory_enforcement": "physical_host", "memory_limit_bytes": 15 * 2**30,
                    "swap_policy_verified":True,"swap_enforcement":"observed_host_swap","swap_limit_bytes":0,"host_swap_bytes":0,"host_swap_bytes_at_end":0},
                "exit_code": 0, "native_exit_code": 0, "timed_out": False, "owned_group_cleanup": {"group_empty": True}}
            (self.root / f"supervisor-{i}.log").write_text(json.dumps(resource) + "\n")
        roles = 3 if protocol == "autobahn" else 1
        samples = [{"source": i, "destination": (i + 1) % 4, "protocol_role_index": role, "median_rtt_ms": 1, "samples_ms": [1]*20}
                   for role in range(roles) for i in range(4)]
        raw["network"] = {"backend": "Linux_tc_netem_scoped_ingress", "settings": selected["network"], "before": samples,
            "configured": [dict(row, median_rtt_ms=21, samples_ms=[21]*20) for row in samples], "after_cleanup": samples,
            "configuration": {str(i): {"active_objects_complete": True, "physical_qdisc_configuration_unchanged": True} for i in range(4)},
            "cleanup": {str(i): {"phase": "cleared", "physical_qdisc_configuration_unchanged": True} for i in range(4)}}
        return selected, raw, value

    def campaign_case(self, protocol="mysticeti"):
        case = {"protocol": protocol, "nodes": 4, "rate": 4, "bound_ms": 100, "added_delay_ms": 10, "fault": "none"}
        config = {"purpose": "development", "warmup_seconds": 0, "measurement_seconds": 1, "useful_transaction_bytes": 8}
        return case, config

    def test_all_native_protocols_normalize_through_common_contract_without_formal_eligibility(self):
        for protocol in adapter.PROTOCOLS:
            selected, raw, value = self.setup_case(protocol)
            data = adapter.normalize(selected, raw, value, self.root)
            case, config = self.campaign_case(protocol)
            accepted = campaign.validate_result(case, config, data, inventory=value)
            self.assertEqual(accepted["comparison"]["replica_tcp_written_bytes"], 400)
            self.assertEqual(accepted["comparison"]["completion_count"], 4)
            self.assertEqual(set(accepted["measured_remote_role_artifacts"]), {"0", "1", "2", "3"})
            self.assertIn("scripts/native_campaign.py", data["runner_dependencies"])
            self.assertFalse(data["comparison_eligible"])
            config["purpose"] = "formal"
            with self.assertRaisesRegex(ValueError, "formal comparison acceptance"):
                campaign.validate_result(case, config, data, inventory=value)

    def test_role_artifact_receipt_cleanup_and_resource_substitutions_fail(self):
        for change in ("binary", "receipt", "cleanup", "dispatch", "resource", "source", "nonce", "resource_nonce"):
            selected, raw, value = self.setup_case("autobahn")
            if change == "binary": raw["hosts"]["0"]["artifacts"]["benchmark_client"]["sha256"] = "d" * 64
            if change == "receipt": value["publication_receipts_sha256"] = "d" * 64
            if change == "cleanup": raw["cleanup"]["0"] = {"state": "owned_termination_requested"}
            if change == "dispatch": raw["dispatch"]["failures"]["0"] = "wrapper failure"
            if change == "resource":
                path = self.root / "supervisor-0.log"; row = json.loads(path.read_text()); row["effective_budget"]["cpus"] = [99]; path.write_text(json.dumps(row) + "\n")
            if change == "source": selected["campaign_adapter_sources"]["scripts/native_campaign.py"] = "e" * 64
            if change == "nonce": raw["nonce"] = "0" * 32
            if change == "resource_nonce":
                path = self.root / "supervisor-0.log"; row = json.loads(path.read_text()); row["nonce"] = "0" * 32; path.write_text(json.dumps(row) + "\n")
            with self.subTest(change=change), self.assertRaises(ValueError): adapter.normalize(selected, raw, value, self.root)

    def test_every_native_peer_role_needs_calibration_and_exact_published_role_identity(self):
        selected, raw, value = self.setup_case("autobahn")
        data = adapter.normalize(selected, raw, value, self.root); case, config = self.campaign_case("autobahn")
        broken = copy.deepcopy(data)
        broken["network_shaping"]["configured"] = broken["network_shaping"]["configured"][:4]
        with self.assertRaisesRegex(ValueError, "exact committee ring"):
            campaign.validate_result(case, config, broken, inventory=value)
        data["deployment"]["machines"]["0"]["artifacts"]["node"]["sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "role artifacts"):
            campaign.validate_result(case, config, data, inventory=value)

    def test_campaign_routes_native_publication_to_fixed_adapter_without_connecting(self):
        publication = self.fixture.publication("shoal")
        source = self.root / "publication.json"; prep.json_file(source, publication)
        case, config = self.campaign_case("shoal")
        config.update(remote_inventories={"shoal": {"4": str(source)}}, drain_seconds=1, deadline_ms=1000)
        with patch.object(remote_native.Connection, "command", side_effect=AssertionError("no SSH in planning")):
            value = campaign.case_inventory(case, config)
            path = self.root / "inventory.json"; prep.json_file(path, value)
            command = campaign.adapter_command(case, config, self.root / "result", path)
        self.assertTrue(command[1].endswith("scripts/native_campaign.py"))
        self.assertIn("--execute", command)
        self.assertEqual(value["publication_sha256"], prep.sha(source))
        unsupported = dict(case, fault="all_message_omission")
        with self.assertRaisesRegex(ValueError, "implemented native adapter"):
            campaign.adapter_command(unsupported, config, self.root / "result", path)

    def test_oversized_supervisor_log_and_regressed_traffic_fail(self):
        selected, raw, value = self.setup_case()
        raw["hosts"]["0"]["result"]["traffic"]["after"]["values"]["benchmark_tcp_written_bytes"] = 0
        with self.assertRaisesRegex(ValueError, "regressed"): adapter.normalize(selected, raw, value, self.root)
        path = self.root / "oversized.log"; path.write_bytes(b"x" * (1024**2 + 1))
        with self.assertRaisesRegex(ValueError, "oversized"): adapter.resource_summary(path, selected["hosts"][0]["budget"])

    def test_stale_or_delayed_cost_samples_and_omission_counts_fail(self):
        for protocol in ("mysticeti","shoal"):
            selected,raw,value=self.setup_case(protocol)
            sample=raw["hosts"]["0"]["result"]["traffic"]["after"]
            if protocol=="shoal":sample["observed_us"]-=100_000
            else:
                for key in ("request_started_monotonic_ns","response_received_monotonic_ns","midpoint_monotonic_ns"):sample[key]+=100_000_000
            with self.subTest(protocol=protocol),self.assertRaisesRegex(ValueError,"sample window differs"):
                adapter.normalize(selected,raw,value,self.root)
        selected,raw,value=self.setup_case("autobahn")
        raw["hosts"]["0"]["result"]["omission_observation"]={"messages_omitted":2,"serialized_bytes_omitted":100,"by_native_unit":{"WorkerBatch":1}}
        with self.assertRaisesRegex(ValueError,"omission units"):
            adapter.normalize(selected,raw,value,self.root)
        raw["hosts"]["0"]["result"]["omission_observation"]["by_native_unit"]["WorkerBatch"]=2
        raw["hosts"]["0"]["result"]["crypto_cpu"]={"scope":"fixture native CPU","whole_run":{}}
        result=adapter.normalize(selected,raw,value,self.root)
        self.assertEqual(result["omission_observation"]["by_native_unit"],{"WorkerBatch":2})
        self.assertEqual(result["crypto_cpu_by_host"]["0"]["scope"],"fixture native CPU")

    def test_autobahn_relative_observer_clock_is_bound_to_each_host_epoch(self):
        selected, raw, value = self.setup_case("autobahn")
        result = adapter.normalize(selected, raw, value, self.root)
        for i, host in raw["hosts"].items():
            sample = result["traffic_ledger"]["per_host"][i]["sample_window"]
            self.assertEqual(sample["counter_observed_elapsed_us"], [2_000_000] * 2)
            self.assertEqual(sample["counter_observed_monotonic_ns"],
                             [host["result"]["epoch_monotonic_ns"] + 2_000_000_000] * 2)
        raw["hosts"]["0"]["result"]["traffic"]["processes"][0]["observed_us"] = 999_999
        with self.assertRaisesRegex(ValueError, "predates the declared endpoint"):
            adapter.normalize(selected, raw, value, self.root)


if __name__ == "__main__": unittest.main()
