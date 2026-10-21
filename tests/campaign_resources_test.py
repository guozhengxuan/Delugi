import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import campaign_resources as resources
import run_campaign as campaign


class ImmutableResourceContract(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        self.known=self.root/"known";self.known.write_text("fixture host key")
        self.budget={"enforcement":"dedicated_host","cpus":[0,1],"memory_bytes":16*2**30,"swap_bytes":0,"disk_bytes":200*2**30,"network_mbps":1000}
        self.hosts=[{"replica":i,"ssh":f"user@host{i}","advertised":f"10.0.0.{i+1}:9000","control_port":9001,
            "identity_file":str(self.known),"known_hosts_file":str(self.known),"budget":copy.deepcopy(self.budget),
            "binary":{"path":"/opt/replica","sha256":"a"*64}} for i in range(4)]
        self.inventory={"schema":1,"hosts":self.hosts}
        self.source=self.root/"inventory.json";self.source.write_text(json.dumps(self.inventory))
        self.config={"protocols":["delugi"],"nodes":[4],"remote_inventories":{"delugi":{"4":str(self.source)}},"purpose":"development"}
        self.case={"protocol":"delugi","nodes":4,"fault":"none","added_delay_ms":10}

    def tearDown(self):self.temporary.cleanup()

    def contract(self,protocol="delugi"):
        inventory=copy.deepcopy(self.inventory);inventory["inventory_source_sha256"]="b"*64
        effective={"cpus":[0,1],"memory_enforcement":"physical_host","memory_limit_bytes":15*2**30,"cpu_enforcement":"inherited_process_affinity",
            "swap_policy_verified":True,"swap_enforcement":"observed_host_swap","swap_limit_bytes":0,"host_swap_bytes":0,"host_swap_bytes_at_end":0}
        summary={"nonce":"owned","budget":self.budget,"exit_code":0,"native_exit_code":0,"timed_out":False,
                 "owned_group_cleanup":{"group_empty":True},"effective_budget":effective}
        data={"deployment":{"nonce":"owned","inventory":inventory,"machines":{str(i):{"resource_summary":summary} for i in range(4)}}}
        return resources.verified_contract(dict(self.case,protocol=protocol),self.config,data,inventory)

    def test_snapshot_bytes_are_archived_once_and_source_drift_fails_before_next_trial(self):
        snapshots=resources.snapshot_inventories(self.config,self.root/"snapshots")
        first=campaign.case_inventory(self.case,self.config,snapshots)
        second=campaign.case_inventory(dict(self.case,added_delay_ms=20),self.config,snapshots)
        self.assertEqual(first["inventory_source_sha256"],second["inventory_source_sha256"])
        record=snapshots["delugi:n4"]
        self.assertEqual(Path(record["snapshot"]).read_bytes(),self.source.read_bytes())
        changed=copy.deepcopy(self.inventory);changed["hosts"][0]["budget"]["cpus"]=[0]
        self.source.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError,"source changed"):
            campaign.case_inventory(self.case,self.config,snapshots)

    def test_known_host_and_snapshot_substitution_fail(self):
        snapshots=resources.snapshot_inventories(self.config,self.root/"snapshots")
        self.known.write_text("different host key")
        with self.assertRaisesRegex(ValueError,"host-key inventory changed"):
            campaign.case_inventory(self.case,self.config,snapshots)
        self.known.write_text("fixture host key")
        Path(snapshots["delugi:n4"]["snapshot"]).write_text("{}")
        with self.assertRaisesRegex(ValueError,"snapshot changed"):
            campaign.case_inventory(self.case,self.config,snapshots)

    def test_effective_budget_and_static_placement_bind_across_rates_presets_and_protocols(self):
        contract=self.contract();registry={}
        hashed=resources.accept_contract(registry,contract)
        self.assertEqual(hashed,resources.canonical_hash(contract))
        resources.accept_contract(registry,self.contract("autobahn"))
        for field,change in (("cpus",[2,3]),("memory_bytes",8*2**30),("disk_bytes",100*2**30),("network_mbps",500)):
            changed=copy.deepcopy(contract);changed["placement"][0]["budget"][field]=change
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,"changed between trials"):
                resources.accept_contract(registry,changed)
        changed=self.contract("shoal");changed["placement"][0]["budget"]["cpus"]=[0]
        changed["effective_budgets"]["0"]=dict(changed["effective_budgets"]["0"],cpus=[0])
        changed["matched_budget_equivalence"][0].update(cpu_count=1,effective_cpu_count=1)
        with self.assertRaisesRegex(ValueError,"matched per-validator"):
            resources.accept_contract(registry,changed)

    def test_local_and_remote_resource_claims_cannot_be_mixed(self):
        registry={};resources.accept_contract(registry,self.contract())
        local={"validation":"local_unenforced_diagnostic","protocol":"autobahn","nodes":4}
        with self.assertRaisesRegex(ValueError,"unenforced local"):
            resources.accept_contract(registry,local)
        registry={};resources.accept_contract(registry,local)
        with self.assertRaisesRegex(ValueError,"matched per-validator"):
            resources.accept_contract(registry,self.contract())

    def test_effective_cgroup_limit_and_resource_proof_are_not_optional(self):
        budget={"enforcement":"cgroup","cpus":[0],"memory_bytes":2**30,"cgroup_parent":"/sys/fs/cgroup/bench"}
        row={"nonce":"owned","budget":budget,"exit_code":0,"native_exit_code":0,"timed_out":False,
             "owned_group_cleanup":{"group_empty":True},"effective_budget":{"cpus":[0],"memory_enforcement":"cgroup_memory_max",
                "cpu_enforcement":"cgroup_quota_and_inherited_process_affinity","memory_limit_bytes":2**30}}
        self.assertEqual(resources.effective_summary(row,budget,"owned")["memory_limit_bytes"],2**30)
        for edit in ({"memory_limit_bytes":2**29},{"cpu_enforcement":"unknown"},{"cpus":[1]}):
            changed=copy.deepcopy(row);changed["effective_budget"].update(edit)
            with self.assertRaises(ValueError):resources.effective_summary(changed,budget,"owned")
        with self.assertRaisesRegex(ValueError,"incomplete"):resources.effective_summary(row,budget,"different")

    def test_unbound_swap_remains_diagnostic_and_formal_requires_effective_policy(self):
        contract=self.contract()
        self.assertEqual(contract["validation"],resources.VERIFIED)
        inventory=copy.deepcopy(self.inventory);inventory["inventory_source_sha256"]="b"*64
        for host in inventory["hosts"]:host["budget"].pop("swap_bytes")
        summaries={}
        for host in inventory["hosts"]:
            effective=copy.deepcopy(contract["effective_budgets"][str(host["replica"])])
            for key in tuple(effective):
                if "swap" in key:effective.pop(key)
            summaries[str(host["replica"]) ]={"resource_summary":{"nonce":"owned","budget":host["budget"],
                "exit_code":0,"native_exit_code":0,"timed_out":False,"owned_group_cleanup":{"group_empty":True},"effective_budget":effective}}
        data={"deployment":{"nonce":"owned","inventory":inventory,"machines":summaries}}
        diagnostic=resources.verified_contract(self.case,self.config,data,inventory)
        self.assertEqual(diagnostic["validation"],resources.UNVERIFIED_SWAP)
        with self.assertRaisesRegex(ValueError,"explicit observed or enforced swap"):
            resources.verified_contract(self.case,dict(self.config,purpose="formal"),data,inventory)

    def test_changed_or_unenforced_swap_cannot_satisfy_budget_proof(self):
        budget=dict(self.budget)
        effective=self.contract()["effective_budgets"]["0"]
        row={"nonce":"owned","budget":budget,"exit_code":0,"native_exit_code":0,"timed_out":False,
            "owned_group_cleanup":{"group_empty":True},"effective_budget":effective}
        for edit in ({"host_swap_bytes_at_end":2**30},{"swap_policy_verified":False},{"swap_limit_bytes":2**30}):
            changed=copy.deepcopy(row);changed["effective_budget"].update(edit)
            with self.subTest(edit=edit),self.assertRaisesRegex(ValueError,"swap"):
                resources.effective_summary(changed,budget,"owned")
        budget.update(enforcement="cgroup",cgroup_parent="/sys/fs/cgroup/bench")
        row["budget"]=budget
        row["effective_budget"].update(memory_enforcement="cgroup_memory_max",memory_limit_bytes=budget["memory_bytes"],
            cpu_enforcement="cgroup_quota_and_inherited_process_affinity",swap_enforcement="cgroup_memory_swap_max")
        self.assertEqual(resources.effective_summary(row,budget,"owned")["swap_limit_bytes"],0)
        row["effective_budget"]["swap_enforcement"]="observed_host_swap"
        with self.assertRaisesRegex(ValueError,"cgroup swap"):
            resources.effective_summary(row,budget,"owned")

    def test_versioned_contract_verifier_rejects_partial_proof_and_summary_substitution(self):
        complete=self.contract()
        self.assertEqual(resources.validate_verified_contract(complete,"delugi",4),complete)
        for mutate in (lambda c:c.pop("schema"), lambda c:c.update(schema=1),
                       lambda c:c["effective_budgets"]["0"].pop("swap_policy_verified"),
                       lambda c:c["effective_budgets"].pop("3"),
                       lambda c:c["matched_budget_equivalence"][0].update(cpu_count=999),
                       lambda c:c["placement"][0].update(known_hosts_sha256="unbound"),
                       lambda c:c["effective_budgets"]["0"].update(host_swap_bytes=False)):
            changed=copy.deepcopy(complete);mutate(changed)
            with self.assertRaises(ValueError):resources.validate_verified_contract(changed,"delugi",4)
        old=copy.deepcopy(complete);old.pop("schema")
        with self.assertRaisesRegex(ValueError,"legacy contracts are diagnostic"):
            resources.accept_contract({},old)
        with self.assertRaisesRegex(ValueError,"committee differs"):
            resources.validate_verified_contract(complete,"delugi",7)


if __name__=="__main__":unittest.main()
