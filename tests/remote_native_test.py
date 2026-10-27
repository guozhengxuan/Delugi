import copy
import concurrent.futures
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import remote_native as remote
import deployment_prepare as prep


class NativePlacement(unittest.TestCase):
    def test_compact_profile_has_exact_total_population_at_fifty(self):
        for protocol in ('mysticeti','autobahn'):
            for n in (4,10,50):
                cfg=remote.native.settings({'population_profile':'compact-n10-n50-v1',
                    'rate':1001,'warmup':0,'duration':60,'drain':15,'faulty':[0]},n,protocol)
                self.assertEqual(sum(cfg['counts']),60060)
                self.assertEqual(cfg['counts'][0],0)
                self.assertLessEqual(max(cfg['counts'][1:])-min(cfg['counts'][1:]),1)
                if protocol=='mysticeti':
                    role,argv,env=remote.native.launches(protocol,Path('/owned'),1,
                        {'mysticeti':'/published/mysticeti'},cfg,'/usr/bin/python3',1234000)[0]
                    self.assertEqual(env['BENCHMARK_GLOBAL_RATE'],'1001')
                    self.assertEqual(env['BENCHMARK_MEMBER_COUNT'],str(n))
                    self.assertEqual(env['BENCHMARK_HONEST_ORIGINS'],','.join(map(str,range(1,n))))
        with self.assertRaises(ValueError):remote.native.settings({},50,'mysticeti')
        with self.assertRaises(ValueError):remote.native.settings({'population_profile':'compact-n10-n50-v1'},50,'shoal')

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        for name in ("key","known"):(self.root/name).write_text("fixture; never connected")
    def tearDown(self):self.tmp.cleanup()

    def test_packaged_runtime_imports_without_workspace_fallback(self):
        self.assertIn("scripts/baselines/shoal_receipts.py",prep.CONTROLLER_NATIVE)
        for name in remote.RUNTIME_FILES:
            destination=self.root/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes((prep.ROOT/name).read_bytes())
        env={key:value for key,value in os.environ.items() if key not in ("PYTHONPATH", "PYTHONHOME")}
        result=subprocess.run([sys.executable,"-c","import remote_native; import native_placement"],
            cwd=self.root/"scripts",env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def publication(self,protocol="mysticeti"):
        hosts=[];receipts={};recipe=prep.recipe(protocol)
        for i in range(4):
            binaries=[{"name":name,"path":f"/tmp/published-{i}/{name}","sha256":"1"*64,"bytes":10} for name in recipe["binaries"]]
            hosts.append({"replica":i,"ssh":f"user@host-{i}","identity_file":str(self.root/"key"),"known_hosts_file":str(self.root/"known"),
                "advertised":f"10.0.0.{i+1}:9000","control_port":9001,"binary":{"path":binaries[0]["path"],"sha256":"1"*64},
                "python_executable":sys.executable,"budget":{"enforcement":"dedicated_host","cpus":[0],"memory_bytes":16*2**30,"swap_bytes":0}})
            receipts[str(i)]={"protocol":protocol,"recipe":recipe,"source_bundle_sha256":"2"*64,"binaries":binaries,"native_remote_runner_supported":False}
        return {"protocol":protocol,"inventory":{"schema":1,"hosts":hosts},"receipts":receipts}

    def selected(self,protocol="mysticeti"):
        pin=remote.pin_for(protocol)
        if protocol=="shoal":pin["observer_contract"]=remote.native.SHOAL_OBSERVER_CONTRACT
        with patch.object(remote,"pin_for",return_value=pin):
            return remote.plan(self.publication(protocol),{"rate":4,"useful_bytes":8,"warmup":0,"duration":1,"drain":1})

    def mock_shoal_observer(self):
        observer=Mock()
        observer.plan={"run_id":"a"*32,"sha3_256":"b"*64,"counts":[1]*4,"useful_bytes":8}
        observer.environment.return_value={"BENCHMARK_FINITE_PLAN":"/owned/observer-plan.json","BENCHMARK_OBSERVER_MODE":"full"}
        observer.archive.return_value=Mock(index_sha256="b"*64)
        observer.evidence.return_value={"contract":remote.native.SHOAL_OBSERVER_CONTRACT,"mode":"full"}
        return observer

    def ledger(self,i):
        offset=i*10**12
        return {"requests":[{"request_id":f"r{i}","origin":i,"sequence":0,"useful_bytes":8,"scheduled_us":offset,
                   "admitted_us":offset+10,"batch_ready_us":offset+15,"materialized_us":offset+20+i}],
            "outputs":[{"request_id":f"r{j}","origin":j,"sequence":0,"useful_bytes":8,"output_index":j,"exact_batch_id":f"b{j}","materialized_us":offset+20+j} for j in range(4)],
            "batches":[{"exact_batch_id":f"b{j}","payload_bytes":48,"materialized_us":offset+20+j} for j in range(4)],
            "window_start_us":offset,"window_end_us":offset+1000000,"observed_us":offset+2000000,"output_index_base":0}

    def test_exact_protocol_roles_private_peer_ports_and_host_local_clocks(self):
        for protocol in ('mysticeti','autobahn','autobahn-blips','shoal'):
            selected=self.selected(protocol);cfg=selected["settings"];root=Path("/tmp/delugi-native-"+selected["nonce"])
            binaries={name:row["path"] for name,row in selected["hosts"][0]["native_binaries"].items()}
            launch=remote.native.launches(protocol,root,0,binaries,cfg,"/opt/python3.11",987654321000)
            self.assertEqual(len(launch),2 if protocol.startswith("autobahn") else 1)
            self.assertTrue(all(role in ("validator","primary","worker-0") for role,_,_ in launch))
            if protocol.startswith("autobahn"):
                self.assertEqual(launch[0][2]["BENCHMARK_EPOCH_NS"],"987654321000")
                argv=remote.native.application(protocol,root,0,cfg,"/opt/python3.11",987654321000)
                self.assertEqual(argv[0],"/opt/python3.11")
                self.assertEqual(argv[argv.index("--epoch-ns")+1],"987654321000")
                self.assertEqual(len(selected["endpoints"][0]["peer"]),3)
            self.assertFalse(selected.get("comparison_eligible",False))

    def test_simpleit_publication_has_explicit_case_and_fixed_recipe(self):
        for protocol in ('simpleit-mempool','simpleit-dispersed'):
            selected=self.selected(protocol)
            self.assertEqual(selected['settings']['case'],'healthy')
            self.assertEqual(selected['build_recipe']['binaries'],['node'])
            self.assertEqual(selected['build_recipe']['toolchain'],'1.92.0')
            with self.assertRaisesRegex(ValueError,'faulty identities'):
                remote.native.settings({'case':'silent-first-leader','warmup':0},4,protocol)

    def test_missing_or_old_python_is_rejected_before_native_launch(self):
        publication=self.publication();publication["inventory"]["hosts"][0].pop("python_executable")
        with self.assertRaisesRegex(ValueError,"Python"):
            remote.plan(publication,{})
        request={"host":{"python_executable":sys.executable}}
        for version in ((3,8,10),(3,10,14)):
            with self.subTest(version=version),patch.object(remote.sys,"version_info",version):
                with self.assertRaisesRegex(ValueError,"Python>=3.11"):
                    remote.check_artifacts(request)

    def test_python310_bootstrap_rejects_before_runtime_upload_or_launch(self):
        selected=self.selected();calls=[];remote_root=self.root/"remote"
        class OldPythonConnection:
            def __init__(self,host):self.host=host
            def command(self,argv,**kwargs):
                calls.append("bootstrap")
                return subprocess.run([sys.executable,"-c","import sys; sys.version_info=(3,10,14)\n"+argv[2],*argv[3:]],
                    check=True,capture_output=True,text=True,timeout=10)
            def upload(self,*args):raise AssertionError("unsupported interpreter reached runtime upload")
            def rpc_native(self,root,request):
                calls.append(request["action"])
                if request["action"]!="cleanup":raise AssertionError("unsupported interpreter reached native control")
                return {"state":"not_started"}
        with patch.object(remote,"root_for",return_value=remote_root):
            result=remote.execute(selected,self.root/"result",connection_factory=OldPythonConnection)
        self.assertEqual(result["status"],"failed")
        self.assertIn("CalledProcessError",result["error"])
        self.assertEqual(calls,["bootstrap","cleanup"])
        self.assertFalse(remote_root.exists())

    def test_shoal_old_or_unknown_observer_contract_is_rejected_before_connection(self):
        pin=remote.pin_for("shoal")
        for contract in (None,"legacy-full-journal","future-unreviewed"):
            with patch.object(remote,"pin_for",return_value=pin|{"observer_contract":contract}):
                with self.assertRaisesRegex(ValueError,"finite observer contract"):
                    remote.plan(self.publication("shoal"),{})

    def test_shoal_child_disables_telemetry_even_with_inherited_force_override(self):
        inherited={"APTOS_FORCE_ENABLE_TELEMETRY":"1", "APTOS_DISABLE_TELEMETRY":"0", "BENCHMARK_STALE":"1", "PATH":"/owned/bin"}
        original=dict(inherited)
        env=remote.native.child_environment("shoal", {"BENCHMARK_COHORT_PATH":"/owned/cohort"}, inherited)
        self.assertEqual(env["APTOS_DISABLE_TELEMETRY"], "1")
        self.assertNotIn("APTOS_FORCE_ENABLE_TELEMETRY", env)
        self.assertNotIn("BENCHMARK_STALE", env)
        self.assertEqual(env["BENCHMARK_COHORT_PATH"], "/owned/cohort")
        self.assertEqual(env["PATH"], "/owned/bin")
        self.assertEqual(inherited, original)
        self.assertEqual(remote.native.child_environment("mysticeti", {}, inherited)["APTOS_FORCE_ENABLE_TELEMETRY"], "1")

    def test_shoal_child_uses_direct_peer_connections_despite_inherited_proxies(self):
        inherited={key:"http://127.0.0.1:1" for key in (
            "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HtTp_PrOxY")}
        inherited.update(NO_PROXY="localhost", no_proxy="localhost", KEEP="yes")
        original=dict(inherited)
        env=remote.native.child_environment("shoal", {"HTTPS_PROXY":"http://127.0.0.1:2"}, inherited)
        self.assertEqual(env, {"KEEP":"yes", "APTOS_DISABLE_TELEMETRY":"1", "NO_PROXY":"*", "no_proxy":"*"})
        self.assertEqual(inherited, original)
        self.assertEqual(remote.native.child_environment("mysticeti", {}, inherited), original)

    def test_publication_recipe_is_fixed_and_exact_actual_sidecar_must_match(self):
        publication = self.publication()
        for receipt in publication["receipts"].values():
            receipt["recipe"] = dict(receipt["recipe"], release_debug="2")
        with self.assertRaisesRegex(ValueError, "fixed reviewed"):
            remote.plan(publication, {})
        selected = self.selected()
        host = copy.deepcopy(selected["hosts"][0])
        for row in host["native_binaries"].values():
            binary = self.root / row["name"]; binary.write_bytes(b"fixed native fixture")
            row.update(path=str(binary), sha256=prep.sha(binary))
            stamp = {"binary_sha256":row["sha256"], "source_bundle_sha256":selected["source_bundle_sha256"],
                "recipe":selected["build_recipe"], "provenance":{"protocol":selected["protocol"], **selected["pin"]}}
            prep.json_file(str(binary) + ".build.json", stamp)
        request = {key:selected[key] for key in ("protocol", "pin", "source_bundle_sha256", "build_recipe")}
        request["host"] = host
        self.assertEqual(set(remote.check_artifacts(request)["artifacts"]), set(host["native_binaries"]))
        # A different but otherwise permitted build recipe must not describe the
        # same retained executable: it disagrees with the immutable build stamp.
        request["build_recipe"] = prep.recipe("mysticeti", jobs=2)
        with self.assertRaisesRegex(ValueError, "build recipe differs from publication"):
            remote.check_artifacts(request)

    def test_configuration_generator_routes_one_private_key_per_validator(self):
        import base64
        names=[base64.b64encode(bytes([i])*32).decode() for i in range(4)]
        root=self.root/"run";root.mkdir();seen=[]
        def run(argv,**kwargs):
            seen.append(argv);path=Path(argv[-1]);i=int(path.stem.split("-")[-1]);path.write_text(json.dumps({"name":names[i],"secret":f"sk{i}"}))
            return subprocess.CompletedProcess(argv,0,"","")
        cfg=remote.native.settings({"rate":4,"duration":1,"warmup":0},4)
        files=remote.native.generate("autobahn",root,[f"10.0.0.{i+1}" for i in range(4)],{"node":"/fixed/node"},cfg,"a"*32,run=run)
        for i,row in enumerate(files):
            self.assertEqual([p.name for p in row if p.name.startswith("key-")],[f"key-{i}.json"])
        committee=json.loads((root/"fixture/committee.json").read_text())["authorities"]
        self.assertEqual(committee[names[0]]["workers"]["0"]["transactions"],"127.0.0.1:9004")
        self.assertEqual(committee[names[2]]["workers"]["0"]["worker_to_worker"],"10.0.0.2:9011")
        self.assertEqual(remote.native.first_leader_record('autobahn',root,1)['author'],names[2])
        self.assertTrue(all(argv[:2]==["/fixed/node","generate_keys"] for argv in seen))

    def test_reducer_uses_origin_durations_despite_arbitrary_cross_host_offsets(self):
        cfg=self.selected()["settings"]
        result=remote.native.reduce({i:self.ledger(i) for i in range(4)},cfg)
        self.assertEqual(result["cohort"]["completed"],4)
        self.assertEqual(result["cohort"]["window"]["unique_completion_tps"],4)
        self.assertEqual(result["agreement"]["common_prefix_length"],4)
        self.assertFalse(result["comparison_eligible"])

    def test_plan_capacity_fault_budget_and_changed_runtime_fail_before_connection(self):
        for values in ({"duration":301},{"faulty":[0,1]},
                       {"pause_replica":0},{"deadline_ms":-1},{"shell":"arbitrary"}):
            with self.assertRaises(ValueError):remote.plan(self.publication(),values)
        selected=self.selected();selected["runtime_sources"]["scripts/remote_native.py"]="0"*64
        factory=Mock()
        with self.assertRaisesRegex(ValueError,"source changed"):
            remote.execute(selected,self.root/"changed",connection_factory=factory)
        factory.assert_not_called()

    def fake_lifecycle(self,cleanup=None,supervisor_failure=False,protocol="mysticeti",arm_failure=False,receipt_failure=False,receipt_mismatch=False):
        selected=self.selected(protocol);case=self;calls=[];archives={};states={};armed=set();arm_barrier=threading.Event()
        class FakeConnection:
            def __init__(self,host):self.host=host;self.i=host["replica"]
            def upload(self,source,destination):calls.append((self.i,"upload",destination))
            def command(self,argv,**kwargs):
                calls.append((self.i,"command",argv))
                if supervisor_failure and self.i==0 and "--request" in argv:
                    raise RuntimeError("owned resource supervisor failed")
                if protocol=="shoal" and "--request" in argv:
                    if not arm_barrier.wait(timeout=2):raise RuntimeError("mock Shoal arm was never sent")
                    calls.append((self.i,"worker_returned",None))
                if argv[0]=="cat":
                    name=Path(argv[1]).name;kwargs["stdout"].write(archives[(self.i,name)].read_bytes())
                if argv[-1]=="_export":
                    request=json.loads(kwargs["input"]);source=case.root/f"evidence-{self.i}"
                    remote.runtime_evidence.pack(source,remote.runtime_evidence.selected_files(source),kwargs["stdout"],
                        {"nonce":selected["nonce"],"replica":self.i,"plan_sha256":request["plan_sha256"]})
                return subprocess.CompletedProcess(argv,0,"","")
            def rpc_native(self,root,request):
                action=request["action"];calls.append((self.i,action,None))
                if action=="preflight":return {"python_version":[3,11,0],"python_sha256":"3"*64}
                if action=="generate":
                    outputs={}
                    for i in range(4):
                        source=case.root/f"config-{i}";(source/"fixture").mkdir(parents=True);(source/"fixture/config.json").write_text("{}")
                        archive=case.root/f"configuration-{i}.tar";archives[(0,archive.name)]=archive
                        outputs[str(i)]=remote.archive_selected(source,["fixture/config.json"],archive,"native-configuration",{"replica":i,"nonce":selected["nonce"]})
                    return outputs
                if action=="install":return {"installed":True}
                if action=='seal_configuration':return {'sealed':True,'replica':0,'own_archive_sha256':request['sha256']}
                if action=="readiness":
                    return remote.startup_identity(request)|{"state":"prepared","readiness":{"ready":True},"readiness_sha256":str(self.i)*64}
                if action=="arm":
                    if arm_failure and self.i==0:raise RuntimeError("mock host refused arm")
                    armed.add(self.i)
                    if len(armed)==4:arm_barrier.set()
                    return remote.startup_identity(request)|{"state":"arm_requested","readiness_sha256":request["readiness_sha256"]}
                if action=="status":
                    source=case.root/f"evidence-{self.i}";source.mkdir();prep.json_file(source/"ledger.json",case.ledger(self.i))
                    store=remote.native.native_cohort_store.NativeStore(source/"stage.sqlite")
                    try:
                        store.legacy(source/"ledger.json",self.i);cohorts=store.archive(source/"cohorts")
                    finally:store.close()
                    states[self.i]={"status":"completed","replica":self.i,"epoch_monotonic_ns":10**12+self.i*10**9,
                        "native_observer":{},"cohort_archive":{"path":"cohorts/index.json","sha256":cohorts.index_sha256,"schema":2}}
                    prep.json_file(source/"result.json",states[self.i])
                    return states[self.i]
                if action=="collect":
                    return {"format":remote.runtime_evidence.FORMAT,"metadata":{"nonce":selected["nonce"],"replica":self.i,"plan_sha256":request["plan_sha256"]}}
                if action=="cleanup":
                    if arm_failure:arm_barrier.set()
                    if isinstance(cleanup,Exception):raise cleanup
                    return cleanup or {"state":"finished","exit_code":0}
                raise AssertionError(action)
        receipt={"planned":4,"admitted":4,"all_correct_completed":4,
                 "origins":[{"origin":i,"planned":1,"admitted":1,"all_correct_completed":1} for i in range(4)]}
        if receipt_mismatch:
            # Preserve the committee total while changing per-origin credit.
            receipt["origins"][0]["all_correct_completed"]=0
            receipt["origins"][1]["all_correct_completed"]=2
        with patch.object(remote,"pin_for",return_value=selected["pin"]),\
             patch.object(remote.native,"collected_shoal_receipt",return_value={}),\
             patch.object(remote.native.shoal_receipts,"compare",return_value={},side_effect=ValueError("native prefixes disagree") if receipt_failure else None),\
             patch.object(remote.native.shoal_receipts,"summarize",return_value=receipt):
            result=remote.execute(selected,self.root/"result",connection_factory=FakeConnection)
        return result,calls,selected

    def test_end_to_end_local_mock_plan_configuration_launch_collection_cleanup(self):
        result,calls,selected=self.fake_lifecycle()
        self.assertEqual(result["status"],"completed",result)
        self.assertEqual(result["cohort"]["completed"],4)
        self.assertEqual(len(result["cleanup"]),4)
        self.assertEqual(len([row for row in calls if row[1]=="install"]),3)
        supervisor=json.loads((self.root/"result/supervisor-0.json").read_text())
        self.assertEqual(supervisor["binary"],sys.executable)
        self.assertEqual(supervisor["budget"],selected["hosts"][0]["budget"])
        self.assertLess(supervisor["max_runtime_seconds"],100)
        self.assertTrue((self.root/"result/host-0/ledger.json").is_file())
        self.assertTrue((self.root/"result/host-0/cohorts/index.json").is_file())
        self.assertEqual(result["cohort_archive"]["format"],"native-cohort-collection-v1")

    def test_cleanup_refusal_invalidates_an_otherwise_completed_measurement(self):
        result,_,_=self.fake_lifecycle(RuntimeError("owned process identity changed"))
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["cohort"]["completed"],4)
        self.assertIn("not confirmation",result["cleanup_acceptance_error"])
        self.assertTrue((self.root/"result/host-0/ledger.json").is_file())

    def test_mock_shoal_lifecycle_prepares_all_hosts_before_arm_and_retains_cleanup(self):
        result,calls,selected=self.fake_lifecycle(protocol="shoal")
        self.assertEqual(result["status"],"completed",result)
        first_arm=next(i for i,row in enumerate(calls) if row[1]=="arm")
        self.assertEqual({row[0] for row in calls[:first_arm] if row[1]=="readiness"},set(range(4)))
        self.assertEqual(len(result["startup"]["prepared"]),4)
        self.assertEqual(len(result["startup"]["arms"]),4)
        self.assertEqual(len(result["cleanup"]),4)
        supervisor=json.loads((self.root/"result/supervisor-0.json").read_text())
        cfg=selected["settings"]
        self.assertEqual(supervisor["max_runtime_seconds"],cfg["warmup"]+cfg["duration"]+cfg["drain"]+2*cfg["startup_seconds"]+30)

    def test_failed_shoal_arm_cleans_waiting_workers_before_joining_them(self):
        result,calls,_=self.fake_lifecycle(protocol="shoal",arm_failure=True)
        self.assertEqual(result["status"],"failed")
        self.assertIn("refused arm",result["startup_failure"]["error"])
        self.assertEqual(len(result["startup_failure"]["cleanup"]),4)
        self.assertEqual(result["dispatch"]["failures"],{})
        first_cleanup=next(i for i,row in enumerate(calls) if row[1]=="cleanup")
        first_return=next(i for i,row in enumerate(calls) if row[1]=="worker_returned")
        self.assertLess(first_cleanup,first_return)
        self.assertEqual(len(result["cleanup"]),4)

    def test_receipt_failure_after_successful_reduction_still_fails_acceptance(self):
        result,_,_=self.fake_lifecycle(protocol="shoal",receipt_failure=True)
        self.assertEqual(result["status"],"failed")
        self.assertIn("native prefixes disagree",result["error"])
        self.assertEqual(result["cohort"]["completed"],4)
        self.assertEqual(len(result["cleanup"]),4)

    def test_shoal_receipt_reconciles_each_origin_not_only_committee_total(self):
        result,_,_=self.fake_lifecycle(protocol="shoal",receipt_mismatch=True)
        self.assertEqual(result["status"],"failed")
        self.assertIn("detailed finite cohort differs",result["error"])
        self.assertEqual(result["finite_output_receipt"]["all_correct_completed"],4)

    def test_requested_termination_is_not_completed_cleanup(self):
        result,_,_=self.fake_lifecycle({"state":"owned_termination_requested"})
        self.assertEqual(result["status"],"failed")
        self.assertIn("not confirmed",result["cleanup_acceptance_error"])

    def test_failed_supervisor_cannot_be_overridden_by_completed_native_result(self):
        result,_,_=self.fake_lifecycle(supervisor_failure=True)
        self.assertEqual(result["status"],"failed")
        self.assertEqual(result["cohort"]["completed"],4)
        self.assertIn("resource supervisors failed",result["supervisor_acceptance_error"])

    def test_multiminute_population_uses_disk_envelope_not_old_whole_file_caps(self):
        selected=remote.plan(self.publication(),{"rate":4000,"duration":180,"warmup":0})
        self.assertEqual(sum(selected["settings"]["counts"]),720000)

    def test_cleanup_refuses_reused_native_pid_without_signalling(self):
        root=self.root/"owned";root.mkdir();prep.json_file(root/"process.json",{"nonce":"a"*32,"pid":123,"pid_start":"old"})
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote.remote_worker,"pid_start",return_value="replacement"),patch.object(remote.os,"killpg") as kill:
            with self.assertRaisesRegex(RuntimeError,"identity"):
                remote.rpc({"action":"cleanup","nonce":"a"*32})
            kill.assert_not_called()

    def test_host_worker_uses_one_local_epoch_and_pauses_only_native_children(self):
        selected=self.selected("autobahn");cfg=selected["settings"]
        cfg.update(faulty=[0],correct=[1,2,3],pause_replica=0,pause_after=.1,pause_seconds=.2)
        root=self.root/("delugi-native-"+selected["nonce"]);root.mkdir()
        request={"nonce":selected["nonce"],"settings":cfg,"protocol":"autobahn","host":selected["hosts"][0],"endpoint":selected["endpoints"][0],"ips":[f"10.0.0.{i+1}" for i in range(4)]}
        clock=[500000000000000];spawned=[]
        def now(*args):clock[0]+=100000000;return clock[0]
        class Process:
            def __init__(self,argv,**kwargs):
                self.pid=100+len(spawned);self.code=None;self.argv=argv;spawned.append(self)
                if "autobahn_cohort.py" in " ".join(argv):prep.json_file(root/"ledger.json",self_ledger)
                else:
                    role="primary" if argv[-1]=="primary" else "worker-0"
                    prep.json_file(root/"observer"/role/"io.json",{"written_bytes":1,"window_written_bytes":1})
                self.test_no_session="start_new_session" not in kwargs
            def poll(self):return self.code
            def wait(self,**kwargs):self.code=0;return 0
            def terminate(self):self.code=0
            def kill(self):self.code=-9
        self_ledger=self.ledger(0)
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote,"check_artifacts",return_value={}),\
             patch.object(remote.time,"clock_gettime_ns",side_effect=now),patch.object(remote.time,"sleep"),\
             patch.object(remote.socket,"create_connection",return_value=nullcontext()),\
             patch.object(remote.subprocess,"Popen",side_effect=Process),patch.object(remote.os,"kill") as kill:
            self.assertEqual(remote.run_host(request),0)
        self.assertEqual(len(spawned),3)
        self.assertTrue(all(p.test_no_session for p in spawned))
        pauses=[call.args[0] for call in kill.call_args_list if call.args[1]==remote.signal.SIGSTOP]
        self.assertNotIn(spawned[2].pid,pauses)
        self.assertTrue({spawned[0].pid,spawned[1].pid}.issubset(pauses))
        result=json.loads((root/"result.json").read_text())
        application=spawned[2].argv
        self.assertEqual(application[application.index("--epoch-ns")+1],str(result["epoch_monotonic_ns"]))
        self.assertFalse(result["comparison_eligible"])

    def shoal_readiness_fixture(self, crypto="off"):
        root=self.root/"shoal-ready";(root/"logs").mkdir(parents=True)
        (root/"logs/validator.log").write_bytes(b"native starting\n")
        readiness=remote.native.ShoalReadiness(root,0,8001,1_000_000_000,crypto)
        reply=Mock(status=200);reply.__enter__=Mock(return_value=reply);reply.__exit__=Mock(return_value=False)
        return root,readiness,reply

    def test_shoal_rest_and_counter_presence_do_not_replace_native_bootstrap(self):
        root,readiness,reply=self.shoal_readiness_fixture()
        with patch.object(remote.native.shoal_cohort,"direct_urlopen",return_value=reply):
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["ready"])
            prep.json_file(root/"io.json",{"observed_us":2_000_000,"written_bytes":1,"read_bytes":1})
            marker=readiness.marker
            with (root/"logs/validator.log").open("ab") as stream:stream.write(marker[:20])
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["ready"])
            with (root/"logs/validator.log").open("ab") as stream:stream.write(marker[20:]+b"\n")
            self.assertTrue(readiness.observe(now=lambda:2_000_000_000)["ready"])
            reply.status=503
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["ready"])

    def test_shoal_readiness_validates_meter_values_freshness_and_optional_crypto(self):
        root,readiness,reply=self.shoal_readiness_fixture("on")
        (root/"logs/validator.log").write_bytes(readiness.marker)
        with patch.object(remote.native.shoal_cohort,"direct_urlopen",return_value=reply):
            for bad in (-1,True,"0"):
                prep.json_file(root/"io.json",{"observed_us":2_000_000,"written_bytes":bad,"read_bytes":1})
                with self.assertRaisesRegex(ValueError,"TCP counters"):readiness.observe(now=lambda:2_000_000_000)
            prep.json_file(root/"io.json",{"observed_us":500_000,"written_bytes":1,"read_bytes":1})
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["io_ready"])
            prep.json_file(root/"io.json",{"observed_us":2_000_001,"written_bytes":1,"read_bytes":1})
            with self.assertRaisesRegex(ValueError,"future"):readiness.observe(now=lambda:2_000_000_000)
            prep.json_file(root/"io.json",{"observed_us":2_000_000,"written_bytes":1,"read_bytes":1})
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["ready"])
            cpu={"schema":1,"monotonic_ns":2_000_000_000,"operations":{kind:{"calls":0,"thread_cpu_ns":0} for kind in readiness.operations}}
            prep.json_file(root/"crypto-0-validator.json",cpu)
            self.assertTrue(readiness.observe(now=lambda:2_000_000_000)["ready"])
            self.assertFalse(readiness.observe(now=lambda:5_000_000_000)["ready"])
            cpu["operations"]["ordinary_verify"]["calls"]=-1
            prep.json_file(root/"crypto-0-validator.json",cpu)
            with self.assertRaisesRegex(ValueError,"crypto counters"):readiness.observe(now=lambda:2_000_000_000)

    def test_shoal_readiness_rejects_replaced_log_and_oversized_meter(self):
        root,readiness,reply=self.shoal_readiness_fixture()
        with patch.object(remote.native.shoal_cohort,"direct_urlopen",return_value=reply):
            readiness.observe(now=lambda:2_000_000_000)
            (root/"io.json").write_bytes(b" "*65537)
            with self.assertRaisesRegex(ValueError,"bounded size"):readiness.observe(now=lambda:2_000_000_000)
            (root/"io.json").unlink()
            (root/"logs/validator.log").rename(root/"logs/old.log")
            (root/"logs/validator.log").write_bytes(readiness.marker)
            with self.assertRaisesRegex(ValueError,"replaced"):readiness.observe(now=lambda:2_000_000_000)

    def test_shoal_readiness_requires_the_exact_initialized_finite_observer(self):
        root,_,reply=self.shoal_readiness_fixture()
        plan={"run_id":"a"*32,"sha3_256":"b"*64,"counts":[1]*4}
        readiness=remote.native.ShoalReadiness(root,0,8001,1_000_000_000,"off",observer_plan=plan)
        (root/"logs/validator.log").write_bytes(readiness.marker)
        prep.json_file(root/"io.json",{"observed_us":2_000_000,"written_bytes":1,"read_bytes":1})
        sample={"schema":1,"format":"shoal-native-counters-v1","run_id":plan["run_id"],"plan_sha3_256":plan["sha3_256"],
                "origin":0,"mode":"full","observed_us":2_000_000,"output_count":0,"own_eligible_count":0,"payload_bytes":0,"batch_count":0}
        with patch.object(remote.native.shoal_cohort,"direct_urlopen",return_value=reply):
            self.assertFalse(readiness.observe(now=lambda:2_000_000_000)["ready"])
            prep.json_file(root/"receipt-0/counters.json",sample)
            self.assertTrue(readiness.observe(now=lambda:2_000_000_000)["ready"])
            for change in ({"origin":1},{"plan_sha3_256":"c"*64},{"mode":"compact"},{"own_eligible_count":2}):
                prep.json_file(root/"receipt-0/counters.json",sample|change)
                with self.assertRaisesRegex(ValueError,"finite observer readiness"):
                    readiness.observe(now=lambda:2_000_000_000)

    def test_shoal_full_observer_authenticates_plan_and_rechecks_transferred_receipt(self):
        # Synthetic Ed25519-signed BCS and native receipt fixtures exercise the
        # real parser/reducer path; this is not a native execution benchmark.
        from shoal_test import signed_fixture
        from shoal_receipts_test import NativeReceiptTests
        run_id="11"*16;root=self.root/("delugi-native-"+run_id);(root/"fixture").mkdir(parents=True)
        cfg=remote.native.settings({"rate":4,"useful_bytes":8,"warmup":0,"duration":.00004,"drain":.00001},4,"shoal")
        cfg["counts"]=[1]*4;identities=[]
        for origin in range(4):
            raw=signed_fixture(origin=origin,run=run_id)
            row=remote.native.shoal_cohort.decode_signed_workload(raw)|{"bcs_hex":raw.hex()}
            identities.append(row["request_id"])
            (root/"fixture"/f"plan-{origin}.jsonl").write_text(json.dumps(row)+"\n")
        observer=remote.native.ShoalObserver(root,2,cfg)
        try:
            self.assertTrue((root/"admission-2.bits").exists())
            self.assertFalse((root/"admission-0.bits").exists())
            self.assertEqual(observer.environment()["BENCHMARK_ORIGIN"],"2")
            observer.publisher.admit(0)
            observer.arm(50_000)
            self.assertFalse((root/"freeze-0.json").exists())
            self.assertEqual(json.loads((root/"freeze-2.json").read_text())["requested_us"],100)
            NativeReceiptTests().fixture(root,observer.plan,2,[(i,0,identity) for i,identity in enumerate(identities)],empty=True)
            (root/"output-2.jsonl").rename(root/"cohort.jsonl")
            events=[json.loads(row) for row in (root/"cohort.jsonl").read_text().splitlines()]
            for event in events:
                if event["event"]=="output":event["origin_eligible"]=True
            (root/"cohort.jsonl").write_text("".join(json.dumps(row)+"\n" for row in events))
            admitted=root/"admitted.jsonl"
            admitted.write_text(json.dumps({"request_id":identities[2],"origin":2,"sequence":0,"useful_bytes":8,
                "scheduled_us":50,"admitted_us":60,"batch_ready_us":None,"materialized_us":None,"rejected_us":None,"rejection_reason":None})+"\n")
            observer.await_receipt([])
            archive=observer.archive(50_000,admitted);evidence=observer.evidence()
            self.assertTrue(evidence["verification"]["full_native_prefix"]["verified"])
            self.assertEqual(archive.ledgers[2]["observed_us"],110)
            value=remote.native.collected_shoal_receipt(root,2,cfg,run_id,50_000,evidence,archive)
            self.assertEqual(value["bits"][("own_eligible",2)],b"\x01")
            with self.assertRaisesRegex(ValueError,"host-local epoch"):
                remote.native.collected_shoal_receipt(root,2,cfg,run_id,51_000,evidence,archive)
            with self.assertRaisesRegex(ValueError,"fingerprint"):
                remote.native.collected_shoal_receipt(root,2,cfg,run_id,50_000,evidence|{"header_sha256":"0"*64},archive)
            rows=(root/"cohort.jsonl").read_text().splitlines()
            (root/"cohort.jsonl").write_text("\n".join(rows[:-1])+"\n")
            with self.assertRaisesRegex(ValueError,"detailed output"):
                remote.native.collected_shoal_receipt(root,2,cfg,run_id,50_000,evidence,archive)
        finally:observer.close()

    def test_shoal_arm_requires_and_binds_complete_preparation_receipt(self):
        root=self.root/"arm";root.mkdir()
        request={"protocol":"shoal","nonce":"a"*32,"plan_sha256":"b"*64,"host":{"replica":0}}
        with patch.object(remote,"checked_root",return_value=root):
            with self.assertRaisesRegex(RuntimeError,"before preparation"):remote.rpc(request|{"action":"arm"})
            prepared=remote.startup_identity(request)|{"state":"prepared","readiness":{"ready":True}}
            remote.publish_startup(root,"readiness.json",prepared)
            observed=remote.rpc(request|{"action":"readiness"})
            with self.assertRaisesRegex(ValueError,"changed before arm"):
                remote.rpc(request|{"action":"arm","readiness_sha256":"c"*64})
            arm=request|{"action":"arm","readiness_sha256":observed["readiness_sha256"]}
            first=remote.rpc(arm)
            self.assertEqual(first,remote.rpc(arm))
            self.assertNotIn("epoch_monotonic_ns",first)
            with self.assertRaisesRegex(ValueError,"identity differs"):
                remote.rpc(arm|{"plan_sha256":"d"*64})
        self.assertFalse((root/"arm.json.pending").exists())

    def test_cleanup_before_worker_start_leaves_a_bound_abort_tombstone(self):
        root=self.root/"cancelled";root.mkdir()
        request={"protocol":"shoal","nonce":"a"*32,"plan_sha256":"b"*64,"host":{"replica":0}}
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote.os,"killpg") as kill:
            self.assertEqual(remote.rpc(request|{"action":"cleanup"}),{"state":"not_started"})
            with self.assertRaisesRegex(RuntimeError,"aborted"):
                remote.check_startup_abort(root,request)
            with self.assertRaisesRegex(RuntimeError,"aborted"):
                remote.rpc(request|{"action":"arm"})
            with self.assertRaisesRegex(ValueError,"identity differs"):
                remote.check_startup_abort(root,request|{"plan_sha256":"c"*64})
            kill.assert_not_called()

    def test_shoal_controller_barrier_never_arms_a_partial_prepared_committee(self):
        selected=self.selected("shoal");calls=[];polls={i:0 for i in range(4)};prepared=set()
        requests={i:{"nonce":selected["nonce"],"plan_sha256":"a"*64,"host":{"replica":i},"settings":selected["settings"]} for i in range(4)}
        class Connection:
            def __init__(self,i):self.i=i
            def rpc_native(self,root,request):
                i=self.i;calls.append((i,request["action"]))
                if request["action"]=="readiness":
                    polls[i]+=1
                    ready=i!=3 or polls[i]>=2
                    if ready:prepared.add(i)
                    return remote.startup_identity(request)|{"state":"prepared" if ready else "preparing","readiness":{"ready":ready},"readiness_sha256":str(i)*64}
                self_case.assertEqual(prepared,set(range(4)))
                self_case.assertNotIn("epoch_monotonic_ns",request)
                return remote.startup_identity(request)|{"state":"arm_requested","readiness_sha256":request["readiness_sha256"]}
        self_case=self;evidence={};futures={i:concurrent.futures.Future() for i in range(4)}
        with patch.object(remote.time,"sleep"):
            remote.arm_prepared_shoal({i:Connection(i) for i in range(4)},requests,self.root,futures,evidence)
        self.assertEqual(len(evidence["arms"]),4)
        self.assertEqual(polls[3],2)
        futures[0].set_result(None);calls.clear()
        with self.assertRaisesRegex(RuntimeError,"supervisor ended"):
            remote.arm_prepared_shoal({i:Connection(i) for i in range(4)},requests,self.root,futures,{})
        self.assertFalse(calls)

    def test_shoal_host_prepares_then_arms_one_local_epoch_for_ingress_and_faults(self):
        selected=self.selected("shoal");cfg=selected["settings"]
        cfg.update(startup_seconds=1,duration=.3,drain=.1,faulty=[0],correct=[1,2,3],omit_replica=0,omission_after=.1,omission_seconds=.1)
        root=self.root/("delugi-native-"+selected["nonce"]);(root/"fixture").mkdir(parents=True)
        prep.json_file(root/"fixture/authors.json",{str(i):str(i)*64 for i in range(4)})
        request={"nonce":selected["nonce"],"plan_sha256":"a"*64,"settings":cfg,"protocol":"shoal","host":selected["hosts"][0],"endpoint":selected["endpoints"][0],"ips":[f"10.0.0.{i+1}" for i in range(4)]}
        clock=[500_000_000_000];spawned=[];ingress_epochs=[];readiness_calls=[]
        def now(*args):return clock[0]
        def sleep(seconds):
            clock[0]+=max(int(seconds*1e9),10_000_000)
            if (root/"readiness.json").exists() and not (root/"arm.json").exists():
                self.assertFalse((root/"omission-interval.txt").exists())
                observed=remote.rpc(request|{"action":"readiness"})
                remote.rpc(request|{"action":"arm","readiness_sha256":observed["readiness_sha256"]})
        class Process:
            def __init__(self,argv,**kwargs):self.pid=600;self.code=None;spawned.append(self)
            def poll(self):return self.code
            def wait(self,**kwargs):self.code=0;return 0
            def terminate(self):self.code=-15
            def kill(self):self.code=-9
        class Ready:
            def __init__(self,*args,**kwargs):pass
            def observe(self):
                readiness_calls.append(clock[0]);ready=len(readiness_calls)>=3
                prep.json_file(root/"io.json",{"observed_us":clock[0]//1000,"written_bytes":1,"read_bytes":1})
                return {"ready":ready,"bootstrapped":ready,"io_ready":True,"api_ready":True,"crypto_ready":True}
        def ingress(path,plan,address,rate,epoch,*args,**kwargs):
            ingress_epochs.append(epoch);kwargs["on_admit"](0);path.write_text("");return str(path)
        observer=self.mock_shoal_observer()
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote,"check_artifacts",return_value={}),\
             patch.object(remote.time,"clock_gettime_ns",side_effect=now),patch.object(remote.time,"sleep",side_effect=sleep),\
             patch.object(remote.native,"ShoalReadiness",Ready),patch.object(remote.native,"ShoalObserver",return_value=observer),patch.object(remote.subprocess,"Popen",side_effect=Process),\
             patch.object(remote.native.shoal_cohort,"ingress_to_journal",side_effect=ingress),\
             patch.object(remote.native,"archive_ledger",return_value=Mock(index_sha256="b"*64)),patch.object(remote.os,"kill"):
            self.assertEqual(remote.run_host(request),0)
        result=json.loads((root/"result.json").read_text());epoch=result["epoch_monotonic_ns"]
        self.assertEqual(ingress_epochs,[epoch//1000])
        self.assertEqual(result["omission_schedule"]["start_monotonic_ns"],epoch+100_000_000)
        self.assertGreater(epoch,result["startup"]["prepared_monotonic_ns"])
        self.assertGreater(result["startup"]["armed_monotonic_ns"],result["startup"]["prepared_monotonic_ns"])
        self.assertEqual(result["startup"]["epoch_monotonic_ns"],epoch)
        observer.arm.assert_called_once_with(epoch)
        observer.publisher.admit.assert_called_once_with(0)
        observer.await_receipt.assert_called_once_with(spawned)
        observer.close.assert_called_once()
        self.assertIsNotNone(spawned[0].poll())
        self.assertFalse(result["comparison_eligible"])

    def test_shoal_failed_preparation_has_no_epoch_arrivals_or_fault_interval(self):
        selected=self.selected("shoal");root=self.root/"failure";root.mkdir()
        request={"nonce":selected["nonce"],"plan_sha256":"a"*64,"settings":dict(selected["settings"],startup_seconds=1),"protocol":"shoal","host":selected["hosts"][0],"endpoint":selected["endpoints"][0]}
        clock=[1_000_000_000]
        def sleep(seconds):clock[0]+=250_000_000
        process=Mock();process.poll.return_value=None;events=[];result={}
        with patch.object(remote.native,"ShoalReadiness") as ready,patch.object(remote.time,"clock_gettime_ns",side_effect=lambda *args:clock[0]),patch.object(remote.time,"sleep",side_effect=sleep):
            ready.return_value.observe.return_value={"ready":False,"api_ready":True,"bootstrapped":False,"io_ready":False}
            with self.assertRaisesRegex(RuntimeError,"preparation timed out"):
                remote.prepare_and_arm_shoal(root,request,[process],events,result,clock[0])
        self.assertNotIn("epoch_monotonic_ns",result)
        self.assertFalse((root/"readiness.json").exists())
        self.assertFalse((root/"omission-interval.txt").exists())

    def test_shoal_prepared_host_times_out_without_a_committee_arm(self):
        selected=self.selected("shoal");root=self.root/"waiting";root.mkdir()
        request={"nonce":selected["nonce"],"plan_sha256":"a"*64,"settings":dict(selected["settings"],startup_seconds=1),"host":selected["hosts"][0],"endpoint":selected["endpoints"][0]}
        clock=[1_000_000_000];process=Mock();process.poll.return_value=None;result={}
        def sleep(seconds):clock[0]+=250_000_000
        with patch.object(remote.native,"ShoalReadiness") as ready,patch.object(remote.time,"clock_gettime_ns",side_effect=lambda *args:clock[0]),patch.object(remote.time,"sleep",side_effect=sleep):
            ready.return_value.observe.return_value={"ready":True}
            with self.assertRaisesRegex(RuntimeError,"committee arm timed out"):
                remote.prepare_and_arm_shoal(root,request,[process],[],result,clock[0])
        self.assertTrue((root/"readiness.json").is_file())
        self.assertNotIn("epoch_monotonic_ns",result["startup"])
        self.assertFalse((root/"omission-interval.txt").exists())

    def test_shoal_lost_readiness_after_barrier_cannot_select_an_epoch(self):
        selected=self.selected("shoal");root=self.root/"lost-ready";root.mkdir()
        request={"nonce":selected["nonce"],"plan_sha256":"a"*64,"settings":selected["settings"],"protocol":"shoal","host":selected["hosts"][0],"endpoint":selected["endpoints"][0]}
        clock=[1_000_000_000];process=Mock();process.poll.return_value=None;result={}
        def sleep(seconds):
            clock[0]+=100_000_000
            observed=remote.rpc(request|{"action":"readiness"})
            remote.rpc(request|{"action":"arm","readiness_sha256":observed["readiness_sha256"]})
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote.native,"ShoalReadiness") as ready,\
             patch.object(remote.time,"clock_gettime_ns",side_effect=lambda *args:clock[0]),patch.object(remote.time,"sleep",side_effect=sleep):
            ready.return_value.observe.side_effect=[{"ready":True},{"ready":False,"io_ready":False}]
            with self.assertRaisesRegex(RuntimeError,"readiness was lost"):
                remote.prepare_and_arm_shoal(root,request,[process],[],result,clock[0])
        self.assertNotIn("epoch_monotonic_ns",result["startup"])
        self.assertFalse((root/"omission-interval.txt").exists())

    def test_shoal_startup_control_calls_have_finite_transport_timeouts(self):
        selected=self.selected("shoal");connection=remote.Connection(selected["hosts"][0])
        request={"action":"readiness","settings":dict(selected["settings"],startup_seconds=3)}
        with patch.object(connection,"command",return_value=subprocess.CompletedProcess([],0,"{}","")) as command:
            connection.rpc_native(self.root,request)
            self.assertEqual(command.call_args.kwargs["timeout"],3)
            connection.rpc_native(self.root,request|{"action":"cleanup"})
            self.assertEqual(command.call_args.kwargs["timeout"],30)

    def test_shoal_preparation_failure_reaps_owned_process_without_launching_ingress(self):
        selected=self.selected("shoal");root=self.root/"failed-worker";(root/"fixture").mkdir(parents=True)
        prep.json_file(root/"fixture/authors.json",{str(i):str(i)*64 for i in range(4)})
        request={"nonce":selected["nonce"],"plan_sha256":"a"*64,"settings":selected["settings"],"protocol":"shoal","host":selected["hosts"][0],"endpoint":selected["endpoints"][0],"ips":[f"10.0.0.{i+1}" for i in range(4)]}
        process=Mock(pid=600);process.poll.return_value=None;process.wait.return_value=-15
        with patch.object(remote,"checked_root",return_value=root),patch.object(remote,"check_artifacts",return_value={}),\
             patch.object(remote.subprocess,"Popen",return_value=process),patch.object(remote.os,"kill") as kill,\
             patch.object(remote.native,"ShoalObserver",return_value=self.mock_shoal_observer()),\
             patch.object(remote,"prepare_and_arm_shoal",side_effect=RuntimeError("native Shoal preparation timed out")),\
             patch.object(remote.native.shoal_cohort,"ingress_to_journal") as ingress:
            self.assertEqual(remote.run_host(request),1)
        ingress.assert_not_called();process.terminate.assert_called_once();process.wait.assert_called_once_with(timeout=5)
        kill.assert_called_once_with(600,remote.signal.SIGCONT)
        result=json.loads((root/"result.json").read_text())
        self.assertIsNone(result["epoch_monotonic_ns"])
        self.assertIsNone(result["omission_schedule"])
        self.assertFalse((root/"omission-interval.txt").exists())

    def test_omission_uses_host_epoch_and_exact_native_recipient_identity(self):
        cfg=remote.native.settings({"rate":4,"warmup":0,"duration":1,"faulty":[0],"omit_replica":0,
            "omission_after":.1,"omission_seconds":.2,"publish_to_replica":[1],"attacker_rate":2},4,"autobahn")
        self.assertEqual(cfg["rates"][0],2)
        self.assertNotIn(0,cfg["correct"])
        ips=[f"10.0.0.{i+1}" for i in range(4)]
        worker=remote.native.fault_environment("autobahn",self.root,0,"worker-0",cfg,ips)
        primary=remote.native.fault_environment("autobahn",self.root,0,"primary",cfg,ips)
        self.assertEqual(worker["BENCHMARK_FAULT_ALLOWED"],"10.0.0.2:9011")
        self.assertFalse(any(key.startswith("BENCHMARK_FAULT_") for key in primary))
        args=remote.native.SimpleNamespace(**cfg,faulty_replica=cfg["faulty"],nodes=4)
        schedule=remote.native.native_faults.arm(args,self.root,9000000000000)
        self.assertEqual(schedule["start_monotonic_ns"],9000100000000)
        self.assertEqual(schedule["end_monotonic_ns"],9000300000000)

    def test_native_netem_selects_every_peer_role_but_excludes_client_and_control_ports(self):
        publication=self.publication("autobahn")
        for host in publication["inventory"]["hosts"]:host["network_interface"]="ens5"
        selected=remote.plan(publication,{"rate":4,"duration":1,"network":{"delay_ms":10,"loss_percent":0}})
        connections={i:Mock() for i in range(4)}
        network=remote.NativeNetwork(selected,Path("/tmp/fixture"),connections)
        baseline=[{"source":i,"destination":(i+1)%4,"protocol_role_index":role,"median_rtt_ms":1,"samples_ms":[1]*20} for role in range(3) for i in range(4)]
        delayed=[dict(row,median_rtt_ms=21,samples_ms=[21]*20) for row in baseline]
        network.start_echoes=Mock(return_value=[]);network.stop_echoes=Mock()
        network.calibrate_ring=Mock(side_effect=[baseline,delayed])
        network.netem_rpc=Mock(return_value={"active_objects_complete":True,"physical_qdisc_configuration_unchanged":True})
        result=network.configure_network()
        self.assertEqual(len(result["calibration"]),12)
        self.assertTrue(all(row["delay_within_calibration_tolerance"] for row in result["calibration"]))
        request=network.netem_rpc.call_args_list[0].args[1]
        self.assertEqual(request["local_ports"],[9000,9001,9005])
        self.assertEqual(len(request["peers"]),9)
        self.assertNotIn(9004,[row["port"] for row in request["peers"]])
        self.assertEqual(network.remote_python(network.hosts[0]),sys.executable)
        network.calibrate_ring=Mock(return_value=baseline)
        network.netem_rpc=Mock(return_value={"phase":"cleared","physical_qdisc_configuration_unchanged":True})
        network.clear_network()
        self.assertFalse(network.netem_hosts)
        self.assertTrue(all(row["returned_to_baseline"] for row in network.network_evidence["cleanup_calibration"]))


if __name__=="__main__":unittest.main()
