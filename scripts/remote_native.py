#!/usr/bin/env python3
"""Fixed native protocols on explicit existing hosts; default is a local plan.

Python>=3.11 is an explicit remote prerequisite. No generic remote shell recipe,
cloud creation, or cross-host timestamp subtraction is exposed by this command.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import gzip
import json
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import sys
import time
import uuid

import deployment_prepare as prep
import remote_worker
import linux_netem
import linux_egress
import runtime_evidence
from native_network import NativeNetwork, observed_wan
sys.path.insert(0,str(Path(__file__).with_name("baselines")))
import native_placement as native

MAX_LEDGER=64*1024**2
PROTOCOLS=("mysticeti","autobahn","autobahn-blips","shoal","simpleit-mempool","simpleit-dispersed")
RUNTIME_FILES=tuple(dict.fromkeys((*prep.CONTROLLER_COMMON,*prep.CONTROLLER_NATIVE,
    "scripts/remote_native.py","scripts/native_network.py","scripts/runtime_evidence.py","scripts/baselines/native_placement.py","scripts/baselines/native_cohort_store.py","scripts/cohort_store.py",
    "scripts/baselines/mysticeti.py","scripts/baselines/autobahn_cohort.py","scripts/baselines/shoal_cohort.py","scripts/baselines/shoal_receipts.py")))
# Native adapters share controller modules. Bind the complete Python runtime,
# never checkout contents, secrets, caches, raw results or generated keys.
RUNTIME_FILES=tuple(sorted(set(RUNTIME_FILES)|{p.relative_to(prep.ROOT).as_posix()
    for p in (prep.ROOT/'scripts').rglob('*.py') if '__pycache__' not in p.parts}))


def interpreter(host):
    selected=host.get("python_executable")
    if not isinstance(selected,str) or not selected.startswith("/") or ".." in Path(selected).parts:
        raise ValueError("native host requires an explicit absolute Python>=3.11 executable")
    return selected


def pin_for(protocol):
    pins=json.loads((prep.ROOT/"provenance/baselines.json").read_text())["baselines"]
    pin=dict(pins["autobahn" if protocol=="autobahn-blips" else protocol])
    if protocol=="autobahn-blips":pin.update(pin["disruption_artifact"])
    result={"commit":pin["commit"],"patch_sha256":prep.sha(prep.ROOT/pin["instrumentation_patch"])}
    if protocol=="shoal":result["observer_contract"]=pin.get("observer_contract")
    return result


def plan(publication, values):
    protocol=publication["protocol"]
    if protocol not in PROTOCOLS:raise ValueError("fixed native protocol required")
    hosts=sorted(json.loads(json.dumps(publication["inventory"]["hosts"])),key=lambda host:host["replica"]);prep.validate_hosts({"schema":1,"hosts":hosts})
    values=copy_json(values);network=values.pop("network",None)
    cfg=native.settings(values,len(hosts),protocol);receipts=publication["receipts"]
    selected=prep.recipe(protocol);pin=pin_for(protocol);build_recipe=None
    if protocol=="shoal" and pin.get("observer_contract")!=native.SHOAL_OBSERVER_CONTRACT:
        raise ValueError("Shoal artifact does not declare the required finite observer contract")
    for host in hosts:
        interpreter(host)
        receipt=receipts[str(host["replica"])] if str(host["replica"]) in receipts else receipts[host["replica"]]
        prep.validate_receipt(receipt,receipt["recipe"],receipt["source_bundle_sha256"])
        if receipt["protocol"]!=protocol or receipt["recipe"]["binaries"]!=selected["binaries"]:raise ValueError("publication protocol mismatch")
        if build_recipe is not None and receipt["recipe"]!=build_recipe:raise ValueError("native publication mixes build recipes")
        build_recipe=receipt["recipe"]
        host["native_binaries"]={row["name"]:row for row in receipt["binaries"]}
    if len({row["source_bundle_sha256"] for row in receipts.values()})!=1:raise ValueError("native publication mixes source bundles")
    ips=[host["advertised"].rsplit(":",1)[0] for host in sorted(hosts,key=lambda h:h["replica"])]
    if len(set(ips))!=len(hosts):raise ValueError("one distinct private address per native validator required")
    selected={"schema":1,"protocol":protocol,"nonce":uuid.uuid4().hex,"hosts":hosts,"settings":cfg,"network":network,
            "pin":pin,"build_recipe":copy_json(build_recipe),"source_bundle_sha256":next(iter(receipts.values()))["source_bundle_sha256"],
            "endpoints":native.endpoints(protocol,ips),"runtime_sources":{name:prep.sha(prep.ROOT/name) for name in RUNTIME_FILES},
            "evidence_envelope":runtime_evidence.envelope(),
            "eligibility":"placement scripts locally tested; remote/native acceptance is not inferred",
            "limitations":["No synchronized global clock assumed; origins use their own host's monotonic epoch.",
                "Native cohort postprocessing uses bounded schema2 pages and disk-backed reduction; native custody/live materializer state still grows with workload. Runtime evidence transfer has a separately declared disk envelope.",
                "Native metrics may bind wildcard addresses; private firewall/security-group isolation is a prerequisite.",
                "Shoal instrumentation/compiled native acceptance is separately recorded; no formal comparison eligibility here.",
                "Native endpoint/calibration and omission scripts have only local mocked acceptance; no remote performance claim."]}
    validate_network(selected)
    return selected


def copy_json(value):return json.loads(json.dumps(value))


def validate_network(selected):
    network=selected.get("network")
    if network is None:return
    if set(network)-{"delay_ms","loss_percent","rate_mbps","mode"}:raise ValueError("unknown native network setting")
    observed_wan(network)
    if 'rate_mbps' in network and network.get('loss_percent',0)!=0:raise ValueError('aggregate egress profile does not silently combine ingress loss')
    for host in selected["hosts"]:
        i=host["replica"]
        request={"action":"configure","nonce":selected["nonce"],"interface":host.get("network_interface"),
            "peers":[peer for row in selected["endpoints"] if row["replica"]!=i for peer in row["peer"]],
            "local_ports":[peer["port"] for peer in selected["endpoints"][i]["peer"]],
            "delay_ms":network.get("delay_ms",0),"loss_percent":network.get("loss_percent",0)}
        if 'rate_mbps' in network:
            request.pop('loss_percent');request['rate_mbps']=network['rate_mbps'];linux_egress.validate_request(request)
        else:linux_netem.validate_request(request)


def root_for(nonce):
    if not re.fullmatch("[0-9a-f]{32}",nonce):raise ValueError("invalid native run nonce")
    return Path("/tmp")/("delugi-native-"+nonce)


def checked_root(request):
    root=root_for(request["nonce"])
    if root.is_symlink() or not root.is_dir() or root.stat().st_uid!=os.getuid():raise ValueError("unowned native directory")
    state=json.loads((root/"owner.json").read_text())
    if state.get("nonce")!=request["nonce"] or state.get("plan_sha256")!=request["plan_sha256"]:raise ValueError("native ownership identity differs")
    return root


def bounded_json(path,limit=MAX_LEDGER):
    if Path(path).stat().st_size>limit:raise ValueError("native evidence exceeds declared ledger envelope")
    return json.loads(Path(path).read_text())


def startup_identity(request):
    return {"nonce": request["nonce"], "plan_sha256": request["plan_sha256"],
            "replica": request["host"]["replica"]}


def publish_startup(root, name, value):
    """Publish a complete, one-shot control file without replacing evidence."""
    path = root / name
    temporary = root / (name + ".pending")
    with temporary.open("x") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink()


def startup_record(root, name, request):
    row = bounded_json(root / name, 65536)
    if any(row.get(key) != value for key, value in startup_identity(request).items()):
        raise ValueError("native startup nonce/plan/replica identity differs")
    return row


def check_startup_abort(root, request):
    if (root / "abort.json").exists():
        startup_record(root, "abort.json", request)
        raise RuntimeError("native Shoal startup was aborted by the controller")


def prepare_and_arm_shoal(root, request, processes, events, result, started_ns, observer=None):
    """Prepare without arrivals, then accept the controller's committee barrier."""
    cfg = request["settings"]
    deadline = started_ns + cfg["startup_seconds"] * 1_000_000_000
    readiness = native.ShoalReadiness(root, request["host"]["replica"],
                                     request["endpoint"]["control_port"], started_ns, cfg["crypto_meter"],
                                     observer_plan=observer.plan if observer is not None else None)
    result["startup"] = {"policy": "all-host native bootstrap, validated counters and REST200 before host-local arm",
                         "prepare_started_monotonic_ns": started_ns, "prepare_deadline_monotonic_ns": deadline,
                         "arm_deadline_monotonic_ns": deadline + cfg["startup_seconds"] * 1_000_000_000}
    events.append({"event": "prepare_started", "monotonic_ns": started_ns})
    while True:
        check_startup_abort(root, request)
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("native process exited during preparation")
        observed = readiness.observe()
        now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        result["startup"]["readiness"] = observed
        if now >= deadline:
            raise RuntimeError("native Shoal preparation timed out before the workload was armed")
        if observed["ready"]:
            break
        time.sleep(.05)
    prepared = startup_identity(request) | {"state": "prepared", "prepared_monotonic_ns": now, "readiness": observed}
    publish_startup(root, "readiness.json", prepared)
    result["startup"]["prepared_monotonic_ns"] = now
    events.append({"event": "prepared", "monotonic_ns": now})
    while True:
        check_startup_abort(root, request)
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("native process exited while awaiting committee arm")
        now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        if now >= result["startup"]["arm_deadline_monotonic_ns"]:
            raise RuntimeError("native Shoal committee arm timed out; no workload admitted")
        if (root / "arm.json").exists():
            intent = startup_record(root, "arm.json", request)
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            if (intent.get("state") != "arm_requested"
                    or type(intent.get("requested_monotonic_ns")) is not int
                    or not prepared["prepared_monotonic_ns"] <= intent["requested_monotonic_ns"] <= now
                    or intent.get("readiness_sha256") != prep.sha(root / "readiness.json")):
                raise ValueError("native arm does not bind this preparation receipt")
            observed = readiness.observe()
            if not observed["ready"]:
                raise RuntimeError("native Shoal readiness was lost before arm")
            now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
            if now >= result["startup"]["arm_deadline_monotonic_ns"]:
                raise RuntimeError("native Shoal committee arm missed its deadline")
            epoch = now + 100_000_000
            result["startup"].update(arm_intent=intent, armed_monotonic_ns=now, arm_readiness=observed,
                                     epoch_monotonic_ns=epoch)
            events.append({"event": "armed", "monotonic_ns": now, "epoch_monotonic_ns": epoch})
            return epoch
        time.sleep(.05)


def check_artifacts(request):
    host=request["host"];version=list(sys.version_info[:3])
    if version[:2]<[3,11] or Path(sys.executable).resolve()!=Path(interpreter(host)).resolve():raise ValueError("selected Python>=3.11 interpreter was not used")
    if request["protocol"]=="shoal" and request["pin"].get("observer_contract")!=native.SHOAL_OBSERVER_CONTRACT:
        raise ValueError("Shoal artifact finite observer contract is unsupported")
    build_recipe=request["build_recipe"]
    if build_recipe!=prep.recipe(request["protocol"],build_recipe["jobs"],build_recipe["toolchain"]):raise ValueError("native build recipe differs from fixed reviewed commands")
    if set(host["native_binaries"])!=set(prep.recipe(request["protocol"])["binaries"]):raise ValueError("native binary role inventory differs")
    identities={}
    for name,row in host["native_binaries"].items():
        if prep.sha(row["path"])!=row["sha256"]:raise ValueError("native executable hash differs")
        stamp=bounded_json(row["path"]+".build.json",32*1024**2)
        provenance=stamp.get("provenance",{})
        if (stamp.get("binary_sha256")!=row["sha256"] or stamp.get("source_bundle_sha256")!=request["source_bundle_sha256"]
                or provenance.get("protocol")!=request["protocol"] or provenance.get("commit")!=request["pin"]["commit"]
                or provenance.get("patch_sha256")!=request["pin"]["patch_sha256"]):raise ValueError("native artifact source/patch stamp differs")
        if stamp.get("recipe")!=build_recipe:raise ValueError("native artifact build recipe differs from publication")
        identities[name]={"sha256":row["sha256"],"stamp_sha256":prep.sha(row["path"]+".build.json")}
    return {"python":sys.executable,"python_realpath":str(Path(sys.executable).resolve()),"python_version":version,
            "python_sha256":prep.sha(sys.executable),"artifacts":identities}


def archive_selected(root, names, destination, kind, metadata=None):
    entries={}
    for name in names:
        prep.relative(name);path=Path(root)/name
        if path.is_symlink():raise ValueError("native evidence/configuration symlink refused")
        entries[name]=(path,prep.file_entry(path,root))
    if len(entries)>prep.MAX_FILES or sum(entry["bytes"] for _,entry in entries.values())>prep.MAX_BYTES:raise ValueError("native archive exceeds envelope")
    manifest=Path(destination).with_suffix(".manifest.json")
    prep.json_file(manifest,{"schema":1,"kind":kind,"metadata":metadata or {},"files":{name:entry for name,(_,entry) in entries.items()}})
    entries["manifest.json"]=(manifest,prep.file_entry(manifest,manifest.parent))
    prep.archive_files(destination,entries)
    return {"sha256":prep.sha(destination),"bytes":Path(destination).stat().st_size}


def rpc(request):
    action=request["action"]
    if action=="preflight":return check_artifacts(request)
    root=checked_root(request)
    if action in ("readiness", "arm"):
        if request["protocol"] != "shoal" and not request['protocol'].startswith('simpleit'):raise ValueError("prepare/arm is unsupported by this native adapter")
        check_startup_abort(root, request)
        if (root / "result.json").exists():
            return {"state": "finished", "result_status": bounded_json(root / "result.json")["status"]}
        if not (root / "readiness.json").exists():
            if action == "arm":raise RuntimeError("native Shoal cannot arm before preparation")
            return startup_identity(request) | {"state": "preparing"}
        prepared = startup_record(root, "readiness.json", request)
        if prepared.get("state") != "prepared" or prepared.get("readiness", {}).get("ready") is not True:
            raise ValueError("native preparation receipt is not ready")
        digest = prep.sha(root / "readiness.json")
        if action == "readiness":return prepared | {"readiness_sha256": digest}
        if request.get("readiness_sha256") != digest:raise ValueError("native preparation changed before arm")
        if not (root / "arm.json").exists():
            publish_startup(root, "arm.json", startup_identity(request) | {"state": "arm_requested",
                "readiness_sha256": digest, "requested_monotonic_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC)})
        intent = startup_record(root, "arm.json", request)
        if intent.get("readiness_sha256") != digest:raise ValueError("native arm preparation identity differs")
        return intent
    if action=="generate":
        check_artifacts(request)
        selected=native.generate(request["protocol"],root,request["ips"],{name:row["path"] for name,row in request["host"]["native_binaries"].items()},request["settings"],request["nonce"])
        return {str(i):archive_selected(root,[str(path.relative_to(root)) for path in names],root/f"configuration-{i}.tar","native-configuration",{"replica":i,"nonce":request["nonce"]}) for i,names in enumerate(selected)}
    if action=='seal_configuration':
        # Host0 is a temporary ceremony host. Remove all other validators' keys
        # and the TLS CA private key before any validator process starts.
        marker=root/'configuration-sealed.json'
        if marker.exists():
            prior=bounded_json(marker)
            if prior.get('own_archive_sha256')!=request['sha256']:raise ValueError('ceremony seal belongs to another archive')
            return prior
        archive=root/'configuration-0.tar';expected=request['sha256']
        if prep.sha(archive)!=expected:raise ValueError('ceremony archive changed before sealing')
        own=root/'own-configuration';own.mkdir(mode=0o700)
        manifest=prep.unpack_verified(archive,own,expected)
        if manifest.get('metadata')!={'replica':0,'nonce':request['nonce']}:raise ValueError('wrong ceremony owner')
        shutil.rmtree(root/'fixture');(own/'fixture').rename(root/'fixture')
        # Archive extraction normalizes files to0644. Apply the same private
        # configuration permissions as install before launching host0; the
        # native TLS implementation correctly refuses a world-readable key.
        for path in (root/'fixture').rglob('*'):
            if path.is_file():path.chmod(0o600)
        for path in root.glob('configuration-*.tar'):
            if path.is_symlink():raise ValueError('linked ceremony archive refused')
            path.unlink()
        value={'sealed':True,'replica':0,'own_archive_sha256':expected};prep.json_file(marker,value);return value
    if action=="install":
        manifest=prep.unpack_verified(root/"configuration.tar",root/"incoming",request["sha256"])
        if manifest.get("metadata")!={"replica":request["replica"],"nonce":request["nonce"]}:raise ValueError("wrong replica configuration archive")
        (root/"incoming/fixture").rename(root/"fixture")
        for path in (root/"fixture").rglob("*"):
            if path.is_file():path.chmod(0o600)
        return {"installed":True}
    if action=="collect":
        result=bounded_json(root/"result.json")
        return {"format":runtime_evidence.FORMAT,"metadata":{"nonce":request["nonce"],
            "replica":result["replica"],"plan_sha256":request["plan_sha256"]}}
    if action=="status":return bounded_json(root/"result.json") if (root/"result.json").exists() else {"status":"running"}
    if action=="cleanup":
        # A cancellation tombstone also covers a dispatched worker that has not
        # written process.json yet. It must never start arrivals after cleanup.
        if (request.get("protocol") == "shoal" or request.get('protocol','').startswith('simpleit')) and not (root / "abort.json").exists():
            publish_startup(root, "abort.json", startup_identity(request) | {"state": "abort_requested",
                "requested_monotonic_ns": time.clock_gettime_ns(time.CLOCK_MONOTONIC)})
        state_path=root/"process.json"
        if not state_path.exists():return {"state":"not_started"}
        prior=bounded_json(state_path)
        if prior.get("nonce")!=request["nonce"]:raise ValueError("native process nonce differs")
        if "exit_code" in prior:
            if prior.get("owned_group_cleanup",{}).get("group_empty") is not True:
                raise RuntimeError("owned native group cleanup was not confirmed")
            return {"state":"finished","exit_code":prior["exit_code"]}
        state=remote_worker.owned_state(state_path,request["nonce"])
        os.killpg(state["pid"],signal.SIGCONT);os.killpg(state["pid"],signal.SIGTERM)
        return {"state":"owned_termination_requested"}
    raise ValueError("unsupported fixed native action")


def run_host(request):
    root=checked_root(request);preflight=check_artifacts(request);cfg=request["settings"];protocol=request["protocol"];index=request["host"]["replica"]
    if protocol.startswith('simpleit'):
        from baselines import simpleit_remote
        return simpleit_remote.run_host(request,root,preflight)
    if cfg['case']=='silent-first-leader' and index==1:
        proof=native.first_leader_record(protocol,root,index)
        # No native process is launched. The owned supervisor still attests the
        # absent replica's configuration and participates in normal cleanup.
        result={'status':'completed','replica':index,'preflight':preflight,'silent_leader':True,
            'cohort_excluded':True,'native_processes_started':0,'first_leader':proof,
            'fault_interval':'absent from protocol startup through the complete trial',
            'comparison_eligible':False}
        prep.json_file(root/'result.json',result)
        (root/'host-events.jsonl').write_text(json.dumps({'event':'first_leader_not_started',**proof})+'\n')
        return 0
    if protocol=='mysticeti':
        # Genesis creates empty storage directories on the ceremony host. Empty
        # directories are deliberately not in per-host configuration archives.
        # Recreate only this validator's owned directory before opening its WAL.
        (root/'fixture/genesis'/f'storage-{index}').mkdir(mode=0o700)
    # Clock origin is selected on this host, never copied from the controller.
    startup_started=time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    epoch=None if protocol=="shoal" else startup_started+cfg["startup_seconds"]*1_000_000_000
    entries=native.launches(protocol,root,index,{name:row["path"] for name,row in request["host"]["native_binaries"].items()},cfg,sys.executable,epoch)
    processes=[];logs=[];app=None;admitted=None;observer=None;pool=None;events=[];result={"status":"failed","replica":index,"epoch_monotonic_ns":epoch,"preflight":preflight,"comparison_eligible":False}
    (root/"logs").mkdir()
    args=native.SimpleNamespace(**cfg,faulty_replica=cfg["faulty"],nodes=len(cfg["rates"]))
    result["omission_schedule"]=native.native_faults.arm(args,root,epoch) if protocol!="shoal" and index==cfg["omit_replica"] else None
    def launch(name,argv,values):
        output=(root/"logs"/(name+".log")).open("wb");logs.append(output)
        env=native.child_environment(protocol,values)
        process=subprocess.Popen(argv,cwd=root,env=env,stdout=output,stderr=subprocess.STDOUT)
        processes.append(process);events.append({"event":"launch","role":name,"pid":process.pid,"argv":argv,"monotonic_ns":time.clock_gettime_ns(time.CLOCK_MONOTONIC)})
        return process
    try:
        if protocol=="shoal":
            check_startup_abort(root, request)
            observer=native.ShoalObserver(root,index,cfg)
        for name,argv,env in entries:
            env.update(native.fault_environment(protocol,root,index,name,cfg,request["ips"]))
            if observer is not None:env.update(observer.environment())
            launch(name,argv,env)
        control=request["endpoint"]["control_port"]
        port=control if control is not None else 9004+6*index
        while protocol!="shoal":
            if any(p.poll() is not None for p in processes):raise RuntimeError("native process exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.2):pass
                break
            except OSError:
                if time.clock_gettime_ns(time.CLOCK_MONOTONIC)>=epoch:raise RuntimeError("native startup missed declared host-local epoch")
                time.sleep(.05)
        if protocol=="shoal":
            epoch=prepare_and_arm_shoal(root,request,processes,events,result,startup_started,observer)
            result["epoch_monotonic_ns"]=epoch
            observer.arm(epoch)
            result["omission_schedule"]=native.native_faults.arm(args,root,epoch) if index==cfg["omit_replica"] else None
            if time.clock_gettime_ns(time.CLOCK_MONOTONIC)>=epoch:
                raise RuntimeError("native Shoal missed the armed local epoch before ingress")
        app_argv=native.application(protocol,root,index,cfg,sys.executable,epoch)
        native_processes=list(processes)
        if app_argv:app=launch("application",app_argv,{})
        if protocol=="shoal":
            pool=concurrent.futures.ThreadPoolExecutor(max_workers=1)
            admitted=root/"admitted.jsonl"
            arrival=pool.submit(native.shoal_cohort.ingress_to_journal,admitted,root/"fixture"/f"plan-{index}.jsonl","http://127.0.0.1:8001",cfg["rates"][index],epoch//1000,int(cfg["warmup"]*1e6),int(cfg["duration"]*1e6),int(cfg["drain"]*1e6),on_admit=observer.publisher.admit)
        before=None;after=None;cpu_before=None;cpu_after=None;paused=False;resumed=False;started=False
        end=epoch+int((cfg["warmup"]+cfg["duration"]+cfg["drain"])*1e9)
        while time.clock_gettime_ns(time.CLOCK_MONOTONIC)<end:
            now=time.clock_gettime_ns(time.CLOCK_MONOTONIC);elapsed=(now-epoch)/1e9
            if not started and now>=epoch:
                if protocol=="mysticeti":(root/"arrivals.start").touch()
                events.append({"event":"arrival_epoch_released","monotonic_ns":now});started=True
            if any(p.poll() is not None for p in native_processes):raise RuntimeError("native validator exited")
            if app and app.poll() not in (None,0):raise RuntimeError("native application collector exited")
            if protocol=="mysticeti":
                if before is None and elapsed>=cfg["warmup"]:before=native.mysticeti.snapshot(control)
                if after is None and elapsed>=cfg["warmup"]+cfg["duration"]:after=native.mysticeti.snapshot(control)
            if protocol=="shoal":
                if before is None and elapsed>=cfg["warmup"]:before=bounded_json(root/"io.json")
                if after is None and elapsed>=cfg["warmup"]+cfg["duration"]:after=bounded_json(root/"io.json")
            if cfg["crypto_meter"]=="on":
                if cpu_before is None and elapsed>=cfg["warmup"]:cpu_before=native.native_faults.cpu_snapshot(root)
                if cpu_after is None and elapsed>=cfg["warmup"]+cfg["duration"]:cpu_after=native.native_faults.cpu_snapshot(root)
            if index==cfg["pause_replica"]:
                if not paused and elapsed>=cfg["warmup"]+cfg["pause_after"]:
                    for p in native_processes:os.kill(p.pid,signal.SIGSTOP)
                    events.append({"event":"native_pause","monotonic_ns":now});paused=True
                if paused and not resumed and elapsed>=cfg["warmup"]+cfg["pause_after"]+cfg["pause_seconds"]:
                    for p in native_processes:os.kill(p.pid,signal.SIGCONT)
                    events.append({"event":"native_resume","monotonic_ns":now});resumed=True
            time.sleep(.002)
        if app and app.wait(timeout=5)!=0:raise RuntimeError("native application failed")
        if protocol=="shoal":
            arrival.result(timeout=2);pool.shutdown();pool=None
            # A complete native batch may finish after the declared cutoff.
            # Its actual frozen endpoint is retained, never backdated.
            observer.await_receipt(native_processes)
        if protocol=="mysticeti":
            final=native.mysticeti.snapshot(control)
            result["traffic"]={"before":before,"after":after,"final":final,"boundary":"native successful replica stream writes; scrape intervals host-local"}
        elif protocol.startswith("autobahn"):
            result["traffic"]={"processes":[bounded_json(root/"observer"/role/"io.json") for role in ("primary","worker-0")],"boundary":"native successful replica stream writes including host-local worker links"}
        else:
            final=bounded_json(root/"io.json")
            result["traffic"]={"before":before,"after":after,"final":final,"boundary":"native underlying TCP including encrypted framing/authentication; REST ingress excluded","native_acceptance":"source hooks; built end-to-end gate remains separate"}
        result["omission_observation"]=native.native_faults.collect_omissions(root)
        if cfg["crypto_meter"]=="on":
            final_cpu=native.native_faults.cpu_snapshot(root)
            if (not cpu_before or len(cpu_before)!=len(entries)
                    or set(cpu_before)!=set(cpu_after or {}) or set(cpu_before)!=set(final_cpu)):
                raise ValueError("native crypto sample is missing or changed a process")
            result["crypto_cpu"]=native.native_faults.cpu_ledger(cpu_before,cpu_after,final_cpu)
        result["cost_scope"]={"final_sample_completed_monotonic_ns":time.clock_gettime_ns(time.CLOCK_MONOTONIC),
            "boundary":"last native counter samples before SIGSTOP and shutdown; processes were still running while sampled",
            "complete_setup_through_shutdown_cost":False,
            "excluded_tail":"writes and crypto after the final sample, including native shutdown; resource-wrapper CPU totals are separately retained"}
        for p in native_processes:os.kill(p.pid,signal.SIGSTOP)
        archive=observer.archive(epoch,admitted) if observer is not None else native.archive_ledger(protocol,root,index,cfg,epoch,admitted)
        if observer is not None:result["native_observer"]=observer.evidence()
        result["cohort_archive"]={"path":"cohorts/index.json","sha256":archive.index_sha256,"schema":2}
        result.update(status="completed",clock="origin ingress and materialization on this host only")
    except BaseException as error:
        result["error"]=f"{type(error).__name__}: {error}"
    finally:
        for p in processes:
            if p.poll() is None:os.kill(p.pid,signal.SIGCONT);p.terminate()
        for p in processes:
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        if pool is not None:pool.shutdown(wait=True,cancel_futures=True)
        if observer is not None:observer.close()
        for stream in logs:stream.close()
        (root/"host-events.jsonl").write_text("".join(json.dumps(row)+"\n" for row in events))
        result["finished_monotonic_ns"]=time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        prep.json_file(root/"result.json",result)
    return 0 if result["status"]=="completed" else 1


class Connection(prep.Connection):
    def rpc_native(self,root,request):
        limits = {"timeout": min(10, request["settings"]["startup_seconds"])} if request["action"] in ("readiness", "arm") else {}
        if request["action"] == "cleanup":limits = {"timeout": 30}
        return json.loads(self.command([interpreter(self.host),str(root/"controller/scripts/remote_native.py"),"_rpc"],input=json.dumps(request),text=True,capture_output=True,**limits).stdout)


def arm_prepared_shoal(connections, requests, root, futures, evidence):
    """All hosts prepare before any arm request; epochs are chosen on each host."""
    allowance = next(iter(requests.values()))["settings"]["startup_seconds"]
    deadline = time.monotonic() + 2*allowance
    evidence.update(policy="all prepared before concurrent host-local arm", prepared={}, arms={},
                    controller_started_monotonic_ns=time.monotonic_ns())
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as controls:
        while len(evidence["prepared"]) != len(connections):
            if any(future.done() for future in futures.values()):
                raise RuntimeError("native supervisor ended before committee preparation/arm")
            pending = {i: controls.submit(connection.rpc_native, root, requests[i] | {"action": "readiness"})
                       for i, connection in connections.items() if i not in evidence["prepared"]}
            for i, future in pending.items():
                observed = future.result()
                if any(observed.get(key) != value for key, value in startup_identity(requests[i]).items()):
                    raise ValueError("native readiness response identity differs")
                if observed.get("state") == "prepared":
                    if (observed.get("readiness", {}).get("ready") is not True
                            or not re.fullmatch("[0-9a-f]{64}", observed.get("readiness_sha256", ""))):
                        raise ValueError("native readiness response lacks a bound ready receipt")
                    evidence["prepared"][i] = observed
                elif observed.get("state") != "preparing":
                    raise RuntimeError("native host failed before committee preparation/arm")
            if time.monotonic() >= deadline:
                raise RuntimeError("native committee preparation timed out; no arm sent")
            if len(evidence["prepared"]) != len(connections):time.sleep(.05)
        # A host dying between this barrier and receipt processing is rejected
        # by its host worker. No controller time is used as a workload epoch.
        evidence["controller_all_prepared_monotonic_ns"] = time.monotonic_ns()
        pending = {i: controls.submit(connection.rpc_native, root, requests[i] | {"action": "arm",
                    "readiness_sha256": evidence["prepared"][i]["readiness_sha256"]})
                   for i, connection in connections.items()}
        for i, future in pending.items():
            intent = future.result()
            if (any(intent.get(key) != value for key, value in startup_identity(requests[i]).items())
                    or intent.get("state") != "arm_requested"
                    or intent.get("readiness_sha256") != evidence["prepared"][i]["readiness_sha256"]):
                raise ValueError("native arm response identity differs")
            evidence["arms"][i] = intent
    evidence["controller_finished_monotonic_ns"] = time.monotonic_ns()


def execute(selected, output, connection_factory=Connection):
    if connection_factory is Connection:
        from aliyun_bench import campaign_connections
        with campaign_connections(Connection) as factory:
            return execute(selected, output, factory)
    if selected["protocol"] not in PROTOCOLS:raise ValueError("unsupported native protocol")
    prep.validate_hosts({"schema":1,"hosts":selected["hosts"]})
    for host in selected["hosts"]:interpreter(host)
    cfg=selected["settings"]
    if cfg!=native.settings({key:value for key,value in cfg.items() if key not in ("correct","rates","counts")},len(selected["hosts"]),selected["protocol"]):
        raise ValueError("native finite settings were changed after derivation")
    ips=[host["advertised"].rsplit(":",1)[0] for host in selected["hosts"]]
    if selected["endpoints"]!=native.endpoints(selected["protocol"],ips):raise ValueError("native endpoint plan differs")
    if selected.get("evidence_envelope")!=runtime_evidence.envelope():raise ValueError("native evidence envelope differs")
    validate_network(selected)
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    if selected["runtime_sources"]!={name:prep.sha(prep.ROOT/name) for name in RUNTIME_FILES}:raise ValueError("native controller source changed after planning")
    if selected["pin"]!=pin_for(selected["protocol"]):raise ValueError("native patch/pin changed after planning")
    build_recipe=selected["build_recipe"]
    if build_recipe!=prep.recipe(selected["protocol"],build_recipe["jobs"],build_recipe["toolchain"]):raise ValueError("native build recipe differs from fixed reviewed commands")
    prep.json_file(output/"plan.json",selected);plan_hash=prep.sha(output/"plan.json")
    root=root_for(selected["nonce"]);connections={};requests={}
    archive_selected(prep.ROOT,RUNTIME_FILES,output/"runtime.tar","native-runtime")
    runtime_hash=prep.sha(output/"runtime.tar")
    def req(host):
        return {"nonce":selected["nonce"],"plan_sha256":plan_hash,"protocol":selected["protocol"],"host":host,
            "pin":selected["pin"],"build_recipe":build_recipe,"source_bundle_sha256":selected["source_bundle_sha256"],"settings":selected["settings"],
            "endpoint":selected["endpoints"][host["replica"]],"ips":[row["peer"][0]["ip"] for row in selected["endpoints"]]}
    # Bootstrap source uses Python3.8 syntax; the explicit selected interpreter is
    # checked before executing the controller modules that require tomllib.
    bootstrap="""import json,os,sys
from pathlib import Path
if sys.version_info<(3,11):raise ValueError('native placement requires Python>=3.11 for the packaged controller tomllib dependency')
p=Path(sys.argv[1]);p.mkdir(mode=0o700);(p/'incoming').mkdir()
(p/'owner.json').write_text(json.dumps({'nonce':sys.argv[2],'plan_sha256':sys.argv[3]}))
"""
    result={"status":"failed","comparison_eligible":False,"nonce":selected["nonce"],"hosts":{}};network=None
    try:
        for host in selected["hosts"]:
            connection=connection_factory(host);connections[host["replica"]]=connection;request=req(host);requests[host["replica"]]=request
            connection.command([interpreter(host),"-c",bootstrap,str(root),selected["nonce"],plan_hash],capture_output=True)
            connection.upload(prep.__file__,str(root/"deployment_prepare.py"));connection.upload(output/"runtime.tar",str(root/"runtime.tar"))
            # The bounded extractor is the just-uploaded exact preparation helper.
            # Keep the original scripts/ hierarchy so relative imports are exact.
            code="import sys;sys.path.insert(0,sys.argv[1]);import deployment_prepare as p;from pathlib import Path;d=Path(sys.argv[1])/'controller';d.mkdir();p.unpack_verified(Path(sys.argv[1])/'runtime.tar',d,sys.argv[2])"
            connection.command([interpreter(host),"-c",code,str(root),runtime_hash],capture_output=True)
            result["hosts"][host["replica"]]=connection.rpc_native(root,request|{"action":"preflight"})
        generated=connections[0].rpc_native(root,requests[0]|{"action":"generate"})
        result["configuration_archives"]=generated
        for host in selected["hosts"]:
            i=host["replica"]
            if i==0:continue
            archive=output/f"configuration-{i}.tar"
            with archive.open("xb") as stream:connections[0].command(["cat",str(root/f"configuration-{i}.tar")],stdout=stream,stderr=subprocess.PIPE)
            archive.chmod(0o600)
            if prep.sha(archive)!=generated[str(i)]["sha256"]:raise ValueError("native configuration download changed")
            connections[i].upload(archive,str(root/"configuration.tar"))
            connections[i].rpc_native(root,requests[i]|{"action":"install","replica":i,"sha256":generated[str(i)]["sha256"]})
        result['ceremony_sealed']=connections[0].rpc_native(root,requests[0]|{'action':'seal_configuration','sha256':generated['0']['sha256']})
        if result['ceremony_sealed'].get('sealed') is not True:raise ValueError('ceremony secrets were not sealed')
        if selected.get("network"):
            network=NativeNetwork(selected,root,connections)
            result["network"]=network.configure_network()
        runtime_limit=sum(cfg[k] for k in ("warmup","duration","drain","startup_seconds"))+30
        if selected["protocol"]=="shoal" or selected['protocol'].startswith('simpleit'):runtime_limit+=cfg["startup_seconds"]
        if selected['protocol'].startswith('simpleit'):runtime_limit+=300
        for host in selected["hosts"]:
            i=host["replica"];request=requests[i]
            prep.json_file(output/f"host-{i}.json",request);connections[i].upload(output/f"host-{i}.json",str(root/"run.json"))
            # Resource wrapper owns one supervisor and every native/application
            # descendant. The supervisor does not create separate process groups.
            remote_python=interpreter(host)
            digest=result["hosts"][i]["python_sha256"]
            supervisor={"action":"run","nonce":selected["nonce"],"binary":remote_python,"binary_sha256":digest,
                "directory":str(root),"state":str(root/"process.json"),"budget":host["budget"],
                "max_runtime_seconds":runtime_limit,
                "arguments":[str(root/"controller/scripts/remote_native.py"),"_host",str(root/"run.json")]}
            prep.json_file(output/f"supervisor-{i}.json",supervisor);connections[i].upload(output/f"supervisor-{i}.json",str(root/"supervisor.json"))
        def launch(i):
            host=selected["hosts"][i]
            with (output/f"supervisor-{i}.log").open("wb") as stream:
                return connections[i].command([interpreter(host),str(root/"controller/scripts/remote_worker.py"),"--request",str(root/"supervisor.json")],stdout=stream,stderr=subprocess.STDOUT,timeout=runtime_limit+30)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as pool:
            # Concurrent dispatch bounds start skew; raw host-local epochs and
            # controller send/return bounds are retained, not equated.
            started=time.monotonic_ns();futures={i:pool.submit(launch,i) for i in connections}
            startup_error=None
            if selected["protocol"]=="shoal" or selected['protocol'].startswith('simpleit'):
                result["startup"]={}
                try:
                    arm_prepared_shoal(connections,requests,root,futures,result["startup"])
                except BaseException as error:
                    startup_error=error
                    result["startup_failure"]={"error":f"{type(error).__name__}: {error}",
                        "controller_monotonic_ns":time.monotonic_ns(),"cleanup":{}}
                    # Stop waiting or partially armed hosts before joining their
                    # blocking SSH futures, rather than waiting a full workload.
                    with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as cleanup_pool:
                        cleanup_futures={i:cleanup_pool.submit(connection.rpc_native,root,requests[i]|{"action":"cleanup"})
                                         for i,connection in connections.items()}
                        for i,future in cleanup_futures.items():
                            try:result["startup_failure"]["cleanup"][i]=future.result()
                            except Exception as cleanup_error:
                                result["startup_failure"]["cleanup"][i]={"error":f"{type(cleanup_error).__name__}: {cleanup_error}"}
            failures={}
            for i,future in futures.items():
                try:future.result()
                except Exception as error:failures[i]=type(error).__name__
            result["dispatch"]={"controller_started_ns":started,"controller_finished_ns":time.monotonic_ns(),"failures":failures}
            if startup_error is not None:raise startup_error
        archives={};shoal_receipts={}
        compressed=cfg.get('population_profile')=='compact-n10-n50-v1'
        def collect_one(i):
            connection=connections[i]
            state=connection.rpc_native(root,requests[i]|{"action":"status"});result["hosts"][i]["result"]=state
            artifact=connection.rpc_native(root,requests[i]|{"action":"collect"});path=output/(f'evidence-{i}.stream.gz' if compressed else f'evidence-{i}.stream')
            metadata={"nonce":selected["nonce"],"replica":i,"plan_sha256":plan_hash}
            if artifact!={"format":runtime_evidence.FORMAT,"metadata":metadata}:raise ValueError("native evidence receipt identity differs")
            with path.open("xb") as stream:
                connection.command([interpreter(selected["hosts"][i]),str(root/"controller/scripts/remote_native.py"),"_export"],
                    input=json.dumps(requests[i]|({'compression':'gzip'} if compressed else {})).encode(),stdout=stream,stderr=subprocess.PIPE,timeout=900)
            directory=output/f"host-{i}";directory.mkdir()
            with (gzip.open(path,'rb') if compressed else path.open('rb')) as stream:result["hosts"][i]["evidence"]=runtime_evidence.unpack(stream,directory,expected_metadata=metadata)
            if state["status"]!="completed":return None
            if state.get('cohort_excluded'):
                if not (cfg['case']=='silent-first-leader' and i==1 and state.get('silent_leader') and
                        (selected['protocol'].startswith('simpleit') or state.get('native_processes_started')==0)):
                    raise ValueError('unrecognized excluded native cohort')
                return None
            archive=native.native_cohort_store.ShardedArchive(directory/"cohorts/index.json")
            if archive.index_sha256!=state["cohort_archive"]["sha256"] or set(archive.ledgers)!={i}:
                raise ValueError("native host cohort archive identity differs")
            count=0
            for row in archive.rows(i,"requests"):
                if row["sequence"]!=count or row["origin"]!=i or row["useful_bytes"]!=selected["settings"]["useful_bytes"]:
                    raise ValueError("native ledger differs from selected finite origin workload")
                count+=1
            if count!=selected["settings"]["counts"][i]:raise ValueError("native finite request population differs")
            if selected["protocol"]=="shoal":
                shoal_receipts[i]=native.collected_shoal_receipt(directory,i,cfg,selected["nonce"],
                    state["epoch_monotonic_ns"],state["native_observer"],archive)
            return archive
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as pool:
            collected={i:pool.submit(collect_one,i) for i in connections}
            failures={}
            for i,future in collected.items():
                try:
                    archive=future.result()
                    if archive is not None:archives[i]=archive
                except Exception as error:failures[i]=f'{type(error).__name__}: {error}'
            if failures:raise RuntimeError(f'native evidence collection failed: {failures}')
        expected=set(connections)-({1} if cfg['case']=='silent-first-leader' else set())
        if set(archives)!=expected:raise RuntimeError("one or more native hosts failed; partial evidence retained")
        if selected['protocol'].startswith('simpleit'):
            from baselines import simpleit_remote
            result['native_output']=simpleit_remote.verify_collected(output,cfg,expected)
        result.update(native.reduce_archives([archives[i] for i in sorted(archives)],selected["settings"],output),status="completed")
        if selected["protocol"]=="shoal":
            result["native_receipt_agreement"]=native.shoal_receipts.compare(shoal_receipts,cfg["correct"])
            observed=native.shoal_receipts.summarize(shoal_receipts,cfg["correct"])
            detailed=result["finite_output_receipt"]
            fields=("planned","admitted","all_correct_completed")
            def origins(receipt):
                return [(row["origin"],*(row[key] for key in fields)) for row in receipt["origins"]]
            if any(observed[key]!=detailed[key] for key in fields) or origins(observed)!=origins(detailed):
                raise ValueError("detailed finite cohort differs from native Shoal receipt")
            result["observer_finite_output_receipt"]=observed
        if result["dispatch"]["failures"]:
            result.update(status="failed",supervisor_acceptance_error="one or more owned resource supervisors failed after or during native collection; reduced evidence retained")
    except BaseException as error:result.update(status="failed",error=f"{type(error).__name__}: {error}")
    finally:
        result["cleanup"]={}
        for i,connection in connections.items():
            try:
                cleanup=connection.rpc_native(root,requests[i]|{"action":"cleanup"});result["cleanup"][i]=cleanup
                if cleanup.get("state")!="finished" or cleanup.get("exit_code")!=0:
                    result["status"]="failed";result["cleanup_acceptance_error"]="owned native termination was not confirmed successful at every host"
            except Exception as error:
                result["cleanup"][i]={"error":type(error).__name__,"remote_timeout_guard":"finite supervisor remains authoritative"}
                result["status"]="failed";result["cleanup_acceptance_error"]="owned native cleanup failed; timeout guard is not confirmation"
        if network is not None:
            try:network.clear_network()
            except Exception as error:
                result["network_cleanup_error"]=f"{type(error).__name__}: {error}";result["status"]="failed"
            result["network"]=network.network_evidence
        result["remote_evidence_policy"]="nonce-owned native stores/configuration/receipts retained; no host-wide deletion"
        prep.json_file(output/"result.json",result)
    return result


def main():
    if len(sys.argv)>1 and sys.argv[1]=="_rpc":print(json.dumps(rpc(json.load(sys.stdin))));return 0
    if len(sys.argv)>1 and sys.argv[1]=="_export":
        request=json.load(sys.stdin);root=checked_root(request);result=bounded_json(root/"result.json")
        names=list(runtime_evidence.selected_files(root))
        if request['protocol'].startswith('simpleit'):
            from baselines import simpleit_remote
            names=list(dict.fromkeys(names+simpleit_remote.evidence_files(root,request['host']['replica'])))
        if request.get('compression') not in (None,'gzip'):raise ValueError('unsupported evidence compression')
        stream=gzip.GzipFile(fileobj=sys.stdout.buffer,mode='wb',compresslevel=1,mtime=0) if request.get('compression')=='gzip' else sys.stdout.buffer
        try:runtime_evidence.pack(root,names,stream,
            {"nonce":request["nonce"],"replica":result["replica"],"plan_sha256":request["plan_sha256"]})
        finally:
            if stream is not sys.stdout.buffer:stream.close()
        return 0
    if len(sys.argv)==3 and sys.argv[1]=="_host":return run_host(json.loads(Path(sys.argv[2]).read_text()))
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest="action",required=True)
    make=commands.add_parser("plan");make.add_argument("--publication",type=Path,required=True);make.add_argument("--settings",type=Path,required=True);make.add_argument("--output",type=Path,required=True)
    run=commands.add_parser("run");run.add_argument("--plan",type=Path,required=True);run.add_argument("--output",type=Path,required=True);run.add_argument("--execute",action="store_true")
    args=parser.parse_args()
    if args.action=="plan":result=plan(json.loads(args.publication.read_text()),json.loads(args.settings.read_text()));prep.json_file(args.output,result)
    elif args.execute:result=execute(json.loads(args.plan.read_text()),args.output)
    else:result={"status":"local preview; no SSH or host changes","plan":json.loads(args.plan.read_text())}
    print(json.dumps(result,indent=2));return 0 if result.get("status")!="failed" else 1


if __name__=="__main__":raise SystemExit(main())
