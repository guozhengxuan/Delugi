#!/usr/bin/env python3
"""Published native Autobahn with independent arrivals and verified output cohorts.

Each validator keeps its native primary and worker processes, cryptography,
RocksDB, batching, repair and leader selection. A separate application process
joins ordered primary headers with verified locally retained worker payloads.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import sys
import time
import uuid
import resource

sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_artifacts as artifact
import native_faults
import native_receipts
import native_cohort_store
sys.path.insert(0,str(artifact.ROOT/"scripts"))
import cohort_metrics
import network_delay


def allocate_base(count):
    for _ in range(100):
        sock=socket.socket();sock.bind(("127.0.0.1",0));base=sock.getsockname()[1];sock.close()
        if base+count>=65535:continue
        held=[]
        try:
            for port in range(base,base+count):
                listener=socket.socket();held.append(listener);listener.bind(("127.0.0.1",port))
            return base
        except OSError:pass
        finally:
            for listener in held:listener.close()
    raise RuntimeError("Cannot reserve contiguous native worker ports")


def prefix_agreement(ledgers,correct):
    sequences=[[ (row["output_index"],row["request_id"],row["exact_batch_id"]) for row in ledgers[i]["outputs"]] for i in correct]
    for sequence in sequences:
        if [x[0] for x in sequence]!=list(range(len(sequence))):raise RuntimeError("Native application output has ordinal gaps")
    common=min(map(len,sequences))
    longest=max(sequences,key=len)
    if any(sequence!=longest[:len(sequence)] for sequence in sequences):raise RuntimeError("Native payload-verified output prefixes disagree")
    import hashlib
    return {"replicas_agree_on_common_prefix":True,"common_prefix_length":common,"sequence_lengths":list(map(len,sequences)),"common_prefix_sha256":hashlib.sha256(json.dumps(sequences[0][:common]).encode()).hexdigest(),"correct_replicas":correct}


def argument_parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--build",action="store_true");p.add_argument("--build-only",action="store_true")
    p.add_argument("--disruption-artifact",action="store_true")
    p.add_argument("--warmup",type=float,default=1);p.add_argument("--duration",type=float,default=5)
    p.add_argument("--drain",type=float,default=2);p.add_argument("--deadline-ms",type=float,default=1000)
    p.add_argument("--rate",type=int,default=400);p.add_argument("--useful-bytes",type=int,default=472)
    p.add_argument("--ingress-batch-ms",type=int,default=10);p.add_argument("--batch-bytes",type=int,default=500_000)
    p.add_argument("--bound-ms",type=int,default=100);p.add_argument("--nodes",type=int,default=4)
    p.add_argument("--workers",type=int,choices=[1],default=1,help="One native worker per validator in current application adapter")
    p.add_argument("--tokio-workers",type=int,default=2)
    p.add_argument("--faulty-replica",type=int,action="append",default=[])
    p.add_argument("--pause-replica",type=int);p.add_argument("--pause-after",type=float,default=1)
    p.add_argument("--pause-seconds",type=float,default=0.5)
    p.add_argument("--output",type=Path)
    p.add_argument("--cohort-observer",choices=("full","compact"),default="full")
    native_faults.add_arguments(p)
    return p


def main():
    p=argument_parser();args=p.parse_args()
    try:native_faults.validate(args,protocol="autobahn")
    except ValueError as error:p.error(str(error))
    if min(args.duration,args.rate,args.useful_bytes,args.ingress_batch_ms,args.batch_bytes,args.bound_ms,args.tokio_workers,args.deadline_ms)<=0 or min(args.warmup,args.drain)<0 or args.nodes<4 or args.nodes>31 or (args.nodes-1)%3 or len(set(args.faulty_replica))>(args.nodes-1)//3 or any(i<0 or i>=args.nodes for i in args.faulty_replica):
        p.error("invalid positive settings or Byzantine budget (n4 f1)")
    correct=[i for i in range(args.nodes) if i not in args.faulty_replica]
    if args.pause_replica is not None and not (0<=args.pause_after<args.duration and 0<args.pause_seconds<=args.duration-args.pause_after):p.error("finite disruption must fit measurement window")
    source,pin=artifact.prepare("autobahn",args.disruption_artifact)
    target=artifact.ROOT/"benchmarks/.cache"/("autobahn-blips-target" if args.disruption_artifact else "autobahn-target")
    output=(args.output or artifact.ROOT/"results/local"/("autobahn-native-"+uuid.uuid4().hex)).resolve();output.mkdir(parents=True,exist_ok=False)
    manifest={"schema":2,"baseline":"autobahn","source_commit":pin["commit"],"source_remote":pin["repository"],"status":"running","commands":[],"settings":vars(args)|{"output":str(output),"replicas":args.nodes,"correct_replicas":correct},"started_unix_ns":time.time_ns(),"limitations":["Native RocksDB non-sync writes; output is verified local payload availability, not durable fsync or VM execution.","Application observer verifies native retained batches and adds local read/journal/poll cost; observer overhead included, not yet independently quantified.","Native slot cuts are linearized by (height, author, full digest), implementing the paper-required deterministic within-slot order absent from the original unused HashMap-ordered upcall.","All native primary/worker traffic included; payload/evidence/repair and crypto CPU decomposition remains separate instrumentation work."]}
    processes=[];streams=[];native_by_replica={i:[] for i in range(args.nodes)};shaped=False;usage_before=None
    try:
        if args.build or args.build_only:artifact.build("autobahn",disruption=args.disruption_artifact,output=output/"build",toolchain="stable")
        stamp=json.loads((target/"build-provenance.json").read_text())
        if stamp["source_commit"]!=pin["commit"]:raise RuntimeError("Native build/source pin mismatch")
        diff=subprocess.check_output(["git","-C",str(source),"diff","HEAD"])
        import hashlib
        if hashlib.sha256(diff).hexdigest()!=stamp["source_diff_sha256"]:raise RuntimeError("Native source changed since binary build")
        for entry in stamp["binaries"]:
            if artifact.sha256(entry["path"])!=entry["sha256"]:raise RuntimeError("Native binary hash mismatch")
        manifest.update(build_provenance=stamp,source_diff_sha256=stamp["source_diff_sha256"],cargo_lock_sha256=stamp["cargo_lock_sha256"])
        (output/"source.patch").write_bytes(diff)
        if args.build_only:manifest["status"]="built";return 0
        spec=importlib.util.spec_from_file_location("native_autobahn_config",source/"benchmark/benchmark/config.py")
        config=importlib.util.module_from_spec(spec);spec.loader.exec_module(config)
        binary=target/"release/node";keys=[]
        for index in range(args.nodes):
            path=output/f"key-{index}.json";subprocess.run([str(binary),"generate_keys","--filename",str(path)],check=True,capture_output=True);path.chmod(0o600);keys.append(config.Key.from_file(str(path)))
        base_port=allocate_base(6*args.nodes);committee=config.LocalCommittee([key.name for key in keys],base_port,1)
        committee.print(str(output/"committee.json"))
        parameters={"timeout_delay":args.bound_ms,"header_size":32,"max_header_delay":args.ingress_batch_ms,"gc_depth":50,"sync_retry_delay":args.bound_ms,"sync_retry_nodes":3,"batch_size":args.batch_bytes,"max_batch_delay":args.ingress_batch_ms,"use_optimistic_tips":True,"use_parallel_proposals":True,"k":4,"use_fast_path":True,"fast_path_timeout":args.bound_ms,"use_ride_share":False,"car_timeout":args.bound_ms,"simulate_asynchrony":False,"asynchrony_start":15000,"asynchrony_duration":3000}
        if args.disruption_artifact:
            parameters.update(asynchrony_type=[],asynchrony_start=[],asynchrony_duration=[],affected_nodes=[],egress_penalty=0,use_fast_sync=False,use_exponential_timeouts=False)
        config.NodeParameters(parameters).print(str(output/"parameters.json"))
        # Explicit common host CLOCK_MONOTONIC epoch. Remote collectors must use
        # the shared deployment adapter's origin-local clock contract instead.
        epoch=time.clock_gettime_ns(time.CLOCK_MONOTONIC)+2_000_000_000
        manifest["omission_schedule"]=native_faults.arm(args,output,epoch)
        # Native worker client and peer addresses differ; map the latter for selective publication.
        worker_peers={i:committee.json["authorities"][key.name]["workers"][0]["worker_to_worker"] for i,key in enumerate(keys)}
        env=os.environ.copy();env.update(TOKIO_WORKER_THREADS=str(args.tokio_workers),RUST_LOG="info",BENCHMARK_EPOCH_NS=str(epoch),BENCHMARK_WARMUP_US=str(int(args.warmup*1e6)),BENCHMARK_DURATION_US=str(int(args.duration*1e6)))
        def launch(command,name,environment):
            stream=(output/(name+".log")).open("wb");streams.append(stream)
            manifest["commands"].append({"argv":command,"log":name+".log"})
            process=subprocess.Popen(command,cwd=output,env=environment,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True);processes.append(process);return process
        usage_before=resource.getrusage(resource.RUSAGE_CHILDREN)
        for index in range(args.nodes):
            base=[str(binary),"-vv","run","--keys",str(output/f"key-{index}.json"),"--committee",str(output/"committee.json"),"--parameters",str(output/"parameters.json")]
            for role,tail in (("primary",["primary"]),("worker-0",["worker","--id","0"])):
                local=env|{"BENCHMARK_OBSERVER_DIR":str(output/f"observer-{index}"/role)}
                local.update(native_faults.environment(args,output,index,worker_peers,role=role))
                if role=="primary":
                    local={key:value for key,value in local.items() if not key.startswith("BENCHMARK_FAULT_")}
                native_by_replica[index].append(launch(base+["--store",str(output/f"store-{index}-{role}"),*tail],f"{role}-{index}",local))
        shaping=network_delay.configure_from_environment("autobahn",list(range(base_port,base_port+6*args.nodes)))
        if shaping is not None:shaped=True;manifest["network_shaping"]=shaping
        applications=[]
        rates=[0 if index not in correct else args.rate//len(correct)+(correct.index(index)<args.rate%len(correct)) for index in range(args.nodes)]
        if args.omit_replica is not None:rates[args.omit_replica]=args.attacker_rate
        planned_counts=[(int(args.warmup*1e6)+int(args.duration*1e6))*rate//1_000_000 for rate in rates]
        for index,addresses in enumerate(committee.workers_addresses()):
            rate=rates[index]
            command=[sys.executable,str(Path(__file__).with_name("autobahn_cohort.py")),"--origin",str(index),"--rate",str(rate),"--useful-bytes",str(args.useful_bytes),"--epoch-ns",str(epoch),"--warmup-us",str(int(args.warmup*1e6)),"--duration-us",str(int(args.duration*1e6)),"--drain-us",str(int(args.drain*1e6)),"--workers","1","--address",addresses[0][1],"--observer-dir",str(output/f"observer-{index}"),"--output",str(output/f"ledger-{index}.json")]
            command += ["--cohort-observer",args.cohort_observer,"--planned-counts",",".join(map(str,planned_counts))]
            applications.append(launch(command,f"application-{index}",env))
        manifest["process_ids"]=[process.pid for process in processes];paused=False;resumed=False
        cpu_before=None;cpu_after=None
        end=epoch+int((args.warmup+args.duration+args.drain)*1e9)
        while time.clock_gettime_ns(time.CLOCK_MONOTONIC)<end or any(process.poll() is None for process in applications):
            now=(time.clock_gettime_ns(time.CLOCK_MONOTONIC)-epoch)/1e9
            if cpu_before is None and now>=args.warmup:cpu_before=native_faults.cpu_snapshot(output)
            if cpu_after is None and now>=args.warmup+args.duration:cpu_after=native_faults.cpu_snapshot(output)
            if args.pause_replica is not None:
                if not paused and now>=args.warmup+args.pause_after:
                    for process in native_by_replica[args.pause_replica]:os.kill(process.pid,signal.SIGSTOP)
                    paused=True
                if paused and not resumed and now>=args.warmup+args.pause_after+args.pause_seconds:
                    for process in native_by_replica[args.pause_replica]:os.kill(process.pid,signal.SIGCONT)
                    resumed=True
            if any(process.poll() is not None for row in native_by_replica.values() for process in row):raise RuntimeError("Native primary/worker exited prematurely")
            if any(process.poll() not in (None,0) for process in applications):raise RuntimeError("Native application observer failed; inspect log")
            if time.clock_gettime_ns(time.CLOCK_MONOTONIC)>end+5_000_000_000:raise RuntimeError("Application observation missed bounded shutdown")
            time.sleep(0.01)
        time.sleep(0.03)  # allow aggregate IO snapshot after measurement boundary
        manifest["omission_observation"]=native_faults.collect_omissions(output)
        if args.crypto_meter=="on":manifest["crypto_cpu_ledger"]=native_faults.cpu_ledger(cpu_before or {},cpu_after or {},native_faults.cpu_snapshot(output))
        manifest["runner_dependencies"]=native_faults.dependency_hashes([Path(__file__),Path(native_faults.__file__),Path(cohort_metrics.__file__),Path(native_receipts.__file__),Path(__file__).with_name("autobahn_cohort.py"),Path(native_cohort_store.__file__),artifact.ROOT/"scripts/cohort_store.py",Path(network_delay.__file__),artifact.ROOT/"scripts/timing_calibration.py"])
        manifest["observer_control"]={"mode":args.cohort_observer,"scope":"Detailed cohort observer; identical native slot zipper, retained-payload digest/content validation and contiguous materialization in both modes; native payload-copy and slot-journal cost retained in both.","per_request_timestamps_and_rows":args.cohort_observer=="full","latency_available":args.cohort_observer=="full"}
        if args.cohort_observer=="compact":
            # Compact observer controls preserve the historical bitmap/checkpoint
            # format. Full-cohort campaign reduction below never loads these
            # complete files or populations into controller memory.
            ledgers={i:json.loads((output/f"ledger-{i}.json").read_text()) for i in range(args.nodes)}
            receipts={index:ledger["compact_receipt"] for index,ledger in ledgers.items()}
            manifest["compact_output_agreement"]=native_receipts.compare(receipts,correct)
            manifest["finite_output_receipt"]=native_receipts.summarize(receipts,{i:ledgers[i]["admitted_bits"] for i in correct},correct)
            manifest["agreement"]=manifest["compact_output_agreement"]
            io=[json.loads((output/f"observer-{i}"/role/"io.json").read_text()) for i in range(args.nodes) for role in ("primary","worker-0")]
            manifest["traffic_ledger"]={"per_process":io,"measurement_written_bytes":sum(row["window_written_bytes"] for row in io),"whole_run_written_bytes":sum(row["written_bytes"] for row in io),"counter_boundary":"successful_replica_tcp_stream_writes"}
            manifest["status"]="completed"
            return 0
        staging=native_cohort_store.NativeStore(output/"native-cohort-stage.sqlite")
        try:
            for i in range(args.nodes):staging.legacy(output/f"ledger-{i}.json",i)
            archive=staging.archive(output/"cohorts")
        finally:staging.close()
        reduced=native_cohort_store.reduce_archive(archive,output/"cohort-reduction.sqlite",correct,args.deadline_ms)
        manifest.update({key:reduced[key] for key in ("cohort","agreement","cohort_archive","output_exclusions","finite_output_receipt")})
        manifest["compact_output_agreement"]={**reduced["agreement"],"receipt_check":"native final rolling receipt fingerprint checked against streamed exact output; checkpoint/bitmap diagnostics retained in raw ledgers"}
        io=[json.loads((output/f"observer-{i}"/role/"io.json").read_text()) for i in range(args.nodes) for role in ("primary","worker-0")]
        written=sum(row["window_written_bytes"] for row in io);total=sum(row["written_bytes"] for row in io)
        manifest["traffic_ledger"]={"per_process":io,"measurement_written_bytes":written,"whole_run_written_bytes":total,"counter_boundary":"successful_replica_tcp_stream_writes","includes":"native primary and worker sockets including intra-validator traffic; external client sends excluded"}
        window=manifest["cohort"]["window"]
        manifest["comparison"]={"protocol":"autobahn","replicas":args.nodes,"offered_tx_s":args.rate,"bound_ms":args.bound_ms,"transaction_bytes":args.useful_bytes+40,"useful_transaction_bytes":args.useful_bytes,"ingress_batch_ms":args.ingress_batch_ms,"warmup_seconds":args.warmup,"measurement_seconds":args.duration,"accounting_schema":1,"endpoint_contract":cohort_metrics.ENDPOINT,"latency_endpoint":"Independent origin application ingress to payload-verified contiguous native header/worker-batch output using one local monotonic clock; includes observer polling and local read cost.","cohort":manifest["cohort"],"unique_completion_tps":window["unique_completion_tps"],"completion_count":window["completion_count"],"mean_latency_ms":reduced["mean_latency_ms"],"mean_latency_scope":"completed cohort members only; censored cohort quantiles authoritative","generated_count":manifest["cohort"]["scheduled"],"generation_tps":manifest["cohort"]["scheduled"]/args.duration,"traffic_boundary":"successful_replica_tcp_stream_writes","replica_tcp_written_bytes":written,"replica_tcp_read_bytes":sum(row["window_read_bytes"] for row in io),"replica_tcp_written_bytes_per_second":written/args.duration,"end_pending_generated_transactions_at_origins":[row["pending"] for row in manifest["cohort"]["origins"]],"resource_cost":cohort_metrics.cost_ratios(written,manifest["cohort"])}
        manifest["comparison"]["finite_run_resource_cost"]=cohort_metrics.cost_ratios(total,manifest["cohort"],boundary="finite_run")
        manifest["comparison"].update(generated_count=window["admission_count"],generation_tps=window["admission_tps"])
        manifest["native_fault_scope"]="Faulty worker initial payload broadcasts and optional payload repair replies; primary consensus/control and honest custody unchanged. Extra faulty-origin traffic is excluded from honest useful-work credit."
        manifest["checks"]={"independent_primary_and_worker_processes":True,"native_crypto_storage_batching_preserved":True,"formal_materialization_endpoint":True,"finite_arrivals_and_unfinished_cohorts":True}
        manifest["status"]="completed"
    except BaseException as error:
        import traceback
        manifest["status"]="failed";manifest["error"]=f"{type(error).__name__}: {error}";(output/"error.txt").write_text(traceback.format_exc())
    finally:
        for row in native_by_replica.values():
            for process in row:
                if process.poll() is None:os.kill(process.pid,signal.SIGCONT)
        for process in processes:
            if process.poll() is None:process.terminate()
        for process in processes:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for stream in streams:stream.close()
        if usage_before is not None:
            usage_after=resource.getrusage(resource.RUSAGE_CHILDREN)
            manifest["process_cpu"]={"scope":"Whole finite run through process shutdown; all native primary/worker and application child processes, excludes runner and prior build/genesis", "user_seconds":usage_after.ru_utime-usage_before.ru_utime,"system_seconds":usage_after.ru_stime-usage_before.ru_stime}
        if shaped:manifest["network_shaping_cleanup"]=network_delay.clear_from_environment()
        manifest["runner_sha256"]=artifact.sha256(__file__);manifest["finished_unix_ns"]=time.time_ns()
        (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n");print(output)
    return 0 if manifest["status"] in ("completed","built") else 1

if __name__=="__main__":sys.exit(main())
