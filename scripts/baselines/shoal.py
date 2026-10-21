#!/usr/bin/env python3
"""Pinned Shoal++ local launcher and finite-cohort contract.

--plan-only validates/archives commands without compiling or launching anything.
Native execution requires exact separately recorded Linux build provenance.
The current source adapter is not yet a native-acceptance/performance result.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import resource
import signal
import subprocess
import struct
import sys
import time
import urllib.request
import uuid
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_artifacts as artifacts
import native_faults
import native_cohort_store
import shoal_cohort
import shoal_receipts
sys.path.insert(0,str(artifacts.ROOT/"scripts"))
import cohort_metrics


def monotonic_us():return time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000


def direct_protocol_environment(environment):
    """Native peer TCP and loopback controls must not inherit download proxies."""
    return {key:value for key,value in environment.items()
            if key.lower() not in {'http_proxy','https_proxy','all_proxy','no_proxy'}} | {
                'NO_PROXY':'*','no_proxy':'*'}


def runtime_swap_snapshot(path=Path('/proc/swaps')):
    raw=path.read_text()
    lines=raw.splitlines()
    if not lines or not lines[0].startswith('Filename'):
        raise ValueError('unrecognized native Linux swap status')
    return {'observed_us':monotonic_us(),'raw':raw,'enabled':any(line.strip() for line in lines[1:])}


def options():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--nodes",type=int,default=4);p.add_argument("--rate",type=int,default=400)
    p.add_argument("--useful-bytes",type=int,default=472);p.add_argument("--warmup",type=float,default=1)
    p.add_argument("--duration",type=float,default=3);p.add_argument("--drain",type=float,default=5)
    p.add_argument("--deadline-ms",type=float,default=1000);p.add_argument("--batch-bytes",type=int,default=500000)
    p.add_argument("--ingress-batch-ms",type=int,default=10);p.add_argument("--bound-ms",type=int,default=100)
    p.add_argument("--faulty-replica",type=int,action="append",default=[])
    p.add_argument("--pause-replica",type=int);p.add_argument("--pause-after",type=float,default=1)
    p.add_argument("--pause-seconds",type=float,default=0.5)
    p.add_argument("--plan-only",action="store_true");p.add_argument("--output",type=Path,required=True)
    p.add_argument('--observer-mode',choices=['full','compact'],default='full')
    native_faults.add_arguments(p)
    return p


def validate(args):
    native_faults.validate(args,protocol="shoal")
    if args.nodes<4 or args.nodes>31 or (args.nodes-1)%3:raise ValueError("expected n=3f+1,4..31")
    faulty=set(args.faulty_replica)
    if len(faulty)>(args.nodes-1)//3 or any(index<0 or index>=args.nodes for index in faulty):raise ValueError("fixed faulty identities exceed budget")
    if args.pause_replica is not None:
        if args.pause_replica not in faulty:raise ValueError("paused identity must belong to fixed faulty set")
        if not (0<=args.pause_after<args.duration and 0<args.pause_seconds<=args.duration-args.pause_after):raise ValueError("finite pause must fit measurement window")
    if min(args.rate,args.useful_bytes,args.duration,args.deadline_ms,args.batch_bytes,args.ingress_batch_ms,args.bound_ms)<=0 or min(args.warmup,args.drain)<0:raise ValueError("invalid workload or native timing setting")
    return [index for index in range(args.nodes) if index not in faulty]


def command_plan(args, run_id):
    correct=validate(args);root=args.output.resolve();target=artifacts.ROOT/"benchmarks/.cache/shoal-target"
    fixture=target/"release/shoal-fixture";binary=target/"release/aptos-node"
    warmup=int(args.warmup*1e6);duration=int(args.duration*1e6)
    rates=[args.rate//len(correct)+(correct.index(index)<args.rate%len(correct)) if index in correct else 0 for index in range(args.nodes)]
    if args.omit_replica is not None:rates[args.omit_replica]=args.attacker_rate
    counts=[(warmup+duration)*rate//1_000_000 for rate in rates]
    return {"schema":1,"run_id":run_id,"correct_replicas":correct,"rates":rates,"counts":counts,
            "genesis":[str(fixture),str(root/"genesis"),str(args.nodes),str(args.batch_bytes),str(args.ingress_batch_ms),str(args.bound_ms)],
            "workloads":[[str(fixture),"workload",str(root/f"plan-{index}.jsonl"),run_id,str(index),str(counts[index]),str(args.useful_bytes)] for index in range(args.nodes)],
            "validators":[[str(binary),"-f",str(root/"genesis"/str(index)/"node.yaml")] for index in range(args.nodes)],
            "build_provenance":str(target/"build-provenance.json"),
            "native_mode":"consensus-only-perf-test; direct payloads; three DAGs; weak votes; native reputation",
            "native_execution_verified":False,"traffic_accounting_available":True,
            "traffic_boundary":"native underlying validator TCP writes; encrypted Noise/framing/handshakes included; REST ingress excluded"}


def parse_fixture(stdout, root, nodes):
    configs={}
    for line in stdout.splitlines():
        values=line.split()
        if len(values) not in (3,4) or not values[0].isdigit():continue
        index=int(values[0]);path=Path(values[1]).resolve();address=values[2]
        if index in configs or not 0<=index<nodes:raise ValueError("duplicate/out-of-range native fixture identity")
        if path!=(root/str(index)/"node.yaml").resolve():raise ValueError("native fixture path escaped selected genesis")
        host,port=address.rsplit(":",1)
        if host!="127.0.0.1" or not 0<int(port)<65536:raise ValueError("local native REST endpoint must be loopback")
        configs[index]={"path":path,"address":"http://"+address,"author":values[3] if len(values)==4 else None}
    if set(configs)!=set(range(nodes)) or len({row["address"] for row in configs.values()})!=nodes:
        raise ValueError("native fixture did not return distinct endpoints for every validator")
    return configs


def output_agreement(ledgers, correct):
    sequences=[[(row["output_index"],row["request_id"],row["exact_batch_id"]) for row in ledgers[index]["outputs"]] for index in correct]
    longest=max(sequences,key=len)
    if any(sequence!=longest[:len(sequence)] for sequence in sequences):raise RuntimeError("native Shoal exact output prefixes disagree")
    return {"replicas_agree_on_common_prefix":True,"common_prefix_length":min(map(len,sequences)),"sequence_lengths":list(map(len,sequences))}


def verify_binaries(plan):
    stamp=json.loads(Path(plan["build_provenance"]).read_text())
    _,pin=artifacts.prepare("shoal")
    if stamp.get("status")!="built" or stamp["source_commit"]!=pin["commit"]:raise ValueError("native Shoal build pin/status mismatch")
    if platform.system()!="Linux" or not stamp.get("abi",{}).get("platform","").startswith("Linux"):
        raise ValueError("selected native Shoal recipe requires Linux ABI (local VM is supported)")
    patch=artifacts.ROOT/pin["instrumentation_patch"]
    if stamp["source_diff_sha256"]!=artifacts.sha256(patch):raise ValueError("native Shoal patch changed after build")
    if stamp.get('observer_contract')!='shoal-native-receipt-v1':raise ValueError('native Shoal binary lacks required finite observer receipt contract')
    required={str(Path(plan["genesis"][0])),str(Path(plan["validators"][0][0]))}
    binaries={entry["path"]:entry for entry in stamp["binaries"]}
    if not required.issubset(binaries):raise ValueError("native build lacks validator or fixture binary")
    for path in required:
        if artifacts.sha256(path)!=binaries[path]["sha256"]:raise ValueError("native Shoal binary hash mismatch")
    return stamp


def io_snapshot(output,nodes):
    return {index:json.loads(path.read_text()) for index in range(nodes) if (path:=output/f"io-{index}.json").exists()}


class NativeReadiness:
    """Observe the pinned bootstrap event before choosing the workload epoch."""
    marker=b'The node has successfully bootstrapped!'
    def __init__(self,output,nodes,require_receipts=False):
        self.output=output;self.offsets={index:0 for index in range(nodes)}
        self.tails={index:b'' for index in range(nodes)};self.bootstrapped=set()
        self.require_receipts=require_receipts
    def observe(self):
        for index in self.offsets:
            if index in self.bootstrapped:continue
            with (self.output/f'validator-{index}.log').open('rb') as stream:
                stream.seek(self.offsets[index])
                while chunk:=stream.read(65536):
                    self.offsets[index]+=len(chunk)
                    joined=self.tails[index]+chunk
                    self.tails[index]=joined[-len(self.marker):]
                    if self.marker in joined:self.bootstrapped.add(index);break
        counters=io_snapshot(self.output,len(self.offsets))
        receipts=shoal_receipts.counters(self.output,len(self.offsets)) if self.require_receipts else {}
        return {'bootstrapped':sorted(self.bootstrapped),'counter_replicas':sorted(counters),
                'receipt_replicas':sorted(receipts),
                'ready':len(self.bootstrapped)==len(self.offsets)==len(counters) and (not self.require_receipts or len(receipts)==len(self.offsets))}


def exact_io_snapshot(output,frozen_us):
    rows={}
    for index,observed in frozen_us.items():
        with (output/f'io-{index}.counters').open('rb') as source:raw=source.read(25)
        if len(raw)!=24:raise ValueError('invalid native shared TCP counter size')
        magic,written,read=struct.unpack('=QQQ',raw)
        if magic!=0x444c47494f563031:raise ValueError('invalid native shared TCP counter header')
        rows[index]={'written_bytes':written,'read_bytes':read,'observed_us':observed,'source':'frozen_shared_native_atomics'}
    return rows


def freeze_owned(process):
    os.kill(process.pid,signal.SIGSTOP)
    _,status=os.waitpid(process.pid,os.WUNTRACED)
    if not os.WIFSTOPPED(status):
        process.returncode=os.waitstatus_to_exitcode(status)
        raise RuntimeError('native validator exited before journal freeze')
    return monotonic_us()


def linux_process_state(pid, proc_root=Path('/proc')):
    """Read one bounded Linux task identity/state, including names with ')'."""
    with (Path(proc_root)/str(pid)/'stat').open('rb') as stream:raw=stream.read(4097)
    if len(raw)>4096:raise RuntimeError('owned native process stat exceeds bound')
    opening,closing=raw.find(b'('),raw.rfind(b')')
    fields=raw[closing+1:].split()
    if opening<1 or closing<opening or int(raw[:opening].strip())!=pid or len(fields)<20:
        raise RuntimeError('malformed owned native process stat')
    return {'pid':pid,'state':fields[0].decode('ascii'),'parent_pid':int(fields[1]),
            'process_group':int(fields[2]),'session':int(fields[3]),'start_ticks':int(fields[19])}


class NativePause:
    """One owned, fixed-fault pause with bounded observed stop/resume receipts."""
    def __init__(self, process, replica, faulty, start_us, end_us, *, now=None,
                 sleep=None, send_signal=None, read_state=None, ack_timeout_us=1_000_000):
        if replica not in faulty or not 0<=start_us<end_us or not 0<ack_timeout_us<=1_000_000:
            raise ValueError('invalid owned fixed-fault pause schedule')
        self.process=process;self.now=now or monotonic_us;self.sleep=sleep or time.sleep
        self.send_signal=send_signal or os.kill;self.read_state=read_state or linux_process_state
        self.identity=None
        self.record={'replica':replica,'pid':process.pid,'configured_start_us':start_us,
            'configured_end_us':end_us,'clock':'CLOCK_MONOTONIC microseconds',
            'acknowledgement_timeout_us':ack_timeout_us,'status':'configured'}

    def observe(self):
        if self.process.poll() is not None:raise RuntimeError('owned native process exited during pause')
        state=self.read_state(self.process.pid)
        identity={key:state[key] for key in ('pid','parent_pid','process_group','session','start_ticks')}
        if (identity['pid']!=self.record['pid'] or identity['parent_pid']!=os.getpid()
                or identity['process_group']!=self.record['pid'] or identity['session']!=self.record['pid']
                or (self.identity is not None and identity!=self.identity)):
            raise RuntimeError('owned native process identity changed during pause')
        if state['state'] not in ('R','S','D','T','t','K','W','P','I'):
            raise RuntimeError('owned native process is not live during pause')
        if self.identity is None:
            self.identity=identity;self.record['process_identity']=dict(identity)
            self.record['before_state']=state['state'];self.record['before_observed_us']=self.now()
        self.record['last_observed_state']=state['state']
        return state['state']

    def acknowledge(self, phase, stopped):
        sent=self.record[phase+'_sent_us']
        while True:
            state=self.observe();observed=self.now()
            if observed<sent or observed-sent>self.record['acknowledgement_timeout_us']:
                raise RuntimeError('native pause '+phase+' acknowledgement timed out')
            if (state in ('T','t'))==stopped:
                self.record.update({phase+'_observed_us':observed,phase+'_state':state,
                                    phase+'_ack_us':observed-sent,phase+'_identity':dict(self.identity)})
                return
            self.sleep(.001)

    def tick(self):
        try:
            if self.record['status']=='configured' and self.now()>=self.record['configured_start_us']:
                if self.observe() in ('T','t'):raise RuntimeError('native process was already stopped before requested pause')
                sent=self.now()
                if sent>=self.record['configured_end_us']:raise RuntimeError('native pause missed its configured interval')
                self.record['stop_sent_us']=sent
                self.send_signal(self.record['pid'],signal.SIGSTOP)
                self.acknowledge('stop',True);self.record['status']='stopped'
            if self.record['status']=='stopped' and self.now()>=self.record['configured_end_us']:
                if self.observe() not in ('T','t'):raise RuntimeError('native process resumed before owned SIGCONT')
                sent=self.now();self.record['resume_sent_us']=sent
                self.send_signal(self.record['pid'],signal.SIGCONT)
                self.acknowledge('resume',False)
                lower=sent-self.record['stop_observed_us']
                upper=self.record['resume_observed_us']-self.record['stop_sent_us']
                if lower<=0:raise RuntimeError('native pause has no positive observed stopped interval')
                self.record.update(status='completed',observed_stopped_interval_us=lower,
                    actual_interval_bounds_us={'lower':lower,'upper':upper},
                    duration_scope='Stopped-state confirmation to SIGCONT is a lower bound; signal/ack span is an upper bound, not an exact transition timestamp.')
        except Exception as error:
            self.record.update(status='failed',error=f'{type(error).__name__}: {error}')
            raise

    def finish(self):
        # The loop may cross the configured end on its last 10ms sample.
        self.tick()
        if self.record['status']!='completed':
            self.record.update(status='failed',error='native pause lacks complete stop/resume acknowledgements')
            raise RuntimeError(self.record['error'])


def tcp_ledger(before,after,final,nodes,frozen_us=None):
    if any(set(snapshot)!=set(range(nodes)) for snapshot in (before,after,final)):
        raise ValueError("native TCP counters missing for a validator")
    delta={index:{field:after[index][field]-before[index][field] for field in ("written_bytes","read_bytes")} for index in range(nodes)}
    if any(value<0 for row in delta.values() for value in row.values()):raise ValueError("native TCP counters regressed")
    if any(final[index][field]<after[index][field] for index in range(nodes) for field in ('written_bytes','read_bytes')):raise ValueError('native frozen TCP counters regressed')
    gaps={index:frozen_us[index]-final[index]['observed_us'] for index in range(nodes)} if frozen_us else None
    if gaps and any(value<0 for value in gaps.values()):raise ValueError('native counter snapshot follows confirmed freeze')
    return {"before":before,"after":after,"frozen_final":final,"measurement":delta,
            "measurement_written_bytes":sum(row["written_bytes"] for row in delta.values()),
            "finite_run_written_bytes":sum(row["written_bytes"] for row in final.values()),
            "final_snapshot_to_freeze_us":gaps,
            "finite_run_cost_status":"exact totals recorded by native successful-I/O counters through confirmed process suspension" if all(row.get('source')=='frozen_shared_native_atomics' for row in final.values()) else "lower bound through latest per-validator snapshot; unsampled tail is not included",
            "scope":"recorded successful underlying native validator TCP writes, including encrypted framing/authentication; external REST ingress, syscall completions not yet recorded at suspension, and shutdown traffic excluded; not kernel-wire totals",
            "sampling":"10ms snapshots; actual absolute monotonic per-validator boundaries retained"}


def frozen_crypto_ledger(output,before,after):
    final=native_faults.cpu_snapshot(output)
    # With no drain the loop can reach its end before taking the end sample.
    # Preserve the actual frozen periodic sample instead of inventing zero work.
    return native_faults.cpu_ledger(before or {},final if after is None else after,final)


def comparison_summary(args, reduced, traffic, encoded_sizes):
    """Normalize measured fields without promoting native acceptance status."""
    cohort=reduced['cohort'];window=cohort['window']
    written=traffic['measurement_written_bytes']
    return {
        'protocol':'shoal','replicas':args.nodes,'offered_tx_s':args.rate,
        'bound_ms':args.bound_ms,'useful_transaction_bytes':args.useful_bytes,
        'transaction_bytes':encoded_sizes[0] if len(encoded_sizes)==1 else None,
        'native_serialized_transaction_bytes':encoded_sizes,
        'warmup_seconds':args.warmup,'measurement_seconds':args.duration,
        'ingress_batch_ms':args.ingress_batch_ms,'accounting_schema':1,
        'endpoint_contract':cohort_metrics.ENDPOINT,'cohort':cohort,
        'latency_endpoint':'Independent origin application ingress to locally available signed native payload in the contiguous Shoal round-robin DAG output order, using one process-host monotonic clock; includes native application observer cost.',
        'unique_completion_tps':window['unique_completion_tps'],
        'completion_count':window['completion_count'],
        'mean_latency_ms':reduced['mean_latency_ms'],
        'mean_latency_scope':'completed cohort members only; unfinished/censored cohort quantiles remain authoritative',
        'generated_count':window['admission_count'],'generation_tps':window['admission_tps'],
        'traffic_boundary':'successful_replica_tcp_stream_writes',
        'replica_tcp_written_bytes':written,
        'replica_tcp_read_bytes':sum(row['read_bytes'] for row in traffic['measurement'].values()),
        'replica_tcp_written_bytes_per_second':written/args.duration,
        'end_pending_generated_transactions_at_origins':[row['pending'] for row in cohort['origins']],
        'resource_cost':cohort_metrics.cost_ratios(written,cohort),
        'finite_run_resource_cost':cohort_metrics.cost_ratios(traffic['finite_run_written_bytes'],cohort,boundary='finite_run'),
    }


def archive_adapter_sources(output):
    paths=[Path(__file__),Path(shoal_cohort.__file__),Path(shoal_receipts.__file__),Path(cohort_metrics.__file__),
        Path(native_cohort_store.__file__),Path(native_faults.__file__),Path(artifacts.__file__),
        artifacts.ROOT/'scripts/cohort_store.py',Path(__file__).with_name('mysticeti_wal.py'),artifacts.MANIFEST]
    hashes={}
    for path in paths:
        destination=output/'adapter-sources'/path.resolve().relative_to(artifacts.ROOT)
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(path.read_bytes())
        hashes[str(path)]=artifacts.sha256(destination)
    return hashes


def main():
    parser=options();args=parser.parse_args()
    try:plan=command_plan(args,uuid.uuid4().hex)
    except ValueError as error:parser.error(str(error))
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    manifest={"schema":1,"baseline":"shoal","status":"prepared","settings":vars(args)|{"output":str(output)},"plan":plan,
              "limitations":["Native build/execution acceptance is pending; source/mock contract tests are separate.","Native consensus-only performance mode bypasses VM and uses FakeAptosDB for transaction/history maps.","Native instrumentation has not passed a built end-to-end acceptance gate; no formal comparison classification.","One native account per ingress origin retains the default 100 pending transactions/account; no capacity claim."]}
    manifest['runner_dependencies']=archive_adapter_sources(output)
    manifest['runner_sha256']=manifest['runner_dependencies'][str(Path(__file__))]
    processes=[];streams=[];usage_before=None;store=None;publishers=[]
    try:
        if args.plan_only:return 0
        manifest["build_provenance"]=verify_binaries(plan)
        manifest['swap_before']=runtime_swap_snapshot()
        if manifest['swap_before']['enabled']:raise RuntimeError('disable build-only swap before native validators run')
        manifest['source_commit']=manifest['build_provenance']['source_commit']
        manifest['source_diff_sha256']=manifest['build_provenance']['source_diff_sha256']
        result=subprocess.run(plan["genesis"],capture_output=True,text=True)
        (output/"genesis.stdout").write_text(result.stdout);(output/"genesis.stderr").write_text(result.stderr)
        result.check_returncode()
        configs=parse_fixture(result.stdout,output/"genesis",args.nodes)
        if args.omit_replica is not None and any(row["author"] is None for row in configs.values()):raise ValueError("semantic omission requires exact native validator account identities")
        selected=(output/"genesis/on-chain-consensus.yaml").read_text()
        if "DAG" not in selected or "Jolteon" in selected:raise RuntimeError("native fixture did not select explicit DAG genesis")
        for index,command in enumerate(plan["workloads"]):
            result=subprocess.run(command,capture_output=True)
            (output/f"workload-{index}.stdout").write_bytes(result.stdout)
            (output/f"workload-{index}.stderr").write_bytes(result.stderr)
            result.check_returncode()
        plan_paths=[output/f"plan-{index}.jsonl" for index in range(args.nodes)]
        store=native_cohort_store.NativeStore(output/'native-staging.sqlite')
        manifest['native_workload_encoding']=shoal_cohort.prepare_plan_store(store,plan_paths,plan['run_id'],plan['counts'],args.useful_bytes)
        observer_plan=shoal_receipts.prepare_plan(store,output,plan['run_id'],plan['counts'],args.useful_bytes)
        shoal_receipts.prepare_admissions(output,observer_plan)
        publishers=[shoal_receipts.AdmissionPublisher(output/f'admission-{index}.bits',observer_plan,index) for index in range(args.nodes)]
        manifest['observer_plan']=observer_plan
        usage_before=resource.getrusage(resource.RUSAGE_CHILDREN)
        for index,command in enumerate(plan["validators"]):
            stream=(output/f"validator-{index}.log").open("wb");streams.append(stream)
            env=direct_protocol_environment(os.environ)|{"BENCHMARK_COHORT_PATH":str(output/f"output-{index}.jsonl"),"BENCHMARK_RUN_ID":plan["run_id"],"BENCHMARK_IO_PATH":str(output/f"io-{index}.json"),"APTOS_DISABLE_TELEMETRY":"1"}
            env.pop('APTOS_FORCE_ENABLE_TELEMETRY',None)
            env.update(shoal_receipts.environment(output,observer_plan,index,args.observer_mode))
            env.update(native_faults.environment(args,output,index,{i:row["author"] for i,row in configs.items()}))
            if index==args.omit_replica:env["BENCHMARK_FAULT_AUTHOR"]=configs[index]["author"]
            processes.append(subprocess.Popen(command,env=env,cwd=output,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True))
        manifest['external_telemetry']='disabled using native APTOS_DISABLE_TELEMETRY; force-enable override removed from child environment'
        manifest['proxy_policy']='Native validator children strip inherited HTTP/HTTPS/ALL proxy variables; local REST uses an explicit proxy-free opener.'
        readiness=NativeReadiness(output,args.nodes,require_receipts=True)
        manifest['startup_readiness']={'started_us':monotonic_us(),
            'policy':'REST ready, pinned native state-sync bootstrap event and initialized native TCP counters on every validator before choosing the arrival epoch; configured warmup remains unchanged'}
        ready_deadline=time.monotonic()+90;ready=set()
        while True:
            if any(process.poll() is not None for process in processes):raise RuntimeError("native validator exited during startup")
            for index,config in configs.items():
                if index in ready:continue
                try:
                    with shoal_cohort.direct_urlopen(config["address"]+"/v1",timeout=0.3) as reply:
                        if reply.status==200:ready.add(index)
                except OSError:pass
            observed=readiness.observe()
            manifest['startup_readiness'].update(observed,api_replicas=sorted(ready))
            if len(ready)==args.nodes and observed['ready']:break
            if time.monotonic()>ready_deadline:raise RuntimeError("native Shoal startup timed out")
            time.sleep(0.05)
        manifest['startup_readiness']['completed_us']=monotonic_us()
        epoch=monotonic_us()+100_000;warmup=int(args.warmup*1e6);duration=int(args.duration*1e6);drain=int(args.drain*1e6)
        manifest["epoch_us"]=epoch
        pause=None
        if args.pause_replica is not None:
            pause=NativePause(processes[args.pause_replica],args.pause_replica,args.faulty_replica,
                epoch+warmup+round(args.pause_after*1e6),
                epoch+warmup+round((args.pause_after+args.pause_seconds)*1e6))
            manifest['pause_observation']=pause.record
        requested=epoch+warmup+duration+drain
        shoal_receipts.arm(output,observer_plan,requested)
        manifest["omission_schedule"]=native_faults.arm(args,output,epoch*1000)
        before=None;after=None;cpu_before=None;cpu_after=None;receipt_before=None;receipt_after=None
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.nodes) as executor:
            arrivals={index:executor.submit(shoal_cohort.ingress_to_journal,output/f'ingress-{index}.jsonl',plan_paths[index],configs[index]["address"],plan["rates"][index],epoch,warmup,duration,drain,now=monotonic_us,on_admit=publishers[index].admit) for index in range(args.nodes)}
            while monotonic_us()<epoch+warmup+duration+drain:
                if any(process.poll() is not None for process in processes):raise RuntimeError("native Shoal validator exited")
                elapsed=monotonic_us()-epoch-warmup
                if before is None and elapsed>=0:before=io_snapshot(output,args.nodes);cpu_before=native_faults.cpu_snapshot(output);receipt_before=shoal_receipts.counters(output,args.nodes)
                if after is None and elapsed>=duration:after=io_snapshot(output,args.nodes);cpu_after=native_faults.cpu_snapshot(output);receipt_after=shoal_receipts.counters(output,args.nodes)
                if pause is not None:pause.tick()
                time.sleep(0.01)
            if pause is not None:pause.finish()
            admitted={index:future.result() for index,future in arrivals.items()}
        shoal_receipts.await_headers(output,args.nodes,processes)
        # Stop only owned processes at the finite boundary before collecting files.
        frozen={index:freeze_owned(process) for index,process in enumerate(processes)}
        manifest['traffic_snapshots']={'before':before,'after':after,'frozen_final':exact_io_snapshot(output,frozen),'frozen_us':frozen}
        manifest["traffic_ledger"]=tcp_ledger(before or {},after or io_snapshot(output,args.nodes),manifest['traffic_snapshots']['frozen_final'],args.nodes,frozen)
        manifest['traffic_ledger']['periodic_snapshot_at_freeze']=io_snapshot(output,args.nodes)
        receipts={index:shoal_receipts.load(output,observer_plan,index,args.observer_mode,requested) for index in range(args.nodes)}
        manifest['native_admission_verification']={index:shoal_receipts.verify_admissions(admitted[index],receipts[index]) for index in range(args.nodes)}
        manifest['observer_receipt_agreement']=shoal_receipts.compare(receipts,plan['correct_replicas'])
        manifest['observer_finite_output_receipt']=shoal_receipts.summarize(receipts,plan['correct_replicas'])
        manifest['observer_receipts']={index:{'header':receipt['header'],'header_sha256':receipt['header_sha256'],'checkpoint_sha3_256':receipt['checkpoint_sha3_256']} for index,receipt in receipts.items()}
        manifest['observer_counter_snapshots']={'before':receipt_before,'after':receipt_after or shoal_receipts.counters(output,args.nodes),'scope':'Common native20ms samples at complete-batch boundaries; actual sample times retained, no compact request latency'}
        manifest["omission_observation"]=native_faults.collect_omissions(output)
        manifest["native_fault_scope"]="Faulty author's native node/certified-node publication and repair response units containing its own node; native control/certificates and honest custody remain unchanged. A repair response may also bundle other nodes; the whole native response is omitted, not edited."
        if args.crypto_meter=="on":
            manifest["crypto_cpu_ledger"]=frozen_crypto_ledger(output,cpu_before,cpu_after)
            manifest["crypto_cpu_ledger"]["scope"]="Native BLS12-381 sign and verification/aggregate-verification primitives; failed attempts charged. Signing includes preimage serialization; verification serialization occurs outside the inner guard. Client Ed25519 and Noise authentication are separate."
            manifest["crypto_cpu_ledger"]["unmetered_authentication_work"]="BLS signature aggregation/proof assembly, client Ed25519 checks, Noise authentication and caller-side validation/serialization remain in process CPU; these primitive counters do not claim total authentication CPU."
        if args.observer_mode=='compact':
            if any((output/f'output-{index}.jsonl').exists() for index in range(args.nodes)):raise RuntimeError('compact mode created a detailed request journal')
            manifest.update(status='completed',agreement=manifest['observer_receipt_agreement'],finite_output_receipt=manifest['observer_finite_output_receipt'],comparison_eligible=False,
                acceptance_scope='compact detailed-observer cost control; native materialization/authentication retained; latency unavailable')
        else:
            manifest['detailed_receipt_verification']={index:shoal_receipts.verify_full(receipts[index],output/f'output-{index}.jsonl') for index in range(args.nodes)}
            for index in range(args.nodes):
                path=output/f"output-{index}.jsonl"
                events=native_cohort_store.journal_rows(path) if path.exists() else iter(())
                shoal_cohort.collect_store(store,index,native_cohort_store.journal_rows(admitted[index]),events,epoch,warmup,duration,drain,observed_us=receipts[index]['header']['frozen_us'])
                manifest['detailed_receipt_verification'][index]['eligibility']=shoal_receipts.verify_local_eligibility(store,receipts[index])
                evidence=[plan_paths[index],Path(admitted[index])]+([path] if path.exists() else [])
                store.metadata[index]['native_evidence']={str(item):artifacts.sha256(item) for item in evidence}
            archive=store.archive(output/'cohort-pages')
            reduced=native_cohort_store.reduce_archive(archive,output/'cohort.sqlite',plan['correct_replicas'],args.deadline_ms)
            manifest.update(reduced)
            expected=manifest['observer_finite_output_receipt']
            if any(reduced['finite_output_receipt'][key]!=expected[key] for key in ('planned','admitted','all_correct_completed')):raise ValueError('detailed cohort differs from native finite eligibility receipt')
            manifest['comparison']=comparison_summary(args,reduced,manifest['traffic_ledger'],manifest['native_workload_encoding']['native_serialized_transaction_bytes'])
            manifest["finite_run_resource_cost"]=cohort_metrics.cost_ratios(manifest["traffic_ledger"]["finite_run_written_bytes"],manifest["cohort"],boundary="finite_run")
            manifest["status"]="completed"
            manifest['acceptance_scope']='functional native finite-cohort observation; formal comparison acceptance remains a separate gate'
            manifest["comparison_eligible"]=False
    except BaseException as error:
        manifest.update(status="failed",error=f"{type(error).__name__}: {error}")
        return 1
    finally:
        for process in processes:
            if process.poll() is None:os.kill(process.pid,signal.SIGCONT);process.terminate()
        for process in processes:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        manifest['owned_process_cleanup']={'all_reaped':all(process.returncode is not None for process in processes),
            'processes':[{'pid':process.pid,'returncode':process.returncode} for process in processes]}
        for stream in streams:stream.close()
        for publisher in publishers:publisher.close()
        if store:store.close()
        if 'swap_before' in manifest:
            manifest['swap_after']=runtime_swap_snapshot()
            if manifest['swap_after']['enabled']:
                manifest.update(status='failed',resource_policy_error='swap was enabled at final native boundary',comparison_eligible=False)
        if usage_before:
            after=resource.getrusage(resource.RUSAGE_CHILDREN)
            manifest["native_child_cpu"]={"user_seconds":after.ru_utime-usage_before.ru_utime,"system_seconds":after.ru_stime-usage_before.ru_stime,"scope":"native processes only; ingress runner CPU separate"}
            if 'comparison' in manifest:
                manifest['comparison']['process_cpu_seconds']=manifest['native_child_cpu']['user_seconds']+manifest['native_child_cpu']['system_seconds']
                manifest['comparison']['process_cpu_scope']=manifest['native_child_cpu']['scope']
        try:
            if any(artifacts.sha256(path)!=digest for path,digest in manifest['runner_dependencies'].items()):
                raise ValueError('native adapter source changed during run; archived input bytes retained')
        except (ValueError,OSError) as error:
            manifest.update(status='failed',source_provenance_error=str(error))
        (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    return 0 if manifest['status']=='completed' else 1


if __name__=="__main__":raise SystemExit(main())
