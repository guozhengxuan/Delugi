"""Fixed native placement recipes; all timing below belongs to one validator host."""
from __future__ import annotations
import json
import base64
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cohort_metrics
import mysticeti
import autobahn_cohort
import shoal_cohort
import shoal_receipts
import native_faults
import native_cohort_store
import compact_campaign

SHOAL_OBSERVER_CONTRACT = "shoal-native-receipt-v1"


def settings(value, nodes, protocol="autobahn"):
    result = {"rate": 400, "useful_bytes": 472, "warmup": 1, "duration": 3, "drain": 5,
              "deadline_ms": 1000, "bound_ms": 100, "batch_ms": 10, "batch_bytes": 500000,
              "tokio_workers": 2, "startup_seconds":10, "faulty": [], "pause_replica": None, "pause_after": 1, "pause_seconds": .5,
              "omit_replica":None,"omission_after":1,"omission_seconds":.5,"publish_to_replica":[],
              "omit_repair":False,"attacker_rate":100,"crypto_meter":"off",
              "population_profile":None,"case":"healthy"}
    if set(value) - set(result): raise ValueError("unsupported native placement setting")
    result.update(value)
    compact=result['population_profile']=='compact-n10-n50-v1'
    if result['population_profile'] not in (None,'compact-n10-n50-v1'):raise ValueError('unknown native population profile')
    if compact:
        if nodes not in (4,10,50) or protocol not in ('mysticeti','autobahn','simpleit-mempool','simpleit-dispersed'):
            raise ValueError('compact native placement requires the selected4/10/50 implementation')
        if (result['warmup']!=0 or not 0<result['duration']<=60 or not 0<=result['drain']<=15
                or result['rate']>80000 or result['useful_bytes']>4096):
            raise ValueError('compact native workload envelope exceeded')
    elif nodes < 4 or nodes > 31 or (nodes - 1) % 3: raise ValueError("expected n=3f+1 in 4..31")
    if any(type(result[k]) is not int or result[k] <= 0 for k in ("rate", "useful_bytes", "bound_ms", "batch_ms", "batch_bytes", "tokio_workers")):
        raise ValueError("positive integer native settings required")
    if not isinstance(result["deadline_ms"],(int,float)) or isinstance(result["deadline_ms"],bool) or not 0<result["deadline_ms"]<=600000:
        raise ValueError("bounded positive native deadline required")
    if type(result["startup_seconds"]) is not int or not 1<=result["startup_seconds"]<=120:raise ValueError("native startup allowance must be1..120seconds")
    if result["useful_bytes"] > 1048576 or result["batch_bytes"] > 32*1024**2 or result["bound_ms"] > 60000 or result["tokio_workers"]>64:
        raise ValueError("native payload/timer envelope exceeded")
    if any(not isinstance(result[k], (int, float)) or isinstance(result[k], bool) or not 0 <= result[k] <= 300 for k in ("warmup", "duration", "drain")) or not result["duration"]:
        raise ValueError("bounded finite native run required")
    faulty = result["faulty"]
    if protocol.startswith('simpleit'):
        if (result['case'] not in ('healthy','missing-data','silent-first-leader') or result['warmup']!=0
                or result['crypto_meter']!='off' or result['pause_replica'] is not None or result['omit_replica'] is not None):
            raise ValueError('Simple-IT uses explicit native case hooks and no offered warmup')
        expected=[] if result['case']=='healthy' else [1 if result['case']=='silent-first-leader' else 0]
        if faulty!=expected:raise ValueError('Simple-IT faulty identities must match the fixed native hook')
    elif result['case']!='healthy':
        if protocol not in ('autobahn','mysticeti') or result['case']!='silent-first-leader' or faulty!=[1] or result['pause_replica'] is not None or result['omit_replica'] is not None:
            raise ValueError('native first-leader case requires fixed absent identity1 and no timed injection')
    if len(set(faulty)) != len(faulty) or len(faulty) > (nodes-1)//3 or any(type(i) is not int or not 0 <= i < nodes for i in faulty):
        raise ValueError("fixed faulty identities exceed budget")
    if result["pause_replica"] is not None and (result["pause_replica"] not in faulty or not 0 <= result["pause_after"] < result["duration"] or not 0 < result["pause_seconds"] <= result["duration"] - result["pause_after"]):
        raise ValueError("finite pause must target fixed faulty identity within measurement")
    correct = [i for i in range(nodes) if i not in faulty]
    if result["crypto_meter"] not in ("off","on") or type(result["attacker_rate"]) is not int:raise ValueError("invalid native meter/attacker setting")
    native_faults.validate(SimpleNamespace(**result,nodes=nodes,faulty_replica=faulty),protocol="autobahn" if protocol.startswith("autobahn") else protocol)
    rates = [result["rate"]//len(correct) + (correct.index(i) < result["rate"]%len(correct)) if i in correct else 0 for i in range(nodes)]
    if result["omit_replica"] is not None:rates[result["omit_replica"]]=result["attacker_rate"]
    counts = [int((result["warmup"] + result["duration"])*1e6)*rate//1000000 for rate in rates]
    if compact:
        plan=compact_campaign.origin_plan(result['rate'],round(result['duration']*1e6),nodes,correct)
        counts=plan['counts']
        if result['omit_replica'] is not None:
            counts[result['omit_replica']]=round(result['duration']*1e6)*result['attacker_rate']//1000000
    return {**result, "correct": correct, "rates": rates, "counts": counts}


def endpoints(protocol, ips):
    rows = []
    for i, ip in enumerate(ips):
        ports = [1500+i] if protocol == "mysticeti" else ([8000] if protocol == "shoal" else [9000+6*i, 9001+6*i, 9005+6*i])
        rows.append({"replica": i, "peer": [{"ip": ip, "port": p} for p in ports],
                     "control_port": 1500+len(ips)+i if protocol == "mysticeti" else (8001 if protocol == "shoal" else None)})
    return rows


def generate(protocol, root, ips, binaries, cfg, run_id, run=subprocess.run):
    """Generate one common ceremony, return exact per-host file allowlists."""
    if protocol.startswith('simpleit'):
        from baselines import simpleit_remote
        return simpleit_remote.generate(protocol,root,ips,binaries,cfg,run_id)
    root = Path(root); fixture = root/"fixture"; fixture.mkdir()
    n = len(ips); selected = [[] for _ in ips]
    def command(argv, env=None):
        result = run(argv, env=env, check=True, capture_output=True, text=True)
        return result.stdout
    if protocol == "mysticeti":
        (fixture/"node-parameters.yaml").write_text(mysticeti.node_parameters_text(cfg["bound_ms"]))
        command([binaries["mysticeti"], "benchmark-genesis", "--ips", *ips, "--working-directory", str(fixture/"genesis"),
                 "--node-parameters-path", str(fixture/"node-parameters.yaml")])
        for i in range(n):
            client = fixture/f"client-{i}.yaml"
            client.write_text(f'load: {cfg["rates"][i]}\ntransaction_size: {cfg["useful_bytes"]+40}\ninitial_delay:\n  secs: 1\n  nanos: 0\n')
            selected[i] = [fixture/"genesis/committee.yaml", fixture/"genesis/public-config.yaml", fixture/"genesis"/f"private-config-{i}.yaml", client]
    elif protocol.startswith("autobahn"):
        authorities = {}; keys=[]
        generated=[]
        for i in range(n):
            key=fixture/f'ceremony-{i}.json';command([binaries['node'],'generate_keys','--filename',str(key)])
            generated.append(json.loads(key.read_text()));key.unlink()
        generated.sort(key=lambda k:base64.b64decode(k['name'],validate=True))
        # Native SemiParallelRR starts at(slot1,view1): rank2 in BTreeMap.
        # Canonically place that key at deployment identity1 before any process
        # starts. This changes placement only, not native leader election.
        generated[1],generated[2]=generated[2],generated[1]
        for i, ip in enumerate(ips):
            key = fixture/f"key-{i}.json";key.write_text(json.dumps(generated[i]))
            keys.append(key); name = json.loads(key.read_text())["name"]; port=9000+6*i
            authorities[name] = {"stake":1,"consensus":{"consensus_to_consensus":f"{ip}:{port}"},
                "primary":{"primary_to_primary":f"{ip}:{port+1}","worker_to_primary":f"127.0.0.1:{port+2}"},
                "workers":{"0":{"primary_to_worker":f"127.0.0.1:{port+3}","transactions":f"127.0.0.1:{port+4}","worker_to_worker":f"{ip}:{port+5}"}}}
        (fixture/"committee.json").write_text(json.dumps({"authorities":authorities}))
        parameters={"timeout_delay":cfg["bound_ms"],"header_size":32,"max_header_delay":cfg["batch_ms"],"gc_depth":50,"sync_retry_delay":cfg["bound_ms"],"sync_retry_nodes":3,"batch_size":cfg["batch_bytes"],"max_batch_delay":cfg["batch_ms"],"use_optimistic_tips":True,"use_parallel_proposals":True,"k":4,"use_fast_path":True,"fast_path_timeout":cfg["bound_ms"],"use_ride_share":False,"car_timeout":cfg["bound_ms"],"simulate_asynchrony":False,"asynchrony_start":15000,"asynchrony_duration":3000}
        if protocol == "autobahn-blips": parameters.update(asynchrony_type=[],asynchrony_start=[],asynchrony_duration=[],affected_nodes=[],egress_penalty=0,use_fast_sync=False,use_exponential_timeouts=False)
        (fixture/"parameters.json").write_text(json.dumps(parameters))
        for i in range(n): selected[i]=[keys[i],fixture/"committee.json",fixture/"parameters.json"]
    elif protocol == "shoal":
        env=os.environ|{"SHOAL_BENCHMARK_VALIDATOR_IPS":",".join(ips)}
        stdout=command([binaries["shoal-fixture"],str(fixture/"genesis"),str(n),str(cfg["batch_bytes"]),str(cfg["batch_ms"]),str(cfg["bound_ms"])],env)
        authors={}
        for line in stdout.splitlines():
            parts=line.split()
            if len(parts)==4 and parts[0].isdigit():authors[int(parts[0])]=parts[3]
        if cfg["omit_replica"] is not None and set(authors)!=set(range(n)):raise ValueError("native Shoal omission requires exact ceremony author identities")
        (fixture/"authors.json").write_text(json.dumps(authors))
        if "DAG" not in (fixture/"genesis/on-chain-consensus.yaml").read_text(): raise ValueError("native ceremony did not select DAG")
        plans=[]
        for i in range(n):
            path=fixture/f"plan-{i}.jsonl"; plans.append(path)
            command([binaries["shoal-fixture"],"workload",str(path),run_id,str(i),str(cfg["counts"][i]),str(cfg["useful_bytes"])])
        for i in range(n): selected[i]=sorted(p for p in (fixture/"genesis"/str(i)).rglob("*") if p.is_file())+plans+[fixture/"genesis/on-chain-consensus.yaml",fixture/"authors.json"]
    else: raise ValueError("unsupported fixed native protocol")
    for row in selected:
        for path in row:
            if path.is_symlink() or not path.is_file() or fixture not in path.parents: raise ValueError("generated configuration escaped owned ceremony")
            path.chmod(0o600)
    return selected


def first_leader_record(protocol, root, replica):
    """Check the real author election against the private ceremony placement."""
    fixture=Path(root)/'fixture'
    if protocol=='autobahn':
        committee=json.loads((fixture/'committee.json').read_text())
        names=sorted(committee['authorities'],key=lambda s:base64.b64decode(s,validate=True))
        own=json.loads((fixture/f'key-{replica}.json').read_text())['name']
        if replica!=1 or own!=names[2]:raise ValueError('absent Autobahn identity is not(slot1,view1) leader')
        return {'replica':1,'author':own,'slot':1,'view':1,'native_rule':'BTreeMap rank(slot+view)%n'}
    if protocol=='mysticeti':
        if replica!=1:raise ValueError('absent Mysticeti identity is not round1 leader offset0')
        return {'replica':1,'round':1,'leader_offset':0,'native_rule':'(round+offset)%n',
            'other_leader_offset_1_remains_honest':True}
    raise ValueError('no absent-leader recipe for this native artifact')


def launches(protocol, root, replica, binaries, cfg, python, epoch_ns):
    root=Path(root); fixture=root/"fixture"; i=replica
    env={"RUST_LOG":"info","TOKIO_WORKER_THREADS":str(cfg["tokio_workers"])}
    if protocol=="mysticeti":
        env.update(CONSENSUS_ONLY="1",BENCHMARK_COHORT_PATH=str(root/"cohort.jsonl"),BENCHMARK_COHORT_START=str(root/"arrivals.start"),
            BENCHMARK_WARMUP_US=str(int(cfg["warmup"]*1e6)),BENCHMARK_DURATION_US=str(int(cfg["duration"]*1e6)),BENCHMARK_DRAIN_US=str(int(cfg["drain"]*1e6)),BENCHMARK_INGRESS_US=str(cfg["batch_ms"]*1000))
        if cfg.get('population_profile')=='compact-n10-n50-v1':
            env.update(BENCHMARK_POPULATION_PROFILE='compact-n10-n50-v1',BENCHMARK_GLOBAL_RATE=str(cfg['rate']),
                BENCHMARK_HONEST_ORIGINS=','.join(map(str,cfg['correct'])),BENCHMARK_MEMBER_COUNT=str(len(cfg['rates'])))
        return [("validator",[binaries["mysticeti"],"run","--authority",str(i),"--committee-path",str(fixture/"genesis/committee.yaml"),"--public-config-path",str(fixture/"genesis/public-config.yaml"),"--private-config-path",str(fixture/"genesis"/f"private-config-{i}.yaml"),"--client-parameters-path",str(fixture/f"client-{i}.yaml")],env)]
    if protocol.startswith("autobahn"):
        env.update(BENCHMARK_EPOCH_NS=str(epoch_ns),BENCHMARK_WARMUP_US=str(int(cfg["warmup"]*1e6)),BENCHMARK_DURATION_US=str(int(cfg["duration"]*1e6)))
        base=[binaries["node"],"-vv","run","--keys",str(fixture/f"key-{i}.json"),"--committee",str(fixture/"committee.json"),"--parameters",str(fixture/"parameters.json")]
        return [(role,base+["--store",str(root/("store-"+role)),*tail],env|{"BENCHMARK_OBSERVER_DIR":str(root/"observer"/role)}) for role,tail in (("primary",["primary"]),("worker-0",["worker","--id","0"]))]
    return [("validator",[binaries["aptos-node"],"-f",str(fixture/"genesis"/str(i)/"node.yaml")],env|{"BENCHMARK_COHORT_PATH":str(root/"cohort.jsonl"),"BENCHMARK_RUN_ID":root.name.removeprefix("delugi-native-"),"BENCHMARK_IO_PATH":str(root/"io.json"),"APTOS_DISABLE_TELEMETRY":"1","NO_PROXY":"*","no_proxy":"*"})]


class ShoalReadiness:
    """Bounded observation of the pinned native bootstrap and initialized meters.

    Shoal's output and meter hooks use the host monotonic clock directly. They
    need no workload epoch at launch; the origin and fault interval are armed
    only after the whole committee has prepared.
    """
    marker = b"The node has successfully bootstrapped!"
    operations = ("ordinary_sign", "ordinary_verify", "ordinary_verify_batch", "ordinary_verify_batch_multi")

    def __init__(self, root, replica, control_port, started_ns, crypto_meter, observer_plan=None):
        self.root = Path(root)
        self.replica, self.control_port = replica, control_port
        self.started_ns, self.crypto_meter = started_ns, crypto_meter
        self.observer_plan = observer_plan
        self.offset, self.tail, self.identity, self.bootstrapped = 0, b"", None, False

    @staticmethod
    def read_json(path):
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("native readiness counter is not a regular file")
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise ValueError("native readiness counter exceeds bounded size")
        return json.loads(raw)

    @staticmethod
    def unsigned(value):
        return type(value) is int and 0 <= value <= 2**64-1

    def observe(self, now=None):
        now = now or (lambda: time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        path = self.root / "logs/validator.log"
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            identity = (info.st_dev, info.st_ino)
            if not stat.S_ISREG(info.st_mode) or info.st_size < self.offset or self.identity not in (None, identity):
                raise ValueError("native readiness log was replaced or truncated")
            self.identity = identity
            if not self.bootstrapped:
                stream.seek(self.offset)
                # Bound each poll even when native logs grow faster than polling.
                raw = stream.read(1024*1024)
                self.offset += len(raw)
                joined = self.tail + raw
                self.bootstrapped = self.marker in joined
                self.tail = joined[-len(self.marker):]
        io = self.read_json(self.root / "io.json")
        now_ns = now()
        io_ready = False
        if io is not None:
            if not isinstance(io, dict) or any(not self.unsigned(io.get(k)) for k in ("observed_us", "written_bytes", "read_bytes")):
                raise ValueError("invalid native readiness TCP counters")
            if io["observed_us"] * 1000 > now_ns:
                raise ValueError("native readiness TCP sample is in the future")
            io_ready = self.started_ns <= io["observed_us"] * 1000 and now_ns - io["observed_us"] * 1000 <= 2_000_000_000
        cpu_ready = self.crypto_meter != "on"
        cpu = None
        if self.crypto_meter == "on":
            cpu = self.read_json(self.root / f"crypto-{self.replica}-validator.json")
            now_ns = now()
            if cpu is not None:
                if (not isinstance(cpu, dict) or cpu.get("schema") != 1
                        or not self.unsigned(cpu.get("monotonic_ns")) or not isinstance(cpu.get("operations"), dict)
                        or any(not isinstance(cpu["operations"].get(kind), dict)
                               or any(not self.unsigned(cpu["operations"][kind].get(field)) for field in ("calls", "thread_cpu_ns"))
                               for kind in self.operations)):
                    raise ValueError("invalid native readiness crypto counters")
                if cpu["monotonic_ns"] > now_ns:
                    raise ValueError("native readiness crypto sample is in the future")
                cpu_ready = self.started_ns <= cpu["monotonic_ns"] and now_ns - cpu["monotonic_ns"] <= 2_000_000_000
        api_ready = False
        try:
            with shoal_cohort.direct_urlopen(f"http://127.0.0.1:{self.control_port}/v1", timeout=.3) as reply:
                api_ready = reply.status == 200
        except OSError:
            pass
        receipt_ready = self.observer_plan is None
        if self.observer_plan is not None:
            common = self.read_json(self.root / f"receipt-{self.replica}/counters.json")
            if common is not None:
                # The finite native observer must have initialized before the
                # application can publish its first admission bit.
                expected = {"schema":1, "format":"shoal-native-counters-v1", "origin":self.replica, "mode":"full",
                            "run_id":self.observer_plan["run_id"], "plan_sha3_256":self.observer_plan["sha3_256"]}
                if (not isinstance(common, dict) or any(common.get(key) != value for key,value in expected.items())
                        or any(not self.unsigned(common.get(key)) for key in
                               ("schema", "origin", "observed_us", "output_count", "own_eligible_count", "payload_bytes", "batch_count"))
                        or common["own_eligible_count"] > self.observer_plan["counts"][self.replica]):
                    raise ValueError("invalid native finite observer readiness counters")
                sampled_now = now()
                if common["observed_us"] * 1000 > sampled_now:
                    raise ValueError("native observer readiness sample is in the future")
                receipt_ready = self.started_ns <= common["observed_us"] * 1000 and sampled_now - common["observed_us"] * 1000 <= 2_000_000_000
        return {"bootstrapped": self.bootstrapped, "io_ready": io_ready, "api_ready": api_ready,
                "crypto_ready": cpu_ready, "crypto_required": self.crypto_meter == "on",
                "receipt_ready": receipt_ready, "receipt_required": self.observer_plan is not None,
                "io_observed_us": io["observed_us"] if io else None,
                "crypto_observed_ns": cpu["monotonic_ns"] if cpu else None,
                "counter_validation_monotonic_ns": now_ns, "observed_monotonic_ns": now(),
                "ready": self.bootstrapped and io_ready and api_ready and cpu_ready and receipt_ready}


class ShoalObserver:
    """One host's authenticated finite plan, admission map and full receipt."""
    def __init__(self, root, replica, cfg):
        self.root, self.replica, self.cfg = Path(root), replica, cfg
        self.publisher = self.store = None
        self.receipt = self.verification = None
        try:
            self.store = native_cohort_store.NativeStore(self.root / "native-cohort-stage.sqlite")
            paths = [self.root / "fixture" / f"plan-{i}.jsonl" for i in range(len(cfg["counts"]))]
            run_id = self.root.name.removeprefix("delugi-native-")
            self.encoding = shoal_cohort.prepare_plan_store(self.store, paths, run_id, cfg["counts"], cfg["useful_bytes"])
            self.plan = shoal_receipts.prepare_plan(self.store, self.root, run_id, cfg["counts"], cfg["useful_bytes"])
            shoal_receipts.prepare_admission(self.root, self.plan, replica)
            self.publisher = shoal_receipts.AdmissionPublisher(self.root / f"admission-{replica}.bits", self.plan, replica)
        except BaseException:
            self.close()
            raise

    def environment(self):
        return shoal_receipts.environment(self.root, self.plan, self.replica, "full")

    def arm(self, epoch_ns):
        self.requested_us = epoch_ns // 1000 + sum(int(self.cfg[k]*1e6) for k in ("warmup", "duration", "drain"))
        shoal_receipts.arm_origin(self.root, self.plan, self.replica, self.requested_us)

    def await_receipt(self, processes):
        shoal_receipts.await_headers(self.root, len(self.cfg["counts"]), processes, origins=[self.replica])
        self.receipt = shoal_receipts.load(self.root, self.plan, self.replica, "full", self.requested_us)

    def archive(self, epoch_ns, admitted):
        if self.receipt is None:raise ValueError("native Shoal full receipt was not verified")
        self.verification = {
            "admissions": shoal_receipts.verify_admissions(admitted, self.receipt),
            "full_native_prefix": shoal_receipts.verify_full(self.receipt, self.root / "cohort.jsonl")}
        cfg=self.cfg
        shoal_cohort.collect_store(self.store, self.replica, native_cohort_store.journal_rows(admitted),
            native_cohort_store.journal_rows(self.root / "cohort.jsonl"), epoch_ns//1000,
            int(cfg["warmup"]*1e6), int(cfg["duration"]*1e6), int(cfg["drain"]*1e6),
            observed_us=self.receipt["header"]["frozen_us"])
        self.verification["own_first_output_eligibility"] = shoal_receipts.verify_local_eligibility(self.store, self.receipt)
        self.store.metadata[self.replica]["shoal_native_receipt"] = self.evidence()
        return self.store.archive(self.root / "cohorts")

    def evidence(self):
        if self.receipt is None:raise ValueError("native Shoal receipt is not available")
        return {"contract": SHOAL_OBSERVER_CONTRACT, "mode": "full", "origin": self.replica,
                "plan": {key:self.plan[key] for key in ("sha3_256", "run_id", "counts", "useful_bytes")},
                "requested_us": self.requested_us, "frozen_us": self.receipt["header"]["frozen_us"],
                "header_sha256": self.receipt["header_sha256"], "checkpoint_sha3_256": self.receipt["checkpoint_sha3_256"],
                "verification": self.verification, "native_workload_encoding": self.encoding}

    def close(self):
        if self.publisher is not None:self.publisher.close();self.publisher=None
        if self.store is not None:self.store.close();self.store=None


def collected_shoal_receipt(root, replica, cfg, run_id, epoch_ns, evidence, archive):
    """Recheck transferred full evidence before committee-wide useful credit."""
    if (evidence.get("contract") != SHOAL_OBSERVER_CONTRACT or evidence.get("mode") != "full"
            or evidence.get("origin") != replica or type(epoch_ns) is not int or epoch_ns <= 0):
        raise ValueError("unsupported native Shoal observer evidence")
    plan = evidence["plan"]
    if (plan.get("run_id") != run_id or plan.get("counts") != cfg["counts"]
            or plan.get("useful_bytes") != cfg["useful_bytes"]
            or shoal_receipts.file_digest(Path(root) / "observer-plan.json") != plan.get("sha3_256")):
        raise ValueError("transferred Shoal finite observer plan differs")
    requested = epoch_ns//1000 + sum(int(cfg[k]*1e6) for k in ("warmup", "duration", "drain"))
    if evidence.get("requested_us") != requested:raise ValueError("native Shoal freeze differs from host-local epoch")
    receipt = shoal_receipts.load(root, plan, replica, "full", requested)
    if any(evidence.get(key) != receipt[key] for key in ("header_sha256", "checkpoint_sha3_256")):
        raise ValueError("transferred Shoal receipt fingerprint differs")
    if evidence.get("frozen_us") != receipt["header"]["frozen_us"]:
        raise ValueError("transferred Shoal actual freeze endpoint differs")
    shoal_receipts.verify_admissions(Path(root)/"admitted.jsonl", receipt)
    shoal_receipts.verify_full(receipt, Path(root)/"cohort.jsonl")
    eligible=bytearray((cfg["counts"][replica]+7)//8)
    for row in archive.rows(replica,"requests"):
        if row["materialized_us"] is not None:eligible[row["sequence"]//8]|=1<<(row["sequence"]%8)
    if bytes(eligible)!=receipt["bits"][("own_eligible",replica)]:
        raise ValueError("transferred full cohort differs from native first-output eligibility")
    if sum(row["payload_bytes"] for row in archive.rows(replica,"batches"))!=receipt["header"]["payload_bytes"]:
        raise ValueError("transferred full cohort materialized bytes differ from native receipt")
    return receipt


def child_environment(protocol, values, inherited=None):
    env={k:v for k,v in (os.environ if inherited is None else inherited).items() if not k.startswith("BENCHMARK_")}
    env.update(values)
    if protocol=="shoal":
        # Upstream force-enable takes precedence over disable. Match the local
        # launcher, including when the supervisor inherits this override.
        env.pop("APTOS_FORCE_ENABLE_TELEMETRY",None)
        env["APTOS_DISABLE_TELEMETRY"]="1"
        # Aptos peer TCP also consults proxy variables. Build-download proxies
        # must not redirect the configured benchmark peers or local REST calls.
        env={key:value for key,value in env.items()
             if key.lower() not in {"http_proxy","https_proxy","all_proxy","no_proxy"}}
        env.update(NO_PROXY="*",no_proxy="*")
    return env


def fault_environment(protocol,root,index,role,cfg,ips):
    args=SimpleNamespace(**cfg,faulty_replica=cfg["faulty"],nodes=len(ips))
    peers={i:i for i in range(len(ips))}
    if protocol.startswith("autobahn"):peers={i:f"{ip}:{9005+6*i}" for i,ip in enumerate(ips)}
    if protocol=="shoal":peers={int(i):value for i,value in json.loads((Path(root)/"fixture/authors.json").read_text()).items()}
    env=native_faults.environment(args,Path(root),index,peers,role=role)
    if protocol.startswith("autobahn") and role=="primary":env={key:value for key,value in env.items() if not key.startswith("BENCHMARK_FAULT_")}
    if protocol=="shoal" and index==cfg["omit_replica"]:env["BENCHMARK_FAULT_AUTHOR"]=peers[index]
    return env


def application(protocol, root, replica, cfg, python, epoch_ns):
    if not protocol.startswith("autobahn"): return None
    command=[python,str(Path(__file__).with_name("autobahn_cohort.py")),"--origin",str(replica),"--rate",str(cfg["rates"][replica]),
            "--useful-bytes",str(cfg["useful_bytes"]),"--epoch-ns",str(epoch_ns),"--warmup-us",str(int(cfg["warmup"]*1e6)),
            "--duration-us",str(int(cfg["duration"]*1e6)),"--drain-us",str(int(cfg["drain"]*1e6)),"--workers","1",
            "--address",f"127.0.0.1:{9004+6*replica}","--observer-dir",str(Path(root)/"observer"),"--output",str(Path(root)/"ledger.json"),
            "--cohort-observer","full","--planned-counts",",".join(map(str,cfg["counts"]))]
    if cfg.get('population_profile')=='compact-n10-n50-v1':
        command+=['--global-rate',str(cfg['rate']),'--honest-origins',','.join(map(str,cfg['correct']))]
    return command


def ledger(protocol, root, replica, cfg, epoch_ns, admitted=None):
    root=Path(root)
    if protocol=="mysticeti": return mysticeti.read_cohort(root/"cohort.jsonl",replica)
    if protocol.startswith("autobahn"): return json.loads((root/"ledger.json").read_text())
    plans=[]
    for i,count in enumerate(cfg["counts"]): plans+=shoal_cohort.load_plan(root/"fixture"/f"plan-{i}.jsonl",root.name.removeprefix("delugi-native-"),i,count,cfg["useful_bytes"])
    raw=(root/"cohort.jsonl").read_bytes()
    if raw and not raw.endswith(b"\n"): raise ValueError("native journal ends mid-record")
    return shoal_cohort.collect(plans,admitted,[json.loads(line) for line in raw.splitlines()],epoch_ns//1000,int(cfg["warmup"]*1e6),int(cfg["duration"]*1e6),int(cfg["drain"]*1e6))


def archive_ledger(protocol, root, replica, cfg, epoch_ns, admitted=None):
    """Bounded campaign collection; legacy ledger() remains a replay API."""
    root=Path(root);store=native_cohort_store.NativeStore(root/"native-cohort-stage.sqlite",population_profile=cfg.get('population_profile'))
    try:
        if protocol=="mysticeti":store.mysticeti(root/"cohort.jsonl",replica,mysticeti.cohort_request_id)
        elif protocol.startswith("autobahn"):store.legacy(root/"ledger.json",replica)
        else:
            paths=[root/"fixture"/f"plan-{i}.jsonl" for i in range(len(cfg["counts"]))]
            shoal_cohort.prepare_plan_store(store,paths,root.name.removeprefix("delugi-native-"),cfg["counts"],cfg["useful_bytes"])
            rows=native_cohort_store.journal_rows(admitted) if isinstance(admitted,(str,Path)) else iter(admitted)
            shoal_cohort.collect_store(store,replica,rows,native_cohort_store.journal_rows(root/"cohort.jsonl"),
                epoch_ns//1000,int(cfg["warmup"]*1e6),int(cfg["duration"]*1e6),int(cfg["drain"]*1e6))
        return store.archive(root/"cohorts")
    finally:store.close()


def reduce_archives(archives, cfg, directory):
    directory=Path(directory)
    collection=native_cohort_store.combine_archives(archives,directory/"native-cohorts.json",population_profile=cfg.get('population_profile'))
    result=native_cohort_store.reduce_archive(collection,directory/"cohort-reduction.sqlite",cfg["correct"],cfg["deadline_ms"])
    return {**result,"clock":"origin-local ingress/materialization only; no subtraction across hosts",
            "comparison_eligible":False}


def reduce(ledgers, cfg):
    return {"cohort":cohort_metrics.summarize_cohorts(ledgers,correct_replicas=cfg["correct"],deadline_ms=cfg["deadline_ms"]),
            "agreement":mysticeti.check_output_prefixes({i:ledgers[i] for i in cfg["correct"]}),
            "clock":"origin-local ingress/materialization only; no subtraction across hosts",
            "comparison_eligible":False}
