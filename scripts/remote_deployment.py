"""Inventory-driven SSH placement shared by native benchmark adapters.

Control services stay on remote loopback and are reached through pinned-host-key
SSH tunnels. Inventory names exact existing hosts/artifacts; this module never
creates cloud resources, builds binaries, or kills processes outside its nonce.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import select
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from run_network import Child, ROOT, sha, unused_addresses
import timing_calibration


def validate_inventory(data, nodes=None):
    if data.get("schema") != 1 or not data.get("hosts"):
        raise ValueError("explicit schema1 host inventory required")
    if data.get("protocol") not in (None, "delugi") or data.get("remote_runner_supported") is False:
        raise ValueError("native remote workload adapter is unavailable; artifact publication alone does not enable a run")
    hosts = data["hosts"]
    if nodes is not None and len(hosts) != nodes:
        raise ValueError("inventory must place every validator exactly once")
    if sorted(h["replica"] for h in hosts) != list(range(len(hosts))):
        raise ValueError("replica IDs must be contiguous and unique")
    if len({h["ssh"] for h in hosts}) != len(hosts):
        raise ValueError("this profile requires one dedicated host per validator")
    settings = data.get("netem")
    if settings is not None and (not 0 <= settings.get("delay_ms", 0) <= 1000 or not 0 <= settings.get("loss_percent", 0) <= 100):
        raise ValueError("invalid scoped netem delay or packet loss")
    advertised = []
    for host in hosts:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+", host["ssh"]) or host["ssh"].startswith("-"):
            raise ValueError("invalid SSH target")
        address, port = host["advertised"].rsplit(":", 1)
        if ipaddress.ip_address(address).version != 4 or not 1 <= int(port) <= 65535:
            raise ValueError("remote profile currently requires literal IPv4 and valid TCP ports")
        advertised.append(host["advertised"])
        if settings is not None and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", host.get("network_interface", "")):
            raise ValueError("scoped netem requires the explicit ingress network interface")
        if not 1 <= host["control_port"] <= 65535 or host["control_port"] == int(port):
            raise ValueError("separate remote loopback control port required")
        binary = PurePosixPath(host["binary"]["path"])
        if not binary.is_absolute() or ".." in binary.parts or not re.fullmatch("[0-9a-f]{64}", host["binary"]["sha256"]):
            raise ValueError("remote binary requires an absolute path and exact SHA256")
        if "python_executable" in host:
            interpreter = host["python_executable"]
            if not isinstance(interpreter, str) or not PurePosixPath(interpreter).is_absolute() or ".." in PurePosixPath(interpreter).parts:
                raise ValueError("declared Python interpreter requires an absolute path")
        budget = host["budget"]
        if (not budget["cpus"] or any(type(v) is not int or v < 0 for v in budget["cpus"])
                or len(set(budget["cpus"])) != len(budget["cpus"]) or budget["memory_bytes"] <= 0):
            raise ValueError("explicit CPU set and total validator memory budget required")
        if budget.get("enforcement") not in ("dedicated_host", "cgroup"):
            raise ValueError("declare dedicated-host envelope or delegated-cgroup enforcement")
        if "swap_bytes" in budget and (type(budget["swap_bytes"]) is not int or budget["swap_bytes"] < 0):
            raise ValueError("declared swap budget must be nonnegative integer bytes")
        if budget["enforcement"] == "cgroup" and not budget.get("cgroup_parent"):
            raise ValueError("cgroup budget requires a delegated cgroup parent")
        for key in ("identity_file", "known_hosts_file"):
            if not Path(host[key]).expanduser().is_file():
                raise ValueError(f"missing explicit SSH {key}")
    if len(set(advertised)) != len(hosts):
        raise ValueError("advertised validator endpoints must be unique")
    return data


def ssh_arguments(host):
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=3",
            "-o", "UserKnownHostsFile=" + str(Path(host["known_hosts_file"]).expanduser()),
            "-i", str(Path(host["identity_file"]).expanduser())]


class RemoteProcess:
    def __init__(self, process, deployment, host, state):
        self.local, self.deployment, self.host, self.state = process, deployment, host, state

    def __getattr__(self, name):
        return getattr(self.local, name)

    def send_signal(self, signum):
        if self.local.poll() is not None:
            return
        self.deployment.rpc(self.host, {"action": "signal", "state": self.state,
            "nonce": self.deployment.nonce, "signal": signal.Signals(signum).name})

    def terminate(self):
        try:
            self.send_signal(signal.SIGTERM)
        finally:
            # Closing this SSH process does not authorize a host-wide kill.
            self.local.terminate()

    def kill(self):
        try:
            self.send_signal(signal.SIGKILL)
        finally:
            self.local.kill()


class RemoteChild(Child):
    def __init__(self, deployment, node_id, directory):
        self.id, self.events, self.errors = node_id, [], []
        self.deployment = deployment
        self.lock = threading.Lock()
        self.stderr = (directory / f"replica-{node_id}.stderr").open("w")
        host = deployment.hosts[node_id]
        remote = deployment.remote_directory
        request_path = remote + "/run.json"
        request = deployment.run_request(node_id)
        command = ssh_arguments(host) + [host["ssh"], shlex.join([deployment.remote_python(host), "-u", remote + "/remote_worker.py", "--request", request_path])]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1)
        self.process = RemoteProcess(process, deployment, host, request["state"])
        self.reader = threading.Thread(target=self._read, args=(directory,), daemon=True)
        self.reader.start()

    def finish(self):
        result = super().finish()
        summaries = [event for event in self.events if event.get("event") == "deployment_resource_summary"]
        if len(summaries) != 1:
            self.errors.append("remote whole-worker resource summary is missing or duplicated")
        else:
            self.deployment.machine_metadata[self.id]["resource_summary"] = {
                key: value for key, value in summaries[0].items() if not key.startswith("_controller_")}
        return result


class RemoteDeployment:
    def __init__(self, inventory):
        self.inventory = validate_inventory(copy.deepcopy(inventory))
        self.hosts = {host["replica"]: host for host in inventory["hosts"]}
        self.nonce = uuid.uuid4().hex
        self.remote_directory = "/tmp/delugi-evaluation-" + self.nonce
        self.tunnels, self.commands, self.machine_metadata = [], [], {}
        self.config = None
        self.netem_hosts, self.network_evidence = [], {}

    def remote_python(self, host):
        return host.get("python_executable", "python3")

    def protocol_endpoints(self, host):
        ip, port = host["advertised"].rsplit(":", 1)
        return [{"ip": ip, "port": int(port)}]

    def execute(self, host, arguments, *, input=None, timeout=60, check=True):
        command = ssh_arguments(host) + [host["ssh"], shlex.join(arguments)]
        result = subprocess.run(command, input=input, text=True, capture_output=True, timeout=timeout)
        self.commands.append({"host": host["ssh"], "arguments": arguments, "returncode": result.returncode})
        if check and result.returncode:
            raise RuntimeError(f"remote command failed on {host['ssh']}: {result.stderr[-2000:]}")
        return result

    def upload(self, host, source, destination):
        # Stream bounded chunks into the nonce-owned file; no encoded whole-file
        # copy is retained in either process or in the command evidence.
        code = """import hashlib,os,sys
p,expected=sys.argv[1:]; h=hashlib.sha256()
with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
 for block in iter(lambda:sys.stdin.buffer.read(1048576),b''):
  out.write(block); h.update(block)
if h.hexdigest()!=expected: raise ValueError('uploaded file digest mismatch')
"""
        digest = hashlib.sha256()
        with Path(source).open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        arguments = [self.remote_python(host), "-c", code, destination, digest.hexdigest()]
        command = ssh_arguments(host) + [host["ssh"], shlex.join(arguments)]
        with Path(source).open("rb") as stream:
            result = subprocess.run(command, stdin=stream, capture_output=True, timeout=60)
        self.commands.append({"host": host["ssh"], "arguments": arguments, "returncode": result.returncode})
        if result.returncode:
            raise RuntimeError("remote upload failed on %s: %s" % (host["ssh"], result.stderr[-2000:].decode(errors="replace")))

    def run_request(self, replica):
        host, remote = self.hosts[replica], self.remote_directory
        return {"action": "run", "nonce": self.nonce, "binary": host["binary"]["path"],
                "binary_sha256": host["binary"]["sha256"], "directory": remote,
                "state": remote + "/process.json", "budget": host["budget"],
                "max_runtime_seconds": self.config["max_runtime_ms"] / 1000 + 30,
                "arguments": ["--config", remote + "/config.json", "--id", str(replica)]}

    def rpc(self, host, request):
        return json.loads(self.execute(host, [self.remote_python(host), self.remote_directory + "/remote_worker.py"],
                                       input=json.dumps(request)).stdout)

    def prepare(self, config, directory):
        validate_inventory(self.inventory, len(config["addresses"]))
        self.config = config
        count = len(self.hosts)
        config["addresses"] = [self.hosts[i]["advertised"] for i in range(count)]
        config["bind_addresses"] = [self.hosts[i].get("bind", "0.0.0.0:" + self.hosts[i]["advertised"].rsplit(":", 1)[1]) for i in range(count)]
        remote_controls = ["127.0.0.1:" + str(self.hosts[i]["control_port"]) for i in range(count)]
        config["control_addresses"] = remote_controls
        local_controls = unused_addresses(count)
        for replica, host in self.hosts.items():
            self.execute(host, ["mkdir", "-m", "700", self.remote_directory])
            self.upload(host, ROOT / "scripts/remote_worker.py", self.remote_directory + "/remote_worker.py")
            if self.inventory.get("netem"):
                self.upload(host, ROOT / "scripts/linux_netem.py", self.remote_directory + "/linux_netem.py")
                if self.inventory['netem'].get('rate_mbps') is not None:
                    self.upload(host, ROOT / 'scripts/linux_egress.py',self.remote_directory+'/linux_egress.py')
            self.machine_metadata[replica] = self.rpc(host, {"action": "inspect", "binary": host["binary"]["path"]})
            if self.machine_metadata[replica]["binary_sha256"] != host["binary"]["sha256"]:
                raise ValueError("remote inventory binary hash does not match host")
            stamp = self.machine_metadata[replica].get("build_stamp")
            sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted((ROOT / "src").rglob("*.rs"))]
            expected_sources = {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in sources}
            if host.get('artifact') is not None:
                artifact=host['artifact']
                publication=json.loads(self.execute(host,[self.remote_python(host),
                    artifact['directory']+'/source/scripts/common_artifact.py','verify',
                    '--directory',artifact['directory'],'--host','--archive',artifact['directory']+'.tar.gz',
                    '--archive-sha256',artifact['archive_sha256']],timeout=180).stdout)
                if publication['binary_sha256']!=host['binary']['sha256']:raise ValueError('common publication and selected node differ')
                self.machine_metadata[replica]['common_publication']=publication
            elif (not stamp or stamp.get("binary_sha256") != host["binary"]["sha256"]
                    or stamp.get("inputs", {}).get("sources") != expected_sources):
                raise ValueError("remote native artifact lacks a build stamp matching the selected current Rust source")
            local_key = config["key_files"][replica]
            self.upload(host, local_key, self.remote_directory + f"/key-{replica}.json")
            remote_config = copy.deepcopy(config)
            remote_config["key_files"] = [self.remote_directory + f"/key-{i}.json" for i in range(count)]
            if remote_config.get('storage_profile')=='shared-rocksdb-written-v1':
                if not getattr(self,'shared_storage',False):raise ValueError('remote shared storage profile is not enabled by this adapter')
                remote_config['storage_directory']=self.remote_directory+'/records'
                self.execute(host,['mkdir','-m','700',remote_config['storage_directory']])
            path = directory / f"remote-config-{replica}.json"
            path.write_text(json.dumps(remote_config, indent=2))
            self.upload(host, path, self.remote_directory + "/config.json")
            run_path = directory / f"remote-run-{replica}.json"
            run_path.write_text(json.dumps(self.run_request(replica), indent=2))
            self.upload(host, run_path, self.remote_directory + "/run.json")
            command = ssh_arguments(host) + ["-o", "ExitOnForwardFailure=yes", "-N", "-L",
                local_controls[replica] + ":" + remote_controls[replica], host["ssh"]]
            stderr = (directory / f"tunnel-{replica}.stderr").open("w")
            tunnel = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
            self.tunnels.append((tunnel, stderr))
        controller_config = copy.deepcopy(config)
        controller_config["control_addresses"] = local_controls
        return controller_config

    def child(self, replica, directory):
        for tunnel, _ in self.tunnels:
            if tunnel.poll() is not None:
                raise RuntimeError("owned SSH control tunnel exited")
        return RemoteChild(self, replica, directory)

    def configure_network(self):
        settings = self.inventory.get("netem")
        if not settings:
            return None
        echoes = []
        try:
            echoes = self.start_echoes("before")
            self.network_evidence["before"] = self.calibrate_ring()
            baseline = self.calibration_records(self.network_evidence["before"])
            for replica, host in self.hosts.items():
                peers = [endpoint for other_id, other in self.hosts.items() if other_id != replica for endpoint in self.protocol_endpoints(other)]
                request = {"action": "configure", "nonce": self.nonce,
                           "interface": host["network_interface"], "peers": peers,
                           "local_ports": [endpoint["port"] for endpoint in self.protocol_endpoints(host)],
                           "delay_ms": settings.get("delay_ms", 0), "loss_percent": settings.get("loss_percent", 0)}
                # Register before applying so partial setup still gets cleanup.
                self.netem_hosts.append(host)
                configured = self.netem_rpc(host, request)
                self.network_evidence.setdefault("configuration", {})[replica] = configured
                if not configured.get("active_objects_complete") or not configured.get("physical_qdisc_configuration_unchanged"):
                    raise RuntimeError("scoped netem objects or preserved physical queue configuration failed verification")
            self.network_evidence["configured"] = self.calibrate_ring()
            active = self.calibration_records(self.network_evidence["configured"])
            comparisons = []
            for edge in sorted(baseline):
                check = timing_calibration.addition(baseline[edge]["median"], active[edge]["median"], settings.get("delay_ms", 0))
                comparisons.append({"source": edge[0], "destination": edge[1], "protocol_role_index": edge[2],
                                    **check, "delay_within_calibration_tolerance": check["addition_matches"]})
            self.network_evidence["calibration"] = comparisons
            if not all(c["delay_within_calibration_tolerance"] for c in comparisons):
                raise RuntimeError("peer RTTs do not verify the configured added delay")
            self.network_evidence.update(backend="Linux_tc_netem_scoped_ingress", settings=settings,
                edge_scope="directed ring covering each replica as sender and receiver; raw RTT samples retained",
                loss_scope="kernel TCP packet loss, separate from semantic payload omission")
            return self.network_evidence
        except BaseException:
            self.clear_network(verify_after=False)
            raise
        finally:
            self.stop_echoes(echoes)

    def start_echoes(self, phase):
        echoes = []
        try:
            for host in self.hosts.values():
                state = self.remote_directory + "/echo-" + phase + "-" + uuid.uuid4().hex + ".json"
                request = {"action": "echo", "nonce": self.nonce, "state": state,
                           "bind_ip": "0.0.0.0", "port": int(host["advertised"].rsplit(":", 1)[1]),
                           "lifetime_seconds": 180}
                command = ssh_arguments(host) + [host["ssh"], shlex.join([self.remote_python(host), "-u", self.remote_directory + "/remote_worker.py"])]
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                echoes.append((host, process, state))
                process.stdin.write(json.dumps(request))
                process.stdin.close()
                ready, _, _ = select.select([process.stdout], [], [], 20)
                if not ready or json.loads(process.stdout.readline()).get("ready") is not True:
                    raise RuntimeError("owned calibration echo did not become ready within 20 seconds")
            return echoes
        except BaseException:
            self.stop_echoes(echoes)
            raise

    def stop_echoes(self, echoes):
        errors = []
        for host, process, state in echoes:
            try:
                if process.poll() is None:
                    self.rpc(host, {"action": "signal", "nonce": self.nonce,
                                   "state": state, "signal": "SIGTERM"})
                    process.wait(timeout=10)
            except Exception as error:
                errors.append(f"{host['ssh']}: {error}")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()
        if errors:
            self.network_evidence.setdefault("echo_cleanup_errors", []).extend(errors)
            raise RuntimeError("; ".join(errors))

    def calibrate_ring(self):
        count = len(self.hosts)
        def sample(replica):
            destination = (replica + 1) % count
            host, peer = self.hosts[replica], self.hosts[destination]
            ip, port = peer["advertised"].rsplit(":", 1)
            return {"source": replica, "destination": destination,
                    **self.rpc(host, {"action": "probe", "ip": ip, "port": int(port), "count": 20})}
        with ThreadPoolExecutor(max_workers=count) as workers:
            return list(workers.map(sample, range(count)))

    def calibration_records(self, rows):
        count = len(self.hosts)
        roles = len(self.protocol_endpoints(self.hosts[0]))
        if any(len(self.protocol_endpoints(host)) != roles for host in self.hosts.values()):
            raise ValueError("native protocol role population differs across hosts")
        expected = {(i, (i + 1) % count, role) for role in range(roles) for i in range(count)}
        return timing_calibration.edge_records(rows, expected, require_roles=roles > 1)

    def netem_rpc(self, host, request):
        response = json.loads(self.execute(host, ["sudo", "-n", self.remote_python(host), self.remote_directory + "/linux_netem.py"],
                                          input=json.dumps(request)).stdout)
        if response.get("ok") is not True:
            raise RuntimeError(response.get("error", "owned netem helper failed"))
        return response["result"]

    def clear_network(self, verify_after=True):
        results, errors = {}, []
        had_netem = bool(self.netem_hosts)
        for host in self.netem_hosts:
            try:
                self.network_evidence.setdefault("final_status", {})[host["replica"]] = self.netem_rpc(host, {"action": "status", "nonce": self.nonce})
            except Exception as error:
                self.network_evidence.setdefault("final_status_errors", {})[host["replica"]] = str(error)
            try:
                results[host["replica"]] = self.netem_rpc(host, {"action": "clear", "nonce": self.nonce})
                if results[host["replica"]].get("phase") != "cleared" or not results[host["replica"]].get("physical_qdisc_configuration_unchanged"):
                    raise RuntimeError("owned netem cleanup failed verification")
            except Exception as error:
                errors.append(f"{host['ssh']}: {error}")
        if errors:
            raise RuntimeError("; ".join(errors))
        self.netem_hosts = []
        self.network_evidence["cleanup"] = results
        if verify_after and had_netem and self.network_evidence.get("before"):
            echoes = self.start_echoes("after")
            try:
                self.network_evidence["after_cleanup"] = self.calibrate_ring()
                baseline = self.calibration_records(self.network_evidence["before"])
                after = self.calibration_records(self.network_evidence["after_cleanup"])
                checks = [{"source": edge[0], "destination": edge[1], "protocol_role_index": edge[2],
                           "baseline_median_rtt_ms": baseline[edge]["median"],
                           "after_median_rtt_ms": after[edge]["median"],
                           "returned_to_baseline": timing_calibration.restored(baseline[edge]["median"], after[edge]["median"])}
                          for edge in sorted(baseline)]
                self.network_evidence["cleanup_calibration"] = checks
                if not all(check["returned_to_baseline"] for check in checks):
                    raise RuntimeError("peer RTT did not return to baseline after owned netem cleanup")
            finally:
                self.stop_echoes(echoes)
        return results

    def close(self):
        errors = []
        if self.netem_hosts:
            try:
                self.clear_network()
            except Exception as error:
                errors.append(str(error))
        for tunnel, stream in self.tunnels:
            try:
                if tunnel.poll() is None:
                    tunnel.terminate()
                    try:
                        tunnel.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        tunnel.kill()
                        tunnel.wait(timeout=5)
            except Exception as error:
                errors.append(str(error))
            finally:
                stream.close()
        if errors:
            raise RuntimeError("; ".join(errors))
        return {"nonce": self.nonce, "remote_run_directory": self.remote_directory,
                "tunnels_closed": all(t.poll() is not None for t, _ in self.tunnels),
                "remote_artifacts": "retained in nonce-owned directory; no source/build/host-wide cleanup"}

    def provenance(self):
        return {"schema": 1, "nonce": self.nonce, "inventory": self.inventory,
                "remote_run_directory": self.remote_directory, "machines": self.machine_metadata,
                "commands": self.commands, "helper_sha256": sha((ROOT / "scripts/remote_worker.py").read_bytes()),
                "resource_scope": "one native validator and all descendant workers per declared host/cgroup",
                "control": "authenticated native loopback service via strict-host-key SSH tunnels"}

    def launch_plan(self):
        """Reviewable argv, not an executed cloud provisioning recipe."""
        return {"nonce": self.nonce, "remote_directory": self.remote_directory,
                "hosts": [{"replica": i, "ssh": host["ssh"], "artifact": host["binary"],
                           "advertised": host["advertised"], "budget": host["budget"],
                           "preflight": ssh_arguments(host) + [host["ssh"], "python3 <uploaded-owned-worker> (inspect pinned native artifact and build stamp)"],
                           "native_arguments": ["--config", self.remote_directory + "/config.json", "--id", str(i)],
                           "control": f"local ephemeral tunnel to remote 127.0.0.1:{host['control_port']}",
                           "netem_privilege": "sudo -n python3 <uploaded-scoped-netem-helper>" if self.inventory.get("netem") else None}
                          for i, host in self.hosts.items()],
                "cleanup": "native stop, nonce/PID-start guarded termination if necessary, remove only owned netem handles, close owned SSH tunnels"}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--plan-output", type=Path, required=True)
    arguments = parser.parse_args()
    deployment = RemoteDeployment(json.loads(arguments.inventory.read_text()))
    arguments.plan_output.write_text(json.dumps(deployment.launch_plan(), indent=2) + "\n")
    print(arguments.plan_output)
