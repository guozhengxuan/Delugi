import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from remote_deployment import RemoteDeployment, RemoteProcess, RemoteChild, ssh_arguments, validate_inventory
import remote_worker


def ring_rtts(value):
    return [{"source": i, "destination": (i+1)%4, "median_rtt_ms": value, "samples_ms": [value]*20} for i in range(4)]


class OwnedRemotePlacement(unittest.TestCase):
    def test_remote_child_retains_actual_wrapper_resource_proof_before_provenance(self):
        child=RemoteChild.__new__(RemoteChild);child.id=0;child.errors=[]
        child.deployment=Mock(machine_metadata={0:{}})
        child.events=[{"event":"startup"},{"event":"deployment_resource_summary","nonce":"owned",
            "effective_budget":{"cpus":[0]},"_controller_received_monotonic_ns":999}]
        with patch("remote_deployment.Child.finish",return_value={"telemetry_errors":child.errors}):
            result=child.finish()
        self.assertEqual(result["telemetry_errors"],[])
        self.assertEqual(child.deployment.machine_metadata[0]["resource_summary"]["nonce"],"owned")
        self.assertNotIn("_controller_received_monotonic_ns",child.deployment.machine_metadata[0]["resource_summary"])
        child.events=[]
        with patch("remote_deployment.Child.finish",return_value={"telemetry_errors":child.errors}):
            self.assertTrue(child.finish()["telemetry_errors"])

    @unittest.skipUnless(hasattr(os, "fork") and hasattr(os, "killpg"), "POSIX owned process groups required")
    def test_stopped_descendant_is_drained_after_its_supervisor_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "descendant.pid"
            code = """import os,signal,sys,time
pid=os.fork()
if pid==0:
 signal.signal(signal.SIGTERM,signal.SIG_IGN if sys.argv[2]=='ignore' else signal.SIG_DFL)
 os.kill(os.getpid(),signal.SIGSTOP)
 time.sleep(60)
 os._exit(0)
os.waitpid(pid,os.WUNTRACED)
open(sys.argv[1],'w').write(str(pid))
os._exit(0)
"""
            unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"], start_new_session=True)
            try:
                for mode in ("default", "ignore"):
                    child = subprocess.Popen([sys.executable, "-c", code, str(marker), mode], start_new_session=True)
                    try:
                        self.assertEqual(child.wait(timeout=5), 0)
                        descendant = int(marker.read_text())
                        os.kill(descendant, 0)  # The exited supervisor did not clean its paused child.
                        report = remote_worker.finish_owned_group(child, term_seconds=.15, kill_seconds=3)
                        self.assertTrue(report["group_empty"])
                        self.assertTrue(report["remaining_group_after_leader"])
                        self.assertEqual(report["signals"][:2], ["SIGCONT", "SIGTERM"])
                        self.assertEqual("SIGKILL" in report["signals"], mode == "ignore")
                        with self.assertRaises(ProcessLookupError): os.killpg(child.pid, 0)
                        self.assertIsNone(unrelated.poll())
                    finally:
                        try: os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        child.wait()
            finally:
                unrelated.terminate(); unrelated.wait(timeout=5)

    def test_owned_group_that_remains_after_kill_is_a_failure(self):
        child = Mock(pid=1234)
        with patch.object(remote_worker.os, "killpg") as kill:
            with self.assertRaisesRegex(RuntimeError, "remains"):
                remote_worker.finish_owned_group(child, term_seconds=0, kill_seconds=0)
        self.assertIn(((1234, signal.SIGKILL),), [(call.args,) for call in kill.call_args_list])

    def test_process_exit_state_waits_for_descendant_cleanup_and_accounts_timeout(self):
        for timed_out in (False, True):
            with self.subTest(timed_out=timed_out), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.json"
                child = Mock(pid=1234)
                child.wait.side_effect = [subprocess.TimeoutExpired("fixture", 1), 0] if timed_out else [0, 0]
                cleanup = {"group_empty": True, "remaining_group_after_leader": True, "signals": ["SIGCONT", "SIGTERM"]}
                request = {"binary": sys.executable, "binary_sha256": remote_worker.sha(sys.executable),
                    "state": str(path), "budget": {}, "nonce": "owned", "arguments": [], "directory": directory, "max_runtime_seconds": 1}
                with patch.object(remote_worker.os, "sched_getaffinity", return_value={0}, create=True),\
                     patch.object(remote_worker, "validate_resource_budget", return_value={}),\
                     patch.object(remote_worker, "make_cgroup", return_value=None),\
                     patch.object(remote_worker, "pid_start", return_value="same"),\
                     patch.object(remote_worker.subprocess, "Popen", return_value=child),\
                     patch.object(remote_worker.signal, "signal"),\
                     patch.object(remote_worker, "finish_owned_group", return_value=cleanup) as finish,\
                     patch("builtins.print"):
                    self.assertEqual(remote_worker.process_run(request), 124 if timed_out else 125)
                state = json.loads(path.read_text())
                self.assertTrue(state["owned_group_cleanup"]["group_empty"])
                self.assertEqual(state["native_exit_code"], 0)
                self.assertEqual(state["timed_out"], timed_out)
                finish.assert_called_once_with(child)

    def test_dedicated_host_does_not_pretend_to_enforce_a_smaller_memory_cap(self):
        spec = {"enforcement": "dedicated_host", "cpus": [1, 3], "memory_bytes": 16 * 2**30}
        actual = 15 * 2**30
        effective = remote_worker.validate_resource_budget(spec, {0, 1, 2, 3}, actual)
        self.assertEqual(effective["memory_limit_bytes"], actual)
        self.assertEqual(effective["memory_enforcement"], "physical_host")
        spec["memory_bytes"] = 2**30
        with self.assertRaisesRegex(ValueError, "below host RAM"):
            remote_worker.validate_resource_budget(spec, {0, 1, 2, 3}, actual)
        spec.update(enforcement="cgroup", cgroup_parent="/sys/fs/cgroup/benchmarks")
        effective = remote_worker.validate_resource_budget(spec, {0, 1, 2, 3}, actual)
        self.assertEqual(effective["memory_limit_bytes"], 2**30)
        self.assertEqual(effective["memory_enforcement"], "cgroup_memory_max")

    def test_remote_worker_rejects_ambiguous_or_impossible_resource_envelopes(self):
        base = {"enforcement": "dedicated_host", "cpus": [0], "memory_bytes": 16 * 2**30}
        for changes in ({"cpus": []}, {"cpus": [False]}, {"cpus": [0, 0]},
                        {"cpus": [4]}, {"memory_bytes": True}, {"memory_bytes": -1},
                        {"cgroup_parent": "/sys/fs/cgroup/benchmarks"},
                        {"enforcement": "cgroup"}, {"enforcement": "anything"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                remote_worker.validate_resource_budget(base | changes, {0, 1}, 15 * 2**30)
        with self.assertRaisesRegex(ValueError, "no greater than host RAM"):
            remote_worker.validate_resource_budget(base | {"enforcement": "cgroup",
                "cgroup_parent": "/sys/fs/cgroup/benchmarks"}, {0, 1}, 15 * 2**30)

    def test_swap_capacity_is_explicit_and_unknown_is_not_zero(self):
        spec = {"enforcement": "dedicated_host", "cpus": [0], "memory_bytes": 16 * 2**30, "swap_bytes": 0}
        effective = remote_worker.validate_resource_budget(spec, {0}, 15 * 2**30, 0)
        self.assertTrue(effective["swap_policy_verified"])
        self.assertEqual(effective["swap_limit_bytes"], 0)
        for observed in (None, 2**30):
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                remote_worker.validate_resource_budget(spec, {0}, 15 * 2**30, observed)
        legacy = dict(spec); legacy.pop("swap_bytes")
        effective = remote_worker.validate_resource_budget(legacy, {0}, 15 * 2**30, 2**30)
        self.assertFalse(effective["swap_policy_verified"])
        self.assertEqual(effective["host_swap_bytes"], 2**30)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meminfo"
            self.assertIsNone(remote_worker.host_swap_bytes(path))
            path.write_text("MemTotal: 16000000 kB\nSwapTotal: 4096 kB\n")
            self.assertEqual(remote_worker.host_swap_bytes(path), 4096 * 1024)
            path.write_text("SwapTotal: invalid kB\n")
            with self.assertRaises(ValueError): remote_worker.host_swap_bytes(path)

    def test_cgroup_swap_is_configured_read_back_and_requires_controller(self):
        data = {"/sys/fs/cgroup/bench/cgroup.procs": "", "/sys/fs/cgroup/bench/delugi-owned/memory.swap.max": "max"}
        class CgroupPath:
            def __init__(self, value): self.value = value
            def __str__(self): return self.value
            def __truediv__(self, value): return CgroupPath(self.value + "/" + value)
            def resolve(self): return self
            def exists(self): return self.value in data
            def mkdir(self, **kwargs): pass
            def rmdir(self): pass
            def write_text(self, value): data[self.value] = value
            def read_text(self): return data[self.value]
        spec = {"enforcement": "cgroup", "cpus": [0], "memory_bytes": 2**30,
                "swap_bytes": 0, "cgroup_parent": "/sys/fs/cgroup/bench"}
        effective = remote_worker.validate_resource_budget(spec, {0}, 16 * 2**30, 4 * 2**30)
        self.assertEqual(effective["swap_enforcement"], "cgroup_memory_swap_max")
        with patch.object(remote_worker, "Path", CgroupPath):
            remote_worker.make_cgroup(spec, "owned")
            self.assertEqual(data["/sys/fs/cgroup/bench/delugi-owned/memory.swap.max"], "0")
            del data["/sys/fs/cgroup/bench/delugi-owned/memory.swap.max"]
            with self.assertRaisesRegex(ValueError, "memory.swap.max"):
                remote_worker.make_cgroup(spec, "owned")

    def inventory(self, directory):
        identity, known = Path(directory) / "identity", Path(directory) / "known_hosts"
        identity.write_text("fixture, never used to connect")
        known.write_text("fixture, never used to connect")
        return {"schema": 1, "hosts": [{"replica": i, "ssh": f"ubuntu@node-{i}",
            "identity_file": str(identity), "known_hosts_file": str(known),
            "advertised": f"10.0.0.{i+1}:9000", "control_port": 9001,
            "binary": {"path": "/opt/delugi/delugi-replica", "sha256": "a" * 64},
            "budget": {"enforcement": "dedicated_host", "cpus": [0, 1], "memory_bytes": 2**30}}
            for i in range(4)]}

    def test_every_host_key_and_artifact_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.inventory(directory)
            self.assertEqual(validate_inventory(data, 4), data)
            command = ssh_arguments(data["hosts"][0])
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("BatchMode=yes", command)
            data["hosts"][0]["binary"]["sha256"] = "unpinned"
            with self.assertRaisesRegex(ValueError, "SHA256"):
                validate_inventory(data)

    def test_shared_hosts_and_missing_resource_enforcement_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            data = self.inventory(directory)
            data["hosts"][1]["ssh"] = data["hosts"][0]["ssh"]
            with self.assertRaisesRegex(ValueError, "dedicated host"):
                validate_inventory(data)
            data = self.inventory(directory)
            data["hosts"][0]["budget"]["enforcement"] = "unlimited"
            with self.assertRaisesRegex(ValueError, "enforcement"):
                validate_inventory(data)

    def test_ssh_argument_injection_and_control_port_overlap_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for change in ({"ssh": "ubuntu@host; touch /tmp/unowned"}, {"control_port": 9000},
                           {"python_executable": "python3"}, {"python_executable": "/opt/../python3"}):
                data = self.inventory(directory)
                data["hosts"][0].update(change)
                with self.assertRaises(ValueError):
                    validate_inventory(data)

    def test_remote_signal_uses_nonce_owned_state_not_local_ssh_pid(self):
        local, deployment = Mock(), Mock()
        local.poll.return_value = None
        deployment.nonce = "a" * 32
        process = RemoteProcess(local, deployment, {"replica": 2}, "/tmp/owned/process.json")
        process.send_signal(signal.SIGSTOP)
        deployment.rpc.assert_called_once_with({"replica": 2}, {
            "action": "signal", "state": "/tmp/owned/process.json", "nonce": "a" * 32, "signal": "SIGSTOP"})
        local.send_signal.assert_not_called()

    def test_native_launch_preserves_one_process_and_all_worker_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = RemoteDeployment(self.inventory(directory))
            deployment.config = {"max_runtime_ms": 10000}
            request = deployment.run_request(2)
            self.assertEqual(request["budget"]["cpus"], [0, 1])
            self.assertEqual(request["arguments"][-2:], ["--id", "2"])
            self.assertTrue(request["state"].startswith("/tmp/delugi-evaluation-"))
            self.assertEqual(request["nonce"], deployment.nonce)

    def test_live_calibration_rejects_bad_raw_evidence_and_clears_applied_rules(self):
        for phase in ("before", "configured"):
            for mutation in ("median", "missing", "duplicate"):
                with self.subTest(phase=phase, mutation=mutation), tempfile.TemporaryDirectory() as directory:
                    inventory = self.inventory(directory)
                    inventory["netem"] = {"delay_ms": 10}
                    for host in inventory["hosts"]: host["network_interface"] = "eth0"
                    deployment = RemoteDeployment(inventory)
                    baseline, active = ring_rtts(1), ring_rtts(21)
                    bad = baseline if phase == "before" else active
                    if mutation == "median": bad[0]["samples_ms"] = [100]*20
                    elif mutation == "missing": bad.pop()
                    else: bad[-1] = copy.deepcopy(bad[0])
                    deployment.start_echoes = Mock(return_value=[])
                    deployment.stop_echoes = Mock()
                    deployment.calibrate_ring = Mock(side_effect=[baseline, active])
                    deployment.netem_rpc = Mock(return_value={"active_objects_complete": True,
                        "physical_qdisc_configuration_unchanged": True, "phase": "cleared"})
                    with self.assertRaises(ValueError): deployment.configure_network()
                    actions = [call.args[1]["action"] for call in deployment.netem_rpc.call_args_list]
                    self.assertEqual(actions.count("configure"), 0 if phase == "before" else 4)
                    self.assertEqual(actions.count("clear"), 0 if phase == "before" else 4)
                    self.assertEqual(deployment.netem_hosts, [])
                    deployment.stop_echoes.assert_called_once_with([])

    def test_live_calibration_joins_edges_by_identity_and_enforces_zero_delay(self):
        for delay, active, accepted in ((10, 21, True), (10, 27, False), (0, 4, False)):
            with self.subTest(delay=delay, active=active), tempfile.TemporaryDirectory() as directory:
                inventory = self.inventory(directory)
                inventory["netem"] = {"delay_ms": delay}
                for host in inventory["hosts"]: host["network_interface"] = "eth0"
                deployment = RemoteDeployment(inventory)
                deployment.start_echoes = Mock(return_value=[])
                deployment.stop_echoes = Mock()
                deployment.calibrate_ring = Mock(side_effect=[ring_rtts(1), list(reversed(ring_rtts(active)))])
                deployment.netem_rpc = Mock(return_value={"active_objects_complete": True,
                    "physical_qdisc_configuration_unchanged": True, "phase": "cleared"})
                if accepted:
                    evidence = deployment.configure_network()
                    self.assertEqual([row["source"] for row in evidence["calibration"]], list(range(4)))
                    self.assertTrue(all(row["addition_matches"] for row in evidence["calibration"]))
                    deployment.clear_network(verify_after=False)
                else:
                    with self.assertRaisesRegex(RuntimeError, "configured added delay"):
                        deployment.configure_network()
                self.assertEqual(deployment.netem_hosts, [])

    def test_clear_is_attempted_when_status_fails_and_checks_after_rtt(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = RemoteDeployment(self.inventory(directory))
            deployment.netem_hosts = [deployment.hosts[0]]
            deployment.network_evidence["before"] = ring_rtts(2)
            deployment.netem_rpc = Mock(side_effect=[RuntimeError("status unavailable"),
                {"phase": "cleared", "physical_qdisc_configuration_unchanged": True}])
            deployment.start_echoes = Mock(return_value=[])
            deployment.stop_echoes = Mock()
            deployment.calibrate_ring = Mock(return_value=ring_rtts(2.1))
            deployment.clear_network()
            self.assertEqual([c.args[1]["action"] for c in deployment.netem_rpc.call_args_list], ["status", "clear"])
            self.assertTrue(deployment.network_evidence["cleanup_calibration"][0]["returned_to_baseline"])
            self.assertEqual(deployment.netem_hosts, [])

    def test_cleanup_rtt_failure_keeps_owned_queue_cleared(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = RemoteDeployment(self.inventory(directory))
            deployment.netem_hosts = [deployment.hosts[0]]
            deployment.network_evidence["before"] = ring_rtts(2)
            deployment.netem_rpc = Mock(return_value={"phase": "cleared", "physical_qdisc_configuration_unchanged": True})
            deployment.start_echoes = Mock(return_value=[])
            deployment.stop_echoes = Mock()
            deployment.calibrate_ring = Mock(return_value=ring_rtts(40))
            with self.assertRaisesRegex(RuntimeError, "return to baseline"):
                deployment.clear_network()
            self.assertEqual(deployment.netem_hosts, [])
            deployment.stop_echoes.assert_called_once_with([])

    def test_tunnels_close_even_when_network_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = RemoteDeployment(self.inventory(directory))
            deployment.netem_hosts = [deployment.hosts[0]]
            deployment.clear_network = Mock(side_effect=RuntimeError("host unavailable"))
            tunnel, stream = Mock(), Mock()
            tunnel.poll.return_value = None
            deployment.tunnels = [(tunnel, stream)]
            with self.assertRaisesRegex(RuntimeError, "host unavailable"):
                deployment.close()
            tunnel.terminate.assert_called_once()
            stream.close.assert_called_once()

    def test_reused_pid_cannot_be_signalled_from_a_stale_state_file(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "process.json"
            path.write_text(json.dumps({"pid": 1234, "nonce": "owned", "pid_start": "first"}))
            with patch.object(remote_worker, "pid_start", return_value="replacement"):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    remote_worker.owned_state(path, "owned")
            with patch.object(remote_worker, "pid_start", return_value="first"):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    remote_worker.owned_state(path, "another-run")


if __name__ == "__main__":
    unittest.main()
