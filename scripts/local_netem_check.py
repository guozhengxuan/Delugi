#!/usr/bin/env python3
"""Exercise the existing netem helper inside disposable Linux namespaces.

Run as root only inside a task-owned Linux VM. This creates no cloud resources
and changes no VM-host network interface. A private mount/network/PID namespace
contains two connected network namespaces, four temporary echo servers, and the
exact existing netem helper. The PID namespace kills every descendant if the
controller exits. Results are RTT calibration evidence, not protocol benchmarks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import statistics
import subprocess
import sys
import time
import uuid

import remote_worker
import timing_calibration


ROOT = Path(__file__).resolve().parent
PORT, CONTROL_PORT = 19400, 19401
PEERS = [("dla", "10.203.0.1"), ("dlb", "10.203.0.2")]


def namespace_ids():
    return {kind: os.stat("/proc/self/ns/" + kind).st_ino for kind in ("net", "mnt", "pid")}


def assess(phases, delay_ms):
    """Accept measured RTT addition, cleanup restoration and an unshaped control."""
    if set(phases) != {"before", "configured", "after"}:
        raise ValueError("all three calibration phases are required")
    evidence = []
    for sender in range(2):
        for port in (PORT, CONTROL_PORT):
            key = str(sender) + ":" + str(port)
            rows = [phases[phase][key] for phase in ("before", "configured", "after")]
            for row in rows:
                if len(row["samples_ms"]) != 20 or any(not 0 <= x < 10000 for x in row["samples_ms"]):
                    raise ValueError("twenty finite nonnegative RTT samples required")
                if row["median_rtt_ms"] != statistics.median(row["samples_ms"]):
                    raise ValueError("reported RTT median differs from raw samples")
            before, configured, after = [row["median_rtt_ms"] for row in rows]
            evidence.append({"sender": sender, "port": port,
                             "scope": "selected" if port == PORT else "unselected_control",
                             **timing_calibration.addition(before, configured, delay_ms if port == PORT else 0),
                             "returned_to_baseline": timing_calibration.restored(before, after)})
    return {"passed": all(row["addition_matches"] and row["returned_to_baseline"] for row in evidence),
            "checks": evidence,
            "scope": "two-way TCP echo RTT; no independent one-way or protocol-latency claim"}


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def command(argv, request=None):
    result = subprocess.run(argv, input=None if request is None else json.dumps(request),
                            capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {argv!r}: {result.stderr[-2000:]} {result.stdout[-2000:]}")
    return result.stdout


def in_namespace(name, script, request):
    output = command(["ip", "netns", "exec", name, sys.executable, str(ROOT / script)], request)
    value = json.loads(output)
    if script == "linux_netem.py":
        if value.get("ok") is not True or not isinstance(value.get("result"), dict):
            raise RuntimeError("netem helper returned a failed or malformed RPC envelope")
        return value["result"]
    return value


def require_cleared(state, allow_absent=False):
    if allow_absent and state.get("phase") == "absent" and state.get("mutated") is False:
        return
    if (state.get("phase") != "cleared" or not state.get("physical_qdisc_configuration_unchanged")
            or state.get("ifb") is not None or state.get("owned_filters") != []):
        raise RuntimeError("netem cleanup did not confirm absent owned objects and unchanged interface root")


def archive_helper_state(directory, nonce, phase):
    path = Path("/run/delugi-netem") / nonce / "state.json"
    if not path.exists():
        return {"nonce": nonce, "phase": phase, "state_present": False}
    if path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError("symlinked lab helper state")
    with path.open("rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise RuntimeError("lab helper state exceeds 1 MiB")
    name = "netem-state-" + nonce + "-" + phase + ".json"
    (directory / name).write_bytes(raw)
    return {"nonce": nonce, "phase": phase, "state_present": True, "path": name,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def private_lab(directory, delay_ms):
    ownership = json.loads((directory / "ownership.json").read_text())
    current = namespace_ids()
    if os.getpid() != 1 or any(current[kind] == ownership["outer_namespaces"][kind] for kind in current):
        raise RuntimeError("refusing to run without private mount/network/PID namespaces")
    report = {"schema": 1, "status": "failed", "nonce": ownership["nonce"],
              "private_namespaces": current, "delay_ms": delay_ms, "phases": {},
              "helper": {}, "helper_state_archives": [],
              "cleanup": {"processes": [], "netem": [], "namespaces": []}}
    servers, handles, names, configured, issued = [], [], [], [], []
    try:
        # Hide both host registries in our private mount tree. Final helper
        # state is copied to the evidence directory before this tree vanishes.
        for target in ("/run/netns", "/run/delugi-netem"):
            if Path(target).is_symlink():
                raise RuntimeError("refusing symlinked private mount target")
            Path(target).mkdir(exist_ok=True)
            command(["mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", target])
        for name, _ in PEERS:
            command(["ip", "netns", "add", name]); names.append(name)
        command(["ip", "link", "add", "dva", "type", "veth", "peer", "name", "dvb"])
        for index, (name, address) in enumerate(PEERS):
            device = ("dva", "dvb")[index]
            command(["ip", "link", "set", device, "netns", name])
            command(["ip", "-n", name, "address", "add", address + "/30", "dev", device])
            command(["ip", "-n", name, "link", "set", device, "up"])
            command(["ip", "-n", name, "link", "set", "lo", "up"])
            for port in (PORT, CONTROL_PORT):
                request = {"action": "echo", "nonce": ownership["nonce"],
                           "state": str(directory / f"echo-{index}-{port}.json"),
                           "bind_ip": address, "port": port, "lifetime_seconds": 120}
                stderr = (directory / f"echo-{index}-{port}.stderr").open("w")
                handles.append(stderr)
                child = subprocess.Popen(["ip", "netns", "exec", name, sys.executable,
                                          str(ROOT / "remote_worker.py")], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=stderr, text=True, start_new_session=True)
                servers.append(child)
                child.stdin.write(json.dumps(request)); child.stdin.close()
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    if not selector.select(10) or json.loads(child.stdout.readline()) != {"ready": True}:
                        raise RuntimeError("owned echo did not become ready")

        def probe(phase):
            report["phases"][phase] = {}
            for sender, (name, _) in enumerate(PEERS):
                for port in (PORT, CONTROL_PORT):
                    report["phases"][phase][str(sender) + ":" + str(port)] = in_namespace(
                        name, "remote_worker.py", {"action": "probe", "ip": PEERS[1 - sender][1],
                                                   "port": port, "count": 20})

        probe("before")
        for index, (name, _) in enumerate(PEERS):
            nonce = uuid.uuid4().hex
            configured.append((name, nonce))
            issued.append(nonce)
            report["helper"][name] = in_namespace(name, "linux_netem.py", {
                "action": "configure", "nonce": nonce, "interface": ("dva", "dvb")[index],
                "peers": [{"ip": PEERS[1 - index][1], "port": PORT}], "local_ports": [PORT],
                "delay_ms": delay_ms, "loss_percent": 0})
            state = report["helper"][name]
            if (state.get("phase") != "active" or not state.get("active_objects_complete")
                    or not state.get("physical_qdisc_configuration_unchanged")):
                raise RuntimeError("scoped netem objects or unchanged interface root were not verified")
            report["helper_state_archives"].append(archive_helper_state(directory, nonce, "configured"))
        probe("configured")
        for name, nonce in configured:
            cleared = in_namespace(name, "linux_netem.py", {"action": "clear", "nonce": nonce})
            report["cleanup"]["netem"].append(cleared)
            require_cleared(cleared)
            report["helper_state_archives"].append(archive_helper_state(directory, nonce, "cleared"))
        configured.clear()
        probe("after")
        report["assessment"] = assess(report["phases"], delay_ms)
        report["status"] = "passed" if report["assessment"]["passed"] else "failed"
    except Exception as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    finally:
        errors = []
        for name, nonce in configured:
            try:
                cleared = in_namespace(name, "linux_netem.py", {"action": "clear", "nonce": nonce})
                report["cleanup"]["netem"].append(cleared)
                require_cleared(cleared, allow_absent=True)
            except Exception as error:
                errors.append("netem: " + str(error))
        for nonce in issued:
            try:
                report["helper_state_archives"].append(archive_helper_state(directory, nonce, "final"))
            except Exception as error:
                errors.append("helper state evidence: " + str(error))
        for child in servers:
            try:
                report["cleanup"]["processes"].append(remote_worker.finish_owned_group(child, 2, 2))
                child.wait(timeout=2)
            except Exception as error:
                errors.append("echo: " + str(error))
            finally:
                for stream in (child.stdin, child.stdout):
                    if stream is not None:
                        stream.close()
        for handle in handles:
            handle.close()
        for name in reversed(names):
            try:
                command(["ip", "netns", "delete", name])
                report["cleanup"]["namespaces"].append({"name": name, "deleted": True})
            except Exception as error:
                errors.append("namespace: " + str(error))
        try:
            remaining = json.loads(command(["ip", "-j", "netns", "list"]))
            report["cleanup"]["namespaces_remaining"] = remaining
            if remaining:
                errors.append("private named namespaces remain")
        except Exception as error:
            errors.append("namespace inventory: " + str(error))
        if errors:
            report["cleanup"]["errors"] = errors; report["status"] = "failed"
        report["kernel"] = os.uname().release
        report["sources"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                             for name in ("local_netem_check.py", "linux_netem.py", "remote_worker.py")}
        write(directory / "result.json", report)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--delay-ms", type=float, default=10)
    parser.add_argument("--private-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires Linux root inside a task-owned local VM")
    if not 1 <= args.delay_ms <= 100:
        parser.error("delay must be between 1 and 100 ms")
    directory = args.output.absolute()
    if args.private_child:
        return private_lab(directory, args.delay_ms)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    write(directory / "ownership.json", {"nonce": uuid.uuid4().hex, "outer_namespaces": namespace_ids(),
                                        "created_unix": time.time(), "purpose": "isolated local RTT calibration"})
    with (directory / "controller.log").open("w") as log:
        process = subprocess.run(["unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc",
                                  "--kill-child=SIGKILL", sys.executable, str(Path(__file__).resolve()),
                                  "--private-child", "--output", str(directory),
                                  "--delay-ms", str(args.delay_ms)], stdout=log, stderr=subprocess.STDOUT,
                                 timeout=240)
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
