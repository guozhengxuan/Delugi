#!/usr/bin/env python3
"""Small Linux supervisor for one owned benchmark process or calibration echo.

Uploaded with the run, invoked over authenticated SSH. No host-wide process or
filesystem operations. Signals require both an ownership nonce and Linux PID
start-time match. Resource limits apply before the native process is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import socket
import statistics
import subprocess
import sys
import time


def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pid_start(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]


def owned_state(path, nonce):
    state = json.loads(Path(path).read_text())
    if state["nonce"] != nonce or pid_start(state["pid"]) != state["pid_start"]:
        raise RuntimeError("owned process identity changed; refusing signal")
    return state


def host_swap_bytes(path="/proc/meminfo"):
    """Linux configured swap capacity; unavailable is never reported as zero."""
    try:
        with open(path) as source:
            for line in source:
                fields = line.split()
                if fields and fields[0] == "SwapTotal:":
                    if len(fields) != 3 or fields[2] != "kB" or not fields[1].isdigit():
                        raise ValueError("malformed observed host swap capacity")
                    return int(fields[1]) * 1024
    except OSError:
        pass
    return None


def validate_resource_budget(spec, available_cpus, physical_memory, physical_swap=None):
    """Describe a limit only when affinity, cgroups, or the host enforces it."""
    cpus, memory = spec.get("cpus"), spec.get("memory_bytes")
    if (not isinstance(cpus, list) or not cpus
            or any(type(cpu) is not int or cpu < 0 for cpu in cpus)
            or len(set(cpus)) != len(cpus) or not set(cpus) <= set(available_cpus)):
        raise ValueError("declared CPU placement is invalid or unavailable")
    if type(memory) is not int or memory <= 0 or physical_memory <= 0:
        raise ValueError("positive integer memory envelope and observed host RAM required")
    swap = spec.get("swap_bytes")
    if swap is not None and (type(swap) is not int or swap < 0):
        raise ValueError("declared swap budget must be nonnegative integer bytes")
    if physical_swap is not None and (type(physical_swap) is not int or physical_swap < 0):
        raise ValueError("observed host swap capacity must be nonnegative integer bytes")
    swap_effective = {"host_swap_bytes": physical_swap, "swap_limit_bytes": None,
                      "swap_enforcement": "unavailable_or_undeclared", "swap_policy_verified": False}
    mode = spec.get("enforcement")
    if mode == "dedicated_host":
        if spec.get("cgroup_parent") is not None:
            raise ValueError("dedicated-host and delegated-cgroup enforcement cannot be mixed")
        if memory < physical_memory:
            raise ValueError("a memory cap below host RAM requires delegated-cgroup enforcement")
        if swap is not None:
            if physical_swap is None:
                raise ValueError("declared dedicated-host swap budget requires observed host swap capacity")
            if physical_swap > swap:
                raise ValueError("observed host swap exceeds the declared swap budget")
            swap_effective.update(swap_limit_bytes=physical_swap, swap_enforcement="observed_host_swap", swap_policy_verified=True)
        elif physical_swap is not None:
            swap_effective.update(swap_limit_bytes=physical_swap, swap_enforcement="observed_host_swap_undeclared")
        return {"memory_enforcement": "physical_host", "memory_limit_bytes": physical_memory,
                "cpus": cpus, "cpu_enforcement": "inherited_process_affinity", **swap_effective}
    if mode == "cgroup":
        if not spec.get("cgroup_parent") or memory > physical_memory:
            raise ValueError("cgroup requires a delegated parent and memory no greater than host RAM")
        if swap is not None:
            swap_effective.update(swap_limit_bytes=swap, swap_enforcement="cgroup_memory_swap_max", swap_policy_verified=True)
        return {"memory_enforcement": "cgroup_memory_max", "memory_limit_bytes": memory,
                "cpus": cpus, "cpu_enforcement": "cgroup_quota_and_inherited_process_affinity", **swap_effective}
    raise ValueError("choose dedicated_host or cgroup resource enforcement")


def make_cgroup(spec, nonce):
    parent = spec.get("cgroup_parent")
    if parent is None:
        if spec.get("enforcement") != "dedicated_host":
            raise ValueError("choose delegated cgroup or explicit dedicated-host resource envelope")
        return None
    parent = Path(parent).resolve()
    if not str(parent).startswith("/sys/fs/cgroup/") or not (parent / "cgroup.procs").exists():
        raise ValueError("invalid delegated cgroup parent")
    group = parent / ("delugi-" + nonce)
    group.mkdir(mode=0o700)
    try:
        (group / "memory.max").write_text(str(spec["memory_bytes"]))
        if spec.get("swap_bytes") is not None:
            swap_limit = group / "memory.swap.max"
            if not swap_limit.exists():
                raise ValueError("declared swap budget requires the cgroup memory.swap.max controller")
            swap_limit.write_text(str(spec["swap_bytes"]))
            if swap_limit.read_text().strip() != str(spec["swap_bytes"]):
                raise ValueError("cgroup swap limit differs after configuration")
        (group / "cpu.max").write_text(f"{len(spec['cpus']) * 100000} 100000")
        if (group / "cpuset.cpus").exists():
            (group / "cpuset.cpus").write_text(",".join(map(str, spec["cpus"])))
        return group
    except BaseException:
        group.rmdir()
        raise


def finish_owned_group(child, term_seconds=5, kill_seconds=5):
    """Drain the new session created by this Popen, even after its leader exits.

    This is deliberately an in-process launch handle, not a PID read from a stale
    file. A process group retains its identifier while any member exists. Once
    absence is observed we never signal that identifier again.
    """
    def present():
        child.poll()  # Reap our leader so its zombie cannot keep the group alive.
        try:
            os.killpg(child.pid, 0)
            return True
        except ProcessLookupError:
            return False

    def send(signum):
        try:
            os.killpg(child.pid, signum)
            return True
        except ProcessLookupError:
            return False

    def await_empty(seconds):
        end = time.monotonic() + seconds
        while present():
            if time.monotonic() >= end:
                return False
            time.sleep(.02)
        return True

    report = {"group_empty": False, "remaining_group_after_leader": present(), "signals": []}
    if not report["remaining_group_after_leader"]:
        report["group_empty"] = True
        return report
    # A stopped native child cannot handle TERM until CONT releases it.
    for signum in (signal.SIGCONT, signal.SIGTERM):
        if not send(signum):
            report["group_empty"] = True
            return report
        report["signals"].append(signal.Signals(signum).name)
    if not await_empty(term_seconds):
        if send(signal.SIGKILL):
            report["signals"].append("SIGKILL")
        if not await_empty(kill_seconds):
            raise RuntimeError("owned process group remains after bounded cleanup")
    report["group_empty"] = True
    return report


def process_run(request):
    binary = Path(request["binary"]).resolve()
    if sha(binary) != request["binary_sha256"]:
        raise RuntimeError("remote native binary does not match declared artifact")
    state_path = Path(request["state"])
    if state_path.exists():
        raise RuntimeError("owned process state already exists")
    budget, nonce = request["budget"], request["nonce"]
    available = os.sched_getaffinity(0)
    physical_memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    effective_budget = validate_resource_budget(budget, available, physical_memory, host_swap_bytes())
    cgroup = make_cgroup(budget, nonce)
    child = None
    group_finished = False
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    def configure_child():
        os.sched_setaffinity(0, set(budget["cpus"]))
        if cgroup is not None:
            (cgroup / "cgroup.procs").write_text(str(os.getpid()))
    try:
        child = subprocess.Popen([str(binary), *request["arguments"]], cwd=request["directory"],
                                 start_new_session=True, preexec_fn=configure_child)
        state = {"nonce": nonce, "pid": child.pid, "pid_start": pid_start(child.pid),
                 "binary": str(binary), "binary_sha256": request["binary_sha256"], "cgroup": str(cgroup) if cgroup else None}
        descriptor = os.open(state_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(state, stream)
        def forward(signum, _frame):
            if child.poll() is None:
                os.killpg(child.pid, signum)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, forward)
        timed_out = False
        try:
            child.wait(timeout=request["max_runtime_seconds"])
        except subprocess.TimeoutExpired:
            timed_out = True
        cleanup = finish_owned_group(child)
        group_finished = True
        native_code = child.wait()
        effective_budget["host_swap_bytes_at_end"] = host_swap_bytes()
        if (budget.get("enforcement") == "dedicated_host" and effective_budget.get("swap_policy_verified") is True
                and effective_budget["host_swap_bytes_at_end"] != effective_budget["host_swap_bytes"]):
            raise RuntimeError("host swap capacity changed during the declared resource interval")
        # A timeout or orphaned descendant cannot become a successful run merely
        # because the session leader exits zero while cleanup is being performed.
        code = 124 if timed_out else (125 if native_code == 0 and cleanup["remaining_group_after_leader"] else native_code)
        counters = {}
        if cgroup is not None:
            for name in ("cpu.stat", "memory.peak", "memory.events", "io.stat"):
                if (cgroup / name).exists():
                    counters[name] = (cgroup / name).read_text()
        usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
        print(json.dumps({"event": "deployment_resource_summary", "nonce": nonce, "pid": child.pid,
                          "budget": budget, "effective_budget": effective_budget,
                          "child_cpu_seconds": {
                              "user": usage_after.ru_utime - usage_before.ru_utime,
                              "system": usage_after.ru_stime - usage_before.ru_stime},
                          "child_peak_rss_bytes": usage_after.ru_maxrss * 1024,
                          "counters": counters, "native_exit_code": native_code,
                          "exit_code": code, "timed_out": timed_out, "owned_group_cleanup": cleanup}), flush=True)
        state["exit_code"] = code
        state["native_exit_code"] = native_code
        state["timed_out"] = timed_out
        state["owned_group_cleanup"] = cleanup
        state_path.write_text(json.dumps(state))
        return code
    finally:
        if child is not None and not group_finished:
            finish_owned_group(child)
            child.wait()
        if cgroup is not None:
            cgroup.rmdir()


def echo(request):
    # The owning SSH process lifetime bounds this temporary calibration service.
    if os.getpgrp() != os.getpid():
        os.setsid()
    state = {"nonce": request["nonce"], "pid": os.getpid(), "pid_start": pid_start(os.getpid())}
    descriptor = os.open(request["state"], os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(state, stream)
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((request["bind_ip"], request["port"]))
    server.listen()
    server.settimeout(1)
    end = time.monotonic() + request.get("lifetime_seconds", 120)
    print(json.dumps({"ready": True}), flush=True)
    while time.monotonic() < end:
        try:
            connection, _ = server.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(5)
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                connection.sendall(data)
    server.close()


def probe(request):
    samples = []
    with socket.create_connection((request["ip"], request["port"]), timeout=10) as connection:
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(request.get("count", 20) + 3):
            payload = i.to_bytes(8, "little") + b"c" * 56
            start = time.perf_counter_ns()
            connection.sendall(payload)
            returned = b""
            while len(returned) < len(payload):
                part = connection.recv(len(payload) - len(returned))
                if not part:
                    raise RuntimeError("calibration echo closed")
                returned += part
            elapsed = (time.perf_counter_ns() - start) / 1e6
            if returned != payload:
                raise RuntimeError("calibration payload differs")
            if i >= 3:
                samples.append(elapsed)
    return {"samples_ms": samples, "median_rtt_ms": statistics.median(samples)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, help="read request file; default stdin JSON")
    args = parser.parse_args()
    request = json.loads(args.request.read_text() if args.request else sys.stdin.read())
    action = request["action"]
    if action == "run":
        return process_run(request)
    if action == "signal":
        prior = json.loads(Path(request["state"]).read_text())
        if prior["nonce"] != request["nonce"]:
            raise RuntimeError("owned process nonce differs")
        if "exit_code" in prior:
            print(json.dumps({"already_finished": True, "exit_code": prior["exit_code"]}), flush=True)
            return 0
        state = owned_state(request["state"], request["nonce"])
        signum = getattr(signal, request["signal"])
        if signum not in (signal.SIGSTOP, signal.SIGCONT, signal.SIGTERM, signal.SIGKILL):
            raise ValueError("unsupported owned-process signal")
        os.killpg(state["pid"], signum)
        response = {"signalled_owned_pid": state["pid"], "signal": request["signal"]}
    elif action == "probe":
        response = probe(request)
    elif action == "echo":
        echo(request)
        return 0
    elif action == "inspect":
        response = {"system": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
                    "allowed_cpus": sorted(os.sched_getaffinity(0)),
                    "memory_bytes": os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"),
                    "host_swap_bytes": host_swap_bytes(),
                    "binary_sha256": sha(request["binary"])}
        stamp = Path(request["binary"] + ".build.json")
        if stamp.exists():
            response["build_stamp_sha256"] = sha(stamp)
            response["build_stamp"] = json.loads(stamp.read_text())
    else:
        raise ValueError("unknown remote worker action")
    print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
