#!/usr/bin/env python3
"""Administrator-started, bounded helper for selected loopback TCP ports only.

Never reloads /etc/pf.conf, flushes the main ruleset, changes sysctls, or modifies
other anchors/pipes. It owns one random com.apple anchor, two unused pipes and
one PF enable-reference token. Cleanup releases only these resources. A separate
unprivileged echo calibration must pass before measurements are accepted.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import time

PFCTL = "/sbin/pfctl"
DNCTL = "/usr/sbin/dnctl"
MAX_REQUEST = 32768


def pipe_ids(listing):
    return {int(value) for value in re.findall(r"^\s*(\d+)\s*:", listing, re.MULTILINE)}


def validate_request(protocol, ports, delay_ms):
    if protocol not in {"calibration", "delugi", "raptr", "mysticeti"}:
        raise ValueError("unknown protocol")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 128:
        raise ValueError("expected 1..128 replica TCP ports")
    if any(type(port) is not int or not 1024 <= port <= 65535 for port in ports):
        raise ValueError("ports must be integers in1024..65535")
    if type(delay_ms) is not int or not 1 <= delay_ms <= 100:
        raise ValueError("delay must be an integer in1..100ms")
    return sorted(set(ports))


def rules_for(ports, pipes):
    port_set = "{ " + ", ".join(str(port) for port in ports) + " }"
    # Both directions traverse outbound lo0 once. Quick prevents double matching
    # when both endpoint ports are selected. Distinct pipes avoid shared bandwidth.
    return (f"dummynet out quick on lo0 inet proto tcp from 127.0.0.1 port {port_set} to 127.0.0.1 pipe {pipes[0]}\n"
            f"dummynet out quick on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.1 port {port_set} pipe {pipes[1]}\n")


class Shaper:
    def __init__(self, directory):
        self.directory = directory
        self.anchor = "com.apple/delugi-" + secrets.token_hex(6)
        self.pipes = []
        self.reference = None
        self.active = None
        self.created_pipes = set()
        self.anchor_loaded = False
        self.started = time.time()
        self.helper_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    def run(self, argv, text=None, check=True):
        process = subprocess.run(argv, input=text, text=True, capture_output=True, timeout=10)
        entry = {"time": time.time(), "argv": argv, "stdin": text,
                 "returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        with (self.directory / "commands.jsonl").open("a") as stream:
            stream.write(json.dumps(entry) + "\n")
        if check and process.returncode:
            raise RuntimeError(f"{Path(argv[0]).name} failed: {process.stderr.strip()}")
        return process.stdout + process.stderr

    def initialize(self):
        # Preserve read-only snapshots before any mutation. Enabling PF may make
        # existing system rules active; no global rules are loaded or replaced.
        self.run([PFCTL, "-s", "all"])
        existing = self.run([DNCTL, "list"])
        if existing.strip():
            raise RuntimeError("Existing dummynet configuration detected; use an isolated Linux host or remove only known benchmark residue")
        used = pipe_ids(existing)
        candidates = [number for number in range(60000, 61000) if number not in used]
        if len(candidates) < 2:
            raise RuntimeError("no unused benchmark pipe IDs")
        self.pipes = candidates[:2]
        enabled = self.run([PFCTL, "-E"])
        match = re.search(r"Token\s*:\s*(\d+)", enabled, re.IGNORECASE)
        if not match:
            raise RuntimeError("PF did not return an enable-reference token")
        self.reference = match[1]

    def clear(self):
        evidence = {"active": self.active, "pipes": {}}
        errors = []
        # Darwin's multi-pipe listing can omit a live pipe. Ownership comes from
        # our configuration attempts, never from an enumeration of current state.
        for pipe in sorted(self.created_pipes):
            try:
                evidence["pipes"][str(pipe)] = self.run([DNCTL, "pipe", str(pipe), "show"], check=False)
            except Exception as error:
                errors.append(str(error))
        if self.anchor_loaded:
            try:
                self.run([PFCTL, "-a", self.anchor, "-f", "-"], text="")
                self.anchor_loaded = False
            except Exception as error:
                errors.append(str(error))
        # A surviving rule pointing at a deleted pipe can drop traffic. Keep the
        # delay pipes alive until their rules are confirmed removed.
        if not self.anchor_loaded:
            for pipe in sorted(self.created_pipes):
                try:
                    self.run([DNCTL, "pipe", "delete", str(pipe)])
                    self.created_pipes.remove(pipe)
                except Exception as error:
                    errors.append(str(error))
        if not self.created_pipes and not self.anchor_loaded:
            self.active = None
        if errors:
            raise RuntimeError("Cleanup failed: " + "; ".join(errors))
        return evidence

    def configure(self, protocol, ports, delay_ms):
        ports = validate_request(protocol, ports, delay_ms)
        if self.active or self.created_pipes or self.anchor_loaded:
            raise RuntimeError("another trial still owns the shaper; clear it first")
        if self.run([DNCTL, "list"]).strip():
            raise RuntimeError("Dummynet pipes were claimed by another process; refusing to overwrite")
        rules = rules_for(ports, self.pipes)
        self.run([PFCTL, "-a", self.anchor, "-n", "-f", "-"], text=rules)
        self.active = {"protocol": protocol, "replica_ports": ports, "one_way_delay_ms": delay_ms,
                       "backend": "macOS_dummynet", "interface": "lo0", "direction": "out_only",
                       "anchor": self.anchor, "pipes": self.pipes, "rules": rules,
                       "helper_sha256": self.helper_sha256, "configured_unix_ns": time.time_ns(),
                       "scope": "selected loopback IPv4 TCP ports, both byte directions and kernel TCP ACKs; no bandwidth cap"}
        try:
            for pipe in self.pipes:
                # Track before attempting: a timed-out command may still mutate.
                self.created_pipes.add(pipe)
                self.run([DNCTL, "pipe", str(pipe), "config", "bw", "0", "delay", f"{delay_ms}ms", "queue", "100", "mask", "all"])
            self.anchor_loaded = True
            self.run([PFCTL, "-a", self.anchor, "-f", "-"], text=rules)
        except Exception as error:
            try:
                self.clear()
            except Exception as cleanup_error:
                raise RuntimeError(f"Configuration failed: {error}; {cleanup_error}") from error
            raise
        return self.active

    def shutdown(self):
        errors = []
        for _ in range(3):
            try:
                self.clear()
                errors = []
                break
            except Exception as error:
                errors = [str(error)]
        if self.reference:
            try:
                self.run([PFCTL, "-X", self.reference])
                self.reference = None
            except Exception as error:
                errors.append(str(error))
        return errors


def serve(directory, lifetime, recover_owned_pipe=None):
    if os.geteuid() != 0:
        raise RuntimeError("Administrator authentication is required; run the prepared sudo command")
    directory = directory.resolve()
    owner = directory.stat().st_uid
    if directory.stat().st_mode & 0o077:
        raise RuntimeError("control directory must be private (mode0700)")
    token = (directory / "token").read_text().strip()
    if not re.fullmatch(r"[a-f0-9]{64}", token):
        raise RuntimeError("invalid capability token")
    control = directory / "control.sock"
    if control.exists():
        raise RuntimeError("control socket already exists")
    shaper = Shaper(directory)
    stopping = False
    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    status = {"status": "starting", "pid": os.getpid(), "anchor": shaper.anchor}
    try:
        if recover_owned_pipe is not None:
            shaper.run([DNCTL, "pipe", "delete", str(recover_owned_pipe)])
        shaper.initialize()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(control))
            control.chmod(0o600)
            os.chown(control, owner, -1)
            server.listen(4)
            server.settimeout(1)
            status["status"] = "ready"
            (directory / "status.json").write_text(json.dumps(status, indent=2) + "\n")
            print("Ready. Only explicitly selected benchmark loopback ports will be delayed. Ctrl-C cleans up.", flush=True)
            deadline = time.monotonic() + lifetime
            while not stopping and time.monotonic() < deadline:
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(5)
                    try:
                        with connection.makefile("rb") as stream:
                            body = stream.readline(MAX_REQUEST)
                        if len(body) >= MAX_REQUEST:
                            raise ValueError("request too large")
                        data = json.loads(body)
                        if not hmac.compare_digest(str(data.get("token", "")), token):
                            raise ValueError("invalid capability")
                        command = data.get("command")
                        if command == "configure":
                            result = shaper.configure(data.get("protocol"), data.get("ports"), data.get("delay_ms"))
                        elif command == "clear":
                            result = shaper.clear()
                        elif command == "status":
                            result = {**status, "active": shaper.active}
                        elif command == "stop":
                            stopping, result = True, {"stopping": True}
                        else:
                            raise ValueError("unknown command")
                        reply = {"ok": True, "result": result}
                    except Exception as error:
                        reply = {"ok": False, "error": str(error)}
                    connection.sendall(json.dumps(reply).encode() + b"\n")
    finally:
        errors = shaper.shutdown()
        control.unlink(missing_ok=True)
        status.update(status="stopped" if not errors else "cleanup_failed", cleanup_errors=errors,
                      remaining_pipes=sorted(shaper.created_pipes), anchor_loaded=shaper.anchor_loaded,
                      remaining_reference=shaper.reference)
        (directory / "status.json").write_text(json.dumps(status, indent=2) + "\n")
        print(json.dumps(status), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--lifetime", type=int, default=3600)
    parser.add_argument("--recover-owned-pipe", type=int,
                        help="Delete one explicitly identified residue from this benchmark's prior helper")
    args = parser.parse_args()
    if not 60 <= args.lifetime <= 7200:
        parser.error("lifetime must be60..7200seconds")
    if args.recover_owned_pipe is not None and not 60000 <= args.recover_owned_pipe < 61000:
        parser.error("recovery is restricted to the benchmark pipe range60000..60999")
    serve(args.directory, args.lifetime, args.recover_owned_pipe)
