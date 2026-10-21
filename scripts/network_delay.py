#!/usr/bin/env python3
"""Unprivileged client for the scoped localhost dummynet helper."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import statistics
import threading
import time
import timing_calibration

ROOT = Path(__file__).resolve().parents[1]
MAX_REQUEST = 32768


def request(command, **fields):
    control = os.environ.get("DELUGI_SHAPER_CONTROL")
    token_file = os.environ.get("DELUGI_SHAPER_TOKEN_FILE")
    if not control or not token_file:
        raise RuntimeError("Both DELUGI_SHAPER_CONTROL and DELUGI_SHAPER_TOKEN_FILE are required")
    body = json.dumps({"command": command, "token": Path(token_file).read_text().strip(), **fields}).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect(control)
        client.sendall(body)
        with client.makefile("rb") as stream:
            data = stream.readline(MAX_REQUEST)
    reply = json.loads(data)
    if not reply.get("ok"):
        raise RuntimeError(reply.get("error", "network shaper rejected request"))
    return reply["result"]


def configure_from_environment(protocol, replica_ports):
    enabled = os.environ.get("DELUGI_SHAPER_CONTROL")
    delay = os.environ.get("DELUGI_NETWORK_DELAY_MS")
    if not enabled and not delay:
        return None
    if not enabled or not delay:
        raise RuntimeError("Requested network delay needs both helper control and delay settings")
    milliseconds = int(delay)
    result = request("configure", protocol=protocol, ports=list(replica_ports), delay_ms=milliseconds)
    result["client_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return result


def clear_from_environment():
    return request("clear") if os.environ.get("DELUGI_SHAPER_CONTROL") else None


def prepare(directory):
    directory = Path(directory).resolve()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    token = directory / "token"
    token.write_text(secrets.token_hex(32) + "\n")
    token.chmod(0o600)
    environment = {"DELUGI_SHAPER_CONTROL": str(directory / "control.sock"),
                   "DELUGI_SHAPER_TOKEN_FILE": str(token), "DELUGI_NETWORK_DELAY_MS": "10"}
    (directory / "environment.json").write_text(json.dumps(environment, indent=2) + "\n")
    helper = directory / "dummynet_helper.py"
    shutil.copy2(ROOT / "scripts/dummynet_helper.py", helper)
    command = ["sudo", "/usr/bin/python3", str(helper),
               "--directory", str(directory), "--lifetime", "7200"]
    (directory / "start-command.txt").write_text(shlex.join(command) + "\n")
    print(shlex.join(command))
    return environment


def calibration(directory, delay_ms=10):
    """Verify both directions on an established connection and an unshaped control."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    listeners, clients, threads = [], [], []
    def echo(server):
        with server.accept()[0] as connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while data := connection.recv(65536):
                connection.sendall(data)
    def sample(client, count):
        values = []
        for index in range(count):
            payload = index.to_bytes(4, "little") + b"d" * 60
            start = time.perf_counter_ns()
            client.sendall(payload)
            data = b""
            while len(data) < len(payload):
                piece = client.recv(len(payload) - len(data))
                if not piece:
                    raise RuntimeError("calibration connection closed")
                data += piece
            if data != payload:
                raise RuntimeError("calibration payload changed")
            values.append((time.perf_counter_ns() - start) / 1e6)
        return values
    result = {"status": "failed", "requested_one_way_delay_ms": delay_ms}
    try:
        if int(os.environ.get("DELUGI_NETWORK_DELAY_MS", "0")) != delay_ms:
            raise RuntimeError("Calibration delay and requested environment delay differ")
        clear_from_environment()
        for _ in range(2):
            server = socket.socket()
            server.bind(("127.0.0.1", 0))
            server.listen()
            listeners.append(server)
            thread = threading.Thread(target=echo, args=(server,), daemon=True)
            thread.start()
            threads.append(thread)
            client = socket.create_connection(server.getsockname(), timeout=5)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            clients.append(client)
        result["baseline_rtt_ms"] = sample(clients[0], 20)
        result["control_baseline_rtt_ms"] = sample(clients[1], 20)
        result["shaping"] = configure_from_environment("calibration", [listeners[0].getsockname()[1]])
        if result["shaping"] is None:
            raise RuntimeError("Calibration requires a configured kernel shaper")
        result["shaped_rtt_ms"] = sample(clients[0], 30)
        result["control_rtt_ms"] = sample(clients[1], 20)
        added = statistics.median(result["shaped_rtt_ms"]) - statistics.median(result["baseline_rtt_ms"])
        result["median_added_rtt_ms"] = added
        if not timing_calibration.addition(statistics.median(result["baseline_rtt_ms"]),
                                          statistics.median(result["shaped_rtt_ms"]), delay_ms)["addition_matches"]:
            raise RuntimeError(f"Expected about {2*delay_ms}ms added RTT; observed {added:.3f}ms")
        if not timing_calibration.addition(statistics.median(result["control_baseline_rtt_ms"]),
                                          statistics.median(result["control_rtt_ms"]), 0)["addition_matches"]:
            raise RuntimeError("Unselected control socket was delayed")
        result["status"] = "passed"
    except Exception as error:
        result["error"] = str(error)
    finally:
        try:
            result["cleanup"] = clear_from_environment()
            if result["status"] == "passed":
                result["after_cleanup_rtt_ms"] = sample(clients[0], 20)
                result["control_after_cleanup_rtt_ms"] = sample(clients[1], 20)
                result["assessment"] = timing_calibration.local_record(result, delay_ms)
                if not result["assessment"]["passed"]:
                    raise RuntimeError("RTT did not return to baseline after owned shaping cleanup")
        except Exception as error:
            result["status"], result["cleanup_error"] = "failed", str(error)
        for client in clients:
            client.close()
        for server in listeners:
            server.close()
        for thread in threads:
            thread.join(timeout=2)
        (directory / "calibration.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "calibrate", "status", "stop"])
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.directory)
    elif args.action == "calibrate":
        outcome = calibration(args.directory)
        print(json.dumps(outcome, indent=2))
        raise SystemExit(0 if outcome["status"] == "passed" else 1)
    else:
        print(json.dumps(request(args.action), indent=2))
