#!/usr/bin/env python3
"""Real independent replicas behind an unprivileged pipelined TCP delay proxy.

This is an application byte-stream delay diagnostic, not a kernel network
preset. Each received chunk becomes eligible for forwarding after delay_ms;
reading continues while older chunks wait. Signed frames and signed ACKs pass
unchanged. Control connections bypass the proxies.
"""
import argparse
import asyncio
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import run_network
import run_sustained

ROOT = run_network.ROOT
CHUNK_BYTES = 65536
QUEUE_CHUNKS = 512


def address_tuple(address):
    host, port = address.rsplit(":", 1)
    if host != "127.0.0.1" or not 1 <= int(port) <= 65535:
        raise ValueError("proxy targets must be loopback TCP addresses")
    return host, int(port)


async def delayed_stream(reader, writer, delay_seconds, counters):
    """Separate read and write tasks: delay never gates the next incoming read."""
    queue = asyncio.Queue(maxsize=QUEUE_CHUNKS)
    loop = asyncio.get_running_loop()

    async def read():
        while True:
            data = await reader.read(CHUNK_BYTES)
            if not data:
                await queue.put(None)
                return
            received = loop.time()
            counters["read_bytes"] += len(data)
            counters["read_chunks"] += 1
            if queue.full():
                counters["queue_capacity_waits"] += 1
            await queue.put((received, data))
            counters["peak_queued_chunks"] = max(counters["peak_queued_chunks"], queue.qsize())

    async def write():
        while True:
            item = await queue.get()
            if item is None:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return
            received, data = item
            await asyncio.sleep(max(0, received + delay_seconds - loop.time()))
            forwarded = loop.time()
            writer.write(data)
            await writer.drain()
            elapsed_us = (forwarded - received) * 1_000_000
            counters["forwarded_bytes"] += len(data)
            counters["forwarded_chunks"] += 1
            counters["forward_delay_sum_us"] += elapsed_us
            counters["forward_delay_min_us"] = min(counters["forward_delay_min_us"], elapsed_us)
            counters["forward_delay_max_us"] = max(counters["forward_delay_max_us"], elapsed_us)

    tasks = [asyncio.create_task(read()), asyncio.create_task(write())]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def stream_counters():
    return {"read_bytes": 0, "read_chunks": 0, "forwarded_bytes": 0,
            "forwarded_chunks": 0, "peak_queued_chunks": 0, "queue_capacity_waits": 0,
            "forward_delay_sum_us": 0.0, "forward_delay_min_us": float("inf"),
            "forward_delay_max_us": 0.0}


class DelayProxy:
    """One event-loop thread owns all proxy sockets and connection tasks."""
    def __init__(self, targets, delay_ms):
        self.targets = [address_tuple(target) for target in targets]
        if not 0 <= delay_ms <= 1000:
            raise ValueError("delay_ms must be between zero and 1000")
        self.delay_ms = delay_ms
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="delugi-tcp-delay")
        self.servers, self.connections, self.records = [], set(), []
        self.addresses = []
        self.closed = False

    def start(self):
        self.thread.start()
        try:
            asyncio.run_coroutine_threadsafe(self._start(), self.loop).result(10)
        except BaseException:
            self.close()
            raise
        return self

    async def _start(self):
        for replica, target in enumerate(self.targets):
            async def accept(reader, writer, replica=replica, target=target):
                await self._connection(replica, target, reader, writer)
            server = await asyncio.start_server(accept, "127.0.0.1", 0)
            self.servers.append(server)
            self.addresses.append("127.0.0.1:" + str(server.sockets[0].getsockname()[1]))

    async def _connection(self, replica, target, reader, writer):
        task = asyncio.current_task()
        self.connections.add(task)
        record = {"destination_replica": replica, "closed": False,
                  "client_to_replica": stream_counters(), "replica_to_client": stream_counters()}
        self.records.append(record)
        backend, pumps = None, []
        try:
            deadline = self.loop.time() + 5
            while True:
                try:
                    incoming, backend = await asyncio.open_connection(*target)
                    break
                except ConnectionRefusedError:
                    if self.loop.time() >= deadline:
                        raise
                    await asyncio.sleep(.01)
            for stream in (writer, backend):
                stream.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            pumps = [asyncio.create_task(delayed_stream(reader, backend, self.delay_ms / 1000,
                                                      record["client_to_replica"])),
                     asyncio.create_task(delayed_stream(incoming, writer, self.delay_ms / 1000,
                                                      record["replica_to_client"]))]
            await asyncio.gather(*pumps)
        except asyncio.CancelledError:
            record["cancelled_at_cleanup"] = True
            raise
        except Exception as error:
            record["error"] = f"{type(error).__name__}: {error}"
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (writer, backend):
                if stream is not None:
                    stream.close()
            for stream in (writer, backend):
                if stream is not None:
                    try:
                        await stream.wait_closed()
                    except OSError:
                        pass
            record["closed"] = True
            self.connections.discard(task)

    async def _close(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        if self.connections:
            _, pending = await asyncio.wait(self.connections, timeout=1)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    def close(self):
        if self.closed:
            return
        if self.thread.is_alive():
            try:
                asyncio.run_coroutine_threadsafe(self._close(), self.loop).result(10)
            finally:
                self.loop.call_soon_threadsafe(self.loop.stop)
                self.thread.join(10)
            if self.thread.is_alive():
                raise RuntimeError("proxy event-loop thread failed to stop")
        self.loop.close()
        self.closed = True

    def report(self):
        if not self.closed:
            raise RuntimeError("proxy report requires completed cleanup")
        records = copy.deepcopy(self.records)
        for record in records:
            for direction in ("client_to_replica", "replica_to_client"):
                counters = record[direction]
                count = counters["forwarded_chunks"]
                counters["mean_forward_delay_us"] = counters["forward_delay_sum_us"] / count if count else None
                if not count:
                    counters["forward_delay_min_us"] = None
        return {"delay_ms_per_direction": self.delay_ms, "proxy_addresses": self.addresses,
                "backend_addresses": [f"{host}:{port}" for host, port in self.targets],
                "thread_stopped": not self.thread.is_alive(), "connections": records,
                "forwarded_bytes_definition": "bytes accepted by asyncio write then drain; validation telemetry only, not replica traffic accounting"}


class ProxiedChildren:
    """Inject addresses without changing production Config or runner semantics."""
    def __init__(self, delay_ms):
        self.delay_ms, self.proxy, self.children = delay_ms, None, []
        self.original_child = run_network.Child

    def child(self, binary, config_path, node_id, directory):
        config = json.loads(config_path.read_text())
        if self.proxy is None:
            self.proxy = DelayProxy(config["addresses"], self.delay_ms).start()
        own_listener = config["addresses"][node_id]
        config["addresses"] = list(self.proxy.addresses)
        config["addresses"][node_id] = own_listener
        path = directory / f"config-replica-{node_id}.json"
        path.write_text(json.dumps(config, indent=2) + "\n")
        path.chmod(0o600)
        child = self.original_child(binary, path, node_id, directory)
        self.children.append(child)
        return child

    def close(self):
        # Also covers failure during run_network's list-comprehension spawn.
        errors = []
        for child in self.children:
            try:
                if child.process.poll() is None:
                    child.finish()
            except Exception as error:
                errors.append(f"replica cleanup: {error}")
        if self.proxy is not None:
            try:
                self.proxy.close()
            except Exception as error:
                errors.append(f"proxy cleanup: {error}")
        if errors:
            raise RuntimeError("; ".join(errors))


def verify_proxy(report):
    if not report["thread_stopped"] or not report["connections"]:
        raise AssertionError("proxy failed to handle traffic or stop")
    if any(child["exit_code"] is None for child in report.get("owned_replica_processes", [])):
        raise AssertionError("owned replica remained alive after cleanup")
    for record in report["connections"]:
        if not record["closed"] or record.get("error"):
            raise AssertionError(f"proxy connection failed: {record}")
        for direction in ("client_to_replica", "replica_to_client"):
            counters = record[direction]
            if counters["read_bytes"] != counters["forwarded_bytes"]:
                raise AssertionError("proxy cleanup discarded bytes")
            if counters["queue_capacity_waits"]:
                raise AssertionError("proxy delay queue saturated; diagnostic is invalid")
            if counters["forwarded_chunks"] and counters["forward_delay_min_us"] < report["delay_ms_per_direction"] * 1000 - 100:
                raise AssertionError("proxy forwarded earlier than the configured delay")


def calibration(delay_ms):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(.1)
    stop, errors = threading.Event(), []

    def echo():
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(.1)
                while not stop.is_set():
                    try:
                        data = connection.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    connection.sendall(data)

    def guarded_echo():
        try:
            echo()
        except Exception as error:
            errors.append(str(error))

    target = f"127.0.0.1:{listener.getsockname()[1]}"
    thread = threading.Thread(target=guarded_echo, name="delugi-delay-calibration")
    thread.start()
    proxy = None
    try:
        proxy = DelayProxy([target], delay_ms).start()
        samples = {}
        for name, address in (("direct", target), ("proxied", proxy.addresses[0])):
            with socket.create_connection(address_tuple(address), timeout=3) as client:
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                rows = []
                for _ in range(11):
                    started = time.monotonic_ns()
                    client.sendall(b"x")
                    if client.recv(1) != b"x":
                        raise AssertionError("calibration lost echo bytes")
                    rows.append((time.monotonic_ns() - started) / 1_000_000)
                samples[name] = rows[1:]
        added = statistics.median(samples["proxied"]) - statistics.median(samples["direct"])
        if not 2 * delay_ms - 1 <= added <= 2 * delay_ms + 30:
            raise AssertionError(f"calibration added RTT is inconsistent: {added}ms")
        proxy.close()
        report = proxy.report()
        verify_proxy(report)
        return {"status": "passed", "samples_rtt_ms": samples, "median_added_rtt_ms": added,
                "proxy": report}
    finally:
        if proxy is not None:
            proxy.close()
        stop.set()
        thread.join(3)
        listener.close()
        if thread.is_alive() or errors:
            raise RuntimeError(f"calibration cleanup failed: {errors}")


def run_proxied(binary, directory, delay_ms, operation):
    factory = ProxiedChildren(delay_ms)
    result, report, cleanup_errors = None, None, []
    try:
        with patch.object(run_network, "Child", factory.child), patch.object(run_sustained, "Child", factory.child):
            result = operation()
    except Exception as error:
        result = {"status": "failed", "error": f"{type(error).__name__}: {error}"}
    finally:
        directory.mkdir(parents=True, exist_ok=True)
        try:
            factory.close()
        except Exception as error:
            cleanup_errors.append(f"{type(error).__name__}: {error}")
        if factory.proxy is not None:
            try:
                report = factory.proxy.report()
            except Exception as error:
                report = {"report_error": f"{type(error).__name__}: {error}"}
        if report is not None:
            report["owned_replica_processes"] = [{"id": child.id, "pid": child.process.pid,
                                                  "exit_code": child.process.poll()}
                                                 for child in factory.children]
            (directory / "proxy.json").write_text(json.dumps(report, indent=2) + "\n")
    if report is None:
        cleanup_errors.append("replica fixture did not start any proxy")
    else:
        result["proxy"] = {"path": str(directory / "proxy.json"),
                           "sha256": run_network.sha((directory / "proxy.json").read_bytes())}
    if cleanup_errors:
        result["status"], result["diagnostic_cleanup_errors"] = "failed", cleanup_errors
    try:
        verify_proxy(report)
    except Exception as error:
        result["status"] = "failed"
        result["proxy_error"] = f"{type(error).__name__}: {error}"
    (directory / "diagnostic-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def archived_build(binary, manifest_path, output):
    """Bind a preserved binary to its original verified source snapshot."""
    source = json.loads(manifest_path.read_text())
    stamp = source["build_stamp"]
    actual = run_network.sha(binary.read_bytes())
    if source.get("status") not in ("passed", "built") or actual != stamp["binary_sha256"] or actual != source["binary_sha256"]:
        raise RuntimeError("archived binary does not match its successful original manifest")
    if stamp["inputs"]["compiler"] != source["rustc"]:
        raise RuntimeError("archived build compiler provenance disagrees")
    original_sources = {entry["path"]: entry["sha256"] for entry in source["source_files"]}
    inputs = stamp["inputs"]["sources"]
    if not {"Cargo.toml", "Cargo.lock", "src/transport.rs", "src/process.rs"}.issubset(inputs):
        raise RuntimeError("archived build lacks required source identity")
    copied = []
    for name, digest in inputs.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or (name not in ("Cargo.toml", "Cargo.lock") and not name.startswith("src/")):
            raise RuntimeError("archived build has an invalid source path")
        data = (manifest_path.parent / "snapshot" / relative).read_bytes()
        if original_sources.get(name) != digest or run_network.sha(data) != digest:
            raise RuntimeError(f"archived source disagrees with build stamp: {name}")
        destination = output / "binary-source" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        copied.append({"path": name, "sha256": digest})
    (output / "original-build-manifest.json").write_bytes(manifest_path.read_bytes())
    return {"build_stamp": stamp, "binary_git_head": source["git_head"],
            "binary_source_scope": "original archived build source, independent of the current working tree",
            "binary_source_files": copied,
            "binary_specification": source.get("specification", {
                "review_status": "historical build did not record an explicit specification selection",
                "note": "Use the original build manifest and source archive; do not infer a current specification pin."}),
            "archived_build_manifest": {"path": str(manifest_path), "sha256": run_network.sha(manifest_path.read_bytes())}}


def verify_archived_ordering_config(output):
    """Never silently reinterpret the new defaults when replaying an old binary."""
    source = (output / "binary-source/src/process.rs").read_text()
    if "pub ordering_mode:" not in source:
        raise RuntimeError("archived binary predates explicit ordering modes; replay it with its original archived harness")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/delugi-replica")
    parser.add_argument("--archived-build-manifest", type=Path,
                        help="verify a preserved binary against its original build stamp and source snapshot")
    parser.add_argument("--delay-ms", type=float, default=10)
    parser.add_argument("--bound-ms", type=int, default=100)
    run_network.add_ordering_arguments(parser)
    run_network.add_spec_arguments(parser)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--transaction-size", type=int, default=512)
    parser.add_argument("--ingress-batch-ms", type=int, default=100)
    parser.add_argument("--warmup", type=float, default=2)
    parser.add_argument("--duration", type=float, default=5)
    parser.add_argument("--drain", type=float, default=30)
    parser.add_argument("--scenario", choices=("all", "finite", "sustained"), default="all")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 1, "status": "incomplete", "command": sys.argv,
                "started_utc": datetime.now(timezone.utc).isoformat(),
                "classification": "independent_replica_processes_userspace_tcp_byte_stream_delay_diagnostic",
                "method": {"delay": "Each chunk waits at least delay_ms after proxy read, independently in both directions; reader and writer run concurrently; no frame or ACK parsing, no per-chunk round-trip gate",
                           "replicas": "four independent real replica processes, real protocol and transport signatures; bundled PROG pacing by default; resolved ordering settings recorded explicitly",
                           "routing": "each replica binds its own backend address; every peer destination points to the destination proxy; control addresses are direct",
                           "limitations": "Userspace stream chunks, not IP packets or kernel shaping; TCP handshakes are not artificially delayed; real CPU/event-loop/OS scheduling may add delay; no bandwidth limit or packet loss; proxy scheduling metrics and RTT calibration retained",
                           "latency": "sustained: originating replica insertion before batch production to post-handler local materialization, completed-in-window; finite preloaded test endpoints are separately retained by the existing runner",
                           "traffic": "native counters include signed data frames and ACK stream bytes once at replica sockets; exclude proxy duplicate writes, control, TCP/IP headers and kernel retries"},
                "settings": {k: v for k, v in vars(args).items() if k not in ("output", "binary", "archived_build_manifest", "spec_snapshot", "paper_repository")},
                "scheduling": run_network.scheduling_provenance(run_network.ordering_options(
                    args.bound_ms, args.ordering_batch, args.round_barrier_ms,
                    args.progress_pacing_ms, args.ordering_mode)),
                "machine": run_network.machine_metadata(), "source_files": [], "trials": []}
    try:
        manifest["specification"] = run_network.archive_spec(args.spec_snapshot, output / "snapshot", args.paper_repository)
        if any(os.environ.get(name) for name in ("DELUGI_SHAPER_CONTROL", "DELUGI_NETWORK_DELAY_MS", "DELUGI_SHAPER_TOKEN_FILE")):
            raise RuntimeError("unset kernel-shaper environment for the isolated userspace diagnostic")
        binary = args.binary.resolve()
        if args.archived_build_manifest:
            manifest.update(archived_build(binary, args.archived_build_manifest.resolve(), output))
            verify_archived_ordering_config(output)
            sources = []
        else:
            compiler = subprocess.run(["rustc", "--version", "--verbose"], cwd=ROOT, capture_output=True,
                                      text=True, check=True).stdout.strip()
            manifest["build_stamp"] = run_sustained.verify_build_stamp(binary, compiler)
            manifest["binary_source_scope"] = "current working tree verified against release build stamp"
            sources = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"] + sorted((ROOT / "src").rglob("*.rs"))
        manifest["binary"] = {"path": str(binary), "sha256": run_network.sha(binary.read_bytes())}
        manifest["harness_git_head"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                                     text=True, check=True).stdout.strip()
        if not args.archived_build_manifest:
            manifest["binary_git_head"] = manifest["harness_git_head"]
        sources += [ROOT / name for name in ("scripts/run_tcp_delay.py", "scripts/run_network.py", "scripts/run_sustained.py", "scripts/network_delay.py", "scripts/timing_calibration.py", "scripts/spec_provenance.py", "tests/tcp_delay_test.py")]
        for source in sources:
            relative, data = source.relative_to(ROOT), source.read_bytes()
            destination = output / "snapshot" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            manifest["source_files"].append({"path": str(relative), "sha256": run_network.sha(data)})
        manifest["calibration"] = calibration(args.delay_ms)
        if args.scenario in ("all", "finite"):
            for label, silent in (("honest-round4", None), ("silent-leader-three-anchors", 0)):
                directory = output / label
                result = run_proxied(binary, directory, args.delay_ms,
                                     lambda: run_network.run_trial(binary, directory, {"silent": silent}, args.bound_ms, 30, 32,
                                                                   args.ordering_batch, args.round_barrier_ms, args.progress_pacing_ms, args.ordering_mode))
                manifest["trials"].append({"label": label, "result": result})
                if result["status"] != "passed":
                    raise AssertionError(f"{label} failed: {result.get('error', result.get('proxy_error'))}")
        if args.scenario in ("all", "sustained"):
            directory = output / "sustained"
            result = run_proxied(binary, directory, args.delay_ms,
                                 lambda: run_sustained.run_trial(binary, directory, args.rate, args.warmup, args.duration,
                                                                args.transaction_size, args.ingress_batch_ms, args.bound_ms, args.drain,
                                                                args.ordering_batch, args.round_barrier_ms, args.progress_pacing_ms, args.ordering_mode))
            manifest["trials"].append({"label": "sustained", "result": result})
            manifest["comparison"] = result.get("comparison")
            if result["status"] != "passed":
                raise AssertionError(f"sustained failed: {result.get('error', result.get('proxy_error'))}")
        for source in manifest["source_files"]:
            if run_network.sha((ROOT / source["path"]).read_bytes()) != source["sha256"]:
                raise RuntimeError(f"source changed during run: {source['path']}")
        if run_network.sha(binary.read_bytes()) != manifest["binary"]["sha256"]:
            raise RuntimeError("binary changed during run")
        run_network.verify_spec_unchanged(manifest["specification"])
        manifest["status"] = "passed"
    except Exception as error:
        manifest["status"], manifest["error"] = "failed", f"{type(error).__name__}: {error}"
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        manifest["artifacts"] = [{"path": str(path.relative_to(output)), "sha256": run_network.sha(path.read_bytes())}
                                 for path in sorted(output.rglob("*")) if path.is_file()]
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(output / "manifest.json"), "status": manifest["status"],
                      "comparison": manifest.get("comparison"), "error": manifest.get("error")}), flush=True)
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
