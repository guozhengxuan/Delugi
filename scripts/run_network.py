#!/usr/bin/env python3
"""Run independent replicas over real loopback TCP and archive finite workload measurements.

This is a coordinated, non-saturating integration experiment. The harness
preloads four batch waves before starting ordering. Leaders then issue signed
REPORT requests and replicas answer automatically; the controller never asks
for an observation. Preloading is fixture coordination, not a protocol rule.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import secrets
import socket
import statistics
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
# Also support the standalone importlib-based regression tests.
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))
from spec_provenance import add_spec_arguments, archive_spec, verify_spec_unchanged, scheduling_provenance
from shared_core_conformance import source_inventory
MAX_REPLY = 16 * 1024 * 1024


def machine_metadata():
    metadata = {"system": platform.system(), "release": platform.release(),
                "architecture": platform.machine(), "processor": platform.processor(),
                "logical_cpus": os.cpu_count()}
    if sys.platform == "darwin":
        for name, field in (("hw.model", "model"), ("machdep.cpu.brand_string", "cpu_model"),
                            ("hw.memsize", "memory_bytes"), ("hw.physicalcpu", "physical_cpus")):
            reply = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True)
            if reply.returncode == 0:
                value = reply.stdout.strip()
                metadata[field] = int(value) if value.isdecimal() else value
    elif hasattr(os, "sysconf"):
        try:
            metadata["memory_bytes"] = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        except (OSError, ValueError):
            pass
    return metadata


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest_key(value):
    if isinstance(value, list):
        return bytes(value).hex()
    return str(value)


def percentile(values, fraction):
    """Nearest-rank sample quantile, meaningful here only as a descriptive statistic."""
    if not values:
        return None
    ordered = sorted(values)
    import math
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def summary_ms(values):
    values = [v / 1000 for v in values]
    if not values:
        return {"samples": 0}
    return {"samples": len(values), "min_ms": min(values), "median_ms": statistics.median(values),
            "p95_ms": percentile(values, .95), "max_ms": max(values)}


def unused_addresses(count):
    # Reserve the whole set together to avoid selecting the same ephemeral port.
    # There is a small unavoidable bind race before the children take ownership.
    held = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(("127.0.0.1", 0))
            held.append(sock)
        return ["127.0.0.1:" + str(sock.getsockname()[1]) for sock in held]
    finally:
        for sock in held:
            sock.close()


def verify_round_four_history(events, silent):
    proposals = [event for node_events in events.values() for event in node_events
                 if event.get("event") == "proposal" and event.get("round") == 4]
    if len(proposals) != 1:
        raise AssertionError("round four must have exactly one full proposal event")
    proposal = proposals[0].get("message", {}).get("Propose", {})
    evidence = proposal.get("history", {}).get("Evidence") if isinstance(proposal.get("history"), dict) else None
    if not evidence:
        raise AssertionError("round four must carry real HISTORY3 evidence")
    reports = evidence.get("reports", [])
    if len(reports) != 3 or len({report["signer"] for report in reports}) != 3:
        raise AssertionError("round four lacks three distinct HISTORY3 reporters")
    if any(report["body"]["horizon"] != 1 for report in reports):
        raise AssertionError("round-four history must have exact horizon one")
    entries = proposal["header"]["body"]["entries"]
    if entries["horizon"] != 1:
        raise AssertionError("round-four signed entries have the wrong horizon")
    if silent == 0:
        if evidence["pivot"] != 0 or evidence["proof"] is not None or entries["pivot"] != 0 or entries["digest"] is not None:
            raise AssertionError("silent round one needs a negative HISTORY3 projection")
        if any(report["body"]["positives"] for report in reports):
            raise AssertionError("silent-round history contains an unsupported positive")
    else:
        proof = evidence.get("proof")
        if evidence["pivot"] != 1 or not proof or proof["cer"]["body"]["round"] != 1 or entries["pivot"] != 1:
            raise AssertionError("honest round one needs an actual positive CER proof")
        if entries["digest"] != proof["cer"]["body"]["digest"]:
            raise AssertionError("positive HISTORY3 proof and fixed projection disagree")
    return {"horizon": 1, "pivot": evidence["pivot"],
            "reporters": [report["signer"] for report in reports], "has_cer_proof": evidence["proof"] is not None}


def verify_outputs(snapshots, live, rounds, silent, submitted, events):
    """Validate exact useful output and ordering, including silent-slot resolution."""
    expected_rounds = [r for r in range(1, rounds + 1) if (r - 1) % len(snapshots) != silent]
    expected_ids = {digest_key(tx) for record in submitted for tx in record["transactions"]}
    expected_count = sum(len(record["transactions"]) for record in submitted)
    if len(expected_ids) != expected_count or not expected_ids:
        raise AssertionError("fixture transaction IDs must be distinct and nonempty")
    first = snapshots[live[0]]
    for node_id in live:
        node = snapshots[node_id]
        if node["executed_rounds"] != expected_rounds:
            raise AssertionError(f"replica {node_id}: wrong executed rounds")
        if node["executed"] != first["executed"] or node["state_hash"] != first["state_hash"]:
            raise AssertionError(f"replica {node_id}: execution or state differs")
        actual_ids = [digest_key(tx["transaction"]) for tx in node["executed"]]
        if len(actual_ids) != expected_count or set(actual_ids) != expected_ids:
            raise AssertionError(f"replica {node_id}: missing, unexpected, or duplicate transactions")
        for entry in node["executed"]:
            if entry["round"] != expected_rounds[0]:
                raise AssertionError(f"replica {node_id}: preloaded transaction was not materialized in the first honest slot")
        if node["pending_materialization"] != 0:
            raise AssertionError(f"replica {node_id}: incomplete materialization")
        batches = node.get("materialized_batches", [])
        if not batches or batches != first.get("materialized_batches"):
            raise AssertionError(f"replica {node_id}: missing or divergent exact batch output")
        expected_batches = [(producer, height) for producer in live for height in range(1, rounds + 1)]
        actual_batches = [(batch["header"]["producer"], batch["header"]["height"]) for batch in batches]
        if actual_batches != expected_batches or any(not batch.get("payload") for batch in batches):
            raise AssertionError(f"replica {node_id}: missing, duplicate, or misordered preloaded batches")
        expected_heights = [rounds if i in live else 0 for i in range(len(snapshots))]
        if node.get("cumulative_heights") != expected_heights:
            raise AssertionError(f"replica {node_id}: wrong cumulative output heights")
        deliveries = node["ordering"]["deliveries"]
        if deliveries != first["ordering"]["deliveries"]:
            raise AssertionError(f"replica {node_id}: ordered descriptors differ")
        if [entry["round"] for entry in deliveries] != expected_rounds:
            raise AssertionError(f"replica {node_id}: incorrect ordered descriptor sequence")
        for r in range(1, rounds + 1):
            status = node["ordering"]["statuses"].get(str(r))
            if (r - 1) % len(snapshots) == silent:
                if status != "Skip":
                    raise AssertionError(f"replica {node_id}: silent round {r} was not skipped")
            elif not isinstance(status, dict) or "Commit" not in status:
                raise AssertionError(f"replica {node_id}: round {r} lacks committed classification")
        direct = {int(event["round"]) for event in events[node_id]
                  if event.get("event") == "direct_commit" and "round" in event}
        if not set(expected_rounds).issubset(direct):
            raise AssertionError(f"replica {node_id}: honest anchor lacks direct-commit event")
    if silent is not None:
        if snapshots[silent]["executed"]:
            raise AssertionError("silent replica executed transactions")
        if any(event.get("event") in {"proposal", "direct_commit", "ordered_descriptor", "transaction_materialized",
                                      "report_broadcast", "observation_snapshot"}
               for event in events[silent]):
            raise AssertionError("silent replica performed protocol work")
    history = verify_round_four_history(events, silent)
    composition = verify_composition(snapshots, events, live, rounds, expected_rounds)
    return {"expected_rounds": expected_rounds, "transactions_per_correct_replica": expected_count, "round_four_history": history,
            "composition": composition,
            "state_hash": first["state_hash"],
            "ordered_descriptor_digests": [{"round": d["round"], "digest": d["digest"]}
                                           for d in first["ordering"]["deliveries"]]}


def verify_composition(snapshots, events, live, rounds, expected_rounds):
    """Require automatic signed REPORT/OBS and inspect the actual input proofs.

    Signature validity is checked by the native protocol. This archive check
    binds each signed object's slot/signer/base and requires distinct current
    sources for every coordinate, including empty suffixes.
    """
    n = len(snapshots)
    f = (n - 1) // 3
    reports, observations, inputs = {}, {}, {}
    for node_id, node_events in events.items():
        for event in node_events:
            r = event.get("round")
            if not isinstance(r, int) or not 1 <= r <= rounds:
                continue
            kind = event.get("event")
            if kind not in {"report_broadcast", "observation_snapshot", "proposal"}:
                continue
            if r not in expected_rounds or node_id not in live:
                raise AssertionError("silent slot or replica performed composition work")
            if kind == "report_broadcast":
                key, target = r, reports
                if node_id != (r - 1) % n:
                    raise AssertionError("REPORT came from the wrong leader")
                signed = event.get("report", {})
                if signed.get("signer") != node_id or len(signed.get("signature", [])) != 64:
                    raise AssertionError("REPORT lacks its leader signature")
                if signed.get("body", {}).get("opportunity") != r:
                    raise AssertionError("REPORT signed the wrong opportunity")
            elif kind == "observation_snapshot":
                key, target = (r, node_id), observations
                signed = snapshots[node_id].get("observation_evidence", {}).get(str(r), {})
                if signed.get("signer") != node_id or len(signed.get("signature", [])) != 64:
                    raise AssertionError("OBS lacks its reporter signature")
                if signed.get("body", {}).get("opportunity") != r:
                    raise AssertionError("OBS signed the wrong opportunity")
            else:
                key, target = r, inputs
                if node_id != (r - 1) % n:
                    raise AssertionError("input constructed by the wrong leader")
            if key in target:
                raise AssertionError(f"duplicate {kind} event")
            target[key] = signed if kind == "observation_snapshot" else event
    if set(reports) != set(expected_rounds):
        raise AssertionError("missing automatic signed REPORT")
    if set(observations) != {(r, i) for r in expected_rounds for i in live}:
        raise AssertionError("missing automatic signed OBS")
    if set(inputs) != set(expected_rounds):
        raise AssertionError("missing inspected availability input")
    empty_coordinates = 0
    for r, event in inputs.items():
        descriptor, proof = event.get("descriptor", {}), event.get("availability_proof", {})
        report_body = reports[r]["report"]["body"]
        if descriptor.get("base") != report_body.get("base"):
            raise AssertionError("input base differs from signed REPORT")
        if len(descriptor.get("frontier", [])) != n or len(descriptor.get("targets", [])) != n:
            raise AssertionError("input lacks its full descriptor")
        if proof.get("sources") != []:
            raise AssertionError("reference input contains historical sources")
        pool, coordinates = proof.get("pool", []), proof.get("coordinates", [])
        if len(pool) != n - f or len({o.get("signer") for o in pool}) != n - f:
            raise AssertionError("input lacks a distinct current observation pool")
        for observation in pool:
            own = observations.get((r, observation.get("signer")))
            if observation != own:
                raise AssertionError("input pool does not match emitted current OBS")
            if observation["body"].get("base") != descriptor["base"]:
                raise AssertionError("current OBS names another base")
        if len(coordinates) != n:
            raise AssertionError("input lacks all current coordinates")
        for k, coordinate in enumerate(coordinates):
            if not isinstance(coordinate, dict) or "Witnesses" not in coordinate:
                raise AssertionError("reference input has a noncurrent coordinate")
            witnesses = coordinate["Witnesses"].get("witnesses", [])
            if len(witnesses) != f + 1:
                raise AssertionError("current coordinate lacks f+1 witnesses")
            signers = []
            for witness in witnesses:
                source = witness.get("source")
                if not isinstance(source, dict) or set(source) != {"Current"}:
                    raise AssertionError("reference witness is historical")
                index = source["Current"]
                if not isinstance(index, int) or not 0 <= index < len(pool):
                    raise AssertionError("current witness index is invalid")
                signer = pool[index]["signer"]
                if witness.get("reporter") != signer:
                    raise AssertionError("current witness label differs from actual signer")
                signers.append(signer)
            if len(set(signers)) != f + 1:
                raise AssertionError("current witnesses reuse an OBS signer")
            empty_coordinates += descriptor["targets"][k] == descriptor["frontier"][k]
    return {"construction": "all-current", "signed_reports": len(reports),
            "signed_observations": len(observations), "inputs": len(inputs),
            "historical_sources": 0, "empty_coordinates": empty_coordinates}


def collect_latency(live, submitted, events, first_submission_us, start_us, rounds):
    admitted = {digest_key(tx): record for record in submitted for tx in record["transactions"]}
    per_transaction = []
    per_replica = {}
    all_completion = []
    all_observed_completion = []
    all_observed_ordered = []
    first_submission_ns = min(record["submission_start_monotonic_ns"] for record in submitted)
    proposal_times = {}
    for node_id in live:
        milestones = {name: {} for name in ("input_ready", "proposal", "direct_commit", "ordered_descriptor", "materialized")}
        observed = {}
        ordered_receipts = {}
        for event in events[node_id]:
            kind = event.get("event")
            if kind == "ordering_input_ready":
                kind = "input_ready"
            if kind in milestones and "round" in event:
                milestones[kind].setdefault(str(event["round"]), event["observed_unix_us"])
                if kind == "proposal":
                    proposal_times.setdefault(str(event["round"]), event["observed_unix_us"])
            if kind == "ordered_descriptor":
                ordered_receipts[str(event["round"])] = event["_controller_received_monotonic_ns"]
            if kind == "transaction_materialized":
                key = digest_key(event["transaction"])
                if key in observed:
                    raise AssertionError(f"replica {node_id}: duplicate transaction materialization telemetry")
                observed[key] = (event["observed_unix_us"], event["_controller_received_monotonic_ns"], event["round"])
        if set(observed) != set(admitted):
            raise AssertionError(f"replica {node_id}: missing transaction completion timestamps")
        for key, (completed, received_ns, executed_round) in observed.items():
            source = admitted[key]
            elapsed = completed - source["submission_start_unix_us"]
            local = completed - source["accepted_unix_us"]
            if elapsed < 0 or local < 0:
                raise AssertionError("negative measured latency; clocks or timestamps are inconsistent")
            ordered = milestones["ordered_descriptor"].get(str(executed_round))
            if ordered is None or ordered < source["submission_start_unix_us"] or completed < ordered:
                raise AssertionError("missing or inconsistent ordered-release timestamp")
            ordered_received = ordered_receipts.get(str(executed_round))
            if ordered_received is None or ordered_received < source["submission_start_monotonic_ns"]:
                raise AssertionError("missing or inconsistent observed ordered-release timestamp")
            per_transaction.append({"replica": node_id, "transaction": key, "executed_round": executed_round,
                                    "client_observed_ordered_release_us": (ordered_received - source["submission_start_monotonic_ns"]) / 1000,
                                    "client_submission_to_ordered_release_us": ordered - source["submission_start_unix_us"],
                                    "client_observed_materialization_us": (received_ns - source["submission_start_monotonic_ns"]) / 1000,
                                    "client_submission_to_materialization_us": elapsed,
                                    "producer_acceptance_to_materialization_us": local})
        finished = max(value[0] for value in observed.values())
        all_observed_completion.append(max(value[1] for value in observed.values()))
        all_observed_ordered.append(max(ordered_receipts.values()))
        all_completion.append(finished)
        per_replica[str(node_id)] = {
            "milestones_unix_us": milestones,
            "start_to_last_transaction_us": finished - start_us,
            "first_submission_to_last_transaction_us": finished - first_submission_us,
            "submission_latency": summary_ms([entry["client_submission_to_materialization_us"]
                                              for entry in per_transaction if entry["replica"] == node_id]),
        }
    stage = []
    for node_id in live:
        ms = per_replica[str(node_id)]["milestones_unix_us"]
        for r in range(1, rounds + 1):
            key = str(r)
            proposal = proposal_times.get(key)
            commit = ms["direct_commit"].get(key)
            ordered = ms["ordered_descriptor"].get(key)
            materialized = ms["materialized"].get(key)
            ready = ms["input_ready"].get(key)
            stage.append({"replica": node_id, "round": r,
                          "input_ready_to_proposal_us": None if ready is None or proposal is None else proposal - ready,
                          "proposal_to_direct_commit_us": None if proposal is None or commit is None else commit - proposal,
                          "proposal_to_ordered_release_us": None if proposal is None or ordered is None else ordered - proposal,
                          "ordered_release_to_materialization_us": None if ordered is None or materialized is None else materialized - ordered})
    if any(value < 0 for row in stage for key, value in row.items() if key.endswith("_us") and value is not None):
        raise AssertionError("negative stage latency; inconsistent timestamps")
    elapsed = max(all_completion) - first_submission_us
    observed_elapsed = (max(all_observed_completion) - first_submission_ns) / 1000
    return {"clock": "same-host CLOCK_REALTIME microseconds; controller checks against monotonic elapsed time; events timestamped after handler completion",
            "client_observed_ordered_release": summary_ms([row["client_observed_ordered_release_us"] for row in per_transaction]),
            "client_observed_materialization": summary_ms([row["client_observed_materialization_us"] for row in per_transaction]),
            "client_submission_to_ordered_release": summary_ms([row["client_submission_to_ordered_release_us"] for row in per_transaction]),
            "client_submission_to_materialization": summary_ms([row["client_submission_to_materialization_us"] for row in per_transaction]),
            "producer_acceptance_to_materialization": summary_ms([row["producer_acceptance_to_materialization_us"] for row in per_transaction]),
            "all_correct_completion_from_first_submission_us": observed_elapsed,
            "all_correct_ordered_from_first_submission_us": (max(all_observed_ordered) - first_submission_ns) / 1000,
            "all_correct_server_completion_from_first_submission_us": elapsed,
            "finite_workload_transactions_per_second": len(admitted) * 1_000_000 / observed_elapsed,
            "per_replica": per_replica, "stages": stage, "per_transaction": per_transaction}


class Child:
    def __init__(self, binary, config_path, node_id, directory):
        self.id = node_id
        self.events = []
        self.errors = []
        self.lock = threading.Lock()
        self.stderr = (directory / f"replica-{node_id}.stderr").open("w")
        self.process = subprocess.Popen([str(binary), "--config", str(config_path), "--id", str(node_id)],
                                        cwd=ROOT, stdout=subprocess.PIPE, stderr=self.stderr, text=True,
                                        bufsize=1)
        self.reader = threading.Thread(target=self._read, args=(directory,), daemon=True)
        self.reader.start()

    def _read(self, directory):
        with (directory / f"replica-{self.id}.stdout.jsonl").open("w") as raw, \
                (directory / f"replica-{self.id}.observed.jsonl").open("w") as observed:
            for line in self.process.stdout:
                received_ns = time.monotonic_ns()
                raw.write(line)
                raw.flush()
                try:
                    event = json.loads(line)
                    event["_controller_received_monotonic_ns"] = received_ns
                    with self.lock:
                        self.events.append(event)
                    observed.write(json.dumps({"received_monotonic_ns": received_ns, "event": event}) + "\n")
                    observed.flush()
                except Exception as error:
                    self.errors.append(str(error))

    def finish(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.reader.join(timeout=2)
        self.stderr.close()
        return {"id": self.id, "pid": self.process.pid, "exit_code": self.process.returncode,
                "telemetry_errors": self.errors}


class Controller:
    def __init__(self, config, directory, children, *, streaming=False):
        self.stream = (directory / "control.jsonl").open("w") if streaming else None
        self.streaming = streaming
        self.config, self.directory, self.children = config, directory, children
        self.sequence = 0
        self.lock = threading.Lock()
        self.commands = []
        self.last_snapshots = {}
        self.traffic = {i: {"requests": 0, "written_bytes": 0, "read_bytes": 0}
                        for i in range(len(children))}

    def check(self):
        for child in self.children:
            if child.process.poll() is not None:
                raise RuntimeError(f"replica {child.id} exited early with {child.process.returncode}")
            if child.errors:
                raise RuntimeError(f"replica {child.id} emitted invalid JSON: {child.errors}")
            failures = [event for event in child.events if event.get("event") in {"fatal", "error"}]
            if failures:
                raise RuntimeError(f"replica {child.id} reported {failures[-1]}")

    def request(self, node_id, kind, **fields):
        with self.lock:
            self.sequence += 1
            request_id = f"request-{self.sequence}"
        command = {"token": self.config["control_token"], "type": kind, "request_id": request_id, **fields}
        raw = json.dumps(command, separators=(",", ":")).encode() + b"\n"
        begin_ns, begin_us = time.monotonic_ns(), time.time_ns() // 1000
        host, port = self.config["control_addresses"][node_id].rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as sock:
            sock.settimeout(5)
            sock.sendall(raw)
            stream = sock.makefile("rb")
            reply_raw = stream.readline(MAX_REPLY + 1)
            if len(reply_raw) > MAX_REPLY or not reply_raw.endswith(b"\n"):
                raise RuntimeError("control reply exceeds bound or is truncated")
        reply = json.loads(reply_raw)
        record = {"replica": node_id, "type": kind, "request_id": request_id, **fields,
                  "start_unix_us": begin_us, "start_monotonic_ns": begin_ns,
                  "duration_us": (time.monotonic_ns() - begin_ns) // 1000, "reply": reply}
        with self.lock:
            if not self.streaming:
                self.commands.append(record)
            elif kind not in {"cohort", "outputs", "batches"} or reply.get("ok") is not True:
                self.stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                self.stream.flush()
            self.traffic[node_id]["requests"] += 1
            self.traffic[node_id]["written_bytes"] += len(raw)
            self.traffic[node_id]["read_bytes"] += len(reply_raw)
        if reply.get("request_id") != request_id or reply.get("id") != node_id or reply.get("ok") is not True:
            raise RuntimeError(f"control command failed: {record}")
        return record

    def many(self, ids, kind, **fields):
        with ThreadPoolExecutor(max_workers=len(ids)) as pool:
            return list(pool.map(lambda node_id: self.request(node_id, kind, **fields), ids))

    def snapshots(self):
        records = self.many(list(range(len(self.children))), "snapshot")
        self.last_snapshots = {record["replica"]: record["reply"]["data"] for record in records}
        return self.last_snapshots

    def wait(self, predicate, deadline, label):
        while time.monotonic() < deadline:
            self.check()
            snapshots = self.snapshots()
            if predicate(snapshots):
                return snapshots
            time.sleep(.01)
        raise TimeoutError(f"timed out waiting for {label}")

    def archive_record(self, record):
        """Persist a ledger-page reference after its separately hashed page is saved."""
        if self.streaming:
            with self.lock:
                self.stream.write(json.dumps(record, separators=(",", ":")) + "\n")
                self.stream.flush()

    def save(self):
        if self.streaming:
            with self.lock:
                if not self.stream.closed:
                    self.stream.flush()
                    self.stream.close()
        else:
            with (self.directory / "control.jsonl").open("w") as stream:
                for command in sorted(self.commands, key=lambda item: item["start_monotonic_ns"]):
                    stream.write(json.dumps(command) + "\n")
        (self.directory / "snapshots.json").write_text(json.dumps(self.last_snapshots, indent=2) + "\n")


def queued_frames(snapshot):
    return sum(peer["outstanding_frames"] + peer.get("deferred_frames", 0)
               for peer in snapshot["transport"]["peers"].values())


WRITTEN_CATEGORY_KEYS = ("payload_bytes", "evidence_control_bytes", "repair_bytes", "transport_overhead_bytes")


def written_categories(snapshot):
    """Conserve actual successful TCP writes, including partials/replays/ACKs."""
    peers = list(snapshot["transport"]["peers"].values())
    if not peers or not any("written_categories" in peer for peer in peers):
        return {"available": False, "reason": "legacy snapshot has no actual-written category counters"}
    if not all("written_categories" in peer for peer in peers):
        raise AssertionError("partial actual-written category population")
    totals = dict.fromkeys((*WRITTEN_CATEGORY_KEYS, "total_written_bytes"), 0)
    for peer in peers:
        row = peer["written_categories"]
        if any(type(row.get(key)) is not int or row[key] < 0 for key in totals):
            raise AssertionError("invalid actual-written category counter")
        actual = peer["ack_bytes_written"] + sum(layer["data_bytes_written"] for layer in peer["layers"].values())
        if sum(row[key] for key in WRITTEN_CATEGORY_KEYS) != row["total_written_bytes"] or actual != row["total_written_bytes"]:
            raise AssertionError("actual-written categories do not conserve TCP bytes")
        for key in totals:
            totals[key] += row[key]
    return {"available": True, "boundary": "successful replica TCP writes; partial writes, retransmissions and ACKs included", **totals}


def aggregate_traffic(snapshots, silent, workload_rounds=4):
    by_replica = {}
    for node_id, snapshot in snapshots.items():
        transport = snapshot["transport"]
        peers = list(transport["peers"].values())
        layers = [layer for peer in peers for layer in peer["layers"].values()]
        def layer_total(name):
            return sum(layer[name] for layer in layers)
        def peer_total(name):
            return sum(peer[name] for peer in peers)
        row = {"transport_enqueued_payload_bytes": layer_total("enqueued_payload_bytes"),
               "protocol_payload_written_bytes": layer_total("payload_bytes_written"),
               "data_frame_written_bytes": layer_total("data_bytes_written"),
               "data_frame_read_bytes": transport["data_bytes_read"],
               "ack_written_bytes": peer_total("ack_bytes_written"),
               "ack_read_bytes": peer_total("ack_bytes_read"),
               "enqueued_frames": layer_total("enqueued_frames"),
               "acknowledged_frames": layer_total("acknowledged_frames"),
               "accepted_frames": layer_total("accepted_frames"),
               "outstanding_frames": peer_total("outstanding_frames"),
               "deferred_frames": sum(peer.get("deferred_frames", 0) for peer in peers),
               "scheduled_frames": sum(layer.get("scheduled_frames", layer["enqueued_frames"]) for layer in layers),
               "retries": peer_total("retries"),
               "partial_frame_written_bytes": peer_total("partial_frame_bytes_written"),
               "connection_failures": peer_total("connection_failures"),
               "rejected_frames": transport["rejected_frames"],
               "queue_full_failures": transport["queue_full_failures"],
               "deferred_accepts": transport.get("deferred_accepts", 0),
               "resource_exhaustions": transport.get("resource_exhaustions", 0)}
        if row["deferred_frames"] or row["scheduled_frames"] != row["enqueued_frames"]:
            raise AssertionError(f"replica {node_id}: deferred transport work at cutoff")
        if row["resource_exhaustions"]:
            raise AssertionError(f"replica {node_id}: transport resource envelope exhausted")
        indices = snapshot["protocol"]["by_index"]
        row["workload_index_enqueued_bytes"] = sum(counter["encoded_bytes"] for index, counter in indices.items() if int(index) <= workload_rounds)
        row["beyond_workload_enqueued_bytes"] = sum(counter["encoded_bytes"] for index, counter in indices.items() if int(index) > workload_rounds)
        row["workload_index_enqueued_messages"] = sum(counter["messages"] for index, counter in indices.items() if int(index) <= workload_rounds)
        row["beyond_workload_enqueued_messages"] = sum(counter["messages"] for index, counter in indices.items() if int(index) > workload_rounds)
        row["protocol_enqueued_bytes"] = row["workload_index_enqueued_bytes"] + row["beyond_workload_enqueued_bytes"]
        row["protocol_enqueued_messages"] = row["workload_index_enqueued_messages"] + row["beyond_workload_enqueued_messages"]
        row["ordering_bundle_frames"] = sum(peer["layers"].get("OrderingBundle", {}).get("enqueued_frames", 0) for peer in peers)
        singles = row["enqueued_frames"] - row["ordering_bundle_frames"]
        row["ordering_bundle_members"] = row["protocol_enqueued_messages"] - singles
        if not 2 * row["ordering_bundle_frames"] <= row["ordering_bundle_members"] <= 32 * row["ordering_bundle_frames"]:
            raise AssertionError("logical message counts disagree with bounded transport bundles")
        # The bundle layout is a u32 count followed by one u32 length per member.
        row["bundle_enqueued_envelope_bytes"] = 4 * (row["ordering_bundle_frames"] + row["ordering_bundle_members"])
        if row["protocol_enqueued_bytes"] + row["bundle_enqueued_envelope_bytes"] != row["transport_enqueued_payload_bytes"]:
            raise AssertionError("logical protocol index counters disagree with transport enqueue counters")
        row["auth_and_framing_written_bytes"] = row["data_frame_written_bytes"] - row["protocol_payload_written_bytes"]
        row["socket_written_bytes"] = row["data_frame_written_bytes"] + row["ack_written_bytes"]
        row["socket_read_bytes"] = row["data_frame_read_bytes"] + row["ack_read_bytes"]
        row["written_categories"] = written_categories(snapshot)
        if row["outstanding_frames"] or row["acknowledged_frames"] != row["enqueued_frames"]:
            raise AssertionError(f"replica {node_id}: unacknowledged transport work at cutoff")
        if node_id == silent and row["enqueued_frames"]:
            raise AssertionError("silent replica enqueued a protocol frame")
        by_replica[str(node_id)] = row
    total = {name: sum(row[name] for row in by_replica.values()) for name in next(iter(by_replica.values())) if name != "written_categories"}
    total["written_categories"] = ({"available": True, **{key: sum(row["written_categories"][key] for row in by_replica.values())
        for key in (*WRITTEN_CATEGORY_KEYS, "total_written_bytes")}} if all(row["written_categories"]["available"] for row in by_replica.values())
        else {"available": False, "reason": "actual-written categories unavailable in legacy snapshots"})
    if total["data_frame_written_bytes"] != total["data_frame_read_bytes"] or total["ack_written_bytes"] != total["ack_read_bytes"]:
        raise AssertionError("successful TCP writes and reads do not balance after drain")
    return {"per_replica": by_replica, "total": total,
            "accounting": "Successful data-frame and acknowledgement stream reads/writes, including retransmitted/partial application writes; excludes TCP/IP headers, TCP retransmissions, and control API bytes; includes silent recipients and beyond-workload traffic"}


def ordering_options(bound_ms, ordering_batch=True, round_barrier_ms=None, progress_pacing_ms=None,
                     ordering_mode=None):
    """Resolve and record the default bundled PROG schedule or an explicit comparison."""
    if bound_ms <= 0:
        raise ValueError("bound_ms must be positive")
    if round_barrier_ms is not None and progress_pacing_ms is not None:
        raise ValueError("round barrier and progress pacing are mutually exclusive")
    for deadline in (round_barrier_ms, progress_pacing_ms):
        if deadline is not None and not 0 < deadline <= bound_ms:
            raise ValueError("ordering release deadline must be positive and at most bound_ms")
    mode = ordering_mode or ("barrier" if round_barrier_ms is not None else "progress")
    options = {"ordering_batch": bool(ordering_batch), "ordering_mode": mode}
    if mode == "progress" and round_barrier_ms is None:
        options["progress_pacing_ms"] = progress_pacing_ms if progress_pacing_ms is not None else bound_ms
    elif mode == "barrier" and progress_pacing_ms is None:
        options["round_barrier_ms"] = round_barrier_ms if round_barrier_ms is not None else bound_ms
    elif mode != "canonical" or round_barrier_ms is not None or progress_pacing_ms is not None:
        raise ValueError("ordering mode and release deadline options conflict")
    return options


def add_ordering_arguments(parser):
    parser.add_argument("--ordering-mode", choices=("progress", "canonical", "barrier"),
                        help="ordering schedule (default: progress; a barrier deadline selects barrier)")
    batching = parser.add_mutually_exclusive_group()
    batching.add_argument("--ordering-batch", action="store_true", default=True,
                          help="immediately bundle enabled ordering messages (default)")
    batching.add_argument("--no-ordering-batch", dest="ordering_batch", action="store_false",
                          help="disable bundling for an explicit comparison")
    parser.add_argument("--round-barrier-ms", type=int,
                        help="select the full round barrier with this release deadline")
    parser.add_argument("--progress-pacing-ms", type=int,
                        help="PROG release deadline (default: bound-ms)")


def run_trial(binary, directory, scenario, bound_ms, timeout, transaction_bytes,
              ordering_batch=True, round_barrier_ms=None, progress_pacing_ms=None, ordering_mode=None):
    directory.mkdir(parents=True)
    result = {"label": directory.name, "scenario": scenario, "status": "incomplete", "pass": False}
    children = []
    controller = None
    wall_begin, mono_begin = time.time_ns(), time.monotonic_ns()
    try:
        keys = subprocess.run([str(binary), "--keygen", str(directory / "keys"), "--nodes", "4"],
                              cwd=ROOT, capture_output=True, text=True)
        (directory / "keygen.stdout").write_text(keys.stdout)
        (directory / "keygen.stderr").write_text(keys.stderr)
        if keys.returncode:
            raise RuntimeError("replica key generation failed")
        key_data = json.loads(keys.stdout)
        addresses = unused_addresses(8)
        config = {"instance": list(secrets.token_bytes(32)), "addresses": addresses[:4],
                  "control_addresses": addresses[4:], "control_token": secrets.token_hex(32),
                  "public_keys": key_data["public_keys"], "key_files": key_data["key_files"],
                  "bound_ms": bound_ms, "chunk_capacity": 4, "workload_rounds": 4,
                  "silent": scenario.get("silent"), "max_runtime_ms": int((timeout + 5) * 1000),
                  **ordering_options(bound_ms, ordering_batch, round_barrier_ms, progress_pacing_ms, ordering_mode)}
        config_path = directory / "config.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        os.chmod(config_path, 0o600)
        children = [Child(binary, config_path, node_id, directory) for node_id in range(4)]
        controller = Controller(config, directory, children)
        deadline = time.monotonic() + timeout
        while not all(any(event.get("event") == "ready" for event in child.events) for child in children):
            controller.check()
            if time.monotonic() >= deadline:
                raise TimeoutError("replicas did not become ready")
            time.sleep(.01)
        live = [i for i in range(4) if i != scenario.get("silent")]
        controller.many(list(range(4)), "prepare")
        submitted = []
        gates = []
        for r in range(1, 5):
            records = controller.many(live, "submit", round=r, count=2, size=transaction_bytes)
            for record in records:
                data = record["reply"]["data"]
                submitted.append({"replica": record["replica"], "round": r,
                                  "transactions": data["transactions"],
                                  "submission_start_unix_us": record["start_unix_us"],
                                  "submission_start_monotonic_ns": record["start_monotonic_ns"],
                                  "accepted_unix_us": record["reply"]["observed_unix_us"]})
            controller.wait(lambda nodes: all(all(nodes[i]["holding_heights"][producer] >= r
                                                 for producer in live) for i in live),
                            deadline, f"wave {r} dissemination")
            gate_us = time.time_ns() // 1000
            gates.append({"wave": r, "all_honest_hold_wave_unix_us": gate_us})
        starts = controller.many(list(range(4)), "start")
        start_us = min(record["start_unix_us"] for record in starts)
        expected_rounds = [r for r in range(1, 5) if (r - 1) % 4 != scenario.get("silent")]
        expected_txs = 4 * len(live) * 2
        controller.wait(lambda nodes: all(nodes[i]["executed_rounds"] == expected_rounds and
                                         len(nodes[i]["executed"]) == expected_txs and
                                         nodes[i]["pending_materialization"] == 0 for i in live),
                        deadline, "identical complete end-to-end workload")
        cutoff_records = controller.many(list(range(4)), "quiesce")
        # Freeze protocol work explicitly, then keep the transport running until
        # all pre-cutoff frames/ACKs drain. Post-cutoff protocol arrivals are
        # recorded as discarded, and no new timer work is generated.
        # Hold the measurement open until all writers are idle and the successful
        # write/read counters are unchanged for at least 100 ms. Pending future
        # protocol timers are intentionally retained in the recorded snapshot.
        previous, stable_since = None, time.monotonic()
        while True:
            controller.check()
            snapshots = controller.snapshots()
            signature = json.dumps({i: s["transport"] for i, s in snapshots.items()}, sort_keys=True)
            if all(queued_frames(s) == 0 for s in snapshots.values()) and signature == previous:
                if time.monotonic() - stable_since >= .1:
                    break
            else:
                stable_since = time.monotonic()
            previous = signature
            if time.monotonic() >= deadline:
                raise TimeoutError("transport did not drain")
            time.sleep(.02)
        events = {child.id: list(child.events) for child in children}
        correctness = verify_outputs(snapshots, live, 4, scenario.get("silent"), submitted, events)
        first_us = min(record["submission_start_unix_us"] for record in submitted)
        latency = collect_latency(live, submitted, events, first_us, start_us, 4)
        drift_us = abs((time.time_ns() - wall_begin) - (time.monotonic_ns() - mono_begin)) / 1000
        if drift_us > 10_000:
            raise AssertionError(f"realtime clock diverged from monotonic clock by {drift_us} us")
        result.update({"pass": True, "status": "passed", "correctness": correctness,
                       "latency": latency, "clock_drift_us": drift_us, "submitted": submitted,
                       "preload_readiness_gates": gates,
                       "ordering_start_commands": [{"replica": item["replica"], "start_unix_us": item["start_unix_us"],
                                                    "duration_us": item["duration_us"]} for item in starts],
                       "measurement_cutoffs": [{"id": item["replica"], "reply": item["reply"]} for item in cutoff_records],
                       "traffic": aggregate_traffic(snapshots, scenario.get("silent")),
                       "replicas": [{"id": i, "pid": children[i].process.pid,
                                     "transport": snapshots[i]["transport"], "protocol": snapshots[i]["protocol"],
                                     "holding_heights": snapshots[i]["holding_heights"],
                                     "executed_rounds": snapshots[i]["executed_rounds"],
                                     "state_hash": snapshots[i]["state_hash"]} for i in range(4)]})
        controller.many(list(range(4)), "stop")
        for child in children:
            child.process.wait(timeout=3)
        if any(child.process.returncode != 0 for child in children):
            raise RuntimeError("a replica exited unsuccessfully after stop")
    except Exception as error:
        result.update({"pass": False, "status": "failed", "error": str(error)})
    finally:
        result["processes"] = [child.finish() for child in children]
        if controller:
            controller.save()
            result["control_traffic"] = controller.traffic
        result["elapsed_seconds"] = (time.monotonic_ns() - mono_begin) / 1_000_000_000
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--bound-ms", type=int, default=250)
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--transaction-bytes", type=int, default=32)
    parser.add_argument("--skip-checks", action="store_true", help="development only: skip format/unit checks, still build release")
    parser.add_argument("--scenario", choices=["all", "honest", "silent"], default="all")
    add_ordering_arguments(parser)
    add_spec_arguments(parser)
    args = parser.parse_args()
    if args.repeats < 1 or not 10 <= args.bound_ms <= 10000 or args.timeout <= 0 or not 1 <= args.transaction_bytes <= 4096:
        parser.error("invalid bounded experiment arguments")
    run = ROOT / "results" / "local" / ("network-" + uuid.uuid4().hex)
    run.mkdir(parents=True)
    manifest = {"schema": 3, "classification": "real_process_loopback_tcp_option_a_integration",
                "status": "incomplete", "started_utc": datetime.now(timezone.utc).isoformat(),
                "scope": "Four independent replica processes, authenticated framed loopback TCP, real Ed25519/MMR/Option A availability/ordering/materialization; optional protocol-silent process; signed leader REPORT requests, authenticated earlier bases, all-current construction and exact-batch output. This network fixture uses nonforking producers; Byzantine forks and non-genesis base validation are exercised separately by Rust tests",
                "machine": machine_metadata(),
                "gate": "real_process_correctness_integration_not_capacity",
                "scheduling": scheduling_provenance(ordering_options(args.bound_ms, args.ordering_batch,
                    args.round_barrier_ms, args.progress_pacing_ms, args.ordering_mode)),
                "method": {"workload": "4 finite batch waves preloaded before ordering starts, 2 distinct transactions per honest producer per wave; no warmup; not saturation throughput",
                           "preload_gate": "Prepare enables dissemination without ordering; harness waits until all correct replicas hold each wave, then starts ordering after wave four. Leaders issue signed REPORTs and replicas answer automatically. There are no controller report commands. Preload gates are fixture coordination, not protocol rules",
                           "traffic": "Separate logical protocol bytes, authenticated envelope/framing bytes, actual successful TCP stream reads/writes, and client control bytes; excludes TCP/IP/link overhead and kernel retransmissions",
                           "latency": "Headline: controller monotonic TCP submission start to post-handler stdout completion-event receipt; separate same-host server event timestamps minus submission/admission with realtime clock drift check. Includes all remaining preload gates, delayed ordering start and cryptographic work; stdout receipt overhead included in headline. This preloaded workload is not latency-comparable to the earlier interleaved controller-report fixture",
                           "storage": "Independent in-memory replica state; no crash recovery or persistent custody",
                           "keys": "Fresh OS-random per-run private keys stored mode0600 solely as archived experiment fixtures",
                           "shutdown": "After all correct output completes, explicit quiesce freezes handlers/timers; pre-cutoff transport drains and ACKs post-cutoff discarded deliveries; pending outbound frames zero and counters stable100ms before final snapshots and graceful stop",
                           "repeats": args.repeats, "checks_skipped": args.skip_checks},
                "source_files": [], "trials": [], "commands": []}

    def command(command_args, label):
        completed = subprocess.run(command_args, cwd=ROOT, capture_output=True, text=True)
        (run / f"{label}.stdout").write_text(completed.stdout)
        (run / f"{label}.stderr").write_text(completed.stderr)
        manifest["commands"].append({"args": command_args, "label": label, "exit_code": completed.returncode})
        if completed.returncode:
            raise RuntimeError(f"{label} failed; see retained logs")
        return completed.stdout

    try:
        sources = [ROOT / item for item in ("Cargo.toml", "Cargo.lock", "README.md", "IMPLEMENTATION_PLAN.md",
                                            "scripts/run_network.py", "scripts/spec_provenance.py", "scripts/shared_core_conformance.py")]
        sources = sorted(set(sources) | {ROOT / name for name in source_inventory(ROOT)})
        sources += sorted((ROOT / "tests").glob("*network*.py"))
        for source in sources:
            data, relative = source.read_bytes(), source.relative_to(ROOT)
            dest = run / "snapshot" / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            manifest["source_files"].append({"path": str(relative), "sha256": sha(data)})
        manifest["specification"] = archive_spec(args.spec_snapshot, run / "snapshot", args.paper_repository)
        manifest["paper_head"] = manifest["specification"]["paper_head"]
        manifest["rustc"] = command(["rustc", "--version", "--verbose"], "rustc").strip()
        manifest["cargo"] = command(["cargo", "--version"], "cargo").strip()
        if not args.skip_checks:
            command(["cargo", "fmt", "--check"], "format")
            command(["cargo", "test", "--workspace", "--offline", "--locked"], "tests")
            command(["cargo", "test", "--workspace", "--offline", "--locked", "--", "--ignored", "--test-threads=1"], "socket-tests")
            command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "*network*.py"], "runner-tests")
        command(["cargo", "build", "--release", "--offline", "--locked", "--bin", "delugi-replica"], "release-build")
        binary = ROOT / "target" / "release" / "delugi-replica"
        manifest["binary_sha256"] = sha(binary.read_bytes())
        scenarios = []
        if args.scenario in ("all", "honest"):
            scenarios.append({"label": "honest-round-four", "silent": None})
        if args.scenario in ("all", "silent"):
            scenarios.append({"label": "silent-first-three-anchors", "silent": 0})
        for scenario in scenarios:
            for repeat in range(args.repeats):
                label = f"{scenario['label']}-repeat-{repeat}"
                trial = run_trial(binary, run / label, scenario, args.bound_ms, args.timeout, args.transaction_bytes,
                                  args.ordering_batch, args.round_barrier_ms, args.progress_pacing_ms, args.ordering_mode)
                manifest["trials"].append(trial)
                print(json.dumps({"trial": label, "status": trial["status"], "error": trial.get("error")}), flush=True)
                if not trial["pass"]:
                    raise RuntimeError(f"trial failed: {label}: {trial.get('error')}")
        for entry in manifest["source_files"]:
            if sha((ROOT / entry["path"]).read_bytes()) != entry["sha256"]:
                raise RuntimeError(f"source changed during measurement: {entry['path']}; rerun with stable sources")
        manifest["scenario_summary"] = []
        for scenario in scenarios:
            trials = [trial for trial in manifest["trials"] if trial["scenario"] == scenario]
            manifest["scenario_summary"].append({"scenario": scenario,
                "all_correct_completion": summary_ms([trial["latency"]["all_correct_completion_from_first_submission_us"] for trial in trials]),
                "finite_workload_transactions_per_second": [trial["latency"]["finite_workload_transactions_per_second"] for trial in trials]})
        verify_spec_unchanged(manifest["specification"])
        manifest["status"] = "passed"
    except Exception as error:
        manifest.update({"status": "failed", "error": str(error)})
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"status": manifest["status"], "manifest": str(run / "manifest.json"),
                          "trials": len(manifest["trials"]), "error": manifest.get("error")}, indent=2))
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
