#!/usr/bin/env python3
"""Independent-arrival multi-process Delugi benchmark with exact output cohorts."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import math
import os
import signal
import subprocess
import sys
import time
import uuid

from run_network import add_ordering_arguments, Child, Controller, ROOT, machine_metadata, sha, unused_addresses, queued_frames, ordering_options, written_categories, WRITTEN_CATEGORY_KEYS
from run_network import (add_shared_artifact_arguments, archive_shared_delugi_build,
                         verify_shared_delugi_build, storage_options, validate_storage_snapshots, STORAGE_PROFILES)
from network_delay import configure_from_environment, clear_from_environment
from cohort_metrics import cost_ratios, ENDPOINT
from cohort_store import collect_sharded, CohortDatabase, sha_file
import observer_receipts
from spec_provenance import add_spec_arguments, archive_spec, verify_spec_unchanged, scheduling_provenance


def tcp_counters(snapshot):
    transport = snapshot["transport"]
    peers = list(transport["peers"].values())
    return {
        "written_bytes": sum(peer["ack_bytes_written"] + sum(layer["data_bytes_written"]
                             for layer in peer["layers"].values()) for peer in peers),
        "read_bytes": transport["data_bytes_read"] + sum(peer["ack_bytes_read"] for peer in peers),
    }


def counter_delta(start, end, key):
    value = end[key] - start[key]
    if value < 0:
        raise AssertionError(f"counter decreased: {key}")
    return value


def summarize_windows(snapshots, offered_rate, transaction_size, warmup, ingress_batch_ms=10):
    rows, histogram = [], {}
    loads = [snapshot[boundary]["load"] for snapshot in snapshots.values()
             for boundary in ("measurement_start", "measurement_end")]
    admission_schema = {"admitted" in load for load in loads}
    if len(admission_schema) != 1:
        raise AssertionError("admission counter availability changed between replica windows")
    has_admission_counts = next(iter(admission_schema))
    def pending(load):
        if not has_admission_counts:
            return load["pending"] + load.get("arrival_pending", 0)
        count = load["admitted"] - load["completed"]
        if count < 0:
            raise AssertionError("eligible completions exceed admissions")
        return count
    modes = {snapshot[boundary]["load"].get("observer_mode", "full") for snapshot in snapshots.values()
             for boundary in ("measurement_start", "measurement_end")}
    if len(modes) != 1 or not modes <= {"full", "compact"}:
        raise AssertionError("observer mode changed between replica windows")
    mode = next(iter(modes))
    for replica, snapshot in sorted(snapshots.items()):
        start, end = snapshot["measurement_start"], snapshot["measurement_end"]
        duration = counter_delta(start, end, "elapsed_us") / 1_000_000
        if duration <= 0:
            raise AssertionError("measurement interval must be positive")
        load_start, load_end = start["load"], end["load"]
        completed = counter_delta(load_start, load_end, "completed")
        generated = counter_delta(load_start, load_end, "inserted")
        latency_sum = counter_delta(load_start, load_end, "latency_sum_us")
        if mode == "compact" and (latency_sum or load_start["latency_histogram_ms"] or load_end["latency_histogram_ms"]):
            raise AssertionError("compact observer cannot report detailed latency")
        for bucket in set(load_start["latency_histogram_ms"]) | set(load_end["latency_histogram_ms"]):
            count = load_end["latency_histogram_ms"].get(bucket, 0) - load_start["latency_histogram_ms"].get(bucket, 0)
            if count < 0:
                raise AssertionError("latency histogram counter decreased")
            histogram[int(bucket)] = histogram.get(int(bucket), 0) + count
        before, after = tcp_counters(start), tcp_counters(end)
        rows.append({"replica": replica, "seconds": duration, "completion_count": completed,
                     "generated_count": generated, "unique_completion_tps": completed / duration,
                     "generation_tps": generated / duration, "latency_sum_us": latency_sum,
                     "pending_at_start": pending(load_start),
                     "pending_at_end": pending(load_end),
                     "unbatched_admissions_at_start": load_start.get("arrival_pending", 0),
                     "unbatched_admissions_at_end": load_end.get("arrival_pending", 0),
                     "maximum_schedule_lag_us": load_end["maximum_schedule_lag_us"],
                     "written_bytes": counter_delta(before, after, "written_bytes"),
                     "read_bytes": counter_delta(before, after, "read_bytes"),
                     "start_unix_us": start["observed_unix_us"], "end_unix_us": end["observed_unix_us"]})
        category_start, category_end = written_categories(start), written_categories(end)
        if category_start["available"] != category_end["available"]:
            raise AssertionError("actual-written category schema changed during measurement")
        rows[-1]["written_categories"] = ({"available": True, **{key: counter_delta(category_start, category_end, key)
            for key in (*WRITTEN_CATEGORY_KEYS, "total_written_bytes")}} if category_start["available"] else category_start)
        if "process_resources" in start and "user_cpu_us" in start["process_resources"]:
            rows[-1]["process_cpu_us"] = sum(counter_delta(start["process_resources"], end["process_resources"], name)
                                                for name in ("user_cpu_us", "system_cpu_us"))
            rows[-1]["peak_rss_bytes"] = end["process_resources"]["peak_rss_bytes"]
    completed = sum(row["completion_count"] for row in rows)
    if mode == "full" and sum(histogram.values()) != completed:
        raise AssertionError("histogram must count every origin-local completion exactly once")
    duration = sum(row["seconds"] for row in rows) / len(rows)
    written = sum(row["written_bytes"] for row in rows)
    read = sum(row["read_bytes"] for row in rows)
    comparison = {"protocol": "delugi", "replicas": len(rows), "offered_tx_s": offered_rate,
                  "transaction_bytes": transaction_size, "warmup_seconds": warmup, "ingress_batch_ms": ingress_batch_ms,
                  "measurement_seconds": duration,
                  "unique_completion_tps": sum(row["unique_completion_tps"] for row in rows),
                  "mean_latency_ms": sum(row["latency_sum_us"] for row in rows) / completed / 1000 if completed and mode == "full" else None,
                  "latency_endpoint": ("admission to origin-local payload-verified contiguous append; completed-in-sampled-window population"
                                       if all("observer_mode" in load for load in loads) else
                                       "legacy completed-in-window timing; snapshot lacks explicit observer mode and does not establish the admission-to-append endpoint"),
                  "traffic_boundary": "successful_replica_tcp_stream_writes",
                  "replica_tcp_written_bytes": written, "replica_tcp_read_bytes": read,
                  "replica_tcp_written_bytes_per_second": sum(row["written_bytes"] / row["seconds"] for row in rows),
                  "completion_count": completed, "generated_count": sum(row["generated_count"] for row in rows),
                  "generation_tps": sum(row["generation_tps"] for row in rows),
                  "pending_at_start": sum(row["pending_at_start"] for row in rows),
                  "pending_at_end": sum(row["pending_at_end"] for row in rows)}
    comparison["pending_boundary"] = ("admitted requests without eligible own-origin output" if has_admission_counts
                                      else "legacy ready-pending plus arrival queue; admission count unavailable")
    comparison["written_categories"] = ({"available": True, **{key: sum(row["written_categories"][key] for row in rows)
        for key in (*WRITTEN_CATEGORY_KEYS, "total_written_bytes")}} if all(row["written_categories"]["available"] for row in rows)
        else {"available": False, "reason": "actual-written categories unavailable in legacy snapshots"})
    comparison["observer_mode"] = mode
    comparison["latency_available"] = mode == "full"
    if mode == "compact":
        comparison["latency_endpoint"] = "unavailable: compact observer retains finite membership and exact receipts without request timestamps"
        comparison["comparison_eligible"] = False
        for row in rows:
            row["latency_sum_us"] = None
            row["maximum_schedule_lag_us"] = None
    comparison["generation_target_met"] = comparison["generation_tps"] >= .95 * offered_rate
    comparison["completion_target_met"] = comparison["unique_completion_tps"] >= .95 * offered_rate
    comparison["process_cpu_seconds"] = sum(row["process_cpu_us"] for row in rows) / 1e6 if all("process_cpu_us" in row for row in rows) else None
    comparison["hottest_replica_written_bytes"] = max(row["written_bytes"] for row in rows)
    tails = {}
    for percentile in (50, 95, 99):
        target, count = math.ceil(completed * percentile / 100), 0
        tails[f"p{percentile}_upper_bound_ms"] = None
        for bucket, amount in sorted(histogram.items()):
            count += amount
            if count >= target and completed:
                tails[f"p{percentile}_upper_bound_ms"] = bucket
                break
    return {"comparison": comparison, "per_replica": rows,
            "latency_histogram_ms": histogram, "latency_quantiles": tails,
            "measurement_start_skew_us": max(r["start_unix_us"] for r in rows) - min(r["start_unix_us"] for r in rows),
            "measurement_end_skew_us": max(r["end_unix_us"] for r in rows) - min(r["end_unix_us"] for r in rows),
            "offered_load_fraction": comparison["generation_tps"] / offered_rate}


def assert_healthy(snapshots):
    for replica, snapshot in snapshots.items():
        if snapshot["rejected_protocol_messages"] or snapshot["transport"]["queue_full_failures"] or snapshot["transport"]["rejected_frames"] or snapshot["transport"].get("resource_exhaustions", 0):
            raise AssertionError(f"replica {replica}: invalid protocol frame or transport overload")


def arrivals_drained(snapshot):
    load = snapshot["load"]
    return load.get("arrival_finished", True) and load.get("arrival_pending", 0) == 0 and load["pending"] == 0


def assert_agreement(snapshots, extra_generated=0):
    generated = sum(s["load"]["inserted"] for s in snapshots.values()) + extra_generated
    hashes = {tuple(s["state_hash"]) for s in snapshots.values()}
    if len(hashes) != 1 or any(s["executed_count"] != generated or s["load"]["pending"] for s in snapshots.values()):
        raise AssertionError("replicas did not materialize all distinct generated transactions with identical output state")
    return {"unique_generated_transactions": generated, "executed_per_replica": generated,
            "state_hash": next(iter(hashes)), "replicas_agree": True}


def assert_common_prefix(replies, count, replicas=4):
    hashes = {tuple(reply["reply"]["data"]["state_hash"]) for reply in replies}
    if len(replies) != replicas or len(hashes) != 1 or any(reply["reply"]["data"]["count"] != count for reply in replies):
        raise AssertionError("replicas disagree on their common executed prefix")
    return {"common_prefix_count": count, "common_prefix_state_hash": next(iter(hashes)),
            "replicas_agree_on_common_prefix": True}


def assert_correct_prefixes(controller, snapshots, correct):
    """Verify every pair's overlapping output, including tails past a laggard."""
    counts = {replica: snapshots[replica]["executed_count"] for replica in correct}
    checks = []
    for count in sorted(set(counts.values())):
        replicas = [replica for replica in correct if counts[replica] >= count]
        if len(replicas) < 2:
            continue
        check = assert_common_prefix(controller.many(replicas, "prefix", count=count), count, len(replicas))
        checks.append({"replicas": replicas, **check})
    minimum = min(counts.values())
    if not checks or checks[0]["common_prefix_count"] != minimum:
        raise AssertionError("correct replica common prefix was not checked")
    return {**checks[0], "correct_replicas": list(correct), "all_correct_overlap_prefixes_verified": True,
            "overlap_checks": checks,
            "origin_notification_validation": "all notified prefix counts are at most the final minimum correct prefix, authenticated and compared here"}


def replica_network_ports(config):
    addresses = config["addresses"]
    if not 4 <= len(addresses) <= 31 or (len(addresses) - 1) % 3 or any(not address.startswith("127.0.0.1:") for address in addresses):
        raise ValueError("Shaping expects a supported 3f+1 loopback committee")
    ports = [int(address.rsplit(":", 1)[1]) for address in addresses]
    if len(set(ports)) != len(addresses) or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Replica TCP ports must be distinct and valid")
    return ports


def collect_ledger(controller, replica, snapshot, warmup_seconds, measurement_seconds):
    """Read bounded pages after quiescence, binding all pages to one total."""
    ledger = {"batch_ready_precedes_materialization": False, "output_index_base": 1, "output_prefix_count": snapshot["executed_count"]}
    observed = snapshot["elapsed_us"]
    for command, label in (("cohort", "requests"), ("outputs", "outputs"), ("batches", "batches")):
        entries, offset, total = [], 0, None
        while True:
            record = controller.request(replica, command, offset=offset, limit=1024)
            page = record["reply"]["data"]
            if page["replica"] != replica or (total is not None and page["total"] != total):
                raise AssertionError("ledger changed during frozen collection")
            total = page["total"]
            entries.extend(page["entries"])
            ledger["collected_us"] = max(ledger.get("collected_us", 0), page["elapsed_us"])
            if command == "cohort" and offset == 0:
                ledger["manifest"] = page.get("manifest")
            next_offset = page.get("next_offset")
            if next_offset is None:
                if len(entries) != total:
                    raise AssertionError("incomplete paginated ledger")
                break
            if next_offset != len(entries) or next_offset <= offset or next_offset > total:
                raise AssertionError("invalid ledger pagination")
            offset = next_offset
        ledger[label] = entries
    start = snapshot["load"]["start_elapsed_us"]
    ledger.update(window_start_us=start + round(warmup_seconds * 1_000_000),
                  window_end_us=start + round((warmup_seconds + measurement_seconds) * 1_000_000),
                  observed_us=observed)
    return ledger


def validate_workload_manifests(ledgers, config):
    load = config["sustained"]
    total_count = ((load["warmup_ms"] + load["measurement_ms"]) * load.get("total_rate", load["rate_per_replica"])) // 1000
    for replica, ledger in ledgers.items():
        signed = ledger.get("manifest")
        if replica not in load["origins"]:
            if signed is not None or ledger["requests"]:
                raise AssertionError("disabled ingress has a workload manifest or requests")
            continue
        rank = load["origins"].index(replica)
        count = ((total_count + len(load["origins"]) - 1 - rank) // len(load["origins"])) if "total_rate" in load else total_count
        expected = {"instance": config["instance"], "origin": replica, "rate_per_second": load["rate_per_replica"],
                    "count": count, "useful_bytes": load["useful_bytes"], "identity_version": 2,
                    "total_rate": load.get("total_rate"), "origins": load["origins"]}
        if not signed or signed["signer"] != replica or len(signed.get("signature", [])) != 64:
            raise AssertionError("missing signed finite workload manifest")
        if any(signed["body"].get(k) != v for k, v in expected.items()) or len(ledger["requests"]) != count:
            raise AssertionError("workload manifest differs from experiment configuration")
        start = signed["body"]["start_elapsed_us"]
        for sequence, row in enumerate(ledger["requests"]):
            position, rate = (sequence * len(load["origins"]) + rank + 1, load["total_rate"]) if "total_rate" in load else (sequence + 1, load["rate_per_replica"])
            scheduled = start + (position * 1_000_000 + rate - 1) // rate
            if row["sequence"] != sequence or row["scheduled_us"] != scheduled or row["useful_bytes"] != load["useful_bytes"]:
                raise AssertionError("request ledger does not match its finite manifest recipe")


def run_trial(binary, directory, total_rate, warmup_seconds, measurement_seconds,
              transaction_size=512, batch_ms=10, bound_ms=250, drain_seconds=30,
              ordering_batch=True, round_barrier_ms=None, progress_pacing_ms=None, ordering_mode=None,
              useful_bytes=None, max_batch_transactions=128, arrival_queue_capacity=65536,
              deadline_ms=1000, pause_replica=None, pause_after=0, pause_duration=0,
              cohort_accounting=True, nodes=4, resource_profile=None,
              fault_replica=None, fault_scope="payload", fault_after=0, fault_duration=0, fault_peers=None,
              measure_costs=False, deployment=None, fault_batches=0, fault_batch_transactions=64, fault_payload_bytes=472,
              cohort_observer="full", storage_profile=STORAGE_PROFILES[0]):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    if deployment is not None and storage_profile != STORAGE_PROFILES[0]:
        raise ValueError("shared disk profile acceptance is currently local only")
    if nodes not in (4, 7, 31):
        raise ValueError("validated campaign committees are 4,7,31")
    if pause_replica is not None and fault_replica is not None:
        raise ValueError("choose a process pause or a semantic omission, not both")
    faulty = pause_replica if pause_replica is not None else fault_replica
    origins = [i for i in range(nodes) if i != faulty]
    if total_rate <= 0 or warmup_seconds < 0 or measurement_seconds <= 0:
        raise ValueError("rate and duration must be positive; warmup must be nonnegative")
    if pause_replica is not None and (pause_replica not in range(nodes) or not 0 <= pause_after < measurement_seconds or pause_duration <= 0
            or pause_after + pause_duration > measurement_seconds + drain_seconds):
        raise ValueError("finite process pause must resume before the drain deadline")
    if fault_replica is not None and (fault_replica not in range(nodes) or fault_scope not in ("payload", "all")
            or fault_after < 0 or fault_duration <= 0 or fault_after >= measurement_seconds
            or (fault_peers is not None and any(i not in range(nodes) or i == fault_replica for i in fault_peers))):
        raise ValueError("invalid semantic omission experiment")
    if fault_batches and (fault_replica is None or fault_scope != "payload"):
        raise ValueError("authored fault batches require a fixed payload-omission identity")
    if not 0 <= fault_batches <= 4 or not 1 <= fault_batch_transactions <= 128 or not 0 <= fault_payload_bytes <= 4096 or 8 + fault_batch_transactions * (40 + fault_payload_bytes) > 256 * 1024:
        raise ValueError("fault workload exceeds bounded native fixture batch limits")
    if useful_bytes is None:
        useful_bytes = transaction_size - 60
    if useful_bytes <= 0 or min(max_batch_transactions, arrival_queue_capacity) <= 0 or deadline_ms <= 0 or drain_seconds < 0:
        raise ValueError("invalid useful workload, arrival bounds, or deadline")
    transaction_size = useful_bytes + 60
    keys = subprocess.run([str(binary), "--keygen", str(directory / "keys"), "--nodes", str(nodes)],
                          cwd=ROOT, text=True, capture_output=True, check=True)
    keys = json.loads(keys.stdout)
    addresses = unused_addresses(nodes * 2)
    config = {"instance": list(os.urandom(32)), "addresses": addresses[:nodes], "control_addresses": addresses[nodes:],
              "control_token": os.urandom(32).hex(), **keys, "bound_ms": bound_ms,
              "chunk_capacity": 64, "workload_rounds": 4, "silent": None,
              "max_runtime_ms": int((warmup_seconds + measurement_seconds + drain_seconds + 25) * 1000),
              "sustained": {"rate_per_replica": math.ceil(total_rate / len(origins)), "total_rate": total_rate,
                            "transaction_bytes": transaction_size,
                            "useful_bytes": useful_bytes, "origins": origins,
                            "max_batch_transactions": max_batch_transactions,
                            "arrival_queue_capacity": arrival_queue_capacity,
                            "batch_ms": batch_ms, "warmup_ms": round(warmup_seconds * 1000),
                            "measurement_ms": round(measurement_seconds * 1000)},
              **ordering_options(bound_ms, ordering_batch, round_barrier_ms, progress_pacing_ms, ordering_mode)}
    config["measure_costs"] = measure_costs
    config.update(storage_options(directory, storage_profile))
    if cohort_observer not in ("full", "compact"):
        raise ValueError("cohort observer must be full or compact")
    config["observer_mode"] = cohort_observer
    if resource_profile is not None or nodes > 7:
        config["resource_profile"] = resource_profile or "complete-32mib-n31-v1"
    if fault_replica is not None:
        config["fault"] = {"replica": fault_replica, "scope": fault_scope,
                           "start_after_load_ms": round((warmup_seconds + fault_after) * 1000),
                           "duration_ms": round(fault_duration * 1000)}
        if fault_peers is not None:
            config["fault"]["peers"] = fault_peers
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    children, controller, shaping, paused = [], None, None, None
    fault_submissions = []
    result = {"status": "failed", "config": str(config_path), "settings": config["sustained"],
              "protocol_bound_ms": bound_ms, "children": [],
              "ordering_options": {k: config[k] for k in ("ordering_batch", "ordering_mode", "round_barrier_ms", "progress_pacing_ms") if k in config}}
    result["scheduling"] = scheduling_provenance(config)
    result["fault"] = {"kind": "finite_process_pause_all_traffic" if pause_replica is not None else "none",
                       "replica": pause_replica, "correct_origins": origins,
                       "after_measurement_start_seconds": pause_after, "duration_seconds": pause_duration,
                       "events": []}
    result["deadline_ms"] = deadline_ms
    if fault_replica is not None:
        result["fault"] = {"kind": "semantic_outgoing_omission", **config["fault"], "correct_origins": origins}
        result["fault"]["authored_workload"] = {"batches": fault_batches,
            "transactions_per_batch": fault_batch_transactions, "transaction_payload_bytes": fault_payload_bytes,
            "identity_recipe": "SHA256(bincode(fixture-transaction,producer:u32,height:u64,index:u64))",
            "content_recipe": "byte[j]=(producer+height+index+j) mod 256",
            "useful_credit": "excluded from authenticated honest-origin workload; exact batch bytes and actual network costs remain charged",
            "submissions": fault_submissions}
    try:
        helper_source = (ROOT / "scripts/network_delay.py").read_bytes()
        (directory / "network_delay.py").write_bytes(helper_source)
        result["network_shaping_helper_sha256"] = sha(helper_source)
        policy_source = (ROOT / "scripts/timing_calibration.py").read_bytes()
        (directory / "timing_calibration.py").write_bytes(policy_source)
        result["network_timing_policy_sha256"] = sha(policy_source)
        controller_config = config
        if deployment is not None:
            controller_config = deployment.prepare(config, directory)
            config_path.write_text(json.dumps(config, indent=2) + "\n")
            result["deployment"] = deployment.provenance()
            shaping = deployment.configure_network()
        for i in range(nodes):
            children.append(Child(binary, config_path, i, directory) if deployment is None else deployment.child(i, directory))
        controller = Controller(controller_config, directory, children, streaming=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            controller.check()
            if all(any(event.get("event") == "ready" for event in child.events) for child in children):
                break
            time.sleep(.01)
        else:
            raise TimeoutError("replicas did not become ready")
        ports = replica_network_ports(config) if deployment is None else [int(a.rsplit(":", 1)[1]) for a in config["addresses"]]
        result["replica_network_ports"] = ports
        if deployment is None:
            shaping = configure_from_environment("delugi", ports)
        result["network_shaping"] = shaping
        controller.many(list(range(nodes)), "start")
        start_unix_us = time.time_ns() // 1000 + 1_000_000
        controller.many(list(range(nodes)), "load", start_unix_us=start_unix_us)
        load_start = time.monotonic() + (start_unix_us - time.time_ns() // 1000) / 1e6
        final_deadline = load_start + warmup_seconds + measurement_seconds + drain_seconds
        pause_start = load_start + warmup_seconds + pause_after
        pause_done = pause_replica is None
        def advance_fault():
            nonlocal paused, pause_done
            now = time.monotonic()
            if fault_batches and not fault_submissions and now >= load_start + warmup_seconds + fault_after:
                for height in range(1, fault_batches + 1):
                    record = controller.request(fault_replica, "submit", round=height,
                                                count=fault_batch_transactions, size=fault_payload_bytes)
                    fault_submissions.append(record)
            if not pause_done and paused is None and now >= pause_start:
                children[pause_replica].process.send_signal(signal.SIGSTOP)
                paused = pause_replica
                result["fault"]["events"].append({"action": "pause", "controller_monotonic_ns": time.monotonic_ns()})
            if paused is not None and now >= pause_start + pause_duration:
                children[paused].process.send_signal(signal.SIGCONT)
                result["fault"]["events"].append({"action": "resume", "controller_monotonic_ns": time.monotonic_ns()})
                paused, pause_done = None, True
        def snapshots_now():
            advance_fault()
            if paused is None:
                current = controller.snapshots()
            else:
                records = controller.many([i for i in range(nodes) if i != paused], "snapshot")
                current = {r["replica"]: r["reply"]["data"] for r in records}
            if cohort_accounting and cohort_observer == "full" and all(i in current for i in origins):
                count = min(current[i]["executed_count"] for i in origins)
                controller.many(origins, "observe_prefix", count=count)
            return current
        deadline = time.monotonic() + warmup_seconds + measurement_seconds + 10
        while time.monotonic() < deadline:
            controller.check()
            snapshots = snapshots_now()
            assert_healthy(snapshots)
            if all(i in snapshots and snapshots[i]["measurement_end"] is not None for i in origins):
                break
            time.sleep(.5)
        else:
            raise TimeoutError("replicas did not finish their measurement windows")
        result.update(summarize_windows({i: snapshots[i] for i in origins}, total_rate, transaction_size, warmup_seconds, batch_ms))
        # Traffic always covers the whole committee, including the fixed faulty
        # identity. After a pause its window counters are diagnostic only; the
        # precise completed cohort and total-run costs are retained separately.
        if len(snapshots) == nodes and all(s["measurement_end"] is not None for s in snapshots.values()):
            whole = summarize_windows(snapshots, total_rate, transaction_size, warmup_seconds, batch_ms)
            for key in ("replica_tcp_written_bytes", "replica_tcp_read_bytes", "replica_tcp_written_bytes_per_second", "written_categories"):
                result["comparison"][key] = whole["comparison"][key]
        else:
            result["comparison"]["traffic_window_includes_paused_replica"] = False
        result["comparison"]["replicas"] = nodes
        result["comparison"]["protocol_bound_ms"] = bound_ms
        drain_started = time.monotonic()
        deadline = final_deadline
        while time.monotonic() < deadline:
            controller.check()
            snapshots = snapshots_now()
            assert_healthy(snapshots)
            generated = sum(s["load"]["inserted"] for s in snapshots.values()) + sum(len(r["reply"]["data"]["transactions"]) for r in fault_submissions)
            if pause_done and len(snapshots) == nodes and all(s["executed_count"] == generated and arrivals_drained(s) for s in snapshots.values()):
                break
            time.sleep(.1)
        result["drain_seconds"] = time.monotonic() - drain_started
        advance_fault()
        result["collection_deadline_controller_monotonic_ns"] = round(final_deadline * 1e9)
        quiescence = controller.many(list(range(nodes)), "quiesce")
        frozen_at = {r["replica"]: r["reply"]["data"].get("elapsed_us") for r in quiescence if "replica" in r}
        deadline, previous, stable_at = time.monotonic() + 10, None, None
        while time.monotonic() < deadline:
            snapshots = controller.snapshots()
            signature = [tcp_counters(s) for s in snapshots.values()]
            if all(queued_frames(s) == 0 for s in snapshots.values()) and signature == previous:
                if stable_at is None:
                    stable_at = time.monotonic()
                if time.monotonic() - stable_at >= .1:
                    break
            else:
                stable_at = None
            previous = signature
            time.sleep(.05)
        else:
            raise TimeoutError("transport did not drain after quiescence")
        assert_healthy(snapshots)
        result["storage"] = validate_storage_snapshots(snapshots, storage_profile)
        if pause_replica is not None:
            whole = summarize_windows(snapshots, total_rate, transaction_size, warmup_seconds, batch_ms)
            for key in ("replica_tcp_written_bytes", "replica_tcp_read_bytes", "replica_tcp_written_bytes_per_second", "written_categories"):
                result["comparison"][key] = whole["comparison"][key]
            result["comparison"]["traffic_window_includes_paused_replica"] = True
            result["comparison"]["traffic_window_note"] = "faulty replica boundaries can be delayed by process suspension; total-run absolute costs are authoritative"
        generated = sum(s["load"]["inserted"] for s in snapshots.values()) + sum(len(r["reply"]["data"]["transactions"]) for r in fault_submissions)
        result["drain_complete"] = all(s["executed_count"] == generated and arrivals_drained(s) for s in snapshots.values())
        if any(s["executed_count"] > generated for s in snapshots.values()):
            raise AssertionError("replica executed more transactions than were generated")
        result["agreement"] = assert_correct_prefixes(controller, snapshots, origins)
        minimum_output = min(s["executed_count"] for s in snapshots.values())
        try:
            result["agreement"]["all_replica_minimum_diagnostic"] = assert_common_prefix(
                controller.many(list(range(nodes)), "prefix", count=minimum_output), minimum_output, nodes)
        except AssertionError as error:
            result["agreement"]["all_replica_minimum_diagnostic"] = {"common_prefix_count": minimum_output,
                "replicas_agree_on_common_prefix": False, "error": str(error),
                "boundary": "faulty replica output is diagnostic; correct overlap prefixes are the correctness gate"}
        result["agreement"]["executed_counts"] = {i:s["executed_count"] for i,s in snapshots.items()}
        result["agreement"]["unique_generated_transactions"] = generated
        if result["drain_complete"]:
            result["agreement"].update(assert_agreement(snapshots, sum(len(r["reply"]["data"]["transactions"]) for r in fault_submissions)))
        result["global_pending_by_replica"] = {i:generated-s["executed_count"] for i,s in snapshots.items()}
        final_traffic = [tcp_counters(s) for s in snapshots.values()]
        if sum(t["written_bytes"] for t in final_traffic) != sum(t["read_bytes"] for t in final_traffic):
            raise AssertionError("drained TCP reads and writes differ")
        result["final_tcp"] = final_traffic
        result["final_backlog"] = [s["load"]["pending"] for s in snapshots.values()]
        result["observer_window_metrics"] = dict(result["comparison"])
        # Both observer modes authenticate the same bounded finite receipts.
        if cohort_accounting or cohort_observer == "compact":
            receipt_archive, receipt_index = observer_receipts.collect(controller, snapshots, directory / "receipts", origins, observer_receipts.configured_counts(config), cohort_observer)
            receipt_verification = subprocess.run([str(binary), "--config", str(config_path), "--verify-workload-archive", receipt_archive["path"]],
                cwd=ROOT, capture_output=True, text=True)
            (directory / "receipt-verification.stdout").write_text(receipt_verification.stdout)
            (directory / "receipt-verification.stderr").write_text(receipt_verification.stderr)
            if receipt_verification.returncode:
                raise AssertionError(f"authenticated receipt verification failed: {receipt_verification.stderr.strip()}")
            verified_receipts = json.loads(receipt_verification.stdout)
            if verified_receipts.get("verified") is not True or verified_receipts.get("index_sha256") != receipt_archive["sha256"]:
                raise AssertionError("verified receipt archive differs from collected index")
            result["observer_receipt_archive"] = receipt_archive
            result["observer_receipt_authentication"] = verified_receipts
            result["observer_receipt"] = observer_receipts.summarize(receipt_index, directory / "receipts", origins)
            denominator = result["observer_receipt"]
            total_written = sum(t["written_bytes"] for t in final_traffic)
            result["observer_finite_cost"] = {"written_bytes": total_written,
                "reference_replica": denominator["reference_replica"],
                "exact_m_out_bytes": denominator["reference_m_out_bytes"],
                "unique_eligible_u_out_bytes": denominator["reference_unique_eligible_u_out_bytes"],
                "written_bytes_per_m_out_byte": total_written / denominator["reference_m_out_bytes"] if denominator["reference_m_out_bytes"] else None,
                "written_bytes_per_u_out_byte": total_written / denominator["reference_unique_eligible_u_out_bytes"] if denominator["reference_unique_eligible_u_out_bytes"] else None,
                "boundary": "whole committee actual TCP writes through quiescence and transport drain; one declared output prefix; honest event-latched origin eligibility; receipt control bytes excluded"}
        result["cohort_observer"] = cohort_observer
        result["observer_cost_boundary"] = "detailed observer above common finite bitmaps and exact receipts; post-freeze receipt signing, queries and verification excluded from measured protocol interval"
        if cohort_accounting and cohort_observer == "full":
            archive = collect_sharded(controller, snapshots, directory / "cohorts", warmup_seconds,
                                      measurement_seconds, frozen_at=frozen_at)
            result["cohort_ledger"] = {"path": str(archive.path), "sha256": archive.index_sha256,
                                      "schema": 2, "resource_contract": archive.index["resource_contract"]}
            verification = subprocess.run([str(binary), "--config", str(config_path), "--verify-workload-archive", str(archive.path)],
                                          cwd=ROOT, capture_output=True, text=True)
            (directory / "cohort-verification.stdout").write_text(verification.stdout)
            (directory / "cohort-verification.stderr").write_text(verification.stderr)
            if verification.returncode:
                raise AssertionError(f"authenticated cohort verification failed: {verification.stderr.strip()}")
            result["cohort_authentication"] = json.loads(verification.stdout)
            if result["cohort_authentication"].get("verified") is not True or result["cohort_authentication"].get("index_sha256") != archive.index_sha256:
                raise AssertionError("authenticated archive index differs from collected/reduced index")
            database = CohortDatabase(directory / "cohort.sqlite", archive.ledgers)
            try:
                database.ingest(archive.rows)
                result["cohort"] = database.summarize(correct_replicas=origins, deadline_ms=deadline_ms)
                completed_mean_ms = database.completed_mean_ms
                result["cohort_output_exclusions"] = database.output_exclusions
            finally:
                database.close()
            result["cohort_database"] = {"path": str(database.path), "sha256": sha_file(database.path),
                "bytes": database.path.stat().st_size, "cache_bytes": 16 * 1024 * 1024,
                "temporary_sorting": "file-backed", "quantiles": "exact nearest-rank SQL; censored cohort retained"}
            result["cost"] = cost_ratios(result["comparison"]["replica_tcp_written_bytes"], result["cohort"])
            result["total_run_tcp_written_bytes"] = sum(t["written_bytes"] for t in final_traffic)
            result["finite_run_cost"] = cost_ratios(result["total_run_tcp_written_bytes"], result["cohort"], boundary="finite_run")
            final_categories = [written_categories(snapshot) for snapshot in snapshots.values()]
            result["finite_run_written_categories"] = ({"available": True, **{key: sum(row[key] for row in final_categories)
                for key in (*WRITTEN_CATEGORY_KEYS, "total_written_bytes")}} if all(row["available"] for row in final_categories)
                else {"available": False, "reason": "actual-written categories unavailable in legacy snapshots"})
            if result["comparison"]["written_categories"]["available"]:
                result["cost_by_written_category"] = {key: cost_ratios(result["comparison"]["written_categories"][key], result["cohort"])
                    for key in WRITTEN_CATEGORY_KEYS}
            if result["finite_run_written_categories"]["available"]:
                result["finite_run_cost_by_written_category"] = {key: cost_ratios(result["finite_run_written_categories"][key], result["cohort"], boundary="finite_run")
                    for key in WRITTEN_CATEGORY_KEYS}
            result["legacy_completed_window_diagnostics"] = dict(result["comparison"])
            window = result["cohort"]["window"]
            result["comparison"].update(window)
            result["comparison"].update(endpoint_contract=ENDPOINT, accounting_schema=1,
                useful_transaction_bytes=useful_bytes, transaction_bytes=transaction_size,
                latency_endpoint="admission to origin-local payload-verified contiguous output; intended-arrival cohort with censoring",
                cohort=result["cohort"], mean_latency_ms=None,
                deadline_ms=deadline_ms, cost=result["cost"],
                correct_replicas=origins, scheduled_count=result["cohort"]["scheduled"])
            result["comparison"]["generated_count"] = window["admission_count"]
            result["comparison"]["generation_tps"] = window["admission_tps"]
            result["comparison"]["generation_target_met"] = window["admission_tps"] >= .95 * total_rate
            result["comparison"]["completion_target_met"] = window["unique_completion_tps"] >= .95 * total_rate
            result["comparison"]["mean_latency_ms"] = completed_mean_ms
            result["comparison"]["mean_latency_population"] = "completed members of intended-arrival cohort; quantiles retain unfinished"
        if cohort_observer == "compact":
            result["comparison_eligible"] = False
            result["comparison"].update(comparison_eligible=False, latency_available=False,
                mean_latency_ms=None, cohort=None, endpoint_contract=None,
                useful_transaction_bytes=useful_bytes,
                compact_receipt=result["observer_receipt"],
                population="sampled own-origin eligible completions; finite all-correct membership separately retained")
            result["latency_quantiles"] = None
            result["latency_histogram_ms"] = None
            if any(any(value for value in snapshot.get("detailed_observer_storage", {}).values()) for snapshot in snapshots.values()):
                raise AssertionError("compact mode retained detailed observer storage")
        result["fault_accounting"] = {i: s.get("fault_omitted", {}) for i, s in snapshots.items()}
        if fault_replica is not None:
            omitted = sum(row["messages"] for rows in result["fault_accounting"].values() for row in rows.values())
            result["fault"]["omitted_messages"] = omitted
            result["fault"]["efficacy"] = "effective_logical_omission" if omitted else "no_op_fault_smoke"
            result["fault"]["authored_transaction_count"] = sum(len(r["reply"]["data"]["transactions"]) for r in fault_submissions)
            result["fault"]["honest_ingress_transaction_count"] = sum(s["load"]["inserted"] for s in snapshots.values())
        result["construction_accounting"] = {i: {"construction": s.get("construction", {}),
            "empty_inputs_with_pending_local_requests": s.get("empty_inputs_with_pending_local_requests", 0),
            "pending_materialization": s.get("pending_materialization", 0)} for i, s in snapshots.items()}
        result["resource_observer_enabled"] = measure_costs
        result["resources"] = {i: {"process": s.get("process_resources", {}),
                                   "operation_costs": s.get("operation_costs", {}),
                                   "retained_state": s.get("retained_state", {})} for i, s in snapshots.items()}
        result["hottest_replica_total_written_bytes"] = max(t["written_bytes"] for t in final_traffic)
        controller.many(list(range(nodes)), "stop")
        for child in children:
            child.process.wait(timeout=5)
        result["generation_target_met"] = result["comparison"]["generation_target_met"]
        result["completion_target_met"] = result["comparison"]["completion_target_met"]
        result["comparison"]["drain_complete"] = result["drain_complete"]
        result["status"] = "passed"
    except Exception as error:
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        cleanup_errors = []
        if paused is not None:
            try:
                children[paused].process.send_signal(signal.SIGCONT)
            except Exception as error:
                cleanup_errors.append(f"resume paused child: {error}")
        if controller:
            try:
                controller.save()
            except Exception as error:
                cleanup_errors.append(f"controller save: {type(error).__name__}: {error}")
        for child in children:
            try:
                result["children"].append(child.finish())
            except Exception as error:
                cleanup_errors.append(f"child cleanup: {type(error).__name__}: {error}")
        if shaping is not None:
            try:
                result["network_shaping_cleanup"] = clear_from_environment() if deployment is None else deployment.clear_network()
            except Exception as error:
                result["network_shaping_cleanup_error"] = f"{type(error).__name__}: {error}"
                cleanup_errors.append(f"network shaping cleanup: {type(error).__name__}: {error}")
        if deployment is not None:
            try:
                result["deployment"] = deployment.provenance()
                result["deployment_cleanup"] = deployment.close()
            except Exception as error:
                cleanup_errors.append(f"remote deployment cleanup: {error}")
        if cleanup_errors:
            result["status"] = "failed"
            result["cleanup_errors"] = cleanup_errors
            result["error"] = "; ".join(filter(None, [result.get("error"), *cleanup_errors]))
        if result["status"] == "passed" and any(c["exit_code"] != 0 or c["telemetry_errors"] for c in result["children"]):
            result["status"], result["error"] = "failed", "replica exit or telemetry failure"
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def build_inputs(compiler):
    # Include extracted crate manifests and sources; root/src alone can no longer
    # authenticate the executable after the shared-services workspace extraction.
    from shared_core_conformance import source_inventory
    return {"compiler": compiler, "sources": source_inventory(ROOT, include_workspace=False)}


def verify_build_stamp(binary, compiler):
    stamp_path = Path(str(binary) + ".build.json")
    stamp = json.loads(stamp_path.read_text())
    if stamp.get("inputs") != build_inputs(compiler) or stamp.get("binary_sha256") != sha(binary.read_bytes()):
        raise RuntimeError("release build stamp does not match current source, compiler and binary; rebuild without --skip-build")
    return stamp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--nodes", type=int, choices=(4, 7, 31), default=4)
    parser.add_argument("--inventory", type=Path, help="explicit existing-host SSH inventory; no cloud provisioning")
    parser.add_argument("--resource-profile", choices=("legacy-1mib-v1", "complete-32mib-n31-v1"))
    parser.add_argument("--cohort-observer", choices=("full", "compact"), default="full", help="detailed timing or compact finite receipts; compact has no request latency metrics")
    parser.add_argument("--measure-costs", action="store_true", help="enable optional crypto/proof resource counters; use paired runs to quantify observer overhead")
    parser.add_argument("--transaction-size", type=int, help="legacy actual encoded transaction size; includes 60 bytes of ID, workload identity and encoding")
    parser.add_argument("--useful-bytes", type=int, help="useful application bytes per request (default472); independent of native encoding")
    parser.add_argument("--warmup", type=float, default=10)
    parser.add_argument("--duration", type=float, default=30)
    parser.add_argument("--batch-ms", "--ingress-batch-ms", dest="batch_ms", type=int, default=10)
    parser.add_argument("--bound-ms", type=int, default=250)
    parser.add_argument("--max-batch-transactions", type=int, default=128)
    parser.add_argument("--arrival-queue-capacity", type=int, default=65536)
    parser.add_argument("--drain", type=float, default=30)
    parser.add_argument("--deadline-ms", type=float, default=1000)
    parser.add_argument("--pause-replica", type=int)
    parser.add_argument("--pause-after", type=float, default=0, help="seconds after measurement begins")
    parser.add_argument("--pause-duration", type=float, default=0)
    parser.add_argument("--fault-replica", type=int)
    parser.add_argument("--fault-scope", choices=("payload", "all"), default="payload")
    parser.add_argument("--fault-after", type=float, default=0)
    parser.add_argument("--fault-duration", type=float, default=0)
    parser.add_argument("--fault-peers", type=int, nargs="+")
    parser.add_argument("--fault-batches", type=int, default=0, help="bounded authored batches by fixed faulty origin; excluded from honest useful output")
    parser.add_argument("--fault-batch-transactions", type=int, default=64)
    parser.add_argument("--fault-payload-bytes", type=int, default=472)
    add_ordering_arguments(parser)
    add_spec_arguments(parser)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/delugi-replica")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--build-only", action="store_true", help="compile, stamp and archive without launching a trial")
    add_shared_artifact_arguments(parser)
    args = parser.parse_args()
    if args.shared_build_receipt and (not args.skip_build or args.build_only or args.inventory):
        parser.error("shared build receipt requires --skip-build, a local trial and no --build-only")
    if args.storage_profile != STORAGE_PROFILES[0] and not args.shared_build_receipt:
        parser.error("disk profile requires an explicit shared build receipt with compiled backend")
    useful_bytes = args.useful_bytes if args.useful_bytes is not None else (args.transaction_size - 60 if args.transaction_size is not None else 472)
    transaction_size = useful_bytes + 60
    output = (args.output or ROOT / "results/local" / ("sustained-" + uuid.uuid4().hex)).resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 2, "status": "incomplete", "protocol": "delugi", "replicas": args.nodes,
                "started_utc": datetime.now(timezone.utc).isoformat(), "machine": machine_metadata(),
                "method": {"workload": "independent open-loop ingress threads; finite signed workload manifests bind identities; actual transaction encoding is useful bytes+60 (32-byte ID,8-byte vector length,20-byte authenticated request metadata)",
                           "load": "intended arrival schedule is independent of protocol progress; bounded ingress rejection and batching are separately accounted; no completed-only cohort omission",
                           "completion": "exact payload-verified contiguous output; per-origin monotonic scheduled/admitted/batch-ready/materialized clocks; exact identity dedup excludes replicated and replayed useful credit",
                           "windows": "replicas capture their own counter boundaries on the protocol thread around a shared future start; actual interval and inter-replica skew retained",
                           "latency_quantiles": "exact observed microseconds; unfinished cohort members retained as right-censored ages; undefined quantiles and bounds remain visible",
                           "traffic": "successful authenticated replica TCP stream writes including data framing, signatures and ACKs; separate reads; excludes client/control traffic, TCP/IP headers and kernel retransmissions",
                           "storage": "independent in-memory custody/order/output; all protocol signatures and validation enabled; no durability",
                           "trace": "bounded paginated exact request/output/batch ledgers retained with source and binary provenance",
                           "shutdown": "stop arrivals after finite schedule, allow declared drain, quiesce, verify exact common prefix, collect frozen ledgers and stop; incomplete and zero-output trials remain accounted outcomes"},
                "source_files": []}
    manifest["cohort_observer"] = args.cohort_observer
    manifest["storage_profile"] = args.storage_profile
    if args.storage_profile == STORAGE_PROFILES[1]:
        manifest["method"]["storage"] = "fresh shared RocksDB Written record mirror before process-local Visible custody; typed memory cache retained; no core crash recovery; WAL enabled sync=false"
    if args.cohort_observer == "compact":
        manifest["comparison_eligible"] = False
        manifest["method"]["latency_quantiles"] = "unavailable: detailed request timestamps disabled; finite membership and exact output/batch receipts retained"
        manifest["method"]["trace"] = "bounded signed finite receipt headers and membership bitmap pages; no request/output timestamp ledger"
    manifest["method"]["observer_cost_boundary"] = "common receipt baseline in both modes; receipt signing and collection occur after frozen measured endpoint"
    shared_validation = None
    try:
        manifest["specification"] = archive_spec(args.spec_snapshot, output / "snapshot", args.paper_repository)
        sources = [ROOT / p for p in ("Cargo.toml", "Cargo.lock", "scripts/run_sustained.py", "scripts/run_network.py", "scripts/network_delay.py", "scripts/timing_calibration.py", "scripts/cohort_metrics.py", "scripts/cohort_store.py", "scripts/observer_receipts.py", "scripts/spec_provenance.py", "scripts/remote_deployment.py", "scripts/remote_worker.py", "scripts/linux_netem.py", "tests/sustained_runner_test.py", "tests/cohort_metrics_test.py", "tests/cohort_store_test.py", "tests/shared_delugi_artifact_test.py")]
        from shared_core_conformance import source_inventory
        sources += [ROOT / "scripts/shared_core_conformance.py"]
        sources = sorted(set(sources) | {ROOT / name for name in source_inventory(ROOT)})
        for source in sources:
            relative, data = source.relative_to(ROOT), source.read_bytes()
            destination = output / "snapshot" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            manifest["source_files"].append({"path": str(relative), "sha256": sha(data)})
        commands = [(["git", "rev-parse", "HEAD"], "git_head"),
                    (["git", "status", "--porcelain"], "git_status")]
        if not args.shared_build_receipt:
            commands.insert(0, (["rustc", "--version", "--verbose"], "rustc"))
        for command, label in commands:
            process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
            manifest[label] = process.stdout.strip()
        if not args.skip_build:
            if args.binary.resolve() != (ROOT / "target/release/delugi-replica").resolve():
                raise ValueError("custom --binary requires --skip-build and a matching build stamp")
            inputs = build_inputs(manifest["rustc"])
            build = subprocess.run(["cargo", "build", "--release", "--offline", "--locked", "--bin", "delugi-replica"], cwd=ROOT, capture_output=True, text=True)
            (output / "build.stdout").write_text(build.stdout)
            (output / "build.stderr").write_text(build.stderr)
            if build.returncode:
                raise RuntimeError("release build failed")
            if inputs != build_inputs(manifest["rustc"]):
                raise RuntimeError("protocol source changed during release build")
            stamp = {"inputs": inputs, "binary_sha256": sha(args.binary.read_bytes()),
                     "built_utc": datetime.now(timezone.utc).isoformat()}
            Path(str(args.binary) + ".build.json").write_text(json.dumps(stamp, indent=2) + "\n")
        if args.shared_build_receipt:
            shared_validation = archive_shared_delugi_build(args.binary, args.shared_build_receipt,
                output / "shared-build", args.storage_profile)
            manifest["shared_build"] = shared_validation
            manifest["binary_sha256"] = shared_validation["binary"]["sha256"]
        else:
            manifest["build_stamp"] = verify_build_stamp(args.binary, manifest["rustc"])
            manifest["binary_sha256"] = sha(args.binary.read_bytes())
        if args.build_only:
            manifest["status"] = "built"
        else:
            deployment = None
            if args.inventory:
                from remote_deployment import RemoteDeployment
                deployment = RemoteDeployment(json.loads(args.inventory.read_text()))
            result = run_trial(args.binary.resolve(), output / "trial", args.rate, args.warmup,
                               args.duration, transaction_size, args.batch_ms, args.bound_ms, args.drain,
                               ordering_batch=args.ordering_batch, round_barrier_ms=args.round_barrier_ms,
                               progress_pacing_ms=args.progress_pacing_ms, ordering_mode=args.ordering_mode,
                               useful_bytes=useful_bytes, max_batch_transactions=args.max_batch_transactions,
                               arrival_queue_capacity=args.arrival_queue_capacity, deadline_ms=args.deadline_ms,
                               pause_replica=args.pause_replica, pause_after=args.pause_after, pause_duration=args.pause_duration,
                               nodes=args.nodes, resource_profile=args.resource_profile,
                               fault_replica=args.fault_replica, fault_scope=args.fault_scope,
                               fault_after=args.fault_after, fault_duration=args.fault_duration, fault_peers=args.fault_peers,
                               measure_costs=args.measure_costs, deployment=deployment, cohort_observer=args.cohort_observer,
                               fault_batches=args.fault_batches, fault_batch_transactions=args.fault_batch_transactions,
                               fault_payload_bytes=args.fault_payload_bytes, storage_profile=args.storage_profile)
            manifest["trial"] = result
            manifest["status"] = result["status"]
            for key in ("network_shaping", "network_shaping_cleanup", "network_shaping_cleanup_error",
                        "network_shaping_helper_sha256", "replica_network_ports", "protocol_bound_ms"):
                if key in result:
                    manifest[key] = result[key]
            if "comparison" in result:
                manifest["comparison"] = result["comparison"]
            if "error" in result:
                manifest["error"] = result["error"]
        verify_spec_unchanged(manifest["specification"])
        for source in manifest["source_files"]:
            if sha((ROOT / source["path"]).read_bytes()) != source["sha256"]:
                raise RuntimeError(f"benchmark source changed during run: {source['path']}")
    except Exception as error:
        manifest["status"], manifest["error"] = "failed", f"{type(error).__name__}: {error}"
    finally:
        if shared_validation is not None:
            try:
                _, checked = verify_shared_delugi_build(args.binary, args.shared_build_receipt, args.storage_profile)
                if checked["receipt_sha256"] != shared_validation["receipt_sha256"]:
                    raise ValueError("shared build receipt changed during trial")
                manifest["shared_build_after"] = checked
            except Exception as error:
                manifest["status"], manifest["error"] = "failed", f"shared artifact post-run verification: {error}"
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(output / "manifest.json"), "status": manifest["status"], "comparison": manifest.get("comparison"), "error": manifest.get("error")}), flush=True)
    return 0 if manifest["status"] in ("passed", "built") else 1


if __name__ == "__main__":
    sys.exit(main())
