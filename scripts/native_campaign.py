#!/usr/bin/env python3
"""Fixed native remote placement adapter for the common campaign contract.

Run only against an explicit published artifact inventory. This normalizes
measurements; it never upgrades source/mock acceptance to formal eligibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys

import cohort_metrics
import deployment_prepare as prep
import remote_native
from run_comparison import TRAFFIC_BOUNDARY, finite

PROTOCOLS = ("mysticeti", "autobahn", "shoal")
FAULTS = ("none", "process_pause", "payload_omission", "tcp_packet_loss")
CONTROLLER_FILES = ("scripts/native_campaign.py", "scripts/run_campaign.py", "scripts/campaign_frontier.py", "scripts/campaign_resources.py", "scripts/run_comparison.py", "scripts/timing_calibration.py")


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def build_plan(value, cfg):
    selected = remote_native.plan(value["native_publication"], cfg)
    selected["campaign_adapter_sources"] = {name: prep.sha(prep.ROOT / name) for name in CONTROLLER_FILES}
    return selected


def inventory(publication, protocol, nodes, publication_sha256):
    if protocol not in PROTOCOLS or publication.get("protocol") != protocol:
        raise ValueError("native campaign requires the matching publication receipt")
    hosts = publication["inventory"]["hosts"]
    prep.validate_hosts({"schema": 1, "hosts": hosts})
    if len(hosts) != nodes:
        raise ValueError("native publication committee differs from campaign")
    receipts = publication["receipts"]
    if set(map(str, receipts)) != {str(i) for i in range(nodes)}:
        raise ValueError("native publication receipt population differs")
    roles = prep.recipe(protocol)["binaries"]
    for host in hosts:
        remote_native.interpreter(host)
        receipt = receipts.get(str(host["replica"]), receipts.get(host["replica"]))
        prep.validate_receipt(receipt, receipt["recipe"], receipt["source_bundle_sha256"])
        if receipt["protocol"] != protocol or receipt["recipe"]["binaries"] != roles:
            raise ValueError("native publication roles differ")
    if len({row["source_bundle_sha256"] for row in receipts.values()}) != 1:
        raise ValueError("native publication mixes source bundles")
    if len({canonical_hash(row["recipe"]) for row in receipts.values()}) != 1:
        raise ValueError("native publication mixes build recipes")
    return {"schema": 1, "protocol": protocol, "hosts": hosts, "native_publication": publication,
            "publication_sha256": publication_sha256, "publication_receipts_sha256": canonical_hash(receipts)}


def validate_inventory(value, protocol, nodes):
    checked = inventory(value["native_publication"], protocol, nodes, value["publication_sha256"])
    if any(value.get(key) != item for key, item in checked.items()):
        raise ValueError("native inventory was changed outside its publication")
    return checked


def role_artifacts(value):
    return {str(host["replica"]): {row["name"]: row["sha256"] for row in
            value["native_publication"]["receipts"][str(host["replica"])]["binaries"]} for host in value["hosts"]}


def measured_roles(data, value):
    expected = role_artifacts(value)
    actual = {str(i): {role: row["sha256"] for role, row in machine["artifacts"].items()}
              for i, machine in data["deployment"]["machines"].items()}
    if actual != expected:
        raise ValueError("measured native role artifacts differ from publication")
    if data.get("publication_receipts_sha256") != value["publication_receipts_sha256"]:
        raise ValueError("native measured publication receipt hashes differ")
    return actual


def integer(value, name):
    finite(value, name)
    if value != int(value):
        raise ValueError(name + " must be an integer counter")
    return int(value)


def traffic(protocol, hosts, cfg):
    rows = {}
    for i, host in hosts.items():
        result = host["result"]; sample = result["traffic"]
        epoch = integer(result["epoch_monotonic_ns"], "host epoch")
        target_start = epoch + round(cfg["warmup"] * 1e9)
        target_end = target_start + round(cfg["duration"] * 1e9)
        if protocol == "autobahn":
            processes = sample["processes"]
            if len(processes) != 2:
                raise ValueError("native traffic is missing a primary or worker")
            # Autobahn's observer records elapsed microseconds from its declared
            # BENCHMARK_EPOCH_NS; Mysticeti and Shoal snapshots below are absolute.
            elapsed = [integer(row["observed_us"], "native counter observation") for row in processes]
            observed = [epoch + value * 1000 for value in elapsed]
            if any(value < target_end for value in observed):
                raise ValueError("native window counter sample predates the declared endpoint")
            values = {name: sum(integer(row[field], field) for row in processes) for name, field in
                      (("written", "window_written_bytes"), ("read", "window_read_bytes"), ("sampled_final_written", "written_bytes"))}
            intervals = {"window_start_monotonic_ns": target_start, "window_end_monotonic_ns": target_end,
                         "counter_observed_monotonic_ns": observed,
                         "counter_observed_elapsed_us": elapsed,
                         "counter_clock": "elapsed from this host's BENCHMARK_EPOCH_NS",
                         "scope": "native per-write timestamp filtering inside the exact local interval"}
        else:
            def timestamp(phase):
                row = sample[phase]
                if protocol == "mysticeti":
                    start = integer(row["request_started_monotonic_ns"], "scrape start")
                    end = integer(row["response_received_monotonic_ns"], "scrape end")
                    midpoint = integer(row["midpoint_monotonic_ns"], "scrape midpoint")
                    if not start <= midpoint <= end: raise ValueError("native scrape interval is malformed")
                    return midpoint
                return integer(row["observed_us"], "counter snapshot timestamp") * 1000
            start, end = timestamp("before"), timestamp("after")
            tolerance = round(max(.005, min(.1, cfg["duration"] * .02)) * 1e9)
            if end <= start or abs(start-target_start) > tolerance or abs(end-target_end) > tolerance:
                raise ValueError("native counter sample window differs from the cohort measurement window")
            intervals = {"window_start_monotonic_ns": target_start, "window_end_monotonic_ns": target_end,
                         "sample_start_monotonic_ns": start, "sample_end_monotonic_ns": end,
                         "sample_interval_seconds": (end-start)/1e9,
                         "start_offset_ms": (start-target_start)/1e6, "end_offset_ms": (end-target_end)/1e6,
                         "maximum_endpoint_offset_ms": tolerance/1e6,
                         "scope": "sampled same-host counters; endpoint offsets checked against exact cohort window"}
            def counter(phase, field):
                selected = sample[phase]
                if protocol == "mysticeti": selected = selected["values"]
                key = "benchmark_tcp_" + field + "_bytes" if protocol == "mysticeti" else field + "_bytes"
                return integer(selected[key], key)
            values = {field: counter("after", field) - counter("before", field) for field in ("written", "read")}
            values["sampled_final_written"] = counter("final", "written")
            if values["sampled_final_written"] < counter("after", "written"):
                raise ValueError("native final traffic counter regressed")
        if any(value < 0 for value in values.values()):
            raise ValueError("native traffic counters regressed")
        rows[str(i)] = {**values, "sample_window": intervals}
    return {"per_host": rows, "measurement_written_bytes": sum(row["written"] for row in rows.values()),
            "measurement_read_bytes": sum(row["read"] for row in rows.values()),
            "sampled_final_written_bytes": sum(row["sampled_final_written"] for row in rows.values()),
            "finite_run_cost_status": "incomplete: final samples precede process stop/shutdown; later writes excluded",
            "counter_boundary": TRAFFIC_BOUNDARY,
            "sampling_scope": "sum of same-duration origin-host windows; raw local counter sample boundaries retained; no shared global clock"}


def resource_summary(path, budget, nonce=None):
    rows = []
    with Path(path).open("rb") as source:
        for raw in iter(lambda: source.readline(1024**2 + 1), b""):
            if len(raw) > 1024**2:
                raise ValueError("oversized native supervisor evidence line")
            try: row = json.loads(raw)
            except (ValueError, UnicodeDecodeError): continue
            if isinstance(row, dict) and row.get("event") == "deployment_resource_summary": rows.append(row)
            if len(rows) > 1:
                raise ValueError("duplicate native supervisor resource summary")
    if (len(rows) != 1 or rows[0].get("budget") != budget or rows[0].get("exit_code") != 0
            or rows[0].get("native_exit_code") != 0 or rows[0].get("timed_out") is not False
            or rows[0].get("owned_group_cleanup", {}).get("group_empty") is not True):
        raise ValueError("native all-role resource/cleanup envelope was not confirmed")
    if nonce is not None and rows[0].get("nonce") != nonce:
        raise ValueError("native supervisor resource evidence belongs to a different run")
    effective = rows[0].get("effective_budget", {})
    expected_mode = "physical_host" if budget["enforcement"] == "dedicated_host" else "cgroup_memory_max"
    if (effective.get("cpus") != budget["cpus"] or effective.get("memory_enforcement") != expected_mode
            or not 0 < effective.get("memory_limit_bytes", 0) <= budget["memory_bytes"]):
        raise ValueError("native effective all-role resource envelope differs")
    return rows[0]


def normalize(selected, raw, value, directory):
    cfg, protocol = selected["settings"], selected["protocol"]
    validate_inventory(value, protocol, len(selected["hosts"]))
    if raw.get("nonce") != selected["nonce"]:
        raise ValueError("native result belongs to a different run")
    if raw.get("status") != "completed" or raw.get("dispatch", {}).get("failures"):
        raise ValueError("native remote execution did not complete")
    ids = {str(i) for i in range(len(selected["hosts"]))}
    hosts = {str(i): row for i, row in raw["hosts"].items()}
    cleanup = {str(i): row for i, row in raw["cleanup"].items()}
    if (set(hosts) != ids or set(cleanup) != ids or any(row.get("state") != "finished" or row.get("exit_code") != 0 for row in cleanup.values())
            or raw.get("cleanup_acceptance_error") or raw.get("network_cleanup_error")):
        raise ValueError("native per-host completion and cleanup were not confirmed")
    expected_roles = role_artifacts(value)
    machines = {}
    for host in selected["hosts"]:
        i = str(host["replica"]); observed = hosts[i]
        if {role: row["sha256"] for role, row in observed["artifacts"].items()} != expected_roles[i]:
            raise ValueError("native preflight artifact population differs")
        if observed["result"].get("status") != "completed":
            raise ValueError("native host failed after preflight")
        resources = resource_summary(Path(directory) / f"supervisor-{i}.log", host["budget"], selected["nonce"])
        machines[i] = {"artifacts": observed["artifacts"], "python": {key: observed[key] for key in
                       ("python", "python_realpath", "python_version", "python_sha256")}, "resource_summary": resources}
    counters = traffic(protocol, hosts, cfg)
    cohort, agreement = raw["cohort"], raw["agreement"]
    window = cohort["window"]
    written, read = counters["measurement_written_bytes"], counters["measurement_read_bytes"]
    current = {name: prep.sha(prep.ROOT / name) for name in CONTROLLER_FILES}
    if selected.get("campaign_adapter_sources") != current:
        raise ValueError("native campaign adapter changed after planning")
    dependencies = dict(selected["runtime_sources"])
    dependencies.update(current)
    first = value["native_publication"]["receipts"]["0"]
    if selected.get("build_recipe") != first["recipe"]:
        raise ValueError("native selected build recipe differs from publication")
    omission_units = {}; omitted_messages = omitted_bytes = 0
    for host in hosts.values():
        omission = host["result"].get("omission_observation", {})
        count = integer(omission.get("messages_omitted", 0), "omitted message count")
        size = integer(omission.get("serialized_bytes_omitted", 0), "omitted serialized bytes")
        units = omission.get("by_native_unit", {})
        if not isinstance(units, dict) or sum(integer(value, "native omission unit count") for value in units.values()) != count:
            raise ValueError("native omission units do not reconcile with omitted messages")
        omitted_messages += count; omitted_bytes += size
        for name, value_count in units.items():
            if not isinstance(name, str) or not name: raise ValueError("invalid native omission unit")
            omission_units[name] = omission_units.get(name, 0) + value_count
    result = {"schema": 2, "status": "completed", "baseline": protocol, "comparison_eligible": False,
        "acceptance_scope": "functional remote measurement contract; native fidelity, complete finite costs and remote acceptance remain separate gates",
        "settings": cfg, "source_commit": selected["pin"]["commit"], "source_diff_sha256": selected["pin"]["patch_sha256"],
        "runner_sha256": prep.sha(__file__), "runner_dependencies": dependencies,
        "publication_sha256": value["publication_sha256"], "publication_receipts_sha256": value["publication_receipts_sha256"],
        "build_provenance": {"binaries": first["binaries"], "recipe": first["recipe"], "per_host_artifacts": expected_roles,
                             "publication_receipts_sha256": value["publication_receipts_sha256"], "source_bundle_sha256": selected["source_bundle_sha256"]},
        "binary": {"sha256": first["binaries"][0]["sha256"]}, "cohort": cohort, "agreement": agreement,
        "traffic_ledger": counters, "deployment": {"machines": machines, "clock": raw["clock"], "nonce": selected["nonce"],
                       "inventory": {"schema": 1, "hosts": value["hosts"]},
                       "dispatch": raw["dispatch"], "cleanup": cleanup, "all_native_application_children_share_host_budget": True},
        "omission_observation": {"messages_omitted": omitted_messages, "serialized_bytes_omitted": omitted_bytes,
                                 "by_native_unit": omission_units},
        "omission_observation_by_host": {i: host["result"].get("omission_observation", {}) for i, host in hosts.items()},
        "native_cost_scopes": {i: host["result"]["cost_scope"] for i, host in hosts.items()},
        "crypto_cpu_by_host": {i: host["result"].get("crypto_cpu") for i, host in hosts.items()},
        "native_traffic_samples_by_host": {i: host["result"]["traffic"] for i, host in hosts.items()},
        "comparison": {"protocol": protocol, "replicas": len(hosts), "offered_tx_s": cfg["rate"],
            "useful_transaction_bytes": cfg["useful_bytes"], "ingress_batch_ms": cfg["batch_ms"], "bound_ms": cfg["bound_ms"],
            "warmup_seconds": cfg["warmup"], "measurement_seconds": cfg["duration"],
            "accounting_schema": 1, "endpoint_contract": cohort_metrics.ENDPOINT,
            "latency_endpoint": "Independent origin ingress to verified contiguous native payload materialization on that same host; observer/read costs included; no cross-host timestamp subtraction.",
            "cohort": cohort, "unique_completion_tps": window["unique_completion_tps"], "completion_count": window["completion_count"],
            "mean_latency_ms": raw.get("mean_latency_ms"), "mean_latency_scope": "completed cohort members; unfinished/censored quantiles retained",
            "generated_count": window["admission_count"], "generation_tps": window["admission_tps"],
            "traffic_boundary": TRAFFIC_BOUNDARY, "replica_tcp_written_bytes": written, "replica_tcp_read_bytes": read,
            "replica_tcp_written_bytes_per_second": written / cfg["duration"],
            "native_order_fidelity": agreement.get("native_order_fidelity", {"status": "incomplete"}),
            "end_pending_generated_transactions_at_origins": [row["pending"] for row in cohort["origins"]],
            "resource_cost": cohort_metrics.cost_ratios(written, cohort)}}
    if selected.get("network") is not None:
        shaping = raw["network"]
        expected = {key: value["netem"][key] for key in ("delay_ms", "loss_percent")}
        if selected["network"] != expected or shaping.get("settings") != expected:
            raise ValueError("native kernel impairment differs from campaign inventory")
        result["network_shaping"] = {**shaping, "settings": value["netem"]}
        result["network_shaping_cleanup"] = shaping["cleanup"]
    return result


def settings(args, value):
    network = value.get("netem")
    return {"rate": args.rate, "useful_bytes": args.useful_bytes, "warmup": args.warmup,
        "duration": args.duration, "drain": args.drain, "deadline_ms": args.deadline_ms,
        "batch_ms": args.ingress_batch_ms, "batch_bytes": args.batch_bytes, "bound_ms": args.bound_ms,
        "tokio_workers": args.tokio_workers, "faulty": args.faulty_replica,
        "pause_replica": args.pause_replica, "pause_after": args.pause_after, "pause_seconds": args.pause_seconds,
        "omit_replica": args.omit_replica, "omission_after": args.omission_after,
        "omission_seconds": args.omission_seconds, "publish_to_replica": args.publish_to_replica,
        "attacker_rate": args.attacker_rate, "omit_repair": args.omit_repair, "crypto_meter": args.crypto_meter,
        **({"network": {key: network[key] for key in ("delay_ms", "loss_percent")}} if network is not None else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nodes", type=int, required=True); parser.add_argument("--rate", type=int, required=True)
    parser.add_argument("--useful-bytes", type=int, required=True)
    for name, default in (("warmup", 1), ("duration", 3), ("drain", 5), ("deadline-ms", 1000),
                          ("pause-after", 1), ("pause-seconds", .5), ("omission-after", 1), ("omission-seconds", .5)):
        parser.add_argument("--" + name, type=float, default=default)
    for name, default in (("ingress-batch-ms", 10), ("bound-ms", 100), ("batch-bytes", 500000), ("tokio-workers", 2), ("attacker-rate", 100)):
        parser.add_argument("--" + name, type=int, default=default)
    for name in ("pause-replica", "omit-replica"): parser.add_argument("--" + name, type=int)
    for name in ("faulty-replica", "publish-to-replica"): parser.add_argument("--" + name, type=int, action="append", default=[])
    parser.add_argument("--omit-repair", action="store_true"); parser.add_argument("--crypto-meter", choices=("off", "on"), default="off")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(); value = json.loads(args.inventory.read_text())
    validate_inventory(value, value["protocol"], args.nodes)
    selected = build_plan(value, settings(args, value))
    if not args.execute:
        print(json.dumps({"status": "planned; no SSH or host changes", "plan": selected}, indent=2)); return 0
    args.output.mkdir(parents=True, exist_ok=False)
    for name, digest in selected["campaign_adapter_sources"].items():
        path = args.output / "adapter-sources" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((prep.ROOT / name).read_bytes())
        if prep.sha(path) != digest: raise ValueError("native campaign source changed during archival")
    manifest = {"status": "failed", "comparison_eligible": False}
    try:
        raw = remote_native.execute(selected, args.output / "placement")
        manifest = normalize(selected, raw, value, args.output / "placement")
        manifest["placement_result"] = {"path": "placement/result.json", "sha256": prep.sha(args.output / "placement/result.json")}
    except (ValueError, KeyError, OSError, RuntimeError) as error:
        manifest["error"] = f"{type(error).__name__}: {error}"
    finally: prep.json_file(args.output / "manifest.json", manifest)
    print(json.dumps({"status": manifest["status"], "manifest": str(args.output / "manifest.json")}))
    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__": raise SystemExit(main())
