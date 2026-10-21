#!/usr/bin/env python3
"""Plan/run the reviewed three-family native implementation campaign.

Unsupported adapter cases remain explicit incomplete records. This driver
never builds, substitutes a different protocol, or silently drops a fault case.
Use --plan-only to inspect the complete matrix before spending benchmark time.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from run_comparison import (ROOT, validate_comparison, validate_timing, configured_bound,
                            artifact_identity, finite, write_json, sha256)
from spec_provenance import archive_spec, verify_spec_unchanged
import campaign_frontier as frontier
import campaign_resources as resources
import timing_calibration

FAMILIES = ("healthy", "responsiveness", "recovery")
ADAPTERS = {
    "delugi": {"path": "scripts/run_sustained.py", "nodes": [4, 7, 31],
               "faults": ["none", "payload_omission", "all_message_omission", "process_pause", "tcp_packet_loss"], "remote": True},
    "mysticeti": {"path": "scripts/baselines/mysticeti.py", "nodes": [4, 7, 31],
                  "faults": ["none", "process_pause", "payload_omission"]},
    "autobahn": {"path": "scripts/baselines/autobahn.py", "nodes": [4, 7, 31], "faults": ["none", "process_pause", "payload_omission"]},
    "shoal": {"path": "scripts/baselines/shoal.py", "nodes": [4, 7],
              "faults": ["none", "process_pause", "payload_omission"],
              "fault_nodes": {"none": [4, 7], "process_pause": [4], "payload_omission": [4]},
              "acceptance": "benchmarks/results/shoal-native-local-acceptance-2026-10-19.json"},
    "raptr": {"path": "scripts/baselines/raptr.py", "nodes": [], "faults": []},
}

# These cases are required by the reviewed plan, independently of whether an
# adapter can yet execute them. A generic timed process pause is not evidence
# for leader-aligned silence, nor is persistent packet loss a transient burst.
REVIEWED_SCENARIOS = {
    "responsiveness": (
        ("nonleader_withholding", "payload_omission", "nonleader selection and eligibility witness"),
        ("nonleader_selective_publication", "payload_omission", "nonleader selection, recipient schedule and eligibility witness"),
        ("transient_tcp_loss", "tcp_packet_loss", "finite kernel-loss schedule and actual drop efficacy ledger"),
    ),
    "recovery": (
        ("silent_leader_then_honest", "all_message_omission", "native leader-triggered silence and subsequent honest-leader witness"),
        ("fault_bursts", "all_message_omission", "multiple omission/withdrawal events over a fixed faulty identity set"),
        ("selective_publication", "payload_omission", "recovery-specific selective-publication schedule and proposal/replay diagnostics"),
        ("sustained_attack", "payload_omission", "attack through drain and recovery-specific proposal/replay diagnostics"),
        ("withdrawn_attack", "payload_omission", "withdrawal efficacy and recovery-specific proposal/replay diagnostics"),
        ("payload_blocked_contiguous_output", "payload_omission", "native-valid committed descriptor with witnessed payload-blocked contiguous output"),
    ),
}


def fixed_faulty_replicas(config, nodes):
    """The union of faulty identities is fixed across a committee's scenarios."""
    selected = config.get("fixed_faulty_replicas", {})
    if not isinstance(selected, dict):
        raise ValueError("fixed_faulty_replicas must map committee sizes to identity lists")
    default = config.get("fault", {}).get("replica", 0)
    ids = selected.get(str(nodes), [default])
    if (not isinstance(ids, list) or not ids or any(type(i) is not int or not 0 <= i < nodes for i in ids)
            or len(set(ids)) != len(ids) or len(ids) > (nodes - 1) // 3):
        raise ValueError("fixed faulty identities must be distinct committee members and their union must be <= f")
    if default not in ids:
        raise ValueError("legacy fault replica must belong to the fixed faulty identity set")
    return sorted(ids)


def reviewed_scenarios_enabled(config):
    return config["purpose"] == "formal" or config.get("include_reviewed_scenarios", False)


def scenario_cases(base, config):
    """Reviewable intentions only; unsupported execution is never inferred."""
    family, nodes = base["family"], base["nodes"]
    faulty = fixed_faulty_replicas(config, nodes)
    fault = config.get("fault", {})
    start, duration = fault.get("after_seconds", 1), fault.get("duration_seconds", 2)
    gap = config.get("burst_gap_seconds", duration)
    count = config.get("burst_count", 3)
    for name, kind, requirement in REVIEWED_SCENARIOS.get(family, ()):
        event = {"action": kind, "identities": faulty, "start_after_measurement_seconds": start,
                 "duration_seconds": duration, "withdrawal": "resume ordinary native behavior"}
        if name == "silent_leader_then_honest":
            event.update(identities=[faulty[0]], trigger="first native leadership opportunity of this fixed identity after the start threshold",
                         withdrawal="after the selected native leadership opportunity; do not rewrite native leader selection")
            event.pop("duration_seconds")
        if name.startswith("nonleader_"):
            event["eligibility"] = "identity must be a nonleader for the observed native proposal opportunity; archive witness"
        if name == "nonleader_withholding":
            event["recipient_policy"] = "publish payload to no correct peers during the eligible window; native control behavior continues"
        if "selective_publication" in name or name == "payload_blocked_contiguous_output":
            event["recipient_policy"] = "publish to a nonempty strict subset of correct peers; native validation and honest custody unchanged"
        if name == "sustained_attack":
            event.pop("duration_seconds")
            event["end"] = "declared end of measurement plus drain; no recovery claim before withdrawal"
            event["withdrawal"] = "after the declared observation endpoint"
        if name == "transient_tcp_loss":
            event.update(identities=[], impairment_scope="scoped benchmark TCP packets; distinct from application-message omission")
        events = [event]
        if name == "fault_bursts":
            events = [{**event, "start_after_measurement_seconds": start + k * (duration + gap)} for k in range(count)]
        diagnostics = ["all honest-origin cohorts through drain/deadline", "exact output gaps and backlog recovery",
                       "proposal fate separately from transaction replay", "native validation and leader selection preserved"]
        if name == "silent_leader_then_honest":
            diagnostics += ["three subsequent honest Delugi anchors; counterpart native schedule retained"]
        if name == "payload_blocked_contiguous_output":
            diagnostics += ["descriptor-commit and payload-materialization events proving the intended block; no forced invalid references or deleted honest custody"]
        yield {**base, "scenario": name, "fault": kind, "faulty_replicas": faulty,
               "fault_schedule": events, "required_evidence": diagnostics,
               "execution_requirement": "Unsupported reviewed scenario: " + requirement,
               "load_policy": {"kind": "common_offered_load", "rate": base["rate"]}}


def validate_case_fault_budget(case, config):
    """Check the identity union, not merely simultaneous fault cardinality."""
    expected = fixed_faulty_replicas(config, case["nodes"])
    if case.get("faulty_replicas", expected) != expected:
        raise ValueError("case changes the committee's fixed faulty identity set")
    for event in case.get("fault_schedule", []):
        ids = event.get("identities", [])
        if (not isinstance(ids, list) or any(type(i) is not int for i in ids)
                or len(set(ids)) != len(ids) or not set(ids) <= set(expected)):
            raise ValueError("fault event introduces an identity outside the fixed <= f set")


def validate_config(config):
    if config.get("schema") != 1 or config.get("purpose") not in ("development", "formal"):
        raise ValueError("schema1 and explicit purpose development/formal required")
    protocols, families = config["protocols"], config.get("families", list(FAMILIES))
    if not protocols or len(set(protocols)) != len(protocols) or not set(protocols) <= set(ADAPTERS):
        raise ValueError("distinct known native protocols required")
    if len(set(families)) != len(families) or not set(families) <= set(FAMILIES) or not families:
        raise ValueError("choose from exactly the three reviewed experiment families")
    if config["purpose"] == "formal":
        if set(families) != set(FAMILIES) or not {"delugi", "mysticeti", "autobahn", "shoal"} <= set(protocols):
            raise ValueError("formal campaign requires all three families and published core counterparts")
        if config["measurement_seconds"] < 120 or config["repeats"] < 3:
            raise ValueError("formal stability claims require repeated multi-minute trials")
    if config["repeats"] < 1 or config["measurement_seconds"] <= 0 or config["warmup_seconds"] < 0:
        raise ValueError("positive repeat/duration and nonnegative warmup required")
    if config["drain_seconds"] < 0 or config["deadline_ms"] <= 0 or config["useful_transaction_bytes"] <= 0:
        raise ValueError("invalid drain, deadline, or useful byte size")
    if not config["nodes"] or any(n not in (4, 7, 31) for n in config["nodes"]):
        raise ValueError("committee gate is n=4,7,31")
    if not config["healthy_rates"] or len(set(config["healthy_rates"])) != len(config["healthy_rates"]) or any(rate <= 0 for rate in config["healthy_rates"]) or config["common_below_capacity_rate"] <= 0:
        raise ValueError("positive useful offered rates required")
    if not config["bounds_ms"] or any(not 1 <= v <= 60000 for v in config["bounds_ms"]):
        raise ValueError("explicit configured bounds required")
    if not config["added_delays_ms"] or any(not 0 <= v <= 100 for v in config["added_delays_ms"]):
        raise ValueError("explicit independent added delay sweep required")
    if config["purpose"] == "formal" and config.get("include_reviewed_scenarios") is False:
        raise ValueError("formal plans cannot omit reviewed recovery and disruption scenarios")
    if "include_reviewed_scenarios" in config and type(config["include_reviewed_scenarios"]) is not bool:
        raise ValueError("include_reviewed_scenarios must be a boolean")
    for nodes in config["nodes"]:
        fixed_faulty_replicas(config, nodes)
    if reviewed_scenarios_enabled(config):
        fractions = config.get("matched_utilizations", [.5])
        if (not isinstance(fractions, list) or not fractions or len(set(fractions)) != len(fractions)
                or any(type(v) not in (int, float) or not 0 < v < 1 for v in fractions)):
            raise ValueError("reviewed plans require distinct matched-utilization fractions strictly between zero and one")
        fault = config.get("fault", {})
        start, duration = fault.get("after_seconds", 1), fault.get("duration_seconds", 2)
        gap, bursts = config.get("burst_gap_seconds", duration), config.get("burst_count", 3)
        for value, name, positive in ((start, "fault start", False), (duration, "fault duration", True), (gap, "burst gap", True)):
            finite(value, name, positive=positive)
        if type(bursts) is not int or not 2 <= bursts <= 32:
            raise ValueError("reviewed burst plans require between 2 and 32 events")
        if start + (bursts - 1) * (duration + gap) + duration > config["measurement_seconds"]:
            raise ValueError("reviewed burst/withdrawal schedule must finish within the measurement interval")
    for protocol in protocols:
        frontier.tuning_options(config, protocol)
    frontier.policy(config, max(config["healthy_rates"]))
    return config


def trial_plan(config):
    validate_config(config)
    families = config.get("families", FAMILIES)
    cases = []
    for repeat in range(config["repeats"]):
        protocols = config["protocols"]
        offset = repeat % len(protocols)
        for family in families:
            rates = config["healthy_rates"] if family == "healthy" else [config["common_below_capacity_rate"]]
            faults = {"healthy": ["none"],
                      "responsiveness": ["none", "payload_omission", "tcp_packet_loss"],
                      "recovery": ["process_pause", "all_message_omission"]}[family]
            for nodes in config["nodes"]:
                for rate in rates:
                    for delay in config["added_delays_ms"]:
                        for bound in config["bounds_ms"]:
                            for fault in faults:
                                for protocol in protocols[offset:] + protocols[:offset]:
                                    cases.append({"family": family, "protocol": protocol, "nodes": nodes,
                                           "rate": rate, "added_delay_ms": delay, "bound_ms": bound,
                                           "fault": fault, "repeat": repeat})
                                    if reviewed_scenarios_enabled(config):
                                        cases[-1]["scenario"] = "healthy_frontier" if family == "healthy" else "legacy_" + fault
                                        cases[-1]["faulty_replicas"] = fixed_faulty_replicas(config, nodes)
                                        cases[-1]["load_policy"] = {"kind": "common_offered_load", "rate": rate}
                            if reviewed_scenarios_enabled(config) and family != "healthy":
                                for protocol in protocols[offset:] + protocols[:offset]:
                                    base = {"family": family, "protocol": protocol, "nodes": nodes,
                                            "rate": rate, "added_delay_ms": delay, "bound_ms": bound, "repeat": repeat}
                                    expanded = list(scenario_cases(base, config))
                                    cases.extend(expanded)
                                    # The load must later be derived from an accepted
                                    # native healthy frontier; assigning the common
                                    # rate here would mislabel the comparison.
                                    clean = {**base, "scenario": "clean", "fault": "none",
                                             "faulty_replicas": fixed_faulty_replicas(config, nodes), "fault_schedule": []}
                                    for utilization in config.get("matched_utilizations", [.5]):
                                        for scenario in [clean, *expanded]:
                                            cases.append({**scenario, "rate": None,
                                                "scenario_execution_requirement": scenario.get("execution_requirement"),
                                                "load_policy": {"kind": "matched_utilization", "fraction": utilization,
                                                    "rate_selection": "fraction of this protocol's accepted repeated healthy frontier at the same n, delay, bound and tail target"},
                                                "execution_requirement": "Unsupported matched-utilization cell: accepted-frontier rate resolution and native scenario execution are required"})
    # Complete all healthy repetitions before requiring capacity evidence for
    # any fault family. Stable sort retains rotated native order within cells.
    for case in sorted(cases, key=lambda case: list(FAMILIES).index(case["family"])):
        if case["family"] == "healthy" and frontier.enabled(config):
            for tuning in frontier.tuning_options(config, case["protocol"]):
                yield {**case, "tuning_id": tuning["id"], "tuning": tuning["parameters"]}
        else:
            yield case


def selected_inventory(case, config):
    return config.get("remote_inventories", {}).get(case["protocol"], {}).get(str(case["nodes"]))


def case_inventory(case, config, snapshots=None):
    source = selected_inventory(case, config)
    if source is None:
        return None
    data, source_hash = resources.read_inventory(source, case["protocol"], case["nodes"], snapshots)
    if case["protocol"] != "delugi":
        import native_campaign
        data = native_campaign.inventory(data, case["protocol"], case["nodes"], source_hash)
    else:
        from remote_deployment import validate_inventory
        validate_inventory(data, case["nodes"])
    data["inventory_source_sha256"] = source_hash
    loss = config.get("tcp_loss_percent", 0) if case["fault"] == "tcp_packet_loss" else 0
    if case["fault"] == "tcp_packet_loss" and not 0 < loss < 100:
        raise ValueError("TCP-loss experiment requires explicit tcp_loss_percent in (0,100)")
    data["netem"] = {"delay_ms": case["added_delay_ms"], "loss_percent": loss,
                     "application_interval": "setup through declared drain; before/configured/after RTT calibration retained"}
    return data


def adapter_command(case, config, directory, inventory_path=None):
    validate_case_fault_budget(case, config)
    if case.get("execution_requirement"):
        raise ValueError(case["execution_requirement"])
    if case.get("fault") not in ("none", "tcp_packet_loss") and len(fixed_faulty_replicas(config, case["nodes"])) > 1:
        raise ValueError("fixed multiple-fault identity ingress and schedule are not implemented by this adapter")
    protocol, adapter = case["protocol"], ADAPTERS[case["protocol"]]
    remote = selected_inventory(case, config) is not None
    native_remote = remote and protocol in ("mysticeti", "autobahn", "shoal")
    if native_remote:
        import native_campaign
        adapter = {"path": "scripts/native_campaign.py", "nodes": [4, 7, 31],
                   "faults": native_campaign.FAULTS, "remote": True}
    if not (ROOT / adapter["path"]).is_file():
        raise ValueError("native published artifact adapter is not integrated")
    if case["nodes"] not in adapter["nodes"]:
        raise ValueError("committee size lacks native adapter acceptance")
    if case["fault"] not in adapter["faults"]:
        raise ValueError("fault requires an implemented native adapter; packet loss cannot substitute for semantic omission")
    if case["nodes"] not in adapter.get("fault_nodes", {}).get(case["fault"], adapter["nodes"]):
        raise ValueError("this committee/fault combination lacks native local acceptance")
    if protocol == "shoal" and not remote and case["added_delay_ms"]:
        raise ValueError("local Shoal added-delay support is not calibrated or integrated")
    if remote and not adapter.get("remote"):
        raise ValueError("native adapter remote placement is not yet accepted")
    if case["fault"] == "tcp_packet_loss" and not remote:
        raise ValueError("TCP loss needs scoped Linux inventory; packet loss cannot substitute for semantic omission")
    faulty = case["fault"] not in ("none", "tcp_packet_loss")
    tuning = case.get("tuning", config.get("native_tuning", {}).get(protocol, {}))
    command = [sys.executable, str(ROOT / adapter["path"]), "--rate", str(case["rate"]),
               "--useful-bytes", str(config["useful_transaction_bytes"]),
               "--warmup", str(config["warmup_seconds"]), "--duration", str(config["measurement_seconds"]),
               "--drain", str(config["drain_seconds"]), "--deadline-ms", str(config["deadline_ms"]),
               "--ingress-batch-ms", str(tuning.get("ingress_batch_ms", 10)),
               "--bound-ms", str(case["bound_ms"]), "--output", str(directory)]
    if remote:
        command += ["--inventory", str(inventory_path or selected_inventory(case, config))]
        if native_remote:
            command += ["--execute"]
    if protocol == "delugi":
        command += ["--skip-build", "--nodes", str(case["nodes"]), "--spec-snapshot", str(Path(config["spec_snapshot"]).resolve())]
        if config.get("paper_repository"):
            command += ["--paper-repository", str(Path(config["paper_repository"]).resolve())]
        for option in ("max_batch_transactions", "arrival_queue_capacity", "ordering_mode", "resource_profile"):
            if option in tuning:
                command += ["--" + option.replace("_", "-"), str(tuning[option])]
        fault = config.get("fault", {"replica": 0, "after_seconds": 1, "duration_seconds": 2})
        if case["fault"] == "process_pause":
            command += ["--pause-replica", str(fault["replica"]), "--pause-after", str(fault["after_seconds"]),
                        "--pause-duration", str(fault["duration_seconds"])]
        elif faulty:
            command += ["--fault-replica", str(fault["replica"]), "--fault-after", str(fault["after_seconds"]),
                        "--fault-duration", str(fault["duration_seconds"]),
                        "--fault-scope", "payload" if case["fault"] == "payload_omission" else "all"]
            if fault.get("peers") is not None:
                command += ["--fault-peers", *map(str, fault["peers"])]
            if case["fault"] == "payload_omission":
                command += ["--fault-batches", str(fault.get("authored_batches", 1)),
                            "--fault-batch-transactions", str(fault.get("transactions_per_batch", 64)),
                            "--fault-payload-bytes", str(fault.get("payload_bytes", 472))]
    else:
        command += ["--nodes", str(case["nodes"])]
        if case["fault"] == "process_pause":
            fault = config.get("fault", {"replica": 0, "after_seconds": 1, "duration_seconds": 2})
            command += ["--faulty-replica", str(fault["replica"]), "--pause-replica", str(fault["replica"]),
                        "--pause-after", str(fault["after_seconds"]), "--pause-seconds", str(fault["duration_seconds"])]
        if case["fault"] == "payload_omission":
            fault = config.get("fault", {"replica": 0, "after_seconds": 1, "duration_seconds": 2})
            command += ["--faulty-replica", str(fault["replica"]), "--omit-replica", str(fault["replica"]),
                        "--omission-after", str(fault["after_seconds"]), "--omission-seconds", str(fault["duration_seconds"]),
                        "--attacker-rate", str(fault.get("attacker_rate", 100))]
            if fault.get("peers") is not None:
                for recipient in range(case["nodes"]):
                    if recipient != fault["replica"] and recipient not in fault["peers"]:
                        command += ["--publish-to-replica", str(recipient)]
            if protocol == "autobahn" and fault.get("omit_repair", False):
                command += ["--omit-repair"]
        if protocol in ("autobahn", "shoal") and "batch_bytes" in tuning:
            command += ["--batch-bytes", str(tuning["batch_bytes"])]
    return command


def validate_local_native_cleanup(protocol, manifest):
    """A successful result must not conceal uncollected owned validators."""
    if protocol != "shoal":
        return
    cleanup = manifest.get("owned_process_cleanup", {})
    rows = cleanup.get("processes")
    nodes = manifest.get("settings", {}).get("nodes")
    if (cleanup.get("all_reaped") is not True or not isinstance(rows, list)
            or type(nodes) is not int or len(rows) != nodes
            or any(not isinstance(row, dict) or type(row.get("pid")) is not int
                   or row["pid"] <= 0 or type(row.get("returncode")) is not int
                   or row["returncode"] not in (0, -15) for row in rows)
            or len({row["pid"] for row in rows}) != nodes):
        raise ValueError("native local Shoal cleanup lacks all distinct reaped validators")
    for name in ("swap_before", "swap_after"):
        if manifest.get(name, {}).get("enabled") is not False:
            raise ValueError("native local Shoal requires verified disabled swap at both boundaries")
    readiness = manifest.get("startup_readiness", {})
    expected = set(range(nodes))
    if (readiness.get("ready") is not True
            or any(not isinstance(readiness.get(key), list)
                   or len(readiness[key]) != nodes
                   or any(type(index) is not int for index in readiness[key])
                   or set(readiness[key]) != expected
                   for key in ("api_replicas", "bootstrapped", "counter_replicas"))
            or type(readiness.get("started_us")) is not int
            or type(readiness.get("completed_us")) is not int
            or type(manifest.get("epoch_us")) is not int
            or not 0 <= readiness["started_us"] <= readiness["completed_us"] < manifest["epoch_us"]):
        raise ValueError("native local Shoal workload epoch must follow complete bootstrap/counter/REST readiness")


def validate_fault_effect(case, manifest):
    if case["protocol"] == "delugi" and case["fault"] in ("payload_omission", "all_message_omission"):
        trial = manifest.get("trial", manifest)
        counts = trial.get("fault_accounting", {})
        dropped = sum(row.get("messages", 0) for replica in counts.values() for row in replica.values())
        if dropped == 0:
            raise ValueError("no-op fault smoke: selected semantic omission dropped no message")
        return {"omitted_messages": dropped, "scope": trial["fault"]}
    if case["protocol"] in ("mysticeti", "autobahn", "shoal") and case["fault"] == "payload_omission":
        observation = manifest.get("omission_observation", {})
        if observation.get("messages_omitted", 0) <= 0:
            raise ValueError("no-op fault smoke: native omission dropped no message")
        return {"observation": observation,
                "native_unit": {"mysticeti": "own signed block (payload and consensus coupled)",
                                "autobahn": "worker payload broadcast/repair; primary continues",
                                "shoal": "own native DAG node/certified-node publication or repair unit"}[case["protocol"]]}
    return None


def cohort_backlog(comparison):
    """Exact admission/materialization ledger is authoritative when available."""
    window = comparison.get("cohort", {}).get("window", {})
    values = {}
    for key in ("pending_at_start", "pending_at_end"):
        top, exact = comparison.get(key), window.get(key)
        if top is not None and exact is not None and top != exact:
            raise ValueError("top-level backlog contradicts exact cohort window")
        value = exact if exact is not None else top
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("backlog must be a nonnegative request count")
        values[key] = value
    return values


def validate_linux_timing(manifest, case, inventory):
    """Validate recorded scoped-kernel evidence; this does not execute shaping."""
    trial = manifest.get("trial", manifest)
    shaping = manifest.get("network_shaping", trial.get("network_shaping"))
    cleanup = manifest.get("network_shaping_cleanup", trial.get("network_shaping_cleanup"))
    expected = inventory["netem"]
    if expected.get("delay_ms") != case["added_delay_ms"]:
        raise ValueError("selected inventory delay differs from campaign preset")
    loss = finite(expected.get("loss_percent"), "loss_percent")
    if (case["fault"] == "tcp_packet_loss" and not 0 < loss < 100) or (case["fault"] != "tcp_packet_loss" and loss != 0):
        raise ValueError("selected inventory packet loss differs from campaign fault")
    if (not isinstance(shaping, dict) or shaping.get("backend") != "Linux_tc_netem_scoped_ingress"
            or shaping.get("settings") != expected or not isinstance(cleanup, dict)):
        raise ValueError("trial Linux netem settings/backend/cleanup differ from selected inventory")
    ids = {str(i) for i in range(case["nodes"])}
    for group, predicate in ((shaping.get("configuration"), lambda r: r.get("active_objects_complete") is True and r.get("physical_qdisc_configuration_unchanged") is True),
                             (cleanup, lambda r: r.get("phase") == "cleared" and r.get("physical_qdisc_configuration_unchanged") is True)):
        if not isinstance(group, dict) or set(map(str, group)) != ids or not all(predicate(row) for row in group.values()):
            raise ValueError("Linux netem setup/cleanup is incomplete for the committee")
    def samples(name):
        rows = shaping[name]
        native = "native_publication" in inventory
        roles = range(3 if case["protocol"] == "autobahn" and native else 1)
        edges = {(i, (i+1)%case["nodes"], role) for role in roles for i in range(case["nodes"])}
        return {edge: value["median"] for edge, value in
                timing_calibration.edge_records(rows, edges, require_roles=native).items()}
    before, active, after = (samples(name) for name in ("before", "configured", "after_cleanup"))
    for edge in before:
        if not timing_calibration.addition(before[edge], active[edge], case["added_delay_ms"])["addition_matches"]:
            raise ValueError("Linux RTT evidence does not verify configured delay")
        if not timing_calibration.restored(before[edge], after[edge]):
            raise ValueError("Linux RTT did not return to baseline after cleanup")
    if shaping.get("echo_cleanup_errors") or shaping.get("final_status_errors"):
        raise ValueError("Linux shaping evidence contains cleanup/status failures")
    return {"backend": shaping["backend"], "added_delay_ms": case["added_delay_ms"],
            "loss_percent": expected["loss_percent"], "bound_ms": case["bound_ms"],
            "calibration_policy": timing_calibration.POLICY,
            "calibration": "before/configured/after committee ring RTTs verified", "cleanup_verified": True}


def validate_result(case, config, data, *, calibration=None, after_calibration=None, inventory=None, identities=None):
    """Same native comparison, artifact and timing gates as the small driver."""
    try:
        tuning = case.get("tuning", config.get("native_tuning", {}).get(case["protocol"], {}))
        cohort_backlog(data["comparison"])
        comparison = validate_comparison(data, case["protocol"], case["rate"], None,
            config["warmup_seconds"], config["measurement_seconds"], tuning.get("ingress_batch_ms", 10),
            useful_bytes=config["useful_transaction_bytes"], require_cohorts=True, replicas=case["nodes"])
        if config["purpose"] == "formal":
            if data.get("comparison_eligible") is False:
                raise ValueError("native adapter explicitly lacks formal comparison acceptance")
            fidelity = comparison.get("native_order_fidelity", {})
            if fidelity.get("status") == "incomplete" or (case["protocol"] != "delugi" and
                    fidelity.get("status") not in ("complete_observer_sequence", "verified_native_wal")):
                raise ValueError("formal native comparison requires complete output-order fidelity evidence")
        trial = data.get("trial", data)
        if inventory is None:
            validate_local_native_cleanup(case["protocol"], data)
        if any(part.get(key) for part in (data, trial) for key in
               ("cleanup_errors", "network_shaping_cleanup_error", "deployment_cleanup_error")):
            raise ValueError("trial reports cleanup failure")
        if configured_bound(data, case["protocol"]) != case["bound_ms"]:
            raise ValueError("native configured bound differs from campaign preset")
        if inventory is not None:
            timing = validate_linux_timing(data, case, inventory)
        elif case["added_delay_ms"]:
            if (not isinstance(calibration, dict) or calibration.get("status") != "passed"
                    or calibration.get("requested_one_way_delay_ms") != case["added_delay_ms"]):
                raise ValueError("campaign delay calibration is absent or mismatched")
            if (not isinstance(after_calibration, dict) or after_calibration.get("status") != "passed"
                    or after_calibration.get("requested_one_way_delay_ms") != case["added_delay_ms"]
                    or after_calibration.get("shaping", {}).get("helper_sha256") != calibration["shaping"]["helper_sha256"]):
                raise ValueError("campaign post-trial calibration is absent or mismatched")
            for check in (calibration, after_calibration):
                if not timing_calibration.local_record(check, case["added_delay_ms"])["passed"]:
                    raise ValueError("campaign raw RTT calibration does not verify requested delay")
            if not isinstance(data.get("network_shaping"), dict) or not isinstance(data.get("network_shaping_cleanup"), dict):
                raise ValueError("trial shaping and cleanup evidence are required")
            timing = validate_timing(data, case["protocol"], case["added_delay_ms"], case["bound_ms"], calibration["shaping"]["helper_sha256"])
        else:
            if data.get("network_shaping") is not None or trial.get("network_shaping") is not None:
                raise ValueError("zero added-delay cell unexpectedly applied kernel shaping")
            timing = {"added_delay_ms": 0, "bound_ms": case["bound_ms"], "kernel_shaping": False}
        identity = artifact_identity(data, case["protocol"])
        measured_native_roles = None
        if inventory is not None and "native_publication" in inventory:
            import native_campaign
            measured_native_roles = native_campaign.measured_roles(data, inventory)
            # Exact host receipts are checked against this immutable (protocol,n)
            # inventory. The reusable artifact family must stay the same across n.
            roles = sorted({role for row in measured_native_roles.values() for role in row})
            identity = {"source_commit": data["source_commit"], "source_diff": data["source_diff_sha256"],
                "source_bundle_sha256": data["build_provenance"]["source_bundle_sha256"],
                "build_recipe": data["build_provenance"]["recipe"],
                "remote_role_artifacts": {role: sorted({row[role] for row in measured_native_roles.values()}) for role in roles},
                "runner": data["runner_sha256"]}
        if "runner_dependencies" in data:
            dependencies = data["runner_dependencies"]
            if (not isinstance(dependencies, dict) or not dependencies
                    or any(not isinstance(name, str) or not isinstance(digest, str) or len(digest) != 64
                           or any(c not in "0123456789abcdef" for c in digest) for name, digest in dependencies.items())):
                raise ValueError("malformed native runner dependency hashes")
            identity["runner_dependencies"] = dependencies
        if inventory is not None:
            if "native_publication" in inventory:
                pass  # Exact per-host role/receipt binding was checked above.
            else:
                machines = trial["deployment"]["machines"]
                expected = {str(host["replica"]): host["binary"]["sha256"] for host in inventory["hosts"]}
                actual = {str(replica): row["binary_sha256"] for replica,row in machines.items()}
                if actual != expected:
                    raise ValueError("measured remote binary population differs from inventory")
                identity["remote_binaries"] = sorted(set(actual.values()))
        if identities is not None and case["protocol"] in identities and identity != identities[case["protocol"]]:
            raise ValueError("native source or binary changed between campaign trials")
        resource_contract = resources.verified_contract(case, config, data, inventory)
        return {"comparison": comparison, "timing": timing, "artifact_identity": identity,
                **({"measured_remote_role_artifacts": measured_native_roles,
                    "publication_receipts_sha256": inventory["publication_receipts_sha256"]} if measured_native_roles is not None else {}),
                "resource_contract": resource_contract, "resource_contract_sha256": resources.canonical_hash(resource_contract)}
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError("malformed campaign result: " + str(error)) from error


def below_capacity_evidence(trials, case, config):
    """Require measured healthy support before labelling a fault rate below capacity."""
    if frontier.enabled(config):
        evidence = []
        protocols = [case["protocol"]] if case.get("load_policy", {}).get("kind") == "matched_utilization" else config["protocols"]
        for protocol in protocols:
            accepted = frontier.select_frontier(trials, case, config, protocol)["selected"]
            if case["rate"] >= accepted["rate"]:
                raise ValueError(f"{protocol} common fault load must be strictly below the accepted measured frontier")
            evidence.extend(row["trial"] for row in accepted["evidence"])
        return evidence
    evidence = []
    for protocol in config["protocols"]:
        matches = {}
        for trial in trials:
            if trial.get("status") != "passed" or trial["case"]["family"] != "healthy":
                continue
            prior = trial["case"]
            if (prior["protocol"] != protocol or prior["nodes"] != case["nodes"] or prior["rate"] < case["rate"]
                    or prior["added_delay_ms"] != case["added_delay_ms"] or prior["bound_ms"] != case["bound_ms"]):
                continue
            row = trial["comparison"]
            cohort = row["cohort"]
            p99 = cohort["admission_to_output"]["p99"]
            backlog = cohort_backlog(row)
            if (cohort["unfinished"] == 0 and cohort["rejected"] == 0 and
                    row["unique_completion_tps"] >= prior["rate"] * .95 and
                    p99["value_ms"] is not None and p99["value_ms"] <= config["deadline_ms"] and
                    backlog["pending_at_start"] is not None and backlog["pending_at_end"] is not None and
                    backlog["pending_at_end"] <= backlog["pending_at_start"]):
                # Three rates from one repetition are not three repetitions of
                # a sustainable point. Keep one label per independent repeat.
                matches.setdefault(prior["rate"], {}).setdefault(prior["repeat"], trial["label"])
        required = 3 if config["purpose"] == "formal" else 1
        accepted = [labels for labels in matches.values() if len(labels) >= required]
        if not accepted:
            raise ValueError(f"{protocol} lacks repeated healthy capacity evidence at the common fault-case offered rate")
        evidence.extend(next(iter(accepted)).values())
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    config = validate_config(json.loads(args.config.read_text()))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {"schema": 1, "purpose": config["purpose"], "status": "planned", "config": config,
                "runner_sha256": sha256(__file__), "frontier_reducer_sha256": sha256(frontier.__file__),
                "timing_policy_sha256": sha256(timing_calibration.__file__),
                "trials": [], "artifact_identities": {},
                "scope": "native independent-process implementation experiments; explicit SSH host inventory or local placement; no durability equivalence claim"}
    manifest["resource_contracts"] = {}
    manifest["remote_inventory_sources"] = resources.snapshot_inventories(config, output / "inventory-sources")
    manifest["resource_validator_sha256"] = sha256(resources.__file__)
    if config.get("remote_inventories"):
        manifest["native_remote_adapter_sha256"] = sha256(ROOT / "scripts/native_campaign.py")
    manifest["specification"] = archive_spec(Path(config["spec_snapshot"]), output / "snapshot", config.get("paper_repository"))
    original_shaper_environment = {key: os.environ.get(key) for key in ("DELUGI_NETWORK_DELAY_MS", "DELUGI_SHAPER_CONTROL")}
    for index, case in enumerate(trial_plan(config)):
        label = f"{index:04d}-{case['family']}-{case['protocol']}-n{case['nodes']}-{case['rate']}"
        record = {"label": label, "case": case, "status": "planned"}
        manifest["trials"].append(record)
        try:
            if not args.plan_only:
                case, selected = frontier.resolve_case(manifest["trials"], case, config)
                record["case"] = case
                if selected is not None:
                    record["selected_healthy_frontier"] = selected
            validate_case_fault_budget(case, config)
            if case.get("execution_requirement"):
                raise ValueError(case["execution_requirement"])
            inventory = case_inventory(case, config, manifest["remote_inventory_sources"])
            inventory_path = None
            if inventory is not None:
                inventory_path = output / (label + ".inventory.json")
                write_json(inventory_path, inventory)
                record["inventory"] = {"path": str(inventory_path), "sha256": sha256(inventory_path)}
            record["command"] = adapter_command(case, config, output / label, inventory_path)
            if args.plan_only:
                continue
            if case["family"] != "healthy":
                record["common_load_evidence"] = below_capacity_evidence(manifest["trials"], case, config)
            if case["added_delay_ms"] and inventory is None:
                from network_delay import calibration
                os.environ["DELUGI_NETWORK_DELAY_MS"] = str(case["added_delay_ms"])
                record["delay_calibration"] = calibration(output / (label + "-calibration"), case["added_delay_ms"])
                if record["delay_calibration"]["status"] != "passed":
                    raise ValueError("requested network delay was not calibrated")
            else:
                os.environ.pop("DELUGI_NETWORK_DELAY_MS", None)
                os.environ.pop("DELUGI_SHAPER_CONTROL", None)
            record["started_unix_ns"] = time.time_ns()
            with (output / (label + ".log")).open("w") as log:
                process = subprocess.run(record["command"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            record["finished_unix_ns"] = time.time_ns()
            child = output / label / "manifest.json"
            record["manifest"] = {"path": str(child), "sha256": sha256(child)}
            data = json.loads(child.read_text())
            if process.returncode:
                raise RuntimeError(data.get("error", "native adapter failed"))
            record["fault_effect"] = validate_fault_effect(case, data)
            if case["added_delay_ms"] and inventory is None:
                record["delay_calibration_after"] = calibration(output / (label + "-calibration-after"), case["added_delay_ms"])
            accepted = validate_result(case, config, data, calibration=record.get("delay_calibration"),
                                       after_calibration=record.get("delay_calibration_after"),
                                       inventory=inventory, identities=manifest["artifact_identities"])
            # Recheck the original source and host-key inventory after the trial,
            # before any result can influence a measured frontier.
            if inventory is not None:
                case_inventory(case, config, manifest["remote_inventory_sources"])
            resources.accept_contract(manifest["resource_contracts"], accepted["resource_contract"])
            record.update(accepted)
            if case["family"] == "healthy" and frontier.enabled(config):
                record["stability_acceptance"] = frontier.stability_evidence(accepted["comparison"], case, config)
            manifest["artifact_identities"][case["protocol"]] = accepted["artifact_identity"]
            record["status"] = "passed"
        except (ValueError, RuntimeError, OSError, KeyError) as error:
            record.update(status="incomplete", reason=str(error))
        finally:
            for key, value in original_shaper_environment.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            write_json(output / "manifest.json", manifest)
    verify_spec_unchanged(manifest["specification"])
    if frontier.enabled(config) and not args.plan_only:
        manifest["healthy_frontiers"] = []
        for protocol in config["protocols"]:
            for nodes in config["nodes"]:
                for delay in config["added_delays_ms"]:
                    for bound in config["bounds_ms"]:
                        cell = {"protocol": protocol, "nodes": nodes, "added_delay_ms": delay, "bound_ms": bound}
                        try:
                            manifest["healthy_frontiers"].append(frontier.select_frontier(manifest["trials"], cell, config))
                        except ValueError as error:
                            manifest["healthy_frontiers"].append({**cell, "status": "incomplete", "reason": str(error)})
    manifest["status"] = ("planned" if args.plan_only else "passed") if all(
        row["status"] == ("planned" if args.plan_only else "passed") for row in manifest["trials"]) else "incomplete"
    if any(row.get("status") == "incomplete" for row in manifest.get("healthy_frontiers", [])):
        manifest["status"] = "incomplete"
    write_json(output / "manifest.json", manifest)
    print(json.dumps({"manifest": str(output / "manifest.json"), "status": manifest["status"]}))
    return 0 if manifest["status"] in ("passed", "planned") else 1


if __name__ == "__main__":
    raise SystemExit(main())
