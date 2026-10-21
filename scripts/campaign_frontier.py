"""Conservative selection from a declared native tuning/load grid.

This selects a measured operating point, never an extrapolated capacity. Every
configured repetition of that exact point must pass. Relative subwindows are
derived from authenticated origin-local ledgers; drain completion cannot erase
measurement-window backlog or pre-admission delay.
"""
from __future__ import annotations

import hashlib
import json
import math

import campaign_resources


TUNABLE = {
    "delugi": {"ingress_batch_ms", "max_batch_transactions", "arrival_queue_capacity", "ordering_mode", "resource_profile"},
    "mysticeti": {"ingress_batch_ms"},
    "autobahn": {"ingress_batch_ms", "batch_bytes"},
    "shoal": {"ingress_batch_ms", "batch_bytes"},
    "raptr": {"ingress_batch_ms"},
}
GRID_TUNABLE = {protocol: {"ingress_batch_ms"} | ({"max_batch_transactions"} if protocol == "delugi" else
                {"batch_bytes"} if protocol in ("autobahn", "shoal") else set()) for protocol in TUNABLE}


def enabled(config):
    return config.get("purpose") == "formal" or "frontier" in config or "native_tuning_grid" in config


def tuning_options(config, protocol):
    base = config.get("native_tuning", {}).get(protocol, {})
    grid = config.get("native_tuning_grid", {}).get(protocol, [{}])
    if not isinstance(base, dict) or not isinstance(grid, list) or not 1 <= len(grid) <= 32:
        raise ValueError("native tuning requires a map and a grid of 1..32 parameter maps")
    result, seen = [], set()
    for variation in grid:
        if not isinstance(variation, dict):
            raise ValueError("native tuning grid entries must be parameter maps")
        if not set(variation) <= GRID_TUNABLE[protocol]:
            raise ValueError("tuning grid may vary native batching only; scheduling mode and resource envelope must stay fixed")
        params = {"ingress_batch_ms": 10, **base, **variation}
        if not set(params) <= TUNABLE[protocol]:
            raise ValueError(f"{protocol} tuning contains an unsupported native parameter")
        for key, value in params.items():
            if key in ("ordering_mode", "resource_profile"):
                if not isinstance(value, str) or not value:
                    raise ValueError("named native tuning choices must be nonempty strings")
            elif type(value) is not int or value <= 0:
                raise ValueError("native batching/queue parameters must be positive integers")
        serialized = json.dumps(params, sort_keys=True, separators=(",", ":"))
        if serialized in seen:
            raise ValueError("duplicate effective native tuning points")
        seen.add(serialized)
        result.append({"id": hashlib.sha256(serialized.encode()).hexdigest(), "parameters": params})
    return result


def policy(config, rate):
    selected = config.get("frontier", {})
    if not isinstance(selected, dict) or not set(selected) <= {
            "tail_target_ms", "minimum_goodput_fraction", "maximum_net_backlog_growth",
            "maximum_backlog_excursion"}:
        raise ValueError("unknown frontier acceptance policy")
    target = selected.get("tail_target_ms", config["deadline_ms"])
    values = {"tail_target_ms": target,
        "minimum_goodput_fraction": selected.get("minimum_goodput_fraction", .95),
        "maximum_net_backlog_growth": selected.get("maximum_net_backlog_growth", 0),
        "maximum_backlog_excursion": selected.get("maximum_backlog_excursion", math.ceil(rate*target/1000))}
    for key, value in values.items():
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise ValueError("frontier policy values must be finite and nonnegative")
    if not target or not 0 < values["minimum_goodput_fraction"] <= 1:
        raise ValueError("positive common tail target and goodput fraction in (0,1] required")
    for key in ("maximum_net_backlog_growth", "maximum_backlog_excursion"):
        if type(values[key]) is not int:
            raise ValueError("backlog allowances are integer request counts")
    return values


def stability_evidence(comparison, case, config):
    """Fail closed on missing, contradictory or growing exact subwindow data."""
    acceptance = policy(config, case["rate"])
    cohort = comparison["cohort"]
    window = cohort["window"]
    data = window.get("stability")
    if not isinstance(data, dict) or data.get("schema") != 1 or data.get("subwindows") != 10:
        raise ValueError("frontier requires ten exact origin-local stability subwindows")
    samples, intervals = data.get("samples"), data.get("intervals")
    if not isinstance(samples, list) or len(samples) != 11 or not isinstance(intervals, list) or len(intervals) != 10:
        raise ValueError("incomplete stability subwindow population")
    for rows, index, fields in ((samples, "boundary", ("pending_admitted", "scheduled_not_output")),
                                (intervals, "interval", ("scheduled", "admitted", "completed", "rejected"))):
        for i, row in enumerate(rows):
            if not isinstance(row, dict) or row.get(index) != i or any(type(row.get(k)) is not int or row[k] < 0 for k in fields):
                raise ValueError("malformed exact subwindow counters")
    durations = data.get("origin_duration_us")
    origins = {str(row["origin"]) for row in cohort["origins"]}
    if not isinstance(durations, dict) or set(durations) != origins:
        raise ValueError("stability origin clock population differs from cohort")
    expected = config["measurement_seconds"] * 1_000_000
    if any(type(value) not in (int, float) or not math.isfinite(value) or abs(value-expected) > 1 for value in durations.values()):
        raise ValueError("stability subwindows do not cover the declared measurement duration")
    if (samples[0]["pending_admitted"] != window["pending_at_start"] or
            samples[-1]["pending_admitted"] != window["pending_at_end"] or
            sum(row["completed"] for row in intervals) != window["completion_count"] or
            sum(row["admitted"] for row in intervals) != window["admission_count"] or
            sum(row["scheduled"] for row in intervals) != cohort["scheduled"]):
        raise ValueError("stability subwindows contradict exact cohort totals")
    for i, interval in enumerate(intervals):
        for pending, arriving in (("pending_admitted", "admitted"), ("scheduled_not_output", "scheduled")):
            if samples[i+1][pending] != samples[i][pending] + interval[arriving] - interval["completed"]:
                raise ValueError("stability subwindow flow conservation failed")
    reasons = []
    if cohort["unfinished"] or cohort["rejected"]:
        reasons.append("unfinished or rejected intended cohort")
    for endpoint in ("admission_to_output", "scheduled_to_output"):
        quantile = cohort[endpoint]["p99"]
        value = quantile.get("value_ms")
        if (quantile.get("status") != "observed" or type(value) not in (int, float)
                or not math.isfinite(value) or value > acceptance["tail_target_ms"]):
            reasons.append(endpoint + " p99 is censored or exceeds the common tail target")
    if comparison["unique_completion_tps"] < case["rate"] * acceptance["minimum_goodput_fraction"]:
        reasons.append("measurement-window goodput below the declared offered-load fraction")
    backlog = {}
    for field in ("pending_admitted", "scheduled_not_output"):
        values = [row[field] for row in samples]
        backlog[field] = {"net_growth": values[-1]-values[0], "peak_excursion": max(values)-values[0]}
        if backlog[field]["net_growth"] > acceptance["maximum_net_backlog_growth"]:
            reasons.append(field + " grows across the window")
        if backlog[field]["peak_excursion"] > acceptance["maximum_backlog_excursion"]:
            reasons.append(field + " exceeds the allowed subwindow excursion")
    return {"eligible": not reasons, "reasons": reasons, "policy": acceptance, "backlog": backlog,
            "scope": "declared ten-subwindow stability and both censored p99 gates; finite measured operating point"}


def select_frontier(trials, case, config, protocol=None):
    protocol = protocol or case["protocol"]
    options = {row["id"]: row["parameters"] for row in tuning_options(config, protocol)}
    groups, resources, resource_validation = {}, set(), set()
    for trial in trials:
        prior = trial["case"]
        if (prior["family"] != "healthy" or prior["protocol"] != protocol or
                any(prior[key] != case[key] for key in ("nodes", "added_delay_ms", "bound_ms"))):
            continue
        if "healthy_rates" in config and prior["rate"] not in config["healthy_rates"]:
            raise ValueError("healthy trial rate differs from the declared offered-load grid")
        if trial.get("status") == "passed":
            contract, digest = trial.get("resource_contract"), trial.get("resource_contract_sha256")
            current_verified = (isinstance(contract, dict) and contract.get("schema") == campaign_resources.CONTRACT_SCHEMA
                                and contract.get("validation") == campaign_resources.VERIFIED)
            if config["purpose"] == "formal" or current_verified:
                campaign_resources.validate_verified_contract(contract, protocol, case["nodes"])
            resource_validation.add("current_verified" if current_verified else "legacy_or_unverified_diagnostic")
            if contract is not None or digest is not None:
                if (not isinstance(contract, dict) or not isinstance(digest, str) or
                        digest != hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()):
                    raise ValueError("frontier resource contract hash differs")
            resources.add(digest)
            if len(resources) > 1:
                raise ValueError("resource or placement contract changed across healthy frontier trials")
        tuning = prior.get("tuning_id", next(iter(options)) if len(options) == 1 else None)
        if tuning not in options or prior.get("tuning", options[tuning]) != options[tuning]:
            raise ValueError("healthy trial tuning differs from the declared native grid")
        key = (prior["rate"], tuning)
        groups.setdefault(key, {}).setdefault(prior["repeat"], []).append(trial)
    required = set(range(config["repeats"]))
    points = []
    for (rate, tuning), repeats in sorted(groups.items()):
        failures, evidence = [], []
        if set(repeats) != required or any(len(rows) != 1 for rows in repeats.values()):
            failures.append("missing or duplicate independent repetitions")
        for repeat, rows in sorted(repeats.items()):
            for trial in rows:
                if trial.get("status") != "passed":
                    failures.append(f"repeat {repeat} was not accepted")
                    continue
                check = stability_evidence(trial["comparison"], trial["case"], config)
                evidence.append({"trial": trial["label"], **check})
                failures.extend(check["reasons"])
        points.append({"rate": rate, "tuning_id": tuning, "tuning": options[tuning],
                       "eligible": not failures, "reasons": failures, "evidence": evidence})
    eligible = [point for point in points if point["eligible"]]
    if not eligible:
        raise ValueError(f"{protocol} lacks a repeated healthy frontier passing exact subwindows and the common tail target")
    # A deterministic tie-break avoids choosing a setting from one lucky run.
    winner = min(eligible, key=lambda point: (-point["rate"], point["tuning_id"]))
    return {"protocol": protocol, "nodes": case["nodes"], "added_delay_ms": case["added_delay_ms"],
            "bound_ms": case["bound_ms"], "tail_target_ms": policy(config, winner["rate"])["tail_target_ms"],
            "resource_contract_sha256": next(iter(resources)),
            "resource_validation": "current_verified" if resource_validation == {"current_verified"} else "legacy_or_unverified_diagnostic",
            "selected": winner, "points": points,
            "scope": "highest accepted offered load in the declared sampled tuning grid; no extrapolated maximum capacity"}


def resolve_case(trials, case, config):
    """Bind fault/secondary load to prior independent healthy repetitions."""
    if case["family"] == "healthy" or not enabled(config):
        return case, None
    frontier = select_frontier(trials, case, config)
    winner = frontier["selected"]
    result = {**case, "tuning_id": winner["tuning_id"], "tuning": winner["tuning"]}
    load = case.get("load_policy", {"kind": "common_offered_load"})
    if load["kind"] == "matched_utilization":
        rate = math.floor(winner["rate"] * load["fraction"])
        if not 0 < rate < winner["rate"]:
            raise ValueError("matched utilization does not yield a positive rate below the measured frontier")
        result["rate"] = rate
        result["load_policy"] = {**load, "resolved_rate": rate, "frontier_rate": winner["rate"],
                                 "rounding": "floor to integer committee-wide requests per second"}
        result.pop("execution_requirement", None)
        if case.get("scenario_execution_requirement"):
            result["execution_requirement"] = case["scenario_execution_requirement"]
    return result, frontier
