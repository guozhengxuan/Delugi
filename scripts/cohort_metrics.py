"""Protocol-independent, identity-based benchmark accounting (schema 1).

All *_us timestamps in a replica ledger use that replica's monotonic clock.
Only origin-local timestamps are subtracted. Remote output identity membership
establishes coverage at collection, never an invented remote event latency.
"""
from __future__ import annotations

import math
from bisect import bisect_left, bisect_right

SCHEMA = 1
ENDPOINT = "admission_to_origin_local_payload_verified_contiguous_output_v1"


def identity(value):
    if isinstance(value, list):
        if len(value) != 32 or any(type(x) is not int or not 0 <= x <= 255 for x in value):
            raise ValueError("request digest must contain 32 bytes")
        return bytes(value).hex()
    if not isinstance(value, str) or not value:
        raise ValueError("identity must be a nonempty string or 32-byte digest")
    return value


def number(value, label):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and nonnegative")
    return value


def quantiles(observed, censored):
    """Bounds for an empirical cohort, without dropping unfinished requests.

    A missing request is known only to exceed its observed age. An exact
    quantile is reported only when no censored request can move that rank.
    Completed-only quantiles are explicitly secondary diagnostics.
    """
    observed, censored = sorted(observed), sorted(censored)
    lower = sorted(observed + censored)
    result = {"population": len(lower), "completed": len(observed), "unfinished": len(censored)}
    for percentile in (50, 95, 99):
        rank = math.ceil(len(lower) * percentile / 100)
        candidate = observed[rank - 1] if rank and rank <= len(observed) else None
        exact = candidate is not None and (not censored or candidate <= censored[0])
        result[f"p{percentile}"] = {
            "value_ms": candidate / 1000 if exact else None,
            "lower_bound_ms": lower[rank - 1] / 1000 if rank else None,
            "status": "observed" if exact else ("censored" if rank else "empty"),
        }
    return result


def _request_key(row):
    return identity(row.get("request_id", row.get("id")))


def _validate_request(row, replica, observed_us, collected_us=None, *, batch_ready_available=True, batch_ready_precedes_materialization=True):
    if type(batch_ready_precedes_materialization) is not bool:
        raise ValueError("batch-ready ordering must be an explicit boolean")
    if type(batch_ready_available) is not bool:
        raise ValueError("batch-ready availability must be an explicit boolean")
    collected_us = observed_us if collected_us is None else number(collected_us, "collected_us")
    if collected_us < observed_us:
        raise ValueError("collection precedes materialization freeze")
    if row["origin"] != replica:
        raise ValueError("origin ledger contains another origin's request")
    number(row["useful_bytes"], "useful_bytes")
    previous = number(row["scheduled_us"], "scheduled_us")
    stages = ("admitted_us",) + (("batch_ready_us",) if batch_ready_precedes_materialization and (batch_ready_available or row.get("batch_ready_us") is not None) else ()) + ("materialized_us",)
    for position, stage in enumerate(stages):
        value = row.get(stage)
        if value is None:
            if any(row.get(next_stage) is not None for next_stage in
                   stages[position + 1:]):
                raise ValueError("later stage without preceding stage")
            break
        number(value, stage)
        if value < previous or value > observed_us:
            raise ValueError(f"invalid monotonic stage ordering: {stage}")
        previous = value
    if not batch_ready_precedes_materialization and row.get("batch_ready_us") is not None:
        value = number(row["batch_ready_us"], "batch_ready_us")
        if row.get("admitted_us") is None or not row["admitted_us"] <= value <= observed_us:
            raise ValueError("own batch readiness precedes admission or exceeds observation")
    if row.get("rejected_us") is not None:
        if row.get("admitted_us") is not None:
            raise ValueError("request cannot be admitted and rejected")
        if not row["scheduled_us"] <= row["rejected_us"] <= observed_us:
            raise ValueError("invalid rejection time")
    if row.get("all_correct_observed_us") is not None and (
            row.get("materialized_us") is None or row["all_correct_observed_us"] < row["materialized_us"] or row["all_correct_observed_us"] > collected_us):
        raise ValueError("all-correct observation precedes own output or exceeds collection")
    if row.get("post_handler_published_us") is not None and (
            row.get("materialized_us") is None or not row["materialized_us"] <= row["post_handler_published_us"] <= collected_us):
        raise ValueError("publication precedes materialization or exceeds collection")


def window_stability(ledgers, correct, rows):
    """Ten exact relative subwindows, using one origin clock per request.

    ``rows(origin)`` streams (scheduled, admitted, materialized, rejected).
    Memory is O(committee + 10), independent of the request population. The
    scheduled backlog includes rejected work, so admission throttling or drops
    cannot make an overloaded offered workload appear stable.
    """
    samples = [{"boundary": i, "pending_admitted": 0, "scheduled_not_output": 0} for i in range(11)]
    intervals = [{"interval": i, "scheduled": 0, "admitted": 0, "completed": 0, "rejected": 0} for i in range(10)]
    durations = {}
    for origin in correct:
        start, end = (ledgers[origin][key] for key in ("window_start_us", "window_end_us"))
        durations[str(origin)] = end - start
        # Keep integral native clocks integral even above IEEE-754's exact
        # integer range; rounding an absolute epoch can collapse boundaries.
        boundaries = [start + (end-start)*i//10 for i in range(11)]
        for scheduled, admitted, done, rejected in rows(origin):
            for boundary, sample in zip(boundaries, samples):
                unfinished = done is None or done >= boundary
                sample["pending_admitted"] += int(admitted is not None and admitted < boundary and unfinished)
                sample["scheduled_not_output"] += int(scheduled < boundary and unfinished)
            for field, stamp in (("scheduled", scheduled), ("admitted", admitted),
                                 ("completed", done), ("rejected", rejected)):
                if stamp is not None and start <= stamp < end:
                    intervals[bisect_right(boundaries, stamp)-1][field] += 1
    return {"schema": 1, "subwindows": 10, "origin_duration_us": durations,
            "clock": "equal fractions of each origin's own measurement window, floored to microseconds; no cross-host timestamp subtraction",
            "boundary": "half-open intervals; pending immediately before each boundary; scheduled_not_output retains rejected and not-yet-admitted requests",
            "samples": samples, "intervals": intervals}


def summarize_cohorts(ledgers, *, correct_replicas=None, deadline_ms=1000, output_replica=None):
    """Reduce frozen/paginated native ledgers; preserve unfinished/zero output.

    Per-replica ledger: requests, outputs, batches, window_start_us,
    window_end_us, observed_us. The request cohort is intended arrivals in the
    half-open measurement window. Goodput is unique honest origin-local output
    during that window, including carried-in work (separately counted).
    """
    number(deadline_ms, "deadline_ms")
    ledgers = {int(k): v for k, v in ledgers.items()}
    correct = sorted(ledgers if correct_replicas is None else correct_replicas)
    if not correct or len(correct) != len(set(correct)) or not set(correct) <= set(ledgers):
        raise ValueError("nonempty unique correct replica set required")
    output_replica = correct[0] if output_replica is None else output_replica
    if output_replica not in correct:
        raise ValueError("reference output replica must be correct")
    all_requests, requests_by_origin, outputs_by_replica = {}, {}, {}
    for replica, ledger in sorted(ledgers.items()):
        start, end, observed = (number(ledger[k], k) for k in
                                ("window_start_us", "window_end_us", "observed_us"))
        if end <= start or observed < end:
            raise ValueError("ledger must cover a positive finished measurement window")
        own = {}
        for row in ledger["requests"]:
            _validate_request(row, replica, observed, ledger.get("collected_us"), batch_ready_available=ledger.get("batch_ready_available", True), batch_ready_precedes_materialization=ledger.get("batch_ready_precedes_materialization", True))
            key = _request_key(row)
            if key in all_requests:
                raise ValueError("duplicate request identity in admission ledgers")
            all_requests[key] = row
            own[key] = row
        requests_by_origin[replica] = own
        outputs = {}
        prior_index = -1
        for row in ledger["outputs"]:
            key = _request_key(row)
            index = number(row["output_index"], "output_index")
            if int(index) != index or index <= prior_index:
                raise ValueError("output entries must have increasing exact ordinals")
            prior_index = index
            timestamp = number(row["materialized_us"], "materialized_us")
            if timestamp > observed:
                raise ValueError("output is later than ledger observation")
            # Replayed application IDs in different exact batches are retained
            # in the raw output but only the first contributes useful goodput.
            outputs.setdefault(key, row)
        outputs_by_replica[replica] = outputs

    for replica, outputs in outputs_by_replica.items():
        for key, row in outputs.items():
            request = all_requests.get(key)
            if request is not None and (row["origin"] != request["origin"] or
                                        row["useful_bytes"] != request["useful_bytes"]):
                raise ValueError("output identity content disagrees with admitted manifest")

    origins, admission_latencies, admission_censored = [], [], []
    scheduled_latencies, scheduled_censored, cohort_ids = [], [], set()
    completion_count = useful_bytes = carried_in = admission_count = 0
    pending_at_start = pending_at_end = 0
    useful_rate = completion_rate = admission_rate = 0
    for replica in correct:
        ledger = ledgers[replica]
        start, end, observed = (ledger[k] for k in ("window_start_us", "window_end_us", "observed_us"))
        cohort = {k: r for k, r in requests_by_origin[replica].items() if start <= r["scheduled_us"] < end}
        cohort_ids.update(cohort)
        complete = admitted = rejected = deadline_complete = pending = deadline_unresolved = 0
        oldest = 0
        for key, row in cohort.items():
            done, ingress = row.get("materialized_us"), row.get("admitted_us")
            if ingress is not None:
                admitted += 1
                (admission_latencies if done is not None else admission_censored).append(
                    (done if done is not None else observed) - ingress)
            if row.get("rejected_us") is not None:
                rejected += 1
            if done is not None:
                local_output = outputs_by_replica[replica].get(key)
                if local_output is None or local_output["materialized_us"] != done:
                    raise ValueError("local completion does not reconcile with exact output ledger")
                complete += 1
                scheduled_latencies.append(done - row["scheduled_us"])
                deadline_complete += done <= row["scheduled_us"] + deadline_ms * 1000
            else:
                age = observed - row["scheduled_us"]
                scheduled_censored.append(age)
                oldest = max(oldest, age)
                pending += row.get("rejected_us") is None
                deadline_unresolved += row.get("rejected_us") is None and observed < row["scheduled_us"] + deadline_ms * 1000
        window_output = [(k, r) for k, r in outputs_by_replica[replica].items()
                         if r["origin"] == replica and k in requests_by_origin[replica]
                         and requests_by_origin[replica][k].get("admitted_us") is not None
                         and requests_by_origin[replica][k].get("materialized_us") is not None
                         and requests_by_origin[replica][k]["admitted_us"] <= r["materialized_us"]
                         and start <= r["materialized_us"] < end]
        count, volume = len(window_output), sum(r["useful_bytes"] for _, r in window_output)
        carried = sum(requests_by_origin[replica][k]["scheduled_us"] < start for k, _ in window_output)
        duration = (end - start) / 1_000_000
        window_admissions = sum(r.get("admitted_us") is not None and start <= r["admitted_us"] < end
                                for r in requests_by_origin[replica].values())
        admission_count += window_admissions
        admission_rate += window_admissions / duration
        def pending_at(boundary):
            return sum(row.get("admitted_us") is not None and row["admitted_us"] < boundary
                       and (row.get("materialized_us") is None or row["materialized_us"] >= boundary)
                       for row in requests_by_origin[replica].values())
        pending_at_start += pending_at(start)
        pending_at_end += pending_at(end)
        completion_count += count
        useful_bytes += volume
        carried_in += carried
        completion_rate += count / duration
        useful_rate += volume / duration
        origins.append({"origin": replica, "scheduled": len(cohort), "admitted": admitted,
                        "rejected": rejected, "completed": complete, "unfinished": len(cohort) - complete,
                        "pending": pending, "deadline_completed": deadline_complete,
                        "deadline_unresolved": deadline_unresolved,
                        "deadline_missed": len(cohort) - deadline_complete - deadline_unresolved,
                        "deadline_completion_fraction": deadline_complete / len(cohort) if cohort else None,
                        "deadline_completion_fraction_upper_bound": (deadline_complete + deadline_unresolved) / len(cohort) if cohort else None,
                        "oldest_outstanding_ms": oldest / 1000,
                        "window_completion_count": count, "window_u_out_bytes": volume,
                        "window_seconds": duration})
    all_correct_ids = set.intersection(*(set(outputs_by_replica[r]) for r in correct))
    observed_everywhere = {key for key in cohort_ids & all_correct_ids
                           if all_requests[key].get("admitted_us") is not None
                           and all_requests[key].get("materialized_us") is not None}
    reference = ledgers[output_replica]
    seen_batches, batch_bytes, total_batch_bytes = set(), 0, 0
    for row in reference["batches"]:
        key = identity(row["exact_batch_id"])
        if key in seen_batches:
            raise ValueError("duplicate exact batch identity in materialized batch ledger")
        seen_batches.add(key)
        total_batch_bytes += number(row["payload_bytes"], "payload_bytes")
        if reference["window_start_us"] <= row["materialized_us"] < reference["window_end_us"]:
            batch_bytes += number(row["payload_bytes"], "payload_bytes")
    total_scheduled = len(cohort_ids)
    fractions = [r["deadline_completion_fraction"] for r in origins if r["scheduled"]]
    # Admission is checked at the origin; reference output membership is checked
    # locally at the declared output prefix. Different replica clocks are never
    # subtracted to decide whether a remote materialization preceded admission.
    reference_useful = {key: all_requests[key] for key in outputs_by_replica[output_replica]
                        if key in all_requests and all_requests[key]["origin"] in correct
                        and all_requests[key].get("admitted_us") is not None
                        and all_requests[key].get("materialized_us") is not None}
    known_prefix_count = max((r["output_index"] + 1 - reference.get("output_index_base", 1) for r in reference["outputs"]), default=0)
    output_prefix_count = reference.get("output_prefix_count", known_prefix_count)
    if type(output_prefix_count) is not int or output_prefix_count < known_prefix_count:
        raise ValueError("declared output prefix is smaller than an exact output ordinal")
    result = {
        "schema": SCHEMA, "endpoint_contract": ENDPOINT,
        "clock": "per-origin monotonic; remote membership has no cross-clock latency",
        "cohort": "honest-origin intended arrivals in each half-open measurement window",
        "deadline_ms": deadline_ms, "deadline_start": "intended_submission",
        "origins": origins, "scheduled": total_scheduled,
        "admitted": sum(r["admitted"] for r in origins), "rejected": sum(r["rejected"] for r in origins),
        "completed": sum(r["completed"] for r in origins), "unfinished": sum(r["unfinished"] for r in origins),
        "deadline_completion_fraction": sum(r["deadline_completed"] for r in origins) / total_scheduled if total_scheduled else None,
        "deadline_fraction_status": "lower_bound" if any(r["deadline_unresolved"] for r in origins) else "observed",
        "deadline_unresolved": sum(r["deadline_unresolved"] for r in origins),
        "deadline_missed": sum(r["deadline_missed"] for r in origins),
        "deadline_completion_fraction_upper_bound": sum(r["deadline_completed"] + r["deadline_unresolved"] for r in origins) / total_scheduled if total_scheduled else None,
        "worst_origin_deadline_completion_fraction": min(fractions) if fractions else None,
        "admission_to_output": quantiles(admission_latencies, admission_censored),
        "scheduled_to_output": quantiles(scheduled_latencies, scheduled_censored),
        "all_correct_collection": {"completed": len(observed_everywhere),
                                   "unfinished": total_scheduled - len(observed_everywhere),
                                   "fraction": len(observed_everywhere) / total_scheduled if total_scheduled else None,
                                   "boundary": "final exact output collection; not remote event latency"},
        "window": {"completion_count": completion_count, "unique_completion_tps": completion_rate,
                   "stability": window_stability(ledgers, correct, lambda origin: (
                       (r["scheduled_us"], r.get("admitted_us"), r.get("materialized_us"), r.get("rejected_us"))
                       for r in requests_by_origin[origin].values())),
                   "admission_count": admission_count, "admission_tps": admission_rate,
                   "pending_at_start": pending_at_start, "pending_at_end": pending_at_end,
                   "pending_boundary": "honest own-origin admitted requests without exact local materialization at each half-open window boundary",
                   "u_out_bytes": useful_bytes, "useful_goodput_bytes_per_second": useful_rate,
                   "carried_in_completion_count": carried_in,
                   "m_out_bytes": batch_bytes, "m_out_replica": output_replica,
                   "m_out_boundary": "distinct exact batch payloads in selected replica measurement window"},
        "finite_run": {"m_out_bytes": total_batch_bytes,
                       "u_out_bytes": sum(row["useful_bytes"] for row in reference_useful.values()),
                       "unique_honest_completion_count": len(reference_useful),
                       "output_replica": output_replica,
                       "output_prefix_count": output_prefix_count,
                       "boundary": "selected final output prefix intersected with honest origin admission-to-output completions; setup/warmup/drain retained"},
    }
    selected = [(replica, row) for replica in correct for row in ledgers[replica]["requests"]
                if ledgers[replica]["window_start_us"] <= row["scheduled_us"] < ledgers[replica]["window_end_us"]]
    if selected and all("all_correct_observed_us" in row for _, row in selected):
        complete, censored, before_deadline, unresolved = [], [], 0, 0
        per_origin = {replica: {"scheduled": 0, "observed_by_deadline": 0} for replica in correct}
        for replica, row in selected:
            per_origin[replica]["scheduled"] += 1
            at = row["all_correct_observed_us"]
            deadline = row["scheduled_us"] + deadline_ms * 1000
            if at is not None:
                complete.append(at - row["scheduled_us"])
                before_deadline += at <= deadline
                per_origin[replica]["observed_by_deadline"] += at <= deadline
            else:
                censored.append(ledgers[replica].get("collected_us", ledgers[replica]["observed_us"]) - row["scheduled_us"])
                unresolved += ledgers[replica].get("collected_us", ledgers[replica]["observed_us"]) < deadline
        fractions = [r["observed_by_deadline"] / r["scheduled"] for r in per_origin.values() if r["scheduled"]]
        result["all_correct_origin_observed"] = {
            "endpoint": "notification of verified common output prefix received on origin's own monotonic clock; includes polling/controller/return delay",
            "scheduled_to_observation": quantiles(complete, censored), "deadline_unresolved": unresolved,
            "deadline_completion_fraction_lower_bound": before_deadline / len(selected),
            "worst_origin_deadline_completion_fraction_lower_bound": min(fractions) if fractions else None,
            "origins": per_origin}
    return result


def cost_ratios(written_bytes, cohort, *, boundary="window"):
    """Keep absolute costs when either output denominator is zero."""
    number(written_bytes, "written_bytes")
    window = cohort[boundary]
    return {"boundary": boundary, "written_bytes": written_bytes,
            "written_bytes_per_u_out_byte": written_bytes / window["u_out_bytes"] if window["u_out_bytes"] else None,
            "written_bytes_per_m_out_byte": written_bytes / window["m_out_bytes"] if window["m_out_bytes"] else None}


def observed_all_correct_deadlines(ledgers, observations, *, correct_replicas, deadline_ms):
    """Notification-observed completion using bounded local clock bridges.

    This variant is for independent processes on ONE host sharing a monotonic
    clock frequency. A snapshot's local sample occurred between controller send
    and receive, giving a conservative epoch offset interval. A distributed
    deployment must provide calibrated bridges instead of claiming this model.
    Poll/return delay is included in completion, not subtracted away.
    """
    correct = list(correct_replicas)
    by_replica = {replica: [] for replica in correct}
    offsets = {replica: [] for replica in correct}
    for row in observations:
        replica = row["replica"]
        if replica not in by_replica:
            continue
        low = row["start_monotonic_us"] - row["elapsed_us"]
        high = row["received_monotonic_us"] - row["elapsed_us"]
        if high < low:
            raise ValueError("snapshot receive precedes send")
        offsets[replica].append((low, high))
        by_replica[replica].append(row)
    bridges, prefix_counts = {}, {}
    for replica in correct:
        if not offsets[replica]:
            raise ValueError("missing origin/controller clock bridge")
        low = max(x[0] for x in offsets[replica])
        high = min(x[1] for x in offsets[replica])
        if low > high:
            raise ValueError("inconsistent same-host monotonic clock bridges")
        bridges[replica] = (low, high)
        by_replica[replica].sort(key=lambda x: x["received_monotonic_us"])
        prefix_counts[replica] = [r["executed_count"] for r in by_replica[replica]]
        if prefix_counts[replica] != sorted(prefix_counts[replica]):
            raise ValueError("observed output prefix regressed")
    output_positions = {replica: {} for replica in correct}
    for replica in correct:
        base = ledgers[replica].get("output_index_base", 1)
        if base not in (0, 1):
            raise ValueError("output_index_base must be zero or one")
        for row in ledgers[replica]["outputs"]:
            # Filtered ledgers can omit unknown application records, so the
            # real native ordinal, never enumerate(), determines the prefix.
            count = row["output_index"] + 1 - base
            if count <= 0:
                raise ValueError("invalid native output ordinal")
            output_positions[replica].setdefault(_request_key(row), count)
    rows = []
    for origin in correct:
        ledger = ledgers[origin]
        tally = {"origin": origin, "scheduled": 0, "observed_by_deadline": 0,
                 "clock_boundary_uncertain": 0, "not_observed_by_deadline": 0,
                 "unfinished_at_collection": 0, "deadline_unresolved_at_collection": 0}
        for request in ledger["requests"]:
            if not ledger["window_start_us"] <= request["scheduled_us"] < ledger["window_end_us"]:
                continue
            tally["scheduled"] += 1
            key, received = _request_key(request), []
            for replica in correct:
                count = output_positions[replica].get(key)
                index = bisect_left(prefix_counts[replica], count) if count is not None else len(prefix_counts[replica])
                observed = by_replica[replica][index]["received_monotonic_us"] if index < len(prefix_counts[replica]) else None
                if observed is None:
                    break
                received.append(observed)
            if len(received) != len(correct):
                tally["unfinished_at_collection"] += 1
                latest = min(max(r["received_monotonic_us"] for r in by_replica[replica]) for replica in correct)
                deadline_high = request["scheduled_us"] + deadline_ms * 1000 + bridges[origin][1]
                if latest < deadline_high:
                    tally["deadline_unresolved_at_collection"] += 1
                else:
                    tally["not_observed_by_deadline"] += 1
                continue
            observed = max(received)
            deadline = request["scheduled_us"] + deadline_ms * 1000
            low, high = bridges[origin]
            if observed <= deadline + low:
                tally["observed_by_deadline"] += 1
            elif observed <= deadline + high:
                tally["clock_boundary_uncertain"] += 1
            else:
                tally["not_observed_by_deadline"] += 1
        tally["completion_fraction_lower_bound"] = tally["observed_by_deadline"] / tally["scheduled"] if tally["scheduled"] else None
        rows.append(tally)
    denominator = sum(r["scheduled"] for r in rows)
    fractions = [r["completion_fraction_lower_bound"] for r in rows if r["scheduled"]]
    return {"clock_model": "single-host monotonic epoch bridges bounded by control request round trips",
            "completion_endpoint": "controller receipt of exact output-prefix snapshots at every correct replica; includes polling and return delay",
            "deadline_ms": deadline_ms, "deadline_start": "intended_submission",
            "clock_offset_bounds_us": bridges, "origins": rows,
            "scheduled": denominator,
            "completion_fraction_lower_bound": sum(r["observed_by_deadline"] for r in rows) / denominator if denominator else None,
            "worst_origin_completion_fraction_lower_bound": min(fractions) if fractions else None,
            "clock_boundary_uncertain": sum(r["clock_boundary_uncertain"] for r in rows),
            "deadline_unresolved_at_collection": sum(r["deadline_unresolved_at_collection"] for r in rows),
            "unfinished_at_collection": sum(r["unfinished_at_collection"] for r in rows)}
