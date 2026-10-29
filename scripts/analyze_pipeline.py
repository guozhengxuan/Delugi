#!/usr/bin/env python3
"""Audit saved TCP-delay runs without starting replicas or subtracting host clocks.

Run with a Python environment containing matplotlib to also create the figure.
The JSON audit otherwise uses only the standard library and existing reducers.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import statistics

from cohort_metrics import identity
from cohort_store import ShardedArchive, sha_file
from latency_decomposition import analyze as request_decomposition


SPANS = {
    "report_to_pool_ms": ("report_us", "pool_us"),
    "pool_to_input_ms": ("pool_us", "input_us"),
    "input_to_proposal_ms": ("input_us", "proposal_us"),
    "proposal_to_direct_commit_ms": ("proposal_us", "direct_us"),
}


def stats(values):
    values = sorted(values)
    if not values:
        return {"count": 0, "mean": None, "median": None, "p95": None, "min": None, "max": None}
    return {"count": len(values), "mean": statistics.fmean(values), "median": statistics.median(values),
            "p95": values[math.ceil(.95 * len(values)) - 1], "min": values[0], "max": values[-1]}


def read(path):
    return json.loads(Path(path).read_bytes())


def first(events, event, kind=None):
    return next((e for e in events if e["event"] == event and
                 (kind is None or e["detail"].get("kind") == kind)), None)


def proxy_metrics(report):
    if not report.get("thread_stopped") or not report.get("connections"):
        raise ValueError("proxy absent or not stopped")
    if any(row["exit_code"] is None for row in report.get("owned_replica_processes", [])):
        raise ValueError("replica remained alive")
    result = {"configured_one_way_ms": report["delay_ms_per_direction"]}
    for direction in ("client_to_replica", "replica_to_client"):
        rows = []
        for connection in report["connections"]:
            if not connection.get("closed") or connection.get("error"):
                raise ValueError("proxy connection failed")
            row = connection[direction]
            if row["read_bytes"] != row["forwarded_bytes"] or row["queue_capacity_waits"]:
                raise ValueError("proxy dropped bytes or saturated")
            if row["forwarded_chunks"]:
                if row["forward_delay_min_us"] < report["delay_ms_per_direction"] * 1000 - 100:
                    raise ValueError("proxy forwarded early")
                rows.append(row)
        chunks = sum(row["forwarded_chunks"] for row in rows)
        result[direction] = {
            "chunks": chunks, "bytes": sum(row["forwarded_bytes"] for row in rows),
            "mean_hold_ms": sum(row["forward_delay_sum_us"] for row in rows) / chunks / 1000 if chunks else None,
            "min_hold_ms": min((row["forward_delay_min_us"] / 1000 for row in rows), default=None),
            "max_hold_ms": max((row["forward_delay_max_us"] / 1000 for row in rows), default=None),
            "peak_queued_chunks": max((row["peak_queued_chunks"] for row in rows), default=0),
        }
    result.update(no_discarded_bytes=True, no_queue_saturation=True,
                  definition="chunk read to asyncio write, before drain; not end-to-end one-way network delay")
    return result


def leader_rows(replica, trace, ledger):
    grouped = defaultdict(list)
    for event in sorted(trace["events"], key=lambda e: e["at_us"]):
        grouped[event["round"]].append(event)
    result = []
    for round_number, events in sorted(grouped.items()):
        proposal = first(events, "ordering_outbox", "PROPOSE")
        if proposal is None:
            continue
        if proposal["detail"]["signer"] != replica:
            raise ValueError("leader outbox signer differs from trace owner")
        if sum(e["event"] == "ordering_outbox" and e["detail"].get("kind") == "PROPOSE" for e in events) != 1:
            raise ValueError("more than one leader proposal outbox for one round")
        markers = {"report": first(events, "dissemination_outbox", "REPORT"),
                   "pool": first(events, "observation_pool_fixed"),
                   "input": first(events, "input_fixed"), "proposal": proposal,
                   "direct": first(events, "direct_commit"),
                   "admission": first(events, "admission"),
                   "history": first(events, "history_quorum")}
        validated = first(events, "proposal_validated")
        if markers["direct"] and (validated is None or
                identity(validated["detail"]["digest"]) != identity(markers["direct"]["detail"]["digest"])):
            raise ValueError("leader proposal validation and direct commit have different digests")
        row = {"replica": replica, "round": round_number,
               **{name + "_us": event["at_us"] if event else None for name, event in markers.items()}}
        row["in_measurement_window"] = ledger["window_start_us"] <= proposal["at_us"] < ledger["window_end_us"]
        row["report_detail"] = markers["report"]["detail"] if markers["report"] else None
        row["pool_signers"] = markers["pool"]["detail"].get("signers") if markers["pool"] else None
        row["missing_spans"] = []
        for name, (start, end) in SPANS.items():
            row[name] = None
            if row[start] is None or row[end] is None:
                row["missing_spans"].append(name)
            elif row[start] > row[end]:
                raise ValueError(f"nonsequential same-round leader markers: {replica}/{round_number}/{name}")
            else:
                row[name] = (row[end] - row[start]) / 1000
        if row["report_us"] is not None and row["history_us"] is not None:
            row["report_before_history_quorum"] = row["report_us"] < row["history_us"]
            row["report_to_history_quorum_ms"] = (row["history_us"] - row["report_us"]) / 1000
        result.append(row)
    return result


def normalized_cadence(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["replica"]].append(row)
    intervals = []
    for replica, own in sorted(grouped.items()):
        own.sort(key=lambda row: row["round"])
        for left, right in zip(own, own[1:]):
            if not left["in_measurement_window"] or not right["in_measurement_window"]:
                continue
            gap = right["round"] - left["round"]
            elapsed_ms = (right["proposal_us"] - left["proposal_us"]) / 1000
            if gap <= 0 or elapsed_ms < 0:
                raise ValueError("nonmonotonic own-leader proposal sequence")
            intervals.append({"replica": replica, "from_round": left["round"], "to_round": right["round"],
                              "round_gap": gap, "elapsed_ms": elapsed_ms,
                              "normalized_ms_per_round": elapsed_ms / gap})
    return intervals


def completion_checks(result, decomposition):
    """Final intended cohorts are distinct from half-open window completions."""
    cohort = result["cohort"]
    return {
        "drain_complete": result["drain_complete"],
        "correct_replica_prefixes_agree": result["agreement"]["all_correct_overlap_prefixes_verified"],
        "intended_cohort_complete": cohort["scheduled"] == cohort["completed"] and cohort["unfinished"] == 0,
        "all_correct_collection_complete": cohort["all_correct_collection"]["completed"] == cohort["scheduled"],
        "request_stage_coverage_complete": decomposition["covered"] == cohort["scheduled"] and not decomposition["excluded"],
    }


def guard_evidence(replica, trace, config):
    """Check instrumented typed guards; retained core performs signature checks."""
    n = len(config["addresses"])
    f = (n - 1) // 3
    counts = Counter()

    def signers(values):
        if not isinstance(values, list) or any(type(value) is not int or not 0 <= value < n for value in values):
            raise ValueError("invalid instrumented signer identity")
        if len(set(values)) != len(values):
            raise ValueError("duplicate instrumented quorum signer")
        return len(values)

    for event in trace["events"]:
        detail, round_number = event["detail"], event["round"]
        if event["event"] == "progress_quorum":
            if signers(detail["signers"]) < n - f or detail["admit"] != round_number + 1:
                raise ValueError("progress quorum instrumentation violates admission guard")
            counts["progress_quorums_with_distinct_n_minus_f_signers"] += 1
        elif event["event"] == "observation_pool_fixed":
            if signers(detail["signers"]) != n - f or (round_number - 1) % n != replica:
                raise ValueError("observation pool is not an exact distinct n-f leader pool")
            counts["pools_with_exact_distinct_n_minus_f_signers"] += 1
        elif event["event"] == "dissemination_outbox" and detail.get("kind") == "REPORT":
            if config["report_schedule"] != "pipeline":
                continue
            if (type(detail["admitted"]) is not int or type(detail["local_report_horizon"]) is not int
                    or detail["local_report_horizon"] < 0 or type(detail["exact_history_ready"]) is not bool):
                raise ValueError("invalid typed pipeline preparation state")
            if (detail["signer"] != replica or (round_number - 1) % n != replica or
                    detail["admitted"] < round_number or detail["schedule"] != "pipeline"):
                raise ValueError("pipeline REPORT violates leader/admission guard")
            branches = {
                "initial_four_rounds": round_number <= 4,
                "own_terminal_prefix_plus_four": round_number > 4 and detail["local_report_horizon"] >= round_number - 4,
                "f_plus_one_closed": signers(detail["closed_signers"]) >= f + 1,
                "exact_history_ready": detail["exact_history_ready"],
            }
            if not any(branches.values()):
                raise ValueError("pipeline REPORT has no justified bounded-preparation branch")
            counts["pipeline_reports_with_satisfied_guard"] += 1
            for name, satisfied in branches.items():
                if satisfied:
                    counts["report_branch_true_" + name] += 1
    return counts


def analyze_run(root):
    root = Path(root).resolve()
    manifest = read(root / "manifest.json")
    trial = root / "sustained"
    result = read(trial / "diagnostic-result.json")
    if manifest["status"] != "passed" or result["status"] != "passed":
        raise ValueError("only completed, passed archived runs can be analyzed")
    # Check retained measured evidence against the original run manifest.
    artifacts = {row["path"]: row["sha256"] for row in manifest["artifacts"]}
    evidence = [trial / "diagnostic-result.json", trial / "result.json", trial / "config.json",
                trial / "proxy.json", trial / "cohorts/index.json"]
    for entry in result["causal_trace"]["files"]:
        evidence.append(trial / "causal-traces" / f"replica-{entry['replica']}.json")
    for path in evidence:
        if artifacts.get(path.relative_to(root).as_posix()) != sha_file(path):
            raise ValueError(f"retained run artifact changed: {path}")
    config = read(trial / "config.json")
    if (not result["causal_trace"].get("complete") or
            sorted(entry["replica"] for entry in result["causal_trace"]["files"]) != list(range(len(config["addresses"])))):
        raise ValueError("causal traces do not cover every configured replica")
    archive = ShardedArchive(trial / "cohorts/index.json")
    authentication = result["cohort_authentication"]
    if authentication.get("verified") is not True or authentication["index_sha256"] != archive.index_sha256:
        raise ValueError("cohort archive does not match retained authentication result")
    rows, trace_meta, timer_counts, guard_counts = [], [], Counter(), Counter()
    for entry in result["causal_trace"]["files"]:
        replica = entry["replica"]
        path = trial / "causal-traces" / f"replica-{replica}.json"
        trace = read(path)
        if (sha_file(path) != entry["sha256"] or trace["replica"] != replica or
                trace["schema"] != "delugi-causal-trace-v1" or trace["dropped"] or
                trace["run_error"] is not None or trace["total"] != len(trace["events"])):
            raise ValueError("incomplete, changed, or mismatched causal trace")
        if dict(Counter(e["event"] for e in trace["events"])) != trace["counts"]:
            raise ValueError("trace event counts disagree")
        context = first(trace["events"], "run_context")
        if context is None or context["detail"]["instance"] != config["instance"]:
            raise ValueError("trace does not belong to this run")
        ledger = archive.ledgers[replica]
        if ledger.get("manifest") and ledger["manifest"]["body"]["instance"] != config["instance"]:
            raise ValueError("cohort does not belong to this run")
        # Consume all shard iterators to execute their terminal hash checks.
        for stream in ("requests", "outputs", "batches"):
            for _ in archive.rows(replica, stream):
                pass
        rows.extend(leader_rows(replica, trace, ledger))
        guard_counts.update(guard_evidence(replica, trace, config))
        timer_counts.update({name: trace["counts"].get(name, 0) for name in
                             ("main_timer_expiry", "catchup_timer_expiry", "no_cer")})
        trace_meta.append({"replica": replica, "events": trace["total"], "dropped": trace["dropped"],
                           "detail_stride": trace["detail_stride"], "run_bound": True})
    intervals = normalized_cadence(rows)
    window_rows = [row for row in rows if row["in_measurement_window"]]
    complete_rows = [row for row in window_rows if not row["missing_spans"]]
    decomposition = request_decomposition(trial / "cohorts/index.json", trial / "causal-traces")
    cohort = result["cohort"]
    agreement = result["agreement"]
    correct = result["comparison"]["correct_replicas"]
    checks = {
        "no_trace_drops": all(row["dropped"] == 0 for row in trace_meta),
        "retained_cohort_authentication_verified": True,
        "instrumented_quorum_and_preparation_guards_hold": True,
        **completion_checks(result, decomposition),
    }
    summary = {
        "run": str(root), "status": "verified" if all(checks.values()) else "incomplete_coverage",
        "analysis_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "manifest_sha256": sha_file(root / "manifest.json"),
        "binary_sha256": manifest["binary"]["sha256"], "checks": checks,
        "settings": {name: config.get(name) for name in
                     ("bound_ms", "ordering_mode", "ordering_batch", "report_schedule", "silent", "sustained")},
        "correct_replicas": correct, "traces": trace_meta,
        "cohort": {name: cohort[name] for name in ("scheduled", "admitted", "rejected", "completed", "unfinished")},
        "window_completions": {"count": result["comparison"]["completion_count"],
                               "carried_in": cohort["window"].get("carried_in_completion_count"),
                               "definition": "completions during the half-open measurement window, distinct from final intended-cohort completion"},
        "deadline_missed": cohort["deadline_missed"],
        "all_correct_collection": cohort["all_correct_collection"],
        "agreement": {name: agreement.get(name) for name in
                      ("common_prefix_count", "common_prefix_state_hash", "executed_counts", "unique_generated_transactions")},
        "mean_admission_to_append_ms": decomposition["mean_admission_to_append_ms"],
        "request_stages": decomposition["stages"],
        "request_stage_coverage": {name: decomposition[name] for name in ("scheduled", "completed", "covered", "excluded")},
        "unique_completion_tps": result["comparison"]["unique_completion_tps"],
        "measured_tcp_written_bytes": result["comparison"]["replica_tcp_written_bytes"],
        "proxy": proxy_metrics(read(trial / "proxy.json")),
        "calibration_added_rtt_ms": manifest["calibration"]["median_added_rtt_ms"],
        "leader_proposal_count": len(rows), "leader_proposals_in_window": len(window_rows),
        "complete_leader_chains_in_window": len(complete_rows),
        "leader_chain_exclusions": dict(Counter(reason for row in window_rows for reason in row["missing_spans"])),
        "leader_stage_ms": {name: stats([row[name] for row in complete_rows]) for name in SPANS},
        "leader_stage_population": "same complete leader rounds with proposal outbox inside own measurement window; unweighted by transactions",
        "report_before_history_quorum": dict(Counter(row.get("report_before_history_quorum", "unobserved") for row in window_rows)),
        "normalized_proposal_cadence_ms": stats([row["normalized_ms_per_round"] for row in intervals]),
        "round_weighted_cadence_ms": (sum(row["elapsed_ms"] for row in intervals) /
                                      sum(row["round_gap"] for row in intervals)) if intervals else None,
        "cadence_by_leader": {str(replica): stats([row["normalized_ms_per_round"] for row in intervals if row["replica"] == replica])
                              for replica in correct},
        "cadence_round_gaps": dict(Counter(row["round_gap"] for row in intervals)),
        "timer_expiries_whole_trace": dict(timer_counts),
        "instrumented_guards_whole_trace": dict(guard_counts),
        "guard_evidence_scope": "Instrumentation reports distinct authenticated sender identities and preparation-state facts. This checks the reported predicates; it does not independently reverify every protocol-message signature. Report branch counts overlap.",
    }
    return summary, {"leader_rounds": rows, "cadence_intervals": intervals}


def render(summary, details, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    colors = ("#2a9d8f", "#e9c46a", "#9aa5b1", "#6b63a6")
    labels = ("REPORT → OBS pool", "OBS pool → input", "Input → PROPOSE", "PROPOSE → direct commit")
    names = list(SPANS)
    means = [summary["leader_stage_ms"][name]["mean"] for name in names]
    if any(value is None for value in means):
        raise ValueError("no complete leader chains available to plot")
    figure, axes = plt.subplots(2, 1, figsize=(11, 7.4), layout="constrained")
    boundaries = [-sum(means[:3]), -sum(means[1:3]), -means[2], 0, means[3]]
    for index, (left, right) in enumerate(zip(boundaries, boundaries[1:])):
        axes[0].barh(0, right - left, left=left, height=.4, color=colors[index])
    axes[0].scatter([0], [0], marker="v", color="#222222", zorder=4)
    axes[0].axvline(0, color="#222222", lw=1, ls="--")
    axes[0].set(yticks=[], xlabel="Leader-local time relative to logical PROPOSE outbox (ms)",
                title=f"Mean leader-round stages · {summary['complete_leader_chains_in_window']} complete rounds")
    axes[0].set_ylim(-.7, .7)
    axes[0].legend(handles=[Patch(color=color, label=f"{label}: {value:.2f} ms")
                           for color, label, value in zip(colors, labels, means)],
                   loc="upper center", bbox_to_anchor=(.5, -.32), ncol=2, frameon=False)
    grouped = defaultdict(list)
    for row in details["leader_rounds"]:
        if row["in_measurement_window"] and not row["missing_spans"]:
            grouped[row["replica"]].append(row)
    replica, own = max(grouped.items(), key=lambda item: (len(item[1]), -item[0]))
    own.sort(key=lambda row: row["round"])
    start = max(0, len(own) // 2 - 1)
    selected = own[start:start + 3]
    zero = selected[0]["proposal_us"]
    for y, row in enumerate(selected):
        for index, (start_name, end_name) in enumerate(SPANS.values()):
            left, right = (row[start_name] - zero) / 1000, (row[end_name] - zero) / 1000
            axes[1].barh(y, right - left, left=left, height=.5, color=colors[index])
        axes[1].scatter([(row["proposal_us"] - zero) / 1000], [y], marker="v", color="#222222", zorder=4)
    axes[1].set(yticks=list(range(len(selected))), yticklabels=[f"Round {row['round']}" for row in selected],
                xlabel="Same replica's measured monotonic time, shifted to first shown PROPOSE (ms)",
                title=f"Actual consecutive proposals by leader {replica} · other leaders' proposals omitted")
    axes[1].invert_yaxis()
    cadence = summary["normalized_proposal_cadence_ms"]["mean"]
    figure.suptitle(f"Delugi healthy pipeline · mean own-leader cycle ÷ round gap = {cadence:.2f} ms/round\n"
                   f"Configured δ = {summary['proxy']['configured_one_way_ms']:g} ms; "
                   f"calibrated added RTT = {summary['calibration_added_rtt_ms']:.2f} ms; "
                   f"Δ = {summary['settings']['bound_ms']} ms", fontsize=13)
    for axis in axes:
        axis.spines[["top", "right", "left"]].set_visible(False)
        axis.grid(axis="x", alpha=.18)
        axis.set_axisbelow(True)
    figure.savefig(output.with_suffix(".png"), dpi=180)
    figure.savefig(output.with_suffix(".pdf"))
    plt.close(figure)


def render_requests(reports, output):
    """Keep the fault recovery scale separate without hiding its large value."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    colors = ("#8cb9de", "#487fb2", "#6b63a6", "#df9343", "#c779a7", "#e4d96a")
    figure, axes = plt.subplots(1, len(reports), figsize=(11, 4.4), squeeze=False, layout="constrained")
    labels = {"healthy": "Healthy", "silent": "Persistent silent node"}
    for axis, (label, report) in zip(axes[0], reports.items()):
        total, left = report["mean_admission_to_append_ms"], 0
        for color, stage in zip(colors, report["request_stages"]):
            value = stage["mean_ms"]
            axis.barh(0, value, left=left, height=.4, color=color)
            if value > .13 * total:
                axis.text(left + value / 2, 0, f"{value:.2f}", ha="center", va="center", color="white")
            left += value
        axis.set(xlim=(0, total * 1.08), ylim=(-.5, .5), yticks=[],
                 xlabel="Mean admission → verified append (ms)",
                 title=f"{labels.get(label, label)} · {report['settings']['sustained']['total_rate']} tx/s\n"
                       f"{total:.2f} ms · {report['cohort']['completed']}/{report['cohort']['scheduled']} complete")
        axis.spines[["top", "right", "left"]].set_visible(False)
        axis.grid(axis="x", alpha=.18)
        axis.set_axisbelow(True)
    figure.suptitle("Request latency decomposition · independent x-axis scales", fontsize=14)
    figure.legend(handles=[Patch(color=color, label=stage["stage"])
                           for color, stage in zip(colors, next(iter(reports.values()))["request_stages"])],
                  loc="outside lower center", ncol=3, frameon=False)
    figure.savefig(output.with_suffix(".png"), dpi=180)
    figure.savefig(output.with_suffix(".pdf"))
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--healthy", type=Path, required=True)
    parser.add_argument("--silent", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-figure", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    reports, details = {}, {}
    for label, root in (("healthy", args.healthy), ("silent", args.silent)):
        if root is None:
            continue
        reports[label], details[label] = analyze_run(root)
        (args.output / f"{label}-rounds.json").write_text(json.dumps(details[label], indent=2) + "\n")
    document = {
        "schema": "delugi-saved-pipeline-audit-v1", "runs": reports,
        "analysis_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "contracts": [
            "All durations subtract timestamps from one replica's monotonic clock; no wall-clock alignment.",
            "Cadence is elapsed time between successive proposals by one leader divided by their round-number gap; it is not a measurement of adjacent proposals on different hosts.",
            "Leader stages join the same exact round and use identical complete leader-round populations; they are not transaction-weighted and do not sum to transaction latency.",
            "PROPOSE marks the logical ordering outbox before runtime encoding/transport enqueue, not a socket departure.",
            "Direct commit means the local CER quorum; request output additionally requires scanner prefix and payload availability.",
            "Stage means include boundary-spanning preparation/commit when proposal is inside the measurement window. Cadence requires both proposals inside the window.",
            "Missing markers remain exclusions; incomplete cohorts and trace drops cannot become zero latencies.",
            "Proxy delay applies to independently pipelined TCP byte-stream chunks, not packet shaping; measured hold excludes later transport drain and receive processing.",
            "The figure's lower panel is three observed rounds from one process clock; other leaders are omitted. Its upper panel contains means, not a synchronized global trace.",
        ],
    }
    (args.output / "summary.json").write_text(json.dumps(document, indent=2) + "\n")
    if not args.no_figure:
        render(reports["healthy"], details["healthy"], args.output / "healthy-pipeline")
        render_requests(reports, args.output / "request-latency")
    print(json.dumps({label: {"status": report["status"],
                             "cohort": report["cohort"],
                             "cadence_mean_ms": report["normalized_proposal_cadence_ms"]["mean"],
                             "proposal_to_direct_mean_ms": report["leader_stage_ms"]["proposal_to_direct_commit_ms"]["mean"]}
                      for label, report in reports.items()}, indent=2))


if __name__ == "__main__":
    main()
