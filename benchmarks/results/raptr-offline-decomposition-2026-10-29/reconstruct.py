#!/usr/bin/env python3
"""Reconstruct only recorded Raptr latency boundaries; never launch a benchmark."""
import hashlib
import json
from pathlib import Path
from statistics import fmean

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
RUN = ROOT / "benchmark/.state/runs/delugi-raptr-wan-30s-20261028"
PUBLIC = ROOT / "benchmarks/results/fabric-wan-30s-2026-10-28/summary.json"
FIELDS = ["planned_us", "offered_us", "prepared_us", "admitted_us", "first_materialized_us"]
STAGES = ["scheduling", "preparation_and_lock_wait", "admission", "admitted_to_output_combined"]


def read(path):
    return json.loads(path.read_text())


def check_file(path, descriptor):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == descriptor["sha256"], f"Hash mismatch: {path}"
    if "bytes" in descriptor:
        assert len(data) == descriptor["bytes"], f"Size mismatch: {path}"
    return {"path": str(path.relative_to(ROOT)), "sha256": digest, "bytes": len(data)}


def lines(path):
    with path.open() as source:
        for line in source:
            yield json.loads(line)


def reduce_trial(row, public):
    trial = RUN / "trials" / row["trial_id"]
    result_path = trial / "result.json"
    evidence = [check_file(result_path, row["result"])]
    assert evidence[0]["sha256"] == public["result_sha256"]
    result = read(result_path)
    stages = {key: [] for key in STAGES}
    totals, exclusions, per_origin = [], [], []
    admitted = scheduled = batch_ready = 0
    for origin in result["correct_replicas"]:
        node = trial / "replicas" / f"node-{origin}"
        final = node / "final.json"
        auth = result["authentication"][str(origin)]
        assert auth["verified"]
        evidence.append(check_file(final, {"sha256": auth["receipt_sha256"]}))
        assert evidence[-1]["sha256"] == result["evidence"][str(final)]["sha256"]
        receipt = read(final)
        assert receipt["signer"] == origin
        for descriptor in receipt["body"]["files"]:
            path = node / descriptor["name"]
            evidence.append(check_file(path, descriptor))
            if str(path) in result["evidence"]:
                assert evidence[-1]["sha256"] == result["evidence"][str(path)]["sha256"]

        credited = {}
        for output in lines(node / "output.jsonl"):
            for batch in output["batches"]:
                for tx in batch["transactions"]:
                    if tx["own_credit"]:
                        assert tx["origin"] == origin and tx["eligible"] and tx["first_seen"]
                        assert tx["request_id"] not in credited
                        credited[tx["request_id"]] = (output["append_us"], output["event"])
        origin_rows = list(lines(node / "requests.jsonl"))
        origin_completed = 0
        for request in origin_rows:
            scheduled += 1
            admitted += request["admitted_us"] is not None
            batch_ready += request["own_batch_ready_us"] is not None
            if request["first_materialized_us"] is None:
                exclusions.append({"origin": origin, "sequence": request["sequence"],
                                   "cancelled_us": request.get("cancelled_us"),
                                   "admitted_us": request["admitted_us"],
                                   "reason": request.get("rejection")})
                continue
            assert credited.pop(request["request_id"]) == (
                request["first_materialized_us"], request["first_materialized_event"])
            stamps = [request[field] for field in FIELDS]
            assert all(isinstance(stamp, int) for stamp in stamps)
            deltas = [b - a for a, b in zip(stamps, stamps[1:])]
            assert all(delta >= 0 for delta in deltas)
            assert sum(deltas) == stamps[-1] - stamps[0]
            for key, delta in zip(STAGES, deltas):
                stages[key].append(delta)
            totals.append(stamps[-1] - stamps[0])
            origin_completed += 1
        assert not credited
        assert len(origin_rows) == auth["planned"]
        assert origin_completed == auth["origin_completed"]
        per_origin.append({"origin": origin, "scheduled": len(origin_rows), "completed": origin_completed})
    populations = result["reduction"]["populations"]
    assert scheduled == populations["planned"] == public["scheduled"]
    assert admitted == populations["admitted"] == public["admitted"]
    assert len(totals) == populations["completed"] == public["completed"]
    assert batch_ready == 0
    assert all(r["admitted_us"] is None and r["cancelled_us"] is not None for r in exclusions)
    assert len(exclusions) == populations["cancelled"]
    return {
        "case": row["case"], "trial_id": row["trial_id"],
        "scheduled": scheduled, "admitted": admitted, "completed": len(totals),
        "completion_fraction": len(totals) / scheduled, "excluded": exclusions,
        "per_origin": per_origin, "own_batch_ready_timestamps": batch_ready,
        "stage_sum_us": {key: sum(values) for key, values in stages.items()},
        "stage_mean_ms": {key: fmean(values) / 1000 for key, values in stages.items()},
        "scheduled_to_output_mean_ms": fmean(totals) / 1000,
        "published_full_scheduled_cohort_quantiles": {
            key: value for key, value in public.items() if key.startswith("end_to_end_")
        },
        "source_files": evidence,
    }


def plot(rows):
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "svg.fonttype": "none", "svg.hashsalt": "raptr-offline-20261029"})
    colors = ["#2B7DAD", "#E6A23C", "#4A9B77", "#C5CED7"]
    fig = plt.figure(figsize=(12, 7.7), facecolor="white")
    fig.text(.075, .94, "Raptr: latency recovered from saved journals", fontsize=20, weight="bold", color="#192D40")
    fig.text(.075, .895, "Four regions · 30 s input · 100 tx/s · 1 useful byte/tx · Δ = 1,000 ms · natural WAN", color="#526274", fontsize=11)
    fig.text(.075, .852, "Arithmetic means over completed requests; the same requests contribute to every stage.", fontsize=11)
    ax = fig.add_axes([.16, .55, .75, .24])
    for y, row in enumerate(rows):
        left = 0
        for key, color in zip(STAGES, colors):
            value = row["stage_mean_ms"][key]
            ax.barh(y, value, left=left, color=color, height=.45,
                    edgecolor="#77899A" if key == STAGES[-1] else color,
                    linewidth=.6, hatch="///" if key == STAGES[-1] else None)
            left += value
        ax.text(left + 35, y, f"{row['scheduled_to_output_mean_ms']:,.2f} ms", va="center", weight="bold", fontsize=11)
    ax.set_yticks([0, 1], ["Healthy", "Silent leader"])
    ax.invert_yaxis()
    ax.set_xlim(0, 3500)
    ax.set_xlabel("Scheduled arrival → verified application output (ms)", labelpad=10)
    ax.set_axisbelow(True)
    ax.grid(axis="x", color="#E6EBEF")
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(axis="both", length=0)

    table_ax = fig.add_axes([.075, .265, .85, .20])
    table_ax.axis("off")
    labels = ["Scheduling\nplanned → offered", "Preparation + lock wait\noffered → prepared",
              "Admission\nprepared → admitted", "Pipeline, unsplit\nadmitted → output"]
    table = table_ax.table(
        cellText=[[f"{row['stage_mean_ms'][key]:,.3f} ms" for key in STAGES] for row in rows],
        colLabels=labels, rowLabels=["Healthy", "Silent leader"],
        cellLoc="center", rowLoc="center", bbox=[.10, 0, .90, 1])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    for (r, c), cell in table.get_celld().items():
        cell.set_edgecolor("#DEE5EB")
        if r == 0:
            cell.set_facecolor(colors[c]); cell.set_text_props(color="white" if c < 3 else "#192D40", weight="bold")
        else:
            cell.set_facecolor("#F6F8FA" if r == 1 else "white")
    fig.text(.075, .207, "Coverage: healthy 3,000 / 3,000; silent leader 2,984 / 3,000 (99.47%).", fontsize=11)
    fig.text(.075, .174, "The 16 silent-leader exclusions were cancelled before admission. They are not assigned zero latency.", fontsize=10, color="#526274")
    fig.text(.075, .12, "Hatched interval combines batching, dissemination, consensus, payload fetch, FIFO release and logging.", fontsize=10, color="#192D40")
    fig.text(.075, .087, "Its internal boundaries were not recorded; a paper-style consensus-stage split cannot be recovered.", fontsize=10, color="#192D40")
    fig.text(.075, .037, "Source: saved 2026-10-28 journals · local monotonic timestamps · offline reconstruction only", fontsize=9, color="#6D7D8C")
    fig.savefig(HERE / "raptr-latency-decomposition.png", dpi=180)
    svg = HERE / "raptr-latency-decomposition.svg"
    fig.savefig(svg, metadata={"Date": None})
    svg.write_text("\n".join(line.rstrip() for line in svg.read_text().splitlines()) + "\n")
    plt.close(fig)


def main():
    state = read(RUN / "state.json")
    public = {row["trial_id"]: row for row in read(PUBLIC)["rows"]}
    selected = [row for row in state["rows"] if row["protocol"] == "raptr"]
    assert [(r["case"], r["status"]) for r in selected] == [
        ("healthy", "completed"), ("silent-first-leader", "completed")]
    rows = [reduce_trial(row, public[row["trial_id"]]) for row in selected]
    summary = {
        "schema": 1, "analysis_date": "2026-10-29", "run": RUN.name,
        "boundary_fields": FIELDS, "cohort": "completed scheduled requests, pooled across correct origins",
        "clock": "origin-local CLOCK_MONOTONIC microseconds; no cross-host subtraction",
        "verification": "Hashes revalidated against saved verified signed-receipt descriptors and published result hashes; signatures not reverified in this offline script. Every completed request matched to its credited output event and append timestamp.",
        "missing_boundaries": ["native batch ready", "proposal", "consensus commit", "payload ready", "FIFO release", "journal formatting start"],
        "rows": rows,
    }
    (HERE / "decomposition.json").write_text(json.dumps(summary, indent=2) + "\n")
    plot(rows)
    for row in rows:
        print(row["case"], row["completed"], row["stage_mean_ms"], "total", row["scheduled_to_output_mean_ms"])


if __name__ == "__main__":
    main()
