#!/usr/bin/env python3
"""Plot the healthy request cohorts from phase_delta_comparison.py and wan_delta_utc.py."""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import MaxNLocator


BLUE = "#17609A"
ORANGE = "#C05916"
GRAY = "#58677A"
TEXT = "#192C3F"


def point(axis, y, interval, color, marker="o"):
    low, central, high = interval
    if not low <= central <= high:
        raise ValueError(f"unordered interval {interval}")
    axis.errorbar(central, y, xerr=[[central - low], [high - central]], color=color,
                  marker=marker, ms=5.5, lw=1.4, capsize=3, zorder=3)
    axis.annotate(f"{central:.1f}", (high, y), xytext=(6, 0), textcoords="offset points",
                  ha="left", va="center", color=color, size=8)


def scalar(value):
    return (value, value, value)


def setup(axis, title, labels, intervals):
    axis.set_title(title, loc="left", pad=10, weight="bold", size=10, color=TEXT)
    axis.set_yticks(range(len(labels)), labels, fontsize=8)
    axis.set_ylim(len(labels) - .5, -.5)
    lo = min(0, min(s[0] for s in intervals))
    hi = max(0, max(s[2] for s in intervals))
    span = max(10, hi-lo)
    axis.set_xlim(lo-.035*span, hi+.25*span)
    axis.axvline(0, color="#A6AEB6", lw=.8)
    axis.xaxis.set_major_locator(MaxNLocator(5))
    axis.xaxis.grid(True, color="#DAE0E5", lw=.65)
    axis.set_axisbelow(True)
    axis.tick_params(length=0, pad=5, color=GRAY, labelcolor=TEXT, labelsize=8)
    axis.spines[["top", "left", "right"]].set_visible(False)
    axis.spines["bottom"].set_color("#ADB7C2")
    axis.set_xlabel("Mean latency (ms)", size=8, color=GRAY, labelpad=5)


def render(phase, utc, folder):
    counts = []
    for protocol in ("delugi", "raptr"):
        count = phase[protocol]["validation"]["covered"]
        if not (utc[protocol]["requests"] == count > 0 and
                phase[protocol]["instrumented"] and not phase[protocol]["validation"]["excluded"]):
            raise ValueError(f"incomplete healthy {protocol} cohort")
        counts.append(count)
    if counts[0] != counts[1]:
        raise ValueError("protocol cohort sizes differ")

    def utc_stage(protocol, name):
        stage = utc[protocol]["stages"][name]
        if stage["count"] != counts[0]:
            raise ValueError(f"incomplete UTC stage {protocol}/{name}")
        return stage["mean_ms"]

    titles = ("Admission → batch broadcast", "Batch broadcast → first proposal emission",
              "First proposal emission → verified output", "Admission → verified output",
              "Admission → first proposal accepted at origin")
    keys = ("admit_to_broadcast", "broadcast_to_first_emission", "first_emission_to_output", "admit_to_output")
    matched = []
    for protocol in ("delugi", "raptr"):
        local = phase[protocol]["stages"]["admit_to_first_local"]
        if local["samples"] != counts[0]:
            raise ValueError("incomplete first-acceptance cohort")
        matched.append([utc_stage(protocol, key) for key in keys] + [scalar(local["mean_ms"])])
    schedule = utc["delugi"]["report_schedule"]
    wait_labels = ["Half the mean REPORT spacing", "Wait to next REPORT, uniform arrival¹",
                   "Wait to next REPORT, observed", "Broadcast → first inclusion’s REPORT²",
                   "First inclusion’s REPORT → frozen pool"]
    wait = [scalar(schedule["half_mean_gap_ms_at_estimated_utc"]),
            scalar(schedule["uniform_time_residual_ms_at_estimated_utc"]),
            utc_stage("delugi", "broadcast_to_next_any_report"),
            utc_stage("delugi", "broadcast_to_winning_report"),
            utc_stage("delugi", "winning_report_to_pool")]
    colors = [GRAY, GRAY, BLUE, BLUE, BLUE]
    for key, label in (("broadcast_to_winner_payload", "Broadcast → including leader’s batch receipt"),
                       ("winner_payload_to_pull", "Including leader’s batch receipt → payload pull"),
                       ("winning_pull_to_select", "Payload pull → batch selection")):
        metric = utc["raptr"]["stages"].get(key)
        if metric and metric["count"]:
            if metric["count"] != counts[0]:
                label += f" (n={metric['count']:,})"
            wait_labels.append(label)
            wait.append(metric["mean_ms"])
            colors.append(ORANGE)
    gap_labels = ("Broadcast → emission gap", "Broadcast → emission gap less REPORT wait⁴",
                  "Admission → emission gap", "Admission → emission, relaxed support³")
    gaps = [utc["comparison_ms"][key] for key in
            ("broadcast_to_first_emission", "broadcast_to_emit_gap_minus_winning_report_phase_paired_clocks",
             "admit_to_first_emission", "admit_to_first_emission_if_insufficient_obs_waived")]

    plt.rcParams.update({"font.family":"DejaVu Sans", "pdf.fonttype":42, "axes.unicode_minus":True})
    fig, axes = plt.subplots(3, 1, figsize=(7.9, 8.8), gridspec_kw={"height_ratios":[5.9, len(wait)+.5, 4.6]})
    fig.subplots_adjust(left=.408, right=.975, top=.865, bottom=.135, hspace=.65)
    fig.text(.035, .973, "Four-region proposal and output latency", size=14,
             weight="bold", color=TEXT)
    rate, size, duration, _ = phase["delugi"]["workload"]
    fig.text(.035, .941, f"Healthy four-region run  ·  {rate} tx/s  ·  {duration/1000:g} s  ·  "
             f"{size} useful byte{'s' if size != 1 else ''}/tx  ·  {counts[0]:,} requests per protocol",
             size=9, color=GRAY)
    ax = axes[0]
    setup(ax, "(a)  Matched endpoints", titles, matched[0] + matched[1])
    for y in range(len(titles)):
        for k, (color, marker, delta) in enumerate(((BLUE, "o", -.15), (ORANGE, "s", .15))):
            point(ax, y+delta, matched[k][y], color, marker)
    fig.legend(handles=[Line2D([], [], color=c, marker=m, linewidth=0, label=l)
                        for c,m,l in [(BLUE,"o","Delugi"),(ORANGE,"s","Raptr")]],
               loc="upper left", bbox_to_anchor=(.035, .932), frameon=False, ncol=2,
               borderaxespad=0, handlelength=1, handletextpad=.3, columnspacing=1.0, fontsize=8)

    ax = axes[1]
    setup(ax, "(b)  Batch eligibility and first proposal inclusion", wait_labels, wait)
    for y, interval in enumerate(wait):
        point(ax, y, interval, colors[y], "D" if y < 2 else "s" if colors[y] == ORANGE else "o")
    ax = axes[2]
    setup(ax, "(c)  Delugi − Raptr differences", gap_labels, gaps)
    for y, gap in enumerate(gaps):
        point(ax, y, gap, TEXT if y % 2 == 0 else GRAY, "o" if y % 2 == 0 else "D")
    fig.text(.035,.081,
             "Whiskers show bounds conditional on the measured clock calibration, bounded drift and possible first-proposer identities.\n"
             "¹ Time-weighted residual on measured REPORT launches. Half-spacing predicts this wait only for regular launches.\n"
             "² The REPORT for the first proposal including the batch can launch before broadcast. Raptr counts origin-leader batch transit as zero.\n"
             "³ Fixed proposal schedule, relaxing support for locally provable candidates. The exact causal share of the gap remains unidentified.\n"
             "⁴ For this residual, measurements sharing a host clock cancel part of the clock uncertainty in the cohort mean.",
             size=7, color=GRAY, va="top", linespacing=1.52)
    folder.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(folder/f"healthy-latency.{ext}", dpi=220, bbox_inches="tight", pad_inches=.12)
    plt.close(fig)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument("--phase", type=Path, default=here/"phase-comparison.json")
    parser.add_argument("--utc", type=Path, default=here/"utc-comparison.json")
    parser.add_argument("--output", type=Path, default=here)
    args = parser.parse_args()
    render(json.loads(args.phase.read_text()), json.loads(args.utc.read_text()), args.output)
