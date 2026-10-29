# WAN mechanism audit: the recovery anchor now receives timeout-period arrivals

The corrected WAN run removes the demonstrated early-input regression. In the
silent case, **2,891 of 3,000 transactions now execute in the third honest
anchor**, versus 183 previously. The former dominant pattern—2,811 requests
entering the following first anchor and waiting through another silent
round—does not occur in this corrected cohort.

| Metric | Previous pipeline | Corrected pipeline |
|---|---:|---:|
| Healthy mean admission → output | 617.370 ms | 511.034 ms |
| Healthy mean prefix wait | 5.023 ms | 0.011 ms |
| Silent mean admission → output | 10,742.390 ms | 4,093.175 ms |
| Silent mean prefix wait | 6,655.111 ms | 246.420 ms |
| Third-anchor input fixed → PROPOSE, mean over four within-window anchors | 6,631.925 ms | 0.232 ms |

The silent-case decrease is 6,649.215 ms (61.9%). Of that decrease, 6,408.690 ms
(96.4%) is removed prefix waiting. All four before/after case populations
contain 3,000 scheduled, admitted, completed and fully decomposed requests,
with no exclusions; all correct replicas ultimately collected those outputs.

## Where the requests execute

Replica 0 remains silent, so rounds modulo four equal to 2, 3 and 0 are the
first, second and third honest anchors after each missing leader.

| Execution position | Previous requests | Corrected requests | Corrected mean prefix wait |
|---|---:|---:|---:|
| First honest anchor | 2,811 | 0 | No samples |
| Second honest anchor | 6 | 109 | 6,781.547 ms |
| Third honest anchor | 183 | 2,891 | 0.025 ms |

The previous full trace contains six third-anchor inputs frozen for a mean
6,629.630 ms before proposal. The corrected full trace contains five, with
mean age 0.238 ms. The table above uses the four anchors whose proposals lie
inside each run's measurement window, avoiding a change in drain population.
These are **round-weighted** input ages, separate from transaction-weighted
latency means.

## One request stays in the current recovery anchor

This example is the median admission among 963 origin-3 measurement requests
that arrived while a silent predecessor was unresolved and executed in that
same third anchor. Every timestamp below is from replica 3's monotonic clock.

Request `e60143c9e53bdd434b5358ad4fee820be297013cde59f5d1e968d3adee16e15e`,
origin 3, sequence 499:

| Event | Time (ms) |
|---|---:|
| Main timer for silent round 9 armed | 17,767.782 |
| Request admitted | 20,568.478 |
| Exact batch sealed | 20,569.464 |
| NoCER(9) | 24,767.812 |
| REPORT(12) | 24,768.782 |
| HISTORY3 quorum for proposal 12 | 25,008.389 |
| Observation pool for 12 complete | 25,010.935 |
| Input(12) fixed | 25,012.536 |
| PROPOSE(12) | 25,012.800 |
| Round 12 classified committed | 25,258.762 |
| Round 12 released by contiguous scanner | 25,258.784 |
| Exact batch output | 25,262.365 |

The request waits for the ongoing silent-round timer, then joins fresh
observations for anchor 12 and outputs with that anchor. Its total latency is
4,693.887 ms; its post-classification prefix wait is 0.022 ms. Input 12 waits
only 0.264 ms before proposal. The retained REPORT marker has no validated
proposal 9 and uses the completed local history fallback, as intended.

The previous audit found 904 origin-3 requests admitted after the preceding
third anchor's input froze, before its proposal, and then executed in the next
first anchor. The corrected trace has zero matches for that specific pattern.
This does not mean every arrival can enter the nearest anchor.

## Remaining latency and observation cutoffs

The corrected silent mean still includes 3,600.876 ms awaiting an execution
proposal, 242.651 ms in agreement after local validation, and 246.420 ms of
prefix wait. Main and catch-up timers were not shortened. The 109 second-anchor
requests account for nearly all the remaining prefix wait.

A concrete residual boundary case is origin 3, sequence 165. Its own immutable
observation for anchor 4 was fixed at 10,525.875 ms; the request arrived at
10,548.478 ms and its batch sealed at 10,548.792 ms. Anchor 4's input completed
at 10,767.990 ms and proposed at 10,768.112 ms. This request instead executed
in round 7, waited 6,754.582 ms for the prefix and output at 18,255.474 ms.
The audit finds 32 origin-3 requests with this same ordering of events. This
illustrates the remaining observation-cutoff effect: delaying preparation
removes the long stale-input interval, but does not refresh signed observations
when later requests arrive. The example does not attribute every residual
request to the same cause or establish a universal freshness bound.

## Healthy pipeline and measurement scope

| Within-window leader diagnostic | Previous | Corrected |
|---|---:|---:|
| Input fixed → PROPOSE, round-weighted mean | 48.959 ms (284 rounds) | 3.692 ms (305 rounds) |
| Same-leader normalized cadence | 105.711 ms/round (280 pairs) | 98.575 ms/round (301 pairs) |
| Silent same-leader normalized cadence, including timeout cycles | 1,772.113 ms/round (9 pairs) | 1,785.033 ms/round (9 pairs) |

Cadence subtracts successive proposals on one leader's clock and divides by
their round-number gap; both proposals must lie inside that leader's input
window. The earlier published healthy cadence, 105.548 ms/round, used all 356
full-trace pairs including startup/warmup/drain. The matching corrected
full-trace statistic is 98.453 ms/round over 367 pairs. Both definitions and
their populations are retained in the JSON; no cross-host timestamp
subtraction is used.

Before and after ran over the real WAN at different times. The observed
healthy improvement includes network variation: agreement also changes from
187.550 to 173.813 ms. The causal evidence for the scheduling correction is
the later REPORT, short fixed-input age and changed recovery-anchor inclusion;
this audit does not assign the full healthy latency decrease to the guard.

Detailed handler spans are sampled at stride 64 in both runs. The critical
readiness, proposal, classification and outbox markers used here cover every
round, and the traces report no dropped events. Transaction intervals begin
at origin-local admission and end at origin-local exact output; the proposal
midpoint is local full validation, so proposal transit belongs to the preceding
stage. Leader durations overlap transaction stages and cannot be added to them.

## Evidence

[`mechanism-audit.json`](mechanism-audit.json) retains exact cohort counts,
stage means, per-position statistics, all leader rounds, both cadence
populations, guard checks, selected requests and source hashes.
[`mechanism_audit.py`](mechanism_audit.py) independently joins the silent cohort
through the established prior audit and verifies equality of its stage means.
It validates final result hashes, authenticated cohort/shard bindings, trace
run identities and completeness, and the version-specific REPORT guards.

The before campaign is `delugi-pipeline-wan-20261029-clock-aligned`; corrected
is `delugi-freshness-wan-20261030`, source `5c7057f` containing runtime correction
`8d84dec`. See the [main comparison](README.md) for run configuration, deployment
provenance, latency plots and retained Raptr comparison.

```sh
python3 benchmarks/results/delugi-freshness-wan-2026-10-30/mechanism_audit.py \
  --before benchmark/.state/runs/delugi-pipeline-wan-20261029-clock-aligned \
  --after benchmark/.state/runs/delugi-freshness-wan-20261030 \
  --output benchmarks/results/delugi-freshness-wan-2026-10-30/mechanism-audit.json
```
