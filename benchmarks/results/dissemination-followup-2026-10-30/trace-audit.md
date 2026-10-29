# Corrected Delugi dissemination audit, 30 October 2026

Offline audit of the existing healthy 4-region run. No protocol edits, builds,
network calls, or new benchmark executions. Delugi run
`delugi-freshness-wan-20261030`, healthy trial `b02e64f55f4e7fa0598860f6`;
saved Raptr run `raptr-wan-stages-20261029`, healthy trial
`9b65f5c790b85b8186317c0f`.

## Reproduce

Run `python3 analyze.py`, `python3 extra.py`, `python3 current_metrics.py`, and
`python3 obs_order_statistics.py --output obs-order-statistics.json` from this
directory. The first two scripts default to the local audit output directory;
`--output` overrides that directory. All inputs are downloaded local archives.
The readers verify both full request cohorts, exact batch identities, source
bindings, and stage boundaries: 3,000 covered requests and no exclusions for
each protocol. `validation.json` records the input hashes; `current-metrics.json`
also binds the causal traces, cohort index, and final snapshots used here.

## Main facts

| Mean, ms | Delugi | Raptr |
|---|---:|---:|
| Admission to sealed batch | 0.602 | 74.672 |
| Sealed batch to origin acceptance of execution proposal | 336.507 | 190.541 |
| Admission to that acceptance | 337.109 | 265.213 |

The common-boundary gap is **71.896 ms**, not 145.966 ms. The difference between
these gaps, 74.070 ms, is the preceding batching-stage accounting difference;
it is not a batching intervention or a predicted speedup.

The stronger same-clock diagnostic uses 1,024 Delugi requests whose origin is
also the execution-round leader:

| Sequential stage | Mean ms |
|---|---:|
| Admission to batch seal | 0.598 |
| Batch seal to REPORT outbox | 92.141 |
| REPORT outbox to frozen 3-OBS pool | 178.291 |
| Frozen pool to fixed input | 0.776 |
| Fixed input to PROPOSE outbox | 4.288 |
| PROPOSE outbox to local verified acceptance | 0.020 |
| Admission to local acceptance | **276.115** |

Thus observed post-pool CPU/scheduling is small compared with the REPORT
exchange and opportunity waiting. Frankfurt has a ~13.98 ms input-to-PROPOSE
wait across loaded proposal rounds; the other leaders average 0.27–0.29 ms.
The Raptr origin=leader subset is 950 requests, with admission-to-acceptance
206.372 ms (batching 73.474 ms, then 132.898 ms). These subsets have different
leader and request composition and are diagnostics, not a controlled effect.

The sampled arrival-order audit contains 44 post-startup opportunities:
REPORT to first remote accepted OBS dispatch averages 41.187 ms; first to second
remote adds 133.558 ms; pool fixation averages 174.872 ms after REPORT. The first
remote is always in the collector's continent cluster; the second crosses to
the other cluster. This is an order-statistic diagnostic, not permission to
reduce the pool threshold or a per-request saved-latency estimate. Actual frozen
pool signers are present, but their checkpoint frontiers are not retained.

## New finding: many proposals overlap in what they execute

First execution assignments for the 3,000 exact batches are strongly uneven:

| Leader | Requests first executed | Distinct first-execution rounds |
|---|---:|---:|
| Singapore | 0 | 0 |
| Frankfurt | 665 | 77 |
| London | 1,641 | 77 |
| Seoul | 694 | 76 |

Singapore still creates 93 proposals in the full trace, all 93 classified Commit
at replica 0. During the local load window it performs 76 input constructions,
with 300 advancing coordinates and only one wholly empty input. This establishes
that zero first outputs is **not** failure to propose or generally empty inputs.
This is consistent with advancing inputs overlapping batches already executed
by preceding committed rounds. The available logs establish no new output for
this measured cohort, but do not retain exact proposal contents or identify
each batch's earliest proposal inclusion.

Every one of 76 loaded adjacent Seoul/Singapore round pairs exhibits the later
Singapore proposal accepted before its predecessor at all four observers:

| Observer | Later Singapore proposal leads predecessor, mean ms |
|---|---:|
| Singapore | 83.303 |
| Frankfurt | 60.163 |
| London | 80.116 |
| Seoul | 12.772 |

All values compare two events on the same observer's monotonic clock. Singapore
round OBS snapshots also precede predecessor Seoul round snapshots at Singapore,
Frankfurt and London in all 76 pairs, by 50.489, 32.567 and 48.086 ms respectively.
At Seoul, its own preceding-round snapshot comes first by 18.556 ms. In other
words, the WAN's opportunity snapshots and proposal receipts overlap and reorder;
an aggregate ~99 ms/round cadence is not a regular stream of equally productive
transaction-inclusion opportunities. This is a supported mechanism candidate,
not a quantitative attribution of the 71.896 ms difference.

Descriptively reweighting Raptr's origin/execution-leader cell means to Delugi's
cell counts gives admission-to-acceptance 260.988 ms, versus Raptr's observed
265.213 ms. The gap becomes 76.121 ms. Thus the different origin/leader composition
does not explain away the observed gap. This adjustment does not control WAN
variation, request phases or causal selection into execution rounds.

## Source readiness and observation limits

`current-metrics.json` records measurement-end minus measurement-start
construction counters for every leader. Source-threshold misses are
1,159/1,225/1,232/1,229; unavailable-source-suffix counts are 15/0/5/177;
unavailable-target-proof counts are 2,875/3,095/3,227/3,215. These count candidate
checks, not requests, stalled constructions, elapsed waits, or missed legal
opportunities. Each scan may reject newer candidates and promptly select a
valid earlier target. There are only 1/0/1/1 wholly empty constructions during
the load window. The counts do not establish that source readiness is irrelevant
to inclusion, nor that it explains a particular fraction of the latency.

The OBS checkpoint diagnostic over all requests is:
80.370 ms seal-to-next-own-OBS, 74.107 ms next-own-OBS-to-execution-round-own-OBS,
then 182.030 ms to execution-proposal acceptance. Counts of intervening local OBS
opportunities are 0:1,183; 1:560; 2:878; 3:316; 4:50; 5:13. Because opportunity
round numbers can arrive out of order, these are chronological event counts.
An origin's own OBS may not belong to the leader's frozen pool and is not a
proven prerequisite for its batch. None of these counts proves that an earlier
opportunity could legally include that batch.

The current pipeline permits speculative future admissions, so the old
admission-to-REPORT and HISTORY3-to-REPORT metrics have been removed from this
adapted summary. They would misleadingly call speculative lead time a waiting
stage. The old OBS audit's outdated HistoryReady source references were likewise
removed.

`snapshots.json` retains cumulative heights and aggregate counters, not per-round
proposal values, signed OBS coordinates, selected WA witnesses or proof state.
Sustained-mode logging in `core/delugi/src/process.rs::Runtime::log` filters the
ordinary `observation_snapshot` trace containing heights. Therefore first legal
inclusion and exact coordinate readiness before pool completion cannot be
reconstructed from the saved WAN data. That missing evidence is the narrowest
next observer-only instrumentation target.
