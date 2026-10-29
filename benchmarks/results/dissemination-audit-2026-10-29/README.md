# Why Delugi's measured inclusion stage is longer

The [five-delay follow-up](5delta-followup.md) corrects an incomplete inference
from this first audit: Raptr's published 5δ already includes optimistic
certification overlap. That structural fact alone does not explain a difference
from Delugi's favorable 5δ target. The follow-up examines transaction eligibility
at REPORT snapshots, composition timing, actual proposal cadence and the
requested two-stage split at leader proposal finalization.

The saved healthy WAN evidence points to **when availability collection blocks
proposal inclusion**, together with batching and reporting-opportunity timing.
It does not support a simple Raptr-two-signatures versus Delugi-three-signatures
explanation. Delugi's REPORT-to-OBS-pool collection and Raptr's background PoA
collection take almost the same measured time. Raptr's optimistic path can
accept a proposal before the local PoA arrives.

This is an offline audit of the 28 October Delugi and 29 October Raptr healthy
four-region runs. Both contain 3,000 scheduled, completed and fully traced
requests with zero exclusions. No protocol implementation changed, no workload
was rerun, and no cloud resources were created. The [validation record](validation.json)
and [numeric summary](summary.json) bind the original evidence.

## Thresholds and where they apply

At n=4 and f=1:

| Condition | Required replicas | Role |
|---|---:|---|
| Delugi frozen current OBS pool | n−f = **3** | Leader waits before constructing this opportunity's input |
| Delugi WA for one advancing coordinate | f+1 = **2** | Witnesses selected from that pool |
| Raptr Quorum Store PoA / ProofOfStore | **3** | Background availability certificate |
| Raptr QC overall | **3** | Ordering-vote quorum |
| Raptr data-holding votes for a particular certified prefix | f+1 = **2** | Prefix threshold inside the larger QC |

Delugi broadcasts a sealed batch immediately. Its round leader opens REPORT,
responds locally with OBS, freezes the first three distinct OBS vectors, then
constructs the input and proposes. Each coordinate's WA contains two witnesses.
See [REPORT/OBS collection](../../../core/delugi/src/composed.rs#L300),
[pool validation](../../../core/delugi/src/availability.rs#L501) and
[WA validation](../../../core/delugi/src/availability.rs#L539).

Raptr's `poa_quorum` and `storage_requirement` are separate settings:
[rehost.rs](../../../core/raptr/native/src/rehost.rs#L74). Its actual Quorum Store
aggregation checks supermajority voting power:
[proof_coordinator.rs](../../../core/raptr/qs/src/quorum_store/proof_coordinator.rs#L250).
The tested profile enables optimistic subblocks with a 30 ms minimum batch age;
the leader can include batches lacking PoA:
[proof_manager.rs](../../../core/raptr/qs/src/quorum_store/proof_manager.rs#L131).
The legacy `allow_batches_without_pos_in_proposal=false` option does not disable
this Raptr subblock path.

Of the 3,000 Raptr requests, **2,610 (87%)** first output through optimistic
subblocks and 390 through certified-proof sections. Proposal acceptance precedes
the producer's local PoA for **1,349 requests**, all in optimistic subblocks.
For that group, stored→proposal averages **113.301 ms**, while stored→PoA averages
**180.035 ms**. This is direct evidence that proposal inclusion overlaps
background certification; grouping these observations is not an ablation of
optimism.

## Correcting the displayed comparison

The common plotted stage ends at origin-local acceptance of the execution
proposal. All values below are request-weighted means, in milliseconds.

| Interval | Delugi | Raptr |
|---|---:|---:|
| Admission → batch stored | 0.634 | 74.672 |
| Batch stored → accepted execution proposal | 336.206 | 190.541 |
| **Admission → accepted execution proposal** | **336.841** | **265.213** |

The isolated inclusion bars differ by **145.665 ms**. Including the preceding
batch stage reduces the complete admission-to-proposal difference to
**71.627 ms**; Raptr spends **74.038 ms** more before its inclusion timer starts.
This arithmetic does not estimate how changing batching would change either
protocol. Delugi has 3,000 unique exact batches in this cohort; Raptr has 804.

The two availability round trips are almost equal:

| Collector region | Delugi REPORT → frozen three-OBS pool | Raptr batch stored → PoA |
|---|---:|---:|
| Singapore | 164.203 | 162.635 |
| Frankfurt | 164.240 | 160.982 |
| London | 197.637 | 200.225 |
| Seoul | 183.472 | 187.850 |
| All requests | **178.325** | **177.923** |

These are separately measured leader-local and producer-local diagnostic
durations. They are not spliced into a cross-host transaction timeline.

## Where Delugi spends the remaining time

The strongest additive causal split uses the **928 requests whose origin is also
their execution leader**, so every boundary is on the same host:

```text
batch sealed ──90.576 ms──> REPORT
             ──177.580 ms──> three-OBS pool fixed
             ──  1.153 ms──> validated proposal
total: 269.310 ms
```

This directly exposes reporting-opportunity wait followed by the full collection
round trip. Across the complete cohort, leader admission→REPORT averages
**0.469 ms** (maximum 1.704 ms), and pool→validated proposal averages
**1.147 ms** (maximum 1.736 ms). Healthy post-admission HISTORY3/preparation or
proposal construction therefore does not account for the long bar. The selected
`HistoryReady` REPORT schedule differs from the paper's entry trigger, but
reinstating the old early immutable snapshot would reintroduce the previously
observed stale-input problem.

A short constructor does not rule out missing source/proof state: construction
can promptly select equality or an earlier target and leave a batch for another
opportunity. The 90.576 ms before the execution round's REPORT is measured
waiting, not established avoidable delay. Small post-admission preparation also
does not rule out history-dependent timing before admission.

For all 3,000 Delugi requests, a same-origin chronology splits the 336.206 ms into
**156.373 ms from sealing to that origin's OBS snapshot for the execution round**
and **179.834 ms from that snapshot to the accepted proposal**. The origin's OBS
is a local checkpoint: its membership in the frozen pool is not logged for a
foreign leader, so this is not asserted to be a causal dependency in every case.
Sealing→next local OBS averages 89.310 ms, with another 67.063 ms to the actual
execution-round OBS. Zero/one/two intervening OBS opportunities occur for
1,388/1,348/264 requests. Their existence does not prove earlier legal inclusion.

Origin/leader mixture explains little: reweighting Delugi's sixteen cells to
Raptr's counts changes 336.206 to 334.434 ms; reverse reweighting changes Raptr's
190.541 to 191.095 ms.

## The valid part of the threshold intuition

The four-region topology has nearby Asian and European pairs. In **28 sampled
post-startup REPORT rounds**, waiting for the second remote OBS rather than the
first adds **136.761 ms** on average:

| Leader | REPORT → first remote OBS | First → second remote OBS |
|---|---:|---:|
| Singapore | 65.613 | 98.358 |
| Frankfurt | 15.451 | 148.629 |
| London | 14.842 | 182.446 |
| Seoul | 65.639 | 117.611 |

Thus quorum arrival order matters substantially on this topology. But Raptr's
PoA also waits for three signers and takes about the same round-trip time.
The key distinction is that the optimistic proposal path can proceed without
waiting for that PoA. The 136.761 ms number is a sampled arrival-order diagnostic,
not a valid smaller-pool protocol or a measured latency saving. Target feasibility
and Delugi's n−f pool invariant remain unchanged. Detailed dispatches are sampled:
213 opportunities lack the needed records and two have no completed pool; all
exclusions are in [the order-statistic audit](obs_order_statistics.json).

## Why the two “2δ” claims do not predict equal bars

Raptr defines its theoretical dissemination interval from batch broadcast until
the leader emits an including proposal. Its two delays comprise one batch
transmission and one average inclusion wait; proposal transit belongs to its
three-delay consensus interval. Batch-formation waiting is excluded from that
theoretical count. Our local measured inclusion bar also contains proposal
transit back to the origin. See [the paper's definitions](https://arxiv.org/html/2504.18649v2#S2.SS2)
and [performance analysis](https://arxiv.org/html/2504.18649v2#S5.SS4).

Delugi's pinned two-delay readiness theorem starts at leader round entry and
ends at some valid input, allowing empty fallback. Its productive evidence bound
additionally assumes the needed batches reached reporters before their snapshots
and that the selected pool supports the targets. It is not an arbitrary-arrival
batch-to-proposal bound. The pinned source and hashes are recorded under
`source_references` in [obs_order_statistics.json](obs_order_statistics.json).

## Next local diagnostic

Before changing scheduling, record Delugi's exact fixed base, batch custody
arrival, OBS snapshot branch/checkpoint identities and signer arrival order,
frozen-pool membership, selected WA witnesses/target, and leader-held source
suffix/proof readiness. Record why a candidate misses an opportunity: insufficient
support, missing source/proof state, a frozen snapshot, prior base coverage or an
eligibility/limit rule. Distinguish early coordinate readiness from complete
input readiness: two actual current observations and locally available proof
state are only a subcondition. Their relation to the exact base and final fixed
pool must be checked; arbitrary custodians outside that pool do not establish a
legal input. Do not use future observations or payloads to infer past readiness.

For Raptr, record proposer-local batch receipt, minimum-age eligibility,
payload-pull opportunities, optimistic-versus-proof selection, proposer-local
PoA availability and individual storage-signature receipts. Producer-local PoA
time alone does not reveal what the proposer knew. For both protocols, separate
proposal enqueue/send and origin receipt/validation. Keep local spans and exact
message identities; do not subtract different host clocks. Report batch- and
opportunity-weighted results alongside request-weighted latency.

The first controlled local comparison should retain each implementation's
existing behavior and native quorum rules, use a four-process two-cluster delay
profile and fixed arrival seeds, and vary arrival phase across repetitions. A
separate Raptr optimistic/certified-only control can test overlap while holding
its batching, age settings, timers and networking fixed. Use a supported control
if available; otherwise treat it as an explicit future ablation. It must not
silently replace the default counterpart. Test batching sensitivity separately,
checking actual batch sizes and release cadence rather than only config labels.

Preserve `HistoryReady`, once-only REPORT/OBS, immutable snapshots and the first
valid frozen pool. Prompt payload processing and proof-state indexing may help
productive readiness before the existing snapshot, if traces establish that
cause. This audit implements no threshold, scheduling or instrumentation change.

## Review with GPT-6 Pro

The requested discussion in [delugi eval context](https://chatgpt.com/c/6ad0826d-7048-83ec-b309-e09c2dca6590)
completed on 29 October 2026. The [verbatim prompt and response](pro-consultation.json)
record the chat/turn/message identities and source audit commit. The existing
chat's model was retained. Pro reviewed the supplied audit; it did not rerun the
experiments or independently reproduce the archive analysis.

The review supports opportunity timing plus Delugi's exposed pool barrier,
contrasted with Raptr's optimistic certification overlap, as the leading
explanation. It rejects the two-signature versus three-signature PoA premise and
endorses the 71.627 ms common admission-to-proposal comparison. The avoidable
portion remains unmeasured. In particular, 87% optimistic output does not mean
87% realizes a full round-trip saving, and a proposal arriving after PoA does not
prove that it waited for PoA.

The next diagnostics above incorporate the review's main additions: exact
source/proof readiness and exclusion reasons, proposer-local Raptr state,
proposal transport/validation boundaries, and batch/opportunity weighting.
The saved WAN runs occurred on separate days; regional reweighting does not
control day-to-day variation. Requests sharing batches or opportunities are
not independent observations. The observed 136.761 ms second-remote-OBS wait is
not a prediction for a semantics-preserving optimization.

## Reproduce

The scripts read only the retained local archives and write diagnostic files:

```sh
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/analyze.py
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/extra.py
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/obs_order_statistics.py --output results/local/dissemination-audit-20261029/obs_order_statistics.json
```

The first script re-runs the original source-bound reducers before joining the
requests. Outputs default to the ignored local audit directory. The regenerated
three numeric summaries match their published copies exactly.
