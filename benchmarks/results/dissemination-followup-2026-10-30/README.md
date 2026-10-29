# Why corrected Delugi still waits longer before proposing

The strongest current explanation is **batch eligibility at immutable observation
snapshots, amplified by WAN topology and overlapping rounds**. Correcting the
pipeline increased proposal frequency; it did not make every proposal cover
newer batches. The saved traces locate the remaining healthy delay before
proposal acceptance, with little processing time after the observation pool
closes. They do not yet identify each batch's earliest legally productive pool.

This investigation reads the existing corrected Delugi run and saved Raptr run.
It changes no protocol implementation and performs no new cloud runs.
The [trace audit](trace-audit.md), [aggregates](summary.json),
[same-clock diagnostics](current-metrics.json), and
[validation bindings](validation.json) retain the calculations.

## First compare the same interval

Both healthy cohorts have 3,000 covered completed requests and no exclusions.
All following measured intervals use one origin's monotonic clock.

| Mean milliseconds | Corrected Delugi | Saved Raptr |
|---|---:|---:|
| Admission → sealed batch | 0.602 | 74.672 |
| Sealed batch → accepted execution-associated proposal | 336.507 | 190.541 |
| Admission → accepted execution-associated proposal | **337.109** | **265.213** |
| Admission → verified contiguous application output | 511.034 | 448.581 |

The common preproposal gap is **71.896 ms**. The larger displayed
dissemination-only gap, 145.966 ms, includes 74.070 ms that Raptr records in the
preceding batching stage. This arithmetic is not a batching ablation or a
prediction of the effect of changing Raptr's batching configuration.

The stored midpoint remains origin-local acceptance of the execution-associated
proposal. It includes proposal transit and can differ from the first proposal
containing the batch. It cannot be relabeled as leader emission or first
inclusion. The [preceding midpoint audit](../dissemination-audit-2026-10-29/5delta-followup.md)
explains the intended first-inclusion metric and its missing capture fields.

## Where the current leader-local time goes

For the 1,024 requests whose origin is also the execution-round leader, the
following stages are additive and use that same leader's clock:

| Stage | Mean ms |
|---|---:|
| Admission → batch seal | 0.598 |
| Batch seal → relevant REPORT outbox | 92.141 |
| REPORT → frozen three-OBS pool | 178.291 |
| Pool → fixed input | 0.776 |
| Fixed input → PROPOSE outbox | 4.288 |
| PROPOSE outbox → local acceptance | 0.020 |
| Total admission → local acceptance | **276.115** |

Post-pool processing is small in this subset; the main observed delay is waiting
for the relevant opportunity and its evidence exchange. This selected subset
does not represent all origins/leaders, and REPORT waiting is not proven
avoidable idle time.

Across 44 sampled post-startup opportunities, the first accepted remote OBS
dispatch follows REPORT by 41.187 ms on average; the second remote response
adds 133.558 ms. Each first remote is in the leader's Asia/Europe cluster and
the second crosses between clusters. Pool closure averages 174.872 ms.
These are opportunity-weighted diagnostics, not request-weighted savings.

Delugi requires **three OBS in its pool and two supporting witnesses per WA**
at n=4. Native Raptr's explicit PoA also requires three signatures; f+1 is its
storage/prefix-support threshold. Therefore “Raptr collects two signatures
while Delugi collects three” is incorrect. Raptr can select optimistic batches
without waiting for PoA, but that optimism is already included in its paper's
five-delay analysis. It does not independently explain unequal implementations
of an otherwise identical five-delay path.

## Why one proposal per delta need not mean two deltas to include a batch

Current code sends sealed batches immediately (`composed.rs::produce`), fixes
one OBS immediately upon a valid REPORT (`answer_report`), and freezes the first
n−f distinct reports (`collect`). `AvailabilityConfig::build_coordinate_with_metrics` requires
f+1 covering current observations plus local source suffix/proof state to
advance beyond the base. Those observations and the selected input are not
refreshed when newer payloads arrive.

Consider an explicit homogeneous-delay example with four honest replicas:
REPORTs open every δ; remote links take exactly δ; local work is immediate;
sources/proofs and ordering history are otherwise ready. REPORT(u) induces
remote snapshots at u+δ and closes its pool at u+2δ. A batch broadcast at
u+ε, for 0<ε<δ, reaches nonproducers at u+δ+ε, after their snapshots. At most
its producer can report it, which is insufficient for two witnesses.

The next REPORT opens at u+δ. Its two remote observations cover the batch,
even if the leader's earlier local snapshot does not. Its pool closes at
u+3δ. Thus the batch takes **3δ−ε** to reach a proposal in this model. Uniform
phase gives **2.5δ**, despite a proposal every δ. With an additional ideal
three-delay direct-commit path, the corresponding mean is 5.5δ.

The [event model](snapshot_phase.py) checks 3,936 opportunity simulations:
all origin/rotating-leader combinations, 20 phases, all six remote response tie
orders, and favorable alignment. At δ=10 ms it obtains 25 ms to proposal and
55 ms to ideal direct commitment. A batch broadcast immediately before REPORT
instead approaches 2δ to proposal and 5δ to direct commitment. Equality requires
the payload to be processed before the snapshot, not merely sent at the same
timestamp.

This is a **conditional possible execution**, not a universal Delugi bound,
a Rust benchmark, or a numerical explanation of the WAN gap. It identifies the
missing premise: batches must reach enough reporters before their one-shot
snapshots. An overlapping pipeline alone does not establish that premise.

The pinned dissemination specification makes the same distinction: its
input-preparation theorem bounds REPORT/entry to **some valid input**, including
fallback. Its two-delay evidence theorem additionally assumes that needed
batches reach reporters before their reports, that selected reports support
the targets, and that leader proof-producing state is ready. It explicitly
excludes arbitrary batching/reporting schedules from that claim. Raptr's
[Section 5.4](https://arxiv.org/html/2504.18649v2#S5.SS4) instead counts payload
transmission plus average proposal-inclusion waiting for its common-case
transaction path.

## Why this WAN makes snapshot freshness consequential

For batch origin o, leader L, REPORT emission u and reporter j, a simplified
necessary coverage condition is

`batch_emission + delay(o,j) <= REPORT_emission + delay(L,j)`.

At least f+1 signers **inside the frozen pool** must cover the exact batch;
matching authenticated branches and leader source/proof readiness are also
necessary. A nearby reporter can receive REPORT and freeze its state while an
overseas batch is still travelling. Merely possessing the payload at the leader
before proposal does not update those already signed observations.

The saved run exhibits systematic overlap, not just a theoretical possibility:

- In each of 76 loaded adjacent Seoul/Singapore round pairs, the later Singapore
  proposal is accepted before its predecessor at every observer. Its lead is
  83.303/60.163/80.116/12.772 ms at Singapore/Frankfurt/London/Seoul respectively.
- At Singapore, Frankfurt and London, that later round's OBS is also fixed
  before the preceding round's OBS in all 76 pairs. Each comparison is on one
  observer's clock; no cross-host timestamp subtraction is used.
- Singapore emits 93 proposals and all 93 are classified Commit at replica 0,
  yet none of the 3,000 measured batches first executes in a Singapore-led
  round. Its loaded-window inputs mostly advance all four coordinates. This is
  consistent with overlapping previously executed batches; proposal count does
  not measure fresh inclusion opportunities for this cohort. Exact proposal
  contents are unavailable, so this does not reconstruct first inclusion.

These inversions also make the midpoint limitation consequential. If a batch
appears in an earlier-emitted, later-numbered proposal but executes through a
different proposal received afterward, the current execution-associated split
assigns that interval to dissemination. A first-inclusion split would assign it
to ordering/recovery. The logs cannot determine how often this occurs. Both
transaction eligibility and this potential reassignment must be measured before
attributing the entire 71.896 ms difference to dissemination itself.

The common-boundary gap also depends strongly on origin:

| Origin | Delugi admission → proposal acceptance, ms | Raptr, ms |
|---|---:|---:|
| Singapore | 381.063 | 264.995 |
| Frankfurt | 277.827 | 251.862 |
| London | 286.208 | 266.192 |
| Seoul | 403.340 | 277.804 |

This is consistent with geographical snapshot eligibility and overlapping
frontiers being important. It does not prove their exact causal share: the runs
were independent, native batching differs, and exact first-inclusion membership
is absent. Candidate-level proof/source failure counters also show that source
readiness must remain in the audit; a fast constructor can choose an older
target instead of waiting.

Standardizing Raptr's origin/execution-leader cell means to Delugi's request
counts gives 260.988 ms, leaving a 76.121 ms gap. All occupied Delugi cells have
Raptr observations. This descriptive adjustment shows that the skewed leader
mixture does not explain away the gap; it is not a controlled causal comparison.

## Silent recovery is a separate comparison

Corrected Delugi's preproposal interval including batching is 3,601.53 ms versus
Raptr's 2,358.25 ms; total latency is 4,093.18 versus 2,985.65 ms. These workloads
have persistent recurring faults and different native timer rules: eligible
7Δ main/3Δ catch-up for Delugi versus 4Δ from round entry for Raptr. They also
silence different regions. Equal Δ therefore does not mean equal recovery
waiting. The previous extra recovery-cycle freshness bug has been removed for
most requests; the remaining silent-case difference must not be attributed to
healthy-path quorum thresholds alone. See the
[current WAN report](../delugi-freshness-wan-2026-10-30/README.md).

## Decisive next check

The saved logs retain pool signers and timestamps, but not signed OBS frontiers,
selected WA witnesses, per-round proposal contents, or source-state availability.
Even final snapshots contain only cumulative state/counters. Therefore the
earliest legal inclusion opportunity cannot be reconstructed fully offline.

The narrow next step is observer-only capture of these fields, plus actual
proposal handoff and exact first-inclusion membership, in a common-clock local
four-process run. Sweep batch arrival phase while holding timers, quorums,
batching and networking fixed; include a two-cluster delay profile. For each
batch, classify earlier opportunities as insufficient covering observations,
missing source/proof state, or eligible but omitted. The last category would
identify a remaining implementation bug. Changing thresholds, refreshing
signed OBS, or declaring all measured waiting inherent is not justified by the
present evidence.

## Reproduction

From the repository root, choose a scratch directory under `results/local`:

```sh
audit_out=results/local/dissemination-followup-20261030/recheck
audit_scripts=benchmarks/results/dissemination-followup-2026-10-30
python3 "$audit_scripts/analyze.py" --output "$audit_out"
python3 "$audit_scripts/extra.py" --output "$audit_out"
python3 "$audit_scripts/current_metrics.py" --output "$audit_out"
python3 "$audit_scripts/obs_order_statistics.py" --output "$audit_out/obs-order-statistics.json"
python3 "$audit_scripts/snapshot_phase.py"
```

The readers use retained local archives and regenerate aggregates; request-level
intermediates stay under `results/local`. `snapshot_phase.py` uses only the
Python standard library and does not execute either protocol.

The source line references above describe current runtime revision `5c7057f`.
The obsolete alternating δ/3δ cadence model is not used in this diagnosis.
