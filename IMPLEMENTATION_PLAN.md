# Delugi implementation and evaluation plan

Updated **29 October 2026**. The offline dissemination audit and requested
GPT-6 Pro review are complete. At four replicas, Delugi needs three current OBS
reports and two witnesses per advancing WA; Raptr's background PoA also needs
three signatures. The leading explanation is Delugi's proposal-blocking pool
exchange versus Raptr's optimistic inclusion during certification, together
with reporting opportunities and native batching. Collection averages are
178.33/177.92 ms. The common admission-to-proposal gap is **71.63 ms**, versus
145.67 ms between the stored-batch-to-proposal bars. No protocol code or workload
changed for this audit. See the [reproducible audit and Pro review](benchmarks/results/dissemination-audit-2026-10-29/README.md).
The next local diagnosis must establish exact snapshot eligibility and
source/proof readiness before selecting a scheduling optimization.

Raptr now has bounded, opt-in timestamps for exact
batch storage, availability quorum, verified proposal acceptance, commit slices,
payload validation and contiguous release. Its application endpoint now precedes
diagnostic serialization, matching Delugi's verified contiguous-output boundary.
Both protocols passed local healthy and silent-leader checks: four processes,
100 tx/s, one useful byte, Δ=100 ms, five seconds input plus three seconds drain;
all four runs completed and fully decomposed **500/500** requests with zero trace
drops. Validation passed **41 Rust and 135 Python tests**. `fab decompose` now
supports either protocol using downloaded signed evidence. See the
[local timing validation](benchmarks/results/raptr-timestamps-local-2026-10-29/README.md).
The timestamp-enabled Linux release **`3b4a1d9` has now completed two Raptr-only
Aliyun runs**, healthy and silent leader: four regions, **30 seconds at 100 tx/s**,
one useful byte, Δ=1,000 ms and the saved 20 Mbps natural-WAN profile. Healthy
completed and fully traced **3,000/3,000** requests; silent completed and fully
traced **2,992/3,000**, with eight London requests cancelled before admission.
Both execution/agreement checks passed and every admitted request completed.
There were zero dropped trace events and no repeated workload attempts.

| Mean admission-to-output stage, ms | Raptr healthy | Saved Delugi healthy | Raptr silent | Saved Delugi silent |
|---|---:|---:|---:|---:|
| Batch formation | 74.67 | 0.63 | 89.63 | 0.66 |
| Dissemination / inclusion | 190.54 | 336.21 | 2,268.63 | 3,472.68 |
| Consensus | 180.87 | 182.44 | 275.47 | 242.20 |
| Output processing | 2.50 | 0.12 | 351.93 | 464.91 |
| Total | **448.58** | **519.40** | **2,985.65** | **4,180.45** |

Delugi was not rerun; its 28 October traces were revalidated. Raptr's healthy
consensus time is almost equal to Delugi's; less proposal/inclusion waiting
accounts for its lower total despite longer native batching. Both silent runs
are dominated by proposal waiting. Raptr's silent output stage includes
290.54 ms of request-weighted section acceptance, primarily repeated signature
validation before deduplication in large recovery sections. That span also
includes blocking mutex and admission-row I/O work. No implementation change
was made during this rerun. Availability quorum overlapped proposal acceptance
for 1,349 healthy and 214 silent completed requests; serial-quorum bars therefore
describe smaller cohorts and must not replace the primary comparison.

See the [Raptr WAN comparison](benchmarks/results/raptr-wan-stages-2026-10-29/README.md)
and [stage figure](benchmarks/results/raptr-wan-stages-2026-10-29/latency-decomposition-comparison.png).
The Linux release passed 28 Rust and five supervisor tests. All four instances
and security groups are deleted; the build target was removed. The quote-based
fleet estimate is **CNY 14.07**, pending final billing. The previous WAN archives
retain their original post-journal Raptr endpoint. Different native batching,
4Δ versus eligible 7Δ recovery timers, faulty regions/mechanisms, separate-day
WAN conditions and observer overhead still require qualification before formal
comparison. Stage means exclude the eight unadmitted requests; full scheduled
cohort statistics retain them.

The earlier modified common Linux release **`cef4e22` has
completed four-region verification** through Fabric: exactly four **30-second**
runs, one healthy and one silent-first-leader case per protocol, at 100 tx/s,
one useful byte and Δ=1,000 ms. Singapore, Frankfurt, London and Seoul used
natural WAN delay and the saved 20 Mbps egress profile.

| Protocol / case | Completed / scheduled | Window goodput | End-to-end p50 / p95 |
|---|---:|---:|---:|
| Raptr healthy | 3,000 / 3,000 | 98.37 tx/s | 453 / 612 ms |
| Delugi healthy | 3,000 / 3,000 | 98.23 tx/s | 519 / 668 ms |
| Raptr silent leader | 2,984 / 3,000 | 81.80 tx/s | 3,077 / 5,380 ms |
| Delugi silent leader | 3,000 / 3,000 | 93.03 tx/s | 4,250 / 7,248 ms |

All execution/agreement checks passed. Raptr's 16 missing scheduled requests
were cancelled before admission at the finite cutoff; all 2,984 admitted
requests completed. They remain in the scheduled-cohort statistics. Delugi's
two decompositions cover all 3,000 requests each with zero dropped trace events.
Its silent-case mean is 4,180 ms: 3,473 ms awaiting the execution proposal,
242 ms in agreement and 462 ms awaiting contiguous prefix release. Frozen-input
age stayed below 0.48 ms. The honest nodes still reached admission round 39
while delivery reached round 20: the correction removes stale payload snapshots,
not the recurring timeout or admission/delivery round gap.

See the [30-second verification report](benchmarks/results/fabric-wan-30s-2026-10-28/README.md),
[record](benchmarks/results/fabric-wan-30s-2026-10-28/record.json),
[comparison](benchmarks/results/fabric-wan-30s-2026-10-28/latency-throughput-end_to_end.pdf)
and [decomposition](benchmarks/results/fabric-wan-30s-2026-10-28/latency-decomposition.pdf).
All four instances and owned security groups are deleted. The fleet cost estimate
is **CNY 17.51**, including preparation/build time, pending provider billing.
The release suite passed 24 tests; remote build intermediates and approximately
2 GiB of local build intermediates were cleared. This is a four-node verification
checkpoint; the 10/50-node formal comparison remains ahead.

The silent-leader backlog was first reproduced and corrected locally. Leaders
froze availability inputs at admission, then held
those stale inputs while waiting for HISTORY3. The new default opens the one
REPORT after admission and exact history readiness; `admission` remains available
for comparison. This is an explicit composition schedule revision to the pinned
paper's entry trigger. Ordering rules, timers and the scanner are unchanged.

At four local processes, 100 tx/s, Δ=1,000 ms, one useful byte, 60 seconds and at
most 15 seconds of drain, the old silent case completed **3,407/6,000** and the
fixed case **6,000/6,000**. Window goodput rose from **43.43 to 91.75 tx/s**.
Frozen-input age reached **34.97 s** before the fix and stayed below **0.9 ms**
after it. The fixed healthy control completed all 6,000 requests at 100 tx/s.
These were unshaped loopback correctness/causality checks with in-memory custody,
performed before the latest WAN rerun. The residual silent-case latency follows recurring 7Δ windows;
the fault silences the same replica on every fourth leadership opportunity.

See the [diagnostic record](benchmarks/results/silent-leader-fix-2026-10-28/record.json)
and [stage definitions and trace collection](docs/evaluation/latency-decomposition.md).
Bounded traces now join exact batches to proposal, classification, prefix and
append events. Fabric downloads their control pages and `fab decompose` produces
the additive means offline. The one-minute healthy trace hit its configured cap;
its decomposition was rejected. A separate five-second capture covered all
500 requests without dropped events. Before formal evaluation, review the paper's
REPORT trigger and qualify instrumentation overhead and larger-committee behavior.

The prior common Linux release `e2d1164` ran through
the saved Fabric deployment in Singapore, Frankfurt, London and Seoul.
**This was the pre-fix WAN baseline; the latest rerun is recorded above.**
Both healthy runs and Raptr's silent-leader run completed
all 6,000 requests. Delugi's silent-leader run completed 3,918/6,000, achieved
50.35 tx/s at 100 offered tx/s, and has a censored median latency of at least
24.796 seconds. Its honest replicas reached current round 72 but delivered only
through round 40. All agreement checks passed; this does not qualify its
sustained fault-case performance.

The [Fabric WAN record](benchmarks/results/fabric-wan-2026-10-28/record.json),
[CSV](benchmarks/results/fabric-wan-2026-10-28/summary.csv) and
[latency-throughput figure](benchmarks/results/fabric-wan-2026-10-28/latency-throughput-end_to_end.pdf)
retain exactly four one-minute runs at one input rate. All four instances and
owned security groups are deleted, and the remote Cargo target was removed.
The new quote-based cost estimate is CNY 20.33, pending final provider billing.
No consensus implementation code changed for this rerun.

All six Linux implementations build and deploy. Counterpart gaps, including
Autobahn's silent-leader recovery failure, still precede the main comparison.
The [WAN verification record](benchmarks/results/wan-verification-2026-10-28.json)
contains the bounded run matrix, artifact identities, outcomes and resource cleanup.
All four instances and their owned security groups have been deleted. Raw
results are retained locally; the record contains a quote-based cost estimate
and does not present it as a reconciled provider bill.

The reusable entry point is now [`benchmark/fabfile.py`](benchmark/fabfile.py),
with [saved settings and one parameter file](benchmark/README.md). The lower-level
[compact campaign runbook](docs/evaluation/compact-campaign.md) remains the artifact-build reference.
The [counterpart proposal](benchmarks/plans/2026-10-27-counterparts-and-aliyun.txt)
and [budget/load-point audit](benchmarks/plans/2026-10-27-aliyun-budget.txt)
retain the rationale and paper figure counts. Their former implementation
pending statements are superseded by this plan and its evidence.

The [configurable transport/Fabric checkpoint](benchmarks/results/configurable-transport-fabric-2026-10-28.json)
records the earlier local follow-up: 189 controller regressions, shared TCP tests
and four successful common-core process checks. The later Fabric rerun is recorded
separately above.

## 1. Scope fixed by the author

Six principal implementations: **Delugi, integrated Raptr, Simple-IT
Opt-Mempool, Simple-IT Opt-Dispersed, original Autobahn, Mysticeti-C**.
Delugi/Raptr share the executable and reusable services. The four other
implementations use pinned author sources, recorded patches and native
services behind the same campaign controller. Shoal, Vantage and Mysticeti-FPC
are outside this matrix.

The original six-implementation verification used **two workload attempts per implementation**:
healthy and silent first leader, each configured for 60 seconds, with one
100 tx/s total honest input rate, one useful byte per transaction and at most
15 seconds of drain. The four hosts are in Singapore, Frankfurt, London and
Seoul. Their provider egress cap is 20 Mbps; traffic uses an authenticated
WireGuard overlay. The maximum measured RTT is 240 ms, with zero loss in the
20-sample measurements of all 12 directed paths. Delta is 1,000 ms, using the
pinned Simple-IT default floor and retaining native timer multipliers.

Raptr's two attempts terminated early after approximately 55–58 seconds and
count toward the limit. One Simple-IT startup failure occurred before any arm
request or input; it was retained, repaired and retried. No started workload
was repeated. The larger matrix below is future work, outside this verification.

| Setting | Planned main campaign |
| --- | --- |
| Main committees | Exactly 10 and 50; n=4 remains a qualification fixture |
| Offered load | 1k, 4k, 8k, 16k, 32k, 64k total honest tx/s |
| Duration | One 60-second measurement; zero offered warmup; at most 15-second drain |
| Repetition | One; allowance of at most two additional points/reruns per curve, not automatically scheduled |
| Payload | 512 useful bytes; native encoding is recorded separately |
| Timing | Added one-way δ=10 ms; protocol input Δ=100 ms with native multipliers |
| Network | 100 Mbps aggregate private protocol egress per validator across peers and roles, including protocol ACKs |
| Machines | Singapore ecs.g9i.xlarge, 4 vCPU, 16 GiB, 200 GiB; one validator and all its roles per host |
| Cases | Healthy curve; one missing-data case; one native silent-first-leader case |
| Budget | User ceiling is the private recorded balance plus CNY 2,000; working allocation CNY 1,000 |

The default matrix contains 72 healthy and 24 conditional fault cells. The
estimate remains CNY 516–921 including reserve; this is an estimate, not a live
quote. Preparation, verification, collection and cleanup add billed wall time
outside the 60-second offered window. Public SSH/export bandwidth is a separate
5 Mbps setting. Keep finite leases, per-lease caps and the durable aggregate
budget ledger. A budget allowance is not evidence that the account was topped up.

## 2. Implemented and tested

| Component | Current evidence |
| --- | --- |
| Delugi core | HISTORY3, CLOSED, catch-up timers, scanner; authenticated bases, all-current construction, empty fallback, exact-batch forks/deduplication; paced PROG and immediate bundling |
| Integrated Raptr | Real pinned consensus and Quorum Store behind shared services; bounded sustained schema-2 input spools and signed journals; exact cutoff/cancellation accounting and traffic windows |
| Shared workload | One exact global schedule, independent of consensus; non-divisible rates, fixed honest-origin population, admission cutoff, censored unfinished work |
| Simple-IT | Both failure-capable author revisions build locally; mTLS identities, real arrivals, deterministic complete materialization, signed bounded evidence; healthy, silent-leader and three-header repair fixtures; both complete 60-second 4k tx/s diagnostics |
| Mysticeti/Autobahn | Native arrivals and output/cohort adapters; matched timer input; explicit original Autobahn pin; true first-leader startup absence supported by remote host lifecycle |
| n=50 profiles | Delugi explicit 64 MiB complete-current profile; f=16, high quorum 34, amplification 17; Raptr PoA corrected to native strict two-thirds quorum 34 |
| Campaign routing | One settings file resolves all six adapters and 96 cells; unsupported settings fail before provisioning; requested/effective values retained |
| Fleet lifecycle | Budget reserve before dispatch; exact owned IDs/tags; private peer firewall; bounded leases; artifact publication reuse; sequential interleaved trials; deletion on failure |
| Remote execution | All-host readiness/arm for common Raptr and Simple-IT; independent host clocks; only own secret keys; ceremony sealing; finite process supervision; gzip parallel evidence collection |
| Results | Exact cohort reduction; CSV retains failed/zero/censored/unrun cells; latency/goodput/completion/traffic PDF and PNG; sampled and final traffic boundaries remain distinct |
| Networking | Aggregate Linux egress tree, scoped peer/role selectors, before/during/after RTT checks, owned cleanup; real two-namespace aggregate bandwidth acceptance |

The WAN deployment adds a four-region lease profile, exact-peer WireGuard
setup and an observed-WAN mode that records real delays without applying
synthetic delay tolerances. Uploads are atomic and checksum checked, with a
bounded deadline suitable for WAN transfers. Original Autobahn builds with
libclang 14 and GCC 11, preserving its pinned protocol sources. Ceremony
sealing now restores host 0's private-key permissions after archive extraction;
41 remote-native tests and the local certificate test pass (the optional live
TLS probe was not run in that test invocation).

The 27 October Python suite ran 237 checks: **227 passed and 10 skipped**
(Linux-only and explicit native opt-in tests). Separate real-process and Linux
receipts supply their own evidence; skipped tests are not counted as passes.
The campaign state-machine tests use fake cloud/SSH backends. They do not imply
that the full new controller has run on Alibaba.

Evidence:

- [Four-region deployment verification](benchmarks/results/wan-verification-2026-10-28.json).
- [Current campaign checkpoint](benchmarks/results/compact-campaign-implementation-2026-10-27.json).
- [Simple-IT builds, authentication and workload fixtures](benchmarks/results/simpleit-local-2026-10-27.json).
- [Integrated Raptr sustained and scale fixtures](benchmarks/results/compact-integrated-local-2026-10-27.json).
- [Real Linux egress calibration](benchmarks/results/linux-egress-local-2026-10-27.json).
- [Earlier four-host pilot](benchmarks/results/aliyun-four-host-pilot-2026-10-26.json): 12/12 finite Delugi/Raptr functional trials; unshaped, different finite workloads. Its four instances and security group were deleted. This is historical acceptance of that artifact, not the new sustained campaign.

## 3. Qualification findings that determine the next work

1. **The WAN transport failure is repaired and remotely verified.** The
   tested Linux release (`5bb8899`) used a 100 ms TCP connection timeout; only
   four directed edges connected and eight longer edges failed. Both Delugi
   cases delivered zero transactions; Raptr also exhausted its outbound budget.
   A shared JSON `TransportConfig` now reaches both factories and records the
   effective connect/ACK/I/O/frame/reconnect timers and resource budgets. The
   connection default is 5,000 ms; Δ and consensus transitions are unchanged.
   Both common cores passed healthy/silent-leader local process checks with an
   explicit 5,678 ms connection timeout and 80/80 completions in each run.
   The rebuilt Linux publication passed 24 release tests. All 15 collected
   replica journals across the new four runs show a 5,000 ms connect timeout
   and zero rejected frames. Healthy end-to-end medians were 527.216 ms for
   Delugi and 455.189 ms for Raptr. The fault runs use their native first-leader
   hooks: Delugi replica 0 in Singapore retains transport ACKs; Raptr replica 1
   in Frankfurt is process-paused before arm. This is one load point, not a
   capacity curve or a statistically replicated comparison.

   **The pre-fix Delugi fault-case backlog was diagnosed and corrected.** Pending requests grew from
   1,772 at 30 seconds to 2,979 at 60 seconds; 2,082 remained unfinished at
   collection. All honest nodes were at current round 72 / delivered round 40,
   with zero transport rejections, queue-full failures or resource exhaustions.
   Its p50/p95 end-to-end latencies are lower bounds of 24.796/35.085 seconds.
   The later trace identified inputs frozen before HISTORY3 readiness. The
   `history_ready` composition schedule passed the local 60-second regression
   and the new 30-second WAN check, completing every scheduled request. Its
   recurring 7Δ waits and admission/delivery round gap remain explicit; tracing
   overhead and larger committees are not yet qualified.
2. **n=50 at Δ=100 ms remains open.** The local shared-machine Raptr empty test
   stalled before round 4. Δ=1,000 ms reached round 4 but qualifies only that
   diagnostic. Preserve 100 ms for the main series and resolve the failure on
   the actual release/profile before a paid sweep.
3. **Original Autobahn did not recover useful output with its first leader
   absent.** At 1,001 tx/s for 60 seconds, all 60,060 scheduled requests were
   accounted for and zero completed. Native output progressed through empty
   slots 1–4 and stalled at slot 5. Lifecycle/evidence capture passed; liveness
   did not. Investigate native timeout configuration/behavior and retain this
   result. The WAN verification reproduced zero completions from 6,000 admitted
   requests with the first leader absent, while its healthy run completed all
   6,000. Do not silently substitute the separate disruption branch.
4. **Simple-IT security qualification remains incomplete.** Direct-sender mTLS
   does not authenticate all transferred certificates or establish fallback
   safety. The mempool constructor fix is disclosed: its old cut certificate
   reset at two votes while its verifier required three at n=4. Test forged,
   replayed and forwarded evidence and the complete fallback path before making
   Byzantine claims. Both variants produced agreeing output in both WAN cases,
   but their one-transaction verification batches accumulated backlog at
   100 tx/s. Mempool completed 1,676/984 transactions in healthy/silent cases;
   Dispersed completed 1,121/147, out of 6,000 each. These batch settings do not
   measure the implementations' capacity.
5. **Observation and scale gates remain.** Mysticeti's remote exact observed
   workload prefixes agree, but do not establish a complete signed WAL terminal
   prefix. Both WAN cases completed all 6,000 requests; this qualifies the
   recorded workload progress, not the missing signed WAL proof. Requalify
   output fidelity, observer overhead, bounded state/RSS/disk
   growth and traffic-window alignment on the selected artifacts. Run loaded
   network calibration on actual hosts; namespace and idle RTT checks do not
   establish loaded cloud queueing behavior.

The new Delugi RocksDB silent-leader fixture made progress and agreed across
the three correct replicas: 300 scheduled, 221 completed and 79 unfinished at
the short cutoff. Mysticeti's corresponding short fixture completed 2,993 of
3,003 requests. These are functional observations on one local machine, not
comparative latency or capacity results. An absent leader from startup may be
skipped before measured arrivals begin; record that fault interval explicitly.

## 4. Next sequence

1. **Instrument productive readiness and proposal eligibility locally.** The
   source/trace audit and Pro review are complete; the avoidable portion of the
   healthy inclusion gap remains unmeasured. Capture exact fixed bases, OBS
   snapshots/branches, frozen-pool signers, WA witnesses, source/proof readiness
   and missed-opportunity reasons. Separate coordinate readiness from full
   legal input readiness. For Raptr, capture proposer-local batch arrival,
   eligibility/pull and PoA state. Separate proposal send and origin validation;
   retain local clocks and exact identities. Use request-, batch- and
   opportunity-weighted summaries. Start controlled local timing checks with
   unchanged native behavior; vary arrival phase, then test Raptr optimism and
   batching in separate controls. Preserve HistoryReady, fixed snapshots and
   n−f/f+1 thresholds; the sampled third-response wait is not a safe optimization.
2. **Review the REPORT-trigger revision and its local/WAN evidence.** The stale-input
   cause is fixed; the recurring 7Δ timeout cost remains explicit. Align the paper's
   entry-trigger wording with the selected composition schedule before a formal
   evaluation. Qualify tracing overhead and choose trace caps for the expected round
   rate. Preserve all prior WAN attempts and incomplete cohorts. The corrected
   common binary has now passed the bounded four-region check above; this does
   not establish the canonical paper's timing claim or larger-scale performance.
3. **Resolve the counterpart gaps.** Diagnose original Autobahn's recovery;
   choose Simple-IT batch targets compatible with the offered rate; audit its
   certificates/fallback and complete Mysticeti's signed native-order proof.
4. **Choose the next bounded qualification plan.** Both the four-run 28 October
   matrix and the two-run Raptr timestamp rerun are complete, with no repeat
   attempts. Retain the respective 16/8 cancelled pre-admission tail arrivals.
   Review the cost of validating repeated transaction occurrences in Raptr's
   output adapter before interpreting output processing as a protocol effect.
   Agree on the next finite matrix after the counterpart fixes; do not silently
   turn this smoke check into a rate sweep. Reuse exact native publications
   while their source and recipe identities match, and retain all failed runs.
5. **Qualify the intended 10/50 profiles and network.** Resolve the n=50 nominal
   timer failure and verify aggregate 100 Mbps and loaded delay on the selected
   hosts before interpreting latency/throughput curves.
6. **Run the agreed main matrix.** Use one common settings file and one campaign
   command, with fresh quotes and the durable budget ledger. Preparation and
   collection remain outside the one-minute measurement; release owned resources
   after collection and reconcile actual billing before releasing reservations.

`benchmark/parameters.json` now supports an explicit common `fault_rate`, as
used by the 100 tx/s verification preset. A null value retains the selector below.
The controller's fault-rate selector is diagnostic: at least 99% admission and
by-drain completion, and second-half pending growth at most 1% of that half's
offered population. It chooses below the largest jointly accepted point when
possible. Otherwise fault cells remain `not_run`. This does not certify the
stricter paper frontier rule. Define final frontier acceptance before producing
paper claims; do not relabel these points as measured maximum capacity.

## 5. Core and measurement contracts

Keep consensus/availability policy under `core/delugi` and `core/raptr`;
reuse network, crypto, storage, ingress and lifecycle in `shared`, `core-api`
and `node`. `ProtocolFactory` provides `name`, `run`, `generate_keys`,
`verify_archive` and `verify_ledger`. Native counterparts remain separately
named author systems. See the [interface map](docs/architecture/delugi-code-structure-2026-10-22.txt)
and [shared-service contract](benchmarks/plans/2026-10-21-shared-service-contract.txt).

- Q verifies complete immutable supplied metadata; payload retrieval stays
  outside proposal validation/scanner decisions. HISTORY3, once-only
  VOTE/CER/report obligations, terminal outcomes and 7Δ/3Δ timers remain intact.
- Earlier bases contain signed ordering headers, matching descriptors and
  n−f matching short CER signatures. Construction uses the frozen current OBS
  pool and authenticated-base empty fallback. Advancing targets require the
  leader's exact suffix and proof-producing state.
- Exact batch identity includes producer, height and unsigned-header digest.
  Valid Byzantine forks may both be ordered; exact-batch and request deduplication
  remain separate.
- Default scheduling uses originating-PROG pacing with a finite Δ release
  deadline and immediate bundling of enabled messages. Canonical and unbundled
  ablations remain explicit. TCP pipelines frames without an unconditional ACK gate.
- Shared RocksDB Written uses WAL-enabled `sync=false` writes before visibility.
  It does not provide core restart recovery. Native executor/worker, crypto,
  batching, storage and repair differences stay in effective manifests.

Use the selected archived tree matching
[spec-2026-10-19.json](provenance/spec-2026-10-19.json); live ordering.tex differs.
Do not refresh historical hashes automatically. Record the pacing amendment
separately. Canonical direct-commit bounds are not transaction admission-to-output
bounds for the paced implementation.

Primary latency is successful origin-local admission to the first locally
payload-verified contiguous application append. Retain scheduled-arrival
latency, rejected/cancelled/unoffered requests and unfinished censored tails.
Use same-host monotonic differences. Report useful unique completion TPS in
the measurement window and completion fractions by the drain cutoff. Remote
all-correct event latency requires its own qualified measurement.

Traffic tables expose measurement-window successful stream writes separately
from sampled total-run writes. Native TLS, worker-local links, sample offsets
and lateness stay explicit. SSH export is excluded; TCP/IP headers and kernel
retransmissions require separately named OS counters. Zero-output cost ratios
remain undefined. Stage figures must use local spans and causal dependencies;
never add overlapping spans or subtract different host clocks.

Continue periodic commits/pushes. Keep sources, binary receipts and raw evidence;
remove disposable targets. New outputs remain `comparison_eligible=false`
until the listed gates are actually satisfied.
