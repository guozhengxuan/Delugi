# Progress — 21 October 2026

## Approved shared-runtime implementation

The user approved the reviewed local Delugi-to-Raptr phase and requested periodic
commits and GitHub pushes. Work resumes with frozen service/output contracts,
source-preserving Delugi extraction, then the Raptr port and local acceptance.
The pre-extraction source and verified Delugi executable are preserved under
`results/local/shared-core-20261021/reference/`. Subsequent sections record earlier
checkpoints; their paused status is superseded by this approval. Native Raptr
observer fragments remain unfinished and are not accepted benchmark results.


## Implementation paused for shared architecture review

Two consultation rounds in `delugi context` are complete. The
[reviewed shared-core proposal](benchmarks/plans/2026-10-21-shared-core-architecture.txt)
recommends refactoring Delugi's services, preserving protocol-owned dissemination
and recovery, then porting Raptr first. Approval is requested only for the local
Delugi-to-Raptr phase. Implementation remains paused pending the user's agreement.

The user explicitly stopped implementation on October 21. The next decision is
a shared runtime with protocol-specific `core/<protocol>` subtrees and reusable
network, crypto, node, mempool and evaluation services. Consult `delugi context`
and study the Sonnino HotStuff/Ditto family, then obtain the user's approval of
the concrete plan before any implementation, build or benchmark resumes.

The immutable source checkpoint is
`results/local/architecture-review-20261021/implementation-checkpoint/manifest.json`.
It preserves 137 Delugi/support files, 22 changed/new native Raptr files and both
tracked diffs. Raptr artifact guards passed 28 checks and independent ingress
passed 8 before the pause; the new native observer and collector remain
incomplete and unaccepted. No Raptr native build or new trial started. All agents
stopped implementation and a filtered host process check found no task build,
validator or owned VM process. Earlier plans below are historical pending review.

## Raptr priority amendment

Raptr is now the primary counterpart, ahead of further Shoal work, following the
user's explicit direction. The [Raptr-first plan](benchmarks/plans/2026-10-21-raptr-priority.txt)
supersedes the older supplementary designation. Work continues from the authors'
existing pinned `raptr-public` checkout. Its historical aggregate metrics need
finite authenticated cohorts and contiguous payload-ready output accounting
before joining the current comparison harness. New Shoal trials are deferred;
its completed validator and unfinished build evidence are retained separately.

## Current local continuation

The [October 21 continuation](benchmarks/plans/2026-10-21-local-continuation.txt)
keeps execution local. The current increments are independent Mysticeti WAL
prefix verification, Shoal full/compact observers and local campaign integration,
and locally tested prepare/arm startup for future Shoal deployments.

The shared calibration policy now checks raw RTT samples and exact directed
peer/role identities. At added delta = 10 ms, the accepted added median RTT is
20 ± 5 ms; selected and control paths must return to baseline after cleanup.
Forged summary medians, missing/duplicate peers and falsely passed labels are
rejected. All four failed October 19 VM observations remain rejected. There is
no new verified 10 ms protocol measurement. The revised source checkpoint passed
205 focused Python checks and revalidated all five retained Shoal fixtures;
see the [timing/campaign record](benchmarks/results/campaign-timing-validation-2026-10-21.json).

The local campaign accepts Shoal healthy n4/n7 and the previously accepted n4
pause/semantic-omission configurations. It requires native bootstrap, REST and
counter readiness before admission, swap disabled, and every owned process
reaped. Added-delay Shoal campaigns remain disabled until a calibrated local
transport path is integrated. A fresh n4/n7 campaign awaits the observer build.

Mysticeti's frozen output-prefix verification is complete: 32 retained replica
archives match 1,988,196 complete-block checkpoints against signed native WAL
blocks, and all eight runs have matching correct-replica prefixes. The bounded
reader used 52.6 MB peak process memory; derived scratch was removed. Its 52
Python tests pass, including altered/missing/reordered output evidence. The
adapter now performs the check after stopping its owned replicas. This verifies
native output bytes and persisted commit order through the exact freeze;
admission clocks, quorum certificates and durable fsync are separate claims.
See the [WAL prefix report](benchmarks/results/mysticeti-wal-prefix-fidelity-2026-10-21.txt).

Shoal native observer acceptance is in progress. Exact binaries and historical
evidence remain retained. The October 19 checkpoint below records the earlier
accepted artifacts and measurements.

Future Shoal deployment now prepares every host before arming ingress. Readiness
requires native bootstrap, direct REST, fresh network counters and the exact
finite observer identity. A failed arm stops the other owned workers, including
late launches. Full-mode receipts are revalidated after transfer and reconciled
with each origin's detailed cohort; failed validation fails the run. All 61
local contract checks pass. See the [deployment readiness record](benchmarks/results/remote-shoal-readiness-2026-10-21.json).
This does not claim remote execution or synchronized clocks across hosts.

The combined current Python checkpoint passes 366 main and 120 baseline tests;
see the [regression record](benchmarks/results/combined-local-validation-2026-10-21.json).
The Shoal pause harness records requested and observed boundaries, checks the
owned process identity, and requires bounded stop/resume acknowledgements. Its
29 focused checks and a real Linux pause/resume/final-freeze smoke pass; the
smoke child was reaped. This closes the gap between a configured pause and an
observed pause without changing native protocol code.
Shoal's new native build and live observer controls remain separate acceptance.

## Accepted checkpoint — 19 October 2026

## Evaluation migration: local acceptance

The [reviewed October 19 plan](benchmarks/plans/2026-10-19-evaluation-migration.txt)
retains the Delugi core and compares native published artifacts through a common
external harness. Current work is local only; cloud deployment and the new
verified 10 ms added-delay comparison have not run. Mac administrator access is
unavailable; no further password or helper action is requested.

The campaign now evaluates declared native batching grids against a common tail
target and ten exact backlog subwindows. It requires every repetition of one
load/setting to pass before selecting a measured frontier or resolving matched
utilization. See the [frontier contract](benchmarks/plans/2026-10-19-frontier-selection.txt).
Shoal's pinned native validator and genesis/workload fixture now build and pass
five bounded local acceptance fixtures in the task-owned Linux VM.
The new full/compact Delugi observer source passed 248 ordinary Rust checks and
all 19 actual TCP/process checks. Both modes retain payload validation and exact
correctness receipts; only full mode retains detailed request timings. The new
release passed six functional fixtures and six alternating observer trials;
every sustained run completed 4,800 requests at all four replicas. Detailed
instrumentation added 0.19–1.60% CPU across these short pairs, with median 0.43%.
Full-mode p99 was 16.41–16.51 ms with no added delay and configured bound 100 ms.
The [observer validation report](benchmarks/results/delugi-observer-validation-2026-10-19.txt)
records exact boundaries and identities. Build cleanup removed 331 MB of
intermediates; target retains only the verified executable and stamp, about 3 MiB.
The previous release and its evidence remain unchanged. Python verification
passed 328 main and 68 baseline checks; the earlier 394-check
[validation record](benchmarks/results/migration-observer-python-2026-10-19.json)
retains its own logs and source snapshot.

Mysticeti's full/compact observer passed all 62 native core tests, including three
new receipt tests and the native TCP test, plus 127 focused Python checks. All
12 live trials passed: both modes agree on healthy, empty and unfinished
cohorts, and every sustained run completed 4,800/4,800 requests at all four
replicas. The median CPU difference was +0.46% across three short pairs
(range +0.12% to +0.92%). This measures detailed instrumentation above the common
correctness observer, not total observer-free cost or a capacity difference.
All 48 processes were reaped. Cleanup saved 6.47 GB through removal of build
intermediates and recomputable SQL caches plus verified raw-evidence compression.
Both binary versions and exact evidence recovery instructions remain in the
[Mysticeti validation record](benchmarks/results/mysticeti-observer-validation-2026-10-19.txt).
Independent signed WAL-tail fidelity remains an open comparison gate.

Shoal's healthy n4 and n7 fixtures completed 120/120 and 210/210 requests;
finite-pause and semantic-omission fixtures each completed 120/120 honest
requests with matching output prefixes. The omission suppressed six actual
native publications; attacker output remains in the raw prefix without useful
honest-output credit. The empty fixture completed 0/0 and retains 274,647 TCP
bytes with undefined cost ratios. Native DAG bootstrap and initialized counters
must precede the workload epoch, local peers and REST bypass inherited proxies,
and every accepted run verifies swap disabled at both boundaries. A zero-drain
CPU accounting regression was corrected in the collector. These launch and
measurement fixes leave the tested native binaries unchanged. Shoal observer
overhead and campaign integration remain open. Cleanup removed 6.26 GB of
allocated build intermediates inside the VM, retaining both tested executables
and their stamp (167 MB). The task-owned VM is stopped. Source, dependency caches
and raw evidence remain; the host sparse disk size is a separate quantity.
All 17 Linux adapter contract tests passed. The
[Shoal acceptance report](benchmarks/results/shoal-native-local-acceptance-2026-10-19.json)
retains the five accepted runs, failed attempts and cleanup evidence.

Later cohort regressions reject output-before-admission credit even when event
timestamps round to the same microsecond; raw output and M_out stay retained.
Six full-mode Delugi archives replayed unchanged. Prepared deployment packages
now include the new Mysticeti receipt reader and mirror Shoal's scoped child
proxy settings; 42 local deployment/native-campaign checks passed, including an
isolated packaged-runtime import. No remote execution occurred. Remote Shoal
readiness still needs the native-bootstrap/epoch guard validated locally; its
current TCP-only check is not covered by the accepted local launch path.

The [isolated Linux delay check](benchmarks/results/local-netem-calibration-2026-10-19.json)
verified setup and complete cleanup twice, but failed timing calibration: the
10 ms setting added 25.8–29.4 ms RTT instead of 20 ms within the declared tolerance.
No protocol benchmark used those conditions. The VM therefore does not replace
the pending verified 10 ms added-delay comparison.

The runner now uses independent finite arrivals, authenticated identities and
origin-local admission-to-output cohorts with explicit unfinished requests,
deadlines and drain. This changes the measurement contract from the historical
completed-window measurements below. Raw archives and binaries preserve that
distinction. The [current status](benchmarks/plans/2026-10-19-migration-status.txt)
records outstanding native adapter and distributed acceptance work.

The frozen Delugi hardening release passed 236 Rust checks, all 19 actual TCP/process checks,
and live schema-2 healthy/zero-output collection. All 1,200 finite requests in the
healthy fixture materialized at all four replicas. Exact successful-write byte
categories reconcile with total traffic, and a 31.7 MB authenticated n31 witness
passes complete Q and TCP transfer. These are functional acceptance checks.

The [short matched local pilot](benchmarks/results/migration-matched-n4-final-2026-10-19.json)
uses 1,200 offered tx/s, 472 useful bytes, no added network delay and an exposed
100 ms bound preset. Delugi, Mysticeti and Autobahn each completed all 3,600
measured requests; origin-local p99 values were 16.380, 13.098 and 26.076 ms.
This single rate point does not establish sustainable capacity. Native timers,
batching, persistence and transport still differ.

The current Delugi target retains only its tested executable and build stamp,
about 3 MiB. The repository occupies 46.68 GiB, of which 42.56 GiB is retained
local evidence. Historical raw evidence remains retained or recoverably compressed.
Full migration is still in progress: Shoal observer controls and campaign
integration, advanced fault scenarios, native resource attribution and Mysticeti
WAL-tail fidelity remain local acceptance gates.

## Historical validation — 14 October 2026

## Default ordering schedule

PROG-only pacing with immediate per-peer ordering bundling is now the default.
Origin PROG(`k`) is released after entry when a full valid proposal at `k-1` or
`k` is available, or at the finite Δ deadline. PROG(1), `f+1` amplification, and
all enabled positive ordering messages remain immediate. Bundling has no fill
wait or timer. Canonical scheduling and the full outgoing barrier remain
explicit comparison modes; [README](README.md) documents the exact guards and
configuration.

Fresh validation passed **216 Rust tests and 127 Python tests**, plus independent-
process round-4 and silent-leader recovery tests in the default, canonical, and
full-barrier modes. The default was exercised without any ordering opt-in flags.
At 4,000 offered tx/s, delta=10 ms, Delta=100 ms, 512-byte transactions, and
100 ms ingress cadence, the new binary completed 3,999.943 tx/s at **70.997 ms**
mean transaction latency over a 60-second window after 10 seconds warmup.
Pending transactions stayed at zero at both boundaries; the run fully drained,
and all four replicas agreed. Successful replica TCP writes averaged 10.439 MB/s.
The [default-promotion validation record](benchmarks/results/bundling-default-2026-10-14.json)
binds the checks and measurements to the final source and binary hashes.

Removed **51.56 GiB** of generated Delugi/Raptr/Mysticeti/Vantage build output
after validation. The repository occupies about 35.56 GiB, primarily retained
raw benchmark evidence. Build directories are ignored and require rebuilding;
source checkouts, recorded results, logs, and source snapshots were preserved.

This promotes the measured PROG-only variant below; its earlier measurements
remain historical. The current paper sources remain unchanged, so the
new default's PROG-origin timing is an implementation amendment whose latency
proof must be incorporated into the specification.

## Ordering pacing experiments and measured backlog removal

The measurements and validation in this section were collected before the
default change, when both pacing variants and bundling were opt-in.

Implemented the requested wait-for-readiness round barrier, immediate per-peer
message bundling, and a narrower alternative that paces only originating PROG.
The full barrier waits for a valid proposal, own vote, and the previous round's
terminal outcome and exact history report before releasing its ready messages.
An independent finite deadline and recovery escape keep missing proposals from
deadlocking admission. Quorum, signature, Q, history, and outcome checks remain
intact; no timeout fabricates CLOSED or a certificate.

The full barrier removed measured admission/certification drift, but held a ready
CER for 9.93 ms on average. Pacing only PROG avoids that added delay: VOTE, CER,
HISTORY3, and CLOSED retain their original prompt-send rules. Immediate `f+1`
PROG amplification remains enabled in both modes. Both change the paper's
PROG-origin timing; the canonical latency theorem is not automatically a theorem
for either scheduling variant.

The final **same-binary, tracing-disabled** comparison used four independent
replicas, 4,000 offered tx/s, 512-byte transactions, 100 ms ingress cadence,
10 seconds warmup and 60 seconds measurement. Requested one-way proxy delay was
delta=10 ms and protocol Delta=100 ms; calibration measured 22.43/22.50 ms added
RTT, including userspace scheduling. Each mode has one run at this duration.

| Mode | Completed tx/s | Mean transaction latency (ms) | TCP writes (MB/s) | Pending transactions, start → end |
| --- | ---: | ---: | ---: | ---: |
| Canonical scheduling | 3,933.356 | 584.404 | 16.429 | 400 → 4,401 |
| PROG-only pacing + immediate bundling | 4,000.019 | 71.296 | 10.434 | 0 → 0 |

Latency runs from origin insertion immediately before signed batch production to
post-handler local materialization, using transactions completed in the window.
It is not PROPOSE-to-commit latency. Canonical ten-second epoch latency reached
1,014 ms in the last epoch; PROG pacing stayed near 71 ms. The admitted-minus-
delivered gap grew from 14 to 101 in the canonical run and stayed at 2–3 with
PROG pacing. Both runs fully drained and all four replicas agreed on every
generated transaction.

Separate stride-64 traced diagnostics measured 388.25 ms transaction latency for
canonical scheduling, 355.45 ms for immediate bundling alone, 76.95 ms for the full
barrier, and 71.19 ms for PROG-only pacing. Exact PROPOSE-to-direct-commit means
were 32.41, 44.51, and 32.96 ms for canonical, full barrier, and PROG-only
respectively. With PROG pacing, all 5,327 releases in the measurement window were
readiness-triggered, with no deadline release; HISTORY3 was already available
before input fixation. The three-round certification-minus-admission cadence
excess fell from 0.476 ms to 0.001 ms, eliminating the observed accumulation.

These traced runs span two builds and are diagnostic observations, not an
identical-binary four-way ablation. A stride-128 canonical control also stayed
near 77 ms, demonstrating sensitivity to tracing and host scheduling. The
tracing-disabled final pair establishes the improvement on the same binary;
these local tests do not establish a universal latency ratio or WAN capacity.

Validation of those experimental builds passed **214 Rust tests**, including the
16 explicit socket tests, and **59 Python tests**. Both scheduling variants passed independent-process
round-4 and silent-leader-followed-by-three-honest-anchors tests. Deterministic
tests also cover delta=99 ms with Delta=100 ms, invalid/header-only proposals,
amplification, deferred CLOSED counting, and authenticated Byzantine hints.

These runs explicitly enabled `--progress-pacing-ms 100 --ordering-batch`
for PROG pacing and `--round-barrier-ms 100 --ordering-batch` for the full barrier.
Current runners select PROG pacing and bundling by default; use
`--ordering-mode canonical --no-ordering-batch` for the earlier canonical
scheduling/framing choices, or `--ordering-mode barrier` for the full barrier.
[Verified compact results](benchmarks/results/ordering-gap-2026-10-14.json)
link every retained run, source identity, validation result and the stage figure.

## Earlier admission/delivery profiling and sustained results

The old per-frame ACK gate is absent. Transport is byte-identical between the
727.718 ms run and the subsequent 140.400 ms local-validation-reuse trial; neither
filled its ACK window. Profiling instead found repeated settlement/history scans,
duplicate cryptographic and proposal checks, and input age growing while the
HISTORY3 dependency chain lagged independent PROG admission. The recorded healthy
CER outcomes preceded main/catch-up expiry; there was no healthy 7-Delta wait.

The implementation now indexes unfinished work, scans only the unpassed suffix,
wakes on incoming packets, reuses exact successful signature checks, reuses
completed local proposal/Q/report-proof validation, and avoids discarded
serializations. All wire bytes, frozen observations/inputs, protocol guards,
timer constants and exact-batch output rules are preserved. Canonical specification
hashes still match the 13 October pin. Validation passed 200 Rust and eight
Python tests, including legacy behavior comparisons and real TCP fault cases.

The final binary was measured sequentially in three repetitions at each rate,
with four independent replicas, 512-byte transactions, 100 ms ingress cadence,
ten seconds warmup and thirty seconds measurement. The delay proxy requests
delta=10 ms per direction and protocol Delta remains 100 ms.

| Offered tx/s | Median completed tx/s | Median mean latency (ms) | Median TCP writes (MB/s) |
| ---: | ---: | ---: | ---: |
| 1,000 | 996.664 | 199.403 | 11.554 |
| 4,000 | 3,933.384 | 422.869 | 16.367 |

Every run drained and all replicas agreed, but every measurement window gained
pending transactions. A separate 60-second measurement at 1,000 tx/s averaged
194.386 ms while successive ten-second epoch means rose from 107 to 323 ms;
the admitted-minus-delivered gap grew from 9 to 33–34. The sustained latency
issue is reduced, not fully resolved, and no steady-state capacity is claimed.
The maximum peer window was 17 frames / 85,800 bytes across the six repetitions,
with zero transport retries or failures. Honest round-4 and silent-leader followed
by three honest anchors both passed on the same final binary.

The [profiling report](benchmarks/SETTLEMENT_PROFILING.md) and
[verified compact results](benchmarks/results/admission-profile-2026-10-14.json)
preserve intermediate regressions, exact endpoints, all repeated trials, growth
epochs and raw archives. These userspace-delay measurements remain separate
from the earlier kernel-shaped three-protocol matrix.

## Earlier ACK pipeline fix and exposed sustained-load regression

The per-frame transport ACK gate is removed. Each peer pipelines a bounded
64-frame/8-MiB window while an independent reader collects authenticated ACKs.
FIFO retirement, exact suffix replay, sequence-gap rejection, retry deduplication
and bounded shutdown pass real TCP fault tests. Accepted sockets now explicitly
use blocking I/O with timeouts, fixing macOS receiver busy polling. Proposal
readiness and certificate candidate selection also avoid redundant verification
while preserving history bytes and complete proposal checks.

Final verification passed 156 Rust tests, including 16 explicit loopback tests,
and 8 Python delay-proxy tests. Four-process honest round-4 and silent-leader
recovery tests passed with delta=10 ms and Delta=100 ms, with complete output
agreement and cleanup.

At that intervention the native latency issue was **not resolved**. With matched userspace TCP delay
and 1,000 offered tx/s, the original versus final 10-second-warmup/30-second-window
runs measured 919.203 versus 2,418.452 ms mean latency, and 997.465 versus 929.973
completed tx/s. Final pending transactions grew from 1,200 to 3,300 before fully
draining. Per-replica CPU fell from roughly 280% to 104% after the socket fix,
but control traffic and the admitted-versus-delivered round gap increased.
This result prompted the admission/delivery profiling reported above.
Short-run latency improved but did not predict sustained behavior.

The [transport report](benchmarks/TRANSPORT_PIPELINE.md) records the implementation,
regressions, all intermediate results and final measurement limits. This
userspace-proxy experiment is separate from the archived kernel-shaped matrix
below; no old measurement was overwritten and no three-protocol rerun is claimed.

## Timing-controlled rerun and evaluation architecture

The requested delta=10 ms / Delta=100 ms comparison passed all 18 trials,
plus a three-protocol low-load preflight. All protocols delivered close to both
1,000 and 4,000 offered tx/s. Median mean latency was Delugi 761.595/789.816 ms,
Raptr 161.144/175.228 ms, and Mysticeti 46.724/45.363 ms respectively. The added
round-trip delay calibrated at 20.681 ms before and 20.618 ms after the matrix.
All six Delugi trials drained and agreed on complete output; temporary network
rules, pipes and the helper's PF reference were removed.

The [timing report](benchmarks/TIMING_COMPARISON.md) and
[raw-linked compact results](benchmarks/results/timing-controlled-2026-10-13.json)
record throughput, traffic, timer mappings, native metric boundaries and the
macOS droptail/statistic limitation. An independent audit rechecked all 18 trials.
A counter audit identified Delugi's then-current stop-and-wait per-peer transport at
roughly 49 frames/s under 20 ms RTT; it does not attribute the full latency to a timer.
Raptr now exposes its native bound while preserving multipliers and independent
batching. Mysticeti's public timeout is now wired to its native task, preserving
its effective one-second default. The Delugi binary was unchanged for that matrix.

Vantage pin 199098c4978e4a97a7d3707ec9aac6de086969db built unmodified and passed all
five native functional smokes. Coverage was 712 unchanged workspace tests plus the
remaining authentication test with an archived ephemeral-port fixture adjustment;
the checkout and measured binary were restored/unchanged. These native smokes use
one process and are separate from the four-process comparison.

The [architecture decision](benchmarks/ARCHITECTURE_COMPARISON.md) recommends a
Vantage-derived shared runtime with a Delugi adapter, preserving this repository
as the reference and retaining native Raptr/Mysticeti as external baselines.
Manual Mysticeti consensus reimplementation is deferred. AWS has the documented
WAN harness path; Alibaba needs provider integration. No remote fork or cloud
resources were created. The earlier native-timer comparison below remains intact.

## Sustained load and matched four-replica comparison

The new sustained driver generates paced transactions inside each independent
Delugi replica and records unique origin completions, latency histograms, actual
input, queue growth and successful TCP writes. Custody now indexes branch and
checkpoint updates, and local materialization reads verified suffix records
without constructing network-transfer packets. Fork, proof and segmented-retrieval
regressions cover both changes.

The matched comparison uses 512-byte serialized transactions, 100 ms origin
ingress batches, 10-second warmup and 30-second measurement windows. All trials
run sequentially on the same Apple M4 Pro host. Each implementation and rate has
three valid repeats; pinned native baseline algorithms, internal batching,
cryptography, storage and logging are retained.

| Offered tx/s | Implementation | Median completion tx/s | Median mean latency (ms) | Median TCP writes (MB/s) |
| ---: | --- | ---: | ---: | ---: |
| 1,000 | Delugi | 930.9 | 1,519.740 | 3.484 |
| 1,000 | Raptr | 999.5 | 91.342 | 3.018 |
| 1,000 | Mysticeti | 999.9 | 1.603 | 27.794 |
| 4,000 | Delugi | 3,819.6 | 1,402.016 | 8.100 |
| 4,000 | Raptr | 4,000.1 | 107.408 | 7.540 |
| 4,000 | Mysticeti | 3,999.1 | 2.083 | 33.906 |

Delugi accumulated queues at both rates despite generating close to the requested
load. All six trials later drained and passed complete transaction-output
agreement across four replicas. Both baselines kept up at these two tested rates.
Delugi had lower measured TCP traffic than Mysticeti and slightly higher traffic
than Raptr. Native storage and precise latency endpoints differ; the report
documents them alongside ranges and actual input rates.

One Raptr attempt failed because a non-atomic metrics scrape produced a negative
derived pending estimate. A parser-only correction preserves that signed estimate
and validates actual counters independently. The failed attempt is retained;
one replacement passed with identical native binaries. Reanalysis left all five
other Raptr measurements unchanged. All owned processes were reaped.

Validation: 142 Delugi Rust tests, including five real socket/process tests;
101 Python tests; 55 native Mysticeti tests (one upstream test ignored); and five
new native Raptr instrumentation tests passed. Formatting and whitespace checks
passed. See the [comparison report](benchmarks/MATCHED_COMPARISON.md) and
[compact results with archive hashes](benchmarks/results/matched-2026-10-13.json).

## Option A composition — implemented and verified

The implementation now follows the October 13 standalone specifications pinned
in `provenance/spec-2026-10-13.json`. Earlier directly certified descriptors
supply self-contained base evidence. Leaders select the greatest locally held
eligible base and automatically issue signed REPORT requests on admission;
replicas answer once, including before their own admission. Q uses only supplied
metadata. The constructor scans every coordinate, selects its highest feasible
current advance or an empty suffix, and supplies an all-current witness.

Materialization emits exact `(producer, height, unsigned-header digest)` identities
once in descriptor/producer/height order. Distinct Byzantine forks, including
unseen batches below the current cumulative height, remain in the common logical
batch log. Shared prefixes are deduplicated; signature encodings are excluded
from logical output. Application duplicate IDs and malformed payloads are
separate deterministic no-ops. Invalid authenticated peer inputs are counted and
rejected without stopping the honest process.

**Validation passed:** 130 ordinary Rust tests plus five explicitly enabled real
socket/process tests; 24 Python network-harness tests; 18 reproduced semantic
traces; and six real four-process TCP trials. The broader Python test discovery
also passed all 57 tests. Fork regressions validate genuine signed proposals and
availability witnesses, then compare materialization at all four replicas.
The recurring-silent semantic run also exercises certificate adoption: round 7
uses base 2 and round 8 uses base 3, with unchanged immutable Q.

The native acceptance harness prepares four finite batch waves before starting
ordering, then relies entirely on protocol REPORT/OBS. It checks exact batch and
transaction agreement, round-4 HISTORY3, all honest anchors, and the silent round's
skip. All-current evidence contained four signed REPORTs and 16 OBSs in honest
runs, or three REPORTs and nine OBSs in silent runs. Every trial used distinct
processes and fresh keys; all exited successfully. Socket reads/writes balanced;
outstanding frames, retries, rejected frames/protocol inputs and queue failures
were zero in these six acceptance trials.

| Median of three trials | Honest rounds 1–4 | Silent leader 1, honest anchors 2–4 |
| --- | ---: | ---: |
| Exact batches at each honest replica | 16 | 12 |
| Distinct transactions at each honest replica | 32 | 24 |
| All submitted transactions materialized | 98.249 ms | 1,851.905 ms |
| Descriptor delivery through round 4 | 116.968 ms | 1,850.391 ms |
| Total successful TCP stream writes, including ACKs | 444,996 bytes | 4,358,234 bytes |

Latency starts at the first client submission and ends at controller receipt of
post-handler events. It includes preparation and telemetry. The preloaded workload
can finish its transaction output in the first honest proposal, before the final
descriptor is delivered. Traffic includes ongoing progress beyond workload round 4;
its longer recovery interval contributes to silent-run traffic. TCP/IP headers,
kernel retransmissions and separate client-control bytes are excluded from this
socket figure. These finite acceptance measurements use a different workload
schedule from the historical runs below and the native sustained baselines.

[Compact results and archive hashes](results/option-a-2026-10-13.json) retain the
precise endpoints, per-trial traffic and provenance. Raw network archive:
`results/local/network-e9a90648a8f14267bb4d516b2ee27267/manifest.json`.
Semantic archive:
`results/local/composed-a079a8a98b6e4deebc0d09f4ceeb5bb6/manifest.json`.

The bounded availability profile supports 4 or 7 replicas. It reserves the largest
canonical u64-height proof vectors and complete current evidence within 1 MiB;
larger committees require a larger message profile. State and custody remain in
memory. The sustained-load increment above adds matched performance measurements;
singleton execution, durable restart and multi-host evaluation remain subsequent work.

## Historical initial native baselines

The official Raptr and Mysticeti paper artifacts are pinned in
`provenance/baselines.json`, with reusable native-process runners under
`scripts/baselines/`. Build caches, upstream checkouts and full raw archives are
local and ignored; patches and compact result summaries are versioned.

Mysticeti's unmodified pinned source builds with Rust 1.78. Three sequential
four-validator localhost trials at 1,000 configured transactions per second,
10 seconds of warmup and 30 seconds of measurement produced across-trial medians
of 999.812 observed tx/s and 1.290 ms mean generation-to-consensus-commit latency.
52 native core tests passed and one upstream test was ignored.

Raptr's native Aptos node and Forge release build succeeds with documented macOS
and stale performance-interface repairs. Three sequential four-validator trials
at 1,000 configured transactions per second, 10 seconds of warmup after readiness
and 30 seconds of measurement produced across-trial medians of 1,000.279 unique
ingress completions per second and 93.066 ms mean insertion-to-payload-ready-commit
latency. Nine native signature tests, 26 runner regressions and a four-process
smoke test passed. All trials exited naturally and left no owned processes.

See [baseline documentation](benchmarks/README.md) for commands, raw-manifest
hashes and measurement boundaries. These are small native consensus workloads,
with no application execution or matched comparison against Delugi's finite
integration workload. Transaction sizes and latency endpoints also differ between
the two baselines; these results are not a comparative ranking. Network traffic
is not measured by either native adapter. These baseline measurements were
completed before the Option A implementation increment above.

## Historical implementation and measurements — 12 October 2026

The remainder records the earlier implementation and its original fixture. Its
base authorization, historical-first policy and compatibility rejection are
superseded by the Option A implementation above.

Delugi now runs as independent replica processes over real authenticated loopback
TCP. The same ordering/dissemination state machine runs in each process with real
clocks, serialization, signatures, proof construction and in-memory custody. The
requested round-4 and silent-leader recovery tests have passed with measured
end-to-end latency and traffic. The canonical paper files were not modified.

## Current implementation

The existing reference includes signed sequential batches, exact branch storage,
indexed chunked MMRs, current/historical availability evidence, immutable Q,
HISTORY3/CLOSED, main/catch-up timers, the scanner, segmented FETCH/DATA retrieval
and deterministic transaction materialization.

The new process layer adds:

- `src/transport.rs`: bounded TCP frames signed over instance/identity/sequence,
  layer and payload hash; signed acknowledgements; per-peer FIFO queues;
  reconnect and exact-frame retry; duplicate suppression; explicit overload failure.
- `src/process.rs` and `src/bin/delugi_replica.rs`: independent replica state,
  monotonic timers, loopback TCP batch/control requests, fresh per-run Ed25519 keys,
  real post-handler telemetry, and explicit observation cutoff/drain/shutdown.
- `scripts/run_network.py`: four-process launch, coordinated workload/reporting,
  exact useful-output checks, repeated measurements, traffic reconciliation,
  source/spec snapshots and complete raw logs, including failures.
- Transport and process regressions for fragmented/coalesced frames, forged or
  oversized inputs, lost acknowledgements, reconnect duplicates, late peers,
  queue saturation, authenticated pre-start mailbox retention, unauthorized
  client commands and ungated consecutive batch production.

Transport is an initial reliable implementation: one frame is outstanding per
peer while its signed ACK is awaited. Its additional signature, queueing and
stop-and-wait costs are measured. It is not an optimized networking baseline.
Accepted control sockets explicitly use blocking timeout I/O, including on macOS
where accepted sockets may inherit a listener's nonblocking flag.

## Verified measured results

**All six real-network trials passed:** three all-honest runs and three with
replica 0 protocol-silent. Every trial used four distinct OS processes, fresh keys
and a fresh instance. All honest replicas agreed on every descriptor, exact
transaction sequence and final state hash. Honest round 4 carried real HISTORY3
through horizon 1; silent round 1 was skipped via honest anchors 2/3/4.

**122 Rust tests passed** (118 ordinary tests plus four explicitly enabled real
socket/process tests), along with **15 Python measurement-harness tests** and
formatting checks. Every process exited successfully. Every measured run ended
with zero outstanding frames, zero retries, zero rejected frames and zero queue
saturation failures. Actual replica TCP reads and writes balanced after draining.

Environment: Apple M4 Pro, 12 logical/physical CPU cores, 24 GiB memory,
macOS Darwin 25.6.0, arm64; optimized Rust release build; Δ=250 ms; no inserted
packet delays. Four finite batch waves contain two distinct 32-byte transactions
per honest producer. There is no warmup or saturation load sweep.

| Metric | Honest rounds 1–4 | Silent first leader, anchors 2–4 |
| --- | --- | --- |
| Distinct materialized transactions at every correct replica | 32 | 24 |
| All-correct completion from first batch submission, median of 3 | 112.159 ms | 1,772.147 ms |
| Completion range across repeats | 103.152–121.827 ms | 1,770.440–1,773.988 ms |
| Per-transaction materialization latency, median within each run | 32.592–35.003 ms | 1,730.871–1,756.871 ms |
| Per-transaction p95 within each run | 37.908–49.979 ms | 1,769.115–1,773.294 ms |
| Replica TCP bytes, median total across all senders | 890,805 | 4,488,569 |
| Replica TCP byte range | 704,997–953,847 | 4,475,297–4,564,883 |
| Protocol bytes charged to workload indices through 4 | 201,327 | 127,800 |
| Protocol bytes charged beyond workload index 4 | 130,638–201,288 | 1,224,245–1,249,679 |

Headline latency uses the controller's monotonic clock, from starting its TCP
batch-submission request to receiving post-handler completion telemetry for every
correct replica. It includes reporting coordination, real cryptographic work,
materialization and telemetry delivery. Raw results also report submission-to-
ordered-release, producer-acceptance-to-materialization, input-readiness-to-proposal,
proposal-to-direct-commit, proposal-to-ordered-release and release-to-materialization.
Server-stage endpoints use same-host realtime microseconds with a monotonic drift
check; internal state-machine maps retain handler-entry milliseconds and are not
misreported as completion times. Per-transaction samples across replicas are
correlated descriptive observations, not independent confidence estimates.

Replica TCP totals count successful application writes once, including length
framing, signed envelopes and signed ACKs. Corresponding reads are a reconciliation
check and are not added again. They include sends to the silent process and all
protocol traffic before the observation cutoff, including uncapped admission and
later-round traffic. They exclude TCP/IP/link headers and kernel retransmissions.
Client/control TCP request and response bytes are recorded separately. Descriptor,
witness, payload, internal metadata and authentication counters remain separate;
availability evidence carried in PROPOSE is not charged twice.

The longer failed-round interval generates substantial beyond-workload PROG and
other control traffic. These costs are retained, not removed by capping admission.
After all correct replicas materialize all submitted transactions, the controller
quiesces protocol dispatch concurrently, drains pre-cutoff transport and waits for
stable counters before snapshots and shutdown. This declares the finite measurement
window; it is not a new consensus stopping rule.

Final archive:
[network manifest](results/local/network-bdabce767ae84103b0986bf1ee048ce8/manifest.json).
It contains exact source/spec snapshots, dependency lockfile, release binary hash,
build/test output, hardware metadata, per-run configurations and fixture keys,
raw process and controller-observed events, signed proposals, client command/reply
records, per-replica snapshots, transaction/stage measurements, read/write counters
and process exit statuses. Results are local and ignored; shared artifact storage
has not been established.

```sh
cargo test --offline --locked
cargo test --offline --locked -- --ignored --test-threads=1
python3 -m unittest discover -s tests -p '*network*.py'
python3 scripts/run_network.py --repeats 3 --bound-ms 250 --timeout 20
```

The second test command and measured runner require permission to bind local TCP
sockets. Each replica can also be launched individually with
`delugi-replica --config FILE --id ID`; the runner records its exact configuration.

## Scope and remaining work

These are measured finite localhost integration experiments, not virtual-time
results, sustained-throughput measurements, WAN results or an application execution
benchmark. The TCP workload command specifies batch count/size and the producer
generates the deterministic transaction payloads; it is not yet a general client API
that uploads arbitrary transaction bytes. Before each once-only observation event,
the harness waits until all correct nodes hold the current batch wave. It then
proceeds without waiting for consensus. This external reporting coordination is
included in end-to-end latency and does not add a producer receipt gate.

Common named bases remain explicitly assigned immutable public-genesis fixtures.
Producer branches are nonforking, with an optional wholly protocol-silent member.
The silent process still authenticates TCP frames and sends transport ACKs, but
never starts its ordering handlers, produces batches, reports observations or
executes transactions. Thus this is a silent-protocol fault, not a dead-host test.

At this historical snapshot, common-base coordination, readiness and concurrent
frontier compatibility were open adapter obligations. The old materializer
rejected incompatible frontiers. The current Option A implementation supersedes
that behavior and emits both exact branches in common order.
All custody, sequence and execution state remains in memory. Reconnection works,
but durable recovery after process restart is not implemented. Remaining systems
work includes arbitrary client submissions/open-loop load, storage/recovery,
transport optimization, multi-host deployment and matched counterpart comparisons.

## Earlier reference results

The deterministic composed snapshot
`results/local/composed-f7e13947e89c4ad9b146292321d63350` passed 114 tests and 18
reproduced traces. It additionally covers delayed payloads, retrieval without pi,
seven replicas, recurring silent rounds, historical bases, corrupted DATA and
multi-frame retrieval of 1,024 transactions. Its virtual-time measurements are
separate from the real-network results above.

The earlier ordering-only archive is
`results/local/ordering-d7c6a46213aa4348b7f53a4bc36f017f` (72 tests and 16 traces
at that snapshot). Initial bounded ordering runs remain in `results/local/initial-*`.
