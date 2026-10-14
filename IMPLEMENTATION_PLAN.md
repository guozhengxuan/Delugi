# Delugi implementation and evaluation plan

Protocol and implementation context: Option A, 2026-10-13. Objective: reduce dissemination cost while keeping ordering efficient and robust.
This plan preserves the two contributions: ordinary-signature cumulative availability and efficient, robust ordering.
The default implementation now combines PROG-only pacing with immediate
per-peer ordering bundling. Origin PROG(`k`) waits after entry for a full valid
proposal at `k-1` or `k`, with a finite Δ deadline; PROG(1), `f+1` amplification,
and enabled PROPOSE/VOTE/CER/HISTORY3/CLOSED messages remain immediate. Bundling
combines available messages without waiting to fill a frame. Canonical scheduling
and the full outgoing barrier remain explicit comparison modes.

Before this default change, the same-binary, tracing-disabled comparison at
4,000 offered tx/s, δ=10 ms and Δ=100 ms measured 71.296 ms transaction latency
and 4,000.019 completions/s with PROG pacing plus bundling. Its pending count
stayed at zero, while canonical scheduling's pending count grew from 400 to
4,401 and measured mean latency was 584.404 ms. These are one 60-second window
per mode on a local host, not a WAN capacity result. A stride-128 canonical
control stayed near 77 ms, showing scheduling sensitivity; traced diagnostics
separately measured 32.96 ms PROPOSE-to-direct-commit latency with PROG pacing.
See [PROGRESS](PROGRESS.md#ordering-pacing-experiments-and-measured-backlog-removal)
for cohorts, binary identities and historical validation.

The paper sources remain pinned to 13 October. Default PROG pacing changes their
PROG-origin rule; incorporate this scheduling amendment and its latency conditions
into the ordering specification before making formal claims. The prior
[settlement report](benchmarks/SETTLEMENT_PROFILING.md) retains the canonical
implementation's local-validation and retained-history optimizations, its 200
Rust/eight Python test validation, and its earlier sustained measurements.

The earlier [transport fix](benchmarks/TRANSPORT_PIPELINE.md) already pipelines
frames independently of outstanding ACKs, with bounded retry storage and
authenticated replay. Its accepted-socket correction removes macOS busy polling.
The current native investigation uses a userspace delay proxy; the earlier
kernel-shaped matrix remains a separate archived experiment. Larger load
sweeps, distributed hosts and faulted performance experiments remain required.
The 13 October timing-controlled delta=10 ms / Delta=100 ms comparison passed all 18 trials.
Vantage and its Autobahn/Simple-IT variants build and pass local tests. The next
architecture step is a shared external cloud harness followed by a Delugi adapter
in a pinned Vantage fork, retaining the current reference core and native
Raptr/Mysticeti baselines. Preserve protocol evidence and native Mysticeti blocks;
validate adapters by differential traces before formal comparisons. See
`benchmarks/TIMING_COMPARISON.md` and `benchmarks/ARCHITECTURE_COMPARISON.md`.
No applicable `AGENTS.md` was found in the inspected repository and ancestor directories.

## 1. Sources and implementation status

The canonical specifications are in `/Users/zhengxuanguo/gitrepo/delugi-paper`.
References below use **O** for `protocol/ordering.tex` and **D** for `protocol/dissemination.tex`; the module-map line ranges below refer to the historical 12 October snapshot; current authoritative sources are pinned separately.
The protocol README establishes their authority over archives and dated research notes.

| Material | Status | Interpretation |
| --- | --- | --- |
| `protocol/ordering.tex` | Current paper specification; default scheduling amendment pending | HISTORY3, projected signed headers, proactive VOTE attachments, short CER, PROG/CLOSED, fixed timers, coherent scanner. Its PROG-origin rule remains available as canonical mode. |
| `protocol/dissemination.tex` | Current specification, untracked working-tree file at audit | Signed sequential batches, chunked MMR, current/historical availability evidence, retrieval, indefinite custody. |
| `protocol/README.md` | Current authority guide, modified working tree | Separates the two specifications and explicitly preserves adapter/composition obligations. |
| `research/claims.md` | Historical context | The 13 October standalone specifications and architecture catch-up supersede older SAFE-2 descriptions. |
| September Python checkers and saved JSON outputs | Historical finite checks | Useful candidate invariants and test fixtures after inspection; not the current protocol runtime or verification. |
| `research/notes/check_quadratic_core.py` | Algebraic accounting checker | Its scope excludes cryptography, networking and ordering execution; it is not an implementation. |
| `DELUGI_EVALUATION_CONTEXT.txt` | Current implementation brief | Requires real replicas, clients, measured throughput/latency, reproducible comparisons, and honest accounting. |
| Rust crate in this workspace | Current integrated implementation | Full proposal/history verification, slot guards, progress/timers, scanner, dissemination and materialization; PROG pacing is the default schedule, with immediate ordering bundling in real replica processes. |
| Generic ordering state machine | Implemented with explicit schedule selection | HISTORY3, PROG/CLOSED, main/catch-up timers, scanner and ordered descriptors; default PROG pacing, canonical comparison and full-barrier comparison. Empirical checks are not a proof. |
| Dissemination and composed semantic traces | Implemented | Signed batches, indexed MMRs, current/historical WA, custody/retrieval, immutable adapter configuration and deterministic materialization. |
| Independent processes and TCP | Bounded pipelined transport implemented | Independent ACK reads, FIFO replay of unacknowledged frames, frame/byte windows, authentication, exact-once acceptance for immutable retries, monotonic timers and measured local traffic; no durable restart. |
| Official counterpart builds and comparable measurements | Matched sustained runner implemented | Four processes, 512-byte serialized transactions, 100 ms ingress cadence, actual unique completions and TCP writes; see `benchmarks/MATCHED_COMPARISON.md`. |
| Raptr v2 artifact | Native node and Forge built and instrumented | Pinned `a4c98047cf8aeae3571168d02fb7e343140d2948`, explicit build/launch and measurement patch; native consensus and Quorum Store preserved. |
| Mysticeti v6 artifact | Native validators built and instrumented | Pinned `96fd83154bb5e168def9a81ee8f3e90e94e46a2e`, explicit measurement patch; 55 native tests passed, one upstream test ignored. |

Paper HEAD at audit: `b5f3e5f623cf2ed1fb9b9954bdeae7ac36a86b82`.
HEAD alone does not identify the current sources: record working-tree SHA-256 hashes and status for every run.
The current source hashes are in `provenance/spec-2026-10-13.json`; the 12 October snapshot remains historical. Each archived run records toolchain and dependencies.
Do not import HREADY, progress tickets, full-history relays, ChainTS, or archived fallback code into the implementation.
Counterpart starting points: [Raptr artifact](https://github.com/aptos-labs/aptos-core/tree/raptr-public) and
[Mysticeti artifact](https://github.com/asonnino/mysticeti/tree/paper). The initial proxy failure is resolved;
exact source pins, build adaptations and small native benchmark results are documented in `benchmarks/`.
Nearby Gnosis Rust transport/crypto/harness code is a possible reuse source, pending audit; it is not a Delugi or counterpart baseline.

## 2. Formal modules and code boundaries

The following are module responsibilities, not a claim that each module already exists.

| Module | API or responsibility | Canonical source |
| --- | --- | --- |
| Wire and cryptography | Bounded canonical parsing; instance/config/type domains; ordinary signatures; digest unsigned header fields. | O:153–158, 304–314, 389–420; D:128–135 |
| Proposal verifier | Verify leader, hashes, complete history, exact fixed projection, and immutable local `Q(r,x,pi)`. | O:173–183, 258–290, 389–395 |
| Per-slot state/evidence | One VOTE; immutable CER/NO-CER; retained actual trigger signatures; atomic state and send effects. | O:185–201, 316–348, 413–420 |
| Progress and timers | Predecessor-closed admission, once-only PROG, exact CLOSED obligations, independent 7Δ/3Δ timers; default PROG pacing is an implementation scheduling amendment. | O:327–362, 424–434; amendment described in README |
| HISTORY3 | Exact horizon, greatest three own CERs, positive proofs, fixed bridges and bounded projection. | O:238–290, 351–356, 373–395 |
| Scanner/output | Coherent descending snapshot; first eligible authority; stop at unknown; release contiguous prefix exactly once. | O:440–469 |
| External adapter | Bounded opaque values; immutable base authentication; common reporting event; readiness before admission. | O:173–183; D:137–185, 971–991 |
| Batch store | Authenticate signed records and payload hashes; buffer gaps; store forks by producer/height/exact digest. | D:203–221, 543–578 |
| Chunked MMR | Canonical peaks, interval-node index, exact cover proofs, boundary completion, membership/base-tip openings. | D:223–357 |
| Observations and WA | One full signed vector/opportunity, n−f pool, f+1 witnesses/coordinate, at least n−f current coordinates. | D:361–491, 579–592 |
| Historical sources | Original signed bindings, complete source vectors, authenticated old bases, explicit bridge proofs. | D:406–430, 461–479, 523–527 |
| Custody/retrieval | Register obligations; retain indefinitely; serve exact suffixes; authenticate boundary and reconstruct checkpoint. | D:187–198, 597–615, 943–963 |
| Simulation/instrumentation | Deterministic event order, injectable faults, physical serialized bytes and original charged indices. | O:222–229; D:794–900 |

Keep parsing/verification separate from mutation. An accepted projected history entry is not a signature set.
VOTE carries the signed header and value, not history or the availability witness; CER remains short.
An honest availability constructor must hold every selected source's entire exact suffix and proof-producing state.
Current MMR peaks or an OBS base-to-source proof do not necessarily produce a later target-to-source proof (D:351–357).
Q must return using supplied immutable metadata; missing sources are rejection, not an instruction to fetch.
Payload FETCH/DATA runs outside ordering decision and scanner handlers.

## 3. Option A composition contract — 13 October 2026

The authoritative Option A revision resolves the earlier concurrent-frontier
compatibility issue. Different branches of a faulty producer may both be ordered.
Q remains immutable: VerifyBase and VerifyAvailability use supplied authenticated
metadata, independently of local execution, previous votes or the prior proposal.

- Genesis is always eligible. An earlier base b<r carries its signed ordering
  header, matching descriptor and n−f matching short CER signatures. Its target
  vector equals the named base. Verification requires no earlier history or WA.
- A leader selects the greatest locally held eligible base and sends one signed
  REPORT on entry. Correct replicas answer its first valid request once, including
  before their own round admission. The leader freezes n−f distinct valid OBS.
- BuildWA evaluates every coordinate, choosing its highest feasible advancing
  target while holding the exact source suffixes and proof state. Otherwise an
  empty suffix uses f+1 current OBS base proofs. The reference source table is empty.
- FIFO materialization emits exact identities once in round/producer/height order.
  Cumulative heights use max; unseen identities at older heights still appear.
  Logical output excludes signature encodings. Application validation is separate.
- Earlier certified bases cannot be skipped and precede their references. This
  connects authenticated prefixes to deterministic batch output without serializing
  concurrent proposal construction.

Tests must accept and emit both individually Q-valid Byzantine forks, preserve
shared-prefix deduplication, reject malformed certificates and relabeled witnesses,
exercise metadata-only empty fallback and keep immutable Q independent of caches.
The paper's 2δ input preparation theorem assumes immediate finite handlers after
GST; its 3δ aligned / 5δ unaligned ordering bounds end at direct commitment and
refer to canonical scheduling. The default PROG-pacing amendment requires its own
latency conditions. Materialization uses persistent custody and fair service for
eventual output.

## 4. Staged implementation and acceptance gates

### Stage 0: bounded ordering slice — completed and archived

Implement a scoped signed genesis proposal wire profile, its local verifier, and per-slot VOTE/CER/direct-decision guards.
Use real Ed25519 signatures and hashing in a virtual-time, deterministic message scheduler.
Exercise round 1 with signed PROG admission (including later PROGs), immediate self-delivery, and its initial 7Δ main timer.
This historical increment omitted nonempty HISTORY3, CLOSED-dependent main timers, catch-up, backward resolution and ordered delivery; Stage 1 now implements them.
Unsupported histories/rounds must not be accepted as empty history by convenience.
Save the exact seed/schedule, configuration, events, source/dependency provenance, and serialized byte counts.

### Stage 1: generic ordering — implemented, regression and schedule coverage continue

Implement full HISTORY3 construction and verification, all PROG/CLOSED obligations, 7Δ/3Δ timers, and retained old-round handlers.
Implement the coherent scanner and atomic contiguous delivery cursor; preserve once-only sends and exact horizons.
Test round 4 explicitly: it requires nonempty-horizon HISTORY3 through round 1 and cannot use the genesis shortcut.
Test a silent leader followed by three honest direct anchors; older rounds must eventually resolve and release consistently.
Also cover conflicting proposals, unsupported positives, raised pivots and both bridges, CER before header/value, and matching late VOTE.
Test CER-versus-NO-CER ties, no reopening, projected entries excluded from evidence stores, and duplicate/reordered delivery.
Test nearer unknown authorities, cross-horizon agreement, exact reports after coalesced catch-up, and delayed pre-GST packets.
Require report horizons h≥1; preserve main-timer arming even after a terminal outcome and independent catch-up deadlines per exact h.
Every honest proposal's fate is recorded. Finite passes support correspondence; they do not prove the protocol.

### Stage 2: independent dissemination and real proof work — implemented

Implement signed batches, indexed chunked MMR, base-tip membership, OBS, current/historical WA, and the strict constructor.
Implement exact-suffix custody/retrieval and mutation tests before measuring proof CPU and attestation amortization.
Run the small heights-3/5/8 experiment below and historical oldBase→currentBase→target→source tests.
Test source unavailability separately from payload absence at validators; include zero-output/failed opportunities in costs.
Measure supplemental historical source material X_r, proof acquisition, retained nodes, request/response traffic, and retries.

### Stage 3: Option A composition and independent processes

Implement self-contained base authentication, automatic signed reporting and the
all-current constructor. Preserve admission quorum guards and fixed timers;
PROG pacing uses complete proposal readiness with a finite release deadline,
and never waits for payload retrieval. Exercise Byzantine forks, raw height regressions,
shared-prefix deduplication, malformed application payloads and authenticated
non-genesis bases. Preserve historical-source verification as an optional path.

The local TCP acceptance workload prepares four finite waves before starting
ordering, then uses protocol REPORT/OBS to cover round 4 and silent leader 1 followed
by anchors 2/3/4. Check every distinct logical batch and transaction at every honest
replica, agreement, completion, signed reporting and all-current evidence. Archive
real latency and successful socket byte counters with exact source/spec provenance.

### Stage 4: counterpart baselines and measured evaluation

Prioritize actual official Raptr and Mysticeti artifacts where available; pin code revision, paper version, and implemented variant.
If a runnable official artifact is unavailable, state that fact; label any reimplementation and validate it before comparison.
Reuse mature support components only after checking semantics and dependency/build suitability; do not inherit another consensus core.
Run matched hardware/network/crypto/load/batch configurations and each protocol's documented native settings.
Use repeated load sweeps and the three regimes: missing follower payloads, Byzantine nonleaders, and Byzantine leaders affecting successors.
Measure useful distinct executed output, direct decisions, ordered-release gaps, every honest proposal's inclusion, and failed/no-op costs.
Separate internal control, x copies, pi copies, payload, retrieval, history repair, and all reporting opportunities by charged index.
Report uncertainty, saturation, leader ingress/egress, CPU, signatures/hashes/proofs, queues, memory, and retained history.
Do not present virtual time as performance, infer transaction starvation from proposal exclusion, or claim universal superiority.

## 5. Smallest first experiment and exact criteria

The original first run was a correctness trace of the initial ordering slice, not a throughput or wall-clock latency benchmark. Its archived snapshots preserve that scope. Current runs include full ordering and descriptor delivery.
Use n=4, f=1, a valid bounded generic Q input, round 1, real cryptography, δ=10 and Δ=100 in virtual-time units.
Self-delivery is immediate; every cross-replica message in the favorable schedule takes exactly δ.
All replicas begin admitted through round 1 at t=0, emit signed PROG(1), and the leader broadcasts its complete proposal at t=0.
The proposal is already ready: this trace does not measure batch production, reporting, or availability readiness.

| Virtual time | Required event |
| --- | --- |
| 0 | Admission through 1; PROG(1) multicast; complete signed round-1 proposal broadcast. |
| 10 | n−f distinct PROG(1) received; admission through 2; PROG(2); validated proposal enables VOTE(1). |
| 20 | n−f distinct PROG(2) received; admission through 3; matching VOTE threshold enables CER(1). |
| 30 | n−f matching CERs directly decide the same round-1 digest at all correct replicas. |

Pass: exactly one own VOTE and CER per participating honest replica, valid distinct-signature thresholds, no conflicting decision,
no VOTE before admission 2, no CER before admission 3, and direct decisions at the scheduled time with retained trigger evidence.
Emit no ordered-release or execution event: the scanner and application are not implemented in this increment.
Count serialized sends per sender, recipient, message class and original round; separate external x and pi bytes.
Reject changed header/value/witness/domain/signature bytes and duplicate-signature quorum inflation.
Replay must produce identical semantic events and byte counts for the same seed and configuration.
Failure includes accepting malformed input, premature transitions, duplicate honest sends, divergent direct decisions,
or claiming ordered output from this incomplete slice. Passing is evidence for this trace only.

Implemented checks repeat δ=20 with the same Δ=100 (VOTE 20, CER 40, decision 60), then silence one nonleader.
All three possible silent nonleaders are covered by tests; archived repeated scenarios use replica 3.
With three honest participants and timely communication, their n−f thresholds complete at the stated ticks.
Continue to require output absence in this bounded slice. Ordered delivery becomes a separate Stage-1 acceptance gate.

The smallest dissemination trace uses n=4, f=1, K=4 and an honest stream with frozen-pool report heights 3, 5 and 8.
When the leader holds the exact suffix through 8 and indexed nodes, the highest current target is 5, supported by sources 5 and 8.
With leader holdings only through 3, no advance has enough usable sources and BuildWA selects the current base equality immediately.
Construction is once per frozen pool; later payload arrival does not revise that proposal.
A later opportunity with the complete source state can select height 5.
Exercise same-chunk 1→3, boundary 4→9, crossing 3→9, exact equality, and invalid equal-height conflicting checkpoints.
Mutations of proof order/roots, base-tip opening, source base, predecessor chain, and witness identity must fail.
A metadata-only validator must accept the complete genuine witness without FETCH, then retrieve and reconstruct missing selected bytes.
Success requires exact target selection, one OBS/opportunity, faithful source-holding gates, and identical authenticated suffix bytes.
Combine these evidence checks with exact-identity output tests across Byzantine forks and authenticated bases.

## Current ordering acceptance gate

`src/replica.rs` implements all generic ordering handlers over the wire verifier,
HISTORY3 and scanner modules. `tests/ordering_scenarios.rs` exercises round 4
using real signed history, then a silent first leader followed by honest anchors
2/3/4. The recorded canonical reference schedule exposes input/history waiting:
proposal 4 at tick 730 and
ordered release at 760 for δ=10, Δ=100. Repeated silent round 5 resolves through
anchors 6/7/8 at tick 1470 in the recorded schedule. Unit tests cover timer
expiry before admission, independent larger-horizon deadlines, every exact
report after a prefix sweep, metadata waiting and signature-evidence separation.

The default PROG-pacing schedule must pass these round-4 and silent-leader
acceptance cases through both semantic traces and independent replica processes.
Explicit canonical and full-barrier modes remain available for comparison, and
archives must record the resolved schedule, release deadline and bundling mode.

The dissemination and composed runtime now follow the Option A contract above.
Source holding applies to advancing targets; empty fallback provides current
availability without source payloads. Exact-batch output replaces the former
cross-frontier compatibility rejection. Regressions and archived semantic/TCP
runs are recorded in PROGRESS.md. The independent-process profile retains state
in memory. Sustained generation and the initial matched 1,000/4,000 tx/s comparison
are implemented; broader load sweeps, multi-host deployment, durable state and
faulted performance experiments remain the next evaluation stages.
