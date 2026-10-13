# Delugi implementation and evaluation plan

Audit date: 2026-10-12. Objective: reduce dissemination cost while keeping ordering efficient and robust.
This plan preserves the two contributions: ordinary-signature cumulative availability and efficient, robust ordering.
The current increment runs integrated ordering, dissemination, retrieval and deterministic transaction materialization in independent replica processes over real TCP. Local finite-workload measurements are an initial systems acceptance gate; comparative and sustained-load evaluation remain required.
No applicable `AGENTS.md` was found in the inspected repository and ancestor directories.

## 1. Sources and implementation status

The canonical specifications are in `/Users/zhengxuanguo/gitrepo/delugi-paper`.
References below use **O** for `protocol/ordering.tex` and **D** for `protocol/dissemination.tex`; numbers are audited source lines.
The protocol README establishes their authority over archives and dated research notes.

| Material | Status | Interpretation |
| --- | --- | --- |
| `protocol/ordering.tex` | Current specification | HISTORY3, projected signed headers, proactive VOTE attachments, short CER, PROG/CLOSED, fixed timers, coherent scanner. |
| `protocol/dissemination.tex` | Current specification, untracked working-tree file at audit | Signed sequential batches, chunked MMR, current/historical availability evidence, retrieval, indefinite custody. |
| `protocol/README.md` | Current authority guide, modified working tree | Separates the two specifications and explicitly preserves adapter/composition obligations. |
| `research/claims.md` | Mixed current and historical ledger, modified | SAFE-2 is explicitly open at line 210; some other entries still name superseded machinery. |
| September Python checkers and saved JSON outputs | Historical finite checks | Useful candidate invariants and test fixtures after inspection; not the current protocol runtime or verification. |
| `research/notes/check_quadratic_core.py` | Algebraic accounting checker | Its scope excludes cryptography, networking and ordering execution; it is not an implementation. |
| `DELUGI_EVALUATION_CONTEXT.txt` | Current implementation brief | Requires real replicas, clients, measured throughput/latency, reproducible comparisons, and honest accounting. |
| Rust crate in this workspace | Current integrated implementation | Canonical full proposal/history verification, slot guards, progress/timers, scanner, dissemination and materialization, used by both semantic traces and real replica processes. |
| Generic ordering state machine | Implemented as a deterministic reference | HISTORY3, PROG/CLOSED, main/catch-up timers, scanner and ordered descriptors; empirical checks support correspondence, not a proof. |
| Dissemination and composed semantic traces | Implemented | Signed batches, indexed MMRs, current/historical WA, custody/retrieval, immutable adapter configuration and deterministic materialization. |
| Independent processes and TCP | Initial local acceptance implementation | Authenticated framed messages and acknowledgments, real client control, monotonic local timers, signed traces, measured local latency and traffic; no durable restart. |
| Official counterpart builds and comparable measurements | Unverified | Establish actual artifact provenance and baseline tests before comparing results. |
| Raptr v2 artifact | Located, not built/run or revision-pinned | The paper links the Aptos `raptr-public` branch. |
| Mysticeti v6 artifact | Located, not built/run | The paper pins `96fd831`; its `paper` branch README labels it an unmaintained reproducibility prototype. |

Paper HEAD at audit: `b5f3e5f623cf2ed1fb9b9954bdeae7ac36a86b82`.
HEAD alone does not identify the current sources: record working-tree SHA-256 hashes and status for every run.
The initial source hashes are in `provenance/spec-2026-10-12.json`; each archived run records toolchain and dependencies.
Do not import HREADY, progress tickets, full-history relays, ChainTS, or archived fallback code into the implementation.
Counterpart starting points: [Raptr artifact](https://github.com/aptos-labs/aptos-core/tree/raptr-public) and
[Mysticeti artifact](https://github.com/asonnino/mysticeti/tree/paper). Neither has produced a local baseline result.
The initial remote Git probe failed because the configured local proxy was unreachable; launch/version mapping remains unverified.
Nearby Gnosis Rust transport/crypto/harness code is a possible reuse source, pending audit; it is not a Delugi or counterpart baseline.

## 2. Formal modules and code boundaries

The following are module responsibilities, not a claim that each module already exists.

| Module | API or responsibility | Canonical source |
| --- | --- | --- |
| Wire and cryptography | Bounded canonical parsing; instance/config/type domains; ordinary signatures; digest unsigned header fields. | O:153–158, 304–314, 389–420; D:128–135 |
| Proposal verifier | Verify leader, hashes, complete history, exact fixed projection, and immutable local `Q(r,x,pi)`. | O:173–183, 258–290, 389–395 |
| Per-slot state/evidence | One VOTE; immutable CER/NO-CER; retained actual trigger signatures; atomic state and send effects. | O:185–201, 316–348, 413–420 |
| Progress and timers | Predecessor-closed admission, once-only PROG, exact CLOSED obligations, independent 7Δ/3Δ timers. | O:327–362, 424–434 |
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

## 3. Semantic blockers and independent engineering

These unresolved interfaces block a general composed BFT-SMR claim, not implementation of the independent modules.

| Semantic obligation | Why it matters | Work that can proceed |
| --- | --- | --- |
| Concurrent frontier compatibility, SAFE-2 | Two immutable-Q-valid frontiers can select incompatible Byzantine branches from the same base. | Generic ordering, availability, and explicitly honest-producer integration. |
| Immutable base authentication and common-base reporting | The specs require a shared authorized named base and bounded evidence, but do not instantiate a general service. | Public-genesis cases, explicit adapter types, verifier and report machinery. |
| Input readiness at honest round entry | Eventual source/proof arrival does not establish the ordering admission-time premise. | Record readiness separately; use pre-ready inputs in ordering experiments. |
| Execution and client duplication semantics | Exact batch identities and duplicate client transactions are different objects. | Define a labeled deterministic workload with unique client IDs before execution benchmarks. |

Concrete SAFE-2 regression: take n=4, f=1 and a Byzantine producer B with incompatible branches α and β after genesis.
At opportunity r, B and honest holder A sign observations supporting α at height 1; a third report completes the current pool.
At opportunity s using the same named old base, B and honest holder C support β at height 2; another report completes that pool.
The opportunities are prepared concurrently before either is ordered, and β already differs from α at height 1.
Other producer coordinates supply the required current entries. Each branch has f+1 distinct witnesses and exact valid proofs.
Both frontiers can therefore pass availability Q and both descriptors can be ordered, while β does not extend α.
The test must record the unresolved compatibility obligation; it must not silently repair the output.
No coordinate projection, discarded committed frontier, frozen epoch base, or mutable latest-frontier check inside Q is adopted.
See D:978–997 and `research/claims.md:210`.

Nonblocking engineering includes canonical codecs, real signatures, deterministic scheduling, exact guards, persistence interfaces,
MMR proofs, observation validation, indexed storage, indefinite custody, retrieval, counters, and real process transport.
Keep indefinite retention for the reference implementation. Execution alone does not release custody.
Crashes, reconfiguration, pruning, and Byzantine branch-resource caps need separately scoped semantics and measurements.

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

### Stage 3: actual processes and honest-producer integration — initial local implementation

Independently running replicas and a client use real serialization, TCP, signature verification and in-memory storage.
The local acceptance workload supplies immutable public-genesis bases and uses honest sequential producers, with an optional completely silent protocol participant; this does not choose a recurring base repair.
Inputs arrive asynchronously without changing ordering admission or resetting timers. Ready-input-at-entry remains an unresolved composition premise. Deterministic coverage separately delays one follower's selected payload while allowing complete metadata to arrive.
Require consistent descriptor ordering while that follower's execution waits, then authenticated retrieval and identical output logs.
State the adapter and fault scope for every subsequent multi-round run; keep SAFE-2 unresolved until an author-approved contract exists.
Record client admission, batch emission/holding, OBS, evidence-ready, input-ready, proposal, validation, VOTE, CER, decision,
ordered release, payload-ready, and execution completion. CPU, queues, and serialization consume real wall time here.

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
With leader holdings only through 3, this coordinate has one usable source and BuildWA must return unavailable.
After missing source bytes/state arrive, it must choose 5 without asking for another signature for the same opportunity.
This single-coordinate failure need not block a frontier if three other coordinates are current; test the global threshold separately.
Exercise same-chunk 1→3, boundary 4→9, crossing 3→9, exact equality, and invalid equal-height conflicting checkpoints.
Mutations of proof order/roots, base-tip opening, source base, predecessor chain, and witness identity must fail.
A metadata-only validator must accept the complete genuine witness without FETCH, then retrieve and reconstruct missing selected bytes.
Success requires exact target selection, one OBS/opportunity, faithful source-holding gates, and identical authenticated suffix bytes.
Keep this dissemination trace and the one-slot honest-producer integration distinct from a general Byzantine-frontier composition claim.

## Current ordering acceptance gate

`src/replica.rs` implements all generic ordering handlers over the wire verifier,
HISTORY3 and scanner modules. `tests/ordering_scenarios.rs` exercises round 4
using real signed history, then a silent first leader followed by honest anchors
2/3/4. The latter exposes input/history waiting: proposal 4 at tick 730 and
ordered release at 760 for δ=10, Δ=100. Repeated silent round 5 resolves through
anchors 6/7/8 at tick 1470 in the recorded schedule. Unit tests cover timer
expiry before admission, independent larger-horizon deadlines, every exact
report after a prefix sweep, metadata waiting and signature-evidence separation.

The dissemination modules and honest/silent-producer integration now pass their
semantic gates. `src/mmr.rs`, `src/batch.rs`, `src/availability.rs` and
`src/composed.rs` preserve exact suffixes, one report per opportunity, source
holding, immutable Q, original historical sources, retrieval without pi, and
whole-frontier compatibility checks before deterministic materialization.
The end-to-end fixture explicitly supplies per-opportunity public-genesis bases;
it does not implement a common-base protocol. Inputs arrive asynchronously and
readiness is logged rather than presumed. SAFE-2 remains an explicit failing
composition implication, with independently Q-valid incompatible-fork regression.
The independent-process TCP implementation now measures the same finite round-4
and silent-leader recovery scenarios on one host. Its client reporting barrier is
an explicit experiment input, not a consensus or producer-send rule. Measurements
include preparation and reporting wait, and distinguish protocol bytes from
transport authentication, acknowledgments and retries. A local finite workload
does not establish sustainable throughput or WAN behavior.
Next are sustained offered-load sweeps, deployment across hosts, durable state,
counterpart comparisons and broader adversarial schedules. The implementation has
no durable crash recovery; complete generic ordering is not a claim of
unrestricted full-Delugi composition.
