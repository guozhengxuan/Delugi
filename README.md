# Delugi implementation and experiments

The objective is to reduce dissemination cost while keeping ordering efficient
and robust. This repository implements ordering and dissemination, including a
transaction path from signed batches through availability proofs, ordered
descriptors, payload retrieval and materialization. Deterministic traces exercise
protocol semantics; independent replica processes exercise the same state
machines over real TCP and measure local end-to-end latency and traffic.

## Implemented ordering

- `src/wire.rs`: canonical, bounded Ed25519/SHA-256 messages; instance,
  configuration, role, leader and value/history bindings. The full ordering v2
  profile carries explicit history and its exact signed projection.
- `src/history.rs`: nonrecursive CER proofs, usable HISTORY3 reports, compact
  histories, greatest known pivots, predecessor bridges and negative assertions.
- `src/slot.rs`: once-only full-validation VOTEs, CER amplification, immutable
  terminal outcomes and independent direct commitments.
- `src/replica.rs`: complete generic ordering handlers, predecessor-closed PROG
  admission, exact reports followed by CLOSED, independent 7Δ/3Δ timers, retained
  old-round work, atomic in-memory effects and immediate local self-delivery.
- `src/scanner.rs`: coherent descending classification, nearest-authority barriers,
  fixed signed entries and contiguous once-only descriptor delivery.
- `src/simulation.rs`: real signed/serialized packets, virtual time, silent replicas,
  delayed/duplicated packets and accounting by original protocol index.
- `scripts/run_ordering.py`: repeated scenarios with exact source/spec snapshots,
  lockfile, raw signed traces, build/test output and content-hash provenance.

The implementation retains evidence and once-only state in memory for the full
process lifetime. Crash recovery and persistent disk storage are not implemented.
The state machine drains enabled positive transitions before timeout negatives;
report effects enter the outbox before their CLOSED effects. Resolution never
requests metadata and cannot delay an enabled logical send.

## Integrated dissemination

- `src/mmr.rs`: indexed chunked MMRs, exact prefix proofs, explicit crossing-chunk
  completion, and authenticated base-tip membership openings.
- `src/batch.rs`: signed sequential batches, out-of-order buffering, exact fork
  storage, indefinite custody, and atomic suffix reconstruction. Batches are
  bounded at 256 KiB; cumulative retrieval uses independently verified DATA parts
  within the 1 MiB wire limit, including reordered parts.
- `src/availability.rs`: one complete signed observation per opportunity, exact
  n−f current pools, f+1 distinct witnesses per coordinate, at least n−f current
  coordinates, and current/historical verification. Honest construction requires
  the entire exact source suffix and indexed proof state; it prefers the highest
  feasible current target before historical fallback.
- `src/composed.rs`: immutable captured Q configuration, once-only reporting,
  frozen pools, retries on source arrival, retained original historical sources,
  asynchronous ordering input, exact FETCH/DATA service, and ordered materialization.
- `src/end_to_end.rs` and `tests/end_to_end_scenarios.rs`: real signed/serialized
  transaction-path traces through round 4, silence and recovery, missing payloads,
  descriptor-only recipients, duplicates, and seven replicas.
- `scripts/run_end_to_end.py`: source/spec snapshots and repeated signed traces.

The named-base registry is an explicit trusted adapter input. It matches supplied
immutable opportunity/base/authentication tuples and never checks a changing local
frontier inside Q. Independent tests cover authorized non-genesis bases and
historical source reuse. End-to-end scenarios assign public genesis separately to
concurrently prepared opportunities and use nonforking producers, with an optional
completely silent replica. This is a fixture premise, not a frozen-epoch repair or
an implementation of the missing common-base coordination service.

Ordering starts at tick zero; batches are produced without receipt gates, reports
snapshot after dissemination, and input arrives asynchronously. Readiness is logged
separately and never resets ordering timers. These runs therefore do not assume or
establish the theorem's ready-input-at-entry premise.

Materialization waits for the oldest ordered descriptor's authenticated bytes,
preflights every coordinate's compatibility, then expands by ordering round,
producer index, batch height, and transaction position. Exact batches are emitted
once; the workload defines duplicate transaction IDs as deterministic no-ops and
hashes each newly executed ID/payload into a state digest. This measures payload
integrity and deterministic materialization, not application smart-contract work.
A conflicting committed frontier produces an explicit composition error before
partial execution. An executable SAFE-2 regression shows that two incompatible
frontiers can each satisfy availability Q; this research obligation is still open.

## Run

Use Rust/Cargo and Python 3 from this directory:

```sh
cargo test --offline --locked
cargo run --offline --locked --bin ordering-trace -- --rounds 4 --until 70
cargo run --offline --locked --bin ordering-trace -- --silent 0 --rounds 4 --until 800
cargo run --offline --locked --bin ordering-trace -- --silent 0 --rounds 8 --until 1500
python3 scripts/run_ordering.py
cargo run --offline --locked --bin end-to-end-trace -- --until 300
cargo run --offline --locked --bin end-to-end-trace -- --silent 0 --until 900
cargo run --offline --locked --bin end-to-end-trace -- --delay-payload --data-delay 120 --descriptor-only --until 700
python3 scripts/run_end_to_end.py
python3 scripts/run_network.py
python3 scripts/run_network.py --scenario silent --repeats 3 --bound-ms 250
```

A fresh machine must first fetch the locked dependencies with
`cargo fetch --locked`. The initial development toolchain is Rust 1.94.0-nightly
(`31010ca61`, 2025-12-16); each run records its actual compiler and dependency lockfile.
`run_initial.py` forwards to the current suite. Archived initial-run snapshots
preserve the earlier genesis-only implementation and its original runner.

The generic ordering simulator supports 4 or 7 replicas, configurable positive δ < Δ, one optional
silent member, a finite input workload, and an observation deadline. Workload and
observation limits do not cap protocol admission or suppress old-round work.
Inputs are pre-ready for all honest leaders within the workload; no input is
supplied after that endpoint. The fixture Q recognizes immutable round-tagged
values and witnesses. It does not implement availability.

Membership IDs are zero-based; round 1 is led by ID 0. Deterministic simulator
fixture private keys are publicly derivable and strictly for tests. The wire configuration rejects
committees whose mandatory metadata cannot fit the 1 MiB frame, and reserves the
worst-case history overhead before accepting bounded external values/witnesses.

## Acceptance scenarios

With n=4, δ=10 and Δ=100, the all-honest run proposes rounds 1–4 at ticks
0/10/20/30 and directly commits at 30/40/50/60. Round 4 contains actual signed
HISTORY3(1) evidence and a CER proof, not an empty-history shortcut.

With replica 0 silent, rounds 2 and 3 directly commit but ordered delivery waits
at round 1. Its main timer expires at tick 720; exact reports permit proposal 4
at 730. The three honest anchors resolve round 1 as to-skip and deliver rounds
2/3/4 at tick 760. A second silent round 5 is resolved by anchors 6/7/8.
These timings describe these precise virtual schedules, not a uniform recovery bound.
The CLI reports an incomplete run if the workload ends on an unresolved silent
round; include later honest anchors to resolve that trailing gap.

Additional tests check malformed/fake-high histories, raised pivots and bridges,
CER before proposal, late matching VOTEs, absent or bad VOTE attachments, exact
catch-up deadlines and report obligations, distinct signer thresholds, metadata
waiting, duplicates, 7-member quorums and deterministic replay.

For the composed δ=10, Δ=100 workload, batch waves begin at ticks 0/30/60/90,
inputs and proposals are ready at 30/60/90/120, and honest round-4 materialization
finishes at 150. With replica 0 silent, three honest anchors release rounds 2–4
at tick 760, including the height-one batches covered cumulatively by round 2.
These endpoints include reporting and proof preparation, unlike the pre-ready
ordering-only trace above. Exact per-replica events are archived by the runner.

## Independent replicas over TCP

`scripts/run_network.py` builds the release executable and launches four
`delugi-replica` processes with separate state, listening ports and freshly
generated Ed25519 keys. It runs the honest round-4 case and the silent first
leader followed by anchors 2/3/4, three times each by default. There are no
simulated packet delays. Each process invokes the same ordering and composed
state machines with monotonic elapsed milliseconds; cryptography, serialization,
proof construction, queues and socket I/O consume real time. Membership and the
instance are fixed by the per-run configuration. Keys are mode-0600 experiment
fixtures, retained with the local archive.

The transport signs each bounded frame, binding its instance, sender, recipient,
sequence, layer and payload hash. It signs acknowledgments after authenticated
mailbox acceptance. One writer per peer sends FIFO, waits for the signed
acknowledgment, and retries the exact frame after a failed connection or missing
acknowledgment. Receiver sequence state suppresses duplicate delivery across
reconnections. This stop-and-wait design and its extra signatures are included
in measured costs; it is an initial reliable transport, not a throughput-optimized
network stack. Bounded output saturation fails the run explicitly. Sequence
state and custody are in memory; reconnecting is supported, process restart
recovery is not.

A separate loopback TCP control client submits four finite batch waves, with two
unique transactions per honest producer per wave. Before each once-only report,
the experiment waits until every honest node holds that wave. It then submits
the next wave without waiting for consensus commitment or ordered output.
This is a coordinated test workload and external reporting event, not a new
producer receipt gate or consensus rule. The wait is included in end-to-end
latency. Reports still bind the supplied immutable common genesis bases, and
ordering inputs arrive asynchronously. With the silent configuration, the
fourth process remains available for authenticated transport and acknowledgments
but performs no protocol handling, batch production or reporting.

The runner checks every submitted transaction at every honest replica, exact
transaction order and final state hash, matching ordered descriptors, direct
commitment of all honest anchors, and `Skip` for silent round 1. After all honest
outputs complete, it declares the observation endpoint and quiesces protocol
dispatch, then drains already-enqueued transport work before final counters and
shutdown. Admission remains uncapped during the observation interval; traffic
from rounds beyond the four-round workload is included. Quiescing is a finite
experiment boundary, not a protocol stopping rule.

Post-handler event timestamps measure completed work. Internal state-machine
maps retain handler-entry times and are diagnostic, not completion latency.
The headline completion metric uses the controller's monotonic clock from TCP
submission start to receipt of each post-handler completion event; it includes
stdout telemetry delivery. Separate stage and transaction endpoints use the
same host clock, checked against monotonic time. Submission-to-ordered-release,
submission-to-materialization and complete-proposal-to-direct-commit are reported
separately. Finite workload
completion rate is not sustainable transaction throughput, and loopback results
do not establish WAN performance or the abstract three-delay bound.

Traffic distinguishes logical protocol payloads, descriptor/witness copies,
batch payloads, signed transport envelopes and acknowledgments, retry writes,
and client control bytes. Successful socket-write and read counters include
framing and authentication; they exclude TCP/IP/link headers and kernel
retransmissions. Payload witnesses inside PROPOSE are charged once, not again
as a separate availability broadcast. Raw process output, client commands,
snapshots, source/specification hashes, release binary hash and measurements are
saved under a unique `results/local/network-*` directory. Failed runs are retained.
Timing and signature traces may differ between real executions; agreement and
completion must hold in every repeat.

## Measurement boundaries and provenance

The ordering and composed simulators produce semantic traces with real
cryptographic work and zero modeled local processing time. They are not
real-network performance, transaction throughput, substantive application
execution, formal verification, or proof that full Delugi composes.
The ordering-only runner delivers generic descriptors; the composed runner adds
a finite transaction workload and deterministic payload materialization. The
separate TCP runner measures independent processes on one host; durable recovery,
load sweeps, deployment across hosts and counterpart measurements remain work.

Every nonself send is charged, including silent recipients and deliveries pending
at observation end. HISTORY3/CLOSED charge to h+3; other sends charge to their
original round. Opaque x/pi copies are separated from metadata and framing;
injected duplicates are separated from prescribed sends. Transport overhead,
CPU/queue latency is not represented in these simulators. Composed runs additionally charge BATCH,
OBS, FETCH and segmented DATA, separating payload copies from control bytes.
Availability witnesses are charged only where actually sent in PROPOSE; there is
no second virtual dissemination charge for the same evidence.

The runners create unique ignored `results/local/ordering-*` or
`results/local/composed-*` directories,
preserves unsuccessful runs and requires identical signed replays. It rejects
changed source files during archival and changed canonical specification hashes.
There is no shared artifact storage or implementation Git history yet; preserve
local result directories separately. Current paper working-tree hashes and Git
HEAD are pinned in `provenance/spec-2026-10-12.json`.

[PROGRESS.md](PROGRESS.md) links the latest verified run.
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) maps the formal modules and next
stages. Common-base authorization, input readiness for composed Delugi and
concurrent Byzantine frontier compatibility remain explicit research obligations.
No coordinate projection, mutable Q, or other implicit repair is adopted.
