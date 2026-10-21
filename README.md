# Delugi implementation and experiments

The objective is to reduce dissemination cost while keeping ordering efficient
and robust. This repository implements ordering and dissemination, including a
transaction path from signed batches through availability proofs, ordered
descriptors, payload retrieval and materialization. Deterministic traces exercise
protocol semantics; independent replica processes exercise the same state
machines over real TCP and measure local end-to-end latency and traffic.
The default ordering schedule paces originating PROG messages against proposal
readiness, with a Δ release deadline, and immediately bundles already-enabled
ordering messages per peer.

The sustained-load harness runs four independent replicas with paced transaction
generation and measures unique completions, latency, queue growth and TCP traffic.
The [matched comparison](benchmarks/MATCHED_COMPARISON.md) runs Delugi and pinned
Raptr/Mysticeti paper artifacts with the same offered rates, serialized transaction
size and ingress cadence. [Baseline documentation](benchmarks/README.md) also retains
the earlier native workload measurements. The
[timing-controlled rerun](benchmarks/TIMING_COMPARISON.md) matches added one-way
delay 10 ms and bound 100 ms across all three. The
[Vantage architecture review](benchmarks/ARCHITECTURE_COMPARISON.md) records local
tests and the recommended framework for formal evaluation.

## Shared workspace

Protocol policy lives in `core/delugi`: ordering, availability, dissemination,
repair, exact batch identity, custody and output expansion. The shared crates
provide TCP queues and connections, cryptographic execution, timed ingress,
process-local storage, ordered output queues, control mailboxes, timers and
operation accounting. `core-api` declares service barriers and node factories;
`node` provides common command parsing and lifecycle dispatch. The root `delugi`
crate preserves existing imports and executable names.

`delugi-node --protocol delugi` and `delugi-replica` select the same factory.
The memory storage profile completes at Visible, with no crash-recovery claim.
Native policies may require stronger storage barriers; unsupported requests fail.
Core actor turn ordering and timer arming remain core-owned during extraction.
The shared resource profile records component limits and existing gaps; it is not
an aggregate RSS or CPU enforcement claim.

Raptr is the first counterpart being ported from the pinned authors' code under
`core/raptr`. Its executable output contract and source-preserving native import
are separate from a runnable shared-service replica. Raptr is not yet registered
in the node CLI or accepted for shared-runtime performance comparisons. Native
reference artifacts and historical results remain separate. See the
[approved architecture](benchmarks/plans/2026-10-21-shared-core-architecture.txt)
and [frozen services](benchmarks/plans/2026-10-21-shared-service-contract.txt).

## Implemented ordering

- `core/delugi/src/wire.rs`: canonical, bounded Ed25519/SHA-256 messages; instance,
  configuration, role, leader and value/history bindings. The Option A v3
  profile carries explicit history and its exact signed projection.
- `core/delugi/src/history.rs`: nonrecursive CER proofs, usable HISTORY3 reports, compact
  histories, greatest known pivots, predecessor bridges and negative assertions.
- `core/delugi/src/slot.rs`: once-only full-validation VOTEs, CER amplification, immutable
  terminal outcomes and independent direct commitments.
- `core/delugi/src/replica.rs`: complete generic ordering handlers, predecessor-closed PROG
  admission, default PROG pacing, exact reports followed by CLOSED, independent 7Δ/3Δ timers, retained
  old-round work, atomic in-memory effects and immediate local self-delivery.
- `core/delugi/src/scanner.rs`: coherent descending classification, nearest-authority barriers,
  fixed signed entries and contiguous once-only descriptor delivery.
- `core/delugi/src/simulation.rs`: real signed/serialized packets, virtual time, silent replicas,
  delayed/duplicated packets and accounting by original protocol index.
- `scripts/run_ordering.py`: repeated scenarios with exact source/spec snapshots,
  lockfile, raw signed traces, build/test output and content-hash provenance.

The implementation retains evidence and once-only state in memory for the full
process lifetime. Crash recovery and persistent disk storage are not implemented.
The state machine drains enabled positive transitions before timeout negatives;
report effects enter the outbox before their CLOSED effects. Resolution never
requests metadata and cannot delay an enabled logical send.

## Integrated dissemination

- `core/delugi/src/mmr.rs`: indexed chunked MMRs, exact prefix proofs, explicit crossing-chunk
  completion, and authenticated base-tip membership openings.
- `core/delugi/src/batch.rs`: signed sequential batches, out-of-order buffering, exact fork
  storage, indefinite custody, and atomic suffix reconstruction. Batches are
  bounded at 256 KiB; cumulative retrieval uses independently verified DATA parts
  within the 1 MiB wire limit, including reordered parts.
- `core/delugi/src/availability.rs`: authenticated earlier bases, signed REPORT/OBS bindings,
  exact n−f current pools and f+1 actual OBS signers per WA. Q checks only supplied
  immutable evidence. The reference constructor chooses each highest feasible
  current advance, otherwise an empty suffix supported by current reports.
  Historical-source verification remains available with explicit source bytes.
- `core/delugi/src/composed.rs`: automatic leader REPORT on round admission, greatest locally
  held eligible base, one response to the first valid request, frozen pools,
  immediate all-current construction, exact FETCH/DATA service and FIFO output.
- `core/delugi/src/end_to_end.rs` and `tests/end_to_end_scenarios.rs`: signed transaction-path
  traces through round 4, silent-leader recovery, missing payloads,
  descriptor-only recipients, duplicates and seven replicas.
- `scripts/run_end_to_end.py`: source/spec snapshots and repeated signed traces.

A non-genesis base contains an earlier leader's signed header, its bound
frontier descriptor and n−f distinct matching short CER signatures. Its round
must precede the current opportunity. Genesis always remains eligible. Neither
base selection nor Q waits for payload execution. Correct reporters answer a
valid REPORT even before their own admission to that round.

For every advancing target, the constructor holds the exact source suffixes and
indexed proof state. If none is feasible, it reuses f+1 current reports' supplied
base-to-source proofs for target=base; this empty suffix needs no payload.
Every coordinate is current and the reference historical source table is empty.
Availability-specific parser budgets reserve space for the complete accepted pool,
base evidence and all constructed WAs within the selected complete-message profile.

Option A allows distinct Byzantine forks in the common output. Materialization
processes ordering round, producer index and suffix height, suppressing only an
already emitted `(producer, height, unsigned-header digest)` identity. A lower
raw target can contribute an unseen fork. Cumulative heights take a maximum and
never filter output. The logical batch log contains unsigned authenticated fields
and ordered payload, excluding signature encodings. FIFO processing materializes
each earlier certified base before its reference.

The workload application treats repeated transaction IDs and malformed application
payloads as deterministic no-ops while retaining every distinct authenticated
batch in the logical output. Its state hash measures deterministic application
output; the exact batch log is checked separately. Custody and execution state
remain in memory.

## Run

Use Rust/Cargo and Python 3 from this directory:

```sh
cargo test --offline --locked
cargo run --offline --locked --bin ordering-trace -- --rounds 4 --until 70
cargo run --offline --locked --bin ordering-trace -- --silent 0 --rounds 4 --until 800
cargo run --offline --locked --bin ordering-trace -- --silent 0 --rounds 8 --until 1500
python3 scripts/run_ordering.py --spec-snapshot provenance/spec-2026-10-19.json
cargo run --offline --locked --bin end-to-end-trace -- --until 300
cargo run --offline --locked --bin end-to-end-trace -- --silent 0 --until 900
cargo run --offline --locked --bin end-to-end-trace -- --delay-payload --data-delay 120 --descriptor-only --until 700
python3 scripts/run_end_to_end.py --spec-snapshot provenance/spec-2026-10-19.json
python3 scripts/run_network.py --spec-snapshot provenance/spec-2026-10-19.json
python3 scripts/run_network.py --spec-snapshot provenance/spec-2026-10-19.json --scenario silent --repeats 3 --bound-ms 250
python3 scripts/run_sustained.py --spec-snapshot provenance/spec-2026-10-19.json --rate 1000 --ingress-batch-ms 100 --warmup 10 --duration 30
```

A fresh machine must first fetch the locked dependencies with
`cargo fetch --locked`. The initial development toolchain is Rust 1.94.0-nightly
(`31010ca61`, 2025-12-16); each run records its actual compiler and dependency lockfile.
`run_initial.py` forwards to the current suite. Archived initial-run snapshots
preserve the earlier genesis-only implementation and its original runner.

Every archiving runner requires an explicit `--spec-snapshot`; there is no automatic
latest-version selection. The October 19 snapshot pins the reviewed normative TeX
sources and keeps conformance checks separate from performance claims. To replay
an older snapshot, select its original manifest and use `--paper-repository` to
point to the matching paper tree or archived `snapshot/paper` directory. Selected
hashes are checked before and after the run, and the sources are archived verbatim.

The generic ordering simulator supports 4 or 7 replicas, configurable positive δ < Δ, one optional
silent member, a finite input workload, and an observation deadline. Workload and
observation limits do not cap protocol admission or suppress old-round work.
Inputs are pre-ready for all honest leaders within the workload; no input is
supplied after that endpoint. The fixture Q recognizes immutable round-tagged
values and witnesses. It does not implement availability.

Membership IDs are zero-based; round 1 is led by ID 0. Deterministic simulator
fixture private keys are publicly derivable and strictly for tests. The wire configuration rejects
committees whose mandatory metadata cannot fit their selected frame profile, and reserves the
worst-case history overhead before accepting bounded external values/witnesses.

## Acceptance scenarios

In the recorded canonical reference schedule with n=4, δ=10 and Δ=100,
the all-honest run proposes rounds 1–4 at ticks
0/10/20/30 and directly commits at 30/40/50/60. Round 4 contains actual signed
HISTORY3(1) evidence and a CER proof, not an empty-history shortcut.

In that reference schedule with replica 0 silent, rounds 2 and 3 directly commit
but ordered delivery waits at round 1. Its main timer expires at tick 720; exact reports permit proposal 4
at 730. The three honest anchors resolve round 1 as to-skip and deliver rounds
2/3/4 at tick 760. A second silent round 5 is resolved by anchors 6/7/8.
These timings describe these precise virtual schedules, not a uniform recovery bound.
The CLI reports an incomplete run if the workload ends on an unresolved silent
round; include later honest anchors to resolve that trailing gap.

Additional tests check malformed/fake-high histories, raised pivots and bridges,
CER before proposal, late matching VOTEs, absent or bad VOTE attachments, exact
catch-up deadlines and report obligations, distinct signer thresholds, metadata
waiting, duplicates, 7-member quorums and deterministic replay.

The composed fixture prepares its finite batch workload at tick zero and starts
ordering at 2δ. Signed REPORT/OBS exchanges then prepare inputs automatically.
Delayed-payload tests keep one receiver missing selected bytes, exercise empty
fallback and retrieve committed suffixes while ordering continues. Exact input,
proposal, commit and materialization events are archived by the runner.

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
mailbox acceptance. One writer per peer pipelines FIFO frames while an independent
reader collects signed acknowledgments. The default window holds up to 64 frames
and 8 MiB of encoded data; a full window waits for ACKs. A separate 4,096-frame
outbox and at most one staged frame bound queued memory. Reconnection replays
the exact unacknowledged suffix before new frames. Only a valid FIFO-head ACK
retires a frame; receiver sequence state suppresses duplicate delivery and rejects
gaps. The oldest written frame has a configurable 2-second ACK timeout, while
idle connections remain open. The signed framing and ACK costs remain included
in measurements. Bounded output saturation fails the run explicitly. Sequence
state and custody are in memory; reconnecting is supported, process restart
recovery is not.

The [transport pipeline report](benchmarks/TRANSPORT_PIPELINE.md) records the
14 October fix, real TCP fault regressions, accepted-socket timeout correction
on macOS, and native before/after measurements.
The subsequent [settlement profiling report](benchmarks/SETTLEMENT_PROFILING.md)
tracks repeated validation and retained-history work on the delivery path,
causal timing, and sustained reruns with the same transport and timer settings.

The default process configuration and the network, sustained, and TCP-delay
runners use **PROG-only pacing plus immediate per-peer ordering bundling**.
Originating PROG(`k`) waits after entry to `k` until a complete valid proposal at
`k-1` or `k` is available, or until the release deadline Δ expires. PROG(1) and
`f+1` PROG amplification remain immediate. PROPOSE, VOTE, CER, HISTORY3, and
CLOSED leave as soon as their original guards enable them. The same-round
proposal escape prevents a missing predecessor from forcing an otherwise valid
proposal to wait for the deadline. This rule changes the paper's PROG-origin
timing; it is now the implementation default.

Immediate bundling combines already-enabled ordering messages for each recipient
at the end of an effect drain, without a batching timer or waiting for additional
messages. A physical frame carries at most 32 independently verified messages
and at most the selected profile’s encoded-payload limit (1 MiB in the legacy profile).
HISTORY3 remains unicast to its collector.
Logical message counters and physical frame/ACK byte counters are retained
separately; trace packet identities include a bundle member index.

The explicit comparison modes are `--ordering-mode canonical`, which uses the
original PROG-origin rule, and `--ordering-mode barrier`, which uses the full
outgoing round barrier described below. `--ordering-mode progress` selects the
default explicitly. Bundling stays enabled in every mode unless
`--no-ordering-batch` is supplied; canonical scheduling with that flag reproduces
the scheduling and framing choices of the earlier canonical comparisons.
Archived binaries from before explicit ordering modes must use their archived
harness; the current delay runner rejects them before starting a trial.
`--ordering-batch` remains accepted as an explicit enable flag.

Process JSON uses `ordering_mode` (`progress`, `canonical`, or `barrier`) and
`ordering_batch` (default `true`). Omitted mode selects `progress`, except that
`round_barrier_ms` selects `barrier` when no mode is given. The optional
`progress_pacing_ms` and `round_barrier_ms` deadline aliases select the corresponding
mode and override its Δ default; each must be positive and at most `bound_ms`.
Conflicting modes or both deadline aliases are rejected. With `--bound-ms 100`,
the default pacing deadline is 100 ms.

For example, after building and stamping the release binary, the default run is:

```sh
python3 scripts/run_tcp_delay.py --spec-snapshot provenance/spec-2026-10-19.json --output results/local/progress-trial \
  --scenario sustained --rate 4000 --transaction-size 512 \
  --ingress-batch-ms 100 --warmup 10 --duration 30 \
  --delay-ms 10 --bound-ms 100
```

The [measured comparison](PROGRESS.md#ordering-pacing-experiments-and-measured-backlog-removal)
was collected before this default change, with PROG pacing and bundling explicitly
enabled. It removed observed backlog growth and measured approximately 33 ms
PROPOSE-to-direct-commit latency at 10 ms one-way delay. The default change does
not extend the paper's canonical latency theorem: the aligned 3δ path requires
origin PROG for the round to have been released by proposal broadcast. The
independent `7Δ` and `3Δ` timers, signature/Q checks, and terminal outcome guards
are unchanged.

[Fresh default validation](PROGRESS.md#default-ordering-schedule) passed the full
test suite and real-process recovery checks, and sustained 4,000 tx/s at 71.0 ms
mean transaction latency without backlog growth over the measured 60 seconds.

The full outgoing barrier remains an experimental comparison mode. Barrier `r`
waits for a fully validated proposal and own VOTE at `r`, plus the terminal own
outcome and exact report at `r-1` (omitted at `r=1`). It then releases
PROG(`r+1`), VOTE(`r`), CER(`r-1`) when present, and the related HISTORY3/CLOSED.
Its independent deadline starts on entry to `r+1`; it releases only enabled
messages and never fabricates a certificate or CLOSED. Later-enabled messages
at an already-released barrier leave immediately. PROG amplification remains
immediate. A held origin PROG is not signed or counted locally, and a held own
CLOSED does not count toward a catch-up threshold before emission.

In this full-barrier mode, an authenticated remote CLOSED(`h`) or an actually
emitted own CLOSED(`h`) releases pending and future barriers through `h+1`.
This is a send scheduling hint, not additional quorum evidence or a terminal
outcome. A Byzantine signer can use a distant CLOSED hint to disable pacing;
the experiment does not claim phase alignment under Byzantine scheduling.
PROG-only pacing does not hold positive messages or use this CLOSED scheduling
hint. Neither pacing mode automatically inherits the canonical latency theorem.

A separate loopback TCP control client prepares four finite batch waves, with
two unique transactions per honest producer per wave. The `prepare` phase enables
production and dissemination before ordering starts; the harness confirms every
honest replica holds the workload, then starts ordering. Leaders automatically
issue signed REPORT requests on entry and replicas answer once. The controller
sends no reporting commands. This finite acceptance schedule differs from the
older interleaved fixture, so their measured latencies should be interpreted
with their respective workload boundaries. Submission-to-completion includes
preparation. The silent process accepts transport frames and acknowledgments but
performs no protocol handling, batch production or reporting.

The runner checks every submitted transaction at every honest replica, exact
transaction order and final state hash, matching logical batch logs, all-current signed reporting evidence, direct
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
separate TCP runners measure independent processes on one host, including sustained
loads and matched counterpart trials. Durable recovery, larger load sweeps and
deployment across hosts remain work. Counterpart runs are recorded in `benchmarks/`.

Existing-host deployment preparation is available in
[`scripts/deployment_prepare.py`](scripts/deployment_prepare.py). It imports saved
Loom inventories, bundles exact sources, plans pinned Linux builds, publishes
verified artifacts and cleans only owned build intermediates. Build, publish and
cleanup commands default to a local preview. The
[deployment workflow](benchmarks/plans/2026-10-19-deployment-workflow.txt) gives the
full sequence. Local mocked contracts are tested; live remote deployment has not
been tested. Native artifacts use the separate fixed-protocol placement entry point
[`scripts/remote_native.py`](scripts/remote_native.py), with a declared Python3.10+
interpreter and an ingress/materialization observer on each validator host.
Its local mocked lifecycle tests do not establish remote benchmark acceptance.

The October 19 sustained runner schedules independent finite arrivals. Headline
latency uses one origin-local monotonic clock from application admission to
payload-verified contiguous output. Scheduled-arrival latency and post-handler
publication are separate endpoints. The measured cohort contains every request
scheduled in the half-open measurement interval, including late completions during
the declared drain and unfinished requests. Censored p50/p95/p99 and deadline
completion remain authoritative; a completed-only mean is explicitly labelled.
Window goodput counts unique admitted honest requests output during that window,
so it has a different population from the scheduled-request latency cohort.

Authenticated workload records are collected in bounded, hashed pages and checked
offline before a disk-backed exact reducer computes agreement and useful work.
The archive has no aggregate 1 GiB limit; protocol runtime state still grows with
the workload. Each run requires a new result directory and retains unfinished or
zero-output outcomes. See the [current migration status](benchmarks/plans/2026-10-21-migration-status.txt)
and [archive contract](benchmarks/plans/2026-10-19-cohort-storage.txt) for tested limits.

Every nonself send is charged, including silent recipients and deliveries pending
at observation end. HISTORY3/CLOSED charge to h+3; other sends charge to their
original round. Opaque x/pi copies are separated from metadata and framing;
injected duplicates are separated from prescribed sends. Transport overhead,
CPU/queue latency is not represented in these simulators. Composed runs additionally charge BATCH,
REPORT, OBS, FETCH and segmented DATA, separating payload copies from control bytes.
Availability witnesses are charged only where actually sent in PROPOSE; there is
no second virtual dissemination charge for the same evidence.

The runners create unique ignored `results/local/ordering-*` or
`results/local/composed-*` directories,
preserves unsuccessful runs and requires identical signed replays. It rejects
changed source files during archival and changed canonical specification hashes.
Raw archives remain local and ignored; preserve them separately. Current paper
working-tree hashes and Git HEAD are pinned in `provenance/spec-2026-10-19.json`.
The earlier snapshot and its measurements remain available for historical replay.

[PROGRESS.md](PROGRESS.md) links the latest verified run.
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) maps the formal modules and next
stages. The current composition implements the 13 October Option A revision.
The legacy `legacy-1mib-v1` profile supports availability committees of 4 or 7
replicas, reserving complete u64-height proof vectors. The opt-in
`complete-32mib-n31-v1` profile reserves complete messages up to 32 MiB and
committees through 31. Its identifier, limits, and ordered membership are bound
into the authenticated configuration; the legacy configuration hash stays unchanged.
The larger profile retains the full u64 checkpoint range. It reserves the complete
observation pool, all-current witnesses, authenticated base, and worst-case
HISTORY3 before accepting inputs. Incomplete or oversized evidence cannot satisfy Q.

Transport limits include aggregate byte budgets for queued/replayed outgoing frames,
read buffers, and the protocol mailbox, as well as frame/count bounds. Inbox/read
pressure waits; the process retains saturated outbox frames in bounded per-peer
FIFO queues and rotates retries. Exhaustion of the finite envelope is an explicit
failure, never a silent discard. The larger profile uses a 30-second transport body/ACK
timeout, independently of ordering Δ. Byte high-water marks are included in snapshots.

Actual successful stream-write counters split original BATCH payload bytes,
evidence/control, complete FETCH/DATA repair messages, and transport overhead.
Repair includes its embedded payload and evidence; overhead includes authentication,
frame and bundle framing, and all ACK bytes. These disjoint categories sum exactly
to outbound bytes, including partial writes and replays. Logical accepted-message
counters remain separate. TCP/IP headers and kernel retransmissions are excluded.

Optional operation metrics distinguish protocol signatures from data-frame and ACK
authentication, and record content-hash, prefix-proof and construction work. Linux
and macOS expose thread CPU time alongside monotonic elapsed time. Nested operation
costs overlap and must not be summed; compare enabled and disabled trials to quantify
observer overhead. Constructor counters distinguish empty inputs from productive
advancement and record unavailable base proofs, source suffixes and source proofs.
The application cohort ledger separately identifies pending honest data.

The specification’s singleton procedure is not implemented. Durable recovery,
bounded custody and validation of distributed-host campaigns remain subsequent work.
