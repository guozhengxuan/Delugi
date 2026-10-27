# Delugi implementation and evaluation plan

Updated **27 October 2026 (Asia/Taipei)**. Reviewed against implementation and
results at commit `427c7e6`, including the completed four-host Aliyun pilot.
This document is the active next-step plan. The dated plans and result receipts
linked below retain their original scope and evidence.

The [27 October counterpart and Aliyun proposal](benchmarks/plans/2026-10-27-counterparts-and-aliyun.txt)
adds the requested Raptr, Simple-IT, Autobahn and Mysticeti study design, common
campaign interface and paper-derived figures. The author selected exactly
**10 and 50 replicas**, omitting the intermediate size. The 50-replica case
requires general-membership quorum/proof and resource-profile qualification;
it must not be replaced with 49. This selection updates the scale targets below
and does not authorize a new cloud lease. The remaining proposal is unchanged.

## 1. Current stage and priorities

**The shared Delugi/Raptr implementation has passed local conformance and an
unshaped, four-host Linux functional pilot. The next milestone is matched
sustained-load evaluation of these two integrated cores.**

| Area | Accepted evidence | Remaining work |
| --- | --- | --- |
| Delugi ordering and Option A composition | HISTORY3, CLOSED, catch-up timers, scanner, authenticated bases, all-current construction, empty fallback, exact-batch fork handling and deduplication; deterministic and independent-process checks | Preserve conformance while extending the evaluation path; reconcile the scheduling amendment with the selected paper snapshot |
| Shared architecture | `core/delugi` and real pinned `core/raptr` consensus/Quorum Store behind one executable and reusable services | Extend workload, lifecycle and evidence mechanisms; retain protocol-owned policy |
| Local common-node acceptance | [30 Delugi cases](benchmarks/results/common-node-delugi-validation-2026-10-21.json) and [six Raptr cases](benchmarks/results/common-node-raptr-validation-2026-10-21.json), including actual missing-payload repair | Requalify each new executable and every claimed profile |
| Linux release and publication | 19 native tests; portable source-bound artifact verified on four hosts | Build again when compiled sources or dependencies change; reuse the retained artifact for its existing revision |
| Aliyun deployment | [12/12 trials passed](benchmarks/results/aliyun-four-host-pilot-2026-10-26.txt): both protocols, healthy round 4 and silent first leader plus three honest anchors, three repetitions each | Matched sustained workloads and calibrated delay, then larger committees and WAN |
| Performance accounting | Delugi sustained cohorts and reusable cohort/frontier/calibration machinery exist; integrated Raptr has authenticated finite inputs and output | Bounded sustained Raptr generation/journals, common cohorts, equal measurement windows and integrated campaign routing |
| Additional counterparts | Pinned native Raptr/Mysticeti artifacts and Vantage-family work are retained | Mysticeti, Autobahn, Simple-IT and Shoal are not integrated selectable common-node cores; defer new ports until the Delugi/Raptr comparison |

The accepted cloud fixture used four Singapore `ecs.g9i.xlarge` hosts, 128 useful
bytes per transaction, shared RocksDB Written storage, Δ = 100 ms and **zero
injected delay**. Delugi preloaded 32 transactions (24 with a silent leader);
Raptr used 64 finite timed requests (48 with a silent leader). Their workload
shapes and traffic endpoints differ, so `comparison_eligible=false`.

All four instances and the dedicated security group were deleted on 26 October
at 19:44:37 Taipei. The CNY 50 authorization covered that completed two-hour
pilot. A new paid campaign needs a new explicit lease and budget. No cloud
resources are to be created by this planning update.

The approved [21 October architecture](benchmarks/plans/2026-10-21-shared-core-architecture.txt)
supersedes the older proposal to make a Vantage fork the main implementation.
The [23 October qualification plan](benchmarks/plans/2026-10-23-linux-distributed-qualification.txt)
remains useful design detail, but its Linux-build and four-host-pilot pending
status is superseded by the [26 October receipt](benchmarks/results/aliyun-four-host-pilot-2026-10-26.json).
Historical native-artifact and 13 October timing results remain separate from
acceptance of the current shared implementation.

## 2. Architecture and protocol contracts to preserve

| Boundary | Current responsibility |
| --- | --- |
| `core/delugi/` | Ordering predicates, HISTORY3, PROG/CLOSED, timers, scanner; signed batches/MMR/availability, base authentication, custody, retrieval and exact output |
| `core/raptr/` | Pinned native consensus, Quorum Store, native messages/certificates, batching/dissemination/repair and native output expansion |
| `shared/` | Network connections/queues, cryptographic execution, independent ingress, storage, output queues, runtime/task ownership and counters |
| `core-api/`, `node/` | Lifecycle factory, opaque per-core configuration, key generation, archive/ledger verification and common CLI dispatch |
| `scripts/`, `tests/` | Workload plans, deployment, faults, measurement, reduction, provenance and acceptance; reuse these existing locations |

`ProtocolFactory` exposes `name`, `run`, `generate_keys`, `verify_archive` and
`verify_ledger`. It is a lifecycle interface; it does not impose universal
consensus messages or availability certificates. The common executable selects
`--protocol delugi|raptr` from `node/src/shared_main.rs`. Its assembly manifest
is `core/raptr/node/Cargo.toml`; the retained binary name is `raptr-shared-node`.
See [interface and parameter references](docs/architecture/delugi-code-structure-2026-10-22.txt)
and the [service contract](benchmarks/plans/2026-10-21-shared-service-contract.txt).
The dated interface map's cloud-pending statements are superseded by this plan.

Preserve these implementation obligations:

- Delugi's Q validates complete supplied immutable metadata. Payload retrieval
  stays outside proposal validation and scanner decision handlers.
- An earlier base carries its signed ordering header, matching descriptor and
  `n−f` matching short CER signatures. The reference constructor uses the frozen
  current OBS pool and authenticated-base empty fallback. An advancing target
  requires the leader's exact suffix and proof-producing state.
- Exact batch identity includes producer, height and unsigned-header digest.
  Individually valid Byzantine forks may both be ordered. FIFO materialization
  emits each exact identity once; application-request deduplication is separate.
- Preserve full HISTORY3 verification, once-only VOTE/CER/report obligations,
  immutable terminal outcomes, independent 7Δ/3Δ timers and contiguous scanning.
  Projected history entries are not substitute signature sets.
- Default scheduling is originating-PROG pacing with a finite Δ release deadline
  plus immediate bundling of already-enabled messages. PROG(1), amplification
  and enabled proposal/vote/certificate/history/closure effects remain immediate.
  Canonical scheduling and bundling on/off remain explicit ablation controls.
- Shared TCP pipelines frames without an unconditional per-frame ACK gate;
  bounded backpressure and authenticated replay remain enabled for both cores.
  Sharing infrastructure preserves each protocol's signing, certification,
  batching, timer multipliers and repair rules.
- Shared RocksDB Written means WAL-enabled, `sync=false` writes before visibility.
  It does not implement core restart recovery. Memory Visible is a separately
  named profile. Delugi and Raptr retain different actor/executor topologies.

## 3. Next implementation sequence and acceptance gates

### E0 — Freeze the comparison contract and specification identity

**First deliverable:** a versioned common campaign schema and one reviewable n=4
Delugi/Raptr development configuration, with explicit effective settings.

Use [spec-2026-10-19.json](provenance/spec-2026-10-19.json) as the latest reviewed
manifest, not the old plan's blanket 13 October reference. The 27 October audit
found that live `protocol/ordering.tex` differs from this manifest; live
`protocol/dissemination.tex` matches it. Review that ordering diff and either
select the matching archived paper tree explicitly or create a freshly reviewed
snapshot. Keep historical manifests unchanged. `scripts/spec_provenance.py`
already rejects mismatches; do not bypass it by refreshing hashes automatically.

Record the schedule variant separately from the paper identity. Canonical
3δ/5δ ordering bounds end at direct commitment under their stated conditions;
they are not end-to-end transaction bounds for the default paced implementation.
The 2δ input-readiness claim permits empty fallback and does not imply useful
output. Resolve specification correspondence before making formal algorithmic
claims from the new measurements.

Version the integrated campaign path around an explicit two-protocol study
scope. `scripts/aliyun_bench.py` currently accepts only the finite n=4 pilot.
The older `scripts/run_campaign.py` formal mode requires the historical
Delugi/Mysticeti/Autobahn/Shoal set and does not qualify this integrated Raptr
study. Reuse its reduction and acceptance mechanisms through an explicit new
adapter/schema; preserve the old validator and archived campaign meaning.

**Gate:** a configuration resolves to exact source/spec/artifact identities,
workload populations, timing windows, storage/resource profiles and protocol
settings. Unsupported controls fail validation. No execution or spending is
implied by generating a plan.

### E1 — Bounded sustained Raptr workload and shared cohort reduction

**Highest-priority code work.** Extend `core/raptr/node/src/workload.rs`, its
configuration/lifecycle, and the integrated runner. Reuse `shared/mempool`,
`scripts/cohort_store.py` and `scripts/cohort_metrics.py`; keep BCS construction,
native identity checks, batch cutting and QS policy in the Raptr core.

Current limits explain why the finite pilot cannot become a load benchmark by
changing a count: the Python runner fixes four nodes and at most 5,000 requests
per origin; the node precomputes at most 100,000 requests / 128 MiB, bounds each
measurement/drain interval to 60 seconds, clones retained journals at freeze,
and uses a fixed 180-second end guard. The reducer also bounds journal row count.

Implement bounded preparation chunks or a sharded pre-generated spool, streaming
signed/hash-bound evidence, and lifecycle guards derived from the declared run.
Keep arrivals independent of consensus progress. Record actual offer attempts,
preparation lag, rejected/cancelled offers and cutoff crossings explicitly; the
current cutoff-crossing path returns without an offer outcome. Preserve rejection
of late admission and never credit output that precedes successful admission.

Normalize intended, offered, admitted, rejected, cancelled, completed, unfinished
and unoffered populations into the common cohort store. Preserve raw native
section/batch/transaction order and exact batch identities; count useful request
identities once across retransmission and replication. Keep the accepted finite
schema and fixtures replayable.

**Gate:** empty, zero-output, unfinished, saturated-queue and cutoff-crossing
fixtures reconcile every identity; duplicate/tampered/missing journal shards
fail verification. A multi-minute run has bounded producer/observer memory and
bounded spool/journal storage. Measure protocol retained-state growth separately;
Delugi's indefinite custody and retained history must not be silently pruned.

### E2 — Common distributed lifecycle, clocks, traffic and diagnostics

Extend the existing `aliyun_bench.py`, `common_cloud_worker.py` and common-artifact
path for the sustained schema. Delugi's legacy `run_sustained.py` still rejects
remote common-build receipts and remote shared RocksDB trials. Replace those
restrictions only through a validated deployment capability and lifecycle.

Prepare every host, verify readiness, then arm a host-local monotonic epoch and
relative phase schedule. Preserve abort tombstones, exact PID/start/group
ownership, pinned SSH session reuse, bounded collection and independent cleanup
on every contacted host. Record actual phase skew and scheduling lag. Workload
and fault timing must not depend on subtracting remote host clocks.

Add authenticated counter snapshots at equivalent warmup, measurement, drain and
shutdown boundaries. Delugi's fully drained final counters and Raptr's counters
frozen before shutdown currently cover different intervals. Retain all phases,
and compare only the same selected measurement boundary.

Define detailed and minimal observation profiles for the integrated campaign.
Both retain correctness receipts and population accounting; only the detailed
profile supplies per-request/stage timing. Keep observer buffers bounded and
measure their overhead in paired runs.

Add optional stage observations without making them protocol prerequisites:
origin admission and batch readiness; leader input/history readiness; HISTORY3
construction and serialized bytes; outbound queue/write; proposal verification;
vote/CER quorum and direct commit; scanner release; payload retrieval and actual
application append. HISTORY3 construction is a leader stage. Preserve native
Raptr stage names and mark unavailable observations explicitly. Report local
spans and causal dependencies; do not stack overlapping spans or subtract clocks
from different hosts to manufacture an end-to-end breakdown.

**Gate:** fake-host tests and real local Linux lifecycle tests cover partial
prepare/start, lost/late arm, controller interruption, paused children, PID
reuse, disk exhaustion, truncated/tampered export and cleanup failure. Arbitrary
host monotonic offsets leave primary metrics unchanged. Traffic conservation
and phase-window parity pass before protocol comparisons are eligible.

### E3 — Requalify the final Linux artifact and sustained harness locally

After E1/E2, build one common release artifact for both cores. Preserve the
successful two-job guarded recipe, source/dependency/profile closure, ELF/ABI
checks and bounded disk/RSS/time supervision. Verify the archived executable
and receipt before removing disposable targets; keep targets out of Git.

On the exact new hash, rerun both protocols' round-4, silent-first-leader,
missing-payload repair, empty and unfinished controls, plus every claimed
storage/observer/schedule profile. Retain Delugi deterministic/wire conformance
and native Raptr/QS regressions. Keep rejected attempts in the evidence ledger.

Then run unshaped local Linux sustained checks at 1k and 4k total tx/s, an
explicit overload point, and a five-minute soak. Inspect conservation, censored
tails, backlog subwindows, journals, phase counters, CPU/RSS and retained storage.
Run paired detailed/minimal observation controls before using detailed traces
as performance results. Local placement results qualify the harness; they do
not establish distributed capacity.

**Gate:** both cores pass on the same artifact, all workers/tasks are reaped,
evidence validates after transfer, and load/observation machinery stays within
its declared resource envelope. A failed protocol point is retained as a result;
a broken generator or incomplete evidence makes the comparison ineligible.

### E4 — Matched four-host Aliyun timing and load qualification

After E0–E3, prepare a fresh priced lease for user approval. Reuse the tested
Singapore host class and private networking as the first placement. Build before
the paid measurement window where possible, and publish one verified artifact.

Run this small development matrix first:

| Item | Initial setting |
| --- | --- |
| Protocols / placement | Integrated Delugi and Raptr; n=4, one validator per equal dedicated host |
| Storage / payload | Shared RocksDB Written; 128 useful bytes per transaction; actual encoded bytes retained |
| Offered rates | 1,000 and 4,000 total tx/s, identically allocated over active honest origins |
| Network / bound | Unshaped control, then injected δ=10 ms; configured Δ=100 ms in both |
| Duration / repeats | 10 s warmup + 60 s measurement + 30 s drain; three repetitions per cell |
| Batching | First record each core's effective native/default policy; then a declared supported batching grid |
| Execution order | Interleave protocols and record the order/seed; fresh owned stores for each trial |

This is 24 healthy trials before tuning expansion. The durations and controls
are planned capabilities, not claims that the finite pilot CLI already supports
them. The development matrix precedes formal capacity selection.
The declared phases total 40 minutes across the sequential matrix; the lease
must also cover publication, calibration, startup, verification, export and
cleanup. Price any build host and retry allowance separately before approval.

Calibrate Linux `tc/netem` on the exact private peer paths, applying the intended
one-way delay once per path. Retain raw established-TCP RTT samples before,
during and after shaping plus an unselected control. For δ=10 ms, the existing
policy requires added median RTT of 20±5 ms and restoration within 2 ms. Bind
measurements to peer/role identities; this validates added RTT, not independent
one-way clock measurements. A failed calibration keeps the run diagnostic.
Record native baseline RTT and any observed queueing under load as well.

Δ is the configured delay-bound input, not a latency added to measurements.
Raptr's operative `delta_ms` maps to native multipliers (leader 4Δ, extra QC wait
0.1Δ, fetch 2Δ, status 10Δ, round synchronization 15Δ); preserve those settings.
Delugi retains its 7Δ/3Δ timers. Matching Δ does not mean replacing the protocols'
native timeout rules with identical timers.

**Gate:** exact workload/resource/storage identity, complete cohorts, calibrated
paths for shaped cells, equivalent traffic windows, output agreement and full
cleanup. Produce throughput/latency/backlog/traffic curves and a 4k tx/s stage
breakdown that can locate history waiting, batching, queueing or retrieval delay.

### E5 — Capacity, scheduling ablations and recovery under sustained load

Extend the healthy load grid from 1k/4k by bounded increases until an unstable
point is observed, then refine around the highest accepted sampled rate. Freeze
the grid, batching candidates, tail target and acceptance policy before selection.
Use at least 120-second measurement windows and three repetitions for formal
frontier claims; do not promote the 60-second development cells.

Reuse [frontier selection](benchmarks/plans/2026-10-19-frontier-selection.txt):
all repetitions must pass exact cohort conservation, zero rejected/unfinished
measured work, scheduled/admission p99 within the common declared tail target,
at least 95% useful measurement-window goodput, and declared net-backlog and
excursion limits across ten subwindows. Preserve failures and censored tails.
A selected frontier is the highest accepted measured point, not an extrapolated
maximum. Freeze the same resource contract across load/tuning choices.

Run Delugi's four required scheduling cells: canonical or paced PROG, each with
bundling off/on, on the same binary and pipelined transport. Add empty/fallback
opportunities and a detailed/minimal observer pair. This isolates the scheduling
and bundling effects from cryptography, load, transport or observation changes.

Then test missing follower payloads, controlled nonleader omissions and silent
leaders affecting successors under a common absolute rate strictly below both
healthy frontiers. Start with the retained three-honest-anchor recovery case.
Add matched-utilization trials as a separate series. Keep a fixed faulty identity
set of size at most f throughout each run; record actual fault activation and
recovery times. A process pause or payload omission is not arbitrary Byzantine
computation. Signed equivocation/fork performance requires its own fault actor
and correctness acceptance before inclusion.

**Gate:** equivalent fault semantics and offered populations, retained honest
proposal/output evidence, completed repair/recovery witnesses, censored unfinished
work and bounded cleanup. Report recovery time, backlog drain and costs alongside
healthy goodput and latency, including failed/empty opportunities.

### E6 — Scale, WAN and later counterparts

Generalize integrated runners, private-network validation, membership/key
creation, fault selection and evidence reduction for the author-selected n=10
and n=50 evaluation cases. Omit intermediate-size performance campaigns; retain
small existing fixtures as regression checks.
Raptr's Rust configuration accepts n=3f+1 up to 31, but its accepted Python runner
and private deployment profile currently require four nodes. An n setting alone
is insufficient. For n=50/f=16, review the general n>=3f+1 specification and all
consensus, availability and optimistic-path thresholds before implementation;
ordinary high quorums require 34 rather than 2f+1=33. Extend and validate the
wire, process, network and provider limits, including proposal/witness size and
queue/memory envelopes, before paid load sweeps. Do not round n=50 down to 49.

After regional acceptance, plan Alibaba WAN placements with measured path RTTs
and heterogeneous delay, recording whether the chosen Δ covers the test regime.
Keep WAN observations separate from controlled regional δ experiments.

Only after the first accepted Delugi/Raptr comparison, scope a Mysticeti port
against its preserved native artifact, then other counterparts as needed. Keep
protocol-specific DAG/availability/repair policy under its own core. Core crash
recovery, durable fsync profiles and arbitrary Byzantine execution remain separate
implementation milestones, not settings enabled by this evaluation plan.

## 4. Parameterization required for the next campaign schema

Every run must record both the requested setting and the effective setting.

| Control | Available now | Next-step contract |
| --- | --- | --- |
| Useful transaction bytes | Pilot 1–4096, default 128; broader bounds in individual runners | Match useful bytes; record native signed/encoded size separately; later sweep 512/4096 useful bytes |
| Total offered rate and origin allocation | Delugi sustained runner; Raptr finite counts/cadence | Shared open-loop total-rate recipe, exact fractional scheduling and honest-origin population |
| Warmup / measurement / drain | Delugi sustained phases; Raptr finite horizon | Versioned multi-minute phases and derived process/collection deadlines |
| Batch count and cut cadence | Delugi `max_batch_transactions` / ingress cadence; Raptr native QS policy | Expose operative per-core knobs with boundary tests; retain defaults and a declared tuning grid |
| Batch bytes | Delugi wire/profile bounds; Raptr QS configuration fields | Raptr's native per-batch byte-filter loop is inactive; do not advertise `sender_max_batch_bytes` as an enforced cap |
| Maximum proposal payload | Protocol-specific descriptor, transaction, batch and byte limits | Name each unit and boundary separately; validate against wire/proof limits; Raptr's nominal 200-batch pull can admit 201 on its current path |
| Pending payload / queue budgets | Component-specific frame, byte, ingress, output and task limits | Bind effective per-component envelopes plus observed/enforced whole-worker resources; do not call a pending-byte limit a proposal cap |
| δ | Pilot unshaped; existing calibration/netem mechanisms | Validated per-path shaping, raw RTT evidence and exact cleanup |
| Δ | Pilot fixes 100 ms | Record each operative mapping and native multiplier; initial matched setting remains 100 ms |
| Committee and f | Integrated pilot n=4, f=1 | Author-selected n=10/f=3 and n=50/f=16; qualify general quorums and larger profiles for 50 |
| Injected faults | Named silent-leader and missing-payload controls | Separate fault budget f from injected count/type/identity/time; qualify 0, then 1, then up to f |
| Storage | Memory Visible; common RocksDB Written | Match backend/completion/WAL/sync policy; record lack of core restart recovery |
| Scheduling / observation | Delugi canonical/paced/barrier and bundling controls; finite native Raptr evidence | Primary Delugi paced+immediate bundling, explicit ablations, aligned full/minimal observation evidence |
| Hardware / deployment | Four equal dedicated hosts, affinity, observed RAM/swap, private peers | Hash-bound host/executor/network/storage profiles; explicit lease, export and cleanup bounds |

Raptr's operative QS settings are top-level `quorum_store`; serializing a field
under `consensus.quorum_store` does not establish that the adapter uses it.
Preserve native defaults for the reference series. Any changed native policy or
newly enforced formerly inactive limit must be named, reviewed and requalified
as a variant. Equal CPU/RAM and shared providers do not erase native cryptographic
or executor differences; report those effective profiles.

## 5. Measurements, evidence and completion criteria

Primary latency is **successful origin-local admission to the first locally
verified contiguous application append**. Also report scheduled-arrival latency
so slow preparation, blocked admission or rejection cannot hide load. Use only
same-host monotonic differences. Verify output membership and compatible exact
prefixes at every correct replica; remote all-correct latency remains unavailable
without a separately qualified end-to-end acknowledgement measurement.

Report useful unique completion throughput in the measurement window, completed
cohort fractions after drain, p50/p95/p99 with unfinished requests retained as
censored observations, and ten-subwindow admitted/scheduled backlog. Separate
warmup carry-in, measured-cohort work and drain completions. Preserve empty,
zero-output, overloaded and failed runs; zero-output cost ratios are undefined.

Keep exact emitted batch payload `M_out` separate from unique useful honest
application payload `U_out`. Count all opportunities and costs: payload,
availability/history/certificate control, framing/authentication/ACK overhead,
repair, retransmitted application writes, failed/empty opportunities and
carried-in evidence. Compare matching stream-write windows; TCP/IP headers and
kernel retransmissions require separately named OS measurements. Record CPU,
RSS, disk/state growth, per-replica/leader traffic and queue pressure.

Each accepted result retains source/spec/lock/toolchain identities, build receipt
and binary hash, requested/effective configuration, placement/resource proof,
raw workload/output evidence, phase/fault/calibration records, signed final
receipts, reducer version, failed attempts and cleanup proof. Continue native
verification before reduction. Raptr's current export authenticates observer
journals, transactions and output order; it does not export raw native QC proofs.

The next milestone is complete when E0–E4 produce a reproducible matched n=4
Delugi/Raptr report at unshaped and δ=10 ms / Δ=100 ms settings, including 4k tx/s,
without unresolved cohort, timing, traffic or cleanup gaps. E5 qualifies capacity
and fault-performance claims; E6 expands scope. Continue periodic commits/pushes,
retain verified artifacts and raw evidence, and remove disposable build targets.
