# Evaluation architecture decision — 2026-10-13

Use a Vantage-derived evaluation workspace for a controlled comparison of Delugi,
Vantage, Autobahn and Simple-IT. Keep this Delugi repository as the specification
implementation, test oracle and experiment record. Retain pinned native Raptr
and Mysticeti as external implementation baselines. Begin with a common external
harness; port Delugi into Vantage's runtime next. A manual Mysticeti rewrite is
not the first step.

This recommendation concerns future implementation work. This increment fetched
and tested Vantage locally and prepared the shared timing experiment; it does not
create a GitHub fork or provision cloud machines.

## Evidence and scope

Vantage is pinned to
[`199098c4978e4a97a7d3707ec9aac6de086969db`](https://github.com/polinikita/vantage-bft/tree/199098c4978e4a97a7d3707ec9aac6de086969db).
Its source and Cargo.lock built without modifications, using a workspace-local
Rust 1.95.0 toolchain. The checkout contains Vantage, Autobahn optimistic,
Autobahn seamless, Simple-IT, and Simple-IT Bracha variants under an Apache-2.0
license. Its Autobahn lineage and co-located implementations should be identified
by this exact pin; they are not interchangeable with every original paper artifact.

Validation passed 712 unchanged workspace tests. The remaining authentication
test hardcodes port 5900, already occupied on this host. It passed with an archived
test-only change to choose an ephemeral port; original source bytes were restored.
Release-mode tests enabled debug assertions for workspace crates because one
upstream expected-panic test depends on a debug assertion. The measured release
binary was unchanged by these test adaptations.

All five native local-benchmark variants passed with four authorities, one worker
per authority, 512-byte native transactions, 1,000 offered tx/s, a two-second
warmup, a ten-second measurement window, explicit zero mimicked RTT, and native
Delta=200 ms. These are functional measurements in **one OS process** with
multiple Tokio tasks, sockets and stores. The numbers below describe that run;
the earlier Delugi comparison uses independent replica processes.

| Variant | Native completed tx/s | Mean materialized latency (ms) |
| --- | ---: | ---: |
| Vantage | 992.4 | 95.53 |
| Autobahn optimistic | 990.0 | 138.23 |
| Autobahn seamless | 980.0 | 236.57 |
| Simple-IT | 992.4 | 133.20 |
| Simple-IT Bracha | 991.1 | 142.40 |

[Compact results and raw evidence hashes](results/vantage-local-2026-10-13.json)
record complete settings, test adaptations, all five summaries, native traffic,
and post-window drain observations. Native throughput uses the maximum committed
count across authorities; native mean latency combines replicated worker
observations. Native traffic includes different links/accounting from our
successful replica TCP-write metric. These rows therefore do not establish a
performance ranking against Delugi, Raptr or Mysticeti.

## Implementation differences that matter

This table describes the 13 October snapshot. The [14 October transport fix](TRANSPORT_PIPELINE.md)
replaces Delugi's per-frame ACK gate with bounded pipelining; the protocol and
authentication distinctions remain.

| Dimension | Delugi on 13 October | Pinned Vantage workspace | Consequence for evaluation |
| --- | --- | --- | --- |
| Runtime | Independent Rust processes; synchronous state-machine/effects boundary, dedicated TCP threads and central event handling | Tokio actors; separate primary and worker components; native local smoke runs them in one process, container deployment separates roles | Use the same replica/worker process and CPU allocation for a controlled comparison |
| Transport | Per-peer FIFO, one signed frame followed by a signed application ACK before the next frame; retries and deduplication | Asynchronous senders, batching/coalescing, authenticated cross-validator channels and reconnection | Delugi's stop-and-wait transport can amplify latency and queue growth as RTT increases; share a pipelined transport while retaining protocol evidence |
| Authentication | Ed25519 ordering/dissemination evidence plus signed transport frames/ACKs | Pairwise BLAKE3 channel MACs; protocol-dependent transferable signatures, including Ed25519 where required | Normalize channel services separately from protocol-required signatures; preserve actual cryptographic cost |
| Payload model | Signed producer/height/previous-digest records, MMR custody proofs, authenticated imported bases, all-current construction or empty fallback, exact unsigned-header-digest dedup | Workers hash/store/disseminate batches and report digests; primary consumes digests and notifies committed payloads | A Delugi adapter must preserve record identity, ancestry and proof semantics rather than substituting plain Vantage batch hashes |
| Ordering/recovery | HISTORY3/CLOSED, 7Delta main timer, 3Delta catch-up timer, scanner; ordering metadata pushed, payload FETCH/DATA separate | Protocol-specific primary actors, availability/frontier/sequence tracking, repair and state synchronization | Share infrastructure without replacing either protocol's certificates, resolution rules or recovery traffic |
| Storage/retention | In-memory retained custody and protocol state; no production GC or crash-restart persistence | RocksDB actors with staged read-your-writes overlay and asynchronous non-sync writes; in-memory GC/retention and recovery facilities | Agree on durability and disk-pruning policy; the current store API has no payload-delete operation, and a commit acknowledgement is not automatically a synchronous disk barrier |
| Benchmark infrastructure | Local independent-process runners, pinned native artifacts, agreement tests, counter snapshots, manifests | Local/Docker harnesses and a separate WAN campaign tool | Reuse mature deployment pieces and adapt metrics explicitly |

Sources in the pinned checkout: [protocol selection and role messages](https://github.com/polinikita/vantage-bft/blob/199098c4978e4a97a7d3707ec9aac6de086969db/primary/src/primary.rs),
[worker batch processing](https://github.com/polinikita/vantage-bft/blob/199098c4978e4a97a7d3707ec9aac6de086969db/worker/src/processor.rs),
[authenticated channels](https://github.com/polinikita/vantage-bft/blob/199098c4978e4a97a7d3707ec9aac6de086969db/network/src/channel_auth.rs),
[storage](https://github.com/polinikita/vantage-bft/blob/199098c4978e4a97a7d3707ec9aac6de086969db/store/src/lib.rs).
Delugi's corresponding boundaries are `src/replica.rs`, `src/composed.rs`,
`src/transport.rs`, `src/batch.rs`, and `src/process.rs`.

Vantage's current channel-auth constructor derives pairwise keys from a shared
benchmark seed; its source explicitly identifies this as a stand-in for direct
key provisioning. For Byzantine experiments that allow a replica to inspect its
configuration, provision only that replica's pairwise keys. A committee-wide seed
would let its holder derive other replicas' channel keys. Preserve Vantage's
non-transferable MAC model and each protocol's required transferable evidence.

Vantage is a useful runtime foundation, not a ready-made plug-in API. Adding a
Delugi variant requires protocol selection/configuration, actors, record/proof
storage, payload materialization and metrics adapters. Existing Delugi
receive/tick-to-effects logic supplies a practical transition-system boundary.
Keep its deterministic tests as an oracle and compare identical event traces
through the reference core and the new adapter, including Byzantine forks,
empty fallback, duplicate records, round 4 and silent-leader recovery.

## Why equal Delta alone is insufficient

Delta is a bound parameter or an explicit mapping to a native timer; it is not a
universal batching interval or an enforced minimum latency. At the user's selected
preset, added one-way network delay delta is 10 ms and Delta is 100 ms. Preserve
native multipliers:

| Implementation | Mapping at Delta=100 ms | Separate native pacing |
| --- | --- | --- |
| Delugi | Main timeout 700 ms; catch-up timeout 300 ms | Existing producer batching and event/transport queues |
| Raptr | Leader timeout 400 ms; partial-QC wait 10 ms; block fetch 200 ms; round synchronization 1,500 ms | Quorum Store poll 150 ms, nonempty minimum 80 ms, maximum batch interval 300 ms; payload wait budget 1,500 ms |
| Mysticeti | Explicitly set leader-readiness timeout T=100 ms | Quorum clock and eligible block production; 100 ms generator cadence retained |
| Vantage family, for a future matched run | `--delta-ms 100`; reconciliation enforces each protocol's own timeout factors | Worker/header/transport batching remains separately configured; `--mimic-latency-ms` denotes RTT, so 20 ms corresponds to delta=10 ms |

The pinned Mysticeti runtime previously ignored its public leader_timeout setting
and hardcoded one second. This increment wires the setting to the actual task,
preserves the historical effective one-second default, and tests timer firing
and reset with a paused clock. This T=Delta mapping is an experimental choice;
Mysticeti does not expose an identical theorem-level Delta parameter.

In a representative old 1,000 tx/s Raptr trial, the mean ingress-to-first-Quorum-
Store-pull wait was 80.501 ms and ingress-to-payload-ready completion was 99.499 ms.
The separate batch-creation-to-commit mean was 18.069 ms and proposal-to-commit
mean 8.205 ms; these latter means use different populations and should not be
subtracted from one another as a transaction-level decomposition. Much of the
observed ingress latency was therefore batching wait, not the 800 ms leader
timeout then configured.

The corresponding old Delugi trial generated about 1,000.12 tx/s, completed
930.92 tx/s, and grew pending work from 620 to 2,696 transactions during the
window. Its 1,519.74 ms mean includes queueing. Mysticeti can produce eligible
blocks immediately on localhost. These measurements explain why the earlier
native-settings table cannot isolate protocol latency. Preserve that table as
historical evidence and report the calibrated timing rerun separately.

The controlled pilot provides direct transport evidence. At 40 tx/s, each directed
Delugi peer stream acknowledged 48.90–49.01 frames/s; in the first 1,000 tx/s trial,
48.83–48.93 frames/s. Both sent ten BATCH frames/s per peer plus about 39 control
frames/s, with outstanding queues and zero retries/ACK failures. That service
rate is close to the roughly 50-frame/s ceiling of one acknowledged frame per
20 ms round trip. Increasing transactions per batch raises transaction throughput
without removing the control-frame queue. These counters identify a transport
bottleneck; stage timestamps are still needed to apportion the full admission-to-
materialization latency. The current measurements therefore motivate a pipelined
shared transport before making an algorithm-level latency claim.
The [transport audit](results/delugi-transport-audit-2026-10-13.json) retains the
exact two-trial population, per-peer inputs, formulas, source identities and raw
snapshot hashes. It does not establish a 700 ms timeout wait.

## Common infrastructure and native baselines

For the controlled algorithm comparison, fork Vantage's pinned runtime and port
Delugi into it. This reuses three relevant counterpart families and their worker,
network, storage and observability services. Reimplementing every counterpart
inside the current lightweight Delugi process layer would add more new consensus
code to validate while still requiring those services to be built.

For implementation comparisons, run the pinned native Raptr and Mysticeti with
the same external workload schedule, network conditions, machines, faults and
measurement schema. Their internal batching, data placement, crypto and storage
remain recorded experimental dimensions. A shared repository alone does not make
these dimensions equivalent.

Avoid a manual Mysticeti consensus rewrite initially. Its signed StatementBlock
contains payload and parent references; native block verification, quorum clock,
WAL and block production are coupled. Replacing full blocks with Vantage
batch-digest headers would change data availability and signed evidence. A later
port should retain native block bytes and transition logic, adapt network/store
interfaces, validate differential traces and recovery, and be reported as a
separate implementation. See the pinned [block representation](https://github.com/asonnino/mysticeti/blob/96fd83154bb5e168def9a81ee8f3e90e94e46a2e/crates/mysticeti-core/src/types.rs)
and [block production](https://github.com/asonnino/mysticeti/blob/96fd83154bb5e168def9a81ee8f3e90e94e46a2e/crates/mysticeti-core/src/core.rs).

The [wan-bench README](https://github.com/polinikita/wan-bench#readme) documents
AWS EC2 lifecycle management, one validator per instance, a monitoring controller,
private addresses in one availability zone, and tc netem WAN emulation. It
supports Vantage/Autobahn/Simple-IT and Starfish adapters. Alibaba requires a
provider implementation for provisioning, networking, credentials and teardown;
Docker, SSH, netem and Prometheus are reusable components. Start the first formal
campaign on AWS to use the existing deployment path, then reproduce a selected
subset on Alibaba if provider sensitivity is part of the study.

Before a formal campaign, require:

1. A shared open-loop generator and exact serialized transaction size, common
   admission/materialization timestamps, origin-based unique completion counts,
   identical warmup/measurement/drain windows, and queue-growth reporting.
2. Identical instances, CPU/memory quotas, worker counts, storage policy and
   bandwidth/delay/fault schedules. Record observed RTT distributions and clock
   uncertainty. An injected delay is additional delay, not a proof that Delta
   bounds an uncontrolled cloud path.
3. Raw outbound-byte counters at a common boundary, with client, worker, repair,
   authentication and retransmission scope specified. wan-bench's median-node
   wire-efficiency metric differs from our total TCP stream-write rate.
4. Fresh stores and run identities per independent repeat; restart-with-state
   for recovery tests. Campaign resume preserves benchmark checkpoints; restarting
   the same container preserves validator state. Verify fresh-trial disk reset
   explicitly. Preserve overload failures and raw logs.
5. Source/image pins, archived configurations, randomized or rotated sequential
   runs, and identical metric scrape intervals. The WAN README's default 30-second
   scrape interval is too coarse for our 30-second measurement windows; use
   explicit boundary snapshots and a shorter recovery time series.

Use fault-free load sweeps, silent-leader recovery and Byzantine fork scenarios
as distinct experiments. Require complete workload accounting and agreement
checks before publishing throughput/latency curves. Keep the outstanding
incompatibility question separate from this infrastructure decision, as requested.
