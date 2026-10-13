# Progress — 12 October 2026

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

General common-base coordination, ready input at honest entry, and compatibility
of concurrent Byzantine frontiers remain open adapter obligations. SAFE-2 tests
continue to show that independently Q-valid conflicting frontiers are possible;
materialization raises an explicit composition error before partial execution.
All custody, sequence and execution state remains in memory. Reconnection works,
but durable recovery after process restart is not implemented. Remaining systems
work includes arbitrary client submissions/open-loop load, storage/recovery,
transport optimization, multi-host deployment and counterpart measurements.

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
