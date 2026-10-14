# Latency endpoint and timer audit — 14 October 2026

**Implementation update:** the native ACK gate has since been removed. See the
[transport pipeline report](TRANSPORT_PIPELINE.md) for the bounded window,
regressions, macOS socket correction and native reruns. The diagnosis below
describes the original 13 October transport and preserves its measurements.

The 758–799 ms Delugi measurements in the [timing-controlled comparison](TIMING_COMPARISON.md)
are producer insertion to local post-handler materialization. They are not
proposal broadcast to direct commitment. No Delta term is added to the latency
calculation, and the positive ordering path has no unconditional 7Delta wait.
An isolated diagnostic of the unchanged composed protocol reproduces 757.8 ms
with the original transport's ACK gate, versus 50.0 ms without that gate; both
results are identical at Delta=100, 250 and 1,000 ms, with no NO-CER outcomes.
The three implementations use different completion endpoints, so the table does
not establish a protocol-level consensus latency ratio.

## Exact measurement boundaries

| Implementation | Start | End | Clock |
| --- | --- | --- | --- |
| Delugi | One timestamp per producer batch, before transaction construction and signed batch production | Origin processes the completed composed handler's effects, after ordered materialization, decoding, deduplication and deterministic state hashing | Same-process monotonic `Instant` |
| Raptr | Each transaction, after HTTP receipt and batch decoding, just before enqueueing to the internal mempool channel | Origin mempool handles commit notification after consensus retrieves the payload | Same-process monotonic `Instant` |
| Mysticeti | Generator batch timestamp after its pacing tick, before transaction construction/enqueueing | Timestamp captured on entry to the origin's commit handler, **before sub-DAG linearization** and subsequent committed-sub-DAG processing | UTC wall clock; start truncated to milliseconds |

Source anchors:

- Delugi: [`Runtime::load_tick`](../src/process.rs) captures `now_us` before
  constructing transactions and stores it in `load.pending`; `Runtime::effects`
  captures `completed_at` after processing effects and observes
  `completed_at - inserted_at`. [`run_sustained.py`](../scripts/run_sustained.py)
  divides the window's latency-sum increment by its completion-count increment
  and converts microseconds to milliseconds.
- Raptr: [`mempool.rs`](baselines/raptr/aptos-node/src/mempool.rs), API insertion
  around line 464 and commit notification around line 74;
  [`raptr_manager.rs`](baselines/raptr/consensus/src/raptr_manager.rs) retrieves
  payloads before notification around line 1122.
- Mysticeti: [`transactions_generator.rs`](baselines/mysticeti/crates/mysticeti-core/src/transactions_generator.rs)
  stamps generation around line 74;
  [`block_handler.rs`](baselines/mysticeti/crates/mysticeti-core/src/block_handler.rs)
  captures `current_timestamp` around line 436, before calling the commit
  interpreter. The later transaction loop uses that earlier timestamp.
- Both native adapters compute the increment in latency histogram sum divided
  by the increment in count, converting seconds to milliseconds. Neither adds
  a timeout or network-delay parameter.

All three pooled comparison metrics count a transaction once at its originating
replica. Their populations are completions observed inside the measurement
window: transactions inserted before the window can contribute, and transactions
still pending at its end do not. They do not measure client responses or
completion at all replicas. Raptr excludes HTTP transit and decoding; Delugi
includes more work after ordering than Mysticeti. The endpoint mismatch alone
does not quantify or explain the hundreds-of-milliseconds gap.

## Delta is configured, but not charged to every successful round

At Delta=100 ms, Delugi arms a 700 ms main timer and a 300 ms catch-up timer.
These are deadlines, not mandatory phase durations:

- [`Slot::drive`](../src/slot.rs) emits CER as soon as round admission and the
  required VOTE/CER evidence permit it. A CER quorum directly commits immediately.
- [`Replica::settle`](../src/replica.rs) runs positive transitions to a fixed
  point on receive, input and timer events, then handles expiry and scanning.
- [`Scanner`](../src/scanner.rs) releases a resolved prefix without a duration
  gate; [`composed::Node`](../src/composed.rs) materializes released descriptors
  immediately when their payloads are held.

An earlier OPEN outcome can delay the contiguous history prefix and therefore a
later proposal. A timeout can close that gap. Correct replicas alone do not rule
out a timeout if their messages are substantially queued. Conversely, a timer
expiry notice does not prove a timeout on the critical path: timers remain armed
after CER, and expiry can revisit an already-terminal slot without creating
NO-CER. A regression in `src/replica.rs` explicitly has CER at 300 ms with a main
deadline of 1,000 ms.

The six controlled Delugi archives bound the number of local NO-CER outcomes at
only 2–3 per node over roughly 323–330 eligible rounds. Each own CER is broadcast
once to three peers; irreversible NO-CER prevents a later own CER. Therefore
`current_round - 2 - sent_CER_messages / 3` is an upper bound on NO-CER outcomes
among eligible rounds. This rules out fallback in every round, but does not
recover actual CER times relative to deadlines or quantify timer-induced delay.

The manuscript's aligned 3delta theorem starts at complete proposal broadcast
and ends at direct commitment, assuming timely protocol messages and aligned
entry. It excludes input preparation and waiting before the proposal; ordered
release can additionally require an earlier prefix. With unaligned entry, the
corresponding bound is 5delta. Neither theorem says that the measured insertion
to post-materialization endpoint must equal 3delta, nor does it justify a 700 ms
healthy-path wait.

## The injected delay is not the logical message-delivery bound

The original `transport.rs` wrote one frame on each directed peer
stream, waited for and verified its application ACK, then dequeued the next frame.
Ordering messages and dissemination batches share that FIFO. At a 20 ms RTT,
the ideal limit is 50 frames/s per stream even without bandwidth or CPU limits.
A frame behind five complete frame/ACK exchanges can wait about 100 ms before
its own 10 ms transit begins.

The [archived transport audit](results/delugi-transport-audit-2026-10-13.json)
found about 49 acknowledged frames/s on every directed stream in the 40 tx/s
preflight and the first 1,000 tx/s trial. Roughly 10 batch frames/s plus 39
ordering/control frames/s share each stream. Approximately 60 directed control
frames per proposed round across 12 streams leave about 8 rounds/s; observed
round progress was about 7.8/s. This is evidence of a transport service limit,
not a numerical decomposition of each transaction's latency.

Thus a 10 ms kernel delay does not provide a 10 ms bound from logical protocol
send to receive in this implementation. Matching injected delta and configured
Delta is useful, but does not equalize transport queueing, batching or completion
endpoints across native implementations.

## Controlled diagnostic: ACK gating reproduces the latency scale

[`examples/latency_diagnostic.rs`](../examples/latency_diagnostic.rs) runs four
honest instances of the unchanged `composed::Node`, with real signatures,
serialization, validation, ordering and materialization. It advances virtual
time, assigning zero modeled time to local computation. Every producer inserts
one small transaction every 100 ms, giving 40 tx/s. All six cases use delta=10 ms,
a 10-second horizon and origin completions in the window [2 s, 10 s).

The only transport difference is whether each directed peer FIFO must wait a
2delta frame/ACK exchange before sending its next frame. Both layers share that
FIFO. The pipelined case delivers every packet 10 ms after logical enqueue.

| Modeled transport | Insertion to proposal (ms) | Proposal to local direct commit (ms) | Commit to materialization (ms) | Total (ms) |
| --- | ---: | ---: | ---: | ---: |
| Pipelined, no per-frame ACK gate | 20.000 | 30.000 | 0.000 | 50.000 |
| Original per-peer stop-and-wait ACK gate | 420.282 | 337.492 | 0.000 | 757.774 |

Every row is unchanged across Delta=100, 250 and 1,000 ms. The full transaction
completion timelines are identical across the three bounds for each transport,
and all six traces have zero NO-CER transitions. There are 320 measured origin
completions per pipelined case and 319 per stop-and-wait case. Each transaction's
first inclusion proposal equals its eventual execution proposal in this
population; the displayed stages therefore add on the same transactions.
All replicas agree on their common executed prefix.

Stop-and-wait yields a mean logical enqueue-to-receive delay of 126.84 ms and a
maximum of 200 ms across delivered packets, despite 10 ms propagation. Its
queueing alone reproduces the scale of the native 758–799 ms observation without
charging any CPU time or waiting for NO-CER. The pipelined case exhibits the
expected 3delta proposal-to-direct-commit path.

This is a causal intervention within a deterministic model, not a rerun of the
native process benchmarks or an exact decomposition of their measurements.
It does not model cryptographic CPU cost, operating-system scheduling, actual
TCP, bandwidth serialization or the original transaction sizes. No drain follows
the horizon: stop-and-wait retains 28 origin transactions, while pipelined has
completed all 400 generated transactions. Original native runs remain unchanged.
The archive includes every packet, stage and timer event, source snapshots,
binary identity and commands in
[`results/local/latency-diagnostic-20261014/manifest.json`](../results/local/latency-diagnostic-20261014/manifest.json).
The [derived summary](../results/local/latency-diagnostic-20261014/summary.json)
records all six cases and validates stage additivity and invariant completion
timelines across Delta values. The example's three focused tests and the seven
baseline-metric tests passed; source snapshots and binary hashes were verified.

Trace interpretation: `actual_cer_received` counts standalone CER packets;
history/proposal proofs can also contribute CER evidence. Direct-commit times
come from the protocol's actual effect. Catch-up expiry relations compare its
horizon h with commit(h), although expiry visits slots through h. The complete
absence of effective NO-CER and the invariant completion timelines support the
timer-independence finding for these modeled executions.

## Limits of the original evidence and corrected reporting

Sustained mode suppresses proposal, certificate, timer and materialization stage
logs, and compact snapshots omit their timestamp maps. The original results
cannot retrospectively separate insertion-to-proposal, proposal-to-commit,
commit-to-release and release-to-post-handler completion. They also cannot
identify which timer expiries actually created NO-CER. The observed proximity
to 7Delta is not evidence that 7Delta was added or obligatorily awaited.

The current Mysticeti runner now explicitly labels its endpoint as commit-handler
entry before linearization. Reports link this audit. Historical raw manifests,
hashes and numerical results are preserved.

A matched evaluation should report two distinct metrics: local intake to ordered
payload availability, with equivalent processing boundaries across protocols;
and complete proposal/block broadcast to the corresponding consensus decision.
For Delugi, stage traces should also record exact batch identity, timer
arm/deadline/expiry, effective NO-CER, queue wait and post-handler completion.
This is needed before assigning the full native 758–799 ms result to a cause.
