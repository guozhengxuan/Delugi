# Transport pipeline fix — 14 October 2026

This report preserves the transport intervention and its original measurements.
The subsequent [settlement investigation](SETTLEMENT_PROFILING.md) profiles the
remaining admission/delivery backlog and records later implementation results.

The per-frame ACK gate in [`src/transport.rs`](../src/transport.rs) is removed.
Each peer now has a FIFO write window and an independent ACK reader. The default
window holds at most 64 frames and 8 MiB of encoded data. The separate bounded
outbox holds 4,096 frames; at most one dequeued frame is staged while waiting for
byte capacity. A full window applies backpressure, while other peer writers
continue independently.

Signed data frames and signed ACKs are unchanged. ACKs follow authenticated inbox
acceptance, and only a matching authenticated FIFO-head ACK retires a pending
frame. Reconnection replays the exact unacknowledged suffix before admitting new
frames. Closing a connection cancels and joins its ACK reader, preventing stale
connection results from affecting the replacement. Receivers reject sequence
gaps and suppress already-accepted sequence numbers across reconnects. The
oldest fully written frame has a configurable two-second ACK timeout; idle
connections do not expire. Sequence state remains in memory across connections,
not across process restarts.

New counters expose current and maximum retained window frames and bytes.
Existing traffic counters continue to count actual writes, including retries and
partial writes, separately from successful logical acceptance and ACK retirement.

**Outcome at this intervention:** the ACK gate is fixed and the source passes correctness tests.
The sustained-load latency problem remains unresolved. The final 30-second
measurement regressed against the original binary; the short-run improvement
does not persist. This change is not a demonstrated end-to-end performance win.

## Proposal validation exposed by faster delivery

The first native trial after removing the ACK gate passed correctness checks but
regressed under sustained load. With 2 seconds of warmup and a 5-second window at
1,000 offered tx/s, latency increased from 896.554 ms to 1,169.883 ms, and output
fell from 1,020.058 to 705.727 tx/s. The original binary's completion count
temporarily exceeded arrivals by draining a backlog. The pipelined trial's
pending transactions grew from 376 to 1,846. This unsuccessful performance
intervention is retained in the [initial comparison](../results/local/transport-pipeline-comparison-20261014/summary.json).

The window was not full: observed maxima were 12–14 frames per peer, with zero
ACK failures or retries. Admission advanced much faster, exposing two sources
of repeated cryptographic work in [`Replica::propose`](../src/replica.rs):

- Inputs waiting for HISTORY3 were repeatedly cloned and Q-checked on each
  settlement. Readiness now filters them before cloning. Immutable input
  admission and complete proposal verification still check Q.
- Every proposal reverified the complete retained certificate history. Candidate
  selection now supplies only the greatest eligible local certificate round and
  its two exact predecessors, retaining every digest at those rounds. Reports
  remain unchanged, and the existing history builder still validates the
  supplied evidence and assembled history.

This selection preserves history bytes. If L is the greatest eligible local
round and P the eventual pivot, P is at least L. For P=L the relevant local
rounds are L, L−1 and L−2; for P=L+1 or L+2 the needed local predecessors are a
subset; for P>L+2 no local predecessor can contribute. All candidate digests at
those rounds remain available to the builder's canonical encoded-proof choice.
Retained proofs have already passed authentication. No protocol evidence,
signature format, timer constant or history-selection rule changes.

## Accepted-socket busy polling on macOS

Native measurements also exposed an existing receiver bug: macOS inherits the
listener's nonblocking flag on accepted sockets, while `read_frame` expects
blocking reads with timeouts. Idle receiver threads consequently spun on
`WouldBlock`. `configure` now explicitly restores blocking mode before setting
timeouts, for accepted and outbound sockets. Shutdown still interrupts outbound
ACK readers, and accepted readers check cancellation after the bounded I/O wait.

A real TCP regression checks that an empty read waits for its configured timeout,
then successfully receives a byte. Its negative control failed immediately with
the old configuration and passed after the fix. A subsequent repeat found a race
in the test's nonblocking `accept` setup; bounded polling corrected that setup.
The failed verification archive remains alongside the successful final repeat.

## Native before/after results

Each run uses four independent replica processes on the same M4 Pro host,
1,000 offered tx/s, 512-byte serialized transactions, 100 ms ingress cadence,
delta=10 ms per proxy direction and Delta=100 ms. Short runs have 2 seconds of
warmup and 5 seconds of measurement; long runs have 10 and 30 seconds. Latency
uses the same origin insertion to post-handler materialization endpoint in both
binaries, pooling completions inside the measurement window. These are single
trials, not repeated estimates. MB is 1,000,000 bytes.

| Window | Binary | Mean latency (ms) | Completed tx/s | Pending start → end | Replica TCP writes (MB/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| Short | Original ACK gate | 896.554 | 1,020.058 | 900 → 800 | 2.372 |
| Short | Final pipeline + validation + socket fixes | 645.395 | 879.897 | 300 → 900 | 10.363 |
| Long | Original ACK gate | 919.203 | 997.465 | 800 → 875 | 2.364 |
| Long | Final pipeline + validation + socket fixes | 2,418.452 | 929.973 | 1,200 → 3,300 | 8.713 |

The final long run generated 999.971 tx/s. Its p95/p99 histogram upper bounds
were 3,225/3,287 ms, versus 1,043/1,091 ms originally. After generation stopped,
the final run drained in 3.362 seconds versus 0.584 seconds originally. Every
replica then agreed on all generated transactions and the final state hash.
The final finite tests passed honest rounds 1–4 and a silent first leader
followed by honest anchors 2–4, including round-1 skip and matching output.

An owned-process `ps` snapshot at approximately 35 seconds of process age showed
102.8–105.4% CPU per final replica, versus 273–282% originally. This supports the
busy-polling diagnosis, but the remaining approximately one-core load and growing
admitted-versus-delivered round gap still require profiling. Faster admission
and much higher control traffic now coexist with a growing transaction backlog.
In the final long run that round gap grew from 101 to 154–155, while pending
materializations remained zero. The largest retained peer window was only 16
frames / 44,966 bytes, below the 64-frame / 8-MiB limits. Retries, ACK failures,
write failures and duplicate accepts were all zero. Proxy-forwarded byte totals
matched final native read/write totals exactly, and all children and proxy
threads exited. These counters locate a progress backlog without evidence of
window-capacity pressure or missing payload materialization.
The evidence does not identify the exact remaining CPU bottleneck or assign the
latency increase to a particular timer. Protocol timers and metric endpoints were
unchanged.

Raw final runs: [short plus finite scenarios](../results/local/tcp-delay-socket-fixed-short-20261014/manifest.json)
and [long sustained run](../results/local/tcp-delay-socket-fixed-long-20261014/manifest.json).
The [comparison summary](../results/local/transport-pipeline-comparison-20261014/final-summary.json)
preserves the original and every intermediate variant with source/binary hashes.
In particular, pipeline plus validation optimization before the socket fix
measured 669.176 ms short and 2,452.636 ms long; those regressions were retained.

## Validation and reproducibility

The final source passed **156 Rust tests**: 140 default tests and 16 explicit
loopback tests. Eight Python delay-proxy tests also passed. Full command output,
exit status and source hashes are in the
[validation archive](../results/local/transport-pipeline-socket-validation-v2-20261014/manifest.json).

The ten new [transport integration tests](../tests/transport_pipeline.rs) cover
multiple frames arriving before the first ACK, one-ACK window advancement,
separate frame/byte bounds, bounded outbox rejection without consuming a sequence,
exact replay after lost ACKs, timeout recovery on an open socket, forged ACK and
payload rejection, sequence-gap rejection, and shutdown with blocked ACKs or a
full inbox. Three proposal regressions check predicate call counts while waiting
for HISTORY3 and byte-for-byte equivalence with the full-history builder across
gaps, future proofs, raised pivots, unselected reports and competing digests.

The [final release build](../results/local/transport-pipeline-socket-build-v2-20261014/manifest.json)
records source snapshots, compiler identity and the binary hash. The original
benchmark binary and the intermediate binaries are preserved with
their original provenance. No archived measurement was overwritten.

[`scripts/run_tcp_delay.py`](../scripts/run_tcp_delay.py) runs independent real
replica processes behind an opaque TCP byte-stream delay proxy. It delays both
data and ACK directions while continuing to read subsequent chunks, so it does
not impose a frame-by-frame round-trip gate. Control connections bypass the
proxy. Each run records RTT calibration, stream forwarding delays, bytes, queue
capacity waits, process exits and agreement checks. This is a userspace stream
delay experiment; it is distinct from the 13 October kernel-shaped matrix.
