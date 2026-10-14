# Admission and delivery profiling — 14 October 2026

The current transport continuously pipelines queued frames while earlier ACKs
are outstanding. No ACK-window limit bound any of the six final sustained
trials. Repeated validation and retained-history work have been removed without
changing protocol rules. Final median mean latency is 199.403 ms at 1,000 offered
tx/s and 422.869 ms at 4,000 offered tx/s. The remaining admission/delivery gap
still grows, so these results do not establish steady-state latency. The
[compact verified results](results/admission-profile-2026-10-14.json) retain every
repeat, exact binaries, source hashes, measurement boundaries and raw archives.

This investigation follows the [transport pipeline fix](TRANSPORT_PIPELINE.md).
The socket-corrected pipelined binary sustained 929.973 completed tx/s at 1,000
offered tx/s, with 2,418.452 ms mean insertion-to-materialization latency over a
30-second measurement after 10 seconds of warmup. Pending transactions grew
from 1,200 to 3,300, and the admission/delivery round gap grew from 101 to 154–155.
The transport window remained below capacity and pending materialization was zero.

## Profile and implementation changes

A separate instrumented trial sampled one owned replica for five seconds at
approximately 20 seconds of process age. The release binary was the exact
preserved pre-optimization binary. Of 3,845 main-thread samples, 74.5% included
`Replica::settle`, 34.9% were attributed directly to it, 9.2% included
`scanner::scan`, and 20.9% included signature verification. Inclusive percentages
overlap. Repeated tree traversal, insertion and allocation were also prominent.
The [profile archive](../results/local/admission-profile-before-20261014/summary.json)
records raw symbolized stacks, parser checks, profiler commands and binary hashes.
Its instrumented latency is excluded from performance comparisons.

The implementation repeatedly swept retained history on each message and each
fixed-point pass. That made work per event grow with execution length. Enabled
messages also waited for the synchronous handler to return. The changes address
that work without adding delays or changing protocol prerequisites:

- Slots are retried when new evidence, full validation or a relevant admission
  change can enable an action. Terminal slots remain retained and can still vote
  or directly commit when their guards permit it.
- PROG processing excludes earlier rounds whose sends and admissions are already
  complete. Proposal readiness tracks only inputs whose proposals remain unsent.
- HISTORY3 construction resumes after the immutable, contiguous own-report
  prefix. Every new exact report still precedes its CLOSED broadcast.
- Timer readiness and deadlines are indexed. Main and catch-up timers retain
  their original once flags, deadlines and notices, including arms on terminal
  rounds. Due events are processed in the original round order, with main
  expiries before catch-up. Expired catch-up timers preserve their deadlines
  while waiting for admission. After positive transitions reach a fixed point,
  finishing an already-terminal slot has no effect and is skipped.
- The scanner reuses a result only when admission and the lengths of the
  insert-only, immutable direct-commit/header/value maps are unchanged. Any new
  attachment invalidates reuse. Changed snapshots still run the original full
  backward scanner and monotonicity checks.
- Base selection clones only the first eligible certificate from the unchanged
  descending candidate order. Availability construction verifies a fixed base
  once before checking its observations and again with the assembled input,
  avoiding three redundant base checks for four replicas. Public validators and
  complete proposal verification remain in place.

Only `src/replica.rs` and `src/availability.rs` changed relative to the prior
native binary in this first optimization. Protocol wire formats, timer constants, input-freezing rules,
availability selection, exact-batch deduplication, transaction generation and
measurement endpoints remain unchanged. Both canonical specification hashes
still match [the 13 October pin](../provenance/spec-2026-10-13.json).

## Verification

The [full validation archive](../results/local/admission-optimization-validation-20261014/manifest.json)
passed 166 Rust tests: 147 default tests, 16 explicit localhost TCP tests and
three deterministic latency-diagnostic tests. Eight Python delay-proxy tests
also passed. Test-only legacy sweep helpers compare exact signed message bytes,
effect order, timer events, retained maps, slot states and delivery on every
replayed event. Coverage includes Byzantine forks, future evidence, admission
jumps, expired-but-unadmitted catch-up, late header/value attachments, late direct
commitment after NO-CER, and timer deadline order differing from round order.

A paired four-replica replay covers reordered and duplicate traffic through
round 10, including an initial silent leader. A 96-round structural regression
confirms that ticks and duplicate evidence perform no repeated work on completed
slots, reports, timer arms/expiries or scanner state. Availability tests compare
signed observations and constructed input bytes, and preserve rejection of
malformed bases, signatures, bindings and prefix proofs. Independent review
found no blocking issue.

## Indexed settlement result

The first unprofiled rerun did not resolve sustained backlog. At 1,000 offered
tx/s it completed 893.344 tx/s with 2,886.836 ms mean latency. Pending
transactions grew from 1,200 to 4,400; the admitted-minus-delivered round gap
grew from 110–111 to 372. Pending materialization remained zero. The maximum
peer window was only 16 frames / 46,408 bytes, with no ACK failures, retries or
write failures. All four replicas subsequently drained and agreed on 39,900
transactions. Successful correctness checks do not make this a performance pass.
The [unprofiled archive](../results/local/admission-optimized-first-20261014/summary.json)
retains the binary, source hashes, calibration and original observations.

A [separate profile](../results/local/admission-profile-after-20261014/summary.json)
confirmed that indexed settlement removed the repeated scan cost: `settle`
fell to 16.8% inclusive and 0.055% self time; scanner self time was 1.15%.
Per-replica CPU was approximately 45%, down from approximately 104% before
indexing. Sleeping accounted for 57% of main-thread samples, and strict
signature verification accounted for 23.1% of all samples—over half of the
remaining awake samples. This identifies a serial dependency cost despite
spare CPU; it does not establish that the network or input queues are stable.

PROG admission is independent of proposal delivery. The three-round history
chain requires proposal validation, votes, an own outcome and exact HISTORY3
reports. Repeated verification of the same signed evidence occurs along that
chain. Inputs freeze at admission, so any sustained difference between the two
rates increases the age of the input when its proposal is eventually delivered.
Changing admission guards or refreshing observations would change protocol
semantics and is excluded from this investigation.

## Exact signature reuse

`src/wire.rs` now shares a bounded cache across committee clones. Its key contains
the actual public-key bytes, signer, domain, complete canonical signing preimage
and exact signature bytes. Equality compares all these bytes. The first check
uses Ed25519 `verify_strict`; only success is inserted. Every context, shape,
leader, history, quorum, binding, availability and Q check still executes.
Signing does not seed the cache. Public-key mutation on a cloned committee
cannot reuse a result for the former key.

The cache evicts in FIFO order and retains at most 4,096 entries and 4 MiB of
key bytes. Both indexes share each key allocation; index metadata has the entry
bound and is not included in the key-byte cap. Cryptography runs outside the
mutex. Concurrent misses may verify twice but insert once. A poisoned lock
falls back to strict verification, and oversized entries bypass storage.

The [cache validation archive](../results/local/admission-cache-validation-20261014/manifest.json)
passed 175 Rust tests (156 default, 16 explicit localhost TCP and three latency
diagnostics) plus eight Python delay-proxy tests. Nine added regressions compare
cached and original verification over valid and adversarial inputs, exercise
all cache bounds and concurrency/failure paths, and prove that a warmed signature
cannot bypass semantic checks. Independent review found no blocking issue.

The [first unprofiled cache trial](../results/local/admission-cache-first-20261014/summary.json)
improved to 966.673 completed tx/s and 826.278 ms mean latency. However, pending
transactions grew from 300 to 1,300, and the admission/delivery gap grew from
33–34 to 115 rounds. Over 30 seconds, admission advanced 2,629 rounds while
delivery advanced 2,547–2,548 rounds. Per-replica CPU at approximately 35 seconds
was 38.9–39.9%. Pending materialization remained zero and there were no transport
retries or errors. All replicas drained in 1.090 seconds and agreed on 39,900
transactions. This optimization improves the critical path but does not yet
resolve its sustained rate difference. The additional repetition/load matrix
was stopped pending a causal timing trace.

A [separate cache CPU profile](../results/local/admission-profile-cache-20261014/summary.json)
used the preserved measured binary and original source snapshot, independent of
subsequent diagnostic edits. Of 3,679 main-thread samples, 74.9% were sleeping,
6.4% included signature verification, 7.8% included settlement and 3.9% included
scanner/release. The cache reduced cryptographic work; the remaining rate
difference persists while CPU is available. Instrumented throughput/latency
are excluded from the unprofiled results.

## Causal timing

An opt-in recorder (`DELUGI_CAUSAL_TRACE_DIR=/absolute/path`) now captures
monotonic readiness and message timestamps in memory and writes one JSON file
per replica at shutdown. It is absent by default. Core events cover every round;
detailed spans cover eight consecutive rounds per 64-round bucket. Each replica
has a 100,000-event cap and an explicit dropped count. The instrumented run
retained approximately 86,800 events per replica with zero dropped events.
Trace-on/off comparisons preserve exact effects and state. The
[instrumentation validation](../results/local/admission-causal-validation-20261014/manifest.json)
passed 178 Rust and eight Python tests.

The [causal timing archive](../results/local/admission-causal-trace-20261014/summary.json)
shows that HISTORY3 quorum was the last prerequisite for all 2,534 measured
proposals. Mean fixed-input age at proposal readiness grew from 523.4 ms to
870.3 ms to 1,261.5 ms across the successive ten-second measurement intervals.
Once history was available, readiness took 4.2 microseconds and proposal
assembly took 0.562 ms. The local three-round CER dependency chain averaged
35.731 ms, while admission advanced three rounds in 34.245 ms. That repeated
rate difference explains the growing age of frozen inputs.

All 14,196 main-timer expiries followed their local CER, by approximately
676.7 ms on average. All 14,316 catch-up expiries followed the observed local
positive outcomes in their horizon prefix. There were no NO-CER events. These timer
notifications do not add a 7-Delta wait to the measured healthy path.

Scanner/release spans grew from approximately 0.117 ms in the 1,000-round
bucket to 0.198 ms in the 2,000-round bucket and 0.260 ms in the 3,000-round
bucket. Authenticated HISTORY3 messages waited 1.358 ms on average for main-loop
dispatch. Locally ready PROPOSE messages waited 0.524 ms before transport enqueue
began; HISTORY3 messages waited 0.105 ms. These are within-replica durations.
Nested spans are not added as separate CPU costs, and enqueue is not a socket
write or remote delivery. Instrumented results are diagnostic, not performance
replicates.

## Unfinished suffix and event-driven wakeup

Classification now recomputes only rounds after the delivery cursor. Each
classification depends exclusively on later rounds, so the suffix is exactly
the suffix of a full descending scan. Passed Commit/Skip statuses remain stored.
Every new direct commitment is checked against any previous final status, and
every previously final status in the live suffix is compared with the new scan.
With increasing horizons and immutable retained evidence, a changed passed
classification would require a changed later final authority; following that
dependency upward ends at a conflicting direct commitment, which is rejected.
Local NO-CER remains distinct from final scanner Skip: a later direct commitment
after a local NO-CER is still allowed by the original rules.

The public full scanner remains available. An independent frozen scanner oracle
compares every suffix cut over 128 direct-commit masks, three malformed/attachment
snapshots and four horizons. Regression cases cover conflicting late evidence,
matching late direct commitment without redelivery, live-suffix conflicts and
the paired honest/silent-leader replays. A structural work check visits four
live rounds after a 96-round passed prefix, versus 100 rounds in the original.

An eligible idle process now waits up to one millisecond on its transport inbox
instead of sleeping unconditionally. An arriving packet wakes it and is kept
for the next ordinary turn, after the control-request check. The turn still
processes at most one message before checking timers and generation. Pre-start
packets remain in the transport mailbox, timeout does not add a second sleep,
and disconnection retains the sleep fallback to prevent spinning. Protocol
timer constants and guards are unchanged.

The [full validation archive](../results/local/admission-wakeup-validation-20261014/manifest.json)
passed 185 Rust tests and eight Python delay-proxy tests. Independent reviews
approved both changes. Final performance runs explicitly remove both causal
trace environment variables.

The [first unprofiled suffix/wakeup trial](../results/local/admission-wakeup-first-20261014/summary.json)
completed 970.012 tx/s with 727.718 ms mean latency. Pending transactions still
grew from 300 to 1,200. Admission advanced 2,784 rounds while delivery advanced
2,698; the gap grew from 32 to 118. There were no transport errors and all
39,900 transactions agreed after draining. Removing historical scan work and
idle polling therefore improved processing but did not close the rate gap.

## Reuse of completed local validation

A locally constructed proposal now carries a private validation token through
the existing self-delivery FIFO. Construction still performs complete proposal
verification. When that exact owned proposal reaches self-ingestion, it enters
the same retained-state updates without repeating the completed verification.
Raw messages, including a public echo of the local proposal, still take the full
validator. No message is ingested earlier and no send changes position.

Local construction also reuses the successful Q result only for the exact
round, value and witness already admitted into private immutable input storage.
Any mismatch invokes Q normally. Header, history, signature and hash bindings
remain checked. History construction no longer rechecks report attachments
that the same call has just successfully verified; local candidate proofs and
the assembled history retain their checks and canonical selection order.

The [validation archive](../results/local/admission-validation-reuse-validation-20261014/manifest.json)
passed 189 Rust tests (170 default, 16 explicit localhost TCP, three latency
diagnostics) and eight Python delay-proxy tests. Replays compare exact effects
and retained state with the original path. Adversarial tests preserve rejection
of mismatched inputs and invalid history even when local Q can be reused.

The [30-second trial](../results/local/admission-reuse-first-20261014/summary.json)
completed 993.320 tx/s with 140.400 ms mean latency. Pending transactions grew
from zero to 200 and the admission/delivery gap from 8–9 to 18 rounds. A separate
[60-second growth check](../results/local/admission-reuse-growth-20261014/summary.json)
completed 996.670 tx/s with 145.194 ms mean latency; pending transactions again
grew from zero to 200 and the gap from 6–7 to 22 rounds. The six ten-second
measurement epochs increased from approximately 86.7 to 214.9 ms. These runs
substantially reduce the delay but retain a small rate difference. They do not
establish bounded latency over indefinite execution. All replicas drained and
agreed on all 39,900 and 69,900 transactions respectively.

## What the ACK evidence establishes

The former frame → ACK → next-frame transport was a real serialization bug.
The current writer admits and writes fresh frames while earlier ACKs remain
outstanding. An independent TCP regression withholds all ACKs and observes three
frames arriving, then confirms that one released ACK opens one slot in the
deliberately three-frame test window. Production limits are 64 frames and 8 MiB
per peer. ACKs retire retry storage; they are not consensus votes or certificates.

The 727.718 ms suffix/wakeup run and the 140.400 ms validation-reuse run have
[byte-identical transport source](../results/local/admission-reuse-first-20261014/transport-comparison.json).
Only `src/replica.rs` and `src/history.rs` differ in their native source snapshots.
The former run's maximum peer window was 17 frames / 45,864 bytes, below both
limits even allowing the largest possible next frame. High-water counters update
on every insertion, so a full window between snapshots would be recorded.
All twelve directed links established once and had zero retries, ACK failures,
write failures or connection failures. Thus the per-frame ACK gate and the
bounded ACK window do not explain that post-fix 728 ms measurement.

ACK signing/verification, receiver ACK writes and TCP backpressure still have
processing costs. Existing counters do not measure their durations. This audit
does not claim those costs are zero or assign the entire original kernel-shaped
700-plus-ms result to one cause. The original kernel-shaped experiment used the
old transport and is a different preserved experiment.

## Remaining retained-pool and serialization work

Composition now indexes unfinished frozen observation pools. A pool enters the
index at the same exact quorum that freezes it and leaves only after successful
ordering input supply, at the original completion-record insertion point.
Retries retain an ascending entry snapshot. Construction or supply errors leave
unfinished pools available; recursive admission/report processing sees the same
new pools in the same order. Completed pools and observations remain retained.
The public `input_ready` map is completion telemetry, not a supported control
for deleting completed inputs to force reconstruction.

Legacy-selector comparisons cover frozen observations, late and malformed
duplicates, construction failures after partial success, supply failures, nested
admission/report retries and exact effects/state. Four retries after 64 completed
pools visit zero candidates instead of 256. Adding one unfinished pool visits
one candidate instead of 65. These tests establish removed growing work rather
than predicting a particular latency improvement.

Size-only guards now use the same bounded first pass that pinned Bincode 1.3.3
already performs before allocating and writing a byte vector. This avoids the
discarded second pass. The helper is private to the crate and used only with
deterministic derived wire structures. A borrowed ordering-message layout keeps
the exact outer discriminator and avoids cloning complete proposals/reports
just to size them. Canonical hashing, signing, proof selection and transmitted
bytes still use the original encoder. Combined value/witness limits and the
original order of rejection remain unchanged.

Differential tests compare actual encoded bytes, sizes and errors for all
ordering variants and availability structures. They cover below, at and above
the 1 MiB outer limit, deeply nested oversized components, and combined input
budgets. The full validation and final native measurements below include these
changes along with the earlier optimizations.

The [final validation archive](../results/local/admission-final-validation-20261014/manifest.json)
passed 200 Rust tests: 181 default tests, 16 explicit localhost TCP tests and
three deterministic latency diagnostics. Eight Python delay-proxy tests passed.
The source hashes were unchanged throughout validation. Independent reviews
approved the indexed composition and bounded sizing changes, and whitespace
checks passed.

## Final repeated native measurements

All six repetitions use the same preserved binary
`c2140aaddeefa8122f35e8360e12918c3d51b13e3292df6eea1a8f2575586b6c`,
with causal tracing disabled. Each has ten seconds of warmup and thirty seconds
of measurement. No valid overloaded observation was discarded or replaced.
Independent auditing reproduced the metric arithmetic from native boundary
snapshots and verified identical settings and twenty native input-file hashes.

| Offered tx/s | Completed tx/s, median (range) | Mean latency, median (range), ms | Replica TCP writes, median MB/s | Pending increase per trial |
| ---: | ---: | ---: | ---: | --- |
| 1,000 | 996.664 (993.323–996.667) | 199.403 (190.439–204.932) | 11.554 | 100, 200, 100 |
| 4,000 | 3,933.384 (3,933.253–3,946.613) | 422.869 (334.076–471.182) | 16.367 | 2,001, 1,999, 1,601 |

Actual median generation was 999.998 and 3,999.980 tx/s respectively. The
per-trial p95 histogram upper bounds ranged from 256–299 ms at 1,000 tx/s and
515–708 ms at 4,000 tx/s; p99 bounds ranged from 276–324 and 543–743 ms.
These are per-trial quantiles, not quantiles of a pooled population. Completion
and generation `target_met` flags mean at least 95% of offered rate in the
runner; they do not assert exact load matching or stable queues.

Admission-minus-delivery gaps grew by 12–18 rounds at 1,000 tx/s and 36–48 rounds
at 4,000 tx/s. Pending materialization was zero at all window boundaries. Every
replica drained completely and agreed on all generated output, but backlog grew
in every window. The largest peer window over all six trials was 17 frames /
85,800 bytes. All 72 directed-peer records had one established connection and
zero retries, ACK failures, write failures, duplicate frames or partial writes.
Proxy queue-capacity waits were zero. Native final read/write totals agreed.

The additional [60-second growth trial](../results/local/admission-final-growth-20261014/summary.json)
at 1,000 tx/s measured 996.668 completed tx/s and 194.386 ms mean latency.
Pending transactions grew from 100 to 300; the round gap grew from 9 to 33–34.
Admission advanced 5,444–5,445 rounds while delivery advanced 5,420. Successive
approximately ten-second measurement epochs averaged 107, 115, 161, 213, 255 and
323 ms. Epoch cuts use the existing half-second control snapshots; exact window
boundaries use embedded native timestamps. This increasing age rules out calling
the observed finite windows steady state. It does not prove inevitable unbounded
growth or isolate the remaining processing cost.

The same binary passed independent-process honest rounds 1–4 with 32 identical
transactions at every replica. With replica 0 silent, all three correct replicas
skipped round 1, delivered honest anchors 2–4 and agreed on 24 transactions.
The latter round-4 history has horizon 1, pivot 0 and reporters 1–3, without a
CER proof for the silent round. All owned processes and proxies exited cleanly.

## Final causal and CPU check

A [separate instrumented trial](../results/local/admission-final-causal-profile-20261014/manifest.json)
uses the same frozen binary at 4,000 offered tx/s, with ten seconds of warmup
and thirty seconds of measurement. It records 89,451–89,487 events per replica
with zero drops and samples one owned replica for five seconds at approximately
twenty seconds of process age. Instrumented throughput and latency are excluded
from the repeated results above.

HISTORY3 quorum was the last prerequisite for all 2,718 measured proposals.
Fixed-input age at readiness averaged 177, 294 and 412 ms over the successive
measurement epochs. Once the quorum arrived, readiness took about 3.5
microseconds. Scanner spans were approximately 5–6.6 microseconds. All 10,872
CER actions in the measurement window followed vote quorum; the threshold-to-action interval
averaged 9.8 microseconds. No NO-CER event occurred.

The [matched phase analysis](../results/local/admission-final-causal-profile-20261014/supplement-summary.json)
compares admission and CER spacing for the same two rounds at the same replica.
Across 10,872 r−3→r pairs, CER spacing averaged 33.1198 ms and admission spacing
32.7691 ms, an excess of 0.35067 ms per three-round relation. Every relation
satisfies the identity between that spacing difference and the increase in
CER age relative to admission. All four replicas' gaps grew from 16 to 44:
admission advanced 2,746 rounds and delivery 2,718. This directly measures the
remaining accumulated phase difference without subtracting clocks across replicas
or comparing unmatched populations.

The main-thread sample contained 3,924 samples, of which 78.4% were blocked on
the timed input receive. Signature verification appeared in 32.8% of the other
samples and hashing in 22.6%; these are overlapping inclusive stack percentages.
Writers spent approximately 98% of their sampled stacks waiting for queued
messages, ACK readers almost all their samples waiting for socket input, and
data receivers approximately 97–98% waiting for socket input. Thread roles are
inferred from their stacks; these percentages are stack occupancy, not CPU
utilization. Blocking in the independent ACK reader does not block the writer.
The sample provides no evidence of socket-write backpressure, and the recorded
17-frame / 83,510-byte maximum excludes ACK-window saturation in this trial.

The remaining measured delay is age accumulated along the HISTORY3/CER
dependency chain relative to independent admission. There is no measured
hundreds-of-milliseconds ready-action delay, hidden healthy-path 7-Delta wait,
or active per-frame ACK gate. The evidence does not prove that future drift is
inevitable, nor establish steady-state latency after these implementation fixes.

## Measurement method

Unprofiled runs use four independent replica processes, delta=10 ms added in
each userspace TCP-proxy direction, Delta=100 ms, 512-byte serialized transactions
and 100 ms ingress cadence. The normal sustained window has 10 seconds of warmup
and 30 seconds of measurement. Latency is origin insertion before batch
production to post-handler materialization, for completions inside the window.
Throughput counts unique origin completions; traffic counts successful replica
TCP stream writes, including signed frames and ACKs. Proxy writes are not counted
again. MB means 1,000,000 bytes.

The requested 10 ms is a minimum userspace chunk residence. Across the six
repetitions, whole-trial chunk-count-weighted mean residence was 10.189–10.276 ms,
the worst individual chunk took 29.541 ms, and calibration measured
22.393–22.482 ms of added round-trip delay. These local proxy results remain
separate from the 13 October kernel-shaped Raptr/Mysticeti comparison. No new
counterpart results or cross-protocol latency ranking are inferred here.

The byte-stream proxy and measurement scripts are unchanged. Actual scheduling
delays and RTT calibration are recorded. These runs are distinct from the
13 October kernel-shaped three-protocol matrix.
