# Latency decomposition and silent-leader diagnosis

The instrumentation follows the stage-accounting approach of Raptr §7.2 / Figure 3
([paper](https://arxiv.org/abs/2504.18649)): distinguish batching, inclusion,
agreement and materialization. Delugi's availability and history work overlap;
they must not be added as if they were consecutive transaction stages.

## Boundaries

Each request is joined to its **exact batch identity**, the ordering round that
first materializes that batch, and the proposal digest released in that round.
Every subtraction uses the request origin's monotonic clock.

| Additive stage | Start → end |
|---|---|
| Batch formation | Request admitted → signed local batch stored |
| Await execution proposal | Batch stored → full local validation of its eventual execution proposal |
| Agreement | Full proposal validation → first final scanner classification |
| Contiguous prefix wait | Classification → ordered descriptor released |
| Payload wait | Descriptor released → every exact named suffix locally available |
| Application append | Payload ready → this transaction's verified contiguous append |

The six arithmetic means use the **same completed, fully instrumented request
cohort** and sum to its mean admission-to-append latency. Scheduled-arrival to
admission is reported separately. The output names the scheduled, completed and
covered populations. Unfinished requests, absent boundaries and nonsequential
observations are counted explicitly; none are substituted with zeros. A missing
local full proposal (for example, an indirect commitment preceding that proposal)
excludes that request from the additive bars, while retaining its cohort result.

These stages deliberately refer to the proposal that actually releases the
batch, rather than an earlier proposal that may also reference it. Forked batch
identities and proposal digests are never joined by height alone. The reducer
rejects mixed-run traces, failed traces, dropped events and changed control pages.

Separate round diagnostics retain admission, REPORT, observation quorum,
construction, input fixation, HISTORY3 report receipt/quorum and encoded bytes,
history assembly, proposal verification/send, VOTE/CER quorum, CLOSED thresholds,
timer arm/expiry, NO-CER, classification, prefix release and payload readiness.
Transport enqueue, authenticated mailbox arrival and dispatch remain distinct.
Wire sizes exclude TCP framing unless the field explicitly says otherwise.
Leader preparation spans overlap request stages and are not added to their bars.
The agreement bar begins after local validation: proposal transit is assigned to
the preceding stage. It is therefore not the paper's full 3δ interval. Separate
leader-local `leader_outbox_to_direct_ms` spans run from logical PROPOSE emission
to the direct CER-quorum decision. HISTORY3 generation, encoded message size and
first-report-to-quorum collection are also reported separately.

## Collection and offline figures

Instrumentation is opt-in, bounded and buffered in memory. No stage performs file
I/O or pauses execution. Control collection runs only after protocol quiescence.
The normal diagnostic defaults are a 64-round detail stride and 100,000-event
cap; critical stage boundaries cover every round. For short investigations use
stride 1 and a suitable explicit cap. A nonzero dropped count invalidates the
decomposition. Instrumented runs require an observer-overhead study before being
used as final performance evidence.

For the standalone local runner, add:

```sh
--causal-trace --trace-stride 1 --trace-max-events 1000000
```

Collected files are `trial/causal-traces/replica-N.json`. The Fabric parameter file
can set the same options under `protocol_options.delugi`:

```json
{
  "report_schedule": "history_ready",
  "causal_trace": {"detail_stride": 1, "max_events": 1000000}
}
```

The existing remote control connection downloads bounded pages; no extra port,
SSH step or manual remote path is needed. The
[28 October four-region rerun](../../benchmarks/results/fabric-wan-30s-2026-10-28/README.md)
verified this collection path for healthy and silent-leader Delugi. Each 30-second,
100 tx/s case covered all 3,000 requests with zero dropped events. The fault case
averaged 4,180 ms admission-to-append, dominated by 3,473 ms awaiting the execution
proposal and 462 ms awaiting contiguous prefix release; agreement averaged 242 ms.
Frozen inputs remained younger than 0.48 ms. Instrumentation overhead remains
unmeasured, so these are causal diagnostics and deployment verification evidence.

Timer-expiry events include callbacks for already-decided rounds. Count `no_cer`
or the associated state transition when diagnosing actual timeout-dependent
progress; a raw expiry count alone does not mean a request waited for that timer.

Once logs are present, from `benchmark/`:

```sh
fab decompose --cohorts=/absolute/trial/cohorts/index.json \
  --traces=/absolute/trial/causal-traces --output=/absolute/figures
```

This command only reads local files and writes JSON/PNG. The standalone reducer
is `scripts/latency_decomposition.py`. Environment-based tracing is retained for
older diagnostic workflows; configured and environment tracing cannot be enabled
together. Only explicitly selected legacy traces may bypass the newer run-ID
binding; their report records that limitation.

## Raptr instrumentation and the shared application boundary

Raptr now records batch storage, verified availability quorum, acceptance of a
locally verified full proposal, native commit slices, payload validation, and contiguous output
release. Enable the bounded recorder through `protocol_options.raptr` (or the
local runner's `--node-options-json`):

```json
{"latency_trace": {"max_events": 100000}}
```

The recorder is disabled when this option is absent. Its `latency-trace.json`
is bound to the run, configuration, replica and monotonic clock, and hashed in
the final signed receipt. The configured cap bounds retained events; any dropped
event invalidates the decomposition. Collection and trace serialization occur
after the observer freezes.

For each originating replica, the Raptr reducer joins the request's **first
credited output** to the exact native batch identity (epoch, author, nonce, batch
ID and digest), full proposal digest, and native proof/sub-block section. Native
prefix extensions have separate commit boundaries: a later section does not
inherit an earlier prefix's commit timestamp.

| Raptr additive stage | Start → end |
|---|---|
| Batch formation | Request admitted → full local batch persisted |
| Dissemination / inclusion | Batch persisted → locally verified execution proposal accepted by the core |
| Consensus | Verified proposal accepted → commit decision for the exact output slice |
| Payload retrieval / validation | Commit decision → exact slice's native payload validated |
| Contiguous output wait | Payload validated → FIFO output section released |
| Output consumer wait | FIFO release → application consumer starts processing |
| Application acceptance | Consumer starts → request identity, eligibility and deduplication accepted |

All seven means use the same completed, fully instrumented request cohort and
sum to its admission-to-application latency. Scheduled-to-admitted delay is
reported separately. Missing boundaries and locally nonsequential observations
are counted as exclusions rather than replaced with zero. Batch storage and
availability are recovered from exact-batch trace events; the legacy nullable
`own_batch_ready_us` field is not repurposed.

Availability-quorum timing is also retained as a separate stored-to-quorum
diagnostic. Raptr can reference a streaming batch before its availability quorum
has formed, so this duration can overlap proposal processing and consensus. The
report states how many covered requests have a local quorum timestamp and how
many quorums occur after the execution proposal. This overlapping duration is
not added to the primary bars.

The optional `serial_quorum_cohort` gives a separate eight-stage decomposition
for exactly those covered requests whose observed timestamps satisfy
`stored <= availability quorum <= proposal`. It splits dissemination/inclusion
into stored-to-quorum and quorum-to-proposal, and reports its own coverage,
exclusions and same-cohort means. This observed ordering does not imply that the
protocol waits for a quorum before proposing a streaming batch. Requests with
late or absent quorum timestamps retain their primary seven-stage decomposition.
Add `--serial-quorum-figure /absolute/figures/raptr-serial-quorum.png` only when
that subset is nonempty to render this alternative breakdown.

For a cross-protocol overview, the report additionally groups the seven means
into batch formation, dissemination/inclusion, consensus, and output processing.
Delugi's corresponding first three stages are batch formation, awaiting the
execution proposal, and agreement; its prefix/payload/application stages form
output processing. Raw payload and prefix stages remain protocol-specific:
Delugi releases an ordered descriptor before materializing its payload, whereas
Raptr's application adapter validates payloads before releasing its FIFO section.
Raptr's proposal acceptance timestamp follows full network verification and any
verified-inbox queue delay. That queue delay belongs to dissemination/inclusion;
the consensus bar does not begin at the network verifier's return.

The Raptr application endpoint is now versioned as
`verified_contiguous_application_acceptance_v2`. It occurs inside the serialized
application consumer, after native payload validation and application
identity/eligibility/deduplication checks, and **before diagnostic BCS/JSON journal
construction**. Consumer queue delay and workload-mutex wait remain included.
This matches Delugi's semantic boundary: a verified, contiguous application
output accepted before its diagnostic journal is constructed. Both are
consensus-only synthetic workloads, not VM execution measurements.

Each Raptr output section retains `app_processing_start_us`, `append_us`, and
`journal_constructed_us`. The last minus the middle is reported separately as
observer construction overhead; it is not added to end-to-end latency. A section
accepted before the deadline can finish constructing its journal after the
deadline. Publication or envelope failure invalidates the run. The new
`timing_contract` on each output section and `output_endpoint` in the effective
profile prevent old and new endpoints from being silently mixed.

Older archives retain their original endpoint after journal construction. In
particular, the 28 October WAN logs cannot acquire the new stages retroactively;
their [offline partial decomposition](../../benchmarks/results/raptr-offline-decomposition-2026-10-29/README.md)
remains unchanged.

The [29 October local validation](../../benchmarks/results/raptr-timestamps-local-2026-10-29/README.md)
completed healthy and silent-leader runs for both protocols with full 500-request
coverage in every run. Fabric also supports this offline path:

```sh
fab decompose --protocol=raptr --config=/absolute/trial/config.json \
  --replicas=/absolute/trial/replicas --verification=/absolute/trial/manifest.json \
  --output=/absolute/figures
```

For downloaded remote archives, `--verification` can name their completed
`result.json`. Collection includes the signed `latency-trace.json` whenever
Raptr's `node.protocol_options.raptr.latency_trace` is configured. No deployment
or protocol run is triggered by decomposition.

After the native archive verifier has succeeded, the local-only reducer accepts
its saved result or manifest and rechecks all receipt/file hash bindings:

```sh
python3 scripts/raptr_latency_decomposition.py \
  --config /absolute/trial/config.json \
  --replicas /absolute/trial/replicas \
  --verification /absolute/trial/manifest.json \
  --output /absolute/figures/raptr-decomposition.json \
  --figure /absolute/figures/raptr-decomposition.png
```

The reducer does not launch replicas or reverify native signatures. It checks
the previously verified receipt hashes, exact signed source files, endpoint
version, trace completeness, request/output endpoint agreement and additive
stage accounting. Raw local tests validate those boundaries; observer overhead
and matched fault placement still need to be measured for a formal comparison.

## Composition scheduling correction

The old composition issued REPORT at round admission. PROG pacing can admit
rounds while a preceding silent leader still awaits its 7Δ main timer. REPORT
froze observations and the immutable input early; when HISTORY3 eventually enabled
the proposal, that proposal still referenced the old input. Repeating this
schedule made input age and transaction backlog grow, even when agreement itself
remained fast.

The default `history_ready` schedule opens the one REPORT only when the leader is
admitted **and** has an authenticated quorum at the exact required history horizon.
Either admission or the history-quorum event can wake preparation. The first three
rounds need no HISTORY3. Already fixed inputs are never refreshed. An explicit
`admission` setting retains the old behavior for comparisons.

This is a **composition schedule revision** to the pinned paper's entry-triggered
REPORT, recorded in run provenance. The paper snapshot is preserved. Ordering's
PROG/VOTE/CER/CLOSED/HISTORY3 guards, immutable Q, timer durations and scanner rules
are unchanged; the revision does not establish the canonical paper's timing claim.

The fault hook silences replica 0 for the entire run. In a four-replica round-robin
committee, rounds 1, 5, 9, … therefore have silent leaders. The repeated 7Δ waits
and the resulting admission-versus-delivery round gap remain observable. The
correction prevents stale payload snapshots from adding an accumulating delay;
it does not replace those protocol timers with an artificial fast skip.
