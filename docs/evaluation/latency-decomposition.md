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
SSH step or manual remote path is needed. This wiring is implemented and tested
locally; no new cloud deployment was performed for this change.

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
