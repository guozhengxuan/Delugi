# Verification of the snapshot-phase explanation without remote deployments

The extra half-delta effect is reproduced by the **unchanged signed Delugi core**
under homogeneous links. For the WAN, a richer snapshot/eligibility model is
needed: using the saved RTT matrix, the same core produces **330.97 ms** from
batch broadcast to the locally accepted execution-associated proposal, compared
with **336.51 ms** in the saved WAN run. Earlier excluded inputs overwhelmingly
lack two covering observations. This is strong evidence for the proposed
mechanism, but does not identify the causal allocation of every millisecond in
the two independent WAN runs.

No remote machines were provisioned or benchmarks rerun remotely. Production
protocol source is unchanged. Added files are an isolated diagnostic test,
local runners/analyzers, and this evidence report.

## What the existing WAN logs prove

Both healthy cohorts revalidate at 3,000 requests with zero exclusions.
Delugi's admission-to-execution-associated-proposal acceptance is 337.109 ms;
Raptr's is 265.213 ms. The observed difference is 71.896 ms, including batching.

We bounded how much choosing the execution-associated proposal could overstate
Delugi's time to **first locally accepted inclusion**. For each batch executed
in round R, every prior round is confirmed Commit, with a matching digest and
completed FIFO materialization before that batch. Thus an earlier accepted
proposal containing it could only be an overlapping higher-numbered round.
Treating every such possible proposal as containing the batch gives the most
generous correction compatible with the logs, without needing their missing
contents.

| Saved-log result | Mean ms |
|---|---:|
| Delugi admission → execution-associated proposal acceptance |337.109|
| Maximum possible correction to first local inclusion |23.139|
| **Delugi admission → first local inclusion, lower bound** |**313.970**|
| Raptr admission → first local inclusion, reconstructed exactly |265.213|
| **Remaining Delugi–Raptr gap, lower bound** |**48.757**|

Raptr's full-prefix outputs retain membership even for deduplicated batches.
All earlier locally accepted proposals have complete retained membership; the
few uncovered terminal proposals occur after every cohort-associated proposal.
This proves that its execution-associated and first-local-inclusion midpoints
coincide for all 3,000 healthy requests. The general partial-prefix caveat does
not apply to this particular cohort.

These are local acceptance bounds, **not cross-host first-emission timestamps**.
Proposal propagation remains in the measured interval. Reproducers and evidence:
[saved-WAN bound](midpoint-bound.json), [method](offline-method.md),
[Raptr membership](raptr-membership.json), [Raptr method](raptr-method.md).

The WAN's observation opportunities are unevenly spaced. Halving their mean
interval predicts 49.423 ms residual waiting, while integrating uniform arrivals
over their actual schedule predicts 79.886 ms. Measured batch seal→next own OBS
is 80.370 ms. Thus a regular-spacing δ/2 calculation misses approximately 31 ms
even for this checkpoint. An origin's own OBS need not be a required pool
witness, so this diagnostic cannot be added directly to the causal gap.
See [phase statistics](observation-phase.json).

## Test against the actual signed core

[phase_eligibility.rs](../../../core/delugi/tests/phase_eligibility.rs) executes
the existing Node state machines with deterministic virtual network times.
Messages are signed, serialized, decoded and checked; emitted proposals pass
the real signature, history and Q predicates. Only CPU, storage and transport
queue time are omitted from the virtual clock. Observers inspect the real
first-three pool and the leader's store at input construction. Reconstructing
the input from that snapshot must reproduce the exact emitted value/proof bytes.

With δ=10 ms, 160 tagged batches cover ten arrival phases, four origins and four
leader rotations. Their average broadcast→first proposal is **25.000 ms**,
and broadcast→output is 55.000 ms. All 320 examined earlier batch/input pairs
lack two covering observations. No eligible batch is omitted. This confirms
the conditional 2.5δ mechanism in implementation, beyond the earlier abstract
timing model. Raptr's 2δ remains its paper-style transmission-plus-inclusion
calculation; we did not run a new Raptr latency experiment here.

For the WAN approximation, link delays are half the average of the two saved
directional median RTTs. This explicitly assumes symmetry; these are not
measured one-way protocol delays. The model uses chunk capacity 64, Δ = 1,000 ms,
canonical ordering and pipeline reporting, with 100 aggregate transactions/s
staggered across origins at 0/10/20/30 ms. It has 2 s of empty protocol startup,
10 s of input and 6 s of drain. Each transaction is already in its own batch;
there is no batching delay or storage/CPU cost in these numbers.

| Interval, mean ms | Saved WAN Delugi | Signed-core WAN approximation |
|---|---:|---:|
| Batch seal/broadcast → execution-associated local acceptance |336.507|330.968|
| Batch seal/broadcast → verified output |510.432|502.523|
| Batch broadcast → first proposal emission |Unavailable|285.105|
| Batch broadcast → first local inclusion acceptance |Bounded only|309.599|

The close means are a prediction check using measured RTT inputs, not a replay
of the actual message schedule or a fitted estimate of δ. Startup, batching,
CPU, asymmetric links and remote start offsets differ. Agreement on these
means alone would not prove the mechanism; the actual pool contents add the
causal evidence:

- **2,127** earlier batch/input pairs lack two covering OBS.
- **3** have enough covering observations but lack usable source/proof state.
- **0** are eligible at the construction snapshot but omitted.
- Singapore first-executes zero batches but is the **first proposer for 172**.
  Thus earlier inclusion and later execution association genuinely differ in
  this reproduction; the mean midpoint reassignment is 21.369 ms.

These counts are batch–opportunity pairs, not distinct requests or milliseconds
of delay. The source state used in each check precedes any later workload or
network event. Mention of a batch in a witness alone never counts as proposal
inclusion; the selected descriptor must cover it.

Sensitivity checks retain the same core rules:

| Local virtual-time case | First emission | First local acceptance | Execution-associated acceptance | Output |
|---|---:|---:|---:|---:|
| Saved-RTT symmetric approximation |285.105|309.599|330.968|502.523|
| Whole arrival schedule shifted 5 ms |285.599|310.005|331.383|502.971|
| All link delays halved |142.875|155.026|165.760|251.580|
| Physical regions reversed along leader cycle |265.532|284.030|325.003|502.481|

The effect persists across arrival phase, scales with network delay and changes
with the location of leaders. A single extra 0.5δ is therefore an inadequate
numerical description of this WAN behavior.

A separate read-only counterfactual keeps actual proposal times and actual
construction snapshots but removes the OBS support requirement from eligibility.
It advances first proposal by 163.069 ms on average in the main approximation.
That measures dependence on the evidence gate in this fixed schedule. It is
**not a valid changed Delugi protocol, an achievable speedup, or a Raptr
performance prediction**; it must not be assigned to the observed 71.896 ms gap.

[Core summaries and examples](core-summary.json), [method](core-method.md), and
[build/source record](core-build-record.json) bind the complete local evidence.

## Independent processes and real TCP

The retained shared binary also ran four independent local processes with
existing finite-mode full proposal logging and unprivileged pipelined TCP delay
proxies. No runtime code or quorum rule changed. All 96 submitted batches
completed in matching order with no dropped causal traces.

| Diagnostic | Batches | Earlier excluding batch/proposal pairs lacking two OBS | First-local / execution-associated acceptance, ms |
|---|---:|---:|---:|
| Uniform 10 ms links, Δ = 100 ms |16|37|93.493 /97.759|
| Saved-RTT symmetric links, Δ = 1,000 ms |80|202|375.727 /392.835|

Every locally accepted proposal has retained full signed pool contents, with
matching round, base, producer context and unique signers. All earlier examined
excluding proposals lack two covering sources. The WAN-like run also reproduces
zero first executions under Singapore, despite 18 first local inclusions there.

These are mechanism checks, **not performance estimates**. They use the native
debug binary, full synchronous JSON proposal logging and short finite workloads.
The uniform run has 3/5/5/4 catch-up timer expiries across the replicas, so it
cannot validate an ideal timer-free latency claim. The WAN-like run has none.
Only the signed-core virtual-time test above establishes the 25 ms ideal result.
See [process summaries](process-summary.json).

## Conclusion and remaining limit

The snapshot-phase effect is real in the current implementation. With a WAN
delay matrix, immutable observations and overlapping proposal schedules are
sufficient to reproduce Delugi's observed preproposal latency closely. The
saved logs also prove that midpoint accounting alone cannot remove the gap.

The exact real-WAN attribution between snapshot support, source readiness,
proposal propagation and processing remains unidentified because Delugi's
archived proposals omit the necessary contents. The justified conclusion is
strong support for the snapshot/eligibility mechanism—not a measured statement
that the whole gap equals 0.5δ, or that changing one gate would save 72 ms.

## Reproduction and retention

The adjacent `verify_saved_wan.py` and `verify_raptr_membership.py` accept
`--output` for a scratch directory under `results/local`. They read the original
WAN archives and repeat all cohort/membership assertions. `collect_verification.py`
checks source/build hashes and reduces retained local experiments to the
committed summaries. The core method gives its test command. Local process
commands are in `scripts/verify_phase_local.py`; `scripts/analyze_phase_local.py`
validates the full proofs and same-origin timing joins.

Complete local evidence remains under `results/local/phase-verification-20261030`.
The 98 MiB temporary build directory was removed; only the 2.7 MiB diagnostic
executable is retained. Existing production build caches were not expanded.
