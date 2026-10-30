# Saved-WAN verification without new deployments

`verify_saved_wan.py` revalidates both healthy 3,000-request cohorts and computes
two new checks. No protocol code changes, builds, or network calls are involved.

## The midpoint ambiguity cannot explain the whole measured gap

For Delugi, each request's first exact-batch materialization occurs while the
FIFO output queue expands the suffix of a committed descriptor at round R.
Every round 1..R is recorded Commit, matches its validated proposal digest,
and has reached payload-ready before that materialization. Consequently, no
earlier-numbered proposal's expanded suffix could contain the batch: it would
have materialized earlier and exact-batch deduplication would have credited that
earlier round. This follows from `composed.rs::accept_ordering` (strictly increasing
descriptor rounds), `materialize` (FIFO expansion and first insertion), and the
scanner's contiguous prefix release.

An earlier locally accepted proposal containing the batch can therefore only
be a higher-numbered overlapping proposal. We enumerate every such proposal
accepted after the batch was sealed and before its execution-associated proposal
was accepted. Conservatively pretend that the earliest candidate contains the
batch, even though candidate membership is unknown. This yields an upper bound
on how far the measured midpoint could move earlier:

| Origin | Requests | Potentially affected | Mean maximum shift, ms | Lower bound admission→first local acceptance, ms |
|---|---:|---:|---:|---:|
| Singapore | 750 | 727 | 59.649 | 321.413 |
| Frankfurt | 750 | 40 | 3.256 | 274.570 |
| London | 750 | 24 | 2.574 | 283.634 |
| Seoul | 750 | 724 | 27.079 | 376.261 |
| All | 3,000 | 1,515 | **23.139** | **313.970** |

Raptr's first local inclusion can never be later than its execution-associated
acceptance, whose measured mean is 265.213 ms. Therefore even the maximal
favorable Delugi correction leaves at least **48.757 ms** of mean latency gap
at the first-local-validated-acceptance boundary. The independent Raptr audit
additionally establishes that its two midpoints coincide for all 3,000 requests.

This is not a bound on first leader emission: different leader/origin clocks and
different proposal transit remain outside the bound. It establishes that simply
correcting duplicate-proposal attribution cannot erase the observed local
acceptance disadvantage. It does not attribute the remaining delay to snapshots.

## Actual WAN observation phases violate the regular-δ simplification

For each origin, sort its own OBS events chronologically and integrate the
residual time to the next OBS over the interval between its first and last
measured sealed batches. This gives the exact expectation for uniform time
sampling of that observed event schedule. It does not assume regular intervals.

| Origin | Half mean OBS gap, ms | Uniform-time residual, ms | Actual seal→next own OBS, ms |
|---|---:|---:|---:|
| Singapore | 49.527 | 77.156 | 77.723 |
| Frankfurt | 49.390 | 83.482 | 83.620 |
| London | 49.375 | 80.118 | 81.004 |
| Seoul | 49.400 | 78.790 | 79.136 |
| Mean | **49.423** | **79.886** | **80.370** |

The complete-interval renewal formula is E[I²]/(2E[I]), rather than E[I]/2.
The clipped integration accounts exactly for the finite measurement boundary.
Observed gap ranges extend from 0.577 to 222.065 ms. The actual input phases
closely match uniform-time sampling, but the opportunity intervals are highly
unequal; using one half of the average cadence underpredicts this local
checkpoint wait by approximately 31 ms.

An origin's OBS is not necessarily inside the selected pool or a WA witness.
Thus this is evidence against applying the regular-δ phase formula numerically
to the WAN trace, not a measurement of an avoidable 31 ms or proof of the first
legally productive pool.

## What is absent

The retained cohort SQLite database contains requests, outputs, batches,
latencies and windows, not proposal contents. Sustained stdout retains only
lifecycle and aggregate snapshots. Causal proposal markers retain digests and
byte counts; OBS markers retain opportunity/base and selected pool signer IDs,
but not coordinate checkpoints or WA witnesses. Sampled BATCH dispatches lack
exact batch IDs, and BATCH enqueue events are explicitly not traced. They cannot
be joined reliably to individual batches to reconstruct reporter custody.

Outputs: `midpoint-bound.json`, `midpoint-bound-rows.json`,
`observation-phase.json`, and `validation.json`. The row file is a private
reproducibility intermediate; aggregates and script are suitable for the report.

```sh
python3 results/local/phase-verification-20261030/offline/verify_saved_wan.py
```
