# Pinned paper baselines

The source revisions are fixed in `provenance/baselines.json`. Upstream checkouts,
local toolchains and build caches are ignored. Reusable runners, any artifact
patches, and compact result summaries belong in this repository. Raw logs,
configurations, fixture keys and measurement manifests stay under `results/local/`.

## Current sustained comparison

The [architecture decision](ARCHITECTURE_COMPARISON.md) records the pinned Vantage
build, all five local variants, and the recommended common runtime for formal
evaluation. [Vantage results](results/vantage-local-2026-10-13.json) are native
single-process functional measurements, with separate metric definitions.

The earlier table below retains native timer settings. The completed
[timing-controlled experiment](TIMING_COMPARISON.md) sets added one-way delay to
10 ms and the protocol bound to 100 ms,
using a calibrated, scoped kernel shaper and preserving native timer multipliers.
The runner now accepts `--network-delay-ms 10 --bound-ms 100`; it requires the
prepared helper environment and rejects a failed delay calibration.

The [matched comparison](MATCHED_COMPARISON.md) runs Delugi, Raptr and Mysticeti
as four independent processes on an Apple M4 Pro with 12 CPU cores and 24 GiB
memory. It matches 512-byte serialized transactions, 100 ms ingress batches,
1,000/4,000 offered tx/s, 10-second warmup and 30-second measurement windows.
Each point is repeated three times. The adapters now measure successful replica
TCP stream writes and disjoint origin-local completions; native internal
batching, cryptography, storage and logging remain enabled.

The explicit [Raptr patch](patches/raptr-local.patch) and
[Mysticeti patch](patches/mysticeti-local.patch) include measurement counters and
exact serialized-size checks. Their source commits remain pinned. See the
matched comparison for current commands, provenance and measurement boundaries.

## Historical native workload measurements

The remainder records the earlier baseline increment, before the matched
instrumentation. Its source-patch, transaction-size and missing-traffic statements
describe those archived builds. These small fault-free runs established executable
baselines with their original workloads; they are retained separately from the
current matched trials.

### Mysticeti

Source: `asonnino/mysticeti`, commit
`96fd83154bb5e168def9a81ee8f3e90e94e46a2e`, the Mysticeti v6 paper artifact.
The source and dependency lockfile are unmodified. The runner builds an optimized
release with Rust 1.78 in a workspace-local toolchain and verifies the binary
against a recorded build stamp before reuse.

From the repository root:

```sh
python3 scripts/baselines/mysticeti.py --build-only
python3 scripts/baselines/mysticeti.py --warmup 10 --duration 30
python3 scripts/baselines/mysticeti_test.py
python3 tests/baseline_metrics_test.py
```

Initial builds require network access. Runs require permission to open localhost
TCP listeners. No Docker or cloud deployment is required.

The runner starts four native validators in Mysticeti-C mode. Both the
`consensus_only` configuration and `CONSENSUS_ONLY` environment switch are set.
Pipelining and two leaders per round are enabled; each validator has two Tokio
workers plus its consensus thread. The native generator emits 250 transactions
per second per validator, with 512 bytes per transaction. It is an internal
synthetic client, without application transaction authentication or execution.

Three sequential trials used a 10-second warmup and 30-second measurement window.
Each row below is the median across the four replicas' independent observations;
replica counts are never summed as unique system throughput.

| Trial | Observed commit throughput (tx/s) | Mean generation-to-commit latency (ms) |
| --- | ---: | ---: |
| 1 | 998.905 | 1.408 |
| 2 | 999.838 | 1.290 |
| 3 | 999.812 | 1.274 |

The compact [result summary](results/mysticeti-local-2026-10-13.json) includes the
exact raw manifest paths and hashes. Across-trial medians are 999.812 tx/s and
1.290 ms. These observations show delivery near the configured low offered load;
they do not estimate maximum sustainable throughput.

Latency begins at the generator's millisecond-resolution UTC timestamp and ends
at each replica's shared-transaction commit-handler entry, before sub-DAG
linearization and subsequent committed-sub-DAG processing. This differs from
Delugi's post-materialization endpoint; see the [latency audit](LATENCY_AUDIT.md).
Throughput and mean latency use differences between before/after Prometheus
counter snapshots. Native histogram buckets only establish a p95 upper bound of
100 ms; no precise tail latency is inferred. Network byte counters are unavailable.

All replicas made progress and their committed leader authority/round sequences
had matching prefixes. Those native debug references do not contain block digests
or transaction order, so this is not a full output-agreement check. Debug logging
overhead is included. The native WAL remains enabled, with background fsync every
second rather than a synchronous fsync at each commit. The run ends by terminating
validators after the final scrape; it is not a drain-to-zero or crash-recovery test.

Validation: 52 native core tests passed, one upstream test was ignored, and 12
measurement-runner regressions passed. The native HTTP smoke tests require a
localhost proxy bypass. The runner also respects the artifact's source-port
mapping: advertised validator ports must remain below 6554 because outbound
source ports are ten times the advertised ports. These are environment and
configuration adaptations; no Mysticeti source patch was required.

### Raptr

Source: `aptos-labs/aptos-core`, commit
`a4c98047cf8aeae3571168d02fb7e343140d2948`, the `raptr-public` paper branch.
The native Aptos node and Forge release build succeeds with Rust 1.78. The
standalone simulator is not used. The explicit
[source patch](patches/raptr-local.patch) contains these adaptations:

- Limit workspace build targets to the node and Forge; prune 146 unreachable
  lockfile packages without adding or upgrading any package version.
- Populate the three validator networks expected by this branch, using distinct
  localhost ports and the native identity/peer-address conventions.
- Shorten the native client's startup ramp for small local runs and log encoded
  request batch sizes. Transaction generation and pacing remain native.
- Enforce locked dependencies during Forge's internal node rebuild.
- Align stale performance-mode mempool and database helper APIs with their
  callers. The standard shared-mempool helper is compiled but not used by this
  benchmark's custom mempool. Database adaptations preserve genesis writes and
  the artifact's in-memory helper behavior; Raptr and Quorum Store algorithms
  are unchanged.

On current macOS SDKs the runner adds `-Dfdopen=fdopen` to its build's `CFLAGS`,
preventing old bundled zlib code from selecting an obsolete classic-Mac stub.
The dependency source/version is unchanged. All adaptations and failed build
attempts are retained in local archives.

From the repository root, after installing the workspace-local Rust 1.78
toolchain through the Mysticeti runner, or passing its location with `--toolchain`:

```sh
python3 scripts/baselines/raptr.py --build-only
python3 scripts/baselines/raptr.py --warmup 10 --duration 30
python3 tests/raptr_baseline_test.py
```

The runner verifies the Forge executable against a build stamp containing the
source diff, patch, lockfile, compiler and build flags. Forge builds the native
node with its own feature selection before starting four independent validators.
Executable hashing occurs outside the timed workload interval.

The native workload uses synthetic `aptos_coin_transfer` transactions with
`NoAccountAuthenticator`, unique random senders and increasing sequence numbers.
The observed native request sample is a 214-byte BCS batch containing one
transaction; this is not Mysticeti's 512-byte workload, nor a network-wire byte
measurement.
Real BLS consensus signatures and authenticated Aptos networking remain enabled.
VM execution is disabled. Quorum Store stores batch payloads and batch IDs in
RocksDB with native write settings, without an explicit fsync for each write.
Raptr's protocol state remains in memory; restart recovery is not exercised.
Genesis initialization uses the native database wrapper and real AptosDB.

The primary throughput counter counts each locally submitted transaction once
when its ingress node receives the payload-ready commit notification. These
counts are summed across ingress nodes; the separate replicated transaction
inclusion counters are never summed as unique output. Every node must show
positive inclusions and positive local ingress completions. Mean latency begins
at mempool insertion and excludes client generation, scheduling and HTTP ingress.
It is transaction-weighted over completions within the measurement window,
before application execution, and is not an all-replica completion barrier.
Native batch-commit and leader-local block-commit latencies remain separately
labeled in raw manifests. Network wire bytes are not measured by this adapter.

The runner allows the configured five-second startup delay plus 45 seconds for
actual ingress completions at every node, then applies the configured warmup.
This preparation time is recorded separately.
For a 30-second measurement with default settings, the native client lifetime is
95 seconds, leaving time for preparation, warmup and the final scrape. Success
requires Forge to exit naturally with status zero; cleanup checks the task's own
process group. A failed initial smoke, whose first scrape preceded the lazily
registered completion metrics, is retained in the raw archives.

The artifact may log `client timedout` after successfully recording a materialized
completion: the batch HTTP handler has already dropped the acknowledgement
receiver. This native logging overhead is retained. HTTP admission alone is not
counted as completion. Metrics establish progress and useful completions at each
node; full transaction-order agreement is not exposed or asserted by this adapter.

The four-process smoke run and three sequential measured trials passed. Each
trial used 1,000 configured transactions per second total (250 per node), a
10-second warmup after readiness and a 30-second measurement window.

| Trial | Unique ingress completion throughput (tx/s) | Mean insertion-to-payload-ready-commit latency (ms) |
| --- | ---: | ---: |
| 1 | 1,000.193 | 93.974 |
| 2 | 1,000.279 | 91.951 |
| 3 | 1,000.372 | 93.066 |

The compact [result summary](results/raptr-local-2026-10-13.json) records raw
manifest and metric-file hashes, exact binaries, source patch and per-replica
observations. Across-trial medians are 1,000.279 tx/s and 93.066 ms. All trials
used identical native binaries, exited naturally with status zero and left no
owned processes running. These figures describe delivery at the configured low
load, not maximum sustainable throughput. Different transaction sizes, native
configurations and latency endpoints prevent a direct latency ranking against
Mysticeti or Delugi.

Validation: nine native BLS/BCS signature tests and 26 runner regressions passed.
All reported trial metrics were recomputed from archived Prometheus snapshots.
