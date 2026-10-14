# Matched four-replica sustained comparison

This is the retained **native-timer, unshaped localhost** comparison. Protocol
timeouts were different, and the table does not isolate protocol latency. The
[architecture and timing review](ARCHITECTURE_COMPARISON.md) explains the native
batching and queueing effects and the follow-up delta=10 ms, Delta=100 ms preset.
Frozen patches for these historical binaries are
[Raptr](patches/raptr-matched-2026-10-13.patch) and
[Mysticeti](patches/mysticeti-matched-2026-10-13.patch); current patch filenames
also contain the later timing-configuration plumbing.

The sustained runner compares Delugi Option A with the pinned Raptr and Mysticeti
paper implementations. All three run as four independent replica processes on
the same host. Each workload uses 512-byte serialized transactions, equal offered
rates at the four origins, 100 ms origin ingress batches, a 10-second warmup, and
a 30-second measurement window.
The default matrix repeats 1,000 and 4,000 offered transactions per second three
times. Protocols run sequentially; their order rotates between repetitions.

## Results — 13 October 2026

The completed comparison contains 18 valid trials on an Apple M4 Pro, 12 cores,
24 GiB RAM, Darwin 25.6.0. Each cell is the median of three trials followed by its
minimum–maximum range. MB means 1,000,000 bytes. Latency is the mean within each
trial, with endpoints specified below.

| Offered tx/s | Implementation | Unique completion tx/s | Mean latency (ms) | Replica TCP writes (MB/s) |
| ---: | --- | ---: | ---: | ---: |
| 1,000 | Delugi | 930.9 [922.9–956.0] | 1,519.740 [1,464.551–1,675.745] | 3.484 [3.364–3.489] |
| 1,000 | Raptr | 999.5 [998.5–1,002.9] | 91.342 [88.033–99.499] | 3.018 [2.961–3.081] |
| 1,000 | Mysticeti | 999.9 [999.9–999.9] | 1.603 [1.482–1.900] | 27.794 [27.558–29.634] |
| 4,000 | Delugi | 3,819.6 [3,759.6–3,831.3] | 1,402.016 [1,379.371–1,531.075] | 8.100 [8.044–8.151] |
| 4,000 | Raptr | 4,000.1 [3,990.9–4,009.8] | 107.408 [92.308–116.152] | 7.540 [7.528–7.583] |
| 4,000 | Mysticeti | 3,999.1 [3,998.9–3,999.4] | 2.083 [1.935–2.597] | 33.906 [33.721–33.993] |

Delugi generated close to the offered load but accumulated pending transactions
in every measurement window. Its median completion rates were 93.1% and 95.5%
of the two offered rates. Queues grew by 1,324–2,309 transactions at 1,000 tx/s and
5,021–7,280 at 4,000 tx/s. All six trials subsequently drained in 1.70–3.52 seconds;
all four replicas had identical complete transaction-output hashes and counts.
This demonstrates eventual completion under the tested finite load interval,
while queue growth shows that this implementation did not keep up during it.

| Offered tx/s | Implementation | Actual input tx/s, median [range] | Pending at window end, range |
| ---: | --- | ---: | ---: |
| 1,000 | Delugi generation | 1,000.1 [999.9–1,000.1] | 2,129–2,759 |
| 1,000 | Raptr admission | 1,001.2 [1,000.1–1,001.3] | 50–150 |
| 1,000 | Mysticeti generation | 999.9 [999.9–999.9] | 0 |
| 4,000 | Delugi generation | 3,998.6 [3,996.6–4,002.3] | 7,623–10,953 |
| 4,000 | Raptr admission | 4,003.1 [3,997.6–4,003.5] | 400–600 |
| 4,000 | Mysticeti generation | 3,999.1 [3,998.9–3,999.4] | 0 |

Raptr pending values are signed estimates from independently scraped admission
and completion counters, not atomic queue gauges. Mysticeti's values use origin
generation and completion observations. Both baselines sustained the offered
rates at these two points. Delugi's measured write rate was below Mysticeti's
and slightly above Raptr's; the differing completion rates and native storage
and latency boundaries remain part of the comparison.

The [compact results](results/matched-2026-10-13.json) retain every included trial,
actual window, source/binary identity, input rate, backlog, agreement check,
raw-manifest path and SHA-256. All owned replica processes were reaped.

### Preserved measurement failure and replacement

The original sequential matrix produced 17 valid trials and one failed Raptr
1,000 tx/s trial. A non-atomic scrape read 10,150 admissions and 10,175 completions
at one node, while its byte counter already represented 10,175 admissions. The
old parser rejected the derived pending estimate of −25 as a counter regression;
the actual cumulative counters were finite and increasing.

The parser now preserves signed pending estimates with skew flags, validates
actual counters independently, and saves timing before metric analysis. The
failed attempt remains unchanged. Its exact interval was not persisted, so no
precise throughput was reconstructed. One replacement ran after the matrix with
the same native source, build stamp and executables. Recomputing the five valid
original Raptr trials with the corrected parser left all measured rates, latency
and traffic unchanged. The summary includes those five trials and the replacement.

Original matrix: `results/local/comparison-20261013-final/manifest.json`.
Replacement: `results/local/raptr-sustained-parser-retry-20261013/manifest.json`.
Correction and regression evidence:
`results/local/raptr-sustained-parser-correction-20261013/validation.json`.
No trial was excluded because of its throughput or latency.

### Validation

142 Delugi Rust tests passed, including five explicitly enabled localhost tests,
round-4 ordering, silent-leader recovery, fork handling and multi-frame retrieval.
101 Python tests passed across the experiment runners. Mysticeti passed 55 native
tests with one upstream test ignored; Raptr passed five new native instrumentation
tests. Rust formatting and whitespace checks passed. Short functional smokes and
earlier development diagnostics are archived separately and excluded from the
fixed comparison population. Their manifest hashes are in the compact results.

## Delugi sustained-load implementation

Each replica generates unique transactions on its protocol thread, captures its
own monotonic measurement boundaries, and records origin-local completions,
latency histograms, schedule lag and queue sizes. Protocol rounds continue without
the finite acceptance fixture's input limit. A shared future start aligns the four
windows; observed boundary skew is retained in the archive.

Sustained runs exposed repeated full-history scans in batch custody and repeated
network-packet construction during local materialization. The store now indexes
buffered children and historical checkpoints, extending one state per actual
branch or imported anchor. Local materialization reads verified suffix records
directly and deduplicates exact batches before application decoding. Network
FETCH/DATA serialization, proof checks and fork semantics remain unchanged.
Regression tests compare indexed proofs with exhaustive prefix checks and local
materialization with reversed, segmented network retrieval across large forks.

## Reproduce

Build the three release implementations before running the matrix:

```sh
python3 scripts/run_sustained.py --build-only
python3 scripts/baselines/raptr.py --build-only
python3 scripts/baselines/mysticeti.py --build-only
python3 scripts/run_comparison.py --rates 1000 4000 --repeats 3 --warmup 10 --duration 30
```

Use the toolchains recorded in each build manifest. The pinned baselines use
Rust 1.78; the local Delugi build uses the installed stable toolchain. Local TCP
listeners and process inspection require the corresponding host permissions.
`--output` selects a new archive directory. Every adapter retains configuration,
raw measurements, binary hashes and source provenance. The matrix retains failed
trials and labels its overall status failed if any requested trial fails.

Individual adapters can be run with the same `--rate`, `--transaction-size`,
`--ingress-batch-ms 100`, `--warmup`, `--duration` and `--output` arguments. The Delugi adapter additionally
supports `--batch-ms`, `--bound-ms`, `--binary` and `--skip-build`.

## Shared measurements

Throughput counts each transaction once at its originating replica using each
implementation's native completion observation described below. Summing these disjoint origin counts yields
system throughput. Replicated observations of the same transaction are retained
separately and never added as unique throughput.

Latency is a transaction-weighted mean over transactions completing inside the
measurement window. Delugi starts its monotonic clock at producer insertion,
immediately before signed batch construction, and ends after local materialization.
Raptr uses the native API insertion clock through payload retrieval and commit
notification at the ingress node. Mysticeti uses the native millisecond UTC
generation timestamp through entry to the origin's consensus commit handler,
before its interpreter and per-transaction callback work. Raptr excludes
client-side generation and HTTP ingress. All three endpoints precede application
VM execution; Delugi performs its deterministic payload-integrity materialization.
These are different endpoints, not a matched measure of consensus-stage latency.
The [14 October latency audit](LATENCY_AUDIT.md) documents the distinction and
the subsequent timing-controlled experiment; archived numbers are unchanged.

Traffic is the sum of successful replica TCP stream writes during the window,
including protocol messages, native framing, authentication and application ACKs.
Raptr counts below Noise encryption; Mysticeti counts at its TCP stream; Delugi
uses its authenticated transport counters. Reads are recorded separately. TCP/IP
headers, kernel retransmissions, metrics scrapes and client/control connections
are outside this boundary. Live snapshot cuts can differ by bytes in flight;
adding reads to writes would count each delivery twice. Bytes per completion are
ratios within the measurement window; with changing queues they do not establish
the complete byte cost of a drained transaction cohort.

Each adapter records actual generation or admission and outstanding transactions.
Delugi also records schedule lag and allows 30 seconds after the window to drain
inserted transactions. It checks identical hashes at the common executed prefix;
when fully drained it also checks identical complete output and transaction counts
at every replica. Undrained workloads retain their measured rates, outstanding
counts and explicit drain status rather than disappearing from the comparison.
The baselines retain their native shutdown behavior and expose per-replica
progress; their metrics do not establish full transaction-order agreement.

## Workload and native settings

The common size is the serialized transaction object, excluding its containing
batch/block framing. Delugi encodes a 32-byte ID, an 8-byte vector length and
472 bytes of data. Mysticeti encodes an 8-byte vector length and 504 data bytes,
including its timestamp and random identifier. Raptr pads its native consensus-only
transaction to exactly 512 BCS bytes, preserving sender, sequence number and
`NoAccountAuthenticator`. Serialized size is checked in each native adapter.
The earlier Mysticeti baseline's 512-byte data setting encoded to 520 bytes;
the new comparison accounts for that length prefix.

At 1,000 total tx/s, each origin supplies 25 transactions every 100 ms; at 4,000,
it supplies 100. Delugi's generator uses cumulative pacing and records schedule
lag; Raptr sends native HTTP batches at this cadence; Mysticeti retains its
native generator cadence. The adapters record actual admission and completion,
so scheduling delays remain visible. Raptr's default one-transaction requests and
Delugi's default 10 ms generator remain available as native workload modes.

The experiment retains native consensus algorithms, signatures, internal batching,
timeouts, worker allocation and storage. Delugi uses a 250 ms delay bound,
in-memory custody and signed stop-and-wait TCP frames.
Mysticeti retains pipelined two-leader consensus,
two Tokio workers per replica plus its consensus thread, and background-fsynced
WAL. Raptr retains Quorum Store batching, 200 ms native
delta, authenticated networking and RocksDB payload storage. VM execution is
disabled in the paper baselines. Baseline logging remains native, with Mysticeti
leader traces enabled for its prefix check; Delugi uses compact benchmark
telemetry. These differences are part of the measured implementations and are
recorded in their raw manifests.

The two offered-load points measure delivery under these local conditions. They
do not determine maximum capacity. For interpretation, inspect achieved ingress,
completion rate, latency and queue growth together. Three-trial summaries report
medians and ranges; failed or under-delivering trials remain visible in the archive.

## Instrumentation provenance

Raptr remains pinned at `a4c98047cf8aeae3571168d02fb7e343140d2948` and Mysticeti at
`96fd83154bb5e168def9a81ee8f3e90e94e46a2e`. The explicit patches under
`benchmarks/patches/` include the local build adaptations and measurement counters.
The new counters observe successful stream I/O, exact transaction size and
origin-local completions. Build stamps bind the source diff, compiler, lockfile
and executable. Delugi archives the full Rust source, dependency lockfile,
benchmark runners and October 13 specification provenance for every trial.
