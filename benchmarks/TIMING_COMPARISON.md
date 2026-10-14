# Timing-controlled comparison — 13 October 2026

**14 October latency audit:** the recorded endpoints differ: Delugi finishes after
materialization and effect processing, Raptr at the origin's payload-ready commit
notification, and Mysticeti at commit-handler entry before linearization. These
numbers compare the current implementations, not matched consensus stages. The
[latency audit](LATENCY_AUDIT.md) explains the clocks, timer paths and transport
queueing. Its separate diagnostic reproduces 757.8 ms using the original ACK gate
and 50.0 ms without that gate; both are invariant to Delta=100/250/1,000 ms with
zero NO-CER outcomes. These are virtual-time diagnostic results. Original native
measurements and archived manifests are preserved.

The ACK gate was subsequently removed; the [transport pipeline report](TRANSPORT_PIPELINE.md)
records the fix and native before/after experiments. Those runs use a userspace
TCP delay proxy and do not replace this kernel-shaped matrix.

All 18 sequential trials passed with the selected **delta=10 ms added one-way
network delay and Delta=100 ms**. Each point uses four independent native replica
processes, 512-byte serialized transactions, 100 ms origin ingress cadence,
10-second warmup, 30-second measurement, and three repetitions. The same Apple
M4 Pro host has 12 cores and 24 GiB RAM. Protocol order rotates between repeats.

Cells show the median across repetitions followed by the minimum–maximum range.
Latency is each trial's transaction-weighted completion-window mean. MB is
1,000,000 bytes. Throughput counts unique origin completions, not replicated
output summed across nodes.

| Offered tx/s | Implementation | Completed tx/s | Mean latency (ms) | Replica TCP writes (MB/s) |
| ---: | --- | ---: | ---: | ---: |
| 1,000 | Delugi | 1,001.4 [997.5–1,001.6] | 761.595 [758.449–771.260] | 2.500 [2.500–2.501] |
| 1,000 | Raptr | 998.2 [998.1–999.8] | 161.144 [157.754–163.919] | 1.904 [1.896–1.906] |
| 1,000 | Mysticeti | 999.6 [999.6–999.7] | 46.724 [46.124–46.913] | 1.942 [1.939–1.944] |
| 4,000 | Delugi | 3,995.8 [3,993.2–4,003.2] | 789.816 [785.642–799.127] | 7.102 [7.099–7.115] |
| 4,000 | Raptr | 4,001.0 [3,997.9–4,002.7] | 175.228 [172.552–177.719] | 6.494 [6.492–6.494] |
| 4,000 | Mysticeti | 3,998.8 [3,998.2–3,998.9] | 45.363 [44.976–48.618] | 6.599 [6.574–6.600] |

All implementations delivered close to both offered rates. These points measure
achieved output under the tested loads, not maximum capacity. Delugi's pending
work changed by −50 to +75 transactions at 1,000 tx/s and −83 to +204 at 4,000 tx/s;
all six trials drained in 0.256–0.561 seconds. All four Delugi replicas agreed on
the complete generated transaction count and output hash in every run. Native
baseline checks remain implementation-specific: Mysticeti verifies a matching
prefix of leader authority/round references, with exact transaction order not
checked by this runner.

The [compact results](results/timing-controlled-2026-10-13.json) retain all 18
attempts, exact values, source/binary identities, timing evidence, output checks,
and SHA-256 links to raw manifests. A separate [40 tx/s preflight](results/timing-preflight-2026-10-13.json)
passed for all three, with mean latency 781.527 ms for Delugi, 159.308 ms for Raptr
and 47.066 ms for Mysticeti.

## What the controlled preset establishes

The added round-trip delay was 20.681 ms before and 20.618 ms after the main matrix,
using an established TCP echo connection; an unselected control remained sub-ms.
The same macOS dummynet helper shapes both directions of selected replica TCP
connections, including kernel ACKs. It shapes four Delugi ports, all twelve Raptr
validator network ports, and four Mysticeti ports. Client/control/metrics ports
are excluded. Shaping starts after readiness and before warmup, and is cleared
between trials. All temporary rules, both owned pipes and the helper's PF enable
reference were removed after the experiment.

The helper configures no bandwidth cap and a 100-slot droptail queue per flow.
Darwin's flow-statistic display is malformed on this host, so it cannot establish
zero packet drops. Reported traffic is successful application TCP-stream writes,
including protocol framing/authentication/application ACKs, excluding TCP/IP
headers and kernel retransmissions. This is a controlled local implementation
comparison, with nominal injected delay rather than a strict per-packet delay
floor or a cloud latency bound.

The initial echo calibration exposed a cleanup bug: a truncated pipe listing
caused the first helper to lose ownership of one inactive pipe. That helper was
stopped, the known residue was removed, cleanup was fixed and tested, and two
calibration/cleanup cycles passed before any protocol trial. The initial evidence
and corrected helper command log are archived under
`results/local/timing-preset-validation-20261013/`.

## Timer mapping and remaining implementation differences

| Implementation | Applied mapping for Delta=100 ms |
| --- | --- |
| Delugi | Main timer 700 ms; catch-up timer 300 ms |
| Raptr | Leader 400 ms; partial-QC wait 10 ms; fetch 200 ms; round synchronization 1,500 ms |
| Mysticeti | Native leader-readiness timeout T=100 ms; quorum-clock gating retained |

Native timer structures and multipliers are preserved. Raptr's independent
Quorum Store batching remains 150 ms polling, 80 ms nonempty minimum and 300 ms
maximum batch interval. Mysticeti's previously ignored public timeout setting
is now connected to the runtime; its effective historical default remains one
second. Its T=Delta mapping is explicit experimental configuration, not an
identical native theorem parameter.

The mean-latency endpoints remain: Delugi producer insertion to post-handler
materialization; Raptr API mempool insertion to payload-ready commit notification
at the ingress replica; Mysticeti generation UTC timestamp to origin commit-handler
entry before sub-DAG linearization and subsequent committed-sub-DAG processing.
The endpoint work is not matched across implementations. Worker/thread arrangements, storage,
cryptography and internal batching remain native and documented in raw manifests.

The gap persists after matching the requested timing preset. Delugi's directed
peer streams sustain about 49 acknowledged frames/s in the inspected low-load
and first 1,000 tx/s runs, near the one-frame-per-20-ms-RTT ceiling. Ten payload
frames/s plus roughly 39 control frames/s share each stream. Outstanding queues,
zero application retries/ACK failures, and no payload FETCH/DATA in these runs
support a transport bottleneck. They do not decompose the full latency or prove
that transactions waited for a 700 ms timeout. See the [counter audit](results/delugi-transport-audit-2026-10-13.json).

The [earlier native-settings results](MATCHED_COMPARISON.md) remain unchanged.
Matching timing substantially changes both latency and traffic; those earlier
numbers should not be used as an isolated protocol comparison. The next formal
comparison should use the [shared-runtime plan](ARCHITECTURE_COMPARISON.md), with
Delugi adapted to a Vantage fork and native Raptr/Mysticeti retained as external
implementation baselines.

## Reproduction and validation

Build the pinned adapters, prepare a fresh scoped helper with
`scripts/network_delay.py prepare --directory <private-directory>`, start its
printed administrator command, and load its `environment.json` variables into
the runner process. Then run:

```sh
python3 scripts/run_comparison.py --network-delay-ms 10 --bound-ms 100 \
  --rates 1000 4000 --repeats 3 --warmup 10 --duration 30 \
  --output results/local/<fresh-directory>
```

The runner rejects failed echo calibration, mismatched native bounds or shaping
identity, missing cleanup, source/binary changes across repeats, wrong workload
sizes, invalid counters and inconsistent rates. `summarize_timing_comparison.py`
revalidates every successful trial and raw-manifest hash before recomputing the
aggregate. No failed trial was removed from this matrix; all 18 passed.

Validation in this increment: 115 top-level Python tests; 16 Mysticeti adapter
tests; 57 native Mysticeti tests with one upstream ignored; two native Raptr
configuration tests; and the real 3-trial preflight plus 18-trial matrix. The
Delugi protocol binary is unchanged from the earlier comparison. Vantage build,
713-test coverage and five functional smokes are recorded separately in the
[architecture report](ARCHITECTURE_COMPARISON.md).
