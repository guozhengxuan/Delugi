# What the half-δ term explains in the four-region repeat

At 100 tx/s, Delugi took **292.2 ms** on average from batch broadcast to the first leader proposal containing the batch. Raptr took **139.5 ms**. The point estimate of the gap is **152.7 ms**. The literal half of Delugi’s mean REPORT spacing was **49.3 ms**. The measured interval that matters for Delugi was **110.0 ms** from broadcast to the launch of the REPORT used by the first including proposal.

[Latency figure (PDF)](healthy-latency.pdf) · [PNG](healthy-latency.png) · [cross-host measurements and bounds](utc-comparison.json) · [same-clock measurements and snapshot evidence](phase-comparison.json)

## Timed experiment

The matched healthy runs and Raptr’s silent-leader run used the same four Aliyun hosts sequentially, with one validator in each of Singapore, Frankfurt, London and Seoul. The Delugi silent-leader retry used replacement hosts of the same type in those regions. Each protocol ran once healthy and once with its first leader persistently silent. Each input window lasted 30 seconds at 100 aggregate tx/s, with a 15-second drain, one useful byte per transaction, Δ = 1,000 ms, 20 Mbps configured egress and no injected network delay. The 12 directional median overlay RTTs ranged from 13.9 to 222 ms. We reused the previous protocol-specific batching and fault settings. The silent identity was in Singapore for Delugi and Frankfurt for Raptr. [Workload configuration](parameters.json) · [Measured RTTs](network-matrix.json)

All four hosts ran the instrumented Linux release built from `6e49f91`. Both protocols timestamped message handoffs while running normally and exported their traces after the timed run. For Delugi, the batch start is its seal immediately before creating the broadcast effect. The first transport enqueue started 0.0035 ms later on average. For Raptr, the start is the native Quorum Store broadcast call. The midpoint is the **first proposal emitted by any leader whose payload actually includes the batch**. The endpoint is contiguous, payload-verified output at the request’s origin.

## Where the healthy difference arose

| Per-request mean, ms | Delugi | Raptr | Delugi minus Raptr |
|---|---:|---:|---:|
| Admission → batch broadcast | 0.6 | 75.3 | −74.7 |
| Batch broadcast → first proposal emission | 292.2 | 139.5 | +152.7 |
| Admission → first proposal emission | 292.8 | 214.8 | +78.0 |
| First proposal emission → verified output | 231.6 | 230.4 | +1.2 |
| Admission → verified output, origin clock | **524.4** | **445.2** | **+79.2** |

In the uniform-link model, let a batch be broadcast θ after a REPORT launch, with θ uniform over (0, δ). If the in-flight REPORT misses the batch, the next one starts δ − θ later. Its REPORT/OBS exchange takes 2δ. The expected broadcast-to-proposal time is therefore 2δ + E[δ − θ] = 2.5δ. The [signed-core phase sweep](../phase-verification-2026-10-30/README.md) measured 25.0 ms at δ = 10 ms. In Delugi, a leader freezes the first three signed observations for its opportunity. Two observations must cover the batch. Receiving the batch before sending the proposal can still leave the leader with only one covering observation.

The trace gives three different measurements of that wait.

1. **Regular-spacing prediction, 49.3 ms.** This is half the mean observed inter-REPORT interval. At least 301 launches fell within the load window under all allowed clock offsets. Even allowing 30.1292 seconds for that window, half its mean spacing was at most 50.22 ms. The broadcast-to-emission gap was at least 80.34 ms.
2. **Wait for the next REPORT of any round, 71.8 ms.** Integrating uniform arrivals over the actual launch times predicts 71.7 ms. A random arrival falls more often in a long interval than a short one.
3. **Signed interval to the REPORT for the first including proposal, 110.0 ms.** A subsequent REPORT can also miss the batch. Choosing the proposal by actual membership identifies the REPORT its leader used. Its launch can precede the broadcast. The combined clock and leader-identity bounds on the mean are 70.8–180.4 ms.

After that REPORT launched, Delugi took 175.9 ms to freeze the pool, 0.7 ms to construct its input, and 5.6 ms to emit the proposal. Raptr took 42.9 ms from broadcast to payload receipt at the first including leader (zero network transit for a batch already at its origin-leader), 96.0 ms from receipt to the proposal’s payload pull, and 0.7 ms from pull to proposal emission. Raptr used optimistic inclusion for 2,820 of the 3,000 requests and a proof for 180.

Subtracting the **productive REPORT interval** from the broadcast-to-emission gap leaves a central estimate of **42.7 ms**. We compute the residual directly as Delugi’s time from that REPORT to emission (182.2 ms) minus Raptr’s complete broadcast-to-emission time (139.5 ms). Pairing positive and negative timestamp terms on the same hosts narrows the residual’s clock-calibration bounds to **24.77–53.53 ms**. Each host’s constant clock offset cancels in its paired terms. The calculation retains uncertainty from drift, unmatched terms, and ambiguous first-proposal identities. An independent pairing under a 501 ppm allowance gave 23.69–54.61 ms. The positive residual means that **even the productive REPORT wait explains only part of the broadcast-to-emission gap** on this run.

Raptr spent 74.7 ms longer before batch broadcast. At the common admission boundary, subtracting the productive REPORT interval from the 78.0 ms gap leaves **−32.0 ms** (bounds **−50.0 to −21.1 ms**). The report wait is thus large enough to exceed the admission gap; Raptr’s longer batching offsets part of it. These differences describe the observed timeline. The 110.0 ms includes a productive-evidence requirement as well as arrival phase. It cannot be interpreted as the speedup from removing one delay.

## What the signed snapshots establish

In 7,046 earlier batch/proposal pairs examined on origin-local clocks, the frozen pool contained fewer than two observations covering that batch. In **3,711** of these pairs the leader already had a locally provable candidate covering it. Even including the fourth reporter would have left 5,909 pairs short of two observations. For 1,137 pairs the omitted fourth report could supply the second observation. One batch can miss multiple opportunities.

On the actual acceptance schedule, analytically allowing candidates with a local proof but insufficient signed observations would move first local acceptance earlier for 2,127 of 3,000 requests, by 170.1 ms averaged over the whole cohort. This quantifies how strongly the first inclusion depends on the witnesses under the observed schedule. A real protocol change could also change subsequent proposals, bases and timing.

As an independent check on clocks, admission to the **first including proposal accepted at the origin** took 319.7 ms for Delugi and 260.7 ms for Raptr. Both endpoints use the same origin clock. Choosing the proposal credited with execution instead inflates that 59.0 ms gap to 80.4 ms. This explains why the historical bar for dissemination cannot be read as time to first leader emission.

## Healthy and silent-leader results

| Protocol | Case | Verified outputs | In-window goodput, tx/s | Mean admission → output, ms | Recorded outbound MB in window |
|---|---|---:|---:|---:|---:|
| Delugi | healthy | 3,000/3,000 | 98.20 | 524.43 | 39.45 |
| Raptr | healthy | 3,000/3,000 | 98.10 | 445.20 | 15.85 |
| Delugi | silent-first-leader | 3,000/3,000 | 90.17 | 4,133.65 | 8.54 |
| Raptr | silent-first-leader | 3,000/3,000 | 83.17 | 3,042.70 | 40.17 |

Every one of the 12,000 timed requests had a verified output and complete stage coverage. Goodput counts completions during the 30-second window. Latency follows requests through the drain. The silent cases exercise the protocols’ native timeout policies and different faulty locations. Their means do not isolate a healthy REPORT-phase effect. [Trial measurements and recorded stages](trials.json)

Both four-host fleets and their security groups were deleted. The combined quote-based estimate for building, deploying and running the tests was **¥17.82**, pending final billing. [Resource and cost record](cleanup.json)

## Evidence and uncertainty

We joined 3,000 verified healthy requests per protocol and paired 20,238 Delugi and 10,956 Raptr cross-region message legs. The full directed breakdown covers batch, REPORT, OBS, proposal, vote and certificate traffic for Delugi, and batch, proposal, QC vote and CC vote traffic for Raptr. Each sample spans the recorded send/receive callbacks, including intervening transport and validation work. The private archive retains the batch identities and raw signed evidence. [Per-direction aggregates](utc-comparison.json)

Separate hosts use separate monotonic clocks. Bracketing samples mapped each host clock to UTC using the synchronized Linux kernel’s reported maximum error, sampled read width, and a 500 ppm allowance between probes. The uncertainty intervals include ambiguity about which leader emitted the first including proposal. That identity was ambiguous for 1,659 Delugi requests and zero Raptr requests. All healthy request intervals closed to within 0.5 µs at the central estimates. With one run per configuration the bounds describe clock uncertainty within this run only.

The first Fabric preflight stopped before starting any workload because the controller checkout included post-build analysis scripts. Running Fabric from the exact release revision passed the source and binary checks. All timed runs use the same instrumented release. A later SSH handshake reset in Seoul stopped the first Delugi silent-leader attempt before load or any control command. The deployment controller released those hosts. The retry selected only that case from its saved effective configuration.
