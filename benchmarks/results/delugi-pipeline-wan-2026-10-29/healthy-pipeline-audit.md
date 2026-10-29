# Healthy WAN pipeline audit

The new pipeline proposes faster, but this run does **not** show lower fresh-transaction latency. Across the same 3,000 completed requests, admission to origin-local verified append rose from **519.40 ms to 617.37 ms**. The increase is localized mainly before the execution proposal: **336.21 → 424.00 ms**. Agreement rose only **182.44 → 187.55 ms**; contiguous-prefix wait rose **0.009 → 5.023 ms**.

## Exact observations

- The complete leader proposal streams give a mean of **105.55 ms per round**, compared with **145.59 ms** previously. This is the mean interval between successive proposals from the same leader, divided by four; every proposal marker is retained. It is not a claim that every adjacent proposal arrives 105.55 ms apart. Heterogeneous WAN links produce out-of-order adjacent round arrivals, particularly at Asian replicas. Detailed handler spans sample eight rounds per 64; the cadence above does not use that sampled subset.
- The four measured ring RTT medians did not worsen: Singapore–Frankfurt **162.49 → 159.32 ms**, Frankfurt–London **13.81 → 14.07 ms**, London–Seoul **239.73 → 239.26 ms**, Seoul–Singapore **64.37 → 62.42 ms**. These are four sampled edges, not a full all-pairs or per-message timing record.
- Leader input remains immutable after construction. In the new run, Singapore and Frankfurt freeze it approximately **96.22 / 95.86 ms** before their proposal; previously these waits were **0.29 / 0.32 ms**. London and Seoul still wait only **0.31 / 0.26 ms** after input construction. The average over leaders is **48.16 ms**, versus **0.30 ms** previously. These are round-weighted diagnostics, not additive transaction-weighted stage bars.
- Exact example, Singapore round 65: `input_fixed=9,956,463 µs`, `history_quorum=10,054,280 µs`, `PROPOSE outbox=10,054,568 µs`. Its fixed input waits **98.105 ms** before sending, with **97.817 ms** of that before HISTORY3 quorum. REPORT was sent at `9,794,871 µs`; collection/construction took **161.592 ms**. All timestamps are on Singapore's monotonic clock. `composed.rs` constructs once from its frozen observation pool, and `replica.rs` independently requires proposal history readiness; no new batch can refresh the already fixed input.
- A direct same-clock transaction check confirms this wait for the origin=leader subset: **86 Singapore transactions** averaged **98.48 ms** from input fixation to local validated proposal; **285 Frankfurt transactions** averaged **96.82 ms**. Corresponding prior subsets averaged about **0.32 / 0.36 ms**. The subset populations differ and do not explain the entire 87.80 ms aggregate increase.
- The delay increase is geographically uneven. Await-proposal means by origin were Singapore **337.89 → 483.27 ms**, Frankfurt **313.95 → 347.71 ms**, London **338.06 → 354.54 ms**, Seoul **354.93 → 510.48 ms**. First execution is now concentrated in London-led rounds: **1,849/3,000 (61.63%)**, versus **908/3,000 (30.27%)** before. This is an exact join from output batch identity to its materializing proposal round. It demonstrates a changed inclusion pattern; these retained events do not separately identify every remote batch-arrival and observation-snapshot cutoff, so they do not establish a full causal allocation of the extra wait.

## Timeout check

There were **1,182 main-timer callbacks and 1,326 catch-up callbacks** in the new healthy trace. **Every callback came after both its round's own CER action and local scanner classification.** There were **zero NO-CER outcomes**. The previous healthy run likewise had only post-completion callbacks (784 main and 894 catch-up). Thus the healthy trace does not show waiting for Δ to finish these transactions. Timer callback counts alone would be misleading.

## Conclusion and limits

The pipeline cadence improved by about **27.5%**, while the frozen-input/history overlap and first-inclusion pattern changed. Faster round production does not ensure that newly admitted transactions enter a fresher proposal sooner on asymmetric WAN links. The traces directly identify a roughly 96 ms input-to-history wait at two leaders and a shift toward London-led execution, with most latency regression borne by Asian origins. They do **not** isolate all causes of the aggregate 87.80 ms pre-proposal increase. No implementation change or additional remote experiment was performed for this audit.

This is a sequential comparison of one old and one new healthy WAN run, not a controlled repeated experiment. All request-stage subtraction is origin-local monotonic. Proposal validation, rather than remote leader-send time, is the shared decomposition boundary, so proposal transmission is included in the preceding await-proposal stage.

## Artifact and provenance audit

The current catalog points to `results/local/delugi-pipeline-wan-20261029/repacked-runtime/publication.json`. Existing `campaign_execute.validate_artifacts` passes against the current controller runtime and local shared verifier. Both retained Linux artifact verifications report `verified`; the sole changed manifest member is `source/scripts/run_sustained.py`. The ELF and original build receipt hashes are unchanged. No methodological or correctness issue was found in that repack/catalog binding audit.

Reproduce offline with `benchmarks/.cache/aliyun-python/bin/python benchmarks/results/delugi-pipeline-wan-2026-10-29/audit_healthy.py`. Structured statistics, artifact bindings, trace hashes, timer checks, leader rows, and transaction subset metrics are retained in `healthy-pipeline-audit.json`.

Inputs:

- Previous healthy: `benchmark/.state/runs/delugi-raptr-wan-30s-20261028/trials/5e2250ff5121e8d986930b2e/trial`.
- Pipeline healthy: `benchmark/.state/runs/delugi-pipeline-wan-20261029-clock-aligned/trials/b02e64f55f4e7fa0598860f6/trial`.
- Code: `core/delugi/src/composed.rs` (`report`, `collect`, one-time input construction); `core/delugi/src/replica.rs` (`pipeline_preparation_ready`, timer processing); `scripts/latency_decomposition.py` (request boundary contract).
