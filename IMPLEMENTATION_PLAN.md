# Delugi implementation and evaluation plan

Updated **27 October 2026**. Implementation checkpoint: `90a5d1f`.
The approved compact campaign is implemented through local tests. The next
stage is qualification of the final Linux artifacts and the 10/50-replica
profiles, followed by paid measurement. No cloud resources were created for
this implementation phase.

Working commands are in the [compact campaign runbook](docs/evaluation/compact-campaign.md).
The [counterpart proposal](benchmarks/plans/2026-10-27-counterparts-and-aliyun.txt)
and [budget/load-point audit](benchmarks/plans/2026-10-27-aliyun-budget.txt)
retain the rationale and paper figure counts. Their former implementation
pending statements are superseded by this plan and its evidence.

## 1. Scope fixed by the author

Six principal implementations: **Delugi, integrated Raptr, Simple-IT
Opt-Mempool, Simple-IT Opt-Dispersed, original Autobahn, Mysticeti-C**.
Delugi/Raptr share the executable and reusable services. The four other
implementations use pinned author sources, recorded patches and native
services behind the same campaign controller. Shoal, Vantage and Mysticeti-FPC
are outside this matrix.

| Setting | Current campaign |
| --- | --- |
| Main committees | Exactly 10 and 50; n=4 remains a qualification fixture |
| Offered load | 1k, 4k, 8k, 16k, 32k, 64k total honest tx/s |
| Duration | One 60-second measurement; zero offered warmup; at most 15-second drain |
| Repetition | One; allowance of at most two additional points/reruns per curve, not automatically scheduled |
| Payload | 512 useful bytes; native encoding is recorded separately |
| Timing | Added one-way δ=10 ms; protocol input Δ=100 ms with native multipliers |
| Network | 100 Mbps aggregate private protocol egress per validator across peers and roles, including protocol ACKs |
| Machines | Singapore ecs.g9i.xlarge, 4 vCPU, 16 GiB, 200 GiB; one validator and all its roles per host |
| Cases | Healthy curve; one missing-data case; one native silent-first-leader case |
| Budget | User ceiling is the private recorded balance plus CNY 2,000; working allocation CNY 1,000 |

The default matrix contains 72 healthy and 24 conditional fault cells. The
estimate remains CNY 516–921 including reserve; this is an estimate, not a live
quote. Preparation, verification, collection and cleanup add billed wall time
outside the 60-second offered window. Public SSH/export bandwidth is a separate
5 Mbps setting. Keep finite leases, per-lease caps and the durable aggregate
budget ledger. A budget allowance is not evidence that the account was topped up.

## 2. Implemented and tested

| Component | Current evidence |
| --- | --- |
| Delugi core | HISTORY3, CLOSED, catch-up timers, scanner; authenticated bases, all-current construction, empty fallback, exact-batch forks/deduplication; paced PROG and immediate bundling |
| Integrated Raptr | Real pinned consensus and Quorum Store behind shared services; bounded sustained schema-2 input spools and signed journals; exact cutoff/cancellation accounting and traffic windows |
| Shared workload | One exact global schedule, independent of consensus; non-divisible rates, fixed honest-origin population, admission cutoff, censored unfinished work |
| Simple-IT | Both failure-capable author revisions build locally; mTLS identities, real arrivals, deterministic complete materialization, signed bounded evidence; healthy, silent-leader and three-header repair fixtures; both complete 60-second 4k tx/s diagnostics |
| Mysticeti/Autobahn | Native arrivals and output/cohort adapters; matched timer input; explicit original Autobahn pin; true first-leader startup absence supported by remote host lifecycle |
| n=50 profiles | Delugi explicit 64 MiB complete-current profile; f=16, high quorum 34, amplification 17; Raptr PoA corrected to native strict two-thirds quorum 34 |
| Campaign routing | One settings file resolves all six adapters and 96 cells; unsupported settings fail before provisioning; requested/effective values retained |
| Fleet lifecycle | Budget reserve before dispatch; exact owned IDs/tags; private peer firewall; bounded leases; artifact publication reuse; sequential interleaved trials; deletion on failure |
| Remote execution | All-host readiness/arm for common Raptr and Simple-IT; independent host clocks; only own secret keys; ceremony sealing; finite process supervision; gzip parallel evidence collection |
| Results | Exact cohort reduction; CSV retains failed/zero/censored/unrun cells; latency/goodput/completion/traffic PDF and PNG; sampled and final traffic boundaries remain distinct |
| Networking | Aggregate Linux egress tree, scoped peer/role selectors, before/during/after RTT checks, owned cleanup; real two-namespace aggregate bandwidth acceptance |

The focused final Python suite ran 237 checks: **227 passed and 10 skipped**
(Linux-only and explicit native opt-in tests). Separate real-process and Linux
receipts supply their own evidence; skipped tests are not counted as passes.
The campaign state-machine tests use fake cloud/SSH backends. They do not imply
that the full new controller has run on Alibaba.

Evidence:

- [Current campaign checkpoint](benchmarks/results/compact-campaign-implementation-2026-10-27.json).
- [Simple-IT builds, authentication and workload fixtures](benchmarks/results/simpleit-local-2026-10-27.json).
- [Integrated Raptr sustained and scale fixtures](benchmarks/results/compact-integrated-local-2026-10-27.json).
- [Real Linux egress calibration](benchmarks/results/linux-egress-local-2026-10-27.json).
- [Earlier four-host pilot](benchmarks/results/aliyun-four-host-pilot-2026-10-26.json): 12/12 finite Delugi/Raptr functional trials; unshaped, different finite workloads. Its four instances and security group were deleted. This is historical acceptance of that artifact, not the new sustained campaign.

## 3. Qualification findings that determine the next work

1. **Final Linux artifacts are not yet qualified.** Current local builds include
   macOS and debug artifacts. Rebuild the common Linux publication at the selected
   pushed revision with Delugi RocksDB enabled, and qualify all four native Linux
   x86_64 release archives. The controller rejects stale runtime, wrong
   architecture, pin, patch or role.
2. **n=50 at Δ=100 ms remains open.** The local shared-machine Raptr empty test
   stalled before round 4. Δ=1,000 ms reached round 4 but qualifies only that
   diagnostic. Preserve 100 ms for the main series and resolve the failure on
   the actual release/profile before a paid sweep.
3. **Original Autobahn did not recover useful output with its first leader
   absent.** At 1,001 tx/s for 60 seconds, all 60,060 scheduled requests were
   accounted for and zero completed. Native output progressed through empty
   slots 1–4 and stalled at slot 5. Lifecycle/evidence capture passed; liveness
   did not. Investigate native timeout configuration/behavior and retain this
   result. Do not silently substitute the separate disruption branch.
4. **Simple-IT security qualification remains incomplete.** Direct-sender mTLS
   does not authenticate all transferred certificates or establish fallback
   safety. The mempool constructor fix is disclosed: its old cut certificate
   reset at two votes while its verifier required three at n=4. Test forged,
   replayed and forwarded evidence and the complete fallback path before making
   Byzantine claims.
5. **Observation and scale gates remain.** Mysticeti's remote exact observed
   workload prefixes agree, but do not establish a complete signed WAL terminal
   prefix. Requalify output fidelity, observer overhead, bounded state/RSS/disk
   growth and traffic-window alignment on the selected artifacts. Run loaded
   network calibration on actual hosts; namespace and idle RTT checks do not
   establish loaded cloud queueing behavior.

The new Delugi RocksDB silent-leader fixture made progress and agreed across
the three correct replicas: 300 scheduled, 221 completed and 79 unfinished at
the short cutoff. Mysticeti's corresponding short fixture completed 2,993 of
3,003 requests. These are functional observations on one local machine, not
comparative latency or capacity results. An absent leader from startup may be
skipped before measured arrivals begin; record that fault interval explicitly.

## 4. Next sequence

1. **Close local qualification gaps.** Diagnose Autobahn's zero-output recovery;
   audit Simple-IT certificates/fallback; complete the selected Mysticeti
   output-fidelity gate. Preserve failed attempts and original artifact identities.
2. **Build and freeze Linux publications.** Use guarded recipes, pinned locks
   and source snapshots. Verify both common roles and all native roles, retain
   binary/build receipts, then delete disposable targets. Reuse publications
   only while their exact source/runtime identities match.
3. **Run bounded qualification fixtures.** On each final artifact: round 4,
   silent leader, missing payload, empty/unfinished/overload, output agreement,
   cleanup and selected storage. Test n=10 and exactly n=50 at the nominal timer;
   local co-location supplies functional evidence only.
4. **Perform small shaped cloud qualification after those gates.** Resolve
   fresh quotes/leases against the same ledger. Check 4k tx/s healthy and
   silent-leader cases for each implementation, one minute per cell. Validate
   aggregate 100 Mbps, added RTT, loaded delay, resource limits, exact populations,
   transfer and cleanup before the main sweep.
5. **Run the main matrix once.** Change the common settings file, freeze its
   plan, then use one `campaign --execute` operation. Select the same accepted
   healthy input rate for all fault cases at a committee size. Extra points or
   reruns require an explicit new plan within the shared allowance and budget.

The controller's fault-rate selector is diagnostic: at least 99% admission and
by-drain completion, and second-half pending growth at most 1% of that half's
offered population. It chooses below the largest jointly accepted point when
possible. Otherwise fault cells remain `not_run`. This does not certify the
stricter paper frontier rule. Define final frontier acceptance before producing
paper claims; do not relabel these points as measured maximum capacity.

## 5. Core and measurement contracts

Keep consensus/availability policy under `core/delugi` and `core/raptr`;
reuse network, crypto, storage, ingress and lifecycle in `shared`, `core-api`
and `node`. `ProtocolFactory` provides `name`, `run`, `generate_keys`,
`verify_archive` and `verify_ledger`. Native counterparts remain separately
named author systems. See the [interface map](docs/architecture/delugi-code-structure-2026-10-22.txt)
and [shared-service contract](benchmarks/plans/2026-10-21-shared-service-contract.txt).

- Q verifies complete immutable supplied metadata; payload retrieval stays
  outside proposal validation/scanner decisions. HISTORY3, once-only
  VOTE/CER/report obligations, terminal outcomes and 7Δ/3Δ timers remain intact.
- Earlier bases contain signed ordering headers, matching descriptors and
  n−f matching short CER signatures. Construction uses the frozen current OBS
  pool and authenticated-base empty fallback. Advancing targets require the
  leader's exact suffix and proof-producing state.
- Exact batch identity includes producer, height and unsigned-header digest.
  Valid Byzantine forks may both be ordered; exact-batch and request deduplication
  remain separate.
- Default scheduling uses originating-PROG pacing with a finite Δ release
  deadline and immediate bundling of enabled messages. Canonical and unbundled
  ablations remain explicit. TCP pipelines frames without an unconditional ACK gate.
- Shared RocksDB Written uses WAL-enabled `sync=false` writes before visibility.
  It does not provide core restart recovery. Native executor/worker, crypto,
  batching, storage and repair differences stay in effective manifests.

Use the selected archived tree matching
[spec-2026-10-19.json](provenance/spec-2026-10-19.json); live ordering.tex differs.
Do not refresh historical hashes automatically. Record the pacing amendment
separately. Canonical direct-commit bounds are not transaction admission-to-output
bounds for the paced implementation.

Primary latency is successful origin-local admission to the first locally
payload-verified contiguous application append. Retain scheduled-arrival
latency, rejected/cancelled/unoffered requests and unfinished censored tails.
Use same-host monotonic differences. Report useful unique completion TPS in
the measurement window and completion fractions by the drain cutoff. Remote
all-correct event latency requires its own qualified measurement.

Traffic tables expose measurement-window successful stream writes separately
from sampled total-run writes. Native TLS, worker-local links, sample offsets
and lateness stay explicit. SSH export is excluded; TCP/IP headers and kernel
retransmissions require separately named OS counters. Zero-output cost ratios
remain undefined. Stage figures must use local spans and causal dependencies;
never add overlapping spans or subtract different host clocks.

Continue periodic commits/pushes. Keep sources, binary receipts and raw evidence;
remove disposable targets. New outputs remain `comparison_eligible=false`
until the listed gates are actually satisfied.
