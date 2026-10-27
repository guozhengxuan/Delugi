# Compact six-protocol campaign

Implemented at `90a5d1f`; local qualification is recorded in
[the checkpoint receipt](../../benchmarks/results/compact-campaign-implementation-2026-10-27.json).
Read [the active plan](../../IMPLEMENTATION_PLAN.md) for remaining Linux,
security, recovery and n=50 gates. No paid resources were launched while
implementing this controller.

## One settings file

Start with
[`compact-campaign.native-services.json`](../../benchmarks/configs/compact-campaign.native-services.json).
It selects six implementations, n=10/50, six coarse rates, 60 seconds, 512 useful
bytes, δ=10 ms, Δ=100 ms and aggregate 100 Mbps. Null batch/proposal controls mean
explicit native defaults. The resolver rejects a common knob that any selected
adapter cannot enforce. Changing protocol selection also requires matching
`protocol_options` keys.

From the repository root, these commands are offline:

```sh
python3 scripts/aliyun_bench.py campaign \
  --config benchmarks/configs/compact-campaign.native-services.json \
  --plan --output results/local/next-campaign-plan.json
python3 scripts/aliyun_bench.py campaign \
  --config benchmarks/configs/compact-campaign.native-services.json \
  --resolve --output results/local/next-campaign-resolved.json
```

Use fresh output names. The selected paper tree must match the frozen spec
manifest; an unreviewed live paper edit cannot silently update its identity.
The default has 96 cells. The up-to-24 additional-point allowance is recorded
but does not dispatch automatic searches or repetitions.

## Prepare reusable artifacts once per source revision

Use Linux x86_64 release artifacts for g9i hosts, with published source,
patch, lock, compiler and binary hashes. macOS binaries and old runtime bundles
are rejected before an execution backend is instantiated. Build separately from
measurement; the campaign never compiles on validators during a trial.

For the common Delugi/Raptr executable, use an existing, explicitly owned Linux
builder inventory with Python 3.12+, required packages and at least 60 GiB free.
These commands do not provision a builder:

```sh
python3 scripts/aliyun_bench.py build-plan --inventory BUILDER_INVENTORY.json \
  --revision FULL_PUSHED_COMMIT --install-system-packages --output BUILD_PLAN.json
python3 scripts/aliyun_bench.py build --plan BUILD_PLAN.json --execute
python3 scripts/aliyun_bench.py build-status --plan BUILD_PLAN.json --execute
python3 scripts/aliyun_bench.py build-collect --plan BUILD_PLAN.json --execute \
  --output results/local/common-linux-publication
```

The asynchronous builder uses Rust 1.78.0, bounded jobs/time/RSS/disk, tests the
common executable, packs both roles and removes its disposable Cargo target.
Wait for successful completion before collecting. The catalog uses the local
`publication.json` returned by collection. Delugi requires the compiled
`rocksdb-records` feature. A source-matching local common executable/build receipt
is also required for Delugi's local evidence verification.

For native implementations, prepare the pinned source plus committed patch and
lock. Simple-IT preparation is explicit:

```sh
python3 scripts/baselines/simpleit.py simpleit-mempool
python3 scripts/baselines/simpleit.py simpleit-dispersed
```

Use the fixed build path for each of `mysticeti`, `autobahn`,
`simpleit-mempool`, `simpleit-dispersed`:

```sh
python3 scripts/deployment_prepare.py bundle --protocol PROTOCOL \
  --jobs 2 --output results/local/PROTOCOL-source
python3 scripts/deployment_prepare.py plan --hosts BUILDER_INVENTORY.json \
  --bundle results/local/PROTOCOL-source --output PROTOCOL_BUILD_PLAN.json
python3 scripts/deployment_prepare.py build --plan PROTOCOL_BUILD_PLAN.json \
  --execute --install-system-packages --output results/local/PROTOCOL-linux-build
python3 scripts/deployment_prepare.py clean --plan PROTOCOL_BUILD_PLAN.json --execute
```

The builder needs the pinned Rust toolchain or the checksummed installer assets
accepted by `bundle --help`. Its `artifacts.tar` is the catalog entry. Preserve
the collected archive/receipt before `clean`. Native sources must already match
their pinned patch; bundle validation rejects arbitrary checkout diffs.

## Catalog, leases and one execution

Copy the [catalog template](../../benchmarks/configs/compact-artifacts.example.json)
and [authorization template](../../benchmarks/configs/compact-execution.example.json)
into a private ignored directory. Fill placeholders with absolute local paths.
The catalog contains one common publication, its local verifier, and four native
Linux archives. Authorization binds the exact `plan_sha256` and one lease for
each selected committee size.

Each compact lease uses `profile: compact-n10-n50-v1`, exact `maximum_instances`
10 or 50, lifetime at most three hours, a fresh quote, a per-lease cap and the
same persistent aggregate budget ledger. Start from the existing
[lease field example](../../benchmarks/configs/aliyun-pilot-lease.example.json),
add `campaign_budget: {path, authorization_sha256}`, and replace pilot values
with the reviewed compact lease. Do not reuse the old CNY 50 pilot authorization.
Initialize `campaign_budget.Ledger` once using the privately recorded ceiling
in integer fen and the hash of authorization evidence. Existing spending or
ambiguous reservations must never be reset. Reconcile final billing before
settling a released lease.

Select the existing Loom VPC/vSwitch/key pair and Ubuntu 24.04 image. SDK
credentials remain controller-local. SSH is restricted to the controller /32;
peer rules use exact private /32 addresses and fixed protocol port ranges. Large
peer rule sets use at most 100 entries per API call, matching the
[Alibaba API limit](https://api.alibabacloud.com/document/Ecs/2014-05-26/AuthorizeSecurityGroup?updateTime=2024-12-04).

SSH host keys are either pretrusted, or the explicitly selected
`first-use-owned-address` policy captures ED25519 keys at the exact IPs returned
for the tagged owned fleet. It then uses strict checking; host authentication
is never disabled. Record the policy and known-host file hash. Select the actual
interface name for private shaping.

Install controller dependencies in a disposable environment using
[`requirements-campaign.txt`](../../benchmarks/requirements-campaign.txt).
After qualification and lease review, one command publishes and runs all selected
implementations on each owned fleet:

```sh
python3 scripts/aliyun_bench.py campaign \
  --config benchmarks/configs/compact-campaign.native-services.json \
  --execute --authorization PRIVATE_EXECUTION.json \
  --output results/local/aliyun-compact-campaign
```

It validates configuration, spec, archives, current runtime and budget bindings
before cloud acquisition. It reuses artifacts and the fleet within each committee,
uses fresh stores, interleaves protocols at each input rate, verifies/reduces
evidence, writes CSV/plots and deletes exact owned resources. Paid operations
remain protected by the saved lease and aggregate budget.

A new trial requires 30 minutes of remaining lease time for preparation,
verification, bounded export and deletion. This reserve is not an extra workload
window. Check actual export cost in the qualification pilot: 5 Mbps public links
can dominate collection despite gzip and concurrent transfers. If a matrix
does not fit its lease, retain unrun cells and review a new bounded plan; the
controller does not silently extend a lease.

## Results and restart behavior

- `state.json`: plan/artifact/runtime bindings, trial status, current dispatch,
  fleet cleanup and plot status.
- `resolved/`: requested/effective configuration for every dispatched cell.
- `trials/`: source/build identities, per-host evidence, typed verification,
  cohorts, calibration, resource and cleanup records. Secret keys stay outside
  exported evidence. Controller configuration packages containing keys are private.
- `results.csv`: useful goodput, admission/completion fractions, unfinished work,
  p50/p95/p99, and separate measurement/total sampled stream-write counts.
- `figures/`: healthy latency/goodput, completion and traffic diagnostics. Censored
  quantiles are not plotted as zero. Failed, interrupted and unrun cells remain
  in the table, even when no curve can be drawn.

Traffic retains native boundaries, including TLS and worker-local links where
present; it does not assert identical services or kernel-byte accounting. The
plotted mean rate divides measurement bytes by 60 seconds and committee size;
inspect timing quality and per-host samples.

Repeating an unchanged completed command is a no-op. An in-flight record causes
owned-fleet cleanup, preserves the ambiguous trial and refuses implicit reruns.
A failed campaign stays terminal. A closed lease cannot be reopened; use a new
reviewed lease identity and plan. Interrupted publication may need manual evidence
inspection. Cloud auto-release remains independent of the controller, and an
unconfirmed deletion remains an error.

The fault-rate selector requires a common accepted healthy rate. It does not
tune per protocol. If no common point qualifies, fault cells remain `not_run`.
Process absence and selective omission are named faults, not arbitrary Byzantine
execution. Outputs stay diagnostic until the active plan's qualification gates pass.
