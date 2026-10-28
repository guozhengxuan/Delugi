# Reusable Fabric benchmark

Edit `parameters.json` for each experiment. Keep `settings.json` and `.state/`
for the deployment. `fab remote` resolves the whole selected matrix, checks
artifact identities, creates or reuses the saved fleet, publishes each unchanged
binary once, runs the configurations, verifies output, and retains logs/results.
No per-run Python script or manually copied authorization hash is needed.

This follows the configuration split in
[Narwhal's benchmark](https://github.com/asonnino/narwhal/tree/master/benchmark)
and `Loom/benchmark`: saved cloud settings, benchmark parameters, node parameters,
an instance manager, and a small Fabric entry point. Narwhal's Rust `Parameters`
and `Committee` are loaded by its node factory; here the two common cores load
one shared `TransportConfig`. Consensus policy stays in `core/delugi` and
`core/raptr`; existing network, storage, crypto and evidence machinery is reused.

```text
benchmark/
  fabfile.py                  commands; no protocol policy
  bench/config.py             deployment settings + bench/node validation
  bench/instance.py           saved fleets, host authentication, WAN overlay
  bench/remote.py             publications, campaign execution and resume
  settings.example.json      reusable deployment configuration
  parameters.example.json    one common experiment configuration
  .state/                    private inventories, artifacts, leases and runs
scripts/
  campaign_adapters.py        requested → effective native configuration
  evaluation_parameters.py   shared transport units and native tuning validation
  campaign_execute.py        finite runs, evidence, results and failure handling
shared/network/               configurable common TCP transport
```

## Setup once

Install `benchmark/requirements.txt` in a virtual environment. The local
`benchmarks/.cache/aliyun-python` environment already contains Fabric. From this
folder, import Loom's saved settings and the existing reviewed regional leases:

```sh
fab init --loom=../../Loom/benchmark/settings.json \
  --lease-plans=/absolute/singapore-lease.json,/absolute/frankfurt-lease.json,/absolute/london-lease.json,/absolute/seoul-lease.json
```

Both original lease state files and standalone lease plans are accepted. This
copies configuration and credential **paths**, never credential contents. It
creates no cloud resources. The imported lease plans live under `.state/` and
retain the aggregate spending ledger, region, VPC/subnet, image, instance type,
disk, bandwidth, controller address and expiry. New fleets use new ownership
identities; the old instances are never reopened or repurposed.

Alternatively pass `--inventory=/absolute/existing-hosts.json` instead of lease
plans. That inventory must already contain authenticated host keys and a working
private network. Instance lifecycle commands do not delete externally supplied
hosts. `settings.example.json` shows this mode. For another committee size, add
its saved lease plans/inventory under `settings.testbeds` once.

Select the immutable binaries once in `.state/artifacts.json`, using
[`compact-artifacts.example.json`](../benchmarks/configs/compact-artifacts.example.json).
A superset catalog can retain all six implementations while individual parameter
files select a subset. Saved `protocol_options` can also cover all six; changing
`bench.protocols` automatically selects their options without deleting the rest. The existing
[build/publication runbook](../docs/evaluation/compact-campaign.md#prepare-reusable-artifacts-once-per-source-revision)
prepares these binaries once per source revision. Runs never compile code during
measurement. A changed source/runtime requires a rebuilt common Linux publication;
stale artifacts fail **before** fleet acquisition.

The current private setup retains the four regional templates and native artifact
references. The rebuilt common Linux archive and local verifier have completed
the four-region Fabric rerun. Its [record](../benchmarks/results/fabric-wan-2026-10-28/record.json)
and [figure](../benchmarks/results/fabric-wan-2026-10-28/latency-throughput-end_to_end.pdf)
include Delugi's incomplete silent-leader cohort. The fleet has been deleted;
future creation needs enough remaining aggregate budget reservation.

## Run and reuse

```sh
fab plan --output=/absolute/new-resolved-plan.json  # offline; inspect all effective values
fab remote                                       # one deployment/run/collection step
fab logs                                         # saved table and figure paths
fab info                                         # saved fleet identity and expiry
fab destroy                                      # delete owned instances/groups
```

`fab create` and `fab install` are optional separate preparation steps.
`fab start`/`fab stop` operate on exact saved instances. Stopping leaves disks
billable. With `settings.keep_alive=true`, successful runs retain the fleet until
its existing provider expiry or `fab destroy`. Set it to `false` to delete the
fleet after collection. A failure destroys the owned fleet even when reuse was
requested. Ambiguous in-flight runs are retained and never automatically repeated.
Cleanup commands do not require a valid parameter file, paper snapshot or binary.

A run directory is selected by the resolved plan hash. Repeating `fab remote`
with identical parameters resumes/returns that record without another workload.
Changing parameters produces a new immutable run directory and reuses the live
fleet and unchanged publications. `--name=explicit-new-label` deliberately selects
a new run. A controller lock prevents simultaneous runs or lifecycle changes on
the same saved testbed. Every run retains the requested config, effective configs,
source bindings, results CSV and raw evidence directories.

## Parameters and units

| Location | Controls |
| --- | --- |
| `bench` | protocol selection; `nodes` (4/10/50); scalar/list total honest `rate`; useful `tx_size` in bytes; duration (1–60 seconds); drain (0–15); runs (1–10); seed; cases; faulty count |
| `bench.fault_rate` | Explicit common fault-run rate, or `null` to select from accepted healthy results |
| `node` | Added one-way delay in milliseconds, aggregate validator egress Mbps, common Δ in milliseconds, native batching controls and proposal limits |
| `node.transport` | Shared Delugi/Raptr TCP connect, ACK, I/O, incomplete-frame and reconnect deadlines in milliseconds; inbox/outbox/deferred/window capacities and byte budgets; reader-connection limit |
| `node.protocol_options` | Per-core transport overrides; Delugi arrival queue/resource profile; Raptr native consensus, Quorum Store and runtime limits; native startup delay and supported batching overrides |
| `settings` | Saved testbeds; shared ports; SSH timeout/keepalive; whole-host CPU/RAM budget; provisioning/install/cleanup time budgets; fleet reuse |
| `settings.testbeds.*.overlay` | Private subnet, UDP port, MTU and keepalive; derived committee size; exact peer routes |
| saved regional lease plans | Region, image, VPC/subnet, keypair, instance type, disk GiB, public bandwidth, finite lifetime, live quote and aggregate budget binding |

The example selects the requested **12 trials**: six implementations × healthy
and silent-first-leader, 4 nodes, 100 total honest tx/s, 1 useful byte, 60 seconds,
Δ=1,000 ms and no injected WAN delay. The transport example uses 5,000 ms connect,
30,000 ms ACK/frame deadlines, 1,000 ms I/O and 100 ms reconnect delay. These are
explicit experiment settings, independent of Δ; they do not enter the consensus
timer calculation. The built-in connection default is now 5 seconds as well.
Missing queue overrides preserve the selected core's resource profile; snapshots
record the effective values. Unsupported or misspelled options fail offline.

The generic `configured-evaluation-v1` lease profile supports adjustable ECS
type/disk/bandwidth/peer ports within validated bounds, with a live quote and
aggregate budget reservation. Existing historical lease profiles retain their
original restrictions. Keep the saved Loom settings' instance type/key/regions
consistent with a new regional plan. Public cloud bandwidth and aggregate
protocol shaping are separate limits; the smaller physical limit still applies.

Not every native implementation exposes the same control. `batching` is a common
request: the adapter rejects it if any selected protocol cannot enforce it.
Per-protocol `batching` overrides are available on supported native adapters;
Raptr exposes its native `quorum_store` fields (for example
`sender_max_batch_txns`, `sender_max_batch_bytes`, and
`batch_generation_max_interval_ms`) rather than claiming a common useful-byte
batch cap. The allowed numeric native fields are listed in
[`evaluation_parameters.py`](../scripts/evaluation_parameters.py).

Common proposal byte/reference caps are currently unsupported and must be
`null`; truncating Delugi's all-current proposal would change its semantics.
The current fault hooks support healthy (`faults=0`) or one fixed faulty identity
(`faults=1`), with `silent-first-leader` and `missing-data` cases. A larger value
is rejected rather than approximated by a single fault. Native role ports and
algorithm constants without an exposed adapter remain protocol-specific.

## Checks completed for this change

The shared transport and Delugi unit tests pass, including the round-4 and
silent-leader recovery fixtures. A real TCP pipeline test verifies that the
configured timeout reaches the recorded runtime limits. Four short local process
checks (healthy/silent leader for both common cores) completed all 80 scheduled
requests per run, with `connect_timeout_ms=5678` visible in runtime evidence.
These development-build checks establish configuration wiring and functional
progress; they are not WAN latency/throughput measurements.

Controller tests cover fixed fault rates, non-default durations, invalid settings,
artifact rejection before paid operations, publication reuse, repeat-command
idempotency, failure cleanup, and adjustable SSH/overlay parameters. The old WAN
results remain unchanged. The two-attempt allowance for that verification has
been exhausted; a new bounded remote matrix must be selected before more runs.

## Build, download, parse and plot with Fabric

Delugi also supports bounded latency-stage tracing and offline `fab decompose`.
See [the stage boundaries, trace settings and REPORT scheduling revision](../docs/evaluation/latency-decomposition.md).
The `history_ready` REPORT schedule is the default; `admission` retains the old
composition schedule for explicit comparisons. Both are recorded in results.

`bench/logs.py` and `bench/plot.py` adopt Narwhal's separation of per-run parsing,
summary export and publication figures ([logs.py](https://github.com/asonnino/narwhal/blob/master/benchmark/benchmark/logs.py),
[plot.py](https://github.com/asonnino/narwhal/blob/master/benchmark/benchmark/plot.py)).
Here the parser checks frozen result hashes and derives metrics from verified
request identities. Missing completions remain censored; missing latency is never
zero. Both protocols use origin-local monotonic clocks and contiguous,
payload-verified output. No remote clock is subtracted from an origin clock.

```sh
fab create                        # reuse the saved regional deployment
fab build                         # committed/pushed common sources, asynchronous
fab build-status                  # inspect progress, no repeated dispatch
fab build-collect                 # collect and select the completed Linux archive
fab remote --name=wan-check        # all selected configurations, once each
fab logs --name=wan-check          # CSV, JSON and text summary
fab download --name=wan-check      # bundle the raw logs already fetched by remote
fab plot --name=wan-check          # scheduled-arrival → verified-output latency
fab plot --name=wan-check --endpoint=admission
fab destroy                       # needed if keep_alive=true
```

Use `keep_alive=true` during build preparation and `false` before `remote` for
automatic teardown after collection. Build dispatch never starts validators.
The remote build runs the pinned release tests and removes its Cargo target.
`build-collect` updates only the common publication in the reusable catalog;
native archives and the local verifier are preserved.

Figures show median points and p95 whiskers separately for healthy and fault
cases. A censored percentile is an upward lower-bound arrow. These are request
percentiles, not repetition confidence intervals. At one configured input rate,
the figure contains one measured point per protocol/case, not a capacity curve.
Throughput counts exact useful completions inside the measurement window;
latency follows the planned request cohort through its bounded drain.
The execution status `passed`/`completed` is distinct from the exported
`cohort_status`: unfinished requests remain an unsuccessful load qualification
even when agreement checks pass. `fab plot --scale=auto` uses a labeled logarithmic
latency axis when the range spans at least 20×; `linear` and `log` are explicit
overrides. Unfinished counts are printed on the figure.

If the controller's public address changes, `fab access --cidr=A.B.C.D/32`
updates only port 22 on the exact tagged security groups and removes the old
controller rule. It records the effective address separately from the immutable
paid lease plan. It never opens a subnet or changes protocol peer rules. Then
`fab create` resumes setup on the same machines without another paid allocation.
