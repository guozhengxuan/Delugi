# Real signed-core eligibility diagnostic

This diagnostic runs the unchanged Delugi Node implementation in deterministic
virtual time. Every network message is serialized and bounded-decoded; every
emitted proposal passes the real signature, history and Q checks. It is not a
wall-clock networking benchmark. CPU, disk, TCP queues, transport bundling and
serialization time are absent from the virtual delay budget.

The observer captures each actual input-construction snapshot before the next
network/workload event. It reconstructs the exact first-three pool, invokes the
public constructor against that same current store, and asserts that its value
and proof bytes match the actual emitted proposal. It separately checks each
already-broadcast batch for two covering observations and usable local source
proofs. No eligible-but-omitted batch was found.

The uniform experiment has 160 tagged batches, four origins, ten arrival phases
and four leader rotations. Every link takes 10 ms, self-delivery is immediate,
and chunk capacity is 4. Actual first-proposal latency is 25 ms on average and
output latency 55 ms. The 320 examined earlier batch/input pairs lack two covering
observations. This confirms the conditional 2.5δ mechanism in the implementation,
not only in the earlier abstract model.

WAN profiles each have 1,000 batches at 100 aggregate transactions/s, one already
sealed transaction per batch, 10 ms stagger between successive origins and 40 ms
per-origin intervals. They use chunk capacity 64 and Δ = 1,000 ms, canonical ordering,
pipeline REPORT scheduling and in-memory storage. Empty protocol startup lasts
2 s; load lasts 10 s, followed by up to 6 s of drain. This approximates steady-state
WAN scheduling; it does not replay the exact remote startup, batching, CPU or
clock offsets. The symmetric link matrix in milliseconds is:

```
0     80    87.5  32.2
80    0      6.75 97
87.5  6.75   0   120
32.2 97    120     0
```

Each value is half the mean of the two saved directional median RTTs. This is a
symmetry assumption, not a measured protocol one-way delay. Additional cases
shift the whole staggered load by 5 ms, halve all links, or reverse physical region
assignment along the rotating leader order. Exact per-case configuration is in
signed-core.json.

The selection-only counterfactual retains actual proposal times and actual
input snapshots, but marks a batch selectable when its local target suffix and
proof exist without the OBS support rule. This is an offline diagnostic, not a
valid modified Delugi protocol and not an estimate of Raptr performance. Its
reported time gain cannot be interpreted as an achievable speedup. With n = 4 the
producer-as-leader local shortcut also makes its uniform result differ from a
paper calculation charging every batch one remote transmission.

The authoritative final result is signed-core.json. The files with
initial-rounded-links and synchronous-ablation in their names retain earlier
sensitivity executions: they used simultaneous origin arrivals and chunk4 and
must not be presented as the matching WAN configuration.

Reproduce from the repository root:

```
CARGO_TARGET_DIR=/private/tmp/delugi-phase-eligibility-target cargo test --offline -p delugi-core --test phase_eligibility --release --no-run
DELUGI_PHASE_REPORT=results/local/phase-verification-20261030/core/signed-core.json /private/tmp/delugi-phase-eligibility-target/release/deps/phase_eligibility-786ae5388979c641 --ignored --nocapture
```

A retained executable, run stdout and build-record.json permit rerunning this
artifact without retaining build intermediates. Production Rust source files
were not modified.
