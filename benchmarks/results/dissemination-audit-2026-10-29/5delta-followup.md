# Reconsidering equal five-delay paths and the primary split

## Author clarification: restore the one-delay pipeline

The author clarified that the intended healthy execution sends the next
dissemination and ordering wave together after the appropriate n−f round
messages arrive. It must emit one new proposal per δ in steady state. The
2,3,6,7,… sequence below describes the implemented composition's extra gates;
it is not the intended Delugi cadence or a reason to accept that slower cadence.

Define B_r as the communication boundary that emits proposal P_r. The intended
steady pipeline can overlap these sends:

| At B_r | Destination / purpose |
|---|---|
| PROPOSE(r), VOTE(r−1), CER(r−2) | Ordering recipients |
| HISTORY3(r−2), with corresponding CLOSED when enabled | History goes to L(r+1) |
| OBS(r+1) | Reply to the already received REPORT; goes to L(r+1) |
| REPORT(r+2) | L(r+2) opens preparation two proposal positions ahead |
| PROG(r+2) | Advance admission while current proposals finish |

Then REPORT(r+2) at B_r → OBS(r+2) at B_(r+1) → prepared proposal(r+2) at
B_(r+2). Two-delay preparation and one-delay proposal spacing are compatible
because different opportunities overlap. At B_r the admission index is r+2;
communication boundaries, admission indices and proposal indices are distinct.
Each message retains its authenticated evidence, quorum and once-only guards;
this table describes the healthy steady wave, not a universal wait-for-all
barrier under faults.

Two implemented gates prevent this wave:

1. `ProgressPacing` holds originating PROG(r+2) until complete proposal(r+1)
   or proposal(r+2), which is unavailable at B_r. See
   [the configured rule](../../../core/delugi/src/replica.rs#L2275) and
   [its readiness predicate](../../../core/delugi/src/replica.rs#L2587).
2. `HistoryReady` holds REPORT(r+2) until HISTORY3(r−1). Those reports leave
   with CER(r−1) at B_(r+1) and arrive at B_(r+2), when proposal(r+2) should
   already be ready. See [REPORT admission](../../../core/delugi/src/composed.rs#L300)
   and [history readiness](../../../core/delugi/src/replica.rs#L2341).

Immediate transport bundling groups messages already enabled by these guards;
it does not remove the gates or create the intended cross-layer wave. The next
implementation work must restore the two-position preparation lead and verify
δ-spaced proposals in the real implementation while retaining the silent-leader
stale-input regression. No core change is made by this clarification.

## Prior five-delay audit

The previous explanation based on Raptr's optimistic certificate overlap was
incomplete. Raptr's published five-delay calculation already includes that
optimization. It cannot, by itself, explain the difference from a Delugi path
claimed to take the same five delays.

## What the two delay counts assume

[Raptr §5.4](https://arxiv.org/html/2504.18649v2#S5.SS4) assigns one delay to batch
transmission, one average delay to inclusion with proposals spaced two delays
apart, and three delays to consensus. The inclusion term assumes an arrival
phase distribution; five delays is not a per-transaction minimum. Its
[definitions](https://arxiv.org/html/2504.18649v2#S2.SS2) place the stage boundary
at leader proposal multicast.

Delugi's pinned dissemination specification has two distinct two-delay results:

- Input preparation after round entry produces some valid input, permitting
  equality fallback (`dissemination.tex:830–843`).
- The productive evidence path starts at batch emission and requires the needed
  reporters to receive those batches and emit their snapshots by one delay,
  and the leader to possess the exact source/proof state by two delays
  (`dissemination.tex:859–885`).

The latter explicitly requires a favorable reporting schedule. The same source
calls execution-inclusive three-to-five delays a favorable integration target
(`dissemination.tex:887–894`). Neither result supplies the missing average
arrival-phase argument for an arbitrary transaction stream. Source identities
are bound in [the original audit](obs_order_statistics.json).

## The dependency that requires investigation

The tested composition opens one REPORT after admission and exact history
readiness, snapshots once at each recipient, freezes the first n−f OBS pool,
and constructs the proposal. The signed observations cannot incorporate bytes
that arrive after those snapshots. A transaction can therefore miss an
opportunity even while that opportunity's proposal is still being prepared.

For a batch sealed at time s, let u_r be an opportunity's REPORT opening and
P_r its proposal emission. In a zero-processing homogeneous-delay illustration,
remote REPORT snapshots occur at u_r+δ and their replies reach the leader at
u_r+2δ. If the batch is broadcast just after u_r, its copies arrive just after
those remote snapshots. At most its own producer can report it; that is
insufficient for f+1 witnesses when f≥1. It waits for another suitable REPORT.

Under the additional assumptions of complete productive source state, sufficient
current witnesses, no history/admission delay after REPORT, and immediate
construction, the comparison is:

```text
Raptr:  batch broadcast → one-way batch arrival → next eligible proposal
Delugi: batch broadcast → suitable REPORT opportunity → OBS round trip → proposal
```

The REPORT outbound leg can overlap payload dissemination when their timing is
aligned. Waiting for that alignment or missing a snapshot is the omitted phase
cost. A favorable batch aligned with REPORT can still reach evidence in 2δ;
that does not make every random arrival's average preparation cost 2δ.

For regular REPORT spacing S and uniform arrival phase in this illustration,
Delugi's batch-to-proposal mean is 2δ+S/2. For Raptr with regular proposal
spacing B it is δ+B/2, giving 2δ when B=2δ. For varying intervals and independent
stationary arrivals, the residual phase term is E[I²]/(2E[I]), not generally
E[I]/2. These are conditional timing models, not fitted explanations of the WAN
gap. Real snapshot support, local source state and timing determine which
opportunity can actually include each exact batch.

The current PROG pacing also couples later admission to receipt of a neighboring
full proposal (`core/delugi/src/replica.rs:2275–2281`), so the paper's ready
one-delay pipeline cannot simply be assumed for the composed implementation.
This is separate from a long HISTORY3 computation after admission: that interval
was small in the healthy archive.

For fixed admission e, history readiness h and preparation duration A, the
reference overlapping schedule proposes at max(h,e+A), while HistoryReady
proposes at max(e,h)+A. The direct serialization penalty is
min(A,max(h−e,0)). The measured small admission→REPORT interval bounds this
direct penalty in the selected healthy requests. It does not qualify the
opportunity cadence created by the combined pacing and preparation rules.

## Code-derived timing model

The [event model](ideal_cadence.py) includes four replicas, self delivery,
f+1 PROG/CER amplification, n−f quorums, VOTE/CER admission guards and exact
contiguous HISTORY3 production. All remote messages take δ; CPU and payload/
proof readiness costs are zero; pacing deadlines exceed 2δ. This is an
analytical abstraction, not a run of the Rust implementation.

| Schedule | Proposal times, in δ | Repeating REPORT gaps | Average residual REPORT wait |
|---|---|---|---|
| Canonical PROG, REPORT on admission | 2, 3, 4, 5, … | 1 | 0.5δ |
| Canonical PROG, HistoryReady REPORT | 2, 3, 4, 7, 8, 9, … | 1, 1, 3 | 1.1δ |
| Current paced PROG, either REPORT policy | 2, 3, 6, 7, 10, 11, … | 1, 3 | 1.25δ |

Every modeled proposal follows its REPORT by 2δ and every direct commit follows
the proposal by 3δ. For the current alternating gaps, independent uniform
arrival phase gives (1²+3²)/(2(1+3))δ = 1.25δ waiting. If the first REPORT after
emission covers the transaction under the homogeneous-link and complete-source
assumptions, the conditional averages are **3.25δ to proposal and 6.25δ to direct
commit**. The model does not include batching, scanner release or application
output. Two separate source audits checked the guards and the sequences through
240 rounds; [the saved model output](ideal_cadence.json) contains 24 rounds per
variant and all assumptions. The simulation corroborates the periodic pattern;
the average also assumes earlier REPORTs are ineligible, as established in the
immediate-snapshot example above. It is not a general transaction-latency theorem.

For the current paced abstraction the repeating pattern follows the recurrence
e₁=0, e₂=δ, e_r=max(e_(r−1)+δ,p_(r−2)+2δ), and p_r=e_r+2δ. Before the earlier
qualifying proposal reaches remote replicas, only its leader can release the
held originating PROG; one signer cannot trigger f+1 amplification. Remote
reception and their next PROG transmission require two delays in total. If
proposal readiness already holds at entry, the next admission takes one delay.
Induction gives e_r=[4 floor((r−1)/2)+((r−1) mod 2)]δ. It also gives
p_(r−3)+3δ≤e_r (history ready), e_(r+1)≤p_r+δ (timely VOTE admission), and
e_(r+2)=p_r+2δ (timely CER admission), closing the assumed dependencies. This
argument applies to the stated timing abstraction only.

This explains why the actual composition cannot simply inherit an average
transaction-level five-delay claim. It does not assign a numerical fraction of
the WAN gap to pacing. In particular, changing HistoryReady back to admission
alone leaves the paced sequence unchanged in this healthy model; it would also
restore the previously observed stale-input risk under silent leaders.

## What the WAN cadence does and does not show

Same-leader four-round cycles avoid subtracting different host clocks and avoid
the alternating proposal-transit routes at a fixed foreign observer. Their
normalized cadence is approximately **146 ms per round for Delugi and 151 ms
for Raptr**. Raptr uses self-acceptance as a cadence proxy because emission was
not logged. Thus a claim that Delugi simply proposes less frequently in these
WAN runs is unsupported. The remaining question is which proposal can first
include a batch, given its reporters' snapshot cutoffs and source state.

The exact coverage and per-cycle records are retained in the cadence summaries;
the [Delugi summary](delugi-cadence-summary.json) and
[Raptr summary](raptr-cadence-summary.json) restrict both endpoints of each cycle
to the original local 30-second measurement window. They are separate from
request-weighted stage means. In a heterogeneous network,
two usable observations must satisfy the batch-arrival/snapshot relation inside
the frozen pool. For origin o, leader L and witness j, a simplified necessary
condition is s+d(o,j) ≤ u_r+d(L,j), together with matching branch/proof state.
Receiving a batch at the leader before pool closure does not imply that two
already-signed observations cover it.

## A simpler primary decomposition

Use three explicit events for every transaction:

| Event | Meaning |
|---|---|
| A | Successful admission at the origin |
| P | The leader finalizes the first valid proposal containing the exact transaction/batch and hands it to the outgoing consensus path |
| O | The origin accepts its payload-verified, contiguous application output |

**Dissemination = P−A. Consensus = O−P. Total = O−A.**

Batch formation and all inclusion waiting belong to dissemination. Proposal
transmission, voting, recovery after first inclusion, and application release
belong to consensus in this application-endpoint view. Detailed batching,
availability, decision and output spans remain diagnostics; they need not appear
as additional primary bars. A separate strict decision endpoint can test the
paper's three-delay consensus claim without conflating output processing.

Use the full labels **dissemination to first proposal** and **consensus/recovery
through verified contiguous output** in the figure caption. Preserve separate
censored counts for requests never proposed and requests proposed but unfinished.

P is proposal finalization/handoff, not local acceptance at another replica and
not the first socket byte. Use the same logical handoff boundary in both cores.
Record the first inclusion and the eventual execution-associated proposal
separately: choosing only the latter would move failed-inclusion/reproposal
waiting back into dissemination. Exact membership and proposal digest are
required, including prefixes that do not commit in the first proposal.

## What the saved archives can reconstruct

Delugi records logical PROPOSE outbox events. For its 928 requests whose origin
is also the execution leader, admission→outbox averages 269.928 ms and
outbox→origin output 204.149 ms, totaling 474.076 ms. This selected subset and
execution-associated midpoint do not represent the full 3,000-request first-
inclusion decomposition. Origin=eventual execution leader does not establish
origin=first proposing leader.

Raptr records proposal acceptance, including leader loopback acceptance, but no
proposal finalization/handoff event. Its native block wall-clock timestamp is
sampled before construction and is not an emission timestamp. Neither archive
contains enough proposed-batch membership to prove every transaction's first
inclusion. The existing all-request bars therefore cannot be relabeled as the
requested split.

For a general origin and leader, A/O and P use different clocks. A local
four-process test can record a common host monotonic clock. A remote test must
record qualified clock mappings and uncertainty; no subtraction of independent
elapsed clocks is valid. The total O−A remains an exact same-origin duration.
This instrumentation requirement changes observation, not consensus semantics.

The midpoint audit is reproducible with [midpoints.py](midpoints.py); its
[summary](midpoint-summary.json) retains coverage, explicit Raptr proxy labels
and source-validation bindings. Both archived source-bound decompositions were
rechecked at 3,000/3,000 requests with zero exclusions.

## Pro review and next diagnostic

In the continued [Pro discussion](https://chatgpt.com/c/6ad0826d-7048-83ec-b309-e09c2dca6590),
Pro explicitly revised the previous explanation: optimism is already counted
in Raptr's five-delay result, and snapshot-phase waiting is the missing
comparison. The [verbatim response](pro-5delta-consultation.json) independently
derives the illustrative 2δ+τ/2 transaction path for regular REPORT spacing τ.
The code-derived pacing model above was produced by the local source audit.

The [final focused review](pro-model-midpoint-consultation.json) accepts the
conditional 3.25δ/6.25δ arithmetic and the correction to **first valid inclusion**
as the primary midpoint. Pro's earlier response had recommended the
output-associated proposal. The follow-up resolves that distinction: if a valid
proposal A includes a batch but only later proposal B produces output, A→B is
consensus/recovery under the author's requested boundary. If R=P_out−P_first,
then D_out=D_first+R and C_first=C_out+R. Both definitions will remain explicit;
malformed proposals and un-emitted candidates do not establish first inclusion.

The immediate next step is observer-only capture of proposal handoff and exact
first-inclusion membership, plus REPORT/pool/source readiness, in a common-clock
local test. Vary arrival phase while preserving protocol rules. A certified-only
Raptr experiment is not the priority: it would measure the already-known cost
of removing optimism rather than test Delugi's productive opportunity timing.
No protocol implementation or cloud workload changed during this follow-up.

## Reproduce the offline checks

From the repository root, with the retained original archives present:

```sh
python3 benchmarks/results/dissemination-audit-2026-10-29/ideal_cadence.py
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/delugi-cadence.py
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/raptr-cadence.py
benchmarks/.cache/aliyun-python/bin/python benchmarks/results/dissemination-audit-2026-10-29/midpoints.py
```

The timing abstraction needs no archive and performs no protocol execution.
The other helpers only read retained evidence and regenerate the adjacent
summaries. [Validation](followup-validation.json) records the 240-round model
check; the midpoint summary records full-cohort source validation.
