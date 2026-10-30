# Saved healthy Raptr: first-local-inclusion verification

`analyze.py` reads the existing `raptr-wan-stages-20261029` healthy trial and
revalidates the signed archive/file bindings through the existing reducer. It
covers all 3,000 requests with zero exclusions. No execution or networking is
performed.

The execution-associated proposal is also the **first locally accepted proposal
containing the exact batch** for every measured request in this healthy run.
This is established from complete contents, not inferred from round number:

- Every recorded committed proposal commits its whole prefix (`include_proofs`,
  sub-blocks 0 through 7). Each has all nine corresponding output sections.
- The output publisher retains batch entries even when exact-batch output credit
  is deduplicated (`core/raptr/src/output.rs`, lines 467–478). Every observed batch
  occurs exactly once in each node's journal here.
- All locally accepted proposals up to every measured request's associated
  proposal have complete committed contents in those sections.
- Only terminal round 294/295 proposals lack complete output membership. Their
  local acceptance times are after every measured request's associated proposal
  (latest associated rounds are 196/200/200/198).

Therefore correcting Raptr's existing healthy midpoint to first **local**
inclusion produces zero shift. This does not recover first leader emission,
which requires a different clock boundary.

The origin=execution-leader diagnostic covers 950 requests in 252 exact batches:

| Span | Mean ms | Minimum ms | Maximum ms |
|---|---:|---:|---:|
| Admission to stored batch | 73.474 | 0.762 | 151.189 |
| Stored batch to local proposal acceptance | 132.898 | 35.087 | 256.646 |
| Stored batch to local PoA | 178.880 | 159.363 | 219.174 |

For these requests, no earlier proposal by that same leader occurs between
`stored + 30 ms` and the associated proposal. This only checks a conservative
age-ready milestone; it does not prove exact payload-pull eligibility.

Actual implementation gates differ from the abstract delay calculation:

- The 30 ms optimistic minimum age is measured from a batch creation wall-clock
  timestamp inferred from its expiration, **not** from arrival at the proposer.
  WAN transport can already consume that age. Adding 30 ms after receipt would
  misdescribe the implementation (`batch_proof_queue.rs`, lines 619–638).
- Upon round entry, the leader awaits `prepare_block`, then signs and multicasts
  the result. Payload pulling can return a non-full or empty payload immediately
  with the native pending-ordering configuration. The 150 ms maximum polling
  setting is not a mandatory 150 ms preproposal wait (`protocol.rs`, lines
  1043–1084; `dissemination.rs`, lines 208–254; `quorum_store_client.rs`, lines
  110–158).
- `BatchStored` is intentionally recorded only for producer-local payloads.
  Foreign batch arrival, payload-pull selection, and proposal outbox events are
  absent. Thus the saved trace cannot directly measure remote arrival-to-pull
  waiting at a leader.

The retained native binary exists, but its Raptr node factory calls `Transport::bind`
with the same configured address list for listeners and peers. Its public config
has no separate bind/advertised-address override. A delay-proxy run using this
binary therefore needs an adapter change/rebuild or kernel shaping; no such run
was performed for this audit.

Run `python3 analyze.py` from this directory to reproduce `summary.json` and
request-level local intermediates. The summary retains source/file hashes.
