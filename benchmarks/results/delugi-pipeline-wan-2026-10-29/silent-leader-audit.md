# New WAN silent-case diagnosis: the early snapshot misses the recovery anchor

The new four-region run confirms the previously identified local mechanism.
All **3,000/3,000** scheduled requests were admitted, completed and fully joined
to the latency trace; no requests were excluded from these means.

| Transaction-weighted stage | New pipeline WAN, ms | Previous history-ready WAN, ms |
|---|---:|---:|
| Batch formation | 0.631 | 0.665 |
| Await execution proposal | 3,847.897 | 3,472.675 |
| Agreement after local proposal validation | 236.817 | 242.196 |
| Contiguous prefix wait | **6,655.111** | **462.063** |
| Payload wait | 0.425 | 1.052 |
| Application append | 1.510 | 1.794 |
| Total | **10,742.390** | **4,180.446** |

The total increased by 6,561.945 ms; **6,193.047 ms (94.4%)** of that increase
is contiguous-prefix waiting. The new execution distribution explains it:

| First execution position in each four-round cycle | New requests | Mean prefix wait, ms | Previous requests |
|---|---:|---:|---:|
| First honest anchor, round mod 4 = 2 | **2,811** | **7,088.344** | 0 |
| Second honest anchor, round mod 4 = 3 | 6 | 6,665.196 | 212 |
| Third honest anchor, round mod 4 = 0 | 183 | 0.029 | **2,788** |

The six observed third-anchor proposals across the new full trace, including
drain, hold their fixed inputs for **6,629.630 ms** on average before emission.
That statistic is round weighted. First-anchor execution inputs themselves are
young: their request-weighted age is 8.655 ms, median 0.292 ms. A mean weighted
only by requests entering third anchors would hide most of the missed traffic.

## One exact request demonstrates the cause

All timestamps below use replica 3's monotonic clock. This request is selected
at the median admission time among the 904 origin-3 requests that demonstrably
arrived after the preceding third anchor froze but before that anchor proposed.

Request identity:
`609983941cf7338978c60f1cadca896109f767a1712e6257e43d6b0965c1dd2c`
(origin 3, sequence 500).

| Event | Time, ms |
|---|---:|
| REPORT(12), the third anchor after silent round 9 | 17,242.140 |
| Input(12) fixed | **17,493.923** |
| Request admitted | **19,823.828** |
| Its exact batch sealed | 19,824.108 |
| NoCER(9) | 23,999.359 |
| HISTORY3 quorum permits proposal 12 | 24,239.677 |
| PROPOSE(12) emitted | 24,239.951 |
| Request's execution proposal 14 locally validated | 24,383.067 |
| Round 14 classified committed | 24,622.876 |
| NoCER(13), the next silent leader | **31,240.909** |
| PROPOSE(16), the next third honest anchor | 31,242.839 |
| Round 14 released by the contiguous scanner | 31,485.651 |
| Request appended | 31,488.481 |

Input 12 was already immutable **2,329.905 ms before this request existed**.
It therefore could not include the request when the third anchor finally
proposed. The request enters the first anchor of the next cycle, round 14,
commits promptly, and then waits **6,862.775 ms** behind the next silent round.
Its total admission-to-output latency is **11,664.653 ms**.

This is the same freshness mechanism seen locally. Bounded lookahead limits
how many future inputs are prepared, but does not bound their age in elapsed
time while HISTORY3 waits for a missing leader. Early preparation improves the
healthy pipeline while late third-anchor collection had incorporated most
timeout-period arrivals into the anchor that immediately releases the prefix.

The evidence identifies a **composition/freshness tradeoff**, not slow CER
collection, a transport ACK gate, or a safety failure. The immutable input and
contiguous-output rules behaved as implemented. Refreshing a fixed input
would require a separately reviewed composition change; this audit makes no
protocol modification.

## Evidence and scope

New run:
`benchmark/.state/runs/delugi-pipeline-wan-20261029-clock-aligned`, silent trial
`d22bcc884402d1e925c4eed8`.

Old run:
`benchmark/.state/runs/delugi-raptr-wan-30s-20261028`, silent trial
`b5619611ae844d5a1d749182`.

Both use four regions, 30 seconds at 100 tx/s, one useful byte, Δ=1,000 ms,
20 Mbps, and persistent silence at replica 0. The executions occurred at
different times; the table is an observed before/after comparison, not an
isolation of every environmental effect. The concrete causal chain uses only
the new run and one clock. The previous history-ready trace independently
shows late third-anchor REPORT collection and 2,788 third-anchor executions.

`silent-leader-audit.json` and `fault-mechanism-old-wan-audit.json` retain
source hashes, exact cohorts, execution-position counts, leader-local input
ages, and the selected request. `audit_fault.py` re-reads frozen evidence,
checks result/trace hashes, preserves missing/unfinished requests, and performs
no cloud operation or workload execution.
