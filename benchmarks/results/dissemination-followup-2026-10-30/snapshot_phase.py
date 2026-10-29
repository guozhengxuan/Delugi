#!/usr/bin/env python3
"""A conditional timing example, not a measured or universal Delugi bound.

Four honest nodes; all remote links take exactly DELAY_MS; local work is zero;
one REPORT opens per DELAY_MS; each reporter snapshots immediately on receipt;
the first three OBS form the immutable pool; two covering OBS and complete
leader source/proof state suffice for the one new batch. Healthy history and
ordering are already aligned, so proposal follows pool closure immediately and
direct commit is three delays later. Different remote tie orders are enumerated.

The simulator has only batch arrival, REPORT receipt/snapshot, and OBS receipt
events. It does not run the Rust implementation or model its other guards.
"""
import heapq
import itertools
import json
from pathlib import Path
from statistics import mean

N = 4
DELAY_MS = 10.0


def opportunity(batch_at, report_at, origin, leader, remote_order):
    held = [False] * N
    snapshot = {}
    pool = []
    events = []
    serial = 0

    def enqueue(at, kind, replica, value=None):
        nonlocal serial
        heapq.heappush(events, (at, serial, kind, replica, value))
        serial += 1

    # Away from equality there is no tie ambiguity. At equality, the batch is
    # delivered before the REPORT snapshot, explicitly defining the favorable
    # boundary case (the tests also use a strictly earlier batch).
    for replica in range(N):
        enqueue(batch_at + (0 if replica == origin else DELAY_MS), "batch", replica)
    enqueue(report_at, "report", leader)
    for replica in remote_order:
        enqueue(report_at + DELAY_MS, "report", replica)
    closed_at = None
    leader_ready_at_close = None
    while events:
        at, _, kind, replica, value = heapq.heappop(events)
        if kind == "batch":
            held[replica] = True
        elif kind == "report":
            assert replica not in snapshot
            snapshot[replica] = {"at_ms": at, "covers_batch": held[replica]}
            enqueue(at + (0 if replica == leader else DELAY_MS), "obs", replica,
                    held[replica])
        elif kind == "obs" and len(pool) < 3:
            pool.append({"reporter": replica, "at_ms": at, "covers_batch": value})
            if len(pool) == 3:
                closed_at = at
                leader_ready_at_close = held[leader]
    support = sum(item["covers_batch"] for item in pool)
    return {
        "report_at_ms": report_at, "leader": leader, "origin": origin,
        "pool": pool, "support": support, "pool_closed_at_ms": closed_at,
        "leader_source_ready": leader_ready_at_close,
        "productive": support >= 2 and leader_ready_at_close,
    }


def main():
    records = []
    checks = 0
    # Twenty midpoint phases uniformly partition each one-delay interval.
    for report_cycle in range(4, 8):
        preceding_at = report_cycle * DELAY_MS
        for origin in range(N):
            for phase_index in range(20):
                phase = (phase_index + 0.5) * DELAY_MS / 20
                batch_at = preceding_at + phase
                preceding_leader = report_cycle % N
                next_leader = (report_cycle + 1) % N
                # Every remote tie order: first-three selection cannot rescue
                # the preceding REPORT or spoil the next REPORT in this model.
                before = []
                after = []
                for leader, at, target in ((preceding_leader, preceding_at, before),
                                           (next_leader, preceding_at + DELAY_MS, after)):
                    for order in itertools.permutations(i for i in range(N) if i != leader):
                        result = opportunity(batch_at, at, origin, leader, order)
                        target.append(result)
                        checks += 1
                assert all(item["support"] <= 1 and not item["productive"] for item in before)
                assert all(item["support"] >= 2 and item["productive"] for item in after)
                proposal_at = after[0]["pool_closed_at_ms"]
                assert all(item["pool_closed_at_ms"] == proposal_at for item in after)
                records.append({
                    "origin": origin, "preceding_leader": preceding_leader,
                    "next_leader": next_leader, "phase_ms": phase,
                    "batch_to_proposal_ms": proposal_at - batch_at,
                    "batch_to_direct_commit_ms": proposal_at + 3 * DELAY_MS - batch_at,
                })
    for leader in range(N):
        for origin in range(N):
            for order in itertools.permutations(i for i in range(N) if i != leader):
                result = opportunity(100 - 0.000001, 100, origin, leader, order)
                assert result["productive"]
                checks += 1
    output = {
        "kind": "conditional-snapshot-phase-example-v1",
        "scope": __doc__,
        "delay_ms": DELAY_MS,
        "opportunity_simulations_checked": checks,
        "phase_origin_leader_cases": len(records),
        "means_ms": {
            "batch_to_proposal": mean(row["batch_to_proposal_ms"] for row in records),
            "batch_to_direct_commit": mean(row["batch_to_direct_commit_ms"] for row in records),
        },
        "conclusion": "For these assumptions, the next REPORT is first productive; "
                      "uniform arrival phase gives 2.5δ to proposal and 5.5δ to direct "
                      "commit. Alignment just before REPORT instead approaches 2δ and 5δ. "
                      "This demonstrates a possible phase cost despite δ proposal cadence; "
                      "it does not estimate the WAN latency gap.",
        "examples": [records[0], records[19], records[60], records[79]],
    }
    Path(__file__).with_suffix(".json").write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({k: output[k] for k in ("opportunity_simulations_checked", "phase_origin_leader_cases", "means_ms")}, indent=2))


if __name__ == "__main__":
    main()
