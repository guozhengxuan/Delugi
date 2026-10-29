#!/usr/bin/env python3
"""Zero-CPU, homogeneous-delay timing abstraction; not a protocol execution.

Includes every replica's self delivery, f+1 PROG/CER amplification, n-f quorums,
VOTE/CER admission guards, exact contiguous HISTORY3 production, and either
canonical or current proposal-gated originating PROG. Valid input takes a fresh
REPORT/OBS exchange. All nodes are honest; deadlines never fire; payload/proof
feasibility and cryptographic computation are assumed. Units are delta.
"""
from collections import defaultdict
import heapq
import itertools
import json
from pathlib import Path

N, F, QUORUM = 4, 1, 3


class Model:
    def __init__(self, paced, history_ready_reports, rounds=24):
        self.paced, self.history_ready_reports, self.rounds = paced, history_ready_reports, rounds
        self.events, self.serial, self.time = [], itertools.count(), 0
        self.nodes = [Node(self, replica) for replica in range(N)]

    def send(self, sender, kind, round_number, recipient=None):
        for receiver in range(N) if recipient is None else [recipient]:
            heapq.heappush(self.events, (self.time + int(sender != receiver),
                          next(self.serial), receiver, sender, kind, round_number))

    def run(self):
        for node in self.nodes:
            node.enter(1)
            node.drive()
        delivered = 0
        while self.events:
            self.time, _, receiver, sender, kind, round_number = heapq.heappop(self.events)
            node = self.nodes[receiver]
            node.receive(sender, kind, round_number)
            node.drive()
            delivered += 1
            assert delivered < 100000, 'nontermination in finite abstraction'
        rows = []
        for r in range(1, self.rounds + 1):
            leader = self.nodes[(r - 1) % N]
            row = {'round': r, 'leader': leader.id, 'entry': leader.entry[r],
                   'report': leader.report[r], 'input_ready': leader.input[r],
                   'proposal': leader.proposal[r],
                   'history_quorum': leader.history_ready.get(r - 3),
                   'commit_at_every_replica': [n.commit[r] for n in self.nodes]}
            assert len(set(row['commit_at_every_replica'])) == 1
            assert row['commit_at_every_replica'][0] == row['proposal'] + 3
            expected = (4 * ((r - 1) // 2) + 2 + (r - 1) % 2 if self.paced
                        else 5 * ((r - 1) // 3) + 2 + (r - 1) % 3
                        if self.history_ready_reports else r + 1)
            assert row['proposal'] == expected, (self.paced, row, expected)
            rows.append(row)
        report_gaps = [b['report'] - a['report'] for a, b in zip(rows, rows[1:])]
        period = next(p for p in range(1, len(report_gaps) + 1)
                      if all(g == report_gaps[i % p] for i, g in enumerate(report_gaps)))
        repeating_gaps = report_gaps[:period]
        phase_wait = sum(g * g for g in repeating_gaps) / (2 * sum(repeating_gaps))
        return {'schedule': 'progress_pacing' if self.paced else 'canonical',
                'report_schedule': 'history_ready' if self.history_ready_reports else 'admission',
                'delivered_events': delivered, 'rounds': rows,
                'maximum_pacing_hold': max((t - n.entry[r] for n in self.nodes
                    for r, t in n.progress_release.items()), default=0),
                'proposal_gaps': [b['proposal'] - a['proposal'] for a, b in zip(rows, rows[1:])],
                'repeating_report_gaps_delta': repeating_gaps,
                'steady_residual_report_wait_delta': phase_wait,
                'batch_emission_to_proposal_mean_delta_under_explicit_phase_assumptions': 2 + phase_wait,
                'batch_emission_to_direct_commit_mean_delta_under_explicit_phase_assumptions': 5 + phase_wait}


class Node:
    def __init__(self, model, replica):
        self.m, self.id, self.current = model, replica, 0
        self.entry, self.report, self.input, self.proposal = {}, {}, {}, {}
        self.progress_release, self.history_ready, self.commit = {}, {}, {}
        self.progress, self.votes, self.cers = [defaultdict(set) for _ in range(3)]
        self.observations, self.histories = defaultdict(set), defaultdict(set)
        self.got_proposal, self.report_answered = set(), set()
        self.sent_progress, self.sent_vote, self.sent_cer = set(), set(), set()
        self.history_sent = 0

    def enter(self, r):
        for entered in range(self.current + 1, r + 1):
            self.entry[entered] = self.m.time
            if entered == 1 or not self.m.paced:
                self.send_progress(entered)
        self.current = max(self.current, r)

    def send_progress(self, r):
        if r not in self.sent_progress:
            self.sent_progress.add(r)
            self.progress_release[r] = self.m.time
            self.m.send(self.id, 'PROG', r)

    def receive(self, sender, kind, r):
        if kind == 'PROG': self.progress[r].add(sender)
        elif kind == 'PROPOSE': self.got_proposal.add(r)
        elif kind == 'VOTE': self.votes[r].add(sender)
        elif kind == 'CER': self.cers[r].add(sender)
        elif kind == 'HISTORY3':
            self.histories[r].add(sender)
            if len(self.histories[r]) == QUORUM:
                self.history_ready[r] = self.m.time
        elif kind == 'REPORT':
            if r not in self.report_answered:
                assert sender == (r - 1) % N
                self.report_answered.add(r)
                self.m.send(self.id, 'OBS', r, recipient=sender)
        elif kind == 'OBS': self.observations[r].add(sender)
        else: raise ValueError(kind)

    def drive(self):
        while True:
            before = (self.current, len(self.sent_progress), len(self.report), len(self.input),
                      len(self.proposal), len(self.sent_vote), len(self.sent_cer),
                      self.history_sent, len(self.commit))
            for r in range(self.current, self.m.rounds + 2):
                if len(self.progress[r]) >= F + 1:
                    self.send_progress(r)  # amplification bypasses origin pacing
                if len(self.progress[r]) >= QUORUM:
                    self.enter(r + 1)
            for r in range(2, self.current + 1):
                if r - 1 in self.got_proposal or r in self.got_proposal:
                    self.send_progress(r)
            for r in range(1, self.m.rounds + 1):
                history_ready = r <= 3 or len(self.histories[r - 3]) >= QUORUM
                if ((r - 1) % N == self.id and self.current >= r
                        and (history_ready or not self.m.history_ready_reports)
                        and r not in self.report):
                    self.report[r] = self.m.time
                    self.m.send(self.id, 'REPORT', r)
                if len(self.observations[r]) >= QUORUM and r not in self.input:
                    self.input[r] = self.m.time
                if (r in self.input and history_ready and self.current >= r
                        and r not in self.proposal):
                    self.proposal[r] = self.m.time
                    self.m.send(self.id, 'PROPOSE', r)
                if r in self.got_proposal and self.current >= r + 1 and r not in self.sent_vote:
                    self.sent_vote.add(r)
                    self.m.send(self.id, 'VOTE', r)
                if (self.current >= r + 2 and r not in self.sent_cer
                        and (len(self.votes[r]) >= QUORUM or len(self.cers[r]) >= F + 1)):
                    self.sent_cer.add(r)
                    self.m.send(self.id, 'CER', r)
                if len(self.cers[r]) >= QUORUM and r not in self.commit:
                    self.commit[r] = self.m.time
            while self.history_sent + 1 in self.sent_cer and self.history_sent + 3 <= self.current:
                self.history_sent += 1
                h = self.history_sent
                self.m.send(self.id, 'HISTORY3', h, recipient=(h + 2) % N)
            after = (self.current, len(self.sent_progress), len(self.report), len(self.input),
                     len(self.proposal), len(self.sent_vote), len(self.sent_cer),
                     self.history_sent, len(self.commit))
            if before == after: return


def main():
    out = {
        'schema': 1, 'kind': 'analytical-event-timing-abstraction-not-implementation-test',
        'assumptions': ['n4 f1; all honest; homogeneous one-way delay delta exactly1; self delivery0',
                        'Zero CPU, unlimited transport, valid complete inputs after REPORT/OBS; no payload/proof feasibility delay',
                        'Aligned startup; pacing/main/catch-up deadlines inactive; pacing deadline greater than2delta permits the modeled hold',
                        'Exact HISTORY3(r-3) quorum and contiguous report prefix modeled; report schedule is an explicit variant',
                        'For transaction phase means only: uniform arrival phase relative to stationary REPORT epochs; tx can be covered by the first REPORT at or after emission; no batch formation delay'],
        'interpretation': 'These conditional results expose a dependency in current pacing. They are neither a measured WAN delta fit nor a proof of arbitrary transaction inclusion. The actual WAN is heterogeneous.',
        'source_rules': {'core/delugi/src/replica.rs': [2275, 2587, 2605, 2684, 3104, 3130],
                         'core/delugi/src/slot.rs': [125], 'core/delugi/src/composed.rs': [300, 336, 384]},
        'models': [Model(paced, ready).run() for paced, ready in
                   [(False, False), (False, True), (True, False), (True, True)]],
    }
    path = Path(__file__).with_suffix('.json')
    path.write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps({'output': str(path), 'models': [
        {k: v for k, v in m.items() if k != 'rounds'} | {'first10': m['rounds'][:10]}
        for m in out['models']]}, indent=2))


if __name__ == '__main__': main()
