//! Signed, serialized executions of the real composed core in constant-delay
//! virtual time. This is a protocol regression, not a performance benchmark.
use delugi_core::availability::{genesis_binding, AvailabilityConfig, AvailabilityProof};
use delugi_core::batch::{BatchStore, Record};
use delugi_core::composed::{self, Effect, Node, ReportSchedule};
use delugi_core::end_to_end::transactions;
use delugi_core::history::{self, Entries, History};
use delugi_core::replica::{Effect as OrderingEffect, OrderingSchedule};
use delugi_core::scanner::Status;
use delugi_core::wire::{self, Committee, Digest, Id, Kind, Message, Proposal, Statement};
use std::collections::{BTreeMap, BTreeSet};

const N: Id = 4;
const DELTA: u64 = 10;
const BOUND: u64 = 100;

#[derive(Clone, Debug)]
enum Packet {
    Ordering(Message),
    Availability(composed::Message),
}

impl Packet {
    fn key(&self) -> (&'static str, u64) {
        match self {
            Self::Ordering(message) => delugi_core::simulation::message_kind(message),
            Self::Availability(message) => match message {
                composed::Message::Batch(record) => ("BATCH", record.header.body.height),
                composed::Message::Report { base, .. } => ("REPORT", base.opportunity),
                composed::Message::Observation(obs) => ("OBS", obs.body.opportunity),
                composed::Message::Fetch { target, .. } => ("FETCH", target.height),
                composed::Message::Data(data) => ("DATA", data.to.height),
                composed::Message::DataPart(part) => ("DATA", part.requested_to.height),
            },
        }
    }
}

#[derive(Clone, Debug)]
struct Sent {
    from: Id,
    to: Option<Id>,
    at: u64,
    packet: Packet,
}

#[derive(Clone, Debug)]
struct Received {
    to: Id,
    at: u64,
    packet: Packet,
}

enum Event {
    Start(Id),
    Produce(Id, u64),
    Timer(Id),
    Deliver {
        from: Id,
        to: Id,
        packet: Packet,
        reject: bool,
    },
}

struct Harness {
    committee: Committee,
    availability: AvailabilityConfig,
    nodes: Vec<Node>,
    silent: Option<Id>,
    delta: u64,
    now: u64,
    serial: u64,
    events: BTreeMap<(u64, u64), Event>,
    sent: Vec<Sent>,
    received: Vec<Received>,
    observations: BTreeMap<(Id, u64), u64>,
    notices: BTreeMap<(Id, String, u64), u64>,
    commits: BTreeMap<(Id, u64), (u64, Digest)>,
    rejected: usize,
}

fn leader(round: u64) -> Id {
    ((round - 1) % u64::from(N)) as Id
}

impl Harness {
    fn new(silent: Option<Id>, rounds: u64) -> Self {
        let committee = Committee::new(
            [91; 32],
            (0..N).map(|id| wire::fixture_key(id).public).collect(),
        )
        .unwrap();
        let availability = AvailabilityConfig::new(committee.clone(), 4).unwrap();
        let nodes = (0..N)
            .map(|id| {
                let mut node = Node::new(
                    committee.clone(),
                    id,
                    wire::fixture_key(id),
                    BOUND,
                    availability.clone(),
                    4,
                )
                .unwrap();
                node.ordering
                    .configure_ordering(OrderingSchedule::Canonical)
                    .unwrap();
                node.configure_report_schedule(ReportSchedule::Pipeline)
                    .unwrap();
                node.set_opportunity_limit(rounds).unwrap();
                node
            })
            .collect();
        Self {
            committee,
            availability,
            nodes,
            silent,
            delta: DELTA,
            now: 0,
            serial: 0,
            events: BTreeMap::new(),
            sent: vec![],
            received: vec![],
            observations: BTreeMap::new(),
            notices: BTreeMap::new(),
            commits: BTreeMap::new(),
            rejected: 0,
        }
    }

    fn schedule(&mut self, at: u64, event: Event) {
        self.events.insert((at, self.serial), event);
        self.serial += 1;
    }

    fn workload(&mut self, batches: u64, interval: u64) {
        for id in 0..N {
            if self.silent == Some(id) {
                continue;
            }
            for height in 1..=batches {
                self.schedule((height - 1) * interval, Event::Produce(id, height));
            }
            self.schedule(2 * self.delta, Event::Start(id));
        }
    }

    fn send(&mut self, from: Id, to: Option<Id>, packet: Packet) {
        self.sent.push(Sent {
            from,
            to,
            at: self.now,
            packet: packet.clone(),
        });
        // The actual cores already perform local self delivery; retain its
        // evidence for quorum checks, without delivering it a second time.
        if to.is_none() || to == Some(from) {
            self.received.push(Received {
                to: from,
                at: self.now,
                packet: packet.clone(),
            });
        }
        for recipient in to.map_or_else(|| (0..N).collect::<Vec<_>>(), |id| vec![id]) {
            if recipient != from {
                self.schedule(
                    self.now + self.delta,
                    Event::Deliver {
                        from,
                        to: recipient,
                        packet: packet.clone(),
                        reject: false,
                    },
                );
            }
        }
    }

    fn emit(&mut self, id: Id, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Ordering(effect) => match effect {
                    OrderingEffect::Send { to, message } => {
                        self.send(id, to, Packet::Ordering(message))
                    }
                    OrderingEffect::Wake { at } => self.schedule(at, Event::Timer(id)),
                    OrderingEffect::Notice { kind, round } => {
                        self.notices
                            .entry((id, kind.into(), round))
                            .or_insert(self.now);
                    }
                    OrderingEffect::DirectCommit { round, digest } => {
                        assert!(self
                            .commits
                            .insert((id, round), (self.now, digest))
                            .is_none());
                    }
                    OrderingEffect::Deliver(_) => {}
                },
                Effect::Send { to, message } => self.send(id, to, Packet::Availability(message)),
                Effect::Trace(_) => {}
            }
        }
        for &round in self.nodes[id as usize].observations.keys() {
            self.observations.entry((id, round)).or_insert(self.now);
        }
    }

    fn run_until(&mut self, until: u64) {
        let mut steps = 0;
        while self
            .events
            .first_key_value()
            .is_some_and(|(&(at, _), _)| at <= until)
        {
            let ((at, _), event) = self.events.pop_first().unwrap();
            self.now = at;
            let id = match &event {
                Event::Start(id) | Event::Timer(id) | Event::Produce(id, _) => *id,
                Event::Deliver { to, .. } => *to,
            };
            if self.silent == Some(id) {
                continue;
            }
            let effects = match event {
                Event::Start(_) => self.nodes[id as usize].start(at),
                Event::Timer(_) => self.nodes[id as usize].tick(at),
                Event::Produce(_, height) => self.nodes[id as usize]
                    .produce(at, wire::encode(&transactions(id, height, 1, 8)).unwrap()),
                Event::Deliver {
                    from,
                    packet,
                    reject,
                    ..
                } => {
                    // Serialize and bounded-decode every actual network delivery.
                    let result = match &packet {
                        Packet::Ordering(message) => {
                            let bytes = self.committee.encode(message).unwrap();
                            self.nodes[id as usize]
                                .receive_ordering(at, self.committee.decode(&bytes).unwrap())
                        }
                        Packet::Availability(message) => {
                            let bytes = self.committee.encode(message).unwrap();
                            self.nodes[id as usize].receive(
                                at,
                                from,
                                self.committee.decode(&bytes).unwrap(),
                            )
                        }
                    };
                    if reject {
                        assert!(result.is_err(), "invalid packet accepted: {packet:?}");
                        self.rejected += 1;
                        continue;
                    }
                    if result.is_ok() {
                        self.received.push(Received { to: id, at, packet });
                    }
                    result
                }
            }
            .unwrap_or_else(|error| panic!("replica {id} at {at}: {error}\n{}", self.step_trace()));
            self.emit(id, effects);
            steps += 1;
            assert!(steps < 1_000_000, "unbounded fixture event production");
        }
    }

    fn step_trace(&self) -> String {
        self.sent
            .iter()
            .filter(|s| !matches!(s.packet.key().0, "BATCH" | "FETCH" | "DATA"))
            .take(300)
            .map(|s| {
                format!(
                    "t={} node={} {}({}) to={:?}\n",
                    s.at,
                    s.from,
                    s.packet.key().0,
                    s.packet.key().1,
                    s.to
                )
            })
            .collect()
    }

    fn sends(&self, from: Id, kind: &str, round: u64) -> Vec<&Sent> {
        self.sent
            .iter()
            .filter(|s| s.from == from && s.packet.key() == (kind, round))
            .collect()
    }

    fn only_send_time(&self, from: Id, kind: &str, round: u64) -> u64 {
        let sends = self.sends(from, kind, round);
        assert_eq!(
            sends.len(),
            1,
            "node {from} {kind}({round})\n{}",
            self.step_trace()
        );
        sends[0].at
    }

    fn statement_signers(
        &self,
        to: Id,
        kind: Kind,
        round: u64,
        digest: Option<Digest>,
        by: u64,
    ) -> BTreeSet<Id> {
        self.received
            .iter()
            .filter(|r| r.to == to && r.at <= by)
            .filter_map(|r| {
                let statement = match &r.packet {
                    Packet::Ordering(Message::Vote { vote, .. }) => vote,
                    Packet::Ordering(Message::Prog(s) | Message::Cer(s) | Message::Closed(s)) => s,
                    _ => return None,
                };
                (statement.body.kind == kind
                    && statement.body.round == round
                    && statement.body.digest == digest)
                    .then_some(statement.signer)
            })
            .collect()
    }

    fn assert_typed_causality(&self) {
        for ((id, kind, round), at) in &self.notices {
            if kind == "admission" && *round > 1 {
                assert!(
                    self.statement_signers(*id, Kind::Prog, round - 1, None, *at)
                        .len()
                        >= 3,
                    "admission needs a same-round PROG quorum"
                );
            }
        }
        for sent in &self.sent {
            match &sent.packet {
                Packet::Ordering(Message::History3(report)) => {
                    assert_eq!(sent.to, Some(leader(report.header.body.horizon + 3)));
                }
                Packet::Ordering(
                    Message::Propose(_)
                    | Message::Vote { .. }
                    | Message::Cer(_)
                    | Message::Closed(_)
                    | Message::Prog(_),
                )
                | Packet::Availability(composed::Message::Report { .. }) => {
                    assert_eq!(sent.to, None, "this protocol message must be broadcast");
                }
                Packet::Availability(composed::Message::Observation(observation)) => {
                    assert_eq!(sent.to, Some(leader(observation.body.opportunity)));
                }
                _ => {}
            }
            if let Packet::Availability(composed::Message::Report { base, .. }) = &sent.packet {
                let completed_prefix = self
                    .sent
                    .iter()
                    .filter(|prior| prior.at <= sent.at && Some(prior.from) != self.silent)
                    .filter_map(|prior| match &prior.packet {
                        Packet::Ordering(Message::History3(report)) => {
                            Some(report.header.body.horizon)
                        }
                        _ => None,
                    })
                    .max()
                    .unwrap_or(0);
                assert!(
                    base.opportunity <= completed_prefix + 4,
                    "REPORT {} outran every correct completed prefix {}",
                    base.opportunity,
                    completed_prefix
                );
            }
            if let Packet::Ordering(message) = &sent.packet {
                match message {
                    Message::Vote { vote, .. } => {
                        self.committee.verify_statement(vote).unwrap();
                        assert!(
                            self.notices[&(sent.from, "admission".into(), vote.body.round + 1)]
                                <= sent.at
                        );
                        assert!(self.received.iter().any(|r| r.to == sent.from && r.at <= sent.at
                            && matches!(&r.packet, Packet::Ordering(Message::Propose(p))
                                if wire::proposal_digest(&p.header.body) == vote.body.digest.unwrap())));
                    }
                    Message::Cer(cer) => {
                        self.committee.verify_statement(cer).unwrap();
                        assert!(
                            self.notices[&(sent.from, "admission".into(), cer.body.round + 2)]
                                <= sent.at
                        );
                        let votes = self.statement_signers(
                            sent.from,
                            Kind::Vote,
                            cer.body.round,
                            cer.body.digest,
                            sent.at,
                        );
                        let mut cers = self.statement_signers(
                            sent.from,
                            Kind::Cer,
                            cer.body.round,
                            cer.body.digest,
                            sent.at,
                        );
                        // The CER currently being justified cannot count as
                        // one of its own amplification-trigger signatures.
                        cers.remove(&sent.from);
                        assert!(
                            votes.len() >= 3 || cers.len() >= 2,
                            "CER lacks typed trigger quorum"
                        );
                    }
                    Message::History3(report) => {
                        history::verify_report(&self.committee, report).unwrap();
                        for proof in &report.proofs {
                            assert!(
                                self.only_send_time(sent.from, "CER", proof.cer.body.round)
                                    <= sent.at
                            );
                        }
                    }
                    Message::Closed(closed) => {
                        assert!(
                            self.only_send_time(sent.from, "HISTORY3", closed.body.round)
                                <= sent.at
                        );
                    }
                    Message::Propose(proposal) => {
                        let round = proposal.header.body.round;
                        self.committee
                            .verify_proposal(proposal, |r, value, witness| {
                                self.availability.q(r, value, witness)
                            })
                            .unwrap();
                        let proof: AvailabilityProof =
                            self.committee.decode(&proposal.witness).unwrap();
                        assert_eq!(
                            proof
                                .pool
                                .iter()
                                .map(|o| o.signer)
                                .collect::<BTreeSet<_>>()
                                .len(),
                            3
                        );
                        for observation in &proof.pool {
                            assert_eq!(observation.body.opportunity, round);
                            if observation.signer == sent.from {
                                assert!(self.observations[&(sent.from, round)] <= sent.at);
                            } else {
                                assert!(self.received.iter().any(|r| r.to == sent.from && r.at <= sent.at
                                    && matches!(&r.packet, Packet::Availability(composed::Message::Observation(o)) if o == observation)));
                            }
                        }
                        if let History::Evidence { reports, .. } = &proposal.history {
                            assert_eq!(
                                reports
                                    .iter()
                                    .map(|h| h.signer)
                                    .collect::<BTreeSet<_>>()
                                    .len(),
                                3
                            );
                            for header in reports {
                                assert_eq!(header.body.horizon, round - 3);
                                assert!(self.received.iter().any(|r| r.to == sent.from && r.at <= sent.at
                                    && matches!(&r.packet, Packet::Ordering(Message::History3(h)) if h.header == *header)));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        for ((id, round), (at, digest)) in &self.commits {
            assert!(
                self.statement_signers(*id, Kind::Cer, *round, Some(*digest), *at)
                    .len()
                    >= 3,
                "direct commitment lacks a same-digest CER quorum"
            );
        }
    }
}

#[test]
fn healthy_pipeline_emits_the_complete_signed_wave_every_delta() {
    let mut run = Harness::new(None, 12);
    // Keep batches arriving across the measured waves, so equality-only inputs
    // cannot accidentally satisfy the pipeline regression.
    run.workload(12, DELTA);
    run.run_until(18 * DELTA);
    let startup = 2 * DELTA;
    for round in 1..=12 {
        let proposal_at = startup + (round + 1) * DELTA;
        assert_eq!(
            run.only_send_time(leader(round), "PROPOSE", round),
            proposal_at,
            "proposal round {round}\n{}",
            run.step_trace()
        );
        for id in 0..N {
            assert_eq!(run.commits[&(id, round)].0, proposal_at + 3 * DELTA);
        }
    }
    for round in 4..=10 {
        let wave = startup + (round + 1) * DELTA;
        assert_eq!(run.only_send_time(leader(round), "PROPOSE", round), wave);
        assert_eq!(
            run.only_send_time(leader(round + 2), "REPORT", round + 2),
            wave
        );
        for id in 0..N {
            // Local proposal validation and local OBS need no network hop.
            let vote_at = if id == leader(round - 1) {
                wave - DELTA
            } else {
                wave
            };
            assert_eq!(run.only_send_time(id, "VOTE", round - 1), vote_at);
            for kind in ["CER", "HISTORY3", "CLOSED"] {
                assert_eq!(
                    run.only_send_time(id, kind, round - 2),
                    wave,
                    "{kind} wave {round} replica {id}\n{}",
                    run.step_trace()
                );
            }
            assert_eq!(run.only_send_time(id, "PROG", round + 2), wave);
            if id == leader(round + 1) {
                assert_eq!(run.observations[&(id, round + 1)], wave - DELTA);
            } else {
                assert_eq!(run.only_send_time(id, "OBS", round + 1), wave);
            }
        }
    }
    run.assert_typed_causality();
    assert_eq!(run.nodes[0].executed.len(), 48);
    for node in &run.nodes {
        assert_eq!(node.executed, run.nodes[0].executed);
        assert_eq!(node.executed_rounds, (1..=12).collect::<Vec<_>>());
        for round in 4..=10 {
            assert!(
                node.materialized_batches
                    .iter()
                    .any(|batch| batch.round == round),
                "wave {round} carried no fresh payload"
            );
        }
    }
}

#[test]
fn silent_leader_pipeline_keeps_three_anchors_and_finishes_late_streamed_batches() {
    let mut run = Harness::new(Some(0), 12);
    run.workload(12, 100);
    run.run_until(3500);
    let expected: BTreeSet<_> = (1..N)
        .flat_map(|id| (1..=12).map(move |height| transactions(id, height, 1, 8)[0].id))
        .collect();
    for node in &run.nodes[1..] {
        assert_eq!(node.ordering.last_delivered(), 12);
        assert_eq!(node.executed, run.nodes[1].executed);
        assert_eq!(
            node.executed
                .iter()
                .map(|e| e.transaction)
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(node.executed.len(), expected.len());
        for silent_round in [1, 5, 9] {
            assert_eq!(node.ordering.statuses()[&silent_round], Status::Skip);
            for anchor in silent_round + 1..=silent_round + 3 {
                assert!(run.commits.contains_key(&(node.id, anchor)));
            }
            assert!(
                node.executed_at[&(silent_round + 1)]
                    >= run.commits[&(node.id, silent_round + 3)].0
            );
        }
    }
    for sent in &run.sent {
        let (kind, round) = sent.packet.key();
        if kind == "REPORT" && round > 4 {
            let prefix = run
                .sends(sent.from, "HISTORY3", round - 4)
                .first()
                .map(|s| s.at);
            let history = run
                .notices
                .get(&(sent.from, "proposal_history_ready".into(), round));
            let closed = run.statement_signers(sent.from, Kind::Closed, round - 3, None, sent.at);
            assert!(
                prefix.is_some_and(|at| at <= sent.at)
                    || history.is_some_and(|at| *at <= sent.at)
                    || closed.len() >= 2,
                "REPORT {round} outran its own completed prefix"
            );
        }
    }
    assert!(run.nodes[1]
        .executed
        .iter()
        .any(|e| e.height == 12 && e.round >= 8));
    run.assert_typed_causality();
}

fn fork_proposals(run: &Harness) -> (Proposal, Proposal, Record, Record) {
    let mut a = BatchStore::new(run.committee.clone(), 4).unwrap();
    let mut b = BatchStore::new(run.committee.clone(), 4).unwrap();
    let mut empty = BatchStore::new(run.committee.clone(), 4).unwrap();
    let record_a = a
        .produce(
            &wire::fixture_key(0),
            0,
            wire::encode(&transactions(0, 1, 1, 8)).unwrap(),
        )
        .unwrap();
    let record_b = b
        .produce(
            &wire::fixture_key(0),
            0,
            wire::encode(&transactions(0, 2, 1, 8)).unwrap(),
        )
        .unwrap();
    let base = genesis_binding(a.config(), 1, N as usize);
    let common = run
        .availability
        .observe(&base, &mut empty, &wire::fixture_key(3), 3)
        .unwrap();
    let make = |store: &mut BatchStore, honest: Id| {
        let pool = vec![
            run.availability
                .observe(&base, store, &wire::fixture_key(0), 0)
                .unwrap(),
            run.availability
                .observe(&base, store, &wire::fixture_key(honest), honest)
                .unwrap(),
            common.clone(),
        ];
        let (value, witness) = run
            .availability
            .build_all_current(&base, &pool, store)
            .unwrap();
        let history = History::Empty;
        let header = wire::sign(
            &wire::fixture_key(0),
            0,
            wire::Header {
                context: run.committee.context.clone(),
                round: 1,
                value_hash: wire::hash(&value),
                witness_hash: wire::hash(&witness),
                history_hash: wire::hash(&history),
                entries: Entries::empty(),
            },
        );
        Proposal {
            header,
            value,
            witness,
            history,
        }
    };
    (make(&mut a, 1), make(&mut b, 2), record_a, record_b)
}

#[test]
fn equivocating_leader_cannot_turn_forked_witnesses_into_conflicting_commits() {
    let mut run = Harness::new(Some(0), 4);
    run.workload(1, 0);
    let (a, b, record_a, record_b) = fork_proposals(&run);
    // The two honest witness identities retain the exact source branch they
    // signed; only producer/leader zero equivocates in this fixture.
    for (to, record) in [(1, record_a), (2, record_b)] {
        run.schedule(
            0,
            Event::Deliver {
                from: 0,
                to,
                packet: Packet::Availability(composed::Message::Batch(record)),
                reject: false,
            },
        );
    }
    for proposal in [&a, &b] {
        run.committee
            .verify_proposal(proposal, |r, value, witness| {
                run.availability.q(r, value, witness)
            })
            .unwrap();
    }
    let digest_a = wire::proposal_digest(&a.header.body);
    assert_ne!(digest_a, wire::proposal_digest(&b.header.body));
    for id in 1..N {
        for (at, proposal) in [
            (35, if id == 3 { &b } else { &a }),
            (45, if id == 3 { &a } else { &b }),
        ] {
            run.schedule(
                at,
                Event::Deliver {
                    from: 0,
                    to: id,
                    packet: Packet::Ordering(Message::Propose(proposal.clone())),
                    reject: false,
                },
            );
        }
        let vote = wire::sign(
            &wire::fixture_key(0),
            0,
            Statement {
                context: run.committee.context.clone(),
                kind: Kind::Vote,
                round: 1,
                digest: Some(digest_a),
            },
        );
        run.schedule(
            37,
            Event::Deliver {
                from: 0,
                to: id,
                packet: Packet::Ordering(Message::Vote {
                    vote,
                    header: Some(a.header.clone()),
                    value: Some(a.value.clone()),
                }),
                reject: false,
            },
        );
        // Sign a header around a cross-branch value/witness splice: signature
        // authenticity must not substitute for the actual availability proof.
        let mut graft = a.clone();
        graft.witness = b.witness.clone();
        graft.header.body.witness_hash = wire::hash(&graft.witness);
        graft.header = wire::sign(&wire::fixture_key(0), 0, graft.header.body);
        run.schedule(
            55,
            Event::Deliver {
                from: 0,
                to: id,
                packet: Packet::Ordering(Message::Propose(graft)),
                reject: true,
            },
        );
    }
    run.run_until(1000);
    assert_eq!(run.rejected, 3);
    for id in 1..N {
        let votes = run.sends(id, "VOTE", 1);
        assert_eq!(votes.len(), 1, "honest node voted twice for equivocation");
        let Packet::Ordering(Message::Vote { vote, .. }) = &votes[0].packet else {
            unreachable!()
        };
        assert_eq!(
            vote.body.digest,
            Some(if id == 3 {
                wire::proposal_digest(&b.header.body)
            } else {
                digest_a
            })
        );
        assert_eq!(run.commits[&(id, 1)].1, digest_a);
        assert_eq!(run.nodes[id as usize].ordering.committed(1), Some(digest_a));
    }
    assert_eq!(
        run.commits
            .iter()
            .filter(|((_, round), _)| *round == 1)
            .map(|(_, (_, digest))| digest)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
}

#[test]
fn pipeline_timeout_fallback_requires_distinct_authenticated_closed_at_the_exact_horizon() {
    let mut run = Harness::new(None, 5);
    let effects = run.nodes[0].start(0).unwrap();
    run.emit(0, effects);
    let statement = |kind, round, signer, committee: &Committee| {
        wire::sign(
            &wire::fixture_key(signer),
            signer,
            Statement {
                context: committee.context.clone(),
                kind,
                round,
                digest: None,
            },
        )
    };
    for (at, signer) in [(1, 1), (2, 2)] {
        run.schedule(
            at,
            Event::Deliver {
                from: signer,
                to: 0,
                packet: Packet::Ordering(Message::Prog(statement(
                    Kind::Prog,
                    4,
                    signer,
                    &run.committee,
                ))),
                reject: false,
            },
        );
    }
    run.run_until(2);
    assert_eq!(run.nodes[0].ordering.current_round(), 5);
    assert!(run.nodes[0].ordering.own_reports().is_empty());
    assert!(run.sends(0, "REPORT", 5).is_empty());
    for (at, horizon, signer) in [(3, 1, 1), (4, 2, 1), (5, 2, 1), (6, 3, 2)] {
        run.schedule(
            at,
            Event::Deliver {
                from: signer,
                to: 0,
                packet: Packet::Ordering(Message::Closed(statement(
                    Kind::Closed,
                    horizon,
                    signer,
                    &run.committee,
                ))),
                reject: false,
            },
        );
    }
    run.run_until(6);
    assert!(
        run.sends(0, "REPORT", 5).is_empty(),
        "duplicates or wrong horizons opened a REPORT"
    );
    let mut forged = statement(Kind::Closed, 2, 2, &run.committee);
    forged.signature[0] ^= 1;
    run.schedule(
        7,
        Event::Deliver {
            from: 2,
            to: 0,
            packet: Packet::Ordering(Message::Closed(forged)),
            reject: true,
        },
    );
    run.run_until(7);
    assert!(run.sends(0, "REPORT", 5).is_empty());
    for at in [8, 9] {
        run.schedule(
            at,
            Event::Deliver {
                from: 2,
                to: 0,
                packet: Packet::Ordering(Message::Closed(statement(
                    Kind::Closed,
                    2,
                    2,
                    &run.committee,
                ))),
                reject: false,
            },
        );
    }
    run.run_until(9);
    assert_eq!(run.rejected, 1);
    assert_eq!(run.only_send_time(0, "REPORT", 5), 8);
    assert!(run.nodes[0].ordering.own_reports().is_empty());
    assert!(
        !run.nodes[0].ordering.input_preparation_ready(5),
        "test accidentally supplied HISTORY3 quorum"
    );
}

#[test]
fn silent_leader_still_recovers_when_link_delay_is_close_to_the_timer_bound() {
    let mut run = Harness::new(Some(0), 12);
    run.delta = BOUND - 1;
    run.workload(12, 0);
    run.run_until(3500);
    for node in &run.nodes[1..] {
        assert_eq!(node.ordering.last_delivered(), 12);
        assert_eq!(node.executed_rounds, vec![2, 3, 4, 6, 7, 8, 10, 11, 12]);
        assert_eq!(node.executed, run.nodes[1].executed);
        assert_eq!(node.executed.len(), 36);
        for silent_round in [1, 5, 9] {
            assert_eq!(node.ordering.statuses()[&silent_round], Status::Skip);
            for anchor in silent_round + 1..=silent_round + 3 {
                assert!(run.commits.contains_key(&(node.id, anchor)));
            }
            assert!(
                node.executed_at[&(silent_round + 1)]
                    >= run.commits[&(node.id, silent_round + 3)].0
            );
        }
    }
    assert!(run.only_send_time(leader(12), "REPORT", 12) > 4 * run.delta);
    run.assert_typed_causality();
}
