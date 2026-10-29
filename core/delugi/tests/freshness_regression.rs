//! Transaction-freshness regressions over the production signed composed core.
//! Virtual time tests causality and recovery cycles, not machine throughput.
use delugi_core::availability::AvailabilityConfig;
use delugi_core::composed::{self, Effect, Node, ReportSchedule};
use delugi_core::end_to_end::transactions;
use delugi_core::replica::{Effect as OrderingEffect, OrderingSchedule};
use delugi_core::wire::{self, Committee, Digest, Id, Message};
use std::collections::BTreeMap;

const N: Id = 4;
const DELTA: u64 = 10;
const BOUND: u64 = 100;

#[derive(Clone)]
enum Packet {
    Ordering(Message),
    Availability(composed::Message),
}
enum Event {
    Start(Id),
    Produce(Id, u64),
    Timer(Id),
    Receive(Id, Id, Packet),
}
struct Network {
    committee: Committee,
    availability: AvailabilityConfig,
    nodes: Vec<Node>,
    silent: Option<Id>,
    now: u64,
    serial: u64,
    events: BTreeMap<(u64, u64), Event>,
    proposed: BTreeMap<u64, u64>,
    committed: BTreeMap<(Id, u64), u64>,
    reports: BTreeMap<u64, u64>,
    observations: BTreeMap<(Id, u64), usize>,
}
fn leader(round: u64) -> Id {
    ((round - 1) % u64::from(N)) as Id
}
impl Network {
    fn new(silent: Option<Id>, rounds: u64) -> Self {
        let committee = Committee::new(
            [103; 32],
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
            now: 0,
            serial: 0,
            events: BTreeMap::new(),
            proposed: BTreeMap::new(),
            committed: BTreeMap::new(),
            reports: BTreeMap::new(),
            observations: BTreeMap::new(),
        }
    }
    fn schedule(&mut self, at: u64, event: Event) {
        self.events.insert((at, self.serial), event);
        self.serial += 1;
    }
    fn send(&mut self, from: Id, to: Option<Id>, packet: Packet) {
        match &packet {
            Packet::Ordering(Message::Propose(proposal)) => {
                let r = proposal.header.body.round;
                assert_eq!(from, leader(r));
                self.committee
                    .verify_proposal(proposal, |r, x, proof| self.availability.q(r, x, proof))
                    .unwrap();
                assert!(self.proposed.insert(r, self.now).is_none());
            }
            Packet::Availability(composed::Message::Report { base, .. }) => {
                assert_eq!(from, leader(base.opportunity));
                assert!(self.reports.insert(base.opportunity, self.now).is_none());
            }
            Packet::Availability(composed::Message::Observation(observation)) => {
                *self
                    .observations
                    .entry((from, observation.body.opportunity))
                    .or_default() += 1;
            }
            _ => {}
        }
        // Production handles self delivery; never synthesize another self vote.
        for recipient in to.map_or_else(|| (0..N).collect::<Vec<_>>(), |id| vec![id]) {
            if recipient != from {
                self.schedule(
                    self.now + DELTA,
                    Event::Receive(from, recipient, packet.clone()),
                );
            }
        }
    }
    fn effects(&mut self, id: Id, effects: Vec<Effect>) {
        for effect in effects {
            match effect {
                Effect::Ordering(OrderingEffect::Send { to, message }) => {
                    self.send(id, to, Packet::Ordering(message))
                }
                Effect::Ordering(OrderingEffect::Wake { at }) => {
                    self.schedule(at, Event::Timer(id))
                }
                Effect::Ordering(OrderingEffect::DirectCommit { round, .. }) => {
                    assert!(self.committed.insert((id, round), self.now).is_none());
                }
                Effect::Send { to, message } => self.send(id, to, Packet::Availability(message)),
                _ => {}
            }
        }
    }
    fn run(&mut self, until: u64) {
        let mut count = 0;
        while self
            .events
            .first_key_value()
            .is_some_and(|(&(at, _), _)| at <= until)
        {
            let ((at, _), event) = self.events.pop_first().unwrap();
            self.now = at;
            let id = match &event {
                Event::Start(id) | Event::Produce(id, _) | Event::Timer(id) => *id,
                Event::Receive(_, id, _) => *id,
            };
            if self.silent == Some(id) {
                continue;
            }
            let effects = match event {
                Event::Start(_) => self.nodes[id as usize].start(at),
                Event::Produce(_, height) => self.nodes[id as usize]
                    .produce(at, wire::encode(&transactions(id, height, 1, 8)).unwrap()),
                Event::Timer(_) => self.nodes[id as usize].tick(at),
                Event::Receive(from, _, packet) => match packet {
                    Packet::Ordering(message) => {
                        let bytes = self.committee.encode(&message).unwrap();
                        self.nodes[id as usize]
                            .receive_ordering(at, self.committee.decode(&bytes).unwrap())
                    }
                    Packet::Availability(message) => {
                        let bytes = self.committee.encode(&message).unwrap();
                        self.nodes[id as usize].receive(
                            at,
                            from,
                            self.committee.decode(&bytes).unwrap(),
                        )
                    }
                },
            }
            .unwrap_or_else(|e| panic!("node {id} at {at}: {e}"));
            self.effects(id, effects);
            count += 1;
            assert!(count < 1_000_000, "fixture produced unbounded events");
        }
    }
    fn output(&self, node: Id, producer: Id, height: u64) -> (u64, u64) {
        let transaction: Digest = transactions(producer, height, 1, 8)[0].id;
        let n = &self.nodes[node as usize];
        let executed: Vec<_> = n
            .executed
            .iter()
            .filter(|e| e.transaction == transaction)
            .collect();
        assert_eq!(
            executed.len(),
            1,
            "node {node}, producer {producer}, height {height}"
        );
        (executed[0].round, n.executed_at[&executed[0].round])
    }
    fn assert_agreement(&self) {
        let honest: Vec<_> = (0..N).filter(|id| self.silent != Some(*id)).collect();
        for &id in &honest {
            assert_eq!(
                self.nodes[id as usize].executed,
                self.nodes[honest[0] as usize].executed
            );
        }
        assert!(
            self.observations.values().all(|count| *count == 1),
            "freshness cannot be repaired by re-signing an observation"
        );
    }
}

#[test]
fn batches_arriving_during_silence_use_the_same_recovery_anchor() {
    let mut net = Network::new(Some(0), 12);
    for id in 1..N {
        net.schedule(0, Event::Produce(id, 1));
        net.schedule(2 * DELTA, Event::Start(id));
        // Both are far inside a timeout, with ample dissemination time before
        // its third honest anchor may safely release the blocked prefix.
        net.schedule(250, Event::Produce(id, 2));
        net.schedule(1_000, Event::Produce(id, 3));
    }
    net.run(3_000);
    net.assert_agreement();
    for (height, anchor) in [(2, 4), (3, 8)] {
        eprintln!(
            "recovery anchor {anchor}: REPORT={} ms, PROPOSE={} ms, example output={:?}",
            net.reports[&anchor],
            net.proposed[&anchor],
            net.output(1, 1, height)
        );
        for producer in 1..N {
            for id in 1..N {
                let (round, output_at) = net.output(id, producer, height);
                assert_eq!(round, anchor,
                    "late batch ({producer},{height}) at replica {id} missed recovery anchor {anchor}; \
                     REPORT times {:?}, PROPOSE times {:?}; actual output {output_at} ms",
                    net.reports, net.proposed);
                assert!(
                    output_at <= net.committed[&(id, anchor)],
                    "fresh recovery payload waited for an additional timeout cycle"
                );
            }
        }
    }
}

#[test]
fn healthy_pipeline_keeps_delta_cadence_with_post_start_arrivals() {
    let mut net = Network::new(None, 24);
    for id in 0..N {
        net.schedule(0, Event::Start(id));
        // No preloaded payloads: repeated arrivals straddle observation cutoffs.
        for height in 1..=24 {
            net.schedule(5 + (height - 1) * 7, Event::Produce(id, height));
        }
    }
    net.run(350);
    net.assert_agreement();
    for round in 5..=24 {
        assert_eq!(
            net.proposed[&round] - net.proposed[&(round - 1)],
            DELTA,
            "fixing recovery freshness must preserve the healthy pipeline"
        );
        for id in 0..N {
            assert_eq!(
                net.committed[&(id, round)] - net.proposed[&round],
                3 * DELTA
            );
        }
    }
    for producer in 0..N {
        for height in 1..=24 {
            let admitted = 5 + (height - 1) * 7;
            for id in 0..N {
                let (_, output_at) = net.output(id, producer, height);
                assert!(
                    output_at <= admitted + 7 * DELTA,
                    "live payload ({producer},{height}) waited {} ms",
                    output_at - admitted
                );
            }
        }
    }
}

#[test]
fn speculative_preparation_requires_full_exact_predecessor_validation() {
    use delugi_core::history::{self, History};
    use delugi_core::replica::Replica;
    use delugi_core::wire::{Header, Kind, Proposal, Statement};

    let committee = Committee::new(
        [104; 32],
        (0..N).map(|id| wire::fixture_key(id).public).collect(),
    )
    .unwrap();
    let proposal = |round, witness: &[u8]| {
        let value = b"valid".to_vec();
        let history = History::Empty;
        let header = Header {
            context: committee.context.clone(),
            round,
            value_hash: wire::hash(&value),
            witness_hash: wire::hash(&witness.to_vec()),
            history_hash: wire::hash(&history),
            entries: history::project(round, &history),
        };
        Proposal {
            header: wire::sign(&wire::fixture_key(leader(round)), leader(round), header),
            value,
            witness: witness.to_vec(),
            history,
        }
    };
    let statement = |signer, kind, round, digest| {
        wire::sign(
            &wire::fixture_key(signer),
            signer,
            Statement {
                context: committee.context.clone(),
                kind,
                round,
                digest,
            },
        )
    };
    for proposal_before_admission in [false, true] {
        let mut replica = Replica::new(
            committee.clone(),
            3,
            wire::fixture_key(3),
            BOUND,
            BTreeMap::new(),
            |round, value, witness| round <= 3 && value == b"valid" && witness == b"proof",
        );
        replica.start(0).unwrap();
        let enter = |replica: &mut Replica, now| {
            for signer in [0, 1] {
                replica
                    .receive(now, Message::Prog(statement(signer, Kind::Prog, 3, None)))
                    .unwrap();
            }
            assert_eq!(replica.current_round(), 4);
        };
        if !proposal_before_admission {
            enter(&mut replica, 1);
        }
        assert!(!replica.pipeline_preparation_ready(4));

        let first = proposal(1, b"proof");
        let digest = wire::proposal_digest(&first.header.body);
        // Authentic signed metadata, votes and CERs do not establish Q.
        replica
            .receive(
                2,
                Message::Vote {
                    vote: statement(0, Kind::Vote, 1, Some(digest)),
                    header: Some(first.header.clone()),
                    value: Some(first.value.clone()),
                },
            )
            .unwrap();
        replica
            .receive(3, Message::Cer(statement(0, Kind::Cer, 1, Some(digest))))
            .unwrap();
        assert!(!replica.preparation_predecessor_validated(4));
        assert!(!replica.pipeline_preparation_ready(4));
        assert!(replica
            .receive(4, Message::Propose(proposal(1, b"invalid proof")))
            .is_err());
        assert!(!replica.preparation_predecessor_validated(4));
        assert!(!replica.pipeline_preparation_ready(4));
        // A fully valid neighboring proposal cannot substitute for round k−3.
        replica
            .receive(5, Message::Propose(proposal(2, b"proof")))
            .unwrap();
        assert!(!replica.preparation_predecessor_validated(4));
        assert!(!replica.pipeline_preparation_ready(4));

        let effects = replica.receive(6, Message::Propose(first)).unwrap();
        assert!(replica.preparation_predecessor_validated(4));
        assert!(effects.iter().any(|e| matches!(
            e,
            OrderingEffect::Notice {
                kind,
                round: 4
            } if kind == "pipeline_preparation_ready"
        )));
        if proposal_before_admission {
            assert!(!replica.pipeline_preparation_ready(4));
            enter(&mut replica, 7);
        }
        assert!(
            replica.own_reports().is_empty(),
            "test accidentally used completed-prefix fallback"
        );
        assert!(
            replica.pipeline_preparation_ready(4),
            "both validation/admission arrival orders must enable speculative preparation"
        );
    }
}
