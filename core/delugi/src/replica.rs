//! Complete deterministic ordering transitions, with an atomic in-memory outbox.
//!
//! The caller supplies monotonic local time and authenticated wire messages, then
//! drains the returned effects before scheduling further external events. Every
//! signature is still checked here. Self-delivery is drained in the same call.
//! State/evidence/outbox are retained for the process lifetime; crash recovery,
//! disk durability, dissemination and application execution are separate layers.
use crate::causal::{self, Trace as CausalTrace};
use crate::history::{self, CerProof, History, Report, ReportHeader};
use crate::scanner::{self, Delivery, Status};
use crate::slot::{Action, Slot, Terminal, Trigger};
use crate::wire::{
    self, Committee, Digest, Header, Id, Kind, Message, Proposal, Signed, Statement,
};
use ed25519_dalek::Keypair;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[cfg(test)]
mod round_barrier_tests {
    use super::*;

    fn replica(id: Id, inputs: Inputs) -> Replica {
        replica_in_mode(id, inputs, PacingMode::RoundBarrier)
    }

    fn unconfigured_replica(id: Id, inputs: Inputs) -> Replica {
        let committee = Committee::new(
            [93; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        Replica::new(
            committee,
            id,
            wire::fixture_key(id),
            100,
            inputs,
            |_, x, _| x != b"invalid",
        )
    }

    fn replica_in_mode(id: Id, inputs: Inputs, mode: PacingMode) -> Replica {
        let mut n = unconfigured_replica(id, inputs);
        match mode {
            PacingMode::RoundBarrier => n.enable_round_barrier(100).unwrap(),
            PacingMode::ProgressOnly => n.enable_progress_pacing(100).unwrap(),
        }
        n
    }

    fn statement(
        n: &Replica,
        signer: Id,
        kind: Kind,
        round: u64,
        digest: Option<Digest>,
    ) -> Signed<Statement> {
        wire::sign(
            &wire::fixture_key(signer),
            signer,
            Statement {
                context: n.committee.context.clone(),
                kind,
                round,
                digest,
            },
        )
    }

    fn proposal(n: &Replica, round: u64, value: &[u8]) -> Proposal {
        assert!(round <= 3);
        let history = History::Empty;
        let header = Header {
            context: n.committee.context.clone(),
            round,
            value_hash: wire::hash(&value.to_vec()),
            witness_hash: wire::hash(&Vec::<u8>::new()),
            history_hash: wire::hash(&history),
            entries: history::project(round, &history),
        };
        let leader = n.leader(round);
        Proposal {
            header: wire::sign(&wire::fixture_key(leader), leader, header),
            value: value.to_vec(),
            witness: vec![],
            history,
        }
    }

    fn enter(n: &mut Replica, now: u64, round: u64) -> Vec<Effect> {
        let mut out = Vec::new();
        for signer in [1, 2] {
            let s = statement(n, signer, Kind::Prog, round - 1, None);
            out.extend(n.receive(now, Message::Prog(s)).unwrap());
        }
        assert!(n.current >= round);
        out
    }

    fn sent(effects: &[Effect], kind: &str, round: u64) -> usize {
        effects
            .iter()
            .filter(|e| match e {
                Effect::Send { message, .. } => {
                    let (k, r, _) = causal::ordering_key(message);
                    k == kind && r == round
                }
                _ => false,
            })
            .count()
    }

    fn waiting_second_barrier() -> (Replica, Digest) {
        let mut n = replica(0, Inputs::new());
        n.start(0).unwrap();
        enter(&mut n, 0, 2);
        let first = proposal(&n, 1, b"first");
        let digest = wire::proposal_digest(&first.header.body);
        n.receive(1, Message::Propose(first)).unwrap();
        enter(&mut n, 2, 3);
        let second = proposal(&n, 2, b"second");
        let effects = n.receive(3, Message::Propose(second)).unwrap();
        assert_eq!(sent(&effects, "VOTE", 2), 0);
        assert!(n.slots[&2].voted().is_some());
        assert!(!n.progress_sent.contains(&3));
        assert_eq!(n.round_barriers.as_ref().unwrap().pending[&2].deadline, 102);
        (n, digest)
    }

    fn vote_first(n: &mut Replica, now: u64, digest: Digest) -> Vec<Effect> {
        let mut out = Vec::new();
        for signer in [1, 2] {
            let vote = statement(n, signer, Kind::Vote, 1, Some(digest));
            out.extend(
                n.receive(
                    now,
                    Message::Vote {
                        vote,
                        header: None,
                        value: None,
                    },
                )
                .unwrap(),
            );
        }
        out
    }

    #[test]
    fn constructor_default_is_immediate_and_comparison_override_is_once_before_start() {
        for bound in [17, 100] {
            let c = Committee::new(
                [93; 32],
                (0..4).map(|i| wire::fixture_key(i).public).collect(),
            )
            .unwrap();
            let mut n = Replica::try_new(
                c,
                0,
                wire::fixture_key(0),
                bound,
                Inputs::new(),
                |_, _, _| true,
            )
            .unwrap();
            assert_eq!(n.ordering_schedule(), OrderingSchedule::Canonical);
            assert_eq!(n.snapshot()["ordering_schedule"], "canonical");
            assert!(!n.schedule_configured);
            assert!(n.enable_progress_pacing(0).is_err());
            assert!(n.enable_progress_pacing(bound + 1).is_err());
            assert!(!n.schedule_configured);
            n.start(0).unwrap();
            assert_eq!(sent(&enter(&mut n, 3, 2), "PROG", 2), 1);
            assert!(n.round_barriers.is_none());
            assert!(n.configure_ordering(OrderingSchedule::Canonical).is_err());
        }
        let mut explicit = unconfigured_replica(0, Inputs::new());
        explicit.enable_progress_pacing(37).unwrap();
        assert_eq!(
            explicit.ordering_schedule(),
            OrderingSchedule::ProgressPacing {
                release_delay_ms: 37
            }
        );
        assert!(explicit
            .configure_ordering(OrderingSchedule::Canonical)
            .is_err());
    }

    #[test]
    fn round_barrier_requires_full_exact_proposal_and_configures_only_before_start() {
        let mut n = replica(0, Inputs::new());
        assert!(n.enable_round_barrier(100).is_err());
        n.start(0).unwrap();
        assert!(n.enable_round_barrier(100).is_err());
        let effects = enter(&mut n, 0, 2);
        assert_eq!(sent(&effects, "PROG", 2), 0);
        assert!(
            !n.progress.get(&2).is_some_and(|v| v.contains_key(&0)),
            "held origin must not self-count"
        );
        let invalid = proposal(&n, 1, b"invalid");
        assert!(n.receive(1, Message::Propose(invalid)).is_err());
        let distant = proposal(&n, 3, b"future");
        n.receive(2, Message::Propose(distant)).unwrap();
        let valid = proposal(&n, 1, b"first");
        let vote = statement(
            &n,
            1,
            Kind::Vote,
            1,
            Some(wire::proposal_digest(&valid.header.body)),
        );
        n.receive(
            3,
            Message::Vote {
                vote,
                header: Some(valid.header.clone()),
                value: Some(valid.value.clone()),
            },
        )
        .unwrap();
        assert!(
            !n.progress_sent.contains(&2),
            "header attachment is not full validation"
        );
        assert_eq!(n.round_barriers.as_ref().unwrap().pending[&1].deadline, 100);
        let effects = n.receive(4, Message::Propose(valid)).unwrap();
        assert_eq!(sent(&effects, "PROG", 2), 1);
        assert_eq!(sent(&effects, "VOTE", 1), 1);
        let b = n.round_barriers.as_ref().unwrap();
        assert_eq!((b.ready_releases, b.deadline_releases), (1, 0));
        assert!(!b.pending.contains_key(&1));
        assert_eq!(sent(&n.tick(100).unwrap(), "PROG", 2), 0);
    }

    #[test]
    fn round_barrier_releases_joint_messages_once_and_keeps_report_before_closed() {
        let (mut n, digest) = waiting_second_barrier();
        let effects = vote_first(&mut n, 4, digest);
        for (kind, round) in [
            ("PROG", 3),
            ("VOTE", 2),
            ("CER", 1),
            ("HISTORY3", 1),
            ("CLOSED", 1),
        ] {
            assert_eq!(
                sent(&effects, kind, round),
                1,
                "{kind} missing from joint release"
            );
        }
        let kinds: Vec<_> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { message, .. } => Some(causal::ordering_key(message).0),
                _ => None,
            })
            .collect();
        assert!(
            kinds.iter().position(|k| *k == "HISTORY3").unwrap()
                < kinds.iter().position(|k| *k == "CLOSED").unwrap()
        );
        assert!(n.own_reports.contains_key(&1));
        assert_eq!(
            n.cers[&(1, digest)].len(),
            1,
            "release does not self-deliver again"
        );
        assert!(n.round_barriers.as_ref().unwrap().pending.get(&2).is_none());
        assert_eq!(n.main_deadline(1), Some(702));
        let later = n.tick(102).unwrap();
        assert_eq!(sent(&later, "VOTE", 2) + sent(&later, "CER", 1), 0);
    }

    #[test]
    fn round_barrier_deadline_does_not_invent_outcomes_or_hold_late_messages_again() {
        let (mut n, digest) = waiting_second_barrier();
        assert_eq!(sent(&n.tick(101).unwrap(), "VOTE", 2), 0);
        let effects = n.tick(102).unwrap();
        assert_eq!(sent(&effects, "PROG", 3), 1);
        assert_eq!(sent(&effects, "VOTE", 2), 1);
        assert_eq!(
            sent(&effects, "CER", 1) + sent(&effects, "HISTORY3", 1) + sent(&effects, "CLOSED", 1),
            0
        );
        assert_eq!(n.terminal(1), Terminal::Open);
        assert_eq!(n.main_deadline(1), Some(702));
        let late = vote_first(&mut n, 103, digest);
        for kind in ["CER", "HISTORY3", "CLOSED"] {
            assert_eq!(sent(&late, kind, 1), 1);
        }
        assert_eq!(sent(&late, "PROG", 3), 0);
        assert_eq!(n.round_barriers.as_ref().unwrap().deadline_releases, 1);
    }

    #[test]
    fn round_barrier_amplification_bypasses_only_progress_even_below_current_round() {
        let (mut n, _) = waiting_second_barrier();
        enter(&mut n, 4, 6); // Authenticated future PROGs jump admission.
        assert!(!n.progress_sent.contains(&3));
        let mut effects = Vec::new();
        for signer in [1, 2] {
            let s = statement(&n, signer, Kind::Prog, 3, None);
            effects.extend(n.receive(5, Message::Prog(s)).unwrap());
        }
        assert_eq!(sent(&effects, "PROG", 3), 1);
        assert_eq!(sent(&effects, "VOTE", 2), 0);
        assert!(n.round_barriers.as_ref().unwrap().pending.contains_key(&2));
        let effects = n.tick(102).unwrap();
        assert_eq!(sent(&effects, "PROG", 3), 0);
        assert_eq!(sent(&effects, "VOTE", 2), 1);
    }

    #[test]
    fn round_barrier_held_closed_cannot_self_arm_catchup_and_invalid_hint_does_nothing() {
        let mut n = replica(0, Inputs::new());
        n.start(0).unwrap();
        enter(&mut n, 0, 2);
        let first = proposal(&n, 1, b"first");
        let digest = wire::proposal_digest(&first.header.body);
        n.receive(1, Message::Propose(first)).unwrap();
        enter(&mut n, 2, 3);
        let effects = vote_first(&mut n, 3, digest);
        assert_eq!(sent(&effects, "CLOSED", 1), 0);
        assert!(n.own_reports.contains_key(&1));
        assert!(n.closed_sent.contains_key(&1)); // Assembled, still held.
        assert!(!n.closed.get(&1).is_some_and(|s| s.contains_key(&0)));
        assert_eq!(n.catchup_deadline(1), None);
        let mut invalid = statement(&n, 1, Kind::Closed, 1, None);
        invalid.signature[0] ^= 1;
        assert!(n.receive(4, Message::Closed(invalid)).is_err());
        assert_eq!(n.round_barriers.as_ref().unwrap().urgent_through, 0);
        assert!(n.round_barriers.as_ref().unwrap().pending.contains_key(&2));
        let remote = statement(&n, 1, Kind::Closed, 1, None);
        let effects = n.receive(5, Message::Closed(remote)).unwrap();
        for kind in ["CER", "HISTORY3", "CLOSED"] {
            assert_eq!(sent(&effects, kind, 1), 1);
        }
        assert!(n.closed[&1].contains_key(&0));
        assert_eq!(n.catchup_deadline(1), Some(305));
        assert_eq!(n.round_barriers.as_ref().unwrap().urgent_releases, 1);
        let kinds: Vec<_> = effects
            .iter()
            .filter_map(|e| match e {
                Effect::Send { message, .. } => Some(causal::ordering_key(message).0),
                _ => None,
            })
            .collect();
        assert!(
            kinds.iter().position(|k| *k == "HISTORY3").unwrap()
                < kinds.iter().position(|k| *k == "CLOSED").unwrap()
        );
        assert_eq!(sent(&n.tick(102).unwrap(), "CLOSED", 1), 0);
    }

    #[test]
    fn round_barrier_remote_closed_hint_is_sticky_across_future_admission_without_forging_outcomes()
    {
        let mut n = replica(0, Inputs::new());
        n.start(0).unwrap();
        let remote = statement(&n, 1, Kind::Closed, 8, None);
        n.receive(1, Message::Closed(remote)).unwrap();
        assert_eq!(n.current, 1);
        assert_eq!(n.catchup_deadline(8), None); // One hint is not f+1 evidence.
        assert_eq!(n.round_barriers.as_ref().unwrap().urgent_through, 9);
        enter(&mut n, 2, 10);
        assert!((1..=8).all(|r| n.terminal(r) == Terminal::Open));
        let reports: Vec<_> = (1..=3)
            .map(|id| Report {
                header: wire::sign(
                    &wire::fixture_key(id),
                    id,
                    ReportHeader {
                        context: n.committee.context.clone(),
                        horizon: 5,
                        positives: vec![],
                    },
                ),
                proofs: vec![],
            })
            .collect();
        let history = history::build_history(&n.committee, 8, &reports, &[]).unwrap();
        let value = b"eighth".to_vec();
        let witness = Vec::new();
        let header = Header {
            context: n.committee.context.clone(),
            round: 8,
            value_hash: wire::hash(&value),
            witness_hash: wire::hash(&witness),
            history_hash: wire::hash(&history),
            entries: history::project(8, &history),
        };
        let p = Proposal {
            header: wire::sign(&wire::fixture_key(3), 3, header),
            value,
            witness,
            history,
        };
        let digest = wire::proposal_digest(&p.header.body);
        let effects = n.receive(3, Message::Propose(p)).unwrap();
        assert_eq!(
            sent(&effects, "VOTE", 8),
            1,
            "later-entry barrier must inherit the hint"
        );
        assert_eq!(n.terminal(7), Terminal::Open);
        for signer in [1, 2] {
            let vote = statement(&n, signer, Kind::Vote, 8, Some(digest));
            n.receive(
                4,
                Message::Vote {
                    vote,
                    header: None,
                    value: None,
                },
            )
            .unwrap();
        }
        assert_eq!(n.terminal(8), Terminal::Cer(digest));
        assert!((1..=7).all(|r| n.terminal(r) == Terminal::Open));
        let second = statement(&n, 2, Kind::Closed, 8, None);
        n.receive(5, Message::Closed(second)).unwrap();
        assert_eq!(n.catchup_deadline(8), Some(305));
        for signer in [1, 2] {
            let cer = statement(&n, signer, Kind::Cer, 8, Some(digest));
            n.receive(6, Message::Cer(cer)).unwrap();
        }
        assert_eq!(n.committed(8), Some(digest));
        assert_eq!(n.terminal(8), Terminal::Cer(digest));
    }

    #[test]
    fn round_barrier_single_distant_closed_can_disable_pacing_but_not_advance_admission() {
        let mut n = replica(0, Inputs::new());
        n.start(0).unwrap();
        let hint = statement(&n, 1, Kind::Closed, wire::MAX_ROUND, None);
        let effects = n.receive(1, Message::Closed(hint)).unwrap();
        assert_eq!(n.current, 1);
        assert_eq!(n.terminal(1), Terminal::Open);
        assert_eq!(n.catchup_deadline(wire::MAX_ROUND), None);
        assert!(effects.iter().all(|e| !matches!(e, Effect::Send { .. })));
        assert_eq!(
            n.round_barriers.as_ref().unwrap().urgent_through,
            wire::MAX_ROUND + 1
        );
        let effects = enter(&mut n, 2, 2);
        assert_eq!(sent(&effects, "PROG", 2), 1);
        assert_eq!(n.current, 2);
        assert_eq!(n.terminal(1), Terminal::Open);
        assert!(n.own_reports.is_empty());
        assert!(n.closed_sent.is_empty());
        assert_eq!(n.round_barriers.as_ref().unwrap().urgent_releases, 1);
    }

    #[test]
    fn progress_pacing_requires_exact_full_validation_and_accepts_same_round_escape() {
        let mut n = replica_in_mode(0, Inputs::new(), PacingMode::ProgressOnly);
        n.start(0).unwrap();
        assert!(n.enable_round_barrier(100).is_err());
        enter(&mut n, 0, 2);
        let invalid = proposal(&n, 1, b"invalid");
        assert!(n.receive(1, Message::Propose(invalid)).is_err());
        let unrelated = proposal(&n, 3, b"third");
        n.receive(2, Message::Propose(unrelated)).unwrap();
        assert!(!n.progress_sent.contains(&2));
        let first = proposal(&n, 1, b"first");
        let vote = statement(
            &n,
            1,
            Kind::Vote,
            1,
            Some(wire::proposal_digest(&first.header.body)),
        );
        n.receive(
            3,
            Message::Vote {
                vote,
                header: Some(first.header),
                value: Some(first.value),
            },
        )
        .unwrap();
        assert!(!n.progress_sent.contains(&2));
        let second = proposal(&n, 2, b"second");
        let effects = n.receive(4, Message::Propose(second)).unwrap();
        assert_eq!(
            sent(&effects, "PROG", 2),
            1,
            "same-round proposal must release its origin gate"
        );
        assert_eq!(sent(&effects, "VOTE", 1), 0);
        assert!(n.snapshot().get("progress_pacing").is_some());
        assert!(n.snapshot().get("experimental_round_barrier").is_none());
        let effects = enter(&mut n, 5, 3);
        assert_eq!(
            sent(&effects, "PROG", 3),
            1,
            "retained predecessor must release new gate"
        );
        assert_eq!(n.round_barriers.as_ref().unwrap().held_messages, 0);
    }

    #[test]
    fn progress_pacing_sends_cer_history_closed_immediately_and_ignores_closed_urgency() {
        let mut n = replica_in_mode(0, Inputs::new(), PacingMode::ProgressOnly);
        n.start(0).unwrap();
        enter(&mut n, 0, 2);
        let first = proposal(&n, 1, b"first");
        let digest = wire::proposal_digest(&first.header.body);
        let effects = n.receive(1, Message::Propose(first)).unwrap();
        assert_eq!(sent(&effects, "VOTE", 1), 1);
        assert_eq!(sent(&effects, "PROG", 2), 1);
        enter(&mut n, 2, 3);
        let effects = vote_first(&mut n, 3, digest);
        for kind in ["CER", "HISTORY3", "CLOSED"] {
            assert_eq!(
                sent(&effects, kind, 1),
                1,
                "positive/report sends must not wait on proposal2"
            );
        }
        assert!(
            n.closed[&1].contains_key(&0),
            "prompt CLOSED self-delivers normally"
        );
        assert!(!n.progress_sent.contains(&3));
        let hint = statement(&n, 1, Kind::Closed, wire::MAX_ROUND, None);
        n.receive(4, Message::Closed(hint)).unwrap();
        assert!(!n.progress_sent.contains(&3));
        let pacing = n.round_barriers.as_ref().unwrap();
        assert_eq!((pacing.urgent_through, pacing.urgent_releases), (0, 0));
        assert_eq!(pacing.peak_held_messages, 0);
        assert_eq!(pacing.pending[&2].deadline, 102);
        let effects = n.tick(102).unwrap();
        assert_eq!(sent(&effects, "PROG", 3), 1);
        assert_eq!(
            sent(&effects, "CER", 1) + sent(&effects, "HISTORY3", 1) + sent(&effects, "CLOSED", 1),
            0
        );
    }

    #[test]
    fn progress_pacing_amplification_remains_immediate_without_proposal_or_outcome() {
        let mut n = replica_in_mode(0, Inputs::new(), PacingMode::ProgressOnly);
        n.start(0).unwrap();
        enter(&mut n, 0, 2);
        assert!(!n.progress_sent.contains(&2));
        let effects = enter(&mut n, 1, 3);
        assert_eq!(sent(&effects, "PROG", 2), 1);
        assert_eq!(n.current, 3);
        assert_eq!(n.terminal(1), Terminal::Open);
        assert!(n.proposals.is_empty());
        assert!(n.own_reports.is_empty());
        assert_eq!(sent(&n.tick(100).unwrap(), "PROG", 2), 0);
    }

    enum Event {
        Packet(usize, Message),
        Wake(usize),
    }

    fn schedule(
        events: &mut BTreeMap<(u64, u64), Event>,
        serial: &mut u64,
        from: usize,
        now: u64,
        delta: u64,
        silent: Option<usize>,
        effects: Vec<Effect>,
    ) {
        for effect in effects {
            match effect {
                Effect::Send { to, message } => {
                    for target in 0..4 {
                        if target != from
                            && Some(target) != silent
                            && (to.is_none() || to == Some(target as Id))
                        {
                            *serial += 1;
                            let bytes = wire::encode(&message).unwrap();
                            events.insert(
                                (now + delta, *serial),
                                Event::Packet(target, wire::decode(&bytes).unwrap()),
                            );
                        }
                    }
                }
                Effect::Wake { at } => {
                    assert!(at > now);
                    *serial += 1;
                    events.insert((at, *serial), Event::Wake(from));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn default_pacing_and_barrier_commit_round4_and_recover_silent_first_with_three_anchors() {
        for delta in [10, 99] {
            for silent in [None, Some(0)] {
                for mode in [PacingMode::RoundBarrier, PacingMode::ProgressOnly] {
                    let inputs: Inputs = (1..=4)
                        .map(|r| (r, (format!("value-{r}").into_bytes(), vec![])))
                        .collect();
                    let mut nodes: Vec<_> = (0..4)
                        .map(|id| replica_in_mode(id, inputs.clone(), mode))
                        .collect();
                    let mut events = BTreeMap::new();
                    let mut serial = 0;
                    for (id, n) in nodes.iter_mut().enumerate() {
                        if Some(id) != silent {
                            schedule(
                                &mut events,
                                &mut serial,
                                id,
                                0,
                                delta,
                                silent,
                                n.start(0).unwrap(),
                            );
                        }
                    }
                    let mut steps = 0;
                    while let Some(((now, _), event)) = events.pop_first() {
                        steps += 1;
                        assert!(
                            steps < 15000 && now < 10000,
                            "barrier failed to recover delta={delta} silent={silent:?}"
                        );
                        let (id, effects) = match event {
                            Event::Packet(id, message) => {
                                (id, nodes[id].receive(now, message).unwrap())
                            }
                            Event::Wake(id) => (id, nodes[id].tick(now).unwrap()),
                        };
                        schedule(&mut events, &mut serial, id, now, delta, silent, effects);
                        if nodes
                            .iter()
                            .enumerate()
                            .all(|(id, n)| Some(id) == silent || n.cursor >= 4)
                        {
                            break;
                        }
                    }
                    let active: Vec<_> = nodes
                        .iter()
                        .enumerate()
                        .filter(|(id, _)| Some(*id) != silent)
                        .map(|(_, n)| n)
                        .collect();
                    for n in &active {
                        assert_eq!(n.cursor, 4);
                        assert!(n.current >= 6);
                        let expected: Vec<_> = if silent.is_some() {
                            vec![2, 3, 4]
                        } else {
                            vec![1, 2, 3, 4]
                        };
                        assert_eq!(
                            n.deliveries.iter().map(|d| d.round).collect::<Vec<_>>(),
                            expected
                        );
                        for r in &expected {
                            assert!(n.committed(*r).is_some());
                            assert!(
                                matches!(n.terminal(*r), Terminal::Cer(_)),
                                "honest round chose NO-CER delta={delta} r={r}"
                            );
                        }
                        if silent.is_some() {
                            assert_eq!(n.terminal(1), Terminal::NoCer);
                            assert_eq!(n.statuses[&1], Status::Skip);
                            assert!(n.main_timers[&1].acted);
                        } else if mode == PacingMode::RoundBarrier {
                            let b = n.round_barriers.as_ref().unwrap();
                            assert_eq!(b.ready_releases, 4, "healthy B1..B4 use joint readiness");
                            assert_eq!(
                                b.deadline_releases, 1,
                                "only missing finite-input round5 uses fallback"
                            );
                            assert!(b.released.contains(&5));
                        } else {
                            let p = n.round_barriers.as_ref().unwrap();
                            assert_eq!(p.ready_releases, 4);
                            assert_eq!(
                                p.deadline_releases, 0,
                                "finite final CER must leave without waiting for proposal5"
                            );
                            assert!(p.pending.contains_key(&5));
                            assert_eq!(p.peak_held_messages, 0);
                            assert_eq!(p.urgent_through, 0);
                        }
                    }
                    assert!(active
                        .windows(2)
                        .all(|pair| pair[0].deliveries == pair[1].deliveries));
                }
            }
        }
    }
}

/// Immutable adapter configuration may be captured; mutable replica state must not be.
pub type Predicate = Box<dyn Fn(u64, &[u8], &[u8]) -> bool + Send + Sync>;
pub type Inputs = BTreeMap<u64, (Vec<u8>, Vec<u8>)>;
type Signatures = BTreeMap<(u64, Digest), BTreeMap<Id, Signed<Statement>>>;

/// Only local construction creates this owned token, after complete proposal
/// verification. It cannot enter through a public or wire receive path.
struct VerifiedProposal(Proposal);

enum InboxMessage {
    Message(Message),
    VerifiedProposal(VerifiedProposal),
}

#[derive(Clone, Debug)]
pub enum Effect {
    /// None means multicast. The caller sends to other members only; self has
    /// already been enqueued in this transition's local mailbox.
    Send {
        to: Option<Id>,
        message: Message,
    },
    Wake {
        at: u64,
    },
    DirectCommit {
        round: u64,
        digest: Digest,
    },
    Deliver(Delivery),
    Notice {
        kind: String,
        round: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    fn accepts(_: u64, _: &[u8], _: &[u8]) -> bool {
        true
    }
    fn node() -> Replica {
        let c = Committee::new(
            [42; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let mut n = Replica::new(c, 0, wire::fixture_key(0), 100, BTreeMap::new(), accepts);
        n.configure_ordering(OrderingSchedule::Canonical).unwrap();
        n.start(0).unwrap();
        n
    }
    fn short(n: &Replica, signer: Id, kind: Kind, r: u64, d: Option<Digest>) -> Signed<Statement> {
        wire::sign(
            &wire::fixture_key(signer),
            signer,
            Statement {
                context: n.committee.context.clone(),
                kind,
                round: r,
                digest: d,
            },
        )
    }
    fn closed(n: &mut Replica, at: u64, h: u64) {
        for i in [1, 2] {
            let s = short(n, i, Kind::Closed, h, None);
            n.receive(at, Message::Closed(s)).unwrap();
        }
    }
    fn enter(n: &mut Replica, at: u64, k: u64) -> Vec<Effect> {
        let mut effects = Vec::new();
        for i in [1, 2] {
            let s = short(n, i, Kind::Prog, k - 1, None);
            effects.extend(n.receive(at, Message::Prog(s)).unwrap());
        }
        effects
    }
    #[test]
    fn expired_catchup_waits_for_admission_and_never_restarts() {
        let mut n = node();
        closed(&mut n, 0, 1);
        assert_eq!(n.catchup_deadline(1), Some(300));
        n.tick(300).unwrap();
        assert_eq!(n.terminal(1), Terminal::Open);
        enter(&mut n, 350, 3);
        assert_eq!(n.terminal(1), Terminal::NoCer);
        closed(&mut n, 400, 1);
        assert_eq!(n.catchup_deadline(1), Some(300));
        assert!(n.own_reports.contains_key(&1));
    }
    #[test]
    fn exact_deadlines_and_every_exact_report_survive_prefix_catchup() {
        let mut n = node();
        closed(&mut n, 0, 1);
        closed(&mut n, 100, 5);
        assert_eq!(n.catchup_deadline(1), Some(300));
        assert_eq!(n.catchup_deadline(5), Some(400));
        enter(&mut n, 300, 3);
        assert_eq!(n.terminal(1), Terminal::NoCer);
        enter(&mut n, 350, 7);
        for r in 2..=5 {
            assert_eq!(
                n.terminal(r),
                Terminal::Open,
                "larger horizon inherited earlier expiry"
            );
        }
        let effects = n.tick(400).unwrap();
        for h in 2..=5 {
            assert_eq!(n.terminal(h), Terminal::NoCer);
            let report = n.own_reports.get(&h).unwrap();
            assert_eq!(report.header.body.horizon, h);
            history::verify_report(&n.committee, report).unwrap();
            let report_pos=effects.iter().position(|e|matches!(e,Effect::Send{message:Message::History3(r),..} if r.header.body.horizon==h)).unwrap();
            let closed_pos = effects
                .iter()
                .position(
                    |e| matches!(e,Effect::Send{message:Message::Closed(s),..} if s.body.round==h),
                )
                .unwrap();
            assert!(report_pos < closed_pos);
        }
        assert_eq!(n.own_reports.len(), 5);
        assert_eq!(n.closed_sent.len(), 5);
        assert!(!n.tick(401).unwrap().iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::History3(_) | Message::Closed(_),
                ..
            }
        )));
    }
    #[test]
    fn received_real_evidence_beats_expired_negative_timer_at_admission() {
        let mut n = node();
        let d = [7; 32];
        closed(&mut n, 0, 1);
        for i in [1, 2, 3] {
            let vote = short(&n, i, Kind::Vote, 1, Some(d));
            n.receive(
                299,
                Message::Vote {
                    vote,
                    header: None,
                    value: None,
                },
            )
            .unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Open);
        enter(&mut n, 300, 3);
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        assert_eq!(n.main_deadline(1), Some(1000)); // arms even after own CER
        history::verify_proof(&n.committee, &n.own_proofs[&1]).unwrap();
        assert!(!n.proposals.keys().any(|(r, _)| *r == 1));
        assert!(n.deliveries.is_empty());
    }
    fn initial_proposal(n: &Replica, r: u64, value: Vec<u8>) -> Proposal {
        let history = History::Empty;
        let witness = Vec::new();
        let header = Header {
            context: n.committee.context.clone(),
            round: r,
            value_hash: wire::hash(&value),
            witness_hash: wire::hash(&witness),
            history_hash: wire::hash(&history),
            entries: history::project(r, &history),
        };
        Proposal {
            header: wire::sign(&wire::fixture_key(n.leader(r)), n.leader(r), header),
            value,
            witness,
            history,
        }
    }
    #[test]
    fn cer_before_proposal_then_one_matching_validated_vote() {
        let mut n = node();
        enter(&mut n, 0, 3);
        let p = initial_proposal(&n, 1, b"matching".to_vec());
        let d = wire::proposal_digest(&p.header.body);
        for i in [1, 2] {
            let s = short(&n, i, Kind::Cer, 1, Some(d));
            n.receive(10, Message::Cer(s)).unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        assert_eq!(n.committed(1), Some(d));
        assert!(n.deliveries.is_empty());
        assert!(n.votes.get(&(1, d)).is_none());
        let effects = n.receive(20, Message::Propose(p.clone())).unwrap();
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(
                    e,
                    Effect::Send {
                        message: Message::Vote { .. },
                        ..
                    }
                ))
                .count(),
            1
        );
        assert_eq!(n.deliveries.len(), 1);
        let again = n.receive(21, Message::Propose(p)).unwrap();
        assert!(!again.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Vote { .. },
                ..
            } | Effect::Deliver(_)
        )));
    }
    #[test]
    fn independent_vote_signature_and_later_matching_attachment() {
        let mut n = node();
        enter(&mut n, 0, 3);
        let p = initial_proposal(&n, 1, b"payload".to_vec());
        let d = wire::proposal_digest(&p.header.body);
        for i in [1, 2, 3] {
            let vote = short(&n, i, Kind::Vote, 1, Some(d));
            n.receive(
                10,
                Message::Vote {
                    vote,
                    header: None,
                    value: None,
                },
            )
            .unwrap();
        }
        assert_eq!(n.terminal(1), Terminal::Cer(d));
        let mut bad = p.header.clone();
        bad.signature[0] ^= 1;
        let vote = short(&n, 1, Kind::Vote, 1, Some(d));
        n.receive(
            11,
            Message::Vote {
                vote: vote.clone(),
                header: Some(bad),
                value: Some(p.value.clone()),
            },
        )
        .unwrap();
        assert!(!n.headers.contains_key(&(1, d)));
        n.receive(
            12,
            Message::Vote {
                vote,
                header: Some(p.header),
                value: Some(p.value.clone()),
            },
        )
        .unwrap();
        assert_eq!(n.values[&(1, d)], p.value);
        assert!(n.slots[&1].voted().is_none()); // attachment is not full validation
    }
    #[test]
    fn projected_positive_never_enters_actual_signature_store() {
        let mut n = node();
        enter(&mut n, 0, 6);
        let entries = history::Entries {
            horizon: 1,
            pivot: 1,
            digest: Some([9; 32]),
            previous: vec![],
        };
        let value = vec![1];
        let header = Header {
            context: n.committee.context.clone(),
            round: 4,
            value_hash: wire::hash(&value),
            witness_hash: [0; 32],
            history_hash: [0; 32],
            entries,
        };
        let d = wire::proposal_digest(&header);
        let header = wire::sign(&wire::fixture_key(3), 3, header);
        let vote = short(&n, 1, Kind::Vote, 4, Some(d));
        n.receive(
            10,
            Message::Vote {
                vote,
                header: Some(header),
                value: Some(value),
            },
        )
        .unwrap();
        assert!(n.cers.get(&(1, [9; 32])).is_none());
        assert!(n.proofs.get(&(1, [9; 32])).is_none());
        assert_eq!(n.terminal(1), Terminal::Open);
        assert_eq!(n.statuses[&1], Status::Undecided);
    }
    #[test]
    fn closed_is_not_echoed_and_does_not_assert_all_negative() {
        let mut n = node();
        let s = short(&n, 1, Kind::Closed, 1, None);
        let effects = n.receive(0, Message::Closed(s)).unwrap();
        assert!(!effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Closed(_),
                ..
            }
        )));
        assert_eq!(n.terminal(1), Terminal::Open);
    }
    #[test]
    fn invalid_external_input_is_rejected_before_fixing_or_hashing_it() {
        let mut n = node();
        let too_large = vec![0; wire::MAX_WIRE_BYTES];
        assert!(n.supply_input(0, 1, too_large, vec![]).is_err());
        assert!(!n.inputs.contains_key(&1));
        let effects = n.supply_input(0, 1, b"valid".to_vec(), vec![]).unwrap();
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Propose(_),
                ..
            }
        )));
        let c = n.committee.clone();
        let bad = BTreeMap::from([(0, (vec![], vec![]))]);
        assert!(Replica::try_new(c, 0, wire::fixture_key(0), 100, bad, accepts).is_err());
    }

    fn cer_proof(n: &Replica, owner: Id, round: u64, digest: Digest) -> CerProof {
        CerProof {
            cer: short(n, owner, Kind::Cer, round, Some(digest)),
            triggers: (0..3)
                .map(|id| short(n, id, Kind::Vote, round, Some(digest)))
                .collect(),
        }
    }

    fn history_report(n: &Replica, owner: Id, horizon: u64, rounds: &[u64]) -> Report {
        let proofs: Vec<_> = rounds
            .iter()
            .map(|round| cer_proof(n, owner, *round, [*round as u8; 32]))
            .collect();
        Report {
            header: wire::sign(
                &wire::fixture_key(owner),
                owner,
                ReportHeader {
                    context: n.committee.context.clone(),
                    horizon,
                    positives: proofs
                        .iter()
                        .map(|proof| (proof.cer.body.round, proof.cer.body.digest.unwrap()))
                        .collect(),
                },
            ),
            proofs,
        }
    }

    #[test]
    fn waiting_for_history_quorum_does_not_recheck_immutable_input() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        for at_construction in [true, false] {
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = calls.clone();
            let inputs = if at_construction {
                BTreeMap::from([(5, (b"value".to_vec(), b"witness".to_vec()))])
            } else {
                BTreeMap::new()
            };
            let mut n = Replica::try_new(
                node().committee,
                0,
                wire::fixture_key(0),
                100,
                inputs,
                move |round, value, witness| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    round == 5 && value == b"value" && witness == b"witness"
                },
            )
            .unwrap();
            n.start(0).unwrap();
            enter(&mut n, 0, 5);
            if !at_construction {
                n.supply_input(0, 5, b"value".to_vec(), b"witness".to_vec())
                    .unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            for signer in [1, 2] {
                let report = history_report(&n, signer, 2, &[]);
                n.receive(0, Message::History3(report)).unwrap();
            }
            for now in 1..=50 {
                let effects = n.tick(now).unwrap();
                assert!(!effects.iter().any(|effect| matches!(
                    effect,
                    Effect::Send {
                        message: Message::Propose(_),
                        ..
                    }
                )));
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!n.proposal_sent.contains(&5));
            let report = history_report(&n, 3, 2, &[]);
            let effects = n.receive(51, Message::History3(report)).unwrap();
            assert!(effects.iter().any(|effect| matches!(
                effect,
                Effect::Send { message: Message::Propose(proposal), .. }
                    if proposal.header.body.round == 5
            )));
            // Admission evaluates Q once. Local assembled verification reuses
            // that exact immutable tuple, then owned self-delivery reuses the
            // complete proposal check without changing its ingestion phase.
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            for now in 52..=60 {
                n.tick(now).unwrap();
            }
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let proposal = effects
                .iter()
                .find_map(|effect| match effect {
                    Effect::Send {
                        message: Message::Propose(p),
                        ..
                    } => Some(p.clone()),
                    _ => None,
                })
                .unwrap();
            // Public receive cannot reuse local provenance, even for the exact
            // same proposal and our own signer: full verification runs again.
            n.receive(61, Message::Propose(proposal.clone())).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let mut tampered = proposal.clone();
            tampered.witness.push(0);
            assert!(n.receive(62, Message::Propose(tampered)).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 2); // binding fails before Q
            let mut rejected = proposal;
            rejected.value = b"rejected".to_vec();
            rejected.header.body.value_hash = wire::hash(&rejected.value);
            rejected.header = wire::sign(&wire::fixture_key(0), 0, rejected.header.body);
            assert!(n.receive(63, Message::Propose(rejected)).is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 3); // valid bindings still require Q
        }
    }

    #[test]
    fn verified_local_proposal_keeps_fifo_and_defers_every_ingest_mutation() {
        let inputs = BTreeMap::from([(1, (b"local".to_vec(), vec![]))]);
        let mut pair = [
            replay_node(0, false, inputs.clone()),
            replay_node(0, true, inputs),
        ];
        for n in &mut pair {
            n.current = 1;
            n.send(
                Some(n.id),
                Message::Closed(short(n, n.id, Kind::Closed, 2, None)),
            )
            .unwrap();
            n.propose().unwrap();
            n.send(
                Some(n.id),
                Message::Prog(short(n, n.id, Kind::Prog, 2, None)),
            )
            .unwrap();
            assert!(n.proposals.is_empty());
            assert!(n.headers.is_empty());
            assert!(n.values.is_empty());
            assert!(!n.closed.contains_key(&2));
            assert!(!n.progress.contains_key(&2));
            assert_eq!(n.inbox.len(), 3);
            assert!(matches!(
                n.inbox.front(),
                Some(InboxMessage::Message(Message::Closed(_)))
            ));
            assert!(matches!(
                n.inbox.back(),
                Some(InboxMessage::Message(Message::Prog(_)))
            ));
        }
        assert!(matches!(
            pair[0].inbox.get(1),
            Some(InboxMessage::VerifiedProposal(_))
        ));
        assert!(matches!(
            pair[1].inbox.get(1),
            Some(InboxMessage::Message(Message::Propose(_)))
        ));
        assert_eq!(effect_bytes(&pair[0].outbox), effect_bytes(&pair[1].outbox));
        // Original raw self-delivery is the independent state/effect oracle.
        replay_step(&mut pair, ReplayEvent::Tick(0));
        assert_eq!(pair[0].proposals.len(), 1);
        assert!(pair[0].closed[&2].contains_key(&0));
        assert!(pair[0].progress[&2].contains_key(&0));
    }

    #[test]
    fn local_q_reuse_requires_exact_admitted_tuple_and_keeps_full_proposal_checks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let mut n = Replica::try_new(
            node().committee,
            0,
            wire::fixture_key(0),
            100,
            BTreeMap::from([(5, (b"value".to_vec(), b"witness".to_vec()))]),
            move |r, x, pi| {
                counted.fetch_add(1, Ordering::SeqCst);
                r == 5 && x == b"value" && pi == b"witness"
            },
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1); // Original Q checked first.
        assert!(n.q_for_local_proposal(5, b"value", b"witness"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for (r, x, pi) in [
            (6, b"value".as_slice(), b"witness".as_slice()),
            (5, b"changed".as_slice(), b"witness".as_slice()),
            (5, b"value".as_slice(), b"changed".as_slice()),
        ] {
            assert!(!n.q_for_local_proposal(r, x, pi));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4); // Every mismatch called Q.
        let reports: Vec<_> = (0..3).map(|id| history_report(&n, id, 2, &[])).collect();
        let history = history::build_history(&n.committee, 5, &reports, &[]).unwrap();
        let mut p = initial_proposal(&n, 5, b"value".to_vec());
        p.witness = b"witness".to_vec();
        p.history = history;
        p.header.body.witness_hash = wire::hash(&p.witness);
        p.header.body.history_hash = wire::hash(&p.history);
        p.header.body.entries = history::project(5, &p.history);
        p.header = wire::sign(&wire::fixture_key(0), 0, p.header.body);
        n.verify_local_proposal(&p).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        let mut bad_header = p.clone();
        bad_header.header.body.value_hash[0] ^= 1;
        bad_header.header = wire::sign(&wire::fixture_key(0), 0, bad_header.header.body);
        assert!(n.verify_local_proposal(&bad_header).is_err());
        let mut missing_history = p.clone();
        missing_history.history = History::Empty;
        missing_history.header.body.history_hash = wire::hash(&missing_history.history);
        missing_history.header = wire::sign(&wire::fixture_key(0), 0, missing_history.header.body);
        // This header itself is valid, and the exact (r,x,pi) was Q-approved,
        // but complete verification must still reject its missing HISTORY3.
        n.committee.verify_header(&missing_history.header).unwrap();
        assert!(n.verify_local_proposal(&missing_history).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        // Generic self-send has no local construction token and cannot reuse Q.
        n.send(None, Message::Propose(p)).unwrap();
        assert!(matches!(
            n.inbox.back(),
            Some(InboxMessage::Message(Message::Propose(_)))
        ));
        n.settle().unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn pruned_proof_candidates_preserve_full_history_bytes() {
        // Round13 has horizon10. Include local gaps, future evidence, every
        // relation of a report-raised pivot to L, and an unselected report.
        let cases: &[(&[u64], [&[u64]; 4], u64)] = &[
            (&[], [&[], &[], &[], &[]], 0),
            (&[11, 12], [&[], &[], &[], &[]], 0),
            (&[1, 2, 3, 4, 5, 6, 7, 8, 11], [&[], &[], &[], &[]], 8),
            (&[1, 3, 8, 12], [&[], &[], &[], &[]], 8),
            (&[1, 6, 7, 8, 11], [&[9], &[], &[], &[]], 9),
            (&[1, 6, 7, 8, 11], [&[10], &[], &[], &[]], 10),
            (&[1, 5, 6, 7, 11], [&[10], &[], &[], &[]], 10),
            (&[1, 5, 6, 7, 11], [&[], &[], &[], &[10, 9, 8]], 10),
            (&[], [&[10, 9, 8], &[], &[], &[]], 10),
        ];
        for (local_rounds, report_rounds, expected_pivot) in cases {
            let mut n = node();
            for &round in *local_rounds {
                let proof = cer_proof(&n, 1, round, [round as u8; 32]);
                history::verify_proof(&n.committee, &proof).unwrap();
                n.retain_proof(proof);
            }
            let reports: Vec<_> = report_rounds
                .iter()
                .enumerate()
                .map(|(id, rounds)| history_report(&n, id as Id, 10, rounds))
                .collect();
            let full: Vec<_> = n.proofs.values().cloned().collect();
            let pruned = n.proposal_proofs(13);
            let old = history::build_history(&n.committee, 13, &reports, &full).unwrap();
            let new = history::build_history(&n.committee, 13, &reports, &pruned).unwrap();
            assert_eq!(wire::encode(&new).unwrap(), wire::encode(&old).unwrap());
            assert_eq!(history::project(13, &new).pivot, *expected_pivot);
            let local_pivot = local_rounds.iter().filter(|round| **round <= 10).max();
            let expected: Vec<_> = full
                .iter()
                .filter(|proof| {
                    local_pivot.is_some_and(|pivot| {
                        (pivot.saturating_sub(2).max(1)..=*pivot).contains(&proof.cer.body.round)
                    })
                })
                .cloned()
                .collect();
            assert_eq!(pruned, expected);
            assert!(n.proposal_proofs(3).is_empty());
        }
    }

    #[test]
    fn proof_pruning_keeps_all_digests_for_canonical_encoded_choice() {
        let mut n = node();
        for round in 1..=11 {
            // The smallest encoded proof starts with signer0 even though its
            // digest is larger than the signer3 proof's digest/map key.
            for (owner, digest) in [(3, [0; 32]), (0, [255; 32])] {
                let proof = cer_proof(&n, owner, round, digest);
                history::verify_proof(&n.committee, &proof).unwrap();
                n.retain_proof(proof);
            }
        }
        let reports: Vec<_> = (0..4).map(|id| history_report(&n, id, 10, &[])).collect();
        let full: Vec<_> = n.proofs.values().cloned().collect();
        let pruned = n.proposal_proofs(13);
        assert_eq!(pruned.len(), 6);
        let old = history::build_history(&n.committee, 13, &reports, &full).unwrap();
        let new = history::build_history(&n.committee, 13, &reports, &pruned).unwrap();
        assert_eq!(wire::encode(&new).unwrap(), wire::encode(&old).unwrap());
        let entries = history::project(13, &new);
        assert_eq!(entries.pivot, 10);
        assert_eq!(entries.digest, Some([255; 32]));
        assert!(entries
            .previous
            .iter()
            .all(|(_, entry)| *entry == history::Entry::Cer([255; 32])));
    }

    #[derive(Clone)]
    enum ReplayEvent {
        Start(u64),
        Tick(u64),
        Receive(u64, Message),
        Input(u64, u64, Vec<u8>),
    }

    fn replay_node(id: Id, legacy: bool, inputs: Inputs) -> Replica {
        let c = Committee::new(
            [42; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let mut n = Replica::new(c, id, wire::fixture_key(id), 100, inputs, accepts);
        n.configure_ordering(OrderingSchedule::Canonical).unwrap();
        n.legacy_sweeps = legacy;
        // Replay also checks that opt-in diagnostics preserve exact effects/state.
        if !legacy {
            n.enable_causal_trace(CausalTrace::for_test());
        }
        n
    }

    fn effect_bytes(effects: &[Effect]) -> Vec<Value> {
        effects
            .iter()
            .map(|effect| match effect {
                Effect::Send { to, message } => json!(["send", to, wire::encode(message).unwrap()]),
                Effect::Wake { at } => json!(["wake", at]),
                Effect::DirectCommit { round, digest } => json!(["commit", round, digest]),
                Effect::Deliver(delivery) => json!(["deliver", delivery]),
                Effect::Notice { kind, round } => json!(["notice", kind, round]),
            })
            .collect()
    }

    fn replay_step(pair: &mut [Replica; 2], event: ReplayEvent) -> Vec<Effect> {
        let apply = |n: &mut Replica, event: ReplayEvent| match event {
            ReplayEvent::Start(now) => n.start(now),
            ReplayEvent::Tick(now) => n.tick(now),
            ReplayEvent::Receive(now, message) => n.receive(now, message),
            ReplayEvent::Input(now, round, value) => n.supply_input(now, round, value, vec![]),
        };
        let first = apply(&mut pair[0], event.clone()).unwrap();
        let second = apply(&mut pair[1], event).unwrap();
        assert_eq!(
            effect_bytes(&first),
            effect_bytes(&second),
            "effect order/bytes changed"
        );
        let [indexed, legacy] = pair;
        assert_eq!(indexed.snapshot(), legacy.snapshot());
        assert_eq!(
            format!("{:?}", indexed.slots),
            format!("{:?}", legacy.slots)
        );
        assert_eq!(indexed.version, legacy.version);
        assert_eq!(indexed.inputs, legacy.inputs);
        assert_eq!(indexed.votes, legacy.votes);
        assert_eq!(indexed.cers, legacy.cers);
        assert_eq!(indexed.progress, legacy.progress);
        assert_eq!(indexed.closed, legacy.closed);
        assert_eq!(indexed.progress_sent, legacy.progress_sent);
        assert_eq!(indexed.proposal_sent, legacy.proposal_sent);
        assert_eq!(indexed.proposals, legacy.proposals);
        assert_eq!(indexed.values, legacy.values);
        assert_eq!(indexed.reports, legacy.reports);
        assert_eq!(indexed.proofs, legacy.proofs);
        assert!(indexed.inbox.is_empty() && legacy.inbox.is_empty());
        assert!(indexed.dirty_slots.is_empty());
        assert_eq!(
            indexed.open_outcomes,
            indexed
                .slots
                .iter()
                .filter_map(|(r, slot)| (slot.terminal() == Terminal::Open).then_some(*r))
                .collect()
        );
        assert_eq!(
            indexed.direct,
            indexed
                .slots
                .iter()
                .filter_map(|(r, slot)| slot.committed().map(|d| (*r, d)))
                .collect()
        );
        assert_eq!(
            indexed.pending_proposals,
            indexed
                .inputs
                .keys()
                .filter(|r| indexed.leader(**r) == indexed.id && !indexed.proposal_sent.contains(r))
                .copied()
                .collect()
        );
        assert_eq!(
            indexed.main_deadlines,
            indexed
                .main_timers
                .iter()
                .filter_map(|(r, t)| (!t.acted).then_some((t.deadline, *r)))
                .collect()
        );
        assert_eq!(
            indexed.catchup_deadlines,
            indexed
                .catchup_timers
                .iter()
                .filter_map(
                    |(h, t)| (!t.acted && t.deadline > indexed.now).then_some((t.deadline, *h))
                )
                .collect()
        );
        assert_eq!(
            indexed.catchup_expired,
            indexed
                .catchup_timers
                .iter()
                .filter_map(|(h, t)| (!t.acted && t.deadline <= indexed.now).then_some(*h))
                .collect()
        );
        first
    }

    fn replay_statement(
        pair: &mut [Replica; 2],
        now: u64,
        signer: Id,
        kind: Kind,
        r: u64,
        d: Option<Digest>,
    ) -> Vec<Effect> {
        let s = short(&pair[0], signer, kind, r, d);
        let message = match kind {
            Kind::Vote => Message::Vote {
                vote: s,
                header: None,
                value: None,
            },
            Kind::Cer => Message::Cer(s),
            Kind::Prog => Message::Prog(s),
            Kind::Closed => Message::Closed(s),
        };
        replay_step(pair, ReplayEvent::Receive(now, message))
    }

    fn replay_pair() -> [Replica; 2] {
        let mut pair = [
            replay_node(0, false, Inputs::new()),
            replay_node(0, true, Inputs::new()),
        ];
        replay_step(&mut pair, ReplayEvent::Start(0));
        pair
    }

    #[test]
    fn indexed_settlement_matches_sweeps_with_future_forks_and_late_attachments() {
        let mut pair = replay_pair();
        let p = initial_proposal(&pair[0], 1, b"late payload".to_vec());
        let d = wire::proposal_digest(&p.header.body);
        for signer in [1, 2] {
            replay_statement(&mut pair, 0, signer, Kind::Closed, 1, None);
        }
        // Future evidence does not certify before r+2 admission, even at the
        // timer deadline; the admission-triggered positive transition wins.
        for signer in [1, 2, 3] {
            replay_statement(&mut pair, 299, signer, Kind::Vote, 1, Some(d));
        }
        for signer in [1, 2] {
            replay_statement(&mut pair, 300, signer, Kind::Prog, 2, None);
        }
        assert_eq!(pair[0].terminal(1), Terminal::Cer(d));
        assert!(pair[0].catchup_timers[&1].acted);
        replay_statement(&mut pair, 300, 1, Kind::Cer, 1, Some(d));
        replay_statement(&mut pair, 300, 2, Kind::Cer, 1, Some(d));
        assert_eq!(pair[0].committed(1), Some(d));
        assert!(pair[0].deliveries.is_empty());
        // An unchanged signed VOTE can gain a header, then a value. Neither
        // insertion dirties the slot, but both must invalidate scanner reuse.
        let vote = short(&pair[0], 1, Kind::Vote, 1, Some(d));
        replay_step(
            &mut pair,
            ReplayEvent::Receive(
                301,
                Message::Vote {
                    vote: vote.clone(),
                    header: Some(p.header.clone()),
                    value: None,
                },
            ),
        );
        pair[0].work = SettlementWork::default();
        replay_step(
            &mut pair,
            ReplayEvent::Receive(
                302,
                Message::Vote {
                    vote,
                    header: Some(p.header.clone()),
                    value: Some(p.value.clone()),
                },
            ),
        );
        assert_eq!(pair[0].work.slots, 0);
        assert_eq!(pair[0].work.scans, 1);
        assert_eq!(pair[0].deliveries.len(), 1);
        replay_step(&mut pair, ReplayEvent::Receive(303, Message::Propose(p)));

        // A Byzantine round-2 leader supplies two fully valid proposals. Keep
        // both, while the first enabled vote remains immutable.
        let fork_a = initial_proposal(&pair[0], 2, b"fork-a".to_vec());
        let fork_b = initial_proposal(&pair[0], 2, b"fork-b".to_vec());
        replay_step(
            &mut pair,
            ReplayEvent::Receive(304, Message::Propose(fork_a.clone())),
        );
        replay_step(
            &mut pair,
            ReplayEvent::Receive(305, Message::Propose(fork_b)),
        );
        let voted = pair[0].slots[&2].voted();
        for signer in [1, 2] {
            replay_statement(&mut pair, 310, signer, Kind::Closed, 5, None);
        }
        replay_step(&mut pair, ReplayEvent::Tick(610));
        assert!(!pair[0].catchup_timers[&5].acted);
        // A future slot already has VOTE evidence; the admission leap must
        // revisit it as well as previously admitted but open rounds.
        for signer in [1, 2, 3] {
            replay_statement(&mut pair, 620, signer, Kind::Vote, 5, Some([5; 32]));
        }
        for signer in [1, 2] {
            replay_statement(&mut pair, 700, signer, Kind::Prog, 6, None);
        }
        assert_eq!(pair[0].terminal(5), Terminal::Cer([5; 32]));
        assert_eq!(pair[0].terminal(2), Terminal::NoCer);
        assert_eq!(pair[0].slots[&2].voted(), voted);
        // NO-CER is not an eviction: later matching CER quorum directly commits.
        let d2 = wire::proposal_digest(&fork_a.header.body);
        for signer in [1, 2, 3] {
            replay_statement(&mut pair, 710, signer, Kind::Cer, 2, Some(d2));
        }
        assert_eq!(pair[0].committed(2), Some(d2));
        assert_eq!(pair[0].terminal(2), Terminal::NoCer);
        // A late signed report contributes actual evidence even when addressed
        // to another leader, and exact report/proposal readiness remains live.
        let report = history_report(&pair[0], 1, 8, &[8, 7, 6]);
        replay_step(
            &mut pair,
            ReplayEvent::Receive(720, Message::History3(report)),
        );
        for signer in [1, 2] {
            replay_statement(&mut pair, 721, signer, Kind::Prog, 9, None);
        }
        for signer in [1, 2, 3] {
            let report = history_report(&pair[0], signer, 6, &[]);
            replay_step(
                &mut pair,
                ReplayEvent::Receive(722, Message::History3(report)),
            );
        }
        replay_step(
            &mut pair,
            ReplayEvent::Input(723, 9, b"asynchronous".to_vec()),
        );
        assert!(pair[0].proposal_sent.contains(&9));
        replay_step(&mut pair, ReplayEvent::Tick(1500));
    }

    #[test]
    fn indexed_expiries_preserve_round_order_across_different_deadlines() {
        let mut pair = replay_pair();
        for signer in [1, 2] {
            replay_statement(&mut pair, 0, signer, Kind::Prog, 6, None);
        }
        for (now, h) in [(10, 2), (20, 1)] {
            for signer in [1, 2, 3] {
                replay_statement(&mut pair, now, signer, Kind::Closed, h, None);
            }
        }
        assert!(pair[0].main_deadline(5) < pair[0].main_deadline(4));
        assert!(pair[0].catchup_deadline(2) < pair[0].catchup_deadline(1));
        let effects = replay_step(&mut pair, ReplayEvent::Tick(1000));
        let expiries: Vec<_> = effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Notice { kind, round } if kind.ends_with("_expiry") => {
                    Some((kind.as_str(), *round))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            expiries,
            vec![
                ("main_timer_expiry", 1),
                ("main_timer_expiry", 2),
                ("main_timer_expiry", 3),
                ("main_timer_expiry", 4),
                ("main_timer_expiry", 5),
                ("catchup_timer_expiry", 1),
                ("catchup_timer_expiry", 2),
            ]
        );
    }

    #[test]
    fn settled_prefix_is_not_revisited_on_tick_or_duplicate_evidence() {
        let mut pair = replay_pair();
        const PREFIX: u64 = 96;
        for h in 1..=PREFIX {
            for signer in [1, 2, 3] {
                replay_statement(&mut pair, 0, signer, Kind::Closed, h, None);
            }
        }
        for signer in [1, 2] {
            replay_statement(&mut pair, 0, signer, Kind::Prog, PREFIX + 1, None);
        }
        replay_step(&mut pair, ReplayEvent::Tick(1000));
        assert_eq!(pair[0].own_reports.len(), PREFIX as usize);
        assert_eq!(pair[0].main_timers.len(), PREFIX as usize);
        assert_eq!(pair[0].catchup_timers.len(), PREFIX as usize);
        pair[0].work = SettlementWork::default();
        for now in 1001..=1010 {
            replay_step(&mut pair, ReplayEvent::Tick(now));
            replay_statement(&mut pair, now, 1, Kind::Closed, PREFIX, None);
            replay_statement(&mut pair, now, 1, Kind::Prog, PREFIX + 1, None);
        }
        assert_eq!(pair[0].work.slots, 0);
        assert_eq!(pair[0].work.report_prefix, 0);
        assert_eq!(pair[0].work.main_arms, 0);
        assert_eq!(pair[0].work.catchup_arms, 0);
        assert_eq!(pair[0].work.expiries, 0);
        assert_eq!(pair[0].work.finishes, 0);
        assert_eq!(pair[0].work.proposals, 0);
        assert_eq!(pair[0].work.scans, 0);
        assert_eq!(pair[0].work.scanned_rounds, 0);
        // Only the live current-round PROG entry remains relevant per step.
        assert_eq!(pair[0].work.progress, 30);
    }

    fn scanner_attachment(
        n: &mut Replica,
        round: u64,
        entries: history::Entries,
        with_value: bool,
    ) -> Digest {
        // As in scanner's unit fixtures, these are authenticated structural
        // projections. Full HISTORY3 is irrelevant to these local scanner tests.
        let mut p = initial_proposal(n, round, round.to_le_bytes().to_vec());
        p.header.body.entries = entries;
        p.header = wire::sign(
            &wire::fixture_key(n.leader(round)),
            n.leader(round),
            p.header.body,
        );
        n.committee.verify_header(&p.header).unwrap();
        let digest = wire::proposal_digest(&p.header.body);
        n.retain_header(round, digest, p.header, with_value.then_some(p.value));
        digest
    }

    fn scanner_negative(round: u64) -> history::Entries {
        history::Entries {
            horizon: round.saturating_sub(3),
            pivot: 0,
            digest: None,
            previous: vec![],
        }
    }

    fn scanner_direct(n: &mut Replica, round: u64, digest: Digest) {
        for signer in [1, 2, 3] {
            n.retain_statement(short(n, signer, Kind::Cer, round, Some(digest)));
        }
        // Direct commit needs no admission; avoid introducing unrelated own CER
        // transitions in a fixture that exercises the direct-commit boundary.
        let actions = n.slots.get_mut(&round).unwrap().drive(0);
        assert_eq!(actions, vec![Action::DirectCommit(digest)]);
        n.apply_actions(round, actions).unwrap();
    }

    fn passed_scanner_prefix(commit: bool) -> (Replica, Digest) {
        let mut n = node();
        n.current = 4;
        let first = scanner_attachment(&mut n, 1, scanner_negative(1), true);
        let entries = if commit {
            history::Entries {
                horizon: 1,
                pivot: 1,
                digest: Some(first),
                previous: vec![],
            }
        } else {
            scanner_negative(4)
        };
        let fourth = scanner_attachment(&mut n, 4, entries, false);
        scanner_direct(&mut n, 4, fourth);
        n.scan_and_release();
        assert_eq!(n.cursor, 1);
        assert_eq!(
            n.statuses[&1],
            if commit {
                Status::Commit(first)
            } else {
                Status::Skip
            }
        );
        n.outbox.clear();
        (n, first)
    }

    #[test]
    fn passed_prefix_still_rejects_conflicting_late_direct_commitments() {
        for commit in [false, true] {
            let (mut n, first) = passed_scanner_prefix(commit);
            let conflicting = if commit { [82; 32] } else { first };
            let mut direct = n.direct.clone();
            direct.insert(1, conflicting);
            let old_full_scan = scanner::scan(n.current, &direct, &n.headers);
            assert_ne!(old_full_scan[&1], n.statuses[&1]);
            // Deliberately inconsistent evidence: both implementations must
            // detect a safety violation, not silently retain the old prefix.
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scanner_direct(&mut n, 1, conflicting);
            }))
            .unwrap_err();
            let text = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap();
            assert!(text.contains("decided classification changed"));
            assert!(!n.direct.contains_key(&1));
            assert!(!n
                .outbox
                .iter()
                .any(|e| matches!(e, Effect::DirectCommit { round: 1, .. })));
        }
    }

    #[test]
    fn matching_late_direct_commit_keeps_passed_prefix_without_redelivery() {
        let (mut n, first) = passed_scanner_prefix(true);
        let delivered = n.deliveries.clone();
        let statuses = n.statuses.clone();
        scanner_direct(&mut n, 1, first);
        n.work = SettlementWork::default();
        n.scan_and_release();
        assert_eq!(n.statuses, statuses);
        assert_eq!(n.statuses, scanner::scan(n.current, &n.direct, &n.headers));
        assert_eq!(n.deliveries, delivered);
        assert_eq!(n.cursor, 1);
        assert_eq!(n.work.scanned_rounds, 3);
        assert!(!n.outbox.iter().any(|e| matches!(e, Effect::Deliver(_))));
    }

    #[test]
    #[should_panic(expected = "decided classification changed")]
    fn live_suffix_keeps_final_classification_assertions_before_attachments_arrive() {
        let mut n = node();
        let digest = [81; 32];
        scanner_direct(&mut n, 1, digest);
        n.scan_and_release();
        assert_eq!(n.cursor, 0); // No header or value has arrived.
        assert_eq!(n.statuses[&1], Status::Commit(digest));
        // Deliberately bypass the admission check to prove the original suffix
        // assertion also remains. Real retained direct entries never mutate.
        n.direct.insert(1, [82; 32]);
        n.scan_and_release();
    }

    #[test]
    fn changed_snapshot_scans_only_live_suffix_and_matches_full_reference() {
        const PREFIX: u64 = 96;
        const HORIZON: u64 = PREFIX + 4;
        let mut pair = [node(), node()];
        pair[1].legacy_sweeps = true;
        for n in &mut pair {
            n.current = HORIZON;
            for round in 1..=PREFIX {
                let digest = scanner_attachment(n, round, scanner_negative(round), true);
                scanner_direct(n, round, digest);
            }
            n.scan_and_release();
            assert_eq!(n.cursor, PREFIX);
            n.outbox.clear();
            n.work = SettlementWork::default();
            let digest = scanner_attachment(n, HORIZON, scanner_negative(HORIZON), false);
            scanner_direct(n, HORIZON, digest);
            n.scan_and_release();
        }
        assert_eq!(pair[0].snapshot(), pair[1].snapshot());
        assert_eq!(effect_bytes(&pair[0].outbox), effect_bytes(&pair[1].outbox));
        assert_eq!(pair[0].work.scanned_rounds, 4);
        assert_eq!(pair[1].work.scanned_rounds, HORIZON as usize);
        assert_eq!(pair[0].cursor, PREFIX + 1); // New anchor resolves one Skip.
        assert_eq!(pair[0].deliveries.len(), PREFIX as usize);
        assert_eq!(pair[0].statuses.len(), HORIZON as usize); // Prefix is retained.
    }

    #[test]
    fn indexed_four_replica_replay_matches_sweeps_through_honest_and_silent_rounds() {
        const LAST: u64 = 10;
        fn enqueue(queue: &mut VecDeque<(usize, Message)>, sender: usize, effects: Vec<Effect>) {
            for effect in effects {
                if let Effect::Send { to, message } = effect {
                    // Stop external progress at a finite admission horizon;
                    // retain all VOTE/CER/HISTORY3/CLOSED traffic at that horizon.
                    if matches!(&message, Message::Prog(s) if s.body.round > LAST + 1) {
                        continue;
                    }
                    for target in 0..4 {
                        if target != sender && (to.is_none() || to == Some(target as Id)) {
                            queue.push_back((target, message.clone()));
                        }
                    }
                }
            }
        }
        fn drain(nodes: &mut [[Replica; 2]], queue: &mut VecDeque<(usize, Message)>, now: u64) {
            let mut received = 0;
            while !queue.is_empty() {
                received += 1;
                assert!(received < 12000, "finite replay failed to quiesce");
                // A deterministic external delivery schedule, with reordering
                // and duplicate messages, is identical for oracle and indexes.
                let (target, message) = if received % 7 == 0 {
                    queue.pop_back().unwrap()
                } else {
                    queue.pop_front().unwrap()
                };
                let effects = replay_step(
                    &mut nodes[target],
                    ReplayEvent::Receive(now, message.clone()),
                );
                enqueue(queue, target, effects);
                if received % 17 == 0 {
                    let effects =
                        replay_step(&mut nodes[target], ReplayEvent::Receive(now, message));
                    enqueue(queue, target, effects);
                }
            }
        }
        for silent_first in [false, true] {
            let inputs: Inputs = (1..=LAST)
                .filter(|r| !silent_first || *r != 1)
                .map(|r| (r, (format!("payload-{r}").into_bytes(), vec![])))
                .collect();
            let mut nodes: Vec<_> = (0..4)
                .map(|id| {
                    [
                        replay_node(id, false, inputs.clone()),
                        replay_node(id, true, inputs.clone()),
                    ]
                })
                .collect();
            let mut queue = VecDeque::new();
            for (id, pair) in nodes.iter_mut().enumerate() {
                let effects = replay_step(pair, ReplayEvent::Start(0));
                enqueue(&mut queue, id, effects);
            }
            drain(&mut nodes, &mut queue, 10);
            for now in [1000, 2000, 3000] {
                for (id, pair) in nodes.iter_mut().enumerate() {
                    let effects = replay_step(pair, ReplayEvent::Tick(now));
                    enqueue(&mut queue, id, effects);
                }
                drain(&mut nodes, &mut queue, now);
            }
            let expected: Vec<_> = (1..=LAST).filter(|r| !silent_first || *r != 1).collect();
            for pair in &nodes {
                let indexed = &pair[0];
                assert_eq!(
                    indexed
                        .deliveries
                        .iter()
                        .map(|d| d.round)
                        .collect::<Vec<_>>(),
                    expected
                );
                assert_eq!(indexed.cursor, LAST);
                assert_eq!(
                    indexed.statuses[&1],
                    if silent_first {
                        Status::Skip
                    } else {
                        Status::Commit(indexed.committed(1).unwrap())
                    }
                );
                for r in 2..=4 {
                    assert!(indexed.committed(r).is_some());
                }
            }
        }
    }

    #[test]
    fn lazy_direct_certificates_match_complete_reverse_candidate_order() {
        let mut n = node();
        // Use actual retained signed metadata, including two candidate digests
        // in one round. This helper is independent of Slot certificate choice.
        for (round, value, count, attachment) in [
            (1, b"a".as_slice(), 3, true),
            (2, b"a", 4, true),
            (2, b"b", 3, true),
            (3, b"future", 3, true),
            (2, b"incomplete", 2, true),
            (2, b"missing", 3, false),
        ] {
            let p = initial_proposal(&n, round, value.to_vec());
            let d = wire::proposal_digest(&p.header.body);
            if attachment {
                n.retain_header(round, d, p.header, Some(p.value));
            }
            for signer in (0..count).rev() {
                let cer = short(&n, signer, Kind::Cer, round, Some(d));
                n.retain_statement(cer);
            }
        }
        for before in [0, 1, 2, 3, 4] {
            let legacy: Vec<_> = n
                .cers
                .iter()
                .rev()
                .filter_map(|(&(r, d), cers)| {
                    if r >= before || cers.len() < n.quorum() {
                        return None;
                    }
                    Some((
                        n.headers.get(&(r, d))?.clone(),
                        n.values.get(&(r, d))?.clone(),
                        cers.values().take(n.quorum()).cloned().collect::<Vec<_>>(),
                    ))
                })
                .collect();
            let lazy: Vec<_> = n.direct_certificates_before(before).collect();
            assert_eq!(lazy, legacy);
            assert_eq!(
                n.direct_certificates_before(before).next(),
                legacy.first().cloned()
            );
            for (_, _, cers) in lazy {
                assert_eq!(
                    cers.iter().map(|s| s.signer).collect::<Vec<_>>(),
                    vec![0, 1, 2]
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Timer {
    deadline: u64,
    acted: bool,
}

/// Outgoing scheduling policy. New replicas emit PROG immediately on admission;
/// availability preparation overlaps ordering without delaying round progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderingSchedule {
    /// Immediate PROG emission from the reference ordering algorithm (default).
    Canonical,
    /// Delay only originating PROG until a full neighboring proposal or deadline.
    ProgressPacing { release_delay_ms: u64 },
    /// Experimental joint-message barrier; positive messages can also wait.
    RoundBarrier { release_delay_ms: u64 },
}

/// Output scheduling gate, separate from both canonical outcome timers.
/// Barrier r starts on entry to r+1. Local evidence and self delivery proceed
/// while outward messages wait for the joint prerequisites or this deadline.
struct RoundBarrier {
    deadline: u64,
    outgoing: Vec<(Option<Id>, Message)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PacingMode {
    RoundBarrier,
    ProgressOnly,
}

struct RoundBarriers {
    mode: PacingMode,
    release_delay_ms: u64,
    pending: BTreeMap<u64, RoundBarrier>,
    deadlines: BTreeSet<(u64, u64)>,
    dirty: BTreeSet<u64>,
    released: BTreeSet<u64>,
    amplify: BTreeSet<u64>,
    ready_releases: u64,
    deadline_releases: u64,
    urgent_releases: u64,
    urgent_through: u64,
    held_messages: usize,
    peak_held_messages: usize,
    peak_pending: usize,
}

impl RoundBarriers {
    fn new(mode: PacingMode, release_delay_ms: u64, urgent_through: u64) -> Self {
        Self {
            mode,
            release_delay_ms,
            pending: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            dirty: BTreeSet::new(),
            released: BTreeSet::new(),
            amplify: BTreeSet::new(),
            ready_releases: 0,
            deadline_releases: 0,
            urgent_releases: 0,
            urgent_through,
            held_messages: 0,
            peak_held_messages: 0,
            peak_pending: 0,
        }
    }
}

#[cfg(test)]
#[derive(Default, Debug, PartialEq, Eq)]
struct SettlementWork {
    slots: usize,
    progress: usize,
    report_prefix: usize,
    main_arms: usize,
    catchup_arms: usize,
    expiries: usize,
    finishes: usize,
    proposals: usize,
    scans: usize,
    scanned_rounds: usize,
}

pub struct Replica {
    committee: Committee,
    id: Id,
    key: Keypair,
    bound: u64,
    q: Predicate,
    inputs: Inputs,
    now: u64,
    started: bool,
    current: u64,
    cursor: u64,
    version: u64,
    slots: BTreeMap<u64, Slot>,
    // Scheduling indexes only: all original slots, evidence, and once guards
    // remain retained. A terminal slot can still vote or directly commit later.
    dirty_slots: BTreeSet<u64>,
    open_outcomes: BTreeSet<u64>,
    pending_proposals: BTreeSet<u64>,
    votes: Signatures,
    cers: Signatures,
    progress: BTreeMap<u64, BTreeMap<Id, Signed<Statement>>>,
    closed: BTreeMap<u64, BTreeMap<Id, Signed<Statement>>>,
    progress_sent: BTreeSet<u64>,
    round_barriers: Option<RoundBarriers>,
    schedule_configured: bool,
    closed_sent: BTreeMap<u64, Signed<Statement>>,
    proposal_sent: BTreeSet<u64>,
    proposals: BTreeMap<(u64, Digest), Proposal>,
    headers: BTreeMap<(u64, Digest), Signed<Header>>,
    values: BTreeMap<(u64, Digest), Vec<u8>>,
    reports: BTreeMap<u64, BTreeMap<Id, Report>>,
    own_reports: BTreeMap<u64, Report>,
    own_proofs: BTreeMap<u64, CerProof>,
    proofs: BTreeMap<(u64, Digest), CerProof>,
    main_timers: BTreeMap<u64, Timer>,
    catchup_timers: BTreeMap<u64, Timer>,
    main_arm_ready: BTreeSet<u64>,
    catchup_arm_ready: BTreeSet<u64>,
    main_deadlines: BTreeSet<(u64, u64)>,
    catchup_deadlines: BTreeSet<(u64, u64)>,
    catchup_expired: BTreeSet<u64>,
    direct: BTreeMap<u64, Digest>,
    scanned_inputs: Option<(u64, usize, usize, usize)>,
    statuses: BTreeMap<u64, Status>,
    deliveries: Vec<Delivery>,
    inbox: VecDeque<InboxMessage>,
    outbox: Vec<Effect>,
    causal: Option<CausalTrace>,
    #[cfg(test)]
    legacy_sweeps: bool,
    #[cfg(test)]
    work: SettlementWork,
}

impl Replica {
    pub fn new(
        committee: Committee,
        id: Id,
        key: Keypair,
        bound: u64,
        inputs: Inputs,
        q: impl Fn(u64, &[u8], &[u8]) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self::try_new(committee, id, key, bound, inputs, q).expect("invalid replica configuration")
    }
    pub fn try_new(
        committee: Committee,
        id: Id,
        key: Keypair,
        bound: u64,
        inputs: Inputs,
        q: impl Fn(u64, &[u8], &[u8]) -> bool + Send + Sync + 'static,
    ) -> Result<Self, String> {
        if bound == 0
            || bound > u64::MAX / 7
            || committee.keys.get(id as usize) != Some(&key.public)
        {
            return Err("invalid timer bound or own identity/key".into());
        }
        for (round, (value, witness)) in &inputs {
            if *round == 0 || *round > wire::MAX_ROUND {
                return Err("invalid input round".into());
            }
            committee.validate_input_size(value, witness)?;
            if !q(*round, value, witness) {
                return Err("configured input fails Q".into());
            }
        }
        let pending_proposals = inputs
            .keys()
            .filter(|r| ((**r - 1) % committee.keys.len() as u64) as Id == id)
            .copied()
            .collect();
        Ok(Self {
            committee,
            id,
            key,
            bound,
            q: Box::new(q),
            inputs,
            now: 0,
            started: false,
            current: 0,
            cursor: 0,
            version: 0,
            slots: BTreeMap::new(),
            dirty_slots: BTreeSet::new(),
            open_outcomes: BTreeSet::new(),
            pending_proposals,
            votes: BTreeMap::new(),
            cers: BTreeMap::new(),
            progress: BTreeMap::new(),
            closed: BTreeMap::new(),
            progress_sent: BTreeSet::new(),
            round_barriers: None,
            schedule_configured: false,
            closed_sent: BTreeMap::new(),
            proposal_sent: BTreeSet::new(),
            proposals: BTreeMap::new(),
            headers: BTreeMap::new(),
            values: BTreeMap::new(),
            reports: BTreeMap::new(),
            own_reports: BTreeMap::new(),
            own_proofs: BTreeMap::new(),
            proofs: BTreeMap::new(),
            main_timers: BTreeMap::new(),
            catchup_timers: BTreeMap::new(),
            main_arm_ready: BTreeSet::from([1, 2, 3]),
            catchup_arm_ready: BTreeSet::new(),
            main_deadlines: BTreeSet::new(),
            catchup_deadlines: BTreeSet::new(),
            catchup_expired: BTreeSet::new(),
            direct: BTreeMap::new(),
            scanned_inputs: None,
            statuses: BTreeMap::new(),
            deliveries: Vec::new(),
            inbox: VecDeque::new(),
            outbox: Vec::new(),
            causal: None,
            #[cfg(test)]
            legacy_sweeps: false,
            #[cfg(test)]
            work: SettlementWork::default(),
        })
    }
    fn quorum(&self) -> usize {
        self.committee.keys.len() - (self.committee.keys.len() - 1) / 3
    }
    pub(crate) fn enable_causal_trace(&mut self, trace: CausalTrace) {
        self.causal = Some(trace);
    }
    /// Opt into an experimental protocol variant before starting. Barrier r
    /// releases PROG(r+1), VOTE(r), CER(r-1), and the exact prior report/CLOSED
    /// only after full validation, own VOTE and prior outcome/report readiness,
    /// or a finite deadline from entry to r+1. PROG amplification bypasses the
    /// barrier. Any authenticated remote CLOSED(h), or our actually broadcast
    /// CLOSED(h), permanently bypasses barriers through h+1 to preserve timely
    /// positive sends during catch-up. One Byzantine distant hint can therefore
    /// disable pacing, but cannot create an outcome or bypass admission quorum.
    /// This variant does not inherit the canonical latency theorems.
    pub fn enable_round_barrier(&mut self, release_delay_ms: u64) -> Result<(), String> {
        self.configure_ordering(OrderingSchedule::RoundBarrier { release_delay_ms })
    }
    /// Configure the default origin-only pacing with an explicit delay.
    /// Entering k schedules PROG(k) for the
    /// first full valid proposal at k-1 or k, or the independent entry deadline.
    /// Initial PROG and f+1 amplification remain immediate. All VOTE, CER,
    /// HISTORY3 and CLOSED sends/self-deliveries retain their original timing.
    /// CLOSED hints do not release these gates. This mode is mutually exclusive
    /// with the round barrier and does not inherit entry-only 3-delta alignment.
    pub fn enable_progress_pacing(&mut self, release_delay_ms: u64) -> Result<(), String> {
        self.configure_ordering(OrderingSchedule::ProgressPacing { release_delay_ms })
    }
    /// Override the constructor's progress-pacing default once before starting.
    /// No retained evidence or protocol guards change when selecting a policy.
    pub fn configure_ordering(&mut self, schedule: OrderingSchedule) -> Result<(), String> {
        if self.started || self.current != 0 || self.schedule_configured {
            return Err("ordering schedule must be configured once before start".into());
        }
        self.round_barriers = match schedule {
            OrderingSchedule::Canonical => None,
            OrderingSchedule::ProgressPacing { release_delay_ms }
            | OrderingSchedule::RoundBarrier { release_delay_ms } => {
                if release_delay_ms == 0 || release_delay_ms > self.bound {
                    return Err(
                        "pacing release delay must be positive and at most the timer bound".into(),
                    );
                }
                let mode = if matches!(schedule, OrderingSchedule::ProgressPacing { .. }) {
                    PacingMode::ProgressOnly
                } else {
                    PacingMode::RoundBarrier
                };
                let urgent_through = if mode == PacingMode::RoundBarrier {
                    self.closed.keys().next_back().map_or(0, |h| h + 1)
                } else {
                    0
                };
                Some(RoundBarriers::new(mode, release_delay_ms, urgent_through))
            }
        };
        self.schedule_configured = true;
        Ok(())
    }
    pub fn ordering_schedule(&self) -> OrderingSchedule {
        match &self.round_barriers {
            None => OrderingSchedule::Canonical,
            Some(gates) if gates.mode == PacingMode::ProgressOnly => {
                OrderingSchedule::ProgressPacing {
                    release_delay_ms: gates.release_delay_ms,
                }
            }
            Some(gates) => OrderingSchedule::RoundBarrier {
                release_delay_ms: gates.release_delay_ms,
            },
        }
    }
    fn amplification(&self) -> usize {
        (self.committee.keys.len() - 1) / 3 + 1
    }
    fn leader(&self, r: u64) -> Id {
        ((r - 1) % self.committee.keys.len() as u64) as Id
    }
    pub fn current_round(&self) -> u64 {
        self.current
    }
    /// The composition layer may open its one reporting opportunity when the
    /// scheduled leader is admitted and has the exact history needed to propose.
    /// This is a readiness query, not a change to admission or outcome timers.
    pub fn input_preparation_ready(&self, round: u64) -> bool {
        round > 0
            && round <= self.current
            && self.leader(round) == self.id
            && (round <= 3
                || self.reports.get(&(round - 3)).map_or(0, BTreeMap::len) >= self.quorum())
    }
    /// Last locally completed, authenticated outcome prefix. HISTORY3 is sent
    /// before this prefix becomes visible to the composition layer.
    pub fn own_report_horizon(&self) -> u64 {
        self.own_reports.keys().next_back().copied().unwrap_or(0)
    }
    /// Prepare two proposal positions ahead of the healthy send wave. At the
    /// boundary emitting P(r-2), own CER/HISTORY3(r-4) and a fully validated
    /// P(r-3) enable REPORT(r). Its two-message exchange completes alongside
    /// history for P(r). Outcome progress alone can run ahead of that wave:
    /// freezing without P(r-3) makes a silent predecessor's recovery anchor
    /// miss all arrivals during its timeout. Round 4 uses the genesis prefix,
    /// but still requires P(1); only rounds 1..=3 prepare unconditionally.
    /// A completed own prefix r-3 also permits fresh recovery preparation.
    /// f+1 CLOSED(r-3) or exact history readiness retain timely recovery when
    /// local outcomes lag: each has at least one honest completed-prefix sender.
    /// Thus every prepared round is at most the greatest correct prefix + 4.
    pub fn pipeline_preparation_ready(&self, round: u64) -> bool {
        round > 0
            && round <= self.current
            && self.leader(round) == self.id
            && (round <= 3
                || self.own_reports.contains_key(&(round - 3))
                || ((round == 4 || self.own_reports.contains_key(&(round - 4)))
                    && self.preparation_predecessor_validated(round))
                || self.closed.get(&(round - 3)).map_or(0, BTreeMap::len) >= self.amplification()
                || self.input_preparation_ready(round))
    }
    /// Only a full authenticated proposal that passed immutable Q supplies the
    /// speculative wave evidence. A retained header, VOTE, or CER is insufficient.
    pub fn preparation_predecessor_validated(&self, round: u64) -> bool {
        round.checked_sub(3).filter(|h| *h > 0).is_some_and(|h| {
            self.proposals
                .range((h, [0; 32])..=(h, [u8::MAX; 32]))
                .next()
                .is_some()
        })
    }
    /// Authenticated distinct CLOSED senders supporting preparation recovery.
    pub fn preparation_closed_signers(&self, round: u64) -> Vec<Id> {
        round
            .checked_sub(3)
            .and_then(|h| self.closed.get(&h))
            .map(|s| s.keys().copied().collect())
            .unwrap_or_default()
    }
    pub fn last_delivered(&self) -> u64 {
        self.cursor
    }
    pub fn terminal(&self, r: u64) -> Terminal {
        self.slots.get(&r).map_or(Terminal::Open, Slot::terminal)
    }
    pub fn committed(&self, r: u64) -> Option<Digest> {
        self.slots.get(&r).and_then(Slot::committed)
    }
    /// Complete earlier direct certificates available to the composition layer,
    /// greatest round first. Eligibility depends on authenticated metadata, not
    /// on local ordered delivery or payload execution.
    pub fn direct_certificates_before(
        &self,
        before: u64,
    ) -> impl Iterator<Item = (Signed<Header>, Vec<u8>, Vec<Signed<Statement>>)> + '_ {
        self.cers
            .range(..(before, [0; 32]))
            .rev()
            .filter_map(|(&(round, digest), cers)| {
                if cers.len() < self.quorum() {
                    return None;
                }
                Some((
                    self.headers.get(&(round, digest))?.clone(),
                    self.values.get(&(round, digest))?.clone(),
                    cers.values().take(self.quorum()).cloned().collect(),
                ))
            })
    }
    pub fn deliveries(&self) -> &[Delivery] {
        &self.deliveries
    }
    pub fn own_reports(&self) -> &BTreeMap<u64, Report> {
        &self.own_reports
    }
    pub fn statuses(&self) -> &BTreeMap<u64, Status> {
        &self.statuses
    }
    pub fn main_deadline(&self, r: u64) -> Option<u64> {
        self.main_timers.get(&r).map(|t| t.deadline)
    }
    pub fn catchup_deadline(&self, h: u64) -> Option<u64> {
        self.catchup_timers.get(&h).map(|t| t.deadline)
    }

    pub fn start(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        if !self.started {
            self.started = true;
            self.enter(1)?;
        }
        self.settle()
    }
    pub fn receive(&mut self, now: u64, message: Message) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        // Check an entire bounded frame before any state mutation from its fields.
        self.committee
            .encoded_size(&wire::MessageRef::from(&message))?;
        self.ingest(message)?;
        self.settle()
    }
    pub fn tick(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        self.set_time(now)?;
        self.settle()
    }
    /// Explicit asynchronous input arrival for testing the external-readiness
    /// premise. Supplying late input does not reset any ordering timer.
    pub fn supply_input(
        &mut self,
        now: u64,
        round: u64,
        value: Vec<u8>,
        witness: Vec<u8>,
    ) -> Result<Vec<Effect>, String> {
        let validation_start = self.causal.as_ref().map(CausalTrace::now_us);
        self.set_time(now)?;
        self.committee.validate_input_size(&value, &witness)?;
        if round == 0 || round > wire::MAX_ROUND || !(self.q)(round, &value, &witness) {
            return Err("invalid immutable input".into());
        }
        if self.inputs.contains_key(&round) {
            return Err("input already fixed for round".into());
        }
        self.inputs.insert(round, (value, witness));
        if let Some(trace) = &self.causal {
            trace.span("input_fixed", round, validation_start.unwrap(), json!({}));
        }
        if self.leader(round) == self.id {
            self.pending_proposals.insert(round);
        }
        self.version += 1;
        self.settle()
    }
    fn set_time(&mut self, now: u64) -> Result<(), String> {
        if now < self.now {
            return Err("local clock moved backwards".into());
        }
        self.now = now;
        Ok(())
    }
    fn slot(&mut self, r: u64) -> &mut Slot {
        let n = self.committee.keys.len();
        let own = self.id;
        self.slots.entry(r).or_insert_with(|| {
            self.dirty_slots.insert(r);
            self.open_outcomes.insert(r);
            Slot::new(r, n, own)
        })
    }
    fn notice(&mut self, kind: &str, round: u64) {
        if let Some(trace) = &self.causal {
            match kind {
                "no_cer" => trace.mark("no_cer", round, json!({})),
                "main_timer_expiry" => trace.mark("main_timer_expiry", round, json!({})),
                "catchup_timer_expiry" => trace.mark("catchup_timer_expiry", round, json!({})),
                _ => {}
            }
        }
        self.outbox.push(Effect::Notice {
            kind: kind.into(),
            round,
        });
    }
    fn signed(&self, kind: Kind, round: u64, digest: Option<Digest>) -> Signed<Statement> {
        wire::sign(
            &self.key,
            self.id,
            Statement {
                context: self.committee.context.clone(),
                kind,
                round,
                digest,
            },
        )
    }
    fn emit_outgoing(&mut self, to: Option<Id>, message: &Message) {
        if let Message::Closed(s) = message {
            if s.signer == self.id {
                // A locally assembled but held CLOSED is not a timer hint.
                // Its actual broadcast is, just as an authenticated remote one.
                self.hint_round_barrier_urgency(s.body.round);
            }
        }
        if let Some(trace) = &self.causal {
            let (kind, round, signer) = causal::ordering_key(&message);
            if matches!(kind, "PROPOSE" | "VOTE" | "CER" | "HISTORY3") || trace.sampled(round) {
                trace.mark(
                    "ordering_outbox",
                    round,
                    json!({"kind":kind,"signer":signer,"to":to,
                        "encoded_message_bytes":self.committee.encoded_size(&wire::MessageRef::from(message)).ok()}),
                );
            }
        }
        self.outbox.push(Effect::Send {
            to,
            message: message.clone(),
        });
    }
    fn enqueue_outgoing(&mut self, to: Option<Id>, message: Message) -> Result<Message, String> {
        self.committee
            .encoded_size(&wire::MessageRef::from(&message))?;
        if self
            .round_barriers
            .as_ref()
            .map_or(true, |b| b.mode == PacingMode::ProgressOnly)
        {
            self.emit_outgoing(to, &message);
            return Ok(message);
        }
        let barrier = match &message {
            Message::Vote { vote, .. } => Some(vote.body.round),
            Message::Cer(s) | Message::Closed(s) => Some(s.body.round + 1),
            Message::History3(report) => Some(report.header.body.horizon + 1),
            // PROG origin is handled by the barrier release. Amplification,
            // initial PROG, and complete proposals always leave immediately.
            Message::Prog(_) | Message::Propose(_) => None,
        };
        if let (Some(barriers), Some(r)) = (&mut self.round_barriers, barrier) {
            if !barriers.released.contains(&r) {
                let pending = barriers
                    .pending
                    .get_mut(&r)
                    .expect("phase guard enters round before its output barrier");
                pending.outgoing.push((to, message.clone()));
                barriers.dirty.insert(r);
                barriers.held_messages += 1;
                barriers.peak_held_messages =
                    barriers.peak_held_messages.max(barriers.held_messages);
                if let Some(trace) = &self.causal {
                    let (kind, round, signer) = causal::ordering_key(&message);
                    trace.mark(
                        "ordering_held",
                        round,
                        json!({"kind":kind,"signer":signer,"to":to,"barrier":r}),
                    );
                }
                return Ok(message);
            }
        }
        self.emit_outgoing(to, &message);
        Ok(message)
    }
    fn send(&mut self, to: Option<Id>, message: Message) -> Result<(), String> {
        let message = self.enqueue_outgoing(to, message)?;
        let held_closed = matches!(&message, Message::Closed(s) if self.round_barriers.as_ref()
            .is_some_and(|b| b.mode == PacingMode::RoundBarrier && b.pending.contains_key(&(s.body.round + 1))));
        // Do not let an unbroadcast own CLOSED plus Byzantine signatures arm
        // catch-up before any correct CLOSED has actually left its barrier.
        if !held_closed && (to.is_none() || to == Some(self.id)) {
            self.inbox.push_back(InboxMessage::Message(message));
        }
        Ok(())
    }
    fn send_verified_proposal(&mut self, verified: VerifiedProposal) -> Result<(), String> {
        let message = self.enqueue_outgoing(None, Message::Propose(verified.0))?;
        let Message::Propose(proposal) = message else {
            unreachable!("enqueue_outgoing preserves its message")
        };
        // Preserve the original FIFO position and defer every ingest mutation
        // until this owned, unchanged proposal reaches the head of the inbox.
        self.inbox
            .push_back(InboxMessage::VerifiedProposal(VerifiedProposal(proposal)));
        Ok(())
    }
    fn send_progress(&mut self, r: u64) -> Result<(), String> {
        if self.progress_sent.insert(r) {
            self.version += 1;
            self.send(None, Message::Prog(self.signed(Kind::Prog, r, None)))?;
        }
        Ok(())
    }
    fn has_complete_proposal(&self, r: u64) -> bool {
        self.proposals
            .range((r, [0; 32])..=(r, [u8::MAX; 32]))
            .next()
            .is_some()
    }
    fn barrier_ready(&self, r: u64) -> bool {
        if self.round_barriers.as_ref().unwrap().mode == PacingMode::ProgressOnly {
            return self.has_complete_proposal(r) || self.has_complete_proposal(r + 1);
        }
        self.has_complete_proposal(r)
            && self.slots.get(&r).is_some_and(|s| s.voted().is_some())
            && (r == 1
                || (self.terminal(r - 1) != Terminal::Open
                    && self.own_reports.contains_key(&(r - 1))))
    }
    fn hint_round_barrier_urgency(&mut self, horizon: u64) {
        if let Some(barriers) = &mut self.round_barriers {
            if barriers.mode == PacingMode::RoundBarrier && horizon + 1 > barriers.urgent_through {
                barriers.urgent_through = horizon + 1;
                self.version += 1;
            }
        }
    }
    fn release_round_barriers(&mut self, include_expired: bool) -> Result<(), String> {
        let Some(barriers) = &mut self.round_barriers else {
            return Ok(());
        };
        let dirty = std::mem::take(&mut barriers.dirty);
        let urgent: BTreeSet<_> = barriers
            .pending
            .range(..=barriers.urgent_through)
            .map(|(r, _)| *r)
            .collect();
        let mut due = BTreeSet::new();
        while include_expired
            && barriers
                .deadlines
                .first()
                .is_some_and(|(at, _)| *at <= self.now)
        {
            let (_, round) = barriers.deadlines.pop_first().unwrap();
            due.insert(round);
        }
        let amplify = std::mem::take(&mut barriers.amplify);
        for r in amplify {
            self.send_progress(r)?;
        }
        let ready: BTreeSet<_> = dirty
            .into_iter()
            .filter(|r| self.barrier_ready(*r))
            .collect();
        let release: BTreeSet<_> = due
            .union(&ready)
            .copied()
            .chain(urgent.iter().copied())
            .collect();
        for r in release {
            let barriers = self.round_barriers.as_mut().unwrap();
            let pending = barriers.pending.remove(&r).unwrap();
            debug_assert!(barriers.mode != PacingMode::ProgressOnly || pending.outgoing.is_empty());
            barriers.deadlines.remove(&(pending.deadline, r));
            assert!(barriers.released.insert(r));
            barriers.held_messages -= pending.outgoing.len();
            let reason = if ready.contains(&r) {
                barriers.ready_releases += 1;
                "ready"
            } else if urgent.contains(&r) {
                barriers.urgent_releases += 1;
                "closed_hint"
            } else {
                barriers.deadline_releases += 1;
                "deadline"
            };
            self.version += 1;
            if let Some(trace) = &self.causal {
                trace.mark(
                    if barriers.mode == PacingMode::ProgressOnly {
                        "progress_pacing_release"
                    } else {
                        "round_barrier_release"
                    },
                    if barriers.mode == PacingMode::ProgressOnly {
                        r + 1
                    } else {
                        r
                    },
                    json!({"reason":reason,"messages":pending.outgoing.len()}),
                );
            }
            self.send_progress(r + 1)?;
            // Preserve assembly order, especially HISTORY3 before its CLOSED.
            // The original send already self-delivered: never enqueue twice.
            for (to, message) in pending.outgoing {
                self.emit_outgoing(to, &message);
                if matches!(message, Message::Closed(_)) && (to.is_none() || to == Some(self.id)) {
                    // CLOSED alone deferred self-delivery until its real send.
                    self.inbox.push_back(InboxMessage::Message(message));
                }
            }
        }
        Ok(())
    }
    fn enter(&mut self, k: u64) -> Result<(), String> {
        if k > wire::MAX_ROUND {
            return Err("round representation exhausted".into());
        }
        if k > self.current {
            let release_deadline = self
                .round_barriers
                .as_ref()
                .map(|p| {
                    self.now
                        .checked_add(p.release_delay_ms)
                        .ok_or("pacing clock overflow")
                })
                .transpose()?;
            let old = self.current;
            self.current = k;
            self.version += 1;
            for r in old + 1..=k {
                self.slot(r);
                if let Some(trace) = &self.causal {
                    trace.mark("admission", r, json!({}));
                }
                self.notice("admission", r);
                if r == 1 || release_deadline.is_none() {
                    self.send_progress(r)?;
                } else {
                    let deadline = release_deadline.unwrap();
                    let barriers = self.round_barriers.as_mut().unwrap();
                    assert!(barriers
                        .pending
                        .insert(
                            r - 1,
                            RoundBarrier {
                                deadline,
                                outgoing: Vec::new(),
                            }
                        )
                        .is_none());
                    barriers.deadlines.insert((deadline, r - 1));
                    barriers.dirty.insert(r - 1);
                    barriers.peak_pending = barriers.peak_pending.max(barriers.pending.len());
                    self.outbox.push(Effect::Wake { at: deadline });
                }
            }
            // Only the r+1 VOTE and r+2 CER admission guards can have changed
            // on an existing slot. Include old future-evidence slots as well.
            self.dirty_slots.extend(
                self.slots
                    .range(old.saturating_sub(1).max(1)..k)
                    .map(|(r, _)| *r),
            );
        }
        Ok(())
    }
    fn retain_statement(&mut self, signed: Signed<Statement>) {
        let s = &signed.body;
        let r = s.round;
        let kind = s.kind;
        let digest = s.digest;
        if kind == Kind::Closed && signed.signer != self.id {
            // Called only for authenticated evidence. A remote hint weakens
            // send pacing, never creates a signature, outcome or admission.
            self.hint_round_barrier_urgency(r);
        }
        let changed = match s.kind {
            Kind::Vote => {
                let d = s.digest.unwrap();
                self.slot(r).observe_vote(signed.signer, d);
                self.votes
                    .entry((r, d))
                    .or_default()
                    .insert(signed.signer, signed)
                    .is_none()
            }
            Kind::Cer => {
                let d = s.digest.unwrap();
                self.slot(r).observe_cer(signed.signer, d);
                self.cers
                    .entry((r, d))
                    .or_default()
                    .insert(signed.signer, signed)
                    .is_none()
            }
            Kind::Prog => self
                .progress
                .entry(r)
                .or_default()
                .insert(signed.signer, signed)
                .is_none(),
            Kind::Closed => self
                .closed
                .entry(r)
                .or_default()
                .insert(signed.signer, signed)
                .is_none(),
        };
        if changed {
            self.version += 1;
            match kind {
                Kind::Vote | Kind::Cer => {
                    self.dirty_slots.insert(r);
                    if let Some(trace) = &self.causal {
                        let store = if kind == Kind::Vote {
                            &self.votes
                        } else {
                            &self.cers
                        };
                        let threshold = if kind == Kind::Vote {
                            self.quorum()
                        } else {
                            self.amplification()
                        };
                        let digest = digest.unwrap();
                        if store[&(r, digest)].len() == threshold {
                            trace.mark(
                                if kind == Kind::Vote {
                                    "vote_quorum_retained"
                                } else {
                                    "cer_amplification_retained"
                                },
                                r,
                                json!({"digest":digest,"admitted":self.current}),
                            );
                        }
                    }
                }
                Kind::Closed => {
                    let count = self.closed[&r].len();
                    if count == self.amplification() {
                        if let Some(round) = r.checked_add(3).filter(|r| *r <= wire::MAX_ROUND) {
                            self.notice("pipeline_preparation_ready", round);
                        }
                    }
                    if let Some(trace) = &self.causal {
                        if count == self.amplification() || count == self.quorum() {
                            trace.mark(
                                "closed_threshold",
                                r,
                                json!({"signers":count,
                                "admitted":self.current,"main_round":r+3}),
                            );
                        }
                    }
                    if count >= self.quorum() && !self.main_timers.contains_key(&(r + 3)) {
                        self.main_arm_ready.insert(r + 3);
                    }
                    if count >= self.amplification() && !self.catchup_timers.contains_key(&r) {
                        self.catchup_arm_ready.insert(r);
                    }
                }
                Kind::Prog => {
                    if self.progress[&r].len() >= self.amplification()
                        && !self.progress_sent.contains(&r)
                    {
                        if let Some(barriers) = &mut self.round_barriers {
                            // A higher admission can leave an earlier origin
                            // held. It must still amplify immediately even
                            // though drive_progress scans only current onward.
                            barriers.amplify.insert(r);
                        }
                    }
                }
            }
        }
    }
    fn retain_proof(&mut self, proof: CerProof) {
        let r = proof.cer.body.round;
        let d = proof.cer.body.digest.unwrap();
        self.retain_statement(proof.cer.clone());
        for s in &proof.triggers {
            self.retain_statement(s.clone());
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.proofs.entry((r, d)) {
            e.insert(proof);
            self.version += 1;
        }
    }
    fn retain_history(&mut self, history: &History) {
        if let History::Evidence {
            proof, previous, ..
        } = history
        {
            if let Some(p) = proof {
                self.retain_proof(p.clone());
            }
            for (_, p) in previous {
                if let Some(p) = p {
                    self.retain_proof(p.clone());
                }
            }
        }
    }
    fn retain_header(&mut self, r: u64, d: Digest, header: Signed<Header>, value: Option<Vec<u8>>) {
        if self.committee.verify_header(&header).is_err()
            || header.body.round != r
            || wire::proposal_digest(&header.body) != d
        {
            return;
        }
        if let Some(value) = value {
            if self.committee.hash(&value) == header.body.value_hash
                && !self.values.contains_key(&(r, d))
            {
                self.values.insert((r, d), value);
                self.version += 1;
            }
        }
        if let std::collections::btree_map::Entry::Vacant(e) = self.headers.entry((r, d)) {
            e.insert(header);
            self.version += 1;
        }
    }
    fn checked_statement(&self, s: &Signed<Statement>, kind: Kind) -> Result<(), String> {
        self.committee.verify_statement(s)?;
        if s.body.kind != kind {
            return Err("outer message/statement kind mismatch".into());
        }
        Ok(())
    }
    fn retain_validated_proposal(&mut self, p: Proposal) {
        let r = p.header.body.round;
        let d = wire::proposal_digest(&p.header.body);
        self.retain_header(r, d, p.header.clone(), Some(p.value.clone()));
        self.retain_history(&p.history);
        if !self.proposals.contains_key(&(r, d)) {
            if let Some(trace) = &self.causal {
                trace.mark(
                    "proposal_validated",
                    r,
                    json!({"digest":d,
                    "value_bytes":p.value.len(),"witness_bytes":p.witness.len()}),
                );
            }
            self.slot(r).validate(d);
            self.dirty_slots.insert(r);
            self.proposals.insert((r, d), p);
            if let Some(barriers) = &mut self.round_barriers {
                // Only this exact fully validated proposal can satisfy its
                // barrier. Headers and distant proposals do not release it.
                if barriers.pending.contains_key(&r) {
                    barriers.dirty.insert(r);
                }
                // Proposal k also releases an origin-only PROG(k) gate; the
                // full round barrier still requires its exact proposal r.
                if barriers.mode == PacingMode::ProgressOnly
                    && r > 1
                    && barriers.pending.contains_key(&(r - 1))
                {
                    barriers.dirty.insert(r - 1);
                }
            }
            self.version += 1;
            self.notice("full_validation", r);
            // The prefix or admission may have arrived first. Wake the exact
            // later opportunity when its missing speculative evidence arrives.
            if let Some(round) = r.checked_add(3).filter(|r| *r <= wire::MAX_ROUND) {
                self.notice("pipeline_preparation_ready", round);
            }
        }
    }
    fn ingest(&mut self, message: Message) -> Result<(), String> {
        match message {
            Message::Propose(p) => {
                let verification_start = self
                    .causal
                    .as_ref()
                    .filter(|t| t.sampled(p.header.body.round))
                    .map(CausalTrace::now_us);
                self.committee.verify_proposal(&p, &self.q)?;
                let r = p.header.body.round;
                if let Some(start) = verification_start {
                    self.causal.as_ref().unwrap().span(
                        "proposal_verify",
                        r,
                        start,
                        json!({"path":"ingest"}),
                    );
                }
                self.retain_validated_proposal(p);
            }
            Message::Vote {
                vote,
                header,
                value,
            } => {
                self.checked_statement(&vote, Kind::Vote)?;
                let r = vote.body.round;
                let d = vote.body.digest.unwrap();
                self.retain_statement(vote);
                // A missing or invalid attachment never suppresses a valid vote.
                if let Some(header) = header {
                    self.retain_header(r, d, header, value);
                }
            }
            Message::Cer(s) => {
                self.checked_statement(&s, Kind::Cer)?;
                self.retain_statement(s);
            }
            Message::Prog(s) => {
                self.checked_statement(&s, Kind::Prog)?;
                self.retain_statement(s);
            }
            Message::Closed(s) => {
                self.checked_statement(&s, Kind::Closed)?;
                self.retain_statement(s);
            }
            Message::History3(report) => {
                history::verify_report(&self.committee, &report)?;
                let h = report.header.body.horizon;
                for proof in &report.proofs {
                    self.retain_proof(proof.clone());
                }
                if self.leader(h + 3) == self.id {
                    let sender = report.header.signer;
                    let report_bytes = self
                        .causal
                        .as_ref()
                        .map(|_| self.committee.encoded_size(&report).ok());
                    if let std::collections::btree_map::Entry::Vacant(e) =
                        self.reports.entry(h).or_default().entry(sender)
                    {
                        e.insert(report);
                        self.version += 1;
                        if let Some(trace) = &self.causal {
                            trace.mark(
                                "history_report_received",
                                h + 3,
                                json!({"horizon":h,
                                "sender":sender,"encoded_report_bytes":report_bytes}),
                            );
                        }
                        if self.reports[&h].len() == self.quorum() {
                            if let Some(trace) = &self.causal {
                                trace.mark("history_quorum", h + 3, json!({"horizon":h}));
                            }
                            self.notice("proposal_history_ready", h + 3);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn apply_actions(&mut self, r: u64, actions: Vec<Action>) -> Result<(), String> {
        for action in actions {
            self.version += 1;
            match action {
                Action::Vote(d) => {
                    let signed = self.signed(Kind::Vote, r, Some(d));
                    self.retain_statement(signed.clone());
                    let header = self.headers[&(r, d)].clone();
                    let value = self.values[&(r, d)].clone();
                    self.send(
                        None,
                        Message::Vote {
                            vote: signed,
                            header: Some(header),
                            value: Some(value),
                        },
                    )?;
                }
                Action::Cer(d) => {
                    if let Some(trace) = &self.causal {
                        trace.mark("own_cer_action", r, json!({"digest":d}));
                    }
                    self.open_outcomes.remove(&r);
                    let trigger = self.slots[&r].proof().expect("CER retains proof").clone();
                    let triggers = match trigger {
                        Trigger::Votes(ids) => ids
                            .into_iter()
                            .map(|i| self.votes[&(r, d)][&i].clone())
                            .collect(),
                        Trigger::Cers(ids) => ids
                            .into_iter()
                            .map(|i| self.cers[&(r, d)][&i].clone())
                            .collect(),
                    };
                    let cer = self.signed(Kind::Cer, r, Some(d));
                    let proof = CerProof {
                        cer: cer.clone(),
                        triggers,
                    };
                    history::verify_proof(&self.committee, &proof)?;
                    self.own_proofs.insert(r, proof.clone());
                    self.retain_proof(proof);
                    self.send(None, Message::Cer(cer))?;
                }
                Action::DirectCommit(d) => {
                    // Completed classifications are retained without rescanning.
                    // A newly direct commitment must agree with every old final
                    // classification, including an indirectly committed slot.
                    if let Some(old) = self.statuses.get(&r) {
                        if *old != Status::Undecided {
                            assert_eq!(*old, Status::Commit(d), "decided classification changed");
                        }
                    }
                    assert!(self.direct.insert(r, d).is_none());
                    assert!(self
                        .cers
                        .get(&(r, d))
                        .is_some_and(|s| s.len() >= self.quorum()));
                    if let Some(trace) = &self.causal {
                        trace.mark("direct_commit", r, json!({"digest":d}));
                    }
                    self.outbox.push(Effect::DirectCommit {
                        round: r,
                        digest: d,
                    });
                }
            }
        }
        Ok(())
    }
    fn drive_slots(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_drive_slots();
        }
        // Snapshot ascending rounds, exactly as the old whole-map sweep.
        let rounds = std::mem::take(&mut self.dirty_slots);
        for r in rounds {
            #[cfg(test)]
            {
                self.work.slots += 1;
            }
            let actions = self.slots.get_mut(&r).unwrap().drive(self.current);
            self.apply_actions(r, actions)?;
        }
        Ok(())
    }
    fn drive_progress(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_drive_progress();
        }
        let counts: Vec<_> = self
            .progress
            .range(self.current..)
            .map(|(r, v)| (*r, v.len()))
            .collect();
        // Earlier rounds already sent PROG during EnterRound and cannot
        // advance admission. Snapshot counts before processing future rounds.
        for (r, n) in counts {
            #[cfg(test)]
            {
                self.work.progress += 1;
            }
            if n >= self.amplification() {
                self.send_progress(r)?;
            }
            if n >= self.quorum() {
                if let Some(trace) = &self.causal {
                    trace.mark(
                        "progress_quorum",
                        r,
                        json!({
                            "signers":self.progress[&r].keys().copied().collect::<Vec<_>>(),
                            "admit":r+1
                        }),
                    );
                }
                self.enter(r + 1)?;
            }
        }
        Ok(())
    }
    fn make_reports(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_make_reports();
        }
        // Own reports are an immutable contiguous prefix, and outcomes never
        // reopen. Retry only the first not-yet-reported outcome onward.
        let reported = self.own_reports.keys().next_back().copied().unwrap_or(0);
        let mut prefix = reported;
        while prefix < self.current.saturating_sub(2) && self.terminal(prefix + 1) != Terminal::Open
        {
            prefix += 1;
            #[cfg(test)]
            {
                self.work.report_prefix += 1;
            }
        }
        for h in reported + 1..=prefix {
            if let Some(trace) = &self.causal {
                trace.mark(
                    "history_ready",
                    h,
                    json!({"next_proposal_round":h + 3,"admitted":self.current}),
                );
            }
            let proofs: Vec<_> = self
                .own_proofs
                .range(..=h)
                .rev()
                .take(3)
                .map(|(_, p)| p.clone())
                .collect();
            let positives = proofs
                .iter()
                .map(|p| (p.cer.body.round, p.cer.body.digest.unwrap()))
                .collect();
            let report = Report {
                header: wire::sign(
                    &self.key,
                    self.id,
                    ReportHeader {
                        context: self.committee.context.clone(),
                        horizon: h,
                        positives,
                    },
                ),
                proofs,
            };
            history::verify_report(&self.committee, &report)?;
            // Queue the complete exact report before signing and queuing CLOSED.
            self.send(Some(self.leader(h + 3)), Message::History3(report.clone()))?;
            self.own_reports.insert(h, report);
            self.version += 1;
            let closed = self.signed(Kind::Closed, h, None);
            self.closed_sent.insert(h, closed.clone());
            self.send(None, Message::Closed(closed))?;
            // Wake both resolved recovery and speculative wave opportunities,
            // including when admission or proposal validation arrived first.
            for offset in [3, 4] {
                if let Some(round) = h.checked_add(offset).filter(|r| *r <= wire::MAX_ROUND) {
                    self.notice("pipeline_preparation_ready", round);
                }
            }
        }
        Ok(())
    }
    /// Retained proofs have already passed authentication. Only the greatest
    /// in-horizon local round and its two exact predecessors can enter history.
    /// If a report raises the pivot, any relevant local predecessor is still
    /// within these rounds. Keep every digest there for canonical proof choice.
    fn proposal_proofs(&self, round: u64) -> Vec<CerProof> {
        if round <= 3 {
            return Vec::new();
        }
        let Some((&(pivot, _), _)) = self.proofs.range(..=(round - 3, [u8::MAX; 32])).next_back()
        else {
            return Vec::new();
        };
        self.proofs
            .range((pivot.saturating_sub(2).max(1), [0; 32])..=(pivot, [u8::MAX; 32]))
            .map(|(_, proof)| proof.clone())
            .collect()
    }
    /// Input admission already checked this exact immutable tuple with Q. This
    /// adapter is local-only; no round-only or remote-proposal trust is inferred.
    fn q_for_local_proposal(&self, round: u64, value: &[u8], witness: &[u8]) -> bool {
        self.inputs
            .get(&round)
            .is_some_and(|(fixed_value, fixed_witness)| {
                fixed_value.as_slice() == value && fixed_witness.as_slice() == witness
            })
            || (self.q)(round, value, witness)
    }
    fn verify_local_proposal(&self, proposal: &Proposal) -> Result<(), String> {
        self.committee
            .verify_proposal(proposal, |r, x, pi| self.q_for_local_proposal(r, x, pi))
    }
    fn propose(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_propose();
        }
        let ready: Vec<_> = self
            .pending_proposals
            .range(..=self.current)
            .filter(|r| {
                **r <= 3
                    || self
                        .reports
                        .get(&(**r - 3))
                        .is_some_and(|reports| reports.len() >= self.quorum())
            })
            .map(|r| (*r, self.inputs[r].clone()))
            .collect();
        for (r, (value, witness)) in ready {
            if let Some(trace) = &self.causal {
                trace.mark("proposal_ready", r, json!({"admitted":self.current}));
            }
            #[cfg(test)]
            {
                self.work.proposals += 1;
            }
            // Immutable input was Q-checked at admission. Full proposal
            // verification below remains the boundary for the assembled value.
            let reports = self
                .reports
                .get(&r.saturating_sub(3))
                .map(|v| v.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let proofs = self.proposal_proofs(r);
            let history_start = self
                .causal
                .as_ref()
                .filter(|t| t.sampled(r))
                .map(CausalTrace::now_us);
            let history = history::build_history(&self.committee, r, &reports, &proofs)?;
            if let Some(start) = history_start {
                self.causal.as_ref().unwrap().span(
                    "history_build",
                    r,
                    start,
                    json!({"reports":reports.len(),"local_proofs":proofs.len(),
                        "encoded_history_bytes":self.committee.encoded_size(&history).ok()}),
                );
            }
            let header = Header {
                context: self.committee.context.clone(),
                round: r,
                value_hash: self.committee.hash(&value),
                witness_hash: self.committee.hash(&witness),
                history_hash: self.committee.hash(&history),
                entries: history::project(r, &history),
            };
            let proposal = Proposal {
                header: wire::sign(&self.key, self.id, header),
                value,
                witness,
                history,
            };
            let verification_start = self
                .causal
                .as_ref()
                .filter(|t| t.sampled(r))
                .map(CausalTrace::now_us);
            self.verify_local_proposal(&proposal)?;
            if let Some(trace) = &self.causal {
                if let Some(start) = verification_start {
                    trace.span("proposal_verify", r, start, json!({"path":"assembled"}));
                }
                trace.mark("proposal_assembled", r, json!({}));
            }
            self.send_verified_proposal(VerifiedProposal(proposal))?;
            self.proposal_sent.insert(r);
            self.pending_proposals.remove(&r);
            self.version += 1;
        }
        Ok(())
    }
    fn arm_timers(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_arm_timers();
        }
        let rounds: Vec<_> = self
            .main_arm_ready
            .range(..=self.current.saturating_sub(2))
            .copied()
            .collect();
        for r in rounds {
            #[cfg(test)]
            {
                self.work.main_arms += 1;
            }
            if !self.main_timers.contains_key(&r) {
                let deadline = self
                    .now
                    .checked_add(7 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.main_timers.insert(
                    r,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.main_deadlines.insert((deadline, r));
                self.main_arm_ready.remove(&r);
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("main_timer_arm", r);
                if let Some(trace) = &self.causal {
                    trace.mark(
                        "main_timer_arm",
                        r,
                        json!({"protocol_now_ms":self.now,
                        "deadline_ms":deadline,"duration_ms":7*self.bound}),
                    );
                }
                self.version += 1;
            }
        }
        // Catch-up arms independently of admission; each exact endpoint has
        // its own original deadline and retained once guard.
        let horizons: Vec<_> = self.catchup_arm_ready.iter().copied().collect();
        for h in horizons {
            #[cfg(test)]
            {
                self.work.catchup_arms += 1;
            }
            if !self.catchup_timers.contains_key(&h) {
                let deadline = self
                    .now
                    .checked_add(3 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.catchup_timers.insert(
                    h,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.catchup_deadlines.insert((deadline, h));
                self.catchup_arm_ready.remove(&h);
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("catchup_timer_arm", h);
                if let Some(trace) = &self.causal {
                    trace.mark(
                        "catchup_timer_arm",
                        h,
                        json!({"protocol_now_ms":self.now,
                        "deadline_ms":deadline,"duration_ms":3*self.bound}),
                    );
                }
                self.version += 1;
            }
        }
        Ok(())
    }
    fn finish(&mut self, r: u64) -> Result<(), String> {
        #[cfg(test)]
        {
            self.work.finishes += 1;
        }
        let before = self.terminal(r);
        let admitted = self.current;
        let actions = self.slot(r).finish(admitted);
        self.apply_actions(r, actions)?;
        if self.terminal(r) != Terminal::Open {
            self.open_outcomes.remove(&r);
        }
        if before != self.terminal(r) {
            self.version += 1;
            if self.terminal(r) == Terminal::NoCer {
                self.notice("no_cer", r);
            }
        }
        Ok(())
    }
    fn expire_timers(&mut self) -> Result<(), String> {
        #[cfg(test)]
        if self.legacy_sweeps {
            return self.legacy_expire_timers();
        }
        // Deadlines discover due timers, but effect order remains round order
        // (not deadline order), with all main expiries before catch-up expiries.
        let mut rounds = BTreeSet::new();
        while self
            .main_deadlines
            .first()
            .is_some_and(|(at, _)| *at <= self.now)
        {
            let (_, r) = self.main_deadlines.pop_first().unwrap();
            rounds.insert(r);
        }
        for r in rounds {
            #[cfg(test)]
            {
                self.work.expiries += 1;
            }
            self.main_timers.get_mut(&r).unwrap().acted = true;
            self.version += 1;
            self.notice("main_timer_expiry", r);
            if self.open_outcomes.contains(&r) {
                self.finish(r)?;
            }
        }
        while self
            .catchup_deadlines
            .first()
            .is_some_and(|(at, _)| *at <= self.now)
        {
            let (_, h) = self.catchup_deadlines.pop_first().unwrap();
            self.catchup_expired.insert(h);
        }
        let horizons: Vec<_> = self
            .catchup_expired
            .range(..=self.current.saturating_sub(2))
            .copied()
            .collect();
        for h in horizons {
            #[cfg(test)]
            {
                self.work.expiries += 1;
            }
            self.catchup_expired.remove(&h);
            self.catchup_timers.get_mut(&h).unwrap().acted = true;
            self.version += 1;
            self.notice("catchup_timer_expiry", h);
            // Positive transitions reached their fixed point before this phase.
            // FinishRound on a terminal outcome is therefore a no-op; earlier
            // negative finishes cannot enable votes, CERs, or direct commits.
            let rounds: Vec<_> = self.open_outcomes.range(..=h).copied().collect();
            for r in rounds {
                self.finish(r)?;
            }
        }
        Ok(())
    }
    fn settle(&mut self) -> Result<Vec<Effect>, String> {
        loop {
            let before = self.version;
            while let Some(message) = self.inbox.pop_front() {
                match message {
                    InboxMessage::Message(message) => self.ingest(message)?,
                    InboxMessage::VerifiedProposal(proposal) => {
                        // Committee and immutable Q have not changed; the exact
                        // owned proposal already passed all checks before send.
                        self.retain_validated_proposal(proposal.0);
                    }
                }
            }
            self.release_round_barriers(false)?;
            self.drive_progress()?;
            self.drive_slots()?;
            self.make_reports()?;
            self.propose()?;
            self.arm_timers()?;
            if !self.inbox.is_empty() || self.version != before {
                continue;
            }
            // Even a due pacing release observes the positive fixed
            // point first. Releasing PROG can enable more positive transitions
            // before either original outcome timer is allowed to act.
            self.release_round_barriers(true)?;
            if !self.inbox.is_empty() || self.version != before {
                continue;
            }
            // No enabled positive transition remains with the evidence received
            // at this local step. Each expired timer now takes CER before NO-CER.
            self.expire_timers()?;
            if !self.inbox.is_empty() || self.version != before {
                continue;
            }
            break;
        }
        // All three maps are insert-only, with immutable entries. Equal lengths
        // and admission therefore identify exactly the same scanner/release
        // inputs. Late headers or values invalidate this key even if no new
        // statement, terminal outcome, or direct commitment arrived.
        let inputs = (
            self.current,
            self.direct.len(),
            self.headers.len(),
            self.values.len(),
        );
        let reuse = self.scanned_inputs == Some(inputs);
        #[cfg(test)]
        let reuse = reuse && !self.legacy_sweeps;
        if !reuse {
            let scan_start = self
                .causal
                .as_ref()
                .filter(|t| t.sampled(self.current))
                .map(CausalTrace::now_us);
            self.scan_and_release();
            if let Some(start) = scan_start {
                self.causal.as_ref().unwrap().span(
                    "scanner",
                    self.current,
                    start,
                    json!({"cursor":self.cursor}),
                );
            }
            self.scanned_inputs = Some(inputs);
        }
        Ok(std::mem::take(&mut self.outbox))
    }
    fn scan_and_release(&mut self) {
        #[cfg(test)]
        {
            self.work.scans += 1;
        }
        #[cfg(test)]
        let legacy_direct;
        #[cfg(test)]
        let direct = if self.legacy_sweeps {
            legacy_direct = self
                .slots
                .iter()
                .filter_map(|(r, s)| s.committed().map(|d| (*r, d)))
                .collect();
            &legacy_direct
        } else {
            &self.direct
        };
        #[cfg(not(test))]
        let direct = &self.direct;
        let first = self.cursor + 1; // cursor <= current <= MAX_ROUND leaves room.
        #[cfg(test)]
        let first = if self.legacy_sweeps { 1 } else { first };
        let statuses = if first == 1 {
            scanner::scan(self.current, direct, &self.headers)
        } else {
            scanner::scan_from(first, self.current, direct, &self.headers)
        };
        #[cfg(test)]
        {
            self.work.scanned_rounds += statuses.len();
        }
        for (r, old) in self.statuses.range(first..) {
            if *old != Status::Undecided {
                assert_eq!(statuses.get(r), Some(old), "decided classification changed");
            }
        }
        // Only passed Commit/Skip statuses are frozen. With increasing horizons
        // and immutable headers/direct evidence, a changed old final status
        // would require a changed later final authority or a conflicting new
        // direct commitment. Following the former strictly upward must end at
        // the latter, which apply_actions rejects. The live suffix still gets
        // the original monotonicity assertion, including commits lacking data.
        if let Some(trace) = &self.causal {
            for (r, status) in &statuses {
                if *status != Status::Undecided
                    && self
                        .statuses
                        .get(r)
                        .map_or(true, |old| *old == Status::Undecided)
                {
                    trace.mark(
                        "classified",
                        *r,
                        json!({"status":status,
                        "direct":self.direct.contains_key(r)}),
                    );
                }
            }
        }
        self.statuses.extend(statuses);
        let previous_cursor = self.cursor;
        let delivered = scanner::release_with_committee(
            &self.committee,
            &self.statuses,
            &self.headers,
            &self.values,
            &mut self.cursor,
        );
        for d in delivered {
            if let Some(trace) = &self.causal {
                trace.mark("prefix_release", d.round, json!({"digest":d.digest}));
            }
            self.deliveries.push(d.clone());
            self.outbox.push(Effect::Deliver(d));
        }
        if self.cursor != previous_cursor {
            if let Some(trace) = &self.causal {
                trace.mark(
                    "prefix_advance",
                    self.cursor,
                    json!({"previous_cursor":previous_cursor,
                    "admitted":self.current,"next_status":self.statuses.get(&(self.cursor+1))}),
                );
            }
        }
    }
    #[cfg(test)]
    fn legacy_drive_slots(&mut self) -> Result<(), String> {
        let rounds: Vec<_> = self.slots.keys().copied().collect();
        for r in rounds {
            let actions = self.slots.get_mut(&r).unwrap().drive(self.current);
            self.apply_actions(r, actions)?;
        }
        Ok(())
    }
    #[cfg(test)]
    fn legacy_drive_progress(&mut self) -> Result<(), String> {
        let counts: Vec<_> = self.progress.iter().map(|(r, v)| (*r, v.len())).collect();
        for (r, n) in counts {
            if n >= self.amplification() {
                self.send_progress(r)?;
            }
            if n >= self.quorum() {
                self.enter(r + 1)?;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn legacy_make_reports(&mut self) -> Result<(), String> {
        let mut prefix = 0;
        while prefix < self.current.saturating_sub(2) && self.terminal(prefix + 1) != Terminal::Open
        {
            prefix += 1;
        }
        for h in 1..=prefix {
            if self.own_reports.contains_key(&h) {
                continue;
            }
            let proofs: Vec<_> = self
                .own_proofs
                .range(..=h)
                .rev()
                .take(3)
                .map(|(_, p)| p.clone())
                .collect();
            let positives = proofs
                .iter()
                .map(|p| (p.cer.body.round, p.cer.body.digest.unwrap()))
                .collect();
            let report = Report {
                header: wire::sign(
                    &self.key,
                    self.id,
                    ReportHeader {
                        context: self.committee.context.clone(),
                        horizon: h,
                        positives,
                    },
                ),
                proofs,
            };
            history::verify_report(&self.committee, &report)?;
            // Queue the complete exact report before signing and queuing CLOSED.
            self.send(Some(self.leader(h + 3)), Message::History3(report.clone()))?;
            self.own_reports.insert(h, report);
            self.version += 1;
            let closed = self.signed(Kind::Closed, h, None);
            self.closed_sent.insert(h, closed.clone());
            self.send(None, Message::Closed(closed))?;
            for offset in [3, 4] {
                if let Some(round) = h.checked_add(offset).filter(|r| *r <= wire::MAX_ROUND) {
                    self.notice("pipeline_preparation_ready", round);
                }
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn legacy_propose(&mut self) -> Result<(), String> {
        let ready: Vec<_> = self
            .inputs
            .range(..=self.current)
            .filter(|(r, _)| self.leader(**r) == self.id && !self.proposal_sent.contains(r))
            .filter(|(r, _)| {
                **r <= 3
                    || self
                        .reports
                        .get(&(**r - 3))
                        .is_some_and(|reports| reports.len() >= self.quorum())
            })
            .map(|(r, x)| (*r, x.clone()))
            .collect();
        for (r, (value, witness)) in ready {
            // Immutable input was Q-checked at admission. Full proposal
            // verification below remains the boundary for the assembled value.
            let reports = self
                .reports
                .get(&r.saturating_sub(3))
                .map(|v| v.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            let proofs = self.proposal_proofs(r);
            let history = history::build_history(&self.committee, r, &reports, &proofs)?;
            let header = Header {
                context: self.committee.context.clone(),
                round: r,
                value_hash: self.committee.hash(&value),
                witness_hash: self.committee.hash(&witness),
                history_hash: self.committee.hash(&history),
                entries: history::project(r, &history),
            };
            let proposal = Proposal {
                header: wire::sign(&self.key, self.id, header),
                value,
                witness,
                history,
            };
            self.committee.verify_proposal(&proposal, &self.q)?;
            self.send(None, Message::Propose(proposal))?;
            self.proposal_sent.insert(r);
            self.version += 1;
        }
        Ok(())
    }
    #[cfg(test)]
    fn legacy_arm_timers(&mut self) -> Result<(), String> {
        for r in 1..=self.current.saturating_sub(2) {
            let ready = r <= 3
                || self
                    .closed
                    .get(&(r - 3))
                    .is_some_and(|s| s.len() >= self.quorum());
            if ready && !self.main_timers.contains_key(&r) {
                let deadline = self
                    .now
                    .checked_add(7 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.main_timers.insert(
                    r,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("main_timer_arm", r);
                self.version += 1;
            }
        }
        let horizons: Vec<_> = self
            .closed
            .iter()
            .filter(|(_, s)| s.len() >= self.amplification())
            .map(|(h, _)| *h)
            .collect();
        for h in horizons {
            if !self.catchup_timers.contains_key(&h) {
                let deadline = self
                    .now
                    .checked_add(3 * self.bound)
                    .ok_or("timer clock overflow")?;
                self.catchup_timers.insert(
                    h,
                    Timer {
                        deadline,
                        acted: false,
                    },
                );
                self.outbox.push(Effect::Wake { at: deadline });
                self.notice("catchup_timer_arm", h);
                self.version += 1;
            }
        }
        Ok(())
    }
    #[cfg(test)]
    fn legacy_expire_timers(&mut self) -> Result<(), String> {
        let rounds: Vec<_> = self
            .main_timers
            .iter()
            .filter(|(_, t)| !t.acted && t.deadline <= self.now)
            .map(|(r, _)| *r)
            .collect();
        for r in rounds {
            self.main_timers.get_mut(&r).unwrap().acted = true;
            self.version += 1;
            self.notice("main_timer_expiry", r);
            self.finish(r)?;
        }
        let horizons: Vec<_> = self
            .catchup_timers
            .iter()
            .filter(|(h, t)| !t.acted && t.deadline <= self.now && self.current >= **h + 2)
            .map(|(h, _)| *h)
            .collect();
        for h in horizons {
            self.catchup_timers.get_mut(&h).unwrap().acted = true;
            self.version += 1;
            self.notice("catchup_timer_expiry", h);
            for r in 1..=h {
                self.finish(r)?;
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Value {
        let mut snapshot = json!({"id":self.id,"current_round":self.current,"last_delivered":self.cursor,
            "deliveries":self.deliveries,"statuses":self.statuses,
            "own_reports":self.own_reports.values().collect::<Vec<_>>(),
            "own_proofs":self.own_proofs.values().collect::<Vec<_>>(),
            "closed_sent":self.closed_sent.values().collect::<Vec<_>>(),
            "main_timers":self.main_timers.iter().map(|(r,t)|json!({"round":r,"deadline":t.deadline,"acted":t.acted})).collect::<Vec<_>>(),
            "catchup_timers":self.catchup_timers.iter().map(|(h,t)|json!({"horizon":h,"deadline":t.deadline,"acted":t.acted})).collect::<Vec<_>>(),
            "headers":self.headers.values().collect::<Vec<_>>()});
        snapshot["ordering_schedule"] = json!(match self.ordering_schedule() {
            OrderingSchedule::Canonical => "canonical",
            OrderingSchedule::ProgressPacing { .. } => "progress_pacing",
            OrderingSchedule::RoundBarrier { .. } => "round_barrier",
        });
        if let Some(barriers) = &self.round_barriers {
            let key = if barriers.mode == PacingMode::ProgressOnly {
                "progress_pacing"
            } else {
                "experimental_round_barrier"
            };
            snapshot[key] = json!({
                "release_delay_ms":barriers.release_delay_ms,
                "released_count":barriers.released.len(),
                "ready_releases":barriers.ready_releases,
                "deadline_releases":barriers.deadline_releases,
                "urgent_releases":barriers.urgent_releases,
                "urgent_through":barriers.urgent_through,
                "held_messages":barriers.held_messages,
                "peak_held_messages":barriers.peak_held_messages,
                "peak_pending":barriers.peak_pending,
                "pending":barriers.pending.iter().map(|(r,b)|json!({
                    "round":r,"deadline":b.deadline,"held_messages":b.outgoing.len()
                })).collect::<Vec<_>>()
            });
        }
        snapshot
    }
}
