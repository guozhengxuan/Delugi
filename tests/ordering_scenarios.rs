//! Multi-replica ordering scenarios using signed wire packets and virtual time.
use delugi::history::{self, Entry, History};
use delugi::scanner::Status;
use delugi::simulation::{self, Config, DelayRule, Run};
use delugi::slot::Terminal;
use delugi::wire::{self, Committee, Kind, Message};
use std::collections::BTreeSet;

fn rounds(node: &delugi::replica::Replica) -> Vec<u64> {
    node.deliveries()
        .iter()
        .map(|delivery| delivery.round)
        .collect()
}

fn successful(run: &Run, expected: &[u64]) {
    let mut first = None;
    for (id, node) in run.nodes.iter().enumerate() {
        if run.config.silent == Some(id as u32) {
            continue;
        }
        assert_eq!(
            node.ordering_schedule(),
            delugi::replica::OrderingSchedule::ProgressPacing {
                release_delay_ms: run.config.bound
            }
        );
        assert_eq!(rounds(node), expected, "replica {id}");
        if let Some(deliveries) = first {
            assert_eq!(node.deliveries(), deliveries);
        } else {
            first = Some(node.deliveries());
        }
        for delivery in node.deliveries() {
            assert_eq!(delivery.value, simulation::input(delivery.round).0);
            assert_eq!(node.committed(delivery.round), Some(delivery.digest));
        }
    }
    assert_eq!(run.summary()["pass"], true);
}

#[test]
fn all_honest_pipeline_through_round_four_has_three_delay_commitments() {
    for delta in [10, 20, 99] {
        let run = simulation::run(Config {
            delta,
            until: 7 * delta,
            ..Config::default()
        })
        .unwrap();
        successful(&run, &[1, 2, 3, 4]);
        for round in 1..=4 {
            assert_eq!(run.proposal_times[&round], (round - 1) * delta);
            for id in 0..4 {
                assert_eq!(run.direct_commits[&(id, round)], (round + 2) * delta);
            }
        }
        // The observation endpoint is not an artificial round-admission cap.
        assert!(run.nodes.iter().all(|node| node.current_round() > 4));
    }
}

#[test]
fn round_four_binds_real_exact_endpoint_reports_and_cer_proof() {
    let run = simulation::run(Config {
        until: 70,
        ..Config::default()
    })
    .unwrap();
    let p4 = run
        .messages
        .iter()
        .find_map(|sent| match &sent.message {
            Message::Propose(proposal) if proposal.header.body.round == 4 => Some(proposal),
            _ => None,
        })
        .unwrap();
    let History::Evidence {
        reports,
        pivot,
        proof,
        previous,
    } = &p4.history
    else {
        panic!("round four requires actual HISTORY3 evidence")
    };
    assert_eq!(reports.len(), 3);
    assert_eq!(*pivot, 1);
    assert!(previous.is_empty());
    let digest = run.nodes[0].committed(1).unwrap();
    assert_eq!(proof.as_ref().unwrap().cer.body.digest, Some(digest));
    for report in reports {
        assert_eq!(report.body.horizon, 1);
        assert_eq!(report.body.positives, vec![(1, digest)]);
        assert_eq!(
            report,
            &run.nodes[report.signer as usize].own_reports()[&1].header
        );
    }
    assert_eq!(p4.header.body.history_hash, wire::hash(&p4.history));
    assert_eq!(p4.header.body.entries.entry(1), Some(Entry::Cer(digest)));
    let keys: Vec<_> = (0..4).map(wire::fixture_key).collect();
    let committee = Committee::new([2; 32], keys.iter().map(|key| key.public).collect()).unwrap();
    committee
        .verify_proposal(p4, |round, x, pi| {
            let expected = simulation::input(round);
            x == expected.0 && pi == expected.1
        })
        .unwrap();
}

#[test]
fn silent_first_leader_requires_history_wait_then_three_honest_anchors() {
    let config = Config {
        silent: Some(0),
        ..Config::default()
    };
    let before = simulation::run(Config {
        until: 700,
        ..config.clone()
    })
    .unwrap();
    assert!(!before.proposal_times.contains_key(&4));
    for node in &before.nodes[1..] {
        assert!(node.committed(2).is_some());
        assert!(node.committed(3).is_some());
        assert!(node.deliveries().is_empty());
        assert_eq!(node.statuses().get(&1), Some(&Status::Undecided));
    }
    let run = simulation::run(config).unwrap();
    successful(&run, &[2, 3, 4]);
    // Missing proposal1 lets round2's valid proposal release PROG2. This
    // adds one delta before entry3, and therefore before the unchanged 7Δ timer.
    assert_eq!(run.proposal_times[&4], 740);
    for id in 1..4 {
        let node = &run.nodes[id as usize];
        assert_eq!(node.terminal(1), Terminal::NoCer);
        assert_eq!(node.statuses().get(&1), Some(&Status::Skip));
        assert_eq!(node.main_deadline(1), Some(730));
        assert!(node.catchup_deadline(1).is_some());
        assert!(node.own_reports()[&1].header.body.positives.is_empty());
        assert_eq!(run.direct_commits[&(id, 4)], 770);
        assert!(run
            .trace
            .iter()
            .filter(
                |event| event["event"] == "ordered_descriptor_delivery" && event["replica"] == id
            )
            .all(|event| event["at"] == 770));
    }
    // A failed opportunity is counted, and traffic to the silent node is charged.
    assert!(!run.proposal_times.contains_key(&1));
    assert!(run.sends.iter().any(|packet| packet.to == 0));
    assert!(run
        .sends
        .iter()
        .any(|packet| packet.kind == "PROG" && packet.round > 4));
}

#[test]
fn recurring_silent_leader_is_resolved_by_a_second_honest_triple() {
    let run = simulation::run(Config {
        silent: Some(0),
        rounds: 8,
        until: 1500,
        ..Config::default()
    })
    .unwrap();
    successful(&run, &[2, 3, 4, 6, 7, 8]);
    for id in 1..4 {
        assert_eq!(
            run.nodes[id as usize].statuses().get(&5),
            Some(&Status::Skip)
        );
        assert_eq!(run.nodes[id as usize].terminal(5), Terminal::NoCer);
        assert_eq!(run.direct_commits[&(id, 8)], 1480);
    }
    assert_eq!(run.proposal_times[&8], 1450);
}

#[test]
fn seven_replicas_use_distinct_five_signature_quorums() {
    let run = simulation::run(Config {
        nodes: 7,
        until: 70,
        ..Config::default()
    })
    .unwrap();
    successful(&run, &[1, 2, 3, 4]);
    for node in &run.nodes {
        let proof = &node.own_reports()[&1].proofs[0];
        assert_eq!(proof.triggers.len(), 5);
        let signers: BTreeSet<_> = proof.triggers.iter().map(|s| s.signer).collect();
        assert_eq!(signers.len(), 5);
        assert!(proof.triggers.iter().all(|s| s.body.kind == Kind::Vote));
    }
}

#[test]
fn duplicate_delivery_does_not_repeat_actions_reports_or_outputs() {
    let run = simulation::run(Config {
        duplicate_packets: true,
        until: 70,
        ..Config::default()
    })
    .unwrap();
    successful(&run, &[1, 2, 3, 4]);
    let mut actions = BTreeSet::new();
    for sent in &run.messages {
        let (kind, round) = simulation::message_kind(&sent.message);
        assert!(
            actions.insert((sent.from, kind, round)),
            "duplicate {kind} at {round}"
        );
    }
    for packet in &run.sends {
        assert_ne!(packet.from, packet.to, "no queued self delivery");
    }
    let summary = run.summary();
    assert!(summary["injected_duplicate_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        summary["network_sends"].as_u64().unwrap(),
        2 * summary["protocol_nonself_sends"].as_u64().unwrap()
    );
}

#[test]
fn metadata_waits_do_not_prevent_direct_commit_or_cer_amplification() {
    let config = Config {
        rounds: 1,
        until: 200,
        // Replica 3 also collects exact reports through round 1. Their CER
        // proofs carry real VOTE signatures, so delay that evidence route too
        // to isolate certification from the f+1 short CER messages alone.
        delays: ["PROPOSE", "VOTE", "HISTORY3"]
            .into_iter()
            .map(|kind| DelayRule {
                from: None,
                to: Some(3),
                kind: Some(kind.into()),
                round: Some(1),
                extra: 200,
            })
            .collect(),
        ..Config::default()
    };
    let before = simulation::run(config.clone()).unwrap();
    let node = &before.nodes[3];
    let digest = node.committed(1).expect("CERs commit without metadata");
    assert_eq!(before.direct_commits[&(3, 1)], 30);
    assert_eq!(node.terminal(1), Terminal::Cer(digest));
    assert!(node.deliveries().is_empty());
    assert_eq!(node.last_delivered(), 0);
    assert!(node.own_reports()[&1].proofs[0]
        .triggers
        .iter()
        .all(|s| s.body.kind == Kind::Cer));
    assert!(!before.messages.iter().any(|sent| sent.from == 3
        && matches!(&sent.message,
        Message::Vote { vote, .. } if vote.body.round == 1)));
    let after = simulation::run(Config {
        until: 230,
        ..config
    })
    .unwrap();
    successful(&after, &[1]);
    assert!(after.messages.iter().any(|sent| sent.from == 3
        && matches!(&sent.message,
        Message::Vote { vote, .. } if vote.body.round == 1)));
    let deliveries: Vec<_> = after
        .trace
        .iter()
        .filter(|event| event["event"] == "ordered_descriptor_delivery" && event["replica"] == 3)
        .collect();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0]["at"], 210);
}

#[test]
fn deterministic_replay_preserves_signed_evidence_and_event_order() {
    let config = Config {
        until: 70,
        ..Config::default()
    };
    let first = simulation::run(config.clone()).unwrap();
    let second = simulation::run(config).unwrap();
    assert_eq!(first.summary(), second.summary());
}

#[test]
fn observation_horizon_leaves_queued_evidence_and_control_traffic_counted() {
    let run = simulation::run(Config {
        until: 20,
        ..Config::default()
    })
    .unwrap();
    let summary = run.summary();
    assert_eq!(summary["pass"], false);
    assert!(summary["unfinished_queued_events"].as_u64().unwrap() > 0);
    assert!(run.sends.iter().any(|packet| packet.arrives_at > 20));
    assert_eq!(
        summary["network_serialized_bytes"].as_u64().unwrap(),
        run.sends
            .iter()
            .map(|packet| packet.bytes as u64)
            .sum::<u64>()
    );
    assert_eq!(
        summary["network_serialized_bytes"].as_u64().unwrap(),
        summary["x_copy_bytes"].as_u64().unwrap()
            + summary["pi_copy_bytes"].as_u64().unwrap()
            + summary["internal_and_framing_bytes"].as_u64().unwrap()
    );
}

#[test]
fn history_messages_are_unicast_to_the_exact_next_leader() {
    let run = simulation::run(Config {
        until: 70,
        ..Config::default()
    })
    .unwrap();
    let committee = Committee::new(
        [2; 32],
        (0..4).map(|id| wire::fixture_key(id).public).collect(),
    )
    .unwrap();
    let mut count = 0;
    for sent in &run.messages {
        if let Message::History3(report) = &sent.message {
            count += 1;
            let h = report.header.body.horizon;
            assert_eq!(sent.to, Some(((h + 2) % 4) as u32));
            assert_eq!(report.header.signer, sent.from);
            history::verify_report(&committee, report).unwrap();
        }
    }
    assert!(count >= 16);
}
