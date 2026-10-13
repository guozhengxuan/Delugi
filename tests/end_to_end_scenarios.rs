use delugi::availability::{self, AvailabilityConfig, AvailabilityProof, Descriptor};
use delugi::batch::BatchStore;
use delugi::end_to_end::{self, Config, PayloadDelay, Run};
use delugi::mmr;
use delugi::scanner::Status;
use delugi::wire::{self, Committee, Message};
use std::collections::BTreeSet;

fn assert_complete(run: &Run) {
    assert_eq!(run.summary()["pass"], true, "{}", run.summary());
    let correct: Vec<_> = run
        .nodes
        .iter()
        .filter(|node| run.config.silent != Some(node.id))
        .collect();
    let expected_rounds: Vec<_> = (1..=run.config.rounds)
        .filter(|r| run.config.silent != Some(((r - 1) % u64::from(run.config.nodes)) as u32))
        .collect();
    let expected: BTreeSet<_> = (0..run.config.nodes)
        .filter(|id| run.config.silent != Some(*id))
        .flat_map(|id| {
            (1..=run.config.rounds).flat_map(move |height| {
                end_to_end::transactions(
                    id,
                    height,
                    run.config.transactions_per_batch,
                    run.config.transaction_bytes,
                )
                .into_iter()
                .map(|transaction| transaction.id)
            })
        })
        .collect();
    assert!(
        !expected.is_empty(),
        "empty frontiers are not useful output"
    );
    for node in &correct {
        assert_eq!(node.executed, correct[0].executed);
        assert_eq!(node.state_hash(), correct[0].state_hash());
        assert_eq!(node.executed_rounds, expected_rounds);
        assert_eq!(node.ordering.deliveries(), correct[0].ordering.deliveries());
        assert_eq!(node.pending_materialization(), 0);
        let actual: BTreeSet<_> = node.executed.iter().map(|e| e.transaction).collect();
        assert_eq!(actual, expected);
        assert_eq!(node.executed.len(), actual.len(), "duplicate execution");
        assert!(node.executed.windows(2).all(|pair| {
            (pair[0].round, pair[0].producer, pair[0].height)
                <= (pair[1].round, pair[1].producer, pair[1].height)
        }));
        for executed in &node.executed {
            let record = node
                .store
                .get_record(executed.producer, executed.batch_digest)
                .expect("materialized batch must be retained");
            assert_eq!(record.header.body.height, executed.height);
            let transactions: Vec<delugi::composed::Transaction> =
                wire::decode(&record.payload).unwrap();
            assert!(transactions.iter().any(|tx| tx.id == executed.transaction));
        }
        assert_eq!(node.observations.len(), run.config.rounds as usize);
        for round in 1..=run.config.rounds {
            if run.config.silent == Some(((round - 1) % u64::from(run.config.nodes)) as u32) {
                assert_eq!(node.ordering.statuses()[&round], Status::Skip);
            }
        }
    }
}

#[test]
fn honest_round_four_orders_and_materializes_real_batches() {
    let run = end_to_end::run(Config::default()).unwrap();
    assert_complete(&run);
    assert_eq!(run.proposals.len(), 4);
    assert_eq!(run.nodes[0].executed.len(), 32);
    for round in 1..=4 {
        let leader = ((round - 1) % 4) as usize;
        assert!(run.nodes[leader].input_ready[&round] <= run.proposals[&round]);
        for node in &run.nodes {
            assert!(run.commits[&(node.id, round)] >= run.proposals[&round]);
            assert!(node.executed_at[&round] >= node.ordered_at[&round]);
        }
    }
    assert!(run.sends.iter().any(|send| send.kind == "HISTORY3"));
    assert!(run.sends.iter().any(|send| send.kind == "CLOSED"));
    assert!(run.sends.iter().any(|send| send.kind == "OBS"));
    assert!(run.nodes.iter().all(|node| node.store.custody_count() > 0));
}

#[test]
fn silent_first_leader_preserves_three_honest_anchors_and_their_batches() {
    let run = end_to_end::run(Config {
        silent: Some(0),
        ..Config::default()
    })
    .unwrap();
    assert_complete(&run);
    assert_eq!(run.proposals.keys().copied().collect::<Vec<_>>(), [2, 3, 4]);
    for node in run.nodes.iter().filter(|node| node.id != 0) {
        assert_eq!(node.executed_rounds, [2, 3, 4]);
        assert_eq!(node.executed.len(), 24);
        assert!(run.commits[&(node.id, 2)] < run.proposals[&4]);
        assert!(node.executed_at[&2] >= run.commits[&(node.id, 4)]);
        // Height-one batches survive the lost proposal through round two's
        // cumulative frontier, rather than being silently discarded.
        assert_eq!(
            node.executed
                .iter()
                .filter(|entry| entry.height == 1 && entry.round == 2)
                .count(),
            6
        );
    }
    assert!(run.sends.iter().any(|send| send.to == 0));
}

#[test]
fn recurring_silent_leader_through_eight_keeps_distinct_cumulative_output() {
    let run = end_to_end::run(Config {
        silent: Some(0),
        rounds: 8,
        until: 1700,
        ..Config::default()
    })
    .unwrap();
    assert_complete(&run);
    for node in run.nodes.iter().filter(|node| node.id != 0) {
        assert_eq!(node.executed_rounds, [2, 3, 4, 6, 7, 8]);
        assert_eq!(node.executed.len(), 48);
        assert_eq!(node.ordering.statuses()[&5], Status::Skip);
        assert!(node.executed_at[&6] >= run.commits[&(node.id, 8)]);
    }
}

fn delayed_config() -> Config {
    Config {
        until: 1200,
        delayed_payload: Some(PayloadDelay {
            producer: 2,
            receiver: 0,
            extra: 2000,
        }),
        data_delay: 120,
        ..Config::default()
    }
}

#[test]
fn missing_payload_does_not_block_q_or_ordering_but_delays_materialization() {
    let run = end_to_end::run(delayed_config()).unwrap();
    assert_complete(&run);
    let slow = &run.nodes[0];
    assert!(slow.requested_count() > 0);
    // Replica zero leads round one without producer two's source bytes, so
    // honest construction leaves that coordinate at the base. Round two's
    // leader includes it and exposes the actual execution retrieval wait.
    assert!(slow.executed_at[&2] > slow.ordered_at[&2]);
    assert!(run.commits[&(0, 4)] < slow.executed_at[&4]);
    assert!(run
        .sends
        .iter()
        .any(|send| send.kind == "FETCH" && send.from == 0));
    assert!(run
        .sends
        .iter()
        .any(|send| send.kind == "DATA" && send.to == 0));
    assert!(run
        .sends
        .iter()
        .filter(|send| { send.kind == "BATCH" && send.from == 2 && send.to == 0 })
        .all(|send| send.arrives_at > run.config.until));
}

#[test]
fn vote_only_descriptor_recipient_retrieves_without_proposal_witness() {
    let run = end_to_end::run(Config {
        proposal_delay_to: Some(0),
        ..delayed_config()
    })
    .unwrap();
    assert_complete(&run);
    assert!(run
        .sends
        .iter()
        .filter(|send| send.kind == "PROPOSE" && send.to == 0)
        .all(|send| send.arrives_at > run.config.until));
    assert!(run.sends.iter().any(|send| {
        send.kind == "VOTE"
            && send.to == 0
            && send.arrives_at <= run.config.until
            && send.x_bytes > 0
            && send.pi_bytes == 0
    }));
    assert!(run.nodes[0].requested_count() > 0);
    assert!(run.nodes[0].executed_at[&2] > run.nodes[0].ordered_at[&2]);
    for send in run
        .sends
        .iter()
        .filter(|send| send.kind == "FETCH" && send.from == 0)
    {
        let recipients: BTreeSet<_> = run
            .sends
            .iter()
            .filter(|other| {
                other.kind == "FETCH"
                    && other.from == 0
                    && other.at == send.at
                    && other.index == send.index
            })
            .map(|other| other.to)
            .collect();
        assert_eq!(recipients, BTreeSet::from([1, 2, 3]));
    }
}

#[test]
fn duplicate_packets_do_not_duplicate_observations_or_execution() {
    let plain = end_to_end::run(Config::default()).unwrap();
    let duplicated = end_to_end::run(Config {
        duplicates: true,
        ..Config::default()
    })
    .unwrap();
    assert_complete(&duplicated);
    for (plain, duplicated) in plain.nodes.iter().zip(&duplicated.nodes) {
        assert_eq!(plain.executed, duplicated.executed);
        assert_eq!(plain.observations, duplicated.observations);
        assert_eq!(duplicated.observations.len(), 4);
    }
    assert!(duplicated.sends.iter().any(|send| send.injected_duplicate));
}

#[test]
fn seven_replicas_recover_from_silent_leader_with_real_five_signer_quorums() {
    let run = end_to_end::run(Config {
        nodes: 7,
        silent: Some(0),
        ..Config::default()
    })
    .unwrap();
    assert_complete(&run);
    assert_eq!(run.nodes[1].executed.len(), 48);
    for value in &run.messages {
        if value["layer"] == "ordering" {
            if let Message::Propose(proposal) =
                serde_json::from_value(value["message"].clone()).unwrap()
            {
                let proof: AvailabilityProof = wire::decode(&proposal.witness).unwrap();
                assert_eq!(proof.pool.len(), 5);
            }
        }
    }
}

#[test]
fn q_uses_canonical_supplied_evidence_and_immutable_base_authorization() {
    let run = end_to_end::run(Config::default()).unwrap();
    let committee = Committee::new(
        [23; 32],
        (0..4).map(|id| wire::fixture_key(id).public).collect(),
    )
    .unwrap();
    let config = mmr::Config {
        context: committee.context.clone(),
        chunk_capacity: 4,
    };
    let verifier = AvailabilityConfig::new(
        committee.clone(),
        4,
        (1..=4)
            .map(|r| availability::genesis_binding(&config, r, 4))
            .collect(),
    )
    .unwrap();
    let proposal = run
        .messages
        .iter()
        .filter(|value| value["layer"] == "ordering")
        .find_map(|value| {
            match serde_json::from_value::<Message>(value["message"].clone()).unwrap() {
                Message::Propose(proposal) if proposal.header.body.round == 4 => Some(proposal),
                _ => None,
            }
        })
        .unwrap();
    assert!(verifier.q(4, &proposal.value, &proposal.witness));
    assert!(!verifier.q(3, &proposal.value, &proposal.witness));
    assert!(!verifier.q(4, &proposal.value, &[]));
    let descriptor: Descriptor = wire::decode(&proposal.value).unwrap();
    assert_eq!(wire::encode(&descriptor).unwrap(), proposal.value);
    let mut bad_value = proposal.value.clone();
    bad_value.push(0);
    assert!(!verifier.q(4, &bad_value, &proposal.witness));
    let mut bad_witness = proposal.witness.clone();
    bad_witness.push(0);
    assert!(!verifier.q(4, &proposal.value, &bad_witness));
    let mut proof: AvailabilityProof = wire::decode(&proposal.witness).unwrap();
    proof.pool[0].signature[0] ^= 1;
    assert!(!verifier.q(4, &proposal.value, &wire::encode(&proof).unwrap()));
    // A new local held frontier cannot change the truth of the old input.
    let mut unrelated_local_store = BatchStore::new(committee, 4).unwrap();
    for _ in 0..12 {
        unrelated_local_store
            .produce(&wire::fixture_key(0), 0, vec![1, 2, 3])
            .unwrap();
    }
    assert!(verifier.q(4, &proposal.value, &proposal.witness));
}

#[test]
fn cumulative_suffix_larger_than_one_frame_retrieves_and_materializes() {
    let run = end_to_end::run(Config {
        rounds: 8,
        until: 1700,
        transactions_per_batch: 32,
        transaction_bytes: 4096,
        delayed_payload: Some(PayloadDelay {
            producer: 2,
            receiver: 0,
            extra: 10000,
        }),
        data_delay: 120,
        ..Config::default()
    })
    .unwrap();
    let expected_count = 4 * 8 * 32;
    for node in &run.nodes {
        assert_eq!(node.executed, run.nodes[0].executed);
        assert_eq!(node.executed.len(), expected_count);
        assert_eq!(node.executed_rounds, (1..=8).collect::<Vec<_>>());
        assert_eq!(node.pending_materialization(), 0);
        assert_eq!(
            node.executed
                .iter()
                .map(|entry| entry.transaction)
                .collect::<BTreeSet<_>>()
                .len(),
            expected_count
        );
    }
    assert!(run
        .sends
        .iter()
        .all(|send| send.bytes <= wire::MAX_WIRE_BYTES));
    // One exact request goes to each holder. At least one holder must send
    // multiple DATA frames for the same cumulative height-eight suffix.
    let mut final_response_frames = std::collections::BTreeMap::new();
    for send in run
        .sends
        .iter()
        .filter(|send| send.kind == "DATA" && send.to == 0 && send.index == 8)
    {
        *final_response_frames.entry(send.from).or_insert(0) += 1;
    }
    assert!(final_response_frames.values().any(|frames| *frames > 1));
}
