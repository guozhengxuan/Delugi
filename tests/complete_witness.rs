//! Authenticated resource-envelope fixtures, not payload-custody benchmarks.
//! Sparse subtree commitments exercise u64-height canonical proofs without
//! materializing an exponential payload history. Every proof hash, observation,
//! base certificate, history signature, and transport frame is verified.
//! Historical sources deliberately exercise Q's accepted envelope; the reference
//! all-current constructor and benchmark scheduling remain unchanged.
use delugi::availability::{
    AvailabilityConfig, AvailabilityProof, BaseCertificate, Descriptor, Observation, Observed,
    Source, SourceRef, WeakAvailability, Witness,
};
use delugi::history::{self, CerProof, Entries, History, ReportHeader};
use delugi::mmr::{self, BasicProof, Checkpoint, Config, Peak, PrefixProof};
use delugi::transport::{Layer, Transport, TransportSettings};
use delugi::wire::{self, Committee, Digest, Header, Id, Kind, Message, Proposal, Statement};
use serde::Serialize;
use std::net::TcpListener;
use std::time::Duration;

// Match the canonical MMR wire enum; keep this fixture independent of private
// proof-construction helpers so the public verifier checks its complete result.
#[derive(Clone, Copy, Serialize)]
enum Level {
    Inner,
    Top,
}

fn bag(c: &Config, id: Id, level: Level, len: u64, peaks: &[Peak]) -> Digest {
    wire::hash(&(
        "MMR/BAG",
        &c.context,
        c.chunk_capacity,
        id,
        level,
        len,
        peaks,
    ))
}

fn append(c: &Config, id: Id, level: Level, peaks: &mut Vec<Peak>, mut d: u32, mut root: Digest) {
    while peaks.last().is_some_and(|peak| peak.height == d) {
        let left = peaks.pop().unwrap().root;
        d += 1;
        root = wire::hash(&(
            "MMR/NODE",
            &c.context,
            c.chunk_capacity,
            id,
            level,
            d,
            left,
            root,
        ));
    }
    peaks.push(Peak { height: d, root });
}

fn crossing(c: &Config, id: Id) -> (Checkpoint, Checkpoint, PrefixProof) {
    let old = (1u64 << 62) - 2;
    let new = (1u64 << 63) - 1;
    let top_peaks: Vec<_> = (0..62)
        .rev()
        .filter(|d| old & (1u64 << d) != 0)
        .map(|height| Peak {
            height,
            root: wire::hash(&("fixture/subtree", id, height)),
        })
        .collect();
    let partial = vec![Peak {
        height: 0,
        root: wire::hash(&("fixture/partial", id)),
    }];
    let next = wire::hash(&("fixture/completion", id));
    let mut completed = partial.clone();
    append(c, id, Level::Inner, &mut completed, 0, next);
    let completed_root = bag(c, id, Level::Inner, 2, &completed);
    let chunk = wire::hash(&(
        "MMR/CHUNK",
        &c.context,
        c.chunk_capacity,
        id,
        old + 1,
        completed_root,
    ));
    let mut remaining_peaks = top_peaks.clone();
    append(c, id, Level::Top, &mut remaining_peaks, 0, chunk);
    let initial_remaining = remaining_peaks.clone();
    let mut from = old + 1;
    let mut suffix = Vec::new();
    while from < new {
        let d = (63 - (new - from).leading_zeros()).min(from.trailing_zeros());
        let root = wire::hash(&("fixture/suffix", id, from, d));
        suffix.push(root);
        append(c, id, Level::Top, &mut remaining_peaks, d, root);
        from += 1u64 << d;
    }
    let a = Checkpoint {
        context: c.context.clone(),
        chunk_capacity: 2,
        producer: id,
        height: old * 2 + 1,
        top: bag(c, id, Level::Top, old, &top_peaks),
        partial: bag(c, id, Level::Inner, 1, &partial),
    };
    let b = Checkpoint {
        context: c.context.clone(),
        chunk_capacity: 2,
        producer: id,
        height: new * 2,
        top: bag(c, id, Level::Top, new, &remaining_peaks),
        partial: bag(c, id, Level::Inner, 0, &[]),
    };
    let proof = PrefixProof::Crossing {
        completion: BasicProof::Extension {
            peaks: partial,
            suffix: vec![next],
        },
        completed_root,
        top_peaks,
        remaining: BasicProof::Extension {
            peaks: initial_remaining,
            suffix,
        },
    };
    mmr::verify_prefix(c, &a, &b, &proof).unwrap();
    (a, b, proof)
}

fn fixture() -> (AvailabilityConfig, Proposal) {
    let committee = Committee::with_profile(
        [194; 32],
        (0..31).map(|id| wire::fixture_key(id).public).collect(),
        wire::ResourceProfile::Complete32MibN31V1,
    )
    .unwrap();
    let config = AvailabilityConfig::new(committee.clone(), 2).unwrap();
    let triples: Vec<_> = (0..31).map(|id| crossing(&config.mmr, id)).collect();
    let frontier: Vec<_> = triples.iter().map(|(a, _, _)| a.clone()).collect();
    let base_value = wire::encode(&Descriptor {
        base: 0,
        frontier: (0..31).map(|id| mmr::genesis(&config.mmr, id)).collect(),
        targets: frontier.clone(),
    })
    .unwrap();
    let base_header = wire::sign(
        &wire::fixture_key(0),
        0,
        Header {
            context: committee.context.clone(),
            round: 1,
            value_hash: wire::hash(&base_value),
            witness_hash: [95; 32],
            history_hash: wire::empty_history_hash(),
            entries: Entries::empty(),
        },
    );
    let digest = wire::proposal_digest(&base_header.body);
    let authentication = wire::encode(&BaseCertificate {
        header: base_header,
        value: base_value,
        cers: (0..21)
            .map(|id| {
                wire::sign(
                    &wire::fixture_key(id),
                    id,
                    Statement {
                        context: committee.context.clone(),
                        kind: Kind::Cer,
                        round: 1,
                        digest: Some(digest),
                    },
                )
            })
            .collect(),
    })
    .unwrap();
    let observed: Vec<_> = triples
        .iter()
        .map(|(_, b, proof)| Observed {
            checkpoint: b.clone(),
            proof: proof.clone(),
        })
        .collect();
    let observation = |id, opportunity| {
        wire::sign(
            &wire::fixture_key(id),
            id,
            Observation {
                context: committee.context.clone(),
                opportunity,
                base: 1,
                frontier_hash: wire::hash(&frontier),
                coordinates: observed.clone(),
            },
        )
    };
    let round = 113;
    let mut proof = AvailabilityProof {
        authentication: authentication.clone(),
        pool: (0..21).map(|id| observation(id, round)).collect(),
        coordinates: Vec::new(),
        sources: Vec::new(),
    };
    for k in 0..31 {
        let mut witnesses = Vec::new();
        for id in 0..11 {
            let source = if k < 21 {
                SourceRef::Current(id)
            } else {
                let source = Source {
                    frontier: frontier.clone(),
                    authentication: authentication.clone(),
                    observation: observation(id, 2 + (k as u64 - 21) * 11 + id as u64),
                };
                let digest = source.digest().unwrap();
                proof.sources.push((digest, source));
                SourceRef::Historical(digest)
            };
            witnesses.push(Witness {
                reporter: id,
                source,
                base_bridge: PrefixProof::Empty,
                target_to_source: triples[k].2.clone(),
            });
        }
        proof.coordinates.push(WeakAvailability::Witnesses {
            base_to_target: PrefixProof::Empty,
            witnesses,
        });
    }
    proof.sources.sort_by_key(|(digest, _)| *digest);
    let value = wire::encode(&Descriptor {
        base: 1,
        frontier: frontier.clone(),
        targets: frontier,
    })
    .unwrap();
    let witness = committee.encode(&proof).unwrap();
    // A valid large witness, rather than padding or simultaneous impossible
    // maxima in separate proof components, must exercise most of the envelope.
    assert!(witness.len() > committee.input_budget() * 9 / 10);
    assert!(value.len() + witness.len() <= committee.input_budget());
    let history = History::Evidence {
        reports: (0..21)
            .map(|id| {
                wire::sign(
                    &wire::fixture_key(id),
                    id,
                    ReportHeader {
                        context: committee.context.clone(),
                        horizon: round - 3,
                        positives: vec![(1, digest)],
                    },
                )
            })
            .collect(),
        pivot: 1,
        proof: Some(CerProof {
            cer: wire::sign(
                &wire::fixture_key(0),
                0,
                Statement {
                    context: committee.context.clone(),
                    kind: Kind::Cer,
                    round: 1,
                    digest: Some(digest),
                },
            ),
            triggers: (0..21)
                .map(|id| {
                    wire::sign(
                        &wire::fixture_key(id),
                        id,
                        Statement {
                            context: committee.context.clone(),
                            kind: Kind::Vote,
                            round: 1,
                            digest: Some(digest),
                        },
                    )
                })
                .collect(),
        }),
        previous: Vec::new(),
    };
    let leader = ((round - 1) % 31) as Id;
    let header = wire::sign(
        &wire::fixture_key(leader),
        leader,
        Header {
            context: committee.context.clone(),
            round,
            value_hash: committee.hash(&value),
            witness_hash: committee.hash(&witness),
            history_hash: committee.hash(&history),
            entries: history::project(round, &history),
        },
    );
    eprintln!(
        "authenticated fixture: value={} witness={} budget={} historical_sources={}",
        value.len(),
        witness.len(),
        committee.input_budget(),
        proof.sources.len()
    );
    (
        config,
        Proposal {
            header,
            value,
            witness,
            history,
        },
    )
}

#[test]
fn near_capacity_authenticated_witness_passes_q_and_rejects_tampering() {
    let (config, mut proposal) = fixture();
    config
        .committee
        .verify_proposal(&proposal, |r, x, pi| config.q(r, x, pi))
        .unwrap();
    assert!(wire::decode::<AvailabilityProof>(&proposal.witness).is_err());
    let mut bad_prefix: AvailabilityProof = config.committee.decode(&proposal.witness).unwrap();
    let PrefixProof::Crossing {
        remaining: BasicProof::Extension { suffix, .. },
        ..
    } = &mut bad_prefix.pool[0].body.coordinates[0].proof
    else {
        panic!("wrong fixture proof")
    };
    suffix[0][0] ^= 1;
    let reporter = bad_prefix.pool[0].signer;
    bad_prefix.pool[0] = wire::sign(
        &wire::fixture_key(reporter),
        reporter,
        bad_prefix.pool[0].body.clone(),
    );
    // Even a valid ordinary signature cannot authenticate an inconsistent MMR extension.
    assert!(!config.q(
        proposal.header.body.round,
        &proposal.value,
        &config.committee.encode(&bad_prefix).unwrap()
    ));
    drop(bad_prefix);
    let mut witness: AvailabilityProof = config.committee.decode(&proposal.witness).unwrap();
    witness.sources[0].1.observation.signature[0] ^= 1;
    let changed = config.committee.encode(&witness).unwrap();
    assert!(!config.q(proposal.header.body.round, &proposal.value, &changed));
    // Re-signing the outer proposal cannot turn corrupt nested evidence into Q.
    proposal.witness = changed;
    proposal.header.body.witness_hash = config.committee.hash(&proposal.witness);
    let leader = proposal.header.signer;
    proposal.header = wire::sign(&wire::fixture_key(leader), leader, proposal.header.body);
    assert!(config
        .committee
        .verify_proposal(&proposal, |r, x, pi| config.q(r, x, pi))
        .is_err());
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets; transfers a near-32MiB authenticated witness"]
fn near_capacity_authenticated_witness_reaches_q_over_complete_tcp_frame() {
    let (config, proposal) = fixture();
    let guards: Vec<_> = (0..31)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = guards
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    drop(guards);
    let settings = TransportSettings::for_committee(&config.committee);
    let mut receiver = Transport::bind(
        1,
        config.committee.clone(),
        wire::fixture_key(1),
        addresses.clone(),
        settings.clone(),
    )
    .unwrap();
    let mut sender = Transport::bind(
        0,
        config.committee.clone(),
        wire::fixture_key(0),
        addresses,
        settings,
    )
    .unwrap();
    let bytes = config
        .committee
        .encode(&Message::Propose(proposal))
        .unwrap();
    let expected = config.committee.hash(&bytes);
    sender.send(1, Layer::Ordering, bytes).unwrap();
    let received = receiver.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(received.from, 0);
    assert_eq!(received.sequence, 1);
    assert_eq!(received.layer, Layer::Ordering);
    assert_eq!(config.committee.hash(&received.payload), expected);
    let Message::Propose(proposal) = config.committee.decode(&received.payload).unwrap() else {
        panic!("wrong message")
    };
    config
        .committee
        .verify_proposal(&proposal, |r, x, pi| config.q(r, x, pi))
        .unwrap();
    assert_eq!(receiver.snapshot().rejected_frames, 0);
    sender.shutdown();
    receiver.shutdown();
}
