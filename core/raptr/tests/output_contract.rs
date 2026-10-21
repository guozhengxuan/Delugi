use delugi_raptr_core::*;

fn limits() -> Limits {
    Limits {
        max_slices: 64,
        max_sections: 128,
        max_batch_occurrences: 256,
        max_pending_transactions: 4096,
        max_pending_payload_bytes: 1 << 20,
    }
}

// This deliberately is NOT a native cryptographic verifier. It computes facts
// from fixture bytes independently of the expected descriptor, so corruption,
// field mismatches and native-fetch slicing errors exercise the real checks.
struct FixtureVerifier;

impl BatchPayloadVerifier<u8> for FixtureVerifier {
    fn inspect(&self, author: &Author, transactions: &[u8]) -> Result<PayloadFacts, Error> {
        let mut digest = *author;
        for (index, byte) in transactions.iter().enumerate() {
            digest[index % 32] = digest[index % 32].wrapping_add(*byte);
        }
        Ok(PayloadFacts {
            digest,
            num_txns: transactions.len() as u64,
            num_bytes: 33 + transactions.len() as u64,
        })
    }
}

fn batch(id: u64, txns: &[u8]) -> BatchInfo {
    let author = [id as u8; 32];
    let facts = FixtureVerifier.inspect(&author, txns).unwrap();
    BatchInfo {
        key: BatchKey {
            epoch: 7,
            author,
            nonce: 10,
            id,
            digest: facts.digest,
        },
        expiration: 1000,
        num_txns: facts.num_txns,
        num_bytes: facts.num_bytes,
        gas_bucket_start: 0,
    }
}

fn block(round: i64) -> BlockId {
    BlockId {
        epoch: 7,
        digest: [round as u8; 32],
        round,
        author: [9; 32],
    }
}

fn full(round: i64) -> CommitSlice {
    CommitSlice {
        block: block(round),
        include_proofs: true,
        proofs: vec![batch(1, &[90]), batch(8, &[])],
        sub_blocks: vec![
            (0, vec![batch(2, &[20])]),
            (1, vec![]),
            (2, vec![batch(2, &[20]), batch(3, &[255])]),
            (3, vec![]),
            (4, vec![]),
            (5, vec![]),
            (6, vec![]),
            (7, vec![]),
        ],
    }
}

fn slice(full: &CommitSlice, from: usize, to: usize, include_proofs: bool) -> CommitSlice {
    CommitSlice {
        block: full.block.clone(),
        include_proofs,
        proofs: if include_proofs {
            full.proofs.clone()
        } else {
            vec![]
        },
        sub_blocks: full.sub_blocks[from..to].to_vec(),
    }
}

fn fetched(slice: &CommitSlice) -> Vec<u8> {
    slice
        .sub_blocks
        .iter()
        .flat_map(|(_, batches)| batches)
        .chain(&slice.proofs)
        .flat_map(|batch| match batch.key.id {
            1 => vec![90],
            2 => vec![20],
            3 => vec![255],
            8 => vec![],
            _ => panic!("fixture batch"),
        })
        .collect()
}

fn txns(sections: &[PublishedSection<u8>]) -> Vec<u8> {
    sections
        .iter()
        .flat_map(|section| &section.batches)
        .flat_map(|batch| &batch.transactions)
        .copied()
        .collect()
}

#[test]
fn all_legal_prefix_partitions_match_one_commit_even_with_reverse_fetch_completion() {
    let full = full(1);
    let mut combined = OutputContract::new(limits());
    let ticket = combined.reserve(full.clone()).unwrap().ticket;
    combined
        .resolve_native_fetch(ticket, fetched(&full), &FixtureVerifier)
        .unwrap();
    let expected = combined.take_ready();
    assert_eq!(txns(&expected), [90, 20, 20, 255]);
    assert_eq!(expected.len(), 9); // proofs plus every original subblock, including empties

    // Every partition of eight subblocks, also with a proof-only first commit.
    for proof_only_first in [false, true] {
        for cuts in 0u16..128 {
            let mut contract = OutputContract::new(limits());
            let mut requests = Vec::new();
            let mut start = 0;
            let mut first = true;
            if proof_only_first {
                let part = slice(&full, 0, 0, true);
                requests.push((
                    contract.reserve(part.clone()).unwrap().ticket,
                    fetched(&part),
                ));
                first = false;
            }
            for end in 1..=8 {
                if end == 8 || (cuts & (1 << (end - 1))) != 0 {
                    let part = slice(&full, start, end, first);
                    requests.push((
                        contract.reserve(part.clone()).unwrap().ticket,
                        fetched(&part),
                    ));
                    first = false;
                    start = end;
                }
            }
            for (ticket, bytes) in requests.into_iter().rev() {
                contract
                    .resolve_native_fetch(ticket, bytes, &FixtureVerifier)
                    .unwrap();
            }
            assert_eq!(
                contract.take_ready(),
                expected,
                "cuts={cuts}, proof_only={proof_only_first}"
            );
            assert_eq!(contract.snapshot().pending_slices, 0);
        }
    }
}

#[test]
fn later_round_and_extension_cannot_bypass_a_blocked_initial_fetch() {
    let one = full(1);
    let initial = slice(&one, 0, 1, true);
    let extension = slice(&one, 1, 8, false);
    let two = full(3); // native committed rounds need not be consecutive
    let mut contract = OutputContract::new(limits());
    let first = contract.reserve(initial.clone()).unwrap().ticket;
    let second = contract.reserve(extension.clone()).unwrap().ticket;
    let third = contract.reserve(two.clone()).unwrap().ticket;
    contract
        .resolve_native_fetch(third, fetched(&two), &FixtureVerifier)
        .unwrap();
    contract
        .resolve_native_fetch(second, fetched(&extension), &FixtureVerifier)
        .unwrap();
    assert!(contract.take_ready().is_empty());
    assert_eq!(contract.snapshot().resolved_pending_slices, 2);
    contract
        .resolve_native_fetch(first, fetched(&initial), &FixtureVerifier)
        .unwrap();
    let published = contract.take_ready();
    assert_eq!(published.len(), 18);
    assert!(published[..9]
        .iter()
        .all(|section| section.block.round == 1));
    assert!(published[9..]
        .iter()
        .all(|section| section.block.round == 3));
}

#[test]
fn raw_repeated_batches_and_unknown_transactions_survive_unique_batch_accounting() {
    let full = full(1);
    let mut contract = OutputContract::new(limits());
    let ticket = contract.reserve(full.clone()).unwrap().ticket;
    contract
        .resolve_native_fetch(ticket, fetched(&full), &FixtureVerifier)
        .unwrap();
    let published = contract.take_ready();
    let batches: Vec<_> = published
        .iter()
        .flat_map(|section| &section.batches)
        .collect();
    assert_eq!(batches.len(), 5);
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.first_occurrence)
            .collect::<Vec<_>>(),
        [true, true, true, false, true]
    );
    assert_eq!(txns(&published), [90, 20, 20, 255]); // no application-identity filter here
    assert_eq!(contract.snapshot().published_transactions, 4);
}

#[test]
fn duplicate_callback_and_resolution_never_emit_duplicate_sections() {
    let full = full(1);
    let mut contract = OutputContract::new(limits());
    let reservation = contract.reserve(full.clone()).unwrap();
    assert!(!reservation.duplicate);
    assert_eq!(
        contract.reserve(full.clone()).unwrap(),
        Reservation {
            duplicate: true,
            ..reservation
        }
    );
    contract
        .resolve_native_fetch(reservation.ticket, fetched(&full), &FixtureVerifier)
        .unwrap();
    assert_eq!(
        contract.resolve_native_fetch(reservation.ticket, fetched(&full), &FixtureVerifier),
        Err(Error::AlreadyResolved)
    );
    assert_eq!(contract.take_ready().len(), 9);
    assert!(contract.reserve(full).unwrap().duplicate);
    assert!(contract.take_ready().is_empty());
}

#[test]
fn rejects_bad_extension_renumbering_forks_and_conflicting_descriptors_atomically() {
    let full = full(1);
    let mut contract = OutputContract::<u8>::new(limits());
    contract.reserve(slice(&full, 0, 1, true)).unwrap();
    let before = contract.snapshot();
    assert_eq!(
        contract.reserve(slice(&full, 2, 3, false)),
        Err(Error::NonContiguousCommit)
    );
    assert_eq!(
        contract.reserve(slice(&full, 0, 2, true)),
        Err(Error::NonContiguousCommit)
    );
    let mut fork = full.clone();
    fork.block.digest[31] ^= 1;
    assert_eq!(contract.reserve(fork), Err(Error::ConflictingBlock));
    let mut changed = slice(&full, 1, 3, false);
    changed.sub_blocks[1].1[0].num_bytes += 1;
    assert_eq!(contract.reserve(changed), Err(Error::ConflictingBatch));
    assert_eq!(contract.snapshot(), before);
    contract.reserve(slice(&full, 1, 8, false)).unwrap();
}

#[test]
fn invalid_native_fetch_count_digest_or_size_never_mutates_reservation() {
    let full = full(1);
    let mut contract = OutputContract::new(limits());
    let ticket = contract.reserve(full.clone()).unwrap().ticket;
    let before = contract.snapshot();
    assert_eq!(
        contract.resolve_native_fetch(ticket, vec![20], &FixtureVerifier),
        Err(Error::TransactionCount)
    );
    assert_eq!(
        contract.resolve_native_fetch(ticket, vec![20, 21, 255, 90], &FixtureVerifier),
        Err(Error::PayloadMismatch)
    );
    // Supplying canonical order instead of the actual native return order fails.
    assert_eq!(
        contract.resolve_native_fetch(ticket, vec![90, 20, 20, 255], &FixtureVerifier),
        Err(Error::PayloadMismatch)
    );
    assert_eq!(contract.snapshot(), before);
    contract
        .resolve_native_fetch(ticket, fetched(&full), &FixtureVerifier)
        .unwrap();
    assert_eq!(txns(&contract.take_ready()), [90, 20, 20, 255]);

    let mut wrong_size = full.clone();
    wrong_size.proofs[0].num_bytes += 1;
    let mut contract = OutputContract::new(limits());
    let ticket = contract.reserve(wrong_size.clone()).unwrap().ticket;
    assert_eq!(
        contract.resolve_native_fetch(ticket, fetched(&wrong_size), &FixtureVerifier),
        Err(Error::PayloadMismatch)
    );
}

#[test]
fn capacity_rejection_does_not_advance_prefix_or_hide_resolved_pending_payload() {
    let full = full(1);
    let initial = slice(&full, 0, 1, true);
    let extension = slice(&full, 1, 8, false);
    let mut bounded = limits();
    bounded.max_pending_transactions = 2;
    let mut contract = OutputContract::new(bounded);
    let first = contract.reserve(initial.clone()).unwrap().ticket;
    let before = contract.snapshot();
    assert_eq!(contract.reserve(extension.clone()), Err(Error::Capacity));
    assert_eq!(contract.snapshot(), before);
    contract
        .resolve_native_fetch(first, fetched(&initial), &FixtureVerifier)
        .unwrap();
    assert_eq!(contract.snapshot().pending_transactions, 2);
    contract.take_ready();
    contract.reserve(extension).unwrap();
}

#[test]
fn independent_freeze_preserves_empty_or_blocked_prefix_and_censors_late_results() {
    let mut empty = OutputContract::<u8>::new(limits());
    assert_eq!(empty.freeze().published_sections, 0);
    assert_eq!(empty.reserve(full(1)), Err(Error::Frozen));

    let full = full(1);
    let mut blocked = OutputContract::new(limits());
    let first = blocked.reserve(slice(&full, 0, 1, true)).unwrap().ticket;
    let later_slice = slice(&full, 1, 8, false);
    let later = blocked.reserve(later_slice.clone()).unwrap().ticket;
    blocked
        .resolve_native_fetch(later, fetched(&later_slice), &FixtureVerifier)
        .unwrap();
    let frozen = blocked.freeze();
    assert_eq!(frozen.published_sections, 0);
    assert_eq!(frozen.pending_slices, 2);
    assert_eq!(frozen.resolved_pending_slices, 1);
    assert_eq!(frozen.pending_transactions, 4);
    assert_eq!(
        blocked.resolve_native_fetch(first, vec![20, 90], &FixtureVerifier),
        Err(Error::Frozen)
    );
    assert!(blocked.take_ready().is_empty());
    assert_eq!(blocked.snapshot(), frozen);
}

#[test]
fn all_empty_native_sections_remain_visible() {
    let empty = CommitSlice {
        block: block(1),
        include_proofs: true,
        proofs: vec![],
        sub_blocks: (0..8).map(|i| (i, vec![])).collect(),
    };
    let mut contract = OutputContract::<u8>::new(limits());
    let ticket = contract.reserve(empty).unwrap().ticket;
    contract
        .resolve_native_fetch(ticket, vec![], &FixtureVerifier)
        .unwrap();
    let sections = contract.take_ready();
    assert_eq!(sections.len(), 9);
    assert_eq!(sections[0].kind, SectionKind::Proofs);
    for index in 0..8 {
        assert_eq!(sections[index + 1].kind, SectionKind::SubBlock(index));
    }
    assert_eq!(contract.freeze().published_transactions, 0);
}

#[test]
fn descriptor_bcs_layout_and_full_width_identity_are_fixed() {
    // Independently laid out native fixed-width schema, deliberately using
    // different id/nonce values to detect accidental field swapping.
    let mut native = [0u8; 120];
    for i in 0..32 {
        native[i] = i as u8;
        native[64 + i] = (255 - i) as u8;
    }
    for (offset, number) in [
        (32, 1u64),
        (40, 2),
        (48, 3),
        (56, 4),
        (96, 5),
        (104, 6),
        (112, 7),
    ] {
        native[offset..offset + 8].copy_from_slice(&number.to_le_bytes());
    }
    let info = BatchInfo::from_native_bcs(&native).unwrap();
    assert_eq!((info.key.id, info.key.nonce, info.key.epoch), (1, 2, 3));
    assert_eq!(
        (
            info.expiration,
            info.num_txns,
            info.num_bytes,
            info.gas_bucket_start
        ),
        (4, 5, 6, 7)
    );
    assert_eq!(info.to_native_bcs(), native);
    assert_eq!(
        BatchInfo::from_native_bcs(&native[..119]),
        Err(Error::InvalidDescriptor)
    );
    let mut modified = info.clone();
    modified.key.digest[31] ^= 1;
    assert_ne!(info.key, modified.key);
    let mut renewed = info.clone();
    renewed.expiration += 1;
    assert_eq!(info.key, renewed.key);
    assert_ne!(info, renewed);
}
