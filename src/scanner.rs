//! Frozen-snapshot backward resolution and ordered value delivery.
//!
//! The caller supplies authenticated, retained evidence. In particular, entries
//! in a header are not signatures and this module never promotes them into
//! VOTE/CER evidence. Classification is recomputed in one coherent descending
//! pass; delivery is a separate pass and cannot influence classification.

use crate::history::Entry;
use crate::wire::{hash, proposal_digest, Committee, Digest, Header, Signed};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Status {
    Commit(Digest),
    Skip,
    Undecided,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Delivery {
    pub round: u64,
    pub digest: Digest,
    pub value: Vec<u8>,
}

/// Look up the exact attachment, never another header from the same round.
/// Signature verification remains the caller's responsibility.
fn matching_header(
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
    round: u64,
    digest: Digest,
) -> Option<&Signed<Header>> {
    headers
        .get(&(round, digest))
        .filter(|header| header.body.round == round && proposal_digest(&header.body) == digest)
}

/// Implement the classification pass of TryDecide on a finite frozen snapshot.
///
/// Only an explicit Skip may be passed while searching later rounds. The first
/// Undecided, absent required header, or absent entry ends this round's search;
/// a farther commitment never overrides that barrier. A direct commitment is
/// classified immediately, even before its header or value arrives.
pub fn scan(
    horizon: u64,
    direct: &BTreeMap<u64, Digest>,
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
) -> BTreeMap<u64, Status> {
    scan_from(1, horizon, direct, headers)
}

/// Recompute an exact suffix without consulting retained prefix classifications.
/// Every dependency of round r is at least r+3, so descending induction gives
/// the same suffix as the full scan, even for structurally malformed snapshots.
pub(crate) fn scan_from(
    first: u64,
    horizon: u64,
    direct: &BTreeMap<u64, Digest>,
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
) -> BTreeMap<u64, Status> {
    assert!(first > 0, "scanner rounds start at one");
    let mut statuses = BTreeMap::new();
    for round in (first..=horizon).rev() {
        let status = if let Some(digest) = direct.get(&round) {
            Status::Commit(*digest)
        } else {
            let mut resolved = Status::Undecided;
            if let Some(first) = round.checked_add(3) {
                for later in first..=horizon {
                    match statuses.get(&later) {
                        Some(Status::Skip) => continue,
                        Some(Status::Commit(digest)) => {
                            if let Some(header) = matching_header(headers, later, *digest) {
                                resolved = match header.body.entries.entry(round) {
                                    Some(Entry::Cer(digest)) => Status::Commit(digest),
                                    Some(Entry::NoCer) => Status::Skip,
                                    None => Status::Undecided,
                                };
                            }
                        }
                        Some(Status::Undecided) | None => {}
                    }
                    break;
                }
            }
            resolved
        };
        statuses.insert(round, status);
    }
    statuses
}

/// Emit the oldest contiguous decided prefix, advancing the durable cursor only
/// after each skipped or delivered slot. Missing attachments stop this run.
///
/// `cursor` starts at zero and denotes the last passed round. Callers persist its
/// advancement atomically with delivery. Equal values in different slots are
/// distinct outputs and are deliberately not deduplicated.
pub fn release(
    statuses: &BTreeMap<u64, Status>,
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
    values: &BTreeMap<(u64, Digest), Vec<u8>>,
    cursor: &mut u64,
) -> Vec<Delivery> {
    release_matching(statuses, headers, values, cursor, |value, digest| {
        hash(value) == *digest
    })
}

/// Profile-aware delivery for the authenticated committee. The legacy public
/// release helper remains byte-for-byte compatible for existing fixtures.
pub(crate) fn release_with_committee(
    committee: &Committee,
    statuses: &BTreeMap<u64, Status>,
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
    values: &BTreeMap<(u64, Digest), Vec<u8>>,
    cursor: &mut u64,
) -> Vec<Delivery> {
    release_matching(statuses, headers, values, cursor, |value, digest| {
        committee.validate_input_size(value, &[]).is_ok() && committee.hash(value) == *digest
    })
}

fn release_matching(
    statuses: &BTreeMap<u64, Status>,
    headers: &BTreeMap<(u64, Digest), Signed<Header>>,
    values: &BTreeMap<(u64, Digest), Vec<u8>>,
    cursor: &mut u64,
    matches: impl Fn(&Vec<u8>, &Digest) -> bool,
) -> Vec<Delivery> {
    let mut deliveries = Vec::new();
    while let Some(round) = cursor.checked_add(1) {
        match statuses.get(&round) {
            Some(Status::Skip) => {}
            Some(Status::Commit(digest)) => {
                let header = match matching_header(headers, round, *digest) {
                    Some(header) => header,
                    None => break,
                };
                let value = match values.get(&(round, *digest)) {
                    Some(value) if matches(value, &header.body.value_hash) => value,
                    _ => break,
                };
                deliveries.push(Delivery {
                    round,
                    digest: *digest,
                    value: value.clone(),
                });
            }
            Some(Status::Undecided) | None => break,
        }
        *cursor = round;
    }
    deliveries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Entries;
    use crate::wire::{empty_history_hash, fixture_key, sign, Committee, Id};

    // These local scanner fixtures use real leader signatures and coherent
    // decision projections where stated. They intentionally do not construct
    // full HISTORY3 proofs: those are validated before entering this module.
    // Malformed projections are used only in explicitly named structural-guard
    // tests, never as purported admissible protocol traces.
    fn committee() -> Committee {
        Committee::new([17; 32], (0..4).map(|id| fixture_key(id).public).collect()).unwrap()
    }

    fn negative(horizon: u64) -> Entries {
        Entries {
            horizon,
            pivot: 0,
            digest: None,
            previous: vec![],
        }
    }

    fn header(round: u64, entries: Entries, value: &[u8]) -> (Digest, Signed<Header>) {
        let committee = committee();
        let leader = ((round - 1) % 4) as Id;
        let body = Header {
            context: committee.context,
            round,
            value_hash: hash(&value.to_vec()),
            witness_hash: hash(&Vec::<u8>::new()),
            history_hash: if round <= 3 {
                empty_history_hash()
            } else {
                hash(&("scanner-projected-history-fixture", &entries))
            },
            entries,
        };
        let digest = proposal_digest(&body);
        (digest, sign(&fixture_key(leader), leader, body))
    }

    fn insert(
        headers: &mut BTreeMap<(u64, Digest), Signed<Header>>,
        round: u64,
        entries: Entries,
    ) -> Digest {
        let (digest, signed) = header(round, entries, &round.to_le_bytes());
        headers.insert((round, digest), signed);
        digest
    }

    // Frozen pre-suffix implementation, independent of scan/scan_from.
    fn full_scan_reference(
        horizon: u64,
        direct: &BTreeMap<u64, Digest>,
        headers: &BTreeMap<(u64, Digest), Signed<Header>>,
    ) -> BTreeMap<u64, Status> {
        let mut statuses = BTreeMap::new();
        for round in (1..=horizon).rev() {
            let status = if let Some(digest) = direct.get(&round) {
                Status::Commit(*digest)
            } else {
                let mut resolved = Status::Undecided;
                if let Some(first) = round.checked_add(3) {
                    for later in first..=horizon {
                        match statuses.get(&later) {
                            Some(Status::Skip) => continue,
                            Some(Status::Commit(digest)) => {
                                if let Some(header) = matching_header(headers, later, *digest) {
                                    resolved = match header.body.entries.entry(round) {
                                        Some(Entry::Cer(digest)) => Status::Commit(digest),
                                        Some(Entry::NoCer) => Status::Skip,
                                        None => Status::Undecided,
                                    };
                                }
                            }
                            Some(Status::Undecided) | None => {}
                        }
                        break;
                    }
                }
                resolved
            };
            statuses.insert(round, status);
        }
        statuses
    }

    #[test]
    fn every_suffix_matches_original_scan_even_on_malformed_snapshots() {
        let mut headers = BTreeMap::new();
        let mut digests = BTreeMap::new();
        for round in 1u64..=9 {
            let entries = if round == 5 {
                negative(0) // Deliberately missing the required round-2 entry.
            } else {
                negative(round.saturating_sub(3))
            };
            digests.insert(round, insert(&mut headers, round, entries));
        }
        let fourth = digests[&4];
        let ninth = insert(
            &mut headers,
            9,
            Entries {
                horizon: 6,
                pivot: 4,
                digest: Some(fourth),
                previous: vec![(2, Entry::NoCer), (3, Entry::NoCer)],
            },
        );
        digests.insert(9, ninth);
        let mut missing_header = headers.clone();
        missing_header.remove(&(4, fourth));
        let mut wrong_map_key = headers.clone();
        wrong_map_key.insert((4, fourth), headers[&(6, digests[&6])].clone());
        for headers in [headers, missing_header, wrong_map_key] {
            // Every combination of direct anchors 4..9, plus an attachment-free
            // direct round 1. Undecided barriers and explicit skip chains vary.
            for mask in 0..128 {
                let mut direct = BTreeMap::new();
                for round in 4..=9 {
                    if mask & (1 << (round - 4)) != 0 {
                        direct.insert(round, digests[&round]);
                    }
                }
                if mask & 64 != 0 {
                    direct.insert(1, [91; 32]);
                }
                for horizon in [0, 4, 7, 9] {
                    let full = full_scan_reference(horizon, &direct, &headers);
                    assert_eq!(scan(horizon, &direct, &headers), full);
                    for first in 1..=horizon + 1 {
                        let expected = full.range(first..).map(|(r, s)| (*r, *s)).collect();
                        assert_eq!(scan_from(first, horizon, &direct, &headers), expected);
                    }
                    assert!(scan_from(horizon + 2, horizon, &direct, &headers).is_empty());
                }
            }
        }
    }

    #[test]
    fn no_authority_means_undecided_and_zero_horizon_is_empty() {
        assert!(scan(0, &BTreeMap::new(), &BTreeMap::new()).is_empty());
        let statuses = scan(4, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(statuses.len(), 4);
        assert!(statuses.values().all(|status| *status == Status::Undecided));
    }

    #[test]
    fn nearer_undecided_stops_farther_committed_authority() {
        let mut headers = BTreeMap::new();
        let fifth = insert(&mut headers, 5, negative(2));
        let statuses = scan(5, &BTreeMap::from([(5, fifth)]), &headers);
        assert_eq!(statuses[&4], Status::Undecided);
        assert_eq!(statuses[&1], Status::Undecided);
        assert_eq!(statuses[&2], Status::Skip);
    }

    #[test]
    fn nearer_commit_without_matching_header_stops_farther_authority() {
        let mut headers = BTreeMap::new();
        let (fourth, fourth_header) = header(4, negative(1), b"fourth");
        let fifth = insert(&mut headers, 5, negative(2));
        let direct = BTreeMap::from([(4, fourth), (5, fifth)]);
        let statuses = scan(5, &direct, &headers);
        assert_eq!(statuses[&4], Status::Commit(fourth));
        assert_eq!(statuses[&1], Status::Undecided);

        // Another correctly signed header at round 4 does not satisfy the exact
        // attachment dependency or suppress a subsequently arriving match.
        let conflicting = insert(&mut headers, 4, negative(1));
        assert_ne!(conflicting, fourth);
        assert_eq!(scan(5, &direct, &headers)[&1], Status::Undecided);
        headers.insert((4, fourth), fourth_header);
        assert_eq!(scan(5, &direct, &headers)[&1], Status::Skip);
    }

    #[test]
    fn structural_guard_missing_entry_stops_without_farther_fallback() {
        // Round 4's deliberately malformed empty projection is a local guard
        // fixture, not an admissible HISTORY3 proposal.
        let mut headers = BTreeMap::new();
        let fourth = insert(&mut headers, 4, negative(0));
        let fifth = insert(&mut headers, 5, negative(2));
        let statuses = scan(5, &BTreeMap::from([(4, fourth), (5, fifth)]), &headers);
        assert_eq!(statuses[&1], Status::Undecided);
    }

    #[test]
    fn direct_commit_precedes_attachments_and_values_never_overtake() {
        let (first, first_header) = header(1, negative(0), b"first");
        let (second, second_header) = header(2, negative(0), b"second");
        let direct = BTreeMap::from([(1, first), (2, second)]);
        let mut headers = BTreeMap::new();
        let statuses = scan(2, &direct, &headers);
        assert_eq!(statuses[&1], Status::Commit(first));
        assert_eq!(statuses[&2], Status::Commit(second));
        let mut cursor = 0;
        let mut values = BTreeMap::from([((2, second), b"second".to_vec())]);
        headers.insert((2, second), second_header);
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
        assert_eq!(cursor, 0);
        headers.insert((1, first), first_header);
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
        values.insert((1, first), b"first".to_vec());
        let delivered = release(&statuses, &headers, &values, &mut cursor);
        assert_eq!(
            delivered.iter().map(|d| d.round).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(cursor, 2);
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
    }

    #[test]
    fn attachment_consistency_guards_wrong_map_key_and_wrong_value() {
        let (digest, signed) = header(1, negative(0), b"value");
        let (_, other) = header(1, negative(0), b"other");
        let statuses = BTreeMap::from([(1, Status::Commit(digest))]);
        let mut headers = BTreeMap::from([((1, digest), other)]);
        let mut values = BTreeMap::from([((1, digest), b"value".to_vec())]);
        let mut cursor = 0;
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
        headers.insert((1, digest), signed);
        values.insert((1, digest), b"altered".to_vec());
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
        assert_eq!(cursor, 0);
        values.insert((1, digest), b"value".to_vec());
        assert_eq!(release(&statuses, &headers, &values, &mut cursor).len(), 1);
    }

    fn bridge_fixture() -> (
        BTreeMap<u64, Digest>,
        BTreeMap<(u64, Digest), Signed<Header>>,
        Digest,
    ) {
        let mut headers = BTreeMap::new();
        let fourth = insert(&mut headers, 4, negative(1));
        let mut direct = BTreeMap::new();
        for round in 7..=9 {
            let digest = insert(
                &mut headers,
                round,
                Entries {
                    horizon: round - 3,
                    pivot: 4,
                    digest: Some(fourth),
                    previous: vec![(2, Entry::NoCer), (3, Entry::NoCer)],
                },
            );
            direct.insert(round, digest);
        }
        (direct, headers, fourth)
    }

    #[test]
    fn pivot_bridges_omitted_positions_in_one_coherent_pass() {
        let (direct, headers, fourth) = bridge_fixture();
        for signed in headers.values() {
            committee().verify_header(signed).unwrap();
        }
        let statuses = scan(9, &direct, &headers);
        assert_eq!(statuses[&4], Status::Commit(fourth));
        for round in [1, 2, 3, 5, 6] {
            assert_eq!(statuses[&round], Status::Skip, "round {round}");
        }
        // Round 7 omits round 1, but it cannot be selected to resolve round 1:
        // its positive pivot at 4 is classified first and bridges to header 4.
        let seventh = &headers[&(7, direct[&7])];
        assert_eq!(seventh.body.entries.entry(1), None);
        for round in 7..=9 {
            assert_eq!(statuses[&round], Status::Commit(direct[&round]));
        }
    }

    #[test]
    fn indirect_commit_can_precede_its_header_but_blocks_earlier_resolution() {
        let (direct, mut headers, fourth) = bridge_fixture();
        let fourth_header = headers.remove(&(4, fourth)).unwrap();
        let statuses = scan(9, &direct, &headers);
        assert_eq!(statuses[&4], Status::Commit(fourth));
        assert_eq!(statuses[&1], Status::Undecided);
        headers.insert((4, fourth), fourth_header);
        let resolved = scan(9, &direct, &headers);
        assert_eq!(resolved[&4], Status::Commit(fourth));
        assert_eq!(resolved[&1], Status::Skip);
    }

    #[test]
    fn decided_statuses_agree_across_horizons_in_coherent_fixture() {
        let (direct, headers, _) = bridge_fixture();
        let mut previous = scan(0, &direct, &headers);
        for horizon in 1..=9 {
            let current = scan(horizon, &direct, &headers);
            for (round, status) in previous {
                if status != Status::Undecided {
                    assert_eq!(current[&round], status, "round {round}, horizon {horizon}");
                }
            }
            previous = current;
        }
    }

    #[test]
    fn silent_leader_followed_by_three_direct_anchors_resolves_prefix() {
        let mut headers = BTreeMap::new();
        let mut direct = BTreeMap::new();
        let mut values = BTreeMap::new();
        for round in 2u64..=4 {
            let digest = insert(&mut headers, round, negative(round.saturating_sub(3)));
            direct.insert(round, digest);
            values.insert((round, digest), round.to_le_bytes().to_vec());
        }
        let statuses = scan(4, &direct, &headers);
        assert_eq!(statuses[&1], Status::Skip);
        let mut cursor = 0;
        let delivered = release(&statuses, &headers, &values, &mut cursor);
        assert_eq!(
            delivered.iter().map(|d| d.round).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
        assert_eq!(cursor, 4);
        assert_eq!(scan(4, &direct, &headers), statuses);
    }

    #[test]
    fn equal_values_in_distinct_slots_are_each_delivered_once() {
        let value = b"same-value".to_vec();
        let mut direct = BTreeMap::new();
        let mut headers = BTreeMap::new();
        let mut values = BTreeMap::new();
        for round in 1..=3 {
            let (digest, signed) = header(round, negative(0), &value);
            direct.insert(round, digest);
            headers.insert((round, digest), signed);
            values.insert((round, digest), value.clone());
        }
        let statuses = scan(3, &direct, &headers);
        let mut cursor = 0;
        let delivered = release(&statuses, &headers, &values, &mut cursor);
        assert_eq!(delivered.len(), 3);
        assert!(delivered.iter().all(|delivery| delivery.value == value));
        assert_eq!(cursor, 3);
        assert!(release(&statuses, &headers, &values, &mut cursor).is_empty());
        assert_eq!(scan(3, &direct, &headers), statuses);
    }
}
