//! HISTORY3 reports, compact history certificates, and their decision entries.
//!
//! Complete reports carry each listed own CER proof. A proposal retains only
//! signed report headers and its pivot/two predecessor proofs; verifying that
//! compact history deliberately does not demand the omitted report proofs.

use crate::wire::{
    encode, encoded_size, Committee, Context, Digest, Kind, MessageRef, Signed, SigningDomain,
    Statement, MAX_ROUND,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
thread_local! {
    static PROOF_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportHeader {
    pub context: Context,
    pub horizon: u64,
    pub positives: Vec<(u64, Digest)>,
}

impl SigningDomain for ReportHeader {
    const DOMAIN: &'static str = "history3-report";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub header: Signed<ReportHeader>,
    pub proofs: Vec<CerProof>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CerProof {
    pub cer: Signed<Statement>,
    pub triggers: Vec<Signed<Statement>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum History {
    Empty,
    Evidence {
        reports: Vec<Signed<ReportHeader>>,
        pivot: u64,
        proof: Option<CerProof>,
        previous: Vec<(u64, Option<CerProof>)>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    Cer(Digest),
    NoCer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entries {
    pub horizon: u64,
    pub pivot: u64,
    pub digest: Option<Digest>,
    pub previous: Vec<(u64, Entry)>,
}

impl Entries {
    pub fn empty() -> Self {
        Self {
            horizon: 0,
            pivot: 0,
            digest: None,
            previous: Vec::new(),
        }
    }

    /// Interpret a structurally verified projection at a positive target round.
    pub fn entry(&self, j: u64) -> Option<Entry> {
        if j == 0 || j > self.horizon {
            return None;
        }
        if j == self.pivot {
            return self.digest.map(Entry::Cer);
        }
        if j > self.pivot {
            return Some(Entry::NoCer);
        }
        self.previous
            .iter()
            .find_map(|(round, entry)| (*round == j).then_some(*entry))
    }
}

fn quorum(committee: &Committee) -> usize {
    committee.keys.len() - (committee.keys.len() - 1) / 3
}

fn predecessors(pivot: u64) -> Vec<u64> {
    (pivot.saturating_sub(2).max(1)..pivot).collect()
}

/// Whether the signed top-three list actually asserts NO-CER at `j`.
/// Positions below the third item of a full list convey no negative assertion.
pub fn negative(header: &ReportHeader, j: u64) -> bool {
    j >= 1
        && j <= header.horizon
        && !header.positives.iter().any(|(round, _)| *round == j)
        && (header.positives.len() < 3
            || header
                .positives
                .last()
                .map_or(false, |(round, _)| j > *round))
}

/// Verify a CER plus one exact minimal trigger set; attachments do not authorize
/// voting and no causal ordering is inferred from cryptographic signatures.
pub fn verify_proof(committee: &Committee, proof: &CerProof) -> Result<(), String> {
    #[cfg(test)]
    PROOF_VERIFICATIONS.with(|count| count.set(count.get() + 1));
    encoded_size(proof)?;
    committee.verify_statement(&proof.cer)?;
    if proof.cer.body.kind != Kind::Cer {
        return Err("CER proof wrapper must be a CER statement".into());
    }
    let kind = proof
        .triggers
        .first()
        .ok_or("CER proof has no trigger signatures")?
        .body
        .kind;
    let threshold = match kind {
        Kind::Vote => quorum(committee),
        Kind::Cer => (committee.keys.len() - 1) / 3 + 1,
        _ => return Err("CER proof trigger must be VOTE or CER".into()),
    };
    if proof.triggers.len() != threshold {
        return Err("CER proof must carry exactly its trigger threshold".into());
    }
    let mut signers = BTreeSet::new();
    for trigger in &proof.triggers {
        committee.verify_statement(trigger)?;
        if trigger.body.kind != kind
            || trigger.body.round != proof.cer.body.round
            || trigger.body.digest != proof.cer.body.digest
        {
            return Err("CER proof trigger kind, round, or digest mismatch".into());
        }
        if !signers.insert(trigger.signer) {
            return Err("CER proof trigger signers must be distinct".into());
        }
    }
    Ok(())
}

fn verify_report_header(
    committee: &Committee,
    header: &Signed<ReportHeader>,
) -> Result<(), String> {
    encoded_size(header)?;
    let body = &header.body;
    if body.context != committee.context {
        return Err("HISTORY3 instance or configuration mismatch".into());
    }
    if body.horizon == 0 || body.horizon > MAX_ROUND {
        return Err("HISTORY3 horizon is outside the supported positive range".into());
    }
    if body.positives.len() > 3 {
        return Err("HISTORY3 contains more than three positive entries".into());
    }
    let mut last = body.horizon + 1;
    for (round, _) in &body.positives {
        if *round == 0 || *round >= last {
            return Err("HISTORY3 rounds must decrease strictly within the horizon".into());
        }
        last = *round;
    }
    committee.verify_signature(header)
}

/// A usable complete report has exactly one matching own CER proof per listed
/// position, in the signed list's order. It cannot advertise a proof-free pivot.
pub fn verify_report(committee: &Committee, report: &Report) -> Result<(), String> {
    encoded_size(&MessageRef::History3(report))?;
    verify_report_header(committee, &report.header)?;
    if report.proofs.len() != report.header.body.positives.len() {
        return Err("HISTORY3 must attach exactly its listed proofs".into());
    }
    for ((round, digest), proof) in report.header.body.positives.iter().zip(&report.proofs) {
        verify_proof(committee, proof)?;
        if proof.cer.signer != report.header.signer
            || proof.cer.body.round != *round
            || proof.cer.body.digest != Some(*digest)
        {
            return Err("HISTORY3 proof does not match its reporter or listed CER".into());
        }
    }
    Ok(())
}

/// Structural checks available from a leader header alone. These deliberately
/// do not claim that the backing history, proofs, or external Q are valid.
pub(crate) fn verify_entries(round: u64, entries: &Entries) -> Result<(), String> {
    if round == 0 || round > MAX_ROUND {
        return Err("proposal round is outside the supported positive range".into());
    }
    if round <= 3 {
        return if *entries == Entries::empty() {
            Ok(())
        } else {
            Err("initial proposal entries must be empty".into())
        };
    }
    if entries.horizon != round - 3 || entries.pivot > entries.horizon {
        return Err("decision entry horizon or pivot mismatch".into());
    }
    if entries.digest.is_some() != (entries.pivot != 0) {
        return Err("decision entry pivot digest shape mismatch".into());
    }
    if entries.previous.iter().map(|(r, _)| *r).collect::<Vec<_>>() != predecessors(entries.pivot) {
        return Err("decision entries require exactly the ordered positive predecessors".into());
    }
    Ok(())
}

/// Verify compact proposal history. Unlike complete-report admission, the
/// retained signed lists need no proofs for positions omitted from the history.
pub fn verify_history(committee: &Committee, round: u64, history: &History) -> Result<(), String> {
    encoded_size(history)?;
    if round == 0 || round > MAX_ROUND {
        return Err("history proposal round is outside the supported positive range".into());
    }
    if round <= 3 {
        return if *history == History::Empty {
            Ok(())
        } else {
            Err("rounds 1 through 3 require the unique empty history".into())
        };
    }
    let (reports, pivot, proof, previous) = match history {
        History::Empty => return Err("later proposals require HISTORY3 evidence".into()),
        History::Evidence {
            reports,
            pivot,
            proof,
            previous,
        } => (reports, *pivot, proof, previous),
    };
    let horizon = round - 3;
    if reports.len() != quorum(committee) || pivot > horizon {
        return Err("history requires an exact report quorum and an in-range pivot".into());
    }
    let mut signers = BTreeSet::new();
    for report in reports {
        verify_report_header(committee, report)?;
        if report.body.horizon != horizon || !signers.insert(report.signer) {
            return Err("history reports need distinct signers and the exact horizon".into());
        }
        if report.body.positives.iter().any(|(r, _)| *r > pivot) {
            return Err("history pivot lies below a signed positive".into());
        }
    }
    match (pivot, proof) {
        (0, None) => {}
        (0, Some(_)) | (_, None) => return Err("history pivot proof shape mismatch".into()),
        (_, Some(proof)) => {
            verify_proof(committee, proof)?;
            if proof.cer.body.round != pivot {
                return Err("history pivot proof round mismatch".into());
            }
        }
    }
    if previous.iter().map(|(r, _)| *r).collect::<Vec<_>>() != predecessors(pivot) {
        return Err("history requires exactly the ordered positive predecessors".into());
    }
    for (j, proof) in previous {
        match proof {
            Some(proof) => {
                verify_proof(committee, proof)?;
                if proof.cer.body.round != *j {
                    return Err("history predecessor proof round mismatch".into());
                }
            }
            None => {
                if !reports.iter().all(|r| negative(&r.body, *j)) {
                    return Err(
                        "history NO-CER predecessor lacks unanimous negative reports".into(),
                    );
                }
            }
        }
    }
    Ok(())
}

/// Project validated history into its signed constant-size decision entries.
/// Invalid proof digest shapes are programmer errors; validate network history
/// before projecting it.
pub fn project(round: u64, history: &History) -> Entries {
    match history {
        History::Empty => Entries::empty(),
        History::Evidence {
            pivot,
            proof,
            previous,
            ..
        } => Entries {
            horizon: round.saturating_sub(3),
            pivot: *pivot,
            digest: proof.as_ref().and_then(|p| p.cer.body.digest),
            previous: previous
                .iter()
                .map(|(j, proof)| {
                    (
                        *j,
                        match proof {
                            Some(proof) => Entry::Cer(
                                proof
                                    .cer
                                    .body
                                    .digest
                                    .expect("project requires a validated CER proof"),
                            ),
                            None => Entry::NoCer,
                        },
                    )
                })
                .collect(),
        },
    }
}

/// Deterministically select a quorum of usable reports and the greatest known
/// valid CER pivot. Invalid/fake-positive reports cannot suppress valid reports.
/// Local proofs may raise the pivot beyond every selected report's maximum.
pub fn build_history(
    committee: &Committee,
    round: u64,
    reports: &[Report],
    local_proofs: &[CerProof],
) -> Result<History, String> {
    if round == 0 || round > MAX_ROUND {
        return Err("history proposal round is outside the supported positive range".into());
    }
    if round <= 3 {
        return Ok(History::Empty);
    }
    let horizon = round - 3;
    // Sort full encoded reports to break even Byzantine same-signer equivocation
    // deterministically. A rejected report never reserves that signer's slot.
    let mut usable: Vec<_> = reports
        .iter()
        .filter(|r| r.header.body.horizon == horizon && verify_report(committee, r).is_ok())
        .map(|r| {
            (
                r.header.signer,
                encode(r).expect("verified report is bounded"),
                r,
            )
        })
        .collect();
    usable.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    let mut selected = BTreeMap::new();
    let mut proofs: BTreeMap<u64, (Vec<u8>, CerProof)> = BTreeMap::new();
    for (_, _, report) in &usable {
        selected.entry(report.header.signer).or_insert(*report);
    }
    if selected.len() < quorum(committee) {
        return Err("not enough usable reports at the exact horizon".into());
    }
    // Every usable supplied report is local evidence, including any that is not
    // retained in the selected quorum. Invalid local proofs are ignored.
    let verified_local = local_proofs
        .iter()
        .filter(|proof| proof.cer.body.round <= horizon && verify_proof(committee, proof).is_ok());
    for proof in usable
        .iter()
        .flat_map(|(_, _, r)| r.proofs.iter())
        .chain(verified_local)
    {
        // verify_report above already checked every immutable attached proof.
        // Only the separately supplied local candidates need another check.
        if proof.cer.body.round > horizon {
            continue;
        }
        let bytes = encode(proof)?;
        let key = proof.cer.body.round;
        if proofs.get(&key).map_or(true, |(old, _)| bytes < *old) {
            proofs.insert(key, (bytes, proof.clone()));
        }
    }
    let headers: Vec<_> = selected
        .values()
        .take(quorum(committee))
        .map(|r| r.header.clone())
        .collect();
    let pivot = proofs.keys().next_back().copied().unwrap_or(0);
    let previous = predecessors(pivot)
        .into_iter()
        .map(|j| (j, proofs.get(&j).map(|(_, p)| p.clone())))
        .collect();
    let history = History::Evidence {
        reports: headers,
        pivot,
        proof: proofs.get(&pivot).map(|(_, p)| p.clone()),
        previous,
    };
    verify_history(committee, round, &history)?;
    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{fixture_key, hash, sign, Header, Id, Message, Proposal};
    use std::cell::Cell;

    fn committee() -> Committee {
        Committee::new([31; 32], (0..4).map(|id| fixture_key(id).public).collect()).unwrap()
    }

    fn statement(
        c: &Committee,
        id: Id,
        kind: Kind,
        round: u64,
        digest: Digest,
    ) -> Signed<Statement> {
        sign(
            &fixture_key(id),
            id,
            Statement {
                context: c.context.clone(),
                kind,
                round,
                digest: matches!(kind, Kind::Vote | Kind::Cer).then_some(digest),
            },
        )
    }

    fn proof(c: &Committee, owner: Id, round: u64) -> CerProof {
        let digest = hash(&("fixture-proposal", round));
        CerProof {
            cer: statement(c, owner, Kind::Cer, round, digest),
            triggers: (0..3)
                .map(|id| statement(c, id, Kind::Vote, round, digest))
                .collect(),
        }
    }

    fn report(c: &Committee, id: Id, horizon: u64, rounds: &[u64]) -> Report {
        let proofs: Vec<_> = rounds.iter().map(|r| proof(c, id, *r)).collect();
        Report {
            header: sign(
                &fixture_key(id),
                id,
                ReportHeader {
                    context: c.context.clone(),
                    horizon,
                    positives: proofs
                        .iter()
                        .map(|p| (p.cer.body.round, p.cer.body.digest.unwrap()))
                        .collect(),
                },
            ),
            proofs,
        }
    }

    fn resign(report: &mut Report) {
        report.header = sign(
            &fixture_key(report.header.signer),
            report.header.signer,
            report.header.body.clone(),
        );
    }

    fn empty_reports(c: &Committee, horizon: u64) -> Vec<Report> {
        (0..3).map(|id| report(c, id, horizon, &[])).collect()
    }

    #[test]
    fn nested_oversize_history_keeps_original_first_guard_errors() {
        let c = committee();
        let mut r = report(&c, 0, 3, &[3, 2, 1]);
        r.proofs[1].triggers[0].signature = vec![0; crate::wire::MAX_WIRE_BYTES];
        assert_eq!(
            verify_proof(&c, &r.proofs[1]),
            encode(&r.proofs[1]).map(|_| ())
        );
        let expected = encode(&Message::History3(r.clone())).map(|_| ());
        assert!(expected.is_err());
        assert_eq!(verify_report(&c, &r), expected);
        let h = History::Evidence {
            reports: vec![r.header],
            pivot: 2,
            proof: Some(r.proofs[1].clone()),
            previous: vec![],
        };
        assert_eq!(verify_history(&c, 6, &h), encode(&h).map(|_| ()));
        let mut header = report(&c, 0, 3, &[]).header;
        header.signature = vec![0; crate::wire::MAX_WIRE_BYTES];
        assert_eq!(
            verify_report_header(&c, &header),
            encode(&header).map(|_| ())
        );
    }

    // Frozen original builder: report-attached candidates are checked twice.
    fn strict_build_history(
        committee: &Committee,
        round: u64,
        reports: &[Report],
        local_proofs: &[CerProof],
    ) -> Result<History, String> {
        if round == 0 || round > MAX_ROUND {
            return Err("history proposal round is outside the supported positive range".into());
        }
        if round <= 3 {
            return Ok(History::Empty);
        }
        let horizon = round - 3;
        let mut usable: Vec<_> = reports
            .iter()
            .filter(|r| r.header.body.horizon == horizon && verify_report(committee, r).is_ok())
            .map(|r| {
                (
                    r.header.signer,
                    encode(r).expect("verified report is bounded"),
                    r,
                )
            })
            .collect();
        usable.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        let mut selected = BTreeMap::new();
        let mut proofs: BTreeMap<u64, (Vec<u8>, CerProof)> = BTreeMap::new();
        for (_, _, report) in &usable {
            selected.entry(report.header.signer).or_insert(*report);
        }
        if selected.len() < quorum(committee) {
            return Err("not enough usable reports at the exact horizon".into());
        }
        for proof in usable
            .iter()
            .flat_map(|(_, _, r)| r.proofs.iter())
            .chain(local_proofs.iter())
        {
            if proof.cer.body.round > horizon || verify_proof(committee, proof).is_err() {
                continue;
            }
            let bytes = encode(proof)?;
            let key = proof.cer.body.round;
            if proofs.get(&key).map_or(true, |(old, _)| bytes < *old) {
                proofs.insert(key, (bytes, proof.clone()));
            }
        }
        let headers = selected
            .values()
            .take(quorum(committee))
            .map(|r| r.header.clone())
            .collect();
        let pivot = proofs.keys().next_back().copied().unwrap_or(0);
        let previous = predecessors(pivot)
            .into_iter()
            .map(|j| (j, proofs.get(&j).map(|(_, p)| p.clone())))
            .collect();
        let history = History::Evidence {
            reports: headers,
            pivot,
            proof: proofs.get(&pivot).map(|(_, p)| p.clone()),
            previous,
        };
        verify_history(committee, round, &history)?;
        Ok(history)
    }

    #[test]
    fn reuse_of_current_call_report_checks_preserves_canonical_bytes_and_rejections() {
        let c = committee();
        let ordinary: Vec<_> = (0..3).map(|id| report(&c, id, 10, &[8, 5, 3])).collect();
        let mut cases = vec![ordinary.clone()];
        let mut equivocation = ordinary.clone();
        equivocation.push(report(&c, 0, 10, &[10, 9, 8]));
        equivocation.push(report(&c, 3, 10, &[7, 6, 5]));
        cases.push(equivocation); // Useful proofs outside the selected report quorum.
        let mut bad_signature = report(&c, 3, 10, &[10]);
        bad_signature.proofs[0].cer.signature[0] ^= 1;
        let mut missing = report(&c, 0, 10, &[10]);
        missing.proofs.clear();
        let mut wrong_owner = report(&c, 0, 10, &[10]);
        wrong_owner.proofs[0] = proof(&c, 1, 10);
        let wrong_horizon = report(&c, 3, 11, &[10]);
        let bad = vec![bad_signature, missing, wrong_owner, wrong_horizon];
        let mut mixed = ordinary;
        mixed.extend(bad.clone());
        cases.push(mixed);
        cases.push(bad); // No valid report quorum must still reject.

        let mut malformed_local = proof(&c, 3, 10);
        malformed_local.triggers[2] = malformed_local.triggers[0].clone();
        let local = vec![proof(&c, 3, 9), proof(&c, 3, 11), malformed_local];
        for mut reports in cases {
            for _ in 0..2 {
                for round in [0, 3, 13, MAX_ROUND + 1] {
                    let expected = strict_build_history(&c, round, &reports, &local)
                        .map(|h| encode(&h).unwrap());
                    let actual =
                        build_history(&c, round, &reports, &local).map(|h| encode(&h).unwrap());
                    assert_eq!(actual, expected);
                }
                reports.reverse();
            }
        }
    }

    #[test]
    fn report_proofs_are_checked_once_before_final_assembled_history_validation() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 3, &[3, 2, 1])).collect();
        PROOF_VERIFICATIONS.with(|count| count.set(0));
        let expected = strict_build_history(&c, 6, &reports, &[]).unwrap();
        let old_calls = PROOF_VERIFICATIONS.with(Cell::get);
        PROOF_VERIFICATIONS.with(|count| count.set(0));
        let actual = build_history(&c, 6, &reports, &[]).unwrap();
        let calls = PROOF_VERIFICATIONS.with(Cell::get);
        assert_eq!(encode(&actual).unwrap(), encode(&expected).unwrap());
        assert_eq!(old_calls, 21); // 9 in reports + 9 candidates + 3 final proofs.
        assert_eq!(calls, 12); // 9 in reports + 3 final proofs; none are trusted blindly.
    }

    fn proposal(c: &Committee, round: u64, history: History) -> Proposal {
        let value = b"ordered-value".to_vec();
        let witness = vec![];
        let leader = ((round - 1) % c.keys.len() as u64) as Id;
        Proposal {
            header: sign(
                &fixture_key(leader),
                leader,
                Header {
                    context: c.context.clone(),
                    round,
                    value_hash: hash(&value),
                    witness_hash: hash(&witness),
                    history_hash: hash(&history),
                    entries: project(round, &history),
                },
            ),
            value,
            witness,
            history,
        }
    }

    #[test]
    fn top_three_negatives_only_cover_the_asserted_range() {
        let c = committee();
        let report = report(&c, 0, 10, &[8, 5, 3]);
        verify_report(&c, &report).unwrap();
        for j in [4, 6, 7, 9, 10] {
            assert!(negative(&report.header.body, j));
        }
        for j in [0, 1, 2, 3, 5, 8, 11] {
            assert!(!negative(&report.header.body, j));
        }
        let mut short = report.header.body;
        short.positives.pop();
        assert!(negative(&short, 1));
        assert!(negative(&short, 3));
    }

    #[test]
    fn proof_requires_matching_exact_distinct_trigger_signatures() {
        let c = committee();
        let valid = proof(&c, 3, 2);
        verify_proof(&c, &valid).unwrap();
        let mut duplicate = valid.clone();
        duplicate.triggers[2] = duplicate.triggers[0].clone();
        assert!(verify_proof(&c, &duplicate).is_err());
        let mut short = valid.clone();
        short.triggers.pop();
        assert!(verify_proof(&c, &short).is_err());
        let mut long = valid.clone();
        long.triggers.push(statement(
            &c,
            3,
            Kind::Vote,
            2,
            valid.cer.body.digest.unwrap(),
        ));
        assert!(verify_proof(&c, &long).is_err());
        for replacement in [
            statement(&c, 2, Kind::Cer, 2, valid.cer.body.digest.unwrap()),
            statement(&c, 2, Kind::Vote, 3, valid.cer.body.digest.unwrap()),
            statement(&c, 2, Kind::Vote, 2, [99; 32]),
        ] {
            let mut bad = valid.clone();
            bad.triggers[2] = replacement;
            assert!(verify_proof(&c, &bad).is_err());
        }
        let mut bad_wrapper = valid.clone();
        bad_wrapper.cer = statement(&c, 3, Kind::Vote, 2, valid.cer.body.digest.unwrap());
        assert!(verify_proof(&c, &bad_wrapper).is_err());
        let mut tampered = valid.clone();
        tampered.triggers[0].signature[0] ^= 1;
        assert!(verify_proof(&c, &tampered).is_err());
        let mut other = c.clone();
        other.context.instance[0] ^= 1;
        assert!(verify_proof(&other, &valid).is_err());
    }

    #[test]
    fn amplification_proof_uses_f_plus_one_cers_without_inventing_causal_checks() {
        let c = committee();
        let mut p = proof(&c, 0, 1);
        p.triggers = (0..2)
            .map(|id| statement(&c, id, Kind::Cer, 1, p.cer.body.digest.unwrap()))
            .collect();
        verify_proof(&c, &p).unwrap();
        p.triggers.pop();
        assert!(verify_proof(&c, &p).is_err());
    }

    #[test]
    fn complete_report_requires_exact_own_proofs() {
        let c = committee();
        let valid = report(&c, 1, 5, &[5, 3, 1]);
        verify_report(&c, &valid).unwrap();
        let mut missing = valid.clone();
        missing.proofs.pop();
        assert!(verify_report(&c, &missing).is_err());
        let mut extra = valid.clone();
        extra.proofs.push(proof(&c, 1, 2));
        assert!(verify_report(&c, &extra).is_err());
        let mut other_reporter = valid.clone();
        other_reporter.proofs[0] = proof(&c, 2, 5);
        assert!(verify_report(&c, &other_reporter).is_err());
        let mut wrong_position = valid.clone();
        wrong_position.proofs.swap(0, 1);
        assert!(verify_report(&c, &wrong_position).is_err());
        let mut fake_hash = valid;
        fake_hash.header.body.positives[0].1 = [101; 32];
        resign(&mut fake_hash);
        assert!(verify_report(&c, &fake_hash).is_err());
    }

    #[test]
    fn report_shape_and_context_are_checked_even_when_signed() {
        let c = committee();
        for rounds in [&[5, 3, 1, 0][..], &[5, 5][..], &[2, 3][..], &[6][..]] {
            let bad = report(&c, 0, 5, rounds);
            assert!(verify_report(&c, &bad).is_err());
        }
        let mut zero = report(&c, 0, 1, &[]);
        zero.header.body.horizon = 0;
        resign(&mut zero);
        assert!(verify_report(&c, &zero).is_err());
        let mut context = report(&c, 0, 1, &[]);
        context.header.body.context.configuration[0] ^= 1;
        resign(&mut context);
        assert!(verify_report(&c, &context).is_err());
    }

    #[test]
    fn all_negative_round_four_history_has_pivot_zero() {
        let c = committee();
        let h = build_history(&c, 4, &empty_reports(&c, 1), &[]).unwrap();
        verify_history(&c, 4, &h).unwrap();
        let e = project(4, &h);
        assert_eq!(
            e,
            Entries {
                horizon: 1,
                pivot: 0,
                digest: None,
                previous: vec![]
            }
        );
        assert_eq!(e.entry(1), Some(Entry::NoCer));
        assert_eq!(e.entry(0), None);
        assert_eq!(e.entry(2), None);
        c.verify_proposal(&proposal(&c, 4, h), |_, _, _| true)
            .unwrap();
    }

    #[test]
    fn positive_round_four_proposal_validates_and_roundtrips() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 1, &[1])).collect();
        let h = build_history(&c, 4, &reports, &[]).unwrap();
        let p = proposal(&c, 4, h);
        assert_eq!(p.header.body.entries.pivot, 1);
        assert_eq!(
            p.header.body.entries.entry(1),
            Some(Entry::Cer(proof(&c, 0, 1).cer.body.digest.unwrap()))
        );
        let bytes = encode(&Message::Propose(p.clone())).unwrap();
        assert_eq!(
            crate::wire::decode::<Message>(&bytes).unwrap(),
            Message::Propose(p.clone())
        );
        c.verify_proposal(&p, |_, _, _| true).unwrap();
    }

    #[test]
    fn fake_high_report_does_not_reserve_the_valid_reporters_slot() {
        let c = committee();
        let mut fake = report(&c, 0, 10, &[10]);
        fake.proofs.clear();
        let mut reports = vec![fake];
        reports.extend(empty_reports(&c, 10));
        reports.push(report(&c, 3, 9, &[9]));
        let h = build_history(&c, 13, &reports, &[]).unwrap();
        assert_eq!(project(13, &h).pivot, 0);
        reports.reverse();
        assert_eq!(build_history(&c, 13, &reports, &[]).unwrap(), h);
    }

    #[test]
    fn distinct_reporters_and_exact_horizons_are_required() {
        let c = committee();
        let r = report(&c, 0, 2, &[]);
        assert!(build_history(&c, 5, &[r.clone(), r.clone(), r], &[]).is_err());
        assert!(build_history(&c, 5, &empty_reports(&c, 1), &[]).is_err());
        let mut h = build_history(&c, 5, &empty_reports(&c, 2), &[]).unwrap();
        if let History::Evidence { reports, .. } = &mut h {
            reports[2] = reports[0].clone();
        }
        assert!(verify_history(&c, 5, &h).is_err());
        let mut h = build_history(&c, 5, &empty_reports(&c, 2), &[]).unwrap();
        if let History::Evidence { reports, .. } = &mut h {
            reports[2] = report(&c, 2, 1, &[]).header;
        }
        assert!(verify_history(&c, 5, &h).is_err());
    }

    #[test]
    fn local_pivot_may_rise_above_every_report_with_negative_bridges() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 10, &[3, 2, 1])).collect();
        let local = vec![proof(&c, 3, 9), proof(&c, 3, 11)];
        let h = build_history(&c, 13, &reports, &local).unwrap();
        let e = project(13, &h);
        assert_eq!(e.pivot, 9);
        assert_eq!(e.previous, vec![(7, Entry::NoCer), (8, Entry::NoCer)]);
        assert_eq!(e.entry(10), Some(Entry::NoCer));
        assert_eq!(e.entry(6), None);
        assert!(e.entry(9).is_some());
    }

    #[test]
    fn raised_pivot_retains_positive_bridge_and_rejects_fake_negative() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 10, &[8, 5, 3])).collect();
        let mut h = build_history(&c, 13, &reports, &[proof(&c, 3, 9)]).unwrap();
        let e = project(13, &h);
        assert_eq!(e.previous[0], (7, Entry::NoCer));
        assert_eq!(
            e.previous[1],
            (8, Entry::Cer(proof(&c, 0, 8).cer.body.digest.unwrap()))
        );
        if let History::Evidence { previous, .. } = &mut h {
            previous[1].1 = None;
        }
        assert!(verify_history(&c, 13, &h).is_err());
    }

    #[test]
    fn compact_validation_does_not_require_omitted_list_proofs() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 7, &[7, 4, 2])).collect();
        let h = build_history(&c, 10, &reports, &[]).unwrap();
        match &h {
            History::Evidence {
                previous, proof, ..
            } => {
                assert!(proof.is_some());
                assert_eq!(previous, &vec![(5, None), (6, None)]);
            }
            _ => panic!("expected compact history"),
        }
        verify_history(&c, 10, &h).unwrap();
        c.verify_proposal(&proposal(&c, 10, h), |_, _, _| true)
            .unwrap();
        // These signed report headers remain sufficient inside D_r even if a
        // receiver never obtained their full reports with rounds 4 and 2.
        let incomplete = Report {
            header: reports[0].header.clone(),
            proofs: vec![reports[0].proofs[0].clone()],
        };
        assert!(verify_report(&c, &incomplete).is_err());
    }

    #[test]
    fn history_rejects_missing_pivot_wrong_predecessors_and_understated_pivot() {
        let c = committee();
        let reports: Vec<_> = (0..3).map(|id| report(&c, id, 4, &[4, 2])).collect();
        let valid = build_history(&c, 7, &reports, &[]).unwrap();
        let mut no_proof = valid.clone();
        if let History::Evidence { proof, .. } = &mut no_proof {
            *proof = None;
        }
        assert!(verify_history(&c, 7, &no_proof).is_err());
        let mut bad_round = valid.clone();
        if let History::Evidence { proof: p, .. } = &mut bad_round {
            *p = Some(proof(&c, 0, 3));
        }
        assert!(verify_history(&c, 7, &bad_round).is_err());
        let mut wrong_previous = valid.clone();
        if let History::Evidence { previous, .. } = &mut wrong_previous {
            previous.reverse();
        }
        assert!(verify_history(&c, 7, &wrong_previous).is_err());
        let mut missing_previous = valid.clone();
        if let History::Evidence { previous, .. } = &mut missing_previous {
            previous.pop();
        }
        assert!(verify_history(&c, 7, &missing_previous).is_err());
        let mut low = valid;
        if let History::Evidence { pivot, .. } = &mut low {
            *pivot = 2;
        }
        assert!(verify_history(&c, 7, &low).is_err());
    }

    #[test]
    fn signed_structural_projection_never_establishes_full_validity() {
        let c = committee();
        let valid = proposal(
            &c,
            4,
            build_history(&c, 4, &empty_reports(&c, 1), &[]).unwrap(),
        );
        let mut bad = valid.clone();
        bad.history = History::Empty;
        bad.header.body.history_hash = hash(&bad.history);
        bad.header = sign(&fixture_key(3), 3, bad.header.body);
        c.verify_header(&bad.header).unwrap();
        assert!(c
            .verify_proposal(&bad, |_, _, _| panic!("Q must run last"))
            .is_err());
        let mut changed_projection = valid;
        changed_projection.header.body.entries.pivot = 1;
        changed_projection.header.body.entries.digest = Some([81; 32]);
        changed_projection.header = sign(&fixture_key(3), 3, changed_projection.header.body);
        c.verify_header(&changed_projection.header).unwrap();
        let q_calls = Cell::new(0);
        assert!(c
            .verify_proposal(&changed_projection, |_, _, _| {
                q_calls.set(q_calls.get() + 1);
                true
            })
            .is_err());
        assert_eq!(q_calls.get(), 0);
    }

    #[test]
    fn genesis_and_header_shape_reject_noncanonical_history() {
        let c = committee();
        let h = build_history(&c, 4, &empty_reports(&c, 1), &[]).unwrap();
        assert!(verify_history(&c, 3, &h).is_err());
        assert!(verify_history(&c, 4, &History::Empty).is_err());
        assert!(verify_history(&c, 0, &History::Empty).is_err());
        assert!(verify_entries(4, &Entries::empty()).is_err());
        let mut e = project(4, &h);
        e.previous.push((1, Entry::NoCer));
        assert!(verify_entries(4, &e).is_err());
        assert_eq!(Entries::empty().entry(1), None);
    }
}
