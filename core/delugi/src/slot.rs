//! A deterministic reference implementation of the per-round ordering guards.
//!
//! This module deliberately does not validate wire messages or execute `Q`. The
//! caller must verify signatures, instance/configuration bindings, message type,
//! round, and membership before supplying evidence. It must retain those actual
//! signatures so that a returned [`Trigger`] can be materialized as a CER proof.
//! `validate` may be called only after complete proposal validation, including
//! its history, signed decision entries, and `Q`.
//!
//! Signer IDs are zero-based positions in the immutable configured membership.
//! Admission means the replica's current round; admission to a later round does
//! not disable this slot. Timers, progress, history, and resolution live outside
//! this module. A caller must apply emitted actions and retained state atomically.

use std::collections::{BTreeMap, BTreeSet};

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Open,
    Cer(Digest),
    NoCer,
}

/// IDs of the verified signatures justifying our own CER, excluding its own
/// signed CER wrapper. The caller retains and retrieves the actual signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trigger {
    Votes(Vec<u32>),
    Cers(Vec<u32>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Vote(Digest),
    Cer(Digest),
    DirectCommit(Digest),
}

#[derive(Debug)]
pub struct Slot {
    round: u64,
    n: usize,
    own: u32,
    quorum: usize,
    amplification: usize,
    voted: Option<Digest>,
    terminal: Terminal,
    committed: Option<Digest>,
    proof: Option<Trigger>,
    validated: BTreeSet<Digest>,
    votes: BTreeMap<Digest, BTreeSet<u32>>,
    cers: BTreeMap<Digest, BTreeSet<u32>>,
}

impl Slot {
    /// Create a non-genesis slot for n = 3f + 1 and f >= 1.
    ///
    /// Panics for invalid configuration, an unknown own signer, round zero, or
    /// a round whose phase-admission indices cannot be represented.
    pub fn new(round: u64, n: usize, own: u32) -> Self {
        assert!(round >= 1 && round <= u64::MAX - 2, "invalid slot round");
        assert!(n >= 4 && (n - 1) % 3 == 0, "requires n = 3f + 1, f >= 1");
        assert!(n <= u32::MAX as usize, "membership exceeds signer ID range");
        assert!((own as usize) < n, "own signer is not a member");
        let f = (n - 1) / 3;
        Self {
            round,
            n,
            own,
            quorum: n - f,
            amplification: f + 1,
            voted: None,
            terminal: Terminal::Open,
            committed: None,
            proof: None,
            validated: BTreeSet::new(),
            votes: BTreeMap::new(),
            cers: BTreeMap::new(),
        }
    }

    pub fn voted(&self) -> Option<Digest> {
        self.voted
    }

    pub fn terminal(&self) -> Terminal {
        self.terminal
    }

    pub fn committed(&self) -> Option<Digest> {
        self.committed
    }

    pub fn proof(&self) -> Option<&Trigger> {
        self.proof.as_ref()
    }

    /// Retain one verified VOTE signature's identity. Repeats count once.
    pub fn observe_vote(&mut self, signer: u32, digest: Digest) {
        assert!((signer as usize) < self.n, "VOTE signer is not a member");
        self.votes.entry(digest).or_default().insert(signer);
    }

    /// Retain one verified CER signature's identity. Repeats count once.
    pub fn observe_cer(&mut self, signer: u32, digest: Digest) {
        assert!((signer as usize) < self.n, "CER signer is not a member");
        self.cers.entry(digest).or_default().insert(signer);
    }

    /// Record successful *complete* proposal validation by the caller.
    pub fn validate(&mut self, digest: Digest) {
        self.validated.insert(digest);
    }

    /// Drain enabled local actions to a fixed point, retaining our own emitted
    /// VOTE/CER as immediately self-delivered evidence.
    ///
    /// Ordered maps give deterministic digest/signer selection if multiple
    /// candidates are supplied. Certificate uniqueness is a protocol property
    /// under the fault bound, not something signature verification alone proves.
    pub fn drive(&mut self, admitted: u64) -> Vec<Action> {
        let mut actions = Vec::new();
        loop {
            let before = actions.len();
            if admitted >= self.round + 1 && self.voted.is_none() {
                let candidate = match self.terminal {
                    Terminal::Open => self.validated.iter().next().copied(),
                    Terminal::Cer(digest) if self.validated.contains(&digest) => Some(digest),
                    Terminal::Cer(_) | Terminal::NoCer => None,
                };
                if let Some(digest) = candidate {
                    self.voted = Some(digest);
                    self.observe_vote(self.own, digest);
                    actions.push(Action::Vote(digest));
                }
            }
            if admitted >= self.round + 2 && self.terminal == Terminal::Open {
                // Prefer the VOTE trigger whenever both kinds are available.
                let enabled = Self::threshold(&self.votes, self.quorum)
                    .map(|(digest, ids)| (digest, Trigger::Votes(ids)))
                    .or_else(|| {
                        Self::threshold(&self.cers, self.amplification)
                            .map(|(digest, ids)| (digest, Trigger::Cers(ids)))
                    });
                if let Some((digest, trigger)) = enabled {
                    self.terminal = Terminal::Cer(digest);
                    self.proof = Some(trigger);
                    self.observe_cer(self.own, digest);
                    actions.push(Action::Cer(digest));
                }
            }
            // Direct commitment is independent of own outcome, admission, and
            // the availability of the full proposal or its VOTE attachments.
            if self.committed.is_none() {
                if let Some((digest, _)) = Self::threshold(&self.cers, self.quorum) {
                    self.committed = Some(digest);
                    actions.push(Action::DirectCommit(digest));
                }
            }
            if actions.len() == before {
                return actions;
            }
        }
    }

    /// Process a caller-authorized main/catch-up timer expiry for this slot.
    /// Draining enabled work first guarantees CER precedes NO-CER when they
    /// become eligible in the same local step. Terminal outcomes never change.
    pub fn finish(&mut self, admitted: u64) -> Vec<Action> {
        assert!(
            admitted >= self.round + 2,
            "FinishRound requires round + 2 admission"
        );
        let actions = self.drive(admitted);
        if self.terminal == Terminal::Open {
            self.terminal = Terminal::NoCer;
        }
        actions
    }

    fn threshold(
        evidence: &BTreeMap<Digest, BTreeSet<u32>>,
        needed: usize,
    ) -> Option<(Digest, Vec<u32>)> {
        evidence.iter().find_map(|(digest, ids)| {
            (ids.len() >= needed).then(|| (*digest, ids.iter().take(needed).copied().collect()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Digest = [1; 32];
    const B: Digest = [2; 32];

    fn slot() -> Slot {
        Slot::new(1, 4, 0)
    }

    fn vote_quorum(slot: &mut Slot, digest: Digest) {
        for signer in 1..=3 {
            slot.observe_vote(signer, digest);
        }
    }

    #[test]
    fn votes_require_a_quorum_of_distinct_signers_without_amplification() {
        let mut s = slot();
        s.observe_vote(1, A);
        s.observe_vote(1, A);
        s.observe_vote(2, A);
        assert!(s.drive(3).is_empty()); // f+1 VOTEs is not a trigger.
        s.observe_vote(3, A);
        assert_eq!(s.drive(3), vec![Action::Cer(A)]);
        assert_eq!(s.proof(), Some(&Trigger::Votes(vec![1, 2, 3])));
        assert!(s.drive(3).is_empty());
    }

    #[test]
    fn cer_amplification_counts_distinct_signers_and_self_delivery() {
        let mut s = slot();
        s.observe_cer(1, A);
        s.observe_cer(1, A);
        assert!(s.drive(3).is_empty());
        s.observe_cer(2, A);
        assert!(s.drive(2).is_empty());
        assert_eq!(s.drive(3), vec![Action::Cer(A), Action::DirectCommit(A)]);
        assert_eq!(s.proof(), Some(&Trigger::Cers(vec![1, 2])));
        assert_eq!(s.committed(), Some(A));
    }

    #[test]
    fn vote_requires_validation_and_admission_then_can_enable_own_cer() {
        let mut s = slot();
        s.observe_vote(1, A);
        s.observe_vote(2, A);
        assert!(s.drive(3).is_empty());
        s.validate(A);
        assert!(s.drive(1).is_empty());
        assert_eq!(s.drive(2), vec![Action::Vote(A)]);
        assert_eq!(s.drive(3), vec![Action::Cer(A)]);
        assert_eq!(s.proof(), Some(&Trigger::Votes(vec![0, 1, 2])));
    }

    #[test]
    fn no_cer_is_irreversible_but_does_not_block_direct_commit() {
        let mut s = slot();
        assert!(s.finish(3).is_empty());
        assert_eq!(s.terminal(), Terminal::NoCer);
        s.validate(A);
        vote_quorum(&mut s, A);
        for signer in 1..=3 {
            s.observe_cer(signer, A);
        }
        assert_eq!(s.drive(100), vec![Action::DirectCommit(A)]);
        assert!(s.finish(100).is_empty());
        assert_eq!(s.terminal(), Terminal::NoCer);
        assert_eq!(s.voted(), None);
        assert_eq!(s.proof(), None);
    }

    #[test]
    fn cer_before_proposal_permits_only_a_later_matching_vote() {
        let mut s = slot();
        vote_quorum(&mut s, A);
        assert_eq!(s.drive(3), vec![Action::Cer(A)]);
        s.validate(B);
        assert!(s.drive(3).is_empty());
        assert_eq!(s.voted(), None);
        s.validate(A);
        assert_eq!(s.drive(3), vec![Action::Vote(A)]);
        assert_eq!(s.voted(), Some(A));
        assert_eq!(s.terminal(), Terminal::Cer(A));
    }

    #[test]
    fn vote_once_even_when_another_proposal_is_valid() {
        let mut s = slot();
        s.validate(B);
        assert_eq!(s.drive(2), vec![Action::Vote(B)]);
        s.validate(A);
        assert!(s.drive(10).is_empty());
        assert_eq!(s.voted(), Some(B));
    }

    #[test]
    fn finish_prioritizes_cer_and_prefers_vote_proof() {
        let mut s = slot();
        vote_quorum(&mut s, A);
        s.observe_cer(1, A);
        s.observe_cer(2, A);
        assert_eq!(s.finish(3), vec![Action::Cer(A), Action::DirectCommit(A)]);
        assert_eq!(s.terminal(), Terminal::Cer(A));
        assert_eq!(s.proof(), Some(&Trigger::Votes(vec![1, 2, 3])));
        assert!(s.finish(3).is_empty());
    }

    #[test]
    fn earlier_round_rules_remain_enabled() {
        let mut s = slot();
        s.validate(A);
        s.observe_vote(1, A);
        s.observe_vote(2, A);
        assert_eq!(s.drive(100), vec![Action::Vote(A), Action::Cer(A)]);
        assert_eq!(s.terminal(), Terminal::Cer(A));
    }

    #[test]
    fn direct_commit_needs_neither_admission_nor_proposal() {
        let mut s = slot();
        for signer in 1..=3 {
            s.observe_cer(signer, A);
        }
        assert_eq!(s.drive(0), vec![Action::DirectCommit(A)]);
        assert_eq!(s.terminal(), Terminal::Open);
        assert_eq!(s.voted(), None);
        assert_eq!(s.committed(), Some(A));
        assert!(s.drive(0).is_empty());
        assert_eq!(s.drive(3), vec![Action::Cer(A)]);
    }

    #[test]
    #[should_panic(expected = "FinishRound requires")]
    fn finish_rejects_missing_admission() {
        slot().finish(2);
    }

    #[test]
    #[should_panic(expected = "requires n = 3f + 1")]
    fn reject_f_zero() {
        Slot::new(1, 1, 0);
    }

    #[test]
    #[should_panic(expected = "requires n = 3f + 1")]
    fn reject_invalid_membership_size() {
        Slot::new(1, 5, 0);
    }

    #[test]
    #[should_panic(expected = "VOTE signer is not a member")]
    fn reject_unknown_signer() {
        slot().observe_vote(4, A);
    }
}
