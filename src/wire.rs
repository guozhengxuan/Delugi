//! Canonical wire and cryptographic checks for Delugi ordering.
//!
//! The profile uses SHA-256, ordinary Ed25519 signatures, fixed-width integers,
//! little-endian Bincode 1.3 encoding, and a 1 MiB encoded-message limit. The wire
//! types contain no maps. Generic encoding helpers must likewise receive ordered
//! canonical structures, never unordered maps. Parsing and verification have no
//! protocol-state side effects; a valid VOTE signature does not validate any
//! attached header/value or authorize voting without a complete valid proposal.

use crate::history::{self, Entries, History, Report};
use bincode::Options;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

pub type Digest = [u8; 32];
/// Replica identifiers are zero-based positions in the ordered committee.
pub type Id = u32;

pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
/// Leave room for the protocol's `r + 3` indexing without wrapping.
pub const MAX_ROUND: u64 = u64::MAX - 3;
pub const GENESIS_HISTORY_ROUNDS: u64 = 3;
const PROFILE: &str = "delugi/reference/ordering/v2";
const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Context {
    pub instance: Digest,
    pub configuration: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Kind {
    Vote,
    Cer,
    Prog,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    pub context: Context,
    pub kind: Kind,
    pub round: u64,
    pub digest: Option<Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub context: Context,
    pub round: u64,
    pub value_hash: Digest,
    pub witness_hash: Digest,
    pub history_hash: Digest,
    pub entries: Entries,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub signer: Id,
    pub body: T,
    pub signature: Vec<u8>,
}

/// A complete proposal binds its full history and exact decision projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub header: Signed<Header>,
    pub value: Vec<u8>,
    pub witness: Vec<u8>,
    pub history: History,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Propose(Proposal),
    Vote {
        vote: Signed<Statement>,
        header: Option<Signed<Header>>,
        value: Option<Vec<u8>>,
    },
    Cer(Signed<Statement>),
    Prog(Signed<Statement>),
    Closed(Signed<Statement>),
    History3(Report),
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_WIRE_BYTES as u64)
        .reject_trailing_bytes()
}

/// Encode ordered canonical structures with the fixed profile and size limit.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    options().serialize(value).map_err(|e| e.to_string())
}

/// Reject malformed encodings, trailing bytes, and oversized complete messages.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err("encoded message exceeds the 1 MiB limit".into());
    }
    options().deserialize(bytes).map_err(|e| e.to_string())
}

/// Hash a canonical, bounded, serializable value with an explicit profile domain.
///
/// Like `sign`, this constructor expects trusted, already bounded local values.
/// Network verifiers check encoded sizes before invoking it. Unsupported custom
/// serializers and oversized local inputs are programmer errors and panic.
pub fn hash<T: Serialize>(value: &T) -> Digest {
    let encoded = encode(value).expect("hash input must be canonical and bounded");
    let mut hasher = Sha256::new();
    hasher.update(PROFILE.as_bytes());
    hasher.update(b"\0content-hash\0");
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

/// Proposal identity depends on the canonical header, never signature bytes.
pub fn proposal_digest(header: &Header) -> Digest {
    hash(&("proposal-header", header))
}

pub fn empty_history_hash() -> Digest {
    hash(&History::Empty)
}

/// Stable wire roles for signing; Rust type names are never part of the wire.
pub trait SigningDomain {
    const DOMAIN: &'static str;
}

impl SigningDomain for Header {
    const DOMAIN: &'static str = "leader-header";
}

impl SigningDomain for Statement {
    const DOMAIN: &'static str = "ordering-statement";
}

fn signing_bytes<T: Serialize + SigningDomain>(signer: Id, body: &T) -> Result<Vec<u8>, String> {
    // Binding the reporter explicitly prevents relabeling even in a badly
    // configured system; Committee::new also rejects duplicate public keys.
    encode(&(PROFILE, "signature", T::DOMAIN, signer, body))
}

/// Sign a trusted local header/statement; this does not validate its semantics.
pub fn sign<T: Serialize + Clone + SigningDomain>(key: &Keypair, signer: Id, body: T) -> Signed<T> {
    let bytes = signing_bytes(signer, &body).expect("signed input must be bounded");
    Signed {
        signer,
        body,
        signature: key.sign(&bytes).to_bytes().to_vec(),
    }
}

/// Deterministic **public test seed**. Never use these keys for a deployment.
///
/// Anyone can recover every private key this helper produces. It exists only to
/// make local reference traces and regression tests reproducible.
pub fn fixture_key(id: Id) -> Keypair {
    let seed = hash(&("PUBLIC-INSECURE-TEST-KEY", id));
    let secret = SecretKey::from_bytes(&seed).expect("32-byte test seed");
    let public = PublicKey::from(&secret);
    Keypair { secret, public }
}

/// Size fixtures use the real wire types and encoding, with fixed-length dummy
/// signatures. Cryptographic validity is irrelevant to their exact frame size.
/// Round 6 permits the structural maximum: three positive positions in each
/// report, a pivot proof, and two positive predecessor proofs. VOTE triggers
/// (n-f) are larger than CER triggers (f+1), so they bound either proof form.
fn maximum_control_frames(n: usize) -> [Message; 3] {
    let quorum = n - (n - 1) / 3;
    let context = Context {
        instance: [0; 32],
        configuration: [0; 32],
    };
    let signed_statement = |signer, kind, round| Signed {
        signer,
        body: Statement {
            context: context.clone(),
            kind,
            round,
            digest: Some([0; 32]),
        },
        signature: vec![0; SIGNATURE_BYTES],
    };
    let proof_at = |round| history::CerProof {
        cer: signed_statement(0, Kind::Cer, round),
        triggers: (0..quorum)
            .map(|id| signed_statement(id as Id, Kind::Vote, round))
            .collect(),
    };
    let reports: Vec<_> = (0..quorum)
        .map(|id| Signed {
            signer: id as Id,
            body: history::ReportHeader {
                context: context.clone(),
                horizon: 3,
                positives: vec![(3, [0; 32]), (2, [0; 32]), (1, [0; 32])],
            },
            signature: vec![0; SIGNATURE_BYTES],
        })
        .collect();
    let report = Report {
        header: reports[0].clone(),
        proofs: vec![proof_at(3), proof_at(2), proof_at(1)],
    };
    let history = History::Evidence {
        reports,
        pivot: 3,
        proof: Some(proof_at(3)),
        previous: vec![(1, Some(proof_at(1))), (2, Some(proof_at(2)))],
    };
    let header = Signed {
        signer: (5 % n) as Id,
        body: Header {
            context,
            round: 6,
            value_hash: [0; 32],
            witness_hash: [0; 32],
            history_hash: [0; 32],
            entries: history::project(6, &history),
        },
        signature: vec![0; SIGNATURE_BYTES],
    };
    let vote = Message::Vote {
        vote: Signed {
            signer: 0,
            body: Statement {
                context: header.body.context.clone(),
                kind: Kind::Vote,
                round: 6,
                digest: Some([0; 32]),
            },
            signature: vec![0; SIGNATURE_BYTES],
        },
        header: Some(header.clone()),
        value: Some(Vec::new()),
    };
    let proposal = Message::Propose(Proposal {
        header,
        value: Vec::new(),
        witness: Vec::new(),
        history,
    });
    [proposal, vote, Message::History3(report)]
}

/// Reserve enough bytes that *every* legal history, report, and VOTE still fits
/// with the accepted application input. Fixed-width vector lengths make each
/// added input byte contribute exactly one encoded byte to its enclosing frame.
fn input_budget_for_members(n: usize) -> Result<usize, String> {
    let frames = maximum_control_frames(n);
    let mut overhead = 0;
    for (index, frame) in frames.iter().enumerate() {
        // Disable the limit only while measuring the fixture, so oversized
        // committee configurations can be rejected before any protocol action.
        let bytes = options()
            .with_no_limit()
            .serialized_size(frame)
            .map_err(|e| e.to_string())?;
        if bytes > MAX_WIRE_BYTES as u64 {
            return Err("committee mandatory ordering frames exceed the wire limit".into());
        }
        if index < 2 {
            overhead = overhead.max(bytes);
        }
    }
    Ok(MAX_WIRE_BYTES - overhead as usize)
}

#[derive(Clone, Debug)]
pub struct Committee {
    pub context: Context,
    pub keys: Vec<PublicKey>,
    input_budget: usize,
}

impl Committee {
    pub fn new(instance: Digest, keys: Vec<PublicKey>) -> Result<Self, String> {
        let n = keys.len();
        if n < 4 || (n - 1) % 3 != 0 || n > Id::MAX as usize {
            return Err("committee requires n = 3f + 1 >= 4 representable members".into());
        }
        let mut ordered_keys = Vec::with_capacity(n);
        for key in &keys {
            let bytes = key.to_bytes();
            if ordered_keys.contains(&bytes) {
                return Err("committee public keys must be distinct".into());
            }
            ordered_keys.push(bytes);
        }
        let input_budget = input_budget_for_members(n)?;
        // All wire limits, algorithms, the HISTORY3 boundary, the derived input
        // budget, and ordered membership are configuration identity.
        let profile = (
            "committee-configuration",
            PROFILE,
            "sha256/ed25519-strict/bincode1.3-fixint-little-endian",
            MAX_WIRE_BYTES as u64,
            MAX_ROUND,
            GENESIS_HISTORY_ROUNDS,
            input_budget as u64,
            ordered_keys,
        );
        encode(&profile)?;
        Ok(Self {
            context: Context {
                instance,
                configuration: hash(&profile),
            },
            keys,
            input_budget,
        })
    }

    /// Maximum combined value and witness bytes reserved by this wire profile.
    /// The budget leaves room for the largest legal HISTORY3 in any round.
    pub fn input_budget(&self) -> usize {
        self.input_budget
    }

    /// Validate locally supplied bytes before fixing the input or hashing it.
    /// Neither early rounds nor smaller histories relax this common limit.
    pub fn validate_input_size(&self, value: &[u8], witness: &[u8]) -> Result<(), String> {
        match value.len().checked_add(witness.len()) {
            Some(bytes) if bytes <= self.input_budget => Ok(()),
            _ => Err("combined value and witness exceed the committee input budget".into()),
        }
    }

    pub(crate) fn verify_signature<T: Serialize + SigningDomain>(
        &self,
        signed: &Signed<T>,
    ) -> Result<(), String> {
        let key = self
            .keys
            .get(signed.signer as usize)
            .ok_or("signature signer is not a committee member")?;
        if signed.signature.len() != SIGNATURE_BYTES {
            return Err("Ed25519 signature must contain exactly 64 bytes".into());
        }
        let signature = Signature::from_bytes(&signed.signature).map_err(|e| e.to_string())?;
        let bytes = signing_bytes(signed.signer, &signed.body)?;
        key.verify_strict(&bytes, &signature)
            .map_err(|_| "invalid Ed25519 signature".into())
    }

    /// Check short evidence independently from any VOTE attachments.
    ///
    /// Handlers must additionally require the expected `Kind` for their outer
    /// message variant; moving a valid CER into `Message::Prog` is not a PROG.
    pub fn verify_statement(&self, signed: &Signed<Statement>) -> Result<(), String> {
        encode(signed)?;
        let body = &signed.body;
        if body.context != self.context {
            return Err("statement instance or configuration mismatch".into());
        }
        if body.round == 0 || body.round > MAX_ROUND {
            return Err("statement round is outside the supported positive range".into());
        }
        let expects_digest = matches!(body.kind, Kind::Vote | Kind::Cer);
        if body.digest.is_some() != expects_digest {
            return Err("statement digest shape does not match its kind".into());
        }
        self.verify_signature(signed)
    }

    /// Verify the leader header and projection shape, without inferring full
    /// history or Q validity from the leader signature alone.
    pub fn verify_header(&self, signed: &Signed<Header>) -> Result<(), String> {
        encode(signed)?;
        let body = &signed.body;
        if body.context != self.context {
            return Err("header instance or configuration mismatch".into());
        }
        if body.round == 0 || body.round > MAX_ROUND {
            return Err("header round is outside the supported positive range".into());
        }
        history::verify_entries(body.round, &body.entries)?;
        if self.keys.is_empty() {
            return Err("empty committee".into());
        }
        let leader = ((body.round - 1) % self.keys.len() as u64) as Id;
        if signed.signer != leader {
            return Err("header signer is not the round-robin leader".into());
        }
        if body.round <= GENESIS_HISTORY_ROUNDS && body.history_hash != empty_history_hash() {
            return Err("genesis proposal must bind the unique empty history".into());
        }
        self.verify_signature(signed)
    }

    /// Validate all complete-proposal bindings before evaluating immutable Q.
    ///
    /// `q` must be a common total deterministic predicate of these inputs only.
    pub fn verify_proposal(
        &self,
        proposal: &Proposal,
        q: impl Fn(u64, &[u8], &[u8]) -> bool,
    ) -> Result<(), String> {
        // Include the outer message discriminator in the total frame budget.
        encode(&Message::Propose(proposal.clone()))?;
        self.validate_input_size(&proposal.value, &proposal.witness)?;
        self.verify_header(&proposal.header)?;
        let header = &proposal.header.body;
        if header.value_hash != hash(&proposal.value) {
            return Err("proposal value does not match its header".into());
        }
        if header.witness_hash != hash(&proposal.witness) {
            return Err("proposal witness does not match its header".into());
        }
        if header.history_hash != hash(&proposal.history) {
            return Err("proposal history does not match its header".into());
        }
        history::verify_history(self, header.round, &proposal.history)?;
        if header.entries != history::project(header.round, &proposal.history) {
            return Err("proposal decision entries do not match its history".into());
        }
        if !q(header.round, &proposal.value, &proposal.witness) {
            return Err("external predicate Q rejected proposal".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn committee() -> Committee {
        Committee::new([7; 32], (0..4).map(|i| fixture_key(i).public).collect()).unwrap()
    }

    fn proposal(committee: &Committee, round: u64) -> Proposal {
        let value = b"test-value".to_vec();
        let witness = b"test-witness".to_vec();
        let leader = ((round - 1) % committee.keys.len() as u64) as Id;
        Proposal {
            header: sign(
                &fixture_key(leader),
                leader,
                Header {
                    context: committee.context.clone(),
                    round,
                    value_hash: hash(&value),
                    witness_hash: hash(&witness),
                    history_hash: empty_history_hash(),
                    entries: Entries::empty(),
                },
            ),
            value,
            witness,
            history: History::Empty,
        }
    }

    fn statement(committee: &Committee, kind: Kind) -> Signed<Statement> {
        sign(
            &fixture_key(0),
            0,
            Statement {
                context: committee.context.clone(),
                kind,
                round: 1,
                digest: matches!(kind, Kind::Vote | Kind::Cer).then_some([8; 32]),
            },
        )
    }

    #[test]
    fn canonical_encoding_is_fixed_little_endian_and_strict() {
        assert_eq!(encode(&0x0102_0304u32).unwrap(), vec![4, 3, 2, 1]);
        assert_eq!(encode(&vec![9u8]).unwrap(), vec![1, 0, 0, 0, 0, 0, 0, 0, 9]);
        assert!(decode::<u32>(&[4, 3, 2]).is_err());
        assert!(decode::<u32>(&[4, 3, 2, 1, 0]).is_err());
        assert!(decode::<Message>(&[255, 255, 255, 255]).is_err());
        assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn total_size_limit_applies_to_encoding_and_decoding() {
        assert!(encode(&vec![0u8; MAX_WIRE_BYTES]).is_err());
        assert!(decode::<Vec<u8>>(&vec![0u8; MAX_WIRE_BYTES + 1]).is_err());
        let at_limit = vec![0u8; MAX_WIRE_BYTES - 8];
        assert_eq!(encode(&at_limit).unwrap().len(), MAX_WIRE_BYTES);
    }

    #[test]
    fn committee_binds_ordered_distinct_membership_and_profile() {
        let keys: Vec<_> = (0..4).map(|i| fixture_key(i).public).collect();
        for n in [0, 1, 2, 3, 5, 6] {
            let members = (0..n).map(|i| fixture_key(i).public).collect();
            assert!(Committee::new([7; 32], members).is_err());
        }
        let mut duplicate = keys.clone();
        duplicate[3] = duplicate[0];
        assert!(Committee::new([7; 32], duplicate).is_err());
        let original = Committee::new([7; 32], keys.clone()).unwrap();
        let mut reversed = keys;
        reversed.reverse();
        let reordered = Committee::new([7; 32], reversed).unwrap();
        assert_ne!(
            original.context.configuration,
            reordered.context.configuration
        );
        assert!(Committee::new([7; 32], (0..7).map(|i| fixture_key(i).public).collect()).is_ok());
    }

    #[test]
    fn exact_frame_budget_reserves_complete_history_and_checks_combined_input() {
        for n in [4, 7] {
            let committee =
                Committee::new([7; 32], (0..n).map(|i| fixture_key(i).public).collect()).unwrap();
            let budget = committee.input_budget();
            assert!(budget < MAX_WIRE_BYTES);
            let value = vec![0; budget / 2];
            let mut witness = vec![0; budget - value.len()];
            committee.validate_input_size(&value, &witness).unwrap();
            witness.push(0);
            assert!(value.len() < budget && witness.len() < budget);
            assert!(committee.validate_input_size(&value, &witness).is_err());
            assert!(committee
                .validate_input_size(&vec![0; MAX_WIRE_BYTES], &[])
                .is_err());

            let mut frames = maximum_control_frames(n as usize);
            if let Message::Propose(p) = &mut frames[0] {
                p.value = value;
                witness.pop();
                p.witness = witness;
            }
            if let Message::Vote { value, .. } = &mut frames[1] {
                *value = Some(vec![0; budget]);
            }
            assert_eq!(encode(&frames[0]).unwrap().len(), MAX_WIRE_BYTES);
            assert!(encode(&frames[1]).unwrap().len() <= MAX_WIRE_BYTES);
            assert!(encode(&frames[2]).unwrap().len() <= MAX_WIRE_BYTES);
            if let Message::Propose(p) = &mut frames[0] {
                p.value.push(0);
            }
            assert!(encode(&frames[0]).is_err());
        }
    }

    #[test]
    fn oversized_mandatory_committee_frames_are_rejected() {
        // Exercise the exact same size check called by Committee::new without
        // generating thousands of keys merely to measure fixed-size signatures.
        assert!(input_budget_for_members(3001).is_err());
        let frames = maximum_control_frames(3001);
        assert!(
            options()
                .with_no_limit()
                .serialized_size(&frames[2])
                .unwrap()
                > MAX_WIRE_BYTES as u64
        );
    }

    #[test]
    fn proposal_roundtrip_and_q_validation() {
        let committee = committee();
        for round in 1..=3 {
            let proposal = proposal(&committee, round);
            let message = Message::Propose(proposal.clone());
            let bytes = encode(&message).unwrap();
            assert_eq!(decode::<Message>(&bytes).unwrap(), message);
            committee
                .verify_proposal(&proposal, |r, x, pi| {
                    r == round && x == b"test-value" && pi == b"test-witness"
                })
                .unwrap();
            assert!(committee
                .verify_proposal(&proposal, |_, _, _| false)
                .is_err());
        }
    }

    #[test]
    fn tampered_proposal_parts_are_rejected_before_q() {
        let committee = committee();
        let valid = proposal(&committee, 1);
        let mut cases = Vec::new();
        let mut changed = valid.clone();
        changed.header.signature[0] ^= 1;
        cases.push(changed);
        let mut changed = valid.clone();
        changed.header.body.value_hash[0] ^= 1;
        cases.push(changed);
        let mut changed = valid.clone();
        changed.value[0] ^= 1;
        cases.push(changed);
        let mut changed = valid.clone();
        changed.witness[0] ^= 1;
        cases.push(changed);
        let mut changed = valid;
        changed.header.body.history_hash[0] ^= 1;
        changed.header = sign(&fixture_key(0), 0, changed.header.body);
        cases.push(changed);
        for changed in cases {
            let q_calls = Cell::new(0);
            assert!(committee
                .verify_proposal(&changed, |_, _, _| {
                    q_calls.set(q_calls.get() + 1);
                    true
                })
                .is_err());
            assert_eq!(q_calls.get(), 0);
        }
    }

    #[test]
    fn oversized_in_memory_proposal_is_rejected_without_hashing_or_q() {
        let committee = committee();
        let mut proposal = proposal(&committee, 1);
        proposal.value = vec![0; MAX_WIRE_BYTES];
        assert!(committee
            .verify_proposal(&proposal, |_, _, _| panic!("Q must not run"))
            .is_err());
    }

    #[test]
    fn wrong_leader_and_missing_later_history_are_rejected() {
        let committee = committee();
        let mut wrong_leader = proposal(&committee, 1);
        wrong_leader.header = sign(&fixture_key(1), 1, wrong_leader.header.body);
        assert!(committee.verify_header(&wrong_leader.header).is_err());
        let later = proposal(&committee, 4);
        assert!(committee.verify_header(&later.header).is_err());
        assert!(committee.verify_proposal(&later, |_, _, _| true).is_err());
        let mut zero = proposal(&committee, 1);
        zero.header.body.round = 0;
        zero.header = sign(&fixture_key(0), 0, zero.header.body);
        assert!(committee.verify_header(&zero.header).is_err());
    }

    #[test]
    fn all_statement_kinds_validate_without_attachments() {
        let committee = committee();
        for kind in [Kind::Vote, Kind::Cer, Kind::Prog, Kind::Closed] {
            committee
                .verify_statement(&statement(&committee, kind))
                .unwrap();
        }
        let vote = statement(&committee, Kind::Vote);
        let packet = Message::Vote {
            vote: vote.clone(),
            header: None,
            value: None,
        };
        assert_eq!(
            decode::<Message>(&encode(&packet).unwrap()).unwrap(),
            packet
        );
        committee.verify_statement(&vote).unwrap();
    }

    #[test]
    fn statement_shape_and_round_boundaries_are_checked_even_when_signed() {
        let committee = committee();
        for kind in [Kind::Vote, Kind::Cer, Kind::Prog, Kind::Closed] {
            let mut body = statement(&committee, kind).body;
            body.digest = if body.digest.is_some() {
                None
            } else {
                Some([1; 32])
            };
            assert!(committee
                .verify_statement(&sign(&fixture_key(0), 0, body))
                .is_err());
        }
        for round in [0, MAX_ROUND + 1, u64::MAX] {
            let mut body = statement(&committee, Kind::Prog).body;
            body.round = round;
            assert!(committee
                .verify_statement(&sign(&fixture_key(0), 0, body))
                .is_err());
        }
        for round in [4, MAX_ROUND] {
            let mut body = statement(&committee, Kind::Prog).body;
            body.round = round;
            committee
                .verify_statement(&sign(&fixture_key(0), 0, body))
                .unwrap();
        }
    }

    #[test]
    fn cross_instance_configuration_kind_and_reporter_replays_fail() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        let mut other_instance = committee.clone();
        other_instance.context.instance[0] ^= 1;
        assert!(other_instance.verify_statement(&valid).is_err());
        let mut other_configuration = committee.clone();
        other_configuration.context.configuration[0] ^= 1;
        assert!(other_configuration.verify_statement(&valid).is_err());
        let mut other_kind = valid.clone();
        other_kind.body.kind = Kind::Cer;
        assert!(committee.verify_statement(&other_kind).is_err());
        let mut other_reporter = valid.clone();
        other_reporter.signer = 1;
        assert!(committee.verify_statement(&other_reporter).is_err());
        let mut nonmember = valid;
        nonmember.signer = 4;
        assert!(committee.verify_statement(&nonmember).is_err());
        let valid_proposal = proposal(&committee, 1);
        assert!(other_instance
            .verify_header(&valid_proposal.header)
            .is_err());
        assert!(other_configuration
            .verify_header(&valid_proposal.header)
            .is_err());
    }

    #[test]
    fn type_domain_prevents_same_layout_signature_reuse() {
        #[derive(Clone, Serialize)]
        struct DifferentRole(Statement);
        impl SigningDomain for DifferentRole {
            const DOMAIN: &'static str = "some-other-protocol-role";
        }
        let committee = committee();
        let body = statement(&committee, Kind::Vote).body;
        let other = sign(&fixture_key(0), 0, DifferentRole(body.clone()));
        assert_eq!(encode(&other.body).unwrap(), encode(&body).unwrap());
        let reused = Signed {
            signer: 0,
            body,
            signature: other.signature,
        };
        assert!(committee.verify_statement(&reused).is_err());
    }

    #[test]
    fn signature_length_and_tampering_fail() {
        let committee = committee();
        for length in [0, 63, 65] {
            let mut bad = statement(&committee, Kind::Cer);
            bad.signature.resize(length, 0);
            assert!(committee.verify_statement(&bad).is_err());
        }
        let mut bad = statement(&committee, Kind::Cer);
        bad.signature[0] ^= 1;
        assert!(committee.verify_statement(&bad).is_err());
    }

    #[test]
    fn proposal_digest_excludes_signature_bytes() {
        let committee = committee();
        let proposal = proposal(&committee, 1);
        let digest = proposal_digest(&proposal.header.body);
        let mut changed_signature = proposal.header.clone();
        changed_signature.signature.fill(0);
        assert_eq!(digest, proposal_digest(&changed_signature.body));
        assert!(committee.verify_header(&changed_signature).is_err());
        let mut changed_header = proposal.header.body;
        changed_header.witness_hash[0] ^= 1;
        assert_ne!(digest, proposal_digest(&changed_header));
        assert_eq!(hash(&History::Empty), empty_history_hash());
    }
}
