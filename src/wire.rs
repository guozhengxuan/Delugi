//! Canonical wire and cryptographic checks for Delugi ordering.
//!
//! The profile uses SHA-256, ordinary Ed25519 signatures, fixed-width integers,
//! little-endian Bincode 1.3 encoding, and an explicit bounded message profile. The wire
//! types contain no maps. Generic encoding helpers must likewise receive ordered
//! canonical structures, never unordered maps. Parsing and verification have no
//! protocol-state side effects; a valid VOTE signature does not validate any
//! attached header/value or authorize voting without a complete valid proposal.

use crate::history::{self, Entries, History, Report};
use bincode::Options;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{HashSet, VecDeque};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub type Digest = [u8; 32];
/// Replica identifiers are zero-based positions in the ordered committee.
pub type Id = u32;

pub const MAX_WIRE_BYTES: usize = 1024 * 1024;
/// Versioned experiment resource envelopes, not limits on protocol heights.
/// The legacy constructor and free encoding helpers retain their original 1 MiB
/// behavior. Larger complete evidence must use the selected committee's helpers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResourceProfile {
    #[default]
    #[serde(rename = "legacy-1mib-v1")]
    Legacy1MibV1,
    #[serde(rename = "complete-32mib-n31-v1")]
    Complete32MibN31V1,
}

impl ResourceProfile {
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Legacy1MibV1 => "legacy-1mib-v1",
            Self::Complete32MibN31V1 => "complete-32mib-n31-v1",
        }
    }

    pub fn max_wire_bytes(self) -> usize {
        match self {
            Self::Legacy1MibV1 => MAX_WIRE_BYTES,
            Self::Complete32MibN31V1 => 32 * 1024 * 1024,
        }
    }

    pub fn max_committee_members(self) -> usize {
        match self {
            // An allocation guard before constructing exact worst-case HISTORY3
            // fixtures; the existing mandatory-frame check is tighter in practice.
            Self::Legacy1MibV1 => 1024,
            Self::Complete32MibN31V1 => 31,
        }
    }
}
/// Leave room for the protocol's `r + 3` indexing without wrapping.
pub const MAX_ROUND: u64 = u64::MAX - 3;
pub const GENESIS_HISTORY_ROUNDS: u64 = 3;
const PROFILE: &str = "delugi/reference/ordering/v3-option-a";
const SIGNATURE_BYTES: usize = 64;
const SIGNATURE_CACHE_ENTRIES: usize = 4096;
const SIGNATURE_CACHE_BYTES: usize = 4 * 1024 * 1024;

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

/// Borrowed layout of `Message`, including every variant in the same order.
/// Used only for bounded sizing, so complete proposal/report guards need no
/// deep clone. Tests compare both its bytes and sizes with every owned variant.
#[derive(Serialize)]
pub(crate) enum MessageRef<'a> {
    Propose(&'a Proposal),
    Vote {
        vote: &'a Signed<Statement>,
        header: &'a Option<Signed<Header>>,
        value: &'a Option<Vec<u8>>,
    },
    Cer(&'a Signed<Statement>),
    Prog(&'a Signed<Statement>),
    Closed(&'a Signed<Statement>),
    History3(&'a Report),
}

impl<'a> From<&'a Message> for MessageRef<'a> {
    fn from(message: &'a Message) -> Self {
        match message {
            Message::Propose(p) => Self::Propose(p),
            Message::Vote {
                vote,
                header,
                value,
            } => Self::Vote {
                vote,
                header,
                value,
            },
            Message::Cer(s) => Self::Cer(s),
            Message::Prog(s) => Self::Prog(s),
            Message::Closed(s) => Self::Closed(s),
            Message::History3(r) => Self::History3(r),
        }
    }
}

fn options() -> impl Options {
    options_with_limit(MAX_WIRE_BYTES)
}

fn options_with_limit(maximum: usize) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(maximum as u64)
        .reject_trailing_bytes()
}

/// Encode ordered canonical structures with the fixed profile and size limit.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    options().serialize(value).map_err(|e| e.to_string())
}

/// The same bounded first pass used by `encode`, without allocating/writing a
/// discarded byte vector. Only use for deterministic derived concrete wire
/// types, not arbitrary serializers whose behavior can differ between passes.
/// Hashing, signing, canonical tie-breaks, and actual output still use `encode`.
pub(crate) fn encoded_size<T: Serialize + ?Sized>(value: &T) -> Result<u64, String> {
    options().serialized_size(value).map_err(|e| e.to_string())
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
    hash_encoded(&encoded)
}

fn hash_encoded(encoded: &[u8]) -> Digest {
    let _cost = crate::meter::measure(crate::meter::Operation::ContentHash);
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
    let signature = {
        let _cost = crate::meter::measure(crate::meter::Operation::signature(T::DOMAIN, true));
        key.sign(&bytes).to_bytes().to_vec()
    };
    Signed {
        signer,
        body,
        signature,
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
#[cfg(test)]
fn input_budget_for_members(n: usize) -> Result<usize, String> {
    input_budget_for_profile(n, MAX_WIRE_BYTES)
}

#[cfg(test)]
mod resource_profile_tests {
    use super::*;

    fn committee(profile: ResourceProfile, n: u32) -> Committee {
        Committee::with_profile(
            [91; 32],
            (0..n).map(|i| fixture_key(i).public).collect(),
            profile,
        )
        .unwrap()
    }

    #[test]
    fn legacy_identity_and_encoding_remain_unchanged() {
        let c = committee(ResourceProfile::Legacy1MibV1, 4);
        let original = (
            "committee-configuration",
            PROFILE,
            "sha256/ed25519-strict/bincode1.3-fixint-little-endian",
            MAX_WIRE_BYTES as u64,
            MAX_ROUND,
            GENESIS_HISTORY_ROUNDS,
            input_budget_for_members(4).unwrap() as u64,
            c.keys.iter().map(|key| key.to_bytes()).collect::<Vec<_>>(),
        );
        assert_eq!(c.context.configuration, hash(&original));
        let message = Message::History3(
            match maximum_control_frames(4).into_iter().last().unwrap() {
                Message::History3(report) => report,
                _ => unreachable!(),
            },
        );
        assert_eq!(c.encode(&message), encode(&message));
        assert_eq!(c.hash(&message), hash(&message));
    }

    #[test]
    fn profiles_are_authenticated_and_committee_allocation_is_bounded() {
        let legacy = committee(ResourceProfile::Legacy1MibV1, 4);
        let complete = committee(ResourceProfile::Complete32MibN31V1, 4);
        assert_ne!(legacy.context.configuration, complete.context.configuration);
        assert_eq!(complete.max_wire_bytes(), 32 * 1024 * 1024);
        assert!(Committee::with_profile(
            [91; 32],
            (0..34).map(|i| fixture_key(i).public).collect(),
            ResourceProfile::Complete32MibN31V1
        )
        .is_err());
        assert!(serde_json::from_str::<ResourceProfile>("\"complete-unbounded\"").is_err());
    }

    #[test]
    fn large_complete_proposal_is_bounded_before_q_and_not_accepted_by_legacy() {
        let c = committee(ResourceProfile::Complete32MibN31V1, 31);
        let value = vec![7; MAX_WIRE_BYTES + 1];
        let witness = vec![8; MAX_WIRE_BYTES + 1];
        let history = History::Empty;
        let proposal = Proposal {
            header: sign(
                &fixture_key(0),
                0,
                Header {
                    context: c.context.clone(),
                    round: 1,
                    value_hash: c.hash(&value),
                    witness_hash: c.hash(&witness),
                    history_hash: c.hash(&history),
                    entries: Entries::empty(),
                },
            ),
            value,
            witness,
            history,
        };
        c.verify_proposal(&proposal, |_, _, _| true).unwrap();
        let digest = proposal_digest(&proposal.header.body);
        let mut cursor = 0;
        let delivered = crate::scanner::release_with_committee(
            &c,
            &std::collections::BTreeMap::from([(1, crate::scanner::Status::Commit(digest))]),
            &std::collections::BTreeMap::from([((1, digest), proposal.header.clone())]),
            &std::collections::BTreeMap::from([((1, digest), proposal.value.clone())]),
            &mut cursor,
        );
        assert_eq!(cursor, 1);
        assert_eq!(delivered[0].value, proposal.value);
        let message = Message::Propose(proposal.clone());
        let encoded = c.encode(&message).unwrap();
        assert!(encoded.len() > MAX_WIRE_BYTES);
        assert!(encode(&message).is_err());
        assert!(decode::<Message>(&encoded).is_err());
        assert!(matches!(
            c.decode::<Message>(&encoded).unwrap(),
            Message::Propose(_)
        ));
        assert!(c.decode::<Message>(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(c.decode::<Message>(&trailing).is_err());
        let mut changed = proposal;
        changed.witness[0] ^= 1;
        let reached_q = std::cell::Cell::new(false);
        assert!(c
            .verify_proposal(&changed, |_, _, _| {
                reached_q.set(true);
                true
            })
            .is_err());
        assert!(!reached_q.get());
    }

    #[test]
    fn largest_history_and_vote_fit_with_maximum_accepted_input() {
        let c = committee(ResourceProfile::Complete32MibN31V1, 31);
        let mut frames = maximum_control_frames(31);
        if let Message::Propose(proposal) = &mut frames[0] {
            proposal.witness.resize(c.input_budget(), 0);
        }
        assert_eq!(
            c.encoded_size(&frames[0]).unwrap() as usize,
            c.max_wire_bytes()
        );
        for message in frames {
            assert!(c.encoded_size(&message).unwrap() as usize <= c.max_wire_bytes());
        }
        assert!(c.validate_input_lengths(c.input_budget(), 1).is_err());
    }
}

fn input_budget_for_profile(n: usize, maximum: usize) -> Result<usize, String> {
    let frames = maximum_control_frames(n);
    let mut overhead = 0;
    for (index, frame) in frames.iter().enumerate() {
        // Disable the limit only while measuring the fixture, so oversized
        // committee configurations can be rejected before any protocol action.
        let bytes = options()
            .with_no_limit()
            .serialized_size(frame)
            .map_err(|e| e.to_string())?;
        if bytes > maximum as u64 {
            return Err("committee mandatory ordering frames exceed the wire limit".into());
        }
        if index < 2 {
            overhead = overhead.max(bytes);
        }
    }
    Ok(maximum - overhead as usize)
}

/// Exact cryptographic inputs, rather than a message digest or protocol object
/// identity. In particular, public committee keys may change on a cloned value.
#[derive(Eq, PartialEq, Hash)]
struct SignatureCacheKey {
    public_key: [u8; 32],
    signer: Id,
    domain: &'static str,
    preimage: Box<[u8]>,
    signature: [u8; SIGNATURE_BYTES],
}

impl SignatureCacheKey {
    fn retained_bytes(&self) -> usize {
        // The domain has static storage. Both indexes share one Arc allocation,
        // so there is exactly one retained preimage per entry. Index/Arc metadata
        // is separately bounded by max_entries; this is a key-byte, not RSS, cap.
        std::mem::size_of::<Self>() + self.preimage.len()
    }
}

struct SignatureCache {
    entries: HashSet<Arc<SignatureCacheKey>>,
    fifo: VecDeque<Arc<SignatureCacheKey>>,
    retained_bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl std::fmt::Debug for SignatureCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureCache")
            .field("entries", &self.entries.len())
            .field("retained_bytes", &self.retained_bytes)
            .finish()
    }
}

impl SignatureCache {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashSet::new(),
            fifo: VecDeque::new(),
            retained_bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    /// Call only after verify_strict succeeds. Concurrent misses may verify the
    /// same key; the second check keeps insertion and byte accounting unique.
    fn insert_verified(&mut self, key: SignatureCacheKey) {
        let bytes = key.retained_bytes();
        if self.max_entries == 0 || bytes > self.max_bytes || self.entries.contains(&key) {
            return;
        }
        while self.entries.len() >= self.max_entries || bytes > self.max_bytes - self.retained_bytes
        {
            let oldest = self.fifo.pop_front().expect("cache indexes agree");
            self.entries.remove(&oldest);
            self.retained_bytes -= oldest.retained_bytes();
        }
        let key = Arc::new(key);
        self.retained_bytes += bytes;
        self.entries.insert(Arc::clone(&key));
        self.fifo.push_back(key);
    }
}

#[derive(Clone, Debug)]
pub struct Committee {
    pub context: Context,
    pub keys: Vec<PublicKey>,
    resource_profile: ResourceProfile,
    input_budget: usize,
    signature_cache: Arc<Mutex<SignatureCache>>,
    #[cfg(test)]
    strict_verifications: Arc<AtomicUsize>,
}

impl Committee {
    pub fn new(instance: Digest, keys: Vec<PublicKey>) -> Result<Self, String> {
        Self::with_profile(instance, keys, ResourceProfile::Legacy1MibV1)
    }

    pub fn with_profile(
        instance: Digest,
        keys: Vec<PublicKey>,
        resource_profile: ResourceProfile,
    ) -> Result<Self, String> {
        let n = keys.len();
        if n < 4 || (n - 1) % 3 != 0 || n > Id::MAX as usize {
            return Err("committee requires n = 3f + 1 >= 4 representable members".into());
        }
        if n > resource_profile.max_committee_members() {
            return Err("committee exceeds the selected resource profile".into());
        }
        let mut ordered_keys = Vec::with_capacity(n);
        for key in &keys {
            let bytes = key.to_bytes();
            if ordered_keys.contains(&bytes) {
                return Err("committee public keys must be distinct".into());
            }
            ordered_keys.push(bytes);
        }
        let input_budget = input_budget_for_profile(n, resource_profile.max_wire_bytes())?;
        // All wire limits, algorithms, the HISTORY3 boundary, the derived input
        // budget, and ordered membership are configuration identity.
        let profile = (
            "committee-configuration",
            PROFILE,
            "sha256/ed25519-strict/bincode1.3-fixint-little-endian",
            resource_profile.max_wire_bytes() as u64,
            MAX_ROUND,
            GENESIS_HISTORY_ROUNDS,
            input_budget as u64,
            ordered_keys,
        );
        encoded_size(&profile)?;
        // Preserve legacy bytes and configuration hashes exactly. New envelopes
        // additionally name their version and committee allocation bound.
        let configuration = if resource_profile == ResourceProfile::Legacy1MibV1 {
            hash(&profile)
        } else {
            hash(&(
                profile,
                resource_profile.identifier(),
                resource_profile.max_committee_members() as u64,
            ))
        };
        Ok(Self {
            context: Context {
                instance,
                configuration,
            },
            keys,
            resource_profile,
            input_budget,
            signature_cache: Arc::new(Mutex::new(SignatureCache::new(
                SIGNATURE_CACHE_ENTRIES,
                SIGNATURE_CACHE_BYTES,
            ))),
            #[cfg(test)]
            strict_verifications: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Maximum combined value and witness bytes reserved by this wire profile.
    /// The budget leaves room for the largest legal HISTORY3 in any round.
    pub fn input_budget(&self) -> usize {
        self.input_budget
    }

    pub fn resource_profile(&self) -> ResourceProfile {
        self.resource_profile
    }

    pub fn max_wire_bytes(&self) -> usize {
        self.resource_profile.max_wire_bytes()
    }

    pub fn encode<T: Serialize>(&self, value: &T) -> Result<Vec<u8>, String> {
        options_with_limit(self.max_wire_bytes())
            .serialize(value)
            .map_err(|e| e.to_string())
    }

    pub fn decode<T: DeserializeOwned>(&self, bytes: &[u8]) -> Result<T, String> {
        if bytes.len() > self.max_wire_bytes() {
            return Err("encoded message exceeds the selected resource profile".into());
        }
        options_with_limit(self.max_wire_bytes())
            .deserialize(bytes)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn encoded_size<T: Serialize + ?Sized>(&self, value: &T) -> Result<u64, String> {
        options_with_limit(self.max_wire_bytes())
            .serialized_size(value)
            .map_err(|e| e.to_string())
    }

    /// Same content domain and canonical bytes as the legacy helper, with this
    /// committee's allocation bound. The configuration digest binds the profile.
    pub fn hash<T: Serialize>(&self, value: &T) -> Digest {
        hash_encoded(
            &self
                .encode(value)
                .expect("hash input must be canonical and bounded"),
        )
    }

    /// Validate locally supplied bytes before fixing the input or hashing it.
    /// Neither early rounds nor smaller histories relax this common limit.
    pub fn validate_input_size(&self, value: &[u8], witness: &[u8]) -> Result<(), String> {
        self.validate_input_lengths(value.len(), witness.len())
    }

    pub(crate) fn validate_input_lengths(
        &self,
        value: usize,
        witness: usize,
    ) -> Result<(), String> {
        match value.checked_add(witness) {
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
        let cache_key = SignatureCacheKey {
            public_key: key.to_bytes(),
            signer: signed.signer,
            domain: T::DOMAIN,
            preimage: signing_bytes(signed.signer, &signed.body)?.into_boxed_slice(),
            signature: signed
                .signature
                .as_slice()
                .try_into()
                .expect("checked length"),
        };
        if self
            .signature_cache
            .lock()
            .map(|cache| cache.entries.contains(&cache_key))
            .unwrap_or(false)
        {
            crate::meter::signature_cache_hit();
            return Ok(());
        }
        // Never hold the cache lock during cryptography. A poisoned cache is
        // bypassed, not trusted; the original strict check still decides.
        #[cfg(test)]
        self.strict_verifications.fetch_add(1, Ordering::Relaxed);
        {
            let _cost = crate::meter::measure(crate::meter::Operation::signature(T::DOMAIN, false));
            key.verify_strict(&cache_key.preimage, &signature)
                .map_err(|_| "invalid Ed25519 signature".to_string())?;
        }
        if let Ok(mut cache) = self.signature_cache.lock() {
            cache.insert_verified(cache_key);
        }
        Ok(())
    }

    /// Check short evidence independently from any VOTE attachments.
    ///
    /// Handlers must additionally require the expected `Kind` for their outer
    /// message variant; moving a valid CER into `Message::Prog` is not a PROG.
    pub fn verify_statement(&self, signed: &Signed<Statement>) -> Result<(), String> {
        encoded_size(signed)?;
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
        encoded_size(signed)?;
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
        self.encoded_size(&MessageRef::Propose(proposal))?;
        self.validate_input_size(&proposal.value, &proposal.witness)?;
        self.verify_header(&proposal.header)?;
        let header = &proposal.header.body;
        if header.value_hash != self.hash(&proposal.value) {
            return Err("proposal value does not match its header".into());
        }
        if header.witness_hash != self.hash(&proposal.witness) {
            return Err("proposal witness does not match its header".into());
        }
        if header.history_hash != self.hash(&proposal.history) {
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

    // Independent reference path: the verifier before caching was introduced.
    fn uncached_signature<T: Serialize + SigningDomain>(
        committee: &Committee,
        signed: &Signed<T>,
    ) -> Result<(), String> {
        let key = committee
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

    fn strict_calls(committee: &Committee) -> usize {
        committee.strict_verifications.load(Ordering::Relaxed)
    }

    fn cache_stats(committee: &Committee) -> (usize, usize) {
        let cache = committee.signature_cache.lock().unwrap();
        assert_eq!(cache.entries.len(), cache.fifo.len());
        assert_eq!(
            cache.retained_bytes,
            cache
                .fifo
                .iter()
                .map(|key| key.retained_bytes())
                .sum::<usize>()
        );
        assert!(cache.entries.len() <= cache.max_entries);
        assert!(cache.retained_bytes <= cache.max_bytes);
        (cache.entries.len(), cache.retained_bytes)
    }

    #[test]
    fn cache_requires_first_strict_check_and_shares_successes_across_clones() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        assert_eq!(strict_calls(&committee), 0); // Signing never seeds the cache.
        assert_eq!(cache_stats(&committee), (0, 0));
        committee.verify_statement(&valid).unwrap();
        assert_eq!(strict_calls(&committee), 1);
        committee.verify_statement(&valid).unwrap();
        committee.clone().verify_statement(&valid).unwrap();
        assert_eq!(strict_calls(&committee), 1);
        assert_eq!(cache_stats(&committee).0, 1);
    }

    #[test]
    fn cached_and_original_strict_verifiers_agree_on_adversarial_corpus() {
        let committee = committee();
        let mut corpus = Vec::new();
        for signer in 0..4 {
            for kind in [Kind::Vote, Kind::Cer, Kind::Prog, Kind::Closed] {
                let mut body = statement(&committee, kind).body;
                body.round = 11 + signer as u64;
                let valid = sign(&fixture_key(signer), signer, body);
                corpus.push(valid.clone());
                let mut changed = valid.clone();
                changed.body.round += 1;
                corpus.push(changed);
                let mut changed = valid.clone();
                changed.body.context.configuration[0] ^= 1;
                corpus.push(changed);
                let mut changed = valid.clone();
                changed.signer = (signer + 1) % 4;
                corpus.push(changed);
                let mut changed = valid.clone();
                changed.signature[0] ^= 1;
                corpus.push(changed);
                for length in [0, 63, 65] {
                    let mut changed = valid.clone();
                    changed.signature.resize(length, 0);
                    corpus.push(changed);
                }
                let mut changed = valid;
                changed.signer = 4;
                corpus.push(changed);
            }
        }
        // The second pass exercises both positive hits and repeated rejections.
        for _ in 0..2 {
            for signed in &corpus {
                assert_eq!(
                    committee.verify_signature(signed),
                    uncached_signature(&committee, signed)
                );
            }
        }
        assert_eq!(cache_stats(&committee).0, 16);
    }

    #[test]
    fn cache_keys_include_actual_public_key_and_signer_after_clone_mutation() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        committee.verify_statement(&valid).unwrap();
        let mut changed_keys = committee.clone();
        changed_keys.keys[0] = fixture_key(9).public;
        assert!(changed_keys.verify_statement(&valid).is_err());
        let replacement = sign(&fixture_key(9), 0, valid.body.clone());
        changed_keys.verify_statement(&replacement).unwrap();
        assert!(committee.verify_statement(&replacement).is_err());
        committee.verify_statement(&valid).unwrap();

        // Even if public fields are mutated into a duplicate-key configuration,
        // the signed reporter binding remains mandatory.
        let mut duplicate_key = committee.clone();
        duplicate_key.keys[1] = duplicate_key.keys[0];
        let mut relabeled = valid;
        relabeled.signer = 1;
        assert!(duplicate_key.verify_statement(&relabeled).is_err());
        assert_eq!(cache_stats(&committee).0, 2);
    }

    #[test]
    fn cached_crypto_never_skips_context_shape_leader_binding_or_q_checks() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        committee.verify_statement(&valid).unwrap();
        let mut changed_context = committee.clone();
        changed_context.context.instance[0] ^= 1;
        changed_context.verify_signature(&valid).unwrap();
        assert!(changed_context.verify_statement(&valid).is_err());
        let mut bad_shape = valid.body.clone();
        bad_shape.digest = None;
        let bad_shape = sign(&fixture_key(0), 0, bad_shape);
        committee.verify_signature(&bad_shape).unwrap();
        assert!(committee.verify_statement(&bad_shape).is_err());

        let mut header = proposal(&committee, 5).header.body;
        header.entries.horizon = 2;
        let header = sign(&fixture_key(0), 0, header);
        committee.verify_header(&header).unwrap();
        let mut missing_history = proposal(&committee, 5);
        missing_history.header = header.clone();
        assert!(committee
            .verify_proposal(&missing_history, |_, _, _| {
                panic!("a cached leader signature does not validate HISTORY3")
            })
            .is_err());
        let mut changed_membership = committee.clone();
        changed_membership
            .keys
            .extend((4..7).map(|id| fixture_key(id).public));
        changed_membership.verify_signature(&header).unwrap();
        assert!(changed_membership.verify_header(&header).is_err());

        let valid = proposal(&committee, 1);
        committee.verify_proposal(&valid, |_, _, _| true).unwrap();
        let calls = Cell::new(0);
        assert!(committee
            .verify_proposal(&valid, |_, _, _| {
                calls.set(calls.get() + 1);
                false
            })
            .is_err());
        assert_eq!(calls.get(), 1);
        let mut changed_value = valid.clone();
        changed_value.value.push(0);
        let mut changed_witness = valid;
        changed_witness.witness.push(0);
        for changed in [changed_value, changed_witness] {
            assert!(committee
                .verify_proposal(&changed, |_, _, _| {
                    panic!("Q must follow complete binding checks")
                })
                .is_err());
        }
    }

    #[test]
    fn failed_signatures_never_populate_or_evict_a_cached_success() {
        let mut committee = committee();
        committee.signature_cache = Arc::new(Mutex::new(SignatureCache::new(1, 4096)));
        let valid = statement(&committee, Kind::Cer);
        committee.verify_statement(&valid).unwrap();
        let before = cache_stats(&committee);
        let mut invalid = valid.clone();
        invalid.signature[0] ^= 1;
        for _ in 0..4 {
            assert!(committee.verify_statement(&invalid).is_err());
            assert_eq!(cache_stats(&committee), before);
        }
        assert_eq!(strict_calls(&committee), 5);
        committee.verify_statement(&valid).unwrap();
        assert_eq!(strict_calls(&committee), 5);
    }

    #[test]
    fn cache_is_fifo_and_bounded_by_entries_and_retained_key_bytes() {
        let mut committee = committee();
        let signed: Vec<_> = (1..=4)
            .map(|round| {
                let mut body = statement(&committee, Kind::Vote).body;
                body.round = round;
                sign(&fixture_key(0), 0, body)
            })
            .collect();
        committee.verify_statement(&signed[0]).unwrap();
        let entry_bytes = cache_stats(&committee).1;
        for (entries, bytes) in [(2, 4096), (4096, 2 * entry_bytes)] {
            committee.signature_cache = Arc::new(Mutex::new(SignatureCache::new(entries, bytes)));
            committee.verify_statement(&signed[0]).unwrap();
            committee.verify_statement(&signed[1]).unwrap();
            committee.verify_statement(&signed[0]).unwrap(); // Hit does not change FIFO.
            committee.verify_statement(&signed[2]).unwrap();
            assert_eq!(cache_stats(&committee), (2, 2 * entry_bytes));
            let before = strict_calls(&committee);
            committee.verify_statement(&signed[1]).unwrap();
            assert_eq!(strict_calls(&committee), before);
            committee.verify_statement(&signed[0]).unwrap();
            assert_eq!(strict_calls(&committee), before + 1);
            assert_eq!(cache_stats(&committee), (2, 2 * entry_bytes));
        }
        // A single oversized key and a disabled cache both preserve strict checks.
        for (entries, bytes) in [(4096, entry_bytes - 1), (0, 4096)] {
            committee.signature_cache = Arc::new(Mutex::new(SignatureCache::new(entries, bytes)));
            let before = strict_calls(&committee);
            for _ in 0..2 {
                committee.verify_statement(&signed[0]).unwrap();
            }
            assert_eq!(strict_calls(&committee), before + 2);
            assert_eq!(cache_stats(&committee), (0, 0));
        }
    }

    #[test]
    fn cache_handles_concurrent_misses_and_warmed_clone_hits() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let committee = committee.clone();
                let valid = valid.clone();
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    barrier.wait();
                    committee.verify_statement(&valid).unwrap();
                });
            }
        });
        assert!((1..=8).contains(&strict_calls(&committee)));
        assert_eq!(cache_stats(&committee).0, 1);
        let before = strict_calls(&committee);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let committee = committee.clone();
                let valid = &valid;
                scope.spawn(move || {
                    for _ in 0..8 {
                        committee.verify_statement(valid).unwrap();
                    }
                });
            }
        });
        assert_eq!(strict_calls(&committee), before);
        assert_eq!(cache_stats(&committee).0, 1);
    }

    #[test]
    fn poisoned_cache_falls_back_to_strict_for_successes_and_failures() {
        let committee = committee();
        let valid = statement(&committee, Kind::Vote);
        committee.verify_statement(&valid).unwrap();
        let cache = Arc::clone(&committee.signature_cache);
        assert!(std::thread::spawn(move || {
            let _guard = cache.lock().unwrap();
            panic!("deliberate cache poison");
        })
        .join()
        .is_err());
        for _ in 0..2 {
            committee.verify_statement(&valid).unwrap();
        }
        let mut invalid = valid;
        invalid.signature[0] ^= 1;
        assert!(committee.verify_statement(&invalid).is_err());
        assert_eq!(strict_calls(&committee), 4);
        assert!(committee.signature_cache.lock().is_err());
    }

    #[test]
    fn oversized_signing_preimage_is_rejected_before_cache_or_crypto() {
        #[derive(Serialize)]
        struct Blob(Vec<u8>);
        impl SigningDomain for Blob {
            const DOMAIN: &'static str = "cache-size-test";
        }
        let committee = committee();
        let signed = Signed {
            signer: 0,
            body: Blob(vec![0; MAX_WIRE_BYTES]),
            signature: statement(&committee, Kind::Vote).signature,
        };
        assert_eq!(
            committee.verify_signature(&signed),
            uncached_signature(&committee, &signed)
        );
        assert!(committee.verify_signature(&signed).is_err());
        assert_eq!(strict_calls(&committee), 0);
        assert_eq!(cache_stats(&committee), (0, 0));
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

    fn assert_size_matches_encoding<T: Serialize>(value: &T) {
        assert_eq!(
            encoded_size(value),
            encode(value).map(|bytes| bytes.len() as u64)
        );
    }

    #[test]
    fn borrowed_message_sizes_and_bytes_match_every_owned_variant_and_nested_limit() {
        let c = committee();
        let mut messages = maximum_control_frames(4).to_vec();
        messages.extend([
            Message::Propose(proposal(&c, 1)),
            Message::Vote {
                vote: statement(&c, Kind::Vote),
                header: None,
                value: None,
            },
            Message::Cer(statement(&c, Kind::Cer)),
            Message::Prog(statement(&c, Kind::Prog)),
            Message::Closed(statement(&c, Kind::Closed)),
        ]);
        let original = proposal(&c, 1);
        let overhead =
            encode(&Message::Propose(original.clone())).unwrap().len() - original.value.len();
        for length in [
            MAX_WIRE_BYTES - overhead - 1,
            MAX_WIRE_BYTES - overhead,
            MAX_WIRE_BYTES - overhead + 1,
        ] {
            let mut p = original.clone();
            p.value = vec![0; length];
            messages.push(Message::Propose(p));
        }
        let Message::History3(mut oversized) = maximum_control_frames(4)[2].clone() else {
            unreachable!()
        };
        oversized.proofs[1].triggers[0].signature = vec![0; MAX_WIRE_BYTES];
        assert_size_matches_encoding(&oversized);
        assert_size_matches_encoding(&oversized.proofs[1]);
        messages.push(Message::History3(oversized));
        for message in messages {
            let borrowed = MessageRef::from(&message);
            let encoded = encode(&message);
            assert_eq!(encode(&borrowed), encoded);
            assert_eq!(
                encoded_size(&borrowed),
                encoded.map(|bytes| bytes.len() as u64)
            );
            assert_size_matches_encoding(&message);
            match message {
                Message::Propose(p) => {
                    assert_size_matches_encoding(&p.header);
                    assert_size_matches_encoding(&p.history);
                }
                Message::History3(r) => {
                    assert_size_matches_encoding(&r.header);
                    for proof in r.proofs {
                        assert_size_matches_encoding(&proof);
                    }
                }
                _ => {}
            }
        }
        let mut short = statement(&c, Kind::Vote);
        assert_size_matches_encoding(&short);
        short.signature = vec![0; MAX_WIRE_BYTES];
        let old_error = encode(&short).unwrap_err();
        assert_eq!(c.verify_statement(&short), Err(old_error));
        let mut header = original.header;
        header.signature = vec![0; MAX_WIRE_BYTES];
        let old_error = encode(&header).unwrap_err();
        assert_eq!(c.verify_header(&header), Err(old_error));
    }

    #[test]
    fn bounded_sizing_matches_encoding_errors_and_preserves_input_guard_order() {
        for length in [
            0,
            MAX_WIRE_BYTES - 9,
            MAX_WIRE_BYTES - 8,
            MAX_WIRE_BYTES - 7,
            MAX_WIRE_BYTES,
        ] {
            assert_size_matches_encoding(&vec![0u8; length]);
        }
        let c = committee();
        for (x, pi) in [
            (0, 0),
            (c.input_budget(), 0),
            (c.input_budget() - 1, 1),
            (c.input_budget(), 1),
        ] {
            assert_eq!(
                c.validate_input_lengths(x, pi),
                c.validate_input_size(&vec![0; x], &vec![0; pi])
            );
        }
        let mut p = proposal(&c, 1);
        p.value = vec![0; MAX_WIRE_BYTES];
        let original_guard = encode(&Message::Propose(p.clone())).map(|_| ());
        assert!(original_guard.is_err());
        assert_eq!(
            c.verify_proposal(&p, |_, _, _| panic!("size must reject before Q")),
            original_guard
        );
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
        committee.verify_signature(&other).unwrap();
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
        committee.verify_header(&proposal.header).unwrap();
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
