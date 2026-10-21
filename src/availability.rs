//! Signed cumulative observations and the immutable availability predicate.
//!
//! Bases are authenticated by earlier directly certified ordering descriptors.
//! Validation uses only supplied evidence; it never consults a mutable frontier.
//! The reference constructor uses current observations at every coordinate.

use crate::batch::BatchStore;
use crate::history::{Entries, Entry};
use crate::mmr::{self, Checkpoint, Config as MmrConfig, PrefixProof};
use crate::wire::{
    self, Committee, Context, Digest, Header, Id, Kind, Signed, SigningDomain, Statement,
};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedBase {
    pub opportunity: u64,
    pub identity: u64,
    pub frontier: Vec<Checkpoint>,
    pub authentication: Vec<u8>,
}

/// Public genesis needs no external certificate. Its name binds the full base.
pub fn genesis_binding(config: &MmrConfig, opportunity: u64, n: usize) -> NamedBase {
    let frontier: Vec<_> = (0..n).map(|id| mmr::genesis(config, id as Id)).collect();
    NamedBase {
        opportunity,
        identity: 0,
        frontier,
        authentication: Vec::new(),
    }
}

/// A bounded, nonrecursive certificate for the target frontier of an earlier
/// ordering proposal. Short CER signatures certify the unsigned header digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BaseCertificate {
    pub header: Signed<Header>,
    pub value: Vec<u8>,
    pub cers: Vec<Signed<Statement>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReportRequest {
    pub context: Context,
    pub opportunity: u64,
    pub base: u64,
    pub frontier_hash: Digest,
    pub authentication_hash: Digest,
}

impl SigningDomain for ReportRequest {
    const DOMAIN: &'static str = "dissemination-report";
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observed {
    pub checkpoint: Checkpoint,
    pub proof: PrefixProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub context: Context,
    pub opportunity: u64,
    pub base: u64,
    pub frontier_hash: Digest,
    pub coordinates: Vec<Observed>,
}

impl SigningDomain for Observation {
    const DOMAIN: &'static str = "dissemination-observation";
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub base: u64,
    pub frontier: Vec<Checkpoint>,
    pub targets: Vec<Checkpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub frontier: Vec<Checkpoint>,
    pub authentication: Vec<u8>,
    pub observation: Signed<Observation>,
}

impl Source {
    pub fn digest(&self) -> Result<Digest, String> {
        let preimage = ("dissemination-source", self);
        wire::encoded_size(&preimage)?;
        Ok(wire::hash(&preimage))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceRef {
    Current(u32),
    Historical(Digest),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    pub reporter: Id,
    pub source: SourceRef,
    pub base_bridge: PrefixProof,
    pub target_to_source: PrefixProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WeakAvailability {
    /// The sole noncurrent equality encoding; it carries no holder assertion.
    Base,
    Witnesses {
        base_to_target: PrefixProof,
        witnesses: Vec<Witness>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AvailabilityProof {
    pub authentication: Vec<u8>,
    pub pool: Vec<Signed<Observation>>,
    pub coordinates: Vec<WeakAvailability>,
    /// Strictly increasing canonical source hashes; source bytes are embedded.
    pub sources: Vec<(Digest, Source)>,
}

#[derive(Clone, Debug)]
pub struct CachedWitness {
    pub source: Source,
    /// Original-source base to this cached coordinate's base. Keeping this
    /// proof matters when the cache outlives proof-producing payload state.
    pub base_bridge: PrefixProof,
    pub target_to_source: PrefixProof,
}

#[derive(Clone, Debug)]
pub struct CachedCoordinate {
    pub base: Checkpoint,
    pub target: Checkpoint,
    pub base_to_target: PrefixProof,
    pub witnesses: Vec<CachedWitness>,
}

/// Constructor work observed on the existing selection path. Local candidates
/// are indexed checkpoints, not a claim that every associated payload is held.
/// Empty-with-progress counters distinguish valid fallback from useful output;
/// the workload ledger separately identifies pending honest application data.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ConstructionMetrics {
    pub completed_constructions: u64,
    pub frozen_reports: u64,
    pub advanced_coordinates: u64,
    pub empty_coordinates: u64,
    pub indexed_candidates: u64,
    pub examined_candidates: u64,
    pub base_proof_unavailable: u64,
    pub source_suffix_unavailable: u64,
    pub target_proof_unavailable: u64,
    pub source_threshold_unmet: u64,
    pub empty_with_local_candidates: u64,
    pub empty_with_observed_advance: u64,
    pub wholly_empty_inputs: u64,
    pub wholly_empty_with_local_candidates: u64,
    pub wholly_empty_with_observed_advance: u64,
}

impl ConstructionMetrics {
    pub fn add(&mut self, other: &Self) {
        self.completed_constructions += other.completed_constructions;
        self.frozen_reports += other.frozen_reports;
        self.advanced_coordinates += other.advanced_coordinates;
        self.empty_coordinates += other.empty_coordinates;
        self.indexed_candidates += other.indexed_candidates;
        self.examined_candidates += other.examined_candidates;
        self.base_proof_unavailable += other.base_proof_unavailable;
        self.source_suffix_unavailable += other.source_suffix_unavailable;
        self.target_proof_unavailable += other.target_proof_unavailable;
        self.source_threshold_unmet += other.source_threshold_unmet;
        self.empty_with_local_candidates += other.empty_with_local_candidates;
        self.empty_with_observed_advance += other.empty_with_observed_advance;
        self.wholly_empty_inputs += other.wholly_empty_inputs;
        self.wholly_empty_with_local_candidates += other.wholly_empty_with_local_candidates;
        self.wholly_empty_with_observed_advance += other.wholly_empty_with_observed_advance;
    }
}

/// Conservative canonical upper bound for any u64-height PrefixProof. A basic
/// proof has at most 64 peaks and 128 dyadic-cover roots. Crossing adds two
/// such proofs, a completed root, and at most 64 top peaks. This does not cap
/// checkpoint heights beyond their u64 representation.
pub const MAX_PREFIX_PROOF_BYTES: usize =
    4 + 2 * (4 + 8 + 64 * 36 + 8 + 128 * 32) + 32 + 8 + 64 * 36;

/// A clone contains only immutable public validation inputs. In particular, Q
/// neither observes a local cache nor asks a network service for source bytes.
#[derive(Clone, Debug)]
pub struct AvailabilityConfig {
    pub committee: Committee,
    pub mmr: MmrConfig,
    observation_budget: usize,
    base_certificate_budget: usize,
    #[cfg(test)]
    base_verification_calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl AvailabilityConfig {
    pub fn new(committee: Committee, chunk_capacity: u64) -> Result<Self, String> {
        let mmr = MmrConfig {
            context: committee.context.clone(),
            chunk_capacity,
        };
        mmr.validate()?;
        let (observation_budget, base_certificate_budget) = compatible_budgets(&committee, &mmr)?;
        Ok(Self {
            committee,
            mmr,
            observation_budget,
            base_certificate_budget,
            #[cfg(test)]
            base_verification_calls: Default::default(),
        })
    }

    /// Maximum complete signed OBS accepted by this configuration. The reserve
    /// admits every pool of n-f accepted observations plus every all-current WA.
    pub fn observation_budget(&self) -> usize {
        self.observation_budget
    }

    pub fn verify_named_base(&self, base: &NamedBase) -> Result<(), String> {
        wire::encoded_size(base)?;
        self.verify_base(
            base.opportunity,
            base.identity,
            &base.frontier,
            &base.authentication,
        )
    }

    pub fn report(
        &self,
        base: &NamedBase,
        key: &Keypair,
        id: Id,
    ) -> Result<Signed<ReportRequest>, String> {
        self.verify_named_base(base)?;
        if self.committee.keys.get(id as usize).map(|k| k.as_bytes()) != Some(key.public.as_bytes())
        {
            return Err("REPORT key does not match signer".into());
        }
        let request = wire::sign(
            key,
            id,
            ReportRequest {
                context: self.committee.context.clone(),
                opportunity: base.opportunity,
                base: base.identity,
                frontier_hash: wire::hash(&base.frontier),
                authentication_hash: wire::hash(&base.authentication),
            },
        );
        self.verify_report(&request, base)?;
        Ok(request)
    }

    pub fn verify_report(
        &self,
        request: &Signed<ReportRequest>,
        base: &NamedBase,
    ) -> Result<(), String> {
        wire::encoded_size(request)?;
        self.verify_named_base(base)?;
        self.committee.verify_signature(request)?;
        if request.signer != ((base.opportunity - 1) % self.committee.keys.len() as u64) as Id
            || request.body.context != self.committee.context
            || request.body.opportunity != base.opportunity
            || request.body.base != base.identity
            || request.body.frontier_hash != wire::hash(&base.frontier)
            || request.body.authentication_hash != wire::hash(&base.authentication)
        {
            return Err("REPORT leader, context, base, or attachment binding mismatch".into());
        }
        Ok(())
    }

    fn verify_frontier(&self, frontier: &[Checkpoint]) -> Result<(), String> {
        if frontier.len() != self.committee.keys.len() {
            return Err("frontier must have exactly one checkpoint per producer".into());
        }
        for (k, checkpoint) in frontier.iter().enumerate() {
            if checkpoint.producer != k as Id {
                return Err("frontier producer index mismatch".into());
            }
            mmr::verify_prefix(&self.mmr, checkpoint, checkpoint, &PrefixProof::Empty)?;
        }
        Ok(())
    }

    pub fn verify_base(
        &self,
        r: u64,
        b: u64,
        frontier: &[Checkpoint],
        eta: &[u8],
    ) -> Result<(), String> {
        #[cfg(test)]
        self.base_verification_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        wire::encoded_size(&(r, b, frontier, eta))?;
        if r == 0 || r > wire::MAX_ROUND || b >= r {
            return Err("base must be an earlier round of a supported opportunity".into());
        }
        self.verify_frontier(frontier)?;
        let n = self.committee.keys.len();
        let f = (n - 1) / 3;
        if b == 0 {
            let genesis = genesis_binding(&self.mmr, r, n);
            return if frontier == genesis.frontier && eta.is_empty() {
                Ok(())
            } else {
                Err("genesis requires the public frontier and empty evidence".into())
            };
        }
        if f == 0 {
            return Err("zero-fault configuration requires a genesis base".into());
        }
        if eta.len() > self.base_certificate_budget {
            return Err("base certificate exceeds its compatible component budget".into());
        }
        let cert: BaseCertificate = wire::decode(eta)?;
        self.committee.verify_header(&cert.header)?;
        if cert.header.body.round != b || cert.header.body.value_hash != wire::hash(&cert.value) {
            return Err("base certificate header round or value binding mismatch".into());
        }
        let descriptor = self.decode_descriptor(&cert.value)?;
        if descriptor.base >= b || descriptor.targets != frontier {
            return Err(
                "base certificate descriptor is malformed or targets another frontier".into(),
            );
        }
        if cert.cers.len() != n - f {
            return Err("base certificate requires exactly n-f CER signatures".into());
        }
        let digest = wire::proposal_digest(&cert.header.body);
        let mut signers = BTreeSet::new();
        for cer in &cert.cers {
            self.committee.verify_statement(cer)?;
            if cer.body.kind != Kind::Cer
                || cer.body.round != b
                || cer.body.digest != Some(digest)
                || !signers.insert(cer.signer)
            {
                return Err("base certificate has a mismatched or duplicate CER".into());
            }
        }
        Ok(())
    }

    pub fn verify_observation(
        &self,
        base: &NamedBase,
        observation: &Signed<Observation>,
    ) -> Result<(), String> {
        self.verify_named_base(base)?;
        self.verify_observation_at(base.opportunity, base.identity, &base.frontier, observation)
    }

    fn verify_observation_at(
        &self,
        r: u64,
        b: u64,
        frontier: &[Checkpoint],
        observation: &Signed<Observation>,
    ) -> Result<(), String> {
        if wire::encoded_size(observation)? > self.observation_budget as u64 {
            return Err("observation exceeds its compatible component budget".into());
        }
        self.committee.verify_signature(observation)?;
        let body = &observation.body;
        if body.context != self.committee.context
            || body.opportunity != r
            || body.base != b
            || body.frontier_hash != wire::hash(&frontier)
            || body.coordinates.len() != self.committee.keys.len()
        {
            return Err("observation opportunity, base, context, or vector shape mismatch".into());
        }
        for (k, observed) in body.coordinates.iter().enumerate() {
            if observed.checkpoint.producer != k as Id {
                return Err("observation producer index mismatch".into());
            }
            mmr::verify_prefix(
                &self.mmr,
                &frontier[k],
                &observed.checkpoint,
                &observed.proof,
            )?;
        }
        Ok(())
    }

    /// Caller owns the one-OBS-per-opportunity flag. Obligations are registered
    /// before the signature is formed; failures may conservatively retain more.
    pub fn observe(
        &self,
        base: &NamedBase,
        store: &mut BatchStore,
        key: &Keypair,
        id: Id,
    ) -> Result<Signed<Observation>, String> {
        if self.committee.keys.get(id as usize).map(|k| k.as_bytes()) != Some(key.public.as_bytes())
        {
            return Err("observation key does not match reporter".into());
        }
        self.verify_named_base(base)?;
        let mut coordinates = Vec::with_capacity(base.frontier.len());
        for (k, a) in base.frontier.iter().enumerate() {
            let mut candidates = store.checkpoints(k as Id);
            candidates.push(a.clone());
            sort_checkpoints(&mut candidates);
            let selected = candidates
                .into_iter()
                .find_map(|c| {
                    if !store.holds(a, &c) {
                        return None;
                    }
                    store.proof(a, &c).ok().map(|proof| Observed {
                        checkpoint: c,
                        proof,
                    })
                })
                .ok_or("authenticated base equality is unavailable")?;
            if selected.checkpoint != *a {
                store.register_custody(a, &selected.checkpoint)?;
            }
            coordinates.push(selected);
        }
        let body = Observation {
            context: self.committee.context.clone(),
            opportunity: base.opportunity,
            base: base.identity,
            frontier_hash: wire::hash(&base.frontier),
            coordinates,
        };
        // Reserve the complete signature-domain framing before the infallible
        // local signing helper. Incoming checks use its fallible verifier.
        if wire::encoded_size(&body)? > (wire::MAX_WIRE_BYTES - 512) as u64 {
            return Err("observation leaves insufficient signature framing space".into());
        }
        let observation = wire::sign(key, id, body);
        // The same immutable base was verified before construction. Keep all
        // signed observation and prefix checks without rechecking its certificate.
        self.verify_observation_at(
            base.opportunity,
            base.identity,
            &base.frontier,
            &observation,
        )?;
        Ok(observation)
    }

    pub fn decode_descriptor(&self, bytes: &[u8]) -> Result<Descriptor, String> {
        let x: Descriptor = wire::decode(bytes)?;
        self.verify_frontier(&x.frontier)?;
        self.verify_frontier(&x.targets)?;
        Ok(x)
    }

    pub fn q(&self, r: u64, x: &[u8], pi: &[u8]) -> bool {
        self.verify_encoded(r, x, pi).is_ok()
    }

    pub fn verify_encoded(&self, r: u64, x: &[u8], pi: &[u8]) -> Result<(), String> {
        self.committee.validate_input_size(x, pi)?;
        let x = self.decode_descriptor(x)?;
        let pi: AvailabilityProof = self.committee.decode(pi)?;
        self.verify_availability(r, &x, &pi)
    }

    pub fn verify_availability(
        &self,
        r: u64,
        x: &Descriptor,
        pi: &AvailabilityProof,
    ) -> Result<(), String> {
        // Each bounded size fits the selected complete-message profile and usize. Keep the
        // same x, pi, then combined-input guard order without allocating bytes.
        let xb = self.committee.encoded_size(x)? as usize;
        let pb = self.committee.encoded_size(pi)? as usize;
        self.committee.validate_input_lengths(xb, pb)?;
        self.verify_frontier(&x.frontier)?;
        self.verify_frontier(&x.targets)?;
        self.verify_base(r, x.base, &x.frontier, &pi.authentication)?;
        let n = self.committee.keys.len();
        let f = (n - 1) / 3;
        if pi.pool.len() != n - f || pi.coordinates.len() != n {
            return Err("availability pool or coordinate count is not exact".into());
        }
        let mut reporters = BTreeSet::new();
        for observation in &pi.pool {
            self.verify_observation_at(r, x.base, &x.frontier, observation)?;
            if !reporters.insert(observation.signer) {
                return Err("duplicate current reporter".into());
            }
        }
        let mut sources = BTreeMap::new();
        let mut previous = None;
        for (digest, source) in &pi.sources {
            if previous.map_or(false, |last| last >= *digest) || source.digest()? != *digest {
                return Err("source table is not canonical or a source hash mismatches".into());
            }
            self.verify_historical_source(r, source)?;
            previous = Some(*digest);
            sources.insert(*digest, source);
        }
        let mut used = BTreeSet::new();
        let mut current = 0;
        for k in 0..n {
            let a = &x.frontier[k];
            let c = &x.targets[k];
            let (base_to_target, witnesses) = match &pi.coordinates[k] {
                WeakAvailability::Base => {
                    if c != a {
                        return Err("noncurrent base form must be exact equality".into());
                    }
                    continue;
                }
                WeakAvailability::Witnesses {
                    base_to_target,
                    witnesses,
                } => (base_to_target, witnesses),
            };
            mmr::verify_prefix(&self.mmr, a, c, base_to_target)?;
            if witnesses.len() != f + 1 {
                return Err("WA requires exactly f+1 witnesses".into());
            }
            let mut identities = BTreeSet::new();
            let mut is_current = true;
            for witness in witnesses {
                let observation = match &witness.source {
                    SourceRef::Current(index) => {
                        if witness.base_bridge != PrefixProof::Empty {
                            return Err("current source bridge must be empty".into());
                        }
                        pi.pool
                            .get(*index as usize)
                            .ok_or("current source index is unresolved")?
                    }
                    SourceRef::Historical(digest) => {
                        is_current = false;
                        let source = sources
                            .get(digest)
                            .ok_or("historical source reference is unresolved")?;
                        used.insert(*digest);
                        mmr::verify_prefix(
                            &self.mmr,
                            &source.frontier[k],
                            a,
                            &witness.base_bridge,
                        )?;
                        &source.observation
                    }
                };
                if observation.signer != witness.reporter {
                    return Err("WA reporter does not match source signer".into());
                }
                if !identities.insert(observation.signer) {
                    return Err("duplicate verified WA signer".into());
                }
                mmr::verify_prefix(
                    &self.mmr,
                    c,
                    &observation.body.coordinates[k].checkpoint,
                    &witness.target_to_source,
                )?;
            }
            if is_current {
                current += 1;
            }
        }
        if current < n - f {
            return Err("frontier lacks n-f current coordinates".into());
        }
        if used.len() != sources.len() {
            return Err("unused historical source table entry".into());
        }
        Ok(())
    }

    fn verify_historical_source(&self, r: u64, source: &Source) -> Result<(), String> {
        wire::encoded_size(source)?;
        let old = &source.observation.body;
        if old.opportunity >= r {
            return Err("historical source is not from an earlier opportunity".into());
        }
        self.verify_frontier(&source.frontier)?;
        self.verify_base(
            old.opportunity,
            old.base,
            &source.frontier,
            &source.authentication,
        )?;
        self.verify_observation_at(
            old.opportunity,
            old.base,
            &source.frontier,
            &source.observation,
        )
    }

    /// Construct all coordinates from a frozen current pool. Empty selections
    /// copy the reporters' already verified proofs and need no source payload.
    pub fn build_all_current(
        &self,
        base: &NamedBase,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let (value, proof, _) = self.build_all_current_with_metrics(base, pool, store)?;
        Ok((value, proof))
    }

    pub fn build_all_current_with_metrics(
        &self,
        base: &NamedBase,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> Result<(Vec<u8>, Vec<u8>, ConstructionMetrics), String> {
        let _cost = crate::meter::measure(crate::meter::Operation::AvailabilityConstruct);
        let mut metrics = ConstructionMetrics {
            frozen_reports: pool.len() as u64,
            ..ConstructionMetrics::default()
        };
        self.verify_named_base(base)?;
        let n = self.committee.keys.len();
        let f = (n - 1) / 3;
        if pool.len() != n - f {
            return Err("construction requires a frozen exact n-f pool".into());
        }
        let mut reporters = BTreeSet::new();
        for observation in pool {
            // The base is fixed and was checked once above; every observation
            // still needs its own signature, binding, shape, and prefix checks.
            self.verify_observation_at(
                base.opportunity,
                base.identity,
                &base.frontier,
                observation,
            )?;
            if !reporters.insert(observation.signer) {
                return Err("construction pool has duplicate reporters".into());
            }
        }
        let mut targets = Vec::with_capacity(n);
        let mut coordinates = Vec::with_capacity(n);
        for k in 0..n {
            let (target, wa) = self.build_coordinate_with_metrics(
                &base.frontier[k],
                k,
                pool,
                store,
                &mut metrics,
            )?;
            targets.push(target);
            coordinates.push(wa);
        }
        let x = Descriptor {
            base: base.identity,
            frontier: base.frontier.clone(),
            targets,
        };
        let pi = AvailabilityProof {
            authentication: base.authentication.clone(),
            pool: pool.to_vec(),
            coordinates,
            sources: Vec::new(),
        };
        self.verify_availability(base.opportunity, &x, &pi)?;
        let value = self.committee.encode(&x)?;
        let proof = self.committee.encode(&pi)?;
        metrics.completed_constructions = 1;
        if metrics.advanced_coordinates == 0 {
            metrics.wholly_empty_inputs = 1;
            metrics.wholly_empty_with_local_candidates =
                u64::from(metrics.empty_with_local_candidates > 0);
            metrics.wholly_empty_with_observed_advance =
                u64::from(metrics.empty_with_observed_advance > 0);
        }
        Ok((value, proof, metrics))
    }

    pub fn construct(
        &self,
        base: &NamedBase,
        store: &BatchStore,
        pool: &[Signed<Observation>],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        self.build_all_current(base, pool, store)
    }

    #[cfg(test)]
    fn build_coordinate(
        &self,
        a: &Checkpoint,
        k: usize,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> Result<(Checkpoint, WeakAvailability), String> {
        self.build_coordinate_with_metrics(a, k, pool, store, &mut ConstructionMetrics::default())
    }

    fn build_coordinate_with_metrics(
        &self,
        a: &Checkpoint,
        k: usize,
        pool: &[Signed<Observation>],
        store: &BatchStore,
        metrics: &mut ConstructionMetrics,
    ) -> Result<(Checkpoint, WeakAvailability), String> {
        let threshold = (self.committee.keys.len() - 1) / 3 + 1;
        let mut candidates = store.checkpoints(k as Id);
        candidates.retain(|target| target.height > a.height);
        sort_checkpoints(&mut candidates);
        let local_candidates = candidates.len();
        metrics.indexed_candidates += local_candidates as u64;
        for target in candidates {
            metrics.examined_candidates += 1;
            let Ok(base_to_target) = store.proof(a, &target) else {
                metrics.base_proof_unavailable += 1;
                continue;
            };
            let mut usable = Vec::new();
            for (index, observation) in pool.iter().enumerate() {
                let source_cp = &observation.body.coordinates[k].checkpoint;
                if !store.holds(a, source_cp) {
                    metrics.source_suffix_unavailable += 1;
                    continue;
                }
                let Ok(target_to_source) = store.proof(&target, source_cp) else {
                    metrics.target_proof_unavailable += 1;
                    continue;
                };
                usable.push((
                    source_cp.height,
                    observation.signer,
                    index,
                    target_to_source,
                ));
            }
            usable.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
            if usable.len() < threshold {
                metrics.source_threshold_unmet += 1;
                continue;
            }
            let witnesses = usable
                .into_iter()
                .take(threshold)
                .map(|(_, reporter, index, target_to_source)| Witness {
                    reporter,
                    source: SourceRef::Current(index as u32),
                    base_bridge: PrefixProof::Empty,
                    target_to_source,
                })
                .collect();
            metrics.advanced_coordinates += 1;
            return Ok((
                target,
                WeakAvailability::Witnesses {
                    base_to_target,
                    witnesses,
                },
            ));
        }
        metrics.empty_coordinates += 1;
        metrics.empty_with_local_candidates += u64::from(local_candidates > 0);
        metrics.empty_with_observed_advance += u64::from(
            pool.iter()
                .any(|observation| observation.body.coordinates[k].checkpoint.height > a.height),
        );
        let mut ordered: Vec<_> = pool.iter().enumerate().collect();
        ordered.sort_by_key(|(_, observation)| observation.signer);
        let witnesses = ordered
            .into_iter()
            .take(threshold)
            .map(|(index, observation)| Witness {
                reporter: observation.signer,
                source: SourceRef::Current(index as u32),
                base_bridge: PrefixProof::Empty,
                target_to_source: observation.body.coordinates[k].proof.clone(),
            })
            .collect();
        Ok((
            a.clone(),
            WeakAvailability::Witnesses {
                base_to_target: PrefixProof::Empty,
                witnesses,
            },
        ))
    }

    /// Retain complete original signed sources and selected prefix proofs.
    pub fn cache(
        &self,
        r: u64,
        x: &Descriptor,
        pi: &AvailabilityProof,
    ) -> Result<Vec<CachedCoordinate>, String> {
        self.verify_availability(r, x, pi)?;
        let sources: BTreeMap<_, _> = pi.sources.iter().cloned().collect();
        let mut result = Vec::new();
        for (k, wa) in pi.coordinates.iter().enumerate() {
            let WeakAvailability::Witnesses {
                base_to_target,
                witnesses,
            } = wa
            else {
                continue;
            };
            let mut retained = Vec::new();
            for witness in witnesses {
                let source = match &witness.source {
                    SourceRef::Current(index) => Source {
                        frontier: x.frontier.clone(),
                        authentication: pi.authentication.clone(),
                        observation: pi.pool[*index as usize].clone(),
                    },
                    SourceRef::Historical(digest) => sources[digest].clone(),
                };
                retained.push(CachedWitness {
                    source,
                    base_bridge: witness.base_bridge.clone(),
                    target_to_source: witness.target_to_source.clone(),
                });
            }
            result.push(CachedCoordinate {
                base: x.frontier[k].clone(),
                target: x.targets[k].clone(),
                base_to_target: base_to_target.clone(),
                witnesses: retained,
            });
        }
        Ok(result)
    }
}

/// Fixed-width wire lengths let us reserve exact framing plus a conservative
/// canonical proof bound without allocating a worst-case aggregate message.
fn compatible_budgets(committee: &Committee, mmr: &MmrConfig) -> Result<(usize, usize), String> {
    let n = committee.keys.len();
    let f = (n - 1) / 3;
    let quorum = n - f;
    let frontier = genesis_binding(mmr, 1, n).frontier;
    let descriptor = Descriptor {
        base: 0,
        frontier: frontier.clone(),
        targets: frontier.clone(),
    };
    let value = wire::encode(&descriptor)?;
    let header = Signed {
        signer: 0,
        body: Header {
            context: committee.context.clone(),
            round: 6,
            value_hash: [0; 32],
            witness_hash: [0; 32],
            history_hash: [0; 32],
            entries: Entries {
                horizon: 3,
                pivot: 3,
                digest: Some([0; 32]),
                previous: vec![(1, Entry::Cer([0; 32])), (2, Entry::Cer([0; 32]))],
            },
        },
        signature: vec![0; 64],
    };
    let statement = Signed {
        signer: 0,
        body: Statement {
            context: committee.context.clone(),
            kind: Kind::Cer,
            round: 1,
            digest: Some([0; 32]),
        },
        signature: vec![0; 64],
    };
    let cert = BaseCertificate {
        header,
        value: value.clone(),
        cers: vec![],
    };
    let certificate_bytes = wire::encode(&cert)?
        .len()
        .checked_add(
            quorum
                .checked_mul(wire::encode(&statement)?.len())
                .ok_or("certificate size overflow")?,
        )
        .ok_or("certificate size overflow")?;
    let witness_bytes = 4 + 8 + 4 + MAX_PREFIX_PROOF_BYTES; // reporter, current ref, empty bridge, target proof
    let wa_bytes = 4
        + MAX_PREFIX_PROOF_BYTES
        + 8
        + (f + 1)
            .checked_mul(witness_bytes)
            .ok_or("WA size overflow")?;
    let fixed = value
        .len()
        .checked_add(32)
        .and_then(|v| v.checked_add(certificate_bytes))
        .and_then(|v| n.checked_mul(wa_bytes).and_then(|wa| v.checked_add(wa)))
        .ok_or("availability size overflow")?;
    let remaining = committee
        .input_budget()
        .checked_sub(fixed)
        .ok_or("committee all-current proof reserve exceeds the ordering input budget")?;
    let observation_budget = remaining / quorum;
    let minimum = Signed {
        signer: 0,
        body: Observation {
            context: committee.context.clone(),
            opportunity: 1,
            base: 0,
            frontier_hash: [0; 32],
            coordinates: frontier
                .into_iter()
                .map(|checkpoint| Observed {
                    checkpoint,
                    proof: PrefixProof::Empty,
                })
                .collect(),
        },
        signature: vec![0; 64],
    };
    let maximum_observation = wire::encode(&minimum)?
        .len()
        .checked_add(
            n.checked_mul(MAX_PREFIX_PROOF_BYTES - 4)
                .ok_or("observation size overflow")?,
        )
        .ok_or("observation size overflow")?;
    if observation_budget < maximum_observation {
        return Err(
            "committee cannot fit all canonical current observation vectors and WAs".into(),
        );
    }
    Ok((observation_budget, certificate_bytes))
}

fn checkpoint_order(a: &Checkpoint, b: &Checkpoint) -> std::cmp::Ordering {
    b.height
        .cmp(&a.height)
        .then_with(|| mmr::checkpoint_digest(a).cmp(&mmr::checkpoint_digest(b)))
}

fn sort_checkpoints(checkpoints: &mut Vec<Checkpoint>) {
    checkpoints.sort_by(checkpoint_order);
    checkpoints.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fixture_key;

    fn fixture() -> (AvailabilityConfig, BatchStore) {
        let committee =
            Committee::new([71; 32], (0..4).map(|id| fixture_key(id).public).collect()).unwrap();
        let store = BatchStore::new(committee.clone(), 4).unwrap();
        (AvailabilityConfig::new(committee, 4).unwrap(), store)
    }

    fn same_bounded_size<T: Serialize>(value: &T) {
        assert_eq!(
            wire::encoded_size(value),
            wire::encode(value).map(|bytes| bytes.len() as u64)
        );
    }

    #[test]
    fn size_only_guards_match_all_availability_types_and_nested_oversize_errors() {
        let (config, mut store) = fixture();
        let binding = base(&config, 1);
        let pool = observations(&config, &binding, &mut store);
        let (x, pi) = decoded(&config, &binding, &pool, &store);
        let request = config.report(&binding, &fixture_key(0), 0).unwrap();
        let source = Source {
            frontier: binding.frontier.clone(),
            authentication: binding.authentication.clone(),
            observation: pool[0].clone(),
        };
        same_bounded_size(&binding);
        same_bounded_size(&(
            binding.opportunity,
            binding.identity,
            binding.frontier.as_slice(),
            binding.authentication.as_slice(),
        ));
        same_bounded_size(&request);
        same_bounded_size(&pool[0]);
        same_bounded_size(&pool[0].body);
        same_bounded_size(&x);
        same_bounded_size(&pi);
        same_bounded_size(&source);
        same_bounded_size(&("dissemination-source", &source));
        assert_eq!(
            source.digest().unwrap(),
            wire::hash(&("dissemination-source", &source))
        );

        let mut oversized_base = binding.clone();
        oversized_base.authentication = vec![0; wire::MAX_WIRE_BYTES];
        same_bounded_size(&oversized_base);
        assert_eq!(
            config.verify_named_base(&oversized_base),
            wire::encode(&oversized_base).map(|_| ())
        );
        let mut oversized_request = request;
        oversized_request.signature = vec![0; wire::MAX_WIRE_BYTES];
        same_bounded_size(&oversized_request);
        assert_eq!(
            config.verify_report(&oversized_request, &oversized_base),
            wire::encode(&oversized_request).map(|_| ())
        );
        let mut oversized_source = source;
        oversized_source.observation.body.coordinates[0].proof = PrefixProof::Within {
            inner: mmr::BasicProof::Extension {
                peaks: vec![],
                suffix: vec![[0; 32]; wire::MAX_WIRE_BYTES / 32],
            },
        };
        same_bounded_size(&oversized_source);
        same_bounded_size(&oversized_source.observation);
        same_bounded_size(&oversized_source.observation.body);
        assert_eq!(
            oversized_source.digest(),
            wire::encode(&("dissemination-source", &oversized_source)).map(|_| [0; 32])
        );

        let mut large_pi = pi;
        for length in [config.committee.input_budget(), wire::MAX_WIRE_BYTES] {
            large_pi.authentication = vec![0; length];
            same_bounded_size(&large_pi);
            let old_guards = wire::encode(&x).and_then(|xb| {
                wire::encode(&large_pi)
                    .and_then(|pb| config.committee.validate_input_size(&xb, &pb))
            });
            assert!(old_guards.is_err());
            assert_eq!(config.verify_availability(1, &x, &large_pi), old_guards);
        }
    }

    fn base(config: &AvailabilityConfig, r: u64) -> NamedBase {
        genesis_binding(&config.mmr, r, config.committee.keys.len())
    }

    fn observations(
        config: &AvailabilityConfig,
        base: &NamedBase,
        store: &mut BatchStore,
    ) -> Vec<Signed<Observation>> {
        (0..3)
            .map(|id| config.observe(base, store, &fixture_key(id), id).unwrap())
            .collect()
    }

    fn decoded(
        config: &AvailabilityConfig,
        base: &NamedBase,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> (Descriptor, AvailabilityProof) {
        let (x, pi) = config.build_all_current(base, pool, store).unwrap();
        (wire::decode(&x).unwrap(), wire::decode(&pi).unwrap())
    }

    fn certified(
        config: &AvailabilityConfig,
        b: u64,
        r: u64,
        targets: Vec<Checkpoint>,
    ) -> NamedBase {
        let value = wire::encode(&Descriptor {
            base: 0,
            frontier: base(config, b).frontier,
            targets: targets.clone(),
        })
        .unwrap();
        let leader = ((b - 1) % config.committee.keys.len() as u64) as Id;
        let header = wire::sign(
            &fixture_key(leader),
            leader,
            Header {
                context: config.committee.context.clone(),
                round: b,
                value_hash: wire::hash(&value),
                witness_hash: [44; 32],
                history_hash: wire::empty_history_hash(),
                entries: Entries::empty(),
            },
        );
        let digest = wire::proposal_digest(&header.body);
        let cers = (0..3)
            .map(|id| {
                wire::sign(
                    &fixture_key(id),
                    id,
                    Statement {
                        context: config.committee.context.clone(),
                        kind: Kind::Cer,
                        round: b,
                        digest: Some(digest),
                    },
                )
            })
            .collect();
        NamedBase {
            opportunity: r,
            identity: b,
            frontier: targets,
            authentication: wire::encode(&BaseCertificate {
                header,
                value,
                cers,
            })
            .unwrap(),
        }
    }

    // Pre-optimization construction path: independently validate the same base
    // through every public observation check, then validate the assembled input.
    fn strict_build_all_current(
        config: &AvailabilityConfig,
        binding: &NamedBase,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        config.verify_named_base(binding)?;
        let n = config.committee.keys.len();
        let f = (n - 1) / 3;
        if pool.len() != n - f {
            return Err("construction requires a frozen exact n-f pool".into());
        }
        let mut reporters = BTreeSet::new();
        for observation in pool {
            config.verify_observation(binding, observation)?;
            if !reporters.insert(observation.signer) {
                return Err("construction pool has duplicate reporters".into());
            }
        }
        let mut targets = Vec::with_capacity(n);
        let mut coordinates = Vec::with_capacity(n);
        for k in 0..n {
            let (target, wa) = config.build_coordinate(&binding.frontier[k], k, pool, store)?;
            targets.push(target);
            coordinates.push(wa);
        }
        let x = Descriptor {
            base: binding.identity,
            frontier: binding.frontier.clone(),
            targets,
        };
        let pi = AvailabilityProof {
            authentication: binding.authentication.clone(),
            pool: pool.to_vec(),
            coordinates,
            sources: Vec::new(),
        };
        config.verify_availability(binding.opportunity, &x, &pi)?;
        Ok((wire::encode(&x)?, wire::encode(&pi)?))
    }

    #[test]
    fn same_base_rechecks_are_removed_without_changing_signed_or_constructed_bytes() {
        use std::sync::atomic::Ordering;
        let (config, mut source) = fixture();
        for id in 0..4 {
            source
                .produce(&fixture_key(id), id, vec![id as u8])
                .unwrap();
        }
        for binding in [
            base(&config, 1),
            certified(&config, 1, 3, base(&config, 1).frontier),
        ] {
            let coordinates = binding
                .frontier
                .iter()
                .enumerate()
                .map(|(id, a)| {
                    let checkpoint = source
                        .checkpoints(id as Id)
                        .into_iter()
                        .max_by_key(|cp| cp.height)
                        .unwrap();
                    Observed {
                        proof: source.proof(a, &checkpoint).unwrap(),
                        checkpoint,
                    }
                })
                .collect();
            let expected = wire::sign(
                &fixture_key(0),
                0,
                Observation {
                    context: config.committee.context.clone(),
                    opportunity: binding.opportunity,
                    base: binding.identity,
                    frontier_hash: wire::hash(&binding.frontier),
                    coordinates,
                },
            );
            config.base_verification_calls.store(0, Ordering::Relaxed);
            let actual = config
                .observe(&binding, &mut source, &fixture_key(0), 0)
                .unwrap();
            assert_eq!(config.base_verification_calls.load(Ordering::Relaxed), 1);
            assert_eq!(
                wire::encode(&actual).unwrap(),
                wire::encode(&expected).unwrap()
            );
            config.verify_observation(&binding, &actual).unwrap();
            let mut pool = observations(&config, &binding, &mut source);
            pool.swap(0, 2);
            let missing = BatchStore::new(config.committee.clone(), 4).unwrap();
            for store in [&source, &missing] {
                config.base_verification_calls.store(0, Ordering::Relaxed);
                let actual = config.build_all_current(&binding, &pool, store).unwrap();
                assert_eq!(config.base_verification_calls.load(Ordering::Relaxed), 2);
                config.base_verification_calls.store(0, Ordering::Relaxed);
                let expected = strict_build_all_current(&config, &binding, &pool, store).unwrap();
                assert_eq!(config.base_verification_calls.load(Ordering::Relaxed), 5);
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn construction_still_rejects_invalid_bases_and_each_observation_binding() {
        let (config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let binding = certified(&config, 1, 3, base(&config, 1).frontier);
        let pool = observations(&config, &binding, &mut store);
        let compare_rejection = |binding: &NamedBase, pool: &[Signed<Observation>]| {
            let previous = strict_build_all_current(&config, binding, pool, &store);
            let optimized = config.build_all_current(binding, pool, &store);
            assert!(previous.is_err());
            assert_eq!(optimized, previous);
        };
        for change in 0..5 {
            let mut changed = binding.clone();
            match change {
                0 => {
                    let mut certificate: BaseCertificate =
                        wire::decode(&changed.authentication).unwrap();
                    certificate.cers[0].signature[0] ^= 1;
                    changed.authentication = wire::encode(&certificate).unwrap();
                }
                1 => changed.opportunity = changed.identity,
                2 => changed.identity = 0,
                3 => changed.frontier[0].producer = 1,
                _ => changed.authentication.push(0),
            }
            compare_rejection(&changed, &pool);
            let mut receiver = store.clone();
            assert!(config
                .observe(&changed, &mut receiver, &fixture_key(0), 0)
                .is_err());
        }
        for change in 0..8 {
            let mut changed = pool.clone();
            match change {
                0 => changed[0].signature[0] ^= 1,
                1 => changed[0].body.opportunity += 1,
                2 => changed[0].body.base = 0,
                3 => changed[0].body.frontier_hash = [99; 32],
                4 => changed[0].body.context.instance = [99; 32],
                5 => {
                    changed[0].body.coordinates.pop();
                }
                6 => changed[0].body.coordinates[0].proof = PrefixProof::Empty,
                _ => changed[1] = changed[0].clone(),
            }
            // Except the explicit signature-corruption case, malformed contents
            // carry a valid signature: structural/prefix checks must still run.
            if (1..=6).contains(&change) {
                changed[0] = wire::sign(&fixture_key(0), 0, changed[0].body.clone());
            }
            compare_rejection(&binding, &changed);
        }
        compare_rejection(&binding, &pool[..2]);
        assert!(config
            .observe(&binding, &mut store, &fixture_key(1), 0)
            .is_err());
    }

    #[test]
    fn genesis_and_authenticated_earlier_base_need_no_registry_or_payload() {
        let (config, mut store) = fixture();
        let first = base(&config, 1);
        config.verify_named_base(&first).unwrap();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let pool = observations(&config, &first, &mut store);
        let (x, _) = decoded(&config, &first, &pool, &store);
        let authenticated = certified(&config, 1, 3, x.targets);
        config.verify_named_base(&authenticated).unwrap();
        // Q/base verification does not reconstruct old Q or fetch old history.
        let mut missing = BatchStore::new(config.committee.clone(), 4).unwrap();
        let empty_pool = observations(&config, &authenticated, &mut missing);
        let (x, pi) = decoded(&config, &authenticated, &empty_pool, &missing);
        assert_eq!(x.targets, authenticated.frontier);
        assert!(pi.sources.is_empty());
        config.verify_availability(3, &x, &pi).unwrap();
    }

    #[test]
    fn base_certificate_rejects_malformed_or_mismatched_authentication() {
        let (config, _) = fixture();
        let valid = certified(&config, 1, 2, base(&config, 1).frontier);
        let original: BaseCertificate = wire::decode(&valid.authentication).unwrap();
        let reject = |cert: BaseCertificate| {
            let mut changed = valid.clone();
            changed.authentication = wire::encode(&cert).unwrap();
            assert!(config.verify_named_base(&changed).is_err());
        };
        let mut cert = original.clone();
        cert.cers.pop();
        reject(cert);
        let mut cert = original.clone();
        cert.cers.push(cert.cers[0].clone());
        reject(cert);
        let mut cert = original.clone();
        cert.cers[1] = cert.cers[0].clone();
        reject(cert);
        let mut cert = original.clone();
        cert.value[0] ^= 1;
        reject(cert);
        let mut cert = original.clone();
        cert.header.signature[0] ^= 1;
        reject(cert);
        let mut cert = original.clone();
        cert.header = wire::sign(&fixture_key(1), 1, cert.header.body.clone());
        reject(cert);
        for change in 0..4 {
            let mut cert = original.clone();
            let mut body = cert.cers[0].body.clone();
            match change {
                0 => body.kind = Kind::Vote,
                1 => body.round += 1,
                2 => body.digest = Some([12; 32]),
                _ => body.context.instance = [99; 32],
            }
            cert.cers[0] = wire::sign(&fixture_key(0), 0, body);
            reject(cert);
        }
        let mut changed = valid.clone();
        changed.identity = 0;
        assert!(config.verify_named_base(&changed).is_err());
        let mut changed = valid.clone();
        changed.opportunity = 1;
        assert!(config.verify_named_base(&changed).is_err());
        let mut changed = valid.clone();
        changed.identity = 2;
        assert!(config.verify_named_base(&changed).is_err());
        let mut changed = valid;
        changed.authentication.push(0);
        assert!(config.verify_named_base(&changed).is_err());
    }

    #[test]
    fn certificate_targets_and_original_descriptor_fields_are_bound() {
        let (config, mut store) = fixture();
        let mut frontier = base(&config, 1).frontier;
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        frontier[0] = store
            .checkpoints(0)
            .into_iter()
            .max_by_key(|c| c.height)
            .unwrap();
        let mut authenticated = certified(&config, 1, 2, frontier);
        authenticated.frontier = base(&config, 1).frontier;
        assert!(config.verify_named_base(&authenticated).is_err());
        let mut cert: BaseCertificate = wire::decode(&authenticated.authentication).unwrap();
        let mut descriptor: Descriptor = wire::decode(&cert.value).unwrap();
        descriptor.base = 1; // The prior descriptor cannot name itself as base.
        cert.value = wire::encode(&descriptor).unwrap();
        cert.header.body.value_hash = wire::hash(&cert.value);
        cert.header = wire::sign(&fixture_key(0), 0, cert.header.body);
        let digest = wire::proposal_digest(&cert.header.body);
        for cer in &mut cert.cers {
            cer.body.digest = Some(digest);
            *cer = wire::sign(&fixture_key(cer.signer), cer.signer, cer.body.clone());
        }
        authenticated.frontier = descriptor.targets;
        authenticated.authentication = wire::encode(&cert).unwrap();
        assert!(config.verify_named_base(&authenticated).is_err());
    }

    #[test]
    fn profile_excludes_zero_fault_committees() {
        // VerifyBase retains the specification's f=0/genesis guard, while
        // this fixed ordering profile explicitly supports n=3f+1 >=4 only.
        assert!(Committee::new([71; 32], vec![fixture_key(0).public]).is_err());
    }

    #[test]
    fn signed_report_authenticates_leader_opportunity_and_attachments() {
        let (config, _) = fixture();
        let binding = certified(&config, 1, 2, base(&config, 1).frontier);
        let request = config.report(&binding, &fixture_key(1), 1).unwrap();
        config.verify_report(&request, &binding).unwrap();
        assert!(config.report(&binding, &fixture_key(0), 0).is_err());
        let mut other = binding.clone();
        other.opportunity = 3;
        assert!(config.verify_report(&request, &other).is_err());
        // Reordering valid CERs preserves certificate validity but must not
        // preserve the request's exact evidence attachment hash.
        let mut cert: BaseCertificate = wire::decode(&binding.authentication).unwrap();
        cert.cers.swap(0, 1);
        other = binding.clone();
        other.authentication = wire::encode(&cert).unwrap();
        config.verify_named_base(&other).unwrap();
        assert!(config.verify_report(&request, &other).is_err());
        let mut tampered = request.clone();
        tampered.body.frontier_hash = [7; 32];
        assert!(config.verify_report(&tampered, &binding).is_err());
    }

    #[test]
    fn observations_bind_complete_vector_and_register_custody() {
        let (config, mut store) = fixture();
        let binding = base(&config, 1);
        store
            .produce(&fixture_key(0), 0, b"batch".to_vec())
            .unwrap();
        let observation = config
            .observe(&binding, &mut store, &fixture_key(0), 0)
            .unwrap();
        assert_eq!(store.custody_count(), 1);
        config.verify_observation(&binding, &observation).unwrap();
        assert!(config
            .verify_observation(&base(&config, 2), &observation)
            .is_err());
        let mut changed = observation;
        changed.body.coordinates[0].checkpoint.height = 0;
        assert!(config.verify_observation(&binding, &changed).is_err());
    }

    #[test]
    fn empty_fallback_copies_current_proofs_without_source_payloads() {
        let (config, mut source_store) = fixture();
        let binding = base(&config, 1);
        for id in 0..4 {
            source_store
                .produce(&fixture_key(id), id, vec![id as u8])
                .unwrap();
        }
        let mut pool = observations(&config, &binding, &mut source_store);
        pool.swap(0, 2);
        let missing = BatchStore::new(config.committee.clone(), 4).unwrap();
        let (x, pi) = decoded(&config, &binding, &pool, &missing);
        assert_eq!(x.targets, binding.frontier);
        assert!(pi.sources.is_empty());
        for (k, wa) in pi.coordinates.iter().enumerate() {
            let WeakAvailability::Witnesses {
                base_to_target,
                witnesses,
            } = wa
            else {
                panic!()
            };
            assert_eq!(*base_to_target, PrefixProof::Empty);
            assert_eq!(
                witnesses.iter().map(|w| w.reporter).collect::<Vec<_>>(),
                vec![0, 1]
            );
            for witness in witnesses {
                let SourceRef::Current(index) = witness.source else {
                    panic!()
                };
                assert_eq!(
                    witness.target_to_source,
                    pool[index as usize].body.coordinates[k].proof
                );
            }
        }
        config.verify_availability(1, &x, &pi).unwrap();
        let (measured_value, measured_proof, empty_metrics) = config
            .build_all_current_with_metrics(&binding, &pool, &missing)
            .unwrap();
        assert_eq!(measured_value, wire::encode(&x).unwrap());
        assert_eq!(measured_proof, wire::encode(&pi).unwrap());
        assert_eq!(empty_metrics.completed_constructions, 1);
        assert_eq!(empty_metrics.frozen_reports, 3);
        assert_eq!(empty_metrics.empty_coordinates, 4);
        assert_eq!(empty_metrics.empty_with_observed_advance, 4);
        assert_eq!(empty_metrics.empty_with_local_candidates, 0);
        assert_eq!(empty_metrics.wholly_empty_with_observed_advance, 1);
        let (advancing, _) = decoded(&config, &binding, &pool, &source_store);
        assert!(advancing.targets.iter().all(|c| c.height == 1));
        let (_, _, ready_metrics) = config
            .build_all_current_with_metrics(&binding, &pool, &source_store)
            .unwrap();
        assert_eq!(ready_metrics.advanced_coordinates, 4);
        assert_eq!(ready_metrics.empty_coordinates, 0);
        assert_eq!(ready_metrics.source_suffix_unavailable, 0);
    }

    #[test]
    fn advancing_construction_requires_complete_source_suffix() {
        let (config, mut source) = fixture();
        let binding = base(&config, 1);
        source.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let leader = source.clone();
        source.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let pool = observations(&config, &binding, &mut source);
        let (x, _) = decoded(&config, &binding, &pool, &leader);
        assert_eq!(x.targets[0].height, 0); // Holding target 1 alone is insufficient.
        let (_, _, metrics) = config
            .build_all_current_with_metrics(&binding, &pool, &leader)
            .unwrap();
        assert_eq!(metrics.empty_with_local_candidates, 1);
        assert_eq!(metrics.source_suffix_unavailable, 3);
        assert_eq!(metrics.source_threshold_unmet, 1);
        assert_eq!(metrics.wholly_empty_with_local_candidates, 1);
    }

    #[test]
    fn highest_target_then_highest_source_heights_then_signer_identity() {
        let (config, mut store) = fixture();
        let binding = base(&config, 1);
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let low = config
            .observe(&binding, &mut store, &fixture_key(0), 0)
            .unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let middle = config
            .observe(&binding, &mut store, &fixture_key(1), 1)
            .unwrap();
        store.produce(&fixture_key(0), 0, vec![3]).unwrap();
        let high = config
            .observe(&binding, &mut store, &fixture_key(2), 2)
            .unwrap();
        let (x, pi) = decoded(&config, &binding, &[low, middle, high], &store);
        assert_eq!(x.targets[0].height, 2);
        let WeakAvailability::Witnesses { witnesses, .. } = &pi.coordinates[0] else {
            panic!()
        };
        assert_eq!(
            witnesses.iter().map(|w| w.reporter).collect::<Vec<_>>(),
            vec![2, 1]
        );
    }

    #[test]
    fn empty_current_coordinates_require_distinct_verified_sources() {
        let (config, mut store) = fixture();
        let binding = base(&config, 1);
        let pool = observations(&config, &binding, &mut store);
        let (x, pi) = decoded(&config, &binding, &pool, &store);
        let mut changed = pi.clone();
        changed.pool[1] = changed.pool[0].clone();
        assert!(config.verify_availability(1, &x, &changed).is_err());
        let mut changed = pi.clone();
        if let WeakAvailability::Witnesses { witnesses, .. } = &mut changed.coordinates[0] {
            witnesses[1] = witnesses[0].clone();
        }
        assert!(config.verify_availability(1, &x, &changed).is_err());
        let mut changed = pi;
        changed.coordinates[0] = WeakAvailability::Base;
        config.verify_availability(1, &x, &changed).unwrap();
        changed.coordinates[1] = WeakAvailability::Base;
        assert!(config.verify_availability(1, &x, &changed).is_err());
    }

    fn use_historical_coordinate(
        pi: &mut AvailabilityProof,
        k: usize,
        old_x: &Descriptor,
        old_pi: &AvailabilityProof,
    ) {
        let WeakAvailability::Witnesses {
            base_to_target,
            witnesses,
        } = &old_pi.coordinates[k]
        else {
            panic!()
        };
        let mut historical = Vec::new();
        for witness in witnesses {
            let SourceRef::Current(index) = witness.source else {
                panic!()
            };
            let source = Source {
                frontier: old_x.frontier.clone(),
                authentication: old_pi.authentication.clone(),
                observation: old_pi.pool[index as usize].clone(),
            };
            let digest = source.digest().unwrap();
            pi.sources.push((digest, source));
            historical.push(Witness {
                reporter: witness.reporter,
                source: SourceRef::Historical(digest),
                base_bridge: PrefixProof::Empty,
                target_to_source: witness.target_to_source.clone(),
            });
        }
        pi.sources.sort_by_key(|(digest, _)| *digest);
        pi.coordinates[k] = WeakAvailability::Witnesses {
            base_to_target: base_to_target.clone(),
            witnesses: historical,
        };
    }

    #[test]
    fn historical_extension_validates_original_sources_and_rejects_unused_entries() {
        let (config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let old_pool = observations(&config, &base(&config, 1), &mut store);
        let (old_x, old_pi) = decoded(&config, &base(&config, 1), &old_pool, &store);
        let mut missing = BatchStore::new(config.committee.clone(), 4).unwrap();
        let pool = observations(&config, &base(&config, 2), &mut missing);
        let (mut x, mut pi) = decoded(&config, &base(&config, 2), &pool, &missing);
        x.targets[0] = old_x.targets[0].clone();
        use_historical_coordinate(&mut pi, 0, &old_x, &old_pi);
        config.verify_availability(2, &x, &pi).unwrap();
        let extra = Source {
            frontier: old_x.frontier.clone(),
            authentication: old_pi.authentication.clone(),
            observation: old_pool[2].clone(),
        };
        pi.sources.push((extra.digest().unwrap(), extra));
        pi.sources.sort_by_key(|(digest, _)| *digest);
        assert!(config.verify_availability(2, &x, &pi).is_err());
    }

    #[test]
    fn historical_source_labels_cannot_duplicate_a_real_signer() {
        let (config, mut store) = fixture();
        let old_pool = observations(&config, &base(&config, 1), &mut store);
        let (old_x, old_pi) = decoded(&config, &base(&config, 1), &old_pool, &store);
        let pool = observations(&config, &base(&config, 3), &mut store);
        let (x, mut pi) = decoded(&config, &base(&config, 3), &pool, &store);
        use_historical_coordinate(&mut pi, 0, &old_x, &old_pi);
        // A second genuinely signed source at another opportunity is still the
        // same reporter. Its distinct source digest adds no holder identity.
        let repeated = Source {
            frontier: base(&config, 2).frontier,
            authentication: vec![],
            observation: config
                .observe(&base(&config, 2), &mut store, &fixture_key(0), 0)
                .unwrap(),
        };
        let digest = repeated.digest().unwrap();
        pi.sources
            .retain(|(_, source)| source.observation.signer == 0);
        pi.sources.push((digest, repeated));
        pi.sources.sort_by_key(|(digest, _)| *digest);
        let WeakAvailability::Witnesses { witnesses, .. } = &mut pi.coordinates[0] else {
            panic!()
        };
        witnesses[1].source = SourceRef::Historical(digest);
        assert!(config.verify_availability(3, &x, &pi).is_err()); // Claimed signer 1 is false.
        let WeakAvailability::Witnesses { witnesses, .. } = &mut pi.coordinates[0] else {
            panic!()
        };
        witnesses[1].reporter = 0;
        assert!(config.verify_availability(3, &x, &pi).is_err()); // Actual signer is duplicated.
    }

    #[test]
    fn historical_sources_preserve_authenticated_original_base_and_bridge() {
        let (config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let intermediate = store
            .checkpoints(0)
            .into_iter()
            .max_by_key(|c| c.height)
            .unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let old_pool = observations(&config, &base(&config, 1), &mut store);
        let (old_x, old_pi) = decoded(&config, &base(&config, 1), &old_pool, &store);
        let mut frontier = old_x.frontier.clone();
        frontier[0] = intermediate;
        let binding = certified(&config, 1, 3, frontier);
        let pool = observations(&config, &binding, &mut store);
        let (x, mut pi) = decoded(&config, &binding, &pool, &store);
        use_historical_coordinate(&mut pi, 0, &old_x, &old_pi);
        let WeakAvailability::Witnesses {
            base_to_target,
            witnesses,
        } = &mut pi.coordinates[0]
        else {
            panic!()
        };
        *base_to_target = store.proof(&x.frontier[0], &x.targets[0]).unwrap();
        for witness in witnesses {
            witness.base_bridge = store.proof(&old_x.frontier[0], &x.frontier[0]).unwrap();
        }
        config.verify_availability(3, &x, &pi).unwrap();
        // Authenticated old metadata is not relabelled to the new frontier.
        let mut changed = pi.clone();
        changed.sources[0].1.frontier = x.frontier.clone();
        assert!(config.verify_availability(3, &x, &changed).is_err());
        let WeakAvailability::Witnesses { witnesses, .. } = &mut pi.coordinates[0] else {
            panic!()
        };
        witnesses[0].base_bridge = PrefixProof::Empty;
        assert!(config.verify_availability(3, &x, &pi).is_err());
    }

    #[test]
    fn byzantine_producer_forks_are_independently_valid_at_equal_heights() {
        let (config, mut branch_a) = fixture();
        let mut branch_b = branch_a.clone();
        let mut empty = branch_a.clone();
        branch_a
            .produce(&fixture_key(0), 0, b"fork A".to_vec())
            .unwrap();
        branch_b
            .produce(&fixture_key(0), 0, b"fork B".to_vec())
            .unwrap();
        let a = base(&config, 1);
        let b = base(&config, 2);
        let pool_a = vec![
            config
                .observe(&a, &mut branch_a, &fixture_key(0), 0)
                .unwrap(),
            config
                .observe(&a, &mut branch_a, &fixture_key(1), 1)
                .unwrap(),
            config.observe(&a, &mut empty, &fixture_key(2), 2).unwrap(),
        ];
        let pool_b = vec![
            config
                .observe(&b, &mut branch_b, &fixture_key(0), 0)
                .unwrap(),
            config.observe(&b, &mut empty, &fixture_key(1), 1).unwrap(),
            config
                .observe(&b, &mut branch_b, &fixture_key(2), 2)
                .unwrap(),
        ];
        let (xa, pa) = config.build_all_current(&a, &pool_a, &branch_a).unwrap();
        let (xb, pb) = config.build_all_current(&b, &pool_b, &branch_b).unwrap();
        assert!(config.q(1, &xa, &pa));
        assert!(config.q(2, &xb, &pb));
        let xa: Descriptor = wire::decode(&xa).unwrap();
        let xb: Descriptor = wire::decode(&xb).unwrap();
        assert_eq!(xa.targets[0].height, xb.targets[0].height);
        assert_ne!(xa.targets[0], xb.targets[0]);
        assert!(branch_a.proof(&xa.targets[0], &xb.targets[0]).is_err());
    }

    #[test]
    fn compatible_component_budgets_reserve_the_complete_current_aggregate() {
        use crate::mmr::{BasicProof, Peak};
        let basic = BasicProof::Extension {
            peaks: vec![
                Peak {
                    height: 0,
                    root: [0; 32]
                };
                64
            ],
            suffix: vec![[0; 32]; 128],
        };
        let maximum = PrefixProof::Crossing {
            completion: basic.clone(),
            completed_root: [0; 32],
            top_peaks: vec![
                Peak {
                    height: 0,
                    root: [0; 32]
                };
                64
            ],
            remaining: basic,
        };
        assert_eq!(
            wire::encode(&maximum).unwrap().len(),
            MAX_PREFIX_PROOF_BYTES
        );
        for (n, profile) in [
            (4, wire::ResourceProfile::Legacy1MibV1),
            (7, wire::ResourceProfile::Legacy1MibV1),
            (31, wire::ResourceProfile::Complete32MibN31V1),
        ] {
            let committee = Committee::with_profile(
                [71; 32],
                (0..n).map(|id| fixture_key(id).public).collect(),
                profile,
            )
            .unwrap();
            let config = AvailabilityConfig::new(committee, 4).unwrap();
            let f = (n as usize - 1) / 3;
            let quorum = n as usize - f;
            let binding = base(&config, 1);
            let maximum_observation = Signed {
                signer: 0,
                body: Observation {
                    context: config.committee.context.clone(),
                    opportunity: 1,
                    base: 0,
                    frontier_hash: [0; 32],
                    coordinates: binding
                        .frontier
                        .iter()
                        .cloned()
                        .map(|checkpoint| Observed {
                            checkpoint,
                            proof: maximum.clone(),
                        })
                        .collect(),
                },
                signature: vec![0; 64],
            };
            assert!(
                wire::encode(&maximum_observation).unwrap().len() <= config.observation_budget()
            );
            let value = wire::encode(&Descriptor {
                base: 0,
                frontier: binding.frontier.clone(),
                targets: binding.frontier,
            })
            .unwrap();
            let wa = WeakAvailability::Witnesses {
                base_to_target: maximum.clone(),
                witnesses: (0..=f)
                    .map(|i| Witness {
                        reporter: i as Id,
                        source: SourceRef::Current(i as u32),
                        base_bridge: PrefixProof::Empty,
                        target_to_source: maximum.clone(),
                    })
                    .collect(),
            };
            let fixed = value.len()
                + 32
                + config.base_certificate_budget
                + n as usize * wire::encode(&wa).unwrap().len();
            assert!(
                fixed + quorum * config.observation_budget() <= config.committee.input_budget()
            );
            assert!(
                fixed + quorum * (config.observation_budget() + 1)
                    > config.committee.input_budget()
            );
            // Serialize the entire conservative u64-height aggregate, including
            // the authenticated-base reserve. These synthetic roots test size
            // closure; cryptographically valid inputs are tested separately.
            let aggregate = AvailabilityProof {
                authentication: vec![0; config.base_certificate_budget],
                pool: vec![maximum_observation; quorum],
                coordinates: vec![wa; n as usize],
                sources: vec![],
            };
            let proof = config.committee.encode(&aggregate).unwrap();
            config
                .committee
                .validate_input_size(&value, &proof)
                .unwrap();
            if n == 31 {
                assert!(proof.len() > wire::MAX_WIRE_BYTES);
            }
        }
        for n in [10, 13] {
            let committee =
                Committee::new([71; 32], (0..n).map(|id| fixture_key(id).public).collect())
                    .unwrap();
            assert!(AvailabilityConfig::new(committee, 4).is_err());
        }
    }

    #[test]
    fn complete_profile_accepts_authenticated_all_current_and_empty_inputs_at_n31() {
        let committee = Committee::with_profile(
            [72; 32],
            (0..31).map(|id| fixture_key(id).public).collect(),
            wire::ResourceProfile::Complete32MibN31V1,
        )
        .unwrap();
        let config = AvailabilityConfig::new(committee.clone(), 4).unwrap();
        let mut store = BatchStore::new(committee, 4).unwrap();
        let binding = base(&config, 1);
        let empty_pool: Vec<_> = (0..21)
            .map(|id| {
                config
                    .observe(&binding, &mut store, &fixture_key(id), id)
                    .unwrap()
            })
            .collect();
        let (empty_value, empty_proof) = config
            .build_all_current(&binding, &empty_pool, &store)
            .unwrap();
        assert!(config.q(1, &empty_value, &empty_proof));
        assert_eq!(
            config.decode_descriptor(&empty_value).unwrap().targets,
            binding.frontier
        );
        for id in 0..31 {
            store.produce(&fixture_key(id), id, vec![id as u8]).unwrap();
        }
        let pool: Vec<_> = (0..21)
            .map(|id| {
                config
                    .observe(&binding, &mut store, &fixture_key(id), id)
                    .unwrap()
            })
            .collect();
        let (value, proof) = config.build_all_current(&binding, &pool, &store).unwrap();
        assert!(config.q(1, &value, &proof));
        assert!(config
            .decode_descriptor(&value)
            .unwrap()
            .targets
            .iter()
            .all(|point| point.height == 1));
        assert!(!config.q(1, &value, &proof[..proof.len() - 1]));
        let mut malformed: AvailabilityProof = config.committee.decode(&proof).unwrap();
        malformed.pool[0].signature[0] ^= 1;
        assert!(!config.q(1, &value, &config.committee.encode(&malformed).unwrap()));
    }

    #[test]
    fn malformed_oversized_and_noncanonical_inputs_fail_without_fetches() {
        let (config, mut store) = fixture();
        assert!(!config.q(1, &[255; 10], &[255; 10]));
        assert!(!config.q(1, &vec![0; wire::MAX_WIRE_BYTES], &[]));
        let binding = base(&config, 1);
        let mut observation = config
            .observe(&binding, &mut store, &fixture_key(0), 0)
            .unwrap();
        observation.signature = vec![0; config.observation_budget()];
        assert!(config
            .verify_observation(&binding, &observation)
            .unwrap_err()
            .contains("component budget"));
        let pool = observations(&config, &binding, &mut store);
        let (x, mut pi) = decoded(&config, &binding, &pool, &store);
        let WeakAvailability::Witnesses { witnesses, .. } = &mut pi.coordinates[0] else {
            panic!()
        };
        witnesses[0].source = SourceRef::Current(99);
        assert!(config.verify_availability(1, &x, &pi).is_err());
        let mut binding = binding;
        binding.opportunity = 0;
        assert!(config.verify_named_base(&binding).is_err());
    }
}
