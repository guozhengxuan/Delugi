//! Signed cumulative observations and the immutable availability predicate.
//!
//! Named-base authorization is an explicit external contract: this reference
//! profile compares with a supplied, immutable registry. It does not infer a
//! common base from a replica's changing execution or ordering frontier.

use crate::batch::BatchStore;
use crate::mmr::{self, Checkpoint, Config as MmrConfig, PrefixProof};
use crate::wire::{self, Committee, Context, Digest, Id, Signed, SigningDomain};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedBase {
    pub opportunity: u64,
    pub identity: Digest,
    pub frontier: Vec<Checkpoint>,
    pub authentication: Vec<u8>,
}

/// Public genesis needs no external certificate. Its name binds the full base.
pub fn genesis_binding(config: &MmrConfig, opportunity: u64, n: usize) -> NamedBase {
    let frontier: Vec<_> = (0..n).map(|id| mmr::genesis(config, id as Id)).collect();
    NamedBase {
        opportunity,
        identity: wire::hash(&("dissemination-genesis-base", &frontier)),
        frontier,
        authentication: Vec::new(),
    }
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
    pub base: Digest,
    pub frontier_hash: Digest,
    pub coordinates: Vec<Observed>,
}

impl SigningDomain for Observation {
    const DOMAIN: &'static str = "dissemination-observation";
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Descriptor {
    pub base: Digest,
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
        wire::encode(&preimage)?;
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

/// A clone contains only immutable public validation inputs. In particular, Q
/// neither observes a local cache nor asks a network service for source bytes.
#[derive(Clone, Debug)]
pub struct AvailabilityConfig {
    pub committee: Committee,
    pub mmr: MmrConfig,
    bases: BTreeMap<u64, NamedBase>,
}

impl AvailabilityConfig {
    pub fn new(
        committee: Committee,
        chunk_capacity: u64,
        bases: Vec<NamedBase>,
    ) -> Result<Self, String> {
        if chunk_capacity == 0 {
            return Err("chunk capacity must be positive".into());
        }
        let mmr = MmrConfig {
            context: committee.context.clone(),
            chunk_capacity,
        };
        mmr.validate()?;
        let mut config = Self {
            committee,
            mmr,
            bases: BTreeMap::new(),
        };
        let mut identities = BTreeMap::<Digest, (Vec<Checkpoint>, Vec<u8>)>::new();
        for base in bases {
            wire::encode(&base)?;
            if base.opportunity == 0 || base.opportunity > wire::MAX_ROUND {
                return Err("base opportunity outside supported positive range".into());
            }
            config.verify_frontier(&base.frontier)?;
            if let Some((frontier, authentication)) = identities.get(&base.identity) {
                if frontier != &base.frontier || authentication != &base.authentication {
                    return Err("one base identity names conflicting immutable contents".into());
                }
            } else {
                identities.insert(
                    base.identity,
                    (base.frontier.clone(), base.authentication.clone()),
                );
            }
            if config.bases.insert(base.opportunity, base).is_some() {
                return Err("duplicate authorized reporting opportunity".into());
            }
        }
        Ok(config)
    }

    pub fn binding(&self, opportunity: u64) -> Result<&NamedBase, String> {
        self.bases
            .get(&opportunity)
            .ok_or_else(|| "reporting opportunity has no authorized named base".into())
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

    fn verify_base(
        &self,
        r: u64,
        b: &Digest,
        frontier: &[Checkpoint],
        eta: &[u8],
    ) -> Result<(), String> {
        let expected = self.binding(r)?;
        if b != &expected.identity
            || frontier != expected.frontier
            || eta != expected.authentication
        {
            return Err(
                "named base does not match its externally authorized immutable binding".into(),
            );
        }
        Ok(())
    }

    pub fn verify_observation(
        &self,
        r: u64,
        observation: &Signed<Observation>,
    ) -> Result<(), String> {
        let base = self.binding(r)?;
        self.verify_observation_at(r, base.identity, &base.frontier, observation)
    }

    fn verify_observation_at(
        &self,
        r: u64,
        b: Digest,
        frontier: &[Checkpoint],
        observation: &Signed<Observation>,
    ) -> Result<(), String> {
        wire::encode(observation)?;
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
        r: u64,
        store: &mut BatchStore,
        key: &Keypair,
        id: Id,
    ) -> Result<Signed<Observation>, String> {
        if self.committee.keys.get(id as usize).map(|k| k.as_bytes()) != Some(key.public.as_bytes())
        {
            return Err("observation key does not match reporter".into());
        }
        let base = self.binding(r)?;
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
            opportunity: r,
            base: base.identity,
            frontier_hash: wire::hash(&base.frontier),
            coordinates,
        };
        // Reserve the complete signature-domain framing before the infallible
        // local signing helper. Incoming checks use its fallible verifier.
        if wire::encode(&body)?.len() > wire::MAX_WIRE_BYTES - 512 {
            return Err("observation leaves insufficient signature framing space".into());
        }
        let observation = wire::sign(key, id, body);
        self.verify_observation(r, &observation)?;
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
        let pi: AvailabilityProof = wire::decode(pi)?;
        self.verify_availability(r, &x, &pi)
    }

    pub fn verify_availability(
        &self,
        r: u64,
        x: &Descriptor,
        pi: &AvailabilityProof,
    ) -> Result<(), String> {
        let xb = wire::encode(x)?;
        let pb = wire::encode(pi)?;
        self.committee.validate_input_size(&xb, &pb)?;
        self.verify_frontier(&x.frontier)?;
        self.verify_frontier(&x.targets)?;
        self.verify_base(r, &x.base, &x.frontier, &pi.authentication)?;
        let n = self.committee.keys.len();
        let f = (n - 1) / 3;
        if pi.pool.len() != n - f || pi.coordinates.len() != n {
            return Err("availability pool or coordinate count is not exact".into());
        }
        let mut reporters = BTreeSet::new();
        for observation in &pi.pool {
            self.verify_observation(r, observation)?;
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
                if !identities.insert(witness.reporter) {
                    return Err("duplicate WA reporter".into());
                }
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
        wire::encode(source)?;
        let old = &source.observation.body;
        if old.opportunity >= r {
            return Err("historical source is not from an earlier opportunity".into());
        }
        self.verify_frontier(&source.frontier)?;
        self.verify_base(
            old.opportunity,
            &old.base,
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

    /// Build every current coordinate using the strict source-holding rule.
    /// Historical sources are complete originals; extra material is never
    /// embedded unless selected by a coordinate witness.
    pub fn build(
        &self,
        r: u64,
        pool: &[Signed<Observation>],
        store: &BatchStore,
        historical: &[Source],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
        self.build_with_cache(r, pool, store, historical, &[])
    }

    pub fn build_with_cache(
        &self,
        r: u64,
        pool: &[Signed<Observation>],
        store: &BatchStore,
        historical: &[Source],
        cache: &[CachedCoordinate],
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
        let base = self.binding(r)?;
        let n = self.committee.keys.len();
        let f = (n - 1) / 3;
        if pool.len() != n - f {
            return Err("construction requires a frozen exact n-f pool".into());
        }
        let mut reporters = BTreeSet::new();
        for observation in pool {
            self.verify_observation(r, observation)?;
            if !reporters.insert(observation.signer) {
                return Err("construction pool has duplicate reporters".into());
            }
        }
        for source in historical {
            self.verify_historical_source(r, source)?;
        }
        let mut targets = Vec::with_capacity(n);
        let mut coordinates = Vec::with_capacity(n);
        let mut sources = BTreeMap::new();
        let mut current_count = 0;
        for k in 0..n {
            let a = &base.frontier[k];
            if let Some((target, wa, selected)) =
                self.build_coordinate(a, k, pool, store, &[], false)?
            {
                current_count += 1;
                targets.push(target);
                coordinates.push(wa);
                sources.extend(selected);
                continue;
            }
            let mut alternatives = Vec::new();
            if let Some(item) = self.build_coordinate(a, k, pool, store, historical, true)? {
                alternatives.push(item);
            }
            for cached in cache
                .iter()
                .filter(|cached| cached.target.producer == k as Id)
            {
                if let Ok(Some(item)) = self.rebase_cached(r, a, k, cached, store) {
                    alternatives.push(item);
                }
            }
            alternatives.sort_by(|left, right| checkpoint_order(&left.0, &right.0));
            if let Some((target, wa, selected)) = alternatives.into_iter().next() {
                targets.push(target);
                coordinates.push(wa);
                sources.extend(selected);
            } else {
                targets.push(a.clone());
                coordinates.push(WeakAvailability::Base);
            }
        }
        if current_count < n - f {
            return Ok(None);
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
            sources: sources.into_iter().collect(),
        };
        self.verify_availability(r, &x, &pi)?;
        Ok(Some((wire::encode(&x)?, wire::encode(&pi)?)))
    }

    fn build_coordinate(
        &self,
        a: &Checkpoint,
        k: usize,
        pool: &[Signed<Observation>],
        store: &BatchStore,
        historical: &[Source],
        require_historical: bool,
    ) -> Result<Option<(Checkpoint, WeakAvailability, BTreeMap<Digest, Source>)>, String> {
        let threshold = (self.committee.keys.len() - 1) / 3 + 1;
        let mut sources = Vec::new();
        for (index, observation) in pool.iter().enumerate() {
            sources.push((
                observation,
                SourceRef::Current(index as u32),
                PrefixProof::Empty,
                None,
            ));
        }
        for source in historical {
            if let Ok(bridge) = store.proof(&source.frontier[k], a) {
                sources.push((
                    &source.observation,
                    SourceRef::Historical(source.digest()?),
                    bridge,
                    Some(source),
                ));
            }
        }
        let mut candidates = store.checkpoints(k as Id);
        candidates.push(a.clone());
        sort_checkpoints(&mut candidates);
        for target in candidates {
            let Ok(base_to_target) = store.proof(a, &target) else {
                continue;
            };
            let mut usable = Vec::new();
            for (observation, reference, bridge, original) in &sources {
                let source_cp = &observation.body.coordinates[k].checkpoint;
                // Even a base target requires complete possession of the exact
                // advertised source suffix, not merely the base proof/root.
                if !store.holds(a, source_cp) {
                    continue;
                }
                let Ok(target_to_source) = store.proof(&target, source_cp) else {
                    continue;
                };
                usable.push((
                    source_cp.height,
                    observation.signer,
                    reference.clone(),
                    bridge.clone(),
                    target_to_source,
                    *original,
                ));
            }
            usable.sort_by(|left, right| {
                right
                    .0
                    .cmp(&left.0)
                    .then_with(|| left.1.cmp(&right.1))
                    .then_with(|| source_order(&left.2, &right.2))
            });
            let mut distinct = BTreeSet::new();
            usable.retain(|entry| distinct.insert(entry.1));
            if usable.len() < threshold {
                continue;
            }
            let mut chosen: Vec<_> = usable.iter().take(threshold).cloned().collect();
            if require_historical && !chosen.iter().any(|entry| entry.5.is_some()) {
                if let Some(old) = usable
                    .iter()
                    .skip(threshold)
                    .find(|entry| entry.5.is_some())
                {
                    chosen.pop();
                    chosen.push(old.clone());
                } else {
                    continue;
                }
            }
            let mut selected = BTreeMap::new();
            let witnesses = chosen
                .into_iter()
                .map(
                    |(_, reporter, source, base_bridge, target_to_source, original)| {
                        if let (SourceRef::Historical(digest), Some(original)) = (&source, original)
                        {
                            selected.insert(*digest, original.clone());
                        }
                        Witness {
                            reporter,
                            source,
                            base_bridge,
                            target_to_source,
                        }
                    },
                )
                .collect();
            return Ok(Some((
                target,
                WeakAvailability::Witnesses {
                    base_to_target,
                    witnesses,
                },
                selected,
            )));
        }
        Ok(None)
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

    fn rebase_cached(
        &self,
        r: u64,
        a: &Checkpoint,
        k: usize,
        cached: &CachedCoordinate,
        store: &BatchStore,
    ) -> Result<Option<(Checkpoint, WeakAvailability, BTreeMap<Digest, Source>)>, String> {
        if cached.target.height < a.height {
            return Ok(None);
        }
        let base_to_target = if cached.base == *a {
            cached.base_to_target.clone()
        } else {
            store.proof(a, &cached.target)?
        };
        mmr::verify_prefix(&self.mmr, a, &cached.target, &base_to_target)?;
        let threshold = (self.committee.keys.len() - 1) / 3 + 1;
        if cached.witnesses.len() != threshold {
            return Err("cached WA witness count mismatch".into());
        }
        let mut identities = BTreeSet::new();
        let mut selected = BTreeMap::new();
        let mut witnesses = Vec::new();
        for witness in &cached.witnesses {
            self.verify_historical_source(r, &witness.source)?;
            if !identities.insert(witness.source.observation.signer) {
                return Err("cached WA duplicate reporter".into());
            }
            let original_base = &witness.source.frontier[k];
            let bridge = if original_base == a {
                PrefixProof::Empty
            } else if cached.base == *a {
                witness.base_bridge.clone()
            } else {
                store.proof(original_base, a)?
            };
            mmr::verify_prefix(&self.mmr, original_base, a, &bridge)?;
            mmr::verify_prefix(
                &self.mmr,
                &cached.target,
                &witness.source.observation.body.coordinates[k].checkpoint,
                &witness.target_to_source,
            )?;
            let digest = witness.source.digest()?;
            selected.insert(digest, witness.source.clone());
            witnesses.push(Witness {
                reporter: witness.source.observation.signer,
                source: SourceRef::Historical(digest),
                base_bridge: bridge,
                target_to_source: witness.target_to_source.clone(),
            });
        }
        Ok(Some((
            cached.target.clone(),
            WeakAvailability::Witnesses {
                base_to_target,
                witnesses,
            },
            selected,
        )))
    }
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

fn source_order(a: &SourceRef, b: &SourceRef) -> std::cmp::Ordering {
    match (a, b) {
        (SourceRef::Current(a), SourceRef::Current(b)) => a.cmp(b),
        (SourceRef::Historical(a), SourceRef::Historical(b)) => a.cmp(b),
        (SourceRef::Current(_), _) => std::cmp::Ordering::Less,
        (_, SourceRef::Current(_)) => std::cmp::Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fixture_key;

    fn fixture() -> (AvailabilityConfig, BatchStore) {
        let committee =
            Committee::new([71; 32], (0..4).map(|id| fixture_key(id).public).collect()).unwrap();
        let store = BatchStore::new(committee.clone(), 4).unwrap();
        let bases = (1..=5)
            .map(|r| genesis_binding(store.config(), r, 4))
            .collect();
        (AvailabilityConfig::new(committee, 4, bases).unwrap(), store)
    }

    fn observations(
        config: &AvailabilityConfig,
        r: u64,
        store: &mut BatchStore,
    ) -> Vec<Signed<Observation>> {
        (0..3)
            .map(|id| config.observe(r, store, &fixture_key(id), id).unwrap())
            .collect()
    }

    fn decoded(
        config: &AvailabilityConfig,
        r: u64,
        pool: &[Signed<Observation>],
        store: &BatchStore,
    ) -> (Descriptor, AvailabilityProof) {
        let (x, pi) = config.build(r, pool, store, &[]).unwrap().unwrap();
        (wire::decode(&x).unwrap(), wire::decode(&pi).unwrap())
    }

    #[test]
    fn complete_observation_signature_and_original_binding_are_required() {
        let (config, mut store) = fixture();
        store
            .produce(&fixture_key(0), 0, b"batch".to_vec())
            .unwrap();
        let observation = config.observe(1, &mut store, &fixture_key(0), 0).unwrap();
        assert_eq!(store.custody_count(), 1);
        config.verify_observation(1, &observation).unwrap();
        assert!(config.verify_observation(2, &observation).is_err());
        let mut tampered = observation;
        tampered.body.coordinates[0].checkpoint.height = 0;
        assert!(config.verify_observation(1, &tampered).is_err());
    }

    #[test]
    fn empty_current_coordinates_still_need_f_plus_one_distinct_sources() {
        let (config, mut store) = fixture();
        let pool = observations(&config, 1, &mut store);
        let (x, mut pi) = decoded(&config, 1, &pool, &store);
        assert!(x.targets.iter().all(|cp| cp.height == 0));
        assert!(pi.coordinates.iter().all(
            |wa| matches!(wa, WeakAvailability::Witnesses { witnesses, .. } if witnesses.len() == 2)
        ));
        pi.coordinates[0] = WeakAvailability::Base;
        config.verify_availability(1, &x, &pi).unwrap();
        pi.coordinates[1] = WeakAvailability::Base;
        assert!(config.verify_availability(1, &x, &pi).is_err());
    }

    #[test]
    fn duplicate_pool_or_wa_reporters_are_rejected() {
        let (config, mut store) = fixture();
        let pool = observations(&config, 1, &mut store);
        let (x, pi) = decoded(&config, 1, &pool, &store);
        let mut duplicate_pool = pi.clone();
        duplicate_pool.pool[1] = duplicate_pool.pool[0].clone();
        assert!(config.verify_availability(1, &x, &duplicate_pool).is_err());
        let mut duplicate_wa = pi;
        if let WeakAvailability::Witnesses { witnesses, .. } = &mut duplicate_wa.coordinates[0] {
            witnesses[1] = witnesses[0].clone();
        }
        assert!(config.verify_availability(1, &x, &duplicate_wa).is_err());
    }

    #[test]
    fn build_requires_complete_source_suffix_even_for_a_base_target() {
        let (config, mut source_store) = fixture();
        source_store
            .produce(&fixture_key(0), 0, b"unreceived payload".to_vec())
            .unwrap();
        let pool = observations(&config, 1, &mut source_store);
        let leader = BatchStore::new(config.committee.clone(), 4).unwrap();
        let (x, pi) = decoded(&config, 1, &pool, &leader);
        assert_eq!(x.targets[0].height, 0);
        assert_eq!(pi.coordinates[0], WeakAvailability::Base);
        assert!(pi.coordinates[1..]
            .iter()
            .all(|wa| matches!(wa, WeakAvailability::Witnesses { .. })));
        // Public validity is independent of receiver holdings and accepts the
        // higher proof once constructed by a holder.
        let (higher_x, higher_pi) = decoded(&config, 1, &pool, &source_store);
        assert_eq!(higher_x.targets[0].height, 1);
        config
            .verify_availability(1, &higher_x, &higher_pi)
            .unwrap();
    }

    #[test]
    fn highest_target_uses_highest_source_heights_then_identity() {
        let (config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let low = config.observe(1, &mut store, &fixture_key(0), 0).unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let middle = config.observe(1, &mut store, &fixture_key(1), 1).unwrap();
        store.produce(&fixture_key(0), 0, vec![3]).unwrap();
        let high = config.observe(1, &mut store, &fixture_key(2), 2).unwrap();
        let (x, pi) = decoded(&config, 1, &[low, middle, high], &store);
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
    fn historical_cache_retains_full_original_sources_and_rejects_unused_entries() {
        let (config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let old_pool = observations(&config, 1, &mut store);
        let (old_x, old_pi) = decoded(&config, 1, &old_pool, &store);
        let cached = config.cache(1, &old_x, &old_pi).unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let new_pool = observations(&config, 2, &mut store);
        let missing = BatchStore::new(config.committee.clone(), 4).unwrap();
        let (xb, pb) = config
            .build_with_cache(2, &new_pool, &missing, &[], &cached)
            .unwrap()
            .unwrap();
        let x: Descriptor = wire::decode(&xb).unwrap();
        let mut pi: AvailabilityProof = wire::decode(&pb).unwrap();
        assert_eq!(x.targets[0].height, 1);
        assert_eq!(pi.sources.len(), 2);
        assert!(pi
            .sources
            .iter()
            .all(|(_, source)| source.observation.body.opportunity == 1
                && source.frontier == old_x.frontier));
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
    fn feasible_current_base_beats_a_higher_historical_cache() {
        let (config, mut full) = fixture();
        full.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let old = observations(&config, 1, &mut full);
        let (old_x, old_pi) = decoded(&config, 1, &old, &full);
        let cached = config.cache(1, &old_x, &old_pi).unwrap();
        let mut empty = BatchStore::new(config.committee.clone(), 4).unwrap();
        let current = observations(&config, 2, &mut empty);
        let (xb, pb) = config
            .build_with_cache(2, &current, &empty, &[], &cached)
            .unwrap()
            .unwrap();
        let x: Descriptor = wire::decode(&xb).unwrap();
        let pi: AvailabilityProof = wire::decode(&pb).unwrap();
        assert_eq!(x.targets[0].height, 0);
        assert!(pi.sources.is_empty());
    }

    #[test]
    fn historical_sources_keep_old_bases_across_an_authorized_base_advance() {
        let (old_config, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let new_base = store
            .checkpoints(0)
            .into_iter()
            .find(|cp| cp.height == 1)
            .unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let old_pool = observations(&old_config, 1, &mut store);
        let (old_x, old_pi) = decoded(&old_config, 1, &old_pool, &store);
        let cache = old_config.cache(1, &old_x, &old_pi).unwrap();
        let mut binding = old_config.binding(2).unwrap().clone();
        binding.frontier[0] = new_base;
        binding.authentication = b"externally authorized checkpoint".to_vec();
        binding.identity = wire::hash(&("external-base", &binding.frontier));
        let config = AvailabilityConfig::new(
            old_config.committee.clone(),
            4,
            vec![old_config.binding(1).unwrap().clone(), binding.clone()],
        )
        .unwrap();
        let mut advanced = store.clone();
        advanced.produce(&fixture_key(0), 0, vec![3]).unwrap();
        let pool = observations(&config, 2, &mut advanced);
        // Store lacks all current sources at height 3; it retains enough nodes
        // to bridge the historical genesis base to the new height-1 base.
        let (xb, pb) = config
            .build_with_cache(2, &pool, &store, &[], &cache)
            .unwrap()
            .unwrap();
        let x: Descriptor = wire::decode(&xb).unwrap();
        let pi: AvailabilityProof = wire::decode(&pb).unwrap();
        assert_eq!(x.frontier[0].height, 1);
        assert_eq!(x.targets[0].height, 2);
        assert!(pi
            .sources
            .iter()
            .all(|(_, source)| source.frontier[0].height == 0));
        config.verify_availability(2, &x, &pi).unwrap();
        let mut relabeled = pi;
        relabeled.sources[0].1.frontier = binding.frontier;
        assert!(config.verify_availability(2, &x, &relabeled).is_err());
    }

    #[test]
    fn cached_historical_bridge_survives_without_original_payload_or_proof_nodes() {
        let (original, mut store) = fixture();
        store.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let base_cp = store
            .checkpoints(0)
            .into_iter()
            .find(|cp| cp.height == 1)
            .unwrap();
        let boundary = store.boundary(&base_cp).unwrap();
        store.produce(&fixture_key(0), 0, vec![2]).unwrap();
        let old_pool = observations(&original, 1, &mut store);
        let (old_x, old_pi) = decoded(&original, 1, &old_pool, &store);
        let old_cache = original.cache(1, &old_x, &old_pi).unwrap();
        let mut base2 = original.binding(2).unwrap().clone();
        base2.frontier[0] = base_cp;
        base2.authentication = vec![9];
        base2.identity = wire::hash(&("external-base", &base2.frontier));
        let mut base3 = base2.clone();
        base3.opportunity = 3;
        let config = AvailabilityConfig::new(
            original.committee.clone(),
            4,
            vec![original.binding(1).unwrap().clone(), base2, base3],
        )
        .unwrap();
        let mut advanced = store.clone();
        advanced.produce(&fixture_key(0), 0, vec![3]).unwrap();
        let pool2 = observations(&config, 2, &mut advanced);
        let (x2b, p2b) = config
            .build_with_cache(2, &pool2, &store, &[], &old_cache)
            .unwrap()
            .unwrap();
        let x2: Descriptor = wire::decode(&x2b).unwrap();
        let p2: AvailabilityProof = wire::decode(&p2b).unwrap();
        let retained = config.cache(2, &x2, &p2).unwrap();
        let pool3 = observations(&config, 3, &mut advanced);
        let mut metadata_only = BatchStore::new(config.committee.clone(), 4).unwrap();
        metadata_only.install_boundary(&boundary).unwrap();
        assert_eq!(metadata_only.record_count(), 0);
        assert!(metadata_only
            .proof(&old_x.frontier[0], &x2.frontier[0])
            .is_err());
        let (x3b, p3b) = config
            .build_with_cache(3, &pool3, &metadata_only, &[], &retained)
            .unwrap()
            .unwrap();
        let x3: Descriptor = wire::decode(&x3b).unwrap();
        assert_eq!(x3.targets[0].height, 2);
        config.verify_encoded(3, &x3b, &p3b).unwrap();
    }

    #[test]
    fn q_is_false_on_oversized_or_malformed_input_without_fetches() {
        let (config, _) = fixture();
        assert!(!config.q(1, &[255; 10], &[255; 10]));
        assert!(!config.q(1, &vec![0; wire::MAX_WIRE_BYTES], &[]));
        let mut source = Source {
            frontier: config.binding(1).unwrap().frontier.clone(),
            authentication: vec![0; wire::MAX_WIRE_BYTES],
            observation: wire::sign(
                &fixture_key(0),
                0,
                Observation {
                    context: config.committee.context.clone(),
                    opportunity: 1,
                    base: [0; 32],
                    frontier_hash: [0; 32],
                    coordinates: vec![],
                },
            ),
        };
        assert!(source.digest().is_err());
        source.authentication.clear();
        assert!(config.verify_historical_source(1, &source).is_err());
    }

    #[test]
    fn safe2_individually_available_byzantine_forks_do_not_imply_compatible_frontiers() {
        // Producer/reporter 0 equivocates. Honest 1 holds branch A and honest
        // 2 holds B. Each f+1 coordinate quorum has an honest obligated holder,
        // yet the quorums intersect only at Byzantine 0. Q intentionally does
        // not claim a cross-round frontier-compatibility rule.
        let (config, mut branch_a) = fixture();
        let mut branch_b = branch_a.clone();
        let mut empty = branch_a.clone();
        branch_a
            .produce(&fixture_key(0), 0, b"fork A".to_vec())
            .unwrap();
        branch_b
            .produce(&fixture_key(0), 0, b"fork B".to_vec())
            .unwrap();
        let pool_a = vec![
            config
                .observe(1, &mut branch_a, &fixture_key(0), 0)
                .unwrap(),
            config
                .observe(1, &mut branch_a, &fixture_key(1), 1)
                .unwrap(),
            config.observe(1, &mut empty, &fixture_key(2), 2).unwrap(),
        ];
        let pool_b = vec![
            config
                .observe(2, &mut branch_b, &fixture_key(0), 0)
                .unwrap(),
            config.observe(2, &mut empty, &fixture_key(1), 1).unwrap(),
            config
                .observe(2, &mut branch_b, &fixture_key(2), 2)
                .unwrap(),
        ];
        let (xa, pa) = config.build(1, &pool_a, &branch_a, &[]).unwrap().unwrap();
        let (xb, pb) = config.build(2, &pool_b, &branch_b, &[]).unwrap().unwrap();
        assert!(config.q(1, &xa, &pa));
        assert!(config.q(2, &xb, &pb));
        let xa: Descriptor = wire::decode(&xa).unwrap();
        let xb: Descriptor = wire::decode(&xb).unwrap();
        assert_eq!(xa.frontier, xb.frontier);
        assert_eq!(xa.targets[0].height, 1);
        assert_eq!(xb.targets[0].height, 1);
        assert_ne!(xa.targets[0], xb.targets[0]);
        assert!(mmr::verify_prefix(
            &config.mmr,
            &xa.targets[0],
            &xb.targets[0],
            &PrefixProof::Empty
        )
        .is_err());
        assert!(branch_a.proof(&xa.targets[0], &xb.targets[0]).is_err());
    }
}
