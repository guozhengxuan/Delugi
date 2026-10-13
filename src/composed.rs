//! Composed reference runtime. Named-base authorization is supplied immutable
//! configuration, not a claim to solve the paper's common-base service. Ordered
//! frontiers must be compatible; a conflicting committed frontier is an explicit
//! composition error, never projected away. Payload storage/custody are in memory.
use crate::availability::{
    AvailabilityConfig, AvailabilityProof, CachedCoordinate, Descriptor, Observation, Source,
};
use crate::batch::{record_digest, BatchStore, Data, DataPart, Record};
use crate::mmr::{self, Checkpoint};
use crate::replica::{Effect as OrderingEffect, Replica};
use crate::wire::{self, Committee, Digest, Id, Signed};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Batch(Record),
    Observation(Signed<Observation>),
    Fetch {
        base: Checkpoint,
        target: Checkpoint,
    },
    Data(Data),
    DataPart(DataPart),
}

#[derive(Clone, Debug)]
pub enum Effect {
    Ordering(OrderingEffect),
    Send { to: Option<Id>, message: Message },
    Trace(Value),
}

/// A deterministic payload-integrity workload, not a smart-contract engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: Digest,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Executed {
    pub round: u64,
    pub producer: Id,
    pub height: u64,
    pub batch_digest: Digest,
    pub transaction: Digest,
    pub state_hash: Digest,
}

pub struct Node {
    pub id: Id,
    pub ordering: Replica,
    pub store: BatchStore,
    pub executed: Vec<Executed>,
    pub executed_rounds: Vec<u64>,
    pub input_ready: BTreeMap<u64, u64>,
    pub ordered_at: BTreeMap<u64, u64>,
    pub executed_at: BTreeMap<u64, u64>,
    pub observations: BTreeMap<u64, Signed<Observation>>,
    committee: Committee,
    key: Keypair,
    availability: AvailabilityConfig,
    collected: BTreeMap<u64, BTreeMap<Id, Signed<Observation>>>,
    pools: BTreeMap<u64, Vec<Signed<Observation>>>,
    sources: BTreeMap<Digest, Source>,
    cached: Vec<CachedCoordinate>,
    cached_inputs: BTreeSet<(u64, Digest, Digest)>,
    pending_ordered: VecDeque<(u64, Descriptor)>,
    frontier: Vec<Checkpoint>,
    requested: BTreeMap<Digest, (Checkpoint, Checkpoint)>,
    pending_requests: BTreeMap<(Id, Digest), (Checkpoint, Checkpoint)>,
    served: BTreeSet<(Id, Digest)>,
    batch_ids: BTreeSet<Digest>,
    transaction_ids: BTreeSet<Digest>,
    state: Digest,
}

impl Node {
    pub fn new(
        committee: Committee,
        id: Id,
        key: Keypair,
        bound: u64,
        availability: AvailabilityConfig,
        chunk_capacity: u64,
    ) -> Result<Self, String> {
        if availability.committee.context != committee.context
            || availability.committee.keys != committee.keys
            || availability.mmr.context != committee.context
            || availability.mmr.chunk_capacity != chunk_capacity
        {
            return Err("ordering and availability configurations differ".into());
        }
        let verifier = availability.clone();
        let ordering_key = Keypair::from_bytes(&key.to_bytes()).map_err(|e| e.to_string())?;
        let ordering = Replica::try_new(
            committee.clone(),
            id,
            ordering_key,
            bound,
            BTreeMap::new(),
            move |r, x, pi| verifier.q(r, x, pi),
        )?;
        let store = BatchStore::new(committee.clone(), chunk_capacity)?;
        let frontier = (0..committee.keys.len() as Id)
            .map(|k| mmr::genesis(store.config(), k))
            .collect();
        Ok(Self {
            id,
            ordering,
            store,
            executed: Vec::new(),
            executed_rounds: Vec::new(),
            input_ready: BTreeMap::new(),
            ordered_at: BTreeMap::new(),
            executed_at: BTreeMap::new(),
            observations: BTreeMap::new(),
            committee,
            key,
            availability,
            collected: BTreeMap::new(),
            pools: BTreeMap::new(),
            sources: BTreeMap::new(),
            cached: Vec::new(),
            cached_inputs: BTreeSet::new(),
            pending_ordered: VecDeque::new(),
            frontier,
            requested: BTreeMap::new(),
            pending_requests: BTreeMap::new(),
            served: BTreeSet::new(),
            batch_ids: BTreeSet::new(),
            transaction_ids: BTreeSet::new(),
            state: wire::hash(&"delugi/deterministic-materialization/v1"),
        })
    }
    pub fn start(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let effects = self.ordering.start(now)?;
        self.accept_ordering(now, effects)
    }
    pub fn tick(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let effects = self.ordering.tick(now)?;
        self.accept_ordering(now, effects)
    }
    pub fn receive_ordering(
        &mut self,
        now: u64,
        message: wire::Message,
    ) -> Result<Vec<Effect>, String> {
        if let wire::Message::Propose(proposal) = &message {
            self.committee
                .verify_proposal(proposal, |r, x, pi| self.availability.q(r, x, pi))?;
            self.remember(
                proposal.header.body.round,
                &proposal.value,
                &proposal.witness,
            )?;
        }
        let effects = self.ordering.receive(now, message)?;
        let mut result = self.accept_ordering(now, effects)?;
        result.extend(self.retry(now)?);
        Ok(result)
    }
    fn remember(&mut self, r: u64, value: &[u8], witness: &[u8]) -> Result<(), String> {
        let key = (r, wire::hash(&value), wire::hash(&witness));
        if self.cached_inputs.contains(&key) {
            return Ok(());
        }
        let x: Descriptor = wire::decode(value)?;
        let pi: AvailabilityProof = wire::decode(witness)?;
        self.cached.extend(self.availability.cache(r, &x, &pi)?);
        for observation in &pi.pool {
            let source = Source {
                frontier: x.frontier.clone(),
                authentication: pi.authentication.clone(),
                observation: observation.clone(),
            };
            self.sources.insert(source.digest()?, source);
        }
        for (digest, source) in pi.sources {
            self.sources.insert(digest, source);
        }
        self.cached_inputs.insert(key);
        Ok(())
    }
    pub fn produce(&mut self, now: u64, payload: Vec<u8>) -> Result<Vec<Effect>, String> {
        let record = self.store.produce(&self.key, self.id, payload)?;
        let mut effects = vec![Effect::Send {
            to: None,
            message: Message::Batch(record),
        }];
        effects.extend(self.retry(now)?);
        Ok(effects)
    }
    /// The external fixture invokes exactly one common, authorized base event.
    /// Repeating it cannot renew a signature or change the observation snapshot.
    pub fn report(&mut self, now: u64, round: u64) -> Result<Vec<Effect>, String> {
        if self.observations.contains_key(&round) {
            return Ok(Vec::new());
        }
        let observation = self
            .availability
            .observe(round, &mut self.store, &self.key, self.id)?;
        self.observations.insert(round, observation.clone());
        let to = ((round - 1) % self.committee.keys.len() as u64) as Id;
        let mut effects = vec![Effect::Trace(
            json!({"event":"observation_snapshot", "replica":self.id,
            "round":round,"at":now,"heights":observation.body.coordinates.iter().map(|o|o.checkpoint.height).collect::<Vec<_>>()}),
        )];
        if to == self.id {
            self.collect(observation)?;
            effects.extend(self.retry(now)?);
        } else {
            effects.push(Effect::Send {
                to: Some(to),
                message: Message::Observation(observation),
            });
        }
        Ok(effects)
    }
    fn collect(&mut self, observation: Signed<Observation>) -> Result<(), String> {
        let r = observation.body.opportunity;
        self.availability.verify_observation(r, &observation)?;
        if ((r - 1) % self.committee.keys.len() as u64) as Id != self.id {
            return Err("observation addressed to wrong collector".into());
        }
        if self.pools.contains_key(&r) {
            return Ok(());
        }
        let received = self.collected.entry(r).or_default();
        received.entry(observation.signer).or_insert(observation);
        let quorum = self.committee.keys.len() - (self.committee.keys.len() - 1) / 3;
        if received.len() == quorum {
            self.pools.insert(r, received.values().cloned().collect());
        }
        Ok(())
    }
    /// `from` is authenticated by the transport. The deterministic scheduler
    /// fixes it when enqueueing; a production transport must enforce this contract.
    pub fn receive(&mut self, now: u64, from: Id, message: Message) -> Result<Vec<Effect>, String> {
        if from as usize >= self.committee.keys.len() {
            return Err("unknown channel peer".into());
        }
        wire::encode(&message)?;
        match message {
            Message::Batch(record) => {
                self.store.receive(record)?;
            }
            Message::Observation(observation) => {
                self.collect(observation)?;
            }
            Message::Fetch { base, target } => {
                mmr::validate_checkpoint(self.store.config(), &base)?;
                mmr::validate_checkpoint(self.store.config(), &target)?;
                if base.producer as usize >= self.committee.keys.len()
                    || base.producer != target.producer
                    || base.height > target.height
                {
                    return Err("invalid fetch endpoints".into());
                }
                // Endpoint syntax and exact branch membership are also checked by serve.
                let key = suffix_key(&base, &target);
                if !self.served.contains(&(from, key)) {
                    self.pending_requests
                        .entry((from, key))
                        .or_insert((base, target));
                }
            }
            Message::Data(data) => {
                let key = suffix_key(&data.from, &data.to);
                if self.requested.get(&key) != Some(&(data.from.clone(), data.to.clone())) {
                    return Err("unsolicited or mismatched DATA endpoints".into());
                }
                self.store
                    .accept_requested_data(&data.from, &data.to, &data)?;
            }
            Message::DataPart(part) => {
                let key = suffix_key(&part.requested_from, &part.requested_to);
                if self.requested.get(&key)
                    != Some(&(part.requested_from.clone(), part.requested_to.clone()))
                {
                    return Err("unsolicited or mismatched DATA part endpoints".into());
                }
                self.store.accept_requested_part(
                    &part.requested_from,
                    &part.requested_to,
                    &part,
                )?;
            }
        }
        self.retry(now)
    }
    fn retry(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let mut effects = Vec::new();
        let rounds: Vec<_> = self
            .pools
            .keys()
            .copied()
            .filter(|r| !self.input_ready.contains_key(r))
            .collect();
        for r in rounds {
            let sources: Vec<_> = self
                .sources
                .values()
                .filter(|s| s.observation.body.opportunity < r)
                .cloned()
                .collect();
            if let Some((x, pi)) = self.availability.build_with_cache(
                r,
                &self.pools[&r],
                &self.store,
                &sources,
                &self.cached,
            )? {
                self.committee.validate_input_size(&x, &pi)?;
                self.remember(r, &x, &pi)?;
                let next = self.ordering.supply_input(now, r, x, pi)?;
                self.input_ready.insert(r, now);
                effects.push(Effect::Trace(
                    json!({"event":"ordering_input_ready","replica":self.id,"round":r,"at":now}),
                ));
                effects.extend(self.accept_ordering(now, next)?);
            }
        }
        let pending: Vec<_> = self
            .pending_requests
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for ((requester, key), (base, target)) in pending {
            if self.store.holds(&base, &target) {
                // An empty unknown boundary can be logically held but not yet
                // serveable. Retain that request until its opening is available.
                let Ok(parts) = self.store.serve_parts(&base, &target) else {
                    continue;
                };
                let messages: Vec<_> = parts.into_iter().map(Message::DataPart).collect();
                for message in &messages {
                    wire::encode(message)?;
                }
                self.served.insert((requester, key));
                self.pending_requests.remove(&(requester, key));
                for message in messages {
                    effects.push(Effect::Send {
                        to: Some(requester),
                        message,
                    });
                }
            }
        }
        effects.extend(self.materialize(now)?);
        Ok(effects)
    }
    fn accept_ordering(
        &mut self,
        now: u64,
        effects: Vec<OrderingEffect>,
    ) -> Result<Vec<Effect>, String> {
        let mut result = Vec::new();
        for effect in effects {
            if let OrderingEffect::Deliver(delivery) = &effect {
                let descriptor = self.availability.decode_descriptor(&delivery.value)?;
                self.ordered_at.insert(delivery.round, now);
                self.pending_ordered.push_back((delivery.round, descriptor));
            }
            result.push(Effect::Ordering(effect));
        }
        result.extend(self.materialize(now)?);
        Ok(result)
    }
    fn materialize(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let mut effects = Vec::new();
        while let Some((round, descriptor)) = self.pending_ordered.front().cloned() {
            let mut missing = false;
            for (base, target) in descriptor.frontier.iter().zip(&descriptor.targets) {
                if !self.store.holds(base, target) {
                    missing = true;
                    let key = suffix_key(base, target);
                    if !self.requested.contains_key(&key) {
                        self.requested.insert(key, (base.clone(), target.clone()));
                        effects.push(Effect::Send {
                            to: None,
                            message: Message::Fetch {
                                base: base.clone(),
                                target: target.clone(),
                            },
                        });
                    }
                }
            }
            if missing {
                break;
            }
            // Validate the WHOLE frontier and payload expansion before changing
            // execution state. No partial projection of incompatible coordinates.
            let mut records = Vec::new();
            for (k, target) in descriptor.targets.iter().enumerate() {
                let previous = &self.frontier[k];
                let relation = if previous.height <= target.height {
                    self.store.proof(previous, target)
                } else {
                    self.store.proof(target, previous)
                };
                if relation.is_err() {
                    return Err(format!("composition conflict at round {round}, producer {k}: committed frontiers do not share a branch"));
                }
                if target.height > previous.height {
                    for part in self.store.serve_parts(previous, target)? {
                        records.extend(part.data.records);
                    }
                }
            }
            let mut parsed = Vec::new();
            for record in records {
                let transactions: Vec<Transaction> = wire::decode(&record.payload)?;
                parsed.push((record, transactions));
            }
            for (record, transactions) in parsed {
                let digest = record_digest(&record);
                if !self.batch_ids.insert(digest) {
                    continue;
                }
                for tx in transactions {
                    // Application convention: unique transaction IDs execute once;
                    // repeated IDs are deterministic no-ops, even in other batches.
                    if !self.transaction_ids.insert(tx.id) {
                        continue;
                    }
                    self.state = wire::hash(&("execution-step", self.state, tx.id, &tx.bytes));
                    self.executed.push(Executed {
                        round,
                        producer: record.header.body.producer,
                        height: record.header.body.height,
                        batch_digest: digest,
                        transaction: tx.id,
                        state_hash: self.state,
                    });
                }
            }
            for (k, target) in descriptor.targets.into_iter().enumerate() {
                if target.height > self.frontier[k].height {
                    self.frontier[k] = target;
                }
            }
            self.pending_ordered.pop_front();
            self.executed_rounds.push(round);
            self.executed_at.insert(round, now);
            effects.push(Effect::Trace(
                json!({"event":"materialized","replica":self.id,"round":round,
                "at":now,"total_transactions":self.executed.len(),"state_hash":self.state}),
            ));
        }
        Ok(effects)
    }
    pub fn state_hash(&self) -> Digest {
        self.state
    }
    pub fn pending_materialization(&self) -> usize {
        self.pending_ordered.len()
    }
    pub fn served_count(&self) -> usize {
        self.served.len()
    }
    pub fn requested_count(&self) -> usize {
        self.requested.len()
    }
}

fn suffix_key(base: &Checkpoint, target: &Checkpoint) -> Digest {
    wire::hash(&("exact-suffix", base, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::availability::genesis_binding;
    use crate::scanner::Delivery;

    fn node(id: Id) -> Node {
        let c = Committee::new(
            [71; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let mc = mmr::Config {
            context: c.context.clone(),
            chunk_capacity: 4,
        };
        let a = AvailabilityConfig::new(
            c.clone(),
            4,
            (1..=4).map(|r| genesis_binding(&mc, r, 4)).collect(),
        )
        .unwrap();
        Node::new(c, id, wire::fixture_key(id), 100, a, 4).unwrap()
    }
    fn payload(tag: u8) -> Vec<u8> {
        wire::encode(&vec![Transaction {
            id: [tag; 32],
            bytes: vec![tag; 4],
        }])
        .unwrap()
    }
    fn deliver(
        node: &mut Node,
        round: u64,
        targets: Vec<Checkpoint>,
    ) -> Result<Vec<Effect>, String> {
        let base = node.availability.binding(round).unwrap();
        let x = Descriptor {
            base: base.identity,
            frontier: base.frontier.clone(),
            targets,
        };
        node.accept_ordering(
            round,
            vec![OrderingEffect::Deliver(Delivery {
                round,
                digest: [round as u8; 32],
                value: wire::encode(&x).unwrap(),
            })],
        )
    }
    #[test]
    fn report_never_resigns_after_later_payload_and_keeps_custody() {
        let mut n = node(0);
        n.produce(0, payload(1)).unwrap();
        n.report(1, 1).unwrap();
        let signed = n.observations[&1].clone();
        n.produce(2, payload(2)).unwrap();
        assert!(n.report(3, 1).unwrap().is_empty());
        assert_eq!(n.observations[&1], signed);
        assert_eq!(signed.body.coordinates[0].checkpoint.height, 1);
        assert!(n.store.custody_count() > 0);
    }
    #[test]
    fn invalid_data_is_atomic_and_valid_retry_materializes_once() {
        let mut source = node(1);
        let mut receiver = node(0);
        source.produce(0, payload(1)).unwrap();
        let mut targets = receiver.frontier.clone();
        targets[1] = source.store.checkpoints(1).pop().unwrap();
        let effects = deliver(&mut receiver, 1, targets.clone()).unwrap();
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                message: Message::Fetch { .. },
                ..
            }
        )));
        let part = source
            .store
            .serve_parts(&receiver.frontier[1], &targets[1])
            .unwrap()
            .remove(0);
        let mut bad = part.clone();
        bad.data.records[0].payload[0] ^= 1;
        assert!(receiver.receive(2, 1, Message::DataPart(bad)).is_err());
        assert!(receiver.executed.is_empty());
        assert_eq!(receiver.store.record_count(), 0);
        let mut wrong = part.clone();
        wrong.requested_to = wrong.requested_from.clone();
        assert!(receiver.receive(2, 1, Message::DataPart(wrong)).is_err());
        receiver
            .receive(2, 1, Message::DataPart(part.clone()))
            .unwrap();
        assert_eq!(receiver.executed.len(), 1);
        receiver.receive(3, 1, Message::DataPart(part)).unwrap();
        assert_eq!(receiver.executed.len(), 1);
        assert_eq!(receiver.executed_rounds, [1]);
    }
    #[test]
    fn fetch_waits_for_payload_and_serves_once_even_with_duplicates() {
        let mut holder = node(0);
        let mut producer = node(1);
        producer.produce(0, payload(2)).unwrap();
        let base = holder.frontier[1].clone();
        let target = producer.store.checkpoints(1).pop().unwrap();
        let request = Message::Fetch {
            base: base.clone(),
            target: target.clone(),
        };
        assert!(holder.receive(0, 2, request.clone()).unwrap().is_empty());
        assert_eq!(holder.pending_requests.len(), 1);
        let data = producer.store.serve(&base, &target).unwrap();
        let effects = holder
            .receive(1, 1, Message::Batch(data.records[0].clone()))
            .unwrap();
        assert_eq!(
            effects
                .iter()
                .filter(|e| matches!(
                    e,
                    Effect::Send {
                        message: Message::DataPart(_),
                        ..
                    }
                ))
                .count(),
            1
        );
        assert!(holder.receive(2, 2, request).unwrap().is_empty());
        assert_eq!(holder.served_count(), 1);
        assert!(holder.pending_requests.is_empty());
        // An equal unknown endpoint has no payload obligation, but still needs
        // an authenticated boundary to construct a DATA response.
        let mut other = node(0);
        assert!(other
            .receive(
                0,
                2,
                Message::Fetch {
                    base: target.clone(),
                    target
                }
            )
            .unwrap()
            .is_empty());
        assert_eq!(other.pending_requests.len(), 1);
    }
    #[test]
    fn incompatible_committed_frontier_halts_before_any_partial_execution() {
        let mut n = node(0);
        let mut alpha = node(3);
        let mut beta = node(3);
        alpha.produce(0, payload(1)).unwrap();
        beta.produce(0, payload(2)).unwrap();
        let a = alpha.store.checkpoints(3).pop().unwrap();
        let b = beta.store.checkpoints(3).pop().unwrap();
        let genesis = n.frontier[3].clone();
        n.store
            .accept_data(&alpha.store.serve(&genesis, &a).unwrap())
            .unwrap();
        n.store
            .accept_data(&beta.store.serve(&genesis, &b).unwrap())
            .unwrap();
        let mut targets = n.frontier.clone();
        targets[3] = a;
        deliver(&mut n, 1, targets).unwrap();
        let before = n.executed.clone();
        let state = n.state_hash();
        // The earlier producer's new data must not leak into execution before
        // discovering producer three's incompatible coordinate.
        n.produce(2, payload(9)).unwrap();
        let mut targets = n.frontier.clone();
        targets[0] = n.store.checkpoints(0).pop().unwrap();
        targets[3] = b;
        assert!(deliver(&mut n, 2, targets)
            .unwrap_err()
            .contains("composition conflict"));
        assert_eq!(n.executed, before);
        assert_eq!(n.state_hash(), state);
        assert_eq!(n.executed_rounds, [1]);
        assert_eq!(n.pending_materialization(), 1);
    }
}
