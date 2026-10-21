//! Option A composition: authenticated earlier bases, one signed reporting
//! request per opportunity, all-current availability, and exact-batch output.
//! Faulty producers may contribute multiple branches. Payload storage and custody
//! are retained in memory; cumulative heights never filter unseen batch identities.
use crate::availability::{
    genesis_binding, AvailabilityConfig, BaseCertificate, Descriptor, NamedBase, Observation,
    ReportRequest,
};
use crate::batch::{record_digest, BatchHeader, BatchStore, Data, DataPart, Record};
use crate::causal::Trace as CausalTrace;
use crate::mmr::{self, Checkpoint};
use crate::replica::{Effect as OrderingEffect, Replica};
use crate::wire::{self, Committee, Digest, Id, Signed};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    Batch(Record),
    Report {
        request: Signed<ReportRequest>,
        base: NamedBase,
    },
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

/// Canonical output contains authenticated unsigned fields and ordered payload.
/// Signature encodings authenticate records but are not part of logical output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedBatch {
    pub round: u64,
    pub header: BatchHeader,
    pub payload: Vec<u8>,
}

pub struct Node {
    pub id: Id,
    pub ordering: Replica,
    pub store: BatchStore,
    pub executed: Vec<Executed>,
    pub materialized_batches: Vec<MaterializedBatch>,
    pub executed_rounds: Vec<u64>,
    /// Completion telemetry maintained by this node, not a mutable retry control.
    pub input_ready: BTreeMap<u64, u64>,
    pub ordered_at: BTreeMap<u64, u64>,
    pub executed_at: BTreeMap<u64, u64>,
    pub observations: BTreeMap<u64, Signed<Observation>>,
    pub construction_metrics: crate::availability::ConstructionMetrics,
    /// Optional measurement observer; absent from protocol identities/guards.
    pub output_observed_us: Vec<u64>,
    pub batch_observed_us: Vec<u64>,
    output_clock: Option<Instant>,
    output_receipt_observer: Option<Box<dyn Fn(&Transaction, &mut dyn FnMut()) + Send>>,
    committee: Committee,
    key: Keypair,
    availability: AvailabilityConfig,
    collected: BTreeMap<u64, BTreeMap<Id, Signed<Observation>>>,
    pools: BTreeMap<u64, Vec<Signed<Observation>>>,
    // Frozen pools remain retained; only unfinished input construction is retried.
    pending_input_rounds: BTreeSet<u64>,
    bindings: BTreeMap<u64, NamedBase>,
    report_sent: BTreeSet<u64>,
    opportunity_limit: u64,
    delivered_descriptors: BTreeMap<u64, Digest>,
    pending_ordered: VecDeque<(u64, Descriptor)>,
    cumulative_heights: Vec<u64>,
    requested: BTreeMap<Digest, (Checkpoint, Checkpoint)>,
    pending_requests: BTreeMap<(Id, Digest), (Checkpoint, Checkpoint)>,
    served: BTreeSet<(Id, Digest)>,
    batch_ids: BTreeSet<(Id, u64, Digest)>,
    transaction_ids: BTreeSet<Digest>,
    state: Digest,
    causal: Option<CausalTrace>,
    #[cfg(test)]
    legacy_pool_scan: bool,
    #[cfg(test)]
    retry_pool_checks: usize,
}

impl Node {
    /// Measurement-only synchronization around the exact contiguous append.
    /// The observer must invoke append once; validation and effects stay outside.
    pub fn observe_output_receipts(
        &mut self,
        observer: impl Fn(&Transaction, &mut dyn FnMut()) + Send + 'static,
    ) {
        self.output_receipt_observer = Some(Box::new(observer));
    }
    pub fn observe_output_from(&mut self, clock: Instant) -> Result<(), String> {
        if !self.executed.is_empty() || !self.materialized_batches.is_empty() {
            return Err("output observer must attach before any materialization".into());
        }
        self.output_clock = Some(clock);
        Ok(())
    }
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
        let cumulative_heights = vec![0; committee.keys.len()];
        Ok(Self {
            id,
            ordering,
            store,
            executed: Vec::new(),
            materialized_batches: Vec::new(),
            executed_rounds: Vec::new(),
            input_ready: BTreeMap::new(),
            ordered_at: BTreeMap::new(),
            executed_at: BTreeMap::new(),
            observations: BTreeMap::new(),
            construction_metrics: crate::availability::ConstructionMetrics::default(),
            output_observed_us: Vec::new(),
            batch_observed_us: Vec::new(),
            output_clock: None,
            output_receipt_observer: None,
            committee,
            key,
            availability,
            collected: BTreeMap::new(),
            pools: BTreeMap::new(),
            pending_input_rounds: BTreeSet::new(),
            bindings: BTreeMap::new(),
            report_sent: BTreeSet::new(),
            opportunity_limit: wire::MAX_ROUND,
            delivered_descriptors: BTreeMap::new(),
            pending_ordered: VecDeque::new(),
            cumulative_heights,
            requested: BTreeMap::new(),
            pending_requests: BTreeMap::new(),
            served: BTreeSet::new(),
            batch_ids: BTreeSet::new(),
            transaction_ids: BTreeSet::new(),
            state: wire::hash(&"delugi/deterministic-materialization/v1"),
            causal: None,
            #[cfg(test)]
            legacy_pool_scan: false,
            #[cfg(test)]
            retry_pool_checks: 0,
        })
    }
    pub(crate) fn enable_causal_trace(&mut self, trace: CausalTrace) {
        self.ordering.enable_causal_trace(trace.clone());
        self.causal = Some(trace);
    }
    /// Limit autonomous input opportunities in finite experiments. Ordering
    /// progress remains independent; honest nodes still answer valid REPORTs.
    pub fn set_opportunity_limit(&mut self, last: u64) -> Result<(), String> {
        if last == 0 || last > wire::MAX_ROUND || self.ordering.current_round() != 0 {
            return Err("opportunity limit must be fixed before starting".into());
        }
        self.opportunity_limit = last;
        Ok(())
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
        let (kind, round, _) = crate::causal::ordering_key(&message);
        let ordering_start = self
            .causal
            .as_ref()
            .filter(|t| t.sampled(round))
            .map(CausalTrace::now_us);
        let effects = self.ordering.receive(now, message)?;
        if let Some(start) = ordering_start {
            self.causal.as_ref().unwrap().span(
                "ordering_return",
                round,
                start,
                json!({"kind":kind}),
            );
        }
        let mut result = self.accept_ordering(now, effects)?;
        result.extend(self.retry(now)?);
        Ok(result)
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
    fn leader(&self, round: u64) -> Id {
        ((round - 1) % self.committee.keys.len() as u64) as Id
    }
    fn choose_base(&self, round: u64) -> Result<NamedBase, String> {
        for (header, value, cers) in self.ordering.direct_certificates_before(round) {
            let descriptor = self.availability.decode_descriptor(&value)?;
            let base = NamedBase {
                opportunity: round,
                identity: header.body.round,
                frontier: descriptor.targets,
                authentication: wire::encode(&BaseCertificate {
                    header,
                    value,
                    cers,
                })?,
            };
            self.availability.verify_named_base(&base)?;
            return Ok(base);
        }
        Ok(genesis_binding(
            self.store.config(),
            round,
            self.committee.keys.len(),
        ))
    }
    /// Compatibility hook for callers: only an admitted scheduled leader can
    /// initiate its one signed REPORT. Observations always follow that request.
    pub fn report(&mut self, now: u64, round: u64) -> Result<Vec<Effect>, String> {
        if round == 0 || round > wire::MAX_ROUND {
            return Err("invalid reporting opportunity".into());
        }
        if round > self.opportunity_limit
            || self.leader(round) != self.id
            || round > self.ordering.current_round()
            || self.report_sent.contains(&round)
        {
            return Ok(Vec::new());
        }
        let base = self.choose_base(round)?;
        let request = self.availability.report(&base, &self.key, self.id)?;
        let message = Message::Report {
            request: request.clone(),
            base: base.clone(),
        };
        self.committee.encoded_size(&message)?;
        self.report_sent.insert(round);
        if let Some(trace) = &self.causal {
            trace.mark(
                "dissemination_outbox",
                round,
                json!({"kind":"REPORT","signer":self.id,"to":null,"base":base.identity}),
            );
        }
        let mut effects = vec![Effect::Send { to: None, message }];
        effects.extend(self.answer_report(now, request, base)?);
        effects.extend(self.retry(now)?);
        Ok(effects)
    }
    fn answer_report(
        &mut self,
        now: u64,
        request: Signed<ReportRequest>,
        base: NamedBase,
    ) -> Result<Vec<Effect>, String> {
        // Invalid requests never consume the one-observation opportunity. This
        // handler intentionally does not require local ordering admission.
        self.availability.verify_report(&request, &base)?;
        let round = base.opportunity;
        if self.observations.contains_key(&round) {
            return Ok(Vec::new());
        }
        let observation = self
            .availability
            .observe(&base, &mut self.store, &self.key, self.id)?;
        self.bindings.insert(round, base);
        self.observations.insert(round, observation.clone());
        if let Some(trace) = &self.causal {
            trace.mark(
                "observation_fixed",
                round,
                json!({"base":observation.body.base}),
            );
        }
        let mut effects = vec![Effect::Trace(
            json!({"event":"observation_snapshot", "replica":self.id,
            "round":round,"base":observation.body.base,"at":now,
            "heights":observation.body.coordinates.iter().map(|o|o.checkpoint.height).collect::<Vec<_>>()}),
        )];
        let to = self.leader(round);
        if to == self.id {
            self.collect(observation)?;
        } else {
            if let Some(trace) = &self.causal {
                trace.mark(
                    "dissemination_outbox",
                    round,
                    json!({"kind":"OBS","signer":self.id,"to":to}),
                );
            }
            effects.push(Effect::Send {
                to: Some(to),
                message: Message::Observation(observation),
            });
        }
        Ok(effects)
    }
    fn collect(&mut self, observation: Signed<Observation>) -> Result<(), String> {
        let round = observation.body.opportunity;
        if round == 0 || round > wire::MAX_ROUND || self.leader(round) != self.id {
            return Err("observation addressed to wrong collector".into());
        }
        let base = self
            .bindings
            .get(&round)
            .ok_or("observation has no fixed signed REPORT binding")?;
        self.availability.verify_observation(base, &observation)?;
        if self.pools.contains_key(&round) {
            return Ok(());
        }
        let received = self.collected.entry(round).or_default();
        received.entry(observation.signer).or_insert(observation);
        let quorum = self.committee.keys.len() - (self.committee.keys.len() - 1) / 3;
        if received.len() == quorum {
            self.pools
                .insert(round, received.values().cloned().collect());
            self.pending_input_rounds.insert(round);
            if let Some(trace) = &self.causal {
                trace.mark("observation_pool_fixed", round, json!({}));
            }
        }
        Ok(())
    }
    /// `from` is authenticated by the transport. The deterministic scheduler
    /// fixes it when enqueueing; a production transport must enforce this contract.
    pub fn receive(&mut self, now: u64, from: Id, message: Message) -> Result<Vec<Effect>, String> {
        if from as usize >= self.committee.keys.len() {
            return Err("unknown channel peer".into());
        }
        self.committee.encoded_size(&message)?;
        match message {
            Message::Report { request, base } => {
                let mut effects = self.answer_report(now, request, base)?;
                effects.extend(self.retry(now)?);
                return Ok(effects);
            }
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
    fn pending_pool_rounds(&mut self) -> Vec<u64> {
        #[cfg(test)]
        {
            if self.legacy_pool_scan {
                self.retry_pool_checks += self.pools.len();
                return self
                    .pools
                    .keys()
                    .copied()
                    .filter(|r| !self.input_ready.contains_key(r))
                    .collect();
            }
            self.retry_pool_checks += self.pending_input_rounds.len();
        }
        self.pending_input_rounds
            .iter()
            .copied()
            .filter(|r| !self.input_ready.contains_key(r))
            .collect()
    }
    fn retry(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let mut effects = Vec::new();
        // Keep the original ascending entry snapshot, including when accepting
        // ordering effects recursively constructs an input from another pool.
        let rounds = self.pending_pool_rounds();
        for r in rounds {
            let construction_start = self
                .causal
                .as_ref()
                .filter(|t| t.sampled(r))
                .map(CausalTrace::now_us);
            // Construction consumes the frozen pool and this finite store snapshot
            // exactly once. Every unavailable advance has an immediate empty fallback.
            let (x, pi, construction) = self.availability.build_all_current_with_metrics(
                &self.bindings[&r],
                &self.pools[&r],
                &self.store,
            )?;
            let (value_bytes, witness_bytes) = (x.len(), pi.len());
            if let Some(start) = construction_start {
                self.causal.as_ref().unwrap().span(
                    "input_construct",
                    r,
                    start,
                    json!({"value_bytes":value_bytes,"witness_bytes":witness_bytes,"construction":construction}),
                );
            }
            self.committee.validate_input_size(&x, &pi)?;
            let next = self.ordering.supply_input(now, r, x, pi)?;
            self.input_ready.insert(r, now);
            self.construction_metrics.add(&construction);
            // Errors before input fixation retain the pool for the next retry.
            // Remove before accept_ordering, which can itself call retry.
            self.pending_input_rounds.remove(&r);
            effects.push(Effect::Trace(
                json!({"event":"ordering_input_ready","replica":self.id,"round":r,"at":now,
                    "value_bytes": value_bytes, "witness_bytes": witness_bytes, "construction": construction}),
            ));
            effects.extend(self.accept_ordering(now, next)?);
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
                    self.committee.encoded_size(message)?;
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
        let mut admissions = Vec::new();
        for effect in effects {
            if let OrderingEffect::Deliver(delivery) = &effect {
                let descriptor = self.availability.decode_descriptor(&delivery.value)?;
                let identity = wire::hash(&delivery.value);
                if let Some(previous) = self.delivered_descriptors.get(&delivery.round) {
                    if *previous != identity {
                        return Err("conflicting ordered descriptor for one round".into());
                    }
                    continue;
                }
                if self
                    .delivered_descriptors
                    .keys()
                    .next_back()
                    .map_or(false, |r| *r >= delivery.round)
                {
                    return Err("ordered descriptor rounds must increase".into());
                }
                self.delivered_descriptors.insert(delivery.round, identity);
                self.ordered_at.insert(delivery.round, now);
                self.pending_ordered.push_back((delivery.round, descriptor));
            }
            if let OrderingEffect::Notice { kind, round } = &effect {
                if kind == "admission" {
                    admissions.push(*round);
                }
            }
            result.push(Effect::Ordering(effect));
        }
        result.extend(self.materialize(now)?);
        for round in admissions {
            result.extend(self.report(now, round)?);
        }
        Ok(result)
    }
    fn materialize(&mut self, now: u64) -> Result<Vec<Effect>, String> {
        let materialize_round = self.pending_ordered.front().map(|(r, _)| *r);
        let materialize_start = self
            .causal
            .as_ref()
            .filter(|t| materialize_round.is_some_and(|r| t.sampled(r)))
            .map(CausalTrace::now_us);
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
            // Expand each descriptor's own exact named suffixes in producer then
            // height order. No relation to a previous raw target is required.
            let mut records = Vec::new();
            for (base, target) in descriptor.frontier.iter().zip(&descriptor.targets) {
                if base != target {
                    records.extend(self.store.local_records(base, target)?);
                }
            }
            for record in records {
                let digest = record_digest(record);
                let identity = (
                    record.header.body.producer,
                    record.header.body.height,
                    digest,
                );
                if !self.batch_ids.insert(identity) {
                    continue;
                }
                // Decode only a previously unseen batch. A faulty producer's
                // malformed application payload remains in the common batch log
                // and executes as a no-op.
                let transactions: Vec<Transaction> =
                    wire::decode(&record.payload).unwrap_or_default();
                self.cumulative_heights[identity.0 as usize] =
                    self.cumulative_heights[identity.0 as usize].max(identity.1);
                self.materialized_batches.push(MaterializedBatch {
                    round,
                    header: record.header.body.clone(),
                    payload: record.payload.clone(),
                });
                for tx in transactions {
                    // Application convention: unique transaction IDs execute once;
                    // repeated IDs are deterministic no-ops, even in other batches.
                    if !self.transaction_ids.insert(tx.id) {
                        continue;
                    }
                    let mut appended = false;
                    let mut append = || {
                        assert!(!appended, "output observer attempted a second append");
                        appended = true;
                        self.state = wire::hash(&("execution-step", self.state, tx.id, &tx.bytes));
                        self.executed.push(Executed {
                            round,
                            producer: record.header.body.producer,
                            height: record.header.body.height,
                            batch_digest: digest,
                            transaction: tx.id,
                            state_hash: self.state,
                        });
                        if let Some(clock) = self.output_clock {
                            self.output_observed_us
                                .push(clock.elapsed().as_micros() as u64);
                        }
                    };
                    if let Some(observer) = &self.output_receipt_observer {
                        observer(&tx, &mut append);
                    } else {
                        append();
                    }
                    assert!(appended, "output observer omitted application append");
                }
                if let Some(clock) = self.output_clock {
                    self.batch_observed_us
                        .push(clock.elapsed().as_micros() as u64);
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
        if let Some(start) = materialize_start {
            self.causal.as_ref().unwrap().span(
                "materialize",
                materialize_round.unwrap(),
                start,
                json!({"pending":self.pending_ordered.len()}),
            );
        }
        Ok(effects)
    }
    pub fn cumulative_heights(&self) -> &[u64] {
        &self.cumulative_heights
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
    use crate::scanner::Delivery;

    fn node(id: Id) -> Node {
        let c = Committee::new(
            [71; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap();
        let a = AvailabilityConfig::new(c.clone(), 4).unwrap();
        let mut node = Node::new(c, id, wire::fixture_key(id), 100, a, 4).unwrap();
        node.set_opportunity_limit(4).unwrap();
        node
    }
    fn payload(tag: u8) -> Vec<u8> {
        wire::encode(&vec![Transaction {
            id: [tag; 32],
            bytes: vec![tag; 4],
        }])
        .unwrap()
    }
    fn pool_pair() -> [Node; 2] {
        let indexed = node(0);
        let mut legacy = node(0);
        legacy.legacy_pool_scan = true;
        [indexed, legacy]
    }
    fn assert_pool_pair(pair: &[Node; 2]) {
        let [a, b] = pair;
        assert_eq!(a.ordering.snapshot(), b.ordering.snapshot());
        assert_eq!(a.collected, b.collected);
        assert_eq!(a.pools, b.pools);
        assert_eq!(a.bindings, b.bindings);
        assert_eq!(a.observations, b.observations);
        assert_eq!(a.report_sent, b.report_sent);
        assert_eq!(a.input_ready, b.input_ready);
        assert_eq!(a.pending_input_rounds, b.pending_input_rounds);
        assert_eq!(a.ordered_at, b.ordered_at);
        assert_eq!(a.executed_at, b.executed_at);
        assert_eq!(a.delivered_descriptors, b.delivered_descriptors);
        assert_eq!(a.pending_ordered, b.pending_ordered);
        assert_eq!(a.pending_requests, b.pending_requests);
        assert_eq!(a.requested, b.requested);
        assert_eq!(a.served, b.served);
        assert_eq!(a.executed, b.executed);
        assert_eq!(a.executed_rounds, b.executed_rounds);
        assert_eq!(a.materialized_batches, b.materialized_batches);
        assert_eq!(a.cumulative_heights, b.cumulative_heights);
        assert_eq!(a.batch_ids, b.batch_ids);
        assert_eq!(a.transaction_ids, b.transaction_ids);
        assert_eq!(a.state_hash(), b.state_hash());
        assert_eq!(a.store.record_count(), b.store.record_count());
        assert_eq!(a.store.custody_count(), b.store.custody_count());
        for id in 0..4 {
            assert_eq!(a.store.checkpoints(id), b.store.checkpoints(id));
        }
        for n in pair {
            assert_eq!(
                n.pending_input_rounds,
                n.pools
                    .keys()
                    .copied()
                    .filter(|r| !n.input_ready.contains_key(r))
                    .collect()
            );
        }
    }
    fn observer_for(base: &NamedBase, signer: Id) -> Signed<Observation> {
        let mut observer = node(signer);
        observer
            .availability
            .observe(
                base,
                &mut observer.store,
                &wire::fixture_key(signer),
                signer,
            )
            .unwrap()
    }
    fn freeze_pool(n: &mut Node, round: u64) -> Vec<Effect> {
        let base = genesis_binding(n.store.config(), round, 4);
        let request = n.availability.report(&base, &n.key, n.id).unwrap();
        let effects = n.answer_report(0, request, base.clone()).unwrap();
        for signer in [1, 2] {
            n.collect(observer_for(&base, signer)).unwrap();
        }
        assert!(n.pending_input_rounds.contains(&round));
        effects
    }
    fn paired_retry(pair: &mut [Node; 2], now: u64) -> Result<Vec<Effect>, String> {
        let a = pair[0].retry(now);
        let b = pair[1].retry(now);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_pool_pair(pair);
        a
    }
    fn ready_rounds(effects: &[Effect]) -> Vec<u64> {
        effects
            .iter()
            .filter_map(|e| match e {
                Effect::Trace(value) if value["event"] == "ordering_input_ready" => {
                    value["round"].as_u64()
                }
                _ => None,
            })
            .collect()
    }
    #[test]
    fn pending_pools_match_legacy_order_and_keep_frozen_observations() {
        let mut pair = pool_pair();
        for round in [9, 1, 5] {
            let a = freeze_pool(&mut pair[0], round);
            let b = freeze_pool(&mut pair[1], round);
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_pool_pair(&pair);
        }
        let pools = pair[0].pools.clone();
        let observations = pair[0].observations.clone();
        assert_eq!(
            ready_rounds(&paired_retry(&mut pair, 1).unwrap()),
            [1, 5, 9]
        );
        for n in &mut pair {
            // Later payload arrival and duplicate OBS must not reconstruct input
            // or mutate the quorum/OBS snapshot that fixed it.
            n.produce(2, payload(1)).unwrap();
            n.collect(pools[&1][0].clone()).unwrap();
            let mut malformed = pools[&1][0].clone();
            malformed.signature[0] ^= 1;
            assert!(n.collect(malformed).is_err());
            assert_eq!(n.pools, pools);
            assert_eq!(n.observations, observations);
        }
        assert!(paired_retry(&mut pair, 3).unwrap().is_empty());
    }
    #[test]
    fn failed_pool_construction_retains_unfinished_suffix_for_retry() {
        let mut pair = pool_pair();
        for n in &mut pair {
            for round in [9, 5, 1] {
                freeze_pool(n, round);
            }
        }
        let original = pair[0].pools[&5].clone();
        for n in &mut pair {
            // Test-only corruption of an immutable retained attachment forces
            // failure after round 1 succeeds, without weakening ingress checks.
            n.pools.get_mut(&5).unwrap()[0].signature[0] ^= 1;
        }
        assert!(paired_retry(&mut pair, 1).is_err());
        assert_eq!(pair[0].input_ready.keys().copied().collect::<Vec<_>>(), [1]);
        assert_eq!(pair[0].pending_input_rounds, BTreeSet::from([5, 9]));
        for n in &mut pair {
            n.pools.insert(5, original.clone());
        }
        assert_eq!(ready_rounds(&paired_retry(&mut pair, 2).unwrap()), [5, 9]);
    }
    #[test]
    fn supply_input_failure_keeps_pool_pending_and_frozen() {
        let mut pair = pool_pair();
        for n in &mut pair {
            freeze_pool(n, 5);
            n.ordering.tick(10).unwrap();
        }
        let frozen = pair[0].pools.clone();
        assert_eq!(
            paired_retry(&mut pair, 9).unwrap_err(),
            "local clock moved backwards"
        );
        assert!(pair[0].input_ready.is_empty());
        assert_eq!(pair[0].pending_input_rounds, BTreeSet::from([5]));
        assert_eq!(ready_rounds(&paired_retry(&mut pair, 10).unwrap()), [5]);
        assert_eq!(pair[0].pools, frozen);
    }
    #[test]
    fn retry_visits_unfinished_pools_independent_of_retained_history() {
        let mut pair = pool_pair();
        for n in &mut pair {
            for index in 0..64 {
                freeze_pool(n, 1 + 4 * index);
            }
        }
        assert_eq!(ready_rounds(&paired_retry(&mut pair, 1).unwrap()).len(), 64);
        for n in &mut pair {
            n.retry_pool_checks = 0;
        }
        for now in 2..6 {
            assert!(paired_retry(&mut pair, now).unwrap().is_empty());
        }
        assert_eq!(pair[0].retry_pool_checks, 0);
        assert_eq!(pair[1].retry_pool_checks, 4 * 64);
        for n in &mut pair {
            freeze_pool(n, 257);
            n.retry_pool_checks = 0;
        }
        assert_eq!(ready_rounds(&paired_retry(&mut pair, 6).unwrap()), [257]);
        assert_eq!(pair[0].retry_pool_checks, 1);
        assert_eq!(pair[1].retry_pool_checks, 65);
    }
    #[test]
    fn nested_admission_reports_include_new_pools_in_each_retry_snapshot() {
        let mut pair = pool_pair();
        let mut admissions = Vec::new();
        for n in &mut pair {
            n.set_opportunity_limit(13).unwrap();
            freeze_pool(n, 13);
            freeze_pool(n, 1);
            let mut effects = n.ordering.start(0).unwrap();
            // Retain actual admission effects for accept_ordering below, while
            // arranging two observations before each leader's own REPORT/OBS.
            for signer in [1, 2] {
                effects.extend(
                    n.ordering
                        .receive(
                            0,
                            wire::Message::Prog(wire::sign(
                                &wire::fixture_key(signer),
                                signer,
                                wire::Statement {
                                    context: n.committee.context.clone(),
                                    kind: wire::Kind::Prog,
                                    round: 9,
                                    digest: None,
                                },
                            )),
                        )
                        .unwrap(),
                );
            }
            assert!(n.ordering.current_round() >= 9);
            effects.retain(|e| {
                matches!(e,
                    OrderingEffect::Notice { kind, round: 5 | 9 } if kind == "admission"
                )
            });
            assert_eq!(effects.len(), 2);
            admissions.push(effects);
            for round in [5, 9] {
                let base = genesis_binding(n.store.config(), round, 4);
                n.bindings.insert(round, base.clone());
                for signer in [1, 2] {
                    n.collect(observer_for(&base, signer)).unwrap();
                }
                assert!(!n.pools.contains_key(&round));
            }
        }
        let a = pair[0].accept_ordering(1, admissions.remove(0)).unwrap();
        let b = pair[1].accept_ordering(1, admissions.remove(0)).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        // First REPORT completes pool 5: its nested retry sees [1, 5, 13].
        // The next REPORT completes pool 9 only after that snapshot has drained.
        assert_eq!(ready_rounds(&a), [1, 5, 13, 9]);
        assert_pool_pair(&pair);
    }
    #[test]
    fn pending_pool_selection_preserves_public_completion_containment_check() {
        let mut pair = pool_pair();
        for n in &mut pair {
            freeze_pool(n, 5);
            // Pre-populated telemetry still skips a pending entry, as before.
            // Removing actual completed entries is not a supported retry API.
            n.input_ready.insert(5, 0);
            assert!(n.retry(1).unwrap().is_empty());
            assert!(n.pending_input_rounds.contains(&5));
            n.input_ready.remove(&5);
        }
        assert_eq!(ready_rounds(&paired_retry(&mut pair, 2).unwrap()), [5]);
    }
    #[test]
    fn incoming_size_guard_matches_bounded_encoding_before_mutation() {
        let mut source = node(1);
        let mut receiver = node(0);
        let mut record = source
            .store
            .produce(&source.key, source.id, payload(1))
            .unwrap();
        record.payload = vec![0; wire::MAX_WIRE_BYTES];
        let message = Message::Batch(record);
        let error = wire::encode(&message).unwrap_err();
        assert_eq!(receiver.receive(0, 1, message).unwrap_err(), error);
        assert_eq!(receiver.store.record_count(), 0);
        assert!(receiver.pending_input_rounds.is_empty());
    }
    fn deliver(
        node: &mut Node,
        round: u64,
        targets: Vec<Checkpoint>,
    ) -> Result<Vec<Effect>, String> {
        let base = genesis_binding(node.store.config(), round, 4);
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
    fn causal_trace_does_not_change_both_layer_effects_or_fixed_inputs() {
        let mut traced = node(0);
        let mut plain = node(0);
        plain.legacy_pool_scan = true;
        let trace = CausalTrace::for_test();
        traced.enable_causal_trace(trace.clone());
        let compare = |a: Vec<Effect>, b: Vec<Effect>| {
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
        };
        compare(
            traced.produce(0, payload(1)).unwrap(),
            plain.produce(0, payload(1)).unwrap(),
        );
        let a = traced.start(1).unwrap();
        let b = plain.start(1).unwrap();
        let request = a
            .iter()
            .find_map(|e| match e {
                Effect::Send {
                    message: m @ Message::Report { .. },
                    ..
                } => Some(m.clone()),
                _ => None,
            })
            .unwrap();
        compare(a, b);
        for signer in [1, 2] {
            let mut observer = node(signer);
            let observation = observer
                .receive(2, 0, request.clone())
                .unwrap()
                .into_iter()
                .find_map(|e| match e {
                    Effect::Send {
                        message: m @ Message::Observation(_),
                        ..
                    } => Some(m),
                    _ => None,
                })
                .unwrap();
            compare(
                traced.receive(2, signer, observation.clone()).unwrap(),
                plain.receive(2, signer, observation).unwrap(),
            );
        }
        for signer in [1, 2] {
            let prog = wire::Message::Prog(wire::sign(
                &wire::fixture_key(signer),
                signer,
                wire::Statement {
                    context: traced.committee.context.clone(),
                    kind: wire::Kind::Prog,
                    round: 2,
                    digest: None,
                },
            ));
            compare(
                traced.receive_ordering(3, prog.clone()).unwrap(),
                plain.receive_ordering(3, prog).unwrap(),
            );
        }
        assert_eq!(traced.ordering.snapshot(), plain.ordering.snapshot());
        assert_eq!(traced.observations, plain.observations);
        assert_eq!(traced.input_ready, plain.input_ready);
        assert_eq!(traced.pending_input_rounds, plain.pending_input_rounds);
        assert_eq!(traced.executed, plain.executed);
        assert_eq!(traced.state_hash(), plain.state_hash());
        let counts = trace.summary()["counts"].clone();
        for event in [
            "admission",
            "observation_fixed",
            "input_fixed",
            "proposal_ready",
            "proposal_assembled",
            "ordering_outbox",
            "dissemination_outbox",
        ] {
            assert!(counts[event].as_u64().unwrap_or(0) > 0, "missing {event}");
        }
    }

    #[test]
    fn report_never_resigns_after_later_payload_and_keeps_custody() {
        let mut n = node(0);
        n.produce(0, payload(1)).unwrap();
        n.start(1).unwrap();
        let signed = n.observations[&1].clone();
        n.produce(2, payload(2)).unwrap();
        assert!(n.report(3, 1).unwrap().is_empty());
        assert_eq!(n.observations[&1], signed);
        assert_eq!(signed.body.coordinates[0].checkpoint.height, 1);
        assert!(n.store.custody_count() > 0);
    }
    #[test]
    fn synchronous_produce_retry_latches_admitted_output_before_own_ready_publication() {
        use crate::workload::{self, AdmissionReceipt};
        use std::sync::{Arc, Mutex};
        let instance = [88; 32];
        let bytes = wire::encode(&vec![workload::transaction(instance, 0, 0, 8)]).unwrap();
        let mut source = node(0);
        source.produce(0, bytes.clone()).unwrap();
        let mut full = node(0);
        let mut compact = node(0);
        full.observe_output_from(Instant::now()).unwrap();
        let a = Arc::new(Mutex::new(AdmissionReceipt::new(1)));
        let b = Arc::new(Mutex::new(AdmissionReceipt::new(1)));
        for (node, receipt) in [(&mut full, a.clone()), (&mut compact, b.clone())] {
            receipt.lock().unwrap().admitted.insert(0);
            node.observe_output_receipts(move |_, append| {
                let mut receipt = receipt.lock().unwrap();
                append();
                receipt.materialized(0);
            });
        }
        let mut targets = genesis(&full);
        targets[0] = source.store.checkpoints(0).pop().unwrap();
        deliver(&mut full, 1, targets.clone()).unwrap();
        deliver(&mut compact, 1, targets).unwrap();
        assert!(full.executed.is_empty());
        assert!(compact.executed.is_empty());
        let left = full.produce(2, bytes.clone()).unwrap();
        let right = compact.produce(2, bytes).unwrap();
        assert_eq!(format!("{left:?}"), format!("{right:?}"));
        assert_eq!(full.executed, compact.executed);
        assert_eq!(full.executed.len(), 1);
        for receipt in [&a, &b] {
            let mut receipt = receipt.lock().unwrap();
            assert_eq!(receipt.ready.ones, 0);
            assert_eq!(receipt.completed.ones, 1);
            receipt.mark_ready(0);
            assert_eq!(receipt.ready_pending, 0);
        }
    }
    #[test]
    fn full_and_compact_receipts_preserve_execution_and_latch_before_publication() {
        use crate::workload::{self, AdmissionReceipt};
        use std::sync::{Arc, Mutex};
        let instance = [77; 32];
        let normal = workload::transaction(instance, 0, 0, 8);
        let preplayed = workload::transaction(instance, 0, 1, 8);
        let mut wrong = workload::transaction(instance, 0, 2, 8);
        wrong.bytes[20] ^= 1;
        let mut source = node(1);
        source
            .produce(
                0,
                wire::encode(&vec![normal.clone(), preplayed, wrong, normal]).unwrap(),
            )
            .unwrap();
        source
            .produce(0, wire::encode(&Vec::<Transaction>::new()).unwrap())
            .unwrap();
        source.produce(0, vec![255]).unwrap(); // Exact malformed application no-op.
        let mut full = node(0);
        let mut compact = node(0);
        full.observe_output_from(Instant::now()).unwrap();
        let a = Arc::new(Mutex::new(AdmissionReceipt::new(3)));
        let b = Arc::new(Mutex::new(AdmissionReceipt::new(3)));
        for (node, receipt) in [(&mut full, a.clone()), (&mut compact, b.clone())] {
            {
                let mut r = receipt.lock().unwrap();
                r.admitted.insert(0);
                r.mark_ready(0);
            }
            node.observe_output_receipts(move |tx, append| {
                if let Some((origin, seq, bytes)) = workload::identify(instance, tx) {
                    if origin == 0 && seq < 3 && bytes == 8 {
                        let mut membership = receipt.lock().unwrap();
                        append();
                        membership.materialized(seq);
                        return;
                    }
                }
                append();
            });
        }
        let mut targets = genesis(&full);
        targets[1] = source.store.checkpoints(1).pop().unwrap();
        assert_eq!(
            format!("{:?}", deliver(&mut full, 1, targets.clone()).unwrap()),
            format!("{:?}", deliver(&mut compact, 1, targets.clone()).unwrap())
        );
        for part in source
            .store
            .serve_parts(&genesis(&full)[1], &targets[1])
            .unwrap()
        {
            assert_eq!(
                format!(
                    "{:?}",
                    full.receive(2, 1, Message::DataPart(part.clone())).unwrap()
                ),
                format!(
                    "{:?}",
                    compact.receive(2, 1, Message::DataPart(part)).unwrap()
                )
            );
        }
        // Independent ingress can advance before Runtime publishes handler
        // effects. The append callback already froze preplay eligibility.
        for receipt in [&a, &b] {
            let mut r = receipt.lock().unwrap();
            r.admitted.insert(1);
            r.mark_ready(1);
            assert_eq!(r.completed.ones, 1);
            assert!(!r.completed.contains(1));
            assert!(!r.seen_output.contains(2));
        }
        assert_eq!(full.executed, compact.executed);
        assert_eq!(full.materialized_batches, compact.materialized_batches);
        assert_eq!(full.executed.len(), 3);
        assert_eq!(full.materialized_batches.len(), 3);
        assert_eq!(full.output_observed_us.len(), 3);
        assert!(compact.output_observed_us.is_empty());
        assert!(compact.batch_observed_us.is_empty());
        assert_eq!(
            full.executed
                .iter()
                .fold(workload::output_seed(), workload::output_step),
            compact
                .executed
                .iter()
                .fold(workload::output_seed(), workload::output_step)
        );
        assert_eq!(
            full.materialized_batches
                .iter()
                .fold(workload::batch_seed(), workload::batch_step),
            compact
                .materialized_batches
                .iter()
                .fold(workload::batch_seed(), workload::batch_step)
        );
        assert_ne!(
            compact.materialized_batches[..1]
                .iter()
                .fold(workload::batch_seed(), workload::batch_step),
            compact
                .materialized_batches
                .iter()
                .fold(workload::batch_seed(), workload::batch_step)
        );
    }
    #[test]
    fn append_observer_tracks_verified_output_without_changing_log_or_effects() {
        let mut source = node(1);
        source.produce(0, payload(1)).unwrap();
        let mut plain = node(0);
        let mut observed = node(0);
        let clock = Instant::now();
        observed.observe_output_from(clock).unwrap();
        let mut targets = genesis(&plain);
        targets[1] = source.store.checkpoints(1).pop().unwrap();
        let a = deliver(&mut plain, 1, targets.clone()).unwrap();
        let b = deliver(&mut observed, 1, targets.clone()).unwrap();
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert!(observed.output_observed_us.is_empty());
        let part = source
            .store
            .serve_parts(&genesis(&plain)[1], &targets[1])
            .unwrap()
            .remove(0);
        let a = plain
            .receive(2, 1, Message::DataPart(part.clone()))
            .unwrap();
        let b = observed
            .receive(2, 1, Message::DataPart(part.clone()))
            .unwrap();
        let after = clock.elapsed().as_micros() as u64;
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
        assert_eq!(plain.executed, observed.executed);
        assert_eq!(plain.materialized_batches, observed.materialized_batches);
        assert!(plain.output_observed_us.is_empty());
        assert_eq!(observed.output_observed_us.len(), 1);
        assert_eq!(observed.batch_observed_us.len(), 1);
        assert!(observed.output_observed_us[0] <= observed.batch_observed_us[0]);
        assert!(observed.batch_observed_us[0] <= after);
        observed.receive(3, 1, Message::DataPart(part)).unwrap();
        assert_eq!(observed.output_observed_us.len(), 1);
        assert!(observed.observe_output_from(clock).is_err());
    }
    #[test]
    fn invalid_data_is_atomic_and_valid_retry_materializes_once() {
        let mut source = node(1);
        let mut receiver = node(0);
        source.produce(0, payload(1)).unwrap();
        let mut targets = genesis(&receiver);
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
            .serve_parts(&genesis(&receiver)[1], &targets[1])
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
        let base = genesis(&holder)[1].clone();
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
    fn genesis(node: &Node) -> Vec<Checkpoint> {
        genesis_binding(node.store.config(), 1, 4).frontier
    }
    fn deliver_with_base(
        node: &mut Node,
        round: u64,
        base: u64,
        frontier: Vec<Checkpoint>,
        targets: Vec<Checkpoint>,
    ) -> Result<Vec<Effect>, String> {
        let descriptor = Descriptor {
            base,
            frontier,
            targets,
        };
        node.accept_ordering(
            round,
            vec![OrderingEffect::Deliver(Delivery {
                round,
                digest: [round as u8; 32],
                value: wire::encode(&descriptor).unwrap(),
            })],
        )
    }
    fn copy_suffix(destination: &mut Node, source: &Node, target: &Checkpoint) {
        let base = mmr::genesis(source.store.config(), target.producer);
        destination
            .store
            .accept_data(&source.store.serve(&base, target).unwrap())
            .unwrap();
    }
    fn valid_input(base: &NamedBase, source: &Node, target: &Checkpoint) -> (Vec<u8>, Vec<u8>) {
        let mut holders = [node(0), node(1), node(2)];
        let mut pool = Vec::new();
        for holder in &mut holders {
            copy_suffix(holder, source, target);
            pool.push(
                holder
                    .availability
                    .observe(
                        base,
                        &mut holder.store,
                        &wire::fixture_key(holder.id),
                        holder.id,
                    )
                    .unwrap(),
            );
        }
        let (value, witness) = holders[0]
            .availability
            .build_all_current(base, &pool, &holders[0].store)
            .unwrap();
        assert!(source.availability.q(base.opportunity, &value, &witness));
        let descriptor: Descriptor = wire::decode(&value).unwrap();
        assert_eq!(descriptor.targets[target.producer as usize], *target);
        (value, witness)
    }
    fn complete_proposal(round: u64, value: Vec<u8>, witness: Vec<u8>) -> wire::Proposal {
        let context = node(0).committee.context;
        let history = crate::history::History::Empty;
        let header = wire::Header {
            context,
            round,
            value_hash: wire::hash(&value),
            witness_hash: wire::hash(&witness),
            history_hash: wire::hash(&history),
            entries: crate::history::project(round, &history),
        };
        let leader = ((round - 1) % 4) as Id;
        wire::Proposal {
            header: wire::sign(&wire::fixture_key(leader), leader, header),
            value,
            witness,
            history,
        }
    }
    fn base_certificate(proposal: &wire::Proposal) -> BaseCertificate {
        let digest = wire::proposal_digest(&proposal.header.body);
        let cers = (0..3)
            .map(|id| {
                wire::sign(
                    &wire::fixture_key(id),
                    id,
                    wire::Statement {
                        context: proposal.header.body.context.clone(),
                        kind: wire::Kind::Cer,
                        round: proposal.header.body.round,
                        digest: Some(digest),
                    },
                )
            })
            .collect();
        BaseCertificate {
            header: proposal.header.clone(),
            value: proposal.value.clone(),
            cers,
        }
    }
    #[test]
    fn q_valid_forks_with_authenticated_base_materialize_same_log_everywhere() {
        let mut alpha = node(3);
        let mut beta = node(3);
        alpha.produce(0, payload(1)).unwrap();
        beta.produce(0, payload(1)).unwrap();
        alpha.produce(0, payload(2)).unwrap();
        let a2 = alpha.store.checkpoints(3).pop().unwrap();
        alpha.produce(0, payload(3)).unwrap();
        let a3 = alpha.store.checkpoints(3).pop().unwrap();
        beta.produce(0, payload(4)).unwrap();
        let b2 = beta.store.checkpoints(3).pop().unwrap();
        let base1 = genesis_binding(alpha.store.config(), 1, 4);
        let (x1, pi1) = valid_input(&base1, &alpha, &a2);
        let first = complete_proposal(1, x1, pi1);
        let descriptor: Descriptor = wire::decode(&first.value).unwrap();
        let base2 = NamedBase {
            opportunity: 2,
            identity: 1,
            frontier: descriptor.targets,
            authentication: wire::encode(&base_certificate(&first)).unwrap(),
        };
        let (x2, pi2) = valid_input(&base2, &alpha, &a3);
        let second = complete_proposal(2, x2, pi2);
        let base3 = genesis_binding(alpha.store.config(), 3, 4);
        let (x3, pi3) = valid_input(&base3, &beta, &b2);
        let third = complete_proposal(3, x3, pi3);
        let mut replicas = [node(0), node(1), node(2), node(3)];
        for replica in &mut replicas {
            // Every input is a complete, signed proposal with genuine current
            // observations, MMR proofs, and immutable Q validation. Delivery below
            // isolates the deterministic output contract from ordering scheduling.
            copy_suffix(replica, &alpha, &a3);
            copy_suffix(replica, &beta, &b2);
            for proposal in [&first, &second, &third] {
                replica
                    .committee
                    .verify_proposal(proposal, |r, x, pi| replica.availability.q(r, x, pi))
                    .unwrap();
                let round = proposal.header.body.round;
                replica
                    .accept_ordering(
                        round,
                        vec![OrderingEffect::Deliver(Delivery {
                            round,
                            digest: wire::proposal_digest(&proposal.header.body),
                            value: proposal.value.clone(),
                        })],
                    )
                    .unwrap();
            }
            assert_eq!(
                replica
                    .materialized_batches
                    .iter()
                    .map(|b| b.header.height)
                    .collect::<Vec<_>>(),
                [1, 2, 3, 2]
            );
            assert_eq!(
                replica
                    .executed
                    .iter()
                    .map(|e| e.transaction[0])
                    .collect::<Vec<_>>(),
                [1, 2, 3, 4]
            );
            assert_eq!(replica.cumulative_heights()[3], 3);
        }
        for replica in &replicas[1..] {
            assert_eq!(
                replica.materialized_batches,
                replicas[0].materialized_batches
            );
            assert_eq!(replica.executed, replicas[0].executed);
            assert_eq!(replica.state_hash(), replicas[0].state_hash());
        }
    }
    #[test]
    fn greatest_complete_earlier_certificate_is_eligible_before_payload_execution() {
        let mut source = node(3);
        source.produce(0, payload(1)).unwrap();
        let target = source.store.checkpoints(3).pop().unwrap();
        let mut receiver = node(2);
        for round in [1, 2] {
            let base = genesis_binding(source.store.config(), round, 4);
            let (value, witness) = valid_input(&base, &source, &target);
            let proposal = complete_proposal(round, value, witness);
            let cert = base_certificate(&proposal);
            receiver
                .ordering
                .receive(0, wire::Message::Propose(proposal))
                .unwrap();
            for cer in cert.cers {
                receiver
                    .ordering
                    .receive(0, wire::Message::Cer(cer))
                    .unwrap();
            }
        }
        assert_eq!(receiver.store.record_count(), 0);
        assert!(receiver.executed.is_empty());
        assert_eq!(receiver.choose_base(2).unwrap().identity, 1);
        let chosen = receiver.choose_base(3).unwrap();
        assert_eq!(chosen.identity, 2);
        assert_eq!(chosen.frontier[3], target);
        receiver.availability.verify_named_base(&chosen).unwrap();
        let request = receiver
            .availability
            .report(&chosen, &wire::fixture_key(2), 2)
            .unwrap();
        let effects = receiver.answer_report(1, request, chosen.clone()).unwrap();
        assert!(effects.iter().any(|e| matches!(e, Effect::Trace(_))));
        // Missing base payloads do not prevent empty-suffix observations.
        assert_eq!(
            receiver.observations[&3].body.coordinates[3].checkpoint,
            target
        );
        assert_eq!(receiver.store.record_count(), 0);
    }
    #[test]
    fn byzantine_forks_overlap_and_lower_targets_emit_every_exact_batch_once() {
        let mut n = node(0);
        let mut alpha = node(3);
        let mut beta = node(3);
        // Same first batch, then different signed records at equal heights.
        alpha.produce(0, payload(1)).unwrap();
        beta.produce(0, payload(1)).unwrap();
        alpha.produce(0, payload(2)).unwrap();
        let a2 = alpha.store.checkpoints(3).pop().unwrap();
        alpha.produce(0, payload(3)).unwrap();
        let a3 = alpha.store.checkpoints(3).pop().unwrap();
        beta.produce(0, payload(4)).unwrap();
        let b2 = beta.store.checkpoints(3).pop().unwrap();
        copy_suffix(&mut n, &alpha, &a3);
        copy_suffix(&mut n, &beta, &b2);
        let mut targets = genesis(&n);
        targets[3] = a2.clone();
        deliver(&mut n, 1, targets.clone()).unwrap();
        let mut higher = targets.clone();
        higher[3] = a3;
        // A different authenticated base selects just the next alpha suffix.
        deliver_with_base(&mut n, 2, 1, targets.clone(), higher.clone()).unwrap();
        assert_eq!(n.cumulative_heights()[3], 3);
        let mut lower = genesis(&n);
        lower[3] = b2;
        deliver(&mut n, 3, lower.clone()).unwrap();
        assert_eq!(n.cumulative_heights()[3], 3);
        assert_eq!(
            n.executed
                .iter()
                .map(|e| e.transaction[0])
                .collect::<Vec<_>>(),
            [1, 2, 3, 4]
        );
        assert_eq!(
            n.materialized_batches
                .iter()
                .map(|b| b.header.height)
                .collect::<Vec<_>>(),
            [1, 2, 3, 2]
        );
        let before = n.state_hash();
        // Duplicate deliveries and overlapping already-emitted suffixes are no-ops.
        deliver(&mut n, 3, lower).unwrap();
        deliver(&mut n, 4, higher).unwrap();
        assert_eq!(n.materialized_batches.len(), 4);
        assert_eq!(n.state_hash(), before);
        assert_eq!(n.executed_rounds, [1, 2, 3, 4]);
    }
    #[test]
    fn different_forks_with_repeated_transactions_are_batches_but_application_noops() {
        let mut n = node(0);
        let mut alpha = node(3);
        let mut beta = node(3);
        alpha.produce(0, payload(1)).unwrap();
        let transactions = vec![Transaction {
            id: [1; 32],
            bytes: vec![99; 4],
        }];
        beta.produce(0, wire::encode(&transactions).unwrap())
            .unwrap();
        for (round, source) in [(1, &alpha), (2, &beta)] {
            let target = source.store.checkpoints(3).pop().unwrap();
            copy_suffix(&mut n, source, &target);
            let mut targets = genesis(&n);
            targets[3] = target;
            deliver(&mut n, round, targets).unwrap();
        }
        assert_eq!(n.materialized_batches.len(), 2);
        assert_eq!(n.executed.len(), 1);
        assert_eq!(n.cumulative_heights()[3], 1);
        assert_ne!(
            n.materialized_batches[0].header,
            n.materialized_batches[1].header
        );
    }
    #[test]
    fn malformed_byzantine_payload_is_logged_and_honest_execution_continues() {
        let mut n = node(0);
        let mut faulty = node(3);
        faulty.produce(0, vec![0xff]).unwrap();
        let target = faulty.store.checkpoints(3).pop().unwrap();
        copy_suffix(&mut n, &faulty, &target);
        let mut targets = genesis(&n);
        targets[3] = target;
        deliver(&mut n, 1, targets).unwrap();
        assert_eq!(n.materialized_batches.len(), 1);
        assert!(n.executed.is_empty());
        n.produce(0, payload(1)).unwrap();
        let mut targets = genesis(&n);
        targets[0] = n.store.checkpoints(0).pop().unwrap();
        deliver(&mut n, 2, targets).unwrap();
        assert_eq!(n.materialized_batches.len(), 2);
        assert_eq!(n.executed.len(), 1);
        assert_eq!(n.executed_rounds, [1, 2]);
    }
    #[test]
    fn first_valid_report_is_answered_once_before_ordering_admission() {
        let mut n = node(0);
        n.produce(0, payload(1)).unwrap();
        let base = genesis_binding(n.store.config(), 2, 4);
        let request = n
            .availability
            .report(&base, &wire::fixture_key(1), 1)
            .unwrap();
        let mut bad = request.clone();
        bad.signature[0] ^= 1;
        assert!(n
            .receive(
                1,
                1,
                Message::Report {
                    request: bad,
                    base: base.clone()
                }
            )
            .is_err());
        assert!(n.observations.is_empty());
        let message = Message::Report { request, base };
        let effects = n.receive(2, 1, message.clone()).unwrap();
        assert_eq!(n.ordering.current_round(), 0);
        assert_eq!(n.observations.len(), 1);
        assert!(effects.iter().any(|e| matches!(
            e,
            Effect::Send {
                to: Some(1),
                message: Message::Observation(_)
            }
        )));
        let snapshot = n.observations[&2].clone();
        n.produce(3, payload(2)).unwrap();
        assert!(n.receive(4, 1, message).unwrap().is_empty());
        assert_eq!(n.observations[&2], snapshot);
        assert_eq!(snapshot.body.coordinates[0].checkpoint.height, 1);
    }
    #[test]
    fn signed_report_freezes_pool_and_empty_input_without_waiting_for_payload() {
        let mut leader = node(0);
        let mut reporters = [node(1), node(2), node(3)];
        let mut producer = node(3);
        producer.produce(0, payload(8)).unwrap();
        let checkpoint = producer.store.checkpoints(3).pop().unwrap();
        for reporter in &mut reporters {
            copy_suffix(reporter, &producer, &checkpoint);
        }
        let effects = leader.start(0).unwrap();
        let request = effects
            .into_iter()
            .find_map(|e| match e {
                Effect::Send {
                    message: m @ Message::Report { .. },
                    ..
                } => Some(m),
                _ => None,
            })
            .unwrap();
        let mut proposal = None;
        for reporter in &mut reporters {
            let effects = reporter.receive(1, 0, request.clone()).unwrap();
            let observation = effects
                .into_iter()
                .find_map(|e| match e {
                    Effect::Send {
                        message: m @ Message::Observation(_),
                        ..
                    } => Some(m),
                    _ => None,
                })
                .unwrap();
            for effect in leader.receive(2, reporter.id, observation).unwrap() {
                if let Effect::Ordering(OrderingEffect::Send {
                    message: wire::Message::Propose(p),
                    ..
                }) = effect
                {
                    proposal = Some(p);
                }
            }
        }
        let proposal = proposal.unwrap();
        let descriptor: Descriptor = wire::decode(&proposal.value).unwrap();
        let proof: crate::availability::AvailabilityProof =
            wire::decode(&proposal.witness).unwrap();
        assert_eq!(descriptor.targets, descriptor.frontier);
        assert!(proof.sources.is_empty());
        assert_eq!(proof.pool.len(), 3);
        assert_eq!(leader.pools[&1].len(), 3);
        assert_eq!(leader.input_ready[&1], 2);
        assert_eq!(leader.store.record_count(), 0);
        assert!(reporters.iter().all(|r| r.ordering.current_round() == 0));
    }
    #[test]
    fn output_order_and_state_ignore_record_signature_encoding() {
        // The compared log serializes unsigned headers and ordered payload only.
        let n = node(0);
        let mut source = node(3);
        source.produce(0, payload(1)).unwrap();
        let target = source.store.checkpoints(3).pop().unwrap();
        let data = source.store.serve(&genesis(&n)[3], &target).unwrap();
        let mut record = data.records[0].clone();
        let first = MaterializedBatch {
            round: 1,
            header: record.header.body.clone(),
            payload: record.payload.clone(),
        };
        let digest = record_digest(&record);
        record.header.signature.fill(0);
        let second = MaterializedBatch {
            round: 1,
            header: record.header.body.clone(),
            payload: record.payload.clone(),
        };
        assert_eq!(record_digest(&record), digest);
        assert_eq!(first, second);
        assert_eq!(
            wire::encode(&first).unwrap(),
            wire::encode(&second).unwrap()
        );
        // The altered authentication is still rejected on input.
        let mut receiver = node(0);
        assert!(receiver.receive(0, 3, Message::Batch(record)).is_err());
    }
    #[test]
    fn local_materialization_matches_segmented_transfer_across_large_forks() {
        let mut alpha = node(3);
        let large_payload = |tag| {
            wire::encode(&vec![Transaction {
                id: [tag; 32],
                bytes: vec![tag; crate::batch::MAX_BATCH_PAYLOAD - 48],
            }])
            .unwrap()
        };
        let mut main_records = Vec::new();
        for tag in 1..=3 {
            main_records.push(
                alpha
                    .store
                    .produce(&wire::fixture_key(3), 3, large_payload(tag))
                    .unwrap(),
            );
        }
        let mut beta = node(3);
        beta.store = alpha.store.clone();
        for tag in 4..=7 {
            main_records.push(
                alpha
                    .store
                    .produce(&wire::fixture_key(3), 3, large_payload(tag))
                    .unwrap(),
            );
        }
        let fork_records: Vec<_> = (14..=15)
            .map(|tag| {
                beta.store
                    .produce(&wire::fixture_key(3), 3, large_payload(tag))
                    .unwrap()
            })
            .collect();
        let mut local = node(0);
        let mut transferred = node(0);
        for record in main_records.iter().chain(&fork_records) {
            local.store.receive(record.clone()).unwrap();
        }
        let base = genesis(&local)[3].clone();
        let main_end = alpha.store.checkpoints(3).pop().unwrap();
        let fork_end = beta.store.checkpoints(3).pop().unwrap();
        assert!(
            alpha.store.serve(&base, &main_end).is_err(),
            "fixture must exceed a single DATA frame"
        );
        for (round, source, target) in [
            (1, &alpha, &main_end),
            (2, &beta, &fork_end),
            (3, &alpha, &main_end),
        ] {
            let parts = source.store.serve_parts(&base, target).unwrap();
            assert!(parts.len() > 1);
            let network_records: Vec<_> = parts
                .iter()
                .flat_map(|part| part.data.records.iter())
                .collect();
            assert_eq!(
                source.store.local_records(&base, target).unwrap(),
                network_records
            );
            for part in parts.iter().rev() {
                transferred
                    .store
                    .accept_requested_part(&base, target, part)
                    .unwrap();
            }
            let mut targets = genesis(&local);
            targets[3] = target.clone();
            deliver(&mut local, round, targets.clone()).unwrap();
            deliver(&mut transferred, round, targets).unwrap();
            assert_eq!(local.materialized_batches, transferred.materialized_batches);
            assert_eq!(local.executed, transferred.executed);
            assert_eq!(local.state_hash(), transferred.state_hash());
        }
        assert_eq!(
            local
                .materialized_batches
                .iter()
                .map(|b| b.header.height)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6, 7, 4, 5]
        );
        assert_eq!(
            local
                .executed
                .iter()
                .map(|tx| tx.transaction[0])
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5, 6, 7, 14, 15]
        );
        assert_eq!(local.cumulative_heights()[3], 7);
        assert_eq!(local.executed_rounds, vec![1, 2, 3]);
        let main_four = alpha
            .store
            .checkpoints(3)
            .into_iter()
            .find(|cp| cp.height == 4)
            .unwrap();
        assert!(local.store.local_records(&main_four, &fork_end).is_err());
    }
}
