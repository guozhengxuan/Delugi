//! Virtual-time client -> BATCH -> OBS/WA -> ordering -> FETCH/DATA ->
//! deterministic materialization. All protocol messages use actual bounded
//! serialization and signature verification. Local CPU and execution take zero
//! modeled time; this is deliberately not a distributed performance benchmark.
use crate::availability::AvailabilityConfig;
use crate::composed::{self, Effect, Node, Transaction};
use crate::mmr;
use crate::replica::Effect as OrderingEffect;
use crate::scanner::Status;
use crate::simulation::message_kind;
use crate::wire::{self, Committee, Id};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub nodes: Id,
    pub rounds: u64,
    pub delta: u64,
    pub bound: u64,
    pub until: u64,
    pub silent: Option<Id>,
    pub chunk_capacity: u64,
    pub transactions_per_batch: u64,
    pub transaction_bytes: usize,
    pub duplicates: bool,
    /// Delay only one producer's original BATCH packets to this receiver.
    /// FETCH/DATA remain independently schedulable.
    pub delayed_payload: Option<PayloadDelay>,
    /// Extra delay on all retrieval DATA responses (not ordering metadata).
    pub data_delay: u64,
    /// Delay full proposals only; proactive VOTE descriptors are still delivered.
    pub proposal_delay_to: Option<Id>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PayloadDelay {
    pub producer: Id,
    pub receiver: Id,
    pub extra: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            nodes: 4,
            rounds: 4,
            delta: 10,
            bound: 100,
            until: 900,
            silent: None,
            chunk_capacity: 4,
            transactions_per_batch: 2,
            transaction_bytes: 32,
            duplicates: false,
            delayed_payload: None,
            data_delay: 0,
            proposal_delay_to: None,
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Send {
    pub from: Id,
    pub to: Id,
    pub at: u64,
    pub arrives_at: u64,
    pub kind: String,
    pub index: u64,
    pub bytes: usize,
    pub x_bytes: usize,
    pub pi_bytes: usize,
    pub payload_bytes: usize,
    pub injected_duplicate: bool,
}
#[derive(Clone, Copy)]
enum Layer {
    Ordering,
    Dissemination,
}
enum Event {
    Packet {
        from: Id,
        to: Id,
        layer: Layer,
        bytes: Vec<u8>,
    },
    Timer(Id),
    Produce {
        producer: Id,
        height: u64,
    },
    Start(Id),
}

pub struct Run {
    pub config: Config,
    pub nodes: Vec<Node>,
    pub trace: Vec<Value>,
    pub sends: Vec<Send>,
    pub messages: Vec<Value>,
    pub proposals: BTreeMap<u64, u64>,
    pub commits: BTreeMap<(Id, u64), u64>,
    events: BTreeMap<(u64, u64), Event>,
    sequence: u64,
    now: u64,
}

pub fn run(config: Config) -> Result<Run, String> {
    if !matches!(config.nodes, 4 | 7)
        || config.rounds == 0
        || config.rounds > 32
        || config.delta == 0
        || config.delta >= config.bound
        || config.bound > 1_000_000
        || config.until > 10_000_000
        || config.transactions_per_batch == 0
        || config.transactions_per_batch > 128
        || config.transaction_bytes > 4096
        || config.silent.is_some_and(|id| id >= config.nodes)
        || config
            .proposal_delay_to
            .is_some_and(|id| id >= config.nodes)
        || config.delayed_payload.as_ref().is_some_and(|d| {
            d.producer >= config.nodes || d.receiver >= config.nodes || d.extra > 10_000_000
        })
        || config.data_delay > 10_000_000
    {
        return Err("invalid bounded end-to-end fixture configuration".into());
    }
    if wire::encode(&transactions(
        0,
        1,
        config.transactions_per_batch,
        config.transaction_bytes,
    ))?
    .len()
        > crate::batch::MAX_BATCH_PAYLOAD
    {
        return Err("configured transactions exceed the per-batch payload limit".into());
    }
    let committee = Committee::new(
        [23; 32],
        (0..config.nodes)
            .map(|id| wire::fixture_key(id).public)
            .collect(),
    )?;
    let mmr_config = mmr::Config {
        context: committee.context.clone(),
        chunk_capacity: config.chunk_capacity,
    };
    mmr_config.validate()?;
    let availability = AvailabilityConfig::new(committee.clone(), config.chunk_capacity)?;
    let nodes = (0..config.nodes)
        .map(|id| {
            let mut node = Node::new(
                committee.clone(),
                id,
                wire::fixture_key(id),
                config.bound,
                availability.clone(),
                config.chunk_capacity,
            )?;
            node.set_opportunity_limit(config.rounds)?;
            Ok::<_, String>(node)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut run = Run {
        config,
        nodes,
        trace: Vec::new(),
        sends: Vec::new(),
        messages: Vec::new(),
        proposals: BTreeMap::new(),
        commits: BTreeMap::new(),
        events: BTreeMap::new(),
        sequence: 0,
        now: 0,
    };
    for r in 1..=run.config.rounds {
        let at = 0;
        for id in 0..run.config.nodes {
            run.schedule(
                at,
                Event::Produce {
                    producer: id,
                    height: r,
                },
            );
        }
    }
    for id in 0..run.config.nodes {
        if run.config.silent != Some(id) {
            // Prepare the finite workload before ordering begins. Delayed
            // payload experiments still leave the selected receiver missing
            // bytes; its automatic REPORT response uses the empty fallback.
            run.schedule(2 * run.config.delta, Event::Start(id));
        }
    }
    while let Some((&(at, _), _)) = run.events.first_key_value() {
        if at > run.config.until {
            break;
        }
        let (_, event) = run.events.pop_first().unwrap();
        run.now = at;
        let id = match &event {
            Event::Packet { to, .. } => *to,
            Event::Timer(id) => *id,
            Event::Produce { producer, .. } => *producer,
            Event::Start(id) => *id,
        };
        if run.config.silent == Some(id) {
            continue;
        }
        let effects = match event {
            Event::Packet {
                from, bytes, layer, ..
            } => match layer {
                Layer::Ordering => {
                    run.nodes[id as usize].receive_ordering(at, wire::decode(&bytes)?)?
                }
                Layer::Dissemination => {
                    run.nodes[id as usize].receive(at, from, wire::decode(&bytes)?)?
                }
            },
            Event::Timer(_) => run.nodes[id as usize].tick(at)?,
            Event::Start(_) => run.nodes[id as usize].start(at)?,
            Event::Produce { height, .. } => {
                let txs = transactions(
                    id,
                    height,
                    run.config.transactions_per_batch,
                    run.config.transaction_bytes,
                );
                run.trace.push(json!({"event":"client_submit_and_batch_emit","replica":id,"height":height,"at":at,
                    "transactions":txs.iter().map(|t|t.id).collect::<Vec<_>>()}));
                run.nodes[id as usize].produce(at, wire::encode(&txs)?)?
            }
        };
        run.emit(id, effects)?;
    }
    Ok(run)
}

pub fn transactions(producer: Id, height: u64, count: u64, size: usize) -> Vec<Transaction> {
    (0..count)
        .map(|i| Transaction {
            id: wire::hash(&("fixture-transaction", producer, height, i)),
            bytes: (0..size)
                .map(|j| (producer as u64 + height + i + j as u64) as u8)
                .collect(),
        })
        .collect()
}

impl Run {
    fn schedule(&mut self, at: u64, event: Event) {
        self.events.insert((at, self.sequence), event);
        self.sequence += 1;
    }
    fn emit(&mut self, id: Id, effects: Vec<Effect>) -> Result<(), String> {
        for effect in effects {
            match effect {
                Effect::Ordering(order) => match order {
                    OrderingEffect::Send { to, message } => {
                        let (kind, r) = message_kind(&message);
                        if kind == "PROPOSE" && self.proposals.insert(r, self.now).is_some() {
                            return Err("duplicate proposal".into());
                        }
                        let (x, pi) = match &message {
                            wire::Message::Propose(p) => (p.value.len(), p.witness.len()),
                            wire::Message::Vote { value, .. } => {
                                (value.as_ref().map_or(0, Vec::len), 0)
                            }
                            _ => (0, 0),
                        };
                        self.messages.push(json!({"from":id,"to":to,"at":self.now,"layer":"ordering","message":message}));
                        self.send(
                            id,
                            to,
                            Layer::Ordering,
                            wire::encode(&message)?,
                            kind,
                            if matches!(kind, "HISTORY3" | "CLOSED") {
                                r + 3
                            } else {
                                r
                            },
                            x,
                            pi,
                            0,
                        )?;
                    }
                    OrderingEffect::Wake { at } => self.schedule(at, Event::Timer(id)),
                    OrderingEffect::DirectCommit { round, digest } => {
                        if self.commits.insert((id, round), self.now).is_some() {
                            return Err("duplicate direct commit".into());
                        }
                        self.trace.push(json!({"event":"direct_commit","replica":id,"round":round,"at":self.now,"digest":digest}));
                    }
                    OrderingEffect::Deliver(d) => self
                        .trace
                        .push(json!({"event":"ordered_descriptor","replica":id,
                        "round":d.round,"at":self.now,"digest":d.digest})),
                    OrderingEffect::Notice { kind, round } => self
                        .trace
                        .push(json!({"event":kind,"replica":id,"round":round,"at":self.now})),
                },
                Effect::Send { to, message } => {
                    let (kind, index, payload) = match &message {
                        composed::Message::Batch(r) => {
                            ("BATCH", r.header.body.height, r.payload.len())
                        }
                        composed::Message::Observation(o) => ("OBS", o.body.opportunity, 0),
                        composed::Message::Report { base, .. } => ("REPORT", base.opportunity, 0),
                        composed::Message::Fetch { target, .. } => ("FETCH", target.height, 0),
                        composed::Message::Data(d) => (
                            "DATA",
                            d.to.height,
                            d.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                        composed::Message::DataPart(p) => (
                            "DATA",
                            p.requested_to.height,
                            p.data.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                    };
                    self.messages.push(json!({"from":id,"to":to,"at":self.now,"layer":"dissemination","message":message}));
                    self.send(
                        id,
                        to,
                        Layer::Dissemination,
                        wire::encode(&message)?,
                        kind,
                        index,
                        0,
                        0,
                        payload,
                    )?;
                }
                Effect::Trace(value) => self.trace.push(value),
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        from: Id,
        to: Option<Id>,
        layer: Layer,
        bytes: Vec<u8>,
        kind: &str,
        index: u64,
        x_bytes: usize,
        pi_bytes: usize,
        payload_bytes: usize,
    ) -> Result<(), String> {
        let recipients: Vec<_> = to.map_or_else(|| (0..self.config.nodes).collect(), |id| vec![id]);
        for recipient in recipients {
            // Local BATCH is stored at production, local OBS collected by report,
            // local ordering delivery drained by the ordering engine, and a local
            // FETCH is unnecessary because materialization checked local holdings.
            if recipient == from {
                continue;
            }
            let mut extra = 0;
            if kind == "BATCH" {
                if let Some(d) = &self.config.delayed_payload {
                    if d.receiver == recipient && d.producer == from {
                        extra += d.extra;
                    }
                }
            }
            if kind == "DATA" {
                extra += self.config.data_delay;
            }
            if kind == "PROPOSE" && self.config.proposal_delay_to == Some(recipient) {
                extra += self.config.until + 1;
            }
            let copies = if self.config.duplicates { 2 } else { 1 };
            for copy in 0..copies {
                let at = self.now + self.config.delta + extra + copy;
                self.sends.push(Send {
                    from,
                    to: recipient,
                    at: self.now,
                    arrives_at: at,
                    kind: kind.into(),
                    index,
                    bytes: bytes.len(),
                    x_bytes,
                    pi_bytes,
                    payload_bytes,
                    injected_duplicate: copy != 0,
                });
                self.schedule(
                    at,
                    Event::Packet {
                        from,
                        to: recipient,
                        layer,
                        bytes: bytes.clone(),
                    },
                );
            }
        }
        Ok(())
    }
    pub fn summary(&self) -> Value {
        let correct: Vec<_> = self
            .nodes
            .iter()
            .filter(|n| self.config.silent != Some(n.id))
            .collect();
        let expected_rounds: Vec<_> = (1..=self.config.rounds)
            .filter(|r| self.config.silent != Some(((r - 1) % u64::from(self.config.nodes)) as Id))
            .collect();
        let expected_transactions = (self.config.nodes as usize
            - usize::from(self.config.silent.is_some()))
            * self.config.rounds as usize
            * self.config.transactions_per_batch as usize;
        let first = correct[0];
        let pass = correct.iter().all(|n| {
            n.executed == first.executed
                && n.executed.len() == expected_transactions
                && n.executed_rounds == expected_rounds
                && n.pending_materialization() == 0
                && n.ordering.deliveries() == first.ordering.deliveries()
                && expected_rounds
                    .iter()
                    .all(|r| n.ordering.committed(*r).is_some())
                && (1..=self.config.rounds).all(|r| {
                    self.config.silent != Some(((r - 1) % u64::from(self.config.nodes)) as Id)
                        || n.ordering.statuses().get(&r) == Some(&Status::Skip)
                })
        });
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for send in &self.sends {
            *by_kind.entry(&send.kind).or_default() += send.bytes;
        }
        let total: usize = self.sends.iter().map(|s| s.bytes).sum();
        let x: usize = self.sends.iter().map(|s| s.x_bytes).sum();
        let pi: usize = self.sends.iter().map(|s| s.pi_bytes).sum();
        let payload: usize = self.sends.iter().map(|s| s.payload_bytes).sum();
        json!({"schema":1,"experiment":"composed-end-to-end","classification":"deterministic_semantic_trace",
            "pass":pass,"config":self.config,"proposal_times":self.proposals,"expected_rounds":expected_rounds,
            "expected_distinct_transactions":expected_transactions,
            "scope":"Option A authenticated bases, autonomous signed REPORT/OBS, all-current construction and exact-batch materialization; honest producers plus optional silent replica",
            "base_contract":"leader chooses greatest locally held earlier direct certificate or genesis; Q checks supplied immutable evidence; Byzantine forks use distinct exact batch identities",
            "readiness":"finite workload emitted at tick 0; ordering begins at 2delta and each leader requests reports on entry; selected delayed BATCH packets remain unavailable; readiness and proposal times logged separately",
            "execution":"ordering round, producer index, height, transaction position; repeated exact batches suppressed; repeated transaction IDs deterministic no-op; zero modeled CPU/service time; indefinite in-memory custody",
            "network_contract":"authenticated scheduler peer IDs; real bounded canonical messages, Ed25519 and SHA-256; eventual old packets; no real transport or wall-clock performance claims",
            "replicas":correct.iter().map(|n|json!({"replica":n.id,"input_ready":n.input_ready,
                "ordered_at":n.ordered_at,"materialized_at":n.executed_at,"executed_rounds":n.executed_rounds,
                "executed":n.executed,"materialized_batches":n.materialized_batches,"cumulative_heights":n.cumulative_heights(),"state_hash":n.state_hash(),"requested_suffixes":n.requested_count(),
                "served_suffixes":n.served_count(),"pending_materialization":n.pending_materialization(),
                "observation_count":n.observations.len(),"ordering":n.ordering.snapshot()})).collect::<Vec<_>>(),
            "bytes_by_kind":by_kind,"network_serialized_bytes":total,"x_copy_bytes":x,"pi_copy_bytes":pi,
            "payload_copy_bytes":payload,"control_and_framing_bytes":total-x-pi-payload,
            "injected_duplicate_bytes":self.sends.iter().filter(|s|s.injected_duplicate).map(|s|s.bytes).sum::<usize>(),
            "accounting":"every nonself send, including silent recipients and arrivals beyond horizon; pi counted only inside actual PROPOSE packets; retrieval/payload separate; transport overhead excluded",
            "sends":self.sends,"trace":self.trace,"messages":self.messages,"pending_events":self.events.len()})
    }
}
