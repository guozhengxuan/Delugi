//! Deterministic semantic experiments over the full ordering state machine.
//!
//! Local transitions take zero modeled time. Every outward message is encoded,
//! queued by (arrival tick, insertion sequence), decoded, and then verified by
//! the receiving replica. These experiments measure neither CPU nor transport
//! performance. The observation horizon stops the scheduler, never round entry.
use crate::replica::{Effect, Replica};
use crate::scanner::Status;
use crate::wire::{self, Committee, Message};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct Config {
    pub nodes: u32,
    pub delta: u64,
    pub bound: u64,
    /// Inputs are available on entry for leader rounds 1 through this endpoint.
    pub rounds: u64,
    pub until: u64,
    /// This replica neither starts nor receives; sends to it are still charged.
    pub silent: Option<u32>,
    pub duplicate_packets: bool,
    pub delays: Vec<DelayRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            nodes: 4,
            delta: 10,
            bound: 100,
            rounds: 4,
            until: 800,
            silent: None,
            duplicate_packets: false,
            delays: Vec::new(),
        }
    }
}

/// Add deterministic delay to matching packets. Round is the original statement
/// round (endpoint h for HISTORY3 and CLOSED), not its communication charge.
#[derive(Clone, Debug, Serialize)]
pub struct DelayRule {
    pub from: Option<u32>,
    pub to: Option<u32>,
    pub kind: Option<String>,
    pub round: Option<u64>,
    pub extra: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SentPacket {
    pub from: u32,
    pub to: u32,
    pub sent_at: u64,
    pub arrives_at: u64,
    pub kind: String,
    pub round: u64,
    pub bytes: usize,
    pub x_bytes: usize,
    pub pi_bytes: usize,
    pub injected_duplicate: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EmittedMessage {
    pub from: u32,
    pub to: Option<u32>,
    pub at: u64,
    pub message: Message,
}

enum Event {
    Packet { to: u32, bytes: Vec<u8> },
    Timer { node: u32 },
}

pub struct Run {
    pub config: Config,
    pub nodes: Vec<Replica>,
    pub trace: Vec<Value>,
    pub sends: Vec<SentPacket>,
    pub messages: Vec<EmittedMessage>,
    pub direct_commits: BTreeMap<(u32, u64), u64>,
    pub proposal_times: BTreeMap<u64, u64>,
    events: BTreeMap<(u64, u64), Event>,
    sequence: u64,
    now: u64,
}

pub fn input(round: u64) -> (Vec<u8>, Vec<u8>) {
    (
        format!("ordering-reference-value-{round}").into_bytes(),
        format!("ordering-reference-witness-{round}").into_bytes(),
    )
}

fn external_validity(round: u64, value: &[u8], witness: &[u8]) -> bool {
    let expected = input(round);
    value == expected.0 && witness == expected.1
}

pub fn run(config: Config) -> Result<Run, String> {
    if config.delta == 0 || config.delta >= config.bound {
        return Err("require 0 < delta < bound".into());
    }
    if config.rounds == 0 || config.rounds > 10_000 || config.until > u64::MAX / 2 {
        return Err("require 1..=10000 workload rounds and a bounded observation horizon".into());
    }
    if config.bound > u64::MAX / 100 || config.silent.is_some_and(|id| id >= config.nodes) {
        return Err("invalid timer bound or silent replica".into());
    }
    if config.nodes != 4 && config.nodes != 7 {
        return Err("this fixture supports 4 or 7 replicas".into());
    }
    let keys: Vec<_> = (0..config.nodes).map(wire::fixture_key).collect();
    let committee = Committee::new([2; 32], keys.iter().map(|key| key.public).collect())?;
    let nodes = keys
        .into_iter()
        .enumerate()
        .map(|(id, key)| {
            let inputs = (1..=config.rounds)
                .filter(|r| (r - 1) % u64::from(config.nodes) == id as u64)
                .map(|r| (r, input(r)))
                .collect();
            Replica::new(
                committee.clone(),
                id as u32,
                key,
                config.bound,
                inputs,
                external_validity,
            )
        })
        .collect();
    let mut run = Run {
        config,
        nodes,
        trace: Vec::new(),
        sends: Vec::new(),
        messages: Vec::new(),
        direct_commits: BTreeMap::new(),
        proposal_times: BTreeMap::new(),
        events: BTreeMap::new(),
        sequence: 0,
        now: 0,
    };
    for id in 0..run.config.nodes {
        if run.config.silent != Some(id) {
            let effects = run.nodes[id as usize].start(0)?;
            run.emit(id, effects)?;
        }
    }
    while let Some((&(at, _), _)) = run.events.first_key_value() {
        if at > run.config.until {
            break;
        }
        let ((at, _), event) = run.events.pop_first().expect("event exists");
        run.now = at;
        let id = match &event {
            Event::Packet { to, .. } => *to,
            Event::Timer { node } => *node,
        };
        if run.config.silent == Some(id) {
            continue;
        }
        let effects = match event {
            Event::Packet { bytes, .. } => {
                let message: Message = wire::decode(&bytes)?;
                let (kind, round) = message_kind(&message);
                run.trace.push(
                    json!({"event":"receive","replica":id,"at":at,"kind":kind,"round":round}),
                );
                run.nodes[id as usize].receive(at, message)?
            }
            Event::Timer { .. } => {
                run.trace
                    .push(json!({"event":"timer_wake","replica":id,"at":at}));
                run.nodes[id as usize].tick(at)?
            }
        };
        run.emit(id, effects)?;
    }
    Ok(run)
}

impl Run {
    fn schedule(&mut self, at: u64, event: Event) -> Result<(), String> {
        self.events.insert((at, self.sequence), event);
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("event sequence overflow")?;
        Ok(())
    }

    fn emit(&mut self, id: u32, effects: Vec<Effect>) -> Result<(), String> {
        for effect in effects {
            match effect {
                Effect::Send { to, message } => self.send(id, to, message)?,
                Effect::Wake { at } => {
                    if at < self.now {
                        return Err("replica scheduled a timer in the past".into());
                    }
                    self.schedule(at, Event::Timer { node: id })?;
                }
                Effect::DirectCommit { round, digest } => {
                    if self.direct_commits.insert((id, round), self.now).is_some() {
                        return Err("duplicate direct-commit notification".into());
                    }
                    self.trace.push(json!({"event":"direct_commit","replica":id,
                        "round":round,"digest":digest,"at":self.now}));
                }
                Effect::Deliver(delivery) => {
                    self.trace.push(json!({"event":"ordered_descriptor_delivery","replica":id,
                        "round":delivery.round,"digest":delivery.digest,"value":delivery.value,"at":self.now}));
                }
                Effect::Notice { kind, round } => {
                    self.trace
                        .push(json!({"event":kind,"replica":id,"round":round,"at":self.now}));
                }
            }
        }
        Ok(())
    }

    fn send(&mut self, from: u32, target: Option<u32>, message: Message) -> Result<(), String> {
        let bytes = wire::encode(&message)?;
        let (kind, round) = message_kind(&message);
        if kind == "PROPOSE" && self.proposal_times.insert(round, self.now).is_some() {
            return Err("multiple proposals in an honest fixture round".into());
        }
        let (x_bytes, pi_bytes) = match &message {
            Message::Propose(p) => (p.value.len(), p.witness.len()),
            Message::Vote { value, .. } => (value.as_ref().map_or(0, Vec::len), 0),
            _ => (0, 0),
        };
        self.messages.push(EmittedMessage {
            from,
            to: target,
            at: self.now,
            message: message.clone(),
        });
        if target.is_some_and(|id| id >= self.config.nodes) {
            return Err("send target is outside the committee".into());
        }
        let recipients: Vec<_> = match target {
            Some(to) => vec![to],
            None => (0..self.config.nodes).collect(),
        };
        for to in recipients {
            // The engine synchronously self-delivers both unicast and multicast.
            if from == to {
                continue;
            }
            let mut arrival = self
                .now
                .checked_add(self.config.delta)
                .ok_or("arrival overflow")?;
            for rule in &self.config.delays {
                if rule.from.is_none_or(|id| id == from)
                    && rule.to.is_none_or(|id| id == to)
                    && rule.kind.as_deref().is_none_or(|k| k == kind)
                    && rule.round.is_none_or(|r| r == round)
                {
                    arrival = arrival.checked_add(rule.extra).ok_or("delay overflow")?;
                }
            }
            let copies = if self.config.duplicate_packets { 2 } else { 1 };
            for copy in 0..copies {
                let arrives_at = arrival
                    .checked_add(copy)
                    .ok_or("duplicate arrival overflow")?;
                let packet = SentPacket {
                    from,
                    to,
                    sent_at: self.now,
                    arrives_at,
                    kind: kind.into(),
                    round,
                    bytes: bytes.len(),
                    x_bytes,
                    pi_bytes,
                    injected_duplicate: copy > 0,
                };
                self.trace
                    .push(json!({"event":"send","kind":kind,"round":round,
                    "charged_index":if matches!(kind,"HISTORY3"|"CLOSED") {round+3} else {round},
                    "from":from,"to":to,"at":self.now,"arrives_at":arrives_at,
                    "bytes":packet.bytes,"x_bytes":x_bytes,"pi_bytes":pi_bytes,
                    "injected_duplicate":packet.injected_duplicate}));
                self.sends.push(packet);
                self.schedule(
                    arrives_at,
                    Event::Packet {
                        to,
                        bytes: bytes.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> Value {
        let correct: Vec<_> = (0..self.config.nodes)
            .filter(|id| self.config.silent != Some(*id))
            .collect();
        let expected_rounds: Vec<_> = (1..=self.config.rounds)
            .filter(|round| {
                self.config.silent != Some(((round - 1) % u64::from(self.config.nodes)) as u32)
            })
            .collect();
        let first = &self.nodes[correct[0] as usize];
        let pass = correct.iter().all(|id| {
            let node = &self.nodes[*id as usize];
            node.deliveries() == first.deliveries()
                && node
                    .deliveries()
                    .iter()
                    .map(|d| d.round)
                    .collect::<Vec<_>>()
                    == expected_rounds
                && expected_rounds.iter().all(|r| node.committed(*r).is_some())
                && (1..=self.config.rounds).all(|r| {
                    self.config.silent != Some(((r - 1) % u64::from(self.config.nodes)) as u32)
                        || node.statuses().get(&r) == Some(&Status::Skip)
                })
        });
        let bytes: usize = self.sends.iter().map(|s| s.bytes).sum();
        let x_bytes: usize = self.sends.iter().map(|s| s.x_bytes).sum();
        let pi_bytes: usize = self.sends.iter().map(|s| s.pi_bytes).sum();
        let commits: Vec<_> = correct
            .iter()
            .map(|id| {
                json!({"replica":id,
            "direct_commit_at":self.direct_commits.get(&(*id,1)),
            "by_round":self.direct_commits.iter().filter(|((node,_),_)| node==id)
                .map(|((_,round),at)| json!({"round":round,"at":at})).collect::<Vec<_>>(),
            "current_round":self.nodes[*id as usize].current_round(),
            "last_delivered":self.nodes[*id as usize].last_delivered(),
            "deliveries":self.nodes[*id as usize].deliveries(),
            "statuses":self.nodes[*id as usize].statuses()})
            })
            .collect();
        json!({"schema":2,"experiment":"multi-round-ordering","classification":"deterministic_semantic_trace",
            "scope":"full ordering with immutable fixture inputs; ordered descriptor delivery, no application execution or measured network performance",
            "config":self.config,"n":self.config.nodes,"f":(self.config.nodes-1)/3,
            "delta_ticks":self.config.delta,"Delta_ticks":self.config.bound,
            "silent_replica":self.config.silent,"observed_until":self.config.until,
            "last_processed_at":self.now,"pass":pass,"expected_delivered_rounds":expected_rounds,
            "cryptography":"Ed25519 + SHA-256, deterministic PUBLIC TEST keys",
            "input_readiness":"valid inputs ready at entry only through configured workload endpoint; round admission remains uncapped",
            "event_order":"arrival tick, then insertion sequence; engine self-delivery synchronous and uncharged",
            "proposal_times":self.proposal_times,"commits":commits,
            "network_serialized_bytes":bytes,"network_sends":self.sends.len(),
            "protocol_nonself_sends":self.sends.iter().filter(|s|!s.injected_duplicate).count(),
            "injected_duplicate_bytes":self.sends.iter().filter(|s|s.injected_duplicate).map(|s|s.bytes).sum::<usize>(),
            "accounting":"all nonself sends and injected duplicate copies, including silent recipients and beyond-workload control traffic; no transport overhead",
            "x_copy_bytes":x_bytes,"pi_copy_bytes":pi_bytes,
            "internal_and_framing_bytes":bytes-x_bytes-pi_bytes,
            "unfinished_queued_events":self.events.len(),"trace":self.trace,
            "emitted_signed_messages":self.messages,
            "replica_snapshots":correct.iter().map(|id| json!({"replica":id,
                "state":self.nodes[*id as usize].snapshot()})).collect::<Vec<_>>()})
    }
}

pub fn message_kind(message: &Message) -> (&'static str, u64) {
    match message {
        Message::Propose(p) => ("PROPOSE", p.header.body.round),
        Message::Vote { vote, .. } => ("VOTE", vote.body.round),
        Message::Cer(s) => ("CER", s.body.round),
        Message::Prog(s) => ("PROG", s.body.round),
        Message::Closed(s) => ("CLOSED", s.body.round),
        Message::History3(report) => ("HISTORY3", report.header.body.horizon),
    }
}
