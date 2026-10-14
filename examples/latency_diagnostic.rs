//! Virtual-time latency diagnosis using the unchanged composed protocol.
//! No CPU, bandwidth, TCP/kernel, or process scheduling time is modeled.
use delugi::availability::{AvailabilityConfig, Descriptor};
use delugi::composed::{self, Effect, Node, Transaction};
use delugi::replica::Effect as OrderingEffect;
use delugi::simulation::message_kind;
use delugi::wire::{self, Committee, Digest, Id};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::Instant;

const N: Id = 4;
const MAX_EVENTS: u64 = 250_000;
const MAX_WALL_SECONDS: u64 = 180;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Transport {
    Pipelined,
    StopAndWait,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Config {
    transport: Transport,
    delta_ms: u64,
    bound_ms: u64,
    until_ms: u64,
    warmup_ms: u64,
    batch_ms: u64,
}

#[derive(Default)]
struct Links {
    free_at: BTreeMap<(Id, Id), u64>,
}
impl Links {
    fn schedule(&mut self, config: Config, from: Id, to: Id, now: u64) -> (u64, u64) {
        let start = if config.transport == Transport::StopAndWait {
            now.max(*self.free_at.get(&(from, to)).unwrap_or(&0))
        } else {
            now
        };
        if config.transport == Transport::StopAndWait {
            self.free_at.insert((from, to), start + 2 * config.delta_ms);
        }
        (start, start + config.delta_ms)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Serialize)]
struct Packet {
    from: Id,
    to: Id,
    layer: Layer,
    kind: String,
    index: u64,
    queued_at_ms: u64,
    send_start_ms: u64,
    arrives_at_ms: u64,
    bytes: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct Round {
    replica: Id,
    round: u64,
    admission_at_ms: Option<u64>,
    proposal_at_ms: Option<u64>,
    own_cer_at_ms: Option<u64>,
    received_cers: Vec<(Id, u64)>,
    direct_commit_at_ms: Option<u64>,
    ordered_release_at_ms: Option<u64>,
    materialization_at_ms: Option<u64>,
    main_timer_arm_at_ms: Option<u64>,
    main_deadline_ms: Option<u64>,
    main_timer_expiry_at_ms: Option<u64>,
    catchup_timer_arm_at_ms: Option<u64>,
    catchup_deadline_ms: Option<u64>,
    catchup_timer_expiry_at_ms: Option<u64>,
    no_cer_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct Submitted {
    transaction: Digest,
    producer: Id,
    height: u64,
    insertion_at_ms: u64,
    first_proposal_round: Option<u64>,
    first_proposal_at_ms: Option<u64>,
}

#[derive(Serialize)]
struct Completion {
    transaction: Digest,
    origin: Id,
    replica: Id,
    height: u64,
    insertion_at_ms: u64,
    first_proposal_round: u64,
    first_proposal_at_ms: u64,
    execution_round: u64,
    execution_proposal_at_ms: u64,
    direct_commit_at_ms: Option<u64>,
    ordered_release_at_ms: u64,
    materialization_at_ms: u64,
    local_origin: bool,
    in_completion_window: bool,
}

struct Run {
    config: Config,
    nodes: Vec<Node>,
    events: BTreeMap<(u64, u64), Event>,
    event_sequence: u64,
    events_processed: u64,
    now: u64,
    links: Links,
    packets: Vec<Packet>,
    trace: Vec<Value>,
    rounds: BTreeMap<(Id, u64), Round>,
    proposals: BTreeMap<u64, u64>,
    submitted: BTreeMap<Digest, Submitted>,
    materialized: BTreeMap<(Id, Digest), (u64, u64)>,
    executed_cursor: [usize; N as usize],
    timer_wakes: BTreeSet<(Id, u64)>,
}

impl Run {
    fn schedule(&mut self, at: u64, event: Event) {
        self.events.insert((at, self.event_sequence), event);
        self.event_sequence += 1;
    }

    fn round(&mut self, replica: Id, round: u64) -> &mut Round {
        self.rounds
            .entry((replica, round))
            .or_insert_with(|| Round {
                replica,
                round,
                ..Round::default()
            })
    }

    fn send(
        &mut self,
        from: Id,
        to: Option<Id>,
        layer: Layer,
        kind: &str,
        index: u64,
        bytes: Vec<u8>,
    ) {
        let recipients = to.map_or_else(|| (0..N).collect(), |id| vec![id]);
        for to in recipients {
            // Node has already processed all local protocol effects atomically.
            if from == to {
                continue;
            }
            let (start, arrival) = self.links.schedule(self.config, from, to, self.now);
            self.packets.push(Packet {
                from,
                to,
                layer,
                kind: kind.into(),
                index,
                queued_at_ms: self.now,
                send_start_ms: start,
                arrives_at_ms: arrival,
                bytes: bytes.len(),
            });
            self.schedule(
                arrival,
                Event::Packet {
                    from,
                    to,
                    layer,
                    bytes: bytes.clone(),
                },
            );
        }
    }

    fn observe_proposal(&mut self, from: Id, proposal: &wire::Proposal) -> Result<(), String> {
        let round = proposal.header.body.round;
        if self.proposals.insert(round, self.now).is_some() {
            return Err("duplicate proposal".into());
        }
        let descriptor: Descriptor = wire::decode(&proposal.value)?;
        let mut included = Vec::new();
        for (base, target) in descriptor.frontier.iter().zip(&descriptor.targets) {
            if base == target {
                continue;
            }
            for record in self.nodes[from as usize]
                .store
                .local_records(base, target)?
            {
                let transactions: Vec<Transaction> = wire::decode(&record.payload)?;
                for transaction in transactions {
                    let submitted = self
                        .submitted
                        .get_mut(&transaction.id)
                        .ok_or("unknown proposed transaction")?;
                    if submitted.first_proposal_round.is_none() {
                        submitted.first_proposal_round = Some(round);
                        submitted.first_proposal_at_ms = Some(self.now);
                    }
                    included.push(transaction.id);
                }
            }
        }
        self.trace.push(
            json!({"event":"proposal_inclusion","replica":from,"round":round,"at_ms":self.now,
            "transactions":included,"base_round":descriptor.base,
            "base_heights":descriptor.frontier.iter().map(|c|c.height).collect::<Vec<_>>(),
            "target_heights":descriptor.targets.iter().map(|c|c.height).collect::<Vec<_>>()}),
        );
        Ok(())
    }

    fn emit(&mut self, id: Id, effects: Vec<Effect>) -> Result<(), String> {
        let now = self.now;
        for effect in effects {
            match effect {
                Effect::Ordering(effect) => match effect {
                    OrderingEffect::Send { to, message } => {
                        let (kind, round) = message_kind(&message);
                        if let wire::Message::Propose(proposal) = &message {
                            self.observe_proposal(id, proposal)?;
                        }
                        if matches!(message, wire::Message::Cer(_)) {
                            self.round(id, round).own_cer_at_ms = Some(now);
                            self.trace.push(json!({"event":"actual_cer_emitted","replica":id,"round":round,"at_ms":now}));
                        }
                        self.send(
                            id,
                            to,
                            Layer::Ordering,
                            kind,
                            round,
                            wire::encode(&message)?,
                        );
                    }
                    OrderingEffect::Wake { at } => {
                        if self.timer_wakes.insert((id, at)) {
                            self.schedule(at, Event::Timer(id));
                        }
                    }
                    OrderingEffect::DirectCommit { round, .. } => {
                        if self
                            .round(id, round)
                            .direct_commit_at_ms
                            .replace(now)
                            .is_some()
                        {
                            return Err("duplicate commitment".into());
                        }
                        self.trace.push(
                            json!({"event":"direct_commit","replica":id,"round":round,"at_ms":now}),
                        );
                    }
                    OrderingEffect::Deliver(delivery) => {
                        self.round(id, delivery.round).ordered_release_at_ms = Some(now);
                        self.trace.push(json!({"event":"ordered_release","replica":id,"round":delivery.round,"at_ms":now}));
                    }
                    OrderingEffect::Notice { kind, round } => {
                        let main = self.nodes[id as usize].ordering.main_deadline(round);
                        let catchup = self.nodes[id as usize].ordering.catchup_deadline(round);
                        let row = self.round(id, round);
                        match kind.as_str() {
                            "admission" => row.admission_at_ms = Some(now),
                            "main_timer_arm" => {
                                row.main_timer_arm_at_ms = Some(now);
                                row.main_deadline_ms = main;
                            }
                            "catchup_timer_arm" => {
                                row.catchup_timer_arm_at_ms = Some(now);
                                row.catchup_deadline_ms = catchup;
                            }
                            "main_timer_expiry" => row.main_timer_expiry_at_ms = Some(now),
                            "catchup_timer_expiry" => row.catchup_timer_expiry_at_ms = Some(now),
                            "no_cer" => row.no_cer_at_ms = Some(now),
                            _ => {}
                        }
                        self.trace
                            .push(json!({"event":kind,"replica":id,"round":round,"at_ms":now}));
                    }
                },
                Effect::Send { to, message } => {
                    let (kind, index) = match &message {
                        composed::Message::Batch(record) => ("BATCH", record.header.body.height),
                        composed::Message::Report { base, .. } => ("REPORT", base.opportunity),
                        composed::Message::Observation(observation) => {
                            ("OBS", observation.body.opportunity)
                        }
                        composed::Message::Fetch { target, .. } => ("FETCH", target.height),
                        composed::Message::Data(data) => ("DATA", data.to.height),
                        composed::Message::DataPart(part) => {
                            ("DATA_PART", part.requested_to.height)
                        }
                    };
                    self.send(
                        id,
                        to,
                        Layer::Dissemination,
                        kind,
                        index,
                        wire::encode(&message)?,
                    );
                }
                Effect::Trace(mut value) => {
                    if value["event"] == "materialized" {
                        let round = value["round"]
                            .as_u64()
                            .ok_or("missing materialization round")?;
                        self.round(id, round).materialization_at_ms = Some(now);
                    }
                    // Keep the protocol's existing timestamp too; at_ms is the diagnostic convention.
                    value["at_ms"] = json!(now);
                    self.trace.push(value);
                }
            }
        }
        for executed in &self.nodes[id as usize].executed[self.executed_cursor[id as usize]..] {
            if self
                .materialized
                .insert((id, executed.transaction), (executed.round, now))
                .is_some()
            {
                return Err("duplicate execution".into());
            }
        }
        self.executed_cursor[id as usize] = self.nodes[id as usize].executed.len();
        Ok(())
    }

    fn execute(config: Config) -> Result<Self, String> {
        if config.delta_ms == 0
            || config.bound_ms <= config.delta_ms
            || config.until_ms > 30_000
            || config.warmup_ms >= config.until_ms
            || config.batch_ms == 0
        {
            return Err("invalid diagnostic configuration".into());
        }
        let committee = Committee::new(
            [94; 32],
            (0..N).map(|id| wire::fixture_key(id).public).collect(),
        )?;
        let availability = AvailabilityConfig::new(committee.clone(), 4)?;
        let nodes = (0..N)
            .map(|id| {
                Node::new(
                    committee.clone(),
                    id,
                    wire::fixture_key(id),
                    config.bound_ms,
                    availability.clone(),
                    4,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut run = Self {
            config,
            nodes,
            events: BTreeMap::new(),
            event_sequence: 0,
            events_processed: 0,
            now: 0,
            links: Links::default(),
            packets: Vec::new(),
            trace: Vec::new(),
            rounds: BTreeMap::new(),
            proposals: BTreeMap::new(),
            submitted: BTreeMap::new(),
            materialized: BTreeMap::new(),
            executed_cursor: [0; N as usize],
            timer_wakes: BTreeSet::new(),
        };
        // Identical inputs and tie order in all six cases; ordering starts at t=0.
        for at in (0..config.until_ms).step_by(config.batch_ms as usize) {
            for producer in 0..N {
                run.schedule(
                    at,
                    Event::Produce {
                        producer,
                        height: at / config.batch_ms + 1,
                    },
                );
            }
        }
        for id in 0..N {
            run.schedule(0, Event::Start(id));
        }
        let started = Instant::now();
        while let Some((&(at, _), _)) = run.events.first_key_value() {
            if at > config.until_ms {
                break;
            }
            run.events_processed += 1;
            if run.events_processed > MAX_EVENTS || started.elapsed().as_secs() > MAX_WALL_SECONDS {
                return Err(format!(
                    "diagnostic resource cap exceeded at virtual {at}ms after {} events",
                    run.events_processed
                ));
            }
            let (_, event) = run.events.pop_first().unwrap();
            run.now = at;
            let id = match &event {
                Event::Packet { to, .. } => *to,
                Event::Timer(id) | Event::Start(id) => *id,
                Event::Produce { producer, .. } => *producer,
            };
            let effects = match event {
                Event::Packet {
                    from, layer, bytes, ..
                } => match layer {
                    Layer::Ordering => {
                        let message: wire::Message = wire::decode(&bytes)?;
                        if let wire::Message::Cer(cer) = &message {
                            run.round(id, cer.body.round).received_cers.push((from, at));
                            run.trace.push(json!({"event":"actual_cer_received","replica":id,"from":from,"round":cer.body.round,"at_ms":at}));
                        }
                        run.nodes[id as usize].receive_ordering(at, message)?
                    }
                    Layer::Dissemination => {
                        run.nodes[id as usize].receive(at, from, wire::decode(&bytes)?)?
                    }
                },
                Event::Timer(_) => {
                    run.timer_wakes.remove(&(id, at));
                    run.nodes[id as usize].tick(at)?
                }
                Event::Start(_) => run.nodes[id as usize].start(at)?,
                Event::Produce { height, .. } => {
                    let transaction = Transaction {
                        id: wire::hash(&("latency-diagnostic", id, height)),
                        bytes: vec![id as u8; 32],
                    };
                    run.submitted.insert(
                        transaction.id,
                        Submitted {
                            transaction: transaction.id,
                            producer: id,
                            height,
                            insertion_at_ms: at,
                            first_proposal_round: None,
                            first_proposal_at_ms: None,
                        },
                    );
                    run.nodes[id as usize].produce(at, wire::encode(&vec![transaction])?)?
                }
            };
            run.emit(id, effects)?;
        }
        for row in run.rounds.values_mut() {
            row.proposal_at_ms = run.proposals.get(&row.round).copied();
        }
        Ok(run)
    }

    fn output(&self) -> Result<Value, String> {
        let mut completions = Vec::new();
        for (&(replica, transaction), &(round, at)) in &self.materialized {
            let submitted = &self.submitted[&transaction];
            let stage = &self.rounds[&(replica, round)];
            completions.push(Completion {
                transaction,
                origin: submitted.producer,
                replica,
                height: submitted.height,
                insertion_at_ms: submitted.insertion_at_ms,
                first_proposal_round: submitted
                    .first_proposal_round
                    .ok_or("execution before proposal inclusion")?,
                first_proposal_at_ms: submitted.first_proposal_at_ms.unwrap(),
                execution_round: round,
                execution_proposal_at_ms: *self
                    .proposals
                    .get(&round)
                    .ok_or("executed round has no proposal")?,
                direct_commit_at_ms: stage.direct_commit_at_ms,
                ordered_release_at_ms: stage
                    .ordered_release_at_ms
                    .ok_or("execution before ordering")?,
                materialization_at_ms: at,
                local_origin: replica == submitted.producer,
                in_completion_window: at >= self.config.warmup_ms && at < self.config.until_ms,
            });
        }
        completions.sort_by_key(|c| (c.insertion_at_ms, c.origin, c.replica));
        let measured: Vec<_> = completions
            .iter()
            .filter(|c| c.local_origin && c.in_completion_window)
            .collect();
        let common = self.nodes.iter().map(|n| n.executed.len()).min().unwrap();
        let agreement = self
            .nodes
            .iter()
            .all(|n| n.executed[..common] == self.nodes[0].executed[..common]);
        if !agreement {
            return Err("executed prefix disagreement".into());
        }
        let mut relations = BTreeMap::<String, Value>::new();
        for kind in [
            "actual_cer_emitted",
            "actual_cer_received",
            "main_timer_expiry",
            "catchup_timer_expiry",
            "no_cer",
        ] {
            let mut counts = BTreeMap::<&str, u64>::from([
                ("before_commit", 0),
                ("same_time_as_commit", 0),
                ("after_commit", 0),
                ("no_commit_by_horizon", 0),
            ]);
            for event in self.trace.iter().filter(|e| e["event"] == kind) {
                let key = (
                    event["replica"].as_u64().unwrap() as Id,
                    event["round"].as_u64().unwrap(),
                );
                let at = event["at_ms"].as_u64().unwrap();
                let relation = match self.rounds[&key].direct_commit_at_ms {
                    None => "no_commit_by_horizon",
                    Some(commit) if at < commit => "before_commit",
                    Some(commit) if at == commit => "same_time_as_commit",
                    Some(_) => "after_commit",
                };
                *counts.get_mut(relation).unwrap() += 1;
            }
            relations.insert(kind.into(), json!(counts));
        }
        let delivered: Vec<_> = self
            .packets
            .iter()
            .filter(|p| p.arrives_at_ms <= self.config.until_ms)
            .collect();
        let summary = json!({
            "local_origin_completion_count":measured.len(),
            "local_origin_completion_tps":measured.len() as f64*1000.0/(self.config.until_ms-self.config.warmup_ms) as f64,
            "insertion_to_materialization_ms":stats(measured.iter().map(|c|c.materialization_at_ms-c.insertion_at_ms)),
            "insertion_to_first_proposal_ms":stats(measured.iter().map(|c|c.first_proposal_at_ms-c.insertion_at_ms)),
            "execution_proposal_to_direct_commit_ms":stats(measured.iter().filter_map(|c|c.direct_commit_at_ms.map(|at|at-c.execution_proposal_at_ms))),
            "direct_commit_to_ordered_release_ms":stats(measured.iter().filter_map(|c|c.direct_commit_at_ms.filter(|at|*at<=c.ordered_release_at_ms).map(|at|c.ordered_release_at_ms-at))),
            "ordered_release_to_materialization_ms":stats(measured.iter().map(|c|c.materialization_at_ms-c.ordered_release_at_ms)),
            "delivered_packet_queue_delay_ms":stats(delivered.iter().map(|p|p.send_start_ms-p.queued_at_ms)),
            "delivered_packet_effective_delay_ms":stats(delivered.iter().map(|p|p.arrives_at_ms-p.queued_at_ms)),
            "delivered_packets_exceeding_Delta":delivered.iter().filter(|p|p.arrives_at_ms-p.queued_at_ms>self.config.bound_ms).count(),
            "event_relations_to_same_round_local_direct_commit":relations,
            "generated_transactions":self.submitted.len(),"pending_local_origin_transactions":self.submitted.len()-completions.iter().filter(|c|c.local_origin).count(),
            "events_processed":self.events_processed,"proposals":self.proposals.len(),"direct_commits":self.rounds.values().filter(|r|r.direct_commit_at_ms.is_some()).count(),
            "packets_emitted":self.packets.len(),"packets_delivered":delivered.len(),"packets_pending_at_horizon":self.packets.len()-delivered.len(),
            "pending_scheduler_events":self.events.len(),"common_execution_prefix_transactions":common,"common_execution_prefix_agreement":agreement,
            "replicas":self.nodes.iter().map(|n|json!({"id":n.id,"current_round":n.ordering.current_round(),"executed":n.executed.len(),"last_delivered":n.ordering.last_delivered(),"pending_materialization":n.pending_materialization(),"state_hash":n.state_hash()})).collect::<Vec<_>>()});
        Ok(
            json!({"schema":1,"status":"passed","classification":"deterministic_zero_cpu_semantic_diagnostic_not_reconstruction_of_real_run",
            "config":self.config,"model":{
                "honest_replicas":N,"transactions_per_batch_per_producer":1,"offered_tx_s":N as u64*1000/self.config.batch_ms,
                "transaction_payload_bytes":32,"protocol":"Unchanged composed::Node with real signatures, serialization, validation and scanner",
                "clock":"Virtual milliseconds; local computation consumes zero modeled time",
                "pipelined":"Each packet arrives at enqueue time plus delta; no per-message ACK gate",
                "stop_and_wait":"One FIFO per directed peer shared by ordering/dissemination; start=max(enqueue,free), arrival=start+delta, free=start+2delta",
                "ack":"Implicit immediate ACK at receipt plus delta return transit; no extra CPU/receiver-inbox wait",
                "completion_window":"Local-origin completions with warmup_ms <= materialization < until_ms; includes older arrivals completed in the window",
                "inclusion":"First proposal suffix containing this exact transaction; execution_round identifies the descriptor that eventually materialized it",
                "timer_relations":"Timestamps compared with same-round local direct commit across full horizon; equal timestamps do not establish causal order",
                "limitations":["No OS processes, real TCP, kernel shaper, bandwidth serialization, cryptographic CPU cost, payload-size effects, or failures",
                    "Models the transport ACK gate, not complete TCP behavior or all overheads of the previous measured run",
                    "Sustained 40 tx/s with small transactions is diagnostic, not a reproduction of the 1000 tx/s benchmark",
                    "No drain after horizon; pending transactions/messages are retained in counts, and completion latency excludes unfinished transactions",
                    "A FIFO backlog can make enqueue-to-receive delay exceed configured Delta; such a run is not a bounded-delay timing proof"]},
            "summary":summary,"transactions":self.submitted.values().collect::<Vec<_>>(),"completions":completions,
            "rounds":self.rounds.values().collect::<Vec<_>>(),"trace":self.trace,"packets":self.packets}),
        )
    }
}

fn stats(values: impl Iterator<Item = u64>) -> Value {
    let mut values: Vec<_> = values.collect();
    values.sort_unstable();
    if values.is_empty() {
        return json!({"count":0,"mean":null,"p50":null,"p99":null,"max":null});
    }
    let percentile = |p: usize| values[(values.len() * p).div_ceil(100).saturating_sub(1)];
    json!({"count":values.len(),"mean":values.iter().sum::<u64>() as f64/values.len() as f64,
        "p50":percentile(50),"p99":percentile(99),"max":values.last().unwrap()})
}

fn main() -> Result<(), String> {
    let mut config = Config {
        transport: Transport::Pipelined,
        delta_ms: 10,
        bound_ms: 100,
        until_ms: 10_000,
        warmup_ms: 2_000,
        batch_ms: 100,
    };
    let mut output = None::<PathBuf>;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--transport" => {
                config.transport = match value.as_str() {
                    "pipelined" => Transport::Pipelined,
                    "stop-and-wait" => Transport::StopAndWait,
                    _ => return Err("unknown transport".into()),
                }
            }
            "--bound-ms" => config.bound_ms = value.parse().map_err(|_| "invalid bound")?,
            "--until-ms" => config.until_ms = value.parse().map_err(|_| "invalid horizon")?,
            "--warmup-ms" => config.warmup_ms = value.parse().map_err(|_| "invalid warmup")?,
            "--output" => output = Some(value.into()),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    let output = output.ok_or("--output is required")?;
    if output.exists() {
        return Err("refusing to replace an existing diagnostic output".into());
    }
    let run = Run::execute(config)?;
    let value = run.output()?;
    std::fs::write(
        &output,
        serde_json::to_vec(&value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"output":output,"config":config,"summary":value["summary"]})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(transport: Transport) -> Config {
        Config {
            transport,
            delta_ms: 10,
            bound_ms: 1000,
            until_ms: 400,
            warmup_ms: 100,
            batch_ms: 100,
        }
    }
    #[test]
    fn fifo_ack_gate_is_shared_per_directed_peer() {
        let c = config(Transport::StopAndWait);
        let mut links = Links::default();
        assert_eq!(links.schedule(c, 0, 1, 0), (0, 10));
        assert_eq!(links.schedule(c, 0, 1, 0), (20, 30));
        assert_eq!(links.schedule(c, 0, 1, 15), (40, 50));
        assert_eq!(links.schedule(c, 0, 2, 0), (0, 10));
        assert_eq!(links.schedule(c, 1, 0, 0), (0, 10));
    }
    #[test]
    fn pipeline_does_not_wait_for_previous_ack() {
        let c = config(Transport::Pipelined);
        let mut links = Links::default();
        assert_eq!(links.schedule(c, 0, 1, 0), (0, 10));
        assert_eq!(links.schedule(c, 0, 1, 0), (0, 10));
        assert_eq!(links.schedule(c, 0, 1, 15), (15, 25));
    }
    #[test]
    fn real_protocol_can_materialize_before_seven_delta_bound() {
        let run = Run::execute(config(Transport::Pipelined)).unwrap();
        let output = run.output().unwrap();
        assert!(
            output["summary"]["local_origin_completion_count"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert_eq!(output["summary"]["common_execution_prefix_agreement"], true);
        assert!(!run.trace.iter().any(|e| e["event"] == "no_cer"));
        assert!(run
            .materialized
            .values()
            .all(|(_, at)| *at < 7 * run.config.bound_ms));
    }
}
