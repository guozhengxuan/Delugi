//! Independent replica driver with real clocks, authenticated replica TCP and a
//! loopback capability-protected client/control endpoint. This local experiment
//! retains in-memory state and externally authorized named bases; it is not a
//! durable or WAN deployment profile.
use crate::availability::{genesis_binding, AvailabilityConfig};
use crate::composed::{self, Effect, Node};
use crate::end_to_end::transactions;
use crate::mmr;
use crate::replica::Effect as OrderingEffect;
use crate::simulation::message_kind;
use crate::transport::{Layer, Transport, TransportSettings};
use crate::wire::{self, Committee, Digest, Id};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub instance: Digest,
    pub addresses: Vec<SocketAddr>,
    pub control_addresses: Vec<SocketAddr>,
    pub control_token: String,
    pub public_keys: Vec<Vec<u8>>,
    pub key_files: Vec<PathBuf>,
    pub bound_ms: u64,
    pub chunk_capacity: u64,
    pub workload_rounds: u64,
    pub silent: Option<Id>,
    pub max_runtime_ms: u64,
}
impl Config {
    pub fn validate(&self, id: Id) -> Result<Committee, String> {
        let n = self.public_keys.len();
        if !matches!(n, 4 | 7)
            || id as usize >= n
            || self.addresses.len() != n
            || self.control_addresses.len() != n
            || self.key_files.len() != n
            || self.control_token.len() < 32
            || self.bound_ms == 0
            || self.bound_ms > 60_000
            || self.workload_rounds == 0
            || self.workload_rounds > 32
            || self.max_runtime_ms < self.bound_ms * 8
            || self.max_runtime_ms > 600_000
            || self.silent.is_some_and(|s| s as usize >= n)
        {
            return Err("invalid local process configuration".into());
        }
        let mut addresses = BTreeSet::new();
        for address in self.addresses.iter().chain(&self.control_addresses) {
            if !address.ip().is_loopback() || address.port() == 0 || !addresses.insert(*address) {
                return Err("local profile requires distinct nonzero loopback addresses".into());
            }
        }
        let keys = self
            .public_keys
            .iter()
            .map(|bytes| PublicKey::from_bytes(bytes).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let c = Committee::new(self.instance, keys)?;
        mmr::Config {
            context: c.context.clone(),
            chunk_capacity: self.chunk_capacity,
        }
        .validate()?;
        Ok(c)
    }
}

pub fn keygen(directory: &Path, n: usize) -> Result<Value, String> {
    if !matches!(n, 4 | 7) {
        return Err("key generation supports 4 or 7 members".into());
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let mut public_keys = Vec::new();
    let mut key_files = Vec::new();
    let mut entropy = File::open("/dev/urandom").map_err(|e| e.to_string())?;
    for id in 0..n {
        let mut seed = [0; 32];
        entropy.read_exact(&mut seed).map_err(|e| e.to_string())?;
        let secret = SecretKey::from_bytes(&seed).map_err(|e| e.to_string())?;
        public_keys.push(PublicKey::from(&secret).to_bytes().to_vec());
        let path = directory.join(format!("replica-{id}.key"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|e| e.to_string())?;
        file.write_all(&seed).map_err(|e| e.to_string())?;
        key_files.push(fs::canonicalize(path).map_err(|e| e.to_string())?);
    }
    Ok(json!({"public_keys":public_keys,"key_files":key_files}))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    #[serde(rename = "type")]
    kind: String,
    token: String,
    #[serde(default)]
    request_id: Value,
    round: Option<u64>,
    count: Option<u64>,
    size: Option<usize>,
}
struct Request {
    command: Command,
    reply: mpsc::SyncSender<Value>,
}
#[derive(Default)]
struct ControlStats {
    received: AtomicU64,
    sent: AtomicU64,
    rejected: AtomicU64,
}
struct Control {
    requests: mpsc::Receiver<Request>,
    stop: Arc<AtomicBool>,
    stats: Arc<ControlStats>,
    handle: Option<thread::JoinHandle<()>>,
}
impl Control {
    fn bind(address: SocketAddr, token: String) -> Result<Self, String> {
        let listener =
            TcpListener::bind(address).map_err(|e| format!("control bind {address}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(ControlStats::default());
        let (sender, requests) = mpsc::sync_channel(64);
        let flag = stop.clone();
        let metrics = stats.clone();
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        // macOS can inherit O_NONBLOCK from this nonblocking
                        // listener. Timeout-based line reads require blocking I/O.
                        if socket.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
                        let mut bytes = Vec::new();
                        let read = BufReader::new(&mut socket)
                            .take(65_537)
                            .read_until(b'\n', &mut bytes);
                        metrics
                            .received
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        let parsed = if read.is_ok()
                            && bytes.len() <= 65_536
                            && bytes.last() == Some(&b'\n')
                        {
                            serde_json::from_slice::<Command>(&bytes)
                                .map_err(|e| format!("invalid control JSON: {e}"))
                        } else {
                            Err(format!(
                                "incomplete or oversized control frame: {} bytes, read result {:?}",
                                bytes.len(),
                                read
                            ))
                        };
                        let answer = match parsed {
                            Ok(command) if command.token == token => {
                                let (tx, rx) = mpsc::sync_channel(1);
                                match sender.try_send(Request{command,reply:tx}) {
                                    Ok(())=>rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_|json!({"ok":false,"error":"control handler timeout"})),
                                    Err(_)=>json!({"ok":false,"error":"control queue full"}),
                                }
                            }
                            Ok(_) => {
                                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                json!({"ok":false,"error":"unauthorized control request"})
                            }
                            Err(error) => {
                                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                json!({"ok":false,"error":error})
                            }
                        };
                        if let Ok(mut encoded) = serde_json::to_vec(&answer) {
                            encoded.push(b'\n');
                            if socket.write_all(&encoded).is_ok() {
                                metrics
                                    .sent
                                    .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            requests,
            stop,
            stats,
            handle: Some(handle),
        })
    }
    fn snapshot(&self) -> Value {
        json!({"received_bytes":self.stats.received.load(Ordering::Relaxed),
        "sent_bytes":self.stats.sent.load(Ordering::Relaxed),"rejected_requests":self.stats.rejected.load(Ordering::Relaxed)})
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[derive(Clone, Default, Serialize)]
struct Counter {
    messages: u64,
    encoded_bytes: u64,
    x_bytes: u64,
    pi_bytes: u64,
    payload_bytes: u64,
}
impl Counter {
    fn add(&mut self, bytes: usize, x: usize, pi: usize, payload: usize) {
        self.messages += 1;
        self.encoded_bytes += bytes as u64;
        self.x_bytes += x as u64;
        self.pi_bytes += pi as u64;
        self.payload_bytes += payload as u64;
    }
}
struct Runtime {
    config: Config,
    id: Id,
    node: Node,
    transport: Transport,
    control: Control,
    origin: Instant,
    wall_origin: u64,
    timers: BTreeSet<u64>,
    active: bool,
    started: bool,
    quiesced: bool,
    produced: u64,
    emitted_transactions: usize,
    processed_messages: u64,
    post_cutoff_frames: u64,
    silent_ignored_frames: u64,
    by_kind: BTreeMap<String, Counter>,
    by_peer: BTreeMap<Id, Counter>,
    by_index: BTreeMap<u64, Counter>,
    proposals: BTreeMap<u64, u64>,
    commits: BTreeMap<u64, u64>,
    measured_ordered: BTreeMap<u64, u64>,
    measured_materialized: BTreeMap<u64, u64>,
}
impl Runtime {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
    fn log(&self, mut event: Value) -> Result<(), String> {
        event["replica"] = json!(self.id);
        event["observed_unix_us"] = json!(unix_us());
        event["elapsed_us"] = json!(self.origin.elapsed().as_micros() as u64);
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer(&mut out, &event).map_err(|e| e.to_string())?;
        out.write_all(b"\n")
            .and_then(|_| out.flush())
            .map_err(|e| e.to_string())
    }
    fn effects(&mut self, effects: Vec<Effect>) -> Result<(), String> {
        for effect in effects {
            match effect {
                Effect::Ordering(effect) => match effect {
                    OrderingEffect::Send { to, message } => {
                        let (kind, round) = message_kind(&message);
                        let (x, pi) = match &message {
                            wire::Message::Propose(p) => (p.value.len(), p.witness.len()),
                            wire::Message::Vote { value, .. } => {
                                (value.as_ref().map_or(0, Vec::len), 0)
                            }
                            _ => (0, 0),
                        };
                        let bytes = wire::encode(&message)?;
                        self.send(
                            to,
                            Layer::Ordering,
                            bytes,
                            kind,
                            if matches!(kind, "HISTORY3" | "CLOSED") {
                                round + 3
                            } else {
                                round
                            },
                            x,
                            pi,
                            0,
                        )?;
                        if kind == "PROPOSE" {
                            self.proposals.insert(round, unix_us());
                            self.log(json!({"event":"proposal","round":round,"message":message}))?;
                        }
                    }
                    OrderingEffect::Wake { at } => {
                        self.timers.insert(at);
                    }
                    OrderingEffect::DirectCommit { round, digest } => {
                        self.commits.insert(round, unix_us());
                        self.log(json!({"event":"direct_commit","round":round,"digest":digest}))?;
                    }
                    OrderingEffect::Deliver(d) => {
                        self.measured_ordered.insert(d.round, unix_us());
                        self.log(
                            json!({"event":"ordered_descriptor","round":d.round,"digest":d.digest}),
                        )?;
                    }
                    OrderingEffect::Notice { kind, round } => {
                        self.log(json!({"event":kind,"round":round}))?
                    }
                },
                Effect::Send { to, message } => {
                    let (kind, index, payload) = match &message {
                        composed::Message::Batch(r) => {
                            ("BATCH", r.header.body.height, r.payload.len())
                        }
                        composed::Message::Observation(o) => ("OBS", o.body.opportunity, 0),
                        composed::Message::Fetch { target, .. } => ("FETCH", target.height, 0),
                        composed::Message::Data(d) => (
                            "DATA",
                            d.to.height,
                            d.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                        composed::Message::DataPart(d) => (
                            "DATA",
                            d.requested_to.height,
                            d.data.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                    };
                    self.send(
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
                Effect::Trace(mut value) => {
                    // Preserve the engine's handler-entry milliseconds separately.
                    if let Some(at) = value.as_object_mut().and_then(|o| o.remove("at")) {
                        value["protocol_entry_ms"] = at;
                    }
                    if value["event"] == "ordering_input_ready" {
                        value["event"] = json!("input_ready");
                    }
                    if value["event"] == "materialized" {
                        if let Some(round) = value["round"].as_u64() {
                            self.measured_materialized.insert(round, unix_us());
                        }
                    }
                    self.log(value)?;
                }
            }
        }
        // Actual externally observable completion, after the synchronous handler
        // and its queued effect processing; not the engine's dispatch timestamp.
        for entry in &self.node.executed[self.emitted_transactions..] {
            self.log(
                json!({"event":"transaction_materialized","transaction":entry.transaction,
                "round":entry.round,"producer":entry.producer,"height":entry.height,
                "batch_digest":entry.batch_digest,"state_hash":entry.state_hash}),
            )?;
        }
        self.emitted_transactions = self.node.executed.len();
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        to: Option<Id>,
        layer: Layer,
        bytes: Vec<u8>,
        kind: &str,
        index: u64,
        x: usize,
        pi: usize,
        payload: usize,
    ) -> Result<(), String> {
        let recipients: Vec<_> = to.map_or_else(
            || (0..self.config.addresses.len() as Id).collect(),
            |id| vec![id],
        );
        for peer in recipients {
            if peer == self.id {
                continue;
            }
            self.transport.send(peer, layer, bytes.clone())?;
            self.by_kind
                .entry(kind.into())
                .or_default()
                .add(bytes.len(), x, pi, payload);
            self.by_peer
                .entry(peer)
                .or_default()
                .add(bytes.len(), x, pi, payload);
            self.by_index
                .entry(index)
                .or_default()
                .add(bytes.len(), x, pi, payload);
        }
        Ok(())
    }
    fn snapshot(&self) -> Value {
        json!({"replica":self.id,"silent":self.config.silent==Some(self.id),"started":self.started,"quiesced":self.quiesced,
            "ordering":{"current_round":self.node.ordering.current_round(),"last_delivered":self.node.ordering.last_delivered(),
                "deliveries":self.node.ordering.deliveries(),"statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>()},
            "statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>(),
            "deliveries":self.node.ordering.deliveries(),"commits":self.commits,"proposals":self.proposals,
            "input_ready":self.node.input_ready,"ordered_at":self.node.ordered_at,"executed_at":self.node.executed_at,
            "protocol_timestamp_units":"milliseconds from process origin sampled at handler entry",
            "observed_ordered_unix_us":self.measured_ordered,"observed_materialized_unix_us":self.measured_materialized,
            "executed":self.node.executed,"executed_rounds":self.node.executed_rounds,"state_hash":self.node.state_hash(),
            "holding_heights":(0..self.config.addresses.len() as Id).map(|id|self.node.store.checkpoints(id).last().map_or(0,|p|p.height)).collect::<Vec<_>>(),
            "observations":self.node.observations.len(),"record_count":self.node.store.record_count(),"custody_count":self.node.store.custody_count(),
            "pending_materialization":self.node.pending_materialization(),"processed_messages":self.processed_messages,
            "pending_timer_count":self.timers.len(),"next_timer_ms":self.timers.first(),
            "post_cutoff_frames":self.post_cutoff_frames,"silent_ignored_frames":self.silent_ignored_frames,"transport":self.transport.snapshot(),"control":self.control.snapshot(),
            "protocol":{"by_kind":self.by_kind,"by_peer":self.by_peer,"by_index":self.by_index},
            "elapsed_us":self.origin.elapsed().as_micros() as u64,"observed_unix_us":unix_us(),"wall_origin_unix_us":self.wall_origin})
    }
    fn command(&mut self, c: &Command) -> Result<Value, String> {
        let now = self.now_ms();
        match c.kind.as_str() {
            "start" => {
                if self.quiesced {
                    return Err("run is quiesced".into());
                }
                if !self.started {
                    self.started = true;
                    self.active = true;
                    if self.config.silent != Some(self.id) {
                        let e = self.node.start(now)?;
                        self.effects(e)?;
                    }
                    self.log(
                        json!({"event":"started","silent":self.config.silent==Some(self.id)}),
                    )?;
                }
                Ok(json!({"started":true}))
            }
            "submit" => {
                if !self.active || self.config.silent == Some(self.id) {
                    return Err("replica is not active for submissions".into());
                }
                let r = c.round.ok_or("submit requires round")?;
                let count = c.count.unwrap_or(2);
                let size = c.size.unwrap_or(32);
                if r != self.produced + 1
                    || r > self.config.workload_rounds
                    || count == 0
                    || count > 128
                    || size > 4096
                {
                    return Err("submission must be the next bounded workload batch".into());
                }
                let txs = transactions(self.id, r, count, size);
                let payload = wire::encode(&txs)?;
                if payload.len() > crate::batch::MAX_BATCH_PAYLOAD {
                    return Err("batch payload limit exceeded".into());
                }
                let e = self.node.produce(now, payload)?;
                self.produced = r;
                self.effects(e)?;
                let ids: Vec<_> = txs.iter().map(|t| t.id).collect();
                self.log(json!({"event":"submitted","round":r,"height":r,"transactions":ids}))?;
                Ok(json!({"transactions":ids,"height":r,"round":r}))
            }
            "report" => {
                if !self.active || self.config.silent == Some(self.id) {
                    return Err("replica cannot report".into());
                }
                let r = c.round.ok_or("report requires round")?;
                if r == 0 || r > self.config.workload_rounds {
                    return Err("unknown reporting opportunity".into());
                }
                let e = self.node.report(now, r)?;
                self.effects(e)?;
                Ok(json!({"round":r,"reported":true}))
            }
            "snapshot" => Ok(self.snapshot()),
            "quiesce" => {
                self.active = false;
                self.quiesced = true;
                self.log(json!({"event":"quiesced"}))?;
                Ok(json!({"quiesced":true}))
            }
            "stop" => {
                if !self.quiesced {
                    return Err("quiesce and drain before stop".into());
                }
                Ok(self.snapshot())
            }
            _ => Err("unknown control command".into()),
        }
    }
}

pub fn run(config: Config, id: Id) -> Result<(), String> {
    let committee = config.validate(id)?;
    let bytes = fs::read(&config.key_files[id as usize]).map_err(|e| e.to_string())?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    let public = PublicKey::from(&secret);
    if committee.keys[id as usize] != public {
        return Err("private key does not match configured identity".into());
    }
    let key = Keypair { secret, public };
    let transport_key = Keypair::from_bytes(&key.to_bytes()).map_err(|e| e.to_string())?;
    let mc = mmr::Config {
        context: committee.context.clone(),
        chunk_capacity: config.chunk_capacity,
    };
    let av = AvailabilityConfig::new(
        committee.clone(),
        config.chunk_capacity,
        (1..=config.workload_rounds)
            .map(|r| genesis_binding(&mc, r, committee.keys.len()))
            .collect(),
    )?;
    let node = Node::new(
        committee.clone(),
        id,
        key,
        config.bound_ms,
        av,
        config.chunk_capacity,
    )?;
    let transport = Transport::bind(
        id,
        committee,
        transport_key,
        config.addresses.clone(),
        TransportSettings::default(),
    )?;
    let control = Control::bind(
        config.control_addresses[id as usize],
        config.control_token.clone(),
    )?;
    let mut rt = Runtime {
        config,
        id,
        node,
        transport,
        control,
        origin: Instant::now(),
        wall_origin: unix_us(),
        timers: BTreeSet::new(),
        active: false,
        started: false,
        quiesced: false,
        produced: 0,
        emitted_transactions: 0,
        processed_messages: 0,
        post_cutoff_frames: 0,
        silent_ignored_frames: 0,
        by_kind: BTreeMap::new(),
        by_peer: BTreeMap::new(),
        by_index: BTreeMap::new(),
        proposals: BTreeMap::new(),
        commits: BTreeMap::new(),
        measured_ordered: BTreeMap::new(),
        measured_materialized: BTreeMap::new(),
    };
    rt.log(json!({"event":"ready","pid":std::process::id(),"control_address":rt.config.control_addresses[id as usize],
        "replica_address":rt.config.addresses[id as usize],"clock":"monotonic local timers; same-host UNIX microsecond telemetry"}))?;
    let outcome = (|| -> Result<(), String> {
        loop {
            if rt.origin.elapsed().as_millis() > rt.config.max_runtime_ms as u128 {
                return Err("process observation deadline exceeded".into());
            }
            let mut work = false;
            if let Ok(request) = rt.control.requests.try_recv() {
                work = true;
                let result = rt.command(&request.command);
                let stop = request.command.kind == "stop" && result.is_ok();
                let reply = match result {
                    Ok(data) => {
                        json!({"type":"reply","id":id,"request_id":request.command.request_id,
                    "ok":true,"observed_unix_us":unix_us(),"data":data})
                    }
                    Err(error) => {
                        json!({"type":"reply","id":id,"request_id":request.command.request_id,
                    "ok":false,"observed_unix_us":unix_us(),"error":error})
                    }
                };
                let _ = request.reply.send(reply);
                if stop {
                    rt.log(json!({"event":"final","snapshot":rt.snapshot()}))?;
                    break;
                }
            }
            // Fair one-message turns, with command and timer checks every turn.
            let received = if rt.started || rt.quiesced || rt.config.silent == Some(id) {
                rt.transport.recv_timeout(Duration::ZERO).ok()
            } else {
                None
            }; // Retain pre-start packets in the bounded transport mailbox.
            if let Some(received) = received {
                work = true;
                if rt.active && rt.config.silent != Some(id) {
                    let now = rt.now_ms();
                    let result = match received.layer {
                        Layer::Ordering => wire::decode(&received.payload)
                            .and_then(|m| rt.node.receive_ordering(now, m)),
                        Layer::Dissemination => wire::decode(&received.payload)
                            .and_then(|m| rt.node.receive(now, received.from, m)),
                    };
                    match result {
                        Ok(e) => {
                            rt.processed_messages += 1;
                            rt.effects(e)?;
                        }
                        Err(error) => {
                            return Err(format!(
                                "authenticated peer {} sent rejected protocol input: {error}",
                                received.from
                            ))
                        }
                    }
                } else if rt.config.silent == Some(id) {
                    rt.silent_ignored_frames += 1;
                } else {
                    rt.post_cutoff_frames += 1;
                }
            }
            if rt.active
                && rt.config.silent != Some(id)
                && rt.timers.first().is_some_and(|at| *at <= rt.now_ms())
            {
                work = true;
                let now = rt.now_ms();
                while rt.timers.first().is_some_and(|at| *at <= now) {
                    rt.timers.pop_first();
                }
                let e = rt.node.tick(now)?;
                rt.effects(e)?;
            }
            if !work {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    })();
    if let Err(error) = &outcome {
        let _ = rt.log(json!({"event":"fatal","error":error,"snapshot":rt.snapshot()}));
    }
    rt.transport.shutdown();
    outcome
}
fn unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock predates Unix epoch")
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_control_parser_is_bounded_and_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Command>(
            r#"{"type":"submit","token":"test","round":1,"unexpected":true}"#
        )
        .is_err());
        let c: Command =
            serde_json::from_str(r#"{"type":"snapshot","token":"test","request_id":7}"#).unwrap();
        assert_eq!(c.kind, "snapshot");
        assert_eq!(c.request_id, 7);
    }
}
