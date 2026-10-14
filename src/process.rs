//! Independent replica driver with real clocks, authenticated replica TCP and a
//! loopback capability-protected client/control endpoint. This local experiment
//! retains in-memory custody and uses self-contained authenticated bases.
use crate::availability::AvailabilityConfig;
use crate::causal::{self, Trace as CausalTrace};
use crate::composed::{self, Effect, Node};
use crate::end_to_end::transactions;
use crate::mmr;
use crate::replica::{Effect as OrderingEffect, OrderingSchedule};
use crate::simulation::message_kind;
use crate::transport::{Layer, Received, Transport, TransportSettings};
use crate::wire::{self, Committee, Digest, Id};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingMode {
    Canonical,
    Progress,
    Barrier,
}

fn default_ordering_batch() -> bool {
    true
}

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
    #[serde(default)]
    pub sustained: Option<SustainedConfig>,
    /// Zero-wait, per-effect-drain ordering packet aggregation, enabled by default.
    #[serde(default = "default_ordering_batch")]
    pub ordering_batch: bool,
    /// Defaults to PROG pacing. Explicit canonical/barrier modes support comparisons.
    #[serde(default)]
    pub ordering_mode: Option<OrderingMode>,
    /// Experimental ordering send barrier; its fallback begins at round entry.
    #[serde(default)]
    pub round_barrier_ms: Option<u64>,
    /// Origin-PROG release deadline; defaults to bound_ms in progress mode.
    #[serde(default)]
    pub progress_pacing_ms: Option<u64>,
}
/// Sustained benchmark load is generated at the producer, on the protocol
/// thread. Transaction sizes include the canonical Transaction encoding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SustainedConfig {
    pub rate_per_replica: u64,
    pub transaction_bytes: usize,
    pub batch_ms: u64,
    pub warmup_ms: u64,
    pub measurement_ms: u64,
}
impl SustainedConfig {
    fn validate(&self) -> Result<(), String> {
        if self.rate_per_replica == 0
            || self.rate_per_replica > 25_000
            || self.transaction_bytes < 40
            || self.transaction_bytes > 4096
            || self.batch_ms == 0
            || self.batch_ms > 1000
            || self.rate_per_replica * self.batch_ms > 128_000
            || self.warmup_ms == 0
            || self.measurement_ms == 0
            || self.warmup_ms + self.measurement_ms > 300_000
        {
            return Err("invalid sustained load configuration".into());
        }
        Ok(())
    }
}

impl Config {
    pub fn ordering_schedule(&self) -> Result<OrderingSchedule, String> {
        for delay in [self.round_barrier_ms, self.progress_pacing_ms]
            .into_iter()
            .flatten()
        {
            if delay == 0 || delay > self.bound_ms {
                return Err(
                    "ordering release deadline must be positive and at most bound_ms".into(),
                );
            }
        }
        let mode = self
            .ordering_mode
            .unwrap_or(if self.round_barrier_ms.is_some() {
                OrderingMode::Barrier
            } else {
                OrderingMode::Progress
            });
        match mode {
            OrderingMode::Canonical
                if self.round_barrier_ms.is_none() && self.progress_pacing_ms.is_none() =>
            {
                Ok(OrderingSchedule::Canonical)
            }
            OrderingMode::Progress if self.round_barrier_ms.is_none() => {
                Ok(OrderingSchedule::ProgressPacing {
                    release_delay_ms: self.progress_pacing_ms.unwrap_or(self.bound_ms),
                })
            }
            OrderingMode::Barrier if self.progress_pacing_ms.is_none() => {
                Ok(OrderingSchedule::RoundBarrier {
                    release_delay_ms: self.round_barrier_ms.unwrap_or(self.bound_ms),
                })
            }
            _ => Err("ordering mode and release deadline options conflict".into()),
        }
    }

    pub fn validate(&self, id: Id) -> Result<Committee, String> {
        self.ordering_schedule()?;
        if let Some(load) = &self.sustained {
            load.validate()?;
            if self.silent.is_some() {
                return Err("sustained profile requires all four honest replicas".into());
            }
        }
        let n = self.public_keys.len();
        if !matches!(n, 4 | 7)
            || id as usize >= n
            || self.addresses.len() != n
            || self.control_addresses.len() != n
            || self.key_files.len() != n
            || self.control_token.len() < 32
            || self.bound_ms == 0
            || self.bound_ms > 60_000
            || self
                .round_barrier_ms
                .is_some_and(|ms| ms == 0 || ms > self.bound_ms)
            || self
                .progress_pacing_ms
                .is_some_and(|ms| ms == 0 || ms > self.bound_ms)
            || (self.round_barrier_ms.is_some() && self.progress_pacing_ms.is_some())
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
    start_unix_us: Option<u64>,
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
#[derive(Default)]
struct LoadMetrics {
    start_us: Option<u64>,
    next_batch_us: u64,
    inserted: u64,
    completed: u64,
    latency_sum_us: u64,
    /// Sparse one-millisecond upper-bound buckets, including zero for zero.
    latency_histogram_ms: BTreeMap<u64, u64>,
    pending: BTreeMap<Digest, u64>,
    maximum_schedule_lag_us: u64,
    window_start: Option<Value>,
    window_end: Option<Value>,
}

fn scheduled_transactions(elapsed_us: u64, rate: u64) -> u64 {
    ((elapsed_us as u128 * rate as u128) / 1_000_000) as u64
}

fn sustained_transaction(
    instance: Digest,
    producer: Id,
    sequence: u64,
    size: usize,
) -> composed::Transaction {
    composed::Transaction {
        id: wire::hash(&("sustained-transaction", instance, producer, sequence)),
        bytes: vec![producer as u8; size - 40],
    }
}

/// Hash after an exact application-output prefix, without serializing its log.
fn execution_prefix_hash(executed: &[composed::Executed], count: u64) -> Result<Digest, String> {
    if count == 0 {
        return Ok(wire::hash(&"delugi/deterministic-materialization/v1"));
    }
    let index = usize::try_from(count - 1).map_err(|_| "prefix count exceeds platform range")?;
    executed
        .get(index)
        .map(|entry| entry.state_hash)
        .ok_or_else(|| "prefix is beyond local execution".into())
}

/// Wake an eligible idle loop on transport arrival, without dispatching until
/// the next turn's control check. A disconnected inbox must not busy-spin.
fn idle_receive<T>(
    eligible: bool,
    receive: impl FnOnce(Duration) -> Result<T, mpsc::RecvTimeoutError>,
    sleep: impl FnOnce(Duration),
) -> Option<T> {
    let timeout = Duration::from_millis(1);
    if eligible {
        match receive(timeout) {
            Ok(message) => return Some(message),
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
    sleep(timeout);
    None
}

// This envelope belongs to the authenticated transport layer, not the signed
// ordering protocol. A fixed count/length layout bounds allocation before any
// member is decoded. No member needs to be valid for its siblings to be tried.
const MAX_ORDERING_BUNDLE_MEMBERS: usize = 32;

fn encode_ordering_bundle<'a>(
    members: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, String> {
    let members: Vec<_> = members.into_iter().collect();
    if !(2..=MAX_ORDERING_BUNDLE_MEMBERS).contains(&members.len()) {
        return Err("ordering bundle member count is outside 2..=32".into());
    }
    let mut size = 4usize;
    for member in &members {
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(member.len()))
            .ok_or("ordering bundle length overflow")?;
        if size > wire::MAX_WIRE_BYTES {
            return Err("ordering bundle exceeds the frame payload limit".into());
        }
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for member in members {
        bytes.extend_from_slice(&(member.len() as u32).to_le_bytes());
        bytes.extend_from_slice(member);
    }
    Ok(bytes)
}

fn decode_ordering_bundle(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    if bytes.len() < 4 || bytes.len() > wire::MAX_WIRE_BYTES {
        return Err("invalid ordering bundle size".into());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if !(2..=MAX_ORDERING_BUNDLE_MEMBERS).contains(&count) {
        return Err("ordering bundle member count is outside 2..=32".into());
    }
    let mut members = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        let length = bytes
            .get(offset..offset + 4)
            .ok_or("truncated ordering bundle length")?;
        let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .ok_or("ordering bundle length overflow")?;
        members.push(
            bytes
                .get(offset..end)
                .ok_or("truncated ordering bundle member")?,
        );
        offset = end;
    }
    if offset != bytes.len() {
        return Err("ordering bundle has trailing bytes".into());
    }
    Ok(members)
}

fn recipients(to: Option<Id>, own: Id, count: usize) -> Vec<Id> {
    to.map_or_else(|| (0..count as Id).collect(), |id| vec![id])
        .into_iter()
        .filter(|id| *id != own)
        .collect()
}

#[derive(Clone, Debug)]
struct OrderingToSend {
    bytes: Vec<u8>,
    kind: String,
    index: u64,
    x: usize,
    pi: usize,
}
impl OrderingToSend {
    fn round(&self) -> u64 {
        if matches!(self.kind.as_str(), "HISTORY3" | "CLOSED") {
            self.index - 3
        } else {
            self.index
        }
    }
}

#[derive(Default)]
struct OrderingBatcher {
    // Per-peer order is exactly the original effect order, including H3/CLOSED.
    pending: BTreeMap<Id, (usize, Vec<OrderingToSend>)>,
}
impl OrderingBatcher {
    fn push(&mut self, peer: Id, message: OrderingToSend) -> Vec<Vec<OrderingToSend>> {
        let mut ready = Vec::new();
        let size = 4 + message.bytes.len();
        if self.pending.get(&peer).is_some_and(|(bytes, messages)| {
            messages.len() == MAX_ORDERING_BUNDLE_MEMBERS || bytes + size > wire::MAX_WIRE_BYTES
        }) {
            ready.push(self.take(peer).unwrap());
        }
        // A valid single wire message can fill the frame limit without room
        // for the bundle's length fields. Send it in the unchanged single form.
        if 4 + size > wire::MAX_WIRE_BYTES {
            ready.push(vec![message]);
        } else {
            let entry = self.pending.entry(peer).or_insert_with(|| (4, Vec::new()));
            entry.0 += size;
            entry.1.push(message);
        }
        ready
    }
    fn take(&mut self, peer: Id) -> Option<Vec<OrderingToSend>> {
        self.pending.remove(&peer).map(|(_, messages)| messages)
    }
    fn drain(self) -> impl Iterator<Item = (Id, Vec<OrderingToSend>)> {
        self.pending
            .into_iter()
            .map(|(peer, (_, messages))| (peer, messages))
    }
}

struct LogicalReceived {
    frame: Received,
    member_index: u32,
    member_count: u32,
}

fn expand_received(frame: Received) -> Result<VecDeque<LogicalReceived>, String> {
    if frame.layer != Layer::OrderingBundle {
        return Ok(VecDeque::from([LogicalReceived {
            frame,
            member_index: 0,
            member_count: 1,
        }]));
    }
    let members = decode_ordering_bundle(&frame.payload)?;
    let member_count = members.len() as u32;
    Ok(members
        .into_iter()
        .enumerate()
        .map(|(index, payload)| LogicalReceived {
            frame: Received {
                from: frame.from,
                sequence: frame.sequence,
                layer: Layer::Ordering,
                payload: payload.to_vec(),
                received_at: frame.received_at,
            },
            member_index: index as u32,
            member_count,
        })
        .collect())
}

struct Runtime {
    causal: Option<CausalTrace>,
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
    rejected_protocol_messages: u64,
    post_cutoff_frames: u64,
    post_cutoff_messages: u64,
    silent_ignored_frames: u64,
    by_kind: BTreeMap<String, Counter>,
    by_peer: BTreeMap<Id, Counter>,
    by_index: BTreeMap<u64, Counter>,
    proposals: BTreeMap<u64, u64>,
    commits: BTreeMap<u64, u64>,
    measured_ordered: BTreeMap<u64, u64>,
    measured_materialized: BTreeMap<u64, u64>,
    load: LoadMetrics,
}
impl Runtime {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
    fn log(&self, mut event: Value) -> Result<(), String> {
        if self.config.sustained.is_some()
            && !matches!(
                event["event"].as_str(),
                Some(
                    "ready"
                        | "started"
                        | "load_scheduled"
                        | "load_window_start"
                        | "load_window_end"
                        | "quiesced"
                        | "protocol_rejected"
                        | "fatal"
                        | "final"
                )
            )
        {
            return Ok(());
        }
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
        let mut pending = OrderingBatcher::default();
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
                        let index = if matches!(kind, "HISTORY3" | "CLOSED") {
                            round + 3
                        } else {
                            round
                        };
                        if self.config.ordering_batch {
                            let message = OrderingToSend {
                                bytes,
                                kind: kind.into(),
                                index,
                                x,
                                pi,
                            };
                            for peer in recipients(to, self.id, self.config.addresses.len()) {
                                for packet in pending.push(peer, message.clone()) {
                                    self.send_ordering_packet(peer, packet)?;
                                }
                            }
                        } else {
                            self.send(to, Layer::Ordering, bytes, kind, index, x, pi, 0)?;
                        }
                        if kind == "PROPOSE" && self.config.sustained.is_none() {
                            self.proposals.insert(round, unix_us());
                            if let wire::Message::Propose(proposal) = &message {
                                let descriptor: crate::availability::Descriptor =
                                    wire::decode(&proposal.value)?;
                                let availability_proof: crate::availability::AvailabilityProof =
                                    wire::decode(&proposal.witness)?;
                                self.log(json!({"event":"proposal","round":round,"message":message,
                                    "descriptor":descriptor,"availability_proof":availability_proof}))?;
                            }
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
                    if let composed::Message::Report { request, base } = &message {
                        if self.config.sustained.is_none() {
                            self.log(json!({"event":"report_broadcast","round":base.opportunity,
                            "report":request,"base":base}))?;
                        }
                    }
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
                        composed::Message::DataPart(d) => (
                            "DATA",
                            d.requested_to.height,
                            d.data.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                    };
                    // Preserve each peer's cross-layer FIFO. Messages for other
                    // peers can remain pending until their own boundary/end.
                    for peer in recipients(to, self.id, self.config.addresses.len()) {
                        if let Some(packet) = pending.take(peer) {
                            self.send_ordering_packet(peer, packet)?;
                        }
                    }
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
        for (peer, packet) in pending.drain() {
            self.send_ordering_packet(peer, packet)?;
        }
        // Actual externally observable completion, after the synchronous handler
        // and its queued effect processing; not the engine's dispatch timestamp.
        let completed_at = self.origin.elapsed().as_micros() as u64;
        for entry in &self.node.executed[self.emitted_transactions..] {
            if let Some(inserted_at) = self.load.pending.remove(&entry.transaction) {
                let latency = completed_at - inserted_at;
                self.load.completed += 1;
                self.load.latency_sum_us += latency;
                *self
                    .load
                    .latency_histogram_ms
                    .entry(latency.div_ceil(1000))
                    .or_default() += 1;
            }
            if self.config.sustained.is_some() {
                continue;
            }
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
        for peer in recipients(to, self.id, self.config.addresses.len()) {
            let round = if matches!(kind, "HISTORY3" | "CLOSED") {
                index - 3
            } else if matches!(kind, "BATCH" | "FETCH" | "DATA") {
                0
            } else {
                index
            };
            let enqueue_start = self
                .causal
                .as_ref()
                .filter(|t| round != 0 && t.sampled(round))
                .map(CausalTrace::now_us);
            let sequence = self.transport.send(peer, layer, bytes.clone())?;
            if let Some(start) = enqueue_start {
                self.causal.as_ref().unwrap().span("transport_enqueue", round, start,
                    json!({"kind":kind,"peer":peer,"signer":self.id,"sequence":sequence,"member_index":0,"member_count":1,"payload_bytes":bytes.len()}));
            }
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
    fn send_ordering_packet(
        &mut self,
        peer: Id,
        messages: Vec<OrderingToSend>,
    ) -> Result<(), String> {
        if messages.len() == 1 {
            let message = messages.into_iter().next().unwrap();
            return self.send(
                Some(peer),
                Layer::Ordering,
                message.bytes,
                &message.kind,
                message.index,
                message.x,
                message.pi,
                0,
            );
        }
        let payload =
            encode_ordering_bundle(messages.iter().map(|message| message.bytes.as_slice()))?;
        let enqueue_start = self.causal.as_ref().map(CausalTrace::now_us);
        let sequence = self.transport.send(peer, Layer::OrderingBundle, payload)?;
        for (member_index, message) in messages.iter().enumerate() {
            let round = message.round();
            if let Some(trace) = &self.causal {
                if trace.sampled(round) {
                    trace.span("transport_enqueue", round, enqueue_start.unwrap(),
                        json!({"kind":message.kind,"peer":peer,"signer":self.id,"sequence":sequence,
                            "member_index":member_index,"member_count":messages.len(),"payload_bytes":message.bytes.len()}));
                }
            }
            self.by_kind.entry(message.kind.clone()).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
            self.by_peer.entry(peer).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
            self.by_index.entry(message.index).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
        }
        Ok(())
    }
    fn compact_snapshot(&self) -> Value {
        let now_us = self.origin.elapsed().as_micros() as u64;
        let mut snapshot = json!({"replica":self.id,"started":self.started,"quiesced":self.quiesced,
            "elapsed_us":now_us,"observed_unix_us":unix_us(),
            "current_round":self.node.ordering.current_round(),"last_delivered":self.node.ordering.last_delivered(),
            "executed_count":self.node.executed.len(),"materialized_batch_count":self.node.materialized_batches.len(),
            "state_hash":self.node.state_hash(),"cumulative_heights":self.node.cumulative_heights(),
            "pending_materialization":self.node.pending_materialization(),"processed_messages":self.processed_messages,
            "rejected_protocol_messages":self.rejected_protocol_messages,"post_cutoff_frames":self.post_cutoff_frames,"post_cutoff_messages":self.post_cutoff_messages,
            "transport":self.transport.snapshot(),"ordering_batch":self.config.ordering_batch,"round_barrier_ms":self.config.round_barrier_ms,"protocol_by_kind":self.by_kind,
            "load":{"inserted":self.load.inserted,"completed":self.load.completed,"pending":self.load.pending.len(),
                "latency_sum_us":self.load.latency_sum_us,"latency_histogram_ms":self.load.latency_histogram_ms,
                "maximum_schedule_lag_us":self.load.maximum_schedule_lag_us,"start_elapsed_us":self.load.start_us,
                "expected_total":self.config.sustained.as_ref().map(|c|scheduled_transactions((c.warmup_ms+c.measurement_ms)*1000,c.rate_per_replica))}});
        snapshot["progress_pacing_ms"] = json!(self.config.progress_pacing_ms);
        snapshot["ordering_mode"] = json!(self.config.ordering_mode);
        if let Some(trace) = &self.causal {
            snapshot["causal_trace"] = trace.summary();
        }
        snapshot
    }
    fn snapshot(&self) -> Value {
        if self.config.sustained.is_some() {
            let mut value = self.compact_snapshot();
            value["measurement_start"] = json!(self.load.window_start);
            value["measurement_end"] = json!(self.load.window_end);
            return value;
        }
        let mut snapshot = json!({"replica":self.id,"silent":self.config.silent==Some(self.id),"started":self.started,"quiesced":self.quiesced,
            "ordering":{"current_round":self.node.ordering.current_round(),"last_delivered":self.node.ordering.last_delivered(),
                "deliveries":self.node.ordering.deliveries(),"statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>()},
            "statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>(),
            "deliveries":self.node.ordering.deliveries(),"commits":self.commits,"proposals":self.proposals,
            "input_ready":self.node.input_ready,"ordered_at":self.node.ordered_at,"executed_at":self.node.executed_at,
            "protocol_timestamp_units":"milliseconds from process origin sampled at handler entry",
            "observed_ordered_unix_us":self.measured_ordered,"observed_materialized_unix_us":self.measured_materialized,
            "executed":self.node.executed,"executed_rounds":self.node.executed_rounds,"state_hash":self.node.state_hash(),
            "materialized_batches":self.node.materialized_batches,"cumulative_heights":self.node.cumulative_heights(),
            "holding_heights":(0..self.config.addresses.len() as Id).map(|id|self.node.store.checkpoints(id).last().map_or(0,|p|p.height)).collect::<Vec<_>>(),
            "observations":self.node.observations.len(),"observation_evidence":self.node.observations,
            "record_count":self.node.store.record_count(),"custody_count":self.node.store.custody_count(),
            "pending_materialization":self.node.pending_materialization(),"processed_messages":self.processed_messages,
            "rejected_protocol_messages":self.rejected_protocol_messages,
            "pending_timer_count":self.timers.len(),"next_timer_ms":self.timers.first(),
            "post_cutoff_frames":self.post_cutoff_frames,"post_cutoff_messages":self.post_cutoff_messages,"silent_ignored_frames":self.silent_ignored_frames,"transport":self.transport.snapshot(),"ordering_batch":self.config.ordering_batch,"round_barrier_ms":self.config.round_barrier_ms,"control":self.control.snapshot(),
            "protocol":{"by_kind":self.by_kind,"by_peer":self.by_peer,"by_index":self.by_index},
            "elapsed_us":self.origin.elapsed().as_micros() as u64,"observed_unix_us":unix_us(),"wall_origin_unix_us":self.wall_origin});
        snapshot["progress_pacing_ms"] = json!(self.config.progress_pacing_ms);
        snapshot["ordering_mode"] = json!(self.config.ordering_mode);
        snapshot
    }
    fn load_tick(&mut self) -> Result<bool, String> {
        let Some(config) = self.config.sustained.clone() else {
            return Ok(false);
        };
        let Some(start) = self.load.start_us else {
            return Ok(false);
        };
        if self.load.window_end.is_some() {
            return Ok(false);
        }
        let now_us = self.origin.elapsed().as_micros() as u64;
        if now_us < start {
            return Ok(false);
        }
        let elapsed = now_us - start;
        if elapsed >= config.warmup_ms * 1000 && self.load.window_start.is_none() {
            self.load.window_start = Some(self.compact_snapshot());
            self.log(json!({"event":"load_window_start"}))?;
        }
        let duration_us = (config.warmup_ms + config.measurement_ms) * 1000;
        if elapsed >= duration_us {
            self.load.window_end = Some(self.compact_snapshot());
            self.log(json!({"event":"load_window_end"}))?;
            return Ok(true);
        }
        if elapsed < self.load.next_batch_us {
            return Ok(false);
        }
        let due = scheduled_transactions(elapsed, config.rate_per_replica);
        let count = due
            .saturating_sub(self.load.inserted)
            .min(128)
            .min(((crate::batch::MAX_BATCH_PAYLOAD - 8) / config.transaction_bytes) as u64);
        self.load.maximum_schedule_lag_us = self
            .load
            .maximum_schedule_lag_us
            .max(elapsed.saturating_sub(self.load.next_batch_us));
        self.load.next_batch_us += config.batch_ms * 1000;
        if count == 0 {
            return Ok(true);
        }
        let mut txs = Vec::new();
        for sequence in self.load.inserted..self.load.inserted + count {
            let tx = sustained_transaction(
                self.config.instance,
                self.id,
                sequence,
                config.transaction_bytes,
            );
            self.load.pending.insert(tx.id, now_us);
            txs.push(tx);
        }
        self.load.inserted += count;
        let e = self.node.produce(self.now_ms(), wire::encode(&txs)?)?;
        self.produced += 1;
        self.effects(e)?;
        Ok(true)
    }
    fn command(&mut self, c: &Command) -> Result<Value, String> {
        let now = self.now_ms();
        match c.kind.as_str() {
            "load" => {
                if !self.started
                    || self.config.sustained.is_none()
                    || self.load.start_us.is_some()
                    || self.quiesced
                {
                    return Err(
                        "load requires a started sustained replica with no previous schedule"
                            .into(),
                    );
                }
                let requested = c
                    .start_unix_us
                    .ok_or("load requires a future start_unix_us")?;
                let wall = unix_us();
                if requested <= wall || requested - wall > 10_000_000 {
                    return Err("load start must be within the next ten seconds".into());
                }
                self.load.start_us =
                    Some(self.origin.elapsed().as_micros() as u64 + requested - wall);
                self.load.next_batch_us = self.config.sustained.as_ref().unwrap().batch_ms * 1000;
                self.log(json!({"event":"load_scheduled","start_unix_us":requested}))?;
                Ok(json!({"start_unix_us":requested}))
            }
            "prepare" => {
                if self.started || self.quiesced {
                    return Err("prepare must precede ordering start".into());
                }
                // Enable independent batch production/reception before starting
                // the finite ordering experiment. Reporting remains driven by
                // actual ordering round entries and signed leader requests.
                self.active = true;
                Ok(json!({"prepared":true}))
            }
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
            "prefix" => {
                let count = c.count.ok_or("prefix requires count")?;
                Ok(
                    json!({"count":count,"state_hash":execution_prefix_hash(&self.node.executed,count)?}),
                )
            }
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

pub fn run(mut config: Config, id: Id) -> Result<(), String> {
    let committee = config.validate(id)?;
    let schedule = config.ordering_schedule()?;
    match schedule {
        OrderingSchedule::Canonical => config.ordering_mode = Some(OrderingMode::Canonical),
        OrderingSchedule::ProgressPacing { release_delay_ms } => {
            config.ordering_mode = Some(OrderingMode::Progress);
            config.progress_pacing_ms = Some(release_delay_ms);
        }
        OrderingSchedule::RoundBarrier { release_delay_ms } => {
            config.ordering_mode = Some(OrderingMode::Barrier);
            config.round_barrier_ms = Some(release_delay_ms);
        }
    }
    let bytes = fs::read(&config.key_files[id as usize]).map_err(|e| e.to_string())?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    let public = PublicKey::from(&secret);
    if committee.keys[id as usize] != public {
        return Err("private key does not match configured identity".into());
    }
    let key = Keypair { secret, public };
    let transport_key = Keypair::from_bytes(&key.to_bytes()).map_err(|e| e.to_string())?;
    let av = AvailabilityConfig::new(committee.clone(), config.chunk_capacity)?;
    let mut node = Node::new(
        committee.clone(),
        id,
        key,
        config.bound_ms,
        av,
        config.chunk_capacity,
    )?;
    node.ordering.configure_ordering(schedule)?;
    if config.sustained.is_none() {
        node.set_opportunity_limit(config.workload_rounds)?;
    }
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
        causal: None,
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
        rejected_protocol_messages: 0,
        post_cutoff_frames: 0,
        post_cutoff_messages: 0,
        silent_ignored_frames: 0,
        by_kind: BTreeMap::new(),
        by_peer: BTreeMap::new(),
        by_index: BTreeMap::new(),
        proposals: BTreeMap::new(),
        commits: BTreeMap::new(),
        measured_ordered: BTreeMap::new(),
        measured_materialized: BTreeMap::new(),
        load: LoadMetrics::default(),
    };
    let causal_output = CausalTrace::from_environment(rt.origin, rt.wall_origin, id)?;
    if let Some((trace, _)) = &causal_output {
        rt.causal = Some(trace.clone());
        rt.node.enable_causal_trace(trace.clone());
    }
    rt.log(json!({"event":"ready","pid":std::process::id(),"control_address":rt.config.control_addresses[id as usize],
        "replica_address":rt.config.addresses[id as usize],"clock":"monotonic local timers; same-host UNIX microsecond telemetry"}))?;
    let outcome = (|| -> Result<(), String> {
        let mut pending_received = None;
        let mut pending_members = VecDeque::new();
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
            let receive_eligible =
                rt.active || rt.started || rt.quiesced || rt.config.silent == Some(id);
            let mut logical_received = if receive_eligible {
                pending_members.pop_front()
            } else {
                None
            };
            if logical_received.is_none() && receive_eligible {
                let frame = pending_received
                    .take()
                    .or_else(|| rt.transport.recv_timeout(Duration::ZERO).ok());
                if let Some(frame) = frame {
                    work = true;
                    if rt.active
                        && rt.config.silent != Some(id)
                        && frame.layer == Layer::OrderingBundle
                    {
                        let peer = frame.from;
                        match expand_received(frame) {
                            Ok(members) => {
                                pending_members = members;
                                logical_received = pending_members.pop_front();
                            }
                            Err(error) => {
                                rt.rejected_protocol_messages += 1;
                                rt.log(
                                    json!({"event":"protocol_rejected","peer":peer,"reason":error}),
                                )?;
                            }
                        }
                    } else {
                        // Singles retain their original no-expansion path. Silent
                        // or quiesced replicas discard physical frames without
                        // allocating or interpreting a possibly Byzantine envelope.
                        logical_received = Some(LogicalReceived {
                            frame,
                            member_index: 0,
                            member_count: 1,
                        });
                    }
                }
            } // Pre-start packets stay in the bounded transport mailbox.
            if let Some(LogicalReceived {
                frame: received,
                member_index,
                member_count,
            }) = logical_received
            {
                work = true;
                if rt.active && rt.config.silent != Some(id) {
                    let now = rt.now_ms();
                    let dispatch_start = rt.causal.as_ref().map(CausalTrace::now_us);
                    let mut trace_key = None;
                    let result = match received.layer {
                        Layer::Ordering => wire::decode(&received.payload)
                            .and_then(|m| {
                                if let Some(trace) = &rt.causal {
                                    let (kind, round, signer) = causal::ordering_key(&m);
                                    if trace.sampled(round) {
                                        trace_key = Some((kind, round));
                                        trace.at("dispatch", round, dispatch_start.unwrap(), None,
                                            json!({"kind":kind,"peer":received.from,"signer":signer,
                                                "sequence":received.sequence,"member_index":member_index,"member_count":member_count,"mailbox_us":trace.offset_us(received.received_at),
                                                "decode_done_us":trace.now_us()}));
                                    }
                                }
                                rt.node.receive_ordering(now, m)
                            }),
                        Layer::Dissemination => wire::decode(&received.payload)
                            .and_then(|m| {
                                if let Some(trace) = &rt.causal {
                                    let (kind, round, signer) = causal::dissemination_key(&m);
                                    if trace.sampled(if round == 0 { received.sequence } else { round }) {
                                        trace_key = Some((kind, round));
                                        trace.at("dispatch", round, dispatch_start.unwrap(), None,
                                            json!({"kind":kind,"peer":received.from,"signer":signer,
                                                "sequence":received.sequence,"member_index":member_index,"member_count":member_count,"mailbox_us":trace.offset_us(received.received_at),
                                                "decode_done_us":trace.now_us()}));
                                    }
                                }
                                rt.node.receive(now, received.from, m)
                            }),
                        Layer::OrderingBundle => unreachable!("bundles are expanded before dispatch"),
                    };
                    let handler_end = rt.causal.as_ref().map(CausalTrace::now_us);
                    if let Some((kind, round)) = trace_key {
                        rt.causal.as_ref().unwrap().at("handler", round, handler_end.unwrap(), dispatch_start,
                            json!({"kind":kind,"peer":received.from,"sequence":received.sequence,"member_index":member_index,"member_count":member_count,"accepted":result.is_ok()}));
                    }
                    match result {
                        Ok(e) => {
                            rt.processed_messages += 1;
                            rt.effects(e)?;
                            if let Some((kind, round)) = trace_key {
                                rt.causal.as_ref().unwrap().span("effect_drain", round, handler_end.unwrap(),
                                    json!({"kind":kind,"peer":received.from,"sequence":received.sequence,"member_index":member_index,"member_count":member_count}));
                            }
                        }
                        Err(error) => {
                            // An authenticated member can still be Byzantine.
                            // Invalid peer input is rejected without stopping
                            // honest processing of later protocol messages.
                            rt.rejected_protocol_messages += 1;
                            rt.log(json!({"event":"protocol_rejected",
                                "peer":received.from,"reason":error}))?;
                        }
                    }
                } else if rt.config.silent == Some(id) {
                    rt.silent_ignored_frames += 1;
                } else {
                    rt.post_cutoff_messages += 1;
                    if member_index == 0 {
                        rt.post_cutoff_frames += 1;
                    }
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
            if rt.active && rt.started && !rt.quiesced {
                work |= rt.load_tick()?;
            }
            if !work {
                pending_received = idle_receive(
                    receive_eligible,
                    |timeout| rt.transport.recv_timeout(timeout),
                    thread::sleep,
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = &outcome {
        let _ = rt.log(json!({"event":"fatal","error":error,"snapshot":rt.snapshot()}));
    }
    rt.transport.shutdown();
    if let Some((trace, path)) = causal_output {
        if let Err(error) = trace.write(&path, &outcome) {
            return Err(match outcome {
                Ok(()) => format!("causal trace write failed: {error}"),
                Err(original) => format!("{original}; causal trace write failed: {error}"),
            });
        }
    }
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
    fn queued(kind: &str, byte: u8, size: usize) -> OrderingToSend {
        OrderingToSend {
            bytes: vec![byte; size],
            kind: kind.into(),
            index: 4,
            x: 0,
            pi: 0,
        }
    }

    #[test]
    fn ordering_envelope_bounds_count_lengths_and_trailing_bytes_before_members() {
        let encoded = encode_ordering_bundle([b"one".as_slice(), b"two".as_slice()]).unwrap();
        assert_eq!(
            decode_ordering_bundle(&encoded).unwrap(),
            vec![b"one".as_slice(), b"two".as_slice()]
        );
        for count in [0u32, 1, 33, u32::MAX] {
            let mut bytes = encoded.clone();
            bytes[..4].copy_from_slice(&count.to_le_bytes());
            assert!(decode_ordering_bundle(&bytes).is_err());
        }
        for end in 0..encoded.len() {
            assert!(decode_ordering_bundle(&encoded[..end]).is_err());
        }
        let mut bytes = encoded.clone();
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_ordering_bundle(&bytes).is_err());
        let mut bytes = encoded;
        bytes.push(0);
        assert!(decode_ordering_bundle(&bytes).is_err());
        assert!(decode_ordering_bundle(&vec![0; wire::MAX_WIRE_BYTES + 1]).is_err());
        let exact = vec![7; wire::MAX_WIRE_BYTES - 12];
        let at_limit = encode_ordering_bundle([exact.as_slice(), &[]]).unwrap();
        assert_eq!(at_limit.len(), wire::MAX_WIRE_BYTES);
        assert_eq!(decode_ordering_bundle(&at_limit).unwrap()[0], exact);
        assert!(encode_ordering_bundle([exact.as_slice(), &[1]]).is_err());
    }

    #[test]
    fn ordering_batcher_preserves_per_peer_and_cross_layer_order_without_waiting() {
        let mut pending = OrderingBatcher::default();
        let mut sent: BTreeMap<Id, Vec<String>> = BTreeMap::new();
        for peer in recipients(None, 0, 4) {
            assert!(pending.push(peer, queued("CER", 1, 8)).is_empty());
        }
        assert!(pending.push(2, queued("HISTORY3", 2, 8)).is_empty());
        // This is the production cross-layer boundary: flush the DATA peer's
        // ordering prefix, without flushing another peer's still-open group.
        for peer in recipients(Some(2), 0, 4) {
            sent.entry(peer)
                .or_default()
                .extend(pending.take(peer).unwrap().into_iter().map(|m| m.kind));
            sent.entry(peer).or_default().push("DATA".into());
        }
        for peer in recipients(None, 0, 4) {
            assert!(pending.push(peer, queued("CLOSED", 3, 8)).is_empty());
        }
        for (peer, messages) in pending.drain() {
            sent.entry(peer)
                .or_default()
                .extend(messages.into_iter().map(|m| m.kind));
        }
        assert_eq!(sent[&1], ["CER", "CLOSED"]);
        assert_eq!(sent[&2], ["CER", "HISTORY3", "DATA", "CLOSED"]);
        assert_eq!(sent[&3], ["CER", "CLOSED"]);
        assert!(!sent.contains_key(&0));
        let mut single = OrderingBatcher::default();
        single.push(1, queued("PROG", 4, 8));
        assert_eq!(single.drain().next().unwrap().1.len(), 1);
    }

    #[test]
    fn ordering_batcher_flushes_count_and_byte_caps_with_single_frame_fallback() {
        let mut pending = OrderingBatcher::default();
        for _ in 0..MAX_ORDERING_BUNDLE_MEMBERS {
            assert!(pending.push(1, queued("PROG", 1, 8)).is_empty());
        }
        let ready = pending.push(1, queued("VOTE", 2, 8));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), MAX_ORDERING_BUNDLE_MEMBERS);
        let ready = pending.push(1, queued("PROPOSE", 3, wire::MAX_WIRE_BYTES));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0][0].kind, "VOTE");
        assert_eq!(ready[1][0].bytes.len(), wire::MAX_WIRE_BYTES);
        assert!(pending.take(1).is_none());
        pending.push(1, queued("PROPOSE", 4, wire::MAX_WIRE_BYTES - 8));
        let ready = pending.push(1, queued("CER", 5, 8));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0][0].bytes.len(), wire::MAX_WIRE_BYTES - 8);
        assert_eq!(pending.take(1).unwrap()[0].kind, "CER");
    }

    #[test]
    fn bundle_members_have_distinct_trace_keys_and_independent_protocol_validation() {
        let committee = Committee::new(
            [71; 32],
            (0..4).map(|id| wire::fixture_key(id).public).collect(),
        )
        .unwrap();
        let node = || {
            let availability = AvailabilityConfig::new(committee.clone(), 4).unwrap();
            let mut node = Node::new(
                committee.clone(),
                3,
                wire::fixture_key(3),
                100,
                availability,
                4,
            )
            .unwrap();
            node.set_opportunity_limit(4).unwrap();
            node.start(0).unwrap();
            node
        };
        // This proposal is authentically signed and bound, but its value and
        // witness fail the composition's Q predicate. Later valid PROGs from
        // other signers remain independently usable inside the same frame.
        let value = vec![1];
        let witness = vec![2];
        let bad_proposal = wire::Message::Propose(wire::Proposal {
            header: wire::sign(
                &wire::fixture_key(0),
                0,
                wire::Header {
                    context: committee.context.clone(),
                    round: 1,
                    value_hash: wire::hash(&value),
                    witness_hash: wire::hash(&witness),
                    history_hash: wire::hash(&crate::history::History::Empty),
                    entries: crate::history::Entries::empty(),
                },
            ),
            value,
            witness,
            history: crate::history::History::Empty,
        });
        let progress = |id| {
            wire::Message::Prog(wire::sign(
                &wire::fixture_key(id),
                id,
                wire::Statement {
                    context: committee.context.clone(),
                    kind: wire::Kind::Prog,
                    round: 1,
                    digest: None,
                },
            ))
        };
        let payloads = [
            wire::encode(&bad_proposal).unwrap(),
            vec![255],
            wire::encode(&progress(1)).unwrap(),
            wire::encode(&progress(2)).unwrap(),
        ];
        let received_at = Instant::now();
        let mut members = expand_received(Received {
            from: 0,
            sequence: 17,
            layer: Layer::OrderingBundle,
            payload: encode_ordering_bundle(payloads.iter().map(Vec::as_slice)).unwrap(),
            received_at,
        })
        .unwrap();
        let (mut bundled, mut single) = (node(), node());
        let mut rejected = 0;
        let mut keys = BTreeSet::new();
        for (index, bytes) in payloads.iter().enumerate() {
            // A caller takes precisely one item per turn; the remaining items
            // stay queued while normal control/timer/load checks execute.
            let received = members.pop_front().unwrap();
            assert_eq!(members.len(), payloads.len() - index - 1);
            assert_eq!(received.frame.received_at, received_at);
            assert_eq!(received.frame.payload, *bytes);
            assert_eq!(received.member_count, 4);
            assert!(keys.insert((
                received.frame.from,
                received.frame.sequence,
                received.member_index
            )));
            let apply = |node: &mut Node, bytes: &[u8]| {
                wire::decode(bytes)
                    .and_then(|message| node.receive_ordering(1 + index as u64, message))
            };
            let a = apply(&mut bundled, &received.frame.payload);
            let b = apply(&mut single, bytes);
            rejected += usize::from(a.is_err());
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_eq!(bundled.ordering.snapshot(), single.ordering.snapshot());
        }
        assert_eq!(rejected, 2);
        assert_eq!(bundled.ordering.current_round(), 2);
        assert!(members.is_empty());
    }

    #[test]
    fn bundled_progress_is_default_and_comparison_modes_are_explicit_and_bounded() {
        let value = json!({"instance":(vec![1u8;32]), "addresses":["127.0.0.1:12001","127.0.0.1:12002","127.0.0.1:12003","127.0.0.1:12004"],
            "control_addresses":["127.0.0.1:12005","127.0.0.1:12006","127.0.0.1:12007","127.0.0.1:12008"],
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..4).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":["0.key","1.key","2.key","3.key"],"bound_ms":100,"chunk_capacity":4,
            "workload_rounds":4,"silent":null,"max_runtime_ms":5000});
        let mut config: Config = serde_json::from_value(value).unwrap();
        assert!(config.ordering_batch);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::ProgressPacing {
                release_delay_ms: 100
            }
        );
        assert!(config.round_barrier_ms.is_none());
        assert!(config.progress_pacing_ms.is_none());
        config.validate(0).unwrap();
        for progress_only in [false, true] {
            for delay in [0, 1, 100, 101] {
                config.round_barrier_ms = (!progress_only).then_some(delay);
                config.progress_pacing_ms = progress_only.then_some(delay);
                assert_eq!(config.validate(0).is_ok(), (1..=100).contains(&delay));
                let encoded = serde_json::to_value(&config).unwrap();
                let decoded: Config = serde_json::from_value(encoded.clone()).unwrap();
                assert_eq!(decoded.round_barrier_ms, config.round_barrier_ms);
                assert_eq!(decoded.progress_pacing_ms, config.progress_pacing_ms);
                assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
            }
        }
        config.round_barrier_ms = None;
        config.progress_pacing_ms = None;
        config.ordering_mode = Some(OrderingMode::Canonical);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::Canonical
        );
        config.progress_pacing_ms = Some(50);
        assert!(config.validate(0).is_err());
        config.progress_pacing_ms = None;
        config.ordering_mode = Some(OrderingMode::Barrier);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::RoundBarrier {
                release_delay_ms: 100
            }
        );
        config.ordering_mode = Some(OrderingMode::Progress);
        config.round_barrier_ms = Some(50);
        assert!(config.validate(0).is_err());
        config.ordering_mode = None;
        for delay in [1, 100] {
            config.round_barrier_ms = Some(delay);
            config.progress_pacing_ms = Some(delay);
            assert!(config.validate(0).is_err());
        }
    }

    #[test]
    fn idle_receive_retains_prestart_packets_and_takes_only_one_when_eligible() {
        let (tx, rx) = mpsc::sync_channel(2);
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        let mut sleeps = Vec::new();
        assert_eq!(
            idle_receive(
                false,
                |_| -> Result<u32, mpsc::RecvTimeoutError> {
                    panic!("pre-start inbox must remain unread")
                },
                |timeout| sleeps.push(timeout),
            ),
            None
        );
        assert_eq!(sleeps, vec![Duration::from_millis(1)]);
        let pending = idle_receive(
            true,
            |timeout| {
                assert_eq!(timeout, Duration::from_millis(1));
                rx.recv_timeout(timeout)
            },
            |_| panic!("an arriving message must wake the idle turn without a sleep"),
        );
        assert_eq!(pending, Some(1));
        // The wakeup retains a single message; the ordinary turn can check
        // control before dispatching it without consuming a second message.
        assert_eq!(rx.try_recv().unwrap(), 2);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn idle_receive_timeout_does_not_sleep_twice_and_disconnect_does_not_spin() {
        let timeout = Duration::from_millis(1);
        assert_eq!(
            idle_receive::<u32>(
                true,
                |wait| {
                    assert_eq!(wait, timeout);
                    Err(mpsc::RecvTimeoutError::Timeout)
                },
                |_| panic!("the inbox timeout already waited"),
            ),
            None
        );
        let (tx, rx) = mpsc::channel::<u32>();
        drop(tx);
        let mut sleeps = Vec::new();
        assert_eq!(
            idle_receive(true, |wait| rx.recv_timeout(wait), |wait| sleeps.push(wait)),
            None
        );
        assert_eq!(sleeps, vec![timeout]);
    }

    #[test]
    fn sustained_transaction_size_and_ids_match_actual_canonical_encoding() {
        let transaction = sustained_transaction([4; 32], 1, 42, 512);
        assert_eq!(wire::encode(&transaction).unwrap().len(), 512);
        assert_eq!(transaction.bytes.len(), 472);
        assert_eq!(
            wire::encode(&vec![transaction.clone(); 10]).unwrap().len(),
            5128
        );
        assert_ne!(
            transaction.id,
            sustained_transaction([4; 32], 2, 42, 512).id
        );
        assert_ne!(
            transaction.id,
            sustained_transaction([4; 32], 1, 43, 512).id
        );
    }
    #[test]
    fn monotonic_load_schedule_uses_cumulative_fractional_rate_without_rounding_loss() {
        assert_eq!(scheduled_transactions(10_000, 250), 2);
        assert_eq!(scheduled_transactions(20_000, 250), 5);
        assert_eq!(scheduled_transactions(1_000_000, 250), 250);
        assert_eq!(scheduled_transactions(40_000_000, 1000), 40_000);
    }
    #[test]
    fn sustained_profile_rejects_impossible_batch_and_interval_settings() {
        let mut c = SustainedConfig {
            rate_per_replica: 1000,
            transaction_bytes: 512,
            batch_ms: 10,
            warmup_ms: 10_000,
            measurement_ms: 30_000,
        };
        c.validate().unwrap();
        c.transaction_bytes = 39;
        assert!(c.validate().is_err());
        c.transaction_bytes = 512;
        c.batch_ms = 1000;
        assert!(c.validate().is_err());
        c.batch_ms = 10;
        c.measurement_ms = 0;
        assert!(c.validate().is_err());
    }
    #[test]
    fn common_prefix_queries_use_the_exact_requested_output_boundary() {
        let rows = vec![
            composed::Executed {
                round: 1,
                producer: 0,
                height: 1,
                batch_digest: [1; 32],
                transaction: [2; 32],
                state_hash: [3; 32],
            },
            composed::Executed {
                round: 2,
                producer: 1,
                height: 1,
                batch_digest: [4; 32],
                transaction: [5; 32],
                state_hash: [6; 32],
            },
        ];
        assert_eq!(
            execution_prefix_hash(&rows, 0).unwrap(),
            wire::hash(&"delugi/deterministic-materialization/v1")
        );
        assert_eq!(execution_prefix_hash(&rows, 1).unwrap(), [3; 32]);
        assert_eq!(execution_prefix_hash(&rows, 2).unwrap(), [6; 32]);
        assert!(execution_prefix_hash(&rows, 3).is_err());
        assert!(execution_prefix_hash(&rows, u64::MAX).is_err());
    }
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
