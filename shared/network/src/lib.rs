//! Bounded TCP mechanism extracted from the audited Delugi transport.
//! Authentication, wire encoding, channel identity and accounting interpretation
//! are supplied by the core. Scheduling, FIFO, replay and byte leases are shared.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
pub type Id = u32;

pub trait Channel: Copy + Default + std::fmt::Debug + Eq + Ord + Send + Sync + 'static {}
impl<T: Copy + Default + std::fmt::Debug + Eq + Ord + Send + Sync + 'static> Channel for T {}

/// Metadata is local service context. It is never serialized by this crate.
#[derive(Clone, Debug)]
pub struct FrameMeta<C> {
    pub from: Id,
    pub to: Id,
    pub sequence: u64,
    pub layer: C,
    pub payload_length: u32,
    pub payload_hash: [u8; 32],
}
pub struct EncodedFrame<C> {
    pub auth: FrameMeta<C>,
    /// Includes the existing four-byte length prefix.
    pub bytes: Vec<u8>,
    pub payload_offset: usize,
}

pub trait Accounting<C>: Default + Send + 'static {
    fn validate(&self, channel: C, payload: &[u8]) -> Result<(), String>;
    fn written(
        &self,
        payload_offset: usize,
        payload_len: usize,
        start: usize,
        count: usize,
    ) -> WrittenCategories;
}

/// The caller owns all authentication semantics and exact byte formats.
/// Implementations are trusted core adapters, not untrusted peer plugins.
pub trait Authentication: Clone + Send + Sync + 'static {
    type Channel: Channel;
    type Accounting: Accounting<Self::Channel>;
    fn valid_local_identity(&self, id: Id, members: usize) -> bool;
    fn max_wire_bytes(&self) -> usize;
    fn max_frame_body_bytes(&self) -> usize;
    fn max_ack_bytes(&self) -> usize;
    fn profile_identifier(&self) -> String;
    fn written_category_boundary(&self) -> String;
    fn encode_frame(
        &self,
        from: Id,
        to: Id,
        sequence: u64,
        channel: Self::Channel,
        payload: Vec<u8>,
    ) -> Result<EncodedFrame<Self::Channel>, String>;
    fn decode_frame(
        &self,
        to: Id,
        bytes: &[u8],
    ) -> Result<(FrameMeta<Self::Channel>, Vec<u8>), String>;
    /// Return the exact framed ACK, including its existing length prefix.
    fn encode_ack(&self, id: Id, frame: &FrameMeta<Self::Channel>) -> Vec<u8>;
    fn verify_ack(&self, frame: &FrameMeta<Self::Channel>, bytes: &[u8]) -> Result<(), String>;
}

pub trait SettingsProvider {
    fn transport_settings(&self) -> TransportSettings;
}
/// Successful socket-write bytes, including partial attempts and exact replays.
/// Original batch payload excludes its signed header/vector framing. All FETCH,
/// DATA and DATA_PART protocol bytes are repair. Transport overhead includes
/// frame authentication, length prefixes, bundle framing and every ACK byte.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenCategories {
    pub payload_bytes: u64,
    pub evidence_control_bytes: u64,
    pub repair_bytes: u64,
    pub transport_overhead_bytes: u64,
    pub total_written_bytes: u64,
}

impl WrittenCategories {
    pub fn add(&mut self, other: Self) {
        self.payload_bytes += other.payload_bytes;
        self.evidence_control_bytes += other.evidence_control_bytes;
        self.repair_bytes += other.repair_bytes;
        self.transport_overhead_bytes += other.transport_overhead_bytes;
        self.total_written_bytes += other.total_written_bytes;
    }
}

#[derive(Clone, Debug)]
pub struct TransportSettings {
    pub inbox_capacity: usize,
    pub outbox_capacity: usize,
    /// Additional frames retained per peer when its writer mailbox is full.
    /// These share the aggregate and per-peer byte budgets with queued frames.
    pub max_deferred_frames_per_peer: usize,
    /// Unacknowledged frames retained by each writer, separate from its outbox.
    pub max_inflight_frames: usize,
    /// Encoded bytes in the window; one additional dequeued frame may be staged.
    pub max_inflight_bytes: usize,
    /// Aggregate bytes retained by all peer outboxes/windows, not per peer.
    pub max_outstanding_bytes: usize,
    /// Payload bytes accepted into the shared protocol mailbox.
    pub max_inbox_bytes: usize,
    /// Aggregate unauthenticated socket frame buffers across all readers.
    pub max_read_buffer_bytes: usize,
    /// Maximum wait for the oldest fully written frame's ACK; idle links do not expire.
    pub ack_timeout: Duration,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub frame_read_timeout: Duration,
    pub reconnect_delay: Duration,
    pub max_reader_connections: usize,
}

impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            inbox_capacity: 4096,
            outbox_capacity: 4096,
            max_deferred_frames_per_peer: 4096,
            max_inflight_frames: 64,
            max_inflight_bytes: 8 * 1024 * 1024,
            max_outstanding_bytes: 128 * 1024 * 1024,
            max_inbox_bytes: 32 * 1024 * 1024,
            max_read_buffer_bytes: 32 * 1024 * 1024,
            ack_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(100),
            io_timeout: Duration::from_millis(250),
            frame_read_timeout: Duration::from_secs(2),
            reconnect_delay: Duration::from_millis(20),
            max_reader_connections: 64,
        }
    }
}

impl TransportSettings {
    /// Compatibility name: this delegates to a generic settings provider.
    pub fn for_committee<P: SettingsProvider>(provider: &P) -> Self {
        provider.transport_settings()
    }
    /// Compatibility name: the core owns profile selection and values.
    pub fn for_profile<P: SettingsProvider>(provider: P) -> Self {
        provider.transport_settings()
    }
}

#[derive(Debug)]
pub struct Received<C> {
    pub from: Id,
    pub sequence: u64,
    pub layer: C,
    pub payload: Vec<u8>,
    /// Recorded when this authenticated frame first enters the local mailbox.
    pub received_at: Instant,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LayerCounters {
    /// Accepted into the bounded transport, including deferred FIFO entries.
    #[serde(default)]
    pub scheduled_frames: u64,
    #[serde(default)]
    pub scheduled_payload_bytes: u64,
    pub enqueued_frames: u64,
    pub enqueued_payload_bytes: u64,
    /// Includes framing/authentication and bytes from partial or repeated writes.
    pub data_bytes_written: u64,
    /// Actual portions of successful writes falling in the protocol payload.
    pub payload_bytes_written: u64,
    pub full_frames_written: u64,
    pub acknowledged_frames: u64,
    pub accepted_frames: u64,
    pub accepted_payload_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerCounters<C: Ord> {
    pub layers: BTreeMap<C, LayerCounters>,
    #[serde(default)]
    pub written_categories: WrittenCategories,
    pub outstanding_frames: u64,
    #[serde(default)]
    pub deferred_frames: u64,
    #[serde(default)]
    pub deferred_bytes: u64,
    #[serde(default)]
    pub maximum_deferred_frames: u64,
    #[serde(default)]
    pub maximum_deferred_bytes: u64,
    #[serde(default)]
    pub retained_outbound_bytes: u64,
    #[serde(default)]
    pub maximum_retained_outbound_bytes: u64,
    /// Retained window, including a frame currently being written or replayed.
    #[serde(default)]
    pub inflight_frames: u64,
    #[serde(default)]
    pub inflight_bytes: u64,
    #[serde(default)]
    pub maximum_inflight_frames: u64,
    #[serde(default)]
    pub maximum_inflight_bytes: u64,
    pub connection_attempts: u64,
    pub connection_failures: u64,
    pub established_connections: u64,
    pub retries: u64,
    pub write_failures: u64,
    /// Successfully written bytes in a frame whose write subsequently failed.
    pub partial_frame_bytes_written: u64,
    pub ack_failures: u64,
    pub ack_bytes_read: u64,
    pub ack_bytes_written: u64,
    pub duplicate_frames: u64,
    pub verified_data_bytes_read: u64,
    pub incoming_errors: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransportSnapshot<C: Ord> {
    pub peers: BTreeMap<Id, PeerCounters<C>>,
    #[serde(default)]
    pub written_category_boundary: String,
    /// All data-stream bytes read, including malformed/unauthenticated frames.
    pub data_bytes_read: u64,
    pub rejected_frames: u64,
    pub rejected_connections: u64,
    pub accepted_connections: u64,
    pub queue_full_failures: u64,
    /// Mailbox saturation handled by retaining the exact frame for retry.
    #[serde(default)]
    pub deferred_accepts: u64,
    #[serde(default)]
    pub deferred_retry_blocked: u64,
    /// Terminal exhaustion of the declared byte/frame envelope, never a drop.
    #[serde(default)]
    pub resource_exhaustions: u64,
    #[serde(default)]
    pub inbox_payload_bytes: u64,
    #[serde(default)]
    pub maximum_inbox_payload_bytes: u64,
    #[serde(default)]
    pub retained_outbound_bytes: u64,
    #[serde(default)]
    pub maximum_retained_outbound_bytes: u64,
    #[serde(default)]
    pub read_buffer_bytes: u64,
    #[serde(default)]
    pub maximum_read_buffer_bytes: u64,
    #[serde(default)]
    pub resource_profile: String,
    #[serde(default)]
    pub limits: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct ByteBudget {
    used: AtomicUsize,
    high_water: AtomicUsize,
    maximum: usize,
}

impl ByteBudget {
    fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            high_water: AtomicUsize::new(0),
            maximum,
        })
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<ByteReservation> {
        let previous = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= self.maximum)
            })
            .ok()?;
        self.high_water
            .fetch_max(previous + bytes, Ordering::Relaxed);
        Some(ByteReservation {
            budget: self.clone(),
            bytes,
        })
    }
}

#[derive(Debug)]
struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct QueuedFrame<P: Authentication> {
    auth: FrameMeta<P::Channel>,
    bytes: Vec<u8>,
    payload_offset: usize,
    accounting: P::Accounting,
    reservation: Option<ByteReservation>,
    peer_reservation: Option<ByteReservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendReceipt {
    pub sequence: u64,
    /// False means successfully enqueued to the writer; true means retained
    /// in the bounded FIFO until a later retry_deferred call succeeds.
    pub deferred: bool,
}

type Stats<C> = Arc<Mutex<TransportSnapshot<C>>>;

pub struct Transport<P: Authentication> {
    id: Id,
    policy: P,
    outgoing: BTreeMap<Id, SyncSender<QueuedFrame<P>>>,
    sequences: BTreeMap<Id, u64>,
    incoming: Receiver<Received<P::Channel>>,
    stop: Arc<AtomicBool>,
    stats: Stats<P::Channel>,
    outbound_budget: Arc<ByteBudget>,
    peer_outbound_budgets: BTreeMap<Id, Arc<ByteBudget>>,
    deferred: BTreeMap<Id, VecDeque<QueuedFrame<P>>>,
    max_deferred_frames_per_peer: usize,
    retry_cursor: usize,
    read_budget: Arc<ByteBudget>,
    handles: Vec<JoinHandle<()>>,
}

impl<P: Authentication> Transport<P> {
    /// Read-only facade identity; does not alter transport scheduling or wire data.
    pub fn local_id(&self) -> Id { self.id }
    pub fn max_wire_bytes(&self) -> usize { self.policy.max_wire_bytes() }

    pub fn bind(
        id: Id,
        policy: P,
        addresses: Vec<SocketAddr>,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        let bind_address = *addresses
            .get(id as usize)
            .ok_or("invalid local transport identity")?;
        Self::bind_at(id, policy, addresses, bind_address, settings)
    }

    /// Bind locally while peer destinations use their advertised addresses.
    pub fn bind_at(
        id: Id,
        policy: P,
        addresses: Vec<SocketAddr>,
        bind_address: SocketAddr,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        if !policy.valid_local_identity(id, addresses.len()) {
            return Err("transport identity/address list does not match committee".into());
        }
        if settings.inbox_capacity == 0
            || settings.outbox_capacity == 0
            || settings.max_deferred_frames_per_peer == 0
            || settings.max_inflight_frames == 0
            || settings.max_inflight_bytes < policy.max_frame_body_bytes() + 4
            || settings.max_outstanding_bytes / (addresses.len() - 1).max(1)
                < policy.max_frame_body_bytes() + 4
            || settings.max_inbox_bytes < policy.max_wire_bytes()
            || settings.max_read_buffer_bytes < policy.max_frame_body_bytes()
            || settings.ack_timeout.is_zero()
            || settings.max_reader_connections == 0
            || settings.connect_timeout.is_zero()
            || settings.io_timeout.is_zero()
            || settings.frame_read_timeout.is_zero()
            || settings.reconnect_delay.is_zero()
        {
            return Err("transport bounds and timeouts must be positive".into());
        }
        let listener = TcpListener::bind(bind_address).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let (in_tx, incoming) = mpsc::sync_channel(settings.inbox_capacity);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(TransportSnapshot {
            peers: (0..addresses.len() as Id)
                .filter(|peer| *peer != id)
                .map(|peer| (peer, PeerCounters::default()))
                .collect(),
            written_category_boundary: policy.written_category_boundary(),
            resource_profile: policy.profile_identifier(),
            limits: [
                ("protocol_message_bytes", policy.max_wire_bytes() as u64),
                (
                    "frame_bytes_excluding_length_prefix",
                    policy.max_frame_body_bytes() as u64,
                ),
                ("inbox_frames", settings.inbox_capacity as u64),
                ("outbox_frames_per_peer", settings.outbox_capacity as u64),
                (
                    "deferred_frames_per_peer",
                    settings.max_deferred_frames_per_peer as u64,
                ),
                (
                    "retained_outbound_bytes_per_peer",
                    (settings.max_outstanding_bytes / (addresses.len() - 1).max(1)) as u64,
                ),
                (
                    "inflight_frames_per_peer",
                    settings.max_inflight_frames as u64,
                ),
                (
                    "inflight_bytes_per_peer",
                    settings.max_inflight_bytes as u64,
                ),
                (
                    "retained_outbound_bytes",
                    settings.max_outstanding_bytes as u64,
                ),
                ("inbox_payload_bytes", settings.max_inbox_bytes as u64),
                ("read_buffer_bytes", settings.max_read_buffer_bytes as u64),
                ("reader_connections", settings.max_reader_connections as u64),
                (
                    "frame_read_timeout_ms",
                    settings.frame_read_timeout.as_millis() as u64,
                ),
                ("ack_timeout_ms", settings.ack_timeout.as_millis() as u64),
            ]
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect(),
            ..TransportSnapshot::default()
        }));
        let outbound_budget = ByteBudget::new(settings.max_outstanding_bytes);
        let peer_outbound_budgets = (0..addresses.len() as Id)
            .filter(|peer| *peer != id)
            .map(|peer| {
                (
                    peer,
                    ByteBudget::new(settings.max_outstanding_bytes / (addresses.len() - 1).max(1)),
                )
            })
            .collect();
        let max_deferred_frames_per_peer = settings.max_deferred_frames_per_peer;
        let read_budget = ByteBudget::new(settings.max_read_buffer_bytes);
        let mut outgoing = BTreeMap::new();
        let mut handles = Vec::new();
        for (peer, address) in addresses.into_iter().enumerate() {
            let peer = peer as Id;
            if peer == id {
                continue;
            }
            let (tx, rx) = mpsc::sync_channel(settings.outbox_capacity);
            outgoing.insert(peer, tx);
            let args = (
                policy.clone(),
                settings.clone(),
                stop.clone(),
                stats.clone(),
            );
            handles.push(thread::spawn(move || {
                writer(peer, address, rx, args.0, args.1, args.2, args.3)
            }));
        }
        let args = (
            policy.clone(),
            settings,
            stop.clone(),
            stats.clone(),
            read_budget.clone(),
        );
        handles.push(thread::spawn(move || {
            accept_loop(id, listener, in_tx, args.0, args.1, args.2, args.3, args.4)
        }));
        Ok(Self {
            id,
            policy,
            outgoing,
            sequences: BTreeMap::new(),
            incoming,
            stop,
            stats,
            outbound_budget,
            peer_outbound_budgets,
            deferred: BTreeMap::new(),
            max_deferred_frames_per_peer,
            retry_cursor: 0,
            read_budget,
            handles,
        })
    }

    fn prepare(
        &self,
        to: Id,
        layer: P::Channel,
        payload: Vec<u8>,
        accounting: P::Accounting,
    ) -> Result<QueuedFrame<P>, String> {
        if self.stop.load(Ordering::Acquire) {
            return Err("transport is shut down".into());
        }
        if !self.outgoing.contains_key(&to) {
            return Err("invalid/self destination".into());
        }
        accounting.validate(layer, &payload)?;
        let sequence = self
            .sequences
            .get(&to)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("transport sequence exhausted")?;
        let encoded = self
            .policy
            .encode_frame(self.id, to, sequence, layer, payload)?;
        let mut frame = QueuedFrame {
            auth: encoded.auth,
            bytes: encoded.bytes,
            payload_offset: encoded.payload_offset,
            accounting,
            reservation: None,
            peer_reservation: None,
        };
        frame.reservation = Some(self.outbound_budget.reserve(frame.bytes.len()).ok_or_else(
            || {
                self.stats.lock().unwrap().resource_exhaustions += 1;
                "transport resource envelope exhausted: aggregate retained byte budget".to_string()
            },
        )?);
        frame.peer_reservation = Some(
            self.peer_outbound_budgets[&to]
                .reserve(frame.bytes.len())
                .ok_or_else(|| {
                    self.stats.lock().unwrap().resource_exhaustions += 1;
                    format!(
                        "transport resource envelope exhausted: retained byte budget for peer {to}"
                    )
                })?,
        );
        Ok(frame)
    }

    fn enqueue(&self, frame: QueuedFrame<P>) -> Result<(), TrySendError<QueuedFrame<P>>> {
        let to = frame.auth.to;
        let layer = frame.auth.layer;
        let payload_length = frame.auth.payload_length as u64;
        // Hold this lock over the enqueue so worker counters cannot precede
        // logical enqueue, including the outstanding decrement on fast peers.
        let mut stats = self.stats.lock().unwrap();
        match self.outgoing[&to].try_send(frame) {
            Ok(()) => {
                let peer = stats.peers.get_mut(&to).unwrap();
                peer.outstanding_frames += 1;
                let layer = peer.layers.entry(layer).or_default();
                layer.enqueued_frames += 1;
                layer.enqueued_payload_bytes += payload_length;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn scheduled(&mut self, to: Id, layer: P::Channel, sequence: u64, payload_length: u64) {
        self.sequences.insert(to, sequence);
        let mut stats = self.stats.lock().unwrap();
        let layer = stats
            .peers
            .get_mut(&to)
            .unwrap()
            .layers
            .entry(layer)
            .or_default();
        layer.scheduled_frames += 1;
        layer.scheduled_payload_bytes += payload_length;
    }

    /// Immediate enqueue retained for callers that explicitly handle failure.
    /// The process runtime uses send_or_defer so mailbox saturation is retried.
    pub fn send(&mut self, to: Id, layer: P::Channel, payload: Vec<u8>) -> Result<u64, String> {
        if self
            .deferred
            .get(&to)
            .is_some_and(|queue| !queue.is_empty())
        {
            return Err(format!("peer {to} has an earlier deferred FIFO entry"));
        }
        let frame = self.prepare(to, layer, payload, P::Accounting::default())?;
        let sequence = frame.auth.sequence;
        let payload_length = frame.auth.payload_length as u64;
        match self.enqueue(frame) {
            Ok(()) => {
                self.scheduled(to, layer, sequence, payload_length);
                Ok(sequence)
            }
            Err(TrySendError::Full(_frame)) => {
                self.stats.lock().unwrap().queue_full_failures += 1;
                Err(format!("bounded transport outbox for peer {to} is full"))
            }
            Err(TrySendError::Disconnected(_frame)) => Err(format!("writer for peer {to} stopped")),
        }
    }

    /// Own the exact signed frame until it is queued and acknowledged. A full
    /// writer mailbox is temporary backpressure, not a lost protocol effect.
    /// FIFO spans every layer; a new frame never overtakes a deferred one.
    /// Exhausting the declared finite envelope is an explicit terminal error.
    pub fn send_or_defer(
        &mut self,
        to: Id,
        layer: P::Channel,
        payload: Vec<u8>,
    ) -> Result<SendReceipt, String> {
        self.send_or_defer_accounted(to, layer, payload, P::Accounting::default())
    }

    /// Accounting metadata follows the exact frame through deferral/replay and
    /// does not change serialized bytes, authenticated identity or sequencing.
    pub fn send_or_defer_accounted(
        &mut self,
        to: Id,
        layer: P::Channel,
        payload: Vec<u8>,
        accounting: P::Accounting,
    ) -> Result<SendReceipt, String> {
        let backlog = self.deferred.get(&to).map_or(0, VecDeque::len);
        if backlog >= self.max_deferred_frames_per_peer {
            self.stats.lock().unwrap().resource_exhaustions += 1;
            return Err(format!(
                "transport resource envelope exhausted: deferred frame budget for peer {to}"
            ));
        }
        let frame = self.prepare(to, layer, payload, accounting)?;
        let sequence = frame.auth.sequence;
        let payload_length = frame.auth.payload_length as u64;
        let pending = if backlog > 0 {
            Some(frame)
        } else {
            match self.enqueue(frame) {
                Ok(()) => None,
                Err(TrySendError::Full(frame)) => Some(frame),
                Err(TrySendError::Disconnected(_frame)) => {
                    return Err(format!("writer for peer {to} stopped"))
                }
            }
        };
        let deferred = pending.is_some();
        if let Some(frame) = pending {
            let bytes = frame.bytes.len() as u64;
            self.deferred.entry(to).or_default().push_back(frame);
            let mut stats = self.stats.lock().unwrap();
            stats.deferred_accepts += 1;
            let peer = stats.peers.get_mut(&to).unwrap();
            peer.deferred_frames += 1;
            peer.deferred_bytes += bytes;
            peer.maximum_deferred_frames = peer.maximum_deferred_frames.max(peer.deferred_frames);
            peer.maximum_deferred_bytes = peer.maximum_deferred_bytes.max(peer.deferred_bytes);
        }
        self.scheduled(to, layer, sequence, payload_length);
        Ok(SendReceipt { sequence, deferred })
    }

    /// One head per peer per call, with a rotating first peer. Never wait on a
    /// blocked peer and never rebuild/re-sign a retained frame. The event loop
    /// calls this before handling its next input, including during drain.
    pub fn retry_deferred(&mut self) -> Result<usize, String> {
        if self.stop.load(Ordering::Acquire) {
            return Err("transport is shut down".into());
        }
        let peers: Vec<_> = self.outgoing.keys().copied().collect();
        if peers.is_empty() {
            return Ok(0);
        }
        let first = self.retry_cursor % peers.len();
        self.retry_cursor = (first + 1) % peers.len();
        let mut enqueued = 0;
        for offset in 0..peers.len() {
            let peer = peers[(first + offset) % peers.len()];
            let Some(frame) = self.deferred.get_mut(&peer).and_then(VecDeque::pop_front) else {
                continue;
            };
            let bytes = frame.bytes.len() as u64;
            match self.enqueue(frame) {
                Ok(()) => {
                    enqueued += 1;
                    let mut stats = self.stats.lock().unwrap();
                    let counters = stats.peers.get_mut(&peer).unwrap();
                    counters.deferred_frames -= 1;
                    counters.deferred_bytes -= bytes;
                }
                Err(TrySendError::Full(frame)) => {
                    self.deferred.get_mut(&peer).unwrap().push_front(frame);
                    self.stats.lock().unwrap().deferred_retry_blocked += 1;
                }
                Err(TrySendError::Disconnected(frame)) => {
                    self.deferred.get_mut(&peer).unwrap().push_front(frame);
                    return Err(format!(
                        "writer for peer {peer} stopped with a retained frame"
                    ));
                }
            }
        }
        Ok(enqueued)
    }

    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Received<P::Channel>, RecvTimeoutError> {
        let incoming = self.incoming.recv_timeout(timeout)?;
        self.stats.lock().unwrap().inbox_payload_bytes -= incoming.payload.len() as u64;
        Ok(incoming)
    }

    pub fn try_recv(&self) -> Result<Received<P::Channel>, mpsc::TryRecvError> {
        let incoming = self.incoming.try_recv()?;
        self.stats.lock().unwrap().inbox_payload_bytes -= incoming.payload.len() as u64;
        Ok(incoming)
    }

    pub fn snapshot(&self) -> TransportSnapshot<P::Channel> {
        let mut snapshot = self.stats.lock().unwrap().clone();
        for (peer, budget) in &self.peer_outbound_budgets {
            let counters = snapshot.peers.get_mut(peer).unwrap();
            counters.retained_outbound_bytes = budget.used.load(Ordering::Acquire) as u64;
            counters.maximum_retained_outbound_bytes =
                budget.high_water.load(Ordering::Acquire) as u64;
        }
        snapshot.retained_outbound_bytes = self.outbound_budget.used.load(Ordering::Acquire) as u64;
        snapshot.maximum_retained_outbound_bytes =
            self.outbound_budget.high_water.load(Ordering::Acquire) as u64;
        snapshot.read_buffer_bytes = self.read_budget.used.load(Ordering::Acquire) as u64;
        snapshot.maximum_read_buffer_bytes =
            self.read_budget.high_water.load(Ordering::Acquire) as u64;
        snapshot
    }

    /// Stop accepting/retrying, interrupt bounded I/O waits, and join workers.
    /// Pending frames remain visible in the final outstanding-frame counters.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.outgoing.clear();
        self.deferred.clear();
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}

impl<P: Authentication> Drop for Transport<P> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn configure(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
    // BSD/macOS accept inherits the listener's O_NONBLOCK flag. Our workers use
    // blocking I/O with timeouts; leaving it set would busy-spin on WouldBlock.
    stream.set_nonblocking(false)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "transport shutdown")
}

fn write_counted(
    stream: &mut impl Write,
    bytes: &[u8],
    stop: &AtomicBool,
    mut on_write: impl FnMut(usize, usize),
) -> (usize, io::Result<()>) {
    let mut written = 0;
    while written < bytes.len() {
        if stop.load(Ordering::Acquire) {
            return (written, Err(stopped()));
        }
        match stream.write(&bytes[written..]) {
            Ok(0) => {
                return (
                    written,
                    Err(io::Error::new(io::ErrorKind::WriteZero, "TCP write zero")),
                )
            }
            Ok(n) => {
                on_write(written, n);
                written += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return (written, Err(e)),
        }
    }
    (written, Ok(()))
}

/// The initial prefix may idle indefinitely at the receiving end; after any
/// frame byte arrives a bounded total read deadline prevents stalled readers.
fn read_frame(
    stream: &mut TcpStream,
    maximum: usize,
    stop: &AtomicBool,
    allow_idle: bool,
    on_read: &mut impl FnMut(usize),
) -> io::Result<Vec<u8>> {
    read_frame_reserved(
        stream,
        maximum,
        stop,
        allow_idle,
        on_read,
        None,
        Duration::from_secs(2),
    )
    .map(|(bytes, _)| bytes)
}

fn read_frame_reserved(
    stream: &mut TcpStream,
    maximum: usize,
    stop: &AtomicBool,
    allow_idle: bool,
    on_read: &mut impl FnMut(usize),
    budget: Option<&Arc<ByteBudget>>,
    frame_timeout: Duration,
) -> io::Result<(Vec<u8>, Option<ByteReservation>)> {
    let mut prefix = [0u8; 4];
    let mut position = 0;
    let mut deadline = if allow_idle {
        None
    } else {
        Some(Instant::now() + frame_timeout)
    };
    while position < prefix.len() {
        if stop.load(Ordering::Acquire) {
            return Err(stopped());
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "frame deadline"));
        }
        match stream.read(&mut prefix[position..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    if position == 0 {
                        io::ErrorKind::ConnectionAborted
                    } else {
                        io::ErrorKind::UnexpectedEof
                    },
                    "TCP closed",
                ))
            }
            Ok(n) => {
                on_read(n);
                position += n;
                deadline.get_or_insert(Instant::now() + frame_timeout);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    // Reserve before allocation; blocked readers apply TCP backpressure without
    // consuming arbitrary declared lengths. Idle connections hold no byte lease.
    let reservation = if let Some(budget) = budget {
        loop {
            if stop.load(Ordering::Acquire) {
                return Err(stopped());
            }
            if let Some(reservation) = budget.reserve(length) {
                break Some(reservation);
            }
            pause(stop, Duration::from_millis(1));
        }
    } else {
        None
    };
    // Local backpressure is not a peer's stalled-body timeout.
    deadline = Some(Instant::now() + frame_timeout);
    let mut bytes = vec![0; length];
    let mut position = 0;
    while position < length {
        if stop.load(Ordering::Acquire) {
            return Err(stopped());
        }
        if deadline.is_some_and(|at| Instant::now() >= at) {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "frame deadline"));
        }
        match stream.read(&mut bytes[position..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TCP closed")),
            Ok(n) => {
                on_read(n);
                position += n;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok((bytes, reservation))
}

fn pause(stop: &AtomicBool, duration: Duration) {
    let deadline = Instant::now() + duration;
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep((deadline - Instant::now().min(deadline)).min(Duration::from_millis(5)));
    }
}

struct PendingFrame<P: Authentication> {
    frame: QueuedFrame<P>,
    attempted: bool,
    sent_at: Option<Instant>,
}

/// The reader belongs to exactly one connection. Closing it interrupts both I/O
/// and a full notification queue before joining, so no old ACK can affect replay.
struct WriterConnection {
    stream: TcpStream,
    acknowledgements: Receiver<io::Result<Vec<u8>>>,
    cancel: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl WriterConnection {
    fn open<C: Channel>(
        address: SocketAddr,
        peer: Id,
        settings: &TransportSettings,
        stats: Stats<C>,
        maximum_ack_bytes: usize,
    ) -> io::Result<Self> {
        let stream = TcpStream::connect_timeout(&address, settings.connect_timeout)?;
        configure(&stream, settings.io_timeout)?;
        let mut input = stream.try_clone()?;
        let cancel = Arc::new(AtomicBool::new(false));
        let reader_cancel = cancel.clone();
        let (tx, acknowledgements) = mpsc::sync_channel(settings.max_inflight_frames);
        let reader = thread::spawn(move || {
            while !reader_cancel.load(Ordering::Acquire) {
                // Idle sockets may remain open. The writer times out the oldest
                // outstanding frame, while read_frame bounds partial ACK reads.
                let mut result = read_frame(
                    &mut input,
                    maximum_ack_bytes,
                    &reader_cancel,
                    true,
                    &mut |n| {
                        stats
                            .lock()
                            .unwrap()
                            .peers
                            .get_mut(&peer)
                            .unwrap()
                            .ack_bytes_read += n as u64;
                    },
                );
                let failed = result.is_err();
                loop {
                    if reader_cancel.load(Ordering::Acquire) {
                        return;
                    }
                    match tx.try_send(result) {
                        Ok(()) => break,
                        Err(TrySendError::Full(value)) => {
                            result = value;
                            pause(&reader_cancel, Duration::from_millis(1));
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                if failed {
                    break;
                }
            }
        });
        Ok(Self {
            stream,
            acknowledgements,
            cancel,
            reader: Some(reader),
        })
    }
}

impl Drop for WriterConnection {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn retire_ack<P: Authentication>(
    ack: io::Result<Vec<u8>>,
    pending: &mut VecDeque<PendingFrame<P>>,
    pending_bytes: &mut usize,
    policy: &P,
    peer: Id,
    stats: &Stats<P::Channel>,
) -> Result<(), ()> {
    let valid = ack.ok().is_some_and(|bytes| {
        pending.front().is_some_and(|entry| {
            entry.sent_at.is_some() && policy.verify_ack(&entry.frame.auth, &bytes).is_ok()
        })
    });
    if !valid {
        return Err(());
    }
    let entry = pending.pop_front().unwrap();
    *pending_bytes -= entry.frame.bytes.len();
    let mut stats = stats.lock().unwrap();
    let counters = stats.peers.get_mut(&peer).unwrap();
    counters
        .layers
        .entry(entry.frame.auth.layer)
        .or_default()
        .acknowledged_frames += 1;
    counters.outstanding_frames -= 1;
    counters.inflight_frames = pending.len() as u64;
    counters.inflight_bytes = *pending_bytes as u64;
    Ok(())
}

fn writer<P: Authentication>(
    peer: Id,
    address: SocketAddr,
    rx: Receiver<QueuedFrame<P>>,
    policy: P,
    settings: TransportSettings,
    stop: Arc<AtomicBool>,
    stats: Stats<P::Channel>,
) {
    let mut connection: Option<WriterConnection> = None;
    let mut pending = VecDeque::<PendingFrame<P>>::new();
    let mut pending_bytes = 0usize;
    // Dequeue at most one frame beyond the window to inspect its byte size.
    let mut staged: Option<QueuedFrame<P>> = None;
    let mut received_ack = None;
    while !stop.load(Ordering::Acquire) {
        let mut ack_failed = false;
        if let Some(active) = &connection {
            loop {
                let ack =
                    received_ack
                        .take()
                        .or_else(|| match active.acknowledgements.try_recv() {
                            Ok(ack) => Some(ack),
                            Err(mpsc::TryRecvError::Empty) => None,
                            Err(mpsc::TryRecvError::Disconnected) => Some(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "ACK reader stopped",
                            ))),
                        });
                let Some(ack) = ack else { break };
                if retire_ack(ack, &mut pending, &mut pending_bytes, &policy, peer, &stats).is_err()
                {
                    ack_failed = true;
                    break;
                }
            }
            if pending
                .front()
                .and_then(|entry| entry.sent_at)
                .is_some_and(|at| at.elapsed() >= settings.ack_timeout)
            {
                ack_failed = true;
            }
        }
        if ack_failed {
            // An idle peer closing is normal and does not fail any frame's ACK.
            if !pending.is_empty() {
                stats
                    .lock()
                    .unwrap()
                    .peers
                    .get_mut(&peer)
                    .unwrap()
                    .ack_failures += 1;
            }
            connection.take();
            for entry in &mut pending {
                entry.sent_at = None;
            }
            pause(&stop, settings.reconnect_delay);
            continue;
        }

        // Replay the retained suffix completely before admitting new frames.
        if connection.is_some() {
            if let Some(entry) = pending.iter_mut().find(|entry| entry.sent_at.is_none()) {
                if entry.attempted {
                    stats.lock().unwrap().peers.get_mut(&peer).unwrap().retries += 1;
                }
                entry.attempted = true;
                let (written, result) = write_counted(
                    &mut connection.as_mut().unwrap().stream,
                    &entry.frame.bytes,
                    &stop,
                    |offset, count| {
                        let mut stats = stats.lock().unwrap();
                        let counters = stats.peers.get_mut(&peer).unwrap();
                        counters
                            .written_categories
                            .add(entry.frame.accounting.written(
                                entry.frame.payload_offset,
                                entry.frame.auth.payload_length as usize,
                                offset,
                                count,
                            ));
                        let layer = counters.layers.entry(entry.frame.auth.layer).or_default();
                        layer.data_bytes_written += count as u64;
                        layer.payload_bytes_written += (offset + count)
                            .saturating_sub(entry.frame.payload_offset)
                            .saturating_sub(offset.saturating_sub(entry.frame.payload_offset))
                            as u64;
                    },
                );
                {
                    let mut stats = stats.lock().unwrap();
                    let counters = stats.peers.get_mut(&peer).unwrap();
                    let layer = counters.layers.entry(entry.frame.auth.layer).or_default();
                    if result.is_ok() {
                        layer.full_frames_written += 1;
                    } else {
                        counters.write_failures += 1;
                        counters.partial_frame_bytes_written += written as u64;
                    }
                }
                if result.is_ok() {
                    entry.sent_at = Some(Instant::now());
                } else {
                    connection.take();
                    for entry in &mut pending {
                        entry.sent_at = None;
                    }
                    pause(&stop, settings.reconnect_delay);
                }
                continue;
            }
        }

        if staged.is_none() && pending.len() < settings.max_inflight_frames {
            // Fresh sends wake recv_timeout immediately. With traffic in flight,
            // an ACK waits at most 1ms here; a full window waits on ACKs directly.
            match rx.recv_timeout(if pending.is_empty() {
                Duration::from_millis(20)
            } else {
                Duration::from_millis(1)
            }) {
                Ok(frame) => staged = Some(frame),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
        if connection.is_none() && (!pending.is_empty() || staged.is_some()) {
            stats
                .lock()
                .unwrap()
                .peers
                .get_mut(&peer)
                .unwrap()
                .connection_attempts += 1;
            match WriterConnection::open(
                address,
                peer,
                &settings,
                stats.clone(),
                policy.max_ack_bytes(),
            ) {
                Ok(active) => {
                    stats
                        .lock()
                        .unwrap()
                        .peers
                        .get_mut(&peer)
                        .unwrap()
                        .established_connections += 1;
                    connection = Some(active);
                }
                Err(_) => {
                    stats
                        .lock()
                        .unwrap()
                        .peers
                        .get_mut(&peer)
                        .unwrap()
                        .connection_failures += 1;
                    pause(&stop, settings.reconnect_delay);
                }
            }
            // In particular, reconnect must replay pending before staged.
            continue;
        }
        if connection.is_none() {
            continue;
        }
        if staged.as_ref().is_some_and(|frame| {
            pending.len() < settings.max_inflight_frames
                && frame.bytes.len() <= settings.max_inflight_bytes - pending_bytes
        }) {
            let frame = staged.take().unwrap();
            pending_bytes += frame.bytes.len();
            pending.push_back(PendingFrame {
                frame,
                attempted: false,
                sent_at: None,
            });
            let mut stats = stats.lock().unwrap();
            let counters = stats.peers.get_mut(&peer).unwrap();
            counters.inflight_frames = pending.len() as u64;
            counters.inflight_bytes = pending_bytes as u64;
            counters.maximum_inflight_frames = counters
                .maximum_inflight_frames
                .max(counters.inflight_frames);
            counters.maximum_inflight_bytes =
                counters.maximum_inflight_bytes.max(counters.inflight_bytes);
            continue;
        }
        if !pending.is_empty()
            && (staged.is_some() || pending.len() == settings.max_inflight_frames)
        {
            match connection
                .as_ref()
                .unwrap()
                .acknowledgements
                .recv_timeout(Duration::from_millis(20))
            {
                Ok(ack) => received_ack = Some(ack),
                Err(RecvTimeoutError::Disconnected) => {
                    received_ack = Some(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "ACK reader stopped",
                    )));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
    // Drop closes the socket and joins its ACK reader, including on shutdown.
}

#[allow(clippy::too_many_arguments)]
fn accept_loop<P: Authentication>(
    id: Id,
    listener: TcpListener,
    inbox: SyncSender<Received<P::Channel>>,
    policy: P,
    settings: TransportSettings,
    stop: Arc<AtomicBool>,
    stats: Stats<P::Channel>,
    read_budget: Arc<ByteBudget>,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(Mutex::new(BTreeMap::<Id, u64>::new()));
    let mut readers = Vec::<JoinHandle<()>>::new();
    while !stop.load(Ordering::Acquire) {
        // Reap finished connections so reconnects cannot grow the handle list.
        let mut index = 0;
        while index < readers.len() {
            if readers[index].is_finished() {
                let _ = readers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        match listener.accept() {
            Ok((socket, _)) => {
                if active.load(Ordering::Acquire) >= settings.max_reader_connections
                    || configure(&socket, settings.io_timeout).is_err()
                {
                    stats.lock().unwrap().rejected_connections += 1;
                    continue;
                }
                stats.lock().unwrap().accepted_connections += 1;
                active.fetch_add(1, Ordering::AcqRel);
                let args = (
                    inbox.clone(),
                    policy.clone(),
                    stop.clone(),
                    stats.clone(),
                    received.clone(),
                    active.clone(),
                    read_budget.clone(),
                    settings.max_inbox_bytes,
                    settings.frame_read_timeout,
                );
                readers.push(thread::spawn(move || {
                    reader(
                        id, socket, args.0, args.1, args.2, args.3, args.4, args.6, args.7, args.8,
                    );
                    args.5.fetch_sub(1, Ordering::AcqRel);
                }));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                pause(&stop, Duration::from_millis(1));
            }
            Err(_) => {
                stats.lock().unwrap().rejected_connections += 1;
                pause(&stop, Duration::from_millis(5));
            }
        }
    }
    for handle in readers {
        let _ = handle.join();
    }
}

#[allow(clippy::too_many_arguments)]
fn reader<P: Authentication>(
    id: Id,
    mut stream: TcpStream,
    inbox: SyncSender<Received<P::Channel>>,
    policy: P,
    stop: Arc<AtomicBool>,
    stats: Stats<P::Channel>,
    received: Arc<Mutex<BTreeMap<Id, u64>>>,
    read_budget: Arc<ByteBudget>,
    max_inbox_bytes: usize,
    frame_timeout: Duration,
) {
    let mut known_peer = None;
    while !stop.load(Ordering::Acquire) {
        let (bytes, _reservation) = match read_frame_reserved(
            &mut stream,
            policy.max_frame_body_bytes(),
            &stop,
            true,
            &mut |n| {
                stats.lock().unwrap().data_bytes_read += n as u64;
            },
            Some(&read_budget),
            frame_timeout,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                if !stop.load(Ordering::Acquire) && error.kind() != io::ErrorKind::ConnectionAborted
                {
                    let mut stats = stats.lock().unwrap();
                    stats.rejected_frames += 1;
                    if let Some(peer) = known_peer {
                        stats.peers.get_mut(&peer).unwrap().incoming_errors += 1;
                    }
                }
                break;
            }
        };
        let (auth, payload) = match policy.decode_frame(id, &bytes) {
            Ok(verified) => verified,
            Err(_) => {
                stats.lock().unwrap().rejected_frames += 1;
                break;
            }
        };
        if known_peer.is_some_and(|peer| peer != auth.from) {
            stats.lock().unwrap().rejected_frames += 1;
            break;
        }
        known_peer = Some(auth.from);
        stats
            .lock()
            .unwrap()
            .peers
            .get_mut(&auth.from)
            .unwrap()
            .verified_data_bytes_read += (bytes.len() + 4) as u64;
        {
            // Serialize reconnect races across duplicate readers. This mutex
            // also ensures ACK cannot precede first successful mailbox enqueue.
            let mut received = received.lock().unwrap();
            let highest = received.entry(auth.from).or_default();
            if auth.sequence <= *highest {
                stats
                    .lock()
                    .unwrap()
                    .peers
                    .get_mut(&auth.from)
                    .unwrap()
                    .duplicate_frames += 1;
            } else {
                // Replays on old/new sockets may overlap, but a gap must never
                // advance the high-water mark and discard an earlier frame.
                if highest.checked_add(1) != Some(auth.sequence) {
                    let mut stats = stats.lock().unwrap();
                    stats.rejected_frames += 1;
                    stats.peers.get_mut(&auth.from).unwrap().incoming_errors += 1;
                    return;
                }
                let mut incoming = Received {
                    from: auth.from,
                    sequence: auth.sequence,
                    layer: auth.layer,
                    payload,
                    received_at: Instant::now(),
                };
                loop {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    incoming.received_at = Instant::now();
                    let mut counters = stats.lock().unwrap();
                    let payload_bytes = incoming.payload.len() as u64;
                    if counters.inbox_payload_bytes + payload_bytes > max_inbox_bytes as u64 {
                        drop(counters);
                        pause(&stop, Duration::from_millis(1));
                        continue;
                    }
                    match inbox.try_send(incoming) {
                        Ok(()) => {
                            counters.inbox_payload_bytes += payload_bytes;
                            counters.maximum_inbox_payload_bytes = counters
                                .maximum_inbox_payload_bytes
                                .max(counters.inbox_payload_bytes);
                            break;
                        }
                        Err(TrySendError::Full(value)) => {
                            incoming = value;
                            drop(counters);
                            pause(&stop, Duration::from_millis(1));
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
                *highest = auth.sequence;
                let mut stats = stats.lock().unwrap();
                let layer = stats
                    .peers
                    .get_mut(&auth.from)
                    .unwrap()
                    .layers
                    .entry(auth.layer)
                    .or_default();
                layer.accepted_frames += 1;
                layer.accepted_payload_bytes += auth.payload_length as u64;
            }
        }
        let bytes = policy.encode_ack(id, &auth);
        let (_, result) = write_counted(&mut stream, &bytes, &stop, |_, count| {
            let mut stats = stats.lock().unwrap();
            let counters = stats.peers.get_mut(&auth.from).unwrap();
            counters.ack_bytes_written += count as u64;
            counters.written_categories.add(WrittenCategories {
                transport_overhead_bytes: count as u64,
                total_written_bytes: count as u64,
                ..WrittenCategories::default()
            });
        });
        if result.is_err() {
            break;
        }
    }
}

/// Low-level fixture helpers; these call the same production socket functions.
#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;
    pub fn configure(stream: &TcpStream, timeout: Duration) -> io::Result<()> {
        super::configure(stream, timeout)
    }
    pub fn read_frame(
        stream: &mut TcpStream,
        maximum: usize,
        stop: &AtomicBool,
        allow_idle: bool,
        on_read: &mut impl FnMut(usize),
    ) -> io::Result<Vec<u8>> {
        super::read_frame(stream, maximum, stop, allow_idle, on_read)
    }
    pub fn write_counted(
        stream: &mut impl Write,
        bytes: &[u8],
        stop: &AtomicBool,
        on_write: impl FnMut(usize, usize),
    ) -> (usize, io::Result<()>) {
        super::write_counted(stream, bytes, stop, on_write)
    }
}
#[cfg(test)]
mod tests;
