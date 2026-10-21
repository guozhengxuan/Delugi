//! Bounded, authenticated TCP transport for independent reference processes.
//!
//! Every protocol frame and its acknowledgement is signed. A bounded per-peer
//! window pipelines FIFO writes while an independent reader collects ACKs.
//! Reconnects replay the exact unacknowledged suffix before new frames, and the
//! receiver suppresses duplicates. Successful enqueue, socket writes, and
//! acknowledged delivery are distinct counters. Sequence numbers are retained
//! across connections, not process crashes: a restarted experiment needs a new
//! instance (this module does not implement durable crash recovery).

use crate::wire::{self, Committee, Context, Digest, Id, Signed, SigningDomain};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_AUTH_BYTES: usize = 512;
pub const MAX_FRAME_BYTES: usize = wire::MAX_WIRE_BYTES + MAX_AUTH_BYTES + 4;

fn maximum_frame_bytes(committee: &Committee) -> usize {
    committee.max_wire_bytes() + MAX_AUTH_BYTES + 4
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Layer {
    Ordering,
    Dissemination,
    /// Bounded envelope of independently validated canonical ordering messages.
    OrderingBundle,
}

/// Measurement-only classification of the existing serialized payload. This is
/// never sent on the wire or consulted by the protocol. Repair includes its
/// embedded payload and evidence, keeping all four categories disjoint.
#[derive(Clone, Debug, Default)]
pub enum PayloadAccounting {
    #[default]
    EvidenceControl,
    BatchPayloadTail {
        bytes: usize,
    },
    Repair,
    OrderingBundle {
        member_lengths: Vec<u32>,
    },
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
    fn add(&mut self, other: Self) {
        self.payload_bytes += other.payload_bytes;
        self.evidence_control_bytes += other.evidence_control_bytes;
        self.repair_bytes += other.repair_bytes;
        self.transport_overhead_bytes += other.transport_overhead_bytes;
        self.total_written_bytes += other.total_written_bytes;
    }
}

impl PayloadAccounting {
    fn validate(&self, layer: Layer, payload: &[u8]) -> Result<(), String> {
        match self {
            Self::BatchPayloadTail { bytes }
                if layer != Layer::Dissemination || *bytes > payload.len() =>
            {
                Err("batch accounting exceeds its dissemination payload".into())
            }
            Self::Repair if layer != Layer::Dissemination => {
                Err("repair accounting requires a dissemination message".into())
            }
            Self::OrderingBundle { member_lengths } => {
                if layer != Layer::OrderingBundle
                    || !(2..=32).contains(&member_lengths.len())
                    || payload.get(..4) != Some(&(member_lengths.len() as u32).to_le_bytes()[..])
                {
                    return Err("invalid bounded bundle accounting".into());
                }
                let mut offset = 4usize;
                for length in member_lengths {
                    let end = offset.checked_add(4).ok_or("bundle accounting overflow")?;
                    if payload.get(offset..end) != Some(&length.to_le_bytes()[..]) {
                        return Err("bundle accounting differs from serialized framing".into());
                    }
                    offset = end
                        .checked_add(*length as usize)
                        .ok_or("bundle accounting overflow")?;
                    if offset > payload.len() {
                        return Err("bundle accounting exceeds serialized payload".into());
                    }
                }
                if offset != payload.len() {
                    return Err("bundle accounting does not cover serialized payload".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Classify an arbitrary successful contiguous write within a full frame.
    /// Offsets are exact byte positions, so short writes crossing field borders
    /// and repeats of a prefix require no proportional allocation or estimates.
    fn written(
        &self,
        payload_offset: usize,
        payload_len: usize,
        start: usize,
        count: usize,
    ) -> WrittenCategories {
        let end = start + count;
        debug_assert!(end <= payload_offset + payload_len);
        let overlap =
            |left: usize, right: usize| end.min(right).saturating_sub(start.max(left)) as u64;
        let protocol = overlap(payload_offset, payload_offset + payload_len);
        let mut result = WrittenCategories {
            transport_overhead_bytes: count as u64 - protocol,
            total_written_bytes: count as u64,
            ..WrittenCategories::default()
        };
        match self {
            Self::EvidenceControl => result.evidence_control_bytes = protocol,
            Self::BatchPayloadTail { bytes } => {
                result.payload_bytes = overlap(
                    payload_offset + payload_len - *bytes,
                    payload_offset + payload_len,
                );
                result.evidence_control_bytes = protocol - result.payload_bytes;
            }
            Self::Repair => result.repair_bytes = protocol,
            Self::OrderingBundle { member_lengths } => {
                let mut offset = payload_offset + 4;
                for length in member_lengths {
                    offset += 4;
                    result.evidence_control_bytes += overlap(offset, offset + *length as usize);
                    offset += *length as usize;
                }
                result.transport_overhead_bytes += protocol - result.evidence_control_bytes;
            }
        }
        result
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FrameAuth {
    context: Context,
    from: Id,
    to: Id,
    sequence: u64,
    layer: Layer,
    payload_length: u32,
    payload_hash: Digest,
}

impl SigningDomain for FrameAuth {
    const DOMAIN: &'static str = "tcp-data-v1";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ack {
    context: Context,
    from: Id,
    to: Id,
    sequence: u64,
    payload_hash: Digest,
}

impl SigningDomain for Ack {
    const DOMAIN: &'static str = "tcp-ack-v1";
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
    pub fn for_committee(committee: &Committee) -> Self {
        Self::for_profile(committee.resource_profile())
    }

    pub fn for_profile(profile: wire::ResourceProfile) -> Self {
        let mut settings = Self::default();
        if profile == wire::ResourceProfile::Complete32MibN31V1 {
            settings.max_inflight_bytes = 2 * (profile.max_wire_bytes() + MAX_AUTH_BYTES + 8);
            settings.max_outstanding_bytes = 1024 * 1024 * 1024;
            settings.max_inbox_bytes = 128 * 1024 * 1024;
            settings.max_read_buffer_bytes = 128 * 1024 * 1024;
            settings.frame_read_timeout = Duration::from_secs(30);
            settings.ack_timeout = Duration::from_secs(30);
        }
        settings
    }
}

#[derive(Debug)]
pub struct Received {
    pub from: Id,
    pub sequence: u64,
    pub layer: Layer,
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
pub struct PeerCounters {
    pub layers: BTreeMap<Layer, LayerCounters>,
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
pub struct TransportSnapshot {
    pub peers: BTreeMap<Id, PeerCounters>,
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

struct QueuedFrame {
    auth: FrameAuth,
    bytes: Vec<u8>,
    payload_offset: usize,
    accounting: PayloadAccounting,
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

type Stats = Arc<Mutex<TransportSnapshot>>;

pub struct Transport {
    id: Id,
    committee: Committee,
    key: Arc<Keypair>,
    outgoing: BTreeMap<Id, SyncSender<QueuedFrame>>,
    sequences: BTreeMap<Id, u64>,
    incoming: Receiver<Received>,
    stop: Arc<AtomicBool>,
    stats: Stats,
    outbound_budget: Arc<ByteBudget>,
    peer_outbound_budgets: BTreeMap<Id, Arc<ByteBudget>>,
    deferred: BTreeMap<Id, VecDeque<QueuedFrame>>,
    max_deferred_frames_per_peer: usize,
    retry_cursor: usize,
    read_budget: Arc<ByteBudget>,
    handles: Vec<JoinHandle<()>>,
}

impl Transport {
    pub fn bind(
        id: Id,
        committee: Committee,
        key: Keypair,
        addresses: Vec<SocketAddr>,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        let bind_address = *addresses
            .get(id as usize)
            .ok_or("invalid local transport identity")?;
        Self::bind_at(id, committee, key, addresses, bind_address, settings)
    }

    /// Bind locally while peer destinations use their advertised addresses.
    pub fn bind_at(
        id: Id,
        committee: Committee,
        key: Keypair,
        addresses: Vec<SocketAddr>,
        bind_address: SocketAddr,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        if addresses.len() != committee.keys.len()
            || committee.keys.get(id as usize).map(|k| k.to_bytes()) != Some(key.public.to_bytes())
        {
            return Err("transport identity/address list does not match committee".into());
        }
        if settings.inbox_capacity == 0
            || settings.outbox_capacity == 0
            || settings.max_deferred_frames_per_peer == 0
            || settings.max_inflight_frames == 0
            || settings.max_inflight_bytes < maximum_frame_bytes(&committee) + 4
            || settings.max_outstanding_bytes / (addresses.len() - 1).max(1)
                < maximum_frame_bytes(&committee) + 4
            || settings.max_inbox_bytes < committee.max_wire_bytes()
            || settings.max_read_buffer_bytes < maximum_frame_bytes(&committee)
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
        let key = Arc::new(key);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(TransportSnapshot {
            peers: (0..addresses.len() as Id)
                .filter(|peer| *peer != id)
                .map(|peer| (peer, PeerCounters::default()))
                .collect(),
            written_category_boundary: "disjoint successful stream writes, including partial attempts and replay: original BATCH payload; remaining evidence/control; complete FETCH/DATA repair; frame/auth/bundle framing and ACK overhead; excludes TCP/IP headers and kernel retransmissions".into(),
            resource_profile: committee.resource_profile().identifier().to_string(),
            limits: [
                ("protocol_message_bytes", committee.max_wire_bytes() as u64),
                (
                    "frame_bytes_excluding_length_prefix",
                    maximum_frame_bytes(&committee) as u64,
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
                committee.clone(),
                settings.clone(),
                stop.clone(),
                stats.clone(),
            );
            handles.push(thread::spawn(move || {
                writer(peer, address, rx, args.0, args.1, args.2, args.3)
            }));
        }
        let args = (
            committee.clone(),
            key.clone(),
            settings,
            stop.clone(),
            stats.clone(),
            read_budget.clone(),
        );
        handles.push(thread::spawn(move || {
            accept_loop(
                id, listener, in_tx, args.0, args.1, args.2, args.3, args.4, args.5,
            )
        }));
        Ok(Self {
            id,
            committee,
            key,
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
        layer: Layer,
        payload: Vec<u8>,
        accounting: PayloadAccounting,
    ) -> Result<QueuedFrame, String> {
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
        let mut frame = make_frame(
            &self.committee,
            &self.key,
            self.id,
            to,
            sequence,
            layer,
            payload,
        )?;
        frame.accounting = accounting;
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

    fn enqueue(&self, frame: QueuedFrame) -> Result<(), TrySendError<QueuedFrame>> {
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

    fn scheduled(&mut self, to: Id, layer: Layer, sequence: u64, payload_length: u64) {
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
    pub fn send(&mut self, to: Id, layer: Layer, payload: Vec<u8>) -> Result<u64, String> {
        if self
            .deferred
            .get(&to)
            .is_some_and(|queue| !queue.is_empty())
        {
            return Err(format!("peer {to} has an earlier deferred FIFO entry"));
        }
        let frame = self.prepare(to, layer, payload, PayloadAccounting::EvidenceControl)?;
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
        layer: Layer,
        payload: Vec<u8>,
    ) -> Result<SendReceipt, String> {
        self.send_or_defer_accounted(to, layer, payload, PayloadAccounting::EvidenceControl)
    }

    /// Accounting metadata follows the exact frame through deferral/replay and
    /// does not change serialized bytes, authenticated identity or sequencing.
    pub fn send_or_defer_accounted(
        &mut self,
        to: Id,
        layer: Layer,
        payload: Vec<u8>,
        accounting: PayloadAccounting,
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

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Received, RecvTimeoutError> {
        let incoming = self.incoming.recv_timeout(timeout)?;
        self.stats.lock().unwrap().inbox_payload_bytes -= incoming.payload.len() as u64;
        Ok(incoming)
    }

    pub fn try_recv(&self) -> Result<Received, mpsc::TryRecvError> {
        let incoming = self.incoming.try_recv()?;
        self.stats.lock().unwrap().inbox_payload_bytes -= incoming.payload.len() as u64;
        Ok(incoming)
    }

    pub fn snapshot(&self) -> TransportSnapshot {
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

impl Drop for Transport {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn payload_hash(payload: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"delugi/tcp-payload/v1\0");
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into()
}

fn make_frame(
    committee: &Committee,
    key: &Keypair,
    from: Id,
    to: Id,
    sequence: u64,
    layer: Layer,
    payload: Vec<u8>,
) -> Result<QueuedFrame, String> {
    if payload.len() > committee.max_wire_bytes() || sequence == 0 {
        return Err("transport payload/sequence exceeds permitted bounds".into());
    }
    let auth = FrameAuth {
        context: committee.context.clone(),
        from,
        to,
        sequence,
        layer,
        payload_length: payload.len() as u32,
        payload_hash: payload_hash(&payload),
    };
    let signed = wire::sign(key, from, auth.clone());
    let encoded_auth = wire::encode(&signed)?;
    if encoded_auth.len() > MAX_AUTH_BYTES {
        return Err("transport authentication exceeds its frame budget".into());
    }
    let total = 4 + encoded_auth.len() + payload.len();
    let mut bytes = Vec::with_capacity(4 + total);
    bytes.extend_from_slice(&(total as u32).to_le_bytes());
    bytes.extend_from_slice(&(encoded_auth.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&encoded_auth);
    let payload_offset = bytes.len();
    bytes.extend_from_slice(&payload);
    Ok(QueuedFrame {
        auth,
        bytes,
        payload_offset,
        accounting: PayloadAccounting::EvidenceControl,
        reservation: None,
        peer_reservation: None,
    })
}

fn verify_frame(
    committee: &Committee,
    to: Id,
    bytes: &[u8],
) -> Result<(FrameAuth, Vec<u8>), String> {
    if bytes.len() < 4 || bytes.len() > maximum_frame_bytes(committee) {
        return Err("transport frame length is invalid".into());
    }
    let auth_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if auth_len > MAX_AUTH_BYTES || auth_len > bytes.len() - 4 {
        return Err("transport authentication length is invalid".into());
    }
    let signed: Signed<FrameAuth> = wire::decode(&bytes[4..4 + auth_len])?;
    committee.verify_signature(&signed)?;
    let auth = signed.body;
    let payload = &bytes[4 + auth_len..];
    if auth.context != committee.context
        || auth.from != signed.signer
        || auth.to != to
        || auth.from == to
        || auth.sequence == 0
        || payload.len() > committee.max_wire_bytes()
        || auth.payload_length as usize != payload.len()
        || auth.payload_hash != payload_hash(payload)
    {
        return Err("transport authentication/context/payload mismatch".into());
    }
    Ok((auth, payload.to_vec()))
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

struct PendingFrame {
    frame: QueuedFrame,
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
    fn open(
        address: SocketAddr,
        peer: Id,
        settings: &TransportSettings,
        stats: Stats,
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
                let mut result =
                    read_frame(&mut input, MAX_AUTH_BYTES, &reader_cancel, true, &mut |n| {
                        stats
                            .lock()
                            .unwrap()
                            .peers
                            .get_mut(&peer)
                            .unwrap()
                            .ack_bytes_read += n as u64;
                    });
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

fn retire_ack(
    ack: io::Result<Vec<u8>>,
    pending: &mut VecDeque<PendingFrame>,
    pending_bytes: &mut usize,
    committee: &Committee,
    peer: Id,
    stats: &Stats,
) -> Result<(), ()> {
    let valid = ack.ok().is_some_and(|bytes| {
        pending.front().is_some_and(|entry| {
            entry.sent_at.is_some() && verify_ack(committee, &entry.frame.auth, &bytes).is_ok()
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

fn writer(
    peer: Id,
    address: SocketAddr,
    rx: Receiver<QueuedFrame>,
    committee: Committee,
    settings: TransportSettings,
    stop: Arc<AtomicBool>,
    stats: Stats,
) {
    let mut connection: Option<WriterConnection> = None;
    let mut pending = VecDeque::<PendingFrame>::new();
    let mut pending_bytes = 0usize;
    // Dequeue at most one frame beyond the window to inspect its byte size.
    let mut staged: Option<QueuedFrame> = None;
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
                if retire_ack(
                    ack,
                    &mut pending,
                    &mut pending_bytes,
                    &committee,
                    peer,
                    &stats,
                )
                .is_err()
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
            match WriterConnection::open(address, peer, &settings, stats.clone()) {
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

fn verify_ack(committee: &Committee, frame: &FrameAuth, bytes: &[u8]) -> Result<(), String> {
    let signed: Signed<Ack> = wire::decode(bytes)?;
    committee.verify_signature(&signed)?;
    if signed.signer != frame.to
        || signed.body.context != committee.context
        || signed.body.from != frame.to
        || signed.body.to != frame.from
        || signed.body.sequence != frame.sequence
        || signed.body.payload_hash != frame.payload_hash
    {
        return Err("transport ACK does not authenticate this frame".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accept_loop(
    id: Id,
    listener: TcpListener,
    inbox: SyncSender<Received>,
    committee: Committee,
    key: Arc<Keypair>,
    settings: TransportSettings,
    stop: Arc<AtomicBool>,
    stats: Stats,
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
                    committee.clone(),
                    key.clone(),
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
                        id, socket, args.0, args.1, args.2, args.3, args.4, args.5, args.7, args.8,
                        args.9,
                    );
                    args.6.fetch_sub(1, Ordering::AcqRel);
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
fn reader(
    id: Id,
    mut stream: TcpStream,
    inbox: SyncSender<Received>,
    committee: Committee,
    key: Arc<Keypair>,
    stop: Arc<AtomicBool>,
    stats: Stats,
    received: Arc<Mutex<BTreeMap<Id, u64>>>,
    read_budget: Arc<ByteBudget>,
    max_inbox_bytes: usize,
    frame_timeout: Duration,
) {
    let mut known_peer = None;
    while !stop.load(Ordering::Acquire) {
        let (bytes, _reservation) = match read_frame_reserved(
            &mut stream,
            maximum_frame_bytes(&committee),
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
        let (auth, payload) = match verify_frame(&committee, id, &bytes) {
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
        let ack = wire::sign(
            &key,
            id,
            Ack {
                context: committee.context.clone(),
                from: id,
                to: auth.from,
                sequence: auth.sequence,
                payload_hash: auth.payload_hash,
            },
        );
        let encoded = wire::encode(&ack).expect("fixed-size ACK");
        let mut bytes = Vec::with_capacity(encoded.len() + 4);
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn committee() -> Committee {
        Committee::new(
            [71; 32],
            (0..4).map(|i| wire::fixture_key(i).public).collect(),
        )
        .unwrap()
    }

    fn assert_category_conservation(peer: &PeerCounters) {
        let bytes = &peer.written_categories;
        assert_eq!(
            bytes.total_written_bytes,
            bytes.payload_bytes
                + bytes.evidence_control_bytes
                + bytes.repair_bytes
                + bytes.transport_overhead_bytes
        );
        assert_eq!(
            bytes.total_written_bytes,
            peer.layers
                .values()
                .map(|layer| layer.data_bytes_written)
                .sum::<u64>()
                + peer.ack_bytes_written
        );
    }

    fn bundle_payload(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = (parts.len() as u32).to_le_bytes().to_vec();
        for part in parts {
            bytes.extend_from_slice(&(part.len() as u32).to_le_bytes());
            bytes.extend_from_slice(part);
        }
        bytes
    }

    #[test]
    fn written_categories_partition_every_partial_range_and_bundle_boundary() {
        let bundle = bundle_payload(&[&[1, 2, 3], &[4, 5]]);
        // Oracle labels are independent byte-by-byte expected field layouts.
        // 0: overhead, 1: original payload, 2: evidence/control, 3: repair.
        for (accounting, layer, payload, labels) in [
            (
                PayloadAccounting::EvidenceControl,
                Layer::Ordering,
                vec![0; 9],
                vec![2; 9],
            ),
            (
                PayloadAccounting::BatchPayloadTail { bytes: 5 },
                Layer::Dissemination,
                vec![0; 12],
                [vec![2; 7], vec![1; 5]].concat(),
            ),
            (
                PayloadAccounting::Repair,
                Layer::Dissemination,
                vec![0; 7],
                vec![3; 7],
            ),
            (
                PayloadAccounting::OrderingBundle {
                    member_lengths: vec![3, 2],
                },
                Layer::OrderingBundle,
                bundle,
                [vec![0; 8], vec![2; 3], vec![0; 4], vec![2; 2]].concat(),
            ),
        ] {
            accounting.validate(layer, &payload).unwrap();
            let labels = [vec![0; 23], labels].concat();
            for start in 0..=labels.len() {
                for end in start..=labels.len() {
                    let bytes = accounting.written(23, payload.len(), start, end - start);
                    let expected = |label| {
                        labels[start..end]
                            .iter()
                            .filter(|value| **value == label)
                            .count() as u64
                    };
                    assert_eq!(bytes.payload_bytes, expected(1));
                    assert_eq!(bytes.evidence_control_bytes, expected(2));
                    assert_eq!(bytes.repair_bytes, expected(3));
                    assert_eq!(bytes.transport_overhead_bytes, expected(0));
                    assert_eq!(bytes.total_written_bytes, (end - start) as u64);
                }
            }
        }
    }

    #[test]
    fn written_categories_reject_unbounded_or_inexact_bundle_metadata() {
        let valid = bundle_payload(&[&[1, 2, 3], &[4, 5]]);
        for member_lengths in [vec![], vec![3], vec![4, 1], vec![u32::MAX, 2], vec![0; 33]] {
            assert!(PayloadAccounting::OrderingBundle { member_lengths }
                .validate(Layer::OrderingBundle, &valid)
                .is_err());
        }
        assert!(PayloadAccounting::BatchPayloadTail { bytes: 8 }
            .validate(Layer::Dissemination, &[0; 7])
            .is_err());
        assert!(PayloadAccounting::Repair
            .validate(Layer::Ordering, &[0; 7])
            .is_err());
    }

    #[test]
    fn actual_write_observer_charges_only_successful_partial_attempts_and_replay() {
        struct ShortWriter {
            remaining: usize,
            interrupt: bool,
        }
        impl Write for ShortWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.interrupt {
                    self.interrupt = false;
                    return Err(io::ErrorKind::Interrupted.into());
                }
                if self.remaining == 0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let n = bytes.len().min(2).min(self.remaining);
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let frame = [0; 12]; // 5 transport bytes, 2 evidence bytes, 5 payload bytes.
        let accounting = PayloadAccounting::BatchPayloadTail { bytes: 5 };
        let mut categories = WrittenCategories::default();
        let stop = AtomicBool::new(false);
        let (written, result) = write_counted(
            &mut ShortWriter {
                remaining: 7,
                interrupt: true,
            },
            &frame,
            &stop,
            |start, count| categories.add(accounting.written(5, 7, start, count)),
        );
        assert_eq!(written, 7);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(categories.total_written_bytes, 7);
        let (written, result) = write_counted(&mut Vec::new(), &frame, &stop, |start, count| {
            categories.add(accounting.written(5, 7, start, count))
        });
        result.unwrap();
        assert_eq!(written, 12);
        assert_eq!(
            categories,
            WrittenCategories {
                payload_bytes: 5,
                evidence_control_bytes: 4,
                repair_bytes: 0,
                transport_overhead_bytes: 10,
                total_written_bytes: 19
            }
        );
    }

    #[test]
    fn original_batch_payload_tail_matches_canonical_serialization() {
        let c = committee();
        let mut store = crate::batch::BatchStore::new(c.clone(), 4).unwrap();
        let record = store
            .produce(&wire::fixture_key(0), 0, vec![11, 22, 33])
            .unwrap();
        let payload_bytes = record.payload.len();
        let bytes = c.encode(&crate::composed::Message::Batch(record)).unwrap();
        assert_eq!(&bytes[bytes.len() - payload_bytes..], &[11, 22, 33]);
        let accounting = PayloadAccounting::BatchPayloadTail {
            bytes: payload_bytes,
        };
        accounting.validate(Layer::Dissemination, &bytes).unwrap();
        let written = accounting.written(0, bytes.len(), 0, bytes.len());
        assert_eq!(written.payload_bytes, 3);
        assert_eq!(written.evidence_control_bytes, (bytes.len() - 3) as u64);
    }

    #[test]
    fn frame_authenticates_sender_recipient_layer_and_payload() {
        let c = committee();
        let frame = make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            1,
            Layer::Dissemination,
            vec![1, 2, 3],
        )
        .unwrap();
        let (auth, payload) = verify_frame(&c, 1, &frame.bytes[4..]).unwrap();
        assert_eq!(auth.from, 0);
        assert_eq!(auth.layer, Layer::Dissemination);
        assert_eq!(payload, vec![1, 2, 3]);
        assert!(verify_frame(&c, 2, &frame.bytes[4..]).is_err());
        let mut changed = frame.bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_frame(&c, 1, &changed[4..]).is_err());
        let forged =
            make_frame(&c, &wire::fixture_key(2), 0, 1, 1, Layer::Ordering, vec![]).unwrap();
        assert!(verify_frame(&c, 1, &forged.bytes[4..]).is_err());
        let other = Committee::new([72; 32], c.keys.clone()).unwrap();
        assert!(verify_frame(&other, 1, &frame.bytes[4..]).is_err());
    }

    #[test]
    fn ordering_bundle_uses_the_same_authenticated_frame_and_payload_binding() {
        let c = committee();
        let payload = vec![2, 0, 0, 0, 1, 0, 0, 0, 5, 1, 0, 0, 0, 6];
        let frame = make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            7,
            Layer::OrderingBundle,
            payload.clone(),
        )
        .unwrap();
        let (auth, decoded) = verify_frame(&c, 1, &frame.bytes[4..]).unwrap();
        assert_eq!(auth.layer, Layer::OrderingBundle);
        assert_eq!(auth.sequence, 7);
        assert_eq!(decoded, payload);
        let mut changed = frame.bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_frame(&c, 1, &changed[4..]).is_err());
        assert!(verify_frame(&c, 2, &frame.bytes[4..]).is_err());
        // Appending the new layer preserves both existing discriminants and
        // framing/signature sizes; it does not change canonical protocol bytes.
        assert_eq!(wire::encode(&Layer::Ordering).unwrap(), 0u32.to_le_bytes());
        assert_eq!(
            wire::encode(&Layer::Dissemination).unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            wire::encode(&Layer::OrderingBundle).unwrap(),
            2u32.to_le_bytes()
        );
    }

    #[test]
    fn maximum_protocol_payload_fits_separate_transport_frame() {
        let c = committee();
        let frame = make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            1,
            Layer::Ordering,
            vec![9; wire::MAX_WIRE_BYTES],
        )
        .unwrap();
        assert!(frame.bytes.len() - 4 <= MAX_FRAME_BYTES);
        assert_eq!(
            verify_frame(&c, 1, &frame.bytes[4..]).unwrap().1.len(),
            wire::MAX_WIRE_BYTES
        );
        assert!(make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            1,
            Layer::Ordering,
            vec![9; wire::MAX_WIRE_BYTES + 1]
        )
        .is_err());
        assert!(verify_frame(&c, 1, &frame.bytes[4..frame.bytes.len() - 1]).is_err());
        assert!(verify_frame(&c, 1, &[255; 20]).is_err());
    }

    #[test]
    fn selected_profile_authenticates_larger_complete_frames() {
        let c = Committee::with_profile(
            [71; 32],
            (0..31).map(|id| wire::fixture_key(id).public).collect(),
            wire::ResourceProfile::Complete32MibN31V1,
        )
        .unwrap();
        let settings = TransportSettings::for_committee(&c);
        assert!(settings.max_inflight_bytes >= 2 * (maximum_frame_bytes(&c) + 4));
        assert!(settings.max_read_buffer_bytes >= maximum_frame_bytes(&c));
        let frame = make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            1,
            Layer::Ordering,
            vec![9; wire::MAX_WIRE_BYTES + 1],
        )
        .unwrap();
        assert_eq!(
            verify_frame(&c, 1, &frame.bytes[4..]).unwrap().1.len(),
            wire::MAX_WIRE_BYTES + 1
        );
        assert!(verify_frame(&committee(), 1, &frame.bytes[4..]).is_err());
        let mut changed = frame.bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(verify_frame(&c, 1, &changed[4..]).is_err());
    }

    #[test]
    fn byte_leases_cover_queued_staged_and_pending_lifetimes() {
        let budget = ByteBudget::new(10);
        let first = budget.reserve(6).unwrap();
        assert!(budget.reserve(5).is_none());
        let second = budget.reserve(4).unwrap();
        assert!(budget.reserve(usize::MAX).is_none());
        assert_eq!(budget.used.load(Ordering::Acquire), 10);
        drop(first);
        assert_eq!(budget.used.load(Ordering::Acquire), 4);
        drop(second);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        assert_eq!(budget.high_water.load(Ordering::Acquire), 10);
        let c = committee();
        let mut frame =
            make_frame(&c, &wire::fixture_key(0), 0, 1, 1, Layer::Ordering, vec![9]).unwrap();
        let frame_budget = ByteBudget::new(frame.bytes.len());
        frame.reservation = frame_budget.reserve(frame.bytes.len());
        let pending = PendingFrame {
            frame,
            attempted: false,
            sent_at: None,
        };
        assert!(frame_budget.reserve(1).is_none());
        drop(pending);
        assert_eq!(frame_budget.used.load(Ordering::Acquire), 0);
    }

    #[test]
    fn byte_budget_is_shared_across_readers_and_peers() {
        let budget = ByteBudget::new(128);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let budget = budget.clone();
                thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(_lease) = budget.reserve(32) {
                            assert!(budget.used.load(Ordering::Acquire) <= 128);
                            thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        for handle in threads {
            handle.join().unwrap();
        }
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
        assert!(budget.high_water.load(Ordering::Acquire) <= 128);
    }

    fn mailbox_transport(
        deferred_limit: usize,
        peer_byte_limit: usize,
    ) -> (Transport, BTreeMap<Id, Receiver<QueuedFrame>>) {
        let committee = committee();
        let mut outgoing = BTreeMap::new();
        let mut receivers = BTreeMap::new();
        for peer in 1..4 {
            let (sender, receiver) = mpsc::sync_channel(1);
            outgoing.insert(peer, sender);
            receivers.insert(peer, receiver);
        }
        let (_, incoming) = mpsc::sync_channel(1);
        let transport = Transport {
            id: 0,
            committee,
            key: Arc::new(wire::fixture_key(0)),
            outgoing,
            sequences: BTreeMap::new(),
            incoming,
            stop: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(Mutex::new(TransportSnapshot {
                peers: (1..4).map(|peer| (peer, PeerCounters::default())).collect(),
                ..TransportSnapshot::default()
            })),
            outbound_budget: ByteBudget::new(peer_byte_limit * 3),
            peer_outbound_budgets: (1..4)
                .map(|peer| (peer, ByteBudget::new(peer_byte_limit)))
                .collect(),
            deferred: BTreeMap::new(),
            max_deferred_frames_per_peer: deferred_limit,
            retry_cursor: 0,
            read_budget: ByteBudget::new(4096),
            handles: vec![],
        };
        (transport, receivers)
    }

    #[test]
    fn deferred_retry_keeps_exact_cross_layer_fifo_and_serves_healthy_peer() {
        let (mut sender, receivers) = mailbox_transport(8, 8192);
        assert!(
            !sender
                .send_or_defer(1, Layer::Ordering, vec![1])
                .unwrap()
                .deferred
        );
        assert!(
            sender
                .send_or_defer(1, Layer::Dissemination, vec![2])
                .unwrap()
                .deferred
        );
        assert!(
            sender
                .send_or_defer(1, Layer::OrderingBundle, vec![3])
                .unwrap()
                .deferred
        );
        let exact_second = sender.deferred[&1][0].bytes.clone();
        sender.send_or_defer(2, Layer::Ordering, vec![4]).unwrap();
        sender
            .send_or_defer(2, Layer::Dissemination, vec![5])
            .unwrap();
        drop(receivers[&2].recv().unwrap());
        assert_eq!(sender.retry_deferred().unwrap(), 1);
        let healthy = receivers[&2].recv().unwrap();
        assert_eq!(healthy.auth.sequence, 2);
        assert_eq!(&healthy.bytes[healthy.payload_offset..], &[5]);
        assert_eq!(sender.deferred[&1][0].bytes, exact_second);
        // Repeated attempts while full retain the same signed bytes and sequence.
        for _ in 0..3 {
            assert_eq!(sender.retry_deferred().unwrap(), 0);
        }
        assert_eq!(sender.deferred[&1][0].bytes, exact_second);
        let first = receivers[&1].recv().unwrap();
        assert_eq!(first.auth.sequence, 1);
        drop(first);
        assert_eq!(sender.retry_deferred().unwrap(), 1);
        let second = receivers[&1].recv().unwrap();
        assert_eq!(second.bytes, exact_second);
        assert_eq!(second.auth.layer, Layer::Dissemination);
        drop(second);
        assert_eq!(sender.retry_deferred().unwrap(), 1);
        let third = receivers[&1].recv().unwrap();
        assert_eq!(third.auth.sequence, 3);
        assert_eq!(third.auth.layer, Layer::OrderingBundle);
        let snapshot = sender.snapshot();
        assert_eq!(snapshot.peers[&1].deferred_frames, 0);
        assert_eq!(snapshot.peers[&1].deferred_bytes, 0);
        assert_eq!(snapshot.peers[&1].maximum_deferred_frames, 2);
        assert_eq!(snapshot.deferred_accepts, 3);
        assert_eq!(snapshot.resource_exhaustions, 0);
        assert_eq!(snapshot.queue_full_failures, 0);
        assert_eq!(
            snapshot.peers[&1]
                .layers
                .values()
                .map(|l| l.scheduled_frames)
                .sum::<u64>(),
            3
        );
        assert_eq!(
            snapshot.peers[&1]
                .layers
                .values()
                .map(|l| l.enqueued_frames)
                .sum::<u64>(),
            3
        );
        drop(third);
        drop(healthy);
        assert_eq!(sender.snapshot().retained_outbound_bytes, 0);
    }

    #[test]
    fn deferred_frames_retain_actual_wire_classification() {
        let (mut sender, receivers) = mailbox_transport(8, 8192);
        sender.send_or_defer(1, Layer::Ordering, vec![1]).unwrap();
        let receipt = sender
            .send_or_defer_accounted(
                1,
                Layer::Dissemination,
                vec![2; 12],
                PayloadAccounting::BatchPayloadTail { bytes: 5 },
            )
            .unwrap();
        assert!(receipt.deferred);
        assert_eq!(
            sender.snapshot().peers[&1]
                .written_categories
                .total_written_bytes,
            0
        );
        drop(receivers[&1].recv().unwrap());
        sender.retry_deferred().unwrap();
        let frame = receivers[&1].recv().unwrap();
        let categories = frame
            .accounting
            .written(frame.payload_offset, 12, 0, frame.bytes.len());
        assert_eq!(categories.payload_bytes, 5);
        assert_eq!(categories.evidence_control_bytes, 7);
        assert_eq!(categories.total_written_bytes, frame.bytes.len() as u64);
    }

    #[test]
    fn deferred_frame_exhaustion_is_explicit_and_preserves_accepted_frames() {
        let (mut sender, receivers) = mailbox_transport(1, 8192);
        sender.send_or_defer(1, Layer::Ordering, vec![1]).unwrap();
        sender.send_or_defer(1, Layer::Ordering, vec![2]).unwrap();
        let retained = sender.snapshot().retained_outbound_bytes;
        let error = sender
            .send_or_defer(1, Layer::Ordering, vec![3])
            .unwrap_err();
        assert!(error.contains("resource envelope exhausted"));
        assert_eq!(sender.snapshot().retained_outbound_bytes, retained);
        assert_eq!(sender.sequences[&1], 2);
        assert_eq!(sender.snapshot().resource_exhaustions, 1);
        drop(receivers[&1].recv().unwrap());
        sender.retry_deferred().unwrap();
        let second = receivers[&1].recv().unwrap();
        assert_eq!(second.auth.sequence, 2);
        assert_eq!(&second.bytes[second.payload_offset..], &[2]);
        assert_eq!(
            sender.snapshot().peers[&1].layers[&Layer::Ordering].scheduled_frames,
            2
        );
    }

    #[test]
    fn peer_byte_quota_retains_space_for_healthy_peers_and_releases_on_drain() {
        let c = committee();
        let size = make_frame(
            &c,
            &wire::fixture_key(0),
            0,
            1,
            1,
            Layer::Ordering,
            vec![9; 100],
        )
        .unwrap()
        .bytes
        .len();
        let (mut sender, receivers) = mailbox_transport(100, size * 2);
        sender
            .send_or_defer(1, Layer::Ordering, vec![9; 100])
            .unwrap();
        sender
            .send_or_defer(1, Layer::Ordering, vec![9; 100])
            .unwrap();
        let error = sender
            .send_or_defer(1, Layer::Ordering, vec![9; 100])
            .unwrap_err();
        assert!(error.contains("retained byte budget for peer 1"));
        sender
            .send_or_defer(2, Layer::Ordering, vec![8; 100])
            .unwrap();
        let snapshot = sender.snapshot();
        assert_eq!(
            snapshot.peers[&1].retained_outbound_bytes,
            (size * 2) as u64
        );
        assert!(snapshot.peers[&1].maximum_retained_outbound_bytes <= (size * 2) as u64);
        assert!(snapshot.maximum_retained_outbound_bytes <= (size * 6) as u64);
        drop(receivers[&1].recv().unwrap());
        sender.retry_deferred().unwrap();
        drop(receivers[&1].recv().unwrap());
        drop(receivers[&2].recv().unwrap());
        assert_eq!(sender.snapshot().retained_outbound_bytes, 0);
        assert_eq!(sender.snapshot().peers[&1].retained_outbound_bytes, 0);
    }

    #[test]
    fn stopped_writer_retains_deferred_frame_and_reports_terminal_failure() {
        let (mut sender, mut receivers) = mailbox_transport(8, 8192);
        sender.send_or_defer(1, Layer::Ordering, vec![1]).unwrap();
        sender.send_or_defer(1, Layer::Ordering, vec![2]).unwrap();
        let exact = sender.deferred[&1][0].bytes.clone();
        drop(receivers.remove(&1));
        assert!(sender
            .retry_deferred()
            .unwrap_err()
            .contains("stopped with a retained frame"));
        assert_eq!(sender.deferred[&1][0].bytes, exact);
        assert_eq!(sender.snapshot().peers[&1].deferred_frames, 1);
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn deferred_tcp_peer_recovers_without_blocking_healthy_peer() {
        let c = committee();
        let addresses = free_addresses();
        let settings = TransportSettings {
            outbox_capacity: 1,
            max_inflight_frames: 1,
            max_deferred_frames_per_peer: 16,
            ..TransportSettings::default()
        };
        let mut sender = Transport::bind(
            0,
            c.clone(),
            wire::fixture_key(0),
            addresses.clone(),
            settings.clone(),
        )
        .unwrap();
        let mut healthy = Transport::bind(
            2,
            c.clone(),
            wire::fixture_key(2),
            addresses.clone(),
            settings.clone(),
        )
        .unwrap();
        sender.send_or_defer(1, Layer::Ordering, vec![1]).unwrap();
        wait_for(|| sender.snapshot().peers[&1].connection_failures > 0);
        for sequence in 2..=8 {
            let layer = if sequence % 2 == 0 {
                Layer::Dissemination
            } else {
                Layer::Ordering
            };
            sender.send_or_defer(1, layer, vec![sequence]).unwrap();
        }
        assert!(sender.snapshot().peers[&1].deferred_frames > 0);
        sender.send_or_defer(2, Layer::Ordering, vec![99]).unwrap();
        assert_eq!(
            healthy
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .payload,
            vec![99]
        );
        let mut recovered =
            Transport::bind(1, c, wire::fixture_key(1), addresses, settings).unwrap();
        let mut received = Vec::new();
        wait_for(|| {
            sender.retry_deferred().unwrap();
            while let Ok(frame) = recovered.try_recv() {
                received.push(frame);
            }
            received.len() == 8
                && sender.snapshot().peers[&1].outstanding_frames == 0
                && sender.snapshot().peers[&1].deferred_frames == 0
        });
        for (index, frame) in received.iter().enumerate() {
            assert_eq!(frame.sequence, index as u64 + 1);
            assert_eq!(frame.payload, vec![index as u8 + 1]);
        }
        let snapshot = sender.snapshot();
        assert_eq!(snapshot.resource_exhaustions, 0);
        assert!(
            snapshot.maximum_retained_outbound_bytes <= snapshot.limits["retained_outbound_bytes"]
        );
        for peer in snapshot.peers.values() {
            assert!(
                peer.maximum_retained_outbound_bytes
                    <= snapshot.limits["retained_outbound_bytes_per_peer"]
            );
        }
        sender.shutdown();
        healthy.shutdown();
        recovered.shutdown();
    }

    #[test]
    fn acknowledgement_binds_peer_sequence_and_payload() {
        let c = committee();
        let frame =
            make_frame(&c, &wire::fixture_key(0), 0, 1, 3, Layer::Ordering, vec![1]).unwrap();
        let mut ack = Ack {
            context: c.context.clone(),
            from: 1,
            to: 0,
            sequence: 3,
            payload_hash: frame.auth.payload_hash,
        };
        let valid = wire::encode(&wire::sign(&wire::fixture_key(1), 1, ack.clone())).unwrap();
        assert!(verify_ack(&c, &frame.auth, &valid).is_ok());
        ack.sequence = 2;
        let stale = wire::encode(&wire::sign(&wire::fixture_key(1), 1, ack)).unwrap();
        assert!(verify_ack(&c, &frame.auth, &stale).is_err());
        assert!(verify_ack(&c, &frame.auth, &valid[..valid.len() - 1]).is_err());
    }

    fn free_addresses() -> Vec<SocketAddr> {
        let reserved: Vec<_> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        reserved
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect()
    }

    fn wait_for(mut ready: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while !ready() {
            assert!(Instant::now() < deadline, "TCP test condition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn accepted_socket_waits_for_read_timeout_instead_of_busy_polling() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut accepted = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "loopback accept timed out");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        };
        configure(&accepted, Duration::from_millis(40)).unwrap();
        let start = Instant::now();
        let error = accepted.read(&mut [0u8; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        assert!(
            start.elapsed() >= Duration::from_millis(20),
            "accepted socket ignored its blocking timeout and would spin in read_frame"
        );
        client.write_all(&[7]).unwrap();
        let mut byte = [0u8; 1];
        accepted.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [7]);
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn real_tcp_late_peer_bounded_queue_and_exact_traffic() {
        let c = committee();
        let addresses = free_addresses();
        let settings = TransportSettings {
            outbox_capacity: 2,
            ..TransportSettings::default()
        };
        let mut sender = Transport::bind(
            0,
            c.clone(),
            wire::fixture_key(0),
            addresses.clone(),
            settings.clone(),
        )
        .unwrap();
        sender.send(1, Layer::Dissemination, vec![3; 4096]).unwrap();
        wait_for(|| sender.snapshot().peers[&1].connection_failures > 0);
        let mut receiver =
            Transport::bind(1, c, wire::fixture_key(1), addresses, settings).unwrap();
        let got = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(got.from, 0);
        assert_eq!(got.sequence, 1);
        assert_eq!(got.payload, vec![3; 4096]);
        wait_for(|| sender.snapshot().peers[&1].outstanding_frames == 0);
        assert!(receiver.try_recv().is_err());
        let sent = sender.snapshot();
        let accepted = receiver.snapshot();
        let counters = &sent.peers[&1];
        let layer = &counters.layers[&Layer::Dissemination];
        assert_eq!(layer.acknowledged_frames, 1);
        assert_eq!(layer.full_frames_written, 1);
        assert_eq!(layer.payload_bytes_written, 4096);
        assert_eq!(layer.data_bytes_written, accepted.data_bytes_read);
        assert_eq!(
            counters.ack_bytes_read,
            accepted.peers[&0].ack_bytes_written
        );
        assert_eq!(
            accepted.peers[&0].layers[&Layer::Dissemination].accepted_frames,
            1
        );
        // A permanently unavailable peer cannot block an independent writer.
        let mut full = false;
        for _ in 0..20 {
            if sender.send(3, Layer::Ordering, vec![1]).is_err() {
                full = true;
                break;
            }
        }
        assert!(full);
        sender.send(1, Layer::Ordering, vec![9]).unwrap();
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(3))
                .unwrap()
                .payload,
            vec![9]
        );
        wait_for(|| sender.snapshot().peers[&1].outstanding_frames == 0);
        assert!(sender.snapshot().queue_full_failures > 0);
        assert!(sender.snapshot().peers[&3].outstanding_frames > 0);
        sender.shutdown();
        receiver.shutdown();
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn real_tcp_fragment_coalesce_reconnect_dedup_and_rejection() {
        let c = committee();
        let addresses = free_addresses();
        let mut receiver = Transport::bind(
            1,
            c.clone(),
            wire::fixture_key(1),
            addresses.clone(),
            TransportSettings::default(),
        )
        .unwrap();
        let stop = AtomicBool::new(false);
        let frame = |sequence| {
            make_frame(
                &c,
                &wire::fixture_key(0),
                0,
                1,
                sequence,
                Layer::Ordering,
                vec![sequence as u8; 31],
            )
            .unwrap()
        };
        let frames = [frame(1), frame(2), frame(3)];
        let mut socket = TcpStream::connect(addresses[1]).unwrap();
        configure(&socket, Duration::from_millis(250)).unwrap();
        for chunk in frames[0].bytes.chunks(7) {
            socket.write_all(chunk).unwrap();
        }
        let ack = read_frame(&mut socket, MAX_AUTH_BYTES, &stop, false, &mut |_| {}).unwrap();
        verify_ack(&c, &frames[0].auth, &ack).unwrap();
        let together = [frames[1].bytes.clone(), frames[2].bytes.clone()].concat();
        socket.write_all(&together).unwrap();
        for frame in &frames[1..] {
            let ack = read_frame(&mut socket, MAX_AUTH_BYTES, &stop, false, &mut |_| {}).unwrap();
            verify_ack(&c, &frame.auth, &ack).unwrap();
        }
        for sequence in 1..=3 {
            assert_eq!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap()
                    .sequence,
                sequence
            );
        }
        drop(socket);
        // Simulate a sender whose last ACK was lost: reconnect exact same frame.
        let mut retry = TcpStream::connect(addresses[1]).unwrap();
        configure(&retry, Duration::from_millis(250)).unwrap();
        retry.write_all(&frames[2].bytes).unwrap();
        let ack = read_frame(&mut retry, MAX_AUTH_BYTES, &stop, false, &mut |_| {}).unwrap();
        verify_ack(&c, &frames[2].auth, &ack).unwrap();
        assert!(receiver.try_recv().is_err());
        assert_eq!(receiver.snapshot().peers[&0].duplicate_frames, 1);
        drop(retry);
        let mut forged = TcpStream::connect(addresses[1]).unwrap();
        let bad = make_frame(&c, &wire::fixture_key(2), 0, 1, 4, Layer::Ordering, vec![1]).unwrap();
        forged.write_all(&bad.bytes).unwrap();
        drop(forged);
        let mut oversized = TcpStream::connect(addresses[1]).unwrap();
        oversized
            .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes())
            .unwrap();
        drop(oversized);
        let mut truncated = TcpStream::connect(addresses[1]).unwrap();
        truncated.write_all(&32u32.to_le_bytes()).unwrap();
        truncated.write_all(&[1, 2]).unwrap();
        drop(truncated);
        wait_for(|| receiver.snapshot().rejected_frames >= 3);
        assert!(receiver.try_recv().is_err());
        receiver.shutdown();
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn real_tcp_writer_retries_exact_frame_after_lost_ack() {
        let c = committee();
        let addresses = free_addresses();
        let listener = TcpListener::bind(addresses[1]).unwrap();
        let expected_c = c.clone();
        let server = thread::spawn(move || {
            let stop = AtomicBool::new(false);
            let (mut first, _) = listener.accept().unwrap();
            configure(&first, Duration::from_millis(250)).unwrap();
            let one = read_frame(&mut first, MAX_FRAME_BYTES, &stop, false, &mut |_| {}).unwrap();
            let (auth, _) = verify_frame(&expected_c, 1, &one).unwrap();
            drop(first); // Enqueued, but ACK deliberately lost.
            let (mut second, _) = listener.accept().unwrap();
            configure(&second, Duration::from_millis(250)).unwrap();
            let two = read_frame(&mut second, MAX_FRAME_BYTES, &stop, false, &mut |_| {}).unwrap();
            assert_eq!(one, two);
            let ack = wire::encode(&wire::sign(
                &wire::fixture_key(1),
                1,
                Ack {
                    context: expected_c.context.clone(),
                    from: 1,
                    to: 0,
                    sequence: auth.sequence,
                    payload_hash: auth.payload_hash,
                },
            ))
            .unwrap();
            second.write_all(&(ack.len() as u32).to_le_bytes()).unwrap();
            second.write_all(&ack).unwrap();
        });
        let mut sender = Transport::bind(
            0,
            c,
            wire::fixture_key(0),
            addresses,
            TransportSettings::default(),
        )
        .unwrap();
        sender
            .send_or_defer_accounted(
                1,
                Layer::Dissemination,
                vec![44; 16],
                PayloadAccounting::BatchPayloadTail { bytes: 7 },
            )
            .unwrap();
        wait_for(|| sender.snapshot().peers[&1].outstanding_frames == 0);
        let counters = &sender.snapshot().peers[&1];
        assert_eq!(counters.retries, 1);
        assert_eq!(counters.ack_failures, 1);
        assert_eq!(
            counters.layers[&Layer::Dissemination].full_frames_written,
            2
        );
        assert_eq!(
            counters.layers[&Layer::Dissemination].payload_bytes_written,
            32
        );
        assert_eq!(counters.written_categories.payload_bytes, 14);
        assert_eq!(counters.written_categories.evidence_control_bytes, 18);
        assert_category_conservation(counters);
        sender.shutdown();
        server.join().unwrap();
    }

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn real_tcp_written_categories_reconcile_payload_repair_bundles_and_acks() {
        let c = committee();
        let addresses = free_addresses();
        let mut first = Transport::bind(
            0,
            c.clone(),
            wire::fixture_key(0),
            addresses.clone(),
            TransportSettings::default(),
        )
        .unwrap();
        let mut second = Transport::bind(
            1,
            c,
            wire::fixture_key(1),
            addresses,
            TransportSettings::default(),
        )
        .unwrap();
        let bundle = bundle_payload(&[&[1, 2, 3], &[4, 5]]);
        first
            .send_or_defer_accounted(
                1,
                Layer::Dissemination,
                vec![9; 12],
                PayloadAccounting::BatchPayloadTail { bytes: 5 },
            )
            .unwrap();
        first
            .send_or_defer_accounted(
                1,
                Layer::OrderingBundle,
                bundle,
                PayloadAccounting::OrderingBundle {
                    member_lengths: vec![3, 2],
                },
            )
            .unwrap();
        second
            .send_or_defer_accounted(
                0,
                Layer::Dissemination,
                vec![8; 19],
                PayloadAccounting::Repair,
            )
            .unwrap();
        for sequence in 1..=2 {
            assert_eq!(
                second
                    .recv_timeout(Duration::from_secs(3))
                    .unwrap()
                    .sequence,
                sequence
            );
        }
        assert_eq!(
            first.recv_timeout(Duration::from_secs(3)).unwrap().payload,
            vec![8; 19]
        );
        wait_for(|| {
            first.snapshot().peers[&1].outstanding_frames == 0
                && second.snapshot().peers[&0].outstanding_frames == 0
        });
        let first_snapshot = first.snapshot();
        let second_snapshot = second.snapshot();
        let a = &first_snapshot.peers[&1];
        let b = &second_snapshot.peers[&0];
        assert_category_conservation(a);
        assert_category_conservation(b);
        assert_eq!(a.written_categories.payload_bytes, 5);
        assert_eq!(a.written_categories.evidence_control_bytes, 7 + 5);
        assert_eq!(a.written_categories.repair_bytes, 0);
        assert_eq!(b.written_categories.repair_bytes, 19);
        assert_eq!(b.written_categories.payload_bytes, 0);
        assert_eq!(b.written_categories.evidence_control_bytes, 0);
        assert_eq!(a.ack_bytes_written, b.ack_bytes_read);
        assert_eq!(b.ack_bytes_written, a.ack_bytes_read);
        assert_eq!(
            a.written_categories.total_written_bytes + b.written_categories.total_written_bytes,
            first_snapshot.data_bytes_read
                + second_snapshot.data_bytes_read
                + a.ack_bytes_read
                + b.ack_bytes_read
        );
        first.shutdown();
        second.shutdown();
    }
}
