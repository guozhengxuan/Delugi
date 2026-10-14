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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Layer {
    Ordering,
    Dissemination,
    /// Bounded envelope of independently validated canonical ordering messages.
    OrderingBundle,
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
    /// Unacknowledged frames retained by each writer, separate from its outbox.
    pub max_inflight_frames: usize,
    /// Encoded bytes in the window; one additional dequeued frame may be staged.
    pub max_inflight_bytes: usize,
    /// Maximum wait for the oldest fully written frame's ACK; idle links do not expire.
    pub ack_timeout: Duration,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub reconnect_delay: Duration,
    pub max_reader_connections: usize,
}

impl Default for TransportSettings {
    fn default() -> Self {
        Self {
            inbox_capacity: 4096,
            outbox_capacity: 4096,
            max_inflight_frames: 64,
            max_inflight_bytes: 8 * 1024 * 1024,
            ack_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(100),
            io_timeout: Duration::from_millis(250),
            reconnect_delay: Duration::from_millis(20),
            max_reader_connections: 64,
        }
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
    pub outstanding_frames: u64,
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
    /// All data-stream bytes read, including malformed/unauthenticated frames.
    pub data_bytes_read: u64,
    pub rejected_frames: u64,
    pub rejected_connections: u64,
    pub accepted_connections: u64,
    pub queue_full_failures: u64,
}

struct QueuedFrame {
    auth: FrameAuth,
    bytes: Vec<u8>,
    payload_offset: usize,
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
        if addresses.len() != committee.keys.len()
            || committee.keys.get(id as usize).map(|k| k.to_bytes()) != Some(key.public.to_bytes())
        {
            return Err("transport identity/address list does not match committee".into());
        }
        if settings.inbox_capacity == 0
            || settings.outbox_capacity == 0
            || settings.max_inflight_frames == 0
            || settings.max_inflight_bytes < MAX_FRAME_BYTES + 4
            || settings.ack_timeout.is_zero()
            || settings.max_reader_connections == 0
            || settings.connect_timeout.is_zero()
            || settings.io_timeout.is_zero()
            || settings.reconnect_delay.is_zero()
        {
            return Err("transport bounds and timeouts must be positive".into());
        }
        let listener = TcpListener::bind(addresses[id as usize]).map_err(|e| e.to_string())?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let (in_tx, incoming) = mpsc::sync_channel(settings.inbox_capacity);
        let key = Arc::new(key);
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Mutex::new(TransportSnapshot {
            peers: (0..addresses.len() as Id)
                .filter(|peer| *peer != id)
                .map(|peer| (peer, PeerCounters::default()))
                .collect(),
            ..TransportSnapshot::default()
        }));
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
        );
        handles.push(thread::spawn(move || {
            accept_loop(id, listener, in_tx, args.0, args.1, args.2, args.3, args.4)
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
            handles,
        })
    }

    /// Enqueue independently for this peer. Saturation is an explicit error;
    /// callers must fail the run or retry, never discard the protocol action.
    pub fn send(&mut self, to: Id, layer: Layer, payload: Vec<u8>) -> Result<u64, String> {
        if self.stop.load(Ordering::Acquire) {
            return Err("transport is shut down".into());
        }
        let tx = self.outgoing.get(&to).ok_or("invalid/self destination")?;
        let sequence = self
            .sequences
            .get(&to)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("transport sequence exhausted")?;
        let frame = make_frame(
            &self.committee,
            &self.key,
            self.id,
            to,
            sequence,
            layer,
            payload,
        )?;
        let payload_length = frame.auth.payload_length as u64;
        // Hold this lock over the enqueue so worker counters cannot precede
        // logical enqueue, including the outstanding decrement on fast peers.
        let mut stats = self.stats.lock().unwrap();
        match tx.try_send(frame) {
            Ok(()) => {
                self.sequences.insert(to, sequence);
                let peer = stats.peers.get_mut(&to).unwrap();
                peer.outstanding_frames += 1;
                let layer = peer.layers.entry(layer).or_default();
                layer.enqueued_frames += 1;
                layer.enqueued_payload_bytes += payload_length;
                Ok(sequence)
            }
            Err(TrySendError::Full(_)) => {
                stats.queue_full_failures += 1;
                Err(format!("bounded transport outbox for peer {to} is full"))
            }
            Err(TrySendError::Disconnected(_)) => Err(format!("writer for peer {to} stopped")),
        }
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Received, RecvTimeoutError> {
        self.incoming.recv_timeout(timeout)
    }

    pub fn try_recv(&self) -> Result<Received, mpsc::TryRecvError> {
        self.incoming.try_recv()
    }

    pub fn snapshot(&self) -> TransportSnapshot {
        self.stats.lock().unwrap().clone()
    }

    /// Stop accepting/retrying, interrupt bounded I/O waits, and join workers.
    /// Pending frames remain visible in the final outstanding-frame counters.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.outgoing.clear();
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
    if payload.len() > wire::MAX_WIRE_BYTES || sequence == 0 {
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
    })
}

fn verify_frame(
    committee: &Committee,
    to: Id,
    bytes: &[u8],
) -> Result<(FrameAuth, Vec<u8>), String> {
    if bytes.len() < 4 || bytes.len() > MAX_FRAME_BYTES {
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
        || payload.len() > wire::MAX_WIRE_BYTES
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
    stream: &mut TcpStream,
    bytes: &[u8],
    stop: &AtomicBool,
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
            Ok(n) => written += n,
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
    let mut prefix = [0u8; 4];
    let mut position = 0;
    let mut deadline = if allow_idle {
        None
    } else {
        Some(Instant::now() + Duration::from_secs(2))
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
                deadline.get_or_insert(Instant::now() + Duration::from_secs(2));
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
    Ok(bytes)
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
                );
                {
                    let mut stats = stats.lock().unwrap();
                    let counters = stats.peers.get_mut(&peer).unwrap();
                    let layer = counters.layers.entry(entry.frame.auth.layer).or_default();
                    layer.data_bytes_written += written as u64;
                    layer.payload_bytes_written +=
                        written.saturating_sub(entry.frame.payload_offset) as u64;
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
                );
                readers.push(thread::spawn(move || {
                    reader(id, socket, args.0, args.1, args.2, args.3, args.4, args.5);
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
) {
    let mut known_peer = None;
    while !stop.load(Ordering::Acquire) {
        let bytes = match read_frame(&mut stream, MAX_FRAME_BYTES, &stop, true, &mut |n| {
            stats.lock().unwrap().data_bytes_read += n as u64;
        }) {
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
                    match inbox.try_send(incoming) {
                        Ok(()) => break,
                        Err(TrySendError::Full(value)) => {
                            incoming = value;
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
        let (written, result) = write_counted(&mut stream, &bytes, &stop);
        stats
            .lock()
            .unwrap()
            .peers
            .get_mut(&auth.from)
            .unwrap()
            .ack_bytes_written += written as u64;
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
        sender.send(1, Layer::Ordering, vec![44; 16]).unwrap();
        wait_for(|| sender.snapshot().peers[&1].outstanding_frames == 0);
        let counters = &sender.snapshot().peers[&1];
        assert_eq!(counters.retries, 1);
        assert_eq!(counters.ack_failures, 1);
        assert_eq!(counters.layers[&Layer::Ordering].full_frames_written, 2);
        assert_eq!(counters.layers[&Layer::Ordering].payload_bytes_written, 32);
        sender.shutdown();
        server.join().unwrap();
    }
}
