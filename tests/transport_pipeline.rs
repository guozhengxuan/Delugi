//! Public-API TCP regressions with an ACK gate. These assert causal progress
//! before ACK release rather than comparing latency against a timing threshold.
use delugi::transport::{Layer, Transport, TransportSettings, MAX_FRAME_BYTES};
use delugi::wire::{self, Committee};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq)]
enum TamperOnce {
    Neither,
    Payload,
    AckSignature,
    DropFirstData,
}

#[derive(Default)]
struct Trace {
    // Whole original frames, including their length prefix and authentication.
    data: Vec<Vec<u8>>,
    acks_forwarded: usize,
    closed: bool,
}

struct ProxyState {
    traces: BTreeMap<usize, Trace>,
    ack_permits: usize,
    disconnect: BTreeSet<usize>,
    tamper: TamperOnce,
}

struct PendingWrite {
    bytes: Vec<u8>,
    offset: usize,
}

impl PendingWrite {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, offset: 0 }
    }

    fn flush(&mut self, stream: &mut TcpStream) -> io::Result<bool> {
        while self.offset < self.bytes.len() {
            match stream.write(&self.bytes[self.offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.offset += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

struct Connection {
    client: TcpStream,
    server: TcpStream,
    data_buffer: Vec<u8>,
    ack_buffer: Vec<u8>,
    data_pending: VecDeque<PendingWrite>,
    ack_pending: VecDeque<Vec<u8>>,
    active_ack: Option<PendingWrite>,
}

fn receive_available(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn pop_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buffer.len() < 4 {
        return None;
    }
    let size = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;
    assert!((1..=MAX_FRAME_BYTES).contains(&size));
    if buffer.len() < size + 4 {
        return None;
    }
    Some(buffer.drain(..size + 4).collect())
}

impl Connection {
    fn pump(&mut self, id: usize, shared: &Mutex<ProxyState>) -> io::Result<()> {
        receive_available(&mut self.client, &mut self.data_buffer)?;
        while let Some(mut bytes) = pop_frame(&mut self.data_buffer) {
            let mut state = shared.lock().unwrap();
            state.traces.get_mut(&id).unwrap().data.push(bytes.clone());
            if state.tamper == TamperOnce::DropFirstData {
                state.tamper = TamperOnce::Neither;
                continue;
            }
            if state.tamper == TamperOnce::Payload {
                // Payload is last in data framing; our test payloads are nonempty.
                *bytes.last_mut().unwrap() ^= 1;
                state.tamper = TamperOnce::Neither;
            }
            self.data_pending.push_back(PendingWrite::new(bytes));
        }
        while let Some(frame) = self.data_pending.front_mut() {
            if !frame.flush(&mut self.server)? {
                break;
            }
            self.data_pending.pop_front();
        }
        receive_available(&mut self.server, &mut self.ack_buffer)?;
        while let Some(bytes) = pop_frame(&mut self.ack_buffer) {
            self.ack_pending.push_back(bytes);
        }
        loop {
            if self.active_ack.is_none() && !self.ack_pending.is_empty() {
                let mut state = shared.lock().unwrap();
                if state.ack_permits == 0 {
                    break;
                }
                if state.ack_permits != usize::MAX {
                    state.ack_permits -= 1;
                }
                let mut bytes = self.ack_pending.pop_front().unwrap();
                if state.tamper == TamperOnce::AckSignature {
                    // Signed<T> serializes its signature last.
                    *bytes.last_mut().unwrap() ^= 1;
                    state.tamper = TamperOnce::Neither;
                }
                self.active_ack = Some(PendingWrite::new(bytes));
            }
            let completed = match self.active_ack.as_mut() {
                Some(frame) => frame.flush(&mut self.client)?,
                None => break,
            };
            if !completed {
                break;
            }
            self.active_ack = None;
            shared
                .lock()
                .unwrap()
                .traces
                .get_mut(&id)
                .unwrap()
                .acks_forwarded += 1;
        }
        Ok(())
    }

    fn disconnect(&self) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.server.shutdown(Shutdown::Both);
    }
}

struct AckGate {
    address: SocketAddr,
    shared: Arc<Mutex<ProxyState>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl AckGate {
    fn start(destination: SocketAddr, tamper: TamperOnce) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let shared = Arc::new(Mutex::new(ProxyState {
            traces: BTreeMap::new(),
            ack_permits: 0,
            disconnect: BTreeSet::new(),
            tamper,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let state = shared.clone();
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let mut connections = BTreeMap::<usize, Connection>::new();
            let mut next_id = 1;
            while !stopped.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        let server =
                            TcpStream::connect_timeout(&destination, Duration::from_secs(1))
                                .unwrap();
                        for socket in [&client, &server] {
                            socket.set_nodelay(true).unwrap();
                            socket.set_nonblocking(true).unwrap();
                        }
                        state
                            .lock()
                            .unwrap()
                            .traces
                            .insert(next_id, Trace::default());
                        connections.insert(
                            next_id,
                            Connection {
                                client,
                                server,
                                data_buffer: vec![],
                                ack_buffer: vec![],
                                data_pending: VecDeque::new(),
                                ack_pending: VecDeque::new(),
                                active_ack: None,
                            },
                        );
                        next_id += 1;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => panic!("ACK gate accept failed: {e}"),
                }
                let mut closed = Vec::new();
                for (id, connection) in &mut connections {
                    let forced = state.lock().unwrap().disconnect.remove(id);
                    if forced || connection.pump(*id, &state).is_err() {
                        connection.disconnect();
                        closed.push(*id);
                    }
                }
                for id in closed {
                    connections.remove(&id);
                    state.lock().unwrap().traces.get_mut(&id).unwrap().closed = true;
                }
                thread::sleep(Duration::from_millis(1));
            }
            for connection in connections.values() {
                connection.disconnect();
            }
        });
        Self {
            address,
            shared,
            stop,
            worker: Some(worker),
        }
    }

    fn release(&self, count: usize) {
        self.shared.lock().unwrap().ack_permits = count;
    }

    fn disconnect(&self, connection: usize) {
        self.shared.lock().unwrap().disconnect.insert(connection);
    }

    fn ack_count(&self) -> usize {
        self.shared
            .lock()
            .unwrap()
            .traces
            .values()
            .map(|trace| trace.acks_forwarded)
            .sum()
    }
}

impl Drop for AckGate {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Preserve the original assertion if a test is already unwinding.
            let result = worker.join();
            if !thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn wait_for(description: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {description}"
        );
        thread::sleep(Duration::from_millis(2));
    }
}

fn fixture(settings: TransportSettings, tamper: TamperOnce) -> (Transport, Transport, AckGate) {
    let committee = Committee::new(
        [183; 32],
        (0..4).map(|id| wire::fixture_key(id).public).collect(),
    )
    .unwrap();
    let reserved: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut addresses: Vec<_> = reserved
        .iter()
        .map(|listener| listener.local_addr().unwrap())
        .collect();
    drop(reserved);
    let receiver = Transport::bind(
        1,
        committee.clone(),
        wire::fixture_key(1),
        addresses.clone(),
        settings.clone(),
    )
    .unwrap();
    let gate = AckGate::start(addresses[1], tamper);
    addresses[1] = gate.address;
    let sender = Transport::bind(0, committee, wire::fixture_key(0), addresses, settings).unwrap();
    (sender, receiver, gate)
}

fn settings(window: usize, outbox: usize) -> TransportSettings {
    TransportSettings {
        max_inflight_frames: window,
        outbox_capacity: outbox,
        io_timeout: Duration::from_millis(50),
        reconnect_delay: Duration::from_millis(5),
        ..TransportSettings::default()
    }
}

fn payload(sequence: u64) -> Vec<u8> {
    vec![sequence as u8; 64]
}

fn layer(sequence: u64) -> Layer {
    if sequence % 2 == 0 {
        Layer::Dissemination
    } else {
        Layer::Ordering
    }
}

fn send(sender: &mut Transport, sequence: u64) {
    assert_eq!(
        sender.send(1, layer(sequence), payload(sequence)).unwrap(),
        sequence
    );
}

fn receive(receiver: &Transport, sequence: u64) {
    let received = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(received.from, 0);
    assert_eq!(received.sequence, sequence);
    assert_eq!(received.layer, layer(sequence));
    assert_eq!(received.payload, payload(sequence));
}

fn acknowledged(sender: &Transport) -> u64 {
    sender.snapshot().peers[&1]
        .layers
        .values()
        .map(|layer| layer.acknowledged_frames)
        .sum()
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn several_frames_arrive_before_first_ack_and_one_ack_advances_the_window() {
    let (mut sender, receiver, gate) = fixture(settings(3, 8), TamperOnce::Neither);
    for sequence in 1..=6 {
        send(&mut sender, sequence);
    }
    for sequence in 1..=3 {
        receive(&receiver, sequence);
    }
    assert_eq!(gate.ack_count(), 0);
    assert_eq!(acknowledged(&sender), 0);
    assert_eq!(sender.snapshot().peers[&1].outstanding_frames, 6);
    assert_eq!(sender.snapshot().peers[&1].inflight_frames, 3);
    assert!(receiver.try_recv().is_err());
    gate.release(1);
    receive(&receiver, 4);
    wait_for("one forwarded ACK", || gate.ack_count() == 1);
    assert_eq!(gate.ack_count(), 1);
    assert_eq!(acknowledged(&sender), 1);
    gate.release(usize::MAX);
    for sequence in 5..=6 {
        receive(&receiver, sequence);
    }
    wait_for("all pipelined ACKs", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(acknowledged(&sender), 6);
    assert_eq!(sender.snapshot().peers[&1].maximum_inflight_frames, 3);
    assert_eq!(sender.snapshot().peers[&1].inflight_frames, 0);
    assert_eq!(sender.snapshot().peers[&1].inflight_bytes, 0);
    assert!(receiver.try_recv().is_err());
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn blocked_acks_keep_the_window_and_outbox_bounded() {
    let (mut sender, receiver, gate) = fixture(settings(3, 2), TamperOnce::Neither);
    // Fill the window first, avoiding an incidental enqueue race in setup.
    for sequence in 1..=3 {
        send(&mut sender, sequence);
        receive(&receiver, sequence);
    }
    let mut next_sequence = 4;
    loop {
        match sender.send(1, layer(next_sequence), payload(next_sequence)) {
            Ok(sequence) => {
                assert_eq!(sequence, next_sequence);
                next_sequence += 1;
                assert!(
                    next_sequence <= 7,
                    "unbounded queue while ACKs are withheld"
                );
            }
            Err(error) => {
                assert!(
                    error.contains("full"),
                    "unexpected enqueue failure: {error}"
                );
                break;
            }
        }
    }
    let snapshot = sender.snapshot();
    let peer = &snapshot.peers[&1];
    assert_eq!(snapshot.queue_full_failures, 1);
    assert_eq!(peer.inflight_frames, 3);
    // Three in flight, two queued, and at most one staged dequeued frame.
    assert!(peer.outstanding_frames <= 6);
    assert_eq!(peer.outstanding_frames, next_sequence - 1);
    assert_eq!(gate.ack_count(), 0);
    gate.release(usize::MAX);
    for sequence in 4..next_sequence {
        receive(&receiver, sequence);
    }
    wait_for("bounded backlog drain", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    // Rejected admission must not consume the sender's next sequence number.
    send(&mut sender, next_sequence);
    receive(&receiver, next_sequence);
    wait_for("post-backpressure ACK", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(sender.snapshot().peers[&1].maximum_inflight_frames, 3);
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn byte_window_limits_large_frames_independently_of_frame_count() {
    let byte_limit = MAX_FRAME_BYTES + 4;
    let mut config = settings(4, 8);
    config.max_inflight_bytes = byte_limit;
    let (mut sender, receiver, gate) = fixture(config, TamperOnce::Neither);
    let large_payload = vec![37; 700 * 1024];
    for _ in 0..3 {
        sender
            .send(1, Layer::Dissemination, large_payload.clone())
            .unwrap();
    }
    let first = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first.sequence, 1);
    assert_eq!(first.payload, large_payload);
    assert_eq!(gate.ack_count(), 0);
    assert_eq!(sender.snapshot().peers[&1].inflight_frames, 1);
    gate.release(1);
    let second = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(second.sequence, 2);
    assert_eq!(second.payload, large_payload);
    gate.release(usize::MAX);
    let third = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(third.sequence, 3);
    assert_eq!(third.payload, large_payload);
    wait_for("large-frame ACKs", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    let snapshot = sender.snapshot();
    let peer = &snapshot.peers[&1];
    assert_eq!(peer.maximum_inflight_frames, 1);
    assert!(peer.maximum_inflight_bytes <= byte_limit as u64);
    assert!(peer.maximum_inflight_bytes > large_payload.len() as u64);
    assert_eq!(peer.inflight_bytes, 0);
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn lost_acks_replay_identical_frames_without_duplicate_or_reordered_delivery() {
    let (mut sender, receiver, gate) = fixture(settings(4, 16), TamperOnce::Neither);
    for sequence in 1..=4 {
        send(&mut sender, sequence);
    }
    for sequence in 1..=4 {
        receive(&receiver, sequence);
    }
    assert_eq!(gate.ack_count(), 0);
    gate.disconnect(1);
    wait_for("four duplicate replays after ACK loss", || {
        receiver.snapshot().peers[&0].duplicate_frames >= 4
    });
    assert!(receiver.try_recv().is_err());
    assert_eq!(acknowledged(&sender), 0);
    {
        let state = gate.shared.lock().unwrap();
        let original = &state.traces[&1].data;
        assert_eq!(original.len(), 4);
        assert_eq!(&state.traces[&2].data[..4], &original[..]);
        assert!(state.traces[&1].closed);
    }
    gate.release(usize::MAX);
    for sequence in 5..=8 {
        send(&mut sender, sequence);
    }
    for sequence in 5..=8 {
        receive(&receiver, sequence);
    }
    wait_for("ACKs after replay", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    let snapshot = receiver.snapshot();
    assert_eq!(
        snapshot.peers[&0]
            .layers
            .values()
            .map(|layer| layer.accepted_frames)
            .sum::<u64>(),
        8
    );
    assert_eq!(acknowledged(&sender), 8);
    assert!(sender.snapshot().peers[&1].retries >= 4);
    assert!(receiver.try_recv().is_err());
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn corrupt_ack_cannot_release_outstanding_frame() {
    let (mut sender, receiver, gate) = fixture(settings(3, 8), TamperOnce::AckSignature);
    send(&mut sender, 1);
    receive(&receiver, 1);
    gate.release(1);
    wait_for("rejected corrupt ACK", || {
        sender.snapshot().peers[&1].ack_failures > 0
    });
    wait_for("retry after corrupt ACK", || {
        receiver.snapshot().peers[&0].duplicate_frames > 0
    });
    assert_eq!(acknowledged(&sender), 0);
    assert_eq!(sender.snapshot().peers[&1].outstanding_frames, 1);
    assert!(receiver.try_recv().is_err());
    gate.release(usize::MAX);
    wait_for("authenticated replacement ACK", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(acknowledged(&sender), 1);
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn tampered_payload_is_rejected_then_original_frame_retries_in_order() {
    let (mut sender, receiver, gate) = fixture(settings(3, 8), TamperOnce::Payload);
    for sequence in 1..=3 {
        send(&mut sender, sequence);
    }
    wait_for("payload authentication rejection", || {
        receiver.snapshot().rejected_frames > 0
    });
    for sequence in 1..=3 {
        receive(&receiver, sequence);
    }
    assert_eq!(gate.ack_count(), 0);
    gate.release(usize::MAX);
    wait_for("ACKs after authenticated retry", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(acknowledged(&sender), 3);
    assert!(receiver.try_recv().is_err());
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn missing_acks_timeout_and_replay_even_when_tcp_stays_open() {
    let mut config = settings(3, 8);
    config.ack_timeout = Duration::from_millis(100);
    let (mut sender, receiver, gate) = fixture(config, TamperOnce::Neither);
    for sequence in 1..=3 {
        send(&mut sender, sequence);
    }
    for sequence in 1..=3 {
        receive(&receiver, sequence);
    }
    // The proxy never closes the connection: only the transport's ACK deadline
    // can cause a reconnect and duplicate replay while the gate stays closed.
    wait_for("ACK deadline replay", || {
        receiver.snapshot().peers[&0].duplicate_frames >= 3
    });
    assert_eq!(gate.ack_count(), 0);
    assert_eq!(acknowledged(&sender), 0);
    assert!(sender.snapshot().peers[&1].ack_failures > 0);
    assert!(sender.snapshot().peers[&1].established_connections >= 2);
    assert!(receiver.try_recv().is_err());
    gate.release(usize::MAX);
    wait_for("ACKs after deadline recovery", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(acknowledged(&sender), 3);
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn valid_but_gapped_frame_is_rejected_before_replay_restores_fifo() {
    let (mut sender, receiver, gate) = fixture(settings(3, 8), TamperOnce::DropFirstData);
    for sequence in 1..=3 {
        send(&mut sender, sequence);
    }
    // Frame2 still has its original, valid signature. It must not establish
    // highest=2 and cause the later replay of frame1 to be discarded.
    wait_for("authenticated sequence gap rejection", || {
        receiver.snapshot().rejected_frames > 0
    });
    for sequence in 1..=3 {
        receive(&receiver, sequence);
    }
    assert_eq!(gate.ack_count(), 0);
    gate.release(usize::MAX);
    wait_for("ACKs after gap recovery", || {
        sender.snapshot().peers[&1].outstanding_frames == 0
    });
    assert_eq!(acknowledged(&sender), 3);
    assert!(receiver.try_recv().is_err());
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn shutdown_joins_with_acks_held_and_preserves_unacknowledged_counters() {
    let (mut sender, receiver, gate) = fixture(settings(3, 8), TamperOnce::Neither);
    for sequence in 1..=4 {
        send(&mut sender, sequence);
    }
    for sequence in 1..=3 {
        receive(&receiver, sequence);
    }
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let shutdown = thread::spawn(move || {
        sender.shutdown();
        done_tx.send(sender.snapshot()).unwrap();
    });
    let snapshot = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("shutdown must interrupt a waiting ACK reader");
    shutdown.join().unwrap();
    let peer = &snapshot.peers[&1];
    assert_eq!(peer.outstanding_frames, 4);
    assert_eq!(peer.inflight_frames, 3);
    assert_eq!(
        peer.layers
            .values()
            .map(|layer| layer.acknowledged_frames)
            .sum::<u64>(),
        0
    );
    assert_eq!(gate.ack_count(), 0);
    wait_for("shutdown socket closure", || {
        gate.shared.lock().unwrap().traces[&1].closed
    });
}

#[test]
#[ignore = "requires permission to bind localhost TCP sockets"]
fn shutdown_interrupts_reader_blocked_by_full_receive_mailbox() {
    let mut config = settings(3, 8);
    config.inbox_capacity = 1;
    let (mut sender, mut receiver, gate) = fixture(config, TamperOnce::Neither);
    for sequence in 1..=3 {
        send(&mut sender, sequence);
    }
    wait_for("second frame verified behind full mailbox", || {
        let frame_bytes = gate
            .shared
            .lock()
            .unwrap()
            .traces
            .get(&1)
            .and_then(|trace| trace.data.first())
            .map(Vec::len);
        frame_bytes.is_some_and(|bytes| {
            receiver.snapshot().peers[&0].verified_data_bytes_read > bytes as u64
        })
    });
    gate.release(usize::MAX);
    wait_for("first mailbox delivery acknowledged", || {
        acknowledged(&sender) == 1
    });
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let shutdown = thread::spawn(move || {
        receiver.shutdown();
        done_tx.send(receiver.snapshot()).unwrap();
    });
    let snapshot = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("shutdown must interrupt a full mailbox enqueue");
    shutdown.join().unwrap();
    assert_eq!(
        snapshot.peers[&0]
            .layers
            .values()
            .map(|layer| layer.accepted_frames)
            .sum::<u64>(),
        1
    );
    assert_eq!(acknowledged(&sender), 1);
    assert_eq!(sender.snapshot().peers[&1].outstanding_frames, 2);
    sender.shutdown();
}
