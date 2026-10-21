//! Protocol-independent policy fixture. Its toy checksum is deliberately NOT a
//! cryptographic scheme; a different channel encoding and framing prove that the
//! mechanism does not import Delugi codecs or authentication.
use super::*;
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(u16)]
enum Layer {
    #[default]
    Ordering = 10,
    Dissemination = 20,
    OrderingBundle = 30,
}
#[derive(Default)]
enum PayloadAccounting {
    #[default]
    EvidenceControl,
    BatchPayloadTail {
        bytes: usize,
    },
}
impl Accounting<Layer> for PayloadAccounting {
    fn validate(&self, _: Layer, payload: &[u8]) -> Result<(), String> {
        if matches!(self,Self::BatchPayloadTail{bytes} if *bytes>payload.len()) {
            Err("bad tail".into())
        } else {
            Ok(())
        }
    }
    fn written(&self, offset: usize, len: usize, start: usize, count: usize) -> WrittenCategories {
        let end = start + count;
        let overlap = |a: usize, b: usize| end.min(b).saturating_sub(start.max(a)) as u64;
        let protocol = overlap(offset, offset + len);
        let payload = match self {
            Self::BatchPayloadTail { bytes } => overlap(offset + len - bytes, offset + len),
            _ => 0,
        };
        WrittenCategories {
            payload_bytes: payload,
            evidence_control_bytes: protocol - payload,
            transport_overhead_bytes: count as u64 - protocol,
            total_written_bytes: count as u64,
            ..Default::default()
        }
    }
}
#[derive(Clone)]
struct TestPolicy {
    local: Id,
}
impl TestPolicy {
    fn tag(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0xa7, |a, b| a.rotate_left(1) ^ b)
    }
}
impl Authentication for TestPolicy {
    type Channel = Layer;
    type Accounting = PayloadAccounting;
    fn valid_local_identity(&self, id: Id, members: usize) -> bool {
        self.local == id && id < members as u32 && members == 4
    }
    fn max_wire_bytes(&self) -> usize {
        1024
    }
    fn max_frame_body_bytes(&self) -> usize {
        1047
    }
    fn max_ack_bytes(&self) -> usize {
        64
    }
    fn profile_identifier(&self) -> String {
        "independent-test-policy-v1".into()
    }
    fn written_category_boundary(&self) -> String {
        "test exact writes".into()
    }
    fn encode_frame(
        &self,
        from: Id,
        to: Id,
        sequence: u64,
        layer: Layer,
        payload: Vec<u8>,
    ) -> Result<EncodedFrame<Layer>, String> {
        if payload.len() > 1024 || sequence == 0 {
            return Err("bounds".into());
        }
        let mut body = from.to_le_bytes().to_vec();
        body.extend(to.to_le_bytes());
        body.extend(sequence.to_le_bytes());
        body.extend((layer as u16).to_le_bytes());
        body.extend((payload.len() as u32).to_le_bytes());
        let tag = Self::tag(&[body.as_slice(), payload.as_slice()].concat());
        body.push(tag);
        let mut bytes = ((body.len() + payload.len()) as u32).to_le_bytes().to_vec();
        bytes.extend(body);
        let payload_offset = bytes.len();
        bytes.extend(payload.iter());
        Ok(EncodedFrame {
            auth: FrameMeta {
                from,
                to,
                sequence,
                layer,
                payload_length: payload.len() as u32,
                payload_hash: [tag; 32],
            },
            bytes,
            payload_offset,
        })
    }
    fn decode_frame(&self, to: Id, bytes: &[u8]) -> Result<(FrameMeta<Layer>, Vec<u8>), String> {
        if bytes.len() < 23 || bytes.len() > 1047 {
            return Err("size".into());
        }
        let from = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let recipient = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let sequence = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let layer = match u16::from_le_bytes(bytes[16..18].try_into().unwrap()) {
            10 => Layer::Ordering,
            20 => Layer::Dissemination,
            30 => Layer::OrderingBundle,
            _ => return Err("channel".into()),
        };
        let len = u32::from_le_bytes(bytes[18..22].try_into().unwrap());
        let tag = Self::tag(&[&bytes[..22], &bytes[23..]].concat());
        if from >= 4
            || from == to
            || recipient != to
            || sequence == 0
            || len as usize != bytes.len() - 23
            || tag != bytes[22]
        {
            return Err("binding".into());
        }
        Ok((
            FrameMeta {
                from,
                to,
                sequence,
                layer,
                payload_length: len,
                payload_hash: [tag; 32],
            },
            bytes[23..].to_vec(),
        ))
    }
    fn encode_ack(&self, id: Id, frame: &FrameMeta<Layer>) -> Vec<u8> {
        let mut bytes = 17u32.to_le_bytes().to_vec();
        bytes.extend(id.to_le_bytes());
        bytes.extend(frame.from.to_le_bytes());
        bytes.extend(frame.sequence.to_le_bytes());
        bytes.push(frame.payload_hash[0]);
        bytes
    }
    fn verify_ack(&self, frame: &FrameMeta<Layer>, bytes: &[u8]) -> Result<(), String> {
        let mut expected = frame.to.to_le_bytes().to_vec();
        expected.extend(frame.from.to_le_bytes());
        expected.extend(frame.sequence.to_le_bytes());
        expected.push(frame.payload_hash[0]);
        if bytes == expected {
            Ok(())
        } else {
            Err("ack".into())
        }
    }
}
type Transport = super::Transport<TestPolicy>;
type QueuedFrame = super::QueuedFrame<TestPolicy>;
type PendingFrame = super::PendingFrame<TestPolicy>;
type PeerCounters = super::PeerCounters<Layer>;
type TransportSnapshot = super::TransportSnapshot<Layer>;
fn committee() -> TestPolicy {
    TestPolicy { local: 0 }
}
mod wire {
    pub fn fixture_key(_: u32) -> u8 {
        0
    }
}
fn make_frame(
    policy: &TestPolicy,
    _: &u8,
    from: Id,
    to: Id,
    sequence: u64,
    layer: Layer,
    payload: Vec<u8>,
) -> Result<QueuedFrame, String> {
    let f = policy.encode_frame(from, to, sequence, layer, payload)?;
    Ok(QueuedFrame {
        auth: f.auth,
        bytes: f.bytes,
        payload_offset: f.payload_offset,
        accounting: PayloadAccounting::default(),
        reservation: None,
        peer_reservation: None,
    })
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
        policy: committee,
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
fn independent_policy_uses_shared_pipeline_and_exact_accounting() {
    let listeners: Vec<_> = (0..4)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<_> = listeners.iter().map(|l| l.local_addr().unwrap()).collect();
    drop(listeners);
    let settings = TransportSettings {
        outbox_capacity: 2,
        max_deferred_frames_per_peer: 64,
        ..Default::default()
    };
    let mut sender = Transport::bind(
        0,
        TestPolicy { local: 0 },
        addresses.clone(),
        settings.clone(),
    )
    .unwrap();
    let mut receiver = Transport::bind(1, TestPolicy { local: 1 }, addresses, settings).unwrap();
    for sequence in 1..=32 {
        sender
            .send_or_defer(1, Layer::Dissemination, vec![sequence])
            .unwrap();
    }
    for sequence in 1..=32 {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            sender.retry_deferred().unwrap();
            if let Ok(frame) = receiver.recv_timeout(Duration::from_millis(10)) {
                assert_eq!(frame.sequence, sequence as u64);
                assert_eq!(frame.payload, vec![sequence]);
                assert_eq!(frame.layer, Layer::Dissemination);
                break;
            }
            assert!(Instant::now() < deadline);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while sender.snapshot().peers[&1].outstanding_frames != 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    let a = sender.snapshot();
    let b = receiver.snapshot();
    assert_eq!(a.resource_profile, "independent-test-policy-v1");
    assert_eq!(
        a.peers[&1].layers[&Layer::Dissemination].acknowledged_frames,
        32
    );
    assert_eq!(a.peers[&1].written_categories.total_written_bytes, 32 * 28);
    assert_eq!(
        b.peers[&0].written_categories.transport_overhead_bytes,
        32 * 21
    );
    sender.shutdown();
    receiver.shutdown();
}
