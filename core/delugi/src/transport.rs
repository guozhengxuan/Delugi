//! Delugi transport policy over the shared bounded TCP mechanism.
//! This adapter retains the original signed frame/ACK bytes and payload domains.
use crate::wire::{self, Committee, Context, Digest, Id, Signed, SigningDomain};
use serde::{Deserialize, Serialize};
use shared_crypto::Keypair;
use shared_network::{Authentication, SettingsProvider};
pub use shared_network::{LayerCounters, SendReceipt, TransportSettings, WrittenCategories};
use std::net::SocketAddr;
use std::sync::{mpsc, Arc};
use std::time::Duration;
pub type PeerCounters = shared_network::PeerCounters<Layer>;
pub type TransportSnapshot = shared_network::TransportSnapshot<Layer>;
pub type Received = shared_network::Received<Layer>;
const MAX_AUTH_BYTES: usize = 512;
pub const MAX_FRAME_BYTES: usize = wire::MAX_WIRE_BYTES + MAX_AUTH_BYTES + 4;
fn maximum_frame_bytes(committee: &Committee) -> usize {
    committee.max_wire_bytes() + MAX_AUTH_BYTES + 4
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Layer {
    #[default]
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

impl SettingsProvider for Committee {
    fn transport_settings(&self) -> TransportSettings {
        self.resource_profile().transport_settings()
    }
}
impl SettingsProvider for wire::ResourceProfile {
    fn transport_settings(&self) -> TransportSettings {
        let profile = *self;
        let mut settings = TransportSettings::default();
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
impl shared_network::Accounting<Layer> for PayloadAccounting {
    fn validate(&self, layer: Layer, payload: &[u8]) -> Result<(), String> {
        self.validate(layer, payload)
    }
    fn written(&self, offset: usize, len: usize, start: usize, count: usize) -> WrittenCategories {
        self.written(offset, len, start, count)
    }
}
struct CoreFrame {
    auth: FrameAuth,
    bytes: Vec<u8>,
    payload_offset: usize,
}
fn payload_hash(payload: &[u8]) -> Digest {
    shared_crypto::sha256(
        &[
            b"delugi/tcp-payload/v1\0",
            &(payload.len() as u64).to_le_bytes(),
            payload,
        ],
        None,
    )
}

fn make_frame(
    committee: &Committee,
    key: &Keypair,
    from: Id,
    to: Id,
    sequence: u64,
    layer: Layer,
    payload: Vec<u8>,
) -> Result<CoreFrame, String> {
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
    Ok(CoreFrame {
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

impl FrameAuth {
    fn metadata(&self) -> shared_network::FrameMeta<Layer> {
        shared_network::FrameMeta {
            from: self.from,
            to: self.to,
            sequence: self.sequence,
            layer: self.layer,
            payload_length: self.payload_length,
            payload_hash: self.payload_hash,
        }
    }
}
#[derive(Clone)]
struct DelugiAuth {
    committee: Committee,
    key: Arc<Keypair>,
}
impl Authentication for DelugiAuth {
    type Channel = Layer;
    type Accounting = PayloadAccounting;
    fn valid_local_identity(&self, id: Id, members: usize) -> bool {
        members == self.committee.keys.len()
            && self.committee.keys.get(id as usize).map(|k| k.to_bytes())
                == Some(self.key.public.to_bytes())
    }
    fn max_wire_bytes(&self) -> usize {
        self.committee.max_wire_bytes()
    }
    fn max_frame_body_bytes(&self) -> usize {
        maximum_frame_bytes(&self.committee)
    }
    fn max_ack_bytes(&self) -> usize {
        MAX_AUTH_BYTES
    }
    fn profile_identifier(&self) -> String {
        self.committee.resource_profile().identifier().to_string()
    }
    fn written_category_boundary(&self) -> String {
        "disjoint successful stream writes, including partial attempts and replay: original BATCH payload; remaining evidence/control; complete FETCH/DATA repair; frame/auth/bundle framing and ACK overhead; excludes TCP/IP headers and kernel retransmissions".into()
    }
    fn encode_frame(
        &self,
        from: Id,
        to: Id,
        sequence: u64,
        layer: Layer,
        payload: Vec<u8>,
    ) -> Result<shared_network::EncodedFrame<Layer>, String> {
        let frame = make_frame(
            &self.committee,
            &self.key,
            from,
            to,
            sequence,
            layer,
            payload,
        )?;
        Ok(shared_network::EncodedFrame {
            auth: frame.auth.metadata(),
            bytes: frame.bytes,
            payload_offset: frame.payload_offset,
        })
    }
    fn decode_frame(
        &self,
        to: Id,
        bytes: &[u8],
    ) -> Result<(shared_network::FrameMeta<Layer>, Vec<u8>), String> {
        let (auth, payload) = verify_frame(&self.committee, to, bytes)?;
        Ok((auth.metadata(), payload))
    }
    fn encode_ack(&self, id: Id, auth: &shared_network::FrameMeta<Layer>) -> Vec<u8> {
        let ack = wire::sign(
            &self.key,
            id,
            Ack {
                context: self.committee.context.clone(),
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
        bytes
    }
    fn verify_ack(
        &self,
        auth: &shared_network::FrameMeta<Layer>,
        bytes: &[u8],
    ) -> Result<(), String> {
        verify_ack(
            &self.committee,
            &FrameAuth {
                context: self.committee.context.clone(),
                from: auth.from,
                to: auth.to,
                sequence: auth.sequence,
                layer: auth.layer,
                payload_length: auth.payload_length,
                payload_hash: auth.payload_hash,
            },
            bytes,
        )
    }
}

/// Compatibility facade; all queues, workers, sockets and retries are shared.
pub struct Transport {
    inner: shared_network::Transport<DelugiAuth>,
}
impl Transport {
    pub fn bind(
        id: Id,
        committee: Committee,
        key: Keypair,
        addresses: Vec<SocketAddr>,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        shared_network::Transport::bind(
            id,
            DelugiAuth {
                committee,
                key: Arc::new(key),
            },
            addresses,
            settings,
        )
        .map(|inner| Self { inner })
    }
    pub fn bind_at(
        id: Id,
        committee: Committee,
        key: Keypair,
        addresses: Vec<SocketAddr>,
        bind_address: SocketAddr,
        settings: TransportSettings,
    ) -> Result<Self, String> {
        shared_network::Transport::bind_at(
            id,
            DelugiAuth {
                committee,
                key: Arc::new(key),
            },
            addresses,
            bind_address,
            settings,
        )
        .map(|inner| Self { inner })
    }
    pub fn send(&mut self, to: Id, layer: Layer, payload: Vec<u8>) -> Result<u64, String> {
        self.inner.send(to, layer, payload)
    }
    pub fn send_or_defer(
        &mut self,
        to: Id,
        layer: Layer,
        payload: Vec<u8>,
    ) -> Result<SendReceipt, String> {
        self.inner.send_or_defer(to, layer, payload)
    }
    pub fn send_or_defer_accounted(
        &mut self,
        to: Id,
        layer: Layer,
        payload: Vec<u8>,
        accounting: PayloadAccounting,
    ) -> Result<SendReceipt, String> {
        self.inner
            .send_or_defer_accounted(to, layer, payload, accounting)
    }
    pub fn retry_deferred(&mut self) -> Result<usize, String> {
        self.inner.retry_deferred()
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Received, mpsc::RecvTimeoutError> {
        self.inner.recv_timeout(timeout)
    }
    pub fn try_recv(&self) -> Result<Received, mpsc::TryRecvError> {
        self.inner.try_recv()
    }
    pub fn snapshot(&self) -> TransportSnapshot {
        self.inner.snapshot()
    }
    pub fn shutdown(&mut self) {
        self.inner.shutdown()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use shared_network::test_support::{configure, read_frame, write_counted};
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Instant;

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
