//! Explicit Raptr rehost transport profile. Inner payloads are unmodified native
//! BCS and still require native verification. This outer frame is not Aptos Noise.
use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shared_crypto::{Keypair, PublicKey, Signature};
use shared_metrics::Operation;
use shared_network::{Accounting, Authentication, EncodedFrame, FrameMeta, Id, WrittenCategories};
use std::collections::BTreeSet;
use std::sync::Arc;

pub use shared_network_async::{Limits as AsyncLimits, ReceivedBytes, Service};
pub type Sender = shared_network_async::Sender<Auth>;
pub type Receiver = shared_network_async::Receiver<Channel>;
pub const PROFILE: &str = "raptr-native-bcs-v1";
const MAX_AUTH: usize = 512;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Channel {
    #[default]
    Consensus,
    QuorumStore,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Context {
    pub instance: [u8; 32],
    pub configuration: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Signed<T> {
    signer: Id,
    body: T,
    signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FrameAuth {
    context: Context,
    from: Id,
    to: Id,
    sequence: u64,
    channel: Channel,
    payload_length: u32,
    payload_hash: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Ack {
    context: Context,
    from: Id,
    to: Id,
    sequence: u64,
    payload_hash: [u8; 32],
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_AUTH as u64)
        .serialize(value)
        .map_err(|e| e.to_string())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > MAX_AUTH {
        return Err("transport auth exceeds bound".into());
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_AUTH as u64)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|e| e.to_string())
}

#[derive(Clone)]
pub struct Auth {
    id: Id,
    context: Context,
    keys: Arc<Vec<PublicKey>>,
    key: Arc<Keypair>,
    max_wire: usize,
}

impl Auth {
    pub fn new(
        id: Id,
        context: Context,
        keys: Vec<PublicKey>,
        key: Arc<Keypair>,
        max_wire: usize,
    ) -> Result<Self, String> {
        if keys.is_empty()
            || keys.len() > u32::MAX as usize
            || keys.get(id as usize).map(PublicKey::to_bytes) != Some(key.public.to_bytes())
            || PublicKey::from(&key.secret).to_bytes() != key.public.to_bytes()
            || max_wire == 0
            || max_wire > u32::MAX as usize - MAX_AUTH - 8
        {
            return Err("invalid transport key, membership or wire bound".into());
        }
        if keys
            .iter()
            .map(PublicKey::to_bytes)
            .collect::<BTreeSet<_>>()
            .len()
            != keys.len()
        {
            return Err("duplicate transport member key".into());
        }
        Ok(Self {
            id,
            context,
            keys: Arc::new(keys),
            key,
            max_wire,
        })
    }
    fn signing_bytes<T: Serialize>(&self, role: &[u8], signer: Id, body: &T) -> Vec<u8> {
        let encoded = encode(body).expect("fixed transport authentication fits bound");
        let mut bytes = Vec::with_capacity(128 + encoded.len());
        bytes.extend_from_slice(PROFILE.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(role);
        bytes.push(0);
        bytes.extend_from_slice(&signer.to_le_bytes());
        bytes.extend_from_slice(&encoded);
        bytes
    }
    fn sign<T: Serialize>(&self, role: &[u8], body: T, operation: Operation) -> Signed<T> {
        let signature = shared_crypto::sign_ed25519(
            &self.key,
            &self.signing_bytes(role, self.id, &body),
            operation,
        );
        Signed {
            signer: self.id,
            body,
            signature,
        }
    }
    fn verify<T: Serialize>(
        &self,
        role: &[u8],
        signed: &Signed<T>,
        operation: Operation,
    ) -> Result<(), String> {
        let key = self
            .keys
            .get(signed.signer as usize)
            .ok_or("unknown transport signer")?;
        let signature = Signature::from_bytes(&signed.signature)
            .map_err(|_| "invalid transport signature bytes")?;
        shared_crypto::verify_ed25519_strict(
            key,
            &self.signing_bytes(role, signed.signer, &signed.body),
            &signature,
            operation,
        )
    }
    fn hash(&self, payload: &[u8]) -> [u8; 32] {
        shared_crypto::sha256(
            &[
                b"raptr-native-bcs-v1/payload\0",
                &(payload.len() as u64).to_le_bytes(),
                payload,
            ],
            Some(Operation::ContentHash),
        )
    }
}

impl Authentication for Auth {
    type Channel = Channel;
    type Accounting = ByteAccounting;
    fn valid_local_identity(&self, id: Id, members: usize) -> bool {
        self.id == id && self.keys.len() == members
    }
    fn max_wire_bytes(&self) -> usize {
        self.max_wire
    }
    fn max_frame_body_bytes(&self) -> usize {
        self.max_wire + MAX_AUTH + 4
    }
    fn max_ack_bytes(&self) -> usize {
        MAX_AUTH
    }
    fn profile_identifier(&self) -> String {
        PROFILE.into()
    }
    fn written_category_boundary(&self) -> String {
        "disjoint successful stream writes including partial writes/replay: exact caller-declared original payload ranges; remaining native evidence/control; repair ranges; outer frame/auth/length and ACK overhead; excludes TCP/IP headers and kernel retransmissions".into()
    }
    fn encode_frame(
        &self,
        from: Id,
        to: Id,
        sequence: u64,
        channel: Channel,
        payload: Vec<u8>,
    ) -> Result<EncodedFrame<Channel>, String> {
        if from != self.id
            || from == to
            || to as usize >= self.keys.len()
            || sequence == 0
            || payload.len() > self.max_wire
        {
            return Err("invalid transport sender/recipient/sequence/payload bound".into());
        }
        let hash = self.hash(&payload);
        let body = FrameAuth {
            context: self.context.clone(),
            from,
            to,
            sequence,
            channel,
            payload_length: payload.len() as u32,
            payload_hash: hash,
        };
        let encoded = encode(&self.sign(b"data", body, Operation::TransportDataSign))?;
        let mut bytes = Vec::with_capacity(8 + encoded.len() + payload.len());
        bytes.extend_from_slice(&((4 + encoded.len() + payload.len()) as u32).to_le_bytes());
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
        let payload_offset = bytes.len();
        bytes.extend_from_slice(&payload);
        Ok(EncodedFrame {
            auth: FrameMeta {
                from,
                to,
                sequence,
                layer: channel,
                payload_length: payload.len() as u32,
                payload_hash: hash,
            },
            bytes,
            payload_offset,
        })
    }
    fn decode_frame(&self, to: Id, bytes: &[u8]) -> Result<(FrameMeta<Channel>, Vec<u8>), String> {
        if to != self.id || bytes.len() < 4 || bytes.len() > self.max_frame_body_bytes() {
            return Err("invalid frame length/recipient".into());
        }
        let auth_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if auth_len > MAX_AUTH || auth_len > bytes.len() - 4 {
            return Err("invalid frame auth length".into());
        }
        let signed: Signed<FrameAuth> = decode(&bytes[4..4 + auth_len])?;
        self.verify(b"data", &signed, Operation::TransportDataVerify)?;
        let body = signed.body;
        let payload = &bytes[4 + auth_len..];
        if body.context != self.context
            || body.from != signed.signer
            || body.to != to
            || body.from == to
            || body.sequence == 0
            || payload.len() > self.max_wire
            || payload.len() != body.payload_length as usize
            || body.payload_hash != self.hash(payload)
        {
            return Err("transport context, frame identity or payload mismatch".into());
        }
        Ok((
            FrameMeta {
                from: body.from,
                to,
                sequence: body.sequence,
                layer: body.channel,
                payload_length: body.payload_length,
                payload_hash: body.payload_hash,
            },
            payload.to_vec(),
        ))
    }
    fn encode_ack(&self, id: Id, frame: &FrameMeta<Channel>) -> Vec<u8> {
        assert_eq!(id, self.id);
        assert_eq!(frame.to, id);
        let ack = Ack {
            context: self.context.clone(),
            from: id,
            to: frame.from,
            sequence: frame.sequence,
            payload_hash: frame.payload_hash,
        };
        let body = encode(&self.sign(b"ack", ack, Operation::TransportAckSign))
            .expect("fixed ACK fits bound");
        let mut bytes = Vec::with_capacity(4 + body.len());
        bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes
    }
    fn verify_ack(&self, frame: &FrameMeta<Channel>, bytes: &[u8]) -> Result<(), String> {
        let signed: Signed<Ack> = decode(bytes)?;
        self.verify(b"ack", &signed, Operation::TransportAckVerify)?;
        let body = signed.body;
        if frame.from != self.id
            || signed.signer != frame.to
            || body.context != self.context
            || body.from != frame.to
            || body.to != frame.from
            || body.sequence != frame.sequence
            || body.payload_hash != frame.payload_hash
        {
            return Err("ACK does not authenticate this frame".into());
        }
        Ok(())
    }
}

/// Measurement-only offsets into the actual serialized native message. No
/// estimated proportions. Remaining bytes are evidence/control. Ranges must be
/// ordered and disjoint. Classifying useful work is a separate application metric.
#[derive(Clone, Copy, Debug)]
pub enum Category {
    Payload,
    Repair,
}
#[derive(Clone, Debug)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
    pub category: Category,
}
#[derive(Clone, Debug, Default)]
pub struct ByteAccounting {
    pub ranges: Vec<ByteRange>,
}

impl ByteAccounting {
    pub fn repair(bytes: usize) -> Self {
        Self {
            ranges: vec![ByteRange {
                start: 0,
                end: bytes,
                category: Category::Repair,
            }],
        }
    }
}
impl Accounting<Channel> for ByteAccounting {
    fn validate(&self, channel: Channel, payload: &[u8]) -> Result<(), String> {
        let mut end = 0;
        for range in &self.ranges {
            if range.start < end
                || range.end < range.start
                || range.end > payload.len()
                || (matches!(range.category, Category::Payload) && channel != Channel::QuorumStore)
            {
                return Err("invalid native payload accounting ranges".into());
            }
            end = range.end;
        }
        Ok(())
    }
    fn written(
        &self,
        payload_offset: usize,
        payload_len: usize,
        start: usize,
        count: usize,
    ) -> WrittenCategories {
        let end = start + count;
        let overlap = |a: usize, b: usize| end.min(b).saturating_sub(start.max(a)) as u64;
        let protocol = overlap(payload_offset, payload_offset + payload_len);
        let mut result = WrittenCategories {
            total_written_bytes: count as u64,
            transport_overhead_bytes: count as u64 - protocol,
            ..Default::default()
        };
        for range in &self.ranges {
            let bytes = overlap(payload_offset + range.start, payload_offset + range.end);
            match range.category {
                Category::Payload => result.payload_bytes += bytes,
                Category::Repair => result.repair_bytes += bytes,
            }
        }
        result.evidence_control_bytes = protocol - result.payload_bytes - result.repair_bytes;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keys() -> Vec<Arc<Keypair>> {
        (0..3)
            .map(|i| {
                let secret = shared_crypto::SecretKey::from_bytes(&[i + 1; 32]).unwrap();
                Arc::new(Keypair {
                    public: PublicKey::from(&secret),
                    secret,
                })
            })
            .collect()
    }
    fn auth(id: Id) -> Auth {
        let keys = keys();
        Auth::new(
            id,
            Context {
                instance: [1; 32],
                configuration: [2; 32],
            },
            keys.iter().map(|k| k.public).collect(),
            keys[id as usize].clone(),
            1024,
        )
        .unwrap()
    }
    #[test]
    fn opaque_native_bytes_survive_both_channels_and_ack_binds_frame() {
        let (a, b, c) = (auth(0), auth(1), auth(2));
        for channel in [Channel::Consensus, Channel::QuorumStore] {
            for payload in [vec![], (0..=255).collect()] {
                let frame = a.encode_frame(0, 1, 7, channel, payload.clone()).unwrap();
                assert_eq!(
                    u32::from_le_bytes(frame.bytes[..4].try_into().unwrap()) as usize,
                    frame.bytes.len() - 4
                );
                let (meta, got) = b.decode_frame(1, &frame.bytes[4..]).unwrap();
                assert_eq!(got, payload);
                assert_eq!(meta.layer, channel);
                let ack = b.encode_ack(1, &meta);
                a.verify_ack(&frame.auth, &ack[4..]).unwrap();
                let mut wrong = frame.auth.clone();
                wrong.sequence += 1;
                assert!(a.verify_ack(&wrong, &ack[4..]).is_err());
                wrong = frame.auth.clone();
                wrong.payload_hash[0] ^= 1;
                assert!(a.verify_ack(&wrong, &ack[4..]).is_err());
                assert!(c.decode_frame(2, &frame.bytes[4..]).is_err());
            }
        }
    }
    #[test]
    fn every_auth_payload_and_ack_byte_is_authenticated() {
        let (a, b) = (auth(0), auth(1));
        let frame = a
            .encode_frame(0, 1, 1, Channel::QuorumStore, vec![3; 24])
            .unwrap();
        for offset in 4..frame.bytes.len() {
            let mut bytes = frame.bytes.clone();
            bytes[offset] ^= 1;
            assert!(b.decode_frame(1, &bytes[4..]).is_err(), "offset {offset}");
        }
        let ack = b.encode_ack(1, &frame.auth);
        for offset in 4..ack.len() {
            let mut bytes = ack.clone();
            bytes[offset] ^= 1;
            assert!(
                a.verify_ack(&frame.auth, &bytes[4..]).is_err(),
                "ACK offset {offset}"
            );
        }
    }
    #[test]
    fn identities_domains_context_and_bounds_are_strict() {
        let (a, mut b) = (auth(0), auth(1));
        let frame = a
            .encode_frame(0, 1, 1, Channel::Consensus, vec![0])
            .unwrap();
        b.context.instance[0] ^= 1;
        assert!(b.decode_frame(1, &frame.bytes[4..]).is_err());
        assert!(a.encode_frame(1, 0, 1, Channel::Consensus, vec![]).is_err());
        assert!(a.encode_frame(0, 0, 1, Channel::Consensus, vec![]).is_err());
        assert!(a.encode_frame(0, 3, 1, Channel::Consensus, vec![]).is_err());
        assert!(a.encode_frame(0, 1, 0, Channel::Consensus, vec![]).is_err());
        assert!(a
            .encode_frame(0, 1, 1, Channel::Consensus, vec![0; 1025])
            .is_err());
        let mut trailing = frame.bytes[4..].to_vec();
        trailing.push(0);
        assert!(auth(1).decode_frame(1, &trailing).is_err());
        let keys = keys();
        assert!(Auth::new(
            0,
            a.context.clone(),
            vec![keys[0].public, keys[0].public],
            keys[0].clone(),
            128
        )
        .is_err());
        assert!(Auth::new(
            0,
            a.context.clone(),
            vec![keys[0].public],
            keys[1].clone(),
            128
        )
        .is_err());
        let signed = a.sign(
            b"not-data",
            FrameAuth {
                context: a.context.clone(),
                from: 0,
                to: 1,
                sequence: 1,
                channel: Channel::Consensus,
                payload_length: 0,
                payload_hash: a.hash(&[]),
            },
            Operation::TransportDataSign,
        );
        assert!(b
            .verify(b"data", &signed, Operation::TransportDataVerify)
            .is_err());
    }
    #[test]
    fn exact_categories_reconcile_every_partial_write_and_replay() {
        let accounting = ByteAccounting {
            ranges: vec![
                ByteRange {
                    start: 2,
                    end: 8,
                    category: Category::Payload,
                },
                ByteRange {
                    start: 12,
                    end: 16,
                    category: Category::Repair,
                },
            ],
        };
        accounting.validate(Channel::QuorumStore, &[0; 20]).unwrap();
        assert!(accounting.validate(Channel::Consensus, &[0; 20]).is_err());
        ByteAccounting::repair(20)
            .validate(Channel::Consensus, &[0; 20])
            .unwrap();
        let whole = accounting.written(100, 20, 0, 120);
        assert_eq!(
            (
                whole.payload_bytes,
                whole.evidence_control_bytes,
                whole.repair_bytes,
                whole.transport_overhead_bytes
            ),
            (6, 10, 4, 100)
        );
        for split in 0..=120 {
            let mut sum = accounting.written(100, 20, 0, split);
            sum.add(accounting.written(100, 20, split, 120 - split));
            assert_eq!(sum, whole);
        }
        let mut replay = whole.clone();
        replay.add(accounting.written(100, 20, 0, 107));
        assert_eq!(replay.total_written_bytes, 227);
        assert_eq!(replay.payload_bytes, 11);
        assert_eq!(
            replay.total_written_bytes,
            replay.payload_bytes
                + replay.evidence_control_bytes
                + replay.repair_bytes
                + replay.transport_overhead_bytes
        );
        let overlap = ByteAccounting {
            ranges: vec![
                ByteRange {
                    start: 0,
                    end: 4,
                    category: Category::Payload,
                },
                ByteRange {
                    start: 3,
                    end: 6,
                    category: Category::Repair,
                },
            ],
        };
        assert!(overlap.validate(Channel::QuorumStore, &[0; 20]).is_err());
    }
}
