//! Measurement-only finite open-loop workload. This is outside the protocol
//! state machine: a blocked handler cannot slow the intended arrival schedule.
//! A signed manifest authorizes a deterministic, finite set of request contents.
//! Replaying an authorized request cannot create another useful application ID.
use crate::composed::Transaction;
use crate::wire::{self, Digest, Id, Signed, SigningDomain};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"DLGLOAD1";
pub const REQUEST_METADATA_BYTES: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub instance: Digest,
    pub origin: Id,
    pub rate_per_second: u64,
    pub count: u64,
    pub useful_bytes: usize,
    pub start_elapsed_us: u64,
    pub identity_version: u32,
    pub total_rate: Option<u64>,
    pub origins: Vec<Id>,
}
impl SigningDomain for Manifest {
    const DOMAIN: &'static str = "evaluation-workload-manifest-v1";
}
impl Manifest {
    pub fn scheduled_us(&self, sequence: u64) -> u64 {
        let (position, rate) = if let Some(total) = self.total_rate {
            let rank = self
                .origins
                .iter()
                .position(|origin| *origin == self.origin)
                .expect("manifest origin belongs to workload");
            (
                sequence as u128 * self.origins.len() as u128 + rank as u128 + 1,
                total,
            )
        } else {
            (sequence as u128 + 1, self.rate_per_second)
        };
        self.start_elapsed_us + (position * 1_000_000).div_ceil(rate as u128) as u64
    }
    pub fn transaction(&self, sequence: u64) -> Transaction {
        transaction(self.instance, self.origin, sequence, self.useful_bytes)
    }
}

pub fn transaction(
    instance: Digest,
    origin: Id,
    sequence: u64,
    useful_bytes: usize,
) -> Transaction {
    let mut bytes = Vec::with_capacity(REQUEST_METADATA_BYTES + useful_bytes);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&origin.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.resize(REQUEST_METADATA_BYTES + useful_bytes, origin as u8);
    Transaction {
        id: wire::hash(&("evaluation-request-v1", instance, &bytes)),
        bytes,
    }
}

/// Content binding is checked independently of whichever producer included it.
/// Admission and the origin's signed finite manifest are checked by the ledger.
pub fn identify(instance: Digest, tx: &Transaction) -> Option<(Id, u64, usize)> {
    if tx.bytes.len() < REQUEST_METADATA_BYTES || &tx.bytes[..8] != MAGIC {
        return None;
    }
    let origin = u32::from_le_bytes(tx.bytes[8..12].try_into().ok()?);
    let sequence = u64::from_le_bytes(tx.bytes[12..20].try_into().ok()?);
    if tx.bytes[20..].iter().any(|byte| *byte != origin as u8)
        || tx.id != wire::hash(&("evaluation-request-v1", instance, &tx.bytes))
    {
        return None;
    }
    Some((origin, sequence, tx.bytes.len() - REQUEST_METADATA_BYTES))
}

/// Detailed timing is optional; finite membership and exact output receipts are
/// common to both modes. Compact does not change the protocol or application log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverMode {
    #[default]
    Full,
    Compact,
}

#[derive(Clone, Debug)]
pub struct Bitmap {
    pub count: u64,
    pub bytes: Vec<u8>,
    pub ones: u64,
}
impl Bitmap {
    pub fn new(count: u64) -> Self {
        Self {
            count,
            bytes: vec![0; count.div_ceil(8) as usize],
            ones: 0,
        }
    }
    pub fn contains(&self, sequence: u64) -> bool {
        sequence < self.count && self.bytes[sequence as usize / 8] & (1 << (sequence % 8)) != 0
    }
    pub fn insert(&mut self, sequence: u64) -> bool {
        assert!(
            sequence < self.count,
            "receipt identity outside finite manifest"
        );
        if self.contains(sequence) {
            return false;
        }
        self.bytes[sequence as usize / 8] |= 1 << (sequence % 8);
        self.ones += 1;
        true
    }
    pub fn descriptor(&self, name: &str, origin: Id) -> BitmapDescriptor {
        use sha2::{Digest as _, Sha256};
        BitmapDescriptor {
            name: name.into(),
            origin,
            count: self.count,
            bytes: self.bytes.len() as u64,
            ones: self.ones,
            sha256: Sha256::digest(&self.bytes).into(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitmapDescriptor {
    pub name: String,
    pub origin: Id,
    pub count: u64,
    pub bytes: u64,
    pub ones: u64,
    pub sha256: Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub instance: Digest,
    pub replica: Id,
    pub mode: ObserverMode,
    pub manifest: Option<Signed<Manifest>>,
    pub scheduled: u64,
    pub output_count: u64,
    pub output_fingerprint: Digest,
    pub batch_count: u64,
    pub batch_fingerprint: Digest,
    pub m_out_bytes: u64,
    pub streams: Vec<BitmapDescriptor>,
}
impl SigningDomain for Receipt {
    const DOMAIN: &'static str = "evaluation-observer-receipt-v1";
}
/// These bitmaps preserve admission eligibility at the first materialization
/// event. A preplayed output cannot gain credit when admission occurs later.
pub struct AdmissionReceipt {
    pub admitted: Bitmap,
    pub rejected: Bitmap,
    pub ready: Bitmap,
    pub completed: Bitmap,
    pub seen_output: Bitmap,
    pub ready_pending: u64,
}
impl AdmissionReceipt {
    pub fn new(count: u64) -> Self {
        Self {
            admitted: Bitmap::new(count),
            rejected: Bitmap::new(count),
            ready: Bitmap::new(count),
            completed: Bitmap::new(count),
            seen_output: Bitmap::new(count),
            ready_pending: 0,
        }
    }
    pub fn materialized(&mut self, sequence: u64) -> bool {
        if !self.seen_output.insert(sequence) {
            return false;
        }
        if self.admitted.contains(sequence) && self.completed.insert(sequence) {
            if self.ready.contains(sequence) {
                self.ready_pending -= 1;
            }
            return true;
        }
        false
    }
    pub fn mark_ready(&mut self, sequence: u64) {
        if self.ready.insert(sequence) && !self.completed.contains(sequence) {
            self.ready_pending += 1;
        }
    }
    pub fn bitmap(&self, name: &str) -> Option<&Bitmap> {
        match name {
            "admitted" => Some(&self.admitted),
            "rejected" => Some(&self.rejected),
            "ready" => Some(&self.ready),
            "completed" => Some(&self.completed),
            "seen_output" => Some(&self.seen_output),
            _ => None,
        }
    }
    pub fn descriptors(&self, origin: Id) -> Vec<BitmapDescriptor> {
        ["admitted", "rejected", "ready", "completed", "seen_output"]
            .iter()
            .map(|name| self.bitmap(name).unwrap().descriptor(name, origin))
            .collect()
    }
}
pub fn output_seed() -> Digest {
    wire::hash(&"evaluation-exact-output-receipt-v1")
}
pub fn batch_seed() -> Digest {
    wire::hash(&"evaluation-exact-batch-receipt-v1")
}
pub fn output_step(previous: Digest, entry: &crate::composed::Executed) -> Digest {
    wire::hash(&("evaluation-exact-output-step-v1", previous, entry))
}
pub fn batch_step(previous: Digest, entry: &crate::composed::MaterializedBatch) -> Digest {
    wire::hash(&(
        "evaluation-exact-batch-step-v1",
        previous,
        crate::batch::header_digest(&entry.header),
        entry.payload.len() as u64,
    ))
}

#[derive(Clone, Default, Debug, Serialize)]
pub struct Timing {
    pub admitted_us: Option<u64>,
    pub batch_ready_us: Option<u64>,
    pub materialized_us: Option<u64>,
    pub post_handler_published_us: Option<u64>,
    pub rejected_us: Option<u64>,
    pub rejection_reason: Option<String>,
    pub all_correct_observed_us: Option<u64>,
}
#[derive(Serialize)]
pub struct Entry {
    pub id: Digest,
    pub origin: Id,
    pub sequence: u64,
    pub useful_bytes: usize,
    pub scheduled_us: u64,
    #[serde(flatten)]
    pub timing: Timing,
}
pub struct Arrival {
    pub sequence: u64,
    pub transaction: Transaction,
}

pub struct Ingress {
    pub manifest: Signed<Manifest>,
    pub receiver: mpsc::Receiver<Arrival>,
    pub timings: Arc<Mutex<BTreeMap<u64, Timing>>>,
    pub receipt: Arc<Mutex<AdmissionReceipt>>,
    pub mode: ObserverMode,
    pub scheduled: Arc<AtomicU64>,
    pub admitted: Arc<AtomicU64>,
    pub rejected: Arc<AtomicU64>,
    pub finished: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Ingress {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
    pub fn start(manifest: Manifest, key: &Keypair, clock: Instant, capacity: usize) -> Self {
        Self::start_with_mode(manifest, key, clock, capacity, ObserverMode::Full)
    }
    pub fn start_with_mode(
        manifest: Manifest,
        key: &Keypair,
        clock: Instant,
        capacity: usize,
        mode: ObserverMode,
    ) -> Self {
        let signed = wire::sign(key, manifest.origin, manifest.clone());
        let receipt = Arc::new(Mutex::new(AdmissionReceipt::new(manifest.count)));
        let worker_receipt = receipt.clone();
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let timings = Arc::new(Mutex::new(BTreeMap::new()));
        let scheduled = Arc::new(AtomicU64::new(0));
        let admitted = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let finished = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (records, due, accepted, denied, done, cancelled) = (
            timings.clone(),
            scheduled.clone(),
            admitted.clone(),
            rejected.clone(),
            finished.clone(),
            stop.clone(),
        );
        let worker = thread::spawn(move || {
            for sequence in 0..manifest.count {
                let intended = manifest.scheduled_us(sequence);
                loop {
                    if cancelled.load(Ordering::Relaxed) {
                        done.store(true, Ordering::Release);
                        return;
                    }
                    let now = clock.elapsed().as_micros() as u64;
                    if now >= intended {
                        break;
                    }
                    thread::sleep(Duration::from_micros((intended - now).min(1000)));
                }
                let transaction = manifest.transaction(sequence);
                // Publish admission and the channel send atomically from the
                // consumer's perspective in both observer modes.
                let mut membership = worker_receipt.lock().unwrap();
                let mut records = if mode == ObserverMode::Full {
                    Some(records.lock().unwrap())
                } else {
                    None
                };
                let now = if mode == ObserverMode::Full {
                    clock.elapsed().as_micros() as u64
                } else {
                    0
                };
                let mut timing = Timing::default();
                match sender.try_send(Arrival {
                    sequence,
                    transaction,
                }) {
                    Ok(()) => {
                        membership.admitted.insert(sequence);
                        if mode == ObserverMode::Full {
                            timing.admitted_us = Some(now);
                        }
                        accepted.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        membership.rejected.insert(sequence);
                        if mode == ObserverMode::Full {
                            timing.rejected_us = Some(now);
                            timing.rejection_reason = Some(
                                match error {
                                    mpsc::TrySendError::Full(_) => "arrival_queue_full",
                                    mpsc::TrySendError::Disconnected(_) => "ingress_closed",
                                }
                                .into(),
                            );
                        }
                        denied.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if let Some(records) = records.as_mut() {
                    records.insert(sequence, timing);
                }
                due.fetch_add(1, Ordering::Release);
            }
            done.store(true, Ordering::Release);
        });
        Self {
            manifest: signed,
            receipt,
            mode,
            receiver,
            timings,
            scheduled,
            admitted,
            rejected,
            finished,
            stop,
            worker: Some(worker),
        }
    }
    pub fn entries(&self, offset: usize, limit: usize) -> Vec<Entry> {
        let manifest = &self.manifest.body;
        let records = self.timings.lock().unwrap();
        (offset as u64..manifest.count.min(offset.saturating_add(limit) as u64))
            .map(|sequence| Entry {
                id: manifest.transaction(sequence).id,
                origin: manifest.origin,
                sequence,
                useful_bytes: manifest.useful_bytes,
                scheduled_us: manifest.scheduled_us(sequence),
                timing: records.get(&sequence).cloned().unwrap_or_default(),
            })
            .collect()
    }
}
impl Drop for Ingress {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PublicKey, SecretKey};
    fn key() -> Keypair {
        let secret = SecretKey::from_bytes(&[7; 32]).unwrap();
        Keypair {
            public: PublicKey::from(&secret),
            secret,
        }
    }
    #[test]
    fn receipt_eligibility_is_latched_and_never_retroactive() {
        let mut receipt = AdmissionReceipt::new(4);
        assert!(!receipt.materialized(0)); // Future/pre-admission output.
        receipt.admitted.insert(0);
        receipt.mark_ready(0);
        assert!(!receipt.materialized(0)); // A later replay cannot gain credit.
        receipt.admitted.insert(1);
        receipt.mark_ready(1);
        assert!(receipt.materialized(1));
        assert!(!receipt.materialized(1));
        assert_eq!(receipt.completed.ones, 1);
        assert!(receipt.seen_output.contains(0));
        assert!(!receipt.completed.contains(0));
        assert_eq!(receipt.admitted.descriptor("admitted", 0).ones, 2);
    }
    #[test]
    fn admitted_output_is_eligible_before_own_batch_ready() {
        let mut receipt = AdmissionReceipt::new(2);
        receipt.admitted.insert(0);
        assert!(receipt.materialized(0));
        assert_eq!(receipt.completed.ones, 1);
        assert_eq!(receipt.ready_pending, 0);
        receipt.mark_ready(0);
        assert_eq!(receipt.ready_pending, 0);
        receipt.admitted.insert(1);
        receipt.mark_ready(1);
        assert_eq!(receipt.ready_pending, 1);
        assert!(receipt.materialized(1));
        assert_eq!(receipt.ready_pending, 0);
    }
    #[test]
    fn compact_ingress_preserves_admission_rejection_without_timing_rows() {
        for mode in [ObserverMode::Full, ObserverMode::Compact] {
            let manifest = Manifest {
                instance: [1; 32],
                origin: 0,
                rate_per_second: 1_000_000,
                count: 12,
                useful_bytes: 8,
                start_elapsed_us: 0,
                identity_version: 1,
                total_rate: None,
                origins: vec![0],
            };
            let ingress = Ingress::start_with_mode(manifest, &key(), Instant::now(), 2, mode);
            let deadline = Instant::now() + Duration::from_secs(2);
            while !ingress.finished.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(1));
            }
            let receipt = ingress.receipt.lock().unwrap();
            assert_eq!(receipt.admitted.ones, 2);
            assert_eq!(receipt.rejected.ones, 10);
            assert_eq!(receipt.ready.ones, 0);
            assert_eq!(receipt.completed.ones, 0);
            assert_eq!(
                ingress.timings.lock().unwrap().len(),
                if mode == ObserverMode::Full { 12 } else { 0 }
            );
        }
    }
    #[test]
    fn successful_channel_arrival_has_published_receipt_and_full_timestamp() {
        let manifest = Manifest {
            instance: [1; 32],
            origin: 0,
            rate_per_second: 1_000_000,
            count: 1,
            useful_bytes: 8,
            start_elapsed_us: 0,
            identity_version: 1,
            total_rate: None,
            origins: vec![0],
        };
        let clock = Instant::now();
        let ingress = Ingress::start(manifest, &key(), clock, 2);
        let arrival = ingress
            .receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let receipt = ingress.receipt.lock().unwrap();
        assert!(receipt.admitted.contains(arrival.sequence));
        let records = ingress.timings.lock().unwrap();
        assert!(
            records[&arrival.sequence].admitted_us.unwrap() <= clock.elapsed().as_micros() as u64
        );
    }
    #[test]
    fn identity_binds_run_origin_sequence_and_payload() {
        let tx = transaction([1; 32], 2, 9, 400);
        assert_eq!(identify([1; 32], &tx), Some((2, 9, 400)));
        assert_eq!(identify([2; 32], &tx), None);
        let mut changed = tx.clone();
        changed.bytes[20] ^= 1;
        assert_eq!(identify([1; 32], &changed), None);
        assert_ne!(tx.id, transaction([1; 32], 2, 10, 400).id);
    }
    #[test]
    fn stalled_consumer_does_not_erase_arrivals_and_rejections() {
        let manifest = Manifest {
            instance: [1; 32],
            origin: 0,
            rate_per_second: 1_000_000,
            count: 12,
            useful_bytes: 8,
            start_elapsed_us: 0,
            identity_version: 1,
            total_rate: None,
            origins: vec![0],
        };
        let ingress = Ingress::start(manifest, &key(), Instant::now(), 2);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !ingress.finished.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(ingress.admitted.load(Ordering::Relaxed), 2);
        assert_eq!(ingress.rejected.load(Ordering::Relaxed), 10);
        let entries = ingress.entries(0, 20);
        assert_eq!(entries.len(), 12);
        assert_eq!(entries[11].scheduled_us, 12);
        assert_eq!(
            entries[11].timing.rejection_reason.as_deref(),
            Some("arrival_queue_full")
        );
        assert!(entries
            .iter()
            .all(|row| row.timing.materialized_us.is_none()));
    }
    #[test]
    fn finite_manifest_retains_not_yet_admitted_population() {
        let manifest = Manifest {
            instance: [1; 32],
            origin: 0,
            rate_per_second: 3,
            count: 3,
            useful_bytes: 1,
            start_elapsed_us: 10_000_000,
            identity_version: 1,
            total_rate: None,
            origins: vec![0],
        };
        let ingress = Ingress::start(manifest, &key(), Instant::now(), 2);
        let entries = ingress.entries(1, 1);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[0].scheduled_us, 10_666_667);
        assert!(entries[0].timing.admitted_us.is_none());
    }
}
