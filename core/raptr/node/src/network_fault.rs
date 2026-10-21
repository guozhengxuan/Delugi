//! Explicit finite-test ingress omission; disabled in every normal profile.
//! Records authenticated original batches and actual native repair completion.
use anyhow::{anyhow, ensure, Result};
use aptos_consensus_types::{common::Author, proof_of_store::BatchInfo};
use aptos_crypto::HashValue;
use raptr_qs::quorum_store::types::{BatchMsg, BatchResponse};
use serde::Serialize;
use std::sync::{Arc, Mutex};

const MAX_DROPPED_BATCHES: usize = 16_384;
const MAX_REPAIR_REQUESTS: usize = 16_384;
fn now() -> Result<u64> {
    shared_runtime::monotonic_us().map_err(anyhow::Error::msg)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Serialize)]
pub struct BatchWitness {
    pub epoch: u64,
    pub author: String,
    pub nonce: u64,
    pub id: u64,
    pub digest: String,
    pub num_txns: u64,
    pub num_bytes: u64,
    pub native_info_bcs_hex: String,
}
impl BatchWitness {
    fn new(info: &BatchInfo) -> Result<Self> {
        Ok(Self {
            epoch: info.epoch(),
            author: hex(info.author().as_ref()),
            nonce: info.batch_id().nonce,
            id: info.batch_id().id,
            digest: hex(info.digest().as_ref()),
            num_txns: info.num_txns(),
            num_bytes: info.num_bytes(),
            native_info_bcs_hex: hex(&shared_crypto_aptos::encode(info)?),
        })
    }
}
#[derive(Clone, Serialize)]
pub struct DroppedMessage {
    pub message_index: u64,
    pub sender: String,
    pub observed_us: u64,
    pub native_payload_verified: bool,
    pub batches: Vec<BatchWitness>,
}
#[derive(Clone, Serialize)]
pub struct RepairRequest {
    pub rpc_id: u64,
    pub digest: String,
    pub recipient: String,
    pub started_us: u64,
    pub finished_us: Option<u64>,
    pub outcome: String,
    pub received_batch: Option<BatchWitness>,
    pub error: Option<String>,
}
#[derive(Clone, Serialize)]
pub struct PayloadFaultSnapshot {
    pub configured_drop_messages: u64,
    pub dropped_messages: u64,
    pub dropped_batches: usize,
    pub drop_records: Vec<DroppedMessage>,
    pub repair_requests: Vec<RepairRequest>,
}
#[derive(Clone, Default)]
pub(crate) struct PayloadFault(Arc<Mutex<Option<PayloadFaultSnapshot>>>);
impl PayloadFault {
    pub fn configure(&self, count: u64) -> Result<()> {
        ensure!(
            (1..=1000).contains(&count),
            "invalid finite payload omission count"
        );
        let mut state = self.0.lock().unwrap();
        ensure!(state.is_none(), "payload omission already configured");
        *state = Some(PayloadFaultSnapshot {
            configured_drop_messages: count,
            dropped_messages: 0,
            dropped_batches: 0,
            drop_records: vec![],
            repair_requests: vec![],
        });
        Ok(())
    }
    pub fn snapshot(&self) -> Option<PayloadFaultSnapshot> {
        self.0.lock().unwrap().clone()
    }
    pub fn intercept(&self, sender: Author, message: BatchMsg) -> Result<Option<BatchMsg>> {
        let mut guard = self.0.lock().unwrap();
        let state = match guard.as_mut() {
            Some(state) if state.dropped_messages < state.configured_drop_messages => state,
            _ => return Ok(Some(message)),
        };
        // The byte-service already authenticated the sender. Preserve native
        // batch author/digest/count/size validation before recording a drop.
        // Normal traffic still receives its configured native policy limits.
        shared_crypto_aptos::native_validation(|| message.verify(sender, MAX_DROPPED_BATCHES))?;
        message.epoch()?;
        let batches = message.take();
        ensure!(
            state
                .dropped_batches
                .checked_add(batches.len())
                .map_or(false, |n| n <= MAX_DROPPED_BATCHES),
            "payload fault evidence batch envelope exhausted"
        );
        let records = batches
            .iter()
            .map(|batch| BatchWitness::new(batch.batch_info()))
            .collect::<Result<Vec<_>>>()?;
        let record = DroppedMessage {
            message_index: state.dropped_messages,
            sender: hex(sender.as_ref()),
            observed_us: now()?,
            native_payload_verified: true,
            batches: records,
        };
        state.dropped_batches += batches.len();
        state.dropped_messages += 1;
        state.drop_records.push(record);
        Ok(None)
    }
    pub fn request_started(
        &self,
        rpc_id: u64,
        digest: HashValue,
        recipient: Author,
    ) -> Result<Option<usize>> {
        let mut guard = self.0.lock().unwrap();
        let state = match guard.as_mut() {
            Some(state) => state,
            None => return Ok(None),
        };
        ensure!(
            state.repair_requests.len() < MAX_REPAIR_REQUESTS,
            "payload fault repair evidence envelope exhausted"
        );
        let index = state.repair_requests.len();
        state.repair_requests.push(RepairRequest {
            rpc_id,
            digest: hex(digest.as_ref()),
            recipient: hex(recipient.as_ref()),
            started_us: now()?,
            finished_us: None,
            outcome: "pending".into(),
            received_batch: None,
            error: None,
        });
        Ok(Some(index))
    }
    pub fn request_finished(
        &self,
        index: Option<usize>,
        result: &Result<BatchResponse>,
    ) -> Result<()> {
        let index = match index {
            Some(index) => index,
            None => return Ok(()),
        };
        let mut guard = self.0.lock().unwrap();
        let row = guard
            .as_mut()
            .and_then(|state| state.repair_requests.get_mut(index))
            .ok_or_else(|| anyhow!("missing payload fault repair record"))?;
        ensure!(row.finished_us.is_none(), "repair request completed twice");
        match result {
            Ok(BatchResponse::Batch(batch)) => {
                row.received_batch = Some(BatchWitness::new(batch.batch_info())?);
                row.outcome = "received_batch".into();
            }
            Ok(_) => row.outcome = "not_found".into(),
            Err(error) => {
                row.outcome = "failed".into();
                row.error = Some(error.to_string().chars().take(1024).collect());
            }
        }
        row.finished_us = Some(now()?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_consensus_types::proof_of_store::BatchId;
    use raptr_qs::quorum_store::types::Batch;
    fn batch(author: Author) -> Batch {
        Batch::new(
            BatchId {
                id: 19,
                nonce: 0x100000000,
            },
            vec![],
            7,
            u64::MAX,
            author,
            0,
        )
    }
    #[test]
    fn disabled_passes_exact_native_bytes_and_omission_is_finite() {
        let fault = PayloadFault::default();
        let author = Author::new([1; 32]);
        let msg = BatchMsg::new(vec![batch(author)]);
        let bytes = bcs::to_bytes(&msg).unwrap();
        assert_eq!(
            bcs::to_bytes(&fault.intercept(author, msg).unwrap().unwrap()).unwrap(),
            bytes
        );
        assert!(fault.snapshot().is_none());
        fault.configure(1).unwrap();
        assert!(fault
            .intercept(author, BatchMsg::new(vec![batch(author)]))
            .unwrap()
            .is_none());
        assert!(fault
            .intercept(author, BatchMsg::new(vec![batch(author)]))
            .unwrap()
            .is_some());
        let snap = fault.snapshot().unwrap();
        assert_eq!(snap.dropped_messages, 1);
        assert_eq!(snap.dropped_batches, 1);
        let info = &snap.drop_records[0].batches[0];
        assert_eq!(info.nonce, 0x100000000);
        assert_eq!(info.native_info_bcs_hex.len(), 240);
        assert!(fault.configure(1).is_err());
    }
    #[test]
    fn invalid_author_does_not_consume_drop_and_repair_receive_is_recorded() {
        let fault = PayloadFault::default();
        fault.configure(1).unwrap();
        let author = Author::new([1; 32]);
        assert!(fault
            .intercept(Author::new([2; 32]), BatchMsg::new(vec![batch(author)]))
            .is_err());
        assert_eq!(fault.snapshot().unwrap().dropped_messages, 0);
        let b = batch(author);
        let index = fault.request_started(1, *b.digest(), author).unwrap();
        b.verify_with_digest(*b.digest()).unwrap();
        fault
            .request_finished(index, &Ok(BatchResponse::Batch(b)))
            .unwrap();
        let snap = fault.snapshot().unwrap();
        let row = &snap.repair_requests[0];
        assert_eq!(row.outcome, "received_batch");
        assert!(row.finished_us.unwrap() >= row.started_us);
        assert_eq!(row.received_batch.as_ref().unwrap().digest, row.digest);
        assert!(fault
            .request_finished(index, &Err(anyhow!("late")))
            .is_err());
    }
}
