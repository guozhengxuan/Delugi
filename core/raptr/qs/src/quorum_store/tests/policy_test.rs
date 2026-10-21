//! Focused policy/adapter conformance tests, independent of an Aptos node.
use crate::{
    error::DbError,
    payload_manager::{QuorumStorePayloadManager, TPayloadManager},
    quorum_store::{
        batch_store::{BatchReader, BatchStore, BatchWriter},
        proof_manager::ProofManager,
        quorum_store_db::QuorumStoreStorage,
        types::{Batch, PersistedValue},
    },
    test_utils::create_vec_signed_transactions,
};
use anyhow::Result;
use aptos_consensus_types::{
    common::{Payload, PayloadFilter},
    payload::{RaptrPayload, SubBlocks},
    payload_pull_params::OptQSPayloadPullParams,
    proof_of_store::{BatchId, BatchInfo, ProofOfStore},
    request_response::{GetPayloadCommand, GetPayloadRequest, GetPayloadResponse},
    utils::PayloadTxnsSize,
};
use aptos_crypto::HashValue;
use aptos_executor_types::ExecutorResult;
use aptos_types::{
    aggregate_signature::AggregateSignature, transaction::SignedTransaction,
    validator_signer::ValidatorSigner, PeerId,
};
use futures::{channel::oneshot, future::Shared};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Default)]
struct Storage {
    values: Mutex<HashMap<HashValue, PersistedValue>>,
    writes: AtomicUsize,
    fail: AtomicBool,
}
impl QuorumStoreStorage for Storage {
    fn delete_batches(&self, ds: Vec<HashValue>) -> Result<(), DbError> {
        for d in ds {
            self.values.lock().unwrap().remove(&d);
        }
        Ok(())
    }
    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue>> {
        Ok(self.values.lock().unwrap().clone())
    }
    fn save_batch(&self, v: PersistedValue) -> Result<(), DbError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("injected Written failure").into());
        }
        self.values.lock().unwrap().insert(*v.digest(), v);
        Ok(())
    }
    fn get_batch(&self, d: &HashValue) -> Result<Option<PersistedValue>, DbError> {
        Ok(self.values.lock().unwrap().get(d).cloned())
    }
    fn delete_batch_id(&self, _: u64) -> Result<(), DbError> {
        Ok(())
    }
    fn clean_and_get_batch_id(&self, _: u64) -> Result<Option<BatchId>, DbError> {
        Ok(None)
    }
    fn save_batch_id(&self, _: u64, _: BatchId) -> Result<(), DbError> {
        Ok(())
    }
}
fn store(
    storage: Arc<Storage>,
    signer: ValidatorSigner,
) -> (Arc<BatchStore>, shared_runtime_async::Executor) {
    let executor = shared_runtime_async::Executor::new(
        tokio::runtime::Handle::current(),
        Default::default(),
        |_| {},
    )
    .unwrap();
    let group = executor.group("qs-policy-fixture").unwrap();
    (
        Arc::new(BatchStore::new(
            1, false, 0, storage, 10_000_000, 20_000_000, 1000, signer, 0, group,
        )),
        executor,
    )
}
fn batch(author: PeerId, seq: u64, expiry: u64) -> Batch {
    Batch::new(
        BatchId::new_for_test(seq),
        create_vec_signed_transactions(1),
        1,
        expiry,
        author,
        0,
    )
}

#[tokio::test]
async fn custody_ack_requires_successful_written_completion() {
    let signer = ValidatorSigner::random(None);
    let storage = Arc::new(Storage::default());
    let author = signer.author();
    let (store, executor) = store(storage.clone(), signer);
    let first_batch = batch(author, 1, 1000);
    let info = first_batch.batch_info().clone();
    let signed = store.persist(vec![first_batch.into()]);
    assert_eq!(signed.len(), 1);
    assert_eq!(storage.writes.load(Ordering::SeqCst), 1);
    assert_eq!(
        storage
            .get_batch(info.digest())
            .unwrap()
            .unwrap()
            .batch_info(),
        &info
    );
    // Duplicate custody returns a signature without an extra native DB write.
    let repeated = storage.get_batch(info.digest()).unwrap().unwrap();
    assert_eq!(store.persist(vec![repeated]).len(), 1);
    assert_eq!(storage.writes.load(Ordering::SeqCst), 1);
    storage.fail.store(true, Ordering::SeqCst);
    let other = batch(author, 2, 1000);
    let worker = tokio::task::spawn_blocking(move || store.persist(vec![other.into()]));
    assert!(
        worker.await.unwrap_err().is_panic(),
        "native failed write must not emit a custody signature"
    );
    executor.shutdown().await.unwrap();
}

async fn pull(
    manager: &mut ProofManager,
    exclude: HashSet<BatchInfo>,
    exclude_authors: HashSet<PeerId>,
    max: u64,
    now: u64,
) -> RaptrPayload {
    let (callback, rx) = oneshot::channel();
    manager.handle_proposal_request(GetPayloadCommand::GetPayloadRequest(GetPayloadRequest {
        max_txns: PayloadTxnsSize::new(max, 1_000_000),
        max_txns_after_filtering: max,
        soft_max_txns_after_filtering: max,
        max_inline_txns: PayloadTxnsSize::zero(),
        maybe_optqs_payload_pull_params: Some(OptQSPayloadPullParams {
            exclude_authors,
            minimum_batch_age_usecs: 0,
        }),
        filter: PayloadFilter::InQuorumStore(exclude),
        return_non_full: true,
        callback,
        block_timestamp: Duration::from_micros(now),
    }));
    let GetPayloadResponse::GetPayloadResponse(Payload::Raptr(payload)) =
        rx.await.unwrap().unwrap()
    else {
        panic!("native optimistic pull must return Raptr payload")
    };
    payload
}

#[tokio::test]
async fn proof_first_then_optimistic_exclusions_and_commit_removal() {
    let signer = ValidatorSigner::random(None);
    let other = ValidatorSigner::random(None);
    let now = aptos_infallible::duration_since_epoch().as_micros() as u64;
    let expiry = now + 60_000_000;
    let author = signer.author();
    let (store, executor) = store(Arc::new(Storage::default()), signer);
    let proof_batch = batch(author, 1, expiry);
    let opt_batch = batch(other.author(), 2, expiry);
    let proof_info = proof_batch.batch_info().clone();
    let opt_info = opt_batch.batch_info().clone();
    let proof_value: PersistedValue = proof_batch.into();
    let opt_value: PersistedValue = opt_batch.into();
    store.persist(vec![proof_value.clone(), opt_value.clone()]);
    let mut manager = ProofManager::new(author, 1000, 1000, store, true, 60_000_000, 100);
    manager.receive_batches(vec![
        (proof_info.clone(), proof_value.summary()),
        (opt_info.clone(), opt_value.summary()),
    ]);
    manager.receive_proofs(vec![ProofOfStore::new(
        proof_info.clone(),
        AggregateSignature::empty(),
    )]);
    let p = pull(&mut manager, HashSet::new(), HashSet::new(), 1, now + 1).await;
    assert_eq!(p.proof_with_data().len(), 1);
    assert!(p.all_sub_block_batches().is_empty());
    let p = pull(
        &mut manager,
        HashSet::from([proof_info.clone()]),
        HashSet::new(),
        1,
        now + 1,
    )
    .await;
    assert!(p.proof_with_data().is_empty());
    assert_eq!(p.all_sub_block_batches(), vec![opt_info.clone()]);
    let p = pull(
        &mut manager,
        HashSet::from([proof_info.clone()]),
        HashSet::from([other.author()]),
        1,
        now + 1,
    )
    .await;
    assert!(p.all_sub_block_batches().is_empty());
    manager.handle_commit_notification(now + 1, vec![proof_info, opt_info]);
    let p = pull(&mut manager, HashSet::new(), HashSet::new(), 10, now + 2).await;
    assert!(p.proof_with_data().is_empty());
    assert!(p.all_sub_block_batches().is_empty());
    executor.shutdown().await.unwrap();
}

struct Available(HashSet<HashValue>);
impl BatchReader for Available {
    fn exists(&self, d: &HashValue) -> Option<PeerId> {
        self.0.contains(d).then_some(PeerId::ZERO)
    }
    fn get_batch(
        &self,
        _: BatchInfo,
        _: Vec<PeerId>,
    ) -> Shared<Pin<Box<dyn Future<Output = ExecutorResult<Vec<SignedTransaction>>> + Send>>> {
        panic!("availability must not fetch")
    }
    fn update_certified_timestamp(&self, _: u64) {}
}
struct Commit;
impl crate::payload_manager::TQuorumStoreCommitNotifier for Commit {
    fn notify(&self, _: u64, _: Vec<BatchInfo>) {}
}
#[test]
fn available_prefix_reports_every_missing_author_without_fetching() {
    let authors: Vec<_> = (0..4).map(|_| PeerId::random()).collect();
    let batches: Vec<_> = authors
        .iter()
        .enumerate()
        .map(|(i, a)| batch(*a, i as u64, 1000).batch_info().clone())
        .collect();
    let mut sub_blocks = SubBlocks::default();
    sub_blocks[0] = vec![batches[0].clone()].into();
    sub_blocks[1] = vec![batches[1].clone()].into();
    sub_blocks[2] = vec![batches[2].clone()].into();
    let payload = RaptrPayload::new(Vec::new().into(), sub_blocks);
    let manager = QuorumStorePayloadManager::new(
        Arc::new(Available(HashSet::from([*batches[0].digest()]))),
        Box::new(Commit),
        authors.clone(),
        authors.iter().enumerate().map(|(i, a)| (*a, i)).collect(),
    );
    let (prefix, missing) = manager.available_prefix(&payload, 0);
    assert_eq!(prefix, 1);
    assert_eq!(missing.iter_ones().collect::<Vec<_>>(), vec![1, 2]);
}
