//! Native actor assembly with explicit node-owned transport, custody and mempool
//! services. Channel styles/capacities and actor deadlines match InnerBuilder.
use crate::{
    mempool::QuorumStoreRequest,
    network::NetworkSender,
    quorum_store::{
        batch_coordinator::BatchCoordinator,
        batch_generator::BatchGenerator,
        batch_requester::BatchRequester,
        batch_store::{BatchReader, BatchReaderImpl, BatchStore},
        network_listener::NetworkListener,
        proof_coordinator::ProofCoordinator,
        proof_manager::ProofManager,
        quorum_store_coordinator::{CoordinatorCommand, QuorumStoreCoordinator},
        quorum_store_db::QuorumStoreStorage,
        types::{BatchMsg, BatchRequest, BatchResponse},
    },
    round_manager::VerifiedEvent,
};
use anyhow::{ensure, Result};
use aptos_channels::{aptos_channel, message_queues::QueueStyle};
use aptos_config::config::QuorumStoreConfig;
use aptos_consensus_types::{
    common::Author,
    proof_of_store::{ProofCache, ProofOfStoreMsg, SignedBatchInfoMsg},
    request_response::GetPayloadCommand,
};
use aptos_crypto::bls12381::PrivateKey;
use aptos_types::{
    ledger_info::LedgerInfoWithSignatures, validator_signer::ValidatorSigner,
    validator_verifier::ValidatorVerifier,
};
use futures::{SinkExt, StreamExt};
use futures_channel::mpsc;
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc as tokio_mpsc, oneshot},
    task::JoinHandle,
    time::MissedTickBehavior,
};

pub struct AssemblyConfig {
    pub epoch: u64,
    pub author: Author,
    pub config: QuorumStoreConfig,
    pub num_validators: u64,
    pub last_committed_timestamp: u64,
    pub is_new_epoch: bool,
    pub broadcast_proofs: bool,
}

/// The native negative retrieval response is a signed ledger proof, not a
/// fabricated empty batch. The node supplies its actual latest ledger source.
pub trait LatestLedger: Send + Sync {
    fn latest(&self) -> Result<LedgerInfoWithSignatures>;
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum Message {
    Batch(BatchMsg),
    SignedBatchInfo(SignedBatchInfoMsg),
    Proof(ProofOfStoreMsg),
}

#[derive(Debug)]
struct Retrieval {
    request: BatchRequest,
    response: oneshot::Sender<Result<BatchResponse>>,
}

#[derive(Clone)]
pub struct Inbound {
    epoch: u64,
    author: Author,
    config: QuorumStoreConfig,
    verifier: Arc<ValidatorVerifier>,
    proof_cache: ProofCache,
    messages: aptos_channel::Sender<Author, (Author, VerifiedEvent)>,
    retrieval: aptos_channel::Sender<Author, Retrieval>,
}
impl Inbound {
    pub fn receive(&self, sender: Author, message: Message) -> Result<()> {
        self.receive_inner(sender, message, false)
    }
    /// Only the node's local self-send path may call this. Remote bytes always
    /// use `receive`, including bytes claiming the local author's identity.
    /// This preserves the native self-message verification exemption.
    pub fn receive_local(&self, message: Message) -> Result<()> {
        self.receive_inner(self.author, message, true)
    }
    fn receive_inner(&self, sender: Author, message: Message, local: bool) -> Result<()> {
        let event = match message {
            Message::Batch(msg) => {
                ensure!(msg.epoch()? == self.epoch, "batch epoch mismatch");
                if !local {
                    shared_crypto_aptos::native_validation(|| {
                        msg.verify(sender, self.config.receiver_max_num_batches)
                    })?;
                }
                VerifiedEvent::BatchMsg(Box::new(msg))
            }
            Message::SignedBatchInfo(msg) => {
                ensure!(msg.epoch()? == self.epoch, "signed batch epoch mismatch");
                if !local {
                    shared_crypto_aptos::native_validation(|| {
                        msg.verify(
                            sender,
                            self.config.receiver_max_num_batches,
                            self.config.batch_expiry_gap_when_init_usecs,
                            &self.verifier,
                        )
                    })?;
                }
                VerifiedEvent::SignedBatchInfo(Box::new(msg))
            }
            Message::Proof(msg) => {
                ensure!(msg.epoch()? == self.epoch, "proof epoch mismatch");
                if !local {
                    shared_crypto_aptos::native_validation(|| {
                        msg.verify(
                            self.config.receiver_max_num_batches,
                            &self.verifier,
                            &self.proof_cache,
                        )
                    })?;
                }
                VerifiedEvent::ProofOfStoreMsg(Box::new(msg))
            }
        };
        self.messages
            .push(sender, (sender, event))
            .map_err(|e| anyhow::anyhow!("QS inbound queue: {e:?}"))
    }
    pub async fn request_batch(
        &self,
        sender: Author,
        request: BatchRequest,
    ) -> Result<BatchResponse> {
        request.verify(sender)?;
        ensure!(request.epoch() == self.epoch, "retrieval epoch mismatch");
        let (response, rx) = oneshot::channel();
        self.retrieval
            .push(sender, Retrieval { request, response })
            .map_err(|e| anyhow::anyhow!("QS retrieval queue: {e:?}"))?;
        rx.await.map_err(anyhow::Error::from)?
    }
}

pub struct Assembly {
    pub payload_requests: mpsc::Sender<GetPayloadCommand>,
    pub batch_reader: Arc<dyn BatchReader>,
    pub coordinator: mpsc::Sender<CoordinatorCommand>,
    pub inbound: Inbound,
    tasks: Vec<JoinHandle<()>>,
    retrieval_task: JoinHandle<()>,
}
impl Assembly {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        settings: AssemblyConfig,
        network: NetworkSender,
        storage: Arc<dyn QuorumStoreStorage>,
        verifier: Arc<ValidatorVerifier>,
        consensus_key: Arc<PrivateKey>,
        mempool: mpsc::Sender<QuorumStoreRequest>,
        mempool_timeout_ms: u64,
        proof_cache: ProofCache,
        ledger: Arc<dyn LatestLedger>,
    ) -> Result<Self> {
        let AssemblyConfig {
            epoch,
            author,
            config,
            num_validators,
            last_committed_timestamp,
            is_new_epoch,
            broadcast_proofs,
        } = settings;
        ensure!(
            config.channel_size > 0 && config.num_workers_for_remote_batches > 0,
            "native QS requires nonempty channels and remote workers"
        );
        let (payload_requests, payload_rx) = mpsc::channel(config.channel_size);
        let (coordinator, coordinator_rx) = mpsc::channel(config.channel_size);
        let (generator_tx, generator_rx) = tokio_mpsc::channel(config.channel_size);
        let (proof_tx, proof_rx) = tokio_mpsc::channel(config.channel_size);
        let (manager_tx, manager_rx) = tokio_mpsc::channel(config.channel_size);
        let (pressure_tx, pressure_rx) = tokio_mpsc::channel(config.channel_size);
        let (messages, messages_rx) =
            aptos_channel::new(QueueStyle::FIFO, config.channel_size, None);
        let mut worker_txs = Vec::new();
        let mut worker_rxs = Vec::new();
        for _ in 0..config.num_workers_for_remote_batches {
            let (tx, rx) = tokio_mpsc::channel(config.channel_size);
            worker_txs.push(tx);
            worker_rxs.push(rx);
        }
        let requester = BatchRequester::new(
            epoch,
            author,
            config.batch_request_num_peers,
            config.batch_request_retry_limit,
            config.batch_request_retry_interval_ms,
            config.batch_request_rpc_timeout_ms,
            network.clone(),
            verifier.clone(),
        );
        let store = Arc::new(BatchStore::new(
            epoch,
            is_new_epoch,
            last_committed_timestamp,
            storage.clone(),
            config.memory_quota,
            config.db_quota,
            config.batch_quota,
            ValidatorSigner::new(author, consensus_key),
            Duration::from_secs(60).as_micros() as u64,
        ));
        let batch_reader: Arc<dyn BatchReader> =
            Arc::new(BatchReaderImpl::new(store.clone(), requester));
        let mut tasks = Vec::new();
        tasks.push(tokio::spawn(
            QuorumStoreCoordinator::new(
                author,
                generator_tx.clone(),
                worker_txs.clone(),
                proof_tx.clone(),
                manager_tx.clone(),
                messages.clone(),
            )
            .start(coordinator_rx),
        ));
        let mut interval = tokio::time::interval(Duration::from_millis(
            config.batch_generation_poll_interval_ms as u64,
        ));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tasks.push(tokio::spawn(
            BatchGenerator::new(
                epoch,
                author,
                config.clone(),
                storage,
                store.clone(),
                mempool,
                mempool_timeout_ms,
            )
            .start(network.clone(), generator_rx, pressure_rx, interval),
        ));
        for rx in worker_rxs {
            tasks.push(tokio::spawn(
                BatchCoordinator::new(
                    author,
                    network.clone(),
                    manager_tx.clone(),
                    generator_tx.clone(),
                    store.clone(),
                    config.receiver_max_batch_txns as u64,
                    config.receiver_max_batch_bytes as u64,
                    config.receiver_max_total_txns as u64,
                    config.receiver_max_total_bytes as u64,
                    config.batch_expiry_gap_when_init_usecs,
                )
                .start(rx),
            ));
        }
        tasks.push(tokio::spawn(
            ProofCoordinator::new(
                config.proof_timeout_ms,
                author,
                batch_reader.clone(),
                generator_tx,
                proof_cache.clone(),
                broadcast_proofs,
                config.batch_expiry_gap_when_init_usecs,
            )
            .start(proof_rx, network, verifier.clone()),
        ));
        tasks.push(tokio::spawn(
            ProofManager::new(
                author,
                config.back_pressure.backlog_txn_limit_count,
                config.back_pressure.backlog_per_validator_batch_limit_count * num_validators,
                store.clone(),
                config.allow_batches_without_pos_in_proposal,
                config.batch_expiry_gap_when_init_usecs,
                config.max_batches_per_pull,
            )
            .start(pressure_tx, payload_rx, manager_rx),
        ));
        tasks.push(tokio::spawn(
            NetworkListener::new(messages_rx, proof_tx, worker_txs, manager_tx).start(),
        ));
        let (retrieval, mut retrieval_rx) = aptos_channel::new::<Author, Retrieval>(
            QueueStyle::LIFO,
            10,
            Some(&crate::quorum_store::counters::BATCH_RETRIEVAL_TASK_MSGS),
        );
        let retrieval_task = tokio::spawn(async move {
            while let Some(request) = retrieval_rx.next().await {
                crate::quorum_store::counters::RECEIVED_BATCH_REQUEST_COUNT.inc();
                let response = match store.get_batch_from_local(&request.request.digest()) {
                    Ok(value) => Ok(BatchResponse::Batch(
                        value.try_into().expect("stored native batch payload"),
                    )),
                    Err(_) => ledger.latest().map(BatchResponse::NotFound),
                };
                let _ = request.response.send(response);
            }
        });
        Ok(Self {
            payload_requests,
            batch_reader,
            coordinator,
            inbound: Inbound {
                epoch,
                author,
                config,
                verifier,
                proof_cache,
                messages,
                retrieval,
            },
            tasks,
            retrieval_task,
        })
    }
    pub async fn shutdown(mut self) -> Result<()> {
        let (tx, rx) = futures_channel::oneshot::channel();
        self.coordinator
            .send(CoordinatorCommand::Shutdown(tx))
            .await?;
        rx.await?;
        for task in self.tasks {
            task.await?;
        }
        // Native retrieval service is epoch-owned. External cloned handles may
        // outlive shutdown, so explicitly close this service after pipeline ACK.
        self.retrieval_task.abort();
        match self.retrieval_task.await {
            Ok(()) => Ok(()),
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
