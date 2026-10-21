//! Native consensus and QS messages over the common authenticated byte service.
//! RPC correlation is transport metadata; every response retains native types.
use anyhow::{anyhow, ensure, Result};
use aptos_consensus_types::{
    common::Author,
    proof_of_store::{ProofOfStore, ProofOfStoreMsg, SignedBatchInfo, SignedBatchInfoMsg},
};
use raptr::{
    framework::{
        network::{MessageVerifier, NetworkSender, NetworkService},
        NodeId,
    },
    raptr::{Message as ConsensusMessage, Verifier},
};
use raptr_qs::{
    assembly::{Inbound, Message as QsMessage},
    network::NetworkTransport,
    quorum_store::types::{Batch, BatchMsg, BatchRequest, BatchResponse},
};
use raptr_shared_transport::{
    ByteAccounting, ByteRange, Category, Channel, ReceivedBytes, Receiver, Sender,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
#[path = "network_fault.rs"]
mod fault;
pub use fault::PayloadFaultSnapshot;

#[derive(Serialize, Deserialize)]
enum QsWire {
    Message(QsMessage),
    Request { id: u64, request: BatchRequest },
    Response { id: u64, response: BatchResponse },
}

struct Pending {
    recipient: Author,
    response: oneshot::Sender<BatchResponse>,
}

#[derive(Clone)]
pub struct NativeSender {
    shared: Sender,
    authors: Arc<Vec<Author>>,
    own_id: NodeId,
    maximum_bytes: usize,
    maximum_rpcs: usize,
    pending: Arc<Mutex<BTreeMap<u64, Pending>>>,
    next_rpc: Arc<AtomicU64>,
    rejected: Arc<AtomicU64>,
    payload_fault: fault::PayloadFault,
}

impl NativeSender {
    pub fn new(
        shared: Sender,
        authors: Vec<Author>,
        own_id: NodeId,
        maximum_bytes: usize,
        maximum_rpcs: usize,
    ) -> Result<Self> {
        ensure!(
            own_id < authors.len() && maximum_rpcs > 0 && maximum_bytes > 0,
            "invalid native service bounds"
        );
        ensure!(
            authors
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == authors.len(),
            "duplicate native author"
        );
        Ok(Self {
            shared,
            authors: Arc::new(authors),
            own_id,
            maximum_bytes,
            maximum_rpcs,
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            next_rpc: Arc::new(AtomicU64::new(1)),
            rejected: Arc::new(AtomicU64::new(0)),
            payload_fault: fault::PayloadFault::default(),
        })
    }

    pub fn rejected_messages(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
    pub fn configure_payload_fault(&self, drop_initial_batch_messages: u64) -> Result<()> {
        self.payload_fault.configure(drop_initial_batch_messages)
    }
    pub fn payload_fault_snapshot(&self) -> Option<PayloadFaultSnapshot> {
        self.payload_fault.snapshot()
    }
    pub fn status(&self) -> Result<()> {
        self.shared.check().map_err(anyhow::Error::msg)
    }
    pub fn fail(&self, error: impl std::fmt::Display) {
        self.shared.fail(error.to_string());
    }
    pub fn shared(&self) -> &Sender {
        &self.shared
    }

    /// Native send returns unit. A failure latches into the shared service and
    /// the owner must select this terminal future against Protocol::run_ctx.
    pub async fn failed(&self) -> String {
        loop {
            if let Err(error) = self.shared.check() {
                return error;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn id(&self, author: Author) -> Result<usize> {
        self.authors
            .iter()
            .position(|candidate| *candidate == author)
            .ok_or_else(|| anyhow!("native recipient is not a committee member"))
    }

    async fn bytes(
        &self,
        target: usize,
        channel: Channel,
        bytes: Vec<u8>,
        accounting: ByteAccounting,
    ) -> Result<()> {
        ensure!(
            target < self.authors.len(),
            "native target outside committee"
        );
        ensure!(
            bytes.len() <= self.maximum_bytes,
            "native encoded payload exceeds configured envelope"
        );
        self.shared
            .send(u32::try_from(target)?, channel, bytes, accounting)
            .await
            .map_err(anyhow::Error::msg)?;
        Ok(())
    }

    async fn qs(&self, message: QsWire, targets: Vec<usize>) -> Result<()> {
        let bytes = shared_crypto_aptos::encode(&message)?;
        // Native repair replies are separated from initial dissemination. Exact
        // payload subranges are recorded by the native Batch encoding adapter.
        let accounting = match &message {
            QsWire::Request { .. } | QsWire::Response { .. } => ByteAccounting::repair(bytes.len()),
            QsWire::Message(QsMessage::Batch(batch)) => {
                let encoded = batch.encode_with_payload_ranges()?;
                // Both native enums use variant0 for this message. Bind the
                // offsets to exact emitted bytes, rather than assuming layout.
                ensure!(
                    bytes.len() == encoded.bytes.len() + 2
                        && bytes[..2] == [0, 0]
                        && bytes[2..] == encoded.bytes,
                    "native batch envelope layout changed"
                );
                ByteAccounting {
                    ranges: encoded
                        .transaction_ranges
                        .into_iter()
                        .map(|range| ByteRange {
                            start: range.start + 2,
                            end: range.end + 2,
                            category: Category::Payload,
                        })
                        .collect(),
                }
            }
            _ => ByteAccounting::default(),
        };
        for target in targets {
            self.bytes(
                target,
                Channel::QuorumStore,
                bytes.clone(),
                accounting.clone(),
            )
            .await?;
        }
        Ok(())
    }

    async fn qs_or_fail(&self, message: QsWire, targets: Vec<usize>) {
        if let Err(error) = self.qs(message, targets).await {
            self.fail(error);
        }
    }
}

impl NetworkSender for NativeSender {
    type Message = ConsensusMessage;
    async fn send(&self, message: ConsensusMessage, targets: Vec<NodeId>) {
        let bytes = match raptr::rehost::encode(&message, self.maximum_bytes) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        let accounting = if matches!(
            message,
            ConsensusMessage::FetchReq(_) | ConsensusMessage::FetchResp(_)
        ) {
            ByteAccounting::repair(bytes.len())
        } else {
            ByteAccounting::default()
        };
        for target in targets {
            if let Err(error) = self
                .bytes(
                    target,
                    Channel::Consensus,
                    bytes.clone(),
                    accounting.clone(),
                )
                .await
            {
                self.fail(error);
                return;
            }
        }
    }
    fn n_nodes(&self) -> usize {
        self.authors.len()
    }
}

struct RpcRemoval {
    pending: Arc<Mutex<BTreeMap<u64, Pending>>>,
    id: u64,
}
impl Drop for RpcRemoval {
    fn drop(&mut self) {
        self.pending.lock().unwrap().remove(&self.id);
    }
}

#[async_trait::async_trait]
impl NetworkTransport for NativeSender {
    async fn request_batch(
        &self,
        request: BatchRequest,
        recipient: Author,
        timeout: Duration,
    ) -> Result<BatchResponse> {
        let target = self.id(recipient)?;
        let request_digest = request.digest();
        let id = self
            .next_rpc
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| anyhow!("RPC sequence exhausted"))?;
        let (response, receive) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            ensure!(
                pending.len() < self.maximum_rpcs,
                "native RPC envelope exhausted"
            );
            pending.insert(
                id,
                Pending {
                    recipient,
                    response,
                },
            );
        }
        let _remove = RpcRemoval {
            pending: self.pending.clone(),
            id,
        };
        let witness = self
            .payload_fault
            .request_started(id, request_digest, recipient)?;
        let result = async {
            if let Err(error) = self.qs(QsWire::Request { id, request }, vec![target]).await {
                self.fail(&error);
                return Err(error);
            }
            let response = tokio::time::timeout(timeout, receive).await??;
            // The extracted native QS NetworkSender verifies BatchResponse::Batch
            // exactly once; Native BatchRequester verifies a NotFound proof.
            Ok(response)
        }
        .await;
        self.payload_fault.request_finished(witness, &result)?;
        result
    }
    async fn send_signed_batch_info_msg(
        &self,
        infos: Vec<SignedBatchInfo>,
        recipients: Vec<Author>,
    ) {
        let targets = recipients
            .into_iter()
            .map(|author| self.id(author))
            .collect::<Result<Vec<_>>>();
        match targets {
            Ok(targets) => {
                self.qs_or_fail(
                    QsWire::Message(QsMessage::SignedBatchInfo(SignedBatchInfoMsg::new(infos))),
                    targets,
                )
                .await
            }
            Err(error) => self.fail(error),
        }
    }
    async fn broadcast_batch_msg(&self, batches: Vec<Batch>) {
        self.qs_or_fail(
            QsWire::Message(QsMessage::Batch(BatchMsg::new(batches))),
            (0..self.authors.len()).collect(),
        )
        .await;
    }
    async fn broadcast_proof_of_store_msg(&self, proofs: Vec<ProofOfStore>) {
        self.qs_or_fail(
            QsWire::Message(QsMessage::Proof(ProofOfStoreMsg::new(proofs))),
            (0..self.authors.len()).collect(),
        )
        .await;
    }
    async fn send_proof_of_store_msg_to_self(&self, proofs: Vec<ProofOfStore>) {
        self.qs_or_fail(
            QsWire::Message(QsMessage::Proof(ProofOfStoreMsg::new(proofs))),
            vec![self.own_id],
        )
        .await;
    }
}

pub struct ConsensusInbox {
    sender: NativeSender,
    incoming: mpsc::Receiver<(ReceivedBytes<Channel>, ConsensusMessage)>,
}
impl NetworkSender for ConsensusInbox {
    type Message = ConsensusMessage;
    async fn send(&self, message: Self::Message, targets: Vec<NodeId>) {
        self.sender.send(message, targets).await;
    }
    fn n_nodes(&self) -> usize {
        self.sender.n_nodes()
    }
}
impl NetworkService for ConsensusInbox {
    type Sender = NativeSender;
    fn new_sender(&self) -> NativeSender {
        self.sender.clone()
    }
    async fn recv(&mut self) -> (NodeId, ConsensusMessage) {
        match self.incoming.recv().await {
            Some((leased, message)) => (leased.frame.from as usize, message),
            None => {
                self.sender.fail("consensus dispatcher ended");
                std::future::pending().await
            }
        }
    }
}

/// One bounded dispatch task retains the raw-frame byte lease while verifying.
/// Native QS keyed queues decide their own policy admission/drop behavior.
pub fn dispatch(
    mut incoming: Receiver,
    sender: NativeSender,
    verifier: Arc<Verifier>,
    qs: Inbound,
    capacity: usize,
) -> Result<(ConsensusInbox, JoinHandle<()>)> {
    ensure!(capacity > 0, "zero consensus inbox capacity");
    let (tx, rx) = mpsc::channel(capacity);
    let service = ConsensusInbox {
        sender: sender.clone(),
        incoming: rx,
    };
    let task = tokio::spawn(async move {
        let mut requests = tokio::task::JoinSet::new();
        loop {
            let leased = tokio::select! {
                received = incoming.recv() => match received { Ok(value) => value, Err(error) => { sender.fail(error); break; } },
                Some(result) = requests.join_next(), if !requests.is_empty() => {
                    if let Err(error) = result { sender.fail(error); break; }
                    continue;
                }
            };
            let from = leased.frame.from as usize;
            if from >= sender.authors.len() {
                sender.fail("authenticated sender outside committee");
                break;
            }
            match leased.frame.layer {
                Channel::Consensus => {
                    let message =
                        match raptr::rehost::decode(&leased.frame.payload, sender.maximum_bytes) {
                            Ok(message) => message,
                            Err(_) => continue,
                        };
                    if verifier.verify(from, &message).await.is_err() {
                        continue;
                    }
                    if tx.try_send((leased, message)).is_err() {
                        sender.fail("native consensus inbox envelope exhausted or closed");
                        break;
                    }
                }
                Channel::QuorumStore => {
                    let message = match shared_crypto_aptos::decode::<QsWire>(&leased.frame.payload)
                    {
                        Ok(message) => message,
                        Err(_) => continue,
                    };
                    let author = sender.authors[from];
                    match message {
                        QsWire::Message(message) => {
                            let message = match message {
                                QsMessage::Batch(batch) => {
                                    match sender.payload_fault.intercept(author, batch) {
                                        Ok(Some(batch)) => QsMessage::Batch(batch),
                                        Ok(None) => continue,
                                        Err(error) => {
                                            sender.fail(error);
                                            break;
                                        }
                                    }
                                }
                                other => other,
                            };
                            let result = if from == sender.own_id {
                                qs.receive_local(message)
                            } else {
                                qs.receive(author, message)
                            };
                            // Invalid peer payloads are rejected by the native verifier.
                            if result.is_err() {
                                sender.rejected.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        QsWire::Request { id, request } => {
                            if requests.len() >= sender.maximum_rpcs {
                                sender.fail("inbound native RPC envelope exhausted");
                                break;
                            }
                            let qs = qs.clone();
                            let sender = sender.clone();
                            requests.spawn(async move {
                                // Preserve native request validation and signed NotFound.
                                if let Ok(response) = qs.request_batch(author, request).await {
                                    sender
                                        .qs_or_fail(QsWire::Response { id, response }, vec![from])
                                        .await;
                                }
                                drop(leased);
                            });
                        }
                        QsWire::Response { id, response } => {
                            let mut pending = sender.pending.lock().unwrap();
                            if pending.get(&id).map(|value| value.recipient) == Some(author) {
                                if let Some(pending) = pending.remove(&id) {
                                    let _ = pending.response.send(response);
                                }
                            }
                        }
                    }
                }
            }
        }
        requests.abort_all();
        while requests.join_next().await.is_some() {}
    });
    Ok((service, task))
}
