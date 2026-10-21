//! Native Raptr manager's real Quorum Store integration, with explicit shared
//! application callbacks and bounded owned task lifetime. Native pull, prefix,
//! prefetch, repair, and commit-notification policies are preserved.
use crate::{
    network::NativeSender,
    output::{describe, Materializer},
};
use anyhow::{anyhow, Result};
use aptos_bitvec::BitVec;
use aptos_config::config::ConsensusConfig;
use aptos_consensus_types::{
    block::Block,
    common::{Author, Payload, PayloadFilter},
    payload::RaptrPayload,
    payload_pull_params::PayloadPullParameters,
    utils::PayloadTxnsSize,
};
use aptos_crypto::HashValue;
use aptos_types::transaction::SignedTransaction;
use futures::FutureExt;
use raptr::{
    framework::module_network::{match_event_type, ModuleId, ModuleNetworkService},
    raptr::{
        dissemination::{self, CommittedPayload, DisseminationLayer},
        types::{self, N_SUB_BLOCKS},
    },
};
use raptr_qs::{
    liveness::proposal_status_tracker::TOptQSPullParamsProvider,
    payload_client::user::UserPayloadClient, payload_manager::TPayloadManager,
};
use std::{
    collections::HashSet,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::task::JoinHandle;

#[async_trait::async_trait]
pub trait NativeCommitSink: Send + Sync {
    /// The native callbacks are allowed to arrive out of order; this preserves
    /// the pinned mempool notification effect. Application output is separate.
    async fn native_commit(&self, transactions: &[SignedTransaction]) -> Result<()>;
}

#[derive(Clone)]
pub struct OwnedTasks {
    registry: Arc<Mutex<TaskRegistry>>,
    maximum: usize,
    status: NativeSender,
}

#[derive(Default)]
struct TaskRegistry {
    closed: bool,
    handles: Vec<JoinHandle<()>>,
}

impl TaskRegistry {
    fn close(&mut self) -> Vec<JoinHandle<()>> {
        self.closed = true;
        std::mem::take(&mut self.handles)
    }
}

impl OwnedTasks {
    fn new(maximum: usize, status: NativeSender) -> Self {
        Self {
            registry: Arc::new(Mutex::new(TaskRegistry::default())),
            maximum,
            status,
        }
    }
    fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        let mut registry = self.registry.lock().unwrap();
        // Shutdown closes admission under the same lock used to start tasks.
        // A child finishing concurrently cannot escape the owned join set.
        if registry.closed {
            return;
        }
        if registry.handles.len() >= self.maximum {
            self.status.fail("native task lifetime envelope exhausted");
            return;
        }
        registry.handles.push(tokio::spawn(future));
    }
    /// Call only after the declared drain; unresolved work remains explicit in
    /// the output snapshot. Every task is then aborted and reaped.
    pub async fn shutdown(self) -> Result<()> {
        let handles = self.registry.lock().unwrap().close();
        abort_and_reap(handles).await
    }
}

async fn abort_and_reap(handles: Vec<JoinHandle<()>>) -> Result<()> {
    for handle in &handles {
        handle.abort();
    }
    let mut first_error = None;
    for handle in handles {
        match handle.await {
            Ok(()) => {}
            Err(error) if error.is_cancelled() => {}
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error.into()),
        None => Ok(()),
    }
}

pub struct NativeDissemination {
    epoch: u64,
    node_id: usize,
    payload_client: Arc<dyn UserPayloadClient>,
    config: ConsensusConfig,
    payload_manager: Arc<dyn TPayloadManager>,
    module_id: ModuleId,
    provider: Arc<dyn TOptQSPullParamsProvider>,
    authors: Arc<Vec<Author>>,
    status: NativeSender,
    materializer: Materializer,
    sink: Arc<dyn NativeCommitSink>,
    tasks: OwnedTasks,
    materialization_delay: Duration,
}

impl NativeDissemination {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        epoch: u64,
        node_id: usize,
        authors: Vec<Author>,
        config: ConsensusConfig,
        payload_client: Arc<dyn UserPayloadClient>,
        payload_manager: Arc<dyn TPayloadManager>,
        provider: Arc<dyn TOptQSPullParamsProvider>,
        mut module_network: ModuleNetworkService,
        status: NativeSender,
        materializer: Materializer,
        sink: Arc<dyn NativeCommitSink>,
        maximum_tasks: usize,
        materialization_delay: Duration,
    ) -> Result<(Self, OwnedTasks)> {
        anyhow::ensure!(
            node_id < authors.len() && maximum_tasks > 0,
            "invalid dissemination identity/task bound"
        );
        let authors = Arc::new(authors);
        let tasks = OwnedTasks::new(maximum_tasks, status.clone());
        let module_id = module_network.module_id();
        let round_initial_timeout = Duration::from_millis(config.round_initial_timeout_ms);
        let module_payload_manager = payload_manager.clone();
        let module_authors = authors.clone();
        let module_tasks = tasks.clone();
        let module_status = status.clone();
        tasks.spawn(async move {
            loop {
                let (consensus_module, event) = module_network.recv().await;
                if match_event_type::<dissemination::ProposalReceived>(&event) {
                    let event = event
                        .as_any()
                        .downcast::<dissemination::ProposalReceived>()
                        .ok()
                        .unwrap();
                    let dissemination::ProposalReceived { round, payload, .. } = *event;
                    let block_author = module_authors.get(payload.author()).copied();
                    let module_sender = module_network.new_sender();
                    let manager = module_payload_manager.clone();
                    module_tasks.spawn(async move {
                        let (prefix, _) =
                            manager.available_prefix(payload.inner.as_raptr_payload(), 0);
                        if prefix == N_SUB_BLOCKS {
                            module_sender
                                .notify(
                                    consensus_module,
                                    dissemination::FullBlockAvailable { round },
                                )
                                .await;
                        } else if manager
                            .wait_for_payload(
                                &payload.inner,
                                block_author,
                                0,
                                round_initial_timeout,
                                false,
                            )
                            .await
                            .is_ok()
                        {
                            module_sender
                                .notify(
                                    consensus_module,
                                    dissemination::FullBlockAvailable { round },
                                )
                                .await;
                        }
                        // Pinned prototype uses timestamp0: expiry is not inferred
                        // from the local output observer or wall-clock age here.
                        manager.prefetch_payload_data(
                            &payload.inner,
                            block_author.unwrap(),
                            0,
                            None,
                        );
                    });
                } else if match_event_type::<dissemination::NewQCWithPayload>(&event) {
                    let event = event
                        .as_any()
                        .downcast::<dissemination::NewQCWithPayload>()
                        .ok()
                        .unwrap();
                    let dissemination::NewQCWithPayload { payload, qc } = *event;
                    let author = module_authors[payload.author()];
                    let voters: BitVec = qc.signer_ids().map(|id| id as u8).collect();
                    module_payload_manager.prefetch_payload_data(
                        &payload.inner,
                        author,
                        0,
                        Some(voters),
                    );
                } else if match_event_type::<dissemination::Kill>(&event) {
                    break;
                } else {
                    module_status.fail("unhandled native dissemination module event");
                    break;
                }
            }
        });
        Ok((
            Self {
                epoch,
                node_id,
                payload_client,
                config,
                payload_manager,
                module_id,
                provider,
                authors,
                status,
                materializer,
                sink,
                tasks: tasks.clone(),
                materialization_delay,
            },
            tasks,
        ))
    }
}

impl DisseminationLayer for NativeDissemination {
    fn module_id(&self) -> ModuleId {
        self.module_id
    }
    async fn prepare_block(
        &self,
        round: types::Round,
        exclude: HashSet<types::BatchInfo>,
        exclude_authors: Option<BitVec>,
    ) -> types::Payload {
        let mut optqs = self.provider.get_params();
        if let Some(parameters) = optqs.as_mut() {
            if let Some(excluded) = exclude_authors {
                for index in excluded.iter_ones() {
                    parameters.exclude_authors.insert(self.authors[index]);
                }
            }
        }
        let payload = self
            .payload_client
            .pull(
                PayloadPullParameters {
                    max_poll_time: Duration::from_millis(self.config.quorum_store_poll_time_ms),
                    max_txns: PayloadTxnsSize::new(
                        self.config.max_sending_block_txns,
                        self.config.max_sending_block_bytes,
                    ),
                    max_txns_after_filtering: self.config.max_sending_block_txns,
                    soft_max_txns_after_filtering: self.config.max_sending_block_txns,
                    max_inline_txns: PayloadTxnsSize::new(
                        self.config.max_sending_inline_txns,
                        self.config.max_sending_inline_bytes,
                    ),
                    user_txn_filter: PayloadFilter::InQuorumStore(exclude),
                    pending_ordering: true,
                    pending_uncommitted_blocks: 0,
                    recent_max_fill_fraction: 0.0,
                    block_timestamp: aptos_infallible::duration_since_epoch(),
                    maybe_optqs_payload_pull_params: optqs,
                },
                async {}.boxed(),
            )
            .await
            .unwrap_or_else(|_| Payload::Raptr(RaptrPayload::new_empty()));
        types::Payload::new(round, self.node_id, payload)
    }
    async fn available_prefix(
        &self,
        payload: &types::Payload,
        cached: types::Prefix,
    ) -> (types::Prefix, BitVec) {
        self.payload_manager
            .available_prefix(payload.inner.as_raptr_payload(), cached)
    }
    async fn notify_commit(&self, _: Vec<types::Payload>, _: u64, _: Option<BitVec>) {
        self.status
            .fail("native application requires identified commit metadata");
    }
    async fn notify_commit_identified(
        &self,
        payloads: Vec<CommittedPayload>,
        _: u64,
        voters: Option<BitVec>,
    ) {
        // Reservations are synchronous in the core's original commit order.
        let mut reservations = Vec::with_capacity(payloads.len());
        for payload in &payloads {
            let reservation = describe(self.epoch, &self.authors, payload)
                .and_then(|slice| self.materializer.reserve(slice));
            match reservation {
                Ok(value) => reservations.push(Some(value)),
                Err(error) => {
                    self.status.fail(error);
                    reservations.push(None);
                }
            }
        }
        let manager = self.payload_manager.clone();
        let materializer = self.materializer.clone();
        let sink = self.sink.clone();
        let status = self.status.clone();
        let tasks = self.tasks.clone();
        let materialization_delay = self.materialization_delay;
        self.tasks.spawn(async move {
            let payloads: Vec<_> = payloads
                .into_iter()
                .map(|value| value.payload.inner)
                .collect();
            manager.notify_commit(
                aptos_infallible::duration_since_epoch()
                    .saturating_sub(Duration::from_secs(1))
                    .as_micros() as u64,
                payloads.clone(),
            );
            for (payload, reservation) in payloads.into_iter().zip(reservations) {
                let count = payload.as_raptr_payload().num_txns();
                let block = Block::new_for_dag(
                    0,
                    0,
                    0,
                    Vec::new(),
                    payload,
                    Author::ZERO,
                    Vec::new(),
                    HashValue::zero(),
                    BitVec::with_num_bits(8),
                    Vec::new(),
                );
                let manager = manager.clone();
                let materializer = materializer.clone();
                let sink = sink.clone();
                let status = status.clone();
                let voters = voters.clone();
                tasks.spawn(async move {
                    let result: Result<()> = async {
                        let (transactions, _) = manager
                            .get_transactions(&block, voters)
                            .await
                            .map_err(|error| anyhow!("native payload retrieval: {error:?}"))?;
                        anyhow::ensure!(
                            transactions.len() == count,
                            "native fetch transaction count mismatch"
                        );
                        // Preserve native unordered commit notifications before
                        // the added application materializer publishes its FIFO.
                        sink.native_commit(&transactions).await?;
                        // Explicit application-only control; native fetch, custody,
                        // votes and pool notifications remain unchanged.
                        if !materialization_delay.is_zero() {
                            materializer.delay_started(transactions.len())?;
                            tokio::time::sleep(materialization_delay).await;
                            materializer.delay_finished(transactions.len())?;
                        }
                        if let Some(reservation) = reservation {
                            materializer.resolve(reservation, transactions)?;
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        status.fail(error);
                    }
                });
            }
        });
    }
    fn check_payload(&self, payload: &types::Payload) -> Result<(), BitVec> {
        self.payload_manager
            .check_payload_availability(&payload.inner)
    }
    async fn set_first_committed_block_timestamp(&self, _: SystemTime) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[tokio::test]
    async fn shutdown_closes_registry_and_reaps_later_tasks_after_a_panic() {
        let dropped = Arc::new(AtomicUsize::new(0));
        let (ready, mut starts) = tokio::sync::mpsc::channel(2);
        let mut registry = TaskRegistry::default();
        for panic in [true, false] {
            let dropped = dropped.clone();
            let ready = ready.clone();
            registry.handles.push(tokio::spawn(async move {
                let _drop = Dropped(dropped);
                ready.send(()).await.unwrap();
                if panic {
                    panic!("owned lifecycle test panic");
                }
                std::future::pending::<()>().await;
            }));
        }
        starts.recv().await.unwrap();
        starts.recv().await.unwrap();
        let handles = registry.close();
        assert!(registry.closed && registry.handles.is_empty());
        assert!(abort_and_reap(handles).await.is_err());
        assert_eq!(dropped.load(Ordering::SeqCst), 2);
        assert!(registry.close().is_empty());
    }
}
