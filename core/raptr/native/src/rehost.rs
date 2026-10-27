//! Assembly around the pinned native protocol, not a second protocol loop.
//!
//! This module deliberately accepts the real `DisseminationLayer` and native
//! validator membership. Transport authentication is additional to, and never a
//! replacement for, the original native message verifier.
use crate::{
    framework::{
        crypto::{SignatureVerifier, Signer},
        network::{MessageVerifier, NetworkSender, NetworkService},
        NodeId,
    },
    raptr::{
        dissemination::DisseminationLayer, types::N_SUB_BLOCKS, Config, Message, Metrics,
        RaptrNode, TRaptrFailureTracker, Verifier,
    },
};
use anyhow::{ensure, Context, Result};
use aptos_consensus_types::proof_of_store::ProofCache;
use aptos_types::{validator_signer::ValidatorSigner, validator_verifier::ValidatorVerifier};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::Mutex, time::Instant};

/// The native verifier determines indices; no adapter-specific author sorting.
pub struct CommitteeKeys {
    pub id: NodeId,
    pub signer: Signer,
    pub verifier: SignatureVerifier,
    pub committee: Arc<ValidatorVerifier>,
}

impl CommitteeKeys {
    pub fn new(signer: Arc<ValidatorSigner>, committee: Arc<ValidatorVerifier>) -> Result<Self> {
        let indices = committee.address_to_validator_index();
        let id = *indices
            .get(&signer.author())
            .context("local author absent from committee")?;
        ensure!(
            committee.get_public_key(&signer.author()) == Some(signer.public_key()),
            "local signer key does not match committee"
        );
        let mut public_keys = vec![None; committee.len()];
        for (author, &index) in indices {
            ensure!(
                index < public_keys.len(),
                "native validator index outside committee"
            );
            ensure!(
                public_keys[index].is_none(),
                "duplicate native validator index"
            );
            public_keys[index] = committee.get_public_key(author);
        }
        let public_keys = public_keys
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .context("native validator indices are not contiguous")?;
        Ok(Self {
            id,
            signer: Signer::new(signer, id, N_SUB_BLOCKS + 1),
            verifier: SignatureVerifier::new(public_keys, committee.clone(), N_SUB_BLOCKS + 1),
            committee,
        })
    }
}

/// Copies the enabled Raptr manager configuration at the pinned artifact.
/// `delta` is the native configured delay bound, not injected network latency.
pub fn native_config(n_nodes: usize, delta: Duration, end_of_run: Instant) -> Result<Config> {
    ensure!(n_nodes > 0, "empty committee");
    ensure!(!delta.is_zero(), "zero native delay bound");
    let f = (n_nodes - 1) / 3;
    Ok(Config {
        n_nodes,
        f,
        // Match the native validator verifier's strict two-thirds voting power.
        // At n=50 the former 2f+1 shortcut is 33, but QS certificates require 34.
        poa_quorum: 2 * n_nodes / 3 + 1,
        storage_requirement: f + 1,
        leader_timeout: delta * 4,
        delta,
        end_of_run,
        extra_wait_before_qc_vote: delta.mul_f64(0.1),
        enable_partial_qc_votes: true,
        enable_commit_votes: true,
        status_interval: delta * 10,
        round_sync_interval: delta * 15,
        block_fetch_multiplicity: 2.min(n_nodes),
        block_fetch_interval: delta * 2,
    })
}

pub struct Core<DL> {
    pub id: NodeId,
    pub node: Arc<Mutex<RaptrNode<DL>>>,
    pub verifier: Arc<Verifier>,
}

pub fn build_core<DL: DisseminationLayer>(
    config: Config,
    keys: CommitteeKeys,
    dissemination: DL,
    proof_cache: ProofCache,
    metrics: Metrics,
    detailed_logging: bool,
    failure_tracker: Option<Arc<dyn TRaptrFailureTracker>>,
) -> Result<Core<DL>> {
    ensure!(
        config.n_nodes == keys.committee.len(),
        "configuration/committee size mismatch"
    );
    ensure!(
        config.f == (config.n_nodes - 1) / 3,
        "non-native fault threshold"
    );
    ensure!(
        config.block_fetch_multiplicity <= config.quorum(),
        "fetch multiplicity exceeds quorum"
    );
    let id = keys.id;
    let node = RaptrNode::new(
        id,
        config,
        dissemination,
        detailed_logging,
        metrics,
        keys.signer,
        keys.verifier,
        failure_tracker,
    );
    let verifier = Arc::new(Verifier::new(&node, proof_cache));
    Ok(Core {
        id,
        node: Arc::new(Mutex::new(node)),
        verifier,
    })
}

/// Exact native BCS; callers supply the common transport's admitted frame limit.
pub fn encode(message: &Message, maximum_bytes: usize) -> Result<Vec<u8>> {
    let bytes = shared_crypto_aptos::encode(message)?;
    ensure!(
        bytes.len() <= maximum_bytes,
        "native message exceeds transport frame limit"
    );
    Ok(bytes)
}

pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Message> {
    ensure!(
        bytes.len() <= maximum_bytes,
        "native message exceeds transport frame limit"
    );
    Ok(shared_crypto_aptos::decode(bytes)?)
}

/// Invalid native messages are dropped before the original event loop sees them.
/// Peer identities must already be authenticated by the underlying transport.
pub struct VerifiedNetwork<N> {
    inner: N,
    verifier: Arc<Verifier>,
    rejected: Arc<AtomicU64>,
}

impl<N: NetworkService<Message = Message>> VerifiedNetwork<N> {
    pub fn new(inner: N, verifier: Arc<Verifier>) -> Result<Self> {
        ensure!(
            inner.n_nodes() == verifier.config.n_nodes,
            "transport/committee size mismatch"
        );
        Ok(Self {
            inner,
            verifier,
            rejected: Arc::new(AtomicU64::new(0)),
        })
    }
    pub fn rejected_counter(&self) -> Arc<AtomicU64> {
        self.rejected.clone()
    }
}

impl<N: NetworkService<Message = Message>> NetworkSender for VerifiedNetwork<N> {
    type Message = Message;
    async fn send(&self, message: Message, targets: Vec<NodeId>) {
        self.inner.send(message, targets).await;
    }
    fn n_nodes(&self) -> usize {
        self.inner.n_nodes()
    }
}

impl<N: NetworkService<Message = Message>> NetworkService for VerifiedNetwork<N> {
    type Sender = N::Sender;
    fn new_sender(&self) -> Self::Sender {
        self.inner.new_sender()
    }
    async fn recv(&mut self) -> (NodeId, Message) {
        loop {
            let (sender, message) = self.inner.recv().await;
            if sender < self.verifier.config.n_nodes
                && self.verifier.verify(sender, &message).await.is_ok()
            {
                return (sender, message);
            }
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests;
