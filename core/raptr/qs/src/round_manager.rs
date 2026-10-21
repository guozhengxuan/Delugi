//! The native QS-only verified-event boundary, without the consensus round manager.
use crate::quorum_store::types::BatchMsg;
use aptos_consensus_types::proof_of_store::{ProofOfStoreMsg,SignedBatchInfoMsg};
#[derive(Debug)]
pub(crate) enum VerifiedEvent { Shutdown(tokio::sync::oneshot::Sender<()>), SignedBatchInfo(Box<SignedBatchInfoMsg>), BatchMsg(Box<BatchMsg>), ProofOfStoreMsg(Box<ProofOfStoreMsg>) }
