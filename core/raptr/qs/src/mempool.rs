//! Exact native QS/mempool channel boundary; no Aptos mempool engine.
use anyhow::Result;
use aptos_consensus_types::common::{RejectedTransactionSummary,TransactionInProgress,TransactionSummary};
use aptos_types::transaction::SignedTransaction;
use futures::channel::oneshot;
use std::{collections::BTreeMap,fmt};
/// Message sent from QuorumStore to Mempool.
pub enum QuorumStoreRequest {
    GetBatchRequest(
        // max batch size
        u64,
        // max byte size
        u64,
        // return non full
        bool,
        // transactions to exclude from the requested batch
        BTreeMap<TransactionSummary, TransactionInProgress>,
        // callback to respond to
        oneshot::Sender<Result<QuorumStoreResponse>>,
    ),
    // TODO: Do we use it in the real QS as well?
    /// Notifications about *rejected* committed txns.
    RejectNotification(
        // rejected transactions from consensus
        Vec<RejectedTransactionSummary>,
        // callback to respond to
        oneshot::Sender<Result<QuorumStoreResponse>>,
    ),
}

impl fmt::Display for QuorumStoreRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let payload = match self {
            QuorumStoreRequest::GetBatchRequest(
                max_txns,
                max_bytes,
                return_non_full,
                excluded_txns,
                _,
            ) => {
                format!(
                    "GetBatchRequest [max_txns: {}, max_bytes: {}, return_non_full: {}, excluded_txns_length: {}]",
                    max_txns,
                    max_bytes,
                    return_non_full,
                    excluded_txns.len()
                )
            },
            QuorumStoreRequest::RejectNotification(rejected_txns, _) => {
                format!(
                    "RejectNotification [rejected_txns_length: {}]",
                    rejected_txns.len()
                )
            },
        };
        write!(f, "{}", payload)
    }
}

/// Response sent from mempool to consensus.
#[derive(Debug)]
pub enum QuorumStoreResponse {
    /// Block to submit to consensus
    GetBatchResponse(Vec<SignedTransaction>),
    CommitResponse(),
}

