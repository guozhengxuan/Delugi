// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0
//! Native payload metadata constructors used by QS resolution. The upstream
//! consensus-observer publishing call is disabled at the pinned revision.
use aptos_consensus_types::proof_of_store::{BatchInfo,ProofOfStore};
use aptos_types::transaction::SignedTransaction;
use serde::{Serialize,Deserialize};
/// The transaction payload and proof of each block
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadWithProof {
    transactions: Vec<SignedTransaction>,
    proofs: Vec<ProofOfStore>,
}

impl PayloadWithProof {
    pub fn new(transactions: Vec<SignedTransaction>, proofs: Vec<ProofOfStore>) -> Self {
        Self {
            transactions,
            proofs,
        }
    }

    #[cfg(test)]
    /// Returns an empty payload with proof (for testing)
    pub fn empty() -> Self {
        Self {
            transactions: vec![],
            proofs: vec![],
        }
    }
}

/// The transaction payload and proof of each block with a transaction limit
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PayloadWithProofAndLimit {
    payload_with_proof: PayloadWithProof,
    transaction_limit: Option<u64>,
}

impl PayloadWithProofAndLimit {
    pub fn new(payload_with_proof: PayloadWithProof, limit: Option<u64>) -> Self {
        Self {
            payload_with_proof,
            transaction_limit: limit,
        }
    }

    #[cfg(test)]
    /// Returns an empty payload with proof and limit (for testing)
    pub fn empty() -> Self {
        Self {
            payload_with_proof: PayloadWithProof::empty(),
            transaction_limit: None,
        }
    }
}

/// The transaction payload of each block
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum BlockTransactionPayload {
    InQuorumStore(PayloadWithProof),
    InQuorumStoreWithLimit(PayloadWithProofAndLimit),
    QuorumStoreInlineHybrid(PayloadWithProofAndLimit, Vec<BatchInfo>),
    OptQuorumStore(
        PayloadWithProofAndLimit,
        /* OptQS and Inline Batches */ Vec<BatchInfo>,
    ),
    Raikou(PayloadWithProofAndLimit, Vec<BatchInfo>),
}

impl BlockTransactionPayload {
    /// Creates a returns a new InQuorumStore transaction payload
    pub fn new_in_quorum_store(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore>,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        Self::InQuorumStore(payload_with_proof)
    }

    /// Creates a returns a new InQuorumStoreWithLimit transaction payload
    pub fn new_in_quorum_store_with_limit(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore>,
        limit: Option<u64>,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        let proof_with_limit = PayloadWithProofAndLimit::new(payload_with_proof, limit);
        Self::InQuorumStoreWithLimit(proof_with_limit)
    }

    /// Creates a returns a new QuorumStoreInlineHybrid transaction payload
    pub fn new_quorum_store_inline_hybrid(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore>,
        limit: Option<u64>,
        inline_batches: Vec<BatchInfo>,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        let proof_with_limit = PayloadWithProofAndLimit::new(payload_with_proof, limit);
        Self::QuorumStoreInlineHybrid(proof_with_limit, inline_batches)
    }

    pub fn new_opt_quorum_store(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore>,
        limit: Option<u64>,
        batch_infos: Vec<BatchInfo>,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        let proof_with_limit = PayloadWithProofAndLimit::new(payload_with_proof, limit);
        Self::OptQuorumStore(proof_with_limit, batch_infos)
    }

    pub fn new_raikou_payload(
        transactions: Vec<SignedTransaction>,
        proofs: Vec<ProofOfStore>,
        batch_infos: Vec<BatchInfo>,
    ) -> Self {
        let payload_with_proof = PayloadWithProof::new(transactions, proofs);
        let proof_with_limit = PayloadWithProofAndLimit::new(payload_with_proof, None);
        Self::Raikou(proof_with_limit, batch_infos)
    }

    #[cfg(test)]
    /// Returns an empty transaction payload (for testing)
    pub fn empty() -> Self {
        Self::QuorumStoreInlineHybrid(PayloadWithProofAndLimit::empty(), vec![])
    }

    /// Returns the list of inline batches and optimistic batches in the transaction payload
    pub fn optqs_and_inline_batches(&self) -> &[BatchInfo] {
        match self {
            BlockTransactionPayload::QuorumStoreInlineHybrid(_, inline_batches) => inline_batches,
            BlockTransactionPayload::OptQuorumStore(_, optqs_and_inline_batches) => {
                optqs_and_inline_batches
            },
            _ => &[],
        }
    }

    /// Returns the limit of the transaction payload
    pub fn limit(&self) -> Option<u64> {
        match self {
            BlockTransactionPayload::InQuorumStore(_) => None,
            BlockTransactionPayload::InQuorumStoreWithLimit(payload) => payload.transaction_limit,
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.transaction_limit
            },
            BlockTransactionPayload::OptQuorumStore(payload, _) => payload.transaction_limit,
            BlockTransactionPayload::Raikou(payload_with_proof_and_limit, vec) => None,
        }
    }

    /// Returns the proofs of the transaction payload
    pub fn payload_proofs(&self) -> Vec<ProofOfStore> {
        match self {
            BlockTransactionPayload::InQuorumStore(payload) => payload.proofs.clone(),
            BlockTransactionPayload::InQuorumStoreWithLimit(payload) => {
                payload.payload_with_proof.proofs.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.payload_with_proof.proofs.clone()
            },
            BlockTransactionPayload::OptQuorumStore(payload, _) => {
                payload.payload_with_proof.proofs.clone()
            },
            BlockTransactionPayload::Raikou(payload, vec) => {
                payload.payload_with_proof.proofs.clone()
            },
        }
    }

    /// Returns the transactions in the payload
    pub fn transactions(&self) -> Vec<SignedTransaction> {
        match self {
            BlockTransactionPayload::InQuorumStore(payload) => payload.transactions.clone(),
            BlockTransactionPayload::InQuorumStoreWithLimit(payload) => {
                payload.payload_with_proof.transactions.clone()
            },
            BlockTransactionPayload::QuorumStoreInlineHybrid(payload, _) => {
                payload.payload_with_proof.transactions.clone()
            },
            BlockTransactionPayload::OptQuorumStore(payload, _) => {
                payload.payload_with_proof.transactions.clone()
            },
            BlockTransactionPayload::Raikou(payload, vec) => {
                payload.payload_with_proof.transactions.clone()
            },
        }
    }

}
