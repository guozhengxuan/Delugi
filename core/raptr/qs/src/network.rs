//! Byte transport is supplied by the shared node. All native QS message types,
//! destination selection, retry deadlines and permission to send stay in QS.
use crate::quorum_store::types::{Batch, BatchRequest, BatchResponse};
use aptos_consensus_types::{
    common::Author,
    proof_of_store::{ProofOfStore, SignedBatchInfo},
};
use std::{sync::Arc, time::Duration};

#[async_trait::async_trait]
pub trait QuorumStoreSender: Send + Clone {
    async fn request_batch(
        &self,
        request: BatchRequest,
        recipient: Author,
        timeout: Duration,
    ) -> anyhow::Result<BatchResponse>;
    async fn send_signed_batch_info_msg(
        &self,
        signed_batch_infos: Vec<SignedBatchInfo>,
        recipients: Vec<Author>,
    );
    async fn broadcast_batch_msg(&mut self, batches: Vec<Batch>);
    async fn broadcast_proof_of_store_msg(&mut self, proof_of_stores: Vec<ProofOfStore>);
    async fn send_proof_of_store_msg_to_self(&mut self, proof_of_stores: Vec<ProofOfStore>);
}

/// Object-safe service boundary corresponding exactly to native QS operations.
/// Implementations must deliver the self-send through the same verified inbound
/// boundary; transport acceptance is never a proof or custody acknowledgement.
#[async_trait::async_trait]
pub trait NetworkTransport: Send + Sync {
    async fn request_batch(
        &self,
        request: BatchRequest,
        recipient: Author,
        timeout: Duration,
    ) -> anyhow::Result<BatchResponse>;
    async fn send_signed_batch_info_msg(
        &self,
        signed_batch_infos: Vec<SignedBatchInfo>,
        recipients: Vec<Author>,
    );
    async fn broadcast_batch_msg(&self, batches: Vec<Batch>);
    async fn broadcast_proof_of_store_msg(&self, proof_of_stores: Vec<ProofOfStore>);
    async fn send_proof_of_store_msg_to_self(&self, proof_of_stores: Vec<ProofOfStore>);
}

#[derive(Clone)]
pub struct NetworkSender(Arc<dyn NetworkTransport>);
impl NetworkSender {
    pub fn new(transport: Arc<dyn NetworkTransport>) -> Self {
        Self(transport)
    }
}
#[async_trait::async_trait]
impl QuorumStoreSender for NetworkSender {
    async fn request_batch(
        &self,
        request: BatchRequest,
        recipient: Author,
        timeout: Duration,
    ) -> anyhow::Result<BatchResponse> {
        // The pinned native NetworkSender performs this check before handing
        // the response to BatchRequester. The shared byte transport cannot own
        // this native digest/content policy.
        let requested_digest = request.digest();
        let response = self.0.request_batch(request, recipient, timeout).await?;
        if let BatchResponse::Batch(batch) = &response {
            shared_crypto_aptos::native_validation(|| batch.verify_with_digest(requested_digest))?;
        }
        // Native signed NotFound ledger evidence is checked by BatchRequester
        // only when it would short-circuit an expired request.
        Ok(response)
    }
    async fn send_signed_batch_info_msg(
        &self,
        signed_batch_infos: Vec<SignedBatchInfo>,
        recipients: Vec<Author>,
    ) {
        fail::fail_point!("consensus::send::signed_batch_info", |_| ());
        self.0
            .send_signed_batch_info_msg(signed_batch_infos, recipients)
            .await
    }
    async fn broadcast_batch_msg(&mut self, batches: Vec<Batch>) {
        fail::fail_point!("consensus::send::broadcast_batch", |_| ());
        self.0.broadcast_batch_msg(batches).await
    }
    async fn broadcast_proof_of_store_msg(&mut self, proof_of_stores: Vec<ProofOfStore>) {
        fail::fail_point!("consensus::send::proof_of_store", |_| ());
        self.0.broadcast_proof_of_store_msg(proof_of_stores).await
    }
    async fn send_proof_of_store_msg_to_self(&mut self, proof_of_stores: Vec<ProofOfStore>) {
        fail::fail_point!("consensus::send::proof_of_store", |_| ());
        self.0
            .send_proof_of_store_msg_to_self(proof_of_stores)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Reply(BatchResponse);
    #[async_trait::async_trait]
    impl NetworkTransport for Reply {
        async fn request_batch(
            &self,
            _: BatchRequest,
            _: Author,
            _: Duration,
        ) -> anyhow::Result<BatchResponse> {
            Ok(self.0.clone())
        }
        async fn send_signed_batch_info_msg(&self, _: Vec<SignedBatchInfo>, _: Vec<Author>) {
            unreachable!()
        }
        async fn broadcast_batch_msg(&self, _: Vec<Batch>) {
            unreachable!()
        }
        async fn broadcast_proof_of_store_msg(&self, _: Vec<ProofOfStore>) {
            unreachable!()
        }
        async fn send_proof_of_store_msg_to_self(&self, _: Vec<ProofOfStore>) {
            unreachable!()
        }
    }
    #[tokio::test]
    async fn untrusted_fetch_must_match_requested_native_digest() {
        use aptos_consensus_types::proof_of_store::BatchId;
        use aptos_crypto::HashValue;
        let batch = Batch::new(
            BatchId::new_for_test(1),
            crate::test_utils::create_vec_signed_transactions(1),
            1,
            1000,
            Author::ZERO,
            0,
        );
        let digest = *batch.batch_info().digest();
        let network = NetworkSender::new(Arc::new(Reply(BatchResponse::Batch(batch))));
        assert!(network
            .request_batch(
                BatchRequest::new(Author::ZERO, 1, HashValue::random()),
                Author::ZERO,
                Duration::from_secs(1)
            )
            .await
            .is_err());
        assert!(network
            .request_batch(
                BatchRequest::new(Author::ZERO, 1, digest),
                Author::ZERO,
                Duration::from_secs(1)
            )
            .await
            .is_ok());
    }
}
