//! Canonical application output from real native commit metadata and fetches.
use anyhow::{anyhow, Result};
use aptos_consensus_types::common::{Author, BatchPayload};
use aptos_crypto::hash::CryptoHash;
use aptos_types::{account_address::AccountAddress, transaction::SignedTransaction};
use delugi_raptr_core::{
    self as output, BatchPayloadVerifier, CommitSlice, OutputContract, PublishedSection,
    Reservation,
};
use raptr::raptr::dissemination::CommittedPayload;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub fn describe(
    epoch: u64,
    authors: &[Author],
    committed: &CommittedPayload,
) -> Result<CommitSlice> {
    let payload = &committed.payload;
    let author = authors
        .get(payload.author())
        .ok_or_else(|| anyhow!("committed author outside committee"))?;
    let batch =
        |batch: &aptos_consensus_types::proof_of_store::BatchInfo| -> Result<output::BatchInfo> {
            Ok(
                output::BatchInfo::from_native_bcs(&shared_crypto_aptos::encode(batch)?)
                    .map_err(|error| anyhow!("native BatchInfo compatibility: {error:?}"))?,
            )
        };
    Ok(CommitSlice {
        block: output::BlockId {
            epoch,
            digest: *committed.block_digest.as_ref(),
            round: payload.round(),
            author: author.into_bytes(),
        },
        include_proofs: committed.include_proofs,
        proofs: payload
            .poas()
            .iter()
            .map(|proof| batch(proof.info()))
            .collect::<Result<_>>()?,
        sub_blocks: payload
            .inner
            .as_raptr_payload()
            .numbered_sub_blocks()
            .map(|(index, pointer)| {
                Ok((
                    index,
                    pointer
                        .batch_summary
                        .iter()
                        .map(batch)
                        .collect::<Result<_>>()?,
                ))
            })
            .collect::<Result<_>>()?,
    })
}

pub struct NativeBatchVerifier;
impl BatchPayloadVerifier<SignedTransaction> for NativeBatchVerifier {
    fn inspect(
        &self,
        author: &[u8; 32],
        transactions: &[SignedTransaction],
    ) -> Result<output::PayloadFacts, output::Error> {
        // A BCS struct is its fields in declaration order. The borrowed tuple is
        // exactly BatchPayload { author, txns }; the native OnceCell is skipped.
        // This avoids cloning SignedTransaction objects solely to validate them.
        let bytes = shared_crypto_aptos::encode(&(AccountAddress::new(*author), transactions))
            .map_err(|_| output::Error::VerificationFailed)?;
        let digest =
            shared_crypto_aptos::hash_encoded::<<BatchPayload as CryptoHash>::Hasher>(&bytes);
        Ok(output::PayloadFacts {
            digest: *digest.as_ref(),
            num_txns: transactions.len() as u64,
            num_bytes: bytes.len() as u64,
        })
    }
}

#[derive(Clone)]
pub struct Materializer {
    inner: Arc<Mutex<OutputContract<SignedTransaction>>>,
    published: mpsc::Sender<PublishedSection<SignedTransaction>>,
    delay: Arc<Mutex<DelayTelemetry>>,
}

#[derive(Clone, Default, serde::Serialize)]
pub struct DelayTelemetry {
    pub delay_started_count: u64,
    pub delay_finished_count: u64,
    pub delayed_transactions_started: u64,
    pub delayed_transactions_finished: u64,
    pub first_delay_start_us: Option<u64>,
    pub first_delay_finish_us: Option<u64>,
    pub late_resolutions_discarded: u64,
    pub late_transactions_discarded: u64,
}
impl Materializer {
    pub fn new(
        limits: output::Limits,
        output_capacity: usize,
    ) -> (Self, mpsc::Receiver<PublishedSection<SignedTransaction>>) {
        let (published, receiver) = mpsc::channel(output_capacity);
        (
            Self {
                inner: Arc::new(Mutex::new(OutputContract::new(limits))),
                published,
                delay: Arc::new(Mutex::new(DelayTelemetry::default())),
            },
            receiver,
        )
    }
    pub fn reserve(&self, slice: CommitSlice) -> Result<Reservation> {
        self.inner
            .lock()
            .unwrap()
            .reserve(slice)
            .map_err(|error| anyhow!("native output reservation: {error:?}"))
    }
    pub fn resolve(
        &self,
        reservation: Reservation,
        transactions: Vec<SignedTransaction>,
    ) -> Result<()> {
        if reservation.duplicate {
            return Ok(());
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.snapshot().frozen {
            let mut telemetry = self.delay.lock().unwrap();
            telemetry.late_resolutions_discarded += 1;
            telemetry.late_transactions_discarded += transactions.len() as u64;
            return Ok(());
        }
        inner
            .resolve_native_fetch(reservation.ticket, transactions, &NativeBatchVerifier)
            .map_err(|error| anyhow!("native output payload validation: {error:?}"))?;
        // Serialize publication under the same lock as FIFO release. Concurrent
        // fetch completions must not reverse two already-ready output groups.
        for section in inner.take_ready() {
            self.published
                .try_send(section)
                .map_err(|_| anyhow!("application output envelope exhausted or closed"))?;
        }
        Ok(())
    }
    pub fn freeze(&self) -> output::Snapshot {
        self.inner.lock().unwrap().freeze()
    }
    pub fn snapshot(&self) -> output::Snapshot {
        self.inner.lock().unwrap().snapshot()
    }
    pub fn delay_started(&self, transactions: usize) -> Result<()> {
        let mut telemetry = self.delay.lock().unwrap();
        let now = shared_runtime::monotonic_us().map_err(anyhow::Error::msg)?;
        telemetry.delay_started_count += 1;
        telemetry.delayed_transactions_started += transactions as u64;
        telemetry.first_delay_start_us.get_or_insert(now);
        Ok(())
    }
    pub fn delay_finished(&self, transactions: usize) -> Result<()> {
        let mut telemetry = self.delay.lock().unwrap();
        let now = shared_runtime::monotonic_us().map_err(anyhow::Error::msg)?;
        telemetry.delay_finished_count += 1;
        telemetry.delayed_transactions_finished += transactions as u64;
        telemetry.first_delay_finish_us.get_or_insert(now);
        Ok(())
    }
    pub fn delay_telemetry(&self) -> DelayTelemetry {
        self.delay.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_consensus_types::proof_of_store::{BatchId, BatchInfo};
    use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
    use aptos_types::{
        chain_id::ChainId,
        transaction::{RawTransaction, Script, TransactionPayload},
    };
    use rand::{rngs::StdRng, SeedableRng};

    fn transaction(size: usize) -> SignedTransaction {
        let key = Ed25519PrivateKey::generate(&mut StdRng::seed_from_u64(81));
        let raw = RawTransaction::new(
            AccountAddress::new([3; 32]),
            9,
            TransactionPayload::Script(Script::new(vec![7; size], vec![], vec![])),
            100,
            1,
            5000,
            ChainId::test(),
        );
        let signature = key.sign(&raw).unwrap();
        SignedTransaction::new(raw, key.public_key(), signature)
    }
    #[test]
    fn borrowed_payload_hash_and_size_equal_native_for_empty_batch() {
        let author = AccountAddress::new([7; 32]);
        let native = BatchPayload::new(author, vec![]);
        let facts = NativeBatchVerifier
            .inspect(&author.into_bytes(), &[])
            .unwrap();
        assert_eq!(facts.digest, *native.hash().as_ref());
        assert_eq!(facts.num_bytes, native.num_bytes() as u64);
    }
    #[test]
    fn descriptor_bytes_preserve_native_nonce_and_full_digest() {
        let native = BatchInfo::new(
            AccountAddress::new([4; 32]),
            BatchId::new(981),
            7,
            100,
            aptos_crypto::HashValue::new([9; 32]),
            0,
            33,
            12,
        );
        let bytes = shared_crypto_aptos::encode(&native).unwrap();
        let mirror = output::BatchInfo::from_native_bcs(&bytes).unwrap();
        assert_eq!(mirror.to_native_bcs().as_slice(), bytes);
        assert_eq!(mirror.key.nonce, 981);
        assert_eq!(mirror.key.digest, [9; 32]);
    }

    #[test]
    fn borrowed_payload_matches_native_signed_variable_transactions_and_author() {
        let author = AccountAddress::new([6; 32]);
        let transactions = vec![transaction(0), transaction(128), transaction(1001)];
        let native = BatchPayload::new(author, transactions.clone());
        let facts = NativeBatchVerifier
            .inspect(&author.into_bytes(), &transactions)
            .unwrap();
        assert_eq!(facts.digest, *native.hash().as_ref());
        assert_eq!(facts.num_bytes, native.num_bytes() as u64);
        assert_eq!(facts.num_txns, 3);
        let altered = NativeBatchVerifier
            .inspect(&[5; 32], &transactions)
            .unwrap();
        assert_ne!(facts.digest, altered.digest);
        assert_eq!(
            shared_crypto_aptos::encode(&(author, transactions.as_slice())).unwrap(),
            shared_crypto_aptos::encode(&native).unwrap()
        );
    }
}
