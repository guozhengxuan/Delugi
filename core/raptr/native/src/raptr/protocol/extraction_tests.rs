// Test-only oracle: exact pinned commit_qc_impl body, with only its name and
// recursive call renamed. No native live path calls this copy.
use super::*;
use crate::framework::module_network::ModuleId;
use crate::rehost::{native_config, CommitteeKeys};
use aptos_types::{validator_signer::ValidatorSigner, validator_verifier::ValidatorConsensusInfo};

struct NoIo;
impl DisseminationLayer for NoIo {
    fn module_id(&self) -> ModuleId {
        ModuleId::first_dynamic()
    }
    async fn prepare_block(&self, _: Round, _: HashSet<BatchInfo>, _: Option<BitVec>) -> Payload {
        unreachable!()
    }
    async fn available_prefix(&self, _: &Payload, _: Prefix) -> (Prefix, BitVec) {
        unreachable!()
    }
    async fn notify_commit(&self, _: Vec<Payload>, _: u64, _: Option<BitVec>) {
        unreachable!()
    }
    async fn set_first_committed_block_timestamp(&self, _: SystemTime) {
        unreachable!()
    }
}

fn fixture() -> (RaptrNode<NoIo>, Vec<Signer>, SignatureVerifier) {
    let signers: Vec<_> = (0u8..4)
        .map(|id| Arc::new(ValidatorSigner::random(Some([id + 1; 32]))))
        .collect();
    let committee = Arc::new(ValidatorVerifier::new(
        signers
            .iter()
            .map(|signer| ValidatorConsensusInfo::new(signer.author(), signer.public_key(), 1))
            .collect(),
    ));
    let keys = CommitteeKeys::new(signers[0].clone(), committee.clone()).unwrap();
    let signer_values = signers
        .into_iter()
        .map(|signer| {
            CommitteeKeys::new(signer, committee.clone())
                .unwrap()
                .signer
        })
        .collect();
    let verifier = keys.verifier.clone();
    let node = RaptrNode::new(
        0,
        native_config(
            4,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap(),
        NoIo,
        false,
        Metrics {
            block_consensus_latency: None,
            batch_consensus_latency: None,
        },
        keys.signer,
        keys.verifier,
        None,
    );
    (node, signer_values, verifier)
}

fn block(round: Round, parent: QC, signer: &Signer, metadata: bool) -> Block {
    let payload = if metadata {
        use aptos_consensus_types::{
            common::BatchPayload,
            payload::{BatchPointer, RaptrPayload},
            proof_of_store::ProofOfStore,
        };
        let signers: Vec<_> = (0u8..4)
            .map(|id| ValidatorSigner::random(Some([id + 1; 32])))
            .collect();
        let verifier = ValidatorVerifier::new(
            signers
                .iter()
                .map(|signer| ValidatorConsensusInfo::new(signer.author(), signer.public_key(), 1))
                .collect(),
        );
        let info = |index: usize| {
            let author = signers[index % signers.len()].author();
            let contents = BatchPayload::new(author, vec![]);
            BatchInfo::new(
                author,
                BatchId {
                    nonce: 0x1234_0000 + round as u64,
                    id: index as u64,
                },
                1,
                u64::MAX,
                shared_crypto_aptos::hash(&contents),
                0,
                bcs::to_bytes(&contents).unwrap().len() as u64,
                index as u64,
            )
        };
        let proof_info = info(8);
        let signatures: Vec<_> = signers
            .iter()
            .take(3)
            .map(|signer| {
                (
                    signer.author(),
                    shared_crypto_aptos::sign_validator(signer, &proof_info).unwrap(),
                )
            })
            .collect();
        let signature = verifier
            .aggregate_signatures(signatures.iter().map(|(author, sig)| (author, sig)))
            .unwrap();
        let proof = ProofOfStore::new(proof_info, signature);
        let inner = RaptrPayload::new(
            BatchPointer::new(vec![proof]),
            std::array::from_fn(|index| BatchPointer::new(vec![info(index)])),
        );
        // Real signed native metadata (including a certified proof) ensures the
        // oracle compares actual batch descriptors, not only empty sections.
        let payload = Payload::new(round, round as usize % 4, inner.into());
        payload
            .inner
            .verify(&verifier, &ProofCache::new(32), true)
            .unwrap();
        payload
    } else {
        Payload::empty(round, round as usize % 4)
    };
    let data = BlockData {
        timestamp_usecs: 1000 + round as u64,
        payload,
        reason: RoundEntryReason::FullPrefixQC(parent),
    };
    let digest = shared_crypto_aptos::hash(&data);
    let signature = signer.sign(&BlockSignatureData { digest }).unwrap();
    Block::new(data, signature)
}
fn qc(block: &Block, prefix: Prefix, signers: &[Signer], verifier: &SignatureVerifier) -> QC {
    let message = QcVoteSignatureCommonData {
        round: block.round(),
        block_digest: block.digest,
    };
    let sigs = (0..3).map(|id| signers[id].sign_tagged(&message, prefix).unwrap());
    QC::new(
        block.round(),
        block.digest,
        [(0, prefix), (1, prefix), (2, prefix)]
            .into_iter()
            .collect(),
        verifier.aggregate_signatures(sigs).unwrap(),
        BitVec::default(),
        2,
    )
}

#[test]
fn metadata_hook_preserves_exact_pinned_partial_parent_and_duplicate_commit_slices() {
    for (incremental, metadata) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut actual, signers, verifier) = fixture();
        let (mut oracle, _, _) = fixture();
        let first = block(1, QC::genesis(), &signers[1], metadata);
        let first_full = qc(&first, 8, &signers, &verifier);
        let second = block(2, first_full.clone(), &signers[2], metadata);
        for node in [&mut actual, &mut oracle] {
            node.blocks.insert(first.digest, first.clone());
            node.blocks.insert(second.digest, second.clone());
        }
        let mut requests = Vec::new();
        if incremental {
            requests.extend([
                qc(&first, 0, &signers, &verifier),
                qc(&first, 3, &signers, &verifier),
                first_full.clone(),
            ]);
        }
        requests.extend([
            qc(&second, 0, &signers, &verifier),
            qc(&second, 2, &signers, &verifier),
            qc(&second, 8, &signers, &verifier),
            qc(&second, 8, &signers, &verifier),
        ]);
        let mut first_seen = HashSet::new();
        for certificate in requests {
            certificate
                .verify(&Verifier::new(&actual, ProofCache::new(32)))
                .unwrap();
            let expected =
                oracle.pinned_commit_qc_impl(certificate.clone(), CommitReason::Indirect);
            let observed = actual.commit_qc_impl(certificate, CommitReason::Indirect);
            assert_eq!(observed.len(), expected.len());
            for (observed, expected) in observed.into_iter().zip(expected) {
                assert_eq!(
                    bcs::to_bytes(&observed.payload).unwrap(),
                    bcs::to_bytes(&expected).unwrap()
                );
                assert_eq!(
                    observed.block_digest,
                    if expected.round() == 1 {
                        first.digest
                    } else {
                        second.digest
                    }
                );
                assert_eq!(observed.include_proofs, first_seen.insert(expected.round()));
            }
            assert_eq!(actual.committed_qc.id(), oracle.committed_qc.id());
        }
    }
}

#[rustfmt::skip]
impl RaptrNode<NoIo> {
    fn pinned_commit_qc_impl(&mut self, qc: QC, commit_reason: CommitReason) -> Vec<Payload> {
        if qc.id() <= self.committed_qc.id() {
            return vec![];
        }

        let block = &self.blocks[qc.block_digest()];
        let parent = block.parent_qc().clone();

        if parent.is_genesis() {
            self.log_detail(format!("First committed block: {}", qc.round()));
            self.first_committed_block_timestamp =
                Some(UNIX_EPOCH + Duration::from_micros(block.data.timestamp_usecs));
        }

        // Check for safety violations:
        if qc.round() > self.committed_qc.round() && parent.round() < self.committed_qc.round() {
            panic!("Safety violation: committed block was rolled back");
        }
        if parent.round() == self.committed_qc.round()
            && parent.prefix() < self.committed_qc.prefix()
        {
            panic!("Safety violation: optimistically committed transactions were rolled back");
        }

        // First commit the parent block.
        let mut res = self.pinned_commit_qc_impl(parent, CommitReason::Indirect);

        // Then, commit the transactions of this block.
        let block = &self.blocks[qc.block_digest()];

        if qc.round() == self.committed_qc.round() {
            // Extending the prefix of an already committed block.

            assert!(qc.prefix() > self.committed_qc.prefix());

            self.log_detail(format!(
                "Extending the prefix of committed block {}: {} -> {} / {}{} ({:?})",
                qc.round(),
                self.committed_qc.prefix(),
                qc.prefix(),
                N_SUB_BLOCKS,
                if qc.is_full() { " (full)" } else { "" },
                commit_reason,
            ));

            res.push(
                block
                    .payload()
                    .take_sub_blocks(self.committed_qc.prefix()..qc.prefix()),
            );

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.round()) == self.node_id {
                for _ in 0..(qc.prefix() - self.committed_qc.prefix()) {
                    RAIKOU_BATCH_CONSENSUS_LATENCY.observe(
                        now.saturating_duration_since(self.block_create_time[&qc.round()])
                            .as_secs_f64(),
                    );
                    self.metrics.batch_consensus_latency.push((
                        now,
                        self.to_deltas(now - self.block_create_time[&qc.round()]),
                    ));
                }
            }
        } else {
            // Committing a new block.

            self.log_detail(format!(
                "Committing block {} proposed by node {} with {} ACs \
                and prefix {}/{} [{}/{} batches]{} ({:?}).",
                qc.round(),
                self.config.leader(qc.round()),
                block.poas().len(),
                qc.prefix(),
                N_SUB_BLOCKS,
                block
                    .sub_blocks()
                    .take(qc.prefix())
                    .map(|b| b.len())
                    .sum::<usize>(),
                block.sub_blocks().map(|b| b.len()).sum::<usize>(),
                if qc.is_full() { " (full)" } else { "" },
                commit_reason,
            ));

            res.push(block.payload().with_prefix(qc.prefix()));

            RAIKOU_BLOCK_COMMIT_RATE.inc();

            // Record the metrics
            let now = Instant::now();
            if self.config.leader(qc.round()) == self.node_id {
                RAIKOU_BLOCK_CONSENSUS_LATENCY.observe(
                    now.saturating_duration_since(self.block_create_time[&qc.round()])
                        .as_secs_f64(),
                );
                observe_block(block.data.timestamp_usecs, "COMMITBLOCK");
                self.metrics.block_consensus_latency.push((
                    now,
                    self.to_deltas(now - self.block_create_time[&qc.round()]),
                ));
                for _ in 0..(block.poas().len() + qc.prefix()) {
                    RAIKOU_BATCH_CONSENSUS_LATENCY.observe(
                        now.saturating_duration_since(self.block_create_time[&qc.round()])
                            .as_secs_f64(),
                    );
                    self.metrics.batch_consensus_latency.push((
                        now,
                        self.to_deltas(now - self.block_create_time[&qc.round()]),
                    ));
                }
            }
        }

        // Finally, update the committed QC variable.
        self.committed_qc = qc;
        res
    }
}
