use super::*;
use crate::raptr::types::{BlockHash, QcVoteSignatureCommonData};
use aptos_bitvec::BitVec;
use aptos_crypto::{bls12381, Uniform};
use aptos_types::{account_address::AccountAddress, validator_verifier::ValidatorConsensusInfo};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::VecDeque;

fn committee() -> (Vec<Arc<ValidatorSigner>>, Arc<ValidatorVerifier>) {
    let signers: Vec<_> = (0..4)
        .map(|id| {
            let mut rng = StdRng::seed_from_u64(800 + id);
            let key = bls12381::PrivateKey::generate(&mut rng);
            // Deliberately descending author order: native indices follow verifier order.
            let mut address = [0; 32];
            address[31] = (10 - id) as u8;
            Arc::new(ValidatorSigner::new(
                AccountAddress::new(address),
                Arc::new(key),
            ))
        })
        .collect();
    let verifier = ValidatorVerifier::new(
        signers
            .iter()
            .map(|signer| ValidatorConsensusInfo::new(signer.author(), signer.public_key(), 1))
            .collect(),
    );
    (signers, Arc::new(verifier))
}

fn verifier(keys: &CommitteeKeys) -> Arc<Verifier> {
    Arc::new(Verifier {
        config: native_config(
            4,
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap(),
        sig_verifier: keys.verifier.clone(),
        proof_cache: ProofCache::new(128),
    })
}

#[test]
fn native_membership_index_and_key_are_preserved() {
    let (signers, committee) = committee();
    for (index, signer) in signers.iter().enumerate() {
        let keys = CommitteeKeys::new(signer.clone(), committee.clone()).unwrap();
        assert_eq!(keys.id, index);
    }
    let replacement = Arc::new(ValidatorSigner::new(
        signers[0].author(),
        Arc::new(bls12381::PrivateKey::generate(&mut StdRng::seed_from_u64(
            999,
        ))),
    ));
    assert!(CommitteeKeys::new(replacement, committee).is_err());
}

#[tokio::test]
async fn exact_native_qc_vote_bcs_and_signatures() {
    let (signers, committee) = committee();
    let keys = CommitteeKeys::new(signers[0].clone(), committee).unwrap();
    let data = QcVoteSignatureCommonData {
        round: 12,
        block_digest: BlockHash::zero(),
    };
    let sig = keys.signer.sign_tagged(&data, 3).unwrap();
    let message = Message::QcVote(12, 3, BlockHash::zero(), sig, BitVec::default());
    let bytes = encode(&message, 4096).unwrap();
    assert_eq!(bytes, bcs::to_bytes(&message).unwrap());
    let decoded = decode(&bytes, 4096).unwrap();
    verifier(&keys).verify(0, &decoded).await.unwrap();
    assert!(verifier(&keys).verify(1, &decoded).await.is_err());
    assert!(decode(&bytes, bytes.len() - 1).is_err());
    assert!(encode(&message, bytes.len() - 1).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode(&trailing, 4096).is_err());
}

struct Inbox(VecDeque<(NodeId, Message)>);
impl NetworkSender for Inbox {
    type Message = Message;
    async fn send(&self, _: Message, _: Vec<NodeId>) {
        panic!("receive-only fixture")
    }
    fn n_nodes(&self) -> usize {
        4
    }
}
impl NetworkService for Inbox {
    type Sender = Inbox;
    fn new_sender(&self) -> Inbox {
        Inbox(VecDeque::new())
    }
    async fn recv(&mut self) -> (NodeId, Message) {
        self.0.pop_front().expect("fixture exhausted")
    }
}

#[tokio::test]
async fn invalid_sender_and_wrong_native_signature_never_reach_core() {
    let (signers, committee) = committee();
    let keys = CommitteeKeys::new(signers[0].clone(), committee).unwrap();
    let signature = keys
        .signer
        .sign_tagged(
            &QcVoteSignatureCommonData {
                round: 12,
                block_digest: BlockHash::zero(),
            },
            3,
        )
        .unwrap();
    let message = Message::QcVote(12, 3, BlockHash::zero(), signature, BitVec::default());
    let mut network = VerifiedNetwork::new(
        Inbox(VecDeque::from([
            (9, message.clone()),
            (1, message.clone()),
            (0, message),
        ])),
        verifier(&keys),
    )
    .unwrap();
    let rejected = network.rejected_counter();
    let (sender, _) = network.recv().await;
    assert_eq!(sender, 0);
    assert_eq!(rejected.load(Ordering::Relaxed), 2);
}

#[test]
fn config_keeps_native_thresholds_and_timer_multipliers() {
    let config = native_config(4, Duration::from_millis(100), Instant::now()).unwrap();
    assert_eq!(
        (
            config.f,
            config.quorum(),
            config.poa_quorum,
            config.storage_requirement
        ),
        (1, 3, 3, 2)
    );
    assert_eq!(config.leader_timeout, Duration::from_millis(400));
    assert_eq!(config.extra_wait_before_qc_vote, Duration::from_millis(10));
    assert_eq!(config.block_fetch_interval, Duration::from_millis(200));
    assert!(config.enable_partial_qc_votes && config.enable_commit_votes);
    let fifty = native_config(50, Duration::from_millis(100), Instant::now()).unwrap();
    assert_eq!((fifty.f, fifty.quorum(), fifty.poa_quorum, fifty.storage_requirement), (16, 34, 34, 17));
}

#[test]
fn invalid_certificate_signer_tag_and_pair_lengths_are_errors() {
    let (signers, committee) = committee();
    let keys = CommitteeKeys::new(signers[0].clone(), committee).unwrap();
    let data = QcVoteSignatureCommonData {
        round: 9,
        block_digest: BlockHash::zero(),
    };
    let signature = keys.signer.sign_tagged(&data, 1).unwrap();
    assert!(keys
        .verifier
        .verify_tagged(4, &data, 1, &signature)
        .is_err());
    assert!(keys
        .verifier
        .verify_tagged(0, &data, 9, &signature)
        .is_err());
    assert!(keys
        .verifier
        .verify_tagged_multi_signature([0, 1], &data, [1], &signature)
        .is_err());
    assert!(keys
        .verifier
        .verify_tagged_multi_signature([0, 4], &data, [1, 1], &signature)
        .is_err());
    assert!(keys
        .verifier
        .verify_aggregate_signatures([0, 4], vec![&data, &data], &signature)
        .is_err());
    assert!(keys
        .verifier
        .verify_aggregate_signatures([0], vec![&data, &data], &signature)
        .is_err());
}
