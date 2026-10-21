use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey, SigningKey, Uniform};
use aptos_types::{
    account_address::AccountAddress,
    chain_id::ChainId,
    transaction::{RawTransaction, Script, SignedTransaction, TransactionPayload},
};
// Creates a single test transaction for a random account
pub(crate) fn create_signed_transaction(gas_unit_price: u64) -> SignedTransaction {
    let private_key = Ed25519PrivateKey::generate_for_testing();
    let public_key = private_key.public_key();

    let transaction_payload = TransactionPayload::Script(Script::new(vec![], vec![], vec![]));
    let raw_transaction = RawTransaction::new(
        AccountAddress::random(),
        0,
        transaction_payload,
        0,
        gas_unit_price,
        0,
        ChainId::new(10),
    );
    let signature = private_key.sign(&raw_transaction).unwrap();
    SignedTransaction::new(raw_transaction, public_key, signature)
}

pub(crate) fn create_vec_signed_transactions(size: u64) -> Vec<SignedTransaction> {
    (0..size).map(|_| create_signed_transaction(1)).collect()
}

pub(crate) fn create_vec_signed_transactions_with_gas(
    size: u64,
    gas_unit_price: u64,
) -> Vec<SignedTransaction> {
    (0..size)
        .map(|_| create_signed_transaction(gas_unit_price))
        .collect()
}

pub(crate) fn random_validator_verifier(
    count: usize,
    quorum: Option<u128>,
    pseudo: bool,
) -> (
    Vec<aptos_types::validator_signer::ValidatorSigner>,
    aptos_types::validator_verifier::ValidatorVerifier,
) {
    use aptos_types::{
        validator_signer::ValidatorSigner,
        validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
    };
    let signers: Vec<_> = (0..count)
        .map(|i| {
            if pseudo {
                ValidatorSigner::from_int(i as u8)
            } else {
                ValidatorSigner::random([i as u8; 32])
            }
        })
        .collect();
    let infos = signers
        .iter()
        .map(|s| ValidatorConsensusInfo::new(s.author(), s.public_key(), 1))
        .collect();
    let verifier = match quorum {
        Some(q) => ValidatorVerifier::new_with_quorum_voting_power(infos, q).unwrap(),
        None => ValidatorVerifier::new(infos),
    };
    (signers, verifier)
}
