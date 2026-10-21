//! Native Aptos cryptographic mechanisms behind a shared execution boundary.
//!
//! Protocols supply the concrete signed type, hash domain, signer selection and
//! quorum/cache decisions. These calls preserve the pinned BLS/SHA3/BCS backend;
//! they neither change the message encoding nor substitute another algorithm.
use aptos_crypto::{bls12381, hash::CryptoHash, HashValue, Signature, SigningKey};
use aptos_types::validator_signer::ValidatorSigner;
use serde::{de::DeserializeOwned, Serialize};
use shared_metrics::{measure, Operation};

pub fn sign_validator<T: CryptoHash + Serialize>(
    signer: &ValidatorSigner,
    message: &T,
) -> anyhow::Result<bls12381::Signature> {
    let _cost = measure(Operation::ProtocolSign);
    Ok(signer.sign(message)?)
}

pub fn sign_private<T: CryptoHash + Serialize>(
    signer: &bls12381::PrivateKey,
    message: &T,
) -> anyhow::Result<bls12381::Signature> {
    let _cost = measure(Operation::ProtocolSign);
    Ok(signer.sign(message)?)
}

pub fn verify<T: CryptoHash + Serialize>(
    signature: &bls12381::Signature,
    message: &T,
    key: &bls12381::PublicKey,
) -> anyhow::Result<()> {
    let _cost = measure(Operation::ProtocolVerify);
    signature.verify(message, key)
}

pub fn verify_aggregate<T: CryptoHash + Serialize>(
    signature: &bls12381::Signature,
    messages: &[&T],
    keys: &[&bls12381::PublicKey],
) -> anyhow::Result<()> {
    let _cost = measure(Operation::ProtocolVerify);
    signature.verify_aggregate(messages, keys)
}

pub fn aggregate_keys(keys: Vec<&bls12381::PublicKey>) -> anyhow::Result<bls12381::PublicKey> {
    let _cost = measure(Operation::PrefixProofBuild);
    bls12381::PublicKey::aggregate(keys)
}

pub fn aggregate_signatures(
    signatures: Vec<bls12381::Signature>,
) -> anyhow::Result<bls12381::Signature> {
    let _cost = measure(Operation::PrefixProofBuild);
    bls12381::Signature::aggregate(signatures)
}

pub fn hash<T: CryptoHash>(value: &T) -> HashValue {
    let _cost = measure(Operation::ContentHash);
    value.hash()
}

pub fn encode<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<Vec<u8>> {
    Ok(bcs::to_bytes(value)?)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> anyhow::Result<T> {
    Ok(bcs::from_bytes(bytes)?)
}

/// Compatibility types may perform native cached/quorum validation internally.
/// This records the enclosing operation without moving that policy into shared
/// code. Nested primitive costs must not be summed with this scope.
pub fn native_validation<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::PrefixProofVerify);
    operation()
}

pub fn native_signing<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::ProtocolSign);
    operation()
}

pub fn native_construction<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::PrefixProofBuild);
    operation()
}

/// The core supplies the native hasher type, retaining its original seed/domain.
pub fn hash_encoded<H: aptos_crypto::hash::CryptoHasher>(bytes: &[u8]) -> HashValue {
    let _cost = measure(Operation::ContentHash);
    let mut state = H::default();
    state.update(bytes);
    state.finish()
}

/// Native transaction hashing may include an outer Transaction enum or a cached
/// committed hash. The caller retains that exact native policy/representation.
pub fn native_hashing<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::ContentHash);
    operation()
}
pub fn workload_signing<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::WorkloadManifestSign);
    operation()
}
pub fn workload_validation<T>(operation: impl FnOnce() -> T) -> T {
    let _cost = measure(Operation::WorkloadManifestVerify);
    operation()
}
pub fn encoded_size<T: Serialize + ?Sized>(value: &T) -> anyhow::Result<usize> {
    Ok(bcs::serialized_size(value)?)
}
