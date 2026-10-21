//! Synchronous cryptographic execution. Callers own domains, canonical encodings,
//! membership, quorum predicates and cache policy. No protocol types enter here.
use ed25519_dalek::Signer;
pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
pub use sha2::{Digest, Sha256};
use shared_metrics::{measure, Operation};

pub fn sign_ed25519(key: &Keypair, bytes: &[u8], operation: Operation) -> Vec<u8> {
    let _cost = measure(operation);
    key.sign(bytes).to_bytes().to_vec()
}

pub fn verify_ed25519_strict(
    key: &PublicKey, bytes: &[u8], signature: &Signature, operation: Operation,
) -> Result<(), String> {
    let _cost = measure(operation);
    key.verify_strict(bytes, signature).map_err(|_| "invalid Ed25519 signature".to_string())
}

/// Ordered scatter input avoids introducing another concatenation allocation.
/// Domain and length framing are entirely supplied by the calling core.
pub fn sha256(parts: &[&[u8]], operation: Option<Operation>) -> [u8; 32] {
    let _cost = operation.and_then(measure);
    let mut hash = Sha256::new();
    for part in parts { hash.update(part); }
    hash.finalize().into()
}
