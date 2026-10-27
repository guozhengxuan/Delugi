use anyhow::{ensure, Context as _, Result};
use aptos_config::config::{ConsensusConfig, QuorumStoreConfig};
use aptos_crypto::{bls12381, HashValue, Uniform};
use aptos_types::{
    account_address::AccountAddress,
    block_info::BlockInfo,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    validator_signer::ValidatorSigner,
    validator_verifier::{ValidatorConsensusInfo, ValidatorVerifier},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const PROFILE: &str = "raptr-shared-consensus-only-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    pub counts: Vec<u64>,
    pub useful_bytes: usize,
    pub interval_us: u64,
    pub start_delay_ms: u64,
}
/// Local conformance control: suppress original QS delivery at one receiver;
/// native consensus, custody signatures, and repair policy remain unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadFault {
    pub node: u32,
    pub drop_initial_batch_messages: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_wire_bytes: usize,
    pub inbox_frames: usize,
    pub inbox_bytes: usize,
    pub maximum_rpcs: usize,
    pub ingress_capacity: usize,
    pub max_pending_transactions: u64,
    pub max_pending_payload_bytes: u64,
    pub output_capacity: usize,
    pub max_journal_bytes: u64,
    pub max_async_tasks: usize,
    pub max_blocking_tasks: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_wire_bytes: 1024 * 1024,
            inbox_frames: 4096,
            inbox_bytes: 32 * 1024 * 1024,
            maximum_rpcs: 1024,
            ingress_capacity: 4096,
            max_pending_transactions: 100_000,
            max_pending_payload_bytes: 128 * 1024 * 1024,
            output_capacity: 4096,
            max_journal_bytes: 128 * 1024 * 1024,
            max_async_tasks: 100_000,
            max_blocking_tasks: 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub epoch: u64,
    pub run_id: String,
    pub key_directory: PathBuf,
    pub addresses: Vec<SocketAddr>,
    /// Explicit opt-in for the four-host private-network deployment pilot.
    /// Omitted configurations retain the accepted localhost-only contract.
    #[serde(default)]
    pub deployment_profile: Option<String>,
    pub output_directory: PathBuf,
    pub arm_path: PathBuf,
    pub delta_ms: u64,
    pub measurement_duration_ms: u64,
    pub drain_ms: u64,
    pub finite_workload: WorkloadConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub consensus: Option<ConsensusConfig>,
    #[serde(default)]
    pub quorum_store: Option<QuorumStoreConfig>,
    #[serde(default)]
    pub materialization_delay_ms: u64,
    #[serde(default)]
    pub payload_fault: Option<PayloadFault>,
}
impl Config {
    pub fn parse(bytes: &[u8], id: u32) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)?;
        let n = config.addresses.len();
        let l = &config.limits;
        ensure!(
            config.schema == 1
                && config.epoch == 1
                && n >= 4
                && ((n <= 31 && (n - 1) % 3 == 0) || n == 50)
                && (id as usize) < n,
            "invalid finite replica membership/epoch/schema"
        );
        ensure!(
            config.addresses.iter().collect::<BTreeSet<_>>().len() == n,
            "duplicate peer address"
        );
        validate_addresses(&config.addresses, config.deployment_profile.as_deref())?;
        ensure!(unhex(&config.run_id)?.len() == 32, "run_id must be32 bytes");
        ensure!(
            config.finite_workload.counts.len() == n
                && config.finite_workload.useful_bytes <= 65536,
            "invalid workload size/membership"
        );
        ensure!(
            config
                .finite_workload
                .counts
                .iter()
                .try_fold(0_u64, |a, &v| a.checked_add(v))
                .context("workload count overflow")?
                <= 100_000,
            "finite workload exceeds100000 requests"
        );
        ensure!(
            config
                .finite_workload
                .counts
                .iter()
                .sum::<u64>()
                .checked_mul(config.finite_workload.useful_bytes as u64 + 1024)
                .context("prepared byte overflow")?
                <= 128 * 1024 * 1024,
            "finite precomputed request envelope exceeds128MiB"
        );
        ensure!(
            config.delta_ms > 0
                && config.delta_ms <= 60_000
                && config.measurement_duration_ms > 0
                && config.measurement_duration_ms <= 60_000
                && config.drain_ms <= 60_000
                && config.materialization_delay_ms <= 60_000,
            "invalid finite timing bounds"
        );
        ensure!(
            l.max_wire_bytes > 0
                && l.max_wire_bytes <= 1024 * 1024
                && l.inbox_frames > 0
                && l.inbox_frames <= 100_000
                && l.inbox_bytes >= l.max_wire_bytes
                && l.inbox_bytes <= 128 * 1024 * 1024
                && l.maximum_rpcs > 0
                && l.maximum_rpcs <= 100_000
                && l.ingress_capacity > 0
                && l.ingress_capacity <= 100_000
                && l.output_capacity > 0
                && l.output_capacity <= 100_000
                && l.max_journal_bytes > 0
                && l.max_journal_bytes <= 512 * 1024 * 1024,
            "invalid finite resource envelope"
        );
        ensure!(
            l.max_async_tasks > 0
                && l.max_async_tasks <= 1_000_000
                && l.max_blocking_tasks > 0
                && l.max_blocking_tasks <= 100_000,
            "invalid shared task envelope"
        );
        ensure!(
            l.max_pending_transactions > 0
                && l.max_pending_transactions <= 1_000_000
                && l.max_pending_payload_bytes > 0
                && l.max_pending_payload_bytes <= 1024 * 1024 * 1024,
            "invalid output envelope"
        );
        for &count in &config.finite_workload.counts {
            if count > 0 {
                let last = (count - 1)
                    .checked_mul(config.finite_workload.interval_us)
                    .and_then(|v| {
                        v.checked_add(config.finite_workload.start_delay_ms.checked_mul(1000)?)
                    })
                    .context("schedule overflow")?;
                ensure!(
                    last < config.measurement_duration_ms * 1000,
                    "arrival outside finite measurement interval"
                );
            }
        }
        if let Some(fault) = &config.payload_fault {
            ensure!(
                (fault.node as usize) < n
                    && fault.drop_initial_batch_messages > 0
                    && fault.drop_initial_batch_messages <= 1_000,
                "invalid finite missing-payload control"
            );
            ensure!(
                config.finite_workload.counts[fault.node as usize] == 0,
                "missing-payload receiver must not originate workload"
            );
        }
        Ok(config)
    }
}

fn validate_addresses(addresses: &[SocketAddr], profile: Option<&str>) -> Result<()> {
    let valid = match profile {
        None => addresses
            .iter()
            .all(|a| a.ip().is_loopback() && a.port() > 0),
        Some("private-ipv4-n4-v1") => {
            addresses.len() == 4
                && addresses
                    .iter()
                    .map(|a| a.ip())
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 4
                && addresses.iter().all(|a| match a {
                    SocketAddr::V4(v4) => v4.ip().is_private() && v4.port() > 0,
                    SocketAddr::V6(_) => false,
                })
        }
        Some("private-ipv4-n10-n50-v1") => {
            matches!(addresses.len(), 10 | 50)
                && addresses.iter().map(|a| a.ip()).collect::<BTreeSet<_>>().len() == addresses.len()
                && addresses.iter().all(|a| match a {
                    SocketAddr::V4(v4) => v4.ip().is_private() && v4.port() > 0,
                    SocketAddr::V6(_) => false,
                })
        }
        Some(_) => false,
    };
    ensure!(
        valid,
        "peer addresses do not match the explicit local/private deployment profile"
    );
    Ok(())
}

#[cfg(test)]
mod deployment_tests {
    use super::*;
    #[test]
    fn private_placement_is_explicit_and_has_distinct_hosts() {
        let peers: Vec<SocketAddr> = (1..=4)
            .map(|i| format!("10.0.0.{i}:8000").parse().unwrap())
            .collect();
        assert!(validate_addresses(&peers, None).is_err());
        assert!(validate_addresses(&peers, Some("private-ipv4-n4-v1")).is_ok());
        let mut bad = peers.clone();
        bad[3] = "10.0.0.1:8001".parse().unwrap();
        assert!(validate_addresses(&bad, Some("private-ipv4-n4-v1")).is_err());
        bad[3] = "8.8.8.8:8000".parse().unwrap();
        assert!(validate_addresses(&bad, Some("private-ipv4-n4-v1")).is_err());
        assert!(validate_addresses(&peers, Some("unknown")).is_err());
        let local = vec!["127.0.0.1:8000".parse().unwrap()];
        assert!(validate_addresses(&local, None).is_ok());
    }

    #[test]
    fn paper_placement_supports_exactly_ten_and_fifty_distinct_private_hosts() {
        for n in [10, 50] {
            let peers: Vec<SocketAddr> = (1..=n).map(|i| format!("10.1.0.{i}:8000").parse().unwrap()).collect();
            assert!(validate_addresses(&peers, Some("private-ipv4-n10-n50-v1")).is_ok());
            assert!(validate_addresses(&peers, Some("private-ipv4-n4-v1")).is_err());
        }
        let peers = vec!["10.1.0.1:8000".parse().unwrap(); 50];
        assert!(validate_addresses(&peers, Some("private-ipv4-n10-n50-v1")).is_err());
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Result<Vec<u8>> {
    ensure!(text.len() % 2 == 0 && text.is_ascii(), "invalid hex");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
pub fn digest(bytes: &[u8]) -> String {
    hex(&shared_crypto::sha256(&[bytes], None))
}
pub fn write_new(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if secret { 0o600 } else { 0o644 });
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}
pub fn write_json_new(path: &Path, value: &impl Serialize, secret: bool) -> Result<()> {
    let mut b = serde_json::to_vec_pretty(value)?;
    b.push(b'\n');
    write_new(path, &b, secret)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: u32,
    pub author: String,
    pub consensus_public: String,
    pub transport_public: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    pub schema: u32,
    pub epoch: u64,
    pub members: Vec<Member>,
    pub genesis_ledger_sha256: String,
}
#[derive(Serialize, Deserialize)]
struct Secret {
    schema: u32,
    id: u32,
    consensus_secret: String,
    transport_secret: String,
}
pub struct Keys {
    pub committee: Committee,
    pub authors: Vec<AccountAddress>,
    pub verifier: Arc<ValidatorVerifier>,
    pub signer: Arc<ValidatorSigner>,
    pub consensus: Arc<bls12381::PrivateKey>,
    pub transport: Arc<shared_crypto::Keypair>,
    pub transport_keys: Vec<shared_crypto::PublicKey>,
    pub genesis: LedgerInfoWithSignatures,
    pub public_hash: [u8; 32],
}
impl Keys {
    pub fn load(directory: &Path, id: u32) -> Result<Self> {
        let public_bytes = fs::read(directory.join("committee.json"))?;
        let committee: Committee = serde_json::from_slice(&public_bytes)?;
        ensure!(
            committee.schema == 1 && committee.epoch == 1,
            "unsupported key registry"
        );
        let secret: Secret =
            serde_json::from_slice(&fs::read(directory.join(format!("key-{id}.json")))?)?;
        ensure!(
            secret.schema == 1 && secret.id == id,
            "private identity mismatch"
        );
        let mut authors = vec![];
        let mut infos = vec![];
        let mut transport_keys = vec![];
        for (index, m) in committee.members.iter().enumerate() {
            ensure!(m.id as usize == index, "noncontiguous member registry");
            let author = AccountAddress::from_bytes(unhex(&m.author)?)?;
            let public = bls12381::PublicKey::try_from(unhex(&m.consensus_public)?.as_slice())?;
            transport_keys.push(shared_crypto::PublicKey::from_bytes(&unhex(
                &m.transport_public,
            )?)?);
            infos.push(ValidatorConsensusInfo::new(author, public, 1));
            authors.push(author);
        }
        ensure!(
            authors.iter().collect::<BTreeSet<_>>().len() == authors.len()
                && (id as usize) < authors.len(),
            "duplicate/missing author"
        );
        let verifier = Arc::new(ValidatorVerifier::new(infos));
        ensure!(
            verifier.get_ordered_account_addresses() == authors,
            "native index mapping changed"
        );
        let consensus = Arc::new(bls12381::PrivateKey::try_from(
            unhex(&secret.consensus_secret)?.as_slice(),
        )?);
        let signer = Arc::new(ValidatorSigner::new(
            authors[id as usize],
            consensus.clone(),
        ));
        ensure!(
            verifier.get_public_key(&signer.author()) == Some(signer.public_key()),
            "private/public validator key mismatch"
        );
        let secret = shared_crypto::SecretKey::from_bytes(&unhex(&secret.transport_secret)?)?;
        let transport = Arc::new(shared_crypto::Keypair {
            public: shared_crypto::PublicKey::from(&secret),
            secret,
        });
        ensure!(
            transport.public == transport_keys[id as usize],
            "private/public transport key mismatch"
        );
        let genesis_bytes = fs::read(directory.join("genesis-ledger.bcs"))?;
        ensure!(
            digest(&genesis_bytes) == committee.genesis_ledger_sha256,
            "genesis anchor hash mismatch"
        );
        let genesis: LedgerInfoWithSignatures = shared_crypto_aptos::decode(&genesis_bytes)?;
        shared_crypto_aptos::native_validation(|| genesis.verify_signatures(&verifier))?;
        ensure!(
            genesis.ledger_info().epoch() == committee.epoch
                && genesis.ledger_info().timestamp_usecs() == 0,
            "invalid fixed genesis anchor"
        );
        Ok(Self {
            committee,
            authors,
            verifier,
            signer,
            consensus,
            transport,
            transport_keys,
            genesis,
            public_hash: shared_crypto::sha256(&[&public_bytes], None),
        })
    }
}
pub fn generate_keys(directory: &Path, n: usize) -> Result<String> {
    ensure!(
        (n >= 4 && n <= 31 && (n - 1) % 3 == 0) || n == 50,
        "keys require n=3f+1 in4..31 or exactly n=50"
    );
    fs::create_dir_all(directory)?;
    ensure!(
        !directory.join("committee.json").exists(),
        "key directory already initialized"
    );
    let mut rng = rand::rngs::OsRng;
    let mut signers = vec![];
    let mut members = vec![];
    for id in 0..n {
        let key = bls12381::PrivateKey::generate(&mut rng);
        let consensus_secret = hex(&key.to_bytes());
        let mut raw = [0; 32];
        rng.fill_bytes(&mut raw);
        let secret = shared_crypto::SecretKey::from_bytes(&raw)?;
        let public = shared_crypto::PublicKey::from(&secret);
        let author = AccountAddress::new(shared_crypto::sha256(
            &[b"raptr-shared-author-v1", &public.to_bytes()],
            None,
        ));
        let signer = Arc::new(ValidatorSigner::new(author, Arc::new(key)));
        members.push(Member {
            id: id as u32,
            author: hex(&author.into_bytes()),
            consensus_public: hex(&signer.public_key().to_bytes()),
            transport_public: hex(&public.to_bytes()),
        });
        write_json_new(
            &directory.join(format!("key-{id}.json")),
            &Secret {
                schema: 1,
                id: id as u32,
                consensus_secret,
                transport_secret: hex(&raw),
            },
            true,
        )?;
        signers.push(signer);
    }
    let verifier = ValidatorVerifier::new(
        signers
            .iter()
            .map(|s| ValidatorConsensusInfo::new(s.author(), s.public_key(), 1))
            .collect(),
    );
    let ledger = LedgerInfo::new(
        BlockInfo::new(1, 0, HashValue::zero(), HashValue::zero(), 0, 0, None),
        HashValue::zero(),
    );
    let signatures: Vec<_> = signers
        .iter()
        .map(|s| Ok((s.author(), shared_crypto_aptos::sign_validator(s, &ledger)?)))
        .collect::<Result<_>>()?;
    let anchor = LedgerInfoWithSignatures::new(
        ledger,
        verifier.aggregate_signatures(signatures.iter().map(|(a, s)| (a, s)))?,
    );
    shared_crypto_aptos::native_validation(|| anchor.verify_signatures(&verifier))?;
    let bytes = shared_crypto_aptos::encode(&anchor)?;
    write_new(&directory.join("genesis-ledger.bcs"), &bytes, false)?;
    write_json_new(
        &directory.join("committee.json"),
        &Committee {
            schema: 1,
            epoch: 1,
            members,
            genesis_ledger_sha256: digest(&bytes),
        },
        false,
    )?;
    Ok(serde_json::json!({"schema":1,"nodes":n,"committee":directory.join("committee.json"),"profile":PROFILE}).to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Arm {
    pub schema: u32,
    pub run_id: String,
    pub configuration_sha256: String,
    pub epoch_us: u64,
}
