//! Independent replica driver with real clocks, authenticated replica TCP and a
//! loopback capability-protected client/control endpoint. This local experiment
//! uses self-contained authenticated bases. Custody is process-local; an optional
//! fresh RocksDB record mirror adds a Written barrier before local visibility.
use crate::availability::AvailabilityConfig;
pub use crate::batch::StorageProfile;
use crate::causal::{self, Trace as CausalTrace};
use crate::composed::{self, Effect, Node};
use crate::end_to_end::transactions;
use crate::mmr;
use crate::replica::{Effect as OrderingEffect, OrderingSchedule};
use crate::simulation::message_kind;
use crate::transport::{Layer, PayloadAccounting, Received, Transport, TransportSettings};
use crate::wire::{self, Committee, Digest, Id};
use crate::workload::{self, Arrival, Ingress};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingMode {
    Canonical,
    Progress,
    Barrier,
}

fn default_ordering_batch() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub instance: Digest,
    pub addresses: Vec<SocketAddr>,
    /// Listener interfaces can differ from routable peer addresses.
    #[serde(default)]
    pub bind_addresses: Option<Vec<SocketAddr>>,
    #[serde(default)]
    pub resource_profile: wire::ResourceProfile,
    #[serde(default)]
    pub fault: Option<FaultConfig>,
    #[serde(default)]
    pub measure_costs: bool,
    #[serde(default)]
    pub observer_mode: workload::ObserverMode,
    #[serde(default)]
    pub storage_profile: StorageProfile,
    /// Existing parent directory; each process exclusively creates replica-ID.
    #[serde(default)]
    pub storage_directory: Option<PathBuf>,
    pub control_addresses: Vec<SocketAddr>,
    pub control_token: String,
    pub public_keys: Vec<Vec<u8>>,
    pub key_files: Vec<PathBuf>,
    pub bound_ms: u64,
    pub chunk_capacity: u64,
    pub workload_rounds: u64,
    pub silent: Option<Id>,
    pub max_runtime_ms: u64,
    #[serde(default)]
    pub sustained: Option<SustainedConfig>,
    /// Zero-wait, per-effect-drain ordering packet aggregation, enabled by default.
    #[serde(default = "default_ordering_batch")]
    pub ordering_batch: bool,
    /// Defaults to PROG pacing. Explicit canonical/barrier modes support comparisons.
    #[serde(default)]
    pub ordering_mode: Option<OrderingMode>,
    /// Experimental ordering send barrier; its fallback begins at round entry.
    #[serde(default)]
    pub round_barrier_ms: Option<u64>,
    /// Origin-PROG release deadline; defaults to bound_ms in progress mode.
    #[serde(default)]
    pub progress_pacing_ms: Option<u64>,
}
/// Independent open-loop ingress, followed by protocol-thread batching.
/// Useful application bytes exclude the request identity and native encoding.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SustainedConfig {
    pub rate_per_replica: u64,
    /// Exact committee-wide open-loop rate, round-robin across correct ingress.
    #[serde(default)]
    pub total_rate: Option<u64>,
    pub transaction_bytes: usize,
    pub batch_ms: u64,
    pub warmup_ms: u64,
    pub measurement_ms: u64,
    #[serde(default)]
    pub useful_bytes: Option<usize>,
    #[serde(default = "default_batch_transactions")]
    pub max_batch_transactions: usize,
    #[serde(default = "default_arrival_capacity")]
    pub arrival_queue_capacity: usize,
    #[serde(default)]
    pub origins: Option<Vec<Id>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultScope {
    Payload,
    All,
}
/// Finite outgoing application-message omission by one fixed faulty identity.
/// It retains custody and does not modify Q, voting, or leader selection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultConfig {
    pub replica: Id,
    pub start_after_load_ms: u64,
    pub duration_ms: u64,
    pub scope: FaultScope,
    #[serde(default)]
    pub peers: Option<Vec<Id>>,
}
impl FaultConfig {
    fn omits(&self, own: Id, peer: Id, kind: &str, elapsed_ms: u64) -> bool {
        own == self.replica
            && elapsed_ms >= self.start_after_load_ms
            && elapsed_ms < self.start_after_load_ms.saturating_add(self.duration_ms)
            && self
                .peers
                .as_ref()
                .map_or(true, |peers| peers.contains(&peer))
            && (self.scope == FaultScope::All || matches!(kind, "BATCH" | "DATA"))
    }
}
fn default_batch_transactions() -> usize {
    128
}
fn default_arrival_capacity() -> usize {
    65_536
}
impl SustainedConfig {
    pub(crate) fn origin_ids(&self, members: usize) -> Vec<Id> {
        self.origins
            .clone()
            .unwrap_or_else(|| (0..members as Id).collect())
    }
    pub(crate) fn arrival_count(&self, id: Id, members: usize) -> u64 {
        let origins = self.origin_ids(members);
        let Some(rank) = origins.iter().position(|origin| *origin == id) else {
            return 0;
        };
        let duration = (self.warmup_ms + self.measurement_ms) * 1000;
        if let Some(rate) = self.total_rate {
            let total = scheduled_transactions(duration, rate);
            (total + origins.len() as u64 - 1 - rank as u64) / origins.len() as u64
        } else {
            scheduled_transactions(duration, self.rate_per_replica)
        }
    }
    pub(crate) fn manifest(
        &self,
        instance: Digest,
        id: Id,
        members: usize,
        start: u64,
    ) -> workload::Manifest {
        workload::Manifest {
            instance,
            origin: id,
            rate_per_second: self.rate_per_replica,
            count: self.arrival_count(id, members),
            useful_bytes: self.useful_bytes(),
            start_elapsed_us: start,
            identity_version: 2,
            total_rate: self.total_rate,
            origins: self.origin_ids(members),
        }
    }
    pub(crate) fn useful_bytes(&self) -> usize {
        self.useful_bytes.unwrap_or(
            self.transaction_bytes
                .saturating_sub(40 + workload::REQUEST_METADATA_BYTES),
        )
    }
    fn encoded_transaction_bytes(&self) -> usize {
        self.useful_bytes() + 40 + workload::REQUEST_METADATA_BYTES
    }
    pub(crate) fn is_origin(&self, id: Id) -> bool {
        self.origins
            .as_ref()
            .map_or(true, |origins| origins.contains(&id))
    }
    fn validate(&self) -> Result<(), String> {
        if self.rate_per_replica == 0
            || self.rate_per_replica > 25_000
            || self
                .total_rate
                .is_some_and(|rate| rate == 0 || rate > 775_000)
            || self.transaction_bytes < 60
            || self.transaction_bytes > crate::batch::MAX_BATCH_PAYLOAD - 8
            || self.batch_ms == 0
            || self.batch_ms > 1000
            || self.useful_bytes() == 0
            || self.useful_bytes() > crate::batch::MAX_BATCH_PAYLOAD - 68
            || self.max_batch_transactions == 0
            || self.max_batch_transactions > 65_536
            || self.arrival_queue_capacity == 0
            || self.arrival_queue_capacity > 1_000_000
            || self
                .arrival_queue_capacity
                .saturating_mul(self.encoded_transaction_bytes())
                > 64 * 1024 * 1024
            || self.measurement_ms == 0
            || self.warmup_ms.saturating_add(self.measurement_ms) > 3_600_000
            || scheduled_transactions(
                self.warmup_ms
                    .saturating_add(self.measurement_ms)
                    .saturating_mul(1000),
                self.rate_per_replica,
            ) > 5_000_000
        {
            return Err("invalid sustained load configuration".into());
        }
        Ok(())
    }
}

impl Config {
    pub fn ordering_schedule(&self) -> Result<OrderingSchedule, String> {
        for delay in [self.round_barrier_ms, self.progress_pacing_ms]
            .into_iter()
            .flatten()
        {
            if delay == 0 || delay > self.bound_ms {
                return Err(
                    "ordering release deadline must be positive and at most bound_ms".into(),
                );
            }
        }
        let mode = self
            .ordering_mode
            .unwrap_or(if self.round_barrier_ms.is_some() {
                OrderingMode::Barrier
            } else {
                OrderingMode::Progress
            });
        match mode {
            OrderingMode::Canonical
                if self.round_barrier_ms.is_none() && self.progress_pacing_ms.is_none() =>
            {
                Ok(OrderingSchedule::Canonical)
            }
            OrderingMode::Progress if self.round_barrier_ms.is_none() => {
                Ok(OrderingSchedule::ProgressPacing {
                    release_delay_ms: self.progress_pacing_ms.unwrap_or(self.bound_ms),
                })
            }
            OrderingMode::Barrier if self.progress_pacing_ms.is_none() => {
                Ok(OrderingSchedule::RoundBarrier {
                    release_delay_ms: self.round_barrier_ms.unwrap_or(self.bound_ms),
                })
            }
            _ => Err("ordering mode and release deadline options conflict".into()),
        }
    }

    pub fn validate(&self, id: Id) -> Result<Committee, String> {
        self.ordering_schedule()?;
        match (self.storage_profile, &self.storage_directory) {
            (StorageProfile::MemoryVisible, None) => {}
            (StorageProfile::SharedRocksdbWritten, Some(path)) if path.is_absolute() => {
                if !cfg!(feature = "rocksdb-records") {
                    return Err("shared RocksDB profile requires the rocksdb-records build feature".into());
                }
            }
            _ => return Err("storage profile requires memory without a directory or shared RocksDB with an absolute parent directory".into()),
        }
        if let Some(load) = &self.sustained {
            load.validate()?;
            if let Some(origins) = &load.origins {
                let distinct: BTreeSet<_> = origins.iter().copied().collect();
                if origins.is_empty()
                    || distinct.len() != origins.len()
                    || origins.iter().any(|origin| {
                        *origin as usize >= self.public_keys.len() || self.silent == Some(*origin)
                    })
                {
                    return Err("workload origins must be distinct active committee members".into());
                }
            } else if self.silent.is_some() {
                return Err(
                    "silent sustained replica must be excluded from explicit workload origins"
                        .into(),
                );
            }
        }
        let n = self.public_keys.len();
        if let Some(load) = &self.sustained {
            if load
                .total_rate
                .is_some_and(|rate| rate > load.origin_ids(n).len() as u64 * 25_000)
                || (0..n as Id).any(|origin| load.arrival_count(origin, n) > 5_000_000)
            {
                return Err(
                    "workload exceeds the per-origin rate or finite ledger resource envelope"
                        .into(),
                );
            }
        }
        if let Some(fault) = &self.fault {
            let load = self
                .sustained
                .as_ref()
                .ok_or("timed omission requires a sustained workload clock")?;
            if fault.replica as usize >= n
                || fault.duration_ms == 0
                || fault
                    .start_after_load_ms
                    .checked_add(fault.duration_ms)
                    .map_or(true, |end| end > self.max_runtime_ms)
                || load.is_origin(fault.replica)
                || fault.peers.as_ref().is_some_and(|peers| {
                    peers.is_empty()
                        || peers
                            .iter()
                            .any(|peer| *peer as usize >= n || *peer == fault.replica)
                })
            {
                return Err("invalid fixed-identity omission schedule; faulty identity cannot be an honest ingress".into());
            }
        }
        if n < 4
            || (n > 31 && n != 50)
            || ((n - 1) % 3 != 0 && n != 50)
            || id as usize >= n
            || self.addresses.len() != n
            || self
                .bind_addresses
                .as_ref()
                .is_some_and(|addresses| addresses.len() != n)
            || self.control_addresses.len() != n
            || self.key_files.len() != n
            || self.control_token.len() < 32
            || self.bound_ms == 0
            || self.bound_ms > 60_000
            || self
                .round_barrier_ms
                .is_some_and(|ms| ms == 0 || ms > self.bound_ms)
            || self
                .progress_pacing_ms
                .is_some_and(|ms| ms == 0 || ms > self.bound_ms)
            || (self.round_barrier_ms.is_some() && self.progress_pacing_ms.is_some())
            || self.workload_rounds == 0
            || self.workload_rounds > 32
            || self.max_runtime_ms < self.bound_ms * 8
            || self.max_runtime_ms > 3_700_000
            || self.silent.is_some_and(|s| s as usize >= n)
        {
            return Err("invalid process configuration".into());
        }
        let faulty_identities: BTreeSet<_> = self
            .silent
            .into_iter()
            .chain(self.fault.as_ref().map(|fault| fault.replica))
            .collect();
        if faulty_identities.len() > (n - 1) / 3 {
            return Err("configured faulty identities exceed the committee fault budget".into());
        }
        let mut addresses = BTreeSet::new();
        for address in &self.addresses {
            if address.ip().is_unspecified() || address.port() == 0 || !addresses.insert(*address) {
                return Err(
                    "advertised replica addresses must be distinct, specified, and nonzero".into(),
                );
            }
        }
        for address in &self.control_addresses {
            if !address.ip().is_loopback() || address.port() == 0 {
                return Err("control addresses must remain nonzero loopback endpoints; use authenticated deployment tunnels".into());
            }
        }
        if self
            .bind_addresses
            .as_ref()
            .is_some_and(|addresses| addresses.iter().any(|a| a.port() == 0))
        {
            return Err("replica bind ports must be nonzero".into());
        }
        let bind = self.bind_addresses.as_ref().unwrap_or(&self.addresses)[id as usize];
        let control = self.control_addresses[id as usize];
        if bind.port() == control.port()
            && (bind.ip().is_unspecified() || bind.ip() == control.ip())
        {
            return Err("replica and control listeners overlap".into());
        }
        let keys = self
            .public_keys
            .iter()
            .map(|bytes| PublicKey::from_bytes(bytes).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let c = Committee::with_profile(self.instance, keys, self.resource_profile)?;
        mmr::Config {
            context: c.context.clone(),
            chunk_capacity: self.chunk_capacity,
        }
        .validate()?;
        AvailabilityConfig::new(c.clone(), self.chunk_capacity)?;
        Ok(c)
    }
}

pub fn keygen(directory: &Path, n: usize) -> Result<Value, String> {
    if n != 50 && (n < 4 || n > 31 || (n - 1) % 3 != 0) {
        return Err(
            "key generation supports n = 3f + 1 in 4..=31 or n=50; select a compatible resource profile"
                .into(),
        );
    }
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let mut public_keys = Vec::new();
    let mut key_files = Vec::new();
    let mut entropy = File::open("/dev/urandom").map_err(|e| e.to_string())?;
    for id in 0..n {
        let mut seed = [0; 32];
        entropy.read_exact(&mut seed).map_err(|e| e.to_string())?;
        let secret = SecretKey::from_bytes(&seed).map_err(|e| e.to_string())?;
        public_keys.push(PublicKey::from(&secret).to_bytes().to_vec());
        let path = directory.join(format!("replica-{id}.key"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).map_err(|e| e.to_string())?;
        file.write_all(&seed).map_err(|e| e.to_string())?;
        key_files.push(fs::canonicalize(path).map_err(|e| e.to_string())?);
    }
    Ok(json!({"public_keys":public_keys,"key_files":key_files}))
}

/// Offline validation after collection, never part of a timed protocol handler.
/// This authenticates the finite request population and recomputes every ID;
/// it does not claim that benchmark timing logs are cryptographic attestations.
pub fn verify_workload_ledger(config: &Config, ledger: &Value) -> Result<Value, String> {
    let committee = config.validate(0)?;
    let load = config
        .sustained
        .as_ref()
        .ok_or("ledger verification requires sustained configuration")?;
    let ledgers = ledger
        .as_object()
        .ok_or("ledger must be keyed by replica")?;
    if ledgers.len() != committee.keys.len() {
        return Err("ledger must include every replica".into());
    }
    let mut verified_requests = 0u64;
    let mut verified_manifests = 0;
    for id in 0..committee.keys.len() as Id {
        let entry = ledgers
            .get(&id.to_string())
            .ok_or("missing replica ledger")?;
        let rows = entry["requests"]
            .as_array()
            .ok_or("missing request array")?;
        if !load.is_origin(id) {
            if !rows.is_empty() || !entry["manifest"].is_null() {
                return Err("non-ingress replica has a request manifest".into());
            }
        } else {
            let manifest: wire::Signed<workload::Manifest> =
                serde_json::from_value(entry["manifest"].clone()).map_err(|e| e.to_string())?;
            committee.verify_signature(&manifest)?;
            let expected = load.manifest(
                config.instance,
                id,
                committee.keys.len(),
                manifest.body.start_elapsed_us,
            );
            if expected.start_elapsed_us > config.max_runtime_ms * 1000 {
                return Err("manifest start exceeds the configured runtime horizon".into());
            }
            if manifest.signer != id
                || manifest.body != expected
                || rows.len() as u64 != expected.count
            {
                return Err("signed manifest differs from the configured finite workload".into());
            }
            let mut sequences = BTreeSet::new();
            for row in rows {
                let sequence = row["sequence"].as_u64().ok_or("request sequence missing")?;
                let digest: Digest =
                    serde_json::from_value(row["id"].clone()).map_err(|e| e.to_string())?;
                if sequence >= expected.count
                    || !sequences.insert(sequence)
                    || row["origin"].as_u64() != Some(id as u64)
                    || row["useful_bytes"].as_u64() != Some(expected.useful_bytes as u64)
                    || row["scheduled_us"].as_u64() != Some(expected.scheduled_us(sequence))
                    || digest != expected.transaction(sequence).id
                {
                    return Err("request identity or schedule differs from signed manifest".into());
                }
            }
            verified_manifests += 1;
            verified_requests += expected.count;
        }
        for output in entry["outputs"].as_array().ok_or("missing output array")? {
            let origin = output["origin"]
                .as_u64()
                .filter(|id| *id < committee.keys.len() as u64)
                .ok_or("output origin outside committee")? as Id;
            let sequence = output["sequence"]
                .as_u64()
                .ok_or("output sequence missing")?;
            let digest: Digest =
                serde_json::from_value(output["id"].clone()).map_err(|e| e.to_string())?;
            if !load.is_origin(origin)
                || sequence >= load.arrival_count(origin, committee.keys.len())
                || output["useful_bytes"].as_u64() != Some(load.useful_bytes() as u64)
                || digest
                    != workload::transaction(config.instance, origin, sequence, load.useful_bytes())
                        .id
            {
                return Err("output request identity differs from authenticated workload".into());
            }
        }
    }
    Ok(
        json!({"verified":true,"identity_version":2,"signed_manifests":verified_manifests,
        "verified_requests":verified_requests,"authentication":"strict Ed25519 manifest signature; SHA256 canonical request content/instance/origin/sequence"}),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    #[serde(rename = "type")]
    kind: String,
    token: String,
    #[serde(default)]
    request_id: Value,
    round: Option<u64>,
    count: Option<u64>,
    size: Option<usize>,
    start_unix_us: Option<u64>,
    offset: Option<usize>,
    limit: Option<usize>,
    receipt_origin: Option<Id>,
    receipt_stream: Option<String>,
}
type Control = shared_runtime::Control<Command>;
impl shared_runtime::ControlCommand for Command {
    fn token(&self) -> &str {
        &self.token
    }
}

#[derive(Clone, Default, Serialize)]
struct Counter {
    messages: u64,
    encoded_bytes: u64,
    x_bytes: u64,
    pi_bytes: u64,
    payload_bytes: u64,
}
impl Counter {
    fn add(&mut self, bytes: usize, x: usize, pi: usize, payload: usize) {
        self.messages += 1;
        self.encoded_bytes += bytes as u64;
        self.x_bytes += x as u64;
        self.pi_bytes += pi as u64;
        self.payload_bytes += payload as u64;
    }
}
#[derive(Default)]
struct LoadMetrics {
    start_us: Option<u64>,
    next_batch_us: u64,
    inserted: u64,
    completed: u64,
    latency_sum_us: u64,
    /// Sparse one-millisecond upper-bound buckets, including zero for zero.
    latency_histogram_ms: BTreeMap<u64, u64>,
    pending: BTreeMap<Digest, u64>,
    maximum_schedule_lag_us: u64,
    window_start: Option<Value>,
    window_end: Option<Value>,
    ingress: Option<Ingress>,
    batch: Vec<Arrival>,
    outputs: Vec<OutputEntry>,
    batches: Vec<BatchEntry>,
    m_out_bytes: u64,
    u_out_bytes: u64,
    processed_batches: usize,
    useful_output_count: u64,
    output_receipt: Option<Digest>,
    batch_receipt: Option<Digest>,
    materialized_ids: BTreeMap<Id, workload::Bitmap>,
    empty_inputs_with_pending_local_requests: u64,
    observed_prefix: u64,
    observed_output_cursor: usize,
}

impl LoadMetrics {
    fn track_pending(
        pending: &mut BTreeMap<Digest, u64>,
        receipt: &workload::AdmissionReceipt,
        arrival: &Arrival,
        admitted: u64,
    ) {
        if !receipt.completed.contains(arrival.sequence) {
            pending.insert(arrival.transaction.id, admitted);
        }
    }
}

#[derive(Serialize)]
struct OutputEntry {
    id: Digest,
    origin: Id,
    sequence: u64,
    useful_bytes: usize,
    output_index: usize,
    materialized_us: u64,
    post_handler_published_us: u64,
    exact_batch_id: Digest,
    state_hash: Digest,
}
#[derive(Serialize)]
struct BatchEntry {
    exact_batch_id: Digest,
    payload_bytes: usize,
    materialized_us: u64,
    post_handler_published_us: u64,
    output_index: usize,
}

fn scheduled_transactions(elapsed_us: u64, rate: u64) -> u64 {
    ((elapsed_us as u128 * rate as u128) / 1_000_000) as u64
}

fn process_resources() -> Value {
    #[cfg(unix)]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // getrusage writes a complete rusage to valid, correctly aligned storage.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } == 0 {
            let usage = unsafe { usage.assume_init() };
            let micros = |time: libc::timeval| {
                (time.tv_sec as u64)
                    .saturating_mul(1_000_000)
                    .saturating_add(time.tv_usec as u64)
            };
            let peak = usage.ru_maxrss as u64;
            #[cfg(target_os = "macos")]
            let peak_rss_bytes = peak;
            #[cfg(not(target_os = "macos"))]
            let peak_rss_bytes = peak.saturating_mul(1024);
            return json!({"user_cpu_us":micros(usage.ru_utime),"system_cpu_us":micros(usage.ru_stime),
                "peak_rss_bytes":peak_rss_bytes,"memory_boundary":"OS process peak resident set; includes runtime, protocol, workload and telemetry"});
        }
    }
    json!({"available":false})
}

/// Hash after an exact application-output prefix, without serializing its log.
fn execution_prefix_hash(executed: &[composed::Executed], count: u64) -> Result<Digest, String> {
    if count == 0 {
        return Ok(wire::hash(&"delugi/deterministic-materialization/v1"));
    }
    let index = usize::try_from(count - 1).map_err(|_| "prefix count exceeds platform range")?;
    executed
        .get(index)
        .map(|entry| entry.state_hash)
        .ok_or_else(|| "prefix is beyond local execution".into())
}

use shared_runtime::idle_receive;

// This envelope belongs to the authenticated transport layer, not the signed
// ordering protocol. A fixed count/length layout bounds allocation before any
// member is decoded. No member needs to be valid for its siblings to be tried.
const MAX_ORDERING_BUNDLE_MEMBERS: usize = 32;

#[cfg(test)]
fn encode_ordering_bundle<'a>(
    members: impl IntoIterator<Item = &'a [u8]>,
) -> Result<Vec<u8>, String> {
    encode_ordering_bundle_with_limit(members, wire::MAX_WIRE_BYTES)
}
fn encode_ordering_bundle_with_limit<'a>(
    members: impl IntoIterator<Item = &'a [u8]>,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let members: Vec<_> = members.into_iter().collect();
    if !(2..=MAX_ORDERING_BUNDLE_MEMBERS).contains(&members.len()) {
        return Err("ordering bundle member count is outside 2..=32".into());
    }
    let mut size = 4usize;
    for member in &members {
        size = size
            .checked_add(4)
            .and_then(|n| n.checked_add(member.len()))
            .ok_or("ordering bundle length overflow")?;
        if size > limit {
            return Err("ordering bundle exceeds the frame payload limit".into());
        }
    }
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for member in members {
        bytes.extend_from_slice(&(member.len() as u32).to_le_bytes());
        bytes.extend_from_slice(member);
    }
    Ok(bytes)
}

#[cfg(test)]
fn decode_ordering_bundle(bytes: &[u8]) -> Result<Vec<&[u8]>, String> {
    decode_ordering_bundle_with_limit(bytes, wire::MAX_WIRE_BYTES)
}
fn decode_ordering_bundle_with_limit(bytes: &[u8], limit: usize) -> Result<Vec<&[u8]>, String> {
    if bytes.len() < 4 || bytes.len() > limit {
        return Err("invalid ordering bundle size".into());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if !(2..=MAX_ORDERING_BUNDLE_MEMBERS).contains(&count) {
        return Err("ordering bundle member count is outside 2..=32".into());
    }
    let mut members = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        let length = bytes
            .get(offset..offset + 4)
            .ok_or("truncated ordering bundle length")?;
        let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
        offset += 4;
        let end = offset
            .checked_add(length)
            .ok_or("ordering bundle length overflow")?;
        members.push(
            bytes
                .get(offset..end)
                .ok_or("truncated ordering bundle member")?,
        );
        offset = end;
    }
    if offset != bytes.len() {
        return Err("ordering bundle has trailing bytes".into());
    }
    Ok(members)
}

fn recipients(to: Option<Id>, own: Id, count: usize) -> Vec<Id> {
    to.map_or_else(|| (0..count as Id).collect(), |id| vec![id])
        .into_iter()
        .filter(|id| *id != own)
        .collect()
}

#[derive(Clone, Debug)]
struct OrderingToSend {
    bytes: Vec<u8>,
    kind: String,
    index: u64,
    x: usize,
    pi: usize,
}
impl OrderingToSend {
    fn round(&self) -> u64 {
        if matches!(self.kind.as_str(), "HISTORY3" | "CLOSED") {
            self.index - 3
        } else {
            self.index
        }
    }
}

struct OrderingBatcher {
    // Per-peer order is exactly the original effect order, including H3/CLOSED.
    pending: BTreeMap<Id, (usize, Vec<OrderingToSend>)>,
    limit: usize,
}
impl Default for OrderingBatcher {
    fn default() -> Self {
        Self {
            pending: BTreeMap::new(),
            limit: wire::MAX_WIRE_BYTES,
        }
    }
}
impl OrderingBatcher {
    fn push(&mut self, peer: Id, message: OrderingToSend) -> Vec<Vec<OrderingToSend>> {
        let mut ready = Vec::new();
        let size = 4 + message.bytes.len();
        if self.pending.get(&peer).is_some_and(|(bytes, messages)| {
            messages.len() == MAX_ORDERING_BUNDLE_MEMBERS || bytes + size > self.limit
        }) {
            ready.push(self.take(peer).unwrap());
        }
        // A valid single wire message can fill the frame limit without room
        // for the bundle's length fields. Send it in the unchanged single form.
        if 4 + size > self.limit {
            ready.push(vec![message]);
        } else {
            let entry = self.pending.entry(peer).or_insert_with(|| (4, Vec::new()));
            entry.0 += size;
            entry.1.push(message);
        }
        ready
    }
    fn take(&mut self, peer: Id) -> Option<Vec<OrderingToSend>> {
        self.pending.remove(&peer).map(|(_, messages)| messages)
    }
    fn drain(self) -> impl Iterator<Item = (Id, Vec<OrderingToSend>)> {
        self.pending
            .into_iter()
            .map(|(peer, (_, messages))| (peer, messages))
    }
}

struct LogicalReceived {
    frame: Received,
    member_index: u32,
    member_count: u32,
}

#[cfg(test)]
fn expand_received(frame: Received) -> Result<VecDeque<LogicalReceived>, String> {
    expand_received_with_limit(frame, wire::MAX_WIRE_BYTES)
}
fn expand_received_with_limit(
    frame: Received,
    limit: usize,
) -> Result<VecDeque<LogicalReceived>, String> {
    if frame.layer != Layer::OrderingBundle {
        return Ok(VecDeque::from([LogicalReceived {
            frame,
            member_index: 0,
            member_count: 1,
        }]));
    }
    let members = decode_ordering_bundle_with_limit(&frame.payload, limit)?;
    let member_count = members.len() as u32;
    Ok(members
        .into_iter()
        .enumerate()
        .map(|(index, payload)| LogicalReceived {
            frame: Received {
                from: frame.from,
                sequence: frame.sequence,
                layer: Layer::Ordering,
                payload: payload.to_vec(),
                received_at: frame.received_at,
            },
            member_index: index as u32,
            member_count,
        })
        .collect())
}

struct Runtime {
    committee: Committee,
    causal: Option<CausalTrace>,
    config: Config,
    id: Id,
    node: Node,
    transport: Transport,
    control: Control,
    origin: Instant,
    wall_origin: u64,
    timers: shared_runtime::TimerQueue,
    active: bool,
    started: bool,
    quiesced: bool,
    quiesced_at_us: Option<u64>,
    produced: u64,
    emitted_transactions: usize,
    processed_messages: u64,
    rejected_protocol_messages: u64,
    post_cutoff_frames: u64,
    post_cutoff_messages: u64,
    silent_ignored_frames: u64,
    by_kind: BTreeMap<String, Counter>,
    by_peer: BTreeMap<Id, Counter>,
    by_index: BTreeMap<u64, Counter>,
    fault_dropped: BTreeMap<String, Counter>,
    proposals: BTreeMap<u64, u64>,
    commits: BTreeMap<u64, u64>,
    measured_ordered: BTreeMap<u64, u64>,
    measured_materialized: BTreeMap<u64, u64>,
    load: LoadMetrics,
    workload_key: Keypair,
}
impl Runtime {
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
    fn omit_message(
        &mut self,
        peer: Id,
        kind: &str,
        bytes: usize,
        x: usize,
        pi: usize,
        payload: usize,
    ) -> bool {
        let omit = self.load.start_us.is_some_and(|start| {
            let now = self.origin.elapsed().as_micros() as u64;
            now >= start
                && self
                    .config
                    .fault
                    .as_ref()
                    .is_some_and(|fault| fault.omits(self.id, peer, kind, (now - start) / 1000))
        });
        if omit {
            self.fault_dropped
                .entry(kind.into())
                .or_default()
                .add(bytes, x, pi, payload);
        }
        omit
    }
    fn log(&self, mut event: Value) -> Result<(), String> {
        if self.config.sustained.is_some()
            && !matches!(
                event["event"].as_str(),
                Some(
                    "ready"
                        | "started"
                        | "load_scheduled"
                        | "load_window_start"
                        | "load_window_end"
                        | "quiesced"
                        | "protocol_rejected"
                        | "fatal"
                        | "final"
                )
            )
        {
            return Ok(());
        }
        event["replica"] = json!(self.id);
        event["observed_unix_us"] = json!(unix_us());
        event["elapsed_us"] = json!(self.origin.elapsed().as_micros() as u64);
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        serde_json::to_writer(&mut out, &event).map_err(|e| e.to_string())?;
        out.write_all(b"\n")
            .and_then(|_| out.flush())
            .map_err(|e| e.to_string())
    }
    fn effects(&mut self, effects: Vec<Effect>) -> Result<(), String> {
        let mut pending = OrderingBatcher {
            limit: self.committee.max_wire_bytes(),
            ..OrderingBatcher::default()
        };
        for effect in effects {
            match effect {
                Effect::Ordering(effect) => match effect {
                    OrderingEffect::Send { to, message } => {
                        let (kind, round) = message_kind(&message);
                        let (x, pi) = match &message {
                            wire::Message::Propose(p) => (p.value.len(), p.witness.len()),
                            wire::Message::Vote { value, .. } => {
                                (value.as_ref().map_or(0, Vec::len), 0)
                            }
                            _ => (0, 0),
                        };
                        let bytes = self.committee.encode(&message)?;
                        let index = if matches!(kind, "HISTORY3" | "CLOSED") {
                            round + 3
                        } else {
                            round
                        };
                        if self.config.ordering_batch {
                            let message = OrderingToSend {
                                bytes,
                                kind: kind.into(),
                                index,
                                x,
                                pi,
                            };
                            for peer in recipients(to, self.id, self.config.addresses.len()) {
                                for packet in pending.push(peer, message.clone()) {
                                    self.send_ordering_packet(peer, packet)?;
                                }
                            }
                        } else {
                            self.send(to, Layer::Ordering, bytes, kind, index, x, pi, 0)?;
                        }
                        if kind == "PROPOSE" && self.config.sustained.is_none() {
                            self.proposals.insert(round, unix_us());
                            if let wire::Message::Propose(proposal) = &message {
                                let descriptor: crate::availability::Descriptor =
                                    self.committee.decode(&proposal.value)?;
                                let availability_proof: crate::availability::AvailabilityProof =
                                    self.committee.decode(&proposal.witness)?;
                                self.log(json!({"event":"proposal","round":round,"message":message,
                                    "descriptor":descriptor,"availability_proof":availability_proof}))?;
                            }
                        }
                    }
                    OrderingEffect::Wake { at } => {
                        self.timers.insert(at);
                    }
                    OrderingEffect::DirectCommit { round, digest } => {
                        self.commits.insert(round, unix_us());
                        self.log(json!({"event":"direct_commit","round":round,"digest":digest}))?;
                    }
                    OrderingEffect::Deliver(d) => {
                        self.measured_ordered.insert(d.round, unix_us());
                        self.log(
                            json!({"event":"ordered_descriptor","round":d.round,"digest":d.digest}),
                        )?;
                    }
                    OrderingEffect::Notice { kind, round } => {
                        self.log(json!({"event":kind,"round":round}))?
                    }
                },
                Effect::Send { to, message } => {
                    if let composed::Message::Report { request, base } = &message {
                        if self.config.sustained.is_none() {
                            self.log(json!({"event":"report_broadcast","round":base.opportunity,
                            "report":request,"base":base}))?;
                        }
                    }
                    let (kind, index, payload) = match &message {
                        composed::Message::Batch(r) => {
                            ("BATCH", r.header.body.height, r.payload.len())
                        }
                        composed::Message::Observation(o) => ("OBS", o.body.opportunity, 0),
                        composed::Message::Report { base, .. } => ("REPORT", base.opportunity, 0),
                        composed::Message::Fetch { target, .. } => ("FETCH", target.height, 0),
                        composed::Message::Data(d) => (
                            "DATA",
                            d.to.height,
                            d.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                        composed::Message::DataPart(d) => (
                            "DATA",
                            d.requested_to.height,
                            d.data.records.iter().map(|r| r.payload.len()).sum(),
                        ),
                    };
                    // Preserve each peer's cross-layer FIFO. Messages for other
                    // peers can remain pending until their own boundary/end.
                    for peer in recipients(to, self.id, self.config.addresses.len()) {
                        if let Some(packet) = pending.take(peer) {
                            self.send_ordering_packet(peer, packet)?;
                        }
                    }
                    self.send(
                        to,
                        Layer::Dissemination,
                        self.committee.encode(&message)?,
                        kind,
                        index,
                        0,
                        0,
                        payload,
                    )?;
                }
                Effect::Trace(mut value) => {
                    // Preserve the engine's handler-entry milliseconds separately.
                    if let Some(at) = value.as_object_mut().and_then(|o| o.remove("at")) {
                        value["protocol_entry_ms"] = at;
                    }
                    if value["event"] == "ordering_input_ready" {
                        let pending = self.load.ingress.as_ref().map_or(0, |i| {
                            i.admitted
                                .load(Ordering::Acquire)
                                .saturating_sub(self.load.completed)
                        });
                        value["pending_local_honest_requests"] = json!(pending);
                        if pending > 0
                            && value["construction"]["wholly_empty_inputs"].as_u64() == Some(1)
                        {
                            self.load.empty_inputs_with_pending_local_requests += 1;
                        }
                        value["event"] = json!("input_ready");
                    }
                    if value["event"] == "materialized" {
                        if let Some(round) = value["round"].as_u64() {
                            self.measured_materialized.insert(round, unix_us());
                        }
                    }
                    self.log(value)?;
                }
            }
        }
        for (peer, packet) in pending.drain() {
            self.send_ordering_packet(peer, packet)?;
        }
        // Preserve application append and post-handler publication separately.
        // Outbound effect processing cannot move the materialization endpoint.
        let detailed = self.config.observer_mode == workload::ObserverMode::Full;
        let published_at = if detailed {
            self.origin.elapsed().as_micros() as u64
        } else {
            0
        };
        let mut request_contents = BTreeMap::new();
        if let Some(config) = &self.config.sustained {
            for (index, batch) in self
                .node
                .materialized_batches
                .iter()
                .enumerate()
                .skip(self.load.processed_batches)
            {
                let digest = crate::batch::header_digest(&batch.header);
                self.load.m_out_bytes += batch.payload.len() as u64;
                self.load.batch_receipt = Some(workload::batch_step(
                    self.load.batch_receipt.unwrap_or_else(workload::batch_seed),
                    batch,
                ));
                if detailed {
                    self.load.batches.push(BatchEntry {
                        exact_batch_id: digest,
                        payload_bytes: batch.payload.len(),
                        materialized_us: self.node.batch_observed_us[index],
                        post_handler_published_us: published_at,
                        output_index: index + 1,
                    });
                }
                if let Ok(transactions) = wire::decode::<Vec<composed::Transaction>>(&batch.payload)
                {
                    for tx in transactions {
                        let identity = workload::identify(self.config.instance, &tx).filter(
                            |(origin, sequence, bytes)| {
                                (*origin as usize) < self.config.addresses.len()
                                    && config.is_origin(*origin)
                                    && *sequence
                                        < config.arrival_count(*origin, self.config.addresses.len())
                                    && *bytes == config.useful_bytes()
                            },
                        );
                        request_contents.entry((digest, tx.id)).or_insert(identity);
                    }
                }
            }
        }
        for (index, entry) in self
            .node
            .executed
            .iter()
            .enumerate()
            .skip(self.emitted_transactions)
        {
            let completed_at = if detailed {
                self.node.output_observed_us[index]
            } else {
                0
            };
            if self.config.sustained.is_some() {
                self.load.output_receipt = Some(workload::output_step(
                    self.load
                        .output_receipt
                        .unwrap_or_else(workload::output_seed),
                    entry,
                ));
            }
            self.load.pending.remove(&entry.transaction);
            if self.config.sustained.is_some() {
                if let Some(Some((origin, sequence, useful_bytes))) =
                    request_contents.get(&(entry.batch_digest, entry.transaction))
                {
                    self.load.u_out_bytes += *useful_bytes as u64;
                    self.load.useful_output_count += 1;
                    self.load
                        .materialized_ids
                        .get_mut(origin)
                        .ok_or("missing finite origin receipt")?
                        .insert(*sequence);
                    if detailed {
                        self.load.outputs.push(OutputEntry {
                            id: entry.transaction,
                            origin: *origin,
                            sequence: *sequence,
                            useful_bytes: *useful_bytes,
                            output_index: index + 1,
                            materialized_us: completed_at,
                            post_handler_published_us: published_at,
                            exact_batch_id: entry.batch_digest,
                            state_hash: entry.state_hash,
                        });
                    }
                    if *origin == self.id {
                        if let Some(ingress) = &self.load.ingress {
                            // Eligibility is latched at the first output, never
                            // reconstructed by intersecting a later admission.
                            let membership = ingress.receipt.lock().unwrap();
                            let eligible = membership.completed.contains(*sequence);
                            self.load.completed = membership.completed.ones;
                            if detailed && eligible {
                                if let Some(timing) =
                                    ingress.timings.lock().unwrap().get_mut(sequence)
                                {
                                    let admitted = timing
                                        .admitted_us
                                        .ok_or("eligible output lacks admission time")?;
                                    let latency = completed_at
                                        .checked_sub(admitted)
                                        .ok_or("append precedes admission")?;
                                    self.load.latency_sum_us += latency;
                                    *self
                                        .load
                                        .latency_histogram_ms
                                        .entry(latency.div_ceil(1000))
                                        .or_default() += 1;
                                    timing.materialized_us = Some(completed_at);
                                    timing.post_handler_published_us = Some(published_at);
                                }
                            }
                        }
                    }
                }
                continue;
            }
            self.log(
                json!({"event":"transaction_materialized","transaction":entry.transaction,
                "round":entry.round,"producer":entry.producer,"height":entry.height,
                "batch_digest":entry.batch_digest,"state_hash":entry.state_hash}),
            )?;
        }
        self.emitted_transactions = self.node.executed.len();
        self.load.processed_batches = self.node.materialized_batches.len();
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        to: Option<Id>,
        layer: Layer,
        bytes: Vec<u8>,
        kind: &str,
        index: u64,
        x: usize,
        pi: usize,
        payload: usize,
    ) -> Result<(), String> {
        for peer in recipients(to, self.id, self.config.addresses.len()) {
            if self.omit_message(peer, kind, bytes.len(), x, pi, payload) {
                continue;
            }
            let round = if matches!(kind, "HISTORY3" | "CLOSED") {
                index - 3
            } else if matches!(kind, "BATCH" | "FETCH" | "DATA") {
                0
            } else {
                index
            };
            let enqueue_start = self
                .causal
                .as_ref()
                .filter(|t| round != 0 && t.sampled(round))
                .map(CausalTrace::now_us);
            let accounting = match kind {
                // Bincode Record ends with its payload vector. Its length word,
                // signed header and outer enum tag remain evidence/control.
                "BATCH" => PayloadAccounting::BatchPayloadTail { bytes: payload },
                "FETCH" | "DATA" => PayloadAccounting::Repair,
                _ => PayloadAccounting::EvidenceControl,
            };
            let receipt =
                self.transport
                    .send_or_defer_accounted(peer, layer, bytes.clone(), accounting)?;
            let sequence = receipt.sequence;
            if let Some(start) = enqueue_start {
                self.causal.as_ref().unwrap().span(if receipt.deferred {"transport_deferred_accept"} else {"transport_enqueue"}, round, start,
                    json!({"kind":kind,"peer":peer,"signer":self.id,"sequence":sequence,"member_index":0,"member_count":1,"payload_bytes":bytes.len(),"deferred":receipt.deferred}));
            }
            self.by_kind
                .entry(kind.into())
                .or_default()
                .add(bytes.len(), x, pi, payload);
            self.by_peer
                .entry(peer)
                .or_default()
                .add(bytes.len(), x, pi, payload);
            self.by_index
                .entry(index)
                .or_default()
                .add(bytes.len(), x, pi, payload);
        }
        Ok(())
    }
    fn send_ordering_packet(
        &mut self,
        peer: Id,
        messages: Vec<OrderingToSend>,
    ) -> Result<(), String> {
        let messages: Vec<_> = messages
            .into_iter()
            .filter(|message| {
                !self.omit_message(
                    peer,
                    &message.kind,
                    message.bytes.len(),
                    message.x,
                    message.pi,
                    0,
                )
            })
            .collect();
        if messages.is_empty() {
            return Ok(());
        }
        if messages.len() == 1 {
            let message = messages.into_iter().next().unwrap();
            return self.send(
                Some(peer),
                Layer::Ordering,
                message.bytes,
                &message.kind,
                message.index,
                message.x,
                message.pi,
                0,
            );
        }
        let payload = encode_ordering_bundle_with_limit(
            messages.iter().map(|message| message.bytes.as_slice()),
            self.committee.max_wire_bytes(),
        )?;
        let enqueue_start = self.causal.as_ref().map(CausalTrace::now_us);
        let receipt = self.transport.send_or_defer_accounted(
            peer,
            Layer::OrderingBundle,
            payload,
            PayloadAccounting::OrderingBundle {
                member_lengths: messages
                    .iter()
                    .map(|message| message.bytes.len() as u32)
                    .collect(),
            },
        )?;
        let sequence = receipt.sequence;
        for (member_index, message) in messages.iter().enumerate() {
            let round = message.round();
            if let Some(trace) = &self.causal {
                if trace.sampled(round) {
                    trace.span(if receipt.deferred {"transport_deferred_accept"} else {"transport_enqueue"}, round, enqueue_start.unwrap(),
                        json!({"kind":message.kind,"peer":peer,"signer":self.id,"sequence":sequence,
                            "member_index":member_index,"member_count":messages.len(),"payload_bytes":message.bytes.len(),"deferred":receipt.deferred}));
                }
            }
            self.by_kind.entry(message.kind.clone()).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
            self.by_peer.entry(peer).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
            self.by_index.entry(message.index).or_default().add(
                message.bytes.len(),
                message.x,
                message.pi,
                0,
            );
        }
        Ok(())
    }
    fn compact_snapshot(&self) -> Value {
        let now_us = self.origin.elapsed().as_micros() as u64;
        let scheduled = self
            .load
            .ingress
            .as_ref()
            .map_or(0, |i| i.scheduled.load(Ordering::Acquire));
        let admitted = self
            .load
            .ingress
            .as_ref()
            .map_or(0, |i| i.admitted.load(Ordering::Acquire));
        let rejected = self
            .load
            .ingress
            .as_ref()
            .map_or(0, |i| i.rejected.load(Ordering::Acquire));
        let load = json!({"inserted":self.load.inserted,"completed":self.load.completed,"pending":self.load.ingress.as_ref().map_or(0,|i|i.receipt.lock().unwrap().ready_pending),
                "scheduled":scheduled,"admitted":admitted,"batch_ready":self.load.inserted,"rejected":rejected,
                "arrival_pending":admitted.saturating_sub(self.load.inserted),"backpressure":rejected,
                "arrival_finished":self.load.ingress.as_ref().map_or(true, |i|i.finished.load(Ordering::Acquire)),
                "m_out_bytes":self.load.m_out_bytes,"u_out_bytes":self.load.u_out_bytes,
                "m_out_batches":self.load.processed_batches,"useful_output_count":self.load.useful_output_count,
                "observer_mode":self.config.observer_mode,"latency_available":self.config.observer_mode==workload::ObserverMode::Full,
                "useful_bytes_per_request":self.config.sustained.as_ref().map(|c|c.useful_bytes()),
                "encoded_transaction_bytes":self.config.sustained.as_ref().map(|c|c.encoded_transaction_bytes()),
                "window_start_elapsed_us":self.load.start_us.zip(self.config.sustained.as_ref()).map(|(s,c)|s+c.warmup_ms*1000),
                "window_end_elapsed_us":self.load.start_us.zip(self.config.sustained.as_ref()).map(|(s,c)|s+(c.warmup_ms+c.measurement_ms)*1000),
                "latency_sum_us":self.load.latency_sum_us,"latency_histogram_ms":self.load.latency_histogram_ms,
                "maximum_schedule_lag_us":self.load.maximum_schedule_lag_us,"start_elapsed_us":self.load.start_us,
                "expected_total":self.config.sustained.as_ref().map(|c|c.arrival_count(self.id,self.config.addresses.len()))});
        let mut snapshot = json!({"replica":self.id,"started":self.started,"quiesced":self.quiesced,
            "elapsed_us":now_us,"observed_unix_us":unix_us(),
            "current_round":self.node.ordering.current_round(),"last_delivered":self.node.ordering.last_delivered(),
            "executed_count":self.node.executed.len(),"materialized_batch_count":self.node.materialized_batches.len(),
            "state_hash":self.node.state_hash(),"cumulative_heights":self.node.cumulative_heights(),
            "pending_materialization":self.node.pending_materialization(),"processed_messages":self.processed_messages,
            "rejected_protocol_messages":self.rejected_protocol_messages,"post_cutoff_frames":self.post_cutoff_frames,"post_cutoff_messages":self.post_cutoff_messages,
            "transport":self.transport.snapshot(),"ordering_batch":self.config.ordering_batch,"round_barrier_ms":self.config.round_barrier_ms,"protocol_by_kind":self.by_kind,
            "load":load});
        snapshot["progress_pacing_ms"] = json!(self.config.progress_pacing_ms);
        snapshot["resource_profile"] = json!(self.config.resource_profile);
        snapshot["storage"] = json!(self.node.store.storage_snapshot());
        snapshot["quiesced_at_us"] = json!(self.quiesced_at_us);
        snapshot["fault_omitted"] = json!(self.fault_dropped);
        snapshot["construction"] = json!(self.node.construction_metrics);
        snapshot["empty_inputs_with_pending_local_requests"] =
            json!(self.load.empty_inputs_with_pending_local_requests);
        snapshot["operation_costs"] = json!(crate::meter::snapshot());
        snapshot["process_resources"] = process_resources();
        snapshot["retained_state"] = json!({"batch_records":self.node.store.record_count(),
            "custody_registrations":self.node.store.custody_count(),
            "stored_payload_bytes":self.node.store.retained_payload_bytes(),
            "materialized_payload_copy_bytes":self.load.m_out_bytes,
            "observations":self.node.observations.len(),"output_entries":self.node.executed.len()});
        snapshot["observer_mode"] = json!(self.config.observer_mode);
        snapshot["detailed_observer_storage"] = json!({"request_timing_rows": self.load.ingress.as_ref().map_or(0, |i|i.timings.lock().unwrap().len()),
            "output_rows":self.load.outputs.len(),"batch_rows":self.load.batches.len(),"pending_timestamps":self.load.pending.len(),
            "output_timestamps":self.node.output_observed_us.len(),"batch_timestamps":self.node.batch_observed_us.len()});
        snapshot["ordering_mode"] = json!(self.config.ordering_mode);
        snapshot["protocol_counter_boundary"] = json!("accepted into bounded transport including deferred FIFO; actual writer enqueues are transport layer enqueued_* counters");
        if let Some(trace) = &self.causal {
            snapshot["causal_trace"] = trace.summary();
        }
        snapshot
    }
    fn snapshot(&self) -> Value {
        if self.config.sustained.is_some() {
            let mut value = self.compact_snapshot();
            value["measurement_start"] = json!(self.load.window_start);
            value["measurement_end"] = json!(self.load.window_end);
            return value;
        }
        let mut snapshot = json!({"replica":self.id,"silent":self.config.silent==Some(self.id),"started":self.started,"quiesced":self.quiesced,
            "ordering":{"current_round":self.node.ordering.current_round(),"last_delivered":self.node.ordering.last_delivered(),
                "deliveries":self.node.ordering.deliveries(),"statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>()},
            "statuses":self.node.ordering.statuses().range(..=self.config.workload_rounds).collect::<BTreeMap<_,_>>(),
            "deliveries":self.node.ordering.deliveries(),"commits":self.commits,"proposals":self.proposals,
            "input_ready":self.node.input_ready,"ordered_at":self.node.ordered_at,"executed_at":self.node.executed_at,
            "protocol_timestamp_units":"milliseconds from process origin sampled at handler entry",
            "observed_ordered_unix_us":self.measured_ordered,"observed_materialized_unix_us":self.measured_materialized,
            "executed":self.node.executed,"executed_rounds":self.node.executed_rounds,"state_hash":self.node.state_hash(),
            "materialized_batches":self.node.materialized_batches,"cumulative_heights":self.node.cumulative_heights(),
            "holding_heights":(0..self.config.addresses.len() as Id).map(|id|self.node.store.checkpoints(id).last().map_or(0,|p|p.height)).collect::<Vec<_>>(),
            "observations":self.node.observations.len(),"observation_evidence":self.node.observations,
            "record_count":self.node.store.record_count(),"custody_count":self.node.store.custody_count(),
            "pending_materialization":self.node.pending_materialization(),"processed_messages":self.processed_messages,
            "rejected_protocol_messages":self.rejected_protocol_messages,
            "pending_timer_count":self.timers.len(),"next_timer_ms":self.timers.first(),
            "post_cutoff_frames":self.post_cutoff_frames,"post_cutoff_messages":self.post_cutoff_messages,"silent_ignored_frames":self.silent_ignored_frames,"transport":self.transport.snapshot(),"ordering_batch":self.config.ordering_batch,"round_barrier_ms":self.config.round_barrier_ms,"control":self.control.snapshot(),
            "protocol":{"by_kind":self.by_kind,"by_peer":self.by_peer,"by_index":self.by_index},
            "elapsed_us":self.origin.elapsed().as_micros() as u64,"observed_unix_us":unix_us(),"wall_origin_unix_us":self.wall_origin});
        snapshot["storage"] = json!(self.node.store.storage_snapshot());
        snapshot["progress_pacing_ms"] = json!(self.config.progress_pacing_ms);
        snapshot["ordering_mode"] = json!(self.config.ordering_mode);
        snapshot["protocol_counter_boundary"] = json!("accepted into bounded transport including deferred FIFO; actual writer enqueues are transport layer enqueued_* counters");
        snapshot
    }
    fn load_tick(&mut self) -> Result<bool, String> {
        let Some(config) = self.config.sustained.clone() else {
            return Ok(false);
        };
        let Some(start) = self.load.start_us else {
            return Ok(false);
        };
        let now_us = self.origin.elapsed().as_micros() as u64;
        if now_us < start {
            return Ok(false);
        }
        let elapsed = now_us - start;
        if elapsed >= config.warmup_ms * 1000 && self.load.window_start.is_none() {
            self.load.window_start = Some(self.compact_snapshot());
            self.log(json!({"event":"load_window_start"}))?;
        }
        let duration_us = (config.warmup_ms + config.measurement_ms) * 1000;
        if elapsed >= duration_us && self.load.window_end.is_none() {
            self.load.window_end = Some(self.compact_snapshot());
            self.log(json!({"event":"load_window_end"}))?;
        }
        let Some(ingress) = &self.load.ingress else {
            return Ok(false);
        };
        let capacity = config
            .max_batch_transactions
            .min((crate::batch::MAX_BATCH_PAYLOAD - 8) / config.encoded_transaction_bytes());
        while self.load.batch.len() < capacity {
            match ingress.receiver.try_recv() {
                Ok(arrival) => self.load.batch.push(arrival),
                Err(_) => break,
            }
        }
        if self.load.batch.is_empty()
            || (elapsed < self.load.next_batch_us && self.load.batch.len() < capacity)
        {
            return Ok(false);
        }
        self.load.next_batch_us = (elapsed / (config.batch_ms * 1000) + 1) * config.batch_ms * 1000;
        let arrivals = std::mem::take(&mut self.load.batch);
        let mut txs = Vec::with_capacity(arrivals.len());
        {
            // Same channel-publication barrier in both modes.
            let membership = ingress.receipt.lock().unwrap();
            let records = if self.config.observer_mode == workload::ObserverMode::Full {
                Some(ingress.timings.lock().unwrap())
            } else {
                None
            };
            for arrival in &arrivals {
                if !membership.admitted.contains(arrival.sequence) {
                    return Err("accepted arrival lacks admission receipt".into());
                }
                if let Some(records) = &records {
                    let admitted = records[&arrival.sequence]
                        .admitted_us
                        .ok_or("accepted arrival lacks admission time")?;
                    self.load.maximum_schedule_lag_us = self.load.maximum_schedule_lag_us.max(
                        admitted
                            .saturating_sub(ingress.manifest.body.scheduled_us(arrival.sequence)),
                    );
                    LoadMetrics::track_pending(
                        &mut self.load.pending,
                        &membership,
                        arrival,
                        admitted,
                    );
                }
                txs.push(arrival.transaction.clone());
            }
        }
        let e = self.node.produce(self.now_ms(), wire::encode(&txs)?)?;
        if let Some(ingress) = &self.load.ingress {
            let mut membership = ingress.receipt.lock().unwrap();
            for arrival in &arrivals {
                membership.mark_ready(arrival.sequence);
            }
            if self.config.observer_mode == workload::ObserverMode::Full {
                let ready = self.origin.elapsed().as_micros() as u64;
                let mut records = ingress.timings.lock().unwrap();
                for arrival in &arrivals {
                    records.get_mut(&arrival.sequence).unwrap().batch_ready_us = Some(ready);
                }
            }
        }
        self.load.inserted += arrivals.len() as u64;
        self.produced += 1;
        self.effects(e)?;
        Ok(true)
    }
    fn command(&mut self, c: &Command) -> Result<Value, String> {
        let now = self.now_ms();
        match c.kind.as_str() {
            "load" => {
                if !self.started
                    || self.config.sustained.is_none()
                    || self.load.start_us.is_some()
                    || self.quiesced
                {
                    return Err(
                        "load requires a started sustained replica with no previous schedule"
                            .into(),
                    );
                }
                let requested = c
                    .start_unix_us
                    .ok_or("load requires a future start_unix_us")?;
                let wall = unix_us();
                if requested <= wall || requested - wall > 10_000_000 {
                    return Err("load start must be within the next ten seconds".into());
                }
                self.load.start_us =
                    Some(self.origin.elapsed().as_micros() as u64 + requested - wall);
                let config = self.config.sustained.as_ref().unwrap();
                self.load.next_batch_us = config.batch_ms * 1000;
                if config.is_origin(self.id) {
                    let manifest = config.manifest(
                        self.config.instance,
                        self.id,
                        self.config.addresses.len(),
                        self.load.start_us.unwrap(),
                    );
                    self.load.ingress = Some(Ingress::start_with_mode(
                        manifest,
                        &self.workload_key,
                        self.origin,
                        config.arrival_queue_capacity,
                        self.config.observer_mode,
                    ));
                    let ingress = self.load.ingress.as_ref().unwrap();
                    let membership = ingress.receipt.clone();
                    if let Some(previous) = self.load.materialized_ids.get(&self.id) {
                        membership.lock().unwrap().seen_output = previous.clone();
                    }
                    let manifest = ingress.manifest.body.clone();
                    self.node.observe_output_receipts(move |tx, append| {
                        if let Some((origin, sequence, useful)) =
                            workload::identify(manifest.instance, tx)
                        {
                            if origin == manifest.origin
                                && sequence < manifest.count
                                && useful == manifest.useful_bytes
                            {
                                let mut membership = membership.lock().unwrap();
                                append();
                                membership.materialized(sequence);
                                return;
                            }
                        }
                        append();
                    });
                }
                self.log(json!({"event":"load_scheduled","start_unix_us":requested}))?;
                Ok(json!({"start_unix_us":requested}))
            }
            "prepare" => {
                if self.started || self.quiesced {
                    return Err("prepare must precede ordering start".into());
                }
                // Enable independent batch production/reception before starting
                // the finite ordering experiment. Reporting remains driven by
                // actual ordering round entries and signed leader requests.
                self.active = true;
                Ok(json!({"prepared":true}))
            }
            "start" => {
                if self.quiesced {
                    return Err("run is quiesced".into());
                }
                if !self.started {
                    self.started = true;
                    self.active = true;
                    if self.config.silent != Some(self.id) {
                        let e = self.node.start(now)?;
                        self.effects(e)?;
                    }
                    self.log(
                        json!({"event":"started","silent":self.config.silent==Some(self.id)}),
                    )?;
                }
                Ok(json!({"started":true}))
            }
            "submit" => {
                if !self.active || self.config.silent == Some(self.id) {
                    return Err("replica is not active for submissions".into());
                }
                let r = c.round.ok_or("submit requires round")?;
                let count = c.count.unwrap_or(2);
                let size = c.size.unwrap_or(32);
                if r != self.produced + 1
                    || r > self.config.workload_rounds
                    || count == 0
                    || count > 128
                    || size > 4096
                {
                    return Err("submission must be the next bounded workload batch".into());
                }
                let txs = transactions(self.id, r, count, size);
                let payload = wire::encode(&txs)?;
                if payload.len() > crate::batch::MAX_BATCH_PAYLOAD {
                    return Err("batch payload limit exceeded".into());
                }
                let e = self.node.produce(now, payload)?;
                self.produced = r;
                self.effects(e)?;
                let ids: Vec<_> = txs.iter().map(|t| t.id).collect();
                self.log(json!({"event":"submitted","round":r,"height":r,"transactions":ids}))?;
                Ok(json!({"transactions":ids,"height":r,"round":r}))
            }
            "report" => {
                if !self.active || self.config.silent == Some(self.id) {
                    return Err("replica cannot report".into());
                }
                let r = c.round.ok_or("report requires round")?;
                if r == 0 || r > self.config.workload_rounds {
                    return Err("unknown reporting opportunity".into());
                }
                let e = self.node.report(now, r)?;
                self.effects(e)?;
                Ok(json!({"round":r,"reported":true}))
            }
            "snapshot" => Ok(self.snapshot()),
            "observe_prefix" => {
                if self.config.observer_mode != workload::ObserverMode::Full {
                    return Err(
                        "all-correct timestamp observation is unavailable in compact mode".into(),
                    );
                }
                let count = c.count.ok_or("observe_prefix requires count")?;
                if count < self.load.observed_prefix || count > self.node.executed.len() as u64 {
                    return Err(
                        "observed all-correct prefix must be monotonic and locally materialized"
                            .into(),
                    );
                }
                let observed = self.origin.elapsed().as_micros() as u64;
                while let Some(entry) = self.load.outputs.get(self.load.observed_output_cursor) {
                    if entry.output_index as u64 > count {
                        break;
                    }
                    if entry.origin == self.id {
                        if let Some(ingress) = &self.load.ingress {
                            if let Some(timing) =
                                ingress.timings.lock().unwrap().get_mut(&entry.sequence)
                            {
                                if timing.materialized_us.is_some() {
                                    timing.all_correct_observed_us.get_or_insert(observed);
                                }
                            }
                        }
                    }
                    self.load.observed_output_cursor += 1;
                }
                self.load.observed_prefix = count;
                Ok(json!({"count":count,"observed_us":observed}))
            }
            "cohort" | "outputs" | "batches" => {
                if self.config.observer_mode != workload::ObserverMode::Full {
                    return Err("detailed ledger is unavailable in compact observer mode".into());
                }
                let offset = c.offset.unwrap_or(0);
                let limit = c.limit.unwrap_or(256);
                if limit == 0 || limit > 1024 {
                    return Err("ledger page limit must be in 1..=1024".into());
                }
                let (entries, total) = match c.kind.as_str() {
                    "cohort" => self
                        .load
                        .ingress
                        .as_ref()
                        .map_or((json!([]), 0), |ingress| {
                            (
                                json!(ingress.entries(offset, limit)),
                                ingress.manifest.body.count as usize,
                            )
                        }),
                    "outputs" => (
                        json!(self
                            .load
                            .outputs
                            .iter()
                            .skip(offset)
                            .take(limit)
                            .collect::<Vec<_>>()),
                        self.load.outputs.len(),
                    ),
                    _ => (
                        json!(self
                            .load
                            .batches
                            .iter()
                            .skip(offset)
                            .take(limit)
                            .collect::<Vec<_>>()),
                        self.load.batches.len(),
                    ),
                };
                if offset > total {
                    return Err("ledger offset exceeds population".into());
                }
                let next = offset.saturating_add(limit);
                Ok(
                    json!({"replica":self.id,"entries":entries,"total":total,"next_offset":if next<total{Some(next)}else{None},
                    "elapsed_us":self.origin.elapsed().as_micros() as u64,
                    "manifest":self.load.ingress.as_ref().map(|i|&i.manifest)}),
                )
            }
            "receipt" => {
                if !self.quiesced {
                    return Err("receipt requires frozen materialization".into());
                }
                let mut streams = self
                    .load
                    .materialized_ids
                    .iter()
                    .map(|(id, b)| b.descriptor("materialized", *id))
                    .collect::<Vec<_>>();
                if let Some(ingress) = &self.load.ingress {
                    streams.extend(ingress.receipt.lock().unwrap().descriptors(self.id));
                }
                let receipt = workload::Receipt {
                    instance: self.config.instance,
                    replica: self.id,
                    mode: self.config.observer_mode,
                    manifest: self.load.ingress.as_ref().map(|i| i.manifest.clone()),
                    scheduled: self
                        .load
                        .ingress
                        .as_ref()
                        .map_or(0, |i| i.scheduled.load(Ordering::Acquire)),
                    output_count: self.node.executed.len() as u64,
                    output_fingerprint: self
                        .load
                        .output_receipt
                        .unwrap_or_else(workload::output_seed),
                    batch_count: self.node.materialized_batches.len() as u64,
                    batch_fingerprint: self.load.batch_receipt.unwrap_or_else(workload::batch_seed),
                    m_out_bytes: self.load.m_out_bytes,
                    streams,
                };
                // Deliberately outside timed handlers; this is observer/control
                // authentication and is not ordinary consensus protocol work.
                Ok(json!({"receipt":wire::sign(&self.workload_key,self.id,receipt)}))
            }
            "receipt_bitmap" => {
                if !self.quiesced {
                    return Err("receipt bitmap requires frozen materialization".into());
                }
                let origin = c.receipt_origin.ok_or("receipt_origin required")?;
                let name = c
                    .receipt_stream
                    .as_deref()
                    .ok_or("receipt_stream required")?;
                let offset = c.offset.unwrap_or(0);
                let limit = c.limit.unwrap_or(1024);
                if limit == 0 || limit > 4096 {
                    return Err("bitmap byte limit must be in 1..=4096".into());
                }
                let page = |b: &workload::Bitmap| -> Result<Value, String> {
                    if offset > b.bytes.len() {
                        return Err("bitmap offset exceeds bytes".into());
                    }
                    let end = offset.saturating_add(limit).min(b.bytes.len());
                    Ok(
                        json!({"origin":origin,"stream":name,"offset":offset,"bytes":&b.bytes[offset..end],
                        "total":b.bytes.len(),"next_offset":if end<b.bytes.len(){Some(end)}else{None}}),
                    )
                };
                if name == "materialized" {
                    page(
                        self.load
                            .materialized_ids
                            .get(&origin)
                            .ok_or("unknown receipt origin")?,
                    )
                } else {
                    if origin != self.id {
                        return Err("admission receipt belongs to local origin".into());
                    }
                    let ingress = self.load.ingress.as_ref().ok_or("disabled ingress")?;
                    let membership = ingress.receipt.lock().unwrap();
                    page(membership.bitmap(name).ok_or("unknown receipt stream")?)
                }
            }
            "receipt_prefix" => {
                if !self.quiesced {
                    return Err("receipt prefix requires frozen materialization".into());
                }
                let count = c.count.ok_or("receipt prefix count required")? as usize;
                let (total, fingerprint) = match c.receipt_stream.as_deref() {
                    Some("outputs") if count <= self.node.executed.len() => (
                        self.node.executed.len(),
                        self.node.executed[..count]
                            .iter()
                            .fold(workload::output_seed(), workload::output_step),
                    ),
                    Some("batches") if count <= self.node.materialized_batches.len() => (
                        self.node.materialized_batches.len(),
                        self.node.materialized_batches[..count]
                            .iter()
                            .fold(workload::batch_seed(), workload::batch_step),
                    ),
                    _ => {
                        return Err("unknown receipt prefix or count beyond materialization".into())
                    }
                };
                Ok(json!({"count":count,"total":total,"fingerprint":fingerprint}))
            }
            "prefix" => {
                let count = c.count.ok_or("prefix requires count")?;
                Ok(
                    json!({"count":count,"state_hash":execution_prefix_hash(&self.node.executed,count)?}),
                )
            }
            "quiesce" => {
                if let Some(ingress) = &mut self.load.ingress {
                    ingress.stop();
                }
                self.active = false;
                self.quiesced = true;
                let elapsed_us = *self
                    .quiesced_at_us
                    .get_or_insert_with(|| self.origin.elapsed().as_micros() as u64);
                self.log(json!({"event":"quiesced"}))?;
                Ok(json!({"quiesced":true,"elapsed_us":elapsed_us}))
            }
            "stop" => {
                if !self.quiesced {
                    return Err("quiesce and drain before stop".into());
                }
                Ok(self.snapshot())
            }
            _ => Err("unknown control command".into()),
        }
    }
}

pub fn run(mut config: Config, id: Id) -> Result<(), String> {
    crate::meter::configure(config.measure_costs);
    let committee = config.validate(id)?;
    let schedule = config.ordering_schedule()?;
    match schedule {
        OrderingSchedule::Canonical => config.ordering_mode = Some(OrderingMode::Canonical),
        OrderingSchedule::ProgressPacing { release_delay_ms } => {
            config.ordering_mode = Some(OrderingMode::Progress);
            config.progress_pacing_ms = Some(release_delay_ms);
        }
        OrderingSchedule::RoundBarrier { release_delay_ms } => {
            config.ordering_mode = Some(OrderingMode::Barrier);
            config.round_barrier_ms = Some(release_delay_ms);
        }
    }
    let bytes = fs::read(&config.key_files[id as usize]).map_err(|e| e.to_string())?;
    let secret = SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())?;
    let public = PublicKey::from(&secret);
    if committee.keys[id as usize] != public {
        return Err("private key does not match configured identity".into());
    }
    let key = Keypair { secret, public };
    let transport_key = Keypair::from_bytes(&key.to_bytes()).map_err(|e| e.to_string())?;
    let workload_key = Keypair::from_bytes(&key.to_bytes()).map_err(|e| e.to_string())?;
    let av = AvailabilityConfig::new(committee.clone(), config.chunk_capacity)?;
    let mut node = Node::new(
        committee.clone(),
        id,
        key,
        config.bound_ms,
        av,
        config.chunk_capacity,
    )?;
    node.ordering.configure_ordering(schedule)?;
    if config.storage_profile == StorageProfile::SharedRocksdbWritten {
        let parent = config
            .storage_directory
            .as_ref()
            .ok_or("missing record storage parent")?;
        node.store
            .enable_shared_rocksdb(&parent.join(format!("replica-{id}")))?;
    }
    if config.sustained.is_none() {
        node.set_opportunity_limit(config.workload_rounds)?;
    }
    let transport = Transport::bind_at(
        id,
        committee.clone(),
        transport_key,
        config.addresses.clone(),
        config.bind_addresses.as_ref().unwrap_or(&config.addresses)[id as usize],
        TransportSettings::for_committee(&committee),
    )?;
    let control = Control::bind(
        config.control_addresses[id as usize],
        config.control_token.clone(),
    )?;
    let origin = Instant::now();
    if config.observer_mode == workload::ObserverMode::Full || config.sustained.is_none() {
        node.observe_output_from(origin)?;
    }
    let mut load = LoadMetrics::default();
    if let Some(sustained) = &config.sustained {
        for id in 0..config.addresses.len() as Id {
            if sustained.is_origin(id) {
                load.materialized_ids.insert(
                    id,
                    workload::Bitmap::new(sustained.arrival_count(id, config.addresses.len())),
                );
            }
        }
    }
    let mut rt = Runtime {
        committee,
        causal: None,
        config,
        id,
        node,
        transport,
        control,
        origin,
        wall_origin: unix_us(),
        timers: shared_runtime::TimerQueue::new(),
        active: false,
        started: false,
        quiesced: false,
        quiesced_at_us: None,
        produced: 0,
        emitted_transactions: 0,
        processed_messages: 0,
        rejected_protocol_messages: 0,
        post_cutoff_frames: 0,
        post_cutoff_messages: 0,
        silent_ignored_frames: 0,
        by_kind: BTreeMap::new(),
        by_peer: BTreeMap::new(),
        by_index: BTreeMap::new(),
        fault_dropped: BTreeMap::new(),
        proposals: BTreeMap::new(),
        commits: BTreeMap::new(),
        measured_ordered: BTreeMap::new(),
        measured_materialized: BTreeMap::new(),
        load,
        workload_key,
    };
    let causal_output = CausalTrace::from_environment(rt.origin, rt.wall_origin, id)?;
    if let Some((trace, _)) = &causal_output {
        rt.causal = Some(trace.clone());
        rt.node.enable_causal_trace(trace.clone());
    }
    rt.log(json!({"event":"ready","pid":std::process::id(),"control_address":rt.config.control_addresses[id as usize],
        "replica_address":rt.config.addresses[id as usize],"clock":"monotonic local timers; same-host UNIX microsecond telemetry"}))?;
    let outcome = (|| -> Result<(), String> {
        let mut pending_received = None;
        let mut pending_members = VecDeque::new();
        loop {
            if rt.origin.elapsed().as_millis() > rt.config.max_runtime_ms as u128 {
                return Err("process observation deadline exceeded".into());
            }
            // Retained effects progress independently for every peer, even
            // while another peer is unavailable or after protocol quiescence.
            let mut work = rt.transport.retry_deferred()? > 0;
            if let Ok(request) = rt.control.requests.try_recv() {
                work = true;
                let result = rt.command(&request.command);
                let stop = request.command.kind == "stop" && result.is_ok();
                let reply = match result {
                    Ok(data) => {
                        json!({"type":"reply","id":id,"request_id":request.command.request_id,
                    "ok":true,"observed_unix_us":unix_us(),"data":data})
                    }
                    Err(error) => {
                        json!({"type":"reply","id":id,"request_id":request.command.request_id,
                    "ok":false,"observed_unix_us":unix_us(),"error":error})
                    }
                };
                let _ = request.reply.send(reply);
                // Storage failures are local fail-stop conditions, not rejected
                // client requests or Byzantine protocol input.
                rt.node.store.check_storage_health()?;
                if stop {
                    rt.log(json!({"event":"final","snapshot":rt.snapshot()}))?;
                    break;
                }
            }
            // Fair one-message turns, with command and timer checks every turn.
            let receive_eligible =
                rt.active || rt.started || rt.quiesced || rt.config.silent == Some(id);
            let mut logical_received = if receive_eligible {
                pending_members.pop_front()
            } else {
                None
            };
            if logical_received.is_none() && receive_eligible {
                let frame = pending_received
                    .take()
                    .or_else(|| rt.transport.recv_timeout(Duration::ZERO).ok());
                if let Some(frame) = frame {
                    work = true;
                    if rt.active
                        && rt.config.silent != Some(id)
                        && frame.layer == Layer::OrderingBundle
                    {
                        let peer = frame.from;
                        match expand_received_with_limit(frame, rt.committee.max_wire_bytes()) {
                            Ok(members) => {
                                pending_members = members;
                                logical_received = pending_members.pop_front();
                            }
                            Err(error) => {
                                rt.rejected_protocol_messages += 1;
                                rt.log(
                                    json!({"event":"protocol_rejected","peer":peer,"reason":error}),
                                )?;
                            }
                        }
                    } else {
                        // Singles retain their original no-expansion path. Silent
                        // or quiesced replicas discard physical frames without
                        // allocating or interpreting a possibly Byzantine envelope.
                        logical_received = Some(LogicalReceived {
                            frame,
                            member_index: 0,
                            member_count: 1,
                        });
                    }
                }
            } // Pre-start packets stay in the bounded transport mailbox.
            if let Some(LogicalReceived {
                frame: received,
                member_index,
                member_count,
            }) = logical_received
            {
                work = true;
                if rt.active && rt.config.silent != Some(id) {
                    let now = rt.now_ms();
                    let dispatch_start = rt.causal.as_ref().map(CausalTrace::now_us);
                    let mut trace_key = None;
                    let result = match received.layer {
                        Layer::Ordering => rt.committee.decode(&received.payload)
                            .and_then(|m| {
                                if let Some(trace) = &rt.causal {
                                    let (kind, round, signer) = causal::ordering_key(&m);
                                    if trace.sampled(round) {
                                        trace_key = Some((kind, round));
                                        trace.at("dispatch", round, dispatch_start.unwrap(), None,
                                            json!({"kind":kind,"peer":received.from,"signer":signer,
                                                "sequence":received.sequence,"member_index":member_index,"member_count":member_count,"mailbox_us":trace.offset_us(received.received_at),
                                                "decode_done_us":trace.now_us()}));
                                    }
                                }
                                rt.node.receive_ordering(now, m)
                            }),
                        Layer::Dissemination => rt.committee.decode(&received.payload)
                            .and_then(|m| {
                                if let Some(trace) = &rt.causal {
                                    let (kind, round, signer) = causal::dissemination_key(&m);
                                    if trace.sampled(if round == 0 { received.sequence } else { round }) {
                                        trace_key = Some((kind, round));
                                        trace.at("dispatch", round, dispatch_start.unwrap(), None,
                                            json!({"kind":kind,"peer":received.from,"signer":signer,
                                                "sequence":received.sequence,"member_index":member_index,"member_count":member_count,"mailbox_us":trace.offset_us(received.received_at),
                                                "decode_done_us":trace.now_us()}));
                                    }
                                }
                                rt.node.receive(now, received.from, m)
                            }),
                        Layer::OrderingBundle => unreachable!("bundles are expanded before dispatch"),
                    };
                    let handler_end = rt.causal.as_ref().map(CausalTrace::now_us);
                    rt.node.store.check_storage_health()?;
                    if let Some((kind, round)) = trace_key {
                        rt.causal.as_ref().unwrap().at("handler", round, handler_end.unwrap(), dispatch_start,
                            json!({"kind":kind,"peer":received.from,"sequence":received.sequence,"member_index":member_index,"member_count":member_count,"accepted":result.is_ok()}));
                    }
                    match result {
                        Ok(e) => {
                            rt.processed_messages += 1;
                            rt.effects(e)?;
                            if let Some((kind, round)) = trace_key {
                                rt.causal.as_ref().unwrap().span("effect_drain", round, handler_end.unwrap(),
                                    json!({"kind":kind,"peer":received.from,"sequence":received.sequence,"member_index":member_index,"member_count":member_count}));
                            }
                        }
                        Err(error) => {
                            // An authenticated member can still be Byzantine.
                            // Invalid peer input is rejected without stopping
                            // honest processing of later protocol messages.
                            rt.rejected_protocol_messages += 1;
                            rt.log(json!({"event":"protocol_rejected",
                                "peer":received.from,"reason":error}))?;
                        }
                    }
                } else if rt.config.silent == Some(id) {
                    rt.silent_ignored_frames += 1;
                } else {
                    rt.post_cutoff_messages += 1;
                    if member_index == 0 {
                        rt.post_cutoff_frames += 1;
                    }
                }
            }
            if rt.active
                && rt.config.silent != Some(id)
                && rt.timers.first().is_some_and(|at| *at <= rt.now_ms())
            {
                work = true;
                let now = rt.now_ms();
                while rt.timers.first().is_some_and(|at| *at <= now) {
                    rt.timers.pop_first();
                }
                let e = rt.node.tick(now)?;
                rt.effects(e)?;
            }
            if rt.active && rt.started && !rt.quiesced {
                work |= rt.load_tick()?;
            }
            if !work {
                pending_received = idle_receive(
                    receive_eligible,
                    |timeout| rt.transport.recv_timeout(timeout),
                    thread::sleep,
                );
            }
        }
        Ok(())
    })();
    if let Err(error) = &outcome {
        let _ = rt.log(json!({"event":"fatal","error":error,"snapshot":rt.snapshot()}));
    }
    rt.transport.shutdown();
    if let Some((trace, path)) = causal_output {
        if let Err(error) = trace.write(&path, &outcome) {
            return Err(match outcome {
                Ok(()) => format!("causal trace write failed: {error}"),
                Err(original) => format!("{original}; causal trace write failed: {error}"),
            });
        }
    }
    outcome
}
fn unix_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock predates Unix epoch")
        .as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_profile_defaults_and_feature_gate_are_explicit() {
        let mut config:Config=serde_json::from_value(json!({
            "instance":vec![3u8;32],
            "addresses":["127.0.0.1:9000","127.0.0.1:9001","127.0.0.1:9002","127.0.0.1:9003"],
            "control_addresses":["127.0.0.1:9100","127.0.0.1:9101","127.0.0.1:9102","127.0.0.1:9103"],
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..4).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":["0.key","1.key","2.key","3.key"],
            "bound_ms":100,"chunk_capacity":4,"workload_rounds":4,"silent":null,"max_runtime_ms":5000
        })).unwrap();
        assert_eq!(config.storage_profile, StorageProfile::MemoryVisible);
        assert!(config.storage_directory.is_none());
        config.validate(0).unwrap();
        config.storage_directory = Some(PathBuf::from("/unused-parent"));
        assert!(config.validate(0).unwrap_err().contains("storage profile"));
        config.storage_profile = StorageProfile::SharedRocksdbWritten;
        assert_eq!(
            config.validate(0).is_ok(),
            cfg!(feature = "rocksdb-records")
        );
        config.storage_directory = Some(PathBuf::from("relative-parent"));
        assert!(config
            .validate(0)
            .unwrap_err()
            .contains("absolute parent directory"));
        config.storage_directory = None;
        assert!(config.validate(0).unwrap_err().contains("storage profile"));
    }

    #[test]
    fn batching_after_eligible_output_does_not_restore_pending_timestamps() {
        let mut receipt = workload::AdmissionReceipt::new(1);
        receipt.admitted.insert(0);
        assert!(receipt.materialized(0));
        let arrival = Arrival {
            sequence: 0,
            transaction: workload::transaction([1; 32], 0, 0, 4),
        };
        let mut metrics = LoadMetrics::default();
        LoadMetrics::track_pending(&mut metrics.pending, &receipt, &arrival, 1);
        receipt.mark_ready(0);
        assert!(metrics.pending.is_empty());
        assert_eq!(receipt.ready_pending, 0);
    }
    #[test]
    fn finite_semantic_omission_respects_identity_scope_peer_and_deadline() {
        let mut fault = FaultConfig {
            replica: 1,
            start_after_load_ms: 100,
            duration_ms: 200,
            scope: FaultScope::Payload,
            peers: Some(vec![2]),
        };
        assert!(fault.omits(1, 2, "BATCH", 100));
        assert!(fault.omits(1, 2, "DATA", 299));
        for kind in ["FETCH", "OBS", "REPORT", "VOTE", "PROPOSE"] {
            assert!(!fault.omits(1, 2, kind, 150));
        }
        assert!(!fault.omits(0, 2, "BATCH", 150));
        assert!(!fault.omits(1, 3, "BATCH", 150));
        assert!(!fault.omits(1, 2, "BATCH", 99));
        assert!(!fault.omits(1, 2, "DATA", 300));
        fault.scope = FaultScope::All;
        assert!(fault.omits(1, 2, "PROPOSE", 150));
    }

    #[test]
    fn configured_fault_budget_counts_distinct_identities_across_fault_modes() {
        let configuration = |n: usize| -> Config {
            serde_json::from_value(json!({
                "instance":vec![2u8;32],
                "addresses":(0..n).map(|i|format!("127.0.0.1:{}",9000+i)).collect::<Vec<_>>(),
                "control_addresses":(0..n).map(|i|format!("127.0.0.1:{}",9100+i)).collect::<Vec<_>>(),
                "control_token":"01234567890123456789012345678901",
                "public_keys":(0..n as Id).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
                "key_files":vec!["replica.key";n], "bound_ms":100,
                "chunk_capacity":64, "workload_rounds":4, "silent":0,
                "max_runtime_ms":5000,
                "sustained":{"rate_per_replica":100,"transaction_bytes":512,
                    "batch_ms":10,"warmup_ms":0,"measurement_ms":1000,
                    "origins":(2..n).collect::<Vec<_>>()},
                "fault":{"replica":1,"start_after_load_ms":100,
                    "duration_ms":100,"scope":"payload"}
            })).unwrap()
        };
        let mut four = configuration(4);
        assert_eq!(
            four.validate(2).unwrap_err(),
            "configured faulty identities exceed the committee fault budget"
        );
        // Multiple fault modes on the same fixed faulty node consume one identity.
        four.fault.as_mut().unwrap().replica = 0;
        assert!(four.validate(2).is_ok());
        four.silent = None;
        four.fault.as_mut().unwrap().replica = 1;
        assert!(four.validate(2).is_ok());
        // A larger committee admits the same two distinct faulty identities.
        assert!(configuration(7).validate(2).is_ok());
    }

    #[test]
    fn actual_total_rate_population_is_capped_before_workload_allocation() {
        // Config validation alone: do not construct Runtime, Ingress or any
        // finite bitmap to reject an oversized total_rate recipe.
        let n = 31usize;
        let mut config: Config=serde_json::from_value(json!({
            "instance":vec![3u8;32],
            "addresses":(0..n).map(|i|format!("127.0.0.1:{}",12000+i)).collect::<Vec<_>>(),
            "control_addresses":(0..n).map(|i|format!("127.0.0.1:{}",12100+i)).collect::<Vec<_>>(),
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..n as Id).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":vec!["replica.key";n],"bound_ms":100,"chunk_capacity":64,
            "resource_profile":"complete-32mib-n31-v1",
            "workload_rounds":4,"silent":null,"max_runtime_ms":3700000,
            "sustained":{"rate_per_replica":1,"total_rate":775000,"transaction_bytes":512,
                "batch_ms":10,"warmup_ms":0,"measurement_ms":3600000}
        })).unwrap();
        let load = config.sustained.as_ref().unwrap();
        assert!(load.validate().is_ok()); // Legacy fallback rate alone is small.
        assert_eq!(load.arrival_count(0, n), 90_000_000);
        assert_eq!(
            config.validate(0).unwrap_err(),
            "workload exceeds the per-origin rate or finite ledger resource envelope"
        );
        // Preserve the declared limit exactly; no smaller cap is introduced.
        config.sustained.as_mut().unwrap().measurement_ms = 200000;
        assert!((0..n as Id)
            .all(|id| config.sustained.as_ref().unwrap().arrival_count(id, n) == 5_000_000));
        assert!(config.validate(0).is_ok());
        config.sustained.as_mut().unwrap().measurement_ms = 200001;
        assert!(config.validate(0).is_err());
    }

    #[test]
    fn remote_addresses_and_larger_committees_require_complete_compatible_profile() {
        let n = 31;
        let value = json!({"instance":vec![2u8;32],
            "addresses":(0..n).map(|i|format!("10.0.0.{}:9000",i+1)).collect::<Vec<_>>(),
            "bind_addresses":vec!["0.0.0.0:9000";n],
            "control_addresses":vec!["127.0.0.1:9001";n],
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..n as Id).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":vec!["replica.key";n],"bound_ms":100,"chunk_capacity":64,
            "workload_rounds":4,"silent":null,"max_runtime_ms":5000});
        let mut config: Config = serde_json::from_value(value).unwrap();
        assert!(config.validate(0).is_err());
        config.resource_profile = wire::ResourceProfile::Complete32MibN31V1;
        assert!(config.validate(0).is_ok());
        config.control_addresses[0] = "0.0.0.0:9001".parse().unwrap();
        assert!(config.validate(0).is_err());
        config.control_addresses[0] = "127.0.0.1:9000".parse().unwrap();
        assert!(config.validate(0).is_err());
    }
    fn queued(kind: &str, byte: u8, size: usize) -> OrderingToSend {
        OrderingToSend {
            bytes: vec![byte; size],
            kind: kind.into(),
            index: 4,
            x: 0,
            pi: 0,
        }
    }

    #[test]
    fn ordering_envelope_bounds_count_lengths_and_trailing_bytes_before_members() {
        let encoded = encode_ordering_bundle([b"one".as_slice(), b"two".as_slice()]).unwrap();
        assert_eq!(
            decode_ordering_bundle(&encoded).unwrap(),
            vec![b"one".as_slice(), b"two".as_slice()]
        );
        for count in [0u32, 1, 33, u32::MAX] {
            let mut bytes = encoded.clone();
            bytes[..4].copy_from_slice(&count.to_le_bytes());
            assert!(decode_ordering_bundle(&bytes).is_err());
        }
        for end in 0..encoded.len() {
            assert!(decode_ordering_bundle(&encoded[..end]).is_err());
        }
        let mut bytes = encoded.clone();
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_ordering_bundle(&bytes).is_err());
        let mut bytes = encoded;
        bytes.push(0);
        assert!(decode_ordering_bundle(&bytes).is_err());
        assert!(decode_ordering_bundle(&vec![0; wire::MAX_WIRE_BYTES + 1]).is_err());
        let exact = vec![7; wire::MAX_WIRE_BYTES - 12];
        let at_limit = encode_ordering_bundle([exact.as_slice(), &[]]).unwrap();
        assert_eq!(at_limit.len(), wire::MAX_WIRE_BYTES);
        assert_eq!(decode_ordering_bundle(&at_limit).unwrap()[0], exact);
        assert!(encode_ordering_bundle([exact.as_slice(), &[1]]).is_err());
    }

    #[test]
    fn ordering_batcher_preserves_per_peer_and_cross_layer_order_without_waiting() {
        let mut pending = OrderingBatcher::default();
        let mut sent: BTreeMap<Id, Vec<String>> = BTreeMap::new();
        for peer in recipients(None, 0, 4) {
            assert!(pending.push(peer, queued("CER", 1, 8)).is_empty());
        }
        assert!(pending.push(2, queued("HISTORY3", 2, 8)).is_empty());
        // This is the production cross-layer boundary: flush the DATA peer's
        // ordering prefix, without flushing another peer's still-open group.
        for peer in recipients(Some(2), 0, 4) {
            sent.entry(peer)
                .or_default()
                .extend(pending.take(peer).unwrap().into_iter().map(|m| m.kind));
            sent.entry(peer).or_default().push("DATA".into());
        }
        for peer in recipients(None, 0, 4) {
            assert!(pending.push(peer, queued("CLOSED", 3, 8)).is_empty());
        }
        for (peer, messages) in pending.drain() {
            sent.entry(peer)
                .or_default()
                .extend(messages.into_iter().map(|m| m.kind));
        }
        assert_eq!(sent[&1], ["CER", "CLOSED"]);
        assert_eq!(sent[&2], ["CER", "HISTORY3", "DATA", "CLOSED"]);
        assert_eq!(sent[&3], ["CER", "CLOSED"]);
        assert!(!sent.contains_key(&0));
        let mut single = OrderingBatcher::default();
        single.push(1, queued("PROG", 4, 8));
        assert_eq!(single.drain().next().unwrap().1.len(), 1);
    }

    #[test]
    fn ordering_batcher_flushes_count_and_byte_caps_with_single_frame_fallback() {
        let mut pending = OrderingBatcher::default();
        for _ in 0..MAX_ORDERING_BUNDLE_MEMBERS {
            assert!(pending.push(1, queued("PROG", 1, 8)).is_empty());
        }
        let ready = pending.push(1, queued("VOTE", 2, 8));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].len(), MAX_ORDERING_BUNDLE_MEMBERS);
        let ready = pending.push(1, queued("PROPOSE", 3, wire::MAX_WIRE_BYTES));
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0][0].kind, "VOTE");
        assert_eq!(ready[1][0].bytes.len(), wire::MAX_WIRE_BYTES);
        assert!(pending.take(1).is_none());
        pending.push(1, queued("PROPOSE", 4, wire::MAX_WIRE_BYTES - 8));
        let ready = pending.push(1, queued("CER", 5, 8));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0][0].bytes.len(), wire::MAX_WIRE_BYTES - 8);
        assert_eq!(pending.take(1).unwrap()[0].kind, "CER");
    }

    #[test]
    fn bundle_members_have_distinct_trace_keys_and_independent_protocol_validation() {
        let committee = Committee::new(
            [71; 32],
            (0..4).map(|id| wire::fixture_key(id).public).collect(),
        )
        .unwrap();
        let node = || {
            let availability = AvailabilityConfig::new(committee.clone(), 4).unwrap();
            let mut node = Node::new(
                committee.clone(),
                3,
                wire::fixture_key(3),
                100,
                availability,
                4,
            )
            .unwrap();
            node.set_opportunity_limit(4).unwrap();
            node.start(0).unwrap();
            node
        };
        // This proposal is authentically signed and bound, but its value and
        // witness fail the composition's Q predicate. Later valid PROGs from
        // other signers remain independently usable inside the same frame.
        let value = vec![1];
        let witness = vec![2];
        let bad_proposal = wire::Message::Propose(wire::Proposal {
            header: wire::sign(
                &wire::fixture_key(0),
                0,
                wire::Header {
                    context: committee.context.clone(),
                    round: 1,
                    value_hash: wire::hash(&value),
                    witness_hash: wire::hash(&witness),
                    history_hash: wire::hash(&crate::history::History::Empty),
                    entries: crate::history::Entries::empty(),
                },
            ),
            value,
            witness,
            history: crate::history::History::Empty,
        });
        let progress = |id| {
            wire::Message::Prog(wire::sign(
                &wire::fixture_key(id),
                id,
                wire::Statement {
                    context: committee.context.clone(),
                    kind: wire::Kind::Prog,
                    round: 1,
                    digest: None,
                },
            ))
        };
        let payloads = [
            wire::encode(&bad_proposal).unwrap(),
            vec![255],
            wire::encode(&progress(1)).unwrap(),
            wire::encode(&progress(2)).unwrap(),
        ];
        let received_at = Instant::now();
        let mut members = expand_received(Received {
            from: 0,
            sequence: 17,
            layer: Layer::OrderingBundle,
            payload: encode_ordering_bundle(payloads.iter().map(Vec::as_slice)).unwrap(),
            received_at,
        })
        .unwrap();
        let (mut bundled, mut single) = (node(), node());
        let mut rejected = 0;
        let mut keys = BTreeSet::new();
        for (index, bytes) in payloads.iter().enumerate() {
            // A caller takes precisely one item per turn; the remaining items
            // stay queued while normal control/timer/load checks execute.
            let received = members.pop_front().unwrap();
            assert_eq!(members.len(), payloads.len() - index - 1);
            assert_eq!(received.frame.received_at, received_at);
            assert_eq!(received.frame.payload, *bytes);
            assert_eq!(received.member_count, 4);
            assert!(keys.insert((
                received.frame.from,
                received.frame.sequence,
                received.member_index
            )));
            let apply = |node: &mut Node, bytes: &[u8]| {
                wire::decode(bytes)
                    .and_then(|message| node.receive_ordering(1 + index as u64, message))
            };
            let a = apply(&mut bundled, &received.frame.payload);
            let b = apply(&mut single, bytes);
            rejected += usize::from(a.is_err());
            assert_eq!(format!("{a:?}"), format!("{b:?}"));
            assert_eq!(bundled.ordering.snapshot(), single.ordering.snapshot());
        }
        assert_eq!(rejected, 2);
        assert_eq!(bundled.ordering.current_round(), 2);
        assert!(members.is_empty());
    }

    #[test]
    fn bundled_progress_is_default_and_comparison_modes_are_explicit_and_bounded() {
        let value = json!({"instance":(vec![1u8;32]), "addresses":["127.0.0.1:12001","127.0.0.1:12002","127.0.0.1:12003","127.0.0.1:12004"],
            "control_addresses":["127.0.0.1:12005","127.0.0.1:12006","127.0.0.1:12007","127.0.0.1:12008"],
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..4).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":["0.key","1.key","2.key","3.key"],"bound_ms":100,"chunk_capacity":4,
            "workload_rounds":4,"silent":null,"max_runtime_ms":5000});
        let mut config: Config = serde_json::from_value(value).unwrap();
        assert!(config.ordering_batch);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::ProgressPacing {
                release_delay_ms: 100
            }
        );
        assert!(config.round_barrier_ms.is_none());
        assert!(config.progress_pacing_ms.is_none());
        config.validate(0).unwrap();
        for progress_only in [false, true] {
            for delay in [0, 1, 100, 101] {
                config.round_barrier_ms = (!progress_only).then_some(delay);
                config.progress_pacing_ms = progress_only.then_some(delay);
                assert_eq!(config.validate(0).is_ok(), (1..=100).contains(&delay));
                let encoded = serde_json::to_value(&config).unwrap();
                let decoded: Config = serde_json::from_value(encoded.clone()).unwrap();
                assert_eq!(decoded.round_barrier_ms, config.round_barrier_ms);
                assert_eq!(decoded.progress_pacing_ms, config.progress_pacing_ms);
                assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
            }
        }
        config.round_barrier_ms = None;
        config.progress_pacing_ms = None;
        config.ordering_mode = Some(OrderingMode::Canonical);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::Canonical
        );
        config.progress_pacing_ms = Some(50);
        assert!(config.validate(0).is_err());
        config.progress_pacing_ms = None;
        config.ordering_mode = Some(OrderingMode::Barrier);
        assert_eq!(
            config.ordering_schedule().unwrap(),
            OrderingSchedule::RoundBarrier {
                release_delay_ms: 100
            }
        );
        config.ordering_mode = Some(OrderingMode::Progress);
        config.round_barrier_ms = Some(50);
        assert!(config.validate(0).is_err());
        config.ordering_mode = None;
        for delay in [1, 100] {
            config.round_barrier_ms = Some(delay);
            config.progress_pacing_ms = Some(delay);
            assert!(config.validate(0).is_err());
        }
    }

    #[test]
    fn idle_receive_retains_prestart_packets_and_takes_only_one_when_eligible() {
        let (tx, rx) = mpsc::sync_channel(2);
        tx.send(1).unwrap();
        tx.send(2).unwrap();
        let mut sleeps = Vec::new();
        assert_eq!(
            idle_receive(
                false,
                |_| -> Result<u32, mpsc::RecvTimeoutError> {
                    panic!("pre-start inbox must remain unread")
                },
                |timeout| sleeps.push(timeout),
            ),
            None
        );
        assert_eq!(sleeps, vec![Duration::from_millis(1)]);
        let pending = idle_receive(
            true,
            |timeout| {
                assert_eq!(timeout, Duration::from_millis(1));
                rx.recv_timeout(timeout)
            },
            |_| panic!("an arriving message must wake the idle turn without a sleep"),
        );
        assert_eq!(pending, Some(1));
        // The wakeup retains a single message; the ordinary turn can check
        // control before dispatching it without consuming a second message.
        assert_eq!(rx.try_recv().unwrap(), 2);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn idle_receive_timeout_does_not_sleep_twice_and_disconnect_does_not_spin() {
        let timeout = Duration::from_millis(1);
        assert_eq!(
            idle_receive::<u32>(
                true,
                |wait| {
                    assert_eq!(wait, timeout);
                    Err(mpsc::RecvTimeoutError::Timeout)
                },
                |_| panic!("the inbox timeout already waited"),
            ),
            None
        );
        let (tx, rx) = mpsc::channel::<u32>();
        drop(tx);
        let mut sleeps = Vec::new();
        assert_eq!(
            idle_receive(true, |wait| rx.recv_timeout(wait), |wait| sleeps.push(wait)),
            None
        );
        assert_eq!(sleeps, vec![timeout]);
    }

    #[test]
    fn signed_finite_population_verifier_rejects_forged_ids_schedules_and_signatures() {
        let config: Config = serde_json::from_value(json!({
            "instance":vec![1u8;32],
            "addresses":["127.0.0.1:12001","127.0.0.1:12002","127.0.0.1:12003","127.0.0.1:12004"],
            "control_addresses":["127.0.0.1:12005","127.0.0.1:12006","127.0.0.1:12007","127.0.0.1:12008"],
            "control_token":"01234567890123456789012345678901",
            "public_keys":(0..4).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
            "key_files":["0.key","1.key","2.key","3.key"],"bound_ms":100,"chunk_capacity":4,
            "workload_rounds":4,"silent":null,"max_runtime_ms":5000,
            "sustained":{"rate_per_replica":2,"total_rate":7,"transaction_bytes":64,
                "useful_bytes":4,"batch_ms":10,"warmup_ms":0,"measurement_ms":1000}
        })).unwrap();
        let committee = config.validate(0).unwrap();
        let load = config.sustained.as_ref().unwrap();
        let mut ledger = json!({});
        let mut all_schedules = Vec::new();
        for id in 0..4 {
            let manifest = load.manifest(config.instance, id, 4, 900);
            let signed = wire::sign(&wire::fixture_key(id), id, manifest.clone());
            let rows: Vec<_> = (0..manifest.count).map(|sequence| {
                all_schedules.push(manifest.scheduled_us(sequence));
                json!({"id":manifest.transaction(sequence).id,"origin":id,"sequence":sequence,
                    "useful_bytes":manifest.useful_bytes,"scheduled_us":manifest.scheduled_us(sequence)})
            }).collect();
            ledger[id.to_string()] = json!({"manifest":signed,"requests":rows,"outputs":[]});
        }
        let verified = verify_workload_ledger(&config, &ledger).unwrap();
        assert_eq!(verified["verified_requests"], 7);
        all_schedules.sort();
        assert_eq!(
            all_schedules,
            (1u64..=7)
                .map(|i| 900 + (i * 1_000_000).div_ceil(7))
                .collect::<Vec<_>>()
        );
        let mut bad = ledger.clone();
        bad["0"]["requests"][0]["id"][0] = json!(255);
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger.clone();
        bad["0"]["requests"][0]["scheduled_us"] = json!(901);
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger.clone();
        bad["0"]["requests"].as_array_mut().unwrap().pop();
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger.clone();
        bad["0"]["manifest"]["body"]["count"] = json!(999);
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger.clone();
        let mut far_future = load.manifest(config.instance, 0, 4, u64::MAX);
        far_future.start_elapsed_us = u64::MAX;
        bad["0"]["manifest"] =
            serde_json::to_value(wire::sign(&wire::fixture_key(0), 0, far_future)).unwrap();
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger.clone();
        let mut signed: wire::Signed<workload::Manifest> =
            serde_json::from_value(bad["0"]["manifest"].clone()).unwrap();
        signed.signature[0] ^= 1;
        assert!(committee.verify_signature(&signed).is_err());
        bad["0"]["manifest"] = serde_json::to_value(signed).unwrap();
        assert!(verify_workload_ledger(&config, &bad).is_err());
        let mut bad = ledger;
        bad["1"]["outputs"] = json!([{"id":vec![0;32],"origin":0,"sequence":0,"useful_bytes":4}]);
        assert!(verify_workload_ledger(&config, &bad).is_err());
    }
    #[test]
    fn sustained_transaction_size_and_ids_match_actual_canonical_encoding() {
        let transaction = workload::transaction([4; 32], 1, 42, 452);
        assert_eq!(wire::encode(&transaction).unwrap().len(), 512);
        assert_eq!(transaction.bytes.len(), 472);
        assert_eq!(
            wire::encode(&vec![transaction.clone(); 10]).unwrap().len(),
            5128
        );
        assert_ne!(
            transaction.id,
            workload::transaction([4; 32], 2, 42, 452).id
        );
        assert_ne!(
            transaction.id,
            workload::transaction([4; 32], 1, 43, 452).id
        );
    }
    #[test]
    fn monotonic_load_schedule_uses_cumulative_fractional_rate_without_rounding_loss() {
        assert_eq!(scheduled_transactions(10_000, 250), 2);
        assert_eq!(scheduled_transactions(20_000, 250), 5);
        assert_eq!(scheduled_transactions(1_000_000, 250), 250);
        assert_eq!(scheduled_transactions(40_000_000, 1000), 40_000);
    }
    #[test]
    fn sustained_profile_rejects_impossible_batch_and_interval_settings() {
        let mut c = SustainedConfig {
            rate_per_replica: 1000,
            total_rate: None,
            transaction_bytes: 512,
            batch_ms: 10,
            warmup_ms: 10_000,
            measurement_ms: 30_000,
            useful_bytes: None,
            max_batch_transactions: 128,
            arrival_queue_capacity: 65_536,
            origins: None,
        };
        c.validate().unwrap();
        c.transaction_bytes = 39;
        assert!(c.validate().is_err());
        c.transaction_bytes = 512;
        c.batch_ms = 1000;
        c.validate().unwrap(); // Full batches flush independently of the timer.
        c.max_batch_transactions = 0;
        assert!(c.validate().is_err());
        c.max_batch_transactions = 1024;
        c.batch_ms = 10;
        c.measurement_ms = 0;
        assert!(c.validate().is_err());
    }
    #[test]
    fn common_prefix_queries_use_the_exact_requested_output_boundary() {
        let rows = vec![
            composed::Executed {
                round: 1,
                producer: 0,
                height: 1,
                batch_digest: [1; 32],
                transaction: [2; 32],
                state_hash: [3; 32],
            },
            composed::Executed {
                round: 2,
                producer: 1,
                height: 1,
                batch_digest: [4; 32],
                transaction: [5; 32],
                state_hash: [6; 32],
            },
        ];
        assert_eq!(
            execution_prefix_hash(&rows, 0).unwrap(),
            wire::hash(&"delugi/deterministic-materialization/v1")
        );
        assert_eq!(execution_prefix_hash(&rows, 1).unwrap(), [3; 32]);
        assert_eq!(execution_prefix_hash(&rows, 2).unwrap(), [6; 32]);
        assert!(execution_prefix_hash(&rows, 3).is_err());
        assert!(execution_prefix_hash(&rows, u64::MAX).is_err());
    }
    #[test]
    fn client_control_parser_is_bounded_and_rejects_unknown_fields() {
        assert!(serde_json::from_str::<Command>(
            r#"{"type":"submit","token":"test","round":1,"unexpected":true}"#
        )
        .is_err());
        let c: Command =
            serde_json::from_str(r#"{"type":"snapshot","token":"test","request_id":7}"#).unwrap();
        assert_eq!(c.kind, "snapshot");
        assert_eq!(c.request_id, 7);
    }
}
