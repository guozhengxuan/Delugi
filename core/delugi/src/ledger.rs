//! Offline verification of bounded, hashed workload pages. Aggregate evidence
//! size is disk-limited; no request-ID set or whole stream is retained here.
use crate::process::Config;
use crate::wire::{self, Digest, Id};
use crate::workload;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as ShaDigest, Sha256};
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_PAGE: u64 = 8 * 1024 * 1024;
const MAX_LINE: u64 = 4096;
const MAX_ENTRIES: usize = 1024;
const MAX_ROW: usize = 16 * 1024;

#[derive(Deserialize)]
struct Stream {
    path: String,
    sha256: String,
    bytes: u64,
    pages: u64,
    entries: u64,
}
#[derive(Deserialize)]
struct Shard {
    path: String,
    sha256: String,
    bytes: u64,
    entries: u64,
    offset: u64,
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn regular(file: File) -> Result<File, String> {
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("archive component must be a regular file".into());
    }
    Ok(file)
}
fn bounded(file: File, limit: u64) -> Result<Vec<u8>, String> {
    let file = regular(file)?;
    if file.metadata().map_err(|e| e.to_string())?.len() > limit {
        return Err("archive component exceeds byte bound".into());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("archive component exceeds byte bound".into());
    }
    Ok(bytes)
}
fn index_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    regular(options.open(path).map_err(|e| e.to_string())?)
}
/// openat walks directory descriptors with O_NOFOLLOW. A renamed intermediate
/// directory or concurrent symlink cannot redirect a verified confined path.
#[cfg(unix)]
fn confined(root: &Path, relative: &str) -> Result<File, String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    if relative.starts_with('/')
        || relative
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err("archive path must be a confined relative file".into());
    }
    let parts: Vec<_> = relative.split('/').collect();
    let mut current = File::open(root).map_err(|e| e.to_string())?;
    for (position, part) in parts.iter().enumerate() {
        let name = CString::new(*part).map_err(|e| e.to_string())?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if position + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        current = unsafe { File::from_raw_fd(fd) };
    }
    regular(current)
}
#[cfg(not(unix))]
fn confined(_: &Path, _: &str) -> Result<File, String> {
    Err("confined archive verification requires Unix openat semantics".into())
}
fn integer(row: &Value, name: &str) -> Result<u64, String> {
    row[name]
        .as_u64()
        .ok_or_else(|| format!("missing unsigned integer {name}"))
}
fn digest(row: &Value, name: &str) -> Result<Digest, String> {
    serde_json::from_value(row[name].clone()).map_err(|e| format!("invalid {name}: {e}"))
}
fn stream_rows(
    root: &Path,
    replica: Id,
    ledger: &Value,
    name: &str,
    mut visit: impl FnMut(&Value) -> Result<(), String>,
) -> Result<u64, String> {
    let descriptor: Stream =
        serde_json::from_value(ledger["streams"][name].clone()).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(confined(root, &descriptor.path)?);
    let mut index_hash = Sha256::new();
    let (mut total, mut pages, mut bytes) = (0u64, 0u64, 0u64);
    loop {
        let mut line = Vec::new();
        let length = reader
            .by_ref()
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| e.to_string())?;
        if length == 0 {
            break;
        }
        if length as u64 > MAX_LINE || line.last() != Some(&b'\n') {
            return Err("oversized or truncated shard index line".into());
        }
        bytes = bytes
            .checked_add(length as u64)
            .ok_or("index byte count overflow")?;
        index_hash.update(&line);
        let shard: Shard = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
        if shard.offset != total || shard.entries > MAX_ENTRIES as u64 || shard.bytes > MAX_PAGE {
            return Err("shard offset or size differs from bounded population".into());
        }
        let raw = bounded(confined(root, &shard.path)?, MAX_PAGE)?;
        if raw.len() as u64 != shard.bytes || hash(&raw) != shard.sha256 {
            return Err("page hash or byte count differs".into());
        }
        let page: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let entries = page["entries"].as_array().ok_or("page entries missing")?;
        if integer(&page, "replica")? != replica as u64
            || integer(&page, "total")? != descriptor.entries
            || entries.len() as u64 != shard.entries
            || page["manifest"] != ledger["manifest"]
        {
            return Err("page population or manifest differs".into());
        }
        total = total
            .checked_add(shard.entries)
            .ok_or("population overflow")?;
        if total > descriptor.entries
            || (total < descriptor.entries && entries.is_empty())
            || (total < descriptor.entries && page["next_offset"].as_u64() != Some(total))
            || (total == descriptor.entries && !page["next_offset"].is_null())
        {
            return Err("page continuation differs from exact population".into());
        }
        for row in entries {
            if !row.is_object()
                || serde_json::to_vec(row).map_err(|e| e.to_string())?.len() > MAX_ROW
            {
                return Err("ledger row exceeds bounded object envelope".into());
            }
            visit(row)?;
        }
        pages += 1;
        if pages > descriptor.pages {
            return Err("too many shard pages".into());
        }
    }
    if total != descriptor.entries
        || pages != descriptor.pages
        || pages == 0
        || bytes != descriptor.bytes
        || format!("{:x}", index_hash.finalize()) != descriptor.sha256
    {
        return Err("stream index hash or population differs".into());
    }
    Ok(total)
}
fn request_times(
    row: &Value,
    observed: u64,
    collected: u64,
    ready_precedes_output: bool,
) -> Result<(), String> {
    let mut previous = integer(row, "scheduled_us")?;
    let mut missing = false;
    for stage in ["admitted_us", "batch_ready_us", "materialized_us"] {
        if stage == "batch_ready_us" && !ready_precedes_output {
            continue;
        }
        if row[stage].is_null() {
            missing = true;
            continue;
        }
        let value = integer(row, stage)?;
        if missing || value < previous || value > observed {
            return Err("invalid request stage ordering".into());
        }
        previous = value;
    }
    if !ready_precedes_output && !row["batch_ready_us"].is_null() {
        let ready = integer(row, "batch_ready_us")?;
        if ready < integer(row, "admitted_us")? || ready > observed {
            return Err("batch readiness precedes admission or exceeds observation".into());
        }
    }
    if !row["rejected_us"].is_null() {
        let rejected = integer(row, "rejected_us")?;
        if !row["admitted_us"].is_null()
            || rejected < integer(row, "scheduled_us")?
            || rejected > observed
        {
            return Err("invalid request rejection".into());
        }
    }
    if !row["all_correct_observed_us"].is_null()
        && (integer(row, "all_correct_observed_us")? < integer(row, "materialized_us")?
            || integer(row, "all_correct_observed_us")? > collected)
    {
        return Err("all-correct receipt precedes materialization or exceeds collection".into());
    }
    publication_time(row, collected)?;
    Ok(())
}
fn publication_time(row: &Value, collected: u64) -> Result<(), String> {
    if !row["post_handler_published_us"].is_null() {
        let published = integer(row, "post_handler_published_us")?;
        if published < integer(row, "materialized_us")? || published > collected {
            return Err("publication precedes materialization or exceeds collection".into());
        }
    }
    Ok(())
}

/// Schema 3 authenticates compact finite membership and exact-output receipt
/// headers. It is measurement evidence signed by replicas, not a proof that a
/// Byzantine signer truthfully executed its claimed output. Correct overlap and
/// honest-origin eligibility are separate reduction checks.
fn verify_receipt_archive(
    config: &Config,
    index_path: &Path,
    index: &Value,
    raw: &[u8],
) -> Result<Value, String> {
    let committee = config.validate(0)?;
    let load = config
        .sustained
        .as_ref()
        .ok_or("receipt requires sustained workload")?;
    if index["format"] != "delugi-observer-receipts-v1" {
        return Err("unknown receipt format".into());
    }
    let replicas = index["replicas"]
        .as_object()
        .ok_or("missing receipt replicas")?;
    if replicas.len() != committee.keys.len() {
        return Err("receipt requires every replica".into());
    }
    let root = index_path
        .parent()
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut verified_streams = 0u64;
    for id in 0..committee.keys.len() as Id {
        let entry = replicas
            .get(&id.to_string())
            .ok_or("missing receipt replica")?;
        let signed: wire::Signed<workload::Receipt> =
            serde_json::from_value(entry["receipt"].clone()).map_err(|e| e.to_string())?;
        committee.verify_signature(&signed)?;
        let receipt = &signed.body;
        if signed.signer != id
            || receipt.replica != id
            || receipt.instance != config.instance
            || receipt.mode != config.observer_mode
        {
            return Err("receipt identity or observer mode differs from configuration".into());
        }
        let local_count = load.arrival_count(id, committee.keys.len());
        if load.is_origin(id) {
            let manifest = receipt
                .manifest
                .as_ref()
                .ok_or("missing signed receipt manifest")?;
            committee.verify_signature(manifest)?;
            if manifest.signer != id
                || manifest.body.start_elapsed_us > config.max_runtime_ms * 1000
                || manifest.body
                    != load.manifest(
                        config.instance,
                        id,
                        committee.keys.len(),
                        manifest.body.start_elapsed_us,
                    )
            {
                return Err("receipt manifest differs from configured finite population".into());
            }
        } else if receipt.manifest.is_some() || receipt.scheduled != 0 {
            return Err("disabled origin has an admission receipt".into());
        }
        if receipt.scheduled > local_count {
            return Err("scheduled receipt exceeds finite population".into());
        }
        let paths = entry["streams"]
            .as_array()
            .ok_or("missing receipt streams")?;
        let expected_len = (0..committee.keys.len() as Id)
            .filter(|i| load.is_origin(*i))
            .count()
            + if load.is_origin(id) { 5 } else { 0 };
        if receipt.streams.len() != expected_len || paths.len() != expected_len {
            return Err("incomplete receipt streams".into());
        }
        if (receipt.output_count == 0 && receipt.output_fingerprint != workload::output_seed())
            || (receipt.batch_count == 0
                && (receipt.batch_fingerprint != workload::batch_seed()
                    || receipt.m_out_bytes != 0
                    || receipt.output_count != 0))
        {
            return Err("empty receipt count and fingerprint differ".into());
        }
        let mut observed_identities = 0u64;
        let mut seen = std::collections::BTreeSet::new();
        let mut local_files = std::collections::BTreeMap::new();
        let mut local_hashes = std::collections::BTreeMap::new();
        let mut local_expected = std::collections::BTreeMap::new();
        for (descriptor, path) in receipt.streams.iter().zip(paths) {
            let local = ["admitted", "rejected", "ready", "completed", "seen_output"]
                .contains(&descriptor.name.as_str());
            if (!local && descriptor.name != "materialized")
                || (local && descriptor.origin != id)
                || !load.is_origin(descriptor.origin)
                || descriptor.origin as usize >= committee.keys.len()
                || !seen.insert((descriptor.name.clone(), descriptor.origin))
            {
                return Err("unknown or duplicate receipt stream".into());
            }
            let expected_count = load.arrival_count(descriptor.origin, committee.keys.len());
            if descriptor.count != expected_count
                || descriptor.bytes != expected_count.div_ceil(8)
                || descriptor.ones > expected_count
            {
                return Err("receipt bitmap differs from finite population".into());
            }
            if path["name"] != descriptor.name
                || integer(path, "origin")? != descriptor.origin as u64
            {
                return Err("receipt path descriptor mismatch".into());
            }
            let relative = path["path"].as_str().ok_or("missing receipt bitmap path")?;
            let file = confined(&root, relative)?;
            if file.metadata().map_err(|e| e.to_string())?.len() != descriptor.bytes {
                return Err("receipt bitmap byte count mismatch".into());
            }
            let mut reader = BufReader::with_capacity(4096, file);
            let mut digest = Sha256::new();
            let (mut total, mut ones, mut last) = (0u64, 0u64, 0u8);
            let mut chunk = [0u8; 4096];
            loop {
                let n = reader.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > descriptor.bytes {
                    return Err("receipt bitmap changed during read".into());
                }
                digest.update(&chunk[..n]);
                ones += chunk[..n]
                    .iter()
                    .map(|b| b.count_ones() as u64)
                    .sum::<u64>();
                last = chunk[n - 1];
            }
            let actual: Digest = digest.finalize().into();
            if total != descriptor.bytes
                || ones != descriptor.ones
                || actual != descriptor.sha256
                || (descriptor.count % 8 != 0 && last >> (descriptor.count % 8) != 0)
            {
                return Err("receipt bitmap hash, count or padding mismatch".into());
            }
            if descriptor.name == "materialized" {
                observed_identities += descriptor.ones;
            }
            if local || (descriptor.name == "materialized" && descriptor.origin == id) {
                reader.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                local_files.insert(descriptor.name.clone(), reader);
                local_hashes.insert(descriptor.name.clone(), Sha256::new());
                local_expected.insert(descriptor.name.clone(), descriptor.sha256);
            }
            verified_streams += 1;
        }
        if observed_identities > receipt.output_count {
            return Err("receipt identities exceed exact output count".into());
        }
        // Cross-stage relations are checked in bounded lockstep, including the
        // not-yet-scheduled tail and own-origin exact materialization membership.
        if load.is_origin(id) {
            let bytes = local_count.div_ceil(8);
            let mut offset = 0;
            while offset < bytes {
                let length = (bytes - offset).min(4096) as usize;
                let mut chunks = std::collections::BTreeMap::new();
                for (name, file) in &mut local_files {
                    let mut chunk = vec![0u8; length];
                    file.read_exact(&mut chunk).map_err(|e| e.to_string())?;
                    local_hashes.get_mut(name).unwrap().update(&chunk);
                    chunks.insert(name.as_str(), chunk);
                }
                for position in 0..length {
                    let admitted = chunks["admitted"][position];
                    let rejected = chunks["rejected"][position];
                    let ready = chunks["ready"][position];
                    let completed = chunks["completed"][position];
                    let output = chunks["seen_output"][position];
                    let remaining = receipt
                        .scheduled
                        .saturating_sub((offset + position as u64) * 8)
                        .min(8);
                    let scheduled_mask = ((1u16 << remaining) - 1) as u8;
                    if admitted & rejected != 0
                        || admitted | rejected != scheduled_mask
                        || ready & !admitted != 0
                        || completed & !(admitted & output) != 0
                        || output != chunks["materialized"][position]
                    {
                        return Err(
                            "receipt admission, readiness or eligibility relation failed".into(),
                        );
                    }
                }
                offset += length as u64;
            }
        }
        for (name, digest) in local_hashes {
            let actual: Digest = digest.finalize().into();
            if actual != local_expected[&name] {
                return Err("receipt changed during eligibility verification".into());
            }
        }
    }
    Ok(
        json!({"verified":true,"schema":3,"index_sha256":hash(raw),"verified_streams":verified_streams,
        "boundary":"signed finite manifests, receipt headers, bounded bitmap hashes and eligibility relations; correct output-prefix agreement checked separately"}),
    )
}

pub fn verify_workload_archive(config: &Config, index_path: &Path) -> Result<Value, String> {
    let committee = config.validate(0)?;
    let load = config
        .sustained
        .as_ref()
        .ok_or("archive verification requires sustained configuration")?;
    let raw = bounded(index_file(index_path)?, MAX_MANIFEST)?;
    let index: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if index["schema"] == 3 {
        return verify_receipt_archive(config, index_path, &index, &raw);
    }
    if index["schema"] != 2 || index["format"] != "delugi-cohort-pages-v2" {
        return Err("unknown cohort archive schema".into());
    }
    let ledgers = index["replicas"].as_object().ok_or("missing replica map")?;
    if ledgers.len() != committee.keys.len() {
        return Err("archive must include every replica".into());
    }
    let root: PathBuf = index_path
        .parent()
        .unwrap_or(Path::new("."))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let (mut verified_requests, mut verified_outputs, mut verified_batches, mut signed_manifests) =
        (0u64, 0u64, 0u64, 0u64);
    for id in 0..committee.keys.len() as Id {
        let ledger = ledgers
            .get(&id.to_string())
            .ok_or("missing replica ledger")?;
        let observed = integer(ledger, "observed_us")?;
        let collected = if ledger["collected_us"].is_null() {
            observed
        } else {
            integer(ledger, "collected_us")?
        };
        if collected < observed {
            return Err("collection precedes materialization freeze".into());
        }
        if integer(ledger, "window_start_us")? >= integer(ledger, "window_end_us")?
            || integer(ledger, "window_end_us")? > observed
            || ledger["output_index_base"] != 1
        {
            return Err("invalid ledger boundary or output index base".into());
        }
        let prefix = integer(ledger, "output_prefix_count")?;
        let expected = if load.is_origin(id) {
            let manifest: wire::Signed<workload::Manifest> =
                serde_json::from_value(ledger["manifest"].clone()).map_err(|e| e.to_string())?;
            committee.verify_signature(&manifest)?;
            let expected = load.manifest(
                config.instance,
                id,
                committee.keys.len(),
                manifest.body.start_elapsed_us,
            );
            if manifest.signer != id
                || manifest.body != expected
                || expected.start_elapsed_us > config.max_runtime_ms * 1000
            {
                return Err("signed manifest differs from configured workload".into());
            }
            if integer(ledger, "window_start_us")?
                != expected.start_elapsed_us + load.warmup_ms * 1000
                || integer(ledger, "window_end_us")?
                    != expected.start_elapsed_us + (load.warmup_ms + load.measurement_ms) * 1000
            {
                return Err("measurement window differs from authenticated schedule".into());
            }
            signed_manifests += 1;
            Some(expected)
        } else {
            if !ledger["manifest"].is_null() {
                return Err("non-ingress replica has a manifest".into());
            }
            None
        };
        let mut next_sequence = 0;
        let requests = stream_rows(&root, id, ledger, "requests", |row| {
            let expected = expected
                .as_ref()
                .ok_or("non-ingress replica has requests")?;
            let sequence = integer(row, "sequence")?;
            if sequence != next_sequence
                || sequence >= expected.count
                || integer(row, "origin")? != id as u64
                || integer(row, "useful_bytes")? != expected.useful_bytes as u64
                || integer(row, "scheduled_us")? != expected.scheduled_us(sequence)
                || digest(row, "id")? != expected.transaction(sequence).id
            {
                return Err(
                    "request identity, population or schedule differs from signed manifest".into(),
                );
            }
            let ready_precedes =
                ledger
                    .get("batch_ready_precedes_materialization")
                    .map_or(Ok(true), |v| {
                        v.as_bool()
                            .ok_or("batch-ready ordering flag must be boolean")
                    })?;
            request_times(row, observed, collected, ready_precedes)?;
            next_sequence += 1;
            Ok(())
        })?;
        if requests != expected.as_ref().map_or(0, |m| m.count) {
            return Err("finite request population incomplete".into());
        }
        verified_requests += requests;
        let mut previous_ordinal = 0;
        verified_outputs += stream_rows(&root, id, ledger, "outputs", |row| {
            let origin = integer(row, "origin")?;
            let sequence = integer(row, "sequence")?;
            let ordinal = integer(row, "output_index")?;
            if origin >= committee.keys.len() as u64
                || !load.is_origin(origin as Id)
                || sequence >= load.arrival_count(origin as Id, committee.keys.len())
                || integer(row, "useful_bytes")? != load.useful_bytes() as u64
                || digest(row, "id")?
                    != workload::transaction(
                        config.instance,
                        origin as Id,
                        sequence,
                        load.useful_bytes(),
                    )
                    .id
                || ordinal <= previous_ordinal
                || ordinal > prefix
                || integer(row, "materialized_us")? > observed
            {
                return Err(
                    "output identity, ordinal or boundary differs from authenticated workload"
                        .into(),
                );
            }
            publication_time(row, collected)?;
            digest(row, "exact_batch_id")?;
            digest(row, "state_hash")?;
            previous_ordinal = ordinal;
            Ok(())
        })?;
        let mut next_batch = 1;
        verified_batches += stream_rows(&root, id, ledger, "batches", |row| {
            if integer(row, "output_index")? != next_batch
                || integer(row, "materialized_us")? > observed
            {
                return Err("exact batch order or boundary differs".into());
            }
            publication_time(row, collected)?;
            integer(row, "payload_bytes")?;
            digest(row, "exact_batch_id")?;
            next_batch += 1;
            Ok(())
        })?;
    }
    Ok(
        json!({"verified":true,"identity_version":2,"archive_schema":2,"index_sha256":hash(&raw),
        "signed_manifests":signed_manifests,"verified_requests":verified_requests,
        "verified_output_rows":verified_outputs,"verified_exact_batch_rows":verified_batches,
        "authentication":"strict Ed25519 manifests and canonical SHA256 request contents; exact schedule/population, bounded hashed pages and stream indexes",
        "consistency":"cross-stream admission/output joins and exact-ID deduplication are checked separately by disk-backed reducer",
        "resource_contract":{"max_manifest_bytes":MAX_MANIFEST,"max_page_bytes":MAX_PAGE,
            "max_index_line_bytes":MAX_LINE,"max_page_entries":MAX_ENTRIES,"max_row_bytes":MAX_ROW,"aggregate_byte_limit":null,
            "working_state":"one bounded page and at most 31 manifest headers; replica runtime state remains O(N)"}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        root: PathBuf,
        config: Config,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    impl Fixture {
        fn new(change: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "delugi-ledger-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let config: Config = serde_json::from_value(json!({
                "instance":vec![1u8;32],
                "addresses":["127.0.0.1:12001","127.0.0.1:12002","127.0.0.1:12003","127.0.0.1:12004"],
                "control_addresses":["127.0.0.1:12005","127.0.0.1:12006","127.0.0.1:12007","127.0.0.1:12008"],
                "control_token":"01234567890123456789012345678901",
                "public_keys":(0..4).map(|id|wire::fixture_key(id).public.to_bytes().to_vec()).collect::<Vec<_>>(),
                "key_files":["0.key","1.key","2.key","3.key"],"bound_ms":100,"chunk_capacity":4,
                "workload_rounds":4,"silent":null,"max_runtime_ms":5000,
                "sustained":{"rate_per_replica":3,"transaction_bytes":64,"useful_bytes":4,
                    "batch_ms":10,"warmup_ms":0,"measurement_ms":1000}
            })).unwrap();
            let load = config.sustained.as_ref().unwrap();
            let mut replicas = json!({});
            for id in 0..4 {
                let manifest = load.manifest(config.instance, id, 4, 900);
                let mut signed =
                    serde_json::to_value(wire::sign(&wire::fixture_key(id), id, manifest.clone()))
                        .unwrap();
                if change == "signature" && id == 0 {
                    signed["signature"][0] = json!(signed["signature"][0].as_u64().unwrap() ^ 1);
                }
                let mut rows: Vec<_> = (0..manifest.count)
                    .map(|sequence| {
                        json!({
                            "id":manifest.transaction(sequence).id,"origin":id,"sequence":sequence,
                            "useful_bytes":4,"scheduled_us":manifest.scheduled_us(sequence),
                            "admitted_us":null,"batch_ready_us":null,"materialized_us":null
                        })
                    })
                    .collect();
                if id == 0 {
                    match change {
                        "sequence" => rows.swap(0, 1),
                        "missing" => {
                            rows.pop();
                        }
                        "schedule" => rows[0]["scheduled_us"] = json!(1),
                        "identity" => rows[0]["id"] = json!(vec![0u8; 32]),
                        _ => {}
                    }
                }
                let mut ledger = json!({"manifest":signed,"output_index_base":1,"output_prefix_count":0,
                    "window_start_us":900,"window_end_us":1000900,"observed_us":2000000,"streams":{}});
                for (name, rows) in [
                    ("requests", rows),
                    ("outputs", Vec::new()),
                    ("batches", Vec::new()),
                ] {
                    let chunks: Vec<_> = if rows.is_empty() {
                        vec![&rows[..]]
                    } else {
                        rows.chunks(2).collect()
                    };
                    let mut index = Vec::new();
                    let mut offset = 0;
                    for (page_number, chunk) in chunks.iter().enumerate() {
                        let next = offset + chunk.len();
                        let page = json!({"replica":id,"manifest":signed,"elapsed_us":2000000,
                            "entries":chunk,"total":rows.len(),"next_offset":if next<rows.len(){Some(next)}else{None}});
                        let bytes = serde_json::to_vec(&page).unwrap();
                        let filename = format!("{id}-{name}-{page_number}.json");
                        fs::write(root.join(&filename), &bytes).unwrap();
                        let shard = json!({"path":filename,"sha256":hash(&bytes),"bytes":bytes.len(),"entries":chunk.len(),"offset":offset});
                        index.extend(serde_json::to_vec(&shard).unwrap());
                        index.push(b'\n');
                        offset = next;
                    }
                    let filename = format!("{id}-{name}.index.jsonl");
                    fs::write(root.join(&filename), &index).unwrap();
                    ledger["streams"][name] = json!({"path":filename,"sha256":hash(&index),"bytes":index.len(),"pages":chunks.len(),"entries":rows.len()});
                }
                replicas[id.to_string()] = ledger;
            }
            fs::write(
                root.join("index.json"),
                serde_json::to_vec(
                    &json!({"schema":2,"format":"delugi-cohort-pages-v2","replicas":replicas}),
                )
                .unwrap(),
            )
            .unwrap();
            Self { root, config }
        }
        fn verify(&self) -> Result<Value, String> {
            verify_workload_archive(&self.config, &self.root.join("index.json"))
        }
    }
    fn receipt_fixture(change: &str) -> Fixture {
        let mut fixture = Fixture::new("");
        fixture.config.observer_mode = workload::ObserverMode::Compact;
        if change == "empty" {
            let load = fixture.config.sustained.as_mut().unwrap();
            load.rate_per_replica = 1;
            load.measurement_ms = 1;
        }
        let load = fixture.config.sustained.as_ref().unwrap();
        let mut replicas = json!({});
        for id in 0..4 {
            let count = load.arrival_count(id, 4);
            let mut membership = workload::AdmissionReceipt::new(count);
            if count > 0 {
                membership.admitted.insert(0);
                membership.admitted.insert(1);
                membership.mark_ready(0);
                membership.mark_ready(1);
                membership.materialized(0);
                // First output before admission is retained but never gains
                // eligibility even when the final admission bitmap includes it.
                membership.seen_output.insert(1);
            }
            if change == "eligibility" && id == 0 {
                membership.completed.insert(2);
            }
            if change == "padding" && id == 0 {
                membership.admitted.bytes[0] |= 128;
                membership.admitted.ones += 1;
            }
            let mut streams = Vec::new();
            let mut paths = Vec::new();
            for origin in 0..4 {
                let mut bitmap = workload::Bitmap::new(load.arrival_count(origin, 4));
                if count > 0 {
                    bitmap.insert(0);
                    bitmap.insert(1);
                }
                let path = format!("receipt-{id}-materialized-{origin}.bits");
                fs::write(fixture.root.join(&path), &bitmap.bytes).unwrap();
                streams.push(bitmap.descriptor("materialized", origin));
                paths.push(json!({"name":"materialized","origin":origin,"path":path}));
            }
            for name in ["admitted", "rejected", "ready", "completed", "seen_output"] {
                let bitmap = membership.bitmap(name).unwrap();
                let path = format!("receipt-{id}-{name}.bits");
                fs::write(fixture.root.join(&path), &bitmap.bytes).unwrap();
                streams.push(bitmap.descriptor(name, id));
                paths.push(json!({"name":name,"origin":id,"path":path}));
            }
            let receipt = workload::Receipt {
                instance: fixture.config.instance,
                replica: id,
                mode: workload::ObserverMode::Compact,
                manifest: Some(wire::sign(
                    &wire::fixture_key(id),
                    id,
                    load.manifest(fixture.config.instance, id, 4, 900),
                )),
                scheduled: if count > 0 { 2 } else { 0 },
                output_count: if count > 0 { 8 } else { 0 },
                output_fingerprint: if count > 0 {
                    [8; 32]
                } else {
                    workload::output_seed()
                },
                batch_count: if count > 0 { 1 } else { 0 },
                batch_fingerprint: if count > 0 {
                    [9; 32]
                } else {
                    workload::batch_seed()
                },
                m_out_bytes: if count > 0 { 123 } else { 0 },
                streams,
            };
            let mut signed =
                serde_json::to_value(wire::sign(&wire::fixture_key(id), id, receipt)).unwrap();
            if change == "signature" && id == 0 {
                signed["signature"][0] = json!(signed["signature"][0].as_u64().unwrap() ^ 1);
            }
            if change == "missing" && id == 0 {
                paths.pop();
            }
            if change == "path" && id == 0 {
                paths[0]["path"] = json!("../outside.bits");
            }
            replicas[id.to_string()] = json!({"receipt":signed,"streams":paths});
        }
        fs::write(
            fixture.root.join("index.json"),
            serde_json::to_vec(
                &json!({"schema":3,"format":"delugi-observer-receipts-v1","replicas":replicas}),
            )
            .unwrap(),
        )
        .unwrap();
        if change == "hash" {
            fs::write(fixture.root.join("receipt-0-admitted.bits"), [0]).unwrap();
        }
        if change == "mode" {
            fixture.config.observer_mode = workload::ObserverMode::Full;
        }
        fixture
    }
    #[test]
    fn authenticates_compact_receipts_without_detailed_rows_including_empty_population() {
        for change in ["", "empty"] {
            let fixture = receipt_fixture(change);
            let verified = fixture.verify().unwrap();
            assert_eq!(verified["schema"], 3);
            assert_eq!(verified["verified_streams"], 36);
        }
    }
    #[test]
    fn receipt_verifier_rejects_signature_hash_population_padding_and_eligibility_changes() {
        for change in [
            "signature",
            "hash",
            "missing",
            "padding",
            "eligibility",
            "path",
            "mode",
        ] {
            assert!(
                receipt_fixture(change).verify().is_err(),
                "accepted {change}"
            );
        }
    }
    #[test]
    fn receipt_and_publication_use_collection_horizon_not_materialization_freeze() {
        let mut row = json!({"scheduled_us":1,"admitted_us":2,"batch_ready_us":3,
            "materialized_us":4,"post_handler_published_us":6,"all_correct_observed_us":7});
        assert!(request_times(&row, 5, 8, true).is_ok());
        row["all_correct_observed_us"] = json!(9);
        assert!(request_times(&row, 5, 8, true).is_err());
        row["all_correct_observed_us"] = json!(7);
        row["post_handler_published_us"] = json!(3);
        assert!(request_times(&row, 5, 8, true).is_err());
    }
    #[test]
    fn own_batch_ready_is_independent_when_an_admitted_request_is_materialized_elsewhere() {
        let mut row =
            json!({"scheduled_us":1,"admitted_us":2,"materialized_us":3,"batch_ready_us":4});
        assert!(request_times(&row, 5, 5, false).is_ok());
        assert!(request_times(&row, 5, 5, true).is_err());
        row["batch_ready_us"] = Value::Null;
        assert!(request_times(&row, 5, 5, false).is_ok());
        assert!(request_times(&row, 5, 5, true).is_err());
        row["admitted_us"] = Value::Null;
        assert!(request_times(&row, 5, 5, false).is_err());
    }
    #[test]
    fn authenticates_multiple_pages_without_whole_population_buffer() {
        let fixture = Fixture::new("");
        let result = fixture.verify().unwrap();
        assert_eq!(result["verified_requests"], 12);
        assert_eq!(result["signed_manifests"], 4);
        assert!(result["resource_contract"]["aggregate_byte_limit"].is_null());
    }
    #[test]
    fn rejects_changed_population_schedule_identity_and_signature() {
        for change in ["sequence", "missing", "schedule", "identity", "signature"] {
            let fixture = Fixture::new(change);
            assert!(fixture.verify().is_err(), "accepted {change}");
        }
    }
    #[test]
    fn rejects_page_hash_or_index_hash_changes() {
        let fixture = Fixture::new("");
        fs::write(fixture.root.join("0-requests-0.json"), b"{}\n").unwrap();
        assert!(fixture.verify().unwrap_err().contains("hash"));
        let fixture = Fixture::new("");
        let path = fixture.root.join("0-requests.index.jsonl");
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
        assert!(fixture.verify().is_err());
    }
    #[test]
    fn rejects_escape_symlink_and_oversized_components_before_parse() {
        let fixture = Fixture::new("");
        for path in [
            "../outside",
            "/etc/passwd",
            "a/../index.json",
            "./index.json",
        ] {
            assert!(confined(&fixture.root, path).is_err());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                fixture.root.join("0-requests-0.json"),
                fixture.root.join("link"),
            )
            .unwrap();
            assert!(confined(&fixture.root, "link").is_err());
            std::os::unix::fs::symlink(&fixture.root, fixture.root.join("dirlink")).unwrap();
            assert!(confined(&fixture.root, "dirlink/index.json").is_err());
        }
        let huge = fixture.root.join("huge");
        File::create(&huge).unwrap().set_len(MAX_PAGE + 1).unwrap();
        assert!(bounded(index_file(&huge).unwrap(), MAX_PAGE)
            .unwrap_err()
            .contains("byte bound"));
        let path = fixture.root.join("0-requests.index.jsonl");
        fs::write(path, vec![b'x'; MAX_LINE as usize + 1]).unwrap();
        assert!(fixture.verify().unwrap_err().contains("index line"));
    }
}
