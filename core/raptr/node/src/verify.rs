//! Offline authentication and replay of the finite shared-node application
//! archive. This authenticates observer evidence and native payloads; it does
//! not re-verify consensus QCs that are absent from the archive.
use crate::{
    config::{self, Committee, Config},
    workload::{self, Row},
};
use anyhow::{anyhow, ensure, Context as _, Result};
use aptos_consensus_types::common::BatchPayload;
use aptos_crypto::hash::CryptoHash;
use aptos_types::{account_address::AccountAddress, transaction::SignedTransaction};
use delugi_raptr_core::{BatchInfo, BatchKey, BlockId};
use serde::Deserialize;
use serde_json::{json, Value};
use shared_crypto::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    path::{Component, Path, PathBuf},
};

const RECEIPT_LIMIT: u64 = 4 * 1024 * 1024;
const MANIFEST_LIMIT: u64 = 384 * 1024 * 1024;
const JOURNAL_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const RECORD_LIMIT: usize = 64 * 1024 * 1024;
const MAX_SECTIONS: usize = 900_000;
const DOMAIN: &[u8] = b"delugi-shared-observer-receipt-v1\0";

fn uint(v: &Value, name: &str) -> Result<u64> {
    v.get(name)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing unsigned field {name}"))
}
fn string<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {name}"))
}
fn boolean(v: &Value, name: &str) -> Result<bool> {
    v.get(name)
        .and_then(Value::as_bool)
        .with_context(|| format!("missing Boolean field {name}"))
}
fn array<'a>(v: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    v.get(name)
        .and_then(Value::as_array)
        .with_context(|| format!("missing array {name}"))
}
fn fixed(text: &str) -> Result<[u8; 32]> {
    config::unhex(text)?
        .try_into()
        .map_err(|_| anyhow!("expected32-byte identity"))
}

/// New receipts carry owned-task evidence. Older immutable schema-1 receipts
/// predate these fields and remain readable without inventing cleanup evidence.
fn executor_evidence(body: &Value) -> Result<()> {
    let before = body.get("executor_at_freeze");
    let after = body.get("executor_at_cleanup");
    if before.is_none() && after.is_none() {
        return Ok(());
    }
    let before = before.context("missing frozen executor snapshot")?;
    let after = after.context("missing cleanup executor snapshot")?;
    ensure!(
        before["limits"] == after["limits"],
        "executor limits changed"
    );
    for (snapshot, clean) in [(before, false), (after, true)] {
        ensure!(
            snapshot.get("failure").is_some_and(Value::is_null)
                && uint(snapshot, "panicked")? == 0
                && uint(snapshot, "rejected_capacity")? == 0,
            "executor failure or capacity rejection"
        );
        let mut retained_total = 0_u64;
        for kind in ["async", "blocking"] {
            let get = |prefix: &str| uint(snapshot, &format!("{prefix}_{kind}"));
            let admitted = get("admitted")?;
            let joined = get("joined")?;
            let retained = get("retained")?;
            let queued = get("queued")?;
            let active = get("active")?;
            let maximum = get("maximum_retained")?;
            let limit = uint(&snapshot["limits"], &format!("max_{kind}_tasks"))?;
            ensure!(
                admitted.checked_sub(joined) == Some(retained)
                    && get("started")? <= admitted
                    && get("body_finished")? <= get("started")?
                    && get("cancelled")? <= joined
                    && queued.checked_add(active).is_some_and(|v| v <= retained)
                    && retained <= maximum
                    && maximum <= limit
                    && limit > 0,
                "inconsistent executor {kind} counters"
            );
            ensure!(
                !clean || (admitted == joined && retained == 0 && queued == 0 && active == 0),
                "unjoined executor work after cleanup"
            );
            retained_total = retained_total
                .checked_add(retained)
                .context("executor count overflow")?;
        }
        let groups = array(snapshot, "groups")?;
        ensure!(groups.len() <= 64, "executor group bound exceeded");
        let mut ids = BTreeSet::new();
        let mut group_retained = 0_u64;
        for group in groups {
            ensure!(ids.insert(uint(group, "id")?), "duplicate executor group");
            let label = string(group, "label")?;
            ensure!(
                !label.is_empty() && label.len() <= 128,
                "invalid executor group label"
            );
            let retained = uint(group, "retained")?;
            ensure!(
                !clean || (boolean(group, "closed")? && retained == 0),
                "executor group still open or retained"
            );
            boolean(group, "closed")?;
            group_retained = group_retained
                .checked_add(retained)
                .context("executor group count overflow")?;
        }
        ensure!(
            group_retained == retained_total,
            "executor group population mismatch"
        );
    }
    for kind in ["async", "blocking"] {
        for prefix in [
            "admitted",
            "started",
            "body_finished",
            "joined",
            "cancelled",
            "maximum_retained",
        ] {
            let field = format!("{prefix}_{kind}");
            ensure!(
                uint(before, &field)? <= uint(after, &field)?,
                "executor cumulative counter regressed: {field}"
            );
        }
    }
    for field in ["panicked", "rejected_capacity", "rejected_closed"] {
        ensure!(
            uint(before, field)? <= uint(after, field)?,
            "executor cumulative counter regressed: {field}"
        );
    }
    for group in array(before, "groups")? {
        let id = uint(group, "id")?;
        let final_group = array(after, "groups")?
            .iter()
            .find(|v| v["id"].as_u64() == Some(id))
            .context("executor group disappeared before cleanup")?;
        ensure!(
            group["label"] == final_group["label"],
            "executor group identity changed"
        );
    }
    Ok(())
}

fn relative(root: &Path, name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    ensure!(
        !path.as_os_str().is_empty()
            && path.components().all(|c| matches!(c, Component::Normal(_))),
        "unsafe archive path"
    );
    let mut result = root.to_path_buf();
    for part in path.components() {
        result.push(part.as_os_str());
        ensure!(
            !fs::symlink_metadata(&result)?.file_type().is_symlink(),
            "archive symlink rejected"
        );
    }
    Ok(result)
}
fn open(path: &Path, maximum: u64) -> Result<File> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() && !before.file_type().is_symlink() && before.len() <= maximum,
        "nonregular or oversized evidence file"
    );
    let file = File::open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            before.dev() == after.dev() && before.ino() == after.ino(),
            "evidence file replaced while opening"
        );
    }
    ensure!(
        after.len() == before.len(),
        "evidence length changed while opening"
    );
    Ok(file)
}
fn json_file(path: &Path, maximum: u64) -> Result<(Value, String, u64)> {
    let mut file = open(path, maximum)?;
    let mut bytes = Vec::new();
    file.by_ref().take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "evidence grew beyond limit");
    Ok((
        serde_json::from_slice(&bytes)?,
        config::digest(&bytes),
        bytes.len() as u64,
    ))
}
#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    name: String,
    sha256: String,
    bytes: u64,
    rows: u64,
}
fn check_record(record: &FileRecord, hash: &str, bytes: u64, rows: u64) -> Result<()> {
    ensure!(
        record.sha256 == hash && record.bytes == bytes && record.rows == rows,
        "authenticated file record mismatch: {}",
        record.name
    );
    Ok(())
}
/// Hash exactly the bytes passed to the row validator, rejecting a missing last
/// newline. No second file pass can substitute data after authentication.
fn journal(
    path: &Path,
    record: &FileRecord,
    max_rows: u64,
    mut visit: impl FnMut(Value) -> Result<()>,
) -> Result<()> {
    ensure!(
        record.bytes <= JOURNAL_LIMIT && record.rows <= max_rows,
        "journal exceeds finite verifier envelope"
    );
    let mut reader = BufReader::new(open(path, JOURNAL_LIMIT)?);
    let mut hash = Sha256::new();
    let mut bytes = 0_u64;
    let mut rows = 0_u64;
    loop {
        let mut line = Vec::new();
        let length = reader
            .by_ref()
            .take(RECORD_LIMIT as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if length == 0 {
            break;
        }
        ensure!(
            length <= RECORD_LIMIT && line.last() == Some(&b'\n'),
            "oversized or unterminated journal row"
        );
        rows += 1;
        bytes = bytes
            .checked_add(length as u64)
            .context("journal length overflow")?;
        ensure!(
            rows <= max_rows && bytes <= record.bytes,
            "journal exceeds declared population/size"
        );
        hash.update(&line);
        visit(serde_json::from_slice(&line)?)?;
    }
    check_record(
        record,
        &config::hex(hash.finalize().as_slice()),
        bytes,
        rows,
    )
}

struct Verified {
    signer: u32,
    sections: Vec<[u8; 32]>,
    summary: Value,
}
fn public_committee(config: &Config) -> Result<(Committee, String)> {
    let (value, hash, _) = json_file(&config.key_directory.join("committee.json"), RECEIPT_LIMIT)?;
    let committee: Committee = serde_json::from_value(value)?;
    ensure!(
        committee.schema == 1
            && committee.epoch == config.epoch
            && committee.members.len() == config.addresses.len(),
        "public committee mismatch"
    );
    let mut authors = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for (id, member) in committee.members.iter().enumerate() {
        ensure!(
            member.id as usize == id
                && authors.insert(fixed(&member.author)?)
                && keys.insert(fixed(&member.transport_public)?),
            "duplicate/noncontiguous public committee"
        );
        shared_crypto::PublicKey::from_bytes(&config::unhex(&member.transport_public)?)?;
    }
    Ok((committee, hash))
}
fn event(events: &mut BTreeMap<u64, u64>, id: Option<u64>, time: Option<u64>) -> Result<()> {
    match (id, time) {
        (None, None) => Ok(()),
        (Some(id), Some(time)) => {
            ensure!(
                id > 0 && events.insert(id, time).is_none(),
                "duplicate/zero local event"
            );
            Ok(())
        }
        _ => Err(anyhow!("stage event/time presence mismatch")),
    }
}
fn verify_inner(raw: &[u8], path: &Path) -> Result<Verified> {
    let (envelope, receipt_hash, _) = json_file(path, RECEIPT_LIMIT)?;
    let signer = u32::try_from(uint(&envelope, "signer")?)?;
    let config = Config::parse(raw, signer)?;
    let (committee, committee_hash) = public_committee(&config)?;
    ensure!(uint(&envelope, "schema")? == 1, "receipt schema mismatch");
    let encoded = config::unhex(string(&envelope, "body_bcs_hex")?)?;
    let body_json: Vec<u8> = bcs::from_bytes(&encoded)?;
    ensure!(
        bcs::to_bytes(&body_json)? == encoded,
        "noncanonical signed body BCS"
    );
    let body: Value = serde_json::from_slice(&body_json)?;
    ensure!(
        serde_json::to_vec(&body)? == body_json,
        "signed body JSON is not the canonical compact encoding"
    );
    ensure!(
        envelope.get("body") == Some(&body),
        "displayed body differs from signed bytes"
    );
    let signature =
        shared_crypto::Signature::from_bytes(&config::unhex(string(&envelope, "signature_hex")?)?)?;
    let public = shared_crypto::PublicKey::from_bytes(&config::unhex(
        &committee.members[signer as usize].transport_public,
    )?)?;
    let mut signed = DOMAIN.to_vec();
    signed.extend_from_slice(&encoded);
    shared_crypto::verify_ed25519_strict(
        &public,
        &signed,
        &signature,
        shared_metrics::Operation::ObserverReceiptVerify,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        uint(&body, "schema")? == 1
            && uint(&body, "id")? == signer as u64
            && string(&body, "profile")? == config::PROFILE,
        "signed profile/identity mismatch"
    );
    ensure!(
        string(&body, "run_id")? == config.run_id
            && string(&body, "configuration_sha256")? == config::digest(raw)
            && string(&body, "committee_sha256")? == committee_hash,
        "signed configuration binding mismatch"
    );
    ensure!(
        string(&body, "status")? == "completed",
        "failed runtime receipt is not an accepted archive"
    );
    ensure!(
        body.get("async_transport")
            .and_then(|v| v.get("terminal_error"))
            .is_some_and(Value::is_null),
        "transport terminal failure at observer freeze"
    );
    let epoch = uint(&body, "epoch_us")?;
    let deadline = uint(&body, "deadline_us")?;
    let freeze = uint(&body, "freeze_us")?;
    if body.get("snapshot_completed_us").is_some() || body.get("snapshot_copy_us").is_some() {
        let completed = uint(&body, "snapshot_completed_us")?;
        ensure!(
            completed.checked_sub(freeze) == Some(uint(&body, "snapshot_copy_us")?),
            "snapshot copy timing mismatch"
        );
    }
    executor_evidence(&body)?;
    ensure!(
        epoch.checked_add((config.measurement_duration_ms + config.drain_ms) * 1000)
            == Some(deadline)
            && freeze >= deadline,
        "finite deadline/freeze mismatch"
    );
    let root = path.parent().context("receipt has no directory")?;
    let mut records = BTreeMap::new();
    for value in array(&body, "files")? {
        let row: FileRecord = serde_json::from_value(value.clone())?;
        ensure!(
            [
                "workload-manifest.json",
                "requests.jsonl",
                "output.jsonl",
                "effective-profile.json",
                "planned.jsonl",
                "latency-trace.json"
            ]
            .contains(&row.name.as_str()),
            "unrecognized receipt file"
        );
        ensure!(
            records.insert(row.name.clone(), row).is_none(),
            "duplicate receipt file"
        );
    }
    ensure!(
        records.len()
            == (if config.schema == 2 { 5 } else { 4 })
                + usize::from(config.latency_trace.is_some()),
        "missing receipt file"
    );
    ensure!(
        records.contains_key("latency-trace.json") == config.latency_trace.is_some(),
        "latency trace file/configuration mismatch"
    );
    ensure!(
        config.schema == 2 || !records.contains_key("planned.jsonl"),
        "unexpected sustained file"
    );
    ensure!(
        records["output.jsonl"].bytes <= config.limits.max_journal_bytes,
        "application output journal exceeds configured cumulative bound"
    );
    let (profile, hash, size) =
        json_file(&relative(root, "effective-profile.json")?, RECEIPT_LIMIT)?;
    check_record(&records["effective-profile.json"], &hash, size, 1)?;
    if let Some(settings) = &config.latency_trace {
        let (trace, hash, size) =
            json_file(&relative(root, "latency-trace.json")?, MANIFEST_LIMIT)?;
        check_record(&records["latency-trace.json"], &hash, size, 1)?;
        ensure!(
            string(&trace, "schema")? == "raptr-latency-trace-v1"
                && string(&trace, "run_id")? == config.run_id
                && string(&trace, "configuration_sha256")? == config::digest(raw)
                && uint(&trace, "replica")? == signer as u64
                && string(&trace, "clock")? == "CLOCK_MONOTONIC"
                && uint(&trace, "max_events")? == settings.max_events as u64
                && array(&trace, "events")?.len() <= settings.max_events,
            "latency trace binding or envelope mismatch"
        );
        // Overflow remains valid raw evidence, but the stage reducer refuses
        // incomplete traces; it must never fabricate absent boundaries.
        uint(&trace, "dropped")?;
    }
    let endpoint_v2 = profile.get("output_endpoint").is_some();
    if endpoint_v2 {
        ensure!(
            string(&profile, "output_endpoint")? == workload::OUTPUT_ENDPOINT
                && profile.get("latency_trace").cloned().unwrap_or(Value::Null)
                    == serde_json::to_value(&config.latency_trace)?,
            "output observer profile mismatch"
        );
    }
    ensure!(
        string(&profile, "profile")? == config::PROFILE
            && string(&profile, "committee_sha256")? == committee_hash
            && uint(&profile, "configured_delta_ms")? == config.delta_ms
            && uint(&profile, "injected_delay_ms")? == 0,
        "effective execution profile mismatch"
    );
    ensure!(
        profile["consensus"] == serde_json::to_value(config.consensus.clone().unwrap_or_default())?
            && profile["quorum_store"]
                == serde_json::to_value(config.quorum_store.clone().unwrap_or_default())?
            && profile["limits"] == serde_json::to_value(&config.limits)?,
        "effective policy/resource settings differ from configuration"
    );
    let (manifest, hash, size) =
        json_file(&relative(root, "workload-manifest.json")?, MANIFEST_LIMIT)?;
    check_record(&records["workload-manifest.json"], &hash, size, 1)?;
    ensure!(
        uint(&manifest, "schema")? == config.schema as u64
            && uint(&manifest, "origin")? == signer as u64
            && string(&manifest, "profile")? == config::PROFILE
            && string(&manifest, "run_id")? == config.run_id
            && string(&manifest, "configuration_sha256")? == config::digest(raw),
        "workload manifest binding mismatch"
    );
    let planned = config.finite_workload.counts[signer as usize];
    let mut identities = Vec::with_capacity(planned as usize);
    let mut verify_planned = |request: Value| -> Result<()> {
        let sequence = identities.len();
        let bytes = config::unhex(string(&request, "native_transaction_bcs_hex")?)?;
        let tx: SignedTransaction = bcs::from_bytes(&bytes)?;
        ensure!(
            bcs::to_bytes(&tx)? == bytes,
            "noncanonical native transaction bytes"
        );
        let (origin, seq, id) = workload::identify(&config, &committee, &tx)?;
        ensure!(
            origin == signer
                && seq == sequence as u64
                && uint(&request, "sequence")? == seq
                && string(&request, "request_id")? == id
                && uint(&request, "useful_bytes")? == config.finite_workload.useful_bytes as u64,
            "finite request identity mismatch"
        );
        identities.push((id, config::hex(tx.committed_hash().as_ref())));
        Ok(())
    };
    if config.schema == 2 {
        ensure!(
            manifest["planned_file"] == serde_json::to_value(&records["planned.jsonl"])?,
            "planned file descriptor differs"
        );
        journal(
            &relative(root, "planned.jsonl")?,
            &records["planned.jsonl"],
            planned,
            &mut verify_planned,
        )?;
    } else {
        let requests = array(&manifest, "requests")?;
        for request in requests {
            verify_planned(request.clone())?;
        }
    }
    ensure!(
        identities.len() as u64 == planned,
        "planned population mismatch"
    );
    drop(manifest);
    let mut rows = Vec::<Row>::with_capacity(planned as usize);
    let mut events = BTreeMap::new();
    journal(
        &relative(root, "requests.jsonl")?,
        &records["requests.jsonl"],
        planned,
        |value| {
            let row: Row = serde_json::from_value(value)?;
            let sequence = rows.len();
            ensure!(
                row.sequence == sequence as u64
                    && identities.get(sequence)
                        == Some(&(row.request_id.clone(), row.native_transaction_hash.clone()))
                    && row.useful_bytes == config.finite_workload.useful_bytes,
                "request journal identity/order mismatch"
            );
            ensure!(
                row.planned_us == epoch + config.planned_offset_us(signer, row.sequence)?,
                "request intended schedule mismatch"
            );
            ensure!(
                row.admitted_us.is_none() || row.rejected_us.is_none(),
                "request both admitted and rejected"
            );
            for time in [row.admitted_us, row.rejected_us].into_iter().flatten() {
                ensure!(
                    time >= row.planned_us
                        && time
                            < if config.schema == 2 {
                                epoch + config.measurement_duration_ms * 1000
                            } else {
                                deadline
                            },
                    "request admission/rejection outside schedule/deadline"
                );
            }
            event(&mut events, row.admission_event, row.admitted_us)?;
            event(&mut events, row.rejection_event, row.rejected_us)?;
            event(&mut events, row.cancellation_event, row.cancelled_us)?;
            if config.schema == 2 {
                let outcomes = [row.admitted_us, row.rejected_us, row.cancelled_us]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                ensure!(
                    outcomes.len() <= 1 && row.offered_us.is_some() == !outcomes.is_empty(),
                    "offer outcome missing or contradictory"
                );
                if let Some(offered) = row.offered_us {
                    let prepared = row.prepared_us.context("missing preparation endpoint")?;
                    ensure!(
                        row.planned_us <= offered
                            && offered <= prepared
                            && prepared <= outcomes[0]
                            && outcomes[0] <= freeze,
                        "invalid offer/preparation/outcome ordering"
                    );
                } else {
                    ensure!(row.prepared_us.is_none(), "preparation without an offer");
                }
                if let Some(cancelled) = row.cancelled_us {
                    ensure!(
                        cancelled >= epoch + config.measurement_duration_ms * 1000,
                        "early cutoff cancellation"
                    );
                }
            } else {
                ensure!(
                    row.offered_us.is_none()
                        && row.prepared_us.is_none()
                        && row.cancelled_us.is_none(),
                    "sustained field in finite journal"
                );
            }

            ensure!(
                row.rejection.is_some()
                    == (row.rejected_us.is_some() || row.cancelled_us.is_some()),
                "request rejection reason mismatch"
            );
            ensure!(
                row.first_materialized_event.is_some() == row.first_materialized_us.is_some(),
                "completion event/time mismatch"
            );
            if let Some(ready) = row.own_batch_ready_us {
                ensure!(
                    row.admitted_us.is_some_and(|a| a <= ready) && ready <= freeze,
                    "own batch readiness outside admitted lifetime"
                );
            }
            rows.push(row);
            Ok(())
        },
    )?;
    ensure!(rows.len() as u64 == planned, "missing finite request rows");
    let mut sections = Vec::new();
    let mut previous: Option<(BlockId, usize)> = None;
    let mut batches = BTreeMap::<BatchKey, (u64, u64)>::new();
    let mut seen = BTreeSet::new();
    let mut completions = BTreeMap::<u64, (u64, u64)>::new();
    let mut unadmitted = 0_u64;
    let mut raw_txns = 0_u64;
    let mut exact_bytes = 0_u64;
    journal(
        &relative(root, "output.jsonl")?,
        &records["output.jsonl"],
        MAX_SECTIONS as u64,
        |section| {
            ensure!(
                uint(&section, "schema")? == 1
                    && uint(&section, "ordinal")? == sections.len() as u64,
                "output section ordinal gap"
            );
            let time = uint(&section, "append_us")?;
            if endpoint_v2 {
                ensure!(
                    string(&section, "timing_contract")? == workload::OUTPUT_ENDPOINT
                        && uint(&section, "app_processing_start_us")? <= time
                        && time <= uint(&section, "journal_constructed_us")?
                        && uint(&section, "journal_constructed_us")? <= freeze,
                    "invalid pre-journal application timing boundary"
                );
            } else {
                ensure!(
                    section.get("timing_contract").is_none(),
                    "unbound output timing contract"
                );
            }
            let event_id = uint(&section, "event")?;
            ensure!(
                time >= epoch && time < deadline,
                "application output after finite deadline"
            );
            event(&mut events, Some(event_id), Some(time))?;
            let block = &section["block"];
            let block = BlockId {
                epoch: uint(block, "epoch")?,
                round: block
                    .get("round")
                    .and_then(Value::as_i64)
                    .context("invalid native round")?,
                author: fixed(string(block, "author")?)?,
                digest: fixed(string(block, "digest")?)?,
            };
            ensure!(
                block.epoch == config.epoch
                    && committee
                        .members
                        .iter()
                        .any(|m| m.author == config::hex(&block.author)),
                "output block outside committee/epoch"
            );
            let kind = &section["section"];
            let proof = string(kind, "kind")? == "proofs";
            let sub = if proof {
                None
            } else {
                ensure!(string(kind, "kind")? == "sub_block", "unknown section kind");
                Some(usize::try_from(uint(kind, "index")?)?)
            };
            match &previous {
                Some((old, next)) if old == &block => {
                    ensure!(
                        sub == Some(*next) && *next < 8,
                        "noncontiguous native subblock prefix"
                    );
                }
                Some((old, _)) => {
                    ensure!(
                        proof && old.digest != block.digest && old.round < block.round,
                        "noncanonical native block order"
                    );
                }
                None => ensure!(proof, "output lacks initial proofs marker"),
            }
            previous = Some((block.clone(), sub.map_or(0, |i| i + 1)));
            let mut fingerprint_batches = Vec::new();
            for batch in array(&section, "batches")? {
                let descriptor_bytes = config::unhex(string(batch, "native_info_bcs_hex")?)?;
                let info = BatchInfo::from_native_bcs(&descriptor_bytes)
                    .map_err(|e| anyhow!("native BatchInfo: {e:?}"))?;
                ensure!(info.key.epoch == config.epoch, "batch epoch mismatch");
                let key = &batch["key"];
                ensure!(
                    uint(key, "epoch")? == info.key.epoch
                        && fixed(string(key, "author")?)? == info.key.author
                        && uint(key, "nonce")? == info.key.nonce
                        && uint(key, "id")? == info.key.id
                        && fixed(string(key, "digest")?)? == info.key.digest,
                    "displayed/native batch identity mismatch"
                );
                let first = !batches.contains_key(&info.key);
                ensure!(
                    boolean(batch, "first_occurrence")? == first,
                    "exact-batch first occurrence mismatch"
                );
                if let Some(shape) = batches.get(&info.key) {
                    ensure!(
                        *shape == (info.num_txns, info.num_bytes),
                        "same exact batch has conflicting shape"
                    );
                }
                let mut txns = Vec::new();
                let mut fingerprint_txns = Vec::new();
                for transaction in array(batch, "transactions")? {
                    let bytes = config::unhex(string(transaction, "native_transaction_bcs_hex")?)?;
                    let tx: SignedTransaction = bcs::from_bytes(&bytes)?;
                    ensure!(
                        bcs::to_bytes(&tx)? == bytes,
                        "noncanonical output transaction"
                    );
                    let id = config::digest(&bytes);
                    let identity = workload::identify(&config, &committee, &tx).ok();
                    ensure!(
                        string(transaction, "request_id")? == id
                            && boolean(transaction, "eligible")? == identity.is_some(),
                        "output identity/recognized status mismatch"
                    );
                    let mut credit = false;
                    let mut is_first = false;
                    if let Some((origin, seq, verified_id)) = identity {
                        ensure!(
                            verified_id == id
                                && uint(transaction, "origin")? == origin as u64
                                && uint(transaction, "sequence")? == seq,
                            "output finite metadata mismatch"
                        );
                        is_first = seen.insert(id.clone());
                        if origin == signer && is_first {
                            let request = &rows[seq as usize];
                            credit = request.admission_event.is_some_and(|e| e < event_id);
                            if credit {
                                ensure!(
                                    request.admitted_us.is_some_and(|t| t <= time),
                                    "credit precedes admission clock"
                                );
                                completions.insert(seq, (time, event_id));
                            } else {
                                unadmitted += 1;
                            }
                        }
                    } else {
                        ensure!(
                            transaction["origin"].is_null() && transaction["sequence"].is_null(),
                            "foreign output claims finite metadata"
                        );
                    }
                    ensure!(
                        boolean(transaction, "first_seen")? == is_first
                            && boolean(transaction, "own_credit")? == credit,
                        "append-time first-output eligibility mismatch"
                    );
                    fingerprint_txns.push(config::hex(&bytes));
                    txns.push(tx);
                    raw_txns += 1;
                }
                let payload = BatchPayload::new(AccountAddress::new(info.key.author), txns);
                ensure!(
                    payload.hash().as_ref() == &info.key.digest
                        && payload.num_txns() as u64 == info.num_txns
                        && payload.num_bytes() as u64 == info.num_bytes,
                    "native BatchPayload digest/count/bytes mismatch"
                );
                if first {
                    exact_bytes = exact_bytes
                        .checked_add(info.num_bytes)
                        .context("exact batch byte overflow")?;
                }
                batches.insert(info.key.clone(), (info.num_txns, info.num_bytes));
                fingerprint_batches.push(json!({"native_info_bcs_hex":config::hex(&descriptor_bytes),"first_occurrence":first,"transactions":fingerprint_txns}));
            }
            let canonical = json!({"ordinal":sections.len(),"block":{"epoch":block.epoch,"round":block.round,"author":config::hex(&block.author),"digest":config::hex(&block.digest)},"section":kind,"batches":fingerprint_batches});
            sections.push(shared_crypto::sha256(
                &[
                    b"raptr-native-section-archive-v1\0",
                    &serde_json::to_vec(&canonical)?,
                ],
                None,
            ));
            Ok(())
        },
    )?;
    for (sequence, row) in rows.iter().enumerate() {
        ensure!(
            completions.get(&(sequence as u64)).copied()
                == row.first_materialized_us.zip(row.first_materialized_event),
            "origin completion differs from first eligible raw output"
        );
    }
    for (offset, (id, time)) in events.iter().enumerate() {
        ensure!(*id == offset as u64 + 1, "local serialized event gap");
        if offset > 0 {
            ensure!(
                *time >= *events.get(&(id - 1)).unwrap(),
                "local event clock reversal"
            );
        }
    }
    let admitted = rows.iter().filter(|r| r.admitted_us.is_some()).count() as u64;
    let rejected = rows.iter().filter(|r| r.rejected_us.is_some()).count() as u64;
    let cancelled = rows.iter().filter(|r| r.cancelled_us.is_some()).count() as u64;
    let completed = completions.len() as u64;
    let counts = &body["counts"];
    if config.schema == 2 {
        ensure!(
            uint(counts, "cancelled")? == cancelled && counts["ingress_error"].is_null(),
            "failed ingress or cancellation mismatch"
        );
    }
    for (name, value) in [
        ("planned", planned),
        ("scheduled", planned),
        ("offered", admitted + rejected + cancelled),
        ("admitted", admitted),
        ("rejected", rejected),
        ("unoffered", planned - admitted - rejected - cancelled),
        (
            "scheduled_not_offered",
            planned - admitted - rejected - cancelled,
        ),
        ("completed", completed),
        ("origin_completed", completed),
        ("unfinished", admitted - completed),
        ("output_sections", sections.len() as u64),
        ("unique_eligible_output", seen.len() as u64),
        ("unique_recognized_output", seen.len() as u64),
        ("unadmitted_first_outputs", unadmitted),
    ] {
        ensure!(
            uint(counts, name)? == value,
            "finite count mismatch: {name}"
        );
    }
    ensure!(
        boolean(&body["output_snapshot"], "frozen")?
            && uint(&body["output_snapshot"], "published_sections")? >= sections.len() as u64
            && uint(&body["output_snapshot"], "published_transactions")? >= raw_txns,
        "materializer/app prefix inconsistency"
    );
    Ok(Verified {
        signer,
        summary: json!({"schema":1,"verified":true,"signer":signer,"receipt_sha256":receipt_hash,"sections":sections.len(),"raw_transaction_occurrences":raw_txns,"distinct_native_batches":batches.len(),"distinct_native_payload_bytes":exact_bytes,"planned":planned,"admitted":admitted,"origin_completed":completed,"unfinished":admitted-completed,"verification_scope":"signed observer archive, authenticated finite native transactions, exact native batch payloads and canonical section prefix; native QC bytes absent, QC verification not claimed","limits":{"journal_bytes":JOURNAL_LIMIT,"record_bytes":RECORD_LIMIT,"manifest_bytes":MANIFEST_LIMIT,"sections":MAX_SECTIONS}}),
        sections,
    })
}

pub fn verify_receipt(config_bytes: &[u8], path: &Path) -> Result<String> {
    Ok(verify_inner(config_bytes, path)?.summary.to_string())
}
pub fn verify_archive(config_bytes: &[u8], path: &Path) -> Result<String> {
    let config = Config::parse(config_bytes, 0)?;
    let (index, index_hash, _) = json_file(path, RECEIPT_LIMIT)?;
    ensure!(
        uint(&index, "schema")? == 1
            && string(&index, "run_id")? == config.run_id
            && string(&index, "configuration_sha256")? == config::digest(config_bytes),
        "archive index binding mismatch"
    );
    let names = array(&index, "receipts")?;
    ensure!(
        !names.is_empty() && names.len() <= config.addresses.len(),
        "invalid archive receipt count"
    );
    let mut signers = BTreeSet::new();
    let mut longest = Vec::<[u8; 32]>::new();
    let mut reports = Vec::new();
    for name in names {
        let item = verify_inner(
            config_bytes,
            &relative(
                path.parent().context("index parent")?,
                name.as_str().context("receipt path must be string")?,
            )?,
        )?;
        ensure!(signers.insert(item.signer), "duplicate archive signer");
        ensure!(
            longest.iter().zip(&item.sections).all(|(a, b)| a == b),
            "replica native section prefixes diverge"
        );
        if item.sections.len() > longest.len() {
            longest = item.sections;
        }
        reports.push(item.summary);
    }
    Ok(json!({"schema":1,"verified":true,"verified_signers":signers,"index_sha256":index_hash,"replicas":reports,"native_output_overlapping_prefixes_agree":true,"native_qc_reverification":false}).to_string())
}
