//! Producer-authenticated records, exact fork custody, and verified suffix transfer.
//!
//! Storage is deliberately retained indefinitely. A metadata boundary authenticates
//! its terminal digest and peaks, but never counts older payloads as locally held.

use crate::mmr::{self, Boundary, Checkpoint, Config, PrefixProof, State};
pub use crate::record_store::{Snapshot as StorageSnapshot, StorageProfile};
use crate::wire::{encode, hash, sign, Committee, Context, Digest, Id, Signed, SigningDomain};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bound each batch independently; complete DATA responses also obey the wire cap.
pub const MAX_BATCH_PAYLOAD: usize = 256 * 1024;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchHeader {
    pub context: Context,
    pub producer: Id,
    pub height: u64,
    pub previous: Digest,
    pub payload_hash: Digest,
}
impl SigningDomain for BatchHeader {
    const DOMAIN: &'static str = "dissemination-batch";
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Record {
    pub header: Signed<BatchHeader>,
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Data {
    pub from: Checkpoint,
    pub to: Checkpoint,
    pub boundary: Boundary,
    pub records: Vec<Record>,
}
/// A bounded transport segment for one exact FETCH. Prefix proofs bind both
/// segment endpoints to the requested suffix, so segments may arrive reordered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DataPart {
    pub requested_from: Checkpoint,
    pub requested_to: Checkpoint,
    pub data: Data,
    pub before: PrefixProof,
    pub after: PrefixProof,
}
pub fn genesis_digest(c: &Config, k: Id) -> Digest {
    hash(&("BATCH/GENESIS", &c.context, k))
}
pub fn header_digest(h: &BatchHeader) -> Digest {
    hash(&("BATCH/HEADER", h))
}
pub fn record_digest(record: &Record) -> Digest {
    header_digest(&record.header.body)
}
pub fn payload_hash(payload: &[u8]) -> Digest {
    hash(&("BATCH/PAYLOAD", payload))
}

pub fn verify_record(committee: &Committee, record: &Record) -> Result<(), String> {
    if record.payload.len() > MAX_BATCH_PAYLOAD {
        return Err("batch payload exceeds configured limit".into());
    }
    encode(record)?;
    let h = &record.header.body;
    if h.context != committee.context
        || h.producer != record.header.signer
        || h.height == 0
        || h.height == u64::MAX
    {
        return Err("batch context, producer or height mismatch".into());
    }
    committee.verify_signature(&record.header)?;
    if payload_hash(&record.payload) != h.payload_hash {
        return Err("batch payload hash mismatch".into());
    }
    Ok(())
}
#[derive(Clone, Debug)]
struct Branch {
    anchor: Checkpoint,
    state: State,
}
#[derive(Debug)]
pub struct BatchStore {
    committee: Committee,
    config: Config,
    records: crate::record_store::RecordStore,
    retained_payload_bytes: u64,
    /// One mutable tip per fork and independently imported base. Each State already
    /// retains every historical checkpoint and proof node; prefix copies are not
    /// separate branches.
    branches: BTreeMap<usize, Branch>,
    /// Verified records waiting for this exact predecessor (including its height).
    children: BTreeMap<(Id, u64, Digest), BTreeSet<Digest>>,
    /// A representative retained State for each prefix under each custody anchor.
    prefixes: BTreeMap<(Id, u64, Digest), BTreeMap<Digest, usize>>,
    checkpoint_branches: BTreeMap<Digest, BTreeMap<Digest, usize>>,
    checkpoints: BTreeMap<(Id, u64, Digest), Checkpoint>,
    attached: BTreeSet<(Digest, Digest)>,
    #[cfg(test)]
    extension_attempts: usize,
    produced: BTreeMap<Id, (u64, Digest)>,
    custody: BTreeSet<(Digest, Digest)>,
}
impl BatchStore {
    pub fn new(committee: Committee, chunk_capacity: u64) -> Result<Self, String> {
        let config = Config {
            context: committee.context.clone(),
            chunk_capacity,
        };
        config.validate()?;
        let mut store = Self {
            committee,
            config,
            records: crate::record_store::RecordStore::new(),
            retained_payload_bytes: 0,
            branches: BTreeMap::new(),
            children: BTreeMap::new(),
            prefixes: BTreeMap::new(),
            checkpoint_branches: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            attached: BTreeSet::new(),
            #[cfg(test)]
            extension_attempts: 0,
            produced: BTreeMap::new(),
            custody: BTreeSet::new(),
        };
        for k in 0..store.committee.keys.len() as Id {
            let branch = Branch {
                anchor: mmr::genesis(&store.config, k),
                state: State::genesis(&store.config, k),
            };
            let id = store.add_branch(branch);
            store.index_position(id, 0)?;
        }
        Ok(store)
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    /// Memory snapshots support deterministic fork fixtures. A disk-owning
    /// runtime has one namespace and cannot silently become an isolated clone.
    pub fn try_clone_memory(&self) -> Result<Self, String> {
        Ok(Self {
            committee: self.committee.clone(),
            config: self.config.clone(),
            records: self.records.try_clone_memory()?,
            retained_payload_bytes: self.retained_payload_bytes,
            branches: self.branches.clone(),
            children: self.children.clone(),
            prefixes: self.prefixes.clone(),
            checkpoint_branches: self.checkpoint_branches.clone(),
            checkpoints: self.checkpoints.clone(),
            attached: self.attached.clone(),
            #[cfg(test)]
            extension_attempts: self.extension_attempts,
            produced: self.produced.clone(),
            custody: self.custody.clone(),
        })
    }
    pub fn enable_shared_rocksdb(
        &mut self,
        fresh_directory: &std::path::Path,
    ) -> Result<(), String> {
        self.records.enable_rocksdb(fresh_directory)
    }
    pub fn storage_snapshot(&self) -> StorageSnapshot {
        self.records.snapshot()
    }
    pub fn check_storage_health(&self) -> Result<(), String> {
        self.records.check_health()
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
    }
    pub fn retained_payload_bytes(&self) -> u64 {
        self.retained_payload_bytes
    }
    pub fn custody_count(&self) -> usize {
        self.custody.len()
    }
    pub fn get_record(&self, producer: Id, digest: Digest) -> Option<&Record> {
        self.records.get(&(producer, digest))
    }
    fn check_endpoint(&self, p: &Checkpoint) -> Result<(), String> {
        mmr::validate_checkpoint(&self.config, p)?;
        if p.producer as usize >= self.committee.keys.len() {
            return Err("checkpoint producer outside committee".into());
        }
        Ok(())
    }
    /// Appending is local and immediate; it has no observation or receipt gate.
    pub fn produce(
        &mut self,
        key: &Keypair,
        producer: Id,
        payload: Vec<u8>,
    ) -> Result<Record, String> {
        if producer as usize >= self.committee.keys.len() || payload.len() > MAX_BATCH_PAYLOAD {
            return Err("invalid producer or oversized payload".into());
        }
        let (height, previous) = self
            .produced
            .get(&producer)
            .copied()
            .unwrap_or((0, genesis_digest(&self.config, producer)));
        if height >= u64::MAX - 1 {
            return Err("producer height exhausted".into());
        }
        let header = BatchHeader {
            context: self.committee.context.clone(),
            producer,
            height: height + 1,
            previous,
            payload_hash: payload_hash(&payload),
        };
        let record = Record {
            header: sign(key, producer, header),
            payload,
        };
        self.receive(record.clone())?;
        self.produced
            .insert(producer, (height + 1, record_digest(&record)));
        Ok(record)
    }
    /// Signature and payload validation happen before buffering. A verified but
    /// disconnected record stays buffered and cannot advance a held checkpoint.
    pub fn receive(&mut self, record: Record) -> Result<bool, String> {
        verify_record(&self.committee, &record)?;
        let digest = record_digest(&record);
        let producer = record.header.body.producer;
        if !self.insert_record(record)? {
            return Ok(false);
        }
        let mut pending = VecDeque::new();
        self.queue_record(producer, digest, &mut pending);
        self.extend_buffered(pending)?;
        Ok(true)
    }
    fn insert_record(&mut self, record: Record) -> Result<bool, String> {
        let h = record.header.body.clone();
        let digest = record_digest(&record);
        let key = (h.producer, digest);
        if self.records.contains_key(&key) {
            return Ok(false);
        }
        let payload_bytes = record.payload.len() as u64;
        // The optional physical writer completes before any record/index is
        // visible and before a held checkpoint or custody observation can move.
        self.records.put(key, record)?;
        self.children
            .entry((h.producer, h.height, h.previous))
            .or_default()
            .insert(digest);
        self.retained_payload_bytes += payload_bytes;
        Ok(true)
    }
    fn add_branch(&mut self, branch: Branch) -> usize {
        let id = self.branches.len();
        self.branches.insert(id, branch);
        id
    }
    /// Index historical positions once. Existing representatives remain valid
    /// when their tip advances, since State retains the exact historical roots.
    fn index_position(&mut self, id: usize, height: u64) -> Result<(), String> {
        let branch = &self.branches[&id];
        let cp = branch
            .state
            .checkpoint_at(height)
            .ok_or("branch checkpoint missing while indexing")?
            .clone();
        let anchor = mmr::checkpoint_digest(&branch.anchor);
        let digest = if height == 0 {
            genesis_digest(&self.config, cp.producer)
        } else {
            branch
                .state
                .digest_at(height)
                .ok_or("branch terminal digest missing")?
        };
        let checkpoint = mmr::checkpoint_digest(&cp);
        self.prefixes
            .entry((cp.producer, height, digest))
            .or_default()
            .entry(anchor)
            .or_insert(id);
        self.checkpoint_branches
            .entry(checkpoint)
            .or_default()
            .entry(anchor)
            .or_insert(id);
        self.checkpoints
            .entry((cp.producer, height, checkpoint))
            .or_insert(cp);
        // An imported metadata boundary has no custody of its own record.
        if height > branch.anchor.height {
            self.attached.insert((anchor, digest));
        }
        Ok(())
    }
    fn queue_record(&self, producer: Id, digest: Digest, pending: &mut VecDeque<(usize, Digest)>) {
        let h = &self.records[&(producer, digest)].header.body;
        if let Some(prefixes) = self.prefixes.get(&(producer, h.height - 1, h.previous)) {
            pending.extend(prefixes.values().map(|id| (*id, digest)));
        }
    }
    fn queue_children(
        &self,
        id: usize,
        height: u64,
        pending: &mut VecDeque<(usize, Digest)>,
    ) -> Result<(), String> {
        let branch = &self.branches[&id];
        let cp = branch
            .state
            .checkpoint_at(height)
            .ok_or("branch checkpoint missing")?;
        let previous = if height == 0 {
            genesis_digest(&self.config, cp.producer)
        } else {
            branch
                .state
                .digest_at(height)
                .ok_or("branch terminal digest missing")?
        };
        if let Some(children) = self.children.get(&(cp.producer, height + 1, previous)) {
            pending.extend(children.iter().map(|digest| (id, *digest)));
        }
        Ok(())
    }
    fn extend_buffered(&mut self, mut pending: VecDeque<(usize, Digest)>) -> Result<(), String> {
        while let Some((id, digest)) = pending.pop_front() {
            #[cfg(test)]
            {
                self.extension_attempts += 1;
            }
            let branch = &self.branches[&id];
            let anchor = mmr::checkpoint_digest(&branch.anchor);
            if self.attached.contains(&(anchor, digest)) {
                continue;
            }
            let producer = branch.anchor.producer;
            let height = self.records[&(producer, digest)].header.body.height;
            let id = if branch.state.checkpoint().height + 1 == height {
                // Honest traffic has one mutable State, not one cloned State
                // per historical height.
                self.branches.get_mut(&id).unwrap().state.append(digest)?;
                id
            } else {
                // A late fork needs its own retained State. Reconstruct only
                // its common prefix; keep the original anchor's custody limit.
                let boundary = branch.state.boundary(&branch.anchor)?;
                let mut state = State::from_boundary(&self.config, &boundary)?;
                for h in branch.anchor.height + 1..height {
                    state.append(
                        branch
                            .state
                            .digest_at(h)
                            .ok_or("fork prefix digest missing")?,
                    )?;
                }
                state.append(digest)?;
                let anchor = branch.anchor.clone();
                self.add_branch(Branch { anchor, state })
            };
            self.index_position(id, height)?;
            self.queue_children(id, height, &mut pending)?;
        }
        Ok(())
    }
    pub fn checkpoints(&self, producer: Id) -> Vec<Checkpoint> {
        self.checkpoints
            .range((producer, 0, [0; 32])..=(producer, u64::MAX, [255; 32]))
            .map(|(_, cp)| cp.clone())
            .collect()
    }
    fn matching_branch(&self, a: &Checkpoint, b: &Checkpoint) -> Option<&Branch> {
        self.checkpoint_branches
            .get(&mmr::checkpoint_digest(b))?
            .values()
            .filter_map(|id| self.branches.get(id))
            .find(|branch| {
                a.height >= branch.anchor.height
                    && branch.state.checkpoint_at(a.height) == Some(a)
                    && branch.state.checkpoint_at(b.height) == Some(b)
            })
    }
    pub fn holds(&self, a: &Checkpoint, b: &Checkpoint) -> bool {
        if self.check_endpoint(a).is_err()
            || self.check_endpoint(b).is_err()
            || a.producer != b.producer
            || a.height > b.height
        {
            return false;
        }
        if a == b {
            return true;
        }
        let Some(branch) = self.matching_branch(a, b) else {
            return false;
        };
        (a.height + 1..=b.height).all(|h| {
            branch
                .state
                .digest_at(h)
                .map(|d| self.records.contains_key(&(a.producer, d)))
                .unwrap_or(false)
        })
    }
    pub fn proof(&self, a: &Checkpoint, b: &Checkpoint) -> Result<PrefixProof, String> {
        self.check_endpoint(a)?;
        self.check_endpoint(b)?;
        if a == b {
            return Ok(PrefixProof::Empty);
        }
        self.matching_branch(a, b)
            .ok_or("suffix branch is not held")?
            .state
            .proof(a, b)
    }
    pub fn boundary(&self, p: &Checkpoint) -> Result<Boundary, String> {
        self.check_endpoint(p)?;
        if let Some(branches) = self.checkpoint_branches.get(&mmr::checkpoint_digest(p)) {
            for id in branches.values() {
                if let Ok(boundary) = self.branches[id].state.boundary(p) {
                    return Ok(boundary);
                }
            }
        }
        Err("boundary proof state unavailable".into())
    }
    /// Caller authenticates the named base. This method checks its supplied
    /// terminal opening and may then attach already buffered consecutive records.
    pub fn install_boundary(&mut self, boundary: &Boundary) -> Result<bool, String> {
        self.check_endpoint(&boundary.checkpoint)?;
        let state = State::from_boundary(&self.config, boundary)?;
        let anchor = boundary.checkpoint.clone();
        let id = mmr::checkpoint_digest(&anchor);
        if self
            .checkpoint_branches
            .get(&id)
            .is_some_and(|branches| branches.contains_key(&id))
        {
            return Ok(false);
        }
        let height = anchor.height;
        let branch = self.add_branch(Branch { anchor, state });
        self.index_position(branch, height)?;
        let mut pending = VecDeque::new();
        self.queue_children(branch, height, &mut pending)?;
        self.extend_buffered(pending)?;
        Ok(true)
    }
    pub fn register_custody(&mut self, a: &Checkpoint, b: &Checkpoint) -> Result<(), String> {
        if !self.holds(a, b) {
            return Err("cannot register custody without exact suffix".into());
        }
        if a != b {
            self.custody
                .insert((mmr::checkpoint_digest(a), mmr::checkpoint_digest(b)));
        }
        Ok(())
    }
    /// Borrow a locally held exact suffix in height order. Local consumers need
    /// neither transport segments nor their serialized proof envelopes. This
    /// deliberately accepts suffixes larger than one network frame.
    pub fn local_records(&self, a: &Checkpoint, b: &Checkpoint) -> Result<Vec<&Record>, String> {
        if !self.holds(a, b) {
            return Err("requested exact local suffix not held".into());
        }
        if a == b {
            return Ok(Vec::new());
        }
        let branch = self
            .matching_branch(a, b)
            .ok_or("local suffix branch unavailable")?;
        (a.height + 1..=b.height)
            .map(|height| {
                let digest = branch
                    .state
                    .digest_at(height)
                    .ok_or("local suffix digest unavailable")?;
                self.records
                    .get(&(a.producer, digest))
                    .ok_or_else(|| "local suffix payload unavailable".into())
            })
            .collect()
    }
    pub fn serve(&self, a: &Checkpoint, b: &Checkpoint) -> Result<Data, String> {
        if !self.holds(a, b) {
            return Err("requested exact suffix not held".into());
        }
        let boundary = self.boundary(a)?;
        let mut records = Vec::new();
        if a != b {
            let branch = self
                .matching_branch(a, b)
                .ok_or("serving branch unavailable")?;
            for h in a.height + 1..=b.height {
                let digest = branch
                    .state
                    .digest_at(h)
                    .ok_or("serving digest unavailable")?;
                records.push(
                    self.records
                        .get(&(a.producer, digest))
                        .ok_or("serving payload unavailable")?
                        .clone(),
                );
            }
        }
        let data = Data {
            from: a.clone(),
            to: b.clone(),
            boundary,
            records,
        };
        encode(&data)?;
        Ok(data)
    }
    /// Atomically verify the entire DATA suffix before retaining any record.
    /// The transport/adapter must additionally match these endpoints to a FETCH.
    pub fn accept_data(&mut self, data: &Data) -> Result<bool, String> {
        encode(data)?;
        self.check_endpoint(&data.from)?;
        self.check_endpoint(&data.to)?;
        if data.from.producer != data.to.producer
            || data.from.height > data.to.height
            || data.boundary.checkpoint != data.from
        {
            return Err("DATA endpoint mismatch".into());
        }
        let count = data.to.height - data.from.height;
        if count != data.records.len() as u64 {
            return Err("DATA record count mismatch".into());
        }
        let mut state = State::from_boundary(&self.config, &data.boundary)?;
        let mut previous = if data.from.height == 0 {
            genesis_digest(&self.config, data.from.producer)
        } else {
            data.boundary
                .tip
                .as_ref()
                .ok_or("DATA terminal digest missing")?
                .digest
        };
        for (index, record) in data.records.iter().enumerate() {
            verify_record(&self.committee, record)?;
            let h = &record.header.body;
            if h.producer != data.from.producer
                || h.height != data.from.height + index as u64 + 1
                || h.previous != previous
            {
                return Err("DATA contains a nonconsecutive or forked record".into());
            }
            previous = record_digest(record);
            state.append(previous)?;
        }
        if state.checkpoint() != data.to {
            return Err("DATA reconstruction does not match committed endpoint".into());
        }
        let anchor = data.from.clone();
        let anchor_id = mmr::checkpoint_digest(&anchor);
        let endpoint = mmr::checkpoint_digest(&data.to);
        let already_held = self
            .checkpoint_branches
            .get(&endpoint)
            .is_some_and(|branches| branches.contains_key(&anchor_id));
        let mut changed = !already_held;
        let mut new_records = Vec::new();
        for record in &data.records {
            if self.insert_record(record.clone())? {
                new_records.push(record_digest(record));
                changed = true;
            }
        }
        let mut pending = VecDeque::new();
        if !already_held {
            let branch = self.add_branch(Branch { anchor, state });
            for height in data.from.height..=data.to.height {
                self.index_position(branch, height)?;
                self.queue_children(branch, height, &mut pending)?;
            }
        }
        // New payloads may also attach to earlier independently held anchors.
        for digest in new_records {
            self.queue_record(data.from.producer, digest, &mut pending);
        }
        self.extend_buffered(pending)?;
        Ok(changed)
    }
    pub fn accept_requested_data(
        &mut self,
        from: &Checkpoint,
        to: &Checkpoint,
        data: &Data,
    ) -> Result<bool, String> {
        if &data.from != from || &data.to != to {
            return Err("DATA differs from requested exact endpoints".into());
        }
        self.accept_data(data)
    }

    /// Split cumulative suffixes into bounded, independently checked segments.
    /// A small envelope reserve allows the adapter's outer message tag/fields.
    pub fn serve_parts(&self, a: &Checkpoint, b: &Checkpoint) -> Result<Vec<DataPart>, String> {
        const ENVELOPE_RESERVE: usize = 4096;
        if !self.holds(a, b) {
            return Err("requested exact suffix not held".into());
        }
        if a == b {
            let part = DataPart {
                requested_from: a.clone(),
                requested_to: b.clone(),
                data: self.serve(a, b)?,
                before: PrefixProof::Empty,
                after: PrefixProof::Empty,
            };
            return Ok(vec![part]);
        }
        let branch = self
            .matching_branch(a, b)
            .ok_or("serving branch unavailable")?;
        let mut parts = Vec::new();
        let mut start = a.clone();
        while start.height < b.height {
            let boundary = branch.state.boundary(&start)?;
            let before = branch.state.proof(a, &start)?;
            let mut records = Vec::new();
            let mut selected = None;
            for h in start.height + 1..=b.height {
                let digest = branch
                    .state
                    .digest_at(h)
                    .ok_or("serving digest unavailable")?;
                records.push(
                    self.records
                        .get(&(a.producer, digest))
                        .ok_or("serving payload unavailable")?
                        .clone(),
                );
                let end = branch
                    .state
                    .checkpoint_at(h)
                    .ok_or("serving checkpoint unavailable")?
                    .clone();
                let candidate = DataPart {
                    requested_from: a.clone(),
                    requested_to: b.clone(),
                    data: Data {
                        from: start.clone(),
                        to: end.clone(),
                        boundary: boundary.clone(),
                        records: records.clone(),
                    },
                    before: before.clone(),
                    after: branch.state.proof(&end, b)?,
                };
                match encode(&candidate) {
                    Ok(bytes) if bytes.len() <= crate::wire::MAX_WIRE_BYTES - ENVELOPE_RESERVE => {
                        selected = Some(candidate)
                    }
                    _ => break,
                }
            }
            let selected = selected.ok_or("single DATA record exceeds transport segment budget")?;
            start = selected.data.to.clone();
            parts.push(selected);
        }
        Ok(parts)
    }

    pub fn accept_requested_part(
        &mut self,
        from: &Checkpoint,
        to: &Checkpoint,
        part: &DataPart,
    ) -> Result<bool, String> {
        encode(part)?;
        if &part.requested_from != from || &part.requested_to != to {
            return Err("DATA segment differs from requested exact endpoints".into());
        }
        mmr::verify_prefix(&self.config, from, &part.data.from, &part.before)?;
        mmr::verify_prefix(&self.config, &part.data.to, to, &part.after)?;
        self.accept_data(&part.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::fixture_key;
    fn store() -> BatchStore {
        let committee =
            Committee::new([8; 32], (0..4).map(|i| fixture_key(i).public).collect()).unwrap();
        BatchStore::new(committee, 4).unwrap()
    }
    fn populated() -> (BatchStore, Vec<Record>) {
        let mut s = store();
        let records = (0..12)
            .map(|i| s.produce(&fixture_key(0), 0, vec![i; 10]).unwrap())
            .collect();
        (s, records)
    }
    fn at(s: &BatchStore, h: u64) -> Checkpoint {
        s.checkpoints(0)
            .into_iter()
            .find(|p| p.height == h)
            .unwrap()
    }
    #[test]
    fn failed_write_never_publishes_record_or_custody_or_producer_height() {
        let mut receiver = store();
        receiver.records.fail_once_after(0);
        assert!(receiver
            .produce(&fixture_key(0), 0, vec![7])
            .unwrap_err()
            .contains("injected"));
        assert!(receiver.check_storage_health().is_err());
        assert_eq!(receiver.record_count(), 0);
        assert_eq!(receiver.retained_payload_bytes(), 0);
        assert!(receiver.children.is_empty());
        assert!(receiver.produced.is_empty());
        assert_eq!(receiver.checkpoints(0).len(), 1);
        assert_eq!(receiver.custody_count(), 0);
        // Retry is still height one; the failed write cannot publish a gap.
        let record = receiver.produce(&fixture_key(0), 0, vec![7]).unwrap();
        assert_eq!(record.header.body.height, 1);
        assert!(!receiver.receive(record).unwrap());
        assert_eq!(receiver.storage_snapshot().writes.attempts, 2);
        assert_eq!(receiver.storage_snapshot().writes.completed_writes, 1);
        assert_eq!(receiver.storage_snapshot().writes.failures, 1);
    }
    #[test]
    fn verified_data_write_failure_retains_only_written_records_without_custody() {
        let (source, _) = populated();
        let base = at(&source, 0);
        let end = at(&source, 3);
        let data = source.serve(&base, &end).unwrap();
        let mut receiver = store();
        receiver.records.fail_once_after(1);
        let mut invalid = data.clone();
        invalid.records[2].payload[0] ^= 1;
        assert!(receiver.accept_data(&invalid).is_err());
        assert_eq!(receiver.storage_snapshot().writes.attempts, 0);
        assert!(receiver.accept_data(&data).is_err());
        assert_eq!(receiver.record_count(), 1);
        assert_eq!(receiver.retained_payload_bytes(), 10);
        assert!(!receiver.holds(&base, &end));
        assert!(receiver.register_custody(&base, &end).is_err());
        assert_eq!(receiver.custody_count(), 0);
        receiver.accept_data(&data).unwrap();
        assert!(receiver.holds(&base, &end));
        receiver.register_custody(&base, &end).unwrap();
        assert_eq!(receiver.storage_snapshot().writes.completed_writes, 3);
        assert_eq!(receiver.storage_snapshot().writes.attempts, 4);
        assert_eq!(receiver.custody_count(), 1);
    }
    #[test]
    fn memory_profile_keeps_explicit_isolated_fork_clone() {
        let (source, _) = populated();
        let mut fork = source.try_clone_memory().unwrap();
        fork.produce(&fixture_key(0), 0, vec![9]).unwrap();
        assert_eq!(source.record_count(), 12);
        assert_eq!(fork.record_count(), 13);
        assert_eq!(
            source.storage_snapshot().profile,
            StorageProfile::MemoryVisible
        );
        assert_eq!(source.storage_snapshot().writes.attempts, 0);
    }
    #[cfg(not(feature = "rocksdb-records"))]
    #[test]
    fn disk_profile_is_explicitly_unavailable_without_backend_feature() {
        let path =
            std::env::temp_dir().join(format!("delugi-disabled-store-{}", std::process::id()));
        assert!(!path.exists());
        assert!(store()
            .enable_shared_rocksdb(&path)
            .unwrap_err()
            .contains("build feature"));
        assert!(!path.exists());
    }
    #[cfg(feature = "rocksdb-records")]
    #[test]
    fn shared_rocksdb_writes_exact_records_once_before_custody_and_rejects_reopen() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "delugi-record-store-{}-{unique}",
            std::process::id()
        ));
        let (source, records) = populated();
        let mut receiver = store();
        receiver.enable_shared_rocksdb(&path).unwrap();
        assert!(receiver.try_clone_memory().is_err());
        assert!(store().enable_shared_rocksdb(&path).is_err());
        let record = receiver.produce(&fixture_key(0), 0, vec![0; 10]).unwrap();
        assert_eq!(record, records[0]);
        assert!(!receiver.receive(record.clone()).unwrap());
        let mut invalid = records[1].clone();
        invalid.header.signature[0] ^= 1;
        assert!(receiver.receive(invalid).is_err());
        receiver.receive(records[1].clone()).unwrap();
        receiver
            .register_custody(&at(&source, 0), &at(&source, 2))
            .unwrap();
        let snapshot = receiver.storage_snapshot();
        assert_eq!(snapshot.profile, StorageProfile::SharedRocksdbWritten);
        assert_eq!(snapshot.writes.attempts, 2);
        assert_eq!(snapshot.writes.completed_writes, 2);
        assert_eq!(
            snapshot.writes.record_bytes,
            records[..2]
                .iter()
                .map(|r| encode(r).unwrap().len() as u64)
                .sum::<u64>()
        );
        assert!(snapshot.writes.encoded_write_batch_bytes > snapshot.writes.record_bytes);
        assert!(!snapshot.core_restart_recovery);
        assert_eq!(receiver.custody_count(), 1);
        drop(receiver);
        // Independent backend oracle: core startup still refuses this directory.
        let raw = shared_store_rocksdb::RocksStore::open(&path, &["delugi_records"]).unwrap();
        for record in &records[..2] {
            let key = encode(&(record.header.body.producer, record_digest(record))).unwrap();
            assert_eq!(
                raw.get("delugi_records", &key).unwrap(),
                Some(encode(record).unwrap())
            );
        }
        assert_eq!(raw.scan("delugi_records").unwrap().count(), 2);
        drop(raw);
        std::fs::remove_dir_all(&path).unwrap();
    }
    #[test]
    fn production_never_waits_for_reports_or_receipts() {
        let (s, records) = populated();
        assert_eq!(records.len(), 12);
        assert_eq!(at(&s, 12).height, 12);
        assert_eq!(s.custody_count(), 0);
    }
    #[test]
    fn reverse_arrival_is_buffered_until_the_verified_predecessor() {
        let (source, records) = populated();
        let mut receiver = store();
        for r in records[1..].iter().rev() {
            receiver.receive(r.clone()).unwrap();
            assert_eq!(receiver.checkpoints(0).len(), 1);
        }
        receiver.receive(records[0].clone()).unwrap();
        assert!(receiver.holds(&at(&source, 0), &at(&source, 12)));
        assert_eq!(receiver.record_count(), 12);
    }
    #[test]
    fn same_height_forks_retain_both_exact_branches() {
        let mut s = store();
        let a = s.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let mut other = store();
        let b = other.produce(&fixture_key(0), 0, vec![2]).unwrap();
        s.receive(b.clone()).unwrap();
        assert_ne!(record_digest(&a), record_digest(&b));
        assert_eq!(s.checkpoints(0).iter().filter(|p| p.height == 1).count(), 2);
        let b2 = other.produce(&fixture_key(0), 0, vec![3]).unwrap();
        s.receive(b2).unwrap();
        let end = at(&other, 2);
        assert!(s.holds(&at(&s, 0), &end));
        let acp = s
            .checkpoints(0)
            .into_iter()
            .find(|p| p.height == 1 && p != &at(&other, 1))
            .unwrap();
        assert!(!s.holds(&acp, &end));
    }
    #[test]
    fn metadata_boundary_allows_retrieval_without_prebase_payloads() {
        let (source, _) = populated();
        for h in [1, 3, 4, 7, 8] {
            let base = at(&source, h);
            let end = at(&source, 12);
            let mut receiver = store();
            let data = source.serve(&base, &end).unwrap();
            receiver.accept_requested_data(&base, &end, &data).unwrap();
            assert!(receiver.holds(&base, &end));
            assert!(!receiver.holds(&at(&source, 0), &end));
            assert_eq!(receiver.record_count(), (12 - h) as usize);
            mmr::verify_prefix(
                receiver.config(),
                &base,
                &end,
                &receiver.proof(&base, &end).unwrap(),
            )
            .unwrap();
            assert_eq!(receiver.serve(&base, &end).unwrap(), data);
        }
    }
    #[test]
    fn imported_boundary_attaches_buffered_suffix_and_keeps_custody() {
        let (source, records) = populated();
        let base = at(&source, 5);
        let end = at(&source, 12);
        let mut receiver = store();
        for r in &records[5..] {
            receiver.receive(r.clone()).unwrap();
        }
        assert!(!receiver.holds(&base, &end));
        receiver
            .install_boundary(&source.boundary(&base).unwrap())
            .unwrap();
        assert!(receiver.holds(&base, &end));
        receiver.register_custody(&base, &end).unwrap();
        assert_eq!(receiver.custody_count(), 1);
        receiver
            .install_boundary(&source.boundary(&at(&source, 8)).unwrap())
            .unwrap();
        assert!(receiver.holds(&base, &end));
        assert_eq!(receiver.record_count(), 7);
    }
    #[test]
    fn data_rejects_mutations_atomically() {
        let (source, _) = populated();
        let base = at(&source, 3);
        let end = at(&source, 12);
        let good = source.serve(&base, &end).unwrap();
        let mut bad = good.clone();
        bad.records[0].payload[0] ^= 1;
        let mut receiver = store();
        assert!(receiver.accept_data(&bad).is_err());
        assert_eq!(receiver.record_count(), 0);
        let mut bad = good.clone();
        bad.boundary.tip.as_mut().unwrap().digest[0] ^= 1;
        assert!(receiver.accept_data(&bad).is_err());
        let mut bad = good.clone();
        bad.records.swap(0, 1);
        assert!(receiver.accept_data(&bad).is_err());
        let mut bad = good.clone();
        bad.to.partial[0] ^= 1;
        assert!(receiver.accept_data(&bad).is_err());
        assert!(receiver
            .accept_requested_data(&at(&source, 0), &end, &good)
            .is_err());
        assert_eq!(receiver.record_count(), 0);
        receiver.accept_data(&good).unwrap();
    }
    #[test]
    fn bad_signature_payload_and_oversized_records_never_buffer() {
        let mut s = store();
        let mut r = s.produce(&fixture_key(0), 0, vec![1]).unwrap();
        let mut receiver = store();
        r.header.signature[0] ^= 1;
        assert!(receiver.receive(r).is_err());
        assert_eq!(receiver.record_count(), 0);
        assert!(receiver
            .produce(&fixture_key(0), 0, vec![0; MAX_BATCH_PAYLOAD + 1])
            .is_err());
        assert!(receiver.produce(&fixture_key(1), 0, vec![0]).is_err());
        assert_eq!(receiver.record_count(), 0);
    }
    #[test]
    fn boundary_cannot_invent_older_bytes_or_missing_proofs() {
        let (source, _) = populated();
        let mut receiver = store();
        receiver
            .install_boundary(&source.boundary(&at(&source, 8)).unwrap())
            .unwrap();
        assert!(receiver.holds(&at(&source, 8), &at(&source, 8)));
        assert!(!receiver.holds(&at(&source, 0), &at(&source, 8)));
        assert!(receiver.proof(&at(&source, 3), &at(&source, 8)).is_err());
        assert_eq!(receiver.record_count(), 0);
    }

    #[test]
    fn cumulative_retrieval_spans_multiple_frames_and_accepts_reverse_order() {
        let mut source = store();
        for value in 0..7 {
            source
                .produce(&fixture_key(0), 0, vec![value; MAX_BATCH_PAYLOAD])
                .unwrap();
        }
        let base = at(&source, 0);
        let end = at(&source, 7);
        assert!(source.serve(&base, &end).is_err());
        let parts = source.serve_parts(&base, &end).unwrap();
        assert!(parts.len() >= 3);
        let mut receiver = store();
        for part in parts.iter().rev() {
            assert!(encode(part).unwrap().len() < crate::wire::MAX_WIRE_BYTES);
            receiver.accept_requested_part(&base, &end, part).unwrap();
        }
        assert!(receiver.holds(&base, &end));
        assert_eq!(receiver.record_count(), 7);
        let mut forged = parts[0].clone();
        forged.requested_to = at(&source, 6);
        assert!(receiver
            .accept_requested_part(&base, &end, &forged)
            .is_err());
        let mut forged = parts[0].clone();
        forged.after = PrefixProof::Empty;
        assert!(receiver
            .accept_requested_part(&base, &end, &forged)
            .is_err());
    }
    #[test]
    fn long_chain_retains_one_state_and_late_forks_keep_historical_proofs() {
        let mut source = store();
        let key = fixture_key(0);
        let records: Vec<_> = (0..2048)
            .map(|i| {
                source
                    .produce(&key, 0, (i as u64).to_le_bytes().to_vec())
                    .unwrap()
            })
            .collect();
        assert_eq!(
            source.branches.len(),
            4,
            "historical prefixes must not clone entire MMR states"
        );
        assert_eq!(
            source.extension_attempts,
            records.len(),
            "each normal append visits one indexed parent"
        );
        let checkpoints: BTreeMap<_, _> = source
            .checkpoints(0)
            .into_iter()
            .map(|cp| (cp.height, cp))
            .collect();
        for (a, b) in [
            (0, 2048),
            (17, 512),
            (511, 1024),
            (1024, 1555),
            (2047, 2048),
        ] {
            assert!(source.holds(&checkpoints[&a], &checkpoints[&b]));
            mmr::verify_prefix(
                source.config(),
                &checkpoints[&a],
                &checkpoints[&b],
                &source.proof(&checkpoints[&a], &checkpoints[&b]).unwrap(),
            )
            .unwrap();
        }
        let mut previous = record_digest(&records[1023]);
        let mut fork = Vec::new();
        let mut expected = State::genesis(source.config(), 0);
        for record in &records[..1024] {
            expected.append(record_digest(record)).unwrap();
        }
        for height in 1025..=1036 {
            let payload = format!("late fork {height}").into_bytes();
            let record = Record {
                header: sign(
                    &key,
                    0,
                    BatchHeader {
                        context: source.config.context.clone(),
                        producer: 0,
                        height,
                        previous,
                        payload_hash: payload_hash(&payload),
                    },
                ),
                payload,
            };
            previous = record_digest(&record);
            expected.append(previous).unwrap();
            fork.push(record);
        }
        let fork_end = expected.checkpoint();
        for record in fork.iter().rev() {
            source.receive(record.clone()).unwrap();
        }
        assert_eq!(
            source.branches.len(),
            5,
            "only the actual fork adds a state"
        );
        assert_eq!(source.extension_attempts, records.len() + fork.len());
        assert_eq!(source.checkpoints(0).len(), records.len() + fork.len() + 1);
        assert!(source.holds(&checkpoints[&1024], &fork_end));
        assert!(!source.holds(&checkpoints[&1025], &fork_end));
        for base in [&checkpoints[&0], &checkpoints[&17], &checkpoints[&1024]] {
            let actual = source.proof(base, &fork_end).unwrap();
            assert_eq!(actual, expected.proof(base, &fork_end).unwrap());
            mmr::verify_prefix(source.config(), base, &fork_end, &actual).unwrap();
        }
        // Imported anchors attach buffered records but never gain old payloads.
        let mut receiver = store();
        for record in fork.iter().rev() {
            receiver.receive(record.clone()).unwrap();
        }
        receiver
            .install_boundary(&source.boundary(&checkpoints[&1024]).unwrap())
            .unwrap();
        assert!(receiver.holds(&checkpoints[&1024], &fork_end));
        assert!(!receiver.holds(&checkpoints[&0], &fork_end));
        assert_eq!(receiver.branches.len(), 5);
        let data = source.serve(&checkpoints[&1024], &fork_end).unwrap();
        assert!(!receiver.accept_data(&data).unwrap());
        assert!(!receiver.install_boundary(&data.boundary).unwrap());
        assert_eq!(
            receiver.branches.len(),
            5,
            "duplicate DATA and boundaries must not add states"
        );
        assert_eq!(
            receiver.serve(&checkpoints[&1024], &fork_end).unwrap(),
            data
        );
    }

    /// Independent, deliberately exhaustive oracle using the original retained
    /// prefix algorithm. Small fork trees make all-pair comparison affordable.
    fn exhaustive_branches(
        config: &Config,
        records: &[Record],
        boundaries: &[Boundary],
    ) -> Vec<Branch> {
        let mut branches = BTreeMap::new();
        for producer in 0..4 {
            let anchor = mmr::genesis(config, producer);
            let digest = mmr::checkpoint_digest(&anchor);
            branches.insert(
                (digest, digest),
                Branch {
                    anchor,
                    state: State::genesis(config, producer),
                },
            );
        }
        for boundary in boundaries {
            let anchor = boundary.checkpoint.clone();
            let digest = mmr::checkpoint_digest(&anchor);
            branches.insert(
                (digest, digest),
                Branch {
                    anchor,
                    state: State::from_boundary(config, boundary).unwrap(),
                },
            );
        }
        loop {
            let mut added = Vec::new();
            for record in records {
                let h = &record.header.body;
                for branch in branches.values() {
                    let tail = branch.state.checkpoint();
                    if tail.producer != h.producer || tail.height + 1 != h.height {
                        continue;
                    }
                    let previous = if tail.height == 0 {
                        genesis_digest(config, h.producer)
                    } else {
                        branch.state.digest_at(tail.height).unwrap()
                    };
                    if previous != h.previous {
                        continue;
                    }
                    let mut state = branch.state.clone();
                    state.append(record_digest(record)).unwrap();
                    let key = (
                        mmr::checkpoint_digest(&branch.anchor),
                        mmr::checkpoint_digest(&state.checkpoint()),
                    );
                    if !branches.contains_key(&key) {
                        added.push((
                            key,
                            Branch {
                                anchor: branch.anchor.clone(),
                                state,
                            },
                        ));
                    }
                }
            }
            if added.is_empty() {
                break;
            }
            branches.extend(added);
        }
        branches.into_values().collect()
    }

    #[test]
    fn indexed_fork_tree_matches_exhaustive_prefix_oracle() {
        let mut main = store();
        let mut records = Vec::new();
        for i in 0..3 {
            records.push(main.produce(&fixture_key(0), 0, vec![i]).unwrap());
        }
        let mut fork = main.try_clone_memory().unwrap();
        for i in 3..8 {
            records.push(main.produce(&fixture_key(0), 0, vec![i]).unwrap());
        }
        for i in 13..18 {
            records.push(fork.produce(&fixture_key(0), 0, vec![i]).unwrap());
        }
        let boundaries = vec![
            main.boundary(&at(&main, 5)).unwrap(),
            fork.boundary(&at(&fork, 4)).unwrap(),
        ];
        let mut receiver = store();
        // Install overlapping, independent custody anchors among reverse arrivals.
        for record in records.iter().rev().take(6) {
            receiver.receive(record.clone()).unwrap();
        }
        for boundary in &boundaries {
            receiver.install_boundary(boundary).unwrap();
        }
        for record in records.iter().rev().skip(6) {
            receiver.receive(record.clone()).unwrap();
        }
        let oracle = exhaustive_branches(receiver.config(), &records, &boundaries);
        let mut expected = BTreeMap::new();
        for branch in &oracle {
            let cp = branch.state.checkpoint();
            if cp.producer == 0 {
                expected.insert((cp.height, mmr::checkpoint_digest(&cp)), cp);
            }
        }
        let checkpoints = receiver.checkpoints(0);
        assert_eq!(checkpoints, expected.into_values().collect::<Vec<_>>());
        assert_eq!(
            receiver.branches.len(),
            7,
            "four producers, one fork, two metadata anchors"
        );
        for a in &checkpoints {
            for b in &checkpoints {
                if a.height > b.height {
                    continue;
                }
                let held = a == b
                    || oracle.iter().any(|branch| {
                        a.height >= branch.anchor.height
                            && branch.state.checkpoint_at(a.height) == Some(a)
                            && branch.state.checkpoint_at(b.height) == Some(b)
                    });
                assert_eq!(
                    receiver.holds(a, b),
                    held,
                    "wrong suffix result for {a:?} -> {b:?}"
                );
                if held {
                    let proof = receiver.proof(a, b).unwrap();
                    mmr::verify_prefix(receiver.config(), a, b, &proof).unwrap();
                    let data = receiver.serve(a, b).unwrap();
                    let mut recovered = store();
                    recovered.accept_data(&data).unwrap();
                    assert!(recovered.holds(a, b));
                } else {
                    assert!(receiver.proof(a, b).is_err());
                }
            }
        }
    }
}
