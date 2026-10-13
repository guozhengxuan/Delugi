//! Producer-authenticated records, exact fork custody, and verified suffix transfer.
//!
//! Storage is deliberately retained indefinitely. A metadata boundary authenticates
//! its terminal digest and peaks, but never counts older payloads as locally held.

use crate::mmr::{self, Boundary, Checkpoint, Config, PrefixProof, State};
use crate::wire::{encode, hash, sign, Committee, Context, Digest, Id, Signed, SigningDomain};
use ed25519_dalek::Keypair;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
#[derive(Clone, Debug)]
pub struct BatchStore {
    committee: Committee,
    config: Config,
    records: BTreeMap<(Id, Digest), Record>,
    /// Separate entries preserve producer forks and independently imported bases.
    branches: BTreeMap<(Digest, Digest), Branch>,
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
        let mut branches = BTreeMap::new();
        for k in 0..committee.keys.len() as Id {
            let anchor = mmr::genesis(&config, k);
            let id = mmr::checkpoint_digest(&anchor);
            branches.insert(
                (id, id),
                Branch {
                    anchor,
                    state: State::genesis(&config, k),
                },
            );
        }
        Ok(Self {
            committee,
            config,
            records: BTreeMap::new(),
            branches,
            produced: BTreeMap::new(),
            custody: BTreeSet::new(),
        })
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn record_count(&self) -> usize {
        self.records.len()
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
        let id = (record.header.body.producer, record_digest(&record));
        if self.records.contains_key(&id) {
            return Ok(false);
        }
        self.records.insert(id, record);
        self.extend_buffered()?;
        Ok(true)
    }
    fn extend_buffered(&mut self) -> Result<(), String> {
        loop {
            let mut pending = Vec::new();
            for record in self.records.values() {
                let h = &record.header.body;
                for branch in self.branches.values() {
                    let tail = branch.state.checkpoint();
                    if tail.producer != h.producer || tail.height.checked_add(1) != Some(h.height) {
                        continue;
                    }
                    let previous = if tail.height == 0 {
                        genesis_digest(&self.config, h.producer)
                    } else {
                        branch
                            .state
                            .digest_at(tail.height)
                            .ok_or("held branch has no terminal digest")?
                    };
                    if previous != h.previous {
                        continue;
                    }
                    let mut state = branch.state.clone();
                    state.append(record_digest(record))?;
                    let key = (
                        mmr::checkpoint_digest(&branch.anchor),
                        mmr::checkpoint_digest(&state.checkpoint()),
                    );
                    if !self.branches.contains_key(&key) {
                        pending.push((
                            key,
                            Branch {
                                anchor: branch.anchor.clone(),
                                state,
                            },
                        ));
                    }
                }
            }
            if pending.is_empty() {
                break;
            }
            for (key, branch) in pending {
                self.branches.insert(key, branch);
            }
        }
        Ok(())
    }
    pub fn checkpoints(&self, producer: Id) -> Vec<Checkpoint> {
        let mut seen = BTreeMap::new();
        for branch in self.branches.values() {
            let cp = branch.state.checkpoint();
            if cp.producer == producer {
                seen.insert(mmr::checkpoint_digest(&cp), cp);
            }
        }
        let mut result: Vec<_> = seen.into_values().collect();
        result.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then_with(|| mmr::checkpoint_digest(a).cmp(&mmr::checkpoint_digest(b)))
        });
        result
    }
    fn matching_branch(&self, a: &Checkpoint, b: &Checkpoint) -> Option<&Branch> {
        self.branches.values().find(|branch| {
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
        for branch in self.branches.values() {
            if let Ok(boundary) = branch.state.boundary(p) {
                return Ok(boundary);
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
        if self.branches.contains_key(&(id, id)) {
            return Ok(false);
        }
        self.branches.insert((id, id), Branch { anchor, state });
        self.extend_buffered()?;
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
        let key = (
            mmr::checkpoint_digest(&anchor),
            mmr::checkpoint_digest(&data.to),
        );
        let mut changed = !self.branches.contains_key(&key);
        for record in &data.records {
            let id = (record.header.body.producer, record_digest(record));
            if let std::collections::btree_map::Entry::Vacant(e) = self.records.entry(id) {
                e.insert(record.clone());
                changed = true;
            }
        }
        self.branches.insert(key, Branch { anchor, state });
        self.extend_buffered()?;
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
}
