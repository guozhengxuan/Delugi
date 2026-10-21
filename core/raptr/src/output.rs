use delugi_shared_output::ResolutionQueue;
use std::collections::BTreeMap;

pub type Digest = [u8; 32];
pub type Author = [u8; 32];

/// Fixed by the pinned native `RaptrPayload`, not a benchmark tuning option.
pub const N_SUB_BLOCKS: usize = 8;

/// Identity of a real QS batch. Expiration can be renewed without changing the
/// payload identity; all signed descriptor fields remain in `BatchInfo`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatchKey {
    pub epoch: u64,
    pub author: Author,
    pub nonce: u64,
    pub id: u64,
    pub digest: Digest,
}

/// Field-for-field mirror of native BatchInfo. This is an explicit compatibility
/// boundary, not a replacement for native ProofOfStore authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchInfo {
    pub key: BatchKey,
    pub expiration: u64,
    pub num_txns: u64,
    pub num_bytes: u64,
    pub gas_bucket_start: u64,
}

impl BatchInfo {
    /// Native BCS has fixed-width fields: author, id, nonce, epoch, expiration,
    /// digest, transaction count, serialized payload size, gas bucket.
    pub fn from_native_bcs(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 120 {
            return Err(Error::InvalidDescriptor);
        }
        let u64_at =
            |offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed width"));
        Ok(Self {
            key: BatchKey {
                author: bytes[..32].try_into().expect("fixed width"),
                id: u64_at(32),
                nonce: u64_at(40),
                epoch: u64_at(48),
                digest: bytes[64..96].try_into().expect("fixed width"),
            },
            expiration: u64_at(56),
            num_txns: u64_at(96),
            num_bytes: u64_at(104),
            gas_bucket_start: u64_at(112),
        })
    }

    pub fn to_native_bcs(&self) -> [u8; 120] {
        let mut bytes = [0; 120];
        bytes[..32].copy_from_slice(&self.key.author);
        bytes[64..96].copy_from_slice(&self.key.digest);
        for (offset, value) in [
            (32, self.key.id),
            (40, self.key.nonce),
            (48, self.key.epoch),
            (56, self.expiration),
            (96, self.num_txns),
            (104, self.num_bytes),
            (112, self.gas_bucket_start),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockId {
    pub epoch: u64,
    pub digest: Digest,
    /// Native Raptr rounds are signed i64, not application sequence numbers.
    pub round: i64,
    pub author: Author,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SectionKind {
    Proofs,
    /// The original index in the full eight-subblock proposal.
    SubBlock(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub block: BlockId,
    pub kind: SectionKind,
    pub batches: Vec<BatchInfo>,
}

/// One native `notify_commit` payload slice. New blocks include the proofs
/// section even when empty. Prefix extensions exclude it. The native adapter
/// must obtain this flag explicitly; `proofs.is_empty()` cannot recover it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitSlice {
    pub block: BlockId,
    pub include_proofs: bool,
    pub proofs: Vec<BatchInfo>,
    pub sub_blocks: Vec<(usize, Vec<BatchInfo>)>,
}

impl CommitSlice {
    fn validate_shape(&self) -> Result<(), Error> {
        if !self.include_proofs && (!self.proofs.is_empty() || self.sub_blocks.is_empty()) {
            return Err(Error::InvalidSlice);
        }
        let mut previous = None;
        for (index, _) in &self.sub_blocks {
            if *index >= N_SUB_BLOCKS || previous.is_some_and(|prev| *index != prev + 1) {
                return Err(Error::InvalidSlice);
            }
            previous = Some(*index);
        }
        Ok(())
    }

    pub fn canonical_sections(&self) -> Result<Vec<Section>, Error> {
        self.validate_shape()?;
        let mut sections = Vec::with_capacity(self.sub_blocks.len() + 1);
        if self.include_proofs {
            sections.push(Section {
                block: self.block.clone(),
                kind: SectionKind::Proofs,
                batches: self.proofs.clone(),
            });
        }
        sections.extend(self.sub_blocks.iter().map(|(index, batches)| Section {
            block: self.block.clone(),
            kind: SectionKind::SubBlock(*index),
            batches: batches.clone(),
        }));
        Ok(sections)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ticket(usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub ticket: Ticket,
    /// An exact repeated adapter callback must not emit a second section.
    pub duplicate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDescriptor,
    InvalidSlice,
    NonContiguousCommit,
    ConflictingBlock,
    ConflictingBatch,
    Capacity,
    UnknownTicket,
    AlreadyResolved,
    TransactionCount,
    PayloadMismatch,
    VerificationFailed,
    Frozen,
}

/// This is a finite bounded contract harness. All retained reservations count
/// toward max_slices, including published slices needed to recognize retries.
/// A future long-lived runtime must supply explicit persistence/retention.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_slices: usize,
    pub max_sections: usize,
    pub max_batch_occurrences: usize,
    pub max_pending_transactions: u64,
    pub max_pending_payload_bytes: u64,
}

/// Facts computed from actual native BatchPayload(author, SignedTransactions).
/// The implementation must hash/size the exact native BCS payload, not trust
/// fields echoed from the expected descriptor. Request authentication/eligibility
/// is a separate common application operation after native payload validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadFacts {
    pub digest: Digest,
    pub num_txns: u64,
    pub num_bytes: u64,
}

pub trait BatchPayloadVerifier<T> {
    fn inspect(&self, author: &Author, transactions: &[T]) -> Result<PayloadFacts, Error>;
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublishedBatch<T> {
    pub info: BatchInfo,
    /// True only for the first exact batch key. Every occurrence is published.
    pub first_occurrence: bool,
    pub transactions: Vec<T>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublishedSection<T> {
    pub ordinal: usize,
    pub block: BlockId,
    pub kind: SectionKind,
    pub batches: Vec<PublishedBatch<T>>,
}

struct Entry {
    slice: CommitSlice,
    sections: Vec<Section>,
    published: bool,
    transactions: u64,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub frozen: bool,
    pub published_sections: usize,
    pub published_transactions: u64,
    pub pending_slices: usize,
    pub resolved_pending_slices: usize,
    pub pending_transactions: u64,
    pub pending_payload_bytes: u64,
}

/// Pure application materializer: core order is reserved before any fetch starts.
/// A later successful fetch cannot bypass an unavailable earlier slice. It never
/// generates votes, repairs, retries, or modifies the protocol's committed state.
pub struct OutputContract<T> {
    limits: Limits,
    entries: Vec<Entry>,
    pending: ResolutionQueue<usize, Vec<Vec<Vec<T>>>>,
    last_block: Option<(BlockId, usize)>,
    sections_reserved: usize,
    batches_reserved: usize,
    pending_transactions: u64,
    pending_bytes: u64,
    published_sections: usize,
    published_transactions: u64,
    batch_shapes: BTreeMap<BatchKey, (u64, u64)>,
    emitted_batches: BTreeMap<BatchKey, ()>,
    frozen: bool,
}

impl<T> OutputContract<T> {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            entries: Vec::new(),
            pending: ResolutionQueue::new(limits.max_slices),
            last_block: None,
            sections_reserved: 0,
            batches_reserved: 0,
            pending_transactions: 0,
            pending_bytes: 0,
            published_sections: 0,
            published_transactions: 0,
            batch_shapes: BTreeMap::new(),
            emitted_batches: BTreeMap::new(),
            frozen: false,
        }
    }

    pub fn reserve(&mut self, slice: CommitSlice) -> Result<Reservation, Error> {
        if self.frozen {
            return Err(Error::Frozen);
        }
        slice.validate_shape()?;
        if let Some(index) = self.entries.iter().position(|entry| entry.slice == slice) {
            return Ok(Reservation {
                ticket: Ticket(index),
                duplicate: true,
            });
        }
        let first = slice
            .sub_blocks
            .first()
            .map(|(index, _)| *index)
            .unwrap_or(0);
        match &self.last_block {
            None if !slice.include_proofs || first != 0 => return Err(Error::NonContiguousCommit),
            Some((block, prefix)) if block == &slice.block => {
                if slice.include_proofs || first != *prefix {
                    return Err(Error::NonContiguousCommit);
                }
            }
            Some((block, _)) => {
                if block.digest == slice.block.digest || block.round >= slice.block.round {
                    return Err(Error::ConflictingBlock);
                }
                if !slice.include_proofs || first != 0 {
                    return Err(Error::NonContiguousCommit);
                }
            }
            None => {}
        }

        let section_count = slice.sub_blocks.len() + usize::from(slice.include_proofs);
        let count = slice
            .sub_blocks
            .iter()
            .map(|(_, batches)| batches.len())
            .try_fold(slice.proofs.len(), |total, count| total.checked_add(count))
            .ok_or(Error::Capacity)?;
        if self.entries.len() >= self.limits.max_slices
            || section_count
                > self
                    .limits
                    .max_sections
                    .saturating_sub(self.sections_reserved)
            || count
                > self
                    .limits
                    .max_batch_occurrences
                    .saturating_sub(self.batches_reserved)
        {
            return Err(Error::Capacity);
        }
        let mut transactions = 0u64;
        let mut bytes = 0u64;
        let mut new_shapes = BTreeMap::new();
        for batch in slice
            .proofs
            .iter()
            .chain(slice.sub_blocks.iter().flat_map(|(_, batches)| batches))
        {
            if batch.key.epoch != slice.block.epoch {
                return Err(Error::InvalidDescriptor);
            }
            transactions = transactions
                .checked_add(batch.num_txns)
                .ok_or(Error::Capacity)?;
            bytes = bytes.checked_add(batch.num_bytes).ok_or(Error::Capacity)?;
            let shape = (batch.num_txns, batch.num_bytes);
            if self
                .batch_shapes
                .get(&batch.key)
                .or_else(|| new_shapes.get(&batch.key))
                .is_some_and(|existing| existing != &shape)
            {
                return Err(Error::ConflictingBatch);
            }
            new_shapes.insert(batch.key.clone(), shape);
        }
        let pending_transactions = self
            .pending_transactions
            .checked_add(transactions)
            .ok_or(Error::Capacity)?;
        let pending_bytes = self
            .pending_bytes
            .checked_add(bytes)
            .ok_or(Error::Capacity)?;
        self.published_transactions
            .checked_add(pending_transactions)
            .ok_or(Error::Capacity)?;
        if pending_transactions > self.limits.max_pending_transactions
            || pending_bytes > self.limits.max_pending_payload_bytes
        {
            return Err(Error::Capacity);
        }
        let sections = slice.canonical_sections()?;
        // Commit metadata only after every validation/budget check succeeds.
        let ticket = Ticket(self.entries.len());
        self.pending
            .reserve(ticket.0)
            .map_err(|_| Error::Capacity)?;
        self.last_block = Some((
            slice.block.clone(),
            slice.sub_blocks.last().map(|(i, _)| i + 1).unwrap_or(0),
        ));
        self.sections_reserved += sections.len();
        self.batches_reserved += count;
        self.pending_transactions = pending_transactions;
        self.pending_bytes = pending_bytes;
        self.batch_shapes.extend(new_shapes);
        self.entries.push(Entry {
            slice,
            sections,
            published: false,
            transactions,
            bytes,
        });
        Ok(Reservation {
            ticket,
            duplicate: false,
        })
    }

    /// Consume the flat vector returned by the *native* get_transactions path:
    /// selected subblocks first, then proofs. Validate all batch slices before
    /// changing state or reordering/moving their transactions. No transaction is
    /// cloned. Actual native payload bytes/count/hash must match every descriptor.
    pub fn resolve_native_fetch<V: BatchPayloadVerifier<T>>(
        &mut self,
        ticket: Ticket,
        transactions: Vec<T>,
        verifier: &V,
    ) -> Result<(), Error> {
        if self.frozen {
            return Err(Error::Frozen);
        }
        let entry = self.entries.get_mut(ticket.0).ok_or(Error::UnknownTicket)?;
        if entry.published || self.pending.is_resolved(&ticket.0) == Some(true) {
            return Err(Error::AlreadyResolved);
        }
        if u64::try_from(transactions.len()).ok() != Some(entry.transactions) {
            return Err(Error::TransactionCount);
        }
        let mut fetch_order: Vec<usize> = (0..entry.sections.len()).collect();
        if entry.slice.include_proofs {
            fetch_order.rotate_left(1);
        }
        let mut offset = 0usize;
        for index in &fetch_order {
            for batch in &entry.sections[*index].batches {
                let count = usize::try_from(batch.num_txns).map_err(|_| Error::TransactionCount)?;
                let end = offset.checked_add(count).ok_or(Error::TransactionCount)?;
                let slice = transactions
                    .get(offset..end)
                    .ok_or(Error::TransactionCount)?;
                let facts = verifier.inspect(&batch.key.author, slice)?;
                if facts.digest != batch.key.digest
                    || facts.num_txns != batch.num_txns
                    || facts.num_bytes != batch.num_bytes
                {
                    return Err(Error::PayloadMismatch);
                }
                offset = end;
            }
        }
        if offset != transactions.len() {
            return Err(Error::TransactionCount);
        }
        let mut transactions = transactions.into_iter();
        let mut resolved: Vec<Vec<Vec<T>>> =
            (0..entry.sections.len()).map(|_| Vec::new()).collect();
        for index in fetch_order {
            for batch in &entry.sections[index].batches {
                resolved[index].push(
                    transactions
                        .by_ref()
                        .take(batch.num_txns as usize)
                        .collect(),
                );
            }
        }
        self.pending
            .resolve(&ticket.0, resolved)
            .map_err(|_| Error::AlreadyResolved)
    }

    /// Publish only complete sections, retaining empty markers. This finite
    /// harness processes one ready reservation atomically; a future async runtime
    /// must freeze between sections, never inside a section's declared batches.
    pub fn take_ready(&mut self) -> Vec<PublishedSection<T>> {
        let mut result = Vec::new();
        if self.frozen {
            return result;
        }
        while let Some((index, resolved)) = self.pending.pop_ready() {
            let entry = &mut self.entries[index];
            for (section, resolved_batches) in entry.sections.iter().zip(resolved) {
                let mut batches = Vec::with_capacity(section.batches.len());
                for (info, transactions) in section.batches.iter().zip(resolved_batches) {
                    let first_occurrence =
                        self.emitted_batches.insert(info.key.clone(), ()).is_none();
                    batches.push(PublishedBatch {
                        info: info.clone(),
                        first_occurrence,
                        transactions,
                    });
                }
                result.push(PublishedSection {
                    ordinal: self.published_sections,
                    block: section.block.clone(),
                    kind: section.kind,
                    batches,
                });
                self.published_sections += 1;
            }
            entry.published = true;
            self.pending_transactions -= entry.transactions;
            self.pending_bytes -= entry.bytes;
            self.published_transactions += entry.transactions;
        }
        result
    }

    /// Called by an independent shared deadline/control event, including when
    /// the workload is empty or an earlier fetch never completes. The caller
    /// retains the frozen prefix; later native protocol work remains independent.
    pub fn freeze(&mut self) -> Snapshot {
        self.frozen = true;
        self.snapshot()
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            frozen: self.frozen,
            published_sections: self.published_sections,
            published_transactions: self.published_transactions,
            pending_slices: self.pending.len(),
            resolved_pending_slices: self.pending.resolved_len(),
            pending_transactions: self.pending_transactions,
            pending_payload_bytes: self.pending_bytes,
        }
    }
}
