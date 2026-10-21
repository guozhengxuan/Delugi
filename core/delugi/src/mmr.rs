//! Chunked Merkle mountain ranges, indexed consistency proofs, and metadata boundaries.
//! No proof verifier fetches payloads or assumes that a root reveals its children.

use crate::wire::{encode, hash, Context, Digest, Id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub context: Context,
    pub chunk_capacity: u64,
}
impl Config {
    pub fn validate(&self) -> Result<(), String> {
        if !self.chunk_capacity.is_power_of_two() || self.chunk_capacity > (1 << 20) {
            return Err("chunk capacity must be a power of two in 1..=2^20".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub context: Context,
    pub chunk_capacity: u64,
    pub producer: Id,
    pub height: u64,
    pub top: Digest,
    pub partial: Digest,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Level {
    Inner,
    Top,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Peak {
    pub height: u32,
    pub root: Digest,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BasicProof {
    Empty,
    Extension {
        peaks: Vec<Peak>,
        suffix: Vec<Digest>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrefixProof {
    Empty,
    Within {
        inner: BasicProof,
    },
    Boundary {
        top: BasicProof,
    },
    Crossing {
        completion: BasicProof,
        completed_root: Digest,
        top_peaks: Vec<Peak>,
        remaining: BasicProof,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Membership {
    /// Canonical peaks including the opened peak. Its root must reconstruct exactly.
    pub peaks: Vec<Peak>,
    /// Bottom-up siblings; direction is implied by the public leaf index.
    pub siblings: Vec<Digest>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TipOpening {
    pub digest: Digest,
    pub inner: Membership,
    pub top: Option<Membership>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Boundary {
    pub checkpoint: Checkpoint,
    pub top_peaks: Vec<Peak>,
    pub partial_peaks: Vec<Peak>,
    pub tip: Option<TipOpening>,
}

fn bag(c: &Config, k: Id, level: Level, len: u64, peaks: &[Peak]) -> Digest {
    hash(&(
        "MMR/BAG",
        &c.context,
        c.chunk_capacity,
        k,
        level,
        len,
        peaks,
    ))
}
fn parent(c: &Config, k: Id, level: Level, d: u32, left: Digest, right: Digest) -> Digest {
    hash(&(
        "MMR/NODE",
        &c.context,
        c.chunk_capacity,
        k,
        level,
        d,
        left,
        right,
    ))
}
fn leaf(c: &Config, k: Id, height: u64, digest: Digest) -> Digest {
    hash(&(
        "MMR/LEAF",
        &c.context,
        c.chunk_capacity,
        Level::Inner,
        k,
        height,
        digest,
    ))
}
fn chunk(c: &Config, k: Id, index: u64, root: Digest) -> Digest {
    hash(&("MMR/CHUNK", &c.context, c.chunk_capacity, k, index, root))
}
pub fn checkpoint_digest(checkpoint: &Checkpoint) -> Digest {
    hash(&("MMR/CHECKPOINT", checkpoint))
}
pub fn genesis(c: &Config, producer: Id) -> Checkpoint {
    Checkpoint {
        context: c.context.clone(),
        chunk_capacity: c.chunk_capacity,
        producer,
        height: 0,
        top: bag(c, producer, Level::Top, 0, &[]),
        partial: bag(c, producer, Level::Inner, 0, &[]),
    }
}
pub fn validate_checkpoint(c: &Config, p: &Checkpoint) -> Result<(), String> {
    c.validate()?;
    if p.context != c.context || p.chunk_capacity != c.chunk_capacity || p.height == u64::MAX {
        return Err("checkpoint configuration or height mismatch".into());
    }
    let (a, s) = (p.height / c.chunk_capacity, p.height % c.chunk_capacity);
    if (a == 0 && p.top != bag(c, p.producer, Level::Top, 0, &[]))
        || (s == 0 && p.partial != bag(c, p.producer, Level::Inner, 0, &[]))
    {
        return Err("noncanonical empty checkpoint root".into());
    }
    Ok(())
}
fn peak_layout(len: u64) -> Vec<(u64, u32)> {
    let mut result = Vec::new();
    let mut start = 0;
    for d in (0..64).rev() {
        if len & (1u64 << d) != 0 {
            result.push((start, d));
            start += 1u64 << d;
        }
    }
    result
}
fn check_peaks(len: u64, peaks: &[Peak]) -> Result<(), String> {
    let layout = peak_layout(len);
    if peaks.len() != layout.len() || peaks.iter().zip(layout).any(|(p, (_, d))| p.height != d) {
        return Err("noncanonical peak heights".into());
    }
    Ok(())
}
fn cover(mut from: u64, to: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    while from < to {
        let remaining = to - from;
        let d = (63 - remaining.leading_zeros()).min(if from == 0 {
            63
        } else {
            from.trailing_zeros()
        });
        out.push((from, d));
        from += 1u64 << d;
    }
    out
}
fn append_tree(
    c: &Config,
    k: Id,
    level: Level,
    len: &mut u64,
    peaks: &mut Vec<Peak>,
    mut d: u32,
    mut root: Digest,
) -> Result<(), String> {
    if d >= 64 {
        return Err("invalid subtree height".into());
    }
    let size = 1u64 << d;
    if *len % size != 0 {
        return Err("unaligned subtree".into());
    }
    let next = len.checked_add(size).ok_or("MMR length overflow")?;
    while peaks.last().map(|p| p.height) == Some(d) {
        let left = peaks.pop().unwrap().root;
        d += 1;
        root = parent(c, k, level, d, left, root);
    }
    if peaks.last().map(|p| p.height <= d).unwrap_or(false) {
        return Err("invalid append peaks".into());
    }
    peaks.push(Peak { height: d, root });
    *len = next;
    Ok(())
}
fn verify_basic(
    c: &Config,
    k: Id,
    level: Level,
    u: u64,
    ru: Digest,
    v: u64,
    rv: Digest,
    proof: &BasicProof,
) -> Result<(), String> {
    if u > v {
        return Err("descending basic proof".into());
    }
    if u == v {
        return if ru == rv && *proof == BasicProof::Empty {
            Ok(())
        } else {
            Err("unequal basic identity".into())
        };
    }
    let (mut peaks, suffix) = match proof {
        BasicProof::Extension { peaks, suffix } => (peaks.clone(), suffix),
        _ => return Err("missing basic extension".into()),
    };
    check_peaks(u, &peaks)?;
    if bag(c, k, level, u, &peaks) != ru {
        return Err("old peak opening mismatch".into());
    }
    let ranges = cover(u, v);
    if suffix.len() != ranges.len() {
        return Err("incorrect suffix root count".into());
    }
    let mut len = u;
    for ((_, d), root) in ranges.into_iter().zip(suffix) {
        append_tree(c, k, level, &mut len, &mut peaks, d, *root)?;
    }
    if len != v || bag(c, k, level, len, &peaks) != rv {
        return Err("new root mismatch".into());
    }
    Ok(())
}
pub fn verify_prefix(
    c: &Config,
    a: &Checkpoint,
    b: &Checkpoint,
    proof: &PrefixProof,
) -> Result<(), String> {
    let _cost = crate::meter::measure(crate::meter::Operation::PrefixProofVerify);
    encode(proof)?;
    validate_checkpoint(c, a)?;
    validate_checkpoint(c, b)?;
    if a.producer != b.producer || a.height > b.height {
        return Err("incompatible checkpoint endpoints".into());
    }
    if a.height == b.height {
        return if a == b && *proof == PrefixProof::Empty {
            Ok(())
        } else {
            Err("unequal checkpoint identity".into())
        };
    }
    let k = a.producer;
    let cap = c.chunk_capacity;
    let (old, s, new, t) = (
        a.height / cap,
        a.height % cap,
        b.height / cap,
        b.height % cap,
    );
    match (old == new, s, proof) {
        (true, _, PrefixProof::Within { inner }) if a.top == b.top => {
            verify_basic(c, k, Level::Inner, s, a.partial, t, b.partial, inner)
        }
        (false, 0, PrefixProof::Boundary { top }) => {
            verify_basic(c, k, Level::Top, old, a.top, new, b.top, top)
        }
        (
            false,
            _,
            PrefixProof::Crossing {
                completion,
                completed_root,
                top_peaks,
                remaining,
            },
        ) => {
            verify_basic(
                c,
                k,
                Level::Inner,
                s,
                a.partial,
                cap,
                *completed_root,
                completion,
            )?;
            check_peaks(old, top_peaks)?;
            if bag(c, k, Level::Top, old, top_peaks) != a.top {
                return Err("crossing old top mismatch".into());
            }
            let mut peaks = top_peaks.clone();
            let mut len = old;
            append_tree(
                c,
                k,
                Level::Top,
                &mut len,
                &mut peaks,
                0,
                chunk(c, k, old + 1, *completed_root),
            )?;
            verify_basic(
                c,
                k,
                Level::Top,
                len,
                bag(c, k, Level::Top, len, &peaks),
                new,
                b.top,
                remaining,
            )
        }
        _ => Err("wrong prefix proof shape or top root".into()),
    }
}
fn verify_member(
    c: &Config,
    k: Id,
    level: Level,
    len: u64,
    index: u64,
    value: Digest,
    root: Digest,
    m: &Membership,
) -> Result<(), String> {
    check_peaks(len, &m.peaks)?;
    if index >= len || bag(c, k, level, len, &m.peaks) != root {
        return Err("membership endpoint mismatch".into());
    }
    let (peak_index, (start, d)) = peak_layout(len)
        .into_iter()
        .enumerate()
        .find(|(_, (s, d))| index >= *s && index - *s < (1u64 << d))
        .ok_or("missing membership peak")?;
    if m.siblings.len() != d as usize {
        return Err("incorrect membership path length".into());
    }
    let mut node = value;
    for (h, sibling) in m.siblings.iter().enumerate() {
        node = if ((index - start) >> h) & 1 == 0 {
            parent(c, k, level, h as u32 + 1, node, *sibling)
        } else {
            parent(c, k, level, h as u32 + 1, *sibling, node)
        };
    }
    if node != m.peaks[peak_index].root {
        return Err("membership path root mismatch".into());
    }
    Ok(())
}
pub fn verify_boundary(c: &Config, b: &Boundary) -> Result<(), String> {
    encode(b)?;
    let p = &b.checkpoint;
    validate_checkpoint(c, p)?;
    let (a, s) = (p.height / c.chunk_capacity, p.height % c.chunk_capacity);
    check_peaks(a, &b.top_peaks)?;
    check_peaks(s, &b.partial_peaks)?;
    if bag(c, p.producer, Level::Top, a, &b.top_peaks) != p.top
        || bag(c, p.producer, Level::Inner, s, &b.partial_peaks) != p.partial
    {
        return Err("boundary peaks mismatch".into());
    }
    if p.height == 0 {
        return if b.tip.is_none() {
            Ok(())
        } else {
            Err("genesis has no terminal opening".into())
        };
    }
    let tip = b.tip.as_ref().ok_or("missing authenticated base tip")?;
    let value = leaf(c, p.producer, p.height, tip.digest);
    if s > 0 {
        if tip.top.is_some() {
            return Err("unused top membership".into());
        }
        verify_member(
            c,
            p.producer,
            Level::Inner,
            s,
            s - 1,
            value,
            p.partial,
            &tip.inner,
        )
    } else {
        let q = bag(
            c,
            p.producer,
            Level::Inner,
            c.chunk_capacity,
            &tip.inner.peaks,
        );
        verify_member(
            c,
            p.producer,
            Level::Inner,
            c.chunk_capacity,
            c.chunk_capacity - 1,
            value,
            q,
            &tip.inner,
        )?;
        verify_member(
            c,
            p.producer,
            Level::Top,
            a,
            a - 1,
            chunk(c, p.producer, a, q),
            p.top,
            tip.top.as_ref().ok_or("missing top membership")?,
        )
    }
}

/// One indexed MMR branch. Every historical peak opening and internal node is retained.
#[derive(Clone, Debug)]
struct Tree {
    level: Level,
    len: u64,
    peaks: Vec<Peak>,
    nodes: BTreeMap<(u64, u32), Digest>,
    snapshots: BTreeMap<u64, Vec<Peak>>,
}
impl Tree {
    fn seed(level: Level, len: u64, peaks: Vec<Peak>) -> Result<Self, String> {
        check_peaks(len, &peaks)?;
        let nodes = peak_layout(len)
            .into_iter()
            .zip(&peaks)
            .map(|((s, d), p)| ((s, d), p.root))
            .collect();
        let mut snapshots = BTreeMap::new();
        snapshots.insert(len, peaks.clone());
        Ok(Self {
            level,
            len,
            peaks,
            nodes,
            snapshots,
        })
    }
    fn empty(level: Level) -> Self {
        Self::seed(level, 0, Vec::new()).unwrap()
    }
    fn root(&self, c: &Config, k: Id) -> Digest {
        bag(c, k, self.level, self.len, &self.peaks)
    }
    fn root_at(&self, c: &Config, k: Id, len: u64) -> Result<Digest, String> {
        Ok(bag(
            c,
            k,
            self.level,
            len,
            self.snapshots
                .get(&len)
                .ok_or("historical peaks unavailable")?,
        ))
    }
    fn append(&mut self, c: &Config, k: Id, value: Digest) -> Result<(), String> {
        if self.len == u64::MAX {
            return Err("MMR full".into());
        }
        let (mut start, mut d, mut root) = (self.len, 0, value);
        self.nodes.insert((start, 0), root);
        for peak in self.peaks.iter().rev() {
            if peak.height != d {
                break;
            }
            start -= 1u64 << d;
            d += 1;
            root = parent(c, k, self.level, d, peak.root, root);
            self.nodes.insert((start, d), root);
        }
        append_tree(c, k, self.level, &mut self.len, &mut self.peaks, 0, value)?;
        self.snapshots.insert(self.len, self.peaks.clone());
        Ok(())
    }
    fn proof(&self, u: u64, v: u64) -> Result<BasicProof, String> {
        if u > v {
            return Err("descending proof request".into());
        }
        if u == v {
            return Ok(BasicProof::Empty);
        }
        let peaks = self
            .snapshots
            .get(&u)
            .ok_or("old peaks unavailable")?
            .clone();
        if !self.snapshots.contains_key(&v) {
            return Err("target peaks unavailable".into());
        }
        let suffix = cover(u, v)
            .into_iter()
            .map(|key| {
                self.nodes
                    .get(&key)
                    .copied()
                    .ok_or("indexed suffix node unavailable".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BasicProof::Extension { peaks, suffix })
    }
    fn membership(&self, len: u64, index: u64) -> Result<Membership, String> {
        let peaks = self
            .snapshots
            .get(&len)
            .ok_or("membership peaks unavailable")?
            .clone();
        let (start, d) = peak_layout(len)
            .into_iter()
            .find(|(s, d)| index >= *s && index - *s < (1u64 << d))
            .ok_or("membership leaf absent")?;
        let mut siblings = Vec::new();
        for h in 0..d {
            let group = (index - start) >> h;
            let sibling = start + ((group ^ 1) << h);
            siblings.push(
                *self
                    .nodes
                    .get(&(sibling, h))
                    .ok_or("membership node unavailable")?,
            );
        }
        Ok(Membership { peaks, siblings })
    }
    fn ingest_member(&mut self, c: &Config, k: Id, index: u64, value: Digest, m: &Membership) {
        let mut root = value;
        let mut start = index;
        self.nodes.insert((start, 0), root);
        for (d, sibling) in m.siblings.iter().enumerate() {
            let d = d as u32;
            let right = (index >> d) & 1 == 1;
            let sibling_start = if right {
                start - (1 << d)
            } else {
                start + (1 << d)
            };
            self.nodes.insert((sibling_start, d), *sibling);
            if right {
                start = sibling_start;
                root = parent(c, k, self.level, d + 1, *sibling, root)
            } else {
                root = parent(c, k, self.level, d + 1, root, *sibling)
            }
            self.nodes.insert((start, d + 1), root);
        }
    }
}

/// Branch-specific indexed state; cloned when a producer forks. Metadata-only
/// initialization preserves openings without claiming possession of older bytes.
#[derive(Clone, Debug)]
pub(crate) struct State {
    config: Config,
    producer: Id,
    height: u64,
    top: Tree,
    inners: BTreeMap<u64, Tree>,
    checkpoints: BTreeMap<u64, Checkpoint>,
    digests: BTreeMap<u64, Digest>,
}
impl State {
    pub(crate) fn from_boundary(c: &Config, b: &Boundary) -> Result<Self, String> {
        verify_boundary(c, b)?;
        let p = &b.checkpoint;
        let (a, s) = (p.height / c.chunk_capacity, p.height % c.chunk_capacity);
        let mut top = Tree::seed(Level::Top, a, b.top_peaks.clone())?;
        let mut inners = BTreeMap::new();
        inners.insert(a + 1, Tree::seed(Level::Inner, s, b.partial_peaks.clone())?);
        let mut digests = BTreeMap::new();
        if let Some(tip) = &b.tip {
            digests.insert(p.height, tip.digest);
            let v = leaf(c, p.producer, p.height, tip.digest);
            if s > 0 {
                inners
                    .get_mut(&(a + 1))
                    .unwrap()
                    .ingest_member(c, p.producer, s - 1, v, &tip.inner)
            } else {
                let mut inner =
                    Tree::seed(Level::Inner, c.chunk_capacity, tip.inner.peaks.clone())?;
                inner.ingest_member(c, p.producer, c.chunk_capacity - 1, v, &tip.inner);
                let q = inner.root(c, p.producer);
                inners.insert(a, inner);
                top.ingest_member(
                    c,
                    p.producer,
                    a - 1,
                    chunk(c, p.producer, a, q),
                    tip.top.as_ref().unwrap(),
                );
            }
        }
        let mut checkpoints = BTreeMap::new();
        checkpoints.insert(p.height, p.clone());
        Ok(Self {
            config: c.clone(),
            producer: p.producer,
            height: p.height,
            top,
            inners,
            checkpoints,
            digests,
        })
    }
    pub(crate) fn genesis(c: &Config, k: Id) -> Self {
        Self::from_boundary(
            c,
            &Boundary {
                checkpoint: genesis(c, k),
                top_peaks: vec![],
                partial_peaks: vec![],
                tip: None,
            },
        )
        .unwrap()
    }
    pub(crate) fn checkpoint(&self) -> Checkpoint {
        self.checkpoints[&self.height].clone()
    }
    pub(crate) fn checkpoint_at(&self, h: u64) -> Option<&Checkpoint> {
        self.checkpoints.get(&h)
    }
    pub(crate) fn digest_at(&self, h: u64) -> Option<Digest> {
        self.digests.get(&h).copied()
    }
    pub(crate) fn append(&mut self, digest: Digest) -> Result<(), String> {
        if self.height >= u64::MAX - 1 {
            return Err("batch height overflow".into());
        }
        let cap = self.config.chunk_capacity;
        let index = self.height / cap + 1;
        let inner = self
            .inners
            .entry(index)
            .or_insert_with(|| Tree::empty(Level::Inner));
        inner.append(
            &self.config,
            self.producer,
            leaf(&self.config, self.producer, self.height + 1, digest),
        )?;
        if inner.len == cap {
            self.top.append(
                &self.config,
                self.producer,
                chunk(
                    &self.config,
                    self.producer,
                    index,
                    inner.root(&self.config, self.producer),
                ),
            )?;
            self.inners.insert(index + 1, Tree::empty(Level::Inner));
        }
        self.height += 1;
        self.digests.insert(self.height, digest);
        let partial = self.inners[&(self.height / cap + 1)].root(&self.config, self.producer);
        self.checkpoints.insert(
            self.height,
            Checkpoint {
                context: self.config.context.clone(),
                chunk_capacity: cap,
                producer: self.producer,
                height: self.height,
                top: self.top.root(&self.config, self.producer),
                partial,
            },
        );
        Ok(())
    }
    pub(crate) fn proof(&self, a: &Checkpoint, b: &Checkpoint) -> Result<PrefixProof, String> {
        let _cost = crate::meter::measure(crate::meter::Operation::PrefixProofBuild);
        if self.checkpoint_at(a.height) != Some(a)
            || self.checkpoint_at(b.height) != Some(b)
            || a.height > b.height
        {
            return Err("endpoints are not on this held branch".into());
        }
        if a == b {
            return Ok(PrefixProof::Empty);
        }
        let cap = self.config.chunk_capacity;
        let (old, s, new, t) = (
            a.height / cap,
            a.height % cap,
            b.height / cap,
            b.height % cap,
        );
        let proof = if old == new {
            PrefixProof::Within {
                inner: self.inners[&(old + 1)].proof(s, t)?,
            }
        } else if s == 0 {
            PrefixProof::Boundary {
                top: self.top.proof(old, new)?,
            }
        } else {
            let inner = &self.inners[&(old + 1)];
            PrefixProof::Crossing {
                completion: inner.proof(s, cap)?,
                completed_root: inner.root_at(&self.config, self.producer, cap)?,
                top_peaks: self
                    .top
                    .snapshots
                    .get(&old)
                    .ok_or("old top peaks unavailable")?
                    .clone(),
                remaining: self.top.proof(old + 1, new)?,
            }
        };
        verify_prefix(&self.config, a, b, &proof)?;
        Ok(proof)
    }
    pub(crate) fn boundary(&self, p: &Checkpoint) -> Result<Boundary, String> {
        if self.checkpoint_at(p.height) != Some(p) {
            return Err("boundary is not on this held branch".into());
        }
        let cap = self.config.chunk_capacity;
        let (a, s) = (p.height / cap, p.height % cap);
        let top_peaks = self
            .top
            .snapshots
            .get(&a)
            .ok_or("top peaks unavailable")?
            .clone();
        let partial_peaks = self
            .inners
            .get(&(a + 1))
            .and_then(|t| t.snapshots.get(&s))
            .ok_or("partial peaks unavailable")?
            .clone();
        let tip = if p.height == 0 {
            None
        } else {
            let (chunk_index, len) = if s == 0 { (a, cap) } else { (a + 1, s) };
            let inner = self
                .inners
                .get(&chunk_index)
                .ok_or("terminal chunk unavailable")?
                .membership(len, len - 1)?;
            let top = if s == 0 {
                Some(self.top.membership(a, a - 1)?)
            } else {
                None
            };
            Some(TipOpening {
                digest: self
                    .digest_at(p.height)
                    .ok_or("terminal digest unavailable")?,
                inner,
                top,
            })
        };
        let result = Boundary {
            checkpoint: p.clone(),
            top_peaks,
            partial_peaks,
            tip,
        };
        verify_boundary(&self.config, &result)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            context: Context {
                instance: [1; 32],
                configuration: [2; 32],
            },
            chunk_capacity: 4,
        }
    }
    fn state() -> State {
        let c = config();
        let mut s = State::genesis(&c, 2);
        for h in 1u64..=24 {
            s.append(hash(&h)).unwrap()
        }
        s
    }
    #[test]
    fn every_chunked_prefix_and_boundary_verifies() {
        let s = state();
        for a in 0..=24 {
            let x = s.checkpoint_at(a).unwrap();
            verify_boundary(&config(), &s.boundary(x).unwrap()).unwrap();
            for b in a..=24 {
                let y = s.checkpoint_at(b).unwrap();
                verify_prefix(&config(), x, y, &s.proof(x, y).unwrap()).unwrap();
            }
        }
    }
    #[test]
    fn same_height_requires_exact_identity_and_empty_shape() {
        let s = state();
        let a = s.checkpoint_at(3).unwrap();
        let mut b = a.clone();
        b.partial[0] ^= 1;
        assert!(verify_prefix(&config(), a, &b, &PrefixProof::Empty).is_err());
        assert!(verify_prefix(
            &config(),
            a,
            a,
            &PrefixProof::Within {
                inner: BasicProof::Empty
            }
        )
        .is_err());
    }
    #[test]
    fn partial_crossing_binds_explicit_first_chunk() {
        let s = state();
        let a = s.checkpoint_at(1).unwrap();
        let b = s.checkpoint_at(16).unwrap();
        let mut proof = s.proof(a, b).unwrap();
        if let PrefixProof::Crossing { completed_root, .. } = &mut proof {
            completed_root[0] ^= 1
        } else {
            panic!()
        };
        assert!(verify_prefix(&config(), a, b, &proof).is_err());
        assert!(verify_prefix(
            &config(),
            a,
            b,
            &PrefixProof::Boundary {
                top: s.top.proof(0, 4).unwrap()
            }
        )
        .is_err());
    }
    #[test]
    fn missing_additional_and_malformed_nodes_reject() {
        let s = state();
        let a = s.checkpoint_at(0).unwrap();
        let b = s.checkpoint_at(3).unwrap();
        let mut p = s.proof(a, b).unwrap();
        if let PrefixProof::Within {
            inner: BasicProof::Extension { suffix, .. },
        } = &mut p
        {
            suffix.push([0; 32]);
        }
        assert!(verify_prefix(&config(), a, b, &p).is_err());
        let mut p = s.proof(a, b).unwrap();
        if let PrefixProof::Within {
            inner: BasicProof::Extension { suffix, .. },
        } = &mut p
        {
            suffix.pop();
        }
        assert!(verify_prefix(&config(), a, b, &p).is_err());
    }
    #[test]
    fn metadata_seed_extends_without_prebase_leaf_digests() {
        let full = state();
        for h in 1..=16 {
            let base = full.checkpoint_at(h).unwrap();
            let boundary = full.boundary(base).unwrap();
            let mut seeded = State::from_boundary(&config(), &boundary).unwrap();
            assert!(seeded.digest_at(h - 1).is_none());
            for z in h + 1..=24 {
                seeded.append(hash(&z)).unwrap();
                assert_eq!(seeded.checkpoint(), *full.checkpoint_at(z).unwrap());
                let p = seeded.proof(base, &seeded.checkpoint()).unwrap();
                verify_prefix(&config(), base, &seeded.checkpoint(), &p).unwrap();
                verify_boundary(&config(), &seeded.boundary(&seeded.checkpoint()).unwrap())
                    .unwrap();
            }
        }
    }
    #[test]
    fn boundary_tip_and_sibling_mutations_reject() {
        let s = state();
        for h in [3, 4, 8, 11, 16] {
            let mut b = s.boundary(s.checkpoint_at(h).unwrap()).unwrap();
            b.tip.as_mut().unwrap().digest[0] ^= 1;
            assert!(verify_boundary(&config(), &b).is_err());
            let mut b = s.boundary(s.checkpoint_at(h).unwrap()).unwrap();
            b.tip.as_mut().unwrap().inner.siblings.push([0; 32]);
            assert!(verify_boundary(&config(), &b).is_err());
        }
    }
    #[test]
    fn roots_do_not_create_missing_proof_nodes() {
        let s = state();
        let base = s.checkpoint_at(8).unwrap();
        let seeded = State::from_boundary(&config(), &s.boundary(base).unwrap()).unwrap();
        assert!(seeded.proof(s.checkpoint_at(3).unwrap(), base).is_err());
    }
    #[test]
    fn wrong_configuration_and_noncanonical_empty_roots_reject() {
        let mut p = genesis(&config(), 0);
        p.partial = [0; 32];
        assert!(validate_checkpoint(&config(), &p).is_err());
        let mut c = config();
        c.chunk_capacity = 3;
        assert!(c.validate().is_err());
        let p = genesis(&config(), 0);
        c = config();
        c.chunk_capacity = 8;
        assert!(validate_checkpoint(&c, &p).is_err());
    }

    #[test]
    fn diverging_branches_share_only_their_actual_common_prefix() {
        let c = config();
        let mut a = State::genesis(&c, 0);
        for h in 1u64..=3 {
            a.append(hash(&h)).unwrap();
        }
        let common = a.checkpoint();
        let mut b = a.clone();
        for h in 4u64..=12 {
            a.append(hash(&("left", h))).unwrap();
            b.append(hash(&("right", h))).unwrap();
        }
        verify_prefix(
            &c,
            &common,
            &a.checkpoint(),
            &a.proof(&common, &a.checkpoint()).unwrap(),
        )
        .unwrap();
        verify_prefix(
            &c,
            &common,
            &b.checkpoint(),
            &b.proof(&common, &b.checkpoint()).unwrap(),
        )
        .unwrap();
        let old_a = a.checkpoint_at(5).unwrap();
        let old_b = b.checkpoint_at(5).unwrap();
        assert_ne!(old_a, old_b);
        assert!(verify_prefix(&c, old_a, old_b, &PrefixProof::Empty).is_err());
        assert!(verify_prefix(
            &c,
            old_a,
            &b.checkpoint(),
            &b.proof(old_b, &b.checkpoint()).unwrap()
        )
        .is_err());
        assert!(b.proof(old_a, &b.checkpoint()).is_err());
    }
}
