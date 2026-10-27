//! Bounded disk spools and streamed observer journals. Files are private, newly
//! created, and never reused. A failed write poisons the file for the run.
use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use shared_crypto::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
};

fn create(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

pub struct Slots {
    file: File,
    path: PathBuf,
    count: u64,
    width: u64,
    poisoned: bool,
}
impl Slots {
    pub fn create(
        path: &Path,
        count: u64,
        maximum_record: usize,
        maximum_bytes: u64,
    ) -> Result<Self> {
        ensure!(
            maximum_record > 0 && maximum_record <= 128 * 1024,
            "invalid spool record bound"
        );
        let width = maximum_record as u64 + 4;
        let bytes = count.checked_mul(width).context("spool size overflow")?;
        ensure!(bytes <= maximum_bytes, "spool storage envelope exhausted");
        let file = create(path)?;
        file.set_len(bytes)?;
        Ok(Self {
            file,
            path: path.into(),
            count,
            width,
            poisoned: false,
        })
    }
    pub fn len(&self) -> u64 {
        self.count
    }
    pub fn write(&mut self, index: u64, bytes: &[u8]) -> Result<()> {
        ensure!(
            !self.poisoned && index < self.count,
            "invalid/poisoned spool position"
        );
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= self.width - 4,
            "oversized spool record"
        );
        self.poisoned = true;
        self.file.seek(SeekFrom::Start(index * self.width))?;
        self.file.write_all(&(bytes.len() as u32).to_le_bytes())?;
        self.file.write_all(bytes)?;
        self.poisoned = false;
        Ok(())
    }
    pub fn read(&mut self, index: u64) -> Result<Vec<u8>> {
        ensure!(
            !self.poisoned && index < self.count,
            "invalid/poisoned spool position"
        );
        self.file.seek(SeekFrom::Start(index * self.width))?;
        let mut size = [0; 4];
        self.file.read_exact(&mut size)?;
        let size = u32::from_le_bytes(size) as u64;
        ensure!(
            size > 0 && size <= self.width - 4,
            "missing or corrupt spool record"
        );
        let mut bytes = vec![0; size as usize];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    pub fn remove(self) -> Result<()> {
        drop(self.file);
        std::fs::remove_file(self.path)?;
        Ok(())
    }
}

pub enum Rows<T> {
    Memory(Vec<T>),
    Disk(Slots, PhantomData<T>),
}
impl<T: Serialize + DeserializeOwned + Clone> Rows<T> {
    pub fn disk(path: &Path, count: u64, bytes: u64) -> Result<Self> {
        Ok(Self::Disk(
            Slots::create(path, count, 2048, bytes)?,
            PhantomData,
        ))
    }
    pub fn len(&self) -> usize {
        match self {
            Self::Memory(v) => v.len(),
            Self::Disk(s, _) => s.len() as usize,
        }
    }
    pub fn read(&mut self, index: usize) -> Result<T> {
        match self {
            Self::Memory(v) => v.get(index).cloned().context("row outside manifest"),
            Self::Disk(s, _) => Ok(serde_json::from_slice(&s.read(index as u64)?)?),
        }
    }
    pub fn write(&mut self, index: usize, row: T) -> Result<()> {
        match self {
            Self::Memory(v) => {
                *v.get_mut(index).context("row outside manifest")? = row;
                Ok(())
            }
            Self::Disk(s, _) => s.write(index as u64, &serde_json::to_vec(&row)?),
        }
    }
    pub fn remove(self) -> Result<()> {
        if let Self::Disk(s, _) = self {
            s.remove()?;
        }
        Ok(())
    }
}

pub struct Journal {
    writer: BufWriter<File>,
    path: PathBuf,
    hash: Sha256,
    bytes: u64,
    rows: u64,
    limit: u64,
    poisoned: bool,
}
impl Journal {
    pub fn create(path: &Path, limit: u64) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::with_capacity(64 * 1024, create(path)?),
            path: path.into(),
            hash: Sha256::new(),
            bytes: 0,
            rows: 0,
            limit,
            poisoned: false,
        })
    }
    pub fn append(&mut self, value: &impl Serialize) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        bytes.push(b'\n');
        ensure!(!self.poisoned, "journal write previously failed");
        ensure!(
            bytes.len() <= 64 * 1024 * 1024,
            "journal record exceeds64MiB"
        );
        let total = self
            .bytes
            .checked_add(bytes.len() as u64)
            .context("journal size overflow")?;
        ensure!(total <= self.limit, "journal storage envelope exhausted");
        self.poisoned = true;
        self.writer.write_all(&bytes)?;
        self.hash.update(&bytes);
        self.bytes = total;
        self.rows += 1;
        self.poisoned = false;
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.rows as usize
    }
    pub fn finish(mut self) -> Result<Value> {
        ensure!(!self.poisoned, "incomplete journal");
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(
            json!({"name":self.path.file_name().unwrap().to_str().unwrap(),
                  "sha256":crate::config::hex(self.hash.finalize().as_slice()),
                  "bytes":self.bytes,"rows":self.rows}),
        )
    }
}

pub enum Outputs {
    Memory(Vec<Value>),
    Disk(Journal),
}
impl Outputs {
    pub fn len(&self) -> usize {
        match self {
            Self::Memory(v) => v.len(),
            Self::Disk(j) => j.len(),
        }
    }
    pub fn push(&mut self, v: Value) -> Result<()> {
        match self {
            Self::Memory(rows) => {
                rows.push(v);
                Ok(())
            }
            Self::Disk(j) => j.append(&v),
        }
    }
    pub fn finish(self, path: &Path, limit: u64) -> Result<Value> {
        match self {
            Self::Disk(j) => j.finish(),
            Self::Memory(rows) => {
                let mut j = Journal::create(path, limit)?;
                for r in rows {
                    j.append(&r)?;
                }
                j.finish()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn directory() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "delugi-spool-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        p
    }
    #[test]
    fn slots_bound_storage_and_reject_missing_truncated_and_oversized_data() {
        let d = directory();
        let p = d.join("slots");
        assert!(Slots::create(&p, u64::MAX, 100, 4096).is_err());
        let mut s = Slots::create(&p, 3, 100, 312).unwrap();
        assert!(s.read(0).is_err());
        assert!(s.write(0, &[1; 101]).is_err());
        s.write(0, b"abc").unwrap();
        s.write(2, b"last").unwrap();
        assert_eq!(s.read(0).unwrap(), b"abc");
        s.write(0, b"x").unwrap();
        assert_eq!(s.read(0).unwrap(), b"x");
        assert!(Slots::create(&p, 3, 100, 312).is_err());
        s.file.set_len(210).unwrap();
        assert!(s.read(2).is_err());
        s.remove().unwrap();
        std::fs::remove_dir(d).unwrap();
    }
    #[test]
    fn journal_hash_and_count_bind_exact_stream_and_limit_failure_does_not_credit() {
        let d = directory();
        let p = d.join("rows.jsonl");
        let mut j = Journal::create(&p, 16).unwrap();
        j.append(&json!({"a":1})).unwrap();
        j.append(&json!({"a":2})).unwrap();
        assert!(j.append(&json!({"a":3})).is_err());
        let r = j.finish().unwrap();
        let b = std::fs::read(&p).unwrap();
        assert_eq!(r["sha256"], crate::config::digest(&b));
        assert_eq!(r["rows"], 2);
        assert_eq!(r["bytes"], 16);
        std::fs::remove_dir_all(d).unwrap();
    }
}
