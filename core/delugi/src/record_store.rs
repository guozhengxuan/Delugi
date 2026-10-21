//! Delugi owns record identity/encoding and custody. An optional byte writer
//! completes before records become visible to the core's existing read cache.
use crate::{
    batch::Record,
    wire::{encode, Digest, Id},
};
use serde::{Deserialize, Serialize};
use shared_store::Persistence;
use std::{ops::Index, path::Path, time::Instant};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum StorageProfile {
    #[default]
    #[serde(rename = "memory-visible-v1")]
    MemoryVisible,
    #[serde(rename = "shared-rocksdb-written-v1")]
    SharedRocksdbWritten,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct WriteMetrics {
    pub attempts: u64,
    pub completed_writes: u64,
    pub failures: u64,
    pub key_bytes: u64,
    pub record_bytes: u64,
    pub encoded_write_batch_bytes: u64,
    pub elapsed_us: u64,
    pub last_error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub profile: StorageProfile,
    pub core_required_completion: &'static str,
    pub actual_write_completion: &'static str,
    pub core_restart_recovery: bool,
    pub fresh_database_only: bool,
    pub native_backend_profile: Option<&'static str>,
    pub writes: WriteMetrics,
}
struct Written {
    encoded_bytes: usize,
}
trait Writer: std::fmt::Debug + Send {
    fn put(&mut self, key: &[u8], value: &[u8], required: Persistence) -> Result<Written, String>;
}
#[derive(Debug)]
pub(crate) struct RecordStore {
    cache: shared_store::MemoryStore<(Id, Digest), Record>,
    writer: Option<Box<dyn Writer>>,
    metrics: WriteMetrics,
}
impl RecordStore {
    pub fn new() -> Self {
        Self {
            cache: shared_store::MemoryStore::new(),
            writer: None,
            metrics: WriteMetrics::default(),
        }
    }
    pub fn try_clone_memory(&self) -> Result<Self, String> {
        if self.writer.is_some() {
            return Err(
                "disk-owning record store cannot be cloned; use a fresh replica namespace".into(),
            );
        }
        Ok(Self {
            cache: self.cache.clone(),
            writer: None,
            metrics: self.metrics.clone(),
        })
    }
    pub fn len(&self) -> usize {
        self.cache.len()
    }
    pub fn contains_key(&self, key: &(Id, Digest)) -> bool {
        self.cache.contains_key(key)
    }
    pub fn get(&self, key: &(Id, Digest)) -> Option<&Record> {
        self.cache.get(key)
    }
    pub fn put(&mut self, key: (Id, Digest), value: Record) -> Result<(), String> {
        if let Some(writer) = self.writer.as_mut() {
            let key_bytes = encode(&key)?;
            let record_bytes = encode(&value)?;
            self.metrics.attempts += 1;
            let start = Instant::now();
            let result = writer.put(&key_bytes, &record_bytes, Persistence::Visible);
            self.metrics.elapsed_us = self
                .metrics
                .elapsed_us
                .saturating_add(start.elapsed().as_micros().min(u64::MAX as u128) as u64);
            match result {
                Ok(receipt) => {
                    self.metrics.completed_writes += 1;
                    self.metrics.key_bytes += key_bytes.len() as u64;
                    self.metrics.record_bytes += record_bytes.len() as u64;
                    self.metrics.encoded_write_batch_bytes += receipt.encoded_bytes as u64;
                }
                Err(error) => {
                    self.metrics.failures += 1;
                    self.metrics.last_error = Some(error.clone());
                    return Err(error);
                }
            }
        }
        self.cache
            .put(key, value, Persistence::Visible)
            .map_err(|e| format!("visible record cache: {e:?}"))?;
        Ok(())
    }
    pub fn snapshot(&self) -> Snapshot {
        let disk = self.writer.is_some();
        Snapshot {
            profile: if disk {
                StorageProfile::SharedRocksdbWritten
            } else {
                StorageProfile::MemoryVisible
            },
            core_required_completion: "Visible",
            actual_write_completion: if disk {
                "Written (WAL enabled, sync=false)"
            } else {
                "Visible (process-local memory)"
            },
            core_restart_recovery: false,
            fresh_database_only: disk,
            native_backend_profile: if disk {
                Some("blob-lz4-pipelined-v1")
            } else {
                None
            },
            writes: self.metrics.clone(),
        }
    }
    pub fn check_health(&self) -> Result<(), String> {
        self.metrics.last_error.as_ref().map_or(Ok(()), |error| {
            Err(format!("record storage failure: {error}"))
        })
    }
    pub fn enable_rocksdb(&mut self, path: &Path) -> Result<(), String> {
        if self.writer.is_some() || !self.cache.is_empty() {
            return Err("storage profile must be selected before retaining records".into());
        }
        #[cfg(feature = "rocksdb-records")]
        {
            // Atomic directory creation prevents accidental reopen or sharing.
            std::fs::create_dir(path)
                .map_err(|e| format!("fresh Delugi record database directory: {e}"))?;
            let db = shared_store_rocksdb::RocksStore::open(path, &["delugi_records"])
                .map_err(|e| format!("open shared Delugi record database: {e}"))?;
            self.writer = Some(Box::new(RocksWriter(db)));
            Ok(())
        }
        #[cfg(not(feature = "rocksdb-records"))]
        {
            let _ = path;
            Err("shared RocksDB profile requires the rocksdb-records build feature".into())
        }
    }
    #[cfg(test)]
    pub fn fail_once_after(&mut self, successful_writes: usize) {
        self.writer = Some(Box::new(FailingWriter {
            remaining: successful_writes,
            failed: false,
        }));
    }
}
impl Index<&(Id, Digest)> for RecordStore {
    type Output = Record;
    fn index(&self, key: &(Id, Digest)) -> &Record {
        &self.cache[key]
    }
}
#[cfg(feature = "rocksdb-records")]
struct RocksWriter(shared_store_rocksdb::RocksStore);
#[cfg(feature = "rocksdb-records")]
impl std::fmt::Debug for RocksWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RocksWriter(fresh owned namespace)")
    }
}
#[cfg(feature = "rocksdb-records")]
impl Writer for RocksWriter {
    fn put(&mut self, key: &[u8], value: &[u8], required: Persistence) -> Result<Written, String> {
        let receipt = self
            .0
            .put("delugi_records", key, value, required)
            .map_err(|e| format!("Delugi record Written failure: {e}"))?;
        if receipt.completed != Persistence::Written {
            return Err("shared backend failed to complete Written barrier".into());
        }
        Ok(Written {
            encoded_bytes: receipt.encoded_write_batch_bytes,
        })
    }
}
#[cfg(test)]
#[derive(Debug)]
struct FailingWriter {
    remaining: usize,
    failed: bool,
}
#[cfg(test)]
impl Writer for FailingWriter {
    fn put(&mut self, _: &[u8], _: &[u8], required: Persistence) -> Result<Written, String> {
        assert_eq!(required, Persistence::Visible);
        if self.remaining == 0 && !self.failed {
            self.failed = true;
            return Err("injected byte-writer failure before visibility".into());
        }
        self.remaining = self.remaining.saturating_sub(1);
        Ok(Written { encoded_bytes: 0 })
    }
}
