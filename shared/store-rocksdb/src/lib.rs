//! A synchronous, byte-keyed storage service. Serialization, column-family
//! names, namespaces, retention, and permission to sign remain core policy.
//!
//! The optional backend preserves the native blob/LZ4/pipelined-write profile.
//! A successful write completes at `Written`: WAL is enabled, sync is false.
//! `Durable` is rejected before mutation. There is no memory or file fallback.
#[cfg(any(test, feature = "rocksdb-backend"))]
use std::collections::HashSet;
use std::fmt;

pub use core_api::{Persistence, StorageCapabilities, UnsupportedPersistence};

#[cfg(feature = "rocksdb-backend")]
mod backend;
#[cfg(feature = "rocksdb-backend")]
pub use backend::{RocksStore, Scan};

pub const PROFILE_ID: &str = "blob-lz4-pipelined-v1";
pub const CAPABILITIES: StorageCapabilities = StorageCapabilities {
    maximum_completion: Persistence::Written,
    crash_recovery: true,
    fault_model: "RocksDB WAL enabled with sync=false; recovery uses surviving WAL and SST files; no power-loss durability barrier",
};

/// Explicit requested options, not a report of effective native thread counts,
/// memory allocation, or every RocksDB default. In particular the DB-level
/// write buffer option is distinct from the separately constructed CF options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestedOptions {
    pub create_if_missing: bool,
    pub create_missing_column_families: bool,
    pub blob_files: bool,
    pub min_blob_bytes: u64,
    pub blob_file_bytes: u64,
    pub db_write_buffer_bytes: usize,
    pub parallelism: i32,
    pub max_background_jobs: i32,
    pub adaptive_write_thread_yield: bool,
    pub concurrent_memtable_write: bool,
    pub pipelined_write: bool,
    pub requested_cf_block_bytes: usize,
    pub requested_cf_shared_lru_capacity_bytes: usize,
    pub compression: &'static str,
    pub sync: bool,
    pub wal_disabled: bool,
}

pub const REQUESTED_OPTIONS: RequestedOptions = RequestedOptions {
    create_if_missing: true,
    create_missing_column_families: true,
    blob_files: true,
    min_blob_bytes: 16 * 1024,
    blob_file_bytes: 256 * 1024 * 1024,
    db_write_buffer_bytes: 256 * 1024 * 1024,
    parallelism: 16,
    max_background_jobs: 8,
    adaptive_write_thread_yield: true,
    concurrent_memtable_write: true,
    pipelined_write: true,
    requested_cf_block_bytes: 32 * 1024,
    requested_cf_shared_lru_capacity_bytes: 2 * 1024 * 1024 * 1024,
    compression: "lz4",
    sync: false,
    wal_disabled: false,
};

/// An atomic batch retains the supplied operation order. Identical keys in one
/// batch therefore retain RocksDB's ordinary last-operation-wins behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteOp<'a> {
    Put {
        column_family: &'a str,
        key: &'a [u8],
        value: &'a [u8],
    },
    Delete {
        column_family: &'a str,
        key: &'a [u8],
    },
}

impl WriteOp<'_> {
    pub fn column_family(&self) -> &str {
        match self {
            Self::Put { column_family, .. } | Self::Delete { column_family, .. } => column_family,
        }
    }
}

/// Returned only after RocksDB accepts the complete write batch. This receipt
/// does not authorize protocol effects. Correlation stays with the synchronous
/// caller; no operation identifier or namespace is inserted into stored bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteReceipt {
    pub completed: Persistence,
    pub operations: usize,
    /// RocksDB WriteBatch::size_in_bytes(), not WAL/SST/device traffic.
    pub encoded_write_batch_bytes: usize,
}

#[derive(Debug)]
pub enum Error {
    UnsupportedPersistence(UnsupportedPersistence),
    InvalidColumnFamilies(&'static str),
    UnknownColumnFamily(String),
    #[cfg(feature = "rocksdb-backend")]
    Backend {
        operation: &'static str,
        source: rocksdb::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPersistence(error) => write!(
                f,
                "requested {:?} storage completion; profile supports at most {:?}",
                error.requested, error.supported
            ),
            Self::InvalidColumnFamilies(reason) => write!(f, "invalid column families: {reason}"),
            Self::UnknownColumnFamily(name) => write!(f, "unknown column family: {name}"),
            #[cfg(feature = "rocksdb-backend")]
            Self::Backend { operation, source } => write!(f, "RocksDB {operation}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "rocksdb-backend")]
            Self::Backend { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(any(test, feature = "rocksdb-backend"))]
fn require_completion(required: Persistence) -> Result<(), Error> {
    CAPABILITIES
        .require(required)
        .map_err(Error::UnsupportedPersistence)
}

#[cfg(any(test, feature = "rocksdb-backend"))]
fn validate_column_families(names: &[&str]) -> Result<(), Error> {
    if names.is_empty() {
        return Err(Error::InvalidColumnFamilies(
            "at least one named family is required",
        ));
    }
    let mut seen = HashSet::new();
    for name in names {
        if name.is_empty() || name.as_bytes().contains(&0) {
            return Err(Error::InvalidColumnFamilies(
                "names must be nonempty and contain no NUL",
            ));
        }
        if !seen.insert(name) {
            return Err(Error::InvalidColumnFamilies("duplicate family name"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_is_the_maximum_supported_barrier() {
        for required in [
            Persistence::Accepted,
            Persistence::Visible,
            Persistence::Written,
        ] {
            assert!(require_completion(required).is_ok());
        }
        let error = require_completion(Persistence::Durable).unwrap_err();
        assert!(matches!(error, Error::UnsupportedPersistence(_)));
        assert!(error.to_string().contains("Written"));
        assert!(!REQUESTED_OPTIONS.sync);
        assert!(!REQUESTED_OPTIONS.wal_disabled);
    }

    #[test]
    fn duplicate_or_invalid_family_names_fail_before_open() {
        for names in [&[][..], &["a", "a"], &[""], &["a\0b"]] {
            assert!(validate_column_families(names).is_err());
        }
        assert!(validate_column_families(&["a", "b"]).is_ok());
    }

    #[test]
    fn profile_records_values_instead_of_misleading_native_comments() {
        assert_eq!(REQUESTED_OPTIONS.requested_cf_block_bytes, 32 * 1024);
        assert_eq!(
            REQUESTED_OPTIONS.requested_cf_shared_lru_capacity_bytes,
            2 * 1024 * 1024 * 1024
        );
        assert_eq!(REQUESTED_OPTIONS.parallelism, 16);
        assert_eq!(REQUESTED_OPTIONS.max_background_jobs, 8);
        assert_eq!(REQUESTED_OPTIONS.min_blob_bytes, 16 * 1024);
        assert_eq!(REQUESTED_OPTIONS.blob_file_bytes, 256 * 1024 * 1024);
        assert_eq!(REQUESTED_OPTIONS.db_write_buffer_bytes, 256 * 1024 * 1024);
    }
}
