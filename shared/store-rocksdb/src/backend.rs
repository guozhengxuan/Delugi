use crate::{
    require_completion, validate_column_families, Error, Persistence, StorageCapabilities, WriteOp,
    WriteReceipt, CAPABILITIES, PROFILE_ID, REQUESTED_OPTIONS,
};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, ColumnFamilyDescriptor, DBCompressionType,
    DBRawIteratorWithThreadMode, Options, WriteBatch, WriteOptions, DB,
};
use std::collections::HashSet;
use std::path::Path;

/// A physical database. The core chooses its directory and raw family/key/value
/// bytes. This service does not know committee IDs, epochs, batch formats, or
/// retention policy. Dropping it uses ordinary RocksDB drop behavior; no added
/// flush or sync changes native completion semantics.
pub struct RocksStore {
    db: DB,
}

impl RocksStore {
    pub fn open(path: impl AsRef<Path>, column_families: &[&str]) -> Result<Self, Error> {
        validate_column_families(column_families)?;
        let options = database_options();
        let mut table_options = BlockBasedOptions::default();
        table_options.set_block_size(REQUESTED_OPTIONS.requested_cf_block_bytes);
        let cache = Cache::new_lru_cache(REQUESTED_OPTIONS.requested_cf_shared_lru_capacity_bytes);
        table_options.set_block_cache(&cache);
        let mut descriptors = column_families
            .iter()
            .map(|name| {
                let mut options = compression_options();
                options.set_block_based_table_factory(&table_options);
                ColumnFamilyDescriptor::new(*name, options)
            })
            .collect::<Vec<_>>();

        // Match the native schemadb open path: listing fails on first open; the
        // subsequent open returns real errors. Existing extra families remain
        // accessible and use default options plus LZ4, without the new cache.
        let existing = DB::list_cf(&options, path.as_ref()).unwrap_or_default();
        let requested = column_families.iter().copied().collect::<HashSet<_>>();
        let existing_names = existing.iter().map(String::as_str).collect::<HashSet<_>>();
        for name in existing_names.difference(&requested) {
            descriptors.push(ColumnFamilyDescriptor::new(*name, compression_options()));
        }
        let db = DB::open_cf_descriptors(&options, path, descriptors).map_err(|source| {
            Error::Backend {
                operation: "open",
                source,
            }
        })?;
        Ok(Self { db })
    }

    pub fn capabilities(&self) -> StorageCapabilities {
        CAPABILITIES
    }
    pub fn profile_id(&self) -> &'static str {
        PROFILE_ID
    }

    fn family(&self, name: &str) -> Result<&ColumnFamily, Error> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| Error::UnknownColumnFamily(name.to_owned()))
    }

    pub fn get(&self, column_family: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        self.db
            .get_cf(self.family(column_family)?, key)
            .map_err(|source| Error::Backend {
                operation: "get",
                source,
            })
    }

    pub fn put(
        &self,
        column_family: &str,
        key: &[u8],
        value: &[u8],
        required: Persistence,
    ) -> Result<WriteReceipt, Error> {
        self.write_batch(
            &[WriteOp::Put {
                column_family,
                key,
                value,
            }],
            required,
        )
    }

    pub fn delete(
        &self,
        column_family: &str,
        key: &[u8],
        required: Persistence,
    ) -> Result<WriteReceipt, Error> {
        self.write_batch(&[WriteOp::Delete { column_family, key }], required)
    }

    /// Every family and the requested barrier are checked before the one atomic
    /// native write. Errors never downgrade to a weaker completion or fallback.
    pub fn write_batch(
        &self,
        operations: &[WriteOp<'_>],
        required: Persistence,
    ) -> Result<WriteReceipt, Error> {
        require_completion(required)?;
        let mut batch = WriteBatch::default();
        for operation in operations {
            let family = self.family(operation.column_family())?;
            match operation {
                WriteOp::Put { key, value, .. } => batch.put_cf(family, key, value),
                WriteOp::Delete { key, .. } => batch.delete_cf(family, key),
            }
        }
        let encoded_write_batch_bytes = batch.size_in_bytes();
        // Preserve the pinned native WriteOptions::default() exactly: sync is
        // false and WAL is enabled. In particular do not add flush/sync calls.
        self.db
            .write_opt(batch, &WriteOptions::default())
            .map_err(|source| Error::Backend {
                operation: "write_batch",
                source,
            })?;
        Ok(WriteReceipt {
            completed: Persistence::Written,
            operations: operations.len(),
            encoded_write_batch_bytes,
        })
    }

    /// Default native read options, starting at the first key. Each step owns
    /// only the current key/value pair; whole-family collection is core policy.
    pub fn scan(&self, column_family: &str) -> Result<Scan<'_>, Error> {
        let mut inner = self.db.raw_iterator_cf(self.family(column_family)?);
        inner.seek_to_first();
        Ok(Scan {
            inner,
            advance: false,
            done: false,
        })
    }

    /// Optional diagnostics; this method creates no periodic worker and makes
    /// no claim that one property accounts for all background CPU, memory or IO.
    pub fn property_int_value(
        &self,
        column_family: &str,
        property: &str,
    ) -> Result<Option<u64>, Error> {
        self.db
            .property_int_value_cf(self.family(column_family)?, property)
            .map_err(|source| Error::Backend {
                operation: "property_int_value",
                source,
            })
    }
}

pub struct Scan<'a> {
    inner: DBRawIteratorWithThreadMode<'a, DB>,
    advance: bool,
    done: bool,
}

impl Iterator for Scan<'_> {
    type Item = Result<(Box<[u8]>, Box<[u8]>), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        // Native SchemaIterator advances on the next call, after the consumer
        // has processed the previous row. Do not eagerly perform the next IO.
        if self.advance {
            self.inner.next();
        }
        self.advance = true;
        if let Some((key, value)) = self.inner.item() {
            Some(Ok((Box::from(key), Box::from(value))))
        } else {
            // Never advance an invalid native iterator. Deliver any terminal
            // native error, preserving its source, before ending the scan.
            self.done = true;
            self.inner.status().err().map(|source| {
                Err(Error::Backend {
                    operation: "scan",
                    source,
                })
            })
        }
    }
}

fn compression_options() -> Options {
    let mut options = Options::default();
    options.set_compression_type(DBCompressionType::Lz4);
    options
}

fn database_options() -> Options {
    let profile = REQUESTED_OPTIONS;
    let mut options = Options::default();
    options.create_if_missing(profile.create_if_missing);
    options.create_missing_column_families(profile.create_missing_column_families);
    options.set_enable_blob_files(profile.blob_files);
    options.set_min_blob_size(profile.min_blob_bytes);
    options.set_blob_file_size(profile.blob_file_bytes);
    options.set_write_buffer_size(profile.db_write_buffer_bytes);
    options.increase_parallelism(profile.parallelism);
    options.set_max_background_jobs(profile.max_background_jobs);
    options.set_enable_write_thread_adaptive_yield(profile.adaptive_write_thread_yield);
    options.set_allow_concurrent_memtable_write(profile.concurrent_memtable_write);
    options.set_enable_pipelined_write(profile.pipelined_write);
    options
}
