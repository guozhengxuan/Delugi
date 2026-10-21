// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0
//! Native typed Quorum Store schema over the shared Written RocksDB service.
//! Keys/values, per-epoch cleanup and atomic deletion retain upstream encoding.
use crate::{error::DbError, quorum_store::types::PersistedValue};
use anyhow::Result;
use aptos_consensus_types::proof_of_store::BatchId;
use aptos_crypto::HashValue;
use std::collections::HashMap;

pub trait QuorumStoreStorage: Sync + Send {
    fn delete_batches(&self, digests: Vec<HashValue>) -> Result<(), DbError>;
    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue>>;
    fn save_batch(&self, batch: PersistedValue) -> Result<(), DbError>;
    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue>, DbError>;
    fn delete_batch_id(&self, epoch: u64) -> Result<(), DbError>;
    fn clean_and_get_batch_id(&self, current_epoch: u64) -> Result<Option<BatchId>, DbError>;
    fn save_batch_id(&self, epoch: u64, batch_id: BatchId) -> Result<(), DbError>;
}

pub const QUORUM_STORE_DB_NAME: &str = "quorumstoreDB";
pub const BATCH_CF_NAME: &str = "batch";
pub const BATCH_ID_CF_NAME: &str = "batch_ID";

#[cfg(feature = "rocksdb-backend")]
pub struct QuorumStoreDB {
    db: shared_store_rocksdb::RocksStore,
}

#[cfg(feature = "rocksdb-backend")]
impl QuorumStoreDB {
    pub fn open(root: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            db: shared_store_rocksdb::RocksStore::open(
                root.as_ref().join(QUORUM_STORE_DB_NAME),
                &[BATCH_CF_NAME, BATCH_ID_CF_NAME],
            )?,
        })
    }
    pub fn capabilities(&self) -> shared_store_rocksdb::StorageCapabilities {
        shared_store_rocksdb::CAPABILITIES
    }
}

#[cfg(feature = "rocksdb-backend")]
impl QuorumStoreStorage for QuorumStoreDB {
    fn delete_batches(&self, digests: Vec<HashValue>) -> Result<(), DbError> {
        let ops: Vec<_> = digests
            .iter()
            .map(|d| shared_store_rocksdb::WriteOp::Delete {
                column_family: BATCH_CF_NAME,
                key: d.as_ref(),
            })
            .collect();
        self.db
            .write_batch(&ops, shared_store_rocksdb::Persistence::Written)
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
    fn get_all_batches(&self) -> Result<HashMap<HashValue, PersistedValue>> {
        self.db
            .scan(BATCH_CF_NAME)?
            .map(|row| {
                let (key, value) = row?;
                Ok((HashValue::from_slice(&key)?, bcs::from_bytes(&value)?))
            })
            .collect()
    }
    fn save_batch(&self, batch: PersistedValue) -> Result<(), DbError> {
        let bytes = bcs::to_bytes(&batch).map_err(anyhow::Error::from)?;
        self.db
            .put(
                BATCH_CF_NAME,
                batch.digest().as_ref(),
                &bytes,
                shared_store_rocksdb::Persistence::Written,
            )
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
    fn get_batch(&self, digest: &HashValue) -> Result<Option<PersistedValue>, DbError> {
        self.db
            .get(BATCH_CF_NAME, digest.as_ref())
            .map_err(anyhow::Error::from)?
            .map(|v| {
                bcs::from_bytes(&v)
                    .map_err(anyhow::Error::from)
                    .map_err(Into::into)
            })
            .transpose()
    }
    fn delete_batch_id(&self, epoch: u64) -> Result<(), DbError> {
        let key = bcs::to_bytes(&epoch).map_err(anyhow::Error::from)?;
        self.db
            .delete(
                BATCH_ID_CF_NAME,
                &key,
                shared_store_rocksdb::Persistence::Written,
            )
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
    fn clean_and_get_batch_id(&self, current_epoch: u64) -> Result<Option<BatchId>, DbError> {
        // The native algorithm collects before deleting, asserts against future
        // epochs, and removes each old epoch separately. Preserve that behavior.
        let rows: HashMap<u64, BatchId> = self
            .db
            .scan(BATCH_ID_CF_NAME)
            .map_err(anyhow::Error::from)?
            .map(|r| {
                let (key, value) = r?;
                Ok((bcs::from_bytes(&key)?, bcs::from_bytes(&value)?))
            })
            .collect::<Result<_>>()?;
        let mut ret = None;
        for (epoch, batch_id) in rows {
            assert!(current_epoch >= epoch);
            if epoch < current_epoch {
                self.delete_batch_id(epoch)?;
            } else {
                ret = Some(batch_id);
            }
        }
        Ok(ret)
    }
    fn save_batch_id(&self, epoch: u64, batch_id: BatchId) -> Result<(), DbError> {
        let key = bcs::to_bytes(&epoch).map_err(anyhow::Error::from)?;
        let value = bcs::to_bytes(&batch_id).map_err(anyhow::Error::from)?;
        self.db
            .put(
                BATCH_ID_CF_NAME,
                &key,
                &value,
                shared_store_rocksdb::Persistence::Written,
            )
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}

#[cfg(all(test, feature = "rocksdb-backend"))]
mod tests {
    use super::*;
    use crate::quorum_store::types::Batch;
    struct OwnedDir(std::path::PathBuf);
    impl OwnedDir {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "delugi-raptr-qs-schema-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for OwnedDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn native_bcs_keys_values_reopen_and_epoch_cleanup() {
        let dir = OwnedDir::new();
        let author = aptos_types::PeerId::from_hex_literal("0x1").unwrap();
        let value: PersistedValue =
            Batch::new(BatchId::new_for_test(7), vec![], 4, 1000, author, 0).into();
        let digest = *value.digest();
        {
            let db = QuorumStoreDB::open(&dir.0).unwrap();
            db.save_batch(value.clone()).unwrap();
            assert_eq!(
                db.db.get(BATCH_CF_NAME, digest.as_ref()).unwrap().unwrap(),
                bcs::to_bytes(&value).unwrap()
            );
            db.save_batch_id(3, BatchId::new_for_test(2)).unwrap();
            db.save_batch_id(4, BatchId::new_for_test(7)).unwrap();
            assert_eq!(
                db.db
                    .get(BATCH_ID_CF_NAME, &4_u64.to_le_bytes())
                    .unwrap()
                    .unwrap(),
                bcs::to_bytes(&BatchId::new_for_test(7)).unwrap()
            );
        }
        let db = QuorumStoreDB::open(&dir.0).unwrap();
        assert_eq!(db.get_batch(&digest).unwrap(), Some(value.clone()));
        assert_eq!(db.get_all_batches().unwrap().get(&digest), Some(&value));
        assert_eq!(
            db.clean_and_get_batch_id(4).unwrap(),
            Some(BatchId::new_for_test(7))
        );
        assert!(db
            .db
            .get(BATCH_ID_CF_NAME, &3_u64.to_le_bytes())
            .unwrap()
            .is_none());
        db.delete_batches(vec![digest]).unwrap();
        assert!(db.get_batch(&digest).unwrap().is_none());
    }
}
