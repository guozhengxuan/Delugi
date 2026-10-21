#![cfg(feature = "rocksdb-backend")]
use shared_store_rocksdb::{Error, Persistence, RocksStore, WriteOp};
use std::error::Error as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "shared-rocksdb-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("db")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn raw_bytes_atomic_deletes_and_nonce_survive_reopen() {
    let directory = Directory::new();
    let digest = [0xff; 32];
    let epoch = 7u64.to_le_bytes();
    let nonce = [9u64.to_le_bytes(), 11u64.to_le_bytes()].concat();
    {
        let store = RocksStore::open(directory.database(), &["payload", "nonce"]).unwrap();
        let receipt = store
            .write_batch(
                &[
                    WriteOp::Put {
                        column_family: "payload",
                        key: &digest,
                        value: b"\0raw\xff",
                    },
                    WriteOp::Put {
                        column_family: "nonce",
                        key: &epoch,
                        value: &nonce,
                    },
                    WriteOp::Put {
                        column_family: "payload",
                        key: b"remove",
                        value: b"old",
                    },
                ],
                Persistence::Written,
            )
            .unwrap();
        assert_eq!(receipt.completed, Persistence::Written);
        assert_eq!(receipt.operations, 3);
        assert!(receipt.encoded_write_batch_bytes > digest.len() + nonce.len());
        store
            .delete("payload", b"remove", Persistence::Written)
            .unwrap();
    }
    let store = RocksStore::open(directory.database(), &["payload", "nonce"]).unwrap();
    assert_eq!(
        store.get("payload", &digest).unwrap(),
        Some(b"\0raw\xff".to_vec())
    );
    assert_eq!(store.get("nonce", &epoch).unwrap(), Some(nonce));
    assert_eq!(store.get("payload", b"remove").unwrap(), None);
    let rows = store
        .scan("payload")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0.as_ref(), digest);
}

#[test]
fn unsupported_barrier_or_unknown_family_cannot_partially_mutate() {
    let directory = Directory::new();
    let store = RocksStore::open(directory.database(), &["data"]).unwrap();
    store
        .put("data", b"key", b"original", Persistence::Written)
        .unwrap();
    assert!(matches!(
        store.put("data", b"key", b"wrong", Persistence::Durable),
        Err(Error::UnsupportedPersistence(_))
    ));
    assert!(matches!(
        store.delete("data", b"key", Persistence::Durable),
        Err(Error::UnsupportedPersistence(_))
    ));
    let operations = [
        WriteOp::Put {
            column_family: "data",
            key: b"key",
            value: b"wrong",
        },
        WriteOp::Delete {
            column_family: "missing",
            key: b"key",
        },
    ];
    assert!(matches!(
        store.write_batch(&operations, Persistence::Written),
        Err(Error::UnknownColumnFamily(_))
    ));
    assert_eq!(
        store.get("data", b"key").unwrap(),
        Some(b"original".to_vec())
    );
}

#[test]
fn existing_unrequested_families_are_preserved_and_default_is_reopenable() {
    let directory = Directory::new();
    {
        let store = RocksStore::open(directory.database(), &["data", "old"]).unwrap();
        store
            .put("old", b"kept", b"value", Persistence::Written)
            .unwrap();
        store
            .put(
                "default",
                b"default-key",
                b"default-value",
                Persistence::Written,
            )
            .unwrap();
    }
    let store = RocksStore::open(directory.database(), &["data"]).unwrap();
    assert_eq!(store.get("old", b"kept").unwrap(), Some(b"value".to_vec()));
    assert_eq!(
        store.get("default", b"default-key").unwrap(),
        Some(b"default-value".to_vec())
    );
}

#[test]
fn scan_is_byte_ordered_and_write_batch_retains_operation_order() {
    let directory = Directory::new();
    let store = RocksStore::open(directory.database(), &["data"]).unwrap();
    store
        .write_batch(
            &[
                WriteOp::Put {
                    column_family: "data",
                    key: b"z",
                    value: b"first",
                },
                WriteOp::Put {
                    column_family: "data",
                    key: b"a",
                    value: b"kept",
                },
                WriteOp::Delete {
                    column_family: "data",
                    key: b"z",
                },
                WriteOp::Put {
                    column_family: "data",
                    key: b"z",
                    value: b"last",
                },
            ],
            Persistence::Written,
        )
        .unwrap();
    let rows = store
        .scan("data")
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows.iter().map(|(k, _)| k.as_ref()).collect::<Vec<_>>(),
        vec![b"a".as_slice(), b"z".as_slice()]
    );
    assert_eq!(rows[1].1.as_ref(), b"last");
}

#[test]
fn backend_errors_keep_native_source_and_never_fall_back() {
    let directory = Directory::new();
    std::fs::write(directory.database(), b"not a database directory").unwrap();
    let result = RocksStore::open(directory.database(), &["data"]);
    let error = match result {
        Ok(_) => panic!("invalid database path unexpectedly opened"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Error::Backend {
            operation: "open",
            ..
        }
    ));
    assert!(error.source().is_some());
    assert_eq!(
        std::fs::read(directory.database()).unwrap(),
        b"not a database directory"
    );
}
