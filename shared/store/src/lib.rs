//! Process-local typed storage. Keys, identity checks, verification, custody and
//! retention are core policy. This backend promises visibility, never durability.
use std::collections::BTreeMap;
use std::ops::Index;
pub use core_api::{Persistence, StorageCapabilities, UnsupportedPersistence};

pub const MEMORY_CAPABILITIES: StorageCapabilities = StorageCapabilities {
    maximum_completion: Persistence::Visible,
    crash_recovery: false,
    fault_model: "process-local memory; process exit loses all records",
};

#[derive(Clone, Debug)]
pub struct MemoryStore<K, V> {
    values: BTreeMap<K, V>,
}

impl<K: Ord, V> Default for MemoryStore<K, V> {
    fn default() -> Self { Self::new() }
}

impl<K: Ord, V> MemoryStore<K, V> {
    pub fn new() -> Self { Self { values: BTreeMap::new() } }
    pub fn capabilities(&self) -> StorageCapabilities { MEMORY_CAPABILITIES }
    pub fn len(&self) -> usize { self.values.len() }
    pub fn is_empty(&self) -> bool { self.values.is_empty() }
    pub fn contains_key(&self, key: &K) -> bool { self.values.contains_key(key) }
    pub fn get(&self, key: &K) -> Option<&V> { self.values.get(key) }
    /// Unsupported barriers fail before mutation. Accepted requests return only
    /// after the stronger Visible barrier, with process-local read-your-writes.
    pub fn put(&mut self, key: K, value: V, required: Persistence)
        -> Result<Option<V>, UnsupportedPersistence>
    {
        MEMORY_CAPABILITIES.require(required)?;
        Ok(self.values.insert(key, value))
    }
    pub fn remove(&mut self, key: &K) -> Option<V> { self.values.remove(key) }
}

impl<K: Ord, V> Index<&K> for MemoryStore<K, V> {
    type Output = V;
    fn index(&self, key: &K) -> &V { &self.values[key] }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unsupported_barriers_do_not_replace_visible_data() {
        let mut store = MemoryStore::new();
        assert_eq!(store.put("batch", vec![1], Persistence::Visible), Ok(None));
        for barrier in [Persistence::Written, Persistence::Durable] {
            assert!(store.put("batch", vec![2], barrier).is_err());
            assert_eq!(store.get(&"batch"), Some(&vec![1]));
        }
        assert!(!store.capabilities().crash_recovery);
    }
}
