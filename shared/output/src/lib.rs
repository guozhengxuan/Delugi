//! Ordered publication machinery with no protocol identities, crypto, payload
//! validation, deduplication, clocks, or consensus state.

use std::collections::{BTreeMap, VecDeque};

/// Queue order is supplied by the core, never derived from payload arrival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedQueue<T>(VecDeque<T>);

impl<T> Default for OrderedQueue<T> {
    fn default() -> Self {
        Self(VecDeque::new())
    }
}

impl<T> OrderedQueue<T> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_back(&mut self, item: T) {
        self.0.push_back(item);
    }
    pub fn front(&self) -> Option<&T> {
        self.0.front()
    }
    pub fn pop_front(&mut self) -> Option<T> {
        self.0.pop_front()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.0.iter()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolutionError {
    Capacity,
    DuplicateKey,
    UnknownKey,
    AlreadyResolved,
}

/// A bounded set of pending operations in caller-provided order. Resolution may
/// arrive in any order; a resolved tail cannot bypass an unresolved head.
/// Keys are unique while pending. Lifetime-wide replay/idempotence belongs to
/// the caller, as does payload byte budgeting and semantic validation.
pub struct ResolutionQueue<K, V> {
    order: OrderedQueue<K>,
    pending: BTreeMap<K, Option<V>>,
    capacity: usize,
    resolved: usize,
}

impl<K: Ord + Clone, V> ResolutionQueue<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self {
            order: OrderedQueue::new(),
            pending: BTreeMap::new(),
            capacity,
            resolved: 0,
        }
    }

    pub fn reserve(&mut self, key: K) -> Result<(), ResolutionError> {
        if self.pending.contains_key(&key) {
            return Err(ResolutionError::DuplicateKey);
        }
        if self.pending.len() >= self.capacity {
            return Err(ResolutionError::Capacity);
        }
        self.order.push_back(key.clone());
        self.pending.insert(key, None);
        Ok(())
    }

    pub fn resolve(&mut self, key: &K, value: V) -> Result<(), ResolutionError> {
        let entry = self
            .pending
            .get_mut(key)
            .ok_or(ResolutionError::UnknownKey)?;
        if entry.is_some() {
            return Err(ResolutionError::AlreadyResolved);
        }
        *entry = Some(value);
        self.resolved += 1;
        Ok(())
    }

    pub fn is_resolved(&self, key: &K) -> Option<bool> {
        self.pending.get(key).map(Option::is_some)
    }

    pub fn front(&self) -> Option<(&K, Option<&V>)> {
        let key = self.order.front()?;
        Some((
            key,
            self.pending.get(key).expect("queue invariant").as_ref(),
        ))
    }

    pub fn pop_ready(&mut self) -> Option<(K, V)> {
        let (key, value) = self.front()?;
        value?;
        let key = key.clone();
        self.order.pop_front();
        let value = self
            .pending
            .remove(&key)
            .expect("queue invariant")
            .expect("ready head");
        self.resolved -= 1;
        Some((key, value))
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub fn resolved_len(&self) -> usize {
        self.resolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_order_and_duplicates_belong_to_the_caller() {
        let mut queue = OrderedQueue::new();
        queue.push_back((9, "same"));
        queue.push_back((2, "same"));
        assert_eq!(queue.front(), Some(&(9, "same")));
        assert_eq!(queue.pop_front(), Some((9, "same")));
        assert_eq!(queue.pop_front(), Some((2, "same")));
        assert!(queue.is_empty());
    }

    #[test]
    fn reverse_resolution_cannot_pass_an_unresolved_head() {
        let mut queue = ResolutionQueue::new(3);
        for key in [5, 2, 9] {
            queue.reserve(key).unwrap();
        }
        queue.resolve(&9, "third").unwrap();
        queue.resolve(&2, "second").unwrap();
        assert_eq!(queue.front(), Some((&5, None)));
        assert_eq!(queue.pop_ready(), None);
        assert_eq!(queue.resolved_len(), 2);
        queue.resolve(&5, "first").unwrap();
        assert_eq!(queue.pop_ready(), Some((5, "first")));
        assert_eq!(queue.pop_ready(), Some((2, "second")));
        assert_eq!(queue.pop_ready(), Some((9, "third")));
        assert_eq!(queue.resolved_len(), 0);
        assert!(queue.is_empty());
    }

    #[test]
    fn capacity_and_duplicate_resolution_preserve_existing_contents() {
        let mut queue = ResolutionQueue::new(1);
        queue.reserve(7).unwrap();
        assert_eq!(queue.reserve(7), Err(ResolutionError::DuplicateKey));
        assert_eq!(queue.reserve(8), Err(ResolutionError::Capacity));
        assert_eq!(queue.resolve(&8, 8), Err(ResolutionError::UnknownKey));
        queue.resolve(&7, 11).unwrap();
        assert_eq!(queue.resolve(&7, 12), Err(ResolutionError::AlreadyResolved));
        assert_eq!(queue.pop_ready(), Some((7, 11)));
        queue.reserve(8).unwrap(); // a released capacity slot can be reused
    }
}
