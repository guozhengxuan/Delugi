// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

//! Generic copy of the pinned deadline-map mechanism. Equal keys overwrite;
//! a cancelled tick does not remove a pending event.
use std::{collections::BTreeMap, time::Duration};
use tokio::time::{sleep_until, Instant};

pub struct Timer<E> {
    deadlines: BTreeMap<Instant, E>,
}
impl<E> Default for Timer<E> {
    fn default() -> Self {
        Self::new()
    }
}
impl<E> Timer<E> {
    pub fn new() -> Self {
        Self {
            deadlines: BTreeMap::new(),
        }
    }
    pub fn schedule(&mut self, duration: Duration, event: E) {
        self.schedule_at(Instant::now() + duration, event);
    }
    pub fn schedule_at(&mut self, deadline: Instant, event: E) {
        self.deadlines.insert(deadline, event);
    }
    pub fn len(&self) -> usize {
        self.deadlines.len()
    }
    pub fn is_empty(&self) -> bool {
        self.deadlines.is_empty()
    }
    pub async fn tick(&mut self) -> E {
        let next_deadline = self.deadlines.iter().next().map(|(deadline, _)| *deadline);
        match next_deadline {
            Some(deadline) => {
                sleep_until(deadline).await;
                self.deadlines.remove_entry(&deadline).unwrap().1
            }
            None => std::future::pending().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only pinned mechanism oracle. Scheduling keys are supplied identically
    // to compare exact ties and cancellation without relying on host timing jitter.
    struct NativeOracle<E> {
        deadlines: BTreeMap<Instant, E>,
    }
    impl<E> NativeOracle<E> {
        async fn tick(&mut self) -> E {
            let next_deadline = self.deadlines.iter().next().map(|(deadline, _)| *deadline);
            match next_deadline {
                Some(next_deadline) => {
                    sleep_until(next_deadline).await;
                    let (_, event) = self.deadlines.remove_entry(&next_deadline).unwrap();
                    event
                }
                None => {
                    std::future::pending::<()>().await;
                    unreachable!()
                }
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn pinned_order_exact_tie_overwrite_and_cancelled_tick_conform() {
        let base = Instant::now();
        let mut actual = Timer::new();
        let mut oracle = NativeOracle {
            deadlines: BTreeMap::new(),
        };
        for (ms, event) in [(30, 1), (10, 2), (20, 3), (10, 4), (0, 5)] {
            let at = base + Duration::from_millis(ms);
            actual.schedule_at(at, event);
            oracle.deadlines.insert(at, event);
        }
        assert_eq!(actual.tick().await, oracle.tick().await);
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(1), actual.tick())
                    .await
                    .is_err()
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(1), oracle.tick())
                    .await
                    .is_err()
            );
        }
        for expected in [4, 3, 1] {
            assert_eq!(actual.tick().await, expected);
            assert_eq!(oracle.tick().await, expected);
        }
        assert!(actual.is_empty());
        assert!(tokio::time::timeout(Duration::from_secs(1), actual.tick())
            .await
            .is_err());
        assert!(tokio::time::timeout(Duration::from_secs(1), oracle.tick())
            .await
            .is_err());
        actual.schedule(Duration::ZERO, 9);
        assert_eq!(actual.tick().await, 9);
    }
}
