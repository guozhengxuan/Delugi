//! Independent timed ingress with a bounded queue. The caller constructs work,
//! authenticates its manifest and records admission atomically with publication.
//! Batch cuts, availability and retransmission remain protocol policy.
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// A share of one global open-loop arrival stream. `rank` is the position in
/// the explicit honest-origin list, not a replica id or a consensus round.
/// Integer division happens after distributing global sequence numbers, so
/// adding origins cannot multiply or truncate the configured total rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RatePlan {
    rate: u64,
    origins: u64,
    rank: u64,
    start_us: u64,
    count: u64,
}

impl RatePlan {
    pub fn new(rate: u64, duration_us: u64, origins: u64, rank: u64, start_us: u64)
        -> Result<Self, &'static str>
    {
        if origins == 0 || rank >= origins { return Err("invalid origin allocation"); }
        start_us.checked_add(duration_us).ok_or("arrival window overflow")?;
        let total = (rate as u128) * (duration_us as u128) / 1_000_000;
        let total = u64::try_from(total).map_err(|_| "arrival population overflow")?;
        let count = if total <= rank { 0 } else { 1 + (total - 1 - rank) / origins };
        Ok(Self { rate, origins, rank, start_us, count })
    }

    pub fn count(&self) -> u64 { self.count }

    pub fn planned_us(&self, sequence: u64) -> Option<u64> {
        if sequence >= self.count { return None; }
        let global = (sequence as u128) * (self.origins as u128) + self.rank as u128;
        let offset = global * 1_000_000 / self.rate as u128;
        self.start_us.checked_add(u64::try_from(offset).ok()?)
    }
}

pub struct Worker {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Worker {
    /// `offer` runs once per scheduled arrival, independently of the consumer.
    /// It must use nonblocking publication and account for a full/disconnected
    /// queue. No shared service translates queue pressure into availability.
    pub fn start<T: Send + 'static>(
        capacity: usize,
        count: u64,
        clock: Instant,
        schedule: impl Fn(u64) -> u64 + Send + 'static,
        mut offer: impl FnMut(u64, &mpsc::SyncSender<T>) + Send + 'static,
    ) -> (Self, mpsc::Receiver<T>, Arc<AtomicBool>) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let finished = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let done = finished.clone();
        let cancelled = stop.clone();
        let worker = thread::spawn(move || {
            for sequence in 0..count {
                let intended = schedule(sequence);
                loop {
                    if cancelled.load(Ordering::Relaxed) {
                        done.store(true, Ordering::Release);
                        return;
                    }
                    let now = clock.elapsed().as_micros() as u64;
                    if now >= intended { break; }
                    thread::sleep(Duration::from_micros((intended - now).min(1000)));
                }
                offer(sequence, &sender);
            }
            done.store(true, Ordering::Release);
        });
        (Self { stop, worker: Some(worker) }, receiver, finished)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

impl Drop for Worker { fn drop(&mut self) { self.stop(); } }

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    #[test]
    fn total_rate_is_conserved_across_non_dividing_honest_populations() {
        // Includes n=50 with one unavailable ingress and deliberately awkward
        // rates. Per-origin ceil/floor scheduling would change these totals.
        for origins in [3, 4, 9, 10, 34, 49, 50] {
            for rate in [0, 1, 97, 1_001, 4_000] {
                let mut arrivals = Vec::new();
                for rank in 0..origins {
                    let plan = RatePlan::new(rate, 1_000_000, origins, rank, 17).unwrap();
                    for sequence in 0..plan.count() {
                        arrivals.push(plan.planned_us(sequence).unwrap());
                    }
                    assert_eq!(plan.planned_us(plan.count()), None);
                }
                arrivals.sort_unstable();
                assert_eq!(arrivals.len() as u64, rate);
                assert_eq!(arrivals, (0..rate).map(|i| 17 + i * 1_000_000 / rate).collect::<Vec<_>>());
            }
        }
    }
    #[test]
    fn rate_plan_rejects_invalid_populations_and_overflow() {
        assert!(RatePlan::new(1, 1, 0, 0, 0).is_err());
        assert!(RatePlan::new(1, 1, 1, 1, 0).is_err());
        assert!(RatePlan::new(1, 1, 1, 0, u64::MAX).is_err());
        assert!(RatePlan::new(u64::MAX, u64::MAX, 1, 0, 0).is_err());
        let empty = RatePlan::new(0, 60_000_000, 50, 49, 0).unwrap();
        assert_eq!(empty.count(), 0);
        assert_eq!(empty.planned_us(0), None);
    }
    #[test]
    fn full_queue_does_not_pace_independent_arrivals() {
        let rejected = Arc::new(AtomicU64::new(0));
        let count = rejected.clone();
        let (mut worker, rx, done) = Worker::start(1, 100, Instant::now(), |_| 0,
            move |seq, tx| { if tx.try_send(seq).is_err() { count.fetch_add(1, Ordering::Relaxed); } });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done.load(Ordering::Acquire) && Instant::now() < deadline { thread::yield_now(); }
        assert!(done.load(Ordering::Acquire));
        worker.stop();
        assert_eq!(rx.try_recv(), Ok(0));
        assert_eq!(rejected.load(Ordering::Relaxed), 99);
    }
    #[test]
    fn cancellation_joins_a_future_scheduled_worker() {
        let (mut worker, rx, done) = Worker::start(1, 1, Instant::now(), |_| 10_000_000,
            |seq, tx| { tx.try_send(seq).unwrap(); });
        worker.stop();
        assert!(done.load(Ordering::Acquire));
        assert!(rx.try_recv().is_err());
    }
}
