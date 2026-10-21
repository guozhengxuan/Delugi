//! Independent timed ingress with a bounded queue. The caller constructs work,
//! authenticates its manifest and records admission atomically with publication.
//! Batch cuts, availability and retransmission remain protocol policy.
use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
