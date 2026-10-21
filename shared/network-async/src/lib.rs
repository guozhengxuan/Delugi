//! Async mailbox facade over the same bounded TCP service used by synchronous
//! actors. Sending completes on enqueue/defer, never on a peer receipt. Protocol
//! codecs, verifiers, actor order, timers and channel dispatch remain with callers.
use shared_network::{
    Accounting, Authentication, Id, Received, SendReceipt, Transport, TransportSnapshot,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub inbox_frames: usize,
    pub inbox_bytes: usize,
    pub poll_interval: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            inbox_frames: 4096,
            inbox_bytes: 32 * 1024 * 1024,
            poll_interval: Duration::from_millis(1),
        }
    }
}

/// The payload remains charged through decoding/verification until this object
/// is dropped. Keep it alive across any asynchronous verification operation.
#[derive(Debug)]
pub struct ReceivedBytes<C> {
    pub frame: Received<C>,
    _lease: OwnedSemaphorePermit,
}

struct Status {
    stopped: AtomicBool,
    error: Mutex<Option<String>>,
    changed: Notify,
    inbound_frames: AtomicU64,
    self_frames: AtomicU64,
    pending_bytes: AtomicU64,
    maximum_pending_bytes: AtomicU64,
    maximum_leased_bytes: AtomicU64,
}

impl Status {
    fn stop(&self, error: Option<String>) {
        if let Some(error) = error {
            let mut slot = self.error.lock().unwrap();
            if slot.is_none() {
                *slot = Some(error);
            }
        }
        self.stopped.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    fn check(&self) -> Result<(), String> {
        if self.stopped.load(Ordering::Acquire) {
            Err(self
                .error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "transport stopped".into()))
        } else {
            Ok(())
        }
    }
}

struct Inner<P: Authentication> {
    id: Id,
    max_message_bytes: usize,
    limits: Limits,
    transport: Mutex<Transport<P>>,
    incoming: mpsc::Sender<ReceivedBytes<P::Channel>>,
    bytes: Arc<Semaphore>,
    local_sequence: Mutex<u64>,
    status: Arc<Status>,
}

pub struct Sender<P: Authentication> {
    inner: Arc<Inner<P>>,
}
impl<P: Authentication> Clone for Sender<P> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: Authentication> Sender<P> {
    /// No socket write or ACK wait occurs in this future. Exhaustion is an
    /// explicit error: an actor must fail the run or retain/retry the effect.
    pub async fn send(
        &self,
        to: Id,
        channel: P::Channel,
        payload: Vec<u8>,
        accounting: P::Accounting,
    ) -> Result<SendReceipt, String> {
        self.inner.status.check()?;
        if to != self.inner.id {
            return self
                .inner
                .transport
                .lock()
                .map_err(|_| "transport lock poisoned")?
                .send_or_defer_accounted(to, channel, payload, accounting);
        }
        // Self-delivery is an ordered local effect. It incurs no network bytes.
        // Never await its queue from an actor that is also its sole consumer.
        accounting.validate(channel, &payload)?;
        if payload.len() > self.inner.max_message_bytes {
            return Err("self message exceeds declared bound".into());
        }
        let mut sequence = self
            .inner
            .local_sequence
            .lock()
            .map_err(|_| "self sequence lock poisoned")?;
        let next = sequence.checked_add(1).ok_or("self sequence exhausted")?;
        let lease = self
            .inner
            .bytes
            .clone()
            .try_acquire_many_owned(payload.len() as u32)
            .map_err(|_| "async self-delivery byte envelope exhausted")?;
        self.inner.record_leased();
        let frame = Received {
            from: to,
            sequence: next,
            layer: channel,
            payload,
            received_at: Instant::now(),
        };
        self.inner
            .incoming
            .try_send(ReceivedBytes {
                frame,
                _lease: lease,
            })
            .map_err(|_| "async self-delivery frame envelope exhausted or closed")?;
        *sequence = next;
        self.inner
            .status
            .self_frames
            .fetch_add(1, Ordering::Relaxed);
        Ok(SendReceipt {
            sequence: next,
            deferred: false,
        })
    }

    pub fn snapshot(&self) -> Snapshot<P::Channel> {
        self.inner.snapshot()
    }
    pub fn check(&self) -> Result<(), String> {
        self.inner.status.check()
    }
    /// Expose terminal adapter failure to every clone and the receive future.
    pub fn fail(&self, reason: String) {
        self.inner.status.stop(Some(reason));
    }
}

impl<P: Authentication> Inner<P> {
    fn record_leased(&self) {
        let used = self.limits.inbox_bytes - self.bytes.available_permits();
        self.status
            .maximum_leased_bytes
            .fetch_max(used as u64, Ordering::Relaxed);
    }
    fn snapshot(&self) -> Snapshot<P::Channel> {
        Snapshot {
            transport: self.transport.lock().unwrap().snapshot(),
            inbox_frame_limit: self.limits.inbox_frames,
            inbox_byte_limit: self.limits.inbox_bytes,
            leased_bytes: self.limits.inbox_bytes - self.bytes.available_permits(),
            maximum_leased_bytes: self.status.maximum_leased_bytes.load(Ordering::Relaxed),
            pending_bytes: self.status.pending_bytes.load(Ordering::Relaxed),
            maximum_pending_bytes: self.status.maximum_pending_bytes.load(Ordering::Relaxed),
            // One decoded frame can be staged between the service and facade.
            maximum_extra_pending_bytes: self.max_message_bytes,
            inbound_frames: self.status.inbound_frames.load(Ordering::Relaxed),
            self_frames: self.status.self_frames.load(Ordering::Relaxed),
            terminal_error: self.status.error.lock().unwrap().clone(),
        }
    }
}

#[derive(Debug)]
pub struct Snapshot<C: Ord> {
    pub transport: TransportSnapshot<C>,
    pub inbox_frame_limit: usize,
    pub inbox_byte_limit: usize,
    pub leased_bytes: usize,
    pub maximum_leased_bytes: u64,
    pub pending_bytes: u64,
    pub maximum_pending_bytes: u64,
    pub maximum_extra_pending_bytes: usize,
    pub inbound_frames: u64,
    pub self_frames: u64,
    pub terminal_error: Option<String>,
}

pub struct Receiver<C> {
    incoming: mpsc::Receiver<ReceivedBytes<C>>,
    status: Arc<Status>,
}

impl<C> Receiver<C> {
    /// Cancellation safe: a cancelled wait leaves the message in the mailbox.
    pub async fn recv(&mut self) -> Result<ReceivedBytes<C>, String> {
        loop {
            let changed = self.status.changed.notified();
            self.status.check()?;
            tokio::select! {
                item = self.incoming.recv() => return item.ok_or_else(|| "async transport receive mailbox closed".into()),
                _ = changed => {}
            }
        }
    }
}

impl<C> Drop for Receiver<C> {
    fn drop(&mut self) {
        self.status.stop(None);
    }
}

/// Own this guard for the entire node lifetime. Shutdown stops the facade worker
/// before shutting down shared TCP, including all ACK readers and writers.
pub struct Service<P: Authentication> {
    inner: Arc<Inner<P>>,
    worker: Option<JoinHandle<()>>,
}

impl<P: Authentication> Service<P> {
    pub fn start(
        transport: Transport<P>,
        id: Id,
        max_message_bytes: usize,
        limits: Limits,
    ) -> Result<(Self, Sender<P>, Receiver<P::Channel>), String> {
        if transport.local_id() != id
            || transport.max_wire_bytes() != max_message_bytes
            || limits.inbox_frames == 0
            || limits.inbox_bytes < max_message_bytes
            || max_message_bytes == 0
            || limits.inbox_bytes > Semaphore::MAX_PERMITS
            || max_message_bytes > u32::MAX as usize
            || limits.poll_interval.is_zero()
            || limits.poll_interval > Duration::from_millis(100)
        {
            return Err("invalid async transport envelope".into());
        }
        let (incoming, rx) = mpsc::channel(limits.inbox_frames);
        let status = Arc::new(Status {
            stopped: AtomicBool::new(false),
            error: Mutex::new(None),
            changed: Notify::new(),
            inbound_frames: AtomicU64::new(0),
            self_frames: AtomicU64::new(0),
            pending_bytes: AtomicU64::new(0),
            maximum_pending_bytes: AtomicU64::new(0),
            maximum_leased_bytes: AtomicU64::new(0),
        });
        let inner = Arc::new(Inner {
            id,
            max_message_bytes,
            limits,
            transport: Mutex::new(transport),
            incoming,
            bytes: Arc::new(Semaphore::new(limits.inbox_bytes)),
            local_sequence: Mutex::new(0),
            status: status.clone(),
        });
        let work = inner.clone();
        let worker = thread::Builder::new()
            .name("shared-network-async".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pump(&work)));
                match result {
                    Ok(Ok(())) => work.status.stop(None),
                    Ok(Err(error)) => work.status.stop(Some(error)),
                    Err(_) => work
                        .status
                        .stop(Some("async transport worker panicked".into())),
                }
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Self {
                inner: inner.clone(),
                worker: Some(worker),
            },
            Sender { inner },
            Receiver {
                incoming: rx,
                status,
            },
        ))
    }

    pub fn shutdown(&mut self) {
        self.inner.status.stop(None);
        if let Some(worker) = self.worker.take() {
            worker.thread().unpark();
            let _ = worker.join();
        }
        self.inner.transport.lock().unwrap().shutdown();
    }
}

impl<P: Authentication> Drop for Service<P> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn pump<P: Authentication>(inner: &Inner<P>) -> Result<(), String> {
    let mut pending: Option<Received<P::Channel>> = None;
    let mut leased: Option<ReceivedBytes<P::Channel>> = None;
    while !inner.status.stopped.load(Ordering::Acquire) {
        {
            let mut transport = inner
                .transport
                .lock()
                .map_err(|_| "transport lock poisoned")?;
            transport.retry_deferred()?;
            if pending.is_none() && leased.is_none() {
                match transport.try_recv() {
                    Ok(frame) => {
                        if frame.payload.len() > inner.max_message_bytes {
                            return Err("received message exceeds async envelope".into());
                        }
                        inner
                            .status
                            .pending_bytes
                            .store(frame.payload.len() as u64, Ordering::Relaxed);
                        inner
                            .status
                            .maximum_pending_bytes
                            .fetch_max(frame.payload.len() as u64, Ordering::Relaxed);
                        pending = Some(frame);
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        return Err("shared TCP inbox disconnected".into())
                    }
                }
            }
        }
        if let Some(frame) = pending.take() {
            match inner
                .bytes
                .clone()
                .try_acquire_many_owned(frame.payload.len() as u32)
            {
                Ok(lease) => {
                    inner.status.pending_bytes.store(0, Ordering::Relaxed);
                    inner.record_leased();
                    leased = Some(ReceivedBytes {
                        frame,
                        _lease: lease,
                    });
                }
                Err(_) => pending = Some(frame),
            }
        }
        if let Some(item) = leased.take() {
            match inner.incoming.try_send(item) {
                Ok(()) => {
                    inner.status.inbound_frames.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Err(mpsc::error::TrySendError::Full(item)) => leased = Some(item),
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err("async transport mailbox closed".into())
                }
            }
        }
        thread::park_timeout(inner.limits.poll_interval);
    }
    inner.status.pending_bytes.store(0, Ordering::Relaxed);
    Ok(())
}
