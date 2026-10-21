//! Common control mailbox, idle wait and coalescing deadline queue. A core owns
//! actor turns, timer arming conditions and handler/condition atomicity.
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc, Arc};
use std::thread;
use std::time::Duration;

pub trait ControlCommand: DeserializeOwned + Send + 'static {
    fn token(&self) -> &str;
}

pub struct Request<C> {
    pub command: C,
    pub reply: mpsc::SyncSender<Value>,
}
#[derive(Default)]
struct ControlStats {
    received: AtomicU64,
    sent: AtomicU64,
    rejected: AtomicU64,
}
pub struct Control<C: ControlCommand> {
    pub requests: mpsc::Receiver<Request<C>>,
    stop: Arc<AtomicBool>,
    stats: Arc<ControlStats>,
    handle: Option<thread::JoinHandle<()>>,
}
impl<C: ControlCommand> Control<C> {
    pub fn bind(address: SocketAddr, token: String) -> Result<Self, String> {
        let listener =
            TcpListener::bind(address).map_err(|e| format!("control bind {address}: {e}"))?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(ControlStats::default());
        let (sender, requests) = mpsc::sync_channel(64);
        let flag = stop.clone();
        let metrics = stats.clone();
        let handle = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        // macOS can inherit O_NONBLOCK from this nonblocking
                        // listener. Timeout-based line reads require blocking I/O.
                        if socket.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let _ = socket.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = socket.set_write_timeout(Some(Duration::from_secs(2)));
                        let mut bytes = Vec::new();
                        let read = BufReader::new(&mut socket)
                            .take(65_537)
                            .read_until(b'\n', &mut bytes);
                        metrics
                            .received
                            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        let parsed = if read.is_ok()
                            && bytes.len() <= 65_536
                            && bytes.last() == Some(&b'\n')
                        {
                            serde_json::from_slice::<C>(&bytes)
                                .map_err(|e| format!("invalid control JSON: {e}"))
                        } else {
                            Err(format!(
                                "incomplete or oversized control frame: {} bytes, read result {:?}",
                                bytes.len(),
                                read
                            ))
                        };
                        let answer = match parsed {
                            Ok(command) if command.token() == token => {
                                let (tx, rx) = mpsc::sync_channel(1);
                                match sender.try_send(Request{command,reply:tx}) {
                                    Ok(())=>rx.recv_timeout(Duration::from_secs(5)).unwrap_or_else(|_|json!({"ok":false,"error":"control handler timeout"})),
                                    Err(_)=>json!({"ok":false,"error":"control queue full"}),
                                }
                            }
                            Ok(_) => {
                                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                json!({"ok":false,"error":"unauthorized control request"})
                            }
                            Err(error) => {
                                metrics.rejected.fetch_add(1, Ordering::Relaxed);
                                json!({"ok":false,"error":error})
                            }
                        };
                        if let Ok(mut encoded) = serde_json::to_vec(&answer) {
                            encoded.push(b'\n');
                            if socket.write_all(&encoded).is_ok() {
                                metrics
                                    .sent
                                    .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            requests,
            stop,
            stats,
            handle: Some(handle),
        })
    }
    pub fn snapshot(&self) -> Value {
        json!({"received_bytes":self.stats.received.load(Ordering::Relaxed),
        "sent_bytes":self.stats.sent.load(Ordering::Relaxed),"rejected_requests":self.stats.rejected.load(Ordering::Relaxed)})
    }
}
impl<C: ControlCommand> Drop for Control<C> {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Wake an eligible idle loop on transport arrival, without dispatching until
/// the next turn's control check. A disconnected inbox must not busy-spin.
pub fn idle_receive<T>(
    eligible: bool,
    receive: impl FnOnce(Duration) -> Result<T, mpsc::RecvTimeoutError>,
    sleep: impl FnOnce(Duration),
) -> Option<T> {
    let timeout = Duration::from_millis(1);
    if eligible {
        match receive(timeout) {
            Ok(message) => return Some(message),
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => {}
        }
    }
    sleep(timeout);
    None
}


/// Equal deadlines intentionally coalesce, matching the Delugi actor profile.
/// Adapters needing separate per-operation firings must use a different profile.
#[derive(Default)]
pub struct TimerQueue(BTreeSet<u64>);
impl TimerQueue {
    pub fn new() -> Self { Self::default() }
    pub fn insert(&mut self, at: u64) -> bool { self.0.insert(at) }
    pub fn first(&self) -> Option<&u64> { self.0.first() }
    pub fn pop_first(&mut self) -> Option<u64> { self.0.pop_first() }
    pub fn len(&self) -> usize { self.0.len() }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}
