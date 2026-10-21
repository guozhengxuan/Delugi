use serde::Serialize;
use std::{
    any::Any,
    collections::BTreeMap,
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Wake, Waker},
};
use tokio::{
    runtime::Handle,
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
};

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Limits {
    pub max_async_tasks: usize,
    pub max_blocking_tasks: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_async_tasks: 100_000,
            max_blocking_tasks: 1024,
        }
    }
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum ExecutorError {
    InvalidLimits,
    Closed,
    GroupLimit,
    Capacity { kind: &'static str, limit: usize },
    Panicked(String),
    Cancelled,
}
impl fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shared async executor: {self:?}")
    }
}
impl std::error::Error for ExecutorError {}
impl ExecutorError {
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Async,
    Blocking,
}
impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::Async => "async",
            Self::Blocking => "blocking",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub limits: Limits,
    pub admitted_async: u64,
    pub admitted_blocking: u64,
    pub started_async: u64,
    pub started_blocking: u64,
    pub body_finished_async: u64,
    pub body_finished_blocking: u64,
    pub joined_async: u64,
    pub joined_blocking: u64,
    pub cancelled_async: u64,
    pub cancelled_blocking: u64,
    pub panicked: u64,
    pub rejected_capacity: u64,
    pub rejected_closed: u64,
    pub retained_async: usize,
    pub retained_blocking: usize,
    pub queued_async: usize,
    pub queued_blocking: usize,
    pub active_async: usize,
    pub active_blocking: usize,
    pub maximum_retained_async: usize,
    pub maximum_retained_blocking: usize,
    pub groups: Vec<GroupSnapshot>,
    pub failure: Option<ExecutorError>,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupSnapshot {
    pub id: u64,
    pub label: String,
    pub closed: bool,
    pub retained: usize,
}
#[derive(Default)]
struct Counts {
    admitted: [u64; 2],
    started: [u64; 2],
    finished: [u64; 2],
    joined: [u64; 2],
    cancelled: [u64; 2],
    panicked: u64,
    capacity: u64,
    closed: u64,
    maximum: [usize; 2],
}
fn slot(kind: Kind) -> usize {
    if kind == Kind::Async {
        0
    } else {
        1
    }
}
struct Entry {
    group: u64,
    kind: Kind,
    started: bool,
    finished: bool,
    handle: JoinHandle<()>,
}
struct Group {
    label: String,
    closed: bool,
}
struct State {
    limits: Limits,
    groups: BTreeMap<u64, Group>,
    entries: BTreeMap<u64, Entry>,
    next_task: u64,
    next_group: u64,
    closed: bool,
    counts: Counts,
    failure: Option<ExecutorError>,
    failure_notified: bool,
}
struct Inner {
    state: Mutex<State>,
    joining: tokio::sync::Mutex<()>,
    runtime: Handle,
    failure: Arc<dyn Fn(ExecutorError) + Send + Sync>,
}
#[derive(Clone)]
pub struct Executor {
    inner: Arc<Inner>,
}
#[derive(Clone)]
pub struct TaskGroup {
    executor: Executor,
    id: u64,
}

/// Dropping this handle preserves the native detached-task behavior. The executor
/// still owns and joins the underlying task. abort() is explicit cancellation.
pub struct Task<T> {
    receive: Option<oneshot::Receiver<Result<T, ExecutorError>>>,
    immediate: Option<ExecutorError>,
    abort: Option<AbortHandle>,
}
impl<T> Unpin for Task<T> {}
impl<T> Task<T> {
    fn error(error: ExecutorError) -> Self {
        Self {
            receive: None,
            immediate: Some(error),
            abort: None,
        }
    }
    pub fn abort(&self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }
    pub fn is_finished(&self) -> bool {
        self.abort.as_ref().map_or(true, AbortHandle::is_finished)
    }
}
impl<T> Future for Task<T> {
    type Output = Result<T, ExecutorError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(error) = this.immediate.take() {
            return Poll::Ready(Err(error));
        }
        match Pin::new(this.receive.as_mut().expect("completed task polled again")).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(value)) => {
                this.receive = None;
                Poll::Ready(value)
            }
            Poll::Ready(Err(_)) => {
                this.receive = None;
                Poll::Ready(Err(ExecutorError::Cancelled))
            }
        }
    }
}
struct NoWake;
impl Wake for NoWake {
    fn wake(self: Arc<Self>) {}
}
fn panic_error(payload: Box<dyn Any + Send>) -> ExecutorError {
    let text = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string task panic");
    ExecutorError::Panicked(text.chars().take(4096).collect())
}
struct Catch<F> {
    inner: Option<Pin<Box<F>>>,
    owner: Arc<Inner>,
}
impl<F> Drop for Catch<F> {
    fn drop(&mut self) {
        // Native future destructors can panic even after Ready or during abort.
        // Preserve the panic as terminal evidence without losing owned handles.
        if let Err(error) = std::panic::catch_unwind(AssertUnwindSafe(|| drop(self.inner.take()))) {
            self.owner.unexpected_panic(panic_error(error));
        }
    }
}
impl<F: Future> Future for Catch<F> {
    type Output = Result<F::Output, ExecutorError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match std::panic::catch_unwind(AssertUnwindSafe(|| {
            self.inner
                .as_mut()
                .expect("live catch future")
                .as_mut()
                .poll(cx)
        })) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Err(error) => Poll::Ready(Err(panic_error(error))),
        }
    }
}
impl State {
    fn count(&self, kind: Kind) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.kind == kind)
            .count()
    }
    fn join_result(&mut self, id: u64, result: Result<(), tokio::task::JoinError>) {
        let entry = self.entries.remove(&id).expect("joined registered task");
        self.counts.joined[slot(entry.kind)] += 1;
        if let Err(error) = result {
            if error.is_cancelled() {
                self.counts.cancelled[slot(entry.kind)] += 1;
            } else {
                self.counts.panicked += 1;
                if self.failure.is_none() {
                    self.failure = Some(ExecutorError::Panicked(error.to_string()));
                }
            }
        }
    }
    fn reap_finished(&mut self) {
        let ids: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.handle.is_finished())
            .map(|(id, _)| *id)
            .collect();
        let waker = Waker::from(Arc::new(NoWake));
        let mut cx = Context::from_waker(&waker);
        for id in ids {
            // is_finished means the completed JoinHandle can be joined without
            // waiting. This prevents completed metadata causing false rejection.
            if let Poll::Ready(result) =
                Pin::new(&mut self.entries.get_mut(&id).unwrap().handle).poll(&mut cx)
            {
                self.join_result(id, result);
            }
        }
    }
    fn snapshot(&self) -> Snapshot {
        let count = |kind, mode: u8| {
            self.entries
                .values()
                .filter(|e| {
                    e.kind == kind
                        && match mode {
                            0 => true,
                            1 => !e.started,
                            2 => e.started && !e.finished,
                            _ => false,
                        }
                })
                .count()
        };
        Snapshot {
            limits: self.limits,
            admitted_async: self.counts.admitted[0],
            admitted_blocking: self.counts.admitted[1],
            started_async: self.counts.started[0],
            started_blocking: self.counts.started[1],
            body_finished_async: self.counts.finished[0],
            body_finished_blocking: self.counts.finished[1],
            joined_async: self.counts.joined[0],
            joined_blocking: self.counts.joined[1],
            cancelled_async: self.counts.cancelled[0],
            cancelled_blocking: self.counts.cancelled[1],
            panicked: self.counts.panicked,
            rejected_capacity: self.counts.capacity,
            rejected_closed: self.counts.closed,
            retained_async: count(Kind::Async, 0),
            retained_blocking: count(Kind::Blocking, 0),
            queued_async: count(Kind::Async, 1),
            queued_blocking: count(Kind::Blocking, 1),
            active_async: count(Kind::Async, 2),
            active_blocking: count(Kind::Blocking, 2),
            maximum_retained_async: self.counts.maximum[0],
            maximum_retained_blocking: self.counts.maximum[1],
            groups: self
                .groups
                .iter()
                .map(|(id, g)| GroupSnapshot {
                    id: *id,
                    label: g.label.clone(),
                    closed: g.closed,
                    retained: self.entries.values().filter(|e| e.group == *id).count(),
                })
                .collect(),
            failure: self.failure.clone(),
        }
    }
}
impl Inner {
    fn fail(&self, error: ExecutorError) {
        {
            let mut s = self.state.lock().unwrap();
            if s.failure.is_none() {
                s.failure = Some(error);
            }
        }
        self.notify_failure();
    }
    fn notify_failure(&self) {
        let error = {
            let mut s = self.state.lock().unwrap();
            if s.failure_notified {
                None
            } else if let Some(error) = s.failure.clone() {
                s.failure_notified = true;
                Some(error)
            } else {
                None
            }
        };
        // Never execute a core-supplied callback under the executor mutex.
        if let Some(error) = error {
            (self.failure)(error);
        }
    }
    fn unexpected_panic(&self, error: ExecutorError) {
        self.state.lock().unwrap().counts.panicked += 1;
        self.fail(error);
    }
    fn deliver<T>(
        &self,
        send: oneshot::Sender<Result<T, ExecutorError>>,
        result: Result<T, ExecutorError>,
    ) {
        // A detached caller may discard a result whose destructor panics.
        if let Err(error) = std::panic::catch_unwind(AssertUnwindSafe(|| drop(send.send(result)))) {
            self.unexpected_panic(panic_error(error));
        }
    }
    fn started(&self, id: u64) {
        let mut s = self.state.lock().unwrap();
        let e = s
            .entries
            .get_mut(&id)
            .expect("task registered before start");
        e.started = true;
        let kind = e.kind;
        s.counts.started[slot(kind)] += 1;
    }
    fn finished(&self, id: u64, panicked: bool) {
        let mut s = self.state.lock().unwrap();
        let e = s
            .entries
            .get_mut(&id)
            .expect("task retained through body completion");
        e.finished = true;
        let kind = e.kind;
        s.counts.finished[slot(kind)] += 1;
        if panicked {
            s.counts.panicked += 1;
        }
    }
}
impl Executor {
    pub fn new(
        runtime: Handle,
        limits: Limits,
        failure: impl Fn(ExecutorError) + Send + Sync + 'static,
    ) -> Result<Self, ExecutorError> {
        if limits.max_async_tasks == 0
            || limits.max_blocking_tasks == 0
            || limits.max_async_tasks > 1_000_000
            || limits.max_blocking_tasks > 100_000
        {
            return Err(ExecutorError::InvalidLimits);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                runtime,
                joining: tokio::sync::Mutex::new(()),
                failure: Arc::new(failure),
                state: Mutex::new(State {
                    limits,
                    groups: BTreeMap::new(),
                    entries: BTreeMap::new(),
                    next_task: 0,
                    next_group: 0,
                    closed: false,
                    counts: Counts::default(),
                    failure: None,
                    failure_notified: false,
                }),
            }),
        })
    }
    pub fn group(&self, label: impl Into<String>) -> Result<TaskGroup, ExecutorError> {
        let label = label.into();
        let mut s = self.inner.state.lock().unwrap();
        if s.closed {
            return Err(ExecutorError::Closed);
        }
        if s.groups.len() >= 64 || label.is_empty() || label.len() > 128 {
            return Err(ExecutorError::GroupLimit);
        }
        let id = s.next_group;
        s.next_group += 1;
        s.groups.insert(
            id,
            Group {
                label,
                closed: false,
            },
        );
        Ok(TaskGroup {
            executor: self.clone(),
            id,
        })
    }
    pub fn check(&self) -> Result<(), ExecutorError> {
        self.snapshot().failure.map_or(Ok(()), Err)
    }
    pub fn snapshot(&self) -> Snapshot {
        let snapshot = {
            let mut s = self.inner.state.lock().unwrap();
            s.reap_finished();
            s.snapshot()
        };
        self.inner.notify_failure();
        snapshot
    }
    fn close(&self, group: Option<u64>) {
        let mut s = self.inner.state.lock().unwrap();
        if group.is_none() {
            s.closed = true;
        }
        for (id, g) in &mut s.groups {
            if group.map_or(true, |target| target == *id) {
                g.closed = true;
            }
        }
        for entry in s.entries.values() {
            if group.map_or(true, |target| target == entry.group) {
                entry.handle.abort();
            }
        }
    }
    async fn join(&self, group: Option<u64>) -> Result<Snapshot, ExecutorError> {
        // A JoinHandle has one registered waker. Serialize drain controllers,
        // retaining ownership in the registry if either await is cancelled.
        let _joining = self.inner.joining.lock().await;
        std::future::poll_fn(|cx| {
            let mut s = self.inner.state.lock().unwrap();
            let ids: Vec<_> = s
                .entries
                .iter()
                .filter(|(_, e)| group.map_or(true, |target| target == e.group))
                .map(|(id, _)| *id)
                .collect();
            let mut pending = false;
            for id in ids {
                match Pin::new(&mut s.entries.get_mut(&id).unwrap().handle).poll(cx) {
                    Poll::Ready(result) => s.join_result(id, result),
                    Poll::Pending => pending = true,
                }
            }
            let result = if pending {
                Poll::Pending
            } else {
                Poll::Ready(s.failure.clone().map_or_else(|| Ok(s.snapshot()), Err))
            };
            drop(s);
            self.inner.notify_failure();
            result
        })
        .await
    }
    /// Cancellation-safe: all JoinHandles stay in the registry until polled Ready.
    /// A timed-out caller can resume shutdown; running blocking work stays owned.
    pub async fn shutdown(&self) -> Result<Snapshot, ExecutorError> {
        self.close(None);
        self.join(None).await
    }
}
impl TaskGroup {
    pub fn executor(&self) -> &Executor {
        &self.executor
    }
    pub fn spawn<F, T>(&self, future: F) -> Task<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.start(Kind::Async, move |inner, id, send| {
            let handle = inner.runtime.clone();
            handle.spawn(async move {
                inner.started(id);
                let result = Catch {
                    inner: Some(Box::pin(future)),
                    owner: inner.clone(),
                }
                .await;
                let panicked = result.is_err();
                if let Err(error) = &result {
                    inner.fail(error.clone());
                }
                inner.finished(id, panicked);
                inner.deliver(send, result);
            })
        })
    }
    pub fn spawn_blocking<F, T>(&self, body: F) -> Task<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.start(Kind::Blocking, move |inner, id, send| {
            let handle = inner.runtime.clone();
            handle.spawn_blocking(move || {
                inner.started(id);
                let result = std::panic::catch_unwind(AssertUnwindSafe(body)).map_err(panic_error);
                let panicked = result.is_err();
                if let Err(error) = &result {
                    inner.fail(error.clone());
                }
                inner.finished(id, panicked);
                inner.deliver(send, result);
            })
        })
    }
    fn start<T: Send + 'static>(
        &self,
        kind: Kind,
        launch: impl FnOnce(
            Arc<Inner>,
            u64,
            oneshot::Sender<Result<T, ExecutorError>>,
        ) -> JoinHandle<()>,
    ) -> Task<T> {
        let inner = self.executor.inner.clone();
        let mut s = inner.state.lock().unwrap();
        s.reap_finished();
        if s.closed || s.groups.get(&self.id).map_or(true, |g| g.closed) {
            s.counts.closed += 1;
            drop(s);
            inner.notify_failure();
            return Task::error(ExecutorError::Closed);
        }
        let limit = if kind == Kind::Async {
            s.limits.max_async_tasks
        } else {
            s.limits.max_blocking_tasks
        };
        if s.count(kind) >= limit {
            s.counts.capacity += 1;
            let error = ExecutorError::Capacity {
                kind: kind.label(),
                limit,
            };
            drop(s);
            inner.fail(error.clone());
            return Task::error(error);
        }
        let id = s.next_task;
        s.next_task = s
            .next_task
            .checked_add(1)
            .expect("finite executor id exhausted");
        let (send, receive) = oneshot::channel();
        let handle = launch(inner.clone(), id, send);
        let abort = handle.abort_handle();
        s.entries.insert(
            id,
            Entry {
                group: self.id,
                kind,
                started: false,
                finished: false,
                handle,
            },
        );
        s.counts.admitted[slot(kind)] += 1;
        s.counts.maximum[slot(kind)] = s.counts.maximum[slot(kind)].max(s.count(kind));
        drop(s);
        inner.notify_failure();
        Task {
            receive: Some(receive),
            immediate: None,
            abort: Some(abort),
        }
    }
    pub async fn shutdown(&self) -> Result<Snapshot, ExecutorError> {
        self.executor.close(Some(self.id));
        self.executor.join(Some(self.id)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    fn service(a: usize, b: usize) -> (Executor, Arc<AtomicUsize>) {
        let failures = Arc::new(AtomicUsize::new(0));
        let counter = failures.clone();
        (
            Executor::new(
                Handle::current(),
                Limits {
                    max_async_tasks: a,
                    max_blocking_tasks: b,
                },
                move |_| {
                    counter.fetch_add(1, Ordering::SeqCst);
                },
            )
            .unwrap(),
            failures,
        )
    }
    #[tokio::test]
    async fn dropped_result_handle_preserves_execution_and_owner_joins() {
        let (ex, failures) = service(3, 1);
        let group = ex.group("body").unwrap();
        let (tx, rx) = oneshot::channel();
        drop(group.spawn(async move {
            let _ = tx.send(7);
        }));
        assert_eq!(rx.await.unwrap(), 7);
        tokio::task::yield_now().await;
        let done = ex.shutdown().await.unwrap();
        assert_eq!(done.admitted_async, 1);
        assert_eq!(done.joined_async, 1);
        assert_eq!(done.retained_async, 0);
        assert_eq!(failures.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn global_capacity_covers_groups_and_rejects_without_running_body() {
        let (ex, failures) = service(1, 1);
        let a = ex.group("a").unwrap();
        let b = ex.group("b").unwrap();
        let first = a.spawn(std::future::pending::<()>());
        let ran = Arc::new(AtomicUsize::new(0));
        let flag = ran.clone();
        assert!(matches!(
            b.spawn(async move {
                flag.fetch_add(1, Ordering::SeqCst);
            })
            .await,
            Err(ExecutorError::Capacity { .. })
        ));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        assert_eq!(failures.load(Ordering::SeqCst), 1);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(ex.shutdown().await.is_err());
        assert_eq!(ex.snapshot().retained_async, 0);
    }
    #[tokio::test]
    async fn finished_retained_handles_are_reaped_before_capacity_admission() {
        let (ex, _) = service(1, 1);
        let group = ex.group("a").unwrap();
        for value in 0..20 {
            let task = group.spawn(async move { value });
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            assert_eq!(task.await.unwrap(), value);
        }
        let done = ex.shutdown().await.unwrap();
        assert_eq!(done.admitted_async, 20);
        assert_eq!(done.joined_async, 20);
        assert_eq!(done.rejected_capacity, 0);
    }
    #[tokio::test]
    async fn explicit_abort_is_not_failure_and_group_close_preserves_other_group() {
        let (ex, failures) = service(4, 1);
        let a = ex.group("a").unwrap();
        let b = ex.group("b").unwrap();
        let first = a.spawn(std::future::pending::<()>());
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        a.shutdown().await.unwrap();
        assert_eq!(a.spawn(async {}).await.unwrap_err(), ExecutorError::Closed);
        assert_eq!(b.spawn(async { 4 }).await.unwrap(), 4);
        ex.shutdown().await.unwrap();
        assert_eq!(failures.load(Ordering::SeqCst), 0);
        assert_eq!(ex.snapshot().cancelled_async, 1);
    }
    #[tokio::test]
    async fn panic_is_terminal_but_all_other_tasks_remain_joinable() {
        let (ex, failures) = service(4, 1);
        let group = ex.group("a").unwrap();
        let pending = group.spawn(std::future::pending::<()>());
        let panic = group.spawn(async { panic!("owned panic") });
        assert!(matches!(panic.await, Err(ExecutorError::Panicked(_))));
        assert!(ex.shutdown().await.is_err());
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(failures.load(Ordering::SeqCst), 1);
        assert_eq!(ex.snapshot().retained_async, 0);
        assert_eq!(ex.snapshot().panicked, 1);
    }
    #[test]
    fn cancelled_shutdown_retains_running_blocking_and_queued_work() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        rt.block_on(async {
            let (ex, failures) = service(4, 2);
            let group = ex.group("blocking").unwrap();
            let (release, receive) = std::sync::mpsc::channel();
            let (started, ready) = oneshot::channel();
            let running = group.spawn_blocking(move || {
                started.send(()).unwrap();
                receive.recv().unwrap();
                9
            });
            ready.await.unwrap();
            let queued = group.spawn_blocking(|| panic!("queued closure must be cancelled"));
            let before = ex.snapshot();
            assert_eq!(before.active_blocking, 1);
            assert_eq!(before.queued_blocking, 1);
            assert!(
                tokio::time::timeout(Duration::from_millis(5), group.shutdown())
                    .await
                    .is_err()
            );
            // Tokio retains the cancelled queued blocking item until its only
            // worker becomes available. Both handles remain owned/charged.
            assert_eq!(ex.snapshot().retained_blocking, 2);
            assert_eq!(ex.snapshot().active_blocking, 1);
            release.send(()).unwrap();
            assert_eq!(running.await.unwrap(), 9);
            assert!(queued.await.unwrap_err().is_cancelled());
            let done = ex.shutdown().await.unwrap();
            assert_eq!(done.joined_blocking, 2);
            assert_eq!(done.retained_blocking, 0);
            assert_eq!(failures.load(Ordering::SeqCst), 0);
        });
    }
    #[tokio::test]
    async fn simultaneous_group_and_global_shutdown_do_not_lose_join_wakers() {
        let (ex, _) = service(4, 1);
        let group = ex.group("a").unwrap();
        drop(group.spawn(std::future::pending::<()>()));
        let (a, b) = tokio::join!(group.shutdown(), ex.shutdown());
        assert_eq!(a.unwrap().retained_async, 0);
        assert_eq!(b.unwrap().retained_async, 0);
    }
    #[tokio::test]
    async fn future_and_discarded_result_drop_panics_notify_without_waiting_for_reap() {
        struct BadDrop;
        impl Drop for BadDrop {
            fn drop(&mut self) {
                panic!("result destructor")
            }
        }
        struct ReadyDrop;
        impl Future for ReadyDrop {
            type Output = ();
            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        impl Drop for ReadyDrop {
            fn drop(&mut self) {
                panic!("future destructor")
            }
        }
        for result_drop in [false, true] {
            let (ex, failures) = service(4, 1);
            let group = ex.group("drop").unwrap();
            if result_drop {
                drop(group.spawn(async { BadDrop }));
            } else {
                drop(group.spawn(ReadyDrop));
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                while failures.load(Ordering::SeqCst) == 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(failures.load(Ordering::SeqCst), 1);
            assert!(ex.shutdown().await.is_err());
            assert_eq!(ex.snapshot().retained_async, 0);
            assert_eq!(ex.snapshot().panicked, 1);
        }
    }
}
