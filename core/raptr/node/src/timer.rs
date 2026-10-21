//! Native TimerService facade over the shared mechanism; all events, durations
//! and handler scheduling remain core-owned.
use raptr::framework::timer::TimerService;
use std::time::Duration;
pub struct NativeTimer<E>(shared_runtime_async::Timer<E>);
impl<E> NativeTimer<E> {
    pub fn new() -> Self {
        Self(shared_runtime_async::Timer::new())
    }
}
impl<E: Send + Sync> TimerService for NativeTimer<E> {
    type Event = E;
    fn schedule(&mut self, duration: Duration, event: E) {
        self.0.schedule(duration, event)
    }
    async fn tick(&mut self) -> E {
        self.0.tick().await
    }
}
