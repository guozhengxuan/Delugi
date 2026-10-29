//! Optional, bounded, process-local latency observations.
//!
//! No clock domain or protocol metadata is inferred here. The replica installs
//! its monotonic clock before starting native actors. Disabled observation does
//! not evaluate the event closure. All identities are exact native identities;
//! availability may overlap proposal/consensus and is not a sequential barrier.
use crate::{BatchKey, Digest, SectionKind};
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    BatchStored {
        batch: BatchKey,
    },
    AvailabilityQuorum {
        batch: BatchKey,
    },
    ProposalValidated {
        round: i64,
        digest: Digest,
    },
    Committed {
        round: i64,
        digest: Digest,
        include_proofs: bool,
        from_prefix: usize,
        to_prefix: usize,
    },
    PayloadReady {
        round: i64,
        digest: Digest,
        section: SectionKind,
    },
    PrefixReleased {
        round: i64,
        digest: Digest,
        section: SectionKind,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub at_us: u64,
    pub kind: EventKind,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub events: Vec<Event>,
    pub dropped: u64,
    pub max_events: usize,
}

struct State {
    events: Vec<Event>,
    dropped: u64,
    frozen: bool,
}

pub struct Recorder {
    clock: fn() -> u64,
    max_events: usize,
    state: Mutex<State>,
}

static RECORDER: OnceLock<Arc<Recorder>> = OnceLock::new();

/// One native replica runs in each process. Reinstallation is rejected so
/// observations from distinct runs cannot silently share an archive.
pub fn install(max_events: usize, clock: fn() -> u64) -> Result<Arc<Recorder>, &'static str> {
    if max_events == 0 {
        return Err("latency trace max_events must be positive");
    }
    let recorder = Arc::new(Recorder::new(max_events, clock));
    RECORDER
        .set(recorder.clone())
        .map_err(|_| "latency recorder already installed")?;
    Ok(recorder)
}

pub fn enabled() -> bool {
    RECORDER.get().is_some()
}

pub fn record(make: impl FnOnce() -> EventKind) {
    if let Some(recorder) = RECORDER.get() {
        recorder.record(make);
    }
}

impl Recorder {
    fn new(max_events: usize, clock: fn() -> u64) -> Self {
        Self {
            clock,
            max_events,
            state: Mutex::new(State {
                events: Vec::with_capacity(max_events.min(1024)),
                dropped: 0,
                frozen: false,
            }),
        }
    }

    fn record(&self, make: impl FnOnce() -> EventKind) {
        // Capture the boundary before observer lock contention or identity
        // construction. Events from concurrent workers need not be time-sorted.
        let at_us = (self.clock)();
        let mut state = self.state.lock().expect("latency recorder lock");
        if state.frozen {
            return;
        }
        if state.events.len() == self.max_events {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }
        state.events.push(Event {
            at_us,
            kind: make(),
        });
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().expect("latency recorder lock");
        self.snapshot_locked(&state)
    }

    /// Atomically stops collection and copies the bounded buffer. No event is
    /// allowed to mutate the returned campaign snapshot after this boundary.
    pub fn freeze(&self) -> Snapshot {
        let mut state = self.state.lock().expect("latency recorder lock");
        state.frozen = true;
        self.snapshot_locked(&state)
    }

    fn snapshot_locked(&self, state: &State) -> Snapshot {
        Snapshot {
            events: state.events.clone(),
            dropped: state.dropped,
            max_events: self.max_events,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(round: i64) -> EventKind {
        EventKind::Committed {
            round,
            digest: [7; 32],
            include_proofs: false,
            from_prefix: 3,
            to_prefix: 5,
        }
    }

    #[test]
    fn bounded_trace_counts_every_overflow_and_retains_slice_identity() {
        let recorder = Recorder::new(2, || 123);
        recorder.record(|| event(4));
        recorder.record(|| event(5));
        recorder.record(|| panic!("overflow must not construct the event"));
        recorder.record(|| panic!("overflow must not construct the event"));
        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.max_events, 2);
        assert_eq!(snapshot.dropped, 2);
        assert_eq!(
            snapshot.events,
            vec![
                Event {
                    at_us: 123,
                    kind: event(4)
                },
                Event {
                    at_us: 123,
                    kind: event(5)
                }
            ]
        );
    }

    #[test]
    fn freeze_prevents_post_snapshot_events() {
        let recorder = Recorder::new(3, || 10);
        recorder.record(|| event(1));
        let frozen = recorder.freeze();
        recorder.record(|| panic!("frozen trace must not construct the event"));
        assert_eq!(recorder.snapshot().events, frozen.events);
        assert_eq!(recorder.snapshot().dropped, 0);
    }

    #[test]
    fn no_recorder_means_no_identity_construction() {
        assert!(!enabled());
        record(|| panic!("disabled trace must not construct the event"));
    }
}
