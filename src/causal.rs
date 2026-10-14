//! Opt-in local causal diagnostics. This is never part of protocol state or wire.
//! Events use one process-local monotonic origin; no event performs file I/O.
use crate::wire::{Id, Message};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const MAX_EVENTS: usize = 100_000;
const DEFAULT_STRIDE: u64 = 64;
const DETAIL_WIDTH: u64 = 8;

#[derive(Serialize)]
struct Event {
    at_us: u64,
    event: &'static str,
    round: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_us: Option<u64>,
    detail: Value,
}

#[derive(Default)]
struct State {
    events: Vec<Event>,
    dropped: u64,
    counts: BTreeMap<&'static str, u64>,
}

struct Shared {
    origin: Instant,
    wall_origin_us: u64,
    replica: Id,
    stride: u64,
    cap: usize,
    state: Mutex<State>,
}

#[derive(Clone)]
pub(crate) struct Trace(Arc<Shared>);

impl Trace {
    pub(crate) fn from_environment(
        origin: Instant,
        wall_origin_us: u64,
        replica: Id,
    ) -> Result<Option<(Self, PathBuf)>, String> {
        let Some(directory) = std::env::var_os("DELUGI_CAUSAL_TRACE_DIR") else {
            return Ok(None);
        };
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return Err("DELUGI_CAUSAL_TRACE_DIR must be an absolute path".into());
        }
        let stride = std::env::var("DELUGI_CAUSAL_TRACE_STRIDE")
            .map(|s| {
                s.parse::<u64>()
                    .map_err(|_| "invalid causal trace stride".to_string())
            })
            .unwrap_or(Ok(DEFAULT_STRIDE))?;
        if stride == 0 {
            return Err("causal trace stride must be positive".into());
        }
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let path = directory.join(format!("replica-{replica}.json"));
        if path.exists() {
            return Err(format!(
                "causal trace output already exists: {}",
                path.display()
            ));
        }
        Ok(Some((
            Self::new(origin, wall_origin_us, replica, stride, MAX_EVENTS),
            path,
        )))
    }

    fn new(origin: Instant, wall_origin_us: u64, replica: Id, stride: u64, cap: usize) -> Self {
        Self(Arc::new(Shared {
            origin,
            wall_origin_us,
            replica,
            stride,
            cap,
            state: Mutex::new(State::default()),
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::new(Instant::now(), 0, 0, DEFAULT_STRIDE, MAX_EVENTS)
    }

    pub(crate) fn now_us(&self) -> u64 {
        self.0.origin.elapsed().as_micros() as u64
    }

    pub(crate) fn offset_us(&self, instant: Instant) -> Option<u64> {
        instant
            .checked_duration_since(self.0.origin)
            .map(|d| d.as_micros() as u64)
    }

    /// Eight contiguous rounds per bucket retain r-3 -> r links inside each
    /// sampled window. Readiness/outbox events are recorded for every round.
    pub(crate) fn sampled(&self, round: u64) -> bool {
        round % self.0.stride < DETAIL_WIDTH.min(self.0.stride)
    }

    pub(crate) fn mark(&self, event: &'static str, round: u64, detail: Value) {
        self.push(event, round, None, detail);
    }

    pub(crate) fn span(&self, event: &'static str, round: u64, start_us: u64, detail: Value) {
        self.push(event, round, Some(start_us), detail);
    }

    fn push(&self, event: &'static str, round: u64, start_us: Option<u64>, detail: Value) {
        let at_us = self.now_us();
        self.at(event, round, at_us, start_us, detail);
    }

    pub(crate) fn at(
        &self,
        event: &'static str,
        round: u64,
        at_us: u64,
        start_us: Option<u64>,
        detail: Value,
    ) {
        let mut state = self.0.state.lock().unwrap();
        *state.counts.entry(event).or_default() += 1;
        if state.events.len() == self.0.cap {
            state.dropped += 1;
        } else {
            state.events.push(Event {
                at_us,
                event,
                round,
                start_us,
                detail,
            });
        }
    }

    pub(crate) fn summary(&self) -> Value {
        let state = self.0.state.lock().unwrap();
        json!({"events":state.events.len(),"dropped":state.dropped,
            "max_events":self.0.cap,"detail_stride":self.0.stride,
            "detail_width":DETAIL_WIDTH.min(self.0.stride),"counts":state.counts})
    }

    pub(crate) fn write(
        &self,
        path: &std::path::Path,
        outcome: &Result<(), String>,
    ) -> Result<(), String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let state = self.0.state.lock().unwrap();
        let document = json!({"schema":"delugi-causal-trace-v1","replica":self.0.replica,
            "clock":"microseconds from this replica's monotonic Runtime origin",
            "wall_origin_us":self.0.wall_origin_us,"detail_stride":self.0.stride,
            "detail_width":DETAIL_WIDTH.min(self.0.stride),"max_events":self.0.cap,
            "dropped":state.dropped,"counts":state.counts,"run_error":outcome.as_ref().err(),
            "notes":["Core readiness and critical outbox events cover every round; detailed spans/dispatch/send events cover eight contiguous rounds per stride bucket.",
                "For HISTORY3, round denotes its exact horizon h; next_proposal_round is h+3.",
                "Transport enqueue is not socket write or remote delivery. Receive mailbox timestamps follow frame authentication.",
                "Origins differ between replicas; use within-replica durations. wall_origin_us is an approximate wall-clock anchor, not clock synchronization.",
                "Trace is bounded and diagnostic-only; nonzero dropped makes the retained tail incomplete."],
            "events":state.events});
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &document).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())
    }
}

pub(crate) fn ordering_key(message: &Message) -> (&'static str, u64, Id) {
    match message {
        Message::Propose(p) => ("PROPOSE", p.header.body.round, p.header.signer),
        Message::Vote { vote, .. } => ("VOTE", vote.body.round, vote.signer),
        Message::Cer(s) => ("CER", s.body.round, s.signer),
        Message::Prog(s) => ("PROG", s.body.round, s.signer),
        Message::Closed(s) => ("CLOSED", s.body.round, s.signer),
        Message::History3(r) => ("HISTORY3", r.header.body.horizon, r.header.signer),
    }
}

pub(crate) fn dissemination_key(
    message: &crate::composed::Message,
) -> (&'static str, u64, Option<Id>) {
    use crate::composed::Message as M;
    match message {
        M::Report { request, base } => ("REPORT", base.opportunity, Some(request.signer)),
        M::Observation(o) => ("OBS", o.body.opportunity, Some(o.signer)),
        M::Batch(_) => ("BATCH", 0, None),
        M::Fetch { .. } => ("FETCH", 0, None),
        M::Data(_) | M::DataPart(_) => ("DATA", 0, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_is_bounded_and_samples_contiguous_dependency_windows() {
        let trace = Trace::new(Instant::now(), 0, 0, 32, 2);
        for r in 32..40 {
            assert!(trace.sampled(r));
        }
        for r in 40..64 {
            assert!(!trace.sampled(r));
        }
        assert!(trace.sampled(64));
        for r in 1..=5 {
            trace.mark("input_fixed", r, json!({}));
        }
        let summary = trace.summary();
        assert_eq!(summary["events"], 2);
        assert_eq!(summary["dropped"], 3);
        assert_eq!(summary["counts"]["input_fixed"], 5);
        let state = trace.0.state.lock().unwrap();
        assert!(state.events.windows(2).all(|w| w[0].at_us <= w[1].at_us));
    }

    #[test]
    fn shutdown_file_preserves_span_boundaries_errors_and_refuses_overwrite() {
        let trace = Trace::for_test();
        let start = trace.now_us();
        trace.span("handler", 64, start, json!({"kind":"HISTORY3"}));
        let path = std::env::temp_dir().join(format!(
            "delugi-causal-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        trace.write(&path, &Err("original failure".into())).unwrap();
        let decoded: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(decoded["schema"], "delugi-causal-trace-v1");
        assert_eq!(decoded["run_error"], "original failure");
        assert_eq!(decoded["events"][0]["start_us"], start);
        assert!(decoded["events"][0]["at_us"].as_u64().unwrap() >= start);
        assert!(trace.write(&path, &Ok(())).is_err());
        fs::remove_file(path).unwrap();
    }
}
