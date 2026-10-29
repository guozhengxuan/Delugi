//! Raptr native Quorum Store policy over explicit shared service boundaries.
#[macro_use]
extern crate scopeguard;
pub mod assembly;
pub mod counters;
pub mod error;
pub mod liveness;
pub mod logging;
pub mod mempool;
pub mod network;
pub mod quorum_store;
pub mod round_manager;
use aptos_metrics_core::IntGauge;
pub struct IntGaugeGuard {
    gauge: IntGauge,
}

impl IntGaugeGuard {
    pub fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        Self { gauge }
    }
}

impl Drop for IntGaugeGuard {
    fn drop(&mut self) {
        self.gauge.dec();
    }
}

/// Helper function to record metrics for external calls.
/// Include call counts, time, and whether it's inside or not (1 or 0).
/// It assumes a OpMetrics defined as OP_COUNTERS in crate::counters;
#[macro_export]
macro_rules! monitor {
    ($name:literal, $fn:expr) => {{
        use $crate::{counters::OP_COUNTERS, IntGaugeGuard};
        let _timer = OP_COUNTERS.timer($name);
        let _guard = IntGaugeGuard::new(OP_COUNTERS.gauge(concat!($name, "_running")));
        $fn
    }};
}

pub mod payload_client;
pub mod payload_manager;
mod payload_metadata;
mod latency;

#[cfg(test)]
mod test_utils;
