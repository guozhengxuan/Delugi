//! Optional process-local operation accounting. Timers never affect protocol guards.
//!
//! Enabled measurements include nested operations: construction includes proof
//! work, and proof work includes content hashes. Their times must not be summed.
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

static ENABLED: AtomicBool = AtomicBool::new(false);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Operation {
    ProtocolSign,
    ProtocolVerify,
    TransportDataSign,
    TransportDataVerify,
    TransportAckSign,
    TransportAckVerify,
    WorkloadManifestSign,
    WorkloadManifestVerify,
    ObserverReceiptSign,
    ObserverReceiptVerify,
    ContentHash,
    PrefixProofBuild,
    PrefixProofVerify,
    AvailabilityConstruct,
}

impl Operation {
    const ALL: [Self; 14] = [
        Self::ProtocolSign,
        Self::ProtocolVerify,
        Self::TransportDataSign,
        Self::TransportDataVerify,
        Self::TransportAckSign,
        Self::TransportAckVerify,
        Self::WorkloadManifestSign,
        Self::WorkloadManifestVerify,
        Self::ObserverReceiptSign,
        Self::ObserverReceiptVerify,
        Self::ContentHash,
        Self::PrefixProofBuild,
        Self::PrefixProofVerify,
        Self::AvailabilityConstruct,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::ProtocolSign => "protocol_sign",
            Self::ProtocolVerify => "protocol_verify",
            Self::TransportDataSign => "transport_data_sign",
            Self::TransportDataVerify => "transport_data_verify",
            Self::TransportAckSign => "transport_ack_sign",
            Self::TransportAckVerify => "transport_ack_verify",
            Self::WorkloadManifestSign => "workload_manifest_sign",
            Self::WorkloadManifestVerify => "workload_manifest_verify",
            Self::ObserverReceiptSign => "observer_receipt_sign",
            Self::ObserverReceiptVerify => "observer_receipt_verify",
            Self::ContentHash => "content_hash",
            Self::PrefixProofBuild => "prefix_proof_build",
            Self::PrefixProofVerify => "prefix_proof_verify",
            Self::AvailabilityConstruct => "availability_construct",
        }
    }

    pub fn signature(domain: &str, signing: bool) -> Self {
        match (domain, signing) {
            ("tcp-data-v1", true) => Self::TransportDataSign,
            ("tcp-data-v1", false) => Self::TransportDataVerify,
            ("tcp-ack-v1", true) => Self::TransportAckSign,
            ("tcp-ack-v1", false) => Self::TransportAckVerify,
            ("evaluation-workload-manifest-v1", true) => Self::WorkloadManifestSign,
            ("evaluation-workload-manifest-v1", false) => Self::WorkloadManifestVerify,
            ("evaluation-observer-receipt-v1", true) => Self::ObserverReceiptSign,
            ("evaluation-observer-receipt-v1", false) => Self::ObserverReceiptVerify,
            (_, true) => Self::ProtocolSign,
            (_, false) => Self::ProtocolVerify,
        }
    }
}

struct Counters {
    calls: AtomicU64,
    elapsed_ns: AtomicU64,
    cpu_ns: AtomicU64,
    cpu_samples: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
            elapsed_ns: AtomicU64::new(0),
            cpu_ns: AtomicU64::new(0),
            cpu_samples: AtomicU64::new(0),
        }
    }
}

static COUNTERS: [Counters; Operation::ALL.len()] =
    [const { Counters::new() }; Operation::ALL.len()];

pub fn configure(enabled: bool) {
    ENABLED.store(enabled, Ordering::Release);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn thread_cpu_ns() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // The pointer addresses initialized stack storage for exactly one timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return None;
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(time.tv_nsec as u64)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn thread_cpu_ns() -> Option<u64> {
    None
}

pub struct Measurement {
    operation: Operation,
    started: Instant,
    cpu_started_ns: Option<u64>,
}

pub fn measure(operation: Operation) -> Option<Measurement> {
    ENABLED.load(Ordering::Relaxed).then(|| Measurement {
        operation,
        started: Instant::now(),
        cpu_started_ns: thread_cpu_ns(),
    })
}

pub fn signature_cache_hit() {
    if ENABLED.load(Ordering::Relaxed) {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        let cpu_elapsed = self
            .cpu_started_ns
            .and_then(|start| thread_cpu_ns()?.checked_sub(start));
        let counter = &COUNTERS[self.operation as usize];
        counter.elapsed_ns.fetch_add(
            self.started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );
        if let Some(cpu) = cpu_elapsed {
            counter.cpu_ns.fetch_add(cpu, Ordering::Relaxed);
            counter.cpu_samples.fetch_add(1, Ordering::Relaxed);
        }
        counter.calls.fetch_add(1, Ordering::Release);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Cost {
    pub calls: u64,
    pub elapsed_ns: u64,
    pub thread_cpu_ns: Option<u64>,
    pub thread_cpu_samples: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub enabled: bool,
    pub clock: &'static str,
    pub accounting: &'static str,
    pub strict_verification_cache_hits: u64,
    pub operations: BTreeMap<&'static str, Cost>,
}

pub fn snapshot() -> Snapshot {
    let cpu_available = thread_cpu_ns().is_some();
    Snapshot {
        enabled: ENABLED.load(Ordering::Acquire),
        clock: if cpu_available { "monotonic elapsed and CLOCK_THREAD_CPUTIME_ID" } else { "monotonic elapsed; thread CPU unavailable" },
        accounting: "process cumulative completed operation attempts, including failures; nested operation costs overlap and are not additive; counters may advance while sampled; measure observer overhead with enabled/disabled runs",
        strict_verification_cache_hits: CACHE_HITS.load(Ordering::Acquire),
        operations: Operation::ALL.into_iter().map(|operation| {
            let counter = &COUNTERS[operation as usize];
            (operation.name(), Cost { calls: counter.calls.load(Ordering::Acquire),
                elapsed_ns: counter.elapsed_ns.load(Ordering::Acquire),
                thread_cpu_ns: cpu_available.then(|| counter.cpu_ns.load(Ordering::Acquire)),
                thread_cpu_samples: counter.cpu_samples.load(Ordering::Acquire) })
        }).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn optional_meter_reports_counts_elapsed_and_available_cpu_without_relabeling() {
        let _lock = LOCK.lock().unwrap();
        configure(false);
        assert!(measure(Operation::ProtocolSign).is_none());
        configure(true);
        let before = snapshot().operations["protocol_sign"].calls;
        {
            let _measured = measure(Operation::ProtocolSign);
            for value in 0..1000 {
                std::hint::black_box(value);
            }
        }
        let after = snapshot();
        assert!(after.operations["protocol_sign"].calls > before);
        assert!(after.operations["protocol_sign"].elapsed_ns > 0);
        assert!(after.accounting.contains("not additive"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(after.operations["protocol_sign"].thread_cpu_samples > 0);
        configure(false);
    }

    #[test]
    fn transport_authentication_never_counts_as_protocol_signatures() {
        assert_eq!(
            Operation::signature("tcp-data-v1", true).name(),
            "transport_data_sign"
        );
        assert_eq!(
            Operation::signature("tcp-ack-v1", false).name(),
            "transport_ack_verify"
        );
        assert_eq!(
            Operation::signature("dissemination-observation", false).name(),
            "protocol_verify"
        );
        assert_eq!(
            Operation::signature("evaluation-workload-manifest-v1", true).name(),
            "workload_manifest_sign"
        );
    }

    #[test]
    fn observer_receipt_authentication_has_separate_control_accounting() {
        assert_eq!(
            Operation::signature("evaluation-observer-receipt-v1", true).name(),
            "observer_receipt_sign"
        );
        assert_eq!(
            Operation::signature("evaluation-observer-receipt-v1", false).name(),
            "observer_receipt_verify"
        );
        let names: std::collections::BTreeSet<_> = Operation::ALL
            .iter()
            .map(|operation| operation.name())
            .collect();
        assert_eq!(names.len(), Operation::ALL.len());
        assert!(snapshot().operations.contains_key("observer_receipt_sign"));
        assert!(snapshot()
            .operations
            .contains_key("observer_receipt_verify"));
    }
}
