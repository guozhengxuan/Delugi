use aptos_metrics_core::{register_int_counter_vec,register_avg_counter,IntCounterVec,Histogram};
use once_cell::sync::Lazy;
pub static OP_COUNTERS: Lazy<aptos_metrics_core::op_counters::OpMetrics> =
    Lazy::new(|| aptos_metrics_core::op_counters::OpMetrics::new_and_registered("consensus"));

/// Counts the total number of errors
pub static OPTQS_EXCLUDE_AUTHORS_COUNT: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_optqs_exclude_authors",
        "The number of times a batch author appears on the exclude list",
        &["author"]
    )
    .unwrap()
});

pub static OPTQS_LAST_CONSECUTIVE_SUCCESS_COUNT: Lazy<Histogram> = Lazy::new(|| {
    register_avg_counter(
        "aptos_optqs_last_consecutive_successes",
        "The number of last consecutive successes capped at window length",
    )
});

pub static WAIT_FOR_FULL_BLOCKS_TRIGGERED: Lazy<Histogram> = Lazy::new(|| {
    register_avg_counter(
        "aptos_wait_for_full_blocks_triggered",
        "Counts when waiting for full blocks is triggered",
    )
});

/// Counts when pipeline backpressure is triggered
pub static CONSENSUS_PROPOSAL_PAYLOAD_BATCH_AVAILABILITY_IN_QS: Lazy<IntCounterVec> = Lazy::new(
    || {
        register_int_counter_vec!(
            "aptos_consensus_proposal_payload_batch_availability",
            "The number of batches in payload that are available and missing locally by batch author",
            &["author", "is_proof", "state"]
        )
        .unwrap()
    },
);

