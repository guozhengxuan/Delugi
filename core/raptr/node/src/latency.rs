//! Serialize the bounded local observer only after the application is frozen.
use crate::config::{self, Config};
use delugi_raptr_core::{
    latency::{EventKind, Snapshot},
    SectionKind,
};
use serde_json::{json, Value};

fn section(kind: SectionKind) -> Value {
    match kind {
        SectionKind::Proofs => json!({"kind":"proofs"}),
        SectionKind::SubBlock(index) => json!({"kind":"sub_block","index":index}),
    }
}

pub fn document(snapshot: Snapshot, config: &Config, hash: &str, replica: u32) -> Value {
    let events: Vec<_> = snapshot.events.into_iter().map(|event| {
        let name = match &event.kind {
            EventKind::BatchStored { .. } => "batch_stored",
            EventKind::AvailabilityQuorum { .. } => "availability_quorum",
            EventKind::ProposalValidated { .. } => "proposal_validated",
            EventKind::Committed { .. } => "committed",
            EventKind::PayloadReady { .. } => "payload_ready",
            EventKind::PrefixReleased { .. } => "prefix_released",
        };
        let mut value = match event.kind {
            EventKind::BatchStored { batch } | EventKind::AvailabilityQuorum { batch } => {
                json!({"batch":{"epoch":batch.epoch,"author":config::hex(&batch.author),
                    "nonce":batch.nonce,"id":batch.id,"digest":config::hex(&batch.digest)}})
            }
            EventKind::ProposalValidated { round, digest } => json!({"round":round,"digest":config::hex(&digest)}),
            EventKind::Committed { round, digest, include_proofs, from_prefix, to_prefix } =>
                json!({"round":round,"digest":config::hex(&digest),"include_proofs":include_proofs,"from_prefix":from_prefix,"to_prefix":to_prefix}),
            EventKind::PayloadReady { round, digest, section: kind } |
            EventKind::PrefixReleased { round, digest, section: kind } =>
                json!({"round":round,"digest":config::hex(&digest),"section":section(kind)}),
        };
        value["at_us"] = event.at_us.into();
        value["event"] = name.into();
        value
    }).collect();
    json!({"schema":"raptr-latency-trace-v1","run_id":config.run_id,
        "configuration_sha256":hash,"replica":replica,"clock":"CLOCK_MONOTONIC",
        "max_events":snapshot.max_events,"dropped":snapshot.dropped,"events":events})
}
