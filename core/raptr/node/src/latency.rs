//! Serialize the bounded local observer only after the application is frozen.
use crate::config::{self, Config};
use delugi_raptr_core::{
    latency::{EventKind, Snapshot, VoteKind},
    BatchKey, SectionKind,
};
use serde_json::{json, Value};

fn section(kind: SectionKind) -> Value {
    match kind {
        SectionKind::Proofs => json!({"kind":"proofs"}),
        SectionKind::SubBlock(index) => json!({"kind":"sub_block","index":index}),
    }
}

fn batch_value(batch: &BatchKey) -> Value {
    json!({"epoch":batch.epoch,"author":config::hex(&batch.author),
          "nonce":batch.nonce,"id":batch.id,"digest":config::hex(&batch.digest)})
}

pub fn document(snapshot: Snapshot, config: &Config, hash: &str, replica: u32) -> Value {
    let events: Vec<_> = snapshot.events.into_iter().map(|event| {
        let name = match &event.kind {
            EventKind::BatchBroadcast { .. } => "batch_broadcast",
            EventKind::BatchReceived { .. } => "batch_received",
            EventKind::BatchQueued { .. } => "batch_queued",
            EventKind::ProofQueued { .. } => "proof_queued",
            EventKind::ProposalPullStarted { .. } => "proposal_pull_started",
            EventKind::ProposalPayloadSelected { .. } => "proposal_payload_selected",
            EventKind::ProposalEmitted { .. } => "proposal_emitted",
            EventKind::Vote { kind, .. } => match kind {
                VoteKind::QcSent => "qc_vote_sent",
                VoteKind::QcReceived => "qc_vote_received",
                VoteKind::CcSent => "cc_vote_sent",
                VoteKind::CcReceived => "cc_vote_received",
            },
            EventKind::BatchStored { .. } => "batch_stored",
            EventKind::AvailabilityQuorum { .. } => "availability_quorum",
            EventKind::ProposalValidated { .. } => "proposal_validated",
            EventKind::Committed { .. } => "committed",
            EventKind::PayloadReady { .. } => "payload_ready",
            EventKind::PrefixReleased { .. } => "prefix_released",
        };
        let mut value = match event.kind {
            EventKind::BatchStored { batch } | EventKind::AvailabilityQuorum { batch } |
            EventKind::BatchBroadcast { batch } | EventKind::BatchReceived { batch } |
            EventKind::ProofQueued { batch } =>
                json!({"batch":batch_value(&batch)}),
            EventKind::BatchQueued { batch, creation_wall_us, observer_wall_us } =>
                json!({"batch":batch_value(&batch),"creation_wall_us":creation_wall_us,"observer_wall_us":observer_wall_us}),
            EventKind::ProposalPullStarted { round, minimum_batch_age_us } => json!({"round":round,"minimum_batch_age_us":minimum_batch_age_us}),
            EventKind::ProposalPayloadSelected { round, proof_count, batches } =>
                json!({"round":round,"proof_count":proof_count,"batches":batches.iter().map(batch_value).collect::<Vec<_>>()}),
            EventKind::Vote { round, digest, prefix, peer, .. } =>
                json!({"round":round,"digest":config::hex(&digest),"prefix":prefix,"peer":peer}),
            EventKind::ProposalEmitted { round, digest } | EventKind::ProposalValidated { round, digest } => json!({"round":round,"digest":config::hex(&digest)}),
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
