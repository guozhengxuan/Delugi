//! Identity conversion is only evaluated when the node enables observations.
use aptos_consensus_types::proof_of_store::BatchInfo;
use raptr::latency::EventKind;

pub fn key(info: &BatchInfo) -> delugi_raptr_core::BatchKey {
    let id = info.batch_id();
    delugi_raptr_core::BatchKey {
        epoch: info.epoch(),
        author: info.author().into_bytes(),
        nonce: id.nonce,
        id: id.id,
        digest: *info.digest().as_ref(),
    }
}

pub(crate) fn batch_stored(info: &BatchInfo) {
    raptr::latency::record(|| EventKind::BatchStored { batch: key(info) });
}

pub(crate) fn availability_quorum(info: &BatchInfo) {
    raptr::latency::record(|| EventKind::AvailabilityQuorum { batch: key(info) });
}

pub(crate) fn batch_received(info: &BatchInfo) {
    raptr::latency::record(|| EventKind::BatchReceived { batch: key(info) });
}

pub(crate) fn batch_broadcast(info: &BatchInfo) {
    raptr::latency::record(|| EventKind::BatchBroadcast { batch: key(info) });
}

pub(crate) fn batch_queued(info: &BatchInfo, expiry_gap_us: u64) {
    raptr::latency::record(|| EventKind::BatchQueued {
        batch: key(info),
        creation_wall_us: info.expiration().saturating_sub(expiry_gap_us),
        observer_wall_us: aptos_infallible::duration_since_epoch().as_micros() as u64,
    });
}

pub(crate) fn proof_queued(info: &BatchInfo) {
    raptr::latency::record(|| EventKind::ProofQueued { batch: key(info) });
}
