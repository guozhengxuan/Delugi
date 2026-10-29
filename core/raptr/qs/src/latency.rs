//! Identity conversion is only evaluated when the node enables observations.
use aptos_consensus_types::proof_of_store::BatchInfo;
use raptr::latency::EventKind;

fn key(info: &BatchInfo) -> delugi_raptr_core::BatchKey {
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
