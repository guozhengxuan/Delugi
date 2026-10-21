use crate::{
    quorum_store::types::{Batch, BatchMsg},
    test_utils::create_vec_signed_transactions,
};
use aptos_consensus_types::proof_of_store::BatchId;
use aptos_types::PeerId;

#[test]
fn exact_bcs_payload_offsets_cover_multibyte_vector_lengths() {
    for counts in [vec![], vec![0], vec![1, 0, 2], vec![130], vec![0; 130]] {
        let author = PeerId::ZERO;
        let mut expected = Vec::new();
        let batches = counts
            .iter()
            .enumerate()
            .map(|(i, count)| {
                let txns = create_vec_signed_transactions(*count);
                expected.extend(txns.iter().map(|txn| bcs::to_bytes(txn).unwrap()));
                Batch::new(BatchId::new_for_test(i as u64), txns, 1, 1000, author, 0)
            })
            .collect();
        let msg = BatchMsg::new(batches);
        let encoded = msg.encode_with_payload_ranges().unwrap();
        assert_eq!(encoded.bytes, bcs::to_bytes(&msg).unwrap());
        assert_eq!(encoded.transaction_ranges.len(), expected.len());
        let mut end = 0;
        for (range, txn) in encoded.transaction_ranges.into_iter().zip(expected) {
            assert!(range.start >= end);
            assert_eq!(&encoded.bytes[range.clone()], txn.as_slice());
            end = range.end;
        }
    }
}
