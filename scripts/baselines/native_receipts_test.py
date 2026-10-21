from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_receipts as receipts


class CompactReceiptTests(unittest.TestCase):
    def receipt(self, identities):
        result=receipts.Receipt([4,4],8)
        for sequence,identity in enumerate(identities):
            result.output(0,sequence,8,identity,"batch"+str(sequence),True)
            result.batch("batch"+str(sequence),8)
        return result.finish()

    def test_prefix_conflict_not_hidden_by_stalled_replica(self):
        with self.assertRaisesRegex(RuntimeError,"prefixes disagree"):
            receipts.compare({0:self.receipt([]),1:self.receipt(["a"]),2:self.receipt(["b"])},[0,1,2])

    def test_partial_prefix_matches_and_native_order_is_bound(self):
        self.assertTrue(receipts.compare({0:self.receipt(["a"]),1:self.receipt(["a","b"])},[0,1])["replicas_agree_on_common_prefix"])
        self.assertNotEqual(self.receipt(["a","b"])["output_sha256"],self.receipt(["b","a"])["output_sha256"])

    def test_credit_requires_admission_and_all_correct_output(self):
        observed={0:self.receipt(["a","b"]),1:self.receipt(["a"])}
        summary=receipts.summarize(observed,{0:"03",1:"00"},[0,1])
        self.assertEqual(summary["all_correct_completed"],1)
        self.assertFalse(summary["latency_available"])
        self.assertEqual(receipts.summarize(observed,{0:"02",1:"00"},[0,1])["all_correct_completed"],0)

    def test_repeated_identity_never_inflates_useful_credit(self):
        result=receipts.Receipt([1],8)
        for _ in range(3):result.output(0,0,8,"same","batch",True)
        self.assertEqual(result.output_count,3)
        self.assertEqual(receipts.bit_count(result.finish()["materialized_bits"][0]),1)

    def test_warmup_identity_replay_cannot_become_fresh_window_work(self):
        result=receipts.Receipt([1],8)
        result.output(0,0,8,"same","warmup-batch",False)
        result.output(0,0,8,"same","later-batch",True)
        self.assertEqual(receipts.bit_count(result.finish()["window_materialized_bits"][0]),0)

    def test_padding_cannot_inflate_finite_admission_or_output(self):
        observed={0:self.receipt(["a"]),1:self.receipt(["a"])}
        with self.assertRaisesRegex(ValueError,"padding"):
            receipts.summarize(observed,{0:"81",1:"00"},[0,1])
        observed[1]["materialized_bits"][0]="81"
        with self.assertRaisesRegex(ValueError,"padding"):
            receipts.summarize(observed,{0:"01",1:"00"},[0,1])

    def test_empty_length_and_canonical_bitmap_encodings(self):
        self.assertEqual(receipts.finite_bitmap("",0),b"")
        self.assertEqual(receipts.finite_bitmap("ff",8),b"\xff")
        for value,count in (("00",0),("",1),("ff00",8),("FF",8),("0 1",4)):
            with self.assertRaises(ValueError):receipts.finite_bitmap(value,count)


if __name__=="__main__":unittest.main()
