"""Finite compact receipts retain incomplete/preplayed work without fake timing."""
from pathlib import Path
from hashlib import sha256
import copy
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import observer_receipts as receipts


class Controller:
    def __init__(self, count=10):
        self.count = count
        self.bits = {}
        self.bodies = {}
        self.bad_page = self.bad_prefix = False
        self.bitmap_calls = 0
        size = (count+7)//8
        def bitmap(value): return (value if count else 0).to_bytes(size, "little")
        for replica in range(4):
            streams = []
            # seq0 completed normally, seq1 was preplayed before admission;
            # both later admitted, but only seq0 can ever earn useful credit.
            for origin in range(4): self.bits[replica,"materialized",origin] = bitmap(3)
            for name, value in (("admitted",3),("rejected",4),("ready",3),("completed",1),("seen_output",3)):
                self.bits[replica,name,replica] = bitmap(value)
            for (r,name,origin), raw in self.bits.items():
                if r==replica:
                    streams.append(dict(name=name, origin=origin, count=count, bytes=size,
                        ones=sum(x.bit_count() for x in raw), sha256=list(sha256(raw).digest())))
            self.bodies[replica] = dict(replica=replica, mode="compact", scheduled=3 if count else 0,
                manifest={"body":{"count":count,"useful_bytes":8}}, output_count=8 if count else 0, output_fingerprint=[8 if count else 0]*32,
                batch_count=2 if count else 0, batch_fingerprint=[2 if count else 0]*32, m_out_bytes=100 if count else 0, streams=streams)
        self.snapshots={i:dict(executed_count=8 if count else 0,materialized_batch_count=2 if count else 0) for i in range(4)}
    def request(self, replica, kind, **kw):
        if kind == "receipt":
            data={"receipt":{"signer":replica,"body":copy.deepcopy(self.bodies[replica])}}
        elif kind == "receipt_bitmap":
            self.bitmap_calls += 1
            raw=self.bits[replica,kw["receipt_stream"],kw["receipt_origin"]]
            start=kw["offset"]; end=min(len(raw),start+kw["limit"])
            content=list(raw[start:end])
            if self.bad_page: content=[]
            data=dict(origin=kw["receipt_origin"],stream=kw["receipt_stream"],offset=start,
                      total=len(raw),bytes=content,next_offset=end if end<len(raw) else None)
        elif kind == "receipt_prefix":
            is_output=kw["receipt_stream"]=="outputs"
            count=self.bodies[replica]["output_count" if is_output else "batch_count"]
            data=dict(count=kw["count"],total=count,fingerprint=[kw["count"]]*32)
            if self.bad_prefix and replica==2: data["fingerprint"]=[99]*32
        else: raise AssertionError(kind)
        return {"replica":replica,"reply":{"data":data}}
    def many(self, peers, kind, **kw): return [self.request(i,kind,**kw) for i in peers]


class Receipts(unittest.TestCase):
    def test_preplay_rejection_unarrived_and_unfinished_population_retained(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(); archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
            result=receipts.summarize(index,Path(archive["path"]).parent,list(range(4)))
            self.assertEqual(result["scheduled"],40)
            self.assertEqual(result["arrived"],12)
            self.assertEqual(result["admitted"],8)
            self.assertEqual(result["rejected"],4)
            self.assertEqual(result["not_yet_arrived"],28)
            self.assertEqual(result["local_completed"],4)
            self.assertEqual(result["all_correct_completed"],4)
            self.assertEqual(result["all_correct_unfinished"],36)
            self.assertIsNone(result["latency_quantiles"])
            self.assertFalse(result["latency_available"])
            self.assertTrue(archive["agreement"]["batches"]["all_correct_overlap_prefixes_verified"])
    def test_zero_population_uses_one_empty_terminal_page_and_no_latency(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(count=0)
            archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
            result=receipts.summarize(index,Path(archive["path"]).parent,list(range(4)))
            self.assertEqual(result["scheduled"],0)
            self.assertEqual(result["all_correct_completed"],0)
            self.assertEqual(result["reference_unique_eligible_u_out_bytes"],0)
            self.assertIsNone(result["latency_quantiles"])

    def test_changed_population_is_rejected_before_any_bitmap_rpc(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller()
            c.bodies[0]["streams"][0].update(count=10**18, bytes=(10**18+7)//8)
            with self.assertRaisesRegex(AssertionError,"trusted configuration"):
                receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),10),"compact")
            self.assertEqual(c.bitmap_calls,0)

    def test_empty_or_tampered_pages_fail(self):
        for tamper in ("empty","hash"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as root:
                c=Controller()
                if tamper=="empty": c.bad_page=True
                else: c.bits[0,"materialized",0]=b"\x01\0"
                with self.assertRaisesRegex(AssertionError,"empty|hash"):
                    receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
    def test_laggard_does_not_hide_longer_correct_prefix_conflict(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller();c.bad_prefix=True
            c.bodies[0]["output_count"]=0;c.bodies[0]["output_fingerprint"]=[0]*32
            c.snapshots[0]["executed_count"]=0
            with self.assertRaisesRegex(AssertionError,"prefix|receipt"):
                receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
    def test_no_retroactive_useful_credit_from_later_admission(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(); archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
            result=receipts.summarize(index,Path(archive["path"]).parent,list(range(4)))
            # Eight admitted IDs are replicated everywhere; only four were
            # eligible at their original own-origin append event.
            self.assertEqual(result["admitted"],8)
            self.assertEqual(result["all_correct_completed"],4)
    def test_admitted_output_earns_credit_before_own_origin_batch_is_ready(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller()
            for replica in range(4):
                raw=b"\0\0"
                c.bits[replica,"ready",replica]=raw
                descriptor=next(d for d in c.bodies[replica]["streams"] if d["name"]=="ready")
                descriptor.update(ones=0,sha256=list(sha256(raw).digest()))
            archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
            result=receipts.summarize(index,Path(archive["path"]).parent,list(range(4)))
            self.assertEqual(result["batch_ready"],0)
            self.assertEqual(result["all_correct_completed"],4)

    def test_reduction_reauthenticates_consumed_hash_count_and_padding(self):
        for attack in ("hash","popcount","padding"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as root:
                c=Controller()
                archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
                root=Path(archive["path"]).parent
                replica,name,origin=("1","materialized",0) if attack=="padding" else ("0","completed",0)
                entry=index["replicas"][replica]
                descriptor=next(d for d in entry["receipt"]["body"]["streams"] if d["name"]==name and d["origin"]==origin)
                path=root/next(d["path"] for d in entry["streams"] if d["name"]==name and d["origin"]==origin)
                if attack=="hash":
                    # Still satisfies set algebra; would silently lower useful
                    # counts if reduction trusted an earlier verification pass.
                    path.write_bytes(b"\0\0")
                elif attack=="popcount":
                    descriptor["ones"]=0
                else:
                    raw=b"\x03\x80"
                    path.write_bytes(raw)
                    descriptor.update(ones=3,sha256=list(sha256(raw).digest()))
                with self.assertRaisesRegex(AssertionError,"consumed bitmap hash, membership count or padding"):
                    receipts.summarize(index,root,list(range(4)))

    def test_actual_multiple_pages_and_missing_tail(self):
        with tempfile.TemporaryDirectory() as root:
            c=Controller(count=40000)
            archive,index=receipts.collect(c,c.snapshots,Path(root)/"receipt",list(range(4)),dict.fromkeys(range(4),c.count),"compact")
            root=Path(archive["path"]).parent
            self.assertEqual(receipts.summarize(index,root,list(range(4)))["scheduled"],160000)
            path=root/index["replicas"]["0"]["streams"][0]["path"]
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaisesRegex(AssertionError,"truncated"):
                receipts.summarize(index,root,list(range(4)))

if __name__ == "__main__": unittest.main()
