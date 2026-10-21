import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import tracemalloc
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"/"baselines"))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import native_cohort_store as native
from cohort_metrics import summarize_cohorts
from cohort_metrics_test import fixture
import mysticeti


def mixed():
    ledgers=fixture()
    for ledger in ledgers.values():
        ledger["output_index_base"]=0;ledger["outputs"][0]["output_index"]=0
        ledger["outputs"].append(dict(ledger["outputs"][0],output_index=1,materialized_us=6000,exact_batch_id="replay"))
        ledger["batches"].append({"exact_batch_id":"replay","payload_bytes":168,"materialized_us":6000})
    for sequence in (1,2):
        row=dict(ledgers[0]["requests"][0],request_id=str(sequence),sequence=sequence,
                 scheduled_us=2500,admitted_us=3000,batch_ready_us=None,materialized_us=None)
        if sequence==2:row.update(admitted_us=None,rejected_us=3000)
        ledgers[0]["requests"].append(row)
    return ledgers


class BoundedNativeArchives(unittest.TestCase):
    def archive(self,root,ledgers):
        store=native.NativeStore(root/"stage.sqlite")
        try:
            for replica,ledger in ledgers.items():
                path=root/f"ledger-{replica}.json";path.write_text(json.dumps(ledger,indent=2))
                store.legacy(path,replica)
            return store.archive(root/"cohorts")
        finally:store.close()

    def test_exact_reducer_matches_legacy_mixed_censored_duplicate_population(self):
        ledgers=mixed()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=self.archive(root,ledgers)
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0,1,2],10)
            self.assertEqual(result["cohort"],summarize_cohorts(ledgers,correct_replicas=[0,1,2],deadline_ms=10))
            self.assertEqual(result["agreement"]["common_prefix_length"],2)
            self.assertEqual(result["mean_latency_ms"],3)
            self.assertEqual(result["cohort"]["unfinished"],2)

    def test_zero_output_remains_accounted(self):
        ledgers=mixed()
        for ledger in ledgers.values():
            ledger["outputs"]=[];ledger["batches"]=[]
            for row in ledger["requests"]:row["materialized_us"]=None
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=self.archive(root,ledgers)
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0,1,2,3],10)
            self.assertEqual(result["cohort"]["unfinished"],3)
            self.assertIsNone(result["mean_latency_ms"])

    def test_stalled_replica_does_not_hide_longer_conflicting_prefix(self):
        ledgers=mixed();ledgers[0]["outputs"]=[]
        ledgers[2]["outputs"][1]["request_id"]="conflict"
        with tempfile.TemporaryDirectory() as directory:
            archive=self.archive(Path(directory),ledgers)
            with self.assertRaisesRegex(ValueError,"prefixes disagree"):
                native.prefix_agreement(archive,[0,1,2])

    def test_native_journal_identity_and_late_events_match_legacy_replay(self):
        key=mysticeti.cohort_request_id(0,0,8)
        rows=[{"event":"start","origin":0,"count":2,"rate":1000,"useful_bytes":8,"elapsed_us":0,
               "window_start_us":0,"window_end_us":2000,"observed_us":5000},
              {"event":"admitted","request_id":key,"elapsed_us":10},
              {"event":"batch_ready","request_id":key,"elapsed_us":20},
              {"event":"batch","exact_batch_id":"a","payload_bytes":48,"elapsed_us":30},
              {"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
               "output_index":0,"exact_batch_id":"a","elapsed_us":30},
              {"event":"admitted","request_id":mysticeti.cohort_request_id(0,1,8),"elapsed_us":5001}]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/"journal.jsonl";path.write_text("".join(json.dumps(row)+"\n" for row in rows))
            store=native.NativeStore(root/"stage.sqlite")
            try:
                store.mysticeti(path,0,mysticeti.cohort_request_id);archive=store.archive(root/"cohorts")
            finally:store.close()
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0],10)
            self.assertEqual(result["cohort"],summarize_cohorts({0:mysticeti.read_cohort(path,0)},deadline_ms=10))
            rows[4]["request_id"]="not-the-content"
            path.write_text("".join(json.dumps(row)+"\n" for row in rows))
            store=native.NativeStore(root/"bad.sqlite")
            try:
                with self.assertRaisesRegex(ValueError,"content differs"):store.mysticeti(path,0,mysticeti.cohort_request_id)
            finally:store.close()

    def test_mysticeti_preplay_output_remains_uncredited_after_later_admission(self):
        key=mysticeti.cohort_request_id(0,0,8)
        rows=[{"event":"start","origin":0,"count":1,"rate":1000,"useful_bytes":8,"elapsed_us":0,
               "window_start_us":0,"window_end_us":1000,"observed_us":5000},
              {"event":"batch","exact_batch_id":"a","payload_bytes":48,"elapsed_us":5},
              {"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
               "output_index":0,"exact_batch_id":"a","elapsed_us":6,"origin_eligible":False},
              {"event":"admitted","request_id":key,"elapsed_us":10},
              {"event":"batch_ready","request_id":key,"elapsed_us":20}]
        for output_us in (6,10):
            rows[2]["elapsed_us"]=output_us
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/"journal.jsonl";path.write_text("".join(json.dumps(row)+"\n" for row in rows))
                store=native.NativeStore(root/"stage.sqlite")
                try:
                    store.mysticeti(path,0,mysticeti.cohort_request_id);archive=store.archive(root/"archive")
                finally:store.close()
                self.assertEqual(len(list(archive.rows(0,"outputs"))),1)
                self.assertIsNone(next(archive.rows(0,"requests"))["materialized_us"])
                result=native.reduce_archive(archive,root/"reduced.sqlite",[0],1)
                self.assertEqual(result["cohort"]["finite_run"]["unique_honest_completion_count"],0)
                self.assertEqual(result["cohort"]["unfinished"],1)
                self.assertEqual(result["finite_output_receipt"]["all_correct_completed"],0)
                self.assertEqual(result["finite_output_receipt"]["origins"][0]["all_correct_completed"],0)
    
    def test_journal_rejects_partial_and_oversized_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"j"
            for data in (b'{"event":"start"}',b'{"event":"'+b'a'*100+b'"}\n'):
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError,"oversized or truncated"):list(native.journal_rows(path,64))

    def test_mysticeti_full_compact_parity_without_own_ready_or_with_later_ready(self):
        from mysticeti_receipts_test import Fixture as ReceiptFixture
        import mysticeti_receipts
        key=mysticeti.cohort_request_id(0,0,8)
        for ready_us in (None,40):
            rows=[{"event":"start","origin":0,"count":1,"rate":1000,"useful_bytes":8,"elapsed_us":0,
                   "window_start_us":0,"window_end_us":1000,"observed_us":5000},
                  {"event":"admitted","request_id":key,"elapsed_us":10},
                  {"event":"batch","exact_batch_id":"a","payload_bytes":48,"elapsed_us":30},
                  {"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
                   "output_index":0,"exact_batch_id":"a","elapsed_us":30,"origin_eligible":True}]
            if ready_us is not None:rows.append({"event":"batch_ready","request_id":key,"elapsed_us":ready_us})
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/"journal.jsonl";path.write_text("".join(json.dumps(row)+"\n" for row in rows))
                store=native.NativeStore(root/"stage.sqlite")
                try:store.mysticeti(path,0,mysticeti.cohort_request_id);archive=store.archive(root/"archive")
                finally:store.close()
                result=native.reduce_archive(archive,root/"reduce.sqlite",[0],1)
                compact=ReceiptFixture(root/"compact",mode="compact",ready=int(ready_us is not None)).batch("aa00",[(0,b"x"*48)]).save()
                receipt=mysticeti_receipts.summarize({0:compact},[0])
                self.assertFalse(archive.ledgers[0]["batch_ready_precedes_materialization"])
                self.assertEqual(result["cohort"]["completed"],receipt["local_completed"])
                self.assertEqual(result["cohort"]["finite_run"]["u_out_bytes"],receipt["reference_unique_eligible_u_out_bytes"])
                self.assertEqual(result["cohort"]["finite_run"]["m_out_bytes"],receipt["reference_m_out_bytes"])
                self.assertEqual(next(archive.rows(0,"requests"))["batch_ready_us"],ready_us)

    def test_mysticeti_actual_freeze_retains_late_output_without_moving_deadline(self):
        key=mysticeti.cohort_request_id(0,0,8)
        rows=[{"event":"start","origin":0,"count":1,"rate":1000,"useful_bytes":8,"elapsed_us":0,
               "window_start_us":0,"window_end_us":1000,"observed_us":5000},
              {"event":"admitted","request_id":key,"elapsed_us":10},
              {"event":"batch_ready","request_id":key,"elapsed_us":20},
              {"event":"batch","exact_batch_id":"a","payload_bytes":48,"elapsed_us":5500},
              {"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
               "output_index":0,"exact_batch_id":"a","elapsed_us":5501,"origin_eligible":True}]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/"journal.jsonl";path.write_text("".join(json.dumps(row)+"\n" for row in rows))
            for name,endpoint,completed in (("declared",None,0),("frozen",6000,1)):
                store=native.NativeStore(root/(name+".sqlite"))
                try:
                    store.mysticeti(path,0,mysticeti.cohort_request_id,observed_us=endpoint)
                    archive=store.archive(root/name)
                finally:store.close()
                result=native.reduce_archive(archive,root/(name+"-reduced.sqlite"),[0],1)
                self.assertEqual(result["cohort"]["completed"],completed)
                self.assertEqual(result["cohort"]["deadline_missed"],1)
                if endpoint is not None:
                    self.assertEqual(archive.ledgers[0]["declared_observed_us"],5000)
                    self.assertEqual(archive.ledgers[0]["observed_us"],6000)
            for invalid in (4999,True,2**64):
                store=native.NativeStore(root/(str(invalid)+".sqlite"))
                try:
                    with self.assertRaisesRegex(ValueError,"freeze endpoint"):
                        store.mysticeti(path,0,mysticeti.cohort_request_id,observed_us=invalid)
                finally:store.close()

    def test_receipt_bound_own_output_requires_explicit_eligibility(self):
        key=mysticeti.cohort_request_id(0,0,8)
        start={"event":"start","origin":0,"count":1,"rate":1000,"useful_bytes":8,"elapsed_us":0,
               "window_start_us":0,"window_end_us":1000,"observed_us":5000}
        output={"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
                "output_index":0,"exact_batch_id":"a","elapsed_us":30}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for case in ("missing","null","true","false","legacy"):
                row=dict(output)
                if case in ("null","true","false"):row["origin_eligible"]={"null":None,"true":True,"false":False}[case]
                rows=[start,{"event":"admitted","request_id":key,"elapsed_us":10},row]
                path=root/(case+".jsonl");path.write_text("".join(json.dumps(r)+"\n" for r in rows))
                store=native.NativeStore(root/(case+".sqlite"))
                try:
                    if case in ("missing","null"):
                        with self.assertRaisesRegex(ValueError,"explicit append-time eligibility"):
                            store.mysticeti(path,0,mysticeti.cohort_request_id,observed_us=5001)
                    else:
                        store.mysticeti(path,0,mysticeti.cohort_request_id,observed_us=None if case=="legacy" else 5001)
                        request=next(store.rows(0,"requests"))
                        self.assertEqual(request["materialized_us"],None if case=="false" else 30)
                finally:store.close()

    def test_archived_native_diagnostic_events_are_accepted_without_invented_rejection(self):
        path=Path(__file__).resolve().parents[1]/"benchmarks/fixtures/mysticeti-native-journal-prefix-2026-10-19.jsonl"
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);store=native.NativeStore(root/"stage.sqlite")
            try:
                store.mysticeti(path,0,mysticeti.cohort_request_id);archive=store.archive(root/"cohorts")
            finally:store.close()
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0],1000)
            self.assertEqual(result["cohort"],summarize_cohorts({0:mysticeti.read_cohort(path,0)},deadline_ms=1000))
            self.assertTrue(any("native_enqueued_us" in row for row in archive.rows(0,"requests")))

    def test_sparse_workload_journal_cannot_claim_complete_native_prefix(self):
        key=mysticeti.cohort_request_id(0,0,8)
        rows=[{"event":"start","origin":0,"count":1,"rate":1000,"useful_bytes":8,"elapsed_us":0,
               "window_start_us":0,"window_end_us":1000,"observed_us":5000},
              {"event":"admitted","request_id":key,"elapsed_us":10},
              {"event":"batch_ready","request_id":key,"elapsed_us":20},
              {"event":"batch","exact_batch_id":"a","payload_bytes":100,"elapsed_us":30},
              {"event":"materialized","origin":0,"sequence":0,"useful_bytes":8,"request_id":key,
               "output_index":2,"exact_batch_id":"a","elapsed_us":30}]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/"journal.jsonl";path.write_text("".join(json.dumps(row)+"\n" for row in rows))
            store=native.NativeStore(root/"stage.sqlite")
            try:store.mysticeti(path,0,mysticeti.cohort_request_id);archive=store.archive(root/"cohorts")
            finally:store.close()
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0],10)
            self.assertEqual(result["agreement"]["native_order_fidelity"]["status"],"incomplete")
            self.assertEqual(result["agreement"]["native_terminal_prefix"][0],{"count":3,"kind":"lower_bound"})
            self.assertIsNone(archive.ledgers[0]["native_terminal_output_count"])

    def test_missing_batch_ready_is_allowed_only_when_explicitly_unobservable(self):
        ledgers=mixed();ledgers[0]["requests"][0]["batch_ready_us"]=None
        with self.assertRaisesRegex(ValueError,"preceding stage"):summarize_cohorts(ledgers)
        ledgers[0]["batch_ready_available"]=False
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=self.archive(root,ledgers)
            result=native.reduce_archive(archive,root/"reduce.sqlite",[0,1,2,3],10)
            self.assertEqual(result["cohort"],summarize_cohorts(ledgers,deadline_ms=10))

    def test_streamed_json_validates_ignored_values_and_trailing_evidence(self):
        valid={"requests":[],"outputs":[],"batches":[],"diagnostic":{"array":[1,"unicode\u2603",None,True]}}
        list(native.JsonStream(io.StringIO(json.dumps(valid))).ledger_items())
        for raw in ('{"requests":[],"outputs":[],"batches":[],"ignored":[1,]}',
                    json.dumps(valid)+'junk','{"requests":[],"outputs":[],"batches":[],}'):
            with self.assertRaises(ValueError):list(native.JsonStream(io.StringIO(raw)).ledger_items())

    def test_large_ignored_receipt_and_many_rows_do_not_become_python_populations(self):
        class BoundedRead(io.StringIO):
            def read(self,size=-1):
                if not 0<=size<=native.READ_CHUNK:raise AssertionError("unbounded read")
                return super().read(size)
        raw='{"requests":['+','.join(json.dumps({"sequence":i}) for i in range(5000))+'],"outputs":[],"batches":[],"compact_receipt":{"bits":"'+'0'*500000+'"}}'
        stream=BoundedRead(raw);tracemalloc.start()
        count=sum(field=="requests" for field,row in native.JsonStream(stream).ledger_items())
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        self.assertEqual(count,5000)
        self.assertLess(peak,1024*1024)


if __name__=="__main__":unittest.main()
