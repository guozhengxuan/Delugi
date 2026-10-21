import copy
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile
import tracemalloc
import unittest
from unittest.mock import Mock, MagicMock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from cohort_metrics import summarize_cohorts
from cohort_store import CohortDatabase, ShardedArchive, collect_sharded, MAX_PAGE_BYTES, safe_path
from cohort_metrics_test import fixture
from run_network import Controller, written_categories


def reduce_disk(data, **options):
    with tempfile.TemporaryDirectory() as directory:
        store=CohortDatabase(Path(directory)/"cohort.sqlite",data)
        try:
            store.ingest(lambda replica,stream:iter(data[replica][stream]))
            return store.summarize(**options)
        finally:store.close()


class DiskExactCohorts(unittest.TestCase):
    def test_same_microsecond_requires_latched_local_completion(self):
        for eligible in (False, True):
            with self.subTest(eligible=eligible):
                data = fixture()
                data[0]["requests"][0].update(admitted_us=5000, batch_ready_us=5000,
                    materialized_us=5000 if eligible else None)
                actual = reduce_disk(data)
                self.assertEqual(actual, summarize_cohorts(data))
                self.assertEqual(actual["window"]["completion_count"], int(eligible))
                self.assertEqual(actual["window"]["u_out_bytes"], 100 * eligible)
                self.assertEqual(actual["window"]["m_out_bytes"], 168)
                self.assertEqual(actual["finite_run"]["u_out_bytes"], 100 * eligible)
                self.assertEqual(actual["completed"], int(eligible))
                self.assertEqual(actual["unfinished"], int(not eligible))

    def test_admitted_output_may_precede_independent_own_batch_stage(self):
        for readiness in (None, 6000):
            with self.subTest(readiness=readiness):
                data=fixture()
                data[0]["requests"][0]["batch_ready_us"]=readiness
                with self.assertRaises(ValueError): reduce_disk(data)
                for ledger in data.values(): ledger["batch_ready_precedes_materialization"]=False
                actual=reduce_disk(data)
                self.assertEqual(actual,summarize_cohorts(data))
                self.assertEqual(actual["completed"],1)
                self.assertEqual(actual["window"]["completion_count"],1)
                self.assertEqual(actual["finite_run"]["unique_honest_completion_count"],1)
                self.assertEqual(actual["admission_to_output"]["p99"]["value_ms"],3)
                data[0]["requests"][0]["admitted_us"]=None
                with self.assertRaises(ValueError): reduce_disk(data)

    def test_stability_uses_own_clock_and_half_open_boundaries(self):
        data=fixture()
        baseline=reduce_disk(data)["window"]["stability"]
        self.assertEqual(sum(row["completed"] for row in baseline["intervals"]),1)
        for replica,ledger in data.items():
            offset=2**60+(replica+1)*1000000000
            for key in ("window_start_us","window_end_us","observed_us"):
                ledger[key]+=offset
            for stream in ("requests","outputs","batches"):
                for row in ledger[stream]:
                    for key in tuple(row):
                        if key.endswith("_us") and row[key] is not None:row[key]+=offset
        self.assertEqual(reduce_disk(data)["window"]["stability"],baseline)
        self.assertEqual(reduce_disk(data),summarize_cohorts(data))

    def test_matches_small_complete_and_zero_output(self):
        data=fixture()
        self.assertEqual(reduce_disk(data),summarize_cohorts(data))
        data[0]["requests"][0]["materialized_us"]=None
        for ledger in data.values():ledger.update(outputs=[],batches=[])
        self.assertEqual(reduce_disk(data),summarize_cohorts(data))

    def test_generated_mixed_populations_match_every_field(self):
        for seed in range(12):
            rng=random.Random(seed)
            data={i:{"requests":[],"outputs":[],"batches":[],"window_start_us":2000,
                     "window_end_us":5000,"observed_us":7000,"output_index_base":1} for i in range(4)}
            ordinal=0
            for origin in range(4):
                for sequence in range(30):
                    scheduled=1000+sequence*150
                    admitted=scheduled+rng.randrange(1,20)
                    done=admitted+rng.randrange(20,1000)
                    outcome=rng.choice(["complete","complete","pending","rejected"])
                    row={"request_id":f"{origin}-{sequence}","origin":origin,"sequence":sequence,"useful_bytes":100,
                        "scheduled_us":scheduled,"admitted_us":admitted if outcome!="rejected" else None,
                        "batch_ready_us":admitted+5 if outcome!="rejected" else None,
                        "materialized_us":done if outcome=="complete" else None,
                        "rejected_us":admitted if outcome=="rejected" else None,
                        "all_correct_observed_us":done+100 if outcome=="complete" and rng.random()<.7 else None}
                    data[origin]["requests"].append(row)
                    if outcome!="complete":continue
                    ordinal+=1
                    for replica,ledger in data.items():
                        if replica!=origin and rng.random()<.15:continue
                        output={"request_id":row["request_id"],"origin":origin,"useful_bytes":100,
                            "output_index":ordinal,"materialized_us":done,"exact_batch_id":f"batch-{ordinal}"}
                        ledger["outputs"].append(output)
                        ledger["batches"].append({"exact_batch_id":output["exact_batch_id"],"payload_bytes":168,"materialized_us":done})
                    if rng.random()<.2:
                        ordinal+=1
                        for replica,ledger in data.items():
                            ledger["outputs"].append({**output,"output_index":ordinal,"materialized_us":done+1})
            for ledger in data.values():ledger["output_prefix_count"]=ordinal
            with self.subTest(seed=seed):
                self.assertEqual(reduce_disk(data,correct_replicas=[1,2,3],deadline_ms=1),
                                 summarize_cohorts(data,correct_replicas=[1,2,3],deadline_ms=1))

    def test_identity_mismatch_and_duplicate_admission_rejected(self):
        data=fixture();data[2]["outputs"][0]["useful_bytes"]=101
        with self.assertRaisesRegex(ValueError,"identity content"):reduce_disk(data)
        data=fixture();data[0]["requests"].append(data[0]["requests"][0])
        with self.assertRaisesRegex(ValueError,"duplicate request"):reduce_disk(data)

    def test_receipt_horizon_and_post_handler_publication_are_separate_from_freeze(self):
        data=fixture()
        for ledger in data.values():ledger["collected_us"]=30000
        row=data[0]["requests"][0]
        row["all_correct_observed_us"]=25000
        row["post_handler_published_us"]=21000
        self.assertEqual(reduce_disk(data),summarize_cohorts(data))
        row["all_correct_observed_us"]=30001
        for reducer in (reduce_disk,summarize_cohorts):
            with self.assertRaisesRegex(ValueError,"exceeds collection"):reducer(data)
        row["all_correct_observed_us"]=25000
        row["post_handler_published_us"]=4999
        for reducer in (reduce_disk,summarize_cohorts):
            with self.assertRaisesRegex(ValueError,"publication"):reducer(data)

    def test_unknown_and_unadmitted_outputs_are_retained_but_receive_no_useful_credit(self):
        data=fixture();request=data[0]["requests"][0]
        request.update(admitted_us=None,batch_ready_us=None,materialized_us=None)
        for ledger in data.values():
            ledger["outputs"].append({"request_id":"unknown","origin":1,"useful_bytes":100,
                "output_index":2,"materialized_us":6000,"exact_batch_id":"unknown-batch"})
            ledger["batches"].append({"exact_batch_id":"unknown-batch","payload_bytes":168,"materialized_us":6000})
        with tempfile.TemporaryDirectory() as directory:
            store=CohortDatabase(Path(directory)/"cohort.sqlite",data)
            try:
                store.ingest(lambda replica,stream:iter(data[replica][stream]))
                result=store.summarize()
                self.assertEqual(result,summarize_cohorts(data))
                self.assertEqual(result["window"]["u_out_bytes"],0)
                self.assertEqual(result["window"]["m_out_bytes"],336)
                self.assertEqual(store.scalar("SELECT count(*) FROM outputs"),8)
                self.assertEqual(store.output_exclusions["by_replica"][0],{"unknown_request_ids":1,"unadmitted_request_ids":1})
            finally:store.close()

    def test_generated_n31_stream_has_bounded_python_working_memory(self):
        replicas, per_origin = 31, 128
        ledgers={i:{"window_start_us":0,"window_end_us":10000,"observed_us":20000,
                    "output_index_base":1,"output_prefix_count":replicas*per_origin} for i in range(replicas)}
        def rows(replica,stream):
            if stream=="requests":
                for sequence in range(per_origin):
                    scheduled=100+sequence*10
                    yield {"request_id":f"{replica}-{sequence}","origin":replica,"sequence":sequence,
                        "useful_bytes":472,"scheduled_us":scheduled,"admitted_us":scheduled+1,
                        "batch_ready_us":scheduled+2,"materialized_us":scheduled+3}
            elif stream=="outputs":
                for sequence in range(per_origin):
                    for origin in range(replicas):
                        yield {"request_id":f"{origin}-{sequence}","origin":origin,"useful_bytes":472,
                            "output_index":sequence*replicas+origin+1,"materialized_us":103+sequence*10}
            else:
                for sequence in range(per_origin):
                    yield {"exact_batch_id":f"batch-{sequence}","payload_bytes":replicas*532,
                           "materialized_us":103+sequence*10}
        with tempfile.TemporaryDirectory() as directory:
            tracemalloc.start()
            store=CohortDatabase(Path(directory)/"cohort.sqlite",ledgers)
            try:
                store.ingest(rows);result=store.summarize()
                _,peak=tracemalloc.get_traced_memory()
            finally:
                store.close();tracemalloc.stop()
            self.assertEqual(result["completed"],replicas*per_origin)
            self.assertEqual(result["all_correct_collection"]["completed"],replicas*per_origin)
            self.assertLess(peak,8*1024*1024)
            self.assertGreater(store.path.stat().st_size,peak)


class StreamingControllerAndTraffic(unittest.TestCase):
    def test_controller_spools_snapshots_and_only_archived_page_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            controller=Controller({"control_token":"token","control_addresses":["127.0.0.1:1"]},Path(directory),[Mock()],streaming=True)
            connection=MagicMock()
            connection.__enter__.return_value=connection
            replies=[{"request_id":"request-1","id":0,"ok":True,"data":{"elapsed_us":1}},
                     {"request_id":"request-2","id":0,"ok":True,"data":{"entries":[{"id":1}]}}]
            connection.makefile.return_value.readline.side_effect=[(json.dumps(row)+"\n").encode() for row in replies]
            with patch("run_network.socket.create_connection",return_value=connection):
                controller.request(0,"snapshot")
                record=controller.request(0,"cohort",offset=0,limit=1024)
            self.assertEqual(controller.commands,[])
            self.assertEqual(len((Path(directory)/"control.jsonl").read_text().splitlines()),1)
            record["reply"]["data"]={"external_cohort_page":{"path":"page.json","sha256":"digest"}}
            controller.archive_record(record);controller.save();controller.save()
            saved=[json.loads(line) for line in (Path(directory)/"control.jsonl").read_text().splitlines()]
            self.assertEqual(len(saved),2)
            self.assertNotIn("entries",saved[1]["reply"]["data"])

    def test_written_categories_conserve_and_legacy_is_explicitly_unavailable(self):
        peer={"ack_bytes_written":10,"layers":{"data":{"data_bytes_written":90}},
              "written_categories":{"payload_bytes":30,"evidence_control_bytes":20,"repair_bytes":40,
                                    "transport_overhead_bytes":10,"total_written_bytes":100}}
        snapshot={"transport":{"peers":{"1":peer}}}
        self.assertEqual(written_categories(snapshot)["total_written_bytes"],100)
        peer["written_categories"]["payload_bytes"]+=1
        with self.assertRaisesRegex(AssertionError,"conserve"):written_categories(snapshot)
        del peer["written_categories"]
        self.assertFalse(written_categories(snapshot)["available"])


class ShardedCollection(unittest.TestCase):
    def collect(self,directory):
        data=fixture();controller=Mock();records=[]
        def request(replica,kind,offset,limit):
            stream={"cohort":"requests","outputs":"outputs","batches":"batches"}[kind]
            rows=data[replica][stream]
            record={"reply":{"data":{"entries":rows[offset:offset+limit],"total":len(rows),"replica":replica,
                "next_offset":offset+limit if offset+limit<len(rows) else None,"manifest":None,"elapsed_us":20000}}}
            records.append(record);return record
        controller.request.side_effect=request
        snapshots={i:{"elapsed_us":20000,"executed_count":1,"load":{"start_elapsed_us":0}} for i in data}
        archive=collect_sharded(controller,snapshots,Path(directory)/"archive",0,.01)
        return archive,records,data

    def test_pages_are_hashed_and_controller_retains_only_references(self):
        with tempfile.TemporaryDirectory() as directory:
            archive,records,data=self.collect(directory)
            self.assertTrue(all("external_cohort_page" in record["reply"]["data"] for record in records))
            for replica in data:
                for stream in ("requests","outputs","batches"):
                    self.assertEqual(list(archive.rows(replica,stream)),data[replica][stream])
            store=CohortDatabase(Path(directory)/"cohort.sqlite",archive.ledgers)
            try:
                store.ingest(archive.rows)
                self.assertEqual(store.summarize(),summarize_cohorts(data))
            finally:store.close()

    def test_modified_page_and_index_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive,_,_=self.collect(directory)
            path=archive.root/"replica-0/requests-00000000.json"
            path.write_bytes(path.read_bytes()+b" ")
            with self.assertRaisesRegex(ValueError,"digest/size"):list(archive.rows(0,"requests"))
        with tempfile.TemporaryDirectory() as directory:
            archive,_,_=self.collect(directory)
            path=archive.root/"replica-0/requests.index.jsonl"
            path.write_text(path.read_text().replace('"offset":0','"offset":1'))
            with self.assertRaisesRegex(ValueError,"offsets"):list(archive.rows(0,"requests"))

    def test_repeated_terminal_empty_page_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive,_,_=self.collect(directory)
            descriptor=archive.ledgers[1]["streams"]["requests"]
            path=archive.root/descriptor["path"]
            raw=path.read_bytes()*2
            path.write_bytes(raw)
            descriptor.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),pages=2)
            with self.assertRaisesRegex(ValueError,"terminal"):list(archive.rows(1,"requests"))

    def test_path_escape_symlink_and_oversized_page_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            archive,_,_=self.collect(directory)
            with self.assertRaisesRegex(ValueError,"relative"):safe_path(archive.root,"../outside")
            (archive.root/"link").symlink_to(archive.root/"index.json")
            with self.assertRaisesRegex(ValueError,"symlink"):safe_path(archive.root,"link")
            path=archive.root/"replica-0/requests-00000000.json"
            with path.open("wb") as target:target.truncate(MAX_PAGE_BYTES+1)
            with self.assertRaisesRegex(ValueError,"bounded read"):list(archive.rows(0,"requests"))


if __name__=="__main__":unittest.main()
