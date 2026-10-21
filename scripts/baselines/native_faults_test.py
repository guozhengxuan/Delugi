import argparse
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import tracemalloc

spec=importlib.util.spec_from_file_location("native_faults",Path(__file__).with_name("native_faults.py"))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class NativeFaultScopeTests(unittest.TestCase):
    def args(self,**changes):
        values=dict(attacker_rate=100,omit_replica=0,publish_to_replica=[1],omit_repair=False,faulty_replica=[0],duration=5,nodes=4,omission_after=1,omission_seconds=2,pause_replica=None,crypto_meter="on",warmup=1,rate=1200)
        values.update(changes);return argparse.Namespace(**values)

    def test_faulty_identity_required(self):
        with self.assertRaisesRegex(ValueError,"fixed faulty"):
            module.validate(self.args(faulty_replica=[]),protocol="autobahn")

    def test_native_coupling_is_explicit(self):
        with self.assertRaisesRegex(ValueError,"inseparable"):
            module.validate(self.args(omit_repair=True),protocol="mysticeti")

    def test_scope_preserves_other_nodes(self):
        args=self.args(crypto_meter="off")
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            self.assertEqual(module.environment(args,output,2,{1:"peer1"}),{})
            env=module.environment(args,output,0,{1:"peer1"})
            self.assertEqual(env["BENCHMARK_FAULT_ALLOWED"],"peer1")
            schedule=module.arm(args,output,10_000_000_000)
            self.assertEqual((schedule["start_monotonic_ns"],schedule["end_monotonic_ns"]),(12_000_000_000,14_000_000_000))
            self.assertEqual(schedule["attacker_useful_credit"],0)

    def test_withdrawal_interval_required(self):
        with self.assertRaisesRegex(ValueError,"fit"):
            module.validate(self.args(omission_seconds=10),protocol="autobahn")

    def test_empty_omission_keeps_zero_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(module.collect_omissions(Path(directory))["messages_omitted"],0)

    def test_streamed_omission_totals_preserve_every_event_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            expected=0
            for replica in range(3):
                raw=b"".join((json.dumps({"kind":"payload_initial" if i%2 else "payload_repair",
                    "serialized_bytes_omitted":replica*100+i})+"\n").encode() for i in range(7))
                (output/f"omissions-{replica}-worker.jsonl").write_bytes(raw)
                expected+=sum(replica*100+i for i in range(7))
            with patch.object(Path,"read_text",side_effect=AssertionError("whole-file ingestion forbidden")):
                result=module.collect_omissions(output)
            self.assertEqual(result["messages_omitted"],21)
            self.assertEqual(result["serialized_bytes_omitted"],expected)
            self.assertEqual(result["by_native_unit"],{"payload_initial":9,"payload_repair":12})
            for row in result["journals"]:
                self.assertEqual(row["sha256"],hashlib.sha256((output/row["path"]).read_bytes()).hexdigest())
                self.assertEqual(row["events"],7)

    def test_large_journal_has_bounded_python_working_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)
            raw=b'{"kind":"own_signed_block","serialized_bytes_omitted":123}\n'
            with (output/"omissions-0-validator.jsonl").open("wb") as target:
                for _ in range(30000):target.write(raw)
            tracemalloc.start()
            result=module.collect_omissions(output)
            _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
            self.assertEqual(result["messages_omitted"],30000)
            self.assertEqual(result["serialized_bytes_omitted"],30000*123)
            self.assertLess(peak,256*1024)

    def test_malformed_truncated_oversized_and_invalid_counter_fail(self):
        bad=[b'{}',b'[]\n',b'{bad}\n',b'x'*(module.MAX_OMISSION_RECORD_BYTES+1)+b'\n']
        bad += [(json.dumps({"kind":"payload_initial","serialized_bytes_omitted":value})+"\n").encode()
                for value in (-1,True,1.5,2**64)]
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);path=output/"omissions-0-worker.jsonl"
            for raw in bad:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:80]),self.assertRaises(ValueError):module.collect_omissions(output)

    def test_symlinked_omission_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);(output/"raw").write_bytes(b'')
            (output/"omissions-0-worker.jsonl").symlink_to(output/"raw")
            with self.assertRaises(OSError):module.collect_omissions(output)

    def test_special_file_does_not_block_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);os.mkfifo(output/"omissions-0-worker.jsonl")
            with self.assertRaisesRegex(ValueError,"regular file"):module.collect_omissions(output)

if __name__=="__main__":unittest.main()
