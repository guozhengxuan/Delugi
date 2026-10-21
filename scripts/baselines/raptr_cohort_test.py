import ctypes
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import raptr_cohort as cohort
from mysticeti_wal import Ed25519Verifier
from native_cohort_store import NativeStore, reduce_archive


def uleb(value):
    raw = bytearray()
    while value >= 128:
        raw.append((value & 127) | 128); value >>= 7
    return bytes(raw + bytes([value]))


def signed_fixture(origin=0, sequence=0, useful=8, run="11" * 16, marker=cohort.MAGIC):
    """Locally signed synthetic BCS, never evidence of a native protocol run."""
    verifier = Ed25519Verifier(); lib = verifier.lib; pointer = ctypes.c_void_p
    for name, args, result in [
        ("EVP_PKEY_new_raw_private_key_ex", [pointer, ctypes.c_char_p, ctypes.c_char_p, pointer, ctypes.c_size_t], pointer),
        ("EVP_PKEY_get_raw_public_key", [pointer, pointer, pointer], ctypes.c_int),
        ("EVP_DigestSignInit", [pointer, pointer, pointer, pointer, pointer], ctypes.c_int),
        ("EVP_DigestSign", [pointer, pointer, pointer, pointer, ctypes.c_size_t], ctypes.c_int),
    ]:
        function = getattr(lib, name); function.argtypes = args; function.restype = result
    private = lib.EVP_PKEY_new_raw_private_key_ex(None, b"ED25519", None, bytes([0x42 + origin]) * 32, 32)
    public = ctypes.create_string_buffer(32); size = ctypes.c_size_t(32)
    assert lib.EVP_PKEY_get_raw_public_key(private, public, ctypes.byref(size)) == 1
    key = public.raw
    code = marker + bytes.fromhex(run) + struct.pack("<QQQ", origin, sequence, useful) + bytes((origin + sequence + i) % 251 for i in range(useful))
    raw = hashlib.sha3_256(key + b"\0").digest() + struct.pack("<Q", sequence) + b"\0" + uleb(len(code)) + code + b"\0\0" + struct.pack("<QQQ", 1000000, 1, 4000000000) + b"\x04"
    message = hashlib.sha3_256(b"APTOS::RawTransaction").digest() + raw
    context = lib.EVP_MD_CTX_new(); signature = ctypes.create_string_buffer(64); size = ctypes.c_size_t(64)
    try:
        assert lib.EVP_DigestSignInit(context, None, None, None, private) == 1
        assert lib.EVP_DigestSign(context, signature, ctypes.byref(size), message, len(message)) == 1
    finally:
        lib.EVP_MD_CTX_free(context); lib.EVP_PKEY_free(private)
    return raw + b"\0\x20" + key + b"\x40" + signature.raw


def plan_row(origin=0, sequence=0):
    raw = signed_fixture(origin, sequence)
    return cohort.decode_signed_workload(raw) | {"bcs_hex": raw.hex()}


def admissions(plan, at=50):
    return [{key: row[key] for key in ("request_id", "origin", "sequence", "useful_bytes")} |
            {"scheduled_us": 0, "admitted_us": at, "batch_ready_us": None, "materialized_us": None,
             "rejected_us": None, "rejection_reason": None} for row in plan]


class RaptrCohortTests(unittest.TestCase):
    def store(self, root, count=1):
        rows = [plan_row(sequence=i) for i in range(count)]
        path = root / 'plan.jsonl'; path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        store = NativeStore(root / 'staging.sqlite')
        cohort.prepare_plan_store(store, [path], '11' * 16, [count], 8)
        self.addCleanup(store.db.close)
        return store, rows

    def events(self, row, eligibility, times):
        result = [{'event': 'batch', 'exact_batch_id': 'aa' * 88, 'unique_batch': True, 'payload_bytes': 100, 'materialized_us': min(times)}]
        for index, (eligible, timestamp) in enumerate(zip(eligibility, times)):
            result.append({'event': 'output', 'request_id': row['request_id'], 'native_txn_hash': row['request_id'],
                           'origin': 0, 'sequence': 0, 'useful_bytes': 8, 'output_index': index,
                           'exact_batch_id': 'aa' * 88, 'materialized_us': timestamp, 'origin_eligible': eligible})
        return result

    def test_authenticated_bcs_native_identity_and_domain(self):
        raw = signed_fixture(); decoded = cohort.decode_signed_workload(raw)
        self.assertEqual(decoded['request_id'], cohort.transaction_hash(raw))
        self.assertEqual(decoded['serialized_bytes'], len(raw))
        altered = bytearray(raw); altered[-1] ^= 1
        with self.assertRaisesRegex(ValueError, 'signature'):
            cohort.decode_signed_workload(altered)
        with self.assertRaisesRegex(ValueError, 'marker'):
            cohort.decode_signed_workload(signed_fixture(marker=b'DLGCOH02'))
        with self.assertRaises(ValueError):
            cohort.decode_signed_workload(raw + b'extra')

    def test_noncanonical_bcs_and_unbounded_populations_rejected(self):
        with self.assertRaisesRegex(ValueError, 'noncanonical'):
            cohort.BCSReader(b'\x80\0').uleb()
        for counts in ([True], [-1], [5_000_001], [0] * 32):
            with self.assertRaisesRegex(ValueError, 'population'):
                cohort.configuration('11' * 16, counts, 8)

    def test_plan_binding_count_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); row = plan_row(); path = root / 'plan.jsonl'
            path.write_text(json.dumps(row) + '\n')
            self.assertEqual(len(list(cohort.iter_plan(path, '11' * 16, 0, 1, 8))), 1)
            with self.assertRaisesRegex(ValueError, 'configuration'):
                list(cohort.iter_plan(path, '22' * 16, 0, 1, 8))
            row['request_id'] = 'ff' * 32; path.write_text(json.dumps(row) + '\n')
            with self.assertRaisesRegex(ValueError, 'authenticated'):
                list(cohort.iter_plan(path, '11' * 16, 0, 1, 8))
            path.write_text('')
            with self.assertRaisesRegex(ValueError, 'count'):
                list(cohort.iter_plan(path, '11' * 16, 0, 1, 8))

    def test_preplay_earlier_and_same_microsecond_never_gains_credit(self):
        for admitted_at in (100, 101):
            with self.subTest(admitted_at=admitted_at), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); store, rows = self.store(root)
                cohort.collect_store(store, 0, admissions(rows, admitted_at), self.events(rows[0], [False, False], [100, 102]), 0, 0, 110, 0, observed_us=110)
                archive = store.archive(root / 'archive')
                reduced = reduce_archive(archive, root / 'reduce.sqlite', [0], 1)
                self.assertEqual(reduced['finite_output_receipt']['all_correct_completed'], 0)
                self.assertEqual(reduced['cohort']['window']['unique_useful_output_bytes'], 0)
                self.assertEqual(store.serial[(0, 'outputs')], 2)

    def test_preplay_false_to_true_duplicate_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); store, rows = self.store(root)
            with self.assertRaisesRegex(ValueError, 'retroactive'):
                cohort.collect_store(store, 0, admissions(rows, 100), self.events(rows[0], [False, True], [100, 102]), 0, 0, 110, 0, observed_us=110)

    def test_first_eligible_completion_before_own_batching_is_valid(self):
        for ready_at in (None, 105):
            with self.subTest(ready_at=ready_at), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); store, rows = self.store(root)
                stages = [] if ready_at is None else [{'event': 'batch_ready', 'request_id': rows[0]['request_id'], 'observed_us': ready_at}]
                cohort.collect_store(store, 0, admissions(rows), self.events(rows[0], [True, False], [100, 102]), 0, 0, 110, 0, observed_us=110, stages=stages)
                reduced = reduce_archive(store.archive(root / 'archive'), root / 'reduce.sqlite', [0], 1)
                self.assertEqual(reduced['finite_output_receipt']['all_correct_completed'], 1)
                request = json.loads(store.db.execute("SELECT body FROM rows WHERE stream='requests'").fetchone()[0])
                self.assertEqual(request['materialized_us'], 100)
                self.assertEqual(request.get('batch_ready_us'), ready_at)

    def test_unknown_output_retains_actual_ordinal_without_useful_credit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); store, rows = self.store(root)
            events = self.events(rows[0], [False], [100]); events[-1].update(event='uncredited_output', request_id='ff' * 32, native_txn_hash='ff' * 32, origin=-1, useful_bytes=0)
            cohort.collect_store(store, 0, admissions(rows), events, 0, 0, 110, 0, observed_us=110)
            self.assertEqual(store.serial[(0, 'outputs')], 1)
            self.assertIsNone(json.loads(store.db.execute("SELECT body FROM rows WHERE stream='requests'").fetchone()[0])['materialized_us'])

    def test_missing_and_non_boolean_eligibility_rejected(self):
        for flag in (None, 1, 'false'):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); store, rows = self.store(root)
                events = self.events(rows[0], [flag], [100])
                with self.assertRaisesRegex(ValueError, 'Boolean'):
                    cohort.collect_store(store, 0, admissions(rows), events, 0, 0, 110, 0, observed_us=110)

    def test_unfinished_empty_and_truncated_admission_population(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); store, rows = self.store(root, 2)
            with self.assertRaisesRegex(ValueError, 'lost finite'):
                cohort.collect_store(store, 0, admissions(rows[:1]), [], 0, 0, 100, 0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); store, rows = self.store(root, 0)
            cohort.collect_store(store, 0, [], [], 0, 0, 100, 0)
            reduced = reduce_archive(store.archive(root / 'archive'), root / 'reduce.sqlite', [0], 1)
            self.assertEqual(reduced['finite_output_receipt']['planned'], 0)

    def test_native_insertion_is_diagnostic_not_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); store, rows = self.store(root)
            stages = [{'event': 'native_admitted', 'request_id': rows[0]['request_id'], 'observed_us': 70}]
            cohort.collect_store(store, 0, admissions(rows, 50), self.events(rows[0], [True], [100]), 0, 0, 110, 0, stages=stages)
            request = json.loads(store.db.execute("SELECT body FROM rows WHERE stream='requests'").fetchone()[0])
            self.assertEqual((request['admitted_us'], request['native_admitted_us'], request['materialized_us']), (50, 70, 100))


if __name__ == '__main__':
    unittest.main()
