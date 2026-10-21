import json
from pathlib import Path
import tempfile
import threading
import unittest

import raptr_ingress as ingress


def plan(count):
    for index in range(count):
        yield {'request_id': f'{index:064x}', 'origin': 0, 'sequence': index,
               'useful_bytes': 8, 'bcs_hex': index.to_bytes(8, 'little').hex()}


class IndependentIngressTests(unittest.TestCase):
    def run_case(self, directory, rows, **kwargs):
        settings = dict(rate=100000, epoch_us=ingress.monotonic_us() + 5000,
                        warmup_us=0, duration_us=150000, drain_us=150000,
                        on_admit=lambda _: None,
                        submit=lambda *_: (202, ''), max_batch_transactions=1)
        settings.update(kwargs)
        result = ingress.run_origin(rows, directory/'requests.jsonl', directory/'events.jsonl',
                                    'http://127.0.0.1:1', **settings)
        saved = [json.loads(line) for line in (directory/'requests.jsonl').read_text().splitlines()]
        return result, saved

    def test_arrivals_continue_while_first_http_waits_and_bitmap_is_published(self):
        ahead = threading.Event()
        published = set()
        first = True

        def admit(sequence):
            published.add(sequence)
            if sequence >= 20:
                ahead.set()

        def submit(_, batch, timeout):
            nonlocal first
            self.assertTrue(all(int.from_bytes(raw, 'little') in published for raw in batch))
            if first:
                first = False
                self.assertTrue(ahead.wait(1), 'HTTP response incorrectly gated future arrivals')
            return 202, ''

        with tempfile.TemporaryDirectory() as temp:
            result, rows = self.run_case(Path(temp), plan(50), on_admit=admit, submit=submit)
        self.assertEqual((result['planned'], result['admitted'], result['native_queued']), (50, 50, 50))
        self.assertTrue(all(r['admitted_us'] <= r['native_submission_started_us'] <= r['native_queued_us'] for r in rows))

    def test_queue_backpressure_retains_every_planned_arrival(self):
        produced = threading.Event()

        def finite():
            yield from plan(80)
            produced.set()

        def submit(*_):
            self.assertTrue(produced.wait(1), 'publisher backpressure incorrectly blocked source schedule')
            return 202, ''

        with tempfile.TemporaryDirectory() as temp:
            result, rows = self.run_case(Path(temp), finite(), submit=submit, queue_capacity=4)
        self.assertEqual(len(rows), 80)
        self.assertGreater(result['rejected'], 0)
        self.assertLessEqual(result['maximum_queued'], 4)
        self.assertEqual(result['admitted'] + result['rejected'], 80)
        self.assertTrue(all(r['admitted_us'] is None for r in rows if r['rejected_us'] is not None))

    def test_downstream_rejection_and_ambiguity_do_not_erase_admission(self):
        calls = 0

        def submit(*_):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 503, 'native unavailable'
            raise TimeoutError('reply not observed')

        with tempfile.TemporaryDirectory() as temp:
            result, rows = self.run_case(Path(temp), plan(6), submit=submit, max_batch_transactions=3)
        self.assertEqual(result['admitted'], 6)
        self.assertEqual(result['native_rejected'] + result['ambiguous_submission'], 6)
        self.assertEqual(result['rejected'], 0)
        self.assertTrue(all(r['admitted_us'] is not None and r['materialized_us'] is None for r in rows))

    def test_finite_tail_is_retained_after_cutoff(self):
        with tempfile.TemporaryDirectory() as temp:
            result, rows = self.run_case(Path(temp), plan(8), epoch_us=ingress.monotonic_us()-100000,
                                         duration_us=1000, drain_us=0,
                                         submit=lambda *_: self.fail('submission after finite cutoff'))
        self.assertEqual((result['planned'], result['admitted'], result['unadmitted_at_cutoff']), (8, 0, 8))
        self.assertTrue(all(r['unadmitted_at_cutoff'] for r in rows))

    def test_bcs_batch_has_canonical_vector_length_and_exact_native_bytes(self):
        self.assertEqual(ingress.encode_batch([b'a', b'bc']), b'\x02abc')
        self.assertEqual(ingress.encode_batch([b'x']*128), b'\x80\x01'+b'x'*128)
        for batch in ([], [b''], [b'x']*1025, [b'x'*(ingress.MAX_TRANSACTION_BYTES+1)]):
            with self.assertRaises(ValueError):
                ingress.encode_batch(batch)

    def test_ordinal_gap_fails_and_preserves_partial_events(self):
        rows = list(plan(2));rows[1]['sequence'] = 4
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with self.assertRaisesRegex(ValueError, 'ordinal gap'):
                self.run_case(directory, rows)
            self.assertTrue((directory/'events.jsonl').is_file())
            self.assertFalse((directory/'requests.jsonl').exists())

    def test_body_bound_includes_vector_prefix(self):
        raw = b'x' * ingress.MAX_TRANSACTION_BYTES
        self.assertLess(len(ingress.encode_batch([raw] * 511)), ingress.MAX_BATCH_BYTES)
        with self.assertRaisesRegex(ValueError, 'API body bound'):
            ingress.encode_batch([raw] * 512)

    def test_zero_rate_requires_empty_plan(self):
        with tempfile.TemporaryDirectory() as temp:
            result, rows = self.run_case(Path(temp), iter(()), rate=0,
                submit=lambda *_: self.fail('empty origin submitted a batch'))
            self.assertEqual((result['planned'], result['admitted'], rows), (0, 0, []))
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'zero-rate'):
                self.run_case(Path(temp), plan(1), rate=0)


if __name__ == '__main__':
    unittest.main()
