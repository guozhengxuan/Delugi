from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import raptr_latency_decomposition as d


def event(name, at, **fields):
    return {'event': name, 'at_us': at, **fields}


class RaptrDecomposition(unittest.TestCase):
    def setUp(self):
        self.key = {'epoch': 1, 'author': '11'*32, 'nonce': 6, 'id': 4, 'digest': '22'*32}
        self.block = {'round': 5, 'digest': '33'*32}
        self.section = {'kind': 'sub_block', 'index': 3}
        self.events = [event('batch_stored', 102, batch=self.key),
                       event('availability_quorum', 107, batch=self.key),
                       event('proposal_validated', 105, **self.block),
                       event('committed', 111, **self.block, include_proofs=False, from_prefix=3, to_prefix=4),
                       event('payload_ready', 113, **self.block, section=self.section),
                       event('prefix_released', 117, **self.block, section=self.section)]
        self.request = {'request_id': '44'*32, 'sequence': 0, 'planned_us': 100, 'admitted_us': 101,
                        'first_materialized_us': 123, 'first_materialized_event': 4,
                        'rejected_us': None, 'cancelled_us': None}
        self.batch = {'key': self.key, 'transactions': [{'request_id': self.request['request_id'],
                       'origin': 0, 'sequence': 0, 'own_credit': True, 'eligible': True, 'first_seen': True}]}
        self.output = {'block': self.block, 'section': self.section, 'timing_contract': d.ENDPOINT,
                       'event': 4, 'app_processing_start_us': 119, 'append_us': 123,
                       'journal_constructed_us': 130, 'batches': [self.batch]}

    def stages(self, events=None, **changes):
        return d.request_stages(changes.get('request', self.request), changes.get('output', self.output),
                                changes.get('batch', self.batch), d.indexes(self.events if events is None else events))

    def test_additive_intervals_and_post_endpoint_journaling(self):
        stages, journal, availability = self.stages()
        self.assertEqual(stages, [1, 3, 6, 2, 4, 2, 4])
        self.assertEqual(sum(stages), self.output['append_us']-self.request['admitted_us'])
        self.assertEqual(journal, 7)
        self.assertEqual(availability, {'status': 'observed', 'duration_us': 5,
                                       'relative_to_proposal_us': 2, 'after_proposal': True})

    def test_overlapping_or_absent_availability_does_not_invent_a_stage(self):
        without_quorum = [e for e in self.events if e['event'] != 'availability_quorum']
        stages, _, availability = self.stages(without_quorum)
        self.assertEqual(stages, self.stages()[0])
        self.assertEqual(availability, {'status': 'missing'})
        events = deepcopy(self.events); events[1]['at_us'] = 101
        self.assertEqual(self.stages(events)[2], {'status': 'nonsequential'})

    def test_exact_batch_identity_and_proposal_digest_are_required(self):
        events = deepcopy(self.events); events[0]['batch'] = {**self.key, 'nonce': 7}
        with self.assertRaisesRegex(ValueError, 'missing_exact_batch'):
            self.stages(events)
        events = deepcopy(self.events); events[2]['digest'] = '55'*32
        with self.assertRaisesRegex(ValueError, 'missing_execution_proposal'):
            self.stages(events)

    def test_commit_prefix_extensions_join_the_actual_section(self):
        earlier = event('committed', 109, **self.block, include_proofs=True, from_prefix=0, to_prefix=3)
        self.assertEqual(self.stages([earlier, *self.events])[0][2], 6)
        events = [earlier, *[e for e in self.events if e['event'] != 'committed']]
        with self.assertRaisesRegex(ValueError, 'missing_execution_proposal_or_commit_slice'):
            self.stages(events)
        proof = {'kind': 'proofs'}
        events = [*events, event('payload_ready', 113, **self.block, section=proof),
                  event('prefix_released', 117, **self.block, section=proof)]
        self.assertEqual(self.stages(events, output={**self.output, 'section': proof})[0][2], 4)

    def test_nonsequential_points_and_missing_application_timestamps_are_excluded(self):
        for field, value in [('app_processing_start_us', 116), ('append_us', 118), ('journal_constructed_us', 120)]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'nonsequential'):
                self.stages(output={**self.output, field: value})
        with self.assertRaisesRegex(ValueError, 'missing_minimal_application_boundary'):
            self.stages(output={**self.output, 'timing_contract': 'old'})
        with self.assertRaisesRegex(ValueError, 'nonsequential'):
            self.stages(request={**self.request, 'planned_us': 102})
        events = deepcopy(self.events); events[2]['at_us'] = 115
        with self.assertRaisesRegex(ValueError, 'nonsequential'):
            self.stages(events)

    def fixture(self, root):
        root = Path(root); node = root/'replicas/node-0'; node.mkdir(parents=True)
        config = {'addresses': ['a', 'b', 'c', 'd'], 'run_id': '66'*32,
                  'measurement_duration_ms': 1, 'latency_trace': {'max_events': 100}}
        path = root/'config.json'; path.write_text(json.dumps(config))
        config_hash = d.native.sha256(path)
        trace = {'schema': 'raptr-latency-trace-v1', 'replica': 0, 'run_id': config['run_id'],
                 'configuration_sha256': config_hash, 'clock': 'CLOCK_MONOTONIC', 'max_events': 100,
                 'dropped': 0, 'events': self.events}
        unfinished = {**self.request, 'request_id': '77'*32, 'sequence': 1,
                      'first_materialized_us': None, 'first_materialized_event': None}
        missing = {**self.request, 'request_id': '88'*32, 'sequence': 2, 'first_materialized_event': 5}
        other_batch = deepcopy(self.batch); other_batch['key']['digest'] = '99'*32
        other_batch['transactions'][0].update(request_id=missing['request_id'], sequence=2)
        other_output = {**self.output, 'event': 5, 'batches': [other_batch]}
        files = {'latency-trace.json': trace, 'effective-profile.json': {'output_endpoint': d.ENDPOINT},
                 'requests.jsonl': [self.request, unfinished, missing], 'output.jsonl': [self.output, other_output]}
        for name, content in files.items():
            text = ''.join(json.dumps(row)+'\n' for row in content) if name.endswith('.jsonl') else json.dumps(content)
            (node/name).write_text(text)
        receipt = {'signer': 0, 'body': {'id': 0, 'run_id': config['run_id'], 'configuration_sha256': config_hash,
                   'status': 'completed', 'error': None, 'epoch_us': 100,
                   'files': [{'name': name, **d.native.file_record(node/name)} for name in files]}}
        (node/'final.json').write_text(json.dumps(receipt))
        return path, node, {'0': {'verified': True, 'receipt_sha256': d.native.sha256(node/'final.json')}}

    def refresh(self, node, auth):
        receipt = json.loads((node/'final.json').read_text())
        for descriptor in receipt['body']['files']:
            descriptor.update(d.native.file_record(node/descriptor['name']))
        (node/'final.json').write_text(json.dumps(receipt))
        auth['0']['receipt_sha256'] = d.native.sha256(node/'final.json')

    def analyze_fixture(self, path, node, auth):
        return d.analyze(path, node.parent, [0], authentication=auth)

    def test_receipt_bound_analysis_retains_coverage_and_same_cohort(self):
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            result = self.analyze_fixture(path, node, auth)
            self.assertEqual((result['scheduled'], result['admitted'], result['completed'], result['covered']), (3, 3, 2, 1))
            self.assertEqual(result['excluded'], {'unfinished_or_not_admitted': 1, 'missing_exact_batch_stored': 1})
            self.assertAlmostEqual(sum(s['mean_ms'] for s in result['stages']), .022)
            self.assertAlmostEqual(sum(s['mean_ms'] for s in result['common_stages']), .022)
            self.assertAlmostEqual(result['mean_schedule_to_append_ms'], .023)
            self.assertEqual(result['journal_construction_after_endpoint']['mean_ms'], .007)
            self.assertEqual(result['availability_quorum']['after_execution_proposal'], 1)
            self.assertEqual(result['serial_quorum_cohort']['covered'], 0)
            self.assertEqual(result['serial_quorum_cohort']['excluded_from_primary_covered'],
                             {'availability_after_execution_proposal': 1})

    def test_serial_quorum_split_has_its_own_identical_request_cohort(self):
        self.events[1]['at_us'] = 104
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            result = self.analyze_fixture(path, node, auth)
            split = result['serial_quorum_cohort']
            self.assertEqual((split['scheduled'], split['completed'], split['covered']), (3, 2, 1))
            self.assertEqual([stage['sum_us'] for stage in split['stages']], [1, 2, 1, 6, 2, 4, 2, 4])
            self.assertAlmostEqual(sum(stage['mean_ms'] for stage in split['stages']), .022)
            self.assertEqual(split['excluded'], result['excluded'])

    def test_aggregate_native_verifier_shape_and_signer_set(self):
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            aggregate = {'verified': True, 'verified_signers': [0],
                         'replicas': [{**auth['0'], 'signer': 0}]}
            self.assertEqual(self.analyze_fixture(path, node, aggregate)['covered'], 1)
            aggregate['verified_signers'] = [0, 1]
            with self.assertRaisesRegex(ValueError, 'signer set differs'):
                self.analyze_fixture(path, node, aggregate)

    def test_changed_evidence_and_missing_native_verification_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            with self.assertRaisesRegex(ValueError, 'native archive verification'):
                self.analyze_fixture(path, node, {})
            with (node/'output.jsonl').open('a') as stream:
                stream.write('{}\n')
            with self.assertRaisesRegex(ValueError, 'receipt-bound source changed'):
                self.analyze_fixture(path, node, auth)

    def test_mixed_run_dropped_trace_and_old_endpoint_are_rejected(self):
        for field, value, message in [('run_id', '00'*32, 'different runs'), ('dropped', 1, 'incomplete')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as root:
                path, node, auth = self.fixture(root)
                trace = json.loads((node/'latency-trace.json').read_text()); trace[field] = value
                (node/'latency-trace.json').write_text(json.dumps(trace)); self.refresh(node, auth)
                with self.assertRaisesRegex(ValueError, message):
                    self.analyze_fixture(path, node, auth)
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            (node/'effective-profile.json').write_text('{}'); self.refresh(node, auth)
            with self.assertRaisesRegex(ValueError, 'different application endpoint'):
                self.analyze_fixture(path, node, auth)

    def test_request_output_endpoint_mismatch_is_an_error_not_an_exclusion(self):
        with tempfile.TemporaryDirectory() as root:
            path, node, auth = self.fixture(root)
            rows = [json.loads(line) for line in (node/'requests.jsonl').read_text().splitlines()]
            rows[0]['first_materialized_us'] += 1
            (node/'requests.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows)); self.refresh(node, auth)
            with self.assertRaisesRegex(ValueError, 'endpoints disagree'):
                self.analyze_fixture(path, node, auth)

    def test_empty_cohort_cannot_be_plotted(self):
        with self.assertRaisesRegex(ValueError, 'empty instrumented cohort'):
            d.render({'missing': {'covered': 0}}, '/unused.png')


if __name__ == '__main__':
    unittest.main()
