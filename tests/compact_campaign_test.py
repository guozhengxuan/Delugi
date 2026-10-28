import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import compact_campaign as campaign
import aliyun_bench


class CompactCampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = json.loads((ROOT / 'benchmarks/configs/compact-campaign.example.json').read_text())
        self.config['specification'] = {'manifest': 'spec.json', 'paper_repository': 'paper'}
        files = []
        for name in ('ordering', 'dissemination'):
            path = self.root / 'paper' / 'protocol' / (name + '.tex')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(name)
            files.append({'path': 'protocol/' + path.name, 'bytes': len(name),
                          'sha256': hashlib.sha256(name.encode()).hexdigest()})
        (self.root / 'spec.json').write_text(json.dumps({'schema': 2, 'review_status': 'reviewed', 'files': files}))

    def test_compact_matrix_has_one_run_and_shared_loads(self):
        plan = campaign.create_plan(self.config, root=self.root)
        self.assertEqual(plan['trial_count'], 96)
        self.assertEqual(plan['supplemental_limit'], 24)
        healthy = [t for t in plan['trials'] if t['case'] == 'healthy']
        self.assertEqual(len(healthy), 72)
        for protocol in campaign.PROTOCOLS:
            for n in (10, 50):
                rows = [t for t in healthy if t['protocol'] == protocol and t['nodes'] == n]
                self.assertEqual([t['total_honest_input_tps'] for t in rows], self.config['total_honest_input_tps'])
        self.assertTrue(all(t['repeat'] == 0 for t in plan['trials']))
        self.assertFalse(plan['comparison_eligible'])
        self.assertTrue(all(t['total_honest_input_tps'] is None for t in plan['trials'] if t['case'] != 'healthy'))
        self.assertEqual(campaign.validate_plan(plan, root=self.root), plan)
        self.assertEqual(campaign.validate_plan(json.loads(json.dumps(plan)), root=self.root), plan)

    def test_plan_is_deterministic_and_bound_to_specification(self):
        first = campaign.create_plan(self.config, root=self.root)
        self.assertEqual(first, campaign.create_plan(self.config, root=self.root))
        changed = copy.deepcopy(first)
        changed['trials'][0]['total_honest_input_tps'] += 1
        with self.assertRaisesRegex(ValueError, 'changed'):
            campaign.validate_plan(changed, root=self.root)
        (self.root / 'paper/protocol/ordering.tex').write_text('a concurrent source edit')
        with self.assertRaisesRegex(RuntimeError, 'Specification changed'):
            campaign.create_plan(self.config, root=self.root)

    def test_expansion_and_silent_unknown_controls_are_rejected(self):
        mutations = [
            lambda c: c.update(committees=[10, 20, 50]),
            lambda c: c.update(committees=[49]),
            lambda c: c.update(repeats=11),
            lambda c: c.update(repeats=True),
            lambda c: c['duration'].update(measure_s=300),
            lambda c: c['duration'].update(warmup_s=10),
            lambda c: c['duration'].update(drain_s=60),
            lambda c: c['total_honest_input_tps'].append(65_000),
            lambda c: c.update(total_honest_input_tps=[4000, 1000]),
            lambda c: c.update(total_honest_input_tps=[True]),
            lambda c: c.update(protocols=['delugi', 'vantage']),
            lambda c: c.update(protocols=['delugi', 'delugi']),
            lambda c: c.update(supplemental_points_or_reruns_per_curve=3),
            lambda c: c.update(misspelled_timing=1),
            lambda c: c['network'].update(delay=10),
            lambda c: c['protocol_options'].update(shoal={}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                changed = copy.deepcopy(self.config); mutate(changed)
                with self.assertRaises(ValueError):
                    campaign.validate(changed)

    def test_exact_global_rate_with_faulty_origins_removed(self):
        for n, honest in ((10, list(range(1, 10))), (50, list(range(1, 50)))):
            for rate in (0, 1, 97, 1001, 64000):
                value = campaign.origin_plan(rate, 60_000_000, n, honest)
                self.assertEqual(sum(value['counts']), 60 * rate)
                self.assertEqual(value['counts'][0], 0)
                counts = value['counts'][1:]
                self.assertLessEqual(max(counts) - min(counts), 1)
        for origins in ([], [0, 0], [2, 1], [True], [50]):
            with self.assertRaises(ValueError):
                campaign.origin_plan(1000, 60_000_000, 50, origins)

    def test_cli_plan_is_offline(self):
        path = self.root / 'config.json'
        path.write_text(json.dumps(self.config))
        with patch.object(sys, 'argv', ['aliyun_bench.py', 'campaign', '--config', str(path), '--plan']), \
             patch.object(campaign, 'create_plan', return_value={'status': 'planned'}) as plan, \
             patch.object(aliyun_bench.cloud, 'Lease', side_effect=AssertionError('must stay offline')), \
             patch('builtins.print'):
            self.assertEqual(aliyun_bench.main(), 0)
            plan.assert_called_once_with(self.config)

    def test_global_ordinals_have_no_per_origin_rounding_or_timing_gaps(self):
        for n in (4,10,50):
            for rate in (1,97,1001):
                plan=campaign.origin_plan(rate,1_000_000,n,list(range(1,n)))
                offsets=sorted(campaign.arrival_offset_us(plan,i,j)
                    for i in plan['honest_origins'] for j in range(plan['counts'][i]))
                self.assertEqual(offsets,[k*1_000_000//rate for k in range(rate)])


if __name__ == '__main__':
    unittest.main()
