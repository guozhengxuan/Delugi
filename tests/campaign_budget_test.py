from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from campaign_budget import Ledger


class CampaignBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'budget.json'
        self.ledger = Ledger(self.path)
        self.ledger.initialize(100_000, 'a'*64)

    def test_sequential_leases_cannot_each_spend_the_whole_campaign_cap(self):
        self.ledger.reserve('first', 40_000, 'b'*64)
        self.ledger.dispatch('first'); self.ledger.launched('first', ['i-one'])
        self.ledger.settle('first', 35_000, 'c'*64, resources_deleted=True, billing_final=True)
        self.ledger.reserve('second', 40_000, 'd'*64)
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            self.ledger.reserve('third', 30_000, 'e'*64)
        self.assertEqual(Ledger(self.path).snapshot()['available_fen'], 25_000)
        with self.assertRaisesRegex(ValueError, 'reset'):
            Ledger(self.path).initialize(100_000, 'a'*64)

    def test_unknown_creation_outcome_retains_funds_and_cannot_be_retried(self):
        self.ledger.reserve('first', 70_000, 'b'*64)
        self.ledger.dispatch('first')
        with self.assertRaisesRegex(ValueError, 'reconcile'):
            self.ledger.dispatch('first')
        with self.assertRaisesRegex(ValueError, 'possibly paid'):
            self.ledger.cancel('first')
        self.assertEqual(self.ledger.snapshot()['reserved_fen'], 70_000)
        self.ledger.launched('first', ['i-one', 'i-two'])
        self.assertEqual(self.ledger.snapshot()['leases']['first']['status'], 'active')

    def test_cleanup_does_not_release_unbilled_traffic_or_disk_charges(self):
        self.ledger.reserve('first', 40_000, 'b'*64); self.ledger.dispatch('first')
        for deleted, final in [(False, True), (True, False)]:
            with self.assertRaisesRegex(ValueError, 'final billed'):
                self.ledger.settle('first', 20_000, 'c'*64, resources_deleted=deleted, billing_final=final)
        self.assertEqual(self.ledger.snapshot()['reserved_fen'], 40_000)

    def test_real_overrun_is_recorded_and_stops_new_allocations(self):
        self.ledger.reserve('first', 40_000, 'b'*64); self.ledger.dispatch('first')
        result = self.ledger.settle('first', 110_000, 'c'*64, resources_deleted=True, billing_final=True)
        self.assertTrue(result['overspent']); self.assertEqual(result['available_fen'], -10_000)
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            self.ledger.reserve('second', 1, 'd'*64)

    def test_idempotent_reservations_and_changed_plan_rejection(self):
        result = self.ledger.reserve('first', 40_000, 'b'*64)
        self.assertEqual(result, self.ledger.reserve('first', 40_000, 'b'*64))
        with self.assertRaisesRegex(ValueError, 'different'):
            self.ledger.reserve('first', 30_000, 'b'*64)
        self.ledger.cancel('first')
        self.assertEqual(self.ledger.snapshot()['available_fen'], 100_000)
        with self.assertRaises(ValueError): self.ledger.dispatch('first')

    def test_tampered_symlink_and_concurrent_state_fail_closed(self):
        with self.ledger.locked():
            with self.assertRaisesRegex(ValueError, 'another'):
                Ledger(self.path).reserve('first', 1, 'b'*64)
        data = json.loads(self.path.read_text()); data['ceiling_fen'] *= 2
        self.path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.ledger.snapshot()
        link = self.path.parent / 'alias.json'; link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            Ledger(link)

    def test_new_authorization_preserves_unsettled_reservations(self):
        self.ledger.reserve('first', 100_000, 'b'*64); self.ledger.dispatch('first')
        old = self.ledger.snapshot()['leases']
        result = self.ledger.authorize_ceiling(120_000, 'c'*64)
        self.assertEqual(result['leases'], old)
        self.assertEqual(result['available_fen'], 20_000)
        self.assertEqual(result, self.ledger.authorize_ceiling(120_000, 'c'*64))
        self.assertEqual(json.loads(self.path.read_text())['authorization_sha256'], 'a'*64)
        for ceiling, evidence in [(130_000, 'c'*64), (100_000, 'd'*64), (130_000, 'a'*64)]:
            with self.assertRaises(ValueError): self.ledger.authorize_ceiling(ceiling, evidence)


if __name__ == '__main__': unittest.main()
