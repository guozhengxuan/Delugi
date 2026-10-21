import unittest
from shoal_local_build import stop_reason


class BuildBudgetTests(unittest.TestCase):
    def sample(self,elapsed,swap=0,used=10,oom=0):
        return {'elapsed_seconds':elapsed,'swap_current_bytes':swap,'filesystem_used_bytes':used,'memory_events':{'oom':oom,'oom_kill':0}}

    def test_oom_and_disk_abort_do_not_require_repeated_failures(self):
        self.assertIn('OOM',stop_reason(self.sample(1,oom=1),{},None,70,3)[0])
        self.assertIn('ceiling',stop_reason(self.sample(1,used=70),{},None,70,3)[0])

    def test_transient_swap_allowed_sustained_pressure_aborts(self):
        reason,since=stop_reason(self.sample(10,swap=3),{},None,70,3)
        self.assertIsNone(reason);self.assertEqual(since,10)
        reason,since=stop_reason(self.sample(69,swap=3),{},since,70,3)
        self.assertIsNone(reason)
        reason,since=stop_reason(self.sample(70,swap=3),{},since,70,3)
        self.assertIn('60seconds',reason)
        self.assertIsNone(stop_reason(self.sample(71,swap=0),{},since,70,3)[1])


if __name__=='__main__':unittest.main()
