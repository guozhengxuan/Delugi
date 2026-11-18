"""Synthetic clock-domain regression cases for the calibrated WAN measurements."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from wan_delta_utc import HostClock, Point, Span, earliest, elapsed, next_launch, to_first, launch_residual, paired_clock_mean


def sample(t, offset=10_000, error=10):
    return dict(before_ns=t*1000,after_ns=(t+2)*1000,wall_ns=(t+1+offset)*1000,
                ntp_state=0,kernel_maxerror_us=error)


def pt(host,tick,lo,est,hi):
    return Point(host,tick,Span(lo,est,hi))


class ClockTest(unittest.TestCase):
    def test_brackets_runtime_origin_and_bound(self):
        probes=[sample(100),sample(10_100)]
        clock=HostClock(0,probes,dict(before_us=1000,after_us=1002,elapsed_us=200))
        a,b=clock.point(500),clock.point(900)
        self.assertLess(a.utc.lo,11_300)
        self.assertGreater(a.utc.hi,11_300)
        self.assertAlmostEqual(a.utc.est,11_301.5)
        self.assertEqual(elapsed(a,b),Span(400,400,400))

    def test_refuses_steps_sync_failures_and_extrapolation(self):
        for samples, fragment in [
            ([sample(100),sample(10_100,19_000)],'step'),
            ([sample(100),dict(error='offline'),sample(10_100)],'failed'),
            ([sample(100),dict(sample(5100),ntp_state=5),sample(10_100)],'unsynchronized'),
            ([sample(100),sample(40_000_100)],'missing'),
            ([sample(11_100),sample(20_100)],'bracketing')]:
            with self.subTest(fragment=fragment), self.assertRaisesRegex(ValueError,fragment):
                HostClock(0,samples).point(5000)

    def test_candidate_uncertainty_same_host_order_and_signed_intervals(self):
        origin=pt(0,20,90,100,110)
        proposals=[dict(emit=p,round=r) for r,p in enumerate((
            pt(1,40,90,105,120),pt(2,90,99,102,106),
            pt(1,41,91,106,121),pt(3,12,121,130,141)))]
        leader,candidates=earliest(proposals)
        self.assertEqual(leader['round'],1)
        self.assertEqual([c['round'] for c in candidates],[0,1])
        self.assertEqual(to_first(origin,candidates),Span(-20,2,16))
        launches=[pt(1,2,80,85,92),pt(0,30,100,110,120)]
        self.assertEqual(next_launch(origin,launches),Span(0,10,10))

    def test_mean_clock_offsets_cancel_for_balanced_sources_and_destinations(self):
        # Each directed duration has 80 us of uncertainty. Within-host
        # reassociation removes the common clock offsets in the two-event mean.
        a=pt(0,100,960,1000,1040)
        b=pt(1,500,1060,1100,1140)
        c=pt(1,520,1080,1120,1160)
        d=pt(0,140,1000,1040,1080)
        result=paired_clock_mean([(a,b),(c,d)])
        lo,est,hi=result['mean_ms']
        self.assertAlmostEqual(est,.01)
        self.assertLess(hi-lo,.005)
        self.assertLessEqual(lo,.01)
        self.assertGreaterEqual(hi,.01)
        self.assertEqual([v['paired'] for v in result['endpoints_by_host'].values()],[1,1])

    def test_length_weighted_residual_on_irregular_schedule(self):
        launches=[pt(0,t,t,t,t) for t in (0,10_000,40_000)]
        stats=launch_residual(launches,[0,40_000])
        self.assertEqual(stats['uniform_time_residual_ms_at_estimated_utc'],12.5)
        self.assertEqual(stats['half_mean_gap_ms_at_estimated_utc'],10)


if __name__=='__main__':
    unittest.main()
