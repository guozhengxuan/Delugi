"""Fail-closed parsing of upstream Vantage native smoke evidence."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("vantage_baseline", Path(__file__).resolve().parents[1] / "scripts/baselines/vantage.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def fixture(protocol="vantage", panics=0, committed=9900):
    return f"""
 SUMMARY:
 Materialised transaction latency: avg 25.50 ms (stddev 1.00), p50/p90/p99 20.00/30.00/45.00 ms (9900 txs)
BENCHMARK_RESULT protocol={protocol} offered_tps=1000 committed_tps=990.000 throughput_pct=99.000 duration_s=10 submitted=10000 committed={committed} backlog=100 materialized_p50_ms=20.000 materialized_p99_ms=45.000 network_bytes=123456 panics={panics}
 SUMMARY -- STEADY-STATE (client tasks stopped, 1320 ms drain before re-read):
 Materialised transaction latency: avg 50.00 ms (stddev 1.00), p50/p90/p99 40.00/60.00/90.00 ms (10000 txs)
"""


class NativeEvidence(unittest.TestCase):
    def test_native_measurement_is_not_replaced_by_later_drain_snapshot(self):
        result = runner.parse_result(fixture(), "vantage", 1000)
        self.assertEqual(result["committed_tps"],990)
        self.assertEqual(result["committed"],9900)
        self.assertEqual(result["materialized_mean_ms"],25.5)
        self.assertEqual(result["network_bytes"],123456)

    def test_all_five_native_protocol_labels_are_accepted(self):
        for protocol in runner.PROTOCOLS:
            self.assertEqual(runner.parse_result(fixture(protocol),protocol,1000)["protocol"],protocol)

    def test_rejects_panics_no_progress_wrong_protocol_and_rate(self):
        for raw,protocol,rate in ((fixture(panics=1),"vantage",1000),
                                 (fixture(committed=0),"vantage",1000),
                                 (fixture(),"simple-it",1000),
                                 (fixture(),"vantage",4000)):
            with self.assertRaises(RuntimeError):
                runner.parse_result(raw,protocol,rate)

    def test_requires_exactly_one_machine_measurement_summary(self):
        for text in ("",fixture()+fixture()):
            with self.assertRaises(RuntimeError):
                runner.parse_result(text,"vantage",1000)

    def test_workspace_suite_totals_include_ignored_but_not_filter_as_passed(self):
        raw = "test result: ok. 12 passed; 0 failed; 2 ignored; 0 measured; 3 filtered out\n" \
              "test result: ok. 7 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n"
        self.assertEqual(runner.parse_test_results(raw),
                         {"status":"passed","test_suites":2,"passed":19,"failed":0,"ignored":3,"measured":0,"filtered_out":3})
        with self.assertRaises(RuntimeError):
            runner.parse_test_results("no test result")


if __name__ == "__main__":
    unittest.main()
