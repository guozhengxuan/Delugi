"""Calibration acceptance logic; these tests perform no network mutations."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import local_netem_check as lab


def phases():
    result = {}
    for phase in ("before", "configured", "after"):
        result[phase] = {}
        for sender in range(2):
            for port in (lab.PORT, lab.CONTROL_PORT):
                value = .1 + (20 if phase == "configured" and port == lab.PORT else 0)
                result[phase][str(sender) + ":" + str(port)] = {"samples_ms": [value] * 20,
                                                              "median_rtt_ms": value}
    return result


class CalibrationTest(unittest.TestCase):
    def test_helper_envelope_unwrapped_without_changing_worker_rpc(self):
        with patch.object(lab, "command", return_value=json.dumps({"ok": True, "result": {"phase": "active"}})):
            self.assertEqual(lab.in_namespace("dla", "linux_netem.py", {}), {"phase": "active"})
        with patch.object(lab, "command", return_value=json.dumps({"median_rtt_ms": 1})):
            self.assertEqual(lab.in_namespace("dla", "remote_worker.py", {}), {"median_rtt_ms": 1})
        for value in ({"ok": False, "error": "denied"}, {"phase": "active"}, {"ok": True, "result": None}):
            with patch.object(lab, "command", return_value=json.dumps(value)):
                with self.assertRaisesRegex(RuntimeError, "RPC envelope"):
                    lab.in_namespace("dla", "linux_netem.py", {})

    def test_clear_requires_root_restoration_and_no_owned_objects(self):
        cleared = {"phase": "cleared", "physical_qdisc_configuration_unchanged": True,
                   "ifb": None, "owned_filters": []}
        lab.require_cleared(cleared)
        for change in ({"phase": "active"}, {"physical_qdisc_configuration_unchanged": False},
                       {"ifb": {"ifindex": 4}}, {"owned_filters": [{"pref": 1234}]}):
            with self.assertRaises(RuntimeError): lab.require_cleared({**cleared, **change})
        lab.require_cleared({"phase": "absent", "mutated": False}, allow_absent=True)
        with self.assertRaises(RuntimeError): lab.require_cleared({"phase": "absent", "mutated": False})

    def test_private_lab_refuses_a_shared_host_namespace_before_mutating(self):
        outer = {"net": 1, "mnt": 2, "pid": 3}
        for shared in outer:
            inner = {"net": 11, "mnt": 12, "pid": 13}; inner[shared] = outer[shared]
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "ownership.json").write_text(json.dumps({"nonce": "a" * 32,
                                                                      "outer_namespaces": outer}))
                with patch.object(lab, "namespace_ids", return_value=inner), patch.object(lab.os, "getpid", return_value=1), patch.object(lab, "command") as run:
                    with self.assertRaisesRegex(RuntimeError, "private mount/network/PID"):
                        lab.private_lab(directory, 10)
                    run.assert_not_called()

    def test_selected_rtt_control_and_restoration(self):
        self.assertTrue(lab.assess(phases(), 10)["passed"])

    def test_unshaped_one_sided_or_nonrestored_delay_fails(self):
        original = phases()
        for phase, port, value in (("configured", lab.PORT, .1),
                                   ("configured", lab.PORT, 10.1),
                                   ("configured", lab.CONTROL_PORT, 20.1),
                                   ("after", lab.PORT, 20.1)):
            changed = copy.deepcopy(original)
            changed[phase]["0:" + str(port)] = {"samples_ms": [value] * 20, "median_rtt_ms": value}
            self.assertFalse(lab.assess(changed, 10)["passed"])

    def test_missing_phase_or_nonfinite_samples_fail(self):
        value = phases(); value.pop("after")
        with self.assertRaises(ValueError): lab.assess(value, 10)
        value = phases(); value["before"]["0:" + str(lab.PORT)]["samples_ms"][0] = float("nan")
        with self.assertRaises(ValueError): lab.assess(value, 10)
        value = phases(); value["configured"]["0:" + str(lab.PORT)]["median_rtt_ms"] = 20.5
        with self.assertRaisesRegex(ValueError, "median differs"): lab.assess(value, 10)


if __name__ == "__main__": unittest.main()
