"""Extraction evidence gates: missing coverage must never become conformance."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import shared_core_conformance as conformance


class Sources(unittest.TestCase):
    def test_workspace_sources_and_path_dependencies_are_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            contents = {"Cargo.toml": '[package]\nname="fixture"\n[workspace]\nmembers=["shared/*"]\n[dependencies]\nhelper={path="helper"}\ncore={path="core/delugi"}\n',
                        "Cargo.lock": "lock", "src/lib.rs": "root", "core/delugi/src/lib.rs": "core",
                        "core/delugi/Cargo.toml": '[package]\nname="core"\n',
                        "shared/net/Cargo.toml": '[package]\nname="net"\n', "shared/net/src/lib.rs": "net",
                        "helper/Cargo.toml": '[package]\nname="helper"\n', "helper/src/lib.rs": "helper",
                        "tests/contract.rs": "test", "benchmarks/baselines/native/src/lib.rs": "excluded",
                        "core/raptr/Cargo.toml": '[dependencies]\nlarge-native={path="/external/not-ours"}\n',
                        "shared/net/target/ignored.rs": "excluded"}
            for name, data in contents.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(data)
            inventory = conformance.source_inventory(root)
            self.assertEqual(set(inventory), set(contents) - {"benchmarks/baselines/native/src/lib.rs", "shared/net/target/ignored.rs", "core/raptr/Cargo.toml"})
            self.assertNotIn("shared/net/src/lib.rs", conformance.source_inventory(root, include_workspace=False))
            old = inventory["shared/net/src/lib.rs"]
            (root / "shared/net/src/lib.rs").write_text("changed")
            self.assertNotEqual(old, conformance.source_inventory(root)["shared/net/src/lib.rs"])

    def test_source_map_rejects_omission_duplicate_and_edited_relocation(self):
        before, after = {"src/a.rs": "a", "src/b.rs": "b"}, {"core/a.rs": "a", "shared/b.rs": "c"}
        rows = [{"before": ["src/a.rs"], "after": ["core/a.rs"], "kind": "identical"},
                {"before": ["src/b.rs"], "after": ["shared/b.rs"], "kind": "reviewed-adapter", "reason": "public API adapter; wire gate separate"}]
        self.assertFalse(conformance.check_source_map(before, after, rows)["semantic_equivalence_established"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            conformance.check_source_map(before, after, rows[:1])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            conformance.check_source_map(before, after, rows + rows[:1])
        rows[1]["kind"] = "identical"
        with self.assertRaisesRegex(ValueError, "changed source bytes"):
            conformance.check_source_map(before, after, rows)

    def test_symlink_escape_and_missing_member_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / "src").mkdir()
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["absent"]\n')
            with self.assertRaisesRegex(ValueError, "unresolved"):
                conformance.source_inventory(root)
            (root / "Cargo.toml").write_text('[package]\nname="fixture"\n')
            (root / "real.rs").write_text("data")
            (root / "src/lib.rs").symlink_to(root / "real.rs")
            with self.assertRaisesRegex(ValueError, "symlink"):
                conformance.source_inventory(root)


class WireAndTrace(unittest.TestCase):
    def wire(self, root, raw):
        root.mkdir(); (root / "packet.bin").write_bytes(raw)
        index = {"schema": 1, "fixtures": [{"name": "signed-vote", "path": "packet.bin", "bytes": len(raw),
                                            "sha256": hashlib.sha256(raw).hexdigest()}]}
        (root / "index.json").write_text(json.dumps(index))

    def test_same_length_altered_wire_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            left, right = Path(temp) / "left", Path(temp) / "right"
            self.wire(left, b"signed-A"); self.wire(right, b"signed-B")
            with self.assertRaisesRegex(ValueError, "wire bytes differ"):
                conformance.compare_wire(left, right)
            (right / "packet.bin").write_bytes(b"signed-A")
            (right / "index.json").write_bytes((left / "index.json").read_bytes())
            self.assertEqual(conformance.compare_wire(left, right)["fixtures"], 1)
            (right / "packet.bin").write_bytes(b"signed-B")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                conformance.compare_wire(left, right)

    def test_required_inventory_retains_scheduling_and_censored_controls(self):
        plan = conformance.required_plan()
        self.assertEqual(len(plan["finite_cases"]), 6)
        self.assertEqual({(c["ordering_mode"], c["ordering_batch"]) for c in plan["scheduling_cells"]},
                         {(mode, bundle) for mode in ("canonical", "progress") for bundle in (True, False)})
        self.assertTrue(any("forks" in name for name in plan["rust_adversarial_gates"]))
        self.assertEqual(len(plan["trace_cases"]["ordering"]), 8)
        self.assertEqual(len(plan["trace_cases"]["end-to-end"]), 9)

    def test_trace_claim_with_omitted_cases_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "manifest.json").write_text(json.dumps({"status": "passed", "kind": "ordering", "cases": []}))
            with self.assertRaisesRegex(ValueError, "omitted"):
                conformance.compare_traces(root, root)


def finite_fixture(case):
    planned = case["planned"]
    done = 0 if case["outcome"] == "unfinished" else planned
    categories = {"available": True, **dict.fromkeys(conformance.BYTE_CATEGORIES, 1), "total_written_bytes": 4}
    trial = {"status": "passed", "cohort_observer": case["mode"], "settings": {
        "total_rate": case["rate"], "useful_bytes": 472, "warmup_ms": 0,
        "measurement_ms": round(case["duration"] * 1000), "batch_ms": case["batch_ms"]},
        "protocol_bound_ms": 100, "children": [{"id": i, "exit_code": 0, "telemetry_errors": []} for i in range(4)],
        "observer_receipt_authentication": {"verified": True}, "agreement": {"all_correct_overlap_prefixes_verified": True},
        "observer_receipt": {"scheduled": planned, "arrived": planned, "admitted": planned, "rejected": 0,
                             "not_yet_arrived": 0, "batch_ready": done, "local_completed": done,
                             "unfinished": planned-done, "all_correct_completed": done, "all_correct_unfinished": planned-done},
        "finite_run_written_categories": copy.deepcopy(categories), "comparison": {"written_categories": categories}}
    trial.update(ordering_options={"ordering_batch": True, "ordering_mode": "progress", "progress_pacing_ms": 100},
                 final_tcp=[{"written_bytes": 1} for _ in range(4)], observer_finite_cost={"written_bytes": 4})
    manifest = {"status": "passed", "cohort_observer": case["mode"], "replicas": 4, "trial": trial}
    if case["mode"] == "compact":
        for obj in (manifest, trial, trial["comparison"]): obj["comparison_eligible"] = False
        trial["comparison"].update(latency_available=False, mean_latency_ms=None)
        trial["latency_quantiles"] = {"p99": None}
    else:
        trial.update(cohort_authentication={"verified": True}, cohort_ledger={"schema": 2})
    return manifest


class FiniteContract(unittest.TestCase):
    def test_all_six_controls_have_explicit_population_outcomes(self):
        for case in conformance.finite_cases():
            with self.subTest(case=case["name"]):
                self.assertEqual(conformance.audit_finite(finite_fixture(case), case)["status"], "passed")

    def test_unfinished_is_not_silently_promoted_when_it_completed(self):
        case = next(c for c in conformance.finite_cases() if c["name"] == "unfinished-full")
        manifest = finite_fixture(case)
        manifest["trial"]["observer_receipt"].update(local_completed=4, unfinished=0)
        with self.assertRaisesRegex(ValueError, "fixture completed"):
            conformance.audit_finite(manifest, case)

    def test_compact_missing_flags_or_fabricated_latency_fails(self):
        case = next(c for c in conformance.finite_cases() if c["name"] == "healthy-compact")
        manifest = finite_fixture(case); manifest["trial"]["comparison"]["mean_latency_ms"] = 1
        with self.assertRaisesRegex(ValueError, "fabricates"):
            conformance.audit_finite(manifest, case)
        manifest = finite_fixture(case); del manifest["comparison_eligible"]
        with self.assertRaisesRegex(ValueError, "eligibility"):
            conformance.audit_finite(manifest, case)

    def test_compact_without_finite_categories_reports_limitation(self):
        case = next(c for c in conformance.finite_cases() if c["name"] == "empty-compact")
        manifest = finite_fixture(case); del manifest["trial"]["finite_run_written_categories"]
        manifest["trial"]["latency_quantiles"] = None
        self.assertFalse(conformance.audit_finite(manifest, case)["finite_category_breakdown_available"])
        manifest["trial"]["final_tcp"][0]["written_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "TCP totals"):
            conformance.audit_finite(manifest, case)

    def test_written_cleanup_authentication_and_population_gates(self):
        case = conformance.finite_cases()[0]
        changes = [lambda t: t["finite_run_written_categories"].update(total_written_bytes=5),
                   lambda t: t["children"][0].update(exit_code=-9),
                   lambda t: t["observer_receipt_authentication"].update(verified=False),
                   lambda t: t["observer_receipt"].update(admitted=9),
                   lambda t: t["cohort_ledger"].update(schema=1)]
        for change in changes:
            manifest = finite_fixture(case); change(manifest["trial"])
            with self.assertRaises(ValueError): conformance.audit_finite(manifest, case)


if __name__ == "__main__":
    unittest.main()
