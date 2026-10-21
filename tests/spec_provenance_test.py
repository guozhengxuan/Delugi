"""Provenance selection must never silently follow the live working tree."""
import argparse
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import spec_provenance as provenance


class SpecificationSelection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paper = self.root / "paper"
        (self.paper / "protocol").mkdir(parents=True)
        files = []
        for name in ("ordering", "dissemination"):
            path = "protocol/" + name + ".tex"
            data = (name + " reviewed source\n").encode()
            (self.paper / path).write_bytes(data)
            files.append({"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.spec = {"schema": 2, "review_status": "reviewed", "paper_repository": str(self.paper),
                     "client_date": "2026-10-19", "paper_head": "fixture", "files": files}
        self.manifest = self.root / "spec-selected.json"
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.spec) + "\n")

    def archive(self):
        return provenance.archive_spec(self.manifest, self.root / "archive")

    def test_explicit_selection_required_and_source_override_available(self):
        parser = argparse.ArgumentParser()
        provenance.add_spec_arguments(parser)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args([])
        args = parser.parse_args(["--spec-snapshot", str(self.manifest), "--paper-repository", str(self.paper)])
        self.assertEqual(args.spec_snapshot, self.manifest)
        self.assertEqual(args.paper_repository, self.paper)

    def test_complete_verified_archive_preserves_manifest_and_sources(self):
        record = self.archive()
        archive = self.root / "archive"
        self.assertEqual((archive / record["archived_manifest"]).read_bytes(), self.manifest.read_bytes())
        self.assertEqual(record["manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        for entry in record["files"]:
            self.assertEqual((archive / "paper" / entry["path"]).read_bytes(), (self.paper / entry["path"]).read_bytes())
        provenance.verify_spec_unchanged(record)

    def test_historical_manifest_with_archived_paper_override(self):
        self.spec["schema"] = 1
        self.spec.pop("review_status")
        self.spec["paper_repository"] = "/missing/original/paper"
        self.save()
        record = provenance.archive_spec(self.manifest, self.root / "archive", self.paper)
        self.assertEqual(record["review_status"], "historical_snapshot")
        provenance.verify_spec_unchanged(record)

    def test_source_mismatch_does_not_refresh_pin_or_write_partial_archive(self):
        original = self.manifest.read_bytes()
        (self.paper / "protocol/dissemination.tex").write_text("unreviewed edits")
        with self.assertRaisesRegex(RuntimeError, "Specification changed"):
            self.archive()
        self.assertFalse((self.root / "archive").exists())
        self.assertEqual(self.manifest.read_bytes(), original)

    def test_review_status_and_both_normative_sources_required(self):
        self.spec["review_status"] = "draft"
        self.save()
        with self.assertRaisesRegex(ValueError, "reviewed"):
            self.archive()
        self.spec["review_status"] = "reviewed"
        self.spec["files"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "both ordering and dissemination"):
            self.archive()

    def test_duplicate_paths_size_mismatch_and_unsafe_paths_rejected(self):
        original = json.loads(json.dumps(self.spec))
        self.spec["files"].append(self.spec["files"][0])
        self.save()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.archive()
        for path in ("/tmp/source.tex", "../ordering.tex", "protocol/../ordering.tex", "protocol//ordering.tex", "protocol\\ordering.tex"):
            self.spec = json.loads(json.dumps(original))
            self.spec["files"][0]["path"] = path
            self.save()
            with self.assertRaises(ValueError):
                self.archive()
        self.spec = original
        self.spec["files"][0]["bytes"] += 1
        self.save()
        with self.assertRaisesRegex(RuntimeError, "Specification changed"):
            self.archive()

    def test_source_change_during_run_rejected(self):
        record = self.archive()
        (self.paper / "protocol/ordering.tex").write_text("concurrent edit")
        with self.assertRaisesRegex(RuntimeError, "Specification changed"):
            provenance.verify_spec_unchanged(record)

    def test_manifest_change_during_run_rejected_even_with_same_sources(self):
        record = self.archive()
        self.spec["client_date"] = "2026-10-20"
        self.save()
        with self.assertRaisesRegex(RuntimeError, "manifest changed"):
            provenance.verify_spec_unchanged(record)

    def test_no_implicit_latest_snapshot_selection(self):
        (self.root / "spec-2099-01-01.json").write_text(json.dumps({"schema": 999}))
        self.assertEqual(self.archive()["selected_manifest"], str(self.manifest.resolve()))

    def test_reviewed_october_manifest_pins_the_authorized_sources_and_claims(self):
        selected = json.loads((ROOT / "provenance/spec-2026-10-19.json").read_text())
        self.assertEqual(selected["review_status"], "reviewed")
        hashes = {entry["path"]: entry["sha256"] for entry in selected["files"]}
        self.assertEqual(hashes, {
            "protocol/ordering.tex": "c201812a71e1c233aa9ba6bb845a4947ae37c56f2342aa7b940bef91225de8c4",
            "protocol/dissemination.tex": "35743b5e009251d4ff7243d4527a76ee93cc58304b01505b92e66af434f7d825"})
        self.assertEqual(set(selected["claims"]["output_denominators"]), {"M_out", "U_out"})
        self.assertIn("empty fallback", selected["claims"]["input_readiness"])

    def test_four_ablation_cells_are_distinct_and_share_transport(self):
        modes = [provenance.scheduling_provenance({"ordering_mode": mode, "ordering_batch": bundled})
                 for mode in ("canonical", "progress") for bundled in (False, True)]
        self.assertEqual({mode["required_ablation_cell"] for mode in modes},
                         {"immediate/bundle-off", "immediate/bundle-on", "paced/bundle-off", "paced/bundle-on"})
        self.assertEqual(len({mode["transport"] for mode in modes}), 1)
        for mode in modes[2:]:
            self.assertIn("do not establish", mode["theorem_scope"])
        self.assertIsNone(provenance.scheduling_provenance({"ordering_mode": "barrier"})["required_ablation_cell"])


if __name__ == "__main__":
    unittest.main()
