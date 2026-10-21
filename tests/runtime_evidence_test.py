import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import runtime_evidence as evidence


class RuntimeEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"; self.source.mkdir()
        self.target = self.root / "target"; self.target.mkdir()
        (self.source / "cohorts").mkdir()
        (self.source / "cohorts/requests.jsonl").write_bytes(b"large-journal-record\n" * 10000)
        (self.source / "result.json").write_text('{"status":"completed"}')
        (self.source / "empty").write_bytes(b"")
        self.names = ["cohorts/requests.jsonl", "result.json", "empty"]
        self.metadata = {"nonce": "a" * 32, "replica": 2, "plan_sha256": "b" * 64}

    def tearDown(self): self.temporary.cleanup()

    def packed(self, names=None, **kwargs):
        stream = io.BytesIO()
        receipt = evidence.pack(self.source, iter(self.names if names is None else names), stream, self.metadata, chunk_bytes=4096, **kwargs)
        return stream.getvalue(), receipt

    def test_large_journal_roundtrip_uses_bounded_reads_without_manifest_map(self):
        raw, receipt = self.packed()
        class ReadBound(io.BytesIO):
            def read(self, size=-1):
                if not 0 <= size <= 4096: raise AssertionError("unbounded evidence read")
                return super().read(size)
        result = evidence.unpack(ReadBound(raw), self.target, expected_sha256=receipt["sha256"], expected_metadata=self.metadata)
        self.assertEqual(result, receipt)
        self.assertGreater(result["payload_bytes"], 4096 * 40)
        for name in self.names:
            self.assertEqual((self.source / name).read_bytes(), (self.target / name).read_bytes())
            self.assertEqual((self.target / name).stat().st_mode & 0o777, 0o600)

    def test_integrity_truncation_trailing_data_and_ownership_are_rejected(self):
        raw, receipt = self.packed()
        corrupted = raw.replace(b"large-journal-record", b"changed-journal-row", 1)
        cases = [(corrupted, {}, "hash"), (raw[:-1], {}, "header"),
                 (raw + b"extra", {}, "trailing"), (raw, {"expected_sha256": "0" * 64}, "stream hash"),
                 (raw, {"expected_metadata": {"nonce": "another"}}, "ownership")]
        for i, (content, kwargs, message) in enumerate(cases):
            target = self.root / f"invalid-{i}"; target.mkdir()
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                evidence.unpack(io.BytesIO(content), target, **kwargs)

    def test_source_and_destination_symlinks_traversal_and_duplicates_are_rejected(self):
        (self.source / "link").symlink_to(self.source / "result.json")
        for name in ("link", "../result.json", "cohorts/../result.json", "/absolute", "", "./result.json"):
            with self.subTest(name=name), self.assertRaises(ValueError): self.packed([name])
        raw, _ = self.packed(["result.json", "result.json"])
        with self.assertRaises(FileExistsError): evidence.unpack(io.BytesIO(raw), self.target)
        other = self.root / "other"; other.mkdir()
        target = self.root / "symlink-target"; target.mkdir()
        (target / "cohorts").symlink_to(other, target_is_directory=True)
        raw, _ = self.packed()
        with self.assertRaisesRegex(ValueError, "parent"):
            evidence.unpack(io.BytesIO(raw), target)
        self.assertEqual(list(other.iterdir()), [])

    def test_disk_file_and_chunk_envelopes_fail_instead_of_truncating(self):
        with self.assertRaisesRegex(ValueError, "envelope"): self.packed(max_payload_bytes=10)
        with self.assertRaisesRegex(ValueError, "envelope"): self.packed(max_files=1)
        raw, _ = self.packed()
        with self.assertRaisesRegex(ValueError, "envelope"):
            evidence.unpack(io.BytesIO(raw), self.target, max_payload_bytes=10)
        invalid = evidence.MAGIC + json.dumps({"record": "header", "chunk_bytes": evidence.CHUNK_BYTES + 1}).encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "header"):
            evidence.unpack(io.BytesIO(invalid), self.target)

    def test_selection_includes_shards_but_never_keys_builds_or_databases(self):
        for directory in ("fixture", "store", "controller", "logs", "observer"):
            (self.source / directory).mkdir()
            (self.source / directory / "file").write_text("fixture")
        selected = set(evidence.selected_files(self.source))
        self.assertEqual(selected, {"cohorts/requests.jsonl", "result.json", "logs/file", "observer/file"})
        (self.source / "logs/escape").symlink_to(self.source / "fixture/file")
        with self.assertRaisesRegex(ValueError, "symlink"): list(evidence.selected_files(self.source))

    def test_source_mutation_during_transfer_fails(self):
        path = self.source / "cohorts/requests.jsonl"
        class MutatingSink(io.BytesIO):
            changed = False
            def write(self, raw):
                if not self.changed and raw.startswith(b"large-journal-record"):
                    self.changed = True
                    with path.open("ab") as output: output.write(b"later")
                return super().write(raw)
        with self.assertRaisesRegex(ValueError, "changed"):
            evidence.pack(self.source, ["cohorts/requests.jsonl"], MutatingSink(), self.metadata, chunk_bytes=4096)


if __name__ == "__main__": unittest.main()
