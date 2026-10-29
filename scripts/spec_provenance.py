"""Explicit, fail-closed selection and archival of reviewed paper snapshots.

No runner chooses the newest manifest or updates a hash to match a live source.
Historical schema-1 manifests remain selectable with their original source tree
or an archived ``snapshot/paper`` directory supplied via --paper-repository.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SOURCES = {"protocol/ordering.tex", "protocol/dissemination.tex"}


def add_spec_arguments(parser):
    parser.add_argument("--spec-snapshot", type=Path, required=True,
                        help="explicit reviewed spec manifest (for example provenance/spec-2026-10-19.json)")
    parser.add_argument("--paper-repository", type=Path,
                        help="source tree override, including an archived snapshot/paper directory")


def _relative(path):
    if not isinstance(path, str) or "\\" in path:
        raise ValueError("specification source path must be a relative POSIX path")
    relative = PurePosixPath(path)
    if relative.is_absolute() or ".." in relative.parts or str(relative) != path or path == ".":
        raise ValueError(f"invalid specification source path: {path}")
    return relative


def validate_spec(snapshot_path, paper_repository=None):
    """Read and verify the selected manifest and every pinned source, without writes."""
    snapshot_path = Path(snapshot_path).resolve()
    raw = snapshot_path.read_bytes()
    spec = json.loads(raw)
    if spec.get("schema") not in (1, 2):
        raise ValueError("unsupported specification provenance schema")
    if spec["schema"] == 2 and spec.get("review_status") != "reviewed":
        raise ValueError("specification snapshot has not been explicitly reviewed")
    repository = Path(paper_repository or spec["paper_repository"]).resolve()
    files = spec.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError("specification snapshot has no pinned source files")
    verified = []
    seen = set()
    for entry in files:
        relative = _relative(entry["path"])
        if str(relative) in seen:
            raise ValueError(f"duplicate specification source: {relative}")
        seen.add(str(relative))
        expected = entry.get("sha256")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError(f"invalid specification hash: {relative}")
        path = repository / relative
        if not path.resolve().is_relative_to(repository):
            raise ValueError(f"specification source escapes repository: {relative}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected or (
                "bytes" in entry and (type(entry["bytes"]) is not int or len(data) != entry["bytes"])):
            raise RuntimeError(f"Specification changed: {relative}; review and select a fresh provenance snapshot")
        verified.append((str(relative), data, expected))
    if not REQUIRED_SOURCES.issubset(seen):
        raise ValueError("specification snapshot must pin both ordering and dissemination")
    return snapshot_path, raw, spec, repository, verified


def archive_spec(snapshot_path, archive_root, paper_repository=None):
    """Verify before writing, then return JSON-ready identity and archived source hashes.

    archive_root is normally RUN/snapshot. Call verify_spec_unchanged on the returned
    record before accepting the run to detect concurrent edits to the selected pin
    or source files. The selected manifest is preserved verbatim, never rewritten.
    """
    path, raw, spec, repository, verified = validate_spec(snapshot_path, paper_repository)
    archive_root = Path(archive_root)
    manifest_relative = Path("provenance") / path.name
    destination = archive_root / manifest_relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    for relative, data, _ in verified:
        destination = archive_root / "paper" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    return {"selected_manifest": str(path), "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "archived_manifest": manifest_relative.as_posix(),
            "client_date": spec.get("client_date"), "paper_head": spec.get("paper_head"),
            "paper_repository": str(repository),
            "review_status": spec.get("review_status", "historical_snapshot"),
            "files": [{"path": relative, "bytes": len(data), "sha256": digest}
                      for relative, data, digest in verified],
            "claims": spec.get("claims", {}),
            "selection": "explicit; hashes verified before trial; no automatic latest or hash refresh"}


def verify_spec_unchanged(record):
    """Reject a run assembled across concurrent edits to its selected source snapshot."""
    _, raw, _, _, verified = validate_spec(record["selected_manifest"], record["paper_repository"])
    if hashlib.sha256(raw).hexdigest() != record["manifest_sha256"]:
        raise RuntimeError("selected specification manifest changed during run")
    files = [{"path": relative, "bytes": len(data), "sha256": digest}
             for relative, data, digest in verified]
    if files != record["files"]:
        raise RuntimeError("selected specification sources changed during run")


def scheduling_provenance(options, *, transport="bounded_pipelined_authenticated_tcp"):
    """Label a resolved schedule without conflating conformance and timing claims."""
    mode = options["ordering_mode"]
    if mode not in ("canonical", "progress", "barrier"):
        raise ValueError("unknown ordering schedule")
    bundling = bool(options.get("ordering_batch", False))
    return {"ordering_mode": mode, "originating_prog": "immediate" if mode == "canonical" else
            ("paced" if mode == "progress" else "full_round_barrier"),
            "bundling": "immediate_no_fill_timer" if bundling else "off",
            "transport": transport, "release_deadline_ms": options.get("progress_pacing_ms", options.get("round_barrier_ms")),
            "report_schedule": options.get("report_schedule", "unrecorded"),
            "report_schedule_scope": ("bounded pipeline: admitted leader prepares after own outcome prefix r-4, "
                "f+1 CLOSED(r-3), or exact HISTORY3(r-3); startup r<=4; two-delay preparation overlaps history; "
                "fixed observations/inputs and ordering guards/timers are unchanged"
                if options.get("report_schedule") == "pipeline" else
                "composition scheduling variant: delay the one REPORT until exact HISTORY3 is ready; "
                "ordering guards/timers and immutable Q are unchanged; this differs from the pinned paper's entry trigger"
                if options.get("report_schedule") == "history_ready" else "historical admission trigger or unrecorded"),
            "required_ablation_cell": ("immediate" if mode == "canonical" else "paced") +
                ("/bundle-on" if bundling else "/bundle-off") if mode != "barrier" else None,
            "theorem_scope": ("canonical ordering with bounded pipeline composition; input readiness is measured from "
                "its evidence trigger, not arbitrary admission; actual timing requires the stated model conditions")
                if mode == "canonical" and options.get("report_schedule") == "pipeline" else
                "canonical schedule; measured performance still requires stated model conditions" if mode == "canonical" else
                "implementation variant; conformance tests do not establish the canonical timing theorem"}
