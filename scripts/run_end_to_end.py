#!/usr/bin/env python3
"""Archive composed transaction-path semantic traces, never network performance samples."""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import uuid

from spec_provenance import add_spec_arguments, archive_spec, verify_spec_unchanged, scheduling_provenance
from shared_core_conformance import source_inventory

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_spec_arguments(parser)
    args = parser.parse_args()
    run = ROOT / "results" / "local" / ("composed-" + uuid.uuid4().hex)
    run.mkdir(parents=True, exist_ok=False)
    manifest = {
        "schema": 3,
        "classification": "deterministic_semantic_trace",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "machine": {"system": platform.system(), "release": platform.release(), "arch": platform.machine()},
        "scope": "Signed BATCH/MMR/OBS/WA through ordering and payload retrieval to deterministic transaction materialization; Option A authenticated bases and automatic signed reporting, honest sequential producers and optional silent replica; no real transport or performance measurement",
        "source_files": [], "trials": [], "status": "incomplete",
        "crypto_keys": "Public deterministic fixture_key(id) seeds; never deployment keys",
        "event_order": "Arrival tick then increasing insertion sequence; synchronous engine self-delivery",
        "storage": "In-memory evidence and once-only state, retained for full run; no crash recovery",
        "input_readiness": "Finite batch workload is prepared before ordering starts; each leader automatically requests reports on entry; all-current construction with empty fallback; readiness and proposal time recorded separately",
        "accounting": "Every nonself packet, including silent recipients, injected duplicates, and control traffic beyond workload; serialization bytes exclude transport overhead",
        "warmup": "None; finite semantic traces, not performance trials",
        "gate": "correctness_conformance_only",
        "scheduling": scheduling_provenance({"ordering_mode": "progress", "ordering_batch": False, "progress_pacing_ms": 100},
                                             transport="deterministic_event_queue"),
    }

    def command(args, label):
        result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
        (run / (label + ".stdout")).write_text(result.stdout)
        (run / (label + ".stderr")).write_text(result.stderr)
        manifest.setdefault("commands", []).append({
            "args": args, "exit_code": result.returncode, "output_prefix": label,
        })
        if result.returncode:
            raise RuntimeError(f"{label} failed; output retained in {run}")
        return result.stdout

    try:
        sources = [ROOT / name for name in (
            "Cargo.toml", "Cargo.lock", "README.md", "IMPLEMENTATION_PLAN.md",
            "scripts/run_end_to_end.py", "scripts/spec_provenance.py", "scripts/shared_core_conformance.py",
        )]
        sources = sorted(set(sources) | {ROOT / name for name in source_inventory(ROOT)})
        for source in sources:
            relative = source.relative_to(ROOT)
            data = source.read_bytes()
            dest = run / "snapshot" / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            manifest["source_files"].append({"path": str(relative), "sha256": sha(data)})
        manifest["specification"] = archive_spec(args.spec_snapshot, run / "snapshot", args.paper_repository)
        manifest["paper_head"] = manifest["specification"]["paper_head"]
        manifest["rustc"] = command(["rustc", "--version", "--verbose"], "rustc").strip()
        manifest["cargo"] = command(["cargo", "--version"], "cargo").strip()
        command(["cargo", "fmt", "--check"], "format")
        command(["cargo", "test", "--workspace", "--offline", "--locked"], "tests")
        command(["cargo", "build", "--offline", "--locked", "--bin", "end-to-end-trace"], "build")
        binary = ROOT / "target" / "debug" / "end-to-end-trace"
        manifest["binary_sha256"] = sha(binary.read_bytes())
        scenarios = [
            {"label": "honest-round-four", "nodes": 4, "delta": 10, "rounds": 4, "until": 300},
            {"label": "honest-delta-twenty", "nodes": 4, "delta": 20, "rounds": 4, "until": 400},
            {"label": "silent-first-three-anchors", "nodes": 4, "delta": 10, "rounds": 4, "until": 900, "silent": 0},
            {"label": "recurring-silent", "nodes": 4, "delta": 10, "rounds": 8, "until": 1700, "silent": 0},
            {"label": "delayed-payload-retrieval", "nodes": 4, "delta": 10, "rounds": 4, "until": 700, "delay-payload": True, "data-delay": 120},
            {"label": "descriptor-only-retrieval", "nodes": 4, "delta": 10, "rounds": 4, "until": 700, "delay-payload": True, "data-delay": 120, "descriptor-only": True},
            {"label": "duplicate-packets", "nodes": 4, "delta": 10, "rounds": 4, "until": 300, "duplicates": True},
            {"label": "seven-replicas", "nodes": 7, "delta": 10, "rounds": 4, "until": 300},
            {"label": "seven-silent-first", "nodes": 7, "delta": 10, "rounds": 4, "until": 900, "silent": 0},
        ]
        for scenario in scenarios:
            previous = None
            for repeat in range(2):
                label = f"{scenario['label']}-repeat-{repeat}"
                args = [str(binary), "--bound", "100"]
                for flag in ("nodes", "delta", "rounds", "until", "silent", "data-delay"):
                    if flag in scenario:
                        args += ["--" + flag, str(scenario[flag])]
                for flag in ("duplicates", "delay-payload", "descriptor-only"):
                    if scenario.get(flag):
                        args += ["--" + flag]
                raw = command(args, label)
                output = json.loads(raw)
                if output["pass"] is not True:
                    raise RuntimeError(f"Scenario failed: {label}")
                raw_hash = sha(raw.encode())
                if previous is not None and previous != raw_hash:
                    raise RuntimeError(f"Nondeterministic signed trace: {label}")
                previous = raw_hash
                manifest["trials"].append({
                    "label": label, "scenario": scenario, "sha256": raw_hash, "pass": True,
                    "proposal_times": output["proposal_times"],
                    "replicas": [{"replica": node["replica"], "input_ready": node["input_ready"],
                        "ordered_at": node["ordered_at"], "materialized_at": node["materialized_at"],
                        "executed_rounds": node["executed_rounds"], "state_hash": node["state_hash"],
                        "transactions": len(node["executed"]), "requested_suffixes": node["requested_suffixes"]}
                        for node in output["replicas"]],
                    "wire_bytes": output["network_serialized_bytes"],
                    "network_sends": len(output["sends"]),
                    "bytes_by_kind": output["bytes_by_kind"],
                })
        # Refuse an archive assembled across concurrent source edits.
        for entry in manifest["source_files"]:
            if sha((ROOT / entry["path"]).read_bytes()) != entry["sha256"]:
                raise RuntimeError(f"Source changed during archive: {entry['path']}; rerun with stable sources")
        verify_spec_unchanged(manifest["specification"])
        manifest["status"] = "passed"
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
    finally:
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(json.dumps({"status": manifest["status"], "manifest": str(run / "manifest.json"),
            "trials": len(manifest["trials"]), "error": manifest.get("error")}, indent=2))
    return 0 if manifest["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
