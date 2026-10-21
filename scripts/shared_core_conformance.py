#!/usr/bin/env python3
"""Reference/candidate conformance evidence for the mechanical workspace extraction.

This tool never builds code or changes a runner's provenance rules. Deterministic
trace equality, raw wire equality, source coverage, and live finite outcomes are
separate gates. Neither source relocation nor equal byte totals proves protocol
equivalence. Live runs are supplied by the existing, independently stamped runner.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import resource
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
MAX_JSON = 64 * 1024 * 1024
BYTE_CATEGORIES = ("payload_bytes", "evidence_control_bytes", "repair_bytes", "transport_overhead_bytes")


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path, limit=MAX_JSON):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > limit:
        raise ValueError(f"not a bounded regular JSON file: {path}")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON file grew beyond bound")
    return json.loads(raw)


def relative(value):
    if not isinstance(value, str) or "\\" in value:
        raise ValueError("expected relative POSIX source path")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or str(p) != value or value == ".":
        raise ValueError("source path escapes declared root")
    return value


def file_in(root, name):
    root = Path(root).resolve()
    path = root / relative(name)
    if not path.resolve().is_relative_to(root) or not path.is_file():
        raise ValueError(f"source file escapes root or is absent: {name}")
    if any(p.is_symlink() for p in (path, *path.parents) if p != root and p.is_relative_to(root)):
        raise ValueError("symlinked source paths are not supported")
    return path


def source_inventory(root, include_workspace=True):
    """Cover declared Cargo members and recursive local path dependencies.

    Unreferenced standalone ports/native checkouts are never traversed. Build
    stamps select the root package dependency closure; test/source archives also
    include explicitly declared workspace members. Root tests are conformance
    inputs. Outside-repository dependencies fail rather than disappearing.
    """
    root = Path(root).resolve()
    files = set()
    pending = [root / "Cargo.toml"]
    seen = set()
    root_data = tomllib.loads(file_in(root, "Cargo.toml").read_text())
    workspace_dependencies = root_data.get("workspace", {}).get("dependencies", {})
    while pending:
        manifest = pending.pop()
        if manifest in seen:
            continue
        seen.add(manifest)
        if not manifest.resolve().is_relative_to(root):
            raise ValueError("Cargo dependency outside declared source root")
        name = str(manifest.relative_to(root))
        data = tomllib.loads(file_in(root, name).read_text())
        files.add(name)
        base = manifest.parent
        for directory in (base / "src", base / "tests"):
            if directory.exists():
                files.update(str(p.relative_to(root)) for p in directory.rglob("*.rs")
                             if "target" not in p.relative_to(directory).parts)
        build = data.get("package", {}).get("build", "build.rs")
        if isinstance(build, str) and (base / build).exists():
            files.add(str((base / build).relative_to(root)))
        targets = list(data.get("bin", [])) + list(data.get("test", []))
        if "lib" in data:
            targets.append(data["lib"])
        for target in targets:
            if "path" in target:
                files.add(str((base / target["path"]).relative_to(root)))
        workspace = data.get("workspace", {})
        for member in workspace.get("members", []) if include_workspace else []:
            if Path(member).is_absolute() or ".." in Path(member).parts:
                raise ValueError("workspace member escapes source root")
            matches = list(base.glob(member))
            if not matches:
                raise ValueError(f"unresolved workspace member: {member}")
            pending.extend(p / "Cargo.toml" for p in matches)
        tables = [data, *data.get("target", {}).values()]
        for table in tables:
            for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                for dependency_name, dependency in table.get(kind, {}).items():
                    dependency_base = base
                    if isinstance(dependency, dict) and dependency.get("workspace") is True:
                        if dependency_name not in workspace_dependencies:
                            raise ValueError(f"unresolved inherited workspace dependency: {dependency_name}")
                        dependency = workspace_dependencies[dependency_name]
                        dependency_base = root
                    if isinstance(dependency, dict) and "path" in dependency:
                        pending.append((dependency_base / dependency["path"] / "Cargo.toml").resolve())
    for name in ("Cargo.lock", ".cargo/config", ".cargo/config.toml"):
        if (root / name).exists():
            files.add(name)
    return {name: sha256(file_in(root, name)) for name in sorted(files)}


def check_source_map(reference, candidate, rows):
    """Require complete, explicit relocation/change coverage on both sides.

    A reviewed-adapter row records changed bytes, not an equivalence proof. One
    old file may split into several new files and vice versa using list fields.
    """
    before_seen, after_seen, result = set(), set(), []
    for row in rows:
        before, after = row.get("before", []), row.get("after", [])
        if not isinstance(before, list) or not isinstance(after, list) or not (before or after):
            raise ValueError("mapping requires nonempty before/after path lists")
        for names, inventory, seen in ((before, reference, before_seen), (after, candidate, after_seen)):
            for name in names:
                relative(name)
                if name not in inventory or name in seen:
                    raise ValueError(f"unknown or duplicate source mapping: {name}")
                seen.add(name)
        kind = row.get("kind")
        if kind == "identical":
            if len(before) != 1 or len(after) != 1 or reference[before[0]] != candidate[after[0]]:
                raise ValueError("byte-identical relocation changed source bytes")
        elif kind == "reviewed-adapter":
            if not isinstance(row.get("reason"), str) or not row["reason"].strip():
                raise ValueError("changed source mapping needs a concrete review reason")
        else:
            raise ValueError("unknown source mapping kind")
        result.append({**row, "before_hashes": {p: reference[p] for p in before},
                       "after_hashes": {p: candidate[p] for p in after}})
    if before_seen != set(reference) or after_seen != set(candidate):
        raise ValueError(f"incomplete source mapping: old={sorted(set(reference)-before_seen)}, new={sorted(set(candidate)-after_seen)}")
    return {"status": "source_coverage_verified", "semantic_equivalence_established": False, "mappings": result}


def trace_cases(kind):
    if kind not in ("ordering", "end-to-end"):
        raise ValueError("unknown deterministic trace kind")
    end = kind == "end-to-end"
    cases = [
        ("honest-round-four", 4, 10, 4, 300 if end else 70, []),
        ("honest-delta-twenty", 4, 20, 4, 400 if end else 140, []),
        ("silent-first-three-anchors", 4, 10, 4, 900 if end else 800, ["--silent", "0"]),
        ("recurring-silent", 4, 10, 8, 1700 if end else 1500, ["--silent", "0"]),
        ("duplicate-packets", 4, 10, 4, 300 if end else 70, ["--duplicates"]),
        ("seven-replicas", 7, 10, 4, 300 if end else 70, []),
        ("seven-silent-first", 7, 10, 4, 900 if end else 800, ["--silent", "0"]),
    ]
    if end:
        for name, extra in (("delayed-payload-retrieval", []), ("descriptor-only-retrieval", ["--descriptor-only"])):
            cases.append((name, 4, 10, 4, 700, ["--delay-payload", "--data-delay", "120", *extra]))
    else:
        cases.append(("silent-first-delta-twenty", 4, 20, 4, 900, ["--silent", "0"]))
    return [{"name": name, "args": ["--nodes", str(n), "--delta", str(delta), "--bound", "100",
                                    "--rounds", str(rounds), "--until", str(until), *extra]}
            for name, n, delta, rounds, until, extra in cases]


def _child_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_JSON, MAX_JSON))


def run_traces(binary, expected_sha256, output, kind):
    binary, output = Path(binary).resolve(), Path(output)
    if sha256(binary) != expected_sha256:
        raise ValueError("trace binary identity mismatch")
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema": 1, "status": "incomplete", "kind": kind, "binary": str(binary),
              "binary_sha256": expected_sha256, "scope": "deterministic virtual time; no measured network latency", "cases": []}
    try:
        for case in trace_cases(kind):
            hashes = []
            for repeat in range(2):
                prefix = f"{case['name']}-{repeat}"
                stdout, stderr = output / (prefix + ".json"), output / (prefix + ".stderr")
                with stdout.open("xb") as out, stderr.open("xb") as err:
                    process = subprocess.run([str(binary), *case["args"]], stdout=out, stderr=err,
                                             timeout=60, preexec_fn=_child_limit, check=False)
                if process.returncode != 0 or read_json(stdout).get("pass") is not True:
                    raise ValueError(f"trace case failed: {prefix}; exit={process.returncode}")
                hashes.append(sha256(stdout))
            if hashes[0] != hashes[1]:
                raise ValueError(f"nondeterministic trace: {case['name']}")
            result["cases"].append({**case, "sha256": hashes[0], "repeats": 2,
                                     "files": [f"{case['name']}-{i}.json" for i in range(2)]})
        if sha256(binary) != expected_sha256:
            raise ValueError("trace binary changed during run")
        result["status"] = "passed"
    except BaseException as error:
        result["status"], result["error"] = "failed", f"{type(error).__name__}: {error}"
        raise
    finally:
        (output / "manifest.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def compare_traces(reference_dir, candidate_dir):
    manifests = [read_json(Path(p) / "manifest.json") for p in (reference_dir, candidate_dir)]
    first, second = manifests
    if any(m.get("status") != "passed" for m in manifests) or first["kind"] != second["kind"]:
        raise ValueError("trace suites missing or unsuccessful")
    expected = trace_cases(first["kind"])
    for root, manifest in zip((reference_dir, candidate_dir), manifests):
        if [{"name": r["name"], "args": r["args"]} for r in manifest["cases"]] != expected:
            raise ValueError("trace suite omitted or changed required cases")
        for row in manifest["cases"]:
            if row["repeats"] != 2 or len(row["files"]) != 2:
                raise ValueError("missing deterministic replay")
            for name in row["files"]:
                path = file_in(root, name)
                if sha256(path) != row["sha256"] or read_json(path).get("pass") is not True:
                    raise ValueError("trace evidence changed or failed")
    if [r["sha256"] for r in first["cases"]] != [r["sha256"] for r in second["cases"]]:
        raise ValueError("reference/candidate deterministic trace bytes differ")
    return {"status": "passed", "cases": len(expected), "same_protocol": True,
            "scope": "exact JSON trace equality; raw encoded wire bytes require separate gate"}


def compare_wire(reference_root, candidate_root):
    """Compare explicit complete wire fixtures; lengths/hashes alone are insufficient.

    Each root has index.json {schema:1, fixtures:[{name,path,bytes,sha256}]}.
    The independent exporter declares fixture coverage; this checker verifies the
    archived bytes and names, not completeness of the exporter or cryptography.
    """
    indexes = [read_json(Path(p) / "index.json", 1024 * 1024) for p in (reference_root, candidate_root)]
    tables = []
    for root, index in zip((reference_root, candidate_root), indexes):
        if index.get("schema") != 1 or not index.get("fixtures"):
            raise ValueError("raw wire fixture index absent")
        table = {}
        for row in index["fixtures"]:
            name = row["name"]
            if not isinstance(name, str) or not name or name in table:
                raise ValueError("duplicate/invalid wire fixture name")
            path = file_in(root, row["path"])
            if type(row["bytes"]) is not int or row["bytes"] <= 0 or path.stat().st_size != row["bytes"] or sha256(path) != row["sha256"]:
                raise ValueError("wire fixture bytes/hash mismatch")
            table[name] = (path, row["bytes"], row["sha256"])
        tables.append(table)
    if tables[0].keys() != tables[1].keys():
        raise ValueError("wire fixture coverage differs")
    for name, (left, size, digest) in tables[0].items():
        right, right_size, right_digest = tables[1][name]
        if (size, digest) != (right_size, right_digest):
            raise ValueError(f"raw encoded wire bytes differ: {name}")
        with left.open("rb") as a, right.open("rb") as b:
            while chunk := a.read(1024 * 1024):
                if chunk != b.read(len(chunk)):
                    raise ValueError(f"raw encoded wire bytes differ: {name}")
            if b.read(1):
                raise ValueError("wire file grew during comparison")
        if sha256(left) != digest or sha256(right) != digest:
            raise ValueError("wire file changed during comparison")
    return {"status": "passed", "fixtures": len(tables[0]), "bytes": sum(v[1] for v in tables[0].values())}


def finite_cases():
    return [{"name": f"{name}-{mode}", "outcome": name, "mode": mode,
             "rate": rate, "warmup": 0, "duration": duration, "drain": drain, "batch_ms": batch,
             "planned": planned, "nodes": 4, "useful_bytes": 472, "bound_ms": 100,
             "added_delta_ms": 0, "ordering_mode": "progress", "ordering_batch": True,
             "progress_pacing_ms": 100}
            for name, rate, duration, drain, batch, planned in
            (("healthy", 40, .2, 1, 10, 8), ("empty", 1, .1, 0, 10, 0), ("unfinished", 40, .1, 0, 1000, 4))
            for mode in ("full", "compact")]


def audit_finite(manifest, case):
    """Audit an existing trial; authentication evidence must accompany its report.

    This is a report consistency gate, not a substitute for the runner's signed
    archive verifier or an independent archive replay. Cross-run timing/order is
    deliberately not compared because live execution schedules differ.
    """
    trial = manifest.get("trial", {})
    if manifest.get("status") != "passed" or trial.get("status") != "passed":
        raise ValueError("finite trial failed")
    if manifest.get("cohort_observer") != case["mode"] or trial.get("cohort_observer") != case["mode"]:
        raise ValueError("observer mode mismatch")
    settings = trial["settings"]
    for key, value in {"total_rate": case["rate"], "useful_bytes": 472, "warmup_ms": 0,
                       "measurement_ms": round(case["duration"] * 1000), "batch_ms": case["batch_ms"]}.items():
        if settings.get(key) != value:
            raise ValueError(f"finite setting mismatch: {key}")
    if trial.get("protocol_bound_ms") != 100 or manifest.get("replicas") != 4:
        raise ValueError("finite committee/timer mismatch")
    if len(trial.get("children", [])) != 4 or {c["id"] for c in trial["children"]} != set(range(4)) or any(
            c.get("exit_code") != 0 or c.get("telemetry_errors") for c in trial["children"]):
        raise ValueError("owned replica cleanup failed or missing")
    if trial.get("cleanup_errors"):
        raise ValueError("cleanup errors retained")
    if trial.get("observer_receipt_authentication", {}).get("verified") is not True:
        raise ValueError("finite receipt authentication absent")
    if trial.get("agreement", {}).get("all_correct_overlap_prefixes_verified") is not True:
        raise ValueError("correct output overlap agreement absent")
    receipt = trial["observer_receipt"]
    keys = ("scheduled", "arrived", "admitted", "rejected", "not_yet_arrived", "batch_ready", "local_completed",
            "unfinished", "all_correct_completed", "all_correct_unfinished")
    if any(type(receipt.get(k)) is not int or receipt[k] < 0 for k in keys):
        raise ValueError("invalid finite population counts")
    if receipt["scheduled"] != case["planned"] or receipt["arrived"] + receipt["not_yet_arrived"] != receipt["scheduled"] or (
            receipt["admitted"] + receipt["rejected"] != receipt["arrived"]) or (
            receipt["local_completed"] + receipt["unfinished"] != receipt["scheduled"]) or (
            receipt["all_correct_completed"] + receipt["all_correct_unfinished"] != receipt["scheduled"]) or (
            receipt["local_completed"] > receipt["admitted"] or receipt["batch_ready"] > receipt["admitted"]):
        raise ValueError("finite population conservation failed")
    if case["outcome"] == "healthy" and receipt["all_correct_completed"] != case["planned"]:
        raise ValueError("healthy finite cohort incomplete")
    if case["outcome"] == "unfinished" and (receipt["unfinished"] != case["planned"] or receipt["local_completed"] != 0):
        raise ValueError("unfinished fixture completed; do not relabel actual outcome")
    if trial.get("ordering_options") != {"ordering_batch": True, "ordering_mode": "progress", "progress_pacing_ms": 100}:
        raise ValueError("finite scheduling settings changed")
    if trial.get("network_shaping") not in (None, {}):
        raise ValueError("unshaped conformance fixture unexpectedly uses shaping")
    category_sets = [trial.get("comparison", {}).get("written_categories", {})]
    if "finite_run_written_categories" in trial:
        category_sets.append(trial["finite_run_written_categories"])
    elif case["mode"] != "compact":
        raise ValueError("full finite written categories absent")
    for categories in category_sets:
        if categories.get("available") is not True or any(type(categories.get(k)) is not int or categories[k] < 0 for k in BYTE_CATEGORIES):
            raise ValueError("actual written category evidence absent")
        if sum(categories[k] for k in BYTE_CATEGORIES) != categories.get("total_written_bytes"):
            raise ValueError("actual written category conservation failed")
    finite_cost = trial.get("observer_finite_cost", {})
    final_tcp = trial.get("final_tcp", [])
    if len(final_tcp) != 4 or any(type(row.get("written_bytes")) is not int or row["written_bytes"] < 0 for row in final_tcp) or (
            sum(row["written_bytes"] for row in final_tcp) != finite_cost.get("written_bytes")):
        raise ValueError("finite actual TCP totals disagree")
    if case["mode"] == "compact":
        if any(obj.get("comparison_eligible") is not False for obj in (manifest, trial, trial["comparison"])):
            raise ValueError("compact eligibility flag missing")
        quantiles = trial.get("latency_quantiles")
        if (quantiles is not None and (not isinstance(quantiles, dict) or any(value is not None for value in quantiles.values()))) or (
                trial["comparison"].get("latency_available") is not False or trial["comparison"].get("mean_latency_ms") is not None):
            raise ValueError("compact mode fabricates detailed latency")
        if "cohort_ledger" in trial or "cohort" in trial:
            raise ValueError("compact mode retained detailed cohort")
    elif trial.get("cohort_authentication", {}).get("verified") is not True or trial.get("cohort_ledger", {}).get("schema") != 2:
        raise ValueError("full schema2 authentication missing")
    return {"status": "passed", "case": case["name"], "planned": receipt["scheduled"],
            "completed": receipt["local_completed"], "unfinished": receipt["unfinished"],
            "finite_category_breakdown_available": "finite_run_written_categories" in trial,
            "scope": "reported authenticated finite contract and cleanup; no cross-run order or latency equivalence claim"}


def required_plan():
    return {"schema": 1, "status": "planned", "trace_cases": {k: trace_cases(k) for k in ("ordering", "end-to-end")},
            "finite_cases": finite_cases(), "scheduling_cells": [
                {"ordering_mode": mode, "ordering_batch": bundle,
                 "progress_pacing_ms": 100 if mode == "progress" else None,
                 "outcomes": ["healthy", "silent-first-three-anchors"],
                 "acceptance": "preserve exact schedule policy; retain censored/incomplete outcomes; no canonical liveness substitution"}
                for mode in ("canonical", "progress") for bundle in (False, True)],
            "rust_adversarial_gates": [
                "byzantine_producer_forks_are_independently_valid_at_equal_heights",
                "q_valid_forks_with_authenticated_base_materialize_same_log_everywhere",
                "byzantine_forks_overlap_and_lower_targets_emit_every_exact_batch_once",
                "different_forks_with_repeated_transactions_are_batches_but_application_noops",
                "empty_fallback_copies_current_proofs_without_source_payloads",
                "full_and_compact_receipts_preserve_execution_and_latch_before_publication",
                "synchronous_produce_retry_latches_admitted_output_before_own_ready_publication"],
            "raw_wire_gate": "pending independently exported reference/candidate raw fixtures; trace length totals do not substitute",
            "measurement_scope": "local added delay0, bound100ms; deterministic traces use virtual delta10/20; no capacity ranking"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--output", type=Path, required=True)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--root", type=Path, default=ROOT)
    inventory.add_argument("--output", type=Path, required=True)
    source = commands.add_parser("source-map")
    source.add_argument("--reference", type=Path, required=True)
    source.add_argument("--candidate", type=Path, required=True)
    source.add_argument("--mapping", type=Path, required=True)
    source.add_argument("--output", type=Path, required=True)
    traces = commands.add_parser("traces")
    traces.add_argument("--binary", type=Path, required=True)
    traces.add_argument("--sha256", required=True)
    traces.add_argument("--kind", choices=("ordering", "end-to-end"), required=True)
    traces.add_argument("--output", type=Path, required=True)
    for name in ("compare-traces", "compare-wire"):
        command = commands.add_parser(name)
        command.add_argument("--reference", type=Path, required=True)
        command.add_argument("--candidate", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    finite = commands.add_parser("audit-finite")
    finite.add_argument("--manifest", type=Path, required=True)
    finite.add_argument("--case", choices=[c["name"] for c in finite_cases()], required=True)
    finite.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "traces":
        run_traces(args.binary, args.sha256, args.output, args.kind)
        return
    if args.action == "plan": result = required_plan()
    elif args.action == "inventory": result = source_inventory(args.root)
    elif args.action == "source-map": result = check_source_map(read_json(args.reference), read_json(args.candidate), read_json(args.mapping))
    elif args.action == "compare-traces": result = compare_traces(args.reference, args.candidate)
    elif args.action == "compare-wire": result = compare_wire(args.reference, args.candidate)
    else: result = audit_finite(read_json(args.manifest), next(c for c in finite_cases() if c["name"] == args.case))
    with args.output.open("x") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
