#!/usr/bin/env python3
"""Generated schema2/SQLite storage acceptance; never a protocol benchmark.

No replica, authenticated protocol execution, network or build is involved.
Canonical-sized synthetic rows have distinct IDs/ordinals and real file bytes;
the archive is not padded, sparse-file-backed or made of reused output pages.
Only the small recipe, root index, summaries and hashes survive cleanup.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import shutil
import sys
import tempfile
import threading
import time
import uuid
import _thread

from cohort_store import FORMAT, STREAMS, ShardedArchive, CohortDatabase, sha_file

ROOT = Path(__file__).resolve().parents[1]
GIB = 1024**3
MIB = 1024**2


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def identifier(kind, number):
    return hashlib.sha256(f"delugi-generated-storage-v1/{kind}/{number}".encode()).hexdigest()


def rss():
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if sys.platform == "darwin" else value * 1024


def footprint(root):
    logical = allocated = files = 0
    for directory, _, names in os.walk(root):
        for name in names:
            try:
                info = (Path(directory) / name).stat()
            except FileNotFoundError:
                continue  # SQLite can retire its own temporary journal.
            logical += info.st_size
            allocated += info.st_blocks * 512
            files += 1
    return {"logical_bytes": logical, "allocated_bytes": allocated, "files": files}


class Guard:
    def __init__(self, root):
        self.root, self.stop = root, threading.Event()
        self.error = None
        self.maximum_disk = self.maximum_rss = 0
        self.thread = threading.Thread(target=self.monitor, daemon=True)

    def check(self, disk=False):
        self.maximum_rss = max(self.maximum_rss, rss())
        if self.maximum_rss > 240 * MIB:
            raise MemoryError("240 MiB conservative RSS abort threshold exceeded")
        if disk:
            current = footprint(self.root)
            self.maximum_disk = max(self.maximum_disk, current["logical_bytes"], current["allocated_bytes"])
            if self.maximum_disk > 4 * GIB - 128 * MIB:
                raise OSError("scratch nears the 4 GiB disk ceiling")

    def monitor(self):
        iteration = 0
        while not self.stop.wait(.1):
            try:
                self.check(disk=iteration % 10 == 0)
                iteration += 1
            except (MemoryError, OSError) as error:
                self.error = str(error)
                _thread.interrupt_main()
                return


def rows(stream, replica, nodes, per_origin):
    total = nodes * per_origin
    batch_size = 128
    def done(ordinal):
        last = min(total, (ordinal // batch_size + 1) * batch_size) - 1
        return 1000 + last * 100 + 100
    if stream == "requests":
        for sequence in range(per_origin):
            ordinal = sequence * nodes + replica
            scheduled = 1000 + ordinal * 100
            yield {"id": identifier("request", ordinal), "origin": replica, "sequence": sequence,
                   "useful_bytes": 8, "scheduled_us": scheduled, "admitted_us": scheduled + 5,
                   "batch_ready_us": scheduled + 10, "materialized_us": done(ordinal), "rejected_us": None}
    elif stream == "outputs":
        for ordinal in range(total):
            yield {"id": identifier("request", ordinal), "origin": ordinal % nodes,
                   "sequence": ordinal // nodes, "useful_bytes": 8, "output_index": ordinal + 1,
                   "materialized_us": done(ordinal), "post_handler_published_us": done(ordinal) + 1,
                   "exact_batch_id": identifier("batch", ordinal // batch_size),
                   "state_hash": identifier("synthetic-state", ordinal + 1)}
    else:
        for batch in range(math.ceil(total / batch_size)):
            yield {"exact_batch_id": identifier("batch", batch),
                   "payload_bytes": min(batch_size, total - batch * batch_size) * 68,
                   "output_index": batch + 1, "materialized_us": done(batch * batch_size)}


def generate(root, nodes, per_origin, guard):
    root.mkdir()
    total = nodes * per_origin
    populations = {"requests": per_origin, "outputs": total, "batches": math.ceil(total / 128)}
    replicas = {}
    for replica in range(nodes):
        destination = root / f"replica-{replica}"
        destination.mkdir()
        metadata = {"manifest": None, "output_index_base": 1, "output_prefix_count": total,
                    "window_start_us": 0, "window_end_us": total * 100 + 2000,
                    "observed_us": total * 100 + 3000, "streams": {}}
        for stream in STREAMS:
            path = destination / (stream + ".index.jsonl")
            digest, offset, pages, index_bytes = hashlib.sha256(), 0, 0, 0
            iterator = iter(rows(stream, replica, nodes, per_origin))
            with path.open("xb") as index:
                while offset < populations[stream]:
                    entries = [next(iterator) for _ in range(min(512, populations[stream] - offset))]
                    next_offset = offset + len(entries)
                    raw = canonical({"replica": replica, "total": populations[stream], "manifest": None,
                                     "entries": entries, "next_offset": next_offset if next_offset < populations[stream] else None})
                    page = destination / f"{stream}-{pages:08d}.json"
                    with page.open("xb") as target:
                        target.write(raw)
                    line = canonical({"path": str(page.relative_to(root)), "sha256": hashlib.sha256(raw).hexdigest(),
                                      "bytes": len(raw), "entries": len(entries), "offset": offset})
                    index.write(line); digest.update(line); index_bytes += len(line)
                    offset = next_offset; pages += 1
                    guard.check()
            metadata["streams"][stream] = {"path": str(path.relative_to(root)), "sha256": digest.hexdigest(),
                                           "bytes": index_bytes, "pages": pages, "entries": offset}
        replicas[str(replica)] = metadata
        guard.check(disk=True)
        if replica % 5 == 0 or replica + 1 == nodes:
            print(json.dumps({"phase": "generated", "replicas": replica + 1}), flush=True)
    index = root / "index.json"
    index.write_bytes(canonical({"schema": 2, "format": FORMAT, "replicas": replicas,
                                "scope": "synthetic bounded archive fixture; no authenticated protocol execution"}))
    return ShardedArchive(index)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nodes", type=int, default=31)
    parser.add_argument("--requests-per-origin", type=int, default=3500)
    parser.add_argument("--minimum-archive-bytes", type=int, default=GIB + 1)
    args = parser.parse_args()
    if args.nodes not in (4, 7, 31) or args.requests_per_origin <= 0:
        raise ValueError("positive finite population at n=4,7,31 required")
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix="delugi-cohort-storage-stress-", dir="/private/tmp"))
    owner = uuid.uuid4().hex
    (scratch / "owner.json").write_bytes(canonical({"nonce": owner, "purpose": "generated-cohort-storage-stress"}))
    inode = scratch.stat().st_ino
    guard = Guard(scratch); guard.thread.start()
    previous_temp = tempfile.tempdir
    tempfile.tempdir = str(scratch)
    os.environ["SQLITE_TMPDIR"] = str(scratch)
    started = time.monotonic(); database = None
    report = {"schema": 1, "status": "failed", "scope": "generated schema2 archive/SQLite postprocessing; not protocol, authentication or native performance acceptance",
              "recipe": {"generator": str(Path(__file__).relative_to(ROOT)), "generator_sha256": sha_file(__file__),
                         "nodes": args.nodes, "requests_per_origin": args.requests_per_origin, "requests": args.nodes * args.requests_per_origin,
                         "output_rows": args.nodes**2 * args.requests_per_origin, "page_entries": 512,
                         "row_content": "distinct deterministic SHA256 request/batch/state IDs and canonical output fields; no padding or reused/sparse pages"},
              "guards": {"rss_ceiling_bytes": 256 * MIB, "rss_abort_threshold_bytes": 240 * MIB,
                         "scratch_ceiling_bytes": 4 * GIB, "scratch_abort_threshold_bytes": 4 * GIB - 128 * MIB,
                         "monitor_seconds": .1, "disk_scan_seconds": 1},
              "source_sha256": {name: sha_file(ROOT / name) for name in ("scripts/cohort_store.py", "scripts/cohort_metrics.py")}}
    try:
        archive = generate(scratch / "cohorts", args.nodes, args.requests_per_origin, guard)
        report["generation_seconds"] = time.monotonic() - started
        report["archive"] = {**footprint(archive.root), "root_index_sha256": archive.index_sha256}
        if report["archive"]["logical_bytes"] < args.minimum_archive_bytes:
            raise ValueError("generated archive did not exceed the requested aggregate byte threshold")
        shutil.copyfile(archive.path, output / "archive-index.json")
        database = CohortDatabase(scratch / "cohorts.sqlite", archive.ledgers)
        read_count = 0
        def reader(replica, stream):
            nonlocal read_count
            for row in archive.rows(replica, stream):
                read_count += 1
                if read_count % 1024 == 0: guard.check()
                yield row
            if stream == "batches" and (replica % 5 == 0 or replica + 1 == args.nodes):
                print(json.dumps({"phase": "verified_and_ingested", "replicas": replica + 1}), flush=True)
        reduction_started = time.monotonic()
        database.ingest(reader)
        summary = database.summarize(deadline_ms=1000)
        expected = args.nodes * args.requests_per_origin
        assert summary["scheduled"] == summary["admitted"] == summary["completed"] == expected
        assert summary["unfinished"] == 0 and summary["all_correct_collection"]["completed"] == expected
        assert summary["finite_run"]["u_out_bytes"] == expected * 8
        counts = {table: database.scalar(f"SELECT count(*) FROM {table}") for table in ("requests", "outputs", "batches", "latency")}
        assert counts["outputs"] == expected * args.nodes
        raw = canonical(summary); (output / "summary.json").write_bytes(raw)
        report.update(status="passed", reduction_seconds=time.monotonic() - reduction_started,
                      table_rows=counts, summary_sha256=hashlib.sha256(raw).hexdigest(),
                      archive_rows_verified=read_count, aggregate_archive_over_1GiB=report["archive"]["logical_bytes"] > GIB)
        database.close(); database = None
        report["sqlite_bytes"] = (scratch / "cohorts.sqlite").stat().st_size
        guard.check(disk=True)
    except BaseException as error:
        report["error"] = guard.error or f"{type(error).__name__}: {error}"
    finally:
        if database is not None: database.close()
        guard.stop.set(); guard.thread.join(timeout=2)
        report["elapsed_seconds"] = time.monotonic() - started
        report["whole_process_peak_rss_bytes"] = rss()
        report["peak_observed_scratch_bytes"] = max(guard.maximum_disk, footprint(scratch)["logical_bytes"])
        report["scratch_before_cleanup"] = footprint(scratch)
        marker = json.loads((scratch / "owner.json").read_text())
        if scratch.is_symlink() or scratch.stat().st_ino != inode or marker.get("nonce") != owner:
            raise ValueError("owned scratch identity changed; cleanup refused")
        shutil.rmtree(scratch)
        report["cleanup"] = {"owned_scratch_removed": not scratch.exists(), "path": str(scratch),
                             "identity_checked": "exclusive nonce marker and directory inode"}
        tempfile.tempdir = previous_temp
        report["evidence_limits"] = "Only recipe, source hashes, archive root/page-index digests and reduced output are retained; generated raw pages and SQLite were intentionally removed. Page hashes were checked during every ingest. No native signatures or protocol execution are asserted."
        (output / "manifest.json").write_bytes(canonical(report))
    print(json.dumps({"status": report["status"], "report": str(output / "manifest.json")}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
