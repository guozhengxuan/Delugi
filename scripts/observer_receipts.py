"""Bounded finite receipts common to detailed and compact Delugi observers.

Replica signatures are verified by the Rust archive verifier. This module checks
pagination, hashes, finite set algebra and every correct overlapping prefix;
no timestamp or latency is reconstructed from compact membership.
"""
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from pathlib import Path
import json
import os
import stat

FORMAT = "delugi-observer-receipts-v1"
CHUNK = 4096
LOCAL_STREAMS = ("admitted", "rejected", "ready", "completed", "seen_output")


def _data(record):
    return record["reply"]["data"]


def configured_counts(config):
    load = config["sustained"]
    origins = load.get("origins", list(range(len(config["addresses"]))))
    duration_ms = load["warmup_ms"] + load["measurement_ms"]
    if "total_rate" in load and load["total_rate"] is not None:
        total = duration_ms * load["total_rate"] // 1000
        return {origin: (total + len(origins) - 1 - rank) // len(origins) for rank, origin in enumerate(origins)}
    return {origin: duration_ms * load["rate_per_replica"] // 1000 for origin in origins}


def collect(controller, snapshots, destination, correct, counts, mode):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    index = {"schema": 3, "format": FORMAT, "replicas": {},
             "resource_contract": {"bitmap_page_bytes": CHUNK, "reducer_chunk_bytes": CHUNK,
                 "population_storage": "finite bitmaps; protocol/application logs remain retained"}}
    if mode not in ("full", "compact") or not set(counts) <= set(snapshots) or any(type(v) is not int or v < 0 for v in counts.values()):
        raise ValueError("invalid trusted finite receipt configuration")
    header_bytes = 0
    for replica in sorted(snapshots):
        signed = _data(controller.request(replica, "receipt"))["receipt"]
        body = signed["body"]
        if signed["signer"] != replica or body["replica"] != replica or body["output_count"] != snapshots[replica]["executed_count"] or body["batch_count"] != snapshots[replica]["materialized_batch_count"]:
            raise AssertionError("frozen receipt differs from materialization snapshot")
        expected_streams = {("materialized", origin) for origin in counts}
        if replica in counts: expected_streams.update((name, replica) for name in LOCAL_STREAMS)
        if body["mode"] != mode or len(body["streams"]) != len(expected_streams) or not 0 <= body["scheduled"] <= counts.get(replica, 0):
            raise AssertionError("receipt differs from trusted observer configuration")
        if replica in counts:
            if body.get("manifest", {}).get("body", {}).get("count") != counts[replica]:
                raise AssertionError("receipt manifest population differs from configuration")
        elif body.get("manifest") is not None:
            raise AssertionError("disabled origin has receipt manifest")
        header_bytes += len(json.dumps(signed, separators=(",", ":")).encode())
        if header_bytes > 768 * 1024: raise AssertionError("receipt headers exceed index budget")
        # Validate the entire declared stream set before the first bitmap RPC.
        keys = [(d.get("name"), d.get("origin")) for d in body["streams"]]
        if len(set(keys)) != len(keys) or set(keys) != expected_streams or any(d.get("count") != counts.get(d.get("origin")) for d in body["streams"]):
            raise AssertionError("receipt bitmap population differs from trusted configuration")
        entry = {"receipt": signed, "streams": []}
        seen = set()
        for descriptor in body["streams"]:
            name, origin = descriptor["name"], descriptor["origin"]
            if name not in (*LOCAL_STREAMS, "materialized") or type(origin) is not int or origin not in snapshots or (name, origin) in seen:
                raise AssertionError("unknown or duplicate receipt stream")
            seen.add((name, origin))
            if any(type(descriptor[k]) is not int or descriptor[k] < 0 for k in ("count", "bytes", "ones")) or descriptor["bytes"] != (descriptor["count"] + 7) // 8 or descriptor["ones"] > descriptor["count"]:
                raise AssertionError("invalid finite receipt population")
            relative = f"replica-{replica}-{name}-{origin}.bits"
            offset, ones, digest, last = 0, 0, sha256(), 0
            with (destination / relative).open("xb") as stream:
                while True:
                    page = _data(controller.request(replica, "receipt_bitmap", receipt_origin=origin,
                                                    receipt_stream=name, offset=offset, limit=CHUNK))
                    raw = page["bytes"]
                    if not isinstance(raw, list) or len(raw) > CHUNK or any(type(v) is not int or not 0 <= v <= 255 for v in raw):
                        raise AssertionError("invalid bounded receipt page")
                    content = bytes(raw)
                    if page["origin"] != origin or page["stream"] != name or page["offset"] != offset or page["total"] != descriptor["bytes"]:
                        raise AssertionError("receipt page metadata changed")
                    offset += len(content)
                    if offset > descriptor["bytes"] or (not content and offset != descriptor["bytes"]):
                        raise AssertionError("receipt page is empty or exceeds population")
                    stream.write(content); digest.update(content)
                    ones += sum(v.bit_count() for v in content)
                    if content: last = content[-1]
                    expected_next = offset if offset < descriptor["bytes"] else None
                    if page.get("next_offset") != expected_next:
                        raise AssertionError("invalid receipt pagination")
                    if expected_next is None: break
            if list(digest.digest()) != descriptor["sha256"] or ones != descriptor["ones"] or (descriptor["count"] % 8 and last >> (descriptor["count"] % 8)):
                raise AssertionError("receipt hash, membership count or padding mismatch")
            entry["streams"].append({"name": name, "origin": origin, "path": relative})
        index["replicas"][str(replica)] = entry
    path = destination / "index.json"
    raw = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > 1024 * 1024: raise AssertionError("receipt index exceeds bound")
    path.write_bytes(raw)
    agreement = {}
    for kind, count_field, hash_field in (("outputs", "output_count", "output_fingerprint"), ("batches", "batch_count", "batch_fingerprint")):
        bodies = {r: index["replicas"][str(r)]["receipt"]["body"] for r in correct}
        checks = []
        for count in sorted({b[count_field] for b in bodies.values()}):
            peers = [r for r in correct if bodies[r][count_field] >= count]
            replies = controller.many(peers, "receipt_prefix", count=count, receipt_stream=kind)
            if len(replies) != len(peers): raise AssertionError("missing exact receipt prefix")
            fingerprints = set()
            for reply in replies:
                value, replica = _data(reply), reply["replica"]
                if replica not in peers or value["count"] != count or value["total"] != bodies[replica][count_field]:
                    raise AssertionError("receipt prefix count differs")
                fingerprint = tuple(value["fingerprint"])
                if count == bodies[replica][count_field] and fingerprint != tuple(bodies[replica][hash_field]):
                    raise AssertionError("signed receipt differs from exact local prefix")
                fingerprints.add(fingerprint)
            if len({r["replica"] for r in replies}) != len(peers) or len(fingerprints) != 1:
                raise AssertionError("correct exact receipt prefixes disagree")
            checks.append({"count": count, "replicas": peers, "fingerprint": list(next(iter(fingerprints)))})
        agreement[kind] = {"all_correct_overlap_prefixes_verified": True, "checks": checks}
    return {"path": str(path), "sha256": sha256(raw).hexdigest(), "schema": 3,
            "agreement": agreement, "resource_contract": index["resource_contract"]}, index


@contextmanager
def _verified_bitmap(path, descriptor):
    """Authenticate the exact bounded bytes consumed by the reducer."""
    if (any(type(descriptor.get(k)) is not int or descriptor[k] < 0 for k in ("count", "bytes", "ones"))
            or descriptor["bytes"] != (descriptor["count"] + 7) // 8
            or descriptor["ones"] > descriptor["count"]):
        raise AssertionError("invalid finite bitmap descriptor")
    expected = descriptor.get("sha256")
    if not isinstance(expected, list) or len(expected) != 32 or any(type(v) is not int or not 0 <= v <= 255 for v in expected):
        raise AssertionError("invalid finite bitmap digest")

    class Reader:
        def __init__(self, stream):
            self.stream, self.digest = stream, sha256()
            self.offset = self.ones = self.last = 0

        def read(self, size):
            if not 0 <= size <= CHUNK or self.offset + size > descriptor["bytes"]:
                raise AssertionError("finite bitmap read exceeds bounded population")
            raw = self.stream.read(size)
            if len(raw) != size:
                raise AssertionError("truncated finite bitmap")
            self.offset += len(raw)
            self.digest.update(raw)
            self.ones += sum(v.bit_count() for v in raw)
            if raw: self.last = raw[-1]
            return raw

        def finish(self):
            if self.offset != descriptor["bytes"] or self.stream.read(1):
                raise AssertionError("truncated or oversized finite bitmap")
            if (list(self.digest.digest()) != expected or self.ones != descriptor["ones"]
                    or (descriptor["count"] % 8 and self.last >> (descriptor["count"] % 8))):
                raise AssertionError("consumed bitmap hash, membership count or padding mismatch")

    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != descriptor["bytes"]:
            raise AssertionError("truncated or oversized finite bitmap")
        reader = Reader(stream)
        yield reader
        reader.finish()


def summarize(index, root, correct):
    """O(n*chunk) memory; useful credit requires event-latched origin eligibility."""
    root = Path(root)
    by_replica = index["replicas"]
    streams = {(int(replica), item["name"], item["origin"]): root / item["path"]
               for replica, value in by_replica.items() for item in value["streams"]}
    descriptors = {(int(replica), item["name"], item["origin"]): item
                   for replica, value in by_replica.items() for item in value["receipt"]["body"]["streams"]}
    scheduled = admitted = rejected = ready = local_completed = all_completed = expected = 0
    credited_by_replica = dict.fromkeys(correct, 0)
    useful = None
    for origin in correct:
        body = by_replica[str(origin)]["receipt"]["body"]
        if body["manifest"] is None: raise AssertionError("honest origin lacks finite receipt manifest")
        count = body["manifest"]["body"]["count"]
        expected += count; scheduled += body["scheduled"]
        payload_bytes = body["manifest"]["body"]["useful_bytes"]
        if useful is not None and payload_bytes != useful: raise AssertionError("mixed receipt useful payload size")
        useful = payload_bytes
        with ExitStack() as stack:
            def opened(key):
                if descriptors[key]["count"] != count:
                    raise AssertionError("bitmap differs from signed origin population")
                return stack.enter_context(_verified_bitmap(streams[key], descriptors[key]))
            files = {name: opened((origin, name, origin)) for name in LOCAL_STREAMS}
            outputs = [opened((replica, "materialized", origin)) for replica in correct]
            offset = 0
            while offset < (count + 7) // 8:
                n = min(CHUNK, (count + 7) // 8 - offset)
                pieces = {name: f.read(n) for name, f in files.items()}
                materialized = [f.read(n) for f in outputs]
                if any(len(x) != n for x in [*pieces.values(), *materialized]): raise AssertionError("truncated finite bitmap")
                for i in range(n):
                    a, r, b, c, seen = (pieces[name][i] for name in LOCAL_STREAMS)
                    scheduled_mask = (1 << min(8, max(0, body["scheduled"] - 8*(offset+i)))) - 1
                    if a & r or a | r != scheduled_mask or b & ~a or c & ~(a & seen):
                        raise AssertionError("inconsistent finite admission/eligibility receipt")
                    if materialized[correct.index(origin)][i] != seen: raise AssertionError("own output receipt differs from seen identities")
                    shared = c
                    for replica, output in zip(correct, materialized):
                        shared &= output[i]
                        credited_by_replica[replica] += (c & output[i]).bit_count()
                    admitted += a.bit_count(); rejected += r.bit_count(); ready += b.bit_count()
                    local_completed += c.bit_count(); all_completed += shared.bit_count()
                offset += n
    reference = correct[0]
    reference_body = by_replica[str(reference)]["receipt"]["body"]
    return {"reference_replica": reference,
        "reference_output_count": reference_body["output_count"],
        "reference_batch_count": reference_body["batch_count"],
        "reference_m_out_bytes": reference_body["m_out_bytes"],
        "reference_unique_eligible_u_out_bytes": credited_by_replica[reference] * (useful or 0),
        "unique_eligible_output_count_by_replica": credited_by_replica,
        "scheduled": expected, "arrived": scheduled, "admitted": admitted, "rejected": rejected,
        "not_yet_arrived": expected-scheduled, "batch_ready": ready, "local_completed": local_completed,
        "unfinished": expected-local_completed, "all_correct_completed": all_completed,
        "all_correct_unfinished": expected-all_completed, "latency_available": False,
        "latency_quantiles": None, "deadline_misses": None,
        "population": "finite configured honest origins; useful completion latched at original local append after admission",
        "mode": next(iter(by_replica.values()))["receipt"]["body"]["mode"]}
