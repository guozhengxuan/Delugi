"""Hash-bound runtime evidence streams with bounded memory and exclusive output.

Build/configuration tar safety limits are deliberately independent. This format
allows large journals and many shards without an in-memory archive member map.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

MAGIC = b"DELUGI-RUNTIME-EVIDENCE-1\n"
FORMAT = "delugi-runtime-evidence-v1"
CHUNK_BYTES = 8 * 1024**2
HEADER_BYTES = 16 * 1024
MAX_FILES = 2_000_000
MAX_PAYLOAD_BYTES = 128 * 1024**3


def envelope():
    return {"chunk_bytes": CHUNK_BYTES, "max_files_per_host": MAX_FILES,
            "max_payload_bytes_per_host": MAX_PAYLOAD_BYTES,
            "remote_archive_copy": False,
            "controller_storage": "retained stream plus verified extracted files; both count against available disk"}


def relative(name):
    if (not isinstance(name, str) or not name or len(name.encode()) > 4096
            or "\\" in name or "\x00" in name):
        raise ValueError("invalid evidence path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("unsafe evidence path")
    return path


def beneath(root, name, create=False):
    parts = relative(name).parts
    path = Path(root)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("evidence root must be an existing real directory")
    for part in parts[:-1]:
        path = path / part
        if create:
            path.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("evidence parent is not a real directory")
    path = path / parts[-1]
    if path.is_symlink():
        raise ValueError("evidence symlink refused")
    return path


class Writer:
    def __init__(self, stream):
        self.stream, self.digest, self.bytes = stream, hashlib.sha256(), 0

    def write(self, data):
        # Buffered local files/stdout use full writes. Reject an exceptional short
        # write rather than emitting a stream whose final receipt claims success.
        written = self.stream.write(data)
        if written != len(data):
            raise OSError("short evidence write")
        self.digest.update(data)
        self.bytes += len(data)

    def record(self, value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        if len(raw) > HEADER_BYTES:
            raise ValueError("evidence header exceeds limit")
        self.write(raw)


class Reader:
    def __init__(self, stream):
        self.stream, self.digest, self.bytes = stream, hashlib.sha256(), 0

    def consume(self, raw):
        self.digest.update(raw)
        self.bytes += len(raw)
        return raw

    def exact(self, size):
        # File streams read complete chunks unless EOF; bounded callers never
        # request a payload larger than CHUNK_BYTES.
        raw = self.stream.read(size)
        if len(raw) != size:
            raise ValueError("truncated evidence stream")
        return self.consume(raw)

    def record(self):
        raw = self.stream.readline(HEADER_BYTES + 1)
        if len(raw) > HEADER_BYTES or not raw.endswith(b"\n"):
            raise ValueError("missing or oversized evidence header")
        value = json.loads(self.consume(raw))
        if not isinstance(value, dict):
            raise ValueError("evidence record must be an object")
        return value


def pack(root, names, stream, metadata, *, chunk_bytes=CHUNK_BYTES,
         max_files=MAX_FILES, max_payload_bytes=MAX_PAYLOAD_BYTES):
    if type(chunk_bytes) is not int or not 1 <= chunk_bytes <= CHUNK_BYTES:
        raise ValueError("invalid evidence chunk size")
    writer = Writer(stream)
    writer.write(MAGIC)
    writer.record({"record": "header", "metadata": metadata, "chunk_bytes": chunk_bytes})
    count = total = 0
    for name in names:
        path = beneath(root, name)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("evidence input must be a regular file")
            count += 1
            total += before.st_size
            if count > max_files or total > max_payload_bytes:
                raise ValueError("runtime evidence exceeds declared disk/file envelope")
            writer.record({"record": "file", "path": name, "bytes": before.st_size})
            digest, consumed = hashlib.sha256(), 0
            while consumed < before.st_size:
                raw = source.read(min(chunk_bytes, before.st_size - consumed))
                if not raw:
                    raise ValueError("evidence source shrank while streaming")
                digest.update(raw)
                consumed += len(raw)
                writer.record({"record": "chunk", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
                writer.write(raw)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError("evidence source changed while streaming")
            writer.record({"record": "end_file", "sha256": digest.hexdigest()})
    writer.record({"record": "end", "files": count, "payload_bytes": total})
    return {"format": FORMAT, "sha256": writer.digest.hexdigest(), "bytes": writer.bytes,
            "files": count, "payload_bytes": total, "metadata": metadata}


def unpack(stream, root, *, expected_sha256=None, expected_metadata=None,
           max_files=MAX_FILES, max_payload_bytes=MAX_PAYLOAD_BYTES):
    reader = Reader(stream)
    if reader.exact(len(MAGIC)) != MAGIC:
        raise ValueError("unsupported runtime evidence format")
    header = reader.record()
    chunk_bytes = header.get("chunk_bytes")
    if (header.get("record") != "header" or type(chunk_bytes) is not int
            or not 1 <= chunk_bytes <= CHUNK_BYTES):
        raise ValueError("invalid runtime evidence header")
    if expected_metadata is not None and header.get("metadata") != expected_metadata:
        raise ValueError("runtime evidence ownership metadata differs")
    count = total = 0
    while True:
        entry = reader.record()
        if entry.get("record") == "end":
            if entry.get("files") != count or entry.get("payload_bytes") != total:
                raise ValueError("runtime evidence terminal counts differ")
            if stream.read(1):
                raise ValueError("trailing runtime evidence bytes")
            break
        size = entry.get("bytes")
        if entry.get("record") != "file" or type(size) is not int or size < 0:
            raise ValueError("invalid evidence file header")
        count += 1
        total += size
        if count > max_files or total > max_payload_bytes:
            raise ValueError("runtime evidence exceeds declared disk/file envelope")
        path = beneath(root, entry.get("path"), create=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        digest, consumed = hashlib.sha256(), 0
        with os.fdopen(descriptor, "wb") as target:
            while consumed < size:
                part = reader.record()
                length = part.get("bytes")
                if (part.get("record") != "chunk" or type(length) is not int
                        or not 1 <= length <= min(chunk_bytes, size-consumed)):
                    raise ValueError("invalid evidence chunk length")
                raw = reader.exact(length)
                if hashlib.sha256(raw).hexdigest() != part.get("sha256"):
                    raise ValueError("evidence chunk hash differs")
                target.write(raw)
                digest.update(raw)
                consumed += length
        close = reader.record()
        if close.get("record") != "end_file" or close.get("sha256") != digest.hexdigest():
            raise ValueError("evidence file hash differs")
    actual = reader.digest.hexdigest()
    if expected_sha256 is not None and actual != expected_sha256:
        raise ValueError("runtime evidence stream hash differs")
    return {"format": FORMAT, "sha256": actual, "bytes": reader.bytes,
            "files": count, "payload_bytes": total, "metadata": header.get("metadata")}


def selected_files(root):
    """Explicit runtime evidence allowlist; no private configuration or stores."""
    root = Path(root)
    with os.scandir(root) as entries:
        for entry in entries:
            path = Path(entry.path)
            if entry.name in ("logs", "observer", "cohorts"):
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    raise ValueError("runtime evidence directory was substituted")
                yield from walk_files(root, path)
            elif (entry.name in ("result.json", "ledger.json", "host-events.jsonl", "cohort.jsonl", "admitted.jsonl", "io.json", "omission-interval.txt")
                  or entry.name.startswith(("crypto-", "omissions-"))):
                if not entry.is_file(follow_symlinks=False):
                    raise ValueError("runtime evidence file was substituted")
                yield entry.name


def walk_files(root, directory):
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.is_symlink():
                raise ValueError("runtime evidence symlink refused")
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                yield from walk_files(root, path)
            elif entry.is_file(follow_symlinks=False):
                yield path.relative_to(root).as_posix()
            else:
                raise ValueError("runtime evidence input is not a regular file")
