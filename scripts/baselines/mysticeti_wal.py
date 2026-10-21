#!/usr/bin/env python3
"""Read-only audit of the pinned Mysticeti native WAL, independent of JSONL hooks.

This decodes the paper artifact's bincode/CRC formats, verifies native block
digests and Ed25519 signatures, and follows persisted CommitData.sub_dag order.
It does not reconstruct event times or treat a stored commit as a durable fsync.
Only a stopped process or a separately frozen complete WAL boundary is valid.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

MAP_SIZE = 0x10000000


class Reader:
    def __init__(self, data): self.data, self.pos = data, 0
    def take(self, size):
        if size < 0 or size > len(self.data)-self.pos:
            raise ValueError("truncated native bincode value")
        result = self.data[self.pos:self.pos+size]; self.pos += size
        return result
    def integer(self, size): return int.from_bytes(self.take(size), "little")
    def vector(self): return self.take(self.integer(8))
    def count(self, minimum=1):
        count = self.integer(8)
        if count > (len(self.data)-self.pos)//minimum:
            raise ValueError("native vector count exceeds remaining bytes")
        return count
    def finish(self):
        if self.pos != len(self.data): raise ValueError("trailing native bincode bytes")


def reference(reader):
    start = reader.pos
    author, round_number, digest = reader.integer(8), reader.integer(8), reader.vector()
    if len(digest) != 32: raise ValueError("native reference digest is not 32 bytes")
    return {"author":author,"round":round_number,"digest":digest,
            "id":reader.data[start:reader.pos].hex()}


def hash_reference(ref):
    return struct.pack(">QQ",ref["author"],ref["round"])+ref["digest"]


class Ed25519Verifier:
    """OpenSSL EVP verification; no Python packages or native rebuild required."""
    def __init__(self):
        # Apple's compatibility libcrypto stub aborts when dynamically loaded.
        homebrew = Path("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib")
        name = str(homebrew) if homebrew.exists() else ctypes.util.find_library("crypto")
        if not name: raise RuntimeError("OpenSSL libcrypto is required for native signature audit")
        self.lib = lib = ctypes.CDLL(name)
        pointer = ctypes.c_void_p
        for function, args, result in [
            ("EVP_PKEY_new_raw_public_key_ex",[pointer,ctypes.c_char_p,ctypes.c_char_p,pointer,ctypes.c_size_t],pointer),
            ("EVP_MD_CTX_new",[],pointer), ("EVP_MD_CTX_free",[pointer],None),
            ("EVP_PKEY_free",[pointer],None),
            ("EVP_DigestVerifyInit",[pointer,pointer,pointer,pointer,pointer],ctypes.c_int),
            ("EVP_DigestVerify",[pointer,pointer,ctypes.c_size_t,pointer,ctypes.c_size_t],ctypes.c_int),
        ]:
            call = getattr(lib,function); call.argtypes=args; call.restype=result
    def verify(self, public_key, signature, message):
        public_key,signature,message=bytes(public_key),bytes(signature),bytes(message)
        if len(public_key)!=32 or len(signature)!=64: raise ValueError("invalid Ed25519 encoding length")
        lib=self.lib
        key=lib.EVP_PKEY_new_raw_public_key_ex(None,b"ED25519",None,public_key,len(public_key))
        context=lib.EVP_MD_CTX_new()
        if not key or not context: raise RuntimeError("OpenSSL Ed25519 allocation failed")
        try:
            if lib.EVP_DigestVerifyInit(context,None,None,None,key)!=1:
                raise RuntimeError("OpenSSL Ed25519 initialization failed")
            if lib.EVP_DigestVerify(context,signature,len(signature),message,len(message))!=1:
                raise ValueError("native Ed25519 block signature failed")
        finally:
            lib.EVP_MD_CTX_free(context);lib.EVP_PKEY_free(key)


def decode_block(raw, public_keys, verifier):
    reader=Reader(raw);ref=reference(reader)
    includes=[reference(reader) for _ in range(reader.count(56))]
    unsigned=bytearray(struct.pack(">QQ",ref["author"],ref["round"]))
    for included in includes:unsigned.extend(hash_reference(included))
    transactions=[]
    def locator(offsets=1):
        value=hash_reference(reference(reader))
        return value+b"".join(reader.integer(8).to_bytes(8,"big") for _ in range(offsets))
    for _ in range(reader.count(4)):
        kind=reader.integer(4)
        if kind==0:
            payload=reader.vector();transactions.append(payload);unsigned.extend(b"\0"+payload)
        elif kind==1:
            location=locator();vote=reader.integer(4)
            if vote==0:unsigned.extend(b"\1"+location)
            elif vote==1:
                option=reader.integer(1)
                if option==0:unsigned.extend(b"\2"+location)
                elif option==1:unsigned.extend(b"\3"+location+locator())
                else:raise ValueError("invalid native optional reject locator")
            else:raise ValueError("invalid native vote")
        elif kind==2:unsigned.extend(b"\4"+locator(2))
        else:raise ValueError("invalid native base statement")
    unsigned.extend(reader.integer(16).to_bytes(16,"big"))
    epoch=reader.take(1)
    if epoch not in (b"\0",b"\1"):raise ValueError("invalid native epoch boolean")
    unsigned.extend(epoch)
    signature=reader.vector();reader.finish()
    if len(signature)!=64:raise ValueError("invalid native signature size")
    digest=hashlib.blake2b(unsigned+signature,digest_size=32).digest()
    if digest!=ref["digest"]:raise ValueError("native block digest mismatch")
    if ref["round"]:
        if ref["author"]>=len(public_keys):raise ValueError("native block author outside committee")
        verifier.verify(public_keys[ref["author"]],signature,hashlib.blake2b(unsigned,digest_size=32).digest())
    elif transactions or includes or signature!=b"\0"*64:
        raise ValueError("unexpected nonempty native genesis block")
    return ref,includes,transactions


def wal_entries(path, boundary=None):
    size=Path(path).stat().st_size
    if boundary is None:boundary=size
    if boundary<0 or boundary>size:raise ValueError("WAL boundary outside file")
    position=0
    with Path(path).open("rb") as stream:
        while position<boundary:
            stream.seek(position);header=stream.read(16)
            if len(header)!=16:raise ValueError("truncated native WAL header")
            crc,length,tag=struct.unpack("<QII",header)
            if length==0:
                if crc or tag:raise ValueError("nonzero padding header")
                following=(position//MAP_SIZE+1)*MAP_SIZE
                if following>boundary or any(stream.read(following-position-16)):
                    raise ValueError("invalid WAL map padding")
                position=following;continue
            if length<16 or length>MAP_SIZE or position+length>boundary:
                raise ValueError("incomplete WAL entry at declared boundary")
            if position//MAP_SIZE != (position+length-1)//MAP_SIZE:
                raise ValueError("native WAL record crosses map boundary")
            payload=stream.read(length-16)
            if len(payload)!=length-16 or zlib.crc32(payload)!=crc:
                raise ValueError("native WAL CRC mismatch")
            yield position,tag,payload
            position+=length


def committee_keys(path):
    # Intentionally narrow parser for the pinned artifact's emitted YAML arrays.
    text=Path(path).read_text();keys=[]
    for value in re.findall(r"  public_key:\n((?:  - \d+\n)+)",text):
        key=bytes(map(int,re.findall(r"\d+",value)))
        if len(key)!=32:raise ValueError("invalid committee public key")
        keys.append(key)
    if not keys or len(keys)!=text.count("  public_key:"):
        raise ValueError("unsupported native committee YAML")
    return keys


def workload_identity(payload, author):
    if len(payload)<40 or payload[8:16]!=b"DLGCOH01":return None
    origin,sequence,useful=struct.unpack_from("<QQQ",payload,16)
    if origin!=author or useful!=len(payload)-40:return None
    if any(byte!=(origin+sequence+index)%251 for index,byte in enumerate(payload[40:])):return None
    return {"request_id":f"{origin}:{sequence}:{hashlib.blake2b(payload[8:]).digest()[:32].hex()}",
            "origin":origin,"sequence":sequence,"useful_bytes":useful}


def replay(path, keys, boundary=None):
    verifier=Ed25519Verifier();blocks={};committed=set();outputs=[];batches=[]
    entries=0;commits=0;ordinal=0;invalid=0
    for position,tag,payload in wal_entries(path,boundary):
        entries+=1
        if tag in (1,3):
            ref,includes,transactions=decode_block(payload[8:] if tag==3 else payload,keys,verifier)
            block=(ref,includes,transactions)
            if ref["id"] in blocks and blocks[ref["id"]]!=block:raise ValueError("conflicting exact native block identity")
            blocks[ref["id"]]=block
        elif tag==5:
            reader=Reader(payload)
            for _ in range(reader.count(64)):
                leader=reference(reader);subdag=[reference(reader) for _ in range(reader.count(56))]
                if leader["id"] not in {ref["id"] for ref in subdag}:
                    raise ValueError("native commit omits its anchor")
                for ref in subdag:
                    batch=ref["id"]
                    if batch in committed:raise ValueError("native block committed twice")
                    if batch not in blocks:raise ValueError("committed payload absent from native WAL")
                    _,includes,transactions=blocks[batch]
                    if any(item["round"] and item["id"] not in blocks for item in includes):
                        raise ValueError("native committed block lacks retained ancestor")
                    committed.add(batch)
                    batches.append({"exact_batch_id":batch,"payload_bytes":sum(map(len,transactions))})
                    for transaction in transactions:
                        identity=workload_identity(transaction,ref["author"])
                        if identity is None:invalid+=1
                        else:outputs.append(identity|{"output_index":ordinal,"exact_batch_id":batch})
                        ordinal+=1
                commits+=1
            reader.vector();reader.finish()
        elif tag not in (2,4):raise ValueError(f"unknown native WAL tag {tag}")
    return {"outputs":outputs,"batches":batches,"native_output_count":ordinal,
            "uncredited_payload_count":invalid,"native_blocks_verified":len(blocks),
            "native_commit_count":commits,"wal_entries":entries,
            "boundary_bytes":Path(path).stat().st_size if boundary is None else boundary}


def compare_journal(replayed, path):
    events=[json.loads(line) for line in Path(path).read_text().splitlines() if line]
    keys=("request_id","origin","sequence","useful_bytes","output_index","exact_batch_id")
    observed=[{key:event[key] for key in keys} for event in events if event.get("event")=="materialized"]
    if observed!=replayed["outputs"]:raise ValueError("native WAL order/content differs from full output journal")
    observed_batches=[{key:event[key] for key in ("exact_batch_id","payload_bytes")}
                      for event in events if event.get("event")=="batch"]
    if observed_batches!=replayed["batches"]:raise ValueError("native WAL batches differ from full output journal")
    return {"exact_output_equal":True,"exact_batch_sequence_equal":True,"output_count":len(observed)}



# Bounded independent receipt-prefix verification. Legacy replay() above remains
# available for historical small artifacts; this path never materializes a WAL,
# block population, transaction vector or checkpoint sequence in Python memory.
STREAM_CHUNK = 64 * 1024
DEFAULT_DISK_BUDGET = 128 * 1024**3


class RecordReader:
    def __init__(self, stream, offset, length, expected_hash):
        self.stream, self.offset, self.length = stream, offset, length
        self.pos = 0
        self.hash = hashlib.sha256()
        self.body_hash = None
        self.expected_hash = expected_hash

    def chunks(self, size):
        if type(size) is not int or size < 0 or size > self.length-self.pos:
            raise ValueError("truncated streamed native bincode value")
        while size:
            self.stream.seek(self.offset+self.pos)
            raw = self.stream.read(min(size, STREAM_CHUNK))
            if not raw: raise ValueError("truncated streamed native record")
            self.hash.update(raw)
            if self.body_hash is not None: self.body_hash.update(raw)
            self.pos += len(raw); size -= len(raw)
            yield raw

    def take(self, size):
        if size > STREAM_CHUNK: raise ValueError("unbounded native field allocation")
        return b"".join(self.chunks(size))

    def integer(self, size): return int.from_bytes(self.take(size), "little")

    def count(self, minimum):
        count = self.integer(8)
        if count > (self.length-self.pos)//minimum:
            raise ValueError("native vector count exceeds streamed record")
        return count

    def finish(self):
        if self.pos != self.length or self.hash.hexdigest() != self.expected_hash:
            raise ValueError("native record changed during independent decoding")


def streamed_reference(reader):
    author, round_number, size = reader.integer(8), reader.integer(8), reader.integer(8)
    if size != 32: raise ValueError("native reference digest is not 32 bytes")
    digest = reader.take(32)
    raw = struct.pack("<QQQ", author, round_number, 32)+digest
    return {"author":author,"round":round_number,"digest":digest,"id":raw.hex(),"raw":raw}


def stream_records(stream, boundary):
    """CRC and byte hashes with <=64KiB reads, including 256MiB native records."""
    position = 0
    while position < boundary:
        if boundary-position < 16: raise ValueError("truncated native WAL header")
        stream.seek(position); header = stream.read(16)
        if len(header) != 16: raise ValueError("truncated native WAL header")
        crc, length, tag = struct.unpack("<QII", header)
        if length == 0:
            following = (position//MAP_SIZE+1)*MAP_SIZE
            if crc or tag or following > boundary: raise ValueError("invalid native WAL padding")
            remaining = following-position-16
            while remaining:
                raw = stream.read(min(remaining, STREAM_CHUNK))
                if not raw or any(raw): raise ValueError("invalid native WAL padding")
                remaining -= len(raw)
            position = following; continue
        if length < 16 or length > MAP_SIZE or position+length > boundary:
            raise ValueError("incomplete WAL entry before frozen prefix")
        if position//MAP_SIZE != (position+length-1)//MAP_SIZE:
            raise ValueError("native WAL record crosses map boundary")
        remaining = length-16; digest = hashlib.sha256(); actual_crc = 0
        while remaining:
            raw = stream.read(min(remaining, STREAM_CHUNK))
            if not raw: raise ValueError("truncated native WAL payload")
            remaining -= len(raw); digest.update(raw); actual_crc = zlib.crc32(raw, actual_crc)
        if actual_crc != crc: raise ValueError("native WAL CRC mismatch")
        yield position, tag, RecordReader(stream, position+16, length-16, digest.hexdigest())
        position += length


def _stream_block(reader, own, db, keys, verifier):
    if own: reader.take(8)
    reader.body_hash = hashlib.sha256()
    ref = streamed_reference(reader)
    if ref["author"] >= len(keys): raise ValueError("native block author outside committee")
    existing = db.execute("SELECT body_hash FROM blocks WHERE id=?",(ref["id"],)).fetchone()
    unsigned = hashlib.blake2b(digest_size=32)
    unsigned.update(struct.pack(">QQ",ref["author"],ref["round"]))
    includes = reader.count(56)
    for _ in range(includes):
        child = streamed_reference(reader)
        if child["author"] >= len(keys) or child["round"] >= ref["round"]:
            raise ValueError("native block has invalid ancestor reference")
        unsigned.update(hash_reference(child))
        if existing is None:
            db.execute("INSERT INTO edges VALUES(?,?,?)",(ref["id"],child["id"],int(child["round"]!=0)))
    shares = payload_bytes = 0
    def locator(offsets=1):
        value = hash_reference(streamed_reference(reader))
        return value+b"".join(reader.integer(8).to_bytes(8,"big") for _ in range(offsets))
    for _ in range(reader.count(4)):
        kind = reader.integer(4)
        if kind == 0:
            size = reader.integer(8); offset = reader.offset+reader.pos
            unsigned.update(b"\0"); txhash = hashlib.sha256()
            for raw in reader.chunks(size): unsigned.update(raw); txhash.update(raw)
            if existing is None:
                db.execute("INSERT INTO transactions VALUES(?,?,?,?,?)",(ref["id"],shares,offset,size,txhash.hexdigest()))
            shares += 1; payload_bytes += size
        elif kind == 1:
            location = locator(); vote = reader.integer(4)
            if vote == 0: unsigned.update(b"\1"+location)
            elif vote == 1:
                option = reader.integer(1)
                if option == 0: unsigned.update(b"\2"+location)
                elif option == 1: unsigned.update(b"\3"+location+locator())
                else: raise ValueError("invalid native optional reject locator")
            else: raise ValueError("invalid native vote")
        elif kind == 2: unsigned.update(b"\4"+locator(2))
        else: raise ValueError("invalid native base statement")
    unsigned.update(reader.integer(16).to_bytes(16,"big"))
    epoch = reader.take(1)
    if epoch not in (b"\0",b"\1"): raise ValueError("invalid native epoch boolean")
    unsigned.update(epoch)
    if reader.integer(8) != 64: raise ValueError("invalid native signature size")
    signature = reader.take(64); reader.finish()
    blockhash = unsigned.copy(); blockhash.update(signature)
    if blockhash.digest() != ref["digest"]: raise ValueError("native block digest mismatch")
    if ref["round"]: verifier.verify(keys[ref["author"]],signature,unsigned.digest())
    elif includes or shares or signature != b"\0"*64: raise ValueError("unexpected nonempty native genesis block")
    bodyhash = reader.body_hash.hexdigest()
    if existing is not None:
        if existing[0] != bodyhash: raise ValueError("conflicting exact native block identity")
        return False
    db.execute("INSERT INTO blocks VALUES(?,?,?,?,?)",(ref["id"],ref["raw"],ref["author"],payload_bytes,bodyhash))
    return True


def _field(hasher, value):
    hasher.update(struct.pack("<Q",len(value)));hasher.update(value)


def _stream_transaction(stream, offset, size, expected_hash, output_hash, author):
    """Raw output digest plus recipe identity; unknown payloads still advance."""
    output_hash.update(struct.pack("<Q",size)); rawhash=hashlib.sha256(); recipehash=hashlib.blake2b()
    stream.seek(offset); prefix=stream.read(min(size,40))
    if len(prefix)!=min(size,40): raise ValueError("truncated native transaction")
    output_hash.update(prefix);rawhash.update(prefix)
    candidate = len(prefix)==40 and prefix[8:16]==b"DLGCOH01"
    origin=sequence=useful=0
    if candidate:
        origin,sequence,useful=struct.unpack_from("<QQQ",prefix,16)
        candidate=origin==author and useful==size-40
        recipehash.update(prefix[8:])
    remaining=size-len(prefix);index=0
    while remaining:
        raw=stream.read(min(remaining,STREAM_CHUNK))
        if not raw: raise ValueError("truncated native transaction")
        output_hash.update(raw);rawhash.update(raw);remaining-=len(raw)
        if candidate:
            recipehash.update(raw)
            if any(value!=(origin+sequence+index+i)%251 for i,value in enumerate(raw)):candidate=False
        index+=len(raw)
    if rawhash.hexdigest()!=expected_hash:raise ValueError("signed native transaction changed before prefix join")
    if not candidate:return None
    return {"request_id":f"{origin}:{sequence}:{recipehash.digest()[:32].hex()}","origin":origin,"sequence":sequence,"useful_bytes":useful}


def _journal_events(path, event):
    import mysticeti_receipts as receipts
    with receipts.opened(path) as stream:
        while True:
            raw=stream.readline(4*1024*1024+1)
            if not raw:break
            if len(raw)>4*1024*1024 or not raw.endswith(b"\n"):raise ValueError("oversized or truncated native journal row")
            row=json.loads(raw)
            if row.get("event")==event:yield row


def _sha_stream(path):
    digest=hashlib.sha256()
    import mysticeti_receipts as receipts
    with receipts.opened(path) as stream:
        for raw in iter(lambda:stream.read(STREAM_CHUNK),b""):digest.update(raw)
    return digest.hexdigest()


def verify_receipt_prefix(path, keys, receipt, database_path, *, checkpoint_path=None, journal=None,
                          expected_wal_sha256=None, max_database_bytes=DEFAULT_DISK_BUDGET):
    """Verify exact frozen native prefix, with disk indices and bounded IO.

    CommitData is local persisted order, not a signed consensus certificate.
    Only the requested complete-block prefix is replayed; subsequent WAL bytes
    are hash-bound source evidence but explicitly outside this order claim.
    """
    import os, sqlite3, stat
    import mysticeti_receipts as receipts
    path=Path(path); database_path=Path(database_path)
    if database_path.exists():raise ValueError("independent WAL index must be new")
    if path.is_symlink() or path.parent.is_symlink():raise ValueError("native WAL symlink forbidden")
    if type(max_database_bytes)is not int or max_database_bytes<4096:raise ValueError("invalid WAL index disk budget")
    size=path.stat().st_size
    if not stat.S_ISREG(path.stat().st_mode) or size>DEFAULT_DISK_BUDGET:raise ValueError("native WAL file outside envelope")
    before=_sha_stream(path)
    if expected_wal_sha256 is not None and before!=expected_wal_sha256:raise ValueError("native WAL differs from archived source hash")
    header=receipt["header"]
    # Validate hashes/counts via the existing bounded checkpoint reader; do not
    # trust a subset or just a final membership count.
    checkpoints=receipts.checkpoints(receipt,path=checkpoint_path)
    target=header["batch_count"];counts=header["counts"]
    if _sha_stream(receipt["root"] / "header.json") != receipt["header_sha256"]:raise ValueError("receipt header changed before WAL join")
    db=sqlite3.connect(database_path)
    db.execute("PRAGMA cache_size=-16384");db.execute("PRAGMA temp_store=FILE");db.execute("PRAGMA mmap_size=0")
    db.execute("PRAGMA page_size=4096");db.execute("PRAGMA journal_mode=OFF");db.execute(f"PRAGMA max_page_count={max_database_bytes//4096}")
    db.executescript("""CREATE TABLE blocks(id TEXT PRIMARY KEY,raw BLOB,author INTEGER,payload INTEGER,body_hash TEXT);
      CREATE TABLE edges(block TEXT,child TEXT,non_genesis INTEGER);CREATE INDEX byblock ON edges(block);
      CREATE TABLE transactions(block TEXT,ordinal INTEGER,offset INTEGER,size INTEGER,sha256 TEXT,PRIMARY KEY(block,ordinal));
      CREATE TABLE committed(id TEXT PRIMARY KEY);CREATE TABLE materialized(origin INTEGER,sequence INTEGER,PRIMARY KEY(origin,sequence));""")
    output_hash=hashlib.blake2b();batch_hash=hashlib.blake2b()
    outputs=batches=payload_bytes=entries=blocks=commits=uncredited=trailing_commit_blocks=0;covered=0
    full_outputs=_journal_events(journal,"materialized") if journal is not None else None
    full_batches=_journal_events(journal,"batch") if journal is not None else None
    journal_hash=_sha_stream(journal) if journal is not None else None
    verifier=Ed25519Verifier()
    try:
        with receipts.opened(path, size) as stream:
            for position,tag,reader in (stream_records(stream,size) if target else ()):
                if batches==target:break
                entries+=1
                if tag in (1,3):blocks+=_stream_block(reader,tag==3,db,keys,verifier)
                elif tag==5:
                    for _ in range(reader.count(64)):
                        leader=streamed_reference(reader);anchor=False
                        for _ in range(reader.count(56)):
                            ref=streamed_reference(reader);anchor |= ref["id"]==leader["id"]
                            if batches==target:
                                trailing_commit_blocks+=1
                                continue
                            row=db.execute("SELECT raw,author,payload FROM blocks WHERE id=?",(ref["id"],)).fetchone()
                            if row is None:raise ValueError("frozen committed payload absent from native WAL")
                            if db.execute("SELECT 1 FROM edges e LEFT JOIN blocks b ON b.id=e.child WHERE e.block=? AND e.non_genesis=1 AND b.id IS NULL LIMIT 1",(ref["id"],)).fetchone():raise ValueError("native committed block lacks retained ancestor")
                            try:db.execute("INSERT INTO committed VALUES(?)",(ref["id"],))
                            except sqlite3.IntegrityError as error:raise ValueError("native block committed twice") from error
                            rawref,author,batchbytes=row
                            if full_batches is not None:
                                observed=next(full_batches,None)
                                if observed is None or any(observed.get(k)!=v for k,v in {"exact_batch_id":ref["id"],"payload_bytes":batchbytes}.items()):raise ValueError("native WAL batches differ from frozen full journal")
                            for offset,length,txsha in db.execute("SELECT offset,size,sha256 FROM transactions WHERE block=? ORDER BY ordinal",(ref["id"],)):
                                output_hash.update(b"mysticeti-native-output-v1\0");output_hash.update(struct.pack("<QQ",outputs,author));_field(output_hash,rawref)
                                identity=_stream_transaction(stream,offset,length,txsha,output_hash,author)
                                if identity is None:uncredited+=1
                                else:
                                    if full_outputs is not None:
                                        observed=next(full_outputs,None);expected=identity|{"output_index":outputs,"exact_batch_id":ref["id"]}
                                        if observed is None or any(observed.get(k)!=v for k,v in expected.items()):raise ValueError("native WAL output differs from frozen full journal")
                                    if identity["origin"]<len(counts) and identity["sequence"]<counts[identity["origin"]] and identity["useful_bytes"]==header["useful_bytes"]:
                                        db.execute("INSERT OR IGNORE INTO materialized VALUES(?,?)",(identity["origin"],identity["sequence"]))
                                outputs+=1
                            batch_hash.update(b"mysticeti-native-batch-v1\0");batch_hash.update(struct.pack("<Q",batches));_field(batch_hash,rawref);batch_hash.update(struct.pack("<QQ",batchbytes,outputs));_field(batch_hash,output_hash.digest())
                            batches+=1;payload_bytes+=batchbytes
                            expected={"batch_count":batches,"output_count":outputs,"payload_bytes":payload_bytes,"output_hash":output_hash.hexdigest(),"batch_hash":batch_hash.hexdigest()}
                            if next(checkpoints,None)!=expected:raise ValueError("native WAL complete-block checkpoint differs from frozen receipt")
                        if not anchor:raise ValueError("native commit omits its anchor")
                        commits+=1
                    for _ in reader.chunks(reader.integer(8)):pass
                    reader.finish();covered=reader.offset+reader.length
                elif tag in (2,4):pass
                else:raise ValueError(f"unknown native WAL tag {tag}")
                if entries%1024==0:db.commit()
                if batches==target:break
        if batches!=target:raise ValueError("native WAL ends before declared frozen terminal block")
        if next(checkpoints,None) is not None:raise ValueError("extra native receipt checkpoint")
        if full_outputs is not None and (next(full_outputs,None) is not None or next(full_batches,None) is not None):raise ValueError("full journal extends beyond independently verified frozen prefix")
        for origin,count in enumerate(counts):
            values=iter(db.execute("SELECT sequence FROM materialized WHERE origin=? ORDER BY sequence",(origin,)));current=next(values,None)
            with receipts.bitmap(receipt,"materialized",origin) as source:
                for offset in range(0,(count+7)//8,receipts.CHUNK):
                    n=min(receipts.CHUNK,(count+7)//8-offset);expected=bytearray(n)
                    while current is not None and current[0]<(offset+n)*8:
                        sequence=current[0];expected[sequence//8-offset]|=1<<(sequence%8);current=next(values,None)
                    if source.read(n)!=expected:raise ValueError("native WAL membership differs from receipt materialized bitmap")
        if _sha_stream(path)!=before:raise ValueError("native WAL changed during prefix verification")
        if journal is not None and _sha_stream(journal)!=journal_hash:raise ValueError("native full journal changed during prefix verification")
        if _sha_stream(receipt["root"] / "header.json") != receipt["header_sha256"]:raise ValueError("receipt header changed during WAL join")
        db.commit()
        return {"status":"verified","scope":"signature-verified native block bytes and locally persisted CommitData order through the exact complete-block observer freeze; not a consensus certificate or fsync proof",
            "receipt_header_sha256":receipt["header_sha256"],"wal_sha256":before,"wal_bytes":size,"covered_wal_record_end":covered,
            "later_wal_bytes_outside_prefix_claim":size-covered,"commit_subdag_blocks_after_frozen_prefix":trailing_commit_blocks,"batch_count":batches,"native_output_count":outputs,"payload_bytes":payload_bytes,
            "output_hash":output_hash.hexdigest(),"batch_hash":batch_hash.hexdigest(),"native_blocks_verified":blocks,"wal_entries":entries,
            "native_commit_records":commits,"unknown_or_foreign_outputs":uncredited,"exact_checkpoint_sequence_equal":True,"materialized_membership_equal":True,
            "full_journal_equal":True if journal is not None else None,"full_journal_sha256":journal_hash,
            "bounds":{"read_chunk_bytes":STREAM_CHUNK,"sqlite_cache_bytes":16*1024**2,"database_bytes":database_path.stat().st_size,"database_budget_bytes":max_database_bytes},
            "reader_sha256":_sha_stream(Path(__file__))}
    finally:
        db.close()
        checkpoints.close()
        if full_outputs is not None:full_outputs.close();full_batches.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wal",required=True,type=Path);parser.add_argument("--committee",required=True,type=Path)
    parser.add_argument("--journal",type=Path);parser.add_argument("--boundary",type=int);parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args();result=replay(args.wal,committee_keys(args.committee),args.boundary)
    if args.journal:result["journal_agreement"]=compare_journal(result,args.journal)
    result["provenance"]={"wal_sha256":hashlib.sha256(args.wal.read_bytes()).hexdigest(),
                          "committee_sha256":hashlib.sha256(args.committee.read_bytes()).hexdigest(),
                          "reader_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({key:value for key,value in result.items() if key not in ("outputs","batches")}))


if __name__=="__main__":main()
