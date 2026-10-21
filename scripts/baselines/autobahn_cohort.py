#!/usr/bin/env python3
"""Independent Autobahn application ingress and contiguous payload materializer.

Native primary/worker observers expose ordered headers and locally retained batch
bytes. This process verifies the native SHA512 batch digest and application
identity before output; missing payload blocks its entire later output prefix.
It never fetches or fabricates a missing native batch.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import threading
import time
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_receipts


def application_payload(origin, sequence, useful_bytes):
    return (b"\x01" + b"\0" * 7 + b"DLGCOH01" + struct.pack("<QQQ", origin, sequence, useful_bytes)
            + bytes((origin + sequence + i) % 251 for i in range(useful_bytes)))


def request_identity(payload):
    if len(payload) < 40 or payload[8:16] != b"DLGCOH01":
        raise ValueError("native output lacks authenticated workload identity")
    origin, sequence, useful = struct.unpack_from("<QQQ", payload, 16)
    if useful != len(payload)-40:
        raise ValueError("native output content size differs from finite workload")
    if payload != application_payload(origin, sequence, useful):
        raise ValueError("native output content differs from finite workload")
    return origin, sequence, useful, f"{origin}:{sequence}:{hashlib.blake2b(payload[8:]).digest()[:32].hex()}"


def decode_batch(raw, digest):
    if hashlib.sha512(raw).digest()[:32].hex() != digest:
        raise ValueError("local native batch digest verification failed")
    if len(raw) < 12 or struct.unpack_from("<I", raw)[0] != 0:
        raise ValueError("native worker object is not the original bincode Batch variant")
    count = struct.unpack_from("<Q", raw, 4)[0]
    if count > (len(raw)-12)//8:
        raise ValueError("native batch count exceeds available bytes")
    cursor, transactions = 12, []
    for _ in range(count):
        if cursor+8 > len(raw): raise ValueError("truncated native transaction length")
        size = struct.unpack_from("<Q", raw, cursor)[0]; cursor += 8
        if size > len(raw)-cursor: raise ValueError("truncated native transaction payload")
        transactions.append(raw[cursor:cursor+size]); cursor += size
    if cursor != len(raw): raise ValueError("extra bytes in native batch")
    return transactions


def canonical_slot(headers, previous):
    """Topological within-slot zipper; never sorts across committed slots.

    Native validation supplies complete per-lane ancestor histories. The
    application's order must be deterministic although the artifact's unused
    upcall iterates HashMap proposals. Validate per-lane parent continuity too.
    """
    ordered=sorted(headers,key=lambda h:(h["height"],h["author"],h["header_id"]))
    next_previous=dict(previous)
    seen=set()
    for header in ordered:
        key=header["header_id"]
        if key in seen:raise ValueError("duplicate native header in completed slot")
        seen.add(key)
        prior=next_previous.get(header["author"])
        if prior is None:
            if header["height"]!=1:raise ValueError("native lane history does not begin at genesis successor")
        elif header["height"]<=prior["height"] or header["parent_id"]!=prior["header_id"]:
            raise ValueError("native committed lane history lacks topological parent continuity")
        next_previous[header["author"]]=header
    previous.clear();previous.update(next_previous)
    return ordered


def collect(args):
    now = lambda: max(0,(time.clock_gettime_ns(time.CLOCK_MONOTONIC)-args.epoch_ns)//1000)
    deadline = args.warmup_us+args.duration_us+args.drain_us
    count = (args.warmup_us+args.duration_us)*args.rate//1_000_000
    detailed=getattr(args,"cohort_observer","full")=="full"
    planned=getattr(args,"planned_counts",None)
    counts=[int(value) for value in planned.split(",")] if planned else [0]*args.origin+[count]
    if args.origin>=len(counts) or counts[args.origin]!=count:raise ValueError("Origin finite plan differs from arrival schedule")
    receipt=native_receipts.Receipt(counts,args.useful_bytes)
    admitted=bytearray((count+7)//8)
    native_enqueued=0
    requests={}
    for sequence in range(count if detailed else 0):
        payload=application_payload(args.origin,sequence,args.useful_bytes)
        _,_,_,identity=request_identity(payload)
        requests[identity]={"request_id":identity,"origin":args.origin,"sequence":sequence,
                            "useful_bytes":args.useful_bytes,"scheduled_us":sequence*1_000_000//args.rate,
                            "admitted_us":None,"batch_ready_us":None,"materialized_us":None}
    ledger={"requests":list(requests.values()),"output_index_base":0,"outputs":[],"batches":[],
            "window_start_us":args.warmup_us,"window_end_us":args.warmup_us+args.duration_us,
            "observed_us":deadline,"clock":"same-host CLOCK_MONOTONIC; origin ingress/materializer process",
            "cohort_observer":"full" if detailed else "compact"}
    errors=[]
    def ingress():
        nonlocal native_enqueued
        stream=None
        try:
            host,port=args.address.rsplit(":",1)
            while time.clock_gettime_ns(time.CLOCK_MONOTONIC)<args.epoch_ns+deadline*1000:
                try: stream=socket.create_connection((host,int(port)),timeout=0.2);break
                except OSError: time.sleep(0.01)
            if stream is None:return
            stream.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            stream.settimeout(max(0.001,deadline/1e6))
            rows=list(requests.values()) if detailed else None
            for sequence in range(count):
                due=args.epoch_ns+(sequence*1_000_000//args.rate)*1000
                while time.clock_gettime_ns(time.CLOCK_MONOTONIC)<due:
                    time.sleep(max(0,min(0.001,(due-time.clock_gettime_ns(time.CLOCK_MONOTONIC))/1e9)))
                if now()>=deadline:break
                payload=application_payload(args.origin,sequence,args.useful_bytes)
                admitted[sequence//8]|=1<<(sequence%8)
                if detailed:rows[sequence]["admitted_us"]=now()
                # Admission is this independent application ingress; native send
                # backpressure delays subsequent arrivals but never their schedule.
                stream.sendall(struct.pack(">I",len(payload))+payload)
                native_enqueued+=1
                if detailed:rows[sequence]["native_enqueued_us"]=now()
        except (OSError,TimeoutError) as error:
            ledger["ingress_stop_reason"]=str(error)
        finally:
            if stream:stream.close()
    thread=threading.Thread(target=ingress,daemon=True);thread.start()
    header_path=args.observer_dir/"primary"/"slots.jsonl"
    headers=[]; pending=0; offset=0; buffer=b""; seen=set(); available={}
    worker_offsets={worker: [0,b""] for worker in range(args.workers)}
    slot_buffer={};next_slot=1;previous_headers={}
    while now()<deadline:
        if header_path.exists():
            with header_path.open("rb") as stream:
                stream.seek(offset);chunk=stream.read();offset+=len(chunk);buffer+=chunk
            lines=buffer.split(b"\n");buffer=lines.pop()
            for line in lines:
                if not line:continue
                event=json.loads(line)
                if event["event"]=="header":
                    slot_buffer.setdefault(event["slot"],[]).append(event)
                elif event["event"]=="complete":
                    if event["slot"]!=next_slot:raise ValueError("native commit slot sequence has a gap")
                    # The paper requires a deterministic within-slot zipper.
                    # Upstream's unused application upcall iterates a HashMap;
                    # linearize the exact committed slot set here, not votes.
                    complete=slot_buffer.pop(next_slot,[])
                    headers.extend(canonical_slot(complete,previous_headers))
                    next_slot+=1
                else:raise ValueError("unknown native slot observation")
        # A local availability marker is emitted after a native Store read has
        # completed, and atomic rename makes only complete payloads visible.
        for worker in range(args.workers):
            directory=args.observer_dir/f"worker-{worker}"
            journal=directory/"available.jsonl"
            if not journal.exists():continue
            state=worker_offsets[worker]
            with journal.open("rb") as stream:
                stream.seek(state[0]); chunk=stream.read();state[0]+=len(chunk);state[1]+=chunk
            lines=state[1].split(b"\n");state[1]=lines.pop()
            for line in lines:
                if not line:continue
                meta=json.loads(line);digest=meta["digest"]
                if digest in available:continue
                raw=(directory/f"batch-{digest}.bin").read_bytes()
                transactions=decode_batch(raw,digest)
                available[digest]=(meta,transactions)
                for payload in transactions:
                    origin,sequence,useful,identity=request_identity(payload)
                    if origin==args.origin:
                        if sequence>=count or useful!=args.useful_bytes:raise ValueError("native payload absent from own finite manifest")
                        if not admitted[sequence//8]&(1<<(sequence%8)):raise ValueError("native payload observed before application admission")
                        if detailed:
                            row=requests[identity]
                            row["batch_ready_us"]=max(row["admitted_us"],meta["available_us"])
        while pending<len(headers):
            header=headers[pending]
            if any(digest not in available for digest in header["batches"]):break
            for digest in header["batches"]:
                if digest in seen:continue
                seen.add(digest);meta,transactions=available[digest]
                materialized=now()
                if materialized>deadline:break
                payload_bytes=sum(map(len,transactions))
                if detailed:ledger["batches"].append({"exact_batch_id":digest,"payload_bytes":payload_bytes,"materialized_us":materialized})
                for payload in transactions:
                    origin,sequence,useful,identity=request_identity(payload)
                    ordinal=receipt.output_count
                    receipt.output(origin,sequence,useful,identity,digest,args.warmup_us<=materialized<args.warmup_us+args.duration_us)
                    if detailed:
                        output={"request_id":identity,"origin":origin,"sequence":sequence,"useful_bytes":useful,
                                "output_index":ordinal,"exact_batch_id":digest,"materialized_us":materialized}
                        ledger["outputs"].append(output)
                    if origin==args.origin and detailed:
                        row=requests.get(identity)
                        if row is None:raise ValueError("native output absent from own finite manifest")
                        row["materialized_us"]=materialized
                receipt.batch(digest,payload_bytes)
            pending+=1
        time.sleep(0.001)
    ledger["native_ordered_headers"]=headers
    ledger["contiguous_headers_materialized"]=pending
    ledger["payload_blocked_headers"]=len(headers)-pending
    ledger["compact_receipt"]=receipt.finish()
    ledger["admitted_bits"]=admitted.hex()
    ledger["native_enqueued_count"]=native_enqueued
    # Clip ingress work still blocked at the finite boundary, without inventing
    # rejects or counting later completions.
    for row in ledger["requests"]:
        for field in ("admitted_us","batch_ready_us","materialized_us"):
            if row.get(field) is not None and row[field]>deadline:row[field]=None
    args.output.write_text(json.dumps(ledger,indent=2)+"\n")
    return ledger


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("origin","rate","useful-bytes","epoch-ns","warmup-us","duration-us","drain-us","workers"):
        p.add_argument("--"+name,type=int,required=True)
    p.add_argument("--address",required=True);p.add_argument("--observer-dir",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--cohort-observer",choices=("full","compact"),default="full")
    p.add_argument("--planned-counts",help="Common per-origin finite request counts, comma separated")
    args=p.parse_args();collect(args)

if __name__=="__main__":main()
