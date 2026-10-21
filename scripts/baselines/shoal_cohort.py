#!/usr/bin/env python3
"""Finite native Aptos/Shoal ingress and exact output collector.

The narrow BCS decoder independently authenticates the native fixture's signed
Ed25519 script transactions. It rejects other transaction formats rather than
guessing. Native execution acceptance still requires an actual paper-mode build.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
import urllib.error
import urllib.request
sys.path.insert(0,str(Path(__file__).resolve().parent))
from mysticeti_wal import Ed25519Verifier, Reader
from native_cohort_store import journal_rows


class BCSReader(Reader):
    def uleb(self):
        value=0
        for index in range(5):
            byte=self.integer(1);value|=(byte&127)<<(7*index)
            if not byte&128:
                if (index and byte==0) or value>0xffffffff:raise ValueError("noncanonical BCS ULEB128")
                return value
        raise ValueError("BCS ULEB128 exceeds u32")
    def vector(self):return self.take(self.uleb())


def transaction_hash(serialized):
    seed=hashlib.sha3_256(b"APTOS::Transaction").digest()
    return hashlib.sha3_256(seed+b"\0"+serialized).hexdigest()


def decode_signed_workload(serialized, verifier=None):
    reader=BCSReader(serialized);sender=reader.take(32);native_sequence=reader.integer(8)
    if reader.uleb()!=0:raise ValueError("expected native Script payload")
    code=reader.vector()
    if reader.uleb()!=0 or reader.uleb()!=0:raise ValueError("expected empty fixture script arguments")
    reader.integer(8);reader.integer(8);reader.integer(8) # native gas and expiry
    if reader.integer(1)!=4:raise ValueError("expected native test ChainId")
    signed_message=hashlib.sha3_256(b"APTOS::RawTransaction").digest()+serialized[:reader.pos]
    if reader.uleb()!=0:raise ValueError("expected native Ed25519 authenticator")
    public_key=reader.vector();signature=reader.vector();reader.finish()
    (verifier or Ed25519Verifier()).verify(public_key,signature,signed_message)
    if sender!=hashlib.sha3_256(public_key+b"\0").digest():raise ValueError("native signer does not bind sender account")
    if len(code)<48 or code[:8]!=b"DLGCOH02":raise ValueError("expected finite workload script")
    origin,sequence,useful=struct.unpack_from("<QQQ",code,24)
    if sequence!=native_sequence or useful!=len(code)-48:raise ValueError("signed workload metadata mismatch")
    if any(byte!=(origin+sequence+index)%251 for index,byte in enumerate(code[48:])):raise ValueError("signed useful content mismatch")
    return {"request_id":transaction_hash(serialized),"run_id":code[8:24].hex(),"origin":origin,"sequence":sequence,
            "useful_bytes":useful,"serialized_bytes":len(serialized),"sender":sender.hex()}


def iter_plan(path, run_id, origin, count, useful_bytes):
    seen=0;verifier=Ed25519Verifier()
    for row in journal_rows(path):
        serialized=bytes.fromhex(row["bcs_hex"])
        identity=decode_signed_workload(serialized,verifier)
        for key in ("request_id","run_id","origin","sequence","useful_bytes","serialized_bytes"):
            if row[key]!=identity[key]:raise ValueError(f"native plan field differs from authenticated BCS: {key}")
        if identity["run_id"]!=run_id or identity["origin"]!=origin or identity["sequence"]!=seen or identity["useful_bytes"]!=useful_bytes:
            raise ValueError("native plan differs from selected finite workload")
        seen+=1
        yield row
    if seen!=count:raise ValueError("native finite plan count mismatch")


def load_plan(path, run_id, origin, count, useful_bytes):
    return list(iter_plan(path,run_id,origin,count,useful_bytes))


def direct_urlopen(request, timeout):
    """All adapter REST endpoints are explicit host-local controls."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=timeout)


def submit_bcs(address, serialized, timeout):
    request=urllib.request.Request(address.rstrip("/")+"/v1/transactions",data=serialized,
        headers={"Content-Type":"application/x.aptos.signed_transaction+bcs","Accept":"application/json"},method="POST")
    try:
        with direct_urlopen(request,timeout=timeout) as reply:return reply.status,reply.read().decode()
    except urllib.error.HTTPError as error:return error.code,error.read().decode()


def ingress_iter(plan, address, rate, epoch_us, warmup_us, duration_us, drain_us, *, submit=submit_bcs, now=None, sleep=time.sleep,on_admit=None):
    now=now or (lambda:time.clock_gettime_ns(time.CLOCK_MONOTONIC)//1000)
    end=epoch_us+warmup_us+duration_us+drain_us
    for index,planned in enumerate(plan):
        row={key:planned[key] for key in ("request_id","origin","sequence","useful_bytes")}|\
          {"scheduled_us":epoch_us+index*1_000_000//rate,"admitted_us":None,"batch_ready_us":None,
           "materialized_us":None,"rejected_us":None,"rejection_reason":None}
        while now()<row["scheduled_us"]:sleep(min(0.001,(row["scheduled_us"]-now())/1e6))
        if now()>=end:
            yield row
            continue
        row["admitted_us"]=now()
        if on_admit is not None:on_admit(row['sequence'])
        try:
            status,body=submit(address,bytes.fromhex(planned["bcs_hex"]),max(0.001,(end-now())/1e6))
            row["native_submission_status"]=status
            if status==202:row["native_accepted_us"]=now()
            else:
                # The origin application already admitted this request before
                # posting it. Native mempool rejection is downstream failure,
                # not a rejection before application admission.
                row.update(native_rejected_us=now(),native_rejection_reason=f"native HTTP {status}: {body[:1024]}")
        except (OSError,TimeoutError) as error:
            # An ambiguous transport outcome is unfinished, not a fabricated reject.
            row["submission_transport_error"]=str(error)
        yield row


def ingress(*args, **kwargs):return list(ingress_iter(*args,**kwargs))


def ingress_to_journal(output, plan_path, *args, **kwargs):
    """One independent origin thread, preserving every finite planned arrival."""
    with Path(output).open('x') as stream:
        for row in ingress_iter(journal_rows(plan_path),*args,**kwargs):
            stream.write(json.dumps(row,separators=(',',':'))+'\n')
    return str(output)


def prepare_plan_store(store, plan_paths, run_id, counts, useful_bytes):
    """Authenticate finite native BCS once; retain only identity lookup on disk."""
    encoded_sizes=set()
    store.db.execute('CREATE TABLE shoal_plan(id TEXT PRIMARY KEY,origin INTEGER,sequence INTEGER,useful INTEGER,UNIQUE(origin,sequence))')
    for origin,path in enumerate(plan_paths):
        for row in iter_plan(path,run_id,origin,counts[origin],useful_bytes):
            encoded_sizes.add(row['serialized_bytes'])
            store.db.execute('INSERT INTO shoal_plan VALUES(?,?,?,?)',(row['request_id'],origin,row['sequence'],row['useful_bytes']))
            if row['sequence']%1024==0:store.db.commit()
    store.db.commit()
    return {'native_serialized_transaction_bytes':sorted(encoded_sizes),
            'source':'independently verified signed BCS finite plans'}


def collect_store(store, replica, admitted, events, epoch_us, warmup_us, duration_us, drain_us,observed_us=None):
    """Bounded native journal join with the same checks as the legacy collector."""
    declared=epoch_us+warmup_us+duration_us+drain_us
    deadline=declared if observed_us is None else observed_us
    if deadline<declared:raise ValueError('native receipt precedes declared finite cutoff')
    store.metadata[replica]={"output_index_base":0,"window_start_us":epoch_us+warmup_us,
        "window_end_us":epoch_us+warmup_us+duration_us,"observed_us":deadline,"batch_ready_available":False,
        "declared_observed_us":declared,
        "output_sequence_scope":"complete native Shoal application materialization journal; exact signed finite identities verified independently"}
    for row in admitted:
        known=store.db.execute('SELECT origin,sequence,useful FROM shoal_plan WHERE id=?',(row['request_id'],)).fetchone()
        if known!=(replica,row['sequence'],row['useful_bytes']) or row['origin']!=replica:
            raise ValueError('native ingress differs from authenticated finite origin plan')
        store.put(replica,'requests',row)
    planned=store.db.execute('SELECT count(*) FROM shoal_plan WHERE origin=?',(replica,)).fetchone()[0]
    if store.serial.get((replica,'requests'),0)!=planned:raise ValueError('native ingress journal lost finite planned requests')
    next_index=0
    for event in events:
        elapsed=event['materialized_us']
        if elapsed>deadline:continue
        if event['event']=='batch':
            if 'unique_batch'in event and type(event['unique_batch'])is not bool:raise ValueError('invalid native batch uniqueness flag')
            if not event.get('unique_batch',True):continue
            store.put(replica,'batches',{key:event[key] for key in ('exact_batch_id','payload_bytes','materialized_us')})
            continue
        if event['event'] not in ('output','uncredited_output'):raise ValueError('unknown native output event')
        if (observed_us is not None or 'origin_eligible'in event) and type(event.get('origin_eligible'))is not bool:raise ValueError('invalid native eligibility flag')
        if event['output_index']!=next_index:raise ValueError('native output ordinal gap')
        next_index+=1
        batch=store.db.execute("SELECT 1 FROM rows WHERE replica=? AND stream='batches' AND id=?",(replica,event['exact_batch_id'])).fetchone()
        if batch is None:raise ValueError('native output precedes its materialized batch')
        row={key:event[key] for key in ('request_id','origin','sequence','useful_bytes','output_index','exact_batch_id','materialized_us')}
        known=store.db.execute('SELECT origin,sequence,useful FROM shoal_plan WHERE id=?',(row['request_id'],)).fetchone()
        if event['event']=='output' and known:
            if known!=(row['origin'],row['sequence'],row['useful_bytes']):raise ValueError('native output metadata differs from signed finite identity')
            if row['origin']==replica and event.get('origin_eligible',True):
                own=store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' AND id=?",(replica,row['request_id'])).fetchone()
                admitted_at=json.loads(own[0])['admitted_us'] if own else None
                if admitted_at is None or elapsed<admitted_at:raise ValueError('finite native output precedes origin admission')
                store.stage(replica,row['request_id'],'materialized_us',elapsed,first=True)
        else:row.update(origin=-1,sequence=0,useful_bytes=0)
        store.put(replica,'outputs',row)


def collect(plan, admitted, events, epoch_us, warmup_us, duration_us, drain_us):
    deadline=epoch_us+warmup_us+duration_us+drain_us
    own={row["request_id"]:dict(row) for row in admitted};known={row["request_id"]:row for row in plan}
    outputs=[];batches=[];batch_ids=set();next_index=0
    for event in events:
        elapsed=event["materialized_us"]
        if elapsed>deadline:continue
        if event["event"]=="batch":
            if not event.get('unique_batch',True):continue
            batch=event["exact_batch_id"]
            if batch in batch_ids:raise ValueError("duplicate exact native batch accounting")
            batch_ids.add(batch);batches.append({key:event[key] for key in ("exact_batch_id","payload_bytes","materialized_us")})
            continue
        if event["event"] not in ("output","uncredited_output"):raise ValueError("unknown native output event")
        if 'origin_eligible'in event and type(event['origin_eligible'])is not bool:raise ValueError('invalid native eligibility flag')
        if event["output_index"]!=next_index:raise ValueError("native output ordinal gap")
        next_index+=1
        if event["exact_batch_id"] not in batch_ids:raise ValueError("native output precedes its materialized batch")
        row={key:event[key] for key in ("request_id","origin","sequence","useful_bytes","output_index","exact_batch_id","materialized_us")}
        match=known.get(row["request_id"])
        if event["event"]=="output" and match:
            if any(row[key]!=match[key] for key in ("origin","sequence","useful_bytes")):raise ValueError("native output metadata differs from signed finite identity")
            local=own.get(row["request_id"])
            if local and event.get('origin_eligible',True):
                if local["admitted_us"] is None or elapsed<local["admitted_us"]:raise ValueError("finite native output precedes origin admission")
                if local["materialized_us"] is None:local["materialized_us"]=elapsed
        else:
            # Preserve actual native ordinal/hash and all payload cost; no U_out.
            row.update(origin=-1,sequence=0,useful_bytes=0)
        outputs.append(row)
    return {"requests":list(own.values()),"outputs":outputs,"batches":batches,"output_index_base":0,
            "window_start_us":epoch_us+warmup_us,"window_end_us":epoch_us+warmup_us+duration_us,
            "observed_us":deadline,"batch_ready_available":False}
