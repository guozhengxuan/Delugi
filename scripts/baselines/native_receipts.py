"""Compact application output receipts shared by observer-cost controls.

No request timestamps or request-row journal are retained. The application still
validates each payload, advances the same contiguous prefix, and records finite
identity bitmaps plus one cumulative exact-order fingerprint per emitted batch.
Fingerprints are compared within an execution, never between independent orders.
"""
import hashlib
import json
import struct


class Receipt:
    def __init__(self, counts, useful_bytes):
        self.counts=list(counts);self.useful_bytes=useful_bytes
        self.materialized=[bytearray((count+7)//8) for count in counts]
        self.window_materialized=[bytearray((count+7)//8) for count in counts]
        self.digest=hashlib.sha256();self.output_count=0;self.batches=[]

    def output(self, origin, sequence, useful_bytes, identity, exact_batch_id, in_window):
        ordinal=self.output_count
        # Include exact native ordinal, batch and identity, with unambiguous lengths.
        row=json.dumps([ordinal,identity,exact_batch_id],separators=(",",":"),ensure_ascii=True).encode()
        self.digest.update(struct.pack("<Q",len(row)));self.digest.update(row)
        self.output_count+=1
        if 0<=origin<len(self.counts) and 0<=sequence<self.counts[origin] and useful_bytes==self.useful_bytes:
            previously_output=bool(self.materialized[origin][sequence//8]&(1<<(sequence%8)))
            self.materialized[origin][sequence//8]|=1<<(sequence%8)
            if in_window and not previously_output:self.window_materialized[origin][sequence//8]|=1<<(sequence%8)

    def batch(self, exact_batch_id, payload_bytes):
        self.batches.append({"exact_batch_id":exact_batch_id,"payload_bytes":payload_bytes,
                             "output_count":self.output_count,"output_sha256":self.digest.hexdigest()})

    def finish(self):
        return {"schema":1,"planned_counts":self.counts,"useful_bytes":self.useful_bytes,
                "output_count":self.output_count,"output_sha256":self.digest.hexdigest(),
                "materialized_bits":[row.hex() for row in self.materialized],
                "window_materialized_bits":[row.hex() for row in self.window_materialized],
                "batch_checkpoints":self.batches}


def bit_count(hex_value):return sum(byte.bit_count() for byte in bytes.fromhex(hex_value))


def finite_bitmap(hex_value, count):
    if type(count) is not int or count < 0 or not isinstance(hex_value, str):
        raise ValueError("Invalid finite bitmap population or encoding")
    value=bytes.fromhex(hex_value)
    if len(value)!=(count+7)//8 or value.hex()!=hex_value:
        raise ValueError("Finite bitmap length or canonical encoding mismatch")
    if count%8 and value[-1]>>(count%8):
        raise ValueError("Finite bitmap has nonzero population padding")
    return value


def compare(receipts, correct):
    sequences=[receipts[index]["batch_checkpoints"] for index in correct]
    longest=max(sequences,key=len)
    if any(sequence!=longest[:len(sequence)] for sequence in sequences):
        raise RuntimeError("Native compact output prefixes disagree")
    return {"replicas_agree_on_common_prefix":True,"proof":"cumulative exact transaction/order digest at every complete native batch boundary",
            "common_batch_prefix_length":min(map(len,sequences)),
            "sequence_lengths":[receipts[index]["output_count"] for index in correct]}


def summarize(receipts, admitted, correct):
    first=receipts[correct[0]]
    if any(receipt["planned_counts"]!=first["planned_counts"] or receipt["useful_bytes"]!=first["useful_bytes"] for receipt in receipts.values()):
        raise RuntimeError("Compact receipts use different finite workloads")
    origins=[]
    for origin in correct:
        count=first["planned_counts"][origin]
        submitted=finite_bitmap(admitted[origin],count)
        completed=bytearray(submitted)
        for replica in correct:
            observed=finite_bitmap(receipts[replica]["materialized_bits"][origin],count)
            for index,value in enumerate(observed):completed[index]&=value
        origins.append({"origin":origin,"planned":count,"admitted":sum(byte.bit_count() for byte in submitted),
                        "all_correct_completed":sum(byte.bit_count() for byte in completed),
                        "all_correct_completed_bits":completed.hex()})
    return {"planned":sum(row["planned"] for row in origins),"admitted":sum(row["admitted"] for row in origins),
            "all_correct_completed":sum(row["all_correct_completed"] for row in origins),"origins":origins,
            "latency_available":False,"scope":"finite-run identity completion; no event-time or deadline quantiles"}
