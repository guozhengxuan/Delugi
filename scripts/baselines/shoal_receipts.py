"""Source-bound native Shoal finite receipts; compact mode has no request timing.

Both modes authenticate/materialize native payloads and keep the same exact
complete-batch prefix and finite first-output eligibility state. These receipts
are native observer evidence, not an independent consensus/WAL proof.
"""
from contextlib import closing, contextmanager
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import stat
import sqlite3
import struct
import time
from itertools import zip_longest

from native_cohort_store import journal_rows

MAGIC=b'DLGSHAD1'
HEADER_BYTES=72
MAX_POPULATION=5_000_000


def digest(raw):return hashlib.sha3_256(raw).hexdigest()


def prepare_plan(store,output,run_id,counts,useful_bytes):
    if not 1<=len(counts)<=31 or any(type(count)is not int or count<0 for count in counts) or sum(counts)>MAX_POPULATION:raise ValueError('native finite observer population limit')
    if not re.fullmatch('[0-9a-f]{32}',run_id) or type(useful_bytes)is not int or useful_bytes<=0:raise ValueError('invalid finite observer identity')
    path=Path(output)/'observer-plan.json'
    with path.open('x') as stream:
        stream.write(json.dumps({'schema':1,'run_id':run_id,'counts':counts,'useful_bytes':useful_bytes},separators=(',',':'))[:-1]+',"identities":[')
        for origin,count in enumerate(counts):
            if origin:stream.write(',')
            stream.write('[');seen=0
            for identity,sequence in store.db.execute('SELECT id,sequence FROM shoal_plan WHERE origin=? ORDER BY sequence',(origin,)):
                if sequence!=seen:raise ValueError('noncontiguous authenticated native plan')
                if seen:stream.write(',')
                stream.write(json.dumps(identity));seen+=1
            if seen!=count:raise ValueError('native plan population differs')
            stream.write(']')
        stream.write(']}\n')
    return {'path':str(path),'sha3_256':file_digest(path),'run_id':run_id,'counts':counts,'useful_bytes':useful_bytes}


def admission_header(plan,origin):
    return MAGIC+bytes.fromhex(plan['run_id'])+struct.pack('<QQ',origin,plan['counts'][origin])+bytes.fromhex(plan['sha3_256'])


def prepare_admissions(output,plan):
    for origin in range(len(plan['counts'])):prepare_admission(output,plan,origin)


def prepare_admission(output,plan,origin):
    with (Path(output)/f'admission-{origin}.bits').open('xb') as stream:
        stream.write(admission_header(plan,origin));stream.write(bytes((plan['counts'][origin]+7)//8))


class AdmissionPublisher:
    """Single origin thread publishes its bit immediately before HTTP submission."""
    def __init__(self,path,plan,origin):
        self.count=plan['counts'][origin];self.file=Path(path).open('r+b')
        if self.file.read(HEADER_BYTES)!=admission_header(plan,origin):raise ValueError('admission map identity differs')
        if os.fstat(self.file.fileno()).st_size!=HEADER_BYTES+(self.count+7)//8:raise ValueError('admission map size differs')
        self.mapping=mmap.mmap(self.file.fileno(),0)
    def admit(self,sequence):
        if type(sequence)is not int or not 0<=sequence<self.count:raise ValueError('admission sequence outside finite plan')
        index=HEADER_BYTES+sequence//8
        self.mapping[index]=self.mapping[index]|(1<<(sequence%8))
    def close(self):self.mapping.close();self.file.close()


def environment(output,plan,origin,mode):
    output=Path(output)
    return {'BENCHMARK_FINITE_PLAN':plan['path'],'BENCHMARK_ORIGIN':str(origin),
        'BENCHMARK_ADMISSION_PATH':str(output/f'admission-{origin}.bits'),
        'BENCHMARK_RECEIPT_DIR':str(output/f'receipt-{origin}'),
        'BENCHMARK_FREEZE_PATH':str(output/f'freeze-{origin}.json'),'BENCHMARK_OBSERVER_MODE':mode}


def arm(output,plan,requested_us):
    for origin in range(len(plan['counts'])):arm_origin(output,plan,origin,requested_us)


def arm_origin(output,plan,origin,requested_us):
    path=Path(output)/f'freeze-{origin}.json';temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'run_id':plan['run_id'],'requested_us':requested_us})+'\n')
    os.replace(temporary,path)


def await_headers(output,nodes,processes,timeout=10,origins=None):
    origins=range(nodes) if origins is None else origins
    deadline=time.monotonic()+timeout
    while True:
        if all((Path(output)/f'receipt-{index}/header.json').exists() for index in origins):return
        if any(process.poll()is not None for process in processes):raise RuntimeError('native validator exited before complete-batch receipt')
        if time.monotonic()>=deadline:raise RuntimeError('native complete-batch receipt timed out')
        time.sleep(0.01)


def counters(output,nodes):
    return {index:json.loads(path.read_text()) for index in range(nodes)
        if (path:=Path(output)/f'receipt-{index}/counters.json').exists()}


@contextmanager
def regular(path):
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('native receipt symlink')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):raise ValueError('native receipt is not regular')
        yield stream
        after=os.fstat(stream.fileno())
        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise ValueError('native receipt changed during collection')


def file_digest(path):
    value=hashlib.sha3_256()
    with regular(path) as stream:
        for chunk in iter(lambda:stream.read(65536),b''):value.update(chunk)
    return value.hexdigest()


def load(output,plan,origin,mode,requested_us):
    root=Path(output)/f'receipt-{origin}'
    with regular(root/'header.json') as stream:raw=stream.read(128*1024+1)
    if len(raw)>128*1024:raise ValueError('native receipt header too large')
    header=json.loads(raw)
    expected={'schema':1,'format':'shoal-native-receipt-v1','run_id':plan['run_id'],
        'plan_sha3_256':plan['sha3_256'],'origin':origin,'counts':plan['counts'],
        'useful_bytes':plan['useful_bytes'],'mode':mode,'requested_us':requested_us}
    if any(header.get(key)!=value for key,value in expected.items()):raise ValueError('native receipt differs from finite configuration')
    if any(type(header[key])is not int for key in ('schema','origin','useful_bytes','requested_us')) or any(type(count)is not int for count in header['counts']):raise ValueError('native receipt integer encoding differs')
    for key in ('output_count','batch_count','payload_bytes','frozen_us'):
        if type(header[key])is not int or not 0<=header[key]<2**64:raise ValueError('native receipt counter invalid')
    if not requested_us<=header['frozen_us']<=requested_us+10_000_000:raise ValueError('native freeze endpoint outside declared envelope')
    if not re.fullmatch('[0-9a-f]{64}',header['prefix_sha3_256']):raise ValueError('native prefix digest encoding')
    descriptors={(row['name'],row['origin']):row for row in header['streams']}
    expected_keys={('materialized',index) for index in range(len(plan['counts']))}|{('own_seen',origin),('own_eligible',origin)}
    if len(descriptors)!=len(header['streams']) or set(descriptors)!=expected_keys:raise ValueError('native receipt streams differ')
    result={'root':root,'header':header,'bits':{},'header_sha256':hashlib.sha256(raw).hexdigest()}
    for (name,who),row in descriptors.items():
        count=plan['counts'][who];size=(count+7)//8
        if row['path']!=f'{name}-{who}.bits' or row['bytes']!=size:raise ValueError('native bitmap path/size differs')
        with regular(root/row['path']) as stream:bits=stream.read(size+1)
        if len(bits)!=size or (count%8 and bits[-1]>>(count%8)):raise ValueError('native bitmap population/padding differs')
        if digest(bits)!=row['sha3_256'] or sum(byte.bit_count() for byte in bits)!=row['ones']:raise ValueError('native bitmap fingerprint differs')
        result['bits'][(name,who)]=bits
    seen=result['bits'][('own_seen',origin)];eligible=result['bits'][('own_eligible',origin)];own=result['bits'][('materialized',origin)]
    if any(e&~(s&m) or s&~m for e,s,m in zip(eligible,seen,own)):raise ValueError('eligible native identity was not first seen/materialized')
    count=plan['counts'][origin]
    with regular(Path(output)/f'admission-{origin}.bits') as stream:admitted=stream.read(HEADER_BYTES+(count+7)//8+1)
    if admitted[:HEADER_BYTES]!=admission_header(plan,origin) or len(admitted)!=HEADER_BYTES+(count+7)//8:raise ValueError('final admission map differs')
    result['admitted']=admitted[HEADER_BYTES:]
    if count%8 and result['admitted'][-1]>>(count%8):raise ValueError('admission map padding differs')
    if any(e&~a for e,a in zip(eligible,result['admitted'])):raise ValueError('native completion lacks own admission')
    # Bind validation and fingerprint to the same bytes, never a second read.
    for _ in _checkpoints(result,bind=True):pass
    return result


def checkpoints(receipt):
    """Every successful pass must exhaust this bound, terminal-checked stream."""
    yield from _checkpoints(receipt)


def _checkpoints(receipt,bind=False):
    value=hashlib.sha3_256();size=0;batch_count=0;last_output=0;payload_bytes=0
    terminal=digest(b'Shoal-native-prefix-v1');header=receipt['header']
    # Exact first occurrence is a cost invariant, not an observer-supplied hint.
    # An anonymous temporary SQLite file bounds memory even for long prefixes.
    with closing(sqlite3.connect('')) as seen,regular(receipt['root']/'checkpoints.jsonl') as stream:
        seen.execute('PRAGMA cache_size=-1024');seen.execute('PRAGMA journal_mode=OFF')
        seen.execute('CREATE TABLE seen(id TEXT PRIMARY KEY, bytes TEXT NOT NULL)')
        while line:=stream.readline(65537):
            if len(line)>65536 or not line.endswith(b'\n'):raise ValueError('oversized or truncated native checkpoint')
            value.update(line);size+=len(line);row=json.loads(line)
            if not isinstance(row,dict):raise ValueError('native checkpoint must be an object')
            if any(type(row[key])is not int or not 0<=row[key]<2**64 for key in ('batch_index','payload_bytes','first_index','output_count')):raise ValueError('invalid native checkpoint integer')
            if type(row['unique_batch'])is not bool or not re.fullmatch(r'[0-9]+:[0-9a-f]{64}',row['exact_batch_id']) or not re.fullmatch('[0-9a-f]{64}',row['prefix_sha3_256']):raise ValueError('invalid native checkpoint identity')
            if row['batch_index']!=batch_count or row['first_index']!=last_output or row['output_count']<last_output:raise ValueError('native batch checkpoint gap')
            previous=seen.execute('SELECT bytes FROM seen WHERE id=?',(row['exact_batch_id'],)).fetchone()
            if row['unique_batch']!=(previous is None):raise ValueError('native batch uniqueness differs from exact first occurrence')
            if previous is not None and previous[0]!=str(row['payload_bytes']):raise ValueError('repeated native batch payload bytes differ')
            if previous is None:seen.execute('INSERT INTO seen VALUES(?,?)',(row['exact_batch_id'],str(row['payload_bytes'])))
            batch_count+=1;last_output=row['output_count'];terminal=row['prefix_sha3_256']
            if row['unique_batch']:payload_bytes+=row['payload_bytes']
            yield row
    if batch_count!=header['batch_count'] or last_output!=header['output_count'] or payload_bytes!=header['payload_bytes'] or terminal!=header['prefix_sha3_256']:raise ValueError('native terminal receipt differs from complete checkpoints')
    if bind:
        receipt['checkpoint_sha3_256']=value.hexdigest();receipt['checkpoint_bytes']=size
    elif size!=receipt['checkpoint_bytes'] or value.hexdigest()!=receipt['checkpoint_sha3_256']:
        raise ValueError('native checkpoint bytes changed after collection')


def compare(receipts,correct):
    longest=max(correct,key=lambda index:receipts[index]['header']['batch_count'])
    for index in correct:
        with closing(checkpoints(receipts[longest])) as reference,closing(checkpoints(receipts[index])) as candidate:
            # Exhaust both even when a correct replica has an empty/short prefix.
            for expected,row in zip_longest(reference,candidate):
                if row is not None and row!=expected:raise ValueError('native complete-batch prefixes disagree')
    return {'replicas_agree_on_common_prefix':True,
        'sequence_lengths':[receipts[index]['header']['output_count'] for index in correct],
        'complete_batch_lengths':[receipts[index]['header']['batch_count'] for index in correct],
        'scope':'Every correct prefix against the longest complete native batch sequence, including empty, unknown and repeated outputs; source-bound rolling SHA3-256 receipts'}


def summarize(receipts,correct):
    rows=[]
    for origin in correct:
        receipt=receipts[origin];count=receipt['header']['counts'][origin]
        completed=bytearray(receipt['bits'][('own_eligible',origin)])
        for index in correct:
            for offset,value in enumerate(receipts[index]['bits'][('materialized',origin)]):completed[offset]&=value
        rows.append({'origin':origin,'planned':count,'admitted':sum(b.bit_count() for b in receipt['admitted']),
            'all_correct_completed':sum(b.bit_count() for b in completed),'all_correct_completed_bits':completed.hex()})
    return {'planned':sum(r['planned'] for r in rows),'admitted':sum(r['admitted'] for r in rows),
        'all_correct_completed':sum(r['all_correct_completed'] for r in rows),'origins':rows,
        'latency_available':False,'scope':'Exact signed finite identities, own first-output admission eligibility and all-correct final native materialization; no request timestamps in compact mode'}


def verify_full(receipt,path):
    """Independently reconstruct native chain from every detailed output row."""
    def rows():
        for row in journal_rows(path):
            if row['event']not in ('batch','output','uncredited_output'):raise ValueError('unknown detailed native event')
            if type(row['materialized_us'])is not int or not 0<=row['materialized_us']<=receipt['header']['frozen_us']:raise ValueError('detailed event outside native frozen prefix')
            yield row
    events=rows()
    current=bytes.fromhex(digest(b'Shoal-native-prefix-v1'));ordinal=0
    with closing(events),closing(checkpoints(receipt)) as native:
        for checkpoint in native:
            batch=next(events,None)
            if batch is None or batch['event']!='batch' or any(batch.get(key)!=checkpoint[key] for key in ('batch_index','first_index','exact_batch_id','payload_bytes','unique_batch')):raise ValueError('detailed batch boundary differs from native checkpoint')
            current=hashlib.sha3_256(b'B'+current+hashlib.sha3_256(checkpoint['exact_batch_id'].encode()).digest()+struct.pack('<QQ',checkpoint['payload_bytes'],ordinal)).digest()
            while ordinal<checkpoint['output_count']:
                row=next(events,None)
                if row is None or row['event']not in ('output','uncredited_output') or row['output_index']!=ordinal or row['exact_batch_id']!=checkpoint['exact_batch_id']:raise ValueError('detailed output differs from native complete batch')
                current=hashlib.sha3_256(b'T'+current+struct.pack('<Q',ordinal)+bytes.fromhex(row['request_id'])).digest();ordinal+=1
            if current.hex()!=checkpoint['prefix_sha3_256']:raise ValueError('detailed output fingerprint differs')
        if next(events,None)is not None or ordinal!=receipt['header']['output_count'] or current.hex()!=receipt['header']['prefix_sha3_256']:raise ValueError('detailed output truncated native terminal prefix')
    return {'verified':True,'output_count':ordinal,'prefix_sha3_256':current.hex()}


def verify_local_eligibility(store,receipt):
    origin=receipt['header']['origin'];count=receipt['header']['counts'][origin]
    bits=bytearray((count+7)//8)
    for body, in store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='requests' ORDER BY ordinal",(origin,)):
        row=json.loads(body)
        if row['materialized_us']is not None:bits[row['sequence']//8]|=1<<(row['sequence']%8)
    if bytes(bits)!=receipt['bits'][('own_eligible',origin)]:raise ValueError('detailed identities differ from native first-output eligibility')
    payload=sum(json.loads(body)['payload_bytes'] for body, in store.db.execute("SELECT body FROM rows WHERE replica=? AND stream='batches'",(origin,)))
    if payload!=receipt['header']['payload_bytes']:raise ValueError('detailed materialized bytes differ from native receipt')
    return {'verified':True,'origin':origin,'eligible_identity_sha3_256':digest(bits)}


def verify_admissions(path,receipt):
    origin=receipt['header']['origin'];count=receipt['header']['counts'][origin]
    bits=bytearray((count+7)//8);seen=0
    for row in journal_rows(path):
        if row['origin']!=origin or row['sequence']!=seen:raise ValueError('native ingress lost finite origin order')
        if row['admitted_us']is not None:bits[seen//8]|=1<<(seen%8)
        seen+=1
    if seen!=count or bytes(bits)!=receipt['admitted']:raise ValueError('native admission publication differs from ingress journal')
    return {'verified':True,'admitted_identity_sha3_256':digest(bits)}
