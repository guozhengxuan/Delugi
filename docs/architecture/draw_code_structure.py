#!/usr/bin/env python3
"""Draw the source-audited architecture at 57e078e; no protocol execution.

Dependencies: reportlab. Generates vector PDF and editable SVG pages.
Coordinates use a top-left origin to keep the diagrams easy to revise.
"""
from pathlib import Path
import hashlib
import html
import json
import math
import subprocess

from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/pdf'
FIG = ROOT / 'output/figures'
OUT.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)
W, H = 1200, 840
FONT = Path('/System/Library/Fonts/Supplemental')
for name, file in [('Body', 'Arial.ttf'), ('Bold', 'Arial Bold.ttf'),
                   ('Mono', 'Courier New.ttf'), ('MonoBold', 'Courier New Bold.ttf')]:
    pdfmetrics.registerFont(TTFont(name, str(FONT / file)))
C = dict(ink='#1C2F44', muted='#536678', line='#B5C1CF', light='#F4F7FA',
         red='#BD424B', blue='#346BAE', purple='#8054A3', orange='#BA7023',
         green='#247468', amber='#FFF1D8', white='#FFFFFF')
PDF = OUT / 'delugi-code-structure-2026-10-22.pdf'
cv = canvas.Canvas(str(PDF), pagesize=(W, H), pageCompression=1, invariant=1)
cv.setTitle('Delugi and Raptr | Current code, consensus interfaces and evaluation parameters')
cv.setAuthor('Delugi implementation project')
pages = []
all_text = []

class Page:
    def __init__(self, name, number, title, subtitle):
        self.name = name
        self.number = number
        self.svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
                    '<rect width="1200" height="840" fill="white"/>']
        self.text(48, 42, 'DELUGI / IMPLEMENTATION MAP', 11, 'Bold', C['blue'])
        self.text(48, 82, title, 29, 'Bold')
        self.para(48, 107, 1104, subtitle, 12, color=C['muted'], leading=16)
        self.line([(48, 785), (1152, 785)], C['line'], 0.8)
        self.text(48, 809, 'SOURCE SNAPSHOT 57e078e  |  22 OCT 2026  |  Current implementation; no runtime changes', 10, color=C['muted'])
        self.text(1100, 809, f'{number} / 5', 10, 'Bold', C['muted'])

    def text(self, x, y, text, size=12, font='Body', color=None):
        color = color or C['ink']
        if y > 780 and y != 809:
            raise ValueError(f'text outside content area: {text}')
        cv.setFont(font, size)
        cv.setFillColor(HexColor(color))
        cv.drawString(x, H-y, text)
        family = 'Courier New,monospace' if font.startswith('Mono') else 'Arial,sans-serif'
        weight = 'bold' if font.endswith('Bold') or font == 'Bold' else 'normal'
        self.svg.append(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" font-weight="{weight}" fill="{color}">{html.escape(text)}</text>')
        all_text.append(text)

    def wrap(self, text, width, size, font):
        out = []
        for raw in text.split('\n'):
            if not raw:
                out.append('')
                continue
            line = ''
            for word in raw.split():
                candidate = (line + ' ' + word).strip()
                if pdfmetrics.stringWidth(candidate, font, size) <= width:
                    line = candidate
                else:
                    if line:
                        out.append(line)
                    line = word
                    while pdfmetrics.stringWidth(line, font, size) > width:
                        i = len(line)-1
                        while pdfmetrics.stringWidth(line[:i], font, size) > width:
                            i -= 1
                        out.append(line[:i])
                        line = line[i:]
            out.append(line)
        return out

    def para(self, x, y, width, text, size=12, font='Body', color=None, leading=None):
        leading = leading or size*1.35
        lines = self.wrap(text, width, size, font)
        for i, s in enumerate(lines):
            self.text(x, y+i*leading, s, size, font, color)
        return y + len(lines)*leading

    def rect(self, x, y, w, h, fill=None, stroke=None, radius=0):
        fill = fill or C['white']
        stroke = stroke or C['line']
        cv.setFillColor(HexColor(fill)); cv.setStrokeColor(HexColor(stroke)); cv.setLineWidth(1)
        cv.roundRect(x, H-y-h, w, h, radius, stroke=1, fill=1)
        self.svg.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>')

    def line(self, points, color=None, width=1.6, arrow=False, dashed=False):
        color = color or C['ink']
        cv.setStrokeColor(HexColor(color)); cv.setFillColor(HexColor(color)); cv.setLineWidth(width)
        cv.setDash(5, 4) if dashed else cv.setDash()
        p=cv.beginPath();p.moveTo(points[0][0],H-points[0][1])
        for x,y in points[1:]:p.lineTo(x,H-y)
        cv.drawPath(p)
        dash=' stroke-dasharray="5 4"' if dashed else ''
        self.svg.append(f'<polyline points="{" ".join(f"{x},{y}" for x,y in points)}" fill="none" stroke="{color}" stroke-width="{width}"{dash}/>')
        if arrow:
            a,b=points[-2],points[-1];t=math.atan2(b[1]-a[1],b[0]-a[0]);d=8
            v=[b,(b[0]-d*math.cos(t-.42),b[1]-d*math.sin(t-.42)),(b[0]-d*math.cos(t+.42),b[1]-d*math.sin(t+.42))]
            q=cv.beginPath();q.moveTo(v[0][0],H-v[0][1])
            for x,y in v[1:]:q.lineTo(x,H-y)
            q.close();cv.drawPath(q,fill=1,stroke=0)
            self.svg.append(f'<polygon points="{" ".join(f"{x},{y}" for x,y in v)}" fill="{color}"/>')
        cv.setDash()

    def box(self,x,y,w,h,title,path,lines,accent=None,size=12):
        accent=accent or C['blue']
        self.rect(x,y,w,h)
        self.rect(x,y,w,39,C['light'])
        self.text(x+14,y+26,title,15,'Bold',accent)
        end=self.para(x+14,y+57,w-28,path,9.8,'Mono',C['muted'],13)
        end-=3
        self.line([(x+1,end),(x+w-1,end)],C['line'],.8)
        end+=15
        for item in lines:
            if isinstance(item,tuple):
                s,f,col=item
                if f == 'Mono' and col != C['muted']:
                    f = 'MonoBold'
            else:s,f,col=item,'Body',C['ink']
            end=self.para(x+14,end,w-28,s,size,f,col,size*1.32)+5
        if end-size*1.32-5>y+h-8:raise ValueError(f'box overflow {title}: {end} > {y+h}')

    def note(self,x,y,w,h,title,body,fill=None,size=11.5):
        self.rect(x,y,w,h,fill or C['light'],C['line'],6)
        self.text(x+13,y+22,title,12,'Bold')
        end=self.para(x+13,y+42,w-26,body,size,leading=size*1.3) if body else y+22
        if end>y+h+2:raise ValueError(f'note overflow {title}')

    def refs(self,text,y=748):
        self.para(48,y,1104,text,9.5,color=C['muted'],leading=13)

    def finish(self):
        self.svg.append('</svg>')
        path=FIG/f'delugi-{self.name}-2026-10-22.svg'
        path.write_text('\n'.join(self.svg)+'\n')
        pages.append(path)
        cv.showPage()


# 1. Actual folder and lifecycle boundary.
p=Page('code-structure',1,'One node entry point, two protocol cores',
       'Class-and-call-flow layout inspired by the supplied Wahoo++ figure. Solid arrows show ownership/calls; dashed arrows show shared service use.')
p.box(48,143,1104,117,'node/  +  core-api::ProtocolFactory','node/src/shared_main.rs  ->  node/src/lib.rs  ->  core-api/src/lib.rs:44',[
    ('--protocol delugi | raptr    +    opaque protocol JSON configuration','Mono',C['ink']),
    ('name()  |  run(configuration: &[u8], id: u32)  |  generate_keys()  |  verify_archive()  |  verify_ledger()','Mono',C['ink'])],size=12)
p.line([(600,260),(600,282),(317,282),(317,312)],arrow=True)
p.line([(600,282),(883,282),(883,312)],arrow=True)
p.box(48,312,538,272,'core/delugi/','factory.rs -> process.rs -> composed::Node',[
    ('ORDERING  replica / slot / history / scanner','MonoBold',C['blue']),
    'HISTORY3, CLOSED, catch-up, direct commit and ordered delivery',
    ('AVAILABILITY  availability / batch / mmr','MonoBold',C['green']),
    'REPORT/OBS, authenticated bases, batch custody, FETCH/DATA',
    ('STORAGE + OUTPUT  record_store / composed / workload','MonoBold',C['orange']),
    'One synchronous actor loop; exact batch expansion and FIFO output'
],size=12.4)
p.box(614,312,538,272,'core/raptr/','node/factory.rs + native/ + qs/ + transport/',[
    ('ORDERING  native/src/raptr + framework','MonoBold',C['blue']),
    'Pinned Raptr state machine, certificates and native timer policy',
    ('AVAILABILITY  qs/ + node/dissemination.rs','MonoBold',C['green']),
    'Native Quorum Store batching, custody, proofs and payload repair',
    ('OUTPUT  src/output.rs + node/output.rs','MonoBold',C['orange']),
    'Tokio actors; reserve commit order before asynchronous retrieval'
],size=12.4)
p.line([(317,584),(317,615)],dashed=True,arrow=True)
p.line([(883,584),(883,615)],dashed=True,arrow=True)
p.rect(48,615,1104,107,C['light'])
p.text(62,639,'shared/ mechanisms used by the cores',14,'Bold')
cards=[('network + network-async','Bounded TCP; async facade'),('mempool + output','Timed ingress; FIFO queues'),('crypto + crypto-aptos','Core-specific proof formats'),('store + store-rocksdb','Visible / Written barriers'),('runtime + runtime-async','Distinct execution profiles'),('metrics','Traffic + operation counters')]
for i,(title,body) in enumerate(cards):
    x=62+i*181
    p.para(x,663,170,title,10.3,'MonoBold',leading=13)
    p.para(x,696,170,body,10.5,color=C['muted'],leading=13)
p.refs('Code boundary: core-api/src/lib.rs:44; node/src/shared_main.rs:4; core/delugi/src/process.rs:1983; core/raptr/node/src/factory.rs:128.\nNo universal consensus-transition trait exists today. OperationId is declared but is not wired into runtime calls. Detailed source index accompanies this PDF.')
p.finish()


# 2. Delugi interfaces, deliberately separate decision stages.
p=Page('delugi-interfaces',2,'Delugi: composition drives an event/effect core',
       'Public entry signatures are shortened only by omitting &mut self and common Result wrappers. Clock values are the core logical millisecond time.')
p.box(190,153,425,324,'composed::Node','core/delugi/src/composed.rs:144,210,242,385',[
    ('state: ordering: Replica; store: BatchStore','Mono',C['muted']),
    ('pending_ordered; batch_ids; transaction_ids','Mono',C['muted']),
    ('produce(now, payload: Vec<u8>)','Mono',C['red']),
    ('receive(now, from: Id, Message)','Mono',C['blue']),
    ('receive_ordering(now, wire::Message)','Mono',C['blue']),
    ('start(now); tick(now)','Mono',C['purple']),
    'REPORT/OBS -> all-current (value x, witness pi). All entry calls return Result<Vec<composed::Effect>, String>.'
],size=11.5)
p.box(710,153,442,324,'replica::Replica','core/delugi/src/replica.rs:2177,2384-2430',[
    ('Inputs = BTreeMap<round, (value, witness)>','Mono',C['muted']),
    ('Q: Fn(round, &[u8], &[u8]) -> bool','Mono',C['blue']),
    ('start(now); receive(now, Message)','Mono',C['blue']),
    ('tick(now)','Mono',C['purple']),
    ('supply_input(now, round, value, witness)','Mono',C['red']),
    ('-> Result<Vec<replica::Effect>, String>','Mono',C['ink']),
    'slot / history / scanner keep voting, catch-up and delivery policy inside the core.'
],size=11.5)
for y,label,color in [(290,'produce',C['red']),(355,'receive',C['blue']),(420,'time',C['purple'])]:
    p.rect(48,y-18,101,33,C['light'],color,5);p.text(61,y+4,label,12,'Bold',color)
    p.line([(149,y),(190,y)],color,arrow=True)
p.line([(615,285),(710,285)],C['red'],arrow=True)
p.text(631,273,'(x, pi)',11,'MonoBold',C['red'])
p.line([(710,355),(615,355)],C['blue'],arrow=True)
p.text(619,343,'Q(r,x,pi)',9.5,'MonoBold',C['blue'])
p.line([(710,422),(615,422)],C['orange'],arrow=True)
p.text(629,409,'effects',10.5,'Bold',C['orange'])
p.box(710,534,442,180,'process::Runtime::effects','core/delugi/src/process.rs:959; input Vec<composed::Effect>',[
    ('Send {to,message} -> encode / bundle / TCP','Mono',C['blue']),
    ('Wake {at} -> shared TimerQueue','Mono',C['purple']),
    ('DirectCommit / Deliver -> observation log','Mono',C['orange']),
    ('Notice -> diagnostic events','Mono',C['orange'])
],size=11.3)
p.line([(555,477),(555,505),(931,505),(931,534)],C['blue'],arrow=True)
p.text(668,494,'composed effects',11,'Bold',C['blue'])
p.box(190,534,425,180,'Node materialization (same state owner)','core/delugi/src/composed.rs:532-671',[
    '1  Decode descriptor; enqueue in pending_ordered.',
    '2  Missing exact suffix -> FETCH; hold FIFO head.',
    '3  After verified DATA: expand suffix; exact-batch dedup.',
    '4  Decode requests; append contiguous application output.'
],size=11.5,accent=C['orange'])
p.line([(402,477),(402,534)],C['orange'],arrow=True)
p.text(280,508,'accept_ordering',10.5,'Bold',C['orange'])
p.refs('Key separation: DirectCommit != ordered descriptor delivery != payload-verified application output.\nQ checks immutable availability evidence; ordering does not wait for application materialization. TCP ACKs retire bounded in-flight frames, not each next send.')
p.finish()


# 3. Raptr native API and ordering-safe output reservation.
p=Page('raptr-interfaces',3,'Raptr: native handlers plus a dissemination contract',
       'The native Protocol and DisseminationLayer APIs stay in core/raptr; Context connects them to injected service adapters. Handler calls are async.')
p.box(48,150,521,286,'native::framework::Protocol','core/raptr/native/src/framework/mod.rs:36-134',[
    ('associated Message; TimerEvent','Mono',C['muted']),
    ('start_handler(ctx)','Mono',C['red']),
    ('message_handler(ctx, from, message)','Mono',C['blue']),
    ('module_event_handler(ctx, module, event)','Mono',C['blue']),
    ('timer_event_handler(ctx, event)','Mono',C['purple']),
    ('condition_handler(ctx)','Mono',C['purple']),
    'run_ctx holds native state ownership for handler plus condition evaluation.'
],size=11.5)
p.box(640,150,512,286,'Native DisseminationLayer','native/src/raptr/dissemination/mod.rs:81; node/dissemination.rs:204',[
    ('prepare_block(round, excludes, authors)','Mono',C['red']),
    ('    -> Future<Payload>','Mono',C['red']),
    ('available_prefix(payload, cached)','Mono',C['blue']),
    ('    -> Future<(Prefix, BitVec)>','Mono',C['blue']),
    ('check_payload(payload) -> Result<(), BitVec>','Mono',C['blue']),
    ('notify_commit_identified(payloads, ts, voters)','Mono',C['orange']),
    'CommittedPayload binds block_digest, payload and include_proofs.'
],size=11.5)
p.line([(569,278),(640,278)],C['red'],arrow=True)
p.text(584,264,'pull',10.5,'Bold',C['red'])
p.line([(640,365),(569,365)],C['blue'],arrow=True)
p.text(578,352,'prefix',10.5,'Bold',C['blue'])
p.box(48,484,521,228,'Context + shared service adapters','framework/context.rs:19; node/factory.rs:128',[
    ('send / unicast / multicast; notify(module,event)','Mono',C['blue']),
    ('set_timer(duration,event); next_event(); halt()','Mono',C['purple']),
    'NativeDissemination uses real QS actors for pool pulls, certified batches, storage and RPC repair.',
    'Executor: Tokio 2 workers / max 32 blocking threads; Rayon 2. Native timing semantics are retained.'
],size=11.7)
p.line([(308,436),(308,484)],C['purple'],arrow=True)
p.box(640,484,512,228,'Commit reservation -> Materializer -> output','node/dissemination.rs:262; node/output.rs:116',[
    '1  reserve exact commit order before asynchronous fetch.',
    '2  Native QS retrieval + actual payload verification.',
    '3  resolve completed sections; pop_ready only at FIFO head.',
    '4  Workload publisher appends verified contiguous output.',
    'Expansion: proof batches first, then original subblock order. Raw duplicates remain; useful credit is deduplicated.'
],size=11.7,accent=C['orange'])
p.line([(895,436),(895,484)],C['orange'],arrow=True)
p.refs('Common mechanics: shared_mempool::Worker::start; shared_output::ResolutionQueue::{reserve,resolve,pop_ready}; shared_network::Transport.\nProtocol messages, certificate validity, native batch cutting and output expansion remain core-owned. Raptr uses BCS/BLS/SHA3; Delugi uses its own signed wire format.')
p.finish()


def table(page, rows, y=173, heights=None, widths=(153,342,361,248)):
    heads=['PARAMETER','DELUGI TODAY','RAPTR TODAY','EXPOSURE / EVALUATION MEANING']
    x=48
    for w,h in zip(widths,heads):
        page.rect(x,y,w,30,C['ink'],C['ink']);page.text(x+10,y+20,h,10.5,'Bold',C['white']);x+=w
    y+=30
    for i,row in enumerate(rows):
        height=heights[i] if heights else 53
        x=48
        for j,(w,cell) in enumerate(zip(widths,row)):
            page.rect(x,y,w,height,C['white'] if i%2==0 else C['light'])
            font='Bold' if j==0 else 'Body'
            size=11.2 if j else 11.4
            end=page.para(x+10,y+17,w-20,cell,size,font,leading=14.2)
            if end-14.2>y+height-6:raise ValueError(f'table row overflow {row[0]} column {j}: {end} > {y+height}')
            x+=w
        y+=height
    return y


# 4. Disambiguate sizes and the two meanings of delay.
p=Page('workload-parameters',4,'Workload, batch, payload and delay controls',
       'Defaults below belong to the current runner or native configuration, not a proposed matched experiment. CLI = runner flag; JSON = node config; FIXED = source/profile.')
rows=[
('Transaction size','CLI --useful-bytes=472. Canonical encoded request = useful + 60 bytes (532 at default).','CLI --useful-bytes=128. Native signed BCS size is measured; accepted 128-byte payload produced 409-byte transactions.','Match useful bytes; also record actual serialized sizes. Equal useful size does not mean equal wire size.'),
('Input rate / horizon','CLI --rate=1000 total tx/s; warmup 10 s, measure 30 s, drain 30 s. Independent open-loop ingress.','CLI --interval-us=1000; --counts=16/origin. Four origins imply nominal 4000 tx/s, but only 64 finite requests.','Raptr runner is finite conformance, not a sustained-load adapter yet. Preserve rejection and unfinished counts.'),
('Batch tx count','CLI --max-batch-transactions=128; also constrained by encoded byte capacity.','JSON quorum_store.sender_max_batch_txns=500; sender_max_total_txns=500; sender_max_num_batches=1 per pool pull.','Count limits are available. Batch cutting remains core policy; settings alone do not match batch fill.'),
('Batch byte cap','FIXED MAX_BATCH_PAYLOAD=256 KiB. Count <= floor((262144 - 8)/(useful + 60)).','JSON sender_max_batch_bytes=1,048,416 is not enforced by the native splitter. Total pool-pull bytes=4,194,144 is enforced.','Pre-cloud gap: expose an enforced Delugi byte cap; review native Raptr byte-splitting behavior before sweeping it.'),
('Batch cadence','CLI --batch-ms=10 (1..1000 ms). Flush on capacity or elapsed cadence.','JSON QS poll=150 ms; min nonempty=80 ms; max=300 ms; native dynamic backpressure also applies.','Different native batching policies. Record effective cut times and fill, not just a common label.'),
('Proposal bytes / tx','Resource profile: 1 MiB or 32 MiB ordering wire budget. Value+witness allowance reserves mandatory HISTORY3 overhead.','JSON consensus.max_sending_block_txns=50,000; max_sending_block_bytes=30 MiB; inline=100 tx / 200 KiB.','Separate proposal budget from transport frame limit. Raptr message limit is separately 1 MiB by default.'),
('Max payload batches','No independent max_payloads switch. A frontier checkpoint can cover many batches; MMR chunk capacity is not a batch-count cap.','JSON max_batches_per_pull=200; current native > checks can select 201. Native subblock count is fixed at 8.','Use explicit names: batch bytes, tx per batch, batches per proposal, proposal bytes, frame bytes.'),
('Protocol bound Δ','CLI --bound-ms=250 default; acceptance used 100. PROG pacing defaults to Δ; native 7Δ / 3Δ catch-up rules remain.','JSON delta_ms; accepted runner fixes 100. Leader 4Δ; partial-QC wait 0.1Δ; fetch 2Δ; sync 15Δ; status 10Δ.','Δ is protocol configuration. It is not added network delay, nor a latency scoring deadline.'),
('Network delay δ','External calibrated shaper. macOS helper 1..100 ms; Linux ingress netem delay 0..1000 ms and loss 0..100%.','No node delay knob. Current runner records 0 ms added delay; future deployment can reuse the external shaper.','Keep δ, Δ, batching and application hold distinct. Current helper schema has no bandwidth/jitter knobs.')]
table(p,rows,y=148,heights=[55,69,55,69,55,69,69,69,55])
p.refs('Source index: D1-D7 and R1-R7 in docs/architecture/delugi-code-structure-2026-10-22.txt. All limits shown are current source facts.\nThe two Raptr cap qualifications are inherited native behavior, documented here without changing protocol implementation.',y=760)
p.finish()


# 5. A truthful cloud-readiness map, with explicit actual faults vs tolerance.
p=Page('cloud-parameters',5,'Faults, resources and the cloud boundary',
       'n is committee size, f=(n-1)/3 is tolerated faults, and b is the number actually faulty. For the stated fault model require b <= f; n=4,7,31 gives f=1,2,10.')
rows=[
('Committee n / f','CLI --nodes={4,7,31}; process validates 4..31 with n=3f+1. f is derived, not set independently.','JSON/keygen supports 4..31, n=3f+1. Accepted runner fixes n=4; node currently requires loopback addresses.','An n/f setting is not evidence that all n/f campaigns have passed. Current common-binary acceptance is n=4.'),
('Actual faults b','Sustained runner: one paused replica OR one omission replica. Finite silent-first-leader fixture also exists.','Case presets: healthy (0); silent first leader (replica 1); missing-payload receiver 0 with first 3 QS messages dropped.','No general arbitrary-b Byzantine campaign in the common runners. Keep faulty IDs explicit and separate from f.'),
('Fault timing / scope','CLI start/duration/peers; payload drops BATCH+DATA, all drops outgoing application protocol messages.','Preset pause, original-payload omission and application materialization hold; no general event schedule CLI.','Future schedule needs mode, IDs, targets, activation/withdrawal, opportunity witness and positive effect checks.'),
('Storage completion','memory-visible-v1 default; optional shared-rocksdb-written-v1, fresh per-replica directory and typed cache.','Native QS uses shared RocksDB: WAL enabled, sync=false; completes at Written. Native quotas remain core-owned.','Match declared completion profile. Written is not fsync durability; Delugi core restart recovery is absent.'),
('Queues / workers','CLI arrival-queue-capacity=65,536. Sync actor loop; TCP workers. Most transport limits are source/profile fixed.','JSON Limits exposes inbox/RPC/ingress/payload/task caps. Runtime fixed: Tokio 2, max blocking 32, Rayon 2.','Shared TCP default: 64 in-flight frames / 8 MiB per peer. Reused services do not imply equal worker budgets.'),
('Observation / bounds','Full/compact receipts; compact omits detailed latency. --deadline-ms=1000 is scoring, not a protocol timeout.','Finite measurement=2000 ms + drain=2000 ms. JSON task limits=100k async / 1024 blocking; these are not RSS limits.','Primary latency: successful admission to verified contiguous output at the assigned correct origin, one monotonic clock.'),
('Cloud launch','Legacy --inventory SSH/netem path exists. --shared-build-receipt currently rejects --inventory; disk acceptance local-only.','Common Raptr runner is localhost-only. Existing remote-native adapter covers other artifacts, not this Raptr port.','Common executable deployment still needs build/config/host-local start, full receipts, cleanup and resource reconciliation.')]
table(p,rows,y=163,heights=[69,69,69,69,69,69,69])
p.note(48,692,1104,43,'Before cloud parameter sweeps',
       '',fill=C['amber'])
p.text(62,725,'Wire the common-node remote adapter; expose and verify the intended caps; add sustained Raptr ingress and bounded multi-fault schedules.',11.4)
p.refs('Source index: D8-D12, R8-R12, S1-S3. Proposed sweep schema must bind workload, batch, proposal, transport, timing, faults, storage and resources separately.\nThis document records current behavior and extension points. No cloud resources were provisioned and no protocol source was changed.')
p.finish()
cv.save()

txt='\n'.join(all_text)+'\n'
(OUT/'delugi-code-structure-2026-10-22-extracted-outline.txt').write_text(txt)
manifest={
    'date':'2026-10-22','source_commit':'57e078e88d5247ce01b886e6702b43addfeb5ff5',
    'scope':'Source audit and diagram only. No builds, protocol modifications or cloud execution.',
    'reference':{'path':'/Users/zhengxuanguo/Downloads/wahoo++_core.pdf','sha256':hashlib.sha256(Path('/Users/zhengxuanguo/Downloads/wahoo++_core.pdf').read_bytes()).hexdigest()},
    'artifacts':[{'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in [PDF,*pages]],
}
(ROOT/'docs/architecture/artifact-manifest-2026-10-22.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'pdf':str(PDF),'pages':len(pages),'svg':[str(p) for p in pages]},indent=2))
