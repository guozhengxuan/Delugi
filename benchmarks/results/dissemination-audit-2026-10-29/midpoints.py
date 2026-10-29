"""Audit archived proposal midpoint observability; no inferred cross-host times."""
import json,statistics,sys,collections
from pathlib import Path
O=Path(__file__).resolve().parent;ROOT=O.parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from cohort_store import ShardedArchive
from cohort_metrics import identity
import latency_decomposition as d,raptr_latency_decomposition as r
from run_raptr_sustained import journal
D=ROOT/'benchmark/.state/runs/delugi-raptr-wan-30s-20261028/trials/5e2250ff5121e8d986930b2e'
R=ROOT/'benchmark/.state/runs/raptr-wan-stages-20261029/trials/9b65f5c790b85b8186317c0f'
d_verified=d.analyze(D/'trial/cohorts/index.json',D/'trial/causal-traces')
r_result=json.loads((R/'result.json').read_text())
r_verified=r.analyze(R/'config.json',R/'replicas',r_result['correct_replicas'],authentication=r_result['authentication'])
assert d_verified['covered']==r_verified['covered']==3000
assert d_verified['excluded']==r_verified['excluded']=={}
def summarize(rows):
 keys=sorted(set(k for row in rows for k in row if k.endswith('_ms')))
 return {'requests':len(rows),**{k:statistics.mean([x[k] for x in rows if x.get(k) is not None]) for k in keys}}
traces={i:json.loads((D/f'trial/causal-traces/replica-{i}.json').read_text()) for i in range(4)};rounds={i:{} for i in traces}
for i,t in traces.items():
 for e in t['events']:rounds[i].setdefault(e['round'],[]).append(e)
arc=ShardedArchive(D/'trial/cohorts/index.json');dr=[];leader_local_all=[]
outputs={i:list(arc.rows(i,'outputs')) for i in range(4)};output_maps={i:{identity(x['id']):x for x in outputs[i]} for i in range(4)}
for i,ledger in arc.ledgers.items():
 sealed={identity(e['detail']['exact_batch_id']):e for e in traces[i]['events'] if e['event']=='batch_sealed'};mat={}
 for e in traces[i]['events']:
  if e['event']=='batch_materialized':mat.setdefault(identity(e['detail']['exact_batch_id']),e)
 for q in arc.rows(i,'requests'):
  if not ledger['window_start_us']<=q['scheduled_us']<ledger['window_end_us']:continue
  out=output_maps[i][identity(q['id'])];b=identity(out['exact_batch_id']);rr=mat[b]['round'];leader=(rr-1)%4;le=rounds[leader][rr];emit=next(e for e in le if e['event']=='ordering_outbox' and e['detail']['kind']=='PROPOSE')
  lout=output_maps[leader][identity(q['id'])];assert identity(lout['exact_batch_id'])==b
  leader_local_all.append({'origin':i,'leader':leader,'round':rr,'logical_outbox_to_leader_output_ms':(lout['materialized_us']-emit['at_us'])/1000})
  if i!=leader:continue
  events=rounds[i][rr];p=d.first(events,'proposal_validated');assembly=d.first(events,'proposal_assembled');inp=d.first(events,'input_fixed');qenqueue=[e for e in events if e['event']=='transport_enqueue' and e['detail']['kind']=='PROPOSE'];firstq=min((e['at_us'] for e in qenqueue),default=None);lastq=max((e['at_us'] for e in qenqueue),default=None)
  row={'origin':i,'round':rr,'batch':b,'admission_to_logical_outbox_ms':(emit['at_us']-q['admitted_us'])/1000,'sealed_to_logical_outbox_ms':(emit['at_us']-sealed[b]['at_us'])/1000,'logical_outbox_to_origin_output_ms':(out['materialized_us']-emit['at_us'])/1000,'total_admission_to_output_ms':(out['materialized_us']-q['admitted_us'])/1000,'validation_to_outbox_ms':(emit['at_us']-p['at_us'])/1000,'input_fixed_to_outbox_ms':(emit['at_us']-inp['at_us'])/1000,'assembly_to_outbox_ms':(emit['at_us']-assembly['at_us'])/1000,'outbox_to_first_transport_enqueue_ms':None if firstq is None else(firstq-emit['at_us'])/1000,'outbox_to_last_transport_enqueue_ms':None if lastq is None else(lastq-emit['at_us'])/1000}
  assert row['admission_to_logical_outbox_ms']>=0 and row['logical_outbox_to_origin_output_ms']>=0
  assert abs(row['admission_to_logical_outbox_ms']+row['logical_outbox_to_origin_output_ms']-row['total_admission_to_output_ms'])<1e-8
  dr.append(row)
rap=[];authors={x['author']:x['id'] for x in json.loads((R/'public/committee.json').read_text())['members']}
for i in range(4):
 directory=R/f'replicas/node-{i}';trace=json.loads((directory/'latency-trace.json').read_text());ix=r.indexes(trace['events']);own={}
 for out in journal(directory/'output.jsonl',max_rows=900000):
  for b in out['batches']:
   for tx in b['transactions']:
    if tx['own_credit']:own[tx['request_id']]=(out,b)
 for q in journal(directory/'requests.jsonl',max_line=16384):
  out,b=own[q['request_id']];leader=authors[out['block']['author']]
  if i!=leader:continue
  st,_,_=r.request_stages(q,out,b,ix);rap.append({'origin':i,'round':out['block']['round'],'batch':r.batch_key(b['key']),'admission_to_leader_self_acceptance_ms':sum(st[:2])/1000,'sealed_to_leader_self_acceptance_ms':st[1]/1000,'leader_self_acceptance_to_origin_output_ms':sum(st[2:])/1000,'total_admission_to_output_ms':sum(st)/1000})
summary={'delugi_same_host_logical_outbox':{'all':summarize(dr),'by_origin':{str(i):summarize([x for x in dr if x['origin']==i]) for i in range(4)},'unique_rounds':len(set(x['round'] for x in dr)),'unique_batches':len(set(x['batch'] for x in dr)),'transport_enqueue_covered_requests':sum(x['outbox_to_first_transport_enqueue_ms'] is not None for x in dr),'transport_enqueue_covered_rounds':len(set(x['round'] for x in dr if x['outbox_to_first_transport_enqueue_ms'] is not None))},'delugi_all_requests_leader_endpoint_diagnostic':summarize(leader_local_all),'raptr_same_host_self_acceptance_PROXY_NOT_EMISSION':{'all':summarize(rap),'by_origin':{str(i):summarize([x for x in rap if x['origin']==i]) for i in range(4)},'unique_rounds':len(set(x['round'] for x in rap)),'unique_batches':len(set(x['batch'] for x in rap))},'first_inclusion_observability':{'delugi':'No full proposal payloads in causal traces. All observed classified rounds in healthy archive commit directly, supporting output association under ordered materialization; no exact decoded first-inclusion search possible.','raptr':'No proposed-block payload membership or emission events exported; earlier failed/partial optimistic inclusions cannot be recovered. Output-associated proposal != proven first inclusion.'},'clock_contract':'All computed differences are same-host monotonic. No cross-host subtraction. Logical outbox precedes per-peer transport queue insertion; no socket-write emission timestamp. Raptr self-acceptance is after multicast loopback, not emission; proxy explicitly labeled.'}
for i in traces:
 counts=collections.Counter(str(e['detail'].get('status')) if not isinstance(e['detail'].get('status'),dict) else next(iter(e['detail']['status'])) for e in traces[i]['events'] if e['event']=='classified')
 summary.setdefault('delugi_classification_counts',{})[i]=dict(counts)
summary['validation']={'covered':{'delugi':d_verified['covered'],'raptr':r_verified['covered']},'excluded':{'delugi':d_verified['excluded'],'raptr':r_verified['excluded']},'delugi_trace_sources':d_verified['sources'],'raptr_sources':r_verified['sources'],'delugi_cohort_index_sha256':d_verified['cohort_index_sha256'],'raptr_configuration_sha256':r_verified['configuration_sha256']}
(O/'midpoint-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
