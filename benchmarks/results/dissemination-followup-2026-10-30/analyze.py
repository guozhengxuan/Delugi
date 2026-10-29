#!/usr/bin/env python3
import sys,json,hashlib,collections,statistics,argparse
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/"scripts/latency_decomposition.py").is_file());sys.path.insert(0,str(ROOT/'scripts'))
import latency_decomposition as d, raptr_latency_decomposition as r
from cohort_store import ShardedArchive
from cohort_metrics import identity
from run_raptr_sustained import journal
D=ROOT/'benchmark/.state/runs/delugi-freshness-wan-20261030/trials/b02e64f55f4e7fa0598860f6'
R=ROOT/'benchmark/.state/runs/raptr-wan-stages-20261029/trials/9b65f5c790b85b8186317c0f'
parser=argparse.ArgumentParser(description='Offline exact-batch WAN latency audit; no protocol or cloud execution.')
parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parent)
OUT=parser.parse_args().output.resolve();OUT.mkdir(parents=True,exist_ok=True)
d_verified=d.analyze(D/'trial/cohorts/index.json',D/'trial/causal-traces')
r_result=json.loads((R/'result.json').read_text())
r_verified=r.analyze(R/'config.json',R/'replicas',r_result['correct_replicas'],authentication=r_result['authentication'])
assert d_verified['covered']==r_verified['covered']==3000
assert d_verified['excluded']==r_verified['excluded']=={}
validation={'schema':1,'method':'Exact request/batch joins. All spans are local monotonic differences; leader diagnostics never subtract origin timestamps. Origin OBS is a checkpoint, not asserted pool membership except self-leader.', 'covered':{'delugi':d_verified['covered'],'raptr':r_verified['covered']},'excluded':{'delugi':d_verified['excluded'],'raptr':r_verified['excluded']},'delugi_trace_sources':d_verified['sources'],'raptr_sources':r_verified['sources']}
validation['delugi_cohort_index_sha256']=d_verified['cohort_index_sha256']
validation['raptr_configuration_sha256']=r_verified['configuration_sha256']
validation['inputs']=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in [D/'trial/cohorts/index.json',R/'config.json',R/'result.json']]
(OUT/'validation.json').write_text(json.dumps(validation,indent=2)+'\n')
def mean(xs):return statistics.mean(xs) if xs else None
def summarize(rows,keys):
 return {'n':len(rows),**{k:mean([x[k] for x in rows if x.get(k) is not None]) for k in keys}}
def grouped(rows,field,keys):return {str(k):summarize([x for x in rows if x[field]==k],keys) for k in sorted(set(x[field] for x in rows))}
traces={i:json.loads((D/f'trial/causal-traces/replica-{i}.json').read_text()) for i in range(4)}
rounds={i:{} for i in traces}
for i,t in traces.items():
 for e in t['events']:rounds[i].setdefault(e['round'],[]).append(e)
arc=ShardedArchive(D/'trial/cohorts/index.json');dr=[]
for i,ledger in arc.ledgers.items():
 sealed={identity(e['detail']['exact_batch_id']):e for e in traces[i]['events'] if e['event']=='batch_sealed'}
 mat={}
 for e in traces[i]['events']:
  if e['event']=='batch_materialized':mat.setdefault(identity(e['detail']['exact_batch_id']),e)
 own={identity(x['id']):x for x in arc.rows(i,'outputs') if x['origin']==i}
 for q in arc.rows(i,'requests'):
  if not ledger['window_start_us']<=q['scheduled_us']<ledger['window_end_us']:continue
  o=own[identity(q['id'])];b=identity(o['exact_batch_id']);m=mat[b];rr=m['round'];events=rounds[i][rr];leader=(rr-1)%4;le=rounds[leader][rr]
  st=d.request_stages(q,o,sealed[b],m,rounds[i]);obs=d.first(events,'observation_fixed');p=d.first(events,'proposal_validated')
  report=next(e for e in le if e['event']=='dissemination_outbox' and e['detail']['kind']=='REPORT')
  pool=d.first(le,'observation_pool_fixed');inp=d.first(le,'input_fixed');lp=d.first(le,'proposal_validated');ad=d.first(le,'admission');hq=d.first(le,'history_quorum')
  row=dict(origin=i,leader=leader,round=rr,batch=b,seq=q.get('sequence'),batch_ms=st[0]/1000,wait_ms=st[1]/1000,consensus_ms=st[2]/1000,to_proposal_ms=sum(st[:2])/1000,observation_to_proposal_ms=(p['at_us']-obs['at_us'])/1000,sealed_to_observation_ms=(obs['at_us']-sealed[b]['at_us'])/1000,leader_report_to_pool_ms=(pool['at_us']-report['at_us'])/1000,leader_pool_to_proposal_ms=(lp['at_us']-pool['at_us'])/1000,leader_admission_to_report_ms=(report['at_us']-ad['at_us'])/1000,leader_historyquorum_to_report_ms=(report['at_us']-hq['at_us'])/1000 if hq else None)
  if i==leader:row['own_sealed_to_report_ms']=(report['at_us']-sealed[b]['at_us'])/1000
  dr.append(row)
keys=['batch_ms','wait_ms','consensus_ms','to_proposal_ms','sealed_to_observation_ms','observation_to_proposal_ms','leader_report_to_pool_ms','leader_pool_to_proposal_ms','leader_admission_to_report_ms','leader_historyquorum_to_report_ms','own_sealed_to_report_ms']
rap=[];authors={x['author']:x['id'] for x in json.loads((R/'public/committee.json').read_text())['members']}
for i in range(4):
 directory=R/f'replicas/node-{i}';trace=json.loads((directory/'latency-trace.json').read_text());ix=r.indexes(trace['events']);own={}
 for o in journal(directory/'output.jsonl',max_rows=900000):
  for b in o['batches']:
   for tx in b['transactions']:
    if tx['own_credit']:own[tx['request_id']]=(o,b)
 for q in journal(directory/'requests.jsonl',max_line=16384):
  o,b=own[q['request_id']];st,j,a=r.request_stages(q,o,b,ix);rap.append(dict(batch=r.batch_key(b['key']),origin=i,leader=authors[o['block']['author']],round=o['block']['round'],section=r.section_key(o['section']),batch_ms=st[0]/1000,wait_ms=st[1]/1000,consensus_ms=st[2]/1000,to_proposal_ms=sum(st[:2])/1000,quorum_ms=a['duration_us']/1000,quorum_after=a['after_proposal'],quorum_to_proposal_ms=-a['relative_to_proposal_us']/1000))
rkeys=['batch_ms','wait_ms','consensus_ms','to_proposal_ms','quorum_ms','quorum_to_proposal_ms']
report={'delugi':{'all':summarize(dr,keys),'by_origin':grouped(dr,'origin',keys),'by_leader':grouped(dr,'leader',keys),'own_leader':summarize([x for x in dr if x['origin']==x['leader']],keys),'foreign_leader':summarize([x for x in dr if x['origin']!=x['leader']],keys),'sealed_after_own_OBS':summarize([x for x in dr if x['sealed_to_observation_ms']<0],keys),'sealed_before_own_OBS':summarize([x for x in dr if x['sealed_to_observation_ms']>=0],keys),'by_origin_leader':{f'{i}->{l}':summarize([x for x in dr if x['origin']==i and x['leader']==l],keys) for i in range(4) for l in range(4)}},'raptr':{'all':summarize(rap,rkeys),'by_origin':grouped(rap,'origin',rkeys),'by_leader':grouped(rap,'leader',rkeys),'own_leader':summarize([x for x in rap if x['origin']==x['leader']],rkeys),'foreign_leader':summarize([x for x in rap if x['origin']!=x['leader']],rkeys),'by_section':grouped(rap,'section',rkeys),'quorum_after_proposal':summarize([x for x in rap if x['quorum_after']],rkeys),'quorum_before_proposal':summarize([x for x in rap if not x['quorum_after']],rkeys),'by_origin_leader':{f'{i}->{l}':summarize([x for x in rap if x['origin']==i and x['leader']==l],rkeys) for i in range(4) for l in range(4)}}}
report['delugi']['unique_exact_batches']=len(set(x['batch'] for x in dr))
report['raptr']['unique_exact_batches']=len(set(x['batch'] for x in rap))
report['delugi']['checkpoint_caveat']='Same-round origin OBS snapshot may be absent from frozen pool or WA witness; timing is a local milestone, not a proven causal dependency. Origin=leader self OBS is collected synchronously first by implementation.'
report['raptr']['standardized_to_delugi_origin_executionleader_mix']={
 'method':'Use each Delugi origin/execution-leader cell request count as weight on the corresponding Raptr cell mean. Raptr has support for all cells occupied by Delugi; descriptive adjustment only, not causal control.',
 'n':len(dr),
 'mean_ms':{key:sum(cell['n']*report['raptr']['by_origin_leader'][pair][key] for pair,cell in report['delugi']['by_origin_leader'].items() if cell['n'])/len(dr) for key in ['batch_ms','wait_ms','to_proposal_ms']}}
report['accounting']={'sealed_start_gap_ms':mean([x['wait_ms'] for x in dr])-mean([x['wait_ms'] for x in rap]),'admission_start_gap_ms':mean([x['to_proposal_ms'] for x in dr])-mean([x['to_proposal_ms'] for x in rap]),'preceding_batch_difference_ms':mean([x['batch_ms'] for x in rap])-mean([x['batch_ms'] for x in dr])}
# Future admissions are intentionally speculative in the corrected pipeline.
# Do not republish the historical admission/HISTORY3-to-REPORT diagnostics as waits.
def strip_old_pacing_fields(value):
 if isinstance(value, dict):
  for key in ['leader_admission_to_report_ms','leader_historyquorum_to_report_ms']:
   value.pop(key,None)
  for child in value.values():strip_old_pacing_fields(child)
 elif isinstance(value,list):
  for child in value:strip_old_pacing_fields(child)
strip_old_pacing_fields(report)
strip_old_pacing_fields(dr)
(OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'delugi-requests.json').write_text(json.dumps(dr,indent=2)+'\n');(OUT/'raptr-requests.json').write_text(json.dumps(rap,indent=2)+'\n');print(json.dumps({k:{a:b for a,b in v.items() if a not in ['by_origin_leader']} for k,v in report.items()},indent=2))
