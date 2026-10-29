#!/usr/bin/env python3
"""Offline healthy-run audit over retained, source-bound evidence."""
from pathlib import Path
import collections,hashlib,json,statistics,sys,tarfile
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
import latency_decomposition as ld
from cohort_store import ShardedArchive
from cohort_metrics import identity
import campaign_execute,remote_native
OUT=Path(__file__).resolve().parent
TRIALS={'previous':ROOT/'benchmark/.state/runs/delugi-raptr-wan-30s-20261028/trials/5e2250ff5121e8d986930b2e/trial','pipeline':ROOT/'benchmark/.state/runs/delugi-pipeline-wan-20261029-clock-aligned/trials/b02e64f55f4e7fa0598860f6/trial'}
def stat(xs):
 xs=list(xs)
 return {'count':len(xs),'mean_ms':statistics.fmean(xs) if xs else None,'median_ms':statistics.median(xs) if xs else None,'min_ms':min(xs) if xs else None,'max_ms':max(xs) if xs else None}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def analyze(t):
 a=ld.analyze(t/'cohorts/index.json',t/'causal-traces');res=json.loads((t/'result.json').read_text());archive=ShardedArchive(t/'cohorts/index.json');r={'result_sha256':sha(t/'result.json'),'sources':a['sources'],'covered':a['covered'],'mean_admission_to_append_ms':a['mean_admission_to_append_ms'],'stages':a['stages'],'observed_rtt':[{k:v for k,v in x.items() if k!='samples_ms'} for x in res['network_shaping']['observed_rtt']],'leaders':{},'origins':{},'timers':{},'prefix_wait_details':{}}
 timers=collections.Counter();wait_examples=[]
 for i in range(4):
  ev=json.loads((t/f'causal-traces/replica-{i}.json').read_text())['events'];rounds={};sealed={};material={}
  for e in ev:
   rounds.setdefault(e['round'],[]).append(e)
   if e['event']=='batch_sealed':sealed.setdefault(identity(e['detail']['exact_batch_id']),e)
   if e['event']=='batch_materialized':material.setdefault(identity(e['detail']['exact_batch_id']),e)
  leaders=[x for x in a['leader_rounds'] if x['replica']==i]
  r['leaders'][str(i)]={'proposal_count':len(leaders),'normalized_four_round_cadence':stat((b['proposal_us']-a['proposal_us'])/4000 for a,b in zip(leaders,leaders[1:]) if b['round']==a['round']+4),'frozen_input_age':stat(x['frozen_input_age_ms'] for x in leaders),'report_to_input':stat(x['report_to_input_ms'] for x in leaders),'report_to_proposal':stat((x['proposal_us']-x['report_us'])/1000 for x in leaders),'report_before_history_count':sum(x['history_quorum_us'] is not None and x['report_us']<x['history_quorum_us'] for x in leaders)}
  props={rr:ld.first(ee,'proposal_validated')['at_us'] for rr,ee in rounds.items() if ld.first(ee,'proposal_validated')}
  gaps=[(props[rr+1]-props[rr])/1000 for rr in props if rr+1 in props]
  r['leaders'][str(i)]['local_adjacent_proposal_arrival_gaps']=stat(gaps);r['leaders'][str(i)]['out_of_order_adjacent_arrivals']=sum(x<0 for x in gaps)
  for e in ev:
   if e['event'] in ['main_timer_expiry','catchup_timer_expiry']:
    timers[e['event']]+=1
    # Completion of own outcome is the relevant guard, not scanner publication.
    finish=ld.first(rounds[e['round']],'own_cer_action')
    if finish and finish['at_us']<e['at_us']:timers[e['event']+'_after_own_cer']+=1
    decision=ld.first(rounds[e['round']],'classified')
    if decision and decision['at_us']<e['at_us']:timers[e['event']+'_after_classified']+=1
   elif e['event']=='no_cer':timers['no_cer']+=1
  outputs={identity(o['id']):o for o in archive.rows(i,'outputs') if o['origin']==i};reqs=list(archive.rows(i,'requests'));stagevals=[];own=[];split=collections.defaultdict(list)
  for req in reqs:
   if not archive.ledgers[i]['window_start_us']<=req['scheduled_us']<archive.ledgers[i]['window_end_us']:continue
   o=outputs[identity(req['id'])];batch=identity(o['exact_batch_id']);mat=material[batch];rr=mat['round'];st=ld.request_stages(req,o,sealed[batch],mat,rounds);stagevals.append(st);split[(rr-1)%4].append(st[1]/1000)
   prop=ld.first(rounds[rr],'proposal_validated');obs=ld.first(rounds[rr],'observation_fixed');inp=ld.first(rounds[rr],'input_fixed')
   if (rr-1)%4==i:
    own.append({'round':rr,'sealed_to_input_ms':(inp['at_us']-sealed[batch]['at_us'])/1000,'input_to_validated_proposal_ms':(prop['at_us']-inp['at_us'])/1000,'await_ms':st[1]/1000})
   if st[3]>0:wait_examples.append({'replica':i,'round':rr,'sequence':req['sequence'],'prefix_wait_ms':st[3]/1000})
  r['origins'][str(i)]={'count':len(stagevals),'stages':[{'stage':name,'mean_ms':statistics.fmean(x[n] for x in stagevals)/1000} for n,name in enumerate(ld.STAGES)],'await_by_committing_leader':{str(k):stat(v) for k,v in split.items()},'own_leader_tx_subset':{'count':len(own),**{key:stat(o[key] for o in own) for key in ['sealed_to_input_ms','input_to_validated_proposal_ms','await_ms']}}}
 r['timers']=dict(timers);r['timers'].setdefault('no_cer',0);r['prefix_wait_details']={'positive_request_count':len(wait_examples),'max':max(wait_examples,key=lambda x:x['prefix_wait_ms'])};r['leader_rounds']=a['leader_rounds'];return r
result={k:analyze(t) for k,t in TRIALS.items()}
# Verify catalog and current source binding through the existing offline checker.
settings=json.loads((ROOT/'benchmark/settings.json').read_text());catalog=json.loads(Path(settings['artifacts']).read_text());bindings=campaign_execute.validate_artifacts({'protocols':['delugi']},{'common':catalog['common']});pub=json.loads(Path(catalog['common']['publication']).read_text());vpath=ROOT/'results/local/delugi-pipeline-wan-20261029/repacked-runtime/verification.json';v=json.loads(vpath.read_text())
assert v['status']=='verified' and v['original_verification']['status']=='verified' and v['new_verification']['status']=='verified'
assert v['changed_manifest_members']==['source/scripts/run_sustained.py']
assert sha(ROOT/'scripts/run_sustained.py')==v['replacement_sha256']
assert v['binary_sha256']==pub['binary_sha256']
assert sha(pub['archive'])==pub['sha256']
result['publication_audit']={'status':'passed','verification_file_sha256':sha(vpath),'changed_manifest_members':v['changed_manifest_members'],'binary_sha256':v['binary_sha256'],'current_runtime_and_local_verifier_source_bindings_verified':True,'bindings':bindings}
result['constraints']=['All request stage arithmetic uses each origin local monotonic clock.','Leader diagnostics are per-round and cannot be added directly to transaction-weighted stage means.','Four-round cadence uses every retained leader proposal, not sampled handler spans.','The four measured RTT edges are a ring, not all six pairs.','No causal attribution of the full await-proposal increase is established.']
(OUT/'healthy-pipeline-audit.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:{'mean':v['mean_admission_to_append_ms'],'timers':v['timers'],'origin_own_leader':{i:d['own_leader_tx_subset'] for i,d in v['origins'].items()}} for k,v in result.items() if k in TRIALS},indent=2))
