#!/usr/bin/env python3
"""Offline native Raptr cohort and first-local-inclusion audit. No cross-host subtraction."""
import argparse, collections, hashlib, json, statistics, sys
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'scripts/raptr_latency_decomposition.py').exists())
sys.path.insert(0,str(ROOT/'scripts'))
import raptr_latency_decomposition as red
from run_raptr_sustained import journal
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parent)
OUT=parser.parse_args().output.resolve();OUT.mkdir(parents=True,exist_ok=True)
RUN=ROOT/'benchmark/.state/runs/raptr-wan-stages-20261029/trials/9b65f5c790b85b8186317c0f'
result=json.loads((RUN/'result.json').read_text())
validated=red.analyze(RUN/'config.json',RUN/'replicas',result['correct_replicas'],authentication=result['authentication'])
assert validated['covered']==3000 and validated['excluded']=={}
authors={m['author']:m['id'] for m in json.loads((RUN/'public/committee.json').read_text())['members']}
per_node=[]; self_rows=[]; own_proposal_missed=[]
for node in range(4):
 path=RUN/f'replicas/node-{node}';t=json.loads((path/'latency-trace.json').read_text());ix=red.indexes(t['events']);batches,proposals,commits,_,_=ix
 full={red.block_key(e) for e in t['events'] if e['event']=='committed' and e['include_proofs'] and e['from_prefix']==0 and e['to_prefix']==8}
 assert len(full)==sum(e['event']=='committed' for e in t['events'])
 sections=collections.defaultdict(set);membership=collections.defaultdict(set);count=collections.Counter();own={};blockauthors={}
 for out in journal(path/'output.jsonl'):
  block=red.block_key(out['block']);blockauthors[block]=authors[out['block']['author']];sections[block].add(red.section_key(out['section']))
  for batch in out['batches']:
   key=red.batch_key(batch['key']);membership[key].add(block);count[key]+=1
   for tx in batch['transactions']:
    if tx['own_credit']:own[tx['request_id']]=(out,batch)
 assert set(sections)==full
 assert all(s==set(range(-1,8)) for s in sections.values())
 assert all(c==1 for c in count.values())
 uncovered=set(proposals)-full
 checkpoints=[]; requests=list(journal(path/'requests.jsonl',max_line=16384))
 for req in requests:
  out,batch=own[req['request_id']];block=red.block_key(out['block']);key=red.batch_key(batch['key']);p=proposals[block]
  # Every proposal accepted no later than this execution proposal has complete
  # committed output membership, not merely the final execution-associated block.
  assert all(proposals[u]>p for u in uncovered)
  included=membership[key]
  assert min(proposals[b] for b in included)==p
  checkpoints.append(p)
  if blockauthors[block]==node:
   store=batches['batch_stored',key];quorum=batches.get(('availability_quorum',key))
   age_ready=store+30_000 # conservative local sufficient-age checkpoint; not exact selection eligibility
   earlier=[b for b,a in blockauthors.items() if a==node and age_ready<=proposals[b]<p]
   row={'node':node,'request':req['sequence'],'round':block[0],'batch':list(key),'batch_ms':(store-req['admitted_us'])/1000,'stored_to_proposal_ms':(p-store)/1000,'stored_to_poa_ms':(quorum-store)/1000 if quorum else None,'earlier_own_proposals_after_store_plus_30ms':len(earlier)}
   self_rows.append(row)
   if earlier:own_proposal_missed.append(row)
 per_node.append({'node':node,'covered_requests':len(requests),'validated_proposals':len(proposals),'fully_committed_proposals':len(full),'complete_membership_blocks':len(sections),'uncovered_terminal_rounds':sorted(b[0] for b in uncovered),'latest_cohort_proposal_round':max(red.block_key(own[q['request_id']][0]['block'])[0] for q in requests),'distinct_output_batches':len(count),'batch_occurrence_histogram':dict(collections.Counter(count.values())),'stored_events_by_author':dict(collections.Counter(authors[e['batch']['author']] for e in t['events'] if e['event']=='batch_stored')),'uncovered_proposals_after_every_cohort_associated_proposal':True,'first_locally_accepted_inclusion_matches_execution_associated':True})
def stats(rows):
 return {'requests':len(rows),**{k:{'mean':statistics.mean(r[k] for r in rows),'minimum':min(r[k] for r in rows),'maximum':max(r[k] for r in rows)} for k in ['batch_ms','stored_to_proposal_ms','stored_to_poa_ms']}}
report={'kind':'raptr-healthy-first-local-inclusion-offline-audit','validated':{'requests':validated['covered'],'excluded':validated['excluded']},'nodes':per_node,'own_leader':stats(self_rows),'own_leader_by_node':{str(n):stats([r for r in self_rows if r['node']==n]) for n in range(4)},'own_leader_batches':len({tuple(r['batch']) for r in self_rows}),'earlier_own_proposals_after_sufficient_age_count':len(own_proposal_missed),'limitations':['This proves first locally accepted inclusion for the observed healthy cohort; it does not map leader emission timestamps across hosts.','All earlier observed proposals have complete committed membership. Terminal uncovered proposals occur after every cohort associated proposal.','BatchStored events exist only for the producer. Foreign payload-arrival and payload-pull events are absent.','Minimum optimistic batch age is creation-based wall-clock age, not delay added after receipt; stored+30ms is only a conservative local sufficient-age checkpoint.','Existing native binary exposes no bind-versus-advertised override through Raptr Config, so unprivileged delay proxy requires a node adapter change/rebuild.'],'sources':validated['sources'],'source_files':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'core/raptr/src/output.rs',ROOT/'core/raptr/node/src/dissemination.rs',ROOT/'core/raptr/qs/src/quorum_store/batch_store.rs',ROOT/'core/raptr/qs/src/quorum_store/batch_proof_queue.rs']}}
(OUT/'summary.json').write_text(json.dumps(report,indent=2)+'\n');(OUT/'self-leader-rows.json').write_text(json.dumps(self_rows,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('sources','source_files')},indent=2))
