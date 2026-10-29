import json,statistics,bisect,collections,argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
parser=argparse.ArgumentParser(description='Offline local OBS milestone chronology; not proof of prior legal inclusion.')
parser.add_argument('--output',type=Path,default=ROOT/'results/local/dissemination-audit-20261029')
O=parser.parse_args().output.resolve();D=ROOT/'benchmark/.state/runs/delugi-raptr-wan-30s-20261028/trials/5e2250ff5121e8d986930b2e'
def avg(xs):return statistics.mean(xs) if xs else None
rows=json.loads((O/'delugi-requests.json').read_text());out=[]
for i in range(4):
 t=json.loads((D/f'trial/causal-traces/replica-{i}.json').read_text());obs=sorted([e for e in t['events'] if e['event']=='observation_fixed'],key=lambda e:e['at_us']);times=[e['at_us'] for e in obs];inds={e['round']:k for k,e in enumerate(obs)};sealed={bytes(e['detail']['exact_batch_id']).hex():e for e in t['events'] if e['event']=='batch_sealed'}
 for x in [x for x in rows if x['origin']==i]:
  seal=sealed[x['batch']]['at_us'];idx=bisect.bisect_left(times,seal);sel=inds[x['round']];first=obs[idx];target=obs[sel]
  out.append({'origin':i,'leader':x['leader'],'round':x['round'],'first_obs_round':first['round'],'opportunities_before_inclusion_round':sel-idx,'sealed_to_next_local_obs_ms':(first['at_us']-seal)/1000,'next_obs_to_selected_obs_ms':(target['at_us']-first['at_us'])/1000,'selected_obs_to_proposal_ms':x['observation_to_proposal_ms']})
summary={'n':len(out),'opportunities':dict(collections.Counter(x['opportunities_before_inclusion_round'] for x in out)),'all':{k:avg([x[k] for x in out]) for k in ['sealed_to_next_local_obs_ms','next_obs_to_selected_obs_ms','selected_obs_to_proposal_ms']},'by_opportunities':{str(k):{'n':sum(x['opportunities_before_inclusion_round']==k for x in out),**{f:avg([x[f] for x in out if x['opportunities_before_inclusion_round']==k]) for f in ['sealed_to_next_local_obs_ms','next_obs_to_selected_obs_ms','selected_obs_to_proposal_ms']}} for k in sorted(set(x['opportunities_before_inclusion_round'] for x in out))}}
(O/'delugi-opportunity-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
