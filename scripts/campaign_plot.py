"""Plot verified campaign tables; censored percentiles are never drawn as zero."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path


def render(state, directory):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    os.environ.setdefault('MPLCONFIGDIR',str(directory/'.plot-cache'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    rows=state['rows'];nodes=sorted({r['nodes'] for r in rows})
    if not nodes:return {'status':'no_data','files':[]}
    protocols=list(dict.fromkeys(r['protocol'] for r in rows));colors=plt.get_cmap('tab10')
    fig,axes=plt.subplots(3,len(nodes),figsize=(6*len(nodes),10),squeeze=False)
    for column,n in enumerate(nodes):
        for j,p in enumerate(protocols):
            selected=sorted([r for r in rows if r['nodes']==n and r['protocol']==p and r['case']=='healthy' and r.get('metrics') and r['status'] in ('completed','passed')],key=lambda r:r['rate'])
            valid=[r for r in selected if r['metrics']['p50_ms'] is not None]
            axes[0,column].plot([r['metrics']['goodput_tps'] for r in valid],[r['metrics']['p50_ms'] for r in valid],
                marker='o',color=colors(j),label=p)
            valid95=[r for r in selected if r['metrics']['p95_ms'] is not None]
            axes[0,column].plot([r['metrics']['goodput_tps'] for r in valid95],[r['metrics']['p95_ms'] for r in valid95],
                marker='x',linestyle='--',alpha=.7,color=colors(j))
            axes[1,column].plot([r['rate'] for r in selected],[100*r['metrics']['completion_fraction'] for r in selected],
                marker='o',color=colors(j),label=p)
            traffic=[r for r in selected if r['metrics'].get('traffic_measurement_written_bytes') is not None]
            axes[2,column].plot([r['rate'] for r in traffic],
                [r['metrics']['traffic_measurement_written_bytes']*8/60/n/1e6 for r in traffic],
                marker='o',color=colors(j),label=p)
        axes[0,column].set(title=f'n = {n}',xlabel='Verified useful goodput (tx/s)',ylabel='Origin admission → append (ms)')
        axes[1,column].set(xlabel='Total honest input (tx/s)',ylabel='Completed by drain cutoff (%)',ylim=(-2,102))
        axes[2,column].set(xlabel='Total honest input (tx/s)',ylabel='Mean protocol writes / validator (Mbit/s)')
        for ax in axes[:,column]:ax.grid(alpha=.2)
    axes[0,0].legend(fontsize=8)
    title='SYNTHETIC DATA · renderer test only' if state.get('synthetic') else 'Diagnostic campaign · qualification remains separate'
    fig.suptitle(title+'\nSolid: p50; dashed: p95; censored percentiles omitted (retained in CSV)'
                 +'\nTraffic boundaries retain native service differences; see CSV',fontsize=10)
    fig.tight_layout(rect=(0,0,1,.94))
    files=[]
    for ext in ('pdf','png'):
        path=directory/f'latency-goodput.{ext}';fig.savefig(path,dpi=180);files.append(str(path))
    plt.close(fig)
    return {'status':'rendered','files':files,'scope':'healthy curves and completion fractions; failed/censored/fault rows remain in results.csv'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('state',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();print(json.dumps(render(json.loads(args.state.read_text()),args.output),indent=2))
