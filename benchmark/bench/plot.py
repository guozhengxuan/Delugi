"""Latency/throughput figures from LogParser summaries, with visible censoring."""
from __future__ import annotations
import json
import math
import os
from pathlib import Path

LABELS={'delugi':'Delugi','raptr':'Raptr'}
COLORS={'delugi':'#087f8c','raptr':'#7651a8'}
CASES={'healthy':'Healthy','silent-first-leader':'Silent first leader','missing-data':'Missing data'}


def render(summary, directory, *, endpoint='end_to_end', scale='auto'):
    if endpoint not in ('end_to_end','admission'):raise ValueError('unknown latency endpoint')
    if scale not in ('auto','linear','log'):raise ValueError('scale must be auto, linear or log')
    if isinstance(summary,(str,Path)):summary=json.loads(Path(summary).read_text())
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    os.environ.setdefault('MPLCONFIGDIR',str(directory/'.plot-cache'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D
    rows=summary['rows'];cases=list(dict.fromkeys(r['case'] for r in rows))
    if not rows:raise ValueError('no runs to plot')
    fig,axes=plt.subplots(1,len(cases),figsize=(5.8*len(cases),4.7),squeeze=False,sharey=True)
    offered=max(r.get('rate') or 0 for r in rows)
    observed=[]
    for r in rows:
        for k in ('p50','p95'):
            v=r.get(endpoint+'_'+k+'_ms')
            if v is None:v=r.get(endpoint+'_'+k+'_lower_bound_ms')
            if v is not None and math.isfinite(v):observed.append(v/1000)
    ymax=(max(observed or [1]) or 1)*1.35
    positive=[v for v in observed if v>0]
    logarithmic=scale=='log' or (scale=='auto' and positive and max(positive)/min(positive)>=20)
    for ax,case in zip(axes[0],cases):
        selected=[r for r in rows if r['case']==case]
        for i,r in enumerate(selected):
            p=r['protocol'];color=COLORS.get(p,plt.get_cmap('tab10')(i));marker='o' if p=='delugi' else 's'
            x=r.get('goodput_tps');value=r.get(endpoint+'_p50_ms');status=r.get(endpoint+'_p50_status')
            upper=r.get(endpoint+'_p95_ms');label=LABELS.get(p,p)
            if x is None or status=='empty' or (value is None and r.get(endpoint+'_p50_lower_bound_ms') is None):
                ax.text(.03,.07+i*.07,label+': '+r['status']+'; latency unavailable',transform=ax.transAxes,color=color,fontsize=9)
                continue
            censored=value is None
            if censored:value=r.get(endpoint+'_p50_lower_bound_ms')
            if value is None:continue
            y=value/1000
            ax.scatter([x],[y],color=color,marker=marker,s=80,facecolors='none' if censored else color,zorder=4)
            if upper is not None and upper>=value:
                ax.vlines(x,y,upper/1000,color=color,linewidth=1.7,alpha=.75)
                ax.plot([x],[upper/1000],marker='_',markersize=10,color=color)
            elif r.get(endpoint+'_p95_status')=='censored':
                bound=r.get(endpoint+'_p95_lower_bound_ms')
                if bound is not None:
                    tail=max(y,bound/1000)
                    ax.vlines(x,y,tail,color=color,linewidth=1.2,linestyle='--')
                    ax.annotate('',xy=(x,tail*1.25 if logarithmic else tail+ymax*.06),xytext=(x,tail),arrowprops={'arrowstyle':'->','color':color})
            if censored and r.get(endpoint+'_p95_status')!='censored':
                ax.annotate('',xy=(x,y*1.25 if logarithmic else y+ymax*.06),xytext=(x,y),arrowprops={'arrowstyle':'->','color':color})
            # At a common offered rate the points are often vertically aligned.
            # Keep their labels in separate fixed rows, away from the whiskers.
            text=f"{label}: {x:.1f} tx/s · median {'≥' if censored else ''}{y:.3f} s"
            ax.text(.035,(.25 if logarithmic else .95)-i*.105,text,transform=ax.transAxes,va='top',fontsize=9,color=color,
                    bbox={'facecolor':'white','edgecolor':'none','alpha':.85,'pad':2})
        ax.set(title=CASES.get(case,case),xlabel='Measured useful throughput (tx/s)')
        ax.set_xlim(0,max(offered,max((r.get('goodput_tps') or 0 for r in selected),default=0))*1.18 or 1)
        if logarithmic:
            from matplotlib.ticker import FuncFormatter,LogLocator
            ax.set_yscale('log');ax.set_ylim(min(positive or [1])*.65,ymax)
            ax.yaxis.set_major_locator(LogLocator(base=10,subs=(1,3)))
            ax.yaxis.set_major_formatter(FuncFormatter(lambda y,pos:f'{y:g}'))
        else:ax.set_ylim(0,ymax)
        ax.grid(alpha=.18);ax.spines[['top','right']].set_visible(False)
    start='Intended arrival' if endpoint=='end_to_end' else 'Admission'
    axes[0,0].set_ylabel(start+' → origin-local verified output (s)')
    handles=[Line2D([0],[0],marker='o' if p=='delugi' else 's',linestyle='none',color=COLORS.get(p,'gray'),label=LABELS.get(p,p),markersize=7)
             for p in dict.fromkeys(r['protocol'] for r in rows)]
    fig.legend(handles=handles,loc='upper center',bbox_to_anchor=(.5,.91),ncol=len(handles),frameon=False)
    fig.suptitle('Four-region latency–throughput comparison',fontsize=15,fontweight='bold',y=.99)
    params=summary.get('parameters',{});configuration=''
    if params.get('Delta_ms') is not None:
        nodes='/'.join(map(str,params['nodes']))
        network='natural WAN' if params.get('network_modes')==['observed-wan-v1'] else f"added δ = {params.get('added_delay_ms')} ms"
        configuration=f"{nodes} replicas · {params['tx_bytes']} B useful tx · Δ = {params['Delta_ms']} ms · {params['egress_mbps']} Mbps egress · {network}\n"
    incomplete=[f"{LABELS.get(r['protocol'],r['protocol'])} / {CASES.get(r['case'],r['case']).lower()}: {r['scheduled']-r['completed']:,}/{r['scheduled']:,} unfinished at collection"
                for r in rows if r.get('scheduled') is not None and r.get('completed') is not None and r['completed']<r['scheduled']]
    incomplete_text=('\n'+'; '.join(incomplete)) if incomplete else ''
    fig.text(.5,.025,configuration+f"One input rate: {offered:g} tx/s · {summary['measurement_duration_s']} s per run · ≤ {summary['drain_s']} s drain\n"
        'Points: median; whiskers: p95; arrows: censored lower bounds. One run per case.'+(' Logarithmic latency axis.' if logarithmic else '')+incomplete_text,ha='center',fontsize=8.5,color='#444444')
    fig.tight_layout(rect=(0,.16,1,.87))
    files=[]
    for ext in ('png','pdf','svg'):
        path=directory/f'latency-throughput-{endpoint}.{ext}';fig.savefig(path,dpi=190,bbox_inches='tight');files.append(str(path))
    plt.close(fig)
    return {'files':files,'endpoint':endpoint,'scale':'log' if logarithmic else 'linear','rate_points':len({r['rate'] for r in rows}),
            'scope':'one-load measured points; no interpolated capacity curve or repetition error bars'}
