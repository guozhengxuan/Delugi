"""Latency/throughput figures from LogParser summaries, with visible censoring."""
from __future__ import annotations
import json
import math
import os
from pathlib import Path

LABELS={'delugi':'Delugi','raptr':'Raptr'}
COLORS={'delugi':'#087f8c','raptr':'#7651a8'}
CASES={'healthy':'Healthy','silent-first-leader':'Silent first leader','missing-data':'Missing data'}


def render(summary, directory, *, endpoint='end_to_end'):
    if endpoint not in ('end_to_end','admission'):raise ValueError('unknown latency endpoint')
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
    ymax=max(observed or [1])*1.35
    for ax,case in zip(axes[0],cases):
        selected=[r for r in rows if r['case']==case]
        for i,r in enumerate(selected):
            p=r['protocol'];color=COLORS.get(p,plt.get_cmap('tab10')(i));marker='o' if p=='delugi' else 's'
            x=r.get('goodput_tps');value=r.get(endpoint+'_p50_ms');status=r.get(endpoint+'_p50_status')
            upper=r.get(endpoint+'_p95_ms');label=LABELS.get(p,p)
            if x is None or status=='empty' or not r.get('completed'):
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
                    ax.vlines(x,y,max(y,bound/1000),color=color,linewidth=1.2,linestyle='--')
                    ax.annotate('',xy=(x,max(y,bound/1000)+ymax*.06),xytext=(x,max(y,bound/1000)),arrowprops={'arrowstyle':'->','color':color})
            if censored:ax.annotate('',xy=(x,y+ymax*.06),xytext=(x,y),arrowprops={'arrowstyle':'->','color':color})
            offset=(-12,13) if p=='delugi' else (-12,-24)
            text=f"{label}\n{x:.1f} tx/s, {'≥' if censored else ''}{y:.3f} s"
            ax.annotate(text,(x,y),xytext=offset,textcoords='offset points',ha='right',fontsize=9,color=color)
        ax.set(title=CASES.get(case,case),xlabel='Measured useful throughput (tx/s)')
        ax.set_xlim(0,max(offered,max((r.get('goodput_tps') or 0 for r in selected),default=0))*1.18 or 1)
        ax.set_ylim(0,ymax);ax.grid(alpha=.18);ax.spines[['top','right']].set_visible(False)
    start='Intended arrival' if endpoint=='end_to_end' else 'Admission'
    axes[0,0].set_ylabel(start+' → origin-local verified output (s)')
    handles=[Line2D([0],[0],marker='o' if p=='delugi' else 's',linestyle='none',color=COLORS.get(p,'gray'),label=LABELS.get(p,p),markersize=7)
             for p in dict.fromkeys(r['protocol'] for r in rows)]
    fig.legend(handles=handles,loc='upper center',bbox_to_anchor=(.5,.91),ncol=len(handles),frameon=False)
    fig.suptitle('Four-region latency–throughput comparison',fontsize=15,fontweight='bold',y=.99)
    fig.text(.5,.035,f"One input rate: {offered:g} tx/s · {summary['measurement_duration_s']} s per run · {summary['drain_s']} s drain\n"
        'Points: median; whiskers: p95; arrows: censored lower bounds. Each case uses one run.',ha='center',fontsize=9,color='#444444')
    fig.tight_layout(rect=(0,.12,1,.87))
    files=[]
    for ext in ('png','pdf','svg'):
        path=directory/f'latency-throughput-{endpoint}.{ext}';fig.savefig(path,dpi=190,bbox_inches='tight');files.append(str(path))
    plt.close(fig)
    return {'files':files,'endpoint':endpoint,'rate_points':len({r['rate'] for r in rows}),
            'scope':'one-load measured points; no interpolated capacity curve or repetition error bars'}
