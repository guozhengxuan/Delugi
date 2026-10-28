#!/usr/bin/env python3
"""Recreate the paired figure from the published, hash-bound reductions.

Requires matplotlib. Run from any directory; no cloud access or raw logs needed.
"""
from pathlib import Path
import json
import math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

OUT = Path(__file__).resolve().parent
cases = ['healthy', 'silent-first-leader']
reports = {c: json.loads((OUT / ('decomposition-' + c + '.json')).read_text()) for c in cases}
for report in reports.values():
    assert report['covered'] == report['completed'] == report['scheduled'] == 3000
    assert not report['excluded']
    assert math.isclose(sum(s['mean_ms'] for s in report['stages']), report['mean_admission_to_append_ms'], abs_tol=1e-9)

names = ['Healthy', 'Silent leader']
colors = ['#8cb9de', '#487fb2', '#83b83e', '#df9343', '#c779a7', '#e4d96a']
fig = plt.figure(figsize=(12.4, 6.4), layout='constrained')
grid = fig.add_gridspec(2, 1, height_ratios=[3.4, 1.55])
ax = fig.add_subplot(grid[0])
left = [0.0, 0.0]
for i, stage in enumerate(reports['healthy']['stages']):
    values = [reports[c]['stages'][i]['mean_ms'] for c in cases]
    ax.barh(names, values, left=left, height=.48, color=colors[i], label=stage['stage'])
    left = [a + b for a, b in zip(left, values)]
for i, c in enumerate(cases):
    report = reports[c]
    ax.annotate(f"{left[i]:,.1f} ms\n{report['covered']:,}/{report['scheduled']:,} requests covered",
                (left[i], i), xytext=(7, 0), textcoords='offset points', va='center', fontsize=10)
ax.invert_yaxis()
ax.set_xlim(0, max(left) * 1.34)
ax.set_xlabel('Mean admission → verified contiguous append (ms)')
ax.spines[['top', 'right']].set_visible(False)
ax.grid(axis='x', alpha=.2)
ax.set_axisbelow(True)
ax.legend(ncol=3, loc='upper left', bbox_to_anchor=(0, 1.25), frameon=False, fontsize=9)
fig.suptitle('Delugi latency decomposition · four regions · 30 seconds at 100 tx/s', fontsize=15)
table_ax = fig.add_subplot(grid[1])
table_ax.axis('off')
headers = ['Batch\nformation', 'Await execution\nproposal', 'Agreement', 'Contiguous\nprefix wait', 'Payload\nwait', 'Application\nappend', 'Total']
rows = [[f"{s['mean_ms']:,.2f}" for s in reports[c]['stages']] + [f"{reports[c]['mean_admission_to_append_ms']:,.2f}"] for c in cases]
table = table_ax.table(cellText=rows, rowLabels=names, colLabels=headers, cellLoc='center', loc='upper center', bbox=[.05, .4, .95, .6])
table.auto_set_font_size(False)
table.set_fontsize(9)
for (r, c), cell in table.get_celld().items():
    cell.set_edgecolor('#dce2e8')
    if r == 0:
        cell.set_facecolor('#edf2f7')
table_ax.text(0, .2, 'Table values are milliseconds. Each row uses one identical completed, fully instrumented request cohort.', fontsize=9)
table_ax.text(0, .02, 'All timestamps are origin-local. HISTORY3 work and timeout waits overlap these stages and are not added separately.', fontsize=9)
for suffix in ('png', 'pdf'):
    fig.savefig(OUT / ('latency-decomposition.' + suffix), dpi=180)
plt.close(fig)
