"""Generate standalone figures from measured local ablation trials."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from vendorchain.stats import summarize
parser=argparse.ArgumentParser();parser.add_argument('raw');parser.add_argument('--output',required=True)
args=parser.parse_args();root=Path(args.output);root.mkdir(parents=True,exist_ok=True)
rows=[json.loads(x) for x in Path(args.raw).read_text().splitlines() if x.strip()]
rows=[r for r in rows if not r['warmup']]
variants=['structural_inline','isolated_pipeline','hardened','hardened_crypto_x10']
labels=['Inline structural gate','Isolated ingress','Hardened local outbox','Hardened + 10 AES loops']
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':10,'axes.spines.top':False,'axes.spines.right':False})
fig,axes=plt.subplots(1,3,figsize=(14,4.8))
metrics=[('elapsed_ms','Workload latency (ms)',1),('peak_rss_kib','Largest process peak RSS (MiB)',1024),('disk_growth_bytes','Persistent state growth (KiB)',1024)]
for ax,(metric,title,scale) in zip(axes,metrics):
    stats=[summarize([r[metric]/scale for r in rows if r['variant']==v]) for v in variants]
    ax.bar(range(4),[r['mean'] for r in stats],color=['#859caa','#6f9183','#c6a15b','#b77b6b'],
           yerr=[r['ci95'][1]-r['mean'] for r in stats],capsize=3)
    ax.set_xticks(range(4),labels,rotation=30,ha='right');ax.set_ylabel(title)
    ax.grid(axis='y',alpha=.18);ax.set_axisbelow(True)
fig.suptitle('Local ablation: 50 fresh-process trials per variant; 95% t intervals\nReal Tesseract; Syft unavailable; SQLite test ledger; synthetic image',fontsize=12)
fig.tight_layout(rect=[0,0,1,.9]);fig.savefig(root/'resource-comparison.png',dpi=180);plt.close(fig)
fields=['gate_ms','encrypt_ms','persist_ms','decrypt_ms','worker_ms','syft_ms','attest_ms','outbox_prepare_ms','commit_revalidate_ms','ledger_commit_ms','db_finalize_ms','extra_crypto_ms']
fig,ax=plt.subplots(figsize=(10,5))
left=[0]*len(variants)
for field in fields:
    values=[sum((r['stages'].get(field) or 0) for r in rows if r['variant']==v)/sum(r['variant']==v for r in rows) for v in variants]
    if any(values):
        ax.barh(labels,values,left=left,label=field.replace('_ms',''))
        left=[a+b for a,b in zip(left,values)]
ax.set_xlabel('Mean milliseconds (non-overlapping stage wall times)')
ax.set_title('Stage isolation, local workload only; Syft not run')
ax.legend(bbox_to_anchor=(1.02,1),loc='upper left',fontsize=8)
fig.tight_layout();fig.savefig(root/'stage-times.png',dpi=180);plt.close(fig)
fig,ax=plt.subplots(figsize=(8,4.5))
parents=[sum(r['parent_cpu_seconds'] for r in rows if r['variant']==v)/sum(r['variant']==v for r in rows) for v in variants]
children=[sum(r['children_cpu_seconds'] for r in rows if r['variant']==v)/sum(r['variant']==v for r in rows) for v in variants]
ax.bar(labels,parents,label='Parent process');ax.bar(labels,children,bottom=parents,label='Child processes')
ax.set_ylabel('CPU seconds per trial (user + system)');ax.tick_params(axis='x',rotation=20);ax.legend()
ax.set_title('CPU consumption across pipeline variants')
fig.tight_layout();fig.savefig(root/'cpu-comparison.png',dpi=180);plt.close(fig)
# Paired by randomized trial block, not by individual upload.
pairs=[];hardening=[]
for trial in sorted({r['trial'] for r in rows}):
    block={r['variant']:r for r in rows if r['trial']==trial}
    if all(v in block for v in ('isolated_pipeline','hardened')):
        pairs.append(block['hardened']['elapsed_ms']-block['isolated_pipeline']['elapsed_ms'])
        stages=block['hardened']['stages']
        hardening.append(sum(stages[k] for k in ['attest_ms','outbox_prepare_ms','commit_revalidate_ms','db_finalize_ms']))
(root/'hardening-overhead.json').write_text(json.dumps({'kind':'local-non-consensus',
    'pairedHardenedMinusIsolatedMs':summarize(pairs),'instrumentedLocalHardeningStagesMs':summarize(hardening),
    'notes':'Includes local persistence and signature checks; external consensus and Syft overhead not measured.'},indent=2))
