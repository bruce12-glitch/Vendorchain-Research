"""Standalone scientific figures from experiment.py output, with trial CIs."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt


def plot(directory):
    root=Path(directory);report=json.loads((root/'summary.json').read_text());groups=report['variants']
    names=[name for name,g in groups.items() if g['metrics']]
    def panel(axis,metric,title,ylabel):
        subset=[n for n in names if metric in groups[n]['metrics']]
        values=[groups[n]['metrics'][metric] for n in subset]
        axis.bar(range(len(subset)),[s['mean'] for s in values],color='#668c85')
        for i,s in enumerate(values):
            if s['ci95']:axis.errorbar(i,s['mean'],yerr=[[s['mean']-s['ci95'][0]],[s['ci95'][1]-s['mean']]],fmt='none',ecolor='#292929',capsize=3)
        axis.set_xticks(range(len(subset)),subset,rotation=35,ha='right');axis.set_title(title);axis.set_ylabel(ylabel)
    fig,axes=plt.subplots(2,2,figsize=(13,9))
    for axis,metric,title,label in zip(axes.flat,['elapsed_ms','parent_cpu_seconds','parent_peak_rss_kib','disk_growth_bytes'],
                ['Elapsed time','Parent CPU time','Parent process high-water RSS','Retained disk growth'],['ms','CPU seconds','KiB','bytes']):panel(axis,metric,title,label)
    fig.suptitle('Cumulative pipeline variants; means and 95% Student-t intervals')
    fig.tight_layout();fig.savefig(root/'resources.png',dpi=180);plt.close(fig)
    if 'full' in groups:
        keys=['gate_ms','encrypt_ms','persist_ms','decrypt_ms','worker_ms','identity_attestation_ms','syft_ms','cosign_sign_ms','cosign_verify_ms','opa_ms','attest_ms','outbox_prepare_ms','commit_revalidate_ms','ledger_commit_ms','db_finalize_ms']
        metrics=groups['full']['metrics'];keys=[k for k in keys if k in metrics]
        fig,axis=plt.subplots(figsize=(10,7));axis.barh(keys,[metrics[k]['mean'] for k in keys],color='#7696aa')
        axis.set_xlabel('Mean stage duration (ms)');axis.set_title('Full pipeline: non-overlapping stages; OCR is inside worker_ms')
        fig.tight_layout();fig.savefig(root/'stages.png',dpi=180);plt.close(fig)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args();plot(a.directory)
