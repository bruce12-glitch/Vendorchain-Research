"""Standalone scientific figures from experiment.py output, with trial CIs."""
import argparse
import json
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from vendorchain.stats import summarize


def plot(directory):
    root=Path(directory);report=json.loads((root/'summary.json').read_text());groups=report['variants']
    preferred=['baseline','gate','encryption','identity','provenance','policy','full','full_without_client_revalidation','full_crypto_x10']
    names=[name for name in preferred if name in groups and groups[name]['metrics']]
    names += [name for name,g in groups.items() if g['metrics'] and name not in names]
    labels={'full_without_client_revalidation':'Full: no client recheck','full_crypto_x10':'Full: crypto x10',
            'localkeys':'Local keys','vaultkeys':'Vault keys'}
    rows=[json.loads(line) for line in (root/'trials.jsonl').read_text().splitlines() if line.strip()]
    for name in names:
        good=[r for r in rows if r['variant']==name and not r['warmup'] and r['successful']]
        if all('parent_cpu_seconds' in r['metrics'] and 'child_cpu_seconds' in r['metrics'] for r in good):
            groups[name]['metrics']['total_cpu_seconds']=summarize([r['metrics']['parent_cpu_seconds']+r['metrics']['child_cpu_seconds'] for r in good])
        if all('parent_peak_rss_kib' in r['metrics'] and 'largest_child_peak_rss_kib' in r['metrics'] for r in good):
            groups[name]['metrics']['largest_individual_rss_kib']=summarize([max(r['metrics']['parent_peak_rss_kib'],r['metrics']['largest_child_peak_rss_kib']) for r in good])
    def panel(axis,metric,title,ylabel):
        subset=[n for n in names if metric in groups[n]['metrics']]
        values=[groups[n]['metrics'][metric] for n in subset]
        axis.bar(range(len(subset)),[s['mean'] for s in values],color='#668c85')
        for i,s in enumerate(values):
            if s['ci95']:axis.errorbar(i,s['mean'],yerr=[[s['mean']-s['ci95'][0]],[s['ci95'][1]-s['mean']]],fmt='none',ecolor='#292929',capsize=3)
        axis.set_xticks(range(len(subset)),[labels.get(n,n.capitalize()) for n in subset],rotation=35,ha='right');axis.set_title(title);axis.set_ylabel(ylabel)
    fig,axes=plt.subplots(2,2,figsize=(13,9))
    for axis,metric,title,label in zip(axes.flat,['elapsed_ms','total_cpu_seconds','largest_individual_rss_kib','disk_growth_bytes'],
                ['Elapsed time','Parent + child CPU time','Largest individual process RSS','Retained disk growth'],['ms','CPU seconds','KiB','bytes']):panel(axis,metric,title,label)
    fig.suptitle('Local research pipeline; means and 95% Student-t intervals')
    ordering='randomized trial blocks' if report['protocol'].get('randomizationSeed') is not None else 'fixed variant cohorts'
    fig.text(.5,.01,'SQLite; synthetic PNG; '+ordering+'. RSS is an individual-process peak, not aggregate memory.',ha='center',fontsize=9)
    fig.tight_layout(rect=(0,.03,1,.97));fig.savefig(root/'resources.png',dpi=180);plt.close(fig)
    if 'full' in groups:
        keys=['gate_ms','encrypt_ms','persist_ms','decrypt_ms','worker_ms','identity_attestation_ms','syft_ms','cosign_sign_ms','cosign_verify_ms','opa_ms','attest_ms','outbox_prepare_ms','commit_revalidate_ms','ledger_commit_ms','db_finalize_ms']
        metrics=groups['full']['metrics'];keys=[k for k in keys if k in metrics]
        fig,axis=plt.subplots(figsize=(10,7));axis.barh(keys,[metrics[k]['mean'] for k in keys],color='#7696aa')
        axis.set_xlabel('Mean stage duration (ms)');axis.set_title('Full pipeline: non-overlapping stages; OCR is inside worker_ms')
        fig.tight_layout();fig.savefig(root/'stages.png',dpi=180);plt.close(fig)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args();plot(a.directory)
