"""Scientific figures from retained experiment rows, with trial-level intervals."""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from experiment import durable_text
from vendorchain.stats import summarize
from verify_campaign import digest, verify


def captions(report, rows, root):
    """Missing deployment/input provenance stays unspecified."""
    root = Path(root).resolve()
    measured = [r for r in rows if not r.get('warmup')]
    good = [r for r in measured if r.get('successful') is True]
    evidence = sorted({r.get('evidence', 'unknown') for r in measured})
    consensus = 'consensus' in report.get('kind', '') or any(r.get('consensus') for r in measured)
    if consensus:
        title = 'Consensus deployment trials'
    elif good and all(r.get('evidence') in ('local-non-consensus', 'offchain-stage-ablation') for r in good):
        title = 'Local and off-chain pipeline trials'
    else:
        title = 'Research campaign trials'
    retained = []
    for row in good:
        path = root/str(row['variant'])/str(row['trial'])/'input.png'
        present = path.resolve().is_relative_to(root) and path.is_file()
        if present and row.get('inputSHA256'):
            present = digest(path) == row['inputSHA256']
        retained.append(present)
    kinds = {row.get('inputKind', 'unspecified') for row in good}
    if kinds == {'generated-synthetic-png'}:
        inputs = 'generated synthetic PNG inputs'
    elif kinds == {'external-file'}:
        inputs = 'external-file inputs; review provenance unspecified'
    elif kinds and kinds <= {'generated-synthetic-png', 'external-file'}:
        inputs = 'mixed synthetic PNG/external-file inputs; external review provenance unspecified'
    elif retained and all(retained):
        inputs = 'retained PNG inputs; generation/review provenance unspecified'
    elif any(retained):
        inputs = 'mixed input retention; input provenance unspecified'
    else:
        inputs = 'input provenance unspecified'
    stores = sorted({row.get('operationalStore', 'unspecified') for row in good})
    store_labels = {'Store': 'SQLite (Store)', 'PostgresStore': 'PostgreSQL (PostgresStore)'}
    storage = ('Operational store: ' + ', '.join(store_labels.get(store, store) for store in stores) + '.'
               if stores and stores != ['unspecified'] else 'Operational store not recorded in trial metadata.')
    protocol = report.get('protocol', {})
    ordering = ('randomized trial blocks' if protocol.get('randomizationSeed') is not None
                else protocol.get('order', 'execution order unspecified'))
    note = ('Evidence: ' + ', '.join(evidence or ['unavailable']) + '; ' + inputs + '.\n'
            + ordering + '; ' + str(len(measured)-len(good)) + '/' + str(len(measured))
            + ' measured trials failed. ' + storage)
    return title + '; means and 95% Student-t intervals', note, consensus


def plot(directory):
    root = Path(directory)
    manifest_path = root/'sha256-manifest.json'
    # Never refresh hashes of an already stale/tampered campaign.
    if manifest_path.exists():
        verify(root)
    report = json.loads((root/'summary.json').read_text())
    groups = deepcopy(report['variants'])
    rows = [json.loads(line) for line in (root/'trials.jsonl').read_text().splitlines() if line.strip()]
    title, note, consensus = captions(report, rows, root)
    if not manifest_path.exists():
        note += '\nCampaign integrity unverified: no SHA-256 manifest supplied.'
    preferred = ['baseline','gate','encryption','identity','provenance','policy','full',
                 'full_without_client_revalidation','full_crypto_x10']
    names = [n for n in preferred if n in groups and groups[n]['metrics']]
    names += [n for n, group in groups.items() if group['metrics'] and n not in names]
    labels = {'full_without_client_revalidation': 'Full: no client recheck',
              'full_crypto_x10': 'Full: crypto x10', 'localkeys': 'Local keys', 'vaultkeys': 'Vault keys'}
    for name in names:
        good = [r for r in rows if r['variant'] == name and not r['warmup'] and r['successful']]
        if good and all('parent_cpu_seconds' in r['metrics'] and 'child_cpu_seconds' in r['metrics'] for r in good):
            groups[name]['metrics']['total_cpu_seconds'] = summarize([
                r['metrics']['parent_cpu_seconds']+r['metrics']['child_cpu_seconds'] for r in good])
        if good and all('parent_peak_rss_kib' in r['metrics'] and 'largest_child_peak_rss_kib' in r['metrics'] for r in good):
            groups[name]['metrics']['largest_individual_rss_kib'] = summarize([
                max(r['metrics']['parent_peak_rss_kib'], r['metrics']['largest_child_peak_rss_kib']) for r in good])

    def missing(axis):
        axis.text(.5, .5, 'No successful measurements available', transform=axis.transAxes, ha='center')

    def interval(axis, index, value):
        if value['ci95']:
            axis.errorbar(index, value['mean'], yerr=[[value['mean']-value['ci95'][0]],
                          [value['ci95'][1]-value['mean']]], fmt='none', ecolor='#292929', capsize=3)

    def panel(axis, metric, heading, ylabel):
        subset = [n for n in names if metric in groups[n]['metrics']]
        values = [groups[n]['metrics'][metric] for n in subset]
        axis.bar(range(len(subset)), [v['mean'] for v in values], color='#668c85')
        for index, value in enumerate(values):
            interval(axis, index, value)
        axis.set_xticks(range(len(subset)), [labels.get(n, n.capitalize()) for n in subset], rotation=35, ha='right')
        axis.set_title(heading); axis.set_ylabel(ylabel)
        if not values:
            missing(axis)

    if consensus:
        fig, axes = plt.subplots(1, 2, figsize=(13, 7))
        for axis, suffix, heading, ylabel in zip(axes, ['latency_ms', 'committed_tps'],
                ['Committed-request latency by offered concurrency', 'Committed throughput by offered concurrency'], ['ms', 'commits/second']):
            plotted = False
            for name in names:
                metrics = groups[name]['metrics']
                levels = sorted(int(m.group(1)) for metric in metrics if (m := re.fullmatch(r'c(\d+)_'+suffix, metric)))
                if not levels:
                    continue
                values = [metrics[f'c{level}_{suffix}'] for level in levels]
                axis.plot(levels, [v['mean'] for v in values], marker='o', label=labels.get(name, name))
                for level, value in zip(levels, values):
                    interval(axis, level, value)
                plotted = True
            if plotted:
                axis.legend()
            else:
                missing(axis)
            axis.set_title(heading); axis.set_xlabel('Offered concurrency'); axis.set_ylabel(ylabel)
    else:
        fig, axes = plt.subplots(2, 2, figsize=(13, 10))
        for axis, metric, heading, label in zip(axes.flat,
                ['elapsed_ms','total_cpu_seconds','largest_individual_rss_kib','disk_growth_bytes'],
                ['Elapsed time','Parent + child CPU time','Largest individual process RSS','Retained disk growth'],
                ['ms','CPU seconds','KiB','bytes']):
            panel(axis, metric, heading, label)
        note += '\nRSS is an individual-process peak, not aggregate memory.'
    fig.suptitle(title); fig.text(.5, .01, note, ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .13, 1, .95)); fig.savefig(root/'resources.png', dpi=180); plt.close(fig)
    generated = ['resources.png']
    if 'full' in groups:
        keys = ['gate_ms','encrypt_ms','persist_ms','decrypt_ms','worker_ms','identity_attestation_ms',
                'syft_ms','cosign_sign_ms','cosign_verify_ms','opa_ms','attest_ms','outbox_prepare_ms',
                'commit_revalidate_ms','ledger_commit_ms','db_finalize_ms']
        metrics = groups['full']['metrics']; keys = [k for k in keys if k in metrics]
        if keys:
            fig, axis = plt.subplots(figsize=(10, 7)); axis.barh(keys, [metrics[k]['mean'] for k in keys], color='#7696aa')
            axis.set_xlabel('Mean stage duration (ms)'); axis.set_title('Full pipeline stages; OCR is inside worker_ms')
            fig.tight_layout(); fig.savefig(root/'stages.png', dpi=180); plt.close(fig); generated.append('stages.png')
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        manifest.update({filename: digest(root/filename) for filename in generated})
        durable_text(manifest_path, json.dumps(manifest, indent=2)+'\n')
    return {'figures': generated, 'title': title, 'note': note}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('directory'); args = parser.parse_args()
    print(json.dumps(plot(args.directory), indent=2))
