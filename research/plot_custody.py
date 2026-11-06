"""Derive a paired custody figure and raw contrast table from verified observations."""
import argparse
import csv
import json
from pathlib import Path
import statistics

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from verify_campaign import digest, verify


def lag_one(rows, arm):
    values = {r['trial']: r['metrics']['elapsed_ms'] for r in rows
              if r['variant'] == arm and not r['warmup'] and r['successful']}
    pairs = [(values[i], values[i+1]) for i in sorted(values) if i+1 in values]
    correlation = None
    if len(pairs) > 1:
        try:
            correlation = statistics.correlation([p[0] for p in pairs], [p[1] for p in pairs])
        except statistics.StatisticsError:
            pass
    return {'adjacentObservedPairs': len(pairs), 'correlation': correlation,
            'scope': 'Descriptive lag-one correlation; neither an independence test nor evidence of host isolation.'}


def render(directory, output):
    root = Path(directory).resolve(strict=True)
    verified = verify(root)
    report = json.loads((root/'summary.json').read_text())
    if report['kind'] != 'matched-local-vault-custody':
        raise ValueError('a verified matched custody campaign is required')
    out = Path(output).resolve()
    if out.is_relative_to(root):
        raise ValueError('use an output directory outside the source campaign')
    rows = [json.loads(line) for line in (root/'trials.jsonl').read_text().splitlines() if line.strip()]
    lookup = {(r['variant'], r['trial']): r for r in rows if not r['warmup']}
    pairs = []
    for trial in range(report['protocol']['trials']):
        local, vault = (lookup.get((arm, trial)) for arm in ('localkeys', 'vaultkeys'))
        if local and vault and local['successful'] and vault['successful']:
            a, b = local['metrics']['elapsed_ms'], vault['metrics']['elapsed_ms']
            pairs.append({'trial': trial, 'local_elapsed_ms': a, 'vault_elapsed_ms': b,
                          'vault_minus_local_ms': b-a})
    contrasts = report['pairedComparisons']
    primary = contrasts['vault_custody_cost']
    analysis = {'kind': 'derived-matched-custody-analysis', 'sourceCommit': verified['sourceCommit'],
                'sourceManifestSHA256': digest(root/'sha256-manifest.json'),
                'analysisScriptSHA256': digest(Path(__file__)),
                'primaryComparison': primary, 'allPredeclaredComparisons': contrasts,
                'lagOneDiagnostics': {
                    **{arm: lag_one(rows, arm) for arm in ('localkeys', 'vaultkeys')},
                    'pairedElapsedDifferences': lag_one([
                        {'variant':'pair','trial':p['trial'],'warmup':False,'successful':True,
                         'metrics':{'elapsed_ms':p['vault_minus_local_ms']}} for p in pairs], 'pair')},
                'qualifiedForPaper': False,
                'interpretation': 'Intervals are unadjusted, conditional on complete observed pairs and Student-t assumptions. An interval spanning zero does not establish equivalence. Stage contrasts measure full stage durations, not isolated RPC latency. Parent/child resource counters exclude the Vault server.'}
    out.mkdir(parents=True, exist_ok=False)
    (out/'analysis.json').write_text(json.dumps(analysis, indent=2, allow_nan=False)+'\n')
    with (out/'paired-observations.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=['trial', 'local_elapsed_ms', 'vault_elapsed_ms', 'vault_minus_local_ms'])
        writer.writeheader(); writer.writerows(pairs)
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8))
    ax = axes[0]
    if pairs:
        ax.plot([p['trial'] for p in pairs], [p['vault_minus_local_ms'] for p in pairs],
                '.-', linewidth=.7, markersize=4, color='#305b78', label='Observed pair')
    if primary['difference']:
        value = primary['difference']
        ax.axhline(value['mean'], color='#bc5a35', linestyle='--', label='Mean difference')
        if value['ci95']:
            ax.axhspan(*value['ci95'], alpha=.14, color='#bc5a35', label='95% CI for mean')
    ax.axhline(0, color='black', linewidth=.7)
    ax.set(xlabel='Measured trial block', ylabel='Vault − local elapsed time (ms)',
           title=f"Primary contrast: {len(pairs)} observed pairs")
    ax.legend(fontsize=8)
    labels = {'encrypt_ms': 'Encryption stage', 'decrypt_ms': 'Decryption stage',
              'identity_attestation_ms': 'Identity attestation', 'attest_ms': 'Decision attestation'}
    selected = [c for c in contrasts.values() if c['metric'] in labels and c['difference']]
    ax = axes[1]
    for i, contrast in enumerate(selected):
        value = contrast['difference']; interval = value['ci95']
        error = None if interval is None else [[value['mean']-interval[0]], [interval[1]-value['mean']]]
        ax.errorbar(value['mean'], i, xerr=error, fmt='o', color='#305b78', capsize=3)
    ax.set_yticks(range(len(selected)), [labels[c['metric']] for c in selected])
    ax.axvline(0, color='black', linewidth=.7)
    ax.set(xlabel='Vault − local stage duration (ms)', title='Predeclared secondary contrasts')
    fig.suptitle('Matched software custody on the local research pipeline')
    fig.text(.5, .015, 'Unadjusted Student-t intervals · SQLite/local ledger · common Cosign key\nHost isolation and statistical independence require separate validation.', ha='center', fontsize=8)
    fig.tight_layout(rect=(0, .09, 1, .94))
    for suffix in ('pdf', 'svg', 'png'):
        fig.savefig(out/('custody-contrasts.'+suffix), dpi=180)
    plt.close(fig)
    manifest = {p.name: digest(p) for p in sorted(out.iterdir()) if p.is_file()}
    (out/'sha256-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return analysis


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory'); parser.add_argument('--output', required=True)
    args = parser.parse_args()
    render(args.directory, args.output)
