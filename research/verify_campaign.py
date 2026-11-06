"""Verify retained experiment evidence before using its exports in a paper.

This is an integrity/count check, not certification of experiment validity.
It never repairs or overwrites measurements. Use recover_journal.py separately.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile

from experiment import export, paired_differences, summarize_rows
from recover_journal import _same, _validate_record


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def verify(directory):
    root = Path(directory).resolve(strict=True)
    manifest = json.loads((root / 'sha256-manifest.json').read_text())
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError('nonempty SHA-256 manifest required')
    for name, expected in manifest.items():
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name
                or relative.as_posix() != name or name == 'sha256-manifest.json'):
            raise ValueError('unsafe manifest path: ' + name)
        path = root / name
        if (not path.resolve().is_relative_to(root) or path.is_symlink()
                or any(parent.is_symlink() for parent in path.parents if parent != root)
                or not path.is_file()):
            raise ValueError('missing or unsafe evidence file: ' + name)
        if not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected) or digest(path) != expected:
            raise ValueError('evidence digest mismatch: ' + name)
    required = {'plan.json', 'metadata.json', 'summary.json', 'trials.jsonl', 'summary.csv', 'tables.tex'}
    if not required <= manifest.keys():
        raise ValueError('required experiment exports are absent from manifest')
    plan = json.loads((root / 'plan.json').read_text())
    meta = json.loads((root / 'metadata.json').read_text())
    report = json.loads((root / 'summary.json').read_text())
    if meta['planSHA256'] != digest(root / 'plan.json') or not _same(report['protocol'], meta):
        raise ValueError('plan or protocol provenance mismatch')
    if meta.get('sourceFilesSHA256') is not None:
        if ('source-files.sha256.json' not in manifest
                or meta['sourceFilesSHA256'] != digest(root / 'source-files.sha256.json')):
            raise ValueError('source file provenance mismatch')
    names = [task['name'] for task in plan['tasks']]
    if not names or len(names) != len(set(names)) or any(not re.fullmatch('[A-Za-z0-9_-]+', n) for n in names):
        raise ValueError('invalid declared variants')
    trials, warmups = meta['trials'], meta['warmups']
    if type(trials) is not int or trials < 1 or type(warmups) is not int or warmups < 0:
        raise ValueError('invalid trial counts')
    expected = {(name, i) for name in names for i in range(-warmups, trials)}
    record_version = meta.get('trialRecordVersion', 0)
    if type(record_version) is not int or record_version not in (0, 1):
        raise ValueError('unsupported trial record version')
    for filename in ('record.json', 'measurement.json'):
        for path in root.glob('*/*/' + filename):
            relative = path.relative_to(root)
            name, index, _ = relative.parts
            if (not re.fullmatch(r'-?(0|[1-9][0-9]*)', index)
                    or (name, int(index)) not in expected or relative.as_posix() not in manifest):
                raise ValueError('unexpected or unpinned trial evidence: ' + relative.as_posix())
    rows = [json.loads(line) for line in (root / 'trials.jsonl').read_text().splitlines() if line.strip()]
    seen = set()
    for row in rows:
        key = (row.get('variant'), row.get('trial'))
        if key not in expected or key in seen:
            raise ValueError('unexpected or duplicated trial slot')
        seen.add(key)
        _validate_record(row, key)
        if row['successful'] and row.get('exitCode') not in (None, 0):
            raise ValueError('successful trial has nonzero process exit code')
        relative = f'{key[0]}/{key[1]}/record.json'
        measurement = f'{key[0]}/{key[1]}/measurement.json'
        if relative in manifest:
            actual = json.loads((root / relative).read_text())
            retained = {k: v for k, v in row.items() if k not in ('journalRecovered', 'recoverySourceSHA256')}
            if not _same(actual, retained):
                raise ValueError('durable trial record disagrees with journal')
        elif record_version == 1:
            raise ValueError('trial lacks a manifest-pinned durable record')
        elif measurement not in manifest:
            raise ValueError('legacy trial lacks a pinned worker measurement')
        if row['successful']:
            if measurement not in manifest:
                raise ValueError('successful trial lacks pinned measurement')
            actual = json.loads((root / measurement).read_text())
            parent_fields = {'variant', 'trial', 'warmup', 'workerPID', 'startedNs', 'elapsedProcessMs',
                             'exitCode', 'journalRecovered', 'recoverySourceSHA256'}
            if actual.get('successful') is not True or not _same(
                    {k: v for k, v in actual.items() if k not in parent_fields},
                    {k: v for k, v in row.items() if k not in parent_fields}):
                raise ValueError('worker measurement disagrees with journal')
        elif relative not in manifest:
            actual = json.loads((root / measurement).read_text())
            if actual.get('successful') is not False or not _same(actual.get('metrics'), row['metrics']):
                raise ValueError('legacy failed measurement disagrees with journal')
        if row.get('journalRecovered'):
            source = relative if relative in manifest else measurement
            if source not in manifest or manifest[source] != row.get('recoverySourceSHA256'):
                raise ValueError('recovered trial source is not pinned')
    if seen != expected:
        raise ValueError('incomplete journal; recover actual records before exporting')
    variants = summarize_rows(rows, trials, warmups)
    pairs = paired_differences(rows, plan.get('comparisons', []), trials)
    if not _same(variants, report['variants']) or not _same(pairs, report.get('pairedComparisons', {})):
        raise ValueError('summary does not reproduce from retained trials')
    with tempfile.TemporaryDirectory(prefix='vendorchain-verify-') as temporary:
        exports = Path(temporary)
        export(exports, report)
        filenames = ['summary.csv', 'tables.tex']
        paired_exports = {'paired-comparisons.csv', 'paired-comparisons.tex'}
        if paired_exports & manifest.keys():
            if not paired_exports <= manifest.keys():
                raise ValueError('incomplete paired-comparison exports')
            filenames += sorted(paired_exports)
        for filename in filenames:
            if (exports / filename).read_bytes() != (root / filename).read_bytes():
                raise ValueError('statistical export disagrees with summary: ' + filename)
    if report.get('qualifiedForPaper') is not False:
        raise ValueError('automatic paper qualification is unsupported')
    return {'integrityVerified': True, 'filesVerified': len(manifest),
            'sourceCommit': meta.get('sourceCommit'), 'sourceDirty': meta.get('sourceDirty'),
            'kind': report['kind'], 'measuredTrials': sum(not r['warmup'] for r in rows),
            'discardedWarmups': sum(r['warmup'] for r in rows),
            'failedMeasuredTrials': sum(not r['warmup'] and not r['successful'] for r in rows),
            'evidenceKinds': sorted({r.get('evidence', 'unknown') for r in rows}),
            'countProtocolMet': all(g['countProtocolMet'] for g in variants.values()),
            'qualifiedForPaper': False,
            'limitations': 'Hashes and recomputed statistics establish consistency, not authenticity, workload representativeness, host isolation or production validity.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.directory), indent=2, allow_nan=False))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(1, 'Campaign verification failed: ' + str(exc) + '\n')
