"""Recover missing journal lines from retained actual trial evidence.

No measurements, process IDs, or process timings are imputed. Original bytes and
every recovered slot are retained. Statistical exports must reproduce the prior
complete in-memory summary or recovery stops with an error. Failed processes can
be recovered from their durable records even when they produced no measurement.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
from experiment import durable_text, export, summarize_rows, paired_differences


def _same(actual, expected):
    """Compare the entire retained report, allowing only roundoff in numbers."""
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(_same(actual[k], expected[k]) for k in actual)
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(_same(a, b) for a, b in zip(actual, expected))
    if type(actual) in (int, float) and type(expected) in (int, float):
        return math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)
    return type(actual) is type(expected) and actual == expected


def _validate_record(row, key):
    if (row.get('variant'), row.get('trial')) != key or type(row.get('trial')) is not int:
        raise ValueError('record has an unexpected journal slot')
    if row.get('warmup') is not (key[1] < 0) or type(row.get('successful')) is not bool:
        raise ValueError('record has invalid warmup or success metadata')
    metrics=row.get('metrics')
    if not isinstance(metrics,dict) or (row['successful'] and not metrics) or any(
            type(value) not in (int,float) or not math.isfinite(value) for value in metrics.values()):
        raise ValueError('record requires finite measurements')


def recover(directory):
    root=Path(directory);metadata=json.loads((root/'metadata.json').read_text());plan=json.loads((root/'plan.json').read_text())
    names=[task['name'] for task in plan['tasks']]
    if not names or len(set(names)) != len(names):raise ValueError('unique task names required')
    expected={(name,trial) for name in names for trial in range(-metadata['warmups'],metadata['trials'])}
    original=(root/'trials.jsonl').read_bytes();observed=[]
    lines=original.splitlines(keepends=True)
    for index,line in enumerate(lines):
        if not line.strip():continue
        try:observed.append(json.loads(line))
        except (ValueError,UnicodeDecodeError):
            # An interrupted append may leave only its last line incomplete.
            if index != len(lines)-1 or line.endswith(b'\n'):raise ValueError('corrupt journal line') from None
    lookup={}
    for row in observed:
        key=(row.get('variant'),row.get('trial'))
        if key not in expected:raise ValueError('unexpected journal slot')
        if key in lookup:raise ValueError('duplicate journal slot')
        _validate_record(row,key);lookup[key]=row
    rng=random.Random(metadata['randomizationSeed']);rows=[];recovered=[]
    for trial in range(-metadata['warmups'],metadata['trials']):
        tasks=plan['tasks'].copy();rng.shuffle(tasks)
        for task in tasks:
            key=(task['name'],trial);path=root/task['name']/str(trial)
            record_path=path/'record.json';measurement_path=path/'measurement.json'
            record=json.loads(record_path.read_bytes()) if record_path.exists() else None
            if record is not None:_validate_record(record,key)
            row=lookup.get(key,record)
            source=record_path
            if row is None:
                # Older campaigns predate durable parent records. Only actual
                # worker measurements are recoverable; missing timings stay null.
                measurement=json.loads(measurement_path.read_bytes())
                row={**measurement,'variant':key[0],'trial':trial,'warmup':trial<0,
                     'workerPID':None,'startedNs':None,'elapsedProcessMs':None}
                source=measurement_path
            _validate_record(row,key)
            if record is not None and not _same(
                    {k:v for k,v in row.items() if k not in ('journalRecovered','recoverySourceSHA256')},record):
                raise ValueError('journal and durable record disagree')
            if row['successful']:
                measurement=json.loads(measurement_path.read_bytes())
                if row['metrics']!=measurement['metrics'] or measurement.get('successful') is not True:
                    raise ValueError('journal and measurement disagree')
            if key not in lookup:
                digest=hashlib.sha256(source.read_bytes()).hexdigest()
                row={**row,'journalRecovered':True,'recoverySourceSHA256':digest}
                recovered.append({'variant':key[0],'trial':trial,'source':str(source.relative_to(root)),
                                  'sourceSHA256':digest})
            rows.append(row)
    report=json.loads((root/'summary.json').read_text())
    variants=summarize_rows(rows,metadata['trials'],metadata['warmups'])
    pairs=paired_differences(rows,plan.get('comparisons',[]),metadata['trials'])
    if not _same(variants,report['variants']) or not _same(pairs,report.get('pairedComparisons',{})):
        raise ValueError('recovered measurements do not reproduce complete original statistics')
    if not recovered:return {'recovered':0}
    with (root/'trials-original.jsonl').open('xb') as stream:stream.write(original)
    if (root/'sha256-manifest.json').exists():(root/'sha256-manifest.json').rename(root/'sha256-manifest-original.json')
    durable_text(root/'trials.jsonl',''.join(json.dumps(row,allow_nan=False)+'\n' for row in rows))
    report['variants']=variants;report['pairedComparisons']=pairs
    report['journalRecovery']={'recoveredLines':len(recovered),'measurementsImputed':False,
                              'missingProcessMetadataLeftNull':True,'originalStatisticsReproduced':True}
    durable_text(root/'summary.json',json.dumps(report,indent=2,allow_nan=False));export(root,report)
    record={'originalJournalSHA256':hashlib.sha256(original).hexdigest(),'recovered':recovered,
            'note':'Actual individual trial evidence only. Missing parent process metadata stays null.'}
    durable_text(root/'journal-recovery.json',json.dumps(record,indent=2))
    manifest={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file() and p!=root/'sha256-manifest.json'}
    durable_text(root/'sha256-manifest.json',json.dumps(manifest,indent=2))
    return {'recovered':len(recovered),'statisticsReproduced':True,'measurementsImputed':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory');a=p.parse_args();print(json.dumps(recover(a.directory)))
