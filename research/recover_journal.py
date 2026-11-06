"""Recover missing journal lines only from retained actual trial measurements.

No measurements, process IDs, or process timings are imputed. Original bytes and
every recovered slot are retained. Statistical exports must reproduce the prior
complete in-memory summary or recovery stops with an error.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import random
from experiment import durable_text, export, summarize_rows, paired_differences


def recover(directory):
    root=Path(directory);metadata=json.loads((root/'metadata.json').read_text());plan=json.loads((root/'plan.json').read_text())
    original=(root/'trials.jsonl').read_bytes();observed=[json.loads(line) for line in original.decode().splitlines() if line.strip()]
    lookup={(r['variant'],r['trial']):r for r in observed}
    if len(lookup)!=len(observed):raise ValueError('duplicate journal slot')
    rng=random.Random(metadata['randomizationSeed']);rows=[];recovered=[]
    for trial in range(-metadata['warmups'],metadata['trials']):
        tasks=plan['tasks'].copy();rng.shuffle(tasks)
        for task in tasks:
            key=(task['name'],trial);path=root/task['name']/str(trial)
            raw=(path/'measurement.json').read_bytes();measurement=json.loads(raw)
            if key in lookup:
                row=lookup[key]
                if row['metrics']!=measurement['metrics'] or row['successful']!=measurement['successful']:
                    raise ValueError('journal and measurement disagree')
            else:
                source=path/'measurement.json'
                if (path/'record.json').exists():
                    source=path/'record.json';raw=source.read_bytes();row=json.loads(raw)
                    if row['metrics']!=measurement['metrics'] or row['variant']!=task['name'] or row['trial']!=trial:
                        raise ValueError('durable record disagrees with actual measurement')
                else:
                    row={**measurement,'variant':task['name'],'trial':trial,'warmup':trial<0,
                         'workerPID':None,'startedNs':None,'elapsedProcessMs':None}
                row.update(journalRecovered=True,recoverySourceSHA256=hashlib.sha256(raw).hexdigest())
                recovered.append({'variant':task['name'],'trial':trial,'source':str(source.relative_to(root)),
                                  'sourceSHA256':hashlib.sha256(raw).hexdigest()})
            rows.append(row)
    report=json.loads((root/'summary.json').read_text())
    variants=summarize_rows(rows,metadata['trials'],metadata['warmups'])
    for name,cohort in variants.items():
        for metric,summary in cohort['metrics'].items():
            prior=report['variants'][name]['metrics'][metric]
            for field in ('n','mean','stddev','median','p50','p95','p99','ci95'):
                a,b=summary[field],prior[field]
                equal=(a==b) if a is None or b is None else (all(math.isclose(x,y,rel_tol=1e-12,abs_tol=1e-12) for x,y in zip(a,b)) if isinstance(a,list) else math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-12))
                if not equal:raise ValueError('recovered measurements do not reproduce complete original statistics')
    if not recovered:return {'recovered':0}
    with (root/'trials-original.jsonl').open('xb') as stream:stream.write(original)
    if (root/'sha256-manifest.json').exists():(root/'sha256-manifest.json').rename(root/'sha256-manifest-original.json')
    durable_text(root/'trials.jsonl',''.join(json.dumps(row,allow_nan=False)+'\n' for row in rows))
    report['variants']=variants;report['pairedComparisons']=paired_differences(rows,plan.get('comparisons',[]),metadata['trials'])
    report['journalRecovery']={'recoveredLines':len(recovered),'measurementsImputed':False,
                              'missingProcessMetadataLeftNull':True,'originalStatisticsReproduced':True}
    durable_text(root/'summary.json',json.dumps(report,indent=2,allow_nan=False));export(root,report)
    record={'originalJournalSHA256':hashlib.sha256(original).hexdigest(),'recovered':recovered,
            'note':'Actual individual measurement files only. Missing parent process metadata stays null.'}
    durable_text(root/'journal-recovery.json',json.dumps(record,indent=2))
    manifest={p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}
    durable_text(root/'sha256-manifest.json',json.dumps(manifest,indent=2))
    return {'recovered':len(recovered),'statisticsReproduced':True,'measurementsImputed':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory');a=p.parse_args();print(json.dumps(recover(a.directory)))
