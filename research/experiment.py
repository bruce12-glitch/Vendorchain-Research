"""Sequential fresh-process trials, raw logs, Student-t intervals and exports."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import random
import subprocess
import sys
import time
from vendorchain.stats import summarize


def append(path, value):
    with path.open('a') as stream:
        stream.write(json.dumps(value,allow_nan=False)+'\n');stream.flush();os.fsync(stream.fileno())


def summarize_rows(rows, trials, warmups):
    variants = {}
    for name in sorted({r['variant'] for r in rows}):
        cohort = [r for r in rows if r['variant']==name]
        measured = [r for r in cohort if not r['warmup']]
        good = [r for r in measured if r['successful']]
        names = set().union(*(r.get('metrics',{}) for r in good)) if good else set()
        metrics = {key:summarize([r['metrics'][key] for r in good if key in r['metrics']]) for key in sorted(names)}
        variants[name] = {'measuredTrials':len(measured),'successfulTrials':len(good),
            'discardedWarmups':sum(r['warmup'] for r in cohort),'failedTrials':len(measured)-len(good),
            'countProtocolMet':len(measured)==trials and len(good)==trials and trials>=50
                 and warmups>=5 and sum(r['warmup'] for r in cohort)==warmups and all(s['n']==trials for s in metrics.values()),
            'metrics':metrics,'evidenceKinds':sorted({r.get('evidence','unknown') for r in good})}
    return variants


def paired_differences(rows, comparisons, expected):
    results={}
    for spec in comparisons:
        control={r['trial']:r for r in rows if r['variant']==spec['control'] and not r['warmup']}
        treatment={r['trial']:r for r in rows if r['variant']==spec['treatment'] and not r['warmup']}
        differences=[];missing=[]
        for trial in range(expected):
            a,b=control.get(trial),treatment.get(trial);metric=spec['metric']
            if not a or not b or not a['successful'] or not b['successful'] or metric not in a['metrics'] or metric not in b['metrics']:
                missing.append(trial);continue
            differences.append(b['metrics'][metric]-a['metrics'][metric])
        summary=summarize(differences) if differences else None
        if summary:
            summary['unit']='paired trial-block difference: treatment minus control'
            summary['quantileMethod']='linear interpolation over paired differences (R7)'
        results[spec['name']]={**spec,'difference':summary,'missingOrFailedPairs':missing,
                             'complete':not missing and len(differences)==expected,
                             'note':'Unadjusted per-comparison Student-t interval; local process pairing does not itself establish host isolation.'}
    return results


def export(out, report):
    with (out/'summary.csv').open('w',newline='') as stream:
        writer=csv.writer(stream);writer.writerow(['variant','metric','n','mean','stddev','median','p50','p95','p99','ci95_low','ci95_high'])
        for name,group in report['variants'].items():
            for metric,s in group['metrics'].items():
                writer.writerow([name,metric,s['n'],s['mean'],s['stddev'],s['median'],s['p50'],s['p95'],s['p99'],*(s['ci95'] or [None,None])])
    def tex(s):
        return str(s).replace('_',r'\_').replace('%',r'\%').replace('&',r'\&').replace('#',r'\#')
    lines=[r'\begin{tabular}{llrrrr}',r'Variant & Metric & $N$ & Mean & SD & 95\% CI \\',r'\hline']
    for name,group in report['variants'].items():
        for metric,s in group['metrics'].items():
            ci='--' if s['ci95'] is None else f"[{s['ci95'][0]:.4f}, {s['ci95'][1]:.4f}]"
            sd='--' if s['stddev'] is None else f"{s['stddev']:.4f}"
            lines.append(f"{tex(name)} & {tex(metric)} & {s['n']} & {s['mean']:.4f} & {sd} & {ci} "+r'\\')
    (out/'tables.tex').write_text('\n'.join(lines+[r'\end{tabular}'])+'\n')


def campaign(plan_path, output, *, trials=50, warmups=5, smoke=False, isolated_host_attested=False, seed=20261105):
    if type(trials) is not int or type(warmups) is not int or trials<1 or warmups<0 or (not smoke and (trials<50 or warmups<5)):
        raise ValueError('publication protocol requires >=50 trials and >=5 warmups; use --smoke for development')
    plan_path=Path(plan_path).resolve();plan=json.loads(plan_path.read_text())
    tasks=plan['tasks'];names=[t['name'] for t in tasks]
    if not tasks or len(set(names))!=len(names) or any(not re.fullmatch(r'[A-Za-z0-9_-]+',n) for n in names):raise ValueError('unique safe task names required')
    comparisons=plan.get('comparisons',[])
    if len({c['name'] for c in comparisons}) != len(comparisons):raise ValueError('unique comparison names required')
    for c in comparisons:
        if c['control'] not in names or c['treatment'] not in names or c['control']==c['treatment'] or not isinstance(c['metric'],str):
            raise ValueError('comparison must reference two declared tasks and a metric')
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    (out/'plan.json').write_bytes(plan_path.read_bytes())
    commit=subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip()
    metadata={'sourceCommit':commit,'platform':platform.platform(),'python':sys.version,'cpuCount':os.cpu_count(),
              'planSHA256':hashlib.sha256(plan_path.read_bytes()).hexdigest(),'startedNs':time.time_ns(),
              'freshProcessPerTrial':True,'execution':'sequential','isolatedHostAttestedByOperator':isolated_host_attested,
              'noCompetingLoadIndependentlyVerified':False,'smoke':smoke,'trials':trials,'warmups':warmups}
    metadata.update(order='randomized variants within sequential trial blocks',randomizationSeed=seed)
    metadata['sourceDirty']=bool(subprocess.run(['git','status','--porcelain'],capture_output=True,text=True).stdout.strip())
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
    rows=[];rng=random.Random(seed);schedule=[]
    for index in range(-warmups,trials):
        order=tasks.copy();rng.shuffle(order)
        schedule.extend((task,index) for task in order)
    for task,index in schedule:
        command=task['command']
        if not isinstance(command,list) or not command or any(not isinstance(x,str) for x in command):raise ValueError('task command must be an argv array')
        directory=out/task['name']/str(index);directory.mkdir(parents=True)
        env={**os.environ,'VENDORCHAIN_TRIAL_DIR':str(directory),'VENDORCHAIN_TRIAL_INDEX':str(index)}
        started=time.perf_counter_ns()
        started_ns=time.time_ns();proc=None
        try:
            with (directory/'stdout.log').open('wb') as stdout,(directory/'stderr.log').open('wb') as stderr:
                proc=subprocess.Popen(command,stdout=stdout,stderr=stderr,env=env,start_new_session=True)
                try:code=proc.wait(timeout=task.get('timeoutSeconds',600))
                except subprocess.TimeoutExpired:
                    import signal
                    os.killpg(proc.pid,signal.SIGKILL);proc.wait();raise
            if code:raise ValueError('trial process exited '+str(code))
            data=json.loads((directory/'measurement.json').read_text());metrics=data['metrics']
            if not metrics or any(type(v) not in (int,float) or not math.isfinite(v) for v in metrics.values()):raise ValueError('trial requires finite metrics')
            row={**data,'successful':data.get('successful') is True}
        except Exception as exc:
            row={'successful':False,'metrics':{},'evidence':'failed-trial','error':type(exc).__name__}
        row.update(variant=task['name'],trial=index,warmup=index<0,workerPID=None if proc is None else proc.pid,
                   startedNs=started_ns,elapsedProcessMs=(time.perf_counter_ns()-started)/1e6)
        rows.append(row);append(out/'trials.jsonl',row)
        print(json.dumps({'variant':task['name'],'trial':index,'successful':row['successful']}),flush=True)
    report={'kind':plan.get('kind','command-campaign'),'variants':summarize_rows(rows,trials,warmups),
            'pairedComparisons':paired_differences(rows,plan.get('comparisons',[]),trials),
            'protocol':metadata,'qualifiedForPaper':False,
            'qualificationNote':'Review workload, failures, isolation, independence and consensus evidence. Counts alone never confer publication qualification.'}
    (out/'summary.json').write_text(json.dumps(report,indent=2,allow_nan=False));export(out,report)
    manifest={p.relative_to(out).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'sha256-manifest.json').write_text(json.dumps(manifest,indent=2))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--plan',required=True);p.add_argument('--output',required=True)
    p.add_argument('--trials',type=int,default=50);p.add_argument('--warmups',type=int,default=5)
    p.add_argument('--smoke',action='store_true');p.add_argument('--isolated-host-attested',action='store_true')
    p.add_argument('--seed',type=int,default=20261105)
    a=p.parse_args();campaign(a.plan,a.output,trials=a.trials,warmups=a.warmups,smoke=a.smoke,isolated_host_attested=a.isolated_host_attested,seed=a.seed)
