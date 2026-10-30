"""Analyze one measured burst per independent GitHub/Fabric deployment."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from vendorchain.stats import summarize

parser=argparse.ArgumentParser();parser.add_argument('artifacts');parser.add_argument('--output',required=True);parser.add_argument('--expected',type=int,default=50)
args=parser.parse_args();source=Path(args.artifacts);out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
trials=[];problems=[];provenance=[];request_ids=set();tx_ids=set();stage_names=set()
combined=out/'raw-evidence.zip'
with zipfile.ZipFile(combined,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as retained:
    for archive_path in sorted(source.glob('*trial-*.zip')):
        match=re.search(r'trial-(\d+)\.zip$',archive_path.name)
        if not match:continue
        index=int(match.group(1));archive_hash=hashlib.sha256(archive_path.read_bytes()).hexdigest()
        with zipfile.ZipFile(archive_path) as archive:
            names=archive.namelist()
            # Retain all warm-ups, measured requests, public topology and logs.
            for name in names:
                relative=Path(name)
                if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe artifact path')
                retained.writestr('trial-'+str(index)+'/'+name,archive.read(name))
            prefix='.runtime/bft-healthy/'
            needed=prefix+'trials.jsonl'
            if needed not in names:
                problems.append({'trial':index,'reason':'no completed trial log'});continue
            rows=[json.loads(l) for l in archive.read(needed).decode().splitlines() if l.strip()]
            measured=[r for r in rows if not r['warmup']]
            if len(measured)!=1 or len(rows)!=2:
                problems.append({'trial':index,'reason':'expected one warm-up and one measurement'});continue
            row=measured[0]
            metadata=json.loads(archive.read('.runtime/network-metadata.json'))
            if row['concurrency']!=100 or metadata['consensus']!='BFT' or metadata['ordererCount']!=4:
                problems.append({'trial':index,'reason':'unexpected workload/topology'});continue
            data=json.loads(archive.read(prefix+'requests-c100-t0.json'))
            successful=[r for r in data['requests'] if r['success']]
            if (row['evidence']!='fabric-commit-confirmed' or len(data['requests'])!=100
                or len(successful)!=row['successful'] or 100-len(successful)!=row['failed']
                or any(r.get('evidence')!='fabric-commit-confirmed' for r in successful)):
                problems.append({'trial':index,'reason':'request/commit count or evidence mismatch'});continue
            if successful and abs(sum(r['latencyMs'] for r in successful)/len(successful)-row['trialMeanMs'])>1e-6:
                problems.append({'trial':index,'reason':'trial mean does not match raw requests'});continue
            for request in data['requests']:
                if request['recordID'] in request_ids:raise ValueError('duplicate request ID')
                request_ids.add(request['recordID'])
                if request['success']:
                    if request['transactionID'] in tx_ids:raise ValueError('duplicate committed transaction')
                    tx_ids.add(request['transactionID'])
            stages={}
            if successful:
                keys=set.intersection(*(set(r['stages']) for r in successful))
                for key in keys:
                    if all(isinstance(r['stages'][key],(int,float)) for r in successful):
                        stages[key]=sum(r['stages'][key] for r in successful)/len(successful)
                        stage_names.add(key)
            crash=json.loads(archive.read('.runtime/bft-one-crash/trials.jsonl').decode().strip()) if '.runtime/bft-one-crash/trials.jsonl' in names else None
            entry={**row,'deploymentTrial':index,'stages':stages,'metadata':metadata,
                   'oneCrashPassed':bool(crash and crash['successful']==3 and crash['failed']==0 and crash['evidence']=='fabric-commit-confirmed')}
            trials.append(entry)
            provenance.append({'trial':index,'artifactSHA256':archive_hash,'sourceCommit':metadata.get('sourceCommit'),
                               'channelConfigSHA256':metadata['channelConfigSha256']})
indices=[r['deploymentTrial'] for r in trials]
if len(indices)!=len(set(indices)):raise ValueError('duplicate deployment trial')
missing=sorted(set(range(args.expected))-set(indices))
valid=[r for r in trials if r['trialMeanMs'] is not None]
metric=lambda key:summarize([r[key] for r in valid]) if valid else None
stage_summary={key:summarize([r['stages'][key] for r in valid if key in r['stages']]) for key in sorted(stage_names)}
components=['attest_ms','outbox_prepare_ms','commit_revalidate_ms','db_finalize_ms']
hardening=summarize([sum(r['stages'][k] for k in components) for r in valid]) if valid else None
fresh=len({r['metadata']['channelConfigSha256'] for r in trials})==len(trials)
commits=sorted({r['metadata'].get('sourceCommit') for r in trials})
if len(commits)>1:problems.append({'reason':'mixed source commits in declared cohort'})
report={'kind':'independent-deployment-BFT-100','expectedTrials':args.expected,'completeTrials':len(trials),
        'freshDeploymentPerTrialVerifiedByDistinctChannelConfigurations':fresh,
        'warmupsDiscardedPerDeployment':1,'successfulLatencyMs':metric('trialMeanMs'),
        'successfulThroughputPerSecond':summarize([r['successful']/r['durationSeconds'] for r in trials]) if trials else None,
        'measuredOfferedUploads':sum(r['offered'] for r in trials),'measuredCommittedUploads':sum(r['successful'] for r in trials),
        'measuredFailedUploads':sum(r['failed'] for r in trials),'oneOrdererCrashChecksPassed':sum(r['oneCrashPassed'] for r in trials),
        'stages':stage_summary,'instrumentedHardeningStagesMs':hardening,
        'missingTrials':missing,'provisioningOrProtocolProblems':problems,
        'independentDeploymentMinimumMet':len(valid)>=args.expected and not missing and not problems and fresh,
        'protocolMinimumMet':False,'manuscriptSection63Compliant':False,
        'section63Protocol':{'requiredWarmupTrials':5,'observedWarmupBurstsPerDeployment':1,'sequentialExecutionRequired':True,'observedExecution':'parallel independent GitHub runners','noCompetingLoadVerified':False},
        'sourceCommits':commits,'publicationMatrixComplete':False,'archiveSHA256':hashlib.sha256(combined.read_bytes()).hexdigest(),
        'limitations':['100 offered concurrency only','one small synthetic PNG and fixed source project','four orderers colocated within each deployment','hardware heterogeneity retained in trial metadata','component timings are not a causal disabled-control comparison','full 250–10000 and corporate-corpus matrices remain unmeasured'],
        'provenance':provenance}
(out/'summary.json').write_text(json.dumps(report,indent=2))
(out/'trials.jsonl').write_text('\n'.join(json.dumps(r) for r in trials)+'\n')
with (out/'trials.csv').open('w',newline='') as f:
    writer=csv.DictWriter(f,fieldnames=['deploymentTrial','meanMs','durationSeconds','successful','failed','cpuModel','memoryTotalKiB','sourceCommit'])
    writer.writeheader()
    for r in trials:writer.writerow({'deploymentTrial':r['deploymentTrial'],'meanMs':r['trialMeanMs'],'durationSeconds':r['durationSeconds'],
      'successful':r['successful'],'failed':r['failed'],'cpuModel':r['metadata'].get('cpuModel'),'memoryTotalKiB':r['metadata'].get('memoryTotalKiB'),'sourceCommit':r['metadata'].get('sourceCommit')})
if valid:
    fig,axes=plt.subplots(1,2,figsize=(11,4))
    axes[0].hist([r['trialMeanMs']/1000 for r in valid],bins=12,color='#6f9183',edgecolor='white')
    axes[0].set_xlabel('Mean client ingestion-to-commit latency per deployment (s)');axes[0].set_ylabel('Independent deployments')
    selected=['gate_ms','encrypt_ms','persist_ms','decrypt_ms','worker_ms','syft_ms','attest_ms','outbox_prepare_ms','commit_revalidate_ms','ledger_commit_ms','db_finalize_ms']
    values=[stage_summary[k]['mean'] for k in selected]
    axes[1].barh([k.removesuffix('_ms') for k in selected],values,color='#859caa')
    axes[1].set_xlabel('Mean stage duration (ms), excluding API queue')
    fig.suptitle('BFT: 100 offered concurrent uploads; fresh deployment per measured trial')
    fig.tight_layout();fig.savefig(out/'measured-distributions.png',dpi=180);plt.close(fig)
print({k:v for k,v in report.items() if k not in ('stages','provenance')})
