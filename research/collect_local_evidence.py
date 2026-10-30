"""Retain actual regression evidence and 5+50 fresh-process feasibility trials.

The local ledger is a test double. Historical measurements are never reproduced
by asserting their numeric values. All newly measured values are kept as-is.
"""
import argparse
import hashlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import tempfile
import time
import zipfile
from cryptography.exceptions import InvalidTag
from vendorchain.corpus import png
from vendorchain.crypto import encrypt,decrypt
from vendorchain.gstin import valid_gstin
from vendorchain.ingress import validate,Rejected
from vendorchain.settings import initialize,configured
from vendorchain.stats import summarize

ROOT=Path(__file__).resolve().parent.parent

def sha(data):return hashlib.sha256(data).hexdigest()

def one_trial():
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject,NameObject
    # Generate an actual passive PDF of exactly 5 MiB, including xref and EOF.
    size=5*1024*1024; padding=size-1024
    for _ in range(4):
        writer=PdfWriter();writer.add_blank_page(612,792)
        stream=DecodedStreamObject();stream.set_data(b' '*padding)
        writer._root_object[NameObject('/InertBenchmarkPadding')]=writer._add_object(stream)
        buf=io.BytesIO();writer.write(buf);document=buf.getvalue()
        if len(document)==size:break
        padding+=size-len(document)
    assert len(document)==size
    validate(document)
    key=os.urandom(32);ctx={'vendorID':'benchmark','recordID':'trial','documentType':'COMPLIANCE_DOCUMENT'}
    metrics={}
    def measure(name,call):
        start=time.perf_counter_ns();value=call();metrics[name]=(time.perf_counter_ns()-start)/1e6;return value
    image=png()
    measure('direct_structural_gate_ms',lambda:validate(image))
    cipher,meta=measure('envelope_encrypt_5MiB_pdf_ms',lambda:encrypt(document,key,ctx))
    plain=measure('envelope_decrypt_5MiB_pdf_ms',lambda:decrypt(cipher,meta,key,ctx))
    assert plain==document;plain[:]=b'\0'*len(plain)
    assert measure('luhn_mod36_ms',lambda:valid_gstin('27AAPFU0939F1ZV','AAPFU0939F'))
    with tempfile.TemporaryDirectory() as tmp:
        initialize(tmp)
        pipeline=configured(tmp,local=True,no_sbom=True)
        result=measure('local_ingestion_to_commit_ms',lambda:pipeline.run(bytearray(image),'benchmark','trial'))
        assert result['ack']['successful'] and result['evidence']=='local-non-consensus'
    return {'pid':os.getpid(),'metrics':metrics,'pipelineStages':result['stages'],
            'envelopeInputBytes':size,'gateAndPipelineInputBytes':len(image),'ocrExecuted':True,
            'syftExecuted':False,'opaExecuted':False,'evidence':'local-non-consensus',
            'peakProcessRssKiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}

def collect(output,trials=50,warmups=5):
    if trials<1 or warmups<0:raise ValueError('invalid counts')
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    env={**os.environ,'PYTHONPATH':str(ROOT/'research')}
    # Retain the exact executable source even when the working tree is dirty.
    source_paths=list((ROOT/'research/vendorchain').glob('*.py'))
    source_paths+=list((ROOT/'research/tests').glob('*.py'))
    source_paths+=list((ROOT/'research/policies').glob('*.rego'))
    source_paths+=[Path(__file__).resolve(),ROOT/'research/validate_cosign.py',ROOT/'research/requirements.txt']
    with zipfile.ZipFile(out/'measurement-source.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_paths):archive.write(path,str(path.relative_to(ROOT)))
    metadata={'startedAtUTC':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
              'platform':platform.platform(),'python':platform.python_version(),
              'sourceCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
              'sourceDirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip()),
              'packages':{p:importlib.metadata.version(p) for p in ['cryptography','Pillow','pypdf','scipy']},
              'sourceSHA256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in
                              sorted(source_paths)},
              'externalToolVersions':{name:subprocess.run(command,capture_output=True,text=True,check=True).stdout
                                      for name,command in [('node',['node','--version']),('opa',['opa','version']),
                                                           ('cosign',['cosign','version'])]},
              'scope':'Local component/reference-pipeline evidence, not Fabric/production evidence'}
    (out/'metadata.json').write_text(json.dumps(metadata,indent=2))
    commands=[('python-tests',[sys.executable,'-m','unittest','discover','-s','research/tests','-v']),
              ('gateway-tests',['node','--test','research/gateway/test.mjs']),
              ('opa-tests',['opa','test','research/policies','-v'])]
    for name,command in commands:
        completed=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,text=True,timeout=180)
        (out/(name+'.log')).write_text(completed.stdout+completed.stderr)
        if completed.returncode:raise RuntimeError(name+' failed; see raw log')
    (out/'tesseract-version.txt').write_text(subprocess.check_output(['tesseract','--version'],text=True))
    observations=[]
    with tempfile.TemporaryDirectory() as tmp:
        initialize(tmp);pipeline=configured(tmp,local=True,no_ocr=True,no_sbom=True)
        fixture_dir=out/'extension-spoof-v2';fixture_dir.mkdir()
        for index in range(15):
            family='PE' if index%2==0 else 'ELF'
            data=(b'MZ' if family=='PE' else b'\x7fELF')+b'\0'*60+f'INERT_SYNTHETIC_{index:02}'.encode()
            filename=f'spoof-{index:02}-{family.lower()}.'+['pdf','png','jpg','docx','txt'][index%5]
            (fixture_dir/filename).write_bytes(data)
            receive=bytearray(data);rid=f'spoof-{index:02}'
            before=list((pipeline.root/'blobs').iterdir())
            try:pipeline.ingest(receive,'evidence',rid)
            except Rejected as exc:reason=str(exc)
            else:raise AssertionError('executable prefix bypassed gate')
            after=list((pipeline.root/'blobs').iterdir())
            row={'event':'ingress_rejection','fixture':filename,'sha256':sha(data),'family':family,
                 'reasonCode':reason,'ownedReceiveBufferZeroed':not any(receive),
                 'objectsBefore':len(before),'objectsAfter':len(after),
                 'submissionPersisted':pipeline.store.get(rid) is not None,
                 'objectBackend':'local encrypted files; S3/MinIO not tested',
                 'specimenKind':'new inert signature-prefix regression; not a validated loadable executable'}
            assert reason=='EXECUTABLE_SPOOF' and not any(receive) and before==after and not row['submissionPersisted']
            observations.append(row)
        context={'vendorID':'vendor','recordID':'submission','documentType':'COMPLIANCE_DOCUMENT'}
        cipher,meta=encrypt(b'inert private document',b'k'*32,context)
        for field in context:
            try:decrypt(cipher,meta,b'k'*32,{**context,field:'another-context'})
            except InvalidTag:
                observations.append({'event':'cross_context_gcm','changedField':field,
                                     'exception':'cryptography.exceptions.InvalidTag','passed':True})
            else:raise AssertionError('context swap authenticated')
    (out/'security-observations.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in observations))
    rows=[]
    for index in range(-warmups,trials):
        result=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--one-trial'],
                              env=env,cwd=ROOT,capture_output=True,text=True,timeout=90,check=True)
        row={**json.loads(result.stdout),'trial':index,'warmup':index<0}
        rows.append(row)
        with (out/'timing-raw.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
    measured=[r for r in rows if not r['warmup']]
    summary={'measuredTrials':trials,'discardedWarmups':warmups,
             'freshProcessCount':len({r['pid'] for r in rows}),
             'metrics':{k:summarize([r['metrics'][k] for r in measured]) for k in measured[0]['metrics']},
             'fiveWarmupCountMet':warmups>=5,'trialCountMet':trials>=50,
             'historicalTimingsRecovered':False,'fabricConsensusExecuted':False,
             'scope':'Sequential fresh-process feasibility trials on a shared host, synthetic PNG and 5 MiB PDF; host caches persist; independence/no-competing-load not proven'}
    (out/'timing-summary.json').write_text(json.dumps(summary,indent=2))
    from validate_cosign import validate as validate_signature
    validate_signature(out/'cosign')
    files={str(p.relative_to(out)):sha(p.read_bytes()) for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'sha256-manifest.json').write_text(json.dumps(files,indent=2))
    print(json.dumps({'measuredTrials':trials,'warmups':warmups,'spoofRejections':15,'output':str(out)}))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output');parser.add_argument('--trials',type=int,default=50)
    parser.add_argument('--warmups',type=int,default=5);parser.add_argument('--one-trial',action='store_true')
    args=parser.parse_args()
    if args.one_trial:print(json.dumps(one_trial()))
    elif args.output:collect(args.output,args.trials,args.warmups)
    else:parser.error('--output is required')
