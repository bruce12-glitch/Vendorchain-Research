"""Run the actual seven variant workers over a reviewed document manifest.

This measures document-ingress/identity outcomes only. SBOM/signing/policy/key
tampering are separately tested by the security suite, not invented as files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from table12_worker import VARIANTS
from vendorchain.corpus import rate
from vendorchain.ingress import MAX_BYTES


def evaluate(config, manifest_path, output):
    manifest_path=Path(manifest_path).resolve();manifest=json.loads(manifest_path.read_text())
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    rows=[];seen=set();skipped=[]
    for entry in manifest['entries']:
        path=(manifest_path.parent/entry['path']).resolve(strict=True)
        if not path.is_relative_to(manifest_path.parent) or entry['label'] not in ('benign','adversarial'):raise ValueError('invalid manifest path/label')
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(65536),b''):h.update(chunk)
        if h.hexdigest()!=entry['sha256'] or h.hexdigest() in seen:raise ValueError('changed or duplicated fixture')
        seen.add(h.hexdigest())
        if path.stat().st_size>MAX_BYTES:
            skipped.append({'sha256':h.hexdigest(),'reason':'oversized specimens use the dedicated ingress-size tests'});continue
        for variant in VARIANTS:
            directory=out/variant/h.hexdigest();directory.mkdir(parents=True)
            command=[sys.executable,str(Path(__file__).parent/'table12_worker.py'),'--variant',variant,
                     '--config',str(Path(config).resolve()),'--file',str(path),'--local','--allow-local-keys']
            try:
                result=subprocess.run(command,env={**os.environ,'VENDORCHAIN_TRIAL_DIR':str(directory)},capture_output=True,timeout=300)
                (directory/'stdout.log').write_bytes(result.stdout);(directory/'stderr.log').write_bytes(result.stderr)
                if result.returncode:raise ValueError('worker crashed')
                measured=json.loads((directory/'measurement.json').read_text())
                if measured['successful'] is True:outcome='accepted'
                elif measured.get('decision')=='FAIL' or measured.get('error')=='Rejected':outcome='rejected'
                else:outcome='operational-error'
            except Exception as exc:
                outcome='operational-error';measured={'error':type(exc).__name__}
            row={**entry,'variant':variant,'outcome':outcome,'error':measured.get('error')}
            rows.append(row)
            with (out/'outcomes.jsonl').open('a') as stream:stream.write(json.dumps(row)+'\n')
    variants={}
    for variant in VARIANTS:
        selected=[r for r in rows if r['variant']==variant]
        benign=[r for r in selected if r['label']=='benign' and r['outcome']!='operational-error']
        attacks=[r for r in selected if r['label']=='adversarial' and r['outcome']!='operational-error']
        variants[variant]={'bypasses':rate(sum(r['outcome']=='accepted' for r in attacks),len(attacks)),
                           'falseRejections':rate(sum(r['outcome']=='rejected' for r in benign),len(benign)),
                           'operationalErrors':sum(r['outcome']=='operational-error' for r in selected)}
    report={'kind':'measured-document-security-ablation','manifestSHA256':hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            'variants':variants,'skipped':skipped,'evidence':'local-non-consensus',
            'scope':'Each variant is executed. Operational errors are never counted as successful security rejection. This is not coverage of every attack class in Table 12.'}
    (out/'summary.json').write_text(json.dumps(report,indent=2));return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',required=True);p.add_argument('--manifest',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();print(json.dumps(evaluate(a.config,a.manifest,a.output),indent=2))
