"""Real offline Cosign tamper experiment. Never exports the temporary private key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

def validate(output, source=None):
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    if not shutil.which('cosign'):
        raise RuntimeError('Cosign is required; no simulated verification is permitted')
    records=[]
    with tempfile.TemporaryDirectory() as tmp:
        prefix=Path(tmp)/'validation-key'
        env={**os.environ,'COSIGN_PASSWORD':secrets.token_hex(32)}
        def run(name, command):
            result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=90)
            (out/(name+'.log')).write_text(result.stdout+result.stderr)
            records.append({'operation':name,'exitCode':result.returncode,'command':command})
            return result
        version=run('version',['cosign','version'])
        assert version.returncode==0
        if source:
            result=subprocess.run(['syft','dir:'+str(Path(source).resolve()),'-o','cyclonedx-json'],
                                  capture_output=True,timeout=90,check=True)
            original=result.stdout;kind='real-Syft-CycloneDX'
        else:
            original=json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
                                 'components':[{'type':'library','name':'inert-test-component','version':'1.0'}]}).encode()
            kind='handwritten-minimal-CycloneDX-component-test'
        parsed=json.loads(original)
        assert parsed['bomFormat']=='CycloneDX'
        blob=out/'sbom.json';blob.write_bytes(original)
        parsed['version']=int(parsed.get('version',1))+1
        changed=out/'mutated-sbom.json';changed.write_text(json.dumps(parsed))
        assert run('generate-key',['cosign','generate-key-pair','--output-key-prefix',str(prefix)]).returncode==0
        public=out/'cosign.pub';public.write_bytes(prefix.with_suffix('.pub').read_bytes())
        sig=out/'sbom.sig'
        assert run('sign',['cosign','sign-blob','--yes','--key',str(prefix.with_suffix('.key')),
                           '--tlog-upload=false','--output-signature',str(sig),str(blob)]).returncode==0
        verify=['cosign','verify-blob','--offline','--insecure-ignore-tlog=true',
                '--key',str(public),'--signature',str(sig)]
        good=run('verify-original',verify+[str(blob)])
        bad=run('verify-mutated',verify+[str(changed)])
        # A valid positive control distinguishes a bad signature from setup failure.
        passed=good.returncode==0 and bad.returncode!=0 and 'signature' in bad.stderr.lower()
        report={'passed':passed,'signatureSystem':'real Cosign','sbomSource':kind,
                'originalSHA256':hashlib.sha256(original).hexdigest(),
                'mutatedSHA256':hashlib.sha256(changed.read_bytes()).hexdigest(),
                'originalVerificationExitCode':good.returncode,'mutatedVerificationExitCode':bad.returncode,
                'transparencyLogTested':False,'privateKeyRetained':False,
                'scope':'Offline public-key blob signatures; no Rekor/Fulcio, software-safety or pipeline-Cosign claim',
                'operations':records}
        (out/'report.json').write_text(json.dumps(report,indent=2))
        if not passed:raise AssertionError('Cosign positive/negative controls failed')
        return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--source')
    args=parser.parse_args();print(json.dumps(validate(args.output,args.source)))
