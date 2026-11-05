"""Compare a documented header-only baseline with retained structural-gate decisions."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
parser=argparse.ArgumentParser();parser.add_argument('--archive',required=True);parser.add_argument('--gate-report',required=True);parser.add_argument('--output',required=True)
args=parser.parse_args();report=json.loads(Path(args.gate_report).read_text());outcomes=[]
with zipfile.ZipFile(args.archive) as archive:
    manifest=archive.read('manifest.json')
    assert hashlib.sha256(manifest).hexdigest()==report['manifestHash']
    for row in report['results']:
        data=archive.read(row['path'])
        assert hashlib.sha256(data).hexdigest()==row['sha256']
        header=0<len(data)<=5*1024*1024 and data.startswith((b'%PDF-',b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff'))
        outcomes.append({'path':row['path'],'label':row['label'],'headerOnlyAccepted':header,'structuralAccepted':row['accepted']})
attacks=[r for r in outcomes if r['label']=='adversarial'];benign=[r for r in outcomes if r['label']=='benign']
result={'kind':'synthetic-paired-security-ablation','manifestHash':report['manifestHash'],
 'adversarialN':len(attacks),'benignN':len(benign),
 'headerOnlyBypasses':sum(r['headerOnlyAccepted'] for r in attacks),
 'structuralBypasses':sum(r['structuralAccepted'] for r in attacks),
 'headerOnlyFalseRejections':sum(not r['headerOnlyAccepted'] for r in benign),
 'structuralFalseRejections':sum(not r['structuralAccepted'] for r in benign),
 'notes':'Header-only baseline accepts supported signatures within the byte limit. Structural outcomes are reused from the actual isolated gate run. This comparison supports a corpus-specific defensive benefit, not a universal necessity theorem.',
 'outcomes':outcomes}
Path(args.output).write_text(json.dumps(result,indent=2))
print({k:v for k,v in result.items() if k!='outcomes'})
