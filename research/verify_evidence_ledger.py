"""Retain an actual Fabric CLI query and enforce the v2 hash-only world state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

FIELDS={'recordID','vendorID','evidenceRoot','snapshotHash','policyHash','decision','signatureHash','keyID','algorithm','issuedAt','receiptHash','transactionID'}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--requests',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    requests=json.loads(Path(a.requests).read_text())['requests'];request=next(r for r in requests if r['success'])
    out=Path(a.output);out.mkdir(parents=True,exist_ok=False)
    command=['peer','chaincode','query','-C',os.environ.get('FABRIC_CHANNEL','vendorchain'),'-n','vendorchain',
             '-c',json.dumps({'Args':['QueryEvidence',request['recordID']]})]
    proc=subprocess.run(command,capture_output=True,timeout=60,check=True)
    (out/'peer.stdout.json').write_bytes(proc.stdout);(out/'peer.stderr.log').write_bytes(proc.stderr)
    record=json.loads(proc.stdout)
    if set(record)!=FIELDS or record['transactionID']!=request['transactionID'] or record['recordID']!=request['recordID']:
        raise ValueError('unexpected world-state fields or commit/readback mismatch')
    for field in ['evidenceRoot','snapshotHash','policyHash','signatureHash','receiptHash']:
        if len(record[field])!=64 or any(c not in '0123456789abcdef' for c in record[field]):raise ValueError('invalid ledger digest')
    report={'hashOnly':True,'recordID':record['recordID'],'transactionID':record['transactionID'],
            'stdoutSHA256':hashlib.sha256(proc.stdout).hexdigest(),'fieldNames':sorted(FIELDS),
            'scope':'One actual v2 world-state record; historical Equation 9 results are not reconstructed.'}
    (out/'verification.json').write_text(json.dumps(report,indent=2))
