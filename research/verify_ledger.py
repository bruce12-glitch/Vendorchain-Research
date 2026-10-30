"""Retain a real peer CLI query, and inspect the decoded signed receipt schema."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

def verify(requests, output):
    root=Path(__file__).resolve().parent.parent
    out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False)
    rows=json.loads(Path(requests).read_text())['requests']
    sample=next(r for r in rows if r.get('success') and r.get('evidence')=='fabric-commit-confirmed')
    network=Path(os.environ.get('VENDORCHAIN_NETWORK_DIR',root/'.runtime/fabric-samples'))
    command=[str(network/'bin/peer'),'chaincode','query','-C',os.environ['FABRIC_CHANNEL'],
             '-n','vendorchain','-c',json.dumps({'Args':['QueryCompliance',sample['recordID']]})]
    env={**os.environ,'FABRIC_CFG_PATH':str(network/'config'),
         'CORE_PEER_TLS_ENABLED':'true','CORE_PEER_LOCALMSPID':os.environ['FABRIC_MSP_ID'],
         'CORE_PEER_ADDRESS':os.environ['FABRIC_PEER_ENDPOINT'],
         'CORE_PEER_TLS_ROOTCERT_FILE':os.environ['FABRIC_TLS_CERT'],
         'CORE_PEER_MSPCONFIGPATH':str(Path(os.environ['FABRIC_ID_CERT']).parent.parent)}
    result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=30)
    (out/'peer-query-command.json').write_text(json.dumps(command,indent=2))
    (out/'peer-query.stdout.json').write_text(result.stdout)
    (out/'peer-query.stderr.log').write_text(result.stderr)
    if result.returncode:raise RuntimeError('peer chaincode query failed; raw logs retained')
    print('BEGIN_VENDORCHAIN_PEER_QUERY')
    print(result.stdout.strip())
    print('END_VENDORCHAIN_PEER_QUERY')
    record=json.loads(result.stdout)
    expected={'recordID','vendorID','receiptHash','receipt','signature','transactionID','timestamp'}
    if set(record)!=expected:raise ValueError('unexpected compliance world-state fields')
    raw=base64.b64decode(record['receipt'],validate=True);receipt=json.loads(raw)
    expected_receipt={'version','recordID','vendorID','documentHash','ciphertextHash','sbomHash',
                      'policyHash','decision','keyID','issuedAt','expiresAt','nonce'}
    if set(receipt)!=expected_receipt:raise ValueError('unexpected receipt fields')
    for field in ['documentHash','ciphertextHash','sbomHash','policyHash']:
        if not re.fullmatch('[a-f0-9]{64}',receipt[field]):raise ValueError('non-hash payload in '+field)
    if (hashlib.sha256(raw).hexdigest()!=record['receiptHash'] or record['transactionID']!=sample['transactionID']
        or record['recordID']!=sample['recordID'] or receipt['recordID']!=record['recordID']):
        raise ValueError('queried commitment does not match upload acknowledgement')
    (out/'decoded-receipt.json').write_text(json.dumps(receipt,indent=2))
    report={'passed':True,'evidence':'actual-peer-chaincode-query','queryExitCode':result.returncode,
            'recordID':record['recordID'],'transactionID':record['transactionID'],
            'documentAndSbomPayloadAbsentFromQueriedRecord':True,
            'recordContainsReceiptSignatureAndMetadata':True,'equation9SchemaVerified':False,
            'scope':'One queried compliance record, not an enumeration of every world-state namespace; signed-receipt schema differs from the manuscript Equation 9 flat tuple'}
    (out/'report.json').write_text(json.dumps(report,indent=2));return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--requests',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();print(json.dumps(verify(args.requests,args.output)))
