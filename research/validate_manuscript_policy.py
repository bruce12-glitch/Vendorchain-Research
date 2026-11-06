"""Evaluate the recovered Listing 1; synthetic facts are not real attestations."""
import argparse
import copy
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parent.parent

def validate(output):
    out=Path(output);out.mkdir(parents=True,exist_ok=False)
    good={'sbom':{'present':True,'component_count':1,'components':[{'name':'permitted'}],'schema':'cyclonedx'},
          'provenance':{'signature_valid':True,'certificate_approved':True,'certificate_expired':False,'artifact_digest_bound':True},
          'identity':{'state':'verified'},'policy':{'max_components':10,'banned_packages':['banned']},
          'replay':{'detected':False}}
    cases=[('positive',None,None,True),('R1','sbom.present',False,False),
           ('R2','provenance.signature_valid',False,False),('R3-approval','provenance.certificate_approved',False,False),
           ('R3-expiry','provenance.certificate_expired',True,False),('R4','identity.state','unverified',False),
           ('R5','sbom.component_count',0,False),('R6','sbom.component_count',11,False),
           ('R7','sbom.components',[{'name':'banned'}],False),('R8','sbom.schema','other',False),
           ('R9','provenance.artifact_digest_bound',False,False),('R10','replay.detected',True,False),
           ('missing-replay-is-not-detection','replay',None,True)]
    rows=[]
    for name,path,value,expected in cases:
        facts=copy.deepcopy(good)
        if path:
            keys=path.split('.');target=facts
            for key in keys[:-1]:target=target[key]
            if value is None:target.pop(keys[-1])
            else:target[keys[-1]]=value
        command=['opa','eval','--v0-compatible','--stdin-input','--format=json','--data',
                 str(ROOT/'research/manuscript/listing-1.rego'),'data.vendorchain.authorization.allow']
        result=subprocess.run(command,input=json.dumps(facts),capture_output=True,text=True,timeout=10,check=True)
        observed=json.loads(result.stdout)['result'][0]['expressions'][0]['value']
        (out/(name+'.json')).write_text(json.dumps({'input':facts,'stdout':result.stdout,'stderr':result.stderr},indent=2))
        if observed is not expected:raise AssertionError(name+' unexpected decision')
        rows.append({'case':name,'expected':expected,'observed':observed})
    report={'passed':True,'cases':rows,'opaMode':'real OPA --v0-compatible',
            'scope':'Recovered manuscript rule on synthetic predicate inputs; not active pipeline provenance/identity validation',
            'boundary':'Missing replay data permits allow in Listing 1; actual digest-index enforcement is a separate H7 requirement'}
    (out/'report.json').write_text(json.dumps(report,indent=2));print(json.dumps(report));return report

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    validate(parser.parse_args().output)
