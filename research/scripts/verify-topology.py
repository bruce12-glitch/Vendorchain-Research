import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import base64
import tempfile
raw=Path(sys.argv[1]).read_bytes();block=json.loads(raw)
config=block['data']['data'][0]['payload']['data']['config']['channel_group']
orderer=config['groups']['Orderer']['values']
consensus=orderer['ConsensusType']['value']['type']
clusters=[]
def walk(x):
    if isinstance(x,dict):
        for k,v in x.items():
            if k.replace('_','').lower() in ('consentermapping','consenters') and isinstance(v,list):clusters.append(v)
            walk(v)
    elif isinstance(x,list):
        for v in x:walk(v)
walk(config)
if consensus=='etcdraft' and not clusters:
    metadata=orderer['ConsensusType']['value']['metadata']
    if isinstance(metadata,str):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'metadata.pb';source.write_bytes(base64.b64decode(metadata,validate=True))
            decoded=subprocess.run(['configtxlator','proto_decode','--input',str(source),'--type','etcdraft.ConfigMetadata'],capture_output=True,check=True).stdout
            walk(json.loads(decoded))
membership=max(clusters,key=len) if clusters else []
expected=sys.argv[3] if len(sys.argv)>3 else 'BFT'
if consensus!=expected or len(membership)!=4:
    raise SystemExit('Committed configuration does not match the declared four-node consensus')
report={'consensus':consensus,'ordererCount':len(membership),'channelConfigSha256':hashlib.sha256(raw).hexdigest(),
        'samplesCommit':'5789681b4f4d24e58fa40f19a69f5496892374b6','fabricVersion':'3.1.5',
        'colocated':True,'productionDeployment':False,'platform':platform.platform(),
        'cpuCount':__import__('os').cpu_count(), 'membership':membership,
        'sourceCommit':__import__('os').environ.get('GITHUB_SHA'),
        'cpuAffinityCount':len(__import__('os').sched_getaffinity(0)),
        'cpuModel':next((l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),None),
        'memoryTotalKiB':next((int(l.split()[1]) for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemTotal:')),None),
        'nodeVersion':subprocess.run(['node','--version'],capture_output=True,text=True,check=True).stdout.strip(),
        'goVersion':subprocess.run(['go','version'],capture_output=True,text=True,check=True).stdout.strip(),
        'limitations':'One Docker host, development certificates; this checks integration, not production workload fidelity.'}
Path(sys.argv[2]).write_text(json.dumps(report,indent=2))
