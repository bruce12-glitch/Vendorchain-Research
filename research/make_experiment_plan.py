"""Generate an exact seven-variant Table 12 plan for experiment.py."""
import argparse
import json
from pathlib import Path
import sys
from table12_worker import VARIANTS, COMPARATORS

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--output',required=True)
    p.add_argument('--file');p.add_argument('--local',action='store_true');p.add_argument('--allow-local-keys',action='store_true')
    p.add_argument('--comparators',action='store_true');a=p.parse_args()
    tasks=[]
    for variant in VARIANTS+(COMPARATORS if a.comparators else []):
        command=[sys.executable,str(Path(__file__).parent/'table12_worker.py'),'--variant',variant,'--config',str(Path(a.config).resolve())]
        if a.file:command+=['--file',str(Path(a.file).resolve())]
        if a.local:command+=['--local']
        if a.allow_local_keys:command+=['--allow-local-keys']
        tasks.append({'name':variant,'command':command,'timeoutSeconds':300})
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
    with out.open('x') as f:json.dump({'kind':'table12-hardened-cumulative-ablation','tasks':tasks},f,indent=2)
