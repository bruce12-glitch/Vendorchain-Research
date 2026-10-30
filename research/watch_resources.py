"""Sample a local process tree and explicitly selected Fabric containers."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

parser=argparse.ArgumentParser()
parser.add_argument('--pid',type=int,required=True)
parser.add_argument('--state',required=True)
parser.add_argument('--output',required=True)
parser.add_argument('--interval',type=float,default=1)
parser.add_argument('--containers',default='orderer.example.com,orderer2.example.com,orderer3.example.com,orderer4.example.com,peer0.org1.example.com,peer0.org2.example.com')
args=parser.parse_args()
if args.interval<.2:raise SystemExit('interval must be at least 0.2 seconds')
running=True

def stop(*_):
    global running
    running=False
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)

def process_tree(root):
    records={}
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():continue
        try:
            # /proc/<pid>/stat comm may contain spaces and parentheses.
            raw=(directory/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
            records[int(directory.name)]={'ppid':int(fields[1]),'cpuTicks':int(fields[11])+int(fields[12]),'rssBytes':int(fields[21])*os.sysconf('SC_PAGE_SIZE')}
        except (OSError,ValueError,IndexError):continue
    selected={root}
    while True:
        more={pid for pid,r in records.items() if r['ppid'] in selected}
        if more<=selected:break
        selected|=more
    return {str(pid):records[pid] for pid in selected if pid in records}

def growth(path):
    total=0;errors=[]
    for root,dirs,files in os.walk(path,followlinks=False):
        for name in files:
            try:
                p=Path(root)/name
                if not p.is_symlink():total+=p.stat().st_size
            except OSError as exc:errors.append(type(exc).__name__)
    return {'bytes':total,'errors':errors}

out=Path(args.output);out.parent.mkdir(parents=True,exist_ok=True)
with out.open('x') as stream:
    while running:
        start=time.monotonic()
        row={'timeNs':time.time_ns(),'processes':process_tree(args.pid),'clockTicksPerSecond':os.sysconf('SC_CLK_TCK'),
             'pipelineDisk':growth(args.state)}
        try:
            cmd=['docker','stats','--no-stream','--format','{{json .}}',*args.containers.split(',')]
            proc=subprocess.run(cmd,capture_output=True,text=True,timeout=10,check=True)
            row['containers']=[json.loads(l) for l in proc.stdout.splitlines() if l]
        except (OSError,subprocess.SubprocessError,ValueError) as exc:
            row['containers']=None;row['containerMeasurementError']=type(exc).__name__
        stream.write(json.dumps(row)+'\n');stream.flush()
        # Small waits keep shutdown responsive; record the actual sampling time.
        end=start+args.interval
        while running and time.monotonic()<end:time.sleep(min(.1,end-time.monotonic()))
