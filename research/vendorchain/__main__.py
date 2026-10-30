import argparse
import asyncio
import json
import os
from pathlib import Path
from .settings import initialize,configured

def main():
    parser=argparse.ArgumentParser()
    sub=parser.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--state',required=True)
    server=sub.add_parser('serve');server.add_argument('--state',required=True);server.add_argument('--local',action='store_true')
    server.add_argument('--source');server.add_argument('--no-sbom',action='store_true');server.add_argument('--no-ocr',action='store_true')
    server.add_argument('--port',type=int,default=8090);server.add_argument('--workers',type=int,default=8)
    reconcile=sub.add_parser('reconcile');reconcile.add_argument('--state',required=True);reconcile.add_argument('--source');reconcile.add_argument('record_id')
    corpus=sub.add_parser('corpus');corpus.add_argument('--generate');corpus.add_argument('--benign',type=int,default=300);corpus.add_argument('--manifest');corpus.add_argument('--output',required=True)
    abl=sub.add_parser('ablation');abl.add_argument('--output',required=True);abl.add_argument('--trials',type=int,default=50);abl.add_argument('--warmups',type=int,default=3);abl.add_argument('--source')
    args=parser.parse_args()
    if args.command=='init':
        public=initialize(args.state);print(json.dumps({'created':True,'workerKeyID':public['keyID']}))
    elif args.command=='serve':
        pipeline=configured(args.state,local=args.local,source=args.source,no_ocr=args.no_ocr,no_sbom=args.no_sbom)
        asyncio.run(__import__('vendorchain.server',fromlist=['serve']).serve(pipeline,os.environ['API_TOKEN'],args.port,args.workers))
    elif args.command=='reconcile':
        print(json.dumps(configured(args.state,source=args.source).deliver(args.record_id)))
    elif args.command=='corpus':
        from .corpus import generate,evaluate
        manifest=generate(args.generate,args.benign) if args.generate else args.manifest
        if not manifest:parser.error('--generate or --manifest required')
        report=evaluate(manifest);output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2))
        print(json.dumps({k:v for k,v in report.items() if k!='results'}))
    elif args.command=='ablation':
        from .ablation import campaign
        print(json.dumps(campaign(args.output,args.trials,args.warmups,args.source)))
if __name__=='__main__':main()
