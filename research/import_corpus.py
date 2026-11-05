"""Hash-pin a manually reviewed corpus index without inventing document provenance."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def manifest(root, index, output):
    root=Path(root).resolve();output=Path(output).resolve()
    if not output.is_relative_to(root):raise ValueError('manifest must live within corpus root')
    entries=[];seen=set()
    with Path(index).open(newline='') as source:
        for row in csv.DictReader(source):
            if row['label'] not in ('benign','adversarial'):raise ValueError('invalid manual label')
            for field in ('reviewed_by','provenance_uri','family'):
                if not row.get(field):raise ValueError('reviewer, provenance URI and family required')
            path=(root/row['path']).resolve(strict=True)
            if not path.is_relative_to(root) or not path.is_file():raise ValueError('corpus path escapes root')
            if not path.is_relative_to(output.parent):raise ValueError('place manifest above all indexed files')
            digest=hashlib.sha256()
            with path.open('rb') as stream:
                for chunk in iter(lambda:stream.read(65536),b''):digest.update(chunk)
            h=digest.hexdigest()
            if h in seen:raise ValueError('duplicate specimen would inflate the corpus')
            seen.add(h)
            entries.append({'path':path.relative_to(output.parent).as_posix(),'sha256':h,'label':row['label'],
                            'family':row['family'],'source':row['provenance_uri'],'reviewedBy':row['reviewed_by']})
    if not entries:raise ValueError('empty corpus')
    with output.open('x') as stream:json.dump({'version':1,'kind':'externally-supplied-reviewed','entries':entries},stream,indent=2)
    return {'specimens':len(entries),'manifestSHA256':hashlib.sha256(output.read_bytes()).hexdigest(),
            'originIndependentlyVerified':False}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--index',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();print(json.dumps(manifest(a.root,a.index,a.output)))
