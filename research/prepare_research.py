"""Create a complete disposable local-key experiment configuration."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from hardened_cli import initialize
from vendorchain.evidence import sha


def prepare(root):
    root=Path(root).resolve();config=initialize(root)
    source=root/'artifact';source.mkdir()
    for file in (Path(__file__).resolve().parents[1]/'chaincode').glob('*.go'):
        shutil.copyfile(file,source/file.name)
    for name in ['go.mod','go.sum']:
        shutil.copyfile(Path(__file__).resolve().parents[1]/'chaincode'/name,source/name)
    subprocess.run(['cosign','generate-key-pair','--output-key-prefix',str(root/'cosign')],
                   env={**os.environ,'COSIGN_PASSWORD':''},capture_output=True,timeout=30,check=True)
    # Dev-only private material is readable only by this account, ignored by Git.
    (root/'cosign.key').chmod(0o600)
    value=json.loads(config.read_text());value['provenance']['publicSHA256']=sha((root/'cosign.pub').read_bytes())
    config.write_text(json.dumps(value,indent=2))
    return config


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args()
    print(json.dumps({'config':str(prepare(a.output)),'custody':'research-local-keys; not HSM validation'}))
