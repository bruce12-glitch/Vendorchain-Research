"""Provision disposable Transit research keys; never a production Vault setup.

The supplied environment token needs key creation privileges. Production uses
separate administrative and ACL-scoped runtime tokens instead of this lab token.
"""
import argparse
import json
import os
from pathlib import Path
import time
from prepare_research import prepare
from vendorchain.crypto import canonical, decode
from vendorchain.evidence import sha, sign_document
from vendorchain.kms import VaultTransit, VaultSigner


def prepare_vault(root, *, address_env='VAULT_ADDR', token_env='VAULT_TOKEN'):
    config_path=prepare(root);base=config_path.parent;config=json.loads(config_path.read_text())
    transit=VaultTransit(os.environ[address_env],os.environ[token_env]);registry={};now=int(time.time())
    prefix='vc-research-'+os.urandom(6).hex()
    signers={}
    for role in ('identity','decision','policy'):
        name=prefix+'-'+role
        transit.call('keys/'+name,{'type':'ed25519','exportable':False,'allow_plaintext_backup':False})
        pub=transit.key(name)['keys']['1']['public_key']
        registry[name]={'keyID':name,'role':role,'publicKey':pub,'notBefore':now-30,'notAfter':now+86400,'revoked':False}
        config['signers'][role]={'kind':'vault-transit','keyID':name,'key':name,'version':1,'addressEnv':address_env,'tokenEnv':token_env}
        signers[role]=VaultSigner(transit,name,1,decode(pub))
    kek=prefix+'-kek'
    transit.call('keys/'+kek,{'type':'aes256-gcm96','derived':True,'exportable':False,'allow_plaintext_backup':False})
    config['kek']={'kind':'vault-transit','key':kek,'addressEnv':address_env,'tokenEnv':token_env}
    config['researchLocalKeys']=False
    old=json.loads((base/'signed-policy.json').read_text());document=json.loads(decode(old['payload']))['document']
    bundle=sign_document(document,signers['policy'],config['signers']['policy']['keyID'],'vendorchain.policy.v1',now=now,ttl=86400)
    (base/'registry.json').write_bytes(canonical(registry));(base/'signed-policy.json').write_bytes(canonical(bundle))
    (base/'ledger-registration.json').write_bytes(canonical({'keys':list(registry.values()),'policy':{'digest':sha(canonical(bundle)),'notBefore':now-30,'notAfter':now+86400}}))
    config_path.write_text(json.dumps(config,indent=2))
    for name in ('master.hex','identity.private','decision.private','policy.private'):(base/name).unlink()
    return config_path


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args()
    print(json.dumps({'config':str(prepare_vault(a.output)),'custody':'Vault Transit research service; hardware HSM not verified'}))
