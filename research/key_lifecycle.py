"""Operate Vault key rotation/version revocation and retain non-secret audit output."""
import argparse
import json
import os
import re
import time
from vendorchain.kms import VaultTransit

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('operation',choices=['status','rotate','revoke-before-version'])
    p.add_argument('--key',required=True);p.add_argument('--version',type=int);a=p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_-]+',a.key):p.error('invalid key name')
    vault=VaultTransit(os.environ['VAULT_ADDR'],os.environ['VAULT_TOKEN'])
    if a.operation=='rotate':vault.call('keys/'+a.key+'/rotate',{})
    elif a.operation=='revoke-before-version':
        if not a.version or a.version<1:p.error('positive --version required')
        current=vault.key(a.key)
        settings={'min_encryption_version':a.version}
        if current.get('supports_decryption'):settings['min_decryption_version']=a.version
        vault.call('keys/'+a.key+'/config',settings)
    state=vault.key(a.key)
    print(json.dumps({'operation':a.operation,'key':a.key,'at':int(time.time()),
         **{field:state.get(field) for field in ('type','latest_version','min_decryption_version','min_encryption_version','exportable','allow_plaintext_backup')}}))
