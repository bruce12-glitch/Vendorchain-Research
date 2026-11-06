import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from test_custody_plan import CustodyFixture
from prepare_custody_research import prepare_custody
from make_custody_plan import make_plan
from vendorchain.crypto import canonical, decode
from vendorchain.evidence import sha


class PrepareCustodyTests(CustodyFixture):
    def test_preparation_shares_cosign_and_resigns_remote_policy(self):
        remote = self.paths['vaultkeys'].parent
        (remote / 'cosign.key').write_text('unused private key')
        (remote / 'cosign.pub').write_text('unused public key')
        self.configs['vaultkeys']['provenance'] = {
            **self.configs['vaultkeys']['provenance'], 'privateURI': 'cosign.key',
            'publicFile': 'cosign.pub', 'publicSHA256': sha((remote / 'cosign.pub').read_bytes())}
        self.documents['vaultkeys']['provenanceTrust']['publicSHA256'] = self.configs['vaultkeys']['provenance']['publicSHA256']
        self.write_arm('vaultkeys')
        (remote / 'ledger-registration.json').write_bytes(canonical({'policy': {'digest': 'old'}}))
        with patch.dict(os.environ, {'VAULT_ADDR': 'http://fixture.invalid', 'VAULT_TOKEN': 'not-a-secret'}), \
                patch('prepare_custody_research.prepare', return_value=self.paths['localkeys']), \
                patch('prepare_custody_research.prepare_vault', return_value=self.paths['vaultkeys']), \
                patch('prepare_custody_research.VaultTransit') as transit, \
                patch('prepare_custody_research.VaultSigner', return_value=self.keys['vaultkeys']['policy']):
            paths = prepare_custody(self.root / 'prepared')
        self.assertEqual(paths, (self.paths['localkeys'], self.paths['vaultkeys']))
        transit.assert_called_once_with('http://fixture.invalid', 'not-a-secret', mount='transit')
        self.assertFalse((remote / 'cosign.key').exists())
        self.assertFalse((remote / 'cosign.pub').exists())
        config = json.loads(self.paths['vaultkeys'].read_text())
        self.assertEqual(config['provenance'], self.configs['localkeys']['provenance'])
        bundle = json.loads((remote / 'signed-policy.json').read_text())
        body = json.loads(decode(bundle['payload']))
        self.assertEqual(body['expiresAt'], self.now + 3600)
        self.assertEqual(body['document']['identityTrust'], self.documents['vaultkeys']['identityTrust'])
        self.assertEqual(json.loads((remote / 'ledger-registration.json').read_text())['policy']['digest'], sha(canonical(bundle)))
        self.assertEqual(make_plan(*paths)['kind'], 'matched-local-vault-custody')

    def test_missing_credentials_and_existing_directory_fail_before_preparation(self):
        output = self.root / 'fresh'
        with patch.dict(os.environ, {}, clear=True), \
                patch('prepare_custody_research.prepare') as prepare:
            with self.assertRaises(KeyError):
                prepare_custody(output)
            self.assertFalse(output.exists())
            prepare.assert_not_called()
        with patch.dict(os.environ, {'VAULT_ADDR': 'http://fixture.invalid', 'VAULT_TOKEN': 'not-a-secret'}), \
                patch('prepare_custody_research.prepare') as prepare:
            with self.assertRaises(FileExistsError):
                prepare_custody(self.root)
            prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
