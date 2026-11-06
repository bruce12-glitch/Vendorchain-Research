import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from make_custody_plan import main, make_plan
from vendorchain.crypto import canonical, encode
from vendorchain.evidence import sha, sign_document, tree_hash
from vendorchain.sandbox import OCR_POLICY


class CustodyFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = int(time.time())
        self.paths, self.configs, self.registries, self.keys, self.documents = {}, {}, {}, {}, {}
        common = self.root / 'common'
        common.mkdir()
        (common / 'cosign.pub').write_bytes(b'public Cosign fixture')
        (common / 'cosign.key').write_bytes(b'PRIVATE MUST NOT BE READ')
        for name, remote in [('localkeys', False), ('vaultkeys', True)]:
            base = self.root / name
            base.mkdir()
            artifact = base / 'artifact'
            artifact.mkdir()
            (artifact / 'chaincode.go').write_text('package main\n')
            registry, keys, signers = {}, {}, {}
            for role in ('identity', 'decision', 'policy'):
                key_id = name + '-' + role
                key = Ed25519PrivateKey.generate()
                keys[role] = key
                registry[key_id] = {'keyID': key_id, 'publicKey': encode(key.public_key().public_bytes_raw()),
                                    'role': role, 'notBefore': self.now - 60, 'notAfter': self.now + 3600,
                                    'revoked': False}
                signers[role] = ({'kind': 'vault-transit', 'keyID': key_id, 'key': key_id,
                                  'version': 1, 'addressEnv': 'VAULT_ADDR', 'tokenEnv': 'VAULT_TOKEN'}
                                 if remote else {'kind': 'research-file', 'keyID': key_id, 'file': role + '.private'})
            provenance = {'privateURI': str(common / 'cosign.key'), 'publicFile': str(common / 'cosign.pub'),
                          'publicSHA256': sha((common / 'cosign.pub').read_bytes()),
                          'notBefore': self.now - 60, 'notAfter': self.now + 3600}
            self.configs[name] = {
                'researchLocalKeys': not remote, 'state': 'pipeline', 'registry': 'registry.json',
                'policyBundle': 'signed-policy.json', 'signers': signers, 'retentionSeconds': 86400,
                'kek': ({'kind': 'vault-transit', 'key': 'vault-kek', 'addressEnv': 'VAULT_ADDR', 'tokenEnv': 'VAULT_TOKEN'}
                        if remote else {'kind': 'research-file', 'file': 'master.hex'}),
                'gstin': '27AAPFU0939F1ZV', 'expectedPan': 'AAPFU0939F',
                'expectedTerms': ['VENDORCHAIN', '27AAPFU0939F1ZV'], 'source': 'artifact', 'provenance': provenance}
            source = b'package vendorchain.authorization\nallow := true\n'
            self.documents[name] = {
                'policyVersion': 'test-policy-v1', 'opaVersion': '1.4.2',
                'source': encode(source), 'policySHA256': sha(source),
                'query': 'data.vendorchain.authorization.allow',
                'parameters': {'max_components': 10000, 'banned_packages': []},
                'controls': {'ocrPolicy': OCR_POLICY, 'replayRetentionSeconds': 86400},
                'provenanceTrust': {'mode': 'pinned-public-key', **{key: provenance[key] for key in (
                    'publicSHA256', 'notBefore', 'notAfter')}},
                'identityTrust': registry[signers['identity']['keyID']]}
            self.paths[name] = base / 'config.json'
            self.registries[name], self.keys[name] = registry, keys
            self.write_arm(name)

    def write_arm(self, name):
        path = self.paths[name]
        config = self.configs[name]
        path.write_text(json.dumps(config, indent=2))
        (path.parent / 'registry.json').write_bytes(canonical(self.registries[name]))
        bundle = sign_document(self.documents[name], self.keys[name]['policy'],
                               config['signers']['policy']['keyID'], 'vendorchain.policy.v1',
                               now=self.now, ttl=1800)
        (path.parent / 'signed-policy.json').write_bytes(canonical(bundle))

    def plan(self):
        return make_plan(self.paths['localkeys'], self.paths['vaultkeys'])


class CustodyPlanTests(CustodyFixture):
    def test_plan_uses_existing_full_worker_and_paired_elapsed_comparison(self):
        plan = self.plan()
        local, remote = plan['tasks']
        self.assertEqual([local['name'], remote['name']], ['localkeys', 'vaultkeys'])
        for task in plan['tasks']:
            self.assertEqual(task['command'][0], sys.executable)
            self.assertEqual(Path(task['command'][1]).name, 'table12_worker.py')
            self.assertEqual(task['command'][2:4], ['--variant', 'full'])
            self.assertIn('--local', task['command'])
        self.assertIn('--allow-local-keys', local['command'])
        self.assertNotIn('--allow-local-keys', remote['command'])
        self.assertEqual(plan['comparisons'][0], {'name': 'vault_custody_cost', 'control': 'localkeys',
                                               'treatment': 'vaultkeys', 'metric': 'elapsed_ms'})
        self.assertEqual([c['metric'] for c in plan['comparisons']],
                         ['elapsed_ms','encrypt_ms','decrypt_ms','identity_attestation_ms','attest_ms'])
        proof = plan['provenance']['configurations']['localkeys']
        self.assertEqual(proof['configSHA256'], sha(self.paths['localkeys'].read_bytes()))
        self.assertEqual(proof['sourceArtifactSHA256'], tree_hash(self.paths['localkeys'].parent / 'artifact'))
        self.assertEqual(plan['provenance']['ledger'], 'local-non-consensus')
        self.assertEqual(plan['provenance']['operationalStore'], 'SQLite')
        self.assertNotIn('trials', plan)

    def test_generation_never_reads_private_files_or_contacts_vault(self):
        private_paths = {self.root / 'common' / 'cosign.key'}
        for role in ('identity', 'decision', 'policy', 'master'):
            path = self.paths['localkeys'].parent / (role + ('.hex' if role == 'master' else '.private'))
            path.write_text('PRIVATE MUST NOT BE READ')
            private_paths.add(path)
        original_bytes, original_text = Path.read_bytes, Path.read_text
        def guarded_bytes(path, *args, **kwargs):
            self.assertNotIn(path.resolve(), private_paths)
            return original_bytes(path, *args, **kwargs)
        def guarded_text(path, *args, **kwargs):
            self.assertNotIn(path.resolve(), private_paths)
            return original_text(path, *args, **kwargs)
        with patch.object(Path, 'read_bytes', guarded_bytes), patch.object(Path, 'read_text', guarded_text), \
                patch('vendorchain.kms.VaultTransit', side_effect=AssertionError('must not contact Vault')):
            plan = self.plan()
        self.assertNotIn('PRIVATE MUST NOT BE READ', json.dumps(plan))

    def test_rejects_mixed_or_falsely_declared_custody(self):
        original = copy.deepcopy(self.configs)
        cases = [('localkeys', 'researchLocalKeys', False), ('vaultkeys', 'researchLocalKeys', True),
                 ('localkeys', 'researchLocalKeys', 1)]
        for name, field, value in cases:
            with self.subTest(name=name, field=field, value=value):
                self.configs = copy.deepcopy(original)
                self.configs[name][field] = value
                self.write_arm(name)
                with self.assertRaisesRegex(ValueError, 'declare'):
                    self.plan()
                self.configs = copy.deepcopy(original)
                self.write_arm(name)
        for role in ('kek', 'identity', 'decision', 'policy'):
            with self.subTest(role=role):
                self.configs = copy.deepcopy(original)
                spec = self.configs['vaultkeys']['kek'] if role == 'kek' else self.configs['vaultkeys']['signers'][role]
                spec['kind'] = 'research-file'
                self.write_arm('vaultkeys')
                with self.assertRaisesRegex(ValueError, 'custody mode'):
                    self.plan()

    def test_rejects_postgres_even_when_both_configs_declare_it(self):
        for name in self.paths:
            self.configs[name]['postgresDsnEnv'] = 'DATABASE_URL'
            self.write_arm(name)
        with self.assertRaisesRegex(ValueError, 'SQLite'):
            self.plan()

    def test_rejects_different_artifact_and_identity_expectations(self):
        source = self.paths['vaultkeys'].parent / 'artifact' / 'chaincode.go'
        source.write_text('different bytes')
        with self.assertRaisesRegex(ValueError, 'artifact trees'):
            self.plan()
        source.write_text('package main\n')
        for field, value in [('gstin', 'DIFFERENT'), ('expectedPan', 'DIFFERENT'), ('expectedTerms', ['DIFFERENT'])]:
            old = self.configs['vaultkeys'][field]
            self.configs['vaultkeys'][field] = value
            self.write_arm('vaultkeys')
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'semantics'):
                self.plan()
            self.configs['vaultkeys'][field] = old
            self.write_arm('vaultkeys')

    def test_rejects_signed_policy_parameter_source_and_control_confounds(self):
        original = copy.deepcopy(self.documents['vaultkeys'])
        for field, value in [('parameters', {'max_components': 2, 'banned_packages': []}),
                             ('source', encode(b'package different')), ('controls', {})]:
            self.documents['vaultkeys'] = copy.deepcopy(original)
            self.documents['vaultkeys'][field] = value
            if field == 'source':
                self.documents['vaultkeys']['policySHA256'] = sha(b'package different')
            self.write_arm('vaultkeys')
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.plan()

    def test_rejects_policy_tampering_and_unbound_identity_trust(self):
        bundle_path = self.paths['vaultkeys'].parent / 'signed-policy.json'
        envelope = json.loads(bundle_path.read_text())
        envelope['signature'] = encode(bytes(64))
        bundle_path.write_bytes(canonical(envelope))
        with self.assertRaises(InvalidSignature):
            self.plan()
        self.documents['vaultkeys']['identityTrust'] = self.documents['localkeys']['identityTrust']
        self.write_arm('vaultkeys')
        with self.assertRaisesRegex(ValueError, 'identity trust'):
            self.plan()

    def test_requires_one_common_local_cosign_key_and_matching_public_trust(self):
        original = copy.deepcopy(self.configs['vaultkeys']['provenance'])
        self.configs['vaultkeys']['provenance']['privateURI'] = str(self.root / 'another.key')
        self.write_arm('vaultkeys')
        with self.assertRaisesRegex(ValueError, 'same local Cosign'):
            self.plan()
        self.configs['vaultkeys']['provenance'] = original
        self.documents['vaultkeys']['provenanceTrust']['publicSHA256'] = '0' * 64
        self.write_arm('vaultkeys')
        with self.assertRaisesRegex(ValueError, 'provenance trust'):
            self.plan()

    def test_cli_preserves_existing_plan(self):
        output = self.root / 'plan.json'
        output.write_text('keep existing plan')
        argv = ['make_custody_plan.py', '--local-config', str(self.paths['localkeys']),
                '--vault-config', str(self.paths['vaultkeys']), '--output', str(output)]
        with patch.object(sys, 'argv', argv), self.assertRaises(FileExistsError):
            main()
        self.assertEqual(output.read_text(), 'keep existing plan')


if __name__ == '__main__':
    unittest.main()
