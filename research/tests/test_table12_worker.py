import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from table12_worker import run


class WorkerProvenanceTests(unittest.TestCase):
    def test_external_input_and_config_provenance_are_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root/'config.json'; config.write_text('{}')
            document = root/'document.bin'; document.write_bytes(b'public inert fixture')
            def configured(*args, root_override, **kwargs):
                root_override.mkdir(parents=True)
                return SimpleNamespace(root=root_override, store=SimpleNamespace(), policy_hash=lambda: 'a'*64)
            with patch.dict(os.environ, {'VENDORCHAIN_TRIAL_DIR': str(root/'out')}), \
                    patch('table12_worker.configured', side_effect=configured):
                row = run('baseline', config, input_file=document, local=True)
            self.assertTrue(row['successful'])
            self.assertEqual(row['inputKind'], 'external-file')
            self.assertEqual(row['inputSHA256'], hashlib.sha256(document.read_bytes()).hexdigest())
            self.assertEqual(row['configSHA256'], hashlib.sha256(config.read_bytes()).hexdigest())
            self.assertEqual(row['signedPolicySHA256'], 'a'*64)
            self.assertEqual(json.loads((root/'out/measurement.json').read_text()), row)

    def test_config_change_during_initialization_stops_trial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root/'config.json'; config.write_text('{}')
            def changed(*args, **kwargs):
                config.write_text('{"changed":true}')
                return SimpleNamespace()
            with patch.dict(os.environ, {'VENDORCHAIN_TRIAL_DIR': str(root/'out')}), \
                    patch('table12_worker.configured', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'configuration changed'):
                    run('baseline', config, local=True)
            self.assertFalse((root/'out/measurement.json').exists())
