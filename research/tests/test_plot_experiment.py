import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from experiment import campaign
from plot_experiment import captions, plot
from verify_campaign import verify


class PlotExperimentTests(unittest.TestCase):
    def test_consensus_captions_do_not_claim_local_synthetic_or_sqlite(self):
        report = {'kind': 'sequential-independent-consensus-deployments', 'protocol': {}}
        rows = [{'variant': 'bft', 'trial': 0, 'successful': True, 'warmup': False,
                 'evidence': 'fabric-commit-confirmed', 'consensus': 'BFT'}]
        with tempfile.TemporaryDirectory() as tmp:
            title, note, consensus = captions(report, rows, tmp)
        self.assertTrue(consensus); self.assertIn('Consensus deployment', title)
        self.assertIn('input provenance unspecified', note); self.assertNotIn('SQLite', note); self.assertNotIn('synthetic', note)

    def test_external_input_review_is_never_inferred_from_hash(self):
        rows = [{'variant': 'full', 'trial': 0, 'successful': True, 'warmup': False,
                 'evidence': 'local-non-consensus', 'inputSHA256': hashlib.sha256(b'file').hexdigest()}]
        with tempfile.TemporaryDirectory() as tmp:
            title, note, consensus = captions({'kind': 'table12', 'protocol': {'randomizationSeed': 1}}, rows, tmp)
        self.assertFalse(consensus); self.assertIn('Local', title)
        self.assertIn('input provenance unspecified', note); self.assertIn('randomized trial blocks', note)

    def test_explicit_synthetic_and_storage_metadata_are_used(self):
        rows = [{'variant': 'full', 'trial': 0, 'successful': True, 'warmup': False,
                 'inputKind': 'generated-synthetic-png', 'operationalStore': 'Store',
                 'evidence': 'local-non-consensus'}]
        with tempfile.TemporaryDirectory() as tmp:
            _, note, _ = captions({'kind': 'table12'}, rows, tmp)
        self.assertIn('generated synthetic PNG inputs', note)
        self.assertIn('SQLite (Store)', note)
        rows[0].update(inputKind='external-file', operationalStore='PostgresStore')
        with tempfile.TemporaryDirectory() as tmp:
            _, note, _ = captions({'kind': 'table12'}, rows, tmp)
        self.assertIn('external-file inputs; review provenance unspecified', note)
        self.assertIn('PostgreSQL (PostgresStore)', note)
        self.assertNotIn('synthetic', note)

    def test_all_failed_campaign_plots_without_invented_measurements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); plan = root/'plan.json'
            plan.write_text(json.dumps({'tasks': [{'name': 'full', 'command': [sys.executable, '-c', 'raise RuntimeError()']}]}))
            campaign(plan, root/'out', trials=1, warmups=0, smoke=True)
            summary = (root/'out/summary.json').read_bytes(); report = plot(root/'out')
            self.assertEqual(report['figures'], ['resources.png']); self.assertIn('1/1 measured trials failed', report['note'])
            self.assertEqual((root/'out/summary.json').read_bytes(), summary); self.assertTrue(verify(root/'out')['integrityVerified'])

    def test_consensus_figure_is_pinned_and_summary_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); worker = root/'worker.py'
            worker.write_text("import json,os\nfrom pathlib import Path\nPath(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps({'successful':True,'metrics':{'c100_latency_ms':2.5,'c100_committed_tps':40},'evidence':'fabric-commit-confirmed','consensus':'BFT'}))\n")
            plan = root/'plan.json'; plan.write_text(json.dumps({'kind': 'sequential-independent-consensus-deployments',
                                       'tasks': [{'name': 'bft', 'command': [sys.executable, str(worker)]}]}))
            campaign(plan, root/'out', trials=2, warmups=0, smoke=True)
            summary = (root/'out/summary.json').read_bytes(); report = plot(root/'out')
            self.assertIn('Consensus', report['title']); self.assertEqual((root/'out/summary.json').read_bytes(), summary)
            self.assertTrue(verify(root/'out')['integrityVerified'])
            manifest = json.loads((root/'out/sha256-manifest.json').read_text())
            self.assertEqual(manifest['resources.png'], hashlib.sha256((root/'out/resources.png').read_bytes()).hexdigest())

    def test_tampered_campaign_rejected_before_figures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); plan = root/'plan.json'
            plan.write_text(json.dumps({'tasks': [{'name': 'a', 'command': [sys.executable, '-c', 'raise RuntimeError()']}]}))
            campaign(plan, root/'out', trials=1, warmups=0, smoke=True)
            (root/'out/summary.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                plot(root/'out')
            self.assertFalse((root/'out/resources.png').exists())


if __name__ == '__main__':
    unittest.main()
