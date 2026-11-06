import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

from experiment import campaign
from verify_campaign import verify


class CampaignVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        worker = root / 'worker.py'
        worker.write_text("import json,os\nfrom pathlib import Path\n"
                          "Path(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text("
                          "json.dumps({'successful':True,'metrics':{'elapsed_ms':1.5},'evidence':'test-only'}))\n")
        plan = root / 'plan.json'
        plan.write_text(json.dumps({'tasks': [{'name': 'a', 'command': [sys.executable, str(worker)]}]}))
        self.out = root / 'out'
        campaign(plan, self.out, trials=2, warmups=1, smoke=True)

    def repin(self, name):
        path = self.out / 'sha256-manifest.json'
        manifest = json.loads(path.read_text())
        manifest[name] = hashlib.sha256((self.out / name).read_bytes()).hexdigest()
        path.write_text(json.dumps(manifest))

    def test_verifies_real_process_evidence_without_qualifying_smoke(self):
        result = verify(self.out)
        self.assertTrue(result['integrityVerified'])
        self.assertEqual(result['measuredTrials'], 2)
        self.assertEqual(result['discardedWarmups'], 1)
        self.assertFalse(result['countProtocolMet'])
        self.assertFalse(result['qualifiedForPaper'])

    def test_tampered_raw_file_rejected(self):
        (self.out / 'a/0/measurement.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            verify(self.out)

    def test_missing_trial_cannot_be_hidden_by_rehashing(self):
        journal = self.out / 'trials.jsonl'
        journal.write_text('\n'.join(journal.read_text().splitlines()[1:]) + '\n')
        self.repin('trials.jsonl')
        with self.assertRaisesRegex(ValueError, 'incomplete journal'):
            verify(self.out)

    def test_rehashed_summary_and_export_still_must_reproduce(self):
        path = self.out / 'summary.json'
        report = json.loads(path.read_text())
        report['variants']['a']['metrics']['elapsed_ms']['mean'] = 12345
        path.write_text(json.dumps(report))
        self.repin('summary.json')
        with self.assertRaisesRegex(ValueError, 'does not reproduce'):
            verify(self.out)

    def test_rehashed_csv_must_match_computed_statistics(self):
        (self.out / 'summary.csv').write_text('invented,results\n')
        self.repin('summary.csv')
        with self.assertRaisesRegex(ValueError, 'export disagrees'):
            verify(self.out)

    def test_manifest_cannot_read_outside_campaign_or_follow_symlinks(self):
        path = self.out / 'sha256-manifest.json'
        original = path.read_bytes()
        manifest = json.loads(original)
        manifest['../outside'] = '0' * 64
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'unsafe manifest path'):
            verify(self.out)
        path.write_bytes(original)
        target = self.out / 'a/0/measurement.json'
        content = target.read_bytes()
        external = self.out.parent / 'external.json'
        external.write_bytes(content)
        target.unlink()
        target.symlink_to(external)
        with self.assertRaisesRegex(ValueError, 'unsafe evidence file'):
            verify(self.out)

    def test_crashed_trial_verifies_without_worker_measurement(self):
        plan = self.out.parent / 'bad-plan.json'
        plan.write_text(json.dumps({'tasks': [{'name': 'bad', 'command': [sys.executable, '-c', 'raise RuntimeError()']}]}))
        target = self.out.parent / 'failed'
        campaign(plan, target, trials=1, warmups=0, smoke=True)
        result = verify(target)
        self.assertEqual(result['failedMeasuredTrials'], 1)
        self.assertFalse(result['countProtocolMet'])

    def test_legacy_measurements_verify_without_parent_records(self):
        metadata = self.out/'metadata.json'
        meta = json.loads(metadata.read_text()); meta.pop('trialRecordVersion')
        metadata.write_text(json.dumps(meta))
        summary = self.out/'summary.json'
        report = json.loads(summary.read_text()); report['protocol'] = meta
        summary.write_text(json.dumps(report))
        manifest_path = self.out/'sha256-manifest.json'
        manifest = json.loads(manifest_path.read_text())
        for path in self.out.glob('a/*/record.json'):
            manifest.pop(path.relative_to(self.out).as_posix()); path.unlink()
        manifest_path.write_text(json.dumps(manifest))
        self.repin('metadata.json'); self.repin('summary.json')
        self.assertTrue(verify(self.out)['integrityVerified'])

    def test_current_protocol_requires_parent_record(self):
        path = self.out/'a/0/record.json'; path.unlink()
        manifest_path = self.out/'sha256-manifest.json'
        manifest = json.loads(manifest_path.read_text()); manifest.pop('a/0/record.json')
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'durable record'):
            verify(self.out)

    def test_extra_trial_evidence_cannot_be_ignored(self):
        extra = self.out/'a/99'; extra.mkdir()
        (extra/'measurement.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'unexpected or unpinned'):
            verify(self.out)
        self.repin('a/99/measurement.json')
        with self.assertRaisesRegex(ValueError, 'unexpected or unpinned'):
            verify(self.out)

    def update_row(self, **fields):
        journal = self.out/'trials.jsonl'
        rows = [json.loads(line) for line in journal.read_text().splitlines()]
        row = next(r for r in rows if r['trial'] == 0); row.update(fields)
        journal.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        (self.out/'a/0/record.json').write_text(json.dumps(row))
        self.repin('trials.jsonl'); self.repin('a/0/record.json')

    def test_worker_provenance_must_match_journal(self):
        self.update_row(evidence='fabric-commit-confirmed')
        with self.assertRaisesRegex(ValueError, 'worker measurement disagrees'):
            verify(self.out)

    def test_successful_trial_cannot_have_failed_exit_code(self):
        self.update_row(exitCode=1)
        with self.assertRaisesRegex(ValueError, 'nonzero process exit code'):
            verify(self.out)

    def test_custody_provenance_must_match_predeclared_plan(self):
        worker = self.out.parent/'custody-worker.py'
        fields = dict(configSHA256='a'*64, registrySHA256='b'*64,
                      signedPolicySHA256='c'*64, sourceArtifactSHA256='d'*64)
        worker.write_text("import json,os,sys\nfrom pathlib import Path\n"
            "row="+repr({**fields,'successful':True,'metrics':{'elapsed_ms':1.0},
                          'evidence':'local-non-consensus','operationalStore':'Store'})+"\n"
            "row['custody']='research-local-keys' if sys.argv[1]=='localkeys' else 'configured-remote-service'\n"
            "Path(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps(row))\n")
        plan = self.out.parent/'custody-plan.json'
        names = ['localkeys','vaultkeys']
        plan.write_text(json.dumps({'kind':'matched-local-vault-custody',
            'tasks':[{'name':name,'command':[sys.executable,str(worker),name]} for name in names],
            'provenance':{'configurations':{name:fields for name in names}}}))
        target = self.out.parent/'custody'
        campaign(plan,target,trials=1,warmups=0,smoke=True)
        self.assertTrue(verify(target)['integrityVerified'])
        for name in ('measurement.json','record.json'):
            path=target/'vaultkeys/0'/name
            row=json.loads(path.read_text());row['registrySHA256']='e'*64
            path.write_text(json.dumps(row))
        journal=target/'trials.jsonl'
        rows=[json.loads(line) for line in journal.read_text().splitlines()]
        next(r for r in rows if r['variant']=='vaultkeys')['registrySHA256']='e'*64
        journal.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        manifest_path=target/'sha256-manifest.json';manifest=json.loads(manifest_path.read_text())
        for name in ('vaultkeys/0/measurement.json','vaultkeys/0/record.json','trials.jsonl'):
            manifest[name]=hashlib.sha256((target/name).read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError,'custody measurement differs'):
            verify(target)
