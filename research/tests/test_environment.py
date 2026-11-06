from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from importlib import metadata

from check_environment import check, requirements, ROOT


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.pins = requirements(ROOT/'research/requirements.txt')

    @staticmethod
    def run_command(argv, **kwargs):
        outputs = {'tesseract': 'tesseract 5.3.0', 'pdftoppm': 'pdftoppm version 22.12.0',
                   'opa': 'Version: 1.4.2', 'cosign': 'GitVersion: v2.4.3', 'syft': 'Version: 1.55.0',
                   'git': 'git version 2.43.0', 'node': 'v22.12.0', 'go': 'go version go1.23.12 linux/amd64',
                   'npm': '10.9.0', 'docker': '28.0.0', 'bash': 'GNU bash, version 5.2.0',
                   'curl': 'curl 8.0.0', 'flock': 'flock from util-linux 2.39.3'}
        return subprocess.CompletedProcess(argv, 0, outputs[Path(argv[0]).name], '')

    def checks(self, *, version=None, which=None, run=None, consensus=False, root=ROOT):
        with patch('check_environment.platform.system', return_value='Linux'), \
             patch('check_environment.platform.machine', return_value='x86_64'), \
             patch('check_environment.metadata.version', side_effect=version or self.pins.__getitem__), \
             patch('check_environment.shutil.which', side_effect=which or (lambda x: '/bin/' + x)), \
             patch('check_environment.subprocess.run', side_effect=run or self.run_command), \
             patch('PIL.ImageFont.truetype'):
            return check(consensus=consensus, root=root)

    def test_readiness_with_complete_local_prerequisites(self):
        report = self.checks()
        self.assertTrue(report['ready'])
        self.assertEqual(report['mode'], 'local')
        self.assertNotIn('docker-daemon', {c['name'] for c in report['checks']})

    def test_missing_binary_and_version_mismatch_fail_readiness(self):
        def version(name):
            return '0.0.1' if name == 'Pillow' else self.pins[name]
        report = self.checks(version=version, which=lambda x: None if x == 'syft' else '/bin/' + x)
        checks = {c['name']: c for c in report['checks']}
        self.assertFalse(report['ready'])
        self.assertEqual(checks['syft']['status'], 'missing')
        self.assertEqual(checks['python:Pillow']['status'], 'failed')

    def test_missing_python_distribution_is_visible(self):
        def version(name):
            if name == 'psycopg-binary':
                raise metadata.PackageNotFoundError(name)
            return self.pins[name]
        report = self.checks(version=version)
        self.assertFalse(report['ready'])
        self.assertEqual(next(c for c in report['checks'] if c['name'] == 'python:psycopg-binary')['status'], 'missing')

    def test_tool_pin_mismatch_fails(self):
        def run(argv, **kwargs):
            if Path(argv[0]).name == 'opa':
                return subprocess.CompletedProcess(argv, 0, 'Version: 1.4.3', '')
            return self.run_command(argv, **kwargs)
        self.assertFalse(self.checks(run=run)['ready'])

    def test_timeout_is_a_failed_check(self):
        def run(argv, **kwargs):
            if Path(argv[0]).name == 'syft':
                raise subprocess.TimeoutExpired(argv, 15)
            return self.run_command(argv, **kwargs)
        report = self.checks(run=run)
        self.assertFalse(report['ready'])
        item = next(c for c in report['checks'] if c['name'] == 'syft')
        self.assertEqual(item['error'], 'TimeoutExpired')

    def test_unavailable_docker_daemon_cannot_report_ready(self):
        def run(argv, **kwargs):
            if argv[1:2] == ['version'] and Path(argv[0]).name == 'docker':
                return subprocess.CompletedProcess(argv, 1, '', 'Cannot connect to Docker daemon')
            return self.run_command(argv, **kwargs)
        report = self.checks(consensus=True, run=run)
        self.assertFalse(report['ready'])
        checks = {c['name']: c for c in report['checks']}
        self.assertEqual(checks['docker-daemon']['status'], 'failed')
        self.assertIn('repository:research/gateway/node_modules/@hyperledger/fabric-gateway/package.json', checks)

    def test_binary_extra_and_unpinned_requirements(self):
        self.assertEqual(self.pins['psycopg'], self.pins['psycopg-binary'])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'requirements.txt'
            path.write_text('Pillow>=12\n')
            with self.assertRaises(ValueError):
                requirements(path)


if __name__ == '__main__':
    unittest.main()
