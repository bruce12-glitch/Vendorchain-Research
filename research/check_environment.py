"""Read-only prerequisite checks before starting an expensive research campaign.

Readiness covers installed tools, not deployment correctness, credentials, host
isolation, or publication qualification. No images or packages are downloaded.
"""
import argparse
from importlib import metadata
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
# Keep these aligned with the checksum-pinned installers in research/scripts/.
PINNED_TOOLS = {'opa': '1.4.2', 'cosign': '2.4.3', 'syft': '1.55.0'}


def requirements(path):
    """Return installed distribution names and pins, including binary extras."""
    result = {}
    for line in Path(path).read_text().splitlines():
        line = line.partition('#')[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'([A-Za-z0-9_-]+)(\[binary\])?==([0-9][A-Za-z0-9.]+)', line)
        if not match:
            raise ValueError('preflight requires exact distribution pins')
        name, extra, version = match.groups()
        result[name] = version
        if extra:
            if name != 'psycopg':
                raise ValueError('unsupported binary extra')
            result['psycopg-binary'] = version
    return result


def check(consensus=False, root=ROOT):
    root = Path(root)
    checks = []

    def record(name, ready, **details):
        checks.append({'name': name, 'status': 'ready' if ready else 'failed', **details})

    record('platform', platform.system() == 'Linux' and platform.machine() in ('x86_64', 'amd64'),
           observed=platform.system() + '/' + platform.machine(), required='Linux x86_64')
    record('python', sys.version_info >= (3, 12), observed=platform.python_version(), required='>=3.12')
    for name, expected in requirements(root/'research/requirements.txt').items():
        try:
            observed = metadata.version(name)
            record('python:' + name, observed == expected, observed=observed, required=expected)
        except metadata.PackageNotFoundError:
            checks.append({'name': 'python:' + name, 'status': 'missing', 'required': expected})

    def command(name, argv, expected=None, minimum=None, version_pattern=r'(\d+\.\d+(?:\.\d+)?)'):
        binary = shutil.which(argv[0])
        if not binary:
            checks.append({'name': name, 'status': 'missing', 'executable': argv[0]})
            return False
        try:
            proc = subprocess.run([binary, *argv[1:]], capture_output=True, text=True, timeout=15)
            output = proc.stdout + '\n' + proc.stderr
            match = re.search(version_pattern, output)
            observed = match.group(1) if match else None
            valid = proc.returncode == 0 and observed is not None
            if expected is not None:
                valid = valid and observed == expected
            if minimum is not None:
                valid = valid and tuple(map(int, observed.split('.'))) >= minimum
            record(name, bool(valid), observed=observed, required=expected or ('.'.join(map(str, minimum)) + '+' if minimum else 'available'),
                   returncode=proc.returncode)
            return bool(valid)
        except (OSError, subprocess.TimeoutExpired) as exc:
            record(name, False, error=type(exc).__name__)
            return False

    command('tesseract', ['tesseract', '--version'], minimum=(5, 0))
    command('poppler', ['pdftoppm', '-v'])
    command('opa', ['opa', 'version'], expected=PINNED_TOOLS['opa'], version_pattern=r'Version:\s*(\d+\.\d+\.\d+)')
    command('cosign', ['cosign', 'version'], expected=PINNED_TOOLS['cosign'], version_pattern=r'GitVersion:\s*v?(\d+\.\d+\.\d+)')
    command('syft', ['syft', 'version'], expected=PINNED_TOOLS['syft'], version_pattern=r'Version:\s*v?(\d+\.\d+\.\d+)')
    command('git', ['git', '--version'])
    try:
        from PIL import ImageFont
        ImageFont.truetype('DejaVuSansMono.ttf', 44)
        record('synthetic-workload-font', True, required='DejaVuSansMono.ttf')
    except (ImportError, OSError) as exc:
        record('synthetic-workload-font', False, error=type(exc).__name__, required='DejaVuSansMono.ttf')

    for path in ('research/manuscript/listing-1.rego', 'research/schemas/bom-1.5.schema.json',
                 'research/schemas/spdx.schema.json', 'research/schemas/jsf-0.82.schema.json'):
        record('repository:' + path, (root/path).is_file(), required=path)

    if consensus:
        command('node', ['node', '--version'], minimum=(22, 12, 0))
        command('npm', ['npm', '--version'])
        command('go', ['go', 'version'], minimum=(1, 23, 12))
        command('docker-daemon', ['docker', 'version', '--format', '{{.Server.Version}}'])
        command('docker-compose', ['docker', 'compose', 'version', '--short'])
        command('curl', ['curl', '--version'])
        command('bash', ['bash', '--version'])
        command('flock', ['flock', '--version'])
        for path in ('chaincode/go.mod', 'chaincode/go.sum', 'research/gateway/package-lock.json',
                     'research/gateway/node_modules/@hyperledger/fabric-gateway/package.json',
                     'research/gateway/node_modules/@grpc/grpc-js/package.json',
                     'research/scripts/consensus-trial.sh', 'research/plans/consensus.json'):
            record('repository:' + path, (root/path).is_file(), required=path)
    return {'kind': 'research-environment-preflight', 'mode': 'consensus' if consensus else 'local',
            'ready': all(item['status'] == 'ready' for item in checks), 'checks': checks,
            'scope': 'Installed prerequisites only. Deployment, keys, corpus, host isolation and empirical results require separate validation.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consensus', action='store_true', help='also check Docker and Fabric build prerequisites')
    parser.add_argument('--output', help='save the JSON report; stdout always receives the same report')
    args = parser.parse_args()
    report = check(consensus=args.consensus)
    encoded = json.dumps(report, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(encoded)
    print(encoded, end='')
    sys.exit(0 if report['ready'] else 1)
