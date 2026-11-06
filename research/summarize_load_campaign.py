"""Export observed client-confirmed load results, including failed deployments.

Each finalized campaign is verified first. Missing bursts and crashed clients
have unknown outcomes; they are never zero-imputed. Completed bursts with zero
confirmed acknowledgements contribute their observed zero client throughput.
"""
import argparse
import csv
import json
import math
from pathlib import Path

from vendorchain.stats import summarize
from verify_campaign import digest, verify


POLICY_FIELDS = ('policyAllowed', 'policyDenied', 'policyUnknown')
BURST_FIELDS = ('concurrency', 'offered', 'successful', 'failed', *POLICY_FIELDS,
                'durationSeconds', 'trialMeanMs', 'evidence')


def validate_burst(row, levels):
    level = row.get('concurrency')
    if type(level) is not int or level not in levels:
        raise ValueError('unexpected load concurrency')
    if row.get('warmup') is not False or type(row.get('trial')) is not int or row['trial'] != 0:
        raise ValueError('each deployment requires one measured burst per load level')
    for name in ('offered', 'successful', 'failed'):
        if type(row.get(name)) is not int or row[name] < 0:
            raise ValueError('nonnegative integer request counts required')
    if row['offered'] != level or row['successful'] + row['failed'] != row['offered']:
        raise ValueError('offered, acknowledged and failed request counts disagree')
    duration, latency = row.get('durationSeconds'), row.get('trialMeanMs')
    if type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0:
        raise ValueError('positive finite burst duration required')
    if row.get('evidence') == 'trial-crash':
        if row['successful'] != 0 or latency is not None:
            raise ValueError('crashed client cannot assert measured acknowledgement counts')
        return row
    policy = [row.get(name) for name in POLICY_FIELDS]
    if any(type(value) is not int or value < 0 for value in policy) or sum(policy) != row['successful']:
        raise ValueError('acknowledged policy verdict counts disagree')
    if row['successful']:
        if type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0:
            raise ValueError('acknowledged bursts require finite nonnegative mean latency')
    elif latency is not None:
        raise ValueError('zero-acknowledgement bursts cannot have acknowledged mean latency')
    return row


def verify_requests(path, row):
    data = json.loads(path.read_text()); summary = data['summary']; requests = data['requests']
    if not isinstance(requests, list) or len(requests) != row['offered']:
        raise ValueError('raw request count disagrees with burst')
    for key in BURST_FIELDS:
        if summary.get(key) != row[key]:
            raise ValueError('raw request summary disagrees with load journal: ' + key)
    ids = set(); acknowledged = []
    for request in requests:
        record_id = request.get('recordID')
        if not isinstance(record_id, str) or not record_id or record_id in ids:
            raise ValueError('unique raw request identifiers required')
        ids.add(record_id)
        if type(request.get('success')) is not bool:
            raise ValueError('explicit raw request outcome required')
        latency = request.get('latencyMs')
        if type(latency) not in (int, float) or not math.isfinite(latency) or latency < 0:
            raise ValueError('finite nonnegative raw request latency required')
        if request['success']:
            if not isinstance(request.get('transactionID'), str) or not request['transactionID']:
                raise ValueError('acknowledged request requires retained transaction identifier')
            acknowledged.append(request)
    if len(acknowledged) != row['successful']:
        raise ValueError('raw acknowledgement count disagrees with burst')
    verdicts = [sum(request.get('decision') == verdict for request in acknowledged) for verdict in ('PASS', 'FAIL')]
    verdicts.append(len(acknowledged) - sum(verdicts))
    if verdicts != [row[key] for key in POLICY_FIELDS]:
        raise ValueError('raw policy verdicts disagree with burst')
    if acknowledged:
        latency = sum(request['latencyMs'] for request in acknowledged) / len(acknowledged)
        if not math.isclose(latency, row['trialMeanMs'], rel_tol=1e-12, abs_tol=1e-12):
            raise ValueError('raw acknowledged latency disagrees with burst')


def metric(values, unit):
    return {**summarize(values), 'unit': unit} if values else None


def summarize_campaign(directory, levels):
    if (not levels or len(set(levels)) != len(levels)
            or any(type(level) is not int or not 1 <= level <= 10000 for level in levels)):
        raise ValueError('unique load levels in [1, 10000] required')
    root = Path(directory).resolve(strict=True); verified = verify(root)
    manifest = json.loads((root / 'sha256-manifest.json').read_text())
    metadata = json.loads((root / 'metadata.json').read_text()); plan = json.loads((root / 'plan.json').read_text())
    outer_rows = [json.loads(line) for line in (root / 'trials.jsonl').read_text().splitlines() if line.strip()]
    outer = {(row['variant'], row['trial']): row for row in outer_rows if not row['warmup']}
    groups = {}
    for task in plan['tasks']:
        name = task['name']; observed = {level: {} for level in levels}; crashed = {level: {} for level in levels}
        for trial in range(metadata['trials']):
            relative = f'{name}/{trial}/load/trials.jsonl'; path = root / relative
            if relative not in manifest:
                if path.exists():raise ValueError('load journal is not manifest-pinned: ' + relative)
                continue
            seen = set()
            for line in path.read_text().splitlines():
                if not line.strip():continue
                row = validate_burst(json.loads(line), levels); level = row['concurrency']
                if level in seen:raise ValueError('duplicate load level in deployment: ' + relative)
                seen.add(level)
                if row.get('evidence') == 'trial-crash':
                    crashed[level][trial] = row.get('reason', 'client process crashed')
                    continue
                requests = f'{name}/{trial}/load/requests-c{level}-t0.json'
                if requests not in manifest:raise ValueError('raw request file is not manifest-pinned: ' + requests)
                verify_requests(root / requests, row)
                observed[level][trial] = row
        groups[name] = {}
        for level, deployments in observed.items():
            rows = list(deployments.values())
            missing = sorted(set(range(metadata['trials'])) - deployments.keys() - crashed[level].keys())
            groups[name][str(level)] = {
                'expectedDeployments': metadata['trials'], 'observedDeployments': len(rows),
                'missingDeployments': len(missing), 'missingDeploymentTrials': missing,
                'crashedClientDeployments': len(crashed[level]),
                'crashedClientTrials': [{'trial':trial,'reason':reason} for trial,reason in sorted(crashed[level].items())],
                'observedDeploymentTrials': sorted(deployments),
                'observedZeroAcknowledgementDeployments': sum(row['successful'] == 0 for row in rows),
                'failedOuterDeploymentsWithObservedBurst': sum(not outer[name, trial]['successful'] for trial in deployments),
                'offered': sum(row['offered'] for row in rows),
                'clientConfirmedCommits': sum(row['successful'] for row in rows),
                'failedOrUnconfirmed': sum(row['failed'] for row in rows),
                'policyPASS': sum(row['policyAllowed'] for row in rows),
                'policyFAIL': sum(row['policyDenied'] for row in rows),
                'policyUnknown': sum(row['policyUnknown'] for row in rows),
                'evidenceKinds': sorted({row.get('evidence', 'unknown') for row in rows}),
                'metrics': {
                    'clientConfirmedThroughputPerSecond': metric([row['successful'] / row['durationSeconds'] for row in rows], 'client-confirmed acknowledgements per second per deployment burst'),
                    'failedOrUnconfirmedFraction': metric([row['failed'] / row['offered'] for row in rows], 'failed or unconfirmed fraction per completed deployment burst'),
                    'clientConfirmedMeanLatencyMs': metric([row['trialMeanMs'] for row in rows if row['successful']], 'mean client-confirmed acknowledgement latency per deployment burst (ms)'),
                },
            }
    return {
        'kind': 'observed-load-bursts-across-deployments', 'sourceManifestSHA256': digest(root / 'sha256-manifest.json'),
        'sourceCommit': verified.get('sourceCommit'), 'sourceDirty': verified.get('sourceDirty'),
        'sourceIntegrityVerified': True, 'levels': levels,
        'measuredDeploymentsPerVariant': metadata['trials'], 'discardedWarmupDeploymentsPerVariant': metadata['warmups'],
        'variants': groups, 'qualifiedForPaper': False,
        'measurementBoundary': 'Completed client bursts from all measured deployments regardless of outer success. Missing bursts and crashed client outcomes remain unknown. Observed zero-acknowledgement bursts contribute zero client throughput. Each deployment is one replicate per load level.',
        'limitations': 'Client confirmations do not count every ledger commit: lost acknowledgements can hide committed transactions. Crashed client synthetic zero counts are excluded. Latency includes deployments with acknowledgements only, with explicit n. Policy counts refer to acknowledged verdicts. Intervals are unadjusted Student-t intervals and do not establish independence, representative workloads, production consensus or authenticity.',
    }


def export_report(report, output, source):
    out = Path(output).resolve(); root = Path(source).resolve(strict=True)
    if out.is_relative_to(root):raise ValueError('load exports must use a separate output directory outside the source campaign')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'summary.json').write_text(json.dumps(report, indent=2, allow_nan=False)+'\n')
    with (out / 'summary.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        counts = ['expectedDeployments', 'observedDeployments', 'missingDeployments', 'crashedClientDeployments',
                  'observedZeroAcknowledgementDeployments', 'failedOuterDeploymentsWithObservedBurst',
                  'offered', 'clientConfirmedCommits', 'failedOrUnconfirmed', 'policyPASS', 'policyFAIL', 'policyUnknown']
        writer.writerow(['variant', 'concurrency', *counts, 'metric', 'n', 'mean', 'stddev', 'median', 'p50', 'p95', 'p99', 'ci95_low', 'ci95_high'])
        for variant, groups in report['variants'].items():
            for level, group in groups.items():
                for name, summary in group['metrics'].items():
                    values = [summary[key] for key in ('n', 'mean', 'stddev', 'median', 'p50', 'p95', 'p99')] if summary is not None else [0, None, None, None, None, None, None]
                    interval = summary['ci95'] if summary is not None else None
                    writer.writerow([variant, level, *(group[key] for key in counts), name, *values, *(interval or [None, None])])
    hashes = {path.name: digest(path) for path in sorted(out.iterdir()) if path.is_file()}
    (out / 'sha256-manifest.json').write_text(json.dumps(hashes, indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory'); parser.add_argument('--levels', required=True, help='Declared concurrency levels, comma-separated')
    parser.add_argument('--output', required=True); args = parser.parse_args()
    try:
        report = summarize_campaign(args.directory, [int(value) for value in args.levels.split(',')])
        export_report(report, args.output, args.directory)
        print(json.dumps({'output': str(Path(args.output).resolve()), 'qualifiedForPaper': False}))
    except (ValueError, KeyError, TypeError, OSError) as exc:
        parser.exit(1, 'Load summary failed: ' + str(exc) + '\n')
