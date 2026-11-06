"""Validate retained deployment evidence before declaring a consensus trial passed."""
import argparse
import json
import math
from pathlib import Path


def passing_burst(row, offered):
    """A confirmed FAIL verdict is a commit, but fails this valid-document workload."""
    return (
        row.get('warmup') is False and row.get('trial') == 0
        and row.get('concurrency') == offered and row.get('offered') == offered
        and row.get('successful') == offered and row.get('failed') == 0
        and row.get('policyAllowed') == offered and row.get('policyDenied') == 0
        and row.get('policyUnknown') == 0 and row.get('evidence') == 'fabric-commit-confirmed'
        and isinstance(row.get('durationSeconds'), (int, float))
        and math.isfinite(row['durationSeconds']) and row['durationSeconds'] > 0
    )


def summarize(directory, levels, consensus):
    if (not levels or len(set(levels)) != len(levels)
            or any(type(n) is not int or not 1 <= n <= 10000 for n in levels)):
        raise ValueError('unique integer load levels in [1, 10000] required')
    out = Path(directory)
    rows = [json.loads(line) for line in (out/'load/trials.jsonl').read_text().splitlines() if line]
    # Missing, repeated or unexpected load levels cannot silently count as a full sweep.
    complete = len(rows) == len(levels) and [r.get('concurrency') for r in rows] == levels
    metrics = {}
    for row in rows:
        prefix = 'c'+str(row['concurrency'])
        duration = row.get('durationSeconds')
        if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
            raise ValueError('positive finite burst duration required')
        metrics[prefix+'_committed_tps'] = row['successful']/duration
        metrics[prefix+'_failed'] = row['failed']
        if row.get('trialMeanMs') is not None:
            metrics[prefix+'_latency_ms'] = row['trialMeanMs']
    crash_rows = [json.loads(line) for line in (out/'one-crash/trials.jsonl').read_text().splitlines() if line]
    stopped = all((out/f'orderer-running-{when}-crash-load.txt').read_text().strip() == 'false'
                  for when in ('before', 'after'))
    crash_passed = len(crash_rows) == 1 and passing_burst(crash_rows[0], 3) and stopped
    reconciliation = json.loads((out/'reconciliation.json').read_text())
    # An empty reconciliation has zero divergences; it does not prove SQL/ledger consistency.
    reconciled = (reconciliation.get('divergences') == 0
                  and len(reconciliation.get('records', [])) == sum(levels)+3
                  and all(r.get('status') == 'CONSISTENT' for r in reconciliation['records']))
    network = json.loads((out/'network-metadata.json').read_text())
    topology = network.get('consensus') == consensus and network.get('ordererCount') == 4
    successful = (complete and all(passing_burst(row, level) for row, level in zip(rows, levels))
                  and crash_passed and reconciled and topology)
    return {
        'successful': successful, 'metrics': metrics,
        'evidence': 'fabric-commit-confirmed' if successful else 'incomplete-consensus-validation',
        'consensus': network['consensus'], 'channelConfigSHA256': network['channelConfigSha256'],
        'oneOrdererCrashPassed': crash_passed,
        'validation': {'completeSweep': complete, 'fourNodeTopology': topology,
                       'ordererStoppedAtBurstBoundaries': stopped, 'allRecordsReconciled': reconciled},
        'custody': 'research-local-keys',
        'limitations': ['colocated development certificates', 'crash test is not Byzantine attack simulation',
                        'private transient state erased after public evidence capture'],
    }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--levels', required=True)
    parser.add_argument('--consensus', choices=['BFT', 'etcdraft'], required=True)
    args = parser.parse_args()
    report = summarize(args.directory, [int(n) for n in args.levels.split(',')], args.consensus)
    Path(args.directory, 'measurement.json').write_text(json.dumps(report, indent=2, allow_nan=False)+'\n')
