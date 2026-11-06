import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest

from experiment import campaign
from summarize_load_campaign import export_report, summarize_campaign


WORKER = '''import json,os
from pathlib import Path
root=Path(os.environ['VENDORCHAIN_TRIAL_DIR']);index=int(os.environ['VENDORCHAIN_TRIAL_INDEX'])
rows=[]
if index != 2:
 (root/'load').mkdir()
 for level in ([2,4] if index != 1 else [2]):
  committed=level if index != 1 else 0
  row=dict(concurrency=level,trial=0,warmup=False,offered=level,successful=committed,failed=level-committed,
           policyAllowed=committed,policyDenied=0,policyUnknown=0,durationSeconds=2,
           trialMeanMs=10 if committed else None,evidence='fabric-commit-confirmed' if committed else 'local-or-unconfirmed')
  rows.append(row)
  requests=[dict(recordID=str(i),success=i<committed,decision='PASS' if i<committed else None,
                 latencyMs=10,transactionID='tx'+str(i) if i<committed else None) for i in range(level)]
  (root/'load'/('requests-c'+str(level)+'-t0.json')).write_text(json.dumps(dict(summary=row,requests=requests)))
 (root/'load/trials.jsonl').write_text(''.join(json.dumps(row)+'\\n' for row in rows))
root.joinpath('measurement.json').write_text(json.dumps(dict(successful=index!=1 and index!=2,metrics={'outer_latency_ms':1} if index!=2 else {},evidence='fixture-only')))
'''


class LoadCampaignTests(unittest.TestCase):
    def create(self, root, extra=''):
        worker=root/'worker.py';worker.write_text(WORKER+extra)
        plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'raft','command':[sys.executable,str(worker)]}]}))
        campaign(plan,root/'campaign',trials=3,warmups=1,smoke=True)
        return root/'campaign'

    def test_failed_zero_acknowledgement_and_missing_deployments_remain_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.create(root)
            report=summarize_campaign(source,[2,4,8]);group=report['variants']['raft']['2']
            self.assertEqual(group['observedDeployments'],2);self.assertEqual(group['missingDeploymentTrials'],[2])
            self.assertEqual(group['failedOuterDeploymentsWithObservedBurst'],1)
            self.assertEqual(group['offered'],4);self.assertEqual(group['clientConfirmedCommits'],2);self.assertEqual(group['failedOrUnconfirmed'],2)
            self.assertEqual(group['policyPASS'],2);self.assertEqual(group['policyFAIL'],0)
            self.assertEqual(group['observedZeroAcknowledgementDeployments'],1)
            self.assertEqual(group['metrics']['clientConfirmedThroughputPerSecond']['n'],2)
            self.assertEqual(group['metrics']['clientConfirmedThroughputPerSecond']['mean'],.5)
            self.assertEqual(group['metrics']['failedOrUnconfirmedFraction']['mean'],.5)
            self.assertEqual(group['metrics']['clientConfirmedMeanLatencyMs']['n'],1)
            self.assertEqual(report['variants']['raft']['4']['observedDeployments'],1)
            self.assertEqual(report['variants']['raft']['4']['missingDeployments'],2)
            self.assertEqual(report['variants']['raft']['8']['observedDeployments'],0)
            self.assertIsNone(report['variants']['raft']['8']['metrics']['clientConfirmedThroughputPerSecond'])
            self.assertFalse(report['qualifiedForPaper'])
            export_report(report,root/'exports',source)
            with (root/'exports/summary.csv').open(newline='') as stream:rows=list(csv.DictReader(stream))
            self.assertEqual(len(rows),9);self.assertEqual(rows[-1]['n'],'0');self.assertEqual(rows[-1]['mean'],'')
            self.assertTrue((root/'exports/sha256-manifest.json').exists())
            with self.assertRaisesRegex(ValueError,'separate output directory'):export_report(report,source/'extra',source)

    def test_crashed_clients_are_unknown_and_not_measured_zero_throughput(self):
        extra="""if index==1:
 rows[0]['evidence']='trial-crash';rows[0]['reason']='SIGKILL'
 for key in ['policyAllowed','policyDenied','policyUnknown']:rows[0].pop(key)
 (root/'load/trials.jsonl').write_text(json.dumps(rows[0])+'\\n')
"""
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.create(root,extra)
            group=summarize_campaign(source,[2,4])['variants']['raft']['2']
            self.assertEqual(group['observedDeployments'],1);self.assertEqual(group['missingDeployments'],1)
            self.assertEqual(group['crashedClientDeployments'],1)
            self.assertEqual(group['crashedClientTrials'],[{'trial':1,'reason':'SIGKILL'}])
            self.assertEqual(group['metrics']['clientConfirmedThroughputPerSecond']['n'],1)
            self.assertEqual(group['metrics']['clientConfirmedThroughputPerSecond']['mean'],1)

    def test_nested_tampering_fails_source_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.create(root)
            (source/'raft/0/load/trials.jsonl').write_text('')
            with self.assertRaisesRegex(ValueError,'evidence digest mismatch'):summarize_campaign(source,[2,4])

    def test_manifest_pinned_duplicate_levels_and_invalid_counts_rejected(self):
        changes=["if index==0:\n (root/'load/trials.jsonl').write_text(json.dumps(rows[0])+'\\n'+json.dumps(rows[0])+'\\n')\n",
                 "if index==0:\n rows[0]['successful']=-1\n (root/'load/trials.jsonl').write_text(json.dumps(rows[0])+'\\n')\n"]
        for extra in changes:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=self.create(root,extra)
                with self.assertRaises(ValueError):summarize_campaign(source,[2,4])

    def test_missing_or_inconsistent_raw_requests_rejected(self):
        changes=["if index==0:(root/'load/requests-c2-t0.json').unlink()\n",
                 "if index==0:\n p=root/'load/requests-c2-t0.json';data=json.loads(p.read_text());data['requests'][0]['success']=False;p.write_text(json.dumps(data))\n"]
        for extra in changes:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=self.create(root,extra)
                with self.assertRaises(ValueError):summarize_campaign(source,[2,4])

    def test_unpinned_load_journal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=self.create(root)
            load=source/'raft/2/load';load.mkdir();(load/'trials.jsonl').write_text('')
            with self.assertRaisesRegex(ValueError,'not manifest-pinned'):summarize_campaign(source,[2,4])
