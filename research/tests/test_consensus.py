import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from summarize_consensus import summarize

spec = importlib.util.spec_from_file_location('topology', Path(__file__).resolve().parents[1]/'scripts/verify-topology.py')
topology = importlib.util.module_from_spec(spec)
spec.loader.exec_module(topology)


class ConsensusValidationTests(unittest.TestCase):
    def fixture(self, root):
        row = {'warmup':False, 'trial':0, 'concurrency':3, 'offered':3, 'successful':3,
               'failed':0, 'policyAllowed':3, 'policyDenied':0, 'policyUnknown':0,
               'durationSeconds':1, 'trialMeanMs':2, 'evidence':'fabric-commit-confirmed'}
        for directory in ('load', 'one-crash'):
            (root/directory).mkdir()
            (root/directory/'trials.jsonl').write_text(json.dumps(row)+'\n')
        for when in ('before', 'after'):
            (root/f'orderer-running-{when}-crash-load.txt').write_text('false\n')
        (root/'reconciliation.json').write_text(json.dumps({'divergences':0, 'records':[{'status':'CONSISTENT'}]*6}))
        (root/'network-metadata.json').write_text(json.dumps({'consensus':'BFT', 'ordererCount':4, 'channelConfigSha256':'x'}))
        return row

    def test_complete_sweep_and_crash_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            result=summarize(root,[3],'BFT')
            self.assertTrue(result['successful']);self.assertTrue(result['oneOrdererCrashPassed'])
            self.assertEqual(result['metrics']['c3_committed_tps'],3)

    def test_empty_reconciliation_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            (root/'reconciliation.json').write_text('{"divergences":0,"records":[]}')
            result=summarize(root,[3],'BFT')
            self.assertFalse(result['successful']);self.assertFalse(result['validation']['allRecordsReconciled'])

    def test_missing_levels_and_unconfirmed_fault_results_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);row=self.fixture(root)
            self.assertFalse(summarize(root,[3,100],'BFT')['successful'])
            row.update(policyAllowed=0,policyDenied=3)
            (root/'one-crash/trials.jsonl').write_text(json.dumps(row)+'\n')
            result=summarize(root,[3],'BFT')
            self.assertFalse(result['oneOrdererCrashPassed']);self.assertFalse(result['successful'])

    def test_restarted_orderer_and_mislabeled_consensus_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.fixture(root)
            self.assertFalse(summarize(root,[3],'etcdraft')['successful'])
            (root/'orderer-running-after-crash-load.txt').write_text('true\n')
            self.assertFalse(summarize(root,[3],'BFT')['oneOrdererCrashPassed'])

    def test_topology_uses_active_consensus_membership(self):
        members=[{'host':f'o{i}', 'port':7050, 'id':i} for i in range(4)]
        values={'ConsensusType':{'value':{'type':'etcdraft','metadata':{'consenters':members}}},
                'Orderers':{'value':{'consenter_mapping':[{}]*8}}}
        config={'groups':{'Orderer':{'values':values}}}
        self.assertEqual(topology.membership(config),('etcdraft',members))
        config=copy.deepcopy(config)
        config['groups']['Orderer']['values']['ConsensusType']['value']['metadata']['consenters'][1]=members[0]
        with self.assertRaisesRegex(ValueError,'distinct ordering endpoints'):topology.membership(config)

    def test_retained_actual_bft_block_still_validates(self):
        block=json.loads((Path(__file__).resolve().parents[1]/'results/bft-smoke/channel-config.json').read_text())
        consensus,members=topology.membership(block['data']['data'][0]['payload']['data']['config']['channel_group'])
        self.assertEqual(consensus,'BFT');self.assertEqual(len(members),4)
