import csv
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from plot_custody import lag_one, render
from vendorchain.stats import summarize


class CustodyAnalysisTests(unittest.TestCase):
    def test_lag_uses_adjacent_measured_observations_only(self):
        rows=[{'variant':'localkeys','trial':i,'warmup':i<0,'successful':i!=2,
               'metrics':{'elapsed_ms':value}} for i,value in [(-1,9999),(0,1),(1,2),(2,100),(3,4),(4,5)]]
        result=lag_one(rows,'localkeys')
        self.assertEqual(result['adjacentObservedPairs'],2)
        self.assertAlmostEqual(result['correlation'],1)

    def test_constant_or_missing_series_does_not_invent_correlation(self):
        rows=[{'variant':'localkeys','trial':i,'warmup':False,'successful':True,
               'metrics':{'elapsed_ms':1}} for i in range(3)]
        self.assertIsNone(lag_one(rows,'localkeys')['correlation'])
        self.assertIsNone(lag_one(rows,'vaultkeys')['correlation'])

    def test_figure_preserves_incomplete_pairs_and_source_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'campaign';root.mkdir()
            primary={'name':'vault_custody_cost','metric':'elapsed_ms','difference':summarize([2.,4.]),
                     'missingOrFailedPairs':[1],'complete':False}
            report={'kind':'matched-local-vault-custody','protocol':{'trials':3},
                    'pairedComparisons':{'vault_custody_cost':primary}}
            (root/'summary.json').write_text(json.dumps(report))
            (root/'sha256-manifest.json').write_text('{}')
            rows=[]
            for i in range(3):
                rows.extend([{'variant':arm,'trial':i,'warmup':False,'successful':arm=='localkeys' or i!=1,
                              'metrics':{'elapsed_ms':100+(i+2 if arm=='vaultkeys' else 0)}}
                             for arm in ('localkeys','vaultkeys')])
            (root/'trials.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            before={p.name:p.read_bytes() for p in root.iterdir()}
            output=Path(tmp)/'analysis'
            with patch('plot_custody.verify',return_value={'sourceCommit':'fixture'}):
                result=render(root,output)
            with (output/'paired-observations.csv').open(newline='') as stream:
                pairs=list(csv.DictReader(stream))
            self.assertEqual([int(p['trial']) for p in pairs],[0,2])
            self.assertEqual([float(p['vault_minus_local_ms']) for p in pairs],[2,4])
            self.assertEqual(result['primaryComparison']['missingOrFailedPairs'],[1])
            self.assertEqual(result['lagOneDiagnostics']['pairedElapsedDifferences']['adjacentObservedPairs'],0)
            self.assertTrue((output/'custody-contrasts.pdf').read_bytes().startswith(b'%PDF'))
            self.assertTrue((output/'custody-contrasts.svg').is_file())
            self.assertEqual(before,{p.name:p.read_bytes() for p in root.iterdir()})
