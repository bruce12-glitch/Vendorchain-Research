import json
from pathlib import Path
import sys
import tempfile
import unittest
from experiment import campaign, summarize_rows, paired_differences


class ExperimentTests(unittest.TestCase):
    def test_pairing_uses_blocks_and_preserves_missing_pairs(self):
        rows=[]
        for i in range(50):
            rows.extend([{'variant':v,'trial':i,'warmup':False,'successful':True,'metrics':{'ms':i+offset}}
                         for v,offset in [('a',0),('b',2)]])
        spec=[{'name':'cost','control':'a','treatment':'b','metric':'ms'}]
        result=paired_differences(rows,spec,50)['cost']
        self.assertEqual(result['difference']['mean'],2);self.assertEqual(result['difference']['n'],50)
        rows[-1]['successful']=False
        self.assertEqual(paired_differences(rows,spec,50)['cost']['missingOrFailedPairs'],[49])
    def test_failed_trials_are_counted_and_warmups_discarded(self):
        rows=[{'variant':'a','warmup':True,'successful':True,'metrics':{'latency_ms':100000}}]
        rows += [{'variant':'a','warmup':False,'successful':True,'metrics':{'latency_ms':i}} for i in range(50)]
        result=summarize_rows(rows,50,1)['a']
        self.assertEqual(result['metrics']['latency_ms']['n'],50)
        self.assertEqual(result['metrics']['latency_ms']['mean'],24.5)
        self.assertFalse(result['countProtocolMet'])
        rows.append({'variant':'a','warmup':False,'successful':False,'metrics':{}})
        self.assertEqual(summarize_rows(rows,51,1)['a']['failedTrials'],1)

    def test_small_runs_require_explicit_smoke(self):
        with self.assertRaises(ValueError):campaign('unused','unused',trials=1,warmups=0)

    def test_real_subprocess_output_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker=root/'worker.py'
            worker.write_text("import json,os\nfrom pathlib import Path\nPath(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps({'successful':True,'metrics':{'elapsed_ms':1.25},'evidence':'test-only'}))\n")
            plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'a','command':[sys.executable,str(worker)]}]}))
            result=campaign(plan,root/'out',trials=2,warmups=1,smoke=True)
            self.assertEqual(result['variants']['a']['metrics']['elapsed_ms']['n'],2)
            self.assertFalse(result['qualifiedForPaper'])
            self.assertTrue((root/'out/tables.tex').exists())
            self.assertTrue((root/'out/sha256-manifest.json').exists())

    def test_crashed_subprocess_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            result=campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            self.assertEqual(result['variants']['bad']['failedTrials'],1)
