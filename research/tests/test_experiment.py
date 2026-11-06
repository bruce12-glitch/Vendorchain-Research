import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from experiment import campaign, summarize_rows, paired_differences, durable_text, export


class ExperimentTests(unittest.TestCase):
    def test_paired_exports_preserve_failed_pairs_and_escape_tex(self):
        metric='cost_$%&#{}~^'+chr(92)
        rows=[{'variant':variant,'trial':i,'warmup':False,'successful':not(variant=='b' and i==2),
               'metrics':{metric:i+offset}}
              for i in range(3) for variant,offset in [('a',0),('b',2)]]
        specs=[{'name':metric,'control':'a','treatment':'b','metric':metric},
               {'name':'all_missing','control':'a','treatment':'b','metric':'missing'}]
        report={'variants':summarize_rows(rows,3,0),'pairedComparisons':paired_differences(rows,specs,3)}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);export(root,report)
            with (root/'paired-comparisons.csv').open(newline='') as stream:actual=list(csv.DictReader(stream))
            self.assertEqual(actual[0]['comparison'],metric)
            self.assertEqual(actual[0]['n'],'2');self.assertEqual(actual[0]['mean_difference'],'2')
            self.assertEqual(actual[0]['missing_or_failed_pairs'],'1');self.assertEqual(actual[0]['complete'],'False')
            self.assertEqual(actual[1]['n'],'0');self.assertEqual(actual[1]['mean_difference'],'')
            self.assertEqual(actual[1]['stddev'],'');self.assertEqual(actual[1]['ci95_low'],'')
            self.assertEqual(actual[1]['missing_or_failed_pairs'],'3')
            for filename in ['tables.tex','paired-comparisons.tex']:
                text=(root/filename).read_text()
                self.assertIn(r'cost\_\$\%\&\#\{\}\textasciitilde{}\textasciicircum{}\textbackslash{}',text)
            self.assertIn('no complete pairs',(root/'paired-comparisons.tex').read_text())

    def test_empty_paired_exports_contain_no_data_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);export(root,{'variants':{},'pairedComparisons':{}})
            with (root/'paired-comparisons.csv').open(newline='') as stream:self.assertEqual(list(csv.DictReader(stream)),[])
            text=(root/'paired-comparisons.tex').read_text()
            self.assertEqual(text.count(r'\\'),1)
            self.assertIn(r'\end{tabular}',text)

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
        with self.assertRaisesRegex(ValueError,'duplicate measured trial slot'):
            paired_differences(rows+[rows[0]],spec,50)
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

    def test_invalid_plan_fails_before_creating_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json'
            for task in [{'name':'a','command':'echo hello'},
                         {'name':'a','command':[sys.executable],'timeoutSeconds':0},
                         {'name':'a','command':[sys.executable],'timeoutSeconds':float('nan')}]:
                plan.write_text(json.dumps({'tasks':[task]}))
                with self.assertRaises(ValueError):campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
                self.assertFalse((root/'out').exists())

    def test_empty_metrics_never_satisfy_count_protocol(self):
        rows=[{'variant':'a','warmup':i<0,'successful':True,'metrics':{}} for i in range(-5,50)]
        self.assertFalse(summarize_rows(rows,50,5)['a']['countProtocolMet'])

    def test_atomic_write_tolerates_abandoned_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'journal';(Path(tmp)/'journal.writing').write_text('partial old write')
            durable_text(path,'complete')
            self.assertEqual(path.read_text(),'complete')

    def test_real_subprocess_output_and_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker=root/'worker.py'
            worker.write_text("import json,os\nfrom pathlib import Path\nPath(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps({'successful':True,'metrics':{'elapsed_ms':1.25},'evidence':'test-only'}))\n")
            plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'a','command':[sys.executable,str(worker)]}]}))
            with patch('experiment.append',return_value=None):
                result=campaign(plan,root/'out',trials=2,warmups=1,smoke=True)
            self.assertEqual(result['variants']['a']['metrics']['elapsed_ms']['n'],2)
            self.assertFalse(result['qualifiedForPaper'])
            self.assertTrue((root/'out/tables.tex').exists())
            self.assertTrue((root/'out/sha256-manifest.json').exists())
            self.assertTrue((root/'out/source-files.sha256.json').exists())
            self.assertEqual(len((root/'out/trials.jsonl').read_text().splitlines()),3)
            self.assertEqual(len(list((root/'out').glob('a/*/record.json'))),3)

    def test_crashed_subprocess_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            result=campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            self.assertEqual(result['variants']['bad']['failedTrials'],1)
            self.assertEqual(json.loads((root/'out/bad/0/record.json').read_text())['exitCode'],1)

    def test_worker_failure_reason_with_empty_metrics_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker=root/'worker.py'
            worker.write_text("import json,os\nfrom pathlib import Path\nPath(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps({'successful':False,'metrics':{},'evidence':'worker-failure','reason':'dependency-unavailable'}))\n")
            plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'a','command':[sys.executable,str(worker)]}]}))
            result=campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            row=json.loads((root/'out/trials.jsonl').read_text())
            self.assertEqual(row['reason'],'dependency-unavailable')
            self.assertEqual(row['evidence'],'worker-failure')
            self.assertEqual(result['variants']['a']['failedTrials'],1)

    def test_missing_journal_line_recovers_from_actual_durable_record(self):
        from recover_journal import recover
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);worker=root/'worker.py'
            worker.write_text("import json,os\nfrom pathlib import Path\nPath(os.environ['VENDORCHAIN_TRIAL_DIR'],'measurement.json').write_text(json.dumps({'successful':True,'metrics':{'elapsed_ms':1.25},'evidence':'test-only'}))\n")
            plan=root/'plan.json';plan.write_text(json.dumps({'tasks':[{'name':'a','command':[sys.executable,str(worker)]}]}))
            campaign(plan,root/'out',trials=2,warmups=1,smoke=True)
            path=root/'out/trials.jsonl';lines=path.read_text().splitlines();path.write_text('\n'.join(lines[1:])+'\n')
            result=recover(root/'out')
            self.assertEqual(result['recovered'],1)
            self.assertTrue(result['statisticsReproduced']);self.assertFalse(result['measurementsImputed'])
            self.assertEqual(len(path.read_text().splitlines()),3)

    def test_failed_trial_without_measurement_recovers_from_record(self):
        from recover_journal import recover
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json'
            plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            journal=root/'out/trials.jsonl';journal.write_text('')
            self.assertEqual(recover(root/'out')['recovered'],1)
            row=json.loads(journal.read_text())
            self.assertFalse(row['successful']);self.assertEqual(row['metrics'],{})
            self.assertEqual(json.loads((root/'out/summary.json').read_text())['variants']['bad']['failedTrials'],1)

    def test_recovery_rejects_foreign_slots_and_preserves_original(self):
        from recover_journal import recover
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json'
            plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            journal=root/'out/trials.jsonl';row=json.loads(journal.read_text());row['trial']=99
            original=json.dumps(row)+'\n';journal.write_text(original)
            with self.assertRaisesRegex(ValueError,'unexpected journal slot'):recover(root/'out')
            self.assertEqual(journal.read_text(),original)
            self.assertFalse((root/'out/trials-original.jsonl').exists())

    def test_recovery_rejects_altered_counts(self):
        from recover_journal import recover
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json'
            plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            (root/'out/trials.jsonl').write_text('')
            summary=root/'out/summary.json';report=json.loads(summary.read_text())
            report['variants']['bad']['failedTrials']=0;summary.write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError,'original statistics'):recover(root/'out')

    def test_recovery_handles_truncated_last_append(self):
        from recover_journal import recover
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);plan=root/'plan.json'
            plan.write_text(json.dumps({'tasks':[{'name':'bad','command':[sys.executable,'-c','raise RuntimeError()']}]}))
            campaign(plan,root/'out',trials=1,warmups=0,smoke=True)
            journal=root/'out/trials.jsonl';journal.write_bytes(b'{"variant":"bad","tri')
            self.assertEqual(recover(root/'out')['recovered'],1)
            self.assertEqual((root/'out/trials-original.jsonl').read_bytes(),b'{"variant":"bad","tri')
