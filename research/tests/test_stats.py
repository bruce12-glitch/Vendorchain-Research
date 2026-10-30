import unittest
from vendorchain.stats import summarize,summarize_campaign
class StatsTests(unittest.TestCase):
    def test_sample_sd_and_t_interval(self):
        result=summarize([1,2,3,4,5]);self.assertAlmostEqual(result['mean'],3)
        self.assertEqual(result['median'],3);self.assertEqual(result['p50'],3)
        self.assertAlmostEqual(result['p95'],4.8);self.assertAlmostEqual(result['p99'],4.96)
        self.assertAlmostEqual(result['stddev'],1.5811388300841898)
        self.assertAlmostEqual(result['ci95'][0],1.0367568385,places=8)
    def test_fifty_independent_trials_required(self):
        self.assertFalse(summarize([1]*49)['publicationNMet'])
        self.assertTrue(summarize([1]*50)['publicationNMet'])
    def test_missing_values_not_silently_dropped(self):
        for values in [[1,None],[float('nan')],[]]:
            with self.assertRaises(ValueError):summarize(values)
    def test_warmups_excluded_and_no_request_pseudoreplication(self):
        rows=[{'concurrency':100,'warmup':False,'trialMeanMs':5,'offered':100,'successful':100,'failed':0,'durationSeconds':1,'evidence':'fabric-commit-confirmed'} for _ in range(2)]
        rows.append({**rows[0],'warmup':True,'trialMeanMs':100000})
        summary=summarize_campaign(rows)['100'];self.assertEqual(summary['trialLatencyMs']['n'],2)
        self.assertEqual(summary['trialLatencyMs']['mean'],5);self.assertFalse(summary['qualifiedForPaper'])
    def test_all_failed_trials_remain_visible(self):
        row={'concurrency':10,'warmup':False,'trialMeanMs':None,'offered':10,'successful':0,'failed':10,'durationSeconds':1}
        summary=summarize_campaign([row])['10']
        self.assertEqual(summary['failed'],10);self.assertEqual(summary['trialsWithoutSuccessfulCommits'],1)
        self.assertFalse(summary['qualifiedForPaper'])
