from pathlib import Path
import shutil
import subprocess
import unittest
from vendorchain.gstin import check_digit, valid_gstin
from vendorchain.policy import evaluate, REFERENCE_POLICY

class GstinTests(unittest.TestCase):
    def test_known_checksum_and_cross_pan(self):
        self.assertEqual(check_digit('27AAPFU0939F1Z'), 'V')
        self.assertTrue(valid_gstin('27AAPFU0939F1ZV', 'AAPFU0939F'))
        self.assertFalse(valid_gstin('27AAPFU0939F1ZV', 'ABCDE1234F'))
    def test_mutated_checksum_and_bad_format(self):
        for value in ['27AAPFU0939F1Z0', '27aapfu0939f1zv', '', None, '27AAPFU0939F0ZV']:
            self.assertFalse(valid_gstin(value))
    def test_check_digit_rejects_non_base36(self):
        for value in ['', '!'*14, 'a'*14]:
            with self.assertRaises(ValueError):check_digit(value)

@unittest.skipUnless(shutil.which('opa'), 'OPA unavailable; policy tests not measured')
class OpaTests(unittest.TestCase):
    def test_real_rego_bundle(self):
        subprocess.run(['opa','test',str(REFERENCE_POLICY.parent),'-v'], check=True, capture_output=True, timeout=10)
    def test_real_allow_and_deny_decisions(self):
        good={'format':'PNG','documentIntact':True,'ocrExpectedMatches':True,'sbomValid':True}
        self.assertTrue(evaluate(good))
        for key in ['documentIntact','ocrExpectedMatches','sbomValid']:
            self.assertFalse(evaluate({**good,key:False}))
        self.assertFalse(evaluate({}))

if __name__=='__main__':unittest.main()
