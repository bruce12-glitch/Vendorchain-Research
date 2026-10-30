package vendorchain_test

import data.vendorchain.allow

good := {"format": "PDF", "documentIntact": true, "ocrExpectedMatches": true, "sbomValid": true}

test_allow if { allow with input as good }
test_deny_missing_evidence if { not allow with input as {} }
test_deny_bad_format if { not allow with input as object.union(good, {"format": "ELF"}) }
test_deny_identity_mismatch if { not allow with input as object.union(good, {"ocrExpectedMatches": false}) }
test_deny_bad_digest if { not allow with input as object.union(good, {"documentIntact": false}) }
test_deny_missing_sbom if { not allow with input as object.union(good, {"sbomValid": false}) }
