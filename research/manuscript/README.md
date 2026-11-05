# Recovered manuscript policy

`listing-1.rego` reproduces the Rego text in Listing 1 of the user's
`VendorChain_complete_position_fixed.tex` (lines 1498–1532). It was recovered
from the earlier manuscript after the initial repository audit. The full
manuscript is not republished here.

This is Rego v0 syntax. Evaluate it with the pinned OPA's `--v0-compatible`
option, or run `research/validate_manuscript_policy.py`. The active pipeline
continues to use `research/policies/reference.rego`; it must not assert that
Listing 1's provenance, certificate, identity and replay predicates have been
measured merely because the recovered rule parses.

The validation inputs are synthetic predicate facts. A true `signature_valid`
or `certificate_approved` flag in those inputs is not a cryptographic check.
The missing-replay case documents the manuscript's own F7 limitation: a policy
predicate cannot replace H7's digest index and retention-window enforcement.

The exact H1–H7 mapping is now in `docs/hardening.md`. Section 6.3 also explicitly
requires sequential independent trials with no competing load, in addition to
five discarded warm-ups and N ≥ 50; the previous parallel BFT campaign does not
satisfy that protocol.
