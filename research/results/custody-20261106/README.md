# Empirical comparison of software-file and Vault Transit custody

This cohort measures an implemented custody change in the full research pipeline.
It is separate from the earlier nine-variant `empirical-20261106` cohort and must
not be silently pooled with it.

Measurement source: **`a69088e00f0f27dfea4d66c3fa7c9f53d2f980f8`**, clean working
tree. The plan was fixed before measurement with seed `20261106`, one primary
elapsed-time comparison and four secondary stage comparisons. Each arm has five
discarded warmups and 50 measured fresh-process invocations: **100 measured
invocations and 10 warmups**, zero failed invocations or missing pairs.

## Conditions and measurement boundary

Both arms use the same visible identity rendered into PNGs, identical artifact
bytes and signed policy semantics, the same Cosign file key, fresh SQLite state
per invocation, real OCR/Syft/Cosign/OPA and the local non-consensus ledger.
Unique PNG metadata changes the document digest without changing visible text.
The local arm loads a software KEK and Ed25519 worker keys from files. The Vault
arm uses a real **Vault 1.18.3** development service on the same host over IPv4
loopback HTTP, with Transit wrapping/unwrapping and identity/decision signing.
Policy signing is service-custodied too, but occurs during preparation and is
outside the timed path. A single administrative lab token is used.

`elapsed_ms` starts after configuration/key loading and schema initialization.
The initialized Vault instance and its keys are shared across invocations; this
is not a 50-deployment study. It excludes provisioning, startup, TLS, hardware
HSMs, production ACL isolation and Fabric consensus. Client parent/child CPU and
RSS exclude the Vault server and cannot establish total resource savings.

## Measured results

| Arm | N | Mean elapsed (ms) | Sample SD (ms) | Median (ms) | p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| Local software keys | 50 | 1612.732 | 116.369 | 1577.115 | 1853.872 |
| Vault Transit keys | 50 | 1629.673 | 135.361 | 1585.450 | 1865.187 |

The **primary paired mean difference, Vault minus local, is +16.942 ms**,
with a nominal two-sided 95% Student-t interval of **[−7.382, +41.265] ms**.
The point estimate is about 1.05% of the local mean. The interval spans zero:
this cohort does not clearly resolve a total pipeline latency difference under
that interval model, and it does not establish equivalence or negligible cost.

| Predeclared secondary stage contrast | Paired mean difference (ms) | Nominal 95% interval (ms) |
| --- | --- | --- |
| Encryption stage | +3.077 | [2.866, 3.289] |
| Decryption stage | +2.136 | [2.004, 2.268] |
| Identity attestation | +2.970 | [2.740, 3.201] |
| Decision attestation | +4.692 | [4.440, 4.944] |

These are complete stage-duration differences, not isolated network RPC latency.
All five comparisons are retained, including the inconclusive primary result.
Intervals are unadjusted for multiple comparisons. Exact values, R7 percentiles,
all raw pairs and every observed timing remain in the exports.

## Dependence and interpretation

Descriptive lag-one correlations are approximately **0.762** for local-arm
latencies and **0.738** for Vault-arm latencies, indicating serial structure in
the arm sequences. The paired-difference lag-one correlation is about **0.025**.
The paired series has much weaker observed lag-one correlation than either arm;
the small difference-series correlation does not prove independence. The raw paired sequence is plotted and
no outliers are removed. Group and paired Student-t intervals remain nominal,
conditional on their sampling assumptions. An allocated-host replication is
needed for a stronger independent-trial performance claim.

The metadata leaves `noCompetingLoadIndependentlyVerified` false and
`qualifiedForPaper` false. The measurements can support a bounded description of
this real software-custody implementation and workload, not a general production
overhead, security, hardware-attestation or corporate-document accuracy claim.

## Reproducibility and retained evidence

`raw-evidence.tar.xz` contains all 110 trial directories, original generated
input bytes, worker measurements and parent records, journal, plan, metadata,
source hashes, statistical exports and the inner hash manifest under `campaign/`.
It also contains derived PDF/SVG/PNG figures and per-pair CSV, public configuration
and registry/signed-policy snapshots, source artifact copies, observed Vault
key/service metadata, exact container image identity and validation logs.
Private key files, KEK bytes, API tokens, operational databases and private service
state are excluded. The public configuration files preserve exact original path
references for hash checking; regenerate a fresh setup to rerun after extraction.

```bash
mkdir -p .runtime/custody-extracted
tar -xJf research/results/custody-20261106/raw-evidence.tar.xz \
  -C .runtime/custody-extracted
python research/verify_campaign.py .runtime/custody-extracted/campaign
python research/plot_custody.py .runtime/custody-extracted/campaign \
  --output .runtime/custody-recreated-analysis
```

The outer `sha256-manifest.json` pins the supplement; the inner manifest and
verifier check all trial slots, worker provenance, matched-arm digests and
recomputed statistics/exports. Checksums establish internal consistency, not
independent authenticity. Derived-analysis code has separate script-hash
provenance and does not change the measurement source or observations.

For a fresh measurement use [the custody instructions](../../../docs/custody-experiment.md).
The measurement-source CI [run 42160680036](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/42160680036)
passed all four jobs. Post-run local code validation ran 161 tests: 160 passed and
one PostgreSQL test was skipped because that service was not provisioned; real
Vault lifecycle/signing checks passed. Those tests are validation, not additional
empirical trial observations.

Remaining author-run work: representative reviewed documents, the full
independent-deployment Raft/BFT load matrix on a larger host, and any live registry,
hardware custody, production ACL or field claims the paper elects to make. See
[the experiment handoff](../../../docs/experiment-handoff.md).
