# Empirical evaluation runbook

This audit uses `VendorChain_Research_paper (4).pdf`, especially Section 6.3,
Sections 8.1–8.9, Table 12, Section 9.4 and Appendix A. The paper describes the
original prototype and specifies H1–H7 as future work. The current Python/Node/Go
research implementation is a new implementation, with separate source and
measurement provenance. Its timings cannot replace the historical Solo numbers
without changing the paper's implementation and environment description.

## What is implemented and what still needs measurement

| Paper requirement | Current executable path | Evidence boundary |
| --- | --- | --- |
| H1 signed identity | `HardenedPipeline`, separate identity signer | Mutation/role/key tests; syntactic identity, no registry oracle |
| H2 signed policy and replayable decision | Signed source, controls/trust pins, OPA snapshot and commit-time client replay | Tampering tests; authorized decision signer misuse remains possible |
| H3 evidence root | Captured ciphertext, SBOM, artifact, signed identity and decision digests | Substitution regressions; retention and auditor access remain operational duties |
| H4 immutable ledger checks | Go `RecordEvidence`, key/policy registries, freshness and signature verification | Real Fabric CI smoke; chaincode does not execute OPA |
| H5 outbox/reconciliation | SQLite and PostgreSQL stores, confirmed ledger readback, repair CLI | Real PostgreSQL tests; no cross-system atomic transaction claim |
| H6 custody and lifecycle | Vault Transit wrapping/signing, rotation/version revocation | Real Vault tests; dev-service custody does not establish hardware custody or evidence-conditional signing |
| H7 replay window | Atomic digest admission with signed retention configuration | Race, expiry and configuration-mutation tests |
| Table 12 | Seven cumulative variants plus two optional comparators | Fresh-process randomized sequential local campaigns; full variant adds hardening as well as ledger |
| Section 6.3 statistics | Five warmups, ≥50 trials, sample SD, R7 percentiles, Student-t intervals, paired contrasts | Counts do not prove independence, an idle host or a representative workload |
| CFT/BFT sweeps | Fresh four-orderer deployments, levels 100–10,000, one-orderer crash, reconciliation | Full publication-scale sweep still requires a dedicated-host run |
| Reviewed documents | Hash-pinned CSV import and seven-variant document evaluator | Author must supply reviewed, lawfully usable specimens and provenance; generated fixtures are synthetic |

The final 550-file campaign mentioned in the earlier chat was not found in the
merged repository during this audit. Do not cite those trials until the actual
archive is recovered and checked. Existing `research/results/` cohorts have their
own historical limitations and are not silently combined with new runs.

## Bugs repaired in this follow-up

- Check signed controls before replay admission or persistence, and bind the
  SBOM bytes used for the receipt to the inventory evaluated by OPA.
- Prevent Vault redirects from forwarding authentication to another origin.
- Preserve structured worker errors, failed-process records, incomplete journal
  appends, process exit codes and missing paired comparisons.
- Reject duplicated/foreign trial slots and require complete recomputed statistics
  before journal recovery. Pin source file hashes and repository Git provenance.
- Validate Fabric acknowledgement IDs and evidence types; retain HTTP errors and
  unknown/FAIL verdicts separately from successful valid-document workloads.
- Require exact declared load sweeps, complete reconciliation and stopped-orderer
  checks. Verify active consensus membership; serialize trials with a host lock.
- Generate scope-aware plots and paired CSV/LaTeX exports. Verify raw hashes,
  journals, summaries and statistical exports before accepting a campaign.

## Prepare a host

Linux x86_64, Python 3.12+, Tesseract 5+, Poppler and DejaVu Sans Mono are needed.
For consensus also install Node 22.12+, Go 1.23.12+, Docker with Compose and `flock`.
Install OCR/font packages with your host package manager, then run from the repo:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r research/requirements.lock
bash research/scripts/install-validation-tools.sh
bash research/scripts/install-syft.sh
export PATH="$PWD/.runtime/bin:$PATH"
export PYTHONPATH="$PWD/research"
python research/check_environment.py --output .runtime/preflight.json
```

Preflight exits nonzero on missing prerequisites or mismatched pins. It reports
readiness of installed prerequisites, not credentials, isolation or validity.
Record actual OS/kernel/tool versions for the updated Appendix A; the original
paper's environment is not the current harness's environment.

## Run and verify Table 12

Use an otherwise idle host and keep other validation jobs out of timed runs.
The following runs synthetic documents and disposable software keys:

```bash
export COSIGN_PASSWORD=''
python research/prepare_research.py --output .runtime/table12-deployment
python research/make_experiment_plan.py \
  --config .runtime/table12-deployment/config.json \
  --local --allow-local-keys --comparators --output .runtime/table12-plan.json
python research/experiment.py --plan .runtime/table12-plan.json \
  --output .runtime/table12-results --trials 50 --warmups 5 --seed 20261106
python research/verify_campaign.py .runtime/table12-results
python research/plot_experiment.py .runtime/table12-results
python research/verify_campaign.py .runtime/table12-results
```

For development only, use a new output directory and `--trials 2 --warmups 1
--smoke`. The runner refuses to overwrite a campaign. If journal appends are lost
but individual trial records remain, run `recover_journal.py DIRECTORY`, then
verify again. Recovery cannot invent missing trials or resume an unexecuted run.

Retain `trials.jsonl`, every trial directory, `source-files.sha256.json`, the
source commit, plan, metadata and SHA-256 manifest. `summary.csv` and `tables.tex`
are per-variant exports; `paired-comparisons.csv` and `.tex` report treatment-minus-
control contrasts with actual complete/missing pair counts. `resources.png` and
`stages.png` are derived figures and are added to the manifest by the plotter.
The verifier recomputes statistics and exports; checksums provide consistency,
not an independent guarantee that observations are authentic.

The manual Actions workflow **Measured local Table 12 campaign** runs the same
50+5 protocol with two comparators and retains an artifact even after failure.
Download that artifact before its GitHub retention window expires. It excludes
the deployment directory and private keys. Hosted-runner isolation is not
independently established; `qualifiedForPaper` remains false for author review.

## Run consensus and document experiments

On a dedicated Docker host, with enough storage for Fabric images, peers and
chaincode builds:

```bash
npm ci --prefix research/gateway --ignore-scripts --no-audit --no-fund
python research/check_environment.py --consensus --output .runtime/consensus-preflight.json
python research/experiment.py --plan research/plans/consensus.json \
  --output .runtime/consensus-results --trials 50 --warmups 5 --seed 20261106
python research/verify_campaign.py .runtime/consensus-results
python research/plot_experiment.py .runtime/consensus-results
```

This creates 55 fresh deployments per consensus, with seven sequential offered-
concurrency bursts per deployment and a separate three-upload crash exercise.
Each outer deployment is the statistical replicate; individual requests and
load levels within it are not independent replicates. All failures remain in
the evidence. A crash is not an actively Byzantine attack. Full live PostgreSQL/
Vault deployment measurements need a separately configured campaign; the
consensus launcher uses SQLite and explicit research keys.

`benchmark.yml` remains a manually invoked legacy parallel BFT cohort and is
explicitly marked nonpublication. Use `research/plans/consensus.json` for the
current sequential protocol. The ordinary PR workflow runs small healthy/crash
Raft and BFT checks, not the full empirical matrix.

For reviewed documents, follow `experimental-expansion.md` to import a labelled
CSV and run `ablation_security.py`. Its expected identity is deployment-specific;
keep benign labels aligned with that identity or run separate configurations.
Report operational errors, bypass/false-rejection denominators and exact binomial
intervals. Do not infer universal detection or lawful registration from them.

Hardware HSM custody, evidence-conditional signing, live GSTN/certificate
revocation, a representative corporate corpus, multi-host production fault
experiments and a multi-organization field trial remain external validation or
integration work. No result in this runbook claims they have been completed.
