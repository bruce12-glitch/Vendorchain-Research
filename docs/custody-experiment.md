# Paired software custody experiment

This comparison runs the full hardened pipeline with local software KEK and
identity, decision and policy keys versus a software Vault Transit KEK and all
three Transit signers. Both arms use the same local Cosign file key, source
artifact bytes, OCR rules, signed policy semantics, SQLite operational store
and local non-consensus ledger. It measures the combined service-custody cost;
it does not isolate individual remote operations or establish hardware HSM
custody, distributed ledger performance, or production Vault security.

From the repository root, activate the pinned Python environment and put the
documented OCR, Syft, Cosign and OPA executables on `PATH`. Supply `VAULT_ADDR`
and `VAULT_TOKEN` for an already running disposable Vault with the `transit`
engine enabled and permission to create/use research keys. Keep credentials in
the environment; do not commit them. Then run:

```bash
python research/prepare_custody_research.py --output .runtime/custody-setup
python research/make_custody_plan.py \
  --local-config .runtime/custody-setup/localkeys/config.json \
  --vault-config .runtime/custody-setup/vaultkeys/config.json \
  --output .runtime/custody-plan.json
python research/experiment.py --plan .runtime/custody-plan.json \
  --output .runtime/custody-results --seed 20261106
python research/verify_campaign.py .runtime/custody-results
python research/plot_custody.py .runtime/custody-results --output .runtime/custody-analysis
```

Choose fresh output paths when rerunning. Preparation requires a fresh setup
directory. It uses the existing preparation helpers, points both arms at one
Cosign key, re-signs the remote policy after matching its provenance trust, and
removes the unused remote Cosign key pair. An interrupted setup may leave
disposable Transit keys in Vault; discard the lab instance after the campaign.
Public trust and signed policy validity are short lived, so prepare immediately
before running. Do not publish `.runtime/custody-setup`, which contains research
private keys.

The plan generator verifies signed public policy bundles and registry entries,
hashes the actual source trees, rejects mixed custody or PostgreSQL, and requires
matched identity expectations and policy semantics. It records public config,
registry, policy and artifact hashes without reading private keys or contacting
Vault. Successful plan generation alone does not test live credentials; trial
failures remain visible in the runner's evidence.

Each successful observation must match the plan's configuration, registry,
signed-policy and artifact digests. Source and trust-file drift during a worker
execution makes that observation unsuccessful. The verifier also checks the
declared custody mode, SQLite store and local ledger before accepting the cohort.

The existing runner supplies 50 measured trials and five discarded warm-ups per
arm: 110 invocations in total. It randomizes arm order within sequential trial
blocks with the recorded seed. Each invocation uses a fresh process and isolated
SQLite state. Unique synthetic PNG metadata prevents cross-trial replay while
the rendered identity stays the same. `elapsed_ms` begins after configuration,
key loading and database initialization; it covers the full pipeline, including
the remote operations performed during that pipeline. It excludes startup,
provisioning, policy signing at preparation, and networked Fabric consensus.
Parent/child CPU and RSS counters exclude the Vault service; they cannot support
a claim about total client-plus-service resource savings.

Use `paired-comparisons.csv` or `.tex` for the paired difference
`vaultkeys elapsed_ms - localkeys elapsed_ms` and its 95% confidence interval.
The plan predeclares the total elapsed contrast as primary and four secondary
stage contrasts (encryption, decryption, identity attestation and decision
attestation). These are differences in complete stage durations, not isolated
RPC latency measurements. Intervals are unadjusted for multiple comparisons.
Retain `summary.json`, raw measurements, records, logs, metadata, the copied plan
and SHA-256 manifest together. A failed or missing trial is not a zero latency;
the paired export reports incomplete pairs. Report the software Vault topology,
tool versions, host sharing and SQLite/local-ledger scope alongside the results.
The runner deliberately leaves `qualifiedForPaper` false: interpret the measured
evidence and deployment limitations before making a paper claim.
`plot_custody.py` exports PDF/SVG/PNG figures, exact per-pair observations and
descriptive lag-one correlations. Low correlation is not proof of independence;
serial dependence in either arm should be reported rather than concealed.

Validation without a live service:

```bash
PYTHONPATH=research python -m unittest discover -s research/tests -p 'test_*custody*.py' -v
```
