# Manuscript-aligned experimental implementation

This expansion follows the supplied `VendorChain_Research_paper (4).pdf`, Sections
6.3, 8.1-8.7, 9.4, Table 12 and Appendix A. It provides executable mechanisms and
experiment commands. Old Solo timing observations and the original 12-suite/44-test
logs have not been recovered or reconstructed. New results describe this new code.

## Hardened path and trust boundaries

`research/hardened_cli.py` selects `HardenedPipeline`; the original research CLI
remains available to reproduce earlier bounded results. Hardened dependencies fail
closed: real Tesseract, Syft, Cosign and OPA are required. The local ledger is
explicitly `local-non-consensus` and can never establish consensus performance.

Parser subprocesses receive an allowlisted environment rather than inherited
API/gateway/Vault credentials. Their resource limits are not OS privilege,
filesystem or network isolation: separate parser custody/containers remain a
deployment requirement for claims about containment of arbitrary parser code
execution. Inert parser fixtures do not establish that containment property.

| Control | Implementation | Validation scope and residual |
|---|---|---|
| H1 | Separate identity/decision key roles; signed identity containing GSTIN, checksum, OCR result, document digest, context, time and version | Mutation, role and revocation tests. Identity remains syntactic; no government registry oracle. A compromised authorized identity signer can lie. |
| H2 | Signed policy source, OPA version and parameters; verified private evaluation snapshot; signed decision snapshot and commit-time OPA replay | Bundle replacement, missing predicates and policy parameter checks. Registry and policy approval are consortium trust inputs. |
| H3 | Root over encrypted object, SBOM, artifact tree, signed identity and decision snapshot digests | Every root component is covered. Evidence and ciphertexts are retained under the operator's private state directory; retention/access must be operated. |
| H4 | `RecordEvidence` verifies registered decision key/role, policy approval, both signatures, timestamp interval, evidence root and write-once state | Go race tests plus a real-network CI path. Fabric MVCC covers key/policy revocations and duplicate creates racing endorsement. The contract verifies signatures/digests; it does not run OPA or prove semantic truth. |
| H5 | Versioned SQLite or PostgreSQL outbox, VALID Fabric commit/readback before operational confirmation, automatic reconciliation scan/repair CLI | Lost acknowledgement tests; real PostgreSQL integration is enabled in CI. There is no atomic transaction spanning SQL and Fabric. A global advisory lock preserves the reference SQL audit hash chain and can limit throughput. |
| H6 | Vault Transit KEK wrapping and Ed25519 signing; pinned versions, non-exportability checks, remote authorization on every unwrap, rotation/revocation CLI | Real Vault dev-service integration tests. This does not establish hardware HSM custody, durable Vault operations, ACL isolation or evidence-conditional signing. Raw signing access still leaves the authorized-worker misuse residual. |
| H7 | Atomic SHA-256 digest admission index with deployment retention window; identical retry ID/context remains idempotent | Concurrent duplicate admissions, retention expiry, rejected-buffer wiping and no loser object persistence. Index scope is the configured operational database. |

Canonical signed JSON and digest-only receipts are versioned. Equation 13 is encoded
as five raw 32-byte SHA-256 values in its stated order, followed by an unsigned
64-bit big-endian Unix timestamp. The directory artifact digest hashes sorted
relative-path/content-digest pairs; it represents a scanned source tree. It is not
silently presented as the digest of a deployed container image.
The signed decision snapshot also binds the encryption envelope and associated
context; changing SQL metadata cannot leave an apparently intact evidence root.
The signed policy manifest additionally pins the identity-worker trust entry,
Cosign verification key/validity, OCR algorithm/threshold and replay window. A
configuration change must be approved and re-signed rather than silently changing
the meaning of a previously approved policy digest.

The v2 ledger record maps to Equation 14, with `recordID`, `vendorID`, `evidenceRoot`,
`snapshotHash`, `policyHash`, `decision`, `signatureHash`, `keyID`, `algorithm` and
`issuedAt`, plus receipt digest and transaction ID for recovery. It contains no
GSTIN, policy input, SBOM component list, raw receipt or document. It differs from
the original Equation 9 prototype tuple and requires a new research channel or an
explicit migration. Legacy v1 transactions remain available for the earlier CLI;
run `EnableEvidenceOnly` when evaluating hardened guarantees. The new gateway's
`register-evidence` command enables that irreversible channel-local mode before
registering keys. It disables v1 writes even for a caller with a valid legacy
worker key; use a separate channel for legacy reproduction.

OCR now implements normalized substring Levenshtein similarity at the paper's
0.90 threshold, with explicit term/text limits. Scores and algorithm version are
signed into identity evidence. Fuzzy matching can increase false matches; its
accuracy must be measured on reviewed documents, not inferred from the threshold.

Cosign here uses a pinned approved public key with a deployment validity interval,
offline verification and no transparency-log lookup. Listing 1's certificate
predicates represent that configured trust interval; live X.509 chain/revocation
verification is not supplied. The complete vendored CycloneDX 1.5 JSON schema is
validated offline. A signature authenticates the asserted inventory, not its truth.

## Prepare a runnable research deployment

Run from the repository root on Linux/WSL2 with Python 3.12 and Node 22:

```bash
python -m pip install --require-hashes -r research/requirements.lock
bash research/scripts/install-validation-tools.sh
bash research/scripts/install-syft.sh
export PATH="$PWD/.runtime/bin:$PATH"
export PYTHONPATH="$PWD/research"
export COSIGN_PASSWORD=''
python research/prepare_research.py --output .runtime/research-deployment
```

Install Tesseract, Poppler and DejaVu fonts first. The helper generates disposable
local keys, a signed Listing 1 bundle, a pinned Cosign key and a source artifact
copied from this repository. The explicit `--allow-local-keys` flag identifies
this research custody mode. Keep private state out of supplementary archives.

For remote custody, replace the config's signer/KEK specifications with
`kind: vault-transit`, key names, pinned signing versions, `addressEnv` and
`tokenEnv` names; pin their public keys in the registry, re-sign the policy bundle,
and set `researchLocalKeys` false. The live integration test demonstrates this
without retaining application copies of the worker private keys or KEK. Use
separate ACL-scoped tokens and configure TLS outside loopback. The example ACLs
and 30-day rotation schedule are in `research/config/`; the schedule file does not
execute a scheduler.

For a disposable Transit experiment with an already running, initialized Vault
and Transit mount, set `VAULT_ADDR` and a lab administration `VAULT_TOKEN`, then
run `python research/prepare_vault_research.py --output .runtime/vault-deployment`.
This helper creates new non-exportable service keys, pins their public versions,
re-signs the policy bundle and removes the unused local KEK/worker key files.
Its single lab administration token is not a production ACL/custody arrangement.

## Table 12 and measured hardening costs

```bash
python research/make_experiment_plan.py \
  --config .runtime/research-deployment/config.json --local --allow-local-keys \
  --comparators --output .runtime/table12-plan.json
python research/experiment.py --plan .runtime/table12-plan.json \
  --output .runtime/table12-results --trials 50 --warmups 5
python research/plot_experiment.py .runtime/table12-results
```

The seven cumulative variants are baseline, gate, encryption, identity, provenance,
policy and full. The full variant adds the implemented hardened evidence/outbox
path; this is an extension of Table 12 rather than a reproduction of its original
prototype timings. Two optional comparators remove *client* evidence revalidation
in a local-only worker or add ten encryption/decryption loops. The server never
offers a disabled-control mode. The ledger still verifies signatures in the
client-revalidation comparator. Its difference cannot be described as the cost of
turning off all security controls.

Each measured trial is a fresh process with fresh SQLite state. Warm-ups and all
failures remain in JSONL and individual logs. Raw synthetic PNGs are retained;
external documents supplied with `--file` are referenced by digest. Generated PNG
metadata varies per submission while visible OCR text stays fixed. This workload
does not characterize the distribution of corporate documents.
The current runner randomizes variant order within sequential trial blocks using
a recorded seed. The earlier reference campaign at commit `6f510c5` used fixed
variant cohorts and is labeled accordingly; its differences are not causal
overhead estimates.
Plans can predeclare paired comparisons. The current runner reports treatment
minus control within each randomized trial block, including missing/failed pairs
and unadjusted 95% Student-t intervals. These are workload-specific contrasts;
overlapping or non-monotone point estimates are retained as observed.

Outputs include mean, sample standard deviation, median, p50/p95/p99 (R7),
two-sided Student-t 95% intervals, CSV, LaTeX tables, source/plan provenance and a
SHA-256 manifest. `countProtocolMet` records counts and metric completeness only.
`qualifiedForPaper` stays false for author review: no competing load and statistical
independence cannot be established just by launching subprocesses. Small runs
require `--smoke`; nothing is padded to 50 or replaced with paper target values.

Latency excludes config/key loading and database schema initialization. CPU includes
separate parent and child totals; memory reports separate process high-water marks,
not a concurrent sum. Disk growth subtracts initialized state. Stage plots omit
nested OCR/revalidation subspans to avoid double counting. Pair the metrics with
`watch_resources.py` when process-tree and per-orderer sampling is required.

## CFT/BFT sweeps with fresh deployments

On a dedicated Docker host, install Go 1.23.12 and the above tools, then:

```bash
npm ci --prefix research/gateway --ignore-scripts --no-audit --no-fund
python research/experiment.py --plan research/plans/consensus.json \
  --output .runtime/consensus-publication --trials 50 --warmups 5
```

This explicitly requested long campaign creates fresh sequential deployments:
five discarded deployments and 50 measured deployments **per consensus**, with
100/250/500/1,000/2,500/5,000/10,000 offered uploads per measured deployment.
Every level is a sequential burst with a drain check. Four-node Raft and four-node
BFT share the pinned sample infrastructure; the actual committed channel config
must identify the declared consensus and four consenters. This costs substantial
runtime and disk; the full campaign is not automatically launched by a code push.

Each upload uses a complete PNG and unique metadata so H7 does not reject an entire
legitimate workload as identical-content replay. Committed PASS, committed FAIL,
unconfirmed attempts, offered/achieved concurrency, scheduler delay and throughput
remain distinct. Admission rejections at high load are valid observations and make
that trial unsuccessful; they are never converted into successful throughput.

Artifacts retain actual peer CLI query output, hash-only field checks, public
signatures/policy/identity snapshots/SBOMs, channel configuration, image IDs,
per-node resource samples, crash logs and reconciliation results. A stopped fourth
orderer tests crash survival; it is not an actively Byzantine-node attack. All nodes
are colocated and use development certificates. This cannot establish cross-host
production behavior. Production PostgreSQL/Vault experiments require their own
configured deployments; consensus smoke uses SQLite and explicit research keys.

## Reviewed adversarial and legitimate documents

The existing inert corpus generator/evaluator remains executable. For real files,
prepare a CSV with `path,label,family,reviewed_by,provenance_uri` and run:

```bash
python research/import_corpus.py --root research/private-corpus \
  --index reviewed.csv --output research/private-corpus/manifest.json
python -m vendorchain corpus --manifest research/private-corpus/manifest.json \
  --output .runtime/reviewed-corpus-results.json
```

Deduplicate specimens by digest and preserve review/licensing provenance. The
harness verifies bytes and outcomes, not the truth of provenance declarations.
For an executed seven-variant **document** security comparison, run
`research/ablation_security.py --config ... --manifest ... --output ...` with the
research configuration. It records operational errors separately from rejections;
SBOM/key/policy attacks remain separate suite controls. Its local-only workers are
intentionally permitted to disable early controls and must never be public APIs.
For that runner, benign labels must mean an expected valid identity under the
supplied configuration. Use the ordinary corpus evaluator for format-only false
rejection rates on documents belonging to different vendors.
Report Clopper-Pearson intervals alongside observed bypass/false-rejection rates;
zero observed bypasses does not establish a universal zero-bypass guarantee.
Accepted formats are PDF, PNG and JPEG. GIF, SVG and Office documents are outside
the admission policy; report that scope when measuring legitimate rejection rates.

## PostgreSQL and reconciliation

Set `postgresDsnEnv` in config to the name of an environment variable containing a
dedicated PostgreSQL DSN. Apply `hardened_cli.py migrate-postgres --config ...` once
with a migration role. Run with ordinary data privileges afterward.

```bash
python research/hardened_cli.py reconcile --config deployment/config.json \
  --repair --interval 30
```

This scans the outbox, checks real ledger readback and repairs pending SQL
confirmation after a lost acknowledgement. Divergences and lookup failures remain
visible. It does not invent a transaction ID or finalize on endorsement alone.
Retain encrypted objects, identity/snapshot evidence, public verification material,
approved policy versions and authorized unwrap access for the audit window.

## Updating the manuscript

Describe this as a new research implementation: Python workers, a Node Fabric
gateway and Go chaincode. Update Section 5 and Table A1 from the retained run's
actual dependency/environment metadata. The original Node/Redis/Solo testbed and
its historical timings cannot be silently reused as this implementation's results.

For Section 6 and Table 12, state that the new gate performs structural validation
inside a subprocess; `gate_ms` includes that boundary. It does not reproduce the
old magic-prefix-only <1.2 ms observation. The full variant includes new signed
evidence/outbox work. Publish all rejected/failed attempts and keep local SQLite,
Vault dev-service, Raft and BFT results in separate cohorts.

For Section 8, distinguish implemented controls from operational validation.
Vault service custody is exercised; hardware custody and evidence-conditional
signing are not established. Identity is syntactic. Signature approval uses pinned
keys rather than live certificate-chain/revocation validation. PostgreSQL/Fabric
recovery tests do not establish an atomic cross-system transaction.

Use Appendix A to link the exact source commit, locks, corpus manifest, raw archive,
run protocol, CSV/LaTeX tables and CI run. Point artifact availability to this
repository. Do not state that new tests recover the original 12-suite/44-test logs
or that one healthy/crash burst establishes production throughput or Byzantine
attack resilience. Keep the unexecuted full load matrix and reviewed corporate
corpus in Section 9.4 until their actual evidence is collected.
