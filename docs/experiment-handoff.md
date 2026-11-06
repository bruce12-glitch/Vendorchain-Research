# Experimental evidence and remaining runs

This handoff audits the supplied paper's Section 6.3, Table 12 and Section 9.4
against the executable research paths. It supersedes the **status assessment** in
the dated 30 October [evidence checklist](evidence-checklist.md); that file remains
a historical audit. Commands below run from the repository root. Use a new output
directory for each run and record the exact source commit. A command being
available does not mean its experiment has been executed.

## Evidence already retained

| Cohort | Completed evidence | Supported interpretation |
| --- | --- | --- |
| [6 November local campaign](../research/results/empirical-20261106/README.md) | Source `4ceaa19f995bdaee92f7a218dd2b3ca0b3d186c3`; seven cumulative variants and two comparators; 50 measured trials and five warmups each; 450 measured + 45 warmup trials; no failures; raw inputs, per-trial records, metrics, exports and manifest retained | Synthetic-workload, local nonconsensus feasibility and resource observations. Counts/statistics meet the count protocol; host isolation and independence were not established. |
| [CI run 42155159401](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/42155159401) | Real PostgreSQL/Vault checks; separate four-orderer Raft and BFT jobs each commit three healthy uploads and three after one stopped orderer; signed/public evidence, peer output and reconciliation retained in the local campaign's raw archive | Bounded integration and one-orderer crash checks on colocated development networks. Six uploads per consensus are not a load distribution or an actively Byzantine attack. |
| Earlier results | Older synthetic corpus, fixed-order studies and claim-audit artifacts have separate provenance | Keep their inputs, code and limitations separate. The original 44-test logs, historical Solo timings and the earlier chat's missing 550-file campaign have not been recovered. |

The new local campaign's `verification.json` reports 2,486 pinned files verified.
Its `qualifiedForPaper: false` and unverified isolation flags must remain visible;
fresh processes, 50 trials and checksums do not prove independence or authenticity.
The full variant adds signed evidence and outbox work as well as the local ledger.
Its contrast against the policy variant is not a pure Fabric-ledger cost.

## Common preparation and acceptance

Use Linux x86_64, Python 3.12+, Tesseract 5+, Poppler and DejaVu Sans Mono. Install
the host OCR/font packages, then prepare the pinned tools:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r research/requirements.lock
bash research/scripts/install-validation-tools.sh
bash research/scripts/install-syft.sh
export PATH="$PWD/.runtime/bin:$PATH"
export PYTHONPATH="$PWD/research"
export COSIGN_PASSWORD=''
mkdir -p .runtime
python research/check_environment.py --output .runtime/preflight-next.json
```

Keep preflight, commit/dirty-tree status, source hashes, signed configuration,
actual CPU model/logical processors/RAM/storage/kernel, timestamps and tool
versions. For timed experiments, allocate an otherwise idle host, record other
workload and state resets, and assess serial dependence. Do not change isolation
flags solely because the command finished. Keep failed attempts, operational
errors, warmups and missing measurements. Report actual denominators and the
measurement boundary; per-request observations are not independent deployment
replicates. Store public synthetic evidence separately from private deployment
keys, service tokens and confidential documents.

## Runs feasible without external data or a Fabric host

### Verify and reuse the completed local cohort

This is an integrity check, not a new measurement. Extract into a new directory:

```bash
mkdir -p work/verify-empirical-20261106
tar -xJf research/results/empirical-20261106/raw-evidence.tar.xz \
  -C work/verify-empirical-20261106
python research/verify_campaign.py work/verify-empirical-20261106/campaign
```

Acceptance: the verifier succeeds, all 495 declared slots and raw files remain,
and recomputed statistics/CSV/LaTeX match. Preserve the archive's outer checksum
manifest too. Derived graphs may be regenerated, but must not replace raw data.
This supports internally consistent observations at the recorded source commit.

### Re-measure local costs on an allocated idle host, if stronger timing evidence is required

The existing 450 measured trials are complete; repeating them is useful only to
address a stated environment or workload question. A new cohort must not overwrite
or silently pool the current one.

```bash
python research/prepare_research.py --output .runtime/local-next-deployment
python research/make_experiment_plan.py \
  --config .runtime/local-next-deployment/config.json \
  --local --allow-local-keys --comparators --output .runtime/local-next-plan.json
python research/experiment.py --plan .runtime/local-next-plan.json \
  --output .runtime/local-next-results --trials 50 --warmups 5 --seed 20261106
python research/verify_campaign.py .runtime/local-next-results
python research/plot_experiment.py .runtime/local-next-results
python research/verify_campaign.py .runtime/local-next-results
```

Retain every trial directory, `trials.jsonl`, source/plan/metadata hashes, summaries,
paired contrasts and figures. Acceptance: nine groups with 50 measured and five
warmup slots each; failures and missing pairs explicitly reported; mean, sample
SD, median, R7 percentiles and Student-t intervals recompute. Paired intervals are
unadjusted per comparison. A heavier comparator's lower point estimate does not
show that extra work improves speed. These remain local software-key/SQLite
measurements, excluding configuration/key loading and schema initialization.

### Generated format regressions and separate primitive checks

```bash
python -m vendorchain corpus --generate .runtime/corpus-next --benign 1000 \
  --output .runtime/corpus-next-results.json
python research/validate_cosign.py --source "$PWD/chaincode" \
  --output .runtime/cosign-next
python research/validate_manuscript_policy.py --output .runtime/policy-next
python research/validate_ingress_memory.py --concurrency 100,1000,10000 \
  --output .runtime/oversized-next
```

Retain generated bytes/manifest, every specimen decision and exact binomial
intervals; Cosign's original/mutated inventories, public key, signature and command
logs; OPA input/output cases; and HTTP logs/per-request records. Acceptance includes
working positive controls, expected negative controls, zero unexplained operational
errors, and no persistence/buffering for the oversized-header rejection case.
Unexpected outcomes remain results and require investigation. This supports only
the generated corpus, offline pinned-key signature checks and synthetic policy
predicates. The last command sends **no document bodies**, uses N=1 per level and
does not test accepted-body memory, slow clients, parser exploit containment or
Fabric load. Existing equivalent results need not be rerun merely to increase
the number of files.

## Table 12: remaining measurement gap

The seven-variant timing experiment exists. The existing
`research/ablation_security.py` executes those workers over a document manifest,
but its explicit scope is ingress/identity outcomes. It cannot measure all Table
12 columns: the worker creates and signs its own valid SBOM, supplies successful
provenance facts to the policy stage, and removes its temporary state. There is
no declared injection protocol for unsigned/tampered SBOMs or false composed
policy predicates, nor a retained observation of plaintext versus ciphertext at
rest. Calling document rejection rates the complete Table 12 security ablation
would therefore overstate coverage. A local ledger also cannot demonstrate the
table's multi-party audit property.

The smallest useful extension is a **separate local experiment worker**, leaving
public API behavior intact. It should reuse the actual cumulative stages and:

1. Declare inert, hash-pinned scenarios and the injection boundary: valid control,
   extension spoof, malformed GSTIN, mismatching visible identity, unsigned or
   mutated SBOM, and one false predicate at a time in the composed OPA input.
2. Observe persisted bytes before cleanup. Baseline/gate intentionally persist
   plaintext; encryption and later stages must retain ciphertext and successful
   authenticated round-trip checks. A ciphertext/AAD mutation checks integrity,
   separately from the at-rest confidentiality observation.
3. Keep per-scenario/per-variant records, input/config/source hashes, stage reached,
   rejection reason, public evidence and stdout/stderr. Distinguish accepted,
   security-rejected, operational-error and not-applicable outcomes. A setup
   failure is never credited as attack prevention.
4. Export a matrix by attack class with exact tested denominators. Repeated runs
   of identical deterministic fixtures do not create a representative attack
   population. Positive controls must succeed for each relevant variant.
5. Link the full-stage multi-party audit cell to real Fabric channel membership,
   signatures, peer-query output and reconciliation checks, not local acceptance.

This extension was identified during the audit; the commands above do not already
implement it. Its measurements would support finite-scenario mechanism comparisons,
not universal security or vulnerability detection. Before attributing a result to
a disabled control, check that an earlier stage did not block the injected input.

## Author-provided reviewed documents

Supply lawfully usable passive PDF/PNG/JPEG specimens and a reviewed index with
`path,label,family,reviewed_by,provenance_uri`. Predeclare intended formats, vendor
identities, document-size/scan-quality strata, selection procedure, consent/license
and ground truth. Include difficult legitimate files; do not remove policy
rejections after inspecting outcomes. Unsupported GIF/SVG/Office and active or
encrypted PDFs require an explicit scope decision.

```bash
python research/import_corpus.py --root research/private-corpus \
  --index reviewed.csv --output research/private-corpus/manifest.json
python -m vendorchain corpus --manifest research/private-corpus/manifest.json \
  --output .runtime/reviewed-format-results.json
python research/ablation_security.py \
  --config .runtime/local-next-deployment/config.json \
  --manifest research/private-corpus/manifest.json \
  --output .runtime/reviewed-document-ablation
```

The final command's benign labels must mean valid expected identity under that
configuration; use separate approved configurations per identity. The generated
format corpus is not a valid substitute for that identity ground truth. Oversized
specimens are explicitly skipped by this ablation and need the format evaluator's
separate denominator. Retain labelled manifests, hashes, decisions, operational
errors, per-family counts and Clopper–Pearson intervals. A provenance field records
the curator's declaration; the importer cannot independently validate it.

These runs support corpus-specific format/identity false-rejection and bypass
estimates. They cannot establish lawful GSTN registration, current registry status,
or representative accuracy without a defensible sampling frame and oracle.

## Dedicated-host consensus campaign

The current managed host failed during image extraction on its 7.9 GB `vfs`
Docker filesystem, before any network upload measurement. Use a dedicated Linux
Docker host with substantially more free storage, sufficient memory/CPU, Node
22.12+, Go 1.23.12+, Compose and `flock`. Record capacity and the actual Docker
storage driver. The bootstrap refuses an existing Fabric network; use a disposable
host and verify preflight before scheduling the long campaign.

```bash
npm ci --prefix research/gateway --ignore-scripts --no-audit --no-fund
python research/check_environment.py --consensus \
  --output .runtime/consensus-preflight-next.json
python research/experiment.py --plan research/plans/consensus.json \
  --output .runtime/consensus-next --trials 50 --warmups 5 --seed 20261106
python research/verify_campaign.py .runtime/consensus-next
python research/plot_experiment.py .runtime/consensus-next
python research/summarize_load_campaign.py .runtime/consensus-next \
  --levels 100,250,500,1000,2500,5000,10000 \
  --output .runtime/consensus-next-observed-load
```

The plan performs 55 fresh deployments **per consensus**, seven sequential bursts
at 100/250/500/1,000/2,500/5,000/10,000 offered uploads per deployment, then a
separate three-upload exercise after stopping the fourth orderer. Each deployment
is an outer replicate; levels within it and its requests are not independent
replicates. The six-hour timeout is per deployment, not a promised completion time
for the whole campaign. All nodes are colocated and use development certificates.

Retain bootstrap/teardown logs, actual committed channel configuration and four
consenters, image IDs, source/config/plan hashes, every request/status/error,
scheduler/in-flight metrics, per-node resource samples, signed evidence, peer
query stdout, stopped-orderer checks and reconciliation. Acceptance means complete
declared slots and exact load coverage, verified topology, transparent failures,
and internally consistent raw/derived data. It does **not** require forcing every
10,000-upload burst to succeed. Saturation/rejections are valid outcomes.

For overload interpretation use `summarize_load_campaign.py`: the generic variant
summary conditions metrics on successful outer trials. Retain completed bursts
from failed deployments, including zero client-confirmed acknowledgement throughput;
leave unexecuted/crashed/missing bursts unknown. Distinguish client acknowledgements
from ledger commits. Report actual denominators and successful-only latency beside
failure rates. `watch_resources.py` captures process/container samples, but Docker
block I/O is not persistent ledger-volume growth; measure storage volumes separately
for a ledger-storage claim.

This supports colocated Raft/BFT workload curves and one-orderer crash observations.
It does not demonstrate malicious Byzantine behavior, cross-host fault tolerance,
production TLS/ACL/custody, or a production PostgreSQL/Vault deployment. Those
require separately configured campaigns; this launcher uses SQLite and explicit
research software keys.

## Work requiring external systems or a broader study

| Question | Required input or implementation | Evidence needed before making the claim |
| --- | --- | --- |
| PostgreSQL/Vault deployment costs and recovery under load | Dedicated PostgreSQL/Vault services, role-scoped credentials, approved configuration, failure-injection schedule; no canned comparative plan currently supplied | Service versions/configuration, timed valid workloads, database outage/lost-acknowledgement records, actual ledger readback and reconciliation; isolate from software-key/SQLite results |
| Hardware custody or evidence-conditional signing | Actual HSM or a signer that validates evidence before signing, plus its integration | Key non-exportability/authorization and misuse tests; ordinary Vault Transit signing does not establish this property |
| Live registration/certificate revocation | Authorized GSTN/credential oracle and certificate validation/revocation integration | Oracle ground truth, freshness/outage policy, positive/negative/revoked cases and retained nonsecret responses |
| Arbitrary parser compromise containment | Operating-system/container isolation design and authorized containment tests | Demonstrated filesystem/network/credential boundaries; subprocess resource limits and inert files are insufficient |
| Active Byzantine, multi-host or consortium deployment | Separate fault injector, hosts/organizations, network conditions and predeclared safety/liveness criteria | Equivocation/malicious-node observations, independent-host metrics and recovery; stopping one orderer is a crash experiment |
| Field effectiveness | Partner organizations, lawful data access and longitudinal protocol | Operational false-rejection/manual-review outcomes, changes over time and governance/retention evidence |

These are external validation or new integrations, not hidden results obtainable
by rerunning the existing local scripts. They may remain limitations when claims
are restricted to the experiments actually completed.
