# Experiment protocol and commands

## 1. Consensus and load

Use a disposable Linux amd64/WSL2 machine with Docker, Go 1.23+, Python 3.12+,
Node 22.12+, Tesseract, Poppler, curl and Git. The pinned bootstrap refuses an
existing Fabric sample network rather than destroying one.

```bash
pip install -r research/requirements.txt
export PYTHONPATH="$PWD/research"
bash research/scripts/install-syft.sh
export PATH="$PWD/.runtime/bin:$PATH"
(cd research/gateway && npm ci --ignore-scripts)
bash research/scripts/bootstrap-bft.sh
bash research/scripts/integration-smoke.sh
```

Fabric 3.1.5 release binaries and Syft 1.55.0 archives are SHA-256 verified.
The Fabric samples revision is pinned. Services use versioned image tags; retain
`container-images.txt` for exact image IDs. The bootstrap inspects the **committed
channel configuration** and refuses to label a channel BFT unless it finds four
consenters. Its development certificates and colocated Docker host do not recreate
a production consortium or prove independent host fault tolerance.

The smoke script registers a runtime worker public key, starts the Gateway and
upload API, submits real OCR/Syft jobs, then repeats with one orderer stopped.
A crash is not a Byzantine-equivocation test. The script is an integration test
with concurrency 3 and N=1; it must never be reported as the publication sweep.

For the full campaign, keep the Gateway and API running in separate terminals:

```bash
source research/scripts/gateway-env.sh
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export GATEWAY_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m vendorchain init --state .runtime/study
# Set MASTER_KEK_HEX through the experiment runner's secret environment.
# The generated master.hex can be used in this disposable development network.
export MASTER_KEK_HEX="$(cat .runtime/study/master.hex)"
node research/gateway/server.mjs register-key .runtime/study/worker-public.json
node research/gateway/server.mjs
# A separate terminal with the SAME environment:
python -m vendorchain serve --state .runtime/study --source "$PWD/chaincode" --workers 8
# Another terminal with API_TOKEN:
node research/load.mjs --file /absolute/path/to/reviewed-sample.pdf \
  --concurrency 100,250,500,1000,2500,5000,10000 --trials 50 --warmups 3 \
  --metadata .runtime/network-metadata.json --output research/results/bft-load
python research/summarize.py research/results/bft-load/trials.jsonl \
  --output research/results/bft-load/summary.json
```

Workload source is a host-controlled project directory. Never accept a source
filesystem path from an untrusted upload. This example repeats one document;
replace the workload with a reviewed, stratified document mix for paper evidence.

Each trial starts a new Node process, creates fresh IDs, and records **every**
request. Warm-ups are retained but excluded from inference. Mean, sample standard
deviation and two-sided 95% Student-t intervals use the **trial mean**, not thousands
of requests treated as independent replications. At least 50 trial means are
needed per condition. Trials with no valid commits remain counted failures.
Successful-only latency and offered/successful throughput have separate
interpretations; report error rates and saturation along with latency.

The concurrent fetch promises are offered concurrency. They do not prove 10,000
connections reached the server at the exact same instant. Scheduler delay,
in-flight promise count and server queue time are retained. The API bounds
plaintext upload buffers to 64 MiB and active work to a configured thread pool;
503 responses count as failures, not completed commits. Review client CPU,
connection limits, socket backlog and server saturation before interpreting a
curve. This is a closed-loop burst sweep; add an independently paced arrival-rate
study for production workload claims.

Fresh clients do not alone establish statistical independence. Server/ledger
caches persist. An optional `--reset-script /absolute/executable` runs before each
trial; use it to recreate the chosen server state in a separately supervised
experiment. Record which state is reset, randomized order/seeds, host allocation,
input-size strata, worker count, network delay, block settings, disk type, CPU,
RAM, background load and the exact commit. Assess serial correlation and use a
block/bootstrap analysis if the independent-trial assumption does not hold.

## 2. Ingress corpus

```bash
python -m vendorchain corpus --generate .runtime/regression-corpus --benign 1000 \
  --output research/results/ingress.json
python -m vendorchain corpus --manifest /approved/corpus/manifest.json \
  --output research/results/corporate-ingress.json
```

A manifest contains `version: 1`, `kind`, and an `entries` list. Each entry has
`path` relative to the manifest, `label` (`benign`/`adversarial`), `family`, `sha256`
and `source`. Files cannot escape the corpus root, changed hashes fail the run,
and duplicate specimen hashes are rejected. Metadata such as collection date,
license/consent and independent format/exploit validation should be added for a
real corpus. Do not commit confidential corporate documents or PII.

The generated corpus contains 1,000 unusual synthetic benign documents and 86
inert adversarial fixtures. Its image/PDF+ZIP samples are checked by both parsers
before testing the gate, including containers hidden inside image metadata and
PDFs with a valid final xref/EOF after the ZIP directory. It includes active PDF objects, embedded attachments,
DTD-bearing metadata, bounded high-expansion streams, excessive pixel headers,
and the old extension-spoof cases. It does not contain live exploit binaries,
fully validated GIF/PE specimens, every archive-bomb family or a historical
corporate collection. Calling a file a polyglot because it contains two magic
strings is insufficient. GIF and PE have incompatible mandatory signatures at
byte zero; any claimed GIF/PE sample needs independent full-parser validation.

The supported policy is passive PDF/PNG/JPEG. Unsupported legitimate formats,
encrypted PDFs and active forms are policy rejections; report them as such rather
than covertly removing them from the false-rejection denominator. Define the
in-scope benign population before labeling. `external-corporate-reviewed` is a
provenance label supplied by the curator, not automatically verified by the tool.

Observed zero bypasses does not establish universal zero risk. Exact two-sided
Clopper–Pearson intervals quantify finite-corpus uncertainty and still cannot
cover unseen exploit families. Keep all per-specimen decisions and hashes.

## 3. Stage and resource ablations

```bash
python -m vendorchain ablation --trials 50 --warmups 3 \
  --source "$PWD/chaincode" --output research/results/full-ablation
python research/plot.py research/results/full-ablation/raw.jsonl \
  --output research/results/full-ablation/figures
```

The four variants are structural inline ingress, isolated ingress, local hardened
outbox, and the hardened variant plus ten extra AES encrypt/decrypt loops.
All use the same synthetic input and real Tesseract. They are explicit reference
comparators, not an assertion that the missing paper's original baseline was
recovered. Randomized variant order within 50 trial blocks reduces order bias.
A new Python process and temporary state are used for every trial; host caches
persist. Repeated executions must use a new output directory.

Supply `--source` with installed Syft for real SBOM measurements. Omitting it
records `syft_ms: null`, never an invented Syft duration. The local hardening
comparison measures signature verification, outbox preparation, revalidation and
SQL finalization. It cannot substitute for their overhead on a Fabric deployment.

The plots show CPU seconds (parent and reaped children), largest individual
process peak RSS, and persistent state growth. RSS is **not aggregate peak
concurrent RSS**. Use Docker/cgroup sampling or an external supervisor to obtain
whole-system CPU, RAM, disk-I/O rates and ledger growth under real load.
`research/watch_resources.py --pid API_PID --state .runtime/study --output
research/results/resources.jsonl` records process-tree RSS/CPU ticks, pipeline
disk bytes, and selected containers' Docker CPU/memory/block-I/O measurements.
Container collection errors remain null/error fields. It does not infer ledger
volume growth from block I/O; retain a separate storage-volume usage measurement. No
computational-necessity theorem follows from timing ablations alone; couple costs
with attack-bypass/consistency outcomes when disabling a defense.

## 4. Publication acceptance

Retain raw trial/request logs, corpus manifests, source commit, configuration
hash, exact versions, run times and host metadata. Publish the full measured
matrix only after the actual multi-node campaigns, intended fault model, complete
Syft ablations, corporate false-rejection study and manuscript H1–H7 mapping are
reviewed. Missing data stays missing. Never tune expected outcomes into the runner.

Sources: [Fabric Raft configuration](https://hyperledger-fabric.readthedocs.io/en/latest/raft_configuration.html),
[Gateway commit semantics](https://hyperledger.github.io/fabric-gateway/main/api/node/interfaces/Commit.html),
[pinned sample network](https://github.com/hyperledger/fabric-samples/tree/5789681b4f4d24e58fa40f19a69f5496892374b6/test-network),
[Fabric release](https://github.com/hyperledger/fabric/releases/tag/v3.1.5),
[Syft release](https://github.com/anchore/syft/releases/tag/v1.55.0).

The exact generated corpus used in the retained report is archived in
`research/fixtures/generated-corpus.zip`; extract it into an empty directory and
pass its manifest to the evaluator to repeat the same specimen decisions.
`research/security_ablation.py` compares the retained structural outcomes against
a signature-only reference on those identical archived bytes.
