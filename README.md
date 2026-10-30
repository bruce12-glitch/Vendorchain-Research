# VendorChain research validation

This repository now contains an executable document-ingestion research pipeline,
Fabric chaincode, and reproducible experiment runners. It does **not** contain
the Next.js/PostgreSQL/BullMQ application described by the previous README.

The original snapshot was `8640146b86877a8a0f61ff15bbe172fef9cc7812`.
The repair replaces nondeterministic endorsement timestamps, unsigned compliance
writes, and unrestricted record overwrites with proposal timestamps, pinned
Ed25519 worker keys, immutable namespaced records, and commit-confirmed receipts.

## What runs

- Structural PDF/PNG/JPEG parsing in a process with memory, CPU, file-size and
  wall-clock bounds. Active PDF objects, DTD-bearing XML metadata, image trailers,
  excessive expansion and excessive pixel dimensions are rejected.
- Context-bound AES-256-GCM envelope encryption with chunked cipher operations.
  Tesseract and Poppler work through pipes; OCR text stays in a disposable process.
- An atomic SQLite reference state machine and durable outbox. A request becomes
  `COMMITTED` only after a matching valid ledger result and local finalization.
- A Fabric Gateway bridge that waits for `getStatus()` and reads the committed
  receipt back. Lost acknowledgements reconcile by immutable receipt hash.
- A pinned four-orderer Fabric BFT network, healthy/crash integration scripts,
  a 100–10,000 offered-concurrency sweep, independent-trial statistics, adversarial
  corpus evaluation, stage/resource logs, and comparison plots.

SQLite is the reference implementation here. PostgreSQL, production identity
management, a distributed deployment, and production workload evidence remain
separate integration work. An outbox coordinates two durable systems; it does
not turn them into a distributed atomic transaction.

## Local tests

Linux/WSL2, Python 3.12+, Node 22.12+, Tesseract and Poppler are required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r research/requirements.txt
export PYTHONPATH="$PWD/research"
python -m unittest discover -s research/tests -v
node --test research/gateway/test.mjs
(cd chaincode && go test -race ./... && go vet ./...)
```

A deliberately labelled local demonstration can run without Fabric or Syft:

```bash
python -m vendorchain init --state .runtime/demo
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m vendorchain serve --state .runtime/demo --local --no-sbom
```

The upload route is `POST http://127.0.0.1:8090/v1/uploads`, with the document as
its raw body, `Authorization: Bearer $API_TOKEN`, `X-Vendor-ID`, and a unique
`X-Request-ID`. It returns a receipt and stage times after commitment. Its local
mode returns `evidence: local-non-consensus` and cannot supply consensus results.
The API is a bounded loopback research server, intended for controlled experiments.

## Research workflow

Read [the experiment instructions](docs/experiments.md),
[the hardening/control mapping](docs/hardening.md), and
[the evidence status](docs/validation.md) before using results in a manuscript.

```bash
# Inert generated fixtures, including independently parsed image/ZIP polyglots:
python -m vendorchain corpus --generate .runtime/corpus --benign 1000 \
  --output research/results/ingress.json
# Real OCR; Syft is explicitly not measured unless --source is supplied:
python -m vendorchain ablation --trials 50 --warmups 3 \
  --output research/results/ablation
python research/plot.py research/results/ablation/raw.jsonl \
  --output research/results/figures
```

No corpus can establish universal zero bypasses. The evaluator reports observed
errors, denominators, specimen hashes and exact binomial confidence intervals.
Generated documents are not historical corporate records.

## Layout

| Path | Purpose |
| --- | --- |
| `chaincode/` | Authorized worker registry and immutable signed receipts |
| `research/vendorchain/` | Gate, encryption, OCR isolation, state machine, outbox, API |
| `research/gateway/` | TLS Fabric client and commit/readback bridge |
| `research/scripts/` | Verified BFT bootstrap and integration smoke test |
| `research/load*.mjs` | Fresh-process load trials and raw request logs |
| `research/results/` | Measured local evidence, explicitly scoped |
| `docs/` | Protocol, limitations, acceptance criteria |
| `config/` | Historical upstream sample configuration; not the research launcher |

The tracked cosign key is a **public** verification key. The supplied audit's
claim that this alone proves exposed private keys is not supported by this tree.
Runtime secrets and generated artifacts are ignored. No Git history is rewritten.
