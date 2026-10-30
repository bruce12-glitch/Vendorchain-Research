# Supplementary evidence: 30 October 2026

This supplement documents new measurements and the remaining gaps. It does not
recover the original 12-suite/44-test application or its historical timing logs.
The complete status is in [the checklist](../../../docs/evidence-checklist.md).

[Download the retained raw evidence](raw-evidence.zip). The archive contains the
raw trial/request logs, exact new binary fixtures, per-specimen corpus decisions,
functional terminal logs, CI logs, actual peer query, signature experiment files,
source snapshot, resource plots and SHA-256 manifest. No runtime private key is
included. The checksum of the archive is in `archive-sha256.txt`.

## Functional and cryptographic observations

- **59 Python tests, 9 Gateway tests and 6 Rego cases passed locally.** The Rego
  cases also execute inside a Python integration test, so these counts should
  not be summed as distinct tests. Raw logs are under `local/` in the archive.
- **7 Go tests with the race detector and Go vet passed in CI.** The complete
  unit and BFT job logs are retained under `ci/` in the archive. Tested source:
  `6dc7661f85aa8be00adc5d836f19bc72f5f87dc4`.
- **15/15 new inert prefix fixtures rejected** with `EXECUTABLE_SPOOF`, eight PE
  and seven ELF. Each observation checks the owned receive buffer is zero-filled,
  the submission is absent and the encrypted-object count remains zero. This is
  local-file storage evidence, not an S3/MinIO test or a loadable-executable corpus.
- **The original archived synthetic corpus was replayed unchanged:** 0/86
  adversarial bypasses and 0/1,000 benign false rejections. Nominal exact binomial
  95% upper bounds are 4.20% and 0.368%. Related hand-generated specimens are not
  random real-world samples; these bounds do not cover unseen attack families or
  establish performance on historical corporate files.
- **Three context swaps fail with exactly `InvalidTag`:** vendor, submission and
  document type. Ciphertext and wrapped key are otherwise unchanged.
- **Real Cosign positive and negative controls passed.** The local experiment
  uses a handwritten CycloneDX component fixture. The BFT job repeats it on real
  Syft output: original verification exits 0; mutated JSON verification exits 1.
  Verification is offline with an explicit public key; transparency-log and
  keyless identity guarantees are outside this experiment.
- **Actual Fabric CLI query retained.** The queried record's decoded receipt
  hashes match its commitment, and its transaction ID matches the upload's
  commit acknowledgement. It contains signed receipt/identity metadata, not
  document bytes or a full SBOM. It is not an enumeration of every namespace or
  verification against the absent manuscript's Equation 9.

The passing run is [41074705369](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/41074705369).
Its four orderers and peers are colocated on one development runner. Healthy and
one-orderer-crash smoke conditions passed; malicious-orderer behavior, network
partitions and production topology were not evaluated.

## New feasibility measurements

Five warm-up trials were retained and excluded, followed by 50 measured trials,
each in a fresh process. Every outlier is retained. The structural gate and local
pipeline use the same 1,338-byte generated PNG; envelope operations use an actual
passive PDF of exactly 5 MiB. The local pipeline executes real Tesseract and a
SQLite ledger double; it does not execute Syft, OPA or Fabric.

All durations are milliseconds. Percentiles describe the 50 trial measurements,
using R7 interpolation; they are not production request-tail estimates.

| Measurement | Mean | Sample SD | Median / p50 | p95 | p99 | Two-sided 95% t interval |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Direct structural gate | 0.716 | 0.401 | 0.540 | 1.533 | 1.975 | 0.602–0.830 |
| Envelope encryption, 5 MiB PDF | 27.522 | 92.358 | 12.300 | 29.614 | 356.315 | 1.274–53.769 |
| Envelope decryption, 5 MiB PDF | 8.459 | 3.853 | 7.514 | 14.545 | 20.844 | 7.364–9.554 |
| Local Luhn mod-36 / PAN check | 0.0629 | 0.0609 | 0.0365 | 0.1692 | 0.3048 | 0.0456–0.0802 |
| Local ingestion to commit | 940.821 | 1531.037 | 686.619 | 1098.983 | 6576.799 | 505.705–1375.937 |

The large SDs and outliers matter. Student-t intervals depend on the sampling
assumptions; a shared managed host, persistent host caches and fresh-process
library initialization do not recreate a steady production service. These data
do not validate the original 4.8 ms encryption or 342 ms Fabric latency claims.
See `local/timing-raw.jsonl`, `local/timing-summary.json`, `local/metadata.json`
and `local/measurement-source.zip` in the archive.

## Local resource and hardening comparison

The four reference variants each have 50 measured fresh-process runs after five
warm-ups, with randomized variant order. This is **not** Table 12's seven-stage
study. Real OCR runs; Syft/OPA/Fabric do not. CPU, largest-process RSS and persistent
state bytes are recorded; RSS is not aggregate system memory or a cgroup limit.

| Reference variant | Mean elapsed time | 95% t interval |
| --- | ---: | --- |
| Structural inline | 476.11 ms | 436.02–516.19 ms |
| Isolated pipeline | 729.27 ms | 653.69–804.85 ms |
| Hardened local outbox | 777.45 ms | 700.79–854.11 ms |
| Hardened plus ten AES loops | 811.61 ms | 737.06–886.17 ms |

The paired hardened-minus-isolated mean is **48.18 ms**, CI **−30.65–127.00 ms**;
this run does not establish a consistently positive architectural delta. The
directly instrumented hardening stages sum to **20.63 ms**, CI **12.08–29.18 ms**.
The variants do different persistence work, so neither number is a pure causal
estimate of distributed hardening overhead. Raw data, summaries and CPU/resource/
stage plots are under `ablation/` in the archive.

## Oversized ingress and prior campaign

One local smoke burst at each offered concurrency 100, 1,000 and 10,000 declared
a 1 GiB length while sending **zero body bytes**. All 11,100 requests received
HTTP 400; document-buffer peak and encrypted-object count remained zero. The
API's lifetime peak RSS rose to 107,960 KiB. Socket and interpreter memory are
outside the 64 MiB owned-document-buffer budget; these data establish no fixed
global RSS bound. See `oversized-headers/` in the archive.

The previous 100-upload BFT campaign has 50 successful job conclusions and 50
artifact records. It used one warm-up per deployment, not five. The artifact
inventory is retained in `previous-campaign.json`; its expiring artifact URLs
are not permanent preservation of their raw contents. No old artifact was
silently treated as downloaded, recomputed or compliant with the new protocol.

## Reproduction

Use the tested branch and the versions/checksums in the installers and metadata:

```bash
bash research/scripts/install-validation-tools.sh
export PATH="$PWD/.runtime/bin:$PATH" PYTHONPATH="$PWD/research"
python research/collect_local_evidence.py --output .runtime/new-local-evidence --trials 50 --warmups 5
python -m vendorchain ablation --output .runtime/new-ablation --trials 50 --warmups 5
python research/validate_ingress_memory.py --output .runtime/new-oversized-study
```

Each output directory must be new. Follow `docs/experiments.md` for the separate
real Fabric/Syft/OPA integration. Exact fixtures, not just their labels, are
retained. Historical corporate false-rejection data, full concurrency sweeps,
the seven-variant external matrix and formal manuscript reconciliation remain
unobtained.
