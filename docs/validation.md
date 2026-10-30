# Evidence status — 30 October 2026

**Updated checklist:** see [the current audit](evidence-checklist.md) and
[new supplementary evidence](../research/results/claim-audit/README.md). The
local tables below describe the earlier retained run with three warm-ups. They
must not be substituted for the new five-warm-up data or for a Fabric sweep.

The repository has been repaired and tested, but the requested publication matrix
is not complete. The earlier manuscript was recovered after the repository-only
audit; its actual control mapping is now in `docs/hardening.md`. The historical
raw outputs and representative private corporate corpus remain unavailable.

## Measured security results

The final generated corpus contains 1,000 benign synthetic documents and 86 inert
adversarial specimens. The isolated structural gate observed:

| Outcome | Observed errors / specimens | Nominal exact two-sided 95% interval |
| --- | --- | --- |
| Adversarial bypass rate | 0 / 86 | 0–4.20% |
| False-rejection rate | 0 / 1,000 | 0–0.368% |

These intervals assume a binomial sampling model. Hand-generated related
specimens are not a random sample of all possible corporate files or attacks;
the intervals are not real-world exploit-risk guarantees. Zero observed errors
must not be generalized to unseen families. No historical corporate corpus was
validated. The archived exact fixtures are
[`generated-corpus.zip`](../research/fixtures/generated-corpus.zip), SHA-256
`8238cb4bef2242ae4c2b084e9684cad71d77811e8f508bf3c6c09990193cb2e4`.
The per-specimen report retains the manifest hash, specimen hashes and decisions.

The header-only ablation admits 70/86 adversarial specimens; the structural gate
admits 0/86 on the same bytes. Both admit the 1,000 generated benign documents.
This establishes a defensive benefit on this corpus, not malware coverage or a
claim that every architecture stage is universally necessary.

## Measured local stage ablation

Each variant has 50 fresh-process trials after three discarded warm-ups. Variant
order is randomized within trial blocks. These are local SQLite-reference trials
on one 1,338-byte generated PNG with real Tesseract. Syft was unavailable in this
local environment and is recorded as null. The isolated comparator and hardened
variant do different persistence work; the measured delta is an architectural
comparison, not a pure single-variable causal estimate.

| Variant | Mean workload latency | Sample SD | 95% t interval |
| --- | ---: | ---: | ---: |
| Structural inline | 242.02 ms | 29.24 ms | 233.71–250.33 ms |
| Isolated ingress pipeline | 364.71 ms | 34.42 ms | 354.93–374.50 ms |
| Hardened local outbox | 403.94 ms | 46.98 ms | 390.58–417.29 ms |
| Hardened plus ten extra AES loops | 405.13 ms | 67.44 ms | 385.96–424.29 ms |

The paired hardened-minus-isolated delta is **39.22 ms**, 95% CI **24.97–53.47 ms**.
The directly instrumented local signature/outbox/revalidation/finalization stages
sum to **7.87 ms**, 95% CI **7.09–8.66 ms**. External consensus latency is absent
from these local deltas. CPU, largest-process RSS and disk-growth measurements
are retained in raw logs and the figures; largest-process RSS is not aggregate
concurrent system RSS.

![Local resource comparison](../research/results/figures/resource-comparison.png)
![Local CPU comparison](../research/results/figures/cpu-comparison.png)
![Local stage measurements](../research/results/figures/stage-times.png)

## Actual Fabric integration

[GitHub run 41026779493](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/41026779493)
passed the original Python/Gateway/Go race/vet and BFT integration checks
at source commit `b2947886d01aefa3b2d7efbbb1b4714c8eb07fb8`.
The job verified a committed channel with four BFT consenters, executed real
Tesseract and Syft, and confirmed three uploads per burst. It passed both the
healthy and one-orderer-crash conditions. There was one measured trial per
condition and one healthy warm-up: this is an integration smoke test.
The actual channel configuration, image IDs, request timings and provenance are
retained in `research/results/bft-smoke/`. All orderers and peers shared one
GitHub runner; development certificates were used. No malicious-orderer or
cross-host network-partition test was executed.

A separate independent-deployment 100-upload campaign completed all 50 jobs:
[run 41033853808](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/41033853808),
source `6332c83e6ee716ba9b343a77c2c36a7726c4f00f`. Job conclusions and all 50
artifact records were checked; the raw artifact contents have not been downloaded
and recomputed here. It used one warm-up per deployment, so it does not meet the
requested five-warm-up protocol. Its expiring artifact URLs and digests are indexed
in `research/results/claim-audit/previous-campaign.json`. The earlier pilot is a
separate cohort and is not pooled into this campaign.

The final XML-encoding fix also passed **44 Python, 7 Gateway and 7 Go tests**,
Go race/vet, and BFT integration in
[run 41030667638](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/41030667638)
at commit `37502648bdb151f700193de7dbd59874931afda8`. The archived 86-file adversarial
corpus was replayed unchanged against this fix. The local 50-trial ablations were
rerun; the table above uses those final measurements. The larger BFT campaign
uses the earlier tested commit and PNG inputs, which do not exercise XML metadata.

## Remaining publication requirements

| Requested evidence | Status |
| --- | --- |
| Multi-node consensus execution | Four-orderer BFT integration passed; all nodes colocated |
| 100-upload N ≥ 50 campaign | 50 jobs passed; one warm-up, raw review and requested protocol incomplete |
| 250–10,000 upload N ≥ 50 sweeps | Runner implemented; not executed |
| Production workload/host/network fidelity | Not established by the colocated test network |
| Historical corporate false-rejection study | Corpus not supplied; manifest evaluator implemented |
| GIF/PE and validated live parser-exploit corpus | Not supplied or claimed; inert structural specimens tested |
| Full OCR/Syft/resource ablation on production topology | Local OCR ablation completed; external full matrix pending |
| Formal manuscript H1–H7 alignment | Definitions recovered and mapped; full implementation incomplete |
| Publication-ready claim that all requested results are obtained | Not supported |

The implementation adds the mechanisms needed to run these experiments. It does
not manufacture the measurements or redefine a development test as production
validation.
