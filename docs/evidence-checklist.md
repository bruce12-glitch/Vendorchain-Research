# Publication evidence checklist

Checked on 30 October 2026. **The complete requested evidence is not present.**
The repaired research pipeline is in [draft PR #1](https://github.com/bruce12-glitch/Vendorchain-Research/pull/1).
The default `main` branch still contains the upstream Fabric/SBOM prototype, not
the Next.js application described by its old README. A passing CI run validates
its executed checks; it does not certify the entire manuscript checklist.

The supplied attachment is an audit of the older upstream snapshot. It is not
the manuscript, its Equation 9, Listing 1, Table 12 or formal H1–H7 definitions.
Those exact historical specifications and raw outputs have not been recovered.

| Requested proof | Finding after this repair | Evidence or remaining work |
| --- | --- | --- |
| Original 12 suites / 44 unit tests | Missing historical evidence | The original application and suite are absent. Report the new suite's actual counts; do not rename it to match 12/44. |
| Functional header, envelope, checksum, policy and chaincode checks | New implementation and tests | Python security tests, Gateway tests, Go race/vet, a new local GSTIN checksum validator and real OPA tests. The checksum component is not a government lookup or an integrated vendor-credential registry. |
| Fifteen PE/ELF spoof rejections | New regression evidence | Fifteen **new inert prefix fixtures**, eight PE and seven ELF, reject with `EXECUTABLE_SPOOF`; owned bytearrays are zeroed and local encrypted-object/submission counts remain zero. The old archived fifteen fixtures are all PE prefixes. Neither set is a validated collection of loadable malicious executables or the recovered historical PE/ELF set. |
| No object-store persistence on rejection | Partial | Demonstrated for local encrypted-file storage and SQL. No S3/MinIO deployment was exercised. |
| Hash-only ledger / Equation 9 | Partial | The integration now captures actual `peer chaincode query` stdout and checks hashes, transaction ID and the decoded receipt schema. The record also stores a signed receipt and metadata. One compliance query does not enumerate all world-state namespaces or establish equivalence to the missing Equation 9. |
| Historical <1.2 / 4.8 / 0.04 / 342 ms timer outputs | Missing | Original terminal outputs are absent. New measured values are retained without enforcing those targets; 5 MiB is explicitly 5,242,880 bytes. Local-commit timings are not Fabric timings. |
| Cross-submission AES-GCM context binding | Demonstrated locally | Changing vendor, submission or document type while preserving ciphertext/envelope produces exactly `cryptography.exceptions.InvalidTag`. |
| Mutated SBOM fails Cosign | Demonstrated with stated scope | Real offline Cosign accepts an original blob and rejects its changed JSON using the same public key/signature. Local input is a handwritten CycloneDX component fixture; BFT integration repeats the experiment on real Syft output. No Rekor/Fulcio claim. The pipeline's receipt signature remains Ed25519; this experiment does not make every pipeline SBOM a Cosign-signed artifact. |
| N ≥ 50, five discarded warm-ups, all requested statistics | Demonstrated for local feasibility trials | Fresh child process per trial; mean, sample SD, median, p50/p95/p99 and two-sided Student-t 95% interval retained. Shared-host caches and independence/background-load assumptions remain limitations. |
| Multi-node CFT/BFT ordering | Demonstrated on a development topology | Existing four-orderer BFT smoke evidence and a one-orderer crash check. All nodes share one GitHub runner. This is not a distributed production or malicious-orderer evaluation. |
| Existing 100-upload / 50-deployment BFT campaign | Completed jobs; incomplete protocol/evidence review | All 50 job conclusions and 50 artifact records were checked. The campaign used **one** warm-up per deployment; it fails the requested five-warm-up protocol. Raw artifact contents have not been recomputed here. Their expiring URLs are recorded, not represented as permanent raw data. |
| New 100–10,000 upload consensus sweeps | Not obtained | A runner exists, and future independent-campaign workflow warm-ups are now five. The full matrix has not been executed or statistically validated. |
| Advanced adversarial corpus | Bounded synthetic evidence | The retained corpus reports 0/86 bypasses, with independently parsed image/PDF+ZIP polyglots, inert active content, DTD-bearing metadata and bounded expansion cases. It does not establish zero bypasses against native parser exploits or all bomb families. |
| False rejections on historical corporate variants | Not obtained | Retained 0/1,000 result concerns generated documents. A representative, authorized historical corpus with independently established ground truth is absent. |
| Stage-level decryption/OCR/Syft/OPA/Fabric timing | Instrumented; external coverage partial | Real Fabric mode now requires OPA and records `opa_ms`; the HTTP server records `queue_dispatch_ms`. Existing decryption/OCR/Syft/commit stages remain distinct. Missing local external stages are null. Fabric commit timing combines endorsement, ordering, commit wait and readback rather than measuring each separately. |
| Table 12's seven progressive architecture variants | Not obtained | The executed local study has four reference comparators, not the seven requested variants. Fifty measured runs plus five warm-ups per comparator do not substitute for the missing seven-variant external study. |
| CPU/RAM/disk and heavy-encryption comparison | Local reference evidence | Four variants, real Tesseract, raw CPU/largest-process RSS/persistent-byte logs and plots. Syft/OPA/Fabric are not executed in this local comparison. These are not whole-system cgroup or ledger-volume measurements. |
| Hardened design overhead | Local component evidence | Signature verification, outbox preparation, current-key/input/policy revalidation and DB finalization are timed. Compare architectures cautiously: their persistence work differs. The outbox gives recoverable coordination, not atomic synchronized commits across SQL and Fabric. |
| Concurrent oversized upload memory | Narrow local smoke evidence | The separate API process rejects declared 1 GiB requests at offered concurrency 100, 1,000 and 10,000, without reading a body or reserving document buffers. N=1 per condition. This does not prove a global RSS bound for accepted bodies, slow clients, decoder copies or the full Fabric load. |
| H1–H7 exact implementation and validation | Unresolved mapping | Seven operational controls and regression checks exist. The manuscript's exact definitions are absent. Request-ID idempotency exists; content-digest/retention-window replay rejection does not. |
| Measurement harness and exact fixtures | Present for new experiments | `research/collect_local_evidence.py`, the ablation/load runners, archived fixture bytes, source snapshots, raw logs and SHA-256 manifests. These are not the recovered original experiment. |
| Dependency locks / exact tool versions | Present with boundaries | Gateway `package-lock.json`, chaincode `go.mod`/`go.sum`, exact Python direct requirements and checksum-pinned Fabric/Syft/OPA/Cosign installers. Tesseract/Poppler are system packages; capture actual versions rather than infer them from the Node/Go locks. |
| Exact Rego Listing 1 | Missing historical rule; new reference policy present | `research/policies/reference.rego` is versioned and actually executed in Fabric mode. It is explicitly a new policy, not recovered Listing 1. Empty OCR expectations do not establish vendor identity. |

New supplementary material and its scope are indexed in
[the evidence directory](../research/results/claim-audit/README.md).
Retain failed requests, outliers and warm-up rows. Do not describe this repository
as a completed production evaluation until the missing corpus, workload, fault,
ablation and manuscript-alignment work is actually performed.
