# Measured local reference and bounded CI validation

Measurement source: `4ceaa19f995bdaee92f7a218dd2b3ca0b3d186c3` (clean tree).
This is a new cohort; it does not recover the missing campaign from the earlier
chat. The repository's historical Solo observations and older fixed-order cohorts
remain separate.

The randomized sequential campaign completed 50 measured trials and five
discarded warmups per variant: seven cumulative variants plus two comparators,
450 measured trials and 45 warmups overall. No trials failed. Each was a fresh
process using synthetic PNGs, real Tesseract/Syft/Cosign/OPA, SQLite and disposable
software keys. No Fabric throughput is inferred from these timings. The full
variant adds evidence-root/outbox hardening as well as the local ledger.

| Variant | Measured N | Mean elapsed ms | 95% Student-t interval |
| --- | --- | --- | --- |
| Baseline | 50 | 0.776 | [0.730, 0.822] |
| Gate | 50 | 110.147 | [106.152, 114.143] |
| Encryption | 50 | 110.232 | [107.692, 112.772] |
| Identity | 50 | 335.128 | [329.983, 340.273] |
| Provenance | 50 | 1517.064 | [1498.336, 1535.792] |
| Policy | 50 | 1549.961 | [1531.392, 1568.530] |
| Full | 50 | 1603.260 | [1578.415, 1628.105] |
| Full without client revalidation | 50 | 1563.720 | [1540.989, 1586.450] |
| Full with ten extra crypto loops | 50 | 1598.149 | [1578.108, 1618.191] |

Latency excludes configuration/key loading and database initialization. Exact
values, SD, median, R7 p50/p95/p99, stage metrics, failures and paired contrasts
are in the JSON/CSV/LaTeX exports. Non-monotone estimates are retained; the heavier
crypto comparator's lower mean is not evidence that extra work speeds the system
up. See paired intervals and the workload/isolation limitations. Parent/child
CPU and individual-process RSS have the boundaries documented in the runbook;
individual RSS peaks are not simultaneous process-tree memory.

`countProtocolMet` is true and `qualifiedForPaper` remains false. Counts and
hashes do not independently establish host isolation, statistical independence,
workload representativeness or authenticity. Author review is required before
using the observations as paper results.

## Retained raw evidence

`raw-evidence.tar.xz` contains all 495 trial directories, original per-trial input
bytes, parent records and worker measurements, journal, plan, source hashes,
metadata, statistical exports and figures under `campaign/`. It also retains
preflight/local validation logs, the CI provenance below, and three original CI
artifact ZIPs. No deployment directory, software private key or Vault/API token
is included. The local timing workers use disposable transient evidence stores;
this cohort measures pipeline operations, not long-term evidence availability.

Extract into a new directory, then check:

```bash
tar -xJf raw-evidence.tar.xz -C /path/to/new-directory
python research/verify_campaign.py /path/to/new-directory/campaign
```

The inner manifest verifies raw files, journal and recomputed exports. The outer
`sha256-manifest.json` pins this supplement's files and archive. Subsequent
verifier/load-export fixes have separate source provenance and do not alter the
measured values or source commit of this cohort.

## Real CI and the local capacity failure

[CI run 42155159401](https://github.com/bruce12-glitch/Vendorchain-Research/actions/runs/42155159401)
passed all four jobs on the measurement source commit:

- Unit: **135 Python tests passed, zero skips**, real PostgreSQL 16.2 and Vault
  1.18.3; 15 Node tests; Go race tests/vet; policy and shell checks.
- Hardened four-orderer Raft and BFT: each committed three valid-document
  uploads, then three more after stopping one orderer; hash-only world-state
  readback and all six operational records reconciled.
- Existing reference BFT integration also passed.

The hardened artifacts preserve actual channel configuration, peer stdout,
receipts, signatures, snapshots, inventory, encrypted objects and crash checks.
These are tiny colocated development-certificate workloads. They do not establish
production throughput, malicious Byzantine behavior or the 100–10,000-upload
matrix. Artifact ZIP digests are retained by the surrounding archive and its
manifest; the original GitHub artifacts have finite retention.

A separate attempt to bootstrap Raft locally failed before deployment when this
environment's 7.9 GB `vfs` Docker filesystem filled while extracting images.
Its logs and explicit no-measurements report remain under
`local-consensus-attempt/`. BFT was skipped locally for the same prerequisite.
Those local failures are not CI results and are not timing observations.

Still unmeasured: the full independent-deployment load matrix, representative
reviewed corporate documents, hardware HSM/evidence-conditional signing, live
registry/certificate revocation, multi-host production faults and field trials.
Use [the runbook](../../../docs/empirical-readiness.md) for the next experiments.
