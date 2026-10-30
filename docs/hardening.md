# Implemented control mapping

The supplied notes describe seven control gaps but do not include the manuscript's
formal H1–H7 definitions. The labels below are an **operational mapping for this
repair**, not a claim that the absent paper uses identical numbering. Reconcile
them against the manuscript before publication.

| Control | Implemented mechanism | Validation |
| --- | --- | --- |
| H1: Worker trust | Ed25519 receipts, administrator-pinned validity intervals, revocation, authorized MSP/client roles | Python and Go tests for unknown/revoked/expired/tampered keys; ledger key in Fabric MVCC read set |
| H2: Document binding | Exactly 64 hex characters decode to a 32-byte KEK; fresh DEK and nonces; vendor/request/type AAD in payload encryption and DEK wrapping | Cross-vendor/request swaps and tampering fail authentication |
| H3: Hostile ingress | Full bounded parsers, decoded active-PDF object inspection, CRC/segment/trailer checks, page/pixel/expansion limits | Generated polyglots independently validate through both image/PDF and ZIP readers; inert active content, DTD and expansion fixtures rejected |
| H4: Concurrency | Atomic claim, immutable input bindings, snapshot version, expiring worker lease, deterministic request idempotency | 24 competing claims produce one owner; stale results and conflicting request-ID reuse fail |
| H5: DB/ledger coordination | Transactional durable outbox, exact receipt-hash reconciliation, valid-commit readback before DB finalization | Ledger outage, lost acknowledgement and local finalization failure remain recoverable; false acknowledgements do not finalize |
| H6: Ledger integrity | Proposal timestamps; separate composite key namespaces; append-only compliance records; self-certification and old unsigned write route disabled | Go deterministic-timestamp/replay/authorization tests; Gateway tests distinguish endorsement from commit |
| H7: Revalidation and audit | Recheck current version, worker validity, document/ciphertext/SBOM hashes before delivery; chained local events with update/delete triggers; isolated OCR process | Tampered ciphertext and revoked keys fail before commit; audit mutation tests and chain verification |

## Important boundaries

- The receipt attests that an authorized worker reported a result. It is not a
  cryptographic proof of OCR correctness, government registration, or malware
  absence. No GST government integration or identity-certification claim is made.
- Fabric mode now executes the new reference OPA bundle and signs its decision;
  its exact bytes contribute to the policy hash and are rechecked before delivery.
  The policy checks format, worker digest/identity outcomes and SBOM presence. It
  is not the missing manuscript Listing 1, a government lookup or an AI risk model.
  Empty expected OCR terms establish no vendor credential match. The new GSTIN
  checksum/PAN component is tested separately; it is not wired to a vendor registry.
- SQLite plus Fabric cannot perform a shared atomic commit. `PREPARED` and
  `PENDING` are visible recovery states. A lost response after an external commit
  can leave the SQL projection behind until reconciliation succeeds.
- Database triggers do not defeat a database administrator who can drop them.
  Hash chaining needs an externally retained checkpoint to detect truncation or
  complete rewriting; signed ledger receipt hashes provide document anchors,
  not a universal anchor of every local audit event.
- Filesystem mutation after a local pre-submit check remains outside a
  cross-system atomic snapshot. Production storage needs immutable object
  versions and separate IAM principals. Current hashes detect modifications at
  the validation point, not all future writes by a compromised host.
- Key material is generated at runtime with mode 0600. Python and crypto libraries
  create memory copies; bytearray wiping is best-effort and does not prove
  erasure of heap copies, swap or caches. Disable host swap/core dumps as required
  by the deployment's actual threat model.
- The parser/OCR process has rlimits and timeouts, not a container-seccomp or VM
  security boundary. A true native parser exploit needs stronger host isolation.
- Old raw-key ledger data is not silently migrated. The new namespace and receipt
  format are a breaking protocol change; deploy to a new research channel first.
