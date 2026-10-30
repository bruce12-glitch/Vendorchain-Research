# Manuscript-aligned hardening status

The earlier `VendorChain_complete_position_fixed.tex` was located and read after
the initial repository-only audit. The table below uses its actual Section 8
definitions (lines 1950–2065). It supersedes the earlier operational numbering.
**The full H1–H7 design is not implemented.** The manuscript itself distinguishes
specified hardening from measured prototype evidence.

| Manuscript control | Current implementation | Remaining gap |
| --- | --- | --- |
| H1: Signed identity attestation | Signed worker receipts bind submission/vendor/document hashes and a verdict | No complete signed GSTIN, identity-state, checksum/OCR-result, worker/version attestation consumed by the gate; no trusted per-vendor identity registry. A local checksum module and text match are not this attestation. |
| H2: Signed decision snapshot | Receipt signs a verdict and policy hash; delivery checks the current hash | No complete input snapshot with policy and OPA versions, no independently signed policy bundle verified before evaluation, and no full decision-replay implementation. |
| H3: Object-hash evidence root | Receipt binds ciphertext, document and SBOM hashes | No specified evRoot over encrypted object, SBOM, artifact digest, identity attestation, decision snapshot and time; complete retention/auditor access and hash agility are absent. |
| H4: Commit-time revalidation | Go verifies registered worker signatures, expiry, immutable identifiers and MVCC-protected key/record reads; Gateway confirms VALID commit and readback | Complete Delta/ComplianceRecord+ schema is absent. A compromised authorized signer remains trusted; neither evidence-conditional external signing nor independent policy recomputation is implemented. |
| H5: Ledger-first synchronized dual write | Durable SQLite outbox and post-confirmation finalization; exact-hash recovery through CLI/retries | The manuscript's PostgreSQL integration and automatic divergence-detecting reconciliation job are absent. A recoverable outbox, rather than a shared atomic transaction, is the paper's specified approach. |
| H6: Key lifecycle and custody | Local 32-byte KEK, fresh DEKs/nonces, worker validity/revocation checks, best-effort buffer wiping | No non-exportable KMS/HSM custody, KEK versioned wrapping, scheduled rotation or authorized KMS revocation checks; worker signing custody remains in-process. |
| H7: Content-digest replay window | Duplicate request IDs cannot create a second immutable record | Identical content with different submission IDs is still accepted. No digest uniqueness index with a configured retention window is enforced. The diagnostic reproduces this gap. |

Additional working defenses include context-bound AES-GCM, a bounded structural
parser/OCR subprocess, atomic worker claims, append-only local audit events,
explicit executable-prefix rejection and owned-buffer wiping. These mechanisms
are tested, but are not substitutes for the missing formal controls above.

Listing 1 is recovered verbatim in `research/manuscript/listing-1.rego` and tested
with real OPA in v0-compatible mode on synthetic predicate inputs. The active
reference policy is intentionally separate: it cannot assert that certificate,
software-provenance, identity-state and replay predicates have been established.
Empty expected OCR terms now cause a reference-policy denial. A successful ledger
acknowledgement means a verdict was committed; the API returns `decision`
separately so a committed `FAIL` is not confused with an authorization `PASS`.

## Important boundaries

- The receipt attests that an authorized worker reported a result. It is not a
  cryptographic proof of OCR correctness, government registration, or malware
  absence. No GST government integration or identity-certification claim is made.
- Fabric mode now executes the new reference OPA bundle and signs its decision;
  its exact bytes contribute to the policy hash and are rechecked before delivery.
  The policy checks format, worker digest/identity outcomes and SBOM presence. It
  is not the recovered manuscript Listing 1, a government lookup or an AI risk model.
  Nonempty expected text still establishes no registered vendor identity. The GSTIN
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
