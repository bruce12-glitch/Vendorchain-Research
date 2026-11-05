package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func evidenceReceipt(t *testing.T, priv ed25519.PrivateKey, rid string) (EvidenceReceipt, string, string, string) {
	t.Helper()
	h := strings.Repeat("a", 64)
	r := EvidenceReceipt{Version: "vendorchain.receipt.v2", RecordID: rid, VendorID: "vendor", DocumentHash: h, CiphertextHash: h, SBOMHash: h, ArtifactHash: h, IdentityHash: h, SnapshotHash: h, PolicyHash: h, Decision: "PASS", KeyID: "decision", IssuedAt: 1000, ExpiresAt: 1600, Nonce: rid, Algorithm: "sha256"}
	root := sha256.New()
	b, _ := hex.DecodeString(h)
	for i := 0; i < 5; i++ {
		root.Write(b)
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], 1000)
	root.Write(stamp[:])
	r.EvidenceRoot = hex.EncodeToString(root.Sum(nil))
	raw, _ := json.Marshal(r)
	return r, base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw)), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
}
func TestEvidenceCommitHashOnlyAndWriteOnce(t *testing.T) {
	s, ctx, stub, priv := setup(t)
	tx(stub, "v2-setup")
	pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	if err := s.RegisterEvidenceKey(ctx, "decision", pub, 900, 5000, "decision"); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterPolicyDigest(ctx, strings.Repeat("a", 64), 900, 5000); err != nil {
		t.Fatal(err)
	}
	_, raw, sig, ssig := evidenceReceipt(t, priv, "v2")
	tx(stub, "v2-commit")
	if err := s.RecordEvidence(ctx, "v2", raw, sig, ssig); err != nil {
		t.Fatal(err)
	}
	record, err := s.QueryEvidence(ctx, "v2")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(record)
	if strings.Contains(string(encoded), "gstin") || strings.Contains(string(encoded), "components") || strings.Contains(string(encoded), "receipt\"") {
		t.Fatal("unexpected payload in ledger")
	}
	if record.TransactionID != "v2-commit" || record.EvidenceRoot == "" || record.SignatureHash == "" {
		t.Fatal("missing audit binding")
	}
	tx(stub, "v2-replay")
	if s.RecordEvidence(ctx, "v2", raw, sig, ssig) == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestEvidenceRejectsWrongRoleRevocationAndPolicyChanges(t *testing.T) {
	for _, scenario := range []string{"wrong-role", "revoked-key", "revoked-policy", "bad-root", "bad-snapshot", "unknown-policy"} {
		t.Run(scenario, func(t *testing.T) {
			s, ctx, stub, priv := setup(t)
			tx(stub, "setup-v2")
			pub := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
			role := "decision"
			if scenario == "wrong-role" {
				role = "identity"
			}
			if err := s.RegisterEvidenceKey(ctx, "decision", pub, 900, 5000, role); err != nil {
				t.Fatal(err)
			}
			if scenario != "unknown-policy" {
				if err := s.RegisterPolicyDigest(ctx, strings.Repeat("a", 64), 900, 5000); err != nil {
					t.Fatal(err)
				}
			}
			r, raw, sig, ssig := evidenceReceipt(t, priv, "v2")
			if scenario == "revoked-key" {
				if err := s.RevokeEvidenceKey(ctx, "decision"); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "revoked-policy" {
				if err := s.RevokePolicyDigest(ctx, strings.Repeat("a", 64)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "bad-root" {
				r.EvidenceRoot = strings.Repeat("b", 64)
				b, _ := json.Marshal(r)
				raw = base64.StdEncoding.EncodeToString(b)
				sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
			}
			if scenario == "bad-snapshot" {
				ssig = base64.StdEncoding.EncodeToString(make([]byte, 64))
			}
			tx(stub, "attack")
			if s.RecordEvidence(ctx, "v2", raw, sig, ssig) == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}
