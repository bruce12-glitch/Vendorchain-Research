package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"io"
)

// EvidenceReceipt contains digests only. Signed identity/GSTIN, SBOM and decision
// input are retained off-chain and bound through the Equation 13 evidence root.
type EvidenceReceipt struct {
	Version        string `json:"version"`
	RecordID       string `json:"recordID"`
	VendorID       string `json:"vendorID"`
	DocumentHash   string `json:"documentHash"`
	CiphertextHash string `json:"ciphertextHash"`
	SBOMHash       string `json:"sbomHash"`
	ArtifactHash   string `json:"artifactHash"`
	IdentityHash   string `json:"identityHash"`
	SnapshotHash   string `json:"snapshotHash"`
	PolicyHash     string `json:"policyHash"`
	EvidenceRoot   string `json:"evidenceRoot"`
	Decision       string `json:"decision"`
	KeyID          string `json:"keyID"`
	IssuedAt       int64  `json:"issuedAt"`
	ExpiresAt      int64  `json:"expiresAt"`
	Nonce          string `json:"nonce"`
	Algorithm      string `json:"algorithm"`
}
type EvidenceKey struct {
	KeyID     string `json:"keyID"`
	PublicKey string `json:"publicKey"`
	NotBefore int64  `json:"notBefore"`
	NotAfter  int64  `json:"notAfter"`
	Revoked   bool   `json:"revoked"`
	Role      string `json:"role"`
}
type PolicyDigest struct {
	Digest    string `json:"digest"`
	NotBefore int64  `json:"notBefore"`
	NotAfter  int64  `json:"notAfter"`
	Revoked   bool   `json:"revoked"`
}
type EvidenceRecord struct {
	RecordID      string `json:"recordID"`
	VendorID      string `json:"vendorID"`
	EvidenceRoot  string `json:"evidenceRoot"`
	SnapshotHash  string `json:"snapshotHash"`
	PolicyHash    string `json:"policyHash"`
	Decision      string `json:"decision"`
	SignatureHash string `json:"signatureHash"`
	KeyID         string `json:"keyID"`
	Algorithm     string `json:"algorithm"`
	IssuedAt      int64  `json:"issuedAt"`
	ReceiptHash   string `json:"receiptHash"`
	TransactionID string `json:"transactionID"`
}

func (s *SmartContract) RegisterEvidenceKey(ctx contractapi.TransactionContextInterface, keyID, publicKey string, notBefore, notAfter int64, role string) error {
	if err := authorized(ctx, true); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || notBefore < 0 || notAfter <= notBefore {
		return fmt.Errorf("invalid evidence key")
	}
	if role != "identity" && role != "decision" && role != "policy" {
		return fmt.Errorf("invalid evidence key role")
	}
	k, err := key(ctx, "evidenceKey", keyID)
	if err != nil {
		return err
	}
	return putNew(ctx, k, EvidenceKey{keyID, publicKey, notBefore, notAfter, false, role})
}
func (s *SmartContract) RevokeEvidenceKey(ctx contractapi.TransactionContextInterface, keyID string) error {
	if err := authorized(ctx, true); err != nil {
		return err
	}
	k, err := key(ctx, "evidenceKey", keyID)
	if err != nil {
		return err
	}
	raw, err := ctx.GetStub().GetState(k)
	if err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("unknown evidence key")
	}
	var value EvidenceKey
	if err = json.Unmarshal(raw, &value); err != nil {
		return err
	}
	value.Revoked = true
	raw, err = json.Marshal(value)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(k, raw)
}
func (s *SmartContract) RegisterPolicyDigest(ctx contractapi.TransactionContextInterface, digest string, notBefore, notAfter int64) error {
	if err := authorized(ctx, true); err != nil {
		return err
	}
	if !hashPattern.MatchString(digest) || notBefore < 0 || notAfter <= notBefore {
		return fmt.Errorf("invalid policy registration")
	}
	k, err := ctx.GetStub().CreateCompositeKey("policy", []string{digest})
	if err != nil {
		return err
	}
	return putNew(ctx, k, PolicyDigest{digest, notBefore, notAfter, false})
}
func (s *SmartContract) RevokePolicyDigest(ctx contractapi.TransactionContextInterface, digest string) error {
	if err := authorized(ctx, true); err != nil {
		return err
	}
	if !hashPattern.MatchString(digest) {
		return fmt.Errorf("invalid policy digest")
	}
	k, err := ctx.GetStub().CreateCompositeKey("policy", []string{digest})
	if err != nil {
		return err
	}
	raw, err := ctx.GetStub().GetState(k)
	if err != nil {
		return err
	}
	if raw == nil {
		return fmt.Errorf("unknown policy")
	}
	var value PolicyDigest
	if err = json.Unmarshal(raw, &value); err != nil {
		return err
	}
	value.Revoked = true
	raw, err = json.Marshal(value)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(k, raw)
}
func (s *SmartContract) RecordEvidence(ctx contractapi.TransactionContextInterface, recordID, encodedReceipt, signature, snapshotSignature string) error {
	if err := authorized(ctx, false); err != nil {
		return err
	}
	if len(encodedReceipt) > 16384 || len(signature) > 128 || len(snapshotSignature) > 128 {
		return fmt.Errorf("oversized evidence receipt")
	}
	raw, err := base64.StdEncoding.DecodeString(encodedReceipt)
	if err != nil {
		return err
	}
	var r EvidenceReceipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&r); err != nil {
		return err
	}
	if dec.Decode(new(interface{})) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	if r.Version != "vendorchain.receipt.v2" || r.RecordID != recordID || r.Nonce != recordID || !idPattern.MatchString(r.VendorID) || r.Algorithm != "sha256" {
		return fmt.Errorf("invalid evidence context")
	}
	if r.Decision != "PASS" && r.Decision != "FAIL" {
		return fmt.Errorf("invalid decision")
	}
	for _, h := range []string{r.DocumentHash, r.CiphertextHash, r.SBOMHash, r.ArtifactHash, r.IdentityHash, r.SnapshotHash, r.PolicyHash, r.EvidenceRoot} {
		if !hashPattern.MatchString(h) {
			return fmt.Errorf("invalid evidence digest")
		}
	}
	root := sha256.New()
	for _, h := range []string{r.CiphertextHash, r.SBOMHash, r.ArtifactHash, r.IdentityHash, r.SnapshotHash} {
		b, _ := hex.DecodeString(h)
		root.Write(b)
	}
	var stamp [8]byte
	binary.BigEndian.PutUint64(stamp[:], uint64(r.IssuedAt))
	root.Write(stamp[:])
	if r.IssuedAt < 0 || hex.EncodeToString(root.Sum(nil)) != r.EvidenceRoot {
		return fmt.Errorf("evidence root mismatch")
	}
	wk, err := key(ctx, "evidenceKey", r.KeyID)
	if err != nil {
		return err
	}
	value, err := ctx.GetStub().GetState(wk)
	if err != nil {
		return err
	}
	if value == nil {
		return fmt.Errorf("unknown evidence key")
	}
	var worker EvidenceKey
	if err = json.Unmarshal(value, &worker); err != nil {
		return err
	}
	now, err := txTime(ctx)
	if err != nil {
		return err
	}
	t := now.Unix()
	if worker.Role != "decision" || worker.Revoked || t < worker.NotBefore || t >= worker.NotAfter || r.IssuedAt < worker.NotBefore || r.IssuedAt > t+30 || r.ExpiresAt <= t || r.ExpiresAt > worker.NotAfter || r.ExpiresAt <= r.IssuedAt || r.ExpiresAt-r.IssuedAt > 3600 {
		return fmt.Errorf("inactive/wrong-role decision key or stale receipt")
	}
	pk, err := ctx.GetStub().CreateCompositeKey("policy", []string{r.PolicyHash})
	if err != nil {
		return err
	}
	value, err = ctx.GetStub().GetState(pk)
	if err != nil {
		return err
	}
	if value == nil {
		return fmt.Errorf("unregistered policy")
	}
	var policy PolicyDigest
	if err = json.Unmarshal(value, &policy); err != nil {
		return err
	}
	if policy.Revoked || t < policy.NotBefore || t >= policy.NotAfter || r.IssuedAt < policy.NotBefore {
		return fmt.Errorf("inactive policy")
	}
	pub, err := base64.StdEncoding.DecodeString(worker.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("corrupt public key")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || !ed25519.Verify(pub, raw, sig) {
		return fmt.Errorf("invalid receipt signature")
	}
	ssig, err := base64.StdEncoding.DecodeString(snapshotSignature)
	snapshot, _ := hex.DecodeString(r.SnapshotHash)
	if err != nil || !ed25519.Verify(pub, snapshot, ssig) {
		return fmt.Errorf("invalid decision snapshot signature")
	}
	rh := sha256.Sum256(raw)
	dh := sha256.Sum256(ssig)
	record := EvidenceRecord{r.RecordID, r.VendorID, r.EvidenceRoot, r.SnapshotHash, r.PolicyHash, r.Decision, hex.EncodeToString(dh[:]), r.KeyID, r.Algorithm, r.IssuedAt, hex.EncodeToString(rh[:]), ctx.GetStub().GetTxID()}
	k, err := key(ctx, "record", recordID)
	if err != nil {
		return err
	}
	// Key/policy/record reads participate in Fabric MVCC validation, including
	// revocation or conflicting creates between endorsement and commit.
	return putNew(ctx, k, record)
}
func (s *SmartContract) QueryEvidence(ctx contractapi.TransactionContextInterface, recordID string) (*EvidenceRecord, error) {
	k, err := key(ctx, "record", recordID)
	if err != nil {
		return nil, err
	}
	raw, err := ctx.GetStub().GetState(k)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("record not found")
	}
	var value EvidenceRecord
	if err = json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value.EvidenceRoot == "" {
		return nil, fmt.Errorf("not a v2 evidence record")
	}
	return &value, nil
}
