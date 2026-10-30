package main

import (
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "regexp"
 "time"
 "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type SmartContract struct{ contractapi.Contract }
type Vendor struct {
 VendorID string `json:"vendorID"`
 Name string `json:"name"`
 Company string `json:"company"`
 Certified bool `json:"certified"`
 Timestamp string `json:"timestamp"`
}
type WorkerKey struct {
 KeyID string `json:"keyID"`
 PublicKey string `json:"publicKey"`
 NotBefore int64 `json:"notBefore"`
 NotAfter int64 `json:"notAfter"`
 Revoked bool `json:"revoked"`
}
// Receipt is signed as exact UTF-8 bytes, never reserialized by the verifier.
type Receipt struct {
 Version string `json:"version"`
 RecordID string `json:"recordID"`
 VendorID string `json:"vendorID"`
 DocumentHash string `json:"documentHash"`
 CiphertextHash string `json:"ciphertextHash"`
 SBOMHash string `json:"sbomHash"`
 PolicyHash string `json:"policyHash"`
 Decision string `json:"decision"`
 KeyID string `json:"keyID"`
 IssuedAt int64 `json:"issuedAt"`
 ExpiresAt int64 `json:"expiresAt"`
 Nonce string `json:"nonce"`
}
type ComplianceRecord struct {
 RecordID string `json:"recordID"`
 VendorID string `json:"vendorID"`
 ReceiptHash string `json:"receiptHash"`
 Receipt string `json:"receipt"`
 Signature string `json:"signature"`
 TransactionID string `json:"transactionID"`
 Timestamp string `json:"timestamp"`
}
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
func key(ctx contractapi.TransactionContextInterface, kind, id string) (string, error) {
 if !idPattern.MatchString(id) { return "", fmt.Errorf("invalid %s identifier", kind) }
 return ctx.GetStub().CreateCompositeKey(kind, []string{id})
}
func txTime(ctx contractapi.TransactionContextInterface) (time.Time, error) {
 ts, err := ctx.GetStub().GetTxTimestamp()
 if err != nil || ts == nil { return time.Time{}, fmt.Errorf("transaction timestamp unavailable") }
 return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC(), nil
}
// Replace this sample MSP allowlist when deploying to another consortium.
func authorized(ctx contractapi.TransactionContextInterface, admin bool) error {
 identity := ctx.GetClientIdentity()
 msp, err := identity.GetMSPID()
 if err != nil || (msp != "Org1MSP" && msp != "Org2MSP") { return fmt.Errorf("untrusted MSP") }
 cert, err := identity.GetX509Certificate()
 if err != nil || cert == nil { return fmt.Errorf("X.509 identity required") }
 for _, ou := range cert.Subject.OrganizationalUnit { if ou == "admin" { return nil } }
 if !admin {
  role, found, err := identity.GetAttributeValue("vendorchain.role")
  if err == nil && found && role == "submitter" { return nil }
 }
 return fmt.Errorf("authorized submitter/admin identity required")
}
func putNew(ctx contractapi.TransactionContextInterface, k string, value interface{}) error {
 old, err := ctx.GetStub().GetState(k); if err != nil { return err }
 if old != nil { return fmt.Errorf("immutable record already exists") }
 data, err := json.Marshal(value); if err != nil { return err }
 return ctx.GetStub().PutState(k, data)
}
func (s *SmartContract) RegisterVendor(ctx contractapi.TransactionContextInterface, vendorID, name, company string, certified bool) error {
 if err := authorized(ctx, false); err != nil { return err }
 if certified { return fmt.Errorf("clients cannot self-certify vendors") }
 if len(name)==0 || len(name)>256 || len(company)==0 || len(company)>256 { return fmt.Errorf("invalid vendor details") }
 k, err := key(ctx,"vendor",vendorID); if err != nil { return err }
 now, err := txTime(ctx); if err != nil { return err }
 return putNew(ctx,k,Vendor{vendorID,name,company,false,now.Format(time.RFC3339Nano)})
}
func (s *SmartContract) QueryVendor(ctx contractapi.TransactionContextInterface, vendorID string) (*Vendor,error) {
 k, err := key(ctx,"vendor",vendorID); if err != nil { return nil,err }
 b, err := ctx.GetStub().GetState(k); if err != nil { return nil,err }
 if b==nil { return nil,fmt.Errorf("vendor not found; legacy raw keys need explicit migration") }
 var v Vendor; if err:=json.Unmarshal(b,&v); err!=nil { return nil,err }; return &v,nil
}
func (s *SmartContract) RegisterWorkerKey(ctx contractapi.TransactionContextInterface, keyID, publicKey string, notBefore, notAfter int64) error {
 if err:=authorized(ctx,true); err!=nil { return err }
 pub,err:=base64.StdEncoding.DecodeString(publicKey)
 if err!=nil || len(pub)!=ed25519.PublicKeySize { return fmt.Errorf("invalid Ed25519 public key") }
 if notBefore<0 || notAfter<=notBefore { return fmt.Errorf("invalid key validity interval") }
 k,err:=key(ctx,"worker",keyID); if err!=nil { return err }
 return putNew(ctx,k,WorkerKey{keyID,publicKey,notBefore,notAfter,false})
}
func (s *SmartContract) RevokeWorkerKey(ctx contractapi.TransactionContextInterface, keyID string) error {
 if err:=authorized(ctx,true); err!=nil { return err }
 k,err:=key(ctx,"worker",keyID); if err!=nil { return err }
 b,err:=ctx.GetStub().GetState(k); if err!=nil { return err }; if b==nil { return fmt.Errorf("worker key not found") }
 var wk WorkerKey; if err:=json.Unmarshal(b,&wk); err!=nil { return err }; wk.Revoked=true
 data,err:=json.Marshal(wk); if err!=nil { return err }; return ctx.GetStub().PutState(k,data)
}
func (s *SmartContract) RecordHardened(ctx contractapi.TransactionContextInterface, recordID, receipt, signature string) error {
 if err:=authorized(ctx,false); err!=nil { return err }
 if len(receipt)>16384 || len(signature)>128 { return fmt.Errorf("oversized receipt") }
 raw,err:=base64.StdEncoding.DecodeString(receipt); if err!=nil { return err }
 var r Receipt; dec:=json.NewDecoder(bytes.NewReader(raw)); dec.DisallowUnknownFields()
 if err:=dec.Decode(&r); err!=nil { return err }; if dec.Decode(new(interface{}))!=io.EOF { return fmt.Errorf("trailing JSON data") }
 if r.Version!="vendorchain.receipt.v1" || r.RecordID!=recordID || r.Nonce!=recordID { return fmt.Errorf("receipt context mismatch") }
 if r.Decision!="PASS" && r.Decision!="FAIL" { return fmt.Errorf("invalid policy decision") }
 for _,h:=range []string{r.DocumentHash,r.CiphertextHash,r.SBOMHash,r.PolicyHash} { if !hashPattern.MatchString(h) { return fmt.Errorf("invalid receipt digest") } }
 if !idPattern.MatchString(r.VendorID) { return fmt.Errorf("invalid vendor identifier") }
 k,err:=key(ctx,"record",recordID); if err!=nil { return err }
 wkKey,err:=key(ctx,"worker",r.KeyID); if err!=nil { return err }
 wkBytes,err:=ctx.GetStub().GetState(wkKey); if err!=nil { return err }; if wkBytes==nil { return fmt.Errorf("unknown worker key") }
 var wk WorkerKey; if err:=json.Unmarshal(wkBytes,&wk); err!=nil { return err }
 now,err:=txTime(ctx); if err!=nil { return err }; t:=now.Unix()
 if wk.Revoked || t<wk.NotBefore || t>=wk.NotAfter || r.IssuedAt<wk.NotBefore || r.ExpiresAt>wk.NotAfter || r.IssuedAt>t+30 || r.ExpiresAt<=t || r.ExpiresAt<=r.IssuedAt || r.ExpiresAt-r.IssuedAt>3600 { return fmt.Errorf("expired, revoked, or invalid attestation") }
 pub,err:=base64.StdEncoding.DecodeString(wk.PublicKey); if err!=nil || len(pub)!=ed25519.PublicKeySize { return fmt.Errorf("corrupt worker key") }
 sig,err:=base64.StdEncoding.DecodeString(signature); if err!=nil || !ed25519.Verify(pub,raw,sig) { return fmt.Errorf("invalid worker signature") }
 h:=sha256.Sum256(raw)
 record:=ComplianceRecord{recordID,r.VendorID,hex.EncodeToString(h[:]),receipt,signature,ctx.GetStub().GetTxID(),now.Format(time.RFC3339Nano)}
 // Record and key enter the MVCC read set: duplicate submissions and revocations
 // racing endorsement are rejected during peer validation if their reads go stale.
 return putNew(ctx,k,record)
}
func (s *SmartContract) QueryCompliance(ctx contractapi.TransactionContextInterface, recordID string) (*ComplianceRecord,error) {
 k,err:=key(ctx,"record",recordID); if err!=nil { return nil,err }
 b,err:=ctx.GetStub().GetState(k); if err!=nil { return nil,err }; if b==nil { return nil,fmt.Errorf("compliance record not found") }
 var r ComplianceRecord; if err:=json.Unmarshal(b,&r); err!=nil { return nil,err }; return &r,nil
}
// A fail-closed migration error keeps the old endpoint from bypassing signatures.
func (s *SmartContract) RecordCompliance(ctx contractapi.TransactionContextInterface, recordID, vendorID, sbomHash, opaResult string, aiRiskScore int) error {
 return fmt.Errorf("legacy unsigned submissions disabled; use RecordHardened")
}
func (s *SmartContract) GetAuditHistory(ctx contractapi.TransactionContextInterface, recordID string) (string,error) {
 k,err:=key(ctx,"record",recordID); if err!=nil { return "",err }
 it,err:=ctx.GetStub().GetHistoryForKey(k); if err!=nil { return "",err }; defer it.Close()
 history:=[]map[string]interface{}{}
 for it.HasNext() { v,err:=it.Next(); if err!=nil { return "",err }; history=append(history,map[string]interface{}{"txID":v.TxId,"timestamp":v.Timestamp.String(),"isDeleted":v.IsDelete,"value":string(v.Value)}) }
 b,err:=json.Marshal(history); return string(b),err
}
func main() {
 cc,err:=contractapi.NewChaincode(&SmartContract{}); if err!=nil { panic(err) }
 if err:=cc.Start(); err!=nil { panic(err) }
}
