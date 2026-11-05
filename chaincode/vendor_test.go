package main

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/base64"
 "encoding/json"
 "fmt"
 "strings"
 "testing"
 "github.com/golang/protobuf/ptypes/timestamp"
 "github.com/hyperledger/fabric-chaincode-go/shimtest"
 "github.com/hyperledger/fabric-contract-api-go/contractapi"
)
type testIdentity struct{ admin bool; msp string }
func (i *testIdentity) GetID()(string,error){ return "test-client",nil }
func (i *testIdentity) GetMSPID()(string,error){ return i.msp,nil }
func (i *testIdentity) GetAttributeValue(name string)(string,bool,error){ return "submitter",true,nil }
func (i *testIdentity) AssertAttributeValue(name,value string)error{ return nil }
func (i *testIdentity) GetX509Certificate()(*x509.Certificate,error){
 ou:="client";if i.admin { ou="admin" };return &x509.Certificate{Subject:pkix.Name{OrganizationalUnit:[]string{ou}}},nil
}
func setup(t *testing.T)(*SmartContract,*contractapi.TransactionContext,*shimtest.MockStub,ed25519.PrivateKey){
 t.Helper();stub:=shimtest.NewMockStub("vendorchain",nil);stub.MockTransactionStart("setup")
 stub.TxTimestamp=&timestamp.Timestamp{Seconds:1000}
 ctx:=new(contractapi.TransactionContext);ctx.SetStub(stub);ctx.SetClientIdentity(&testIdentity{true,"Org1MSP"})
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil { t.Fatal(err) }
 s:=new(SmartContract)
 if err:=s.RegisterWorkerKey(ctx,"worker",base64.StdEncoding.EncodeToString(pub),900,5000);err!=nil{t.Fatal(err)}
 stub.MockTransactionEnd("setup");return s,ctx,stub,priv
}
func receipt(t *testing.T,priv ed25519.PrivateKey,rid string)(string,string){
 t.Helper();h:=strings.Repeat("a",64)
 r:=Receipt{"vendorchain.receipt.v1",rid,"vendor",h,h,h,h,"PASS","worker",1000,1600,rid}
 raw,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
 return base64.StdEncoding.EncodeToString(raw),base64.StdEncoding.EncodeToString(ed25519.Sign(priv,raw))
}
func tx(stub *shimtest.MockStub,id string){stub.MockTransactionStart(id);stub.TxTimestamp=&timestamp.Timestamp{Seconds:1001}}
func TestHardenedReceiptAndReplay(t *testing.T){
 s,ctx,stub,priv:=setup(t);r,sig:=receipt(t,priv,"record1");tx(stub,"tx1")
 if err:=s.RecordHardened(ctx,"record1",r,sig);err!=nil{t.Fatal(err)}
 v,err:=s.QueryCompliance(ctx,"record1");if err!=nil||v.TransactionID!="tx1"{t.Fatalf("readback: %+v %v",v,err)}
 stub.MockTransactionEnd("tx1");tx(stub,"tx2")
 if s.RecordHardened(ctx,"record1",r,sig)==nil{t.Fatal("replay overwrote immutable record")}
}
func TestTamperAndRevocation(t *testing.T){
 s,ctx,stub,priv:=setup(t);r,sig:=receipt(t,priv,"record1");tx(stub,"tx1")
 if s.RecordHardened(ctx,"record1",r,base64.StdEncoding.EncodeToString(make([]byte,64)))==nil{t.Fatal("unsigned receipt accepted")}
 if s.RecordHardened(ctx,"other",r,sig)==nil{t.Fatal("context swap accepted")}
 if err:=s.RevokeWorkerKey(ctx,"worker");err!=nil{t.Fatal(err)}
 if s.RecordHardened(ctx,"record1",r,sig)==nil{t.Fatal("revoked key accepted")}
}
func TestExpiredReceipt(t *testing.T){
 s,ctx,stub,priv:=setup(t);r,sig:=receipt(t,priv,"record1");tx(stub,"tx1");stub.TxTimestamp=&timestamp.Timestamp{Seconds:1600}
 if s.RecordHardened(ctx,"record1",r,sig)==nil{t.Fatal("expired receipt accepted")}
}
func TestDeterministicProposalTimestamp(t *testing.T){
 for n:=0;n<2;n++{
  s,ctx,stub,_:=setup(t);tx(stub,fmt.Sprint(n));stub.TxTimestamp=&timestamp.Timestamp{Seconds:1234}
  if err:=s.RegisterVendor(ctx,"vendor1","name","company",false);err!=nil{t.Fatal(err)}
  v,err:=s.QueryVendor(ctx,"vendor1");if err!=nil{t.Fatal(err)}
  if v.Timestamp!="1970-01-01T00:20:34Z"{t.Fatal(v.Timestamp)}
 }
}
func TestNamespacesAndSelfCertification(t *testing.T){
 s,ctx,stub,_:=setup(t);tx(stub,"tx1")
 if s.RegisterVendor(ctx,"worker","name","company",true)==nil{t.Fatal("self-certification accepted")}
 if err:=s.RegisterVendor(ctx,"worker","name","company",false);err!=nil{t.Fatal("key namespaces collided:",err)}
 if s.RegisterVendor(ctx,"../bad","name","company",false)==nil{t.Fatal("invalid ID accepted")}
 if s.RecordCompliance(ctx,"r","v",strings.Repeat("a",64),"PASS",0)==nil{t.Fatal("legacy signature bypass")}
}
func TestUnauthorizedKeyRegistration(t *testing.T){
 s,ctx,stub,_:=setup(t);tx(stub,"tx1");ctx.SetClientIdentity(&testIdentity{false,"Org1MSP"})
 if s.RevokeWorkerKey(ctx,"worker")==nil{t.Fatal("non-admin revoked worker key")}
 ctx.SetClientIdentity(&testIdentity{true,"UntrustedMSP"})
 if s.RegisterVendor(ctx,"v","n","c",false)==nil{t.Fatal("untrusted MSP accepted")}
}
func TestContractMetadataBuilds(t *testing.T){
 if _,err:=contractapi.NewChaincode(new(SmartContract));err!=nil{t.Fatal(err)}
}
