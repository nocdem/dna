// Test oracle: run separately with the chain-pinned CIRCL v1.6.3 and v1.6.5.
package main

import (
 "crypto/sha3"
 "encoding/hex"
 "encoding/json"
 "os"
 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)
func hx(b []byte) string { return hex.EncodeToString(b) }
func anchor(b []byte,want string) { h:=sha3.Sum256(b);if hx(h[:])!=want {panic("Splendor committed KAT mismatch")} }
func main() {
 var seed [32]byte;copy(seed[:],[]byte("splendor-quantum-kat-seed-000001"))
 pk,sk:=mldsa65.NewKeyFromSeed(&seed);p,e:=pk.MarshalBinary();if e!=nil {panic(e)};s,e:=sk.MarshalBinary();if e!=nil {panic(e)}
 anchor(p,"a1384dd6dfb705282f8f7e239d34337ae48f1c2f212db49f8ebf87d60a396325")
 anchor(s,"ce564aeaad15f83f2ffe6c150a2347f869aa08acb0fac5b2312c474c7c429839")
 msg:=[]byte("splendor-quantum known-answer message");ctxs:=[][]byte{[]byte("SPLENDOR-QC-TX-v1"),[]byte("SPLENDOR-QC-BLOCK-v1"),nil,make([]byte,255)}
 answers:=[]string{"ca5f30a9c721be55e99a9db9773bf2332b73b1c2b15c618e1aadb6dcf8b2e8f0","e0e38906d1184322c04810027bfc93c0e3f32089e1644acd38a0d2a8476fd0bb"}
 rows:=[]map[string]any{}
 for i,ctx:=range ctxs {
  sig:=make([]byte,mldsa65.SignatureSize);if e:=mldsa65.SignTo(sk,msg,ctx,false,sig);e!=nil {panic(e)}
  if !mldsa65.Verify(pk,msg,ctx,sig) {panic("reference verification")};if i<2 {anchor(sig,answers[i])}
  framed:=append([]byte{0,byte(len(ctx))},ctx...);framed=append(framed,msg...)
  fields:=[][]byte{seed[:],framed,ctx,p,s,sig,make([]byte,32),msg};hexfields:=[]string{}
  for _,f:=range fields {hexfields=append(hexfields,hx(f))}
  rows=append(rows,map[string]any{"scheme":5,"param":65,"id":4000+i,"flags":23,"fields":hexfields})
 }
 if e:=json.NewEncoder(os.Stdout).Encode(rows);e!=nil {panic(e)}
}
