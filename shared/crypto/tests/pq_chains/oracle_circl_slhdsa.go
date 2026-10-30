// Test oracle for Splendor's pinned CIRCL v1.6.5, raw FIPS packed keys.
package main
import (
 "bytes"
 "encoding/hex"
 "encoding/json"
 "os"
 "github.com/cloudflare/circl/sign/slhdsa"
)
func main() {
 seed:=make([]byte,48);for i:=range seed {seed[i]=byte(i)}
 pk,sk,e:=slhdsa.GenerateKey(bytes.NewReader(seed),slhdsa.SHA2_128s);if e!=nil {panic(e)}
 p,e:=pk.MarshalBinary();if e!=nil {panic(e)};s,e:=sk.MarshalBinary();if e!=nil {panic(e)}
 msg:=[]byte("splendor-quantum known-answer message");rows:=[]map[string]any{}
 for i,ctx:=range [][]byte{[]byte("SPLENDOR-QC-TX-v1"),[]byte("SPLENDOR-QC-BLOCK-v1"),make([]byte,255)} {
  sig,e:=slhdsa.SignDeterministic(&sk,slhdsa.NewMessage(msg),ctx);if e!=nil {panic(e)}
  if !slhdsa.Verify(&pk,slhdsa.NewMessage(msg),sig,ctx) {panic("reference verification")}
  framed:=append([]byte{0,byte(len(ctx))},ctx...);framed=append(framed,msg...)
  fields:=[][]byte{seed,framed,ctx,p,s,sig,p[:16],msg};hexfields:=[]string{}
  for _,f:=range fields {hexfields=append(hexfields,hex.EncodeToString(f))}
  rows=append(rows,map[string]any{"scheme":3,"param":1,"id":5000+i,"flags":23,"fields":hexfields})
 }
 if e:=json.NewEncoder(os.Stdout).Encode(rows);e!=nil {panic(e)}
}
