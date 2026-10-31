// Parent test oracle. Link only the pinned upstream Falcon/CIRCL/Edwards
// packages. Input and output are public fixture material. Never import src/pq.
package main

import (
 "crypto/sha512"
 "encoding/base32"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "filippo.io/edwards25519"
 "github.com/algorand/falcon"
 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
)
func main() {
 if len(os.Args)!=3 { panic("mode hex-input required") }
 input,e:=hex.DecodeString(os.Args[2]);if e!=nil {panic(e)}
 switch os.Args[1] {
 case "curve":
  _,e:=new(edwards25519.Point).SetBytes(input);fmt.Print(e==nil)
 case "mldsa65":
  if len(input)!=32 {panic("seed length")};var seed [32]byte;copy(seed[:],input)
  pk,_:=mldsa65.NewKeyFromSeed(&seed);raw,e:=pk.MarshalBinary();if e!=nil {panic(e)}
  fmt.Print(hex.EncodeToString(raw))
 case "algorand":
  if len(input)!=32 {panic("seed length")};pk,_,e:=falcon.GenerateKey(input);if e!=nil {panic(e)}
  var address string;var salt int
  for salt=0;salt<256;salt++ {
   pre:=append([]byte{'P','Q','A','f','1',byte(salt)},pk[:]...)
   raw:=sha512.Sum512_256(pre)
   if _,e:=new(edwards25519.Point).SetBytes(raw[:]);e==nil {continue}
   checksum:=sha512.Sum512_256(raw[:]);body:=append(raw[:],checksum[28:]...)
   address=base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(body);break
  }
  if address=="" {panic("salt exhausted")}
  if e:=json.NewEncoder(os.Stdout).Encode(map[string]any{"seed":os.Args[2],"pk":hex.EncodeToString(pk[:]),"salt":salt,"address":address});e!=nil {panic(e)}
 default:panic("unknown mode")
 }
}
