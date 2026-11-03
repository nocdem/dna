// Parent test oracle. Link only the pinned upstream Falcon/CIRCL/Edwards
// packages. Input and output are public fixture material. Never import src/pq.
//
// Modes (argv: mode, hex of the input):
//   curve, mldsa65, algorand - as before.
//   splendor - Splendor's own rule (sqc-wallet 38ac3ded, cmd/wallet/seed.go:42-51,
//     core/crypto/mldsa.go:154-160,252-275): input = hex of the UTF-8 phrase;
//     lower-case + single spaces, go-bip39 v1.1.0 EntropyFromMnemonic (32 bytes,
//     no PBKDF2), CIRCL v1.6.5 NewKeyFromSeed, address "SQ:" + hex(SHA3-256(pk)).
//   mnemonic - go-bip39 v1.1.0 NewMnemonic of the input entropy (used only to
//     turn public entropies into phrases for the Soqucoin retry search).
// XION and secp-zero are in native2/ (a second module: the Cosmos SDK graph
// resolves circl v1.6.3, this module circl v1.6.5; plan section 6).
package main

import (
 "crypto/sha512"
 "encoding/base32"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "os"
 "strings"
 "filippo.io/edwards25519"
 "github.com/algorand/falcon"
 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
 "github.com/tyler-smith/go-bip39"
 "golang.org/x/crypto/sha3"
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
 case "splendor":
  phrase:=strings.ToLower(strings.Join(strings.Fields(string(input))," "))
  entropy,e:=bip39.EntropyFromMnemonic(phrase);if e!=nil {panic(e)}
  if len(entropy)!=32 {panic("phrase must be 24 words (32-byte entropy)")}
  var seed [32]byte;copy(seed[:],entropy)
  pk,_:=mldsa65.NewKeyFromSeed(&seed);raw,e:=pk.MarshalBinary();if e!=nil {panic(e)}
  digest:=sha3.Sum256(raw)
  if e:=json.NewEncoder(os.Stdout).Encode(map[string]any{"seed":hex.EncodeToString(seed[:]),"pk":hex.EncodeToString(raw),"address":"SQ:"+hex.EncodeToString(digest[:])});e!=nil {panic(e)}
 case "mnemonic":
  phrase,e:=bip39.NewMnemonic(input);if e!=nil {panic(e)}
  fmt.Print(phrase)
 default:panic("unknown mode")
 }
}
