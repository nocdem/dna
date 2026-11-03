// Second parent test oracle: the Cosmos SDK's own key code, on the SDK's own
// dependency graph (circl v1.6.3 through cometbft v0.40.0), never src/pq.
// Input and output are public fixture material. Plan section 6, Kurultay 52
// conditions 1 and 3.
//
// Modes (argv: mode, hex of the input):
//   xion - `xiond keys add --key-type ml_dsa_65 --recover` (XION 9b0acaff,
//     Cosmos SDK 64fd208a): input = hex of the UTF-8 phrase. Runs
//     hd.MlDsa65.Derive()(phrase, "", "m/44'/118'/0'/0/0") (crypto/hd/mldsa65.go
//     -> algo.go Secp256k1.Derive -> hdpath.go), then
//     crypto/keys/mldsa65.GenPrivKeyFromSeed, then PubKey().Address().
//     Output JSON: seed (the 32-byte BIP32 key = the ML-DSA-65 seed), pk, address
//     (the 20 address bytes; Bech32 "xion" is applied by prepare_fixtures.py).
//   secp-zero - zero-parent case of hdpath.go derivePrivateKey (non-hardened
//     step): input = hex of a 32-byte chain code. Output JSON: compressed (decred
//     secp256k1/v4 v4.4.1 PrivKeyFromBytes(32 zero bytes).PubKey()
//     .SerializeCompressed()), childKey (hd.DerivePrivateKeyForPath of the zero
//     parent with the chain code and path "m/0"), childChain (second half of
//     HMAC-SHA512(chain, compressed || BE32(0)); the SDK's exported function
//     returns only the key, so this half is computed here from the native
//     compressed bytes and the first half is checked against the SDK's childKey).
package main

import (
 "bytes"
 "crypto/hmac"
 "crypto/sha512"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "math/big"
 "os"
 secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
 "github.com/cosmos/cosmos-sdk/crypto/hd"
 "github.com/cosmos/cosmos-sdk/crypto/keys/mldsa65"
)
func main() {
 if len(os.Args)!=3 { panic("mode hex-input required") }
 input,e:=hex.DecodeString(os.Args[2]);if e!=nil {panic(e)}
 switch os.Args[1] {
 case "xion":
  seed,e:=hd.MlDsa65.Derive()(string(input),"","m/44'/118'/0'/0/0");if e!=nil {panic(e)}
  priv,e:=mldsa65.GenPrivKeyFromSeed(seed);if e!=nil {panic(e)}
  pub:=priv.PubKey()
  if e:=json.NewEncoder(os.Stdout).Encode(map[string]any{"seed":hex.EncodeToString(seed),"pk":hex.EncodeToString(pub.Bytes()),"address":hex.EncodeToString(pub.Address())});e!=nil {panic(e)}
 case "secp-zero":
  if len(input)!=32 {panic("chain code length")}
  var zero,chain [32]byte;copy(chain[:],input)
  compressed:=secp.PrivKeyFromBytes(zero[:]).PubKey().SerializeCompressed()
  child,e:=hd.DerivePrivateKeyForPath(zero,chain,"m/0");if e!=nil {panic(e)}
  mac:=hmac.New(sha512.New,chain[:]);mac.Write(compressed);mac.Write([]byte{0,0,0,0})
  sum:=mac.Sum(nil)
  want:=new(big.Int).Mod(new(big.Int).SetBytes(sum[:32]),secp.S256().N).FillBytes(make([]byte,32))
  if !bytes.Equal(child,want) {panic(fmt.Sprintf("SDK child key differs from IL mod n: %x vs %x",child,want))}
  if e:=json.NewEncoder(os.Stdout).Encode(map[string]any{"compressed":hex.EncodeToString(compressed),"childKey":hex.EncodeToString(child),"childChain":hex.EncodeToString(sum[32:])});e!=nil {panic(e)}
 default:panic("unknown mode")
 }
}
