// Test-only verifier using pinned ixiosSpark native transaction decoder/Sender.
package main
import("encoding/hex";"fmt";"os";"strings";"math/big";"github.com/ixios-io/ixiosSpark/core/types")
func main(){if len(os.Args)!=2{panic("usage: verify raw-hex-file")};data,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)};raw,err:=hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(data)),"0x"));if err!=nil{panic(err)};var tx types.Transaction;if err=tx.UnmarshalBinary(raw);err!=nil{panic(err)};address,err:=types.Sender(types.NewEIP155Signer(big.NewInt(1)),&tx);if err!=nil{panic(err)};fmt.Printf("%s %s\n",tx.Hash().Hex(),address.Hex())}
