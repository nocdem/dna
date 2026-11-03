// Offline oracle for ixiosSpark ccd1345eed8873a6d0174b3e9a076da67ceb7750.
// Run this file (not directory) from that source module. Synthetic state only.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/holiman/uint256"
	"github.com/ixios-io/ixiosSpark/common"
	"github.com/ixios-io/ixiosSpark/core"
	"github.com/ixios-io/ixiosSpark/core/rawdb"
	"github.com/ixios-io/ixiosSpark/core/state"
	"github.com/ixios-io/ixiosSpark/core/txpool"
	"github.com/ixios-io/ixiosSpark/core/types"
	"github.com/ixios-io/ixiosSpark/core/vm"
	"github.com/ixios-io/ixiosSpark/params"
	"github.com/ixios-io/ixiosSpark/zeta"
	"math/big"
	"os"
	"strings"
)

func main() {
	for _, name := range []string{"full", "compact", "high-limit-refund", "low-price", "pre-aegis", "low-gas", "low-balance", "wrong-nonce", "sender-code"} {
		run(name)
	}
	if len(os.Args) > 1 {
		run("wasm-hedged")
	}
}
func run(name string) {
	cfg := params.MainnetChainConfig
	height := big.NewInt(32400000)
	price := zeta.CalculateMinimumGasPrice(cfg, height)
	floor := new(big.Int).Set(price)
	gas := uint64(1000)
	if name == "high-limit-refund" {
		gas = 21000
	}
	if name == "low-price" {
		price.Sub(price, big.NewInt(1))
	}
	if name == "pre-aegis" {
		height.Sub(height, big.NewInt(1))
	}
	if name == "low-gas" {
		gas = 999
	}
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	_, key := mldsa87.NewKeyFromSeed(&seed)
	var to common.Address
	for i := range to {
		to[i] = byte(i + 1)
	}
	if name == "compact" {
		for i := 0; i < 16; i++ {
			to[i] = 0
		}
	}
	signer := types.NewEIP155Signer(big.NewInt(1))
	var tx *types.Transaction
	var err error
	if name == "wasm-hedged" {
		text, e := os.ReadFile(os.Args[1])
		if e != nil {
			panic(e)
		}
		raw, e := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(text)), "0x"))
		if e != nil {
			panic(e)
		}
		tx = new(types.Transaction)
		if e = tx.UnmarshalBinary(raw); e != nil {
			panic(e)
		}
		back, e := tx.MarshalBinary()
		if e != nil || !bytes.Equal(raw, back) {
			panic("external raw roundtrip mismatch")
		}
		if tx.Hash().Hex() != "0x6664369378ad5093de9ccb3adb024343e64e4293e1f7745e5368f001c1012d20" || tx.Type() != types.LegacyTxType || tx.Nonce() != 7 || tx.Gas() != 1000 || tx.GasPrice().Cmp(price) != 0 || tx.Value().Cmp(big.NewInt(123456789)) != 0 || tx.To() == nil || *tx.To() != to || len(tx.Data()) != 0 {
			panic("external fixture fields mismatch")
		}
	} else {
		tx, err = types.SignTxMLDSA87(types.NewTx(&types.LegacyTx{Nonce: 7, GasPrice: price, Gas: gas, To: &to, Value: big.NewInt(123456789)}), signer, key)
	}
	if err != nil {
		panic(err)
	}
	from, err := types.Sender(signer, tx)
	if err != nil {
		panic(err)
	}
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	st, err := state.New(types.EmptyRootHash, state.NewDatabase(db), nil)
	if err != nil {
		panic(err)
	}
	fund := new(big.Int).Add(new(big.Int).Mul(floor, new(big.Int).SetUint64(gas)), tx.Value())
	st.SetBalance(from, uint256.MustFromBig(fund))
	st.SetNonce(from, 7)
	if name == "low-balance" {
		st.SetBalance(from, uint256.NewInt(1))
	}
	if name == "wrong-nonce" {
		st.SetNonce(from, 8)
	}
	if name == "sender-code" {
		st.SetCode(from, []byte{0})
	}
	h := &types.Header{Number: height, Time: 1793552793345, GasLimit: 30000000, Difficulty: big.NewInt(1), BaseFee: big.NewInt(0)}
	poolErr := txpool.ValidateTransaction(tx, h, signer, &txpool.ValidationOptions{Config: cfg, Accept: 1 << types.LegacyTxType, MaxSize: 128 * 1024, MinTip: big.NewInt(1)})
	var author common.Address
	author[47] = 9
	var used uint64
	receipt, err := core.ApplyTransaction(cfg, nil, &author, new(core.GasPool).AddGas(h.GasLimit), st, h, tx, &used, vm.Config{})
	if name == "full" || name == "compact" || name == "high-limit-refund" || name == "wasm-hedged" {
		if err != nil || poolErr != nil {
			panic(fmt.Sprintf("%s: pool=%v apply=%v", name, poolErr, err))
		}
		if receipt.Status != 1 || receipt.GasUsed != 1000 || used != 1000 || st.GetNonce(from) != 8 || st.GetBalance(to).ToBig().Cmp(tx.Value()) != 0 || st.GetBalance(from).ToBig().Cmp(new(big.Int).Mul(price, new(big.Int).SetUint64(gas-1000))) != 0 {
			panic(fmt.Sprintf("state delta mismatch: status=%d gas=%d used=%d nonce=%d to=%s sender=%s fund=%s", receipt.Status, receipt.GasUsed, used, st.GetNonce(from), st.GetBalance(to).ToBig(), st.GetBalance(from).ToBig(), fund))
		}
		fmt.Printf("PASS %s: receipt=1 gas=1000 fee=%s sender_nonce=8 recipient=%s\n", name, new(big.Int).Mul(price, big.NewInt(1000)), st.GetBalance(to).ToBig())
		return
	}
	if err == nil {
		panic("invalid case accepted: " + name)
	}
	expected := map[string]string{"low-price": "below the required minimum", "pre-aegis": "not allowed before Aegis", "low-gas": "intrinsic gas too low", "low-balance": "insufficient funds", "wrong-nonce": "nonce too low", "sender-code": "sender not an eoa"}[name]
	if !strings.Contains(err.Error(), expected) {
		panic("wrong rejection reason: " + err.Error())
	}
	if (name == "low-gas" || name == "pre-aegis") && poolErr == nil {
		panic("pool unexpectedly accepted " + name)
	}
	if name == "low-price" && poolErr != nil {
		panic("generic pool no longer isolates custom ZETA check")
	}
	fmt.Printf("PASS %s rejected: %v (generic pool: %v)\n", name, err, poolErr)
}
