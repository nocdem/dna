# IXIOS native admission oracle (2026-11-02)

`admission.go` runs against official ixios-io/ixiosSpark v1.1.1,
commit `ccd1345eed8873a6d0174b3e9a076da67ceb7750`.
All seeds, accounts, balances and blocks are synthetic, in-memory only.
No RPC, signed simulation, broadcast, persistent chain or wallet is used.

From the pinned source module:

```
GOCACHE=/tmp/wallet-gocache GOPATH=/tmp/wallet-gopath GOPROXY=off \
/tmp/wallet-golang/go/bin/go run /absolute/path/to/test/ixios-reference/admission.go
```

Use the individual file, not the directory (codec oracle has another main).
Pinned go.mod/go.sum dependencies were retrieved via proxy.golang.org for the
initial build; rerun works offline. Source files were not modified.

Nine cases pass using public `txpool.ValidateTransaction` and
`core.ApplyTransaction`: full48/compact32 recipient success; 21000-gas limit
refund; rejection of below-ZETA price, pre-Aegis signature, 999 gas, insufficient
balance, stale nonce and sender code. Valid cases assert receipt success,
1000 gas used, exact recipient amount, exact sender remainder and nonce increment.
Rejections assert the intended reason. Generic pool validation alone accepts
below-ZETA price; the actual application wrapper rejects it.

IMPORTANT: `params/protocol_params.go` sets `TxGas=1000`, NOT Ethereum's 21000.
At block 32,400,000, `zeta.CalculateMinimumGasPrice` is 93,000,000,000,000,000 wei
per gas. `params/denomination.go` defines one IXIOS as 10^18 wei. Therefore native
empty-data EOA payment consumes 93 IXIOS in this fixture. A 21000 limit requires
an upfront maximum of 1953 IXIOS, but refunds 20000 unused gas (1860 IXIOS).
This is source/native synthetic evidence, NOT a fresh live fee quote. An unsigned
public batch fee/head/chain-id query on 2026-11-02 10:07 UTC returned HTTP403;
no result was available. This verifier did not retry or bypass that failure.
A separate worker subsequently issued a single quote request before the direct
stop instruction reached that worker; this does not resolve the denied batch
request or broaden access. See the team-wide
[RPC probe chronology](../fixtures/ixios-public-read-20261102/rpc-probe-chronology.json).
No further live IXIOS RPC probes are authorized.

The codec-only oracle's 2e9 gas price remains intentionally inadmissible on
post-Aegis mainnet. Codec/Sender correctness is not admission evidence.

Limits: synthetic header/state, no validator block-seal verification, live
mempool configuration, provider reachability or network inclusion guarantee.

## Browser WASM hedged-signature admission

Pass `hedged-admission.hex` as the oracle's sole argument to additionally execute
its externally supplied browser WASM raw transaction. The oracle does NOT
re-sign this case: it decodes the supplied bytes, requires byte-exact native
roundtrip, checks the pinned transaction hash and all expected transfer fields,
recovers/verifies the sender, and executes the same native pool/application
checks in fresh synthetic funded state. The original nine cases still run.

- Fixture file SHA256: `259c609a57bb74b80432de982719e446c931e35563109b0f44d492a0e4a2410a`
- Transaction hash: `0x6664369378ad5093de9ccb3adb024343e64e4293e1f7745e5368f001c1012d20`
- Synthetic seed bytes 00..1f; browser hedging randomness bytes07.
- Result: 10/10 cases PASS, including browser raw receipt status1, gas1000,
  fee93000000000000000000wei, recipient123456789wei, sender nonce8 and zero
  remaining sender balance (funded with exactly value+fee).

This is native offline execution evidence, not live network admission or
inclusion. See `admission-results.txt` for the captured run.
