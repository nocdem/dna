# Nodus EVM examples

Governing record: `docs/plans/decisions/2026-10-06-evm-dev-tooling.md` item 1 — the
developer pack (Nodus solc + guide + example token).

| File | What |
|---|---|
| `NodusToken.sol` | a minimal, self-contained ERC-20-style token: `name`, `symbol`, `decimals` (18), `totalSupply`, `balanceOf`, `transfer`, `approve`, `allowance`, `transferFrom`, the `Transfer` / `Approval` events. The constructor takes no arguments and mints 1,000,000 tokens (`INITIAL_SUPPLY` = 10^24 base units) to the deployer |
| `build.sh` | compiles every `*.sol` here with the Nodus solc into `out/` (refuses a solc whose `--version` lacks `nodus.addr256`, and any compiler diagnostic) |
| `out/VERSION.txt` | the compiler version line and the exact flags |
| `out/default/NodusToken.{creation,runtime}.hex` | no flags — exactly what `nodus-cli evm deploy --solc NodusToken.sol:NodusToken` compiles (`solc --bin <file>`, `nodus/tools/nodus-cli.c` `evm_solc`): legacy pipeline, optimizer off, EVM version prague (the compiler's default) |
| `out/optimize/NodusToken.{creation,runtime}.hex` | `--optimize` (runs 200) |
| `out/NodusToken.abi.json` | the ABI (the same for both configurations; `build.sh` checks) |

```
SOLC=/usr/local/bin/solc-nodus ./build.sh       # only when a .sol or the compiler changes
```

The committed bytecode is executed by `shared/evm/tests/test_example_token.c` (part of
`cd shared/evm && make test`): deploy, the views, `transfer`, `approve`, `transferFrom`,
the events and the raw storage slots, with accounts whose high 12 bytes are non-zero.
Nothing detects a `.sol` edit without a `build.sh` re-run.

## What is different from Ethereum

The Solidity source is ordinary; the compiler and the chain differ
(`nodus/tools/evm/solc/README.md`, "Semantic rules"):

- **Addresses are 32 bytes.** In the ABI an address is the whole 32-byte word, written
  as **64 hex digits** — a 20-byte Ethereum address padded with zeros is a *different*
  account. Function selectors and event topics are unchanged (`transfer(address,uint256)`,
  `Transfer(address,address,uint256)`), and an indexed address topic holds all 32 bytes.
- **`abi.encodePacked(address)` is 32 bytes** (20 on Ethereum): any hash or signature
  over packed addresses differs from Ethereum's.
- **Storage:** an address takes a whole slot and is never packed with smaller
  neighbours; a mapping slot is `keccak256(address32 ‖ slot)`.
- **No `uint160` / `bytes20` conversions** (compile error); use `uint256` / `bytes32`.
  No linked (external/public) library calls, no stored or ABI-encoded external function
  types. `NodusToken.sol` uses none of them.
- **Do not use `ecrecover` for account authorization.** Nodus accounts sign with
  ML-DSA-87 and their address is `SHA3-512(public key)[0..32]`; `ecrecover` returns a
  20-byte secp256k1 address padded to 32 bytes, which is not a Nodus account
  (rule 9). Use `msg.sender`, as this token does.
- Ethereum wallets and tools (MetaMask, ethers / viem, `eth_*` JSON-RPC) expect 20-byte
  addresses and are not supported; deploy and call with `nodus-cli evm …` or the web
  wallet's smart-contracts panel.

## Deploy and use it with nodus-cli

The commands (`nodus-cli evm` with no subcommand prints the usage; `nodus/README.md`
has a copy). `<server>` is a Nodus node, `<keys>` your identity directory;
transactions also need `--submit <ip:port>` (or `--dry-run` to build without sending).

```
nodus-cli evm address --keys <keys>                       # your 32-byte EVM address
nodus-cli -s <server> evm deploy --solc NodusToken.sol:NodusToken \
    --keys <keys> --submit <ip:port>                      # prints the receipt + created contract
nodus-cli -s <server> evm call <token> "balanceOf(address)(uint256)" <your-address>
nodus-cli -s <server> evm send <token> "transfer(address,uint256)" <to> 1000000000000000000 \
    --keys <keys> --submit <ip:port>
nodus-cli -s <server> evm logs --from-height <H> --to-height <H> --address <token>
```

Amounts are base units (`decimals` 18: 1 token = 10^18).
