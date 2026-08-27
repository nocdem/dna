# DNAC — DNA Chain Client Library

**Version:** v0.18.6-ledgerv2-o15b | **TX Wire:** v2 (since v0.17.1)

DNAC is the **client side** of the **DNA Chain** — the post-quantum UTXO
blockchain of the DNA ecosystem. This library builds wallets and
transactions and talks to the witness cluster. It does **not** run
consensus: the chain's consensus (BFT witness) is embedded in
`nodus-server`.

The chain is implemented in three layers of the monorepo:

| Layer | Location | Contents |
|---|---|---|
| **Client** (this directory) | `dnac/` | Wallet, UTXO management, TX builders, witness RPC client, client-side chain verification |
| **Canonical codecs** | `shared/dnac/` | Wire formats compiled byte-identical into both the client (`libdna`) and the witness (`libnodus`) |
| **Consensus** | `nodus/src/witness/` | The BFT witness embedded in `nodus-server` (see `nodus/README.md`) |

## Features (client-side)

- **UTXO model** with per-token UTXO tracking and multi-token balances
- **Dilithium5 (ML-DSA-87) signatures** — NIST Category 5, post-quantum
- **Witness-only architecture** — all chain state lives on the BFT
  witnesses; the wallet syncs via RPC (`dna sync`), no DHT storage of
  chain state
- **TX builders** for every live transaction type: SPEND, BURN,
  TOKEN_CREATE, STAKE, UNSTAKE, DELEGATE, UNDELEGATE,
  VALIDATOR_UPDATE, CHAIN_CONFIG (committee-voted hard-fork parameters),
  GENESIS
- **Explicit committed fee** on the wire (v2 header) with a min-fee gate
  and a fee-burn model (fees are removed from circulation, not paid to
  witnesses)
- **Lock-aware coin selection** — the wallet skips UTXOs still inside
  their post-UNSTAKE cooldown (`unlock_block`), so it never builds a
  transaction consensus is guaranteed to reject
- **Memo support** (up to 255 bytes), **name resolution** (send to a DNA
  name, auto-resolved to a fingerprint), **replay prevention**
- **Client-side verification** — Merkle inclusion proofs, block/anchor
  verification, chain-definition decoding (`src/ledger/`)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                dna-connect-cli  `dna` group                 │
│   (DNA Chain commands live in the unified messenger CLI —   │
│    messenger/cli/cli_dna_chain*.c; no separate binary)      │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  libdna (+ libdnac.a)                                       │
│  wallet · TX builders · witness RPC client (dnac/src/)      │
└─────────────────────────────────────────────────────────────┘
                             │  Nodus client SDK (T2, TCP 4001)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  WITNESS CLUSTER (nodus-server, embedded witness)           │
│  chain-derived committee · PBFT rounds on TCP 4004          │
│  authoritative UTXO set + block storage                     │
└─────────────────────────────────────────────────────────────┘
```

All witness RPCs ride the authenticated, Kyber1024-encrypted Nodus
client connection (Tier 2, TCP 4001) as `dnac_*` verbs — spend, utxo,
history, ledger/ledger-range, block/block-range, tx, committee,
delegations, validator-list, roster, supply, token queries, fee info.
The witness BFT round itself (PROPOSE → PREVOTE → PRECOMMIT → COMMIT,
quorum `(2n)/3+1` over the epoch's validator-set snapshot) runs between
witnesses on TCP 4004.

## Building

DNAC has **no standalone runtime**. Its sources are compiled directly
into `libdna.so` by the messenger build:

```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

The `dnac/build` tree additionally produces `libdnac.a` plus the DNAC
test binaries. The CLI's `dna` command group is enabled at messenger
**configure** time only if `dnac/build/libdnac.a` already exists, so the
full-from-scratch order is:

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)   # 1. libdna
cd /opt/dna/dnac/build      && cmake .. && make -j$(nproc)   # 2. libdnac.a (requires libdna)
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)   # 3. re-run so the CLI picks up libdnac.a
```

## CLI Commands

All DNA Chain commands are subcommands of `dna-connect-cli dna`:

```bash
# Identity & info
dna-connect-cli dna info                    # Wallet info, address, connection, balance
dna-connect-cli dna address                 # Wallet address (fingerprint)
dna-connect-cli dna query <name|fp>         # Lookup identity by name or fingerprint

# Wallet
dna-connect-cli dna balance                 # Native balance
dna-connect-cli dna balance-of <name|fp>    # Balance of another address
dna-connect-cli dna utxos                   # List UTXOs
dna-connect-cli dna send <name|fp> <amount> [memo]
dna-connect-cli dna sync                    # Sync wallet from the witnesses

# History & inspection
dna-connect-cli dna history [n]             # Transaction history
dna-connect-cli dna tx <hash>               # Transaction details
dna-connect-cli dna lookup-tx <hash>        # Fetch raw TX from witnesses
dna-connect-cli dna parse-tx <file>         # Decode a serialized TX

# Tokens
dna-connect-cli dna token-create <name> <symbol> <supply>
dna-connect-cli dna token-list
dna-connect-cli dna token-info <id|symbol>

# Staking & governance
dna-connect-cli dna stake ...               # Become a validator (self-bond)
dna-connect-cli dna unstake ...
dna-connect-cli dna delegate ...
dna-connect-cli dna undelegate ...
dna-connect-cli dna validator-update ...    # Commission change
dna-connect-cli dna validator-list
dna-connect-cli dna delegations
dna-connect-cli dna committee               # Current committee

# Genesis (operator)
dna-connect-cli dna genesis-prepare / genesis-create / genesis-submit

# Network
dna-connect-cli dna witnesses               # Show witness servers
```

Amounts on the CLI are raw base units (10^8 per DNAC).

## Wallet Address

The wallet address is the **SHA3-512 hash of the Dilithium5 public
key** — 64 bytes, 128 hex characters, identical to the DNA Connect
identity fingerprint.

## Transaction Format (v2 — since v0.17.1)

Canonical layout: `dnac/src/transaction/serialize.c`; the shared tx-hash
preimage implementation is `shared/dnac/tx_wire.c::dnac_txw_legacy_tx_hash`
(one implementation for client AND witness).

```
HEADER (82 bytes)
  version:       u8 = 2 (DNAC_PROTOCOL_VERSION)
  type:          u8 (DNAC_TX_*)
  timestamp:     u64 (LE on wire, BE in preimage)
  tx_hash:       bytes[64] (SHA3-512 over the preimage)
  committed_fee: u64 BE — the fee this TX pays, explicit on the wire
BODY
  inputs:   nullifier[64] + amount + token_id[64]
  outputs:  version + recipient_fp[129] + amount + token_id[64]
            + seed[32] + memo_len + memo
  balance rule: sum(inputs) == sum(outputs) + committed_fee
  witnesses: 32B id + Dilithium5 sig + timestamp + pubkey
  signers (1..4): Dilithium5 pubkey + signature
  type-specific appended fields (STAKE / DELEGATE / CHAIN_CONFIG / ...)
  optional chain_def trailer (genesis TX only)
```

**Preimage domain separator (SEC-06):** `"DNAC_TX_V2\0"` — all preimage
integers big-endian. **Min-fee gate:** non-GENESIS TXs need
`committed_fee >= DNAC_MIN_FEE_RAW` (0.01 DNAC); the witness rejects
before signature verification.

### Transaction type map

| Type | Meaning | Status |
|---|---|---|
| 0..10 (except 8) | GENESIS(0), SPEND(1), BURN(2), TOKEN_CREATE(3), STAKE(4), DELEGATE(5), UNSTAKE(6), UNDELEGATE(7), VALIDATOR_UPDATE(9), CHAIN_CONFIG(10) | live |
| 8 | was CLAIM_REWARD — retired in the v0.16 reward redesign | reject |
| 11 (SHIELDED) | shielded transfer (STARK) | assigned, **unconditional reject** until activation |
| 12 / 13 (SHIELD / UNSHIELD) | shielded entry/exit (Wire V3 only) | assigned, **unconditional reject** |
| 14 / 15 / 16 | — | **burned — never reuse** |

Types 14, 15 and 16 are permanently unassigned. 14 was reserved and never
allocated; 15 and 16 were `V2_SCHEDULE` / `V2_READY`, the Ledger V2
activation governance types, removed with the activation ceremony in
season O15J Faz 3. The witness rejects all three by name
(`nodus/src/witness/nodus_witness_verify.c`) and the client serializer
refuses every type above 11 — the same freeze that already covers
SHIELD/UNSHIELD. Recycling a burned id would let an old signed
transaction be reinterpreted under a new meaning.

## Ledger V2 (successor chain)

The DNA Chain is about to transition to the **Ledger V2** architecture —
canonical block headers and BlockIDs, quorum certificates bound to
committed validator-set snapshots, a domain-partitioned state model and
multi-leg envelope transactions. The consensus side lives entirely in
`nodus/src/witness/` (see [`../nodus/README.md`](../nodus/README.md) and
[`../docs/ledger-v1-vs-v2.md`](../docs/ledger-v1-vs-v2.md) for the
grounded V1↔V2 reference). On the client side:

- the canonical V2 codecs (envelope, block header, QC, claims, pools,
  activation records) live in `shared/dnac/` and compile into `libdna`;
- the legacy v2 TX wire above stays the accepted format until the
  switch; Wire V3 (types 11/12/13) is defined but rejected by every
  live admission path;
- successor-chain operations (claims, V2 envelopes) are built with
  `nodus-cli v2-claim` / `nodus-cli v2-envelope` on activation builds.

Migration is governed on-chain: a quorum-voted schedule plus
per-validator readiness signals make the legacy chain terminal at the
activation height, and legacy balances move to the successor chain via
deterministic claims.

## Security

- **Dilithium5 everywhere** — TX signers, witness attestations, BFT votes
- **Nullifiers** (SHA3-512) — double-spend prevention without exposing
  UTXO linkage
- **Fail-closed verification** — DB errors are treated as "nullifier
  exists"; a witness that cannot compute its state does not vote
- **Chain-ID binding** — all BFT messages are validated against the
  chain ID to prevent cross-chain replay
- **Supply invariant** — native supply is hard-conserved by the witness
  supply gate; fee burns are tracked in committed supply state

## Status

**Testnet** — live 7-witness cluster with real tester balances. The
active chain ID rotates on consensus-format wipes; query the cluster
rather than hardcoding it. Ledger V2 activation is the next planned
step.

## License

Licensed under the [Apache License 2.0](LICENSE) (aligned with the rest
of the DNA monorepo since 2026-04-24).

## Related

- [Nodus](../nodus/README.md) — DHT server + embedded DNA Chain witness
- [DNA Connect](../messenger/README.md) — messenger + wallet UI on top
  of this library
- [Explorer](../explorer/README.md) — read-only chain indexer
  (scan.cpunk.io)
