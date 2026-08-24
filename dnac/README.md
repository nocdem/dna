# DNAC — Post-Quantum Digital Cash with BFT Witness Consensus

**Version:** v0.17.8-stake.wip | **TX wire:** v2 | **Current amount mode:** transparent

DNAC is the digital-cash component of the DNA monorepo. The current public
source uses a transparent UTXO ledger whose authoritative state is maintained
by BFT witnesses embedded in Nodus. It does not use the DHT as the ledger or
transaction inbox.

DNAC is a development/testnet component, not a production-ready or anonymous
payment system. Transaction amounts, recipient fingerprints and token IDs are
present in the current transparent wire format. Nullifiers prevent reuse of a
spent output; they do not, by themselves, hide the public transaction graph.

## Current implementation

- **Transparent UTXO ledger** — inputs and outputs carry plaintext amounts and
  token IDs.
- **Post-quantum signatures** — Dilithium5 / ML-DSA-87 algorithm profile; no
  independent validation or certification claim.
- **Witness-only state** — UTXOs, nullifiers, blocks, transactions, validators,
  delegations and chain configuration are stored by witnesses.
- **PBFT-like consensus** — PROPOSE, PREVOTE, PRECOMMIT and COMMIT with a
  `2f+1` quorum.
- **View change** — `VIEW_CHANGE` / `NEW_VIEW`, prepared-certificate
  preservation and timeout-driven leader recovery are implemented and have a
  Stage F scenario test.
- **Hash-linked blocks** — block hashes bind the previous hash, transaction
  root and state root.
- **Commit certificates** — PRECOMMIT quorum signatures are stored with
  committed blocks.
- **State root v3** — commits the UTXO, validator, delegation, epoch-state and
  chain-configuration subtrees. The former reward subtree is retired.
- **Push-settlement rewards** — inflation rewards are distributed as UTXOs at
  epoch boundaries. The former `CLAIM_REWARD` transaction type was removed;
  wire value 8 remains unused.
- **Multi-token support** — custom-token creation, token-aware UTXO selection
  and per-token balances are implemented. `TOKEN_CREATE` burns 10,000,000 DNAC
  in the current source.
- **Known custom-token invariant gap** — the per-token supply check is currently
  advisory/log-only. The hard block-rejection invariant covers native DNAC,
  so the repository does not claim consensus-enforced custom-token
  conservation yet.
- **Chain configuration transactions** — `DNAC_TX_CHAIN_CONFIG` supports
  committee-voted parameter changes.

## Privacy and shielded status

| Path | Source status | Consensus status |
|------|---------------|------------------|
| Transparent transactions | Implemented | Accepted by the current witness path |
| Shielded transaction type 11 | Wire, prover and verifier machinery implemented | Rejected unconditionally until the C3 state transition is implemented |
| Ledger V2 | Under development outside the current path | Not active or deployed by this source tree |

The STARK implementation lives in [`shared/crypto/zk/`](../shared/crypto/zk/).
Its verifier stack is linked into Nodus, but the type-11 witness admission path
ends in a fail-closed rejection. Crypto code being present or linked is not
evidence that a shielded pool is live.

## Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│               dna-connect-cli `dna` commands                │
│          (there is no standalone dnac-cli binary)           │
└──────────────────────────────┬───────────────────────────────┘
                               │ libdna + libdnac
                               ▼
                    ┌──────────────────────┐
                    │ Nodus witness client │
                    └──────────┬───────────┘
                               │ witness RPC / TCP
                               ▼
                    ┌──────────────────────┐
                    │ BFT witness network  │
                    │ authoritative state  │
                    └──────────────────────┘
```

The DHT may still be used by DNA Connect for identity/name resolution, but it
is not the DNAC consensus database.

## Build

From the repository root:

```bash
# Build libdna first; DNAC links against it.
cmake -S messenger -B messenger/build -DCMAKE_BUILD_TYPE=Release
cmake --build messenger/build -j"$(nproc)"

cmake -S dnac -B dnac/build -DCMAKE_BUILD_TYPE=Release
cmake --build dnac/build -j"$(nproc)"
```

The DNAC build produces `libdnac.a`. User-facing commands are provided by
`messenger/build/cli/dna-connect-cli` under the `dna` command group.

## CLI overview

Run `dna-connect-cli dna help` for the command-specific argument forms in the
current binary. Major command groups include:

```text
dna-connect-cli dna info
dna-connect-cli dna address
dna-connect-cli dna query <name|fingerprint>
dna-connect-cli dna balance
dna-connect-cli dna balance-of <fingerprint>
dna-connect-cli dna utxos
dna-connect-cli dna send <fingerprint> <amount> [memo]
dna-connect-cli dna send --token <token_id> <fingerprint> <amount> [memo]
dna-connect-cli dna sync
dna-connect-cli dna history [limit]
dna-connect-cli dna tx <hash>
dna-connect-cli dna witnesses
dna-connect-cli dna token-create <name> <symbol> <supply>
dna-connect-cli dna token-list
dna-connect-cli dna token-info <token_id|symbol>
dna-connect-cli dna stake ...
dna-connect-cli dna unstake ...
dna-connect-cli dna delegate ...
dna-connect-cli dna undelegate ...
dna-connect-cli dna validator-list
dna-connect-cli dna validator-update ...
```

## Current transparent wire

The v2 transaction header is 82 bytes:

```text
version(1) | type(1) | timestamp(8) | tx_hash(64) | committed_fee(8)
```

Transparent inputs and outputs include:

```text
input  = nullifier(64) | amount(8) | token_id(64)
output = version(1) | recipient_fingerprint(129) | amount(8)
         | token_id(64) | nullifier_seed(32) | memo_len(1) | memo
```

The header commits the fee explicitly. Non-genesis transactions must meet the
current minimum-fee gate of 0.01 DNAC. Type-specific tails exist for staking,
delegation, validator updates and chain-configuration transactions.

## Consensus and storage

Witnesses are authoritative for:

- the UTXO set and nullifier set;
- full serialized transactions and transaction queries;
- blocks, transaction roots, state roots and commit certificates;
- validators, delegations, epoch settlement and chain configuration.

Clients submit to a witness; non-leaders forward the request to the current
leader. The leader proposes a batch and witnesses execute the PBFT-like voting
phases. Leader recovery uses the implemented view-change protocol.

## Security scope

- Dilithium5 signatures authenticate transactions and consensus messages.
- Nullifiers and witness-side UTXO checks prevent accepted outputs from being
  spent twice.
- Database and verification failures on critical paths are intended to fail
  closed.
- Native-DNAC supply is checked by the hard supply-invariant gate before block
  commit.
- The current transparent ledger does **not** provide amount privacy,
  recipient anonymity or transaction-graph hiding.
- “Post-quantum” describes the selected primitives and parameter targets; it is
  not an independent audit, certification or production-readiness claim.

## Status boundaries

The source tree proves implementation and test coverage; it does not prove
that a public endpoint is reachable, that a particular commit is deployed, or
that a live chain has a specific current ID or balance. Treat deployment and
live-network claims as operational state that must be verified separately.

Ledger V2 documentation will be updated after its header/BlockID/QC, BFT,
network/sync, activation and Testnet 2 gates are complete. Until then, this
README documents the current public consensus path only.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Related documentation

- [DNA repository overview](../README.md)
- [Nodus](../nodus/README.md)
- [ZK implementation status](../shared/crypto/zk/README.md)
