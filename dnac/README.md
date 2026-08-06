# DNAC - Post-Quantum Zero-Knowledge Cash over DHT

**Version:** v0.18.3-ledgerv2-s6 | **TX Wire:** v2 (since v0.17.1) | **Protocol Amounts:** v1 (Transparent)

DNAC is a privacy-preserving digital cash system built on top of [DNA Connect](https://github.com/nocdem/dna). It lives in the DNA monorepo at `/opt/dna/dnac/`.

## Features

- **UTXO Model** - Unspent Transaction Output model for privacy
- **Dilithium5 Signatures** - Post-quantum digital signatures (NIST Category 5)
- **Witness-Only Architecture** - All state stored on BFT witnesses, no DHT dependency (v0.12.0)
- **BFT Consensus** - Byzantine Fault Tolerant witness consensus (PBFT-like)
- **PBFT Witnessing** - Transactions require PBFT quorum (2f+1) witness attestations
- **Memo Support** - Optional transaction memos up to 255 bytes (v0.6.0)
- **Replay Prevention** - Nonce and timestamp-based replay attack prevention (v0.6.0)
- **Merkle Proofs** - Transaction inclusion proofs via Merkle tree (v0.7.0)
- **BFT-Signed Epochs** - Epoch roots signed by BFT consensus (v0.7.1)
- **Block Hash Linking** - Blocks chained via prev_hash (SHA3-512) for chain integrity (v0.12.0)
- **Commit Certificates** - 2f+1 PRECOMMIT signatures stored per block for trustless verification (v0.12.0)
- **Shared UTXO Set** - Validators maintain shared UTXO state (v0.8.0). Native-DNAC supply is hard-conserved by the witness supply-invariant gate. **Known gap (2026-07-08):** per-token conservation is NOT yet enforced by consensus — custom (TOKEN_CREATE) tokens can be counterfeited by mixing denominations in a SPEND. Tracked as P1 in `dnac/BUGS.md` / `docs/2026-07-08-project-assessment.md` (C1).
- **Cross-Identity Sends** - Full TX data through BFT consensus for multi-party transfers (v0.8.0)
- **Fee Burn Model** - Fees burned (removed from circulation) instead of sent to witnesses (v0.8.1)
- **Genesis System** - Unanimous witness authorization for token creation (v0.5.0)
- **Hub/Spoke TX Storage** - Witnesses store full serialized transactions during BFT commit (v0.10.0)
- **TX Query Protocol** - Clients retrieve full transaction data by hash from witnesses (v0.10.0)
- **Block Query Protocol** - Clients query blocks by height or range from witnesses (v0.10.0)
- **Multi-Token Support** - Custom token creation with per-token UTXO tracking (v0.13.0)
- **Token Creation** - TX_TOKEN_CREATE transaction type with 1 DNAC fee burn (v0.13.0)
- **Per-Token Balances** - Wallet tracks separate UTXO sets per token_id (v0.13.0)
- **Name Resolution** - CLI send accepts DNA name, auto-resolves to fingerprint (v0.13.0)
- **TX Wire v2** - 82-byte header with explicit `committed_fee` field, SEC-06 domain separator, min-fee gate 0.01 DNAC (v0.17.1)
- **Shared TX codec (Ledger V2 S1, 2026-08-05)** - ONE legacy tx-hash preimage implementation for client AND witness (`shared/dnac/tx_wire.c` `dnac_txw_legacy_tx_hash`; the witness's independent hand-written mirror is retired, byte identity pinned by `nodus/tests/test_tx_hash_kat.c` literals captured from the pre-S1 algorithm). Also ships the INACTIVE Transaction Wire V3 codec (106-byte BE header: `wire_version=3 ‖ tx_type ‖ domain_id ‖ pool_id ‖ ruleset_version ‖ statement_version ‖ expiry_height ‖ committed_fee ‖ timestamp ‖ tx_hash[64] ‖ body_len ‖ body`; tx-hash preimage under the 16-byte `DNAC_TX_V5` tag binding chain_id + full context) + canonical `ExecutionContext` (50 B) + canonical IDs (`shared/dnac/ledger_ids.h`: SYSTEM=0, DNA_CORE=1, `DNAC_SHIELDED_POOL_V1`=1). Every active consensus path still gates on wire version 2 — V3 activates only with the Ledger V2 devnet reset. Genesis Rule P.2's supply term now reads the committed `chain_def.initial_supply_raw` on the client too (witness already did), making per-chain supply generic; the 10M self-bond stays macro-pinned until the S6 manifest adds the field.
- **Stake-Delegation v1** - Stake-ranked committee as BFT voting authority; per-block reward accrual; pull-based `CLAIM_REWARD` (`stake-delegation-v1`, v0.17.x)
- **Dynamic validator set (Ledger V2 S3, 2026-08-05)** - The committee size is a governance parameter, not a constant: `DNAC_CFG_TARGET_ACTIVE_COUNT` (chain-config param_id **4**, range `[7, 128]` = `[DNAC_COMMITTEE_SIZE, DNAC_MAX_ACTIVE_VALIDATORS]`, SAFETY grace class) is sampled at each **epoch start height**, so it can never resize a live committee mid-epoch. The authoritative membership for an epoch is its **validator-set snapshot** (canonical codec `shared/dnac/vset_wire.h`, tag `"DNA.VSET.v1"` — 78-byte header + 2642 B/entry), frozen one epoch ahead at every boundary and at genesis, and stored in the witness `validator_set_snapshots` table. New validator status **`DNAC_VALIDATOR_ELIGIBLE = 4`** — bonded and tenured but not seated this epoch; boundary flips move `ACTIVE ↔ ELIGIBLE` per the snapshot, `DELEGATE`/`UNSTAKE`/`VALIDATOR_UPDATE` accept `ELIGIBLE` targets, while Rule N liveness and attendance stay `ACTIVE`-scoped. Self-bond is now `>= DNAC_SELF_STAKE_AMOUNT` (10M DNAC) rather than exactly equal, derived from the STAKE TX's own flow (`bond = Σnative_in − Σnative_out − committed_fee`) and stored in `validators.self_stake`; UNSTAKE graduation repays that actual bond. Quorum everywhere is `dna_bft_quorum(n) = (2n)/3+1` over the set governing the height (n=7 ⇒ 5, unchanged on the live chain).

- **Domain registry + native runtime boundary (Ledger V2 S4, 2026-08-05 — INACTIVE)** - Canonical `DomainManifest` v1 + `DomainRegistryRecord` + signed validator readiness codec (`shared/dnac/domain_wire.{h,c}`; tags `DNA.DOMMAN.v1`, `DNA.RULESET.v1`, `DNA.DRLEAF/DRNODE.v1`, `DNA.DOMPROP.v1`, `DNA.DOMRDY.v1`; empty registry root = the frozen S2 `DNA.E.DOMREG.v1`). Witness side: a compiled `NATIVE_BUILTIN` runtime table with fail-closed exact-tuple lookup (`(domain_id, kind, abi, ruleset_version, ruleset_hash)` — no closest version, no implicit latest), the SYSTEM-owned domain registry with the staged activation scheduler (readiness quorum `floor(2N/3)+1` may SCHEDULE; only ALL-ACTIVE readiness ACTIVATES; two-epoch readiness deadline; unready validators leave via the ordinary S3 epoch transition, NON-SLASHING and floor-guarded; a set change and a ruleset activation never share an epoch boundary; postponement slides exactly one epoch), and inactive V2 semantic admission (`nodus_witness_domreg_admit_v2`). The initial registry is exactly SYSTEM + DNA_CORE; a third native domain is one row + one compiled entry — never a BlockHeader change. Type 11 stays consensus-REJECTED and types 12-14 unassigned at every boundary. No live consensus path calls any of it.

- **Persistence + atomic global-block apply (Ledger V2 S5, 2026-08-05 — INACTIVE)** - Versioned schema (`PRAGMA user_version = 5`; one atomic fail-closed migration covering fresh/S4/legacy DBs; six `v2_*` tables; `utxo_set.domain_id` — every UTXO owned by exactly one domain, legacy backfill → DNA_CORE). Canonical `DomainUpdate v1` (368 B BE, hash tag `DNA.DUPD.v1`, updates-root `DNA.DUNODE.v1`/`DNA.E.DUPD.v1`, batch commitment `DNA.DTXB.v1`, genesis linkage `DNA.E.DUPDPRV.v1`). ONE SQLite transaction per V2 global block (`nodus_witness_v2_apply_block` owns BEGIN IMMEDIATE; phases SYSTEM → cross-domain → domain-local ASC → roots → updates/heads/history → indices → metadata → supply gate → COMMIT; 15 deterministic fault points, rollback proven by full-DB digest byte-compare; replay matrix: idempotent identical re-apply, conflicting height / reused BlockID / gap / wrong prev all reject). V2 supply gate: `genesis + minted − burned == Σutxo + Σself_bond + Σdelegated + Σepoch_pool + shielded(≡0, no pool state table may exist)` with checked arithmetic — official DNA numbers pinned in tests (1B raw total, 7 × 10M bonds CARVED, 930M transparent remainder). Genesis-root cycle break: `DNA.SYSPAYL.v1` — manifest `genesis_state_root` = the domain's RUNTIME-OWNED payload root (SYSTEM: six legs w/o registry/manifest commitments; CORE: full core root), final head root = full composition ⇒ a DAG, no hash fixed point. All INACTIVE — Type 11 still REJECT, no live consensus path calls any of it.

- **Generic genesis/distribution manifest + claims (Ledger V2 S6, 2026-08-05 — INACTIVE)** - `GenesisManifest v1` (`shared/dnac/manifest_wire.{h,c}`, tag `DNA.GMAN.v1`): versioned, canonically BE-encoded, strictly consumer-neutral chain-genesis manifest committing genesis supply, the SYSTEM + DNA_CORE `DomainManifest v1` hashes (layout unchanged) and an OPTIONAL distribution section (presence byte controls field existence — no hidden defaults; unknown versions/enums fail closed): opaque source-network tag + source commitment metadata (consensus never verifies source-chain cryptography), snapshot root, leaf count, exact conversion parameters + FLOOR rounding, excluded amount, total claimable, inclusive claim window, and the versioned auth (1 = DNA-native ML-DSA-87) / fee (1 = NONE) / post-deadline (1 = RETAIN) modes. The manifest deliberately has NO chain_id field: `chain_id = genesis_block_id[0..31]` is derived over the manifest bytes (`block_v2.h`). Distribution snapshot = generic leaves (`DNA.DSLEAF/DSNODE.v1`; opaque length-prefixed source id as canonical key, source amount, dest binding = SHA3-512(recipient pubkey)) with shape-derived inclusion proofs (sibling hashes only). The distribution section commits an EXPLICIT `target_domain_id` (u32) + bounded opaque `target_asset_ref` (1..64 B, interpreted only by the target runtime — the native CORE runtime reads it as the existing 64-byte token_id namespace, native-only in v1); unknown/inactive/unregistered/incompatible targets fail closed. Claims (`DNA.CLAIM.v1` signed preimage) reference the manifest BY MANIFEST HASH (the committed identity — a database sequence keys nothing), verify leaf membership against the COMMITTED snapshot root, recompute the converted amount from committed parameters (checked arithmetic), bind the key to the leaf's destination (substitution rejects), and derive the nullifier from the committed context (`DNA.CLNUL.v1` — chain ‖ manifest_hash ‖ target domain ‖ target asset ‖ leaf hash ⇒ claims of different domains/assets can never collide). An admitted claim is ROUTED to the registered TARGET runtime's `claim_apply` hook, which creates the domain-local output (CORE: a deterministic transparent UTXO, `DNA.CLUTXO.v1`, owner = the 128-hex dest fingerprint, explicit domain ownership — no schema default exists anywhere). Witness side: schema v6 (`v2_manifests`/`v2_dist_state`/`v2_claims_spent`, keyed by committed identity + explicit target), REAL `manifest_root` (SYSTEM) + PER-DOMAIN `claims_root` legs (each runtime commits the root over the claims targeting ITS domain) — empty tables reproduce the frozen S2 tagged-empty roots byte-identically — claims execute inside the ONE S5 block transaction (3 fault points, digest-proven rollback), and supply conservation is runtime-owned: the DNAC equation `genesis + minted − burned == ΣCORE utxo + Σself_bond + Σdelegated + Σepoch_pool + unclaimed CORE-native distribution + shielded(≡0)` lives in the CORE runtime's invariant hook and heterogeneous domain assets are never summed together. The native issuance COMMITMENT itself (`supply_root` over genesis/minted/burned) is likewise CORE-owned: it is a leg of `core_state_root` (6 legs), not of `system_state_root` (7 legs) — mutating issuance moves only the CORE root, a mint into the SYSTEM epoch pool is a generic cross-domain operation touching both domains atomically, and a fee burn is CORE-local. DomainHeads follow the canonical lifecycle: created ONLY in the exact activation block (height 0, root bound to the registry-committed `genesis_state_root`), carried byte-unchanged through PAUSED/RETIRED without runtime execution, never synthesized. A claim MOVES value between two owners of the SAME target-domain asset — never mints, never burns; late claims reject with the state RETAINED (any other disposition is a future versioned mode, fail-closed today). Types 12-14 stay UNASSIGNED — a claim has no live transaction type; no live consensus path calls any of it.
- **F17 Committee Enforcement** - Genesis committee cache pin, fee_pool rollback on commit failure (nodus v0.15.1)
- **Hard-Fork Mechanism v1** - `DNAC_TX_CHAIN_CONFIG` allows committee-voted consensus-parameter changes without chain wipe (v0.14+; design: `docs/plans/2026-04-19-hard-fork-mechanism-design.md`)
- **Merkle State Root** - Block commits include SHA3-512 `state_root` over UTXO/validator/delegation/reward/chain_config roots (v0.11.0; v0.14+ added chain_config input)
- **Inflation Model** - 16→1 DNAC halving schedule shipped in code (`2d344281`/`6cd14f17`); not yet deployed

## Protocol Versions

| Version | Amounts | ZK Technology | Status |
|---------|---------|---------------|--------|
| **v1** | Transparent (plaintext) | None | **Current** |
| **v2** | Hidden | STARKs (PQ-safe) | Future |

v1 uses transparent amounts for simplicity. v2 will add STARK-based zero-knowledge proofs for amount privacy while maintaining post-quantum security.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  dna-connect-cli `dna` group                │
│         (DNAC commands live in dna-connect-cli, the         │
│          unified messenger CLI — there is no separate       │
│          dnac-cli binary anymore)                           │
└─────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
┌─────────────────────┐        ┌─────────────────────┐
│      libdna         │◀───────│      libdnac        │
│  (identity, crypto, │ links  │  (cash + tokens)    │
│   transport)        │        │                     │
└─────────────────────┘        └─────────────────────┘
                                         │
                                    TCP 4004
                                         ▼
                               ┌─────────────────────┐
                               │  WITNESS SERVERS    │
                               │ (dynamic roster)    │
                               │ (PBFT 2f+1 quorum)  │
                               │ (authoritative UTXO │
                               │  + block storage)   │
                               └─────────────────────┘
```

## Building

### Prerequisites

1. Build DNA Connect first (DNAC links against `libdna.so`):
```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

2. Install dependencies:
```bash
# Debian/Ubuntu
sudo apt install libssl-dev libsqlite3-dev pkg-config cmake
```

### Build DNAC

```bash
cd /opt/dna/dnac/build
cmake .. && make -j$(nproc)
```

This builds:
- `libdnac.a` — Static library (linked into `dna-connect-cli`)

There is **no standalone `dnac-cli` binary**. All DNAC commands are reached through `dna-connect-cli` under the `dna` subcommand group. The dispatcher and command implementations live in `messenger/cli/cli_dna_chain.c`.

## CLI Commands

```bash
# Identity & Info
dna-connect-cli dna info                    # Wallet info, address, DHT status, balance
dna-connect-cli dna address                 # Wallet address (fingerprint only)
dna-connect-cli dna query <name|fp>         # Lookup identity by name or fingerprint

# Wallet
dna-connect-cli dna balance                 # Wallet balance
dna-connect-cli dna utxos                   # List UTXOs
dna-connect-cli dna send <name|fp> <amount> [memo]   # Send payment
dna-connect-cli dna genesis-create <fp> <amount>     # Create genesis TX
dna-connect-cli dna genesis-submit <file>            # Submit pre-signed genesis TX
dna-connect-cli dna sync                    # Sync wallet from network

# History
dna-connect-cli dna history [n]             # Transaction history (optional: last n)
dna-connect-cli dna tx <hash>               # Show transaction details

# Token Management
dna-connect-cli dna token-create <name> <symbol> <supply>  # Create new token
dna-connect-cli dna token-list                             # List all known tokens
dna-connect-cli dna token-info <id|symbol>                 # Show token details

# Token-Aware Operations
dna-connect-cli dna balance --token <token_id>             # Token balance
dna-connect-cli dna send --token <id> <name|fp> <amount> [memo]  # Send token

# Network
dna-connect-cli dna witnesses                # Show witness servers
```

## Hub/Spoke Query API (v0.10.0)

Clients trust witnesses and can query the full blockchain view via the hub/spoke model:

### Transaction Query
```c
// Retrieve full serialized TX by hash (caller frees tx_data)
int dnac_query_transaction(dnac_context_t *ctx,
                            const uint8_t *tx_hash,
                            uint8_t **tx_data_out,
                            uint32_t *tx_len_out,
                            uint8_t *tx_type_out,
                            uint64_t *block_height_out);
```

### Block Query
```c
// Query single block by height
int dnac_query_block(dnac_context_t *ctx,
                      uint64_t height,
                      uint8_t *tx_hash_out,
                      uint8_t *tx_type_out,
                      uint64_t *timestamp_out,
                      uint8_t *proposer_out);

// Query block range (max 100 per request)
int dnac_query_block_range(dnac_context_t *ctx,
                            uint64_t from_height,
                            uint64_t to_height,
                            int *count_out,
                            uint64_t *total_out);
```

### Wire Protocol (CBOR over Nodus Tier 2)

| Message Type | ID | Direction | Description |
|---|---|---|---|
| `DNAC_NODUS_MSG_TX_QUERY` | 144 | Client→Witness | Query TX by hash |
| `DNAC_NODUS_MSG_TX_RESPONSE` | 145 | Witness→Client | Full TX data blob |
| `DNAC_NODUS_MSG_BLOCK_QUERY` | 146 | Client→Witness | Query block by height |
| `DNAC_NODUS_MSG_BLOCK_RESPONSE` | 147 | Witness→Client | Block fields |
| `DNAC_NODUS_MSG_BLOCK_RANGE_QUERY` | 148 | Client→Witness | Query block range |
| `DNAC_NODUS_MSG_BLOCK_RANGE_RESPONSE` | 149 | Witness→Client | Array of blocks |

### Witness-Side Storage

Witnesses store full serialized `tx_data` in the `committed_transactions` table during BFT commit. Schema:
```sql
CREATE TABLE committed_transactions (
    tx_hash BLOB PRIMARY KEY,
    tx_type INTEGER NOT NULL,
    tx_data BLOB NOT NULL,
    tx_len  INTEGER NOT NULL,
    block_height INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX idx_ctx_height ON committed_transactions(block_height);
```

### Wallet Address

The wallet address is a **SHA3-512 hash of the Dilithium5 public key**:
- 64 bytes = 128 hexadecimal characters
- Same as DNA Connect identity fingerprint

## Transaction Format (v2 — since v0.17.1)

```
DNAC TRANSACTION v2:
┌─────────────────────────────────────────────────────────────┐
│ HEADER (82 bytes, DNAC_TX_HEADER_SIZE)                      │
│   version: u8 = 2 (DNAC_PROTOCOL_VERSION)                   │
│   type: u8 = TX_SPEND | TX_TOKEN_CREATE | TX_STAKE | ...    │
│   timestamp: u64 (LE on wire, BE in preimage)               │
│   tx_hash: bytes[64] (SHA3-512 over preimage)               │
│   committed_fee: u64 BE (v0.17.1+, fee the TX pays)         │
├─────────────────────────────────────────────────────────────┤
│ INPUTS: nullifier[64] + amount + token_id[64]               │
├─────────────────────────────────────────────────────────────┤
│ OUTPUTS: version + recipient_fp[129] + amount + token_id    │
│          + seed[32] + memo_len + memo                       │
│   (token_id = zeros for native DNAC)                        │
├─────────────────────────────────────────────────────────────┤
│ BALANCE: sum(inputs) == sum(outputs) + committed_fee         │
│          (fee is explicit on wire, no longer inferred)      │
├─────────────────────────────────────────────────────────────┤
│ WITNESSES: 32B id + Dilithium5 sig + timestamp + pubkey     │
├─────────────────────────────────────────────────────────────┤
│ SIGNERS (1..4): Dilithium5 pubkey + signature               │
├─────────────────────────────────────────────────────────────┤
│ TYPE-SPECIFIC APPENDED FIELDS                               │
│   STAKE:      commission_bps + unstake_dest_fp + purpose_tag │
│   DELEGATE:   validator_pubkey + delegation_amount           │
│   UNDELEGATE: validator_pubkey + amount                     │
│   VALIDATOR_UPDATE: new_commission_bps + signed_at_block    │
│   CHAIN_CONFIG:  param_id + new_value + effective_block     │
│                  + proposal_nonce + signed_at_block         │
│                  + valid_before_block + committee_votes[]   │
├─────────────────────────────────────────────────────────────┤
│ OPTIONAL: has_chain_def + chain_def blob (genesis TX only)  │
└─────────────────────────────────────────────────────────────┘
```

**Preimage domain separator (SEC-06):** `"DNAC_TX_V2\0"` (11B) prevents
any future version preimage from colliding with v2. All multi-byte
integers in the preimage are BIG-ENDIAN so the hash is platform-stable.

**Min-fee gate:** non-GENESIS TXs must have
`committed_fee >= DNAC_MIN_FEE_RAW` (0.01 DNAC = 10⁶ raw). Witness
`nodus_witness_verify.c::Check 0` rejects before Dilithium5 sig verify
(~500 µs/signer saved on DoS).

## Witness Infrastructure

DNAC uses a dynamic BFT witness roster for double-spend prevention. Witnesses are nodus-server nodes with witness capability, discovered at runtime:

### BFT Consensus Protocol

```
Client Request → Any Witness → Forward to Leader → Consensus Round → Response

PROPOSE → PREVOTE → PRECOMMIT → COMMIT
   │         │          │          │
   └─ Leader broadcasts proposal
             └─ All witnesses vote
                       └─ Quorum (2/3) reached
                                  └─ Nullifier committed, response sent
```

### Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| Voting authority | Chain-derived | The epoch's validator-set snapshot; the gossip roster is transport-only |
| Active set size | `DNAC_CFG_TARGET_ACTIVE_COUNT` | Chain-config param 4, `[7, 128]`, sampled at the epoch start height (default 7) |
| Quorum | `dna_bft_quorum(n) = (2n)/3+1` | `n` = size of the set governing the height (n=7 ⇒ 5) |
| Leader Election | `(epoch + view) % N` | Rotates hourly |

### Features

- **Embedded in Nodus** - Witness logic runs inside nodus-server process
- **Nullifier Database** - SQLite-based persistent storage
- **Request Forwarding** - Non-leaders forward to current leader

### Witness-Only Storage (v0.12.0)

All blockchain state is stored on BFT witnesses. DHT inbox delivery was removed in v0.12.0 — witnesses are the authoritative source for all data:
- **UTXO set** — maintained by witnesses, clients poll via `dnac_sync_wallet()`
- **Blocks** — hash-linked chain with commit certificates
- **Nullifiers** — double-spend prevention
- **Transaction data** — full serialized TX for client queries

## Security

- **Post-Quantum Signatures**: Dilithium5 for all signatures (NIST Category 5)
- **Nullifiers**: SHA3-512 hash prevents UTXO tracking
- **Linkability Prevention**: Nullifiers prevent transaction graph analysis
- **Double-Spend Prevention**: PBFT quorum (2f+1) witness attestation required
- **UTXO Validation**: Witnesses verify UTXO legitimacy before voting (v0.8.0)
- **Fee Burn**: Transaction fees are permanently removed from circulation (v0.8.1)
- **UTXO Ownership Verification**: Sender fingerprint must match UTXO owner (v0.10.2)
- **Nullifier Fail-Closed**: DB errors assume nullifier exists to prevent double-spend (v0.10.2)
- **Chain ID Validation**: All BFT messages validated against zone chain_id to prevent cross-zone replay (v0.10.2)
- **Secure Nonce Generation**: RNG failure aborts instead of falling back to weak source (v0.10.2)
- **Overflow Protection**: Safe integer arithmetic for genesis supply and balance calculation (v0.10.2)
- **COMMIT Signature Verification**: All BFT COMMIT messages require valid Dilithium5 signature (v0.10.2)

## Status

**Testnet** - v0.18.3-ledgerv2-s6. Not for production use. `stake-delegation-v1` is merged to main and deployed. Runs on a live 7-witness testnet cluster with real tester balances; the active chain ID has rotated through several wipes (each consensus/block-format change requires a stop-all deploy + chain wipe) — query the cluster for the current chain rather than relying on a hardcoded ID here.

### Implemented

- [x] Core wallet functionality (UTXO management, balance tracking)
- [x] Send/receive transactions via DHT
- [x] BFT consensus protocol (PBFT-like, embedded in Nodus)
- [x] Dynamic witness roster (discovered at runtime)
- [x] Leader election and request forwarding
- [x] Double-spend prevention via nullifiers
- [x] End-to-end integration tests
- [x] Multi-input double-spend fix (v0.4.0)
- [x] Genesis transaction with 3-of-3 unanimous authorization (v0.5.0)
- [x] BFT message signing with Dilithium5 (v0.6.0)
- [x] Integer overflow protection (v0.6.0)
- [x] Replay prevention via nonce/timestamp (v0.6.0)
- [x] Memo support up to 255 bytes (v0.6.0)
- [x] Merkle tree for transaction inclusion proofs (v0.7.0)
- [x] Chain synchronization infrastructure (v0.7.0)
- [x] Ledger confirmation tracking (v0.7.0)
- [x] BFT-anchored epoch roots (v0.7.1)
- [x] Shared UTXO set — validators verify UTXO legitimacy before consensus (v0.8.0)
- [x] Cross-identity sends with full TX data through BFT (v0.8.0)
- [x] Fee burn model — fees permanently removed from circulation (v0.8.1)
- [x] Genesis TX verification fix (v0.8.1)
- [x] Hub/spoke TX storage — witnesses persist full tx_data during BFT commit (v0.10.0)
- [x] TX query protocol — clients retrieve full transaction by hash (v0.10.0)
- [x] Block query protocol — clients query blocks by height or range (v0.10.0)
- [x] P0 Security audit fixes — 3 CRITICAL + 3 HIGH vulnerabilities resolved (v0.10.2)
- [x] Dead code cleanup — removed ~10K lines of old standalone witness code (v0.10.3)
- [x] BFT cleanup — removed client-side BFT code (serialize/roster/replay), dynamic witness discovery (v0.11.1)
- [x] Witness-only architecture — removed DHT inbox dependency, wallet syncs from witnesses (v0.12.0)
- [x] Block hash linking — prev_hash chain integrity via SHA3-512 (v0.12.0)
- [x] Commit certificates — 2f+1 PRECOMMIT signatures stored per block (v0.12.0)
- [x] Remote transaction history via witnesses (v0.12.1)
- [x] Multi-token UTXO tracking — per-token balances and UTXO sets (v0.13.0)
- [x] TX_TOKEN_CREATE — custom token creation with 1 DNAC fee burn (v0.13.0)
- [x] Token-aware TX builder — UTXO selection by token_id (v0.13.0)
- [x] CLI send by DNA name — auto-resolve to fingerprint (v0.13.0)

### Tested

- [x] GENESIS transaction flow (3-of-3 unanimous)
- [x] SEND transaction flow
- [x] Double-spend rejection
- [x] Multi-input double-spend rejection
- [x] Service auto-restart on reboot
- [x] Witness mesh reconnection
- [x] Security gap fixes (18 test cases in test_gaps.c)
- [x] Cross-machine send/receive (test_remote.c)
- [x] Cross-identity supply invariant (4 identities, 10000 supply = 9995.5 UTXOs + 4.5 burned)

### Deferred to v2

- [ ] STARK-based zero-knowledge proofs for amount privacy
- [ ] View change protocol (leader failure recovery)

## License

Licensed under the [Apache License 2.0](LICENSE). Aligns with the rest of the DNA monorepo (messenger, nodus, shared-crypto). Changed from MIT on 2026-04-24 — the original MIT claim was a footer in the v0.1.0 initial commit without a LICENSE file; Apache 2.0 includes an explicit patent grant which is preferable for a post-quantum blockchain component.

## Related Projects

- [DNA Connect](https://github.com/nocdem/dna) - Post-quantum encrypted messenger (monorepo: `/opt/dna/messenger/`)
- [Nodus](../nodus/) - Post-quantum Kademlia DHT with PBFT consensus (monorepo: `/opt/dna/nodus/`)
