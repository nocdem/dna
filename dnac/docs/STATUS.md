# DNAC Blockchain — Component Status

**Last verified:** 2026-04-15 (against source code, not memory)
**DNAC version:** v0.14.3
**Nodus version:** v0.12.12
**Chain:** `4a68e14678400c693f1cfefe723d7fa5876c3d2d121048961a83b1a18cc1dcbb` (9 blocks, 7/7 consistent)

This document is the **source of truth** for what DNAC has and what it lacks.
`ROADMAP.md` and `TODO.md` are historical; consult them only for phase history,
not current state.

---

## Architecture (current)

DNAC is a **witness-only post-quantum UTXO blockchain**. The standalone DHT
transport was removed in v0.12.0; all consensus state lives in nodus-server's
embedded witness module (`nodus/src/witness/`).

- **Token model:** UTXO (Bitcoin-style), nullifier-based double-spend prevention
- **Consensus:** PBFT-style BFT (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- **Quorum:** 2f+1 of N witnesses
- **Block production:** Multi-tx blocks, 5s interval, max 10 TXs/block, fee-sorted mempool
- **Finality:** Instant at COMMIT (no fork choice rule, no reorgs)
- **Cryptography:** Dilithium5 signatures, SHA3-512 hashing, Kyber1024 KEM, BIP39 seeds
- **Storage:** Per-chain SQLite at `/var/lib/nodus/data/witness_<chain_id_hex_16>.db`

---

## ✅ SHIPPED

### Consensus
- [x] Witness BFT (PROPOSE → PREVOTE → PRECOMMIT → COMMIT)
- [x] Leader rotation `(epoch + view) % N`
- [x] View change on 5s round timeout, max 3 view changes per request
- [x] 2f+1 quorum
- [x] Commit certificates (replicated via COMMIT msg)
- [x] Multi-tx blocks (v0.14.0)
- [x] Fee-sorted mempool, 64 TX capacity, 10 TX/block batch
- [x] Block linking via prev_hash chain
- [x] State sync (block-by-block catch-up + fork detection + DB rebuild)

### State & Validation
- [x] UTXO set (persistent, post v0.12.0 DHT removal)
- [x] Nullifier-based double-spend prevention
- [x] Atomic multi-input nullifier validation (v0.4.0)
- [x] **Merkle state_root (RFC 6962, SHA3-512)** — `nodus/src/witness/nodus_witness_merkle.c` (521 lines)
  - Leaf hash includes `nullifier || owner || amount || token_id || tx_hash || output_index`
  - Nullifier-sorted leaves, odd-sibling duplication
  - `build_proof` / `verify_proof` API
  - `tx_root` (RFC 6962 over per-block TX hashes)
- [x] state_root bound into block hash preimage
  - `SHA3-512(height || prev_hash || state_root || tx_root || tx_count || timestamp || proposer_id)`
- [x] BFT commit path computes root inside transaction (`nodus_witness_bft.c:1054-1075`)
- [x] **Witness divergence detection** active at COMMIT (`nodus_witness_bft.c:2107-2108`) — mismatch caught
- [x] Cached state_root + invalidation (`nodus_witness.h:283-284`)
- [x] Block hash recomputed before DB commit (v0.11.0 — TX integrity)
- [x] Nullifier fail-closed on DB error (v0.10.2)
- [x] Chain ID validation in all 10 BFT handlers (v0.10.2)
- [x] UTXO ownership verification before PREVOTE (v0.10.2)
- [x] Genesis block + genesis TX handler

### Cryptography
- [x] Dilithium5 (PQ signatures, 2592B pubkey, 4627B sig)
- [x] Kyber1024 (PQ KEM)
- [x] SHA3-512 hashing
- [x] BIP39 wallet seed derivation
- [x] Secure nonce — abort on RNG failure, no weak fallback (v0.10.2)
- [x] Replay prevention: nonce + timestamp + nonce hash table with TTL (v0.11.0)
- [x] COMMIT signature verification (v0.10.2 / v0.11.0)

### Networking
- [x] Witness BFT P2P on dedicated TCP 4004 (v0.10+)
- [x] Inter-node auth on TCP 4002 + 4004 (both fixed)
- [x] T3 wire protocol (CBOR over framed TCP, magic `0x4E44`)
- [x] T2 status query carries state_root to clients (`nodus_tier2.c:1166,2533` — `"sr"` CBOR field)
- [x] T3 inter-witness COMMIT msg carries state_root (`nodus_tier3.h:138,221`)
- [x] Block propagation in cluster
- [x] Block production rate-limit (5s min interval)

### Economics (partial)
- [x] Burn address (all-zero fingerprint) with explicit fee UTXOs
- [x] Supply tracking + invariant check (bit-identical across 7/7 nodes)
- [x] Overflow-safe arithmetic (`safe_add_u64`)
- [x] 8-decimal token (1 DNAC = 100,000,000 raw units)

### Client Layer
- [x] CLI: `dna send`, `dna sync`, `dna balance`, `dna history` (with memo column)
- [x] CLI: `dna chain` for chain inspection
- [x] Flutter wallet UI: `wallet_screen`, `dnac_provider`, history view, UTXO view
- [x] Witness discovery (`dnac_discover_witnesses`) — address-based, no stake gating
- [x] Wallet sync from witnesses (polling)
- [x] Wallet recovery from seed phrase

### Storage / Schema
- [x] SQLite per-chain DB
- [x] Tables: nullifiers, utxo_set, blocks, committed_transactions, commit_certificates, supply_tracking, genesis_state, ledger_entries
- [x] `blocks.state_root BLOB NOT NULL`
- [x] Schema versioning (current schema v12)

---

## ✅ SHIPPED 2026-04-16 — Anchored Merkle Proofs (branch merged, Phase 13 deploy pending)

- [x] **Per-UTXO Merkle proof delivery to clients** — `handle_dnac_utxo` ships per-UTXO `state_root_proof` + `block_height` (`nodus_witness_handlers.c` extended)
- [x] **Per-TX tx_root proof delivery** — `handle_dnac_history` ships per-TX `tx_root_proof` (new `nodus_witness_merkle_build_tx_proof` helper)
- [x] **Client-side Merkle proof verification** — `dnac_merkle_verify_proof()` implemented (`dnac/src/ledger/merkle_verify.c`, RFC 6962, SHA3-512)
- [x] **Block anchor verification** — `dnac_anchor_verify()` verifies block hash + 2f+1 Dilithium5 PRECOMMIT sigs against roster (`dnac/src/ledger/anchor_verify.c`)
- [x] **Genesis verification** — `dnac_genesis_verify()` bootstraps trust from hardcoded `chain_id` (Bitcoin-tier model, single trust root)
- [x] **High-level wrappers** — `dnac_utxo_verify_anchored` + `dnac_tx_verify_anchored` orchestrate the three primitives
- [x] **Genesis block schema** — `dnac_chain_definition_t` embedded in height=0 block hash preimage (witness pubkeys, consensus params, token params, native_token_id, fee_recipient all committed transitively via chain_id)
- [x] **`handle_dnac_genesis` T2 query** — fetches genesis block bytes from any peer
- [x] **`handle_dnac_block` + commit_cert** — response includes 2f+1 signatures
- [x] **Chain registry** — `DNAC_KNOWN_CHAINS[]` array in `dnac/src/ledger/genesis_anchor.c` (multi-chain forward-compat)
- [x] **Runtime trust state** — `dnac_current_trusted_state()` accessor, wallet bootstrap wired into `dnac_init`
- [x] **UTXO verify loop in sync path** — `dnac/src/nodus/tcp_client.c` calls `dnac_utxo_verify_anchored`, flips `verified` flag
- [x] **`dnac_utxo_t.verified` field** — runtime-only, distinguishes anchored vs unverified UTXOs
- [x] **`gen_genesis` operator CLI** — `dnac/tools/gen_genesis.c` builds new genesis + prints chain_id for paste
- [x] **Witness DB schema v14** — `chain_def_blob` column persists chain_def for genesis blocks
- [x] **Hardcoded constant refactor** — `format_amount`, `token_symbol`, `token_decimals` read from trust state (not `#define`)
- [x] **Test coverage** — 29 dnac assertions across 5 test suites (`test_merkle_verify`, `test_anchor_verify`, `test_genesis_verify`, `test_chain_def_codec`, `test_anchored_proofs`) + 1 new nodus test (`test_merkle_tx_proof`, 62/62 ctest)

**Scope NOT yet done (Phase 13 deploy gated on operator approval):**
- Hard fork execution: archive old chain, submit new genesis, paste real `chain_id` into `DNAC_KNOWN_CHAINS`, cluster stop/start
- Per-block anchor fetch for UTXOs whose `block_height` lags `latest_verified_anchor` (minor follow-up)
- Flutter "verified" UI badge (design doc deferred to separate PR)

**Design + plan:** `docs/plans/2026-04-16-dnac-anchored-merkle-proofs-{design,impl}.md`

---

## ⚠️ PARTIAL

- [ ] **Witness peer table slot leak**
  - 4 uncoordinated `peer_count++` sites cause "sent=11" with 6 peers
  - Secondary bug, not blocking consensus

---

## ❌ NOT STARTED

### Decentralization (the real gap)
- [ ] **Witness stake mechanism** (`TX_STAKE`)
  - No `TX_STAKE` type in `dnac/include/dnac/dnac.h` (only GENESIS / SPEND / BURN / TOKEN_CREATE)
  - `nodus_witness.h:44` only has comment: "Struct kept for future extensibility (e.g. stake threshold)"
  - Designed: 10M DNAC self-stake (Ethereum 32 ETH model), unlimited delegation on top
- [ ] **Stake-gated witness discovery**
  - Current discovery is address-based auto-join via gossip (`nodus_witness_peer.c:501,1037`) — no gatekeeping
  - Friend-of-friend manual whitelist only
- [ ] **Slashing** — no equivocation detection, conflicting PREVOTE/PRECOMMIT sigs go unpunished
- [ ] **Unstake mechanism** — time-locked withdrawal (N blocks after request)
- [ ] **v2 weighted random sortition** — designed as "poor man's VRF", deferred until v1 deterministic top-21 ships

### Economics
- [ ] **Witness rewards / fee distribution** — fees currently burn, no payout to active witnesses
- [ ] **Block reward / inflation policy** — undefined
- [ ] **Stake-based incentive alignment** — pure altruism right now

### Operational / UX
- [ ] **Block explorer** — no public chain browser
- [ ] **Light client / SPV** — would unlock once client-side proof verify exists
- [ ] **Snapshot / fast state sync** — only block-by-block replay
- [ ] **T1 decode failure investigation** (Phase 3.2 — pre-existing, unrelated to consensus correctness)
- [ ] **T3 decode failure on peer connect** (pre-existing, doesn't block consensus)

### Future Protocol Versions
- [ ] **Protocol v2: hidden amounts via PQ ZK (STARKs)** — design only, no code
  - STARK libraries to evaluate: winterfell, stone, ethSTARK
  - Range proofs for amounts
  - ~50-200 KB proof size acceptable

---

## Skip-able by design (BFT consequence)

These are *not* gaps — they don't apply to a witness BFT chain:

- ~~Proof-of-Work mining / difficulty adjustment~~ — N/A
- ~~Fork choice rule / chain reorg handling~~ — N/A (instant finality at 2f+1)
- ~~Long-range attacks / weak subjectivity~~ — bounded by witness rotation policy
- ~~Uncle blocks / GHOST~~ — N/A

---

## Critical Path to "Trustless & Permissionless"

The chain **works** today as a permissioned witness federation. To become an
open decentralized chain, the remaining must-haves are:

1. **`TX_STAKE` + stake-gated roster** — defines who can be a witness
2. **Slashing** — defines the cost of misbehavior (paired with #1; alone meaningless)
3. ~~**Client-side Merkle proof verification**~~ — **SHIPPED 2026-04-16** (see shipped section above). Closes the "trust witness blindly" gap via anchored proofs backed by a single hardcoded `chain_id`.
4. **Witness rewards** — economic incentive to stay honest and online

Items 1+2+4 form one design (witness economics) and likely ship together as a
separate PR.

---

## Verification

To re-verify any "shipped" claim above, grep these anchors in source:

| Claim | File:line |
|---|---|
| Merkle implementation | `nodus/src/witness/nodus_witness_merkle.c` |
| state_root in block hash | `dnac/include/dnac/block.h:65,80-83` |
| BFT commit computes root | `nodus/src/witness/nodus_witness_bft.c:1054-1075` |
| Witness divergence detect | `nodus/src/witness/nodus_witness_bft.c:2107-2108` |
| Cached state_root | `nodus/src/witness/nodus_witness.h:283-284` |
| T2 wire ships root | `nodus/src/protocol/nodus_tier2.c:1166,2533` |
| T3 wire ships root | `nodus/src/protocol/nodus_tier3.c:133,251,581,975` |
| Schema NOT NULL | `nodus/src/witness/nodus_witness.c:80` |
| Merkle test | `nodus/tests/test_merkle_utxo_root.c` (169 lines) |
| Client merkle verify | `dnac/src/ledger/merkle_verify.c` (shipped 2026-04-16) |
| Client anchor verify | `dnac/src/ledger/anchor_verify.c` |
| Client genesis verify | `dnac/src/ledger/anchor_verify.c` (same file) |
| Chain registry | `dnac/src/ledger/genesis_anchor.c` (placeholder chain_id → filled at Phase 13) |
| gen_genesis tool | `dnac/tools/gen_genesis.c` |
| Merkle direction convention | `dnac/src/ledger/MERKLE_DIRECTION_CONVENTION.md` |
| Wallet bootstrap | `dnac/src/wallet/wallet.c` — `bootstrap_trusted_state()` |
| UTXO verify in sync | `dnac/src/nodus/tcp_client.c` — `dnac_utxo_verify_anchored` call site |
| No TX_STAKE | `dnac/include/dnac/dnac.h` (grep TX_STAKE → 0 hits) |
