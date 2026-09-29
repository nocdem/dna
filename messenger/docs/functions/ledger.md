# DNA Chain Ledger Functions

The version-3 (cometbft) chain's tagged state-root hierarchy and the
witness-side functions that read/write the committed ledger state it
covers. `shared/dnac/ledger_roots_v2.c` is compiled into BOTH `libdna.so`
(messenger build) and `libnodus` (nodus build); the `nodus_witness_*`
entries live in `nodus/src/witness/` and are nodus-only.

Contract of every tag and preimage: `shared/dnac/ledger_roots_v2.h`
(TAG TABLE + "Composition preimages"). Entries marked **W-A** were
added or changed by the final pre-testnet wipe, package W-A (keyless
treasury pools — decision
`docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md`).

---

## 1. Shared root hashing (`dnac/ledger_roots_v2.h`)

| Function | Description |
|----------|-------------|
| `int dna_v2_empty_root(dna_v2_empty_kind_t kind, uint8_t out[64])` | SHA3-512 of the kind's 16-byte tag alone. **W-A:** new kind `DNA_V2_EMPTY_TREASURY` (`"DNA.E.TREAS.v1"`), appended after `DNA_V2_EMPTY_ACCRUAL`. |
| `int dna_v2_treasury_leaf_hash(uint32_t pool_id, uint64_t balance, uint8_t out[64])` | **NEW (W-A).** `SHA3-512("DNA.TRLEAF.v1" 16 B ‖ pool_id u32 BE ‖ balance u64 BE)`. 0 / -1. |
| `int dna_v2_treasury_root(const uint32_t *pool_ids, const uint64_t *balances, size_t n, uint8_t out[64])` | **NEW (W-A).** Tagged Merkle over treasury leaves, pool_id STRICTLY ascending (duplicate / descending → -1), inner `"DNA.TRNODE.v1"`, odd node promoted, n==1 → the leaf, n==0 → `DNA_V2_EMPTY_TREASURY`. |
| `int dna_v2_system_root(const uint8_t validator_root[64], const uint8_t delegation_root[64], const uint8_t chain_config_root[64], const uint8_t validator_set_root[64], const uint8_t domain_registry_root[64], const uint8_t manifest_root[64], const uint8_t attendance_root[64], const uint8_t treasury_root[64], uint8_t out[64])` | **CHANGED (W-A):** 8 legs under `"DNA.SYS.v4"` — `treasury_root` appended as the LAST parameter/leg (was 7 legs, `"DNA.SYS.v3"`). |
| `int dna_v2_system_payload_root(const uint8_t validator_root[64], const uint8_t delegation_root[64], const uint8_t chain_config_root[64], const uint8_t validator_set_root[64], const uint8_t treasury_root[64], uint8_t out[64])` | **CHANGED (W-A):** 5 legs under `"DNA.SYSPAYL.v3"` — `treasury_root` appended LAST (was 4 legs, `"DNA.SYSPAYL.v2"`). |
| `int dna_v2_accrual_leaf_hash(const uint8_t owner_fp[64], uint64_t amount, uint8_t out[64])` | Reward-accrual leaf (`"DNA.ACLEAF.v1"`), unchanged. |
| `int dna_v2_accrual_root(const uint8_t (*owner_fps)[64], const uint64_t *amounts, size_t n, uint8_t out[64])` | Reward-accrual root (`"DNA.ACNODE.v1"`), unchanged. |
| `int dna_v2_core_root(...)` | 7-leg CORE composition (`"DNA.CORE.v2"`), unchanged. |

---

## 2. Witness treasury state (`nodus/src/witness/nodus_witness_roots_v2.h`)

Constants: `NODUS_TREASURY_POOL_MIN` 1, `NODUS_TREASURY_POOL_MAX` 9,
`NODUS_TREASURY_POOL_COUNT` 9. (`NODUS_TREASURY_POOL_FOUNDATION` 8 is
**REMOVED** by general multisig with the refund below — nothing names
pool 8 any more.)

| Function | Description |
|----------|-------------|
| `int nodus_witness_treasury_root_v2(nodus_witness_t *w, uint8_t out[64])` | **NEW (W-A).** `treasury_root` over `v2_treasury` (pool_id ASC). Fails closed on an absent table, a pool_id outside 1..9, a negative balance, a non-INTEGER column or a scan fault. |
| `int nodus_witness_treasury_total(nodus_witness_t *w, uint64_t *out)` | **NEW (W-A).** Σ `v2_treasury.balance` through the same row checks, checked add — the supply equation's treasury term. |
| ~~`int nodus_witness_treasury_credit(nodus_witness_t *w, uint32_t pool_id, uint64_t amount)`~~ | **REMOVED (general multisig).** Added by W-A for the refund below, its only caller; deleted with it (no dead code). No block path writes a pool after genesis. |
| ~~`int nodus_witness_treasury_graduation_refund(nodus_witness_t *w, uint64_t active_since_block, uint64_t self_stake, int *out_to_treasury)`~~ | **REMOVED (general multisig, decision `2026-09-29-general-multisig.md`).** W-A credited a genesis seat's bond into pool 8 with no UTXO; now EVERY graduate releases its bond as a locked UTXO to its `unstake_destination_fp` — for a genesis seat the Foundation multisig address. |
| `int nodus_witness_system_root_v2(nodus_witness_t *w, uint8_t out[64])` | **CHANGED (W-A, behaviour):** composes the treasury leg (8 legs, `"DNA.SYS.v4"`). Signature unchanged. |
| `int nodus_witness_system_payload_root_v2(nodus_witness_t *w, uint8_t out[64])` | **CHANGED (W-A, behaviour):** composes the treasury leg (5 legs, `"DNA.SYSPAYL.v3"`). Signature unchanged. |

---

## 3. Epoch boundary (`nodus/src/witness/nodus_witness_v2_epoch.h`)

| Item | Description |
|------|-------------|
| ~~`nodus_v2_epoch_result_t.n_grad_utxos`~~ | **REMOVED (general multisig).** W-A added it because a genesis seat's pool-8 refund wrote no UTXO; with the refund gone every graduate writes one, so phase 6e (`nodus_witness_v2_apply.c`) is back to `n_graduates > 0 \|\| dist_accrued > 0 \|\| n_payday_utxos > 0`. `nodus_witness_v2_epoch_boundary_apply`'s signature is unchanged. |

---

## 4. Genesis document and config (`nodus/src/witness/nodus_witness_v2_gen.h`, `nodus/tools/nodus_v2_gen_config.c`)

| Item | Description |
|------|-------------|
| `NODUS_V2_GEN_CONFIG_VERSION_V4` (4u) | **NEW (W-A).** The only accepted `config_version`. `NODUS_V2_GEN_CONFIG_VERSION_V3` is RETIRED (kept only for callers that still name it; every path refuses 3). |
| `nodus_v2_gen_treasury_t { uint32_t pool_id; uint64_t balance; }`, `nodus_v2_gen_config_t.treasury[NODUS_V2_GEN_TREASURY_POOLS]` | **NEW (W-A).** Nine entries, entry i = pool_id i+1; encoded after `payout_interval_epochs` as 9 × (u32 BE ‖ u64 BE), no count field. |
| `int nodus_witness_v2_gen_v3_defaults(nodus_v2_gen_config_t *cfg)` | **CHANGED (W-A, behaviour):** writes `config_version = 4` and the treasury pool IDS (never the balances). |
| `int nodus_witness_v2_gen_v3_encode / _v3_decode / _v3_validate / _config_validate / _chain_id / _v3_source_commit(...)` | **CHANGED (W-A, behaviour):** version 4 only; Rule P.2 counts Σ treasury; the decoder refuses a pool_id that is not its index + 1. Signatures unchanged. |
| `int nodus_v2_gen_config_parse_file(const char *path, nodus_v2_gen_config_t **out_cfg)` | **CHANGED (W-A, behaviour):** `config_version = 4` only; new `[treasury]` block (`pool_id`, `balance`, both required), EXACTLY nine, pool order 1..9. Signature unchanged. **CHANGED (W-C, behaviour):** two OPTIONAL top-level keys `gas_price_raw_per_unit` / `token_create_fee_raw`, defaulted from `_v3_defaults`; a duplicate refuses. |
| `nodus_v2_gen_config_t.gas_price_raw_per_unit`, `nodus_v2_gen_config_t.token_create_fee_raw` | **NEW fields (W-C).** Genesis values of chain-config params 5 and 6; encoded after the treasury block as `u64 BE ‖ u64 BE` (16 bytes, document still `config_version` 4); committed by `gen_seed_state` as `chain_config_history` rows at `effective_block` 0. `_v3_defaults` writes 121 and 10^11; `_v3_validate` refuses gas > `DNAC_CFG_MAX_GAS_PRICE` and a token fee outside `[DNAC_CFG_MIN_TOKEN_CREATE_FEE, DNAC_CFG_MAX_TOKEN_CREATE_FEE]`. The decoder reads both (a document without them is refused by length). |
| `DNAC_CFG_TOKEN_CREATE_FEE_RAW` (6), `DNAC_CFG_MIN_TOKEN_CREATE_FEE` / `DNAC_CFG_MAX_TOKEN_CREATE_FEE` (10^8 / 10^15), `dnac_cfg_param_read_by_consensus` | **NEW / CHANGED (W-C, `dnac/include/dnac/dnac.h`).** `DNAC_CFG_PARAM_MAX_ID` = 6; the read list is {4, 5, 6}. Signatures unchanged. |
| `nodus_rt_exec_ctx_t.token_create_fee` (`nodus/src/witness/nodus_witness_runtime.h`) | **NEW field (W-C).** The committed chain_config param 6 at `global_height` (compiled `NODUS_W_TOKEN_CREATE_FEE` with no row), filled by the engine on every ctx it builds; `rtn_tc_exec` refuses `fee <` it. |
| `static int env_token_create_fee(nodus_witness_t *w, uint64_t height, uint64_t *out, char *reason, size_t reason_size)` (`nodus/src/witness/nodus_witness_v2_apply.c`) | **NEW (W-C, internal).** `nodus_chain_config_get_u64(w, 6, height, NODUS_W_TOKEN_CREATE_FEE, out)`; 0, or -2 (FAULT, reason written) when unreadable. Called by `env_authorize_legs` and `exec_one_env`. |
| `nodus_dnac_fee_info_t.token_create_fee` (`nodus/include/nodus/nodus_types.h`); `int nodus_client_dnac_fee_info(nodus_client_t *client, nodus_dnac_fee_info_t *result_out)` | **NEW field / CHANGED behaviour (W-C).** The decoder reads the optional `token_create_fee` key of the `dnac_fee_info` reply (absent = 0: an older server). Signature unchanged. |

---

## 5. Genesis bundle (`nodus/src/witness/nodus_witness_v2_bundle.h`)

| Item | Description |
|------|-------------|
| `NODUS_V2_GBUNDLE_MAGIC` | **CHANGED (W-A):** `"DNA.GBUNDLE.v5\0\0"`, six tables (… `validator_stats`, `v2_treasury`). |
| `NODUS_V2_GBUNDLE_MAGIC_V4_RETIRED` | **NEW (W-A).** `"DNA.GBUNDLE.v4\0\0"` — refused by its magic. |

---

## 6. Package W-B — exact self-stake, self-delegation (`docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md` items 5, 6)

| Item | Description |
|------|-------------|
| `int dna_vset_validate_bonds(const dna_vset_snapshot_t *snap, uint64_t min_self_bond_raw)` (`shared/dnac/vset_wire.h`) | **REMOVED (W-B).** A `self_bond >= min` policy helper with no caller in any build (its only user was its own unit test, `test_vset_wire.c` §4, also removed). The exact-bond rule lives in the STAKE exec and genesis Rule P.1. |
| `int nodus_witness_v2_balance_copy_write(nodus_witness_t *w, uint64_t epoch_start)` (`nodus_witness_v2_econ.h`) | **CHANGED (W-B, behaviour):** writes `v2_balance_copy(epoch_start, validator_fp, owner_fp, kind, amount)` — the bond as `kind` 0, every delegation (a self-delegation included) as `kind` 1; the primary key includes `kind`. Signature unchanged. |
| `int nodus_witness_v2_balance_copy_frozen(nodus_witness_t *w, uint64_t epoch_start, const uint8_t *pubkey, uint64_t *self_out, uint64_t *total_out)` (`nodus_witness_v2_econ.h`) | **CHANGED (W-B, behaviour):** `*self_out` = the `kind`-0 (bond) row only — no longer "the row owned by the validator", which a self-delegation now also is; `*total_out` = bond + every `kind`-1 row. -1 (fault) on a `kind` outside {0, 1} or a `kind`-0 row owned by anyone but the validator. Signature unchanged. The header's own contract comment (`nodus_witness_v2_econ.h`, "owner_fp == validator_fp") was outside package W-B's file list and still reads the old wording. |
| `static int t6_hex_exact(const char *hex, uint8_t *out, size_t n)` (`nodus/tools/nodus-cli.c`) | **NEW (W-B).** Decodes exactly `n` bytes from `2n` lowercase hex chars; 0 / -1. Used by `v2-envelope delegate --validator`. |
| `static int cmd_v2_stake(const char *server_ip, uint16_t server_port, int argc, char **argv, int cmd_start)` (`nodus/tools/nodus-cli.c`) | **CHANGED (W-B, behaviour):** serves BOTH `v2-envelope stake` (now refuses `--bond` != `DNAC_SELF_STAKE_AMOUNT`) and the NEW `v2-envelope delegate --keys <dir> --validator <hex5184> --amount <raw>` (SYSTEM DELEGATE runtime_op 2 + CORE SYSFUND, the delegator = the `--keys` identity, which may also be the target — self-delegation). Signature unchanged. |
| `static int cmd_stake(...)` (`nodus/tools/nodus-cli.c`) | **CHANGED (W-B, behaviour):** `--bond` must equal `DNAC_SELF_STAKE_AMOUNT` (was `>=`). Signature unchanged. |

---

## 7. General multisig — M-of-N addresses (`docs/plans/decisions/2026-09-29-general-multisig.md`, design §7 rev 2)

`shared/dnac/msig_wire.c` is compiled into `libnodus` only (nodus build —
the CORE auth hook and `nodus-cli`); libdna has no caller.

| Item | Description |
|------|-------------|
| `int dna_msig_desc_encode(uint8_t m, uint8_t n, const uint8_t *pubkeys, uint8_t *out, size_t out_cap, size_t *out_len)` (`shared/dnac/msig_wire.h`) | **NEW.** Descriptor = `"DNA.MSIG.v1"` (16 B zero-padded) ‖ M u8 ‖ N u8 ‖ N × pubkey[2592]. Refuses 2 > N > 7, M outside [1, N], keys not STRICTLY ascending (never sorts), a key whose first 32 bytes are zero, a short buffer. 0 / -1. |
| `int dna_msig_desc_parse(const uint8_t *d, size_t len, uint8_t *m_out, uint8_t *n_out, const uint8_t **keys_out)` | **NEW.** Strict inverse: tag, bounds, `len == 18 + N × 2592` exactly, order, zero key. 0 / -1. |
| `int dna_msig_address(const uint8_t *d, size_t len, uint8_t out[64])` | **NEW.** `SHA3-512(descriptor)` after `dna_msig_desc_parse`. 0 / -1 invalid / -2 hash backend. |
| `NODUS_RT_AUTHKIND_DSA87_MSIG_V1` (3), `NODUS_RT_MSIG_MAX_KEYS` (15), `NODUS_RT_MSIG_MAX_DESC` (7) (`nodus_witness_runtime.h`) | **NEW.** auth_kind 3 = the kind-1 signer section ‖ dcount u8 (1..7) ‖ dcount × (dlen u16 BE ‖ descriptor), descriptors strictly ascending by address, Σ N ≤ 15, exact consumption. CORE's allowlist is {1, 3} (SYSTEM stays {1, 2}); CORE ruleset v4 (ONE bump with W-C). |
| `nodus_rt_auth_verdict_t.n_msig`, `.msig_satisfied[7]`, `.msig_addr[7][64]` | **NEW fields.** Every carried descriptor's address and whether ≥ M of its keys are verified signers; zero for kinds 1/2. `sizeof` 966 → 1 424 B, so `NODUS_V2_APPLY_ENV_COST_BYTES` 20 908 → 21 824, `NODUS_V2_ENV_BATCH_MAX` 3 209 → 3 075, `NODUS_V2_APPLY_MAX_OPS` 17 371 → 17 237 (`nodus_witness_v2_apply.h` pins). |
| `int nodus_rt_auth_dsa87_v1(...)` | **CHANGED (behaviour):** parses/verifies auth_kind 3 (`rtn_auth_msig`, internal). Signature unchanged. |
| `static int rtn_owners_init(...)`, `static int rtn_input_owned(rtn_owners_t *o, const uint8_t owner128[128])`, `static int rtn_owners_all_used(const rtn_owners_t *o)` (`nodus_witness_rt_native.c`) | **NEW (internal).** The ONE input-ownership predicate SPEND, BURN, TOKEN_CREATE and SYSFUND use: owned ⇔ owner ∈ verified signer fps ∨ owner == a satisfied carried multisig address; every carried descriptor must own ≥ 1 input. Replaces `rtn_signer_fps` (removed). |
| `env_authorize_legs` (`nodus_witness_v2_apply.c`), `acache_store` (`nodus_witness_cmt_app.c`) | **CHANGED (behaviour):** the CheckTx recheck cache stores and reuses kind-3 verdicts as it does kind-1 (a kind-3 verdict must carry 1..7 descriptor facts, a kind-1 none). |
| `static int cmd_msig_address(...)`, `cmd_msig_sign(...)`, `cmd_msig_combine(...)`, `cmd_v2_spend_msig(...)` (`nodus/tools/nodus-cli.c`) | **NEW (internal CLI).** `msig address --m M --pubkey <f>...`; `v2-envelope spend --msig <desc> --keys <session> --in <nul>:<amt>... --to <fp> --amount <raw> --export <f>` (UNSIGNED envelope, K = `--signers`, default M); `msig sign --keys <dir> --in <export> --out <sig>` (re-derives the digest, refuses a mismatch); `msig combine --in <export> --sig <f>... (--keys <dir> [--submit] \| --out <env>)` (exactly K signatures, ascending, the chain's auth hook run locally). |
| `nodus_v2_epoch_result_t.n_grad_utxos`, `nodus_witness_treasury_graduation_refund`, `nodus_witness_treasury_credit` | **REMOVED** — see §2 / §3. |
| genesis validator destination (`gen_plan_build`, `nodus_witness_v2_gen.c`) | **CHANGED (behaviour):** `unstake_destination_fp` is checked by SHAPE only (the graduation predicate); the rule "fp == SHA3-512(unstake_destination_pubkey)" is REMOVED — a genesis seat pays the Foundation multisig address, which no single key derives. `unstake_destination_pubkey` MUST be all zero on a genesis row (ONAY 2 item 2 — refused otherwise). |
| `NODUS_V2_GEN_CONFIG_VERSION_V5` (5u), `NODUS_V2_GEN_MAX_GENOUTS` (64), `nodus_v2_gen_output_t { uint8_t owner[64]; uint64_t amount; }`, `nodus_v2_gen_config_t.n_genesis_outputs` / `.genesis_outputs[64]` (`nodus_witness_v2_gen.h`) | **NEW (ONAY 2).** The genesis-output section: `u32 count ‖ count × (owner[64] ‖ amount u64 BE)` after the W-C tail, document order. `NODUS_V2_GEN_CONFIG_VERSION_V4` is RETIRED (every path refuses 4); `_v3_defaults` writes 5. Rule P.2 counts Σ outputs; `total_claimable` excludes them. |
| `int nodus_witness_v2_gen_output_nullifier(const uint8_t source_commit[64], uint32_t index, uint8_t out[64])` | **NEW (ONAY 2).** `SHA3-512("DNA.GENOUT.v1" 16 B ‖ source_commit ‖ index u32 BE)` (84-byte preimage). 0 / -1. |
| `int nodus_witness_v2_gen_seed_outputs(nodus_witness_t *w, const nodus_v2_gen_config_t *cfg, const uint8_t source_commit[64])` | **NEW (ONAY 2).** The ONE genesis-output writer: refuses a non-empty `utxo_set`, inserts each output (nullifier = tx_hash = the identity above, owner hex, amount, index 0, height 0, unlock 0, domain CORE, native), then requires exactly `n_genesis_outputs` rows summing to Σ outputs. Called by `gen_seed_state` (derivation, before the root) and `nodus_witness_v2_bundle_apply` (joiner, from the carried document). 0 / -1. |
| `nodus_v2_gen_config_parse_file` (`nodus/tools/nodus_v2_gen_config.c`) | **CHANGED (behaviour, ONAY 2):** `config_version = 5` only; new `[genesis_output]` block (`owner` 128 hex, `amount`), 0..64, file order. Signature unchanged. |
| `int nodus_witness_v2_bundle_apply(...)` | **CHANGED (behaviour, ONAY 2):** re-derives the genesis outputs from the carried document (after storing it, before the snapshots / registry / genesis apply). Signature unchanged. |
