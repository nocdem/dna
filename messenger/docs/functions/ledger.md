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
| `int dna_v2_empty_root(dna_v2_empty_kind_t kind, uint8_t out[64])` | SHA3-512 of the kind's 16-byte tag alone. **W-A:** new kind `DNA_V2_EMPTY_TREASURY` (`"NDS.E.TREAS.v1"`), appended after `DNA_V2_EMPTY_ACCRUAL`. |
| `int dna_v2_treasury_leaf_hash(uint32_t pool_id, uint64_t balance, uint8_t out[64])` | **NEW (W-A).** `SHA3-512("NDS.TRLEAF.v1" 16 B ‖ pool_id u32 BE ‖ balance u64 BE)`. 0 / -1. |
| `int dna_v2_treasury_root(const uint32_t *pool_ids, const uint64_t *balances, size_t n, uint8_t out[64])` | **NEW (W-A).** Tagged Merkle over treasury leaves, pool_id STRICTLY ascending (duplicate / descending → -1), inner `"NDS.TRNODE.v1"`, odd node promoted, n==1 → the leaf, n==0 → `DNA_V2_EMPTY_TREASURY`. |
| `int dna_v2_system_root(const uint8_t validator_root[64], const uint8_t delegation_root[64], const uint8_t chain_config_root[64], const uint8_t validator_set_root[64], const uint8_t domain_registry_root[64], const uint8_t manifest_root[64], const uint8_t attendance_root[64], const uint8_t treasury_root[64], uint8_t out[64])` | **CHANGED (W-A):** 8 legs under `"NDS.SYS.v4"` — `treasury_root` appended as the LAST parameter/leg (was 7 legs, `"NDS.SYS.v3"`). |
| `int dna_v2_system_payload_root(const uint8_t validator_root[64], const uint8_t delegation_root[64], const uint8_t chain_config_root[64], const uint8_t validator_set_root[64], const uint8_t treasury_root[64], uint8_t out[64])` | **CHANGED (W-A):** 5 legs under `"NDS.SYSPAYL.v3"` — `treasury_root` appended LAST (was 4 legs, `"NDS.SYSPAYL.v2"`). |
| `int dna_v2_accrual_leaf_hash(const uint8_t owner_fp[64], uint64_t amount, uint8_t out[64])` | Reward-accrual leaf (`"NDS.ACLEAF.v1"`), unchanged. |
| `int dna_v2_accrual_root(const uint8_t (*owner_fps)[64], const uint64_t *amounts, size_t n, uint8_t out[64])` | Reward-accrual root (`"NDS.ACNODE.v1"`), unchanged. |
| `int dna_v2_core_root(...)` | 7-leg CORE composition (`"NDS.CORE.v2"`), unchanged. |

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
| `int nodus_witness_system_root_v2(nodus_witness_t *w, uint8_t out[64])` | **CHANGED (W-A, behaviour):** composes the treasury leg (8 legs, `"NDS.SYS.v4"`). Signature unchanged. |
| `int nodus_witness_system_payload_root_v2(nodus_witness_t *w, uint8_t out[64])` | **CHANGED (W-A, behaviour):** composes the treasury leg (5 legs, `"NDS.SYSPAYL.v3"`). Signature unchanged. |

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
| `NODUS_V2_GBUNDLE_MAGIC` | **CHANGED (W-A):** `"NDS.GBUNDLE.v5\0\0"`, six tables (… `validator_stats`, `v2_treasury`). |
| `NODUS_V2_GBUNDLE_MAGIC_V4_RETIRED` | **NEW (W-A).** `"NDS.GBUNDLE.v4\0\0"` — refused by its magic. |

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
| `int dna_msig_desc_encode(uint8_t m, uint8_t n, const uint8_t *pubkeys, uint8_t *out, size_t out_cap, size_t *out_len)` (`shared/dnac/msig_wire.h`) | **NEW.** Descriptor = `"NDS.MSIG.v1"` (16 B zero-padded) ‖ M u8 ‖ N u8 ‖ N × pubkey[2592]. Refuses 2 > N > 7, M outside [1, N], keys not STRICTLY ascending (never sorts), a key whose first 32 bytes are zero, a short buffer. 0 / -1. |
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
| `int nodus_witness_v2_gen_output_nullifier(const uint8_t source_commit[64], uint32_t index, uint8_t out[64])` | **NEW (ONAY 2).** `SHA3-512("NDS.GENOUT.v1" 16 B ‖ source_commit ‖ index u32 BE)` (84-byte preimage). 0 / -1. |
| `int nodus_witness_v2_gen_seed_outputs(nodus_witness_t *w, const nodus_v2_gen_config_t *cfg, const uint8_t source_commit[64])` | **NEW (ONAY 2).** The ONE genesis-output writer: refuses a non-empty `utxo_set`, inserts each output (nullifier = tx_hash = the identity above, owner hex, amount, index 0, height 0, unlock 0, domain CORE, native), then requires exactly `n_genesis_outputs` rows summing to Σ outputs. Called by `gen_seed_state` (derivation, before the root) and `nodus_witness_v2_bundle_apply` (joiner, from the carried document). 0 / -1. |
| `nodus_v2_gen_config_parse_file` (`nodus/tools/nodus_v2_gen_config.c`) | **CHANGED (behaviour, ONAY 2):** `config_version = 5` only; new `[genesis_output]` block (`owner` 128 hex, `amount`), 0..64, file order. Signature unchanged. |
| `int nodus_witness_v2_bundle_apply(...)` | **CHANGED (behaviour, ONAY 2):** re-derives the genesis outputs from the carried document (after storing it, before the snapshots / registry / genesis apply). Signature unchanged. |

---

## 8. Scan supply buckets — `dnac_supply` additive keys (`docs/plans/decisions/2026-09-30-scan-supply-buckets.md`)

Read-only; no consensus caller, no `state_root` input.

| Item | Description |
|------|-------------|
| `NODUS_WITNESS_SUPPLY_TREASURY_POOLS` (9u), `nodus_witness_supply_view_t { int has_supply; nodus_witness_supply_t supply; uint64_t tip; uint64_t treasury[9]; uint64_t unclaimed; }` (`nodus/src/witness/nodus_witness_db.h`) | **NEW.** `treasury[i]` = `v2_treasury.balance` of pool i+1 (no row = 0); `unclaimed` = `nodus_witness_v2_unclaimed_total(DNA_DOMAIN_CORE, native)`. |
| `int nodus_witness_supply_view_get(nodus_witness_t *w, nodus_witness_supply_view_t *out)` (`nodus_witness_db.c`) | **NEW.** Successor chains only. One call on the single witness connection: refuses an open ledger transaction (`sqlite3_get_autocommit` == 0), then `nodus_witness_supply_get` (absent row → `has_supply` 0), `nodus_witness_v2_tip_height`, the treasury scan (non-INTEGER column, pool_id outside 1..9, negative balance → fault) and the unclaimed total. 0 / -1 (never a value on a fault). |
| `static void handle_dnac_supply(...)` (`nodus_witness_handlers.c`) | **CHANGED (behaviour).** Version-3 arm reads through `nodus_witness_supply_view_get`; with a supply row it adds `"reward_pool"`, `"treasury"` (9 uints) and `"unclaimed"` (map 7 → 10 keys, worst case 329 of 512 bytes). A read fault on that arm now answers `NODUS_ERR_INTERNAL_ERROR` "supply state unreadable" (previously zeros for a supply-row fault). Legacy arm unchanged. |
| `NODUS_DNAC_TREASURY_POOLS` (9), `nodus_dnac_supply_buckets_t { bool has; uint64_t current_supply; uint64_t reward_pool; uint64_t treasury[9]; uint64_t unclaimed; }` (`nodus/include/nodus/nodus.h`) | **NEW.** `current_supply` is the SAME reply's `"current"`; `has` false = an older node. |
| `int nodus_dnac_supply_buckets_decode(const uint8_t *raw, size_t raw_len, nodus_dnac_supply_buckets_t *out)` (`nodus_client.c`) | **NEW.** Strict: duplicate key, truncation, non-uint, a `"treasury"` that is not exactly 9 uints, `"current"` missing, or 1-2 of the 3 bucket keys → -1 (`out` zeroed); none of the 3 → 0 with `has` false. |
| `int nodus_client_dnac_supply_buckets(nodus_client_t *client, nodus_dnac_supply_buckets_t *out)` (`nodus_client.c`) | **NEW.** Same `dnac_supply` request as `nodus_client_dnac_supply` (thin accessor; `nodus_dnac_supply_result_t` not grown). 0 / `NODUS_ERR_PROTOCOL_ERROR` malformed / the node's error code / `NODUS_ERR_TIMEOUT` / -1. |
| `exp_chain_tip_t.buckets` (`explorer/src/exp_chain.h`) | **NEW field.** Filled by a fourth round trip in `tip_once`; an older node is not a failure. |
| `EXP_META_SUPPLY_BUCKETS`, `EXP_SUPPLY_BUCKETS_BLOB_LEN` (97), `void exp_supply_buckets_pack(const nodus_dnac_supply_buckets_t *b, uint8_t out[97])`, `int exp_supply_buckets_unpack(const uint8_t *buf, size_t len, nodus_dnac_supply_buckets_t *out)`, `int exp_supply_circulating(const nodus_dnac_supply_buckets_t *b, uint64_t *out)` (`explorer/src/exp_chain.{h,c}`) | **NEW (pure).** The meta blob (has byte + 12 LE u64: current, reward_pool, treasury 1..9, unclaimed) and circulating = current − reward_pool − Σ treasury − unclaimed; -1 on `has` false or any underflow (never wrapped). |

---

## 9. HF-2 — power-weighted governance approval + net-zero blocks (`docs/plans/2026-09-30-gov-weight-netzero-design.md` rev 2; decision `docs/plans/decisions/2026-09-30-governance-stake-weight-and-power-cap.md`)

One height-activated switch, chain_config param 7. No row = both rules as before (see `nodus/docs/ARCHITECTURE.md` "HF-2" for the one pre-activation difference: the envelope-count bound).

| Item | Description |
|------|-------------|
| `DNAC_CFG_HF2_ACTIVE` (7), `DNAC_CFG_HF2_ACTIVE_ON` (1ULL), `DNAC_CFG_PARAM_MAX_ID` 6 → 7 (`dnac/include/dnac/dnac.h`) | **NEW.** Value domain exactly 1 (a one-way switch). `dnac_cfg_param_read_by_consensus` now also answers true for 7. Witness mirrors `CC_PARAM_HF2_ACTIVE` / `CC_HF2_ACTIVE_ON` (`nodus_witness_chain_config.c`, `_Static_assert`-pinned). |
| `int nodus_chain_config_scalar_rules(...)` | **CHANGED (behaviour):** id 7 accepted with value 1 only (0 and every other value -1). Signature unchanged. |
| `uint64_t nodus_chain_config_grace_for_param(uint8_t param_id)` | **CHANGED (behaviour):** id 7 → `DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS`. Signature unchanged. |
| `static int verify_chain_config_rules(...)` (`dnac/src/transaction/verify.c`) | **CHANGED (behaviour):** client mirror — id 7 accepted with value 1 only. |
| `nodus_rt_committee_t.powers` (`nodus/src/witness/nodus_witness_runtime.h`) | **NEW field.** `const uint64_t *`, `count` entries in seat order, each `total_stake / DNAC_DECIMAL_UNIT` (the block-commit derivation). |
| `nodus_rt_auth_verdict_t.approved_power`, `.committee_power` | **NEW fields (appended LAST).** Kind 2 only: checked u64 sums of the verified approving seats' powers and of every seat's; both 0 when the committee sum overflows ("unweighable"); 0 for kinds 1/3. `sizeof` 1 424 → 1 440 B, so `NODUS_V2_APPLY_ENV_COST_BYTES` 21 824 → 21 856, `NODUS_V2_ENV_BATCH_MAX` 3 075 → 3 070, `NODUS_V2_APPLY_MAX_OPS` 17 237 → 17 232 (`nodus_witness_v2_apply.h` pins). |
| `nodus_rt_exec_ctx_t.hf2_active` | **NEW field.** `uint8_t`, 1 when param 7 is active at `global_height`; filled by the engine on every ctx (`env_authorize_legs`, `exec_one_env`). |
| `int nodus_rt_auth_dsa87_v1(...)` | **CHANGED (behaviour):** kind 2 refuses (-1) a non-empty committee view with `powers == NULL` (after the unchanged `count == 0` refusal) and fills the two power sums. Signature unchanged. |
| `int nodus_rt_system_exec(...)` | **CHANGED (behaviour):** CHAIN_CONFIG approval — `ctx->hf2_active` 0: `n_approvals >= dna_bft_quorum(committee_n)` (unchanged); 1: `committee_power > 0` and `approved_power > committee_power * 2 / 3` (checked doubling; overflow refuses). Signature unchanged. |
| `static int env_hf2_active(nodus_witness_t *w, uint64_t height, uint8_t *on, char *reason, size_t reason_size)` (`nodus/src/witness/nodus_witness_v2_apply.c`) | **NEW (internal).** `nodus_chain_config_get_u64(w, 7, height, 0, &v)`; `*on` = (v == 1); a read fault or a stored value outside {0, 1} → -2 (FAULT, reason written). Called by `env_authorize_legs`, `exec_one_env` and phase 9. |
| `static int committee_snapshot_for_height(nodus_witness_t *w, uint64_t height, nodus_rt_committee_t *view, uint8_t **out_pubkeys, uint8_t (**out_fps)[64], uint64_t **out_powers, char *reason, size_t reason_size)` | **CHANGED (internal signature):** + `out_powers` (heap, caller frees; filled before the member array is freed). |
| phase 9 of `nodus_witness_v2_apply_block` | **CHANGED (behaviour):** with param 7 active at the block's height a touched domain whose root is unchanged writes its DomainUpdate with `pre_root == post_root` instead of a block VERDICT. |
| `nodus-cli chain-config propose --param HF2_ACTIVE --value 1 --effective <H>`; `v2-envelope chain-config` (`nodus/tools/nodus-cli.c`) | **CHANGED (CLI).** `HF2_ACTIVE` / `hf2_active` in the param name table. The offline builder reads param 7 at tip + 1 from its database and, when active, picks approver keys in the given order until their power exceeds 2/3 of the committee's. The online `propose` keeps the seat rule for its own early abort (no RPC reports param 7) and prints a note. `witness` prints the seat quorum AND the committee's total voting power with the `> total*2/3` threshold. |

---

## 10. Web wallet package (c2) — the shared CORE SPEND builder (`nodus/include/nodus/nodus_v2_spend.h`, `nodus/src/client/nodus_v2_spend.c`)

Design `docs/plans/2026-09-25-web-wallet-nodus-send-design.md` §0a.3 (c2) / §1.3; decision
`docs/plans/decisions/2026-09-25-web-wallet-nodus-send-transport.md` ("İşlem kurucu" + addendum
2026-09-29 "Yol 2"). Moved out of `nodus/tools/nodus-cli.c` (the `t6_*` helpers and the plan/build
loops of `cmd_v2_spend`); behaviour unchanged. Compiled into `libnodus` (so also into `libdna.so`
via the messenger build) and, standalone, for the browser module. No I/O, no clock, no global RNG:
output seeds come from the caller's `nodus_v2_rand_fn`. (`qgp_dsa87_sign` is hedged — two builds
differ in signature bytes and `wire_id`, never in `intent_id` or any byte outside the auth blob.)

| Item | Description |
|------|-------------|
| `NODUS_V2_SPEND_MAX_IN` (15), `NODUS_V2_SPEND_OUT_LEN` (232), `NODUS_V2_SPEND_MAX_OUTS` (3) | **NEW (moved).** Were `T6_SPEND_MAX_IN` / `T6_SPEND_OUT_LEN` / `T6_SPEND_MAX_OUTS` in nodus-cli. |
| `nodus_v2_spend_rc_t` | **NEW.** 0 OK, 1 `NONE_ELIGIBLE` (plan, count_all), negative refusals `-1 ARG` … `-23 DUP_OUTPUT` (header). |
| `nodus_v2_spend_order_t` | **NEW.** Only `NODUS_V2_SPEND_ORDER_LARGEST_FIRST` (0) — largest amount first, ties by nullifier. Smallest-first is ÖNERİ (`2026-09-25-spend-inputs-64-smallest-first.md` item 1) and refused. |
| `nodus_v2_coin_t { nul[64]; amount; kind; used; }`, `nodus_v2_spend_plan_t { idx[15]; n_in; native_in, token_in, native_change, token_change; }` | **NEW (moved).** Were `t6_coin_t` / `t6_spend_plan_t`. `nul` stays the first member. |
| `nodus_v2_ruleset_id_t { core_ruleset_version; core_ruleset_hash[64]; const dna_meter_policy_t *meter_policy; }` | **NEW.** The CORE ruleset identity + the BLOCK (SYSTEM) metering policy a SPEND is built and priced against. |
| `typedef int (*nodus_v2_rand_fn)(void *ctx, uint8_t *buf, size_t len)` | **NEW.** Caller randomness (0 = OK). |
| `nodus_v2_spend_err_t { k; fee; units; required; pass; n_in, n_out; leg; draws; }` | **NEW.** The numbers a refusal carries, for the caller's message. |
| `int nodus_v2_nul_cmp(const void *a, const void *b)` | **NEW (moved, was `t6_nul_cmp`).** memcmp of the first 64 bytes. |
| `int nodus_v2_spend_sort_coins(nodus_v2_coin_t *coins, int n_coins, nodus_v2_spend_order_t order)` | **NEW (was `qsort(…, t6_coin_cmp)`).** 0 / `ERR_ARG` (unknown order). |
| `int nodus_v2_spend_pick(const nodus_v2_coin_t *coins, int n_coins, uint8_t kind, uint64_t need, nodus_v2_spend_plan_t *plan, uint64_t *sum_out)` | **NEW (moved, was `t6_spend_pick`).** 0 / -1 short / -2 > 15 inputs / -3 sum overflow. |
| `void nodus_v2_xfer_out_put(uint8_t *rec, const char *owner_hex128, uint64_t amount, const uint8_t *token64, const uint8_t seed32[32])` | **NEW (moved, was `t6_xfer_out_put`).** One 232-byte output record. |
| `void nodus_v2_spend_effect_decl(uint32_t n_in, uint32_t n_out, uint32_t *effects_out, uint32_t *bytes_out)` | **NEW (moved, was `t6_spend_effect_decl`).** effects = n_in + n_out + 1; bytes = 116 + 148·n_in + 432·n_out. |
| `int nodus_v2_spend_ceiling(dna_env_in_t *env_in, const dna_meter_policy_t *pol, uint32_t n_reads, uint64_t *ceiling_out)` | **NEW (moved, was `t6_spend_ceiling`).** static_units + n_reads × w_read. 0 / -1. |
| `int nodus_v2_spend_units_for_shape(uint32_t core_ruleset_version, const dna_meter_policy_t *pol, uint32_t alen, int n_in, int n_out, uint64_t *units_out)` | **NEW (moved, was `t6_spend_units_for_shape(core_rt, …)`).** First parameter is now the ruleset version, not the runtime; refuses n_in ∉ 1..15, n_out ∉ 1..3. |
| `int nodus_v2_env_sign_one_key(const dna_env_in_t *env_in, uint8_t *const *auths, const dna_env_leg_ctx_t *lctx, const uint8_t chain32[32], uint64_t tip, const uint8_t *pk, const uint8_t *sk, uint8_t **env_out, size_t *env_len_out, dna_env_preflight_t *pf, nodus_v2_spend_err_t *err)` | **NEW (moved, was `t6_env_sign_one_key(…, const nodus_identity_t *key, …)`).** Takes pk/sk bytes; prints nothing — returns `ERR_PREFLIGHT1` / `ERR_SIGN` (`err->leg`) / `ERR_PREFLIGHT2` / `ERR_ENCODE` / `ERR_ALLOC`. |
| `int nodus_v2_ruleset_from_pins(nodus_v2_ruleset_id_t *out, dna_meter_policy_t *policy_storage)` | **NEW.** Fills the CORE tuple from `nodus_ruleset_pins.h` and rebuilds the SYSTEM meter policy into `policy_storage`; `ERR_PINS` unless its `dna_meter_policy_digest` equals the pinned digest (the WASM start-up self-check). |
| `int nodus_v2_spend_plan(const nodus_v2_spend_plan_req_t *req, nodus_v2_coin_t *coins, int n_coins, nodus_v2_spend_plan_t **plans_out, long *count_out, uint64_t *fee_out, nodus_v2_spend_err_t *err)` | **NEW (the plan loop of `cmd_v2_spend`).** Sorts `coins` in place, plans `count` disjoint spends, bounded gas-price fixed point (≤ 8 passes, one fee per batch; `fee_fixed` never raised). `*plans_out` heap. |
| `int nodus_v2_spend_build(const nodus_v2_spend_build_req_t *req, nodus_v2_spend_built_t *out, nodus_v2_spend_err_t *err)`, `void nodus_v2_spend_built_free(nodus_v2_spend_built_t *b)` | **NEW (the build loop of `cmd_v2_spend`).** One envelope from one plan: call, leg, units, gas check, two-pass signature, then read-back and refusal if it differs from the request. Refuses tip 0 and expiry ∉ (tip, tip + 100]. Optional output-id shard (`shard_m`, `shard_i`). |
| `int nodus_v2_spend_decode(const uint8_t *env, size_t env_len, nodus_v2_spend_decoded_t *out)` | **NEW.** Self-consistent decode of a one-leg CORE SPEND this module builds: inputs, outputs (owner, amount, token, id), fee, expiry, units, declaration. |
| `static int cli_sign_one_key(...)`, `static int cli_rand(void *ctx, uint8_t *buf, size_t len)`, `static void cli_ruleset_id(const nodus_domain_runtime_t *core_rt, const nodus_domain_runtime_t *sys_rt, nodus_v2_ruleset_id_t *out)` (`nodus/tools/nodus-cli.c`) | **NEW (internal).** The CLI's wrappers: prints the sign refusal as before; `nodus_random` as the seed source; the compiled-table ruleset. |

## 11. Generated ruleset pins (`nodus/include/nodus/nodus_ruleset_pins.h`, `nodus/tools/gen_ruleset_pins.c`)

Decision `2026-09-25-web-wallet-nodus-send-transport.md` addendum 2026-09-29 "Yol 2".

| Item | Description |
|------|-------------|
| `NODUS_PIN_CORE_*`, `NODUS_PIN_SYS_METER_*` macros | **NEW (GENERATED — never edit).** CORE domain/kind/abi/ruleset_version/ruleset_hash and the SYSTEM meter policy fields, op list, weights and digest, read from `nodus_runtime_builtin_table()`. Regenerate: `cmake --build <nodus build> --target regen_ruleset_pins`. |
| `int nodus_ruleset_pins_render(char **out, size_t *out_len)` (`nodus/tools/gen_ruleset_pins.c`) | **NEW (tool).** Renders the header text (heap, caller frees); -1 if the runtime selfcheck fails or the SYSTEM policy does not match its committed digest. `test_ruleset_pins` byte-compares it with the checked-in file. |
| `NODUS_PIN_SYS_DOMAIN_ID`, `NODUS_PIN_SYS_RUNTIME_KIND`, `NODUS_PIN_SYS_RUNTIME_ABI`, `NODUS_PIN_SYS_RULESET_VERSION`, `NODUS_PIN_SYS_RULESET_HASH_INIT` | **NEW (GENERATED, 2026-09-30).** The SYSTEM ruleset identity — the staking envelopes' SYSTEM leg signs over it (`shared/dnac/env_preflight.c:77`). Same generator, same byte-compare test (`test_ruleset_pins` R4). |

## 11. Web wallet staking — the shared STAKE / DELEGATE / UNDELEGATE builder (`nodus/src/client/nodus_v2_stake.h`, `nodus/src/client/nodus_v2_stake.c`)

I/O-free, like the (c2) SPEND builder: nodus-cli `v2-envelope stake|delegate|undelegate` and the web wallet's `send.wasm` build every staking envelope with it.

| Item | Description |
|------|-------------|
| `int nodus_v2_stake_ruleset_from_pins(nodus_v2_stake_ruleset_t *out)` | **NEW.** SYSTEM + CORE (version, hash) from the generated pins header; refuses if the SYSTEM meter policy digest does not match. |
| `int nodus_v2_stake_build(const nodus_v2_stake_req_t *req, nodus_v2_stake_built_t *out, nodus_v2_stake_err_t *err)` | **NEW.** Two-leg envelope: SYSTEM record leg (runtime_op 1 STAKE / 2 DELEGATE / 4 UNDELEGATE) + CORE SYSFUND funding leg; kind-1 single signer; fee = max(floor, 400000 × gas_price); native unlocked coins in ascending nullifier order until lock + fee (lock 0 for UNDELEGATE); one deterministic change output. Signs, then reads the envelope back and refuses on any difference. Returns `NODUS_V2_SPEND_OK` or a refusal (−40..−43 bond / commission / amount / op, others shared with the spend builder). |
| `int nodus_v2_stake_decode(const uint8_t *env, size_t env_len, nodus_v2_stake_decoded_t *out)` | **NEW.** Strict decode of a staking envelope built by this module (shape, ops, declarations, input order, one signer = record identity). |
| `void nodus_v2_stake_built_free(nodus_v2_stake_built_t *b)` | **NEW.** NULL-safe. |

---

## 12. Node-local address history index — `dnac_addr_history` (`docs/plans/decisions/2026-10-01-node-address-history-index.md` rev 2; `nodus/src/witness/nodus_witness_addr_index.{h,c}`)

Out of every root, vote and validity path. Written only with the node flag `addr_history_index: true` (nodus.json; `nodus_server_config_t.addr_history_index`, default false). Rows per op: the module header.

| Item | Description |
|------|-------------|
| `bool nodus_witness_addr_index_enabled(const nodus_witness_t *w)` | **NEW.** `w->server->config.addr_history_index`; a witness without a server is OFF. |
| `int nodus_witness_addr_index_migrate(nodus_witness_t *w)` | **NEW.** Rung-free `CREATE ... IF NOT EXISTS` of `addr_history` (PK `(h, i, seq)`, index `(owner, h, i, seq)`) and `addr_history_mark`; called from `nodus_witness_db_migrate_v12` on every open. Aborts on a SQL failure (the `nodus_chain_config_db_migrate` rule). 0 / -1 NULL. |
| `int nodus_witness_addr_index_env(nodus_witness_t *w, uint64_t height, uint32_t item_pos, const dna_env_preflight_t *pf, const nodus_rt_auth_verdict_t *auths, char *reason, size_t reason_size)` | **NEW.** Rows of one applied envelope, inside its SAVEPOINT after `cmt_item_index`. Effects from `nodus_rt_native_describe_leg`; self set = the CORE verdict's signers ∪ satisfied msig addresses. 0 / -1 FAULT (`reason` written). |
| `int nodus_witness_addr_index_claim(nodus_witness_t *w, uint64_t height, uint32_t item_pos, const dna_claim_t *c, const uint8_t nullifier[64], uint32_t target_domain, char *reason, size_t reason_size)` | **NEW.** The applied claim's row (CORE target only): amount from `v2_claims_spent`, wire = SHA3-512(canonical claim bytes). 0 / -1 FAULT. |
| `int nodus_witness_addr_index_boundary(nodus_witness_t *w, uint64_t height, const char *kind, const uint8_t *owner_hex, uint64_t amount)` | **NEW.** One payout / release row at `i = NODUS_ADDR_INDEX_BOUNDARY_POS`. Called from `v2ec_emit` (econ) and `v2ep_release_utxo` (epoch). 0 / -2 FAULT. |
| `int nodus_witness_addr_index_block_close(nodus_witness_t *w, uint64_t height, uint64_t block_time, char *reason, size_t reason_size)` | **NEW.** After phase 6e: stamps `ts = blk->timestamp` (RequestFinalizeBlock.time.seconds) on the height's rows and advances the marker (first height / extend / restart after a gap / FAULT if already indexed). 0 / -1. |
| `int nodus_witness_addr_history_build(nodus_witness_t *w, uint32_t txn_id, const uint8_t *session_fp, const char *owner, const nodus_witness_addr_cursor_t *before, uint32_t limit, uint8_t **out, size_t *out_len, int *err_code, char *err_msg, size_t err_cap)` | **NEW.** The `dnac_addr_history` answer frame. Refusals: bad owner / limit → `PROTOCOL_ERROR`; no session or owner ≠ session (C11) → `NOT_AUTHENTICATED`; no version-3 chain → `NOT_FOUND`; store fault / malformed row → `INTERNAL_ERROR`. 0 / -1. |
| `static void handle_dnac_addr_history(...)` (`nodus_witness_handlers.c`) | **NEW.** Strict args decode (`owner`, `limit`, optional `before` / `bi` / `bq`), passes `conn->peer_id` when `peer_id_set`. `dnac_history` unchanged. |
| `NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT` (100u), `nodus_dnac_addr_history_entry_t`, `nodus_dnac_addr_history_result_t`, `nodus_dnac_addr_history_cursor_t` (`nodus/include/nodus/nodus.h`) | **NEW.** Wire spec beside the client function. |
| `int nodus_client_dnac_addr_history(nodus_client_t *client, const char *owner_hex, const nodus_dnac_addr_history_cursor_t *before, uint32_t limit, nodus_dnac_addr_history_result_t *result_out)` (`nodus_client.c`) | **NEW.** 0 / the node's error code / `NODUS_ERR_PROTOCOL_ERROR` malformed reply / `NODUS_ERR_TIMEOUT` / -1 (bad owner or limit, transport). |
| `int nodus_dnac_addr_history_decode(const uint8_t *raw, size_t raw_len, nodus_dnac_addr_history_result_t *result_out)` | **NEW.** Strict: duplicate key, truncation, unknown kind, peer not empty/128 hex, wire not empty/64 B, count ≠ array length, entries not strictly descending by (h, i, q) → -1. |
| `void nodus_client_free_addr_history_result(nodus_dnac_addr_history_result_t *result)` | **NEW.** NULL-safe. |
| `static int cmd_addr_history(...)` (`nodus/tools/nodus-cli.c`) | **NEW.** `nodus-cli -s <ip> -i <dir> addr-history [--before H[:I:Q]] [--limit N]` — the CLI identity's own history. |
