# Nodus EVM Functions

The Nodus EVM: an Ethereum (Prague) execution engine and its integration
into the version-3 (cometbft) chain as the THIRD domain (`DNA_DOMAIN_EVM`,
domain 2), beside SYSTEM and CORE. Code identifiers keep their `evm`
names; the product is "Nodus EVM", and its design and decision files are
named `nodus-evm`.

Design documents (LOCAL-only, not in git — named, not linked):

- `docs/plans/2026-10-04-nodus-evm-engine-design.md` — the engine (`shared/evm/`).
- `docs/plans/2026-10-04-nodus-evm-chain-integration-design.md` rev 3 — the chain
  integration (runtime ABI 2, envelope pairing, state commitment, receipts,
  mempool, activation, the §18 read RPC).

Governing decision records (also LOCAL-only, `docs/plans/decisions/`):
`2026-10-04-nodus-evm-domain.md`, `2026-10-04-nodus-evm-kurultay-k1.md`
(operator decisions 1-5: CORE-funded ceiling fee; full Prague precompile
set; q = 1 raw unit = 10^10 wei; explicit 64-byte withdraw recipient +
contract tickets; mcl for bn254), `2026-10-04-nodus-evm-kurultay-k2-summary.md`
(MPT + SHA3-512 commitment; one pending EVM transaction per sender; the
EVM gas sum is the one block work limit),
`2026-10-05-nodus-evm-redteam1-operator.md` (D1: at gas price 0 an EVM
CALL / CREATE / DEPOSIT is refused, WITHDRAW / REDEEM stay open).

Build scope: `shared/evm/` and `nodus/src/witness/nodus_witness_rt_evm.c`
are compiled into libnodus only in the standalone nodus build on
non-Windows hosts, which also defines `NODUS_EVM_ENABLED`
(`nodus_witness_rt_evm.h` header block). `shared/dnac/evm_call_wire.c` is
pure C with no nodus header and is also built into the web wallet's wasm
(`web-wallet/crypto/nodus-send-wasm.c`) and `nodus-cli`.

Return convention used across the engine and the node runtime: `0` success
/ deterministic outcome, `-1` deterministic refusal (same on every node),
`-2` node fault (never converted into an outcome), `-3` `EVM_BUDGET`
(engine only — see section 1).

---

## 1. Engine public API (`shared/evm/evm.h`)

The engine never touches storage: committed state is PULLED through a
read-only `evm_backend_t`, every write goes to an engine-owned journaled
overlay (`evm_state_t`), and the caller reads the overlay's canonical,
totally ordered change set afterwards. Address width is configuration (20
for Ethereum, 32 for Nodus), always held as 32 bytes right-aligned. Pinned
reference: `ethereum/execution-specs @a87891f7`, fork Prague; conformance:
execution-spec-tests v5.4.0 `fixtures_stable` Prague state tests with the
documented exclusions. Design: `2026-10-04-nodus-evm-engine-design.md`; the
Nodus profile (`nodus_profile`, tickets) is `2026-10-04-nodus-evm-chain-integration-design.md` §5, §10.

| Function | Description |
|----------|-------------|
| `void evm_tx_result_free(evm_tx_result_t *r)` | Free the owned members of a result (`output`, each log's `data`, `logs`, `tickets`). Harmless on a result `evm_tx_prevalidate` filled. |
| `evm_state_t *evm_state_new(const evm_config_t *cfg, const evm_backend_t *be)` | New overlay over `be`. NULL on allocation failure (fault) and on an invalid config: `precompile_mask` bit 0 or bits 18..31 set, `nodus_profile` not 0/1, a `ticket_addr` that is a numeric precompile address or (20-byte mode) non-canonical. `cfg` and `be` are borrowed and must outlive the state. |
| `void evm_state_free(evm_state_t *st)` | Free the overlay. |
| `int evm_tx_apply(evm_state_t *st, const evm_block_env_t *env, const evm_tx_t *tx, evm_tx_result_t *res)` | Apply one transaction on the overlay (Prague state transition: validity checks, intrinsic gas incl. the EIP-7623 floor, fee debit, value transfer, execution, refunds, coinbase priority fee). `0` applied (`res->status`, incl. `EVM_EXEC_BUDGET`); `-1` refused (`res->tx_error`, overlay unchanged; tx types 3 and 4 → `EVM_TXERR_TYPE_UNSUPPORTED`); `-2` fault (discard the overlay); `-3` only when a backend read the engine needs BEFORE anything can be applied, or while writing the tail of any outcome, was refused — nothing applied. |
| `int evm_tx_prevalidate(evm_state_t *st, const evm_block_env_t *env, const evm_tx_t *tx, evm_tx_result_t *res)` | Mempool pre-validation (integration design §4, §8): exactly the validity checks `evm_tx_apply` runs before execution — the same function — through non-mutating peeks; the overlay stays byte-identical. `0` valid / `-1` refused (`res->tx_error`) / `-2` fault / `-3` budget. `res` holds no owned memory afterwards. |
| `int evm_state_visit_changes(const evm_state_t *st, const evm_change_visitor_t *v)` | Walk the change set relative to the backend: one `account` callback per touched account in strictly ascending address order, then its changed `storage` slots ascending by key (zero value = deleted). Order is total and independent of insertion / hashing. `0`, the visitor's non-zero value, or `-2`; ANY non-zero backend answer during the walk (`EVM_BUDGET` included) is `-2`. |

**Callback slots** (struct members the caller fills, not exported functions):

| Item | Description |
|------|-------------|
| `int (*get_account)(void *ctx, const evm_addr *addr, evm_account_t *out)` | `evm_backend_t`. Fill `out` (`out->exists` says whether the account exists). `0` / `-2`; every backend callback may also return `EVM_BUDGET` (-3), which ends the running transaction as an applied failure no inner frame can catch. Any other value is a fault. |
| `int (*get_code)(void *ctx, const evm_addr *addr, uint8_t *buf, size_t cap, size_t *len_out)` | `evm_backend_t`. Copy the code into `buf`. The bytes MUST be exactly the code whose keccak256 `get_account` reported — the engine does not re-hash; a backend that cannot vouch for that returns `-2`. The node backend verifies both stored digests on every read (`nodus_witness_rt_evm.c be_get_code`). |
| `int (*get_storage)(void *ctx, const evm_addr *addr, const evm_bytes32 *key, evm_bytes32 *val_out)` | `evm_backend_t`. Committed slot value (absent = zero). |
| `int (*get_block_hash)(void *ctx, uint64_t number, evm_bytes32 *hash_out, int *available)` | `evm_backend_t`. BLOCKHASH; `*available = 0` when the backend does not serve that height. |
| `int (*has_storage)(void *ctx, const evm_addr *addr, int *out)` | `evm_backend_t`. `*out = 1` when committed state holds any non-zero slot for `addr`. Feeds the EIP-7610 deployability check, which Nodus RETAINS although execution-specs `2ce21915` removed it upstream. |
| `int (*account)(void *ctx, const evm_account_change_t *c)` | `evm_change_visitor_t`. One touched account; non-zero aborts the walk. |
| `int (*storage)(void *ctx, const evm_addr *addr, const evm_bytes32 *key, const evm_bytes32 *value)` | `evm_change_visitor_t`. One changed slot, after its account's callback. |

**Types and constants** (`evm.h`): `evm_bytes32`, `evm_addr`, `evm_fork_t`
(`EVM_FORK_PRAGUE` = 1), `EVM_BUDGET` (-3), `EVM_STACK_LIMIT` 1024,
`EVM_CALL_DEPTH_LIMIT` 1024, `EVM_MAX_CODE_SIZE` 24576, `EVM_MAX_INITCODE_SIZE`
49152, `EVM_PRECOMPILES_PRAGUE` `0x0003FFFE` (bits 1..17), `evm_config_t`
(fork, `addr_bytes`, 256-bit `chain_id`, `precompile_mask`, and the Nodus
profile fields `nodus_profile`, `ticket_addr`, `ticket_unit`, `ticket_gas`),
`evm_account_t`, `evm_backend_t`, `evm_block_env_t`, `evm_access_entry_t`,
`evm_tx_t` (incl. `intent_id[64]`, Nodus profile), `evm_tx_error_t`,
`evm_exec_status_t` (incl. `EVM_EXEC_BUDGET`), `evm_log_t`,
`evm_tx_result_t` (incl. `gas_used_pre_refund`, `wei_destroyed`, tickets),
`evm_ticket_t` (`ticket_id = SHA3-512("NDS.EVMTKT.v1\0\0\0" (16 B) ‖
intent_id (64 B) ‖ seq u32 BE)`), `evm_account_change_t`,
`evm_change_visitor_t`. The Nodus-profile deviations from Prague (the
ticket hook at `ticket_addr`; no NEW_ACCOUNT surcharge for a value CALL
into it) are listed in the `evm_config_t` comment.

Not covered here (engine-internal / helper headers): `shared/evm/evm_internal.h`,
`shared/evm/evm_u256.h`, `shared/evm/evm_gas.h`.

---

## 2. Precompile start-up check (`shared/evm/evm_precompile.h`)

The precompiled contracts (0x01-0x11) are reached through the interpreter
(`evm_internal.h` `evm_precompile_run`); this header exposes the one check
a node runs before it accepts work. The precompile set is part of the
consensus ruleset (decision `2026-10-04-nodus-evm-kurultay-k1.md`, operator
item 2): a node for which the self-test fails must refuse to start.
Design: `2026-10-04-nodus-evm-engine-design.md`.

| Function | Description |
|----------|-------------|
| `int evm_precompile_selftest(void)` | Known-answer self-test of the precompile set through the interpreter's own dispatch — one known answer per library, `evm_precompile.c` `PC_KATS`: 0x01-0x03, 0x05, 0x06, 0x08-0x0b, 0x0f, 0x11; forces the one-time initialisation of the KZG trusted setup (c-kzg-4844) and mcl (alt_bn128). SHA-256 (blst) and RIPEMD-160 (trezor-crypto) are vendored, pinned code with no initialisation; their vectors still run. Thread-safe, repeatable. `0` every vector matches / `-2` node fault. |
| `int evm_precompile_selftest_report(const char **failed)` | Same, and names the failure. Checks in order: mcl bn254 initialisation (on x86-64 mcl refuses a CPU without AVX + BMI2 + ADX); the KZG trusted setup (loaded eagerly, never first inside block execution); every vector (0x02 SHA-256 and 0x03 RIPEMD-160 included). `*failed` (if non-NULL) receives NULL on success, otherwise a static human-readable name (never freed). `0` / `-2`. |

---

## 3. Node EVM runtime (`nodus/src/witness/nodus_witness_rt_evm.h`)

The EVM domain's runtime (runtime ABI 2): call decoding, execution
through the engine over the node engine's metered reader, the typed-effect
stream, the storage adapter, the SHA3-512 MPT state commitment, the domain
invariant and activation state. Every EVM leg is leg 1 of EXACTLY
`[CORE EVMFUND] + [EVM op]`; CORE pays the fee, locks a deposit into the
CORE reserve or releases a UTXO from it, this runtime moves only the EVM
side. The engine reaches it through the runtime table's function pointers,
with ONE exception — the per-leg trie batch, which `exec_evm_leg` calls by
name under `#ifdef NODUS_EVM_ENABLED`. The domain is resolved only after
the height-activated `EVM_ACTIVE` vote's edge (chain_config param 14,
phase 6b'' of `nodus_witness_v2_apply.c`). Design:
`2026-10-04-nodus-evm-chain-integration-design.md` rev 3 §1-§8, §10, §11, §18.

### 3.1 Descriptor, constants, simulation

| Function | Description |
|----------|-------------|
| `int nodus_rt_evm_runtime_build(nodus_domain_runtime_t *out)` | Fill the EVM runtime entry: domain `DNA_DOMAIN_EVM`, ABI 2, ruleset_version 1, rules {1..5}, no legacy tx types, the shared ML-DSA-87 auth hook (auth_kind 1), exec / prevalidate / adapter / state root / invariant / state_init. `ruleset_hash` DERIVED via `dna_ruleset_desc_hash`, `generation` 0 — the TEST builder; production is the EVM generation's entry in `nodus_witness_runtime.c` with the pinned digest. `0` / `-1`. |
| `int nodus_rt_evm_admit(const nodus_domain_runtime_t *rt, uint8_t tx_type, uint32_t pool_id)` | Legacy-surface hook: the EVM domain owns no legacy tx type — refuses every type (`-1`). |
| `int nodus_rt_evm_tx_cost(const nodus_domain_runtime_t *rt, uint8_t tx_type, uint32_t *cost_out)` | Legacy-surface hook: refuses every type (`-1`). |
| `int nodus_rt_evm_empty_state_root(uint8_t out[64])` | Domain root of the EMPTY state (empty account and ticket tries, zero META) — what `state_init` produces and the `genesis_state_root` a registration commits. No database. `0` / `-1`. |
| `int nodus_rt_evm_ticket_addr(uint8_t out[32])` | The ticket system address `SHA3-512("NDS.EVMWITHDRAW.v1")[0..32]` (the 18 ASCII bytes, no terminator; design §5). `0` / `-1`. |
| `int nodus_rt_evm_simulate(const nodus_domain_runtime_t *rt, struct nodus_witness *w, const nodus_rt_evm_sim_req_t *req, nodus_rt_evm_sim_res_t *res)` | The §18 RPC simulation (`evm_call` / `evm_estimate`): ONE CALL (`to != NULL`) or CREATE through the chain's own execution function over a FRESH overlay and a NON-METERING reader of the committed tables; nothing is written; nonce = the sender's committed nonce, no signature. Keeps the engine's read caps (`NODUS_RT_EVM_READS_BASE`, `NODUS_RT_EVM_MAX_READ_BYTES`) so BUDGET outcomes match. The effect-ceiling failure path is NOT simulated. Caller holds committed state still. `0` (free with `_sim_res_free`) / `-1` outside bounds (gas 0 or over the cap, initcode over EIP-3860, a read budget hit before execution) / `-2` fault. |
| `void nodus_rt_evm_sim_res_free(nodus_rt_evm_sim_res_t *res)` | Free a simulation result (`output`). |

Structs: `nodus_rt_evm_sim_req_t` (`from` 32, `to` 32 or NULL = CREATE,
`value` 32 BE or NULL, `data` / `data_len`, `gas_limit` 1 ..
`NODUS_RT_EVM_TX_GAS_CAP`, `chain_id` 32, `global_height` = tip + 1,
`block_time_s` = the committed tip header seconds, `evm_block_gas_limit`
= param 15 at `global_height`); `nodus_rt_evm_sim_res_t` (`executed`,
`success`, `budget`, `gas_used` = receipt figure, `engine_gas_used`,
`engine_work_gas` = pre-refund gas the §18 budget charges, `output` heap,
`created[32]` / `has_created`, `reads`).

### 3.2 Per-leg trie batch (red-team-1 F6)

Between begin and flush every EVM adapter mutation of `w` writes its rows
at once but applies trie changes to in-memory tries only; flush commits
each touched trie ONCE and writes the new storage / account / tickets
roots inside the caller's transaction (roots equal the per-effect commits
byte for byte). While a batch is open `nodus_rt_evm_state_root` refuses.
One batch at a time per thread; no dry run uses it.

| Function | Description |
|----------|-------------|
| `int nodus_rt_evm_leg_begin(struct nodus_witness *w)` | Open the batch. `0` / `-1` (bad argument, allocation, or a batch still open — the leftover is dropped and the call refused). |
| `int nodus_rt_evm_leg_flush(struct nodus_witness *w)` | Commit every touched trie once and close the batch (closed on failure too; the caller rolls its savepoint back). `0` / `-1` (no batch open for `w`, a failed mutation inside it, a store or trie fault). |
| `void nodus_rt_evm_leg_discard(struct nodus_witness *w)` | Drop the open batch without writing anything; no batch = no-op. |
| `int nodus_rt_evm_leg_open(struct nodus_witness *w)` | `1` when a batch is open for `w` on this thread, else `0`. |

### 3.3 Runtime hooks (referenced by the descriptor)

| Function | Description |
|----------|-------------|
| `int nodus_rt_evm_exec(const nodus_domain_runtime_t *rt, const dna_env_view_t *env, uint16_t leg_index, const nodus_rt_exec_ctx_t *ctx, const nodus_rt_v2_reader_t *reader, nodus_rt_v2_out_t *out)` | The `exec_evm` hook (type `nodus_rt_exec_evm_fn`, `nodus_witness_runtime.h`): runs `nodus_rt_evm_prevalidate` first, then the engine. `0` APPLIED outcome (success or the fixed failure path) / `-1` refused before anything executed / `-2` fault. |
| `int nodus_rt_evm_prevalidate(const nodus_domain_runtime_t *rt, const dna_env_view_t *env, uint16_t leg_index, const nodus_rt_exec_ctx_t *ctx, const nodus_rt_v2_reader_t *reader, nodus_rt_v2_keys_t *keys)` | The `prevalidate_evm` hook (type `nodus_rt_prevalidate_fn`): THE shared pre-validation — call decode, pairing, gas declaration, nonce == committed nonce, value <= balance, intrinsic gas, ticket present — NO VM. CheckTx (new entry and recheck alike) runs only this and takes the conflict keys from `keys` (may be NULL). `0` / `-1` / `-2`. |
| `int nodus_rt_evm_state_root(const nodus_domain_runtime_t *rt, struct nodus_witness *w, uint8_t out[64])` | The EVM domain state root (SHA3-512 MPT, design §6). Refuses (`-1`) while a leg batch is open. |
| `int nodus_rt_evm_invariant(const nodus_domain_runtime_t *rt, struct nodus_witness *w)` | The domain invariant; reads the CORE reserve through `nodus_witness_core_evm_reserve_get` (section 6.3). |
| `int nodus_rt_evm_state_init(const nodus_domain_runtime_t *rt, struct nodus_witness *w, uint64_t activation_global_height)` | Activation state: creates the domain's initial state (the `evm_meta` row is created here, not by the S17 rung). |

**Data items:**

| Item | Description |
|------|-------------|
| `extern const uint32_t NODUS_RT_EVM_RULES[NODUS_RT_EVM_N_RULES]` | The descriptor's rule list {1..5} (`NODUS_RT_EVM_N_RULES` 5) — the ONE array the production table entry and `nodus_rt_evm_runtime_build` share. |
| `extern const struct nodus_domain_adapter NODUS_RT_EVM_ADAPTER` | The EVM storage adapter. |

Constants: adapter / reader op ids `NODUS_RT_EVM_OP_ACCT` 1 (addr32 →
148-byte record), `_SLOT` 2 (addr32‖slot32 → 32 B), `_CODE` 3
(digest64‖chunk u8 → ≤ 8192 B), `_TICKET` 4 (ticket_id64 → 72 B), `_META` 5
(key 0x01 → `NODUS_RT_EVM_META_LEN` = 96 bytes: wei_live[32] ‖ wei_tickets[32]
‖ wei_lost[32], `nodus_witness_rt_evm.c` `meta_encode` / the adapter
table), `_HAS_STORAGE` 6 (read-only);
`NODUS_RT_EVM_ACCT_LEN` 148, `NODUS_RT_EVM_TICKET_LEN` 72,
`NODUS_RT_EVM_META_LEN` 96, `NODUS_RT_EVM_CODE_CHUNK` 8192, `NODUS_RT_EVM_Q`
10000000000 (k1 decision 3), `NODUS_RT_EVM_TICKET_GAS` 25000 (pending the
Faz 3 measurement).

---

## 4. EVM helpers in the always-compiled runtime module (`nodus/src/witness/nodus_witness_runtime.h`)

The ONE call-head decoder and the ONE pairing rule, compiled into every
build (no `NODUS_EVM_ENABLED` needed) so the EVM runtime's decoder, the
CORE EVMFUND hook and the block gas sum of PrepareProposal /
ProcessProposal / FinalizeBlock read the same bytes the same way. The head
IS `dna_evm_head_t` from `shared/dnac/evm_call_wire.h` (`typedef
dna_evm_head_t nodus_rt_evm_head_t;`). Design: integration design §2, §8, §9.

| Function | Description |
|----------|-------------|
| `int nodus_rt_evm_call_head(uint32_t op, const uint8_t *call, size_t len, nodus_rt_evm_head_t *out)` | Decode the fixed head of an EVM call (`dna_evm_call_head`). CALL / CREATE: `ver` and every field up to and including nonce present; bridge ops: EXACT length. `0` / `-1`. |
| `uint8_t nodus_rt_evm_role_for_op(uint32_t evm_op)` | The CORE sibling's role: FEE for CALL / CREATE, DEPOSIT for DEPOSIT, RELEASE for WITHDRAW / REDEEM, `0` otherwise. |
| `int nodus_rt_evm_pair_check(const dna_env_view_t *env)` | THE pairing rule, checked by BOTH runtimes: exactly two legs, leg 0 CORE runtime_op `DNA_CORERULE_EVMFUND` (9), leg 1 EVM, CORE call `ver` = `NODUS_RT_EVMFUND_CALL_VER` and role = `nodus_rt_evm_role_for_op(leg 1's op)` != 0. `0` paired / `-1`. |
| `int nodus_rt_evm_conflict_keys(const dna_env_view_t *env, uint16_t leg, const nodus_rt_auth_verdict_t *verdict, nodus_rt_v2_keys_t *keys)` | The ONE derivation of an EVM leg's mempool conflict keys (dry run full mode, VM-less recheck, the prevalidate hook): `NODUS_RT_EVM_KEY_SENDER_NONCE` (`0x80000010`, sender32 ‖ nonce u64 BE — one pending per sender) for every nonce'd op, `NODUS_RT_EVM_KEY_TICKET` (`0x80000011`) for REDEEM; sender = `signer_fp[0][0..32]` of the VERIFIED verdict. `0` / `-1` (head does not decode, or the verdict is not one signer). |
| `uint64_t nodus_rt_evm_env_block_gas(const dna_env_view_t *env, uint32_t evm_domain)` | One envelope's share of the EVM block gas sum: the DECLARED `gas_limit` for a CALL / CREATE whose head decodes, `NODUS_RT_EVM_BRIDGE_GAS` (21000) for DEPOSIT / WITHDRAW / REDEEM, `0` otherwise. A refused item keeps its share. Pure. |
| `int nodus_runtime_evm_activation_digest(uint64_t *d_out, dna_domain_manifest_t *evm_man_out)` | **`#ifdef NODUS_EVM_ENABLED` only.** The EVM generation's activation digest (what the `EVM_ACTIVE` vote must name, `dnac.h DNAC_CFG_EVM_ACTIVE_D`), re-derived from the compiled generation (SYSTEM / CORE / EVM ruleset hashes, the EVM manifest, the activation spec version, the compiled EVM constants). `evm_man_out` may be NULL. `0` / `-1`. |

Hook typedefs in this header: `nodus_rt_exec_evm_fn`,
`nodus_rt_prevalidate_fn` (signatures as `nodus_rt_evm_exec` /
`nodus_rt_evm_prevalidate` above, `rt` as `const struct
nodus_domain_runtime *`); `nodus_rt_v2_keys_t` (at most
`NODUS_RT_V2_MAX_KEYS` 2 keys of up to `NODUS_RT_V2_KEY_MAX_LEN` 72 bytes).
Limits: `NODUS_RT_EVM_TX_GAS_CAP` 30000000, `NODUS_RT_EVM_BLOCK_GAS_LIMIT`
30000000, `NODUS_RT_EVM_SIM_GAS_PER_HEIGHT` 2 × tx cap,
`NODUS_RT_EVM_READS_BASE`, `NODUS_RT_EVM_MAX_READ_BYTES` 32 MiB.

---

## 5. Call wire codec and envelope builder

### 5.1 `shared/dnac/evm_call_wire.h`

The call bytes of an EVM leg (runtime ops 1-5: CALL, CREATE, DEPOSIT,
WITHDRAW, REDEEM) and of its paired CORE EVMFUND leg (CORE op 9), plus the
canonical receipt (design §7, tag `"NDS.EVMRCPT.v1\0\0"`). ONE codec: the
node's call-head decoder, the EVM runtime's full decode and the CORE
EVMFUND parse all call these functions, and the web wallet and `nodus-cli`
build with them. Pure: no allocation, clock, RNG or nodus header; decoders
BORROW the caller's buffer; every reject returns `-1` and zeroes `*out` /
`*written_out`. Exact byte layouts are in the header block. Design:
integration design rev 3 §2, §7; decisions k1 (1, 3, 4) and k2.

| Function | Description |
|----------|-------------|
| `int dna_evm_access_walk(const uint8_t *body, size_t avail, uint16_t n_access, size_t *used_out, uint64_t *keys_out)` | Walk an access-list body of `n_access` entries (at most `avail` bytes); strict bounds. `used_out` = bytes occupied, `keys_out` = Σ n_keys (either may be NULL). `0` / `-1`. |
| `int dna_evm_access_next(const uint8_t *body, size_t len, size_t *off, const uint8_t **addr_out, uint16_t *n_keys_out, const uint8_t **keys_out)` | ONE cursor step: the entry at `body[*off]` (address, key count, keys or NULL), then `*off` advances. Start at 0; materialising a list is one linear pass (red-team 1 F3). `0` / `-1` (outputs NULL / 0, `*off` unchanged). |
| `int dna_evm_access_put(uint8_t *dst, size_t cap, size_t *off, const uint8_t addr[DNA_EVM_ADDR_LEN], uint16_t n_keys, const uint8_t *keys)` | Append one entry (addr ‖ n_keys u16 ‖ keys) at `dst[*off]`. `0` / `-1` (no room, NULL with keys). |
| `int dna_evm_call_head(uint32_t op, const uint8_t *call, size_t len, dna_evm_head_t *out)` | Decode the FIXED HEAD (op, gas_limit, nonce, amount_raw, value / to / dest_fp / ticket_id pointers, `rest_off`). CALL / CREATE: tail NOT checked (a malformed tail keeps its declared gas in the block gas sum); bridge ops: exact length. `0` / `-1`. |
| `int dna_evm_call_encoded_size(const dna_evm_call_t *c, size_t *out)` | Exact encoded length for `c->op`. `0` / `-1`. |
| `int dna_evm_call_encode(const dna_evm_call_t *c, uint8_t *dst, size_t dst_cap, size_t *written_out)` | Encode; rejects what the decoder rejects (unknown op, malformed access body, CREATE initcode over 49152, a length not fitting u32) and a short `dst_cap`. `written_out` MANDATORY. `0` / `-1`. |
| `int dna_evm_call_decode(uint32_t op, const uint8_t *src, size_t len, dna_evm_call_t *out)` | Strict decode: `ver` first, exact length, trailing bytes reject. `*out` borrows `src`. `0` / `-1`. |
| `uint32_t dna_evmfund_reads(uint8_t role, uint8_t n_in)` | Logical reads of the funding leg: `n_in + 1` (FEE), `n_in + 2` (DEPOSIT / RELEASE: + the CORE EVM reserve); `0` for an unknown role. |
| `uint8_t dna_evmfund_role_for_op(uint32_t op)` | The role the CORE leg must carry beside EVM op `op`; `0` for none. |
| `int dna_evmfund_encoded_size(const dna_evmfund_call_t *c, size_t *out)` | `2 + 1 + 64·n_in + 1 + 232·n_out`. `0` / `-1`. |
| `int dna_evmfund_encode(const dna_evmfund_call_t *c, uint8_t *dst, size_t dst_cap, size_t *written_out)` | Encode the EVMFUND call; rejects a role outside {FEE, DEPOSIT, RELEASE}, `n_in` outside 1..15, non-ascending nullifiers, `n_out` > 16, an output that is not lowercase-hex owner ‖ amount > 0 ‖ zero token. `written_out` MANDATORY. `0` / `-1`. |
| `int dna_evmfund_decode(const uint8_t *src, size_t len, dna_evmfund_call_t *out)` | Strict decode of the same layout; borrows `src`. `0` / `-1`. |
| `int dna_evm_rcpt_decode(const uint8_t *src, size_t len, dna_evm_rcpt_t *out)` | Strict decode of a canonical receipt (tag, status 0/1, bounded lengths, n_topics <= 4, EXACT length). What the node's `evm_receipt` RPC and the clients read a stored receipt with; the node's encoder is `nodus_witness_rt_evm.c rcpt_build`. `0` / `-1`. |
| `int dna_evm_rcpt_log_next(const dna_evm_rcpt_t *r, size_t *cursor, const uint8_t **addr_out, uint8_t *n_topics_out, const uint8_t **topics_out, const uint8_t **data_out, uint32_t *data_len_out)` | One log of a decoded receipt; `*cursor` (start 0) advances past it. `0` / `-1` (no further entry or malformed). |

Types: `dna_evm_call_t`, `dna_evm_head_t`, `dna_evmfund_call_t`,
`dna_evm_rcpt_t`. Constants: `DNA_EVM_CALL_VER` 1, `DNA_EVM_OP_CALL` ..
`DNA_EVM_OP_REDEEM` 1..5, `DNA_EVM_ADDR_LEN` 32, `DNA_EVM_WORD_LEN` 32,
`DNA_EVM_FP_LEN` 64, `DNA_EVM_TICKET_ID_LEN` 64, `DNA_EVM_MAX_INITCODE`
49152, `DNA_EVM_DEPOSIT_CALL_LEN` 17, `DNA_EVM_WITHDRAW_CALL_LEN` 81,
`DNA_EVM_REDEEM_CALL_LEN` 137, `DNA_EVM_Q` 10000000000,
`DNA_EVMFUND_CORE_OP` 9, `DNA_EVMFUND_VER` 1, `DNA_EVMFUND_ROLE_FEE` /
`_DEPOSIT` / `_RELEASE` 1 / 2 / 3, `DNA_EVMFUND_MAX_IN` 15,
`DNA_EVMFUND_MAX_OUT` 16, `DNA_EVMFUND_OUT_LEN` 232, `DNA_EVM_RCPT_TAG_LEN`
16, `DNA_EVM_RCPT_MAX_TOPICS` 4.

### 5.2 `nodus/src/client/nodus_v2_evm.h`

The shared EVM envelope builder: `[CORE EVMFUND] + [EVM op]` priced,
funded, signed and read back, no I/O. Moved out of the web wallet
(`nsw_evm_core` / `nsw_evm_min_units`) so `nodus-cli evm` and the wallet
build byte-identical envelopes from identical inputs (the hedged ML-DSA
signature excepted). Pure: no socket, clock, database or RNG (the change
seed is derived from the input nullifiers). Returns the shared
`nodus_v2_spend_rc_t` values plus `nodus_v2_evm_rc_t` (`-60` ..
`-68`). Design: integration design rev 3 §2, §8, §16, §18; decisions k1
(1, 3, 4), k2 (2), and `2026-09-25-web-wallet-nodus-send-transport.md`.

| Function | Description |
|----------|-------------|
| `int nodus_v2_evm_fund_decl(uint8_t role, uint32_t n_in, uint32_t n_out, uint32_t *effects_out, uint32_t *bytes_out)` | EXACT `(res_max_effects, res_max_effect_bytes)` of the CORE EVMFUND leg for `role`, `n_in` inputs, `n_out` change outputs (formula in the header). `0` / `-1` (unknown role). |
| `int nodus_v2_evm_bridge_decl(uint32_t op, uint32_t *effects_out, uint32_t *bytes_out)` | EXACT declaration of a bridge op's EVM leg: 2 effects; 468 bytes (DEPOSIT / WITHDRAW) or 352 (REDEEM). `0` / `-1` (not a bridge op). |
| `int nodus_v2_evm_min_units(const dna_meter_policy_t *pol, uint32_t core_version, uint32_t op, size_t evm_call_len, uint32_t effects, uint32_t effect_bytes, uint64_t gas_limit, int n_in, int n_out, uint64_t *out, int *meter_status)` | Smallest `res_max_total_units` the node accepts for this SHAPE: static units + (funding + bridge reads) × w_read + (CALL / CREATE) gas_limit × w_gas + FAIL_RESERVE. A function of lengths and declarations only. Returns `NODUS_V2_SPEND_OK` / `_ERR_ARG` / `_ERR_ALLOC` / `_ERR_ENCODE` / `NODUS_V2_EVM_ERR_OP_WEIGHT` / `_ERR_METER` / `_ERR_OVERFLOW`; `meter_status` may be NULL. |
| `int nodus_v2_evm_ref_units(const dna_meter_policy_t *pol, uint32_t core_version, uint32_t op, uint32_t data_len, uint64_t gas_limit, uint64_t *out)` | Minimum of the REFERENCE SHAPE the node's `evm_estimate` prices as `ue` (CALL or CREATE, `data_len` bytes, no access list, default declaration, one input, one change output). A client recovers the read units as `ue − nodus_v2_evm_ref_units(...)`. Returns as `_min_units`. |
| `int nodus_v2_evm_build(const nodus_v2_evm_req_t *req, nodus_v2_evm_built_t *out, nodus_v2_evm_err_t *err)` | Build, sign and self-check ONE envelope, decode it back and refuse unless every decoded field equals the request. Funding: coins ascending by nullifier until lock + fee is covered (lock = amount_raw for DEPOSIT), at most 15; change = ONE native output to the signer, seed `SHA3-512(input nullifiers)[0..32]`. units / fee: fixed point over the funding shape (at most `NODUS_V2_EVM_MAX_PASSES` 8); fee = max(floor, units × gas_price), floor = max(`DNAC_MIN_FEE_RAW`, `NODUS_W_BASE_TX_FEE`). `NODUS_V2_SPEND_OK` or a refusal; `err` may be NULL. |
| `void nodus_v2_evm_built_free(nodus_v2_evm_built_t *b)` | Free a built envelope (`env`). |
| `int nodus_v2_evm_create_address(const uint8_t sender[32], uint64_t nonce, uint8_t out[32])` | CREATE address in the Nodus 32-byte mode: `keccak256(rlp([sender, nonce]))`, all 32 bytes kept (execution-specs@a87891f7 `compute_contract_address` with a 32-byte sender; engine rule `shared/evm/evm_interp.c evm_compute_contract_address`). Lets `nodus-cli` and the wallet check a receipt's `"cr"`. `0` / `-1`. |

Types: `nodus_v2_evm_req_t`, `nodus_v2_evm_built_t`, `nodus_v2_evm_err_t`,
`nodus_v2_evm_rc_t`. Constants: `NODUS_V2_EVM_DEF_EFFECTS` 256,
`NODUS_V2_EVM_DEF_EFFECT_BYTES` 65536, `NODUS_V2_EVM_BRIDGE_READS` 2,
`NODUS_V2_EVM_MAX_PASSES` 8.

---

## 6. Witness storage, receipt index and apply-side helpers

### 6.1 Schema S17 and the log scan (`nodus/src/witness/nodus_witness_v2_schema.h`)

S17 is the live rung: one atomic migration creating, empty, `evm_accounts`,
`evm_slots`, `evm_code`, `evm_code_refs`, `evm_tickets`, `evm_meta` (row
created by `state_init`, not the rung), `v2_evm_reserve` (row `(1, 0)`
written by the rung), `evm_trie_nodes`, and the NODE-LOCAL receipt / log
index `evm_receipts` / `evm_logs` (no root reads them). An S16 version-3
DB is migrated in place at open; version 18+ fails closed. The §18
`evm_logs` cursor scan walks indexes in (global_height, item_index,
log_index) order with an examined-row and gas work bound. Design:
integration design rev 3 §4-§7, §18; red-team 1 F4.

| Function | Description |
|----------|-------------|
| `int nodus_witness_db_migrate_v2s17(nodus_witness_t *w)` | Atomic S17 migration; below 16 runs the S9…S16 chain first, then 16 → 17 with the in-transaction revalidation. `0` migrated or already 17 (idempotent) / `-1` failure with full rollback of the running stage, incl. an unknown user_version (18+). |
| `int nodus_witness_db_migrate_v2s17_ex(nodus_witness_t *w, nodus_v2s17_mig_fail_t fail_at)` | Test variant: deterministic abort inside the 16 → 17 transaction (`V2S17MIG_FAIL_*`). |
| `int nodus_witness_db_ensure_v2s17_indexes(nodus_witness_t *w)` | Create the scan indexes `evm_receipts_by_pos` and `evm_logs_by_addr` on a DB AT S17 when absent (one BEGIN IMMEDIATE, version re-read inside); other versions: nothing. Indexes only — never a table, column, row or user_version change. Called at open after the S17 rung. `0` present / created / not S17; `-1` fault or a same-named index with other key columns. |
| `int nodus_witness_evm_logs_scan(nodus_witness_t *w, const nodus_evm_logs_scan_t *q, nodus_evm_logs_page_t *out)` | The §18 `evm_logs` cursor scan. Each `sqlite3_step` is one examined row; a step runs only within `max_examined` and `gas_cap` (gas = examined × `NODUS_EVM_RPC_GAS_PER_ROW` 2100 + bytes × `NODUS_EVM_RPC_GAS_PER_BYTE` 8). Topic filters compared in C. A scan stopping before `th` returns `truncated = 1` and `next`; resuming skips no match and repeats none. Pure read, no clock; fail-closed on a row outside its shape. `0` (free with `_page_free`) / `-1` (rows freed; `examined` / `gas` still report the work). |
| `void nodus_witness_evm_logs_page_free(nodus_evm_logs_page_t *p)` | Free a scan page's rows. |

| Item | Description |
|------|-------------|
| `extern const char *const nodus_evm_logs_scan_sql[NODUS_EVM_LOGS_SCAN_SQL_N]` | The scan's statement texts (`NODUS_EVM_LOGS_SCAN_SQL_N` 6); index plans pinned by `test_v2_schema.c`. |

Types / constants: `NODUS_V2_SCHEMA_VERSION_S17` 17, `nodus_v2s17_mig_fail_t`,
`nodus_evm_log_pos_t`, `nodus_evm_log_row_t`, `nodus_evm_logs_scan_t`,
`nodus_evm_logs_page_t`, `NODUS_EVM_LOGS_SCAN_MAX_LIM` 1000,
`NODUS_EVM_LOG_POS_MAX` `UINT32_MAX + 1`.

### 6.2 Apply-side EVM functions (`nodus/src/witness/nodus_witness_v2_apply.h`)

The cometbft-lane apply engine's EVM-relevant exports: the CheckTx dry run
with its VM-less mode and the non-mutating conflict probe (red-team 1 F1),
the gas-price rule's price-0 EVM exception (decision
`2026-10-05-nodus-evm-redteam1-operator.md` D1), and the block facts every
node-local EVM simulation reads. Design: integration design rev 3 §3, §4,
§7, §8, §10, §18.

| Function | Description |
|----------|-------------|
| `int nodus_witness_v2_env_dry_run_ex(nodus_witness_t *w, const uint8_t *bytes, size_t len, const nodus_v2_auth_reuse_t *reuse, int novm, nodus_v2_conflict_probe_fn probe, void *probe_ctx, nodus_v2_env_dry_run_t *out, char *reason, size_t reason_size)` | The dry run with its CheckTx mode. `novm` 0 = `nodus_witness_v2_env_dry_run` (an ABI-2 leg EXECUTES probe-only on a fresh overlay); `novm` 1 (CheckTx new entry AND recheck): an ABI-2 leg runs ONLY `prevalidate_evm`, no VM. ABI-2 conflict keys are the SYNTHETIC keys (`nodus_rt_evm_conflict_keys`), never effect rows. `probe` (may be NULL) is called after authorization and before any leg runs; a conflict is `-1` with `NODUS_V2_TX_ERR_EXEC`, a probe failure `-2`. Returns as `nodus_witness_v2_env_dry_run`: `0` would apply / `-1` refused (`out->code`) / `-2` node-local fault. |
| `int nodus_witness_v2_gas_price_at(nodus_witness_t *w, uint64_t height, uint64_t *price_out, char *reason, size_t reason_size)` | Committed `GAS_PRICE_RAW_PER_UNIT` (chain_config param 5) active at `height`, `0` when no row. `0` / `-2` unreadable (fault, reason written). |
| `int nodus_witness_v2_gas_price_judge(const dna_env_view_t *v, uint64_t price, uint32_t *code, char *reason, size_t reason_size)` | PURE. Price 0 → rule off, EXCEPT an envelope with an EVM-domain leg whose op is CALL, CREATE or DEPOSIT is REFUSED (WITHDRAW / REDEEM stay open) — decision D1. Price > 0: every leg SYSTEM → exempt; else refuse when `fee_amount < max(res_max_total_units × price, flat floor)`, u64 overflow = refusal. `0` / `-1` with `*code = NODUS_V2_TX_ERR_FEE`. |
| `int nodus_witness_v2_evm_block_gas_limit(nodus_witness_t *w, uint64_t height, uint64_t *out, char *reason, size_t reason_size)` | EVM block gas limit at `height`: chain_config param 15 (`EVM_BLOCK_GAS_LIMIT`) or `DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT` when no row — the same read the block context uses (unreadable / out-of-range stored value = fault). For the CheckTx max-gas refusal and the §18 simulation. `0` / `-2`. |
| `int nodus_witness_v2_tip_block_time(nodus_witness_t *w, uint64_t tip, uint64_t *out_secs)` | The committed tip block's Comet header seconds — the TIMESTAMP every node-local EVM simulation at tip + 1 sees (CheckTx dry run and §18). ADMISSION ONLY; FinalizeBlock uses the decided block's own time. No clock. `0` / `-1`. |
| `int nodus_witness_v2_evm_blockhash(nodus_witness_t *w, uint64_t height, uint64_t n, nodus_rt_read_res_t *res)` | BLOCKHASH(n) as the block at `height` sees it: window `[height-256, height-1]` from `v2_blocks.block_id[0..32]`, outside it present = 0, a window height without its row = fault. For the §18 simulation. `0` / `-2`. |
| `int nodus_witness_v2_chain_initial_height(nodus_witness_t *w, uint64_t *out)` | The chain's first block height, GENESIS-DERIVED (stored genesis document's `initial_height`, 0 → 1) — the fact `chain_initial_height` the `EVM_ACTIVE` stateful rule reads (red-team 1 F5). Never the oldest stored block. Cached once per open on a gated handle. `0` (`*out >= 1`) / `-2`. |

| Item | Description |
|------|-------------|
| `typedef int (*nodus_v2_conflict_probe_fn)(void *ctx, const nodus_v2_dry_run_row_t *rows, size_t n)` | The mempool's NON-MUTATING pending-conflict probe: is any of the `n` rows already held by ANOTHER pending entry? Only looks; the caller inserts after the whole dry run succeeds. `0` no conflict / `1` conflict / `-2` failure. |
| `nodus_v2_tx_result_t.data_len`, `.data[64]` | ExecTxResult.Data: EMPTY for every item without an applied EVM leg and every refused item (so non-EVM LastResultsHash is byte-identical to before); an applied EVM leg sets the 64-byte SHA3-512 of its canonical receipt (design §7). |
| `nodus_v2_block_t.env_block_pos` (`const size_t *`) | Envelope k's index in the decided block's tx list (red-team 1 F12). NODE-LOCAL: written only into `evm_receipts.item_index`; NULL = the envelope ordinal. |

### 6.3 CORE EVM reserve (`nodus/src/witness/nodus_witness_v2_claims.h`)

The CORE-side read of the reserve bucket that backs every wei inside the
EVM domain (the reserve is CORE state, not EVM state). Design: integration
design rev 3 §5.

| Function | Description |
|----------|-------------|
| `int nodus_witness_core_evm_reserve_get(nodus_witness_t *w, uint64_t *out)` | The CORE EVM RESERVE bucket (`v2_evm_reserve`, S17): raw units locked behind every wei the EVM domain holds. Written only by the EVM generation's CORE EVMFUND; read by the EVM generation's CORE root / invariant and the EVM invariant (`wei_live + wei_tickets + wei_lost == 10^10 × reserve`). `0` / `1` table absent (pre-S17, `*out = 0`) / `-1` fault. |

---

## 7. Client SDK EVM read RPC (`nodus/include/nodus/nodus.h`)

The §18 EVM read RPC. Every answer is ONE node's COMMITTED tip state,
read-only; `"h"` is the committed tip except for receipts and logs (their
INCLUSION height). A node whose EVM domain is not active answers
`NODUS_ERR_NOT_FOUND`; a node too old to know the method answers
`NODUS_ERR_PROTOCOL_ERROR`. Every typed reader is STRICT: every documented
key required and typed, duplicates refused, unknown keys skipped by a
walker that refuses truncation. Node side: `nodus_witness_handlers.c`
"Nodus EVM §18". Design: integration design rev 3 §18.

| Function | Description |
|----------|-------------|
| `int nodus_client_dnac_query_raw(nodus_client_t *client, const char *method, const uint8_t *args, size_t args_len, size_t n_args, uint8_t **reply_out, size_t *reply_len_out)` | The GENERIC §18 call: `method` (any `evm_*` name) with `n_args` pre-encoded CBOR key/value pairs (map ENTRIES, no header). `*reply_out` = heap copy of the reply's `"r"` map (free()). Used by the web wallet's `evmQuery`. `0`; the node's `NODUS_ERR_*`; `NODUS_ERR_TIMEOUT`; `NODUS_ERR_PROTOCOL_ERROR` without an `"r"` map; `-1` on invalid arguments / encode / transport. |
| `int nodus_client_evm_account(nodus_client_t *client, const uint8_t addr[32], nodus_evm_account_t *out)` | `evm_account`: nonce, `balance_wei[32]` BE, `code_hash[32]` (keccak256), `code_size`, `height`. Returns as `_query_raw`. |
| `int nodus_client_evm_code(nodus_client_t *client, const uint8_t addr[32], uint8_t **code_out, size_t *code_len_out, uint64_t *height_out)` | `evm_code`: `*code_out` heap (NULL when no code; free()). |
| `int nodus_client_evm_storage(nodus_client_t *client, const uint8_t addr[32], const uint8_t key[32], uint8_t value_out[32], uint64_t *height_out)` | `evm_storage`: the 32-byte slot value (zero = no row). |
| `int nodus_client_evm_call(nodus_client_t *client, const nodus_evm_call_req_t *req, nodus_evm_call_res_t *out)` | `evm_call`. A call the node refuses before execution comes back as `NODUS_ERR_PROTOCOL_ERROR`, never as `success = 0`. Free with `nodus_evm_call_res_free`. |
| `int nodus_client_evm_estimate(nodus_client_t *client, const nodus_evm_call_req_t *req, nodus_evm_call_res_t *out)` | `evm_estimate`: also fills `gas_limit` (`"ge"`), `units` (`"ue"`, the REFERENCE shape — see `nodus_v2_evm_ref_units`) and `fee` (`"fe"`). |
| `void nodus_evm_call_res_free(nodus_evm_call_res_t *r)` | Free `output`. |
| `int nodus_client_evm_receipt(nodus_client_t *client, const uint8_t intent_id[64], nodus_evm_receipt_t *out)` | `evm_receipt` by intent id; `found = false` when the node answered `{}`. The decoder re-encodes the §7 bytes from the fields and REFUSES a reply whose `"dg"` digest differs. Free with `nodus_evm_receipt_free`. |
| `void nodus_evm_receipt_free(nodus_evm_receipt_t *r)` | Free the receipt's heap members (`output`, `logs`, `tickets`). |
| `int nodus_client_evm_logs(nodus_client_t *client, const nodus_evm_logs_req_t *req, nodus_evm_logs_res_t *out)` | `evm_logs` page. STRICT: `"c"` present exactly when `more` is true; every log inside `[from_height, to_height]`, at or after the request's start, strictly increasing in (h, x, li), before the returned cursor; the cursor inside the range and strictly after the start when the page holds a log. A breach is `NODUS_ERR_PROTOCOL_ERROR`. A page with `more = true` may hold no log. Free with `nodus_evm_logs_free`. |
| `void nodus_evm_logs_free(nodus_evm_logs_res_t *r)` | Free a logs page. |
| `int nodus_client_evm_ticket(nodus_client_t *client, const uint8_t id[64], nodus_evm_ticket_t *out)` | `evm_ticket`: `pending` (`"p"`), `amount_raw` (`"amt"`), `dest_fp[64]` (`"dst"`). |

Structs taken / filled:

| Item | Description |
|------|-------------|
| `nodus_evm_account_t` | `nonce`, `balance_wei[32]`, `code_hash[32]`, `code_size`, `height` (committed tip). |
| `nodus_evm_call_req_t` | `from` (32, EVM sender), `to` (32, NULL = CREATE), `value` (32 BE wei, NULL = none), `data` / `data_len` (`size_t`), `gas` (0 = the node's per-tx gas cap). |
| `nodus_evm_call_res_t` | `success` `"s"`, `output` / `output_len` `"o"` (heap), `gas_used` `"gu"`, `height` `"h"`; `evm_estimate` only: `gas_limit` `"ge"`, `units` `"ue"`, `fee` `"fe"`. |
| `nodus_evm_log_t` | `addr[32]`, `n_topics`, `topics[4][32]`, `data` (heap) / `data_len`; `evm_logs` only (zero inside a receipt): `height` `"h"`, `item` `"x"`, `log_index` `"li"`, `intent_id[64]` `"i"`. |
| `nodus_evm_receipt_t` | `found`, `height`, `item`, `status` (1 / 0), `op` (1..5), `gas_used` (EVM gas), `has_created` / `created[32]`, `output` (heap), `logs` (heap) / `n_logs`, `wei_destroyed[32]`, `tickets` (heap `uint8_t (*)[64]`) / `n_tickets`, `digest[64]`. |
| `nodus_evm_logs_cursor_t` | `{ uint64_t height; uint64_t item; uint64_t log_index; }` — the first (height, item index, log index) the node has not examined yet; `item` / `log_index` may be one past the u32 range (`NODUS_EVM_LOGS_CURSOR_POS_MAX` = `UINT32_MAX + 1`). |
| `nodus_evm_logs_req_t` | `from_height`, `to_height` (`to − from` < `NODUS_EVM_LOGS_MAX_SPAN` 10000), `addr` (32 or NULL), `topic[4]` (32 each or NULL), `limit` 1..`NODUS_EVM_LOGS_MAX_LIMIT` 1000, `cursor` (NULL = start at `(from_height, 0, 0)`; else resume, with the SAME from/to/addr/topics, `from_height <= cursor->height <= to_height`). |
| `nodus_evm_logs_res_t` | `logs` (heap) / `n`, `more`, `has_cursor`, `cursor` (where to resume, valid only when `more`). |
| `nodus_evm_ticket_t` | `pending`, `amount_raw`, `dest_fp[64]`. |

The `dnac_v3` history entry also carries optional EVM facts (`"ri"` /
`"ro"` / `"ev"`; fields `has_evm`, `evm_status`, `evm_gas_used`,
`evm_from`, … `evm_digest`, at most `NODUS_DNAC_V3_EVM_MAX_TICKETS` 32
ticket ids) — documented at `nodus.h` with the history types.
