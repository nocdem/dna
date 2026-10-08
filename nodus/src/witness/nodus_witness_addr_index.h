/**
 * @file nodus_witness_addr_index.h
 * @brief NODE-LOCAL address history index for the version-3 (cometbft
 *        lane) chain, and the `dnac_addr_history` answer builder.
 *
 * GOVERNING RECORD: docs/plans/decisions/2026-10-01-node-address-history-
 * index.md (rev 2 is authoritative over rev 1). What rev 2 fixes, and how
 * this module implements it:
 *
 *  1. PLACE. Rows are written INSIDE the block's SQL transaction: envelope
 *     rows inside the item's SAVEPOINT right after cmt_item_index
 *     (nodus_witness_v2_apply.c), claim rows inside the claim's SAVEPOINT,
 *     boundary rows (payday payout, graduation release) where those
 *     writers insert their utxo_set rows. A refused item's rows go away
 *     with its SAVEPOINT; a failed block's rows go away with the host's
 *     ROLLBACK. A write failure here is a block FAULT (the node stops) —
 *     rev 2 item 1, which voids rev 1's "does not stop block processing".
 *  2. OUT OF CONSENSUS. No root, digest, vote, validity check or state
 *     derivation reads `addr_history` or `addr_history_mark`. With the
 *     node flag OFF nothing is written at all, so the flag may differ from
 *     node to node without any root moving.
 *  3. NO BACKFILL (operator: "zamanla dolsun"). The tables start empty;
 *     the first height indexed after the flag turns on is kept in the
 *     marker row and answered as `from_height`.
 *  6. RUNG-FREE schema: CREATE ... IF NOT EXISTS on every open
 *     (nodus_witness_addr_index_migrate, called from
 *     nodus_witness_db_migrate_v12 like nodus_chain_config_db_migrate);
 *     no schema version rung, the S16 equality gates are untouched.
 *
 * ── THE TABLES ─────────────────────────────────────────────────────────
 *   addr_history(h, i, seq, owner, kind, amount, token, fee, peer, wire, ts)
 *     PRIMARY KEY (h, i, seq); index (owner, h, i, seq).
 *     h      the global height the row's effect was applied at
 *     i      the ENGINE item position: envelopes in block order
 *            (0 .. n_envs-1), then claims (n_envs + j) — the order of
 *            nodus_v2_block_cmt_t.results. NOT the cometbft tx index the
 *            `dnac_v3_block` query reports (FinalizeBlock splits the
 *            block's txs into envelopes and claims, and a claim that does
 *            not decode never reaches the engine); `wire` is the
 *            cross-reference. Block-boundary rows (payout, release) carry
 *            NODUS_ADDR_INDEX_BOUNDARY_POS.
 *     seq    0.. within (h, i), in the order the writer produced the
 *            rows (a deterministic function of the block and the state)
 *     owner  RAW 64-byte fingerprint (SHA3-512 of a pubkey, or a 64-byte
 *            multisig address) — raw, not the 128-hex text utxo_set
 *            stores, to halve the row
 *     kind   text, one of the NODUS_ADDR_KIND_* strings below, or "name"
 *            / "evm_deposit" (defined in nodus_witness_addr_index.c)
 *     amount u64 (stored int64; > INT64_MAX is refused as a FAULT — the
 *            native exec already bounds every stored amount there)
 *     token  64 bytes, all zero = native
 *     fee    the envelope's fee_amount on the PAYER's first row of the
 *            item, 0 everywhere else
 *     peer   RAW 64-byte counterparty, or NULL
 *     wire   the item's full-wire id (envelope: the preflight wire_id =
 *            v2_tx_index.tx_id; claim: SHA3-512 of its canonical bytes,
 *            the phase-12c claim_hash), or NULL on boundary rows
 *     ts     the block time, unix seconds: nodus_v2_block_t.timestamp =
 *            RequestFinalizeBlock.time.seconds (nodus_witness_cmt_app.c,
 *            "blk->timestamp = (uint64_t)req->time.seconds") — the Comet
 *            header's BFT time, identical on every node. Stamped ONCE per
 *            block by nodus_witness_addr_index_block_close, still inside
 *            the block transaction, because the boundary writers
 *            (nodus_witness_v2_econ.c / nodus_witness_v2_epoch.c) are not
 *            handed the block time. No committed row carries NULL.
 *   addr_history_mark(id = 1, from_height, last_height)
 *     from_height the first height of the CURRENT gap-free indexed run;
 *     last_height the last height indexed. A block whose height is not
 *     last_height + 1 (the flag was off for a while) restarts the run at
 *     that height: from_height never claims completeness across a gap.
 *
 * ── ROW DERIVATION (applied envelope) ──────────────────────────────────
 * Effects come from nodus_rt_native_describe_leg (the exec's own
 * decoders). The SELF set of the envelope is the CORE leg's verified
 * verdict exactly as the native exec builds ownership (rtn_owners_init,
 * nodus_witness_rt_native.c): signer_fp[0..n_signers) ∪ the SATISFIED
 * msig_addr[]. The PAYER is JUDGMENT, not grounded (a verdict does not
 * attribute the fee to one of several owners): the first SATISFIED
 * multisig address of the paying leg if it carries one, else its
 * signer_fp[0]; the paying leg is the CORE leg, or leg 0 when the
 * envelope has none.
 *   CORE, each created coin c, in describe (call) order:
 *     TOKEN_CREATE and c.token != native → (c.owner, token_create,
 *                                  c.amount, c.token, peer = payer unless
 *                                  c.owner == payer)
 *     c.owner in SELF              → no row (change; the UNDELEGATE
 *                                  release coin to its delegator)
 *     otherwise                    → (payer, spend_out, c.amount, c.token,
 *                                  peer = c.owner) then (c.owner,
 *                                  spend_in, c.amount, c.token, peer =
 *                                  payer)
 *   CORE BURN                      → (payer, burn, burn_amount, native)
 *   CORE EVMFUND (Nodus EVM)            → the change outputs by the coin rules
 *                                  above; RELEASE (WITHDRAW / REDEEM): the
 *                                  release coin (the describer's LAST
 *                                  created coin) → (recipient, release,
 *                                  amount, native), even when the
 *                                  recipient is a signer — its value
 *                                  leaves the EVM reserve, not the payer.
 *                                  DEPOSIT: (payer, evm_deposit,
 *                                  reserve_in, native) — the amount the
 *                                  item locks into the EVM reserve
 *                                  (kind defined in the .c beside
 *                                  "name"); with only change outputs it
 *                                  is the payer's first row, so the fee
 *                                  rides on it
 *   EVM leg (domain 2)             → no row (no native coin moves)
 *   SYSTEM STAKE                  → (validator, stake, bond)
 *          DELEGATE / UNDELEGATE   → (delegator, delegate|undelegate,
 *                                  amount, peer = validator)
 *          UNSTAKE                 → (validator, unstake, 0)
 *          VALIDATOR_UPDATE        → (validator, validator_update, 0)
 *          CHAIN_CONFIG            → no row
 *   fee_amount > 0 → carried on the payer's first row; when the payer has
 *                    no row in the item, one (payer, fee, 0, native,
 *                    fee = fee_amount) row.
 * Claim (applied, target domain CORE) → (dest_binding, claim, the amount
 *   v2_claims_spent recorded, native, no peer, wire = claim hash). A claim
 *   to another domain writes no row (its amount is not in native units).
 * Payday → (accrual owner, payout, amount); graduation → (destination,
 *   release, amount) for the bond and for every delegation released.
 *   No sender is invented for claims, payouts or releases.
 *
 * DETERMINISM: every row is a function of the block's bytes, the
 * committed state and the engine's own verdicts; nothing reads a clock
 * (ts is the header's time), nothing iterates an unordered set. It does
 * not matter for consensus — nothing reads these rows back into a root —
 * but two index-enabled nodes answer the same history.
 *
 * @file nodus_witness_addr_index.h
 */

#ifndef NODUS_WITNESS_ADDR_INDEX_H
#define NODUS_WITNESS_ADDR_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"   /* nodus_rt_auth_verdict_t */
#include "dnac/env_preflight.h"              /* dna_env_preflight_t     */
#include "dnac/manifest_wire.h"              /* dna_claim_t             */

#ifdef __cplusplus
extern "C" {
#endif

/** `i` of a block-boundary row (payout, release): not an item. */
#define NODUS_ADDR_INDEX_BOUNDARY_POS  0xFFFFFFFFu

#define NODUS_ADDR_KIND_SPEND_OUT         "spend_out"
#define NODUS_ADDR_KIND_SPEND_IN          "spend_in"
#define NODUS_ADDR_KIND_BURN              "burn"
#define NODUS_ADDR_KIND_TOKEN_CREATE      "token_create"
#define NODUS_ADDR_KIND_CLAIM             "claim"
#define NODUS_ADDR_KIND_STAKE             "stake"
#define NODUS_ADDR_KIND_DELEGATE          "delegate"
#define NODUS_ADDR_KIND_UNDELEGATE        "undelegate"
#define NODUS_ADDR_KIND_UNSTAKE           "unstake"
#define NODUS_ADDR_KIND_VALIDATOR_UPDATE  "validator_update"
#define NODUS_ADDR_KIND_PAYOUT            "payout"
#define NODUS_ADDR_KIND_RELEASE           "release"
#define NODUS_ADDR_KIND_FEE               "fee"

/** true when this node was started with `addr_history_index: true`
 *  (nodus_witness_host_config_t.addr_history_index, filled from
 *  nodus_server_config_t.addr_history_index). A witness with no host
 *  (every engine unit test) is OFF. */
bool nodus_witness_addr_index_enabled(const nodus_witness_t *w);

/**
 * Create the two tables and the owner index if absent. Rung-free,
 * idempotent; aborts the process on a SQL failure, exactly like
 * nodus_chain_config_db_migrate (a database that cannot hold the schema
 * is not one this node may open). Runs on every open whatever the flag.
 * @return 0; -1 on NULL arguments.
 */
int nodus_witness_addr_index_migrate(nodus_witness_t *w);

/**
 * Rows of one APPLIED envelope (derivation: the header). Call inside the
 * item's SAVEPOINT, after the item's execution and identity index
 * succeeded. `auths` is the item's per-leg verdict buffer (indexed by
 * leg). A no-op when the flag is off.
 * @return 0; -1 a FAULT on this node, `reason` written (the
 *         cmt_item_index contract — the caller unwinds and fails the
 *         block).
 */
int nodus_witness_addr_index_env(nodus_witness_t *w, uint64_t height,
                                 uint32_t item_pos,
                                 const dna_env_preflight_t *pf,
                                 const nodus_rt_auth_verdict_t *auths,
                                 char *reason, size_t reason_size);

/**
 * The row of one APPLIED claim. Call inside the claim's SAVEPOINT after
 * claim_execute_one succeeded. `target_domain` is the claim's resolved
 * target; only DNA_DOMAIN_CORE writes a row. A no-op when the flag is off.
 * @return 0; -1 FAULT, `reason` written.
 */
int nodus_witness_addr_index_claim(nodus_witness_t *w, uint64_t height,
                                   uint32_t item_pos, const dna_claim_t *c,
                                   const uint8_t nullifier[64],
                                   uint32_t target_domain,
                                   char *reason, size_t reason_size);

/**
 * One block-boundary row (kind NODUS_ADDR_KIND_PAYOUT or _RELEASE) owned
 * by the 128-lowercase-hex fingerprint `owner_hex` (NOT NUL-terminated,
 * the utxo_set owner form both boundary writers hold). A no-op when the
 * flag is off.
 * @return 0; -2 FAULT (the boundary writers' class), logged.
 */
int nodus_witness_addr_index_boundary(nodus_witness_t *w, uint64_t height,
                                      const char *kind,
                                      const uint8_t *owner_hex,
                                      uint64_t amount);

/**
 * Close the block for the index: stamp `block_time` (unix seconds) on
 * every row of `height`, then advance the marker (first indexed height →
 * insert; last + 1 → extend; a gap → restart the run at `height`; a
 * height already indexed → FAULT). Call once per applied block after
 * every writer (after the epoch boundary). A no-op when the flag is off.
 * @return 0; -1 FAULT, `reason` written.
 */
int nodus_witness_addr_index_block_close(nodus_witness_t *w,
                                         uint64_t height,
                                         uint64_t block_time,
                                         char *reason, size_t reason_size);

/** A `dnac_addr_history` cursor: strictly older than (h, i, q) in the
 *  newest-first order. `before` alone on the wire means (before, 0, 0),
 *  i.e. every row below that height. */
typedef struct {
    uint64_t h;
    uint32_t i;
    uint32_t q;
} nodus_witness_addr_cursor_t;

/**
 * The `dnac_addr_history` answer WITHOUT its send (the handler in
 * nodus_witness_handlers.c decodes the args and sends). The wire is
 * specified once, in include/nodus/nodus.h beside
 * nodus_client_dnac_addr_history.
 *
 * Order of refusals: owner not 128 lowercase hex → PROTOCOL_ERROR;
 * `session_fp` NULL or not the owner (C11, the dnac_history rule) →
 * NOT_AUTHENTICATED; limit outside 1..NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT
 * → PROTOCOL_ERROR; no version-3 chain → NOT_FOUND; any store fault or
 * malformed row → INTERNAL_ERROR (never a partial list).
 *
 * @param session_fp  the authenticated session's raw 64-byte fingerprint,
 *                    NULL when the session is not authenticated
 * @param before      NULL = start at the newest row
 * @param out         heap frame on 0 (free it)
 * @return 0; -1 with *err_code / err_msg set.
 */
int nodus_witness_addr_history_build(nodus_witness_t *w, uint32_t txn_id,
                                     const uint8_t *session_fp,
                                     const char *owner,
                                     const nodus_witness_addr_cursor_t *before,
                                     uint32_t limit,
                                     uint8_t **out, size_t *out_len,
                                     int *err_code, char *err_msg,
                                     size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_ADDR_INDEX_H */
