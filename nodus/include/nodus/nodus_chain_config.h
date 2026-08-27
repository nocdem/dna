/**
 * @file nodus_chain_config.h
 * @brief Hard-Fork v1 — witness-side chain_config support
 *
 * See `dnac/docs/plans/2026-04-19-hard-fork-mechanism-design.md`.
 *
 * Public API for:
 *   - Active-override lookup (consumed by finalize_block in Stage D)
 *   - chain_config_root merkle tree construction
 *   - chain_config_tx apply logic (called from apply_tx_to_state)
 *   - DB schema migration (CREATE TABLE chain_config_history)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_CHAIN_CONFIG_H
#define NODUS_CHAIN_CONFIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward decl — avoids a witness header dependency in this API. */
typedef struct nodus_witness nodus_witness_t;

/* ============================================================================
 * DB Schema
 *
 * CREATE TABLE chain_config_history (
 *     param_id          INTEGER NOT NULL,
 *     new_value         INTEGER NOT NULL,
 *     effective_block   INTEGER NOT NULL,
 *     commit_block      INTEGER NOT NULL,
 *     tx_hash           BLOB    NOT NULL,    -- 64 bytes
 *     proposal_nonce    INTEGER NOT NULL,
 *     created_at_unix   INTEGER NOT NULL,
 *     PRIMARY KEY (param_id, effective_block)
 * );
 *
 * CREATE INDEX idx_chain_config_active
 *     ON chain_config_history (param_id, effective_block);
 * ========================================================================== */

/* ============================================================================
 * RESERVED param_id BAND — GENESIS ECONOMICS (O15J Faz 2 Block 2C)
 *
 * ids 1..DNAC_CFG_PARAM_MAX_ID are the GOVERNANCE space: a committee can
 * vote them. The band below is the opposite — values written ONCE, by the
 * pure-V2 genesis builder, that no vote may ever change.
 *
 * WHY THIS TABLE. These parameters must be (a) readable by the runtime,
 * (b) committed into a state root, and (c) carried to a joiner.
 * chain_config_history is the only store in the tree that is all three:
 * nodus_chain_config_compute_root scans it WITHOUT a param_id filter and
 * its root is a SYSTEM leg (nodus_witness_roots_v2.c:266, :285), and
 * nodus_witness_v2_bundle.c:47 replicates it to joiners.
 *
 * WHY GOVERNANCE CANNOT REACH IT. nodus_chain_config_scalar_rules rejects
 * every id outside 1..CC_PARAM_MAX_ID and its switch has no case for these
 * (nodus_witness_chain_config.c:497, :515-516), so no CHAIN_CONFIG tx can
 * insert or replace a band row on either lane. That preserves the property
 * nodus_witness_emission.h states: a committee vote cannot alter the
 * emission schedule.
 *
 * WHY 200+. The band must never collide with a future
 * DNAC_CFG_* allocation, which grows upward from 1 (currently 4). Starting
 * at 200 leaves 195 free governance ids; a future allocation that reaches
 * this band collides with THIS COMMENT rather than silently overwriting a
 * committed economic parameter. The ids fit uint8_t, which is what the
 * merkle leaf preimage stores (nodus_witness_chain_config.c:387).
 *
 * NOT cached: cc_cache_warm_from_db skips every id >= CC_PARAM_SLOTS
 * (nodus_witness_chain_config.c:195) and nodus_chain_config_get_u64
 * returns default_value for them (:245). Band rows are therefore read by
 * their own loader, nodus_witness_v2_econ_params_load.
 * ========================================================================== */

/** Halving period in blocks — the committed DNAC_BLOCKS_PER_YEAR. */
#define NODUS_CC_ECON_BLOCKS_PER_YEAR   200u
/** Raw base units per 1 DNAC — the committed DNAC_DECIMAL_UNIT. */
#define NODUS_CC_ECON_DECIMAL_UNIT      201u
/** Blocks per epoch — the committed DNAC_EPOCH_LENGTH. */
#define NODUS_CC_ECON_EPOCH_LENGTH      202u

/** Inclusive band bounds, for range assertions. */
#define NODUS_CC_ECON_PARAM_MIN         NODUS_CC_ECON_BLOCKS_PER_YEAR
#define NODUS_CC_ECON_PARAM_MAX         NODUS_CC_ECON_EPOCH_LENGTH

/** Every band row is committed at genesis, so its effective_block is 0. */
#define NODUS_CC_ECON_EFFECTIVE_BLOCK   0ULL

/**
 * Idempotent CREATE TABLE migration. Uses IF NOT EXISTS so a second run on
 * an already-migrated DB is a no-op (CC-OPS-001 mitigation). Aborts on
 * genuine SQLite failures with the pinned `MIGRATION FAILURE` log literal
 * so the cluster's log-tripwire fires.
 *
 * @param w  Witness context (w->db must be open).
 * @return 0 on success, -1 on null arg. abort() on SQL failure.
 */
int nodus_chain_config_db_migrate(nodus_witness_t *w);

/* ============================================================================
 * Active-Override Lookup
 * ========================================================================== */

/**
 * Return the currently-active value for `param_id` at `current_block`.
 * Monotonic "latest effective_block wins" lookup — matches the canonical
 * SQL query in design §5.9.
 *
 * If no row exists for `param_id` with `effective_block <= current_block`,
 * returns `default_value`.
 *
 * Consumer sites (Stage D):
 *   - inflation gate: chain_config_get(INFLATION_START_BLOCK, h, 1) then
 *     nodus_emission_per_block(h) (nodus_witness_emission.h)
 *   - max batch size clamp: chain_config_get(MAX_TXS_PER_BLOCK, h, default)
 *   - proposer timer: chain_config_get(BLOCK_INTERVAL_SEC, h, default)
 *
 * @param w              Witness context (w->db must be open).
 * @param param_id       dnac_chain_config_param_id_t value
 *                       (1..DNAC_CFG_PARAM_MAX_ID; 4 = TARGET_ACTIVE_COUNT
 *                       since Ledger V2 S3). Out-of-range ids return
 *                       default_value.
 * @param current_block  Chain height at which to evaluate the override.
 * @param default_value  Returned if no active override exists.
 * @return Active value on success; default_value on no-row / null args.
 */
uint64_t nodus_chain_config_get_u64(nodus_witness_t *w,
                                     uint8_t param_id,
                                     uint64_t current_block,
                                     uint64_t default_value);

/* ============================================================================
 * Merkle Root (state_root contributor)
 * ========================================================================== */

/**
 * Build the `chain_config_root` from `chain_config_history` rows.
 *
 * Leaves are built from:
 *     SHA3-512( param_id(1) || new_value_BE(8) || effective_block_BE(8)
 *               || commit_block_BE(8) || proposal_nonce_BE(8) )
 *
 * Rows sorted by (effective_block ASC, param_id ASC, commit_block ASC,
 * proposal_nonce ASC) — deterministic across all 7 witnesses. An empty
 * table returns `nodus_merkle_empty_root(NODUS_TREE_TAG_CHAIN_CONFIG)`
 * (CC-AUDIT-003 mitigation: tagged empty sentinel, NOT 64 zeros).
 *
 * @param w        Witness context (w->db must be open).
 * @param out_root [out] 64-byte merkle root.
 * @return 0 on success, -1 on null args / SQL error.
 */
int nodus_chain_config_compute_root(nodus_witness_t *w, uint8_t out_root[64]);

/* ============================================================================
 * chain_config_tx Apply (called from apply_tx_to_state)
 * ========================================================================== */

/**
 * Apply a DNAC_TX_CHAIN_CONFIG transaction.
 *
 * Runs the full witness-side consensus rule set (design §6.4):
 *   1. Parse TX body + appended chain_config fields.
 *   2. Re-verify local rules via dnac_tx_verify_chain_config_rules.
 *   3. Freshness: commit_block <= valid_before_block (Rule CC-G).
 *   4. Grace: effective_block >= commit_block + grace_period_for_param
 *      (Rule CC-C). Ergonomic params (MAX_TXS) use
 *      DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS (1 hour); safety-critical
 *      params (BLOCK_INTERVAL_SEC, INFLATION_START_BLOCK, and — since
 *      Ledger V2 S3 — TARGET_ACTIVE_COUNT) use
 *      DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS (24 hours).
 *   5. Committee membership + quorum (Rule CC-F). The committee governing
 *      commit_block - 1 is read from chain state; its SIZE is whatever the
 *      snapshot returns, never a compile-time constant. Two bounds:
 *        (a) committee_sig_count <= committee_count — a proposal cannot
 *            carry more votes than that committee has seats;
 *        (b) verified >= dna_bft_quorum(committee_count).
 *      At the DNA chain's 7 seats dna_bft_quorum(7) == 5, so this is
 *      exactly the historical 5-of-7 rule.
 *   6. Signature verify: each committee_votes[i].signature valid against
 *      that witness's Dilithium5 pubkey over the proposal preimage.
 *   7. Monotonicity (Q5 mitigation): once INFLATION_START_BLOCK has been
 *      set non-zero, reject new_value == 0 or new_value > current_block.
 *   8. INSERT row into chain_config_history (PK conflict = replay reject).
 *
 * Called from apply_tx_to_state in nodus_witness_bft.c. On any rule
 * violation, returns -1 and the enclosing DB transaction will be rolled
 * back by the caller.
 *
 * @param w            Witness context.
 * @param tx_data      Serialized TX bytes (dnac_tx_serialize output).
 * @param tx_len       Byte length of tx_data.
 * @param block_height Block being finalized (commit_block for this TX).
 * @return 0 on success, -1 on any rule failure.
 */
int nodus_chain_config_apply(nodus_witness_t *w,
                              const uint8_t *tx_data,
                              uint32_t tx_len,
                              uint64_t block_height,
                              uint64_t block_timestamp);

/* ============================================================================
 * Vote primitives (Stage C — pure functions used by CLI + RPC handlers)
 * ========================================================================== */

/** Size constants mirror dnac.h — kept local so the nodus standalone build
 *  does not need libdna. Verified against dnac constants in test. */
#define NODUS_CC_PUBKEY_SIZE     2592  /* Dilithium5 pubkey */
#define NODUS_CC_SECKEY_SIZE     4896  /* Dilithium5 secret key */
#define NODUS_CC_SIG_SIZE        4627  /* Dilithium5 signature */
#define NODUS_CC_DIGEST_SIZE     64    /* SHA3-512 proposal digest */
#define NODUS_CC_WITNESS_ID_SIZE 32    /* first 32B of SHA3-512(pubkey) */

/**
 * The SCALAR half of the CHAIN_CONFIG local rules: param allowlist,
 * per-param value bounds, and the signing/validity window shape
 * (signed_at != 0; valid_before > effective; valid_before > signed_at).
 * Pure function — the ONE authority both the legacy apply path
 * (verify_cc_local_rules) and the Ledger V2 native SYSTEM runtime
 * consume, so the rule set cannot fork between lanes. Vote-shape rules
 * (sig-count window, distinct witness_ids) and the quorum decision are
 * deliberately NOT here — they need the committee context.
 * @return 0 legal / -1.
 */
int nodus_chain_config_scalar_rules(uint8_t param_id, uint64_t new_value,
                                    uint64_t signed_at_block,
                                    uint64_t valid_before_block,
                                    uint64_t effective_block_height);

/**
 * Per-param grace minimum in blocks (Q4 Option B tiers): the earliest
 * legal effective_block_height for a proposal committed at height H is
 * H + nodus_chain_config_grace_for_param(param_id). Pure function,
 * exported for the same single-authority reason.
 */
uint64_t nodus_chain_config_grace_for_param(uint8_t param_id);

/**
 * Compute the proposal-preimage digest that committee members sign.
 *
 *   digest = SHA3-512( DNAC_CHAIN_CONFIG_PURPOSE_TAG(16) || chain_id(32) ||
 *                      param_id(1) || new_value_BE(8) ||
 *                      effective_block_height_BE(8) || proposal_nonce_BE(8) ||
 *                      signed_at_block_BE(8) || valid_before_block_BE(8) )
 *
 * All multi-byte integers are big-endian (CC-AUDIT-007). Pure function.
 *
 * @return 0 on success, -1 on null args or OpenSSL failure.
 */
int nodus_chain_config_compute_digest(const uint8_t chain_id[32],
                                       uint8_t  param_id,
                                       uint64_t new_value,
                                       uint64_t effective_block_height,
                                       uint64_t proposal_nonce,
                                       uint64_t signed_at_block,
                                       uint64_t valid_before_block,
                                       uint8_t  out_digest[NODUS_CC_DIGEST_SIZE]);

/**
 * Sign a proposal digest with a committee member's Dilithium5 secret key.
 * Populates out_witness_id = first 32B of SHA3-512(pubkey). Pure function —
 * takes raw key material so it can be called from a CLI tool, RPC handler,
 * or test scaffold without needing a live witness context.
 *
 * @return 0 on success, -1 on null args or sign failure.
 */
int nodus_chain_config_sign_vote(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                  const uint8_t seckey[NODUS_CC_SECKEY_SIZE],
                                  const uint8_t digest[NODUS_CC_DIGEST_SIZE],
                                  uint8_t out_witness_id[NODUS_CC_WITNESS_ID_SIZE],
                                  uint8_t out_signature[NODUS_CC_SIG_SIZE]);

/**
 * Verify a vote signature against a committee member's Dilithium5 pubkey.
 * Pure function. Returns 0 on valid signature, -1 on mismatch or null args.
 */
int nodus_chain_config_verify_vote(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                    const uint8_t digest[NODUS_CC_DIGEST_SIZE],
                                    const uint8_t signature[NODUS_CC_SIG_SIZE]);

/**
 * Derive a witness_id from a Dilithium5 pubkey — first 32 bytes of
 * SHA3-512(pubkey). Matches the on-wire witness_id in
 * dnac_chain_config_vote_t. Pure function.
 *
 * @return 0 on success, -1 on null args or OpenSSL failure.
 */
int nodus_chain_config_derive_witness_id(const uint8_t pubkey[NODUS_CC_PUBKEY_SIZE],
                                          uint8_t out_witness_id[NODUS_CC_WITNESS_ID_SIZE]);

/**
 * Log a single-line summary of chain_config observability counters
 * (Q17 / CC-OPS-005). Call from any periodic tick (e.g., per epoch,
 * per heartbeat) or on-demand via a signal handler. Framework-agnostic
 * — produces a structured log line that downstream grafana/prometheus
 * scrapers can parse if needed. Safe to call at any time.
 */
void nodus_chain_config_log_stats(nodus_witness_t *w);

/* Forward decl — full definitions in nodus_tier3.h / nodus_tcp.h;
 * callers that actually invoke nodus_witness_handle_cc_vote_req must
 * include those headers too (this avoids a deep include-chain for
 * chain_config consumers that only need the primitive API above). */
struct nodus_t3_msg_t_tag;  /* nodus_t3_msg_t is an anonymous-struct typedef */
struct nodus_tcp_conn;

/**
 * Handle an incoming w_cc_vote_req (Stage C.2). Peer-side of the
 * committee vote-collect RPC: proposer sends a proposal, this handler
 * runs local-rule checks, signs the proposal digest with the local
 * Dilithium5 key, and replies with a w_cc_vote_rsp carrying
 * (witness_id, signature). Rejection returns a reason string.
 *
 * msg is declared `const void *` to avoid a circular include with
 * nodus_tier3.h; callers pass `&nodus_t3_msg_t_instance`.
 */
int nodus_witness_handle_cc_vote_req(nodus_witness_t *w,
                                      struct nodus_tcp_conn *conn,
                                      const void *msg);

/* ============================================================================
 * Stage C.3 — per-proposer rate-limit on w_cc_vote_req (CC-OPS-003 / Q15)
 *
 * Prevents a hostile or buggy committee peer from amplifying load by
 * spamming w_cc_vote_req. Per-sender cooldown of NODUS_CC_RATE_LIMIT_
 * WINDOW_MS milliseconds between accepted requests.
 *
 * Scope note: the design doc (§Q15) calls for BOTH a 5s timeout AND
 * "1 in-flight per epoch". Only the 5s cooldown is implemented here —
 * the per-epoch hard cap is implicitly covered by the existing
 * (param_id, effective_block) PRIMARY KEY replay rejection in
 * chain_config_apply, which no duplicate proposal can bypass even if a
 * proposer floods the network within one epoch.
 *
 * In-memory only (by design — a persisted table would have to flush on
 * every accepted request and restarts can reset the counter safely).
 * ========================================================================== */

#define NODUS_CC_RATE_LIMIT_WINDOW_MS        5000u
/* One slot per potentially-active validator (S3: was 7 = the initial seat
 * count). Sized to DNA_MAX_ACTIVE_VALIDATORS so a committee larger than the
 * bootstrap 7 cannot force LRU eviction between legitimate proposers. Kept
 * as a literal — this header is deliberately free of shared/ and dnac/
 * includes so libnodus builds standalone; the value is pinned against
 * DNA_MAX_ACTIVE_VALIDATORS by a _Static_assert in
 * nodus_witness_chain_config.c, alongside the other CC_* mirror pins. */
#define NODUS_CC_RATE_LIMIT_MAX_PROPOSERS    128u

/** One tracked proposer. `in_use` false = free slot. */
typedef struct {
    uint8_t   witness_id[NODUS_CC_WITNESS_ID_SIZE];
    uint64_t  last_accepted_ms;
    bool      in_use;
} nodus_cc_rate_limit_slot_t;

/** Per-witness state — embed one copy in nodus_witness_t. */
typedef struct {
    nodus_cc_rate_limit_slot_t slots[NODUS_CC_RATE_LIMIT_MAX_PROPOSERS];
    uint64_t                    rate_limited_count;  /* lifetime total */
} nodus_cc_rate_limit_table_t;

/**
 * Decide whether to accept a new w_cc_vote_req from `sender_id` at `now_ms`.
 *
 * Side-effect-free: no slot mutation. Call nodus_cc_rate_limit_record() on
 * the accept path AFTER all other validation passes, so rejected-by-rule
 * requests do not starve future valid requests from the same sender.
 *
 * @param t              Table (must be zero-initialized before first use).
 * @param sender_id      Proposer witness_id (first 32B of SHA3-512(pk)).
 * @param now_ms         Current monotonic wall clock (nodus_time_now_ms()).
 * @param elapsed_ms_out (optional) When rate-limited, populated with ms
 *                       since last accepted request from this sender.
 *                       Not touched on accept.
 *
 * @return  0 — allow (no cooldown hit)
 *         -1 — rate-limited (reject with cooldown message)
 */
int nodus_cc_rate_limit_check(nodus_cc_rate_limit_table_t *t,
                               const uint8_t sender_id[NODUS_CC_WITNESS_ID_SIZE],
                               uint64_t now_ms,
                               uint64_t *elapsed_ms_out);

/**
 * Record an accepted w_cc_vote_req. Upserts into an existing slot if
 * `sender_id` is already tracked, else claims the first free slot, else
 * evicts the oldest entry (LRU) — the table is sized to the maximum active
 * validator set, so eviction only happens if a non-committee witness_id
 * somehow slips through, in which case the oldest legitimate entry is
 * preserved.
 *
 * The rate_limited_count counter is NOT touched here — only on reject.
 */
void nodus_cc_rate_limit_record(nodus_cc_rate_limit_table_t *t,
                                 const uint8_t sender_id[NODUS_CC_WITNESS_ID_SIZE],
                                 uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHAIN_CONFIG_H */
