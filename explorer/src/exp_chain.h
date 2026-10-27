/* exp_chain — DNAC Explorer Nodus chain client wrapper + F4 chain-reset FSM.
 *
 * Read-only wrapper around the Nodus client SDK (nodus/include/nodus/nodus.h)
 * for the explorer's chain-scan path. G1 rule (hard): this module NEVER
 * calls into any mutating / spend-path Nodus client function — read-only
 * DNAC queries only (see explorer/README.md G1 for the exact grep gate).
 *
 * exp_chain_t owns one ephemeral Dilithium5 identity (generated at open,
 * never persisted) and one nodus_client_t connection to a single server at
 * a time, chosen from a caller-supplied server list. exp_chain_rotate()
 * advances to the next server in the list (wrapping around) on failure;
 * the network query wrappers below (exp_chain_tip / exp_chain_v3_page) are
 * thin pass-throughs to the version-3 nodus_client_dnac_* calls, guarded
 * by nodus_client_is_ready() and retried once via exp_chain_rotate() on
 * failure before returning an error; exp_chain_balance tries every server;
 * exp_chain_active_stake makes one attempt on the current connection.
 *
 * One exp_chain_t is used by ONE thread: the sync thread owns the handle
 * main.c opens for it, the HTTP thread owns a second, separate handle
 * (own identity, own connection) for the address balance — the two never
 * share a nodus_client_t.
 *
 * F4 chain-reset FSM (exp_reset_fsm_t / exp_reset_fsm_feed): pure logic,
 * no I/O, no globals — safe to unit test without a network. See the
 * exp_reset_fsm_feed doc comment below for the exact CONFIRMED condition.
 */
#ifndef EXP_CHAIN_H
#define EXP_CHAIN_H

#include <stdint.h>

#include "nodus/nodus.h"         /* nodus_dnac_v3_block_result_t */

#ifdef __cplusplus
extern "C" {
#endif

/* Caller-side cap on the server list handed to exp_chain_config_load /
 * exp_chain_open. Matches NODUS_CLIENT_MAX_SERVERS's order of magnitude but
 * is independent of it: exp_chain connects to ONE server at a time (never
 * feeds more than one entry into nodus_client_config_t.servers), so this
 * bound is purely "how many candidate servers the explorer can rotate
 * through", not a Nodus client-config limit. */
#define EXP_CHAIN_MAX_SERVERS 16

typedef struct {
    char     host[64];
    uint16_t port;
} exp_server_t;

typedef struct exp_chain exp_chain_t;

/* Load a server list from a config file: one "host port" per line,
 * whitespace-separated, blank lines and lines whose first non-whitespace
 * character is '#' are skipped (full-line comments only — no trailing
 * inline comments after a host/port pair).
 *
 * Fails (-1) on: file open failure, a non-blank/non-comment line that
 * doesn't parse as "host port" (host <= 63 chars, 1 <= port <= 65535 —
 * port 0 is rejected, it is never a valid listen port), a line whose
 * (host, port) pair exactly duplicates an earlier line in the same file
 * (fix round 1, G6: one witness listed twice could otherwise satisfy
 * exp_reset_fsm_feed's 2-distinct-server confirmation rule on its own),
 * more server lines than `max`, or zero server lines found in the file.
 * On success, *count_out is the number of entries written to `servers`
 * (servers[0..*count_out) — this is unchanged/partial-content-free: a
 * failing parse does not promise servers[] is left untouched, callers
 * should not use `servers` after a non-zero return).
 *
 * @param path       config file path
 * @param servers    [out] caller-allocated array, capacity `max`
 * @param max        capacity of servers[]
 * @param count_out  [out] number of entries written on success
 * @return 0 on success, -1 on failure
 */
int exp_chain_config_load(const char *path, exp_server_t *servers, int max, int *count_out);

/* Open a chain client: generates an ephemeral Dilithium5 identity (never
 * persisted to disk), then nodus_client_init + nodus_client_connect against
 * servers[0]. *c_out is heap-allocated; the underlying nodus_client_t is
 * also heap-allocated internally (it is a multi-megabyte struct — never
 * stack-allocated, project rule).
 *
 * `servers` is copied into *c_out; the caller's array need not outlive
 * this call. count must be in [1, EXP_CHAIN_MAX_SERVERS].
 *
 * @return 0 on success (*c_out populated), -1 on failure (*c_out left NULL;
 *         bad params, identity generation failure, or all servers[0]
 *         connect attempt failed)
 */
int exp_chain_open(exp_chain_t **c_out, const exp_server_t *servers, int count);

/* Disconnect + release everything (including the ephemeral identity's
 * secret key material). Safe to call with c == NULL. */
void exp_chain_close(exp_chain_t *c);

/* Disconnect from the current server and connect to the next one in the
 * list (wrapping around: (current + 1) % count). Advances
 * exp_chain_current_server()'s return value regardless of whether the new
 * connect attempt succeeds — "next server in list" is a movement, not a
 * conditional one.
 *
 * @return 0 on successful connect to the next server, -1 on failure
 */
int exp_chain_rotate(exp_chain_t *c);

/* Index into the server list this client is currently on (or was last
 * connected to). For the reset FSM's server_index parameter. Returns -1
 * for a NULL client. */
int exp_chain_current_server(const exp_chain_t *c);

/* ── Read-only DNAC query wrappers (G1: read-only only) ──────────────
 * Each: if not ready, rotate once; issue the query; on failure, rotate
 * once more and retry; return the final result code. 0 on success,
 * -1 on failure (rotate exhausted, or a node that is not on a version-3
 * chain) or the nodus_client_dnac_* error code (NODUS_ERR_*) on a
 * failed-but-connected query. */

/* One observation of the server's chain: the 32-byte version-3 chain id
 * (dnac_supply "chain_id32" — the F4 reset FSM's key), the committed tip
 * height (dnac_supply "tip", MAX(v2_blocks.global_height)), the supply
 * figures and the supply buckets (display only — decision
 * docs/plans/decisions/2026-09-30-scan-supply-buckets.md). */
typedef struct {
    uint8_t  chain_id32[32];
    uint64_t tip;
    uint64_t supply_genesis;
    uint64_t supply_burned;
    uint64_t supply_current;
    /* reward_pool / treasury[9] / unclaimed and the "current" of THEIR OWN
     * reply (nodus_client_dnac_supply_buckets) — circulating is computed
     * from this struct alone, never mixed with supply_current above (a
     * different round trip). buckets.has == false: an older node. */
    nodus_dnac_supply_buckets_t buckets;
} exp_chain_tip_t;

/* Four dnac_supply round trips on ONE connection (nodus_client_dnac_supply
 * for the figures, _chain_id32, _supply_tip, _supply_buckets — the SDK
 * reads the additive keys through separate accessors); a failure of any
 * of them rotates and redoes all four on the next server, so one
 * observation never mixes two servers. A reply without "chain_id32" or
 * "tip" (a node not on the version-3 chain) is a failure — a missing tip
 * is never read as 0. A reply without the bucket keys (an older node) is
 * NOT a failure: buckets.has is false and Scan shows the buckets as
 * unknown. */
int exp_chain_tip(exp_chain_t *c, exp_chain_tip_t *out);

/* ── Supply buckets: meta blob + circulating (pure, no I/O) ──────────
 *
 * The buckets are stored in db meta as ONE blob (key
 * EXP_META_SUPPLY_BUCKETS), written on every accepted observation, so
 * /api/stats never shows one server's buckets beside another server's
 * figures and an older node's "no buckets" replaces the last known ones
 * (meta has no delete). Layout, EXP_SUPPLY_BUCKETS_BLOB_LEN bytes:
 *   [0]      has (0 or 1)
 *   [1..]    12 × u64 little-endian: current, reward_pool,
 *            treasury[0..8] (pool 1..9), unclaimed
 * has == 0 stores every u64 as 0. */
#define EXP_META_SUPPLY_BUCKETS     "supply_buckets"
#define EXP_SUPPLY_BUCKETS_BLOB_LEN (1 + 8 * (3 + NODUS_DNAC_TREASURY_POOLS))

void exp_supply_buckets_pack(const nodus_dnac_supply_buckets_t *b,
                             uint8_t out[EXP_SUPPLY_BUCKETS_BLOB_LEN]);

/* @return 0 (*out filled); -1 a wrong length or a flag byte other than
 *         0 / 1 (*out zeroed, has false). */
int exp_supply_buckets_unpack(const uint8_t *buf, size_t len,
                              nodus_dnac_supply_buckets_t *out);

/* circulating = current − reward_pool − Σ treasury − unclaimed (decision
 * 2026-09-30-scan-supply-buckets.md: staked and Foundation coins count).
 * @return 0 (*out set); -1 when b->has is false or a subtraction would
 *         go below zero (never a wrapped number; *out untouched). */
int exp_supply_circulating(const nodus_dnac_supply_buckets_t *b,
                           uint64_t *out);

/* ── Active stake (the /api/tps APY estimate's denominator) ───────────
 *    and the bonded-set staking totals (/api/stats "staking")
 *
 * stake / validators: the stake of the validators the node lists with
 * status ACTIVE (0 — "in the active set of the current epoch",
 * dnac/include/dnac/validator.h), summed as self_stake +
 * external_delegated — the stake voting power is built from (validator.h,
 * external_delegated).
 *
 * bonded_*: the same table over the BONDED rows — status ACTIVE or
 * ELIGIBLE (4). validator.h's status comment: "Both ACTIVE and ELIGIBLE
 * are BONDED states: the self-bond stays locked … both remain candidates
 * for the next boundary's selection". RETIRING (1) and AUTO_RETIRED (3)
 * rows are NOT counted: they have left the set (an UNSTAKE, or Rule N)
 * and their bond and delegations are returned at their graduation
 * boundary (nodus_witness_v2_epoch.c graduate), which then zeroes the
 * row's self_stake / total_delegated and marks it UNSTAKED (2) — an
 * UNSTAKED row holds nothing.
 *   bonded_validators   the number of bonded rows
 *   bonded_self_stake   Σ self_stake (the validators' own bonds)
 *   bonded_delegated    Σ total_delegated — every delegation to the row,
 *                       a validator's self-delegation included
 *                       (validator.h total_delegated; decision
 *                       2026-09-28-treasury-pools-and-exact-self-stake.md
 *                       item 6). The supply invariant counts the same
 *                       field as the delegated bucket.
 *   bonded_delegations  Σ delegator_count — the node's
 *                       COUNT(*) of `delegations` rows per validator, i.e.
 *                       delegation POSITIONS ((delegator, validator)
 *                       pairs; one address delegating to two validators
 *                       is two). Valid only when has_delegations is 1: a
 *                       node that sends no "dlg" for a summed row makes
 *                       it unknown (nodus_types.h: unknown is not 0).
 * The number of DISTINCT delegating addresses is not here: no query the
 * explorer can make answers it (dnac_delegations answers only the
 * caller's own delegations).
 *
 * Read through the node's existing dnac_validator_list_query, one paged
 * read with status filter ACTIVE, then one with ELIGIBLE (an UNSTAKED row
 * is never read). It is an observation of the node's current table (like
 * the supply), not the frozen snapshot the epoch reward is computed from —
 * display only. The pages are separate queries: a boundary that moves a
 * row between ACTIVE and ELIGIBLE during the read can count it in neither
 * or both, until the next observation.
 *
 * Stored in db meta as ONE blob (key EXP_META_ACTIVE_STAKE), rewritten on
 * every accepted tip observation; a failed read stores has = 0, so every
 * figure is absent rather than stale. Layout,
 * EXP_ACTIVE_STAKE_BLOB_LEN bytes:
 *   [0]       has (0 or 1)
 *   [1..24]   3 × u64 little-endian: stake, validators, at_tip
 *   [25]      has_delegations (0 or 1)
 *   [26..57]  4 × u64 little-endian: bonded_validators,
 *             bonded_self_stake, bonded_delegated, bonded_delegations
 * has == 0 stores every other byte as 0. A blob of any other length (the
 * earlier 25-byte layout included) does not unpack — read as unknown. */
#define EXP_META_ACTIVE_STAKE     "active_stake"
#define EXP_ACTIVE_STAKE_BLOB_LEN (1 + 8 * 3 + 1 + 8 * 4)

typedef struct {
    int      has;          /* 0: not read (failure / older source) */
    uint64_t stake;        /* raw units (10^-8 NODUS) */
    uint64_t validators;   /* ACTIVE rows summed */
    uint64_t at_tip;       /* the tip height of the observation it was read with */
    uint64_t bonded_validators;   /* ACTIVE + ELIGIBLE rows */
    uint64_t bonded_self_stake;   /* raw units */
    uint64_t bonded_delegated;    /* raw units */
    int      has_delegations;     /* 1: bonded_delegations is known */
    uint64_t bonded_delegations;  /* delegation positions */
} exp_active_stake_t;

void exp_active_stake_pack(const exp_active_stake_t *s,
                           uint8_t out[EXP_ACTIVE_STAKE_BLOB_LEN]);
/* @return 0 (*out filled); -1 a wrong length or a flag byte other than
 *         0 / 1 (*out zeroed, has 0). */
int exp_active_stake_unpack(const uint8_t *buf, size_t len, exp_active_stake_t *out);

/* Adds one validator-list entry to `acc` (pure; the network read's
 * summation): an ACTIVE row to stake / validators and to the bonded_*
 * figures, an ELIGIBLE row to the bonded_* figures only, any other status
 * to nothing. The caller starts the summation with has_delegations = 1;
 * a bonded row without a delegator count (has_delegator_count 0) clears
 * it, and bonded_delegations stops being summed. @return 0; -1 on a u64
 * overflow (acc then unchanged). */
int exp_active_stake_add(exp_active_stake_t *acc,
                         const nodus_dnac_validator_list_entry_t *e);

/* Read the active stake and the bonded totals on the CURRENT connection —
 * one attempt, no rotation (a failure must not move the sync's server
 * between the tip observation and the height walk). For each status read
 * (ACTIVE, then ELIGIBLE) pages by offset until `total` is reached, at
 * most EXP_ACTIVE_STAKE_MAX_PAGES pages each; any failure fails the whole
 * read. out->has = 1 on success; out->at_tip is left 0 (the caller sets
 * it).
 * @return 0; -1 / the NODUS_ERR_* code on failure (out zeroed). */
#define EXP_ACTIVE_STAKE_MAX_PAGES 64
int exp_chain_active_stake(exp_chain_t *c, exp_active_stake_t *out);

/* One dnac_v3_block page (the node's maximum page budget). Free `out` with
 * nodus_client_free_v3_block_result. Walking a whole block is
 * exp_sync_collect_block's job (exp_sync.h). */
int exp_chain_v3_page(exp_chain_t *c, uint64_t height, uint32_t from_index,
                      nodus_dnac_v3_block_result_t *out);

/* One owner's TRANSPARENT balance per token (dnac_balance — decision
 * docs/plans/decisions/2026-09-28-scan-v3-query.md 3a; wire in nodus.h).
 * Unlike the wrappers above this one tries EVERY configured server before
 * it gives up (the current one if ready, then one rotation per further
 * attempt, `count` attempts in all): a failure answer is shown to the user
 * as "unavailable", so it must mean "no server answered", not "the first
 * one did not". Free `out` with nodus_client_free_balance_result.
 * @return 0; the last attempt's error otherwise (`out` then empty). */
int exp_chain_balance(exp_chain_t *c, const char *owner_hex,
                      nodus_dnac_balance_result_t *out);

/* Nodus EVM P4-C — one EVM account's committed state (§18 evm_account:
 * nonce, balance in wei, code hash, code size, the node's tip) and,
 * optionally, the contract's recent logs (§18 evm_logs over the heights
 * (tip − EXP_EVM_LOGS_WINDOW, tip], at most EXP_EVM_LOGS_LIMIT, ascending
 * (height, item, log) — the node's order). Both reads go to the SAME
 * server so the logs window ends at the tip the account was read at;
 * every configured server is tried (the exp_chain_balance rule). `logs`
 * NULL = the account only. Free `logs` with nodus_evm_logs_free.
 * @return 0; the last attempt's error otherwise (outputs then empty).
 * A node whose EVM domain is not active answers NODUS_ERR_NOT_FOUND —
 * a failure, never an empty account.
 *
 * Red-team 1 F4 — the node's evm_logs is a CURSOR scan: a page that
 * stops early (its 100-log limit, the node's examined-row / byte bounds
 * or its per-block work budget) carries logs->has_cursor. `cursor` NULL =
 * the first page over (tip − EXP_EVM_LOGS_WINDOW, tip]; a cursor resumes
 * at cursor->height over [cursor->height, min(tip, cursor->height +
 * EXP_EVM_LOGS_WINDOW − 1)] — the window follows the cursor, so a cursor
 * from an older page stays valid after the tip moved. A cursor above the
 * tip reads no logs (an empty, complete page). The logs are read for ANY
 * address — no code-size condition: a contract whose constructor logged
 * and returned empty runtime code keeps its logs reachable.
 * *logs_from_out / *logs_to_out: the heights the logs page covers. */
#define EXP_EVM_LOGS_WINDOW 1000u    /* blocks; < NODUS_EVM_LOGS_MAX_SPAN */
#define EXP_EVM_LOGS_LIMIT  100u     /* <= NODUS_EVM_LOGS_MAX_LIMIT */
int exp_chain_evm_account(exp_chain_t *c, const uint8_t addr[32],
                          const nodus_evm_logs_cursor_t *cursor,
                          nodus_evm_account_t *acct,
                          nodus_evm_logs_res_t *logs,
                          uint64_t *logs_from_out, uint64_t *logs_to_out);

/* ── F4 chain-reset FSM ──────────────────────────────────────────────
 *
 * Pure logic, no I/O, no globals. Detects a chain reset (witness set
 * restarted the chain / genesis changed) from repeated, cross-server
 * observations of a chain_id that disagrees with the reference.
 *
 * Zero-initialize exp_reset_fsm_t before the first feed (calloc/`= {0}`).
 * ref_chain_id doubles as its own "is the reference established yet?"
 * flag: an all-zero ref_chain_id is treated as unset, so the FIRST feed
 * call either (a) adopts chain_id as the reference if the caller left
 * ref_chain_id zeroed, or (b) is compared against a caller-preseeded
 * reference (e.g. loaded from db meta before the first feed) like any
 * other observation. The FSM is fed the version-3 32-byte chain id
 * (exp_chain_tip_t.chain_id32, dnac_supply "chain_id32"), never the legacy
 * dnac_supply "chain_id" key; a real chain id (hash-derived) is vanishingly
 * unlikely to be all-zero, so this sentinel does not collide with real
 * chain state.
 *
 * Semantics:
 *   - chain_id == ref_chain_id (match): resets FSM tracking state fully
 *     (cand_set=0, servers_seen={-1,-1}, polls_seen=0) and returns
 *     EXP_RESET_NO. ref_chain_id itself is NOT touched by a match.
 *   - chain_id != ref_chain_id (mismatch), and it's a NEW candidate
 *     (cand_set==0, or cand_set==1 but chain_id != cand): tracking
 *     restarts against this new candidate (cand=chain_id, cand_set=1,
 *     servers_seen={server_index,-1}, polls_seen=1) and returns
 *     EXP_RESET_PENDING.
 *   - chain_id != ref_chain_id, and it matches the currently tracked
 *     candidate: polls_seen += 1; server_index is added to servers_seen
 *     if not already present and a slot is free (servers_seen only needs
 *     to track up to 2 distinct servers — that's the confirmation
 *     threshold). Returns EXP_RESET_CONFIRMED once polls_seen >= 2 AND
 *     at least 2 distinct server indices have been recorded (i.e. the
 *     candidate was seen from >=2 distinct servers across >=2 feed
 *     calls); otherwise EXP_RESET_PENDING.
 *
 * "Poll" == one exp_reset_fsm_feed() call — there is no separate poll
 * counter parameter; each feed call is one observation from one server.
 *
 * server_index < 0 (fix round 1): -1 is the "empty slot" sentinel used
 * internally by servers_seen[] (and exp_chain_current_server()'s NULL-client
 * return value) — feeding a negative index into the tracking paths above
 * would collide with that sentinel and corrupt the distinct-server count.
 * A negative server_index is therefore a no-op: it does not mutate any FSM
 * field and simply returns the FSM's current status (NO if no candidate is
 * tracked, else PENDING/CONFIRMED per the existing servers_seen/polls_seen
 * state).
 */

#define EXP_RESET_NO         0
#define EXP_RESET_PENDING    1
#define EXP_RESET_CONFIRMED  2

typedef struct {
    uint8_t ref_chain_id[32];
    uint8_t cand[32];
    int     cand_set;
    int     servers_seen[2];   /* -1 = empty slot */
    int     polls_seen;
} exp_reset_fsm_t;

int exp_reset_fsm_feed(exp_reset_fsm_t *f, const uint8_t chain_id[32], int server_index);

#ifdef __cplusplus
}
#endif

#endif /* EXP_CHAIN_H */
