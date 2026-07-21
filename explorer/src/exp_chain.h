/* exp_chain — DNAC Explorer Nodus chain client wrapper + F4 chain-reset FSM.
 *
 * Read-only wrapper around the Nodus client SDK (nodus/include/nodus/nodus.h)
 * for the explorer's chain-scan path. G1 rule (hard): this module NEVER
 * references a mutating Nodus API (nodus_client_dnac_spend, nodus_client_put,
 * etc.) — read-only DNAC queries only.
 *
 * exp_chain_t owns one ephemeral Dilithium5 identity (generated at open,
 * never persisted) and one nodus_client_t connection to a single server at
 * a time, chosen from a caller-supplied server list. exp_chain_rotate()
 * advances to the next server in the list (wrapping around) on failure;
 * the network query wrappers below (exp_chain_supply/ledger_range/tx/
 * block/utxos) are thin pass-throughs to the matching nodus_client_dnac_*
 * call, guarded by nodus_client_is_ready() and retried once via
 * exp_chain_rotate() on failure before returning an error.
 *
 * F4 chain-reset FSM (exp_reset_fsm_t / exp_reset_fsm_feed): pure logic,
 * no I/O, no globals — safe to unit test without a network. See the
 * exp_reset_fsm_feed doc comment below for the exact CONFIRMED condition.
 */
#ifndef EXP_CHAIN_H
#define EXP_CHAIN_H

#include <stdint.h>

#include "nodus/nodus_types.h"   /* nodus_dnac_*_result_t */

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
 * doesn't parse as "host port" (host <= 63 chars, port <= 65535), more
 * server lines than `max`, or zero server lines found in the file.
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
 * -1 on failure (rotate exhausted) or the nodus_client_dnac_* error code
 * (see nodus/nodus_types.h NODUS_ERR_*) on a failed-but-connected query.
 * Free heap-allocated result fields with the matching
 * nodus_client_free_*_result() (declared in nodus/nodus.h) — unchanged
 * from the underlying Nodus client API, not duplicated here. */

int exp_chain_supply(exp_chain_t *c, nodus_dnac_supply_result_t *out);
int exp_chain_ledger_range(exp_chain_t *c, uint64_t from, uint64_t to, nodus_dnac_range_result_t *out);
int exp_chain_tx(exp_chain_t *c, const uint8_t hash[64], nodus_dnac_tx_result_t *out);
int exp_chain_block(exp_chain_t *c, uint64_t height, nodus_dnac_block_result_t *out);
int exp_chain_utxos(exp_chain_t *c, const char *owner_fp, nodus_dnac_utxo_result_t *out);

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
 * other observation. A real DNAC chain_id (SHA3-512-derived, see
 * nodus_dnac_supply_result_t.chain_id) is vanishingly unlikely to be
 * all-zero, so this sentinel does not collide with real chain state.
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
