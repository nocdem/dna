/* exp_chain — DNAC Explorer Nodus chain client wrapper + F4 reset FSM.
 *
 * See exp_chain.h for the full contract. This file has two independent
 * halves:
 *   - Network wrappers (exp_chain_open/close/rotate/current_server +
 *     exp_chain_tip / exp_chain_v3_page / exp_chain_balance): thin
 *     pass-throughs to the Nodus
 *     client SDK. Not unit-tested here (no network in tests) — the sync
 *     logic above them is tested through exp_sync_source_t fakes.
 *   - exp_reset_fsm_feed: pure logic, unit-tested directly.
 */

#include "exp_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodus/nodus.h"
#include "dnac/validator.h"            /* DNAC_VALIDATOR_ACTIVE, DNAC_MAX_VALIDATORS (dnac.h) */
#include "crypto/nodus_identity.h"

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_CHAIN"

struct exp_chain {
    exp_server_t     servers[EXP_CHAIN_MAX_SERVERS];
    int              count;
    int              current;
    nodus_identity_t identity;
    nodus_client_t  *nc;      /* heap-allocated — multi-MB struct, never stack */
    int              nc_live; /* 1 iff c->nc currently holds a successfully
                                * nodus_client_init()'d struct (mutexes live,
                                * tcp allocated) that MUST go through
                                * nodus_client_close() before reuse/free.
                                * 0 both before the first init and after any
                                * close — a client that failed init (or was
                                * already closed) is never passed to close()
                                * again (fix round 1: destroyed-mutex reuse). */
};

/* Tear down (if connected) and (re)connect to servers[idx]. Always updates
 * c->current to idx, even on failure — "next server in list" is a movement,
 * matching exp_chain_rotate's documented contract.
 *
 * Fix round 1: on a connect-stage failure (init succeeded, connect failed)
 * this function closes c->nc itself before returning -1 — it's the only
 * place that knows init succeeded, so it's the only place that can safely
 * decide a close is owed. Every caller can then uniformly just free(c->nc)
 * without worrying about which stage failed; c->nc_live tracks whether a
 * close is still owed so a second nodus_client_close() is never issued on
 * an already-closed or never-initialized client (destroyed mutexes). */
static int chain_connect(exp_chain_t *c, int idx) {
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    strncpy(cfg.servers[0].ip, c->servers[idx].host, sizeof(cfg.servers[0].ip) - 1);
    cfg.servers[0].port = c->servers[idx].port;
    cfg.server_count = 1;
    /* auto_reconnect left false (zeroed) — exp_chain drives rotation
     * itself via exp_chain_rotate; a second, Nodus-internal reconnect
     * loop racing against that would be undiagnosable non-determinism. */

    c->current = idx;

    if (nodus_client_init(c->nc, &cfg, &c->identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "nodus_client_init failed for %s:%u",
                       c->servers[idx].host, (unsigned)c->servers[idx].port);
        return -1;
    }
    c->nc_live = 1;

    if (nodus_client_connect(c->nc) != 0) {
        QGP_LOG_WARN(LOG_TAG, "connect failed for %s:%u",
                      c->servers[idx].host, (unsigned)c->servers[idx].port);
        nodus_client_close(c->nc);
        c->nc_live = 0;
        return -1;
    }

    return 0;
}

int exp_chain_config_load(const char *path, exp_server_t *servers, int max, int *count_out) {
    if (!path || !servers || max <= 0 || !count_out) return -1;

    FILE *f = fopen(path, "r");
    if (!f) {
        QGP_LOG_ERROR(LOG_TAG, "config_load: cannot open %s", path);
        return -1;
    }

    int count = 0;
    int rc = 0;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '#') continue;

        char host[64];
        unsigned int port = 0;
        if (sscanf(p, "%63s %u", host, &port) != 2 || port == 0 || port > 65535) {
            QGP_LOG_ERROR(LOG_TAG, "config_load: malformed line in %s", path);
            rc = -1;
            break;
        }
        if (count >= max) {
            QGP_LOG_ERROR(LOG_TAG, "config_load: %s has more than %d servers", path, max);
            rc = -1;
            break;
        }

        /* G6 (promoted): reject an exact duplicate (host, port) pair —
         * otherwise one malicious/misconfigured witness listed twice would
         * let a single server satisfy exp_reset_fsm_feed's 2-distinct-
         * server-index confirmation rule on its own. O(n^2) over already-
         * parsed entries is fine — server lists are capped at `max`
         * (EXP_CHAIN_MAX_SERVERS, currently 16). */
        for (int i = 0; i < count; i++) {
            if (servers[i].port == (uint16_t)port && strcmp(servers[i].host, host) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "config_load: duplicate server %s:%u in %s",
                               host, port, path);
                rc = -1;
                break;
            }
        }
        if (rc != 0) break;

        memset(&servers[count], 0, sizeof(servers[count]));
        strncpy(servers[count].host, host, sizeof(servers[count].host) - 1);
        servers[count].port = (uint16_t)port;
        count++;
    }

    fclose(f);

    if (rc == 0 && count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "config_load: %s has no server entries", path);
        rc = -1;
    }

    if (rc != 0) return -1;

    *count_out = count;
    return 0;
}

int exp_chain_open(exp_chain_t **c_out, const exp_server_t *servers, int count) {
    if (!c_out) return -1;
    *c_out = NULL;

    if (!servers || count <= 0 || count > EXP_CHAIN_MAX_SERVERS) return -1;

    exp_chain_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;

    memcpy(c->servers, servers, sizeof(exp_server_t) * (size_t)count);
    c->count = count;
    c->current = 0;

    if (nodus_identity_generate(&c->identity) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "exp_chain_open: identity generation failed");
        free(c);
        return -1;
    }

    c->nc = calloc(1, sizeof(nodus_client_t));
    if (!c->nc) {
        nodus_identity_clear(&c->identity);
        free(c);
        return -1;
    }

    if (chain_connect(c, 0) != 0) {
        /* chain_connect() has already nodus_client_close()'d c->nc if (and
         * only if) init succeeded — c->nc_live tracks that, so this is
         * always a plain free() here, never a second close(). */
        nodus_identity_clear(&c->identity);
        free(c->nc);
        free(c);
        return -1;
    }

    *c_out = c;
    return 0;
}

void exp_chain_close(exp_chain_t *c) {
    if (!c) return;

    if (c->nc) {
        /* Only close a client that's actually live (successfully init'd
         * and not already closed by a prior chain_connect() failure) —
         * closing twice hits already-destroyed mutexes. */
        if (c->nc_live) {
            nodus_client_close(c->nc);
            c->nc_live = 0;
        }
        free(c->nc);
    }
    nodus_identity_clear(&c->identity);
    free(c);
}

int exp_chain_rotate(exp_chain_t *c) {
    if (!c || !c->nc || c->count <= 0) return -1;

    if (c->nc_live) {
        nodus_client_close(c->nc);
        c->nc_live = 0;
    }
    int next = (c->current + 1) % c->count;
    return chain_connect(c, next);
}

int exp_chain_current_server(const exp_chain_t *c) {
    if (!c) return -1;
    return c->current;
}

/* Ensure c->nc is ready, rotating once if not. */
static int ensure_ready(exp_chain_t *c) {
    if (!c || !c->nc) return -1;
    if (nodus_client_is_ready(c->nc)) return 0;
    return exp_chain_rotate(c);
}

/* One tip observation on the current connection: the three dnac_supply
 * round trips back to back, nothing in between that could rotate. */
static int tip_once(exp_chain_t *c, exp_chain_tip_t *out) {
    nodus_dnac_supply_result_t supply;
    memset(&supply, 0, sizeof(supply));
    int rc = nodus_client_dnac_supply(c->nc, &supply);
    if (rc != 0) return rc;

    bool has_cid = false;
    rc = nodus_client_dnac_chain_id32(c->nc, &has_cid, out->chain_id32);
    if (rc != 0) return rc;

    bool has_tip = false;
    rc = nodus_client_dnac_supply_tip(c->nc, &has_tip, &out->tip);
    if (rc != 0) return rc;

    /* the buckets (decision 2026-09-30-scan-supply-buckets.md): an older
     * node answers without them (buckets.has false) — not a failure; a
     * node that cannot read them answers an error, which is one */
    rc = nodus_client_dnac_supply_buckets(c->nc, &out->buckets);
    if (rc != 0) return rc;

    if (!has_cid || !has_tip) {
        QGP_LOG_ERROR(LOG_TAG, "%s:%u answers no chain_id32/tip — not a version-3 node",
                      c->servers[c->current].host, (unsigned)c->servers[c->current].port);
        return -1;
    }

    out->supply_genesis = supply.genesis_supply;
    out->supply_burned = supply.total_burned;
    out->supply_current = supply.current_supply;
    return 0;
}

int exp_chain_tip(exp_chain_t *c, exp_chain_tip_t *out) {
    if (!c || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    memset(out, 0, sizeof(*out));
    int rc = tip_once(c, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        memset(out, 0, sizeof(*out));
        rc = tip_once(c, out);
    }
    return rc;
}

int exp_chain_v3_page(exp_chain_t *c, uint64_t height, uint32_t from_index,
                      nodus_dnac_v3_block_result_t *out) {
    if (!c || !out || height == 0) return -1;
    if (ensure_ready(c) != 0) return -1;

    /* budget 0 = the node's maximum page (NODUS_DNAC_V3_BLOCK_BUDGET_MAX) */
    int rc = nodus_client_dnac_v3_block(c->nc, height, from_index, 0, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_v3_block(c->nc, height, from_index, 0, out);
    }
    return rc;
}

int exp_chain_balance(exp_chain_t *c, const char *owner_hex,
                      nodus_dnac_balance_result_t *out) {
    if (!c || !c->nc || !owner_hex || !out || c->count <= 0) return -1;
    memset(out, 0, sizeof(*out));

    int rc = -1;
    for (int attempt = 0; attempt < c->count; attempt++) {
        /* attempt 0 uses the current server if it is ready; every other
         * attempt (and a not-ready start) moves to the next one — so
         * `count` attempts visit every server at most once */
        if (attempt > 0 || !nodus_client_is_ready(c->nc)) {
            if (exp_chain_rotate(c) != 0) {
                rc = -1;
                continue;
            }
        }
        rc = nodus_client_dnac_balance(c->nc, owner_hex, out);
        if (rc == 0) return 0;
        QGP_LOG_WARN(LOG_TAG, "dnac_balance on %s:%u failed (rc=%d)",
                     c->servers[c->current].host,
                     (unsigned)c->servers[c->current].port, rc);
    }
    return rc != 0 ? rc : -1;
}

int exp_chain_evm_account(exp_chain_t *c, const uint8_t addr[32],
                          const nodus_evm_logs_cursor_t *cursor,
                          nodus_evm_account_t *acct,
                          nodus_evm_logs_res_t *logs,
                          uint64_t *logs_from_out, uint64_t *logs_to_out) {
    if (!c || !c->nc || !addr || !acct || c->count <= 0) return -1;
    memset(acct, 0, sizeof(*acct));
    if (logs) memset(logs, 0, sizeof(*logs));
    if (logs_from_out) *logs_from_out = 0;
    if (logs_to_out) *logs_to_out = 0;

    int rc = -1;
    for (int attempt = 0; attempt < c->count; attempt++) {
        /* the exp_chain_balance rotation: every server at most once */
        if (attempt > 0 || !nodus_client_is_ready(c->nc)) {
            if (exp_chain_rotate(c) != 0) {
                rc = -1;
                continue;
            }
        }
        rc = nodus_client_evm_account(c->nc, addr, acct);
        if (rc == 0 && logs && cursor && cursor->height > acct->height) {
            /* nothing past the tip yet: an empty, complete page, no read */
            if (logs_from_out) *logs_from_out = cursor->height;
            if (logs_to_out) *logs_to_out = acct->height;
        } else if (rc == 0 && logs) {
            nodus_evm_logs_req_t req;
            memset(&req, 0, sizeof(req));
            if (cursor) {
                /* the window follows the cursor (see exp_chain.h) */
                req.from_height = cursor->height;
                req.to_height = acct->height - cursor->height <
                                        EXP_EVM_LOGS_WINDOW
                                    ? acct->height
                                    : cursor->height + EXP_EVM_LOGS_WINDOW - 1;
                req.cursor = cursor;
            } else {
                req.to_height = acct->height;
                req.from_height = acct->height >= EXP_EVM_LOGS_WINDOW
                                      ? acct->height - EXP_EVM_LOGS_WINDOW + 1
                                      : 1;
                if (req.from_height > req.to_height)
                    req.from_height = req.to_height;
            }
            req.addr = addr;
            req.limit = EXP_EVM_LOGS_LIMIT;
            rc = nodus_client_evm_logs(c->nc, &req, logs);
            if (rc == 0) {
                if (logs_from_out) *logs_from_out = req.from_height;
                if (logs_to_out) *logs_to_out = req.to_height;
            } else {
                nodus_evm_logs_free(logs);
                memset(logs, 0, sizeof(*logs));
            }
        }
        if (rc == 0) return 0;
        memset(acct, 0, sizeof(*acct));
        QGP_LOG_WARN(LOG_TAG, "evm_account/evm_logs on %s:%u failed (rc=%d)",
                     c->servers[c->current].host,
                     (unsigned)c->servers[c->current].port, rc);
    }
    return rc != 0 ? rc : -1;
}

/* ── Supply buckets: meta blob + circulating ────────────────────────── */

static void put_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
    return v;
}

void exp_supply_buckets_pack(const nodus_dnac_supply_buckets_t *b,
                             uint8_t out[EXP_SUPPLY_BUCKETS_BLOB_LEN]) {
    memset(out, 0, EXP_SUPPLY_BUCKETS_BLOB_LEN);
    if (!b || !b->has) return;                 /* has 0, every u64 0 */
    uint8_t *p = out;
    *p++ = 1;
    put_u64_le(p, b->current_supply); p += 8;
    put_u64_le(p, b->reward_pool);    p += 8;
    for (int i = 0; i < NODUS_DNAC_TREASURY_POOLS; i++) {
        put_u64_le(p, b->treasury[i]); p += 8;
    }
    put_u64_le(p, b->unclaimed);
}

int exp_supply_buckets_unpack(const uint8_t *buf, size_t len,
                              nodus_dnac_supply_buckets_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!buf || len != EXP_SUPPLY_BUCKETS_BLOB_LEN || buf[0] > 1) return -1;
    if (buf[0] == 0) return 0;
    const uint8_t *p = buf + 1;
    out->current_supply = get_u64_le(p); p += 8;
    out->reward_pool    = get_u64_le(p); p += 8;
    for (int i = 0; i < NODUS_DNAC_TREASURY_POOLS; i++) {
        out->treasury[i] = get_u64_le(p); p += 8;
    }
    out->unclaimed = get_u64_le(p);
    out->has = true;
    return 0;
}

/* ── Active stake: meta blob + summation + read ─────────────────────── */

void exp_active_stake_pack(const exp_active_stake_t *s,
                           uint8_t out[EXP_ACTIVE_STAKE_BLOB_LEN]) {
    memset(out, 0, EXP_ACTIVE_STAKE_BLOB_LEN);
    if (!s || !s->has) return;                 /* has 0, every u64 0 */
    out[0] = 1;
    put_u64_le(out + 1, s->stake);
    put_u64_le(out + 9, s->validators);
    put_u64_le(out + 17, s->at_tip);
}

int exp_active_stake_unpack(const uint8_t *buf, size_t len, exp_active_stake_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!buf || len != EXP_ACTIVE_STAKE_BLOB_LEN || buf[0] > 1) return -1;
    if (buf[0] == 0) return 0;
    out->stake = get_u64_le(buf + 1);
    out->validators = get_u64_le(buf + 9);
    out->at_tip = get_u64_le(buf + 17);
    out->has = 1;
    return 0;
}

int exp_active_stake_add(exp_active_stake_t *acc,
                         const nodus_dnac_validator_list_entry_t *e) {
    if (!acc || !e) return -1;
    if (e->status != (uint8_t)DNAC_VALIDATOR_ACTIVE) return 0;
    uint64_t power_stake = e->self_stake + e->external_delegated;
    if (power_stake < e->self_stake) return -1;
    if (acc->stake + power_stake < acc->stake) return -1;
    acc->stake += power_stake;
    acc->validators++;
    return 0;
}

int exp_chain_active_stake(exp_chain_t *c, exp_active_stake_t *out) {
    if (!c || !c->nc || !out) return -1;
    memset(out, 0, sizeof(*out));
    if (!nodus_client_is_ready(c->nc)) return -1;

    exp_active_stake_t acc;
    memset(&acc, 0, sizeof(acc));
    int offset = 0;
    for (int page = 0; page < EXP_ACTIVE_STAKE_MAX_PAGES; page++) {
        nodus_dnac_validator_list_result_t res;
        memset(&res, 0, sizeof(res));
        int rc = nodus_client_dnac_validator_list(c->nc, (int)DNAC_VALIDATOR_ACTIVE, offset,
                                                  DNAC_MAX_VALIDATORS, &res);
        if (rc != 0) {
            nodus_client_free_validator_list_result(&res);
            QGP_LOG_WARN(LOG_TAG, "dnac_validator_list on %s:%u failed (rc=%d)",
                         c->servers[c->current].host, (unsigned)c->servers[c->current].port, rc);
            return rc;
        }
        int bad = (res.count > 0 && !res.entries);
        for (int i = 0; !bad && i < res.count; i++) {
            if (exp_active_stake_add(&acc, &res.entries[i]) != 0) bad = 1;
        }
        const int count = res.count, total = res.total;
        nodus_client_free_validator_list_result(&res);
        if (bad) {
            QGP_LOG_WARN(LOG_TAG, "%s", "dnac_validator_list: malformed page or stake overflow");
            return -1;
        }
        if (count <= 0 || offset + count >= total) {
            if (count <= 0 && offset < total) {
                QGP_LOG_WARN(LOG_TAG, "%s", "dnac_validator_list: empty page before the end");
                return -1;
            }
            acc.has = 1;
            *out = acc;
            return 0;
        }
        offset += count;
    }
    QGP_LOG_WARN(LOG_TAG, "%s", "dnac_validator_list: page bound exceeded");
    return -1;
}

int exp_supply_circulating(const nodus_dnac_supply_buckets_t *b,
                           uint64_t *out) {
    if (!b || !out || !b->has) return -1;
    uint64_t c = b->current_supply;
    if (b->reward_pool > c) return -1;
    c -= b->reward_pool;
    for (int i = 0; i < NODUS_DNAC_TREASURY_POOLS; i++) {
        if (b->treasury[i] > c) return -1;
        c -= b->treasury[i];
    }
    if (b->unclaimed > c) return -1;
    c -= b->unclaimed;
    *out = c;
    return 0;
}

/* ── F4 chain-reset FSM ─────────────────────────────────────────────── */

static const uint8_t EXP_ZERO32[32] = {0};

static void fsm_reset_tracking(exp_reset_fsm_t *f) {
    f->cand_set = 0;
    f->servers_seen[0] = -1;
    f->servers_seen[1] = -1;
    f->polls_seen = 0;
}

int exp_reset_fsm_feed(exp_reset_fsm_t *f, const uint8_t chain_id[32], int server_index) {
    if (!f || !chain_id) return EXP_RESET_NO;

    /* -1 is also the sentinel exp_chain_current_server() returns for a NULL
     * client, and the "empty slot" value in f->servers_seen[]. A caller
     * that fed server_index == -1 into the mismatch-tracking paths below
     * would silently collide with that sentinel (e.g. servers_seen[0] set
     * to -1 reads back as "still empty", corrupting the distinct-server
     * count). Guard it: report the FSM's current status without touching
     * any tracking state. */
    if (server_index < 0) {
        if (!f->cand_set) return EXP_RESET_NO;
        int distinct = (f->servers_seen[0] != -1) + (f->servers_seen[1] != -1);
        if (f->polls_seen >= 2 && distinct >= 2) return EXP_RESET_CONFIRMED;
        return EXP_RESET_PENDING;
    }

    /* First-ever feed with a zeroed (unset) reference: adopt chain_id as
     * the reference. This observation trivially matches the reference it
     * just established. */
    if (memcmp(f->ref_chain_id, EXP_ZERO32, 32) == 0) {
        memcpy(f->ref_chain_id, chain_id, 32);
        fsm_reset_tracking(f);
        return EXP_RESET_NO;
    }

    /* Matching observation: any match resets FSM tracking state fully. */
    if (memcmp(chain_id, f->ref_chain_id, 32) == 0) {
        fsm_reset_tracking(f);
        return EXP_RESET_NO;
    }

    /* Mismatch. Different candidate than currently tracked (or none
     * tracked yet) — restart tracking against the new candidate. */
    if (!f->cand_set || memcmp(chain_id, f->cand, 32) != 0) {
        memcpy(f->cand, chain_id, 32);
        f->cand_set = 1;
        f->servers_seen[0] = server_index;
        f->servers_seen[1] = -1;
        f->polls_seen = 1;
        return EXP_RESET_PENDING;
    }

    /* Same candidate as tracked: one more poll observing it. */
    f->polls_seen++;
    if (f->servers_seen[0] != server_index && f->servers_seen[1] != server_index) {
        if (f->servers_seen[0] == -1) {
            f->servers_seen[0] = server_index;
        } else if (f->servers_seen[1] == -1) {
            f->servers_seen[1] = server_index;
        }
        /* A 3rd+ distinct server doesn't need a slot — 2 distinct servers
         * is already the confirmation threshold. */
    }

    int distinct = (f->servers_seen[0] != -1) + (f->servers_seen[1] != -1);
    if (f->polls_seen >= 2 && distinct >= 2) {
        return EXP_RESET_CONFIRMED;
    }
    return EXP_RESET_PENDING;
}
