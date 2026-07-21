/* exp_chain — DNAC Explorer Nodus chain client wrapper + F4 reset FSM.
 *
 * See exp_chain.h for the full contract. This file has two independent
 * halves:
 *   - Network wrappers (exp_chain_open/close/rotate/current_server +
 *     exp_chain_supply/ledger_range/tx/block/utxos): thin pass-throughs to
 *     the Nodus client SDK. Not unit-tested here (no network in tests,
 *     see Task 4 plan) — exercised live in Task 9.
 *   - exp_reset_fsm_feed: pure logic, unit-tested directly.
 */

#include "exp_chain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodus/nodus.h"
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

int exp_chain_supply(exp_chain_t *c, nodus_dnac_supply_result_t *out) {
    if (!c || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    int rc = nodus_client_dnac_supply(c->nc, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_supply(c->nc, out);
    }
    return rc;
}

int exp_chain_ledger_range(exp_chain_t *c, uint64_t from, uint64_t to, nodus_dnac_range_result_t *out) {
    if (!c || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    int rc = nodus_client_dnac_ledger_range(c->nc, from, to, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_ledger_range(c->nc, from, to, out);
    }
    return rc;
}

int exp_chain_tx(exp_chain_t *c, const uint8_t hash[64], nodus_dnac_tx_result_t *out) {
    if (!c || !hash || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    int rc = nodus_client_dnac_tx(c->nc, hash, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_tx(c->nc, hash, out);
    }
    return rc;
}

int exp_chain_block(exp_chain_t *c, uint64_t height, nodus_dnac_block_result_t *out) {
    if (!c || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    int rc = nodus_client_dnac_block(c->nc, height, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_block(c->nc, height, out);
    }
    return rc;
}

int exp_chain_utxos(exp_chain_t *c, const char *owner_fp, nodus_dnac_utxo_result_t *out) {
    if (!c || !owner_fp || !out) return -1;
    if (ensure_ready(c) != 0) return -1;

    int rc = nodus_client_dnac_utxo(c->nc, owner_fp, 100, out);
    if (rc != 0) {
        if (exp_chain_rotate(c) != 0) return -1;
        rc = nodus_client_dnac_utxo(c->nc, owner_fp, 100, out);
    }
    return rc;
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
