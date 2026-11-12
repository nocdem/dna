/**
 * @file amm_node_real.c
 * @brief amm_node_t over the client SDK (see amm_node_real.h). The pattern is
 *        tools/faucet/faucet_node_real.c, carried as the bot's own copy (the
 *        faucet is not edited; sharing code is a later decision, plan section
 *        11 / 20): one pinned session, one mutex, a deadline-bounded call
 *        never reconnects, a block walk releases the mutex between pages.
 *
 * "An unreadable answer is never a zero": every call returns AMM_NODE_OK only
 * with its out-parameters valid; a failed, malformed or too-slow read is
 * AMM_NODE_ERR (faucet_node.h).
 */
#define _GNU_SOURCE
#include "amm_node_real.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_NODE"

#define SCAN_MAX_PAGES      1000
#define SCAN_BUDGET_MS      20000   /* one block walk, all pages            */
#define RPC_TIMEOUT_MS      10000   /* the SDK default, restored per call   */
#define PAGE_DEADLINE_MS    10000   /* one page: mutex wait + RPC           */
#define CONNECT_TIMEOUT_MS  5000

struct amm_node_real {
    pthread_mutex_t         mu;
    nodus_client_t          client;
    int                     inited;
    const nodus_identity_t *id;
    nodus_client_config_t   ccfg;
    nodus_key_t             pin;
    char                    self_hex[129];
};

/* Take the session mutex; with a deadline, only until then. 0 = held. */
static int lock_until(amm_node_real_t *n, uint64_t deadline_ms) {
    if (deadline_ms == AMM_NODE_NO_DEADLINE)
        return pthread_mutex_lock(&n->mu) == 0 ? 0 : -1;
    struct timespec ts;
    ts.tv_sec = (time_t)(deadline_ms / 1000u);
    ts.tv_nsec = (long)(deadline_ms % 1000u) * 1000000L;
    return pthread_mutex_clocklock(&n->mu, CLOCK_MONOTONIC, &ts) == 0 ? 0 : -1;
}

/* Connected session or NULL. Lock held. A down session is closed and rebuilt
 * -- by a call WITHOUT a deadline only; the pin is part of ccfg and never
 * relaxed. A call with a deadline gets the session only when it is already
 * up, and has its RPC bounded by the time left. */
static nodus_client_t *session(amm_node_real_t *n, uint64_t deadline_ms) {
    if (deadline_ms != AMM_NODE_NO_DEADLINE) {
        uint64_t now = amm_now_ms();
        if (now >= deadline_ms) return NULL;
        if (!n->inited || !nodus_client_is_ready(&n->client)) return NULL;
        uint64_t left = deadline_ms - now;
        n->client.config.request_timeout_ms =
            left < RPC_TIMEOUT_MS ? (int)left : RPC_TIMEOUT_MS;
        return &n->client;
    }
    if (n->inited && nodus_client_is_ready(&n->client)) {
        n->client.config.request_timeout_ms = RPC_TIMEOUT_MS;
        return &n->client;
    }
    const int was_up = n->inited;
    if (n->inited) {
        QGP_LOG_INFO(LOG_TAG, "the node session is down: closing it and connecting again");
        nodus_client_close(&n->client);
        n->inited = 0;
    }
    memset(&n->client, 0, sizeof(n->client));
    if (nodus_client_init(&n->client, &n->ccfg, n->id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "the node client cannot be initialised");
        return NULL;
    }
    n->inited = 1;
    const uint64_t t0 = amm_now_ms();
    QGP_LOG_INFO(LOG_TAG, "%s the node %s:%u (identity pin of one node in force)",
                 was_up ? "reconnecting to" : "connecting to", n->ccfg.servers[0].ip,
                 (unsigned)n->ccfg.servers[0].port);
    int crc = nodus_client_connect(&n->client);
    if (crc != 0) {
        QGP_LOG_WARN(LOG_TAG, "cannot connect to the node (identity pin in force): the "
                     "client returned %d after %llu ms; a node whose fingerprint is not "
                     "the pinned one is refused", crc,
                     (unsigned long long)(amm_now_ms() - t0));
        nodus_client_close(&n->client);
        n->inited = 0;
        return NULL;
    }
    QGP_LOG_INFO(LOG_TAG, "connected to the node in %llu ms (identity pin matched)",
                 (unsigned long long)(amm_now_ms() - t0));
    return &n->client;
}

/* One line per node call (operator order 2026-11-12: full diagnostic log): what
 * was asked, how long it took, how it ended. `have_session` 0 = no connected
 * session was obtained (the lock timed out, the deadline had passed, or the
 * session was down); otherwise `sdk` is the client SDK's own return code and
 * `rc` the bot's AMM_NODE_* result. */
static void log_call(const char *what, uint64_t t0, int rc, int have_session, int sdk) {
    const unsigned long long ms = (unsigned long long)(amm_now_ms() - t0);
    if (rc == AMM_NODE_OK)
        QGP_LOG_INFO(LOG_TAG, "node call %s: answered in %llu ms (ok)", what, ms);
    else if (!have_session)
        QGP_LOG_WARN(LOG_TAG, "node call %s: no connected session after %llu ms "
                     "(result %d)", what, ms, rc);
    else
        QGP_LOG_WARN(LOG_TAG, "node call %s: failed after %llu ms (the client returned "
                     "%d, the bot result is %d)", what, ms, sdk, rc);
}

#define WITH_SESSION(n, cl, dl, what)                        \
    int rc_ = AMM_NODE_ERR;                                  \
    int sdk_ = 0;                                            \
    const char *what_ = (what);                              \
    const uint64_t t0_ = amm_now_ms();                       \
    if (lock_until((n), (dl)) != 0) {                        \
        log_call(what_, t0_, rc_, 0, 0);                     \
        return rc_;                                          \
    }                                                        \
    nodus_client_t *cl = session((n), (dl));                 \
    const int have_ = cl != NULL;                            \
    if (cl) {

#define END_SESSION(n)                                       \
    }                                                        \
    pthread_mutex_unlock(&(n)->mu);                          \
    log_call(what_, t0_, rc_, have_, sdk_);                  \
    return rc_;

static int r_chain_id32(void *ctx, uint8_t out[32], uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the chain id")
        bool has = false;
        uint8_t id[32];
        sdk_ = nodus_client_dnac_chain_id32(cl, &has, id);
        if (sdk_ == 0 && has) {
            memcpy(out, id, 32);
            rc_ = AMM_NODE_OK;
        }
    END_SESSION(n)
}

static int r_ruleset_info(void *ctx, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the ruleset information")
        sdk_ = nodus_client_dnac_ruleset_info(cl, out);
        if (sdk_ == 0) rc_ = AMM_NODE_OK;
    END_SESSION(n)
}

static int r_gas_price(void *ctx, uint64_t *out, uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the gas price")
        nodus_dnac_fee_info_t fi;
        bool has = false;
        memset(&fi, 0, sizeof(fi));
        sdk_ = nodus_client_dnac_fee_info_ex(cl, &fi, &has);
        if (sdk_ == 0) {
            if (has) {                       /* a present 0 is a valid price */
                *out = fi.gas_price;
                rc_ = AMM_NODE_OK;
            } else {
                rc_ = AMM_NODE_UNREPORTED;
            }
        }
    END_SESSION(n)
}

static int r_balance(void *ctx, const char *owner_hex, const uint8_t token[64],
                     uint64_t *tip_out, uint64_t *total_out, uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the balance")
        nodus_dnac_balance_result_t br;
        memset(&br, 0, sizeof(br));
        sdk_ = nodus_client_dnac_balance(cl, owner_hex, &br);
        if (sdk_ == 0) {
            uint64_t total = 0;                   /* a VALID answer with no
                                                   * row of the token is 0   */
            for (size_t i = 0; i < br.count; i++)
                if (!memcmp(br.tokens[i].token_id, token, 64)) {
                    total = br.tokens[i].total;
                    break;
                }
            *tip_out = br.tip;
            *total_out = total;
            rc_ = AMM_NODE_OK;
            nodus_client_free_balance_result(&br);
        }
    END_SESSION(n)
}

static int r_coins(void *ctx, const uint8_t token[64], amm_coin_list_t *out,
                   uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the coin list")
        nodus_dnac_utxo_result_t ur;
        memset(&ur, 0, sizeof(ur));
        int rc = nodus_client_dnac_utxo_token(cl, n->self_hex, token,
                                              AMM_COINS_MAX, &ur);
        sdk_ = rc;
        if (rc == NODUS_CLIENT_ERR_TOKEN_FILTER_IGNORED) {
            rc_ = AMM_NODE_INCOMPLETE;
        } else if (rc == 0) {
            if (ur.count > AMM_COINS_MAX || ur.count < 0) {
                rc_ = AMM_NODE_ERR;               /* beyond the asked cap   */
            } else {
                int bad = 0;
                out->n = ur.count;
                /* A listing that fills the cap MAY be cut: report it; the
                 * node's amount-DESC order keeps the largest coins. */
                out->truncated = ur.count >= AMM_COINS_MAX;
                out->tip = ur.block_height;
                for (int i = 0; i < ur.count; i++) {
                    if (memcmp(ur.entries[i].token_id, token, 64)) { bad = 1; break; }
                    memcpy(out->c[i].nul, ur.entries[i].nullifier, 64);
                    out->c[i].amount = ur.entries[i].amount;
                    out->c[i].unlock_block = ur.entries[i].unlock_block;
                }
                if (!bad) rc_ = AMM_NODE_OK;
            }
            nodus_client_free_utxo_result(&ur);
        }
    END_SESSION(n)
}

static int r_addr_history(void *ctx, unsigned limit,
                          const nodus_dnac_addr_history_cursor_t *before,
                          nodus_dnac_addr_history_result_t *out, uint64_t dl) {
    amm_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl, "the address history")
        memset(out, 0, sizeof(*out));
        /* the session owner's OWN history (nodus.h:2370-2371): the owner is
         * the bot's address, never another one's */
        sdk_ = nodus_client_dnac_addr_history(cl, n->self_hex, before, limit, out);
        if (sdk_ == 0) rc_ = AMM_NODE_OK;
    END_SESSION(n)
}

static void r_addr_history_free(void *ctx, nodus_dnac_addr_history_result_t *r) {
    (void)ctx;
    nodus_client_free_addr_history_result(r);
}

/* One page of a block walk under the mutex. @return 0 = a page with `*br`
 * filled, AMM_NODE_NOT_HELD, or AMM_NODE_ERR. */
static int scan_page(amm_node_real_t *n, uint64_t height, uint32_t from,
                     uint32_t budget, uint64_t page_deadline,
                     nodus_dnac_v3_block_result_t *br) {
    const uint64_t t0 = amm_now_ms();
    if (lock_until(n, page_deadline) != 0) {
        QGP_LOG_WARN(LOG_TAG, "node call block %llu from item %u: the session lock was not "
                     "obtained after %llu ms", (unsigned long long)height, from,
                     (unsigned long long)(amm_now_ms() - t0));
        return AMM_NODE_ERR;
    }
    int ret = AMM_NODE_ERR;
    int rc = 0;
    nodus_client_t *cl = session(n, page_deadline);
    if (cl) {
        rc = nodus_client_dnac_v3_block(cl, height, from, budget, br);
        if (rc == 0) ret = 0;
        else if (rc == NODUS_ERR_NOT_FOUND) ret = AMM_NODE_NOT_HELD;
    }
    pthread_mutex_unlock(&n->mu);
    if (ret == 0)
        QGP_LOG_INFO(LOG_TAG, "node call block %llu from item %u: answered in %llu ms (ok, "
                     "%zu items)", (unsigned long long)height, from,
                     (unsigned long long)(amm_now_ms() - t0), br->count);
    else if (!cl)
        QGP_LOG_WARN(LOG_TAG, "node call block %llu from item %u: no connected session "
                     "after %llu ms", (unsigned long long)height, from,
                     (unsigned long long)(amm_now_ms() - t0));
    else
        QGP_LOG_WARN(LOG_TAG, "node call block %llu from item %u: %s after %llu ms (the "
                     "client returned %d)", (unsigned long long)height, from,
                     ret == AMM_NODE_NOT_HELD ? "the node does not hold it" : "failed",
                     (unsigned long long)(amm_now_ms() - t0), rc);
    return ret;
}

static int r_block_time(void *ctx, uint64_t height, uint64_t *time_s,
                        uint64_t dl) {
    amm_node_real_t *n = ctx;
    uint64_t now = amm_now_ms();
    if (dl != AMM_NODE_NO_DEADLINE && now >= dl) return AMM_NODE_ERR;
    uint64_t page_dl = now + PAGE_DEADLINE_MS;
    if (dl != AMM_NODE_NO_DEADLINE && dl < page_dl) page_dl = dl;
    nodus_dnac_v3_block_result_t br;
    memset(&br, 0, sizeof(br));
    /* the smallest item budget the node accepts: only the header is wanted */
    int pr = scan_page(n, height, 0, 1, page_dl, &br);
    if (pr != 0) return pr;                       /* NOT_HELD or ERR        */
    int rc = AMM_NODE_ERR;
    if (br.height == height && br.time_ms != 0) {
        *time_s = br.time_ms / 1000u;             /* the header time, seconds */
        rc = AMM_NODE_OK;
    }
    nodus_client_free_v3_block_result(&br);
    return rc;
}

/* The two block walks differ only in what one applied item is tested for.
 * mode 0: an applied item carries `key` as its INTENT id (settlement,
 * faucet scan_block); mode 1: the applied item whose WIRE id is `key`, its
 * intent id goes to `intent_out`. Resumable exactly as faucet_node_real.c. */
static int walk_block(amm_node_real_t *n, uint64_t height, int mode,
                      const uint8_t key[64], uint8_t intent_out[64],
                      uint32_t *from_io, int *found_io, uint64_t dl) {
    /* Per-call budget; the session is taken per page, so the worker never
     * holds it across the walk. A call that runs out of time is incomplete
     * (ERR), never "not found" -- but the validated progress stays in
     * *from_io / *found_io, so the next call resumes at the page where this
     * one stopped. */
    uint64_t end = amm_now_ms() + SCAN_BUDGET_MS;
    if (dl != AMM_NODE_NO_DEADLINE && dl < end) end = dl;
    uint32_t from = *from_io;
    int found = *found_io;
    for (int page = 0; page < SCAN_MAX_PAGES; page++) {
        uint64_t now = amm_now_ms();
        if (now >= end) return AMM_NODE_ERR;
        /* EVERY page has its own bounded deadline: the worker never waits
         * unboundedly for the session nor reconnects inside a page. */
        uint64_t page_dl = now + PAGE_DEADLINE_MS;
        if (page_dl > end) page_dl = end;
        nodus_dnac_v3_block_result_t br;
        memset(&br, 0, sizeof(br));
        int pr = scan_page(n, height, from, 0, page_dl, &br);
        if (pr == AMM_NODE_NOT_HELD) return AMM_NODE_NOT_HELD;
        if (pr != 0) return AMM_NODE_ERR;
        if (br.height != height) {
            nodus_client_free_v3_block_result(&br);
            *from_io = 0; *found_io = 0;            /* malformed: start over  */
            return AMM_NODE_ERR;
        }
        for (size_t i = 0; i < br.count; i++) {
            const nodus_dnac_v3_item_t *it = &br.items[i];
            if (it->code != 0) continue;            /* applied items only     */
            if (mode == 0) {
                if (it->has_intent_id && !memcmp(it->intent_id, key, 64))
                    found = 1;
            } else if (it->has_wire_id && !memcmp(it->wire_id, key, 64) &&
                       it->has_intent_id && !found) {
                memcpy(intent_out, it->intent_id, 64);
                found = 1;
            }
        }
        int more = br.has_next;
        uint32_t next = br.next_index;
        nodus_client_free_v3_block_result(&br);
        if (found || !more) {                       /* a COMPLETE walk        */
            *found_io = found;
            return AMM_NODE_OK;
        }
        if (next <= from) {                         /* no progress: refuse    */
            *from_io = 0; *found_io = 0;
            return AMM_NODE_ERR;
        }
        from = next;
        *from_io = from;                            /* validated boundary     */
        *found_io = found;
    }
    return AMM_NODE_ERR;                            /* page bound: resumable  */
}

static int r_scan_block(void *ctx, uint64_t height, const uint8_t intent_id[64],
                        uint32_t *from_io, int *found_io, uint64_t dl) {
    return walk_block(ctx, height, 0, intent_id, NULL, from_io, found_io, dl);
}

static int r_item_intent(void *ctx, uint64_t height, const uint8_t wire_id[64],
                         uint8_t intent_out[64], uint32_t *from_io,
                         int *found_io, uint64_t dl) {
    return walk_block(ctx, height, 1, wire_id, intent_out, from_io, found_io, dl);
}

static int r_submit(void *ctx, const uint8_t wire_id[64], const uint8_t *env,
                    size_t len, char *msg, size_t msg_cap, uint64_t dl) {
    amm_node_real_t *n = ctx;
    const uint64_t t0 = amm_now_ms();
    char wid[17];                       /* the first 8 bytes of the wire id, hex */
    for (int i = 0; i < 8; i++) snprintf(wid + 2 * i, 3, "%02x", wire_id[i]);
    if (lock_until(n, dl) != 0) {
        QGP_LOG_WARN(LOG_TAG, "node call submit %s...: the session lock was not obtained "
                     "after %llu ms", wid, (unsigned long long)(amm_now_ms() - t0));
        return -1;
    }
    nodus_client_t *cl = session(n, dl);
    int ret = -1;
    int sdk = 0;
    if (cl && len <= UINT32_MAX) {
        nodus_pubkey_t spk;
        nodus_sig_t ssig;
        memcpy(spk.bytes, n->id->pk.bytes, NODUS_PK_BYTES);
        if (nodus_sign(&ssig, wire_id, 64, &n->id->sk) == 0) {
            nodus_dnac_spend_result_t sres;
            memset(&sres, 0, sizeof(sres));
            char em[128];
            em[0] = '\0';
            int rc = nodus_client_dnac_spend_ex(cl, wire_id, env, (uint32_t)len,
                                                &spk, &ssig, 0, &sres, em, sizeof(em));
            sdk = rc;
            if (rc == 0 && sres.status == NODUS_DNAC_APPROVED) ret = 0;
            else if (em[0] != '\0' || rc == 0) ret = 1;   /* the node answered */
            if (msg && msg_cap) snprintf(msg, msg_cap, "%s", em);
            if (rc == 0 && ret != 0)
                QGP_LOG_INFO(LOG_TAG, "node call submit %s...: the node's status was %d",
                             wid, (int)sres.status);
            if (em[0] != '\0')
                QGP_LOG_INFO(LOG_TAG, "node call submit %s...: the node's message: %s", wid, em);
        }
    }
    pthread_mutex_unlock(&n->mu);
    const unsigned long long ms = (unsigned long long)(amm_now_ms() - t0);
    if (ret == 0)
        QGP_LOG_INFO(LOG_TAG, "node call submit %s... (%zu bytes): approved in %llu ms", wid,
                     len, ms);
    else if (ret == 1)
        QGP_LOG_WARN(LOG_TAG, "node call submit %s... (%zu bytes): refused after %llu ms "
                     "(the client returned %d)", wid, len, ms, sdk);
    else
        QGP_LOG_WARN(LOG_TAG, "node call submit %s... (%zu bytes): no answer after %llu ms "
                     "(%s)", wid, len, ms, cl ? "the request failed" : "no connected session");
    return ret;
}

int amm_node_real_open(const amm_cfg_t *cfg, const nodus_identity_t *id,
                       amm_node_real_t **out, amm_node_t *vt) {
    if (!cfg || !id || !out || !vt) return -1;
    *out = NULL;
    amm_node_real_t *n = calloc(1, sizeof(*n));
    if (!n) return -1;
    pthread_mutex_init(&n->mu, NULL);
    n->id = id;
    memcpy(n->pin.bytes, cfg->node_fp, 64);
    snprintf(n->ccfg.servers[0].ip, sizeof(n->ccfg.servers[0].ip), "%s", cfg->node_host);
    n->ccfg.servers[0].port = cfg->node_port;
    n->ccfg.server_count = 1;
    n->ccfg.auto_reconnect = false;
    n->ccfg.connect_timeout_ms = CONNECT_TIMEOUT_MS;
    n->ccfg.request_timeout_ms = RPC_TIMEOUT_MS;
    n->ccfg.pinned_server_fps = &n->pin;
    n->ccfg.pinned_server_fp_count = 1;
    /* The 4001 secret connection carries the chain id: the one chain this
     * bot serves, required by the config. */
    memcpy(n->ccfg.chain_id, cfg->chain_id, sizeof(n->ccfg.chain_id));
    n->ccfg.has_chain_id = true;
    uint8_t raw[64];
    if (qgp_sha3_512(id->pk.bytes, NODUS_PK_BYTES, raw) != 0) {
        pthread_mutex_destroy(&n->mu);
        free(n);
        return -1;
    }
    qgp_fp_raw_to_hex(raw, n->self_hex);
    QGP_LOG_INFO(LOG_TAG, "the node adapter is ready: node %s:%u, connect timeout %d ms, "
                 "request timeout %d ms, the bot's own address %.16s...",
                 n->ccfg.servers[0].ip, (unsigned)n->ccfg.servers[0].port,
                 CONNECT_TIMEOUT_MS, RPC_TIMEOUT_MS, n->self_hex);

    memset(vt, 0, sizeof(*vt));
    vt->ctx = n;
    vt->chain_id32 = r_chain_id32;
    vt->ruleset_info = r_ruleset_info;
    vt->gas_price = r_gas_price;
    vt->block_time = r_block_time;
    vt->balance = r_balance;
    vt->coins = r_coins;
    vt->addr_history = r_addr_history;
    vt->addr_history_free = r_addr_history_free;
    vt->scan_block = r_scan_block;
    vt->item_intent = r_item_intent;
    vt->submit = r_submit;
    *out = n;
    return 0;
}

void amm_node_real_close(amm_node_real_t *n) {
    if (!n) return;
    if (n->inited) nodus_client_close(&n->client);
    pthread_mutex_destroy(&n->mu);
    free(n);
}
