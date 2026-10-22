/**
 * @file faucet_node_real.c
 * @brief faucet_node_t over the client SDK (see faucet_node_real.h).
 *
 * DEADLINES (faucet_node.h): a call with a deadline waits for the session
 * mutex only until the deadline (pthread_mutex_clocklock on CLOCK_MONOTONIC
 * — the same clock as faucet_now_ms), never (re)connects (a reconnect can
 * take several connect timeouts; only the worker, which passes no deadline,
 * rebuilds a down session) and bounds its RPC by the remaining time. A scan
 * releases the mutex between pages, so a long block walk never holds the
 * session against another caller.
 */
#define _GNU_SOURCE
#include "faucet_node_real.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_fingerprint.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "FAUCET_NODE"

#define SCAN_MAX_PAGES      1000
#define SCAN_BUDGET_MS      20000   /* one block walk, all pages            */
#define RPC_TIMEOUT_MS      10000   /* the SDK default, restored per call   */
#define CONNECT_TIMEOUT_MS  5000

struct faucet_node_real {
    pthread_mutex_t         mu;
    nodus_client_t          client;
    int                     inited;
    const nodus_identity_t *id;
    nodus_client_config_t   ccfg;
    nodus_key_t             pin;
    char                    self_hex[129];
};

/* Take the session mutex; with a deadline, only until then. 0 = held. */
static int lock_until(faucet_node_real_t *n, uint64_t deadline_ms) {
    if (deadline_ms == FAUCET_NODE_NO_DEADLINE)
        return pthread_mutex_lock(&n->mu) == 0 ? 0 : -1;
    struct timespec ts;
    ts.tv_sec = (time_t)(deadline_ms / 1000u);
    ts.tv_nsec = (long)(deadline_ms % 1000u) * 1000000L;
    return pthread_mutex_clocklock(&n->mu, CLOCK_MONOTONIC, &ts) == 0 ? 0 : -1;
}

/* Connected session or NULL. Lock held. A down session is closed and
 * rebuilt — by a call WITHOUT a deadline only; the pin is part of ccfg and
 * never relaxed. A call with a deadline gets the session only when it is
 * already up, and has its RPC bounded by the time left. */
static nodus_client_t *session(faucet_node_real_t *n, uint64_t deadline_ms) {
    if (deadline_ms != FAUCET_NODE_NO_DEADLINE) {
        uint64_t now = faucet_now_ms();
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
    if (n->inited) {
        nodus_client_close(&n->client);
        n->inited = 0;
    }
    memset(&n->client, 0, sizeof(n->client));
    if (nodus_client_init(&n->client, &n->ccfg, n->id) != 0) return NULL;
    n->inited = 1;
    if (nodus_client_connect(&n->client) != 0) {
        QGP_LOG_WARN(LOG_TAG, "cannot connect to the node (identity pin in force)");
        nodus_client_close(&n->client);
        n->inited = 0;
        return NULL;
    }
    return &n->client;
}

#define WITH_SESSION(n, cl, dl)                              \
    int rc_ = FAUCET_NODE_ERR;                               \
    if (lock_until((n), (dl)) != 0) return rc_;              \
    nodus_client_t *cl = session((n), (dl));                 \
    if (cl) {

#define END_SESSION(n)                                       \
    }                                                        \
    pthread_mutex_unlock(&(n)->mu);                          \
    return rc_;

static int r_chain_id32(void *ctx, uint8_t out[32], uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        bool has = false;
        uint8_t id[32];
        if (nodus_client_dnac_chain_id32(cl, &has, id) == 0 && has) {
            memcpy(out, id, 32);
            rc_ = FAUCET_NODE_OK;
        }
    END_SESSION(n)
}

static int r_ruleset_info(void *ctx, nodus_dnac_ruleset_info_t *out, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        if (nodus_client_dnac_ruleset_info(cl, out) == 0) rc_ = FAUCET_NODE_OK;
    END_SESSION(n)
}

static int r_gas_price(void *ctx, uint64_t *out, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        nodus_dnac_fee_info_t fi;
        bool has = false;
        memset(&fi, 0, sizeof(fi));
        if (nodus_client_dnac_fee_info_ex(cl, &fi, &has) == 0) {
            if (has) {                       /* a present 0 is a valid price */
                *out = fi.gas_price;
                rc_ = FAUCET_NODE_OK;
            } else {
                rc_ = FAUCET_NODE_UNREPORTED;
            }
        }
    END_SESSION(n)
}

static int r_name_of(void *ctx, const char *owner_hex,
                     nodus_dnac_name_result_t *out, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        if (nodus_client_dnac_name_of(cl, owner_hex, out) == 0) rc_ = FAUCET_NODE_OK;
    END_SESSION(n)
}

static int r_balance(void *ctx, const char *owner_hex, const uint8_t token[64],
                     uint64_t *tip_out, uint64_t *total_out, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        nodus_dnac_balance_result_t br;
        memset(&br, 0, sizeof(br));
        if (nodus_client_dnac_balance(cl, owner_hex, &br) == 0) {
            uint64_t total = 0;                   /* a VALID answer with no
                                                   * row of the token is 0   */
            for (size_t i = 0; i < br.count; i++)
                if (!memcmp(br.tokens[i].token_id, token, 64)) {
                    total = br.tokens[i].total;
                    break;
                }
            *tip_out = br.tip;
            *total_out = total;
            rc_ = FAUCET_NODE_OK;
            nodus_client_free_balance_result(&br);
        }
    END_SESSION(n)
}

static int r_coins(void *ctx, const uint8_t token[64], faucet_coin_list_t *out,
                   uint64_t dl) {
    faucet_node_real_t *n = ctx;
    WITH_SESSION(n, cl, dl)
        nodus_dnac_utxo_result_t ur;
        memset(&ur, 0, sizeof(ur));
        int rc = nodus_client_dnac_utxo_token(cl, n->self_hex, token,
                                              FAUCET_COINS_MAX, &ur);
        if (rc == NODUS_CLIENT_ERR_TOKEN_FILTER_IGNORED) {
            rc_ = FAUCET_NODE_INCOMPLETE;
        } else if (rc == 0) {
            if (ur.count > FAUCET_COINS_MAX || ur.count < 0) {
                rc_ = FAUCET_NODE_ERR;            /* beyond the asked cap   */
            } else {
                int bad = 0;
                out->n = ur.count;
                /* A listing that fills the cap MAY be cut: report it; the
                 * node's amount-DESC order keeps the largest coins, so
                 * the caller plans over them and calls the list incomplete
                 * only when they do not cover the payout. */
                out->truncated = ur.count >= FAUCET_COINS_MAX;
                out->tip = ur.block_height;
                for (int i = 0; i < ur.count; i++) {
                    if (memcmp(ur.entries[i].token_id, token, 64)) { bad = 1; break; }
                    memcpy(out->c[i].nul, ur.entries[i].nullifier, 64);
                    out->c[i].amount = ur.entries[i].amount;
                    out->c[i].unlock_block = ur.entries[i].unlock_block;
                }
                if (!bad) rc_ = FAUCET_NODE_OK;
            }
            nodus_client_free_utxo_result(&ur);
        }
    END_SESSION(n)
}

/* One page of a block walk under the mutex. @return 0 = a page with
 * `*br` filled, FAUCET_NODE_NOT_HELD, or FAUCET_NODE_ERR. */
static int scan_page(faucet_node_real_t *n, uint64_t height, uint32_t from,
                     uint64_t page_deadline, nodus_dnac_v3_block_result_t *br) {
    if (lock_until(n, page_deadline) != 0) return FAUCET_NODE_ERR;
    int ret = FAUCET_NODE_ERR;
    nodus_client_t *cl = session(n, page_deadline);
    if (cl) {
        int rc = nodus_client_dnac_v3_block(cl, height, from, 0, br);
        if (rc == 0) ret = 0;
        else if (rc == NODUS_ERR_NOT_FOUND) ret = FAUCET_NODE_NOT_HELD;
    }
    pthread_mutex_unlock(&n->mu);
    return ret;
}

static int r_scan_block(void *ctx, uint64_t height, const uint8_t intent_id[64],
                        int *found_out, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    /* Whole-walk budget; the session is taken per page, so the worker never
     * holds it across the walk. The walk that runs out of time is
     * incomplete (ERR), never "not found". The session may be rebuilt
     * between pages (a worker call without deadline does that): fine, the
     * block is a committed height. */
    uint64_t end = faucet_now_ms() + SCAN_BUDGET_MS;
    if (dl != FAUCET_NODE_NO_DEADLINE && dl < end) end = dl;
    /* the per-page RPC is bounded by the walk's end; the worker (no caller
     * deadline) may rebuild a down session between pages, so a page it
     * takes passes no deadline when the caller had none */
    uint32_t from = 0;
    int found = 0;
    for (int page = 0; page < SCAN_MAX_PAGES; page++) {
        if (faucet_now_ms() >= end) return FAUCET_NODE_ERR;
        nodus_dnac_v3_block_result_t br;
        memset(&br, 0, sizeof(br));
        int pr = scan_page(n, height, from,
                           dl == FAUCET_NODE_NO_DEADLINE ? FAUCET_NODE_NO_DEADLINE : end,
                           &br);
        if (pr == FAUCET_NODE_NOT_HELD) return FAUCET_NODE_NOT_HELD;
        if (pr != 0) return FAUCET_NODE_ERR;
        if (br.height != height) {
            nodus_client_free_v3_block_result(&br);
            return FAUCET_NODE_ERR;
        }
        for (size_t i = 0; i < br.count; i++) {
            const nodus_dnac_v3_item_t *it = &br.items[i];
            if (it->code == 0 && it->has_intent_id &&
                !memcmp(it->intent_id, intent_id, 64)) found = 1;
        }
        int more = br.has_next;
        uint32_t next = br.next_index;
        nodus_client_free_v3_block_result(&br);
        if (found || !more) {                       /* a COMPLETE walk        */
            *found_out = found;
            return FAUCET_NODE_OK;
        }
        if (next <= from) return FAUCET_NODE_ERR;   /* no progress: refuse    */
        from = next;
    }
    return FAUCET_NODE_ERR;                         /* page bound: incomplete */
}

static int r_submit(void *ctx, const uint8_t wire_id[64], const uint8_t *env,
                    size_t len, char *msg, size_t msg_cap, uint64_t dl) {
    faucet_node_real_t *n = ctx;
    if (lock_until(n, dl) != 0) return -1;
    nodus_client_t *cl = session(n, dl);
    int ret = -1;
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
            if (rc == 0 && sres.status == NODUS_DNAC_APPROVED) ret = 0;
            else if (em[0] != '\0' || rc == 0) ret = 1;   /* the node answered */
            if (msg && msg_cap) snprintf(msg, msg_cap, "%s", em);
        }
    }
    pthread_mutex_unlock(&n->mu);
    return ret;
}

int faucet_node_real_open(const faucet_cfg_t *cfg, const nodus_identity_t *id,
                          faucet_node_real_t **out, faucet_node_t *vt) {
    if (!cfg || !id || !out || !vt) return -1;
    *out = NULL;
    faucet_node_real_t *n = calloc(1, sizeof(*n));
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
    uint8_t raw[64];
    if (qgp_sha3_512(id->pk.bytes, NODUS_PK_BYTES, raw) != 0) {
        pthread_mutex_destroy(&n->mu);
        free(n);
        return -1;
    }
    qgp_fp_raw_to_hex(raw, n->self_hex);

    memset(vt, 0, sizeof(*vt));
    vt->ctx = n;
    vt->chain_id32 = r_chain_id32;
    vt->ruleset_info = r_ruleset_info;
    vt->gas_price = r_gas_price;
    vt->name_of = r_name_of;
    vt->balance = r_balance;
    vt->coins = r_coins;
    vt->scan_block = r_scan_block;
    vt->submit = r_submit;
    *out = n;
    return 0;
}

void faucet_node_real_close(faucet_node_real_t *n) {
    if (!n) return;
    if (n->inited) nodus_client_close(&n->client);
    pthread_mutex_destroy(&n->mu);
    free(n);
}
