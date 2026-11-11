/**
 * @file amm_nodus_watch.c
 * @brief nodus-amm Nodus observation (see amm_nodus_watch.h). Plan section 8
 *        step 6, section 11, section 13, section 17; givens items 32, 49, 54,
 *        59.
 */
#include "amm_nodus_watch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "AMM_NWATCH"

#define CUR_SCAN    "nodus_scan"       /* history processed through this height */
#define CUR_SCAN_TS "nodus_scan_ts"    /* the header time of that height        */

typedef nodus_dnac_addr_history_entry_t hrow_t;

struct amm_nodus_watch {
    amm_nodus_watch_cfg_t cfg;
    amm_node_t            node;
    /* Block-walk progress of the INTENT id resolution, kept IN MEMORY across
     * steps so a walk cut by its time budget resumes at its last validated
     * page (faucet core.scan_prog). Keyed by (height, wire id); touched by
     * the single worker thread only. An incomplete walk decides nothing. */
    struct {
        int      valid;
        uint64_t height;
        uint8_t  wire[64];
        uint32_t from;
    } prog;
};

static const uint8_t ZERO64[64] = {0};

/* ── small helpers ──────────────────────────────────────────────────── */

void amm_nodus_watch_id_text(const uint8_t id[64], char *out, size_t cap) {
    static const char *d = "0123456789abcdef";
    if (cap < 6 + 128 + 1) { if (cap) out[0] = '\0'; return; }
    memcpy(out, "nodus:", 6);
    for (size_t i = 0; i < 64; i++) {
        out[6 + 2 * i] = d[id[i] >> 4];
        out[6 + 2 * i + 1] = d[id[i] & 15];
    }
    out[6 + 128] = '\0';
}

static int hex128(const char *s) {
    if (strlen(s) != 128) return 0;
    for (size_t i = 0; i < 128; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

int amm_nodus_watch_index_ok(int enabled, uint64_t from_height, uint64_t resume) {
    /* "0 = it never indexed" (nodus.h:2386-2388) */
    return enabled && from_height != 0 && from_height <= resume;
}

int amm_nodus_depth_ok(uint64_t tip, uint64_t height, uint64_t wait) {
    return tip >= height && tip - height >= wait;
}

amm_nm_t amm_nodus_watch_match(const hrow_t *row, const amm_swap_t *swap) {
    if (strcmp(row->kind, "spend_in") != 0) return AMM_NM_IGNORED;
    if (memcmp(row->token_id, ZERO64, 64) != 0) return AMM_NM_IGNORED;
    if (strcmp(row->peer, swap->sender) != 0) return AMM_NM_NONE;
    if (row->amount != swap->amount) return AMM_NM_HELD_VALUE;
    /* a chain fact against a chain fact: the payment's block height against
     * the committed tip the bot read at approval (no wall clock) */
    if (row->h <= swap->approved_tip) return AMM_NM_HELD_EARLY;
    if (row->ts > swap->expiry) return AMM_NM_HELD_EXPIRED;
    return AMM_NM_MATCH;
}

/* ── construction ───────────────────────────────────────────────────── */

amm_nodus_watch_t *amm_nodus_watch_new(const amm_nodus_watch_cfg_t *cfg) {
    if (!cfg || !cfg->node || !cfg->journal) return NULL;
    const amm_node_t *n = cfg->node;
    if (!n->ruleset_info || !n->block_time || !n->addr_history ||
        !n->addr_history_free || !n->item_intent) return NULL;
    if (cfg->id_kind != AMM_NW_ID_WIRE && cfg->id_kind != AMM_NW_ID_INTENT)
        return NULL;                      /* question 12: no default           */
    if (cfg->inflight_max == 0 || cfg->inflight_max > (uint64_t)INT64_MAX) return NULL;
    if (cfg->start_height == 0 || cfg->liquidity_wait_blocks == 0 ||
        cfg->page_limit == 0 || cfg->page_limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT ||
        cfg->max_pages == 0) return NULL;
    amm_nodus_watch_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->cfg = *cfg;
    w->node = *cfg->node;
    w->cfg.node = &w->node;
    return w;
}

void amm_nodus_watch_free(amm_nodus_watch_t *w) { free(w); }

/* The height the next step starts at. @return 0 / -1; *have = 1 when a cursor
 * is stored (its value in *cursor). */
static int resume_of(amm_nodus_watch_t *w, uint64_t *resume, int *have,
                     uint64_t *cursor) {
    uint64_t c = 0;
    int g = amm_journal_cursor_get(w->cfg.journal, CUR_SCAN, &c);
    if (g < 0) return -1;
    *have = (g == 0);
    *cursor = (g == 0) ? c : 0;
    if (g == 0) {
        if (c == UINT64_MAX) return -1;
        *resume = c + 1;
    } else {
        *resume = w->cfg.start_height;
    }
    return 0;
}

int amm_nodus_watch_start_check(amm_nodus_watch_t *w, uint64_t deadline_ms,
                                char *why, size_t why_cap) {
    if (!w) return AMM_NW_ERR;
    if (why && why_cap) why[0] = '\0';
    uint64_t resume = 0, cursor = 0;
    int have = 0;
    if (resume_of(w, &resume, &have, &cursor) != 0) return AMM_NW_ERR;
    nodus_dnac_addr_history_result_t res;
    memset(&res, 0, sizeof(res));
    if (w->node.addr_history(w->node.ctx, 1, NULL, &res, deadline_ms) != AMM_NODE_OK)
        return AMM_NW_UNKNOWN;
    int enabled = res.enabled;
    uint64_t from = res.from_height;
    w->node.addr_history_free(w->node.ctx, &res);
    /* plan line 283: from_height at or below the bot's START height, whatever
     * the cursor is */
    if (amm_nodus_watch_index_ok(enabled, from, w->cfg.start_height)) return AMM_NW_OK;
    if (why && why_cap) {
        if (!enabled)
            snprintf(why, why_cap, "the node does not run with addr_history_index: "
                     "the bot cannot see incoming NODUS payments");
        else if (from == 0)
            snprintf(why, why_cap, "the node has never indexed the address history");
        else
            snprintf(why, why_cap, "the node's address history starts at height %llu, "
                     "above the bot's start height %llu",
                     (unsigned long long)from, (unsigned long long)w->cfg.start_height);
    }
    QGP_LOG_ERROR(LOG_TAG, "the node's address history cannot serve the bot "
                  "(enabled %d, from_height %llu, start height %llu): refused", enabled,
                  (unsigned long long)from, (unsigned long long)w->cfg.start_height);
    return AMM_NW_REFUSED;
}

/* ── one step ───────────────────────────────────────────────────────── */

/* Read the history newest first, down to `resume`, into a heap array of the
 * native spend_in rows with resume <= h <= tip, ASCENDING. @return AMM_NW_OK
 * (*rows_out heap, *n_out; `ignored` counts the other history rows in range) /
 * AMM_NW_UNKNOWN / AMM_NW_REFUSED / AMM_NW_ERR. */
static int read_history(amm_nodus_watch_t *w, uint64_t tip, uint64_t resume,
                        uint64_t dl, hrow_t **rows_out, size_t *n_out,
                        int *ignored) {
    hrow_t *rows = NULL;
    size_t n = 0, cap = 0;
    nodus_dnac_addr_history_cursor_t cur;
    const nodus_dnac_addr_history_cursor_t *before = NULL;
    int rc = AMM_NW_UNKNOWN;
    int stop = 0;
    for (uint32_t page = 0; page < w->cfg.max_pages && !stop; page++) {
        nodus_dnac_addr_history_result_t res;
        memset(&res, 0, sizeof(res));
        if (w->node.addr_history(w->node.ctx, w->cfg.page_limit, before, &res,
                                 dl) != AMM_NODE_OK) { rc = AMM_NW_UNKNOWN; goto fail; }
        if (!amm_nodus_watch_index_ok(res.enabled, res.from_height, w->cfg.start_height)) {
            QGP_LOG_ERROR(LOG_TAG, "the node's address history cannot serve the "
                          "bot (enabled %d, from_height %llu, start height %llu): refused",
                          res.enabled, (unsigned long long)res.from_height,
                          (unsigned long long)w->cfg.start_height);
            w->node.addr_history_free(w->node.ctx, &res);
            rc = AMM_NW_REFUSED;
            goto fail;
        }
        if (res.count > w->cfg.page_limit || (res.count && !res.entries)) {
            w->node.addr_history_free(w->node.ctx, &res);
            rc = AMM_NW_UNKNOWN;
            goto fail;
        }
        for (size_t i = 0; i < res.count; i++) {
            const hrow_t *e = &res.entries[i];
            if (e->h < resume) { stop = 1; break; }
            if (e->h > tip) continue;                 /* read at the next step */
            if (strcmp(e->kind, "spend_in") != 0 ||
                memcmp(e->token_id, ZERO64, 64) != 0) {
                (*ignored)++;
                continue;
            }
            if (n == cap) {
                size_t nc = cap ? cap * 2 : 64;
                hrow_t *nr = realloc(rows, nc * sizeof(*rows));
                if (!nr) {
                    w->node.addr_history_free(w->node.ctx, &res);
                    rc = AMM_NW_ERR;
                    goto fail;
                }
                rows = nr;
                cap = nc;
            }
            rows[n++] = *e;
        }
        if (res.count < w->cfg.page_limit) stop = 1;  /* the end of the history */
        if (!stop) {
            cur.h = res.entries[res.count - 1].h;
            cur.i = res.entries[res.count - 1].i;
            cur.q = res.entries[res.count - 1].q;
            before = &cur;
        }
        w->node.addr_history_free(w->node.ctx, &res);
    }
    if (!stop) { rc = AMM_NW_UNKNOWN; goto fail; }    /* the page bound         */
    /* newest first -> ascending */
    for (size_t i = 0; i < n / 2; i++) {
        hrow_t t = rows[i];
        rows[i] = rows[n - 1 - i];
        rows[n - 1 - i] = t;
    }
    *rows_out = rows;
    *n_out = n;
    return AMM_NW_OK;
fail:
    free(rows);
    return rc;
}

/* Resolve a row's wire id to its transfer's intent id (INTENT id kind).
 * @return 0 found (`intent` filled) / 1 the block holds no applied item with
 * that wire id / -1 not readable now (incomplete walk or block not held). */
static int resolve_intent(amm_nodus_watch_t *w, const hrow_t *e, uint8_t intent[64],
                          uint64_t dl) {
    if (!w->prog.valid || w->prog.height != e->h ||
        memcmp(w->prog.wire, e->wire_id, 64) != 0) {
        memset(&w->prog, 0, sizeof(w->prog));
        w->prog.valid = 1;
        w->prog.height = e->h;
        memcpy(w->prog.wire, e->wire_id, 64);
    }
    int found = 0;
    int r = w->node.item_intent(w->node.ctx, e->h, e->wire_id, intent,
                                &w->prog.from, &found, dl);
    if (r == AMM_NODE_OK || r == AMM_NODE_NOT_HELD) w->prog.valid = 0;
    if (r != AMM_NODE_OK) return -1;
    return found ? 0 : 1;
}

static void held_reason(char *dst, size_t cap, const char *why) {
    snprintf(dst, cap, "%s", why);
}

int amm_nodus_watch_step(amm_nodus_watch_t *w, uint64_t deadline_ms,
                         amm_nodus_step_t *out) {
    amm_nodus_step_t local;
    amm_nodus_step_t *o = out ? out : &local;
    memset(o, 0, sizeof(*o));
    if (!w) return AMM_NW_ERR;
    amm_journal_t *j = w->cfg.journal;

    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (w->node.ruleset_info(w->node.ctx, &ri, deadline_ms) != AMM_NODE_OK ||
        ri.tip == 0) return AMM_NW_UNKNOWN;
    const uint64_t tip = ri.tip;
    o->tip = tip;

    uint64_t resume = 0, cursor = 0;
    int have = 0;
    if (resume_of(w, &resume, &have, &cursor) != 0) return AMM_NW_ERR;
    o->through = cursor;
    const int advance = !have || tip > cursor;

    /* the header time of the tip, stored with the cursor (window rule) */
    uint64_t ts_tip = 0;
    if (advance && resume <= tip) {
        if (w->node.block_time(w->node.ctx, tip, &ts_tip, deadline_ms) != AMM_NODE_OK ||
            ts_tip == 0) return AMM_NW_UNKNOWN;
    }

    hrow_t *rows = NULL;
    size_t n = 0;
    int rc = read_history(w, tip, resume, deadline_ms, &rows, &n, &o->ignored);
    if (rc != AMM_NW_OK) return rc;

    /* INTENT id kind: resolve every row that is not recorded yet BEFORE the
     * write transaction (network reads stay outside it) */
    uint8_t (*intent)[64] = NULL;
    int *state = NULL;              /* 0 ok, 1 no applied item, -1 unreadable */
    size_t upto = n;                /* rows [0, upto) are judged             */
    int unknown = 0;
    if (n > 0) {
        intent = calloc(n, 64);
        state = calloc(n, sizeof(*state));
        if (!intent || !state) { free(intent); free(state); free(rows); return AMM_NW_ERR; }
    }
    for (size_t i = 0; i < n && !unknown; i++) {
        const hrow_t *e = &rows[i];
        if (e->peer[0] == '\0' || !hex128(e->peer) || !e->has_wire) {
            QGP_LOG_ERROR(LOG_TAG, "a native spend_in row at height %llu has no "
                          "usable peer or wire id: not judged",
                          (unsigned long long)e->h);
            upto = i; unknown = 1; break;
        }
        amm_nrow_t have_row;
        int g = amm_journal_nrow_get(j, e->h, e->i, e->q, &have_row);
        if (g < 0) { free(intent); free(state); free(rows); return AMM_NW_ERR; }
        if (g == 0) continue;                       /* recorded: skipped below */
        if (w->cfg.id_kind == AMM_NW_ID_INTENT) {
            state[i] = resolve_intent(w, e, intent[i], deadline_ms);
            if (state[i] < 0) { upto = i; unknown = 1; }
        }
    }

    if (amm_journal_tx_begin(j) != 0) { free(intent); free(state); free(rows); return AMM_NW_ERR; }
    int fatal = 0;
    for (size_t i = 0; i < upto && !fatal; i++) {
        const hrow_t *e = &rows[i];
        amm_nrow_t r;
        int g = amm_journal_nrow_get(j, e->h, e->i, e->q, &r);
        if (g < 0) { fatal = 1; break; }
        if (g == 0) { o->skipped++; continue; }
        o->rows++;

        char id[AMM_TID_MAX];
        int have_id = 1;
        if (w->cfg.id_kind == AMM_NW_ID_WIRE) amm_nodus_watch_id_text(e->wire_id, id, sizeof(id));
        else if (state[i] == 0) amm_nodus_watch_id_text(intent[i], id, sizeof(id));
        else { have_id = 0; id[0] = '\0'; }

        memset(&r, 0, sizeof(r));
        r.height = e->h; r.item = e->i; r.seq = e->q;
        memcpy(r.wire, e->wire_id, 64);
        snprintf(r.peer, sizeof(r.peer), "%s", e->peer);
        r.amount = e->amount; r.ts = e->ts;

        char reason[AMM_MSG_MAX];
        reason[0] = '\0';
        amm_swap_t s;
        int counted = 0, waits = 0;
        int q = have_id ? amm_journal_swap_open_nodus(j, id, e->peer, e->amount, &s) : 1;
        if (q < 0) { fatal = 1; break; }
        if (q == 1) {
            held_reason(reason, sizeof(reason), have_id
                        ? "matches no approval"
                        : "the block holds no applied item with this wire id");
        } else {
            amm_nm_t m = amm_nodus_watch_match(e, &s);
            if (m == AMM_NM_HELD_EARLY)
                held_reason(reason, sizeof(reason),
                            "the payment's block is not above the tip read at the approval (before the approval)");
            else if (m == AMM_NM_HELD_EXPIRED)
                held_reason(reason, sizeof(reason),
                            "block time is after the approval's expiry");
            else if (m != AMM_NM_MATCH)
                held_reason(reason, sizeof(reason), "matches no approval");
            else {
                char msg[AMM_MSG_MAX];
                snprintf(msg, sizeof(msg), "NODUS payment counted in block %llu",
                         (unsigned long long)e->h);
                int mk = amm_journal_marker_exists(j, id);
                if (mk < 0) { fatal = 1; break; }
                if (mk == 0) {
                    held_reason(reason, sizeof(reason),
                                "the incoming transfer id is already counted");
                } else {
                    /* the payment is SEEN: the swap takes room in this same
                     * transaction, or waits in line (plan section 13, givens
                     * item 94). A committed Nodus block needs no extra depth
                     * (section 11), so it is counted at once when it holds
                     * room; one that waits is counted by the engine when room
                     * frees. */
                    int took = 0;
                    int t1 = amm_journal_swap_seen(j, s.seq, id, msg,
                                                   w->cfg.inflight_max,
                                                   w->cfg.held_keeps_room, &took);
                    if (t1 == AMM_J_DUP_TRANSFER) {
                        held_reason(reason, sizeof(reason),
                                    "another swap already carries the incoming transfer id");
                    } else if (t1 != 0) {
                        fatal = 1; break;
                    } else {
                        if (took &&
                            amm_journal_swap_transition(j, s.seq, AMM_S_COUNTED, NULL,
                                                        NULL, msg) != 0) {
                            fatal = 1; break;
                        }
                        counted = 1;         /* the row is taken by this swap */
                        waits = !took;
                    }
                }
            }
        }
        if (counted) {
            snprintf(r.state, sizeof(r.state), "%s", AMM_NR_COUNTED);
            r.swap_seq = s.seq;
            if (waits) o->waiting++;
            else o->counted++;
        } else {
            snprintf(r.state, sizeof(r.state), "%s", AMM_NR_HELD);
            snprintf(r.reason, sizeof(r.reason), "%s", reason);
            o->held++;
        }
        if (amm_journal_nrow_put(j, &r) != 0) { fatal = 1; break; }
    }
    if (!fatal && !unknown && advance && resume <= tip) {
        /* the cursor and the time of its block move with the rows */
        if (amm_journal_cursor_put(j, CUR_SCAN, tip) != 0 ||
            amm_journal_cursor_reset(j, CUR_SCAN_TS, ts_tip) != 0) fatal = 1;
    }
    free(intent);
    free(state);
    free(rows);
    if (fatal) {
        amm_journal_tx_rollback(j);
        QGP_LOG_ERROR(LOG_TAG, "a journal write failed: the step wrote nothing");
        return AMM_NW_ERR;
    }
    if (amm_journal_tx_commit(j) != 0) return AMM_NW_ERR;
    if (!unknown && advance && resume <= tip) o->through = tip;
    return unknown ? AMM_NW_UNKNOWN : AMM_NW_OK;
}

/* ── window observation, liquidity depth ─────────────────────────────── */

int amm_nodus_watch_window_observed(amm_nodus_watch_t *w, uint64_t expiry_ts) {
    if (!w) return -1;
    uint64_t c = 0, ts = 0;
    int a = amm_journal_cursor_get(w->cfg.journal, CUR_SCAN, &c);
    int b = amm_journal_cursor_get(w->cfg.journal, CUR_SCAN_TS, &ts);
    if (a < 0 || b < 0) return -1;
    if (a == 1 || b == 1) return 0;     /* nothing processed yet: not observed */
    return ts > expiry_ts ? 1 : 0;
}

int amm_nodus_watch_depth_reached(amm_nodus_watch_t *w, uint64_t height,
                                  uint64_t deadline_ms, int *reached) {
    if (!w || !reached) return -1;
    nodus_dnac_ruleset_info_t ri;
    memset(&ri, 0, sizeof(ri));
    if (w->node.ruleset_info(w->node.ctx, &ri, deadline_ms) != AMM_NODE_OK ||
        ri.tip == 0) return 1;
    *reached = amm_nodus_depth_ok(ri.tip, height, w->cfg.liquidity_wait_blocks);
    return 0;
}
