/* exp_http — DNAC Explorer read-only JSON HTTP API. See exp_http.h. */

#include "exp_http.h"

#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "nodus/nodus.h"          /* NODUS_DNAC_V3_* kinds, bounds */
#include "dnac/dnac.h"            /* dnac_name_bytes_ok (HF-4 name search) */

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_HTTP"

/* ── Small parsing / formatting helpers (no I/O) ────────────────────── */

/* Hard limit G3: list endpoints clamp to <= 100 rows, default 25 (a
 * block's item list defaults to the maximum, 100). */
#define EXP_HTTP_LIMIT_DEFAULT 25
#define EXP_HTTP_LIMIT_MAX     100

/* 8 KB request line/header buffer (G3) — anything longer is 413. */
#define EXP_HTTP_MAX_REQUEST 8192

/* /api/governance: a hard cap on the chain_config records one reply
 * carries — the whole list, not a page (the chain has a handful of votes;
 * a list longer than this answers the first 1000 and "truncated":true). */
#define EXP_HTTP_GOVERNANCE_MAX 1000

/* An item's io rows never exceed the node's per-item bounds. */
#define EXP_HTTP_MAX_IOS (NODUS_DNAC_V3_ITEM_MAX_IN + NODUS_DNAC_V3_ITEM_MAX_OUT)

static int is_lower_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Exactly 128 lowercase-hex chars, nothing else. */
static int is_hash128(const char *s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n != 128) return 0;
    for (size_t i = 0; i < n; i++) {
        if (!is_lower_hex_char(s[i])) return 0;
    }
    return 1;
}

/* Caller guarantees is_hash128(hexstr) already true (exactly 128 chars). */
static void hex128_decode(const char *hexstr, uint8_t out[64]) {
    for (size_t i = 0; i < 64; i++) {
        char hi = hexstr[i * 2];
        char lo = hexstr[i * 2 + 1];
        uint8_t hv = (uint8_t)((hi <= '9') ? (hi - '0') : (hi - 'a' + 10));
        uint8_t lv = (uint8_t)((lo <= '9') ? (lo - '0') : (lo - 'a' + 10));
        out[i] = (uint8_t)((hv << 4) | lv);
    }
}

static int is_all_decimal(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return 0;
    }
    return 1;
}

/* Strict decimal uint64 parse: the ENTIRE string must be digits (no sign,
 * no whitespace, no trailing garbage), and must fit in 64 bits. */
static int parse_u64_strict(const char *s, uint64_t *out) {
    if (!is_all_decimal(s)) return 0;

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0') return 0;

    *out = (uint64_t)v;
    return 1;
}

/* A position "<height>:<index>" — both strict decimal, height >= 1, index
 * within 32 bits. */
static int parse_position(const char *s, uint64_t *h_out, uint32_t *i_out) {
    if (!s) return 0;
    const char *colon = strchr(s, ':');
    if (!colon || colon == s || colon[1] == '\0') return 0;

    char hbuf[24];
    size_t hlen = (size_t)(colon - s);
    if (hlen >= sizeof(hbuf)) return 0;
    memcpy(hbuf, s, hlen);
    hbuf[hlen] = '\0';

    uint64_t h = 0, i = 0;
    if (!parse_u64_strict(hbuf, &h) || h == 0) return 0;
    if (!parse_u64_strict(colon + 1, &i) || i > UINT32_MAX) return 0;
    *h_out = h;
    *i_out = (uint32_t)i;
    return 1;
}

/* Splits "path?query" into path_out/query_out (both NUL-terminated,
 * truncated defensively if they don't fit). No query string ('?' absent)
 * leaves query_out empty. */
static void split_path_query(const char *full, char *path_out, size_t path_cap,
                              char *query_out, size_t query_cap) {
    const char *q = strchr(full, '?');
    if (q) {
        size_t plen = (size_t)(q - full);
        if (plen >= path_cap) plen = path_cap - 1;
        memcpy(path_out, full, plen);
        path_out[plen] = '\0';

        strncpy(query_out, q + 1, query_cap - 1);
        query_out[query_cap - 1] = '\0';
    } else {
        strncpy(path_out, full, path_cap - 1);
        path_out[path_cap - 1] = '\0';
        query_out[0] = '\0';
    }
}

/* Finds `key=value` in an '&'-joined query string and copies the raw value
 * (no percent-decoding — every value this API accepts is plain digits,
 * lowercase hex or a "height:index" position; a client that percent-encodes
 * the ':' gets a 400) into `out`. Returns 1 if the key was present (even
 * with an empty value), else 0. */
static int query_get(const char *qs, const char *key, char *out, size_t outcap) {
    if (!qs || !*qs || !key || !out || outcap == 0) return 0;

    size_t klen = strlen(key);
    const char *p = qs;
    while (*p) {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);

        if (seglen > klen && p[klen] == '=' && strncmp(p, key, klen) == 0) {
            size_t vlen = seglen - klen - 1;
            if (vlen >= outcap) vlen = outcap - 1;
            memcpy(out, p + klen + 1, vlen);
            out[vlen] = '\0';
            return 1;
        }

        if (!amp) break;
        p = amp + 1;
    }
    return 0;
}

/* "limit": absent -> def, present -> strict positive integer clamped to
 * EXP_HTTP_LIMIT_MAX. -1 on a malformed value (-> 400). */
static int parse_limit(const char *query, int def, int *limit_out) {
    *limit_out = def;
    char val[32];
    if (query_get(query, "limit", val, sizeof(val))) {
        uint64_t parsed;
        if (!parse_u64_strict(val, &parsed) || parsed == 0) return -1;
        *limit_out = (parsed > EXP_HTTP_LIMIT_MAX) ? EXP_HTTP_LIMIT_MAX : (int)parsed;
    }
    return 0;
}

static void json_error(exp_json_t *j, const char *msg) {
    exp_json_raw(j, "{\"error\":");
    exp_json_str(j, msg);
    exp_json_raw(j, "}");
}

static void json_position(exp_json_t *j, uint64_t h, uint32_t i) {
    char buf[48];
    snprintf(buf, sizeof(buf), "%llu:%u", (unsigned long long)h, (unsigned)i);
    exp_json_str(j, buf);
}

static const char *kind_name(int kind) {
    switch (kind) {
    case NODUS_DNAC_V3_KIND_EMPTY:    return "empty";
    case NODUS_DNAC_V3_KIND_ENVELOPE: return "envelope";
    case NODUS_DNAC_V3_KIND_CLAIM:    return "claim";
    default:                          return "unknown";
    }
}

static const char *record_name(int kind) {
    switch (kind) {
    case NODUS_DNAC_V3_REC_STAKE:            return "stake";
    case NODUS_DNAC_V3_REC_DELEGATE:         return "delegate";
    case NODUS_DNAC_V3_REC_UNSTAKE:          return "unstake";
    case NODUS_DNAC_V3_REC_UNDELEGATE:       return "undelegate";
    case NODUS_DNAC_V3_REC_VALIDATOR_UPDATE: return "validator_update";
    case NODUS_DNAC_V3_REC_CHAIN_CONFIG:     return "chain_config";
    default:                                 return "unknown";
    }
}

/* chain_config parameter ids — the DNAC_CFG_* enum (dnac/include/dnac/
 * dnac.h). NULL for an id this build does not know (shown by id). */
static const char *param_name(uint32_t id) {
    switch (id) {
    case DNAC_CFG_MAX_TXS_PER_BLOCK:      return "MAX_TXS_PER_BLOCK";
    case DNAC_CFG_BLOCK_INTERVAL_SEC:     return "BLOCK_INTERVAL_SEC";
    case DNAC_CFG_INFLATION_START_BLOCK:  return "INFLATION_START_BLOCK";
    case DNAC_CFG_TARGET_ACTIVE_COUNT:    return "TARGET_ACTIVE_COUNT";
    case DNAC_CFG_GAS_PRICE_RAW_PER_UNIT: return "GAS_PRICE_RAW_PER_UNIT";
    case DNAC_CFG_TOKEN_CREATE_FEE_RAW:   return "TOKEN_CREATE_FEE_RAW";
    case DNAC_CFG_HF2_ACTIVE:             return "HF2_ACTIVE";
    case DNAC_CFG_HF3_ACTIVE:             return "HF3_ACTIVE";
    case DNAC_CFG_RULESET_GEN2:           return "RULESET_GEN2";
    case DNAC_CFG_NAME_PRICE_3P:          return "NAME_PRICE_3P";
    case DNAC_CFG_NAME_PRICE_4P:          return "NAME_PRICE_4P";
    case DNAC_CFG_NAME_PRICE_5P:          return "NAME_PRICE_5P";
    case DNAC_CFG_NAME_PRICE_6P:          return "NAME_PRICE_6P";
    case DNAC_CFG_RULESET_GEN_STORAGE:    return "RULESET_GEN_STORAGE";
    default:                              return NULL;
    }
}

/* ── Row -> JSON emitters ────────────────────────────────────────────── */

static void emit_block(exp_json_t *j, const exp_block_row_t *b, int detail) {
    exp_json_raw(j, "{\"height\":");
    exp_json_u64(j, b->height);
    exp_json_raw(j, ",\"block_id\":");
    exp_json_hex(j, b->block_id, 64);
    exp_json_raw(j, ",\"time\":");
    exp_json_u64(j, b->time_ms);
    exp_json_raw(j, ",\"proposer\":");
    exp_json_hex(j, b->proposer, b->proposer_len);
    exp_json_raw(j, ",\"applied_count\":");
    exp_json_u64(j, b->applied_count);
    exp_json_raw(j, ",\"n_items\":");
    exp_json_u64(j, b->n_items);
    if (detail) {
        exp_json_raw(j, ",\"prev_id\":");
        exp_json_hex(j, b->prev_id, 64);
        exp_json_raw(j, ",\"global_root\":");
        exp_json_hex(j, b->global_root, 64);
    }
    exp_json_raw(j, "}");
}

/* Summary fields shared by every item view (no closing brace — callers
 * append view-specific fields, then "}"). */
static void emit_item_fields(exp_json_t *j, const exp_item_row_t *it) {
    exp_json_raw(j, "{\"position\":");
    json_position(j, it->height, it->idx);
    exp_json_raw(j, ",\"height\":");
    exp_json_u64(j, it->height);
    exp_json_raw(j, ",\"index\":");
    exp_json_u64(j, it->idx);
    exp_json_raw(j, ",\"time\":");
    exp_json_u64(j, it->block_time_ms);
    exp_json_raw(j, ",\"kind\":");
    exp_json_str(j, kind_name(it->kind));
    exp_json_raw(j, ",\"op\":");
    if (it->op[0]) exp_json_str(j, it->op); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"code\":");
    exp_json_u64(j, it->code);
    exp_json_raw(j, it->code != 0 ? ",\"refused\":true" : ",\"refused\":false");
    exp_json_raw(j, ",\"wire_id\":");
    if (it->has_wire_id) exp_json_hex(j, it->wire_id, 64); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"intent_id\":");
    if (it->has_intent_id) exp_json_hex(j, it->intent_id, 64); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"fee\":");
    if (it->has_fee) exp_json_u64_str(j, it->fee); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"burned\":");
    if (it->has_effects && it->burned > 0) exp_json_u64_str(j, it->burned);
    else exp_json_raw(j, "null");
    /* HF-4 NAME_REGISTER: the registered name, the price paid into the
     * reward pool (not a burn) and the owner (the resolved address of the
     * first input; null when not indexed) — all null on any other item. */
    exp_json_raw(j, ",\"name\":");
    if (it->name[0]) exp_json_str(j, it->name); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"name_price\":");
    if (it->name[0]) exp_json_u64_str(j, it->name_price); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"name_owner\":");
    if (it->name[0] && it->name_owner[0]) exp_json_str(j, it->name_owner); else exp_json_raw(j, "null");
}

static void emit_item_summary(exp_json_t *j, const exp_item_row_t *it) {
    emit_item_fields(j, it);
    exp_json_raw(j, "}");
}

static void emit_fp_or_null(exp_json_t *j, const char *fp) {
    if (fp && fp[0]) exp_json_str(j, fp); else exp_json_raw(j, "null");
}

static void emit_record(exp_json_t *j, const exp_record_row_t *r) {
    exp_json_raw(j, "{\"kind\":");
    exp_json_str(j, record_name(r->kind));
    exp_json_raw(j, ",\"validator\":");
    emit_fp_or_null(j, r->validator);
    exp_json_raw(j, ",\"delegator\":");
    emit_fp_or_null(j, r->delegator);
    exp_json_raw(j, ",\"destination\":");
    emit_fp_or_null(j, r->dest);
    exp_json_raw(j, ",\"amount\":");
    exp_json_u64_str(j, r->amount);
    exp_json_raw(j, ",\"commission_bps\":");
    exp_json_u64(j, r->commission_bps);
    exp_json_raw(j, ",\"param_id\":");
    exp_json_u64(j, r->param_id);
    exp_json_raw(j, ",\"new_value\":");
    exp_json_u64_str(j, r->new_value);
    exp_json_raw(j, ",\"effective_height\":");
    exp_json_u64(j, r->effective);
    exp_json_raw(j, "}");
}

static void emit_input(exp_json_t *j, const exp_io_row_t *io) {
    exp_json_raw(j, "{\"coin_id\":");
    exp_json_hex(j, io->coin_id, 64);
    if (io->has_owner) {
        exp_json_raw(j, ",\"address\":");
        exp_json_str(j, io->address);
        exp_json_raw(j, ",\"token_id\":");
        exp_json_hex(j, io->token_id, 64);
        exp_json_raw(j, ",\"amount\":");
        exp_json_u64_str(j, io->amount);
    } else {
        /* the coin's creating item is not in the index (a coin created at
         * a block boundary — a reward payout or a stake release) */
        exp_json_raw(j, ",\"address\":null,\"token_id\":null,\"amount\":null");
    }
    exp_json_raw(j, "}");
}

static void emit_output(exp_json_t *j, const exp_io_row_t *io) {
    exp_json_raw(j, "{\"coin_id\":");
    exp_json_hex(j, io->coin_id, 64);
    exp_json_raw(j, ",\"address\":");
    exp_json_str(j, io->address);
    exp_json_raw(j, ",\"token_id\":");
    exp_json_hex(j, io->token_id, 64);
    exp_json_raw(j, ",\"amount\":");
    exp_json_u64_str(j, io->amount);
    exp_json_raw(j, ",\"unlock_block\":");
    exp_json_u64(j, io->unlock_block);
    exp_json_raw(j, "}");
}

/* ── Endpoint handlers ───────────────────────────────────────────────── */

static void route_stats(exp_db_t *db, exp_json_t *j, int *status) {
    uint64_t indexed_height = 0, tip_height = 0;
    uint64_t supply_current = 0, supply_burned = 0, supply_genesis = 0;
    uint8_t chain_id[32];
    size_t chain_id_len = 0;

    int have_indexed_height = (exp_db_get_meta_u64(db, "last_indexed_height", &indexed_height) == 0);
    int have_tip_height     = (exp_db_get_meta_u64(db, "tip_height", &tip_height) == 0);
    int have_supply_current = (exp_db_get_meta_u64(db, "supply_current", &supply_current) == 0);
    int have_supply_burned  = (exp_db_get_meta_u64(db, "supply_burned", &supply_burned) == 0);
    int have_supply_genesis = (exp_db_get_meta_u64(db, "supply_genesis", &supply_genesis) == 0);
    int have_chain_id = (exp_db_get_meta_blob(db, "chain_id32", chain_id, sizeof(chain_id), &chain_id_len) == 0
                          && chain_id_len == 32);

    exp_json_raw(j, "{\"indexed_height\":");
    if (have_indexed_height) exp_json_u64(j, indexed_height); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"tip_height\":");
    if (have_tip_height) exp_json_u64(j, tip_height); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"chain_id\":");
    if (have_chain_id) exp_json_hex(j, chain_id, 32); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_current\":");
    if (have_supply_current) exp_json_u64_str(j, supply_current); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_burned\":");
    if (have_supply_burned) exp_json_u64_str(j, supply_burned); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_genesis\":");
    if (have_supply_genesis) exp_json_u64_str(j, supply_genesis); else exp_json_raw(j, "null");

    /* Supply buckets (decision 2026-09-30-scan-supply-buckets.md): one
     * meta blob, so the four figures and the "current" they are
     * subtracted from are one reply's. Absent / malformed / an older node
     * (has false) -> every bucket null; circulating is null also when a
     * subtraction would go below zero — never a wrapped number. */
    uint8_t blob[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    size_t blob_len = 0;
    nodus_dnac_supply_buckets_t bk;
    int have_buckets =
        exp_db_get_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob), &blob_len) == 0 &&
        exp_supply_buckets_unpack(blob, blob_len, &bk) == 0 && bk.has;
    uint64_t circulating = 0;
    int have_circulating = have_buckets && exp_supply_circulating(&bk, &circulating) == 0;

    exp_json_raw(j, ",\"reward_pool\":");
    if (have_buckets) exp_json_u64_str(j, bk.reward_pool); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"treasury\":");
    if (have_buckets) {
        exp_json_raw(j, "[");
        for (int i = 0; i < NODUS_DNAC_TREASURY_POOLS; i++) {
            if (i) exp_json_raw(j, ",");
            exp_json_u64_str(j, bk.treasury[i]);
        }
        exp_json_raw(j, "]");
    } else {
        exp_json_raw(j, "null");
    }
    exp_json_raw(j, ",\"unclaimed\":");
    if (have_buckets) exp_json_u64_str(j, bk.unclaimed); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"circulating\":");
    if (have_circulating) exp_json_u64_str(j, circulating); else exp_json_raw(j, "null");
    exp_json_raw(j, "}");

    *status = 200;
}

static void route_blocks(exp_db_t *db, const char *query, exp_json_t *j, int *status) {
    uint64_t before = UINT64_MAX;
    int limit;
    char val[32];
    if (query_get(query, "before", val, sizeof(val)) && !parse_u64_strict(val, &before)) {
        json_error(j, "invalid 'before'");
        *status = 400;
        return;
    }
    if (parse_limit(query, EXP_HTTP_LIMIT_DEFAULT, &limit) != 0) {
        json_error(j, "invalid 'limit'");
        *status = 400;
        return;
    }

    exp_block_row_t rows[EXP_HTTP_LIMIT_MAX];
    int count = 0;
    if (exp_db_query_blocks(db, before, limit, rows, &count) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"blocks\":[");
    for (int i = 0; i < count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_block(j, &rows[i], 0);
    }
    exp_json_raw(j, "]}");
    *status = 200;
}

/* /api/block/<height|block_id>?from=<index>&limit=<n> — the block and one
 * page of its items (index-ascending from `from`, default 0; limit default
 * and maximum 100); "next_from" names the next page's first index, null on
 * the last page. */
static void route_block(exp_db_t *db, const char *ident, const char *query, exp_json_t *j, int *status) {
    exp_block_row_t row;
    int found;

    if (is_hash128(ident)) {
        uint8_t id[64];
        hex128_decode(ident, id);
        found = (exp_db_query_block_by_id(db, id, &row) == 0);
    } else if (is_all_decimal(ident)) {
        uint64_t height;
        if (!parse_u64_strict(ident, &height)) {
            json_error(j, "invalid block height");
            *status = 400;
            return;
        }
        found = (exp_db_query_block_by_height(db, height, &row) == 0);
    } else {
        json_error(j, "invalid block identifier (expected height or 128-hex block id)");
        *status = 400;
        return;
    }

    uint64_t from = 0;
    int limit;
    char val[32];
    if ((query_get(query, "from", val, sizeof(val)) && (!parse_u64_strict(val, &from) || from > UINT32_MAX)) ||
        parse_limit(query, EXP_HTTP_LIMIT_MAX, &limit) != 0) {
        json_error(j, "invalid 'from'/'limit'");
        *status = 400;
        return;
    }

    if (!found) {
        json_error(j, "block not found");
        *status = 404;
        return;
    }

    exp_item_row_t *items = malloc(sizeof(exp_item_row_t) * EXP_HTTP_LIMIT_MAX);
    if (!items) {
        json_error(j, "out of memory");
        *status = 500;
        return;
    }
    int count = 0;
    if (exp_db_query_items(db, row.height, (uint32_t)from, limit, items, &count) != 0) {
        free(items);
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"block\":");
    emit_block(j, &row, 1);
    exp_json_raw(j, ",\"items\":[");
    for (int i = 0; i < count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_item_summary(j, &items[i]);
    }
    exp_json_raw(j, "],\"next_from\":");
    if (count > 0 && (uint64_t)items[count - 1].idx + 1 < row.n_items)
        exp_json_u64(j, (uint64_t)items[count - 1].idx + 1);
    else
        exp_json_raw(j, "null");
    exp_json_raw(j, "}");

    free(items);
    *status = 200;
}

/* /api/tx/<wire_id|intent_id|height:index> — one item with its inputs
 * (consumed coins), outputs (created coins) and record. A refused envelope
 * carries no ids (dnac_v3_block), so the position form is its only
 * address. */
static void route_tx(exp_db_t *db, const char *ident, exp_json_t *j, int *status) {
    exp_item_row_t it;
    int found;
    uint64_t h;
    uint32_t idx;

    if (is_hash128(ident)) {
        uint8_t id[64];
        hex128_decode(ident, id);
        found = (exp_db_query_item_by_id(db, id, &it) == 0);
    } else if (parse_position(ident, &h, &idx)) {
        found = (exp_db_query_item(db, h, idx, &it) == 0);
    } else {
        json_error(j, "invalid tx identifier (expected 128-hex wire/intent id or height:index)");
        *status = 400;
        return;
    }

    if (!found) {
        json_error(j, "tx not found");
        *status = 404;
        return;
    }

    exp_io_row_t ios[EXP_HTTP_MAX_IOS];
    int io_count = 0;
    if (exp_db_query_item_ios(db, it.height, it.idx, ios, EXP_HTTP_MAX_IOS, &io_count) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"tx\":");
    emit_item_fields(j, &it);
    exp_json_raw(j, ",\"record\":");
    if (it.rec.kind != 0) emit_record(j, &it.rec); else exp_json_raw(j, "null");
    exp_json_raw(j, "},\"inputs\":[");
    int first = 1;
    for (int i = 0; i < io_count; i++) {
        if (ios[i].dir != 0) continue;
        if (!first) exp_json_raw(j, ",");
        emit_input(j, &ios[i]);
        first = 0;
    }
    exp_json_raw(j, "],\"outputs\":[");
    first = 1;
    for (int i = 0; i < io_count; i++) {
        if (ios[i].dir != 1) continue;
        if (!first) exp_json_raw(j, ",");
        emit_output(j, &ios[i]);
        first = 0;
    }
    exp_json_raw(j, "]}");
    *status = 200;
}

/* /api/governance — every applied chain_config vote in the index,
 * (height, index) ascending, at most EXP_HTTP_GOVERNANCE_MAX; plus the
 * node's last reported tip and the indexed height, so a reader can tell
 * an activated rule (tip >= effective_height) from a pending one, and see
 * when a vote may still be past the indexed height. A genesis-document
 * row (height 0) is not a block item and is never listed. */
static void route_governance(exp_db_t *db, exp_json_t *j, int *status) {
    uint64_t indexed_height = 0, tip_height = 0;
    int have_indexed_height = (exp_db_get_meta_u64(db, "last_indexed_height", &indexed_height) == 0);
    int have_tip_height     = (exp_db_get_meta_u64(db, "tip_height", &tip_height) == 0);

    /* one row past the cap tells "exactly the cap" from "truncated" */
    exp_item_row_t *rows = malloc(sizeof(exp_item_row_t) * (EXP_HTTP_GOVERNANCE_MAX + 1));
    if (!rows) {
        json_error(j, "out of memory");
        *status = 500;
        return;
    }
    int count = 0;
    if (exp_db_query_records_by_kind(db, NODUS_DNAC_V3_REC_CHAIN_CONFIG, EXP_HTTP_GOVERNANCE_MAX + 1,
                                     rows, &count) != 0) {
        free(rows);
        json_error(j, "query failed");
        *status = 500;
        return;
    }
    int truncated = (count > EXP_HTTP_GOVERNANCE_MAX);
    if (truncated) count = EXP_HTTP_GOVERNANCE_MAX;

    exp_json_raw(j, "{\"tip\":");
    if (have_tip_height) exp_json_u64(j, tip_height); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"indexed_height\":");
    if (have_indexed_height) exp_json_u64(j, indexed_height); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"records\":[");
    for (int i = 0; i < count; i++) {
        const exp_item_row_t *it = &rows[i];
        const char *pname = param_name(it->rec.param_id);
        if (i) exp_json_raw(j, ",");
        exp_json_raw(j, "{\"position\":");
        json_position(j, it->height, it->idx);
        exp_json_raw(j, ",\"height\":");
        exp_json_u64(j, it->height);
        exp_json_raw(j, ",\"index\":");
        exp_json_u64(j, it->idx);
        exp_json_raw(j, ",\"time\":");
        exp_json_u64(j, it->block_time_ms);
        exp_json_raw(j, ",\"param_id\":");
        exp_json_u64(j, it->rec.param_id);
        exp_json_raw(j, ",\"param_name\":");
        if (pname) exp_json_str(j, pname); else exp_json_raw(j, "null");
        exp_json_raw(j, ",\"new_value\":");
        exp_json_u64_str(j, it->rec.new_value);
        exp_json_raw(j, ",\"effective_height\":");
        exp_json_u64(j, it->rec.effective);
        exp_json_raw(j, ",\"wire_id\":");
        if (it->has_wire_id) exp_json_hex(j, it->wire_id, 64); else exp_json_raw(j, "null");
        exp_json_raw(j, ",\"intent_id\":");
        if (it->has_intent_id) exp_json_hex(j, it->intent_id, 64); else exp_json_raw(j, "null");
        exp_json_raw(j, "}");
    }
    exp_json_raw(j, truncated ? "],\"truncated\":true}" : "],\"truncated\":false}");

    free(rows);
    *status = 200;
}

/* tx / seconds as a decimal string with exactly two decimals, rounded half
 * up, integer arithmetic only (no float reaches a reply). seconds >= 1. */
static void json_tps(exp_json_t *j, uint64_t tx, uint64_t seconds) {
    if (seconds == 0) seconds = 1;               /* unreachable: exp_db_query_tps */
    uint64_t whole = tx / seconds;
    uint64_t rem = tx % seconds;                 /* < seconds <= 3600: no overflow below */
    uint64_t centi = (rem * 200 + seconds) / (2 * seconds);
    if (centi == 100) {
        whole++;
        centi = 0;
    }
    char buf[48];
    snprintf(buf, sizeof(buf), "%llu.%02llu", (unsigned long long)whole, (unsigned long long)centi);
    exp_json_str(j, buf);
}

/* "tx":…,"blocks":…,"seconds":…,"tps":"…" (the caller adds the braces). */
static void emit_tps_fields(exp_json_t *j, const exp_tps_count_t *c, uint64_t seconds) {
    exp_json_raw(j, "\"tx\":");
    exp_json_u64(j, c->tx);
    exp_json_raw(j, ",\"blocks\":");
    exp_json_u64(j, c->blocks);
    exp_json_raw(j, ",\"seconds\":");
    exp_json_u64(j, seconds);
    exp_json_raw(j, ",\"tps\":");
    json_tps(j, c->tx, seconds);
}

/* ── APY estimate (/api/tps "apy") ──────────────────────────────────────
 * The operator's formula, display only:
 *   epochs_per_year = 31 557 600 s / (720 × avg_block_s over the last 24 h)
 *   yearly_reward   = reward_pool × (1 − (1 − 1/65536)^epochs_per_year)
 *   apy             = yearly_reward / active_stake
 * 1/65536: each epoch boundary pays reward_pool >> 16
 * (nodus_witness_v2_econ.c settlement_apply, NODUS_V2_GEN_REWARD_DIVISOR_LOG2
 * = 16, nodus_witness_v2_gen.h). An upper bound: a member that misses the
 * attendance bar leaves its share in the pool, fees that refill the pool
 * are ignored, and validator commission is not deducted. */
#define EXP_APY_YEAR_MS        31557600000.0     /* 365.25 days */
#define EXP_APY_REWARD_DIVISOR 65536.0

/* Two decimals of a finite, non-negative double; null otherwise. */
static void json_fixed2(exp_json_t *j, double v) {
    if (!isfinite(v) || v < 0.0) {
        exp_json_raw(j, "null");
        return;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%.2f", v);
    exp_json_str(j, buf);
}

/* "apy":{…} — every input as read (null when not known) and the result
 * (null unless every input is known and the stake is non-zero). */
static void emit_apy(exp_db_t *db, const exp_tps_t *t, exp_json_t *j) {
    uint8_t blob[EXP_SUPPLY_BUCKETS_BLOB_LEN];
    size_t len = 0;
    nodus_dnac_supply_buckets_t bk;
    int have_pool = exp_db_get_meta_blob(db, EXP_META_SUPPLY_BUCKETS, blob, sizeof(blob), &len) == 0 &&
                    exp_supply_buckets_unpack(blob, len, &bk) == 0 && bk.has;

    uint8_t sblob[EXP_ACTIVE_STAKE_BLOB_LEN];
    size_t slen = 0;
    exp_active_stake_t st;
    int have_stake = exp_db_get_meta_blob(db, EXP_META_ACTIVE_STAKE, sblob, sizeof(sblob), &slen) == 0 &&
                     exp_active_stake_unpack(sblob, slen, &st) == 0 && st.has;

    int have_epy = t->have_day_pace && t->day_avg_block_ms > 0;
    double epy = have_epy
        ? EXP_APY_YEAR_MS / ((double)EXP_EPOCH_BLOCKS * (double)t->day_avg_block_ms) : 0.0;

    exp_json_raw(j, "{\"reward_pool\":");
    if (have_pool) exp_json_u64_str(j, bk.reward_pool); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"active_stake\":");
    if (have_stake) exp_json_u64_str(j, st.stake); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"active_validators\":");
    if (have_stake) exp_json_u64(j, st.validators); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"stake_at_tip\":");
    if (have_stake) exp_json_u64(j, st.at_tip); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"avg_block_ms\":");
    if (t->have_day_pace) exp_json_u64(j, t->day_avg_block_ms); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"epochs_per_year\":");
    if (have_epy) json_fixed2(j, epy); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"apy\":");
    if (have_pool && have_stake && st.stake > 0 && have_epy) {
        double kept = exp(epy * log1p(-1.0 / EXP_APY_REWARD_DIVISOR));  /* (1 − 1/65536)^epy */
        double yearly = (double)bk.reward_pool * (1.0 - kept);
        json_fixed2(j, yearly / (double)st.stake * 100.0);
    } else {
        exp_json_raw(j, "null");
    }
    exp_json_raw(j, "}");
}

/* /api/tps — applied transactions per second over the last minute, the
 * last hour and the last 24 UTC hours, the next payday estimate, the past
 * paydays and the APY estimate (exp_db_query_tps, emit_apy). The
 * throughput, payday and pace figures are read off the index by block
 * time: now_ms is the newest indexed block's time, not this host's clock.
 * The APY's pool and stake are the last accepted node observation (meta).
 * An empty index answers nulls and []. */
static void route_tps(exp_db_t *db, exp_json_t *j, int *status) {
    exp_tps_t t;
    if (exp_db_query_tps(db, &t) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }
    if (!t.have) {
        exp_json_raw(j, "{\"now_ms\":null,\"last_minute\":null,\"last_hour\":null,"
                        "\"next_payday\":null,\"paydays\":[],\"apy\":null,\"history\":[]}");
        *status = 200;
        return;
    }

    exp_json_raw(j, "{\"now_ms\":");
    exp_json_u64(j, t.now_ms);
    exp_json_raw(j, ",\"last_minute\":{");
    emit_tps_fields(j, &t.last_minute, 60);
    exp_json_raw(j, "},\"last_hour\":{");
    emit_tps_fields(j, &t.last_hour, EXP_TPS_HOUR_MS / 1000);
    /* an estimate at the current block pace (exp_db.h exp_payday_t) */
    exp_json_raw(j, "},\"next_payday\":{\"height\":");
    exp_json_u64(j, t.payday.height);
    exp_json_raw(j, ",\"blocks_left\":");
    exp_json_u64(j, t.payday.blocks_left);
    exp_json_raw(j, ",\"avg_block_ms\":");
    if (t.payday.have_pace) exp_json_u64(j, t.payday.avg_block_ms); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"est_ms\":");
    if (t.payday.have_pace) exp_json_u64(j, t.payday.est_ms); else exp_json_raw(j, "null");
    /* past paydays, newest first: height + block time only (exp_db.h
     * exp_payday_row_t — no source of a payday's total is readable) */
    exp_json_raw(j, "},\"paydays\":[");
    for (int i = 0; i < t.n_paydays; i++) {
        if (i) exp_json_raw(j, ",");
        exp_json_raw(j, "{\"height\":");
        exp_json_u64(j, t.paydays[i].height);
        exp_json_raw(j, ",\"time\":");
        exp_json_u64(j, t.paydays[i].time_ms);
        exp_json_raw(j, "}");
    }
    exp_json_raw(j, "],\"apy\":");
    emit_apy(db, &t, j);
    exp_json_raw(j, ",\"history\":[");
    for (int i = 0; i < t.n_history; i++) {
        const exp_tps_bucket_t *b = &t.history[i];
        if (i) exp_json_raw(j, ",");
        exp_json_raw(j, "{\"start_ms\":");
        exp_json_u64(j, b->start_ms);
        exp_json_raw(j, ",");
        emit_tps_fields(j, &b->count, b->seconds);
        exp_json_raw(j, "}");
    }
    exp_json_raw(j, "]}");
    *status = 200;
}

/* ── The chain-backed balance source (contract: exp_http.h) ─────────── */

typedef struct {
    int      used;
    char     owner[129];
    uint64_t at_ms;
    nodus_dnac_balance_result_t res;
} exp_balance_slot_t;

struct exp_balance_chain {
    exp_chain_t        *chain;
    exp_balance_slot_t  slots[EXP_BALANCE_CACHE_SLOTS];
};

/* CLOCK_MONOTONIC in ms — the cache's age only (display data, no
 * consensus path). @return 0 / -1 (the cache is then bypassed). */
static int mono_ms(uint64_t *out) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
    *out = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    return 0;
}

/* Deep copy (the token list is heap). @return 0 / -1 (dst left empty). */
static int balance_copy(nodus_dnac_balance_result_t *dst,
                        const nodus_dnac_balance_result_t *src) {
    memset(dst, 0, sizeof(*dst));
    if (src->count > 0) {
        if (!src->tokens || src->count > NODUS_DNAC_BALANCE_MAX_TOKENS) return -1;
        dst->tokens = malloc(src->count * sizeof(*dst->tokens));
        if (!dst->tokens) return -1;
        memcpy(dst->tokens, src->tokens, src->count * sizeof(*dst->tokens));
    }
    dst->count = src->count;
    dst->tip = src->tip;
    return 0;
}

static int balance_chain_get(void *vctx, const char *owner_hex,
                             nodus_dnac_balance_result_t *out) {
    exp_balance_chain_t *b = (exp_balance_chain_t *)vctx;
    if (!b || !owner_hex || !out) return -1;
    memset(out, 0, sizeof(*out));

    uint64_t now = 0;
    int have_now = (mono_ms(&now) == 0);

    if (have_now) {
        for (int i = 0; i < EXP_BALANCE_CACHE_SLOTS; i++) {
            exp_balance_slot_t *s = &b->slots[i];
            if (s->used && strcmp(s->owner, owner_hex) == 0 &&
                now >= s->at_ms && now - s->at_ms <= EXP_BALANCE_CACHE_TTL_MS) {
                if (balance_copy(out, &s->res) == 0) return 0;
                break;                     /* allocation: ask the node */
            }
        }
    }

    if (exp_chain_balance(b->chain, owner_hex, out) != 0) {
        nodus_client_free_balance_result(out);
        return -1;                         /* a failure is never cached */
    }

    if (have_now && strlen(owner_hex) == 128) {
        /* the owner's own slot, else a free one, else the oldest */
        exp_balance_slot_t *slot = NULL;
        for (int i = 0; i < EXP_BALANCE_CACHE_SLOTS && !slot; i++)
            if (b->slots[i].used && strcmp(b->slots[i].owner, owner_hex) == 0)
                slot = &b->slots[i];
        for (int i = 0; i < EXP_BALANCE_CACHE_SLOTS && !slot; i++)
            if (!b->slots[i].used) slot = &b->slots[i];
        if (!slot) {
            slot = &b->slots[0];
            for (int i = 1; i < EXP_BALANCE_CACHE_SLOTS; i++)
                if (b->slots[i].at_ms < slot->at_ms) slot = &b->slots[i];
        }
        nodus_client_free_balance_result(&slot->res);
        slot->used = 0;
        if (balance_copy(&slot->res, out) == 0) {
            memcpy(slot->owner, owner_hex, 129);
            slot->at_ms = now;
            slot->used = 1;
        }
    }
    return 0;
}

int exp_balance_chain_open(exp_balance_chain_t **out, exp_chain_t *chain) {
    if (!out) return -1;
    *out = NULL;
    if (!chain) return -1;
    exp_balance_chain_t *b = calloc(1, sizeof(*b));
    if (!b) return -1;
    b->chain = chain;
    *out = b;
    return 0;
}

void exp_balance_chain_close(exp_balance_chain_t *b) {
    if (!b) return;
    for (int i = 0; i < EXP_BALANCE_CACHE_SLOTS; i++)
        nodus_client_free_balance_result(&b->slots[i].res);
    free(b);
}

void exp_balance_source_chain(exp_balance_source_t *src,
                              exp_balance_chain_t *b) {
    if (!src) return;
    src->ctx = b;
    src->get = balance_chain_get;
}

/* "balances" + "balance_status" (the leading comma included). */
static void emit_balances(exp_json_t *j, int have,
                          const nodus_dnac_balance_result_t *bal) {
    if (!have) {
        exp_json_raw(j, ",\"balances\":null,\"balance_status\":\"unavailable\"");
        return;
    }
    exp_json_raw(j, ",\"balances\":[");
    for (size_t i = 0; i < bal->count; i++) {
        const nodus_dnac_balance_token_t *tk = &bal->tokens[i];
        if (i) exp_json_raw(j, ",");
        exp_json_raw(j, "{\"token_id\":");
        exp_json_hex(j, tk->token_id, 64);
        exp_json_raw(j, ",\"total\":");
        exp_json_u64_str(j, tk->total);
        exp_json_raw(j, ",\"spendable\":");
        exp_json_u64_str(j, tk->spendable);
        exp_json_raw(j, ",\"coins\":");
        exp_json_u64(j, tk->coins);
        exp_json_raw(j, "}");
    }
    exp_json_raw(j, "],\"balance_status\":\"ok\"");
}

/* /api/address/<fp>?before=<height:index>&limit=<n> — the items touching
 * the address, newest first; "next_before" is the cursor of the next page
 * (null when this page is short). "balances" comes from ctx->balance (the
 * node's dnac_balance), fetched BEFORE the index read lock is taken: the
 * round trip never runs under ctx->db_lock. */
static void route_address(exp_http_ctx_t *ctx, const char *fp, const char *query,
                          exp_json_t *j, int *status) {
    if (!is_hash128(fp)) {
        json_error(j, "invalid address fingerprint (expected 128-hex)");
        *status = 400;
        return;
    }

    uint64_t before_h = UINT64_MAX;
    uint32_t before_i = UINT32_MAX;
    int limit;
    char val[48];
    if (query_get(query, "before", val, sizeof(val)) && !parse_position(val, &before_h, &before_i)) {
        json_error(j, "invalid 'before' (expected height:index)");
        *status = 400;
        return;
    }
    if (parse_limit(query, EXP_HTTP_LIMIT_DEFAULT, &limit) != 0) {
        json_error(j, "invalid 'limit'");
        *status = 400;
        return;
    }

    exp_item_row_t *rows = malloc(sizeof(exp_item_row_t) * EXP_HTTP_LIMIT_MAX);
    if (!rows) {
        json_error(j, "out of memory");
        *status = 500;
        return;
    }

    /* the balance: no lock held (exp_http.h, db_lock) */
    nodus_dnac_balance_result_t bal;
    memset(&bal, 0, sizeof(bal));
    int have_bal = (ctx->balance && ctx->balance->get &&
                    ctx->balance->get(ctx->balance->ctx, fp, &bal) == 0);
    if (!have_bal) nodus_client_free_balance_result(&bal);

    /* the index: under the read lock, one *db deref (exp_http_route) */
    int count = 0;
    int db_rc;
    if (ctx->db_lock) pthread_rwlock_rdlock(ctx->db_lock);
    exp_db_t *db = ctx->db ? *ctx->db : NULL;
    db_rc = db ? exp_db_query_address(db, fp, before_h, before_i, limit, rows, &count) : 1;
    if (ctx->db_lock) pthread_rwlock_unlock(ctx->db_lock);

    if (db_rc != 0) {
        free(rows);
        nodus_client_free_balance_result(&bal);
        json_error(j, db ? "query failed" : "index unavailable");
        *status = db ? 500 : 503;
        return;
    }

    exp_json_raw(j, "{\"address\":");
    exp_json_str(j, fp);
    emit_balances(j, have_bal, &bal);
    exp_json_raw(j, ",\"items\":[");
    for (int i = 0; i < count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_item_summary(j, &rows[i]);
    }
    exp_json_raw(j, "],\"next_before\":");
    if (count == limit) json_position(j, rows[count - 1].height, rows[count - 1].idx);
    else exp_json_raw(j, "null");
    exp_json_raw(j, "}");

    free(rows);
    nodus_client_free_balance_result(&bal);
    *status = 200;
}

static void emit_match(exp_json_t *j, int *wrote, const char *type, const char *target) {
    if (*wrote) exp_json_raw(j, ",");
    exp_json_raw(j, "{\"type\":");
    exp_json_str(j, type);
    exp_json_raw(j, ",\"target\":");
    exp_json_str(j, target);
    exp_json_raw(j, "}");
    *wrote = 1;
}

/* Every match is reported, never short-circuited on the first hit:
 * decimal -> block height; "height:index" -> tx position; 128-hex -> tx
 * (wire or intent id), block id, address (has indexed history); a legal
 * chain name (HF-4, dnac_name_bytes_ok — lower-case only, as the chain
 * stores it) -> "name", target = the registering item's position (an
 * all-digit name also matches the block-height branch: both are
 * reported). */
static void route_search(exp_db_t *db, const char *query, exp_json_t *j, int *status) {
    char q[512];
    if (!query_get(query, "q", q, sizeof(q)) || q[0] == '\0') {
        json_error(j, "missing 'q' parameter");
        *status = 400;
        return;
    }

    exp_json_raw(j, "{\"matches\":[");
    int wrote = 0;
    uint64_t h;
    uint32_t idx;

    if (is_all_decimal(q)) {
        if (parse_u64_strict(q, &h)) {
            exp_block_row_t row;
            if (exp_db_query_block_by_height(db, h, &row) == 0) emit_match(j, &wrote, "block", q);
        }
    } else if (parse_position(q, &h, &idx)) {
        exp_item_row_t it;
        if (exp_db_query_item(db, h, idx, &it) == 0) emit_match(j, &wrote, "tx", q);
    } else if (is_hash128(q)) {
        uint8_t bytes[64];
        hex128_decode(q, bytes);

        exp_item_row_t it;
        if (exp_db_query_item_by_id(db, bytes, &it) == 0) emit_match(j, &wrote, "tx", q);

        exp_block_row_t block_row;
        if (exp_db_query_block_by_id(db, bytes, &block_row) == 0) emit_match(j, &wrote, "block", q);

        exp_item_row_t probe;
        int n = 0;
        if (exp_db_query_address(db, q, UINT64_MAX, UINT32_MAX, 1, &probe, &n) == 0 && n > 0)
            emit_match(j, &wrote, "address", q);
    }
    if (dnac_name_bytes_ok((const uint8_t *)q, strlen(q))) {
        exp_item_row_t it;
        if (exp_db_query_item_by_name(db, q, &it) == 0) {
            char pos[48];
            snprintf(pos, sizeof(pos), "%llu:%u", (unsigned long long)it.height, (unsigned)it.idx);
            emit_match(j, &wrote, "name", pos);
        }
    }
    /* none of the shapes: empty matches — search is a lookup, not a
     * format validator. */

    exp_json_raw(j, "]}");
    *status = 200;
}

/* ── Dispatch ────────────────────────────────────────────────────────── */

static void route_index(exp_http_ctx_t *ctx, const char *path_only,
                        const char *query, exp_json_t *body_out,
                        int *status_out);

int exp_http_route(exp_http_ctx_t *ctx, const char *method, const char *path,
                    exp_json_t *body_out, int *status_out) {
    if (!ctx || !method || !path || !body_out || !status_out) return -1;

    exp_json_init(body_out);

    if (strcmp(method, "GET") != 0) {
        *status_out = 405;
        json_error(body_out, "method not allowed");
        return 0;
    }

    char path_only[1024];
    char query[4096];
    split_path_query(path, path_only, sizeof(path_only), query, sizeof(query));

    /* /api/address takes the read lock itself, AFTER its balance round
     * trip (route_address) — a witness query never runs under db_lock. */
    if (strncmp(path_only, "/api/address/", 13) == 0) {
        route_address(ctx, path_only + 13, query, body_out, status_out);
        return 0;
    }

    /* Every other route is index-only: the read lock spans the *db deref
     * and the queries, and is released before the caller writes the
     * response. */
    if (ctx->db_lock) pthread_rwlock_rdlock(ctx->db_lock);
    route_index(ctx, path_only, query, body_out, status_out);
    if (ctx->db_lock) pthread_rwlock_unlock(ctx->db_lock);
    return 0;
}

/* The index-only routes; the caller holds ctx->db_lock (when set). */
static void route_index(exp_http_ctx_t *ctx, const char *path_only,
                        const char *query, exp_json_t *body_out,
                        int *status_out) {
    /* ctx->db is exp_db_t** (the SAME location the sync thread's
     * handle_confirmed_reset swaps) — deref exactly once here, under the
     * rdlock span. A NULL *ctx->db is a real transient state (a reset's
     * reopen failure) — one check covers every route. */
    exp_db_t *db = ctx->db ? *ctx->db : NULL;
    if (!db) {
        *status_out = 503;
        json_error(body_out, "index unavailable");
        return;
    }

    if (strcmp(path_only, "/api/stats") == 0) {
        route_stats(db, body_out, status_out);
        return;
    }
    if (strcmp(path_only, "/api/blocks") == 0) {
        route_blocks(db, query, body_out, status_out);
        return;
    }
    if (strncmp(path_only, "/api/block/", 11) == 0) {
        route_block(db, path_only + 11, query, body_out, status_out);
        return;
    }
    if (strncmp(path_only, "/api/tx/", 8) == 0) {
        route_tx(db, path_only + 8, body_out, status_out);
        return;
    }
    if (strcmp(path_only, "/api/search") == 0) {
        route_search(db, query, body_out, status_out);
        return;
    }
    if (strcmp(path_only, "/api/governance") == 0) {
        route_governance(db, body_out, status_out);
        return;
    }
    if (strcmp(path_only, "/api/tps") == 0) {
        route_tps(db, body_out, status_out);
        return;
    }

    *status_out = 404;
    json_error(body_out, "not found");
}

/* ── Blocking poll() accept loop (Task 9 smoke, NOT unit-tested) ────── */

static const char *status_reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 503: return "Service Unavailable";
    default:  return "Internal Server Error";
    }
}

static void send_all(int fd, const void *data, size_t len) {
    const char *p = (const char *)data;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = write(fd, p + sent, len - sent);
        if (n < 0) {
            if (errno == EINTR) continue;
            QGP_LOG_WARN(LOG_TAG, "write() failed: %s", strerror(errno));
            return;
        }
        if (n == 0) return; /* peer gone */
        sent += (size_t)n;
    }
}

static void send_response(int fd, int status, const char *body) {
    size_t body_len = body ? strlen(body) : 0;

    char header[256];
    int hn = snprintf(header, sizeof(header),
                       "HTTP/1.1 %d %s\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %zu\r\n"
                       "Connection: close\r\n"
                       "\r\n",
                       status, status_reason(status), body_len);
    if (hn <= 0) return;

    send_all(fd, header, (size_t)hn);
    if (body_len > 0) send_all(fd, body, body_len);
}

static void handle_client(exp_http_ctx_t *ctx, int cfd) {
    /* fix round 1, finding 2: was `static`, which made this buffer shared
     * across every connection handled by this thread — harmless today
     * (handle_client runs strictly sequentially on the single serve
     * thread), but Task 7 adds concurrency on this path, and a shared
     * static buffer across concurrent clients is a guaranteed data race.
     * 8KB+1 is trivial on the serve thread's stack, so make it a plain
     * stack array now instead of waiting for Task 7 to hit the bug. */
    char req[EXP_HTTP_MAX_REQUEST + 1];
    size_t total = 0;
    int got_line = 0;

    while (total < EXP_HTTP_MAX_REQUEST) {
        ssize_t n = recv(cfd, req + total, EXP_HTTP_MAX_REQUEST - total, 0);
        if (n <= 0) break;
        total += (size_t)n;
        req[total] = '\0';
        if (memchr(req, '\n', total) != NULL) { got_line = 1; break; }
    }

    if (!got_line) {
        if (total >= EXP_HTTP_MAX_REQUEST) {
            send_response(cfd, 413, "{\"error\":\"request too large\"}");
        } else {
            send_response(cfd, 400, "{\"error\":\"malformed request\"}");
        }
        close(cfd);
        return;
    }

    /* Isolate the request line: "METHOD PATH HTTP/1.1". */
    char *line_end = strchr(req, '\n');
    size_t line_len = (size_t)(line_end - req);
    if (line_len > 0 && req[line_len - 1] == '\r') line_len--;

    char line[2200];
    if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
    memcpy(line, req, line_len);
    line[line_len] = '\0';

    char method[16] = {0};
    char reqpath[2048] = {0};
    if (sscanf(line, "%15s %2047s", method, reqpath) != 2) {
        send_response(cfd, 400, "{\"error\":\"malformed request line\"}");
        close(cfd);
        return;
    }

    exp_json_t body;
    int status = 500;

    /* Task 7 (db-swap race): exp_http_route takes the rdlock itself for
     * exactly the db access (and NOT around /api/address's balance round
     * trip); it is released before send_response's socket I/O. */
    exp_http_route(ctx, method, reqpath, &body, &status);

    send_response(cfd, status, body.buf ? body.buf : "{}");
    exp_json_freebuf(&body);

    close(cfd);
}

int exp_http_serve(exp_http_ctx_t *ctx) {
    /* ctx->db is exp_db_t** (fix round 1, C1) — this only checks that the
     * double-pointer itself was wired up (main.c always passes `&db`, a
     * real stack address, so `!ctx->db` here can only mean a caller bug,
     * never "index temporarily unavailable"). Whether *ctx->db is non-NULL
     * *right now* is a legitimately time-varying question (the sync thread
     * can transiently NULL it across a chain-reset swap) — that's checked
     * per-request in exp_http_route, not here at startup. */
    if (!ctx || !ctx->db || !ctx->stop) {
        QGP_LOG_ERROR(LOG_TAG, "exp_http_serve: invalid ctx");
        return -1;
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "socket() failed: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(ctx->port);
    /* G2 (hard security rule): bind 127.0.0.1 ONLY, never INADDR_ANY. */
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        QGP_LOG_ERROR(LOG_TAG, "inet_pton(127.0.0.1) failed");
        close(lfd);
        return -1;
    }

    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "bind(127.0.0.1:%u) failed: %s", (unsigned)ctx->port, strerror(errno));
        close(lfd);
        return -1;
    }

    if (listen(lfd, 16) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "listen() failed: %s", strerror(errno));
        close(lfd);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "HTTP API listening on 127.0.0.1:%u", (unsigned)ctx->port);

    while (!*ctx->stop) {
        struct pollfd pfd;
        pfd.fd = lfd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int rc = poll(&pfd, 1, 1000); /* 1s timeout so *ctx->stop is checked promptly */
        if (rc < 0) {
            if (errno == EINTR) continue;
            QGP_LOG_ERROR(LOG_TAG, "poll() failed: %s", strerror(errno));
            break;
        }
        if (rc == 0) continue; /* timeout — recheck stop flag */

        if (pfd.revents & POLLIN) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                QGP_LOG_WARN(LOG_TAG, "accept() failed: %s", strerror(errno));
                continue;
            }
            handle_client(ctx, cfd);
        }
    }

    close(lfd);
    QGP_LOG_INFO(LOG_TAG, "HTTP API stopped");
    return 0;
}
