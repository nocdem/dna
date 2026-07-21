/* exp_http — DNAC Explorer read-only JSON HTTP API. See exp_http.h. */

#include "exp_http.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "dnac/transaction.h"     /* DNAC_TX_MAX_INPUTS / DNAC_TX_MAX_OUTPUTS */
#include "nodus/nodus.h"          /* nodus_client_free_utxo_result */

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_HTTP"

/* ── Small parsing / formatting helpers (no I/O) ────────────────────── */

/* Hard limit G3: list endpoints clamp to <= 100 rows, default 25. */
#define EXP_HTTP_LIMIT_DEFAULT 25
#define EXP_HTTP_LIMIT_MAX     100

/* 8 KB request line/header buffer (G3) — anything longer is 413. */
#define EXP_HTTP_MAX_REQUEST 8192

/* input_count + output_count never exceeds this (dnac/transaction.h) —
 * same bound exp_sync.c uses for its io scratch buffer. */
#define EXP_HTTP_MAX_IOS (DNAC_TX_MAX_INPUTS + DNAC_TX_MAX_OUTPUTS)

/* A block's tx list has no fixed compile-time bound (DNAC_CFG_MAX_TXS_PER_BLOCK
 * is a runtime chain-config value, not a header constant) — heap-allocate a
 * generously-sized scratch array rather than risk an oversized stack frame
 * or a silently-too-small fixed one. */
#define EXP_HTTP_MAX_BLOCK_TXS 4096

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

/* Splits "path?query" into path_out/query_out (both NUL-terminated,
 * truncated defensively if they don't fit — a request line under 8 KB
 * always fits these generously-sized stack buffers in practice). No query
 * string ('?' absent) leaves query_out empty. */
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
 * (no percent-decoding — every value this API accepts is plain
 * digits/lowercase-hex/the literal "1", none of which needs it) into `out`.
 * Returns 1 if the key was present (even with an empty value), else 0. */
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

/* Parses the "before"/"limit" pagination pair shared by /api/blocks and
 * /api/address. before_out defaults to UINT64_MAX ("start from the most
 * recent row" — exp_db.h clamps this to INT64_MAX internally, same as the
 * tests' EXP_CURSOR_TOP). limit_out defaults to EXP_HTTP_LIMIT_DEFAULT and
 * is clamped to EXP_HTTP_LIMIT_MAX. Returns 0 on success, -1 on a malformed
 * (present but not a valid positive integer) before/limit value — the
 * caller turns that into a 400. */
static int parse_pagination(const char *query, uint64_t *before_out, int *limit_out) {
    *before_out = UINT64_MAX;
    *limit_out = EXP_HTTP_LIMIT_DEFAULT;

    char val[32];
    if (query_get(query, "before", val, sizeof(val))) {
        uint64_t parsed;
        if (!parse_u64_strict(val, &parsed)) return -1;
        *before_out = parsed;
    }
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

/* Signed balance (addr_stats.balance is a signed credits-minus-debits
 * accumulation, see exp_db.h) formatted as a plain JSON number, not a
 * string — magnitude computed without negating INT64_MIN (UB). */
static void json_i64(exp_json_t *j, int64_t v) {
    if (v < 0) {
        exp_json_raw(j, "-");
        uint64_t mag = (uint64_t)(-(v + 1)) + 1u;
        exp_json_u64(j, mag);
    } else {
        exp_json_u64(j, (uint64_t)v);
    }
}

/* ── Row -> JSON emitters ────────────────────────────────────────────── */

static void emit_block(exp_json_t *j, const exp_block_row_t *b) {
    exp_json_raw(j, "{\"height\":");
    exp_json_u64(j, b->height);
    exp_json_raw(j, ",\"block_hash\":");
    if (b->has_block_hash) exp_json_hex(j, b->block_hash, 64);
    else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"tx_root\":");
    exp_json_hex(j, b->tx_root, 64);
    exp_json_raw(j, ",\"timestamp\":");
    exp_json_u64(j, b->timestamp);
    exp_json_raw(j, ",\"proposer\":");
    exp_json_hex(j, b->proposer, 32);
    exp_json_raw(j, ",\"tx_count\":");
    exp_json_u64(j, b->tx_count);
    exp_json_raw(j, "}");
}

static void emit_tx_summary(exp_json_t *j, const exp_tx_row_t *t) {
    exp_json_raw(j, "{\"hash\":");
    exp_json_hex(j, t->hash, 64);
    exp_json_raw(j, ",\"seq\":");
    exp_json_u64(j, t->seq);
    exp_json_raw(j, ",\"height\":");
    exp_json_u64(j, t->height);
    exp_json_raw(j, ",\"tx_type\":");
    exp_json_u64(j, (uint64_t)t->tx_type);
    exp_json_raw(j, ",\"fee\":");
    exp_json_u64(j, t->fee);
    exp_json_raw(j, ",\"size\":");
    exp_json_u64(j, t->size);
    exp_json_raw(j, ",\"timestamp\":");
    exp_json_u64(j, t->timestamp);
    exp_json_raw(j, ",\"multi_signer\":");
    exp_json_u64(j, (uint64_t)t->multi_signer);
    exp_json_raw(j, "}");
}

static void emit_io(exp_json_t *j, const exp_io_row_t *io) {
    exp_json_raw(j, "{\"direction\":");
    exp_json_raw(j, io->direction == 1 ? "\"out\"" : "\"in\"");
    exp_json_raw(j, ",\"io_index\":");
    exp_json_u64(j, (uint64_t)io->io_index);
    exp_json_raw(j, ",\"address\":");
    exp_json_str(j, io->address);
    exp_json_raw(j, ",\"token_id\":");
    exp_json_hex(j, io->token_id, 64);
    exp_json_raw(j, ",\"amount\":");
    exp_json_u64(j, io->amount);
    exp_json_raw(j, "}");
}

static void emit_utxo_entry(exp_json_t *j, const nodus_dnac_utxo_entry_t *e) {
    exp_json_raw(j, "{\"nullifier\":");
    exp_json_hex(j, e->nullifier, sizeof(e->nullifier));
    exp_json_raw(j, ",\"owner\":");
    exp_json_str(j, e->owner);
    exp_json_raw(j, ",\"amount\":");
    exp_json_u64(j, e->amount);
    exp_json_raw(j, ",\"token_id\":");
    exp_json_hex(j, e->token_id, sizeof(e->token_id));
    exp_json_raw(j, ",\"tx_hash\":");
    exp_json_hex(j, e->tx_hash, sizeof(e->tx_hash));
    exp_json_raw(j, ",\"output_index\":");
    exp_json_u64(j, e->output_index);
    exp_json_raw(j, ",\"block_height\":");
    exp_json_u64(j, e->block_height);
    exp_json_raw(j, "}");
}

/* ── Endpoint handlers ───────────────────────────────────────────────── */

static void route_stats(exp_http_ctx_t *ctx, exp_json_t *j, int *status) {
    exp_db_t *db = ctx->db;

    uint64_t indexed_seq = 0, indexed_height = 0, tip_seq = 0;
    uint64_t supply_current = 0, supply_burned = 0, supply_genesis = 0;
    uint8_t chain_id[32];
    size_t chain_id_len = 0;

    int have_indexed_seq    = (exp_db_get_meta_u64(db, "last_indexed_seq", &indexed_seq) == 0);
    int have_indexed_height = (exp_db_get_meta_u64(db, "last_block_height", &indexed_height) == 0);
    int have_tip_seq        = (exp_db_get_meta_u64(db, "tip_seq", &tip_seq) == 0);
    int have_supply_current = (exp_db_get_meta_u64(db, "supply_current", &supply_current) == 0);
    int have_supply_burned  = (exp_db_get_meta_u64(db, "supply_burned", &supply_burned) == 0);
    int have_supply_genesis = (exp_db_get_meta_u64(db, "supply_genesis", &supply_genesis) == 0);
    int have_chain_id = (exp_db_get_meta_blob(db, "chain_id", chain_id, sizeof(chain_id), &chain_id_len) == 0
                          && chain_id_len == 32);

    exp_json_raw(j, "{\"indexed_seq\":");
    if (have_indexed_seq) exp_json_u64(j, indexed_seq); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"tip_seq\":");
    if (have_tip_seq) exp_json_u64(j, tip_seq); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"indexed_height\":");
    if (have_indexed_height) exp_json_u64(j, indexed_height); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"chain_id\":");
    if (have_chain_id) exp_json_hex(j, chain_id, 32); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_current\":");
    if (have_supply_current) exp_json_u64(j, supply_current); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_burned\":");
    if (have_supply_burned) exp_json_u64(j, supply_burned); else exp_json_raw(j, "null");
    exp_json_raw(j, ",\"supply_genesis\":");
    if (have_supply_genesis) exp_json_u64(j, supply_genesis); else exp_json_raw(j, "null");
    exp_json_raw(j, "}");

    *status = 200;
}

static void route_blocks(exp_http_ctx_t *ctx, const char *query, exp_json_t *j, int *status) {
    uint64_t before;
    int limit;
    if (parse_pagination(query, &before, &limit) != 0) {
        json_error(j, "invalid 'before'/'limit'");
        *status = 400;
        return;
    }

    exp_block_row_t rows[EXP_HTTP_LIMIT_MAX];
    int count = 0;
    if (exp_db_query_blocks(ctx->db, before, limit, rows, &count) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"blocks\":[");
    for (int i = 0; i < count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_block(j, &rows[i]);
    }
    exp_json_raw(j, "]}");
    *status = 200;
}

static void route_block(exp_http_ctx_t *ctx, const char *ident, exp_json_t *j, int *status) {
    exp_block_row_t row;
    int found;

    if (is_hash128(ident)) {
        uint8_t hash[64];
        hex128_decode(ident, hash);
        found = (exp_db_query_block_by_hash(ctx->db, hash, &row) == 0);
    } else if (is_all_decimal(ident)) {
        uint64_t height;
        if (!parse_u64_strict(ident, &height)) {
            json_error(j, "invalid block height");
            *status = 400;
            return;
        }
        found = (exp_db_query_block_by_height(ctx->db, height, &row) == 0);
    } else {
        json_error(j, "invalid block identifier (expected height or 128-hex hash)");
        *status = 400;
        return;
    }

    if (!found) {
        json_error(j, "block not found");
        *status = 404;
        return;
    }

    exp_tx_row_t *txs = malloc(sizeof(exp_tx_row_t) * EXP_HTTP_MAX_BLOCK_TXS);
    if (!txs) {
        json_error(j, "out of memory");
        *status = 500;
        return;
    }

    int tx_count = 0;
    if (exp_db_query_txs_by_height(ctx->db, row.height, txs, EXP_HTTP_MAX_BLOCK_TXS, &tx_count) != 0) {
        free(txs);
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"block\":");
    emit_block(j, &row);
    exp_json_raw(j, ",\"txs\":[");
    for (int i = 0; i < tx_count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_tx_summary(j, &txs[i]);
    }
    exp_json_raw(j, "]}");

    free(txs);
    *status = 200;
}

static void route_tx(exp_http_ctx_t *ctx, const char *ident, exp_json_t *j, int *status) {
    if (!is_hash128(ident)) {
        json_error(j, "invalid tx hash (expected 128-hex)");
        *status = 400;
        return;
    }

    uint8_t hash[64];
    hex128_decode(ident, hash);

    exp_tx_row_t tx;
    exp_io_row_t ios[EXP_HTTP_MAX_IOS];
    int io_count = 0;
    uint8_t *raw = NULL;
    size_t raw_len = 0;

    if (exp_db_query_tx(ctx->db, hash, &tx, ios, EXP_HTTP_MAX_IOS, &io_count, &raw, &raw_len) != 0) {
        json_error(j, "tx not found");
        *status = 404;
        return;
    }

    exp_json_raw(j, "{\"tx\":");
    emit_tx_summary(j, &tx);
    exp_json_raw(j, ",\"ios\":[");
    for (int i = 0; i < io_count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_io(j, &ios[i]);
    }
    exp_json_raw(j, "],\"raw\":");
    if (raw && raw_len > 0) exp_json_hex(j, raw, raw_len);
    else exp_json_raw(j, "null");
    exp_json_raw(j, "}");

    free(raw);
    *status = 200;
}

static void route_address(exp_http_ctx_t *ctx, const char *fp, const char *query,
                           exp_json_t *j, int *status) {
    if (!is_hash128(fp)) {
        json_error(j, "invalid address fingerprint (expected 128-hex)");
        *status = 400;
        return;
    }

    uint64_t before;
    int limit;
    if (parse_pagination(query, &before, &limit) != 0) {
        json_error(j, "invalid 'before'/'limit'");
        *status = 400;
        return;
    }

    int want_utxos = 0;
    char val[8];
    if (query_get(query, "utxos", val, sizeof(val)) && strcmp(val, "1") == 0) {
        want_utxos = 1;
    }

    /* native DNAC = all-zero token_id (design doc §3 F5 / brief). Per the
     * design doc's stated v1 scope ("v1 UI renders only the native DNAC
     * token; other tokens display as 'token balances present' without
     * detail pages") this endpoint surfaces the native balance in full and
     * does not attempt to enumerate every token_id ever touched by this
     * address — exp_db.h has no such enumeration query, only per-key
     * balance lookups. */
    uint8_t native_token[64];
    memset(native_token, 0, sizeof(native_token));
    uint64_t native_balance = 0, native_txc = 0;
    /* fix round 1, finding 3: was previously ignored — a real DB error
     * (-1) fell through with native_balance/native_txc left at their
     * zero-initialized values and rendered as a legitimate zero balance
     * instead of surfacing the failure. */
    if (exp_db_query_balance(ctx->db, fp, native_token, &native_balance, &native_txc) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_tx_row_t rows[EXP_HTTP_LIMIT_MAX];
    int count = 0;
    if (exp_db_query_address(ctx->db, fp, before, limit, rows, &count) != 0) {
        json_error(j, "query failed");
        *status = 500;
        return;
    }

    exp_json_raw(j, "{\"balances\":[{\"token\":\"DNAC\",\"token_id\":");
    exp_json_hex(j, native_token, 64);
    exp_json_raw(j, ",\"balance\":");
    json_i64(j, (int64_t)native_balance);
    exp_json_raw(j, ",\"tx_count\":");
    exp_json_u64(j, native_txc);
    exp_json_raw(j, "}]");

    exp_json_raw(j, ",\"txs\":[");
    for (int i = 0; i < count; i++) {
        if (i) exp_json_raw(j, ",");
        emit_tx_summary(j, &rows[i]);
    }
    exp_json_raw(j, "]");

    if (want_utxos) {
        exp_json_raw(j, ",\"utxos\":");
        if (!ctx->chain) {
            exp_json_raw(j, "{\"source\":\"witness-live\",\"error\":\"unavailable\"}");
        } else {
            nodus_dnac_utxo_result_t ur;
            memset(&ur, 0, sizeof(ur));
            if (exp_chain_utxos(ctx->chain, fp, &ur) != 0) {
                exp_json_raw(j, "{\"source\":\"witness-live\",\"error\":\"unavailable\"}");
            } else {
                exp_json_raw(j, "{\"source\":\"witness-live\",\"block_height\":");
                exp_json_u64(j, ur.block_height);
                exp_json_raw(j, ",\"entries\":[");
                for (int i = 0; i < ur.count; i++) {
                    if (i) exp_json_raw(j, ",");
                    emit_utxo_entry(j, &ur.entries[i]);
                }
                exp_json_raw(j, "]}");
                nodus_client_free_utxo_result(&ur);
            }
        }
    }

    exp_json_raw(j, "}");
    *status = 200;
}

/* precedence: tx hash -> block hash -> address (F7). ALL matches are
 * reported, never short-circuited on the first hit. */
static void route_search(exp_http_ctx_t *ctx, const char *query, exp_json_t *j, int *status) {
    char q[512];
    if (!query_get(query, "q", q, sizeof(q)) || q[0] == '\0') {
        json_error(j, "missing 'q' parameter");
        *status = 400;
        return;
    }

    exp_json_raw(j, "{\"matches\":[");
    int wrote = 0;

    if (is_all_decimal(q)) {
        uint64_t height;
        if (parse_u64_strict(q, &height)) {
            exp_block_row_t row;
            if (exp_db_query_block_by_height(ctx->db, height, &row) == 0) {
                exp_json_raw(j, "{\"type\":\"block\",\"target\":");
                exp_json_str(j, q);
                exp_json_raw(j, "}");
                wrote = 1;
            }
        }
    } else if (is_hash128(q)) {
        uint8_t bytes[64];
        hex128_decode(q, bytes);

        exp_tx_row_t tx_row;
        int io_count_tmp = 0;
        if (exp_db_query_tx(ctx->db, bytes, &tx_row, NULL, 0, &io_count_tmp, NULL, NULL) == 0) {
            if (wrote) exp_json_raw(j, ",");
            exp_json_raw(j, "{\"type\":\"tx\",\"target\":");
            exp_json_str(j, q);
            exp_json_raw(j, "}");
            wrote = 1;
        }

        exp_block_row_t block_row;
        if (exp_db_query_block_by_hash(ctx->db, bytes, &block_row) == 0) {
            if (wrote) exp_json_raw(j, ",");
            exp_json_raw(j, "{\"type\":\"block\",\"target\":");
            exp_json_str(j, q);
            exp_json_raw(j, "}");
            wrote = 1;
        }

        exp_tx_row_t addr_probe[1];
        int addr_count = 0;
        if (exp_db_query_address(ctx->db, q, UINT64_MAX, 1, addr_probe, &addr_count) == 0 && addr_count > 0) {
            if (wrote) exp_json_raw(j, ",");
            exp_json_raw(j, "{\"type\":\"address\",\"target\":");
            exp_json_str(j, q);
            exp_json_raw(j, "}");
            wrote = 1;
        }
    }
    /* neither decimal nor 128-hex: no match shape applies — empty matches
     * array, not an error (F7: search is a lookup, not a format validator). */

    exp_json_raw(j, "]}");
    *status = 200;
}

/* ── Dispatch ────────────────────────────────────────────────────────── */

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

    if (strcmp(path_only, "/api/stats") == 0) {
        route_stats(ctx, body_out, status_out);
        return 0;
    }
    if (strcmp(path_only, "/api/blocks") == 0) {
        route_blocks(ctx, query, body_out, status_out);
        return 0;
    }
    if (strncmp(path_only, "/api/block/", 11) == 0) {
        route_block(ctx, path_only + 11, body_out, status_out);
        return 0;
    }
    if (strncmp(path_only, "/api/tx/", 8) == 0) {
        route_tx(ctx, path_only + 8, body_out, status_out);
        return 0;
    }
    if (strncmp(path_only, "/api/address/", 13) == 0) {
        route_address(ctx, path_only + 13, query, body_out, status_out);
        return 0;
    }
    if (strcmp(path_only, "/api/search") == 0) {
        route_search(ctx, query, body_out, status_out);
        return 0;
    }

    *status_out = 404;
    json_error(body_out, "not found");
    return 0;
}

/* ── Blocking poll() accept loop (Task 9 smoke, NOT unit-tested) ────── */

static const char *status_reason(int status) {
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
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

    /* Task 7 (db-swap race): rdlock spans exactly the db access — the
     * exp_http_route call — and is released before send_response's socket
     * I/O. NULL ctx->db_lock (unit tests) skips locking entirely. */
    if (ctx->db_lock) pthread_rwlock_rdlock(ctx->db_lock);
    exp_http_route(ctx, method, reqpath, &body, &status);
    if (ctx->db_lock) pthread_rwlock_unlock(ctx->db_lock);

    send_response(cfd, status, body.buf ? body.buf : "{}");
    exp_json_freebuf(&body);

    close(cfd);
}

int exp_http_serve(exp_http_ctx_t *ctx) {
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
