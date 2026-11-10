/**
 * @file amm_cfg.c
 * @brief nodus-amm settings parser (see amm_cfg.h).
 */
#include "amm_cfg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFG_FILE_MAX 16384u

/* The plan's USDT contract (section 5), lowercase, no 0x. */
#define USDT_MAINNET_HEX "dac17f958d2ee523a2206206994597c13d831ec7"

/* ── key table ────────────────────────────────────────────────────────── */

typedef struct {
    const char *name;
    size_t      off;       /* offset of the uint64_t field in amm_cfg_t    */
    uint64_t    lo, hi;    /* inclusive bounds                             */
    int         required;
} u64_key_t;

#define HI_MAX (UINT64_MAX / 4)

static const u64_key_t U64_KEYS[] = {
    {"eth_conf_bound_1_usdt",      offsetof(amm_cfg_t, eth_conf_bound_1_usdt),      1, HI_MAX, 0},
    {"eth_conf_bound_2_usdt",      offsetof(amm_cfg_t, eth_conf_bound_2_usdt),      1, HI_MAX, 0},
    {"eth_conf_count_1",           offsetof(amm_cfg_t, eth_conf_count_1),           1, 100,    0},
    {"eth_conf_count_2",           offsetof(amm_cfg_t, eth_conf_count_2),           1, 100,    0},
    {"eth_conf_count_3",           offsetof(amm_cfg_t, eth_conf_count_3),           1, 100,    0},
    {"swap_max_usdt",              offsetof(amm_cfg_t, swap_max_usdt),              1, HI_MAX, 0},
    {"inflight_max_usdt",          offsetof(amm_cfg_t, inflight_max_usdt),          1, HI_MAX, 0},
    {"pool_start_usdt",            offsetof(amm_cfg_t, pool_start_usdt),            1, HI_MAX, 0},
    {"pool_start_nodus",           offsetof(amm_cfg_t, pool_start_nodus),           1, HI_MAX, 0},
    {"liquidity_wait_eth_blocks",  offsetof(amm_cfg_t, liquidity_wait_eth_blocks),  1, HI_MAX, 0},
    {"liquidity_wait_nodus_blocks",offsetof(amm_cfg_t, liquidity_wait_nodus_blocks),1, HI_MAX, 0},
    {"eth_reorg_window_blocks",    offsetof(amm_cfg_t, eth_reorg_window_blocks),    1, HI_MAX, 1},
    {"approval_valid_seconds",     offsetof(amm_cfg_t, approval_valid_seconds),     1, HI_MAX, 0},
    {"eth_chain_id",               offsetof(amm_cfg_t, eth_chain_id),               1, HI_MAX, 0},
    {"commission",                 offsetof(amm_cfg_t, commission),                 0, 0,      0},
    {"payout_final_depth_eth",     offsetof(amm_cfg_t, payout_final_depth_eth),     1, HI_MAX, 1},
    {"http_max_body",              offsetof(amm_cfg_t, http_max_body),              1, HI_MAX, 1},
    {"http_max_response",          offsetof(amm_cfg_t, http_max_response),          1, HI_MAX, 1},
    {"swap_min_usdt",              offsetof(amm_cfg_t, swap_min_usdt),              1, HI_MAX, 0},
    {"eth_price_min_sources",      offsetof(amm_cfg_t, eth_price_min_sources),      1, 4,      0},
    {"eth_price_max_age_seconds",  offsetof(amm_cfg_t, eth_price_max_age_seconds),  1, HI_MAX, 0},
    {"http_port",                  offsetof(amm_cfg_t, http_port),                  1, 65535,  1},
    {"http_conn_cap",              offsetof(amm_cfg_t, http_conn_cap),              1, 64,     1},
    {"http_timeout_ms",            offsetof(amm_cfg_t, http_timeout_ms),            1, HI_MAX, 1},
    {"worker_interval_ms",         offsetof(amm_cfg_t, worker_interval_ms),         1, HI_MAX, 1},
    {"rpc_timeout_ms",             offsetof(amm_cfg_t, rpc_timeout_ms),             1, HI_MAX, 1},
    {"eth_start_height",           offsetof(amm_cfg_t, eth_start_height),           1, HI_MAX, 1},
    {"nodus_start_height",         offsetof(amm_cfg_t, nodus_start_height),         1, HI_MAX, 1},
    {"eth_max_scan_blocks",        offsetof(amm_cfg_t, eth_max_scan_blocks),        1, HI_MAX, 1},
    {"nodus_page_limit",           offsetof(amm_cfg_t, nodus_page_limit),           1, 100,    1},
    {"nodus_max_pages",            offsetof(amm_cfg_t, nodus_max_pages),            1, HI_MAX, 1},
    {"nodus_expiry_ahead",         offsetof(amm_cfg_t, nodus_expiry_ahead),         1, 100,    1},
    {"nodus_resubmit_blocks",      offsetof(amm_cfg_t, nodus_resubmit_blocks),      1, HI_MAX, 1},
    {"nodus_scan_blocks",          offsetof(amm_cfg_t, nodus_scan_blocks),          1, HI_MAX, 1},
};
#define N_U64 (sizeof(U64_KEYS) / sizeof(U64_KEYS[0]))

/* Required non-u64 keys, one bit each; the required u64 keys are tracked by
 * their table index in seen_u64. */
enum {
    REQ_NODE_HOST = 1u << 0, REQ_NODE_PORT = 1u << 1, REQ_NODE_FP  = 1u << 2,
    REQ_CHAIN_ID  = 1u << 3, REQ_JOURNAL   = 1u << 4, REQ_PROVIDERS = 1u << 5,
    REQ_QUORUM    = 1u << 6, REQ_FOUND_ETH = 1u << 7, REQ_FOUND_NODUS = 1u << 8,
    REQ_EIP712    = 1u << 10, REQ_ORIGIN = 1u << 11,
    REQ_HELD_ROOM = 1u << 12, REQ_ETH_KEY = 1u << 13, REQ_NODUS_KEY = 1u << 14,
    REQ_LOCK      = 1u << 15
};

static char *trim(char *s);

/* ETH price source names (plan section 10), by bit. */
static const struct { const char *name; unsigned bit; } PRICE_NAMES[] = {
    {"kraken", AMM_PRICE_KRAKEN}, {"binance", AMM_PRICE_BINANCE},
    {"bitfinex", AMM_PRICE_BITFINEX}, {"coinbase", AMM_PRICE_COINBASE},
};

/* Comma separated source names, each at most once, no empty element. */
static int parse_price_sources(char *val, unsigned *mask) {
    unsigned m = 0;
    char *save = NULL;
    if (!*val || val[0] == ',' || val[strlen(val) - 1] == ',') return -1;
    for (const char *p = val; p[0] && p[1]; p++)
        if (p[0] == ',' && p[1] == ',') return -1;
    for (char *tok = strtok_r(val, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        tok = trim(tok);
        unsigned bit = 0;
        for (size_t i = 0; i < sizeof(PRICE_NAMES) / sizeof(PRICE_NAMES[0]); i++)
            if (!strcmp(tok, PRICE_NAMES[i].name)) bit = PRICE_NAMES[i].bit;
        if (!bit || (m & bit)) return -1;
        m |= bit;
    }
    if (!m) return -1;
    *mask = m;
    return 0;
}

void amm_cfg_defaults(amm_cfg_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->eth_conf_bound_1_usdt       = 100000000ULL;  /* 100 USDT, item 60  */
    cfg->eth_conf_bound_2_usdt       = 1000000000ULL; /* 1,000 USDT, item 60 */
    cfg->eth_conf_count_1            = 3;            /* item 60             */
    cfg->eth_conf_count_2            = 5;            /* item 60             */
    cfg->eth_conf_count_3            = 33;           /* item 60             */
    cfg->swap_max_usdt               = 100000000ULL; /* 100 USDT, item 19   */
    cfg->inflight_max_usdt           = 500000000ULL; /* 500 USDT, item 19   */
    cfg->pool_start_usdt             = 3000000000ULL;          /* item 20   */
    cfg->pool_start_nodus            = 3000000000000000ULL;    /* item 20   */
    cfg->liquidity_wait_eth_blocks   = 300;          /* item 25             */
    cfg->liquidity_wait_nodus_blocks = 3;            /* item 49             */
    cfg->approval_valid_seconds      = 300;          /* item 72: 5 minutes  */
    cfg->eth_chain_id                = 1;            /* item 77; Ethereum   */
    cfg->commission                  = 0;            /* item 73             */
    cfg->swap_min_usdt               = 1000000ULL;   /* item 89: 1 USDT     */
    cfg->eth_price_min_sources       = 3;            /* item 74             */
    cfg->eth_price_max_age_seconds   = 180;          /* item 74             */
    cfg->eth_price_sources           = AMM_PRICE_ALL; /* plan s.10, s.15    */
    for (int i = 0; i < 20; i++) {                   /* plan section 5      */
        unsigned v = 0;
        sscanf(USDT_MAINNET_HEX + 2 * i, "%2x", &v);
        cfg->usdt_contract[i] = (uint8_t)v;
    }
}

/* ── value helpers ────────────────────────────────────────────────────── */

static void set_err(char *err, size_t cap, const char *fmt, const char *a) {
    if (err && cap) snprintf(err, cap, fmt, a);
}

static int hex_exact(const char *s, uint8_t *out, size_t n) {
    if (strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < 2 * n; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int u64_strict(const char *s, uint64_t *out) {
    if (!*s) return -1;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r')) s[--n] = '\0';
    return s;
}

/* Printable ASCII (0x20..0x7e), 1..cap-1 bytes. */
static int printable(const char *s, size_t cap) {
    size_t n = strlen(s);
    if (n == 0 || n >= cap) return 0;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] > 0x7e) return 0;
    return 1;
}

/* An https URL: "https://" then at least one printable non-space byte, no
 * comma (the provider list separator) and no space. */
static int https_url(const char *s) {
    static const char P[] = "https://";
    size_t n = strlen(s);
    if (n <= sizeof(P) - 1 || n >= AMM_URL_MAX) return 0;
    if (strncmp(s, P, sizeof(P) - 1) != 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c > 0x7e || c == ',') return 0;
    }
    return 1;
}

/* Comma separated https URLs into cfg->eth_providers. A duplicate URL, an
 * empty element or more than AMM_MAX_PROVIDERS is a refusal. */
static int parse_providers(char *val, amm_cfg_t *cfg) {
    int n = 0;
    char *save = NULL;
    for (char *tok = strtok_r(val, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        tok = trim(tok);
        if (!https_url(tok) || n >= AMM_MAX_PROVIDERS) return -1;
        for (int i = 0; i < n; i++)
            if (!strcmp(cfg->eth_providers[i], tok)) return -1;
        memcpy(cfg->eth_providers[n], tok, strlen(tok) + 1);
        n++;
    }
    if (n == 0) return -1;
    cfg->n_providers = n;
    return 0;
}

/* An empty element between commas ("a,,b", leading or trailing comma) is
 * invisible to strtok_r, so it is checked on the raw value. */
static int commas_clean(const char *val) {
    size_t n = strlen(val);
    if (n == 0 || val[0] == ',' || val[n - 1] == ',') return 0;
    for (size_t i = 0; i + 1 < n; i++)
        if (val[i] == ',' && val[i + 1] == ',') return 0;
    return 1;
}

static int bool01(const char *val, int *out) {
    if (!strcmp(val, "0")) { *out = 0; return 0; }
    if (!strcmp(val, "1")) { *out = 1; return 0; }
    return -1;
}

/* ── parse ────────────────────────────────────────────────────────────── */

int amm_cfg_parse(const char *text, amm_cfg_t *cfg, char *err, size_t err_cap) {
    if (!text || !cfg) return -1;
    amm_cfg_defaults(cfg);
    size_t tlen = strlen(text);
    if (tlen > CFG_FILE_MAX) {
        set_err(err, err_cap, "%s", "config file too large");
        return -1;
    }
    char *buf = malloc(tlen + 1);
    if (!buf) return -1;
    memcpy(buf, text, tlen + 1);

    unsigned seen = 0;                 /* required keys seen               */
    uint64_t seen_u64 = 0;             /* u64 keys seen (bit = table idx)  */
    unsigned seen_opt = 0;             /* optional non-u64 keys seen       */
    int rc = -1;
    char *save = NULL;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        line = trim(line);
        if (*line == '\0' || *line == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) { set_err(err, err_cap, "line without '=': %s", line); goto out; }
        *eq = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);
        uint64_t u = 0;
        int ok = 0;
        unsigned req = 0, opt = 0;

        /* u64 table first */
        size_t ti = N_U64;
        for (size_t i = 0; i < N_U64; i++)
            if (!strcmp(key, U64_KEYS[i].name)) { ti = i; break; }
        if (ti < N_U64) {
            const u64_key_t *k = &U64_KEYS[ti];
            ok = u64_strict(val, &u) == 0 && u >= k->lo && u <= k->hi;
            if (!ok) { set_err(err, err_cap, "bad value for key: %s", key); goto out; }
            if (seen_u64 & (1ULL << ti)) {
                set_err(err, err_cap, "duplicate key: %s", key);
                goto out;
            }
            seen_u64 |= 1ULL << ti;
            memcpy((char *)cfg + k->off, &u, sizeof(u));
            continue;
        }

        if (!strcmp(key, "node_host")) {
            req = REQ_NODE_HOST;
            ok = *val && strlen(val) < sizeof(cfg->node_host);
            if (ok) memcpy(cfg->node_host, val, strlen(val) + 1);
        } else if (!strcmp(key, "node_port")) {
            req = REQ_NODE_PORT;
            ok = u64_strict(val, &u) == 0 && u >= 1 && u <= 65535;
            if (ok) cfg->node_port = (uint16_t)u;
        } else if (!strcmp(key, "node_fp")) {
            req = REQ_NODE_FP; ok = hex_exact(val, cfg->node_fp, 64) == 0;
        } else if (!strcmp(key, "chain_id")) {
            req = REQ_CHAIN_ID; ok = hex_exact(val, cfg->chain_id, 32) == 0;
        } else if (!strcmp(key, "journal_path")) {
            req = REQ_JOURNAL;
            ok = *val && strlen(val) < sizeof(cfg->journal_path);
            if (ok) memcpy(cfg->journal_path, val, strlen(val) + 1);
        } else if (!strcmp(key, "eth_providers")) {
            req = REQ_PROVIDERS;
            ok = commas_clean(val) && parse_providers(val, cfg) == 0;
        } else if (!strcmp(key, "eth_quorum")) {
            req = REQ_QUORUM;
            ok = u64_strict(val, &u) == 0 && u >= 1 && u <= AMM_MAX_PROVIDERS;
            if (ok) cfg->eth_quorum = (int)u;
        } else if (!strcmp(key, "foundation_eth")) {
            req = REQ_FOUND_ETH; ok = hex_exact(val, cfg->foundation_eth, 20) == 0;
        } else if (!strcmp(key, "foundation_nodus")) {
            uint8_t tmp[64];
            req = REQ_FOUND_NODUS;
            ok = hex_exact(val, tmp, 64) == 0;
            if (ok) memcpy(cfg->foundation_nodus, val, 129);
        } else if (!strcmp(key, "eth_price_sources")) {
            opt = 1u << 4;
            ok = parse_price_sources(val, &cfg->eth_price_sources) == 0;
        } else if (!strcmp(key, "eth_key_path")) {
            req = REQ_ETH_KEY;
            ok = *val && strlen(val) < sizeof(cfg->eth_key_path);
            if (ok) memcpy(cfg->eth_key_path, val, strlen(val) + 1);
        } else if (!strcmp(key, "nodus_key_dir")) {
            req = REQ_NODUS_KEY;
            ok = *val && strlen(val) < sizeof(cfg->nodus_key_dir);
            if (ok) memcpy(cfg->nodus_key_dir, val, strlen(val) + 1);
        } else if (!strcmp(key, "lock_path")) {
            req = REQ_LOCK;
            ok = *val && strlen(val) < sizeof(cfg->lock_path);
            if (ok) memcpy(cfg->lock_path, val, strlen(val) + 1);
        } else if (!strcmp(key, "eip712_name")) {
            req = REQ_EIP712;
            ok = printable(val, sizeof(cfg->eip712_name));
            if (ok) memcpy(cfg->eip712_name, val, strlen(val) + 1);
        } else if (!strcmp(key, "expected_origin")) {
            req = REQ_ORIGIN;
            ok = printable(val, sizeof(cfg->expected_origin));
            if (ok) memcpy(cfg->expected_origin, val, strlen(val) + 1);
        } else if (!strcmp(key, "held_keeps_room")) {
            req = REQ_HELD_ROOM; ok = bool01(val, &cfg->held_keeps_room) == 0;
        } else if (!strcmp(key, "usdt_contract")) {
            opt = 1u << 0; ok = hex_exact(val, cfg->usdt_contract, 20) == 0;
        } else if (!strcmp(key, "swaps_paused")) {
            opt = 1u << 1; ok = bool01(val, &cfg->swaps_paused) == 0;
        } else if (!strcmp(key, "liquidity_paused")) {
            opt = 1u << 2; ok = bool01(val, &cfg->liquidity_paused) == 0;
        } else if (!strcmp(key, "payouts_paused")) {
            opt = 1u << 3; ok = bool01(val, &cfg->payouts_paused) == 0;
        } else {
            set_err(err, err_cap, "unknown key: %s", key);
            goto out;
        }
        if (!ok) { set_err(err, err_cap, "bad value for key: %s", key); goto out; }
        if ((req && (seen & req)) || (opt && (seen_opt & opt))) {
            set_err(err, err_cap, "duplicate key: %s", key);
            goto out;
        }
        seen |= req;
        seen_opt |= opt;
    }

    /* required keys */
    {
        unsigned want = REQ_NODE_HOST | REQ_NODE_PORT | REQ_NODE_FP |
                        REQ_CHAIN_ID | REQ_JOURNAL | REQ_PROVIDERS |
                        REQ_QUORUM | REQ_FOUND_ETH | REQ_FOUND_NODUS |
                        REQ_EIP712 | REQ_ORIGIN | REQ_HELD_ROOM | REQ_ETH_KEY |
                        REQ_NODUS_KEY | REQ_LOCK;
        for (size_t i = 0; i < N_U64; i++) {
            if (U64_KEYS[i].required && !(seen_u64 & (1ULL << i))) {
                set_err(err, err_cap, "a required key is missing: %s",
                        U64_KEYS[i].name);
                goto out;
            }
        }
        if ((seen & want) != want) {
            set_err(err, err_cap, "%s", "a required key is missing (node_host, "
                    "node_port, node_fp, chain_id, journal_path, eth_providers, "
                    "eth_quorum, foundation_eth, foundation_nodus, "
                    "eip712_name, expected_origin, held_keeps_room, "
                    "eth_key_path, nodus_key_dir, lock_path)");
            goto out;
        }
    }
    /* value rules across keys */
    if (cfg->eth_quorum > cfg->n_providers) {
        set_err(err, err_cap, "%s", "eth_quorum is above the number of providers");
        goto out;
    }
    if (cfg->swap_max_usdt > cfg->inflight_max_usdt) {
        set_err(err, err_cap, "%s", "swap_max_usdt is above inflight_max_usdt");
        goto out;
    }
    if (cfg->swap_min_usdt > cfg->swap_max_usdt) {
        set_err(err, err_cap, "%s", "swap_min_usdt is above swap_max_usdt");
        goto out;
    }
    {   /* plan section 15: not more than the number of listed sources */
        unsigned n = 0;
        for (unsigned m = cfg->eth_price_sources; m; m >>= 1) n += m & 1u;
        if (cfg->eth_price_min_sources > n) {
            set_err(err, err_cap, "%s",
                    "eth_price_min_sources is above the number of listed sources");
            goto out;
        }
    }
    if (cfg->eth_conf_bound_1_usdt >= cfg->eth_conf_bound_2_usdt) {
        set_err(err, err_cap, "%s",
                "eth_conf_bound_1_usdt is not below eth_conf_bound_2_usdt");
        goto out;
    }
    if (cfg->eth_conf_count_1 > cfg->eth_conf_count_2 ||
        cfg->eth_conf_count_2 > cfg->eth_conf_count_3) {
        set_err(err, err_cap, "%s",
                "eth_conf_count_1..3 must not decrease");
        goto out;
    }
    /* counts never decrease, so count 3 is the largest */
    if (cfg->eth_reorg_window_blocks < cfg->eth_conf_count_3) {
        set_err(err, err_cap, "%s",
                "eth_reorg_window_blocks is below the largest confirmation count");
        goto out;
    }
    rc = 0;
out:
    free(buf);
    return rc;
}

int amm_cfg_load(const char *path, amm_cfg_t *cfg, char *err, size_t err_cap) {
    FILE *f = fopen(path, "rb");
    if (!f) { set_err(err, err_cap, "cannot open config: %s", path); return -1; }
    char *buf = malloc(CFG_FILE_MAX + 2);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, CFG_FILE_MAX + 1, f);
    int bad = ferror(f);
    fclose(f);
    if (bad || n > CFG_FILE_MAX) {
        free(buf);
        set_err(err, err_cap, "%s", "config unreadable or too large");
        return -1;
    }
    buf[n] = '\0';
    if (memchr(buf, '\0', n)) {
        free(buf);
        set_err(err, err_cap, "%s", "config holds a NUL byte");
        return -1;
    }
    int rc = amm_cfg_parse(buf, cfg, err, err_cap);
    free(buf);
    return rc;
}
