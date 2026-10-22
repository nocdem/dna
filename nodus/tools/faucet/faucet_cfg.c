/**
 * @file faucet_cfg.c
 * @brief nodus-faucet configuration parser (see faucet_cfg.h).
 */
#include "faucet_cfg.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFG_FILE_MAX 16384u

/* Required keys, one bit each. */
enum {
    REQ_NODE_HOST = 1u << 0, REQ_NODE_PORT = 1u << 1, REQ_NODE_FP = 1u << 2,
    REQ_CHAIN_ID  = 1u << 3, REQ_KEY_DIR   = 1u << 4, REQ_JOURNAL = 1u << 5,
    REQ_TOKEN_ID  = 1u << 6, REQ_LISTEN    = 1u << 7,
    REQ_ALL       = 0xFFu
};

void faucet_cfg_defaults(faucet_cfg_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->full_native        = 10000000000000ULL;   /* 100 000 NODUS */
    cfg->full_token         = 100000000ULL;        /* 100 tUSDT, 6 decimals */
    cfg->start_native       = 1000000000ULL;       /* 10 NODUS */
    cfg->fee_ceiling        = 10000000ULL;         /* 0.1 NODUS */
    cfg->expiry_ahead       = 90;
    cfg->storage_ceiling    = 64ULL * 1024 * 1024;
    cfg->queue_cap          = 64;
    cfg->conn_cap           = 16;
    cfg->request_timeout_ms = 5000;
    cfg->poll_ms            = 4000;
}

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
    if (!*s || *s == '-' || *s == '+') return -1;
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

int faucet_cfg_parse(const char *text, faucet_cfg_t *cfg, char *err,
                     size_t err_cap) {
    if (!text || !cfg) return -1;
    faucet_cfg_defaults(cfg);
    size_t tlen = strlen(text);
    if (tlen > CFG_FILE_MAX) {
        set_err(err, err_cap, "%s", "config file too large");
        return -1;
    }
    char *buf = malloc(tlen + 1);
    if (!buf) return -1;
    memcpy(buf, text, tlen + 1);

    unsigned seen = 0;             /* required keys seen                    */
    unsigned long seen_opt = 0;    /* optional keys seen (duplicate guard)  */
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
        unsigned req = 0;
        unsigned long opt = 0;

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
        } else if (!strcmp(key, "key_dir")) {
            req = REQ_KEY_DIR;
            ok = *val && strlen(val) < sizeof(cfg->key_dir);
            if (ok) memcpy(cfg->key_dir, val, strlen(val) + 1);
        } else if (!strcmp(key, "journal_path")) {
            req = REQ_JOURNAL;
            ok = *val && strlen(val) < sizeof(cfg->journal_path);
            if (ok) memcpy(cfg->journal_path, val, strlen(val) + 1);
        } else if (!strcmp(key, "token_id")) {
            req = REQ_TOKEN_ID; ok = hex_exact(val, cfg->token_id, 64) == 0;
        } else if (!strcmp(key, "listen_port")) {
            req = REQ_LISTEN;
            ok = u64_strict(val, &u) == 0 && u >= 1 && u <= 65535;
            if (ok) cfg->listen_port = (uint16_t)u;
        } else if (!strcmp(key, "full_native")) {
            opt = 1UL << 0; ok = u64_strict(val, &cfg->full_native) == 0;
        } else if (!strcmp(key, "full_token")) {
            opt = 1UL << 1; ok = u64_strict(val, &cfg->full_token) == 0;
        } else if (!strcmp(key, "start_native")) {
            opt = 1UL << 2; ok = u64_strict(val, &cfg->start_native) == 0;
        } else if (!strcmp(key, "fee_ceiling")) {
            opt = 1UL << 3; ok = u64_strict(val, &cfg->fee_ceiling) == 0;
        } else if (!strcmp(key, "expiry_ahead")) {
            opt = 1UL << 4; ok = u64_strict(val, &cfg->expiry_ahead) == 0;
        } else if (!strcmp(key, "storage_ceiling")) {
            opt = 1UL << 5; ok = u64_strict(val, &cfg->storage_ceiling) == 0;
        } else if (!strcmp(key, "queue_cap")) {
            opt = 1UL << 6;
            ok = u64_strict(val, &u) == 0 && u >= 1 && u <= 10000;
            if (ok) cfg->queue_cap = (int)u;
        } else if (!strcmp(key, "conn_cap")) {
            opt = 1UL << 7;
            ok = u64_strict(val, &u) == 0 && u >= 1 && u <= 256;
            if (ok) cfg->conn_cap = (int)u;
        } else if (!strcmp(key, "request_timeout_ms")) {
            opt = 1UL << 8;
            ok = u64_strict(val, &u) == 0 && u >= 100 && u <= 60000;
            if (ok) cfg->request_timeout_ms = (int)u;
        } else if (!strcmp(key, "poll_ms")) {
            opt = 1UL << 9;
            ok = u64_strict(val, &u) == 0 && u >= 500 && u <= 60000;
            if (ok) cfg->poll_ms = (int)u;
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
    if ((seen & REQ_ALL) != REQ_ALL) {
        set_err(err, err_cap, "%s", "a required key is missing (node_host, "
                "node_port, node_fp, chain_id, key_dir, journal_path, "
                "token_id, listen_port)");
        goto out;
    }
    /* Value rules. */
    if (cfg->full_native == 0 || cfg->full_token == 0 ||
        cfg->start_native == 0 || cfg->fee_ceiling == 0) {
        set_err(err, err_cap, "%s", "amounts and the fee ceiling must be > 0");
        goto out;
    }
    /* No overflow in capacity arithmetic and in plan + fee sums. */
    if (cfg->full_native > UINT64_MAX / 4 || cfg->start_native > UINT64_MAX / 4 ||
        cfg->fee_ceiling > UINT64_MAX / 4) {
        set_err(err, err_cap, "%s", "an amount is implausibly large");
        goto out;
    }
    if (cfg->expiry_ahead < 10 || cfg->expiry_ahead > 90) {
        set_err(err, err_cap, "%s", "expiry_ahead must be 10..90 (the mempool "
                "admits tip + 100; the gossip margin is 10)");
        goto out;
    }
    if (cfg->storage_ceiling < 1024ULL * 1024) {
        set_err(err, err_cap, "%s", "storage_ceiling must be >= 1 MiB");
        goto out;
    }
    rc = 0;
out:
    free(buf);
    return rc;
}

int faucet_cfg_load(const char *path, faucet_cfg_t *cfg, char *err,
                    size_t err_cap) {
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
    int rc = faucet_cfg_parse(buf, cfg, err, err_cap);
    free(buf);
    return rc;
}
