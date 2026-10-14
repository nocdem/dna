/**
 * @file nodus/src/client/nodus_consent_req.c
 * @brief The consent request code and the node config lookup — see
 *        nodus_consent_req.h for the contract.
 *
 * Governing record: docs/plans/decisions/2026-10-14-consent-request-code.md.
 * Parsing only: no network, no clock, no signing. The values this returns
 * go to nodus-cli cmd_validator_consent as --owner / --expiry / --chain-id,
 * which re-checks each of them (t6_hex_exact, strtoull) and pins the chain
 * id against the node's own before anything is signed.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_consent_req.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>
#endif

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

static void cr_err(char *err, size_t errcap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void cr_err(char *err, size_t errcap, const char *fmt, ...) {
    if (!err || errcap == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errcap, fmt, ap);
    va_end(ap);
}

/* 1 when s[0..n) is exactly n lowercase hex chars */
static int cr_lower_hex(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

int nodus_consent_req_parse(const char *code, nodus_consent_req_t *out,
                            char *err, size_t errcap) {
    if (out) memset(out, 0, sizeof(*out));
    if (!code || !out) {
        cr_err(err, errcap, "no request code given");
        return -1;
    }
    const size_t plen = strlen(NODUS_CONSENT_REQ_PREFIX);
    if (strncmp(code, NODUS_CONSENT_REQ_PREFIX, plen) != 0) {
        cr_err(err, errcap, "not a consent request code: it must start "
               "with \"%s\" (copy the whole line Nodus Connect shows)",
               NODUS_CONSENT_REQ_PREFIX);
        return -1;
    }

    /* the four fields after the prefix: role, owner, expiry, chain —
     * split on ':' by hand (strtok would merge empty fields) */
    const char *f[4];
    size_t      fl[4];
    const char *p = code + plen;
    for (int i = 0; i < 4; i++) {
        const char *colon = strchr(p, ':');
        f[i] = p;
        if (i < 3) {
            if (!colon) {
                cr_err(err, errcap, "the request code has too few fields "
                       "(role:owner:expiry:chain)");
                memset(out, 0, sizeof(*out));
                return -1;
            }
            fl[i] = (size_t)(colon - p);
            p = colon + 1;
        } else {
            if (colon) {
                cr_err(err, errcap, "the request code has text after the "
                       "chain id field");
                memset(out, 0, sizeof(*out));
                return -1;
            }
            fl[i] = strlen(p);
        }
        if (fl[i] == 0) {
            static const char *const names[4] = { "role", "owner",
                                                  "expiry", "chain id" };
            cr_err(err, errcap, "the %s field of the request code is "
                   "empty", names[i]);
            memset(out, 0, sizeof(*out));
            return -1;
        }
    }

    /* role */
    if (fl[0] == 7 && memcmp(f[0], "storage", 7) == 0) {
        out->storage = 1;
    } else if (fl[0] == 7 && memcmp(f[0], "witness", 7) == 0) {
        out->storage = 0;
    } else {
        cr_err(err, errcap, "unknown role in the request code (expected "
               "\"storage\" or \"witness\")");
        memset(out, 0, sizeof(*out));
        return -1;
    }

    /* owner */
    if (fl[1] != NODUS_CONSENT_REQ_OWNER_HEX ||
        !cr_lower_hex(f[1], fl[1])) {
        cr_err(err, errcap, "the owner in the request code must be exactly "
               "%u lowercase hex chars", (unsigned)NODUS_CONSENT_REQ_OWNER_HEX);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    memcpy(out->owner_hex, f[1], fl[1]);
    out->owner_hex[fl[1]] = '\0';

    /* expiry: digits only, no leading zero (so also not "0"), fits uint64 */
    for (size_t i = 0; i < fl[2]; i++) {
        if (f[2][i] < '0' || f[2][i] > '9') {
            cr_err(err, errcap, "the expiry in the request code must be a "
                   "decimal block height (digits only)");
            memset(out, 0, sizeof(*out));
            return -1;
        }
    }
    if (f[2][0] == '0') {
        cr_err(err, errcap, fl[2] == 1
               ? "the expiry in the request code is 0 — not a block height"
               : "the expiry in the request code has a leading zero");
        memset(out, 0, sizeof(*out));
        return -1;
    }
    if (fl[2] > NODUS_CONSENT_REQ_EXPIRY_MAX) {
        cr_err(err, errcap, "the expiry in the request code is too large");
        memset(out, 0, sizeof(*out));
        return -1;
    }
    memcpy(out->expiry_dec, f[2], fl[2]);
    out->expiry_dec[fl[2]] = '\0';
    {
        char *end = NULL;
        errno = 0;
        const unsigned long long e = strtoull(out->expiry_dec, &end, 10);
        if (errno != 0 || !end || *end != '\0' || e == 0) {
            cr_err(err, errcap, "the expiry in the request code is too "
                   "large");
            memset(out, 0, sizeof(*out));
            return -1;
        }
        out->expiry = (uint64_t)e;
    }

    /* chain id */
    if (fl[3] != NODUS_CONSENT_REQ_CHAIN_HEX ||
        !cr_lower_hex(f[3], fl[3])) {
        cr_err(err, errcap, "the chain id in the request code must be "
               "exactly %u lowercase hex chars",
               (unsigned)NODUS_CONSENT_REQ_CHAIN_HEX);
        memset(out, 0, sizeof(*out));
        return -1;
    }
    memcpy(out->chain_hex, f[3], fl[3]);
    out->chain_hex[fl[3]] = '\0';
    return 0;
}

int nodus_consent_req_read_config(const char *path, char *identity_path,
                                  size_t cap, uint16_t *tcp_port,
                                  char *err, size_t errcap) {
    if (!path || !identity_path || cap == 0 || !tcp_port) {
        cr_err(err, errcap, "no config path given");
        return -1;
    }
#ifndef NODUS_HAS_JSONC
    cr_err(err, errcap, "this build cannot read the node config; give -i");
    return -1;
#else
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        cr_err(err, errcap, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    char *buf = malloc((size_t)NODUS_CONSENT_REQ_CONFIG_MAX + 1u);
    if (!buf) {
        fclose(fp);
        cr_err(err, errcap, "out of memory reading %s", path);
        return -1;
    }
    /* one byte past the bound tells "too large" from "exactly the bound" */
    const size_t n = fread(buf, 1, (size_t)NODUS_CONSENT_REQ_CONFIG_MAX + 1u,
                           fp);
    const int rerr = ferror(fp);
    fclose(fp);
    if (rerr) {
        free(buf);
        cr_err(err, errcap, "cannot read %s", path);
        return -1;
    }
    if (n > NODUS_CONSENT_REQ_CONFIG_MAX) {
        free(buf);
        cr_err(err, errcap, "%s is larger than %u bytes", path,
               (unsigned)NODUS_CONSENT_REQ_CONFIG_MAX);
        return -1;
    }
    buf[n] = '\0';

    struct json_tokener *tok = json_tokener_new();
    if (!tok) {
        free(buf);
        cr_err(err, errcap, "out of memory parsing %s", path);
        return -1;
    }
    struct json_object *root = json_tokener_parse_ex(tok, buf, (int)n);
    const enum json_tokener_error jerr = json_tokener_get_error(tok);
    json_tokener_free(tok);
    free(buf);
    if (!root || jerr != json_tokener_success ||
        !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        cr_err(err, errcap, "%s is not a JSON object", path);
        return -1;
    }

    int rc = -1;
    struct json_object *val = NULL;
    if (!json_object_object_get_ex(root, "identity_path", &val) ||
        !json_object_is_type(val, json_type_string)) {
        cr_err(err, errcap, "%s has no \"identity_path\" string", path);
        goto out;
    }
    {
        const char *s = json_object_get_string(val);
        const size_t sl = s ? strlen(s) : 0;
        if (sl == 0) {
            cr_err(err, errcap, "\"identity_path\" in %s is empty", path);
            goto out;
        }
        if (sl >= cap) {
            cr_err(err, errcap, "\"identity_path\" in %s is too long", path);
            goto out;
        }
        /* tcp_port is judged before identity_path is written, so a
         * refused config leaves both outputs untouched */
        uint16_t port = *tcp_port;
        struct json_object *pv = NULL;
        if (json_object_object_get_ex(root, "tcp_port", &pv)) {
            if (!json_object_is_type(pv, json_type_int)) {
                cr_err(err, errcap, "\"tcp_port\" in %s is not an integer",
                       path);
                goto out;
            }
            errno = 0;
            const int64_t v = json_object_get_int64(pv);
            if (errno != 0 || v < 1 || v > 65535) {
                cr_err(err, errcap, "\"tcp_port\" in %s must be 1..65535",
                       path);
                goto out;
            }
            port = (uint16_t)v;
        }
        memcpy(identity_path, s, sl + 1u);
        *tcp_port = port;
    }
    rc = 0;
out:
    json_object_put(root);
    return rc;
#endif
}

int nodus_consent_req_answer_yes(const char *line) {
    if (!line) return 0;
    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
    char low[4];
    if (n == 0 || n > 3) return 0;
    for (size_t i = 0; i < n; i++) {
        const char c = line[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    return (n == 1 && low[0] == 'y') ||
           (n == 3 && memcmp(low, "yes", 3) == 0);
}
