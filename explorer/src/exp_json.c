/* exp_json — DNAC Explorer minimal growable-buffer JSON emitter. See exp_json.h. */

#include "exp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"
#define LOG_TAG "EXP_JSON"

#define EXP_JSON_INITIAL_CAP 256

/* Grows j->buf so at least `extra` more bytes plus a trailing NUL fit.
 * Doubling growth, same pattern as other growable buffers in the tree.
 * On OOM: logs and leaves j->buf/cap/len untouched (still a valid,
 * NUL-terminated, just-not-longer buffer) — callers bail without
 * appending rather than risk a partial/garbage write. */
static int ensure_cap(exp_json_t *j, size_t extra) {
    size_t need = j->len + extra + 1; /* +1 for NUL */
    if (need <= j->cap) return 0;

    size_t new_cap = j->cap ? j->cap : EXP_JSON_INITIAL_CAP;
    while (new_cap < need) {
        if (new_cap > (SIZE_MAX / 2)) { new_cap = need; break; }
        new_cap *= 2;
    }

    char *nb = realloc(j->buf, new_cap);
    if (!nb) {
        QGP_LOG_ERROR(LOG_TAG, "OOM growing json buffer to %zu bytes", new_cap);
        return -1;
    }
    j->buf = nb;
    j->cap = new_cap;
    return 0;
}

void exp_json_init(exp_json_t *j) {
    if (!j) return;
    j->buf = NULL;
    j->len = 0;
    j->cap = 0;
    if (ensure_cap(j, 0) == 0) {
        j->buf[0] = '\0';
    }
}

void exp_json_freebuf(exp_json_t *j) {
    if (!j) return;
    free(j->buf);
    j->buf = NULL;
    j->len = 0;
    j->cap = 0;
}

void exp_json_raw(exp_json_t *j, const char *s) {
    if (!j || !s) return;
    size_t n = strlen(s);
    if (n == 0) return;
    if (ensure_cap(j, n) != 0) return;
    memcpy(j->buf + j->len, s, n);
    j->len += n;
    j->buf[j->len] = '\0';
}

void exp_json_str(exp_json_t *j, const char *s) {
    if (!j) return;

    exp_json_raw(j, "\"");
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            unsigned char c = *p;
            switch (c) {
            case '"':  exp_json_raw(j, "\\\""); break;
            case '\\': exp_json_raw(j, "\\\\"); break;
            case '\n': exp_json_raw(j, "\\n");  break;
            case '\r': exp_json_raw(j, "\\r");  break;
            case '\t': exp_json_raw(j, "\\t");  break;
            case '\b': exp_json_raw(j, "\\b");  break;
            case '\f': exp_json_raw(j, "\\f");  break;
            default:
                if (c < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", (unsigned)c);
                    exp_json_raw(j, esc);
                } else {
                    char one[2];
                    one[0] = (char)c;
                    one[1] = '\0';
                    exp_json_raw(j, one);
                }
                break;
            }
        }
    }
    exp_json_raw(j, "\"");
}

void exp_json_u64(exp_json_t *j, uint64_t v) {
    if (!j) return;
    char buf[32];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
    exp_json_raw(j, buf);
}

void exp_json_hex(exp_json_t *j, const uint8_t *b, size_t n) {
    if (!j) return;

    static const char hexchars[] = "0123456789abcdef";

    exp_json_raw(j, "\"");
    if (b && n > 0) {
        char pair[3];
        for (size_t i = 0; i < n; i++) {
            pair[0] = hexchars[(b[i] >> 4) & 0xF];
            pair[1] = hexchars[b[i] & 0xF];
            pair[2] = '\0';
            exp_json_raw(j, pair);
        }
    }
    exp_json_raw(j, "\"");
}
