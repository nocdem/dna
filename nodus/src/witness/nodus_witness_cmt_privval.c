/**
 * @file nodus_witness_cmt_privval.c
 * @brief cometbft @709fd12b privval/file.go's FILE side for the last-sign
 *        state. Contract: nodus_witness_cmt_privval.h.
 */

#include "witness/nodus_witness_cmt_privval.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_CMTPV"

/* tempfile.go:15-31 */
#define ATOMIC_WRITE_FILE_MAX_NUM_CONFLICTS      5      /* :19 */
#define ATOMIC_WRITE_FILE_MAX_NUM_WRITE_ATTEMPTS 1000   /* :22 */
#define LCG_A 6364136223846793005ULL                    /* :25 */
#define LCG_C 1442695040888963407ULL                    /* :26 */
#define ATOMIC_WRITE_FILE_FLAG \
    (O_WRONLY | O_CREAT | O_SYNC | O_TRUNC | O_EXCL)   /* :30 */

/* ═══════════════════════════════════════════════════════════════════════
 * libs/json ENCODER for FilePVLastSignState (libs/json/encoder.go and
 * libs/json/structs.go for omitempty; libs/bytes/bytes.go for HexBytes)
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    char   *buf;
    size_t  cap;
    size_t  len;
    bool    overflow;
} jw_t;

static void jw_put(jw_t *w, const char *s, size_t n) {
    if (w->overflow) return;
    if (n > w->cap - w->len) { w->overflow = true; return; }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
}

static void jw_str(jw_t *w, const char *s) { jw_put(w, s, strlen(s)); }

/* encoding/base64 StdEncoding with padding — what encoding/json uses for
 * a []byte (encoder.go:124-133 → stdlib). */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void jw_base64(jw_t *w, const uint8_t *p, size_t n) {
    char q[4];
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8) |
                     (uint32_t)p[i + 2];
        q[0] = B64[(v >> 18) & 63]; q[1] = B64[(v >> 12) & 63];
        q[2] = B64[(v >> 6) & 63];  q[3] = B64[v & 63];
        jw_put(w, q, 4);
        i += 3;
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)p[i] << 16;
        q[0] = B64[(v >> 18) & 63]; q[1] = B64[(v >> 12) & 63];
        q[2] = '='; q[3] = '=';
        jw_put(w, q, 4);
    } else if (n - i == 2) {
        uint32_t v = ((uint32_t)p[i] << 16) | ((uint32_t)p[i + 1] << 8);
        q[0] = B64[(v >> 18) & 63]; q[1] = B64[(v >> 12) & 63];
        q[2] = B64[(v >> 6) & 63];  q[3] = '=';
        jw_put(w, q, 4);
    }
}

/* libs/bytes/bytes.go:24-31 — `strings.ToUpper(hex.EncodeToString(bz))`. */
static void jw_hex_upper(jw_t *w, const uint8_t *p, size_t n) {
    static const char HX[] = "0123456789ABCDEF";
    char q[2];
    for (size_t i = 0; i < n; i++) {
        q[0] = HX[p[i] >> 4];
        q[1] = HX[p[i] & 15];
        jw_put(w, q, 2);
    }
}

/* encoder.go:180-200 `encodeReflectStruct` over file.go:75-83, member by
 * member in declaration order, `omitempty` dropping a nil slice
 * (encoder.go:189 `frv.IsZero()`; structs.go:78). */
static int lss_encode_compact(const cmt_lss_t *lss, jw_t *w) {
    char num[32];

    jw_str(w, "{");
    /* :76 Height int64 — encoder.go:107, a quoted decimal. */
    jw_str(w, "\"height\":\"");
    snprintf(num, sizeof num, "%" PRId64, lss->height);
    jw_str(w, num);
    jw_str(w, "\"");
    /* :77 Round int32 — encoder.go:114 → stdlib, a bare number. */
    jw_str(w, ",\"round\":");
    snprintf(num, sizeof num, "%" PRId32, lss->round);
    jw_str(w, num);
    /* :78 Step int8 — likewise. */
    jw_str(w, ",\"step\":");
    snprintf(num, sizeof num, "%d", (int)lss->step);
    jw_str(w, num);
    /* :79 Signature []byte `omitempty` — nil omitted, an empty NON-nil
     * slice is written as "" (the flag decides, not the length). */
    if (lss->has_signature) {
        if (lss->signature_len > sizeof lss->signature) return CMT_FAULT;
        jw_str(w, ",\"signature\":\"");
        jw_base64(w, lss->signature, lss->signature_len);
        jw_str(w, "\"");
    }
    /* :80 SignBytes HexBytes `omitempty` — bytes.go:24-31. */
    if (lss->has_sign_bytes) {
        if (lss->sign_bytes_len > sizeof lss->sign_bytes) return CMT_FAULT;
        jw_str(w, ",\"signbytes\":\"");
        jw_hex_upper(w, lss->sign_bytes, lss->sign_bytes_len);
        jw_str(w, "\"");
    }
    jw_str(w, "}");
    return w->overflow ? CMT_FAULT : CMT_OK;
}

int nodus_cmt_lss_marshal(const cmt_lss_t *lss, char *out, size_t cap,
                          size_t *out_len) {
    if (!lss || !out || !out_len) return CMT_FAULT;
    jw_t w = { out, cap, 0, false };
    int rc = lss_encode_compact(lss, &w);
    if (rc != CMT_OK) return rc;
    *out_len = w.len;
    return CMT_OK;
}

/* encoding/json `Indent(dst, src, "", "  ")` over the compact form of
 * ONE flat object: newline + indent after `{` and after each `,`, a
 * space after each `:`, newline before the closing `}`, string contents
 * copied verbatim, no trailing newline. The compact form has no nested
 * `{`/`[`, so depth is at most one. */
int nodus_cmt_lss_marshal_indent(const cmt_lss_t *lss, char *out,
                                 size_t cap, size_t *out_len) {
    if (!lss || !out || !out_len) return CMT_FAULT;

    char *compact = (char *)malloc(NODUS_CMT_LSS_JSON_MAX);
    if (!compact) return CMT_FAULT;
    size_t clen = 0;
    int rc = nodus_cmt_lss_marshal(lss, compact, NODUS_CMT_LSS_JSON_MAX,
                                   &clen);
    if (rc != CMT_OK) { free(compact); return rc; }

    jw_t w = { out, cap, 0, false };
    bool in_string = false;
    for (size_t i = 0; i < clen; i++) {
        char c = compact[i];
        if (in_string) {
            jw_put(&w, &c, 1);
            if (c == '"') in_string = false;
            continue;
        }
        switch (c) {
        case '"':
            in_string = true;
            jw_put(&w, &c, 1);
            break;
        case '{':
            jw_put(&w, &c, 1);
            if (i + 1 < clen && compact[i + 1] == '}') break;
            jw_str(&w, "\n  ");
            break;
        case ',':
            jw_put(&w, &c, 1);
            jw_str(&w, "\n  ");
            break;
        case ':':
            jw_str(&w, ": ");
            break;
        case '}':
            jw_str(&w, "\n");
            jw_put(&w, &c, 1);
            break;
        default:
            jw_put(&w, &c, 1);
            break;
        }
    }
    free(compact);
    if (w.overflow) return CMT_FAULT;
    *out_len = w.len;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * libs/json DECODER for FilePVLastSignState (libs/json/decoder.go;
 * libs/bytes/bytes.go for HexBytes)
 * ═══════════════════════════════════════════════════════════════════════ */

typedef struct {
    const uint8_t *p;
    size_t         n;
    size_t         i;
} jr_t;

static bool jr_ws(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void jr_skip_ws(jr_t *r) {
    while (r->i < r->n && jr_ws(r->p[r->i])) r->i++;
}

static bool jr_hex_val(uint8_t c, uint8_t *v) {
    if (c >= '0' && c <= '9') { *v = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *v = (uint8_t)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *v = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

/* A JSON string token: returns the raw contents (between the quotes) and
 * whether any backslash escape occurred inside. Control characters below
 * 0x20 are invalid inside a string (stdlib scanner) → false. */
static bool jr_string(jr_t *r, const uint8_t **out, size_t *out_len,
                      bool *escaped) {
    if (r->i >= r->n || r->p[r->i] != '"') return false;
    r->i++;
    size_t start = r->i;
    *escaped = false;
    while (r->i < r->n) {
        uint8_t c = r->p[r->i];
        if (c == '"') {
            *out = r->p + start;
            *out_len = r->i - start;
            r->i++;
            return true;
        }
        if (c < 0x20) return false;
        if (c == '\\') {
            *escaped = true;
            r->i++;
            if (r->i >= r->n) return false;
            uint8_t e = r->p[r->i];
            if (e == 'u') {
                if (r->i + 4 >= r->n) return false;
                for (int k = 1; k <= 4; k++) {
                    uint8_t v;
                    if (!jr_hex_val(r->p[r->i + (size_t)k], &v)) return false;
                }
                r->i += 4;
            } else if (!(e == '"' || e == '\\' || e == '/' || e == 'b' ||
                         e == 'f' || e == 'n' || e == 'r' || e == 't')) {
                return false;
            }
        }
        r->i++;
    }
    return false;
}

/* A JSON number token, returned raw. Grammar: -?(0|[1-9][0-9]*)
 * (\.[0-9]+)?([eE][+-]?[0-9]+)? */
static bool jr_number(jr_t *r, const uint8_t **out, size_t *out_len) {
    size_t start = r->i;
    if (r->i < r->n && r->p[r->i] == '-') r->i++;
    if (r->i >= r->n) return false;
    if (r->p[r->i] == '0') {
        r->i++;
    } else if (r->p[r->i] >= '1' && r->p[r->i] <= '9') {
        while (r->i < r->n && r->p[r->i] >= '0' && r->p[r->i] <= '9') r->i++;
    } else {
        return false;
    }
    if (r->i < r->n && r->p[r->i] == '.') {
        r->i++;
        size_t d = r->i;
        while (r->i < r->n && r->p[r->i] >= '0' && r->p[r->i] <= '9') r->i++;
        if (r->i == d) return false;
    }
    if (r->i < r->n && (r->p[r->i] == 'e' || r->p[r->i] == 'E')) {
        r->i++;
        if (r->i < r->n && (r->p[r->i] == '+' || r->p[r->i] == '-')) r->i++;
        size_t d = r->i;
        while (r->i < r->n && r->p[r->i] >= '0' && r->p[r->i] <= '9') r->i++;
        if (r->i == d) return false;
    }
    *out = r->p + start;
    *out_len = r->i - start;
    return true;
}

static bool jr_literal(jr_t *r, const char *lit) {
    size_t n = strlen(lit);
    if (r->n - r->i < n || memcmp(r->p + r->i, lit, n) != 0) return false;
    r->i += n;
    return true;
}

/* Skip one complete JSON value of any kind (an unknown key's value:
 * decoder.go:186 parses the whole object into a map first, so it must
 * be well-formed, and :190 then ignores it). */
static bool jr_skip_value(jr_t *r, int depth) {
    if (depth > 64) return false;
    jr_skip_ws(r);
    if (r->i >= r->n) return false;
    uint8_t c = r->p[r->i];
    if (c == '"') {
        const uint8_t *s; size_t sl; bool esc;
        return jr_string(r, &s, &sl, &esc);
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const uint8_t *s; size_t sl;
        return jr_number(r, &s, &sl);
    }
    if (c == 't') return jr_literal(r, "true");
    if (c == 'f') return jr_literal(r, "false");
    if (c == 'n') return jr_literal(r, "null");
    if (c == '[') {
        r->i++;
        jr_skip_ws(r);
        if (r->i < r->n && r->p[r->i] == ']') { r->i++; return true; }
        for (;;) {
            if (!jr_skip_value(r, depth + 1)) return false;
            jr_skip_ws(r);
            if (r->i >= r->n) return false;
            if (r->p[r->i] == ',') { r->i++; continue; }
            if (r->p[r->i] == ']') { r->i++; return true; }
            return false;
        }
    }
    if (c == '{') {
        r->i++;
        jr_skip_ws(r);
        if (r->i < r->n && r->p[r->i] == '}') { r->i++; return true; }
        for (;;) {
            jr_skip_ws(r);
            const uint8_t *k; size_t kl; bool esc;
            if (!jr_string(r, &k, &kl, &esc)) return false;
            jr_skip_ws(r);
            if (r->i >= r->n || r->p[r->i] != ':') return false;
            r->i++;
            if (!jr_skip_value(r, depth + 1)) return false;
            jr_skip_ws(r);
            if (r->i >= r->n) return false;
            if (r->p[r->i] == ',') { r->i++; continue; }
            if (r->p[r->i] == '}') { r->i++; return true; }
            return false;
        }
    }
    return false;
}

/* strconv.ParseInt(s, 10, 64) as encoding/json applies it to an integer
 * kind: the token must be a plain integer (no fraction, no exponent —
 * stdlib refuses "1.0" for an int) within [lo, hi]. */
static bool parse_int_token(const uint8_t *s, size_t n, int64_t lo,
                            int64_t hi, int64_t *out) {
    size_t i = 0;
    bool neg = false;
    if (n == 0) return false;
    if (s[0] == '-') { neg = true; i = 1; }
    if (i >= n) return false;
    if (s[i] == '0' && n - i > 1) return false;          /* leading zero  */
    uint64_t acc = 0;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (acc > (UINT64_MAX - d) / 10) return false;
        acc = acc * 10 + d;
    }
    if (neg) {
        if (acc > (uint64_t)INT64_MAX + 1u) return false;
        int64_t v = (acc == (uint64_t)INT64_MAX + 1u)
                        ? INT64_MIN : -(int64_t)acc;
        if (v < lo || v > hi) return false;
        *out = v;
    } else {
        if (acc > (uint64_t)INT64_MAX) return false;
        int64_t v = (int64_t)acc;
        if (v < lo || v > hi) return false;
        *out = v;
    }
    return true;
}

/* base64.StdEncoding decode (padded, strict alphabet) as encoding/json
 * applies it to a []byte. */
static bool b64_val(uint8_t c, uint8_t *v) {
    if (c >= 'A' && c <= 'Z') { *v = (uint8_t)(c - 'A'); return true; }
    if (c >= 'a' && c <= 'z') { *v = (uint8_t)(c - 'a' + 26); return true; }
    if (c >= '0' && c <= '9') { *v = (uint8_t)(c - '0' + 52); return true; }
    if (c == '+') { *v = 62; return true; }
    if (c == '/') { *v = 63; return true; }
    return false;
}

static bool b64_decode(const uint8_t *s, size_t n, uint8_t *out,
                       size_t cap, size_t *out_len) {
    if (n % 4 != 0) return false;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        uint8_t v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            uint8_t c = s[i + (size_t)k];
            if (c == '=') {
                /* Padding only in the last quantum, positions 2-3. */
                if (i + 4 != n || k < 2) return false;
                pad++;
                v[k] = 0;
            } else {
                if (pad) return false;
                if (!b64_val(c, &v[k])) return false;
            }
        }
        uint32_t bits = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                        ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        size_t emit = (size_t)(3 - pad);
        if (o + emit > cap) return false;
        out[o++] = (uint8_t)(bits >> 16);
        if (emit > 1) out[o++] = (uint8_t)(bits >> 8);
        if (emit > 2) out[o++] = (uint8_t)bits;
        /* Non-canonical trailing bits are rejected by Go's strict
         * decoder only in StrictMode; StdEncoding accepts them, so they
         * are accepted here too. */
    }
    *out_len = o;
    return true;
}

/* hex.DecodeString: even length, either case (bytes.go:34-44). */
static bool hex_decode(const uint8_t *s, size_t n, uint8_t *out,
                       size_t cap, size_t *out_len) {
    if (n % 2 != 0) return false;
    if (n / 2 > cap) return false;
    for (size_t i = 0; i < n; i += 2) {
        uint8_t hi, lo;
        if (!jr_hex_val(s[i], &hi) || !jr_hex_val(s[i + 1], &lo)) return false;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return true;
}

int nodus_cmt_lss_unmarshal(const uint8_t *in, size_t len, cmt_lss_t *out) {
    if (!out || (!in && len)) return CMT_FAULT;
    if (len == 0) return CMT_REJECT;            /* decoder.go:19-20      */

    /* decodeReflectStruct (decoder.go:180-199): the object is read whole
     * into a map, then each of the five fields is looked up. A field
     * absent from the map keeps its zero (:193-195); one present is
     * decoded (:191) — `null` meaning the zero value (:44-47). */
    cmt_lss_t lss;
    memset(&lss, 0, sizeof lss);

    jr_t r = { in, len, 0 };
    jr_skip_ws(&r);
    if (r.i >= r.n || r.p[r.i] != '{') return CMT_REJECT;
    r.i++;
    jr_skip_ws(&r);
    bool members = !(r.i < r.n && r.p[r.i] == '}');
    while (members) {
        jr_skip_ws(&r);
        const uint8_t *k; size_t kl; bool kesc;
        if (!jr_string(&r, &k, &kl, &kesc)) return CMT_REJECT;
        jr_skip_ws(&r);
        if (r.i >= r.n || r.p[r.i] != ':') return CMT_REJECT;
        r.i++;
        jr_skip_ws(&r);

        int field = 0;                    /* 1 height 2 round 3 step
                                             4 signature 5 signbytes    */
        if (!kesc) {
            if (kl == 6 && memcmp(k, "height", 6) == 0) field = 1;
            else if (kl == 5 && memcmp(k, "round", 5) == 0) field = 2;
            else if (kl == 4 && memcmp(k, "step", 4) == 0) field = 3;
            else if (kl == 9 && memcmp(k, "signature", 9) == 0) field = 4;
            else if (kl == 9 && memcmp(k, "signbytes", 9) == 0) field = 5;
        }

        if (field == 0) {
            if (!jr_skip_value(&r, 0)) return CMT_REJECT;
        } else if (r.i < r.n && r.p[r.i] == 'n') {
            /* decoder.go:44-47 — `null` sets the zero value. */
            if (!jr_literal(&r, "null")) return CMT_REJECT;
            switch (field) {
            case 1: lss.height = 0; break;
            case 2: lss.round = 0; break;
            case 3: lss.step = 0; break;
            case 4: lss.has_signature = false; lss.signature_len = 0; break;
            default: lss.has_sign_bytes = false; lss.sign_bytes_len = 0; break;
            }
        } else if (field == 1) {
            /* decoder.go:88-93: an int64 must arrive quoted; the inner
             * bytes then go to stdlib as a number. */
            const uint8_t *s; size_t sl; bool esc;
            if (!jr_string(&r, &s, &sl, &esc) || esc) return CMT_REJECT;
            int64_t v;
            if (!parse_int_token(s, sl, INT64_MIN, INT64_MAX, &v))
                return CMT_REJECT;
            lss.height = v;
        } else if (field == 2 || field == 3) {
            const uint8_t *s; size_t sl;
            if (!jr_number(&r, &s, &sl)) return CMT_REJECT;
            int64_t v;
            if (field == 2) {
                if (!parse_int_token(s, sl, INT32_MIN, INT32_MAX, &v))
                    return CMT_REJECT;
                lss.round = (int32_t)v;
            } else {
                if (!parse_int_token(s, sl, INT8_MIN, INT8_MAX, &v))
                    return CMT_REJECT;
                lss.step = (int8_t)v;
            }
        } else if (field == 4) {
            /* decoder.go:105-115 → stdlib base64; :129-132 an empty
             * result becomes nil. */
            const uint8_t *s; size_t sl; bool esc;
            if (!jr_string(&r, &s, &sl, &esc) || esc) return CMT_REJECT;
            size_t n = 0;
            if (!b64_decode(s, sl, lss.signature, sizeof lss.signature, &n))
                return CMT_REJECT;
            lss.signature_len = n;
            lss.has_signature = (n > 0);
        } else {
            /* bytes.go:34-44 HexBytes.UnmarshalJSON: a quoted hex string;
             * "" decodes to an empty NON-nil slice. */
            const uint8_t *s; size_t sl; bool esc;
            if (!jr_string(&r, &s, &sl, &esc) || esc) return CMT_REJECT;
            size_t n = 0;
            if (!hex_decode(s, sl, lss.sign_bytes, sizeof lss.sign_bytes, &n))
                return CMT_REJECT;
            lss.sign_bytes_len = n;
            lss.has_sign_bytes = true;
        }

        jr_skip_ws(&r);
        if (r.i >= r.n) return CMT_REJECT;
        if (r.p[r.i] == ',') { r.i++; continue; }
        if (r.p[r.i] == '}') break;
        return CMT_REJECT;
    }
    if (r.i >= r.n || r.p[r.i] != '}') return CMT_REJECT;
    r.i++;
    jr_skip_ws(&r);
    if (r.i != r.n) return CMT_REJECT;     /* trailing garbage → error   */

    *out = lss;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * libs/tempfile.WriteFileAtomic (tempfile.go:38-129) + R3-B-1
 * ═══════════════════════════════════════════════════════════════════════ */

/* tempfile.go:38-47 `writeFileRandReseed`. The clock is the host's
 * `now`; the pid is the ONE non-`now` source in the port. */
static int write_file_rand_reseed(nodus_cmt_privval_t *ctx, uint64_t *out) {
    cmt_time_t t;
    if (!ctx->now || ctx->now(ctx->now_ctx, &t) != CMT_OK) return CMT_FAULT;
    uint64_t nano = (uint64_t)cmt_time_unix_nano(t);
    uint64_t pid = (uint64_t)((int64_t)getpid() << 20);
    *out = nano + pid;                    /* Go: uint64(int64 + int64)   */
    return CMT_OK;
}

/* tempfile.go:52-72 `randWriteFileSuffix`: advance the LCG, format
 * `int(r)` (a signed 64-bit view of the unsigned state), and turn a
 * leading '-' into '0'. */
static int rand_write_file_suffix(nodus_cmt_privval_t *ctx, char out[24]) {
    uint64_t r = ctx->atomic_write_file_rand;
    if (r == 0) {
        if (write_file_rand_reseed(ctx, &r) != CMT_OK) return CMT_FAULT;
    }
    r = r * LCG_A + LCG_C;                /* :60, wraps like Go's uint64 */
    ctx->atomic_write_file_rand = r;
    /* :65 strconv.Itoa(int(r)) — two's-complement reinterpretation. */
    int64_t v = (r <= (uint64_t)INT64_MAX)
                    ? (int64_t)r
                    : -(int64_t)(UINT64_MAX - r) - 1;
    snprintf(out, 24, "%" PRId64, v);
    if (out[0] == '-') out[0] = '0';      /* :66-70                      */
    return CMT_OK;
}

/* filepath.Dir(filename) for the one shape used here: everything before
 * the last '/', "." when there is none, "/" for a root-level file. */
static int path_dir(const char *filename, char **out_dir) {
    const char *slash = strrchr(filename, '/');
    char *d;
    if (!slash) {
        d = strdup(".");
    } else if (slash == filename) {
        d = strdup("/");
    } else {
        size_t n = (size_t)(slash - filename);
        d = (char *)malloc(n + 1);
        if (d) { memcpy(d, filename, n); d[n] = '\0'; }
    }
    if (!d) return CMT_FAULT;
    *out_dir = d;
    return CMT_OK;
}

static int write_all(int fd, const uint8_t *data, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;            /* :121-122 io.ErrShortWrite   */
        off += (size_t)n;
    }
    return 0;
}

int nodus_cmt_write_file_atomic(nodus_cmt_privval_t *ctx,
                                const char *filename,
                                const uint8_t *data, size_t len,
                                mode_t perm) {
    if (!ctx || !filename || (!data && len)) return CMT_FAULT;

    char *dir = NULL;
    if (path_dir(filename, &dir) != CMT_OK) return CMT_FAULT;   /* :84 */

    size_t name_cap = strlen(dir) + 1 +
                      sizeof NODUS_CMT_ATOMIC_WRITE_FILE_PREFIX + 24;
    char *name = (char *)malloc(name_cap);
    if (!name) { free(dir); return CMT_FAULT; }

    int fd = -1;
    int nconflict = 0;                                          /* :88 */
    int i = 0;
    for (; i < ATOMIC_WRITE_FILE_MAX_NUM_WRITE_ATTEMPTS; i++) {  /* :93 */
        char suffix[24];
        if (rand_write_file_suffix(ctx, suffix) != CMT_OK) {
            free(name); free(dir);
            return CMT_FAULT;
        }
        snprintf(name, name_cap, "%s/%s%s", dir,
                 NODUS_CMT_ATOMIC_WRITE_FILE_PREFIX, suffix);       /* :94 */
        fd = open(name, ATOMIC_WRITE_FILE_FLAG, perm);              /* :95 */
        if (fd < 0) {
            if (errno == EEXIST) {                                  /* :97 */
                if (++nconflict > ATOMIC_WRITE_FILE_MAX_NUM_CONFLICTS) {
                    uint64_t seed;                                 /* :100-104 */
                    if (write_file_rand_reseed(ctx, &seed) != CMT_OK) {
                        free(name); free(dir);
                        return CMT_FAULT;
                    }
                    ctx->atomic_write_file_rand = seed;
                }
                continue;
            }
            QGP_LOG_ERROR(LOG_TAG, "atomic write: open %s failed: %s",
                          name, strerror(errno));                   /* :107 */
            free(name); free(dir);
            return CMT_FAULT;
        }
        break;
    }
    if (i == ATOMIC_WRITE_FILE_MAX_NUM_WRITE_ATTEMPTS) {            /* :111 */
        QGP_LOG_ERROR(LOG_TAG,
                      "could not create atomic write file after %d attempts",
                      i);
        free(name); free(dir);
        return CMT_FAULT;
    }

    /* :116-117 — the temp file is removed on every path; on the success
     * path the rename has already taken the name away. */
    int rc = CMT_FAULT;
    if (write_all(fd, data, len) != 0) {                            /* :119 */
        QGP_LOG_ERROR(LOG_TAG, "atomic write: write failed: %s",
                      strerror(errno));
        close(fd);
        goto cleanup;
    }
    if (close(fd) != 0) {                                           /* :126 */
        QGP_LOG_ERROR(LOG_TAG, "atomic write: close failed: %s",
                      strerror(errno));
        goto cleanup;
    }
    fd = -1;
    if (rename(name, filename) != 0) {                              /* :128 */
        QGP_LOG_ERROR(LOG_TAG, "atomic write: rename to %s failed: %s",
                      filename, strerror(errno));
        goto cleanup;
    }

    /* DEVIATION R3-B-1: the directory entry is made durable too. */
    {
        int dfd = open(dir, O_RDONLY | O_DIRECTORY);
        if (dfd < 0) {
            QGP_LOG_ERROR(LOG_TAG, "atomic write: open dir %s failed: %s",
                          dir, strerror(errno));
            goto cleanup;
        }
        if (fsync(dfd) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "atomic write: fsync dir %s failed: %s",
                          dir, strerror(errno));
            close(dfd);
            goto cleanup;
        }
        close(dfd);
    }
    rc = CMT_OK;

cleanup:
    (void)unlink(name);                   /* :116 — ENOENT after rename  */
    free(name);
    free(dir);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════
 * privval/file.go:135-147 Save, :198-233 loadFilePV (state half)
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_privval_save_lss(void *vctx, const cmt_lss_t *lss) {
    nodus_cmt_privval_t *ctx = (nodus_cmt_privval_t *)vctx;
    if (!ctx || !lss) return CMT_FAULT;
    if (!ctx->state_path || ctx->state_path[0] == '\0') {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "cannot save FilePVLastSignState: filePath not set");
        return CMT_FAULT;                                           /* :138 */
    }
    char *json = (char *)malloc(NODUS_CMT_LSS_JSON_MAX);
    if (!json) return CMT_FAULT;
    size_t n = 0;
    if (nodus_cmt_lss_marshal_indent(lss, json, NODUS_CMT_LSS_JSON_MAX, &n)
        != CMT_OK) {
        free(json);
        return CMT_FAULT;                                           /* :142 */
    }
    int rc = nodus_cmt_write_file_atomic(ctx, ctx->state_path,
                                         (const uint8_t *)json, n, 0600);
    free(json);
    if (rc != CMT_OK) return CMT_FAULT;                             /* :146 */
    return CMT_OK;
}

/* os.ReadFile — the whole file, bounded by NODUS_CMT_LSS_FILE_MAX. */
static int read_whole_file(const char *path, uint8_t **out, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > NODUS_CMT_LSS_FILE_MAX) {
        close(fd);
        return -1;
    }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(n ? n : 1);
    if (!buf) { close(fd); return -1; }
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd);
            return -1;
        }
        if (r == 0) break;
        off += (size_t)r;
    }
    close(fd);
    *out = buf;
    *out_len = off;
    return 0;
}

int nodus_cmt_privval_open(nodus_cmt_privval_t *ctx,
                           const char *state_file_path,
                           cmt_now_fn now, void *now_ctx,
                           bool load_state, cmt_lss_t *out_lss) {
    if (!ctx || !state_file_path || !now || !out_lss) return CMT_FAULT;

    cmt_lss_t pv_state;
    memset(&pv_state, 0, sizeof pv_state);       /* :211 FilePVLastSignState{} */

    if (load_state) {                              /* :213 */
        uint8_t *bz = NULL;
        size_t n = 0;
        if (read_whole_file(state_file_path, &bz, &n) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "cannot read PrivValidator state %s: %s",
                          state_file_path, strerror(errno));
            return CMT_FAULT;                      /* :216 cmtos.Exit */
        }
        int rc = nodus_cmt_lss_unmarshal(bz, n, &pv_state);
        free(bz);
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Error reading PrivValidator state from %s",
                          state_file_path);
            return CMT_FAULT;                      /* :220 cmtos.Exit */
        }
    }

    char *path = strdup(state_file_path);          /* :224 filePath */
    if (!path) return CMT_FAULT;

    memset(ctx, 0, sizeof *ctx);
    ctx->state_path = path;
    ctx->now = now;
    ctx->now_ctx = now_ctx;
    ctx->atomic_write_file_rand = 0;               /* tempfile.go:34 */
    *out_lss = pv_state;
    return CMT_OK;
}

void nodus_cmt_privval_close(nodus_cmt_privval_t *ctx) {
    if (!ctx) return;
    free(ctx->state_path);
    ctx->state_path = NULL;
    ctx->now = NULL;
    ctx->now_ctx = NULL;
}
