/**
 * @file amm_req.c
 * @brief nodus-amm signed-request verification (see amm_req.h).
 */
#include "amm_req.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <string.h>

#include "crypto/hash/keccak256.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/nodus_sign.h"

/* ── small helpers ────────────────────────────────────────────────────── */

static int hex_digit_lower(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* `n` characters of lowercase hex copied to `out` (NUL added); `out` holds
 * n + 1 bytes. */
static int lower_hex_copy(const char *s, size_t n, char *out) {
    for (size_t i = 0; i < n; i++)
        if (hex_digit_lower(s[i]) < 0) return -1;
    memcpy(out, s, n);
    out[n] = '\0';
    return 0;
}

static void hex_to_bytes(const char *hex, size_t nbytes, uint8_t *out) {
    for (size_t i = 0; i < nbytes; i++)
        out[i] = (uint8_t)((hex_digit_lower(hex[2 * i]) << 4) |
                           hex_digit_lower(hex[2 * i + 1]));
}

static void bytes_to_hex(const uint8_t *b, size_t n, char *out) {
    static const char D[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = D[b[i] >> 4];
        out[2 * i + 1] = D[b[i] & 15];
    }
    out[2 * n] = '\0';
}

/* Decimal, 1..20 digits, no sign, no leading zero ("0" alone is allowed),
 * value <= 2^64 - 1 (plan 6.4.2). */
static int dec_u64(const char *s, size_t n, uint64_t *out) {
    if (n == 0 || n > 20) return -1;
    if (n > 1 && s[0] == '0') return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

/* `<integer>.<frac_digits digits> <unit>` -> raw (plan 6.4.2). The integer
 * part is "0" or digits without a leading zero; exactly `frac_digits`
 * fraction digits; the raw value is the digits with the point removed and
 * must fit 2^64 - 1. */
static int amount_text(const char *s, size_t n, unsigned frac_digits,
                       const char *unit, uint64_t *out) {
    size_t ul = strlen(unit);
    if (n < ul + 1 + 1 + frac_digits + 1) return -1;
    if (s[n - ul - 1] != ' ' || memcmp(s + n - ul, unit, ul) != 0) return -1;
    size_t body = n - ul - 1;                       /* integer '.' fraction */
    if (body < 1 + 1 + frac_digits) return -1;
    size_t int_len = body - 1 - frac_digits;
    if (s[int_len] != '.') return -1;
    if (int_len > 1 && s[0] == '0') return -1;
    uint64_t ip = 0, fp = 0, scale = 1;
    for (size_t i = 0; i < int_len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (ip > (UINT64_MAX - d) / 10) return -1;
        ip = ip * 10 + d;
    }
    for (unsigned i = 0; i < frac_digits; i++) {
        char c = s[int_len + 1 + i];
        if (c < '0' || c > '9') return -1;
        fp = fp * 10 + (uint64_t)(c - '0');
        scale *= 10;
    }
    if (ip > (UINT64_MAX - fp) / scale) return -1;
    *out = ip * scale + fp;
    return 0;
}

static void req_no_bytes(uint64_t v, uint8_t out[32]) {
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* ── EIP-712 ──────────────────────────────────────────────────────────── */

static void u256_be(uint64_t v, uint8_t out[32]) { req_no_bytes(v, out); }

int amm_req_eip712_digest(const uint8_t domain_separator[32],
                          const uint8_t struct_hash[32], uint8_t out[32]) {
    if (!domain_separator || !struct_hash || !out) return -1;
    uint8_t buf[2 + 32 + 32];
    buf[0] = 0x19;
    buf[1] = 0x01;
    memcpy(buf + 2, domain_separator, 32);
    memcpy(buf + 34, struct_hash, 32);
    return keccak256(buf, sizeof(buf), out);
}

#define DOMAIN_TYPE "EIP712Domain(string name,uint256 chainId)"
#define USDT_TYPE   "UsdtToNodusRequest(address sender,string destination," \
                    "uint256 amount,uint256 minimumToReceive," \
                    "uint256 requestNumber)"
#define LIQ_TYPE    "LiquidityAddRequest(address ethereumAddress," \
                    "string nodusAddress,uint256 usdtAmount," \
                    "uint256 nodusAmount,uint256 requestNumber)"

int amm_req_domain_separator(const char *name, uint64_t chain_id, uint8_t out[32]) {
    if (!name || !out) return -1;
    uint8_t enc[96];
    if (keccak256((const uint8_t *)DOMAIN_TYPE, sizeof(DOMAIN_TYPE) - 1, enc) != 0)
        return -1;
    if (keccak256((const uint8_t *)name, strlen(name), enc + 32) != 0) return -1;
    u256_be(chain_id, enc + 64);
    return keccak256(enc, sizeof(enc), out);
}

/* hashStruct of a struct (address, string, uint256, uint256, uint256): the
 * shape of both typed requests. `address` as uint160 (12 zero bytes then the
 * 20), `string` as keccak256 of its bytes, `uint256` big-endian
 * (eip-712.md:96-104). */
static int struct_hash5(const char *type, const uint8_t addr[20], const char *str,
                        uint64_t a, uint64_t b, uint64_t c, uint8_t out[32]) {
    uint8_t enc[6 * 32];
    memset(enc, 0, sizeof(enc));
    if (keccak256((const uint8_t *)type, strlen(type), enc) != 0) return -1;
    memcpy(enc + 32 + 12, addr, 20);
    if (keccak256((const uint8_t *)str, strlen(str), enc + 64) != 0) return -1;
    u256_be(a, enc + 96);
    u256_be(b, enc + 128);
    u256_be(c, enc + 160);
    return keccak256(enc, sizeof(enc), out);
}

static int typed_digest(const char *name, uint64_t chain_id, const char *type,
                        const char addr_hex[41], const char *str,
                        uint64_t a, uint64_t b, uint64_t c, uint8_t out[32]) {
    uint8_t addr[20], dom[32], sh[32];
    if (!name || !addr_hex || !str || !out) return -1;
    hex_to_bytes(addr_hex, 20, addr);
    if (amm_req_domain_separator(name, chain_id, dom) != 0) return -1;
    if (struct_hash5(type, addr, str, a, b, c, sh) != 0) return -1;
    return amm_req_eip712_digest(dom, sh, out);
}

int amm_req_usdt_digest(const char *eip712_name, uint64_t chain_id,
                        const amm_req_usdt_t *r, uint8_t out[32]) {
    if (!r) return -1;
    return typed_digest(eip712_name, chain_id, USDT_TYPE, r->sender,
                        r->destination, r->amount, r->minimum,
                        r->request_number, out);
}

int amm_req_liq_add_digest(const char *eip712_name, uint64_t chain_id,
                           const amm_req_liq_add_t *r, uint8_t out[32]) {
    if (!r) return -1;
    return typed_digest(eip712_name, chain_id, LIQ_TYPE, r->ethereum_address,
                        r->nodus_address, r->usdt_amount, r->nodus_amount,
                        r->request_number, out);
}

/* secp256k1 order N, big-endian: shared/evm/evm_precompile.c:138-143
 * (execution-specs ethereum/crypto/elliptic_curve.py SECP256K1N). */
static const uint8_t SECP256K1N_BE[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

/* 0 < x < N, as shared/evm/evm_precompile.c:145-152 (in_range_n). */
static int in_range_n(const uint8_t x[32]) {
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= x[i];
    if (!nonzero) return 0;
    return memcmp(x, SECP256K1N_BE, 32) < 0;
}

int amm_req_eth_recover(const uint8_t digest[32], const uint8_t sig[65],
                        uint8_t addr_out[20]) {
    if (!digest || !sig || !addr_out) return -1;
    /* v exactly 27 or 28 (plan 6.4.3, question 12 point 13 first choice) */
    if (sig[64] != 27 && sig[64] != 28) return -1;
    /* r and s in 1..N-1: the explicit check of the ecrecover port
     * (evm_precompile.c:166-171, execution-specs ecrecover.py) */
    if (!in_range_n(sig) || !in_range_n(sig + 32)) return -1;
    secp256k1_ecdsa_recoverable_signature rs;
    secp256k1_pubkey pub;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1_context_static, &rs, sig, sig[64] - 27))
        return -1;
    if (!secp256k1_ecdsa_recover(secp256k1_context_static, &pub, &rs, digest))
        return -1;
    uint8_t ser[65];
    size_t ser_len = sizeof(ser);
    if (!secp256k1_ec_pubkey_serialize(secp256k1_context_static, ser, &ser_len,
                                       &pub, SECP256K1_EC_UNCOMPRESSED) ||
        ser_len != 65)
        return -1;
    uint8_t h[32];
    if (keccak256(ser + 1, 64, h) != 0) return -1;
    memcpy(addr_out, h + 12, 20);
    return 0;
}

/* "0x" + 40 lowercase hex -> 40 hex without the prefix. */
static int eth_addr_0x(const char *s, char out[41]) {
    if (!s || strlen(s) != 42 || s[0] != '0' || s[1] != 'x') return -1;
    return lower_hex_copy(s + 2, 40, out);
}

static int dec_str(const char *s, uint64_t *out) {
    return s ? dec_u64(s, strlen(s), out) : -1;
}

/* Recover the signer of `digest` and require it equals `addr_hex` (40 hex). */
static int signer_is(const uint8_t digest[32], const uint8_t sig[65],
                     const char addr_hex[41]) {
    uint8_t got[20], want[20];
    if (amm_req_eth_recover(digest, sig, got) != 0) return -1;
    hex_to_bytes(addr_hex, 20, want);
    return memcmp(got, want, 20) == 0 ? 0 : -1;
}

/* ── journal: request-number reuse ────────────────────────────────────── */

static int req_reuse(amm_journal_t *j, const char *sender, const uint8_t req_no[32]) {
    int r = amm_journal_req_marker_exists(j, sender, req_no);
    if (r == 0) return AMM_REQ_REUSED;
    if (r == 1) return AMM_REQ_OK;
    return AMM_REQ_ERR;
}

/* ── typed requests, without the journal ──────────────────────────────── */

static int usdt_check(const amm_cfg_t *cfg, const amm_req_usdt_in_t *in,
                      amm_req_usdt_t *out) {
    memset(out, 0, sizeof(*out));
    if (!in->sender || !in->destination || !in->amount ||
        !in->minimum_to_receive || !in->request_number)
        return AMM_REQ_ERR;
    if (eth_addr_0x(in->sender, out->sender) != 0 ||
        strlen(in->destination) != 128 ||
        lower_hex_copy(in->destination, 128, out->destination) != 0 ||
        dec_str(in->amount, &out->amount) != 0 ||
        dec_str(in->minimum_to_receive, &out->minimum) != 0 ||
        dec_str(in->request_number, &out->request_number) != 0)
        return AMM_REQ_FORMAT;
    req_no_bytes(out->request_number, out->req_no);
    uint8_t digest[32];
    if (amm_req_usdt_digest(cfg->eip712_name, cfg->eth_chain_id, out, digest) != 0)
        return AMM_REQ_ERR;
    if (signer_is(digest, in->signature, out->sender) != 0) return AMM_REQ_SIGNATURE;
    return AMM_REQ_OK;
}

static int liq_eth_check(const amm_cfg_t *cfg, const amm_req_liq_eth_in_t *in,
                         amm_req_liq_add_t *out) {
    memset(out, 0, sizeof(*out));
    if (!in->ethereum_address || !in->nodus_address || !in->usdt_amount ||
        !in->nodus_amount || !in->request_number)
        return AMM_REQ_ERR;
    if (eth_addr_0x(in->ethereum_address, out->ethereum_address) != 0 ||
        strlen(in->nodus_address) != 128 ||
        lower_hex_copy(in->nodus_address, 128, out->nodus_address) != 0 ||
        dec_str(in->usdt_amount, &out->usdt_amount) != 0 ||
        dec_str(in->nodus_amount, &out->nodus_amount) != 0 ||
        dec_str(in->request_number, &out->request_number) != 0)
        return AMM_REQ_FORMAT;
    req_no_bytes(out->request_number, out->req_no);
    uint8_t digest[32];
    if (amm_req_liq_add_digest(cfg->eip712_name, cfg->eth_chain_id, out, digest) != 0)
        return AMM_REQ_ERR;
    if (signer_is(digest, in->signature, out->ethereum_address) != 0)
        return AMM_REQ_SIGNATURE;
    return AMM_REQ_OK;
}

/* ── the Nodus-key texts (plan 6.4.2, 6.4.4, 6.4.6) ───────────────────── */

typedef enum {
    F_NODUS_ADDR,   /* 128 lowercase hex                                   */
    F_ETH_ADDR,     /* "0x" + 40 lowercase hex                             */
    F_NODUS_AMT,    /* <int>.<8 digits> NODUS                              */
    F_USDT_AMT,     /* <int>.<6 digits> USDT                               */
    F_HEX128,       /* transfer id: 128 lowercase hex                      */
    F_HEX64,        /* Nodus chain id: 64 lowercase hex                    */
    F_U64,          /* request number: decimal                             */
    F_BPS           /* basis points: decimal 1..10000                      */
} ftype_t;

typedef struct { const char *key; ftype_t t; } fspec_t;

typedef struct {
    const char *title;       /* line 1                                     */
    const fspec_t *f;
    size_t n;
    size_t signer_idx;       /* the field holding the signer's Nodus address */
    size_t chain_idx;        /* the `Chain ID` field                       */
} tspec_t;

/* Field order of 6.4.4 / 6.4.6. */
static const fspec_t NU_FIELDS[] = {
    {"Sender", F_NODUS_ADDR}, {"Destination", F_ETH_ADDR},
    {"Amount", F_NODUS_AMT}, {"Minimum To Receive", F_USDT_AMT},
    {"Transfer ID", F_HEX128}, {"Chain ID", F_HEX64},
    {"Request Number", F_U64}
};
enum { NU_SENDER, NU_DEST, NU_AMOUNT, NU_MIN, NU_TRANSFER, NU_CHAIN, NU_REQ };

static const fspec_t LA_FIELDS[] = {
    {"Ethereum Address", F_ETH_ADDR}, {"Nodus Address", F_NODUS_ADDR},
    {"USDT Amount", F_USDT_AMT}, {"NODUS Amount", F_NODUS_AMT},
    {"Transfer ID", F_HEX128}, {"Chain ID", F_HEX64},
    {"Request Number", F_U64}
};
enum { LA_ETH, LA_NODUS, LA_USDT, LA_NODUS_AMT, LA_TRANSFER, LA_CHAIN, LA_REQ };

static const fspec_t LW_FIELDS[] = {
    {"Ethereum Address", F_ETH_ADDR}, {"Nodus Address", F_NODUS_ADDR},
    {"Basis Points", F_BPS}, {"Chain ID", F_HEX64},
    {"Request Number", F_U64}
};
enum { LW_ETH, LW_NODUS, LW_BPS, LW_CHAIN, LW_REQ };

static const tspec_t NU_SPEC = {
    "Nodus Swap: NODUS to USDT request", NU_FIELDS,
    sizeof(NU_FIELDS) / sizeof(NU_FIELDS[0]), NU_SENDER, NU_CHAIN
};
static const tspec_t LA_SPEC = {
    "Nodus Swap: liquidity add request", LA_FIELDS,
    sizeof(LA_FIELDS) / sizeof(LA_FIELDS[0]), LA_NODUS, LA_CHAIN
};
static const tspec_t LW_SPEC = {
    "Nodus Swap: liquidity withdraw request", LW_FIELDS,
    sizeof(LW_FIELDS) / sizeof(LW_FIELDS[0]), LW_NODUS, LW_CHAIN
};

#define MAX_FIELDS 8

typedef struct {
    char     s[129];         /* hex types: the hex (an Ethereum address
                              * without "0x")                              */
    uint64_t u;              /* numeric types                              */
} fval_t;

static int parse_value(ftype_t t, const char *p, size_t n, fval_t *v) {
    memset(v, 0, sizeof(*v));
    switch (t) {
    case F_NODUS_ADDR:
    case F_HEX128: return n == 128 ? lower_hex_copy(p, 128, v->s) : -1;
    case F_HEX64:  return n == 64 ? lower_hex_copy(p, 64, v->s) : -1;
    case F_ETH_ADDR:
        if (n != 42 || p[0] != '0' || p[1] != 'x') return -1;
        return lower_hex_copy(p + 2, 40, v->s);
    case F_NODUS_AMT: return amount_text(p, n, 8, "NODUS", &v->u);
    case F_USDT_AMT:  return amount_text(p, n, 6, "USDT", &v->u);
    case F_U64:       return dec_u64(p, n, &v->u);
    case F_BPS:
        if (dec_u64(p, n, &v->u) != 0) return -1;
        return (v->u >= 1 && v->u <= 10000) ? 0 : -1;
    }
    return -1;
}

/* Append helpers for the canonical rebuild: a write that does not fit is a
 * failure, never a truncation. */
typedef struct { char buf[AMM_REQ_TEXT_MAX + 1]; size_t len; int bad; } sb_t;

static void sb_put(sb_t *b, const char *s, size_t n) {
    if (b->bad || n > AMM_REQ_TEXT_MAX - b->len) { b->bad = 1; return; }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
}
static void sb_str(sb_t *b, const char *s) { sb_put(b, s, strlen(s)); }

static void sb_amount(sb_t *b, uint64_t raw, unsigned frac_digits, const char *unit) {
    uint64_t scale = 1;
    for (unsigned i = 0; i < frac_digits; i++) scale *= 10;
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%llu.%0*llu ", (unsigned long long)(raw / scale),
                     (int)frac_digits, (unsigned long long)(raw % scale));
    if (n < 0 || (size_t)n >= sizeof(tmp)) { b->bad = 1; return; }
    sb_put(b, tmp, (size_t)n);
    sb_str(b, unit);
}

static void sb_value(sb_t *b, ftype_t t, const fval_t *v) {
    char tmp[32];
    int n;
    switch (t) {
    case F_NODUS_ADDR:
    case F_HEX128:
    case F_HEX64:    sb_str(b, v->s); break;
    case F_ETH_ADDR: sb_str(b, "0x"); sb_str(b, v->s); break;
    case F_NODUS_AMT: sb_amount(b, v->u, 8, "NODUS"); break;
    case F_USDT_AMT:  sb_amount(b, v->u, 6, "USDT"); break;
    case F_U64:
    case F_BPS:
        n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v->u);
        if (n < 0 || (size_t)n >= sizeof(tmp)) { b->bad = 1; return; }
        sb_put(b, tmp, (size_t)n);
        break;
    }
}

/* Strict parse of one Nodus-key text; then the canonical text is rebuilt from
 * the parsed fields and must equal the signed bytes (plan 6.2, 6.4.2). The
 * input is read, never changed. */
static int parse_text(const tspec_t *sp, const uint8_t *text, size_t len,
                      fval_t v[MAX_FIELDS]) {
    if (!text || len == 0 || len > AMM_REQ_TEXT_MAX) return -1;
    /* ASCII 0x20-0x7E and LF only: no CR, no tab, no other byte; no LF after
     * the last line (plan 6.4.2) */
    for (size_t i = 0; i < len; i++)
        if (text[i] != '\n' && (text[i] < 0x20 || text[i] > 0x7e)) return -1;
    if (text[len - 1] == '\n') return -1;
    const char *p = (const char *)text;

    size_t pos = strlen(sp->title);
    if (len <= pos || memcmp(p, sp->title, pos) != 0 || p[pos] != '\n') return -1;
    pos++;
    for (size_t i = 0; i < sp->n; i++) {
        size_t kl = strlen(sp->f[i].key);
        if (len - pos < kl + 2) return -1;
        if (memcmp(p + pos, sp->f[i].key, kl) != 0 ||
            p[pos + kl] != ':' || p[pos + kl + 1] != ' ')
            return -1;
        size_t vs = pos + kl + 2;
        const char *lf = memchr(p + vs, '\n', len - vs);
        int last = (i + 1 == sp->n);
        if (last ? lf != NULL : lf == NULL) return -1;   /* extra / missing line */
        size_t ve = last ? len : (size_t)(lf - p);
        if (parse_value(sp->f[i].t, p + vs, ve - vs, &v[i]) != 0) return -1;
        pos = last ? len : ve + 1;
    }
    if (pos != len) return -1;

    sb_t b;
    b.len = 0;
    b.bad = 0;
    sb_str(&b, sp->title);
    for (size_t i = 0; i < sp->n; i++) {
        sb_str(&b, "\n");
        sb_str(&b, sp->f[i].key);
        sb_str(&b, ": ");
        sb_value(&b, sp->f[i].t, &v[i]);
    }
    if (b.bad || b.len != len || memcmp(b.buf, text, len) != 0) return -1;
    return 0;
}

/* Everything but the journal: format, chain id, address = SHA3-512(public
 * key), the signature over expected_origin. */
static int text_check(const amm_cfg_t *cfg, const tspec_t *sp,
                      const amm_req_nodus_in_t *in, fval_t v[MAX_FIELDS]) {
    if (!in || !in->text || !in->public_key || !in->signature ||
        !cfg->expected_origin[0])
        return AMM_REQ_ERR;
    if (parse_text(sp, in->text, in->text_len, v) != 0) return AMM_REQ_FORMAT;

    char chain_hex[65];
    bytes_to_hex(cfg->chain_id, 32, chain_hex);
    if (strcmp(v[sp->chain_idx].s, chain_hex) != 0) return AMM_REQ_CHAIN;

    uint8_t raw[64];
    char addr_hex[129];
    if (qgp_sha3_512(in->public_key->bytes, NODUS_PK_BYTES, raw) != 0)
        return AMM_REQ_ERR;
    bytes_to_hex(raw, 64, addr_hex);
    if (strcmp(v[sp->signer_idx].s, addr_hex) != 0) return AMM_REQ_ADDRESS;

    if (nodus_verify_site_message(in->signature,
                                  (const uint8_t *)cfg->expected_origin,
                                  strlen(cfg->expected_origin), in->text,
                                  in->text_len, in->public_key) != 0)
        return AMM_REQ_SIGNATURE;
    return AMM_REQ_OK;
}

/* ── public verify functions ──────────────────────────────────────────── */

int amm_req_usdt_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                        const amm_req_usdt_in_t *in, amm_req_usdt_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!cfg || !j || !in || !out) return AMM_REQ_ERR;
    int rc = usdt_check(cfg, in, out);
    if (rc == AMM_REQ_OK) rc = req_reuse(j, out->sender, out->req_no);
    if (rc != AMM_REQ_OK) memset(out, 0, sizeof(*out));
    return rc;
}

int amm_req_nodus_to_usdt_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                 const amm_req_nodus_in_t *in,
                                 amm_req_nodus_to_usdt_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!cfg || !j || !in || !out) return AMM_REQ_ERR;
    fval_t v[MAX_FIELDS];
    int rc = text_check(cfg, &NU_SPEC, in, v);
    if (rc != AMM_REQ_OK) return rc;
    memcpy(out->sender, v[NU_SENDER].s, sizeof(out->sender));
    memcpy(out->destination, v[NU_DEST].s, sizeof(out->destination));
    out->amount = v[NU_AMOUNT].u;
    out->minimum = v[NU_MIN].u;
    memcpy(out->transfer_id, v[NU_TRANSFER].s, sizeof(out->transfer_id));
    out->request_number = v[NU_REQ].u;
    req_no_bytes(out->request_number, out->req_no);
    rc = req_reuse(j, out->sender, out->req_no);
    if (rc != AMM_REQ_OK) memset(out, 0, sizeof(*out));
    return rc;
}

int amm_req_liquidity_add_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                 const amm_req_liq_eth_in_t *eth,
                                 const amm_req_nodus_in_t *nodus,
                                 amm_req_liq_add_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!cfg || !j || !eth || !nodus || !out) return AMM_REQ_ERR;
    amm_req_liq_add_t e;
    int rc = liq_eth_check(cfg, eth, &e);
    if (rc != AMM_REQ_OK) return rc;
    fval_t v[MAX_FIELDS];
    rc = text_check(cfg, &LA_SPEC, nodus, v);
    if (rc != AMM_REQ_OK) return rc;

    /* the tie (6.4.6): same two addresses, same two raw amounts, same number */
    if (strcmp(e.ethereum_address, v[LA_ETH].s) != 0 ||
        strcmp(e.nodus_address, v[LA_NODUS].s) != 0 ||
        e.usdt_amount != v[LA_USDT].u || e.nodus_amount != v[LA_NODUS_AMT].u ||
        e.request_number != v[LA_REQ].u)
        return AMM_REQ_PAIR;

    memcpy(e.transfer_id, v[LA_TRANSFER].s, sizeof(e.transfer_id));
    rc = req_reuse(j, e.ethereum_address, e.req_no);
    if (rc == AMM_REQ_OK) rc = req_reuse(j, e.nodus_address, e.req_no);
    if (rc != AMM_REQ_OK) return rc;
    *out = e;
    return AMM_REQ_OK;
}

int amm_req_liquidity_withdraw_verify(const amm_cfg_t *cfg, amm_journal_t *j,
                                      const amm_req_nodus_in_t *in,
                                      amm_req_liq_withdraw_t *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!cfg || !j || !in || !out) return AMM_REQ_ERR;
    fval_t v[MAX_FIELDS];
    int rc = text_check(cfg, &LW_SPEC, in, v);
    if (rc != AMM_REQ_OK) return rc;
    memcpy(out->ethereum_address, v[LW_ETH].s, sizeof(out->ethereum_address));
    memcpy(out->nodus_address, v[LW_NODUS].s, sizeof(out->nodus_address));
    out->basis_points = (uint32_t)v[LW_BPS].u;
    out->request_number = v[LW_REQ].u;
    req_no_bytes(out->request_number, out->req_no);
    rc = req_reuse(j, out->nodus_address, out->req_no);
    if (rc != AMM_REQ_OK) memset(out, 0, sizeof(*out));
    return rc;
}
