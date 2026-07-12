/*
 * DNA Engine — Call Crypto (PQ VoIP Faz A)
 *
 * Per-call media key agreement. See dna_call_crypto.h and
 * docs/plans/2026-07-12-pq-voip-faz-a-signaling-design.md §4.3.
 *
 * Uses only audited primitives: hkdf_sha3_256 (RFC 5869 Extract-then-Expand),
 * qgp_sha3_512. No new KEM/KDF/cipher (ANA HEDEF: KAFADAN KRIPTO YASAK).
 *
 * @file dna_call_crypto.c
 */

#include "dna_call_crypto.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_types.h"   /* qgp_base64_encode / qgp_base64_decode */

#include <stdlib.h>
#include <string.h>

extern void qgp_secure_memzero(void *ptr, size_t len);

/* salt = caller_fp[0:32] || callee_fp[0:32]                       (64 B) */
#define CALL_SALT_LEN   64u
/* ikm  = ss_eph || ss_static                                      (64 B) */
#define CALL_IKM_LEN    64u
/* info = "dna-call-v1" || call_id(16) || SHA3-512(eph_pk)[0:32]   (59 B) */
#define CALL_INFO_LEN   (DNA_CALL_INFO_TAG_LEN + DNA_CALL_ID_LEN + 32u)

int dna_call_derive_key(
    const uint8_t ss_eph[DNA_CALL_SS_LEN],
    const uint8_t ss_static[DNA_CALL_SS_LEN],
    const uint8_t caller_fp[DNA_CALL_FP_LEN],
    const uint8_t callee_fp[DNA_CALL_FP_LEN],
    const uint8_t call_id[DNA_CALL_ID_LEN],
    const uint8_t eph_pk[DNA_CALL_KYBER_PK_LEN],
    uint8_t key_out[DNA_CALL_KEY_LEN])
{
    if (!ss_eph || !ss_static || !caller_fp || !callee_fp ||
        !call_id || !eph_pk || !key_out)
        return DNA_CALL_ERR_NULL;

    /* salt = caller_fp[0:32] || callee_fp[0:32] — binds the intended pair
     * (F-BIND), mirroring nodus_circuit_open_e2e's src/peer fp nonces. */
    uint8_t salt[CALL_SALT_LEN];
    memcpy(salt, caller_fp, 32);
    memcpy(salt + 32, callee_fp, 32);

    /* ikm = ss_eph || ss_static — ephemeral first (fixed order, §1.1.2). */
    uint8_t ikm[CALL_IKM_LEN];
    memcpy(ikm, ss_eph, DNA_CALL_SS_LEN);
    memcpy(ikm + DNA_CALL_SS_LEN, ss_static, DNA_CALL_SS_LEN);

    /* info = version tag || call_id || SHA3-512(eph_pk)[0:32]. */
    uint8_t info[CALL_INFO_LEN];
    memcpy(info, DNA_CALL_INFO_TAG, DNA_CALL_INFO_TAG_LEN);
    memcpy(info + DNA_CALL_INFO_TAG_LEN, call_id, DNA_CALL_ID_LEN);

    uint8_t eph_hash[64];
    int rc = qgp_sha3_512(eph_pk, DNA_CALL_KYBER_PK_LEN, eph_hash);
    if (rc != 0) {
        qgp_secure_memzero(ikm, sizeof(ikm));
        return DNA_CALL_ERR_CRYPTO;
    }
    memcpy(info + DNA_CALL_INFO_TAG_LEN + DNA_CALL_ID_LEN, eph_hash, 32);

    rc = hkdf_sha3_256(salt, sizeof(salt),
                       ikm, sizeof(ikm),
                       info, sizeof(info),
                       key_out, DNA_CALL_KEY_LEN);

    qgp_secure_memzero(ikm, sizeof(ikm));
    qgp_secure_memzero(eph_hash, sizeof(eph_hash));

    return (rc == 0) ? DNA_CALL_OK : DNA_CALL_ERR_CRYPTO;
}

/* ===================== canonical signer/verifier (§4.2) ===================== */

/* Portable substring search over a byte range (no memmem — Windows target). */
static const char *find_sub(const char *hay, size_t hlen,
                            const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return NULL;
}

int dna_call_sign_body(const char *body, size_t body_len,
                       const uint8_t *dsa_sk,
                       char *out, size_t out_cap, size_t *out_len)
{
    if (!body || !dsa_sk || !out || !out_len) return DNA_CALL_ERR_NULL;
    if (body_len > DNA_CALL_SIG_MAX_BODY) return DNA_CALL_ERR_OVERSIZE;

    const size_t prefix_len = strlen(DNA_CALL_SIG_PREFIX);   /* 7: "sig":"  */
    const size_t slot_len   = strlen(DNA_CALL_SIG_SLOT);     /* 8: "sig":"" */

    /* Locate the empty sig slot; require it to be unique. */
    const char *slot = find_sub(body, body_len, DNA_CALL_SIG_SLOT, slot_len);
    if (!slot) return DNA_CALL_ERR_FORMAT;
    size_t after = (size_t)(slot - body) + slot_len;
    if (find_sub(body + after, body_len - after, DNA_CALL_SIG_SLOT, slot_len))
        return DNA_CALL_ERR_FORMAT;   /* ambiguous: more than one slot */

    /* Sign the exact bytes (with the empty slot). */
    uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;
    if (qgp_dsa87_sign(sig, &siglen, (const uint8_t *)body, body_len, dsa_sk) != 0)
        return DNA_CALL_ERR_CRYPTO;

    size_t b64len = 0;
    char *b64 = qgp_base64_encode(sig, siglen, &b64len);
    qgp_secure_memzero(sig, sizeof(sig));
    if (!b64) return DNA_CALL_ERR_CRYPTO;

    /* Splice base64 between the two quotes of the sig value:
     * out = body[0 .. insert) + b64 + body[insert .. end),
     * where insert = index just after the opening quote (slot start + 7). */
    size_t insert = (size_t)(slot - body) + prefix_len;
    size_t total = body_len + b64len;
    if (total > out_cap) { free(b64); return DNA_CALL_ERR_OVERSIZE; }

    memcpy(out, body, insert);
    memcpy(out + insert, b64, b64len);
    memcpy(out + insert + b64len, body + insert, body_len - insert);
    *out_len = total;

    free(b64);
    return DNA_CALL_OK;
}

int dna_call_verify_body(const char *signed_body, size_t signed_len,
                         const uint8_t *dsa_pk)
{
    if (!signed_body || !dsa_pk) return DNA_CALL_ERR_NULL;
    if (signed_len > DNA_CALL_SIG_MAX_BODY) return DNA_CALL_ERR_OVERSIZE;

    const size_t prefix_len = strlen(DNA_CALL_SIG_PREFIX);   /* 7 */

    /* Locate  "sig":"  then read the base64 value up to the closing quote.
     * base64 never contains '"', so the scan is unambiguous. */
    const char *pfx = find_sub(signed_body, signed_len, DNA_CALL_SIG_PREFIX, prefix_len);
    if (!pfx) return DNA_CALL_ERR_FORMAT;
    size_t val_start = (size_t)(pfx - signed_body) + prefix_len;

    size_t q = val_start;
    while (q < signed_len && signed_body[q] != '"') q++;
    if (q >= signed_len) return DNA_CALL_ERR_FORMAT;   /* unterminated value */
    size_t b64len = q - val_start;

    /* Reconstruct the signed bytes: remove the base64 value, leaving "sig":""
     * — exactly what the signer signed. */
    size_t recon_len = signed_len - b64len;
    char recon[DNA_CALL_SIG_MAX_BODY];
    memcpy(recon, signed_body, val_start);
    memcpy(recon + val_start, signed_body + q, signed_len - q);

    /* Decode the signature (needs a NUL-terminated base64 string). */
    char b64buf[QGP_DSA87_SIGNATURE_BYTES * 2];
    if (b64len == 0 || b64len >= sizeof(b64buf)) return DNA_CALL_ERR_FORMAT;
    memcpy(b64buf, signed_body + val_start, b64len);
    b64buf[b64len] = '\0';

    size_t siglen = 0;
    uint8_t *sig = qgp_base64_decode(b64buf, &siglen);
    if (!sig) return DNA_CALL_ERR_FORMAT;
    if (siglen == 0 || siglen > QGP_DSA87_SIGNATURE_BYTES) {
        free(sig);
        return DNA_CALL_ERR_FORMAT;
    }

    int vr = qgp_dsa87_verify(sig, siglen,
                              (const uint8_t *)recon, recon_len, dsa_pk);
    free(sig);
    return (vr == 0) ? DNA_CALL_OK : DNA_CALL_ERR_VERIFY;
}

/* ===================== canonical signal builder (§4.2) ===================== */

#include <stdio.h>   /* snprintf */

/* Fixed base prefix shared by every kind:
 * {"type":"call_signal","v":1,"call":"<id>","sig":"","seq":<n>,"kind":"<K>"  */
#define CALL_BASE_FMT \
    "{\"type\":\"call_signal\",\"v\":1,\"call\":\"%s\",\"sig\":\"\"," \
    "\"seq\":%u,\"kind\":\"%s\""

static int is_known_kind(const char *k)
{
    return strcmp(k, DNA_CALL_KIND_INVITE)  == 0 ||
           strcmp(k, DNA_CALL_KIND_RINGING) == 0 ||
           strcmp(k, DNA_CALL_KIND_ACCEPT)  == 0 ||
           strcmp(k, DNA_CALL_KIND_REJECT)  == 0 ||
           strcmp(k, DNA_CALL_KIND_BUSY)    == 0 ||
           strcmp(k, DNA_CALL_KIND_END)     == 0;
}

/* Wrap snprintf: returns DNA_CALL_ERR_OVERSIZE if it would truncate. */
static int finish(char *out, size_t out_cap, size_t *out_len, int n)
{
    if (n < 0 || (size_t)n >= out_cap) return DNA_CALL_ERR_OVERSIZE;
    *out_len = (size_t)n;
    return DNA_CALL_OK;
}

int dna_call_build_body(const dna_call_signal_t *sig,
                        char *out, size_t out_cap, size_t *out_len)
{
    if (!sig || !out || !out_len) return DNA_CALL_ERR_NULL;
    if (!sig->kind || !is_known_kind(sig->kind)) return DNA_CALL_ERR_FORMAT;
    if (!sig->call_id_hex || strlen(sig->call_id_hex) != DNA_CALL_ID_LEN * 2)
        return DNA_CALL_ERR_FORMAT;

    if (strcmp(sig->kind, DNA_CALL_KIND_INVITE) == 0) {
        if (!sig->caller_fp_hex || strlen(sig->caller_fp_hex) != DNA_CALL_FP_LEN * 2 ||
            !sig->eph_pk)
            return DNA_CALL_ERR_FORMAT;
        size_t b64len = 0;
        char *eph_b64 = qgp_base64_encode(sig->eph_pk, DNA_CALL_KYBER_PK_LEN, &b64len);
        if (!eph_b64) return DNA_CALL_ERR_CRYPTO;
        int n = snprintf(out, out_cap,
                         CALL_BASE_FMT ",\"caller\":\"%s\",\"eph_pk\":\"%s\",\"cap\":%s}",
                         sig->call_id_hex, sig->seq, sig->kind,
                         sig->caller_fp_hex, eph_b64,
                         sig->cap_json ? sig->cap_json : "{}");
        free(eph_b64);
        return finish(out, out_cap, out_len, n);
    }

    if (strcmp(sig->kind, DNA_CALL_KIND_ACCEPT) == 0) {
        if (!sig->eph_ct || !sig->static_ct) return DNA_CALL_ERR_FORMAT;
        size_t l1 = 0, l2 = 0;
        char *e1 = qgp_base64_encode(sig->eph_ct, DNA_CALL_KYBER_PK_LEN, &l1);
        char *e2 = qgp_base64_encode(sig->static_ct, DNA_CALL_KYBER_PK_LEN, &l2);
        if (!e1 || !e2) { free(e1); free(e2); return DNA_CALL_ERR_CRYPTO; }
        int n = snprintf(out, out_cap,
                         CALL_BASE_FMT ",\"eph_ct\":\"%s\",\"static_ct\":\"%s\"}",
                         sig->call_id_hex, sig->seq, sig->kind, e1, e2);
        free(e1); free(e2);
        return finish(out, out_cap, out_len, n);
    }

    if (strcmp(sig->kind, DNA_CALL_KIND_REJECT) == 0 ||
        strcmp(sig->kind, DNA_CALL_KIND_BUSY)   == 0 ||
        strcmp(sig->kind, DNA_CALL_KIND_END)    == 0) {
        int n;
        if (sig->has_reason)
            n = snprintf(out, out_cap, CALL_BASE_FMT ",\"reason\":%d}",
                         sig->call_id_hex, sig->seq, sig->kind, sig->reason);
        else
            n = snprintf(out, out_cap, CALL_BASE_FMT "}",
                         sig->call_id_hex, sig->seq, sig->kind);
        return finish(out, out_cap, out_len, n);
    }

    /* RINGING: base fields only. */
    int n = snprintf(out, out_cap, CALL_BASE_FMT "}",
                     sig->call_id_hex, sig->seq, sig->kind);
    return finish(out, out_cap, out_len, n);
}

/* ===================== signal parser (§4.2) ===================== */

/* Locate  "<key>":"  and return the value span [*vp, *vp+*vlen) up to the next
 * '"'. Returns 1 on success, 0 if not found or unterminated. Bounds-checked. */
static int find_str(const char *b, size_t n, const char *key,
                    const char **vp, size_t *vlen)
{
    char tok[40];
    int tn = snprintf(tok, sizeof(tok), "\"%s\":\"", key);
    if (tn < 0 || (size_t)tn >= sizeof(tok)) return 0;
    const char *p = find_sub(b, n, tok, (size_t)tn);
    if (!p) return 0;
    size_t start = (size_t)(p - b) + (size_t)tn;
    size_t i = start;
    while (i < n && b[i] != '"') i++;
    if (i >= n) return 0;             /* unterminated value */
    *vp = b + start;
    *vlen = i - start;
    return 1;
}

/* Locate  "<key>":  followed by an optional-sign integer. */
static int find_int(const char *b, size_t n, const char *key, long *out)
{
    char tok[40];
    int tn = snprintf(tok, sizeof(tok), "\"%s\":", key);
    if (tn < 0 || (size_t)tn >= sizeof(tok)) return 0;
    const char *p = find_sub(b, n, tok, (size_t)tn);
    if (!p) return 0;
    size_t i = (size_t)(p - b) + (size_t)tn;
    int neg = 0;
    if (i < n && b[i] == '-') { neg = 1; i++; }
    if (i >= n || b[i] < '0' || b[i] > '9') return 0;
    long v = 0;
    while (i < n && b[i] >= '0' && b[i] <= '9') {
        v = v * 10 + (b[i] - '0');
        if (v > 1000000000L) v = 1000000000L;   /* clamp, avoid overflow */
        i++;
    }
    *out = neg ? -v : v;
    return 1;
}

/* Decode a base64 value span into a fixed-size buffer; require exact length. */
static int decode_exact(const char *v, size_t vlen, uint8_t *out, size_t expect)
{
    char b64[QGP_DSA87_SIGNATURE_BYTES * 2];
    if (vlen == 0 || vlen >= sizeof(b64)) return 0;
    memcpy(b64, v, vlen);
    b64[vlen] = '\0';
    size_t dlen = 0;
    uint8_t *d = qgp_base64_decode(b64, &dlen);
    if (!d) return 0;
    int ok = (dlen == expect);
    if (ok) memcpy(out, d, expect);
    free(d);
    return ok;
}

int dna_call_parse_body(const char *body, size_t body_len,
                        dna_call_parsed_t *out)
{
    if (!body || !out) return DNA_CALL_ERR_NULL;
    memset(out, 0, sizeof(*out));

    const char *v; size_t vl;

    /* kind (required, known). */
    if (!find_str(body, body_len, "kind", &v, &vl)) return DNA_CALL_ERR_FORMAT;
    if (vl >= sizeof(out->kind)) return DNA_CALL_ERR_FORMAT;
    memcpy(out->kind, v, vl);
    out->kind[vl] = '\0';
    if (!is_known_kind(out->kind)) return DNA_CALL_ERR_FORMAT;

    /* call_id (required, 32 hex). */
    if (!find_str(body, body_len, "call", &v, &vl)) return DNA_CALL_ERR_FORMAT;
    if (vl != DNA_CALL_ID_LEN * 2) return DNA_CALL_ERR_FORMAT;
    memcpy(out->call_id_hex, v, vl);
    out->call_id_hex[vl] = '\0';

    /* seq (required). */
    long seq = 0;
    if (!find_int(body, body_len, "seq", &seq)) return DNA_CALL_ERR_FORMAT;
    out->seq = (uint32_t)seq;

    if (strcmp(out->kind, DNA_CALL_KIND_INVITE) == 0) {
        if (!find_str(body, body_len, "caller", &v, &vl) || vl != DNA_CALL_FP_LEN * 2)
            return DNA_CALL_ERR_FORMAT;
        memcpy(out->caller_fp_hex, v, vl);
        out->caller_fp_hex[vl] = '\0';
        out->has_caller = 1;

        if (!find_str(body, body_len, "eph_pk", &v, &vl) ||
            !decode_exact(v, vl, out->eph_pk, DNA_CALL_KYBER_PK_LEN))
            return DNA_CALL_ERR_FORMAT;
        out->has_eph_pk = 1;
    } else if (strcmp(out->kind, DNA_CALL_KIND_ACCEPT) == 0) {
        if (!find_str(body, body_len, "eph_ct", &v, &vl) ||
            !decode_exact(v, vl, out->eph_ct, DNA_CALL_KYBER_PK_LEN))
            return DNA_CALL_ERR_FORMAT;
        out->has_eph_ct = 1;
        if (!find_str(body, body_len, "static_ct", &v, &vl) ||
            !decode_exact(v, vl, out->static_ct, DNA_CALL_KYBER_PK_LEN))
            return DNA_CALL_ERR_FORMAT;
        out->has_static_ct = 1;
    } else {
        /* REJECT / BUSY / END / RINGING: reason is optional. */
        long r = 0;
        if (find_int(body, body_len, "reason", &r)) {
            out->reason = (int)r;
            out->has_reason = 1;
        }
    }

    return DNA_CALL_OK;
}
