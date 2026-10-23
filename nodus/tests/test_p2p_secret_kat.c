/**
 * @file nodus/tests/test_p2p_secret_kat.c
 * @brief Known-answer / byte-identity pins for the 4004 SecretConnection
 *        (shared/dnac/cmt_p2p_secret.{h,c}) AS IT IS TODAY.
 *
 * Governing: docs/plans/decisions/2026-09-26-witness-port-session.md (the
 * operator-approved byte items: nonce = role ‖ 00 00 00 ‖ u64 BE counter;
 * handshake messages = uvarint(len) ‖ kind(1) ‖ fixed fields, HELLO 0x01,
 * HELLO_R 0x02, KEYX 0x03, AUTHSIG 0x04; tags nodus.wsess.transcript.v1 /
 * nodus.wsess.keys.v1; purpose 0x0A); docs/plans/decisions/2026-10-23-
 * kurultay-43-summary.md ("4004 byte identity is unproven ... fixtures
 * passing against today's code BEFORE the refactor"); docs/plans/
 * 2026-10-23-dht-v2-session-package-design.md rev 1, sub-package 3a.
 *
 * ── THIS TEST MUST PASS ON THE UNCHANGED BASE COMMIT ───────────────────
 * That is its purpose: it records what the 4004 handshake puts on the wire
 * and derives TODAY (base 179fef5cc), in LITERAL bytes typed below — never
 * through the CMT_P2P_SC_* macros — so a later refactor of the code, or of
 * the macros the code uses, cannot change the 4004 bytes unnoticed. A
 * failure after a refactor means the refactor changed the wire.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · KAT vector: T = SHA3-512(tag ‖ i_dsa_pk ‖ r_dsa_pk ‖ r_kem_pk ‖
 *     i_proto_ver ‖ i_chain_id ‖ r_proto_ver ‖ r_chain_id ‖ nonce_i ‖
 *     nonce_r ‖ ct), key = HKDF-SHA3-256(salt = T, ikm = ss, info =
 *     "nodus.wsess.keys.v1/aead"), challenge = same with info
 *     "nodus.wsess.keys.v1/challenge" (32-byte outputs), computed over a
 *     FIXED input vector, equal the hex pinned below. The pinned hex was
 *     computed by python3 (hashlib + hmac), NOT by this tree — see the
 *     commands in the comment above kat_fixed_vector().
 *   · live handshake: after a real ML-DSA-87 / ML-KEM-1024 handshake the
 *     test recomputes T / key / challenge from the machines' public
 *     fields plus the shared secret it captured, and they equal the
 *     machines' own key and challenge, on BOTH sides.
 *   · framing: the bytes the initiator and the responder emit are exactly
 *     HELLO (e5 14 01 ...), HELLO_R (85 21 02 ...), KEYX (a1 0c 03 ...) with
 *     every field at the literal offset typed below and equal to the
 *     identity / struct values.
 *   · sealed frames: the 5 frames of each side's AUTHSIG open under
 *     AES-256-GCM(key, role ‖ 00 00 00 ‖ counter u64 BE) with role 01 for
 *     I→R and 02 for R→I and counters 0..4; plaintext is 1028 bytes
 *     (u32 LE chunk length ‖ chunk ‖ zero pad); the stream is
 *     94 24 04 ‖ sig(4627). The first application frame uses counter 5.
 *     A frame opened with the OTHER role's nonce does not open.
 *   · strict purpose: each side's AUTHSIG verifies over the challenge under
 *     purpose 0x0A with the sender's pk, and under no other purpose
 *     (0x01..0x0B except 0x0A) and not raw.
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build (no compile flags,
 * no environment). Identities come from fixed 32-byte seeds
 * (nodus_identity_from_seed). The handshake nonces and the Encaps coins are
 * random (OS randomness), signatures are hedged — so no nonce, ct or
 * signature byte is pinned; those are checked by structure and by
 * recomputation.
 *
 * WHAT IT LEAVES BEHIND: nothing (heap freed; no files, sockets, threads).
 *
 * HOW IT CAN LIE:
 *   · the live recompute (case 2) uses this tree's SHA3-512 and
 *     hkdf_sha3_256; only the fixed vector (case 1) ties them to an
 *     independent tool (python hashlib/hmac). A construction wrong in the
 *     same way in both tree primitives would be caught only by case 1.
 *   · `ss` and `challenge` are wiped by the machine after use
 *     (sc_derive / job_done VERIFY), so the test copies them at the one
 *     moment they exist (ss: right after the KEM job ran; challenge: right
 *     after the KEM job_done). If the code stopped holding them there the
 *     test fails closed (zero ss / key mismatch), it does not skip.
 *   · AES-256-GCM here is OpenSSL EVP, the same library the code uses; the
 *     nonce layout and key are what is independent, not the cipher.
 *   · both machines run in one process, jobs inline; no worker thread, no
 *     TCP fragmentation (test_p2p_secret.c covers fragments).
 *   · pins the message ENCODING (uvarint/kind), which the header of
 *     cmt_p2p_secret.h marks "NOT GROUNDED" in the reference sense: the
 *     operator approved the bytes, nothing external confirms them.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_secret.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/hkdf_sha3.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

/* ── literal sizes (never the CMT_P2P_SC_* macros) ─────────────────────── */
#define L_PK        2592
#define L_SIG       4627
#define L_KEM_PK    1568
#define L_KEM_CT    1568
#define L_NONCE     32
#define L_CHAIN     32
#define L_FRAME     1028
#define L_SEALED    1044
#define L_AUTHSIG_FRAMES 5
#define L_PRE_LEN   8481        /* 25 + 2*2592 + 1568 + 2*(4+32) + 2*32 + 1568 */

#define PROTO_VER 8u
static const uint8_t PROTO_BE[4] = { 0x00, 0x00, 0x00, 0x08 };
static const uint8_t CHAIN_A[32] = {
    0x9a, 0xbf, 0x84, 0x37, 0xe7, 0x29, 0x0e, 0x45, 0xfe, 0x7b, 0x0f, 0xb2,
    0xcc, 0xd8, 0xc1, 0xa3, 0x32, 0x1c, 0xa4, 0xc0, 0x2f, 0xe1, 0x19, 0x2e,
    0xa9, 0x2e, 0xc9, 0xdf, 0x5f, 0x8d, 0xf0, 0xd2
};

static void fill(uint8_t *b, size_t n, uint8_t base)
{
    size_t k;
    for (k = 0; k < n; k++) {
        b[k] = (uint8_t)(base + k);
    }
}

static void hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t k;
    for (k = 0; k < n; k++) {
        out[2 * k] = d[b[k] >> 4];
        out[2 * k + 1] = d[b[k] & 15];
    }
    out[2 * n] = '\0';
}

/* ══ the recompute under test: the 4004 key schedule, typed out ═══════ */

/**
 * T / key / challenge from the transcript inputs, with every tag, length
 * and field order typed literally here (cmt_p2p_secret.h:62-70).
 * @return 0 on success.
 */
static int kat_derive(const uint8_t *i_dsa_pk, const uint8_t *r_dsa_pk,
                      const uint8_t *r_kem_pk,
                      const uint8_t *i_proto_ver, const uint8_t *i_chain_id,
                      const uint8_t *r_proto_ver, const uint8_t *r_chain_id,
                      const uint8_t *nonce_i, const uint8_t *nonce_r,
                      const uint8_t *ct, const uint8_t *ss,
                      uint8_t T[64], uint8_t key[32], uint8_t chl[32])
{
    static const char tag[] = "nodus.wsess.transcript.v1";
    static const char info_aead[] = "nodus.wsess.keys.v1/aead";
    static const char info_chl[] = "nodus.wsess.keys.v1/challenge";
    uint8_t *pre = (uint8_t *)malloc(L_PRE_LEN);
    size_t o = 0;
    int rc = -1;

    if (pre == NULL) {
        return -1;
    }
    memcpy(pre + o, tag, sizeof(tag) - 1);  o += sizeof(tag) - 1;
    memcpy(pre + o, i_dsa_pk, L_PK);        o += L_PK;
    memcpy(pre + o, r_dsa_pk, L_PK);        o += L_PK;
    memcpy(pre + o, r_kem_pk, L_KEM_PK);    o += L_KEM_PK;
    memcpy(pre + o, i_proto_ver, 4);        o += 4;
    memcpy(pre + o, i_chain_id, L_CHAIN);   o += L_CHAIN;
    memcpy(pre + o, r_proto_ver, 4);        o += 4;
    memcpy(pre + o, r_chain_id, L_CHAIN);   o += L_CHAIN;
    memcpy(pre + o, nonce_i, L_NONCE);      o += L_NONCE;
    memcpy(pre + o, nonce_r, L_NONCE);      o += L_NONCE;
    memcpy(pre + o, ct, L_KEM_CT);          o += L_KEM_CT;
    if (o == L_PRE_LEN && qgp_sha3_512(pre, o, T) == 0 &&
        hkdf_sha3_256(T, 64, ss, 32, (const uint8_t *)info_aead,
                      sizeof(info_aead) - 1, key, 32) == 0 &&
        hkdf_sha3_256(T, 64, ss, 32, (const uint8_t *)info_chl,
                      sizeof(info_chl) - 1, chl, 32) == 0) {
        rc = 0;
    }
    free(pre);
    return rc;
}

/* ══ case 1 — the independent vector ═════════════════════════════════
 *
 * Vector: byte k of a field = (base + k) & 0xff, bases
 *   i_dsa_pk 0x10, r_dsa_pk 0x20, r_kem_pk 0x30, i_chain_id 0x40,
 *   r_chain_id 0x50, nonce_i 0x60, nonce_r 0x70, ct 0x80, ss 0x90;
 *   i_proto_ver = 00 00 00 08, r_proto_ver = 00 00 00 09.
 * Expected values computed with python3 (no tree code involved):
 *
 *   import hashlib, hmac
 *   def fill(n, base): return bytes((base + k) & 0xff for k in range(n))
 *   def hkdf(salt, ikm, info, L=32):            # RFC 5869, HMAC-SHA3-256
 *       prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
 *       return hmac.new(prk, info + b"\x01", hashlib.sha3_256).digest()[:L]
 *   pre = (b"nodus.wsess.transcript.v1" + fill(2592,0x10) + fill(2592,0x20)
 *          + fill(1568,0x30) + bytes([0,0,0,8]) + fill(32,0x40)
 *          + bytes([0,0,0,9]) + fill(32,0x50) + fill(32,0x60)
 *          + fill(32,0x70) + fill(1568,0x80))
 *   T = hashlib.sha3_512(pre).digest(); ss = fill(32,0x90)
 *   print(len(pre), T.hex())
 *   print(hkdf(T, ss, b"nodus.wsess.keys.v1/aead").hex())
 *   print(hkdf(T, ss, b"nodus.wsess.keys.v1/challenge").hex())
 *
 * Output:
 *   T   e36587214d6ee6a2ea44ad05c54feb09982b40862d62002cb234b5077b33dce1
 *       1a80e661f45d1fbe6b16e69c29d89499f8ca53400b3ac5b35c8282ca78de67da
 *   key 109d91c9360708bf239565a83a93f93daa7627a35da278240883dd0402336443
 *   chl 724c04cde74ebb4e492182cb6a14f59f767519eeb66c9a9539cb35448fba0cb4
 */
static void kat_fixed_vector(void)
{
    static const char T_HEX[] =
        "e36587214d6ee6a2ea44ad05c54feb09982b40862d62002cb234b5077b33dce1"
        "1a80e661f45d1fbe6b16e69c29d89499f8ca53400b3ac5b35c8282ca78de67da";
    static const char KEY_HEX[] =
        "109d91c9360708bf239565a83a93f93daa7627a35da278240883dd0402336443";
    static const char CHL_HEX[] =
        "724c04cde74ebb4e492182cb6a14f59f767519eeb66c9a9539cb35448fba0cb4";
    static const uint8_t pv_r[4] = { 0x00, 0x00, 0x00, 0x09 };
    uint8_t i_pk[L_PK], r_pk[L_PK], kem[L_KEM_PK], ct[L_KEM_CT];
    uint8_t i_cid[L_CHAIN], r_cid[L_CHAIN], ni[L_NONCE], nr[L_NONCE], ss[32];
    uint8_t T[64], key[32], chl[32];
    char h_t[129], h_k[65], h_c[65];

    TEST("KAT: T / key / challenge over a fixed vector == python3 values");
    fill(i_pk, sizeof(i_pk), 0x10);
    fill(r_pk, sizeof(r_pk), 0x20);
    fill(kem, sizeof(kem), 0x30);
    fill(i_cid, sizeof(i_cid), 0x40);
    fill(r_cid, sizeof(r_cid), 0x50);
    fill(ni, sizeof(ni), 0x60);
    fill(nr, sizeof(nr), 0x70);
    fill(ct, sizeof(ct), 0x80);
    fill(ss, sizeof(ss), 0x90);
    if (kat_derive(i_pk, r_pk, kem, PROTO_BE, i_cid, pv_r, r_cid, ni, nr, ct, ss,
                   T, key, chl) != 0) {
        FAIL("derive failed");
        return;
    }
    hex(T, 64, h_t);
    hex(key, 32, h_k);
    hex(chl, 32, h_c);
    if (strcmp(h_t, T_HEX) == 0 && strcmp(h_k, KEY_HEX) == 0 &&
        strcmp(h_c, CHL_HEX) == 0) {
        PASS();
    } else {
        FAIL("derived bytes differ from the pinned python3 values");
    }
}

/* ══ host / identities ═══════════════════════════════════════════════ */

typedef struct {
    nodus_identity_t id;
} node_t;

static int host_sign(void *ctx, const uint8_t *msg, size_t msg_len,
                     uint8_t sig_out[4627])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, msg, msg_len, &n->id.sk);

    memcpy(sig_out, sig.bytes, 4627);
    return rc;
}

static int host_verify(void *ctx, const uint8_t sig_in[4627],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t pk_in[2592])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, 4627);
    memcpy(pk.bytes, pk_in, 2592);
    return nodus_verify_session_auth(&sig, msg, msg_len, &pk);
}

typedef struct {
    cmt_p2p_sc_t *sc;
    cmt_p2p_sc_host_t host;
    node_t *node;
} side_t;

static int side_init(side_t *s, node_t *node, cmt_p2p_sc_role_t role)
{
    const uint8_t *kpk = NULL, *ksk = NULL;

    memset(s, 0, sizeof(*s));
    s->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    s->node = node;
    s->host.ctx = node;
    s->host.sign = host_sign;
    s->host.verify = host_verify;
    if (s->sc == NULL) {
        return CMT_FAULT;
    }
    if (role == CMT_P2P_SC_ROLE_RESPONDER) {
        kpk = node->id.mlkem_pk;
        ksk = node->id.mlkem_sk;
    }
    return cmt_p2p_sc_init(s->sc, role, &s->host, node->id.pk.bytes, kpk, ksk,
                           PROTO_VER, CHAIN_A);
}

static void side_free(side_t *s)
{
    if (s->sc != NULL) {
        cmt_p2p_sc_clear(s->sc);
        free(s->sc);
        s->sc = NULL;
    }
}

/** Copy out and consume everything the machine wants written. */
static size_t side_take(side_t *s, uint8_t *dst, size_t cap)
{
    size_t n = 0;
    const uint8_t *o = cmt_p2p_sc_out(s->sc, &n);

    if (n > cap) {
        return (size_t)-1;
    }
    memcpy(dst, o, n);
    cmt_p2p_sc_out_consume(s->sc, n);
    return n;
}

/** Feed all of `in`; true if the machine took every byte with CMT_OK. */
static bool side_feed(side_t *s, const uint8_t *in, size_t n)
{
    size_t c = 0;
    int rc = cmt_p2p_sc_recv(s->sc, in, n, &c);

    return rc == CMT_OK && c == n;
}

/* ══ AES-256-GCM, typed independently of the code under test ═════════ */

/** nonce = role ‖ 00 00 00 ‖ counter u64 BE (decision record item 1). */
static void kat_nonce(uint8_t nonce[12], uint8_t role, uint64_t counter)
{
    int k;

    nonce[0] = role;
    nonce[1] = nonce[2] = nonce[3] = 0x00;
    for (k = 0; k < 8; k++) {
        nonce[4 + k] = (uint8_t)(counter >> (56 - 8 * k));
    }
}

/** @return 0 on success: `sealed` (1028 ct ‖ 16 tag) opened into `plain`. */
static int gcm_open(const uint8_t key[32], uint8_t role, uint64_t counter,
                    const uint8_t *sealed, uint8_t plain[L_FRAME])
{
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok = 0;

    kat_nonce(nonce, role, counter);
    if (ctx != NULL &&
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, plain, &len, sealed, L_FRAME) == 1 &&
        len == L_FRAME &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            (void *)(sealed + L_FRAME)) == 1 &&
        EVP_DecryptFinal_ex(ctx, plain + len, &len) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/**
 * Open the 5 AUTHSIG frames at counters 0..4 under `role`, check the
 * 1028-byte layout of each, and reassemble the stream into `wire` (4630
 * bytes). @return 0 on success.
 */
static int open_authsig(const uint8_t key[32], uint8_t role,
                        const uint8_t *sealed5, uint8_t *wire)
{
    static const uint32_t want_len[L_AUTHSIG_FRAMES] = { 1024, 1024, 1024, 1024, 534 };
    uint8_t plain[L_FRAME];
    size_t off = 0;
    int f;

    for (f = 0; f < L_AUTHSIG_FRAMES; f++) {
        uint32_t cl;
        size_t k;

        if (gcm_open(key, role, (uint64_t)f, sealed5 + (size_t)f * L_SEALED, plain) != 0) {
            return -1;
        }
        cl = (uint32_t)plain[0] | ((uint32_t)plain[1] << 8) |
             ((uint32_t)plain[2] << 16) | ((uint32_t)plain[3] << 24);
        if (cl != want_len[f]) {
            return -1;
        }
        for (k = 4 + cl; k < L_FRAME; k++) {
            if (plain[k] != 0x00) {
                return -1;                      /* pad must be zero */
            }
        }
        memcpy(wire + off, plain + 4, cl);
        off += cl;
    }
    return off == 4630 ? 0 : -1;
}

/* ══ cases 2-5 — one live handshake, stepped by hand ═════════════════ */

#define IR_AUTH_OFF   1571          /* KEYX (2 + 1569) precedes I's AUTHSIG */
#define IR_TOTAL      (1571 + 5220) /* I's whole output after the ENCAPS job */

static void test_live(node_t *a, node_t *b)
{
    side_t i, r;
    uint8_t *hello = (uint8_t *)malloc(4096);
    uint8_t *hello_r = (uint8_t *)malloc(8192);
    uint8_t *i_out = (uint8_t *)malloc(8192);
    uint8_t *r_out = (uint8_t *)malloc(8192);
    uint8_t wire_i[4630], wire_r[4630];
    uint8_t ss_i[32], ss_r[32], key_i[32], key_r[32], chl_i[32], chl_r[32];
    uint8_t T[64], key[32], chl[32];
    size_t n_hello, n_hello_r, n_i, n_r;
    const cmt_p2p_sc_job_t *job;
    bool ok;
    bool f_hello = false, f_hello_r = false, f_keyx = false, f_kat_i = false,
         f_kat_r = false, f_frames = false, f_purpose = false, f_app = false,
         f_auth = false;

    TEST("live handshake: stepped (cases 2-5, results below)");
    if (hello == NULL || hello_r == NULL || i_out == NULL || r_out == NULL ||
        side_init(&i, a, CMT_P2P_SC_ROLE_INITIATOR) != CMT_OK ||
        side_init(&r, b, CMT_P2P_SC_ROLE_RESPONDER) != CMT_OK) {
        FAIL("setup");
        return;
    }

    /* ── HELLO: uvarint(2661) = e5 14, kind 01, then the fields ── */
    n_hello = side_take(&i, hello, 4096);
    f_hello = n_hello == 2663 &&
              hello[0] == 0xe5 && hello[1] == 0x14 && hello[2] == 0x01 &&
              memcmp(hello + 3, a->id.pk.bytes, 2592) == 0 &&
              memcmp(hello + 3, i.sc->i_dsa_pk, 2592) == 0 &&
              memcmp(hello + 2595, i.sc->nonce_i, 32) == 0 &&
              memcmp(hello + 2627, PROTO_BE, 4) == 0 &&
              memcmp(hello + 2631, CHAIN_A, 32) == 0;

    /* ── HELLO_R: uvarint(4229) = 85 21, kind 02, then the fields ── */
    ok = side_feed(&r, hello, n_hello);
    n_hello_r = side_take(&r, hello_r, 8192);
    f_hello_r = ok && n_hello_r == 4231 &&
                hello_r[0] == 0x85 && hello_r[1] == 0x21 && hello_r[2] == 0x02 &&
                memcmp(hello_r + 3, b->id.pk.bytes, 2592) == 0 &&
                memcmp(hello_r + 2595, b->id.mlkem_pk, 1568) == 0 &&
                memcmp(hello_r + 4163, r.sc->nonce_r, 32) == 0 &&
                memcmp(hello_r + 4195, PROTO_BE, 4) == 0 &&
                memcmp(hello_r + 4199, CHAIN_A, 32) == 0;

    /* ── I: HELLO_R in -> ENCAPS; capture ss before job_done wipes it ── */
    memset(ss_i, 0, sizeof(ss_i));
    if (!side_feed(&i, hello_r, n_hello_r) ||
        (job = cmt_p2p_sc_job(i.sc)) == NULL || job->kind != CMT_P2P_SC_JOB_ENCAPS ||
        cmt_p2p_sc_job_run(job, &i.host) != 0) {
        FAIL("initiator did not reach/run ENCAPS");
        goto out;
    }
    memcpy(ss_i, i.sc->ss, 32);
    if (cmt_p2p_sc_job_done(i.sc, 0) != CMT_OK ||
        (job = cmt_p2p_sc_job(i.sc)) == NULL || job->kind != CMT_P2P_SC_JOB_SIGN) {
        FAIL("initiator did not reach SIGN");
        goto out;
    }
    memcpy(key_i, i.sc->key, 32);               /* derived, challenge still held */
    memcpy(chl_i, i.sc->challenge, 32);
    if (cmt_p2p_sc_job_run(job, &i.host) != 0 ||
        cmt_p2p_sc_job_done(i.sc, 0) != CMT_OK) {
        FAIL("initiator SIGN");
        goto out;
    }

    /* ── I's output: KEYX (uvarint(1569) = a1 0c, kind 03, ct) ‖ 5 sealed frames ── */
    n_i = side_take(&i, i_out, 8192);
    f_keyx = n_i == IR_TOTAL &&
             i_out[0] == 0xa1 && i_out[1] == 0x0c && i_out[2] == 0x03 &&
             memcmp(i_out + 3, i.sc->ct, 1568) == 0;

    /* ── R: KEYX in -> DECAPS ── */
    if (!side_feed(&r, i_out, IR_AUTH_OFF) ||
        (job = cmt_p2p_sc_job(r.sc)) == NULL || job->kind != CMT_P2P_SC_JOB_DECAPS ||
        cmt_p2p_sc_job_run(job, &r.host) != 0) {
        FAIL("responder did not reach/run DECAPS");
        goto out;
    }
    memcpy(ss_r, r.sc->ss, 32);
    if (cmt_p2p_sc_job_done(r.sc, 0) != CMT_OK ||
        (job = cmt_p2p_sc_job(r.sc)) == NULL || job->kind != CMT_P2P_SC_JOB_SIGN) {
        FAIL("responder did not reach SIGN");
        goto out;
    }
    memcpy(key_r, r.sc->key, 32);
    memcpy(chl_r, r.sc->challenge, 32);
    if (cmt_p2p_sc_job_run(job, &r.host) != 0 ||
        cmt_p2p_sc_job_done(r.sc, 0) != CMT_OK) {
        FAIL("responder SIGN");
        goto out;
    }
    n_r = side_take(&r, r_out, 8192);

    /* ── case 1 of the live handshake: recompute T / key / challenge ──
     * from each side's OWN public fields and the captured ss. */
    f_kat_i = memcmp(ss_i, ss_r, 32) == 0 &&
              kat_derive(i.sc->i_dsa_pk, i.sc->r_dsa_pk, i.sc->r_kem_pk,
                         i.sc->i_proto_ver, i.sc->i_chain_id,
                         i.sc->r_proto_ver, i.sc->r_chain_id,
                         i.sc->nonce_i, i.sc->nonce_r, i.sc->ct, ss_i,
                         T, key, chl) == 0 &&
              memcmp(key, key_i, 32) == 0 && memcmp(chl, chl_i, 32) == 0 &&
              memcmp(i.sc->i_dsa_pk, a->id.pk.bytes, 2592) == 0 &&
              memcmp(i.sc->r_dsa_pk, b->id.pk.bytes, 2592) == 0 &&
              memcmp(i.sc->r_kem_pk, b->id.mlkem_pk, 1568) == 0;
    f_kat_r = kat_derive(r.sc->i_dsa_pk, r.sc->r_dsa_pk, r.sc->r_kem_pk,
                         r.sc->i_proto_ver, r.sc->i_chain_id,
                         r.sc->r_proto_ver, r.sc->r_chain_id,
                         r.sc->nonce_i, r.sc->nonce_r, r.sc->ct, ss_r,
                         T, key, chl) == 0 &&
              memcmp(key, key_r, 32) == 0 && memcmp(chl, chl_r, 32) == 0 &&
              memcmp(key_i, key_r, 32) == 0 && memcmp(chl_i, chl_r, 32) == 0;

    /* ── sealed AUTHSIG frames: role 01 (I) / 02 (R), counters 0..4 ── */
    f_frames = n_r == 5220 &&
               open_authsig(key_i, 0x01, i_out + IR_AUTH_OFF, wire_i) == 0 &&
               open_authsig(key_r, 0x02, r_out, wire_r) == 0 &&
               wire_i[0] == 0x94 && wire_i[1] == 0x24 && wire_i[2] == 0x04 &&
               wire_r[0] == 0x94 && wire_r[1] == 0x24 && wire_r[2] == 0x04;

    /* ── strict purpose: 0x0A only, over the challenge, with the sender's pk ── */
    if (f_frames) {
        nodus_sig_t si, sr;
        int p;

        memcpy(si.bytes, wire_i + 3, 4627);
        memcpy(sr.bytes, wire_r + 3, 4627);
        f_purpose = nodus_verify_tagged(&si, 0x0A, chl_i, 32, &a->id.pk) == 0 &&
                    nodus_verify_tagged(&sr, 0x0A, chl_r, 32, &b->id.pk) == 0 &&
                    nodus_verify(&si, chl_i, 32, &a->id.pk) != 0 &&
                    nodus_verify(&sr, chl_r, 32, &b->id.pk) != 0;
        for (p = 0x01; p <= 0x0B; p++) {
            if (p == 0x0A) {
                continue;
            }
            if (nodus_verify_tagged(&si, (uint8_t)p, chl_i, 32, &a->id.pk) == 0 ||
                nodus_verify_tagged(&sr, (uint8_t)p, chl_r, 32, &b->id.pk) == 0) {
                f_purpose = false;
            }
        }
    }

    /* ── complete the handshake (each side verifies the other's AUTHSIG) ── */
    if (side_feed(&i, r_out, 5220) && side_feed(&r, i_out + IR_AUTH_OFF, 5220)) {
        while ((job = cmt_p2p_sc_job(i.sc)) != NULL) {
            (void)cmt_p2p_sc_job_done(i.sc, cmt_p2p_sc_job_run(job, &i.host));
        }
        while ((job = cmt_p2p_sc_job(r.sc)) != NULL) {
            (void)cmt_p2p_sc_job_done(r.sc, cmt_p2p_sc_job_run(job, &r.host));
        }
    }
    f_auth = cmt_p2p_sc_is_authenticated(i.sc) && cmt_p2p_sc_is_authenticated(r.sc) &&
             memcmp(i.sc->key, key_i, 32) == 0 && memcmp(r.sc->key, key_r, 32) == 0;

    /* ── first application frame: counter 5, role of the sender ── */
    if (f_auth) {
        static const uint8_t msg[5] = { 'k', 'a', 't', '0', '1' };
        uint8_t sealed_i[L_SEALED], sealed_r[L_SEALED], plain[L_FRAME];
        size_t wi = 0, wr = 0, k;
        bool pad_ok = true;

        f_app = cmt_p2p_sc_write(i.sc, msg, sizeof(msg), sealed_i, sizeof(sealed_i), &wi) == CMT_OK &&
                cmt_p2p_sc_write(r.sc, msg, sizeof(msg), sealed_r, sizeof(sealed_r), &wr) == CMT_OK &&
                wi == L_SEALED && wr == L_SEALED &&
                gcm_open(key_i, 0x01, 5, sealed_i, plain) == 0 &&
                plain[0] == 0x05 && plain[1] == 0x00 && plain[2] == 0x00 &&
                plain[3] == 0x00 && memcmp(plain + 4, msg, 5) == 0;
        for (k = 4 + 5; k < L_FRAME; k++) {
            if (plain[k] != 0x00) {
                pad_ok = false;
            }
        }
        f_app = f_app && pad_ok &&
                gcm_open(key_r, 0x02, 5, sealed_r, plain) == 0 &&
                plain[0] == 0x05 && memcmp(plain + 4, msg, 5) == 0 &&
                /* the other role's nonce, or a wrong counter, does not open */
                gcm_open(key_i, 0x02, 5, sealed_i, plain) != 0 &&
                gcm_open(key_i, 0x01, 6, sealed_i, plain) != 0 &&
                gcm_open(key_i, 0x01, 0, sealed_i, plain) != 0;
    }

    ok = f_hello && f_hello_r && f_keyx && f_kat_i && f_kat_r && f_frames &&
         f_purpose && f_auth && f_app;
    if (ok) {
        PASS();
    } else {
        char m[200];
        snprintf(m, sizeof(m),
                 "hello=%d hello_r=%d keyx=%d kat_i=%d kat_r=%d frames=%d "
                 "purpose=%d auth=%d app=%d",
                 f_hello, f_hello_r, f_keyx, f_kat_i, f_kat_r, f_frames,
                 f_purpose, f_auth, f_app);
        FAIL(m);
    }
out:
    side_free(&i);
    side_free(&r);
    free(hello);
    free(hello_r);
    free(i_out);
    free(r_out);
}

/* ══ main ════════════════════════════════════════════════════════════ */

int main(void)
{
    node_t *a = (node_t *)calloc(1, sizeof(node_t));
    node_t *b = (node_t *)calloc(1, sizeof(node_t));
    uint8_t seed[32];

    printf("test_p2p_secret_kat — 4004 SecretConnection byte pins (base 179fef5cc)\n");
    if (a == NULL || b == NULL) {
        return 1;
    }
    fill(seed, sizeof(seed), 0xA1);
    if (nodus_identity_from_seed(seed, &a->id) != 0) {
        printf("identity A failed\n");
        return 1;
    }
    fill(seed, sizeof(seed), 0xB2);
    if (nodus_identity_from_seed(seed, &b->id) != 0 ||
        !a->id.has_mlkem || !b->id.has_mlkem) {
        printf("identity B failed\n");
        return 1;
    }

    kat_fixed_vector();
    test_live(a, b);

    free(a);
    free(b);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
