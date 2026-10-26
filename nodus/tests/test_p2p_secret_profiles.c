/**
 * @file nodus/tests/test_p2p_secret_profiles.c
 * @brief Session profiles of shared/dnac/cmt_p2p_secret (DHT v2 sub-package
 *        3a): WITNESS (4004), CLIENT (nodus.csess.*), NODE (nodus.nsess.*).
 *
 * Governing: docs/plans/decisions/2026-10-14-kurultay-21-summary.md:216-219
 * (client session nodus.csess.transcript.v1 / nodus.csess.keys.v1 + strict
 * purpose 0x0C; node session nodus.nsess.* + 0x0D, "the 4004 pattern");
 * docs/plans/decisions/2026-10-23-kurultay-43-summary.md (immutable
 * per-connection profiles, 0x0C/0x0D strict on sign and verify, unknown
 * profiles rejected, no 4004 byte change); docs/plans/
 * 2026-10-23-dht-v2-session-package-design.md rev 1, sub-package 3a.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · a handshake with the CLIENT profile (host purpose 0x0C) and one with
 *     the NODE profile (host purpose 0x0D) each reach AUTHENTICATED on both
 *     sides, and the key each side derived equals the key recomputed here
 *     from the public transcript fields with the profile's strings typed
 *     LITERALLY, and differs from the key the WITNESS strings would give;
 *   · a mixed pair (WITNESS vs CLIENT, CLIENT vs NODE, WITNESS vs NODE)
 *     never authenticates on either side;
 *   · fixed-vector T / key / challenge for each of the three profiles equal
 *     hex computed by python3 (command in the comment above the vectors);
 *   · a signature under 0x0C does not verify as 0x0A or 0x0D, 0x0D not as
 *     0x0A or 0x0C, 0x0A not as 0x0C or 0x0D; each verifies under its own;
 *   · init accepts ONLY the three const profiles (by pointer): NULL, a copy
 *     of a const profile, an empty / NULL / 65-byte string and even a
 *     valid-looking 64-byte custom profile are refused (CMT_FAULT);
 *   · cmt_p2p_sc_init (no profile argument) is the WITNESS profile.
 *
 * WHAT IT REQUIRES: a default nodus build; no flags, no environment. Fixed
 * seeds for the identities; handshake nonces and Encaps coins are random,
 * so only structure and recomputation are checked.
 * WHAT IT LEAVES BEHIND: nothing.
 *
 * HOW IT CAN LIE: the live recompute uses this tree's SHA3-512 / HKDF; only
 * the python3 vectors tie them to an outside tool. The profile strings for
 * CLIENT / NODE are the decided tags plus the "/aead" and "/challenge"
 * suffixes, operator-approved in docs/plans/decisions/2026-10-23-dht-v2-
 * session-bytes.md (with NDS1 + strict 0x0C/0x0D separation); the vectors
 * are self-consistent with that decision, not an external source.
 * Both machines run in one process with inline jobs. The 4004 bytes
 * themselves are pinned by test_p2p_secret_kat.c, not here.
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

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define PROTO_VER 8u
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

/* ══ the recompute, strings passed in (typed literally by each caller) ═ */

static int derive(const char *tag, const char *info_aead, const char *info_chl,
                  const uint8_t *i_dsa_pk, const uint8_t *r_dsa_pk,
                  const uint8_t *r_kem_pk,
                  const uint8_t *i_proto_ver, const uint8_t *i_chain_id,
                  const uint8_t *r_proto_ver, const uint8_t *r_chain_id,
                  const uint8_t *nonce_i, const uint8_t *nonce_r,
                  const uint8_t *ct, const uint8_t *ss,
                  uint8_t T[64], uint8_t key[32], uint8_t chl[32])
{
    size_t taglen = strlen(tag);
    uint8_t *pre = (uint8_t *)malloc(taglen + 8456);
    size_t o = 0;
    int rc = -1;

    if (pre == NULL) {
        return -1;
    }
    memcpy(pre + o, tag, taglen);           o += taglen;
    memcpy(pre + o, i_dsa_pk, 2592);        o += 2592;
    memcpy(pre + o, r_dsa_pk, 2592);        o += 2592;
    memcpy(pre + o, r_kem_pk, 1568);        o += 1568;
    memcpy(pre + o, i_proto_ver, 4);        o += 4;
    memcpy(pre + o, i_chain_id, 32);        o += 32;
    memcpy(pre + o, r_proto_ver, 4);        o += 4;
    memcpy(pre + o, r_chain_id, 32);        o += 32;
    memcpy(pre + o, nonce_i, 32);           o += 32;
    memcpy(pre + o, nonce_r, 32);           o += 32;
    memcpy(pre + o, ct, 1568);              o += 1568;
    if (qgp_sha3_512(pre, o, T) == 0 &&
        hkdf_sha3_256(T, 64, ss, 32, (const uint8_t *)info_aead,
                      strlen(info_aead), key, 32) == 0 &&
        hkdf_sha3_256(T, 64, ss, 32, (const uint8_t *)info_chl,
                      strlen(info_chl), chl, 32) == 0) {
        rc = 0;
    }
    free(pre);
    return rc;
}

/* ══ fixed vectors, one per profile ══════════════════════════════════
 *
 * Same input vector as test_p2p_secret_kat.c (byte k of a field =
 * (base + k) & 0xff; bases i_pk 0x10, r_pk 0x20, kem 0x30, i_chain 0x40,
 * r_chain 0x50, nonce_i 0x60, nonce_r 0x70, ct 0x80, ss 0x90;
 * i_proto_ver 00000008, r_proto_ver 00000009). python3:
 *
 *   import hashlib, hmac
 *   def fill(n, base): return bytes((base + k) & 0xff for k in range(n))
 *   def hkdf(salt, ikm, info, L=32):
 *       prk = hmac.new(salt, ikm, hashlib.sha3_256).digest()
 *       return hmac.new(prk, info + b"\x01", hashlib.sha3_256).digest()[:L]
 *   for p in ("w", "c", "n"):
 *       tag = ("nodus.%ssess.transcript.v1" % p).encode()
 *       pre = (tag + fill(2592,0x10) + fill(2592,0x20) + fill(1568,0x30)
 *              + bytes([0,0,0,8]) + fill(32,0x40) + bytes([0,0,0,9])
 *              + fill(32,0x50) + fill(32,0x60) + fill(32,0x70)
 *              + fill(1568,0x80))
 *       T = hashlib.sha3_512(pre).digest(); ss = fill(32,0x90)
 *       print(p, T.hex())
 *       print(p, hkdf(T, ss, ("nodus.%ssess.keys.v1/aead" % p).encode()).hex())
 *       print(p, hkdf(T, ss, ("nodus.%ssess.keys.v1/challenge" % p).encode()).hex())
 *
 * (the "w" lines equal the 4004 vector pinned in test_p2p_secret_kat.c)
 */
typedef struct {
    const char *name;
    const char *tag, *aead, *chl;
    const char *t_hex, *key_hex, *chl_hex;
} vec_t;

static const vec_t VECS[3] = {
    { "WITNESS",
      "nodus.wsess.transcript.v1", "nodus.wsess.keys.v1/aead",
      "nodus.wsess.keys.v1/challenge",
      "e36587214d6ee6a2ea44ad05c54feb09982b40862d62002cb234b5077b33dce1"
      "1a80e661f45d1fbe6b16e69c29d89499f8ca53400b3ac5b35c8282ca78de67da",
      "109d91c9360708bf239565a83a93f93daa7627a35da278240883dd0402336443",
      "724c04cde74ebb4e492182cb6a14f59f767519eeb66c9a9539cb35448fba0cb4" },
    { "CLIENT",
      "nodus.csess.transcript.v1", "nodus.csess.keys.v1/aead",
      "nodus.csess.keys.v1/challenge",
      "753e69caf04b40dc8b89399092c12d6d96c0b0ff215bed44e73b6769b0bd5467"
      "4e5926249a692223332aa2df7b329343a9d6870ceba1df954e0d84d846ecd99e",
      "653da5e1573365e23cf9477701ec33cb6c78669dcf5fd3b74da95de1ead82cad",
      "c9053c12f3809476bf0493970b2bd4b4da7e9a05dd19687a4c8ccc3bc398c637" },
    { "NODE",
      "nodus.nsess.transcript.v1", "nodus.nsess.keys.v1/aead",
      "nodus.nsess.keys.v1/challenge",
      "c99bfa670c31601db53a2da9a216268cada5b4ad5ed72aa6965ea01edb48861f"
      "ecb0b4e569c17da7b55f0cec32d703871196dc149e132de1b510d18118f511d9",
      "2d0d67636c3c8d8e901456a38bab8397199bfd1bfba971b822d74256d3e8d3ea",
      "16cba51358ebdb144b33c8f2c9b97a5a5611d7892d9ab9e27d2cb4bde2a3d3fc" },
};

static void test_vectors(void)
{
    uint8_t i_pk[2592], r_pk[2592], kem[1568], ct[1568];
    uint8_t i_cid[32], r_cid[32], ni[32], nr[32], ss[32];
    static const uint8_t pv_i[4] = { 0, 0, 0, 8 }, pv_r[4] = { 0, 0, 0, 9 };
    int v;

    fill(i_pk, sizeof(i_pk), 0x10);
    fill(r_pk, sizeof(r_pk), 0x20);
    fill(kem, sizeof(kem), 0x30);
    fill(i_cid, sizeof(i_cid), 0x40);
    fill(r_cid, sizeof(r_cid), 0x50);
    fill(ni, sizeof(ni), 0x60);
    fill(nr, sizeof(nr), 0x70);
    fill(ct, sizeof(ct), 0x80);
    fill(ss, sizeof(ss), 0x90);
    for (v = 0; v < 3; v++) {
        uint8_t T[64], key[32], chl[32];
        char h_t[129], h_k[65], h_c[65], name[96];

        snprintf(name, sizeof(name), "KAT: %s T / key / challenge == python3", VECS[v].name);
        TEST(name);
        if (derive(VECS[v].tag, VECS[v].aead, VECS[v].chl, i_pk, r_pk, kem, pv_i,
                   i_cid, pv_r, r_cid, ni, nr, ct, ss, T, key, chl) != 0) {
            FAIL("derive failed");
            continue;
        }
        hex(T, 64, h_t);
        hex(key, 32, h_k);
        hex(chl, 32, h_c);
        if (strcmp(h_t, VECS[v].t_hex) == 0 && strcmp(h_k, VECS[v].key_hex) == 0 &&
            strcmp(h_c, VECS[v].chl_hex) == 0) {
            PASS();
        } else {
            FAIL("differs from the pinned python3 values");
        }
    }
}

/* ══ host with a per-side purpose ════════════════════════════════════ */

typedef struct {
    nodus_identity_t id;
    uint8_t purpose;
} node_t;

static int host_sign(void *ctx, const uint8_t *msg, size_t msg_len, uint8_t sig_out[4627])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_tagged(&sig, n->purpose, msg, msg_len, &n->id.sk);

    memcpy(sig_out, sig.bytes, 4627);
    return rc;
}

static int host_verify(void *ctx, const uint8_t sig_in[4627], const uint8_t *msg,
                       size_t msg_len, const uint8_t pk_in[2592])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    memcpy(sig.bytes, sig_in, 4627);
    memcpy(pk.bytes, pk_in, 2592);
    return nodus_verify_tagged(&sig, n->purpose, msg, msg_len, &pk);
}

typedef struct {
    cmt_p2p_sc_t *sc;
    cmt_p2p_sc_host_t host;
    uint8_t ss[32];      /* copied right after the KEM job ran */
    uint8_t key[32];     /* copied right after the KEM job_done */
    bool have_key;
    uint8_t *pipe;       /* bytes waiting to be fed to THIS side */
    size_t pipe_len;
} side_t;

#define PIPE_CAP 16384

static int side_init(side_t *s, node_t *node, cmt_p2p_sc_role_t role,
                     const cmt_p2p_sc_profile_t *profile)
{
    memset(s, 0, sizeof(*s));
    s->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    s->pipe = (uint8_t *)malloc(PIPE_CAP);
    s->host.ctx = node;
    s->host.sign = host_sign;
    s->host.verify = host_verify;
    if (s->sc == NULL || s->pipe == NULL) {
        return CMT_FAULT;
    }
    return cmt_p2p_sc_init_profile(
        s->sc, role, &s->host, profile, node->id.pk.bytes,
        role == CMT_P2P_SC_ROLE_RESPONDER ? node->id.mlkem_pk : NULL,
        role == CMT_P2P_SC_ROLE_RESPONDER ? node->id.mlkem_sk : NULL,
        PROTO_VER, CHAIN_A);
}

static void side_free(side_t *s)
{
    if (s->sc != NULL) {
        cmt_p2p_sc_clear(s->sc);
        free(s->sc);
    }
    free(s->pipe);
    s->sc = NULL;
    s->pipe = NULL;
}

static size_t run_jobs(side_t *s)
{
    const cmt_p2p_sc_job_t *job;
    size_t ran = 0;

    while ((job = cmt_p2p_sc_job(s->sc)) != NULL) {
        cmt_p2p_sc_job_kind_t kind = job->kind;
        int jrc = cmt_p2p_sc_job_run(job, &s->host);

        if (kind == CMT_P2P_SC_JOB_ENCAPS || kind == CMT_P2P_SC_JOB_DECAPS) {
            memcpy(s->ss, s->sc->ss, 32);      /* wiped by job_done */
        }
        (void)cmt_p2p_sc_job_done(s->sc, jrc);
        if (kind == CMT_P2P_SC_JOB_ENCAPS || kind == CMT_P2P_SC_JOB_DECAPS) {
            memcpy(s->key, s->sc->key, 32);
            s->have_key = true;
        }
        ran++;
    }
    return ran;
}

/** Move `from`'s output into `to`'s pipe, then feed `to` what it accepts. */
static size_t pump(side_t *from, side_t *to)
{
    size_t n = 0, moved = 0, c = 0;
    const uint8_t *o = cmt_p2p_sc_out(from->sc, &n);

    if (n > 0 && n <= PIPE_CAP - to->pipe_len) {
        memcpy(to->pipe + to->pipe_len, o, n);
        to->pipe_len += n;
        cmt_p2p_sc_out_consume(from->sc, n);
        moved = n;
    }
    if (to->pipe_len > 0 &&
        cmt_p2p_sc_recv(to->sc, to->pipe, to->pipe_len, &c) == CMT_OK && c > 0) {
        memmove(to->pipe, to->pipe + c, to->pipe_len - c);
        to->pipe_len -= c;
        moved += c;
    }
    return moved;
}

static void drive(side_t *i, side_t *r)
{
    int guard;

    for (guard = 0; guard < 200; guard++) {
        size_t m = 0;

        m += pump(i, r);
        m += run_jobs(r);
        m += pump(r, i);
        m += run_jobs(i);
        if (m == 0) {
            break;
        }
    }
}

static node_t *g_a, *g_b;

/**
 * One handshake; both sides are zeroed first so side_free is always safe.
 * @return 0 when both sides were set up and driven, -1 on a setup failure
 *         (the caller reports FAIL and still calls side_free on both).
 */
static int handshake(const cmt_p2p_sc_profile_t *pi, uint8_t purpose_i,
                     const cmt_p2p_sc_profile_t *pr, uint8_t purpose_r,
                     side_t *i, side_t *r)
{
    memset(i, 0, sizeof(*i));
    memset(r, 0, sizeof(*r));
    g_a->purpose = purpose_i;
    g_b->purpose = purpose_r;
    if (side_init(i, g_a, CMT_P2P_SC_ROLE_INITIATOR, pi) != CMT_OK) {
        return -1;
    }
    if (side_init(r, g_b, CMT_P2P_SC_ROLE_RESPONDER, pr) != CMT_OK) {
        return -1;
    }
    drive(i, r);
    return 0;
}

static void test_matched(const char *name, const cmt_p2p_sc_profile_t *p,
                         uint8_t purpose, const vec_t *lit)
{
    side_t i, r;
    uint8_t T[64], key[32], chl[32], wkey[32], wchl[32];
    bool ok;

    TEST(name);
    if (handshake(p, purpose, p, purpose, &i, &r) != 0) {
        FAIL("setup failed");
        side_free(&i);
        side_free(&r);
        return;
    }
    ok = i.sc != NULL && r.sc != NULL && cmt_p2p_sc_is_authenticated(i.sc) &&
         cmt_p2p_sc_is_authenticated(r.sc) && i.have_key && r.have_key &&
         memcmp(i.key, r.key, 32) == 0 &&
         memcmp(i.sc->key, i.key, 32) == 0 &&
         derive(lit->tag, lit->aead, lit->chl, i.sc->i_dsa_pk, i.sc->r_dsa_pk,
                i.sc->r_kem_pk, i.sc->i_proto_ver, i.sc->i_chain_id,
                i.sc->r_proto_ver, i.sc->r_chain_id, i.sc->nonce_i, i.sc->nonce_r,
                i.sc->ct, i.ss, T, key, chl) == 0 &&
         memcmp(key, i.key, 32) == 0 &&
         derive("nodus.wsess.transcript.v1", "nodus.wsess.keys.v1/aead",
                "nodus.wsess.keys.v1/challenge", i.sc->i_dsa_pk, i.sc->r_dsa_pk,
                i.sc->r_kem_pk, i.sc->i_proto_ver, i.sc->i_chain_id,
                i.sc->r_proto_ver, i.sc->r_chain_id, i.sc->nonce_i, i.sc->nonce_r,
                i.sc->ct, i.ss, T, wkey, wchl) == 0 &&
         (p == &CMT_P2P_SC_PROFILE_WITNESS || memcmp(wkey, i.key, 32) != 0);
    if (ok) PASS(); else FAIL("not authenticated, or key != literal-string recompute");
    side_free(&i);
    side_free(&r);
}

static void test_mixed(const char *name, const cmt_p2p_sc_profile_t *pi, uint8_t ui,
                       const cmt_p2p_sc_profile_t *pr, uint8_t ur)
{
    side_t i, r;

    TEST(name);
    if (handshake(pi, ui, pr, ur, &i, &r) != 0) {
        FAIL("setup failed");
    } else if (!cmt_p2p_sc_is_authenticated(i.sc) &&
               !cmt_p2p_sc_is_authenticated(r.sc)) {
        PASS();
    } else {
        FAIL("mixed profiles authenticated");
    }
    side_free(&i);
    side_free(&r);
}

static void test_purposes(void)
{
    static const uint8_t chl[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                     17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
    nodus_sig_t s_a, s_c, s_n, s_raw;
    const nodus_pubkey_t *pk = &g_a->id.pk;
    const nodus_seckey_t *sk = &g_a->id.sk;
    bool ok;

    TEST("0x0A / 0x0C / 0x0D signatures verify only under their own purpose");
    ok = nodus_sign(&s_raw, chl, 32, sk) == 0 &&
         /* control: the RAW signature over the challenge is valid raw ... */
         nodus_verify(&s_raw, chl, 32, pk) == 0 &&
         /* ... and every strict session purpose refuses it (no raw fallback) */
         nodus_verify_session_auth(&s_raw, chl, 32, pk) != 0 &&
         nodus_verify_client_session_auth(&s_raw, chl, 32, pk) != 0 &&
         nodus_verify_node_session_auth(&s_raw, chl, 32, pk) != 0 &&
         nodus_sign_session_auth(&s_a, chl, 32, sk) == 0 &&
         nodus_sign_client_session_auth(&s_c, chl, 32, sk) == 0 &&
         nodus_sign_node_session_auth(&s_n, chl, 32, sk) == 0 &&
         nodus_verify_session_auth(&s_a, chl, 32, pk) == 0 &&
         nodus_verify_client_session_auth(&s_c, chl, 32, pk) == 0 &&
         nodus_verify_node_session_auth(&s_n, chl, 32, pk) == 0 &&
         nodus_verify_session_auth(&s_c, chl, 32, pk) != 0 &&
         nodus_verify_node_session_auth(&s_c, chl, 32, pk) != 0 &&
         nodus_verify_session_auth(&s_n, chl, 32, pk) != 0 &&
         nodus_verify_client_session_auth(&s_n, chl, 32, pk) != 0 &&
         nodus_verify_client_session_auth(&s_a, chl, 32, pk) != 0 &&
         nodus_verify_node_session_auth(&s_a, chl, 32, pk) != 0 &&
         /* and a tagged signature is not a valid raw signature */
         nodus_verify(&s_c, chl, 32, pk) != 0 && nodus_verify(&s_n, chl, 32, pk) != 0;
    if (ok) PASS(); else FAIL("purpose separation broken");
}

static void test_bad_profiles(void)
{
    cmt_p2p_sc_t *sc = (cmt_p2p_sc_t *)calloc(1, sizeof(*sc));
    cmt_p2p_sc_host_t host;
    char s64[65], s65[66];
    cmt_p2p_sc_profile_t p;
    bool ok;

    /* Init accepts ONLY the three const profiles, by pointer. Any other
     * profile — a copy of a const one, an empty / NULL / 65-byte string,
     * even a valid-looking 64-byte one — is refused. The string-bound check
     * behind that (sc_profile_ok) is a second guard that no caller outside
     * cmt_p2p_secret.c can reach any more, so it has no test of its own. */
    TEST("NULL, every custom profile and ANON refused; the three const ones accepted");
    host.ctx = g_a;
    host.sign = host_sign;
    host.verify = host_verify;
    memset(s64, 'x', 64);  s64[64] = '\0';
    memset(s65, 'x', 65);  s65[65] = '\0';
#define INIT(pp) cmt_p2p_sc_init_profile(sc, CMT_P2P_SC_ROLE_INITIATOR, &host, (pp), \
        g_a->id.pk.bytes, NULL, NULL, PROTO_VER, CHAIN_A)
    ok = sc != NULL && INIT(NULL) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;                 /* a byte-identical COPY */
    ok = ok && INIT(&p) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;  p.transcript_tag = "";
    ok = ok && INIT(&p) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;  p.info_aead = "";
    ok = ok && INIT(&p) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;  p.info_challenge = NULL;
    ok = ok && INIT(&p) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;  p.transcript_tag = s65;
    ok = ok && INIT(&p) == CMT_FAULT;
    p = CMT_P2P_SC_PROFILE_CLIENT;  p.transcript_tag = s64;   /* valid-looking */
    ok = ok && INIT(&p) == CMT_FAULT;
    /* DHT v2 package 3d: the ANON profile exists but is NOT one of the three
     * this entry point accepts — an ANON machine is made only by
     * cmt_p2p_sc_init_anon / cmt_p2p_sc_init_responder_unbound (their own
     * cases live in test_p2p_secret_anon.c). */
    ok = ok && INIT(&CMT_P2P_SC_PROFILE_ANON) == CMT_FAULT &&
         strcmp(CMT_P2P_SC_PROFILE_ANON.transcript_tag, "nodus.asess.transcript.v1") == 0;
    ok = ok && INIT(&CMT_P2P_SC_PROFILE_WITNESS) == CMT_OK &&
         sc->profile == &CMT_P2P_SC_PROFILE_WITNESS;
    ok = ok && INIT(&CMT_P2P_SC_PROFILE_CLIENT) == CMT_OK &&
         sc->profile == &CMT_P2P_SC_PROFILE_CLIENT;
    ok = ok && INIT(&CMT_P2P_SC_PROFILE_NODE) == CMT_OK &&
         sc->profile == &CMT_P2P_SC_PROFILE_NODE;
#undef INIT
    if (ok) PASS(); else FAIL("profile validation at init is wrong");
    free(sc);
}

static void test_default_is_witness(void)
{
    cmt_p2p_sc_t *sc = (cmt_p2p_sc_t *)calloc(1, sizeof(*sc));
    cmt_p2p_sc_host_t host;

    TEST("cmt_p2p_sc_init (no profile argument) binds the WITNESS profile");
    host.ctx = g_a;
    host.sign = host_sign;
    host.verify = host_verify;
    if (sc != NULL &&
        cmt_p2p_sc_init(sc, CMT_P2P_SC_ROLE_INITIATOR, &host, g_a->id.pk.bytes, NULL,
                        NULL, PROTO_VER, CHAIN_A) == CMT_OK &&
        sc->profile == &CMT_P2P_SC_PROFILE_WITNESS) {
        PASS();
    } else {
        FAIL("default profile is not WITNESS");
    }
    free(sc);
}

int main(void)
{
    uint8_t seed[32];

    printf("test_p2p_secret_profiles — session profiles (DHT v2 3a)\n");
    g_a = (node_t *)calloc(1, sizeof(node_t));
    g_b = (node_t *)calloc(1, sizeof(node_t));
    if (g_a == NULL || g_b == NULL) {
        return 1;
    }
    fill(seed, sizeof(seed), 0xA1);
    if (nodus_identity_from_seed(seed, &g_a->id) != 0) {
        printf("identity A failed\n");
        return 1;
    }
    fill(seed, sizeof(seed), 0xB2);
    if (nodus_identity_from_seed(seed, &g_b->id) != 0) {
        printf("identity B failed\n");
        return 1;
    }

    test_vectors();
    test_matched("WITNESS profile, purpose 0x0A: authenticates, key recomputes",
                 &CMT_P2P_SC_PROFILE_WITNESS, NODUS_PURPOSE_SESSION_AUTH, &VECS[0]);
    test_matched("CLIENT profile, purpose 0x0C: authenticates, key recomputes",
                 &CMT_P2P_SC_PROFILE_CLIENT, NODUS_PURPOSE_CLIENT_SESSION_AUTH, &VECS[1]);
    test_matched("NODE profile, purpose 0x0D: authenticates, key recomputes",
                 &CMT_P2P_SC_PROFILE_NODE, NODUS_PURPOSE_NODE_SESSION_AUTH, &VECS[2]);
    test_mixed("WITNESS (I) vs CLIENT (R): never authenticates",
               &CMT_P2P_SC_PROFILE_WITNESS, NODUS_PURPOSE_SESSION_AUTH,
               &CMT_P2P_SC_PROFILE_CLIENT, NODUS_PURPOSE_CLIENT_SESSION_AUTH);
    test_mixed("CLIENT (I) vs NODE (R): never authenticates",
               &CMT_P2P_SC_PROFILE_CLIENT, NODUS_PURPOSE_CLIENT_SESSION_AUTH,
               &CMT_P2P_SC_PROFILE_NODE, NODUS_PURPOSE_NODE_SESSION_AUTH);
    test_mixed("NODE (I) vs WITNESS (R): never authenticates",
               &CMT_P2P_SC_PROFILE_NODE, NODUS_PURPOSE_NODE_SESSION_AUTH,
               &CMT_P2P_SC_PROFILE_WITNESS, NODUS_PURPOSE_SESSION_AUTH);
    test_mixed("same profile CLIENT, purposes 0x0C vs 0x0D: never authenticates",
               &CMT_P2P_SC_PROFILE_CLIENT, NODUS_PURPOSE_CLIENT_SESSION_AUTH,
               &CMT_P2P_SC_PROFILE_CLIENT, NODUS_PURPOSE_NODE_SESSION_AUTH);
    test_purposes();
    test_bad_profiles();
    test_default_is_witness();

    free(g_a);
    free(g_b);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
