/**
 * @file nodus/tests/test_p2p_secret_anon.c
 * @brief The ANON session family of shared/dnac/cmt_p2p_secret (DHT v2
 *        package 3d, session layer): the no-login client handshake with a
 *        KEM-key certificate, no per-connection signature, two sealed CONFIRM
 *        frames.
 *
 * Governing: docs/plans/2026-10-26-dht-v2-3d-no-login-design.md rev 5 §1
 * (bytes approved by the operator 2026-10-26), §2 (layer bullet), §4 (the
 * 4004 gate); decisions/2026-10-26-wallet-no-node-login.md,
 * decisions/2026-10-26-kurultay-45-summary.md,
 * decisions/2026-09-26-witness-port-session.md (4004 bytes must not change).
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · happy path, in memory: an ANON initiator (no local key) and an UNBOUND
 *     responder both reach AUTHENTICATED; the wire sizes are 70 / 8,858 /
 *     1,571 / 1,044 / 1,044; the key and T the machines hold equal the key and
 *     T recomputed HERE from the captured wire bytes with the nodus.asess.*
 *     strings typed literally and the preimage WITHOUT I_dsa_pk (5,889 B);
 *     cmt_p2p_sc_transcript is equal on both ends and NULL before the end;
 *     sealed data flows both ways afterwards; an ANON-BOUND responder behaves
 *     the same;
 *   · the ANON responder has NO peer key (remote_pubkey NULL in every
 *     state); the initiator's is R's;
 *   · a bad certificate (flipped bit, wrong signer, wrong chain id, a KEM
 *     key the certificate does not cover, a raw signature, a 0x0C session
 *     signature) kills the initiator BEFORE any ENCAPS (no ENCAPS job is
 *     ever issued, no KEYX is ever queued); a pin the caller rejects, and a
 *     certificate verified without the pin accepted, do the same;
 *   · CONFIRM: a forged-but-correct `01 06` frame authenticates (control, so
 *     the forging helper is right); a wrong content, a tail, an empty chunk,
 *     chunkLength 1, a full 1,024-byte chunk, chunkLength 1,025, a flipped
 *     tag bit, a reflected frame and a replayed counter never do, on either
 *     side; a missing CONFIRM leaves both sides unauthenticated;
 *   · CLIENT <-> ANON and WITNESS / NODE <-> ANON mismatches never
 *     authenticate (every direction); an unbound responder WITHOUT a KC
 *     refuses ANON; WITNESS / NODE / CLIENT machines refuse the kinds
 *     0x05 / 0x06 / 0x07 and ANY wrong (kind, length) pair, as does the
 *     unbound responder's first message;
 *   · fragmented input (1-byte and 7-byte feeds) gives the same result for
 *     ANON, for the unbound responder's CLIENT continuation and for the
 *     unbound responder's first-message length prefix;
 *   · init arguments: ANON is refused by cmt_p2p_sc_init_profile; an ANON
 *     initiator with a local key or without verify_kc, a responder without a
 *     KC, are refused;
 *   · 4004 gate: CMT_P2P_SC_HS_MSG_MAX, CMT_P2P_SC_OUT_CAP and the
 *     cmt_p2p_peer.h caps keep their values (compile-time assertions below).
 *
 * WHAT IT REQUIRES: a default nodus build; no flags, no environment. Fixed
 * seeds for the identities; handshake nonces and Encaps coins are random, so
 * only structure and recomputation are checked.
 * WHAT IT LEAVES BEHIND: nothing.
 *
 * HOW IT CAN LIE: the recompute uses this tree's SHA3-512 / HKDF and its own
 * reading of design §1.4; it ties the machine to the design text, not to an
 * outside tool (there is no external reference for this construction, design
 * §6). The pin and job driving here are a test emulation of the layer's
 * (nodus_tcp_sc.c sc_advance); the layer itself is exercised in
 * test_tcp_sc.c. Both machines run in one process with inline jobs.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_secret.h"
#include "dnac/cmt_p2p_peer.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/hkdf_sha3.h"
#include "nodus/nodus_types.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-72s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

#define PROTO_VER 1u
static const uint8_t CHAIN_A[32] = {
    0x9a, 0xbf, 0x84, 0x37, 0xe7, 0x29, 0x0e, 0x45, 0xfe, 0x7b, 0x0f, 0xb2,
    0xcc, 0xd8, 0xc1, 0xa3, 0x32, 0x1c, 0xa4, 0xc0, 0x2f, 0xe1, 0x19, 0x2e,
    0xa9, 0x2e, 0xc9, 0xdf, 0x5f, 0x8d, 0xf0, 0xd2
};
static const uint8_t CHAIN_B[32] = {
    0x11, 0xbf, 0x84, 0x37, 0xe7, 0x29, 0x0e, 0x45, 0xfe, 0x7b, 0x0f, 0xb2,
    0xcc, 0xd8, 0xc1, 0xa3, 0x32, 0x1c, 0xa4, 0xc0, 0x2f, 0xe1, 0x19, 0x2e,
    0xa9, 0x2e, 0xc9, 0xdf, 0x5f, 0x8d, 0xf0, 0xd2
};

/* ══ the 4004 gate: no value moves (design §1.6, §4) ══════════════════ */

_Static_assert(CMT_P2P_SC_HS_MSG_MAX == 4232, "CMT_P2P_SC_HS_MSG_MAX moved (4004 pre-auth cap)");
_Static_assert(CMT_P2P_SC_OUT_CAP == 13684, "CMT_P2P_SC_OUT_CAP moved (4004 handshake output cap)");
_Static_assert(CMT_P2P_CONN_RBUF_PRE_AUTH_CAP == 4232,
               "cmt_p2p_peer.h CMT_P2P_CONN_RBUF_PRE_AUTH_CAP moved");
_Static_assert(CMT_P2P_CONN_RBUF_CAP == 4176, "cmt_p2p_peer.h CMT_P2P_CONN_RBUF_CAP moved");
_Static_assert(CMT_P2P_CONN_RBUF_ALLOC == 4232, "cmt_p2p_peer.h CMT_P2P_CONN_RBUF_ALLOC moved");
_Static_assert(CMT_P2P_CONN_WBUF_CAP == 13684 + 16 * 1044,
               "cmt_p2p_peer.h CMT_P2P_CONN_WBUF_CAP moved");
/* The ANON sizes of design §1.2 / §1.6, restated. */
_Static_assert(CMT_P2P_SC_HELLO_ANON_WIRE == 70 && CMT_P2P_SC_HELLO_R_ANON_WIRE == 8858 &&
               CMT_P2P_SC_KEYX_WIRE == 1571 && CMT_P2P_SC_SEALED_FRAME_SIZE == 1044 &&
               CMT_P2P_SC_KC_MSG_SIZE == 1622,
               "ANON wire sizes");

/* ══ helpers ═════════════════════════════════════════════════════════ */

static void fill(uint8_t *b, size_t n, uint8_t base)
{
    size_t k;
    for (k = 0; k < n; k++) {
        b[k] = (uint8_t)(base + k);
    }
}

typedef struct {
    nodus_identity_t id;
    uint8_t kc[CMT_P2P_SC_SIG_SIZE];     /* the node's certificate, signed ONCE */
} node_t;

static node_t *g_a, *g_b, *g_c;          /* A = the node, B = another node, C = a signer */

/** The certificate of `signer` over (chain, kem_pk of `covers`). */
static int make_kc(const node_t *signer, const uint8_t chain[32], const node_t *covers,
                   uint8_t out[CMT_P2P_SC_SIG_SIZE])
{
    uint8_t msg[CMT_P2P_SC_KC_MSG_SIZE];
    nodus_sig_t sig;

    cmt_p2p_sc_kc_msg(chain, covers->id.mlkem_pk, msg);
    if (nodus_sign_kem_cert(&sig, msg, sizeof(msg), &signer->id.sk) != 0) {
        return -1;
    }
    memcpy(out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return 0;
}

enum { PIN_OK = 0, PIN_BAD, PIN_SKIP };

typedef struct {
    cmt_p2p_sc_t *sc;
    cmt_p2p_sc_host_t host;
    const node_t *node;          /* host key / the node's identity            */
    uint8_t purpose;             /* session-auth purpose of sign / verify     */
    uint8_t ss[32];              /* copied right after the KEM job ran        */
    bool have_ss;
    uint8_t key[32];             /* copied right after the KEM job_done       */
    int pin_mode;
    const uint8_t *pin_pk;       /* the identity the caller meant to dial     */
    int kc_jobs, kc_calls, encaps_ran, sign_calls;
    uint8_t *pipe;               /* bytes waiting to be fed to THIS side      */
    size_t pipe_len;
    uint8_t *log;                /* everything this side WROTE                */
    size_t log_len;
} side_t;

#define PIPE_CAP 32768

static int host_sign(void *ctx, const uint8_t *msg, size_t msg_len, uint8_t sig_out[4627])
{
    side_t *s = (side_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_tagged(&sig, s->purpose, msg, msg_len, &s->node->id.sk);

    s->sign_calls++;
    memcpy(sig_out, sig.bytes, 4627);
    return rc;
}

static int host_verify(void *ctx, const uint8_t sig_in[4627], const uint8_t *msg,
                       size_t msg_len, const uint8_t pk_in[2592])
{
    side_t *s = (side_t *)ctx;
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    memcpy(sig.bytes, sig_in, 4627);
    memcpy(pk.bytes, pk_in, 2592);
    return nodus_verify_tagged(&sig, s->purpose, msg, msg_len, &pk);
}

static int host_verify_kc(void *ctx, const uint8_t sig_in[4627], const uint8_t *msg,
                          size_t msg_len, const uint8_t pk_in[2592])
{
    side_t *s = (side_t *)ctx;
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    s->kc_calls++;
    memcpy(sig.bytes, sig_in, 4627);
    memcpy(pk.bytes, pk_in, 2592);
    return nodus_verify_kem_cert(&sig, msg, msg_len, &pk);
}

static int side_alloc(side_t *s, const node_t *node, uint8_t purpose)
{
    memset(s, 0, sizeof(*s));
    s->sc = (cmt_p2p_sc_t *)calloc(1, sizeof(cmt_p2p_sc_t));
    s->pipe = (uint8_t *)malloc(PIPE_CAP);
    s->log = (uint8_t *)malloc(PIPE_CAP);
    s->node = node;
    s->purpose = purpose;
    s->host.ctx = s;
    s->host.sign = host_sign;
    s->host.verify = host_verify;
    s->host.verify_kc = NULL;
    return (s->sc && s->pipe && s->log) ? CMT_OK : CMT_FAULT;
}

static void side_free(side_t *s)
{
    if (s->sc != NULL) {
        cmt_p2p_sc_clear(s->sc);
        free(s->sc);
    }
    free(s->pipe);
    free(s->log);
    s->sc = NULL;
    s->pipe = NULL;
    s->log = NULL;
}

/** ANON initiator: no key, no sign / verify, only the KC verify. `pin` is the
 *  identity the caller meant to dial. */
static int init_anon_i(side_t *s, const uint8_t *pin_pk, int pin_mode)
{
    if (side_alloc(s, NULL, 0) != CMT_OK) {
        return CMT_FAULT;
    }
    s->host.sign = NULL;                 /* an ANON initiator must never sign ... */
    s->host.verify = NULL;               /* ... or call the session verify        */
    s->host.verify_kc = host_verify_kc;
    s->pin_pk = pin_pk;
    s->pin_mode = pin_mode;
    return cmt_p2p_sc_init_anon(s->sc, CMT_P2P_SC_ROLE_INITIATOR, &s->host, NULL, NULL,
                                NULL, NULL, PROTO_VER, CHAIN_A);
}

/** ANON-BOUND responder with the certificate `kc`. */
static int init_anon_r(side_t *s, const node_t *node, const uint8_t *kc)
{
    if (side_alloc(s, node, 0) != CMT_OK) {
        return CMT_FAULT;
    }
    return cmt_p2p_sc_init_anon(s->sc, CMT_P2P_SC_ROLE_RESPONDER, &s->host,
                                node->id.pk.bytes, node->id.mlkem_pk, node->id.mlkem_sk,
                                kc, PROTO_VER, CHAIN_A);
}

/** UNBOUND responder (4001 / WS accept); kc NULL = ANON not offered. */
static int init_unbound_r(side_t *s, const node_t *node, const uint8_t *kc)
{
    if (side_alloc(s, node, NODUS_PURPOSE_CLIENT_SESSION_AUTH) != CMT_OK) {
        return CMT_FAULT;
    }
    return cmt_p2p_sc_init_responder_unbound(s->sc, &s->host, node->id.pk.bytes,
                                             node->id.mlkem_pk, node->id.mlkem_sk, kc,
                                             PROTO_VER, CHAIN_A);
}

static uint8_t purpose_of(const cmt_p2p_sc_profile_t *p)
{
    if (p == &CMT_P2P_SC_PROFILE_CLIENT) return NODUS_PURPOSE_CLIENT_SESSION_AUTH;
    if (p == &CMT_P2P_SC_PROFILE_NODE) return NODUS_PURPOSE_NODE_SESSION_AUTH;
    return NODUS_PURPOSE_SESSION_AUTH;
}

/** A bound WITNESS / CLIENT / NODE machine (identified: needs its key). */
static int init_bound(side_t *s, const node_t *node, cmt_p2p_sc_role_t role,
                      const cmt_p2p_sc_profile_t *profile)
{
    if (side_alloc(s, node, purpose_of(profile)) != CMT_OK) {
        return CMT_FAULT;
    }
    return cmt_p2p_sc_init_profile(
        s->sc, role, &s->host, profile, node->id.pk.bytes,
        role == CMT_P2P_SC_ROLE_RESPONDER ? node->id.mlkem_pk : NULL,
        role == CMT_P2P_SC_ROLE_RESPONDER ? node->id.mlkem_sk : NULL,
        PROTO_VER, CHAIN_A);
}

/** Run every outstanding job inline, with the layer's pin emulation (the
 *  layer pins BEFORE the KC job, nodus_tcp_sc.c sc_advance). */
static size_t run_jobs(side_t *s)
{
    const cmt_p2p_sc_job_t *job;
    size_t ran = 0;

    while ((job = cmt_p2p_sc_job(s->sc)) != NULL) {
        cmt_p2p_sc_job_kind_t kind = job->kind;
        int jrc;

        if (kind == CMT_P2P_SC_JOB_VERIFY_KC) {
            const uint8_t *rpk = cmt_p2p_sc_remote_pubkey(s->sc);

            s->kc_jobs++;
            if (s->pin_mode != PIN_SKIP) {
                if (rpk == NULL || s->pin_pk == NULL || s->pin_mode == PIN_BAD ||
                    memcmp(rpk, s->pin_pk, 2592) != 0) {
                    cmt_p2p_sc_abort(s->sc);                 /* pin refused */
                    return ran + 1;
                }
                if (cmt_p2p_sc_anon_pin_accepted(s->sc) != CMT_OK) {
                    return ran + 1;
                }
            }
        }
        if (kind == CMT_P2P_SC_JOB_ENCAPS) {
            s->encaps_ran++;
        }
        jrc = cmt_p2p_sc_job_run(job, &s->host);
        if (kind == CMT_P2P_SC_JOB_ENCAPS || kind == CMT_P2P_SC_JOB_DECAPS) {
            memcpy(s->ss, s->sc->ss, 32);          /* wiped by job_done */
            s->have_ss = true;
        }
        (void)cmt_p2p_sc_job_done(s->sc, jrc);
        if (kind == CMT_P2P_SC_JOB_ENCAPS || kind == CMT_P2P_SC_JOB_DECAPS) {
            memcpy(s->key, s->sc->key, 32);
        }
        ran++;
    }
    return ran;
}

static size_t g_chunk;      /* 0 = hand over everything at once */

/** Move `from`'s output into `to`'s pipe (and `from`'s log), then feed `to`
 *  what it accepts, g_chunk bytes at a time. */
static size_t pump(side_t *from, side_t *to)
{
    size_t n = 0, moved = 0;
    const uint8_t *o = cmt_p2p_sc_out(from->sc, &n);

    if (n > 0 && n <= PIPE_CAP - to->pipe_len && n <= PIPE_CAP - from->log_len) {
        memcpy(to->pipe + to->pipe_len, o, n);
        to->pipe_len += n;
        memcpy(from->log + from->log_len, o, n);
        from->log_len += n;
        cmt_p2p_sc_out_consume(from->sc, n);
        moved = n;
    }
    while (to->pipe_len > 0) {
        size_t take = (g_chunk != 0 && g_chunk < to->pipe_len) ? g_chunk : to->pipe_len;
        size_t c = 0;

        if (cmt_p2p_sc_recv(to->sc, to->pipe, take, &c) != CMT_OK || c == 0) {
            break;
        }
        memmove(to->pipe, to->pipe + c, to->pipe_len - c);
        to->pipe_len -= c;
        moved += c;
    }
    return moved;
}

static void drive(side_t *i, side_t *r)
{
    int guard;

    for (guard = 0; guard < 400; guard++) {
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

static bool both_auth(const side_t *i, const side_t *r)
{
    return cmt_p2p_sc_is_authenticated(i->sc) && cmt_p2p_sc_is_authenticated(r->sc);
}

static bool neither_auth(const side_t *i, const side_t *r)
{
    return !cmt_p2p_sc_is_authenticated(i->sc) && !cmt_p2p_sc_is_authenticated(r->sc);
}

/** Bytes still queued for the wire on `s`. */
static size_t out_len(const side_t *s)
{
    size_t n = 0;

    (void)cmt_p2p_sc_out(s->sc, &n);
    return n;
}

/* ══ the independent recompute (design §1.4), from the wire bytes ════════ */

/** T and the AEAD key from the CAPTURED messages, the nodus.asess.* strings
 *  typed literally, the preimage WITHOUT I_dsa_pk. `hello` is I's 70 bytes,
 *  `hello_r` R's 8,858, `keyx` the 1,571 that follow in I's log. */
static int recompute(const uint8_t *hello, const uint8_t *hello_r, const uint8_t *keyx,
                     const uint8_t ss[32], uint8_t T[64], uint8_t key[32])
{
    static const char tag[] = "nodus.asess.transcript.v1";
    static const char info[] = "nodus.asess.keys.v1/aead";
    uint8_t *pre = (uint8_t *)malloc(sizeof(tag) - 1 + 5864);
    size_t o = 0;
    int rc = -1;

    if (pre == NULL) {
        return -1;
    }
    /* HELLO_ANON: uvarint(1) kind(1) nonce_I(32) proto_ver(4) chain_id(32) */
    /* HELLO_R_ANON: uvarint(2) kind(1) R_dsa_pk(2592) R_mlkem_pk(1568) kc_sig(4627)
     *               nonce_R(32) proto_ver(4) chain_id(32) */
    /* KEYX: uvarint(2) kind(1) ct(1568) */
    memcpy(pre + o, tag, sizeof(tag) - 1);  o += sizeof(tag) - 1;
    memcpy(pre + o, hello_r + 3, 2592);     o += 2592;            /* R_dsa_pk   */
    memcpy(pre + o, hello_r + 3 + 2592, 1568); o += 1568;         /* R_mlkem_pk */
    memcpy(pre + o, hello + 34, 4);         o += 4;               /* proto_ver_I */
    memcpy(pre + o, hello + 38, 32);        o += 32;              /* chain_id_I  */
    memcpy(pre + o, hello_r + 8822, 4);     o += 4;               /* proto_ver_R */
    memcpy(pre + o, hello_r + 8826, 32);    o += 32;              /* chain_id_R  */
    memcpy(pre + o, hello + 2, 32);         o += 32;              /* nonce_I     */
    memcpy(pre + o, hello_r + 8790, 32);    o += 32;              /* nonce_R     */
    memcpy(pre + o, keyx + 3, 1568);        o += 1568;            /* ct          */
    if (o == 5889 &&
        qgp_sha3_512(pre, o, T) == 0 &&
        hkdf_sha3_256(T, 64, ss, 32, (const uint8_t *)info, sizeof(info) - 1, key, 32) == 0) {
        rc = 0;
    }
    free(pre);
    return rc;
}

/* ══ forged sealed frames ═════════════════════════════════════════════ */

/** Seal one frame with an explicit key / role / counter and an explicit
 *  chunkLength field (so an oversize field can be written). Same layout as
 *  cmt_p2p_secret.c sc_seal_frame: frame = u32 LE chunkLength ‖ chunk ‖ zero
 *  pad (1028 B); nonce = role ‖ 00 00 00 ‖ u64 BE counter; AES-256-GCM. */
static int forge(const uint8_t key[32], uint8_t role, uint64_t ctr,
                 const uint8_t *chunk, size_t chunk_len, uint32_t len_field,
                 uint8_t out[CMT_P2P_SC_SEALED_FRAME_SIZE])
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx;
    int len = 0, ok = 0, k;

    memset(frame, 0, sizeof(frame));
    frame[0] = (uint8_t)len_field;
    frame[1] = (uint8_t)(len_field >> 8);
    frame[2] = (uint8_t)(len_field >> 16);
    frame[3] = (uint8_t)(len_field >> 24);
    if (chunk_len > 0) {
        memcpy(frame + 4, chunk, chunk_len);
    }
    nonce[0] = role;
    nonce[1] = nonce[2] = nonce[3] = 0;
    for (k = 0; k < 8; k++) {
        nonce[4 + k] = (uint8_t)(ctr >> (56 - 8 * k));
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, out, &len, frame, (int)sizeof(frame)) == 1 &&
        len == (int)sizeof(frame) &&
        EVP_EncryptFinal_ex(ctx, out + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                            out + CMT_P2P_SC_TOTAL_FRAME_SIZE) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/** ANON handshake up to the CONFIRMs: both sides hold their keys and each has
 *  its OWN CONFIRM queued or not yet sent; NOTHING of the CONFIRM stage has
 *  been delivered. After it: i is WAIT_CONFIRM, r is WAIT_CONFIRM with its
 *  CONFIRM (1,044 B) still in its output queue. */
static int reach_confirm(side_t *i, side_t *r)
{
    (void)pump(i, r);            /* HELLO_ANON -> r; r queues HELLO_R_ANON      */
    (void)pump(r, i);            /* HELLO_R_ANON -> i; job VERIFY_KC pending    */
    (void)run_jobs(i);           /* KC verify, pin, ENCAPS; i queues KEYX       */
    (void)pump(i, r);            /* KEYX -> r; DECAPS pending                   */
    (void)run_jobs(r);           /* DECAPS; r queues its sealed CONFIRM         */
    return (i->sc->state == CMT_P2P_SC_ST_WAIT_CONFIRM &&
            r->sc->state == CMT_P2P_SC_ST_WAIT_CONFIRM && out_len(r) == 1044) ? 0 : -1;
}

/* ══ tests ═══════════════════════════════════════════════════════════ */

static void test_happy(const char *name, bool bound_responder, size_t chunk)
{
    side_t i, r;
    uint8_t T[64], key[32];
    uint8_t buf[64], got[64];
    size_t n = 0, c = 0, g = 0, wl = 0;
    uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE];
    bool ok;

    TEST(name);
    g_chunk = chunk;
    if ((init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) != CMT_OK) ||
        (bound_responder ? init_anon_r(&r, g_a, g_a->kc) : init_unbound_r(&r, g_a, g_a->kc)) != CMT_OK) {
        FAIL("setup failed");
        side_free(&i);
        side_free(&r);
        g_chunk = 0;
        return;
    }
    ok = cmt_p2p_sc_transcript(i.sc) == NULL && cmt_p2p_sc_transcript(r.sc) == NULL &&
         cmt_p2p_sc_remote_pubkey(r.sc) == NULL;
    drive(&i, &r);
    g_chunk = 0;
    ok = ok && both_auth(&i, &r) && i.sign_calls == 0 && r.sign_calls == 0 &&
         i.kc_calls == 1 && i.kc_jobs == 1 && i.encaps_ran == 1 && r.kc_calls == 0 &&
         /* exact wire sizes: I wrote HELLO 70 + KEYX 1571 + CONFIRM 1044; R wrote
          * HELLO_R 8858 + CONFIRM 1044 */
         i.log_len == 70 + 1571 + 1044 && r.log_len == 8858 + 1044 &&
         i.log[0] == 69 && i.log[1] == CMT_P2P_SC_MSG_HELLO_ANON &&
         r.log[0] == (0x80 | (8856 & 0x7f)) && r.log[1] == (8856 >> 7) &&
         r.log[2] == CMT_P2P_SC_MSG_HELLO_R_ANON &&
         i.log[70] == (0x80 | (1569 & 0x7f)) && i.log[71] == (1569 >> 7) &&
         i.log[72] == CMT_P2P_SC_MSG_KEYX &&
         i.have_ss && r.have_ss && memcmp(i.ss, r.ss, 32) == 0 &&
         memcmp(i.key, r.key, 32) == 0;
    /* the key and T, recomputed from the captured bytes */
    ok = ok && recompute(i.log, r.log, i.log + 70, i.ss, T, key) == 0 &&
         memcmp(key, i.key, 32) == 0 && memcmp(key, r.key, 32) == 0 &&
         cmt_p2p_sc_transcript(i.sc) != NULL && cmt_p2p_sc_transcript(r.sc) != NULL &&
         memcmp(cmt_p2p_sc_transcript(i.sc), T, 64) == 0 &&
         memcmp(cmt_p2p_sc_transcript(r.sc), T, 64) == 0 &&
         memcmp(cmt_p2p_sc_transcript(i.sc), cmt_p2p_sc_transcript(r.sc), 64) == 0;
    /* peer keys: the initiator learns R's, the ANON responder has none */
    ok = ok && cmt_p2p_sc_remote_pubkey(i.sc) != NULL &&
         memcmp(cmt_p2p_sc_remote_pubkey(i.sc), g_a->id.pk.bytes, 2592) == 0 &&
         cmt_p2p_sc_remote_pubkey(r.sc) == NULL &&
         cmt_p2p_sc_is_anon(i.sc) && cmt_p2p_sc_is_anon(r.sc);
    /* sealed data flows both ways after AUTHENTICATED */
    fill(buf, sizeof(buf), 0x5a);
    ok = ok && cmt_p2p_sc_write(i.sc, buf, sizeof(buf), sealed, sizeof(sealed), &wl) == CMT_OK &&
         wl == sizeof(sealed) &&
         cmt_p2p_sc_read(r.sc, sealed, wl, &c, got, sizeof(got), &g) == CMT_OK &&
         c == wl && g == sizeof(buf) && memcmp(got, buf, sizeof(buf)) == 0 &&
         cmt_p2p_sc_write(r.sc, buf, 10, sealed, sizeof(sealed), &wl) == CMT_OK &&
         cmt_p2p_sc_read(i.sc, sealed, wl, &c, got, sizeof(got), &n) == CMT_OK &&
         n == 10 && memcmp(got, buf, 10) == 0;
    if (ok) PASS(); else FAIL("ANON handshake");
    side_free(&i);
    side_free(&r);
}

static void test_t_differs_per_session(void)
{
    side_t i1, r1, i2, r2;
    bool ok;

    TEST("two ANON sessions of the same pair have different T and keys");
    ok = init_anon_i(&i1, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         init_unbound_r(&r1, g_a, g_a->kc) == CMT_OK &&
         init_anon_i(&i2, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         init_unbound_r(&r2, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        drive(&i1, &r1);
        drive(&i2, &r2);
        ok = both_auth(&i1, &r1) && both_auth(&i2, &r2) &&
             memcmp(cmt_p2p_sc_transcript(i1.sc), cmt_p2p_sc_transcript(i2.sc), 64) != 0 &&
             memcmp(i1.key, i2.key, 32) != 0;
    }
    if (ok) PASS(); else FAIL("T / key reused across sessions");
    side_free(&i1); side_free(&r1); side_free(&i2); side_free(&r2);
}

/** A certificate variant the initiator must refuse, BEFORE any ENCAPS. */
static void test_bad_kc(const char *name, const uint8_t *kc)
{
    side_t i, r;
    bool ok;

    TEST(name);
    ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         init_unbound_r(&r, g_a, kc) == CMT_OK;
    if (ok) {
        drive(&i, &r);
        ok = i.kc_jobs == 1 && i.kc_calls == 1 &&          /* the verify ran, and failed */
             i.encaps_ran == 0 &&                           /* never an ENCAPS ...        */
             i.sc->state == CMT_P2P_SC_ST_DEAD && out_len(&i) == 0 &&
             i.log_len == 70 &&                             /* ... nor a KEYX: only HELLO */
             neither_auth(&i, &r) && cmt_p2p_sc_job(i.sc) == NULL;
    }
    if (ok) PASS(); else FAIL("a bad certificate reached ENCAPS or authenticated");
    side_free(&i);
    side_free(&r);
}

static void test_kc_variants(void)
{
    uint8_t kc[CMT_P2P_SC_SIG_SIZE];
    uint8_t msg[CMT_P2P_SC_KC_MSG_SIZE];
    nodus_sig_t sig;
    int ok;

    memcpy(kc, g_a->kc, sizeof(kc));
    kc[100] ^= 0x01;
    test_bad_kc("bad KC: one flipped bit in kc_sig", kc);

    ok = make_kc(g_c, CHAIN_A, g_a, kc);                 /* right bytes, wrong signer */
    if (ok != 0) { TEST("bad KC: wrong signer"); FAIL("setup"); }
    else test_bad_kc("bad KC: signed by another key than R's claimed key", kc);

    ok = make_kc(g_a, CHAIN_B, g_a, kc);                 /* another chain */
    if (ok != 0) { TEST("bad KC: wrong chain"); FAIL("setup"); }
    else test_bad_kc("bad KC: over another chain id (the initiator uses its OWN)", kc);

    ok = make_kc(g_a, CHAIN_A, g_b, kc);                 /* certifies B's KEM key */
    if (ok != 0) { TEST("bad KC: other KEM key"); FAIL("setup"); }
    else test_bad_kc("bad KC: certifies a KEM key other than the advertised one", kc);

    cmt_p2p_sc_kc_msg(CHAIN_A, g_a->id.mlkem_pk, msg);
    ok = nodus_sign(&sig, msg, sizeof(msg), &g_a->id.sk);   /* raw, no NDS1 tag */
    if (ok != 0) { TEST("bad KC: raw"); FAIL("setup"); }
    else {
        memcpy(kc, sig.bytes, sizeof(kc));
        test_bad_kc("bad KC: a RAW signature over the right message (strict: no fallback)", kc);
    }

    ok = nodus_sign_client_session_auth(&sig, msg, sizeof(msg), &g_a->id.sk);   /* 0x0C */
    if (ok != 0) { TEST("bad KC: 0x0C"); FAIL("setup"); }
    else {
        memcpy(kc, sig.bytes, sizeof(kc));
        test_bad_kc("bad KC: a 0x0C session signature over the same bytes", kc);
    }
}

static void test_pin(void)
{
    side_t i, r;
    bool ok;

    TEST("pin rejected by the caller: aborted, no KC verify, no ENCAPS, no KEYX");
    ok = init_anon_i(&i, g_b->id.pk.bytes, PIN_OK) == CMT_OK &&      /* dialed B, got A */
         init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        drive(&i, &r);
        ok = i.kc_jobs == 1 && i.kc_calls == 0 && i.encaps_ran == 0 &&
             i.sc->state == CMT_P2P_SC_ST_DEAD && i.log_len == 70 && neither_auth(&i, &r);
    }
    if (ok) PASS(); else FAIL("a rejected pin reached ENCAPS");
    side_free(&i);
    side_free(&r);

    TEST("KC valid but the pin was NEVER accepted: the machine kills itself, no ENCAPS");
    ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_SKIP) == CMT_OK &&
         init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        drive(&i, &r);
        ok = i.kc_jobs == 1 && i.kc_calls == 1 && i.encaps_ran == 0 &&
             i.sc->state == CMT_P2P_SC_ST_DEAD && i.log_len == 70 && neither_auth(&i, &r);
    }
    if (ok) PASS(); else FAIL("ENCAPS issued without the pin");
    side_free(&i);
    side_free(&r);

    TEST("cmt_p2p_sc_anon_pin_accepted outside the KC job is a fault");
    ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         cmt_p2p_sc_anon_pin_accepted(i.sc) == CMT_FAULT &&
         cmt_p2p_sc_anon_pin_accepted(NULL) == CMT_FAULT;
    if (ok) PASS(); else FAIL("pin accepted out of turn");
    side_free(&i);
}

static void test_job_kc_guard(void)
{
    side_t i, r;
    cmt_p2p_sc_job_t j;
    bool ok;

    TEST("VERIFY_KC job: refused without verify_kc or with a wrong message length");
    ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        (void)pump(&i, &r);
        (void)pump(&r, &i);
        {
            const cmt_p2p_sc_job_t *job = cmt_p2p_sc_job(i.sc);

            ok = job != NULL && job->kind == CMT_P2P_SC_JOB_VERIFY_KC &&
                 job->msg_len == CMT_P2P_SC_KC_MSG_SIZE &&
                 cmt_p2p_sc_remote_pubkey(i.sc) != NULL &&
                 /* the message is the design's: domain ‖ OWN chain ‖ RECEIVED KEM key */
                 memcmp(job->msg, "nodus.asess.kembind.v1", 22) == 0 &&
                 memcmp(job->msg + 22, CHAIN_A, 32) == 0 &&
                 memcmp(job->msg + 54, g_a->id.mlkem_pk, 1568) == 0;
            if (ok) {
                j = *job;
                ok = cmt_p2p_sc_job_run(&j, NULL) != 0;         /* no host */
                j.msg_len = 1621;
                ok = ok && cmt_p2p_sc_job_run(&j, &i.host) != 0;
            }
        }
    }
    if (ok) PASS(); else FAIL("VERIFY_KC guards or message layout");
    side_free(&i);
    side_free(&r);
}

/** One forged-CONFIRM case. `to_initiator` = the target is the initiator (it
 *  receives a forged SERVER confirm) or the responder (a forged CLIENT one). */
typedef struct {
    const char *name;
    uint8_t chunk[1024];
    size_t chunk_len;       /* bytes copied into the frame */
    uint32_t len_field;     /* the chunkLength field written */
    bool right_role;        /* seal with the sender's role (false: the target's: reflected) */
    uint64_t ctr;
    bool flip_tag;
    bool authenticates;     /* the control */
} confirm_case_t;

static void run_confirm_case(const confirm_case_t *cc, bool to_initiator)
{
    side_t i, r;
    side_t *target, *sender;
    uint8_t frame[CMT_P2P_SC_SEALED_FRAME_SIZE];
    uint8_t role;
    char title[160];
    bool ok;

    snprintf(title, sizeof(title), "CONFIRM to the %s: %s",
             to_initiator ? "initiator" : "responder", cc->name);
    TEST(title);
    if (init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) != CMT_OK ||
        init_unbound_r(&r, g_a, g_a->kc) != CMT_OK || reach_confirm(&i, &r) != 0) {
        FAIL("setup failed");
        side_free(&i);
        side_free(&r);
        return;
    }
    target = to_initiator ? &i : &r;
    sender = to_initiator ? &r : &i;
    role = (uint8_t)(cc->right_role ? sender->sc->role : target->sc->role);
    ok = forge(sender->sc->key, role, cc->ctr, cc->chunk, cc->chunk_len, cc->len_field, frame) == 0;
    if (cc->flip_tag) {
        frame[CMT_P2P_SC_SEALED_FRAME_SIZE - 1] ^= 1;
    }
    {
        size_t c = 0;
        int rc = cmt_p2p_sc_recv(target->sc, frame, sizeof(frame), &c);

        if (cc->authenticates) {
            ok = ok && rc == CMT_OK && c == sizeof(frame) && cmt_p2p_sc_is_authenticated(target->sc) &&
                 /* the initiator answers with its own CONFIRM: one sealed frame */
                 (!to_initiator || out_len(&i) == 1044);
        } else {
            ok = ok && rc == CMT_REJECT && !cmt_p2p_sc_is_authenticated(target->sc) &&
                 target->sc->state == CMT_P2P_SC_ST_DEAD &&
                 /* a refused server CONFIRM is never answered */
                 (!to_initiator || out_len(&i) == 0);
        }
    }
    if (ok) PASS(); else FAIL("CONFIRM rule broken");
    side_free(&i);
    side_free(&r);
}

static void test_confirm_cases(void)
{
    static confirm_case_t cases[10];
    size_t n = 0, k;

    memset(cases, 0, sizeof(cases));
#define CASE(nm, ...) do { cases[n] = (confirm_case_t){ .name = (nm), __VA_ARGS__ }; n++; } while (0)
    CASE("control: exactly `01 06` authenticates", .chunk = { 0x01, 0x06 },
         .chunk_len = 2, .len_field = 2, .right_role = true, .ctr = 0, .authenticates = true);
    CASE("wrong content `01 04` (an AUTHSIG kind)", .chunk = { 0x01, 0x04 },
         .chunk_len = 2, .len_field = 2, .right_role = true, .ctr = 0);
    CASE("tail: `01 06 00` (chunkLength 3)", .chunk = { 0x01, 0x06, 0x00 },
         .chunk_len = 3, .len_field = 3, .right_role = true, .ctr = 0);
    CASE("empty chunk (chunkLength 0)", .chunk_len = 0, .len_field = 0,
         .right_role = true, .ctr = 0);
    CASE("chunkLength 1 (`01` only)", .chunk = { 0x01 }, .chunk_len = 1, .len_field = 1,
         .right_role = true, .ctr = 0);
    CASE("oversized: a full 1,024-byte chunk starting `01 06`", .chunk = { 0x01, 0x06 },
         .chunk_len = 1024, .len_field = 1024, .right_role = true, .ctr = 0);
    CASE("oversized: chunkLength field 1,025", .chunk = { 0x01, 0x06 },
         .chunk_len = 2, .len_field = 1025, .right_role = true, .ctr = 0);
    CASE("flipped tag bit", .chunk = { 0x01, 0x06 }, .chunk_len = 2, .len_field = 2,
         .right_role = true, .ctr = 0, .flip_tag = true);
    CASE("reflected (sealed with the target's own role)", .chunk = { 0x01, 0x06 },
         .chunk_len = 2, .len_field = 2, .right_role = false, .ctr = 0);
    CASE("replayed counter 1 (the first frame must be counter 0)", .chunk = { 0x01, 0x06 },
         .chunk_len = 2, .len_field = 2, .right_role = true, .ctr = 1);
#undef CASE
    for (k = 0; k < n; k++) {
        run_confirm_case(&cases[k], true);
        run_confirm_case(&cases[k], false);
    }

    {
        side_t i, r;
        bool ok;

        TEST("a CONFIRM that never arrives: neither side is authenticated");
        ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
             init_unbound_r(&r, g_a, g_a->kc) == CMT_OK && reach_confirm(&i, &r) == 0 &&
             neither_auth(&i, &r);
        /* the responder's CONFIRM reaches the initiator, the client's never
         * reaches the responder: the responder (which proved first) still waits */
        if (ok) {
            (void)pump(&r, &i);
            ok = cmt_p2p_sc_is_authenticated(i.sc) && !cmt_p2p_sc_is_authenticated(r.sc) &&
                 r.sc->state == CMT_P2P_SC_ST_WAIT_CONFIRM;
        }
        if (ok) PASS(); else FAIL("authenticated without the peer's CONFIRM");
        side_free(&i);
        side_free(&r);
    }
}

/* ══ family selection, mismatches, refused kinds ══════════════════════ */

static void test_mismatch(const char *name, int ikind, const cmt_p2p_sc_profile_t *ip,
                          int rkind, const cmt_p2p_sc_profile_t *rp)
{
    /* kinds: 0 = ANON initiator, 1 = ANON-bound responder, 2 = bound-profile
     * machine (ip / rp), 3 = unbound responder with a KC, 4 = unbound without */
    side_t i, r;
    bool ok;

    TEST(name);
    ok = (ikind == 0 ? init_anon_i(&i, g_a->id.pk.bytes, PIN_OK)
                     : init_bound(&i, g_b, CMT_P2P_SC_ROLE_INITIATOR, ip)) == CMT_OK;
    if (ok) {
        switch (rkind) {
        case 1: ok = init_anon_r(&r, g_a, g_a->kc) == CMT_OK; break;
        case 2: ok = init_bound(&r, g_a, CMT_P2P_SC_ROLE_RESPONDER, rp) == CMT_OK; break;
        case 3: ok = init_unbound_r(&r, g_a, g_a->kc) == CMT_OK; break;
        default: ok = init_unbound_r(&r, g_a, NULL) == CMT_OK; break;
        }
    }
    if (ok) {
        drive(&i, &r);
        ok = neither_auth(&i, &r);
    }
    if (ok) PASS(); else FAIL("a mismatched pair authenticated (or setup failed)");
    side_free(&i);
    side_free(&r);
}

static void test_mismatches(void)
{
    test_mismatch("ANON initiator vs CLIENT-bound responder", 0, NULL, 2, &CMT_P2P_SC_PROFILE_CLIENT);
    test_mismatch("ANON initiator vs NODE-bound responder", 0, NULL, 2, &CMT_P2P_SC_PROFILE_NODE);
    test_mismatch("ANON initiator vs WITNESS-bound responder", 0, NULL, 2, &CMT_P2P_SC_PROFILE_WITNESS);
    test_mismatch("CLIENT initiator vs ANON-bound responder", 2, &CMT_P2P_SC_PROFILE_CLIENT, 1, NULL);
    test_mismatch("NODE initiator vs ANON-bound responder", 2, &CMT_P2P_SC_PROFILE_NODE, 1, NULL);
    test_mismatch("WITNESS initiator vs ANON-bound responder", 2, &CMT_P2P_SC_PROFILE_WITNESS, 1, NULL);
    test_mismatch("ANON initiator vs unbound responder WITHOUT a KC (ANON not offered)", 0, NULL, 4, NULL);
    test_mismatch("NODE initiator vs unbound responder (4002's family is not 4001's)", 2,
                  &CMT_P2P_SC_PROFILE_NODE, 3, NULL);
    test_mismatch("WITNESS initiator vs unbound responder", 2, &CMT_P2P_SC_PROFILE_WITNESS, 3, NULL);

    {
        side_t i, r;
        bool ok;

        /* CONTROL: a CLIENT initiator and an unbound responder do authenticate
         * (the CLIENT continuation is today's handshake), so the negatives
         * above are not a broken harness. */
        TEST("control: CLIENT initiator vs unbound responder authenticates (CLIENT bound)");
        ok = init_bound(&i, g_b, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_CLIENT) == CMT_OK &&
             init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
        if (ok) {
            drive(&i, &r);
            ok = both_auth(&i, &r) && !cmt_p2p_sc_is_anon(r.sc) &&
                 r.sc->profile == &CMT_P2P_SC_PROFILE_CLIENT &&
                 cmt_p2p_sc_remote_pubkey(r.sc) != NULL &&
                 memcmp(cmt_p2p_sc_remote_pubkey(r.sc), g_b->id.pk.bytes, 2592) == 0 &&
                 cmt_p2p_sc_transcript(i.sc) != NULL &&
                 memcmp(cmt_p2p_sc_transcript(i.sc), cmt_p2p_sc_transcript(r.sc), 64) == 0;
        }
        if (ok) PASS(); else FAIL("CLIENT continuation of the unbound responder");
        side_free(&i);
        side_free(&r);
    }
}

/** uvarint of a body length below 16384 into `out`. @return bytes written. */
static size_t uvar(uint8_t *out, size_t v)
{
    size_t n = 0;

    while (v >= 0x80) {
        out[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

/** Feed `s` one plaintext message: uvarint(body_len) ‖ kind ‖ zero fill. */
static int feed_msg(cmt_p2p_sc_t *sc, size_t body_len, uint8_t kind)
{
    uint8_t *m = (uint8_t *)calloc(1, body_len + 4);
    size_t o, c = 0;
    int rc;

    if (m == NULL) {
        return CMT_FAULT;
    }
    o = uvar(m, body_len);
    m[o] = kind;
    rc = cmt_p2p_sc_recv(sc, m, o + body_len, &c);
    free(m);
    return rc;
}

typedef struct {
    const char *name;
    size_t body_len;
    uint8_t kind;
} bad_msg_t;

static void test_refused_kinds(void)
{
    static const bad_msg_t first[] = {
        { "0x05 with HELLO's length 2661", CMT_P2P_SC_HELLO_BODY, CMT_P2P_SC_MSG_HELLO_ANON },
        { "0x01 with HELLO_ANON's length 69", CMT_P2P_SC_HELLO_ANON_BODY, CMT_P2P_SC_MSG_HELLO },
        { "0x07 (HELLO_R_ANON) as a first message, its own length 8856", CMT_P2P_SC_HELLO_R_ANON_BODY,
          CMT_P2P_SC_MSG_HELLO_R_ANON },
        { "0x06 (CONFIRM) as a first message, length 1", 1, CMT_P2P_SC_MSG_CONFIRM },
        { "0x03 (KEYX) as a first message, length 1569", CMT_P2P_SC_KEYX_BODY, CMT_P2P_SC_MSG_KEYX },
        { "0x05 one byte too long (70)", CMT_P2P_SC_HELLO_ANON_BODY + 1, CMT_P2P_SC_MSG_HELLO_ANON },
        { "0x05 one byte too short (68)", CMT_P2P_SC_HELLO_ANON_BODY - 1, CMT_P2P_SC_MSG_HELLO_ANON },
        { "an empty body", 0, 0 },
    };
    size_t k;

    /* the unbound responder (with a KC): the first message's (kind, length) must
     * be exactly (0x01, 2661) or (0x05, 69) */
    for (k = 0; k < sizeof(first) / sizeof(first[0]); k++) {
        side_t r;
        char title[160];
        bool ok;

        snprintf(title, sizeof(title), "unbound responder, first message: %s", first[k].name);
        TEST(title);
        ok = init_unbound_r(&r, g_a, g_a->kc) == CMT_OK &&
             feed_msg(r.sc, first[k].body_len, first[k].kind) == CMT_REJECT &&
             r.sc->state == CMT_P2P_SC_ST_DEAD && !cmt_p2p_sc_is_authenticated(r.sc) &&
             out_len(&r) == 0;
        if (ok) PASS(); else FAIL("accepted a first message that selects no family");
        side_free(&r);
    }

    /* WITNESS / NODE / CLIENT machines: 0x05 / 0x06 / 0x07 are refused wherever
     * they come (responder first step, initiator HELLO_R step, KEYX step) */
    {
        const cmt_p2p_sc_profile_t *profs[3] = { &CMT_P2P_SC_PROFILE_WITNESS,
                                                 &CMT_P2P_SC_PROFILE_NODE,
                                                 &CMT_P2P_SC_PROFILE_CLIENT };
        const char *pn[3] = { "WITNESS", "NODE", "CLIENT" };
        int p;

        for (p = 0; p < 3; p++) {
            side_t s;
            char title[160];
            bool ok;

            snprintf(title, sizeof(title), "%s responder refuses HELLO_ANON (0x05, 69)", pn[p]);
            TEST(title);
            ok = init_bound(&s, g_a, CMT_P2P_SC_ROLE_RESPONDER, profs[p]) == CMT_OK &&
                 feed_msg(s.sc, CMT_P2P_SC_HELLO_ANON_BODY, CMT_P2P_SC_MSG_HELLO_ANON) == CMT_REJECT &&
                 s.sc->state == CMT_P2P_SC_ST_DEAD && out_len(&s) == 0;
            if (ok) PASS(); else FAIL("accepted 0x05");
            side_free(&s);

            snprintf(title, sizeof(title), "%s responder refuses 0x05 even at HELLO's length (2661)", pn[p]);
            TEST(title);
            ok = init_bound(&s, g_a, CMT_P2P_SC_ROLE_RESPONDER, profs[p]) == CMT_OK &&
                 feed_msg(s.sc, CMT_P2P_SC_HELLO_BODY, CMT_P2P_SC_MSG_HELLO_ANON) == CMT_REJECT &&
                 s.sc->state == CMT_P2P_SC_ST_DEAD;
            if (ok) PASS(); else FAIL("accepted kind 0x05");
            side_free(&s);

            snprintf(title, sizeof(title), "%s initiator refuses HELLO_R_ANON (0x07, 8856) and 0x07 at HELLO_R's length", pn[p]);
            TEST(title);
            ok = init_bound(&s, g_b, CMT_P2P_SC_ROLE_INITIATOR, profs[p]) == CMT_OK &&
                 feed_msg(s.sc, CMT_P2P_SC_HELLO_R_ANON_BODY, CMT_P2P_SC_MSG_HELLO_R_ANON) == CMT_REJECT &&
                 s.sc->state == CMT_P2P_SC_ST_DEAD;
            side_free(&s);
            ok = ok && init_bound(&s, g_b, CMT_P2P_SC_ROLE_INITIATOR, profs[p]) == CMT_OK &&
                 feed_msg(s.sc, CMT_P2P_SC_HELLO_R_BODY, CMT_P2P_SC_MSG_HELLO_R_ANON) == CMT_REJECT &&
                 s.sc->state == CMT_P2P_SC_ST_DEAD;
            if (ok) PASS(); else FAIL("accepted 0x07");
            side_free(&s);

            snprintf(title, sizeof(title), "%s machine refuses a CONFIRM (0x06) message and a sealed `01 06`", pn[p]);
            TEST(title);
            ok = init_bound(&s, g_a, CMT_P2P_SC_ROLE_RESPONDER, profs[p]) == CMT_OK &&
                 feed_msg(s.sc, CMT_P2P_SC_CONFIRM_BODY, CMT_P2P_SC_MSG_CONFIRM) == CMT_REJECT &&
                 s.sc->state == CMT_P2P_SC_ST_DEAD;
            side_free(&s);
            if (ok) {
                /* a full identified handshake up to WAIT_AUTHSIG, then a sealed
                 * `01 06` frame where the AUTHSIG must be: refused */
                side_t i, r;
                uint8_t frame[CMT_P2P_SC_SEALED_FRAME_SIZE];
                size_t c = 0;

                ok = init_bound(&i, g_b, CMT_P2P_SC_ROLE_INITIATOR, profs[p]) == CMT_OK &&
                     init_bound(&r, g_a, CMT_P2P_SC_ROLE_RESPONDER, profs[p]) == CMT_OK;
                if (ok) {
                    uint8_t chunk[2] = { 0x01, 0x06 };

                    (void)pump(&i, &r);
                    (void)pump(&r, &i);
                    (void)run_jobs(&i);
                    (void)pump(&i, &r);
                    (void)run_jobs(&r);
                    (void)pump(&r, &i);
                    /* r is WAIT_AUTHSIG; its key is i's key: forge i's frame */
                    ok = r.sc->state == CMT_P2P_SC_ST_WAIT_AUTHSIG &&
                         forge(r.sc->key, CMT_P2P_SC_ROLE_INITIATOR, 0, chunk, 2, 2, frame) == 0 &&
                         cmt_p2p_sc_recv(r.sc, frame, sizeof(frame), &c) == CMT_REJECT &&
                         r.sc->state == CMT_P2P_SC_ST_DEAD && !cmt_p2p_sc_is_authenticated(r.sc);
                }
                side_free(&i);
                side_free(&r);
            }
            if (ok) PASS(); else FAIL("accepted 0x06");
        }
    }
}

static void test_fragmented_first_prefix(void)
{
    side_t i, r;
    bool ok;
    size_t k;

    /* The unbound responder reads its first length prefix one byte at a time:
     * HELLO's prefix (2661 = 0xE5 0x14) is two bytes, HELLO_ANON's one. */
    TEST("unbound responder: the first length prefix split across reads binds the right family");
    ok = init_anon_i(&i, g_a->id.pk.bytes, PIN_OK) == CMT_OK &&
         init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        size_t n = 0, c = 0;
        const uint8_t *o = cmt_p2p_sc_out(i.sc, &n);

        for (k = 0; ok && k < n; k++) {
            ok = cmt_p2p_sc_recv(r.sc, o + k, 1, &c) == CMT_OK && c == 1;
        }
        ok = ok && cmt_p2p_sc_is_anon(r.sc) && out_len(&r) == 8858;
    }
    if (ok) PASS(); else FAIL("1-byte feed of HELLO_ANON");
    side_free(&i);
    side_free(&r);

    TEST("unbound responder: a CLIENT HELLO split across reads binds CLIENT");
    ok = init_bound(&i, g_b, CMT_P2P_SC_ROLE_INITIATOR, &CMT_P2P_SC_PROFILE_CLIENT) == CMT_OK &&
         init_unbound_r(&r, g_a, g_a->kc) == CMT_OK;
    if (ok) {
        size_t n = 0, c = 0;
        const uint8_t *o = cmt_p2p_sc_out(i.sc, &n);

        ok = n == 2 + CMT_P2P_SC_HELLO_BODY &&
             cmt_p2p_sc_recv(r.sc, o, 1, &c) == CMT_OK && c == 1 && !cmt_p2p_sc_is_anon(r.sc) &&
             r.sc->state == CMT_P2P_SC_ST_WAIT_FIRST &&
             cmt_p2p_sc_recv(r.sc, o + 1, 1, &c) == CMT_OK && c == 1 &&
             r.sc->profile == &CMT_P2P_SC_PROFILE_CLIENT &&
             r.sc->state == CMT_P2P_SC_ST_WAIT_HELLO;
    }
    if (ok) PASS(); else FAIL("2-byte prefix of a CLIENT HELLO");
    side_free(&i);
    side_free(&r);
}

static void test_init_args(void)
{
    side_t s;
    cmt_p2p_sc_host_t host;
    bool ok;

    TEST("init: ANON refused by cmt_p2p_sc_init_profile; ANON entry points validate");
    ok = side_alloc(&s, g_a, 0) == CMT_OK;
    host = s.host;
    host.verify_kc = host_verify_kc;
    ok = ok &&
         cmt_p2p_sc_init_profile(s.sc, CMT_P2P_SC_ROLE_INITIATOR, &host, &CMT_P2P_SC_PROFILE_ANON,
                                 g_a->id.pk.bytes, NULL, NULL, PROTO_VER, CHAIN_A) == CMT_FAULT &&
         s.sc->state == CMT_P2P_SC_ST_DEAD &&
         /* initiator: no key of any kind, and verify_kc is required */
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_INITIATOR, &host, g_a->id.pk.bytes, NULL,
                              NULL, NULL, PROTO_VER, CHAIN_A) == CMT_FAULT &&
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_INITIATOR, &s.host, NULL, NULL, NULL, NULL,
                              PROTO_VER, CHAIN_A) == CMT_FAULT &&
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_INITIATOR, &host, NULL, NULL, NULL, g_a->kc,
                              PROTO_VER, CHAIN_A) == CMT_FAULT &&
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_INITIATOR, &host, NULL, NULL, NULL, NULL,
                              PROTO_VER, CHAIN_A) == CMT_OK &&
         s.sc->state == CMT_P2P_SC_ST_WAIT_HELLO_R && out_len(&s) == 70 &&
         /* responder: key, KEM pair and KC all required */
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_RESPONDER, &host, g_a->id.pk.bytes,
                              g_a->id.mlkem_pk, g_a->id.mlkem_sk, NULL, PROTO_VER, CHAIN_A) == CMT_FAULT &&
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_RESPONDER, &host, NULL, g_a->id.mlkem_pk,
                              g_a->id.mlkem_sk, g_a->kc, PROTO_VER, CHAIN_A) == CMT_FAULT &&
         cmt_p2p_sc_init_anon(s.sc, CMT_P2P_SC_ROLE_RESPONDER, &host, g_a->id.pk.bytes,
                              g_a->id.mlkem_pk, g_a->id.mlkem_sk, g_a->kc, PROTO_VER, CHAIN_A) == CMT_OK &&
         s.sc->state == CMT_P2P_SC_ST_WAIT_HELLO &&
         cmt_p2p_sc_init_anon(NULL, CMT_P2P_SC_ROLE_RESPONDER, &host, NULL, NULL, NULL, NULL,
                              PROTO_VER, CHAIN_A) == CMT_FAULT &&
         /* unbound: needs the CLIENT host and the key pair; the KC is optional */
         cmt_p2p_sc_init_responder_unbound(s.sc, &host, g_a->id.pk.bytes, g_a->id.mlkem_pk,
                                           g_a->id.mlkem_sk, NULL, PROTO_VER, CHAIN_A) == CMT_OK &&
         s.sc->state == CMT_P2P_SC_ST_WAIT_FIRST && s.sc->profile == NULL &&
         s.sc->local_kc_sig == NULL;
    {
        cmt_p2p_sc_host_t nosign = host;

        nosign.sign = NULL;
        ok = ok && cmt_p2p_sc_init_responder_unbound(s.sc, &nosign, g_a->id.pk.bytes,
                                                     g_a->id.mlkem_pk, g_a->id.mlkem_sk, g_a->kc,
                                                     PROTO_VER, CHAIN_A) == CMT_FAULT;
    }
    if (ok) PASS(); else FAIL("init argument validation");
    side_free(&s);
}

static void test_profile_strings(void)
{
    TEST("ANON profile strings are exactly design §1.1's, 25 / 24 / 29 bytes");
    if (strcmp(CMT_P2P_SC_PROFILE_ANON.transcript_tag, "nodus.asess.transcript.v1") == 0 &&
        strlen(CMT_P2P_SC_PROFILE_ANON.transcript_tag) == 25 &&
        strcmp(CMT_P2P_SC_PROFILE_ANON.info_aead, "nodus.asess.keys.v1/aead") == 0 &&
        strlen(CMT_P2P_SC_PROFILE_ANON.info_aead) == 24 &&
        strcmp(CMT_P2P_SC_PROFILE_ANON.info_challenge, "nodus.asess.keys.v1/challenge") == 0 &&
        strlen(CMT_P2P_SC_PROFILE_ANON.info_challenge) == 29 &&
        /* differs from the other families' tags at byte 6 only */
        CMT_P2P_SC_PROFILE_ANON.transcript_tag[6] == 'a' &&
        CMT_P2P_SC_PROFILE_CLIENT.transcript_tag[6] == 'c' &&
        CMT_P2P_SC_PROFILE_NODE.transcript_tag[6] == 'n' &&
        CMT_P2P_SC_PROFILE_WITNESS.transcript_tag[6] == 'w' &&
        memcmp(CMT_P2P_SC_PROFILE_ANON.transcript_tag, CMT_P2P_SC_PROFILE_CLIENT.transcript_tag, 6) == 0) {
        PASS();
    } else {
        FAIL("profile strings");
    }
}

int main(void)
{
    uint8_t seed[32];
    node_t **nodes[3];
    uint8_t base[3] = { 0xA1, 0xB2, 0xC3 };
    int k;

    printf("test_p2p_secret_anon — ANON session family (DHT v2 package 3d)\n");
    g_a = (node_t *)calloc(1, sizeof(node_t));
    g_b = (node_t *)calloc(1, sizeof(node_t));
    g_c = (node_t *)calloc(1, sizeof(node_t));
    if (g_a == NULL || g_b == NULL || g_c == NULL) {
        return 1;
    }
    nodes[0] = &g_a;
    nodes[1] = &g_b;
    nodes[2] = &g_c;
    for (k = 0; k < 3; k++) {
        fill(seed, sizeof(seed), base[k]);
        if (nodus_identity_from_seed(seed, &(*nodes[k])->id) != 0 ||
            !(*nodes[k])->id.has_mlkem) {
            printf("identity %d failed\n", k);
            return 1;
        }
        if (make_kc(*nodes[k], CHAIN_A, *nodes[k], (*nodes[k])->kc) != 0) {
            printf("kc %d failed\n", k);
            return 1;
        }
    }

    test_profile_strings();
    test_happy("ANON happy path: unbound responder, wire bytes, key and T recomputed", false, 0);
    test_happy("ANON happy path: ANON-bound responder", true, 0);
    test_happy("ANON happy path, 1-byte fragments both ways", false, 1);
    test_happy("ANON happy path, 7-byte fragments both ways", false, 7);
    test_t_differs_per_session();
    test_kc_variants();
    test_pin();
    test_job_kc_guard();
    test_confirm_cases();
    test_mismatches();
    test_refused_kinds();
    test_fragmented_first_prefix();
    test_init_args();

    free(g_a);
    free(g_b);
    free(g_c);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
