/**
 * @file nodus/tests/test_p2p_secret.c
 * @brief Tests for shared/dnac/cmt_p2p_secret — cometbft @709fd12b
 *        p2p/conn/secret_connection.go ported to C (fleet P2P-PORT, F1).
 *
 * Governing: docs/plans/decisions/2026-09-26-witness-port-session.md;
 * docs/plans/2026-09-26-witness-port-session-design.md §2.1, §2.3, §2R,
 * §2R3 N3/N9; docs/plans/2026-09-26-p2p-port-design.md §2 row 1, §5.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · handshake: two machines with REAL ML-DSA-87 + ML-KEM-1024 identities
 *     (nodus_identity_generate) reach AUTHENTICATED over an in-memory pipe,
 *     derive the same key, and each reports the other's pk — also when
 *     every byte arrives in odd fragments (1, 7, 1043, 1045), which is
 *     what the event loop sees and the reference's blocking ReadFull hides
 *     (TestSecretConnectionHandshake).
 *   · read/write: 100 writes each way of pseudo-random length in
 *     [1, 5 × 1024] come out byte-identical, each write is split into
 *     ceil(len / 1024) sealed frames of 1044 bytes, and a write of at
 *     most 1024 bytes is read in ONE chunk (TestSecretConnectionReadWrite,
 *     its compareWritesReads atomicity rule).
 *   · each of the ten wire-carried inputs of T (I_dsa_pk, nonce_I,
 *     proto_ver_I, chain_id_I, R_dsa_pk, R_mlkem_pk, nonce_R, proto_ver_R,
 *     chain_id_R, ct), flipped by one bit in transit, leaves both sides
 *     unauthenticated; a flipped proto_ver / chain_id is refused before
 *     either side issues a KEM job.
 *   · a proto_ver or chain_id mismatch is refused before any KEM job.
 *   · a second KEYX is an error; a wrong-length or wrong-kind handshake
 *     message is refused as soon as its length prefix is read.
 *   · a round-3 Kyber ciphertext, and a round-3 public key (advertised
 *     against an ML-KEM secret key, or decapsulated by a legacy round-3
 *     peer) never yield a session.
 *   · after the handshake: a replayed frame, a skipped frame and a frame
 *     reflected back to its sender are refused; a counter at UINT64_MAX
 *     refuses to seal and to open, and a multi-frame write that would
 *     cross it seals nothing.
 *   · an AUTHSIG signed by the wrong key, or signed RAW (no NDS1 0x0A
 *     tag), is refused; 0x0A is strict on its own (raw and 0x01-tagged
 *     signatures do not verify as 0x0A).
 *   · the caller's row-10 pin: the claimed pk is readable while ENCAPS is
 *     outstanding and an abort there emits no KEYX.
 *   · plaintext the machine HOLDS (recvBuffer; on a live connection the
 *     AUTHSIG frame's tail) is drained into the connection's pbuf by
 *     cmt_p2p_conn_fill_plain with rbuf EMPTY (Codex 7). The held bytes
 *     are produced here by a short read, not by a crafted AUTHSIG frame
 *     carrying a tail — the drain does not depend on their origin, but
 *     the AUTHSIG-tail producer itself is not driven.
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build (no compile
 * flags, no environment). WHAT IT LEAVES BEHIND: nothing (no files, no
 * sockets, no threads).
 *
 * HOW IT CAN LIE: the two machines run in one process and the jobs run
 * inline — the worker-thread path of R-P2P-8 is not exercised (F3 owns
 * it). The key-equality check reads the machines' public struct; a bug
 * that derived the same WRONG key on both sides would still pass here —
 * the transcript/KDF bytes are checked only for self-consistency, not
 * against an external vector (none exists for this substituted
 * construction). The pseudo-random lengths come from a fixed-seed LCG, so
 * the run is identical every time.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_secret.h"
#include "dnac/cmt_p2p_peer.h"   /* cmt_p2p_conn_fill_plain (Codex 7 case) */
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/enc/qgp_kyber.h"
#include "crypto/enc/qgp_mlkem.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>     /* seal_empty_frame: a frame no Write emits */

_Static_assert(CMT_P2P_SC_DSA_PK_SIZE == NODUS_PK_BYTES, "pk size");
_Static_assert(CMT_P2P_SC_SIG_SIZE == NODUS_SIG_BYTES, "sig size");
_Static_assert(CMT_P2P_SC_KEM_PK_SIZE == NODUS_MLKEM_PK_BYTES, "kem pk size");
_Static_assert(CMT_P2P_SC_KEM_SK_SIZE == NODUS_MLKEM_SK_BYTES, "kem sk size");
_Static_assert(CMT_P2P_SC_KEM_CT_SIZE == NODUS_MLKEM_CT_BYTES, "kem ct size");
_Static_assert(CMT_P2P_SC_KEM_SS_SIZE == NODUS_MLKEM_SS_BYTES, "kem ss size");

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
static const uint8_t CHAIN_B[32] = { 0x01 };

/* ══ identities and the host ═════════════════════════════════════════ */

typedef enum { SIGN_OK = 0, SIGN_WRONG_KEY, SIGN_RAW } sign_mode_t;

typedef struct {
    nodus_identity_t id;
    const nodus_identity_t *wrong;   /* SIGN_WRONG_KEY signs with this sk */
    sign_mode_t mode;
} node_t;

static int host_sign(void *ctx, const uint8_t *msg, size_t msg_len,
                     uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc;

    switch (n->mode) {
    case SIGN_WRONG_KEY:
        rc = nodus_sign_session_auth(&sig, msg, msg_len, &n->wrong->sk);
        break;
    case SIGN_RAW:
        rc = nodus_sign(&sig, msg, msg_len, &n->id.sk);
        break;
    case SIGN_OK:
    default:
        rc = nodus_sign_session_auth(&sig, msg, msg_len, &n->id.sk);
        break;
    }
    memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return rc;
}

static int host_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_session_auth(&sig, msg, msg_len, &pk);
}

/* Heap-allocated identities: generated once, reused by every case. */
static node_t *g_a;      /* plays the initiator */
static node_t *g_b;      /* plays the responder */
static node_t *g_c;      /* a third identity (wrong key) */

/* ══ a byte pipe ═════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *b;
    size_t len;
    size_t cap;
    uint64_t total;       /* bytes ever pushed — the stream offset */
} pipe_t;

static void pipe_init(pipe_t *p, size_t cap)
{
    p->b = (uint8_t *)malloc(cap);
    p->len = 0;
    p->cap = cap;
    p->total = 0;
}

static void pipe_free(pipe_t *p)
{
    free(p->b);
    p->b = NULL;
}

static int pipe_push(pipe_t *p, const uint8_t *b, size_t n)
{
    if (n > p->cap - p->len) {
        return -1;
    }
    memcpy(p->b + p->len, b, n);
    p->len += n;
    p->total += n;
    return 0;
}

static void pipe_pop(pipe_t *p, size_t n)
{
    if (n >= p->len) {
        p->len = 0;
        return;
    }
    memmove(p->b, p->b + n, p->len - n);
    p->len -= n;
}

/* ══ one side of a connection ════════════════════════════════════════ */

typedef int (*job_hook_t)(const cmt_p2p_sc_job_t *job,
                          const cmt_p2p_sc_host_t *host, void *arg);

typedef struct {
    cmt_p2p_sc_t *sc;
    cmt_p2p_sc_host_t host;
    node_t *node;
    job_hook_t hook;      /* NULL = cmt_p2p_sc_job_run */
    void *hook_arg;
    unsigned jobs_seen;   /* bit (1 << kind) for every job kind issued */
    int last_rc;
} side_t;

static int side_init(side_t *s, node_t *node, cmt_p2p_sc_role_t role,
                     const uint8_t *kem_pk, const uint8_t *kem_sk,
                     uint32_t proto_ver, const uint8_t chain[32])
{
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
        if (kem_pk == NULL) {
            kem_pk = node->id.mlkem_pk;
        }
        if (kem_sk == NULL) {
            kem_sk = node->id.mlkem_sk;
        }
    }
    return cmt_p2p_sc_init(s->sc, role, &s->host, node->id.pk.bytes,
                           kem_pk, kem_sk, proto_ver, chain);
}

static void side_free(side_t *s)
{
    if (s->sc != NULL) {
        cmt_p2p_sc_clear(s->sc);
        free(s->sc);
        s->sc = NULL;
    }
}

/** Run every outstanding job. @return 1 if any ran. */
static int side_run_jobs(side_t *s)
{
    int ran = 0;
    const cmt_p2p_sc_job_t *job;

    while ((job = cmt_p2p_sc_job(s->sc)) != NULL) {
        int jrc;

        s->jobs_seen |= 1u << job->kind;
        jrc = (s->hook != NULL) ? s->hook(job, &s->host, s->hook_arg)
                                : cmt_p2p_sc_job_run(job, &s->host);
        s->last_rc = cmt_p2p_sc_job_done(s->sc, jrc);
        ran = 1;
    }
    return ran;
}

/** Move `from`'s output into `pipe`, flipping one bit at stream offset
 *  `tamper` (UINT64_MAX = none). @return bytes moved. */
static size_t side_drain(side_t *from, pipe_t *pipe, uint64_t tamper)
{
    size_t n = 0;
    const uint8_t *o = cmt_p2p_sc_out(from->sc, &n);

    if (n == 0) {
        return 0;
    }
    if (pipe_push(pipe, o, n) != 0) {
        return 0;
    }
    if (tamper != UINT64_MAX && tamper >= pipe->total - n && tamper < pipe->total) {
        pipe->b[pipe->len - (size_t)(pipe->total - tamper)] ^= 0x01;
    }
    cmt_p2p_sc_out_consume(from->sc, n);
    return n;
}

static const size_t FRAG_ALL[] = { (size_t)-1 };
static const size_t FRAG_ODD[] = { 1, 7, 1043, 1045 };

/** Feed `to` from `pipe` in fragments cycling through `frag`. */
static size_t side_feed(side_t *to, pipe_t *pipe, const size_t *frag, size_t nfrag,
                        size_t *k)
{
    size_t total = 0;

    while (pipe->len > 0) {
        size_t want = frag[*k % nfrag];
        size_t n = (want < pipe->len) ? want : pipe->len;
        size_t c = 0;

        to->last_rc = cmt_p2p_sc_recv(to->sc, pipe->b, n, &c);
        (*k)++;
        pipe_pop(pipe, c);
        total += c;
        if (c == 0 || to->last_rc != CMT_OK) {
            break;
        }
    }
    return total;
}

typedef struct {
    const size_t *frag;
    size_t nfrag;
    uint64_t tamper_ir;   /* stream offset I→R to flip, UINT64_MAX none */
    uint64_t tamper_ri;   /* stream offset R→I to flip */
} drive_opts_t;

static void opts_default(drive_opts_t *o)
{
    o->frag = FRAG_ALL;
    o->nfrag = 1;
    o->tamper_ir = UINT64_MAX;
    o->tamper_ri = UINT64_MAX;
}

/** Shuttle bytes and run jobs until neither side makes progress. */
static void drive(side_t *i, side_t *r, pipe_t *ir, pipe_t *ri,
                  const drive_opts_t *o)
{
    size_t ki = 0, kr = 0;
    int guard;

    for (guard = 0; guard < 1000; guard++) {
        size_t moved = 0;

        moved += side_drain(i, ir, o->tamper_ir);
        moved += side_drain(r, ri, o->tamper_ri);
        moved += side_feed(r, ir, o->frag, o->nfrag, &kr);
        moved += (size_t)side_run_jobs(r);
        moved += side_feed(i, ri, o->frag, o->nfrag, &ki);
        moved += (size_t)side_run_jobs(i);
        moved += side_drain(i, ir, o->tamper_ir);
        moved += side_drain(r, ri, o->tamper_ri);
        if (moved == 0) {
            break;
        }
    }
}

/** A fresh authenticated pair over fresh pipes. @return 0 on success. */
static int make_pair(side_t *i, side_t *r, pipe_t *ir, pipe_t *ri)
{
    drive_opts_t o;

    pipe_init(ir, 1u << 20);
    pipe_init(ri, 1u << 20);
    if (side_init(i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A) != CMT_OK ||
        side_init(r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A) != CMT_OK) {
        return -1;
    }
    opts_default(&o);
    drive(i, r, ir, ri, &o);
    if (!cmt_p2p_sc_is_authenticated(i->sc) || !cmt_p2p_sc_is_authenticated(r->sc)) {
        return -1;
    }
    return (ir->len == 0 && ri->len == 0) ? 0 : -1;
}

static void free_pair(side_t *i, side_t *r, pipe_t *ir, pipe_t *ri)
{
    side_free(i);
    side_free(r);
    pipe_free(ir);
    pipe_free(ri);
}

static bool neither_authenticated(const side_t *i, const side_t *r)
{
    return !cmt_p2p_sc_is_authenticated(i->sc) && !cmt_p2p_sc_is_authenticated(r->sc);
}

#define KEM_JOBS ((1u << CMT_P2P_SC_JOB_ENCAPS) | (1u << CMT_P2P_SC_JOB_DECAPS))

/* ══ secret_connection_test.go:56-64 — TestSecretConnectionHandshake ═ */

static void test_handshake(const char *name, const size_t *frag, size_t nfrag)
{
    side_t i, r;
    pipe_t ir, ri;
    drive_opts_t o;
    bool ok;

    TEST(name);
    pipe_init(&ir, 1u << 20);
    pipe_init(&ri, 1u << 20);
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    opts_default(&o);
    o.frag = frag;
    o.nfrag = nfrag;
    drive(&i, &r, &ir, &ri, &o);

    ok = cmt_p2p_sc_is_authenticated(i.sc) && cmt_p2p_sc_is_authenticated(r.sc) &&
         memcmp(i.sc->key, r.sc->key, CMT_P2P_SC_AEAD_KEY_SIZE) == 0 &&
         cmt_p2p_sc_remote_pubkey(i.sc) != NULL &&
         memcmp(cmt_p2p_sc_remote_pubkey(i.sc), g_b->id.pk.bytes, NODUS_PK_BYTES) == 0 &&
         cmt_p2p_sc_remote_pubkey(r.sc) != NULL &&
         memcmp(cmt_p2p_sc_remote_pubkey(r.sc), g_a->id.pk.bytes, NODUS_PK_BYTES) == 0 &&
         i.jobs_seen == ((1u << CMT_P2P_SC_JOB_ENCAPS) | (1u << CMT_P2P_SC_JOB_SIGN) |
                         (1u << CMT_P2P_SC_JOB_VERIFY)) &&
         r.jobs_seen == ((1u << CMT_P2P_SC_JOB_DECAPS) | (1u << CMT_P2P_SC_JOB_SIGN) |
                         (1u << CMT_P2P_SC_JOB_VERIFY)) &&
         ir.len == 0 && ri.len == 0 &&
         i.sc->send_counter == 5 && i.sc->recv_counter == 5 &&
         r.sc->send_counter == 5 && r.sc->recv_counter == 5;
    if (ok) PASS(); else FAIL("session not established or not symmetric");
    free_pair(&i, &r, &ir, &ri);
}

/* ══ secret_connection_test.go:110-225 — TestSecretConnectionReadWrite ═ */

static uint64_t g_lcg;
static uint32_t lcg_next(void)
{
    g_lcg = g_lcg * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint32_t)(g_lcg >> 33);
}

#define RW_N 100

typedef struct {
    uint8_t *data[RW_N];
    size_t len[RW_N];
} writes_t;

static void gen_writes(writes_t *w)
{
    int k;
    size_t j;

    for (k = 0; k < RW_N; k++) {
        /* cmtrand.Int() % (dataMaxSize * 5) + 1 */
        w->len[k] = (size_t)(lcg_next() % (CMT_P2P_SC_DATA_MAX_SIZE * 5)) + 1;
        w->data[k] = (uint8_t *)malloc(w->len[k]);
        for (j = 0; j < w->len[k]; j++) {
            w->data[k][j] = (uint8_t)lcg_next();
        }
    }
}

static void free_writes(writes_t *w)
{
    int k;
    for (k = 0; k < RW_N; k++) {
        free(w->data[k]);
    }
}

/** Write every entry from `from` into `pipe`, checking the frame count. */
static int write_all(side_t *from, pipe_t *pipe, const writes_t *w)
{
    static uint8_t sealed[8 * CMT_P2P_SC_SEALED_FRAME_SIZE];
    int k;

    for (k = 0; k < RW_N; k++) {
        size_t out_len = 0;
        size_t frames = (w->len[k] + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE;

        if (cmt_p2p_sc_write(from->sc, w->data[k], w->len[k], sealed, sizeof(sealed),
                             &out_len) != CMT_OK ||
            out_len != frames * CMT_P2P_SC_SEALED_FRAME_SIZE ||
            pipe_push(pipe, sealed, out_len) != 0) {
            return -1;
        }
    }
    return 0;
}

/** Read everything from `pipe` into `to` with a 1024-byte buffer and
 *  compare to `w` — compareWritesReads (:194-221): the concatenation is
 *  the same, and a write of <= dataMaxSize is exactly one read. */
static int read_compare(side_t *to, pipe_t *pipe, const writes_t *w)
{
    uint8_t buf[CMT_P2P_SC_DATA_MAX_SIZE];
    int k = 0;
    size_t off = 0;           /* bytes of w[k] matched so far */

    while (k < RW_N) {
        size_t c = 0, n = 0;
        int rc = cmt_p2p_sc_read(to->sc, pipe->b, pipe->len, &c, buf, sizeof(buf), &n);

        pipe_pop(pipe, c);
        if (rc != CMT_OK) {
            return -1;
        }
        if (n == 0) {
            if (c == 0) {
                return -1;    /* stalled with writes left */
            }
            continue;
        }
        if (w->len[k] <= CMT_P2P_SC_DATA_MAX_SIZE && (off != 0 || n != w->len[k])) {
            return -1;        /* small write not read atomically */
        }
        if (n > w->len[k] - off || memcmp(buf, w->data[k] + off, n) != 0) {
            return -1;
        }
        off += n;
        if (off == w->len[k]) {
            k++;
            off = 0;
        }
    }
    return pipe->len == 0 ? 0 : -1;
}

static void test_read_write(void)
{
    side_t i, r;
    pipe_t ir, ri;
    writes_t wi, wr;
    bool ok;

    TEST("ReadWrite: 100 writes each way, 1..5*1024 bytes, frames + atomicity");
    g_lcg = 0x5ec2e7c0u;      /* fixed seed: the same lengths every run */
    gen_writes(&wi);
    gen_writes(&wr);
    ok = make_pair(&i, &r, &ir, &ri) == 0 &&
         write_all(&i, &ir, &wi) == 0 &&
         write_all(&r, &ri, &wr) == 0 &&
         read_compare(&r, &ir, &wi) == 0 &&
         read_compare(&i, &ri, &wr) == 0;
    if (ok) PASS(); else FAIL("bytes differ, frame count wrong or small write split");
    free_writes(&wi);
    free_writes(&wr);
    free_pair(&i, &r, &ir, &ri);
}

static void test_frame_boundaries(void)
{
    side_t i, r;
    pipe_t ir, ri;
    uint8_t data[2 * CMT_P2P_SC_DATA_MAX_SIZE + 1];
    static uint8_t sealed[4 * CMT_P2P_SC_SEALED_FRAME_SIZE];
    size_t l1024 = 0, l1025 = 0, l0 = 0, small = 0;
    bool ok;

    TEST("Write: 0 -> nothing, 1024 -> 1 frame, 1025 -> 2, cap too small");
    memset(data, 0xa5, sizeof(data));
    ok = make_pair(&i, &r, &ir, &ri) == 0 &&
         cmt_p2p_sc_write(i.sc, data, 0, sealed, sizeof(sealed), &l0) == CMT_OK && l0 == 0 &&
         cmt_p2p_sc_write(i.sc, data, 1024, sealed, sizeof(sealed), &l1024) == CMT_OK &&
         l1024 == CMT_P2P_SC_SEALED_FRAME_SIZE &&
         cmt_p2p_sc_write(i.sc, data, 1025, sealed, sizeof(sealed), &l1025) == CMT_OK &&
         l1025 == 2 * CMT_P2P_SC_SEALED_FRAME_SIZE &&
         /* a too-small buffer seals nothing and leaves the session alive */
         cmt_p2p_sc_write(i.sc, data, 1025, sealed, CMT_P2P_SC_SEALED_FRAME_SIZE,
                          &small) == CMT_FAULT && small == 0 &&
         i.sc->send_counter == 5 + 3 && cmt_p2p_sc_is_authenticated(i.sc);
    if (ok) PASS(); else FAIL("frame split or capacity rule wrong");
    free_pair(&i, &r, &ir, &ri);
}

/* ══ tampered T inputs ═══════════════════════════════════════════════ */

/* Stream offsets (uvarint prefixes are 2 bytes for every body here). */
#define PFX 2
#define OFF_HELLO_I_PK   (PFX + 1)
#define OFF_HELLO_NONCE  (OFF_HELLO_I_PK + CMT_P2P_SC_DSA_PK_SIZE)
#define OFF_HELLO_PV     (OFF_HELLO_NONCE + CMT_P2P_SC_NONCE_SIZE)
#define OFF_HELLO_CHAIN  (OFF_HELLO_PV + CMT_P2P_SC_PROTO_VER_SIZE)
#define HELLO_WIRE       (PFX + CMT_P2P_SC_HELLO_BODY)
#define OFF_KEYX_CT      (HELLO_WIRE + PFX + 1)
#define OFF_HR_R_PK      (PFX + 1)
#define OFF_HR_KEM_PK    (OFF_HR_R_PK + CMT_P2P_SC_DSA_PK_SIZE)
#define OFF_HR_NONCE     (OFF_HR_KEM_PK + CMT_P2P_SC_KEM_PK_SIZE)
#define OFF_HR_PV        (OFF_HR_NONCE + CMT_P2P_SC_NONCE_SIZE)
#define OFF_HR_CHAIN     (OFF_HR_PV + CMT_P2P_SC_PROTO_VER_SIZE)

_Static_assert(CMT_P2P_SC_HELLO_BODY >= 128 && CMT_P2P_SC_HELLO_BODY < 16384 &&
               CMT_P2P_SC_HELLO_R_BODY < 16384 && CMT_P2P_SC_KEYX_BODY >= 128 &&
               CMT_P2P_SC_KEYX_BODY < 16384, "every prefix is 2 bytes");

typedef struct {
    const char *name;
    int dir;               /* 0 = I→R, 1 = R→I */
    uint64_t off;          /* first byte of the field (+ a middle byte) */
    bool before_kem;       /* must be refused before any KEM job */
} tamper_t;

static void test_tamper(void)
{
    static const tamper_t cases[] = {
        { "I_dsa_pk",    0, OFF_HELLO_I_PK + 100,  false },
        { "nonce_I",     0, OFF_HELLO_NONCE + 5,   false },
        { "proto_ver_I", 0, OFF_HELLO_PV + 3,      true  },
        { "chain_id_I",  0, OFF_HELLO_CHAIN + 7,   true  },
        { "ct",          0, OFF_KEYX_CT + 200,     false },
        { "R_dsa_pk",    1, OFF_HR_R_PK + 100,     false },
        { "R_mlkem_pk",  1, OFF_HR_KEM_PK + 1540,  false },   /* in rho */
        { "nonce_R",     1, OFF_HR_NONCE + 5,      false },
        { "proto_ver_R", 1, OFF_HR_PV + 3,         true  },
        { "chain_id_R",  1, OFF_HR_CHAIN + 7,      true  },
    };
    size_t c;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        side_t i, r;
        pipe_t ir, ri;
        drive_opts_t o;
        char name[96];
        bool ok;

        snprintf(name, sizeof(name), "tampered %s in transit -> no session%s",
                 cases[c].name, cases[c].before_kem ? ", no KEM job" : "");
        TEST(name);
        pipe_init(&ir, 1u << 20);
        pipe_init(&ri, 1u << 20);
        side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
        side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
        opts_default(&o);
        if (cases[c].dir == 0) {
            o.tamper_ir = cases[c].off;
        } else {
            o.tamper_ri = cases[c].off;
        }
        drive(&i, &r, &ir, &ri, &o);

        ok = neither_authenticated(&i, &r) &&
             (i.sc->state == CMT_P2P_SC_ST_DEAD || r.sc->state == CMT_P2P_SC_ST_DEAD);
        if (cases[c].before_kem) {
            ok = ok && ((i.jobs_seen | r.jobs_seen) & KEM_JOBS) == 0;
        }
        if (ok) PASS(); else FAIL("session established or KEM ran on a refused field");
        free_pair(&i, &r, &ir, &ri);
    }
}

/* ══ proto_ver / chain id mismatch ═══════════════════════════════════ */

static void test_mismatch(const char *name, uint32_t pv_i, const uint8_t *ch_i,
                          uint32_t pv_r, const uint8_t *ch_r)
{
    side_t i, r;
    pipe_t ir, ri;
    drive_opts_t o;
    bool ok;

    TEST(name);
    pipe_init(&ir, 1u << 20);
    pipe_init(&ri, 1u << 20);
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, pv_i, ch_i);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, pv_r, ch_r);
    opts_default(&o);
    drive(&i, &r, &ir, &ri, &o);
    ok = neither_authenticated(&i, &r) && r.sc->state == CMT_P2P_SC_ST_DEAD &&
         ((i.jobs_seen | r.jobs_seen) & KEM_JOBS) == 0 &&
         r.jobs_seen == 0;
    if (ok) PASS(); else FAIL("mismatch not refused before KEM");
    free_pair(&i, &r, &ir, &ri);
}

/* ══ KEYX twice; wrong-length / wrong-kind messages ══════════════════ */

static void test_keyx_twice(void)
{
    side_t i, r;
    uint8_t *keyx = (uint8_t *)malloc(2 * (PFX + CMT_P2P_SC_KEYX_BODY));
    const uint8_t *o;
    size_t n = 0, c = 0, klen = PFX + CMT_P2P_SC_KEYX_BODY;
    bool ok = keyx != NULL;

    TEST("KEYX twice -> second one is an error, no session on R");
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);

    /* HELLO → R, HELLO_R → I */
    o = cmt_p2p_sc_out(i.sc, &n);
    ok = ok && cmt_p2p_sc_recv(r.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(i.sc, n);
    o = cmt_p2p_sc_out(r.sc, &n);
    ok = ok && cmt_p2p_sc_recv(i.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(r.sc, n);

    /* I: Encaps → KEYX queued, SIGN outstanding (not run: KEYX alone out) */
    ok = ok && cmt_p2p_sc_job(i.sc) != NULL &&
         cmt_p2p_sc_job(i.sc)->kind == CMT_P2P_SC_JOB_ENCAPS &&
         cmt_p2p_sc_job_done(i.sc, cmt_p2p_sc_job_run(cmt_p2p_sc_job(i.sc), &i.host)) == CMT_OK;
    o = cmt_p2p_sc_out(i.sc, &n);
    ok = ok && n == klen;
    if (ok) {
        memcpy(keyx, o, klen);
        memcpy(keyx + klen, o, klen);
    }

    /* R takes exactly one KEYX and holds */
    ok = ok && cmt_p2p_sc_recv(r.sc, keyx, 2 * klen, &c) == CMT_OK && c == klen &&
         cmt_p2p_sc_job(r.sc) != NULL &&
         cmt_p2p_sc_job(r.sc)->kind == CMT_P2P_SC_JOB_DECAPS;
    /* while Decaps is outstanding nothing more is consumed (HOLD) */
    ok = ok && cmt_p2p_sc_recv(r.sc, keyx + klen, klen, &c) == CMT_OK && c == 0;
    side_run_jobs(&r);                                    /* Decaps + Sign */
    ok = ok && r.sc->state == CMT_P2P_SC_ST_WAIT_AUTHSIG;
    /* the second KEYX now: refused */
    ok = ok && cmt_p2p_sc_recv(r.sc, keyx + klen, klen, &c) == CMT_REJECT &&
         r.sc->state == CMT_P2P_SC_ST_DEAD && !cmt_p2p_sc_is_authenticated(r.sc);
    if (ok) PASS(); else FAIL("second KEYX accepted or not refused");
    free(keyx);
    side_free(&i);
    side_free(&r);
}

/*
 * Seal ONE frame whose chunk length is 0 (an EMPTY frame) under `sc`'s
 * key with the nonce of the PEER role at `counter` — the frame a hostile
 * peer would send. cmt_p2p_sc_write never emits one (a zero-length Write
 * writes nothing, secret_connection.go:199's loop; test_frame_boundaries),
 * so the test seals it itself, with the layout cmt_p2p_secret.c
 * sc_seal_frame / sc_nonce use: frame = u32 LE chunk length ‖ zero pad
 * (1028 bytes), nonce = role ‖ 00 00 00 ‖ counter u64 BE, AES-256-GCM,
 * tag appended. @return 0 or -1.
 */
static int seal_empty_frame(const cmt_p2p_sc_t *sc, uint8_t role, uint64_t counter,
                            uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE])
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    uint8_t nonce[CMT_P2P_SC_AEAD_NONCE_SIZE];
    EVP_CIPHER_CTX *ctx;
    int len = 0, ok = 0, k;

    memset(frame, 0, sizeof(frame));                 /* chunk length 0 */
    memset(nonce, 0, sizeof(nonce));
    nonce[0] = role;
    for (k = 0; k < 8; k++) {
        nonce[4 + k] = (uint8_t)(counter >> (56 - 8 * k));
    }
    ctx = EVP_CIPHER_CTX_new();
    if (ctx != NULL &&
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CMT_P2P_SC_AEAD_NONCE_SIZE, NULL) == 1 &&
        EVP_EncryptInit_ex(ctx, NULL, NULL, sc->key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, sealed, &len, frame, (int)sizeof(frame)) == 1 &&
        len == (int)sizeof(frame) &&
        EVP_EncryptFinal_ex(ctx, sealed + len, &len) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, CMT_P2P_SC_AEAD_OVERHEAD,
                            sealed + CMT_P2P_SC_TOTAL_FRAME_SIZE) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/*
 * red-team Z1 F14 — an EMPTY sealed frame before the AUTHSIG closes the
 * connection. R is taken to WAIT_AUTHSIG (HELLO, HELLO_R, KEYX; its
 * Decaps + Sign run), then handed a VALID sealed frame — right key,
 * right nonce, right counter — whose chunk is empty: R refuses it and is
 * DEAD, never authenticated. That the frame itself is valid (so the
 * refusal is for its emptiness, not a failed open) is shown by R's
 * recv_counter: it advanced past the frame, which happens only after a
 * successful open (sc_open_frame). RED before the fix: CMT_OK, R still
 * waiting, the frame silently consumed (and any number more after it).
 */
static void test_empty_frame_before_authsig(void)
{
    side_t i, r;
    static uint8_t empty[CMT_P2P_SC_SEALED_FRAME_SIZE];
    const uint8_t *o;
    size_t n = 0, c = 0, klen = PFX + CMT_P2P_SC_KEYX_BODY;
    uint64_t rc0;
    bool ok = true;

    TEST("empty sealed frame before AUTHSIG -> connection closed");
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);

    /* HELLO → R, HELLO_R → I */
    o = cmt_p2p_sc_out(i.sc, &n);
    ok = ok && cmt_p2p_sc_recv(r.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(i.sc, n);
    o = cmt_p2p_sc_out(r.sc, &n);
    ok = ok && cmt_p2p_sc_recv(i.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(r.sc, n);
    /* I: Encaps → KEYX; R takes it, Decaps + Sign → WAIT_AUTHSIG */
    ok = ok && cmt_p2p_sc_job(i.sc) != NULL &&
         cmt_p2p_sc_job(i.sc)->kind == CMT_P2P_SC_JOB_ENCAPS &&
         cmt_p2p_sc_job_done(i.sc, cmt_p2p_sc_job_run(cmt_p2p_sc_job(i.sc), &i.host)) == CMT_OK;
    o = cmt_p2p_sc_out(i.sc, &n);
    ok = ok && n >= klen && cmt_p2p_sc_recv(r.sc, o, klen, &c) == CMT_OK && c == klen;
    side_run_jobs(&r);
    ok = ok && r.sc->state == CMT_P2P_SC_ST_WAIT_AUTHSIG;
    rc0 = r.sc->recv_counter;
    ok = ok && seal_empty_frame(r.sc, (uint8_t)CMT_P2P_SC_ROLE_INITIATOR, rc0,
                                empty) == 0;
    ok = ok && cmt_p2p_sc_recv(r.sc, empty, sizeof(empty), &c) == CMT_REJECT &&
         r.sc->recv_counter == rc0 + 1 &&        /* it opened: a valid frame */
         r.sc->state == CMT_P2P_SC_ST_DEAD && !cmt_p2p_sc_is_authenticated(r.sc);
    if (ok) PASS(); else FAIL("an empty pre-AUTHSIG frame was accepted");
    side_free(&i);
    side_free(&r);
}

static void test_bad_length_and_kind(void)
{
    side_t r, r2;
    uint8_t bad_len[2] = { 0, 0 };
    uint8_t wrong_kind[PFX + CMT_P2P_SC_HELLO_BODY];
    size_t c = 0;
    bool ok;

    TEST("wrong length prefix / wrong kind -> refused, no KEM job");
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r2, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    /* uvarint(HELLO_BODY - 1): refused after the 2 prefix bytes */
    bad_len[0] = (uint8_t)(((CMT_P2P_SC_HELLO_BODY - 1) & 0x7f) | 0x80);
    bad_len[1] = (uint8_t)((CMT_P2P_SC_HELLO_BODY - 1) >> 7);
    ok = cmt_p2p_sc_recv(r.sc, bad_len, 2, &c) == CMT_REJECT && c == 2 &&
         r.sc->state == CMT_P2P_SC_ST_DEAD;
    /* right length, KEYX kind byte where HELLO is expected */
    memset(wrong_kind, 0, sizeof(wrong_kind));
    wrong_kind[0] = (uint8_t)((CMT_P2P_SC_HELLO_BODY & 0x7f) | 0x80);
    wrong_kind[1] = (uint8_t)(CMT_P2P_SC_HELLO_BODY >> 7);
    wrong_kind[2] = CMT_P2P_SC_MSG_KEYX;
    ok = ok && cmt_p2p_sc_recv(r2.sc, wrong_kind, sizeof(wrong_kind), &c) == CMT_REJECT &&
         r2.sc->state == CMT_P2P_SC_ST_DEAD && cmt_p2p_sc_job(r2.sc) == NULL;
    if (ok) PASS(); else FAIL("malformed handshake message accepted");
    side_free(&r);
    side_free(&r2);
}

/* ══ round-3 Kyber: ciphertext and public key ════════════════════════ */

/** I's Encaps done with the ROUND-3 API against R's ML-KEM key. */
static int hook_r3_encaps(const cmt_p2p_sc_job_t *job,
                          const cmt_p2p_sc_host_t *host, void *arg)
{
    (void)arg;
    if (job->kind == CMT_P2P_SC_JOB_ENCAPS) {
        return qgp_kem1024_encapsulate(job->kem_ct_out, job->kem_ss_out, job->kem_pk);
    }
    return cmt_p2p_sc_job_run(job, host);
}

/** R is a legacy round-3 peer: Decaps with the round-3 API + kyber_sk. */
static int hook_r3_decaps(const cmt_p2p_sc_job_t *job,
                          const cmt_p2p_sc_host_t *host, void *arg)
{
    const node_t *n = (const node_t *)arg;

    if (job->kind == CMT_P2P_SC_JOB_DECAPS) {
        return qgp_kem1024_decapsulate(job->kem_ss_out, job->kem_ct, n->id.kyber_sk);
    }
    return cmt_p2p_sc_job_run(job, host);
}

typedef enum { R3_CT = 0, R3_PK_MLKEM_SK, R3_PK_LEGACY_PEER } r3_case_t;

static void test_round3(const char *name, r3_case_t which)
{
    side_t i, r;
    pipe_t ir, ri;
    drive_opts_t o;
    bool ok;

    TEST(name);
    pipe_init(&ir, 1u << 20);
    pipe_init(&ri, 1u << 20);
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    if (which == R3_CT) {
        side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
        i.hook = hook_r3_encaps;
    } else {
        /* R advertises its ROUND-3 public key as R_mlkem_pk */
        side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, g_b->id.kyber_pk,
                  g_b->id.mlkem_sk, PROTO_VER, CHAIN_A);
        if (which == R3_PK_LEGACY_PEER) {
            r.hook = hook_r3_decaps;
            r.hook_arg = g_b;
        }
    }
    opts_default(&o);
    drive(&i, &r, &ir, &ri, &o);
    /* Both sides reached AUTHSIG and failed to open the peer's frames. */
    ok = neither_authenticated(&i, &r) &&
         i.sc->state == CMT_P2P_SC_ST_DEAD && r.sc->state == CMT_P2P_SC_ST_DEAD &&
         (i.jobs_seen & (1u << CMT_P2P_SC_JOB_VERIFY)) == 0 &&
         (r.jobs_seen & (1u << CMT_P2P_SC_JOB_VERIFY)) == 0;
    if (ok) PASS(); else FAIL("a round-3 KEM input produced a session");
    free_pair(&i, &r, &ir, &ri);
}

/* ══ counters: replay, gap, reflection, overflow ═════════════════════ */

static int seal_one(side_t *s, uint8_t byte, uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE])
{
    size_t out_len = 0;
    int rc = cmt_p2p_sc_write(s->sc, &byte, 1, sealed, CMT_P2P_SC_SEALED_FRAME_SIZE, &out_len);
    return (rc == CMT_OK && out_len == CMT_P2P_SC_SEALED_FRAME_SIZE) ? 0 : -1;
}

static int open_one(side_t *s, const uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE],
                    uint8_t *byte_out)
{
    size_t c = 0, n = 0;
    int rc = cmt_p2p_sc_read(s->sc, sealed, CMT_P2P_SC_SEALED_FRAME_SIZE, &c,
                             byte_out, 1, &n);
    if (rc != CMT_OK) {
        return rc;
    }
    return (c == CMT_P2P_SC_SEALED_FRAME_SIZE && n == 1) ? CMT_OK : CMT_FAULT;
}

/*
 * Codex 7 — plaintext the secret connection HOLDS (its recvBuffer,
 * secret_connection.go:236-241) is drained into the connection's `pbuf`
 * by cmt_p2p_conn_fill_plain even when no wire byte waits in `rbuf`. On
 * a live connection that plaintext is the tail of the frame that
 * completed the AUTHSIG (typically the start of the peer's NodeInfo) —
 * and no later frame need ever come to push it out. Here it is produced
 * by a SHORT read instead (10 of a 100-byte chunk; the other 90 stay
 * held): the drain reads cmt_p2p_sc_read_pending, not where the bytes
 * came from. RED before the fix: the loop ran only while rbuf held
 * bytes, pbuf stayed empty and the 90 bytes were never delivered.
 */
static void test_fill_plain_drains_held(void)
{
    static uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE];
    uint8_t data[100], head[10];
    side_t i, r;
    pipe_t ir, ri;
    cmt_p2p_conn_t *c = NULL;
    size_t k, olen = 0, used = 0, n = 0;
    bool ok;

    TEST("held plaintext (AUTHSIG tail) is drained with an empty rbuf");
    for (k = 0; k < sizeof(data); k++) {
        data[k] = (uint8_t)(k * 7u + 3u);
    }
    ok = make_pair(&i, &r, &ir, &ri) == 0;
    ok = ok && cmt_p2p_sc_write(i.sc, data, sizeof(data), sealed, sizeof(sealed),
                                &olen) == CMT_OK && olen == sizeof(sealed);
    ok = ok && cmt_p2p_sc_read(r.sc, sealed, olen, &used, head, sizeof(head),
                               &n) == CMT_OK && used == olen && n == sizeof(head);
    ok = ok && memcmp(head, data, sizeof(head)) == 0;
    ok = ok && cmt_p2p_sc_read_pending(r.sc) == sizeof(data) - sizeof(head);
    if (ok) {
        c = cmt_p2p_conn_new();
        ok = c != NULL;
    }
    if (ok) {
        /* the connection takes over R's authenticated machine; rbuf is
         * EMPTY — nothing more arrives from the wire */
        memcpy(c->sc, r.sc, sizeof(*c->sc));
        ok = c->rbuf_len == 0 && cmt_p2p_conn_fill_plain(c) == CMT_OK;
        ok = ok && c->pbuf_len == sizeof(data) - sizeof(head) &&
             memcmp(c->pbuf, data + sizeof(head), c->pbuf_len) == 0 &&
             cmt_p2p_sc_read_pending(c->sc) == 0;
    }
    cmt_p2p_conn_free(c);                   /* zeroes the copied keys too */
    free_pair(&i, &r, &ir, &ri);
    if (ok) PASS(); else FAIL("held plaintext was not drained into pbuf");
}

static void test_counters(void)
{
    static uint8_t f1[CMT_P2P_SC_SEALED_FRAME_SIZE], f2[CMT_P2P_SC_SEALED_FRAME_SIZE];
    side_t i, r;
    pipe_t ir, ri;
    uint8_t b = 0;
    bool ok;

    TEST("replayed frame -> refused");
    ok = make_pair(&i, &r, &ir, &ri) == 0 && seal_one(&i, 0x11, f1) == 0 &&
         open_one(&r, f1, &b) == CMT_OK && b == 0x11 &&
         open_one(&r, f1, &b) == CMT_REJECT && r.sc->state == CMT_P2P_SC_ST_DEAD;
    if (ok) PASS(); else FAIL("replay accepted");
    free_pair(&i, &r, &ir, &ri);

    TEST("skipped frame (gap) -> refused");
    ok = make_pair(&i, &r, &ir, &ri) == 0 && seal_one(&i, 0x11, f1) == 0 &&
         seal_one(&i, 0x22, f2) == 0 &&
         open_one(&r, f2, &b) == CMT_REJECT && r.sc->state == CMT_P2P_SC_ST_DEAD;
    if (ok) PASS(); else FAIL("gap accepted");
    free_pair(&i, &r, &ir, &ri);

    TEST("frame reflected to its sender (own role) -> refused");
    ok = make_pair(&i, &r, &ir, &ri) == 0 &&
         /* I's frame #5 back into I, whose recv counter is also 5 */
         seal_one(&i, 0x33, f1) == 0 && i.sc->recv_counter == 5 &&
         open_one(&i, f1, &b) == CMT_REJECT && i.sc->state == CMT_P2P_SC_ST_DEAD;
    if (ok) PASS(); else FAIL("reflection accepted");
    free_pair(&i, &r, &ir, &ri);

    TEST("in-order frames after the handshake -> accepted");
    ok = make_pair(&i, &r, &ir, &ri) == 0 && seal_one(&i, 0x11, f1) == 0 &&
         seal_one(&i, 0x22, f2) == 0 &&
         open_one(&r, f1, &b) == CMT_OK && b == 0x11 &&
         open_one(&r, f2, &b) == CMT_OK && b == 0x22;
    if (ok) PASS(); else FAIL("in-order frames refused");
    free_pair(&i, &r, &ir, &ri);
}

static void test_overflow(void)
{
    static uint8_t f1[CMT_P2P_SC_SEALED_FRAME_SIZE];
    static uint8_t two[2 * CMT_P2P_SC_SEALED_FRAME_SIZE];
    uint8_t data[2 * CMT_P2P_SC_DATA_MAX_SIZE];
    side_t i, r;
    pipe_t ir, ri;
    size_t out_len = 1;
    uint8_t b = 0;
    bool ok;

    memset(data, 0x5a, sizeof(data));

    TEST("send counter at UINT64_MAX -> refuses to seal");
    ok = make_pair(&i, &r, &ir, &ri) == 0;
    if (ok) {
        i.sc->send_counter = UINT64_MAX;
    }
    ok = ok && cmt_p2p_sc_write(i.sc, data, 1, f1, sizeof(f1), &out_len) == CMT_REJECT &&
         out_len == 0 && i.sc->state == CMT_P2P_SC_ST_DEAD;
    if (ok) PASS(); else FAIL("sealed at UINT64_MAX");
    free_pair(&i, &r, &ir, &ri);

    TEST("UINT64_MAX-1: one frame goes, the next is refused");
    ok = make_pair(&i, &r, &ir, &ri) == 0;
    if (ok) {
        i.sc->send_counter = UINT64_MAX - 1;
        r.sc->recv_counter = UINT64_MAX - 1;
    }
    ok = ok && seal_one(&i, 0x44, f1) == 0 && open_one(&r, f1, &b) == CMT_OK && b == 0x44 &&
         i.sc->send_counter == UINT64_MAX &&
         cmt_p2p_sc_write(i.sc, data, 1, f1, sizeof(f1), &out_len) == CMT_REJECT;
    if (ok) PASS(); else FAIL("counter limit not enforced");
    free_pair(&i, &r, &ir, &ri);

    TEST("multi-frame write crossing UINT64_MAX -> nothing sealed");
    ok = make_pair(&i, &r, &ir, &ri) == 0;
    if (ok) {
        i.sc->send_counter = UINT64_MAX - 1;
    }
    out_len = 1;
    ok = ok && cmt_p2p_sc_write(i.sc, data, sizeof(data), two, sizeof(two),
                                &out_len) == CMT_REJECT &&
         out_len == 0 && i.sc->send_counter == UINT64_MAX - 1;
    if (ok) PASS(); else FAIL("partial write sealed");
    free_pair(&i, &r, &ir, &ri);

    TEST("recv counter at UINT64_MAX -> refuses to open");
    ok = make_pair(&i, &r, &ir, &ri) == 0 && seal_one(&i, 0x55, f1) == 0;
    if (ok) {
        r.sc->recv_counter = UINT64_MAX;
    }
    ok = ok && open_one(&r, f1, &b) == CMT_REJECT && r.sc->state == CMT_P2P_SC_ST_DEAD;
    if (ok) PASS(); else FAIL("opened at UINT64_MAX");
    free_pair(&i, &r, &ir, &ri);
}

/* ══ AUTHSIG verify failure; 0x0A strictness ═════════════════════════ */

static void test_authsig(const char *name, sign_mode_t mode)
{
    side_t i, r;
    pipe_t ir, ri;
    drive_opts_t o;
    bool ok;

    TEST(name);
    pipe_init(&ir, 1u << 20);
    pipe_init(&ri, 1u << 20);
    g_a->mode = mode;
    g_a->wrong = &g_c->id;
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    opts_default(&o);
    drive(&i, &r, &ir, &ri, &o);
    /* R verified I's AUTHSIG and refused it. (I verified R's: in the
     * reference too each side decides for itself, :178.) */
    ok = !cmt_p2p_sc_is_authenticated(r.sc) && r.sc->state == CMT_P2P_SC_ST_DEAD &&
         (r.jobs_seen & (1u << CMT_P2P_SC_JOB_VERIFY)) != 0;
    if (ok) PASS(); else FAIL("bad AUTHSIG authenticated the session");
    g_a->mode = SIGN_OK;
    g_a->wrong = NULL;
    free_pair(&i, &r, &ir, &ri);
}

static void test_purpose_strict(void)
{
    uint8_t ch[32];
    nodus_sig_t raw, auth, sess;
    bool ok;

    TEST("0x0A strict: raw / 0x01 signatures refused, 0x0A accepted");
    memset(ch, 0x3c, sizeof(ch));
    ok = nodus_sign_purpose_is_strict(NODUS_PURPOSE_SESSION_AUTH) &&
         nodus_sign_purpose_is_strict(NODUS_PURPOSE_WITNESS_ADDR) &&
         nodus_sign(&raw, ch, sizeof(ch), &g_a->id.sk) == 0 &&
         nodus_sign_auth_challenge(&auth, ch, &g_a->id.sk) == 0 &&
         nodus_sign_session_auth(&sess, ch, sizeof(ch), &g_a->id.sk) == 0 &&
         nodus_verify_session_auth(&raw, ch, sizeof(ch), &g_a->id.pk) != 0 &&
         nodus_verify_session_auth(&auth, ch, sizeof(ch), &g_a->id.pk) != 0 &&
         nodus_verify_session_auth(&sess, ch, sizeof(ch), &g_a->id.pk) == 0 &&
         nodus_verify_auth_challenge(&sess, ch, &g_a->id.pk) != 0 &&
         nodus_verify_witness_addr(&sess, ch, sizeof(ch), &g_a->id.pk) != 0;
    if (ok) PASS(); else FAIL("0x0A accepted a foreign-domain signature");
}

/* ══ caller pin (row 10), write/read before authentication ═══════════ */

static void test_pin_abort_and_early_io(void)
{
    side_t i, r;
    const uint8_t *o;
    size_t n = 0, c = 0, out_len = 0, rn = 0;
    uint8_t buf[CMT_P2P_SC_SEALED_FRAME_SIZE];
    bool ok;

    TEST("pin: claimed pk visible at ENCAPS, abort there emits no KEYX");
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_c, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    ok = cmt_p2p_sc_remote_pubkey(i.sc) == NULL;
    o = cmt_p2p_sc_out(i.sc, &n);
    ok = ok && cmt_p2p_sc_recv(r.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(i.sc, n);
    o = cmt_p2p_sc_out(r.sc, &n);
    ok = ok && cmt_p2p_sc_recv(i.sc, o, n, &c) == CMT_OK && c == n;
    cmt_p2p_sc_out_consume(r.sc, n);
    /* The dialer expected g_b; the responder is g_c → the caller aborts. */
    ok = ok && cmt_p2p_sc_job(i.sc) != NULL &&
         cmt_p2p_sc_job(i.sc)->kind == CMT_P2P_SC_JOB_ENCAPS &&
         cmt_p2p_sc_remote_pubkey(i.sc) != NULL &&
         memcmp(cmt_p2p_sc_remote_pubkey(i.sc), g_c->id.pk.bytes, NODUS_PK_BYTES) == 0 &&
         memcmp(cmt_p2p_sc_remote_pubkey(i.sc), g_b->id.pk.bytes, NODUS_PK_BYTES) != 0;
    cmt_p2p_sc_abort(i.sc);
    (void)cmt_p2p_sc_out(i.sc, &n);
    ok = ok && n == 0 && cmt_p2p_sc_job(i.sc) == NULL &&
         cmt_p2p_sc_job_done(i.sc, 0) == CMT_REJECT &&
         cmt_p2p_sc_recv(i.sc, buf, 1, &c) == CMT_REJECT;
    if (ok) PASS(); else FAIL("pin/abort path wrong");
    side_free(&i);
    side_free(&r);

    TEST("Write / Read before authentication -> refused");
    side_init(&i, g_a, CMT_P2P_SC_ROLE_INITIATOR, NULL, NULL, PROTO_VER, CHAIN_A);
    side_init(&r, g_b, CMT_P2P_SC_ROLE_RESPONDER, NULL, NULL, PROTO_VER, CHAIN_A);
    memset(buf, 0, sizeof(buf));
    ok = cmt_p2p_sc_write(i.sc, buf, 1, buf, sizeof(buf), &out_len) == CMT_REJECT &&
         out_len == 0 &&
         cmt_p2p_sc_read(r.sc, buf, sizeof(buf), &c, buf, 1, &rn) == CMT_REJECT && rn == 0;
    if (ok) PASS(); else FAIL("I/O allowed before authentication");
    side_free(&i);
    side_free(&r);
}

/* ══ main ════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("test_p2p_secret — secret_connection.go port (P2P-PORT F1)\n");

    g_a = (node_t *)calloc(1, sizeof(node_t));
    g_b = (node_t *)calloc(1, sizeof(node_t));
    g_c = (node_t *)calloc(1, sizeof(node_t));
    if (g_a == NULL || g_b == NULL || g_c == NULL ||
        nodus_identity_generate(&g_a->id) != 0 ||
        nodus_identity_generate(&g_b->id) != 0 ||
        nodus_identity_generate(&g_c->id) != 0 ||
        !g_a->id.has_mlkem || !g_b->id.has_mlkem || !g_c->id.has_mlkem ||
        !g_b->id.has_kyber) {
        printf("identity generation failed\n");
        return 1;
    }

    test_handshake("handshake: real ML-KEM-1024 + ML-DSA-87, whole messages",
                   FRAG_ALL, 1);
    test_handshake("handshake: odd fragments (1, 7, 1043, 1045)",
                   FRAG_ODD, sizeof(FRAG_ODD) / sizeof(FRAG_ODD[0]));
    test_read_write();
    test_frame_boundaries();
    test_tamper();
    test_mismatch("proto_ver 8 vs 7 -> refused before KEM", PROTO_VER, CHAIN_A,
                  7u, CHAIN_A);
    test_mismatch("chain id A vs B -> refused before KEM", PROTO_VER, CHAIN_A,
                  PROTO_VER, CHAIN_B);
    test_keyx_twice();
    test_empty_frame_before_authsig();
    test_bad_length_and_kind();
    test_round3("round-3 Kyber ciphertext -> no session", R3_CT);
    test_round3("round-3 public key vs ML-KEM secret key -> no session", R3_PK_MLKEM_SK);
    test_round3("round-3 public key, legacy round-3 Decaps peer -> no session",
                R3_PK_LEGACY_PEER);
    test_counters();
    test_fill_plain_drains_held();
    test_overflow();
    test_authsig("AUTHSIG signed by the wrong key -> not authenticated", SIGN_WRONG_KEY);
    test_authsig("AUTHSIG signed raw (no 0x0A tag) -> not authenticated", SIGN_RAW);
    test_purpose_strict();
    test_pin_abort_and_early_io();

    free(g_a);
    free(g_b);
    free(g_c);

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
