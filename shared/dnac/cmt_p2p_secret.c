/**
 * @file shared/dnac/cmt_p2p_secret.c
 * @brief cometbft @v0.38.26 `p2p/conn/secret_connection.go` ported to C.
 *        See cmt_p2p_secret.h for the module contract, the blocking-call →
 *        state-machine substitution and the deviations R-P2P-1/8/9/10.
 *
 * Every function names the reference range it ports. The AEAD calls use
 * the OpenSSL EVP interface directly, as nodus/src/crypto/
 * nodus_channel_crypto.c does (its :7-9 reason holds here too: the
 * qgp_aes256_* wrapper draws a random nonce, qgp_aes.h:8, and this nonce
 * is a counter).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "cmt_p2p_secret.h"

#include <string.h>
#include <openssl/evp.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/hash/hkdf_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "CMT_P2P_SC"

/* The transcript preimage (row 4): the profile's tag (1..PROFILE_STR_MAX
 * bytes, checked at init) followed by all-fixed-length fields. */
#define SC_T_FIXED_LEN (CMT_P2P_SC_DSA_PK_SIZE * 2 +                        \
                        CMT_P2P_SC_KEM_PK_SIZE +                            \
                        (CMT_P2P_SC_PROTO_VER_SIZE +                        \
                         CMT_P2P_SC_CHAIN_ID_SIZE) * 2 +                    \
                        CMT_P2P_SC_NONCE_SIZE * 2 +                         \
                        CMT_P2P_SC_KEM_CT_SIZE)
#define SC_T_PREIMAGE_MAX (CMT_P2P_SC_PROFILE_STR_MAX + SC_T_FIXED_LEN)

/* The ANON family's strings and KC domain (design §1.1) are the lengths the
 * design states: 25 / 24 / 29 B tag and infos, 22 B KC domain. */
_Static_assert(sizeof("nodus.asess.transcript.v1") - 1 == 25 &&
               sizeof("nodus.asess.keys.v1/aead") - 1 == 24 &&
               sizeof("nodus.asess.keys.v1/challenge") - 1 == 29 &&
               sizeof(CMT_P2P_SC_KC_DOMAIN) - 1 == CMT_P2P_SC_KC_DOMAIN_LEN,
               "ANON strings: design 2026-10-26-dht-v2-3d-no-login-design.md §1.1");

/* ══ session profiles ════════════════════════════════════════════════ */

const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_WITNESS = {
    CMT_P2P_SC_TAG_T, CMT_P2P_SC_INFO_AEAD, CMT_P2P_SC_INFO_CHALLENGE
};
const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_CLIENT = {
    "nodus.csess.transcript.v1", "nodus.csess.keys.v1/aead",
    "nodus.csess.keys.v1/challenge"
};
const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_NODE = {
    "nodus.nsess.transcript.v1", "nodus.nsess.keys.v1/aead",
    "nodus.nsess.keys.v1/challenge"
};

/* DHT v2 package 3d, design §1.1: all three strings are fixed ASCII. The tag
 * is 25 B like the other families' and differs at byte 6 ("asess" / "csess" /
 * "nsess" / "wsess"), so the T preimages of different families cannot collide. */
const cmt_p2p_sc_profile_t CMT_P2P_SC_PROFILE_ANON = {
    "nodus.asess.transcript.v1", "nodus.asess.keys.v1/aead",
    "nodus.asess.keys.v1/challenge"
};

/** 1..CMT_P2P_SC_PROFILE_STR_MAX bytes before the NUL. */
static bool sc_profile_str_ok(const char *s)
{
    size_t n;

    if (s == NULL) {
        return false;
    }
    n = strnlen(s, CMT_P2P_SC_PROFILE_STR_MAX + 1);
    return n >= 1 && n <= CMT_P2P_SC_PROFILE_STR_MAX;
}

/** The string bounds of a profile. */
static bool sc_profile_strs_ok(const cmt_p2p_sc_profile_t *p)
{
    return sc_profile_str_ok(p->transcript_tag) &&
           sc_profile_str_ok(p->info_aead) && sc_profile_str_ok(p->info_challenge);
}

/** Only the three const profiles of cmt_p2p_sc_init_profile are valid
 *  (compared by pointer: an unknown profile is refused, Kurultay #43); the
 *  string bounds are a second guard. ANON is NOT one of them: it has its own
 *  init entry points. */
static bool sc_profile_ok(const cmt_p2p_sc_profile_t *p)
{
    if (p != &CMT_P2P_SC_PROFILE_WITNESS && p != &CMT_P2P_SC_PROFILE_CLIENT &&
        p != &CMT_P2P_SC_PROFILE_NODE) {
        return false;
    }
    return sc_profile_strs_ok(p);
}

/** The machine is bound to the ANON family. */
static bool sc_is_anon(const cmt_p2p_sc_t *sc)
{
    return sc->profile == &CMT_P2P_SC_PROFILE_ANON;
}

/* ══ small helpers ═══════════════════════════════════════════════════ */

/** Kill the machine: every later call returns CMT_REJECT. Key material
 *  is wiped at once — a dead connection never seals or opens again. */
static int sc_die(cmt_p2p_sc_t *sc, int rc)
{
    sc->state = CMT_P2P_SC_ST_DEAD;
    memset(&sc->job, 0, sizeof(sc->job));
    qgp_secure_memzero(sc->ss, sizeof(sc->ss));
    qgp_secure_memzero(sc->key, sizeof(sc->key));
    qgp_secure_memzero(sc->challenge, sizeof(sc->challenge));
    qgp_secure_memzero(sc->t, sizeof(sc->t));
    return rc;
}

static void put_u32_be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

/** protoio's length prefix (binary.PutUvarint, libs/protoio/writer.go:61,
 *  :80). */
static size_t put_uvarint(uint8_t *out, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

/**
 * binary.ReadUvarint over what has arrived so far (libs/protoio/reader.go
 * :69), capped at CMT_P2P_SC_UVARINT_MAX bytes: no body this module
 * accepts needs more, so a longer prefix is refused as the reference's
 * max-size check (:81-83) would refuse the length it encodes.
 * @return 1 decoded (`*v`, `*plen` set); 0 need more; -1 too long.
 */
static int get_uvarint(const uint8_t *in, size_t len, uint64_t *v, size_t *plen)
{
    uint64_t x = 0;
    unsigned shift = 0;
    size_t i;

    for (i = 0; i < len && i < CMT_P2P_SC_UVARINT_MAX; i++) {
        x |= (uint64_t)(in[i] & 0x7f) << shift;
        if ((in[i] & 0x80) == 0) {
            *v = x;
            *plen = i + 1;
            return 1;
        }
        shift += 7;
    }
    return (i >= CMT_P2P_SC_UVARINT_MAX) ? -1 : 0;
}

/** Queue bytes for the caller to write. */
static int out_push(cmt_p2p_sc_t *sc, const uint8_t *b, size_t n)
{
    if (sc->out_off > 0) {
        memmove(sc->out, sc->out + sc->out_off, sc->out_len);
        sc->out_off = 0;
    }
    if (n > sizeof(sc->out) - sc->out_len) {
        return CMT_FAULT;
    }
    memcpy(sc->out + sc->out_len, b, n);
    sc->out_len += n;
    return CMT_OK;
}

/* ══ secret_connection.go:449-462 — the nonce ════════════════════════ */

/**
 * The reference keeps the nonce as a 12-byte array and increments its
 * trailing 8 bytes (incrNonce :453-462). Here the counter is a u64 and
 * the nonce is built from it: role ‖ 00 00 00 ‖ counter (u64 BE)
 * (cmt_p2p_secret.h "THE SEALED FRAME"). OPERATOR-APPROVED layout:
 * docs/plans/decisions/2026-09-26-witness-port-session.md:77.
 */
static void sc_nonce(uint8_t nonce[CMT_P2P_SC_AEAD_NONCE_SIZE],
                     uint8_t role, uint64_t counter)
{
    int i;

    nonce[0] = role;
    nonce[1] = 0;
    nonce[2] = 0;
    nonce[3] = 0;
    for (i = 0; i < 8; i++) {
        nonce[4 + i] = (uint8_t)(counter >> (56 - 8 * i));
    }
}

static uint8_t sc_peer_role(const cmt_p2p_sc_t *sc)
{
    return (sc->role == CMT_P2P_SC_ROLE_INITIATOR) ? CMT_P2P_SC_ROLE_RESPONDER
                                                   : CMT_P2P_SC_ROLE_INITIATOR;
}

/* ══ secret_connection.go:194-229 — one frame of Write ═══════════════ */

/**
 * :209-215 — build the 1028-byte frame for one chunk (≤ 1024), seal it
 * with the send nonce into `sealed` (1044 bytes) and advance the counter.
 * The caller has already checked the counter can take this frame (N3).
 */
static int sc_seal_frame(cmt_p2p_sc_t *sc, const uint8_t *chunk, size_t chunk_len,
                         uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE])
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    uint8_t nonce[CMT_P2P_SC_AEAD_NONCE_SIZE];
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ok = 0;

    /* :210 binary.LittleEndian.PutUint32(frame, uint32(chunkLength)) */
    memset(frame, 0, sizeof(frame));        /* zero pad (header note) */
    frame[0] = (uint8_t)chunk_len;
    frame[1] = (uint8_t)(chunk_len >> 8);
    frame[2] = (uint8_t)(chunk_len >> 16);
    frame[3] = (uint8_t)(chunk_len >> 24);
    /* :211 copy(frame[dataLenSize:], chunk) */
    if (chunk_len > 0) {
        memcpy(frame + CMT_P2P_SC_DATA_LEN_SIZE, chunk, chunk_len);
    }

    /* :214 sc.sendAead.Seal(sealedFrame[:0], sc.sendNonce[:], frame, nil) */
    sc_nonce(nonce, (uint8_t)sc->role, sc->send_counter);
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
    qgp_secure_memzero(frame, sizeof(frame));
    if (!ok) {
        QGP_LOG_ERROR(LOG_TAG, "AES-256-GCM seal failed");
        return CMT_FAULT;
    }

    /* :215 incrNonce(sc.sendNonce) — the limit was checked before. */
    sc->send_counter++;
    return CMT_OK;
}

/** N3 / :453-459 — can the send counter take `nframes` more frames
 *  without sealing one at UINT64_MAX? */
static bool sc_send_room(const cmt_p2p_sc_t *sc, uint64_t nframes)
{
    return nframes <= UINT64_MAX - sc->send_counter;
}

/** :199-208 — seal `data` as consecutive frames into `out`. Room and
 *  counter checked by the caller. */
static int sc_seal_all(cmt_p2p_sc_t *sc, const uint8_t *data, size_t len,
                       uint8_t *out, size_t *out_len)
{
    size_t off = 0;
    size_t w = 0;

    while (off < len) {
        size_t chunk = len - off;
        int rc;

        if (chunk > CMT_P2P_SC_DATA_MAX_SIZE) {
            chunk = CMT_P2P_SC_DATA_MAX_SIZE;               /* :202-204 */
        }
        rc = sc_seal_frame(sc, data + off, chunk, out + w);
        if (rc != CMT_OK) {
            return rc;
        }
        off += chunk;
        w += CMT_P2P_SC_SEALED_FRAME_SIZE;
    }
    *out_len = w;
    return CMT_OK;
}

/* ══ secret_connection.go:243-265 — one frame of Read ════════════════ */

/**
 * :253-265 — open the assembled sealed frame with the EXPECTED nonce
 * (peer role, receive counter) and return its chunk. A replayed, missing,
 * reordered or reflected frame fails here (header "THE SEALED FRAME").
 * On success `chunk` points into `frame_out`.
 */
static int sc_open_frame(cmt_p2p_sc_t *sc,
                         uint8_t frame_out[CMT_P2P_SC_TOTAL_FRAME_SIZE],
                         const uint8_t **chunk, size_t *chunk_len)
{
    uint8_t nonce[CMT_P2P_SC_AEAD_NONCE_SIZE];
    uint8_t tag[CMT_P2P_SC_AEAD_OVERHEAD];
    EVP_CIPHER_CTX *ctx;
    int len = 0;
    int ok = 0;
    uint32_t chunk_length;

    /* N3: refuse to open at UINT64_MAX (the reference would open it and
     * then panic in incrNonce, :257 → :455-458). */
    if (sc->recv_counter == UINT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "receive counter at its limit");
        return CMT_REJECT;
    }

    sc_nonce(nonce, sc_peer_role(sc), sc->recv_counter);
    memcpy(tag, sc->sealed_buf + CMT_P2P_SC_TOTAL_FRAME_SIZE, sizeof(tag));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CMT_FAULT;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            CMT_P2P_SC_AEAD_NONCE_SIZE, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, sc->key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, frame_out, &len, sc->sealed_buf,
                          CMT_P2P_SC_TOTAL_FRAME_SIZE) == 1 &&
        len == CMT_P2P_SC_TOTAL_FRAME_SIZE &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            CMT_P2P_SC_AEAD_OVERHEAD, tag) == 1 &&
        EVP_DecryptFinal_ex(ctx, frame_out + len, &len) == 1) {
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    sc->sealed_len = 0;
    if (!ok) {
        /* :254-256 "failed to decrypt SecretConnection" */
        QGP_LOG_ERROR(LOG_TAG, "failed to decrypt SecretConnection (counter %llu)",
                      (unsigned long long)sc->recv_counter);
        return CMT_REJECT;
    }
    /* :257 incrNonce(sc.recvNonce) */
    sc->recv_counter++;

    /* :262-265 */
    chunk_length = (uint32_t)frame_out[0] | ((uint32_t)frame_out[1] << 8) |
                   ((uint32_t)frame_out[2] << 16) | ((uint32_t)frame_out[3] << 24);
    if (chunk_length > CMT_P2P_SC_DATA_MAX_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "chunkLength is greater than dataMaxSize");
        return CMT_REJECT;
    }
    *chunk = frame_out + CMT_P2P_SC_DATA_LEN_SIZE;          /* :266 */
    *chunk_len = chunk_length;
    return CMT_OK;
}

/** :245 io.ReadFull(sc.conn, sealedFrame) — take bytes from `in` into
 *  the sealed-frame buffer. @return true when a whole frame is in. */
static bool sc_fill_sealed(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                           size_t *consumed)
{
    size_t need = CMT_P2P_SC_SEALED_FRAME_SIZE - sc->sealed_len;
    size_t take = (in_len - *consumed < need) ? in_len - *consumed : need;

    if (take == 0) {
        return sc->sealed_len == CMT_P2P_SC_SEALED_FRAME_SIZE;
    }
    memcpy(sc->sealed_buf + sc->sealed_len, in + *consumed, take);
    sc->sealed_len += take;
    *consumed += take;
    return sc->sealed_len == CMT_P2P_SC_SEALED_FRAME_SIZE;
}

/* ══ secret_connection.go:114-138 + :335-364 — transcript and secrets ═ */

/**
 * Rows 4-6 (R-P2P-9): T = SHA3-512(TAG_T ‖ I_dsa_pk ‖ R_dsa_pk ‖
 * R_mlkem_pk ‖ proto_ver_I ‖ chain_id_I ‖ proto_ver_R ‖ chain_id_R ‖
 * nonce_I ‖ nonce_R ‖ ct); key and challenge = two HKDF-SHA3-256 calls,
 * salt = T, ikm = ss. Replaces the merlin transcript (:114-129),
 * deriveSecrets (:134, :335-364) and the challenge extraction (:138).
 * `ss` is wiped afterwards — nothing needs it again.
 * ANON (design §1.4): the same order WITHOUT I_dsa_pk (the initiator has none,
 * and no placeholder stands in), a 5,889-byte preimage with the 25-byte tag;
 * only the AEAD key is derived (no challenge: nothing is signed).
 * T is kept in sc->t for every family (read-only through
 * cmt_p2p_sc_transcript once AUTHENTICATED).
 */
static int sc_derive(cmt_p2p_sc_t *sc)
{
    uint8_t pre[SC_T_PREIMAGE_MAX];
    uint8_t t[CMT_P2P_SC_T_SIZE];
    const cmt_p2p_sc_profile_t *pf = sc->profile;
    const bool anon = sc_is_anon(sc);
    size_t taglen = strlen(pf->transcript_tag);     /* 1..STR_MAX, init */
    size_t want = taglen + SC_T_FIXED_LEN - (anon ? CMT_P2P_SC_DSA_PK_SIZE : 0);
    size_t o = 0;
    int rc = CMT_OK;

    if (taglen == 0 || taglen > CMT_P2P_SC_PROFILE_STR_MAX) {
        return CMT_FAULT;                           /* init refused these */
    }
#define SC_APPEND(src, n) do { memcpy(pre + o, (src), (n)); o += (n); } while (0)
    SC_APPEND(pf->transcript_tag, taglen);
    if (!anon) {
        SC_APPEND(sc->i_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
    }
    SC_APPEND(sc->r_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
    SC_APPEND(sc->r_kem_pk, CMT_P2P_SC_KEM_PK_SIZE);
    SC_APPEND(sc->i_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE);
    SC_APPEND(sc->i_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    SC_APPEND(sc->r_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE);
    SC_APPEND(sc->r_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    SC_APPEND(sc->nonce_i, CMT_P2P_SC_NONCE_SIZE);
    SC_APPEND(sc->nonce_r, CMT_P2P_SC_NONCE_SIZE);
    SC_APPEND(sc->ct, CMT_P2P_SC_KEM_CT_SIZE);
#undef SC_APPEND

    if (o != want || o > sizeof(pre) || qgp_sha3_512(pre, o, t) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "transcript hash failed");
        rc = CMT_FAULT;
    } else if (hkdf_sha3_256(t, sizeof(t), sc->ss, sizeof(sc->ss),
                             (const uint8_t *)pf->info_aead,
                             strlen(pf->info_aead),
                             sc->key, sizeof(sc->key)) != 0 ||
               (!anon &&
                hkdf_sha3_256(t, sizeof(t), sc->ss, sizeof(sc->ss),
                              (const uint8_t *)pf->info_challenge,
                              strlen(pf->info_challenge),
                              sc->challenge, sizeof(sc->challenge)) != 0)) {
        QGP_LOG_ERROR(LOG_TAG, "HKDF-SHA3-256 failed");
        rc = CMT_FAULT;
    } else {
        memcpy(sc->t, t, sizeof(sc->t));
    }
    qgp_secure_memzero(sc->ss, sizeof(sc->ss));
    qgp_secure_memzero(t, sizeof(t));
    return rc;
}

/* ══ job issue ═══════════════════════════════════════════════════════ */

static void sc_issue(cmt_p2p_sc_t *sc, cmt_p2p_sc_job_kind_t kind)
{
    memset(&sc->job, 0, sizeof(sc->job));
    sc->job.kind = kind;
    switch (kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        sc->job.kem_pk = sc->r_kem_pk;
        sc->job.kem_ct_out = sc->ct;
        sc->job.kem_ss_out = sc->ss;
        break;
    case CMT_P2P_SC_JOB_DECAPS:
        sc->job.kem_ct = sc->ct;
        sc->job.kem_sk = sc->local_kem_sk;
        sc->job.kem_ss_out = sc->ss;
        break;
    case CMT_P2P_SC_JOB_SIGN:
        sc->job.msg = sc->challenge;
        sc->job.msg_len = sizeof(sc->challenge);
        sc->job.sig_out = sc->local_sig;
        break;
    case CMT_P2P_SC_JOB_VERIFY:
        sc->job.msg = sc->challenge;
        sc->job.msg_len = sizeof(sc->challenge);
        /* Row 9: the pk that went into T — the PEER's role slot. */
        sc->job.dsa_pk = (sc->role == CMT_P2P_SC_ROLE_INITIATOR) ? sc->r_dsa_pk
                                                                 : sc->i_dsa_pk;
        sc->job.sig = sc->remote_sig;
        break;
    case CMT_P2P_SC_JOB_VERIFY_KC:
        /* ANON initiator: the certificate over the message built from OUR
         * chain id and the RECEIVED R_mlkem_pk, under R's claimed key. */
        sc->job.msg = sc->kc_msg;
        sc->job.msg_len = sizeof(sc->kc_msg);
        sc->job.dsa_pk = sc->r_dsa_pk;
        sc->job.sig = sc->remote_sig;
        break;
    case CMT_P2P_SC_JOB_NONE:
    default:
        break;
    }
    sc->state = CMT_P2P_SC_ST_JOB;
}

/* ══ secret_connection.go:95-110 — MakeSecretConnection, first half ══ */

/* :95-106 — key setup and the first message of shareEphPubKey */
int cmt_p2p_sc_init(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role,
                    const cmt_p2p_sc_host_t *host,
                    const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE],
                    const uint8_t *local_kem_pk,
                    const uint8_t *local_kem_sk,
                    uint32_t proto_ver,
                    const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])
{
    return cmt_p2p_sc_init_profile(sc, role, host, &CMT_P2P_SC_PROFILE_WITNESS,
                                   local_dsa_pk, local_kem_pk, local_kem_sk,
                                   proto_ver, chain_id);
}

int cmt_p2p_sc_init_profile(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role,
                            const cmt_p2p_sc_host_t *host,
                            const cmt_p2p_sc_profile_t *profile,
                            const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE],
                            const uint8_t *local_kem_pk,
                            const uint8_t *local_kem_sk,
                            uint32_t proto_ver,
                            const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])
{
    uint8_t msg[CMT_P2P_SC_HS_MSG_MAX];
    size_t o;

    if (sc == NULL) {
        return CMT_FAULT;
    }
    memset(sc, 0, sizeof(*sc));             /* state = DEAD until the end */
    if (!sc_profile_ok(profile)) {
        QGP_LOG_ERROR(LOG_TAG, "invalid session profile");
        return CMT_FAULT;
    }
    if (host == NULL || host->sign == NULL || host->verify == NULL ||
        local_dsa_pk == NULL || chain_id == NULL) {
        return CMT_FAULT;
    }
    if (role == CMT_P2P_SC_ROLE_RESPONDER) {
        if (local_kem_pk == NULL || local_kem_sk == NULL) {
            return CMT_FAULT;
        }
    } else if (role == CMT_P2P_SC_ROLE_INITIATOR) {
        if (local_kem_pk != NULL || local_kem_sk != NULL) {
            return CMT_FAULT;
        }
    } else {
        return CMT_FAULT;
    }

    sc->role = role;
    sc->host = host;
    sc->profile = profile;
    sc->proto_ver = proto_ver;
    memcpy(sc->chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);

    if (role == CMT_P2P_SC_ROLE_RESPONDER) {
        memcpy(sc->r_dsa_pk, local_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
        memcpy(sc->r_kem_pk, local_kem_pk, CMT_P2P_SC_KEM_PK_SIZE);
        put_u32_be(sc->r_proto_ver, proto_ver);
        memcpy(sc->r_chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
        sc->local_kem_sk = local_kem_sk;
        /* Row 2: R's fresh contribution (decision record item 3). */
        if (qgp_platform_random(sc->nonce_r, CMT_P2P_SC_NONCE_SIZE) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "RNG failure (nonce_R)");
            return sc_die(sc, CMT_FAULT);
        }
        sc->state = CMT_P2P_SC_ST_WAIT_HELLO;
        return CMT_OK;
    }

    memcpy(sc->i_dsa_pk, local_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
    put_u32_be(sc->i_proto_ver, proto_ver);
    memcpy(sc->i_chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (qgp_platform_random(sc->nonce_i, CMT_P2P_SC_NONCE_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "RNG failure (nonce_I)");
        return sc_die(sc, CMT_FAULT);
    }

    /* Row 2: HELLO { I_dsa_pk, nonce_I, proto_ver, chain_id } */
    o = put_uvarint(msg, CMT_P2P_SC_HELLO_BODY);
    msg[o++] = CMT_P2P_SC_MSG_HELLO;
    memcpy(msg + o, sc->i_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);  o += CMT_P2P_SC_DSA_PK_SIZE;
    memcpy(msg + o, sc->nonce_i, CMT_P2P_SC_NONCE_SIZE);    o += CMT_P2P_SC_NONCE_SIZE;
    memcpy(msg + o, sc->i_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE);
    o += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(msg + o, sc->i_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    o += CMT_P2P_SC_CHAIN_ID_SIZE;
    if (out_push(sc, msg, o) != CMT_OK) {
        return sc_die(sc, CMT_FAULT);
    }
    sc->state = CMT_P2P_SC_ST_WAIT_HELLO_R;
    return CMT_OK;
}

/** HELLO_ANON (I → R), 70 wire bytes: nonce_I ‖ proto_ver ‖ chain_id. */
static int sc_queue_hello_anon(cmt_p2p_sc_t *sc)
{
    uint8_t msg[CMT_P2P_SC_HELLO_ANON_WIRE];
    size_t o = put_uvarint(msg, CMT_P2P_SC_HELLO_ANON_BODY);

    msg[o++] = CMT_P2P_SC_MSG_HELLO_ANON;
    memcpy(msg + o, sc->nonce_i, CMT_P2P_SC_NONCE_SIZE);        o += CMT_P2P_SC_NONCE_SIZE;
    memcpy(msg + o, sc->i_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE); o += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(msg + o, sc->i_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);   o += CMT_P2P_SC_CHAIN_ID_SIZE;
    if (o != sizeof(msg)) {
        return CMT_FAULT;
    }
    return out_push(sc, msg, o);
}

/* DHT v2 package 3d: the ANON entry point (design §1.5). */
int cmt_p2p_sc_init_anon(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role,
                         const cmt_p2p_sc_host_t *host,
                         const uint8_t *local_dsa_pk,
                         const uint8_t *local_kem_pk,
                         const uint8_t *local_kem_sk,
                         const uint8_t *local_kc_sig,
                         uint32_t proto_ver,
                         const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])
{
    if (sc == NULL) {
        return CMT_FAULT;
    }
    memset(sc, 0, sizeof(*sc));             /* state = DEAD until the end */
    if (!sc_profile_strs_ok(&CMT_P2P_SC_PROFILE_ANON)) {
        QGP_LOG_ERROR(LOG_TAG, "invalid session profile");
        return CMT_FAULT;
    }
    if (host == NULL || chain_id == NULL) {
        return CMT_FAULT;
    }
    if (role == CMT_P2P_SC_ROLE_RESPONDER) {
        if (local_dsa_pk == NULL || local_kem_pk == NULL || local_kem_sk == NULL ||
            local_kc_sig == NULL) {
            return CMT_FAULT;
        }
    } else if (role == CMT_P2P_SC_ROLE_INITIATOR) {
        /* No local key of any kind: the client presents none. */
        if (local_dsa_pk != NULL || local_kem_pk != NULL || local_kem_sk != NULL ||
            local_kc_sig != NULL || host->verify_kc == NULL) {
            return CMT_FAULT;
        }
    } else {
        return CMT_FAULT;
    }

    sc->role = role;
    sc->host = host;
    sc->profile = &CMT_P2P_SC_PROFILE_ANON;
    sc->proto_ver = proto_ver;
    memcpy(sc->chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);

    if (role == CMT_P2P_SC_ROLE_RESPONDER) {
        memcpy(sc->r_dsa_pk, local_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
        memcpy(sc->r_kem_pk, local_kem_pk, CMT_P2P_SC_KEM_PK_SIZE);
        put_u32_be(sc->r_proto_ver, proto_ver);
        memcpy(sc->r_chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
        sc->local_kem_sk = local_kem_sk;
        sc->local_kc_sig = local_kc_sig;
        if (qgp_platform_random(sc->nonce_r, CMT_P2P_SC_NONCE_SIZE) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "RNG failure (nonce_R)");
            return sc_die(sc, CMT_FAULT);
        }
        sc->state = CMT_P2P_SC_ST_WAIT_HELLO;
        return CMT_OK;
    }

    put_u32_be(sc->i_proto_ver, proto_ver);
    memcpy(sc->i_chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (qgp_platform_random(sc->nonce_i, CMT_P2P_SC_NONCE_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "RNG failure (nonce_I)");
        return sc_die(sc, CMT_FAULT);
    }
    if (sc_queue_hello_anon(sc) != CMT_OK) {
        return sc_die(sc, CMT_FAULT);
    }
    sc->state = CMT_P2P_SC_ST_WAIT_HELLO_R;
    return CMT_OK;
}

/* DHT v2 package 3d: a responder that has not chosen its family (design
 * §1.5 "Server on 4001 / WS", steps 1-2). */
int cmt_p2p_sc_init_responder_unbound(cmt_p2p_sc_t *sc,
                                      const cmt_p2p_sc_host_t *host,
                                      const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE],
                                      const uint8_t *local_kem_pk,
                                      const uint8_t *local_kem_sk,
                                      const uint8_t *local_kc_sig,
                                      uint32_t proto_ver,
                                      const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE])
{
    if (sc == NULL) {
        return CMT_FAULT;
    }
    memset(sc, 0, sizeof(*sc));             /* state = DEAD until the end */
    /* The CLIENT continuation needs exactly what a bound CLIENT responder
     * needs; the ANON continuation needs `local_kc_sig` too. */
    if (!sc_profile_ok(&CMT_P2P_SC_PROFILE_CLIENT) ||
        !sc_profile_strs_ok(&CMT_P2P_SC_PROFILE_ANON)) {
        QGP_LOG_ERROR(LOG_TAG, "invalid session profile");
        return CMT_FAULT;
    }
    if (host == NULL || host->sign == NULL || host->verify == NULL ||
        local_dsa_pk == NULL || local_kem_pk == NULL || local_kem_sk == NULL ||
        chain_id == NULL) {
        return CMT_FAULT;
    }

    sc->role = CMT_P2P_SC_ROLE_RESPONDER;
    sc->host = host;
    sc->profile = NULL;                     /* bound once, at the first message */
    sc->proto_ver = proto_ver;
    memcpy(sc->chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    memcpy(sc->r_dsa_pk, local_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);
    memcpy(sc->r_kem_pk, local_kem_pk, CMT_P2P_SC_KEM_PK_SIZE);
    put_u32_be(sc->r_proto_ver, proto_ver);
    memcpy(sc->r_chain_id, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    sc->local_kem_sk = local_kem_sk;
    sc->local_kc_sig = local_kc_sig;        /* NULL: ANON is not offered */
    if (qgp_platform_random(sc->nonce_r, CMT_P2P_SC_NONCE_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "RNG failure (nonce_R)");
        return sc_die(sc, CMT_FAULT);
    }
    sc->state = CMT_P2P_SC_ST_WAIT_FIRST;
    return CMT_OK;
}

void cmt_p2p_sc_kc_msg(const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE],
                       const uint8_t kem_pk[CMT_P2P_SC_KEM_PK_SIZE],
                       uint8_t out[CMT_P2P_SC_KC_MSG_SIZE])
{
    memcpy(out, CMT_P2P_SC_KC_DOMAIN, CMT_P2P_SC_KC_DOMAIN_LEN);
    memcpy(out + CMT_P2P_SC_KC_DOMAIN_LEN, chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    memcpy(out + CMT_P2P_SC_KC_DOMAIN_LEN + CMT_P2P_SC_CHAIN_ID_SIZE, kem_pk,
           CMT_P2P_SC_KEM_PK_SIZE);
}

/** N9 / R15: the peer's proto_ver and chain_id must equal ours — checked
 *  before any KEM work. */
static int sc_check_compat(const cmt_p2p_sc_t *sc,
                           const uint8_t pv[CMT_P2P_SC_PROTO_VER_SIZE],
                           const uint8_t cid[CMT_P2P_SC_CHAIN_ID_SIZE])
{
    uint8_t mine[CMT_P2P_SC_PROTO_VER_SIZE];

    put_u32_be(mine, sc->proto_ver);
    if (memcmp(pv, mine, sizeof(mine)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "peer protocol version %u != ours %u",
                      (unsigned)(((uint32_t)pv[0] << 24) | ((uint32_t)pv[1] << 16) |
                                 ((uint32_t)pv[2] << 8) | (uint32_t)pv[3]),
                      (unsigned)sc->proto_ver);
        return CMT_REJECT;
    }
    if (memcmp(cid, sc->chain_id, CMT_P2P_SC_CHAIN_ID_SIZE) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "peer chain id differs from ours");
        return CMT_REJECT;
    }
    return CMT_OK;
}

/** R: HELLO accepted → HELLO_R queued. */
static int sc_on_hello(cmt_p2p_sc_t *sc, const uint8_t *body)
{
    uint8_t msg[CMT_P2P_SC_HS_MSG_MAX];
    const uint8_t *p = body + 1;
    size_t o;

    if (sc->state == CMT_P2P_SC_ST_WAIT_FIRST) {
        /* Unbound responder: the whole (0x01, 2661) message is in — bind
         * CLIENT now (design §1.5 step 2). */
        sc->profile = &CMT_P2P_SC_PROFILE_CLIENT;
    }
    memcpy(sc->i_dsa_pk, p, CMT_P2P_SC_DSA_PK_SIZE);         p += CMT_P2P_SC_DSA_PK_SIZE;
    memcpy(sc->nonce_i, p, CMT_P2P_SC_NONCE_SIZE);           p += CMT_P2P_SC_NONCE_SIZE;
    memcpy(sc->i_proto_ver, p, CMT_P2P_SC_PROTO_VER_SIZE);   p += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(sc->i_chain_id, p, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (sc_check_compat(sc, sc->i_proto_ver, sc->i_chain_id) != CMT_OK) {
        return sc_die(sc, CMT_REJECT);
    }

    /* Row 2: HELLO_R { R_dsa_pk, R_mlkem_pk, nonce_R, proto_ver, chain_id } */
    o = put_uvarint(msg, CMT_P2P_SC_HELLO_R_BODY);
    msg[o++] = CMT_P2P_SC_MSG_HELLO_R;
    memcpy(msg + o, sc->r_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE);  o += CMT_P2P_SC_DSA_PK_SIZE;
    memcpy(msg + o, sc->r_kem_pk, CMT_P2P_SC_KEM_PK_SIZE);  o += CMT_P2P_SC_KEM_PK_SIZE;
    memcpy(msg + o, sc->nonce_r, CMT_P2P_SC_NONCE_SIZE);    o += CMT_P2P_SC_NONCE_SIZE;
    memcpy(msg + o, sc->r_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE);
    o += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(msg + o, sc->r_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE);
    o += CMT_P2P_SC_CHAIN_ID_SIZE;
    if (out_push(sc, msg, o) != CMT_OK) {
        return sc_die(sc, CMT_FAULT);
    }
    sc->state = CMT_P2P_SC_ST_WAIT_KEYX;
    return CMT_OK;
}

/** I: HELLO_R accepted → ENCAPS job (row 3). The caller's row-10 pin
 *  happens while that job is outstanding (header). */
static int sc_on_hello_r(cmt_p2p_sc_t *sc, const uint8_t *body)
{
    const uint8_t *p = body + 1;

    memcpy(sc->r_dsa_pk, p, CMT_P2P_SC_DSA_PK_SIZE);         p += CMT_P2P_SC_DSA_PK_SIZE;
    memcpy(sc->r_kem_pk, p, CMT_P2P_SC_KEM_PK_SIZE);         p += CMT_P2P_SC_KEM_PK_SIZE;
    memcpy(sc->nonce_r, p, CMT_P2P_SC_NONCE_SIZE);           p += CMT_P2P_SC_NONCE_SIZE;
    memcpy(sc->r_proto_ver, p, CMT_P2P_SC_PROTO_VER_SIZE);   p += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(sc->r_chain_id, p, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (sc_check_compat(sc, sc->r_proto_ver, sc->r_chain_id) != CMT_OK) {
        return sc_die(sc, CMT_REJECT);
    }
    sc_issue(sc, CMT_P2P_SC_JOB_ENCAPS);
    return CMT_OK;
}

/** R, ANON: HELLO_ANON accepted → HELLO_R_ANON queued with the cached KC.
 *  Piecewise into the output queue: the 8,858-byte message is never built on
 *  the stack. */
static int sc_on_hello_anon(cmt_p2p_sc_t *sc, const uint8_t *body)
{
    uint8_t head[CMT_P2P_SC_UVARINT_MAX + 1];
    const uint8_t *p = body + 1;
    size_t o;

    if (sc->state == CMT_P2P_SC_ST_WAIT_FIRST) {
        /* Unbound responder: the whole (0x05, 69) message is in — bind ANON
         * now (design §1.5 step 2). */
        sc->profile = &CMT_P2P_SC_PROFILE_ANON;
    }
    memcpy(sc->nonce_i, p, CMT_P2P_SC_NONCE_SIZE);           p += CMT_P2P_SC_NONCE_SIZE;
    memcpy(sc->i_proto_ver, p, CMT_P2P_SC_PROTO_VER_SIZE);   p += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(sc->i_chain_id, p, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (sc_check_compat(sc, sc->i_proto_ver, sc->i_chain_id) != CMT_OK) {
        return sc_die(sc, CMT_REJECT);
    }
    if (sc->local_kc_sig == NULL) {
        return sc_die(sc, CMT_FAULT);       /* the bind refuses this; belt and braces */
    }

    /* HELLO_R_ANON { R_dsa_pk, R_mlkem_pk, kc_sig, nonce_R, proto_ver, chain_id } */
    o = put_uvarint(head, CMT_P2P_SC_HELLO_R_ANON_BODY);
    head[o++] = CMT_P2P_SC_MSG_HELLO_R_ANON;
    if (out_push(sc, head, o) != CMT_OK ||
        out_push(sc, sc->r_dsa_pk, CMT_P2P_SC_DSA_PK_SIZE) != CMT_OK ||
        out_push(sc, sc->r_kem_pk, CMT_P2P_SC_KEM_PK_SIZE) != CMT_OK ||
        out_push(sc, sc->local_kc_sig, CMT_P2P_SC_SIG_SIZE) != CMT_OK ||
        out_push(sc, sc->nonce_r, CMT_P2P_SC_NONCE_SIZE) != CMT_OK ||
        out_push(sc, sc->r_proto_ver, CMT_P2P_SC_PROTO_VER_SIZE) != CMT_OK ||
        out_push(sc, sc->r_chain_id, CMT_P2P_SC_CHAIN_ID_SIZE) != CMT_OK) {
        return sc_die(sc, CMT_FAULT);
    }
    sc->state = CMT_P2P_SC_ST_WAIT_KEYX;
    return CMT_OK;
}

/** I, ANON: HELLO_R_ANON accepted → the mandatory KC VERIFY job. No ENCAPS
 *  is issued here or anywhere before both the certificate and the caller's
 *  pin are accepted (design §1.5 step 2; zk-auditor F11). */
static int sc_on_hello_r_anon(cmt_p2p_sc_t *sc, const uint8_t *body)
{
    const uint8_t *p = body + 1;

    memcpy(sc->r_dsa_pk, p, CMT_P2P_SC_DSA_PK_SIZE);         p += CMT_P2P_SC_DSA_PK_SIZE;
    memcpy(sc->r_kem_pk, p, CMT_P2P_SC_KEM_PK_SIZE);         p += CMT_P2P_SC_KEM_PK_SIZE;
    memcpy(sc->remote_sig, p, CMT_P2P_SC_SIG_SIZE);          p += CMT_P2P_SC_SIG_SIZE;
    memcpy(sc->nonce_r, p, CMT_P2P_SC_NONCE_SIZE);           p += CMT_P2P_SC_NONCE_SIZE;
    memcpy(sc->r_proto_ver, p, CMT_P2P_SC_PROTO_VER_SIZE);   p += CMT_P2P_SC_PROTO_VER_SIZE;
    memcpy(sc->r_chain_id, p, CMT_P2P_SC_CHAIN_ID_SIZE);
    if (sc_check_compat(sc, sc->r_proto_ver, sc->r_chain_id) != CMT_OK) {
        return sc_die(sc, CMT_REJECT);
    }
    /* The message is built from OUR chain id and the RECEIVED KEM key. */
    cmt_p2p_sc_kc_msg(sc->chain_id, sc->r_kem_pk, sc->kc_msg);
    sc->anon_pin_ok = false;
    sc_issue(sc, CMT_P2P_SC_JOB_VERIFY_KC);
    return CMT_OK;
}

/** R: KEYX accepted (once — the state leaves WAIT_KEYX here and never
 *  returns) → DECAPS job (row 3). */
static int sc_on_keyx(cmt_p2p_sc_t *sc, const uint8_t *body)
{
    memcpy(sc->ct, body + 1, CMT_P2P_SC_KEM_CT_SIZE);
    sc_issue(sc, CMT_P2P_SC_JOB_DECAPS);
    return CMT_OK;
}

/**
 * Assemble one delimited plaintext handshake message (R8: the kind and
 * the exact length for the current step, refused before its body is even
 * buffered when the length is wrong). Dispatches it when complete.
 * `buf` / `cap` is the storage the message is assembled in (hs_buf, or the
 * ANON initiator's anon_hs_buf): the prefix plus the body must fit `cap`
 * (checked against the BUFFER, not only against the step's expected length —
 * design §1.6); `sc->hs_len` counts the bytes in it.
 */
static int sc_recv_hs_msg(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                          size_t *consumed, uint8_t kind, size_t body_len,
                          uint8_t *buf, size_t cap)
{
    while (*consumed < in_len) {
        uint64_t v = 0;
        size_t plen = 0;
        int u = get_uvarint(buf, sc->hs_len, &v, &plen);

        if (u == 0) {
            /* Length prefix incomplete: one byte at a time. */
            buf[sc->hs_len++] = in[(*consumed)++];
            u = get_uvarint(buf, sc->hs_len, &v, &plen);
            if (u == 0) {
                continue;
            }
        }
        if (u < 0 || v != body_len) {
            QGP_LOG_ERROR(LOG_TAG, "handshake message length %llu, step expects %zu",
                          (unsigned long long)v, body_len);
            return sc_die(sc, CMT_REJECT);
        }
        if (plen + body_len > cap) {
            QGP_LOG_ERROR(LOG_TAG, "handshake message of %zu bytes does not fit its %zu-byte buffer",
                          plen + body_len, cap);
            return sc_die(sc, CMT_FAULT);
        }
        {
            size_t total = plen + body_len;
            size_t need = total - sc->hs_len;
            size_t avail = in_len - *consumed;
            size_t take = (avail < need) ? avail : need;

            memcpy(buf + sc->hs_len, in + *consumed, take);
            sc->hs_len += take;
            *consumed += take;
            if (sc->hs_len < total) {
                return CMT_OK;                              /* need more */
            }
            if (buf[plen] != kind) {
                QGP_LOG_ERROR(LOG_TAG, "handshake message kind 0x%02x, step expects 0x%02x",
                              (unsigned)buf[plen], (unsigned)kind);
                return sc_die(sc, CMT_REJECT);
            }
            sc->hs_len = 0;
            switch (kind) {
            case CMT_P2P_SC_MSG_HELLO:       return sc_on_hello(sc, buf + plen);
            case CMT_P2P_SC_MSG_HELLO_R:     return sc_on_hello_r(sc, buf + plen);
            case CMT_P2P_SC_MSG_KEYX:        return sc_on_keyx(sc, buf + plen);
            case CMT_P2P_SC_MSG_HELLO_ANON:  return sc_on_hello_anon(sc, buf + plen);
            case CMT_P2P_SC_MSG_HELLO_R_ANON: return sc_on_hello_r_anon(sc, buf + plen);
            default:                         return sc_die(sc, CMT_FAULT);
            }
        }
    }
    return CMT_OK;
}

/** The step's message for the BOUND family (never for a received kind). */
static int sc_recv_step(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                        size_t *consumed, uint8_t kind, size_t body_len)
{
    return sc_recv_hs_msg(sc, in, in_len, consumed, kind, body_len,
                          sc->hs_buf, sizeof(sc->hs_buf));
}

/**
 * R, family UNBOUND: read the length prefix of the first plaintext message
 * and bind the family ONCE from its exact (kind, length) (design §1.5):
 *   (HELLO 0x01, 2661)      → CLIENT, today's handshake;
 *   (HELLO_ANON 0x05, 69)   → ANON, only when a KC was supplied;
 *   anything else           → REJECT.
 * The length selects the one message that may follow; sc_recv_hs_msg buffers
 * it and checks its kind exactly as for a bound machine, and only then does
 * its handler bind the family (the pair, not the prefix, binds).
 * Nothing in the machine's timestamps lives here — the caller's pre-session
 * deadline runs from accept and is not reset by the binding.
 */
static int sc_recv_first(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                         size_t *consumed)
{
    while (*consumed < in_len) {
        uint64_t v = 0;
        size_t plen = 0;
        int u = get_uvarint(sc->hs_buf, sc->hs_len, &v, &plen);

        if (u == 0) {
            sc->hs_buf[sc->hs_len++] = in[(*consumed)++];
            u = get_uvarint(sc->hs_buf, sc->hs_len, &v, &plen);
            if (u == 0) {
                continue;
            }
        }
        /* The length names the ONLY message that can follow; the family is
         * bound when that whole message has arrived with its kind — in
         * sc_on_hello / sc_on_hello_anon — never from the prefix alone.
         * Until then the machine stays WAIT_FIRST and unbound. */
        if (u > 0 && v == CMT_P2P_SC_HELLO_BODY) {
            return sc_recv_step(sc, in, in_len, consumed,
                                CMT_P2P_SC_MSG_HELLO, CMT_P2P_SC_HELLO_BODY);
        }
        if (u > 0 && v == CMT_P2P_SC_HELLO_ANON_BODY && sc->local_kc_sig != NULL) {
            return sc_recv_step(sc, in, in_len, consumed,
                                CMT_P2P_SC_MSG_HELLO_ANON, CMT_P2P_SC_HELLO_ANON_BODY);
        }
        QGP_LOG_ERROR(LOG_TAG, "first handshake message length %llu selects no family",
                      (unsigned long long)v);
        return sc_die(sc, CMT_REJECT);
    }
    return CMT_OK;
}

/**
 * :169 shareAuthSignature, the reading half (:417-434): open sealed
 * frames and gather the peer's delimited AUTHSIG. Nothing else may come
 * first (R1). Bytes past the AUTHSIG in its last frame stay in recvBuffer
 * for Read, as the reference's unbuffered delimited reader leaves them
 * in sc.recvBuffer (libs/protoio/reader.go:42-53, secret_connection.go
 * :268-271). When the AUTHSIG is complete → VERIFY job.
 */
static int sc_recv_authsig(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                           size_t *consumed)
{
    while (*consumed < in_len) {
        uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
        const uint8_t *chunk = NULL;
        size_t chunk_len = 0;
        size_t off = 0;
        int rc;

        if (!sc_fill_sealed(sc, in, in_len, consumed)) {
            return CMT_OK;                                  /* need more */
        }
        rc = sc_open_frame(sc, frame, &chunk, &chunk_len);
        if (rc != CMT_OK) {
            /* Whatever the failed open left in the frame is not kept
             * (red-team Z1 F16; the reference's frame is GC memory). */
            qgp_secure_memzero(frame, sizeof(frame));
            return sc_die(sc, rc);
        }
        if (chunk_len == 0) {
            /* An EMPTY sealed frame before the AUTHSIG is complete: the
             * reference's Read returns 0 bytes with no error
             * (secret_connection.go:261-273). What its delimited reader
             * does with that depends on where it is: while reading the
             * length PREFIX, byteReader.ReadByte (libs/protoio/io.go:
             * 91-98) returns its buffer's STALE byte with a nil error, so
             * the uvarint takes a byte that was never sent; while reading
             * the BODY, io.ReadFull (libs/protoio/reader.go:89) asks
             * again, so a peer could make this node open frame after
             * frame for free before it ever authenticates. Nothing but the
             * AUTHSIG may come first (design R1): close. STRICTER than the
             * reference (red-team Z1 F14; R-P2P-63). */
            QGP_LOG_ERROR(LOG_TAG, "empty sealed frame before AUTHSIG");
            qgp_secure_memzero(frame, sizeof(frame));
            return sc_die(sc, CMT_REJECT);
        }

        while (off < chunk_len) {
            uint64_t v = 0;
            size_t plen = 0;
            int u = get_uvarint(sc->authsig_buf, sc->authsig_len, &v, &plen);

            if (u == 0) {
                sc->authsig_buf[sc->authsig_len++] = chunk[off++];
                continue;
            }
            if (u < 0 || v != CMT_P2P_SC_AUTHSIG_BODY) {
                QGP_LOG_ERROR(LOG_TAG, "AUTHSIG length %llu, expected %u",
                              (unsigned long long)v, (unsigned)CMT_P2P_SC_AUTHSIG_BODY);
                qgp_secure_memzero(frame, sizeof(frame));
                return sc_die(sc, CMT_REJECT);
            }
            {
                size_t total = plen + CMT_P2P_SC_AUTHSIG_BODY;
                size_t need = total - sc->authsig_len;
                size_t take = (chunk_len - off < need) ? chunk_len - off : need;

                memcpy(sc->authsig_buf + sc->authsig_len, chunk + off, take);
                sc->authsig_len += take;
                off += take;
                if (sc->authsig_len < total) {
                    continue;
                }
                if (sc->authsig_buf[plen] != CMT_P2P_SC_MSG_AUTHSIG) {
                    QGP_LOG_ERROR(LOG_TAG, "first sealed message is not AUTHSIG");
                    qgp_secure_memzero(frame, sizeof(frame));
                    return sc_die(sc, CMT_REJECT);
                }
                memcpy(sc->remote_sig, sc->authsig_buf + plen + 1, CMT_P2P_SC_SIG_SIZE);
                /* The rest of this frame belongs to Read. */
                memcpy(sc->recv_buf, chunk + off, chunk_len - off);
                sc->recv_off = 0;
                sc->recv_len = chunk_len - off;
                qgp_secure_memzero(frame, sizeof(frame));
                sc_issue(sc, CMT_P2P_SC_JOB_VERIFY);
                return CMT_OK;
            }
        }
        qgp_secure_memzero(frame, sizeof(frame));
    }
    return CMT_OK;
}

/**
 * ANON: seal this side's CONFIRM — the delimited message `01 06` as ONE
 * sealed frame — through the handshake's own seal and queue it, like
 * sc_queue_authsig does for AUTHSIG. The public write stays refused before
 * AUTHENTICATED (cmt_p2p_sc_write).
 */
static int sc_queue_confirm(cmt_p2p_sc_t *sc)
{
    uint8_t msg[CMT_P2P_SC_CONFIRM_WIRE];
    uint8_t sealed[CMT_P2P_SC_SEALED_FRAME_SIZE];
    size_t sealed_len = 0;
    size_t o = put_uvarint(msg, CMT_P2P_SC_CONFIRM_BODY);
    int rc;

    msg[o++] = CMT_P2P_SC_MSG_CONFIRM;
    if (o != sizeof(msg) || !sc_send_room(sc, 1)) {
        return CMT_REJECT;
    }
    rc = sc_seal_all(sc, msg, o, sealed, &sealed_len);
    if (rc != CMT_OK) {
        return rc;
    }
    return out_push(sc, sealed, sealed_len);
}

/**
 * ANON: the peer's ONE sealed CONFIRM (design §1.5 steps 4 / 4d). Exactly one
 * frame is taken: chunkLength 2, content `01 06`, nothing else in it — any
 * other length (empty, longer, a tail), any other content, or a frame that
 * does not open (a wrong ct, implicit rejection, surfaces here) is a REJECT.
 * The INITIATOR then answers with its own CONFIRM; either way the machine is
 * AUTHENTICATED. Bytes after this frame belong to Read.
 */
static int sc_recv_confirm(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                           size_t *consumed)
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    int rc;

    if (!sc_fill_sealed(sc, in, in_len, consumed)) {
        return CMT_OK;                                      /* need more */
    }
    rc = sc_open_frame(sc, frame, &chunk, &chunk_len);
    if (rc != CMT_OK) {
        qgp_secure_memzero(frame, sizeof(frame));
        return sc_die(sc, rc);
    }
    if (chunk_len != CMT_P2P_SC_CONFIRM_WIRE ||
        chunk[0] != CMT_P2P_SC_CONFIRM_BODY || chunk[1] != CMT_P2P_SC_MSG_CONFIRM) {
        QGP_LOG_ERROR(LOG_TAG, "the first sealed message is not exactly one CONFIRM");
        qgp_secure_memzero(frame, sizeof(frame));
        return sc_die(sc, CMT_REJECT);
    }
    qgp_secure_memzero(frame, sizeof(frame));
    if (sc->role == CMT_P2P_SC_ROLE_INITIATOR) {
        rc = sc_queue_confirm(sc);
        if (rc != CMT_OK) {
            return sc_die(sc, rc);
        }
    }
    sc->state = CMT_P2P_SC_ST_AUTHENTICATED;
    return CMT_OK;
}

/* :106-184 — the reading side of the handshake, fed bytes. */
int cmt_p2p_sc_recv(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                    size_t *consumed)
{
    if (consumed != NULL) {
        *consumed = 0;
    }
    if (sc == NULL || consumed == NULL || (in == NULL && in_len > 0)) {
        return CMT_FAULT;
    }

    switch (sc->state) {
    case CMT_P2P_SC_ST_DEAD:
        return CMT_REJECT;
    case CMT_P2P_SC_ST_JOB:                   /* HOLD (header, N1) */
    case CMT_P2P_SC_ST_AUTHENTICATED:         /* the rest is Read's */
        return CMT_OK;
    case CMT_P2P_SC_ST_WAIT_FIRST:
        return sc_recv_first(sc, in, in_len, consumed);
    /* The step's message depends on the BOUND family, never on a received
     * kind (design §1.5 step 5): an ANON machine accepts nothing but the ANON
     * kinds, every other machine nothing but its own — 0x05 / 0x06 / 0x07 are
     * a kind-or-length REJECT for WITNESS, NODE and CLIENT. */
    case CMT_P2P_SC_ST_WAIT_HELLO:
        if (sc_is_anon(sc)) {
            return sc_recv_step(sc, in, in_len, consumed,
                                CMT_P2P_SC_MSG_HELLO_ANON, CMT_P2P_SC_HELLO_ANON_BODY);
        }
        return sc_recv_step(sc, in, in_len, consumed,
                            CMT_P2P_SC_MSG_HELLO, CMT_P2P_SC_HELLO_BODY);
    case CMT_P2P_SC_ST_WAIT_HELLO_R:
        if (sc_is_anon(sc)) {
            return sc_recv_hs_msg(sc, in, in_len, consumed,
                                  CMT_P2P_SC_MSG_HELLO_R_ANON, CMT_P2P_SC_HELLO_R_ANON_BODY,
                                  sc->anon_hs_buf, sizeof(sc->anon_hs_buf));
        }
        return sc_recv_step(sc, in, in_len, consumed,
                            CMT_P2P_SC_MSG_HELLO_R, CMT_P2P_SC_HELLO_R_BODY);
    case CMT_P2P_SC_ST_WAIT_KEYX:
        return sc_recv_step(sc, in, in_len, consumed,
                            CMT_P2P_SC_MSG_KEYX, CMT_P2P_SC_KEYX_BODY);
    case CMT_P2P_SC_ST_WAIT_AUTHSIG:
        return sc_recv_authsig(sc, in, in_len, consumed);
    case CMT_P2P_SC_ST_WAIT_CONFIRM:
        return sc_recv_confirm(sc, in, in_len, consumed);
    default:
        return sc_die(sc, CMT_FAULT);
    }
}

const cmt_p2p_sc_job_t *cmt_p2p_sc_job(const cmt_p2p_sc_t *sc)
{
    if (sc == NULL || sc->state != CMT_P2P_SC_ST_JOB) {
        return NULL;
    }
    return &sc->job;
}

/* :124 computeDHSecret (:368-376) → Encaps/Decaps; :163 signChallenge
 * (:389-395); :178 VerifySignature. */
int cmt_p2p_sc_job_run(const cmt_p2p_sc_job_t *job,
                       const cmt_p2p_sc_host_t *host)
{
    if (job == NULL) {
        return -1;
    }
    switch (job->kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        if (job->kem_pk == NULL || job->kem_ct_out == NULL || job->kem_ss_out == NULL) {
            return -1;
        }
        return qgp_mlkem1024_encapsulate(job->kem_ct_out, job->kem_ss_out, job->kem_pk);
    case CMT_P2P_SC_JOB_DECAPS:
        if (job->kem_ct == NULL || job->kem_sk == NULL || job->kem_ss_out == NULL) {
            return -1;
        }
        return qgp_mlkem1024_decapsulate(job->kem_ss_out, job->kem_ct, job->kem_sk);
    case CMT_P2P_SC_JOB_SIGN:
        if (host == NULL || host->sign == NULL || job->msg == NULL || job->sig_out == NULL) {
            return -1;
        }
        return host->sign(host->ctx, job->msg, job->msg_len, job->sig_out);
    case CMT_P2P_SC_JOB_VERIFY:
        if (host == NULL || host->verify == NULL || job->msg == NULL ||
            job->sig == NULL || job->dsa_pk == NULL) {
            return -1;
        }
        return host->verify(host->ctx, job->sig, job->msg, job->msg_len, job->dsa_pk);
    case CMT_P2P_SC_JOB_VERIFY_KC:
        /* The certificate has its own host entry: purpose 0x0E, never the
         * session-auth verify. */
        if (host == NULL || host->verify_kc == NULL || job->msg == NULL ||
            job->sig == NULL || job->dsa_pk == NULL ||
            job->msg_len != CMT_P2P_SC_KC_MSG_SIZE) {
            return -1;
        }
        return host->verify_kc(host->ctx, job->sig, job->msg, job->msg_len, job->dsa_pk);
    case CMT_P2P_SC_JOB_NONE:
    default:
        return -1;
    }
}

/** Row 3 (I) — KEYX { ct } after Encaps. */
static int sc_queue_keyx(cmt_p2p_sc_t *sc)
{
    uint8_t msg[CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_KEYX_BODY];
    size_t o = put_uvarint(msg, CMT_P2P_SC_KEYX_BODY);

    msg[o++] = CMT_P2P_SC_MSG_KEYX;
    memcpy(msg + o, sc->ct, CMT_P2P_SC_KEM_CT_SIZE);
    o += CMT_P2P_SC_KEM_CT_SIZE;
    return out_push(sc, msg, o);
}

/** :169 shareAuthSignature, the writing half (:406-416): the delimited
 *  AUTHSIG through the sealed stream. */
static int sc_queue_authsig(cmt_p2p_sc_t *sc)
{
    uint8_t msg[CMT_P2P_SC_AUTHSIG_WIRE_MAX];
    uint8_t sealed[CMT_P2P_SC_AUTHSIG_FRAMES_MAX * CMT_P2P_SC_SEALED_FRAME_SIZE];
    size_t o = put_uvarint(msg, CMT_P2P_SC_AUTHSIG_BODY);
    size_t sealed_len = 0;
    int rc;

    msg[o++] = CMT_P2P_SC_MSG_AUTHSIG;
    memcpy(msg + o, sc->local_sig, CMT_P2P_SC_SIG_SIZE);
    o += CMT_P2P_SC_SIG_SIZE;

    /* A fresh key: send_counter is 0, the room check cannot fail. */
    if (!sc_send_room(sc, CMT_P2P_SC_AUTHSIG_FRAMES_MAX)) {
        return CMT_REJECT;
    }
    rc = sc_seal_all(sc, msg, o, sealed, &sealed_len);
    if (rc != CMT_OK) {
        return rc;
    }
    return out_push(sc, sealed, sealed_len);
}

int cmt_p2p_sc_job_done(cmt_p2p_sc_t *sc, int job_rc)
{
    cmt_p2p_sc_job_kind_t kind;
    int rc;

    if (sc == NULL) {
        return CMT_FAULT;
    }
    if (sc->state == CMT_P2P_SC_ST_DEAD) {
        return CMT_REJECT;
    }
    if (sc->state != CMT_P2P_SC_ST_JOB) {
        return sc_die(sc, CMT_FAULT);
    }
    kind = sc->job.kind;
    memset(&sc->job, 0, sizeof(sc->job));

    switch (kind) {
    case CMT_P2P_SC_JOB_ENCAPS:
        /* :124-127 — Encaps error = handshake error. This includes the
         * FIPS 203 §7.2 ek check of R_mlkem_pk. */
        if (job_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "ML-KEM-1024 Encaps failed (peer key refused)");
            return sc_die(sc, CMT_REJECT);
        }
        rc = sc_derive(sc);
        if (rc == CMT_OK) {
            rc = sc_queue_keyx(sc);
        }
        if (rc != CMT_OK) {
            return sc_die(sc, rc);
        }
        if (sc_is_anon(sc)) {
            /* ANON: no signature on either side; the node's CONFIRM is the
             * next thing to arrive (design §1.5 step 4). */
            sc->state = CMT_P2P_SC_ST_WAIT_CONFIRM;
            return CMT_OK;
        }
        sc_issue(sc, CMT_P2P_SC_JOB_SIGN);
        return CMT_OK;

    case CMT_P2P_SC_JOB_DECAPS:
        /* Decaps fails only on a malformed dk (§7.3 hash check), which is
         * ours → local fault. A wrong ct is NOT an error (implicit
         * rejection, design §2.3): the AUTHSIG open catches it. */
        if (job_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "ML-KEM-1024 Decaps failed");
            return sc_die(sc, CMT_FAULT);
        }
        rc = sc_derive(sc);
        if (rc != CMT_OK) {
            return sc_die(sc, rc);
        }
        if (sc_is_anon(sc)) {
            /* ANON: the node proves it holds the KEM secret by sending the
             * first sealed CONFIRM (design §1.5 step 4c), then waits for the
             * client's. */
            rc = sc_queue_confirm(sc);
            if (rc != CMT_OK) {
                return sc_die(sc, rc);
            }
            sc->state = CMT_P2P_SC_ST_WAIT_CONFIRM;
            return CMT_OK;
        }
        sc_issue(sc, CMT_P2P_SC_JOB_SIGN);
        return CMT_OK;

    case CMT_P2P_SC_JOB_VERIFY_KC:
        /* Both the certificate and the caller's pin, before any ENCAPS. */
        if (job_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "KEM-key certificate verification failed");
            return sc_die(sc, CMT_REJECT);
        }
        if (!sc->anon_pin_ok) {
            QGP_LOG_ERROR(LOG_TAG, "KEM-key certificate checked before the pin was accepted");
            return sc_die(sc, CMT_REJECT);
        }
        sc_issue(sc, CMT_P2P_SC_JOB_ENCAPS);
        return CMT_OK;

    case CMT_P2P_SC_JOB_SIGN:
        /* :163-166 */
        if (job_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "signing the challenge failed");
            return sc_die(sc, CMT_FAULT);
        }
        rc = sc_queue_authsig(sc);
        if (rc != CMT_OK) {
            return sc_die(sc, rc);
        }
        sc->state = CMT_P2P_SC_ST_WAIT_AUTHSIG;
        return CMT_OK;

    case CMT_P2P_SC_JOB_VERIFY:
        /* :178-180 */
        if (job_rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "challenge verification failed");
            return sc_die(sc, CMT_REJECT);
        }
        /* :182-184 "We've authorized." */
        qgp_secure_memzero(sc->challenge, sizeof(sc->challenge));
        sc->state = CMT_P2P_SC_ST_AUTHENTICATED;
        return CMT_OK;

    case CMT_P2P_SC_JOB_NONE:
    default:
        return sc_die(sc, CMT_FAULT);
    }
}

void cmt_p2p_sc_abort(cmt_p2p_sc_t *sc)
{
    if (sc != NULL) {
        (void)sc_die(sc, CMT_REJECT);
    }
}

const uint8_t *cmt_p2p_sc_out(const cmt_p2p_sc_t *sc, size_t *len)
{
    if (len != NULL) {
        *len = 0;
    }
    if (sc == NULL || len == NULL) {
        return NULL;
    }
    *len = sc->out_len;
    return sc->out + sc->out_off;
}

void cmt_p2p_sc_out_consume(cmt_p2p_sc_t *sc, size_t n)
{
    if (sc == NULL) {
        return;
    }
    if (n >= sc->out_len) {
        sc->out_off = 0;
        sc->out_len = 0;
        return;
    }
    sc->out_off += n;
    sc->out_len -= n;
}

bool cmt_p2p_sc_is_authenticated(const cmt_p2p_sc_t *sc)
{
    return sc != NULL && sc->state == CMT_P2P_SC_ST_AUTHENTICATED;
}

/* :187-190 RemotePubKey */
const uint8_t *cmt_p2p_sc_remote_pubkey(const cmt_p2p_sc_t *sc)
{
    if (sc == NULL || sc->state == CMT_P2P_SC_ST_DEAD) {
        return NULL;
    }
    if (sc->role == CMT_P2P_SC_ROLE_INITIATOR) {
        return (sc->state == CMT_P2P_SC_ST_WAIT_HELLO_R) ? NULL : sc->r_dsa_pk;
    }
    /* An ANON-bound responder has no peer key — the error return, in every
     * state; an UNBOUND one has none until its first message. */
    if (sc_is_anon(sc) || sc->state == CMT_P2P_SC_ST_WAIT_FIRST) {
        return NULL;
    }
    return (sc->state == CMT_P2P_SC_ST_WAIT_HELLO) ? NULL : sc->i_dsa_pk;
}

int cmt_p2p_sc_anon_pin_accepted(cmt_p2p_sc_t *sc)
{
    if (sc == NULL || sc->state != CMT_P2P_SC_ST_JOB ||
        sc->role != CMT_P2P_SC_ROLE_INITIATOR || !sc_is_anon(sc) ||
        sc->job.kind != CMT_P2P_SC_JOB_VERIFY_KC) {
        return CMT_FAULT;
    }
    sc->anon_pin_ok = true;
    return CMT_OK;
}

bool cmt_p2p_sc_is_anon(const cmt_p2p_sc_t *sc)
{
    /* A dead machine reports false: a first message whose length bound the
     * ANON family but whose kind then contradicted it is REJECTed, and the
     * dead machine must not look like an ANON session. */
    return sc != NULL && sc->state != CMT_P2P_SC_ST_DEAD && sc_is_anon(sc);
}

const uint8_t *cmt_p2p_sc_transcript(const cmt_p2p_sc_t *sc)
{
    if (sc == NULL || sc->state != CMT_P2P_SC_ST_AUTHENTICATED) {
        return NULL;
    }
    return sc->t;
}

/* ══ secret_connection.go:192-229 — Write ════════════════════════════ */

int cmt_p2p_sc_write(cmt_p2p_sc_t *sc, const uint8_t *data, size_t len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint64_t nframes;
    int rc;

    if (out_len != NULL) {
        *out_len = 0;
    }
    if (sc == NULL || out_len == NULL || (data == NULL && len > 0) ||
        (out == NULL && len > 0)) {
        return CMT_FAULT;
    }
    if (sc->state == CMT_P2P_SC_ST_DEAD) {
        return CMT_REJECT;
    }
    if (sc->state != CMT_P2P_SC_ST_AUTHENTICATED) {
        QGP_LOG_ERROR(LOG_TAG, "write before the session is authenticated");
        return sc_die(sc, CMT_REJECT);
    }
    if (len == 0) {
        return CMT_OK;                                      /* :199 */
    }
    nframes = (uint64_t)((len + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE);
    if (nframes > (uint64_t)(out_cap / CMT_P2P_SC_SEALED_FRAME_SIZE)) {
        return CMT_FAULT;                   /* caller's buffer; nothing sealed */
    }
    if (!sc_send_room(sc, nframes)) {
        /* :455-458 "can't increase nonce without overflow" — N3: nothing
         * sealed, the session ends. */
        QGP_LOG_ERROR(LOG_TAG, "send counter at its limit");
        return sc_die(sc, CMT_REJECT);
    }
    rc = sc_seal_all(sc, data, len, out, out_len);
    if (rc != CMT_OK) {
        *out_len = 0;
        return sc_die(sc, rc);
    }
    return CMT_OK;
}

/* ══ secret_connection.go:231-273 — Read ═════════════════════════════ */

int cmt_p2p_sc_read(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                    size_t *consumed, uint8_t *data, size_t data_cap,
                    size_t *n)
{
    uint8_t frame[CMT_P2P_SC_TOTAL_FRAME_SIZE];
    const uint8_t *chunk = NULL;
    size_t chunk_len = 0;
    size_t give;
    int rc;

    if (consumed != NULL) {
        *consumed = 0;
    }
    if (n != NULL) {
        *n = 0;
    }
    if (sc == NULL || consumed == NULL || n == NULL ||
        (in == NULL && in_len > 0) || (data == NULL && data_cap > 0)) {
        return CMT_FAULT;
    }
    if (sc->state == CMT_P2P_SC_ST_DEAD) {
        return CMT_REJECT;
    }
    if (sc->state != CMT_P2P_SC_ST_AUTHENTICATED) {
        QGP_LOG_ERROR(LOG_TAG, "read before the session is authenticated");
        return sc_die(sc, CMT_REJECT);
    }

    /* :236-241 — serve recvBuffer first */
    if (sc->recv_len > 0) {
        give = (sc->recv_len < data_cap) ? sc->recv_len : data_cap;
        memcpy(data, sc->recv_buf + sc->recv_off, give);
        sc->recv_off += give;
        sc->recv_len -= give;
        if (sc->recv_len == 0) {
            sc->recv_off = 0;
        }
        *n = give;
        return CMT_OK;
    }

    /* :243-248 */
    if (!sc_fill_sealed(sc, in, in_len, consumed)) {
        return CMT_OK;                                      /* need more */
    }
    /* :250-265 */
    rc = sc_open_frame(sc, frame, &chunk, &chunk_len);
    if (rc != CMT_OK) {
        qgp_secure_memzero(frame, sizeof(frame));
        return sc_die(sc, rc);
    }
    /* :267-271 */
    give = (chunk_len < data_cap) ? chunk_len : data_cap;
    if (give > 0) {
        memcpy(data, chunk, give);
    }
    if (give < chunk_len) {
        memcpy(sc->recv_buf, chunk + give, chunk_len - give);
        sc->recv_off = 0;
        sc->recv_len = chunk_len - give;
    }
    *n = give;
    qgp_secure_memzero(frame, sizeof(frame));
    return CMT_OK;
}

size_t cmt_p2p_sc_read_pending(const cmt_p2p_sc_t *sc)
{
    if (sc == NULL || sc->state != CMT_P2P_SC_ST_AUTHENTICATED) {
        return 0;
    }
    return sc->recv_len;
}

void cmt_p2p_sc_clear(cmt_p2p_sc_t *sc)
{
    if (sc != NULL) {
        qgp_secure_memzero(sc, sizeof(*sc));
    }
}
