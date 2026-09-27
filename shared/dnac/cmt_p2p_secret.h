/**
 * @file shared/dnac/cmt_p2p_secret.h
 * @brief cometbft @709fd12b `p2p/conn/secret_connection.go` ported to C —
 *        the authenticated, encrypted connection every 4004 peer link runs
 *        inside.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Phase F1 of fleet P2P-PORT (docs/plans/2026-09-26-p2p-port-design.md
 * §2 row 1, §9). Nothing in the running node constructs a
 * `cmt_p2p_sc_t` yet — the transport (F3, cmt_p2p_transport) is its first
 * consumer. Additive only; 4001/4002 and today's 4004 path are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * Governing records: docs/plans/decisions/2026-09-26-witness-port-session.md
 * (ML-KEM-1024 only, static keys, reference order with one signature per
 * side, tags `nodus.wsess.transcript.v1` / `nodus.wsess.keys.v1`, purpose
 * 0x0A, one SHA3-512 transcript, two HKDF calls, N9 bytes, AES-256-GCM on
 * the 1024-byte frame) and the session design
 * docs/plans/2026-09-26-witness-port-session-design.md §2.1 rows 1-11,
 * §2.3, §2R (R1, R5, R7, R8), §2R3 (N3, N9).
 *
 * ── WHAT THE REFERENCE DOES (:95-186) AND WHAT THIS DOES ───────────────
 * `MakeSecretConnection` is ONE blocking call: swap ephemeral X25519 keys,
 * derive keys and a challenge from a merlin transcript, sign the
 * challenge, swap the signatures inside the new encrypted channel, verify.
 * Here the same steps are a STATE MACHINE fed bytes and producing bytes —
 * no socket inside, the caller owns every read and write:
 *
 *   `cmt_p2p_sc_recv`   ← bytes the caller read from the socket
 *   `cmt_p2p_sc_out`    → bytes the caller must write to the socket
 *   `cmt_p2p_sc_job`    → the ONE asymmetric operation the machine waits
 *                         for (Encaps / Decaps / Sign / Verify), or NULL
 *   `cmt_p2p_sc_job_run` runs a job — touches ONLY the job, never the
 *                         machine, so it may run on a worker thread
 *                         (deviation R-P2P-8, the F3 transport's bounded
 *                         worker); F1's tests call it inline
 *   `cmt_p2p_sc_job_done` hands the job's result back to the machine
 *
 * While a job is outstanding, `cmt_p2p_sc_recv` consumes NOTHING (the
 * session design §2R3 N1 "HOLD"): the caller keeps the unconsumed bytes
 * and offers them again after `cmt_p2p_sc_job_done`. That is the event
 * loop form of the reference's blocking wait — `MakeSecretConnection`
 * reads the peer's AUTHSIG only after it has signed (:163-169) and returns
 * only after verifying it (:178-184) — so the outcome never depends on how
 * the peer's bytes were split into TCP reads.
 *
 * ── THE HANDSHAKE (DEVIATION R-P2P-9, operator-approved) ───────────────
 * Row numbers are the session design §2.1 table.
 *   I = initiator (dialed), R = responder (accepted).
 *   1-2  I→R HELLO   { I_dsa_pk(2592), nonce_I(32), proto_ver(u32 BE),
 *                      chain_id(32) }
 *        R→I HELLO_R { R_dsa_pk(2592), R_mlkem_pk(1568), nonce_R(32),
 *                      proto_ver(u32 BE), chain_id(32) }
 *        (reference :106 shareEphPubKey; N9 adds proto_ver + chain_id —
 *        R-P2P-10). Each side checks the peer's proto_ver and chain_id
 *        against its own BEFORE any KEM work.
 *   3    I: (ct, ss) = ML-KEM-1024.Encaps(R_mlkem_pk); I→R KEYX { ct(1568) }
 *        R: ss = ML-KEM-1024.Decaps(ct, R_mlkem_sk)  (reference :124)
 *   4    T = SHA3-512( TAG_T ‖ I_dsa_pk ‖ R_dsa_pk ‖ R_mlkem_pk ‖
 *                      proto_ver_I ‖ chain_id_I ‖ proto_ver_R ‖ chain_id_R ‖
 *                      nonce_I ‖ nonce_R ‖ ct )
 *        TAG_T = ASCII "nodus.wsess.transcript.v1", strlen bytes, no NUL
 *        (reference :114-129 merlin transcript)
 *   5-6  key       = HKDF-SHA3-256(salt = T, ikm = ss,
 *                                  info = "nodus.wsess.keys.v1/aead")
 *        challenge = HKDF-SHA3-256(salt = T, ikm = ss,
 *                                  info = "nodus.wsess.keys.v1/challenge")
 *        (reference :134 deriveSecrets, :138 challenge). ONE key; the
 *        direction lives in the nonce's role byte (design row 5).
 *   7    each side signs the challenge under the strict purpose 0x0A
 *        NODUS_PURPOSE_SESSION_AUTH — through the HOST (`sign`), so this
 *        file never sees a secret signing key (reference :163)
 *   8    AUTHSIG { sig(4627) } is the first thing each side writes into the
 *        sealed stream (reference :169). 4627 bytes do not fit one
 *        1024-byte frame: AUTHSIG occupies the first FIVE sealed frames of
 *        each direction (4 × 1024 + 534). Until those bytes are in, no
 *        other sealed data is accepted (session design R1).
 *   9    verify the peer's AUTHSIG over the challenge with the dsa pk that
 *        went into T, through the host (`verify`) (reference :178). Only
 *        then is the session AUTHENTICATED (R1); no caller data is sealed
 *        or opened before that.
 *   10   THE PIN IS THE CALLER'S (reference :58-60). When the initiator
 *        holds a job of kind ENCAPS, `cmt_p2p_sc_remote_pubkey` already
 *        returns R's claimed dsa pk: a caller dialing a known identity
 *        compares it and calls `cmt_p2p_sc_abort` instead of running the
 *        job — row 10's "BEFORE step 3". An unpinned dial (session design
 *        R11) just runs the job.
 *
 * Every plaintext handshake message is ONE message accepted ONCE, in
 * order; a message of the wrong kind or the wrong length for the current
 * step is a REJECT before any KEM work (R8).
 *
 * ⚠ NOT GROUNDED — the message ENCODING (no approved record fixes it):
 * each handshake message is `uvarint(len) ‖ kind(1) ‖ fields`, the
 * length-delimited framing the reference uses for these messages (protoio
 * delimited writer/reader, :305 / :313 / :411 / :419) with a fixed-layout
 * body instead of a protobuf message (there is no proto for HELLO/HELLO_R/
 * KEYX). The reference's reader cap is 1 MiB (:313); here the length must
 * EQUAL the one message the current step expects (session design §2R4 P3:
 * a pre-session buffer is capped at the largest handshake message). The
 * kind bytes are CMT_P2P_SC_MSG_* below. The AUTHSIG carried in the sealed
 * stream uses the same framing (the reference writes it delimited through
 * the SecretConnection, :411).
 *
 * ── THE SEALED FRAME (:194-273, DEVIATION R-P2P-1) ─────────────────────
 *   frame  = chunkLength (u32 LITTLE-endian, :210) ‖ chunk ‖ zero pad
 *            → CMT_P2P_SC_TOTAL_FRAME_SIZE = 1028 bytes (:32-36)
 *   sealed = AES-256-GCM(key, nonce, frame) = 1028 + 16-byte tag
 *            → CMT_P2P_SC_SEALED_FRAME_SIZE = 1044 bytes, always
 * ChaCha20-Poly1305 → AES-256-GCM (NIST SP 800-38D, pinned
 * .claude/ref/pinned-ref-files/) is R-P2P-1. The pad after `chunk` is
 * zeroed; the reference reuses `sendFrame` (:197, :211) and seals whatever
 * the previous chunk left there — the receiver never reads it (:266), the
 * frame size is unchanged, only its content is.
 *
 * The NONCE is implicit, as in the reference (:214, :253: never on the
 * wire). Each side counts its own sends and receives:
 *   nonce(12) = role(1) ‖ 0x00 0x00 0x00 ‖ counter (u64 BIG-endian)
 * role = CMT_P2P_SC_ROLE_INITIATOR (0x01) for I→R frames and
 * CMT_P2P_SC_ROLE_RESPONDER (0x02) for R→I frames — the same values and the
 * same "never 0x00" rule as nodus_channel_crypto.h's nodus_channel_role_t.
 * The receiver builds the nonce it EXPECTS (peer role, its receive
 * counter), so a replayed, dropped, reordered or reflected frame fails the
 * GCM tag: exact counter, no gaps, opposite role only (session design R5,
 * N3) — by construction, with no wire field to parse.
 * ⚠ NOT GROUNDED — the nonce byte layout: the design says "role byte ‖
 * 64-bit counter" (p2p-port design §2 row 1) and the dispatch says big-
 * endian; the 3 zero bytes sit where the reference leaves its 4 unused
 * bytes (:450-452), which is also SP 800-38D §8.2.1's suggested
 * "fixed field leading" form (fixed field = 4 bytes, invocation field =
 * 8 bytes).
 *
 * Counter overflow (reference :453-462 panics when a counter at
 * MaxUint64 is incremented — the frame at MaxUint64 was already sealed):
 * here a counter AT UINT64_MAX refuses to seal and refuses to open — one
 * frame earlier than the reference, per session design N3 ("refuse to
 * encrypt at UINT64_MAX, refuse a received UINT64_MAX"). A multi-frame
 * write that would cross it seals NOTHING.
 *
 * ── ERRORS ─────────────────────────────────────────────────────────────
 * CMT_OK; CMT_REJECT = the peer (or the caller's input) broke the
 * protocol — the machine is DEAD from then on, every later call returns
 * CMT_REJECT, and the caller closes the connection (the reference returns
 * an error from MakeSecretConnection / Read and the connection is
 * stopped); CMT_FAULT = a NULL argument or a local crypto backend failure.
 * A CMT_FAULT during the handshake also kills the machine.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Nothing here is consensus state (p2p-port design §6 D1): nonces, keys
 * and counters are node-local transport. Randomness (nonce_I / nonce_R and
 * the Encaps coins) is OS randomness (`qgp_platform_random`,
 * `qgp_mlkem1024_encapsulate`) — transport-local (D4). No clock is read.
 *
 * ── SIZES ──────────────────────────────────────────────────────────────
 * The ML-DSA-87 and ML-KEM-1024 sizes are taken from shared/crypto
 * (qgp_dilithium.h, qgp_mlkem.h). nodus/include/nodus/nodus_types.h's
 * NODUS_PK_BYTES / NODUS_SIG_BYTES / NODUS_MLKEM_* are the same numbers;
 * shared/dnac must not include nodus/ (cmt_mem.h:245-256 precedent), so
 * the equality is asserted below against the cited literals and again in
 * nodus/tests/test_p2p_secret.c against the nodus constants themselves.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef CMT_P2P_SECRET_H
#define CMT_P2P_SECRET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"                    /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "crypto/enc/qgp_mlkem.h"          /* QGP_MLKEM1024_*                 */
#include "crypto/sign/qgp_dilithium.h"     /* QGP_DSA87_*                     */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ secret_connection.go:32-45 — frame constants ═════════════════════ */

#define CMT_P2P_SC_DATA_LEN_SIZE      4      /* dataLenSize   :34 */
#define CMT_P2P_SC_DATA_MAX_SIZE      1024   /* dataMaxSize   :35 */
#define CMT_P2P_SC_TOTAL_FRAME_SIZE   (CMT_P2P_SC_DATA_MAX_SIZE + \
                                       CMT_P2P_SC_DATA_LEN_SIZE)   /* :36 */
/** aeadSizeOverhead :37 — the GCM tag here (16, SP 800-38D §5.2.1.2),
 *  the Poly1305 tag in the reference (also 16). */
#define CMT_P2P_SC_AEAD_OVERHEAD      16
#define CMT_P2P_SC_SEALED_FRAME_SIZE  (CMT_P2P_SC_TOTAL_FRAME_SIZE + \
                                       CMT_P2P_SC_AEAD_OVERHEAD)   /* 1044 */
#define CMT_P2P_SC_AEAD_KEY_SIZE      32     /* aeadKeySize :38 (AES-256) */
#define CMT_P2P_SC_AEAD_NONCE_SIZE    12     /* aeadNonceSize :39 */
#define CMT_P2P_SC_CHALLENGE_SIZE     32     /* challengeSize :136 */

/* ══ Key / field sizes (R-P2P-9) ══════════════════════════════════════ */

#define CMT_P2P_SC_DSA_PK_SIZE    QGP_DSA87_PUBLICKEYBYTES           /* 2592 */
#define CMT_P2P_SC_SIG_SIZE       QGP_DSA87_SIGNATURE_BYTES          /* 4627 */
#define CMT_P2P_SC_KEM_PK_SIZE    QGP_MLKEM1024_PUBLICKEYBYTES       /* 1568 */
#define CMT_P2P_SC_KEM_SK_SIZE    QGP_MLKEM1024_SECRETKEYBYTES       /* 3168 */
#define CMT_P2P_SC_KEM_CT_SIZE    QGP_MLKEM1024_CIPHERTEXTBYTES      /* 1568 */
#define CMT_P2P_SC_KEM_SS_SIZE    QGP_MLKEM1024_SHAREDSECRET_BYTES   /* 32   */
#define CMT_P2P_SC_NONCE_SIZE     32     /* nonce_I / nonce_R (design row 2) */
#define CMT_P2P_SC_CHAIN_ID_SIZE  32     /* v3 chain id (session design N9)  */
#define CMT_P2P_SC_PROTO_VER_SIZE 4      /* u32 big-endian (N9)              */
#define CMT_P2P_SC_T_SIZE         64     /* SHA3-512 transcript (row 4)      */

_Static_assert(CMT_P2P_SC_DSA_PK_SIZE == 2592,
               "must equal NODUS_PK_BYTES (nodus/include/nodus/nodus_types.h:77)");
_Static_assert(CMT_P2P_SC_SIG_SIZE == 4627,
               "must equal NODUS_SIG_BYTES (nodus/include/nodus/nodus_types.h:79)");
_Static_assert(CMT_P2P_SC_KEM_PK_SIZE == 1568 && CMT_P2P_SC_KEM_CT_SIZE == 1568 &&
               CMT_P2P_SC_KEM_SK_SIZE == 3168 && CMT_P2P_SC_KEM_SS_SIZE == 32,
               "must equal NODUS_MLKEM_* (nodus/include/nodus/nodus_types.h:98-101)");

/* ══ Domain strings (decision record "Ayrıntı kararları"; design §2R R7) ═ */

/** Row 4 TAG_T. ASCII, strlen bytes, no NUL, no length prefix. */
#define CMT_P2P_SC_TAG_T          "nodus.wsess.transcript.v1"
/** Row 5 HKDF info for the AEAD key. */
#define CMT_P2P_SC_INFO_AEAD      "nodus.wsess.keys.v1/aead"
/** Row 5-6 HKDF info for the challenge. */
#define CMT_P2P_SC_INFO_CHALLENGE "nodus.wsess.keys.v1/challenge"

/* ══ Direction roles (nonce byte 0) ═══════════════════════════════════ */

/** Same values as nodus_channel_role_t (nodus_channel_crypto.h): never
 *  0x00, a static per-call-site constant (who dialed), never derived by
 *  comparing keys. The reference sorts the ephemeral keys instead
 *  (:112, :121, :355-361) — there are no ephemeral keys here. */
typedef enum {
    CMT_P2P_SC_ROLE_INITIATOR = 0x01,   /* dialed    */
    CMT_P2P_SC_ROLE_RESPONDER = 0x02    /* accepted  */
} cmt_p2p_sc_role_t;

/* ══ Handshake message kinds (NOT GROUNDED encoding, see file header) ══ */

#define CMT_P2P_SC_MSG_HELLO    0x01
#define CMT_P2P_SC_MSG_HELLO_R  0x02
#define CMT_P2P_SC_MSG_KEYX     0x03
#define CMT_P2P_SC_MSG_AUTHSIG  0x04

/** Body sizes (kind byte + fields), the uvarint length each must carry. */
#define CMT_P2P_SC_HELLO_BODY   (1 + CMT_P2P_SC_DSA_PK_SIZE + CMT_P2P_SC_NONCE_SIZE + \
                                 CMT_P2P_SC_PROTO_VER_SIZE + CMT_P2P_SC_CHAIN_ID_SIZE)
#define CMT_P2P_SC_HELLO_R_BODY (1 + CMT_P2P_SC_DSA_PK_SIZE + CMT_P2P_SC_KEM_PK_SIZE + \
                                 CMT_P2P_SC_NONCE_SIZE + CMT_P2P_SC_PROTO_VER_SIZE + \
                                 CMT_P2P_SC_CHAIN_ID_SIZE)
#define CMT_P2P_SC_KEYX_BODY    (1 + CMT_P2P_SC_KEM_CT_SIZE)
#define CMT_P2P_SC_AUTHSIG_BODY (1 + CMT_P2P_SC_SIG_SIZE)
/** Longest uvarint prefix any of the bodies above needs (< 2^21). */
#define CMT_P2P_SC_UVARINT_MAX  3

/** Largest plaintext handshake message on the wire (HELLO_R). */
#define CMT_P2P_SC_HS_MSG_MAX   (CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_HELLO_R_BODY)
/** The delimited AUTHSIG as written into the sealed stream. */
#define CMT_P2P_SC_AUTHSIG_WIRE_MAX (CMT_P2P_SC_UVARINT_MAX + CMT_P2P_SC_AUTHSIG_BODY)
/** Sealed frames needed for the largest possible delimited AUTHSIG. */
#define CMT_P2P_SC_AUTHSIG_FRAMES_MAX \
    ((CMT_P2P_SC_AUTHSIG_WIRE_MAX + CMT_P2P_SC_DATA_MAX_SIZE - 1) / CMT_P2P_SC_DATA_MAX_SIZE)
/** Output queue: every message one side ever queues (the initiator's
 *  HELLO, KEYX and sealed AUTHSIG) fits undrained. */
#define CMT_P2P_SC_OUT_CAP      (2 * CMT_P2P_SC_HS_MSG_MAX + \
                                 CMT_P2P_SC_AUTHSIG_FRAMES_MAX * CMT_P2P_SC_SEALED_FRAME_SIZE)

/* ══ The host (signing / verifying live outside shared/dnac) ══════════ */

/**
 * The two identity-key operations. shared/dnac does not link
 * nodus_sign.c; nodus binds these to nodus_sign_session_auth /
 * nodus_verify_session_auth (purpose 0x0A, strict).
 *
 * Both may be called from `cmt_p2p_sc_job_run`, which the F3 transport
 * runs on a worker thread (R-P2P-8): they must be safe to call there.
 */
typedef struct {
    void *ctx;
    /** secret_connection.go:389-395 signChallenge — sign `msg` with the
     *  local identity key under NODUS_PURPOSE_SESSION_AUTH. Writes exactly
     *  CMT_P2P_SC_SIG_SIZE bytes. @return 0 on success, non-zero on error. */
    int (*sign)(void *ctx, const uint8_t *msg, size_t msg_len,
                uint8_t sig_out[CMT_P2P_SC_SIG_SIZE]);
    /** :178 `remPubKey.VerifySignature(challenge, remSignature)` under
     *  NODUS_PURPOSE_SESSION_AUTH. @return 0 if valid, non-zero otherwise. */
    int (*verify)(void *ctx, const uint8_t sig[CMT_P2P_SC_SIG_SIZE],
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t pk[CMT_P2P_SC_DSA_PK_SIZE]);
} cmt_p2p_sc_host_t;

/* ══ The asymmetric job (R-P2P-8) ═════════════════════════════════════ */

typedef enum {
    CMT_P2P_SC_JOB_NONE = 0,
    CMT_P2P_SC_JOB_ENCAPS,   /* I, row 3: (ct, ss) = Encaps(R_mlkem_pk)   */
    CMT_P2P_SC_JOB_DECAPS,   /* R, row 3: ss = Decaps(ct, R_mlkem_sk)     */
    CMT_P2P_SC_JOB_SIGN,     /* both, row 7                               */
    CMT_P2P_SC_JOB_VERIFY    /* both, row 9                               */
} cmt_p2p_sc_job_kind_t;

/**
 * One outstanding asymmetric operation. Every pointer points into the
 * machine that issued it and stays valid until `cmt_p2p_sc_job_done` or
 * `cmt_p2p_sc_abort` on that machine; the machine does not touch these
 * buffers meanwhile. Unused pointers are NULL.
 */
typedef struct {
    cmt_p2p_sc_job_kind_t kind;
    /* inputs */
    const uint8_t *kem_pk;     /* ENCAPS: R_mlkem_pk                       */
    const uint8_t *kem_ct;     /* DECAPS: the KEYX ciphertext              */
    const uint8_t *kem_sk;     /* DECAPS: the local ML-KEM secret key      */
    const uint8_t *msg;        /* SIGN / VERIFY: the challenge             */
    size_t         msg_len;
    const uint8_t *dsa_pk;     /* VERIFY: the peer's pk that went into T   */
    const uint8_t *sig;        /* VERIFY: the peer's AUTHSIG               */
    /* outputs */
    uint8_t       *kem_ct_out; /* ENCAPS                                   */
    uint8_t       *kem_ss_out; /* ENCAPS / DECAPS                          */
    uint8_t       *sig_out;    /* SIGN                                     */
} cmt_p2p_sc_job_t;

/* ══ The connection ═══════════════════════════════════════════════════ */

typedef enum {
    CMT_P2P_SC_ST_DEAD = 0,          /* rejected / faulted / aborted       */
    CMT_P2P_SC_ST_WAIT_HELLO,        /* R: expecting HELLO                 */
    CMT_P2P_SC_ST_WAIT_HELLO_R,      /* I: HELLO sent, expecting HELLO_R   */
    CMT_P2P_SC_ST_WAIT_KEYX,         /* R: HELLO_R sent, expecting KEYX    */
    CMT_P2P_SC_ST_JOB,               /* an asymmetric job is outstanding   */
    CMT_P2P_SC_ST_WAIT_AUTHSIG,      /* own AUTHSIG sent, reading the peer's */
    CMT_P2P_SC_ST_AUTHENTICATED      /* row 9 passed: Read/Write open      */
} cmt_p2p_sc_state_t;

/**
 * secret_connection.go:62-88 `SecretConnection` + the handshake's locals.
 * Large (≈ 40 KB): allocate on the heap or statically, never on a stack.
 * The two mutexes (:78, :84) are dropped — one event loop owns the
 * machine; only `cmt_p2p_sc_job_run` may run elsewhere, and it touches
 * the job's buffers only.
 */
typedef struct {
    cmt_p2p_sc_state_t state;
    cmt_p2p_sc_role_t  role;
    const cmt_p2p_sc_host_t *host;

    /* ── N9 fields, ours ── */
    uint32_t proto_ver;
    uint8_t  chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];

    /* ── transcript inputs, indexed by ROLE (I / R), not local / remote ── */
    uint8_t  i_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE];
    uint8_t  r_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE];
    uint8_t  r_kem_pk[CMT_P2P_SC_KEM_PK_SIZE];
    uint8_t  i_proto_ver[CMT_P2P_SC_PROTO_VER_SIZE];
    uint8_t  i_chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];
    uint8_t  r_proto_ver[CMT_P2P_SC_PROTO_VER_SIZE];
    uint8_t  r_chain_id[CMT_P2P_SC_CHAIN_ID_SIZE];
    uint8_t  nonce_i[CMT_P2P_SC_NONCE_SIZE];
    uint8_t  nonce_r[CMT_P2P_SC_NONCE_SIZE];
    uint8_t  ct[CMT_P2P_SC_KEM_CT_SIZE];

    const uint8_t *local_kem_sk;     /* R only; caller-owned, outlives us */

    /* ── derived ── */
    uint8_t  ss[CMT_P2P_SC_KEM_SS_SIZE];
    uint8_t  key[CMT_P2P_SC_AEAD_KEY_SIZE];
    uint8_t  challenge[CMT_P2P_SC_CHALLENGE_SIZE];
    uint8_t  local_sig[CMT_P2P_SC_SIG_SIZE];
    uint8_t  remote_sig[CMT_P2P_SC_SIG_SIZE];

    /* ── the job ── */
    cmt_p2p_sc_job_t job;

    /* ── nonces (:80, :85) as counters; public so a test can stand one
     *    at UINT64_MAX (the reference's overflow, :453-462) ── */
    uint64_t send_counter;
    uint64_t recv_counter;

    /* ── plaintext handshake message assembly (pre-key) ── */
    uint8_t  hs_buf[CMT_P2P_SC_HS_MSG_MAX];
    size_t   hs_len;

    /* ── sealed-frame assembly (:245 io.ReadFull of recvSealedFrame) ── */
    uint8_t  sealed_buf[CMT_P2P_SC_SEALED_FRAME_SIZE];
    size_t   sealed_len;

    /* ── recvBuffer (:79, :237-241, :268-271) ── */
    uint8_t  recv_buf[CMT_P2P_SC_DATA_MAX_SIZE];
    size_t   recv_off;
    size_t   recv_len;

    /* ── the peer's AUTHSIG, reassembled from the sealed stream ── */
    uint8_t  authsig_buf[CMT_P2P_SC_AUTHSIG_WIRE_MAX];
    size_t   authsig_len;

    /* ── bytes the caller must write ── */
    uint8_t  out[CMT_P2P_SC_OUT_CAP];
    size_t   out_off;
    size_t   out_len;
} cmt_p2p_sc_t;

/* ══ secret_connection.go:95-186 — MakeSecretConnection as a machine ══ */

/**
 * Start a handshake. The INITIATOR queues its HELLO (read it with
 * `cmt_p2p_sc_out`); the RESPONDER waits for one.
 *
 * @param local_dsa_pk  our ML-DSA-87 identity public key (copied)
 * @param local_kem_pk  RESPONDER: our ML-KEM-1024 public key (copied);
 *                      INITIATOR: must be NULL (row 1: only R's static
 *                      KEM key is used)
 * @param local_kem_sk  RESPONDER: our ML-KEM-1024 secret key — NOT copied,
 *                      the caller keeps it alive for the machine's life;
 *                      INITIATOR: must be NULL
 * @param proto_ver     our protocol version (N9)
 * @param chain_id      our 32-byte v3 chain id (N9)
 * @return CMT_OK; CMT_FAULT on a NULL / inconsistent argument or an RNG
 *         failure (session design N6: an RNG failure closes the handshake)
 */
int cmt_p2p_sc_init(cmt_p2p_sc_t *sc, cmt_p2p_sc_role_t role,
                    const cmt_p2p_sc_host_t *host,
                    const uint8_t local_dsa_pk[CMT_P2P_SC_DSA_PK_SIZE],
                    const uint8_t *local_kem_pk,
                    const uint8_t *local_kem_sk,
                    uint32_t proto_ver,
                    const uint8_t chain_id[CMT_P2P_SC_CHAIN_ID_SIZE]);

/**
 * Feed bytes read from the connection during the handshake. Consumes as
 * much as the current step needs and stops: at a pending job (HOLD), or
 * once the session is authenticated (every later byte belongs to
 * `cmt_p2p_sc_read`). `*consumed` is always set; the caller keeps the
 * rest and offers it again.
 * @return CMT_OK; CMT_REJECT (machine dead); CMT_FAULT.
 */
int cmt_p2p_sc_recv(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                    size_t *consumed);

/** The outstanding job, or NULL when the machine is not waiting for one. */
const cmt_p2p_sc_job_t *cmt_p2p_sc_job(const cmt_p2p_sc_t *sc);

/**
 * Run a job. Touches only `job`'s buffers and `host`; never the machine.
 * ENCAPS = qgp_mlkem1024_encapsulate (FIPS 203 §7.2 ek check included),
 * DECAPS = qgp_mlkem1024_decapsulate — ML-KEM-1024 ONLY, never the
 * round-3 API (decision record, "İKİ KEM VAR").
 * @return 0 on success (VERIFY: signature valid), non-zero otherwise.
 */
int cmt_p2p_sc_job_run(const cmt_p2p_sc_job_t *job,
                       const cmt_p2p_sc_host_t *host);

/**
 * Hand the job's result back. `job_rc` is `cmt_p2p_sc_job_run`'s return
 * (or the caller's own run of the same operation). Non-zero kills the
 * machine (:125, :164, :178-180 return the error). A failed Encaps is
 * CMT_REJECT — it includes the FIPS 203 §7.2 check of the PEER's
 * R_mlkem_pk; a failed Decaps (only a malformed local dk) or Sign is
 * CMT_FAULT; a failed Verify is CMT_REJECT.
 * @return CMT_OK; CMT_REJECT; CMT_FAULT (also when no job is outstanding).
 */
int cmt_p2p_sc_job_done(cmt_p2p_sc_t *sc, int job_rc);

/** Kill the machine (the caller's pin failed, a deadline passed, …). */
void cmt_p2p_sc_abort(cmt_p2p_sc_t *sc);

/** Bytes to write to the connection: pointer + length (0 = nothing). */
const uint8_t *cmt_p2p_sc_out(const cmt_p2p_sc_t *sc, size_t *len);
/** The caller wrote `n` of them. */
void cmt_p2p_sc_out_consume(cmt_p2p_sc_t *sc, size_t n);

/** Row 9 passed (session design R1 `session_authenticated`). */
bool cmt_p2p_sc_is_authenticated(const cmt_p2p_sc_t *sc);
/** :187-190 RemotePubKey. Once HELLO / HELLO_R has been accepted this is
 *  the peer's CLAIMED key (what went into T); it is AUTHENTICATED only
 *  when `cmt_p2p_sc_is_authenticated`. NULL before that message. */
const uint8_t *cmt_p2p_sc_remote_pubkey(const cmt_p2p_sc_t *sc);

/* ══ secret_connection.go:192-273 — Write / Read ══════════════════════ */

/**
 * :194-229 Write — seal `data` as ceil(len / 1024) frames into `out`
 * (each CMT_P2P_SC_SEALED_FRAME_SIZE bytes, in order). Nothing is sealed
 * and no counter moves unless every frame fits `out_cap` and the send
 * counter can take them all (N3). `len == 0` writes nothing (the
 * reference's loop does not run, :199).
 * @return CMT_OK; CMT_REJECT before authentication or at the counter
 *         limit (machine dead); CMT_FAULT on NULL, a too-small `out_cap`
 *         (machine left intact), or a cipher failure.
 */
int cmt_p2p_sc_write(cmt_p2p_sc_t *sc, const uint8_t *data, size_t len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * :232-273 Read — the reference reads ONE sealed frame per call and hands
 * back its chunk, keeping what does not fit `data` in recvBuffer. Here:
 * first serve recvBuffer; otherwise take bytes from `in` until a sealed
 * frame is complete (`*consumed` says how many), open it and return its
 * chunk. `*n == 0` with CMT_OK = need more bytes.
 * @return CMT_OK; CMT_REJECT on an open failure / chunkLength > 1024 /
 *         counter limit / not authenticated (machine dead); CMT_FAULT.
 */
int cmt_p2p_sc_read(cmt_p2p_sc_t *sc, const uint8_t *in, size_t in_len,
                    size_t *consumed, uint8_t *data, size_t data_cap,
                    size_t *n);

/** Zero every key, secret and buffer. */
void cmt_p2p_sc_clear(cmt_p2p_sc_t *sc);

#ifdef __cplusplus
}
#endif

#endif /* CMT_P2P_SECRET_H */
