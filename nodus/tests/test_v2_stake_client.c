/**
 * @file nodus/tests/test_v2_stake_client.c
 * @brief HF-6 6f-1 — the client path for a generation-4 STAKE and a
 *        ROTATE: the node consent formed the way nodus-cli `validator
 *        consent` forms it, carried through the consent container, laid
 *        out by the shared builder (nodus/src/client/nodus_v2_stake.c) and
 *        fed to the chain's OWN generation-4 hooks.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §2 (STAKE 7301 B, ROTATE 7291 B, the consent re-construction contract,
 * "STAKE/DELEGATE istemci kodlayıcısı generation'a duyarlı olur"), §3 (khan
 * decision A4: ROTATE fee-only), §6.1 (consent bytes, ctx
 * "nodus.valbind.v1"), §6.2 (validator_id); decisions docs/plans/decisions/
 * 2026-10-08-kurultay-14-hf6-summary.md (K7) and 2026-10-03-role-stake-
 * amounts.md 1B (the node consents, the owner signs and pays).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  V1 The consent: the message dna_valbind_consent_msg builds (the codec
 *     call nodus-cli makes) equals an independent restatement of the §6.1
 *     bytes in this file (version 1 BE ‖ chain 32 ‖ op ‖ subject 64 ‖
 *     owner 64 ‖ pk 2592 ‖ expiry u64 BE = 2765), for op 1 and op 2; the
 *     signature dna_valbind_consent_sign makes verifies under
 *     qgp_dsa87_verify_ctx with the ctx bytes "nodus.valbind.v1" written
 *     here, and NOT under the plain empty-ctx qgp_dsa87_verify.
 *  V2 The consent container (nodus_v2_consent_text_*) round-trips every
 *     field byte for byte; it refuses a wrong magic, an uppercase hex
 *     digit, a reordered line, trailing bytes, a missing final newline,
 *     op 3 or a STAKE with a non-zero subject, a ROTATE with a zero
 *     subject, op 4,
 *     a leading-zero / overflowing expiry, a short signature.
 *  S1 Generation-4 STAKE built by nodus_v2_stake_build (GEN_STORAGE
 *     tuples, generation 4, the owner key signs, the consent from V2's
 *     parse): the SYSTEM call equals the restated 7301-byte layout
 *     (owner_fp = SHA3-512(owner pk) ‖ consensus_pk ‖ consent_sig ‖
 *     expiry ‖ commission ‖ bond — test_hf6_stake.c stake2_call's
 *     layout); the read-back fields equal the request.
 *  S2 The GEN_STORAGE SYSTEM read plan of that envelope, with the
 *     engine's chain id and the builder's intent_id as ctx, asks
 *     [op 7 active_count][op 13 validator_id][op 17 SHA3-512(pk)], and
 *     the validator_id it names equals both dna_validator_id_new(chain,
 *     intent_id) — what nodus-cli prints — and an independent restatement
 *     of §6.2; the GEN_EVM runtime refuses the call.
 *  S3 The GEN_STORAGE SYSTEM exec, given the owner as the single verified
 *     signer and the "may apply" reads, APPLIES (it rebuilds the consent
 *     message from the call and verifies the REAL signature — the check
 *     that the client's consent and bytes agree with the chain): three
 *     effects, the op-13 row naming the owner, the consensus key, the
 *     bond, the commission. Another signer is refused.
 *  S4 The GEN_STORAGE CORE exec of the funding leg balances with lock =
 *     bond (Σin == change + fee + bond); one raw unit more on the input
 *     is refused.
 *  R1 ROTATE built against the row S3 created (validator_id = S2's): the
 *     call equals the restated 7291-byte layout (test_hf6_rotate.c
 *     rot_call's); the plan asks [op 13 validator_id][op 17
 *     SHA3-512(new_pk)]; the exec APPLIES (consent rebuilt with the
 *     COMMITTED row's owner and verified): CREATE op 17 role 2, SET op 13
 *     with pending key = the new key and effective epoch = the first
 *     boundary >= h; the funding leg is fee-only (Σin == change + fee; +1
 *     refused).
 *  G1 Generation awareness: a STAKE at generation 0 and at GEN_EVM builds
 *     the legacy 2666-byte call with the same intent_id and identical
 *     bytes outside the two auth blobs (the v1 path is unchanged by the
 *     generation field); ROTATE below generation 4 and DELEGATE /
 *     UNDELEGATE / UNSTAKE at generation 4 are ERR_GEN; a gen-4 STAKE
 *     with bond 0 or INT64_MAX + 1 is ERR_BOND, a commission above the
 *     bound ERR_COMMISSION, a missing consent or a zero ROTATE
 *     validator_id ERR_ARG.
 *  D1 nodus_v2_stake_decode refuses a generation-4 STAKE whose owner_fp
 *     byte was flipped (owner != SHA3-512(signer)) and accepts the
 *     untouched bytes.
 *  HF-6 slice 6b (design rev 6 §11.3 / §11.5, §6.1 op 3; Kurultay #16
 *  khan decision 1):
 *  V3 The op-3 (STORAGE_REGISTER) consent: dna_valbind_consent_msg with
 *     op 3 and a zero subject equals the §6.1 restatement with op byte 3;
 *     the container round-trips an op-3 consent byte for byte, and
 *     refuses op 3 with a non-zero subject (encode and parse).
 *  T1 STORAGE_REGISTER built by nodus_v2_stake_build at generation 4 (the
 *     owner KO signs, the storage node KS consents with op 3 through the
 *     container): the SYSTEM call equals the restated 7299-byte layout
 *     owner_fp = SHA3-512(KO) ‖ node_pk ‖ consent_sig ‖ expiry ‖ bond;
 *     the read-back carries the owner, the node key, the node_fp =
 *     SHA3-512(node_pk), the consent and the bond; the GEN_STORAGE SYSTEM
 *     exec — the real consent verified under the node key — CREATEs the
 *     row with the owner in the payee_fp column; the decoder refuses a
 *     flipped owner_fp byte.
 *  T2 STORAGE_EXIT built at generation 4: the call is exactly the 64-byte
 *     node_fp; read-back amount 0, owner_fp = SHA3-512(signer), node_fp
 *     = the request's; the exec against an ACTIVE row owned by KO
 *     applies, and the node key itself as the signer is refused.
 *  T3 Refusals: REGISTER and EXIT at generation 0 and GEN_EVM (ERR_GEN —
 *     the storage ops have no other layout); REGISTER bond 0 and
 *     INT64_MAX + 1 (ERR_STORAGE_BOND); REGISTER without the node key or
 *     the consent, EXIT without node_fp (ERR_ARG).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 is compiled only with the
 * EVM runtime; the CMake target is registered only then). Environment:
 * none. No database, no network, no files.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Hook level only: the verdict, the active_count / row / reservation
 *    reads and the funding UTXO rows are FABRICATED engine facts. It
 *    proves the client's bytes and consent against the exec's rule
 *    decisions, NOT admission (descriptor ownership, the meter, the
 *    leg signatures — the builder's own preflight self-check covers
 *    those), nor a block applied end to end.
 *  - nodus-cli's `validator consent` body is NOT driven (it is I/O around
 *    two codec calls); this test makes the same two codec calls. The
 *    CLI's file handling, session reads and printing are untested here.
 *  - The layout restatements (V1, S1, R1) are written by the same author
 *    as the builder change; they are self-consistency with the design
 *    bytes and the exec's parsers, not an independent oracle. The exec
 *    accepting the bytes (S3, R1) is the stronger check.
 *  - Written and compiled, NOT RUN by its author (the BUILDER rule).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "client/nodus_v2_stake.h"

#include "dnac/dnac.h"
#include "dnac/validator.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/valbind_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN    ((uint64_t)DNAC_EPOCH_LENGTH)
#define SMIN     ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define PK_LEN   ((size_t)QGP_DSA87_PUBLICKEYBYTES)
#define SIG_LEN  ((size_t)QGP_DSA87_SIGNATURE_BYTES)
#define TIP      8u
#define H_EXEC   9u               /* the fabricated executing height      */
#define EXP      (H_EXEC + 100u)  /* the consent expiry (within 720)      */
#define BPS      500u
#define STK_LEN  7301u            /* design §2 (K7): 64+2592+4627+8+2+8   */
#define ROT_LEN  7291u            /* design §2 (K7): 64+2592+4627+8       */
#define SRG_LEN  7299u            /* design §2 / §11.3: 64+2592+4627+8+8  */
#define SEX_LEN  64u              /* design §2 / §11.5: node_fp           */
#define SBOND    ((uint64_t)DNAC_HF6_STORAGE_BOND_DEFAULT)

/* restated from nodus_witness_rt_native.c (static there) */
#define OP_STATS      7u
#define OP_VAL2       13u
#define OP_KEYRES     17u
#define OP_UTXO       1u
#define V2_REC_LEN    5389u
#define V2_OWNER_OFF  64u
#define V2_CPK_OFF    128u
#define V2_PPK_OFF    (128u + 2592u)
#define V2_KEFF_OFF   (128u + 2u * 2592u)             /* 5312 */
#define V2_SELF_OFF   (V2_KEFF_OFF + 8u)
#define V2_COMM_OFF   (V2_SELF_OFF + 24u)
#define V2_STAT_OFF   (V2_COMM_OFF + 12u)
#define UTXO_REC_LEN  284u
#define UTXO_AMT_OFF  128u
#define UTXO_UNL_OFF  276u
#define OP_STOR       8u
#define OP_STORCNT    9u
#define STOR_REC_LEN  2693u
#define STOR_OWNER_OFF 2592u      /* the payee_fp column (= the owner)    */
#define STOR_BOND_OFF 2656u
#define STOR_STAT_OFF 2664u
#define STOR_REGH_OFF 2665u
#define STOR_EXITH_OFF 2673u

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

/* ══ keys, ruleset, coin ═════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} cl_key_t;

/* KO the owner (signs, pays), KC the node's consensus key at STAKE, KN the
 * rotation target, KX a foreign key, KS a storage node key (HF-6 6b) */
enum { KO, KC, KN, KX, KS, N_KEYS };
static cl_key_t g_k[N_KEYS];

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x6A + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PK_LEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    return 0;
}

static nodus_v2_stake_ruleset_t g_rs4, g_rs3;
static uint8_t g_chain32[DNA_CHAIN_ID_LEN];

static int rs_from(uint32_t gen, nodus_v2_stake_ruleset_t *rs) {
    const nodus_domain_runtime_t *s =
        nodus_runtime_for_generation(gen, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c =
        nodus_runtime_for_generation(gen, DNA_DOMAIN_CORE);
    if (!s || !c) return -1;
    memset(rs, 0, sizeof(*rs));
    rs->sys_ruleset_version  = s->ruleset_version;
    memcpy(rs->sys_ruleset_hash, s->ruleset_hash, 64);
    rs->core_ruleset_version = c->ruleset_version;
    memcpy(rs->core_ruleset_hash, c->ruleset_hash, 64);
    return 0;
}

static nodus_v2_stake_coin_t g_coin;

static void coin_set(uint64_t amount) {
    memset(&g_coin, 0, sizeof(g_coin));
    memset(g_coin.nul, 0x47, 64);
    g_coin.amount = amount;
}

/* ══ V1 — the consent, as nodus-cli `validator consent` forms it ═════ */

/* the §6.1 message restated from the design table (NOT the codec) */
static void msg_restate(uint8_t out[2765], uint8_t op,
                        const uint8_t subject[64], const uint8_t owner[64],
                        const uint8_t pk[2592], uint64_t expiry) {
    memset(out, 0, 2765);
    out[3] = 1;                                  /* version u32 BE = 1  */
    memcpy(out + 4, g_chain32, 32);
    out[36] = op;
    memcpy(out + 37, subject, 64);
    memcpy(out + 101, owner, 64);
    memcpy(out + 165, pk, 2592);
    put64(out + 2757, expiry);
}

/* the consent nodus-cli signs: dna_valbind_consent_msg + _sign (the two
 * codec calls of cmd_validator_consent) — into a container. */
static int consent_make(nodus_v2_consent_t *c, uint8_t op,
                        const uint8_t subject[64], const uint8_t owner[64],
                        int key, uint64_t expiry) {
    memset(c, 0, sizeof(*c));
    c->op = op;
    memcpy(c->chain32, g_chain32, 32);
    memcpy(c->subject, subject, 64);
    memcpy(c->owner_fp, owner, 64);
    memcpy(c->consensus_pk, g_k[key].pk, PK_LEN);
    c->expiry = expiry;
    uint8_t msg[DNA_VALBIND_MSG_LEN];
    size_t sl = 0;
    if (dna_valbind_consent_msg(msg, c->chain32, op, c->subject, c->owner_fp,
                                c->consensus_pk, expiry) != 0)
        return -1;
    if (dna_valbind_consent_sign(c->sig, &sl, msg, g_k[key].sk) != 0 ||
        sl != SIG_LEN)
        return -1;
    return 0;
}

/* field by field (the struct has padding before `expiry`) */
static int consent_eq(const nodus_v2_consent_t *a,
                      const nodus_v2_consent_t *b) {
    return a->op == b->op && a->expiry == b->expiry &&
           memcmp(a->chain32, b->chain32, sizeof(a->chain32)) == 0 &&
           memcmp(a->subject, b->subject, sizeof(a->subject)) == 0 &&
           memcmp(a->owner_fp, b->owner_fp, sizeof(a->owner_fp)) == 0 &&
           memcmp(a->consensus_pk, b->consensus_pk,
                  sizeof(a->consensus_pk)) == 0 &&
           memcmp(a->sig, b->sig, sizeof(a->sig)) == 0;
}

static int t_consent(void) {
    static const uint8_t zero64[64] = { 0 };
    uint8_t vid[64];
    memset(vid, 0x3B, sizeof(vid));
    static uint8_t m_codec[DNA_VALBIND_MSG_LEN], m_rest[2765];
    CHECK(DNA_VALBIND_MSG_LEN == 2765, "message length (design §6.1)");

    /* op 1 */
    CHECK(dna_valbind_consent_msg(m_codec, g_chain32, DNA_VALBIND_OP_STAKE,
                                  zero64, g_k[KO].fp, g_k[KC].pk, EXP) == 0,
          "STAKE message builds");
    msg_restate(m_rest, 1, zero64, g_k[KO].fp, g_k[KC].pk, EXP);
    CHECK(memcmp(m_codec, m_rest, sizeof(m_rest)) == 0,
          "codec STAKE message == the §6.1 restatement");
    /* op 2 */
    CHECK(dna_valbind_consent_msg(m_codec, g_chain32, DNA_VALBIND_OP_ROTATE,
                                  vid, g_k[KO].fp, g_k[KN].pk, EXP) == 0,
          "ROTATE message builds");
    msg_restate(m_rest, 2, vid, g_k[KO].fp, g_k[KN].pk, EXP);
    CHECK(memcmp(m_codec, m_rest, sizeof(m_rest)) == 0,
          "codec ROTATE message == the §6.1 restatement");
    /* V3 — op 3 (STORAGE_REGISTER, design §11.3): zero subject, the
     * storage node key in the key field */
    CHECK(dna_valbind_consent_msg(m_codec, g_chain32,
                                  DNA_VALBIND_OP_STORAGE_REGISTER, zero64,
                                  g_k[KO].fp, g_k[KS].pk, EXP) == 0,
          "STORAGE_REGISTER message builds");
    msg_restate(m_rest, 3, zero64, g_k[KO].fp, g_k[KS].pk, EXP);
    CHECK(memcmp(m_codec, m_rest, sizeof(m_rest)) == 0,
          "codec STORAGE_REGISTER message == the §6.1 restatement, op 3");
    CHECK(dna_valbind_consent_msg(m_codec, g_chain32,
                                  DNA_VALBIND_OP_STORAGE_REGISTER, vid,
                                  g_k[KO].fp, g_k[KS].pk, EXP) != 0,
          "the codec refuses op 3 with a non-zero subject");
    {
        nodus_v2_consent_t s, sr;
        char *st = NULL;
        size_t stl = 0;
        CHECK(consent_make(&s, DNA_VALBIND_OP_STORAGE_REGISTER, zero64,
                           g_k[KO].fp, KS, EXP) == 0,
              "STORAGE_REGISTER consent signs");
        CHECK(nodus_v2_consent_text_encode(&s, &st, &stl) ==
                  NODUS_V2_SPEND_OK &&
              strstr(st, "\nop 3\n") != NULL &&
              nodus_v2_consent_text_parse(st, stl, &sr) ==
                  NODUS_V2_SPEND_OK && consent_eq(&sr, &s),
              "the container carries op 3 and round-trips every field");
        free(st);
    }

    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_ROTATE, vid, g_k[KO].fp, KN, EXP)
          == 0, "ROTATE consent signs");
    static const uint8_t ctx_bytes[16] = {
        'n','o','d','u','s','.','v','a','l','b','i','n','d','.','v','1'
    };
    CHECK(qgp_dsa87_verify_ctx(c.sig, SIG_LEN, m_rest, sizeof(m_rest),
                               ctx_bytes, sizeof(ctx_bytes),
                               g_k[KN].pk) == 0,
          "the signature verifies over the restated bytes with ctx "
          "\"nodus.valbind.v1\"");
    CHECK(qgp_dsa87_verify(c.sig, SIG_LEN, m_rest, sizeof(m_rest),
                           g_k[KN].pk) != 0,
          "and NOT under the plain (empty-ctx) verify — test_hf6_stake "
          "CS_CTX_EMPTY's API");

    /* ── V2. the container ─────────────────────────────────────────── */
    char *t = NULL;
    size_t tl = 0;
    CHECK(nodus_v2_consent_text_encode(&c, &t, &tl) == NODUS_V2_SPEND_OK &&
          t && tl == strlen(t), "container encodes");
    nodus_v2_consent_t r;
    CHECK(nodus_v2_consent_text_parse(t, tl, &r) == NODUS_V2_SPEND_OK &&
          consent_eq(&r, &c), "container round-trips every field");
    /* a second encode is the same text (deterministic) */
    {
        char *t2 = NULL;
        size_t tl2 = 0;
        CHECK(nodus_v2_consent_text_encode(&r, &t2, &tl2) ==
                  NODUS_V2_SPEND_OK && tl2 == tl &&
              memcmp(t, t2, tl) == 0, "re-encode is byte-identical");
        free(t2);
    }
    char *b = malloc(tl + 8);
    CHECK(b != NULL, "alloc");
#define REFUSE(why) CHECK(nodus_v2_consent_text_parse(b, bl, &r) == \
                          NODUS_V2_SPEND_ERR_DECODE && r.op == 0, why)
    size_t bl;
    /* magic */
    memcpy(b, t, tl); bl = tl; b[0] = 'N';
    REFUSE("wrong magic");
    /* uppercase hex in chain_id */
    {
        memcpy(b, t, tl); bl = tl;
        char *p = strstr(b, "chain_id ");
        CHECK(p != NULL, "chain_id line");
        p += 9;
        int done = 0;
        for (; *p != '\n'; p++)
            if (*p >= 'a' && *p <= 'f') { *p = (char)(*p - 'a' + 'A'); done = 1; break; }
        if (!done) {               /* all digits: make one a non-hex letter */
            p = strstr(b, "chain_id ") + 9;
            *p = 'g';
        }
        REFUSE("uppercase / non-hex digit");
    }
    /* reordered: swap the "op" and "chain_id" keywords' lines is hard to
     * do in place; renaming one key is the same refusal class */
    memcpy(b, t, tl); bl = tl;
    {
        char *p = strstr(b, "\nowner ");
        CHECK(p != NULL, "owner line");
        memcpy(p + 1, "owneR", 5);
    }
    REFUSE("a renamed key");
    /* trailing bytes */
    memcpy(b, t, tl); b[tl] = 'x'; bl = tl + 1;
    REFUSE("a byte after the last line");
    /* missing final newline */
    memcpy(b, t, tl); bl = tl - 1;
    REFUSE("no final newline");
    /* a short signature */
    memcpy(b, t, tl - 3); b[tl - 3] = '\n'; bl = tl - 2;
    REFUSE("a signature two hex chars short");
#undef REFUSE
    free(b);
    free(t);
    /* field rules, through the encoder's twin checks */
    {
        nodus_v2_consent_t z = c;
        memset(z.subject, 0, 64);              /* ROTATE, zero subject */
        CHECK(nodus_v2_consent_text_encode(&z, &t, &tl) ==
              NODUS_V2_SPEND_ERR_ARG && t == NULL,
              "encode refuses a ROTATE with a zero subject");
        z = c;
        z.op = DNA_VALBIND_OP_STAKE;           /* STAKE, non-zero subject */
        CHECK(nodus_v2_consent_text_encode(&z, &t, &tl) ==
              NODUS_V2_SPEND_ERR_ARG, "encode refuses a STAKE with a subject");
        z = c;
        z.op = 3;                              /* op 3, non-zero subject */
        CHECK(nodus_v2_consent_text_encode(&z, &t, &tl) ==
              NODUS_V2_SPEND_ERR_ARG,
              "encode refuses op 3 with a non-zero subject");
        z.op = 4;
        CHECK(nodus_v2_consent_text_encode(&z, &t, &tl) ==
              NODUS_V2_SPEND_ERR_ARG, "encode refuses op 4 (no such op)");
    }
    /* the parser's own op / subject / expiry rules over hand-edited text */
    {
        CHECK(nodus_v2_consent_text_encode(&c, &t, &tl) == NODUS_V2_SPEND_OK,
              "re-encode");
        char *e = malloc(tl + 32);
        CHECK(e != NULL, "alloc");
        size_t el;
        /* op 2 -> 1 with the ROTATE (non-zero) subject still in place */
        memcpy(e, t, tl); el = tl;
        {
            char *p = strstr(e, "\nop 2\n");
            CHECK(p != NULL, "op line");
            p[4] = '1';
        }
        CHECK(nodus_v2_consent_text_parse(e, el, &r) ==
              NODUS_V2_SPEND_ERR_DECODE, "parse refuses STAKE + subject");
        memcpy(e, t, tl); el = tl;
        {
            char *p = strstr(e, "\nop 2\n");
            p[4] = '3';
        }
        CHECK(nodus_v2_consent_text_parse(e, el, &r) ==
              NODUS_V2_SPEND_ERR_DECODE,
              "parse refuses op 3 with the (non-zero) ROTATE subject");
        /* expiry with a leading zero */
        {
            char *p = strstr(t, "\nexpiry ");
            CHECK(p != NULL, "expiry line");
            const size_t pre = (size_t)(p - t) + 8;
            memcpy(e, t, pre);
            e[pre] = '0';
            memcpy(e + pre + 1, t + pre, tl - pre);
            el = tl + 1;
            CHECK(nodus_v2_consent_text_parse(e, el, &r) ==
                  NODUS_V2_SPEND_ERR_DECODE, "parse refuses '0' + expiry");
            /* 2^64 */
            const char *big = "18446744073709551616";
            const char *nl = strchr(t + pre, '\n');
            const size_t tail = tl - (size_t)(nl - t);
            memcpy(e, t, pre);
            memcpy(e + pre, big, strlen(big));
            memcpy(e + pre + strlen(big), nl, tail);
            el = pre + strlen(big) + tail;
            CHECK(nodus_v2_consent_text_parse(e, el, &r) ==
                  NODUS_V2_SPEND_ERR_DECODE, "parse refuses expiry 2^64");
            /* 2^64 - 1 is a valid number */
            const char *max = "18446744073709551615";
            memcpy(e + pre, max, strlen(max));
            memcpy(e + pre + strlen(max), nl, tail);
            el = pre + strlen(max) + tail;
            CHECK(nodus_v2_consent_text_parse(e, el, &r) ==
                      NODUS_V2_SPEND_OK && r.expiry == UINT64_MAX,
                  "expiry 2^64 - 1 parses");
        }
        free(e);
        free(t);
    }
    return 0;
}

/* ══ fabricated engine facts (the test_storage_cli pattern) ══════════ */

static nodus_rt_auth_verdict_t g_av;
static nodus_rt_exec_ctx_t     g_ctx;
static uint8_t g_dig[64];
static nodus_rt_read_res_t g_reads[NODUS_RT_MAX_READS];
static uint8_t g_res[DNA_EFFECT_MAX_TOTAL_LEN];

/* ctx with the builder's intent_id — what v2_apply passes the hook
 * (ctx.intent_id = pf->intent_id) */
static void ctx_set(int signer, const uint8_t intent[64]) {
    memset(&g_av, 0, sizeof(g_av));
    g_av.n_signers = 1;
    memcpy(g_av.signer_fp[0], g_k[signer].fp, 64);
    memset(&g_ctx, 0, sizeof(g_ctx));
    memset(g_dig, 0x2E, sizeof(g_dig));
    g_ctx.chain_id = g_chain32;
    g_ctx.global_height = H_EXEC;
    g_ctx.epoch = H_EXEC / E_LEN;
    g_ctx.wire_id = intent;
    g_ctx.intent_id = intent;
    g_ctx.auth_context_commit = g_dig;
    g_ctx.leg_auth_digest = g_dig;
    g_ctx.auth = &g_av;
}

/* the funding leg's reads: one UTXO row per input owned by the owner
 * holding `amount`, then the pool */
static uint16_t fund_reads(const dna_env_view_t *v, uint64_t amount) {
    const uint8_t *c = v->buf + v->call_off[1];
    const uint8_t n_in = c[0];
    memset(g_reads, 0, sizeof(g_reads));
    for (uint8_t i = 0; i < n_in; i++) {
        g_reads[i].present = 1;
        g_reads[i].value_len = UTXO_REC_LEN;
        memcpy(g_reads[i].value, g_k[KO].hex, 128);
        put64(g_reads[i].value + UTXO_AMT_OFF, amount);
        put64(g_reads[i].value + UTXO_UNL_OFF, 0);
    }
    g_reads[n_in].present = 1;
    g_reads[n_in].value_len = 8;
    put64(g_reads[n_in].value, 1000u);
    return (uint16_t)(n_in + 1u);
}

static int sys_exec(const nodus_domain_runtime_t *rt,
                    const dna_env_view_t *v, uint16_t n_reads,
                    dna_effect_view_t *ev) {
    size_t rl = 0;
    int rc = nodus_rt_system_exec(rt, v, 0, &g_ctx, g_reads, n_reads,
                                  g_res, sizeof(g_res), &rl);
    if (rc == 0 && ev && dna_effect_result_decode(g_res, rl, ev) != 0)
        return -9;
    return rc;
}

static int core_exec(const nodus_domain_runtime_t *rt,
                     const dna_env_view_t *v, uint16_t n_reads) {
    size_t rl = 0;
    return nodus_rt_core_exec(rt, v, 1, &g_ctx, g_reads, n_reads,
                              g_res, sizeof(g_res), &rl);
}

static void req_gen4(nodus_v2_stake_req_t *r, nodus_v2_stake_op_t op,
                     const nodus_v2_consent_t *c) {
    memset(r, 0, sizeof(*r));
    r->rs = &g_rs4;
    r->op = op;
    r->chain32 = g_chain32;
    r->tip = TIP;
    r->expiry_height = TIP + 50u;
    r->pk = g_k[KO].pk;
    r->sk = g_k[KO].sk;
    r->amount = op == NODUS_V2_STAKE_OP_STAKE ? SMIN : 0;
    r->commission_bps = op == NODUS_V2_STAKE_OP_STAKE ? BPS : 0;
    r->gas_price = 0;
    r->coins = &g_coin;
    r->n_coins = 1;
    r->generation = NODUS_RT_GEN_STORAGE;
    r->consensus_pk = c->consensus_pk;
    r->consent_sig = c->sig;
    r->consent_expiry = c->expiry;
    r->validator_id = op == NODUS_V2_STAKE_OP_ROTATE ? c->subject : NULL;
}

/* the STAKE of S1-S4 leaves its validator_id and op-13 row for R1 */
static uint8_t g_vid[64];
static uint8_t g_row[V2_REC_LEN];

/* ══ S1-S4 — the generation-4 STAKE ═════════════════════════════════ */

static int t_stake2(void) {
    static const uint8_t zero64[64] = { 0 };
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *s3 =
        nodus_runtime_for_generation(NODUS_RT_GEN_EVM, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s4 && s3 && c4, "generations 3 and 4 compiled");

    /* the node consents (KC) to KO's STAKE; the owner reads it back */
    nodus_v2_consent_t c, cr;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, g_k[KO].fp, KC, EXP)
          == 0, "STAKE consent signs");
    {
        char *t = NULL;
        size_t tl = 0;
        CHECK(nodus_v2_consent_text_encode(&c, &t, &tl) == NODUS_V2_SPEND_OK &&
              nodus_v2_consent_text_parse(t, tl, &cr) == NODUS_V2_SPEND_OK,
              "through the container");
        free(t);
    }

    const uint64_t coin = SMIN + 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_gen4(&r, NODUS_V2_STAKE_OP_STAKE, &cr);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "generation-4 STAKE builds");
    CHECK(b.dec.op == DNA_SYSRULE_STAKE && b.dec.gen4 == 1 &&
          b.dec.amount == SMIN && b.dec.commission_bps == BPS &&
          memcmp(b.dec.identity_pk, g_k[KO].pk, PK_LEN) == 0 &&
          memcmp(b.dec.owner_fp, g_k[KO].fp, 64) == 0 &&
          memcmp(b.dec.consensus_pk, g_k[KC].pk, PK_LEN) == 0 &&
          memcmp(b.dec.consent_sig, c.sig, SIG_LEN) == 0 &&
          b.dec.consent_expiry == EXP && b.n_in == 1 &&
          b.change == coin - SMIN - b.fee,
          "read-back: op 1, the owner signs, consent fields, bond, change");

    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 && v->leg_count == 2 &&
          v->leg[0].domain_id == DNA_DOMAIN_SYSTEM &&
          v->leg[0].runtime_op == DNA_SYSRULE_STAKE &&
          v->leg[1].runtime_op == DNA_CORERULE_SYSFUND,
          "two legs: SYSTEM op 1 + CORE SYSFUND");
    {   /* test_hf6_stake.c stake2_call's layout, restated */
        static uint8_t want[STK_LEN];
        size_t off = 0;
        memcpy(want, g_k[KO].fp, 64);                    off += 64;
        memcpy(want + off, g_k[KC].pk, PK_LEN);          off += PK_LEN;
        memcpy(want + off, c.sig, SIG_LEN);              off += SIG_LEN;
        put64(want + off, EXP);                          off += 8;
        want[off++] = (uint8_t)(BPS >> 8);
        want[off++] = (uint8_t)BPS;
        put64(want + off, SMIN);                         off += 8;
        CHECK(off == STK_LEN && v->leg[0].call_len == STK_LEN &&
              memcmp(v->buf + v->call_off[0], want, STK_LEN) == 0,
              "call = owner_fp ‖ consensus_pk ‖ consent_sig ‖ expiry ‖ "
              "commission ‖ bond (7301 bytes)");
    }

    /* S2 — the plan names the validator_id nodus-cli prints */
    ctx_set(KO, b.intent_id);
    uint8_t vid_cli[64], vid_rest[64], kh[64];
    CHECK(dna_validator_id_new(vid_cli, g_chain32, b.intent_id) == 0,
          "dna_validator_id_new (what nodus-cli prints)");
    {
        uint8_t pre[112];
        memset(pre, 0, 16);
        memcpy(pre, "NDS.VALID.v1", 12);
        memcpy(pre + 16, g_chain32, 32);
        memcpy(pre + 48, b.intent_id, 64);
        CHECK(qgp_sha3_512(pre, sizeof(pre), vid_rest) == 0 &&
              memcmp(vid_rest, vid_cli, 64) == 0,
              "== the §6.2 restatement");
    }
    CHECK(qgp_sha3_512(g_k[KC].pk, PK_LEN, kh) == 0, "key hash");
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s4, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 3 && rq[0].op_id == OP_STATS &&
              rq[1].op_id == OP_VAL2 && rq[1].key_len == 64 &&
              memcmp(rq[1].key, vid_cli, 64) == 0 &&
              rq[2].op_id == OP_KEYRES &&
              memcmp(rq[2].key, kh, 64) == 0,
              "plan [op 7][op 13 = the printed validator_id][op 17 key]");
        CHECK(nodus_rt_system_read_plan(s3, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == -1,
              "the generation-3 runtime refuses the 7301-byte STAKE");
    }

    /* S3 — the exec verifies the real consent and applies */
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;                     /* active_count 7    */
        g_reads[0].value_len = 8;
        put64(g_reads[0].value, 7);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s4, v, 3, &ev) == 0 && ev.effect_count == 3,
              "STAKE exec applies: consent verified, three effects");
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        CHECK(ev.eff[0].op_id == OP_VAL2 &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].value_len == V2_REC_LEN &&
              memcmp(ev.buf + ev.key_off[0], vid_cli, 64) == 0 &&
              memcmp(v0, vid_cli, 64) == 0 &&
              memcmp(v0 + V2_OWNER_OFF, g_k[KO].fp, 64) == 0 &&
              memcmp(v0 + V2_CPK_OFF, g_k[KC].pk, PK_LEN) == 0 &&
              get64(v0 + V2_SELF_OFF) == SMIN &&
              v0[V2_COMM_OFF] == (uint8_t)(BPS >> 8) &&
              v0[V2_COMM_OFF + 1] == (uint8_t)BPS &&
              v0[V2_STAT_OFF] == (uint8_t)DNAC_VALIDATOR_ACTIVE,
              "the op-13 row: validator_id, owner, consensus key, bond, "
              "commission, ACTIVE");
        memcpy(g_vid, vid_cli, 64);
        memcpy(g_row, v0, V2_REC_LEN);
        ctx_set(KX, b.intent_id);
        CHECK(sys_exec(s4, v, 3, NULL) == -1,
              "a signer other than the owner is refused");
        ctx_set(KO, b.intent_id);
    }
    /* S4 — the funding leg: Σin == change + fee + bond */
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(c4, v, nr) == 0, "funding balances, lock = bond");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(c4, v, nr) == -1,
              "one raw unit more on the input breaks the equation");
    }

    /* D1 — decode binds owner_fp to the signer */
    {
        nodus_v2_stake_decoded_t *d = calloc(1, sizeof(*d));
        uint8_t *bad = malloc(b.env_len);
        CHECK(d && bad, "alloc");
        CHECK(nodus_v2_stake_decode(b.env, b.env_len, d) == NODUS_V2_SPEND_OK
              && d->gen4 == 1, "the untouched envelope decodes");
        memcpy(bad, b.env, b.env_len);
        bad[v->call_off[0] + 0] ^= 0x01;           /* owner_fp byte 0   */
        CHECK(nodus_v2_stake_decode(bad, b.env_len, d) ==
                  NODUS_V2_SPEND_ERR_DECODE,
              "an owner_fp that is not SHA3-512(signer) is refused");
        free(bad);
        free(d);
    }
    free(v);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* ══ R1 — ROTATE against the row S3 created ═════════════════════════ */

static int t_rotate(void) {
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s4 && c4, "generation 4 compiled");

    /* the NEW node (KN) consents to KO rotating validator g_vid onto it */
    nodus_v2_consent_t c, cr;
    CHECK(consent_make(&c, DNA_VALBIND_OP_ROTATE, g_vid, g_k[KO].fp, KN, EXP)
          == 0, "ROTATE consent signs");
    {
        char *t = NULL;
        size_t tl = 0;
        CHECK(nodus_v2_consent_text_encode(&c, &t, &tl) == NODUS_V2_SPEND_OK &&
              nodus_v2_consent_text_parse(t, tl, &cr) == NODUS_V2_SPEND_OK,
              "through the container");
        free(t);
    }

    const uint64_t coin = 5000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_gen4(&r, NODUS_V2_STAKE_OP_ROTATE, &cr);
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "ROTATE builds");
    CHECK(b.dec.op == DNA_SYSRULE_ROTATE_CONSENSUS_KEY && b.dec.gen4 == 1 &&
          b.dec.amount == 0 &&
          memcmp(b.dec.validator_id, g_vid, 64) == 0 &&
          memcmp(b.dec.consensus_pk, g_k[KN].pk, PK_LEN) == 0 &&
          memcmp(b.dec.owner_fp, g_k[KO].fp, 64) == 0 &&
          b.dec.consent_expiry == EXP && b.change == coin - b.fee,
          "read-back: op 10, validator_id, new key, fee-only change");

    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 && v->leg_count == 2 &&
          v->leg[0].runtime_op == DNA_SYSRULE_ROTATE_CONSENSUS_KEY &&
          v->leg[1].runtime_op == DNA_CORERULE_SYSFUND, "two legs");
    {   /* test_hf6_rotate.c rot_call's layout, restated */
        static uint8_t want[ROT_LEN];
        memcpy(want, g_vid, 64);
        memcpy(want + 64, g_k[KN].pk, PK_LEN);
        memcpy(want + 64 + PK_LEN, c.sig, SIG_LEN);
        put64(want + 64 + PK_LEN + SIG_LEN, EXP);
        CHECK(v->leg[0].call_len == ROT_LEN &&
              memcmp(v->buf + v->call_off[0], want, ROT_LEN) == 0,
              "call = validator_id ‖ new_pk ‖ consent_sig ‖ expiry "
              "(7291 bytes)");
    }

    ctx_set(KO, b.intent_id);
    uint8_t khn[64];
    CHECK(qgp_sha3_512(g_k[KN].pk, PK_LEN, khn) == 0, "key hash");
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s4, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2 && rq[0].op_id == OP_VAL2 &&
              memcmp(rq[0].key, g_vid, 64) == 0 &&
              rq[1].op_id == OP_KEYRES && memcmp(rq[1].key, khn, 64) == 0,
              "plan [op 13 validator_id][op 17 SHA3-512(new_pk)]");
    }
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;                    /* the committed row */
        g_reads[0].value_len = V2_REC_LEN;
        memcpy(g_reads[0].value, g_row, V2_REC_LEN);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s4, v, 2, &ev) == 0 && ev.effect_count == 2,
              "ROTATE exec applies: consent rebuilt with the committed "
              "owner and verified");
        const uint8_t *v0 = ev.buf + ev.val_off[0];
        const uint8_t *v1 = ev.buf + ev.val_off[1];
        const uint64_t F = ((H_EXEC + E_LEN - 1) / E_LEN) * E_LEN;
        CHECK(ev.eff[0].op_id == OP_KEYRES &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              memcmp(ev.buf + ev.key_off[0], khn, 64) == 0 &&
              ev.eff[0].value_len == 65 && memcmp(v0, g_vid, 64) == 0 &&
              v0[64] == 2u, "CREATE op 17: new key -> validator_id, role 2");
        CHECK(ev.eff[1].op_id == OP_VAL2 &&
              ev.eff[1].effect_kind == DNA_EFFECT_SET &&
              ev.eff[1].value_len == V2_REC_LEN &&
              memcmp(v1 + V2_PPK_OFF, g_k[KN].pk, PK_LEN) == 0 &&
              get64(v1 + V2_KEFF_OFF) == F &&
              memcmp(v1 + V2_CPK_OFF, g_k[KC].pk, PK_LEN) == 0,
              "SET op 13: pending key = the new key, epoch = the first "
              "boundary >= h, current key unchanged");
        ctx_set(KX, b.intent_id);
        CHECK(sys_exec(s4, v, 2, NULL) == -1,
              "a signer other than the row's owner is refused");
        ctx_set(KO, b.intent_id);
    }
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(c4, v, nr) == 0, "funding is fee-only (A4)");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(c4, v, nr) == -1, "+1 on the input refused");
    }
    free(v);
    nodus_v2_stake_built_free(&b);
    return 0;
}

/* ══ G1 — generation awareness and refusals ═════════════════════════ */

static int t_generation(void) {
    static const uint8_t zero64[64] = { 0 };
    coin_set(DNAC_SELF_STAKE_AMOUNT + 9000000000ULL);

    /* the legacy STAKE at generation 0 and at GEN_EVM: one byte stream */
    nodus_v2_stake_req_t r;
    memset(&r, 0, sizeof(r));
    r.rs = &g_rs3;
    r.op = NODUS_V2_STAKE_OP_STAKE;
    r.chain32 = g_chain32;
    r.tip = TIP;
    r.expiry_height = TIP + 50u;
    r.pk = g_k[KO].pk;
    r.sk = g_k[KO].sk;
    r.amount = DNAC_SELF_STAKE_AMOUNT;
    r.commission_bps = BPS;
    r.dest_fp = g_k[KO].fp;
    r.coins = &g_coin;
    r.n_coins = 1;
    nodus_v2_stake_built_t b0, b3;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b0, &e) == NODUS_V2_SPEND_OK,
          "legacy STAKE, generation 0");
    r.generation = NODUS_RT_GEN_EVM;
    CHECK(nodus_v2_stake_build(&r, &b3, &e) == NODUS_V2_SPEND_OK,
          "legacy STAKE, generation 3");
    CHECK(b0.dec.gen4 == 0 && b3.dec.gen4 == 0 &&
          b0.env_len == b3.env_len &&
          memcmp(b0.intent_id, b3.intent_id, 64) == 0,
          "same length, same intent_id");
    {
        dna_env_view_t *v0 = calloc(1, sizeof(*v0));
        CHECK(v0 != NULL, "alloc");
        CHECK(dna_env_decode(b0.env, b0.env_len, v0) == 0 &&
              v0->leg[0].call_len == NODUS_V2_STAKE_CALL_LEN,
              "the 2666-byte legacy call");
        size_t a0 = v0->auth_off[0], a1 = v0->auth_off[1];
        size_t al = v0->leg[0].auth_len;
        int same = 1;
        for (size_t i = 0; i < b0.env_len; i++) {
            if ((i >= a0 && i < a0 + al) || (i >= a1 && i < a1 + al)) continue;
            if (b0.env[i] != b3.env[i]) { same = 0; break; }
        }
        CHECK(same, "byte-identical outside the two (hedged) auth blobs");
        free(v0);
    }
    nodus_v2_stake_built_free(&b0);
    nodus_v2_stake_built_free(&b3);

    /* refusals */
    nodus_v2_consent_t c;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STAKE, zero64, g_k[KO].fp, KC, EXP)
          == 0, "consent");
    nodus_v2_stake_built_t b;
    req_gen4(&r, NODUS_V2_STAKE_OP_STAKE, &c);
    coin_set(SMIN + 9000000000ULL);
    r.amount = 0;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_BOND,
          "gen-4 bond 0");
    r.amount = (uint64_t)INT64_MAX + 1u;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_BOND,
          "gen-4 bond INT64_MAX + 1");
    r.amount = SMIN;
    r.commission_bps = (uint32_t)DNAC_COMMISSION_BPS_MAX + 1u;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_COMMISSION,
          "gen-4 commission above the bound");
    r.commission_bps = BPS;
    r.consent_sig = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "gen-4 STAKE without a consent");
    r.consent_sig = c.sig;
    r.consensus_pk = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "gen-4 STAKE without the consensus key");

    req_gen4(&r, NODUS_V2_STAKE_OP_ROTATE, &c);
    r.validator_id = zero64;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "ROTATE with a zero validator_id");
    r.validator_id = g_vid;
    r.generation = NODUS_RT_GEN_EVM;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
          "ROTATE below generation 4");
    r.generation = 0;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
          "ROTATE at generation 0");

    const nodus_v2_stake_op_t legacy_only[3] = {
        NODUS_V2_STAKE_OP_DELEGATE, NODUS_V2_STAKE_OP_UNDELEGATE,
        NODUS_V2_STAKE_OP_UNSTAKE
    };
    for (int i = 0; i < 3; i++) {
        req_gen4(&r, legacy_only[i], &c);
        r.amount = 100u;
        r.validator_pk = g_k[KC].pk;
        CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
              "DELEGATE / UNDELEGATE / UNSTAKE refused at generation 4");
    }
    return 0;
}

/* ══ T1-T3 — the generation-4 storage calls (HF-6 slice 6b) ═════════ */

static int t_storage(void) {
    static const uint8_t zero64[64] = { 0 };
    const nodus_domain_runtime_t *s4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *c4 =
        nodus_runtime_for_generation(NODUS_RT_GEN_STORAGE, DNA_DOMAIN_CORE);
    CHECK(s4 && c4, "generation 4 compiled");

    /* the storage node KS consents (op 3) to KO owning it; KO reads it */
    nodus_v2_consent_t c, cr;
    CHECK(consent_make(&c, DNA_VALBIND_OP_STORAGE_REGISTER, zero64,
                       g_k[KO].fp, KS, EXP) == 0, "op-3 consent signs");
    {
        char *t = NULL;
        size_t tl = 0;
        CHECK(nodus_v2_consent_text_encode(&c, &t, &tl) == NODUS_V2_SPEND_OK &&
              nodus_v2_consent_text_parse(t, tl, &cr) == NODUS_V2_SPEND_OK,
              "through the container");
        free(t);
    }

    /* ── T1. REGISTER ──────────────────────────────────────────────── */
    const uint64_t coin = SBOND + 9000000000ULL;
    coin_set(coin);
    nodus_v2_stake_req_t r;
    req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER, &cr);
    r.amount = SBOND;
    nodus_v2_stake_built_t b;
    nodus_v2_stake_err_t e;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "STORAGE_REGISTER builds at generation 4");
    CHECK(b.dec.op == DNA_SYSRULE_STORAGE_REGISTER && b.dec.gen4 == 1 &&
          b.dec.amount == SBOND &&
          memcmp(b.dec.identity_pk, g_k[KO].pk, PK_LEN) == 0 &&
          memcmp(b.dec.owner_fp, g_k[KO].fp, 64) == 0 &&
          memcmp(b.dec.consensus_pk, g_k[KS].pk, PK_LEN) == 0 &&
          memcmp(b.dec.node_fp, g_k[KS].fp, 64) == 0 &&
          memcmp(b.dec.consent_sig, c.sig, SIG_LEN) == 0 &&
          b.dec.consent_expiry == EXP && b.n_in == 1 &&
          b.change == coin - SBOND - b.fee,
          "read-back: op 7, the owner signs, node key + node_fp, consent, "
          "bond, change");
    dna_env_view_t *v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 && v->leg_count == 2 &&
          v->leg[0].runtime_op == DNA_SYSRULE_STORAGE_REGISTER &&
          v->leg[1].runtime_op == DNA_CORERULE_SYSFUND,
          "two legs: SYSTEM op 7 + CORE SYSFUND");
    {   /* design §2 / §11.3, restated */
        static uint8_t want[SRG_LEN];
        size_t off = 0;
        memcpy(want, g_k[KO].fp, 64);                    off += 64;
        memcpy(want + off, g_k[KS].pk, PK_LEN);          off += PK_LEN;
        memcpy(want + off, c.sig, SIG_LEN);              off += SIG_LEN;
        put64(want + off, EXP);                          off += 8;
        put64(want + off, SBOND);                        off += 8;
        CHECK(off == SRG_LEN && v->leg[0].call_len == SRG_LEN &&
              memcmp(v->buf + v->call_off[0], want, SRG_LEN) == 0,
              "call = owner_fp ‖ node_pk ‖ consent_sig ‖ expiry ‖ bond "
              "(7299 bytes)");
    }
    ctx_set(KO, b.intent_id);
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s4, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 2 && rq[0].op_id == OP_STOR && rq[0].key_len == 64 &&
              memcmp(rq[0].key, g_k[KS].fp, 64) == 0 &&
              rq[1].op_id == OP_STORCNT && rq[1].key_len == 1 &&
              rq[1].key[0] == 1u,
              "plan [op 8 SHA3-512(node_pk)][op 9 live count]");
    }
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[1].present = 1;                     /* live count 0      */
        g_reads[1].value_len = 8;
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s4, v, 2, &ev) == 0 && ev.effect_count == 1,
              "REGISTER exec applies: the op-3 consent verified under the "
              "node key");
        const uint8_t *rec = ev.buf + ev.val_off[0];
        CHECK(ev.eff[0].op_id == OP_STOR &&
              ev.eff[0].effect_kind == DNA_EFFECT_CREATE &&
              ev.eff[0].value_len == STOR_REC_LEN &&
              memcmp(ev.buf + ev.key_off[0], g_k[KS].fp, 64) == 0 &&
              memcmp(rec, g_k[KS].pk, PK_LEN) == 0 &&
              memcmp(rec + STOR_OWNER_OFF, g_k[KO].fp, 64) == 0 &&
              get64(rec + STOR_BOND_OFF) == SBOND &&
              rec[STOR_STAT_OFF] == 1u &&
              get64(rec + STOR_REGH_OFF) == H_EXEC,
              "CREATE op 8: node key, the OWNER in the payee_fp column, "
              "bond, ACTIVE since h");
        ctx_set(KS, b.intent_id);
        CHECK(sys_exec(s4, v, 2, NULL) == -1,
              "the node key as the signer is not the owner: refused");
        ctx_set(KO, b.intent_id);
    }
    {
        uint16_t nr = fund_reads(v, coin);
        CHECK(core_exec(c4, v, nr) == 0, "funding balances, lock = bond");
        nr = fund_reads(v, coin + 1u);
        CHECK(core_exec(c4, v, nr) == -1, "+1 on the input refused");
    }
    {
        nodus_v2_stake_decoded_t *d = calloc(1, sizeof(*d));
        uint8_t *bad = malloc(b.env_len);
        CHECK(d && bad, "alloc");
        memcpy(bad, b.env, b.env_len);
        bad[v->call_off[0] + 0] ^= 0x01;           /* owner_fp byte 0   */
        CHECK(nodus_v2_stake_decode(bad, b.env_len, d) ==
                  NODUS_V2_SPEND_ERR_DECODE,
              "a REGISTER owner_fp that is not SHA3-512(signer) refused");
        free(bad);
        free(d);
    }
    free(v);
    nodus_v2_stake_built_free(&b);

    /* ── T2. EXIT ──────────────────────────────────────────────────── */
    coin_set(5000000000ULL);
    req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_EXIT, &cr);
    r.consensus_pk = NULL;                         /* not part of EXIT   */
    r.consent_sig = NULL;
    r.node_fp = g_k[KS].fp;
    r.amount = 777;                                /* must be ignored    */
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_OK,
          "STORAGE_EXIT builds at generation 4");
    CHECK(b.dec.op == DNA_SYSRULE_STORAGE_EXIT && b.dec.gen4 == 1 &&
          b.dec.amount == 0 &&
          memcmp(b.dec.owner_fp, g_k[KO].fp, 64) == 0 &&
          memcmp(b.dec.node_fp, g_k[KS].fp, 64) == 0 &&
          b.change == 5000000000ULL - b.fee,
          "read-back: op 8, node_fp, the signer as owner, fee only");
    v = calloc(1, sizeof(*v));
    CHECK(v != NULL, "view alloc");
    CHECK(dna_env_decode(b.env, b.env_len, v) == 0 &&
          v->leg[0].call_len == SEX_LEN &&
          memcmp(v->buf + v->call_off[0], g_k[KS].fp, SEX_LEN) == 0,
          "call = node_fp (64 bytes)");
    ctx_set(KO, b.intent_id);
    {
        nodus_rt_read_req_t rq[NODUS_RT_MAX_READS];
        uint16_t n = 0;
        CHECK(nodus_rt_system_read_plan(s4, v, 0, &g_ctx, rq,
                                        NODUS_RT_MAX_READS, &n) == 0 &&
              n == 1 && rq[0].op_id == OP_STOR &&
              memcmp(rq[0].key, g_k[KS].fp, 64) == 0,
              "plan [op 8 keyed by the call]");
    }
    {
        dna_effect_view_t ev;
        memset(g_reads, 0, sizeof(g_reads));
        g_reads[0].present = 1;
        g_reads[0].value_len = STOR_REC_LEN;
        uint8_t *rec = g_reads[0].value;
        memcpy(rec, g_k[KS].pk, PK_LEN);
        memcpy(rec + STOR_OWNER_OFF, g_k[KO].fp, 64);
        put64(rec + STOR_BOND_OFF, SBOND);
        rec[STOR_STAT_OFF] = 1u;                    /* ACTIVE            */
        put64(rec + STOR_REGH_OFF, 2);
        memset(&ev, 0, sizeof(ev));
        CHECK(sys_exec(s4, v, 1, &ev) == 0 && ev.effect_count == 1 &&
              ev.eff[0].effect_kind == DNA_EFFECT_SET &&
              (ev.buf + ev.val_off[0])[STOR_STAT_OFF] == 2u &&
              get64(ev.buf + ev.val_off[0] + STOR_EXITH_OFF) == H_EXEC,
              "EXIT exec by the row's owner applies: EXITING since h");
        ctx_set(KS, b.intent_id);
        CHECK(sys_exec(s4, v, 1, NULL) == -1,
              "the node key is not the owner: refused");
        ctx_set(KO, b.intent_id);
    }
    {
        uint16_t nr = fund_reads(v, 5000000000ULL);
        CHECK(core_exec(c4, v, nr) == 0, "EXIT funding is fee-only");
    }
    free(v);
    nodus_v2_stake_built_free(&b);

    /* ── T3. refusals ──────────────────────────────────────────────── */
    coin_set(SBOND + 9000000000ULL);
    for (int g = 0; g < 2; g++) {
        const uint32_t gen = g == 0 ? 0u : (uint32_t)NODUS_RT_GEN_EVM;
        req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER, &cr);
        r.amount = SBOND;
        r.generation = gen;
        CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
              "REGISTER below generation 4 (no other layout)");
        req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_EXIT, &cr);
        r.node_fp = g_k[KS].fp;
        r.generation = gen;
        CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_GEN,
              "EXIT below generation 4 (no other layout)");
    }
    req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_REGISTER, &cr);
    r.amount = 0;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_STORAGE_BOND,
          "REGISTER bond 0");
    r.amount = (uint64_t)INT64_MAX + 1u;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_STAKE_ERR_STORAGE_BOND,
          "REGISTER bond INT64_MAX + 1");
    r.amount = SBOND;
    r.consensus_pk = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "REGISTER without the node key");
    r.consensus_pk = cr.consensus_pk;
    r.consent_sig = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "REGISTER without the consent");
    req_gen4(&r, NODUS_V2_STAKE_OP_STORAGE_EXIT, &cr);
    r.node_fp = NULL;
    CHECK(nodus_v2_stake_build(&r, &b, &e) == NODUS_V2_SPEND_ERR_ARG,
          "EXIT without node_fp");
    return 0;
}

int main(void) {
    if (keys_make() != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }
    if (rs_from(NODUS_RT_GEN_STORAGE, &g_rs4) != 0 ||
        rs_from(NODUS_RT_GEN_EVM, &g_rs3) != 0) {
        fprintf(stderr, "generations 3 / 4 missing from the table\n");
        return 1;
    }
    memset(g_chain32, 0x5C, sizeof(g_chain32));
    if (t_consent() != 0) return 1;
    if (t_stake2() != 0) return 1;
    if (t_rotate() != 0) return 1;
    if (t_generation() != 0) return 1;
    if (t_storage() != 0) return 1;
    printf("test_v2_stake_client: %d checks passed\n", g_checks);
    return 0;
}
