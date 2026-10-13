/**
 * Nodus — HF-6 slice 1: validator consent message, FIPS 204 ctx
 * signatures and validator_id derivation (INERT layer).
 *
 * Governing record: design 2026-10-03-hf5-validator-owner-stake §6.1 /
 * §6.2 (bytes approved by the operator 2026-10-08); signature domain =
 * FIPS 204 ctx only (operator 2026-10-08 "evet yalnız ctx", design §6.1).
 *
 * Sections:
 *   1. Consent message layout: every offset and length of §6.1, written
 *      byte-for-byte from the fixture inputs.
 *   2. op / subject rejects (with no partial output) and NULL guards —
 *      ops 0, 4, 0x80, 0xFF; STAKE or STORAGE_REGISTER with a nonzero
 *      subject; ROTATE with a zero subject.
 *   3. Expiry rule edges: h, h+720, h+721, expiry < h, and values next to
 *      UINT64_MAX (a wrapped `h + 720` formula would accept some of them).
 *   4. validator_id: both derivations re-computed in-test from an
 *      explicitly assembled 112-byte preimage.
 *   5. ctx signatures over a real ML-DSA-87 key: sign_ctx → verify_ctx
 *      accepts; another ctx, a shorter ctx, an empty ctx (plain
 *      qgp_dsa87_verify), a ctx-prepended-to-message signature, a
 *      tampered message and another key all REJECT; ctxlen 256 and
 *      (ctx NULL, ctxlen > 0) are refused by both wrappers.
 *   6. Signer binding: consent_verify takes no key — it verifies under
 *      the consensus_pk embedded at offset 165. Key B signing a message
 *      that embeds key A fails; a malformed message (version, op,
 *      op/subject rule) is refused by both consent_sign and
 *      consent_verify; a STORAGE_REGISTER (op 3) consent and a STAKE
 *      (op 1) consent for the same owner/key/expiry do not verify as
 *      each other (cross-role replay).
 *
 * Op 3 = STORAGE_REGISTER (design rev 6 §6.1 / §11.3, operator
 * 2026-10-09 "approved"): subject 64 × 0x00 like STAKE; op 4 is the
 * first unknown op and is refused.
 *
 * Deterministic test bytes: fill(label, n) = SHA3-512(label ‖ u32 BE 0) ‖
 * SHA3-512(label ‖ u32 BE 1) ‖ … truncated to n bytes (label is the ASCII
 * label without a NUL). Every fixture input uses this rule so an
 * independent oracle can reproduce it.
 *
 * ORACLE PINS: the hex constants below come from the independent python
 * oracle shared/dnac/tests/valbind_oracle.py; its full output is
 * shared/dnac/tests/valbind_oracle_out.txt (each constant names its line).
 *
 * @file test_valbind_wire.c
 */

#include "dnac/valbind_wire.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── Deterministic fixture bytes (see file header) ──────────────────── */

static int fill(const char *label, uint8_t *out, size_t n) {
    size_t ll = strlen(label);
    if (ll > 64) return -1;
    uint8_t pre[64 + 4];
    uint8_t h[64];
    memcpy(pre, label, ll);
    size_t done = 0;
    for (uint32_t i = 0; done < n; i++) {
        pre[ll + 0] = (uint8_t)(i >> 24); pre[ll + 1] = (uint8_t)(i >> 16);
        pre[ll + 2] = (uint8_t)(i >> 8);  pre[ll + 3] = (uint8_t)i;
        if (qgp_sha3_512(pre, ll + 4, h) != 0) return -1;
        size_t take = (n - done < 64) ? (n - done) : 64;
        memcpy(out + done, h, take);
        done += take;
    }
    return 0;
}

/* ── Oracle pins (shared/dnac/tests/valbind_oracle.py) ──────────────── */

/* valbind_oracle_out.txt line "consent_rotate.sha3_512" */
static const char *PIN_CONSENT_ROTATE_SHA3 =
    "b036087103797b23c5c7a0ad6ac574ede0a8835fe65ccbb8ed7a3190051b869b"
    "c61ee5a2cc9ad9d5ab6d980ace5cf69ce05ec9c29d41f9fa44cf1f3cd726af73";
/* valbind_oracle_out.txt line "consent_stake.sha3_512" */
static const char *PIN_CONSENT_STAKE_SHA3 =
    "4d1c9e26243a03fe751e87e2d5752d6cf516e9dab23c892c576887d3f89e88a7"
    "6508fe09f008a16a8e6da43921794fafe5f8647b778bda5c76d1e61e9bab4d92";
/* valbind_oracle_out.txt line "consent_storage_register.sha3_512" (op 3,
 * design rev 6 §6.1 / §11.3) — the SHA3-512 of the full 2765-byte oracle
 * message "consent_storage_register.msg", so a match pins every byte. */
static const char *PIN_CONSENT_STORAGE_REGISTER_SHA3 =
    "6272275ce84e3c90ccc9958ff928cf50ce22983a16df93ad0fb558c80c1dd37a"
    "02870c159b8a99df93cd36b36f46d145326df7637934590bb50c0725a5f5a9ec";
/* valbind_oracle_out.txt line "vid_new" */
static const char *PIN_VID_NEW =
    "fc3114bfcf5e7eae33dda49544978f1db32fb8cf50d71500e4d963b1b360557f"
    "17b569d346c730b9b7527fd1aa460852b5616be56faeea03e1c78167e6532753";
/* valbind_oracle_out.txt line "vid_mig" */
static const char *PIN_VID_MIG =
    "99ebdc4b29dc3a05693a2a07da7a46a5edd1fd4dfe2105813cf59111395342098"
    "c31d2f667f3a33f40bc9e325d41a479eef61fda10907e54b77041e74a7a56bc";

static int hex_eq(const uint8_t h[64], const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[129];
    for (int i = 0; i < 64; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[128] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "ORACLE mismatch (%s):\n  oracle: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

static uint64_t rd_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

/* Shared fixture inputs. pk is 2592 bytes — static, not stack. */
static uint8_t g_chain[32], g_subject[64], g_owner[64];
static uint8_t g_pk[DNA_VALBIND_PUBKEY_LEN];

static int load_fixture(void) {
    if (fill("chain", g_chain, sizeof(g_chain)) != 0) return -1;
    if (fill("subject", g_subject, sizeof(g_subject)) != 0) return -1;
    if (fill("owner", g_owner, sizeof(g_owner)) != 0) return -1;
    if (fill("pk", g_pk, sizeof(g_pk)) != 0) return -1;
    return 0;
}

/* ── 1: consent message layout ──────────────────────────────────────── */

static int test_layout(void) {
    CHECK(DNA_VALBIND_MSG_LEN == 2765, "message length"); OK();
    CHECK(DNA_VALBIND_CTX_LEN == 16 &&
          strlen(DNA_VALBIND_CTX) == 16 &&
          memcmp(DNA_VALBIND_CTX, "nodus.valbind.v1", 16) == 0,
          "ctx bytes"); OK();
    CHECK(DNA_VALBIND_MAX_EXPIRY_BLOCKS == 720, "expiry window"); OK();

    static uint8_t m[DNA_VALBIND_MSG_LEN];
    CHECK(dna_valbind_consent_msg(m, g_chain, DNA_VALBIND_OP_ROTATE,
                                  g_subject, g_owner, g_pk, 1000) == 0,
          "consent_msg ROTATE"); OK();

    /* off 0: version u32 BE = 1 */
    CHECK(m[0] == 0 && m[1] == 0 && m[2] == 0 && m[3] == 1, "version"); OK();
    /* off 4: chain_id (32) */
    CHECK(memcmp(m + 4, g_chain, 32) == 0, "chain at 4"); OK();
    /* off 36: op */
    CHECK(m[36] == 2, "op at 36"); OK();
    /* off 37: subject (64) */
    CHECK(memcmp(m + 37, g_subject, 64) == 0, "subject at 37"); OK();
    /* off 101: owner_fp (64) */
    CHECK(memcmp(m + 101, g_owner, 64) == 0, "owner at 101"); OK();
    /* off 165: consensus_pk (2592) */
    CHECK(memcmp(m + 165, g_pk, 2592) == 0, "pk at 165"); OK();
    /* off 2757: expiry u64 BE */
    CHECK(rd_be64(m + 2757) == 1000, "expiry at 2757"); OK();
    CHECK(m[2757] == 0 && m[2763] == 0x03 && m[2764] == 0xE8,
          "expiry big-endian"); OK();
    CHECK(2757 + 8 == DNA_VALBIND_MSG_LEN, "nothing after expiry"); OK();

    {
        uint8_t h[64];
        CHECK(qgp_sha3_512(m, DNA_VALBIND_MSG_LEN, h) == 0, "sha3");
        CHECK(hex_eq(h, PIN_CONSENT_ROTATE_SHA3, "consent_rotate.sha3_512"),
              "ROTATE consent message != oracle"); OK();
    }

    /* STAKE: subject 64 × 0x00 */
    static uint8_t ms[DNA_VALBIND_MSG_LEN];
    uint8_t zero[64] = {0};
    CHECK(dna_valbind_consent_msg(ms, g_chain, DNA_VALBIND_OP_STAKE,
                                  zero, g_owner, g_pk, 1000) == 0,
          "consent_msg STAKE"); OK();
    CHECK(ms[36] == 1, "STAKE op byte"); OK();
    for (size_t i = 0; i < 64; i++)
        CHECK(ms[37 + i] == 0, "STAKE subject zero");
    OK();
    CHECK(memcmp(ms, m, 36) == 0 &&
          memcmp(ms + 101, m + 101, DNA_VALBIND_MSG_LEN - 101) == 0,
          "STAKE differs from ROTATE only in op + subject"); OK();
    {
        uint8_t h[64];
        CHECK(qgp_sha3_512(ms, DNA_VALBIND_MSG_LEN, h) == 0, "sha3");
        CHECK(hex_eq(h, PIN_CONSENT_STAKE_SHA3, "consent_stake.sha3_512"),
              "STAKE consent message != oracle"); OK();
    }

    /* STORAGE_REGISTER (op 3, rev 6 §11.3): subject 64 × 0x00, the key
     * field carries the storage node_pk (here the same fixture pk). */
    static uint8_t mg[DNA_VALBIND_MSG_LEN];
    CHECK(DNA_VALBIND_OP_STORAGE_REGISTER == 3, "STORAGE_REGISTER op value");
    OK();
    CHECK(dna_valbind_consent_msg(mg, g_chain, DNA_VALBIND_OP_STORAGE_REGISTER,
                                  zero, g_owner, g_pk, 1000) == 0,
          "consent_msg STORAGE_REGISTER"); OK();
    CHECK(mg[36] == 3, "STORAGE_REGISTER op byte at 36"); OK();
    for (size_t i = 0; i < 64; i++)
        CHECK(mg[37 + i] == 0, "STORAGE_REGISTER subject zero");
    OK();
    CHECK(memcmp(mg, ms, 36) == 0 &&
          memcmp(mg + 37, ms + 37, DNA_VALBIND_MSG_LEN - 37) == 0,
          "STORAGE_REGISTER differs from STAKE only in the op byte"); OK();
    {
        uint8_t h[64];
        CHECK(qgp_sha3_512(mg, DNA_VALBIND_MSG_LEN, h) == 0, "sha3");
        CHECK(hex_eq(h, PIN_CONSENT_STORAGE_REGISTER_SHA3,
                     "consent_storage_register.sha3_512"),
              "STORAGE_REGISTER consent message != oracle"); OK();
    }
    return 0;
}

/* ── 2: op / subject rejects, no partial output ─────────────────────── */

static int test_rejects(void) {
    static uint8_t m[DNA_VALBIND_MSG_LEN], guard[DNA_VALBIND_MSG_LEN];
    uint8_t zero[64] = {0};
    memset(guard, 0xAA, sizeof(guard));

    /* 3 is STORAGE_REGISTER since rev 6; 4 is the first unknown op. */
    const uint8_t bad_ops[] = { 0, 4, 0x80, 0xFF };
    for (size_t k = 0; k < sizeof(bad_ops); k++) {
        memcpy(m, guard, sizeof(m));
        CHECK(dna_valbind_consent_msg(m, g_chain, bad_ops[k], g_subject,
                                      g_owner, g_pk, 1000) != 0,
              "accepted an unknown op"); OK();
        CHECK(memcmp(m, guard, sizeof(m)) == 0,
              "rejected op wrote output"); OK();
    }

    /* STAKE with a nonzero subject (last byte only — worst case). */
    {
        uint8_t s[64] = {0};
        s[63] = 1;
        memcpy(m, guard, sizeof(m));
        CHECK(dna_valbind_consent_msg(m, g_chain, DNA_VALBIND_OP_STAKE, s,
                                      g_owner, g_pk, 1000) != 0,
              "STAKE accepted a nonzero subject"); OK();
        CHECK(memcmp(m, guard, sizeof(m)) == 0,
              "rejected STAKE wrote output"); OK();
    }
    /* STORAGE_REGISTER with a nonzero subject: last byte only, first byte
     * only, and a full validator_id-like subject — all refused. */
    {
        uint8_t s_last[64] = {0}, s_first[64] = {0};
        s_last[63] = 1;
        s_first[0] = 1;
        const uint8_t *subs[] = { s_last, s_first, g_subject };
        for (size_t k = 0; k < sizeof(subs) / sizeof(subs[0]); k++) {
            memcpy(m, guard, sizeof(m));
            CHECK(dna_valbind_consent_msg(m, g_chain,
                                          DNA_VALBIND_OP_STORAGE_REGISTER,
                                          subs[k], g_owner, g_pk, 1000) != 0,
                  "STORAGE_REGISTER accepted a nonzero subject"); OK();
            CHECK(memcmp(m, guard, sizeof(m)) == 0,
                  "rejected STORAGE_REGISTER wrote output"); OK();
        }
    }
    /* ROTATE with an all-zero subject. */
    memcpy(m, guard, sizeof(m));
    CHECK(dna_valbind_consent_msg(m, g_chain, DNA_VALBIND_OP_ROTATE, zero,
                                  g_owner, g_pk, 1000) != 0,
          "ROTATE accepted an all-zero subject"); OK();
    CHECK(memcmp(m, guard, sizeof(m)) == 0,
          "rejected ROTATE wrote output"); OK();

    /* NULL guards. */
    CHECK(dna_valbind_consent_msg(NULL, g_chain, 2, g_subject, g_owner,
                                  g_pk, 1) != 0, "NULL out"); OK();
    CHECK(dna_valbind_consent_msg(m, NULL, 2, g_subject, g_owner,
                                  g_pk, 1) != 0, "NULL chain"); OK();
    CHECK(dna_valbind_consent_msg(m, g_chain, 2, NULL, g_owner,
                                  g_pk, 1) != 0, "NULL subject"); OK();
    CHECK(dna_valbind_consent_msg(m, g_chain, 2, g_subject, NULL,
                                  g_pk, 1) != 0, "NULL owner"); OK();
    CHECK(dna_valbind_consent_msg(m, g_chain, 2, g_subject, g_owner,
                                  NULL, 1) != 0, "NULL pk"); OK();
    return 0;
}

/* ── 3: expiry rule ─────────────────────────────────────────────────── */

static int test_expiry(void) {
    const uint64_t H = 5000;
    CHECK(dna_valbind_expiry_ok(H, H) == 1, "expiry == h"); OK();
    CHECK(dna_valbind_expiry_ok(H, H + 1) == 1, "expiry == h+1"); OK();
    CHECK(dna_valbind_expiry_ok(H, H + 720) == 1, "expiry == h+720"); OK();
    CHECK(dna_valbind_expiry_ok(H, H + 721) == 0, "expiry == h+721"); OK();
    CHECK(dna_valbind_expiry_ok(H, H - 1) == 0, "expiry == h-1"); OK();
    CHECK(dna_valbind_expiry_ok(H, 0) == 0, "expiry 0 < h"); OK();
    CHECK(dna_valbind_expiry_ok(0, 0) == 1, "h 0, expiry 0"); OK();
    CHECK(dna_valbind_expiry_ok(0, 720) == 1, "h 0, expiry 720"); OK();
    CHECK(dna_valbind_expiry_ok(0, 721) == 0, "h 0, expiry 721"); OK();
    CHECK(dna_valbind_expiry_ok(0, UINT64_MAX) == 0,
          "h 0, expiry UINT64_MAX"); OK();

    /* Near UINT64_MAX — no overflow either way. */
    CHECK(dna_valbind_expiry_ok(UINT64_MAX, UINT64_MAX) == 1,
          "h == expiry == UINT64_MAX"); OK();
    CHECK(dna_valbind_expiry_ok(UINT64_MAX - 720, UINT64_MAX) == 1,
          "expiry - h == 720 at the top"); OK();
    CHECK(dna_valbind_expiry_ok(UINT64_MAX - 721, UINT64_MAX) == 0,
          "expiry - h == 721 at the top"); OK();
    /* A wrapped rule `expiry <= h + 720` would ACCEPT these: h + 720
     * wraps to a small number that is >= the small expiry. */
    CHECK(dna_valbind_expiry_ok(UINT64_MAX - 10, 5) == 0,
          "small expiry below a huge h (wrap trap)"); OK();
    CHECK(dna_valbind_expiry_ok(UINT64_MAX, 0) == 0,
          "expiry 0 below h UINT64_MAX (wrap trap)"); OK();
    CHECK(dna_valbind_expiry_ok(UINT64_MAX, UINT64_MAX - 1) == 0,
          "expiry one below h at the top"); OK();
    return 0;
}

/* ── 4: validator_id ────────────────────────────────────────────────── */

static int test_validator_id(void) {
    CHECK(DNA_VALBIND_ID_PREIMAGE_LEN == 112, "preimage length"); OK();

    uint8_t chain[32], intent[64];
    CHECK(fill("chain", chain, 32) == 0 && fill("intent", intent, 64) == 0,
          "fill");
    static uint8_t oldpk[2592];
    CHECK(fill("oldpk", oldpk, sizeof(oldpk)) == 0, "fill oldpk");

    /* new: SHA3-512("NDS.VALID.v1" + 4×0x00 ‖ chain ‖ intent) */
    uint8_t pre[112], want[64], got[64];
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALID.v1", 12);
    memcpy(pre + 16, chain, 32);
    memcpy(pre + 48, intent, 64);
    CHECK(qgp_sha3_512(pre, sizeof(pre), want) == 0, "sha3");
    CHECK(dna_validator_id_new(got, chain, intent) == 0, "id_new"); OK();
    CHECK(memcmp(got, want, 64) == 0, "id_new != in-test preimage"); OK();
    CHECK(hex_eq(got, PIN_VID_NEW, "vid_new"), "id_new != oracle"); OK();

    /* migrated: SHA3-512("NDS.VALMIG.v1" + 3×0x00 ‖ chain ‖ SHA3(oldpk)) */
    uint8_t pkh[64], got2[64];
    CHECK(qgp_sha3_512(oldpk, sizeof(oldpk), pkh) == 0, "sha3 pk");
    memset(pre, 0, 16);
    memcpy(pre, "NDS.VALMIG.v1", 13);
    memcpy(pre + 16, chain, 32);
    memcpy(pre + 48, pkh, 64);
    CHECK(qgp_sha3_512(pre, sizeof(pre), want) == 0, "sha3");
    CHECK(dna_validator_id_migrated(got2, chain, oldpk) == 0,
          "id_migrated"); OK();
    CHECK(memcmp(got2, want, 64) == 0,
          "id_migrated != in-test preimage"); OK();
    CHECK(hex_eq(got2, PIN_VID_MIG, "vid_mig"), "id_migrated != oracle");
    OK();

    /* Domain separation: the two tags never collide on the same tail. */
    uint8_t a[64], b[64];
    CHECK(dna_validator_id_new(a, chain, pkh) == 0, "id_new(pkh)");
    CHECK(dna_validator_id_migrated(b, chain, oldpk) == 0, "id_mig");
    CHECK(memcmp(a, b, 64) != 0, "VALID and VALMIG tags collide"); OK();

    /* NULL guards. */
    CHECK(dna_validator_id_new(NULL, chain, intent) != 0, "NULL out"); OK();
    CHECK(dna_validator_id_new(got, NULL, intent) != 0, "NULL chain"); OK();
    CHECK(dna_validator_id_new(got, chain, NULL) != 0, "NULL intent"); OK();
    CHECK(dna_validator_id_migrated(NULL, chain, oldpk) != 0, "NULL out");
    OK();
    CHECK(dna_validator_id_migrated(got, NULL, oldpk) != 0, "NULL chain");
    OK();
    CHECK(dna_validator_id_migrated(got, chain, NULL) != 0, "NULL pk"); OK();
    return 0;
}

/* ── 5: ctx signatures ──────────────────────────────────────────────── */

static int test_signatures(void) {
    static uint8_t pk[QGP_DSA87_PUBLICKEYBYTES], sk[QGP_DSA87_SECRETKEYBYTES];
    static uint8_t pk2[QGP_DSA87_PUBLICKEYBYTES], sk2[QGP_DSA87_SECRETKEYBYTES];
    uint8_t seed[32], seed2[32];
    CHECK(fill("sk-seed", seed, 32) == 0 && fill("sk-seed-2", seed2, 32) == 0,
          "fill seeds");
    CHECK(qgp_dsa87_keypair_derand(pk, sk, seed) == 0, "keypair"); OK();
    CHECK(qgp_dsa87_keypair_derand(pk2, sk2, seed2) == 0, "keypair 2"); OK();

    /* The consent message names the signing key as its consensus_pk. */
    static uint8_t m[DNA_VALBIND_MSG_LEN];
    uint8_t zero[64] = {0};
    CHECK(dna_valbind_consent_msg(m, g_chain, DNA_VALBIND_OP_STAKE, zero,
                                  g_owner, pk, 1000) == 0, "consent msg");

    static uint8_t sig[QGP_DSA87_SIGNATURE_BYTES];
    size_t siglen = 0;
    CHECK(dna_valbind_consent_sign(sig, &siglen, m, sk) == 0, "sign"); OK();
    CHECK(siglen == QGP_DSA87_SIGNATURE_BYTES, "siglen"); OK();
    CHECK(dna_valbind_consent_verify(sig, siglen, m) == 0,
          "verify own consent"); OK();

    /* The same signature through the generic wrapper with the same ctx. */
    CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                               (const uint8_t *)"nodus.valbind.v1", 16,
                               pk) == 0, "verify_ctx same ctx"); OK();

    /* Another ctx (same length, last byte differs) must fail. */
    CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                               (const uint8_t *)"nodus.valbind.v2", 16,
                               pk) != 0, "verify under another ctx"); OK();
    /* A ctx prefix (15 bytes) must fail — ctxlen is bound. */
    CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                               (const uint8_t *)"nodus.valbind.v1", 15,
                               pk) != 0, "verify under a ctx prefix"); OK();
    /* Plain (empty-ctx) verify of a ctx signature must fail. */
    CHECK(qgp_dsa87_verify(sig, siglen, m, DNA_VALBIND_MSG_LEN, pk) != 0,
          "plain verify accepted a ctx signature"); OK();
    /* Another key must fail (generic wrapper, explicit key). */
    CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                               (const uint8_t *)DNA_VALBIND_CTX,
                               DNA_VALBIND_CTX_LEN, pk2) != 0,
          "verify under another key"); OK();
    /* A tampered message (expiry low byte) must fail. */
    m[DNA_VALBIND_MSG_LEN - 1] ^= 0x01;
    CHECK(dna_valbind_consent_verify(sig, siglen, m) != 0,
          "verify of a tampered message"); OK();
    m[DNA_VALBIND_MSG_LEN - 1] ^= 0x01;
    CHECK(dna_valbind_consent_verify(sig, siglen, m) == 0,
          "restored message verifies again"); OK();

    /* ── 6: signer binding ──────────────────────────────────────────── */
    {
        /* Key B signs a message that embeds key A → fails: the verifier
         * uses the embedded key, never the signer's. */
        static uint8_t sb[QGP_DSA87_SIGNATURE_BYTES];
        size_t lb = 0;
        CHECK(dna_valbind_consent_sign(sb, &lb, m, sk2) == 0,
              "sign with a key other than the embedded one"); OK();
        CHECK(dna_valbind_consent_verify(sb, lb, m) != 0,
              "key-B signature accepted over a key-A message"); OK();

        /* Swapping the embedded key to B breaks A's signature, and B's
         * signature over the B-embedding message verifies. */
        static uint8_t mb[DNA_VALBIND_MSG_LEN];
        CHECK(dna_valbind_consent_msg(mb, g_chain, DNA_VALBIND_OP_STAKE, zero,
                                      g_owner, pk2, 1000) == 0, "msg B");
        CHECK(dna_valbind_consent_verify(sig, siglen, mb) != 0,
              "key-A signature accepted over a key-B message"); OK();
        CHECK(dna_valbind_consent_sign(sb, &lb, mb, sk2) == 0, "sign B"); OK();
        CHECK(dna_valbind_consent_verify(sb, lb, mb) == 0, "verify B"); OK();

        /* ROTATE consent signs and verifies too. */
        static uint8_t mr[DNA_VALBIND_MSG_LEN];
        CHECK(dna_valbind_consent_msg(mr, g_chain, DNA_VALBIND_OP_ROTATE,
                                      g_subject, g_owner, pk, 1000) == 0,
              "msg ROTATE");
        CHECK(dna_valbind_consent_sign(sb, &lb, mr, sk) == 0, "sign ROTATE");
        OK();
        CHECK(dna_valbind_consent_verify(sb, lb, mr) == 0, "verify ROTATE");
        OK();

        /* STORAGE_REGISTER consent (op 3) signs and verifies, and is NOT
         * interchangeable with a STAKE consent (op 1) for the same owner,
         * key and expiry: the op byte is inside the signed bytes, so a
         * consent given for one role never verifies as the other. `m` is
         * the valid STAKE message signed by `sig` above. */
        static uint8_t mg[DNA_VALBIND_MSG_LEN];
        static uint8_t sg[QGP_DSA87_SIGNATURE_BYTES];
        size_t lg = 0;
        CHECK(dna_valbind_consent_msg(mg, g_chain,
                                      DNA_VALBIND_OP_STORAGE_REGISTER, zero,
                                      g_owner, pk, 1000) == 0,
              "msg STORAGE_REGISTER");
        CHECK(memcmp(mg, m, 36) == 0 &&
              memcmp(mg + 37, m + 37, DNA_VALBIND_MSG_LEN - 37) == 0,
              "STORAGE_REGISTER / STAKE pair differs only in op"); OK();
        CHECK(dna_valbind_consent_sign(sg, &lg, mg, sk) == 0,
              "sign STORAGE_REGISTER"); OK();
        CHECK(dna_valbind_consent_verify(sg, lg, mg) == 0,
              "verify STORAGE_REGISTER"); OK();
        CHECK(dna_valbind_consent_verify(sg, lg, m) != 0,
              "STORAGE_REGISTER consent accepted as a STAKE consent"); OK();
        CHECK(dna_valbind_consent_verify(sig, siglen, mg) != 0,
              "STAKE consent accepted as a STORAGE_REGISTER consent"); OK();
        CHECK(dna_valbind_consent_verify(sig, siglen, m) == 0,
              "STAKE consent still verifies as STAKE"); OK();

        /* Malformed messages: refused by sign AND by verify, even when the
         * signature itself is valid for the bytes (signed via the generic
         * ctx wrapper to prove the parse is what rejects). */
        static uint8_t bad[DNA_VALBIND_MSG_LEN];
        static uint8_t bs[QGP_DSA87_SIGNATURE_BYTES];
        size_t bl = 0;
        for (int c = 0; c < 7; c++) {
            memcpy(bad, m, sizeof(bad));                  /* valid STAKE */
            switch (c) {
            case 0: bad[3] = 0x02; break;                 /* version 2   */
            case 1: bad[0] = 0x01; break;                 /* version 2^24+1 */
            case 2: bad[36] = 0x00; break;                /* op 0        */
            case 3: bad[36] = 0x04; break;                /* op 4        */
            case 4: bad[37 + 63] = 0x01; break;           /* STAKE, subject≠0 */
            case 5: bad[36] = DNA_VALBIND_OP_STORAGE_REGISTER;
                    bad[37] = 0x01; break;                /* op 3, subject≠0 */
            default: bad[36] = DNA_VALBIND_OP_ROTATE;     /* ROTATE, subject=0 */
                     break;
            }
            CHECK(dna_valbind_consent_sign(bs, &bl, bad, sk) != 0,
                  "consent_sign accepted a malformed message"); OK();
            CHECK(qgp_dsa87_sign_ctx(bs, &bl, bad, DNA_VALBIND_MSG_LEN,
                                     (const uint8_t *)DNA_VALBIND_CTX,
                                     DNA_VALBIND_CTX_LEN, sk) == 0,
                  "raw ctx sign");
            CHECK(qgp_dsa87_verify_ctx(bs, bl, bad, DNA_VALBIND_MSG_LEN,
                                       (const uint8_t *)DNA_VALBIND_CTX,
                                       DNA_VALBIND_CTX_LEN, pk) == 0,
                  "raw ctx signature is valid for the bytes"); OK();
            CHECK(dna_valbind_consent_verify(bs, bl, bad) != 0,
                  "consent_verify accepted a malformed message"); OK();
        }
    }

    /* ctx is NOT the message prefix: a plain signature over ctx ‖ msg
     * must not verify as a ctx signature over msg. */
    {
        static uint8_t cm[16 + DNA_VALBIND_MSG_LEN];
        static uint8_t psig[QGP_DSA87_SIGNATURE_BYTES];
        size_t plen = 0;
        memcpy(cm, DNA_VALBIND_CTX, 16);
        memcpy(cm + 16, m, DNA_VALBIND_MSG_LEN);
        CHECK(qgp_dsa87_sign(psig, &plen, cm, sizeof(cm), sk) == 0,
              "plain sign");
        CHECK(dna_valbind_consent_verify(psig, plen, m) != 0,
              "ctx-prepended plain signature accepted"); OK();
    }

    /* Wrapper argument rules. */
    {
        static uint8_t s2[QGP_DSA87_SIGNATURE_BYTES];
        uint8_t ctx256[256];
        size_t l2 = 0;
        memset(ctx256, 'x', sizeof(ctx256));
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, m, DNA_VALBIND_MSG_LEN,
                                 ctx256, 256, sk) != 0,
              "sign_ctx accepted ctxlen 256"); OK();
        CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                                   ctx256, 256, pk) != 0,
              "verify_ctx accepted ctxlen 256"); OK();
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, m, DNA_VALBIND_MSG_LEN,
                                 NULL, 16, sk) != 0,
              "sign_ctx accepted ctx NULL with ctxlen 16"); OK();
        CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, DNA_VALBIND_MSG_LEN,
                                   NULL, 16, pk) != 0,
              "verify_ctx accepted ctx NULL with ctxlen 16"); OK();
        CHECK(qgp_dsa87_sign_ctx(NULL, &l2, m, 1, ctx256, 1, sk) != 0,
              "sign_ctx NULL sig"); OK();
        CHECK(qgp_dsa87_sign_ctx(s2, NULL, m, 1, ctx256, 1, sk) != 0,
              "sign_ctx NULL siglen"); OK();
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, NULL, 1, ctx256, 1, sk) != 0,
              "sign_ctx NULL m"); OK();
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, m, 1, ctx256, 1, NULL) != 0,
              "sign_ctx NULL sk"); OK();
        CHECK(qgp_dsa87_verify_ctx(NULL, siglen, m, 1, ctx256, 1, pk) != 0,
              "verify_ctx NULL sig"); OK();
        CHECK(qgp_dsa87_verify_ctx(sig, siglen, NULL, 1, ctx256, 1, pk) != 0,
              "verify_ctx NULL m"); OK();
        CHECK(qgp_dsa87_verify_ctx(sig, siglen, m, 1, ctx256, 1, NULL) != 0,
              "verify_ctx NULL pk"); OK();

        /* ctxlen 255 is the largest FIPS 204 ctx: sign/verify round-trip. */
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, m, DNA_VALBIND_MSG_LEN,
                                 ctx256, 255, sk) == 0, "sign ctxlen 255");
        OK();
        CHECK(qgp_dsa87_verify_ctx(s2, l2, m, DNA_VALBIND_MSG_LEN,
                                   ctx256, 255, pk) == 0,
              "verify ctxlen 255"); OK();

        /* (NULL, 0) is the empty ctx — the same domain as the plain
         * wrappers (library pre = 0 ‖ 0). */
        CHECK(qgp_dsa87_sign_ctx(s2, &l2, m, DNA_VALBIND_MSG_LEN,
                                 NULL, 0, sk) == 0, "sign empty ctx"); OK();
        CHECK(qgp_dsa87_verify(s2, l2, m, DNA_VALBIND_MSG_LEN, pk) == 0,
              "empty-ctx signature verifies under plain verify"); OK();
        CHECK(dna_valbind_consent_verify(s2, l2, m) != 0,
              "empty-ctx signature accepted as consent"); OK();
    }

    /* Consent wrapper NULL guards. */
    CHECK(dna_valbind_consent_sign(NULL, &siglen, m, sk) != 0, "NULL sig");
    OK();
    CHECK(dna_valbind_consent_sign(sig, NULL, m, sk) != 0, "NULL siglen");
    OK();
    CHECK(dna_valbind_consent_sign(sig, &siglen, NULL, sk) != 0, "NULL msg");
    OK();
    CHECK(dna_valbind_consent_sign(sig, &siglen, m, NULL) != 0, "NULL sk");
    OK();
    CHECK(dna_valbind_consent_verify(NULL, siglen, m) != 0, "NULL sig");
    OK();
    CHECK(dna_valbind_consent_verify(sig, siglen, NULL) != 0, "NULL msg");
    OK();
    return 0;
}

int main(void) {
    if (load_fixture() != 0) {
        fprintf(stderr, "fixture fill failed\n");
        return 1;
    }
    if (test_layout() != 0) return 1;
    if (test_rejects() != 0) return 1;
    if (test_expiry() != 0) return 1;
    if (test_validator_id() != 0) return 1;
    if (test_signatures() != 0) return 1;
    printf("test_valbind_wire: %d checks OK\n", g_checks);
    return 0;
}
