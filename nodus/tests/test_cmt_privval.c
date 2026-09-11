/**
 * Nodus — cometbft @709fd12b C port, wave R2-B: the private validator's
 * signing logic (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the guard which stops a validator signing twice at one
 * height/round/step is privval/file.go's, rule for rule. If this file
 * failed, one of these would be false:
 *   · `voteToStep` maps a prevote to 2 and a precommit to 3 and REFUSES
 *     anything else, where the reference panics (file.go:33-42);
 *   · `CheckHRS` refuses a regression in height, round or step, reports
 *     "reuse the last signature" only when the HRS matches AND the sign
 *     bytes are there, refuses the match with no sign bytes, and FAULTS
 *     on the one state the reference calls impossible — sign bytes
 *     present with no signature (:100-132);
 *   · a FRESH vote is signed with the host's key over
 *     `cmt_vote_sign_bytes`, the signature VERIFIES against the public
 *     key, and the last-sign state is made durable BEFORE the signature
 *     is handed back (:359-365);
 *   · re-signing the IDENTICAL vote reuses the stored signature and does
 *     NOT call the host's signer or its save again (:342-343);
 *   · re-signing a vote that differs ONLY in its timestamp reuses the
 *     stored signature and RESTORES THE OLD TIMESTAMP, which is the
 *     crash-after-signing case the whole mechanism exists for (:344-348);
 *   · re-signing a vote that differs in anything else is refused as
 *     "conflicting data" (:349-351);
 *   · a non-nil precommit ALWAYS gets a fresh extension signature, and
 *     any other vote carrying an extension is refused (:325-334);
 *   · the same three rules hold for a proposal (:373-410);
 *   · a host that cannot make the last-sign state durable makes the whole
 *     signature FAIL, so an unsaved signature is never used.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, NO CLOCK — the `now` callback returns a fixed value,
 * which is sound because the reference's two clock reads
 * (file.go:441, :461) write the SAME value into both sides of a
 * comparison and can change no result. It uses
 * `qgp_dsa87_keypair_derand` with a fixed seed, so the key pair is the
 * same on every run. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files (the reference's two JSON files are not in this
 * port), no processes, no global state beyond this translation unit's own
 * counters, which every test resets. The FilePV and the key material are
 * heap-allocated because a secret key is 4896 bytes and a FilePV carries
 * a 2592-byte public key; every allocation is freed on the success path.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE DURABILITY IS A FLAG, NOT A FSYNC. The `save` callback here
 *     just counts calls and can be told to fail. That the host's real
 *     implementation writes the state durably before returning — the one
 *     property that makes this guard survive a crash — is NOT tested
 *     here and cannot be; it is wave R3's, under D-13.
 *  2. ML-DSA-87 signatures are HEDGED: signing the same bytes twice gives
 *     different bytes. No signature is ever frozen or compared against a
 *     stored vector; the reuse assertions compare against what the SAME
 *     RUN produced, and the verification assertions call the verifier.
 *  3. A fixed `now` cannot expose a clock that is read where it should
 *     not be. The reference's two reads are neutralisers by construction,
 *     and this file asserts the OUTCOME of the timestamp-only branch, not
 *     that no other clock was consulted.
 *  4. Nothing here proves the reactor calls this at the right moment.
 *     Double-sign safety in a running node is the state machine's and the
 *     WAL's, and those are R2-C's and R3's.
 *
 * ── REFERENCE TEST CASES PORTED ────────────────────────────────────────
 * privval/file_test.go (393 lines, pinned by rev 5, SHA-256
 * 48b1c72f93e65e7969cc1d683ef7f2ecdb5c377e3dc3787c0bf04abff492dfc7):
 * `TestSignVote` (:146-192), `TestSignProposal` (:194-237),
 * `TestDifferByTimestamp` (:239-301) and
 * `TestVoteExtensionsAreAlwaysSigned` (:303-...) — each with an ML-DSA-87
 * key in place of the reference's ed25519 one.
 * NOT PORTED, because every one of them is about the two JSON files this
 * port does not have: `TestGenLoadValidator` (:22-33),
 * `TestResetValidator` (:35-57), `TestLoadOrGenValidator` (:59-80),
 * `TestUnmarshalValidatorState` (:82-105),
 * `TestUnmarshalValidatorKey` (:107-144).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_privval.h"

#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ══ the host side ════════════════════════════════════════════════════ */

typedef struct {
    uint8_t *sk;
    int      sign_calls;
    int      sign_fail;      /* return this instead of signing */
    int      save_calls;
    int      save_fail;
} host_t;

static int host_raw_sign(void *ctx, const uint8_t *sign_bytes, size_t len,
                         uint8_t sig_out[CMT_MAX_SIGNATURE_SIZE],
                         size_t *sig_len)
{
    host_t *h = (host_t *)ctx;

    h->sign_calls++;
    if (h->sign_fail != 0) {
        return h->sign_fail;
    }
    if (qgp_dsa87_sign(sig_out, sig_len, sign_bytes, len, h->sk) != 0) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

static cmt_lss_t g_saved;

static int host_save(void *ctx, const cmt_lss_t *lss)
{
    host_t *h = (host_t *)ctx;

    h->save_calls++;
    if (h->save_fail) {
        return CMT_FAULT;
    }
    g_saved = *lss;
    return CMT_OK;
}

/* file.go:441 and :461. A FIXED value: the reference writes it into BOTH
 * timestamps before comparing, so it cannot change any result. */
static const cmt_time_t NOW = { 1700000123LL, 456 };

static int host_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    *out = NOW;
    return CMT_OK;
}

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static uint8_t  CHAIN[32];
static uint8_t  HASH_A[64], HASH_B[64];
static uint8_t *g_pk;
static uint8_t *g_sk;
static host_t   g_host;

static const cmt_time_t TS_A = { 1700000000LL, 123456789 };
static const cmt_time_t TS_B = { 1700000001LL, 987654321 };

static void pat(uint8_t *out, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static void bid_a(cmt_pb_block_id_t *bid, const uint8_t *hash)
{
    cmt_pb_block_id_init(bid);
    memcpy(bid->hash, hash, 64);
    bid->hash_len = 64;
    bid->part_set_header.total = 7;
    memcpy(bid->part_set_header.hash, HASH_A, 64);
    bid->part_set_header.hash_len = 64;
}

static void vote_precommit(cmt_pb_vote_t *v, const uint8_t *bid_hash,
                           cmt_time_t ts)
{
    cmt_pb_vote_init(v);
    v->type   = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    v->height = 9;
    v->round  = 2;
    bid_a(&v->block_id, bid_hash);
    v->timestamp = ts;
    pat(v->validator_address, 32, 0x40);
    v->validator_address_len = 32;
    v->validator_index = 1;
}

static void pv_reset(cmt_file_pv_t *pv)
{
    memset(pv, 0, sizeof(*pv));
    memcpy(pv->pub_key, g_pk, CMT_PB_PUBKEY_LEN);
    cmt_lss_reset(&pv->last_sign_state);
    pv->raw_sign             = host_raw_sign;
    pv->sign_ctx             = &g_host;
    pv->save_last_sign_state = host_save;
    pv->save_ctx             = &g_host;
    pv->now                  = host_now;
    pv->now_ctx              = &g_host;
    g_host.sign_calls = 0;
    g_host.sign_fail  = 0;
    g_host.save_calls = 0;
    g_host.save_fail  = 0;
}

/* ══ voteToStep ═══════════════════════════════════════════════════════ */

static int test_vote_to_step(void)
{
    cmt_pb_vote_t v;
    int8_t        step = -1;

    cmt_pb_vote_init(&v);
    v.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
    CHECK(cmt_vote_to_step(&v, &step) == CMT_OK && step == CMT_STEP_PREVOTE,
          "a prevote is step 2 (file.go:35-36)");
    v.type = (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT;
    CHECK(cmt_vote_to_step(&v, &step) == CMT_OK &&
          step == CMT_STEP_PRECOMMIT,
          "a precommit is step 3 (file.go:37-38)");
    /* The three refusals are CMT_FAULT, not CMT_REJECT: the vote a signer
     * receives is built by the node's own state machine
     * (consensus/state.go:2385-2392), so a third type is a node-local
     * invariant broken — the panic rule's fail-stop half
     * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8 rev 4). */
    v.type = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;
    CHECK(cmt_vote_to_step(&v, &step) == CMT_FAULT,
          "a PROPOSAL is not a vote type — the reference panics (:40)");
    v.type = (int32_t)CMT_PB_MSG_TYPE_UNKNOWN;
    CHECK(cmt_vote_to_step(&v, &step) == CMT_FAULT, "and neither is 0");
    v.type = 12345;
    CHECK(cmt_vote_to_step(&v, &step) == CMT_FAULT,
          "nor an unknown enum value");
    CHECK(cmt_vote_to_step(NULL, &step) == CMT_FAULT, "NULL");
    OK();
    return 0;
}

/* ══ CheckHRS, one row per branch of file.go:100-132 ══════════════════ */

static int test_check_hrs(void)
{
    cmt_lss_t lss;
    bool      same = true;

    /* A reset state accepts anything forward-going. */
    CHECK(cmt_lss_reset(&lss) == CMT_OK, "reset");
    CHECK(lss.height == 0 && lss.round == 0 && lss.step == CMT_STEP_NONE &&
          !lss.has_signature && !lss.has_sign_bytes,
          "reset clears both slices to NIL, not to empty (:89-90)");
    CHECK(cmt_lss_check_hrs(&lss, 1, 0, CMT_STEP_PROPOSE, &same) == CMT_OK &&
          !same, "a fresh state accepts a new HRS and reuses nothing");
    OK();

    lss.height = 5;
    lss.round  = 3;
    lss.step   = CMT_STEP_PREVOTE;          /* 2 */

    CHECK(cmt_lss_check_hrs(&lss, 4, 9, 3, &same) == CMT_REJECT,
          "height regression (:102-104)");
    CHECK(cmt_lss_check_hrs(&lss, 5, 2, 3, &same) == CMT_REJECT,
          "round regression at the same height (:107-109)");
    CHECK(cmt_lss_check_hrs(&lss, 5, 3, 1, &same) == CMT_REJECT,
          "step regression at the same height and round (:112-119)");
    OK();

    CHECK(cmt_lss_check_hrs(&lss, 6, 0, 0, &same) == CMT_OK && !same,
          "a higher height is accepted");
    CHECK(cmt_lss_check_hrs(&lss, 5, 4, 0, &same) == CMT_OK && !same,
          "a higher round at the same height is accepted");
    CHECK(cmt_lss_check_hrs(&lss, 5, 3, 3, &same) == CMT_OK && !same,
          "a higher step at the same height and round is accepted");
    OK();

    /* An EXACT match with no sign bytes: "no SignBytes found" (:127). */
    CHECK(cmt_lss_check_hrs(&lss, 5, 3, 2, &same) == CMT_REJECT && !same,
          "an exact match with no stored sign bytes is refused (:127)");
    OK();

    /* An exact match WITH sign bytes and a signature: reuse (:125). */
    lss.has_sign_bytes = true;
    lss.sign_bytes_len = 4;
    lss.has_signature  = true;
    lss.signature_len  = 4;
    CHECK(cmt_lss_check_hrs(&lss, 5, 3, 2, &same) == CMT_OK && same,
          "an exact match with both stored says REUSE (:125)");
    OK();

    /* Sign bytes with NO signature: the reference PANICS (:122-124). It is
     * this node's own state contradicting itself, so it is FAULT. */
    lss.has_signature = false;
    CHECK(cmt_lss_check_hrs(&lss, 5, 3, 2, &same) == CMT_FAULT,
          "sign bytes with no signature is FAULT, where the reference"
          " panics (:123)");
    OK();

    CHECK(cmt_lss_check_hrs(NULL, 1, 1, 1, &same) == CMT_FAULT, "NULL");
    CHECK(cmt_lss_check_hrs(&lss, 1, 1, 1, NULL) == CMT_FAULT, "NULL out");
    OK();
    return 0;
}

/* ══ signVote ═════════════════════════════════════════════════════════ */

static int test_sign_vote(void)
{
    cmt_file_pv_t *pv;
    cmt_pb_vote_t  v;
    cmt_pb_vote_t  v2;
    uint8_t        sb[CMT_VOTE_SIGN_BYTES_MAX];
    uint8_t        first_sig[CMT_MAX_SIGNATURE_SIZE];
    size_t         first_sig_len;
    size_t         n = 0;

    pv = (cmt_file_pv_t *)malloc(sizeof(*pv));
    CHECK(pv != NULL, "allocation");
    pv_reset(pv);

    /* file_test.go:146-192 — a fresh vote is signed and verifies. */
    vote_precommit(&v, HASH_B, TS_A);
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v) == CMT_OK,
          "a fresh precommit signs");
    CHECK(g_host.sign_calls == 2,
          "the host signed TWICE: the vote and its extension, because a"
          " non-nil precommit always gets an extension signature (:326)");
    CHECK(g_host.save_calls == 1, "and the state was saved once (:421)");
    CHECK(v.signature_len > 0 && v.extension_signature_len > 0,
          "both signatures are set");
    CHECK(cmt_vote_sign_bytes(CHAIN, sizeof(CHAIN), &v, sb, sizeof(sb), &n)
          == CMT_OK, "sign bytes");
    CHECK(qgp_dsa87_verify(v.signature, v.signature_len, sb, n, g_pk) == 0,
          "and the vote signature verifies against the public key");
    CHECK(g_saved.height == 9 && g_saved.round == 2 &&
          g_saved.step == CMT_STEP_PRECOMMIT && g_saved.has_sign_bytes &&
          g_saved.sign_bytes_len == n &&
          memcmp(g_saved.sign_bytes, sb, n) == 0,
          "the saved state carries the exact bytes that were signed");
    OK();

    memcpy(first_sig, v.signature, v.signature_len);
    first_sig_len = v.signature_len;

    /* :341-343 — the IDENTICAL vote reuses the stored signature. The host
     * signs only the EXTENSION again (:326-328 is before the sameHRS
     * branch and is unconditional for a non-nil precommit). */
    g_host.sign_calls = 0;
    g_host.save_calls = 0;
    vote_precommit(&v2, HASH_B, TS_A);
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_OK,
          "re-signing the identical vote succeeds");
    CHECK(g_host.sign_calls == 1,
          "the host signed ONCE — the extension only");
    CHECK(g_host.save_calls == 0,
          "and nothing was saved: the state did not move");
    CHECK(v2.signature_len == first_sig_len &&
          memcmp(v2.signature, first_sig, first_sig_len) == 0,
          "the STORED signature was reused, byte for byte (:343)");
    OK();

    /* :344-348 — a vote that differs ONLY in its timestamp reuses the
     * signature AND takes the OLD timestamp back. This is the whole
     * point: the signature covers the old timestamp, so the vote must
     * carry it. */
    g_host.sign_calls = 0;
    vote_precommit(&v2, HASH_B, TS_B);
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_OK,
          "a vote differing only in its timestamp succeeds");
    CHECK(v2.timestamp.seconds == TS_A.seconds &&
          v2.timestamp.nanos == TS_A.nanos,
          "and its timestamp is REPLACED by the signed one (:347)");
    CHECK(v2.signature_len == first_sig_len &&
          memcmp(v2.signature, first_sig, first_sig_len) == 0,
          "with the stored signature (:348)");
    CHECK(cmt_vote_sign_bytes(CHAIN, sizeof(CHAIN), &v2, sb, sizeof(sb), &n)
          == CMT_OK &&
          qgp_dsa87_verify(v2.signature, v2.signature_len, sb, n, g_pk) == 0,
          "so the result still verifies — which it would not if the"
          " timestamp had been left alone");
    CHECK(g_host.save_calls == 0, "and still nothing was saved");
    OK();

    /* :349-351 — anything else at the same HRS is "conflicting data". */
    vote_precommit(&v2, HASH_A, TS_A);        /* a DIFFERENT BlockID */
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_REJECT,
          "a different block at the same height/round/step is refused");
    OK();

    /* :332-334 — an extension on a vote that is not a non-nil precommit. */
    {
        static const uint8_t ext[3] = { 'a', 'b', 'c' };

        pv_reset(pv);
        vote_precommit(&v2, HASH_B, TS_A);
        v2.type = (int32_t)CMT_PB_MSG_TYPE_PREVOTE;
        v2.extension.data = ext;
        v2.extension.len  = sizeof(ext);
        CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_REJECT,
              "a PREVOTE carrying an extension is refused (:333)");

        /* A NIL precommit — zero BlockID — carrying one, likewise. */
        pv_reset(pv);
        vote_precommit(&v2, HASH_B, TS_A);
        cmt_pb_block_id_init(&v2.block_id);
        v2.extension.data = ext;
        v2.extension.len  = sizeof(ext);
        CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_REJECT,
              "and so is a NIL precommit carrying one");

        /* A nil precommit WITHOUT one signs, and gets NO extension
         * signature. */
        pv_reset(pv);
        vote_precommit(&v2, HASH_B, TS_A);
        cmt_pb_block_id_init(&v2.block_id);
        CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_OK &&
              v2.signature_len > 0 && v2.extension_signature_len == 0,
              "a nil precommit is signed with no extension signature");
        CHECK(g_host.sign_calls == 1, "so the host signed only once");
        OK();
    }

    /* A host that cannot make the state durable FAILS the signature. */
    pv_reset(pv);
    g_host.save_fail = 1;
    vote_precommit(&v2, HASH_B, TS_A);
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_FAULT,
          "an unsaveable state makes the whole signature fail");
    OK();

    /* A signer that fails passes its code through (:360-362). */
    pv_reset(pv);
    g_host.sign_fail = CMT_REJECT;
    vote_precommit(&v2, HASH_B, TS_A);
    CHECK(cmt_pv_sign_vote(pv, CHAIN, sizeof(CHAIN), &v2) == CMT_REJECT,
          "a signer failure is passed through");
    OK();

    free(pv);
    return 0;
}

/* ══ signProposal ═════════════════════════════════════════════════════ */

static int test_sign_proposal(void)
{
    cmt_file_pv_t    *pv;
    cmt_pb_proposal_t p;
    cmt_pb_proposal_t p2;
    uint8_t           sb[CMT_PROPOSAL_SIGN_BYTES_MAX];
    uint8_t           first_sig[CMT_MAX_SIGNATURE_SIZE];
    size_t            first_sig_len;
    size_t            n = 0;

    pv = (cmt_file_pv_t *)malloc(sizeof(*pv));
    CHECK(pv != NULL, "allocation");
    pv_reset(pv);

    /* file_test.go:194-237 — a fresh proposal is signed and verifies. */
    cmt_pb_proposal_init(&p);
    p.type      = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;
    p.height    = 9;
    p.round     = 2;
    p.pol_round = -1;
    bid_a(&p.block_id, HASH_B);
    p.timestamp = TS_A;
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p) == CMT_OK,
          "a fresh proposal signs");
    CHECK(g_host.sign_calls == 1 && g_host.save_calls == 1,
          "one signature, one save — a proposal has no extension");
    CHECK(cmt_proposal_sign_bytes(CHAIN, sizeof(CHAIN), &p, sb, sizeof(sb),
                                  &n) == CMT_OK, "sign bytes");
    CHECK(qgp_dsa87_verify(p.signature, p.signature_len, sb, n, g_pk) == 0,
          "and it verifies");
    CHECK(g_saved.step == CMT_STEP_PROPOSE,
          "the state records step 1, stepPropose (:374)");
    OK();

    memcpy(first_sig, p.signature, p.signature_len);
    first_sig_len = p.signature_len;

    /* :390-392 — identical, reuse. */
    g_host.sign_calls = 0;
    g_host.save_calls = 0;
    p2 = p;
    p2.signature_len = 0;
    memset(p2.signature, 0, sizeof(p2.signature));
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p2) == CMT_OK &&
          p2.signature_len == first_sig_len &&
          memcmp(p2.signature, first_sig, first_sig_len) == 0,
          "the identical proposal reuses the stored signature");
    CHECK(g_host.sign_calls == 0 && g_host.save_calls == 0,
          "with no new signature and no save");
    OK();

    /* :393-395 — differing only in the timestamp: reuse, and take the old
     * timestamp back. */
    p2 = p;
    p2.timestamp = TS_B;
    p2.signature_len = 0;
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p2) == CMT_OK &&
          p2.timestamp.seconds == TS_A.seconds &&
          p2.timestamp.nanos == TS_A.nanos &&
          p2.signature_len == first_sig_len &&
          memcmp(p2.signature, first_sig, first_sig_len) == 0,
          "a timestamp-only difference reuses both (:394-395)");
    OK();

    /* :396-397 — anything else is "conflicting data". */
    p2 = p;
    bid_a(&p2.block_id, HASH_A);
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p2) == CMT_REJECT,
          "a different block at the same HRS is refused");
    OK();

    /* A height regression is refused before anything is signed. */
    pv_reset(pv);
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p) == CMT_OK,
          "sign at height 9");
    p2 = p;
    p2.height = 8;
    p2.signature_len = 0;
    CHECK(cmt_pv_sign_proposal(pv, CHAIN, sizeof(CHAIN), &p2) == CMT_REJECT,
          "and a proposal at height 8 is refused — CheckHRS");
    OK();

    free(pv);
    return 0;
}

/* ══ the adapters ═════════════════════════════════════════════════════ */

static int test_adapters(void)
{
    cmt_file_pv_t   *pv;
    cmt_sign_vote_fn fn = cmt_pv_sign_vote_adapter;
    cmt_pb_vote_t    v;
    uint8_t          sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t           n = 0;

    pv = (cmt_file_pv_t *)malloc(sizeof(*pv));
    CHECK(pv != NULL, "allocation");
    pv_reset(pv);

    /* The assignment above is the real assertion — it would not compile if
     * the adapter did not have the R1 callback's exact shape
     * (cmt_vote.h:332-333), which is what lets a FilePV be handed to
     * cmt_sign_and_check_vote (cmt_vote.h:351). */
    vote_precommit(&v, HASH_B, TS_A);
    CHECK(fn(pv, CHAIN, sizeof(CHAIN), &v) == CMT_OK,
          "signing through the adapter works");
    CHECK(cmt_vote_sign_bytes(CHAIN, sizeof(CHAIN), &v, sb, sizeof(sb), &n)
          == CMT_OK &&
          qgp_dsa87_verify(v.signature, v.signature_len, sb, n, g_pk) == 0,
          "and produces a verifying signature");
    OK();

    /* The public key comes back as it was set. */
    {
        uint8_t *out = (uint8_t *)malloc(CMT_PB_PUBKEY_LEN);

        CHECK(out != NULL, "allocation");
        CHECK(cmt_pv_get_pub_key(pv, out) == CMT_OK &&
              memcmp(out, g_pk, CMT_PB_PUBKEY_LEN) == 0,
              "GetPubKey returns the stored key (file.go:256-258)");
        free(out);
        OK();
    }

    free(pv);
    return 0;
}

int main(void)
{
    uint8_t seed[32];

    pat(CHAIN, sizeof(CHAIN), 0x50);
    pat(HASH_A, sizeof(HASH_A), 0x10);
    pat(HASH_B, sizeof(HASH_B), 0x20);
    pat(seed, sizeof(seed), 0x77);

    g_pk = (uint8_t *)malloc(QGP_DSA87_PUBLICKEYBYTES);
    g_sk = (uint8_t *)malloc(QGP_DSA87_SECRETKEYBYTES);
    if (g_pk == NULL || g_sk == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) {
        fprintf(stderr, "keypair\n");
        return 1;
    }
    memset(&g_host, 0, sizeof(g_host));
    g_host.sk = g_sk;

    if (test_vote_to_step() != 0)  { return 1; }
    if (test_check_hrs() != 0)     { return 1; }
    if (test_sign_vote() != 0)     { return 1; }
    if (test_sign_proposal() != 0) { return 1; }
    if (test_adapters() != 0)      { return 1; }

    free(g_pk);
    free(g_sk);
    printf("test_cmt_privval: OK (%d groups)\n", g_checks);
    return 0;
}
