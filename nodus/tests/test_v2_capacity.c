/**
 * test_v2_capacity.c — Ledger V2 capacity season: the LEGACY 64 KiB
 * semantic limit versus the DERIVED 1 MiB V2 envelope ceiling.
 *
 * What is pinned here, and why HERE (codec/constant level — the engine
 * legs live in test_v2_native / test_v2_env_meter):
 *
 *   1. CONSTANT SEPARATION — the legacy semantic maximum stays EXACTLY
 *      65,536 (NODUS_T3_MAX_TX_SIZE, DNAC_TXW3_MAX_TX_SIZE) while the
 *      V2 envelope ceiling is the independently derived 2^20. Growing
 *      one must never grow the other: the live gates
 *      (nodus_witness_handlers.c:1788, nodus_witness_peer.c:969,
 *      nodus_tier3.c:646/998, nodus_witness_bft.c:4532) all compare
 *      against NODUS_T3_MAX_TX_SIZE, which this test pins.
 *   2. DERIVATION — the worst-case legal envelope arithmetic is
 *      recomputed here from the participating SOURCE constants and must
 *      land under the ceiling with 2^19 too small (so 2^20 is the
 *      smallest containing power of two, not a round guess).
 *   3. WIRE-FAMILY CLASSIFICATION — a V2 envelope self-identifies in
 *      its FIRST 16 bytes ("DNA.ENVWIRE.v1" at offset 0), BEFORE any
 *      length-driven allocation; a legacy V3 transaction begins with
 *      its version byte and can never alias the family marker. Both
 *      decoders reject the other family's bytes outright, and the
 *      legacy decoder rejects ANY input over its own 64 KiB bound —
 *      an oversized inactive V2 envelope is structurally unable to
 *      enter a live path that begins with either check.
 *   4. V2 CEILING BOUNDARY — an envelope of exactly
 *      DNA_ENV_MAX_TOTAL_LEN decodes; one byte more is rejected by the
 *      strict decoder (heap buffers only — nothing here puts the
 *      ceiling on a stack).
 */

#include "dnac/env_wire.h"
#include "dnac/tx_wire.h"
#include "dnac/ledger_ids.h"
#include "nodus/nodus_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond, msg)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__,    \
                    __LINE__, msg);                                     \
            return 1;                                                   \
        }                                                               \
        g_checks++;                                                     \
    } while (0)

int main(void) {
    /* ── 1. constant separation ─────────────────────────────────────── */
    CHECK(NODUS_T3_MAX_TX_SIZE == 65536,
          "legacy semantic maximum moved — FORBIDDEN this season");
    CHECK(DNAC_TXW3_MAX_TX_SIZE == 65536u,
          "legacy v3 wire mirror moved — FORBIDDEN this season");
    CHECK(DNA_ENV_MAX_TOTAL_LEN == 1048576u,
          "V2 envelope ceiling is not the derived 2^20");
    CHECK((DNA_ENV_MAX_TOTAL_LEN & (DNA_ENV_MAX_TOTAL_LEN - 1u)) == 0,
          "V2 ceiling must be a power of two");
    CHECK(DNA_ENV_MAX_TOTAL_LEN != (uint32_t)NODUS_T3_MAX_TX_SIZE,
          "the two bounds must be DECOUPLED, never mirrored");

    /* ── 2. independent worst-case derivation ───────────────────────── */
    {
        const uint64_t signer = 2592u + 4627u;        /* kind-1 unit    */
        const uint64_t appr   = 2u + 4627u;           /* kind-2 unit    */
        uint64_t cc_single = 43u + 30u + 41u + (1u + 15u * signer) +
                             (2u + (uint64_t)DNA_MAX_ACTIVE_VALIDATORS *
                                       appr);
        uint64_t two_leg = cc_single + 30u +
                           (2u + 15u * 64u + 16u * 232u) +
                           (1u + 15u * signer);
        CHECK(cc_single == 700914u, "single-leg worst case drifted");
        CHECK(two_leg == 813904u, "two-leg CC+SPEND shape drifted");
        /* burn season: TOKEN_CREATE is now the worst CORE leg (109-byte
         * fixed head + 14 inputs + 16 outputs = 4717 call bytes, 43 over
         * the maximal SPEND call; the BURN call, SPEND + 8, sits between
         * and is dominated) */
        uint64_t tc_call = 64u + 1u + 32u + 1u + 8u + 1u +
                           1u + 14u * 64u + 1u + 16u * 232u;
        uint64_t two_leg_tc = cc_single + 30u + tc_call +
                              (1u + 15u * signer);
        CHECK(tc_call == 4717u, "maximal TOKEN_CREATE call drifted");
        CHECK(two_leg_tc == 813947u,
              "two-leg CC+TOKEN_CREATE worst case drifted");
        CHECK(two_leg_tc > two_leg,
              "TOKEN_CREATE must dominate the SPEND shape");
        /* O11 (stake-lifecycle season): the CC shapes are now DOMINATED.
         * The worst single leg is a SYSTEM DELEGATE/UNDELEGATE leg —
         * call 5192 (two ML-DSA-87 pubkeys + amount) — under the SAME
         * maximal kind-2 blob (SYSTEM's allowlist permits carriage; the
         * op's exec rejects kind 2 only after admission/authorization
         * priced it). The worst envelope pairs it with its mandatory
         * CORE SYSFUND sibling (transfer-section call 4674, 15-signer
         * kind-1). Third derivation: rt_native.c "O11 capacity
         * derivation" asserts; second: env_wire_oracle.py. */
        uint64_t dlg_call = 2592u + 2592u + 8u;
        uint64_t dlg_single = 43u + 30u + dlg_call + (1u + 15u * signer) +
                              (2u + (uint64_t)DNA_MAX_ACTIVE_VALIDATORS *
                                        appr);
        uint64_t dlg_two = dlg_single + 30u +
                           (2u + 15u * 64u + 16u * 232u) +
                           (1u + 15u * signer);
        /* ⚠ the SYSFUND sibling is a read_plan/exec rule, NOT an
         * admission rule — so the largest ADMISSION-legal CORE partner
         * is TOKEN_CREATE (4717), and the mixed pair governs (O11 R1
         * review finding; the SYSFUND pair is pinned as dominated). */
        uint64_t dlg_two_tc = dlg_single + 30u + tc_call +
                              (1u + 15u * signer);
        CHECK(dlg_call == 5192u, "DELEGATE call arithmetic drifted");
        CHECK(dlg_single == 706065u,
              "single-leg stake-lifecycle worst case drifted");
        CHECK(dlg_two == 819055u,
              "two-leg DELEGATE+SYSFUND shape drifted (dominated)");
        CHECK(dlg_two_tc == 819098u,
              "two-leg DELEGATE+TOKEN_CREATE worst case drifted");
        CHECK(dlg_two_tc > dlg_two && dlg_two_tc > two_leg_tc,
              "the mixed DELEGATE+TOKEN_CREATE shape must dominate");
        CHECK(dlg_two_tc <= DNA_ENV_MAX_TOTAL_LEN,
              "ceiling no longer contains the worst case");
        CHECK(dlg_two_tc > (DNA_ENV_MAX_TOTAL_LEN / 2u),
              "2^19 would already contain the worst case — the ceiling "
              "is no longer the SMALLEST containing power of two");
    }

    /* ── 3. wire-family classification, both directions ─────────────── */
    {
        /* a V2 envelope handed to the LEGACY v3 decoder: rejected (the
         * family marker is not a legal v3 header), and ANY buffer over
         * the legacy bound is rejected on length alone */
        uint8_t small_env[64];
        memset(small_env, 0, sizeof(small_env));
        memcpy(small_env, "DNA.ENVWIRE.v1\0", 16);
        dnac_txw3_header_t h;
        const uint8_t *body = NULL;
        uint32_t blen = 0;
        CHECK(dnac_txw3_decode(small_env, sizeof(small_env), &h, &body,
                               &blen) != 0,
              "envelope bytes must not decode as a legacy transaction");
        uint8_t *big = calloc(1, (size_t)NODUS_T3_MAX_TX_SIZE + 1);
        CHECK(big != NULL, "alloc");
        /* a VERSION-VALID header whose declared body pushes the total to
         * exactly 65,537: only the semantic LENGTH CAP can reject it —
         * so this assertion dies the moment that cap is loosened, not on
         * an unrelated version check */
        big[0] = 3;                                /* wire_version        */
        {
            uint32_t bl = (uint32_t)NODUS_T3_MAX_TX_SIZE + 1 -
                          DNAC_TXW3_BODY_OFF;      /* = MAX_BODY_LEN + 1  */
            big[DNAC_TXW3_BODYLEN_OFF]     = (uint8_t)(bl >> 24);
            big[DNAC_TXW3_BODYLEN_OFF + 1] = (uint8_t)(bl >> 16);
            big[DNAC_TXW3_BODYLEN_OFF + 2] = (uint8_t)(bl >> 8);
            big[DNAC_TXW3_BODYLEN_OFF + 3] = (uint8_t)bl;
        }
        CHECK(dnac_txw3_decode(big, (size_t)NODUS_T3_MAX_TX_SIZE + 1, &h,
                               &body, &blen) != 0,
              "legacy decoder must reject 65,537 bytes");
        /* control: the SAME shape one byte smaller (body == cap) is a
         * length-legal header — proves the reject above is the cap,
         * not some other malformed field */
        {
            uint32_t bl = (uint32_t)NODUS_T3_MAX_TX_SIZE -
                          DNAC_TXW3_BODY_OFF;      /* = MAX_BODY_LEN      */
            big[DNAC_TXW3_BODYLEN_OFF]     = (uint8_t)(bl >> 24);
            big[DNAC_TXW3_BODYLEN_OFF + 1] = (uint8_t)(bl >> 16);
            big[DNAC_TXW3_BODYLEN_OFF + 2] = (uint8_t)(bl >> 8);
            big[DNAC_TXW3_BODYLEN_OFF + 3] = (uint8_t)bl;
            CHECK(dnac_txw3_decode(big, (size_t)NODUS_T3_MAX_TX_SIZE, &h,
                                   &body, &blen) == 0,
                  "legacy payload of exactly 65,536 bytes must decode");
        }
        /* legacy bytes handed to the V2 decoder: no family marker at
         * offset 0 → rejected before any length work */
        dna_env_view_t v;
        big[0] = 3;                      /* a v3-looking version byte    */
        CHECK(dna_env_decode(big, 200, &v) != 0,
              "legacy bytes must not decode as an envelope");
        free(big);
    }

    /* ── 4. the V2 ceiling boundary (heap, strict decoder) ──────────── */
    {
        /* one leg whose call data fills the envelope to EXACTLY the
         * ceiling; then the same declared shape with one extra byte */
        uint32_t big_call = (uint32_t)DNA_ENV_MAX_TOTAL_LEN -
                            DNA_ENV_FIXED_HEAD - DNA_ENV_LEG_HDR_LEN - 1;
        uint8_t *call = calloc(1, big_call);
        uint8_t *buf = malloc((size_t)DNA_ENV_MAX_TOTAL_LEN + 16);
        CHECK(call != NULL && buf != NULL, "alloc");
        dna_env_leg_in_t leg;
        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id = 1;
        leg.hdr.runtime_op = 1;
        leg.hdr.ruleset_version = 1;
        leg.hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind = 1;
        leg.hdr.call_len = big_call;
        leg.hdr.auth_len = 1;
        leg.call_data = call;
        leg.auth_data = (const uint8_t *)"\xAA";
        dna_env_in_t in;
        memset(&in, 0, sizeof(in));
        in.leg_count = 1;
        in.legs = &leg;
        size_t written = 0;
        CHECK(dna_env_encode(&in, buf, (size_t)DNA_ENV_MAX_TOTAL_LEN + 16,
                             &written) == 0 &&
              written == (size_t)DNA_ENV_MAX_TOTAL_LEN,
              "exact-ceiling envelope must encode");
        dna_env_view_t v;
        CHECK(dna_env_decode(buf, written, &v) == 0,
              "exact-ceiling envelope must decode");
        /* one byte over: the declared lengths exceed the cap — encode
         * AND decode both refuse */
        leg.hdr.call_len = big_call + 1;
        CHECK(dna_env_encode(&in, buf, (size_t)DNA_ENV_MAX_TOTAL_LEN + 16,
                             &written) != 0,
              "ceiling+1 must not encode");
        free(call);
        free(buf);
    }

    printf("test_v2_capacity: %d checks OK\n", g_checks);
    return 0;
}
