/**
 * @file test_transcript_grind.c
 * @brief Unit test for dnac_transcript_grind (query/commit PoW grinding).
 *
 * Validates the grind CONTRACT (self-contained — no oracle vector needed):
 *  - grind(0) returns witness 0 and leaves the transcript UNCHANGED (so
 *    query_pow=0 proofs stay byte-identical to the pre-grind path);
 *  - for bits>0, grind returns a witness w that check_witness(bits, w) ACCEPTS
 *    on an identical fresh transcript, and grind advances the transcript state
 *    IDENTICALLY to check_witness(bits, w) (so prover and verifier stay in sync).
 *
 * Grounded to Plonky3 grinding_challenger.rs:29-46.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "transcript.h"
#include "field_goldilocks.h"

static int fails = 0;
#define CHECK(c, n) do { \
    printf("  %-56s %s\n", n, (c) ? "PASS" : "FAIL"); \
    if (!(c)) fails++; \
} while (0)

int main(void) {
    printf("test_transcript_grind: query-PoW grind (Plonky3 grinding_challenger)\n");
    const uint8_t seed[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    /* T1/T2 — bits==0 is a no-op: witness 0, transcript state unchanged. */
    {
        dnac_transcript_t *t = dnac_transcript_init(seed, sizeof seed);
        dnac_transcript_t *ref = dnac_transcript_clone(t);
        fp_t w = dnac_transcript_grind(t, 0);
        CHECK(gold_fp_to_u64(w) == 0, "T1 grind(0) -> witness 0");
        CHECK(dnac_transcript_sample_bits(t, 8) == dnac_transcript_sample_bits(ref, 8),
              "T2 grind(0) leaves transcript state unchanged");
        dnac_transcript_free(t);
        dnac_transcript_free(ref);
    }

    /* T3.. — bits>0: grind finds a valid witness + advances state like check_witness. */
    for (size_t bits = 4; bits <= 12; bits += 4) {
        dnac_transcript_t *t = dnac_transcript_init(seed, sizeof seed);
        dnac_transcript_t *probe = dnac_transcript_clone(t); /* pre-grind snapshot */

        fp_t w = dnac_transcript_grind(t, bits);

        /* A fresh transcript at the same pre-grind state must ACCEPT w. */
        int ok = dnac_transcript_check_witness(probe, bits, w);
        char n1[80];
        snprintf(n1, sizeof n1, "T grind(%zu): witness %llu accepted by check_witness",
                 bits, (unsigned long long)gold_fp_to_u64(w));
        CHECK(ok, n1);

        /* grind(t) and check_witness(probe) both did observe(w)+sample_bits(bits),
         * so the two transcripts are now in the SAME state. */
        char n2[80];
        snprintf(n2, sizeof n2, "T grind(%zu): state == check_witness state", bits);
        CHECK(dnac_transcript_sample_bits(t, 16) == dnac_transcript_sample_bits(probe, 16), n2);

        dnac_transcript_free(t);
        dnac_transcript_free(probe);
    }

    printf("test_transcript_grind: %s (%d fail)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
