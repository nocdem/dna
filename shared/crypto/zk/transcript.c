/**
 * @file transcript.c
 * @brief DNAC Fiat-Shamir transcript — Poseidon2 DuplexChallenger backend
 *        (P1c cutover; thin heap wrapper over duplex_challenger.{c,h}).
 *
 * All sponge semantics live in (and are byte-match-KAT'd through)
 * duplex_challenger.c. This wrapper only owns allocation + the opaque handle.
 * The pre-P1c SHA3-512 HashChallenger backend is DELETED (G-SEC-P1-5 clean
 * cutover — no byte path remains reachable).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "transcript.h"

#include <stdlib.h>
#include <string.h>

/* Q1 domain-separator bytes — documentation/derivation constant (the absorbed
 * form is DNAC_DUPLEX_DS_PREFIX, its 4 LE u64 limbs; see transcript.h). */
const uint8_t DNAC_TRANSCRIPT_PROD_INIT_STATE[] = {
    'D', 'N', 'A', 'C', '|', 'Z', 'K', '|',
    'F', 'R', 'I', '|', 'T', 'R', 'A', 'N',
    'S', 'C', 'R', 'I', 'P', 'T', '|', 'V',
    '1'
};
const size_t DNAC_TRANSCRIPT_PROD_INIT_STATE_LEN =
    sizeof(DNAC_TRANSCRIPT_PROD_INIT_STATE) / sizeof(DNAC_TRANSCRIPT_PROD_INIT_STATE[0]);

struct dnac_transcript_s {
    dnac_duplex_t d;
};

dnac_transcript_t *dnac_transcript_init_empty(void)
{
    dnac_transcript_t *t = (dnac_transcript_t *)malloc(sizeof(*t));
    if (!t) return NULL;
    dnac_duplex_init(&t->d);
    return t;
}

dnac_transcript_t *dnac_transcript_init_from_duplex(const dnac_duplex_t *d)
{
    if (!d) return NULL;
    dnac_transcript_t *t = (dnac_transcript_t *)malloc(sizeof(*t));
    if (!t) return NULL;
    t->d = *d; /* verbatim state copy — the primed state IS the seed */
    return t;
}

dnac_transcript_t *dnac_transcript_init_default(void)
{
    dnac_transcript_t *t = (dnac_transcript_t *)malloc(sizeof(*t));
    if (!t) return NULL;
    dnac_duplex_init_default(&t->d);
    return t;
}

dnac_transcript_t *dnac_transcript_clone(const dnac_transcript_t *src)
{
    if (!src) return NULL;
    dnac_transcript_t *t = (dnac_transcript_t *)malloc(sizeof(*t));
    if (!t) return NULL;
    t->d = src->d; /* value copy — fixed-size state, no owned pointers */
    return t;
}

void dnac_transcript_free(dnac_transcript_t *t)
{
    free(t);
}

void dnac_transcript_observe_fp(dnac_transcript_t *t, fp_t v)
{
    dnac_duplex_observe_fp(&t->d, v);
}

void dnac_transcript_observe_fp2(dnac_transcript_t *t, fp2_t v)
{
    dnac_duplex_observe_fp2(&t->d, v);
}

void dnac_transcript_observe_digest(dnac_transcript_t *t,
                                    const dnac_p2_digest_t *d)
{
    /* MerkleCap / Hash<F,F,4> observe = lane-by-lane field observes
     * (duplex_challenger.rs:186-210). Digest lanes are canonical
     * (permutation outputs / decode-guarded). */
    for (size_t i = 0; i < DNAC_P2M_DIGEST_LANES; i++)
        dnac_duplex_observe_fp(&t->d, gold_fp_from_u64(d->lanes[i]));
}

fp_t dnac_transcript_sample_fp(dnac_transcript_t *t)
{
    return dnac_duplex_sample_fp(&t->d);
}

fp2_t dnac_transcript_sample_fp2(dnac_transcript_t *t)
{
    return dnac_duplex_sample_fp2(&t->d);
}

uint64_t dnac_transcript_sample_bits(dnac_transcript_t *t, size_t bits)
{
    return dnac_duplex_sample_bits(&t->d, bits);
}

bool dnac_transcript_check_witness(dnac_transcript_t *t, size_t bits, fp_t witness)
{
    return dnac_duplex_check_witness(&t->d, bits, witness);
}

fp_t dnac_transcript_grind(dnac_transcript_t *t, size_t bits)
{
    return dnac_duplex_grind(&t->d, bits);
}

#ifdef DNAC_TRANSCRIPT_TESTING
const dnac_duplex_t *dnac_transcript_test_duplex(const dnac_transcript_t *t)
{
    return &t->d;
}
#endif
