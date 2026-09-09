/**
 * @file shared/dnac/tm_vote.c
 * @brief Tendermint T3 — `nodus.vote.v1` preimage + own-vote stamping.
 *
 * INACTIVE: no consensus path calls anything here (wave 1 is additive).
 * See tm_vote.h for the tag, the 229-byte layout and the reference pins.
 *
 * Nothing in this file reads a clock, allocates, sorts, or computes a
 * consensus value. dna_tm_vote_time is arithmetic over its arguments.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "tm_vote.h"

#include <string.h>

/* Tag is EXACTLY 16 bytes, zero-padded ASCII: 13 characters and three zero
 * bytes, of which two are written and the third is the literal's own
 * terminator — so the initializer fits the array exactly, with no character
 * dropped. That is the qc_v2.c:21 idiom, and by construction it cannot draw
 * a truncated-initializer diagnostic from any compiler. */
static const uint8_t TAG_TM_VOTE[DNA_TM_VOTE_TAG_LEN] = "nodus.vote.v1\0\0";

/* Preimage arithmetic is pinned, not assumed: the offsets below are the
 * ones tm_vote.h publishes and the certificate codec verifies against. */
_Static_assert(DNA_TM_VOTE_OFF_TYPE      == DNA_TM_VOTE_TAG_LEN,
               "vote preimage: type offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_BLOCK_ID  == DNA_TM_VOTE_OFF_TYPE + 1,
               "vote preimage: block_id offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_VOTER_ID  == DNA_TM_VOTE_OFF_BLOCK_ID +
                                            DNA_TM_BLOCK_ID_LEN,
               "vote preimage: voter_id offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_HEIGHT    == DNA_TM_VOTE_OFF_VOTER_ID +
                                            DNA_TM_VOTER_ID_LEN,
               "vote preimage: height offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_ROUND     == DNA_TM_VOTE_OFF_HEIGHT + 8,
               "vote preimage: round offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_TIMESTAMP == DNA_TM_VOTE_OFF_ROUND + 4,
               "vote preimage: timestamp offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_CHAIN_ID  == DNA_TM_VOTE_OFF_TIMESTAMP + 8,
               "vote preimage: chain_id offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_OFF_VSET_HASH == DNA_TM_VOTE_OFF_CHAIN_ID +
                                            DNA_CHAIN_ID_LEN,
               "vote preimage: vset_hash offset drifted from T2 §4.1");
_Static_assert(DNA_TM_VOTE_PREIMAGE_LEN  == DNA_TM_VOTE_OFF_VSET_HASH +
                                            DNA_VSET_HASH_LEN,
               "vote preimage layout drifted from 229 bytes");
_Static_assert(DNA_TM_VOTE_PREIMAGE_LEN == 229,
               "vote preimage length drifted from T2 §4.1");
/* The two wire bytes are the reference's SignedMsgType values (D-12). */
_Static_assert(DNA_TM_VOTE_PREVOTE == 0x01 && DNA_TM_VOTE_PRECOMMIT == 0x02,
               "vote type bytes drifted from signing.md:21-25 (D-12)");
_Static_assert(DNA_TM_VOTER_ID_LEN == DNA_VSET_VOTER_ID_LEN,
               "vote voter_id width != validator-set voter_id width");

/* ── Fixed-width big-endian helpers ─────────────────────────────────── */

static void put_be32(uint32_t v, uint8_t out[4]) {
    for (int i = 3; i >= 0; i--) { out[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}
static void put_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xffu); v >>= 8; }
}

/* ── Preimage ───────────────────────────────────────────────────────── */

int dna_tm_vote_preimage(uint8_t type,
                         const uint8_t block_id[DNA_TM_BLOCK_ID_LEN],
                         const uint8_t voter_id[DNA_TM_VOTER_ID_LEN],
                         uint64_t height, uint32_t round, uint64_t timestamp_ms,
                         const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                         const uint8_t vset_hash[DNA_VSET_HASH_LEN],
                         uint8_t out[DNA_TM_VOTE_PREIMAGE_LEN]) {
    if (!block_id || !voter_id || !chain_id || !vset_hash || !out) return -1;
    /* Only the two vote types ever appear here. 0x20 (ProposalType) and
     * every other byte reject: a PROPOSAL is signed by the frame, not by
     * a vote preimage (D-12). */
    if (type != DNA_TM_VOTE_PREVOTE && type != DNA_TM_VOTE_PRECOMMIT)
        return -1;

    uint8_t *p = out;
    memcpy(p, TAG_TM_VOTE, DNA_TM_VOTE_TAG_LEN); p += DNA_TM_VOTE_TAG_LEN;
    *p++ = type;
    memcpy(p, block_id, DNA_TM_BLOCK_ID_LEN);   p += DNA_TM_BLOCK_ID_LEN;
    memcpy(p, voter_id, DNA_TM_VOTER_ID_LEN);   p += DNA_TM_VOTER_ID_LEN;
    put_be64(height, p);      p += 8;
    put_be32(round, p);       p += 4;
    put_be64(timestamp_ms, p); p += 8;
    memcpy(p, chain_id, DNA_CHAIN_ID_LEN);      p += DNA_CHAIN_ID_LEN;
    memcpy(p, vset_hash, DNA_VSET_HASH_LEN);    p += DNA_VSET_HASH_LEN;

    if ((size_t)(p - out) != (size_t)DNA_TM_VOTE_PREIMAGE_LEN) return -1;
    return 0;
}

/* ── Own-vote stamping ──────────────────────────────────────────────── */

int dna_tm_vote_time(uint64_t now_ms, int have_ref, uint64_t ref_time_ms,
                     uint64_t *out_ts_ms) {
    if (!out_ts_ms) return -1;
    /* Rejected in BOTH branches (see tm_vote.h): ref + 1 would wrap to 0,
     * and a guard that depends on the flag is a guard that can be bypassed
     * by passing the flag wrongly. */
    if (ref_time_ms == UINT64_MAX) return -1;

    uint64_t ts = now_ms;
    if (have_ref) {
        /* ref_time_ms != UINT64_MAX was just checked, so +1 cannot wrap. */
        uint64_t floor_ms = ref_time_ms + 1u;
        if (floor_ms > ts) ts = floor_ms;
    }
    *out_ts_ms = ts;
    return 0;
}

/* ── Signer-rule helper ─────────────────────────────────────────────── */

int dna_tm_vote_preimage_diff_class(const uint8_t a[DNA_TM_VOTE_PREIMAGE_LEN],
                                    const uint8_t b[DNA_TM_VOTE_PREIMAGE_LEN]) {
    if (!a || !b) return -1;
    if (memcmp(a, b, (size_t)DNA_TM_VOTE_PREIMAGE_LEN) == 0) return 0;

    /* Everything OUTSIDE the 8-byte timestamp window must be equal for the
     * reference's "timestamp-only difference" branch to apply. */
    const size_t ts_off = (size_t)DNA_TM_VOTE_OFF_TIMESTAMP;
    const size_t ts_end = ts_off + 8u;
    if (memcmp(a, b, ts_off) != 0) return 2;
    if (memcmp(a + ts_end, b + ts_end,
               (size_t)DNA_TM_VOTE_PREIMAGE_LEN - ts_end) != 0) return 2;

    /* Prefix and suffix agree but the whole does not: the difference is
     * inside off 125..132 and nowhere else. */
    return 1;
}
