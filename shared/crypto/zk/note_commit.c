/**
 * @file note_commit.c
 * @brief Implementation of the shielded note-commitment / Merkle-compress sponge.
 *
 * See note_commit.h for the construction and grounding. Byte-matched to
 * tools/vectors/note_commit_sponge.json (Plonky3 PaddingFreeSponge<8,4,4>).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "note_commit.h"

#include <string.h>

#include "poseidon2_goldilocks.h"

/* Stock Plonky3 PaddingFreeSponge<Perm,8,4,4> over 8 fixed-length inputs:
 *   state = 0^8
 *   for each of the two rate-4 blocks: overwrite state[0..4], permute
 *   squeeze state[0..4]
 * Matches sponge.rs:176-203 exactly for an input length that is a multiple of
 * RATE (here 8 = 2·RATE): two full-block permutations, no trailing/pad permute. */
void note_sponge_hash8(const uint64_t in[8], uint64_t out[NOTE_COMMIT_LANES])
{
    uint64_t state[POSEIDON2_GOLD_WIDTH];
    memset(state, 0, sizeof(state));

    /* block 1: overwrite rate [0..4), permute */
    state[0] = in[0];
    state[1] = in[1];
    state[2] = in[2];
    state[3] = in[3];
    poseidon2_goldilocks8_permute(state);

    /* block 2: overwrite rate [0..4), permute */
    state[0] = in[4];
    state[1] = in[5];
    state[2] = in[6];
    state[3] = in[7];
    poseidon2_goldilocks8_permute(state);

    /* squeeze OUT=4 lanes */
    out[0] = state[0];
    out[1] = state[1];
    out[2] = state[2];
    out[3] = state[3];
}

void note_commit(uint64_t value, const uint64_t addr_pub[NOTE_ADDR_LANES],
                 const uint64_t rcm[NOTE_RCM_LANES],
                 uint64_t cm_out[NOTE_COMMIT_LANES])
{
    uint64_t in[8];
    in[0] = value;
    in[1] = addr_pub[0];
    in[2] = addr_pub[1];
    in[3] = addr_pub[2];
    in[4] = addr_pub[3];
    in[5] = rcm[0];
    in[6] = rcm[1];
    in[7] = DNAC_DOMSEP_NOTE;
    note_sponge_hash8(in, cm_out);
}

void note_merkle_compress(const uint64_t left[NOTE_COMMIT_LANES],
                          const uint64_t right[NOTE_COMMIT_LANES],
                          uint64_t out[NOTE_COMMIT_LANES])
{
    uint64_t in[8];
    in[0] = left[0];
    in[1] = left[1];
    in[2] = left[2];
    in[3] = left[3];
    in[4] = right[0];
    in[5] = right[1];
    in[6] = right[2];
    in[7] = right[3];
    note_sponge_hash8(in, out);
}
