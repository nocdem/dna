/**
 * @file shared/dnac/cmt_vote_set.c
 * @brief cometbft @709fd12b `types/vote_set.go` ported to C, plus the
 *        `types/block.go` ToVoteSet family. See cmt_vote_set.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_vote_set.h"

#include <stdlib.h>
#include <string.h>

/* ══ C-only plumbing ══════════════════════════════════════════════════ */

/* Byte equality of two peer ids — Go's map-key equality on a string. */
bool cmt_peer_id_equals(const cmt_peer_id_t *a, const cmt_peer_id_t *b)
{
    if (a == NULL || b == NULL) {
        return false;
    }
    return memcmp(a->id, b->id, sizeof(a->id)) == 0;
}

/*
 * Take ownership of a COPY of `v` and remember it so that
 * cmt_vote_set_free can release it.
 *
 * This is the C plumbing for what Go does with a pointer and a garbage
 * collector: `voteSet.votes` and `votesByBlock[k].votes` hold the SAME
 * `*Vote` value (vote_set.go:278 and :701 store the same argument), and
 * nothing ever frees it. Here one object is allocated and both places
 * borrow it.
 *
 * ⚠ `cmt_vote_copy` (cmt_vote.h:237-241) is a struct copy: the vote's
 * `extension` DESCRIPTOR is copied and its bytes are SHARED, exactly as
 * Go's `[]byte` header copy shares its backing array. The caller's
 * extension bytes must outlive the vote set — see substitution 2 in the
 * header.
 *
 * @return the owned copy, or NULL on allocation failure.
 */
static cmt_vote_t *vote_set_own(cmt_vote_set_t *vs, const cmt_vote_t *v)
{
    cmt_vote_t *copy;

    if (vs->owned_len == vs->owned_cap) {
        size_t       ncap;
        cmt_vote_t **grown;

        ncap = (vs->owned_cap == 0u) ? 16u : (vs->owned_cap * 2u);
        if (ncap > (SIZE_MAX / sizeof(cmt_vote_t *))) {
            return NULL;
        }
        grown = (cmt_vote_t **)realloc(vs->owned, ncap * sizeof(*grown));
        if (grown == NULL) {
            return NULL;
        }
        vs->owned     = grown;
        vs->owned_cap = ncap;
    }
    copy = (cmt_vote_t *)malloc(sizeof(*copy));
    if (copy == NULL) {
        return NULL;
    }
    if (cmt_vote_copy(v, copy) != CMT_OK) {
        free(copy);
        return NULL;
    }
    vs->owned[vs->owned_len] = copy;
    vs->owned_len++;
    return copy;
}

/* The `votesByBlock[blockKey]` map read of vote_set.go:249, :283, :354 and
 * :385. Linear over at most CMT_VOTE_SET_MAX_BLOCKS slots, in insertion
 * order — an ARRAY scan, never a hash-map iteration. */
static cmt_block_votes_t *votes_by_block_find(cmt_vote_set_t *vs,
                                              const uint8_t *key,
                                              size_t key_len)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_VOTE_SET_MAX_BLOCKS; i++) {
        cmt_block_votes_t *bv = &vs->votes_by_block[i];

        if (bv->used && bv->key_len == key_len &&
            memcmp(bv->key, key, key_len) == 0) {
            return bv;
        }
    }
    return NULL;
}

/* ══ blockVotes (vote_set.go:675-711) ═════════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:688-695 — newBlockVotes().
 *
 * The map INSERTION of :300 and :363 is folded in, because in C the key
 * lives in the entry: the reference writes
 * `voteSet.votesByBlock[blockKey] = votesByBlock` immediately after every
 * call, and there is no other caller.
 *
 * @return CMT_OK; CMT_REJECT when every slot is taken (C only — see
 *         CMT_VOTE_SET_MAX_BLOCKS); CMT_FAULT on allocation failure. */
static int new_block_votes(cmt_vote_set_t *vs, bool peer_maj23,
                           const uint8_t *key, size_t key_len,
                           cmt_block_votes_t **out)
{
    cmt_block_votes_t *bv = NULL;
    size_t             i;
    int                rc;

    for (i = 0; i < (size_t)CMT_VOTE_SET_MAX_BLOCKS; i++) {
        if (!vs->votes_by_block[i].used) {
            bv = &vs->votes_by_block[i];
            break;
        }
    }
    if (bv == NULL) {
        return CMT_REJECT;
    }
    if (key_len > sizeof(bv->key)) {
        return CMT_FAULT;
    }
    /* :691 — bits.NewBitArray(numValidators). CMT_BITS_NIL is the
     * reference's nil array for a zero-width set, and cmt_bits_new has
     * already zeroed the struct, which behaves exactly as Go's nil does
     * (Set/Get no-op). It is a normal outcome, not a failure. */
    rc = cmt_bits_new(&bv->bit_array, (int)vs->n_validators);
    if (rc != CMT_OK && rc != CMT_BITS_NIL) {
        return CMT_FAULT;
    }
    /* :692 — make([]*Vote, numValidators). calloc(0) is implementation
     * defined, so a zero-width set gets one unused slot. */
    bv->votes = (cmt_vote_t **)calloc(
        (vs->n_validators == 0u) ? 1u : vs->n_validators, sizeof(cmt_vote_t *));
    if (bv->votes == NULL) {
        return CMT_FAULT;
    }
    bv->peer_maj23 = peer_maj23;                                 /* :690 */
    bv->sum        = 0;                                          /* :693 */
    memcpy(bv->key, key, key_len);
    bv->key_len = key_len;
    bv->used    = true;
    *out        = bv;
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:697-704 —
 * (vs *blockVotes) addVerifiedVote().
 *
 * `already_owned` is C plumbing, not a reference parameter: when the
 * caller has ALREADY allocated the set's copy of this vote (because it
 * also went into `voteSet.votes` at :278 or :272), the same object is
 * stored here, exactly as Go stores the same pointer in both places.
 * Passing NULL makes this function allocate — and it allocates ONLY on
 * the branch that stores, so the :699 guard never leaks.
 *
 * @return CMT_OK, CMT_FAULT on allocation failure. */
static int block_votes_add_verified_vote(cmt_vote_set_t *vs,
                                         cmt_block_votes_t *bv,
                                         const cmt_vote_t *vote,
                                         cmt_vote_t *already_owned,
                                         int64_t voting_power)
{
    int32_t val_index = vote->validator_index;                   /* :698 */

    if (bv->votes[val_index] == NULL) {                          /* :699 */
        cmt_vote_t *stored = already_owned;

        if (stored == NULL) {
            stored = vote_set_own(vs, vote);
            if (stored == NULL) {
                return CMT_FAULT;
            }
        }
        (void)cmt_bits_set_index(&bv->bit_array, (int)val_index, true); /* :700 */
        bv->votes[val_index] = stored;                           /* :701 */
        bv->sum += voting_power;                                 /* :702 */
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:706-711 —
 * (vs *blockVotes) getByIndex(). A NULL `bv` is the reference's nil
 * receiver (:707-709), which a Go map read for an absent key produces. */
static cmt_vote_t *block_votes_get_by_index(cmt_block_votes_t *bv,
                                            int32_t index)
{
    if (bv == NULL) {
        return NULL;
    }
    return bv->votes[index];                                     /* :710 */
}

/* ══ constructors (vote_set.go:78-108) ════════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:78-98 — NewVoteSet() */
int cmt_vote_set_new(const uint8_t *chain_id, size_t chain_id_len,
                     int64_t height, int32_t round, int32_t signed_msg_type,
                     cmt_validator_set_t *val_set, cmt_vote_set_t **out)
{
    cmt_vote_set_t *vs;
    size_t          n;
    int             rc;

    if (out == NULL || val_set == NULL) {
        return CMT_FAULT;
    }
    if (chain_id == NULL && chain_id_len != 0u) {
        return CMT_FAULT;
    }
    /* :82-84 panics on height == 0. REJECT, not FAULT: the height can
     * arrive from a stored commit through Commit.ToVoteSet
     * (consensus/state.go:626-643), so it is data. */
    if (height == 0) {
        return CMT_REJECT;
    }
    /* INVARIANT atlas-dec-7495d337… — the chain id is 32 raw bytes here
     * (R1 decision atlas-dec-9285f4a5…) and the array must hold it. */
    if (chain_id_len > (size_t)CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    n = cmt_validator_set_size(val_set);                         /* :91-95 */
    if (n > (size_t)CMT_VALSET_MAX) {
        return CMT_REJECT;
    }

    vs = (cmt_vote_set_t *)calloc(1u, sizeof(*vs));
    if (vs == NULL) {
        return CMT_FAULT;
    }
    if (chain_id_len != 0u) {
        memcpy(vs->chain_id, chain_id, chain_id_len);            /* :86 */
    }
    vs->chain_id_len       = chain_id_len;
    vs->height             = height;                             /* :87 */
    vs->round              = round;                              /* :88 */
    vs->signed_msg_type    = signed_msg_type;                    /* :89 */
    vs->val_set            = val_set;                            /* :90 */
    vs->extensions_enabled = false;                              /* :67  */
    vs->n_validators       = n;
    vs->sum                = 0;                                  /* :93 */
    vs->has_maj23          = false;                              /* :94 */

    /* :91 — bits.NewBitArray(valSet.Size()); CMT_BITS_NIL for an empty
     * set is the reference's nil array, not a failure. */
    rc = cmt_bits_new(&vs->votes_bit_array, (int)n);
    if (rc != CMT_OK && rc != CMT_BITS_NIL) {
        free(vs);
        return CMT_FAULT;
    }
    vs->votes = (cmt_vote_t **)calloc((n == 0u) ? 1u : n,
                                      sizeof(cmt_vote_t *));     /* :92 */
    /* :95 — make(map[string]*blockVotes, valSet.Size()); the capacity
     * hint is a hint in Go and a hard bound here. */
    vs->votes_by_block = (cmt_block_votes_t *)calloc(
        (size_t)CMT_VOTE_SET_MAX_BLOCKS, sizeof(cmt_block_votes_t));
    /* :96 — make(map[P2PID]BlockID). */
    vs->peer_maj23s = (cmt_peer_maj23_entry_t *)calloc(
        (size_t)CMT_PEER_MAX, sizeof(cmt_peer_maj23_entry_t));
    if (vs->votes == NULL || vs->votes_by_block == NULL ||
        vs->peer_maj23s == NULL) {
        cmt_vote_set_free(vs);
        return CMT_FAULT;
    }
    *out = vs;
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:100-108 — NewExtendedVoteSet() */
int cmt_new_extended_vote_set(const uint8_t *chain_id, size_t chain_id_len,
                              int64_t height, int32_t round,
                              int32_t signed_msg_type,
                              cmt_validator_set_t *val_set,
                              cmt_vote_set_t **out)
{
    int rc;

    rc = cmt_vote_set_new(chain_id, chain_id_len, height, round,
                          signed_msg_type, val_set, out);        /* :105 */
    if (rc != CMT_OK) {
        return rc;
    }
    (*out)->extensions_enabled = true;                           /* :106 */
    return CMT_OK;
}

/* C only — the counterpart of cmt_vote_set_new. */
void cmt_vote_set_free(cmt_vote_set_t *vs)
{
    size_t i;

    if (vs == NULL) {
        return;
    }
    if (vs->votes_by_block != NULL) {
        for (i = 0; i < (size_t)CMT_VOTE_SET_MAX_BLOCKS; i++) {
            free(vs->votes_by_block[i].votes);
        }
        free(vs->votes_by_block);
    }
    for (i = 0; i < vs->owned_len; i++) {
        free(vs->owned[i]);
    }
    free(vs->owned);
    free(vs->votes);
    free(vs->peer_maj23s);
    free(vs);
}

/* ══ accessors (vote_set.go:110-144) ══════════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:110-112 — ChainID() */
const uint8_t *cmt_vote_set_chain_id(const cmt_vote_set_t *vs,
                                     size_t *out_len)
{
    if (vs == NULL) {
        if (out_len != NULL) {
            *out_len = 0u;
        }
        return NULL;
    }
    if (out_len != NULL) {
        *out_len = vs->chain_id_len;
    }
    return vs->chain_id;                                         /* :111 */
}

/* cometbft@709fd12b types/vote_set.go:114-120 — GetHeight() */
int64_t cmt_vote_set_get_height(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return 0;                                                /* :117 */
    }
    return vs->height;                                           /* :119 */
}

/* cometbft@709fd12b types/vote_set.go:122-128 — GetRound() */
int32_t cmt_vote_set_get_round(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return -1;                                               /* :125 */
    }
    return vs->round;                                            /* :127 */
}

/* cometbft@709fd12b types/vote_set.go:130-136 — Type() */
uint8_t cmt_vote_set_type(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return 0x00u;                                            /* :133 */
    }
    return (uint8_t)vs->signed_msg_type;                         /* :135 */
}

/* cometbft@709fd12b types/vote_set.go:138-144 — Size() */
int cmt_vote_set_size(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return 0;                                                /* :141 */
    }
    /* :143 is `voteSet.valSet.Size()`, NOT len(voteSet.votes). The two
     * differ if the shared validator set is mutated after construction;
     * the reference reads the live set here and the construction-time
     * length everywhere it indexes, and so does this port. */
    return (int)cmt_validator_set_size(vs->val_set);
}

/* ══ adding votes (vote_set.go:146-332) ═══════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:244-253 — getVote() */
static cmt_vote_t *get_vote(cmt_vote_set_t *vs, int32_t val_index,
                            const uint8_t *key, size_t key_len)
{
    cmt_vote_t *existing;

    existing = vs->votes[val_index];
    if (existing != NULL) {                                      /* :246 */
        uint8_t ekey[CMT_BLOCK_ID_MAX_BYTES];
        size_t  ekey_len;

        if (cmt_block_id_key(&existing->block_id, ekey, sizeof(ekey),
                             &ekey_len) == CMT_OK &&
            ekey_len == key_len && memcmp(ekey, key, key_len) == 0) {
            return existing;                                     /* :247 */
        }
    }
    /* :249 — votesByBlock[blockKey].getByIndex(valIndex). A Go read of an
     * absent map key yields a nil *blockVotes, and getByIndex has a nil
     * receiver check, so an untracked block is simply "not found". */
    return block_votes_get_by_index(votes_by_block_find(vs, key, key_len),
                                    val_index);
}

/*
 * cometbft@709fd12b types/vote_set.go:255-327 — addVerifiedVote().
 *
 * @param out_conflicting receives a BORROWED pointer to the reference's
 *        `conflicting` return value, or NULL.
 * @return CMT_OK (the reference cannot fail here); CMT_REJECT for the
 *         C-only blockVotes capacity; CMT_FAULT on allocation failure or
 *         at the :267 panic.
 *
 * ⚠ C-ONLY FAILURE MODE: the reference cannot fail part way through. On
 * CMT_FAULT this function may already have written `.votes`, the bit
 * array and `.sum`, and the vote set must be discarded by the caller.
 * The one non-allocation failure, CMT_REJECT, is unreachable while the
 * CMT_VOTE_SET_MAX_BLOCKS derivation holds.
 */
static int add_verified_vote(cmt_vote_set_t *vs, const cmt_vote_t *vote,
                             const uint8_t *key, size_t key_len,
                             int64_t voting_power, bool *out_added,
                             cmt_vote_t **out_conflicting,
                             cmt_vote_set_err_t *out_err)
{
    int32_t            val_index = vote->validator_index;        /* :262 */
    cmt_vote_t        *conflicting = NULL;
    cmt_vote_t        *stored = NULL;
    cmt_block_votes_t *bv = NULL;
    int64_t            orig_sum;
    int64_t            quorum;
    int64_t            total;
    size_t             i;
    int                rc;

    *out_added       = false;
    *out_conflicting = NULL;

    if (vs->votes[val_index] != NULL) {                          /* :265 */
        cmt_vote_t *existing = vs->votes[val_index];

        if (cmt_block_id_equals(&existing->block_id, &vote->block_id)) {
            /* :266-268 panics "addVerifiedVote does not expect duplicate
             * votes". addVote's :209 getVote check has already excluded
             * this exact pair, so the wire cannot reach it: FAULT. */
            return CMT_FAULT;
        }
        conflicting = existing;                                  /* :269 */
        /* :271 — replace the canonical vote when this block IS the
         * majority block. The reference compares maj23.Key() with the
         * blockKey; the same bytes, the same comparison. */
        if (vs->has_maj23) {
            uint8_t mkey[CMT_BLOCK_ID_MAX_BYTES];
            size_t  mkey_len;

            if (cmt_block_id_key(&vs->maj23, mkey, sizeof(mkey),
                                 &mkey_len) != CMT_OK) {
                return CMT_FAULT;
            }
            if (mkey_len == key_len && memcmp(mkey, key, key_len) == 0) {
                stored = vote_set_own(vs, vote);
                if (stored == NULL) {
                    return CMT_FAULT;
                }
                vs->votes[val_index] = stored;                   /* :272 */
                (void)cmt_bits_set_index(&vs->votes_bit_array,
                                         (int)val_index, true);  /* :273 */
            }
        }
        /* :275 — otherwise it does NOT go into voteSet.votes. */
    } else {
        stored = vote_set_own(vs, vote);                         /* :278 */
        if (stored == NULL) {
            return CMT_FAULT;
        }
        vs->votes[val_index] = stored;
        (void)cmt_bits_set_index(&vs->votes_bit_array,
                                 (int)val_index, true);          /* :279 */
        vs->sum += voting_power;                                 /* :280 */
    }

    bv = votes_by_block_find(vs, key, key_len);                  /* :283 */
    if (bv != NULL) {                                            /* :284 */
        if (conflicting != NULL && !bv->peer_maj23) {            /* :285 */
            /* :286-288 — a conflict and nobody vouched for this block. */
            *out_conflicting = conflicting;
            return CMT_OK;
        }
        /* :289 — we will add the vote in a bit. */
    } else {
        if (conflicting != NULL) {                               /* :292 */
            /* :293-295 — not even tracking this blockKey, so forget it. */
            *out_conflicting = conflicting;
            return CMT_OK;
        }
        rc = new_block_votes(vs, false, key, key_len, &bv);      /* :299-300 */
        if (rc == CMT_REJECT) {
            if (out_err != NULL) {
                *out_err = CMT_VOTE_SET_ERR_BLOCK_CAPACITY;
            }
            return CMT_REJECT;
        }
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    }

    orig_sum = bv->sum;                                          /* :305 */
    if (cmt_validator_set_total_voting_power(vs->val_set, &total) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :306 — plain int64. The reference uses no checked arithmetic here,
     * and R1's cmt_validator_set_update_total_voting_power already caps
     * the total at MaxInt64/8 (validator_set.go:319-324), so `total * 2`
     * cannot overflow. */
    quorum = total * 2 / 3 + 1;

    rc = block_votes_add_verified_vote(vs, bv, vote, stored,
                                       voting_power);            /* :309 */
    if (rc != CMT_OK) {
        return rc;
    }

    if (orig_sum < quorum && quorum <= bv->sum) {                /* :312 */
        if (!vs->has_maj23) {                                    /* :314 */
            vs->maj23     = vote->block_id;                      /* :315-316 */
            vs->has_maj23 = true;
            /* :318-322 — copy this block's votes over the canonical ones.
             * NOTE the reference does NOT touch votesBitArray here, and
             * it does not need to: a non-nil votesByBlock[i] implies a
             * non-nil voteSet.votes[i] (:265-281 stores in both), so
             * every bit involved is already set. Ported as-is. */
            for (i = 0; i < vs->n_validators; i++) {
                if (bv->votes[i] != NULL) {
                    vs->votes[i] = bv->votes[i];                 /* :320 */
                }
            }
        }
    }

    *out_added       = true;                                     /* :326 */
    *out_conflicting = conflicting;
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:167-242 — addVote() */
static int add_vote(cmt_vote_set_t *vs, const cmt_vote_t *vote,
                    bool *out_added, cmt_vote_set_err_t *out_err,
                    cmt_vote_t *out_conflicting)
{
    uint8_t         key[CMT_BLOCK_ID_MAX_BYTES];
    size_t          key_len;
    cmt_validator_t val;
    cmt_vote_t     *existing;
    cmt_vote_t     *conflicting = NULL;
    int32_t         val_index;
    int             rc;

    if (vote == NULL) {                                          /* :169 */
        *out_err = CMT_VOTE_SET_ERR_NIL;                         /* :170 */
        return CMT_REJECT;
    }
    val_index = vote->validator_index;                           /* :172 */
    /* :173 — valAddr is vote->validator_address / _len. */
    rc = cmt_block_id_key(&vote->block_id, key, sizeof(key), &key_len);
    if (rc != CMT_OK) {                                          /* :174 */
        return CMT_FAULT;
    }

    if (val_index < 0) {                                         /* :177 */
        *out_err = CMT_VOTE_SET_ERR_INVALID_VALIDATOR_INDEX;     /* :178 */
        return CMT_REJECT;
    } else if (vote->validator_address_len == 0u) {              /* :179 */
        *out_err = CMT_VOTE_SET_ERR_INVALID_VALIDATOR_ADDRESS;   /* :180 */
        return CMT_REJECT;
    }

    if (vote->height != vs->height ||                            /* :184 */
        vote->round != vs->round ||                              /* :185 */
        vote->type != vs->signed_msg_type) {                     /* :186 */
        *out_err = CMT_VOTE_SET_ERR_UNEXPECTED_STEP;             /* :187-189 */
        return CMT_REJECT;
    }

    rc = cmt_validator_set_get_by_index(vs->val_set, val_index, &val);
    if (rc == CMT_REJECT) {                                      /* :193-194 */
        *out_err = CMT_VOTE_SET_ERR_INVALID_VALIDATOR_INDEX;     /* :195-197 */
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    /* C ONLY (INVARIANT atlas-dec-7495d337…). The reference indexes
     * `voteSet.votes[valIndex]` at :246 and :265 with an index bounded
     * only by the LIVE validator set, while the slice was sized at
     * construction; a set that grew between the two would panic in Go and
     * read out of bounds here. The message boundary refuses it. */
    if ((size_t)val_index >= vs->n_validators) {
        *out_err = CMT_VOTE_SET_ERR_INVALID_VALIDATOR_INDEX;
        return CMT_REJECT;
    }

    if (val.address_len != vote->validator_address_len ||        /* :201 */
        val.address_len > sizeof(val.address) ||
        memcmp(vote->validator_address, val.address,
               val.address_len) != 0) {
        *out_err = CMT_VOTE_SET_ERR_INVALID_VALIDATOR_ADDRESS;   /* :202-205 */
        return CMT_REJECT;
    }

    existing = get_vote(vs, val_index, key, key_len);            /* :209 */
    if (existing != NULL) {
        /* INVARIANT — Go's Signature is a slice that carries its own
         * bound; here the length is checked before it drives a memcmp. */
        if (existing->signature_len > sizeof(existing->signature) ||
            vote->signature_len > sizeof(vote->signature)) {
            return CMT_FAULT;
        }
        if (existing->signature_len == vote->signature_len &&
            memcmp(existing->signature, vote->signature,
                   vote->signature_len) == 0) {
            *out_added = false;                                  /* :210-211 */
            return CMT_OK;                                       /* duplicate */
        }
        *out_err = CMT_VOTE_SET_ERR_NON_DETERMINISTIC_SIGNATURE; /* :213 */
        return CMT_REJECT;
    }

    /* :216-231 — check the signature. A validator with no public key
     * would be a nil crypto.PubKey in Go and panic on the first method
     * call; the validator set is ours, so that is an internal fault. */
    if (!val.pub_key.present) {
        return CMT_FAULT;
    }
    if (vs->extensions_enabled) {                                /* :217 */
        uint8_t *scratch;
        size_t   scratch_cap;

        /* cmt_vote_extension_sign_bytes needs 64 + 11 + extension for the
         * canonical body (cmt_vote.c:238-239) plus the delimiter's
         * uvarint prefix; 80 + extension covers both. */
        scratch_cap = 80u + vote->extension.len;
        scratch     = (uint8_t *)malloc(scratch_cap);
        if (scratch == NULL) {
            return CMT_FAULT;
        }
        rc = cmt_vote_verify_vote_and_extension(vs->chain_id,
                                                vs->chain_id_len, vote,
                                                val.pub_key.key, scratch,
                                                scratch_cap);    /* :218 */
        free(scratch);
        if (rc == CMT_REJECT) {
            *out_err = CMT_VOTE_SET_ERR_VERIFY_FAILED;           /* :219 */
            return CMT_REJECT;
        }
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    } else {
        rc = cmt_vote_verify(vs->chain_id, vs->chain_id_len, vote,
                             val.pub_key.key);                   /* :222 */
        if (rc == CMT_REJECT) {
            *out_err = CMT_VOTE_SET_ERR_VERIFY_FAILED;           /* :223 */
            return CMT_REJECT;
        }
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        if (vote->extension_signature_len > 0u ||                /* :225 */
            vote->extension.len > 0u) {
            *out_err = CMT_VOTE_SET_ERR_UNEXPECTED_EXTENSION;    /* :226-229 */
            return CMT_REJECT;
        }
    }

    rc = add_verified_vote(vs, vote, key, key_len, val.voting_power,
                           out_added, &conflicting, out_err);    /* :234 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (conflicting != NULL) {                                   /* :235 */
        if (out_conflicting != NULL) {
            /* The `NewConflictingVoteError(conflicting, vote)` payload of
             * :236. VoteA is this copy; VoteB is the caller's own `vote`,
             * already in hand. A COPY rather than the reference's pointer,
             * so the caller holds nothing that points into the set. */
            *out_conflicting = *conflicting;
        }
        *out_err = CMT_VOTE_SET_ERR_CONFLICTING_VOTES;
        return CMT_REJECT;                                       /* :236 */
    }
    if (!*out_added) {
        /* :238-240 panics "Expected to add non-conflicting vote".
         * added == false happens only together with a conflict (:288,
         * :295), which the branch above already returned, so the wire
         * cannot reach this: FAULT. */
        return CMT_FAULT;
    }
    return CMT_OK;                                               /* :241 */
}

/* cometbft@709fd12b types/vote_set.go:146-165 — AddVote() */
int cmt_vote_set_add_vote(cmt_vote_set_t *vs, const cmt_vote_t *vote,
                          bool *out_added, cmt_vote_set_err_t *out_err,
                          cmt_vote_t *out_conflicting)
{
    bool               added = false;
    cmt_vote_set_err_t err   = CMT_VOTE_SET_ERR_NONE;
    int                rc;

    if (vs == NULL) {                                            /* :158-160 */
        return CMT_FAULT;
    }
    rc = add_vote(vs, vote, &added, &err, out_conflicting);      /* :164 */
    if (out_added != NULL) {
        *out_added = added;
    }
    if (out_err != NULL) {
        *out_err = err;
    }
    return rc;
}

/* cometbft@709fd12b types/vote_set.go:329-367 — SetPeerMaj23() */
int cmt_vote_set_set_peer_maj23(cmt_vote_set_t *vs, cmt_peer_id_t peer,
                                const cmt_block_id_t *block_id,
                                cmt_vote_set_err_t *out_err)
{
    uint8_t                 key[CMT_BLOCK_ID_MAX_BYTES];
    size_t                  key_len;
    cmt_peer_maj23_entry_t *slot      = NULL;
    cmt_peer_maj23_entry_t *free_slot = NULL;
    cmt_block_votes_t      *bv;
    size_t                  i;
    int                     rc;

    if (out_err != NULL) {
        *out_err = CMT_VOTE_SET_ERR_NONE;
    }
    if (vs == NULL || block_id == NULL) {                        /* :335-337 */
        return CMT_FAULT;
    }
    rc = cmt_block_id_key(block_id, key, sizeof(key), &key_len); /* :341 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }

    for (i = 0; i < (size_t)CMT_PEER_MAX; i++) {                 /* :344 */
        if (vs->peer_maj23s[i].used) {
            if (cmt_peer_id_equals(&vs->peer_maj23s[i].peer, &peer)) {
                slot = &vs->peer_maj23s[i];
                break;
            }
        } else if (free_slot == NULL) {
            free_slot = &vs->peer_maj23s[i];
        }
    }
    if (slot != NULL) {
        if (cmt_block_id_equals(&slot->block_id, block_id)) {    /* :345 */
            return CMT_OK;                                       /* :346 */
        }
        if (out_err != NULL) {
            *out_err = CMT_VOTE_SET_ERR_PEER_MAJ23_CONFLICT;     /* :348-349 */
        }
        return CMT_REJECT;
    }
    if (free_slot == NULL) {
        /* C ONLY (INVARIANT atlas-dec-7495d337…): the reference's map is
         * unbounded and its own comment at :330-332 calls that a memory
         * hazard. The 129th distinct peer is refused. */
        if (out_err != NULL) {
            *out_err = CMT_VOTE_SET_ERR_PEER_CAPACITY;
        }
        return CMT_REJECT;
    }
    free_slot->used     = true;                                  /* :351 */
    free_slot->peer     = peer;
    free_slot->block_id = *block_id;

    bv = votes_by_block_find(vs, key, key_len);                  /* :354 */
    if (bv != NULL) {                                            /* :355 */
        if (bv->peer_maj23) {
            return CMT_OK;                                       /* :356-358 */
        }
        bv->peer_maj23 = true;                                   /* :359 */
        /* :360 — no need to copy votes, already there. */
    } else {
        /* :362-363. ⚠ C-ONLY: the peer slot above is already consumed; a
         * failure here leaves the peer recorded without its block, where
         * the reference cannot fail. Unreachable while the
         * CMT_VOTE_SET_MAX_BLOCKS derivation holds. */
        rc = new_block_votes(vs, true, key, key_len, &bv);
        if (rc == CMT_REJECT) {
            if (out_err != NULL) {
                *out_err = CMT_VOTE_SET_ERR_BLOCK_CAPACITY;
            }
            return CMT_REJECT;
        }
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        /* :364 — no votes to copy over. */
    }
    return CMT_OK;                                               /* :366 */
}

/* ══ reading the set (vote_set.go:369-482) ════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:369-377 — BitArray() */
int cmt_vote_set_bit_array(cmt_vote_set_t *vs, cmt_bit_array_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (vs == NULL) {
        memset(out, 0, sizeof(*out));
        return CMT_BITS_NIL;                                     /* :371-373 */
    }
    return cmt_bits_copy(&vs->votes_bit_array, out);             /* :376 */
}

/* cometbft@709fd12b types/vote_set.go:379-390 — BitArrayByBlockID() */
int cmt_vote_set_bit_array_by_block_id(cmt_vote_set_t *vs,
                                       const cmt_block_id_t *block_id,
                                       cmt_bit_array_t *out)
{
    uint8_t            key[CMT_BLOCK_ID_MAX_BYTES];
    size_t             key_len;
    cmt_block_votes_t *bv;
    int                rc;

    if (out == NULL || block_id == NULL) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    if (vs == NULL) {
        return CMT_BITS_NIL;                                     /* :380-382 */
    }
    rc = cmt_block_id_key(block_id, key, sizeof(key), &key_len); /* :385 */
    if (rc != CMT_OK) {
        return rc;
    }
    bv = votes_by_block_find(vs, key, key_len);
    if (bv != NULL) {                                            /* :386 */
        return cmt_bits_copy(&bv->bit_array, out);               /* :387 */
    }
    return CMT_BITS_NIL;                                         /* :389 */
}

/* cometbft@709fd12b types/vote_set.go:392-401 — GetByIndex() */
int cmt_vote_set_get_by_index(cmt_vote_set_t *vs, int32_t val_index,
                              const cmt_vote_t **out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    if (vs == NULL) {
        return CMT_OK;                                           /* :395-397 */
    }
    /* :400 indexes without a bound check; the index reaches this function
     * from a peer's message through the reactor, so the message boundary
     * refuses it (INVARIANT atlas-dec-7495d337…). */
    if (val_index < 0 || (size_t)val_index >= vs->n_validators) {
        return CMT_REJECT;
    }
    *out = vs->votes[val_index];                                 /* :400 */
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:403-415 — List() */
int cmt_vote_set_list(cmt_vote_set_t *vs, cmt_vote_t *out, size_t cap,
                      size_t *out_len)
{
    size_t i;
    size_t n = 0u;

    if (out_len == NULL || (out == NULL && cap != 0u)) {
        return CMT_FAULT;
    }
    *out_len = 0u;
    if (vs == NULL || vs->votes == NULL) {
        return CMT_OK;                                           /* :405-407 */
    }
    for (i = 0; i < vs->n_validators; i++) {                     /* :409 */
        if (vs->votes[i] != NULL) {                              /* :410 */
            n++;
        }
    }
    if (n > cap) {
        return CMT_REJECT;
    }
    n = 0u;
    for (i = 0; i < vs->n_validators; i++) {
        if (vs->votes[i] != NULL) {
            out[n] = *vs->votes[i];                              /* :411 */
            n++;
        }
    }
    *out_len = n;
    return CMT_OK;                                               /* :414 */
}

/* cometbft@709fd12b types/vote_set.go:417-428 — GetByAddress() */
int cmt_vote_set_get_by_address(cmt_vote_set_t *vs, const uint8_t *address,
                                size_t address_len, const cmt_vote_t **out)
{
    int32_t val_index = -1;
    int     rc;

    if (out == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    if (vs == NULL) {
        return CMT_OK;                                           /* :418-420 */
    }
    rc = cmt_validator_set_get_by_address(vs->val_set, address, address_len,
                                          &val_index, NULL);     /* :423 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (val_index < 0) {
        /* :424-426 panics "GetByAddress(address) returned nil". JUDGMENT:
         * the address is a caller argument rather than internal state and
         * the pinned tree has no non-test caller of VoteSet.GetByAddress
         * (every non-test `.GetByAddress(` site is on a ValidatorSet), so
         * there is no internal contract to declare violated — refuse. */
        return CMT_REJECT;
    }
    if ((size_t)val_index >= vs->n_validators) {
        return CMT_REJECT;                     /* same bound as :400 */
    }
    *out = vs->votes[val_index];                                 /* :427 */
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:430-437 — HasTwoThirdsMajority() */
bool cmt_vote_set_has_two_thirds_majority(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return false;                                            /* :431-433 */
    }
    return vs->has_maj23;                                        /* :436 */
}

/* cometbft@709fd12b types/vote_set.go:439-450 — IsCommit() */
bool cmt_vote_set_is_commit(const cmt_vote_set_t *vs)
{
    if (vs == NULL) {
        return false;                                            /* :441-443 */
    }
    if (vs->signed_msg_type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
        return false;                                            /* :444-446 */
    }
    return vs->has_maj23;                                        /* :449 */
}

/* cometbft@709fd12b types/vote_set.go:452-459 — HasTwoThirdsAny() */
int cmt_vote_set_has_two_thirds_any(cmt_vote_set_t *vs, bool *out)
{
    int64_t total;

    if (out == NULL) {
        return CMT_FAULT;
    }
    *out = false;
    if (vs == NULL) {
        return CMT_OK;                                           /* :453-455 */
    }
    if (cmt_validator_set_total_voting_power(vs->val_set, &total) != CMT_OK) {
        return CMT_FAULT;
    }
    *out = (vs->sum > total * 2 / 3);                            /* :458 */
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:461-468 — HasAll() */
int cmt_vote_set_has_all(cmt_vote_set_t *vs, bool *out)
{
    int64_t total;

    if (out == NULL) {
        return CMT_FAULT;
    }
    *out = false;
    if (vs == NULL) {
        return CMT_OK;                                           /* :462-464 */
    }
    if (cmt_validator_set_total_voting_power(vs->val_set, &total) != CMT_OK) {
        return CMT_FAULT;
    }
    *out = (vs->sum == total);                                   /* :467 */
    return CMT_OK;
}

/* cometbft@709fd12b types/vote_set.go:470-482 — TwoThirdsMajority() */
int cmt_vote_set_two_thirds_majority(const cmt_vote_set_t *vs,
                                     cmt_block_id_t *out_block_id,
                                     bool *out_ok)
{
    if (out_block_id == NULL || out_ok == NULL) {
        return CMT_FAULT;
    }
    cmt_pb_block_id_init(out_block_id);            /* the reference's BlockID{} */
    *out_ok = false;
    if (vs == NULL) {
        return CMT_OK;                                           /* :473-475 */
    }
    if (vs->has_maj23) {                                         /* :478 */
        *out_block_id = vs->maj23;                               /* :479 */
        *out_ok       = true;
    }
    return CMT_OK;                                               /* :481 */
}

/* ══ making a commit (vote_set.go:627-671) ════════════════════════════ */

/* cometbft@709fd12b types/vote_set.go:630-671 — MakeExtendedCommit() */
int cmt_vote_set_make_extended_commit(cmt_vote_set_t *vs,
                                      cmt_abci_params_t ap,
                                      cmt_extended_commit_sig_t *sigs,
                                      size_t sigs_cap,
                                      cmt_extended_commit_t *out)
{
    bool   ext_enabled = false;
    size_t i;
    int    rc;

    if (vs == NULL || out == NULL || (sigs == NULL && vs->n_validators != 0u)) {
        return CMT_FAULT;
    }
    if (vs->signed_msg_type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
        /* :639-641 panics. A contract between this function and the
         * consensus state machine, unreachable from the wire: FAULT. */
        return CMT_FAULT;
    }
    if (!vs->has_maj23) {
        return CMT_FAULT;                                        /* :644-646 */
    }
    if (sigs_cap < vs->n_validators) {
        return CMT_REJECT;
    }

    /* :649-658 — one entry per VALIDATOR INDEX, in index order. */
    for (i = 0; i < vs->n_validators; i++) {
        rc = cmt_vote_extended_commit_sig(vs->votes[i], &sigs[i]); /* :651 */
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
        /* :653 — `sig.BlockIDFlag == BlockIDFlagCommit && !v.BlockID...`.
         * Go's && short-circuits, and so does C's: a nil vote yields an
         * ABSENT entry (vote.go:129-131), so `vs->votes[i]` is never
         * dereferenced when it is NULL. */
        if (sigs[i].commit_sig.block_id_flag ==
                (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT &&
            !cmt_block_id_equals(&vs->votes[i]->block_id, &vs->maj23)) {
            cmt_new_extended_commit_sig_absent(&sigs[i]);        /* :654 */
        }
    }

    /* memset rather than cmt_pb_extended_commit_init: that _init PRESERVES
     * `out`'s existing slot pointer and capacity (cmt_pb.c, "slots =
     * m->extended_signatures" before the memset), which are indeterminate
     * in a caller's fresh struct. Every field is assigned below, and
     * ExtendedCommit holds no time, so a zero fill is its complete zero
     * value — the same reasoning as cmt_block.c's four sites (Delta A-1,
     * verifier A). */
    memset(out, 0, sizeof(*out));
    out->height                  = cmt_vote_set_get_height(vs);  /* :661 */
    out->round                   = cmt_vote_set_get_round(vs);   /* :662 */
    out->block_id                = vs->maj23;                    /* :663 */
    out->extended_signatures     = sigs;                         /* :664 */
    out->extended_signatures_cap = sigs_cap;
    out->extended_signatures_len = vs->n_validators;

    /* :666 — ap.VoteExtensionsEnabled(ec.Height). The set's height can
     * never be 0 (cmt_vote_set_new refuses it), so the reference's
     * `h < 1` panic (params.go:76-78) is unreachable. */
    if (cmt_abci_params_vote_extensions_enabled(ap, out->height,
                                                &ext_enabled) != CMT_OK) {
        return CMT_FAULT;
    }
    if (cmt_extended_commit_ensure_extensions(out, ext_enabled) != CMT_OK) {
        /* :667-669 panics: the extension data of the commit we just built
         * from our own verified votes is inconsistent. Internal: FAULT. */
        return CMT_FAULT;
    }
    return CMT_OK;                                               /* :670 */
}

/* ══ rebuilding a vote set from a commit (block.go:1071-1117) ═════════ */

/* cometbft@709fd12b types/block.go:1081-1096 —
 * (ec *ExtendedCommit) addSigsToVoteSet(). File-local, as in the
 * reference. Every panic here is a disagreement between the local store
 * and itself (state.go:610-624), so all of them are CMT_FAULT. */
static int add_sigs_to_vote_set(const cmt_extended_commit_t *ec,
                                cmt_vote_set_t *vs)
{
    cmt_vote_t *vote;
    size_t      idx;
    int         rc = CMT_OK;

    vote = (cmt_vote_t *)malloc(sizeof(*vote));   /* ~9.5 KB, never stack */
    if (vote == NULL) {
        return CMT_FAULT;
    }
    for (idx = 0; idx < ec->extended_signatures_len; idx++) {    /* :1083 */
        bool               added = false;
        cmt_vote_set_err_t err   = CMT_VOTE_SET_ERR_NONE;

        if (ec->extended_signatures[idx].commit_sig.block_id_flag ==
            (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT) {
            continue;                                            /* :1084-1086 */
        }
        if (idx > (size_t)INT32_MAX) {          /* INVARIANT: :1087's int32() */
            rc = CMT_FAULT;
            break;
        }
        rc = cmt_extended_commit_get_extended_vote(ec, (int32_t)idx, vote);
        if (rc != CMT_OK) {                                      /* :1087 */
            rc = CMT_FAULT;
            break;
        }
        if (cmt_vote_validate_basic(vote) != CMT_OK) {           /* :1088 */
            rc = CMT_FAULT;                                      /* :1089 */
            break;
        }
        rc = cmt_vote_set_add_vote(vs, vote, &added, &err, NULL); /* :1091 */
        if (!added || rc != CMT_OK) {                            /* :1092 */
            rc = CMT_FAULT;                                      /* :1093 */
            break;
        }
    }
    free(vote);
    return rc;
}

/* cometbft@709fd12b types/block.go:1071-1079 —
 * (ec *ExtendedCommit) ToExtendedVoteSet() */
int cmt_extended_commit_to_extended_vote_set(const cmt_extended_commit_t *ec,
                                             const uint8_t *chain_id,
                                             size_t chain_id_len,
                                             cmt_validator_set_t *vals,
                                             cmt_vote_set_t **out)
{
    cmt_vote_set_t *vs = NULL;
    int             rc;

    if (ec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    rc = cmt_new_extended_vote_set(chain_id, chain_id_len, ec->height,
                                   ec->round,
                                   (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                   vals, &vs);                   /* :1076 */
    if (rc != CMT_OK) {
        return rc;
    }
    rc = add_sigs_to_vote_set(ec, vs);                           /* :1077 */
    if (rc != CMT_OK) {
        cmt_vote_set_free(vs);
        return rc;
    }
    *out = vs;                                                   /* :1078 */
    return CMT_OK;
}

/* cometbft@709fd12b types/block.go:1098-1117 — (commit *Commit) ToVoteSet() */
int cmt_commit_to_vote_set(const cmt_commit_t *commit,
                           const uint8_t *chain_id, size_t chain_id_len,
                           cmt_validator_set_t *vals, cmt_vote_set_t **out)
{
    cmt_vote_set_t *vs   = NULL;
    cmt_vote_t     *vote = NULL;
    size_t          idx;
    int             rc;

    if (commit == NULL || out == NULL) {
        return CMT_FAULT;
    }
    *out = NULL;
    rc = cmt_vote_set_new(chain_id, chain_id_len, commit->height,
                          commit->round,
                          (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, vals, &vs);
    if (rc != CMT_OK) {                                          /* :1102 */
        return rc;
    }
    vote = (cmt_vote_t *)malloc(sizeof(*vote));   /* ~9.5 KB, never stack */
    if (vote == NULL) {
        cmt_vote_set_free(vs);
        return CMT_FAULT;
    }
    for (idx = 0; idx < commit->signatures_len; idx++) {         /* :1103 */
        bool               added = false;
        cmt_vote_set_err_t err   = CMT_VOTE_SET_ERR_NONE;

        if (commit->signatures[idx].block_id_flag ==
            (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT) {
            continue;                                            /* :1104-1106 */
        }
        if (idx > (size_t)INT32_MAX) {          /* INVARIANT: :1107's int32() */
            rc = CMT_FAULT;
            break;
        }
        rc = cmt_commit_get_vote(commit, (int32_t)idx, vote);    /* :1107 */
        if (rc != CMT_OK) {
            rc = CMT_FAULT;
            break;
        }
        if (cmt_vote_validate_basic(vote) != CMT_OK) {           /* :1108 */
            rc = CMT_FAULT;                                      /* :1109 */
            break;
        }
        rc = cmt_vote_set_add_vote(vs, vote, &added, &err, NULL); /* :1111 */
        if (!added || rc != CMT_OK) {                            /* :1112 */
            rc = CMT_FAULT;                                      /* :1113 */
            break;
        }
    }
    free(vote);
    if (rc != CMT_OK) {
        cmt_vote_set_free(vs);
        return rc;
    }
    *out = vs;                                                   /* :1116 */
    return CMT_OK;
}
