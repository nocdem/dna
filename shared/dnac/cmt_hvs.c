/**
 * @file shared/dnac/cmt_hvs.c
 * @brief cometbft @709fd12b `consensus/types/height_vote_set.go` ported
 *        to C. See cmt_hvs.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_hvs.h"
#include "dnac/cmt_safemath.h"   /* SafeSubInt32 — height_vote_set.go:100 */

#include <stdlib.h>
#include <string.h>

/* ══ C-only plumbing ══════════════════════════════════════════════════ */

/* The `roundVoteSets[round]` map read of :105, :114, :186. An ARRAY scan
 * in insertion order — see substitution 2 in the header for why the
 * rounds cannot be array indices. */
static cmt_hvs_round_entry_t *rvs_find(cmt_hvs_t *hvs, int32_t round)
{
    size_t i;

    for (i = 0; i < hvs->round_vote_sets_len; i++) {
        if (hvs->round_vote_sets[i].round == round) {
            return &hvs->round_vote_sets[i];
        }
    }
    return NULL;
}

/* Make room for one more round entry. Go's map grows itself. */
static int rvs_reserve(cmt_hvs_t *hvs)
{
    size_t                 ncap;
    cmt_hvs_round_entry_t *grown;

    if (hvs->round_vote_sets_len < hvs->round_vote_sets_cap) {
        return CMT_OK;
    }
    ncap = (hvs->round_vote_sets_cap == 0u) ? 8u
                                            : (hvs->round_vote_sets_cap * 2u);
    if (ncap > (SIZE_MAX / sizeof(cmt_hvs_round_entry_t))) {
        return CMT_FAULT;
    }
    grown = (cmt_hvs_round_entry_t *)realloc(hvs->round_vote_sets,
                                             ncap * sizeof(*grown));
    if (grown == NULL) {
        return CMT_FAULT;
    }
    hvs->round_vote_sets     = grown;
    hvs->round_vote_sets_cap = ncap;
    return CMT_OK;
}

/* Free every round's two vote sets and forget them. Go drops the map and
 * lets the collector do this (:77). */
static void rvs_clear(cmt_hvs_t *hvs)
{
    size_t i;

    for (i = 0; i < hvs->round_vote_sets_len; i++) {
        cmt_vote_set_free(hvs->round_vote_sets[i].rvs.prevotes);
        cmt_vote_set_free(hvs->round_vote_sets[i].rvs.precommits);
        hvs->round_vote_sets[i].rvs.prevotes   = NULL;
        hvs->round_vote_sets[i].rvs.precommits = NULL;
    }
    hvs->round_vote_sets_len = 0u;
}

/* ══ addRound / getVoteSet (height_vote_set.go:113-129, :185-198) ═════ */

/* cometbft@709fd12b consensus/types/height_vote_set.go:113-129 —
 * addRound(). The map INSERTION of :125-128 is folded in, because in C
 * the key lives in the entry.
 * @return CMT_OK; CMT_FAULT at the :115-116 panic ("addRound() for an
 *         existing round" — every caller checks first) or on allocation
 *         failure; CMT_REJECT from the vote sets it builds. */
static int add_round(cmt_hvs_t *hvs, int32_t round)
{
    cmt_hvs_round_entry_t *entry;
    cmt_vote_set_t        *prevotes   = NULL;
    cmt_vote_set_t        *precommits = NULL;
    int                    rc;

    if (rvs_find(hvs, round) != NULL) {
        return CMT_FAULT;                                        /* :114-116 */
    }
    rc = rvs_reserve(hvs);
    if (rc != CMT_OK) {
        return rc;
    }
    rc = cmt_vote_set_new(hvs->chain_id, hvs->chain_id_len, hvs->height,
                          round, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                          hvs->val_set, &prevotes);              /* :118 */
    if (rc != CMT_OK) {
        return rc;
    }
    if (hvs->extensions_enabled) {                               /* :120 */
        rc = cmt_new_extended_vote_set(hvs->chain_id, hvs->chain_id_len,
                                       hvs->height, round,
                                       (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                       hvs->val_set, &precommits); /* :121 */
    } else {
        rc = cmt_vote_set_new(hvs->chain_id, hvs->chain_id_len, hvs->height,
                              round, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                              hvs->val_set, &precommits);        /* :123 */
    }
    if (rc != CMT_OK) {
        cmt_vote_set_free(prevotes);
        return rc;
    }
    entry                 = &hvs->round_vote_sets[hvs->round_vote_sets_len];
    entry->round          = round;
    entry->rvs.prevotes   = prevotes;                            /* :126 */
    entry->rvs.precommits = precommits;                          /* :127 */
    hvs->round_vote_sets_len++;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:185-198 —
 * getVoteSet().
 * @param out receives the set, or NULL when the round is not tracked
 *        (:187-189) — the reference's nil, not an error.
 * @return CMT_OK; CMT_FAULT at the :195-197 panic on a vote type that is
 *         neither prevote nor precommit. Every caller in the reference
 *         checks IsVoteTypeValid first (:139, :211) or passes a constant
 *         (:161, :167, :176), so that panic is unreachable; it is a fault
 *         rather than a verdict for exactly that reason. */
static int get_vote_set(cmt_hvs_t *hvs, int32_t round, int32_t vote_type,
                        cmt_vote_set_t **out)
{
    cmt_hvs_round_entry_t *entry;

    *out  = NULL;
    entry = rvs_find(hvs, round);                                /* :186 */
    if (entry == NULL) {
        return CMT_OK;                                           /* :187-189 */
    }
    if (vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE) {         /* :191 */
        *out = entry->rvs.prevotes;                              /* :192 */
        return CMT_OK;
    }
    if (vote_type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {       /* :193 */
        *out = entry->rvs.precommits;                            /* :194 */
        return CMT_OK;
    }
    return CMT_FAULT;                                            /* :195-197 */
}

/* ══ constructors (height_vote_set.go:53-82) ══════════════════════════ */

static int hvs_new(const uint8_t *chain_id, size_t chain_id_len,
                   int64_t height, cmt_validator_set_t *val_set,
                   bool extensions_enabled, cmt_hvs_t **out)
{
    cmt_hvs_t *hvs;
    int        rc;

    if (out == NULL || val_set == NULL) {
        return CMT_FAULT;
    }
    if (chain_id == NULL && chain_id_len != 0u) {
        return CMT_FAULT;
    }
    /* INVARIANT atlas-dec-7495d337… — 32 raw bytes (R1 atlas-dec-9285f4a5…). */
    if (chain_id_len > (size_t)CMT_PB_CHAINID_MAX) {
        return CMT_REJECT;
    }
    hvs = (cmt_hvs_t *)calloc(1u, sizeof(*hvs));
    if (hvs == NULL) {
        return CMT_FAULT;
    }
    if (chain_id_len != 0u) {
        memcpy(hvs->chain_id, chain_id, chain_id_len);           /* :55, :64 */
    }
    hvs->chain_id_len       = chain_id_len;
    hvs->extensions_enabled = extensions_enabled;                /* :56, :65 */
    hvs->peer_catchup_rounds = (cmt_hvs_peer_catchup_t *)calloc(
        (size_t)CMT_PEER_MAX, sizeof(cmt_hvs_peer_catchup_t));
    if (hvs->peer_catchup_rounds == NULL) {
        free(hvs);
        return CMT_FAULT;
    }
    rc = cmt_hvs_reset(hvs, height, val_set);                    /* :58, :67 */
    if (rc != CMT_OK) {
        cmt_hvs_free(hvs);
        return rc;
    }
    *out = hvs;
    return CMT_OK;
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:53-60 —
 * NewHeightVoteSet() */
int cmt_new_height_vote_set(const uint8_t *chain_id, size_t chain_id_len,
                            int64_t height, cmt_validator_set_t *val_set,
                            cmt_hvs_t **out)
{
    return hvs_new(chain_id, chain_id_len, height, val_set, false, out);
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:62-69 —
 * NewExtendedHeightVoteSet() */
int cmt_new_extended_height_vote_set(const uint8_t *chain_id,
                                     size_t chain_id_len, int64_t height,
                                     cmt_validator_set_t *val_set,
                                     cmt_hvs_t **out)
{
    return hvs_new(chain_id, chain_id_len, height, val_set, true, out);
}

/* C only — the counterpart of the two constructors. */
void cmt_hvs_free(cmt_hvs_t *hvs)
{
    if (hvs == NULL) {
        return;
    }
    rvs_clear(hvs);
    free(hvs->round_vote_sets);
    free(hvs->peer_catchup_rounds);
    free(hvs);
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:71-82 — Reset() */
int cmt_hvs_reset(cmt_hvs_t *hvs, int64_t height,
                  cmt_validator_set_t *val_set)
{
    int rc;

    if (hvs == NULL || val_set == NULL) {
        return CMT_FAULT;
    }
    hvs->height  = height;                                       /* :75 */
    hvs->val_set = val_set;                                      /* :76 */
    /* :77-78 — new maps. Go drops the old ones; C frees them. */
    rvs_clear(hvs);
    memset(hvs->peer_catchup_rounds, 0,
           (size_t)CMT_PEER_MAX * sizeof(*hvs->peer_catchup_rounds));

    rc = add_round(hvs, 0);                                      /* :80 */
    if (rc != CMT_OK) {
        return rc;
    }
    hvs->round = 0;                                              /* :81 */
    return CMT_OK;
}

/* ══ accessors (height_vote_set.go:84-111) ════════════════════════════ */

/* cometbft@709fd12b consensus/types/height_vote_set.go:84-88 — Height() */
int64_t cmt_hvs_height(const cmt_hvs_t *hvs)
{
    if (hvs == NULL) {
        return 0;
    }
    return hvs->height;                                          /* :87 */
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:90-94 — Round() */
int32_t cmt_hvs_round(const cmt_hvs_t *hvs)
{
    if (hvs == NULL) {
        return -1;
    }
    return hvs->round;                                           /* :93 */
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:96-111 — SetRound() */
int cmt_hvs_set_round(cmt_hvs_t *hvs, int32_t round)
{
    int32_t new_round;
    int32_t r;
    int     rc;

    if (hvs == NULL) {
        return CMT_FAULT;
    }
    /* :100 — SafeSubInt32(hvs.round, 1), which PANICS on overflow
     * (safemath.go:26-30). ⚠ At hvs->round == 0 this is -1 and the loop
     * below really does create a RoundVoteSet at round -1; see the header. */
    if (cmt_safe_sub_int32(hvs->round, 1, &new_round) != CMT_OK) {
        return CMT_FAULT;
    }
    if (hvs->round != 0 && round < new_round) {
        return CMT_FAULT;                                        /* :101-103 */
    }
    /* :104 — `for r := newRound; r <= round; r++`, written so that
     * `round == INT32_MAX` cannot reach signed overflow, which is
     * undefined in C where Go merely wraps (INVARIANT atlas-dec-7495d337…). */
    if (new_round <= round) {
        r = new_round;
        for (;;) {
            if (rvs_find(hvs, r) == NULL) {                      /* :105-107 */
                rc = add_round(hvs, r);                          /* :108 */
                if (rc != CMT_OK) {
                    return rc;
                }
            }
            if (r == round) {
                break;
            }
            r++;
        }
    }
    hvs->round = round;                                          /* :110 */
    return CMT_OK;
}

/* ══ adding votes (height_vote_set.go:131-156) ════════════════════════ */

/* cometbft@709fd12b consensus/types/height_vote_set.go:131-156 — AddVote() */
int cmt_hvs_add_vote(cmt_hvs_t *hvs, const cmt_vote_t *vote,
                     cmt_peer_id_t peer, bool ext_enabled,
                     bool *out_added, cmt_vote_set_err_t *out_err,
                     cmt_vote_t *out_conflicting)
{
    cmt_vote_set_t         *vset = NULL;
    cmt_hvs_peer_catchup_t *entry = NULL;
    cmt_hvs_peer_catchup_t *free_slot = NULL;
    size_t                  i;
    int                     rc;

    if (out_added != NULL) {
        *out_added = false;
    }
    if (out_err != NULL) {
        *out_err = CMT_VOTE_SET_ERR_NONE;
    }
    if (hvs == NULL || vote == NULL) {
        return CMT_FAULT;
    }
    if (hvs->extensions_enabled != ext_enabled) {
        /* :136-138 panics. The flag comes from the application's own
         * consensus params, not from the wire: FAULT. */
        return CMT_FAULT;
    }
    if (!cmt_is_vote_type_valid(vote->type)) {                   /* :139 */
        return CMT_OK;             /* :140 naked return: added=false, no err */
    }
    rc = get_vote_set(hvs, vote->round, vote->type, &vset);      /* :142 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (vset == NULL) {                                          /* :143 */
        for (i = 0; i < (size_t)CMT_PEER_MAX; i++) {             /* :144 */
            if (hvs->peer_catchup_rounds[i].used) {
                if (cmt_peer_id_equals(&hvs->peer_catchup_rounds[i].peer,
                                       &peer)) {
                    entry = &hvs->peer_catchup_rounds[i];
                    break;
                }
            } else if (free_slot == NULL) {
                free_slot = &hvs->peer_catchup_rounds[i];
            }
        }
        if (entry != NULL && entry->n >= 2) {
            /* :148-151 — punish the peer. */
            if (out_err != NULL) {
                *out_err = CMT_VOTE_SET_ERR_GOT_VOTE_FROM_UNWANTED_ROUND;
            }
            return CMT_REJECT;
        }
        if (entry == NULL && free_slot == NULL) {
            /* C ONLY (INVARIANT atlas-dec-7495d337…): the reference's map
             * is unbounded. The 129th distinct peer is refused. */
            if (out_err != NULL) {
                *out_err = CMT_VOTE_SET_ERR_PEER_CAPACITY;
            }
            return CMT_REJECT;
        }
        rc = add_round(hvs, vote->round);                        /* :145 */
        if (rc != CMT_OK) {
            return rc;
        }
        rc = get_vote_set(hvs, vote->round, vote->type, &vset);  /* :146 */
        if (rc != CMT_OK || vset == NULL) {
            return CMT_FAULT;
        }
        if (entry == NULL) {                                     /* :147 */
            entry       = free_slot;
            entry->used = true;
            entry->peer = peer;
            entry->n    = 0u;
        }
        entry->rounds[entry->n] = vote->round;
        entry->n++;
    }
    return cmt_vote_set_add_vote(vset, vote, out_added, out_err,
                                 out_conflicting);               /* :154 */
}

/* ══ reading (height_vote_set.go:158-222) ═════════════════════════════ */

/* cometbft@709fd12b consensus/types/height_vote_set.go:158-162 — Prevotes() */
cmt_vote_set_t *cmt_hvs_prevotes(cmt_hvs_t *hvs, int32_t round)
{
    cmt_vote_set_t *vset = NULL;

    if (hvs == NULL) {
        return NULL;
    }
    (void)get_vote_set(hvs, round, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &vset);
    return vset;                                                 /* :161 */
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:164-168 —
 * Precommits() */
cmt_vote_set_t *cmt_hvs_precommits(cmt_hvs_t *hvs, int32_t round)
{
    cmt_vote_set_t *vset = NULL;

    if (hvs == NULL) {
        return NULL;
    }
    (void)get_vote_set(hvs, round, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &vset);
    return vset;                                                 /* :167 */
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:170-183 — POLInfo() */
int cmt_hvs_pol_info(cmt_hvs_t *hvs, int32_t *out_pol_round,
                     cmt_block_id_t *out_block_id)
{
    int32_t r;

    if (hvs == NULL || out_pol_round == NULL || out_block_id == NULL) {
        return CMT_FAULT;
    }
    for (r = hvs->round; r >= 0; r--) {                          /* :175 */
        cmt_vote_set_t *rvs = NULL;
        bool            ok  = false;

        (void)get_vote_set(hvs, r, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &rvs);
        /* :177 — rvs may be nil; TwoThirdsMajority is nil-safe
         * (vote_set.go:473-475) and answers (BlockID{}, false). */
        if (cmt_vote_set_two_thirds_majority(rvs, out_block_id,
                                             &ok) != CMT_OK) {
            return CMT_FAULT;
        }
        if (ok) {                                                /* :178 */
            *out_pol_round = r;                                  /* :179 */
            return CMT_OK;
        }
    }
    *out_pol_round = -1;                                         /* :182 */
    cmt_pb_block_id_init(out_block_id);
    return CMT_OK;
}

/* cometbft@709fd12b consensus/types/height_vote_set.go:200-219 —
 * SetPeerMaj23() */
int cmt_hvs_set_peer_maj23(cmt_hvs_t *hvs, int32_t round, int32_t vote_type,
                           cmt_peer_id_t peer, const cmt_block_id_t *block_id,
                           cmt_vote_set_err_t *out_err)
{
    cmt_vote_set_t *vset = NULL;
    int             rc;

    if (out_err != NULL) {
        *out_err = CMT_VOTE_SET_ERR_NONE;
    }
    if (hvs == NULL || block_id == NULL) {
        return CMT_FAULT;
    }
    if (!cmt_is_vote_type_valid(vote_type)) {                    /* :211 */
        if (out_err != NULL) {
            *out_err = CMT_VOTE_SET_ERR_INVALID_VOTE_TYPE;       /* :212 */
        }
        return CMT_REJECT;
    }
    rc = get_vote_set(hvs, round, vote_type, &vset);             /* :214 */
    if (rc != CMT_OK) {
        return CMT_FAULT;
    }
    if (vset == NULL) {
        return CMT_OK;              /* :215-217 something we don't know yet */
    }
    return cmt_vote_set_set_peer_maj23(vset, peer, block_id, out_err);
}
