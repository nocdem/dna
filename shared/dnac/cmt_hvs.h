/**
 * @file shared/dnac/cmt_hvs.h
 * @brief cometbft @709fd12b `consensus/types/height_vote_set.go` ported
 *        to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-A of the cometbft → C consensus port. Additive only; nothing in
 * the running chain calls anything here.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A HeightVoteSet is every VoteSet of one height: prevotes and precommits
 * for round 0 up to the current round, plus up to two extra "catch-up"
 * rounds per peer so that a node behind the network can still be given the
 * commit that ended the height (height_vote_set.go:27-40).
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. STORAGE. `cmt_new_height_vote_set` allocates and `cmt_hvs_free`
 *    releases, for the same reason cmt_vote_set does: a single
 *    `cmt_vote_set_t` is far too large for the stack and this holds two
 *    per round. Allocation failure is CMT_FAULT (register row R1B-11).
 * 2. ROUNDS ARE SPARSE, and they must be. `roundVoteSets map[int32]
 *    RoundVoteSet` (:49) is represented as a GROWABLE ARRAY OF
 *    {round, RoundVoteSet} ENTRIES searched by the round key — NOT as an
 *    array indexed by round. Two facts in the reference force this:
 *      (a) `SetRound` computes `newRound := SafeSubInt32(hvs.round, 1)`
 *          (:100) and loops from there (:104). At `hvs.round == 0`, which
 *          is what `Reset` leaves (:81), that is r = -1, and :105 finds no
 *          entry, so `addRound(-1)` RUNS on the first SetRound of every
 *          height. A round-indexed array cannot hold -1. The reference is
 *          untroubled: a Go map takes -1 as a key, and a VoteSet at round
 *          -1 can never match a vote, whose round is >= 0.
 *      (b) A peer's catch-up round is arbitrary. The reference's own test
 *          adds votes at rounds 999, 1000 and 1001 with nothing in
 *          between (height_vote_set_test.go:31-52). A dense array would
 *          allocate 1001 rounds — two vote sets each — for three used
 *          ones; the Go map allocates three.
 *    Rounds are therefore NOT capped: a liveness failure legitimately
 *    pushes the round number up, and the memory cost is one entry per
 *    round actually reached, exactly as in the reference.
 * 3. PEER CATCH-UP ROUNDS. `peerCatchupRounds map[p2p.ID][]int32` (:50)
 *    becomes a fixed array of CMT_PEER_MAX entries, each holding the at
 *    most two rounds the reference's own comment describes (:38-39). The
 *    129th distinct peer is refused with CMT_VOTE_SET_ERR_PEER_CAPACITY
 *    (INVARIANT atlas-dec-7495d337…); the reference's map is unbounded.
 * 4. PEER IDENTITY. `p2p.ID` → `cmt_peer_id_t` (cmt_vote_set.h). The
 *    reference's `""` — "peerID is "" if origin is self" (:132) — is the
 *    all-zero id and is NOT special-cased, because :144 and :147 do not
 *    special-case it either.
 * 5. ERRORS. One channel, `cmt_vote_set_err_t`, shared with cmt_vote_set:
 *    a vote that reaches `AddVote` either fails here (an unwanted round)
 *    or is forwarded to a VoteSet and fails there, and the caller
 *    (consensus/state.go:2069-2118) discriminates on one error value.
 * 6. PANICS. Each site says which it became and why, at the site.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock, no randomness. `round_vote_sets` is an ARRAY scanned in
 * insertion order; `POLInfo` walks rounds DOWNWARD from `round` to 0
 * (:175), a fixed order, and returns the first majority it finds. The
 * reference's `StringIndented` iterates the map (:240) — it is not
 * ported, and it was display only.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `String` (:224-226), `StringIndented` (:228-255), `MarshalJSON`
 *     (:257-261), `toAllRoundVotes` (:263-278), `type roundVotes`
 *     (:280-286) — logging/JSON, and the only map-order-dependent code in
 *     the file.
 *   · `ErrGotVoteFromUnwantedRound` (:21-25) as an error OBJECT — the
 *     port has no error objects; it is the enum value
 *     CMT_VOTE_SET_ERR_GOT_VOTE_FROM_UNWANTED_ROUND.
 *   · The `sync.Mutex` of :47 — single-threaded port (umbrella rev 3).
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/types/height_vote_set.go  286 lines
 *     d6793961c6f113acad7fa153cf2d912224191350f547860812d623e9ca13964c
 *   libs/math/safemath.go                65 lines
 *     be592544331912400aecaee1ccdc8834afdf8508857d32d475e3f6bfaf3b33d2
 *     ⚠ NOT in the pin record's table; opened for ONE range
 *       (:25-32, SafeSubInt32), which :100 calls. Reported with its hash.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * pin record rev 5 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c),
 * T2 reference pins (atlas-dec-84fab23d6bfec90b9572d70c8937450f — this
 * file is one of the four named there).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_HVS_H
#define SHARED_DNAC_CMT_HVS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_vote_set.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══ RoundVoteSet (height_vote_set.go:16-19) ══════════════════════════ */

/** cometbft@709fd12b consensus/types/height_vote_set.go:16-19 —
 *  `type RoundVoteSet struct`. Both are OWNED by the HeightVoteSet. */
typedef struct {
    cmt_vote_set_t *prevotes;     /* :17 */
    cmt_vote_set_t *precommits;   /* :18 */
} cmt_round_vote_set_t;

/** One entry of `roundVoteSets map[int32]RoundVoteSet` (:49): the map key
 *  beside its value, because C has no map. See substitution 2. */
typedef struct {
    int32_t              round;
    cmt_round_vote_set_t rvs;
} cmt_hvs_round_entry_t;

/** One entry of `peerCatchupRounds map[p2p.ID][]int32` (:50). `n` is
 *  `len(rndz)` and is at most 2, the ceiling :144 enforces. */
typedef struct {
    bool          used;
    cmt_peer_id_t peer;
    int32_t       rounds[2];
    uint8_t       n;
} cmt_hvs_peer_catchup_t;

/* ══ HeightVoteSet (height_vote_set.go:41-222) ════════════════════════ */

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:41-51 —
 * `type HeightVoteSet struct`.
 *
 * Visible for cmt_round_state.h and the tests, as `cmt_vote_set_t` is;
 * constructed only by `cmt_new_height_vote_set` /
 * `cmt_new_extended_height_vote_set` and released only by `cmt_hvs_free`.
 */
typedef struct {
    uint8_t                 chain_id[CMT_PB_CHAINID_MAX];  /* :42          */
    size_t                  chain_id_len;
    int64_t                 height;                        /* :43          */
    cmt_validator_set_t    *val_set;                       /* :44 borrowed */
    bool                    extensions_enabled;            /* :45          */

    int32_t                 round;                         /* :48          */
    cmt_hvs_round_entry_t  *round_vote_sets;               /* :49          */
    size_t                  round_vote_sets_len;
    size_t                  round_vote_sets_cap;
    cmt_hvs_peer_catchup_t *peer_catchup_rounds;           /* :50          */
} cmt_hvs_t;

/* ── constructors ───────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:53-60 —
 * `NewHeightVoteSet()`. Extensions OFF (:56).
 * @param val_set BORROWED; must outlive the height vote set.
 * @param out receives the new object; free it with `cmt_hvs_free`.
 * @return CMT_OK; CMT_REJECT from the vote sets `Reset` builds (a height
 *         of 0, a chain id or a validator count out of range);
 *         CMT_FAULT on NULL or allocation failure.
 */
int cmt_new_height_vote_set(const uint8_t *chain_id, size_t chain_id_len,
                            int64_t height, cmt_validator_set_t *val_set,
                            cmt_hvs_t **out);

/** cometbft@709fd12b consensus/types/height_vote_set.go:62-69 —
 *  `NewExtendedHeightVoteSet()`. Extensions ON (:65), so every precommit
 *  added to it has its extension signature checked (:120-122). */
int cmt_new_extended_height_vote_set(const uint8_t *chain_id,
                                     size_t chain_id_len, int64_t height,
                                     cmt_validator_set_t *val_set,
                                     cmt_hvs_t **out);

/** C only — frees every round's two vote sets and the object itself. The
 *  validator set is BORROWED and is not touched. NULL is a no-op. */
void cmt_hvs_free(cmt_hvs_t *hvs);

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:71-82 — `Reset()`.
 * Drops every round of the previous height and starts again at round 0.
 * In Go the old maps are simply dropped and the GC reclaims them; here
 * every vote set of every round is freed first.
 * @return CMT_OK; CMT_REJECT / CMT_FAULT from `addRound(0)` (:80).
 */
int cmt_hvs_reset(cmt_hvs_t *hvs, int64_t height,
                  cmt_validator_set_t *val_set);

/* ── accessors ──────────────────────────────────────────────────────── */

/** cometbft@709fd12b consensus/types/height_vote_set.go:84-88 —
 *  `Height()`. A NULL receiver would panic in Go; here it answers 0. */
int64_t cmt_hvs_height(const cmt_hvs_t *hvs);

/** cometbft@709fd12b consensus/types/height_vote_set.go:90-94 —
 *  `Round()`. A NULL receiver answers -1, matching
 *  `VoteSet.GetRound`'s nil answer (vote_set.go:125). */
int32_t cmt_hvs_round(const cmt_hvs_t *hvs);

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:96-111 —
 * `SetRound()`. Creates the RoundVoteSets up to `round`.
 *
 * ⚠ ROUND -1. On the first call of a height, `hvs->round` is 0 and the
 * reference's loop starts at `SafeSubInt32(0, 1) == -1` (:100, :104), so
 * a RoundVoteSet AT ROUND -1 IS CREATED. That is the reference's
 * behaviour, verified by reading safemath.go:25-32, and it is reproduced
 * here rather than "fixed" — see substitution 2 in the file header.
 *
 * @return CMT_OK;
 *         CMT_FAULT where the reference panics at :101-103 ("SetRound()
 *           must increment hvs.round") — the caller is the consensus
 *           state machine, not the wire — and where SafeSubInt32 would
 *           panic on overflow (:100);
 *         CMT_REJECT / CMT_FAULT from the vote sets it creates.
 */
int cmt_hvs_set_round(cmt_hvs_t *hvs, int32_t round);

/* ── adding votes ───────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:131-156 —
 * `AddVote()`.
 *
 * @param peer the sender; `cmt_peer_id_self()` for our own vote, which is
 *        the reference's `""` (:132).
 * @param ext_enabled MUST equal the value this object was built with;
 *        the reference panics on a mismatch (:136-138).
 * @param out_added, @param out_err, @param out_conflicting as
 *        `cmt_vote_set_add_vote`; all may be NULL.
 * @return CMT_OK — including the case of a vote whose TYPE is not a vote
 *           type, which the reference drops silently with a naked
 *           `return` (:139-141), giving added = false and no error;
 *         CMT_REJECT with CMT_VOTE_SET_ERR_GOT_VOTE_FROM_UNWANTED_ROUND
 *           when this peer has already used its two catch-up rounds
 *           (:148-151), with CMT_VOTE_SET_ERR_PEER_CAPACITY for the 129th
 *           distinct peer (C only), or with whatever the round's VoteSet
 *           returned (:154);
 *         CMT_FAULT at the :137 panic, on NULL, or on allocation failure.
 */
int cmt_hvs_add_vote(cmt_hvs_t *hvs, const cmt_vote_t *vote,
                     cmt_peer_id_t peer, bool ext_enabled,
                     bool *out_added, cmt_vote_set_err_t *out_err,
                     cmt_vote_t *out_conflicting);

/* ── reading ────────────────────────────────────────────────────────── */

/** cometbft@709fd12b consensus/types/height_vote_set.go:158-162 —
 *  `Prevotes()`. NULL when that round is not tracked (:187-189). The
 *  pointer is BORROWED and dies with the height vote set. */
cmt_vote_set_t *cmt_hvs_prevotes(cmt_hvs_t *hvs, int32_t round);

/** cometbft@709fd12b consensus/types/height_vote_set.go:164-168 —
 *  `Precommits()`. NULL when that round is not tracked. */
cmt_vote_set_t *cmt_hvs_precommits(cmt_hvs_t *hvs, int32_t round);

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:170-183 —
 * `POLInfo()`. The LAST round with a +2/3 prevote majority, walking
 * DOWNWARD from the current round (:175).
 * @param out_pol_round receives the round, or -1 when there is none
 *        (:182).
 * @param out_block_id receives that round's majority BlockID, or the zero
 *        BlockID (:182). Always written.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_hvs_pol_info(cmt_hvs_t *hvs, int32_t *out_pol_round,
                     cmt_block_id_t *out_block_id);

/**
 * cometbft@709fd12b consensus/types/height_vote_set.go:200-219 —
 * `SetPeerMaj23()`.
 * @return CMT_OK — including the "something we don't know about yet"
 *           case of an untracked round (:215-217), which is not an error;
 *         CMT_REJECT with CMT_VOTE_SET_ERR_INVALID_VOTE_TYPE (:211-213)
 *           or whatever `VoteSet.SetPeerMaj23` returned (:218);
 *         CMT_FAULT on NULL.
 */
int cmt_hvs_set_peer_maj23(cmt_hvs_t *hvs, int32_t round, int32_t vote_type,
                           cmt_peer_id_t peer, const cmt_block_id_t *block_id,
                           cmt_vote_set_err_t *out_err);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_HVS_H */
