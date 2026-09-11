/**
 * @file shared/dnac/cmt_vote_set.h
 * @brief cometbft @709fd12b `types/vote_set.go` ported to C, plus the three
 *        `types/block.go` functions that build a VoteSet.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-A of the cometbft → C consensus port. Additive only; nothing in
 * the running chain calls anything here. The live witness BFT, QC V2 and
 * the T3 wave-1 modules are byte-identically untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * A VoteSet collects the signatures of one (height, round, vote type) and
 * answers the one question consensus asks of it: is there a +2/3 majority,
 * and for which block. It also has to survive double-signing validators
 * without letting a peer make it store an unbounded number of votes; the
 * reference's own argument for why that is bounded is at vote_set.go:55-57
 * and is the derivation CMT_VOTE_SET_MAX_BLOCKS below reproduces.
 *
 * ── WHY block.go's ToVoteSet FAMILY LIVES HERE ─────────────────────────
 * `Commit.ToVoteSet` (block.go:1101-1117), `ExtendedCommit.
 * ToExtendedVoteSet` (:1075-1079) and `ExtendedCommit.addSigsToVoteSet`
 * (:1082-1096) are members of package `types` in the reference, where a
 * Commit and a VoteSet are in the same package and may refer to each
 * other freely. In C they cannot: cmt_block.h would have to include this
 * header for `cmt_vote_set_t`, and this header already includes
 * cmt_block.h for `cmt_block_id_t`, `cmt_commit_t` and
 * `cmt_extended_commit_t` — an include cycle. R1's cmt_block.h:80-82
 * anticipated exactly this and listed the three as "wave R2 ports".
 * They are therefore defined in cmt_vote_set.{h,c}, with their block.go
 * citations intact.
 *
 * `ExtendedCommit.ToCommit` (block.go:1130-1143) is NOT here: R1 already
 * ported it as `cmt_extended_commit_to_commit` (cmt_block.h:601-605). It
 * needs no VoteSet, so it never had the cycle problem.
 *
 * ── Substitutions, and nothing else ────────────────────────────────────
 * 1. STORAGE. The reference's VoteSet is a Go object whose maps and
 *    slices the garbage collector owns. Here `cmt_vote_set_new` allocates
 *    the whole structure and `cmt_vote_set_free` releases it; an
 *    allocation failure is CMT_FAULT (transient/owned malloc is permitted
 *    — register row R1B-11). A vote set is far too large for the stack
 *    (see "Size" below), so there is no `_init` form and no caller-storage
 *    form: `_new`/`_free` is the only shape.
 * 2. VOTE OWNERSHIP. `votes []*Vote` (:71) stores the CALLER's pointer in
 *    Go and the GC keeps it alive. Here `cmt_vote_set_add_vote` COPIES the
 *    vote into storage the set owns, because the host's decode buffer is
 *    reused. ⚠ PRECONDITION: a vote's `extension` field is a
 *    `cmt_pb_bytes_t` DESCRIPTOR and the copy shares its bytes, exactly as
 *    R1's `cmt_vote_copy` (cmt_vote.h:237-241) does and exactly as Go's
 *    `[]byte` header copy shares its backing array. THE EXTENSION BYTES OF
 *    EVERY ADDED VOTE MUST OUTLIVE THE VOTE SET. The host's per-height
 *    arena satisfies this; a per-message arena does not.
 * 3. VALIDATORS BY INDEX. `votes []*Vote` of length `valSet.Size()` (:92)
 *    becomes an array of N pointers, N fixed at construction.
 * 4. blockKey. `string(blockHash|blockParts)` (:74) becomes the bytes
 *    `cmt_block_id_key` (cmt_block.h:318) produces, compared with memcmp;
 *    a C string cannot hold the embedded NULs these bytes contain.
 *    `votesByBlock map[string]*blockVotes` becomes a fixed-capacity array
 *    searched linearly — see CMT_VOTE_SET_MAX_BLOCKS.
 * 5. PEER IDENTITY. `P2PID` (:25) is a Go string. Here it is
 *    `cmt_peer_id_t`, 32 bytes, the width of this tree's witness id
 *    (= `cmt_address_hash`, cmt_tmhash.h:100). The reference passes `""`
 *    for the node's OWN messages (height_vote_set.go:132); `""` is
 *    represented by the ALL-ZERO id and is NOT special-cased anywhere,
 *    because the reference does not special-case it either — at :344,
 *    :351, :144 and :147 it is an ordinary map key.
 * 6. PANICS. Each site says which it became and why, at the site.
 * 7. BOUNDS. Every count that a peer can influence is checked explicitly
 *    (INVARIANT atlas-dec-7495d3372e004b24b4f6cc7bff5caf07).
 * 8. ERRORS. The reference returns typed errors its caller discriminates
 *    (consensus/state.go:2069-2118). `cmt_vote_set_err_t` below carries
 *    one value per distinct error the reference can return from this
 *    module — see the enum's own comments for the one place where R1's
 *    verify API collapses three of them into one.
 *
 * ── Size ───────────────────────────────────────────────────────────────
 * A `cmt_vote_t` carries two 4627-byte signature buffers and is about
 * 9.5 KB. N = 128 canonical votes are therefore ~1.2 MB, and the
 * reference's own structural bound on stored vote objects — N canonical
 * plus one per (validator, peer-claimed block) pair, :209 and :285-296 —
 * is N + N·P = 16512 objects, ~157 MB in the adversarial worst case. The
 * COUNT is exactly the reference's; the byte cost is 50× because an
 * ML-DSA-87 signature is 4627 bytes where an ed25519 one is 64. Nothing
 * is preallocated for that worst case: vote objects are allocated one at
 * a time as votes arrive, as Go allocates them.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock, no randomness, no hash-map iteration. `votesByBlock` is an
 * ARRAY scanned in insertion order, and the only place the reference
 * iterates it (`addVerifiedVote`'s quorum copy, :318-322) iterates ONE
 * blockVotes' votes by validator index. `MakeExtendedCommit` walks
 * `votes` in validator-index order (:650). Two nodes fed the same votes
 * in the same order hold the same set; two nodes fed the same votes in a
 * DIFFERENT order can differ in exactly the way the reference differs —
 * `maj23` records the FIRST quorum seen (:314) and `.votes[i]` keeps the
 * FIRST vote seen from validator i (:265-281) — which is why nothing
 * derived from a VoteSet enters a block except through the commit, whose
 * content is fixed by `maj23` and validator index order.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `String` (:492-497), `StringIndented` (:507-530), `MarshalJSON`
 *     (:534-542), `VoteSetJSON` (:547-551), `BitArrayString` (:556-560),
 *     `bitArrayString` (:562-566), `VoteStrings` (:569-573),
 *     `voteStrings` (:575-585), `StringShort` (:596-605), `LogString`
 *     (:609-618), `sumTotalFrac` (:621-625) — logging/JSON. The port map
 *     carries no String/JSON rows.
 *   · `nilVoteSetString` (:487) — used only by the above.
 *   · `VoteSetReader` (:716-724) — a Go interface. C has no interfaces;
 *     the seven methods it names are all ported as plain functions here
 *     and on cmt_extended_commit (cmt_block.h:614-640).
 *   · The `cmtsync.Mutex` of :69 — single-threaded port (umbrella rev 3
 *     item 4). Every `mtx.Lock()`/`defer Unlock()` pair is dropped.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   types/vote_set.go      724 lines 548a256c311755a4a2d83696c90030f144952c64c0e3a459ac86baf844c56880
 *   types/block.go        1555 lines 2094420e26fa23d4b6a592a06e7953025541973694bd96ff9c8e5d9911162109
 *   types/vote.go          454 lines dd978df4530187c34902fad06ba1f7065896ece92b68d07d3a9bfc55ddb82e0f
 *   libs/bits/bit_array.go 497 lines de70791bae05efc5c2e059f56c6582b7cbe700531dfb73c0e53077cfaa297d49
 *   types/validator_set.go 1053 lines 6c3a663aaf84fbee94735731eaba27d1a8e5269dd6e316e0b175595e32902221
 *   consensus/state.go    2653 lines f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *     (read-only, for the caller's error discrimination at :2069-2118 and
 *      the two ToVoteSet call sites at :610-624 and :626-643)
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * pin record rev 5 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c),
 * R1 types port (atlas-dec-9285f4a5c9679f00a4d042a15acf45e4),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_VOTE_SET_H
#define SHARED_DNAC_CMT_VOTE_SET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_bits.h"
#include "cmt_block.h"          /* BlockID, Commit, ExtendedCommit, Key()   */
#include "cmt_vote.h"           /* cmt_vote_t, Verify*, ExtendedCommitSig   */
#include "cmt_validator_set.h"  /* CMT_VALSET_MAX, GetByIndex, TotalPower   */
#include "cmt_params.h"         /* cmt_abci_params_t                        */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ constants ════════════════════════════════════════════════════════ */

/** cometbft@709fd12b types/vote_set.go:14-19 — `MaxVotesCount`.
 *  The reference's DoS ceiling on the number of votes in a set, used by
 *  `ValidateBasic` funcs elsewhere. Carried unchanged; this port's own
 *  ceiling is the tighter CMT_VALSET_MAX. */
#define CMT_MAX_VOTES_COUNT 10000

/**
 * The number of distinct PEERS whose claims a vote set will remember.
 *
 * The reference's `peerMaj23s map[P2PID]BlockID` (:75) and
 * `peerCatchupRounds map[p2p.ID][]int32` (height_vote_set.go:50) are
 * unbounded maps whose own comments say so (":330-332 — NOTE: if there
 * are too many peers, or too much peer churn, this can cause memory
 * issues. TODO: implement ability to remove peers too"). C gets an
 * explicit bound instead (INVARIANT atlas-dec-7495d337…): the 129th
 * DISTINCT peer is refused with CMT_VOTE_SET_ERR_PEER_CAPACITY.
 *
 * 128 is the number of witness peers this tree provisions for:
 * `nodus_witness_peer_t peers[NODUS_T3_MAX_WITNESSES]`
 * (nodus/src/witness/nodus_witness.h:901) with
 * `#define NODUS_T3_MAX_WITNESSES 128`
 * (nodus/include/nodus/nodus_types.h:156). Those two files are CITED, not
 * included: shared/dnac must not depend on nodus/ (the direction rule
 * R1-B recorded for cmt_pubkey_address). The constant this header can
 * actually see and tie itself to is DNA_MAX_ACTIVE_VALIDATORS, which is
 * the same 128 (ledger_ids.h:103). The assertion below pins the LITERAL
 * 128 on purpose: it is the cross-tree coupling with
 * NODUS_T3_MAX_WITNESSES that shared/ cannot express by name, so a change
 * to either side that is not mirrored on the other fails to compile here
 * with a message naming the other constant (Delta A-2, verifier A: an
 * assertion of CMT_PEER_MAX against its own definition checked nothing).
 */
#define CMT_PEER_MAX DNA_MAX_ACTIVE_VALIDATORS

_Static_assert((int)CMT_PEER_MAX == 128,
               "CMT_PEER_MAX must equal NODUS_T3_MAX_WITNESSES "
               "(nodus/include/nodus/nodus_types.h:156); change both");

/**
 * The number of distinct blocks a vote set will track.
 *
 * DERIVATION, and it is the reference's own (vote_set.go:44-57): a
 * `&blockVotes{}` is created in exactly two places.
 *   (a) `addVerifiedVote` :299 — a validator's FIRST vote names a block
 *       nobody has named yet. At most one per validator, so ≤ N.
 *   (b) `SetPeerMaj23` :362 — a peer claims +2/3 for a block. A peer that
 *       has already told us something either repeats itself (:345-347,
 *       nothing to do) or is refused (:348-349), so at most one per peer,
 *       ≤ P.
 * Hence ≤ N + P, and with N ≤ CMT_VALSET_MAX and P ≤ CMT_PEER_MAX the
 * capacity is their sum. Exhausting it is CMT_VOTE_SET_ERR_BLOCK_CAPACITY
 * — unreachable if the derivation holds, and a refusal rather than a
 * write past the end if it does not.
 */
#define CMT_VOTE_SET_MAX_BLOCKS (CMT_VALSET_MAX + CMT_PEER_MAX)

/* ══ peer identity ════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b types/vote_set.go:25 — `type P2PID string`, itself a
 * copy of `p2p.ID` (p2p/key.go:16, a hex-encoded 20-byte node id in the
 * reference).
 *
 * Here a peer is named by its 32-byte witness id — SHA3-512(pubkey)[0..31]
 * = `cmt_address_hash` (cmt_tmhash.h:100), CMT_TMHASH_TRUNCATED_SIZE wide.
 * The reference's `""` (the node's own messages, height_vote_set.go:132)
 * is the ALL-ZERO id.
 *
 * ⚠ `""` IS NOT SPECIAL. The reference stores and looks it up like any
 * other key, and so does this port. A real peer whose id were all zero
 * would collide with "self"; SHA3-512 makes that a 2^-256 event and the
 * reference has the same collision between `""` and a peer literally
 * named "".
 */
typedef struct {
    uint8_t id[CMT_TMHASH_TRUNCATED_SIZE];
} cmt_peer_id_t;

/** The reference's `""` peer id — the node's own messages
 *  (height_vote_set.go:131-132). Not special-cased; just a value. */
static inline cmt_peer_id_t cmt_peer_id_self(void)
{
    cmt_peer_id_t p;
    size_t        i;

    for (i = 0; i < sizeof(p.id); i++) {
        p.id[i] = 0u;
    }
    return p;
}

/** Byte equality of two peer ids — Go's map-key equality on a string. */
bool cmt_peer_id_equals(const cmt_peer_id_t *a, const cmt_peer_id_t *b);

/* ══ errors ═══════════════════════════════════════════════════════════ */

/**
 * One value per distinct error the reference can return from this module
 * and from cmt_hvs. `CMT_VOTE_SET_ERR_NONE` is the reference's `nil`.
 *
 * WHY AN ENUM AND NOT A RETURN CODE ALONE: the reference's caller
 * discriminates. `consensus/state.go:2069-2118 tryAddVote` branches on
 *   · `*types.ErrVoteConflictingVotes` (:2077) → report to the evidence
 *     pool, and it needs BOTH votes;
 *   · `types.ErrVoteNonDeterministicSignature` (:2102) → log, DO NOT
 *     punish the peer;
 *   · `types.ErrInvalidVoteExtension` (:2104) → log, do not punish. Note
 *     that this one is NOT reachable from here: the only place the
 *     pinned tree raises it is `state/execution.go:373`, and
 *     `VerifyVoteAndExtension` (vote.go:242-259) never returns it. It has
 *     no enum value for that reason.
 *   · anything else (:2106-2113) → `ErrAddingVote`, punish the peer.
 * A single CMT_REJECT would erase that distinction and with it the
 * evidence path.
 */
typedef enum {
    /** No error — the reference's `nil`. */
    CMT_VOTE_SET_ERR_NONE = 0,

    /** vote_set.go:170 — `ErrVoteNil`. */
    CMT_VOTE_SET_ERR_NIL,

    /** vote_set.go:178 (`index < 0`) and :195-197 (no such validator) —
     *  `ErrVoteInvalidValidatorIndex`. */
    CMT_VOTE_SET_ERR_INVALID_VALIDATOR_INDEX,

    /** vote_set.go:180 (empty address) and :202-205 (address does not
     *  match the validator at that index) —
     *  `ErrVoteInvalidValidatorAddress`. */
    CMT_VOTE_SET_ERR_INVALID_VALIDATOR_ADDRESS,

    /** vote_set.go:187-189 — `ErrVoteUnexpectedStep`: the vote's
     *  height/round/type is not this set's. */
    CMT_VOTE_SET_ERR_UNEXPECTED_STEP,

    /** vote_set.go:213 — `ErrVoteNonDeterministicSignature`: the same
     *  validator, the same block, a different signature. */
    CMT_VOTE_SET_ERR_NON_DETERMINISTIC_SIGNATURE,

    /**
     * vote_set.go:218-220 / :222-224 — the vote's signature did not
     * verify. The reference wraps THREE distinct errors into these two
     * unnamed `fmt.Errorf`s: `ErrVoteInvalidValidatorAddress` and
     * `ErrVoteInvalidSignature` from `verifyAndReturnProto`
     * (vote.go:219-228), and the unnamed "expected vote extension
     * signature" of vote.go:249-251. R1's `cmt_vote_verify` and
     * `cmt_vote_verify_vote_and_extension` return CMT_REJECT for all
     * three (cmt_vote.h:251-258, :269-272), so this port cannot separate
     * them either — and neither does the reference's own caller, which
     * sends every one of them down the `ErrAddingVote` branch
     * (state.go:2106-2113). Nothing the caller acts on is lost.
     */
    CMT_VOTE_SET_ERR_VERIFY_FAILED,

    /** vote_set.go:225-230 — an unnamed error: extension data is present
     *  on a vote added to a set that does not require extensions. */
    CMT_VOTE_SET_ERR_UNEXPECTED_EXTENSION,

    /** vote_set.go:236 — `NewConflictingVoteError(conflicting, vote)`.
     *  The conflicting vote is written to the caller's `out_conflicting`
     *  when one is supplied. */
    CMT_VOTE_SET_ERR_CONFLICTING_VOTES,

    /** vote_set.go:348-349 — an unnamed error: this peer already claimed
     *  a DIFFERENT block for this (height, round, type). */
    CMT_VOTE_SET_ERR_PEER_MAJ23_CONFLICT,

    /** height_vote_set.go:22-25 / :150 —
     *  `ErrGotVoteFromUnwantedRound`: the peer has already been given its
     *  two catch-up rounds. Raised by cmt_hvs, carried in this enum so a
     *  vote's journey has ONE error channel. */
    CMT_VOTE_SET_ERR_GOT_VOTE_FROM_UNWANTED_ROUND,

    /** height_vote_set.go:212 — an unnamed error: `SetPeerMaj23` was
     *  given something that is not a vote type. Raised by cmt_hvs. */
    CMT_VOTE_SET_ERR_INVALID_VOTE_TYPE,

    /** C ONLY (INVARIANT atlas-dec-7495d337…): the 129th distinct peer,
     *  in `peerMaj23s` or in cmt_hvs' `peerCatchupRounds`. The reference's
     *  maps have no bound and its own comment (:330-332) calls that a
     *  memory hazard. */
    CMT_VOTE_SET_ERR_PEER_CAPACITY,

    /** C ONLY (INVARIANT atlas-dec-7495d337…): `votesByBlock` is full.
     *  Unreachable while the CMT_VOTE_SET_MAX_BLOCKS derivation holds. */
    CMT_VOTE_SET_ERR_BLOCK_CAPACITY
} cmt_vote_set_err_t;

/* ══ blockVotes (vote_set.go:675-711) ═════════════════════════════════ */

/**
 * cometbft@709fd12b types/vote_set.go:681-686 — `type blockVotes struct`.
 *
 * `votes` holds BORROWED pointers into the vote objects the enclosing
 * vote set owns, exactly as the Go slice holds the same `*Vote` values
 * that `voteSet.votes` holds. Freeing is the vote set's job, never this
 * structure's.
 *
 * `key`/`key_len`/`used` are C only: they are the map key this entry is
 * filed under, which Go keeps in the map and C has to keep in the entry.
 */
typedef struct {
    bool             peer_maj23;                    /* :682              */
    cmt_bit_array_t  bit_array;                     /* :683              */
    cmt_vote_t     **votes;                         /* :684, N borrowed  */
    int64_t          sum;                           /* :685              */

    bool             used;                          /* C: slot occupied  */
    uint8_t          key[CMT_BLOCK_ID_MAX_BYTES];   /* C: the map key    */
    size_t           key_len;
} cmt_block_votes_t;

/* ══ VoteSet (vote_set.go:61-711) ═════════════════════════════════════ */

/** One entry of `peerMaj23s map[P2PID]BlockID` (vote_set.go:75). */
typedef struct {
    bool           used;
    cmt_peer_id_t  peer;
    cmt_block_id_t block_id;
} cmt_peer_maj23_entry_t;

/**
 * cometbft@709fd12b types/vote_set.go:61-76 — `type VoteSet struct`.
 *
 * The struct is visible so that cmt_hvs.c and the tests can read it, as
 * R1 made `cmt_validator_set_t` visible; it is CONSTRUCTED ONLY by
 * `cmt_vote_set_new` and released only by `cmt_vote_set_free`. Writing a
 * field by hand breaks invariants the reference keeps implicitly.
 *
 * Every method of the reference takes a `*VoteSet` receiver, so every
 * function here takes a non-const `cmt_vote_set_t *` — several of them
 * (`HasTwoThirdsAny` :458, `HasAll` :467, `addVerifiedVote` :306) reach
 * `valSet.TotalVotingPower()`, which WRITES the reference's lazily
 * recomputed cache (validator_set.go:332-337, R1
 * cmt_validator_set_total_voting_power).
 */
typedef struct {
    uint8_t              chain_id[CMT_PB_CHAINID_MAX];  /* :62           */
    size_t               chain_id_len;
    int64_t              height;                        /* :63           */
    int32_t              round;                         /* :64           */
    int32_t              signed_msg_type;               /* :65           */
    cmt_validator_set_t *val_set;                       /* :66, borrowed */
    bool                 extensions_enabled;            /* :67           */

    cmt_bit_array_t      votes_bit_array;               /* :70           */
    cmt_vote_t         **votes;                         /* :71, N owned  */
    int64_t              sum;                           /* :72           */
    bool                 has_maj23;                     /* :73 nil-ness  */
    cmt_block_id_t       maj23;                         /* :73           */
    cmt_block_votes_t   *votes_by_block;                /* :74           */
    cmt_peer_maj23_entry_t *peer_maj23s;                /* :75           */

    /* C only. */
    size_t               n_validators;   /* valSet.Size() at construction */
    cmt_vote_t         **owned;          /* every vote object this set    */
    size_t               owned_len;      /* allocated, so that _free can  */
    size_t               owned_cap;      /* release them all              */
} cmt_vote_set_t;

/* ── constructors ───────────────────────────────────────────────────── */

/**
 * cometbft@709fd12b types/vote_set.go:78-98 — `NewVoteSet()`.
 *
 * @param chain_id 32 raw bytes at most (umbrella rev 3; R1 decision
 *        atlas-dec-9285f4a5…). A longer id is CMT_REJECT.
 * @param val_set BORROWED and must outlive the vote set, as the
 *        reference's `*ValidatorSet` is shared.
 * @param out receives the new set; the caller frees it with
 *        `cmt_vote_set_free`.
 * @return CMT_OK;
 *         CMT_REJECT where the reference panics on `height == 0` (:82-84)
 *           — the height can arrive from a stored commit
 *           (`Commit.ToVoteSet`, state.go:638), so it is data, not an
 *           internal invariant — and for a chain id or a validator count
 *           that does not fit;
 *         CMT_FAULT on NULL, or on allocation failure.
 */
int cmt_vote_set_new(const uint8_t *chain_id, size_t chain_id_len,
                     int64_t height, int32_t round, int32_t signed_msg_type,
                     cmt_validator_set_t *val_set, cmt_vote_set_t **out);

/** cometbft@709fd12b types/vote_set.go:100-108 — `NewExtendedVoteSet()`.
 *  NewVoteSet with `extensionsEnabled = true`, which makes every added
 *  vote's EXTENSION signature be checked too (:217-220). */
int cmt_new_extended_vote_set(const uint8_t *chain_id, size_t chain_id_len,
                              int64_t height, int32_t round,
                              int32_t signed_msg_type,
                              cmt_validator_set_t *val_set,
                              cmt_vote_set_t **out);

/** C only — releases everything `cmt_vote_set_new` allocated, including
 *  every vote object the set copied in. The validator set is BORROWED and
 *  is not touched. A NULL argument is a no-op, like `free(NULL)`. */
void cmt_vote_set_free(cmt_vote_set_t *vs);

/* ── accessors (vote_set.go:110-144) ────────────────────────────────── */

/** cometbft@709fd12b types/vote_set.go:110-112 — `ChainID()`.
 *  @param out_len receives the length; may be NULL. */
const uint8_t *cmt_vote_set_chain_id(const cmt_vote_set_t *vs,
                                     size_t *out_len);

/** cometbft@709fd12b types/vote_set.go:114-120 — `GetHeight()`.
 *  A NULL set answers 0 (:116-118). */
int64_t cmt_vote_set_get_height(const cmt_vote_set_t *vs);

/** cometbft@709fd12b types/vote_set.go:122-128 — `GetRound()`.
 *  A NULL set answers -1 (:124-126). */
int32_t cmt_vote_set_get_round(const cmt_vote_set_t *vs);

/** cometbft@709fd12b types/vote_set.go:130-136 — `Type()`.
 *  A NULL set answers 0x00 (:132-134). */
uint8_t cmt_vote_set_type(const cmt_vote_set_t *vs);

/** cometbft@709fd12b types/vote_set.go:138-144 — `Size()`.
 *  A NULL set answers 0 (:140-142); otherwise `valSet.Size()`. */
int cmt_vote_set_size(const cmt_vote_set_t *vs);

/* ── adding votes (vote_set.go:146-332) ─────────────────────────────── */

/**
 * cometbft@709fd12b types/vote_set.go:146-165 — `AddVote()`, which is
 * `addVote` (:167-242) under the dropped mutex.
 *
 * ⚠ THE TWO OUTPUTS ARE INDEPENDENT, exactly as the reference's
 * `(added bool, err error)` are. The reference's own test asserts
 * `added == true` together with a non-nil error (vote_set_test.go:314-320,
 * the peerMaj23 path that returns `true, conflicting` at :326), and
 * asserts `added == false` with a nil error for a duplicate (:211). So:
 *   · CMT_OK  + *added == true   → stored;
 *   · CMT_OK  + *added == false  → duplicate (:210-211), nothing to do;
 *   · CMT_REJECT + *added == true  → stored AND conflicting (:236 with
 *     :326) — the evidence case;
 *   · CMT_REJECT + *added == false → refused, `*out_err` says why.
 *
 * The vote is COPIED into storage the set owns; see the header's
 * substitution 2 for what that does and does not copy.
 *
 * @param out_added receives the reference's `added`; may be NULL.
 * @param out_err receives the reference's error as an enum; may be NULL.
 * @param out_conflicting receives a COPY of the OTHER vote when
 *        `*out_err` is CMT_VOTE_SET_ERR_CONFLICTING_VOTES — the
 *        `NewConflictingVoteError(conflicting, vote)` payload of :236,
 *        whose `VoteA` is the conflicting vote already in the set and
 *        whose `VoteB` is the caller's own `vote`, already in hand. May
 *        be NULL. A copy rather than the reference's pointer, so that the
 *        caller is not holding a pointer into the set's storage.
 * @return CMT_OK, CMT_REJECT (see `*out_err`), CMT_FAULT on NULL, on an
 *         allocation failure, or where an internal invariant the wire
 *         cannot reach is violated (:239).
 */
int cmt_vote_set_add_vote(cmt_vote_set_t *vs, const cmt_vote_t *vote,
                          bool *out_added, cmt_vote_set_err_t *out_err,
                          cmt_vote_t *out_conflicting);

/**
 * cometbft@709fd12b types/vote_set.go:329-367 — `SetPeerMaj23()`.
 * A peer claiming +2/3 for a block makes the set TRACK that block, which
 * is the only way a conflicting vote is ever stored (:285-288).
 * @param out_err may be NULL.
 * @return CMT_OK — including the "nothing to do" cases of :345-347 and
 *           :356-358;
 *         CMT_REJECT with CMT_VOTE_SET_ERR_PEER_MAJ23_CONFLICT (:348) or
 *           one of the two C-only capacity errors;
 *         CMT_FAULT on NULL or allocation failure.
 */
int cmt_vote_set_set_peer_maj23(cmt_vote_set_t *vs, cmt_peer_id_t peer,
                                const cmt_block_id_t *block_id,
                                cmt_vote_set_err_t *out_err);

/* ── reading the set (vote_set.go:369-482) ──────────────────────────── */

/** cometbft@709fd12b types/vote_set.go:369-377 — `BitArray()`. A COPY.
 *  @return CMT_OK, CMT_BITS_NIL for a NULL set (:371-373) — positive, and
 *          `*out` is left zeroed, which behaves as the reference's nil
 *          BitArray does. CMT_FAULT on a NULL `out`. */
int cmt_vote_set_bit_array(cmt_vote_set_t *vs, cmt_bit_array_t *out);

/** cometbft@709fd12b types/vote_set.go:379-390 — `BitArrayByBlockID()`.
 *  @return CMT_OK, CMT_BITS_NIL for a NULL set (:380-382) or a block this
 *          set does not track (:389), CMT_REJECT if the BlockID's key does
 *          not fit, CMT_FAULT on NULL. */
int cmt_vote_set_bit_array_by_block_id(cmt_vote_set_t *vs,
                                       const cmt_block_id_t *block_id,
                                       cmt_bit_array_t *out);

/**
 * cometbft@709fd12b types/vote_set.go:392-401 — `GetByIndex()`.
 * The "canonical" vote of that validator when it has conflicting ones.
 * @param out receives a BORROWED pointer, NULL where the reference
 *        returns nil (no vote from that validator, or a NULL set
 *        :395-397). The pointer is valid until `cmt_vote_set_free`.
 * @return CMT_OK; CMT_REJECT where Go's `voteSet.votes[valIndex]` (:400)
 *         would panic on an out-of-range index — the index reaches this
 *         function from a peer's message through the reactor, so the
 *         message boundary refuses it (INVARIANT atlas-dec-7495d337…);
 *         CMT_FAULT on a NULL `out`.
 */
int cmt_vote_set_get_by_index(cmt_vote_set_t *vs, int32_t val_index,
                              const cmt_vote_t **out);

/**
 * cometbft@709fd12b types/vote_set.go:403-415 — `List()`.
 * A copy of every vote the set holds, in validator-index order, with the
 * gaps skipped — so `*out_len` is the number of validators that voted,
 * not the size of the set.
 * ⚠ Each element is ~9.5 KB; for N = 128 the output is ~1.2 MB. Heap.
 * @return CMT_OK; CMT_REJECT when `cap` cannot hold them; CMT_FAULT on a
 *         NULL `out_len`, or a NULL `out` with a non-zero `cap`. A NULL
 *         set yields `*out_len == 0` (the reference's nil slice, :405).
 */
int cmt_vote_set_list(cmt_vote_set_t *vs, cmt_vote_t *out, size_t cap,
                      size_t *out_len);

/**
 * cometbft@709fd12b types/vote_set.go:417-428 — `GetByAddress()`.
 * @param out receives a BORROWED pointer, NULL where the validator has
 *        not voted.
 * @return CMT_OK; CMT_REJECT where the reference panics at :425 because
 *         the address is not in the validator set. JUDGMENT, stated: the
 *         address is a CALLER ARGUMENT rather than internal state, and
 *         the pinned tree contains no non-test caller of
 *         `VoteSet.GetByAddress` (every non-test `.GetByAddress(` site —
 *         e.g. state/state.go:277, consensus/state.go:1876,
 *         types/validation.go:250 — is on a ValidatorSet; verifier A
 *         counted 20+, all of that kind), so there is no internal
 *         contract to declare violated — refusing is the honest answer.
 *         CMT_FAULT on a NULL `out` or set.
 */
int cmt_vote_set_get_by_address(cmt_vote_set_t *vs, const uint8_t *address,
                                size_t address_len, const cmt_vote_t **out);

/** cometbft@709fd12b types/vote_set.go:430-437 — `HasTwoThirdsMajority()`.
 *  A NULL set answers false (:431-433). */
bool cmt_vote_set_has_two_thirds_majority(const cmt_vote_set_t *vs);

/** cometbft@709fd12b types/vote_set.go:439-450 — `IsCommit()`.
 *  A precommit set with a majority; a prevote set is never a commit
 *  (:444-446). */
bool cmt_vote_set_is_commit(const cmt_vote_set_t *vs);

/** cometbft@709fd12b types/vote_set.go:452-459 — `HasTwoThirdsAny()`.
 *  `sum > TotalVotingPower*2/3`, whatever the votes were for.
 *  @param out receives the answer; false for a NULL set (:453-455).
 *  @return CMT_OK, CMT_FAULT on a NULL `out` or a failing power sum. */
int cmt_vote_set_has_two_thirds_any(cmt_vote_set_t *vs, bool *out);

/** cometbft@709fd12b types/vote_set.go:461-468 — `HasAll()`.
 *  `sum == TotalVotingPower`.
 *  @return CMT_OK, CMT_FAULT on a NULL `out` or a failing power sum. */
int cmt_vote_set_has_all(cmt_vote_set_t *vs, bool *out);

/**
 * cometbft@709fd12b types/vote_set.go:470-482 — `TwoThirdsMajority()`.
 * @param out_block_id receives `*maj23` when there is one, and the ZERO
 *        BlockID otherwise (:474, :481) — the reference writes
 *        `BlockID{}`, so `out_block_id` is always written.
 * @param out_ok receives the reference's second return value.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_vote_set_two_thirds_majority(const cmt_vote_set_t *vs,
                                     cmt_block_id_t *out_block_id,
                                     bool *out_ok);

/* ── making a commit (vote_set.go:627-671) ──────────────────────────── */

/**
 * cometbft@709fd12b types/vote_set.go:630-671 — `MakeExtendedCommit()`.
 *
 * One ExtendedCommitSig per VALIDATOR INDEX, in index order (:649-658) —
 * that order is what makes a commit's hash deterministic (D-19 rev 6
 * item 4). A validator that did not vote gives an ABSENT entry through
 * `cmt_vote_extended_commit_sig(NULL, …)` (vote.go:129-131), and one
 * whose vote was for a DIFFERENT block is replaced by an ABSENT entry
 * (:653-655).
 *
 * @param sigs caller storage for `cmt_vote_set_size(vs)` entries; each is
 *        ~4.7 KB, so this is heap in any realistic set.
 * @param out receives the commit, pointing at `sigs`.
 * @return CMT_OK;
 *         CMT_REJECT when `sigs_cap` is too small;
 *         CMT_FAULT where the reference panics at :639-641 (not a
 *           precommit set), :644-646 (no +2/3 for any block) and
 *           :666-669 (the extension data of the commit we just built is
 *           inconsistent) — all three are contracts between this function
 *           and the consensus state machine that calls it, unreachable
 *           from the wire; and CMT_FAULT on NULL.
 */
int cmt_vote_set_make_extended_commit(cmt_vote_set_t *vs,
                                      cmt_abci_params_t ap,
                                      cmt_extended_commit_sig_t *sigs,
                                      size_t sigs_cap,
                                      cmt_extended_commit_t *out);

/* ── rebuilding a vote set from a commit (block.go:1071-1117) ───────── */

/**
 * cometbft@709fd12b types/block.go:1098-1117 — `(commit *Commit)
 * ToVoteSet()`. Lives here, not in cmt_block.h; see the file header.
 *
 * The inverse of MakeExtendedCommit: every non-ABSENT entry becomes a
 * precommit that is validated (:1108) and added (:1111). The reference
 * PANICS if either step fails (:1109, :1113) — this is called on a commit
 * the node already stored and already verified (state.go:626-643
 * `votesFromSeenCommit`), so a failure means the local store disagrees
 * with itself. That is CMT_FAULT, not a verdict on a message.
 *
 * ⚠ The added votes' signatures are VERIFIED, because AddVote verifies
 * (:222). A commit whose signatures do not verify against `vals` is
 * therefore a CMT_FAULT here, exactly as it is a panic in the reference.
 *
 * @param out receives a new set the caller must free.
 * @return CMT_OK; CMT_REJECT from `cmt_vote_set_new` (height 0, chain id
 *         or validator count out of range); CMT_FAULT otherwise.
 */
int cmt_commit_to_vote_set(const cmt_commit_t *commit,
                           const uint8_t *chain_id, size_t chain_id_len,
                           cmt_validator_set_t *vals, cmt_vote_set_t **out);

/**
 * cometbft@709fd12b types/block.go:1071-1079 — `(ec *ExtendedCommit)
 * ToExtendedVoteSet()`, with `addSigsToVoteSet` (:1081-1096) inlined as a
 * file-local static. Lives here; see the file header.
 *
 * The same shape as `cmt_commit_to_vote_set` over an EXTENDED commit, so
 * every added vote's extension signature is verified too (:1076 builds an
 * extended set). Called by `state.go:610-624 votesFromExtendedCommit`.
 * @return as `cmt_commit_to_vote_set`.
 */
int cmt_extended_commit_to_extended_vote_set(const cmt_extended_commit_t *ec,
                                             const uint8_t *chain_id,
                                             size_t chain_id_len,
                                             cmt_validator_set_t *vals,
                                             cmt_vote_set_t **out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_VOTE_SET_H */
