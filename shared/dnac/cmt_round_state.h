/**
 * @file shared/dnac/cmt_round_state.h
 * @brief cometbft @709fd12b `consensus/types/round_state.go` ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-A of the cometbft → C consensus port. Additive only; nothing in
 * the running chain reads or writes a `cmt_round_state_t` yet.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The consensus state machine's variables: where we are (height, round,
 * step), what was proposed, what we locked, what is valid, and every vote
 * of this height and the last. The reference's own note at :65-66 — "Not
 * thread safe. Should only be manipulated by functions downstream of the
 * cs.receiveRoutine" — is the whole concurrency model, and this port's
 * single-threaded event loop is that model made explicit.
 *
 * HEADER ONLY. Every function here is a `static inline` of at most a
 * dozen lines; there is no cmt_round_state.c because there is nothing
 * that needs one.
 *
 * ── WHY RoundStepType.String IS PORTED ─────────────────────────────────
 * The port carries no logging and no JSON, so a `String()` is normally
 * "taşınmadı". THIS ONE IS DIFFERENT, and it is load-bearing:
 * `RoundStateEvent()` (:174-180) puts `rs.Step.String()` into
 * `EventDataRoundState.Step`, which is a STRING field
 * (types/events.go:93-97) whose own comment says "NOTE: This goes into
 * the replay WAL". On replay, `readReplayMessage`
 * (consensus/replay.go:39-90) reads the recorded event back and compares
 * it against the live one field by field:
 *   replay.go:54-57 — `m2 := stepMsg.Data().(types.EventDataRoundState)`
 *                     `if m.Height != m2.Height || m.Round != m2.Round ||
 *                      m.Step != m2.Step { return fmt.Errorf(...) }`
 * So `m.Step` — the string — decides whether a WAL replay is accepted.
 * A different spelling here is a node that cannot replay its own WAL.
 * The eight strings below are byte-for-byte the reference's (:41-56),
 * including the default "RoundStepUnknown" (:58), whose comment "Cannot
 * panic" is the reference's own.
 *
 * ── BLOCK AND PART-SET OWNERSHIP (port map REV 3.4 item 4) ─────────────
 * `ProposalBlock`, `LockedBlock` and `ValidBlock` are POINTERS, as in the
 * reference, and so are their three part sets. In Go they point at
 * garbage-collected objects and two names may alias the same block —
 * `cs.LockedBlock = cs.ProposalBlock` is an ordinary assignment. Here the
 * storage BELONGS TO THE HOST: three block slots and three part-set slots
 * that the host owns, with the rule that A SLOT IS REWRITTEN ONLY WHEN NO
 * NAME POINTS AT IT. Nothing in this header allocates a block, a part set
 * or a validator set, and nothing here frees one.
 *
 * `Votes` (*HeightVoteSet) and `LastCommit` (*VoteSet) are likewise
 * pointers to objects the host created with `cmt_new_height_vote_set` /
 * `cmt_commit_to_vote_set` and must free.
 *
 * ── EventDataRoundState IS NOT DEFINED HERE ────────────────────────────
 * The C struct for `types.EventDataRoundState` belongs to the wire/proto
 * layer and is executor R2-B's (cmt_pb). `cmt_round_state_event` below
 * therefore hands out the three values by pointer and lets that layer
 * assemble them, so the two waves cannot define the same struct twice.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * Nothing here reads a clock: `start_time` and `commit_time` are VALUES
 * the host writes (the clock POLICY atlas-dec-4ac0423068085c100fdfa3e264ca16bc
 * allows a clock read only where the reference has one, and the reference
 * has none in this file). Nothing here allocates, iterates a map, or
 * draws randomness. `cmt_round_step_string` is a pure switch.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `RoundStateSimple` (:106-114) and `(rs *RoundState)
 *     RoundStateSimple()` (:116-138) — the RPC projection; the port has
 *     no RPC layer, and it is built out of MarshalJSON, which is not
 *     ported either.
 *   · `NewRoundEvent` (:140-154) and `CompleteProposalEvent` (:156-171) —
 *     the event bus. The port carries no eventBus, no evsw and no
 *     metrics (port map REV 3.4 item 2). `RoundStateEvent` (:173-180) is
 *     the ONE exception and it is ported, because the WAL replay check
 *     above depends on it.
 *   · `String` (:182-185), `StringIndented` (:187-218), `StringShort`
 *     (:220-224) — display only.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/types/round_state.go  224 lines
 *     44404a9f7c8125449edc3756c50c5f7575a9de45db6fb2b568ead80ac3e8c354
 *   types/events.go                 188 lines
 *     13d8f653492d87fb90d1512ed0495d7d178839b371884e785b2620c29aae3cd5
 *     (read for :93-97, EventDataRoundState's three fields)
 *   consensus/replay.go             565 lines
 *     5609c4d4174a536389cb2814bac09557a66e3299292141b54c635e31425284fe
 *     (read for :39-90, what a replay compares)
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc),
 * pin record rev 5 (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_ROUND_STATE_H
#define SHARED_DNAC_CMT_ROUND_STATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_time.h"
#include "cmt_block.h"          /* cmt_block_t                              */
#include "cmt_part_set.h"       /* cmt_part_set_t                           */
#include "cmt_proposal.h"       /* cmt_proposal_t                           */
#include "cmt_validator_set.h"  /* cmt_validator_set_t                      */
#include "cmt_vote_set.h"       /* cmt_vote_set_t                           */
#include "cmt_hvs.h"            /* cmt_hvs_t                                */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ RoundStepType (round_state.go:12-60) ═════════════════════════════ */

/** cometbft@709fd12b consensus/types/round_state.go:15-16 —
 *  `type RoundStepType uint8`, with the reference's own note: "These must
 *  be numeric, ordered." */
typedef uint8_t cmt_round_step_t;

/** cometbft@709fd12b consensus/types/round_state.go:18-31 — the eight
 *  steps, with the reference's comments. */
enum {
    /** :20 Wait til CommitTime + timeoutCommit */
    CMT_ROUND_STEP_NEW_HEIGHT     = 0x01,
    /** :21 Setup new round and go to RoundStepPropose */
    CMT_ROUND_STEP_NEW_ROUND      = 0x02,
    /** :22 Did propose, gossip proposal */
    CMT_ROUND_STEP_PROPOSE        = 0x03,
    /** :23 Did prevote, gossip prevotes */
    CMT_ROUND_STEP_PREVOTE        = 0x04,
    /** :24 Did receive any +2/3 prevotes, start timeout */
    CMT_ROUND_STEP_PREVOTE_WAIT   = 0x05,
    /** :25 Did precommit, gossip precommits */
    CMT_ROUND_STEP_PRECOMMIT      = 0x06,
    /** :26 Did receive any +2/3 precommits, start timeout */
    CMT_ROUND_STEP_PRECOMMIT_WAIT = 0x07,
    /** :27 Entered commit state machine */
    CMT_ROUND_STEP_COMMIT         = 0x08
    /* :28 NOTE: RoundStepNewHeight acts as RoundStepCommitWait.
     * :30 NOTE: Update IsValid method if you change this! */
};

/** cometbft@709fd12b consensus/types/round_state.go:33-36 — `IsValid()`.
 *  The reference writes `uint8(rs) >= 0x01 && uint8(rs) <= 0x08`; the
 *  `>= 0x01` half is not vacuous only because the type is unsigned in
 *  both languages, so 0 is the one value it excludes from below. */
static inline bool cmt_round_step_is_valid(cmt_round_step_t rs)
{
    return rs >= 0x01 && rs <= 0x08;                             /* :35 */
}

/**
 * cometbft@709fd12b consensus/types/round_state.go:38-60 — `String()`.
 *
 * PORTED, and the eight strings are byte-for-byte the reference's:
 * `EventDataRoundState.Step` is this string, it goes into the WAL, and
 * `consensus/replay.go:55` compares it. See the file header.
 *
 * @return a static string, never NULL; "RoundStepUnknown" (:58) for
 *         anything outside 0x01..0x08 — the reference's default, whose
 *         own comment reads "Cannot panic."
 */
static inline const char *cmt_round_step_string(cmt_round_step_t rs)
{
    switch (rs) {
    case CMT_ROUND_STEP_NEW_HEIGHT:                              /* :41-42 */
        return "RoundStepNewHeight";
    case CMT_ROUND_STEP_NEW_ROUND:                               /* :43-44 */
        return "RoundStepNewRound";
    case CMT_ROUND_STEP_PROPOSE:                                 /* :45-46 */
        return "RoundStepPropose";
    case CMT_ROUND_STEP_PREVOTE:                                 /* :47-48 */
        return "RoundStepPrevote";
    case CMT_ROUND_STEP_PREVOTE_WAIT:                            /* :49-50 */
        return "RoundStepPrevoteWait";
    case CMT_ROUND_STEP_PRECOMMIT:                               /* :51-52 */
        return "RoundStepPrecommit";
    case CMT_ROUND_STEP_PRECOMMIT_WAIT:                          /* :53-54 */
        return "RoundStepPrecommitWait";
    case CMT_ROUND_STEP_COMMIT:                                  /* :55-56 */
        return "RoundStepCommit";
    default:                                                     /* :57-58 */
        return "RoundStepUnknown";
    }
}

/* ══ RoundState (round_state.go:62-103) ═══════════════════════════════ */

/**
 * cometbft@709fd12b consensus/types/round_state.go:64-103 —
 * `type RoundState struct`. Every field carries its reference line.
 *
 * The eleven pointer fields are BORROWED: see "BLOCK AND PART-SET
 * OWNERSHIP" in the file header. A zeroed `cmt_round_state_t` is NOT a
 * valid initial state — `start_time` and `commit_time` must be
 * CMT_TIME_ZERO, not `{0,0}` (cmt_time.h:19-25) — so initialise with
 * `cmt_round_state_init` below.
 */
typedef struct {
    int64_t              height;         /* :68 Height we are working on   */
    int32_t              round;          /* :69                            */
    cmt_round_step_t     step;           /* :70                            */
    cmt_time_t           start_time;     /* :71                            */

    /* :73 Subjective time when +2/3 precommits for Block at Round were
     * found. A VALUE the host writes; nothing here reads a clock. */
    cmt_time_t           commit_time;    /* :74                            */
    cmt_validator_set_t *validators;     /* :75                            */
    cmt_proposal_t      *proposal;       /* :76                            */
    cmt_block_t         *proposal_block; /* :77                            */
    cmt_part_set_t      *proposal_block_parts; /* :78                      */
    int32_t              locked_round;   /* :79                            */
    cmt_block_t         *locked_block;   /* :80                            */
    cmt_part_set_t      *locked_block_parts;   /* :81                      */

    /* :83-90 — the reference's own note on the "Valid..." names: they come
     * from "The latest gossip on BFT consensus" (arXiv 1807.04938) and
     * mean the block or round received 2/3+ non-nil prevotes (a polka).
     * They have NOTHING to do with the application's ProcessProposal
     * verdict. */

    int32_t              valid_round;    /* :93 last round with a POL      */
    cmt_block_t         *valid_block;    /* :94 the block of that POL      */
    cmt_part_set_t      *valid_block_parts;    /* :97                      */
    cmt_hvs_t           *votes;          /* :98                            */
    int32_t              commit_round;   /* :99                            */
    cmt_vote_set_t      *last_commit;    /* :100 last precommits at H-1    */
    cmt_validator_set_t *last_validators;/* :101                           */
    bool                 triggered_timeout_precommit; /* :102              */
} cmt_round_state_t;

/**
 * C only — the zero value of a `RoundState` as Go would build it.
 *
 * Go's `RoundState{}` gives every numeric field 0, every pointer nil and
 * every `time.Time` its own zero, which is NOT an all-zero struct here:
 * cmt_time.h:19-25 warns that `{0, 0}` is the Unix epoch and Go's zero
 * time is CMT_TIME_ZERO. memset alone would therefore build a round state
 * whose two timestamps are 1970 rather than year 1.
 */
static inline void cmt_round_state_init(cmt_round_state_t *rs)
{
    if (rs == NULL) {
        return;
    }
    rs->height                      = 0;
    rs->round                       = 0;
    rs->step                        = 0u;
    rs->start_time                  = CMT_TIME_ZERO;
    rs->commit_time                 = CMT_TIME_ZERO;
    rs->validators                  = NULL;
    rs->proposal                    = NULL;
    rs->proposal_block              = NULL;
    rs->proposal_block_parts        = NULL;
    rs->locked_round                = 0;
    rs->locked_block                = NULL;
    rs->locked_block_parts          = NULL;
    rs->valid_round                 = 0;
    rs->valid_block                 = NULL;
    rs->valid_block_parts           = NULL;
    rs->votes                       = NULL;
    rs->commit_round                = 0;
    rs->last_commit                 = NULL;
    rs->last_validators             = NULL;
    rs->triggered_timeout_precommit = false;
}

/**
 * cometbft@709fd12b consensus/types/round_state.go:173-180 —
 * `(rs *RoundState) RoundStateEvent()`.
 *
 * The reference returns a `types.EventDataRoundState` (events.go:93-97).
 * That C struct is executor R2-B's, in cmt_pb, so this hands out the
 * three fields instead and R2-B/R2-C assemble the message. The values are
 * the reference's exactly: Height (:176), Round (:177) and
 * `Step.String()` (:178) — the STRING, which is what the WAL stores and
 * what replay.go:55 compares.
 *
 * @param out_height, @param out_round, @param out_step each may be NULL.
 *        `*out_step` is a static string owned by this module; it is never
 *        NULL and must not be freed.
 * @return CMT_OK, CMT_FAULT on a NULL `rs`.
 */
static inline int cmt_round_state_event(const cmt_round_state_t *rs,
                                        int64_t *out_height,
                                        int32_t *out_round,
                                        const char **out_step)
{
    if (rs == NULL) {
        return CMT_FAULT;
    }
    if (out_height != NULL) {
        *out_height = rs->height;                                /* :176 */
    }
    if (out_round != NULL) {
        *out_round = rs->round;                                  /* :177 */
    }
    if (out_step != NULL) {
        *out_step = cmt_round_step_string(rs->step);             /* :178 */
    }
    return CMT_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_ROUND_STATE_H */
