/**
 * @file shared/dnac/cmt_msgs.h
 * @brief cometbft @709fd12b `consensus/msgs.go` and the nine reactor
 *        message types of `consensus/reactor.go:1527-1800`, in C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain calls anything here yet; additive only. The live witness BFT and
 * the QC V2 path are untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * This file is the KODEK half of the consensus package: the conversion
 * between the reactor's Go message types and the proto3 messages cmt_pb
 * puts on the wire. `MsgToProto` / `MsgFromProto` are the peer wire;
 * `WALToProto` / `WALFromProto` (cmt_wal.h) are the crash-recovery record,
 * and they call these.
 *
 * ── WHAT IS HERE AND WHAT IS NOT ───────────────────────────────────────
 * HERE: the nine message STRUCTS (fields only) and the four conversions
 * `cmt_msg_to_proto` (msgs.go:21-118) and `cmt_msg_from_proto`
 * (msgs.go:121-237).
 *
 * NOT HERE — the `ValidateBasic()` methods of reactor.go:1536, :1596,
 * :1634, :1653, :1684, :1710, :1730, :1762, :1795 and
 * `NewRoundStepMessage.ValidateHeight` (:1560). They belong to the reactor
 * and are wave R3's.
 *
 * ⚠ CONSEQUENCE, AND IT IS NOT A DETAIL: `MsgFromProto` ENDS in
 * `pb.ValidateBasic()` (msgs.go:232-234) and returns its error. This port
 * stops one step short of that line. `cmt_msg_from_proto` therefore
 * accepts messages the reference would refuse — a negative height, an
 * invalid Step, an empty ProposalPOL bit array, a malformed BlockID — and
 * every caller MUST run the R3 ValidateBasic before acting on one. The
 * same gap reaches `cmt_wal_from_proto`, whose MsgInfo branch
 * (msgs.go:316) goes through this function.
 *
 * ── THE STEP FIELD ─────────────────────────────────────────────────────
 * `NewRoundStepMessage.Step` is a `cstypes.RoundStepType`, which is a
 * `uint8` (consensus/types/round_state.go:16). It is carried here as a
 * `uint8_t` and its named constants are NOT defined: round_state.go is
 * wave R2-C's file, and inventing the enum here would put two definitions
 * of the same eight values in the tree. On the wire the field is a
 * `uint32` (consensus/types.proto:15), and the narrowing back to uint8 is
 * the reference's own `cmtmath.SafeConvertUint8` at msgs.go:129, ported as
 * `cmt_safe_convert_uint8`.
 *
 * ── SUBSTITUTIONS ──────────────────────────────────────────────────────
 * Only the approved ones (umbrella rev 3): 64-byte hashes, ML-DSA-87
 * sizes, a 32-byte address, a 32-byte chain id, and Go's implicit bounds
 * checks written out. Go panics become CMT_REJECT where a peer's bytes can
 * reach them and CMT_FAULT where they guard this node's own consistency;
 * each site says which.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Every function is a pure function of its arguments. No clock, no
 * allocation, no global state, no iteration over anything unordered.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/msgs.go     347 lines
 *                         7acb318c8910da0c0f4d874b9bd6bb4fdc7212736919939fc933dd405b8e4ada
 *   consensus/reactor.go 1817 lines
 *                         b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *                         (only :1503-1810, the message definitions)
 *   consensus/state.go   2653 lines
 *                         f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *                         (only :45-59, msgInfo and timeoutInfo)
 *   proto/tendermint/consensus/types.proto, message.go — see cmt_pb.h.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * K-1 rev 2 (atlas-dec-3ba8153088b0d60c63083028023b61be),
 * INVARIANT (atlas-dec-7495d3372e004b24b4f6cc7bff5caf07),
 * D-16 rev 4 (atlas-dec-0c86593601db977cd5af648b78910004).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_MSGS_H
#define SHARED_DNAC_CMT_MSGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_pb.h"
#include "cmt_bits.h"
#include "cmt_block.h"       /* cmt_block_id_t                          */
#include "cmt_part_set.h"    /* cmt_part_t, cmt_part_set_header_t       */
#include "cmt_proposal.h"    /* cmt_proposal_t                          */
#include "cmt_vote.h"        /* cmt_vote_t                              */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ the nine reactor messages ════════════════════════════════════════ */

/** cometbft@709fd12b consensus/reactor.go:1527-1533 —
 *  `type NewRoundStepMessage struct`. */
typedef struct {
    int64_t height;                   /* reactor.go:1528 */
    int32_t round;                    /* :1529           */
    uint8_t step;                     /* :1530 RoundStepType (uint8) */
    int64_t seconds_since_start_time; /* :1531           */
    int32_t last_commit_round;        /* :1532           */
} cmt_new_round_step_msg_t;

/**
 * cometbft@709fd12b consensus/reactor.go:1587-1593 —
 * `type NewValidBlockMessage struct`.
 *
 * `BlockParts` is a `*bits.BitArray` (:1591); `has_block_parts` is that
 * pointer's presence.
 */
typedef struct {
    int64_t               height;                /* :1588 */
    int32_t               round;                 /* :1589 */
    cmt_part_set_header_t block_part_set_header; /* :1590 */
    bool                  has_block_parts;       /* :1591 pointer */
    cmt_bit_array_t       block_parts;
    bool                  is_commit;             /* :1592 */
} cmt_new_valid_block_msg_t;

/**
 * cometbft@709fd12b consensus/reactor.go:1629-1631 —
 * `type ProposalMessage struct`.
 *
 * The Go field is a `*types.Proposal`. It is held BY VALUE here, as wave
 * R1-C held `State.Proposer` by value (R1C-6,
 * atlas-dec-9285f4a5c9679f00a4d042a15acf45e4): the reference's own code
 * dereferences it unconditionally at msgs.go:49 and reactor.go:1635, so a
 * nil pointer is a panic there and not a state this type can be in.
 */
typedef struct {
    cmt_proposal_t proposal;   /* :1630 */
} cmt_proposal_msg_t;

/**
 * cometbft@709fd12b consensus/reactor.go:1646-1650 —
 * `type ProposalPOLMessage struct`. `ProposalPOL` is a `*bits.BitArray`.
 */
typedef struct {
    int64_t         height;              /* :1647 */
    int32_t         proposal_pol_round;  /* :1648 */
    bool            has_proposal_pol;    /* :1649 pointer */
    cmt_bit_array_t proposal_pol;
} cmt_proposal_pol_msg_t;

/** cometbft@709fd12b consensus/reactor.go:1677-1681 —
 *  `type BlockPartMessage struct`. `Part` is a `*types.Part`, held by
 *  value for the same reason `ProposalMessage.Proposal` is. */
typedef struct {
    int64_t    height;   /* :1678 */
    int32_t    round;    /* :1679 */
    cmt_part_t part;     /* :1680 */
} cmt_block_part_msg_t;

/**
 * cometbft@709fd12b consensus/reactor.go:1705-1707 —
 * `type VoteMessage struct`. `Vote` is a `*types.Vote` and its nil IS
 * reachable: `Vote.ToProto()` returns nil for a nil receiver
 * (types/vote.go:374-376) and msgs.go:74-77 stores that nil in a POINTER
 * proto field, which is then simply omitted. `has_vote` is that pointer.
 */
typedef struct {
    bool       has_vote;   /* :1706 pointer */
    cmt_vote_t vote;
} cmt_vote_msg_t;

/** cometbft@709fd12b consensus/reactor.go:1722-1727 —
 *  `type HasVoteMessage struct`. */
typedef struct {
    int64_t height;   /* :1723 */
    int32_t round;    /* :1724 */
    int32_t type;     /* :1725 cmtproto.SignedMsgType */
    int32_t index;    /* :1726 */
} cmt_has_vote_msg_t;

/** cometbft@709fd12b consensus/reactor.go:1754-1759 —
 *  `type VoteSetMaj23Message struct`. */
typedef struct {
    int64_t          height;    /* :1755 */
    int32_t          round;     /* :1756 */
    int32_t          type;      /* :1757 */
    cmt_block_id_t   block_id;  /* :1758 */
} cmt_vote_set_maj23_msg_t;

/** cometbft@709fd12b consensus/reactor.go:1786-1792 —
 *  `type VoteSetBitsMessage struct`. `Votes` is a `*bits.BitArray`. */
typedef struct {
    int64_t         height;     /* :1787 */
    int32_t         round;      /* :1788 */
    int32_t         type;       /* :1789 */
    cmt_block_id_t  block_id;   /* :1790 */
    bool            has_votes;  /* :1791 pointer */
    cmt_bit_array_t votes;
} cmt_vote_set_bits_msg_t;

/**
 * cometbft@709fd12b consensus/reactor.go:1507-1509 — `type Message
 * interface`, as a tagged union.
 *
 * THE TAG IS THE ONEOF FIELD NUMBER. `cmt_pb_cons_msg_kind_t` already
 * names the nine branches of consensus/types.proto's `Message`, and
 * MsgToProto / MsgFromProto are a bijection between the Go types and those
 * branches (msgs.go:27-115 against :127-230), so a second enum would be
 * two names for one thing. CMT_PB_CONS_MSG_NONE is the reference's nil
 * interface value, which `MsgToProto` refuses at :22-24.
 *
 * ⚠ LARGE — the vote branch alone carries two 4627-byte signatures and the
 * block-part branch a 100-aunt proof. Heap-allocate it; never a stack
 * local in a deep call.
 */
typedef cmt_pb_cons_msg_kind_t cmt_msg_kind_t;

typedef struct {
    cmt_msg_kind_t kind;
    union {
        cmt_new_round_step_msg_t  new_round_step;   /* 1 */
        cmt_new_valid_block_msg_t new_valid_block;  /* 2 */
        cmt_proposal_msg_t        proposal;         /* 3 */
        cmt_proposal_pol_msg_t    proposal_pol;     /* 4 */
        cmt_block_part_msg_t      block_part;       /* 5 */
        cmt_vote_msg_t            vote;             /* 6 */
        cmt_has_vote_msg_t        has_vote;         /* 7 */
        cmt_vote_set_maj23_msg_t  vote_set_maj23;   /* 8 */
        cmt_vote_set_bits_msg_t   vote_set_bits;    /* 9 */
    } u;
} cmt_msg_t;

/* ══ the two WAL payload types that are declared with the state ═══════ */

/**
 * cometbft@709fd12b consensus/state.go:48-51 — `type msgInfo struct`.
 *
 * WHY IT LIVES HERE and not in cmt_wal.h: state.go declares `msgInfo` and
 * `timeoutInfo` together at :47-58, one block, and `msgInfo.Msg` is the
 * `Message` interface this file defines. Splitting the pair would put two
 * halves of one Go declaration in two headers and would make cmt_wal.h
 * include this one anyway.
 *
 * PEER ID SUBSTITUTION (port map REV 3.4 item 7, deviation register R2-2):
 * the reference's `p2p.ID` is a hex string; a DNA peer identity is the
 * 32-byte witness id. `peer_id_len` is 0 for the node's OWN messages,
 * which is the reference's `PeerID: ""` (state.go:839), and 32 otherwise.
 * Nothing between those two lengths is accepted anywhere.
 */
typedef struct {
    cmt_msg_t msg;                              /* state.go:49 */
    uint8_t   peer_id[CMT_PB_PEER_ID_MAX];      /* :50         */
    size_t    peer_id_len;
} cmt_msg_info_t;

/**
 * cometbft@709fd12b consensus/state.go:54-59 — `type timeoutInfo struct`.
 * `Duration` is a `time.Duration`, i.e. a NANOSECOND count; `Step` is a
 * `cstypes.RoundStepType` (uint8).
 */
typedef struct {
    int64_t duration;   /* state.go:55, nanoseconds */
    int64_t height;     /* :56                      */
    int32_t round;      /* :57                      */
    uint8_t step;       /* :58 RoundStepType        */
} cmt_timeout_info_t;

/* ══ msgs.go ══════════════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/msgs.go:21-118 — `MsgToProto()`.
 *
 * The nine cases in the reference's order. The `default` of :113-114
 * ("message not recognized") is CMT_REJECT, and so is the nil message of
 * :22-24.
 *
 * TWO SITES WHERE THE REFERENCE NIL-DEREFERENCES, both named here because
 * a literal translation must decide something:
 *   · :59 `ProposalPol: *pbBits` — `BitArray.ToProto()` returns nil for a
 *     nil array OR one with no words (libs/bits/bit_array.go:476-478), and
 *     the reference dereferences it with no check. This port returns
 *     CMT_FAULT there: a ProposalPOL is built from THIS node's own vote
 *     set, so an empty one is a local inconsistency, not a peer's bytes.
 *     (The reference's own ValidateBasic refuses it too, reactor.go:1660.)
 *   · :107-109 VoteSetBits guards the same call and leaves a ZERO BitArray
 *     when it is nil — which is still emitted, because field 5 is
 *     `(nullable) = false`. Ported exactly, with no FAULT.
 *
 * @param msg the message; `kind` outside 1-9 is the unrecognised case.
 * @param out receives the wire message; its branch is initialised here.
 * @return CMT_OK, CMT_REJECT (:22-24, :113-114, or a field that will not
 *         convert), CMT_FAULT (NULL, or the :59 site above).
 */
int cmt_msg_to_proto(const cmt_msg_t *msg, cmt_pb_cons_message_t *out);

/**
 * cometbft@709fd12b consensus/msgs.go:121-237 — `MsgFromProto()`.
 *
 * The nine cases in the reference's order, each with the conversion the
 * reference performs — `SafeConvertUint8` on Step (:129-133),
 * `PartSetHeaderFromProto` (:142), `BitArray.FromProto` (:148, :168,
 * :219), `ProposalFromProto` (:158), `PartFromProto` (:175),
 * `VoteFromProto` (:187) and `BlockIDFromProto` (:203, :214), several of
 * which validate on their own account.
 *
 * ⚠ STOPS SHORT OF :232-234 — see the file header. ValidateBasic is R3's.
 *
 * @param p the wire message; `sum` of NONE is the reference's nil
 *        (:122-124) and any other unknown branch its default (:228-229).
 * @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL.
 */
int cmt_msg_from_proto(const cmt_pb_cons_message_t *p, cmt_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_MSGS_H */
