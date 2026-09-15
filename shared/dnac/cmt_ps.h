/**
 * @file shared/dnac/cmt_ps.h
 * @brief cometbft @709fd12b `consensus/reactor.go:1017-1482` — `PeerState`
 *        and its methods — and `consensus/types/peer_round_state.go:15-43`
 *        — `PeerRoundState` — ported to C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R3-A of the cometbft → C consensus port. The consumer is
 * `cmt_conr` (the reactor), which nothing in the running chain constructs
 * yet; additive only. The live witness BFT is untouched.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The receiver in the reference is `ps`, so every function is `cmt_ps_*`:
 * `(ps *PeerState) SetHasVote` → `cmt_ps_set_has_vote`. The round-state
 * struct keeps the reference's own abbreviation, `prs`.
 *
 * ── WHAT A PeerState IS ────────────────────────────────────────────────
 * What THIS node believes about ONE peer: its height, round and step, the
 * proposal it has, the block parts and the votes it holds — every one of
 * them learned from the peer's own NewRoundStep / NewValidBlock / HasVote
 * / ProposalPOL / VoteSetBits messages, or marked after a successful send.
 * The gossip routines of the reactor read it to decide what the peer
 * still lacks. It is APPROXIMATE and DELAYED by construction, and nothing
 * here decides a vote, a block or a state root.
 *
 * ── THE BIT ARRAYS ARE POINTERS, AND THAT IS LOAD-BEARING ──────────────
 * `PeerRoundState` holds six `*bits.BitArray` (peer_round_state.go:26,
 * :31-33, :35, :41), and the reference ALIASES them: `CatchupCommit =
 * Precommits` (reactor.go:1263), `Precommits = psCatchupCommit` (:1399),
 * `LastCommit = lastPrecommits` (:1405), and it MUTATES through the
 * pointer `getVoteBitArray` returns (:1358 SetIndex, :1474/:1478 Update).
 * A bit set on Precommits after :1263 is visible through CatchupCommit,
 * and after a same-height round change (:1391-1392 drops Precommits)
 * `getVoteBitArray` reads it back through CatchupCommit (:1208-1213).
 * Value copies would lose that and re-send votes the peer already has.
 * So the six fields are POINTERS here too, into a per-peer POOL of
 * CMT_PS_BITS_SLOTS arrays that stands in for Go's heap. THE SLOT RULE is
 * cmt_cs.h's for block slots: a slot is rewritten only while NO name
 * points at it. With six names, at most five can hold slots while the
 * sixth is being (re)assigned, so six slots always suffice; failing to
 * find one is CMT_FAULT because the derivation says it cannot happen.
 * A NULL pointer is the reference's nil BitArray; cmt_bits already gives
 * every operation its nil answer for NULL (cmt_bits.h:34-41), and a
 * constructor that returns CMT_BITS_NIL leaves the pointer NULL.
 *
 * ── THE PEER IS A DESCRIPTOR, NOT AN OBJECT ────────────────────────────
 * `PeerState.peer` (:1027) is a `p2p.Peer` whose `Send`/`TrySend`
 * (p2p/peer.go:260-268) marshal the message (:270-295, `proto.Marshal` at
 * :280) and hand bytes to the connection. Here the p2p layer is the
 * host's (umbrella substitution 9, and the PQ POLICY
 * atlas-dec-652be084b95d02d253834906271e9fb0: the reference's transport
 * security is OUT OF SCOPE; its files were read for Send/TrySend
 * semantics only), so `cmt_ps_peer_t` carries the two send rows, the
 * peer's 32-byte witness id (p2p/key.go:16 `ID` → substitution 9) and the
 * host's small peer index, plus the reactor-owned scratch the marshal
 * needs. The reactor marshals with `cmt_msg_to_proto` +
 * `cmt_pb_cons_message_marshal` (peer.go:277-280) so the host sees bytes.
 *
 * ── VoteSetReader ──────────────────────────────────────────────────────
 * `PickSendVote`/`PickVoteToSend` take `types.VoteSetReader`
 * (types/vote_set.go:716-724), an interface with two implementations the
 * reactor passes: `*VoteSet` (reactor.go:734, :796, :804, :813, :820,
 * :827, :835) and `*ExtendedCommit` (:765). C has no interfaces
 * (cmt_vote_set.h:108-110); `cmt_vote_set_reader_t` is the two-armed
 * struct and its seven methods dispatch on the arm.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * No clock: `ApplyNewRoundStepMessage`'s `cmttime.Now()` (:1379) is READ
 * BY THE CALLER and handed in as a value, exactly as cmt_cs.h:146-155
 * does for `NewProposal`, so every clock read sits at a reactor call site
 * (D-20 rev 3, atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19: one `now`
 * callback). The ONE random draw is `PickRandom` (:1188) through
 * `cmt_bits_pick_random` — the recorded substitution (cmt_bits.h:256-273),
 * gossip-only. No unordered iteration, no allocation, no global state.
 *
 * ── SUBSTITUTIONS (umbrella rev 5, atlas-dec-d5e766defde138eb6dd02e5b81e735a8)
 * Every `ps.mtx.Lock()` / `defer Unlock()` is dropped (single thread,
 * item 7): :1071, :1080, :1090, :1097, :1123, :1136, :1169, :1274, :1304,
 * :1315, :1324, :1333, :1341, :1364, :1418, :1435, :1452, :1468, :1490.
 * Where the reference has an exported/unexported pair whose only
 * difference is the lock (EnsureVoteBitArrays :1273 / ensureVoteBitArrays
 * :1279), the pair collapses into ONE function carrying both ranges.
 * Panics: none in this range.
 *
 * ── taşınmadı (not ported), with the reason ────────────────────────────
 *   · `SetLogger` (:1063-1066), `MarshalJSON` (:1079-1085), `String`
 *     (:1484-1486), `StringIndented` (:1489-1501), `peerStateStats.String`
 *     (:1041-1044), `PeerRoundState.String`/`StringIndented`
 *     (peer_round_state.go:45-68) — logger, JSON, display (port map YOK).
 *   · `ErrPeerStateHeightRegression`, `ErrPeerStateInvalidStartTime`
 *     (:1018-1019) — declared and never returned in the pinned file
 *     (grep: no other site); nothing to port.
 *   · `RecordVote` / `RecordBlockPart` ARE ported (below) but have NO
 *     CALLER in this port: their only reference caller is
 *     `peerStatsRoutine` (:970, :974), which the port map marks YOK and
 *     whose feed, `cs.statsMsgQueue` (state.go:913, :931), cmt_cs.c:1571
 *     and :1593 do not carry. Stated so the orphan is visible, not hidden.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/reactor.go                1817 lines
 *     b7b4fdd346d99d32b713e82f8dcc95a0ac1b1c3a4b25d7d8c3283fc33dd33427
 *   consensus/types/peer_round_state.go   68 lines
 *     b5bd1eb78629c8f868ee69bae888285217387237497635da69c80d1c02308408
 *   p2p/peer.go                          443 lines
 *     35f3415786016bcbbc156d7999d9686a4f21b85682cfd6378192b135c7260758
 *     (read for :22-48 the Peer interface and :258-295 Send/TrySend/send)
 *   p2p/key.go                           120 lines
 *     db7c7cda77c95229b29e17bcf32e6bc44049510e200ff0e0b842c0761c7ce0bf
 *     (read for :15-16, `type ID string`)
 *   types/vote_set.go                    724 lines
 *     548a256c311755a4a2d83696c90030f144952c64c0e3a459ac86baf844c56880
 *     (read for :716-724, VoteSetReader)
 * Governing records: umbrella rev 5
 * (atlas-dec-d5e766defde138eb6dd02e5b81e735a8), D-20 rev 3
 * (atlas-dec-fb3ed0315ffbfd0459efa779a2e00c19), PQ POLICY
 * (atlas-dec-652be084b95d02d253834906271e9fb0), pin record rev 18
 * (atlas-dec-483ec17cbb352ef0ec2267ccd953339c).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_PS_H
#define SHARED_DNAC_CMT_PS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "cmt_tmhash.h"        /* CMT_OK / CMT_REJECT / CMT_FAULT         */
#include "cmt_time.h"          /* cmt_time_t                              */
#include "cmt_bits.h"          /* cmt_bit_array_t                         */
#include "cmt_pb.h"            /* CMT_PB_PEER_ID_MAX, cmt_pb_cons_message */
#include "cmt_part_set.h"      /* cmt_part_set_header_t                   */
#include "cmt_block.h"         /* cmt_extended_commit_t                   */
#include "cmt_proposal.h"      /* cmt_proposal_t                          */
#include "cmt_vote.h"          /* cmt_vote_t                              */
#include "cmt_vote_set.h"      /* cmt_vote_set_t                          */
#include "cmt_round_state.h"   /* cmt_round_step_t                        */
#include "cmt_msgs.h"          /* the five Apply* message structs         */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ the reactor's channels (reactor.go:24-30) ════════════════════════ */
/* Defined here rather than in cmt_conr.h because `PickSendVote` (:1151)
 * names VoteChannel and this is the lower module; cmt_conr.h's channel
 * descriptor table uses these same names. */

/** cometbft@709fd12b consensus/reactor.go:25 — `StateChannel`. */
#define CMT_CONR_STATE_CHANNEL         ((uint8_t)0x20)
/** cometbft@709fd12b consensus/reactor.go:26 — `DataChannel`. */
#define CMT_CONR_DATA_CHANNEL          ((uint8_t)0x21)
/** cometbft@709fd12b consensus/reactor.go:27 — `VoteChannel`. */
#define CMT_CONR_VOTE_CHANNEL          ((uint8_t)0x22)
/** cometbft@709fd12b consensus/reactor.go:28 — `VoteSetBitsChannel`. */
#define CMT_CONR_VOTE_SET_BITS_CHANNEL ((uint8_t)0x23)

/** cometbft@709fd12b consensus/reactor.go:30 — `maxMsgSize`, 1 MiB. The
 *  same constant cmt_wal.h:95 carries as CMT_MAX_MSG_SIZE for the WAL
 *  record bound; named again here at its own home so the send buffer
 *  below can cite the reactor's line. */
#define CMT_CONR_MAX_MSG_SIZE 1048576

/* ══ PeerRoundState (peer_round_state.go:15-43) ═══════════════════════ */

/**
 * cometbft@709fd12b consensus/types/peer_round_state.go:15-42 —
 * `type PeerRoundState struct`, field for field. Every `*bits.BitArray`
 * is a pointer into the owning `cmt_ps_t`'s pool (see the file header);
 * NULL is nil.
 */
typedef struct {
    int64_t               height;               /* :16 Height peer is at   */
    int32_t               round;                /* :17 -1 if unknown       */
    cmt_round_step_t      step;                 /* :18 Step peer is at     */
    /** :21 Estimated start of round 0 at this height. WRITTEN at
     *  reactor.go:1383 and read by no ported line (only by the display
     *  and JSON rows, which are YOK). */
    cmt_time_t            start_time;
    bool                  proposal;             /* :24                     */
    cmt_part_set_header_t proposal_block_part_set_header;  /* :25         */
    cmt_bit_array_t      *proposal_block_parts; /* :26                     */
    int32_t               proposal_pol_round;   /* :28 -1 if none          */
    cmt_bit_array_t      *proposal_pol;         /* :31 nil until POL msg   */
    cmt_bit_array_t      *prevotes;             /* :32                     */
    cmt_bit_array_t      *precommits;           /* :33                     */
    int32_t               last_commit_round;    /* :34 -1 if none          */
    cmt_bit_array_t      *last_commit;          /* :35                     */
    int32_t               catchup_commit_round; /* :38 -1 if none          */
    cmt_bit_array_t      *catchup_commit;       /* :41                     */
} cmt_prs_t;

/* ══ the peer, as this module sees it (p2p/peer.go:22-48) ═════════════ */

/**
 * p2p/peer.go:40-41 — `Send(Envelope) bool` / `TrySend(Envelope) bool`,
 * with the envelope already marshalled (peer.go:280) so the host sees
 * bytes. `peer_idx` is the host's small index for the connection
 * (substitution 9). A false is the reference's false: not sent.
 *
 * ⚠ DEVIATION R3-A-1 (stated in cmt_conr.h): the reference's `Send`
 * BLOCKS up to `defaultSendTimeout` when the queue is full and only then
 * returns false; here NEITHER row blocks — a full queue is false at once
 * and the reactor retries on its next tick.
 */
typedef bool (*cmt_ps_send_fn)(void *ctx, int peer_idx, uint8_t channel_id,
                               const uint8_t *bytes, size_t len);

/**
 * Reactor-owned scratch every PeerState of one reactor shares — legal
 * because the port is single-threaded and a send completes before the
 * next one begins. It is the C cost of peer.go:277-280's `msg.(Wrapper)`
 * + `proto.Marshal(msg)` temporaries.
 *
 * ⚠ HEAP, never stack: `buf` is CMT_CONR_MAX_MSG_SIZE (1 MiB) and the two
 * messages are ~10 KB each (cmt_msgs.h:209-211). The reactor allocates
 * and frees them (cmt_conr_init / cmt_conr_free).
 */
typedef struct {
    uint8_t               *buf;      /* peer.go:280, the marshalled bytes  */
    size_t                 cap;      /* CMT_CONR_MAX_MSG_SIZE              */
    cmt_pb_cons_message_t *pb;       /* msgs.go:21 MsgToProto's output     */
    cmt_msg_t             *msg;      /* the reactor message being built    */
} cmt_ps_scratch_t;

/** `PeerState.peer` (reactor.go:1027) reduced to what the ported code
 *  reads of it: `ID()` (:283 through `ps.peer.ID()`, and every peer-id
 *  argument the reactor passes to the state machine), `Send` (:1151) and
 *  `TrySend` (reactor.go:308, :863 — the reactor's, not this module's,
 *  but the descriptor is one table). */
typedef struct {
    int               idx;                        /* host's peer index   */
    uint8_t           id[CMT_PB_PEER_ID_MAX];     /* p2p/key.go:16 → 32 B */
    cmt_ps_send_fn    send;                       /* peer.go:260-262     */
    cmt_ps_send_fn    try_send;                   /* peer.go:264-268     */
    void             *ctx;
    cmt_ps_scratch_t *scratch;                    /* peer.go:270-295     */
} cmt_ps_peer_t;

/* ══ PeerState (reactor.go:1022-1059) ═════════════════════════════════ */

/** cometbft@709fd12b consensus/reactor.go:1036-1039 —
 *  `type peerStateStats struct`. */
typedef struct {
    int votes;         /* :1037 */
    int block_parts;   /* :1038 */
} cmt_ps_stats_t;

/** The pool behind the six bit-array pointers of `cmt_prs_t`; see the
 *  file header for why six is enough. */
#define CMT_PS_BITS_SLOTS 6

/**
 * cometbft@709fd12b consensus/reactor.go:1026-1033 — `type PeerState
 * struct`. `logger` (:1028) is YOK; `mtx` (:1030) is dropped; `Stats`
 * (:1032) is a value, the reference's `*peerStateStats` is never nil
 * (:1057).
 *
 * ~1.4 KB each (six 220-byte arrays); the reactor keeps CMT_PEER_MAX of
 * them on the heap.
 */
typedef struct {
    cmt_ps_peer_t   peer;                       /* :1027 */
    cmt_prs_t       prs;                        /* :1031 PRS              */
    cmt_ps_stats_t  stats;                      /* :1032 Stats            */
    /** C only — the storage the six `cmt_prs_t` pointers point into. */
    cmt_bit_array_t pool[CMT_PS_BITS_SLOTS];
} cmt_ps_t;

/* ══ VoteSetReader (types/vote_set.go:716-724) ════════════════════════ */

/**
 * cometbft@709fd12b types/vote_set.go:716-724 — `type VoteSetReader
 * interface`, as the two implementations the reactor hands to
 * `PickSendVote`. Exactly one arm is non-NULL; both NULL is the
 * reference's nil `*VoteSet` passed as an interface (reactor.go:734/:796
 * with `rs.LastCommit == nil` at the initial height), which answers
 * `Size() == 0` (vote_set.go:140-142) and is picked from never.
 */
typedef struct {
    cmt_vote_set_t              *vs;   /* *types.VoteSet                  */
    const cmt_extended_commit_t *ec;   /* *types.ExtendedCommit (:765)    */
} cmt_vote_set_reader_t;

/** A reader over a vote set (NULL allowed — the nil case above). */
static inline cmt_vote_set_reader_t cmt_vote_set_reader_of(cmt_vote_set_t *vs)
{
    cmt_vote_set_reader_t r;

    r.vs = vs;
    r.ec = NULL;
    return r;
}

/** A reader over an extended commit (reactor.go:765). */
static inline cmt_vote_set_reader_t
cmt_extended_commit_reader_of(const cmt_extended_commit_t *ec)
{
    cmt_vote_set_reader_t r;

    r.vs = NULL;
    r.ec = ec;
    return r;
}

/* ══ construction (reactor.go:1046-1059) ══════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:1047-1059 — `NewPeerState()`.
 * Round, ProposalPOLRound, LastCommitRound and CatchupCommitRound start
 * at -1 (:1052-1055); everything else is Go's zero, which for
 * `StartTime` is CMT_TIME_ZERO and not the epoch (cmt_time.h:19-25).
 *
 * @param peer copied. `scratch` must be non-NULL and its three buffers
 *        allocated; `send`/`try_send` may be NULL only for a PeerState
 *        that is never asked to send (the reference's mock peer).
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ps_init(cmt_ps_t *ps, const cmt_ps_peer_t *peer);

/* ══ accessors (reactor.go:1068-1093) ═════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:1070-1076 — `GetRoundState()`.
 * "Returns a shallow copy of the PeerRoundState. There's no point in
 * mutating it since it won't change PeerState." The copy's six pointers
 * ALIAS the pool, exactly as the Go struct copy's do; treat it as
 * read-only (peer_round_state.go:14).
 */
void cmt_ps_get_round_state(const cmt_ps_t *ps, cmt_prs_t *out);

/** cometbft@709fd12b consensus/reactor.go:1089-1093 — `GetHeight()`. */
int64_t cmt_ps_get_height(const cmt_ps_t *ps);

/* ══ what the peer has (reactor.go:1095-1144) ═════════════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:1096-1119 — `SetHasProposal()`.
 * Only for the peer's current height and round (:1100-1102), only once
 * (:1104-1106); the block-parts bit array is created from the proposal's
 * PartSetHeader unless NewValidBlock already created it (:1111-1113).
 * @return CMT_OK, CMT_REJECT from `bits.NewBitArray` on a Total above the
 *         derived bound (cmt_bits.h:129), CMT_FAULT on NULL.
 */
int cmt_ps_set_has_proposal(cmt_ps_t *ps, const cmt_proposal_t *proposal);

/** cometbft@709fd12b consensus/reactor.go:1122-1132 —
 *  `InitProposalBlockParts()`. A no-op once the array exists (:1126). */
int cmt_ps_init_proposal_block_parts(cmt_ps_t *ps,
                                     const cmt_part_set_header_t *psh);

/** cometbft@709fd12b consensus/reactor.go:1135-1144 —
 *  `SetHasProposalBlockPart()`. Only at the peer's height and round
 *  (:1139-1141); a nil array or an index past its width is a no-op
 *  (bit_array.go:84-86, :93-95). */
int cmt_ps_set_has_proposal_block_part(cmt_ps_t *ps, int64_t height,
                                       int32_t round, int index);

/* ══ the peer's send (p2p/peer.go:258-295) ════════════════════════════ */

/**
 * p2p/peer.go:258-262 `Send` / :264-268 `TrySend`, both through :270-295
 * `send`: the message is wrapped and marshalled (:277-280, here
 * `cmt_msg_to_proto` + `cmt_pb_cons_message_marshal` into
 * `peer.scratch`) and the bytes go to the chosen host row (:285).
 *
 * @param use_try_send false is `Send` (:261 `p.mconn.Send`), true is
 *        `TrySend` (:267 `p.mconn.TrySend`).
 * @param out_sent the reference's bool. False when the row is NULL
 *        (the reference's `!p.IsRunning()`, :271-272), when the marshal
 *        fails (:281-283, logged) or when the row answers false.
 * @return CMT_OK; CMT_FAULT on NULL or where `cmt_msg_to_proto` reports
 *         a NODE-LOCAL inconsistency in OUR OWN message (its :59 site,
 *         cmt_msgs.h:274-281 — the reference dereferences nil there and
 *         panics, so that is not a "false" but a stop).
 */
int cmt_ps_peer_send(cmt_ps_t *ps, bool use_try_send, uint8_t channel_id,
                     const cmt_msg_t *msg, bool *out_sent);

/* ══ picking and sending votes (reactor.go:1146-1192) ═════════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:1148-1163 — `PickSendVote()`.
 * Picks a vote the peer lacks (:1149), sends it on the VoteChannel
 * (:1151-1156) and, if the send succeeded, marks it as known (:1157).
 * The marshal (peer.go:277-280) happens here, into `peer.scratch`.
 * @param out_sent the reference's bool.
 * @return CMT_OK; CMT_FAULT on NULL or a `PickVoteToSend` fault. A
 *         marshal failure is peer.go:281-283: logged, false, no fault.
 */
int cmt_ps_pick_send_vote(cmt_ps_t *ps, const cmt_vote_set_reader_t *votes,
                          bool *out_sent);

/**
 * cometbft@709fd12b consensus/reactor.go:1168-1192 — `PickVoteToSend()`.
 * "NOTE: `votes` must be the correct Size() for the Height()."
 * @param out_vote a COPY of `votes.GetByIndex(index)` (:1189); ~9.5 KB,
 *        the caller's heap.
 * @param out_ok the reference's bool.
 * @return CMT_OK; CMT_REJECT from the bit-array bounds; CMT_FAULT on NULL
 *         or a failing random source (cmt_bits.h:271).
 */
int cmt_ps_pick_vote_to_send(cmt_ps_t *ps, const cmt_vote_set_reader_t *votes,
                             cmt_vote_t *out_vote, bool *out_ok);

/**
 * cometbft@709fd12b consensus/reactor.go:1273-1277 `EnsureVoteBitArrays()`
 * and :1279-1299 `ensureVoteBitArrays()` — one function, the lock
 * dropped. Allocates the four arrays of the peer's height (:1281-1293) or
 * its LastCommit for height+1 (:1294-1297); never replaces one that
 * exists. "NOTE: It's important to make sure that numValidators actually
 * matches what the node sees as the number of validators for height."
 * @return CMT_OK, CMT_REJECT above the bit bound, CMT_FAULT on NULL.
 */
int cmt_ps_ensure_vote_bit_arrays(cmt_ps_t *ps, int64_t height,
                                  int num_validators);

/* ══ statistics (reactor.go:1301-1337) — ported, no caller (see header) */

/** cometbft@709fd12b consensus/reactor.go:1303-1310 — `RecordVote()`.
 *  @return the new total. */
int cmt_ps_record_vote(cmt_ps_t *ps);

/** cometbft@709fd12b consensus/reactor.go:1314-1319 — `VotesSent()`. */
int cmt_ps_votes_sent(const cmt_ps_t *ps);

/** cometbft@709fd12b consensus/reactor.go:1323-1329 — `RecordBlockPart()`.
 *  @return the new total. */
int cmt_ps_record_block_part(cmt_ps_t *ps);

/** cometbft@709fd12b consensus/reactor.go:1332-1337 — `BlockPartsSent()`. */
int cmt_ps_block_parts_sent(const cmt_ps_t *ps);

/* ══ marking votes (reactor.go:1339-1360) ═════════════════════════════ */

/** cometbft@709fd12b consensus/reactor.go:1340-1345 — `SetHasVote()`:
 *  `setHasVote(vote.Height, vote.Round, vote.Type, vote.ValidatorIndex)`.
 *  @return CMT_OK; CMT_FAULT on NULL. A negative index is where Go's
 *          `SetIndex(int(index), true)` (:1358) on a live array would
 *          read a negative subscript — cmt_bits_set_index returns
 *          CMT_FAULT for it (cmt_bits.h:153), and the ValidateBasic gate
 *          in the reactor refuses it one layer up (:1740-1742). */
int cmt_ps_set_has_vote(cmt_ps_t *ps, const cmt_vote_t *vote);

/* ══ applying the peer's messages (reactor.go:1362-1481) ══════════════ */

/**
 * cometbft@709fd12b consensus/reactor.go:1363-1414 —
 * `ApplyNewRoundStepMessage()`. Ignores a message that does not advance
 * (H, R, S) (:1368-1370, `CompareHRS`); on a height or round change
 * drops the proposal, the parts and the current vote arrays (:1384-1393);
 * preserves the catch-up commit when the peer reaches its round
 * (:1394-1400); on a height change shifts Precommits into LastCommit when
 * the rounds line up (:1401-1413).
 *
 * @param now the reference's `cmttime.Now()` at :1379, READ BY THE
 *        CALLER (cmt_conr, through its host clock) — this module reads no
 *        clock. `StartTime` becomes `now - SecondsSinceStartTime` seconds
 *        (:1379): the seconds field is moved with a saturation guard, the
 *        nanos are `now`'s. Go's `time.Duration` multiplication wraps and
 *        `Time.Add` is the standard library's, neither in the pinned
 *        tree and neither reproduced — the field is write-only in the
 *        ported code (see `cmt_prs_t`), so nothing observable depends on
 *        it. Recorded as a deviation in the wave report.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
int cmt_ps_apply_new_round_step_message(cmt_ps_t *ps,
                                        const cmt_new_round_step_msg_t *msg,
                                        cmt_time_t now);

/** cometbft@709fd12b consensus/reactor.go:1417-1431 —
 *  `ApplyNewValidBlockMessage()`. The message's bit array is COPIED into
 *  the pool (:1430 stores the pointer; the message is freed by the caller
 *  here). `has_block_parts == false` is the nil pointer.
 *  @return CMT_OK, CMT_REJECT above the bit bound, CMT_FAULT on NULL. */
int cmt_ps_apply_new_valid_block_message(cmt_ps_t *ps,
                                         const cmt_new_valid_block_msg_t *msg);

/** cometbft@709fd12b consensus/reactor.go:1434-1448 —
 *  `ApplyProposalPOLMessage()`. "TODO: Merge onto existing
 *  ps.PRS.ProposalPOL? We might have sent some prevotes in the meantime."
 *  — the reference REPLACES (:1447), and so does this. */
int cmt_ps_apply_proposal_pol_message(cmt_ps_t *ps,
                                      const cmt_proposal_pol_msg_t *msg);

/** cometbft@709fd12b consensus/reactor.go:1451-1460 —
 *  `ApplyHasVoteMessage()`. */
int cmt_ps_apply_has_vote_message(cmt_ps_t *ps, const cmt_has_vote_msg_t *msg);

/**
 * cometbft@709fd12b consensus/reactor.go:1467-1481 —
 * `ApplyVoteSetBitsMessage()`. "`ourVotes` is a BitArray of votes we have
 * for msg.BlockID. NOTE: if ourVotes is nil (e.g. msg.Height <
 * rs.Height), we conservatively overwrite ps's votes w/ msg.Votes."
 * @param our_votes NULL is the reference's nil (:1473).
 * @return CMT_OK, CMT_FAULT on NULL or a failing bit-array combinator.
 */
int cmt_ps_apply_vote_set_bits_message(cmt_ps_t *ps,
                                       const cmt_vote_set_bits_msg_t *msg,
                                       const cmt_bit_array_t *our_votes);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_PS_H */
