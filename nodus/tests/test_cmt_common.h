/**
 * Nodus — cometbft @709fd12b C port, wave R2-T:
 * the C stand-in for `consensus/common_test.go`, the fixture every
 * scenario in test_cmt_cs.c is driven through.
 *
 * HEADER-ONLY, every function `static`. TWO translation units include it:
 * test_cmt_cs.c directly, and test_cmt_byzantine.c through the multi-node
 * driver test_cmt_multinode.h (wave R2-BYZ), which builds N of these
 * fixtures. What those two files use of this one, by grep (2026-09-11):
 * `test_cmt_multinode.h` calls `tc_setup`, `tc_teardown`, `tc_sign_vote`,
 * `tc_decide_proposal`, `tc_set_next_tx` and `tc_store_at`, and reads
 * `tc_t`'s `recs`/`recs_n` (as `tc_block_rec_t`), `applied_height`,
 * `store_height`, `decode_misses`, `conflict_calls` and `tc_store_ent_t`
 * directly; `test_cmt_byzantine.c` calls `tc_check_proposer` and
 * `tc_expected_proposer` and reads `create_calls`, `recs_n` and
 * `recs[].hash`. Those functions, types and fields are therefore an
 * interface: a wave that needs a different shape ADDS a function beside
 * them (which is what R2-T2 did for `tc_stub_sign_vote` and
 * `tc_decide_proposal_from`) rather than changing them. The first version
 * of this comment said one TU included the file; Atlas's include graph
 * said two. R2-T2's first version listed six functions and put
 * `tc_check_proposer` in the wrong file; verifier T2 grepped.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * By itself, nothing — it asserts no property of the port. It is the
 * APPLICATION, SIGNER, BLOCK STORE, WAL, CLOCK and TIMER that
 * `shared/dnac/cmt_cs.c` calls out to, plus the validator stubs and the
 * `ensure*` / `validate*` helpers `consensus/common_test.go` gives its
 * own tests. What it makes true, and what every scenario therefore rests
 * on, is:
 *   · the state machine is driven through its PUBLIC surface only —
 *     `cmt_cs_enter_new_round`, `cmt_cs_step`, `cmt_cs_on_timer_expired`,
 *     `cmt_cs_add_vote`, `cmt_cs_set_proposal_and_block` — never by
 *     writing `cs->rs` behind its back (which is what wave R2-C's
 *     `t_entry_guards` had to do, and named as its own limit);
 *   · every callback in `cmt_cs_host_t` is implemented, so a scenario
 *     that reaches an unimplemented row cannot silently pass;
 *   · nothing reads a wall clock, a random number, an environment
 *     variable, a file or a socket.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * COMPILE FLAGS: `CMT_SOFTWARE_VERSION` must be defined by the build
 *   (`shared/dnac/cmt_state.h:150` refuses to compile without it; the
 *   nodus build passes `NODUS_VERSION_STRING`). Nothing else. A DEFAULT
 *   BUILD is enough; `QGP_FAULT_INJECT` is NOT set, so `CMT_FAIL_POINT()`
 *   expands to `((void)0)` and none of the six fail points of
 *   `cmt_cs.h:159-168` is compiled into the run.
 * ENVIRONMENT: none. No variable is read. In particular `FAIL_TEST_INDEX`
 *   — the only variable the module ever looks at, and only under
 *   QGP_FAULT_INJECT — is never set and never read here.
 * No network, no files, no database.
 *
 * ⚠ PEAK MEMORY, all heap: four `cmt_state_storage_t` at ~1 MB each
 * (three 128-slot validator arrays of 2592-byte keys), one
 * `cmt_state_block_scratch_t` (~350 KB), one `cmt_valset_scratch_t`,
 * four 512 KiB slot payload buffers, and a block-record pool whose
 * marshalled copies are sized to the blocks actually made. About 6 MB
 * per fixture; one fixture is alive at a time and `tc_teardown` frees it.
 *
 * ⚠ RUN TIME. Every signature is a real ML-DSA-87 signature and every
 * vote added to a vote set is really verified. A scenario that walks a
 * height with four validators signs and verifies on the order of thirty
 * signatures. The suite is CPU-bound on Dilithium, not on anything here.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no environment
 * variables. The only state outside a `tc_t` is two `static const`
 * arrays with static storage duration: `tc_ext_bytes`, the 9 bytes of
 * common_test.go:143 (see `tc_sign_vote`), and `tc_ext_bytes_of`, the
 * four 11-byte per-validator extensions of state_test.go:1656-1661. Both
 * are read-only and never freed because they are not allocated.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. `decode_block` NEVER PARSES. This tree deliberately has no
 *     `cmt_pb_block_unmarshal` (cmt_pb.h:1043), so the host cannot turn
 *     bytes back into a block. `tc_decode_block` is a REGISTRY LOOKUP: it
 *     memcmp's the assembled bytes against the marshalled form of every
 *     block this fixture itself created and hands back that block. So the
 *     part-set assembly path IS exercised end to end (parts are split,
 *     gossiped, re-assembled and compared byte for byte), but a
 *     marshal/unmarshal asymmetry is invisible here, and a block that no
 *     scenario created is simply refused — which is the right answer for
 *     a test and the wrong answer for a node.
 *  2. THE APPLICATION NEVER CHANGES ITS APP HASH. `tc_apply_verified_block`
 *     rotates the validator sets exactly as `state/execution.go`'s
 *     `updateState` does, but leaves `app_hash` and `last_results_hash`
 *     untouched, where the reference's kvstore changes both. Consequences,
 *     both real: `needProofBlock` (state.go:1119-1132) is true only at the
 *     initial height and never again, so its second branch is never taken;
 *     and `validateBlock`'s AppHash check can only fail for a block that
 *     was TAMPERED WITH, never for a genuine app-hash disagreement.
 *  3. `tc_validate_block` IS A SUBSET of `state/validation.go`'s
 *     `validateBlock` (:17-149 in the pinned file). THREE checks are
 *     missing, and the ranges below were re-derived from the pinned file
 *     after a verifier found the first version of this entry citing the
 *     opposite of what it said:
 *       · **:91-95** — `state.LastValidators.VerifyCommit`, the non-initial
 *         half of the LastCommit branch. NOT performed, because that row
 *         is declared on a NON-const validator set
 *         (cmt_validator_set.h:896) and this callback's state is const;
 *         casting the const away in a test double is worse than the
 *         omission. A block whose LastCommit carries valid-looking but
 *         WRONG signatures is therefore ACCEPTED here. Its hash is still
 *         checked, by `cmt_block_validate_basic`. Only the initial-height
 *         half (:86-90) is performed.
 *       · **:139-142** — the `default:` arm of the block-time switch, which
 *         refuses a height BELOW the initial height. The C's chain ends in
 *         an `else if` with no `else`, so such a block falls through with
 *         no time check. Immaterial here: the height check at :64-68
 *         refuses it first.
 *       · **:145-147** — `Evidence.MaxBytes` against the block's evidence
 *         size. Immaterial here: no scenario ever puts evidence in a
 *         block.
 *     Performed, in the reference's order: :17-19 (ValidateBasic), :22-27,
 *     :29-33, :35-45, :46-51 (LastBlockID), :54-59 (AppHash), :62-67,
 *     :69-73, :75-84, :86-90, :101-111 (the proposer) and :113-137 (the
 *     block-time switch's first two arms).
 *  4. EVERY SIGNATURE IS RANDOMIZED. `shared/crypto/sign/dsa/config.h:6`
 *     defines `DILITHIUM_RANDOMIZED_SIGNING`, so signing the same bytes
 *     twice gives different signatures, unlike the reference's ed25519.
 *     Nothing in this suite may assert on signature bytes, and nothing
 *     does. Block hashes DO cover the previous commit's signatures, so a
 *     committed block's hash differs between runs — every comparison here
 *     is between values computed inside ONE run, so the VERDICT is
 *     deterministic even though the bytes are not.
 *  5. THE STUBS ARE MockPV, NOT FilePV. `types/validator.go:182-196`
 *     builds each test validator with `NewMockPV()`, so
 *     `types/priv_validator.go:73-100` is the signer the reference's
 *     tests use: it signs whatever it is given, with NO last-sign-state
 *     and NO double-sign protection. `tc_mock_sign_vote` is that function
 *     ported. `cmt_privval.h`'s `cmt_file_pv_t` — the port of the REAL
 *     FilePV, with its CheckHRS and its conflicting-data refusal — is
 *     therefore NOT exercised by this suite at all. That is the
 *     reference's own choice, not a shortcut, but it is a hole HERE: no
 *     scenario in test_cmt_cs.c can catch a double-signing regression.
 *     It is NOT a hole in the port: `nodus/tests/test_cmt_privval.c`
 *     covers `cmt_lss_check_hrs` branch by branch (:261-295, including
 *     every regression that must REJECT) and `cmt_pv_sign_vote`'s reuse,
 *     timestamp-restoration and "conflicting data" paths, ported from
 *     `privval/file_test.go`. The right place for that coverage is the
 *     module's own test, which is where the reference keeps it too.
 *  6. THE VOTE-EXTENSION ARENA IS NEVER RESET. `cmt_cs.h`'s OWNERSHIP (2)
 *     requires the arena to be per-height and reset only after
 *     `updateToState` has released the previous height's vote set. This
 *     fixture allocates one arena for the whole scenario and never resets
 *     it, which satisfies the contract trivially and therefore PROVES
 *     NOTHING about a host that does reset it.
 *  7. THE PEER QUEUE IS FED WITH A SYNTHETIC PEER ID. Go's `addVotes`
 *     (common_test.go:255-259) puts a stub's vote on the PEER queue
 *     carrying an EMPTY PeerID. In this port an empty id means "our own
 *     message" and routes to the INTERNAL queue (cmt_cs.h:841-854), so
 *     the two cannot both be reproduced. `tc_add_vote` keeps the QUEUE
 *     and gives up the ID: it passes `tc->peer_id`, 32 bytes. The one
 *     consequence is that `peerCatchupRounds`
 *     (consensus/types/height_vote_set.go:50, :143-151) accounts a stub's
 *     out-of-round votes against a real peer id where the reference
 *     accounts them against "", so the two-round catch-up ceiling is
 *     reached on a different schedule.
 *  8. THE POLL ORDER IS THE PORT'S, NOT THE REFERENCE'S. Go's
 *     `receiveRoutine` selects at random between the peer queue, the
 *     internal queue and the tock; this port fixes the order
 *     (cmt_cs.h:17-32). Every helper here drains to quiescence before it
 *     returns, so a scenario rarely has both queues non-empty — but where
 *     it does, this suite exercises ONE of the interleavings the
 *     reference is allowed to take, and says nothing about the others.
 *  9. `tc_drain` HIDES HOW MANY STEPS SOMETHING TOOK. It steps until
 *     `cmt_cs_has_work` is false. A scenario therefore cannot tell "the
 *     transition happened on the message I just sent" from "it happened
 *     three messages ago"; it only sees where the round state ended up.
 * 10. THE BLOCK STORE IS A DOZEN ROWS OF ARRAY. `tc_bs_*` keeps one entry
 *     per height with the header, the seen commit and the seen extended
 *     commit, and nothing else. `store/store.go`'s pruning, its batch
 *     writes and every panic it has are not modelled.
 * 11. A PART SET THE STATE MACHINE ASSEMBLED BORROWS THE SENDER'S BYTES.
 *     `cmt_part_set_add_part` stores the part STRUCT, whose `bytes` is a
 *     pointer (cmt_part_set.c:457, `ps->parts[part->index] = *part`), so a
 *     part set built from `tc_set_proposal_and_block` points into THIS
 *     FIXTURE'S `ext_scratch` — the one buffer `tc_decide_proposal_from`
 *     and `tc_make_part_set` marshal into, and which the NEXT call to
 *     either overwrites. The bytes are read at exactly two moments: when
 *     the set completes (the reader, state.go:2005) and when a VALID block
 *     is RE-PROPOSED (state.go:1211 hands `ValidBlockParts` to :1246-1249).
 *     Every scenario drains before it rebuilds, so the first read is safe;
 *     NO scenario re-proposes a fixture-made valid block after a second
 *     fixture-made block, so the second never sees a stale pointer. A
 *     scenario that did would queue parts whose proofs no longer match and
 *     the block would never complete. Named here because nothing checks it.
 * 12. THE EXTENDED-COMMIT CAPTURE RECORDS THE FIXTURE'S OWN CALLS TOO.
 *     `tc_create_proposal_block` remembers the `last_ext_commit` it was
 *     handed (`cap_ext*`, the C answer to state_test.go:1669-1674's
 *     captured RequestPrepareProposal) — but `tc_decide_proposal_from`
 *     calls the same function on the fixture's behalf, so the LAST capture
 *     is whichever of the two ran last. `cap_ext_for_height` says which
 *     height it was for, and the one scenario that reads the capture makes
 *     no fixture-side proposal after the state machine's own.
 *
 * ── WHICH GO HELPER EACH C HELPER STANDS IN FOR ────────────────────────
 * Named at each definition. The systematic difference, stated once: the
 * reference's `ensure*` helpers BLOCK ON A CHANNEL fed by the event bus,
 * with a 200 ms budget (common_test.go:55). This port has no event bus —
 * `eventBus.PublishEvent*` is one of the rows cmt_cs.h:72-74 says is
 * deliberately not ported — so every `tc_ensure_*` here instead drives
 * `cmt_cs_step` to quiescence and then ASSERTS ON THE ROUND STATE. That
 * turns "an event was published" into "the round state says the
 * transition happened", which is a weaker statement about events and a
 * stronger one about state, and it removes every timeout from the suite.
 *
 * Reference @709fd12b (SHA-256 verified before use):
 *   consensus/common_test.go   991 lines
 *     3e3940e51975f030a0190bc2b5217d93ee768eef30097d8b14b379b006023a38
 *   consensus/state_test.go   2620 lines   (R2-T2: :1656-1661, :2579-2590)
 *     9b8080ecfc32198f2bfcbd7ebb3c7b9be3c44c7cf5f053b1eb365b6a24f652c3
 *   consensus/state.go        2653 lines
 *     f9517e9f45f4f9afefebf869eb4674bf0135d5edda00de67eab2e1695c945090
 *   state/execution.go         789 lines
 *     d12730b67e48c4863963c929067905d475543fcd135b99eaa909c502ebecae55
 *   state/state.go             355 lines
 *     02dc0f209451d28202e1cc25c901af29eb48ca6e83ec5b8a69d88be10b1472fc
 *   types/validator_set.go    1053 lines
 *     6c3a663aaf84fbee94735731eaba27d1a8e5269dd6e316e0b175595e32902221
 *   config/config.go          1283 lines
 *     f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21
 * Opened by wave R2-T and reported in its wave report (the "(R2-T2: …)"
 * annotations above mark the lines wave R2-T2 added to that list; R2-T2
 * itself opened one unpinned file, internal/test/config.go, informative
 * only, pin revision 10). Of R2-T's five, the first three turned out to be
 * PINNED already — in tasks/comet-port-map.md rather than in a numbered
 * revision of the pin record, which is why the wave reported them as
 * unpinned; the ORCHESTRATOR checked the map at O6 and recomputed every
 * hash. The last two were genuinely absent and are pin revision 9:
 *   state/validation.go        150 lines   (map line 40, PINNED)
 *     a456fbc7dfb91d893c1eacf737c2f0c4848b154ac8c2d616b45eac5f02b6153a
 *   types/priv_validator.go    158 lines   (map line 911, PINNED)
 *     b3b390493189c5ddbe28f1d41e3f4f1839c816e77ce4ea1208b8eae846de717c
 *   types/validator.go         194 lines   (map line 27, PINNED)
 *     fe21832f8b1edd6e1f5adc151276efe092c5cf36c750ac2925b3332c097da7aa
 *   internal/test/params.go     14 lines   (pin rev 9)
 *     9fc70ac0d7ed096e9d0804af8ec69518aa830cfe9492f103ddc541fa71e670a5
 *   internal/test/block.go      92 lines   (pin rev 9)
 *     fc493e053193adad88184564326068120cca669ec6df9c7df7bf93c9677a6d25
 *
 * @file test_cmt_common.h
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_TESTS_TEST_CMT_COMMON_H
#define NODUS_TESTS_TEST_CMT_COMMON_H

#include "dnac/cmt_cs.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_params.h"

#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ══ assertion plumbing ═══════════════════════════════════════════════ */

/** As wave R2-C's CHECK: report the site and return 1 (failure). Every
 *  helper below returns 0 for success and 1 for failure, and every
 *  scenario propagates. */
#define TC_CHECK(cond, msg) do {                                          \
    if (!(cond)) {                                                        \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n",                    \
                __FILE__, __LINE__, (msg));                               \
        return 1;                                                         \
    }                                                                     \
} while (0)

/** The count of satisfied checks, printed at the end so that a run which
 *  silently stopped asserting is visible as a smaller number. */
static int g_tc_checks = 0;
#define TC_OK() do { g_tc_checks++; } while (0)

/* ══ fixture dimensions ═══════════════════════════════════════════════ */

/** The reference's tests use 1, 2, 3 or 4 validators (state_test.go:66,
 *  :194, :1881, :664). */
#define TC_MAX_VALS       4

/** Transactions a proposed block may carry here. The reference's kvstore
 *  reaps whatever is in the mempool; this fixture proposes what
 *  `tc_set_next_txs` was given, at most this many. */
#define TC_MAX_TXS        2

/** The widest transaction the tx arena holds. One byte over
 *  CMT_BLOCK_PART_SIZE_BYTES is enough to force a two-part block, which
 *  is what the oversized-block scenario needs. */
#define TC_TX_MAX         ((size_t)CMT_BLOCK_PART_SIZE_BYTES + 4096u)

/** Part slots per part set. Every block this fixture makes is one or two
 *  parts; 8 leaves room and keeps `cmt_new_part_set_from_header`'s
 *  `parts_cap` refusal (cmt_part_set.h:263-267) out of the way. */
#define TC_PARTS_CAP      8u

/** The payload buffer behind each of the three part-set slots, and behind
 *  the proposer's marshal scratch. `cmt_cs.h:549` says it must cover
 *  ConsensusParams.Block.MaxBytes — 21 MB at the reference defaults
 *  (params.go:99). THIS FIXTURE DELIBERATELY UNDER-PROVIDES: 512 KiB,
 *  because every block it makes is at most two 64 KiB parts. A block
 *  larger than this is refused at cmt_cs.c's `total_read >= buf_cap`
 *  branch rather than at the MaxBytes check, which is a DIFFERENT
 *  refusal; no scenario here reaches it. */
#define TC_PAYLOAD_CAP    (8u * (unsigned)CMT_BLOCK_PART_SIZE_BYTES)

/** Blocks one scenario may create — every block the state machine
 *  proposes AND every block the fixture makes on a stub's behalf. The
 *  widest ported scenario is TestStateLockPOLUnlockOnUnknownBlock
 *  (state_test.go:858-984), which makes THREE: this node's round-0 block
 *  and two stub blocks. TestStateLockNoPOL (:455-654) makes two — its
 *  round-2 proposal re-uses the ValidBlock and creates nothing. The first
 *  version of this comment said LockNoPOL "makes four"; it was counted,
 *  not measured, and is corrected here by reading the scenarios. */
#define TC_BLOCK_RECS     12

/** Heights the block store keeps. */
#define TC_STORE_MAX      8

/** The vote-extension arena (cmt_cs.h OWNERSHIP (2)). One extension per
 *  precommit this node signs, a handful per scenario. */
#define TC_ARENA_CAP      65536u

/** The widest vote extension the `create_proposal_block` capture keeps a
 *  copy of (HOW IT CAN LIE (12)). The fixture's own extensions are 9 and
 *  11 bytes (common_test.go:143, state_test.go:1656-1661); a longer one
 *  marks the capture as not taken rather than truncating it. */
#define TC_CAP_EXT_MAX    64u

/** WAL rows recorded for inspection. */
#define TC_WAL_MAX        512

/** The seconds field of the genesis time. A constant: nothing here reads
 *  a real clock. */
#define TC_GENESIS_SECONDS ((int64_t)1700000000)

/* ══ what the WAL saw ═════════════════════════════════════════════════ */

/** One row of the recorded WAL, flattened to the fields a scenario ever
 *  asks about. The full `cmt_wal_message_t` carries pointers into storage
 *  that dies with the message, so it is not kept. */
typedef struct {
    int            kind;        /* cmt_wal_kind_t                        */
    bool           sync;        /* WriteSync (:839, :1760) or Write      */
    int            msg_kind;    /* cmt_pb_cons_msg_kind_t, for KIND_MSG  */
    int32_t        vote_type;   /* a vote row's type                     */
    int64_t        height;
    int32_t        round;
} tc_wal_row_t;

/* ══ one block this fixture made ══════════════════════════════════════ */

/**
 * A block, plus every piece of storage it points at, plus its marshalled
 * form so that `tc_decode_block` can find it again.
 *
 * The lifetime rule `cmt_cs.h`'s `create_proposal_block` row states — the
 * host owns whatever `data.txs`, evidence and `last_commit` point into
 * and must keep it alive as long as the slot is named — is satisfied by
 * keeping every record until `tc_teardown`.
 */
typedef struct {
    bool             used;
    cmt_block_t      block;
    cmt_commit_t     last_commit;
    cmt_commit_sig_t sigs[TC_MAX_VALS];
    cmt_pb_bytes_t   txs[TC_MAX_TXS];
    uint8_t         *tx_storage;
    size_t           tx_storage_cap;
    uint8_t         *marshal;
    size_t           marshal_len;
    uint8_t          hash[CMT_TMHASH_SIZE];
} tc_block_rec_t;

/* ══ one height of the block store ════════════════════════════════════ */

typedef struct {
    bool                     saved;
    int64_t                  height;
    cmt_header_t             header;         /* LoadBlockMeta (:1124)    */
    bool                     has_seen;
    cmt_commit_t             seen;           /* LoadSeenCommit (:310)    */
    cmt_commit_sig_t         seen_sigs[TC_MAX_VALS];
    bool                     has_ext;
    cmt_extended_commit_t    ext;            /* LoadBlockExtendedCommit  */
    cmt_extended_commit_sig_t ext_sigs[TC_MAX_VALS];
    bool                     has_commit;
    cmt_commit_t             commit;         /* LoadBlockCommit (:313)   */
    cmt_commit_sig_t         commit_sigs[TC_MAX_VALS];
} tc_store_ent_t;

/* ══ a validator stub ═════════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/common_test.go:71-78 —
 * `type validatorStub struct`.
 *
 * The reference embeds a `types.PrivValidator`; here the key material
 * lives in the fixture and the stub carries only its index into it. The
 * `lastVote` field (:77) IS carried, because :116-121 depends on it.
 */
typedef struct {
    int32_t    index;        /* :72 */
    int64_t    height;       /* :73 */
    int32_t    round;        /* :74 */
    bool       has_last;     /* :77 lastVote == nil */
    cmt_vote_t *last;        /* :77, heap: a vote is ~9.5 KB */
} tc_stub_t;

/* ══ the fixture, which is also the host context ══════════════════════ */

typedef struct {
    /* ── identities ───────────────────────────────────────────────── */
    size_t                nvals;
    uint8_t             (*pk)[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t             (*sk)[QGP_DSA87_SECRETKEYBYTES];
    uint8_t               addr[TC_MAX_VALS][CMT_ADDRESS_SIZE];
    tc_stub_t             vss[TC_MAX_VALS];
    /** Which identity `cs` itself holds. Always 0: the reference's
     *  `randStateWithAppImpl` gives cs1 `privVals[0]`
     *  (common_test.go:486). */
    size_t                self;
    bool                  has_priv_validator;

    /* ── chain identity ───────────────────────────────────────────── */
    uint8_t               chain_id[CMT_PB_CHAINID_MAX];
    size_t                chain_id_len;
    uint8_t               peer_id[CMT_PB_PEER_ID_MAX];

    /* ── the state machine and everything it borrows ──────────────── */
    cmt_genesis_validator_t   gvals[TC_MAX_VALS];
    cmt_consensus_params_t    params;
    cmt_valset_scratch_t     *valscratch;
    cmt_state_block_scratch_t *blkscratch;
    cmt_state_storage_t      *stor_gen;
    cmt_state_storage_t      *stor_cs;
    cmt_state_storage_t      *stor_scratch;
    cmt_state_t              *genesis;
    cmt_cs_t                 *cs;
    cmt_cs_slots_t           *slots;
    cmt_config_t              config;
    cmt_pb_arena_t           *arena;

    /* ── the clock (cmt_cs.h: the ONLY clock in the module) ───────── */
    cmt_time_t            now;
    int                   now_calls;

    /* ── the timer (ticker.go:126, :83-92) ────────────────────────── */
    bool                  armed;
    int64_t               armed_ns;
    int                   arm_calls;
    int                   disarm_calls;

    /* ── the application ──────────────────────────────────────────── */
    /** `ProcessProposal`'s verdict (state.go:1382). */
    bool                  process_accept;
    /** When set, the next block `tc_create_proposal_block` makes has its
     *  AppHash changed after `MakeBlock` and before it is registered —
     *  state_test.go:210-216, which is the only way that test can make a
     *  block `validateBlock` refuses. */
    bool                  tamper_app_hash;
    int                   process_calls;
    int                   create_calls;
    int                   validate_calls;
    int                   apply_calls;
    /** WHICH block the last `apply_verified_block` committed, and at what
     *  height — the C answer to `ensureNewBlockHeader` (common_test.go:
     *  624-641), which asserts the committed header's height AND its
     *  hash. Without these a scenario could only count commits, and a
     *  regression that committed the WRONG block would pass. */
    uint8_t               applied_hash[CMT_TMHASH_SIZE];
    size_t                applied_hash_len;
    int64_t               applied_height;
    int                   extend_calls;
    int                   verify_ext_calls;
    /** The addresses `verify_vote_extension` was called for, in call
     *  order — the C answer to `m.AssertCalled(t, "VerifyVoteExtension"
     *  …)` (state_test.go:1566). */
    uint8_t               verify_ext_addr[TC_MAX_VALS * 4][CMT_ADDRESS_SIZE];
    size_t                verify_ext_len;
    /** What `ExtendVote` answers (state_test.go:1499-1501's mock returns
     *  "extension"; :1664-1666's returns `voteExtensions[0]`). Static
     *  storage duration, never the arena's: `tc_extend_vote` COPIES it
     *  into the arena, which is what OWNERSHIP (2) asks for. Defaulted by
     *  `tc_setup` to `tc_ext_bytes`; a scenario may point it elsewhere. */
    const uint8_t        *extend_ext;
    size_t                extend_ext_len;
    /** The `last_ext_commit` the most recent `create_proposal_block` was
     *  handed — the C answer to state_test.go:1669-1674, which captures
     *  the RequestPrepareProposal whose `LocalLastCommit` carries the
     *  previous height's extended commit (state/execution.go:127-129 feeds
     *  `lastExtCommit` into both). Copied INSIDE the callback, because
     *  cmt_cs.c frees the commit it passed the moment the callback
     *  returns; `cap_ecsigs` is heap (TC_MAX_VALS × ~4.7 KB) and every
     *  entry's extension bytes are copied into `cap_ext_bytes`, so the
     *  capture owns everything it points at. `cap_ext_ok` is false when a
     *  commit did not fit — HOW IT CAN LIE (12) says what the capture is
     *  and is not. */
    int                   cap_ext_calls;
    bool                  cap_ext_ok;
    int64_t               cap_ext_for_height;
    cmt_extended_commit_t cap_ext;
    cmt_extended_commit_sig_t *cap_ecsigs;
    uint8_t               cap_ext_bytes[TC_MAX_VALS][TC_CAP_EXT_MAX];
    /** Transactions the NEXT proposed block carries. */
    uint8_t              *next_txs[TC_MAX_TXS];
    size_t                next_txs_len[TC_MAX_TXS];
    size_t                next_txs_n;

    /* ── the evidence pool (state.go:2094) ────────────────────────── */
    int                   conflict_calls;
    cmt_vote_t           *conflict_a;
    cmt_vote_t           *conflict_b;

    /* ── the block registry ───────────────────────────────────────── */
    tc_block_rec_t       *recs;
    size_t                recs_n;
    uint8_t              *marshal_scratch;
    int                   decode_misses;

    /* ── the block store ──────────────────────────────────────────── */
    tc_store_ent_t       *store;
    int64_t               store_height;

    /* ── the WAL ──────────────────────────────────────────────────── */
    tc_wal_row_t         *wal;
    size_t                wal_len;

    /* ── scratch, because a vote is ~9.5 KB and a proposal ~4.7 KB ── */
    cmt_vote_t           *sv;
    cmt_validator_t      *val;
    cmt_proposal_t       *prop;
    cmt_block_t          *tmp_block;
    /** ⚠ HEAP, NOT STACK: a `cmt_extended_commit_sig_t` carries two
     *  4627-byte signatures, so four of them are 37 KB. */
    cmt_extended_commit_sig_t *ecsigs;
    cmt_part_t           *ext_parts;
    cmt_part_set_t       *ext_part_set;
    uint8_t              *ext_scratch;
} tc_t;

/* ══ small utilities ══════════════════════════════════════════════════ */

/** Bump-allocate from the vote-extension arena (cmt_pb.h:165-169). */
static const uint8_t *tc_arena_put(tc_t *tc, const uint8_t *src, size_t len)
{
    uint8_t *p;

    if (tc->arena == NULL || tc->arena->used + len > tc->arena->cap) {
        return NULL;
    }
    p = tc->arena->buf + tc->arena->used;
    if (len > 0u) {
        memcpy(p, src, len);
    }
    tc->arena->used += len;
    return p;
}

/** The nine bytes `signVote` attaches as a vote extension
 *  (common_test.go:143). `static const` gives them static storage
 *  duration, so they outlive every height without needing the arena —
 *  which trivially satisfies cmt_cs.h's OWNERSHIP (2) for a stub's vote
 *  and is why the arena carries only the extensions this node makes. */
static const uint8_t tc_ext_bytes[9] = {
    'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n'
};

/** cometbft@709fd12b consensus/state_test.go:1656-1661 — the
 *  `voteExtensions` table of TestPrepareProposalReceivesVoteExtensions:
 *  "extension 0" … "extension 3", one per validator INDEX, eleven bytes
 *  each. `static const` for the same OWNERSHIP (2) reason as
 *  `tc_ext_bytes`: a stub's vote points straight at these and they
 *  outlive every height. Spelled as byte lists rather than string
 *  literals so that no terminating NUL is part of the extension. */
#define TC_EXT_OF_LEN 11u
static const uint8_t tc_ext_bytes_of[TC_MAX_VALS][TC_EXT_OF_LEN] = {
    { 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', ' ', '0' },
    { 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', ' ', '1' },
    { 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', ' ', '2' },
    { 'e', 'x', 't', 'e', 'n', 's', 'i', 'o', 'n', ' ', '3' }
};

/* ══ the signer — types/priv_validator.go:73-100, MockPV.SignVote ════ */

/**
 * cometbft@709fd12b types/priv_validator.go:73-100 —
 * `(pv MockPV) SignVote()`, ported.
 *
 * THIS AND NOT `cmt_pv_sign_vote` is the reference's test signer:
 * `types/validator.go:182-196` (`RandValidator`) builds every test
 * validator with `NewMockPV()`, and MockPV keeps NO last-sign-state. The
 * FilePV port (cmt_privval.h) is therefore unexercised by this suite —
 * see HOW IT CAN LIE (5).
 *
 * The three branches are the reference's, in its order: sign the vote's
 * sign bytes (:112-117); sign the EXTENSION's sign bytes for a precommit
 * whose BlockID is not nil (:120-126); refuse an extension on anything
 * else (:127-128); and otherwise leave the extension signature empty
 * (:130).
 */
static int tc_mock_sign_vote(const uint8_t *sk,
                             const uint8_t *chain_id, size_t chain_id_len,
                             cmt_pb_vote_t *v)
{
    uint8_t sb[CMT_VOTE_SIGN_BYTES_MAX];
    uint8_t esb[CMT_VOTE_SIGN_BYTES_MAX + 64];
    size_t  sb_len  = 0u;
    size_t  sig_len = 0u;

    if (cmt_vote_sign_bytes(chain_id, chain_id_len, v,
                            sb, sizeof(sb), &sb_len) != CMT_OK) {
        return CMT_FAULT;                                       /* :112 */
    }
    if (qgp_dsa87_sign(v->signature, &sig_len, sb, sb_len, sk) != 0) {
        return CMT_FAULT;                                       /* :114 */
    }
    v->signature_len = sig_len;                                 /* :117 */

    if (v->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT &&
        !cmt_proto_block_id_is_nil(&v->block_id)) {             /* :121 */
        size_t esb_len = 0u;
        size_t esig_len = 0u;

        if (cmt_vote_extension_sign_bytes(chain_id, chain_id_len, v,
                                          esb, sizeof(esb),
                                          &esb_len) != CMT_OK) {
            return CMT_FAULT;                                   /* :122 */
        }
        if (qgp_dsa87_sign(v->extension_signature, &esig_len,
                           esb, esb_len, sk) != 0) {
            return CMT_FAULT;                                   /* :123 */
        }
        v->extension_signature_len = esig_len;
    } else if (v->extension.len > 0u) {                         /* :127 */
        /* ":128 unexpected vote extension - vote extensions are only
         * allowed in non-nil precommits". */
        return CMT_REJECT;
    } else {
        v->extension_signature_len = 0u;                        /* :130 */
    }
    return CMT_OK;
}

/* ══ the host: sm.BlockExecutor ═══════════════════════════════════════ */

/** Take a free record from the registry. */
static tc_block_rec_t *tc_rec_take(tc_t *tc)
{
    if (tc->recs_n >= (size_t)TC_BLOCK_RECS) {
        return NULL;
    }
    return &tc->recs[tc->recs_n++];
}

/**
 * Marshal `rec->block` and remember the bytes, so that
 * `tc_decode_block` can recognise the same block when the part set is
 * re-assembled on the receiving side.
 */
static int tc_rec_register(tc_t *tc, tc_block_rec_t *rec)
{
    size_t len = 0u;

    if (cmt_block_marshal(&rec->block, tc->marshal_scratch,
                          (size_t)TC_PAYLOAD_CAP, &len) != CMT_OK) {
        return CMT_FAULT;
    }
    rec->marshal = (uint8_t *)malloc(len == 0u ? 1u : len);
    if (rec->marshal == NULL) {
        return CMT_FAULT;
    }
    memcpy(rec->marshal, tc->marshal_scratch, len);
    rec->marshal_len = len;
    if (cmt_block_hash(&rec->block, rec->hash) != CMT_OK) {
        return CMT_FAULT;
    }
    rec->used = true;
    return CMT_OK;
}

/**
 * cometbft@709fd12b state/execution.go:101-159 —
 * `BlockExecutor.CreateProposalBlock`, reduced to its two load-bearing
 * lines: `commit := lastExtCommit.ToCommit()` (:127) and
 * `state.MakeBlock(height, txs, commit, evidence, proposerAddr)` (:128).
 *
 * NOT reproduced: `PendingEvidence` (:117 — this fixture has no evidence
 * pool, so every block is evidence-free), `ReapMaxBytesMaxGas` (:124 —
 * the transactions are whatever `tc_set_next_txs` last supplied),
 * `PrepareProposal` (:129 — the reference's second `MakeBlock` at :158
 * exists only to rebuild the block from what the application returned,
 * and an application that returns its input unchanged makes the two
 * calls identical) and `MaxDataBytes` (:123).
 */
static int tc_create_proposal_block(void *ctx, int64_t height,
                                    const cmt_state_t *state,
                                    const cmt_extended_commit_t *last_ext,
                                    const uint8_t *proposer_addr,
                                    size_t proposer_addr_len,
                                    cmt_block_t *out)
{
    tc_t               *tc = (tc_t *)ctx;
    tc_block_rec_t     *rec;
    cmt_data_t          data;
    cmt_evidence_data_t ev;
    size_t              i;
    size_t              off;

    tc->create_calls++;
    rec = tc_rec_take(tc);
    if (rec == NULL) {
        return CMT_FAULT;
    }

    /* state_test.go:1669-1674 — capture what the proposer was handed, so
     * that a scenario can assert the previous height's extensions ARRIVED
     * here (:1727-1744). Copied now: the caller frees `last_ext` on return
     * (cmt_cs.c, `cs_create_proposal_block`). Not the reference's
     * behaviour — instrumentation, and it changes nothing the state
     * machine sees. HOW IT CAN LIE (12) says what it records. */
    tc->cap_ext_calls++;
    tc->cap_ext_for_height = height;
    tc->cap_ext_ok = cmt_extended_commit_clone(last_ext, tc->cap_ecsigs,
                                               (size_t)TC_MAX_VALS,
                                               &tc->cap_ext) == CMT_OK;
    for (i = 0u; tc->cap_ext_ok && i < tc->cap_ext.extended_signatures_len;
         i++) {
        cmt_extended_commit_sig_t *e = &tc->cap_ecsigs[i];

        if (e->extension.len > (size_t)TC_CAP_EXT_MAX) {
            tc->cap_ext_ok = false;
            break;
        }
        if (e->extension.len > 0u) {
            memcpy(tc->cap_ext_bytes[i], e->extension.data, e->extension.len);
        }
        e->extension.data = tc->cap_ext_bytes[i];
    }

    /* :127 — ToCommit(). The commit lives in the record, because the
     * block will point at it for as long as the slot is named. */
    if (cmt_extended_commit_to_commit(last_ext, rec->sigs,
                                      (size_t)TC_MAX_VALS,
                                      &rec->last_commit) != CMT_OK) {
        return CMT_FAULT;
    }

    off = 0u;
    for (i = 0u; i < tc->next_txs_n && i < (size_t)TC_MAX_TXS; i++) {
        size_t n = tc->next_txs_len[i];

        if (off + n > rec->tx_storage_cap) {
            return CMT_FAULT;
        }
        memcpy(rec->tx_storage + off, tc->next_txs[i], n);
        rec->txs[i].data = rec->tx_storage + off;
        rec->txs[i].len  = n;
        off += n;
    }
    memset(&data, 0, sizeof(data));
    data.txs     = rec->txs;
    data.txs_cap = (size_t)TC_MAX_TXS;
    data.txs_len = (tc->next_txs_n < (size_t)TC_MAX_TXS)
                   ? tc->next_txs_n : (size_t)TC_MAX_TXS;
    memset(&ev, 0, sizeof(ev));

    /* :128 — state.MakeBlock, which is cmt_state_make_block. */
    if (cmt_state_make_block(state, height, &data, &rec->last_commit, &ev,
                             proposer_addr, proposer_addr_len,
                             tc->blkscratch, &rec->block) != CMT_OK) {
        return CMT_FAULT;
    }
    /* state_test.go:211-216 — "make the block bad by tampering with
     * statehash". The reference replaces an EMPTY AppHash with a
     * zero-filled one first (:212-214), which is what this does: the
     * genesis AppHash here is empty, so a tampered block carries a
     * full-width hash where the state carries none. */
    if (tc->tamper_app_hash) {
        memset(rec->block.header.app_hash, 0,
               sizeof(rec->block.header.app_hash));
        rec->block.header.app_hash[0]  = 1u;
        rec->block.header.app_hash_len = (size_t)CMT_TMHASH_SIZE;
    }
    if (tc_rec_register(tc, rec) != CMT_OK) {
        return CMT_FAULT;
    }
    *out = rec->block;
    return CMT_OK;
}

/**
 * cometbft@709fd12b state/execution.go:161-190 —
 * `BlockExecutor.ProcessProposal`, as the mock application of
 * state_test.go:1452 is: it returns a verdict the scenario chose, and
 * counts the call.
 */
static int tc_process_proposal(void *ctx, cmt_block_t *block,
                               const cmt_state_t *state, bool *out_accept)
{
    tc_t *tc = (tc_t *)ctx;

    (void)block;
    (void)state;
    tc->process_calls++;
    *out_accept = tc->process_accept;
    return CMT_OK;
}

/**
 * cometbft@709fd12b state/validation.go:16-150 — `validateBlock`, in the
 * reference's own order, minus the two checks named in HOW IT CAN LIE (3).
 */
static int tc_validate_block(void *ctx, const cmt_state_t *state,
                             cmt_block_t *block)
{
    tc_t    *tc = (tc_t *)ctx;
    uint8_t  h[CMT_TMHASH_SIZE];

    tc->validate_calls++;

    /* :18-21 — internal consistency. */
    if (cmt_block_validate_basic(block, state->version.consensus.block)
            != CMT_OK) {
        return CMT_REJECT;
    }
    /* :24-29 — the version. */
    if (block->header.version.app != state->version.consensus.app ||
        block->header.version.block != state->version.consensus.block) {
        return CMT_REJECT;
    }
    /* :31-35 — the chain id. */
    if (block->header.chain_id_len != state->chain_id_len ||
        memcmp(block->header.chain_id, state->chain_id,
               state->chain_id_len) != 0) {
        return CMT_REJECT;
    }
    /* :37-47 — the height. */
    if (state->last_block_height == 0) {
        if (block->header.height != state->initial_height) {
            return CMT_REJECT;
        }
    } else if (block->header.height != state->last_block_height + 1) {
        return CMT_REJECT;
    }
    /* :50-55 — the previous block. */
    if (!cmt_block_id_equals(&block->header.last_block_id,
                             &state->last_block_id)) {
        return CMT_REJECT;
    }
    /* :58-62 — the app hash. THIS is the check TestStateBadProposal
     * (state_test.go:210-216) tampers its way into. */
    if (block->header.app_hash_len != state->app_hash_len ||
        memcmp(block->header.app_hash, state->app_hash,
               state->app_hash_len) != 0) {
        return CMT_REJECT;
    }
    /* :64-68 — the consensus params. */
    if (cmt_consensus_params_hash(&state->consensus_params, h) != CMT_OK) {
        return CMT_FAULT;
    }
    if (block->header.consensus_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(block->header.consensus_hash, h,
               (size_t)CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    /* :70-74 — the last results. */
    if (block->header.last_results_hash_len != state->last_results_hash_len ||
        memcmp(block->header.last_results_hash, state->last_results_hash,
               state->last_results_hash_len) != 0) {
        return CMT_REJECT;
    }
    /* :76-88 — the two validator set hashes. */
    if (cmt_validator_set_hash(&state->validators,
                               tc->blkscratch->leaves,
                               sizeof(tc->blkscratch->leaves),
                               tc->blkscratch->items,
                               (size_t)CMT_VALSET_MAX, h) != CMT_OK) {
        return CMT_FAULT;
    }
    if (block->header.validators_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(block->header.validators_hash, h,
               (size_t)CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    if (cmt_validator_set_hash(&state->next_validators,
                               tc->blkscratch->leaves,
                               sizeof(tc->blkscratch->leaves),
                               tc->blkscratch->items,
                               (size_t)CMT_VALSET_MAX, h) != CMT_OK) {
        return CMT_FAULT;
    }
    if (block->header.next_validators_hash_len != (size_t)CMT_TMHASH_SIZE ||
        memcmp(block->header.next_validators_hash, h,
               (size_t)CMT_TMHASH_SIZE) != 0) {
        return CMT_REJECT;
    }
    /* :86-95 — the LastCommit. The initial-height branch (:86-90) is
     * performed; the VerifyCommit branch (:91-95) is NOT — HOW IT CAN
     * LIE (3). */
    if (block->header.height == state->initial_height) {
        if (block->last_commit == NULL ||
            block->last_commit->signatures_len != 0u) {
            return CMT_REJECT;
        }
    }
    /* :104-118 — the proposer. */
    if (block->header.proposer_address_len != (size_t)CMT_ADDRESS_SIZE) {
        return CMT_REJECT;
    }
    if (!cmt_validator_set_has_address(&state->validators,
                                       block->header.proposer_address,
                                       block->header.proposer_address_len)) {
        return CMT_REJECT;
    }
    /* :120-140 — the block time. */
    if (block->header.height > state->initial_height) {
        cmt_time_t median;

        if (cmt_time_unix_nano(block->header.time) <=
            cmt_time_unix_nano(state->last_block_time)) {
            return CMT_REJECT;                                  /* :123 */
        }
        if (cmt_state_median_time(block->last_commit,
                                  &state->last_validators,
                                  &median) != CMT_OK) {
            return CMT_FAULT;                                   /* :129 */
        }
        if (median.seconds != block->header.time.seconds ||
            median.nanos != block->header.time.nanos) {
            return CMT_REJECT;                                  /* :131 */
        }
    } else if (block->header.height == state->initial_height) {
        if (block->header.time.seconds != state->last_block_time.seconds ||
            block->header.time.nanos != state->last_block_time.nanos) {
            return CMT_REJECT;                              /* :139-143 */
        }
    }
    return CMT_OK;
}

/**
 * cometbft@709fd12b state/execution.go — `ApplyVerifiedBlock`, whose
 * state transition is `updateState` (the `func updateState(` body).
 *
 * The rotation is exactly the reference's, and it is the whole reason
 * this row cannot be a stub: `Validators ← NextValidators`,
 * `LastValidators ← Validators`, `NextValidators ←
 * NextValidators.IncrementProposerPriority(1)`. Get it wrong and the
 * proposer of the next height is wrong, and every proposer assertion in
 * the suite passes or fails for the wrong reason.
 *
 * NOT reproduced: the ABCI FinalizeBlock round trip, so `AppHash` and
 * `LastResultsHash` are left where they were — HOW IT CAN LIE (2) — and
 * there are never validator updates, so `lastHeightValidatorsChanged`
 * never moves.
 */
static int tc_apply_verified_block(void *ctx, const cmt_block_id_t *block_id,
                                   cmt_block_t *block,
                                   cmt_state_t *in_out_state)
{
    tc_t *tc = (tc_t *)ctx;

    tc->apply_calls++;
    /* Record WHAT was committed, not just that something was. `block_id`
     * is the one `finalizeCommit` built from the block it is applying
     * (state.go:1778-1781), so this is the committed block's identity. */
    tc->applied_height   = block->header.height;
    tc->applied_hash_len = 0u;
    if (block_id != NULL && block_id->hash_len == (size_t)CMT_TMHASH_SIZE) {
        memcpy(tc->applied_hash, block_id->hash, (size_t)CMT_TMHASH_SIZE);
        tc->applied_hash_len = (size_t)CMT_TMHASH_SIZE;
    }

    /* `LastValidators = state.Validators.Copy()` — taken FIRST, because
     * the next line overwrites `validators`. */
    if (cmt_validator_set_copy(&in_out_state->validators,
                               &in_out_state->last_validators) != CMT_OK) {
        return CMT_FAULT;
    }
    /* `Validators = state.NextValidators.Copy()`. */
    if (cmt_validator_set_copy(&in_out_state->next_validators,
                               &in_out_state->validators) != CMT_OK) {
        return CMT_FAULT;
    }
    /* `nValSet := state.NextValidators.Copy(); …
     *  nValSet.IncrementProposerPriority(1)` — in place, since the copy
     *  it protected has already been taken. */
    if (cmt_validator_set_increment_proposer_priority(
            &in_out_state->next_validators, 1) != CMT_OK) {
        return CMT_FAULT;
    }

    in_out_state->last_block_height = block->header.height;
    in_out_state->last_block_id     = *block_id;
    in_out_state->last_block_time   = block->header.time;
    return CMT_OK;
}

/**
 * cometbft@709fd12b consensus/state.go:2400 —
 * `blockExec.ExtendVote(ctx, vote, block, state)`, as the mock of
 * state_test.go:1499-1501 is: it returns the nine bytes "extension" —
 * or, for the one scenario that installs a different answer
 * (:1664-1666, `voteExtensions[0]`), whatever `tc->extend_ext` names.
 *
 * The bytes go in the ARENA, which is what cmt_cs.h's OWNERSHIP (2)
 * requires: `cmt_vote_copy` shares an extension's bytes into every vote
 * set the vote reaches.
 */
static int tc_extend_vote(void *ctx, const cmt_vote_t *vote,
                          cmt_block_t *block, const cmt_state_t *state,
                          cmt_pb_bytes_t *out_ext)
{
    tc_t          *tc = (tc_t *)ctx;
    const uint8_t *p;

    (void)vote;
    (void)block;
    (void)state;
    tc->extend_calls++;
    p = tc_arena_put(tc, tc->extend_ext, tc->extend_ext_len);
    if (p == NULL) {
        return CMT_FAULT;
    }
    out_ext->data = p;
    out_ext->len  = tc->extend_ext_len;
    return CMT_OK;
}

/**
 * cometbft@709fd12b consensus/state.go:2210 —
 * `blockExec.VerifyVoteExtension(ctx, vote)`, as the always-ACCEPT mock
 * of state_test.go:1502-1504 is. The validator address of every call is
 * recorded, which is how a scenario answers the reference's
 * `m.AssertCalled(t, "VerifyVoteExtension", …)` (:1566-1571) and its
 * `AssertNotCalled` twin (:1640-1645).
 */
static int tc_verify_vote_extension(void *ctx, const cmt_vote_t *vote)
{
    tc_t *tc = (tc_t *)ctx;

    tc->verify_ext_calls++;
    if (tc->verify_ext_len < (size_t)(TC_MAX_VALS * 4) &&
        vote->validator_address_len == (size_t)CMT_ADDRESS_SIZE) {
        memcpy(tc->verify_ext_addr[tc->verify_ext_len],
               vote->validator_address, (size_t)CMT_ADDRESS_SIZE);
        tc->verify_ext_len++;
    }
    return CMT_OK;
}

/** Was `verify_vote_extension` ever called for validator `index`? The C
 *  answer to `m.AssertNotCalled(t, "VerifyVoteExtension",
 *  &abci.RequestVerifyVoteExtension{… ValidatorAddress: addr …})`
 *  (state_test.go:1640-1645): the mock matches on the whole request, of
 *  which the address is the field that names the validator; the port has
 *  no request object, so the address alone is what is recorded and
 *  compared. */
static bool tc_verify_ext_called_for(const tc_t *tc, size_t index)
{
    size_t i;

    if (index >= tc->nvals) {
        return false;
    }
    for (i = 0u; i < tc->verify_ext_len; i++) {
        if (memcmp(tc->verify_ext_addr[i], tc->addr[index],
                   (size_t)CMT_ADDRESS_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

/* ══ the host: sm.BlockStore ══════════════════════════════════════════ */

static tc_store_ent_t *tc_store_at(tc_t *tc, int64_t height)
{
    if (height < 1 || height > (int64_t)TC_STORE_MAX) {
        return NULL;
    }
    return &tc->store[height - 1];
}

/** state.go:309, :1730 — `blockStore.Height()`. */
static int tc_bs_height(void *ctx, int64_t *out)
{
    tc_t *tc = (tc_t *)ctx;

    *out = tc->store_height;
    return CMT_OK;
}

/** state.go:313, :629 — `blockStore.LoadBlockCommit(height)`: the commit
 *  for `height`, which the store learns from block `height+1`'s
 *  LastCommit. */
static int tc_bs_load_block_commit(void *ctx, int64_t height,
                                   cmt_commit_t *out, bool *out_found)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e  = tc_store_at(tc, height);

    *out_found = false;
    if (e == NULL || !e->has_commit) {
        return CMT_OK;
    }
    *out       = e->commit;
    *out_found = true;
    return CMT_OK;
}

/** state.go:611 — `blockStore.LoadBlockExtendedCommit(height)`. */
static int tc_bs_load_block_extended_commit(void *ctx, int64_t height,
                                            cmt_extended_commit_t *out,
                                            bool *out_found)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e  = tc_store_at(tc, height);

    *out_found = false;
    if (e == NULL || !e->has_ext) {
        return CMT_OK;
    }
    *out       = e->ext;
    *out_found = true;
    return CMT_OK;
}

/** state.go:1124 — `blockStore.LoadBlockMeta(height)`, of which the
 *  ported code reads exactly `Header.AppHash` (:1131). */
static int tc_bs_load_block_meta(void *ctx, int64_t height,
                                 cmt_header_t *out, bool *out_found)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e  = tc_store_at(tc, height);

    *out_found = false;
    if (e == NULL || !e->saved) {
        return CMT_OK;
    }
    *out       = e->header;
    *out_found = true;
    return CMT_OK;
}

/** state.go:310, :627, :2502 — `blockStore.LoadSeenCommit(height)`. */
static int tc_bs_load_seen_commit(void *ctx, int64_t height,
                                  cmt_commit_t *out, bool *out_found)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e  = tc_store_at(tc, height);

    *out_found = false;
    if (e == NULL || !e->has_seen) {
        return CMT_OK;
    }
    *out       = e->seen;
    *out_found = true;
    return CMT_OK;
}

/** The half of `store.SaveBlock` both save rows share: the header, the
 *  height, and the previous height's commit taken from this block's
 *  LastCommit. */
static int tc_store_put_block(tc_t *tc, cmt_block_t *block)
{
    tc_store_ent_t *e = tc_store_at(tc, block->header.height);

    if (e == NULL) {
        return CMT_FAULT;
    }
    e->saved  = true;
    e->height = block->header.height;
    e->header = block->header;
    if (block->header.height > tc->store_height) {
        tc->store_height = block->header.height;
    }
    if (block->last_commit != NULL &&
        block->last_commit->signatures_len > 0u) {
        tc_store_ent_t *prev = tc_store_at(tc, block->header.height - 1);

        if (prev != NULL) {
            size_t n = block->last_commit->signatures_len;

            if (n > (size_t)TC_MAX_VALS) {
                return CMT_FAULT;
            }
            memcpy(prev->commit_sigs, block->last_commit->signatures,
                   n * sizeof(prev->commit_sigs[0]));
            prev->commit                = *block->last_commit;
            prev->commit.signatures     = prev->commit_sigs;
            prev->commit.signatures_cap = (size_t)TC_MAX_VALS;
            prev->commit.signatures_len = n;
            prev->has_commit            = true;
        }
    }
    return CMT_OK;
}

/** state.go:1737 — `blockStore.SaveBlock(block, blockParts, seenCommit)`. */
static int tc_bs_save_block(void *ctx, cmt_block_t *block,
                            const cmt_part_set_t *parts,
                            const cmt_commit_t *seen_commit)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e;
    size_t          n;

    (void)parts;
    if (tc_store_put_block(tc, block) != CMT_OK) {
        return CMT_FAULT;
    }
    e = tc_store_at(tc, block->header.height);
    n = seen_commit->signatures_len;
    if (n > (size_t)TC_MAX_VALS) {
        return CMT_FAULT;
    }
    if (n > 0u) {
        memcpy(e->seen_sigs, seen_commit->signatures,
               n * sizeof(e->seen_sigs[0]));
    }
    e->seen                = *seen_commit;
    e->seen.signatures     = e->seen_sigs;
    e->seen.signatures_cap = (size_t)TC_MAX_VALS;
    e->seen.signatures_len = n;
    e->has_seen            = true;
    return CMT_OK;
}

/** state.go:1735 — `blockStore.SaveBlockWithExtendedCommit(...)`. The
 *  extended signatures are copied; each entry's EXTENSION still points
 *  into the arena, which outlives the fixture (HOW IT CAN LIE (6)). */
static int tc_bs_save_block_with_extended_commit(
        void *ctx, cmt_block_t *block, const cmt_part_set_t *parts,
        const cmt_extended_commit_t *seen_ext)
{
    tc_t           *tc = (tc_t *)ctx;
    tc_store_ent_t *e;
    size_t          n;

    (void)parts;
    if (tc_store_put_block(tc, block) != CMT_OK) {
        return CMT_FAULT;
    }
    e = tc_store_at(tc, block->header.height);
    n = seen_ext->extended_signatures_len;
    if (n > (size_t)TC_MAX_VALS) {
        return CMT_FAULT;
    }
    if (n > 0u) {
        memcpy(e->ext_sigs, seen_ext->extended_signatures,
               n * sizeof(e->ext_sigs[0]));
    }
    e->ext                         = *seen_ext;
    e->ext.extended_signatures     = e->ext_sigs;
    e->ext.extended_signatures_cap = (size_t)TC_MAX_VALS;
    e->ext.extended_signatures_len = n;
    e->has_ext                     = true;
    return CMT_OK;
}

/* ══ the host: evidencePool, PrivValidator, WAL, decoder, clock ═══════ */

/** state.go:2094 — `evpool.ReportConflictingVotes(voteA, voteB)`. The
 *  reference's own evidence pool is `sm.EmptyEvidencePool{}` in these
 *  tests (common_test.go:422); this one records what it was handed, which
 *  is what the reduced byzantine scenario asserts on. */
static int tc_report_conflicting_votes(void *ctx, const cmt_vote_t *a,
                                       const cmt_vote_t *b)
{
    tc_t *tc = (tc_t *)ctx;

    tc->conflict_calls++;
    if (a != NULL) {
        *tc->conflict_a = *a;
    }
    if (b != NULL) {
        *tc->conflict_b = *b;
    }
    return CMT_OK;
}

/** The `cmt_sign_vote_fn` row (cmt_vote.h:332), backed by this node's own
 *  key through the MockPV port above. */
static int tc_sign_vote_row(void *ctx, const uint8_t *chain_id,
                            size_t chain_id_len, cmt_pb_vote_t *v)
{
    tc_t *tc = (tc_t *)ctx;

    return tc_mock_sign_vote(tc->sk[tc->self], chain_id, chain_id_len, v);
}

/** state.go:1240 — `privValidator.SignProposal(chainID, p)`.
 *  types/priv_validator.go:102-115 — `(pv MockPV) SignProposal()`. */
static int tc_sign_proposal_row(void *ctx, const uint8_t *chain_id,
                                size_t chain_id_len, cmt_proposal_t *p)
{
    tc_t   *tc = (tc_t *)ctx;
    uint8_t sb[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t  sb_len  = 0u;
    size_t  sig_len = 0u;

    if (cmt_proposal_sign_bytes(chain_id, chain_id_len, p,
                                sb, sizeof(sb), &sb_len) != CMT_OK) {
        return CMT_FAULT;
    }
    if (qgp_dsa87_sign(p->signature, &sig_len, sb, sb_len,
                       tc->sk[tc->self]) != 0) {
        return CMT_FAULT;
    }
    p->signature_len = sig_len;
    return CMT_OK;
}

/** state.go:2484 — `privValidator.GetPubKey()`. */
static int tc_get_pub_key(void *ctx, cmt_pb_public_key_t *out)
{
    tc_t *tc = (tc_t *)ctx;

    out->present = true;
    memcpy(out->key, tc->pk[tc->self], (size_t)CMT_PB_PUBKEY_LEN);
    return CMT_OK;
}

/** Record one WAL row; the shared half of the three write callbacks. */
static void tc_wal_record(tc_t *tc, const cmt_wal_message_t *msg, bool sync)
{
    tc_wal_row_t *r;

    if (tc->wal_len >= (size_t)TC_WAL_MAX || msg == NULL) {
        return;
    }
    r = &tc->wal[tc->wal_len++];
    memset(r, 0, sizeof(*r));
    r->kind = (int)msg->kind;
    r->sync = sync;
    if (msg->kind == CMT_PB_WAL_MSG_INFO) {
        r->msg_kind = (int)msg->u.msg_info.msg.kind;
        if (msg->u.msg_info.msg.kind == CMT_PB_CONS_MSG_VOTE) {
            r->vote_type = msg->u.msg_info.msg.u.vote.vote.type;
            r->height    = msg->u.msg_info.msg.u.vote.vote.height;
            r->round     = msg->u.msg_info.msg.u.vote.vote.round;
        } else if (msg->u.msg_info.msg.kind == CMT_PB_CONS_MSG_PROPOSAL) {
            r->height = msg->u.msg_info.msg.u.proposal.proposal.height;
            r->round  = msg->u.msg_info.msg.u.proposal.proposal.round;
        }
    } else if (msg->kind == CMT_PB_WAL_TIMEOUT_INFO) {
        r->height = msg->u.timeout_info.height;
        r->round  = msg->u.timeout_info.round;
    }
}

/** state.go:760, :831, :859 — `wal.Write(...)`. */
static int tc_wal_write(void *ctx, const cmt_wal_message_t *msg)
{
    tc_wal_record((tc_t *)ctx, msg, false);
    return CMT_OK;
}

/** state.go:839, :1760 — `wal.WriteSync(...)`. */
static int tc_wal_write_sync(void *ctx, const cmt_wal_message_t *msg)
{
    tc_wal_record((tc_t *)ctx, msg, true);
    return CMT_OK;
}

/** state.go:1232, :2374 — `wal.FlushAndSync()`. */
static int tc_wal_flush_and_sync(void *ctx)
{
    (void)ctx;
    return CMT_OK;
}

/** replay.go:106, :129 — `wal.SearchForEndHeight(...)`. No scenario here
 *  replays; wave R2-C's `t_catchup_replay` covers the END_HEIGHT rule. */
static int tc_wal_search_end_height(void *ctx, int64_t height, bool *out_found)
{
    (void)ctx;
    (void)height;
    *out_found = false;
    return CMT_OK;
}

/** replay.go:147 — `dec.Decode()`. */
static int tc_wal_read_next(void *ctx, cmt_timed_wal_message_t *out,
                            bool *out_eof)
{
    (void)ctx;
    (void)out;
    *out_eof = true;
    return CMT_OK;
}

/**
 * state.go:2005-2019 — `io.ReadAll` + `proto.Unmarshal` +
 * `types.BlockFromProto`, as ONE row because cmt_pb.h:1043 says this tree
 * has no block wire decoder.
 *
 * ⚠ A REGISTRY LOOKUP, NOT A DECODE — HOW IT CAN LIE (1). The bytes are
 * compared against the marshalled form of every block this fixture made;
 * a hit hands back that block, a miss is the reference's decode error
 * (CMT_REJECT).
 */
static int tc_decode_block(void *ctx, const uint8_t *bytes, size_t len,
                           cmt_block_t *out)
{
    tc_t  *tc = (tc_t *)ctx;
    size_t i;

    for (i = 0u; i < tc->recs_n; i++) {
        tc_block_rec_t *rec = &tc->recs[i];

        if (rec->used && rec->marshal_len == len &&
            memcmp(rec->marshal, bytes, len) == 0) {
            *out = rec->block;
            return CMT_OK;
        }
    }
    tc->decode_misses++;
    return CMT_REJECT;
}

/** THE ONLY CLOCK. cmt_cs.h names its five call sites plus the proposal
 *  stamp; this returns a value the scenario sets and never advances by
 *  itself. */
static int tc_now(void *ctx, cmt_time_t *out)
{
    tc_t *tc = (tc_t *)ctx;

    tc->now_calls++;
    *out = tc->now;
    return CMT_OK;
}

/** ticker.go:126 — `ticker.timer.Reset(ti.Duration)`. */
static int tc_timer_arm(void *ctx, int64_t duration_ns)
{
    tc_t *tc = (tc_t *)ctx;

    tc->arm_calls++;
    tc->armed    = true;
    tc->armed_ns = duration_ns;
    return CMT_OK;
}

/** ticker.go:83-92 — `ticker.stopTimer()`, including the discard of an
 *  expiry that already happened. */
static int tc_timer_disarm(void *ctx)
{
    tc_t *tc = (tc_t *)ctx;

    tc->disarm_calls++;
    tc->armed = false;
    return CMT_OK;
}

/** Fill every row of `cmt_cs_host_t`. A row left NULL would be CMT_FAULT
 *  the first time it were reached (cmt_cs.h:325-330), so all 26 are
 *  wired even where no ported scenario reaches them. */
static void tc_build_host(cmt_cs_host_t *h)
{
    memset(h, 0, sizeof(*h));
    h->create_proposal_block              = tc_create_proposal_block;
    h->process_proposal                   = tc_process_proposal;
    h->validate_block                     = tc_validate_block;
    h->apply_verified_block               = tc_apply_verified_block;
    h->extend_vote                        = tc_extend_vote;
    h->verify_vote_extension              = tc_verify_vote_extension;
    h->bs_height                          = tc_bs_height;
    h->bs_load_block_commit               = tc_bs_load_block_commit;
    h->bs_load_block_extended_commit      = tc_bs_load_block_extended_commit;
    h->bs_load_block_meta                 = tc_bs_load_block_meta;
    h->bs_load_seen_commit                = tc_bs_load_seen_commit;
    h->bs_save_block                      = tc_bs_save_block;
    h->bs_save_block_with_extended_commit =
            tc_bs_save_block_with_extended_commit;
    h->report_conflicting_votes           = tc_report_conflicting_votes;
    h->sign_vote                          = tc_sign_vote_row;
    h->sign_proposal                      = tc_sign_proposal_row;
    h->get_pub_key                        = tc_get_pub_key;
    h->wal_write                          = tc_wal_write;
    h->wal_write_sync                     = tc_wal_write_sync;
    h->wal_flush_and_sync                 = tc_wal_flush_and_sync;
    h->wal_search_end_height              = tc_wal_search_end_height;
    h->wal_read_next                      = tc_wal_read_next;
    h->decode_block                       = tc_decode_block;
    h->now                                = tc_now;
    h->timer_arm                          = tc_timer_arm;
    h->timer_disarm                       = tc_timer_disarm;
}

/* ══ construction ═════════════════════════════════════════════════════ */

static void tc_teardown(tc_t *tc);

/**
 * cometbft@709fd12b consensus/common_test.go:878-902 (`randGenesisDoc`),
 * :904-913 (`randGenesisState`), :476-495 (`randStateWithAppImpl`) and
 * :392-447 (`newStateWithConfigAndBlockStore`) as one function.
 *
 * ── THE ONE DELIBERATE DIFFERENCE, AND WHY IT CHANGES NOTHING ──────────
 * The reference generates each validator with `types.RandValidator`
 * (types/validator.go:182-196), leaves the genesis document's validator
 * LIST in generation order, and sorts only the PRIVATE validators by
 * address (common_test.go:893). `NewValidatorSet` then sorts the set by
 * `ValidatorsByVotingPower` (types/validator_set.go:851-856) — voting
 * power descending, address ascending on a tie — so with every power
 * equal to `testMinPower` (:80) the set ends up in address order, which
 * is the order `privValidators` was sorted into. That is what makes
 * `vss[i]` the validator at index `i`.
 * This fixture derives its keys from fixed seeds and SORTS THE DOCUMENT
 * ITSELF by address before building the state. The resulting set is the
 * same set in the same order — the sort key is identical and the powers
 * are equal — and `tc->vss[i]` is index `i` for the same reason.
 *
 * @param nvals 1..TC_MAX_VALS.
 * @param vote_extensions_enable_height the reference's
 *        `randStateWithAppWithHeight` parameter (:462-470); 0 disables.
 * @param block_max_bytes 0 means "the params.go:99 default"; a scenario
 *        that needs the oversized-block path passes its own, exactly as
 *        state_test.go:277 does.
 * @return 0 on success, 1 on failure (already reported).
 */
static int tc_setup(tc_t *tc, size_t nvals,
                    int64_t vote_extensions_enable_height,
                    int64_t block_max_bytes)
{
    cmt_cs_host_t     host;
    cmt_genesis_doc_t doc;
    size_t            i;
    size_t            j;
    size_t            order[TC_MAX_VALS];

    memset(tc, 0, sizeof(*tc));
    if (nvals == 0u || nvals > (size_t)TC_MAX_VALS) {
        fprintf(stderr, "tc_setup: nvals %zu out of range\n", nvals);
        return 1;
    }
    tc->nvals = nvals;
    tc->self  = 0u;

    tc->pk = (uint8_t (*)[QGP_DSA87_PUBLICKEYBYTES])
             calloc((size_t)TC_MAX_VALS, (size_t)QGP_DSA87_PUBLICKEYBYTES);
    tc->sk = (uint8_t (*)[QGP_DSA87_SECRETKEYBYTES])
             calloc((size_t)TC_MAX_VALS, (size_t)QGP_DSA87_SECRETKEYBYTES);
    tc->valscratch   = (cmt_valset_scratch_t *)calloc(1u,
                            sizeof(*tc->valscratch));
    tc->blkscratch   = (cmt_state_block_scratch_t *)calloc(1u,
                            sizeof(*tc->blkscratch));
    tc->stor_gen     = (cmt_state_storage_t *)calloc(1u, sizeof(*tc->stor_gen));
    tc->stor_cs      = (cmt_state_storage_t *)calloc(1u, sizeof(*tc->stor_cs));
    tc->stor_scratch = (cmt_state_storage_t *)calloc(1u,
                            sizeof(*tc->stor_scratch));
    tc->genesis      = (cmt_state_t *)calloc(1u, sizeof(*tc->genesis));
    tc->cs           = (cmt_cs_t *)calloc(1u, sizeof(*tc->cs));
    tc->slots        = (cmt_cs_slots_t *)calloc(1u, sizeof(*tc->slots));
    tc->arena        = (cmt_pb_arena_t *)calloc(1u, sizeof(*tc->arena));
    tc->recs         = (tc_block_rec_t *)calloc((size_t)TC_BLOCK_RECS,
                            sizeof(*tc->recs));
    tc->store        = (tc_store_ent_t *)calloc((size_t)TC_STORE_MAX,
                            sizeof(*tc->store));
    tc->wal          = (tc_wal_row_t *)calloc((size_t)TC_WAL_MAX,
                            sizeof(*tc->wal));
    tc->sv           = (cmt_vote_t *)calloc(1u, sizeof(*tc->sv));
    tc->val          = (cmt_validator_t *)calloc(1u, sizeof(*tc->val));
    tc->prop         = (cmt_proposal_t *)calloc(1u, sizeof(*tc->prop));
    tc->tmp_block    = (cmt_block_t *)calloc(1u, sizeof(*tc->tmp_block));
    tc->ecsigs       = (cmt_extended_commit_sig_t *)calloc(
                            (size_t)TC_MAX_VALS,
                            sizeof(cmt_extended_commit_sig_t));
    tc->cap_ecsigs   = (cmt_extended_commit_sig_t *)calloc(
                            (size_t)TC_MAX_VALS,
                            sizeof(cmt_extended_commit_sig_t));
    tc->conflict_a   = (cmt_vote_t *)calloc(1u, sizeof(*tc->conflict_a));
    tc->conflict_b   = (cmt_vote_t *)calloc(1u, sizeof(*tc->conflict_b));
    tc->marshal_scratch = (uint8_t *)calloc((size_t)TC_PAYLOAD_CAP, 1u);
    tc->ext_parts    = (cmt_part_t *)calloc((size_t)TC_PARTS_CAP,
                            sizeof(*tc->ext_parts));
    tc->ext_part_set = (cmt_part_set_t *)calloc(1u, sizeof(*tc->ext_part_set));
    tc->ext_scratch  = (uint8_t *)calloc((size_t)TC_PAYLOAD_CAP, 1u);
    if (tc->pk == NULL || tc->sk == NULL || tc->valscratch == NULL ||
        tc->blkscratch == NULL || tc->stor_gen == NULL ||
        tc->stor_cs == NULL || tc->stor_scratch == NULL ||
        tc->genesis == NULL || tc->cs == NULL || tc->slots == NULL ||
        tc->arena == NULL || tc->recs == NULL || tc->store == NULL ||
        tc->wal == NULL || tc->sv == NULL || tc->val == NULL ||
        tc->prop == NULL || tc->tmp_block == NULL || tc->ecsigs == NULL ||
        tc->cap_ecsigs == NULL || tc->conflict_a == NULL ||
        tc->conflict_b == NULL || tc->marshal_scratch == NULL ||
        tc->ext_parts == NULL || tc->ext_part_set == NULL ||
        tc->ext_scratch == NULL) {
        fprintf(stderr, "tc_setup: out of memory\n");
        tc_teardown(tc);
        return 1;
    }

    tc->arena->buf = (uint8_t *)calloc((size_t)TC_ARENA_CAP, 1u);
    tc->arena->cap = (size_t)TC_ARENA_CAP;
    tc->arena->used = 0u;
    if (tc->arena->buf == NULL) {
        tc_teardown(tc);
        return 1;
    }
    for (i = 0u; i < (size_t)TC_BLOCK_RECS; i++) {
        tc->recs[i].tx_storage = (uint8_t *)calloc(TC_TX_MAX, 1u);
        tc->recs[i].tx_storage_cap = TC_TX_MAX;
        if (tc->recs[i].tx_storage == NULL) {
            tc_teardown(tc);
            return 1;
        }
    }
    for (i = 0u; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
        tc->slots->parts[i] = (cmt_part_t *)calloc((size_t)TC_PARTS_CAP,
                                                   sizeof(cmt_part_t));
        tc->slots->parts_cap[i]   = (size_t)TC_PARTS_CAP;
        tc->slots->payload[i]     = (uint8_t *)calloc((size_t)TC_PAYLOAD_CAP,
                                                      1u);
        tc->slots->payload_cap[i] = (size_t)TC_PAYLOAD_CAP;
        if (tc->slots->parts[i] == NULL || tc->slots->payload[i] == NULL) {
            tc_teardown(tc);
            return 1;
        }
    }
    tc->slots->marshal_parts = (cmt_part_t *)calloc((size_t)TC_PARTS_CAP,
                                                    sizeof(cmt_part_t));
    tc->slots->marshal_parts_cap   = (size_t)TC_PARTS_CAP;
    tc->slots->marshal_scratch     = (uint8_t *)calloc((size_t)TC_PAYLOAD_CAP,
                                                       1u);
    tc->slots->marshal_scratch_cap = (size_t)TC_PAYLOAD_CAP;
    if (tc->slots->marshal_parts == NULL ||
        tc->slots->marshal_scratch == NULL) {
        tc_teardown(tc);
        return 1;
    }

    /* ── keys, derandomised so the whole fixture is reproducible ──── */
    for (i = 0u; i < nvals; i++) {
        uint8_t seed[32];

        memset(seed, 0, sizeof(seed));
        seed[0] = (uint8_t)(0xA0u + i);
        seed[1] = (uint8_t)nvals;
        if (qgp_dsa87_keypair_derand(tc->pk[i], tc->sk[i], seed) != 0) {
            fprintf(stderr, "tc_setup: keypair %zu failed\n", i);
            tc_teardown(tc);
            return 1;
        }
    }
    /* Addresses, then an insertion sort by address ascending — the sort
     * `ValidatorsByVotingPower` (validator_set.go:851-856) performs on a
     * set of equal powers. Deterministic and total: the addresses are
     * 32-byte digests of distinct keys. */
    for (i = 0u; i < nvals; i++) {
        uint8_t a[CMT_ADDRESS_SIZE];

        if (cmt_pubkey_address(tc->pk[i], a) != CMT_OK) {
            tc_teardown(tc);
            return 1;
        }
        memcpy(tc->addr[i], a, sizeof(a));
        order[i] = i;
    }
    for (i = 1u; i < nvals; i++) {
        size_t key = order[i];

        j = i;
        while (j > 0u &&
               memcmp(tc->addr[order[j - 1u]], tc->addr[key],
                      (size_t)CMT_ADDRESS_SIZE) > 0) {
            order[j] = order[j - 1u];
            j--;
        }
        order[j] = key;
    }
    /* Permute the keys into address order, so index i IS stub i. */
    {
        uint8_t (*pk2)[QGP_DSA87_PUBLICKEYBYTES];
        uint8_t (*sk2)[QGP_DSA87_SECRETKEYBYTES];
        uint8_t   addr2[TC_MAX_VALS][CMT_ADDRESS_SIZE];

        pk2 = (uint8_t (*)[QGP_DSA87_PUBLICKEYBYTES])
              calloc((size_t)TC_MAX_VALS, (size_t)QGP_DSA87_PUBLICKEYBYTES);
        sk2 = (uint8_t (*)[QGP_DSA87_SECRETKEYBYTES])
              calloc((size_t)TC_MAX_VALS, (size_t)QGP_DSA87_SECRETKEYBYTES);
        if (pk2 == NULL || sk2 == NULL) {
            free(pk2);
            free(sk2);
            tc_teardown(tc);
            return 1;
        }
        for (i = 0u; i < nvals; i++) {
            memcpy(pk2[i], tc->pk[order[i]], (size_t)QGP_DSA87_PUBLICKEYBYTES);
            memcpy(sk2[i], tc->sk[order[i]], (size_t)QGP_DSA87_SECRETKEYBYTES);
            memcpy(addr2[i], tc->addr[order[i]], (size_t)CMT_ADDRESS_SIZE);
        }
        memcpy(tc->pk, pk2, (size_t)TC_MAX_VALS *
                            (size_t)QGP_DSA87_PUBLICKEYBYTES);
        memcpy(tc->sk, sk2, (size_t)TC_MAX_VALS *
                            (size_t)QGP_DSA87_SECRETKEYBYTES);
        memcpy(tc->addr, addr2, sizeof(addr2));
        free(pk2);
        free(sk2);
    }

    /* ── the stubs (common_test.go:82-88, :492) ───────────────────── */
    for (i = 0u; i < nvals; i++) {
        tc->vss[i].index    = (int32_t)i;
        /* :82-88 — `newValidatorStub` leaves Height at Go's zero, 0. The
         * next loop is :492's `incrementHeight(vss[1:]...)`, which is
         * what puts the stubs that actually vote at height 1. */
        tc->vss[i].height   = 0;
        tc->vss[i].round    = 0;
        tc->vss[i].has_last = false;
        tc->vss[i].last     = (cmt_vote_t *)calloc(1u, sizeof(cmt_vote_t));
        if (tc->vss[i].last == NULL) {
            tc_teardown(tc);
            return 1;
        }
    }
    /* :492 — `incrementHeight(vss[1:]...)`, because cs1 starts at 1 and
     * the stubs vote at the height cs1 is ABOUT to be at. The reference
     * increments every stub except vss[0]; so does this. */
    for (i = 1u; i < nvals; i++) {
        tc->vss[i].height++;
    }

    /* ── the chain id (32 raw bytes, the approved substitution) ───── */
    for (i = 0u; i < (size_t)CMT_PB_CHAINID_MAX; i++) {
        tc->chain_id[i] = (uint8_t)(0x50u + i);
    }
    tc->chain_id_len = (size_t)CMT_PB_CHAINID_MAX;
    for (i = 0u; i < (size_t)CMT_PB_PEER_ID_MAX; i++) {
        tc->peer_id[i] = (uint8_t)(0x11u + i);
    }

    /* ── consensus params ─────────────────────────────────────────── */
    cmt_default_consensus_params(&tc->params);
    tc->params.abci.vote_extensions_enable_height =
            vote_extensions_enable_height;
    /* block_max_bytes is applied AFTER MakeGenesisState, below, and not
     * here. The reference does the same: `randState` builds the state
     * with the default params and TestStateOversizedBlock then assigns
     * `cs1.state.ConsensusParams.Block.MaxBytes = maxBytes` directly
     * (state_test.go:277), never re-validating. Validating it here would
     * REFUSE the combination the test wants: ValidateBasic rejects an
     * evidence budget larger than the block budget (params.go:178-181,
     * ported at cmt_params.c:188), and the default evidence budget is
     * 1 MiB against the 64 KiB block this scenario asks for. Setting it
     * before genesis is what made this scenario fail on its first run. */

    /* ── the genesis document and state ───────────────────────────── */
    memset(&doc, 0, sizeof(doc));
    doc.genesis_time.seconds   = TC_GENESIS_SECONDS;
    doc.genesis_time.nanos     = 0;
    memcpy(doc.chain_id, tc->chain_id, tc->chain_id_len);
    doc.chain_id_len           = tc->chain_id_len;
    doc.initial_height         = 1;
    doc.has_consensus_params   = true;
    doc.consensus_params       = tc->params;
    doc.validators             = tc->gvals;
    doc.validators_cap         = (size_t)TC_MAX_VALS;
    doc.validators_len         = nvals;
    doc.app_hash_len           = 0u;
    for (i = 0u; i < nvals; i++) {
        memset(&tc->gvals[i], 0, sizeof(tc->gvals[i]));
        tc->gvals[i].pub_key.present = true;
        memcpy(tc->gvals[i].pub_key.key, tc->pk[i],
               (size_t)QGP_DSA87_PUBLICKEYBYTES);
        /* common_test.go:80 — `testMinPower = 10`, equal for all. */
        tc->gvals[i].power       = 10;
        tc->gvals[i].address_len = 0u;
    }
    if (cmt_state_init(tc->genesis, tc->stor_gen) != CMT_OK) {
        fprintf(stderr, "tc_setup: cmt_state_init failed\n");
        tc_teardown(tc);
        return 1;
    }
    if (cmt_state_make_genesis(&doc, NULL, NULL, tc->valscratch,
                               tc->genesis) != CMT_OK) {
        fprintf(stderr, "tc_setup: cmt_state_make_genesis failed\n");
        tc_teardown(tc);
        return 1;
    }
    /* state_test.go:277 — assigned onto the BUILT state, after genesis
     * and without re-validating. See the note above `cmt_default_
     * consensus_params` for why it cannot go in before. */
    if (block_max_bytes != 0) {
        tc->params.block.max_bytes                     = block_max_bytes;
        tc->genesis->consensus_params.block.max_bytes  = block_max_bytes;
    }

    /* ── the clock, frozen ────────────────────────────────────────── */
    tc->now.seconds = TC_GENESIS_SECONDS;
    tc->now.nanos   = 0;

    /* ── the application's standing answers ───────────────────────── */
    tc->process_accept = true;
    /* state_test.go:1499-1501 — ExtendVote answers "extension" unless a
     * scenario says otherwise. */
    tc->extend_ext     = tc_ext_bytes;
    tc->extend_ext_len = sizeof(tc_ext_bytes);

    /* ── the state machine (state.go:154-208, NewState) ───────────── */
    if (cmt_config_default(&tc->config) != CMT_OK) {
        tc_teardown(tc);
        return 1;
    }
    tc_build_host(&host);
    if (cmt_cs_init(tc->cs, &tc->config, tc->genesis, &host, tc,
                    tc->slots, tc->stor_cs, tc->stor_scratch,
                    tc->arena, 0) != CMT_OK) {
        fprintf(stderr, "tc_setup: cmt_cs_init failed\n");
        tc_teardown(tc);
        return 1;
    }
    /* :285-294 SetPrivValidator, which memoizes the public key at :291. */
    if (cmt_cs_set_priv_validator(tc->cs, true) != CMT_OK) {
        fprintf(stderr, "tc_setup: set_priv_validator failed\n");
        tc_teardown(tc);
        return 1;
    }
    tc->has_priv_validator = true;
    return 0;
}

/** Release everything `tc_setup` allocated. Safe on a partly-built
 *  fixture, which is why every failure path above calls it. */
static void tc_teardown(tc_t *tc)
{
    size_t i;

    if (tc == NULL) {
        return;
    }
    if (tc->cs != NULL) {
        cmt_cs_free(tc->cs);
    }
    if (tc->recs != NULL) {
        for (i = 0u; i < (size_t)TC_BLOCK_RECS; i++) {
            free(tc->recs[i].tx_storage);
            free(tc->recs[i].marshal);
        }
    }
    if (tc->slots != NULL) {
        for (i = 0u; i < (size_t)CMT_CS_BLOCK_SLOTS; i++) {
            free(tc->slots->parts[i]);
            free(tc->slots->payload[i]);
        }
        free(tc->slots->marshal_parts);
        free(tc->slots->marshal_scratch);
    }
    for (i = 0u; i < (size_t)TC_MAX_VALS; i++) {
        free(tc->vss[i].last);
        tc->vss[i].last = NULL;
    }
    if (tc->arena != NULL) {
        free(tc->arena->buf);
    }
    free(tc->pk);
    free(tc->sk);
    free(tc->valscratch);
    free(tc->blkscratch);
    free(tc->stor_gen);
    free(tc->stor_cs);
    free(tc->stor_scratch);
    free(tc->genesis);
    free(tc->cs);
    free(tc->slots);
    free(tc->arena);
    free(tc->recs);
    free(tc->store);
    free(tc->wal);
    free(tc->sv);
    free(tc->val);
    free(tc->prop);
    free(tc->tmp_block);
    free(tc->ecsigs);
    free(tc->cap_ecsigs);
    free(tc->conflict_a);
    free(tc->conflict_b);
    free(tc->marshal_scratch);
    free(tc->ext_parts);
    free(tc->ext_part_set);
    free(tc->ext_scratch);
    memset(tc, 0, sizeof(*tc));
}

/* ══ driving the state machine ════════════════════════════════════════ */

/**
 * C only. The reference's tests never call `receiveRoutine` — they start
 * it as a goroutine (`startRoutines`, common_test.go:218) and then WAIT
 * ON EVENTS. This port has one thread and no event bus, so the test IS
 * the loop: step until nothing is left to do.
 *
 * The bound is a safety net, not a policy: no ported scenario comes near
 * it, and reaching it means the state machine is looping.
 */
static int tc_drain(tc_t *tc)
{
    int n;

    for (n = 0; n < 8192; n++) {
        bool worked = false;
        int  rc;

        if (!cmt_cs_has_work(tc->cs)) {
            return 0;
        }
        rc = cmt_cs_step(tc->cs, &worked);
        if (rc != CMT_OK) {
            fprintf(stderr, "tc_drain: cmt_cs_step returned %d\n", rc);
            return 1;
        }
        if (!worked) {
            return 0;
        }
    }
    fprintf(stderr, "tc_drain: 8192 steps without quiescing\n");
    return 1;
}

/**
 * C only, and the reason wave R2-C could not reach the ticker at all:
 * hand the state machine the expiry of the timer it armed, then let it
 * run. `cmt_cs_on_timer_expired` takes the pending timeout out of the
 * ticker (ticker.go:130-137); `cmt_cs_step` then delivers it to
 * `handleTimeout` against the round state as it was BEFORE the poll
 * (state.go:823, :865).
 */
static int tc_fire_timeout(tc_t *tc)
{
    if (!tc->armed) {
        fprintf(stderr, "tc_fire_timeout: no timer is armed\n");
        return 1;
    }
    tc->armed = false;
    if (cmt_cs_on_timer_expired(tc->cs) != CMT_OK) {
        fprintf(stderr, "tc_fire_timeout: on_timer_expired failed\n");
        return 1;
    }
    return tc_drain(tc);
}

/**
 * cometbft@709fd12b consensus/common_test.go:216-219 — `startTestRound`.
 * `cs.enterNewRound(height, round)` and then the routine; here, the
 * routine is `tc_drain`.
 */
static int tc_start_test_round(tc_t *tc, int64_t height, int32_t round)
{
    if (cmt_cs_enter_new_round(tc->cs, height, round) != CMT_OK) {
        fprintf(stderr, "tc_start_test_round: enter_new_round failed\n");
        return 1;
    }
    return tc_drain(tc);
}

/**
 * common_test.go:177-181 — `incrementRound(vss...)`.
 */
static void tc_increment_round(tc_t *tc, size_t from, size_t to)
{
    size_t i;

    for (i = from; i < to && i < tc->nvals; i++) {
        tc->vss[i].round++;
    }
}

/**
 * common_test.go:171-175 — `incrementHeight(vss...)`.
 *
 * Wave R2-T left this out because the only use it saw was the fixture's
 * own construction (:492, performed inline by `tc_setup`) and no scenario
 * then voted at a second height. TestPrepareProposalReceivesVoteExtensions
 * does (state_test.go:1710), so it exists now. It moves the HEIGHT only;
 * the reference's stubs keep their round across heights and the test
 * increments it separately (:1715-1717).
 */
static void tc_increment_height(tc_t *tc, size_t from, size_t to)
{
    size_t i;

    for (i = from; i < to && i < tc->nvals; i++) {
        tc->vss[i].height++;
    }
}

/* ══ the stubs sign and vote ══════════════════════════════════════════ */

/** common_test.go:979-991 — `signDataIsEqual`, minus its nil test, which
 *  `has_last` carries here. */
static bool tc_sign_data_is_equal(const cmt_vote_t *a, const cmt_vote_t *b)
{
    if (a->type != b->type || a->height != b->height || a->round != b->round) {
        return false;
    }
    if (a->block_id.hash_len != b->block_id.hash_len ||
        memcmp(a->block_id.hash, b->block_id.hash, a->block_id.hash_len) != 0) {
        return false;
    }
    if (a->validator_address_len != b->validator_address_len ||
        memcmp(a->validator_address, b->validator_address,
               a->validator_address_len) != 0) {
        return false;
    }
    if (a->validator_index != b->validator_index) {
        return false;
    }
    if (a->extension.len != b->extension.len) {
        return false;
    }
    if (a->extension.len > 0u &&
        memcmp(a->extension.data, b->extension.data, a->extension.len) != 0) {
        return false;
    }
    return true;
}

/**
 * cometbft@709fd12b consensus/common_test.go:90-132 —
 * `(vs *validatorStub) signVote(voteType, hash, header, voteExtension,
 * extEnabled)`, the METHOD. It takes the extension bytes from its caller
 * and attaches whatever it is given (:109); the rule about WHICH votes may
 * carry one lives in the free function below (:137-145), and
 * `signAddPrecommitWithExtension` (state_test.go:2579-2590) calls this
 * method directly to bypass that rule with a caller-chosen extension.
 *
 * Wave R2-T had the method and the free function as one C function;
 * R2-T2 split them because state_test.go:2587 needs the method alone. The
 * seven existing callers of `tc_sign_vote` (four in test_cmt_cs.c, two in
 * test_cmt_multinode.h, one below) see no change in signature or effect.
 *
 * `out` is filled with a signed vote. The reference's `cmttime.Now()` at
 * :106 is this fixture's frozen clock. Does NOT set `vs->last` — that is
 * :152, in the free function, and :2587-2589 deliberately skips it.
 *
 * @param hash NULL for a nil BlockID (the reference passes a nil slice).
 * @param header NULL for `types.PartSetHeader{}`.
 * @param ext / ext_len the reference's `voteExtension` (:109); NULL/0 for
 *        none. Must have static storage duration or live in the arena —
 *        OWNERSHIP (2) of cmt_cs.h, because the vote set shares the bytes.
 * @param ext_enabled the reference's `extEnabled`, which here decides
 *        only whether the extension signature survives (:127-129).
 */
static int tc_stub_sign_vote(tc_t *tc, tc_stub_t *vs, int32_t vote_type,
                             const uint8_t *hash, size_t hash_len,
                             const cmt_part_set_header_t *header,
                             const uint8_t *ext, size_t ext_len,
                             bool ext_enabled, cmt_vote_t *out)
{
    memset(out, 0, sizeof(*out));
    out->type   = vote_type;
    out->height = vs->height;                                    /* :103 */
    out->round  = vs->round;                                     /* :104 */
    if (hash != NULL && hash_len > 0u) {
        memcpy(out->block_id.hash, hash, hash_len);
        out->block_id.hash_len = hash_len;
    }
    if (header != NULL) {
        out->block_id.part_set_header = *header;                 /* :105 */
    }
    out->timestamp = tc->now;                                    /* :106 */
    memcpy(out->validator_address, tc->addr[vs->index],
           (size_t)CMT_ADDRESS_SIZE);                            /* :107 */
    out->validator_address_len = (size_t)CMT_ADDRESS_SIZE;
    out->validator_index       = vs->index;                      /* :108 */
    if (ext != NULL && ext_len > 0u) {
        out->extension.data = ext;                               /* :109 */
        out->extension.len  = ext_len;
    }

    if (tc_mock_sign_vote(tc->sk[vs->index], tc->chain_id, tc->chain_id_len,
                          out) != CMT_OK) {                      /* :112 */
        fprintf(stderr, "tc_stub_sign_vote: signing failed\n");
        return 1;
    }

    /* :116-121 — "the vote should use the previous vote info when the
     * sign data is the same". The reference does this because FilePV
     * would; MockPV does not, so the stub emulates it. Here it also
     * makes the SIGNATURE reproducible across two identical calls, which
     * randomized ML-DSA-87 otherwise would not be — see HOW IT CAN LIE
     * (4) and the SignSameVoteTwice scenario. */
    if (vs->has_last && tc_sign_data_is_equal(vs->last, out)) {
        memcpy(out->signature, vs->last->signature,
               vs->last->signature_len);
        out->signature_len = vs->last->signature_len;
        out->timestamp     = vs->last->timestamp;
        memcpy(out->extension_signature, vs->last->extension_signature,
               vs->last->extension_signature_len);
        out->extension_signature_len = vs->last->extension_signature_len;
    }

    if (!ext_enabled) {
        out->extension_signature_len = 0u;                   /* :127-129 */
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/common_test.go:134-155 — the free
 * `signVote(vs, voteType, hash, header, extEnabled)`: the extension rule
 * at :137-145, the method above (:146), and `vs.lastVote = v` (:152).
 *
 * @param ext_enabled the reference's `extEnabled`, which decides both
 *        whether an extension is attached (:141-144) and whether the
 *        extension signature survives (:127-129, in the method).
 */
static int tc_sign_vote(tc_t *tc, tc_stub_t *vs, int32_t vote_type,
                        const uint8_t *hash, size_t hash_len,
                        const cmt_part_set_header_t *header,
                        bool ext_enabled, cmt_vote_t *out)
{
    const uint8_t *ext     = NULL;                               /* :136 */
    size_t         ext_len = 0u;

    /* :137-145 — only a non-nil precommit may carry an extension, and it
     * carries one only when extensions are enabled. */
    if (ext_enabled) {
        if (vote_type != (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT) {
            fprintf(stderr, "tc_sign_vote: extensions on a non-precommit\n");
            return 1;                                            /* :140 */
        }
        if ((hash != NULL && hash_len != 0u) ||
            (header != NULL && !cmt_psh_is_zero(header))) {
            ext     = tc_ext_bytes;                              /* :143 */
            ext_len = sizeof(tc_ext_bytes);
        }
    }
    if (tc_stub_sign_vote(tc, vs, vote_type, hash, hash_len, header,
                          ext, ext_len, ext_enabled, out) != 0) {/* :146 */
        return 1;                                            /* :148-150 */
    }
    *vs->last    = *out;                                         /* :152 */
    vs->has_last = true;
    return 0;
}

/**
 * cometbft@709fd12b consensus/common_test.go:255-259 — `addVotes`.
 *
 * ⚠ THE PEER ID IS THIS FIXTURE'S, NOT THE REFERENCE'S EMPTY ONE — see
 * HOW IT CAN LIE (7). The QUEUE is the reference's: the peer queue.
 */
static int tc_add_vote(tc_t *tc, const cmt_vote_t *v)
{
    int rc = cmt_cs_add_vote(tc->cs, v, tc->peer_id,
                             (size_t)CMT_PB_PEER_ID_MAX);

    if (rc != CMT_OK) {
        fprintf(stderr, "tc_add_vote: cmt_cs_add_vote returned %d\n", rc);
        return 1;
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/common_test.go:157-169 — `signVotes` over
 * `vss[from..to)`: sign, and do NOT add. Two scenarios need exactly that —
 * a polka signed at one round and delivered at a later one
 * (state_test.go:1024/:1102 and :1144/:1198).
 *
 * @param out caller storage for `to - from` votes (~9.5 KB each: heap).
 */
static int tc_sign_votes_range(tc_t *tc, int32_t vote_type,
                               const uint8_t *hash, size_t hash_len,
                               const cmt_part_set_header_t *header,
                               bool ext_enabled, size_t from, size_t to,
                               cmt_vote_t *out)
{
    size_t i;

    for (i = from; i < to && i < tc->nvals; i++) {               /* :165 */
        if (tc_sign_vote(tc, &tc->vss[i], vote_type, hash, hash_len,
                         header, ext_enabled, &out[i - from]) != 0) {/* :166 */
            return 1;
        }
    }
    return 0;
}

/**
 * cometbft@709fd12b consensus/common_test.go:255-259 — `addVotes` over an
 * array, then the drain that stands in for the receive routine.
 */
static int tc_add_votes(tc_t *tc, const cmt_vote_t *votes, size_t n)
{
    size_t i;

    for (i = 0u; i < n; i++) {                                   /* :256 */
        if (tc_add_vote(tc, &votes[i]) != 0) {                   /* :257 */
            return 1;
        }
    }
    return tc_drain(tc);
}

/**
 * cometbft@709fd12b consensus/common_test.go:261-271 — `signAddVotes`
 * over `vss[from..to)`, which is how every scenario spells
 * `vs2, vs3, vs4`.
 *
 * The reference signs every stub's vote first (:269 `signVotes`) and
 * only then queues them (:270 `addVotes`). This does the same, because
 * the order matters: a stub whose vote is signed later must still see
 * the round it had when the batch started.
 */
static int tc_sign_add_votes_range(tc_t *tc, int32_t vote_type,
                                   const uint8_t *hash, size_t hash_len,
                                   const cmt_part_set_header_t *header,
                                   bool ext_enabled,
                                   size_t from, size_t to)
{
    cmt_vote_t *votes;
    size_t      n = (to > from) ? (to - from) : 0u;
    int         rc;

    if (to > tc->nvals) {
        n = (tc->nvals > from) ? (tc->nvals - from) : 0u;
    }
    votes = (cmt_vote_t *)calloc(n == 0u ? 1u : n, sizeof(cmt_vote_t));
    if (votes == NULL) {
        return 1;
    }
    if (tc_sign_votes_range(tc, vote_type, hash, hash_len, header,
                            ext_enabled, from, to, votes) != 0) { /* :269 */
        free(votes);
        return 1;
    }
    rc = tc_add_votes(tc, votes, n);                             /* :270 */
    free(votes);
    return rc;
}

/**
 * cometbft@709fd12b consensus/state_test.go:2579-2590 —
 * `signAddPrecommitWithExtension(t, cs, hash, header, extension, stub)`:
 * the stub METHOD with a caller-chosen extension (:2587), then `addVotes`
 * (:2589). It does NOT go through the free `signVote`, so :137-145's rule
 * and :152's `lastVote` update are both skipped — which is the reference's
 * shape, reproduced.
 *
 * @param ext must have static storage duration (OWNERSHIP (2)); the one
 *        caller passes a row of `tc_ext_bytes_of`.
 */
static int tc_sign_add_precommit_with_extension(tc_t *tc, size_t index,
                                                const uint8_t *hash,
                                                size_t hash_len,
                                                const cmt_part_set_header_t *header,
                                                const uint8_t *ext,
                                                size_t ext_len)
{
    cmt_vote_t *v;
    int         rc;

    if (index >= tc->nvals) {
        return 1;
    }
    v = (cmt_vote_t *)calloc(1u, sizeof(*v));
    if (v == NULL) {
        return 1;
    }
    if (tc_stub_sign_vote(tc, &tc->vss[index],
                          (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, hash, hash_len,
                          header, ext, ext_len, true, v) != 0) { /* :2587 */
        free(v);
        return 1;                                                /* :2588 */
    }
    rc = tc_add_votes(tc, v, 1u);                                /* :2589 */
    free(v);
    return rc;
}

/** `signAddVotes(cs1, type, hash, header, ext, vs2, vs3, vs4)` for a
 *  single stub. */
static int tc_sign_add_vote_one(tc_t *tc, size_t index, int32_t vote_type,
                                const uint8_t *hash, size_t hash_len,
                                const cmt_part_set_header_t *header,
                                bool ext_enabled)
{
    return tc_sign_add_votes_range(tc, vote_type, hash, hash_len, header,
                                   ext_enabled, index, index + 1u);
}

/* ══ making a proposal on another validator's behalf ══════════════════ */

/**
 * cometbft@709fd12b types/priv_validator.go:102-115 —
 * `(pv MockPV) SignProposal()`, for a STUB's key: the reference's
 * `vs.SignProposal(chainID, p)` at common_test.go:246 and
 * state_test.go:1187. `tc_sign_proposal_row` above is the same function
 * for this node's own key, reached through the host table.
 */
static int tc_stub_sign_proposal(tc_t *tc, size_t signer, cmt_proposal_t *p)
{
    uint8_t sb[CMT_PROPOSAL_SIGN_BYTES_MAX];
    size_t  sb_len  = 0u;
    size_t  sig_len = 0u;

    if (signer >= tc->nvals) {
        return 1;
    }
    if (cmt_proposal_sign_bytes(tc->chain_id, tc->chain_id_len, p,
                                sb, sizeof(sb), &sb_len) != CMT_OK) {
        return 1;
    }
    if (qgp_dsa87_sign(p->signature, &sig_len, sb, sb_len,
                       tc->sk[signer]) != 0) {
        return 1;
    }
    p->signature_len = sig_len;
    return 0;
}

/**
 * `types.NewProposal(height, round, polRound, blockID)` signed by a stub —
 * common_test.go:244-246 inside `decideProposal`, and on its own at
 * state_test.go:1185-1191, where TestStateLockPOLSafety2 re-proposes an
 * OLD block at a new round with the POL round of the polka it claims.
 *
 * The clock argument is this fixture's frozen `now` — proposal.go:44 reads
 * `cmttime.Now()` inside NewProposal; this tree's `cmt_new_proposal` takes
 * the instant as an argument (cmt_cs.h's clock note).
 */
static int tc_make_signed_proposal(tc_t *tc, size_t signer, int64_t height,
                                   int32_t round, int32_t pol_round,
                                   const cmt_block_id_t *block_id,
                                   cmt_proposal_t *out)
{
    if (cmt_new_proposal(height, round, pol_round, block_id, tc->now,
                         out) != CMT_OK) {                       /* :244 */
        return 1;
    }
    return tc_stub_sign_proposal(tc, signer, out);               /* :246 */
}

/**
 * `block.MakePartSet(types.BlockPartSizeBytes)` for a block the fixture
 * already holds — state_test.go:533, :581, :622, :1139, :1247 and the rest
 * of the reference's MakePartSet calls on a block it has in hand.
 *
 * ⚠ ONE BUFFER. The parts are built into the fixture's own `ext_parts` /
 * `ext_scratch`, the same storage `tc_decide_proposal_from` uses, so this
 * call INVALIDATES whatever part set either function returned before it —
 * and, per HOW IT CAN LIE (11), the bytes of any part set the state
 * machine assembled from that earlier one. Deterministic: the same block
 * marshals to the same bytes and splits into the same parts, which is why
 * the reference can call MakePartSet as often as it likes and compare the
 * headers (:571-576 relies on exactly that).
 */
static int tc_make_part_set(tc_t *tc, const cmt_block_t *block,
                            cmt_part_set_t **out_parts)
{
    memset(tc->ext_part_set, 0, sizeof(*tc->ext_part_set));
    if (cmt_block_make_part_set(block, (uint32_t)CMT_BLOCK_PART_SIZE_BYTES,
                                tc->ext_scratch, (size_t)TC_PAYLOAD_CAP,
                                tc->ext_parts, (size_t)TC_PARTS_CAP,
                                tc->ext_part_set) != CMT_OK) {
        fprintf(stderr, "tc_make_part_set: MakePartSet failed\n");
        return 1;
    }
    *out_parts = tc->ext_part_set;
    return 0;
}

/**
 * cometbft@709fd12b consensus/common_test.go:222-253 — `decideProposal`,
 * with the ONE input the reference takes from the State it is handed made
 * explicit: `polRound := cs.ValidRound` (:235, via :243).
 *
 * The reference builds the block with the given State's own
 * `createProposalBlock` and then signs the PROPOSAL with a different
 * stub's key, which is what makes "a proposal from the validator whose
 * turn it is" possible without a second node. This does the same, with
 * the differences the port forces:
 *   · `createProposalBlock` is private to the module and is not on
 *     cmt_cs.h's surface, so the block is built by calling THIS
 *     FIXTURE'S OWN `tc_create_proposal_block` — the same function the
 *     state machine would have called, with THIS node's state;
 *   · the PROPOSER ADDRESS stamped into the block is the SIGNER's, where
 *     the reference stamps the given State's own (:226 →
 *     state.go:1306). Passing cs1 therefore gives the reference a block
 *     that is byte-identical to cs1's own, and this fixture one that
 *     differs in its proposer. Every scenario that turns on the two blocks
 *     being different (or the same) says so at the site;
 *   · `pol_round` is what the reference's `cs.ValidRound` would have been
 *     for the State it was given: `tc->cs->rs.valid_round` when that
 *     State is cs1 (the wrapper below), and −1 when it is a FRESH second
 *     State — `randState(2)` at state_test.go:604, `newState(cs1.state,
 *     …)` at :902 and :948 — whose ValidRound is the −1 `updateToState`
 *     leaves (state.go:740). Nothing else of that second State is
 *     observable in what decideProposal returns: the block comes from
 *     `cs1.state` either way and the proposal's other fields are the
 *     arguments.
 *
 * @param out_block receives the block (owned by the registry).
 * @param out_parts receives the part set, built into the fixture's own
 *        `ext_parts` / `ext_scratch` — NOT into one of the three slots,
 *        for exactly the reason cmt_cs.h:551-570 gives for the proposer's
 *        marshal buffer; and invalidated by the next call of this or of
 *        `tc_make_part_set` (HOW IT CAN LIE (11)).
 */
static int tc_decide_proposal_from(tc_t *tc, size_t signer, int64_t height,
                                   int32_t round, int32_t pol_round,
                                   cmt_proposal_t *out_prop,
                                   cmt_block_t **out_block,
                                   cmt_part_set_t **out_parts)
{
    cmt_extended_commit_t     ec;
    cmt_block_t              *slot;
    cmt_block_id_t            bid;
    cmt_part_set_header_t     psh;
    uint8_t                   hash[CMT_TMHASH_SIZE];
    size_t                    n_before;

    /* The extended commit the proposer would have used. At the initial
     * height it is empty but not nil (state.go:1290); above it, it is
     * made from the state machine's LastCommit (:1294). */
    memset(&ec, 0, sizeof(ec));
    memset(tc->ecsigs, 0,
           (size_t)TC_MAX_VALS * sizeof(cmt_extended_commit_sig_t));
    ec.extended_signatures     = tc->ecsigs;
    ec.extended_signatures_cap = (size_t)TC_MAX_VALS;
    ec.extended_signatures_len = 0u;
    if (height != tc->cs->state.initial_height) {
        if (tc->cs->rs.last_commit == NULL ||
            !cmt_vote_set_has_two_thirds_majority(tc->cs->rs.last_commit)) {
            fprintf(stderr, "tc_decide_proposal: no LastCommit majority\n");
            return 1;
        }
        if (cmt_vote_set_make_extended_commit(
                tc->cs->rs.last_commit, tc->cs->state.consensus_params.abci,
                tc->ecsigs, (size_t)TC_MAX_VALS, &ec) != CMT_OK) {
            fprintf(stderr, "tc_decide_proposal: MakeExtendedCommit failed\n");
            return 1;
        }
    }

    /* The block goes into a fresh registry record; `tmp_block` is only
     * the out-parameter the host row writes through, because the record
     * itself is what keeps the storage alive. */
    n_before = tc->recs_n;
    if (n_before >= (size_t)TC_BLOCK_RECS) {
        fprintf(stderr, "tc_decide_proposal: the block registry is full\n");
        return 1;
    }
    if (tc_create_proposal_block(tc, height, &tc->cs->state, &ec,
                                 tc->addr[signer],
                                 (size_t)CMT_ADDRESS_SIZE,
                                 tc->tmp_block) != CMT_OK) {
        fprintf(stderr, "tc_decide_proposal: create_proposal_block failed\n");
        return 1;
    }
    slot = &tc->recs[n_before].block;

    /* :233 — block.MakePartSet(types.BlockPartSizeBytes). */
    {
        cmt_part_set_t *parts = NULL;

        if (tc_make_part_set(tc, slot, &parts) != 0) {
            return 1;
        }
    }
    if (cmt_block_hash(slot, hash) != CMT_OK) {
        return 1;
    }
    if (cmt_part_set_header(tc->ext_part_set, &psh) != CMT_OK) {
        return 1;
    }
    memset(&bid, 0, sizeof(bid));
    memcpy(bid.hash, hash, sizeof(hash));
    bid.hash_len        = sizeof(hash);
    bid.part_set_header = psh;

    /* :243-246 — NewProposal(height, round, polRound, blockID), signed by
     * `vs` and not by cs1. */
    if (tc_make_signed_proposal(tc, signer, height, round, pol_round, &bid,
                                out_prop) != 0) {
        return 1;
    }
    if (out_block != NULL) {
        *out_block = slot;
    }
    if (out_parts != NULL) {
        *out_parts = tc->ext_part_set;
    }
    return 0;
}

/**
 * `decideProposal(ctx, t, cs1, vs, height, round)` — the reference's call
 * with cs1 as the State, so the POL round is cs1's ValidRound (:235).
 * Every caller that existed before R2-T2 goes through here unchanged.
 */
static int tc_decide_proposal(tc_t *tc, size_t signer, int64_t height,
                              int32_t round, cmt_proposal_t *out_prop,
                              cmt_block_t **out_block,
                              cmt_part_set_t **out_parts)
{
    return tc_decide_proposal_from(tc, signer, height, round,
                                   tc->cs->rs.valid_round,       /* :235 */
                                   out_prop, out_block, out_parts);
}

/**
 * state.go:513-532 — `SetProposalAndBlock`, which the reference's tests
 * call directly (state_test.go:229, :726, :830 …).
 *
 * ⚠ IT ONLY ENQUEUES, and that is deliberate: :513-532 writes the
 * proposal and then each part onto the PEER QUEUE and returns. The
 * reference's tests depend on it — `TestStateBadProposal` calls it at
 * :229 while the state machine is still at round 0 and only starts
 * round 1 at :234, so the queued proposal must not be handled until the
 * round has changed or `defaultSetProposal` would drop it as
 * out-of-round (:1911). A caller that wants it handled calls `tc_drain`.
 */
static int tc_set_proposal_and_block(tc_t *tc, const cmt_proposal_t *prop,
                                     const cmt_part_set_t *parts)
{
    int rc = cmt_cs_set_proposal_and_block(tc->cs, prop, parts, tc->peer_id,
                                           (size_t)CMT_PB_PEER_ID_MAX);

    if (rc != CMT_OK) {
        fprintf(stderr, "tc_set_proposal_and_block returned %d\n", rc);
        return 1;
    }
    return 0;
}

/* ══ the ensure* family ═══════════════════════════════════════════════ */

/**
 * cometbft@709fd12b consensus/common_test.go:559-576 — `ensureNewRound`.
 * The reference waits for an `EventDataNewRound`; this asserts the round
 * state arrived there. See the note at the top on what that trades away.
 *
 * ⚠ AND ONE THING MORE, because height and round alone are a WEAKER
 * claim than the event. Only `enterNewRound` publishes NewRound, but
 * `finalizeCommit` leaves the machine at height+1 / round 0 / step
 * NEW_HEIGHT (cmt_cs.c:1804 arms the timeout that will run
 * enterNewRound), so this function is already satisfied BEFORE the round
 * has been entered. A caller asserting a new HEIGHT must fire the commit
 * timeout first; the scenario file's HOW IT CAN LIE (15) names the one
 * place that cannot and what it therefore does not prove.
 */
static int tc_ensure_new_round(tc_t *tc, int64_t height, int32_t round)
{
    TC_CHECK(tc->cs->rs.height == height, "ensureNewRound: wrong height");
    TC_OK();
    TC_CHECK(tc->cs->rs.round == round, "ensureNewRound: wrong round");
    TC_OK();
    return 0;
}

/**
 * common_test.go:624-641 — `ensureNewBlockHeader`. The reference waits
 * for `EventDataNewBlockHeader` and asserts the committed header's HEIGHT
 * and its HASH; there is no event here, so this asserts what
 * `apply_verified_block` was last handed. It exists because counting
 * commits is not the same as knowing WHICH block was committed: a
 * regression that committed the wrong block passes an `apply_calls`
 * count and fails this.
 *
 * @param hash may be NULL to assert the height only.
 */
static int tc_ensure_new_block_header(tc_t *tc, int64_t height,
                                      const uint8_t *hash, size_t hash_len)
{
    TC_CHECK(tc->apply_calls > 0,
             "ensureNewBlockHeader: nothing was ever committed");
    TC_OK();
    TC_CHECK(tc->applied_height == height,
             "ensureNewBlockHeader: wrong committed height");
    TC_OK();
    if (hash != NULL) {
        TC_CHECK(tc->applied_hash_len == hash_len &&
                 memcmp(tc->applied_hash, hash, hash_len) == 0,
                 "ensureNewBlockHeader: the WRONG block was committed");
        TC_OK();
    }
    return 0;
}

/**
 * common_test.go:584-601 — `ensureNewProposal`. The reference waits for
 * `EventDataCompleteProposal`; the round state's evidence for the same
 * thing is that both the proposal and its block are installed for this
 * height and round (state.go:1259-1262 is the reference's own definition
 * of a complete proposal).
 */
static int tc_ensure_new_proposal(tc_t *tc, int64_t height, int32_t round)
{
    TC_CHECK(tc->cs->rs.proposal != NULL, "ensureNewProposal: no proposal");
    TC_OK();
    TC_CHECK(tc->cs->rs.proposal->height == height,
             "ensureNewProposal: wrong height");
    TC_OK();
    TC_CHECK(tc->cs->rs.proposal->round == round,
             "ensureNewProposal: wrong round");
    TC_OK();
    TC_CHECK(tc->cs->rs.proposal_block != NULL,
             "ensureNewProposal: no proposal block");
    TC_OK();
    return 0;
}

/**
 * common_test.go:578-582 — `ensureNewTimeout`. The reference waits for
 * the event and checks its height and round; this checks the timer the
 * state machine actually armed, plus the height, round and step of the
 * timeout the ticker is holding (ticker.go:101).
 */
static int tc_ensure_new_timeout(tc_t *tc, int64_t height, int32_t round,
                                 int64_t duration_ns, cmt_round_step_t step)
{
    TC_CHECK(tc->armed, "ensureNewTimeout: no timer is armed");
    TC_OK();
    TC_CHECK(tc->armed_ns == duration_ns,
             "ensureNewTimeout: wrong duration");
    TC_OK();
    TC_CHECK(tc->cs->ticker.ti.height == height,
             "ensureNewTimeout: wrong height");
    TC_OK();
    TC_CHECK(tc->cs->ticker.ti.round == round,
             "ensureNewTimeout: wrong round");
    TC_OK();
    TC_CHECK(tc->cs->ticker.ti.step == step, "ensureNewTimeout: wrong step");
    TC_OK();
    return 0;
}

/**
 * common_test.go:531-537 — `ensureNoNewTimeout`. The reference waits and
 * asserts nothing arrived. There is nothing to wait for here, so this
 * asserts the stronger and cheaper thing: the timeout the ticker holds is
 * NOT the one the scenario says must not have been scheduled.
 */
static int tc_ensure_no_timeout_for(tc_t *tc, int64_t height, int32_t round,
                                    cmt_round_step_t step)
{
    bool same = tc->armed &&
                tc->cs->ticker.ti.height == height &&
                tc->cs->ticker.ti.round == round &&
                tc->cs->ticker.ti.step == step;

    TC_CHECK(!same, "ensureNoNewTimeout: that timeout WAS scheduled");
    TC_OK();
    return 0;
}

/**
 * common_test.go:603-606 — `ensureNewValidBlock`. The reference waits for
 * `EventValidBlock` at (height, round), which the state machine publishes
 * in TWO places for a prevote polka (state.go:2302-2305) and one more on
 * a commit for a block it lacks (:1649-1653). The round state does NOT
 * always carry a ValidBlock afterwards: when the polka is for a block the
 * node does not have, :2295 clears ProposalBlock and only :2298-2300 runs,
 * so `valid_round` is unchanged and asserting it would fail a correct
 * machine. The one fact BOTH branches of :2282-2300 guarantee — and :1647
 * too — is that `ProposalBlockParts` now carries the polka's part-set
 * header, so that is what this asserts, plus the height and round the
 * event would have named.
 *
 * @param psh the polka's part-set header.
 */
static int tc_ensure_new_valid_block(tc_t *tc, int64_t height, int32_t round,
                                     const cmt_part_set_header_t *psh)
{
    TC_CHECK(tc->cs->rs.height == height, "ensureNewValidBlock: wrong height");
    TC_OK();
    TC_CHECK(tc->cs->rs.round == round, "ensureNewValidBlock: wrong round");
    TC_OK();
    TC_CHECK(tc->cs->rs.proposal_block_parts != NULL &&
             cmt_part_set_has_header(tc->cs->rs.proposal_block_parts, psh),
             "ensureNewValidBlock: ProposalBlockParts does not carry the "
             "polka's header");
    TC_OK();
    return 0;
}

/**
 * common_test.go:608-622 — `ensureNewBlock`: `EventDataNewBlock` with
 * `Block.Height == height`. The reference checks the HEIGHT ONLY (:618);
 * `tc_ensure_new_block_header` with a hash is the stronger sibling and a
 * scenario that knows which block it expects should call that as well.
 */
static int tc_ensure_new_block(tc_t *tc, int64_t height)
{
    return tc_ensure_new_block_header(tc, height, NULL, 0u);
}

/**
 * common_test.go:643-646 — `ensureNewUnlock`. The reference waits for
 * `EventUnlock` at (height, round); the state machine publishes it at
 * exactly the three sites that clear the lock (state.go:1497, :1556,
 * :2274), each immediately after `LockedRound = -1; LockedBlock = nil;
 * LockedBlockParts = nil`. So the round-state evidence is those three
 * fields, at that height and round.
 */
static int tc_ensure_new_unlock(tc_t *tc, int64_t height, int32_t round)
{
    TC_CHECK(tc->cs->rs.height == height, "ensureNewUnlock: wrong height");
    TC_OK();
    TC_CHECK(tc->cs->rs.round == round, "ensureNewUnlock: wrong round");
    TC_OK();
    TC_CHECK(tc->cs->rs.locked_round == -1 && tc->cs->rs.locked_block == NULL &&
             tc->cs->rs.locked_block_parts == NULL,
             "ensureNewUnlock: still locked");
    TC_OK();
    return 0;
}

/**
 * common_test.go:524-529 — `ensureNoNewUnlock`. The reference waits out its
 * budget and panics if an Unlock EVENT arrived. There is no event here, so
 * this asserts the stronger and cheaper thing: the lock is STILL the one
 * the caller says it was — same round, same block. A relock onto the same
 * block at a later round would fail this and not the reference's; no
 * ported scenario is in that position, and both tests that call this do
 * so to prove the lock did not move at all (state_test.go:1086-1088,
 * :1202-1204).
 */
static int tc_ensure_no_new_unlock(tc_t *tc, int32_t locked_round,
                                   const uint8_t *locked_hash,
                                   size_t locked_hash_len)
{
    uint8_t lh[CMT_TMHASH_SIZE];

    TC_CHECK(tc->cs->rs.locked_block != NULL,
             "ensureNoNewUnlock: the lock was released");
    TC_OK();
    TC_CHECK(tc->cs->rs.locked_round == locked_round,
             "ensureNoNewUnlock: the locked round moved");
    TC_OK();
    TC_CHECK(cmt_block_hash(tc->cs->rs.locked_block, lh) == CMT_OK &&
             locked_hash_len == (size_t)CMT_TMHASH_SIZE &&
             memcmp(lh, locked_hash, (size_t)CMT_TMHASH_SIZE) == 0,
             "ensureNoNewUnlock: locked on a different block");
    TC_OK();
    return 0;
}

/**
 * common_test.go:517-522 — `ensureNoNewRoundStep`. The reference subscribes
 * to `EventNewRoundStep` AFTER the step it is at and panics if one arrives
 * within its budget; `newStep` (state.go:758-766) fires that event on every
 * `updateRoundStep`. The round-state fact is that the (height, round, step)
 * triple the caller snapshotted is unchanged.
 */
static int tc_ensure_no_new_round_step(tc_t *tc, int64_t height, int32_t round,
                                       cmt_round_step_t step)
{
    TC_CHECK(tc->cs->rs.height == height && tc->cs->rs.round == round &&
             tc->cs->rs.step == step,
             "ensureNoNewRoundStep: the round step moved");
    TC_OK();
    return 0;
}

/** The vote this node put in its own vote set for (round, type). NULL
 *  when it did not vote. */
static const cmt_vote_t *tc_own_vote(tc_t *tc, int32_t round,
                                     int32_t vote_type)
{
    cmt_vote_set_t   *vs;
    const cmt_vote_t *v = NULL;

    if (vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE) {
        vs = cmt_hvs_prevotes(tc->cs->rs.votes, round);
    } else {
        vs = cmt_hvs_precommits(tc->cs->rs.votes, round);
    }
    if (vs == NULL) {
        return NULL;
    }
    /* cmt_vote_set.h:584 — an address the set does not know REJECTS
     * rather than returning nil (the umbrella rev-4 panic rule applied to
     * vote_set.go:425), so a non-OK return here means "not found". */
    if (cmt_vote_set_get_by_address(vs, tc->addr[tc->self],
                                    (size_t)CMT_ADDRESS_SIZE, &v) != CMT_OK) {
        return NULL;
    }
    return v;
}

/**
 * Did THIS NODE sign a vote of that type at that height and round?
 *
 * Read out of the WAL, not out of a vote set, and deliberately: every
 * vote this node makes goes onto the INTERNAL queue (state.go:2472) and
 * is written there by `wal.WriteSync` (:839) before it is handled. That
 * record survives the height changing, where the vote set does not — and
 * a scenario that walks into the next height still has to be able to say
 * what it voted at the height it left.
 */
static bool tc_wal_has_vote(const tc_t *tc, int64_t height, int32_t round,
                            int32_t vote_type)
{
    size_t i;

    for (i = 0u; i < tc->wal_len; i++) {
        const tc_wal_row_t *r = &tc->wal[i];

        if (r->kind == (int)CMT_PB_WAL_MSG_INFO && r->sync &&
            r->msg_kind == (int)CMT_PB_CONS_MSG_VOTE &&
            r->vote_type == vote_type && r->height == height &&
            r->round == round) {
            return true;
        }
    }
    return false;
}

/**
 * cometbft@709fd12b consensus/common_test.go:670-701 — `ensurePrevote` /
 * `ensurePrecommit` / `ensureVote`: this node cast a vote of that type,
 * at that height, in that round.
 *
 * The reference reads the vote off the event bus and checks exactly those
 * three fields (:691-699); this reads the same three off the WAL row the
 * same vote produced.
 */
static int tc_ensure_vote(tc_t *tc, int64_t height, int32_t round,
                          int32_t vote_type)
{
    TC_CHECK(tc_wal_has_vote(tc, height, round, vote_type),
             "ensureVote: this node signed no such vote");
    TC_OK();
    return 0;
}

/**
 * common_test.go:670-701's `ensureVote` on an UNFILTERED vote channel. Most
 * reference tests subscribe with `subscribeToVoter(cs1, addr)` (:356-375),
 * so their `ensurePrevote`/`ensurePrecommit` mean THIS node voted — that is
 * `tc_ensure_vote`. TestStateLockNoPOL subscribes to every vote
 * (state_test.go:467, `subscribeUnBuffered(…, EventQueryVote)`), so there
 * the SAME helper, called right after a `signAddVotes(…, vs2)`, means "the
 * STUB's vote was added" (state.go:2245 publishes EventVote for every vote
 * `AddVote` accepts). The round-state fact is that the stub's vote is in
 * this node's vote set for that round and type — asserted here by address,
 * which is what the event's `vote.ValidatorAddress` would have said.
 *
 * Reads the CURRENT height's vote set, so it is only meaningful before the
 * height moves — every call site in this suite is mid-height.
 */
static int tc_ensure_stub_vote(tc_t *tc, size_t index, int32_t round,
                               int32_t vote_type)
{
    cmt_vote_set_t   *vs;
    const cmt_vote_t *v = NULL;

    TC_CHECK(index < tc->nvals, "ensureStubVote: no such stub");
    TC_OK();
    if (vote_type == (int32_t)CMT_PB_MSG_TYPE_PREVOTE) {
        vs = cmt_hvs_prevotes(tc->cs->rs.votes, round);
    } else {
        vs = cmt_hvs_precommits(tc->cs->rs.votes, round);
    }
    TC_CHECK(vs != NULL, "ensureStubVote: no vote set for that round");
    TC_OK();
    TC_CHECK(cmt_vote_set_get_by_address(vs, tc->addr[index],
                                         (size_t)CMT_ADDRESS_SIZE,
                                         &v) == CMT_OK && v != NULL,
             "ensureStubVote: the stub's vote was not added");
    TC_OK();
    return 0;
}

/**
 * C only. Step the state machine until it reaches `step`, or until it
 * runs out of work. Used where the reference limits the receive routine
 * instead (`startRoutines(3)`, common_test.go:218 / state_test.go:170) so
 * that an assertion can be made mid-height before the chain rolls on.
 */
static int tc_step_until_step(tc_t *tc, cmt_round_step_t step)
{
    int n;

    for (n = 0; n < 8192; n++) {
        bool worked = false;

        if (tc->cs->rs.step == step) {
            return 0;
        }
        if (!cmt_cs_has_work(tc->cs)) {
            return 0;
        }
        if (cmt_cs_step(tc->cs, &worked) != CMT_OK) {
            fprintf(stderr, "tc_step_until_step: cmt_cs_step failed\n");
            return 1;
        }
        if (!worked) {
            return 0;
        }
    }
    fprintf(stderr, "tc_step_until_step: 8192 steps without reaching %u\n",
            (unsigned)step);
    return 1;
}

/**
 * common_test.go:273-291 — `validatePrevote`, and :703-733's
 * `ensurePrevoteMatch` for the hash half.
 * @param hash NULL means "for nil", the reference's `blockHash == nil`.
 */
static int tc_validate_prevote(tc_t *tc, int32_t round, const uint8_t *hash,
                               size_t hash_len)
{
    const cmt_vote_t *v = tc_own_vote(tc, round,
                                      (int32_t)CMT_PB_MSG_TYPE_PREVOTE);

    TC_CHECK(v != NULL, "validatePrevote: no prevote from us");
    TC_OK();
    if (hash == NULL) {
        TC_CHECK(v->block_id.hash_len == 0u,
                 "validatePrevote: expected a prevote for nil");
        TC_OK();
    } else {
        TC_CHECK(v->block_id.hash_len == hash_len &&
                 memcmp(v->block_id.hash, hash, hash_len) == 0,
                 "validatePrevote: prevote is for the wrong block");
        TC_OK();
    }
    return 0;
}

/**
 * common_test.go:307-354 — `validatePrecommit`: the precommit we cast in
 * `this_round`, AND what we are locked on afterwards.
 * @param voted_hash NULL for a precommit for nil.
 * @param locked_hash NULL for "locked on nothing", in which case
 *        `lock_round` is the reference's -1.
 */
static int tc_validate_precommit(tc_t *tc, int32_t this_round,
                                 int32_t lock_round,
                                 const uint8_t *voted_hash,
                                 size_t voted_hash_len,
                                 const uint8_t *locked_hash,
                                 size_t locked_hash_len)
{
    const cmt_vote_t *v = tc_own_vote(tc, this_round,
                                      (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT);
    uint8_t           lh[CMT_TMHASH_SIZE];

    TC_CHECK(v != NULL, "validatePrecommit: no precommit from us");
    TC_OK();
    if (voted_hash == NULL) {
        TC_CHECK(v->block_id.hash_len == 0u,
                 "validatePrecommit: expected a precommit for nil");
        TC_OK();
    } else {
        TC_CHECK(v->block_id.hash_len == voted_hash_len &&
                 memcmp(v->block_id.hash, voted_hash, voted_hash_len) == 0,
                 "validatePrecommit: precommit is for the wrong block");
        TC_OK();
    }
    TC_CHECK(tc->cs->rs.locked_round == lock_round,
             "validatePrecommit: wrong locked round");
    TC_OK();
    if (locked_hash == NULL) {
        TC_CHECK(tc->cs->rs.locked_block == NULL,
                 "validatePrecommit: expected to be locked on nothing");
        TC_OK();
    } else {
        TC_CHECK(tc->cs->rs.locked_block != NULL,
                 "validatePrecommit: expected to be locked on a block");
        TC_OK();
        TC_CHECK(cmt_block_hash(tc->cs->rs.locked_block, lh) == CMT_OK,
                 "validatePrecommit: the locked block will not hash");
        TC_OK();
        TC_CHECK(locked_hash_len == (size_t)CMT_TMHASH_SIZE &&
                 memcmp(lh, locked_hash, (size_t)CMT_TMHASH_SIZE) == 0,
                 "validatePrecommit: locked on the wrong block");
        TC_OK();
    }
    return 0;
}

/** common_test.go:293-305 — `validateLastPrecommit`: our precommit in
 *  `cs.LastCommit`, i.e. at the height that has just been decided. */
static int tc_validate_last_precommit(tc_t *tc, const uint8_t *hash,
                                      size_t hash_len)
{
    const cmt_vote_t *v = NULL;

    TC_CHECK(tc->cs->rs.last_commit != NULL,
             "validateLastPrecommit: no LastCommit");
    TC_OK();
    TC_CHECK(cmt_vote_set_get_by_address(tc->cs->rs.last_commit,
                                         tc->addr[tc->self],
                                         (size_t)CMT_ADDRESS_SIZE,
                                         &v) == CMT_OK && v != NULL,
             "validateLastPrecommit: we are not in LastCommit");
    TC_OK();
    TC_CHECK(v->block_id.hash_len == hash_len &&
             memcmp(v->block_id.hash, hash, hash_len) == 0,
             "validateLastPrecommit: precommit is for the wrong block");
    TC_OK();
    return 0;
}

/* ══ who proposes ═════════════════════════════════════════════════════ */

/**
 * The validator index the reference's proposer arithmetic elects at
 * (height, round), for THIS fixture's shape only: `nvals` validators of
 * EQUAL power, no validator-set change ever, initial height 1.
 *
 * ⚠ DERIVED FROM types/validator_set.go, NOT ASKED OF THE PORT. Asking
 * `cmt_validator_set_get_proposer` what it thinks and then asserting it
 * would be testing the code with itself, which is the honesty wave R2-C
 * kept when it declined to assert the round-1 proposer at all
 * (test_cmt_cs_unit.c:98-102). The derivation, for n validators of power
 * p (total T = n·p), addresses ascending by index:
 *
 *   `NewValidatorSet` (:77-89) ends in `IncrementProposerPriority(1)`
 *   (:85-87) over all-zero priorities. `RescalePriorities` (:158-179) is
 *   a no-op (diff 0) and `shiftByAvgProposerPriority` (:241-249) is a
 *   no-op (avg 0), so `incrementProposerPriority` (:181-198) runs once:
 *   every priority becomes p, `getValWithMostPriority` (:233-239) breaks
 *   the all-equal tie by SMALLEST ADDRESS
 *   (`CompareProposerPriority`, validator.go:65-85), electing
 *   index 0, and that one is docked T. Priorities are then
 *   [p−T, p, …, p] with proposer 0.
 *
 *   Each further increment adds p to all and docks the winner T, and the
 *   winner is always the lowest index among those at the maximum. So the
 *   k-th increment from that state elects index k mod n.
 *
 *   `MakeGenesisState` (state/state.go:317-355) sets Validators to that
 *   set (one increment) and NextValidators to it incremented once more
 *   (:333). `updateState` rotates Validators ← NextValidators at every
 *   height, so at height h the set has had h increments and its proposer
 *   is index (h−1) mod n. `enterNewRound` (state.go:1071-1075) increments
 *   a COPY (round − cs.Round) more times for round r.
 *
 * Hence: (h − 1 + r) mod n. Cross-checked against the reference's own
 * expectations: TestStateProposerSelection0 (state_test.go:78-84) says
 * height 1 round 0 is vss[0] and (state_test.go:95-101) height 2 round 0
 * is vss[1]; TestStateProposerSelection2 (:120-137) says round r elects
 * vss[(i+round) mod n] as it walks rounds upward at height 1.
 */
static size_t tc_expected_proposer(const tc_t *tc, int64_t height,
                                   int32_t round)
{
    int64_t k = (height - 1 + (int64_t)round) % (int64_t)tc->nvals;

    if (k < 0) {
        k += (int64_t)tc->nvals;
    }
    return (size_t)k;
}

/** Assert that the state machine's own validator set elects the index
 *  `tc_expected_proposer` derived. */
static int tc_check_proposer(tc_t *tc, int64_t height, int32_t round)
{
    size_t want = tc_expected_proposer(tc, height, round);

    TC_CHECK(tc->cs->rs.validators != NULL, "check_proposer: no set");
    TC_OK();
    TC_CHECK(cmt_validator_set_get_proposer(tc->cs->rs.validators,
                                            tc->val) == CMT_OK,
             "check_proposer: GetProposer failed");
    TC_OK();
    TC_CHECK(tc->val->address_len == (size_t)CMT_ADDRESS_SIZE &&
             memcmp(tc->val->address, tc->addr[want],
                    (size_t)CMT_ADDRESS_SIZE) == 0,
             "check_proposer: the wrong validator is proposer");
    TC_OK();
    return 0;
}

/* ══ small conveniences the scenarios share ═══════════════════════════ */

/** The hash of the block the round state currently calls the proposal
 *  block, into `out`. */
static int tc_proposal_block_hash(tc_t *tc, uint8_t out[CMT_TMHASH_SIZE])
{
    if (tc->cs->rs.proposal_block == NULL) {
        return 1;
    }
    return cmt_block_hash(tc->cs->rs.proposal_block, out) == CMT_OK ? 0 : 1;
}

/** The part-set header of the current proposal block parts. */
static int tc_proposal_parts_header(tc_t *tc, cmt_part_set_header_t *out)
{
    if (tc->cs->rs.proposal_block_parts == NULL) {
        return 1;
    }
    return cmt_part_set_header(tc->cs->rs.proposal_block_parts, out) == CMT_OK
           ? 0 : 1;
}

/** The zero PartSetHeader — the reference's `types.PartSetHeader{}`. */
static void tc_zero_psh(cmt_part_set_header_t *out)
{
    memset(out, 0, sizeof(*out));
}

/** Give the next proposed block one transaction of `len` bytes. The
 *  content is a fixed pattern: nothing here may depend on randomness. */
static void tc_set_next_tx(tc_t *tc, uint8_t *storage, size_t len)
{
    size_t i;

    for (i = 0u; i < len; i++) {
        storage[i] = (uint8_t)('a' + (i % 26u));
    }
    tc->next_txs[0]     = storage;
    tc->next_txs_len[0] = len;
    tc->next_txs_n      = 1u;
}

#endif /* NODUS_TESTS_TEST_CMT_COMMON_H */
