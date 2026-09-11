/**
 * Nodus — cometbft @709fd12b C port, wave R2-B: consensus/msgs.go's
 * MsgToProto / MsgFromProto (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the conversion between the reactor's nine message types and the
 * proto3 messages on the wire is the reference's, in both directions. If
 * this file failed, one of these would be false:
 *   · every one of the nine types converts to its own oneof branch and
 *     back, and the round trip changes NO byte of the encoding — so no
 *     field is dropped, widened or reordered on the way through;
 *   · the three POINTER fields keep their nil-ness: a nil BlockParts
 *     leaves NewValidBlock's field 4 off the wire, a nil Vote leaves the
 *     Vote branch with an empty body, and a nil Votes leaves VoteSetBits'
 *     ALWAYS field 5 as the zero BitArray — three different reference
 *     behaviours at three sites (msgs.go:39, :74, :107-109);
 *   · the ONE site where the reference nil-dereferences on its own state,
 *     `ProposalPol: *pbBits` at msgs.go:59, is CMT_FAULT here and not a
 *     silent empty array;
 *   · a Step above 255 is REFUSED on the way in, which is the reference's
 *     `cmtmath.SafeConvertUint8` denial at msgs.go:129-133;
 *   · an unrecognised message is refused in both directions
 *     (msgs.go:22-24, :113-114, :122-124, :228-229).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, no clock, no RNG. Safe under `ctest -j`.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state. The
 * message structs are HEAP-allocated because a `cmt_msg_t` is on the
 * order of ten kilobytes; every allocation is freed on the success path
 * and a CHECK failure returns early and leaks, which is acceptable in a
 * failing test process.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. IT DOES NOT VALIDATE. `MsgFromProto` ends in `pb.ValidateBasic()`
 *     (msgs.go:232-234) and this port stops one step short of that line,
 *     so every message this file accepts is a message the reference might
 *     still have refused. A green here says NOTHING about whether a
 *     negative height, an invalid Step or an empty ProposalPOL bit array
 *     is rejected — that is wave R3's ValidateBasic and its own tests.
 *  2. Round trips are compared as ENCODED BYTES, not field by field. Two
 *     structs that encode identically are treated as equal, which is the
 *     property that matters for consensus but would hide a difference in
 *     a field that never reaches the wire. There is no such field in
 *     these nine types.
 *  3. The expected byte strings come from test_cmt_pb.c's vectors by
 *     construction, not from an independent source; what is tested HERE
 *     is the CONVERSION, and the encoding itself is test_cmt_pb.c's
 *     subject.
 *
 * ── REFERENCE TEST CASES PORTED ────────────────────────────────────────
 * consensus/msgs_test.go (418 lines, UNPINNED at the time of writing,
 * SHA-256 ffdb0d011f00ff58643eacdeaf36ece417f532dc36eecf6667d5cd760ba7e3ec):
 * `TestMsgToProto` (:22-196) — the nine round trips and the failure case.
 * Its `nil` case and its per-field random fixtures are reproduced with
 * deterministic ones.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_msgs.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static uint8_t HASH_A[64], HASH_B[64];
static uint8_t ADDR_A[32];
static uint8_t SIG_S[9];
static const cmt_time_t TS_A = { 1700000000LL, 123456789 };
static const uint8_t TEST_BYTES[4] = { 't', 'e', 's', 't' };

static void pat(uint8_t *out, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static void build_fixtures(void)
{
    pat(HASH_A, sizeof(HASH_A), 0x10);
    pat(HASH_B, sizeof(HASH_B), 0x20);
    pat(ADDR_A, sizeof(ADDR_A), 0x40);
    pat(SIG_S,  sizeof(SIG_S),  0x60);
}

static void psh_a(cmt_part_set_header_t *psh)
{
    cmt_pb_part_set_header_init(psh);
    psh->total = 7;
    memcpy(psh->hash, HASH_A, 64);
    psh->hash_len = 64;
}

static void bid_a(cmt_block_id_t *bid)
{
    cmt_pb_block_id_init(bid);
    memcpy(bid->hash, HASH_B, 64);
    bid->hash_len = 64;
    psh_a(&bid->part_set_header);
}

static void bits_1(cmt_bit_array_t *ba)
{
    memset(ba, 0, sizeof(*ba));
    ba->bits     = 1;
    ba->n_elems  = 1;
    ba->elems[0] = 0u;
}

/* ══ helpers ══════════════════════════════════════════════════════════ */

static uint8_t g_buf[16384];
static uint8_t g_buf2[16384];
static uint8_t g_arena_bytes[8192];
static cmt_pb_arena_t g_arena;

static void arena_reset(void)
{
    g_arena.buf  = g_arena_bytes;
    g_arena.cap  = sizeof(g_arena_bytes);
    g_arena.used = 0;
}

/**
 * msg → proto → bytes → proto → msg → proto → bytes, and the two byte
 * strings must be identical. This is the whole of TestMsgToProto's
 * `MsgFromProto(MsgToProto(m))` assertion, expressed on the encoding
 * because that is what two nodes must agree on.
 */
static int round_trip(const char *what, const cmt_msg_t *m, size_t *out_len)
{
    cmt_pb_cons_message_t *pb1;
    cmt_pb_cons_message_t *pb2;
    cmt_msg_t             *back;
    size_t                 n1 = 0;
    size_t                 n2 = 0;
    int                    ok = 0;

    pb1  = (cmt_pb_cons_message_t *)malloc(sizeof(*pb1));
    pb2  = (cmt_pb_cons_message_t *)malloc(sizeof(*pb2));
    back = (cmt_msg_t *)malloc(sizeof(*back));
    if (pb1 == NULL || pb2 == NULL || back == NULL) {
        fprintf(stderr, "%s: out of memory\n", what);
        goto done;
    }
    if (cmt_msg_to_proto(m, pb1) != CMT_OK) {
        fprintf(stderr, "%s: MsgToProto failed\n", what);
        goto done;
    }
    if (cmt_pb_cons_message_marshal(pb1, g_buf, sizeof(g_buf), &n1)
            != CMT_OK) {
        fprintf(stderr, "%s: marshal failed\n", what);
        goto done;
    }
    arena_reset();
    if (cmt_pb_cons_message_unmarshal(g_buf, n1, pb2, &g_arena) != CMT_OK) {
        fprintf(stderr, "%s: unmarshal failed\n", what);
        goto done;
    }
    if (cmt_msg_from_proto(pb2, back) != CMT_OK) {
        fprintf(stderr, "%s: MsgFromProto failed\n", what);
        goto done;
    }
    if (cmt_msg_to_proto(back, pb1) != CMT_OK) {
        fprintf(stderr, "%s: MsgToProto (second) failed\n", what);
        goto done;
    }
    if (cmt_pb_cons_message_marshal(pb1, g_buf2, sizeof(g_buf2), &n2)
            != CMT_OK) {
        fprintf(stderr, "%s: marshal (second) failed\n", what);
        goto done;
    }
    if (n1 != n2 || memcmp(g_buf, g_buf2, n1) != 0) {
        fprintf(stderr, "%s: round trip differs (%zu vs %zu)\n", what, n1,
                n2);
        goto done;
    }
    if (back->kind != m->kind) {
        fprintf(stderr, "%s: kind changed\n", what);
        goto done;
    }
    if (out_len != NULL) {
        *out_len = n1;
    }
    ok = 1;
done:
    free(pb1);
    free(pb2);
    free(back);
    return ok;
}

/* ══ the nine messages ════════════════════════════════════════════════ */

static int test_nine_round_trips(void)
{
    cmt_msg_t *m;
    size_t     n = 0;

    m = (cmt_msg_t *)malloc(sizeof(*m));
    CHECK(m != NULL, "allocation");

    /* msgs.go:28-35 / :128-140 — NewRoundStep. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_NEW_ROUND_STEP;
    m->u.new_round_step.height = 1;
    m->u.new_round_step.round  = 1;
    m->u.new_round_step.step   = 1;
    m->u.new_round_step.seconds_since_start_time = -1;  /* :1547 may be < 0 */
    m->u.new_round_step.last_commit_round = -1;         /* :1549 initial   */
    CHECK(round_trip("NewRoundStep", m, &n), "round trip");
    OK();

    /* msgs.go:37-46 / :141-156 — NewValidBlock with a BitArray. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_NEW_VALID_BLOCK;
    m->u.new_valid_block.height = 9;
    m->u.new_valid_block.round  = 2;
    psh_a(&m->u.new_valid_block.block_part_set_header);
    m->u.new_valid_block.has_block_parts = true;
    bits_1(&m->u.new_valid_block.block_parts);
    m->u.new_valid_block.is_commit = true;
    CHECK(round_trip("NewValidBlock", m, &n), "round trip");
    OK();

    /* msgs.go:48-52 / :157-165 — Proposal. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_PROPOSAL;
    cmt_pb_proposal_init(&m->u.proposal.proposal);
    m->u.proposal.proposal.type      = 32;
    m->u.proposal.proposal.height    = 1;
    m->u.proposal.proposal.round     = 1;
    m->u.proposal.proposal.pol_round = 1;
    bid_a(&m->u.proposal.proposal.block_id);
    m->u.proposal.proposal.timestamp = TS_A;
    memcpy(m->u.proposal.proposal.signature, SIG_S, sizeof(SIG_S));
    m->u.proposal.proposal.signature_len = sizeof(SIG_S);
    CHECK(round_trip("Proposal", m, &n), "round trip");
    OK();

    /* msgs.go:54-60 / :166-173 — ProposalPOL. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_PROPOSAL_POL;
    m->u.proposal_pol.height = 1;
    m->u.proposal_pol.proposal_pol_round = 1;
    m->u.proposal_pol.has_proposal_pol = true;
    bits_1(&m->u.proposal_pol.proposal_pol);
    CHECK(round_trip("ProposalPOL", m, &n), "round trip");
    OK();

    /* msgs.go:62-71 / :174-183 — BlockPart. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_BLOCK_PART;
    m->u.block_part.height = 100;
    m->u.block_part.round  = 1;
    cmt_pb_part_init(&m->u.block_part.part);
    m->u.block_part.part.index      = 1;
    m->u.block_part.part.bytes.data = TEST_BYTES;
    m->u.block_part.part.bytes.len  = sizeof(TEST_BYTES);
    m->u.block_part.part.proof.total = 1;
    m->u.block_part.part.proof.index = 1;
    memcpy(m->u.block_part.part.proof.leaf_hash, HASH_A, 64);
    m->u.block_part.part.proof.leaf_hash_len = 64;
    CHECK(round_trip("BlockPart", m, &n), "round trip");
    OK();

    /* msgs.go:73-77 / :184-194 — Vote. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_VOTE;
    m->u.vote.has_vote = true;
    cmt_pb_vote_init(&m->u.vote.vote);
    m->u.vote.vote.type   = 2;
    m->u.vote.vote.height = 1;
    m->u.vote.vote.round  = 0;
    bid_a(&m->u.vote.vote.block_id);
    m->u.vote.vote.timestamp = TS_A;
    memcpy(m->u.vote.vote.validator_address, ADDR_A, 32);
    m->u.vote.vote.validator_address_len = 32;
    m->u.vote.vote.validator_index = 1;
    memcpy(m->u.vote.vote.signature, SIG_S, sizeof(SIG_S));
    m->u.vote.vote.signature_len = sizeof(SIG_S);
    CHECK(round_trip("Vote", m, &n), "round trip");
    OK();

    /* msgs.go:79-85 / :195-201 — HasVote. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_HAS_VOTE;
    m->u.has_vote.height = 1;
    m->u.has_vote.round  = 1;
    m->u.has_vote.type   = 1;
    m->u.has_vote.index  = 1;
    CHECK(round_trip("HasVote", m, &n), "round trip");
    OK();

    /* msgs.go:87-94 / :202-212 — VoteSetMaj23. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_VOTE_SET_MAJ23;
    m->u.vote_set_maj23.height = 1;
    m->u.vote_set_maj23.round  = 1;
    m->u.vote_set_maj23.type   = 1;
    bid_a(&m->u.vote_set_maj23.block_id);
    CHECK(round_trip("VoteSetMaj23", m, &n), "round trip");
    OK();

    /* msgs.go:96-111 / :213-227 — VoteSetBits. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_VOTE_SET_BITS;
    m->u.vote_set_bits.height = 1;
    m->u.vote_set_bits.round  = 1;
    m->u.vote_set_bits.type   = 1;
    bid_a(&m->u.vote_set_bits.block_id);
    m->u.vote_set_bits.has_votes = true;
    bits_1(&m->u.vote_set_bits.votes);
    CHECK(round_trip("VoteSetBits", m, &n), "round trip");
    OK();

    free(m);
    return 0;
}

/* ══ the POINTER fields, one behaviour each ═══════════════════════════ */

static int test_pointer_fields(void)
{
    cmt_msg_t             *m;
    cmt_pb_cons_message_t *pb;
    size_t                 n = 0;

    m  = (cmt_msg_t *)malloc(sizeof(*m));
    pb = (cmt_pb_cons_message_t *)malloc(sizeof(*pb));
    CHECK(m != NULL && pb != NULL, "allocation");

    /* msgs.go:39, :44 — a nil BlockParts leaves field 4 OFF the wire.
     * `ToProto()` returns nil for a nil array OR one with no words
     * (bit_array.go:476-478), and both must behave the same. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_NEW_VALID_BLOCK;
    m->u.new_valid_block.height = 1;
    m->u.new_valid_block.has_block_parts = false;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_OK &&
          !pb->u.new_valid_block.has_block_parts,
          "a nil BlockParts pointer converts to an absent field");
    m->u.new_valid_block.has_block_parts = true;   /* non-nil but EMPTY */
    memset(&m->u.new_valid_block.block_parts, 0,
           sizeof(m->u.new_valid_block.block_parts));
    CHECK(cmt_msg_to_proto(m, pb) == CMT_OK &&
          !pb->u.new_valid_block.has_block_parts,
          "and so does a non-nil array with no words");
    OK();

    /* msgs.go:74-77 — a nil Vote pointer leaves the BRANCH with an empty
     * body, because Vote.ToProto() returns nil (types/vote.go:374-376)
     * and the proto field is a pointer. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_VOTE;
    m->u.vote.has_vote = false;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_OK && !pb->u.vote.has_vote,
          "a nil Vote converts to an absent field");
    CHECK(cmt_pb_cons_message_marshal(pb, g_buf, sizeof(g_buf), &n)
          == CMT_OK && n == 2 && g_buf[0] == 0x32 && g_buf[1] == 0x00,
          "and the branch is still `32 00` on the wire");
    /* Coming BACK, msgs.go:187 dereferences that nil at types/vote.go:82
     * and panics; a peer can send it, so it is CMT_REJECT. */
    {
        cmt_msg_t *back = (cmt_msg_t *)malloc(sizeof(*back));

        CHECK(back != NULL, "allocation");
        CHECK(cmt_msg_from_proto(pb, back) == CMT_REJECT,
              "and MsgFromProto refuses it, where the reference panics");
        free(back);
    }
    OK();

    /* msgs.go:98, :107-109 — VoteSetBits GUARDS the nil and leaves the
     * ZERO BitArray, which field 5 emits anyway because it is
     * (nullable) = false. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_VOTE_SET_BITS;
    m->u.vote_set_bits.height = 1;
    m->u.vote_set_bits.has_votes = false;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_OK &&
          pb->u.vote_set_bits.votes.bits == 0 &&
          pb->u.vote_set_bits.votes.n_elems == 0,
          "a nil Votes leaves the zero BitArray, not an absent field");
    /* DERIVATION of the length (Delta B-1, ORCHESTRATOR — the executor's
     * first expectation of 8 counted the BRANCH body and forgot the oneof
     * wrapper): body = `08 01` height (2) ‖ `22 02 12 00` field 4, the
     * empty BlockID whose ALWAYS PartSetHeader is `12 00` (4) ‖ `2a 00`
     * field 5, the empty BitArray (2) = 8 bytes; wrapped as Message branch
     * 9: `4a 08` ‖ body = 10 bytes. The last two bytes are field 5. */
    CHECK(cmt_pb_cons_message_marshal(pb, g_buf, sizeof(g_buf), &n)
          == CMT_OK && n == 10 && g_buf[0] == 0x4a && g_buf[1] == 0x08 &&
          g_buf[n - 2] == 0x2a && g_buf[n - 1] == 0x00,
          "and it is still written, as `2a 00`");
    OK();

    /* msgs.go:55, :59 — ProposalPOL DOES NOT guard it: `*pbBits`
     * dereferences a nil. CMT_FAULT, because the POL is built from this
     * node's own vote set. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_PROPOSAL_POL;
    m->u.proposal_pol.height = 1;
    m->u.proposal_pol.has_proposal_pol = false;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_FAULT,
          "an empty ProposalPOL is FAULT, where the reference nil-derefs");
    m->u.proposal_pol.has_proposal_pol = true;
    memset(&m->u.proposal_pol.proposal_pol, 0,
           sizeof(m->u.proposal_pol.proposal_pol));
    CHECK(cmt_msg_to_proto(m, pb) == CMT_FAULT,
          "and so is a non-nil array with no words — the same nil");
    OK();

    free(m);
    free(pb);
    return 0;
}

/* ══ the refusals ═════════════════════════════════════════════════════ */

static int test_refusals(void)
{
    cmt_msg_t             *m;
    cmt_pb_cons_message_t *pb;

    m  = (cmt_msg_t *)malloc(sizeof(*m));
    pb = (cmt_pb_cons_message_t *)malloc(sizeof(*pb));
    CHECK(m != NULL && pb != NULL, "allocation");

    /* msgs.go:22-24 — a nil message. */
    memset(m, 0, sizeof(*m));
    m->kind = CMT_PB_CONS_MSG_NONE;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_REJECT,
          "a message with no type is refused");
    /* msgs.go:113-114 — an unrecognised one. */
    m->kind = (cmt_msg_kind_t)42;
    CHECK(cmt_msg_to_proto(m, pb) == CMT_REJECT,
          "and so is an unrecognised type");
    OK();

    /* msgs.go:122-124 and :228-229, the same on the way back. */
    cmt_pb_cons_message_init(pb);
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "a wire message with no branch is refused");
    pb->sum = (cmt_pb_cons_msg_kind_t)42;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "and so is one on an unknown branch");
    OK();

    /* msgs.go:129-133 — SafeConvertUint8 denies a Step above 255. The
     * wire type is uint32 and the Go type is uint8, so this is where a
     * peer's overflow is caught. */
    cmt_pb_cons_message_init(pb);
    pb->sum = CMT_PB_CONS_MSG_NEW_ROUND_STEP;
    cmt_pb_new_round_step_init(&pb->u.new_round_step);
    pb->u.new_round_step.step = 255;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_OK && m->u.new_round_step.step
          == 255, "Step 255 is the largest that converts");
    pb->u.new_round_step.step = 256;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "Step 256 is denied — SafeConvertUint8, msgs.go:129-133");
    pb->u.new_round_step.step = UINT32_MAX;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "and so is the maximum uint32");
    OK();

    /* NULL arguments are FAULT, never REJECT. */
    CHECK(cmt_msg_to_proto(NULL, pb) == CMT_FAULT, "NULL msg");
    CHECK(cmt_msg_to_proto(m, NULL) == CMT_FAULT, "NULL out");
    CHECK(cmt_msg_from_proto(NULL, m) == CMT_FAULT, "NULL proto");
    CHECK(cmt_msg_from_proto(pb, NULL) == CMT_FAULT, "NULL out");
    OK();

    /* A BitArray whose elems do not agree with its bits is refused on the
     * way in — the ported FromProto's explicit bound (INVARIANT
     * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07). */
    cmt_pb_cons_message_init(pb);
    pb->sum = CMT_PB_CONS_MSG_PROPOSAL_POL;
    cmt_pb_proposal_pol_init(&pb->u.proposal_pol);
    pb->u.proposal_pol.proposal_pol.bits    = 65;   /* needs 2 words */
    pb->u.proposal_pol.proposal_pol.n_elems = 1;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "bits = 65 with one word must REJECT");
    pb->u.proposal_pol.proposal_pol.bits    = -1;
    pb->u.proposal_pol.proposal_pol.n_elems = 0;
    CHECK(cmt_msg_from_proto(pb, m) == CMT_REJECT,
          "and a negative bit count must REJECT");
    OK();

    free(m);
    free(pb);
    return 0;
}

int main(void)
{
    build_fixtures();
    arena_reset();

    if (test_nine_round_trips() != 0) { return 1; }
    if (test_pointer_fields() != 0)   { return 1; }
    if (test_refusals() != 0)         { return 1; }

    printf("test_cmt_msgs: OK (%d groups)\n", g_checks);
    return 0;
}
