/**
 * @file shared/dnac/cmt_msgs.c
 * @brief cometbft @709fd12b `consensus/msgs.go` in C — see cmt_msgs.h for
 *        the contract, the substitutions and the taşınmadı list.
 *
 * Every function carries the `// cometbft@709fd12b <file>:<from>-<to>`
 * line of the Go function it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_msgs.h"
#include "dnac/cmt_safemath.h"   /* SafeConvertUint8 — msgs.go:129 */

#include <string.h>

/* ══ BitArray at the MESSAGE level ════════════════════════════════════
 * `(bA *BitArray) ToProto()` (libs/bits/bit_array.go:475-484) returns a
 * *cmtprotobits.BitArray, and `FromProto` (:487-497) reads one. Wave R1-A
 * ported both with the generated codec FOLDED IN, so `cmt_bits_to_proto`
 * produces BYTES and `cmt_bits_from_proto` consumes them (cmt_pb.h). Here
 * the value is needed as a MESSAGE, because msgs.go stores it in a struct
 * field, so the two rules those functions carry are expressed on the
 * struct instead. This is a shape difference, not a rule difference; the
 * rules and their citations are the same ones.
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * The nil test of `ToProto` (bit_array.go:476-478): a NULL array, or one
 * with no words, converts to nil.
 */
static bool bits_to_proto_is_nil(bool has, const cmt_bit_array_t *ba)
{
    return !has || ba->n_elems == 0u;                  /* :476-478 */
}

/**
 * The value half of `FromProto` (bit_array.go:487-497) plus the length
 * agreement the reference omits and the APPROVED INVARIANT requires —
 * exactly the check `cmt_bits_from_proto` makes after decoding
 * (cmt_pb.h's note on it).
 */
static int bits_from_proto_value(const cmt_bit_array_t *in,
                                 cmt_bit_array_t *out)
{
    if (in->bits < 0 || in->bits > (int)CMT_BITS_MAX_BITS) {
        return CMT_REJECT;
    }
    if (in->n_elems != cmt_bits_num_elems(in->bits)) {
        return CMT_REJECT;
    }
    *out = *in;                                        /* :493-496 */
    return CMT_OK;
}

/* ══ MsgToProto ═══════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/msgs.go:21-118 — MsgToProto() */
int cmt_msg_to_proto(const cmt_msg_t *msg, cmt_pb_cons_message_t *out)
{
    int rc;

    if (msg == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (msg->kind == CMT_PB_CONS_MSG_NONE) {
        return CMT_REJECT;                 /* :22-24 "message is nil" */
    }
    cmt_pb_cons_message_init(out);
    out->sum = (cmt_pb_cons_msg_kind_t)msg->kind;

    switch (msg->kind) {
    case CMT_PB_CONS_MSG_NEW_ROUND_STEP: {           /* :28-35 */
        const cmt_new_round_step_msg_t *m = &msg->u.new_round_step;
        cmt_pb_new_round_step_t        *pb = &out->u.new_round_step;

        cmt_pb_new_round_step_init(pb);
        pb->height                  = m->height;                 /* :30 */
        pb->round                   = m->round;                  /* :31 */
        pb->step                    = (uint32_t)m->step;         /* :32 */
        pb->seconds_since_start_time = m->seconds_since_start_time;/* :33 */
        pb->last_commit_round       = m->last_commit_round;      /* :34 */
        break;
    }
    case CMT_PB_CONS_MSG_NEW_VALID_BLOCK: {          /* :37-46 */
        const cmt_new_valid_block_msg_t *m = &msg->u.new_valid_block;
        cmt_pb_new_valid_block_t        *pb = &out->u.new_valid_block;

        cmt_pb_new_valid_block_init(pb);
        rc = cmt_psh_to_proto(&m->block_part_set_header,
                              &pb->block_part_set_header);       /* :38 */
        if (rc != CMT_OK) {
            return rc;
        }
        /* :39, :44 — ToProto() into a POINTER field: a nil result simply
         * leaves the field off the wire. */
        pb->has_block_parts = !bits_to_proto_is_nil(m->has_block_parts,
                                                    &m->block_parts);
        if (pb->has_block_parts) {
            pb->block_parts = m->block_parts;
        }
        pb->height    = m->height;                               /* :41 */
        pb->round     = m->round;                                /* :42 */
        pb->is_commit = m->is_commit;                            /* :45 */
        break;
    }
    case CMT_PB_CONS_MSG_PROPOSAL: {                 /* :48-52 */
        cmt_pb_cons_proposal_init(&out->u.proposal);
        rc = cmt_proposal_to_proto(&msg->u.proposal.proposal,
                                   &out->u.proposal.proposal);   /* :49 */
        if (rc != CMT_OK) {
            return rc;
        }
        break;
    }
    case CMT_PB_CONS_MSG_PROPOSAL_POL: {             /* :54-60 */
        const cmt_proposal_pol_msg_t *m = &msg->u.proposal_pol;
        cmt_pb_proposal_pol_t        *pb = &out->u.proposal_pol;

        cmt_pb_proposal_pol_init(pb);
        /* :55, :59 — `ProposalPol: *pbBits` DEREFERENCES the result of
         * ToProto() with no nil check, so a nil array or one with no words
         * is a nil-pointer panic in the reference. CMT_FAULT: a
         * ProposalPOL is built from THIS node's own vote set, so an empty
         * one is a local inconsistency and not a peer's message. (The
         * reference's ValidateBasic refuses it as well, reactor.go:1660.) */
        if (bits_to_proto_is_nil(m->has_proposal_pol, &m->proposal_pol)) {
            return CMT_FAULT;
        }
        pb->proposal_pol       = m->proposal_pol;                /* :59 */
        pb->height             = m->height;                      /* :57 */
        pb->proposal_pol_round = m->proposal_pol_round;          /* :58 */
        break;
    }
    case CMT_PB_CONS_MSG_BLOCK_PART: {               /* :62-71 */
        const cmt_block_part_msg_t *m = &msg->u.block_part;
        cmt_pb_block_part_t        *pb = &out->u.block_part;

        cmt_pb_block_part_init(pb);
        rc = cmt_part_to_proto(&m->part, &pb->part);             /* :63-66 */
        if (rc != CMT_OK) {
            return rc;
        }
        pb->height = m->height;                                  /* :68 */
        pb->round  = m->round;                                   /* :69 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE: {                     /* :73-77 */
        const cmt_vote_msg_t *m = &msg->u.vote;

        cmt_pb_cons_vote_init(&out->u.vote);
        /* :74 — Vote.ToProto() returns nil for a nil receiver
         * (types/vote.go:374-376) and :76 stores it in a POINTER field. */
        out->u.vote.has_vote = m->has_vote;
        if (m->has_vote) {
            rc = cmt_vote_to_proto(&m->vote, &out->u.vote.vote);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        break;
    }
    case CMT_PB_CONS_MSG_HAS_VOTE: {                 /* :79-85 */
        const cmt_has_vote_msg_t *m = &msg->u.has_vote;
        cmt_pb_has_vote_t        *pb = &out->u.has_vote;

        cmt_pb_has_vote_init(pb);
        pb->height = m->height;                                  /* :81 */
        pb->round  = m->round;                                   /* :82 */
        pb->type   = m->type;                                    /* :83 */
        pb->index  = m->index;                                   /* :84 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE_SET_MAJ23: {           /* :87-94 */
        const cmt_vote_set_maj23_msg_t *m = &msg->u.vote_set_maj23;
        cmt_pb_vote_set_maj23_t        *pb = &out->u.vote_set_maj23;

        cmt_pb_vote_set_maj23_init(pb);
        rc = cmt_block_id_to_proto(&m->block_id, &pb->block_id); /* :88 */
        if (rc != CMT_OK) {
            return rc;
        }
        pb->height = m->height;                                  /* :90 */
        pb->round  = m->round;                                   /* :91 */
        pb->type   = m->type;                                    /* :92 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE_SET_BITS: {            /* :96-111 */
        const cmt_vote_set_bits_msg_t *m = &msg->u.vote_set_bits;
        cmt_pb_vote_set_bits_t        *pb = &out->u.vote_set_bits;

        cmt_pb_vote_set_bits_init(pb);
        rc = cmt_block_id_to_proto(&m->block_id, &pb->block_id); /* :97 */
        if (rc != CMT_OK) {
            return rc;
        }
        pb->height = m->height;                                  /* :101 */
        pb->round  = m->round;                                   /* :102 */
        pb->type   = m->type;                                    /* :103 */
        /* :98, :107-109 — unlike ProposalPOL, this one GUARDS the nil and
         * leaves the zero BitArray, which field 5 still emits because it
         * is (nullable) = false. */
        if (!bits_to_proto_is_nil(m->has_votes, &m->votes)) {
            pb->votes = m->votes;
        }
        break;
    }
    default:
        return CMT_REJECT;                 /* :113-114 not recognised */
    }
    return CMT_OK;
}

/* ══ MsgFromProto ═════════════════════════════════════════════════════ */

/* cometbft@709fd12b consensus/msgs.go:121-237 — MsgFromProto().
 *
 * ⚠ The reference's last act is `pb.ValidateBasic()` at :232-234. This
 * port stops before it; see cmt_msgs.h. */
int cmt_msg_from_proto(const cmt_pb_cons_message_t *p, cmt_msg_t *out)
{
    int rc;

    if (p == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (p->sum == CMT_PB_CONS_MSG_NONE) {
        return CMT_REJECT;                 /* :122-124 "nil message" */
    }
    memset(out, 0, sizeof(*out));
    out->kind = (cmt_msg_kind_t)p->sum;

    switch (p->sum) {
    case CMT_PB_CONS_MSG_NEW_ROUND_STEP: {           /* :128-140 */
        const cmt_pb_new_round_step_t *pb = &p->u.new_round_step;
        cmt_new_round_step_msg_t      *m = &out->u.new_round_step;
        uint8_t                        rs;

        /* :129-133 — SafeConvertUint8 denies the message on overflow. */
        rc = cmt_safe_convert_uint8((int64_t)pb->step, &rs);
        if (rc != CMT_OK) {
            return rc;
        }
        m->height                   = pb->height;                /* :135 */
        m->round                    = pb->round;                 /* :136 */
        m->step                     = rs;                        /* :137 */
        m->seconds_since_start_time = pb->seconds_since_start_time;/* :138 */
        m->last_commit_round        = pb->last_commit_round;     /* :139 */
        break;
    }
    case CMT_PB_CONS_MSG_NEW_VALID_BLOCK: {          /* :141-156 */
        const cmt_pb_new_valid_block_t *pb = &p->u.new_valid_block;
        cmt_new_valid_block_msg_t      *m = &out->u.new_valid_block;

        rc = cmt_psh_from_proto(&pb->block_part_set_header,
                                &m->block_part_set_header);      /* :142 */
        if (rc != CMT_OK) {
            return rc;
        }
        /* :147-148 — a FRESH BitArray is filled from the wire value.
         * `FromProto` on a nil argument leaves it empty
         * (bit_array.go:488-490), which is the absent-field case; the
         * resulting message is non-nil either way (:154), so
         * has_block_parts is always true here, exactly as the reference's
         * `pbBits := new(bits.BitArray)` is never nil. */
        if (pb->has_block_parts) {
            rc = bits_from_proto_value(&pb->block_parts, &m->block_parts);
            if (rc != CMT_OK) {
                return rc;
            }
        }
        m->has_block_parts = true;
        m->height    = pb->height;                               /* :151 */
        m->round     = pb->round;                                /* :152 */
        m->is_commit = pb->is_commit;                            /* :155 */
        break;
    }
    case CMT_PB_CONS_MSG_PROPOSAL: {                 /* :157-165 */
        rc = cmt_proposal_from_proto(&p->u.proposal.proposal,
                                     &out->u.proposal.proposal); /* :158 */
        if (rc != CMT_OK) {
            return rc;
        }
        break;
    }
    case CMT_PB_CONS_MSG_PROPOSAL_POL: {             /* :166-173 */
        const cmt_pb_proposal_pol_t *pb = &p->u.proposal_pol;
        cmt_proposal_pol_msg_t      *m = &out->u.proposal_pol;

        rc = bits_from_proto_value(&pb->proposal_pol,
                                   &m->proposal_pol);            /* :167-168 */
        if (rc != CMT_OK) {
            return rc;
        }
        m->has_proposal_pol   = true;                            /* :172 */
        m->height             = pb->height;                      /* :170 */
        m->proposal_pol_round = pb->proposal_pol_round;          /* :171 */
        break;
    }
    case CMT_PB_CONS_MSG_BLOCK_PART: {               /* :174-183 */
        const cmt_pb_block_part_t *pb = &p->u.block_part;
        cmt_block_part_msg_t      *m = &out->u.block_part;

        rc = cmt_part_from_proto(&pb->part, &m->part);           /* :175-178 */
        if (rc != CMT_OK) {
            return rc;
        }
        m->height = pb->height;                                  /* :180 */
        m->round  = pb->round;                                   /* :181 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE: {                     /* :184-194 */
        const cmt_pb_cons_vote_t *pb = &p->u.vote;

        /* :187 — `types.VoteFromProto(msg.Vote)` on a NIL pointer
         * DEREFERENCES it immediately (`&pv.BlockID`, types/vote.go:82),
         * so the reference panics here; it has no nil check. The absent
         * POINTER field on the wire IS that nil, and it arrives from a
         * PEER, so the panic maps to CMT_REJECT and never to FAULT. */
        if (!pb->has_vote) {
            return CMT_REJECT;
        }
        rc = cmt_vote_from_proto(&pb->vote, &out->u.vote.vote);
        if (rc != CMT_OK) {
            return rc;
        }
        out->u.vote.has_vote = true;                             /* :193 */
        break;
    }
    case CMT_PB_CONS_MSG_HAS_VOTE: {                 /* :195-201 */
        const cmt_pb_has_vote_t *pb = &p->u.has_vote;
        cmt_has_vote_msg_t      *m = &out->u.has_vote;

        m->height = pb->height;                                  /* :197 */
        m->round  = pb->round;                                   /* :198 */
        m->type   = pb->type;                                    /* :199 */
        m->index  = pb->index;                                   /* :200 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE_SET_MAJ23: {           /* :202-212 */
        const cmt_pb_vote_set_maj23_t *pb = &p->u.vote_set_maj23;
        cmt_vote_set_maj23_msg_t      *m = &out->u.vote_set_maj23;

        rc = cmt_block_id_from_proto(&pb->block_id, &m->block_id);/* :203 */
        if (rc != CMT_OK) {
            return rc;
        }
        m->height = pb->height;                                  /* :208 */
        m->round  = pb->round;                                   /* :209 */
        m->type   = pb->type;                                    /* :210 */
        break;
    }
    case CMT_PB_CONS_MSG_VOTE_SET_BITS: {            /* :213-227 */
        const cmt_pb_vote_set_bits_t *pb = &p->u.vote_set_bits;
        cmt_vote_set_bits_msg_t      *m = &out->u.vote_set_bits;

        rc = cmt_block_id_from_proto(&pb->block_id, &m->block_id);/* :214 */
        if (rc != CMT_OK) {
            return rc;
        }
        rc = bits_from_proto_value(&pb->votes, &m->votes);       /* :218-219 */
        if (rc != CMT_OK) {
            return rc;
        }
        m->has_votes = true;                                     /* :226 */
        m->height    = pb->height;                               /* :222 */
        m->round     = pb->round;                                /* :223 */
        m->type      = pb->type;                                 /* :224 */
        break;
    }
    default:
        return CMT_REJECT;                 /* :228-229 not recognised */
    }
    return CMT_OK;
}
