/**
 * @file nodus_witness_storage_fetch.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the SEGMENT FETCH: channel 0x73 on the witness port 4004. A
 *        holder that must hold segment k and cannot export it from its
 *        own block store fetches it, one part at a time, from another
 *        node that still has the blocks (its block store) or holds the
 *        segment (its file). This header: the wire and the serving side's
 *        decision; the client runs in nodus_witness_storage_holder.c.
 *
 * Decisions: docs/plans/decisions/2026-10-05-kurultay-7-archive-reward-
 * summary.md item 5 ("Fetch is bounded part-level streaming under the
 * 5 MiB frame, verified per chunk; bulk fetch only for active storage
 * members; session pinned to the registered fingerprint"), 2026-10-05-
 * storage-reward-is-for-archive.md (K6: the archive probe on 4004 as
 * 0x72 — this channel follows its framing), 2026-09-26-witness-port-
 * session.md item 3 (the approved channel list: 0x70, 0x71). Design
 * docs/plans/2026-10-05-archive-reward-design.md rev 4 §3.
 *
 * ⚠ PENDING OPERATOR APPROVAL — NEW WIRE. The channel byte 0x73, the
 * request and answer layouts, the codes and the bounds below are this
 * package's choices; no approved record names them (the approved list
 * names 0x70 / 0x71; K6 adds 0x72).
 *
 * ── DETERMINISM (design rev 4 §7 D3, D4) ──────────────────────────────
 * Nothing here writes state or is read by the state machine. What a peer
 * answers, when, and whether a segment file exists decide only which
 * bytes THIS node writes into its own segment directory — and every byte
 * is verified against the consensus-fixed v2_blocks before it is written.
 *
 * ── THE WIRE (channel 0x73 on 4004) ───────────────────────────────────
 * Every message is  kind(1) ‖ body.  All integers big-endian.
 *
 *   kind 0x01 REQUEST — body NODUS_STFETCH_REQ_LEN (37) bytes:
 *     "NDS.STFETCH.v1" padded with 0x00 to 16 ‖ k u64 ‖ h u64 ‖
 *     part u32 ‖ cont u8
 *     k     the segment, >= 1;
 *     h     the height, (k−1)·17280 < h <= k·17280;
 *     part  the part index of block h (0-based), or 0xFFFFFFFF
 *           (NODUS_SEG_PART_COMMIT) = the segment's terminal commit,
 *           then h == k·17280;
 *     cont  the CONTINUATION flag: 0 = this is the first request of
 *           block h — send header(h+1) with the piece; 1 = the requester
 *           continues block h and already holds a verified header(h+1)
 *           — omit it. Any other value is malformed.
 *
 *   kind 0x02 ANSWER —
 *     rq[64] ‖ code(1) ‖ ( code == 0:
 *       hdr_len u32 ‖ header(h+1) proto [hdr_len] ‖
 *       body_len u32 ‖ body [body_len] ‖
 *       proof_len u32 ‖ proof [proof_len] )
 *     rq    = SHA3-512(the 37 request body bytes) — which request this
 *             answers (the 0x71 / 0x72 rq rule);
 *     code  = nodus_stfetch_code_t (0 OK; a refusal is exactly
 *             kind ‖ rq ‖ code, NODUS_STFETCH_REFUSAL_LEN bytes);
 *     hdr   = header(h+1) proto, present (1 … 2048 bytes) iff cont == 0;
 *     body  = a part: the part bytes (0 … 65536); the commit: the
 *             commit proto of k·17280 (1 … NODUS_SEG_COMMIT_MAX);
 *     proof = a part: its Merkle proof proto (1 … 8192); the commit: none
 *             (proof_len 0).
 *   No trailing byte. The widest answer is NODUS_STFETCH_MSG_MAX
 *   (~610 KB, a commit at 128 validators), under the 5 MiB frame — the
 *   commit travels whole because its hash (the binding) is over the
 *   whole of it.
 *
 * ── THE CLIENT'S CHECKS (per chunk, before it is written) ─────────────
 *   The answer must answer the ONE outstanding request (same rq, same
 *   peer). header(h+1), part and commit then go through the segment
 *   build's verification (nodus_witness_storage_segment.h "WHAT IS
 *   VERIFIED") — the bytes doc §6 chain against this node's own
 *   v2_blocks. A peer's bytes reach the disk only after that.
 *
 * ── THE SERVING SIDE (nodus_witness_stfetch_serve) ────────────────────
 *   In order: the request decodes (else the peer is stopped, as on
 *   0x70-0x72); the requester's authenticated 64-byte fingerprint is a
 *   member of the CURRENT frozen storage set S(H), H = floor(tip/E)·E
 *   (committed state: st_freeze copies only ACTIVE registry rows) AND its
 *   registry row is ACTIVE now — the session pin is this: the 4004 secret
 *   connection authenticated the requester's ML-DSA-87 key and the
 *   registry's node_fp must equal SHA3-512 of it in full; segment k is
 *   published (a v2_storage_segments row); the per-requester byte budget
 *   of the epoch is not spent (the holder runtime's table); then the
 *   piece is read from this node's block store when it still has the
 *   block, else from its held segment file, else NOT_HELD.
 *   ONE BLOCK IN FLIGHT PER PEER: the server answers each request at
 *   once (nothing is queued per requester), and the client keeps at most
 *   one request outstanding (nodus_witness_storage_holder.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_STORAGE_FETCH_H
#define NODUS_WITNESS_STORAGE_FETCH_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_store.h"
#include "witness/nodus_witness_storage_segment.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── wire constants (⚠ pending operator approval) ───────────────────── */

#define NODUS_STFETCH_TAG            "NDS.STFETCH.v1"
#define NODUS_STFETCH_TAG_LEN        16u

#define NODUS_STFETCH_KIND_REQ       ((uint8_t)0x01)
#define NODUS_STFETCH_KIND_ANS       ((uint8_t)0x02)

/** tag ‖ k ‖ h ‖ part ‖ cont. */
#define NODUS_STFETCH_REQ_LEN        (16u + 8u + 8u + 4u + 1u)
#define NODUS_STFETCH_REQ_MSG_LEN    (1u + NODUS_STFETCH_REQ_LEN)
/** kind ‖ rq ‖ code. */
#define NODUS_STFETCH_REFUSAL_LEN    (1u + 64u + 1u)

#define NODUS_STFETCH_CONT_FIRST     ((uint8_t)0)
#define NODUS_STFETCH_CONT_HAVE_HDR  ((uint8_t)1)

/** The widest body: the terminal commit (>= one part). */
#define NODUS_STFETCH_BODY_MAX       NODUS_SEG_COMMIT_MAX
/** The widest ANSWER — the 0x73 channel's receive capacity. */
#define NODUS_STFETCH_MSG_MAX        (NODUS_STFETCH_REFUSAL_LEN + 4u +       \
                                      NODUS_SEG_HEADER_MAX + 4u +            \
                                      NODUS_STFETCH_BODY_MAX + 4u +          \
                                      NODUS_STPROBE_PROOF_MAX)

_Static_assert(NODUS_STFETCH_REQ_LEN == 37u, "request layout");
_Static_assert(NODUS_STFETCH_BODY_MAX >= CMT_BLOCK_PART_SIZE_BYTES,
               "a part fits the body bound");
_Static_assert(NODUS_STFETCH_MSG_MAX < 5u * 1024u * 1024u,
               "the answer must fit the 5 MiB frame bound");

/* ── the answer / refusal codes (one byte on the wire) ─────────────── */
typedef enum {
    NODUS_STFETCH_OK               = 0,
    NODUS_STFETCH_REF_NOT_MEMBER   = 1,  /* requester not an ACTIVE member
                                          * of the current frozen set     */
    NODUS_STFETCH_REF_UNKNOWN_SET  = 2,  /* no frozen set at this tip     */
    NODUS_STFETCH_REF_NOT_PUBLISHED= 3,  /* segment k not published here  */
    NODUS_STFETCH_REF_NOT_HELD     = 4,  /* neither store nor file has it */
    NODUS_STFETCH_REF_BUDGET       = 5,  /* the requester's epoch budget
                                          * is spent                      */
    NODUS_STFETCH_REF_FAULT        = 6   /* this node could not answer    */
} nodus_stfetch_code_t;

/* ── the request ────────────────────────────────────────────────────── */

typedef struct {
    uint64_t k;
    uint64_t h;
    uint32_t part;          /* or NODUS_SEG_PART_COMMIT */
    uint8_t  cont;
} nodus_stfetch_req_t;

/** Encode a REQUEST message. Refuses what decode would refuse.
 *  @return 0 / -1. */
int nodus_stfetch_req_encode(const nodus_stfetch_req_t *req,
                             uint8_t out[NODUS_STFETCH_REQ_MSG_LEN]);

/** Decode a REQUEST message: exactly NODUS_STFETCH_REQ_MSG_LEN bytes,
 *  kind 0x01, the padded tag, k >= 1 with k·17280 + 1 inside int64, h in
 *  segment k, part == COMMIT only with h == k·17280, cont 0 or 1.
 *  @return 0 / -1. */
int nodus_stfetch_req_decode(const uint8_t *msg, size_t len,
                             nodus_stfetch_req_t *out);

/** rq = SHA3-512(the 37 request body bytes). @return 0 / -1. */
int nodus_stfetch_req_id(const nodus_stfetch_req_t *req, uint8_t rq[64]);

/* ── the answer ─────────────────────────────────────────────────────── */

/** A decoded ANSWER; the pointers point INTO the message. */
typedef struct {
    uint8_t        rq[64];
    uint8_t        code;
    const uint8_t *hdr;    uint32_t hdr_len;
    const uint8_t *body;   uint32_t body_len;
    const uint8_t *proof;  uint32_t proof_len;
} nodus_stfetch_ans_view_t;

/** A refusal (code != OK). @return 0 / -1. */
int nodus_stfetch_ans_refusal(const uint8_t rq[64], uint8_t code,
                              uint8_t out[NODUS_STFETCH_REFUSAL_LEN]);

/** An OK answer into `out` (cap >= NODUS_STFETCH_MSG_MAX always enough).
 *  `hdr` may be NULL with hdr_len 0; a commit has proof NULL / 0.
 *  @return 0 / -1 (a bound, does not fit). */
int nodus_stfetch_ans_encode(const uint8_t rq[64],
                             const uint8_t *hdr, size_t hdr_len,
                             const uint8_t *body, size_t body_len,
                             const uint8_t *proof, size_t proof_len,
                             uint8_t *out, size_t cap, size_t *len_out);

/** Decode an ANSWER (the generic bounds; no trailing byte; a refusal is
 *  exactly NODUS_STFETCH_REFUSAL_LEN). @return 0 / -1. */
int nodus_stfetch_ans_decode(const uint8_t *msg, size_t len,
                             nodus_stfetch_ans_view_t *out);

/** Whether a decoded OK answer has the shape `req` asks for: header iff
 *  cont == 0; a part: body <= 65536 and a proof; the commit: a body and
 *  no proof. @return true / false. */
bool nodus_stfetch_ans_shape_ok(const nodus_stfetch_req_t *req,
                                const nodus_stfetch_ans_view_t *a);

/* ── the serving side ───────────────────────────────────────────────── */

/**
 * The serving side's whole decision for one decoded request from the
 * peer whose authenticated node key hashes to `sender_fp` (header "THE
 * SERVING SIDE"), the budget excepted (the caller's): admission, then the
 * piece from `store` (may be NULL) or the held file in `seg_dir` (may be
 * NULL). `E` the epoch length. `out` / `cap` receive the OK answer;
 * a refusal writes nothing.
 * @return NODUS_STFETCH_OK (*len_out) or the refusal code.
 */
nodus_stfetch_code_t nodus_witness_stfetch_serve(
        nodus_witness_t *w, nodus_cmt_store_t *store, const char *seg_dir,
        const uint8_t sender_fp[64], const nodus_stfetch_req_t *req,
        uint64_t E, uint8_t *out, size_t cap, size_t *len_out);

/** The piece alone (no admission): from `store` when it has block h
 *  (and, for a part, header(h+1); for the commit, C:k·17280 and
 *  header(k·17280+1)), else from the held segment file in `seg_dir`.
 *  Exported for the unit tests. @return OK / NOT_HELD / FAULT. */
nodus_stfetch_code_t nodus_stfetch_answer_build(
        nodus_cmt_store_t *store, const char *seg_dir,
        const nodus_stfetch_req_t *req, uint8_t *out, size_t cap,
        size_t *len_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STORAGE_FETCH_H */
