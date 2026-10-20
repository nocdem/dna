/**
 * @file nodus_light_hashlist.h
 * @brief Storage package P-B2 — the LIGHT HASH LIST: the trusted block
 *        hashes of one historical segment k, built on a node that has no
 *        ledger by hash-chaining headers backwards from ONE light-verified
 *        header, without executing a block. Its result is a hash source
 *        (nodus_seg_hash_src_t, package P-B1) for the existing segment
 *        build (nodus_seg_build_open_src).
 *
 * Governing: design docs/plans/2026-10-19-windows-light-storage-design.md
 * §3 B2 and its "Rev 1 corrections" (the B2 verification contract and
 * cost), §5, §6 (G1 a lying peer can delay, never inject; G4 the anchor's
 * trust root stays K25-12); decision docs/plans/decisions/2026-10-19-
 * kurultay-26b-summary.md item 9 (piece B = the historical-segment
 * builder only; serving is a later package); docs/plans/decisions/2026-
 * 10-16-kurultay-25-summary.md K25-9 (one light client — the anchor is
 * the existing light client's, never a second verifier), K25-12 (its
 * trust root = the pinned nodes). The 0x73 wire: decision 2026-10-05-
 * storage-reward-is-for-archive.md K6b (nodus_witness_storage_fetch.h).
 *
 * ── THE CHAIN IT FOLLOWS ───────────────────────────────────────────────
 * cometbft headers chain: header(h+1).last_block_id.hash = hash(header(
 * h)). Segment k covers first = (k−1)·P + 1 … last = k·P (P =
 * DNA_V2_SEGMENT_BLOCKS, 17 280 at the shipped epoch length); its build
 * asks the trusted hash at every height of [first, last + 1]
 * (nodus_witness_storage_segment.c check_header: h and h + 1). So:
 *   1. THE ANCHOR — header(last + 1), verified by the light client
 *      against its trust root (cmt_light_client_verify_light_block_at_
 *      height; nodus_light_hashlist_new_from_client below does exactly
 *      that). It gives hash(last + 1) = cmt_header_hash(anchor) and
 *      hash(last) = anchor.last_block_id.hash.
 *   2. THE HEADER PASS — for h = last − 1 down to first, ONE 0x73 request
 *      (k, h, part 0, cont 0): the answer carries header(h + 1) (and part
 *      0 of block h, which is dropped — design §3 B3). header(h + 1) is
 *      accepted only if, in this order:
 *        a. the answer decodes (nodus_stfetch_ans_decode), answers THIS
 *           request (same rq = SHA3-512 of its 37 bytes), is OK (a
 *           refusal is not a header) and has the request's shape
 *           (nodus_stfetch_ans_shape_ok: a header because cont = 0);
 *        b. the header decodes (cmt_pb_header_unmarshal);
 *        c. its height is EXACTLY h + 1 — the light verifier does not
 *           check heights (cmt_light_verifier.h, cmt_light_verify_
 *           backwards "NOTE");
 *        d. cmt_light_verify_backwards(candidate, the trusted header
 *           above it, block_protocol) passes — the reference's
 *           VerifyBackwards (light/verifier.go:212-245): Header.
 *           ValidateBasic, the same chain id, a strictly earlier time,
 *           and the candidate's hash equal to the trusted header's
 *           last_block_id.hash;
 *        e. cmt_header_hash(candidate) equals the hash this list already
 *           holds for h + 1 (the same equality as d's last step, checked
 *           here by this file itself — never only by a helper);
 *        f. its last_block_id.hash is 64 bytes (the segment build's own
 *           rule, check_header V_BLOCK_ID).
 *      Then hash(h) = candidate.last_block_id.hash and the candidate is
 *      the trusted header for the next step. last − first = P − 1
 *      requests (17 279) — the design's "+17 279 requests".
 *   The list never holds a hash on a peer's word: every hash below the
 *   anchor is the last_block_id of a header that hash-chains to it.
 *
 * ── PEERS (the holder's rotation rule, nodus_witness_storage_holder.h
 *    "THE FETCH CLIENT") ───────────────────────────────────────────────
 * ONE request outstanding, to ONE peer. A silent peer (the transport's
 * timeout), a refusal, a malformed answer or a header that fails a–f
 * moves to the next peer (index + 1 mod n); an accepted header keeps the
 * same peer. A full round of n peers without an accepted header ends the
 * step with NODUS_LHL_STEP_ROUND; the caller waits (the holder waits
 * NODUS_STFETCH_RETRY_MS) and steps again, from the next peer. The
 * transport is the caller's (nodus_light_fetch_t) — this file opens no
 * socket, reads no clock and never sleeps.
 *
 * ── MEMORY ─────────────────────────────────────────────────────────────
 * Heap only: the list (P + 1) × 64 bytes (1.1 MB at P = 17 280), two
 * decoded headers and one answer buffer of NODUS_STFETCH_MSG_MAX bytes.
 * Nothing is kept on disk; a restart starts the pass again (B3: v1 keeps
 * one code path).
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Node-local: nothing here enters a block, a vote, a state root or
 * replication. For the same anchor every honest run yields the same P + 1
 * hashes (each one is fixed by the anchor through the hash chain), in
 * whatever order peers answered; which peer answered and how often one
 * was refused only change the statistics.
 *
 * ── NOT HERE ───────────────────────────────────────────────────────────
 * Serving (0x72 / 0x73 on a light node — waits for HF-7, K25-7), the
 * assignment (which k to hold), the 4004 transport, the parts / set /
 * commit fetch (the segment build's existing pieces), a nodus-light
 * command.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_LIGHT_HASHLIST_H
#define NODUS_LIGHT_HASHLIST_H

#include "witness/nodus_witness_storage_segment.h"   /* nodus_seg_hash_src_t */
#include "witness/nodus_witness_storage_fetch.h"     /* the 0x73 wire        */
#include "dnac/cmt_block.h"
#include "dnac/cmt_light_client.h"
#include "dnac/cmt_time.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── the transport (the caller's) ───────────────────────────────────── */

/**
 * One 0x73 exchange with peer `peer` (0 … n_peers − 1): send the REQUEST
 * message `req` (NODUS_STFETCH_REQ_MSG_LEN bytes, kind 0x01 ‖ body) and
 * wait for that peer's answer, at most the caller's timeout.
 * @return 0 an answer from that peer in ans[0 .. *ans_len) (any bytes —
 *           every check is this file's), 1 no answer (silence, timeout,
 *           peer not connected, a message larger than `cap`), -1 a local
 *           fault (the step stops with NODUS_LHL_STEP_FAULT).
 */
typedef int (*nodus_light_fetch_fn)(void *ctx, size_t peer,
                                    const uint8_t *req, size_t req_len,
                                    uint8_t *ans, size_t cap,
                                    size_t *ans_len);

typedef struct {
    void                *ctx;
    size_t               n_peers;      /* >= 1                           */
    nodus_light_fetch_fn request;
} nodus_light_fetch_t;

/* ── why a candidate was not accepted ───────────────────────────────── */

typedef enum {
    NODUS_LHL_R_SILENT = 0,   /* the transport returned no answer        */
    NODUS_LHL_R_ANSWER,       /* does not decode as a 0x73 answer        */
    NODUS_LHL_R_RQ,           /* answers another request                 */
    NODUS_LHL_R_REFUSED,      /* a refusal code (NOT_HELD, …)            */
    NODUS_LHL_R_SHAPE,        /* not the shape of a cont = 0 part answer */
    NODUS_LHL_R_HDR_DECODE,   /* header(h+1) does not decode             */
    NODUS_LHL_R_HEIGHT,       /* its height is not h + 1                 */
    NODUS_LHL_R_BACKWARDS,    /* cmt_light_verify_backwards refused it   */
    NODUS_LHL_R_HASH,         /* its hash != the list's hash at h + 1    */
    NODUS_LHL_R_BLOCK_ID,     /* last_block_id.hash is not 64 bytes      */
    NODUS_LHL_R_COUNT
} nodus_lhl_refusal_t;

/** A short name for logs. Never NULL. */
const char *nodus_lhl_refusal_str(nodus_lhl_refusal_t r);

typedef struct {
    uint64_t requests;                    /* exchanges attempted          */
    uint64_t accepted;                    /* headers accepted             */
    uint64_t refused[NODUS_LHL_R_COUNT];  /* per reason                   */
} nodus_lhl_stats_t;

/* ── the list ───────────────────────────────────────────────────────── */

typedef struct nodus_light_hashlist nodus_light_hashlist_t;

/**
 * A list for segment k anchored at `anchor` = header(k·P + 1), which the
 * CALLER vouches the light client verified (G4: its trust root is the
 * light client's, K25-12) — use nodus_light_hashlist_new_from_client
 * unless the header comes straight from cmt_light_client_verify_light_
 * block_at_height / cmt_light_client_trusted_light_block. The anchor is
 * copied. `block_protocol` is the value Version.Block must equal
 * (CMT_BLOCK_PROTOCOL, as the light client's options).
 * Refused (-1): k == 0; k·P + 1 outside int64 (the 0x73 request rule,
 * nodus_stfetch_req_valid); NULL; an anchor whose height is not exactly
 * k·P + 1 (segment k's range must end right below it); an anchor whose
 * own hash is nil or whose last_block_id.hash is not 64 bytes; out of
 * memory. *out is heap (nodus_light_hashlist_free).
 */
int nodus_light_hashlist_new(uint64_t k, const cmt_header_t *anchor,
                             uint64_t block_protocol,
                             nodus_light_hashlist_t **out);

/**
 * nodus_light_hashlist_new over the anchor the light client `c` returns
 * for height k·P + 1 (cmt_light_client_verify_light_block_at_height at
 * `now`: a block it already trusts as is, else fetched from its primary
 * and verified, saved in its store). The light client's own rules and
 * errors are untouched; `err` (may be NULL) receives its error.
 * @return 0 / 1 the light client refused or could not verify that height
 *         (CMT_REJECT; *err says why) / -1 fault, or k refused as above.
 */
int nodus_light_hashlist_new_from_client(cmt_light_client_t *c, uint64_t k,
                                         cmt_time_t now,
                                         uint64_t block_protocol,
                                         nodus_light_hashlist_t **out,
                                         cmt_light_client_error_t *err);

/** NULL-safe. Clears the list. */
void nodus_light_hashlist_free(nodus_light_hashlist_t *hl);

/** The segment number. */
uint64_t nodus_light_hashlist_k(const nodus_light_hashlist_t *hl);

#define NODUS_LHL_STEP_MORE     0   /* headers left; call again          */
#define NODUS_LHL_STEP_DONE     1   /* every hash of [first, last+1] held */
#define NODUS_LHL_STEP_ROUND    2   /* a full round of peers without an
                                     * accepted header; wait, call again */
#define NODUS_LHL_STEP_FAULT  (-1)  /* NULL, a transport or hash fault   */

/**
 * The header pass, bounded: at most `max_headers` headers accepted per
 * call (the rotation rule in the file header). Already complete →
 * NODUS_LHL_STEP_DONE at once.
 */
int nodus_light_hashlist_step(nodus_light_hashlist_t *hl,
                              const nodus_light_fetch_t *f,
                              uint32_t max_headers);

/** The height whose request goes out next (the answer brings header(h +
 *  1)), or 0 when the list is complete. */
uint64_t nodus_light_hashlist_next_height(const nodus_light_hashlist_t *hl);

/** The peer the next request goes to. */
size_t nodus_light_hashlist_peer(const nodus_light_hashlist_t *hl);

/** The counters so far (copied). */
nodus_lhl_stats_t nodus_light_hashlist_stats(const nodus_light_hashlist_t *hl);

/**
 * The list as the segment build's hash source (P-B1): hash_at(h) answers
 * 0 with the hash for h in [first, last + 1] ONLY once the list is
 * complete (step returned DONE), 1 (absent) for every other h and for
 * every h before that, -1 for a NULL ctx. The source points at `hl`;
 * `hl` must outlive every build opened over it (nodus_seg_hash_src_t's
 * contract) — a complete list never changes again, so it answers the
 * same hashes for as long as it lives.
 */
nodus_seg_hash_src_t nodus_light_hashlist_src(const nodus_light_hashlist_t *hl);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_LIGHT_HASHLIST_H */
