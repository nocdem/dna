/**
 * @file nodus_witness_storage_probe.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-1 —
 *        the NODE side of the archive probe, transport-independent half:
 *        the probe request / answer wire, the serving side's request
 *        checks and answer builder (from the block store), the
 *        reporter's verification chain (against its OWN v2_blocks
 *        hashes), the STORAGE_REPORT call + envelope builder, and the
 *        epoch / window arithmetic the reporter paces itself by.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (K3 3 samples), 2026-10-05-archive-reward-bytes-approved.md
 * (the request bytes and the sample derivation, bytes doc §6),
 * 2026-10-05-kurultay-7-archive-reward-summary.md (verification through
 * the authenticated SUCCESSOR header; a fresh reporter nonce and a
 * deadline), 2026-10-04-storage-reward-who-earns.md. Design docs/plans/
 * 2026-10-05-archive-reward-design.md rev 4 §4 + kept rev 2.2 §4 (the
 * report window, expiry <= tip + 100).
 *
 * ── DETERMINISM (design rev 4 §7 D3) ──────────────────────────────────
 * NOTHING here is a consensus input. The nonce (OS CSPRNG), the deadline
 * (this node's wall clock), the answer and the network timing decide only
 * which bits THIS reporter signs into its STORAGE_REPORT; the report is
 * the ONE path into state, judged by the STORAGE_REPORT exec
 * (nodus_witness_rt_native.c) and the settlement
 * (nodus_witness_v2_storage.c) like any other envelope. Two honest
 * reporters may sign different bits for the same target — the > 2/3
 * rule over reporting power is what settles it.
 *
 * ── THE WIRE (channel 0x72 on 4004, nodus_witness_p2p.h) ──────────────
 * Every message is  kind(1) ‖ body.  All integers big-endian.
 *
 *   kind 0x01 REQUEST — body = EXACTLY the approved bytes doc §6 request,
 *   NODUS_STPROBE_REQ_LEN (288) bytes:
 *     "NDS.STPROBE.v2" padded with 0x00 to 16 ‖ chain_id[32] ‖
 *     epoch_start u64 ‖ S(H)[64] ‖ target_fp[64] ‖ reporter_fp[64] ‖
 *     nonce[32] ‖ deadline_ms u64
 *   The request carries no signature of its own: bytes doc §6 "signed by
 *   the reporter's node key (existing inter-node session auth)" — the
 *   4004 secret connection authenticated the sender's ML-DSA-87 node key,
 *   and the server refuses unless reporter_fp == SHA3-512(that key).
 *
 *   kind 0x02 ANSWER —
 *     rq[64] ‖ code(1) ‖ ( code == 0:  3 × SAMPLE )
 *     rq     = SHA3-512(the 288 request body bytes) — which request this
 *              answers (the 0x71 `rq` rule, decision 2026-09-27-p2p-
 *              fix-2.md (2));
 *     code   = nodus_stprobe_code_t (0 OK; a refusal carries no sample);
 *     SAMPLE = hdr_len u32 ‖ header(h+1) proto [hdr_len] ‖
 *              part_len u32 ‖ the part bytes [part_len] ‖
 *              proof_len u32 ‖ the part's Merkle proof proto [proof_len]
 *              (bytes doc §6 "Answer per sample: header(h+1) proto bytes,
 *              the part bytes, its part proof"), samples i = 0, 1, 2 in
 *              order. The part index travels inside the proof (index).
 *   Bounds: hdr_len <= NODUS_STPROBE_HEADER_MAX, part_len <=
 *   CMT_BLOCK_PART_SIZE_BYTES (65536), proof_len <=
 *   NODUS_STPROBE_PROOF_MAX; no trailing byte. The whole answer is at most
 *   NODUS_STPROBE_MSG_MAX — the channel's receive capacity.
 *   ⚠ The kind byte, rq, code and the sample framing are NOT in the
 *   approved bytes doc (§6 fixes the request and names the three answer
 *   items, not their framing) — a wire choice of this package, recorded
 *   for operator approval like the 0x70 / 0x71 channel descriptors.
 *
 * ── THE SAMPLE (bytes doc §6 + Clarifications) ────────────────────────
 *   x_i = dna_v2_storage_sample_x(nonce, target_fp, i), i = 0, 1, 2;
 *   B   = |eligible segments of the target in (H, H+E]| × 17280;
 *   pos = BE u64 x_i[0..8) mod B → height h (nodus_storage_eligible_
 *         height, ascending height); part = BE u32 x_i[8..12) mod
 *         parts_total(h), parts_total read from header(h+1).last_block_id.
 *   B == 0 → no probe, bit 0.
 *
 * ── THE CHECKS (bytes doc §6), per sample, against the reporter's OWN
 *    v2_blocks (hash[h], hash[h+1]) ───────────────────────────────────
 *   cmt_header_hash(header(h+1)) == hash[h+1]; header.height == h+1;
 *   header.last_block_id.hash == hash[h]; part index = x_i mod
 *   last_block_id.part_set_header.total; proof.index == part index,
 *   proof.total == parts_total; the part passes the reference's
 *   Part.ValidateBasic (size rule, index == proof index); and
 *   cmt_proof_verify(part, proof, part_set_header.hash). Late (past the
 *   reporter's own deadline) or any check failing = NOT OK.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_STORAGE_PROBE_H
#define NODUS_WITNESS_STORAGE_PROBE_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cmt_store.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/cmt_part_set.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── wire constants ─────────────────────────────────────────────────── */

/** The request tag (bytes doc §6), right-padded with 0x00 to 16 bytes. */
#define NODUS_STPROBE_TAG            "NDS.STPROBE.v2"
#define NODUS_STPROBE_TAG_LEN        16u

#define NODUS_STPROBE_KIND_REQ       ((uint8_t)0x01)
#define NODUS_STPROBE_KIND_ANS       ((uint8_t)0x02)

/** The §6 request body: 16 + 32 + 8 + 64 + 64 + 64 + 32 + 8. */
#define NODUS_STPROBE_REQ_LEN        288u
/** A REQUEST message: kind ‖ body. */
#define NODUS_STPROBE_REQ_MSG_LEN    (1u + NODUS_STPROBE_REQ_LEN)
/** A refusal ANSWER message: kind ‖ rq ‖ code. */
#define NODUS_STPROBE_REFUSAL_LEN    (1u + 64u + 1u)

/** Widest header(h+1) proto accepted / produced. ⚠ NOT GROUNDED as a
 *  number: a version-3 header is ~0.9 KB (design rev 4 §0); 2048 leaves
 *  room for every field at its maximum (eight 64-byte hashes, the 64-byte
 *  last_block_id hash and part-set hash, a 32-byte chain id and proposer,
 *  varints) with slack. */
#define NODUS_STPROBE_HEADER_MAX     2048u
/** Widest part proof proto: total + index varints, a 64-byte leaf hash
 *  and at most CMT_MERKLE_MAX_AUNTS (100) 64-byte aunts, each with its
 *  tag and length — < 6.8 KB; 8192 is the bound. */
#define NODUS_STPROBE_PROOF_MAX      8192u
/** One encoded SAMPLE at its widest. */
#define NODUS_STPROBE_SAMPLE_MAX     (12u + NODUS_STPROBE_HEADER_MAX +       \
                                      CMT_BLOCK_PART_SIZE_BYTES +            \
                                      NODUS_STPROBE_PROOF_MAX)
/** The widest ANSWER message — the 0x72 channel's receive capacity. */
#define NODUS_STPROBE_MSG_MAX        (1u + 64u + 1u +                        \
                                      DNA_V2_STORAGE_SAMPLES *               \
                                      NODUS_STPROBE_SAMPLE_MAX)

/** The reporter's answer budget: deadline_ms = its wall clock + this, and
 *  its own monotonic wait for the answer. ⚠ NOT GROUNDED — design rev 4
 *  §9 leaves "probe deadline value" open for implementation review; a
 *  choice, for the operator. 10 s covers reading three parts and sending
 *  ~200 KB at the 4004 send rate (5 120 000 B/s) many times over and
 *  absorbs a few seconds of wall-clock skew between the two nodes. */
#define NODUS_STPROBE_BUDGET_MS      10000u
/** The serving side's per-requester gap (rate limit). ⚠ NOT GROUNDED —
 *  local policy: an honest reporter sends ONE request per target per
 *  epoch. */
#define NODUS_STPROBE_SERVE_GAP_MS   2000u
/** The most eligible segments a probe is computed over (B <= this ×
 *  17280 blocks): 4096 segments = 70 778 880 blocks, decades at today's
 *  pace. A larger count is refused, never truncated. */
#define NODUS_STPROBE_MAX_SEGS       4096u

/** The STORAGE_REPORT envelope's declarations — the B2a engine test that
 *  applies reports end to end (nodus/tests/test_storage_b2.c rep_env). */
#define NODUS_STPROBE_REPORT_UNITS         400000u
#define NODUS_STPROBE_REPORT_EFFECTS       8u
#define NODUS_STPROBE_REPORT_EFFECT_BYTES  16384u
/** The STORAGE_REPORT call: epoch_start(8) ‖ seat(4) ‖ S(H)[64] ‖
 *  bitmap_len(2) ‖ bitmap (rt_native.c RTN_STREP_*; bytes 2026-10-04 item
 *  3). */
#define NODUS_STPROBE_REPORT_CALL_MAX  (78u + DNA_V2_STORAGE_BITMAP_MAX)

_Static_assert(NODUS_STPROBE_REQ_LEN == 16u + 32u + 8u + 64u + 64u + 64u +
                                        32u + 8u,
               "bytes doc §6 request layout");
_Static_assert(NODUS_STPROBE_MSG_MAX < 5u * 1024u * 1024u,
               "the answer must fit the 5 MiB frame bound");
_Static_assert(DNA_V2_STORAGE_SAMPLES == 3u, "K3: 3 samples");

/* ── the answer / refusal codes (on the wire, one byte) ──────────────── */
typedef enum {
    NODUS_STPROBE_OK               = 0,
    NODUS_STPROBE_REF_MALFORMED    = 1,  /* bad tag / epoch_start         */
    NODUS_STPROBE_REF_NOT_ADDRESSED= 2,  /* target_fp != this node        */
    NODUS_STPROBE_REF_WRONG_CHAIN  = 3,  /* chain_id != this chain        */
    NODUS_STPROBE_REF_LATE         = 4,  /* this node's wall clock past
                                          * deadline_ms                   */
    NODUS_STPROBE_REF_NOT_REPORTER = 5,  /* reporter_fp != the sender's
                                          * authenticated key             */
    NODUS_STPROBE_REF_UNKNOWN_SET  = 6,  /* no storage_set(H) here        */
    NODUS_STPROBE_REF_SET_MISMATCH = 7,  /* S(H) differs from this node's */
    NODUS_STPROBE_REF_NOT_MEMBER   = 8,  /* this node not in storage_set(H)*/
    NODUS_STPROBE_REF_NO_BLOCKS    = 9,  /* B == 0: nothing eligible      */
    NODUS_STPROBE_REF_NOT_HELD     = 10, /* a sampled block is not in this
                                          * node's block store            */
    NODUS_STPROBE_REF_RATE         = 11, /* the requester asked too soon  */
    NODUS_STPROBE_REF_NOT_SEATED   = 12, /* the requester holds no seat in
                                          * snapshot(H)                   */
    NODUS_STPROBE_REF_FAULT        = 13  /* this node could not answer    */
} nodus_stprobe_code_t;

/* ── the request ────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  chain_id[DNA_CHAIN_ID_LEN];
    uint64_t epoch_start;
    uint8_t  set_hash[64];
    uint8_t  target_fp[64];
    uint8_t  reporter_fp[64];
    uint8_t  nonce[DNA_V2_STORAGE_NONCE_LEN];
    uint64_t deadline_ms;            /* the reporter's wall clock, ms     */
} nodus_stprobe_req_t;

/** Encode a REQUEST message (kind ‖ the 288-byte body) into `out`.
 *  @return 0 / -1 (NULL). */
int nodus_stprobe_req_encode(const nodus_stprobe_req_t *req,
                             uint8_t out[NODUS_STPROBE_REQ_MSG_LEN]);

/** Decode a REQUEST message: exactly NODUS_STPROBE_REQ_MSG_LEN bytes,
 *  kind 0x01, the padded tag. @return 0 / -1. */
int nodus_stprobe_req_decode(const uint8_t *msg, size_t len,
                             nodus_stprobe_req_t *out);

/** rq = SHA3-512(the 288 request body bytes). @return 0 / -1. */
int nodus_stprobe_req_id(const nodus_stprobe_req_t *req, uint8_t rq[64]);

/**
 * The serving side's checks that need no database (pure): chain_id ==
 * `own_chain`, target_fp == `own_fp`, reporter_fp == `sender_fp` (the
 * sender's authenticated node key, hashed), epoch_start a boundary of
 * epoch length `E` (>= E), and `now_wall_ms` <= deadline_ms.
 * @return NODUS_STPROBE_OK or the refusal code. */
nodus_stprobe_code_t nodus_stprobe_req_check(const nodus_stprobe_req_t *req,
                                             const uint8_t own_fp[64],
                                             const uint8_t own_chain[DNA_CHAIN_ID_LEN],
                                             const uint8_t sender_fp[64],
                                             uint64_t E,
                                             uint64_t now_wall_ms);

/* ── the samples ────────────────────────────────────────────────────── */

/** For i = 0..2: x_i (bytes doc §6) and the sampled height h_i over the
 *  eligible segments `ks[0..n)` (k strictly ascending; B = n × 17280).
 *  @return 0 / -1 (n == 0, n > NODUS_STPROBE_MAX_SEGS, a bad list). */
int nodus_stprobe_samples(const uint8_t nonce[DNA_V2_STORAGE_NONCE_LEN],
                          const uint8_t target_fp[64],
                          const uint64_t *ks, size_t n,
                          uint8_t x_out[DNA_V2_STORAGE_SAMPLES][64],
                          uint64_t h_out[DNA_V2_STORAGE_SAMPLES]);

/* ── the answer ─────────────────────────────────────────────────────── */

typedef struct {
    const uint8_t *header;  uint32_t header_len;
    const uint8_t *part;    uint32_t part_len;
    const uint8_t *proof;   uint32_t proof_len;
} nodus_stprobe_sample_view_t;

/** A decoded ANSWER; every pointer points INTO the decoded message. */
typedef struct {
    uint8_t                     rq[64];
    uint8_t                     code;
    nodus_stprobe_sample_view_t s[DNA_V2_STORAGE_SAMPLES];  /* code 0 only */
} nodus_stprobe_ans_view_t;

/** A refusal ANSWER message (kind ‖ rq ‖ code), code != OK.
 *  @return 0 / -1. */
int nodus_stprobe_ans_refusal(const uint8_t rq[64], uint8_t code,
                              uint8_t out[NODUS_STPROBE_REFUSAL_LEN]);

/** Decode an ANSWER message (bounds above; a refusal must be exactly
 *  NODUS_STPROBE_REFUSAL_LEN bytes; an OK answer exactly three samples
 *  and no trailing byte). @return 0 / -1. */
int nodus_stprobe_ans_decode(const uint8_t *msg, size_t len,
                             nodus_stprobe_ans_view_t *out);

/**
 * The serving side's answer, read from `store`: for each sample height
 * h_i the block meta of h_i + 1 (its header, marshalled as the proto
 * bytes), the part index from x_i and that header's last_block_id part
 * count, and the stored part P:h_i:index with its proof. Writes the OK
 * ANSWER message into `out` (cap >= NODUS_STPROBE_MSG_MAX is always
 * enough). Bounded: nothing is allocated beyond one block meta, one part
 * arena of CMT_BLOCK_PART_SIZE_BYTES and one part.
 * @return NODUS_STPROBE_OK (*len_out set), NODUS_STPROBE_REF_NOT_HELD (a
 *         meta or a part is missing, or a stored header's part count is
 *         0 / names a part the store does not hold), or
 *         NODUS_STPROBE_REF_FAULT (a store read fault, an encoding that
 *         does not fit, NULL).
 */
nodus_stprobe_code_t nodus_stprobe_answer_build(
        nodus_cmt_store_t *store, const uint8_t rq[64],
        const uint8_t x[DNA_V2_STORAGE_SAMPLES][64],
        const uint64_t h[DNA_V2_STORAGE_SAMPLES], uint64_t B,
        uint8_t *out, size_t cap, size_t *len_out);

/* ── the reporter's verification chain ─────────────────────────────── */

typedef enum {
    NODUS_STPROBE_V_OK = 0,
    NODUS_STPROBE_V_BOUNDS,           /* a length outside its bound      */
    NODUS_STPROBE_V_HEADER_DECODE,    /* header(h+1) does not decode     */
    NODUS_STPROBE_V_HEADER_HASH,      /* != hash[h+1] of own v2_blocks   */
    NODUS_STPROBE_V_HEADER_HEIGHT,    /* header.height != h + 1          */
    NODUS_STPROBE_V_BLOCK_ID,         /* last_block_id.hash != hash[h]   */
    NODUS_STPROBE_V_PART_TOTAL,       /* part count 0 / above the cap    */
    NODUS_STPROBE_V_PROOF_DECODE,     /* proof does not decode / basic   */
    NODUS_STPROBE_V_PART_INDEX,       /* proof.index != the sampled part */
    NODUS_STPROBE_V_PROOF_TOTAL,      /* proof.total != parts_total      */
    NODUS_STPROBE_V_PART_BASIC,       /* Part.ValidateBasic refused      */
    NODUS_STPROBE_V_PROOF,            /* the Merkle proof does not hold  */
    NODUS_STPROBE_V_FAULT             /* hash backend / allocation       */
} nodus_stprobe_verify_t;

/** Verify ONE sample (header "THE CHECKS"): `x` its x_i, `B` the
 *  target's eligible block count, `h` the sampled height, `hash_h` /
 *  `hash_h1` this node's own v2_blocks.block_id at h and h + 1. */
nodus_stprobe_verify_t nodus_stprobe_verify_sample(
        const uint8_t x[64], uint64_t B, uint64_t h,
        const uint8_t hash_h[64], const uint8_t hash_h1[64],
        const nodus_stprobe_sample_view_t *s);

/** The whole answer: OK iff not late (`now_mono_ms` <= `deadline_mono_ms`),
 *  rq matches `expect_rq`, code OK and all three samples verify.
 *  @return true = OK, false = NOT OK. */
bool nodus_stprobe_answer_ok(const nodus_stprobe_ans_view_t *a,
                             const uint8_t expect_rq[64],
                             const uint8_t x[DNA_V2_STORAGE_SAMPLES][64],
                             uint64_t B,
                             const uint64_t h[DNA_V2_STORAGE_SAMPLES],
                             const uint8_t hash_h[DNA_V2_STORAGE_SAMPLES][64],
                             const uint8_t hash_h1[DNA_V2_STORAGE_SAMPLES][64],
                             int64_t now_mono_ms, int64_t deadline_mono_ms);

/* ── the report ─────────────────────────────────────────────────────── */

/** The STORAGE_REPORT call (bytes 2026-10-04 item 3): epoch_start u64 ‖
 *  seat u32 ‖ S(H)[64] ‖ bitmap_len u16 ‖ bitmap, bitmap_len =
 *  ceil(count/8), bit i (LSB-first within byte i/8) = ok[i]; unused high
 *  bits 0. count <= DNA_V2_STORAGE_SET_MAX. @return 0 / -1. */
int nodus_stprobe_report_call(uint64_t epoch_start, uint32_t seat,
                              const uint8_t set_hash[64],
                              const bool *ok, uint32_t count,
                              uint8_t out[NODUS_STPROBE_REPORT_CALL_MAX],
                              size_t *len_out);

/**
 * The 1-leg SYSTEM STORAGE_REPORT envelope (rt_native.c rtn_strep_static:
 * one leg, auth kind 1 with one signer, fee 0), built against the SYSTEM
 * manifest `sys_version` / `sys_hash`, preflighted at `applying_height`
 * (the tip + 1 this node submits at) and signed by the seat key `pk` /
 * `sk` (this node's identity — the consensus key, nodus_witness.c
 * witness_cmt_raw_sign). `expiry` must be >= applying_height.
 * *out is heap (free()). @return 0 / -1.
 */
int nodus_stprobe_report_env(const uint8_t chain32[DNA_CHAIN_ID_LEN],
                             uint32_t sys_version,
                             const uint8_t sys_hash[64],
                             uint64_t applying_height, uint64_t expiry,
                             const uint8_t *call, size_t call_len,
                             const uint8_t *pk, const uint8_t *sk,
                             uint8_t **out, size_t *out_len);

/* ── epoch arithmetic (pure; E = the epoch length) ───────────────────── */

/** The probing epoch at committed tip `tip`: H = floor(tip / E) · E — the
 *  epoch (H, H+E] whose frozen set S(H) is committed (block H) and whose
 *  blocks are being produced. @return 0 (H >= E) / -1 (no epoch yet). */
int nodus_stprobe_epoch_for_tip(uint64_t tip, uint64_t E, uint64_t *H_out);

/** Pacing: target j of n is first tried at tip H + floor(j · ⌊3E/4⌋ / n)
 *  — spread over the first three quarters of the epoch, the last quarter
 *  left for retries of targets not connected at their slot. */
uint64_t nodus_stprobe_slot_height(uint64_t H, uint64_t E, size_t j,
                                   size_t n);

/** The report window for epoch H at committed tip `tip`: the applying
 *  height tip + 1 must be in (H+E, H+E+⌊E/2⌋] (rt_native.c
 *  rtn_strep_static); expiry = min(tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD,
 *  H+E+⌊E/2⌋). @return 0 in the window / 1 not yet open / -1 closed or
 *  overflow. */
int nodus_stprobe_report_window(uint64_t H, uint64_t E, uint64_t tip,
                                uint64_t *expiry_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_STORAGE_PROBE_H */
