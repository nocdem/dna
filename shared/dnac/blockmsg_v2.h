/**
 * @file shared/dnac/blockmsg_v2.h
 * @brief Ledger V2 O15B — the canonical BlockMessage v1 wire representation.
 *
 * ═══ WHAT THIS CARRIES, AND WHY IT IS A SEPARATE VERSION ════════════════
 * A finalized Ledger V2 block needs three things to travel: the canonical
 * 413-byte header v3, the QC that certifies it, and the body material the
 * header commits to. `block_v2.{h,c}` already defines the header and
 * `qc_v2.{h,c}` the certificate; neither says how to put them in one frame,
 * which is the hole this file fills.
 *
 * The ENVELOPE version is deliberately independent of the CONSENSUS header
 * version. `DNA_BLKW_VERSION` may advance for purely transport reasons
 * without redefining what a block IS — and, conversely, this codec does not
 * get to reinterpret `DNA_BH2_ENC_SIZE`, the BlockID preimage, or any tag.
 * O13's header v3 is untouched by this season.
 *
 * ═══ THE ONE RULE THIS CODEC ENFORCES ═══════════════════════════════════
 * NOTHING RECEIVED IS AUTHORITY. This decoder produces bounded, structurally
 * valid BYTES and nothing else. It does not compute a BlockID, does not
 * verify a root, does not check a quorum, and never touches committed state.
 * Every authoritative commitment is re-derived downstream by the O14/O15A
 * engine and COMPARED against the header the sender claimed — see
 * `nodus_witness_v2_finalize.h`. If this file ever grows a function that
 * computes a consensus value, that is a second engine and a defect.
 *
 * ═══ CANONICAL LAYOUT (all integers BIG-ENDIAN, no padding) ═════════════
 *
 *   off  size  field
 *   ---  ----  --------------------------------------------------------
 *     0     1  msg_version        DNA_BLKW_VERSION (1). 0 is INVALID.
 *     1     1  body_version       DNA_BLKW_BODY_VERSION (1). 0 is INVALID.
 *     2     4  header_len         MUST be exactly DNA_BH2_ENC_SIZE
 *     6   413  header             canonical BlockHeader v3 bytes
 *   419     4  qc_len             1 .. DNA_QC_V2_MAX_ENC_LEN
 *   423   qc_len  qc              canonical QC V2 bytes
 *     .     4  env_count          0 .. DNA_BLKW_MAX_ENVS
 *     .        per envelope, in canonical batch order:
 *              4  env_len         1 .. DNA_ENV_MAX_TOTAL_LEN
 *              n  env bytes
 *     .     4  claim_count        MUST be 0 — see BODY COMPLETENESS below
 *     .     4  pool_batch_count   MUST be 0 — see BODY COMPLETENESS below
 *     .    32  proposer_id
 *     .     8  timestamp
 *
 * `header_len` is present even though it is fixed. It costs four bytes and
 * it makes the frame self-describing at the point of failure: a peer running
 * a different header size is rejected with a length mismatch here rather
 * than by silently misparsing every field after the header.
 *
 * ═══ WHY IT IS ONE ENCODING PER BLOCK ═══════════════════════════════════
 * Every field is fixed-width or explicitly length-prefixed, there is no
 * optional field, no default that could be omitted, no ordering freedom
 * (envelopes are in canonical batch order, which is also their execution
 * order), and TRAILING BYTES ARE A REJECT. So a block has exactly one
 * encoding, and `dnac_blkmsg_v2_encode(decode(x)) == x` for every x this
 * decoder accepts. `dnac_blkmsg_v2_reencode_equals` checks that property on
 * the receive path so a non-canonical re-encoding of the same block can
 * never be treated as a distinct message.
 *
 * ═══ BODY COMPLETENESS — AN HONEST LABEL ════════════════════════════════
 * `claim_count` and `pool_batch_count` exist in the layout and MUST BE ZERO.
 * They are not padding and not a future-proofing gesture: a `nodus_v2_block_t`
 * genuinely can carry claims (S6) and pool batches (S7), and a wire format
 * that silently dropped them would let a sender commit state this frame
 * cannot express.
 *
 * They are zero because reconstructing those two inputs from committed state
 * is unsolved — `nodus_witness_v2_apply.h` says so directly: claims and pool
 * batches are bound to the header only TRANSITIVELY, through
 * `claims_root` / `pools_root`, never through `tx_root`, so the header does
 * not commit their input bytes. Carrying them would require a canonical
 * claim/pool wire and its own binding argument, which is not this season's
 * work. Declaring them and rejecting non-zero is the fail-closed choice: a
 * block with claims cannot be MISREAD as a block without them.
 *
 * Consequence, stated plainly: BlockMessage v1 can carry only blocks whose
 * claim and pool sets are empty. That is every block the inactive lane can
 * currently produce, and it is a real limit on what a future activated lane
 * may transport.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_BLOCKMSG_V2_H
#define DNAC_BLOCKMSG_V2_H

#include <stddef.h>
#include <stdint.h>

/* Sibling headers, included by plain name — the convention in this
 * directory (see qc_v2.c:13, block_v2.h:97). Consumers outside
 * shared/dnac reach this file as "dnac/blockmsg_v2.h" via -I. */
#include "block_v2.h"
#include "qc_v2.h"
#include "env_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Envelope version. 0 is INVALID; unknown values fail closed. */
#define DNA_BLKW_VERSION        1u
/** Body version. 0 is INVALID; unknown values fail closed. */
#define DNA_BLKW_BODY_VERSION   1u

/**
 * Maximum envelopes in one message.
 *
 * DERIVED, not chosen: it is the apply engine's own batch bound
 * (`NODUS_V2_ENV_BATCH_MAX` == 16, nodus_witness_v2_env.h:121). A message
 * that could carry more envelopes than the engine will ever accept would
 * only be a way to make a receiver allocate for work it must then refuse.
 * Kept as its own name so a reviewer sees the coupling, and pinned equal by
 * a _Static_assert in the ingress layer (which is where both are visible;
 * this header is shared and must not depend on nodus-internal headers).
 */
#define DNA_BLKW_MAX_ENVS       16u

/** Fixed prefix: msg_version(1) + body_version(1) + header_len(4). */
#define DNA_BLKW_PREFIX_LEN     6u

/**
 * Absolute upper bound on an encoded BlockMessage v1, in bytes.
 *
 * Computed from the component maxima rather than picked: prefix + header +
 * qc_len field + maximal QC + env_count field + MAX_ENVS × (len field +
 * maximal envelope) + claim_count + pool_count + proposer + timestamp.
 *
 * At the release ceilings this is large (16 × 1 MiB dominates), which is
 * exactly why the ingress layer applies its OWN, much smaller, frame budget
 * BEFORE allocating anything — see `nodus_witness_v2_ingress.h`. This
 * constant is the codec's structural ceiling, NOT a resource policy.
 */
#define DNA_BLKW_MAX_ENC_LEN                                        \
    ((size_t)DNA_BLKW_PREFIX_LEN + (size_t)DNA_BH2_ENC_SIZE +       \
     4u + (size_t)DNA_QC_V2_MAX_ENC_LEN +                           \
     4u + (size_t)DNA_BLKW_MAX_ENVS * (4u + (size_t)DNA_ENV_MAX_TOTAL_LEN) + \
     4u + 4u + 32u + 8u)

/** One envelope's bytes, borrowed from the decoded buffer. */
typedef struct {
    const uint8_t *bytes;   /**< points INTO the caller's source buffer */
    uint32_t       len;
} dnac_blkmsg_env_t;

/**
 * A decoded BlockMessage v1.
 *
 * ZERO-COPY: `header`, `qc` and every `env[i].bytes` point INTO the source
 * buffer passed to the decoder. They are valid only while that buffer is
 * alive and unmodified. Nothing here is owned, so there is no free function
 * and no ownership to get wrong.
 */
typedef struct {
    uint8_t  msg_version;
    uint8_t  body_version;

    const uint8_t *header;              /**< exactly DNA_BH2_ENC_SIZE bytes */
    const uint8_t *qc;
    uint32_t       qc_len;

    dnac_blkmsg_env_t env[DNA_BLKW_MAX_ENVS];
    uint32_t          env_count;

    uint8_t  proposer_id[32];
    uint64_t timestamp;

    /** Bytes consumed. Equal to the input length — trailing bytes reject. */
    size_t   consumed;
} dnac_blkmsg_v2_t;

/** Decode status. Values are STABLE; append only, never renumber. */
typedef enum {
    DNAC_BLKW_OK               = 0,
    DNAC_BLKW_ERR_ARG          = 1,  /**< NULL argument                     */
    DNAC_BLKW_ERR_TRUNCATED    = 2,  /**< ran out of input mid-field        */
    DNAC_BLKW_ERR_VERSION      = 3,  /**< msg_version unknown or 0          */
    DNAC_BLKW_ERR_BODY_VERSION = 4,  /**< body_version unknown or 0         */
    DNAC_BLKW_ERR_HEADER_LEN   = 5,  /**< header_len != DNA_BH2_ENC_SIZE    */
    DNAC_BLKW_ERR_QC_LEN       = 6,  /**< qc_len 0 or over the QC maximum   */
    DNAC_BLKW_ERR_ENV_COUNT    = 7,  /**< env_count over DNA_BLKW_MAX_ENVS  */
    DNAC_BLKW_ERR_ENV_LEN      = 8,  /**< an env_len is 0 or over the max   */
    DNAC_BLKW_ERR_UNSUPPORTED  = 9,  /**< claim_count/pool_count non-zero   */
    DNAC_BLKW_ERR_TRAILING     = 10, /**< bytes remain after the last field */
    DNAC_BLKW_ERR_OVERFLOW     = 11  /**< length arithmetic would overflow  */
} dnac_blkmsg_status_t;

/** Stable human-readable name for a status (never NULL). */
const char *dnac_blkmsg_v2_status_name(dnac_blkmsg_status_t s);

/**
 * Decode a BlockMessage v1.
 *
 * FAILS BEFORE ALLOCATING OR MUTATING ANYTHING — it allocates nothing at
 * all. `*out` is fully zeroed on entry, so a rejected message never leaves
 * a partially populated structure a careless caller could read.
 *
 * Every length is validated against its maximum BEFORE it is used to
 * advance, and every advance is checked for overflow against the remaining
 * input, so no arithmetic here can wrap or run past the buffer.
 *
 * @param src source bytes.
 * @param len source length.
 * @param out [out] decoded view; zeroed on any failure.
 * @return DNAC_BLKW_OK, or the specific failure class.
 */
dnac_blkmsg_status_t dnac_blkmsg_v2_decode(const uint8_t *src, size_t len,
                                           dnac_blkmsg_v2_t *out);

/**
 * Exact encoded length of the message `m` describes.
 *
 * @return the length, or 0 if `m` is NULL or describes something that
 *         cannot be encoded (counts out of range, a zero-length envelope).
 */
size_t dnac_blkmsg_v2_encoded_len(const dnac_blkmsg_v2_t *m);

/**
 * Encode a BlockMessage v1.
 *
 * The exact inverse of the decoder for every message the decoder accepts.
 *
 * @param m    the message.
 * @param dst  destination buffer.
 * @param cap  destination capacity.
 * @param out_len [out] bytes written.
 * @return DNAC_BLKW_OK, or a failure class (ERR_ARG when `cap` is too small).
 */
dnac_blkmsg_status_t dnac_blkmsg_v2_encode(const dnac_blkmsg_v2_t *m,
                                           uint8_t *dst, size_t cap,
                                           size_t *out_len);

/**
 * Canonical-form check: does `src` re-encode to itself, byte for byte?
 *
 * The receive path's guarantee that a message has exactly one valid
 * encoding. Decoding alone does not give that — a decoder can be tolerant
 * in ways an encoder never is — so the property is CHECKED rather than
 * argued. Any difference means the sender used a form this codec would not
 * produce, and it is rejected.
 *
 * Allocates a scratch buffer of the re-encoded length; on allocation failure
 * it returns 0 (NOT canonical), because "we could not check" must never be
 * reported as "we checked and it was fine".
 *
 * @return 1 canonical, 0 otherwise (including undecodable input).
 */
int dnac_blkmsg_v2_reencode_equals(const uint8_t *src, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BLOCKMSG_V2_H */
