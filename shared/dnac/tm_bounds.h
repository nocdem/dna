/**
 * @file tm_bounds.h
 * @brief Tendermint T3 — derived size bounds (T2 wire design §4.8; D-19 rev 3,
 *        Atlas atlas-dec-d106407a31d7d16d49d51990b75c36c6). No number that can be
 *        derived is retyped: every value below is a formula over constants the
 *        tree already owns. The _Static_asserts pin the formulas to the values
 *        the T2 design published, so a drift in either side fails the build.
 *        Wave 2 asserts DNA_TM_HDR4_LEN == DNA_BH2_ENC_SIZE once header v4 lands.
 */
#ifndef DNA_TM_BOUNDS_H
#define DNA_TM_BOUNDS_H

#include <stddef.h>

#include "ledger_ids.h"                 /* DNA_MAX_ACTIVE_VALIDATORS (128), DNA_CHAIN_ID_LEN (32) */
#include "manifest_wire.h"              /* DNA_CLAIM_MAX_WIRE (11 628)                            */
#include "env_wire.h"                   /* DNA_ENV_MAX_TOTAL_LEN (1 MiB)                          */
#include "blockmsg_v2.h"                /* DNA_BLKW_MAX_ENVS (16)                                 */
#include "crypto/sign/qgp_dilithium.h"  /* QGP_DSA87_SIGNATURE_BYTES (4627)                       */

/* ── nodus.commit.v1 (T2 §4.3, D-17 rev 3) ─────────────────────────────── */
#define DNA_TM_COMMIT_HDR_LEN            94u   /* tag 16 + height 8 + round 4 + block_id 64 + n 2 */
#define DNA_TM_COMMIT_ENTRY_ABSENT_LEN   9u    /* flag 1 + timestamp 8                            */
#define DNA_TM_COMMIT_ENTRY_SIGNED_LEN   (DNA_TM_COMMIT_ENTRY_ABSENT_LEN + QGP_DSA87_SIGNATURE_BYTES)
#define DNA_TM_COMMIT_MAX_LEN \
    (DNA_TM_COMMIT_HDR_LEN + (size_t)DNA_MAX_ACTIVE_VALIDATORS * DNA_TM_COMMIT_ENTRY_SIGNED_LEN)

/* ── header v4 (T2 §4.4, D-19 rev 3) — wave 2 replaces the literal ───────── */
#define DNA_TM_HDR4_LEN                  477u

/* ── body v2 (T2 §4.5; the numbers are BYTE WIDTHS, not values — body_version
 *    is 2 on the wire): msg_version(1) ‖ body_version(1) ‖ header_len(4) ‖ header
 *    ‖ last_commit_len(4) ‖ last_commit ‖ env_count(4) ‖ 16 × env_len(4) ‖ env bytes
 *    ‖ claim_count(4) ‖ pool_batch_count(4) ‖ proposer_id(32) ‖ timestamp(8).
 *    Env byte budget = the runtime's max_block_env_bytes
 *    (nodus_witness_runtime.c:140 = 2 × DNA_ENV_MAX_TOTAL_LEN). ────────────── */
#define DNA_TM_BODY_ENV_BYTES_MAX        (2u * DNA_ENV_MAX_TOTAL_LEN)
#define DNA_TM_BODY_V2_MAX_LEN \
    (6u + DNA_TM_HDR4_LEN + 4u + DNA_TM_COMMIT_MAX_LEN + 4u \
     + (size_t)DNA_BLKW_MAX_ENVS * 4u + DNA_TM_BODY_ENV_BYTES_MAX \
     + 4u + 4u + 32u + 8u)

/* ── value = 0x02 container (T2 §4.5): 0x02 ‖ u32 body_len ‖ body ‖ u32 n_claims
 *    ‖ n × (u32 claim_len ‖ claim). Claim ceiling 10 == NODUS_W_MAX_BLOCK_TXS
 *    (nodus_types.h); nodus_tier3.h asserts that equality. ───────────────── */
#define DNA_TM_MAX_CLAIMS_PER_VALUE      10u
#define DNA_TM_VALUE_MAX_LEN \
    (1u + 4u + DNA_TM_BODY_V2_MAX_LEN + 4u \
     + DNA_TM_MAX_CLAIMS_PER_VALUE * (4u + (size_t)DNA_CLAIM_MAX_WIRE))

_Static_assert(DNA_TM_COMMIT_ENTRY_SIGNED_LEN == 4636u,  "commit entry length drifted from T2 §4.3");
_Static_assert(DNA_TM_COMMIT_MAX_LEN          == 593502u, "CERT_MAX drifted from T2 §4.8");
_Static_assert(DNA_TM_BODY_V2_MAX_LEN         == 2691257u, "BODY_MAX drifted from T2 §4.8");
_Static_assert(DNA_TM_VALUE_MAX_LEN           == 2807586u, "VALUE_MAX drifted from T2 §4.8");

#endif /* DNA_TM_BOUNDS_H */
