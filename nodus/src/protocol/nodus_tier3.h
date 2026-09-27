/**
 * Nodus — Tier 3: the witness message BODIES that survived the move of
 * port 4004 onto the ported cometbft p2p layer (fleet P2P-PORT phase F5).
 *
 * WHAT CHANGED (docs/plans/2026-09-26-p2p-port-design.md §3, OPERATOR-
 * APPROVED channel choice in docs/plans/decisions/2026-09-26-witness-port-
 * session.md "P2P portu bayt/biçim onayları" item 3):
 *   · The tier-3 ENVELOPE — {t, y, q, wh, a, wsig}, a per-message
 *     ML-DSA-87 signature under purpose 0x03 over {q, wh, a} — is DELETED.
 *     A 4004 message is now authenticated by the secret connection it
 *     arrives on (cmt_p2p_secret.h), and its sender IS that connection's
 *     authenticated identity.
 *   · The consensus verbs 35-39 are gone: the reactors' bytes ride the
 *     MConnection channels 0x20-0x23 / 0x30 directly.
 *   · The roster / IDENT verbs 9-11 are gone (the peer mesh is the
 *     switch; addresses travel as signed ADDR records over PEX).
 *   · The genesis bundle (verbs 24/25) and the governance approval
 *     (verbs 40/41) survive as MESSAGES on the nodus channels 0x70 and
 *     0x71 (nodus_witness_p2p.h). Each message is EXACTLY the verb's
 *     former `a` map — the CBOR bytes below are byte-identical to the
 *     `a` value the envelope used to carry. Which of a channel's two
 *     messages arrived is read from its key set: a 0x70 map carrying `t`
 *     or `d` is a response, any other a request; a 0x71 map carrying `e`
 *     is a request, any other a response (proposed register row
 *     R-P2P-48 — no wire byte is added).
 *
 * VERB NUMBERS ARE RETIRED, NEVER REUSED. 1-23 and 26-39 name nothing any
 * more; 24, 25, 40 and 41 survive only as the four message kinds below.
 * No future message may take any number from 1 to 41.
 *
 * Decoded messages use zero-copy pointers for large fields (`chunk`, `e`):
 * valid only while the input buffer is.
 *
 * @file nodus_tier3.h
 */

#ifndef NODUS_TIER3_H
#define NODUS_TIER3_H

#include "nodus/nodus_types.h"
/* O15H D8 — the V2 envelope family marker + its versioned capacity
 * bound, for nodus_t3_tx_size_limit below. env_wire.h is dependency-free
 * by its own rule (it may include ledger_ids.h and nothing from nodus),
 * so this direction of the include is the safe one. */
#include "dnac/env_wire.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* O15H D8 — the family-aware per-transaction size bound, in ONE place.
 * A Ledger V2 envelope is bounded by its OWN versioned capacity constant
 * (DNA_ENV_MAX_TOTAL_LEN, shared/dnac/env_wire.h); everything else keeps
 * the legacy semantic limit. Selection is by the leading 16-byte
 * wire-family marker. Its caller is the client tx-submit gate in
 * nodus_witness_handlers.c. */
static inline uint32_t nodus_t3_tx_size_limit(const uint8_t *tx, size_t len)
{
    return dna_env_wire_is_envelope(tx, len) ? (uint32_t)DNA_ENV_MAX_TOTAL_LEN
                                             : (uint32_t)NODUS_T3_MAX_TX_SIZE;
}

/* ── The four message kinds (the surviving verb numbers) ─────────── */

typedef enum {
    NODUS_T3_NONE           = 0,
    NODUS_T3_V2_GBUNDLE_REQ = 24,  /* channel 0x70 {c, p, o}             */
    NODUS_T3_V2_GBUNDLE_RSP = 25,  /* channel 0x70 {c, p, t, o, d}       */
    NODUS_T3_CC_APPR_REQ    = 40,  /* channel 0x71 {e}                   */
    NODUS_T3_CC_APPR_RSP    = 41,  /* channel 0x71 {ok, i, s, sh, ep} or
                                                  {ok, r}                */
} nodus_t3_msg_type_t;

/** O15E Faz D — genesis bundle REQUEST. Offset-chunked pull.
 *
 * D-24 rev 4 (1): `pin` is 32 bytes — the joiner's ONLY input is the
 * 32-byte chain id (a version-3 chain's identity is the hash of its stored
 * genesis DOCUMENT). `chain` and `pin` name the same identity from two
 * angles — which chain this request is about, and the requester's own
 * expectation of it.
 * Keys: "c" (32B), "p" (32B, the chain id), "o" (uint offset). */
typedef struct {
    uint8_t     chain[32];
    uint8_t     pin[32];
    uint64_t    offset;
} nodus_t3_w_v2_gbundle_q_t;

/** O15E Faz D — genesis bundle RESPONSE. One chunk of the canonical bundle
 * at `offset`; `total` is the full bundle length. `chunk` is zero-copy.
 * Keys: "c" (32B), "p" (32B), "t" (uint total), "o" (uint offset),
 * "d" (bstr chunk). */
#define NODUS_T3_V2_GBUNDLE_CHUNK_MAX 49152u   /* 48 KB per message */
typedef struct {
    uint8_t         chain[32];
    uint8_t         pin[32];
    uint64_t        total;
    uint64_t        offset;
    const uint8_t  *chunk;          /* ptr into decode buf              */
    uint32_t        chunk_len;
} nodus_t3_w_v2_gbundle_r_t;

/** SYSTEM-governance approval REQUEST (D-16 rev 7, W4-CC): a PRE-AUTH
 *  single-leg SYSTEM-governance envelope (today exactly CHAIN_CONFIG).
 *  Key { e: bstr }, e <= DNA_ENV_MAX_TOTAL_LEN; zero-copy on decode. This
 *  layer decodes NOTHING inside `e` — the responder's engine seam does. */
typedef struct {
    const uint8_t *e;       /* ptr into decode buf (rx) / caller buf (tx) */
    size_t         e_len;
} nodus_t3_cc_appr_req_t;

/** SYSTEM-governance approval RESPONSE: one committee seat's answer.
 *  ok=true: seat/sig/set_hash/epoch are the signed "DNA.CCAPPR.v1"
 *  approval (nodus_rt_cc_approval_digest); reason is empty.
 *  ok=false: only reason is meaningful (UTF-8, NUL-terminated). */
typedef struct {
    bool     ok;
    uint16_t seat;
    uint8_t  sig[NODUS_SIG_BYTES];
    uint8_t  set_hash[64];
    uint64_t epoch;
    char     reason[129];   /* <= 128 chars + NUL, D-16 rev 7 "r: tstr <= 128" */
} nodus_t3_cc_appr_rsp_t;

/** The request's `e` ceiling: the engine's own envelope bound, so this
 *  layer can never refuse an envelope the engine would accept. The
 *  response's ceiling is its variable fields' worst case (a 4627-byte
 *  signature, a 64-byte set hash, headroom for the refusal string). */
#define NODUS_T3_CC_APPR_E_MAX    DNA_ENV_MAX_TOTAL_LEN
#define NODUS_T3_CC_APPR_RSP_MAX  (4627u + 64u + 256u)

/** The largest message each channel carries — its descriptor's
 *  RecvMessageCapacity (nodus_witness_p2p.c). The slack covers the map
 *  header, the key strings and the byte-string headers of the fixed
 *  fields (≤ 5 keys × (1 + 2) + 2 × (2 + 32) + 3 × 9 + 5 < 256). */
#define NODUS_T3_GBUNDLE_MSG_MAX  (NODUS_T3_V2_GBUNDLE_CHUNK_MAX + 256u)
#define NODUS_T3_CC_APPR_MSG_MAX  (NODUS_T3_CC_APPR_E_MAX + 256u)

/** A decoded 0x70 / 0x71 message. */
typedef struct {
    nodus_t3_msg_type_t type;
    union {
        nodus_t3_w_v2_gbundle_q_t w_v2_gbundle_q;
        nodus_t3_w_v2_gbundle_r_t w_v2_gbundle_r;
        nodus_t3_cc_appr_req_t    cc_appr_req;
        nodus_t3_cc_appr_rsp_t    cc_appr_rsp;
    };
} nodus_t3_msg_t;

/* ── Encode (each writes the message's CBOR map into `buf`) ──────── */

/** @return 0 on success, -1 on a NULL argument, an out-of-class field or
 *  a too-small `cap`. */
int nodus_t3_gbundle_q_encode(const nodus_t3_w_v2_gbundle_q_t *m,
                              uint8_t *buf, size_t cap, size_t *out_len);
int nodus_t3_gbundle_r_encode(const nodus_t3_w_v2_gbundle_r_t *m,
                              uint8_t *buf, size_t cap, size_t *out_len);
int nodus_t3_cc_appr_req_encode(const nodus_t3_cc_appr_req_t *m,
                                uint8_t *buf, size_t cap, size_t *out_len);
int nodus_t3_cc_appr_rsp_encode(const nodus_t3_cc_appr_rsp_t *m,
                                uint8_t *buf, size_t cap, size_t *out_len);

/* ── Decode ──────────────────────────────────────────────────────── */

/**
 * A channel-0x70 message: the kind from the key set (file header), then
 * the verb's former decoder. The whole buffer must be exactly ONE CBOR
 * map; a negative integer anywhere in it is refused (D-22 rev 3, as the
 * envelope's `a` was).
 * @return 0 (`out->type` 24 or 25); -1 malformed.
 */
int nodus_t3_gbundle_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *out);

/** A channel-0x71 message — the same rules (`out->type` 40 or 41). */
int nodus_t3_cc_appr_decode(const uint8_t *buf, size_t len, nodus_t3_msg_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_TIER3_H */
