/**
 * @file nodus/src/witness/nodus_witness_v2_ingress.c
 * @brief Ledger V2 O15B — external ingress adapter and network result algebra.
 *
 * Contract, the result-to-action table, and the reasons this is dormant are
 * in nodus_witness_v2_ingress.h. Read that first.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_ingress.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_finalize.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"

#include "dnac/blockmsg_v2.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_V2ING"

/* The wire's envelope cap must not exceed what the engine will execute; a
 * frame that could carry more envelopes than the engine accepts is only a
 * way to make a receiver allocate for work it must then refuse. Pinned here
 * because this is the one translation unit where both names are visible. */
_Static_assert((unsigned)DNA_BLKW_MAX_ENVS <= (unsigned)NODUS_V2_ENV_BATCH_MAX,
               "BlockMessage envelope cap exceeds the apply engine batch cap");

const char *nodus_v2_peer_action_name(nodus_v2_peer_action_t a) {
    switch (a) {
    case NODUS_V2_PEER_NONE:      return "NONE";
    case NODUS_V2_PEER_INVALID:   return "INVALID";
    case NODUS_V2_PEER_MALFORMED: return "MALFORMED";
    }
    return "UNKNOWN";
}

/* ── The bounded future-block queue ──────────────────────────────────────
 *
 * A singly linked list, kept in arrival order. It is small by construction
 * (NODUS_V2_ING_QUEUE_MAX_BLOCKS == 32), so a list beats a heap here: every
 * operation is a walk over at most 32 nodes, and the code that a reviewer
 * has to trust stays short.
 *
 * Entries own their bytes. That is the point — a queued frame must survive
 * the receive buffer it arrived in, and borrowing would make the queue's
 * lifetime depend on the transport's.
 */
typedef struct v2_q_entry {
    struct v2_q_entry *next;
    uint8_t  peer_id[32];
    uint64_t height;          /* the block's claimed height (for ordering) */
    uint64_t queued_at;       /* local head when queued — the age origin   */
    uint8_t *bytes;
    size_t   len;
} v2_q_entry_t;

/* Process-wide rather than per-handle, and that is a deliberate, labelled
 * limitation: `nodus_witness_t` is a large shipped struct and O15B does not
 * widen it for a structure that is never populated in production. The queue
 * is only ever non-empty on an ARMED node, and a production node can never
 * arm, so in production this is permanently three zeroed globals.
 *
 * If a future season arms ingress, this MUST move into the handle before
 * two witnesses can share a process. That obligation is named here rather
 * than discovered later. */
static v2_q_entry_t *g_q_head;
static uint32_t      g_q_count;
static uint64_t      g_q_bytes;

static void q_free_entry(v2_q_entry_t *e) {
    if (!e) return;
    free(e->bytes);
    free(e);
}

void nodus_witness_v2_ingress_queue_clear(nodus_witness_t *w) {
    (void)w;
    v2_q_entry_t *e = g_q_head;
    while (e) {
        v2_q_entry_t *n = e->next;
        q_free_entry(e);
        e = n;
    }
    g_q_head  = NULL;
    g_q_count = 0;
    g_q_bytes = 0;
}

void nodus_witness_v2_ingress_queue_stats(nodus_witness_t *w,
                                          uint32_t *n_blocks,
                                          uint64_t *n_bytes) {
    (void)w;
    if (n_blocks) *n_blocks = g_q_count;
    if (n_bytes)  *n_bytes  = g_q_bytes;
}

uint32_t nodus_witness_v2_ingress_queue_prune(nodus_witness_t *w,
                                              uint64_t local_height) {
    (void)w;
    uint32_t evicted = 0;
    v2_q_entry_t **pp = &g_q_head;
    while (*pp) {
        v2_q_entry_t *e = *pp;
        int drop = 0;

        /* Overtaken: the chain reached or passed it, so it is no longer a
         * FUTURE block. Whether it was applied or superseded, holding it
         * cannot help. */
        if (e->height <= local_height) drop = 1;

        /* Too far ahead to be worth holding. Re-checked on every prune,
         * not only at insert, because the distance is measured from a head
         * that moves. */
        if (!drop && e->height > local_height &&
            (e->height - local_height) > NODUS_V2_ING_QUEUE_MAX_DISTANCE)
            drop = 1;

        /* Aged out — measured in LOCAL PROGRESS, never in seconds. If the
         * head has advanced this far and the gap in front of this entry
         * still has not closed, the entry is not the one that will close
         * it. A wall-clock lifetime would put a non-deterministic input
         * next to consensus state; block progress is monotone and both
         * ends agree on it. */
        if (!drop && local_height >= e->queued_at &&
            (local_height - e->queued_at) > NODUS_V2_ING_QUEUE_MAX_AGE_BLOCKS)
            drop = 1;

        if (drop) {
            *pp = e->next;
            g_q_count--;
            g_q_bytes -= (uint64_t)e->len;
            q_free_entry(e);
            evicted++;
            continue;
        }
        pp = &e->next;
    }
    return evicted;
}

static uint32_t q_count_for_peer(const uint8_t *peer_id) {
    uint32_t n = 0;
    for (v2_q_entry_t *e = g_q_head; e; e = e->next)
        if (memcmp(e->peer_id, peer_id, 32) == 0) n++;
    return n;
}

/* Park a frame. Returns 1 queued, 0 refused.
 *
 * Refusal is NOT an error and never a peer judgement: a full queue is this
 * node's resource limit, not the sender's misbehaviour. The block is simply
 * dropped, and catch-up will fetch it again in order. */
static int q_push(const uint8_t *peer_id, uint64_t height,
                  uint64_t local_height, const uint8_t *bytes, size_t len) {
    if (g_q_count >= NODUS_V2_ING_QUEUE_MAX_BLOCKS)                 return 0;
    if (g_q_bytes + (uint64_t)len > NODUS_V2_ING_QUEUE_MAX_BYTES)   return 0;
    if (q_count_for_peer(peer_id) >= NODUS_V2_ING_QUEUE_MAX_PER_PEER) return 0;
    if (height <= local_height)                                     return 0;
    if ((height - local_height) > NODUS_V2_ING_QUEUE_MAX_DISTANCE)  return 0;

    /* Exact duplicate of something already parked: keep the first copy.
     * Re-sending is normal during catch-up and must not multiply memory. */
    for (v2_q_entry_t *e = g_q_head; e; e = e->next) {
        if (e->height == height && e->len == len &&
            memcmp(e->bytes, bytes, len) == 0)
            return 1;                     /* already held — idempotent */
    }

    v2_q_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return 0;
    e->bytes = malloc(len);
    if (!e->bytes) { free(e); return 0; }
    memcpy(e->bytes, bytes, len);
    e->len       = len;
    e->height    = height;
    e->queued_at = local_height;
    if (peer_id) memcpy(e->peer_id, peer_id, 32);

    e->next  = g_q_head;
    g_q_head = e;
    g_q_count++;
    g_q_bytes += (uint64_t)len;
    return 1;
}

/* ── Two LOCAL BOOKKEEPING reads ──────────────────────────────────────
 *
 * Neither decides anything about a block. They pick which entries the
 * queue keeps, which is this node's memory policy. Both are named and kept
 * together so a reviewer can see that they are the ONLY places this file
 * looks at a header field or a database row, and that neither result
 * reaches the engine.
 */

/* This node's committed V2 head, or 0 when there is none / on a fault.
 * A fault reading as 0 is safe HERE and only here: it makes the queue more
 * conservative (every entry looks further ahead, so more are refused or
 * evicted). It is never used to judge a block. */
static uint64_t ing_committed_height(nodus_witness_t *w) {
    if (!w || !w->db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
            -1, &st, NULL) != SQLITE_OK)
        return 0;
    uint64_t h = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v > 0) h = (uint64_t)v;
    }
    sqlite3_finalize(st);
    return h;
}

/* The claimed height of an already-decoded header, for queue ordering.
 *
 * Uses the ONE canonical header decoder (`dna_bh2_decode`) rather than
 * reading the offset by hand — a second reader of a consensus object is
 * exactly what this file must not contain, even for bookkeeping. The value
 * is CLAIMED, never trusted: it only selects which frame this node is
 * willing to hold in memory. */
static uint64_t ing_header_height(const uint8_t *header) {
    dna_block_header_v2_t h;
    if (!header) return 0;
    if (dna_bh2_decode(header, (size_t)DNA_BH2_ENC_SIZE, &h) != 0) return 0;
    return h.block_height;
}

/* ── The result → network action translation ──────────────────────────
 *
 * The ONLY place a peer policy is decided. `nodus_v2_result_blames_peer()`
 * is the predicate, so "which results may be held against a peer" has one
 * definition shared with the engine rather than a copy that can drift. */
static void classify(nodus_v2_ingress_outcome_t *out, int rc) {
    out->result = (nodus_v2_result_t)rc;
    out->ack    = nodus_v2_result_is_accepted(rc) ? 1 : 0;
    out->peer   = nodus_v2_result_blames_peer(rc) ? NODUS_V2_PEER_INVALID
                                                  : NODUS_V2_PEER_NONE;
    out->want_catchup = (rc == NODUS_V2_NOT_YET_LINKABLE) ? 1 : 0;
}

int nodus_witness_v2_ingress_block(nodus_witness_t *w,
                                   const uint8_t *peer_id,
                                   const uint8_t *frame, size_t frame_len,
                                   nodus_v2_ingress_outcome_t *out) {
    nodus_v2_ingress_outcome_t local;
    if (!out) out = &local;
    memset(out, 0, sizeof(*out));
    out->codec_status = DNAC_BLKW_OK;

    if (!w) {
        /* No handle is OUR fault, never the peer's. */
        out->result = NODUS_V2_INTERNAL_FAULT;
        out->peer   = NODUS_V2_PEER_NONE;
        return out->result;
    }

    /* ── 1. THE GATE, BEFORE ANYTHING ELSE ────────────────────────────
     *
     * Not one byte of `frame` is examined here, no row is read, no lock is
     * taken and nothing is queued. This ordering is the whole reason V2
     * ingress is dormant rather than merely unused: an unactivated node
     * does no work at all on V2 traffic, so reaching the port buys an
     * attacker nothing.
     *
     * NOT_ACTIVE is not a verdict — the peer is untouched. */
    /* Both conditions are CHEAP and neither touches the database.
     *
     * `is_armed` is a runtime flag. `gate_authority_present` is the half of
     * the gate that consults nothing (see gate.h) — in a build without the
     * test fixture it is a literal 0.
     *
     * `activation_permitted()` is deliberately NOT used here. It evaluates
     * the FULL preflight, which runs a whole-database supply scan and a
     * validator-snapshot resolve. Calling it per frame would mean an ARMED
     * node did those scans for every frame any peer sent, before examining
     * a single byte — inverting "an unactivated node does no work" into "an
     * activated node does maximal work per frame". Review R2 found this.
     *
     * Readiness is established at ARM time, where the full preflight does
     * run (`nodus_witness_v2_ingress_arm` -> `gate_state`), and it is
     * re-established at every database open. A node whose readiness later
     * lapses is disarmed, not silently downgraded — arming is a decision,
     * not a per-frame re-derivation. */
    if (!nodus_witness_v2_ingress_is_armed(w) ||
        !nodus_witness_v2_gate_authority_present(w)) {
        out->result = NODUS_V2_NOT_ACTIVE;
        out->peer   = NODUS_V2_PEER_NONE;
        out->ack    = 0;
        out->queued = 0;
        return out->result;
    }

    /* ── 2. Frame bounds, BEFORE allocation ───────────────────────────
     *
     * An empty or absent frame IS malformed — that is a property of the
     * bytes and every node agrees.
     *
     * An OVER-CAP frame is NOT. `NODUS_V2_ING_MAX_FRAME_BYTES` is LOCAL
     * resource policy (ingress.h): a node with a larger budget accepts the
     * same block, so "too big for me" is a statement about this node, not
     * about the sender. Reporting it as a consensus verdict would let two
     * honest nodes with different local caps issue different peer
     * judgements for identical bytes — the same class of defect as
     * blaming a peer for our own lag. Review R2 found this.
     *
     * It is reported as INTERNAL_FAULT with NO peer action: this node did
     * not evaluate the block, and says so. */
    if (!frame || frame_len == 0) {
        out->result       = NODUS_V2_CONSENSUS_INVALID;
        out->peer         = NODUS_V2_PEER_MALFORMED;
        out->codec_status = DNAC_BLKW_ERR_TRUNCATED;
        return out->result;
    }
    if (frame_len > NODUS_V2_ING_MAX_FRAME_BYTES) {
        QGP_LOG_WARN(LOG_TAG,
                     "V2 frame of %zu bytes exceeds this node's LOCAL "
                     "budget of %u — refused without judging the peer",
                     frame_len, (unsigned)NODUS_V2_ING_MAX_FRAME_BYTES);
        out->result = NODUS_V2_INTERNAL_FAULT;
        out->peer   = NODUS_V2_PEER_NONE;
        return out->result;
    }

    /* ── 3. Decode + canonical form ───────────────────────────────────
     *
     * The decoder allocates nothing and every length is bounded before it
     * is used to advance. The re-encode equality check is what makes one
     * block have exactly one acceptable frame: a decoder can be tolerant
     * in ways an encoder is not, so the property is verified rather than
     * assumed. A malformed frame is a TRANSPORT judgement and is kept
     * distinct from a consensus verdict — it never reached block
     * semantics. */
    dnac_blkmsg_v2_t msg;
    dnac_blkmsg_status_t st = dnac_blkmsg_v2_decode(frame, frame_len, &msg);
    if (st != DNAC_BLKW_OK) {
        out->result       = NODUS_V2_CONSENSUS_INVALID;
        out->peer         = NODUS_V2_PEER_MALFORMED;
        out->codec_status = (int)st;
        QGP_LOG_WARN(LOG_TAG, "V2 frame rejected: %s",
                     dnac_blkmsg_v2_status_name(st));
        return out->result;
    }
    if (!dnac_blkmsg_v2_reencode_equals(frame, frame_len)) {
        out->result       = NODUS_V2_CONSENSUS_INVALID;
        out->peer         = NODUS_V2_PEER_MALFORMED;
        out->codec_status = (int)DNAC_BLKW_ERR_TRAILING;
        QGP_LOG_WARN(LOG_TAG, "%s",
                     "V2 frame rejected: non-canonical encoding");
        return out->result;
    }

    /* ── 4. THE ONE ENGINE ────────────────────────────────────────────
     *
     * Everything authoritative happens beyond this call and NOT here: the
     * seam dispatches the header version, decodes it strictly, computes
     * the claimed BlockID ITSELF, resolves the governing validator
     * snapshot from committed state, verifies the certificate, and only
     * then applies — with every committed header field as an equality
     * assertion the caller cannot weaken.
     *
     * Note what is NOT passed: no BlockID, no previous BlockID, no
     * validator-set hash, no root, no quorum, no count. The engine derives
     * all of them. This adapter cannot propose any of them because the
     * interface has no parameter for them — the same discipline
     * `nodus_witness_v2_qc_verify()` uses for authority. */
    nodus_v2_envelope_t envs[DNA_BLKW_MAX_ENVS];
    for (uint32_t i = 0; i < msg.env_count; i++) {
        envs[i].env_bytes = msg.env[i].bytes;
        envs[i].env_len   = (size_t)msg.env[i].len;
    }

    nodus_v2_block_t blk;
    memset(&blk, 0, sizeof(blk));
    blk.envs      = msg.env_count ? envs : NULL;
    blk.n_envs    = msg.env_count;

    /* `global_height` IS a caller input — see the field-authority table in
     * nodus_witness_v2_apply.h. The seam does NOT derive it: it VERIFIES
     * it, rejecting when `hdr.block_height != blk->global_height`
     * (nodus_witness_v2_finalize.c:61). That asymmetry with `epoch` (which
     * the seam DOES overwrite from the header, finalize.c:110) is easy to
     * misread, and an earlier draft of this adapter did misread it: it left
     * `global_height` at 0 from the memset and claimed in a comment that
     * the seam supplied it.
     *
     * The consequence was severe and silent. Every well-formed block at
     * height >= 1 failed that equality and became CONSENSUS_INVALID —
     * which `classify()` turns into NODUS_V2_PEER_INVALID. The adapter
     * would have manufactured peer blame out of its own bug, on every
     * honest peer serving any real block: exactly the defect class the
     * -1 / -2 / -3 split exists to prevent. Found by review R2.
     *
     * Supplying it here is safe precisely BECAUSE the seam verifies it: a
     * lying adapter is caught at finalize.c:61 before anything durable
     * happens. The value comes from the one canonical header decoder. */
    blk.global_height = ing_header_height(msg.header);

    /* `timestamp` and `proposer_id` are deliberately NOT set here. The
     * seam overwrites both from the decoded header (finalize.c:111-112)
     * so a caller cannot weaken them; assigning them here would imply an
     * authority this adapter does not have. */

    int rc = nodus_witness_v2_finalize_block(w, msg.header,
                                             (size_t)DNA_BH2_ENC_SIZE,
                                             msg.qc, (size_t)msg.qc_len,
                                             &blk);

    classify(out, rc);

    /* ── 5. Deferral: bounded catch-up, never punishment ──────────────
     *
     * NOT_YET_LINKABLE says the block may be perfectly valid and this node
     * simply lacks its predecessors. So: no peer policy, and the frame is
     * parked so the gap can close without a second round trip — subject to
     * every bound in the header. A refused park is silent and harmless;
     * catch-up will fetch the block again in order. */
    if (rc == NODUS_V2_NOT_YET_LINKABLE) {
        static const uint8_t zero_peer[32] = {0};
        uint64_t local_h = ing_committed_height(w);
        (void)nodus_witness_v2_ingress_queue_prune(w, local_h);
        out->queued = q_push(peer_id ? peer_id : zero_peer,
                             ing_header_height(msg.header),
                             local_h, frame, frame_len);
    }

    return out->result;
}
