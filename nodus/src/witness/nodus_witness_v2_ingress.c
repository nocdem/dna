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

/* ── blkframe v2 — NODUS-side claim carriage (O15F D5) ─────────────────────
 *
 * Contract in nodus_witness_v2_ingress.h. This is a BYTE codec only: like
 * the v1 BlockMessage decoder it computes no consensus value, and the
 * carried claims are re-derived and bound by the one engine downstream. */

static void bf_wr_u32be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t bf_rd_u32be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int nodus_witness_v2_blkframe_encode(const uint8_t *blkmsg, size_t blkmsg_len,
                                     const uint8_t *const *claims,
                                     const size_t *claim_lens,
                                     uint32_t n_claims,
                                     uint8_t **out, size_t *out_len) {
    if (out)     *out     = NULL;
    if (out_len) *out_len = 0;
    if (!blkmsg || blkmsg_len == 0 || !out || !out_len)   return -1;
    if (blkmsg_len > (size_t)DNA_BLKW_MAX_ENC_LEN)         return -1;
    if (n_claims > NODUS_W_MAX_BLOCK_TXS)                  return -1;
    if (n_claims > 0 && (!claims || !claim_lens))          return -1;

    /* total = tag(1) + len(4) + blkmsg + n(4) + Σ( len(4) + claim ). Every
     * component is bounded (blkmsg <= DNA_BLKW_MAX_ENC_LEN, n <= 10, each
     * claim <= DNA_CLAIM_MAX_WIRE), so the sum cannot overflow size_t. */
    size_t total = 1u + 4u + blkmsg_len + 4u;
    for (uint32_t i = 0; i < n_claims; i++) {
        size_t cl = claim_lens[i];
        if (cl == 0 || cl > (size_t)DNA_CLAIM_MAX_WIRE || !claims[i]) return -1;
        total += 4u + cl;
    }

    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    size_t off = 0;
    buf[off++] = NODUS_V2_BLKFRAME_TAG;
    bf_wr_u32be(buf + off, (uint32_t)blkmsg_len); off += 4;
    memcpy(buf + off, blkmsg, blkmsg_len);        off += blkmsg_len;
    bf_wr_u32be(buf + off, n_claims);             off += 4;
    for (uint32_t i = 0; i < n_claims; i++) {
        bf_wr_u32be(buf + off, (uint32_t)claim_lens[i]); off += 4;
        memcpy(buf + off, claims[i], claim_lens[i]);     off += claim_lens[i];
    }
    *out     = buf;
    *out_len = total;
    return 0;
}

int nodus_witness_v2_blkframe_decode(const uint8_t *frame, size_t frame_len,
                                     dnac_blkmsg_v2_t *msg_out,
                                     dna_claim_t *claims_out,
                                     uint32_t claims_cap,
                                     uint32_t *n_claims_out) {
    if (n_claims_out) *n_claims_out = 0;
    if (!frame || !msg_out || !n_claims_out)         return -1;
    if (claims_cap > 0 && !claims_out)               return -1;

    /* tag(1) + blkmsg_len(4) minimum */
    if (frame_len < 5)                               return -1;
    if (frame[0] != NODUS_V2_BLKFRAME_TAG)           return -1;

    size_t off = 1;
    uint32_t blkmsg_len = bf_rd_u32be(frame + off);  off += 4;   /* off == 5 */
    if (blkmsg_len == 0 || blkmsg_len > (uint32_t)DNA_BLKW_MAX_ENC_LEN)
        return -1;
    if ((uint64_t)blkmsg_len > (uint64_t)(frame_len - off)) return -1;
    const uint8_t *bm = frame + off;
    size_t bml = (size_t)blkmsg_len;
    off += bml;

    /* the inner block: strict decode + canonical form (one encoding per
     * block), re-validated by the EXISTING v1 codec — this file never adds
     * a second block decoder. */
    if (dnac_blkmsg_v2_decode(bm, bml, msg_out) != DNAC_BLKW_OK) return -1;
    if (!dnac_blkmsg_v2_reencode_equals(bm, bml))                return -1;

    if ((uint64_t)(frame_len - off) < 4) return -1;
    uint32_t n = bf_rd_u32be(frame + off); off += 4;
    if (n > NODUS_W_MAX_BLOCK_TXS || n > claims_cap) return -1;

    for (uint32_t i = 0; i < n; i++) {
        if ((uint64_t)(frame_len - off) < 4) return -1;
        uint32_t cl = bf_rd_u32be(frame + off); off += 4;
        if (cl == 0 || cl > (uint32_t)DNA_CLAIM_MAX_WIRE) return -1;
        if ((uint64_t)cl > (uint64_t)(frame_len - off))   return -1;
        const uint8_t *cb = frame + off;

        if (dna_claim_decode(cb, (size_t)cl, &claims_out[i]) != 0) return -1;
        /* one accepted encoding per claim — CHECK it re-encodes to the exact
         * input slice (the admission discipline: verify, do not argue). */
        uint8_t scratch[DNA_CLAIM_MAX_WIRE];
        size_t need = dna_claim_encoded_len(&claims_out[i]);
        size_t wr = 0;
        if (need != (size_t)cl ||
            dna_claim_encode(&claims_out[i], scratch, sizeof(scratch),
                             &wr) != 0 ||
            wr != (size_t)cl ||
            memcmp(scratch, cb, (size_t)cl) != 0)
            return -1;
        off += cl;
    }
    if (off != frame_len) return -1;   /* trailing bytes reject */

    *n_claims_out = n;
    return 0;
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
    /* `is_armed` is a runtime flag and costs nothing.
     *
     * `gate_authority_present` NO LONGER costs nothing, and this comment
     * used to say it did. O15J Faz 3 removed the activation ceremony and
     * rewired authority to be DERIVED from the chain's own committed
     * height-0 genesis manifest, so on an ARMED node this is now two
     * SQLite statements per frame against a one-row table. It is no
     * longer "the half of the gate that consults nothing".
     *
     * CARRIED OPEN, deliberately, not overlooked: the cheap form is to
     * settle authority at ARM time (it derives from committed state that
     * cannot change while the database is open) and have this path read
     * the settled answer. That was not done here because several tests
     * set `v2_ingress_armed` directly, so a cached companion flag would
     * silently disarm them — a change worth making on its own, with its
     * own test sweep, not as a tail-end edit of a removal phase. The
     * shape being avoided is the one Review R2 already condemned below.
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

    /* ── 3. Decode + canonical form — dispatch on byte 0 ──────────────
     *
     * A bare BlockMessage v1 starts with `msg_version` == DNA_BLKW_VERSION
     * (1). A NODUS-side blkframe v2 container (claim carriage, O15F D5)
     * starts with NODUS_V2_BLKFRAME_TAG (2). Any other lead byte is
     * neither, and MALFORMED — a v1 decode would reject it on the version
     * field anyway, but dispatching makes the two shapes explicit.
     *
     * Both paths are BYTE codecs: allocate nothing consensus-bearing,
     * bound every length before advancing, and CHECK the one-encoding
     * property rather than assume it (a decoder can be tolerant in ways an
     * encoder is not). A malformed frame is a TRANSPORT judgement, kept
     * distinct from a consensus verdict — it never reached block
     * semantics. Everything authoritative happens beyond step 4. */
    dnac_blkmsg_v2_t msg;
    dna_claim_t     *claims   = NULL;   /* heap: dna_claim_t is ~11.6 KB   */
    uint32_t         n_claims = 0;

    if (frame[0] == NODUS_V2_BLKFRAME_TAG) {
        /* Up to NODUS_W_MAX_BLOCK_TXS claims of ~11.6 KB each (~116 KB):
         * heap, per the repo's heap-fixture discipline, never on the
         * already-large ingress frame. */
        claims = calloc(NODUS_W_MAX_BLOCK_TXS, sizeof(*claims));
        if (!claims) {
            out->result = NODUS_V2_INTERNAL_FAULT;   /* OURS, not the peer */
            out->peer   = NODUS_V2_PEER_NONE;
            return out->result;
        }
        if (nodus_witness_v2_blkframe_decode(frame, frame_len, &msg,
                                             claims, NODUS_W_MAX_BLOCK_TXS,
                                             &n_claims) != 0) {
            free(claims);
            out->result       = NODUS_V2_CONSENSUS_INVALID;
            out->peer         = NODUS_V2_PEER_MALFORMED;
            out->codec_status = (int)DNAC_BLKW_ERR_TRAILING;
            QGP_LOG_WARN(LOG_TAG, "%s",
                         "V2 blkframe container rejected: strict decode");
            return out->result;
        }
    } else {
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
    /* Carried claims (0x02 container only; NULL for a bare v1 frame). Bound
     * TRANSITIVELY through claims_root → global root → BlockID → QC: the
     * engine re-executes them and the header/id equality is the binding.
     * An omitted / extra / substituted-semantics claim lands on a different
     * global root and dies at expect_block_id — never commits wrong state. */
    blk.claims    = n_claims ? claims : NULL;
    blk.n_claims  = n_claims;

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
        /* Park the WHOLE frame (0x01 or 0x02): a re-ingress re-decodes it
         * from byte 0, so the container's claims are recovered too. */
        out->queued = q_push(peer_id ? peer_id : zero_peer,
                             ing_header_height(msg.header),
                             local_h, frame, frame_len);
    }

    /* The claim array (0x02 path) held only for the finalize call above —
     * the engine copied/applied what it needed within its ONE transaction. */
    free(claims);
    return out->result;
}
