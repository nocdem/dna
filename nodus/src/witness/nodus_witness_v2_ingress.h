/**
 * @file nodus/src/witness/nodus_witness_v2_ingress.h
 * @brief Ledger V2 O15B — external ingress adapter and network result algebra.
 *
 * ═══ PRODUCTION-DORMANT ═════════════════════════════════════════════════
 * This is the only path by which a Ledger V2 block could enter from the
 * network, and it is CLOSED. `nodus_witness_v2_ingress_block()` asks the
 * activation gate before it looks at a single byte, and the gate can never
 * open in this build — see nodus_witness_v2_gate.h for why (no committed
 * activation authority exists; the preflight is structurally never ready).
 *
 * A V2 frame arriving on an unactivated node is answered
 * `NODUS_V2_NOT_ACTIVE` with:
 *   - no peer acknowledgement,
 *   - no consensus work (nothing is decoded, hashed or verified),
 *   - no database read or mutation,
 *   - no queue entry,
 *   - no effect on the peer's standing.
 *
 * ═══ ONE ENGINE, ADAPTERS ONLY ══════════════════════════════════════════
 * There is exactly ONE validation-and-apply implementation:
 * `nodus_witness_v2_finalize_block()` (O14) over
 * `nodus_witness_v2_apply_block()`. External peers, local production, sync,
 * replay and restart differ only in how bytes REACH it.
 *
 * So this file MUST NOT and does not:
 *   - compute a BlockID (only the engine does, from derived results),
 *   - compute or check a root,
 *   - resolve a validator set, count a quorum, or verify a signature,
 *   - open a database transaction.
 *
 * It decodes bounded bytes, asks the gate, hands the result to the one
 * engine, and translates the engine's answer into a network action. If a
 * reviewer finds a hash or a root computation in here, that is a second
 * engine and a defect.
 *
 * ═══ THE RESULT ALGEBRA, AND WHAT THE NETWORK DOES WITH IT ══════════════
 *
 *   engine result             ack?   peer policy        queue?
 *   ------------------------  -----  -----------------  --------------------
 *   ACCEPTED / PRECACHE       yes*   none               no
 *   IDEMPOTENT_REPLAY         yes*   none               no  (no second effect)
 *   NOT_YET_LINKABLE          no     NONE — not a fault bounded catch-up
 *   CONSENSUS_INVALID         no     invalid-block      no
 *   RETIRED_VERSION           no     invalid-block      no
 *   UNSUPPORTED_VERSION       no     invalid-block      no
 *   INTERNAL_FAULT            no     NONE — ours        no
 *   NOT_ACTIVE                no     NONE — ours        no
 *   malformed frame           no     malformed-frame    no
 *
 *   * ACKNOWLEDGEMENT IS EMITTED ONLY AFTER THE DURABLE COMMIT RETURNS.
 *     `nodus_v2_ingress_outcome_t.ack` is set from the engine's result, and
 *     the engine returns only after its single COMMIT. There is no path
 *     that acknowledges first and commits later.
 *
 * The three "no policy" rows are the point of the whole table.
 * `NOT_YET_LINKABLE` means this node is behind — synced peers accept the
 * very same bytes. `INTERNAL_FAULT` means THIS node could not compute.
 * `NOT_ACTIVE` means this node never looked. Holding any of them against a
 * peer would be manufacturing evidence out of our own state, which is the
 * defect class O15A closed inside the engine and this file closes at the
 * network boundary. `nodus_v2_result_blames_peer()` is the single predicate
 * that decides, so the rule lives in one place.
 *
 * ═══ RESOURCE POSTURE ═══════════════════════════════════════════════════
 * A frame is bounded BEFORE it is decoded and the decoder allocates
 * nothing. The future-block queue is bounded on FIVE independent axes
 * (count, bytes, height distance, per peer, lifetime) so no peer can make
 * an unactivated — or an activated — node spend unbounded memory, disk or
 * verification work by sending gaps and duplicates.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_INGRESS_H
#define NODUS_WITNESS_V2_INGRESS_H

#include <stddef.h>
#include <stdint.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_result.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Resource policy ──────────────────────────────────────────────────
 *
 * Each constant is classified, because "what kind of limit is this?"
 * decides who may change it and what breaks if they do:
 *
 *   CONSENSUS   — changing it changes which blocks are valid. NONE here.
 *   WIRE        — changing it changes what peers can express; both ends
 *                 must agree. `DNA_BLKW_*` in blockmsg_v2.h.
 *   LOCAL       — a resource policy this node applies to itself. A node
 *                 with different values still agrees on every block; it
 *                 just spends different memory. Everything below is LOCAL.
 */

/**
 * LOCAL. Largest V2 block frame this node will even look at.
 *
 * Deliberately far below `DNA_BLKW_MAX_ENC_LEN` (which is the codec's
 * structural ceiling — 16 × 1 MiB of envelopes dominates it). Sized as
 * 2 MiB to match the committed meter policy's `max_block_env_bytes`, so a
 * block this node would refuse to execute is also a block it refuses to
 * READ, and the cheaper refusal comes first.
 */
#define NODUS_V2_ING_MAX_FRAME_BYTES   (2u * 1024u * 1024u)

/** LOCAL. Maximum blocks held awaiting a missing predecessor. */
#define NODUS_V2_ING_QUEUE_MAX_BLOCKS  32u
/** LOCAL. Maximum total bytes across the queue. */
#define NODUS_V2_ING_QUEUE_MAX_BYTES   (8u * 1024u * 1024u)
/** LOCAL. Maximum entries any ONE peer may occupy. Anti-monopolisation. */
#define NODUS_V2_ING_QUEUE_MAX_PER_PEER 8u
/**
 * LOCAL. How far above the next expected height a block may be and still
 * be worth holding. Beyond this the sender is further ahead than catch-up
 * would close in one pass, so holding the block buys nothing and only
 * reserves memory.
 */
#define NODUS_V2_ING_QUEUE_MAX_DISTANCE 64u
/**
 * LOCAL. Queue entry lifetime, in BLOCKS of local progress — never in
 * seconds. A wall-clock lifetime would make eviction depend on the local
 * clock, which is a non-deterministic input this tree forbids anywhere
 * near consensus. Progress is the only monotone quantity both ends agree
 * on.
 */
#define NODUS_V2_ING_QUEUE_MAX_AGE_BLOCKS 16u

/** What the network layer should do about the peer that sent this. */
typedef enum {
    /** Nothing. The peer did nothing wrong (or we never looked). */
    NODUS_V2_PEER_NONE       = 0,
    /**
     * The peer sent a block that is deterministically invalid. Every
     * honest node with the same committed state agrees, so this is the
     * ONLY class that may be held against it.
     */
    NODUS_V2_PEER_INVALID    = 1,
    /**
     * The bytes were not a well-formed frame — rejected before block
     * semantics were reached. A transport-level judgement, kept separate
     * from INVALID because it says nothing about consensus.
     */
    NODUS_V2_PEER_MALFORMED  = 2
} nodus_v2_peer_action_t;

/** Stable human-readable name for a peer action (never NULL). */
const char *nodus_v2_peer_action_name(nodus_v2_peer_action_t a);

/** The complete outcome of one ingress attempt. */
typedef struct {
    /** The engine's typed result, or NOT_ACTIVE / CONSENSUS_INVALID. */
    nodus_v2_result_t      result;
    /** What to do about the peer. */
    nodus_v2_peer_action_t peer;
    /**
     * 1 only when the block is durably committed and the peer may be
     * acknowledged. Set from the engine's result AFTER it returns, so it
     * cannot be true before the commit.
     */
    int                    ack;
    /** 1 when the block was parked awaiting its predecessor. */
    int                    queued;
    /**
     * 1 when this node should begin bounded catch-up. Set only for
     * NOT_YET_LINKABLE — never a punishment, always a request.
     */
    int                    want_catchup;
    /** Codec status when the frame failed to decode; OK otherwise. */
    int                    codec_status;
} nodus_v2_ingress_outcome_t;

/**
 * Accept one Ledger V2 block frame from a peer.
 *
 * ORDER — the gate is asked FIRST, before any decode:
 *   1. gate closed  → NOT_ACTIVE. Nothing is decoded, nothing is read,
 *      nothing is written, the peer is not judged, nothing is queued.
 *   2. frame bounds → over NODUS_V2_ING_MAX_FRAME_BYTES is MALFORMED,
 *      refused before allocation.
 *   3. decode + canonical re-encode equality → MALFORMED on failure.
 *   4. the ONE engine (`nodus_witness_v2_finalize_block`).
 *   5. translate the engine's result into a network action.
 *
 * @param w        witness handle.
 * @param peer_id  32-byte peer identity, for per-peer queue accounting.
 *                 May be NULL (accounted as the all-zero peer).
 * @param frame    the received bytes.
 * @param frame_len their length.
 * @param out      [out] the outcome; zeroed first, always populated.
 * @return the same value as `out->result`, for callers that want one.
 */
int nodus_witness_v2_ingress_block(nodus_witness_t *w,
                                   const uint8_t *peer_id,
                                   const uint8_t *frame, size_t frame_len,
                                   nodus_v2_ingress_outcome_t *out);

/* ── The bounded future-block queue ──────────────────────────────────── */

/** Current queue occupancy. Any pointer may be NULL. */
void nodus_witness_v2_ingress_queue_stats(nodus_witness_t *w,
                                          uint32_t *n_blocks,
                                          uint64_t *n_bytes);

/**
 * Drop every queued entry. Called on disarm and on shutdown.
 *
 * Idempotent, and safe on a node that never armed — a node that never
 * queued anything has nothing to free, which is exactly the state a
 * production node is always in.
 */
void nodus_witness_v2_ingress_queue_clear(nodus_witness_t *w);

/**
 * Evict entries the local head has outrun.
 *
 * @param w              witness handle.
 * @param local_height   this node's committed head.
 * @return number of entries evicted.
 */
uint32_t nodus_witness_v2_ingress_queue_prune(nodus_witness_t *w,
                                              uint64_t local_height);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_INGRESS_H */
