/**
 * @file nodus/src/witness/nodus_witness_v2_result.h
 * @brief Ledger V2 O15A — the typed result contract shared by every layer
 *        of the V2 block-acceptance path.
 *
 * INACTIVE — Ledger V2 has no external ingress. This header adds no
 * behaviour of its own; it gives the existing return codes names and adds
 * the classes the previous integer contract could not express.
 *
 * ── WHY A TYPE ────────────────────────────────────────────────────────
 * Before O15A the whole path spoke in bare integers, and two genuinely
 * different situations shared the value -1:
 *
 *   - "this block is invalid, and every honest node with the same
 *      committed state agrees"                     — a CONSENSUS VERDICT
 *   - "this block is not the next one in MY chain" — a LOCAL SEQUENCING
 *      condition a node that is merely behind reports while synced peers
 *      accept the very same bytes
 *
 * `nodus_witness_v2_finalize.h` carried that hazard as a prose caveat,
 * because the type system had no way to say it. A caller that read -1 as
 * proof of proposer misbehaviour — and blacklisted on it — would have been
 * punishing honest proposers for its own lag. This enum removes the
 * ambiguity at the seam instead of documenting it.
 *
 * ── NUMERICALLY ADDITIVE, DELIBERATELY ────────────────────────────────
 * 0 / 1 / 2 / -1 / -2 keep the exact values they have carried since S5, so
 * every existing caller and every existing test remains correct and this
 * change introduces no renumbering. The three new classes take values no
 * code could previously return, which is what makes the widening safe: an
 * old caller cannot silently mistake a new class for an old one, because
 * no old producer ever emitted -3, -4 or -5.
 *
 * Naming stable constants is what satisfies "no ambiguous magic integers
 * at a subsystem boundary" — an integer with a documented name and a fixed
 * meaning is a contract, not magic.
 *
 * ── THE THREE FAMILIES ────────────────────────────────────────────────
 * SUCCESS  (>= 0)  the block is accepted; state may have been committed.
 * VERDICT  (-1, -4, -5)  a deterministic judgement about the block itself.
 *                  Every honest node with the same committed state reaches
 *                  the same conclusion. Safe to hold against a peer.
 * DEFERRAL (-3)    no judgement was reached. The block may be perfectly
 *                  valid; this node lacks the predecessor state needed to
 *                  evaluate it.
 * FAULT    (-2)    no judgement was reached. THIS NODE could not compute
 *                  (storage, allocation, hash backend, absent committed
 *                  authority). A node that cannot decide must stay silent:
 *                  silence is survivable at f=2, a confident wrong answer
 *                  forks the chain.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_WITNESS_V2_RESULT_H
#define NODUS_WITNESS_V2_RESULT_H

/**
 * The result of evaluating a Ledger V2 block, at every layer from the
 * parser to the production finalization seam.
 *
 * Every translation layer MUST preserve the class. Collapsing any of these
 * into a boolean accept/reject — `rc != 0`, `rc < 0`, `rc == -1` —
 * reintroduces exactly the confusion this type exists to remove.
 */
typedef enum {
    /* ── SUCCESS ──────────────────────────────────────────────────── */

    /** Committed. */
    NODUS_V2_ACCEPTED            = 0,

    /**
     * Already committed; nothing was written. The caller asserted the
     * identity of the block already stored at this height and the engine
     * served the committed row instead of re-executing.
     */
    NODUS_V2_IDEMPOTENT_REPLAY   = 1,

    /**
     * Committed, but the post-COMMIT / pre-cache-publication window was
     * interrupted (fault point V2AP_FAIL_AFTER_COMMIT). The durable state
     * is correct and a restart recovers; only the in-memory cache is
     * stale. A source-required distinction, not a new class — see
     * nodus_witness_v2_apply.h and nodus_witness_v2_apply.c:2221.
     */
    NODUS_V2_ACCEPTED_PRECACHE   = 2,

    /* ── VERDICTS: judgements about the block ─────────────────────── */

    /**
     * The block is invalid as judged against COMMITTED chain state.
     * Deterministic: every honest node holding the same committed state
     * agrees. This is the only value that may be treated as evidence
     * about the proposer.
     */
    NODUS_V2_CONSENSUS_INVALID   = -1,

    /* ── FAULT: this node could not decide ────────────────────────── */

    /**
     * Node-local failure — storage error, allocation failure, hash
     * backend failure, a malformed local row, absent committed authority
     * for the block's epoch, or a caller passing NULL. Says nothing about
     * the block. MUST NEVER be converted into a rejection, and must never
     * count as a negative validator vote.
     */
    NODUS_V2_INTERNAL_FAULT      = -2,

    /* ── DEFERRAL: not yet evaluable here ─────────────────────────── */

    /**
     * The block cannot be evaluated yet because required predecessor
     * state is absent on this node: its height is beyond the next
     * expected one, or no genesis is committed here at all.
     *
     * This is NOT a statement that the block is invalid. Concretely, the
     * caller MUST NOT: mark the block invalid, commit any state, advance
     * a head, punish or blacklist the peer that offered it, or retry into
     * acceptance through a different authority source.
     *
     * Requesting or queueing the missing history is a SYNC concern and is
     * deliberately absent here — O15A implements no network behaviour.
     *
     * Note the boundary: a block at or below the current head is NOT this
     * class. A stale or duplicate block is evaluable now and gets a
     * verdict; only a block ahead of the chain is deferred.
     */
    NODUS_V2_NOT_YET_LINKABLE    = -3,

    /* ── VERDICTS: version dispatch ───────────────────────────────── */

    /**
     * The header names a RETIRED protocol version (block header v2). Kept
     * distinct from an unknown version so a retired layout can never be
     * silently reinterpreted under the current one, and so operators can
     * tell "your software is too new for this block" from "your software
     * is too old for this block". Fail-closed; never falls back to the
     * legacy lane.
     */
    NODUS_V2_RETIRED_VERSION     = -4,

    /**
     * The header names a version this build does not implement.
     * Fail-closed, and deliberately a different class from
     * NODUS_V2_RETIRED_VERSION.
     */
    NODUS_V2_UNSUPPORTED_VERSION = -5
} nodus_v2_result_t;

/**
 * True when the result means the block was accepted and state may have
 * been committed. Provided so callers stop writing `rc >= 0`, which would
 * silently absorb any future success class.
 */
static inline int nodus_v2_result_is_accepted(int rc) {
    return rc == NODUS_V2_ACCEPTED ||
           rc == NODUS_V2_IDEMPOTENT_REPLAY ||
           rc == NODUS_V2_ACCEPTED_PRECACHE;
}

/**
 * True when the result is a deterministic judgement about the block, and
 * therefore may be held against the peer that offered it.
 *
 * NOT_YET_LINKABLE and INTERNAL_FAULT are excluded on purpose: neither is
 * a judgement, and treating either as one is the defect O15A closes.
 */
static inline int nodus_v2_result_is_verdict(int rc) {
    return rc == NODUS_V2_CONSENSUS_INVALID ||
           rc == NODUS_V2_RETIRED_VERSION ||
           rc == NODUS_V2_UNSUPPORTED_VERSION;
}

/**
 * True when no judgement was reached, for either reason — this node could
 * not compute, or it lacks the predecessor state. A witness in this state
 * must abstain: it may not vote, and it may not reject.
 */
static inline int nodus_v2_result_is_undecided(int rc) {
    return rc == NODUS_V2_INTERNAL_FAULT ||
           rc == NODUS_V2_NOT_YET_LINKABLE;
}

#endif /* NODUS_WITNESS_V2_RESULT_H */
