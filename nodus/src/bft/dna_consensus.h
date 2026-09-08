/* DNA — engine-independent consensus interface (T1).
 *
 * The core SEES NO BYTES: messages arrive decoded, with their signature and
 * the sender's membership already verified by the HOST. id(v) arrives ready
 * made (BlockID, block_v2.h); the core computes no hash.
 *
 * Design: docs/plans/2026-09-08-tendermint-t1-core-design.md §4.1 — the
 * declarations below are NORMATIVE (names, signatures, enum values, defines,
 * field order). Only the doc comments are this file's own.
 *
 * T1 has ZERO consumers: nothing in the tree calls dna_consensus_lookup yet.
 * The engine binding is T4 (main plan §5, §7).
 */
#ifndef DNA_CONSENSUS_H
#define DNA_CONSENSUS_H
#include <stdint.h>
#include <stddef.h>

#define DNA_CONSENSUS_ID_LEN        32   /* validator identity = voter_id (D-7) */
#define DNA_CONSENSUS_VALUE_ID_LEN  64   /* id(v) = BlockID; nil = 64 x 0x00 (D-7) */

/* D-11: the protocol identity carried in chain state.
 * 0 = INVALID (tree rule: enum 0 is fail-closed). */
#define DNA_CONSENSUS_PROTOCOL_INVALID     0u
#define DNA_CONSENSUS_PROTOCOL_TENDERMINT  1u   /* [JUDGMENT] first assigned id */

typedef enum { DNA_CMSG_PROPOSAL = 1, DNA_CMSG_PREVOTE = 2, DNA_CMSG_PRECOMMIT = 3 } dna_cmsg_type_t;

/* A decoded consensus message.
 *
 * PROPOSAL: value/value_len are v's bytes, value_id is id(v), valid_round is
 *           vr (-1 = none).
 * PREVOTE/PRECOMMIT: value_id is the vote (nil = 64 x 0x00), value is NULL and
 *           valid_round is ignored.
 *
 * The core copies everything it keeps; the caller may reuse the buffer as soon
 * as the call returns. */
typedef struct dna_cmsg {
    dna_cmsg_type_t type;
    uint64_t        height;
    uint32_t        round;
    int32_t         valid_round;
    uint8_t         sender[DNA_CONSENSUS_ID_LEN];
    uint8_t         value_id[DNA_CONSENSUS_VALUE_ID_LEN];
    const uint8_t  *value;
    size_t          value_len;
} dna_cmsg_t;

/* The governing set: strictly ascending (memcmp) 32-byte identities.
 * weights == NULL means every member has weight 1 (the DNA instantiation).
 *
 * The core (tm_core) REFUSES weights != NULL in T1 (returns -1); general
 * weights exist only for the tm_proposer reference KATs. */
typedef struct dna_vset {
    uint32_t                 n;
    const uint8_t          (*ids)[DNA_CONSENSUS_ID_LEN];
    const int64_t           *weights;
} dna_vset_t;

/* The decision object: which members supplied the 2f+1 PRECOMMIT(h, r, id(v)).
 * The SIGNATURES stay in the HOST (the T2 quorum certificate); this structure
 * only names the voters. */
typedef struct dna_commit {
    uint64_t        height;
    uint32_t        round;
    uint8_t         value_id[DNA_CONSENSUS_VALUE_ID_LEN];
    uint32_t        n_voters;
    const uint8_t (*voters)[DNA_CONSENSUS_ID_LEN];   /* strictly ascending voter_id (qc_v2.h rule) */
} dna_commit_t;

typedef struct dna_consensus_host {
    void    *ctx;
    uint8_t  self[DNA_CONSENSUS_ID_LEN];
    /* Algorithm 1 getValue().
     *   0 = *value is a malloc'd copy (OWNERSHIP PASSES TO THE CORE, which
     *       frees it), *len is its length, id[] has been filled in.
     *   1 = no value this round -> the proposer behaves exactly like a
     *       non-proposer for this round: it proposes nothing, arms
     *       timeoutPropose and prevotes nil when that fires (design §5.2).
     *  <0 = error; the core treats it as 1.
     * MUST NOT re-enter the core. */
    int  (*get_value)(void *ctx, uint64_t height, uint8_t **value, size_t *len,
                      uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN]);
    /* Algorithm 1 valid(v): 1 valid, 0 invalid, -1 FAULT ("cannot decide right
     * now" — the core does not fire the rule and asks again on the next
     * message/tick; design §5.5). The 1/0 answer for a given v MUST be stable:
     * the core memoises it. MUST NOT re-enter the core.
     *
     * CONTRACT (G7): MUST return 0 when id(value) != value_id. The core
     * computes no hash (design §1), so the HOST is the only place the bytes
     * are bound to the id. Without that check, two well-formed but DIFFERENT
     * values sent to two nodes under the same claimed id would be counted as
     * one value by every threshold in the algorithm. */
    int  (*valid)(void *ctx, uint64_t height, const uint8_t *value, size_t len,
                  const uint8_t id[DNA_CONSENSUS_VALUE_ID_LEN]);
    /* One of this node's own messages, already written to the core's own log.
     * HOST CONTRACT: persist(fsync) then broadcast, in that order (T2/T3). A
     * failed persist halts the host; the core does not roll back. NOT called
     * in replay mode. MUST NOT re-enter the core. */
    void (*emit)(void *ctx, const dna_cmsg_t *own);
    /* The decision. The core is IDLE afterwards; the HOST calls start_height
     * for h+1 when it is ready (the D-4 wait lives in the host). `value` and
     * `commit` are borrowed for the duration of the call only.
     * MUST NOT re-enter the core — in particular, DO NOT call start_height
     * from inside decide: `value` and `commit->voters` point into core memory
     * that start_height frees, so the callback would be reading freed storage
     * from that moment on. Note the wait and call start_height afterwards. */
    void (*decide)(void *ctx, uint64_t height, const uint8_t *value, size_t len, const dna_commit_t *commit);
    /* Observation hooks (may be NULL): round entry (for the D-10 round-state
     * announcement) and the evidence of an equivocation. */
    void (*on_round_start)(void *ctx, uint64_t height, uint32_t round, const uint8_t proposer[DNA_CONSENSUS_ID_LEN]);
    void (*on_equivocation)(void *ctx, const dna_cmsg_t *first, const dna_cmsg_t *second);
} dna_consensus_host_t;

typedef struct dna_consensus dna_consensus_t;   /* opaque; the engine's own state */

/* The engine table (D-11 registry key). EVERY entry takes now_ms: the core
 * NEVER READS A CLOCK. */
typedef struct dna_consensus_ops {
    uint32_t     protocol_id;
    const char  *spec_ref;        /* "arXiv:1807.04938v3 Algorithm 1; cometbft@709fd12b" — "latest" is FORBIDDEN */
    int  (*create)(dna_consensus_t **out, const dna_consensus_host_t *host, const void *params);
    void (*destroy)(dna_consensus_t *c);
    int  (*start_height)(dna_consensus_t *c, uint64_t height, const dna_vset_t *set,
                         const void *proposer_state, uint64_t now_ms);
    int  (*on_message)(dna_consensus_t *c, const dna_cmsg_t *m, uint64_t now_ms);
    int  (*on_tick)(dna_consensus_t *c, uint64_t now_ms);
} dna_consensus_ops_t;

/* Registry: an unknown identity returns NULL (D-11: an unknown protocol id
 * halts the node; that DECISION belongs to the HOST, not to this lookup). */
const dna_consensus_ops_t *dna_consensus_lookup(uint32_t protocol_id);

#endif
