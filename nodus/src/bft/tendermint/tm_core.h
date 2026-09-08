/* DNA — Tendermint consensus core (T1), INTERNAL header.
 *
 * Pure Algorithm 1 (arXiv:1807.04938v3, lines 1-67) plus the reference
 * proposer-priority counter (cometbft@709fd12b). NO I/O, NO CLOCK, NO HASH,
 * NO SIGNATURE, NO SQLite. The dependency surface is exactly
 *   <stdint.h> <stddef.h> <string.h> <stdlib.h>, dna_consensus.h, this file,
 *   dnac/ledger_ids.h
 * and nothing else — anything more is a whitelist violation (design §3).
 *
 * Design: docs/plans/2026-09-08-tendermint-t1-core-design.md §4.2. The
 * declarations down to `tm_ops` are NORMATIVE (names, signatures, enum values,
 * defines, field order); only the doc comments are this file's own. The
 * "INTERNAL" section at the bottom is module-private plumbing shared between
 * tm_state.c / tm_log.c / tm_timeouts.c / tm_proposer.c — no other translation
 * unit may include it.
 */
#ifndef TM_CORE_H
#define TM_CORE_H
#include "../dna_consensus.h"

typedef enum { TM_STEP_PROPOSE = 0, TM_STEP_PREVOTE = 1, TM_STEP_PRECOMMIT = 2 } tm_step_t;

/* [DECISION D-5] compile-time defaults = CometBFT config.go @ e94961b0.
 * The final values come from measurement at T3. */
#define TM_TIMEOUT_PROPOSE_INIT_MS     3000u
#define TM_TIMEOUT_PROPOSE_DELTA_MS     500u
#define TM_TIMEOUT_PREVOTE_INIT_MS     1000u
#define TM_TIMEOUT_PREVOTE_DELTA_MS     500u
#define TM_TIMEOUT_PRECOMMIT_INIT_MS   1000u
#define TM_TIMEOUT_PRECOMMIT_DELTA_MS   500u
/* [JUDGMENT] log bounds — design §5.6 */
#define TM_ROUND_LOOKAHEAD               64u
#define TM_MAX_HEIGHT_LOG_BYTES  (64u * 1024u * 1024u)
#define TM_MAX_VALUE_BYTES        (2u * 1024u * 1024u)  /* one PROPOSAL value; same as the
                                                         * SYSTEM meter's max_block_env_bytes */
#define TM_MAX_ROUND              0x7FFFFFFFu           /* the int32 round fields never wrap */
#define TM_ROUND_LOOKAHEAD_MAX    4096u                 /* ceiling on params.round_lookahead */
#define TM_H1_PROPOSAL_ROUNDS        2u                 /* highest round a BUFFERED h+1 PROPOSAL may carry */

typedef struct tm_params {
    uint32_t propose_init_ms,   propose_delta_ms;
    uint32_t prevote_init_ms,   prevote_delta_ms;
    uint32_t precommit_init_ms, precommit_delta_ms;
    uint32_t round_lookahead;
    size_t   max_height_log_bytes;
    size_t   max_value_bytes;        /* per PROPOSAL; must be > 0 and <= max_height_log_bytes */
} tm_params_t;
void tm_params_default(tm_params_t *p);     /* the constants above */

/* -- Proposer selection (design §6): a pure object, usable INDEPENDENTLY of
 *    the core. --------------------------------------------------------- */
typedef struct tm_proposer tm_proposer_t;   /* opaque: the set (a copy) + int64 priority[n] */
/* NewValidatorSet (validator_set.go:77-89) -> S_1, the height-1 state. */
int  tm_proposer_create(tm_proposer_t **out, const dna_vset_t *genesis_set);
void tm_proposer_destroy(tm_proposer_t *p);
/* Next height: if the set differs, updateWithChangeSet (add/remove/rescale/
 * centre), then IncrementProposerPriority(1). S_h -> S_{h+1}. */
int  tm_proposer_next_height(tm_proposer_t *p, const dna_vset_t *set_for_next);
/* proposer(h, round): IncrementProposerPriority(round) on a COPY
 * (state.go:1071-1075); `p` is left untouched. round 0 performs no increment
 * and returns the proposer the LAST increment selected. */
int  tm_proposer_at(const tm_proposer_t *p, uint32_t round, uint8_t out[DNA_CONSENSUS_ID_LEN]);
/* For the T2 WAL: S_h is the TRIPLE (set, priority vector, ELECTED PROPOSER
 * INDEX), and all three cross the boundary.
 *
 * The index is MANDATORY, not a convenience. The pinned code keeps the elected
 * proposer in its own field (validator_set.go:59 `Proposer`, assigned at :152)
 * and GetProposer (:341-348) returns THAT field; findProposer (:351-359) is
 * only the nil fallback. Because the election ends with A(prop) -= P, the
 * maximum of the vector is no longer the member that was elected — the
 * 4-member genesis state is [-3, 1, 1, 1] with v0 elected while the maximum is
 * v1 — so round 0 cannot be recovered from the vector. Carrying the index
 * closes that; there is NO fallback on the import path.
 *
 * import: proposer_idx >= set->n returns -1. Design §4.2 (decided 2026-09-08
 * after the executor found the gap); pinned by test_tm_proposer §F, which now
 * round-trips round 0 as well. */
int  tm_proposer_export(const tm_proposer_t *p, dna_vset_t *set_out, int64_t *prio_out, uint32_t cap,
                        uint32_t *proposer_idx_out);
int  tm_proposer_import(tm_proposer_t **out, const dna_vset_t *set, const int64_t *prio,
                        uint32_t proposer_idx);

/* -- The core ---------------------------------------------------------- */
typedef struct tm_core tm_core_t;
int  tm_core_create(tm_core_t **out, const dna_consensus_host_t *host, const tm_params_t *p);
void tm_core_destroy(tm_core_t *c);
/* Opening a height = StartRound(0). `prop` is the proposer object the HOST has
 * advanced to S_h (the core never advances it; it keeps a private clone).
 * set->weights != NULL => -1. The h+1 buffer is drained, in arrival order,
 * inside this call — after StartRound(0), which is the only order in which the
 * lookahead window and the round rules are defined. */
int  tm_core_start_height(tm_core_t *c, uint64_t h, const dna_vset_t *set, const tm_proposer_t *prop, uint64_t now_ms);
/* Returns: 0 logged (rules evaluated) - 1 ignored (stale/far height, outside
 * the lookahead, duplicate, wrong proposer, decided height, out of budget)
 * - 2 EQUIVOCATION - -1 error. Rc 2 does not mean the message was dropped:
 * the SECOND distinct vote from one sender at one (round, type) is recorded
 * and counted for its own value (design §5.4, two slots), and the rules have
 * been evaluated. Only a third distinct vote, and a conflicting PROPOSAL, are
 * evidence alone.
 * A height h+1 message that is successfully BUFFERED also returns 0. */
int  tm_core_on_message(tm_core_t *c, const dna_cmsg_t *m, uint64_t now_ms);
int  tm_core_on_tick(tm_core_t *c, uint64_t now_ms);   /* OnTimeout* for EVERY expired timer */

/* Replay (D-8, full WAL): emit is suppressed, no timer is armed, valid() is
 * still asked. The WAL-correct sequence is
 *   create -> replay_begin -> start_height -> replay_message/replay_timeout* ->
 *   replay_end(now)
 * so that the StartRound(0) performed by start_height emits nothing either.
 *
 * Which callbacks run, decided in design §5.9 (2026-09-08):
 *   - EVERY OUTWARD ANNOUNCEMENT is suppressed, not just emit: on_round_start
 *     and on_equivocation would otherwise re-announce history the host already
 *     acted on. The equivocation COUNTER is still rebuilt.
 *   - decide IS called. A node that crashed between "the core decided" and
 *     "the host persisted the block" has to be told; committing a block the
 *     host already holds is idempotent, whereas losing the decision is not
 *     recoverable from the log.
 *   - get_value is NOT called while replaying. The WAL carries this node's own
 *     PROPOSAL record, and asking the host for a value again could manufacture
 *     a different block than the one it already signed.
 *
 * G4 ACROSS A RESTART, also design §5.9: a replayed PREVOTE/PRECOMMIT whose
 * sender is THIS node is AUTHORITATIVE — it restores last_prevote_* /
 * last_precommit_* and, at the current round, raises step to at least that
 * step. Without it, a valid() that answers FAULT during replay would leave
 * step at propose, replay_end would arm timeoutPropose, and the timeout would
 * emit a nil PREVOTE for a round this node had already voted in — a second,
 * different vote for one (height, round). Pinned by test_tm_core §O-d. */
void tm_core_replay_begin(tm_core_t *c);
int  tm_core_replay_message(tm_core_t *c, const dna_cmsg_t *m);        /* received AND own messages */
int  tm_core_replay_timeout(tm_core_t *c, uint64_t h, uint32_t round, tm_step_t step);
void tm_core_replay_end(tm_core_t *c, uint64_t now_ms);                /* timers re-armed from `now` per design §5.9 */

/* Observation (host/tests): */
typedef struct tm_snapshot {
    uint64_t height; uint32_t round; tm_step_t step; int decided;
    /* 1 = PERMANENT core fault (design §5.9): an internal failure happened
     * after state had been mutated. Every entry point returns -1 from then on
     * and only destroy works; the HOST halts. FAULT is not a VERDICT — the
     * node stops, it does not decide. */
    int      fault;
    int32_t  locked_round, valid_round;
    uint8_t  locked_id[DNA_CONSENSUS_VALUE_ID_LEN], valid_id[DNA_CONSENSUS_VALUE_ID_LEN];
    uint32_t equivocations;                  /* recorded at this height */
    /* Observation only (the G5 memory tests read these; no rule does). */
    uint32_t rounds_open;                    /* round slots currently allocated */
    size_t   log_value_bytes;                /* PROPOSAL bytes held by this height's log */
    uint32_t h1_entries;  size_t h1_bytes;   /* the h+1 buffer */
    uint8_t  last_prevote_id[DNA_CONSENSUS_VALUE_ID_LEN];   int32_t last_prevote_round;   /* signing.md cross-check */
    uint8_t  last_precommit_id[DNA_CONSENSUS_VALUE_ID_LEN]; int32_t last_precommit_round;
} tm_snapshot_t;
void tm_core_snapshot(const tm_core_t *c, tm_snapshot_t *out);
extern const dna_consensus_ops_t tm_ops;    /* registry entry */

/* ====================================================================== */
/* INTERNAL — shared between the four tendermint C sources.               */
/* Nothing outside nodus/src/bft/tendermint/ may use anything below.      */
/* ====================================================================== */

/* Priority bound (design §6): with DNA weight 1 and n <= 128 the accumulated
 * priority never leaves +/-(3n+1), so CometBFT's safeAddClip saturation is
 * UNREACHABLE. Rather than clip — which would silently change the proposer
 * sequence — the module REFUSES: any step that would take |A| past this bound
 * returns -1. test_tm_proposer §G pins that the bound is never approached. */
#define TM_PRIO_ABS_BOUND  ((int64_t)1 << 40)

/* tm_eval's fixpoint guard (design §5.8). Each firing advances a monotone
 * quantity (step / round / a first-time flag / decided), and rule 55 can carry
 * the round forward by at most `round_lookahead`, so the loop is finite. If it
 * is not, that is a core defect and the entry point returns -1 rather than
 * spinning. */
#define TM_EVAL_MAX_ITERATIONS  4096u

/* valid() memo states (design §5.5). */
typedef enum { TM_VALID_UNKNOWN = 0, TM_VALID_YES = 1, TM_VALID_NO = 2 } tm_valid_memo_t;

/* tm_log_put_* results. */
#define TM_PUT_LOGGED   0
#define TM_PUT_DUP      1
#define TM_PUT_EQUIV    2
#define TM_PUT_ERR    (-1)

/* TWO SLOTS PER SENDER per (round, type) — design §5.4, the 2026-09-08
 * revision. Slot 0 is the FIRST value this sender was seen voting for and is
 * the one reported to the host as "first" when the second arrives. A second,
 * DIFFERENT value is evidence AND is counted toward its own value's threshold;
 * a third distinct value is evidence only and is not stored.
 *
 * Counting stays a count of DISTINCT SENDERS: a sender contributes at most 1
 * to any one value, and repeats of a value already in a slot are duplicates.
 * The safety argument for holding two, and the liveness failure that one slot
 * caused, are written out in tm_log.c's header. */
#define TM_VOTE_SLOTS 2

typedef struct tm_vote {
    uint8_t n;                    /* slots used: 0, 1 or 2 */
    uint8_t value_id[TM_VOTE_SLOTS][DNA_CONSENSUS_VALUE_ID_LEN];
} tm_vote_t;

/* One round slot of one height's log (design §5.4). Opened on demand. */
typedef struct tm_round {
    uint8_t    prop_have;
    uint8_t    prop_dropped;      /* value bytes reclaimed by the byte cap */
    uint8_t    prop_valid_memo;   /* tm_valid_memo_t */
    int32_t    prop_valid_round;
    uint8_t    prop_value_id[DNA_CONSENSUS_VALUE_ID_LEN];
    uint8_t   *prop_value;        /* owned by the log */
    size_t     prop_value_len;
    uint32_t   prop_sender;       /* index in the governing set */
    tm_vote_t *prevote;           /* n slots, indexed by set position */
    tm_vote_t *precommit;         /* n slots, indexed by set position */
    uint32_t   n_prevote, n_precommit;
    uint8_t   *seen;              /* n bytes: this sender contributed ANY message at this round (line 55) */
    uint32_t   n_seen;
    uint8_t    l34_fired, l36_fired, l47_fired;   /* Algorithm 1 "for the first time" */
    /* proposer(h, round), computed ONCE when the slot is opened (design §5.6,
     * red-team F6): the walk is O(round x n) and re-running it per message is
     * a free CPU amplifier for anyone who can send messages. */
    uint32_t   proposer_idx;
    uint8_t    proposer_known;
} tm_round_t;

typedef struct tm_log {
    uint64_t     height;
    uint32_t     n;
    tm_round_t **rounds;          /* indexed BY ROUND NUMBER; NULL = not opened */
    uint32_t     rounds_cap;
    uint32_t     rounds_end;      /* highest opened round + 1 */
    size_t       value_bytes;     /* PROPOSAL value bytes currently held */
    size_t       max_bytes;       /* the HEIGHT budget (params.max_height_log_bytes) */
} tm_log_t;

void        tm_log_init(tm_log_t *log, uint64_t height, uint32_t n, size_t max_bytes);
void        tm_log_clear(tm_log_t *log);
tm_round_t *tm_log_round(tm_log_t *log, uint32_t round, int create);
/* Make room for `need` more PROPOSAL value bytes on behalf of `writing_round`,
 * with `current_round` = round_p. Reclaim order is a SECURITY property
 * (design §5.6, red-team F1 and round-2 F3), not an optimisation:
 *   - writing_round >= current_round + 2: reclaim NOTHING. Nobody honest is
 *     proposing that far ahead, so the only writer there is an adversary.
 *   - writing_round == current_round + 1: reclaim PAST rounds only
 *     (r < current_round), oldest first. The next round's honest proposer
 *     enters its round first and its proposal can arrive before this node's
 *     timeout, so it must be able to make room — but never from the round
 *     this node is voting in.
 *   - writing_round <= current_round: FUTURE rounds first, highest downward;
 *     then PAST rounds (r < writing_round), oldest upward. Never the writing
 *     round itself.
 * 0 = it fits, -1 = it cannot. */
int         tm_log_reserve(tm_log_t *log, size_t need,
                           uint32_t writing_round, uint32_t current_round);
int         tm_log_put_proposal(tm_log_t *log, uint32_t round, uint32_t sender_idx,
                                const uint8_t value_id[DNA_CONSENSUS_VALUE_ID_LEN],
                                int32_t valid_round, const uint8_t *value, size_t len,
                                uint32_t current_round,
                                uint8_t first_id[DNA_CONSENSUS_VALUE_ID_LEN], int32_t *first_vr);
/* Returns TM_PUT_LOGGED for the sender's FIRST value at this (round, type);
 * TM_PUT_DUP for a value already in one of its slots (nothing changes);
 * TM_PUT_EQUIV for any further DISTINCT value. TM_PUT_EQUIV is NOT "ignored":
 * the SECOND distinct value is stored and counted for its own value, only the
 * THIRD and beyond are evidence alone (design §5.4). A caller that sees
 * TM_PUT_EQUIV must therefore re-evaluate the rules — a threshold may have
 * just been crossed. `first_id`, when non-NULL, receives slot 0 on both the
 * DUP and the EQUIV path and is untouched on the LOGGED path. */
int         tm_log_put_vote(tm_log_t *log, uint32_t round, uint32_t sender_idx, int is_precommit,
                            const uint8_t value_id[DNA_CONSENSUS_VALUE_ID_LEN],
                            uint8_t first_id[DNA_CONSENSUS_VALUE_ID_LEN]);
/* Counts DISTINCT SENDERS holding a vote for `value_id` — a sender with two
 * slots contributes 1 to each of its two values and never 2 to one.
 * value_id == NULL is Algorithm 1's "*": senders with ANY vote here. */
uint32_t    tm_log_count_votes(const tm_round_t *r, uint32_t n, int is_precommit,
                               const uint8_t *value_id);

/* Timers (design §7). One pending slot per step, indexed by tm_step_t. */
typedef struct tm_timer {
    uint8_t  armed;
    uint64_t height;
    uint32_t round;
    uint64_t deadline_ms;
} tm_timer_t;
typedef struct tm_timers { tm_timer_t slot[3]; } tm_timers_t;

uint64_t tm_timeout_ms(const tm_params_t *p, tm_step_t step, uint32_t round);
/* now + timeout, SATURATING at UINT64_MAX. `now` is whatever the host's clock
 * says, so the sum can wrap — and a wrapped deadline compares as already
 * expired, which turns the timer it belongs to into an immediate fire. */
uint64_t tm_deadline_ms(uint64_t now_ms, uint64_t timeout_ms);
void     tm_timers_reset(tm_timers_t *t);
void     tm_timers_schedule(tm_timers_t *t, tm_step_t step, uint64_t h, uint32_t r, uint64_t deadline_ms);
/* Takes the first expired slot in the fixed order PROPOSE, PREVOTE, PRECOMMIT,
 * disarming it BEFORE it is reported. 1 = one was taken, 0 = none. */
int      tm_timers_take_expired(tm_timers_t *t, uint64_t now_ms,
                                tm_step_t *step, uint64_t *h, uint32_t *r);

/* Proposer helpers used by the core. */
int tm_proposer_clone(const tm_proposer_t *p, tm_proposer_t **out);
int tm_proposer_index_at(const tm_proposer_t *p, uint32_t round, uint32_t *out_idx);
int tm_proposer_set_equals(const tm_proposer_t *p, const dna_vset_t *set);

#endif
