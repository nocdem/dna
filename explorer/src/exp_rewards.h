/* Read-only, request-scoped view of a co-located Nodus rewards database.
 * No migration, backfill, RPC or consensus changes. The source must contain
 * the explorer's copied anchor block and a complete address-history run
 * through its own current tip. Every query shares one SQLite snapshot.
 */
#ifndef EXP_REWARDS_H
#define EXP_REWARDS_H

#include "exp_db.h"

#define EXP_REWARDS_MAX 100
/* Per request, independent of wall time. Exhaustion returns unavailable. */
#define EXP_REWARDS_VM_BUDGET 2000000

typedef struct exp_rewards exp_rewards_t;

typedef struct {
    uint64_t height;
    uint64_t time_ms;
    uint64_t amount;
    uint32_t sequence;
    uint8_t owner[64];
} exp_payout_t;

typedef struct {
    uint64_t total;
    uint64_t recipients; /* matching row count (payouts or releases) */
    uint64_t pending;
    int count;
    int has_next;
    uint32_t next_from;
    exp_payout_t rows[EXP_REWARDS_MAX];
} exp_rewards_page_t;

/* 0 success, -1 unavailable. out stays NULL on failure. Source is opened
 * SQLITE_OPEN_READONLY, never immutable; path must be a plain filename.
 * A source tip ahead of anchor is allowed; behind/mismatched is refused. */
int exp_rewards_open(const char *path, const exp_block_row_t *anchor,
                     exp_rewards_t **out);
void exp_rewards_close(exp_rewards_t *r); /* rollback read txn; NULL-safe */
uint64_t exp_rewards_from_height(const exp_rewards_t *r);
uint64_t exp_rewards_at_height(const exp_rewards_t *r);

/* Whole-height total plus sequence-ascending page; from is inclusive.
 * limit 0 reads only the total/count. height must be inside source coverage.
 * next_from is the first unshown row's sequence (gaps are legal). */
int exp_rewards_payday(exp_rewards_t *r, uint64_t height, uint32_t from,
                       int limit, exp_rewards_page_t *out);
/* The same contract over kind='release' rows (graduation bond and
 * delegation releases, one kind on the node). Payout and release rows
 * share one (height, boundary position) sequence space, so each kind's
 * sequences have gaps. out->recipients is the release row count; pending
 * stays 0. Returned stake, never a reward: payday totals exclude it. */
int exp_rewards_releases(exp_rewards_t *r, uint64_t height, uint32_t from,
                         int limit, exp_rewards_page_t *out);
/* Total paid within coverage (NOT balance), current pending and a page
 * ordered by (height,sequence) descending. before is exclusive; (0,0)
 * means newest. Cursor never changes total/pending. */
int exp_rewards_address(exp_rewards_t *r, const uint8_t owner[64],
                        uint64_t before_h, uint32_t before_seq, int limit,
                        exp_rewards_page_t *out);
/* Total released to owner within coverage and a page of release rows,
 * same ordering and cursor as exp_rewards_address. No accrual read:
 * pending stays 0. */
int exp_rewards_address_releases(exp_rewards_t *r, const uint8_t owner[64],
                                 uint64_t before_h, uint32_t before_seq,
                                 int limit, exp_rewards_page_t *out);

#endif
