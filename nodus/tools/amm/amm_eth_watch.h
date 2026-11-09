/**
 * @file amm_eth_watch.h
 * @brief nodus-amm Ethereum observation: USDT payments to the Foundation
 *        address, seen through several providers with a quorum, kept in the
 *        journal with their block hashes, followed through reorganisations.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 9 (all of it), section 7 (what counts, matching, "Only direct
 * transfer from the signer counts"), section 13 (window rule), section 17
 * (restart from stored cursors), givens items 17, 22, 54, 55, 58.
 *
 * WHAT A STEP DOES (amm_eth_watch_step; all reads through the seam table of
 * amm_eth.h, all state in the journal, no clock read, no randomness):
 *  1. Providers: a provider is USED in a step only when it reports chain id
 *     1 (plan section 9; a failed or different answer excludes it for the
 *     step). Fewer usable providers than the quorum Q: nothing is read
 *     further, nothing changes (AMM_W_UNKNOWN).
 *  2. Tip: the tip is the largest value T such that at least Q providers
 *     report a latest block >= T (the Q-th largest reported value, so the
 *     result does not depend on provider order) -- "at least Q providers
 *     report ... a tip at least 3 above it" (section 9, INFERENCE composed
 *     from the quorum rule and the depth rule).
 *  3. Scan, block by block from the stored cursor `eth_scan` (the first
 *     start: the caller's start_height): a block is accepted when at least Q
 *     usable providers return an IDENTICAL header (number, hash, parent hash,
 *     timestamp) and no other header also reaches Q; otherwise the scan
 *     stops (unknown), nothing is written for that block.
 *  4. Reorganisation (plan section 9, THORChain processReorg/reprocessTxs):
 *     an accepted block whose parent hash differs from the stored hash of the
 *     block below it. The changed heights are found by re-reading the
 *     quorum header downward until a stored hash matches (not below the
 *     retained window); EVERY stored record within the retained window --
 *     seen, deep and held alike (a record a swap has counted or paid
 *     included) -- is looked up again by transaction hash:
 *       found at the quorum in the same block -> kept;
 *       found at the quorum in ANOTHER block -> moved: the quorum's ACTUAL
 *         log of the transaction in the new block is read (sender, value,
 *         log index) and the record takes it, state seen (the depth starts
 *         again); a changed value or sender is not the recorded payment: it
 *         is treated as gone (below) and the new record is stored, matching
 *         no approval at the old amount (plan lines 225, 251: held);
 *       no receipt, or a receipt with status != 1, at the quorum -> gone:
 *         amm_journal_payment_gone (a payment waiting for its depth is unpaid
 *         again and its record dropped; a counted or paid payment is a
 *         confirmed reversal: record and swap `reversed`, `reversal_pause`
 *         set, givens item 55);
 *       anything else -> unknown: the WHOLE reorganisation write is
 *         abandoned and retried, nothing is written.
 *     All writes of one reorganisation (stored blocks above the common
 *     ancestor removed, cursor moved back to rescan them, record changes,
 *     the reversal and its pause) are ONE journal transaction decided from
 *     reads made BEFORE it: a stop between decision and write leaves the old
 *     state, the same mismatch is found after the restart (plan section 19:
 *     "also across a restart between detection and the journal write").
 *     A reversal deeper than the retained window is not detected (the stated
 *     limit, section 9; window = eth_reorg_window_blocks).
 *  5. Logs of an accepted block (eth_getLogs, one block): a log is considered
 *     only when its emitter is the USDT contract, it has exactly three
 *     topics, topic0 is the ERC-20 Transfer topic (THORChain
 *     direct_erc20_transfer.go:18), the data is 32 bytes, the recipient topic
 *     is the Foundation address, the value is not zero (THORChain skips a
 *     zero amount, direct_erc20_transfer.go:118-123) and the log sits in the
 *     accepted block (number and hash) -- a provider's filter is not trusted.
 *     Identical logs reported by at least Q distinct providers form a QUORUM
 *     record; fewer than Q: a CANDIDATE, kept and evaluated again each step
 *     (Across "No quorum; retain for next time").
 *  6. Verification of a quorum record, per provider: the receipt must be
 *     found, status 1, in the same block; the transaction's sender must be
 *     the log's `from`, its target the USDT contract and its call data must
 *     start with the transfer(address,uint256) selector a9059cbb (THORChain
 *     direct_erc20_transfer.go:105-126, :172-174, shared/evm/utils.go:31-36;
 *     plan section 7 and line 230: only a direct transfer counts, so a
 *     transferFrom the sender authorised to itself is ignored too). At least Q providers must say valid for the
 *     record to be stored (state seen); at least Q saying invalid (failed
 *     receipt, other sender, other target) -> ignored, never stored; any
 *     other mix -> unknown, the block is retried and nothing is written.
 *  7. Each accepted block is ONE journal transaction: the block hash row, its
 *     records, the cursor; a failed read changes no state.
 *  8. Candidates are evaluated again: a candidate that reaches the quorum and
 *     verifies becomes seen; one that at least Q providers answer without is
 *     dropped; its block no longer the accepted one -> dropped.
 *  9. Depth: a `seen` record whose block is at least `confirmations` below
 *     the tip is looked up again (as in step 4) and, still in place, becomes
 *     `deep` only when at least Q providers report BOTH the payment's block
 *     hash (receipt in that block) AND, themselves, a latest block at least
 *     `confirmations` above it (plan line 252: the same Q providers; the Q-th
 *     largest tip of step 2 alone is not enough). Depth 3 for swaps --
 *     givens item 22; a liquidity deposit's 300 is asked with
 *     amm_eth_watch_depth_reached, the same joint vote with its own depth.
 * 10. Blocks below tip - window are pruned; the tip is stored (`eth_tip`).
 *
 * DETERMINISM: the quorum result depends on the multiset of provider answers,
 * not on their order (counts of identical answers, sorted record keys, the
 * Q-th largest tip). Records and groups are processed sorted by (block, tx,
 * log index).
 *
 * NOT HERE (other packages): the matching of a record to an approval is the
 * pure amm_eth_watch_match below (the engine applies it and moves swaps); no
 * transport; no payout.
 */
#ifndef AMM_ETH_WATCH_H
#define AMM_ETH_WATCH_H

#include <stdint.h>
#include <stddef.h>

#include "amm_eth.h"
#include "amm_journal.h"

typedef struct amm_eth_watch amm_eth_watch_t;

typedef struct {
    const amm_eth_provider_t *providers;   /* copied (the table, not ctx)   */
    int      n_providers;                  /* 1..AMM_ETH_MAX_PROVIDERS      */
    int      quorum;                       /* 1..n_providers (setting, s.9) */
    uint8_t  usdt[20];                     /* the USDT contract             */
    uint8_t  foundation[20];               /* the Foundation address        */
    uint64_t confirmations;                /* depth of a swap payment (3)   */
    uint64_t window_blocks;                /* eth_reorg_window_blocks       */
    uint64_t start_height;                 /* first scan height, used only
                                            * while no cursor is stored     */
    uint32_t max_scan_blocks;              /* blocks per step (>= 1)        */
    amm_journal_t *journal;                /* not owned                     */
} amm_eth_watch_cfg_t;

typedef enum {
    AMM_W_OK      = 0,   /* the step ended with nothing unresolved           */
    AMM_W_UNKNOWN = 1,   /* a required read had no quorum / disagreed: state
                          * written so far stays, the rest is retried       */
    AMM_W_ERR     = -1   /* a journal fault or a bad configuration           */
} amm_w_rc_t;

typedef struct {
    int      usable;        /* providers on chain id 1 this step             */
    uint64_t tip;           /* the quorum tip (0 when unknown)               */
    int      blocks;        /* blocks accepted and written                   */
    int      reorgs;        /* reorganisations written                       */
    int      new_records;   /* records stored seen this step                 */
    int      deep;          /* records that became deep                      */
    int      dropped;       /* records dropped (gone while unpaid / stale)   */
    int      reversed;      /* confirmed reversals written                   */
    int      unknown;       /* reads without a quorum                        */
} amm_eth_step_t;

/** Validate the configuration and build a watcher. NULL on a bad config
 *  (quorum or provider count out of range, window below confirmations, a
 *  zero scan bound, a missing journal or provider function). */
amm_eth_watch_t *amm_eth_watch_new(const amm_eth_watch_cfg_t *cfg);
void amm_eth_watch_free(amm_eth_watch_t *w);

/** One observation step (see the list above). `out` may be NULL. */
int amm_eth_watch_step(amm_eth_watch_t *w, uint64_t deadline_ms,
                       amm_eth_step_t *out);

/** The stored tip and scan cursor (0 / 1 none / -1). */
int amm_eth_watch_tip(amm_eth_watch_t *w, uint64_t *tip);

/** Has the record reached depth `min_depth` by the JOINT vote of plan line
 *  252: at least Q providers must report the record's block (a receipt in
 *  that block with that hash) AND, themselves, a latest block at least
 *  `min_depth` above it. A liquidity deposit asks with its own setting
 *  (liquidity_wait_eth_blocks, 300, plan line 328); the global quorum tip is
 *  not used. Reads through the seam (deadline_ms passed through) and writes
 *  nothing. @return 0 (`*reached` = 0 / 1) / 1 (unknown: fewer than Q usable
 *  providers or no quorum answer; `*reached` untouched) / -1. A record whose
 *  transaction moved or vanished is not reached (0). */
int amm_eth_watch_depth_reached(amm_eth_watch_t *w, const amm_rec_t *rec,
                                uint64_t min_depth, uint64_t deadline_ms,
                                int *reached);

typedef enum {
    AMM_M_NONE         = 0,  /* another sender: not this approval's payment    */
    AMM_M_MATCH        = 1,  /* sender, exact amount, block time within the
                              * validity (plan section 7 "Payment matching",
                              * givens item 54)                              */
    AMM_M_HELD_VALUE   = 2,  /* this sender, another logged value: a payment
                              * that matches no approval -> held (section 7) */
    AMM_M_HELD_EXPIRED = 3   /* this sender and amount, block time after the
                              * expiry: matches no approval -> held (item 54) */
} amm_match_t;

/** PURE. Matching of one record to one approval by sender, exact logged
 *  amount (big-endian 32 bytes) and the BLOCK time against the approval's
 *  expiry (never the bot's clock: a payment whose block time is within the
 *  validity follows its approval even when the bot reads it after the expiry
 *  time, givens item 54). */
amm_match_t amm_eth_watch_match(const amm_rec_t *rec, const uint8_t sender[20],
                                const uint8_t amount_be[32],
                                uint64_t expiry_ts);

/** The window rule of plan section 13 / givens item 54 for an Ethereum
 *  payment: 1 = the payment window of an approval (sender, amount, expiry
 *  time) is FULLY OBSERVED, 0 = not yet, -1 = fault. Observed means: the scan
 *  cursor has passed, on the quorum, a stored block whose header timestamp
 *  is later than the expiry, that block is at least `confirmations` below the
 *  stored tip, and no candidate (below-quorum) record with this sender and
 *  amount whose block time is within the validity (<= expiry) or unknown is
 *  still retained (plan lines 314, 319). Block timestamps strictly increase (execution-
 *  specs fork.py:386-387), so no later block can carry an in-window time. The
 *  caller matches records first (a `seen`/`deep` record for the approval is a
 *  payment, not an unpaid window). No clock is read. */
int amm_eth_watch_window_observed(amm_eth_watch_t *w, uint64_t expiry_ts,
                                  const uint8_t sender[20],
                                  const uint8_t amount_be[32]);

#endif /* AMM_ETH_WATCH_H */
