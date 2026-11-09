/**
 * @file amm_node.h
 * @brief nodus-amm's Nodus seam: every call the bot makes to its LOCAL node
 *        sits behind this table, so the engine is tested against a stub and
 *        run in production against an adapter (not in this package).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 11 (Nodus observation and payout), section 4 ("every call to a
 * chain goes through a seam table; a failed read is unknown, never zero or
 * not found"), section 3 (faucet pattern). Modelled on tools/faucet/
 * faucet_node.h; the faucet is not edited.
 *
 * Return convention (all calls): AMM_NODE_OK with the out-parameters valid;
 * anything else leaves them UNDEFINED and the caller must treat the fact as
 * UNKNOWN -- never as zero, never as "not found".
 *
 * DEADLINES: every call takes `deadline_ms`, an ABSOLUTE CLOCK_MONOTONIC time
 * in milliseconds (amm_now_ms below); 0 = no deadline (faucet_node.h).
 *
 * Calls and the plan lines they serve:
 *   chain_id32     the chain the bot serves (section 11, faucet precedent)
 *   ruleset_info   tip and rule-set tuple (the node's committed height)
 *   balance        a token total of one owner (section 12: balance of the
 *                  bot's Nodus key before approving)
 *   coins          the bot's own coins of one token (section 11)
 *   addr_history   dnac_addr_history pages of the bot's own address:
 *                  incoming `spend_in` rows with peer, amount, token, wire
 *                  id, block time `ts` (section 11, section 8 step 6,
 *                  nodus.h:2360-2410). `enabled` and `from_height` of the
 *                  answer are what the bot checks at start (section 11:
 *                  index on, from_height at or below its start height).
 *   scan_block     settlement: does an applied item of committed block
 *                  `height` carry `intent_id` (section 11, faucet table)
 *   submit         submit signed bytes; no result moves a state
 *                  (faucet_node.h, plan section 11 "the same signed bytes
 *                  resubmitted")
 */
#ifndef AMM_NODE_H
#define AMM_NODE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

typedef enum {
    AMM_NODE_OK         = 0,
    AMM_NODE_ERR        = -1,   /* no answer / transport / malformed /
                                 * deadline passed                          */
    AMM_NODE_NOT_HELD   = -2,   /* scan_block: the node does not hold that
                                 * committed height (pruned)                */
    AMM_NODE_INCOMPLETE = -3    /* coins: the node ignored the token filter */
} amm_node_rc_t;

#define AMM_NODE_NO_DEADLINE 0

/** The single monotonic millisecond clock for deadlines. Scheduling only. */
static inline uint64_t amm_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/** The node lists at most NODUS_DNAC_MAX_UTXO_RESULTS (100) coins. */
#define AMM_COINS_MAX  100

typedef struct {
    uint8_t  nul[64];
    uint64_t amount;
    uint64_t unlock_block;
} amm_coin_t;

typedef struct {
    amm_coin_t c[AMM_COINS_MAX];
    int        n;
    int        truncated;   /* 1 = the listing filled the node's cap; the
                             * listed coins are the LARGEST (faucet_node.h) */
    uint64_t   tip;         /* committed height of the listing              */
} amm_coin_list_t;

typedef struct {
    void *ctx;

    /** The node's 32-byte derived chain id. */
    int (*chain_id32)(void *ctx, uint8_t out[32], uint64_t deadline_ms);

    /** dnac_ruleset_info: tip, generation tuple. */
    int (*ruleset_info)(void *ctx, nodus_dnac_ruleset_info_t *out,
                        uint64_t deadline_ms);

    /** dnac_balance(owner) reduced to ONE token (all-zero = native): the
     *  node's tip of the answer and that token's TOTAL (0 only when the
     *  answer is valid and holds no row of the token). */
    int (*balance)(void *ctx, const char *owner_hex, const uint8_t token[64],
                   uint64_t *tip_out, uint64_t *total_out,
                   uint64_t deadline_ms);

    /** The bot's OWN coins of one token. */
    int (*coins)(void *ctx, const uint8_t token[64], amm_coin_list_t *out,
                 uint64_t deadline_ms);

    /** One dnac_addr_history page of the session owner (the bot's own
     *  address), newest first; `before` NULL = from the newest. The result's
     *  entries are heap and are released with `addr_history_free`. */
    int (*addr_history)(void *ctx, unsigned limit,
                        const nodus_dnac_addr_history_cursor_t *before,
                        nodus_dnac_addr_history_result_t *out,
                        uint64_t deadline_ms);
    void (*addr_history_free)(void *ctx,
                              nodus_dnac_addr_history_result_t *result);

    /** Walk ALL pages of committed block `height` and report whether an
     *  APPLIED item carries `intent_id`; resumable exactly as
     *  faucet_node_t.scan_block (`*from_io`, `*found_io`): only a complete
     *  walk returns AMM_NODE_OK; an incomplete walk is never "not found". */
    int (*scan_block)(void *ctx, uint64_t height, const uint8_t intent_id[64],
                      uint32_t *from_io, int *found_io, uint64_t deadline_ms);

    /** Submit signed bytes. 0 = the node took them into its mempool, 1 = the
     *  node answered with a refusal (text in msg), -1 = no answer. NO result
     *  moves a state. */
    int (*submit)(void *ctx, const uint8_t wire_id[64], const uint8_t *env,
                  size_t len, char *msg, size_t msg_cap, uint64_t deadline_ms);
} amm_node_t;

#endif /* AMM_NODE_H */
