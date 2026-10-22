/**
 * @file faucet_node.h
 * @brief The faucet's node interface: every call the service makes to its
 *        LOCAL node sits behind this small table, so the decision rule, the
 *        claim state machine and the HTTP API are tested against a stub and
 *        run in production against faucet_node_real.c (nodus_client_*).
 *
 * Governing records: docs/plans/2026-10-22-testnet-faucet-design.md section
 * 6 and the operator's "Kendi düğümüne güvensin" (the faucet trusts its
 * local node, identity pinned; an unreadable answer is never a zero).
 *
 * Return convention (all calls): FAUCET_NODE_OK with the out-parameters
 * valid; anything else leaves the out-parameters UNDEFINED and the caller
 * must treat the fact as UNKNOWN — never as zero, never as "not found".
 */
#ifndef FAUCET_NODE_H
#define FAUCET_NODE_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"

typedef enum {
    FAUCET_NODE_OK         = 0,
    FAUCET_NODE_ERR        = -1,   /* no answer / transport / malformed    */
    FAUCET_NODE_NOT_HELD   = -2,   /* scan_block: the node does not hold
                                    * that committed height (pruned)       */
    FAUCET_NODE_INCOMPLETE = -3    /* coins: the list is truncated, or the
                                    * node ignored the token filter        */
} faucet_node_rc_t;

/** The node lists at most NODUS_DNAC_MAX_UTXO_RESULTS (100) coins. */
#define FAUCET_COINS_MAX  100

typedef struct {
    uint8_t  nul[64];
    uint64_t amount;
    uint64_t unlock_block;
} faucet_coin_t;

typedef struct {
    faucet_coin_t c[FAUCET_COINS_MAX];
    int           n;
    uint64_t      tip;          /* committed height of the listing        */
} faucet_coin_list_t;

typedef struct {
    void *ctx;

    /** The node's 32-byte derived chain id. */
    int (*chain_id32)(void *ctx, uint8_t out[32]);

    /** dnac_ruleset_info: tip, generation tuple. */
    int (*ruleset_info)(void *ctx, nodus_dnac_ruleset_info_t *out);

    /** dnac_fee_info gas_price at tip + 1. */
    int (*gas_price)(void *ctx, uint64_t *out);

    /** dnac_name_of(owner). found + name, and the committed height the
     *  answer is from. */
    int (*name_of)(void *ctx, const char *owner_hex,
                   nodus_dnac_name_result_t *out);

    /** dnac_balance(owner) reduced to ONE token (all-zero = native):
     *  the node's tip of the answer and that token's TOTAL (0 only when
     *  the answer is valid and holds no row of the token). */
    int (*balance)(void *ctx, const char *owner_hex, const uint8_t token[64],
                   uint64_t *tip_out, uint64_t *total_out);

    /** The faucet's OWN coins of one token (dnac_utxo with "tok"). */
    int (*coins)(void *ctx, const uint8_t token[64], faucet_coin_list_t *out);

    /** Walk ALL pages of committed block `height` and report whether an
     *  APPLIED item (code 0) carries `intent_id`. Only a complete walk
     *  returns FAUCET_NODE_OK; a block the node does not hold returns
     *  FAUCET_NODE_NOT_HELD; a failed page is FAUCET_NODE_ERR. */
    int (*scan_block)(void *ctx, uint64_t height, const uint8_t intent_id[64],
                      int *found_out);

    /** Submit signed bytes. 0 = the node took them into its mempool,
     *  1 = the node answered with a refusal (text in msg), -1 = no answer.
     *  NO result moves a claim state (design section 6.4). */
    int (*submit)(void *ctx, const uint8_t wire_id[64], const uint8_t *env,
                  size_t len, char *msg, size_t msg_cap);
} faucet_node_t;

#endif /* FAUCET_NODE_H */
