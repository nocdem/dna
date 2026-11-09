/**
 * @file amm_eth.h
 * @brief nodus-amm's Ethereum read seam: every call the bot makes to ONE
 *        Ethereum JSON-RPC provider sits behind this table, so the watcher
 *        (amm_eth_watch) is tested against stub providers. No transport is in
 *        this package: the HTTPS library is DEFERRED to the build package
 *        (plan section 3).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 9 (providers, quorum, depth, reorganisation), section 2 "Pinned"
 * (the JSON-RPC methods each call stands for), section 4 boundary rule
 * ("a failed read is unknown, never zero or not found").
 *
 * RETURN CONVENTION (every call): AMM_ETH_OK with the out-parameters valid;
 * AMM_ETH_NOT_FOUND where the answer is a valid "null" (a block or
 * transaction or receipt the provider does not have) -- a FACT the provider
 * states; anything else (AMM_ETH_ERR: no answer, transport, malformed,
 * deadline passed, more logs than the cap) leaves the out-parameters
 * UNDEFINED and the caller must treat the fact as UNKNOWN, never as zero and
 * never as "not found".
 *
 * DEADLINES: `deadline_ms` is an ABSOLUTE CLOCK_MONOTONIC time in
 * milliseconds, 0 = none (tools/faucet/faucet_node.h). The watcher passes
 * its caller's value through and reads no clock.
 */
#ifndef AMM_ETH_H
#define AMM_ETH_H

#include <stdint.h>
#include <stddef.h>

/** Ethereum mainnet chain id (plan section 9: "each provider must report
 *  chain id 1"; ethereum-lists-chains eip155-1.json:45). */
#define AMM_ETH_CHAIN_ID        1u
#define AMM_ETH_MAX_PROVIDERS   16
/** The most logs one provider may return for one block; more is AMM_ETH_ERR
 *  (a list is never cut). */
#define AMM_ETH_LOGS_MAX        256

typedef enum {
    AMM_ETH_OK         = 0,
    AMM_ETH_ERR        = -1,
    AMM_ETH_NOT_FOUND  = -2
} amm_eth_rc_t;

/** eth_getBlockByNumber (execution-apis block.yaml:63), header fields only. */
typedef struct {
    uint64_t number;
    uint8_t  hash[32];
    uint8_t  parent[32];
    uint64_t timestamp;        /* header timestamp, unix seconds (block.yaml:60) */
} amm_eth_block_t;

/** One log of eth_getLogs (filter.yaml:151): raw topics, as the node
 *  returns them. */
typedef struct {
    uint8_t  address[20];      /* the emitting contract                    */
    int      n_topics;
    uint8_t  topics[4][32];
    uint8_t  data[32];
    int      data_len;
    uint32_t log_index;        /* block-wide log index                     */
    uint8_t  tx[32];
    uint64_t block_number;
    uint8_t  block_hash[32];
} amm_eth_log_t;

/** eth_getTransactionReceipt (transaction.yaml:127): only what the watcher
 *  reads. NOT_FOUND = the provider has no receipt. */
typedef struct {
    int      status;           /* 1 = success, anything else = failed      */
    uint64_t block_number;
    uint8_t  block_hash[32];
} amm_eth_receipt_t;

/** eth_getTransactionByHash (transaction.yaml:1): the sender, the call
 *  target and the start of the call data. The watcher accepts a payment only
 *  when the data starts with the ERC-20 `transfer(address,uint256)` selector
 *  a9059cbb (THORChain HasERC20TransferSelector, shared/evm/utils.go:31-36:
 *  `len(data) >= 4 && data[:4] == selector`; used by
 *  GetTxInFromDirectERC20Transfer, direct_erc20_transfer.go:172-174), so a
 *  transferFrom the sender authorised to itself is not a direct transfer
 *  (plan line 230). */
typedef struct {
    uint8_t  from[20];
    uint8_t  to[20];
    int      has_to;
    uint32_t input_len;        /* length of the whole call data            */
    uint8_t  input_head[4];    /* its first 4 bytes (valid when len >= 4)  */
} amm_eth_tx_t;

typedef struct {
    void *ctx;
    const char *name;          /* for logs only                            */

    /** eth_chainId (client.yaml:1). */
    int (*chain_id)(void *ctx, uint64_t *out, uint64_t deadline_ms);
    /** eth_blockNumber (client.yaml:60): the provider's latest block. */
    int (*block_number)(void *ctx, uint64_t *out, uint64_t deadline_ms);
    /** eth_getBlockByNumber: NOT_FOUND above the provider's tip. */
    int (*get_block)(void *ctx, uint64_t number, amm_eth_block_t *out,
                     uint64_t deadline_ms);
    /** eth_getLogs for ONE block, filtered by contract, topic0 and the
     *  recipient topic by the adapter; the watcher re-checks every field
     *  (a provider's filter is not trusted). `cap` is AMM_ETH_LOGS_MAX; a
     *  provider holding more must return AMM_ETH_ERR. */
    int (*get_logs)(void *ctx, uint64_t block, const uint8_t contract[20],
                    const uint8_t topic0[32], const uint8_t to[20],
                    amm_eth_log_t *out, int cap, int *n, uint64_t deadline_ms);
    /** eth_getTransactionByHash. */
    int (*get_tx)(void *ctx, const uint8_t hash[32], amm_eth_tx_t *out,
                  uint64_t deadline_ms);
    /** eth_getTransactionReceipt. */
    int (*get_receipt)(void *ctx, const uint8_t hash[32],
                       amm_eth_receipt_t *out, uint64_t deadline_ms);
} amm_eth_provider_t;

#endif /* AMM_ETH_H */
