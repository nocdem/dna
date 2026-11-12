/**
 * @file amm_eth.h
 * @brief nodus-amm's Ethereum read seam: every call the bot makes to ONE
 *        Ethereum JSON-RPC provider sits behind this table, so the watcher
 *        (amm_eth_watch) and the payer (amm_eth_pay) are tested against stub
 *        providers. The real transport is amm_eth_rpc (package 3: libcurl,
 *        plan section 3 / givens item 40).
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

/* The Ethereum chain id is the setting eth_chain_id (givens item 77: Sepolia
 * 11155111 in the test phase, mainnet 1 later); amm_eth_watch and amm_eth_pay
 * take it in their configuration. There is no constant. */
#define AMM_ETH_MAX_PROVIDERS   16
/** The most logs one provider may return for one block; more is AMM_ETH_ERR
 *  (a list is never cut). */
#define AMM_ETH_LOGS_MAX        256
/** The logs of one receipt that the table keeps (a USDT transfer carries one
 *  or two: TetherToken.sol:123-134). */
#define AMM_ETH_RCPT_LOGS       8

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
    /** keccak256 of the WHOLE data field (receipt.yaml:32-34: `bytes` of any
     *  length), so that two answers whose logs differ only after the first 32
     *  bytes are different logs. */
    uint8_t  data_digest[32];
} amm_eth_log_t;

/** eth_getTransactionReceipt (transaction.yaml:127): only what the watcher
 *  reads. NOT_FOUND = the provider has no receipt. */
typedef struct {
    int      status;           /* 1 = success, anything else = failed      */
    uint64_t block_number;
    uint8_t  block_hash[32];
    /* The receipt's logs (receipt.yaml:101-105, Log: receipt.yaml:1-40), for
     * the payer's Transfer-log check (plan line 264). Every log of the answer
     * is validated like an eth_getLogs log; the first AMM_ETH_RCPT_LOGS are
     * kept in order, `logs_total` is the number the receipt carries. The
     * watcher ignores them. */
    int      n_logs;
    int      logs_total;
    amm_eth_log_t logs[AMM_ETH_RCPT_LOGS];
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
    /** eth_getLogs for ONE block, by the block's HASH (the "Filter by block
     *  hash" form, execution-apis filter.yaml:40-59: blockHash, address,
     *  topics), filtered by contract, topic0 and the recipient topic by the
     *  adapter; a provider that does not hold the block of that hash answers
     *  with an error (go-ethereum v1.17.8 eth/filters/filter.go:83-97), which
     *  is AMM_ETH_ERR, never an empty list. `block` (the height) stays for the
     *  per-log check: every log must carry that number AND that hash. The
     *  watcher re-checks every field (a provider's filter is not trusted).
     *  `cap` is AMM_ETH_LOGS_MAX; a provider holding more must return
     *  AMM_ETH_ERR. */
    int (*get_logs)(void *ctx, uint64_t block, const uint8_t block_hash[32],
                    const uint8_t contract[20],
                    const uint8_t topic0[32], const uint8_t to[20],
                    amm_eth_log_t *out, int cap, int *n, uint64_t deadline_ms);
    /** eth_getTransactionByHash. */
    int (*get_tx)(void *ctx, const uint8_t hash[32], amm_eth_tx_t *out,
                  uint64_t deadline_ms);
    /** eth_getTransactionReceipt. */
    int (*get_receipt)(void *ctx, const uint8_t hash[32],
                       amm_eth_receipt_t *out, uint64_t deadline_ms);

    /* ── PAYOUT calls (package 3, plan section 10). The watcher never calls
     * them and does not check them; amm_eth_pay refuses a provider that
     * leaves one NULL. Same return convention as above, except that none of
     * them has a NOT_FOUND answer: a `null` result of any of them is
     * AMM_ETH_ERR. A JSON-RPC error object (including estimateGas
     * "execution reverted", execute.yaml:27-30) is AMM_ETH_ERR too: the payer
     * reads every ERR as UNKNOWN. ── */

    /** eth_getBalance (state.yaml:1), block `latest`: the ether balance in
     *  wei, 32-byte big-endian. */
    int (*get_balance)(void *ctx, const uint8_t addr[20], uint8_t out[32],
                       uint64_t deadline_ms);
    /** eth_call (execute.yaml:1) of ERC-20 `balanceOf(address)` on `token`
     *  (erc-20.md:85-90), block `latest`: the 32-byte word the contract
     *  returned. */
    int (*erc20_balance)(void *ctx, const uint8_t token[20],
                         const uint8_t owner[20], uint8_t out[32],
                         uint64_t deadline_ms);
    /** eth_getTransactionCount (state.yaml:109), block `pending` (pending !=
     *  0) or `latest` (pending == 0): the account's nonce. */
    int (*tx_count)(void *ctx, const uint8_t addr[20], int pending,
                    uint64_t *out, uint64_t deadline_ms);
    /** eth_estimateGas (execute.yaml:43) of a call from `from` to `to` with
     *  call data `input`, no value, no fee fields. */
    int (*estimate_gas)(void *ctx, const uint8_t from[20], const uint8_t to[20],
                        const uint8_t *input, size_t input_len, uint64_t *out,
                        uint64_t deadline_ms);
    /** eth_gasPrice (fee_market.yaml:1), wei per gas. */
    int (*gas_price)(void *ctx, uint64_t *out, uint64_t deadline_ms);
    /** eth_maxPriorityFeePerGas (fee_market.yaml:43), wei per gas. */
    int (*max_priority_fee)(void *ctx, uint64_t *out, uint64_t deadline_ms);
    /** eth_sendRawTransaction (submit.yaml:32): the provider's answer is the
     *  transaction hash it computed; the adapter returns it in `hash_out`. */
    int (*send_raw)(void *ctx, const uint8_t *raw, size_t raw_len,
                    uint8_t hash_out[32], uint64_t deadline_ms);
} amm_eth_provider_t;

/** The ETH price seam (plan section 10, givens items 34, 50): the bot reads
 *  the ETH price from a source, to turn the ether it spends on one USDT
 *  payout into the USDT it deducts from that payout. WHICH SOURCE, its
 *  address, its price format, the gas figure converted and the integer
 *  conversion are DEFERRED (plan section 10, section 15 `eth_price_source`),
 *  so the seam is the conversion itself and decides none of them: the caller
 *  hands over what the transaction will carry (gas limit, max fee per gas)
 *  and the adapter answers the USDT raw amount (10^-6 USDT) the user pays.
 *  AMM_ETH_OK with `*usdt_raw` valid, or AMM_ETH_ERR: a price that cannot be
 *  read is UNKNOWN, never zero (plan section 4 boundary rule); the payer then
 *  signs nothing. The real adapter is amm_price.{h,c} (plan section 10,
 *  revision 10: at least 3 of the listed tickers, each answer at most 180 s
 *  old, the median; the conversion and its rounding are stated there). What the
 *  quote stands for -- a ceiling (gas limit x max fee), an expected cost or
 *  another gas figure -- is part of the DEFERRED "gas figure converted and the
 *  integer conversion" (plan line 271) and is not decided here. */
typedef struct {
    void *ctx;
    int (*fee_usdt)(void *ctx, uint64_t gas_limit, uint64_t max_fee_per_gas,
                    uint64_t *usdt_raw, uint64_t deadline_ms);
} amm_eth_price_t;

#endif /* AMM_ETH_H */
