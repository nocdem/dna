/**
 * @file amm_eth_rpc.h
 * @brief nodus-amm's real Ethereum provider: JSON-RPC over HTTPS behind the
 *        amm_eth.h seam table (ONE provider per object; the watcher and the
 *        payer hold several and apply their quorum).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 3 (the HTTPS library is chosen in the build package: system
 * libcurl, found with pkg-config -- orchestrator's decision recorded in
 * tasks/orchestration.md, givens item 40), section 4 boundary rule ("a failed
 * read is unknown, never zero or not found"), section 9 (providers), section
 * 10 (payout reads and the broadcast), section 2 "Pinned for this revision"
 * (the method list).
 *
 * METHOD SHAPES (execution-apis 3284ee80; each call cites its own):
 *   eth_chainId                 src/eth/client.yaml:1
 *   eth_blockNumber             src/eth/client.yaml:60
 *   eth_getBlockByNumber        src/eth/block.yaml:63   (hydrated = false)
 *   eth_getLogs                 src/eth/filter.yaml:151, filter schema
 *                               src/schemas/filter.yaml:40-59 (Filter by block hash)
 *   eth_getTransactionByHash    src/eth/transaction.yaml:1
 *   eth_getTransactionReceipt   src/eth/transaction.yaml:127
 *   eth_call                    src/eth/execute.yaml:1  (balanceOf)
 *   eth_estimateGas             src/eth/execute.yaml:43
 *   eth_getBalance              src/eth/state.yaml:1
 *   eth_getTransactionCount     src/eth/state.yaml:109
 *   eth_sendRawTransaction      src/eth/submit.yaml:32
 *   eth_gasPrice                src/eth/fee_market.yaml:1
 *   eth_maxPriorityFeePerGas    src/eth/fee_market.yaml:43
 * Value formats: src/schemas/base-types.yaml -- `uint` ^0x(0|[1-9a-f][0-9a-f]*)$
 * (:59-62), `bytes` ^0x[0-9a-f]*$ (:14-17), `hash32` ^0x[0-9a-f]{64}$ (:79-82),
 * `address` ^0x[0-9a-fA-F]{40}$ (:1-4), `notFound` null (:83-85). Object
 * fields: block.yaml:1-80 (Block), receipt.yaml:1-40 (Log), :40-140
 * (ReceiptInfo), transaction.yaml:487-517 (TransactionInfo), :519-548
 * (GenericTransaction: `input`), filter.yaml:13-60 (Filter), block.yaml:213-222
 * (BlockTag).
 *
 * THE MAPPING OF AN ANSWER (the rule of plan section 4):
 *   - `null` is AMM_ETH_NOT_FOUND ONLY for the three calls whose schema is
 *     oneOf [notFound, ...] and whose seam says so: get_block, get_tx,
 *     get_receipt. For every other call a `null` is AMM_ETH_ERR.
 *   - EVERY other failure is AMM_ETH_ERR: transport failure, HTTP status
 *     other than 200, a timeout, a response above the size bound, a body
 *     that is not strict JSON, a JSON-RPC `error` object (including
 *     "execution reverted", execute.yaml:27-30), a missing `result`, an `id`
 *     that is not the request's, an unknown top-level key, a value that does
 *     not match its schema pattern (leading zeros, upper-case hex, wrong
 *     length), a number above its integer type, an object that names another
 *     block or transaction than the one asked for, a list above the cap.
 *     Nothing is ever turned into zero, an empty list or "not found".
 *
 * THE JSON PARSER is strict and bounded (faucet_http.h strictness): an
 * object or an array, depth <= AMM_RPC_JSON_DEPTH, at most AMM_RPC_JSON_NODES
 * values, strings only of printable ASCII without escapes (a response that
 * carries an escape -- an error text with one, say -- is refused, which is
 * ERR as an error object is anyway), integers only (no fraction, no
 * exponent, <= 15 digits), no duplicate key in an object, no trailing byte.
 *
 * BOUNDS: the response size is bounded by the caller's `max_response`
 * (plan section 15 names no setting for it: DEFERRED, the caller supplies
 * it, no default is chosen here; 1 KiB .. 16 MiB); the transport enforces it
 * while receiving (a body that would pass it is dropped at once, headers are
 * not trusted) and the mapper checks it again. Each call carries the
 * caller's absolute deadline_ms (amm_eth.h); the curl transport also has its
 * own timeout cap, a required argument with no default.
 *
 * TLS: the curl transport sets CURLOPT_SSL_VERIFYPEER = 1 and
 * CURLOPT_SSL_VERIFYHOST = 2 explicitly (peer and host verification stay ON),
 * allows the https protocol only (no http, no redirect is followed) and
 * refuses a URL that does not start with "https://".
 *
 * SECRETS: a provider URL usually carries an API key; it is never logged.
 */
#ifndef AMM_ETH_RPC_H
#define AMM_ETH_RPC_H

#include <stdint.h>
#include <stddef.h>

#include "amm_eth.h"

#define AMM_RPC_JSON_DEPTH   8
#define AMM_RPC_JSON_NODES   65536
#define AMM_RPC_RESP_MIN     1024u
#define AMM_RPC_RESP_CEIL    (16u * 1024u * 1024u)
#define AMM_RPC_NAME_MAX     32

/** The HTTP POST under the provider: the injection point of the tests.
 *  POST `body` to `url` with Content-Type application/json; AMM_ETH_OK only
 *  when the HTTP status is 200 and the whole response (<= resp_cap bytes) was
 *  received into `resp` (`*resp_len`); anything else is AMM_ETH_ERR (a
 *  response that would pass resp_cap included). `deadline_ms` as in
 *  amm_eth.h. */
typedef int (*amm_rpc_post_fn)(void *ctx, const char *url, const uint8_t *body,
                               size_t body_len, uint8_t *resp, size_t resp_cap,
                               size_t *resp_len, uint64_t deadline_ms);

typedef struct {
    const char     *url;          /* "https://..." (copied)                  */
    const char     *name;         /* label for logs, never the URL (copied)  */
    amm_rpc_post_fn post;
    void           *post_ctx;
    size_t          max_response; /* AMM_RPC_RESP_MIN .. AMM_RPC_RESP_CEIL   */
} amm_eth_rpc_cfg_t;

typedef struct amm_eth_rpc amm_eth_rpc_t;

/** NULL on a bad config (no post, a URL that is not https://, longer than
 *  AMM_URL_MAX - 1, or holding a byte outside 0x21..0x7e, a bound outside its
 *  range). */
amm_eth_rpc_t *amm_eth_rpc_new(const amm_eth_rpc_cfg_t *cfg);
void amm_eth_rpc_free(amm_eth_rpc_t *r);

/** Fill the seam table: every function of amm_eth_provider_t, ctx = `r`.
 *  `r` must outlive the table. */
void amm_eth_rpc_provider(amm_eth_rpc_t *r, amm_eth_provider_t *out);

/* ── the libcurl transport ────────────────────────────────────────────── */

typedef struct amm_rpc_curl amm_rpc_curl_t;

/** curl_global_init, once; call it before any other thread starts (libcurl:
 *  not thread-safe). 0 / -1. */
int amm_rpc_curl_global_init(void);
/** `timeout_cap_ms` is the longest one POST may take whatever the deadline
 *  (> 0, required, no default). NULL on a bad argument. */
amm_rpc_curl_t *amm_rpc_curl_new(uint32_t timeout_cap_ms);
void amm_rpc_curl_free(amm_rpc_curl_t *c);
/** The amm_rpc_post_fn of the libcurl transport; `ctx` is an amm_rpc_curl_t. */
int amm_rpc_curl_post(void *ctx, const char *url, const uint8_t *body,
                      size_t body_len, uint8_t *resp, size_t resp_cap,
                      size_t *resp_len, uint64_t deadline_ms);

#endif /* AMM_ETH_RPC_H */
