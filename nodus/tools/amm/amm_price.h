/**
 * @file amm_price.h
 * @brief nodus-amm ETH price adapter: the real adapter behind the seam
 *        amm_eth_price_t (amm_eth.h). It reads the ETH/USDT price from at
 *        least `eth_price_min_sources` of the listed public tickers, each
 *        answer at most `eth_price_max_age_seconds` old, combined by the
 *        MEDIAN, and turns the ether of one payout into the USDT deducted.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 10)
 * sections 10 (the ETH price paragraph), 15 (rows eth_price_sources,
 * eth_price_min_sources, eth_price_max_age_seconds), 17 (a required fact that
 * cannot be read leaves the swap in its state); givens items 50, 74.
 *
 * SOURCES (Boltz lib/rates/data/DataAggregator.ts:10-15; each address from
 * its exchange file, the pair ETH/USDT built as the file builds it):
 *   kraken    GET https://api.kraken.com/0/public/Ticker?pair=ETHUSDT
 *             (Kraken.ts:12, :16-18); the price is `result.<pair>.c[0]`
 *             (Kraken.ts:21-23)
 *   binance   GET https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT
 *             (Binance.ts:10, :17); `price` (a string, :5-7)
 *   bitfinex  GET https://api.bitfinex.com/v2/ticker/tETHUST (USDT is "UST",
 *             Bitfinex.ts:19-24); element 6 of the list (`data[6]`, :16)
 *   coinbase  GET https://api.exchange.coinbase.com/products/ETH-USDT/ticker
 *             (CoinbasePro.ts:10, :17); `price` (a string)
 * NOT READ (plan section 10): whether each exchange lists the pair under
 * these names today. A source that does not answer in the expected shape is
 * simply not counted.
 *
 * COMBINATION (Boltz DataAggregator.ts:114-124): the fresh answers sorted,
 * the middle one, or for an even count the mean of the two middle ones; here
 * in integers: floor((a + b) / 2). FEWER than eth_price_min_sources fresh
 * answers: the price is UNKNOWN (AMM_ETH_ERR), never zero, never an older
 * value (Boltz keeps the latest rate with no age limit, DataAggregator.ts:
 * 41-44: a stated difference, plan section 0.1). Freshness: an answer counts
 * while now - fetched_at <= max_age; `now` is the monotonic clock in whole
 * seconds (a scheduling clock, node-local, never consensus).
 *
 * SCHEDULE (plan section 10 leaves it to the build package; this is the
 * build's choice, not a plan or operator value): amm_price_poll fetches a
 * source whose last answer is missing or older than max_age / 2 seconds
 * (integer division, at least 1), so every source is read at least once
 * inside max_age with a half-window margin. The worker calls amm_price_poll
 * each cycle; it fetches only the sources that are due.
 *
 * PRICE FORM: USDT raw (10^-6 USDT) per 1 ETH, "price_e6". The decimal text
 * of a source is read strictly (digits, one '.', no sign, no exponent), at
 * most 7 integer digits (below 10,000,000 USDT per ETH) and truncated to 6
 * fraction digits; a zero or malformed price is not an answer.
 *
 * FEE CONVERSION (plan section 10: "the integer conversion ... DEFERRED to
 * the build package": THE BUILD'S CHOICE, reported): the Ethereum cost the
 * payer quotes is gas_limit x max_fee_per_gas in wei (the most the
 * transaction can pay, amm_eth_pay.h); the fee in USDT raw is
 *     ceil(wei * price_e6 / 10^18)
 * rounded UP so that the Foundation, which pays the ether, is never short by
 * truncation, computed in 128 bits; a product that does not fit or a result
 * above 2^64-1 is AMM_ETH_ERR (unknown), never a wrapped value.
 *
 * TRANSPORT SEAM: the HTTPS GET goes through amm_price_get_fn so tests use
 * stubs. The real function (amm_price_curl_get) is libcurl with the exact TLS
 * and protocol options of amm_eth_rpc.c's POST (peer and host verification
 * on, https only, no redirect); amm_eth_rpc.c has no GET and is not edited,
 * so the small GET is its own copy here (reported).
 */
#ifndef AMM_PRICE_H
#define AMM_PRICE_H

#include <stddef.h>
#include <stdint.h>

#include "amm_cfg.h"
#include "amm_eth.h"

/** The HTTPS GET under the sources: AMM_ETH_OK only when the HTTP status is 200
 *  and the whole response (<= resp_cap bytes) was received into `resp`;
 *  anything else is AMM_ETH_ERR. `deadline_ms` is an absolute monotonic time
 *  in ms, 0 = none. */
typedef int (*amm_price_get_fn)(void *ctx, const char *url, uint8_t *resp,
                                size_t resp_cap, size_t *resp_len,
                                uint64_t deadline_ms);

/** Monotonic whole seconds (injected so tests drive time). */
typedef uint64_t (*amm_price_now_fn)(void *ctx);

#define AMM_PRICE_RESP_MAX 8192u   /* one ticker answer; larger is not read */

typedef struct {
    amm_price_get_fn get;
    void            *get_ctx;
    amm_price_now_fn now_s;
    void            *now_ctx;
    unsigned         sources;          /* AMM_PRICE_* mask (amm_cfg.h)       */
    uint64_t         min_sources;      /* 1..number of listed sources        */
    uint64_t         max_age_seconds;  /* >= 1                               */
} amm_price_cfg_t;

typedef struct amm_price amm_price_t;

/** NULL on a bad config (no get or clock, an empty or unknown source mask,
 *  a minimum of 0 or above the listed sources, a zero age). */
amm_price_t *amm_price_new(const amm_price_cfg_t *cfg);
void amm_price_free(amm_price_t *p);

/** The URL of one source bit (AMM_PRICE_KRAKEN ...), NULL for another value. */
const char *amm_price_source_url(unsigned bit);

/** PURE. Read one ticker answer of source `bit` into price_e6. 0 / -1. */
int amm_price_parse(unsigned bit, const char *body, size_t len, uint64_t *price_e6);

/** PURE. Median of `n` values (sorted copy; even count: floor of the mean of
 *  the two middle ones). `n` >= 1. */
uint64_t amm_price_median(const uint64_t *v, int n);

/** THREAD SAFETY: the cache is guarded by an internal mutex, so amm_price_poll
 *  (one thread) and amm_price_get / the seam (quotes, other threads) may run
 *  at once; the network GET is made without the lock.
 *  Fetch every source that is due (see SCHEDULE). A failed fetch keeps the
 *  source's previous answer (it ages out) and changes nothing else.
 *  @return the number of FRESH answers after the call. */
int amm_price_poll(amm_price_t *p, uint64_t deadline_ms);

/** The price now: AMM_ETH_OK with `*price_e6` = the median of the fresh
 *  answers when at least min_sources are fresh, else AMM_ETH_ERR (UNKNOWN). */
int amm_price_get(amm_price_t *p, uint64_t *price_e6);

/** PURE. USDT raw = ceil(gas_limit * max_fee_per_gas * price_e6 / 10^18);
 *  AMM_ETH_ERR on a zero price or an overflow. */
int amm_price_convert(uint64_t gas_limit, uint64_t max_fee_per_gas,
                      uint64_t price_e6, uint64_t *usdt_raw);

/** The amm_eth_price_t seam: ctx = an amm_price_t, `fee_usdt` reads the
 *  cached price (no fetch) and converts. Fill `out` with it. */
void amm_price_seam(amm_price_t *p, amm_eth_price_t *out);

/* ── libcurl GET ─────────────────────────────────────────────────────── */

typedef struct amm_price_curl amm_price_curl_t;
/** `timeout_cap_ms` > 0: the longest one GET may take. curl_global_init is the
 *  caller's (amm_rpc_curl_global_init). NULL on a bad argument. */
amm_price_curl_t *amm_price_curl_new(uint32_t timeout_cap_ms);
void amm_price_curl_free(amm_price_curl_t *c);
/** The amm_price_get_fn of libcurl; `ctx` is an amm_price_curl_t. */
int amm_price_curl_get(void *ctx, const char *url, uint8_t *resp, size_t resp_cap,
                       size_t *resp_len, uint64_t deadline_ms);

#endif /* AMM_PRICE_H */
