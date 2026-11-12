/**
 * @file amm_cfg.h
 * @brief nodus-amm settings: one key = value file, strict.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 15 "Settings" (givens item 26: all numbers adjustable; item 36:
 * the Foundation edits the file and restarts the bot) and section 9 (the
 * provider list and quorum are settings, givens items 17, 58). The format
 * follows tools/faucet/faucet_cfg.h: an unknown key, a duplicate key, a
 * malformed value, a value out of its bounds or a missing required key
 * refuses the WHOLE file ("a value out of bounds refuses the start", plan
 * section 15, OIF solver-config precedent).
 *
 * KEYS (units: USDT raw = 10^-6 USDT, NODUS raw = 10^-8 NODUS, plan section
 * 5; amounts are written as raw integers):
 *
 *   key                        required  default            bounds / source
 *   eth_conf_bound_1_usdt      no        100000000          1.., < eth_conf_bound_2_usdt (givens 60)
 *   eth_conf_bound_2_usdt      no        1000000000         1.., > eth_conf_bound_1_usdt (givens 60)
 *   eth_conf_count_1           no        3                  1..100 (givens 60; OIF
 *                                                           min_confirmations 1..100, plan s.15)
 *   eth_conf_count_2           no        5                  1..100, >= eth_conf_count_1
 *   eth_conf_count_3           no        33                 1..100, >= eth_conf_count_2
 *   swap_max_usdt             no        100000000          > 0, <= inflight_max_usdt (givens 19)
 *   inflight_max_usdt          no        500000000          > 0 (givens 19)
 *   pool_start_usdt            no        3000000000         > 0 (givens 20)
 *   pool_start_nodus           no        3000000000000000   > 0 (givens 20)
 *   liquidity_wait_eth_blocks  no        300                >= 1 (givens 25)
 *   liquidity_wait_nodus_blocks no       3                  >= 1 (givens 49)
 *   liquidity_min_nodus        no        10000000000000     > 0 (givens 96, plan s.15: the smallest NODUS
 *                                                           side of a liquidity add, 100,000 NODUS =
 *                                                           10^13 raw; refused below it at the add question)
 *   swaps_paused               no        0                  0 | 1 (plan s.16, "off")
 *   liquidity_paused           no        0                  0 | 1
 *   payouts_paused             no        0                  0 | 1
 *   usdt_contract              no        0xdAC17F95...1ec7  40 lowercase hex (plan s.5)
 *   eth_providers              YES       (deferred, s.15)   1..AMM_MAX_PROVIDERS https URLs, comma separated
 *   eth_quorum                 YES       (deferred, s.15)   1..number of providers (see below)
 *   eth_reorg_window_blocks    YES       (deferred, s.9/15) >= eth_conf_count_3, the largest count (see below)
 *   approval_valid_seconds     no        300                1.. (givens 72, operator 2026-11-10 "2 ok":
 *                                                           the bot's approval is valid 5 minutes;
 *                                                           was "deferred, > 0")
 *   eth_chain_id               no        1                  1.. The domain chainId of the Ethereum-key
 *                                                           typed requests (plan s.6.1, 6.4.3). Ethereum
 *                                                           mainnet is 1; the test phase runs on Sepolia,
 *                                                           11155111, written in the settings file
 *                                                           (givens 77, operator 2026-11-10 "Tamam, o
 *                                                           sekilde olsun. Test alaninda olsun.")
 *   quote_open_max             no        2000               1.. (givens 98, operator "c"; item 26). The most
 *                                                           open unpaid questions (approved swap rows with no
 *                                                           payment seen, approved or signed liquidity adds
 *                                                           with no deposit matched); at it a new price or
 *                                                           liquidity question is answered "busy". 2000 is
 *                                                           main's proposal; the operator did not name a number.
 *   quote_read_fresh_ms        no        3000               1.. Milliseconds a question's provider reads (the
 *                                                           bot's USDT balance, gas estimate and gas price) and
 *                                                           Nodus balance read are reused by the next question
 *                                                           (monotonic clock, question path only). A
 *                                                           proposal of this build; no decision names a value.
 *   round_rows_max             no        1000               1.. Rows of one list (open approved swaps, the
 *                                                           liquidity adds) examined per worker round; the walk
 *                                                           resumes after the last row in the next round. A
 *                                                           proposal of this build; no decision names a value.
 *   commission                 no        0                  0 only. The plan's key (s.15 table, givens 23).
 *                                                           A setting, value 0 now (givens 73, operator
 *                                                           2026-11-10 "3 ok (bu settings te olmali)").
 *                                                           Its shape and rate stay DEFERRED (plan s.12,
 *                                                           s.15) and no commission code is built until
 *                                                           the shape is decided (plan s.12), so a value
 *                                                           other than 0 has no meaning and refuses the
 *                                                           start (s.15: "a value out of bounds refuses
 *                                                           the start"). Nothing reads it yet.
 *   payout_final_depth_eth     YES       (deferred, s.15)   >= 1
 *   http_max_body              YES       (deferred, s.15)   > 0
 *   http_max_response          YES       (deferred, s.15)   > 0 (bounds the bot's OWN HTTP answers only)
 *   eth_max_response           no        4194304            1024..16777216 Bytes: the bound of one Ethereum
 *                                                           provider JSON-RPC answer (the provider client's own
 *                                                           limits AMM_RPC_RESP_MIN..AMM_RPC_RESP_CEIL). Measured
 *                                                           non-hydrated block answers reach 35,955 bytes
 *                                                           (Sepolia) and 35,772 (mainnet), so the HTTP answer
 *                                                           bound does not fit. A proposal of this build; no
 *                                                           decision names a value (givens 26).
 *   swap_min_usdt              no        1000000            1.., <= swap_max_usdt (givens 89: no swap below
 *                                                           1 USDT on its USDT side; refused at the price question)
 *   eth_price_sources          no        all four           comma separated names from kraken, binance,
 *                                                           bitfinex, coinbase (plan s.10, s.15; Boltz
 *                                                           DataAggregator.ts:10-15); each listed once
 *   eth_price_min_sources      no        3                  1..number of listed sources (givens 74)
 *   eth_price_max_age_seconds  no        180                1.. (givens 74)
 *   (replaces the old single required key eth_price_source)
 *   log_dir                    no        (empty: no file)   absolute path (starts with '/'), at most 200
 *                                                           bytes. The bot writes a timestamped log file,
 *                                                           <log_dir>/nodus-amm.log, besides
 *                                                           the console (operator 2026-11-11 "log DOSYASI!",
 *                                                           givens item 106).
 *   Service keys with no plan line, so REQUIRED and without a default
 *   (nothing is invented): http_port 1..65535, http_conn_cap 1..64,
 *   http_timeout_ms >= 1, worker_interval_ms >= 1, rpc_timeout_ms >= 1,
 *   eth_start_height >= 1, nodus_start_height >= 1, eth_max_scan_blocks >= 1,
 *   nodus_page_limit 1..100, nodus_max_pages >= 1,
 *   nodus_expiry_ahead 1..NODUS_CMT_APP_MAX_EXPIRY_AHEAD (100),
 *   nodus_resubmit_blocks >= 1, nodus_scan_blocks >= 1, eth_key_path (a
 *   file of 64 hex digits, the bot's secp256k1 key), nodus_key_dir (the bot's
 *   Nodus identity directory), lock_path (the single-instance lock file).
 *   eip712_name                YES       (deferred, s.15)   printable ASCII, 1..AMM_STR_MAX-1
 *   expected_origin            YES       (deferred, s.15)   printable ASCII, 1..AMM_STR_MAX-1
 *   held_keeps_room            YES       (deferred, plan    0 | 1: whether a swap in state held
 *                                         l.312, l.407)     keeps its in-flight room; no default,
 *                                                           the plan decides nothing
 *   foundation_eth             YES       (deployment, s.15) 40 lowercase hex (Ethereum address)
 *   foundation_nodus           YES       (deployment, s.15) 128 lowercase hex (Nodus address)
 *   node_host, node_port, node_fp, chain_id, journal_path
 *                              YES       (plan s.11: the bot trusts its own node with
 *                                         pinned identity as the faucet does; s.17 journal)
 *
 * A DEFERRED value has no default here: the plan decides none ("DEFERRED =
 * not decided, not built"), so the Foundation must write it and a file
 * without it refuses the start. READING (reported in the dispatch result):
 * "required" is how a value the plan leaves open is carried without a
 * number invented in code.
 *
 * Bounds that rest on no plan line and are therefore kept to what the rest
 * of the plan already makes structural:
 *   eth_quorum >= 1 and <= the number of providers: "at least Q distinct
 *     providers returned an identical record" (section 9) cannot hold with
 *     Q = 0 (nothing agreed) or Q above N (never reached). The plan writes
 *     NO lower bound beyond this (section 9, "No lower bound on Q is
 *     written here"); the value stays the Foundation's.
 *   eth_reorg_window_blocks >= eth_conf_count_3: the depth rule (section
 *     9) needs the block hashes of the confirmation depth; counts never
 *     decrease, so the third is the largest.
 *
 * The Ethereum confirmation depth is chosen by the payment's USDT amount
 * (givens item 60, operator 2026-11-10 "100 $ kadar 3 1000$ a kadar 5 +1000$
 * = 33", plan section 9 "Depth", section 15 row eth_confirmations): an
 * amount up to and including bound 1 waits count 1, up to and including
 * bound 2 waits count 2, above bound 2 waits count 3 (PLAN READING: "kadar"
 * includes the bound; Across takes the first threshold >= the amount,
 * Relayer.ts:363-367). Load check (plan section 15): bounds strictly
 * ascending (Across RelayerConfig.ts:340-346), counts not decreasing
 * (:374-384), each count 1..100. The key names are this implementation's:
 * the plan names the row "eth_confirmations" and gives no key names.
 *   every u64 setting <= UINT64_MAX/4 (the faucet's "implausibly large"
 *     rule) so sums of settings cannot wrap.
 *
 * NOT here: bot_key_share (its representation is not in the plan), listen port and key
 * directory (amm_http and signing are outside this package).
 */
#ifndef AMM_CFG_H
#define AMM_CFG_H

#include <stdint.h>
#include <stddef.h>

#define AMM_PATH_MAX       256
#define AMM_URL_MAX        200
#define AMM_STR_MAX        128
#define AMM_LOG_DIR_MAX    200    /* longest log_dir value, in bytes       */
#define AMM_MAX_PROVIDERS  16     /* storage size of the provider list     */

/* ETH price sources (plan section 10): the bit of each name in
 * amm_cfg_t.eth_price_sources. */
#define AMM_PRICE_KRAKEN   1u
#define AMM_PRICE_BINANCE  2u
#define AMM_PRICE_BITFINEX 4u
#define AMM_PRICE_COINBASE 8u
#define AMM_PRICE_ALL      15u

typedef struct {
    char     node_host[64];
    uint16_t node_port;
    uint8_t  node_fp[64];
    uint8_t  chain_id[32];                     /* the Nodus chain           */
    char     journal_path[AMM_PATH_MAX];

    char     eth_providers[AMM_MAX_PROVIDERS][AMM_URL_MAX];
    int      n_providers;
    int      eth_quorum;
    uint8_t  foundation_eth[20];
    char     foundation_nodus[129];
    uint8_t  usdt_contract[20];

    uint64_t eth_conf_bound_1_usdt;            /* USDT raw, 10^-6           */
    uint64_t eth_conf_bound_2_usdt;
    uint64_t eth_conf_count_1;                 /* amount <= bound 1         */
    uint64_t eth_conf_count_2;                 /* amount <= bound 2         */
    uint64_t eth_conf_count_3;                 /* amount above bound 2      */
    uint64_t swap_max_usdt;
    uint64_t inflight_max_usdt;
    uint64_t pool_start_usdt;
    uint64_t pool_start_nodus;
    uint64_t liquidity_wait_eth_blocks;
    uint64_t liquidity_wait_nodus_blocks;
    uint64_t liquidity_min_nodus;              /* default 10^13 raw (givens 96) */
    uint64_t eth_reorg_window_blocks;
    uint64_t approval_valid_seconds;           /* default 300 (givens 72)   */
    uint64_t eth_chain_id;                     /* default 1 (givens 77)     */
    uint64_t quote_open_max;                   /* default 2000 (givens 98)  */
    uint64_t quote_read_fresh_ms;              /* default 3000              */
    uint64_t round_rows_max;                   /* default 1000              */
    uint64_t commission;                       /* 0 only (givens 73, s.12)  */
    uint64_t payout_final_depth_eth;
    uint64_t http_max_body;
    uint64_t http_max_response;
    uint64_t eth_max_response;                 /* default 4194304           */
    uint64_t swap_min_usdt;                    /* default 1000000 (givens 89) */
    uint64_t eth_price_min_sources;            /* default 3 (givens 74)     */
    uint64_t eth_price_max_age_seconds;        /* default 180 (givens 74)   */
    unsigned eth_price_sources;                /* AMM_PRICE_* bit mask      */
    uint64_t http_port, http_conn_cap, http_timeout_ms, worker_interval_ms,
             rpc_timeout_ms, eth_start_height, nodus_start_height,
             eth_max_scan_blocks, nodus_page_limit, nodus_max_pages,
             nodus_expiry_ahead, nodus_resubmit_blocks, nodus_scan_blocks;
    char     eth_key_path[AMM_PATH_MAX];
    char     nodus_key_dir[AMM_PATH_MAX];
    char     lock_path[AMM_PATH_MAX];
    char     log_dir[AMM_PATH_MAX];            /* optional; "" = no log file */
    char     eip712_name[AMM_STR_MAX];
    char     expected_origin[AMM_STR_MAX];

    int      swaps_paused;
    int      liquidity_paused;
    int      payouts_paused;
    int      held_keeps_room;                  /* required, 0 | 1           */
} amm_cfg_t;

/** Fill `cfg` with the plan's values (required fields stay zero). */
void amm_cfg_defaults(amm_cfg_t *cfg);

/** Parse the text of a settings file. On refusal `err` (may be NULL) holds
 *  the reason and `cfg` must not be used. @return 0 / -1. */
int amm_cfg_parse(const char *text, amm_cfg_t *cfg, char *err, size_t err_cap);

/** Read and parse a file (size bounded to 16 KiB). @return 0 / -1. */
int amm_cfg_load(const char *path, amm_cfg_t *cfg, char *err, size_t err_cap);

/** Write every setting's value to the log, one line per setting (operator order
 *  2026-11-12: full diagnostic log). Secrets and URLs are not written: the key
 *  paths and the provider list print as "set" / a count, the pinned node
 *  fingerprint as its first 16 hex digits. Call it once the log file is open. */
void amm_cfg_log(const amm_cfg_t *cfg);

#endif /* AMM_CFG_H */
