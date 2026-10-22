/**
 * @file faucet_cfg.h
 * @brief nodus-faucet configuration: one key = value file, strict.
 *
 * Governing records: docs/plans/decisions/2026-10-22-testnet-test-tokens-
 * faucet-dex.md (amounts, fee ceiling, storage limit, host) and docs/plans/
 * 2026-10-22-testnet-faucet-design.md section 6. Every default below is the
 * operator's value from that record; nothing here is chain state.
 *
 * Strict: an unknown key, a duplicate key, a malformed value or a missing
 * required key refuses the whole file (the service does not start on a
 * guess). The listen address is NOT configurable — 127.0.0.1 only.
 */
#ifndef FAUCET_CFG_H
#define FAUCET_CFG_H

#include <stdint.h>
#include <stddef.h>

#define FAUCET_PATH_MAX  256

typedef struct {
    char     node_host[64];            /* the LOCAL node (trusted, pinned)   */
    uint16_t node_port;                /* its client port (4001)             */
    uint8_t  node_fp[64];              /* node identity pin, SHA3-512(pk)    */
    uint8_t  chain_id[32];             /* the only chain this faucet serves  */
    char     key_dir[FAUCET_PATH_MAX]; /* the faucet's own identity          */
    char     journal_path[FAUCET_PATH_MAX];
    uint8_t  token_id[64];             /* tUSDT                              */
    uint64_t full_native;              /* default 10^13  (100 000 NODUS)     */
    uint64_t full_token;               /* default 10^8   (100 tUSDT)         */
    uint64_t start_native;             /* default 10^9   (10 NODUS)          */
    uint64_t fee_ceiling;              /* default 10^7   (0.1 NODUS)         */
    uint64_t expiry_ahead;             /* default 90 blocks                  */
    uint16_t listen_port;              /* on 127.0.0.1                       */
    uint64_t storage_ceiling;          /* journal bytes, default 64 MiB      */
    int      queue_cap;                /* open claims, default 64            */
    int      conn_cap;                 /* HTTP connections, default 16       */
    int      request_timeout_ms;       /* per HTTP request, default 5000     */
    int      poll_ms;                  /* worker cycle, default 4000         */
} faucet_cfg_t;

/** Fill `cfg` with the operator's defaults (required fields stay zero). */
void faucet_cfg_defaults(faucet_cfg_t *cfg);

/** Parse the text of a config file. On refusal `err` (may be NULL) holds
 *  the reason. @return 0 / -1. */
int faucet_cfg_parse(const char *text, faucet_cfg_t *cfg, char *err,
                     size_t err_cap);

/** Read and parse a file (size bounded to 16 KiB). @return 0 / -1. */
int faucet_cfg_load(const char *path, faucet_cfg_t *cfg, char *err,
                    size_t err_cap);

/** fsync a directory (its entries become durable). @return 0 / -1 (errno). */
int faucet_fsync_dir(const char *dir);

/** Create the key directory `dir` (0700) if absent, restrict it, and make
 *  its EXISTENCE durable: fsync of `dir` AND of its parent directory (a
 *  directory entry is the parent's data; without it a power loss after the
 *  identity files were fsynced into `dir` can leave the whole directory —
 *  and the address already shown to the operator — gone). The caller writes
 *  nothing into `dir` before this returns 0. @return 0 / -1 (errno set;
 *  nothing is created beyond `dir` itself). */
int faucet_prepare_key_dir(const char *dir);

#endif /* FAUCET_CFG_H */
