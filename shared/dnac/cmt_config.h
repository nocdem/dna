/**
 * @file shared/dnac/cmt_config.h
 * @brief cometbft @709fd12b `config/config.go`'s ConsensusConfig in C.
 *
 * ═══ ACTIVATION: INACTIVE ═══════════════════════════════════════════════
 * Wave R2-B of the cometbft → C consensus port. Nothing in the running
 * chain reads anything here yet; additive only.
 * ════════════════════════════════════════════════════════════════════════
 *
 * The timeouts the consensus state machine waits on, and the five helpers
 * that turn them into a per-round duration. Every duration is an
 * `int64_t` count of NANOSECONDS, which is exactly what Go's
 * `time.Duration` is, so the arithmetic below is the reference's without a
 * unit conversion anywhere.
 *
 * ── WHAT IS PORTED, AND WHAT IS NOT ────────────────────────────────────
 * PORTED: the fields the consensus core reads (config.go:979-1014, minus
 * the three path fields), `DefaultConsensusConfig` (:1017-1034),
 * `WaitForTxs` (:1054-1057), `Propose` (:1059-1064), `Prevote`
 * (:1066-1071), `Precommit` (:1073-1078) and `Commit` (:1080-1084).
 *
 * taşınmadı, with the reason:
 *   · `RootDir`, `WalPath`, `walFile` (:980-982), `WalFile` (:1086-1092)
 *     and `SetWalFile` (:1094-1097) — a file path and the accessors for
 *     it. This port's WAL is SQLite rows written by the host (D-15), so
 *     there is no wal file and nothing to root.
 *   · `ValidateBasic` (:1099-…) — the bounds check the TOML loader runs.
 *     Configuration arrives here from the host, not from a config file.
 *   · `TestConsensusConfig` (:1036-1052) — the reference's own test
 *     fixture. The R2 tests run on `cmt_config_default`'s values, which is
 *     the honest thing to state: they exercise the arithmetic at the
 *     REFERENCE DEFAULTS and prove nothing about any other setting.
 *
 * ── THE CHAIN OVERRIDES TWO OF THESE AT R3 ─────────────────────────────
 * `create_empty_blocks_interval` becomes 60 000 ms and `timeout_commit`
 * becomes the chain-config block interval, per D-4
 * (atlas-dec-d5ddcba654eb48d861c03a0ecd170718: "blocks follow the block
 * interval when there is demand and a 60 s idle interval when there is
 * none"). That wiring is R3's; the defaults below are the reference's,
 * copied from the pinned file and not from anybody's memory.
 *
 * ── DETERMINISM ────────────────────────────────────────────────────────
 * Every function here is a pure function of its arguments. No clock is
 * read: `cmt_config_commit` takes the time to add to, exactly as the
 * reference's `Commit(t time.Time)` does.
 *
 * ⚠ These durations are a LOCAL scheduling policy, not consensus state.
 * Two nodes with different timeouts still agree on every block; they only
 * wait differently. The one value that IS shared — the block interval —
 * comes from the chain config at R3, not from this file.
 *
 * Reference @709fd12b: config/config.go, 1283 lines, SHA-256
 * f0c2f601d49e1a56b36e8d557387e96ee53ecc3616ecb79749b0f71c0f218c21;
 * only :965-1100 was opened.
 * Governing records: umbrella rev 3 (atlas-dec-d5e766defde138eb6dd02e5b81e735a8),
 * D-4 (atlas-dec-d5ddcba654eb48d861c03a0ecd170718),
 * clock POLICY (atlas-dec-4ac0423068085c100fdfa3e264ca16bc).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_CONFIG_H
#define SHARED_DNAC_CMT_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

#include "cmt_tmhash.h"   /* CMT_OK / CMT_REJECT / CMT_FAULT */
#include "cmt_time.h"     /* cmt_time_t                      */

#ifdef __cplusplus
extern "C" {
#endif

/** One millisecond in nanoseconds — Go's `time.Millisecond`. */
#define CMT_MILLISECOND ((int64_t)1000000)
/** One second in nanoseconds — Go's `time.Second`. */
#define CMT_SECOND      ((int64_t)1000000000)

/**
 * cometbft@709fd12b config/config.go:979-1014 — `type ConsensusConfig`.
 *
 * The path fields of :980-982 are not here (see the header). Every
 * `time.Duration` is a nanosecond count.
 */
typedef struct {
    int64_t timeout_propose;                /* :985  */
    int64_t timeout_propose_delta;          /* :987  */
    int64_t timeout_prevote;                /* :989  */
    int64_t timeout_prevote_delta;          /* :991  */
    int64_t timeout_precommit;              /* :993  */
    int64_t timeout_precommit_delta;        /* :995  */
    int64_t timeout_commit;                 /* :1000 */
    bool    skip_timeout_commit;            /* :1003 */
    bool    create_empty_blocks;            /* :1006 */
    int64_t create_empty_blocks_interval;   /* :1007 */
    int64_t peer_gossip_sleep_duration;     /* :1010 */
    int64_t peer_query_maj23_sleep_duration;/* :1011 */
    int64_t double_sign_check_height;       /* :1013 */
} cmt_config_t;

/**
 * cometbft@709fd12b config/config.go:1017-1034 —
 * `DefaultConsensusConfig()`. Every value is the one at the cited line.
 * @return CMT_OK, CMT_FAULT on NULL.
 */
static inline int cmt_config_default(cmt_config_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    out->timeout_propose                 = 3000 * CMT_MILLISECOND; /* :1020 */
    out->timeout_propose_delta           =  500 * CMT_MILLISECOND; /* :1021 */
    out->timeout_prevote                 = 1000 * CMT_MILLISECOND; /* :1022 */
    out->timeout_prevote_delta           =  500 * CMT_MILLISECOND; /* :1023 */
    out->timeout_precommit               = 1000 * CMT_MILLISECOND; /* :1024 */
    out->timeout_precommit_delta         =  500 * CMT_MILLISECOND; /* :1025 */
    out->timeout_commit                  = 1000 * CMT_MILLISECOND; /* :1026 */
    out->skip_timeout_commit             = false;                  /* :1027 */
    out->create_empty_blocks             = true;                   /* :1028 */
    out->create_empty_blocks_interval    = 0 * CMT_SECOND;         /* :1029 */
    out->peer_gossip_sleep_duration      =  100 * CMT_MILLISECOND; /* :1030 */
    out->peer_query_maj23_sleep_duration = 2000 * CMT_MILLISECOND; /* :1031 */
    out->double_sign_check_height        = (int64_t)0;             /* :1032 */
    return CMT_OK;
}

/** cometbft@709fd12b config/config.go:1054-1057 —
 *  `(cfg *ConsensusConfig) WaitForTxs()`. */
static inline bool cmt_config_wait_for_txs(const cmt_config_t *cfg)
{
    if (cfg == NULL) {
        return false;
    }
    return !cfg->create_empty_blocks ||
           cfg->create_empty_blocks_interval > 0;              /* :1056 */
}

/**
 * cometbft@709fd12b config/config.go:1059-1064 —
 * `(cfg *ConsensusConfig) Propose(round)`.
 *
 * `timeout + delta*round`, in nanoseconds. Go's int64 arithmetic WRAPS on
 * overflow; the products and sums below are formed in unsigned arithmetic
 * for that reason, because signed overflow is undefined in C and the
 * reference has no guard of its own here. The value is identical wherever
 * the reference is itself well defined.
 */
static inline int64_t cmt_config_propose(const cmt_config_t *cfg,
                                         int32_t round)
{
    uint64_t acc;

    if (cfg == NULL) {
        return 0;
    }
    acc = (uint64_t)cfg->timeout_propose_delta * (uint64_t)(int64_t)round;
    acc += (uint64_t)cfg->timeout_propose;
    return (int64_t)acc;                                       /* :1061-1063 */
}

/** cometbft@709fd12b config/config.go:1066-1071 —
 *  `(cfg *ConsensusConfig) Prevote(round)`. */
static inline int64_t cmt_config_prevote(const cmt_config_t *cfg,
                                         int32_t round)
{
    uint64_t acc;

    if (cfg == NULL) {
        return 0;
    }
    acc = (uint64_t)cfg->timeout_prevote_delta * (uint64_t)(int64_t)round;
    acc += (uint64_t)cfg->timeout_prevote;
    return (int64_t)acc;                                       /* :1068-1070 */
}

/** cometbft@709fd12b config/config.go:1073-1078 —
 *  `(cfg *ConsensusConfig) Precommit(round)`. */
static inline int64_t cmt_config_precommit(const cmt_config_t *cfg,
                                           int32_t round)
{
    uint64_t acc;

    if (cfg == NULL) {
        return 0;
    }
    acc = (uint64_t)cfg->timeout_precommit_delta * (uint64_t)(int64_t)round;
    acc += (uint64_t)cfg->timeout_precommit;
    return (int64_t)acc;                                       /* :1075-1077 */
}

/**
 * cometbft@709fd12b config/config.go:1080-1084 —
 * `(cfg *ConsensusConfig) Commit(t)`. `t.Add(cfg.TimeoutCommit)`.
 *
 * Go's `Time.Add` carries nanoseconds into seconds; the same normalisation
 * is written out here, because a `cmt_time_t` keeps `nanos` in [0, 1e9) by
 * the contract of cmt_time.h. NO CLOCK IS READ — `t` is the caller's, as
 * the reference's receiver argument is.
 *
 * @return CMT_OK; CMT_REJECT if the result leaves the valid Timestamp
 *         range (cmt_time_validate); CMT_FAULT on NULL.
 */
static inline int cmt_config_commit(const cmt_config_t *cfg, cmt_time_t t,
                                    cmt_time_t *out)
{
    int64_t  add_secs;
    int64_t  add_nanos;
    uint64_t secs;
    int64_t  nanos;

    if (cfg == NULL || out == NULL) {
        return CMT_FAULT;
    }
    add_secs  = cfg->timeout_commit / CMT_SECOND;
    add_nanos = cfg->timeout_commit % CMT_SECOND;

    secs  = (uint64_t)t.seconds + (uint64_t)add_secs;
    nanos = (int64_t)t.nanos + add_nanos;
    if (nanos >= (int64_t)CMT_TIME_NANOS_PER_SECOND) {
        nanos -= (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  += 1u;
    } else if (nanos < 0) {
        nanos += (int64_t)CMT_TIME_NANOS_PER_SECOND;
        secs  -= 1u;
    }
    out->seconds = (int64_t)secs;
    out->nanos   = (int32_t)nanos;
    return cmt_time_validate(*out);
}

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_CONFIG_H */
