/**
 * @file faucet_core.h
 * @brief nodus-faucet core: the decision rule, the claim API the HTTP layer
 *        calls, and the worker that drives claims through the settlement
 *        state machine.
 *
 * Governing records: docs/plans/decisions/2026-10-22-testnet-test-tokens-
 * faucet-dex.md (operator rules, quoted in nodus/docs/FAUCET.md) and docs/
 * plans/2026-10-22-testnet-faucet-design.md section 6 (rev 2), which is
 * THE spec for this file.
 *
 * DETERMINISM / SCOPE: nothing here is consensus. The clock appears only in
 * the status cache and the HTTP timeouts. Every decision is a function of
 * ONE tip's node reads and the journal; nothing is decided while a claim is
 * open (it resumes).
 */
#ifndef FAUCET_CORE_H
#define FAUCET_CORE_H

#include <stdatomic.h>
#include <stdint.h>

#include "nodus/nodus_types.h"
#include "nodus/nodus_v2_spend.h"
#include "faucet_cfg.h"
#include "faucet_journal.h"
#include "faucet_node.h"

/* ── decision (design 6.1) ──────────────────────────────────────────── */

typedef enum {
    FD_FULL = 0,       /* the address owns a name                           */
    FD_START,          /* no name, native total == 0                        */
    FD_NOT_EMPTY,      /* no name and native total > 0                      */
    FD_UNREADABLE      /* a read failed, or the two reads never agreed on a
                        * height — NOT a verdict about the address          */
} faucet_verdict_kind_t;

typedef struct {
    faucet_verdict_kind_t kind;
    char                  name[37];       /* FD_FULL                        */
    uint64_t              height;         /* the common committed height    */
} faucet_verdict_t;

/** Read name_of and the native balance of `address_hex` and decide.
 *  The two answers must come from the SAME committed height (name "ch" ==
 *  balance "tip"); a mismatch re-reads, at most FAUCET_DECIDE_TRIES times,
 *  then FD_UNREADABLE. An error is never a zero: a failed read is
 *  FD_UNREADABLE. `native_zero` = the all-zero token id. */
#define FAUCET_DECIDE_TRIES 3
int faucet_decide(const faucet_node_t *node, const char *address_hex,
                  faucet_verdict_t *out);

/* ── the service object ─────────────────────────────────────────────── */

typedef struct faucet_core {
    const faucet_cfg_t   *cfg;
    const faucet_node_t  *node;
    faucet_journal_t     *journal;
    const uint8_t        *pk;           /* the faucet's ML-DSA-87 key       */
    const uint8_t        *sk;
    char                  self_hex[129];/* its address (owner of its coins) */
    nodus_v2_rand_fn      rand;         /* output seeds + claim ids         */
    void                 *rand_ctx;
    atomic_int            chain_ok;     /* 1 = the node's chain id matched  */
    /* status cache (HTTP thread only) */
    uint64_t              status_at_ms;
    int                   status_valid;
    uint64_t              status_native, status_token;
} faucet_core_t;

/** Wire a core together. self_hex is derived from pk (SHA3-512). */
int faucet_core_init(faucet_core_t *c, const faucet_cfg_t *cfg,
                     const faucet_node_t *node, faucet_journal_t *journal,
                     const uint8_t *pk, const uint8_t *sk,
                     nodus_v2_rand_fn rand, void *rand_ctx);

/** Compare the node's chain id with the configured one and set chain_ok.
 *  @return 1 match, 0 mismatch or unreadable (chain_ok = 0). */
int faucet_core_check_chain(faucet_core_t *c);

/* ── API (HTTP handler side: decide + journal + answer) ─────────────── */

typedef struct {
    int  http;                       /* 200, 400, 404, 503                  */
    char claim_id[33];
    char state[FJ_STATE_MAX];        /* the build plan's state names        */
    char kind[FJ_KIND_MAX];          /* "full" | "start" | "none"           */
    char message[FJ_MSG_MAX];
} faucet_answer_t;

/** POST /faucet/claim. `address_hex` already validated as 128 lowercase hex
 *  by the HTTP layer; this function does not trust that. */
void faucet_api_claim(faucet_core_t *c, const char *address_hex,
                      faucet_answer_t *ans);
/** GET /faucet/claim/<claim_id>. */
void faucet_api_get_claim(faucet_core_t *c, const char *claim_id,
                          faucet_answer_t *ans);

typedef struct {
    int      open;
    int      paused;
    uint64_t full_left;
    uint64_t start_left;
    char     message[FJ_MSG_MAX];
} faucet_status_t;

/** GET /faucet/status. Capacity is read from the faucet's own balance at
 *  the fee ceiling; the NODUS pool is shared by FULL and START. */
void faucet_api_status(faucet_core_t *c, faucet_status_t *out);

/* ── worker (one claim in flight) ───────────────────────────────────── */

/** Drive the oldest open claim one step (plan+sign, submit, scan,
 *  settle). @return 1 a claim was worked on, 0 nothing to do, -1 a fault
 *  that stopped the step (state unchanged; logged). */
int faucet_worker_step(faucet_core_t *c);

/** The fixed answer for "no claim": 32 zero hex characters. */
#define FAUCET_NO_CLAIM_ID "00000000000000000000000000000000"

#endif /* FAUCET_CORE_H */
