/**
 * @file nodus/src/client/nodus_light_provider.h
 * @brief The light client's PINNED provider: cometbft @v0.38.26
 *        `light/provider` (provider.go:9-29, port
 *        shared/dnac/cmt_light_provider.h) implemented over a
 *        `nodus_client_t` and the `dnac_light_block` RPC on 4001.
 *
 * ═══ STATUS: ONE CALLER — the nodus-light program ═══════════════════════
 * Light client package 2's block source (decision docs/plans/decisions/
 * 2026-10-16-dnac-light-block-rpc.md, APPROVED; Kurultay #25,
 * docs/plans/decisions/2026-10-16-kurultay-25-summary.md). Nothing in a
 * node calls it; the one caller is nodus/tools/nodus-light.c (0.26.11). It
 * sits in nodus's COMMON source list so that it compiles on Windows.
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── PINNED ONLY (Kurultay #25 item 8: "never an unpinned provider") ───
 * `nodus_light_provider_init` REFUSES a client whose configuration has no
 * server key pin (`pinned_server_fps` / `pinned_server_fp_count`,
 * nodus.h nodus_client_config_t). A pinned session authenticates the
 * server with ML-DSA-87 and runs ML-KEM-1024 only (nodus_client.c
 * pin_check_auth_ok). `light_block` re-checks the pin on every call.
 *
 * ── THE THREE ROWS ─────────────────────────────────────────────────────
 *  · chain_id — the chain id the provider was CONFIGURED with
 *    (http.go:59-62 `ChainID()` returns the configured value; it is never
 *    read from the server).
 *  · light_block — nodus_client_dnac_light_block, then
 *    cmt_light_block_decode (`lbpb.Unmarshal` + `LightBlockFromProto`)
 *    into the caller's buffer. Errors, through
 *    nodus_light_provider_map_error:
 *      node NODUS_ERR_NOT_FOUND        → LIGHT_BLOCK_NOT_FOUND
 *      node NODUS_ERR_HEIGHT_TOO_HIGH  → HEIGHT_TOO_HIGH
 *      node NODUS_ERR_RATE_LIMITED     → NO_RESPONSE (DEVIATION below)
 *      any other node error            → NONE (an unnamed error; this
 *                                        includes INTERNAL_ERROR and a
 *                                        node-sent PROTOCOL_ERROR — the
 *                                        reference's default branch,
 *                                        http.go:205-207)
 *      no reply in time                → NO_RESPONSE
 *      not connected / local failure
 *      (rc == -1)                      → NO_RESPONSE (DEVIATION below)
 *      reply refused by the RPC decoder,
 *      or the wrong height             → BAD_LIGHT_BLOCK (reason REJECT)
 *      "lb" that does not decode       → BAD_LIGHT_BLOCK (reason REJECT)
 *    The deadline is the client's `request_timeout_ms` — the bound the
 *    provider interface requires an implementation to set
 *    (cmt_light_provider.h, "context.Context … NO COUNTERPART").
 *    DEVIATION from the reference HTTP provider: it runs
 *    `LightBlock.ValidateBasic(chainID)` itself (http.go:91-95); this
 *    provider does NOT — the light client does it on every block it is
 *    given (decision item 5, D15). The height match (http.go:70-74) IS
 *    checked, by nodus_client_dnac_light_block.
 *    DEVIATION (BUGS.md Z-45): a node's NODUS_ERR_RATE_LIMITED answer
 *    maps to NO_RESPONSE, the benign class the light client does not
 *    remove a provider for. The reference RPC has no "busy" refusal; its
 *    only transient one — a timed-out request, retried with backoff —
 *    ends in ErrNoResponse (http.go:200-210, errors.go:16-18). An
 *    unnamed error is outside the light client's benign set
 *    (light/client.go:757-763, :1106-1112) and would remove an honest
 *    node that is merely at its node-wide dnac_light_block limit
 *    (nodus_witness_handlers.h,
 *    NODUS_LIGHT_BLOCK_RATE_PER_SEC). No retry is done here: the client
 *    asks another provider.
 *    DEVIATION (BUGS.md Z-45): rc == -1 from nodus_client_dnac_light_block
 *    (the client is not connected, or a local allocation / send failure)
 *    maps to NO_RESPONSE. The reference's default branch returns the raw
 *    error for a refused connection or a cancelled context (http.go:
 *    205-207), which falls outside the light client's benign set; here it
 *    is the benign class, so a provider whose session is down is kept.
 *  · report_evidence — LOCAL RECORD ONLY (Kurultay #25 item 2; the
 *    interface's header): the evidence is logged at WARN and counted in
 *    `evidence_recorded`; nothing is sent.
 *
 * ── PLATFORM ───────────────────────────────────────────────────────────
 * Pure C11 over nodus_client.c; no POSIX-only call. Builds on Linux,
 * Windows (mingw) and Android like nodus_client.c.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * No clock (the deadline is the client's), no randomness, no map. What
 * the provider answers is a peer's word and is never trusted here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_LIGHT_PROVIDER_H
#define NODUS_LIGHT_PROVIDER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "nodus/nodus.h"
#include "dnac/cmt_block.h"            /* CMT_MAX_CHAIN_ID_LEN          */
#include "dnac/cmt_light_provider.h"   /* cmt_light_provider_t          */

#ifdef __cplusplus
extern "C" {
#endif

/** One pinned provider. Fill with nodus_light_provider_init; it must
 *  outlive the `cmt_light_provider_t` table that points at it. */
typedef struct {
    nodus_client_t *client;                        /* BORROWED, pinned   */
    uint8_t         chain_id[CMT_MAX_CHAIN_ID_LEN];
    size_t          chain_id_len;
    uint64_t        block_protocol;                /* normally
                                                      CMT_BLOCK_PROTOCOL */
    uint64_t        evidence_recorded;             /* report_evidence's
                                                      local record       */
} nodus_light_provider_t;

/** True when `cfg` carries a usable server key pin: a non-NULL list and
 *  a count > 0 (the shape nodus_client_init accepts as pinned). */
bool nodus_light_provider_config_pinned(const nodus_client_config_t *cfg);

/**
 * Bind `p` to `client` and fill `table` (ctx = p, the three rows).
 *
 * @param chain_id       the configured chain id, 1 .. CMT_MAX_CHAIN_ID_LEN
 *                       bytes (copied)
 * @param block_protocol the value Version.Block must equal on decode
 *                       (cmt_light_block.h — normally CMT_BLOCK_PROTOCOL)
 * @return CMT_OK; CMT_REJECT when the client is NOT pinned (Kurultay #25
 *         item 8) or the chain id length is out of range — `p` and
 *         `table` are then zeroed; CMT_FAULT on NULL.
 */
int nodus_light_provider_init(nodus_light_provider_t *p,
                              nodus_client_t *client,
                              const uint8_t *chain_id, size_t chain_id_len,
                              uint64_t block_protocol,
                              cmt_light_provider_t *table);

/**
 * The error mapping `light_block` applies to the result of
 * nodus_client_dnac_light_block (see the file header). A pure function,
 * exported for tests.
 *
 * @param rc          nodus_client_dnac_light_block's return
 * @param server_err  its `*server_err_out`
 * @param err         filled; may be NULL
 * @return CMT_OK when rc == 0 (code NONE); otherwise CMT_REJECT with the
 *         mapped code.
 */
int nodus_light_provider_map_error(int rc, int server_err,
                                   cmt_light_provider_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_LIGHT_PROVIDER_H */
