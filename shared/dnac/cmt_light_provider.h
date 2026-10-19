/**
 * @file shared/dnac/cmt_light_provider.h
 * @brief cometbft @v0.38.26 `light/provider` — the `Provider` interface
 *        (light/provider/provider.go:9-29) as a C callback table, and its
 *        named errors (light/provider/errors.go:1-29).
 *
 * ═══ STATUS: INTERFACE ONLY — NO IMPLEMENTATION, NO CALLER ══════════════
 * Package 1 of the light client (Kurultay #25 item 1, docs/plans/
 * decisions/2026-10-16-kurultay-25-summary.md: "The provider is an
 * interface, with a mock"). There is NO network code here and no
 * implementation in shared/: the only implementation today is the mock
 * inside nodus/tests/test_cmt_light_block.c (light/provider/mock/
 * mock.go). A networked provider is later work, and Kurultay #25 item 8
 * binds it: it is ALWAYS a pinned session — "never an unpinned
 * provider"; the first pins arrive with the trust root (item 9).
 * ════════════════════════════════════════════════════════════════════════
 *
 * ── DEVIATIONS / NO COUNTERPART, each labelled ─────────────────────────
 *  · `context.Context` (provider.go:25, :28) has NO COUNTERPART. In Go it
 *    carries cancellation and a deadline across goroutines. This port
 *    calls a provider from one event loop, and its precedent for a Go
 *    interface that takes a context is the synchronous callback table
 *    `cmt_mem_app_t` (cmt_mem.h:341-373, proxy/app_conn.go:33), which
 *    drops it; the labelling precedent is cmt_memr.h:85-92. Dropped here,
 *    with this consequence for any implementation: a call returns
 *    within a bound the IMPLEMENTATION sets, and a call that ran out of
 *    it answers CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE — the class the
 *    reference's detector already gives `context.DeadlineExceeded` and
 *    `context.Canceled` (light/detector.go:134). How a networked provider
 *    waits without blocking the loop is that later package's question.
 *  · `ReportEvidence(ctx, types.Evidence)` (:27-28) KEEPS ITS SLOT. Its
 *    implementation in this project is "local record only" (Kurultay #25
 *    item 2: "Evidence sending is replaced by 'stop + local record'
 *    (K24 D3)"): it records the evidence on this node and sends nothing.
 *    ⚠ The argument type is the port's `types.Evidence` wire counterpart,
 *    `cmt_pb_evidence_t` (cmt_pb.h:380-398). The ONLY evidence the
 *    reference's light client ever reports is LightClientAttackEvidence
 *    (light/detector.go:223-224, `sendEvidence`), and this port has
 *    deliberately not got that type (cmt_evidence.h:18, :80; the decoder
 *    REFUSES branch 2, cmt_pb.h:382-387). So today this slot cannot carry
 *    the one evidence its caller would pass; that gap belongs to the
 *    detector package and is not closed here.
 *  · Go's error VALUES become CMT_REJECT plus the optional
 *    `cmt_light_provider_error_t` out-parameter — the pattern of
 *    `cmt_light_error_t` (cmt_light_verifier.h:189-213). Error TEXT is
 *    not carried. A failure of the implementation itself (allocation,
 *    a NULL row) is CMT_FAULT.
 *  · `LightBlock`'s result lands in caller-owned storage, a
 *    `cmt_light_block_buf_t` (cmt_light_block.h) — the C cost of Go
 *    returning a fresh `*types.LightBlock`.
 *
 * ── Determinism ────────────────────────────────────────────────────────
 * The interface itself holds no state. What a provider ANSWERS is a
 * peer's word and is never trusted: the light client
 * (cmt_light_client.c, `provider_light_block`) checks every answer as the
 * reference's provider would — every member present, the header at the
 * requested height, LightBlock.ValidateBasic against the client's chain
 * id (cmt_light_client.h D15; light/provider/http/http.go:80-84, :96-99)
 * — and then verifies it (light/verifier.go, cmt_light_verifier.h). So an
 * implementation need not validate, but it MUST bound its own wait: a
 * call that gets no answer within the implementation's deadline returns
 * NO_RESPONSE (the client has no clock and sets no deadline itself).
 *
 * Reference @v0.38.26:
 *   light/provider/provider.go  29 lines
 *   light/provider/errors.go    29 lines
 *   light/provider/mock/mock.go (ported into the test file only)
 * Governing records: pin decision
 * docs/plans/decisions/2026-09-30-cometbft-pin-v0.38.26.md; Kurultay #25
 * (above); docs/plans/decisions/2026-10-16-relay-port-4003-bandwidth-
 * role.md (B9).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_CMT_LIGHT_PROVIDER_H
#define SHARED_DNAC_CMT_LIGHT_PROVIDER_H

#include <stdint.h>
#include <stddef.h>

#include "cmt_tmhash.h"          /* CMT_OK / CMT_REJECT / CMT_FAULT       */
#include "cmt_pb.h"              /* cmt_pb_evidence_t                     */
#include "cmt_light_block.h"     /* cmt_light_block_buf_t                 */

#ifdef __cplusplus
extern "C" {
#endif

/* ══ light/provider/errors.go ═════════════════════════════════════════ */

#define CMT_LIGHT_PROVIDER_ERR_NONE               0
/** errors.go:9-11 — `ErrHeightTooHigh`: "the height is higher than the
 *  last block that the provider has. The light client will not remove
 *  the provider". */
#define CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH    1
/** errors.go:12-15 — `ErrLightBlockNotFound`: "a provider can't find the
 *  requested header (i.e. it has been pruned). The light client will not
 *  remove the provider". */
#define CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND 2
/** errors.go:16-18 — `ErrNoResponse`: "the provider doesn't respond to
 *  the request in a given time". */
#define CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE        3
/** errors.go:21-29 — `ErrBadLightBlock{Reason}`: "a provider returns an
 *  invalid light block". `reason` carries the wrapped verdict. */
#define CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK    4

/**
 * The reference's provider error values, as one out-parameter. On CMT_OK
 * and on CMT_FAULT `code` is CMT_LIGHT_PROVIDER_ERR_NONE. On CMT_REJECT
 * `code` is one of the four named errors above, or NONE for an unnamed
 * error. `reason` is meaningful only for BAD_LIGHT_BLOCK: the CMT_*
 * return of the check that refused the block (the Go `Reason error`,
 * errors.go:24, without its text).
 */
typedef struct {
    int code;     /* CMT_LIGHT_PROVIDER_ERR_*       */
    int reason;   /* BAD_LIGHT_BLOCK only: CMT_REJECT / CMT_FAULT */
} cmt_light_provider_error_t;

/* ══ light/provider/provider.go:9-29 — Provider ═══════════════════════ */

/**
 * "Provider provides information for the light client to sync
 * (verification happens in the client)." (provider.go:9-10) — as a
 * callback table over an opaque `ctx`, the shape of `cmt_mem_app_t`
 * (cmt_mem.h:354-373). EVERY ROW IS REQUIRED; a caller that meets a NULL
 * row treats it as CMT_FAULT.
 */
typedef struct {
    void *ctx;

    /** provider.go:12-13 — `ChainID() string`. Points `*out` at the
     *  provider's chain id (owned by the provider, valid for its
     *  lifetime) and sets `*out_len`.
     *  @return CMT_OK; CMT_FAULT on NULL. */
    int (*chain_id)(void *ctx, const uint8_t **out, size_t *out_len);

    /** provider.go:15-25 — `LightBlock(ctx, height)`. "0 - the latest.
     *  height must be >= 0." A negative height is the caller's error:
     *  CMT_FAULT. On CMT_OK `out->lb` is the light block. "If there's no
     *  LightBlock for the given height, ErrLightBlockNotFound error is
     *  returned" — CMT_REJECT with code LIGHT_BLOCK_NOT_FOUND; an IO or
     *  other failure to fetch is CMT_REJECT with code NO_RESPONSE or
     *  NONE. `err` may be NULL. See the file header for `ctx`.
     *  @return CMT_OK, CMT_REJECT, CMT_FAULT. */
    int (*light_block)(void *ctx, int64_t height,
                       cmt_light_block_buf_t *out,
                       cmt_light_provider_error_t *err);

    /** provider.go:27-28 — `ReportEvidence(ctx, types.Evidence)`.
     *  Implementation: LOCAL RECORD ONLY (Kurultay #25 item 2) — see the
     *  file header, including why the argument cannot yet carry
     *  LightClientAttackEvidence.
     *  @return CMT_OK, CMT_REJECT, CMT_FAULT on NULL. */
    int (*report_evidence)(void *ctx, const cmt_pb_evidence_t *ev);
} cmt_light_provider_t;

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_CMT_LIGHT_PROVIDER_H */
