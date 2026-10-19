/**
 * @file nodus/src/client/nodus_light_provider.c
 * @brief The light client's pinned provider over `dnac_light_block` —
 *        see nodus_light_provider.h for the contract, the error mapping
 *        and the deviations.
 *
 * Reference @v0.38.26: light/provider/provider.go:9-29,
 * light/provider/errors.go:1-29, light/provider/http/http.go (the shape
 * this replaces: ChainID :59-62, LightBlock :66-98, the error regexps
 * :18-21 and their mapping :148-152 / :194-198).
 * Governing records: docs/plans/decisions/2026-10-16-dnac-light-block-
 * rpc.md (APPROVED), docs/plans/decisions/2026-10-16-kurultay-25-
 * summary.md items 2 and 8, pin decision docs/plans/decisions/
 * 2026-09-30-cometbft-pin-v0.38.26.md.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_light_provider.h"

#include "dnac/cmt_light_block.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>

#define LOG_TAG "LIGHT-PROVIDER"

bool nodus_light_provider_config_pinned(const nodus_client_config_t *cfg)
{
    return cfg != NULL && cfg->pinned_server_fps != NULL &&
           cfg->pinned_server_fp_count > 0;
}

int nodus_light_provider_map_error(int rc, int server_err,
                                   cmt_light_provider_error_t *err)
{
    int code;

    if (err) {
        err->code   = CMT_LIGHT_PROVIDER_ERR_NONE;
        err->reason = CMT_OK;
    }
    if (rc == 0) {
        return CMT_OK;
    }
    if (server_err == NODUS_ERR_NOT_FOUND) {
        code = CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND; /* errors.go:12-15 */
    } else if (server_err == NODUS_ERR_HEIGHT_TOO_HIGH) {
        code = CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH;       /* errors.go:9-11  */
    } else if (server_err == NODUS_ERR_RATE_LIMITED) {
        /* DEVIATION (header): a busy node's refusal is the benign class —
         * the reference's only transient-refusal path, the timed-out retry
         * loop, ends in ErrNoResponse (http.go:200-210, errors.go:16-18) */
        code = CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE;
    } else if (server_err != 0) {
        code = CMT_LIGHT_PROVIDER_ERR_NONE;      /* the node refused: unnamed */
    } else if (rc == NODUS_ERR_TIMEOUT || rc == -1) {
        /* errors.go:16-18; rc == -1 here is a DEVIATION (header) */
        code = CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE;
    } else if (rc == NODUS_ERR_PROTOCOL_ERROR) {
        code = CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK;       /* errors.go:21-29 */
    } else {
        code = CMT_LIGHT_PROVIDER_ERR_NONE;
    }
    if (err) {
        err->code = code;
        if (code == CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK) {
            err->reason = CMT_REJECT;
        }
    }
    return CMT_REJECT;
}

/* provider.go:12-13 — ChainID(): the configured value (http.go:59-62). */
static int lp_chain_id(void *ctx, const uint8_t **out, size_t *out_len)
{
    const nodus_light_provider_t *p = (const nodus_light_provider_t *)ctx;

    if (p == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    *out     = p->chain_id;
    *out_len = p->chain_id_len;
    return CMT_OK;
}

/* provider.go:15-25 — LightBlock(height): "0 - the latest". */
static int lp_light_block(void *ctx, int64_t height,
                          cmt_light_block_buf_t *out,
                          cmt_light_provider_error_t *err)
{
    nodus_light_provider_t *p = (nodus_light_provider_t *)ctx;
    uint64_t                h = 0;
    uint8_t                *lb = NULL;
    size_t                  lb_len = 0;
    int                     server_err = 0;
    int                     rc;

    if (err) {
        err->code   = CMT_LIGHT_PROVIDER_ERR_NONE;
        err->reason = CMT_OK;
    }
    if (p == NULL || p->client == NULL || out == NULL || height < 0) {
        return CMT_FAULT;           /* "height must be >= 0" — caller error */
    }
    if (cmt_light_block_buf_reset(out) != CMT_OK) {
        return CMT_FAULT;
    }
    /* Kurultay #25 item 8 — checked at init, held on every call */
    if (!nodus_light_provider_config_pinned(&p->client->config)) {
        QGP_LOG_ERROR(LOG_TAG, "light_block: the client is not pinned");
        return CMT_FAULT;
    }

    rc = nodus_client_dnac_light_block(p->client, (uint64_t)height, &h,
                                       &lb, &lb_len, &server_err);
    if (rc != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "light_block h=%lld: rc=%d node=%d",
                      (long long)height, rc, server_err);
        return nodus_light_provider_map_error(rc, server_err, err);
    }

    rc = cmt_light_block_decode(lb, lb_len, p->block_protocol, out);
    free(lb);
    if (rc == CMT_REJECT) {
        QGP_LOG_DEBUG(LOG_TAG, "light_block h=%llu: the light block does "
                      "not decode", (unsigned long long)h);
        if (err) {
            err->code   = CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK;
            err->reason = CMT_REJECT;
        }
        return CMT_REJECT;
    }
    if (rc != CMT_OK) {
        cmt_light_block_buf_reset(out);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* provider.go:27-28 — ReportEvidence: LOCAL RECORD ONLY (Kurultay #25
 * item 2). Nothing is sent. */
static int lp_report_evidence(void *ctx, const cmt_pb_evidence_t *ev)
{
    nodus_light_provider_t *p = (nodus_light_provider_t *)ctx;

    if (p == NULL || ev == NULL) {
        return CMT_FAULT;
    }
    p->evidence_recorded++;
    QGP_LOG_WARN(LOG_TAG, "evidence reported (local record #%llu, "
                 "duplicate-vote=%d) — not sent",
                 (unsigned long long)p->evidence_recorded,
                 ev->has_duplicate_vote_evidence ? 1 : 0);
    return CMT_OK;
}

int nodus_light_provider_init(nodus_light_provider_t *p,
                              nodus_client_t *client,
                              const uint8_t *chain_id, size_t chain_id_len,
                              uint64_t block_protocol,
                              cmt_light_provider_t *table)
{
    if (p == NULL || client == NULL || table == NULL ||
        (chain_id == NULL && chain_id_len != 0)) {
        return CMT_FAULT;
    }
    memset(p, 0, sizeof(*p));
    memset(table, 0, sizeof(*table));
    if (!nodus_light_provider_config_pinned(&client->config)) {
        QGP_LOG_ERROR(LOG_TAG, "init: refused — the client has no server "
                      "key pin (a light provider is pinned only)");
        return CMT_REJECT;
    }
    if (chain_id_len == 0 || chain_id_len > sizeof(p->chain_id)) {
        QGP_LOG_ERROR(LOG_TAG, "init: chain id length %llu out of range",
                      (unsigned long long)chain_id_len);
        return CMT_REJECT;
    }
    p->client         = client;
    memcpy(p->chain_id, chain_id, chain_id_len);
    p->chain_id_len   = chain_id_len;
    p->block_protocol = block_protocol;

    table->ctx             = p;
    table->chain_id        = lp_chain_id;
    table->light_block     = lp_light_block;
    table->report_evidence = lp_report_evidence;
    return CMT_OK;
}
