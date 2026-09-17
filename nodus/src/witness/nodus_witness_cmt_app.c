/**
 * @file nodus/src/witness/nodus_witness_cmt_app.c
 * @brief The application table of nodus_witness_cmt_app.h.
 *
 * Every function carries the cometbft @709fd12b site it implements and,
 * where it reads the ledger, the ledger function it reuses. Nothing here
 * re-implements a ledger rule: the admission check, the contextual
 * ruleset table, the batch preflight and the capacity seam are the
 * engine's own entry points, called as the live lane calls them.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_cmt_app.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>                  /* PRId64 in the apply log line   */

/* `sqlite3.h` arrives with witness/nodus_witness.h:27 (the tree's own
 * convention — nodus_witness_cmt_store.c takes it the same way). */

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include "dnac/cmt_tmhash.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/ledger_ids.h"

#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"    /* the STORED chain id
                                              * (nodus_witness_v2_gen.h:786) */
#include "witness/nodus_witness_emission.h"  /* DNAC_DECIMAL_UNIT
                                              * (nodus_witness_emission.h:42) */

#define LOG_TAG "CMT-APP"

/* ═══════════════════════════════════════════════════════════════════════
 * Construction
 * ═══════════════════════════════════════════════════════════════════════ */

/* ORCHESTRATOR delta 1, item B: the smallest canonical item either wire
 * codec accepts. An envelope's own framing minimum (env_wire.h:198-199,
 * 43-byte fixed head + one 30-byte leg header, call_len/auth_len both
 * legally 0 at this layer's framing rules — env_wire.h's own "HONEST
 * LABEL" says this layer parses neither) is smaller by two orders of
 * magnitude than a claim's fixed minimum (manifest_wire.h:452-454,
 * 7 404 bytes: a 2 592-byte pubkey plus a 4 627-byte signature alone
 * dominate it), so an all-envelope block is always the worst case for
 * TOTAL item count. */
#define CMT_APP_MIN_ENV_BYTES ((size_t)(DNA_ENV_FIXED_HEAD + DNA_ENV_LEG_HDR_LEN))

/* ORCHESTRATOR delta 1, item B: the WORST-CASE committee size for
 * sizing an array once, at init, for the node's whole lifetime — the
 * SMALLEST possible validator count, because cmt_max_data_bytes's
 * commit-size term SHRINKS the byte budget as the committee GROWS
 * (shared/dnac/cmt_block.c:1700-1745), so the smallest committee gives
 * the LARGEST possible budget and therefore the safe upper bound on
 * item count regardless of how large the committee grows later (up to
 * DNAC_MAX_ACTIVE_VALIDATORS, dnac.h:201). */
#define CMT_APP_MIN_VALS_FOR_BOUND ((int64_t)1)

/* ORCHESTRATOR delta 2, item A — only TWO arrays remain context-owned
 * across calls (the ABCI response-ownership rule; see the header's
 * struct comment); every other scratch array delta 1 kept here is now
 * local to the row that uses it. NULL-safe throughout. */
void nodus_cmt_app_ledger_release(nodus_cmt_app_ledger_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->prep_txs);
    free(ctx->fb_pb);
    ctx->prep_txs     = NULL;
    ctx->prep_txs_len = 0;
    ctx->prep_txs_cap = 0;
    ctx->fb_pb        = NULL;
    ctx->fb_pb_cap    = 0;
}

int nodus_cmt_app_ledger_init(nodus_cmt_app_ledger_t *ctx, nodus_witness_t *w,
                              const cmt_genesis_doc_t *gendoc)
{
    if (!ctx || !w || !w->db || !gendoc) {
        return CMT_FAULT;
    }
    /* Every ledger seam this module calls refuses a non-successor chain
     * (nodus_witness_v2_produce.c:358-360 and the divert at
     * nodus_witness_verify.c:808-813), so a table bound to a legacy chain
     * would have rows that all fault. Refuse at bind time instead. */
    if (!w->v2_successor) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "the Comet application binds a Ledger V2 successor "
                      "chain only");
        return CMT_FAULT;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->w = w;
    ctx->gendoc = gendoc;

    /* ── ORCHESTRATOR delta 1, item B — THE THREE BOUNDS, DERIVED ────── */

    /* PREP_BOUND: the mempool's own configured `size`. The real mempool
     * config is built later, in nodus_cmt_node_init's step 7a — this
     * calls the SAME pure default constructor early, only to read
     * `.size`; both calls yield the identical value (D-4 rev 3), so
     * there is no second source of truth, only a second read of one. */
    {
        cmt_mempool_config_t mem_cfg_for_bound;
        if (cmt_mempool_config_default(&mem_cfg_for_bound) != CMT_OK ||
            mem_cfg_for_bound.size <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the mempool default config could not be read for "
                          "sizing the prepare-side arrays");
            return CMT_FAULT;
        }
        ctx->prep_bound = (size_t)mem_cfg_for_bound.size;
    }

    /* ENV_BOUND / CLAIM_BOUND: MaxDataBytes (types/block.go:281-300,
     * ported as cmt_max_data_bytes_no_evidence — evidence is never
     * ported, D-23's own "sm.EmptyEvidencePool{}" binding) divided by
     * the smallest canonical item of each class. `block.max_bytes`
     * comes from the genesis document, not a hardcoded 22 020 096 — the
     * ARITHMETIC is D-4 rev 3's, the VALUE read is whatever this chain's
     * committed genesis actually says. */
    {
        int64_t max_bytes = gendoc->has_consensus_params
                                ? gendoc->consensus_params.block.max_bytes
                                : 0;
        int64_t max_data_bytes = 0;
        int64_t min_env_proto  = 0;
        int64_t min_claim_proto = 0;

        if (max_bytes <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the genesis document carries no usable "
                          "Block.MaxBytes — the byte-bound seam cannot be "
                          "sized");
            return CMT_FAULT;
        }
        if (cmt_max_data_bytes_no_evidence(max_bytes,
                                           CMT_APP_MIN_VALS_FOR_BOUND,
                                           &max_data_bytes) != CMT_OK ||
            max_data_bytes <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "MaxDataBytes could not be computed from this "
                          "chain's Block.MaxBytes");
            return CMT_FAULT;
        }
        min_env_proto =
            nodus_cmt_compute_proto_size_for_tx(CMT_APP_MIN_ENV_BYTES);
        min_claim_proto =
            nodus_cmt_compute_proto_size_for_tx((size_t)DNA_CLAIM_FIXED_LEN);
        if (min_env_proto <= 0 || min_claim_proto <= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the minimum item proto-size computed as zero or "
                          "negative — refusing to size the byte-bound seam "
                          "on a nonsensical figure");
            return CMT_FAULT;
        }
        ctx->env_bound   = (size_t)(max_data_bytes / min_env_proto);
        ctx->claim_bound = (size_t)(max_data_bytes / min_claim_proto);
        if (ctx->env_bound == 0 || ctx->claim_bound == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "the derived byte-bound seam has zero capacity — "
                          "Block.MaxBytes is too small for even one minimal "
                          "item");
            return CMT_FAULT;
        }
        QGP_LOG_INFO(LOG_TAG, "byte-bound capacity seam (per-request, delta "
                     "2): max_bytes=%" PRId64 " max_data_bytes=%" PRId64
                     " prep_bound=%zu env_bound=%zu claim_bound=%zu "
                     "item_cap=%u",
                     max_bytes, max_data_bytes, ctx->prep_bound,
                     ctx->env_bound, ctx->claim_bound,
                     (unsigned)NODUS_V2_APPLY_MAX_OPS);
    }

    /* ── delta 2: NOTHING IS ALLOCATED HERE. prep_txs/fb_pb start NULL
     * (the memset above) and are built by their own rows, per request,
     * on first use — see nodus_cmt_app_prepare_proposal /
     * _finalize_block. Every other scratch array is now local to the
     * row that needs it. */
    return CMT_OK;
}

int nodus_cmt_app_ledger_build(nodus_cmt_app_t *out, nodus_cmt_app_ledger_t *ctx)
{
    if (!out || !ctx || !ctx->w) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->ctx                   = ctx;
    out->init_chain            = nodus_cmt_app_init_chain;            /* :20 */
    out->prepare_proposal      = nodus_cmt_app_prepare_proposal;      /* :21 */
    out->process_proposal      = nodus_cmt_app_process_proposal;      /* :22 */
    out->extend_vote           = nodus_cmt_app_extend_vote;           /* :23 */
    out->verify_vote_extension = nodus_cmt_app_verify_vote_extension; /* :24 */
    out->finalize_block        = nodus_cmt_app_finalize_block;        /* :25 */
    out->commit                = nodus_cmt_app_commit;                /* :26 */
    return CMT_OK;
}

/* proxy/app_conn.go:31 — `Error()`. The in-process connection has no
 * sticky error: there is no socket to break. */
static int app_mempool_error(void *vctx)
{
    return vctx ? CMT_OK : CMT_FAULT;
}

/* proxy/app_conn.go:35 — `Flush()`. Nothing is buffered between the
 * mempool and this application: `check_tx` answers in line. */
static int app_mempool_flush(void *vctx)
{
    return vctx ? CMT_OK : CMT_FAULT;
}

int nodus_cmt_app_ledger_build_mempool(cmt_mem_app_t *out,
                                       nodus_cmt_app_ledger_t *ctx)
{
    if (!out || !ctx || !ctx->w) {
        return CMT_FAULT;
    }
    memset(out, 0, sizeof(*out));
    out->ctx      = ctx;
    out->error    = app_mempool_error;
    out->check_tx = nodus_cmt_app_check_tx;
    out->flush    = app_mempool_flush;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The identity `nodus_witness_verify_transaction` demands
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_entry_identity(nodus_cmt_app_ledger_t *ctx,
                                 const uint8_t *bytes, size_t len,
                                 uint8_t out_id[64], uint8_t *out_class)
{
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    dna_env_preflight_t          *pf   = NULL;
    nodus_v2_envelope_t           env;
    uint64_t                      tip = 0;
    uint8_t                       cls;
    int                           rc = CMT_FAULT;

    if (!ctx || !ctx->w || !bytes || len == 0 || !out_id || !out_class) {
        return CMT_FAULT;
    }
    /* The ONE byte-driven classification authority — admission, ingress
     * and round entry share it (nodus_witness_v2_produce.h's contract). */
    cls = nodus_witness_v2_classify_entry(bytes, (uint32_t)len);
    *out_class = cls;

    if (cls == NODUS_W_TX_V2_CLAIM) {
        /* nodus_witness_verify.c:564-572 — the claim lane demands
         * SHA3-512 of the exact claim bytes. */
        if (qgp_sha3_512(bytes, len, out_id) != 0) {
            return CMT_FAULT;                   /* hash backend: node-local */
        }
        return CMT_OK;
    }

    /* nodus_witness_verify.c:750 — the envelope lane demands the DERIVED
     * wire_id. Deriving it needs the committed contextual ruleset table
     * and the candidate height, exactly as the seam builds them. */
    bctx = (nodus_witness_v2_block_ctx_t *)calloc(1, sizeof(*bctx));
    pf   = (dna_env_preflight_t *)calloc(1, sizeof(*pf));
    if (!bctx || !pf) {
        goto done;
    }
    if (nodus_witness_v2_tip_height(ctx->w, &tip) != 0) {
        goto done;                              /* node-local read fault   */
    }
    switch (nodus_witness_v2_block_ctx_build(ctx->w, bctx)) {
    case 0:
        break;
    case -1:
        /* A CHAIN-STATE verdict: SYSTEM is not ACTIVE, so no block on
         * this chain is appliable. Deterministic and identical on every
         * node — a refusal of the candidate, not this node's failure. */
        rc = CMT_REJECT;
        goto done;
    default:
        goto done;                              /* -2 node-local fault     */
    }
    env.env_bytes = bytes;
    env.env_len   = len;
    if (nodus_witness_v2_env_preflight_batch(ctx->w, tip + 1u, bctx->rulesets,
                                             bctx->n_rulesets, &env, 1, pf,
                                             NULL, NULL) != NODUS_V2_ENV_OK) {
        rc = CMT_REJECT;                        /* the bytes yield no id   */
        goto done;
    }
    memcpy(out_id, pf->wire_id, 64);
    rc = CMT_OK;
done:
    free(pf);
    free(bctx);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════
 * CheckTx — proxy/app_conn.go:33-34, D-23 rev 5 (9)
 * ═══════════════════════════════════════════════════════════════════════ */

/** The nonzero `ResponseCheckTx.Code` this application answers a refused
 *  transaction with. The reference reserves 0 for OK
 *  (abci/types/types.go:11) and leaves every other value to the
 *  application; one value is enough because the mempool only tests
 *  `code == CodeTypeOK` (clist_mempool.go:412, :492). */
#define NODUS_CMT_APP_CODE_REJECTED  ((uint32_t)1)

int nodus_cmt_app_check_tx(void *vctx, const cmt_mem_request_check_tx_t *req,
                           cmt_mem_response_check_tx_t *res)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    uint8_t  id[64];
    uint8_t  cls = 0;
    char     reason[256];
    int      rc;

    if (!ctx || !ctx->w || !req || !res) {
        return CMT_FAULT;
    }
    memset(res, 0, sizeof(*res));
    if (!req->tx || req->tx_len == 0) {
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        return CMT_OK;                          /* the request was served  */
    }
    /* `gas_wanted` stays 0: `PostCheckMaxGas` is nil while MaxGas is −1
     * (mempool.go:132-134), which is the value D-4 rev 3 (2) writes into
     * the genesis document, so the mempool never reads it. */
    rc = nodus_cmt_app_entry_identity(ctx, req->tx, req->tx_len, id, &cls);
    if (rc == CMT_FAULT) {
        return CMT_FAULT;                       /* node-local: the panic
                                                 * class of :273/:669     */
    }
    if (rc != CMT_OK) {
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        return CMT_OK;
    }
    reason[0] = '\0';
    /* D-23 rev 5 (9): the ledger's admission check, in ADMISSION mode
     * (nodus_witness_verify.h:50). On a successor chain the function
     * diverts to the V2 lane (nodus_witness_verify.c:808-813) and the
     * legacy parameters are unread — passed as the divert reads them. */
    rc = nodus_witness_verify_transaction(ctx->w, req->tx,
                                          (uint32_t)req->tx_len, id, cls,
                                          NULL, 0, NULL, NULL, 0,
                                          NODUS_WITNESS_VERIFY_ADMISSION,
                                          reason, sizeof(reason));
    if (rc != 0) {
        /* −1 invalid and −2 double-spend are both deterministic verdicts
         * about the bytes; neither is this node failing. */
        QGP_LOG_DEBUG(LOG_TAG, "check_tx refused (rc %d): %s", rc, reason);
        res->code = NODUS_CMT_APP_CODE_REJECTED;
        return CMT_OK;
    }
    /* ── AND THE SIGNATURES ──────────────────────────────────────────
     * The admission lane above verifies NONE. It runs the wire-family
     * marker, the contextual ruleset table, the preflight, a `wire_id`
     * comparison and the committed-intent guard
     * (nodus_witness_verify.c:674-784), and the preflight's own honest
     * label says it decides nothing about "whether any authorization is
     * VALID" (env_preflight.h:57-63). The `wire_id` comparison cannot
     * substitute: this row DERIVES the id from the very bytes it is
     * checking, so the comparison is a tautology (reported round 1) —
     * flipping a byte inside an approval signature changes both sides
     * and is accepted.
     *
     * D-4 rev 3 (1) defines CheckTx as the ledger's admission check
     * INCLUDING the signature, so the authorization stage runs here, on
     * the same shared helper the apply engine's item loop uses. */
    if (cls == NODUS_W_TX_V2_ENVELOPE) {
        reason[0] = '\0';
        rc = nodus_witness_v2_env_authorize(ctx->w, req->tx, req->tx_len,
                                            reason, sizeof(reason));
        if (rc == -2) {
            QGP_LOG_ERROR(LOG_TAG, "check_tx: authorization could not be "
                          "computed on this node: %s", reason);
            return CMT_FAULT;            /* never a verdict about the tx */
        }
        if (rc != 0) {
            QGP_LOG_DEBUG(LOG_TAG, "check_tx refused at authorization: %s",
                          reason);
            res->code = NODUS_CMT_APP_CODE_REJECTED;
        }
    }
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * InitChain — consensus/replay.go:318-373, D-23 rev 5 (7)
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_init_chain(void *vctx,
                             const nodus_abci_request_init_chain_t *req,
                             nodus_abci_response_init_chain_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    dna_vset_snapshot_t    *snap = NULL;
    uint8_t                 chain_id[DNA_CHAIN_ID_LEN];
    uint8_t                 root[64];
    size_t                  i, j;
    int                     rc = CMT_FAULT;

    if (!ctx || !ctx->w || !ctx->gendoc || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));

    /* ── (1) the committed chain id == the request's ───────────────────
     * ONE derivation, the ledger's own: `nodus_witness_v2_chain_id`
     * answers from the height-0 block row where there is one and from
     * the stored genesis document where there is not
     * (nodus_witness_v2_claims.c:186-224), so a version-3 chain and an
     * older one are served by the same call. */
    if (nodus_witness_v2_chain_id(ctx->w, chain_id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the committed chain id is underivable");
        return CMT_FAULT;
    }
    if (req->chain_id_len != DNA_CHAIN_ID_LEN ||
        memcmp(req->chain_id, chain_id, DNA_CHAIN_ID_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the request's chain id is not the "
                      "committed one");
        return CMT_FAULT;
    }

    /* ── (2) the ledger's COMMITTED global root == the document's
     * app_hash ────────────────────────────────────────────────────────
     * The request carries no app_hash (abci/types.proto:76-83; the
     * reference sends six fields, replay.go:327-334), so the comparison
     * uses the genesis document this application was bound to
     * (DEVIATION R3-C1a-1).
     *
     * The ledger side is `nodus_witness_v2_committed_global_root` — the
     * tip block row's stored `global_root`, or the genesis composition
     * where no row exists — NOT `nodus_witness_global_root_v2`, which
     * recomputes from the live tables and is therefore an answer about
     * NOW rather than about the last committed block. One quantity, one
     * reader: the same helper serves anywhere this application needs
     * "the root after the last block". */
    if (nodus_witness_v2_committed_global_root(ctx->w, root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the ledger's committed global root is "
                      "unreadable");
        return CMT_FAULT;
    }
    if (ctx->gendoc->app_hash_len != 64 ||
        memcmp(ctx->gendoc->app_hash, root, 64) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: the genesis document's app_hash is not "
                      "the ledger's committed global root");
        return CMT_FAULT;
    }

    /* ── (3) the committed validator set == the request's validators ──
     * The committed set is the genesis snapshot (epoch start 0). The
     * comparison is a MULTISET comparison on (public key, power), so it
     * does not depend on either side's ordering — the snapshot's rank
     * order and the document's order are different by construction
     * (nodus_witness_vset.h's build contract, D-19 rev 6 (5)). */
    if (nodus_witness_vset_get(ctx->w, 0, &snap, NULL) != 0 || !snap) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "InitChain: no committed genesis validator snapshot");
        return CMT_FAULT;
    }
    if (req->validators_len != (size_t)snap->active_count) {
        QGP_LOG_ERROR(LOG_TAG, "InitChain: the request carries %zu validators, "
                      "the committed snapshot %u", req->validators_len,
                      (unsigned)snap->active_count);
        goto done;
    }
    /* A TRUE MULTISET EQUALITY, not a per-entry lookup.
     *
     * Each committed entry may be consumed AT MOST ONCE, so a request
     * carrying the same key twice cannot satisfy two positions with one
     * committed row: [A, A] against a committed [A, B] leaves B
     * unmatched and A already used, and is refused. Counting matches
     * per request entry — what this did before — accepted exactly that,
     * because each of the two A's found its one match independently.
     *
     * Unreachable through `derive_v3`, which refuses a duplicate
     * validator pubkey before anything is written
     * (nodus_witness_v2_gen.c:703-710, Rule P.3) — but InitChain's whole
     * job is to distrust the document it is handed, so it must not
     * depend on the producer's rule. With the counts equal and every
     * committed entry consumed at most once, "every request entry
     * matched" is multiset equality. */
    {
        bool used[DNAC_COMMITTEE_SIZE];

        if ((size_t)snap->active_count > DNAC_COMMITTEE_SIZE) {
            QGP_LOG_ERROR(LOG_TAG, "InitChain: the committed snapshot holds "
                          "%u validators, above the compiled committee size "
                          "%u", (unsigned)snap->active_count,
                          (unsigned)DNAC_COMMITTEE_SIZE);
            goto done;
        }
        memset(used, 0, sizeof(used));
        for (i = 0; i < req->validators_len; i++) {
            const cmt_pb_validator_update_t *v = &req->validators[i];
            bool matched = false;

            if (!v->pub_key.present) {
                QGP_LOG_ERROR(LOG_TAG, "InitChain: request validator %zu "
                              "carries no public key", i);
                goto done;
            }
            for (j = 0; j < (size_t)snap->active_count; j++) {
                uint64_t whole;

                if (used[j] ||
                    memcmp(v->pub_key.key, snap->entries[j].pubkey,
                           DNA_VSET_PUBKEY_LEN) != 0) {
                    continue;
                }
                /* THE POWER IS IN WHOLE UNITS, NOT RAW ONES.
                 * `gen_v3_row_derive` (nodus_witness_v2_gen.c:2302-2321)
                 * computes `power = self_stake / decimal_unit` — the
                 * SELF stake alone, because delegated is zero at genesis
                 * by construction (the config has no delegation input;
                 * gen.c:2315-2317 states it as a read fact, gen.h:613-621
                 * records why) — and the config's `decimal_unit` must
                 * equal the compiled DNAC_DECIMAL_UNIT (gen.c:529-533,
                 * nodus_witness_emission.h:42 = 100 000 000). Comparing
                 * against the RAW `total_stake` would refuse every real
                 * version-3 document by a factor of 10^8; `total_stake`
                 * IS the self stake at genesis for the same reason. */
                whole = snap->entries[j].total_stake / DNAC_DECIMAL_UNIT;
                if (v->power < 0 || (uint64_t)v->power != whole) {
                    QGP_LOG_ERROR(LOG_TAG, "InitChain: validator %zu's power "
                                  "%lld is not the committed stake %llu raw "
                                  "(= %llu whole units)", i,
                                  (long long)v->power,
                                  (unsigned long long)
                                      snap->entries[j].total_stake,
                                  (unsigned long long)whole);
                    goto done;
                }
                used[j] = true;
                matched = true;
                break;
            }
            if (!matched) {
                QGP_LOG_ERROR(LOG_TAG, "InitChain: request validator %zu "
                              "matches no UNUSED committed entry", i);
                goto done;
            }
        }
    }

    /* ── the response: app_hash, NO validator update, NO param update ──
     * replay.go:346-360 applies an update only when the application
     * returns one; returning none leaves the genesis document's set and
     * parameters in place, which is what D-23 rev 5 (7) requires. */
    memcpy(resp->app_hash, root, 64);
    resp->app_hash_len = 64;
    resp->validators = NULL;
    resp->validators_len = 0;
    resp->has_consensus_params = false;
    rc = CMT_OK;
done:
    dna_vset_free(&snap);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════════
 * PrepareProposal — state/execution.go:129-153, D-4 rev 3 (3)
 * ═══════════════════════════════════════════════════════════════════════ */

/** Is this envelope a chain_config transaction?
 *
 * The legacy lane keys the rule on the entry class
 * `NODUS_W_TX_CHAIN_CONFIG` (nodus_witness_bft.c:5434-5465 leader side,
 * :6264-6280 follower side). The V2 lane has no such class — every entry
 * is an ENVELOPE or a CLAIM — so the same transaction is identified by
 * what it DOES: a leg on the SYSTEM domain (DNA_DOMAIN_SYSTEM,
 * shared/dnac/ledger_ids.h:52) whose `runtime_op` is
 * DNA_SYSRULE_CHAIN_CONFIG (nodus_witness_runtime.h:82 — "runtime_op 6,
 * legacy tx 10", nodus_witness_rt_native.c:17). DEVIATION R3-C1a-3: the
 * mapping is derived from the two sites above, not written anywhere as a
 * rule.
 */
static bool env_is_chain_config(const dna_env_view_t *v)
{
    uint16_t l;

    for (l = 0; l < v->leg_count; l++) {
        if (v->leg[l].domain_id == DNA_DOMAIN_SYSTEM &&
            v->leg[l].runtime_op == DNA_SYSRULE_CHAIN_CONFIG) {
            return true;
        }
    }
    return false;
}

/**
 * ORCHESTRATOR delta 2, item A — run the ledger's whole-batch capacity
 * seam over the `n` request indices in `order` (`order[k]` is an index
 * into `txs`). Builds a LIGHTWEIGHT `nodus_witness_batch_item_t` view,
 * heap, sized to `n` (per-request, never to a caller's worst-case
 * bound), freed before every return. `cap` is the CALLER's own already-
 * established admission ceiling (`ctx->prep_bound` for PrepareProposal,
 * `ctx->env_bound` for ProcessProposal) — `n` is always <= `cap` here,
 * both call sites refuse a larger request before this function is ever
 * reached, so this is a second, cheap belt-and-braces check inside
 * `nodus_witness_v2_produce_batch_check_capped`, not a live guard.
 * @return 0 clean, -1 with `*fail_slot` naming the offending SLOT of
 *         `order`, -2 node-local fault (including an allocation
 *         failure for the view array itself).
 */
static int app_seam_check(nodus_cmt_app_ledger_t *ctx,
                          const cmt_pb_bytes_t *txs,
                          const size_t *order, size_t n, size_t cap,
                          int *fail_slot)
{
    nodus_witness_batch_item_t   *view = NULL;
    nodus_v2_batch_check_result_t result;
    int fi = 0;
    int rc;
    size_t k;

    if (fail_slot) {
        *fail_slot = 0;
    }
    if (n == 0) {
        return 0;                            /* an empty block is legal   */
    }
    view = (nodus_witness_batch_item_t *)calloc(n, sizeof(*view));
    if (!view) {
        return -2;
    }
    for (k = 0; k < n; k++) {
        const cmt_pb_bytes_t *t = &txs[order[k]];

        /* The seam reads tx_type, tx_data and tx_len only
         * (nodus_witness_v2_produce.c:369-386); the bytes are BORROWED
         * from the request and outlive this call. Classified fresh here
         * rather than threaded through a shared ctx array — delta 2
         * removed that array, and re-classifying (a leading-bytes check)
         * is cheap. */
        view[k].tx_type = nodus_witness_v2_classify_entry(t->data,
                                                           (uint32_t)t->len);
        view[k].tx_data = t->data;
        view[k].tx_len  = t->len;
    }
    memset(&result, 0, sizeof(result));
    rc = nodus_witness_v2_produce_batch_check_capped(
        ctx->w, view, (int)n, (int)cap, &fi, &result);
    if (rc == -1 && fail_slot) {
        *fail_slot = (fi >= 0 && (size_t)fi < n) ? fi : 0;
    }
    free(view);
    return rc;
}

int nodus_cmt_app_prepare_proposal(
        void *vctx, const nodus_abci_request_prepare_proposal_t *req,
        nodus_abci_response_prepare_proposal_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    size_t   n = 0, i, k, kept;
    int64_t  total = 0;
    size_t   guard;
    int      rc_out = CMT_FAULT;

    /* ORCHESTRATOR delta 2, item A — every array below is LOCAL and
     * PER-REQUEST, sized to req->txs_len (never to prep_bound's worst
     * case), freed via goto-cleanup before every return. Only
     * `new_prep_txs` survives past this function — it becomes
     * `ctx->prep_txs`, the RESPONSE buffer the ABCI ownership rule keeps
     * valid until the NEXT call to this same method. */
    uint64_t       *fee       = NULL;
    uint8_t        *class_arr = NULL;
    bool           *is_cc     = NULL;
    size_t         *order     = NULL;
    cmt_pb_bytes_t *new_prep_txs = NULL;

    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));

    /* delta 2 — THIS call is "the next call" the ABCI ownership rule
     * means: the PREVIOUS response buffer may now be freed. A FAULT
     * return below stops the node anyway (umbrella panic rule), so
     * there is no "next call" to have left it valid for. */
    free(ctx->prep_txs);
    ctx->prep_txs     = NULL;
    ctx->prep_txs_len = 0;
    ctx->prep_txs_cap = 0;

    if (req->txs_len > ctx->prep_bound) {
        /* An explicit bound, INVARIANT
         * atlas-dec-7495d3372e004b24b4f6cc7bff5caf07 — the mempool's own
         * configured size. The host reaps at most what it was
         * configured for; more than this module can hold is a
         * node-local configuration mismatch, not a peer's doing. */
        QGP_LOG_ERROR(LOG_TAG, "PrepareProposal carries %zu transactions, the "
                      "bound is %zu", req->txs_len, ctx->prep_bound);
        return CMT_FAULT;
    }
    if (req->txs_len == 0) {
        resp->txs     = NULL;
        resp->txs_len = 0;
        return CMT_OK;                       /* nothing to allocate        */
    }

    fee       = (uint64_t *)calloc(req->txs_len, sizeof(*fee));
    class_arr = (uint8_t *)calloc(req->txs_len, sizeof(*class_arr));
    is_cc     = (bool *)calloc(req->txs_len, sizeof(*is_cc));
    order     = (size_t *)calloc(req->txs_len, sizeof(*order));
    if (!fee || !class_arr || !is_cc || !order) {
        rc_out = CMT_FAULT;
        goto done;
    }

    /* ── classify and price every candidate ─────────────────────────── */
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];
        dna_env_view_t view;
        uint8_t cls;

        if (!t->data || t->len == 0) {
            continue;                        /* nothing to propose        */
        }
        cls = nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len);
        class_arr[i] = cls;
        is_cc[i]     = false;
        fee[i]       = 0;
        if (cls == NODUS_W_TX_V2_ENVELOPE) {
            memset(&view, 0, sizeof(view));
            if (dna_env_decode(t->data, t->len, &view) != 0) {
                continue;                    /* the engine would refuse it */
            }
            /* env_wire.h:53 — `fee_amount` u64 BE at offset 25. */
            fee[i]   = view.fee_amount;
            is_cc[i] = env_is_chain_config(&view);
        }
        /* A CLAIM carries no fee field (dna_claim_t has none), so its
         * ordering key is 0 and it sorts after every paying envelope.
         * DEVIATION R3-C1a-2: D-4 rev 3 (3) says "fee-descending" and
         * does not define a claim's fee. */
        order[n++] = i;
    }

    /* ── fee-descending, STABLE (ties keep arrival order) ────────────
     * Insertion sort with a strict `>` test: an element moves past an
     * earlier one only when its fee is strictly greater, so equal fees
     * stay in request order. This is the legacy mempool's own ordering
     * discipline (nodus_witness_mempool.c:59-73 inserts before the FIRST
     * entry with a strictly smaller fee). */
    for (k = 1; k < n; k++) {
        size_t cur = order[k];
        size_t j   = k;

        while (j > 0 && fee[order[j - 1]] < fee[cur]) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = cur;
    }

    /* ── a chain_config transaction rides alone ──────────────────────
     * The legacy leader keeps the chain_config entry and requeues the
     * rest (nodus_witness_bft.c:5434-5465); here the rest simply stay in
     * the mempool, because PrepareProposal only chooses. */
    for (k = 0; k < n; k++) {
        if (is_cc[order[k]]) {
            order[0] = order[k];
            n = 1;
            break;
        }
    }

    /* ── the byte budget: drop from the TAIL ─────────────────────────
     * `max_tx_bytes` bounds `ComputeProtoSizeForTxs` of the answer
     * (types/tx.go:188-192; the host validates it again at
     * nodus_witness_cmt_host.c:802 through `nodus_cmt_txs_validate`), so
     * the accumulation must use the same measure. */
    kept = 0;
    total = 0;
    for (k = 0; k < n; k++) {
        int64_t cost =
            nodus_cmt_compute_proto_size_for_tx(req->txs[order[k]].len);

        if (cost < 0 || total > req->max_tx_bytes - cost) {
            break;                           /* the tail does not fit      */
        }
        total += cost;
        kept++;
    }
    n = kept;

    /* ── ORCHESTRATOR delta 11 — the engine's own per-block ARRAY bound
     * (R3-W3-C2a-19). `n` here is envelopes AND claims mixed by request
     * position (`order[]` was built from every entry, unconditional of
     * class, at the classify step above), so capping it here bounds the
     * WHOLE proposal, not one class of it. That is enough for the
     * engine's own bounds it must never exceed: its total-claims scratch
     * (`claim_nuls[MAX_OPS][64]`, nodus_witness_v2_apply.c ~:2608, the
     * bound this delta's harness run actually broke — 40 claims in one
     * block, every node FAULTED FinalizeBlock at height 7,
     * `/tmp/stagef-20260917T034259Z`) and the universal envelope-batch
     * cap (`NODUS_V2_ENV_BATCH_MAX`, nodus_witness_v2_env.h:121, also
     * this engine's release size). It is NOT enough for the per-domain
     * `d->n_tx` bound (apply.c ~:2842/:3328/:3417): that counter
     * increments once per LEG naming a domain, not once per envelope,
     * and one envelope may carry up to DNA_ENV_MAX_LEGS (64,
     * env_wire.h:290) legs — so a single envelope with many legs on one
     * domain is not made safe by a bound on ITEM count. Nothing found
     * in `env_wire.c`/`env_preflight.c` forbids a repeated `domain_id`
     * across one envelope's legs (grepped, not found) — a real gap, but
     * apply.c's own array (`d->wire_ids[MAX_OPS][64]`) and its per-item
     * admission ordering are outside this package's whitelist; reported
     * as a RISK, not fixed here.
     *
     * Dropping the same TAIL the byte budget just dropped needs no new
     * decision: the list is still fee-descending with chain_config alone
     * first (above), so the tail is the lowest-fee remainder. Shaping
     * the proposal this way is squarely inside the Application's own
     * contract, not a deviation from it — abci++_methods.md's
     * PrepareProposal section: "The Application _can_ modify the raw
     * proposal: it can reorder, remove or add transactions... If the
     * Application considers that `tx` should not be proposed in this
     * block ... then it should not include it in
     * `PrepareProposalResponse.txs`" (spec/abci/abci++_methods.md:347-
     * 351, cometbft @709fd12b). Placed BEFORE the seam call below so an
     * over-count proposal is trimmed before the seam ever runs the
     * (much more expensive) per-item admission over items that would be
     * dropped anyway. */
    if (n > NODUS_V2_APPLY_MAX_OPS) {
        n = NODUS_V2_APPLY_MAX_OPS;
    }

    /* ── the engine's own seam: never propose what apply would refuse ──
     * O15I capacity seam. A named offender is dropped and the seam re-run
     * (the leader's own handling, nodus_witness_bft.c:5286-5296 — rc −1
     * with a trustworthy index names an entry, anything else is this
     * node's fault and opens no round); a fault stops the proposal. */
    for (guard = 0; guard <= ctx->prep_bound; guard++) {
        int fail_slot = 0;
        int rc = app_seam_check(ctx, req->txs, order, n, ctx->prep_bound,
                                &fail_slot);

        if (rc == 0) {
            break;
        }
        if (rc != -1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "PrepareProposal: the capacity seam faulted on "
                          "this node");
            rc_out = CMT_FAULT;
            goto done;
        }
        if (n == 0) {
            break;                           /* nothing left to drop: an
                                              * EMPTY block is legal       */
        }
        for (k = (size_t)fail_slot; k + 1 < n; k++) {
            order[k] = order[k + 1];
        }
        n--;
    }

    /* ── the RESPONSE buffer: ctx-owned past this return, sized to the
     * KEPT count `n`, never to prep_bound. ─────────────────────────── */
    if (n > 0) {
        new_prep_txs = (cmt_pb_bytes_t *)calloc(n, sizeof(*new_prep_txs));
        if (!new_prep_txs) {
            rc_out = CMT_FAULT;
            goto done;
        }
        for (k = 0; k < n; k++) {
            new_prep_txs[k] = req->txs[order[k]];
        }
    }
    ctx->prep_txs     = new_prep_txs;   /* NULL when n == 0, and that is
                                         * a valid empty response         */
    ctx->prep_txs_len = n;
    ctx->prep_txs_cap = n;
    resp->txs     = ctx->prep_txs;
    resp->txs_len = n;
    rc_out = CMT_OK;

done:
    free(fee);
    free(class_arr);
    free(is_cc);
    free(order);
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * ProcessProposal — state/execution.go:162-188
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_process_proposal(
        void *vctx, const nodus_abci_request_process_proposal_t *req,
        nodus_abci_response_process_proposal_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    size_t   i, n = 0;
    size_t  *order = NULL;
    int      rc;
    int      rc_out = CMT_FAULT;

    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    resp->status = NODUS_ABCI_PROPOSAL_STATUS_REJECT;

    /* A proposal is a PEER'S input: every refusal of it is a verdict
     * carried in `status`, never a return code — the host turns a
     * non-CMT_OK return into CMT_FAULT and stops the node
     * (nodus_witness_cmt_host.c:882-884). Umbrella rev 6's panic rule.
     *
     * ORCHESTRATOR delta 11 (R3-W3-C2a-19) — the engine's own per-block
     * ARRAY bound, checked FIRST and alone: the cheapest possible check
     * (one comparison against `req->txs_len`, nothing allocated, nothing
     * read from `req->txs`) and it must run before every other check so
     * a request a LATER check would otherwise spend work rejecting for
     * a different reason is still caught here. An honest proposer never
     * trips this: PrepareProposal (above) never returns more than
     * `NODUS_V2_APPLY_MAX_OPS` items, so this is coherent with it in the
     * sense abci++_methods.md requires ("PrepareProposal-ProcessProposal
     * coherence", consensus/state.go:1372-1381) — the liveness warning
     * at spec/abci/abci++_methods.md:463-464 ("applications SHOULD
     * always ACCEPT unless they really know the liveness implications
     * of REJECT") does not apply to a REJECT an honest round never
     * reaches. `ProcessProposalResponse.status == REJECT` is exactly
     * what turns into a nil prevote (abci++_methods.md:456-457, 488-490;
     * `defaultDoPrevote`, consensus/state.go:1382-1396 — `!isAppValid`
     * signs a nil vote instead of the proposal's block). */
    if (req->txs_len > NODUS_V2_APPLY_MAX_OPS) {
        QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu transactions exceed "
                     "the engine's per-block item bound %u — refused "
                     "before any per-item work", req->txs_len,
                     (unsigned)NODUS_V2_APPLY_MAX_OPS);
        return CMT_OK;                       /* status stays REJECT        */
    }

    /* ORCHESTRATOR delta 2, item A: env_bound, NOT prep_bound. delta 1
     * narrowed this to prep_bound because prep_class/prep_order/
     * seam_entry/seam_ptr were SHARED, fixed-size, ctx-owned arrays
     * sized to prep_bound for memory reasons. delta 2 makes every array
     * here per-request and local, so there is no fixed array left for a
     * 5 000-item narrowing to protect, and the reference imposes no such
     * rule on ProcessProposal — its only ceiling is the byte-derived
     * physical limit, the SAME one FinalizeBlock already uses. A count
     * above env_bound is therefore MALFORMED under this chain's own
     * consensus params (D-4 rev 3) and refused as a proposal verdict
     * (REJECT), before anything is allocated for it. */
    if (req->txs_len > ctx->env_bound) {
        QGP_LOG_WARN(LOG_TAG, "ProcessProposal: %zu transactions exceed "
                     "env_bound %zu — malformed under this chain's own "
                     "consensus params", req->txs_len, ctx->env_bound);
        return CMT_OK;                       /* status stays REJECT        */
    }
    if (req->txs_len > 0) {
        order = (size_t *)calloc(req->txs_len, sizeof(*order));
        if (!order) {
            return CMT_FAULT;
        }
    }
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];

        if (!t->data || t->len == 0) {
            rc_out = CMT_OK;                 /* an empty item: REJECT      */
            goto done;
        }
        order[n++] = i;
    }
    rc = app_seam_check(ctx, req->txs, order, n, ctx->env_bound, NULL);
    if (rc == -2) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "ProcessProposal: the capacity seam faulted on this "
                      "node — no verdict about the proposal");
        rc_out = CMT_FAULT;
        goto done;
    }
    if (rc == 0) {
        resp->status = NODUS_ABCI_PROPOSAL_STATUS_ACCEPT;
    }
    rc_out = CMT_OK;

done:
    free(order);
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * The vote-extension pair — abci/types/application.go:100-108
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_extend_vote(void *vctx,
                              const nodus_abci_request_extend_vote_t *req,
                              nodus_abci_response_extend_vote_t *resp)
{
    (void)req;
    if (!vctx || !resp) {
        return CMT_FAULT;
    }
    /* :100-102 — `&ResponseExtendVote{}`: an EMPTY extension. Vote
     * extensions are off (VoteExtensionsEnableHeight 0, D-4 rev 3 (2)),
     * so no committed block reaches this row. */
    memset(resp, 0, sizeof(*resp));
    return CMT_OK;
}

int nodus_cmt_app_verify_vote_extension(
        void *vctx, const nodus_abci_request_verify_vote_extension_t *req,
        nodus_abci_response_verify_vote_extension_t *resp)
{
    (void)req;
    if (!vctx || !resp) {
        return CMT_FAULT;
    }
    /* :104-108 — Status ACCEPT. */
    memset(resp, 0, sizeof(*resp));
    resp->status = NODUS_ABCI_VERIFY_STATUS_ACCEPT;
    return CMT_OK;
}

/* ═══════════════════════════════════════════════════════════════════════
 * FinalizeBlock — state/execution.go:224-258's callee: the ledger's
 * cometbft apply lane (D-23 rev 5 (6))
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_finalize_block(void *vctx,
                                 const nodus_abci_request_finalize_block_t *req,
                                 nodus_abci_response_finalize_block_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    nodus_v2_block_t       *blk = NULL;
    size_t i, n_env = 0, n_claim = 0;
    size_t claim_alloc;
    int    rc;
    int    rc_out = CMT_FAULT;

    /* ORCHESTRATOR delta 2, item A — every array below is LOCAL and
     * PER-REQUEST, sized to req->txs_len (fb_claim capped additionally
     * at claim_bound — see claim_alloc below), freed via goto-cleanup
     * before every return. Only `new_fb_pb` survives past this
     * function — it becomes `ctx->fb_pb`, the RESPONSE buffer the ABCI
     * ownership rule keeps valid until the NEXT call to this method. */
    uint8_t                        *class_arr = NULL;
    size_t                         *of_arr    = NULL;
    nodus_v2_envelope_t            *env_arr   = NULL;
    dna_claim_t                    *claim_arr = NULL;
    nodus_v2_tx_result_t           *results_arr = NULL;
    cmt_pb_stored_exec_tx_result_t *new_fb_pb   = NULL;

    if (resp) {
        memset(resp, 0, sizeof(*resp));
    }
    if (!ctx || !ctx->w || !req || !resp) {
        return CMT_FAULT;
    }

    /* delta 2 — THIS call is "the next call" the ABCI ownership rule
     * means for FinalizeBlock's own response: the PREVIOUS tx_results
     * buffer may now be freed. A FAULT return below stops the node
     * anyway (umbrella panic rule). */
    free(ctx->fb_pb);
    ctx->fb_pb     = NULL;
    ctx->fb_pb_cap = 0;

    /* env_bound, not the retired NODUS_CMT_APP_MAX_TXS — the byte-derived
     * count no honestly-decided block (Block.MaxBytes, D-4 rev 3) can
     * physically exceed. A decided block is never refused with a
     * verdict, but this can only be reached by a physically-impossible
     * request given the chain's own consensus params — a node-local
     * configuration mismatch, not anyone's transaction's fault. */
    if (req->txs_len > ctx->env_bound) {
        QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock carries %zu transactions, "
                      "the byte-derived bound is %zu", req->txs_len,
                      ctx->env_bound);
        return CMT_FAULT;
    }
    /* ORCHESTRATOR delta 4, item A — `results_arr` is allocated on BOTH
     * branches, unconditionally, even when `req->txs_len == 0`: the
     * engine's own precondition (nodus_witness_v2_apply.c:2185-2191, NOT
     * this file's whitelist) refuses `blk->cmt.results == NULL`
     * BEFORE it ever looks at the count, so a NULL array stops the node
     * on the very first EMPTY decided block — and under D-4 rev 3 a
     * quiet chain produces one every `create_empty_blocks_interval`
     * (60 s), so this is not a corner case, it is the FIRST block a
     * quiet chain ever applies. `calloc(0, …)` is never relied on here —
     * its result is implementation-defined and this tree builds for
     * Windows/Android too — so the count passed to calloc is
     * `req->txs_len ? req->txs_len : 1` while `results_cap` (read at
     * :1169 below) stays the true `req->txs_len` (0 for an empty block):
     * the engine only ever reads `results[0..n_envs+n_claims)`, which is
     * the empty range when both are 0, so the one extra slot calloc'd
     * for the NULL-avoidance is never touched. */
    results_arr = (nodus_v2_tx_result_t *)
        calloc(req->txs_len ? req->txs_len : 1, sizeof(*results_arr));
    if (!results_arr) {
        rc_out = CMT_FAULT;
        goto done;
    }
    if (req->txs_len == 0) {
        /* An empty decided block: still applied (n_envs=n_claims=0 is
         * legal); `class_arr`/`of_arr`/`env_arr`/`claim_arr` stay NULL —
         * every loop below is bounded by `req->txs_len` (0), so none of
         * them is ever indexed. Only `results_arr` above needs the
         * NULL-avoidance, because the engine reads `blk->cmt.results`
         * itself before consulting the counts. */
    } else {
        /* delta 2: fb_claim capped at claim_bound (~2 972), NEVER at
         * req->txs_len (up to env_bound, ~293 525) — a claim's own
         * minimum wire size is two orders of magnitude larger than an
         * envelope's, so allocating dna_claim_t VALUES (~11.6 KB each)
         * at env_bound scale would be the multi-gigabyte mistake this
         * whole delta exists to avoid. The `n_claim >= claim_alloc`
         * guard below (unchanged logic from delta 1) still protects
         * against the physically-impossible case of MORE claims than
         * that within one request. */
        claim_alloc = (req->txs_len < ctx->claim_bound)
                          ? req->txs_len : ctx->claim_bound;

        class_arr   = (uint8_t *)calloc(req->txs_len, sizeof(*class_arr));
        of_arr      = (size_t *)calloc(req->txs_len, sizeof(*of_arr));
        env_arr     = (nodus_v2_envelope_t *)calloc(req->txs_len,
                                                    sizeof(*env_arr));
        /* results_arr is already allocated above, unconditionally
         * (delta 4, item A) — not repeated here. */
        claim_arr   = claim_alloc
            ? (dna_claim_t *)calloc(claim_alloc, sizeof(*claim_arr))
            : NULL;
        if (!class_arr || !of_arr || !env_arr ||
            (claim_alloc && !claim_arr)) {
            rc_out = CMT_FAULT;
            goto done;
        }
    }

    /* ── classify, and split the two item kinds out ──────────────────
     * D-23 rev 5 (6): "an item that does not even decode is a per-item
     * failure, not a block failure". The classification boundary is
     * here: bytes the ONE byte-driven authority
     * (`nodus_witness_v2_classify_entry`) calls an ENVELOPE go to the
     * engine's envelope list, bytes it calls a CLAIM are decoded and go
     * to its claim list, and a claim whose bytes do not decode is coded
     * here — the engine never sees it.
     *
     * The engine applies both kinds per item; the block never fails
     * because one of them did. */
    for (i = 0; i < req->txs_len; i++) {
        const cmt_pb_bytes_t *t = &req->txs[i];

        class_arr[i] = (t->data && t->len)
            ? nodus_witness_v2_classify_entry(t->data, (uint32_t)t->len)
            : (uint8_t)0;
        of_arr[i] = (size_t)-1;
        if (class_arr[i] == NODUS_W_TX_V2_ENVELOPE) {
            env_arr[n_env].env_bytes = t->data;
            env_arr[n_env].env_len   = t->len;
            of_arr[i] = n_env;
            n_env++;
        } else if (class_arr[i] == NODUS_W_TX_V2_CLAIM) {
            /* claim_alloc (== MIN(req->txs_len, claim_bound)) is the
             * true physical ceiling for THIS request; reaching it is the
             * same class of node-local impossibility as the txs_len
             * guard above, NOT a peer's malformed bytes — treated
             * identically to a claim that does not decode (D-23 rev 5
             * (6): a per-item failure, not a block failure) so a decided
             * block is never refused a verdict here, and logged loudly
             * because it should never actually happen. */
            if (n_claim >= claim_alloc) {
                QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: claim count would "
                              "exceed this request's claim bound %zu at "
                              "block position %zu — coding this item as a "
                              "decode failure rather than overflowing "
                              "the claim array", claim_alloc, i);
            } else if (dna_claim_decode(t->data, t->len,
                                        &claim_arr[n_claim]) == 0) {
                of_arr[i] = n_claim;
                n_claim++;
            }
            /* a claim that does not decode (or would overflow the
             * derived bound above) keeps of_arr[i] == -1 and is coded
             * below; its bytes never reach the engine */
        }
    }

    /* ── the engine, ONCE, inside the host's transaction ─────────── */
    blk = (nodus_v2_block_t *)calloc(1, sizeof(*blk));
    if (!blk) {
        rc_out = CMT_FAULT;
        goto done;
    }
    blk->global_height = (uint64_t)req->height;
    blk->epoch = nodus_v2_epoch_for_height(blk->global_height);
    memcpy(blk->proposer_id, req->proposer_address,
           req->proposer_address_len > 32 ? 32 : req->proposer_address_len);
    /* `timestamp` is informational in the engine and enters no identity
     * (nodus_v2_block_t's contract); the block's real time is the Comet
     * header's, which consensus owns. */
    blk->timestamp = (uint64_t)req->time.seconds;
    blk->envs = n_env ? env_arr : NULL;
    blk->n_envs = n_env;
    blk->claims = n_claim ? claim_arr : NULL;
    blk->n_claims = n_claim;
    blk->cmt.on = true;
    memcpy(blk->cmt.block_hash, req->hash,
           req->hash_len > 64 ? 64 : req->hash_len);
    /* `v2_blocks.vset_hash` receives the request's NEXT-validators hash
     * — the only validator hash `RequestFinalizeBlock` carries
     * (execution.go:226). D-17 rev 7 (6) calls the column "the block's
     * ValidatorsHash"; the two coincide only while validator updates are
     * empty. REGISTER ROW R3-C1a-10, stated in full at
     * nodus_v2_block_cmt_t.validators_hash. */
    memcpy(blk->cmt.validators_hash, req->next_validators_hash,
           req->next_validators_hash_len > 64
               ? 64 : req->next_validators_hash_len);
    blk->cmt.results = results_arr;
    /* delta 2: results_arr is sized to req->txs_len itself (this
     * request's own true worst case for n_env + n_claim), not to
     * env_bound — the per-request array already IS the tight bound. */
    blk->cmt.results_cap = req->txs_len;
    blk->fail_at = ctx->test_fail_at;    /* TEST-ONLY; 0 = no injection */
    blk->fail_env_index    = ctx->test_fail_env_index;
    blk->fail_effect_index = ctx->test_fail_effect_index;

    rc = nodus_witness_v2_apply_block(ctx->w, blk);
    if (rc != 0) {
        /* The lane's rule: a decided block is never refused, so the only
         * negative the engine can return here is a node-local fault and
         * the host must roll back and stop. The engine's own reason is
         * logged because it names the check that failed.
         *
         * ORCHESTRATOR delta 11 (R3-W3-C2a-19): the engine's own
         * per-block ARRAY bound (`nodus_witness_v2_apply.c`'s FAULT
         * naming `MAX_OPS`) is the LAST line of defence, never the
         * first — an honest proposer/validator pair never reaches it,
         * because `nodus_cmt_app_prepare_proposal` (above) never packs
         * more than `NODUS_V2_APPLY_MAX_OPS` items and
         * `nodus_cmt_app_process_proposal` (above) REJECTs any proposal
         * that carries more before doing any per-item work. A decided
         * block reaching this FAULT with more than that bound means
         * both of those gates were bypassed — +2/3 of the validators
         * decided a block no honest node running this application could
         * have proposed or accepted, the reference's "byzantine +2/3
         * committed an invalid block" class (umbrella panic rule,
         * atlas-dec-d5e766defde138eb6dd02e5b81e735a8, rev 6 in this
         * tree — the dispatch that named this delta cited "umbrella rev
         * 4"; this tree's own governing record is rev 6, cited as read,
         * not the dispatch's number) — this node stopping is correct. */
        QGP_LOG_ERROR(LOG_TAG, "FinalizeBlock: the ledger could not apply "
                      "the decided block at height %" PRId64 " (rc %d): %s",
                      req->height, rc, blk->out_reason);
        rc_out = CMT_FAULT;
        goto done;
    }

    /* ── the RESPONSE buffer: ctx-owned past this return, sized to
     * req->txs_len (one result per block position), never to env_bound. */
    if (req->txs_len > 0) {
        new_fb_pb = (cmt_pb_stored_exec_tx_result_t *)
            calloc(req->txs_len, sizeof(*new_fb_pb));
        if (!new_fb_pb) {
            rc_out = CMT_FAULT;
            goto done;
        }
    }

    /* ── one ExecTxResult per item, in BLOCK ORDER ─────────────────
     * The engine's results are envelopes first then claims, each in its
     * own order; `of_arr` maps a block position back to its slot in
     * whichever list it went to. */
    for (i = 0; i < req->txs_len; i++) {
        cmt_pb_stored_exec_tx_result_t *r = &new_fb_pb[i];
        const nodus_v2_tx_result_t     *e = NULL;

        memset(r, 0, sizeof(*r));
        if (of_arr[i] != (size_t)-1) {
            if (class_arr[i] == NODUS_W_TX_V2_ENVELOPE) {
                e = &blk->cmt.results[of_arr[i]];
            } else {
                e = &blk->cmt.results[n_env + of_arr[i]];
            }
        }
        if (e) {
            r->det.code       = e->code;
            r->det.gas_wanted = (int64_t)e->gas_wanted;
            r->det.gas_used   = (int64_t)e->gas_used;
        } else {
            /* bytes the engine never saw: a claim that does not decode,
             * or an empty item. The classification boundary's own code
             * (D-23 rev 5 (6)). */
            r->det.code = NODUS_V2_TX_ERR_DECODE;
        }
        /* `data` stays EMPTY — one of the two values D-23 rev 4 allows.
         * The engine retains no per-item effect bytes (apply.h's
         * nodus_v2_tx_result_t says why), so producing them would mean
         * changing exec_one_env's contract. Reported as a gap. */
    }
    ctx->fb_pb     = new_fb_pb;
    ctx->fb_pb_cap = req->txs_len;
    resp->tx_results = ctx->fb_pb;
    resp->tx_results_cap = req->txs_len;   /* delta 2: per-request */
    resp->tx_results_len = req->txs_len;

    /* app_hash = the ledger's global state root AFTER this block
     * (D-23 rev 4 (3)); consensus binds it as the NEXT header's AppHash
     * (D-19 rev 6 (1)). */
    memcpy(resp->app_hash, blk->out_global_root, 64);
    resp->app_hash_len = 64;

    /* validator_updates EMPTY in W2 — a NAMED GAP, not a statement that
     * the set never changes. The epoch boundary that graduates and
     * retires validators runs inside the apply (D-23 rev 4 (3): "validator
     * updates at the epoch boundary, power = stake"), and turning its
     * result into ABCI ValidatorUpdates is R3-T's. Until it is wired, a
     * Comet chain's validator set never moves. */
    resp->validator_updates = NULL;
    resp->validator_updates_len = 0;
    resp->has_consensus_param_updates = false;   /* none, D-23 rev 4 (3) */
    resp->events_len = 0;                        /* no events (YOK)      */

    rc_out = CMT_OK;

done:
    free(blk);
    free(class_arr);
    free(of_arr);
    free(env_arr);
    free(claim_arr);
    free(results_arr);
    return rc_out;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Commit — the COMMIT of the host's ONE transaction, D-23 rev 5 (5)
 * ═══════════════════════════════════════════════════════════════════════ */

int nodus_cmt_app_commit(void *vctx, nodus_abci_response_commit_t *resp)
{
    nodus_cmt_app_ledger_t *ctx = (nodus_cmt_app_ledger_t *)vctx;
    char *err = NULL;

    if (!ctx || !ctx->w || !ctx->w->db || !resp) {
        return CMT_FAULT;
    }
    memset(resp, 0, sizeof(*resp));
    /* The host opened the transaction before FinalizeBlock. Being outside
     * one here means the bracket was never opened or was already closed —
     * a node-local invariant broken, never a peer's doing: CMT_FAULT. */
    if (sqlite3_get_autocommit(ctx->w->db)) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "Commit called outside the host's transaction");
        return CMT_FAULT;
    }
    if (sqlite3_exec(ctx->w->db, "COMMIT", NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "COMMIT failed: %s", err ? err : "?");
        sqlite3_free(err);
        return CMT_FAULT;
    }
    /* `retain_height` 0: this application asks for no pruning in W2, so
     * `pruneBlocks` (execution.go:309-316) is not entered. */
    resp->retain_height = 0;
    return CMT_OK;
}
