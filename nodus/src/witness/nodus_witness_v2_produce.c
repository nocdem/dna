/**
 * @file nodus/src/witness/nodus_witness_v2_produce.c
 * @brief Ledger V2 O15D — successor block production over the ONE engine.
 *
 * Contract, scope and the QC-formation rationale: nodus_witness_v2_produce.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_qc.h"
#include "witness/nodus_witness_v2_result.h"
#include "witness/nodus_witness_v2_env.h"     /* the pre-commit seam    */
#include "witness/nodus_witness_domreg.h"     /* committed ruleset ctx  */
#include "witness/nodus_witness_db.h"
#include "server/nodus_server.h"       /* w->server->identity (sign key) */

#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "dnac/ledger_ids.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2PROD"

/* ── tip ────────────────────────────────────────────────────────────── */

int nodus_witness_v2_tip_height(nodus_witness_t *w, uint64_t *height_out) {
    if (!w || !w->db || !height_out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    *height_out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return 0;
}

/* ── pool helpers ───────────────────────────────────────────────────── */

/* Our snapshot-convention voter id: SHA3-512(pubkey)[0..31] — the
 * DNA.VSET.v1 entry derivation (vset_wire.h), never the roster id. */
static int prod_my_voter_id(nodus_witness_t *w, uint8_t out[32]) {
    uint8_t full[64];
    if (!w->server) return -1;
    if (qgp_sha3_512(w->server->identity.pk.bytes, NODUS_PK_BYTES,
                     full) != 0)
        return -1;
    memcpy(out, full, 32);
    return 0;
}

static void prod_pool_reset(nodus_witness_t *w, uint64_t height) {
    memset(&w->v2_certpool, 0, sizeof(w->v2_certpool));
    w->v2_certpool.height = height;
}

/* Insert (dedup by voter). Returns 1 inserted, 0 duplicate/full. */
static int prod_pool_insert(nodus_witness_t *w, const uint8_t voter_id[32],
                            const uint8_t block_id[64],
                            const uint8_t sig[NODUS_SIG_BYTES]) {
    for (uint32_t i = 0; i < w->v2_certpool.n; i++) {
        if (memcmp(w->v2_certpool.slots[i].voter_id, voter_id, 32) == 0)
            return 0;                       /* keep-first, one per voter */
    }
    if (w->v2_certpool.n >= DNAC_MAX_ACTIVE_VALIDATORS) return 0;
    uint32_t i = w->v2_certpool.n++;
    memcpy(w->v2_certpool.slots[i].voter_id, voter_id, 32);
    memcpy(w->v2_certpool.slots[i].block_id, block_id, 64);
    memcpy(w->v2_certpool.slots[i].sig, sig, NODUS_SIG_BYTES);
    return 1;
}

static int prod_cert_cmp(const void *a, const void *b) {
    return memcmp(((const dna_qc_v2_cert_t *)a)->voter_id,
                  ((const dna_qc_v2_cert_t *)b)->voter_id,
                  DNA_CERT_V2_VOTER_ID_LEN);
}

/* ── QC assembly ────────────────────────────────────────────────────── */

int nodus_witness_v2_qc_try_attach(nodus_witness_t *w) {
    if (!w || !w->db || !w->v2_successor) return -1;
    if (!w->v2_certpool.committed || w->v2_certpool.height == 0) return 1;
    if (w->v2_certpool.qc_attached) return 0;

    uint64_t h = w->v2_certpool.height;

    /* Committed authority for this height — the O12 resolver. Absent
     * authority here is a node-local condition; never a verdict. */
    dna_vset_snapshot_t *snap = NULL;
    uint32_t n = 0, quorum = 0;
    if (nodus_witness_v2_epoch_authority_for_height(w, h, &snap, &n,
                                                    &quorum) != 0 || !snap)
        return -1;

    /* Verify every pooled cert that matches OUR committed BlockID against
     * the snapshot's frozen pubkeys. Bad entries are skipped, not judged. */
    dna_qc_v2_cert_t *valid = calloc((size_t)n, sizeof(*valid));
    if (!valid) { dna_vset_free(&snap); return -1; }
    uint32_t n_valid = 0;

    for (uint32_t i = 0; i < w->v2_certpool.n && n_valid < n; i++) {
        if (memcmp(w->v2_certpool.slots[i].block_id,
                   w->v2_certpool.local_block_id, 64) != 0)
            continue;                       /* diverged sender — skip    */
        const uint8_t *pk = NULL;
        for (uint16_t e = 0; e < snap->active_count; e++) {
            if (memcmp(snap->entries[e].voter_id,
                       w->v2_certpool.slots[i].voter_id, 32) == 0) {
                pk = snap->entries[e].pubkey;
                break;
            }
        }
        if (!pk) continue;                  /* not a member — skip       */
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(w->v2_certpool.local_block_id,
                                 w->v2_certpool.slots[i].voter_id, h,
                                 w->v2_chain32, w->v2_certpool.vset_hash,
                                 pre) != 0)
            continue;
        if (qgp_dsa87_verify(w->v2_certpool.slots[i].sig,
                             DNA_CERT_V2_SIG_LEN, pre, sizeof(pre),
                             pk) != 0)
            continue;                       /* invalid — skip            */
        /* dedup among valid (pool already dedups by voter) */
        memcpy(valid[n_valid].voter_id,
               w->v2_certpool.slots[i].voter_id, 32);
        memcpy(valid[n_valid].sig, w->v2_certpool.slots[i].sig,
               DNA_CERT_V2_SIG_LEN);
        n_valid++;
    }

    if (n_valid < quorum) {
        free(valid);
        dna_vset_free(&snap);
        return 1;                           /* not yet                   */
    }

    /* Canonical QC: strictly ascending voter ids. */
    qsort(valid, (size_t)n_valid, sizeof(valid[0]), prod_cert_cmp);

    int ret = -1;
    dna_qc_v2_t *qc = dna_qc_v2_alloc((uint16_t)n_valid);
    uint8_t *qc_bytes = NULL;
    sqlite3_stmt *st = NULL;
    do {
        if (!qc) break;
        memcpy(qc->certs, valid, (size_t)n_valid * sizeof(valid[0]));

        /* The stored canonical header — decode, then hand the assembled
         * QC to the ONE verifier before anything durable happens. */
        uint8_t hdr_bytes[DNA_BH2_ENC_SIZE];
        if (sqlite3_prepare_v2(w->db,
                "SELECT header, block_id FROM v2_blocks "
                "WHERE global_height = ?1", -1, &st, NULL) != SQLITE_OK)
            break;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        if (sqlite3_step(st) != SQLITE_ROW ||
            sqlite3_column_bytes(st, 0) != DNA_BH2_ENC_SIZE ||
            sqlite3_column_bytes(st, 1) != 64 ||
            memcmp(sqlite3_column_blob(st, 1),
                   w->v2_certpool.local_block_id, 64) != 0)
            break;
        memcpy(hdr_bytes, sqlite3_column_blob(st, 0), DNA_BH2_ENC_SIZE);
        sqlite3_finalize(st);
        st = NULL;

        dna_block_header_v2_t hdr;
        if (dna_bh2_decode(hdr_bytes, sizeof(hdr_bytes), &hdr) != 0) break;
        if (nodus_witness_v2_qc_verify(w, &hdr, qc) != 0) break;

        size_t cap = dna_qc_v2_encoded_len(qc);
        size_t used = 0;
        if (cap == 0) break;
        qc_bytes = malloc(cap);
        if (!qc_bytes) break;
        if (dna_qc_v2_encode(qc, qc_bytes, cap, &used) != 0) break;

        if (sqlite3_prepare_v2(w->db,
                "UPDATE v2_blocks SET qc = ?1 WHERE global_height = ?2 "
                "AND block_id = ?3 AND qc IS NULL", -1, &st, NULL)
            != SQLITE_OK)
            break;
        sqlite3_bind_blob(st, 1, qc_bytes, (int)used, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)h);
        sqlite3_bind_blob(st, 3, w->v2_certpool.local_block_id, 64,
                          SQLITE_STATIC);
        if (sqlite3_step(st) != SQLITE_DONE) break;
        /* changes 0 = a QC is already there (attached earlier / by a
         * replayed drain) — same terminal state, idempotent. */
        w->v2_certpool.qc_attached = true;
        QGP_LOG_INFO(LOG_TAG, "QC attached at height %llu (%u certs, "
                     "quorum %u of %u)", (unsigned long long)h,
                     (unsigned)n_valid, (unsigned)quorum, (unsigned)n);
        ret = 0;
    } while (0);

    if (st) sqlite3_finalize(st);
    free(qc_bytes);
    if (qc) dna_qc_v2_free(&qc);
    free(valid);
    dna_vset_free(&snap);
    return ret == 0 ? 0 : (w->v2_certpool.qc_attached ? 0 : -1);
}

/* ── cert collection ────────────────────────────────────────────────── */

void nodus_witness_v2_cert_note(nodus_witness_t *w,
                                uint64_t height,
                                const uint8_t voter_id[32],
                                const uint8_t block_id[64],
                                const uint8_t sig[NODUS_SIG_BYTES]) {
    if (!w || !w->v2_successor || !voter_id || !block_id || !sig) return;
    if (height == 0) return;

    if (w->v2_certpool.height != height) {
        /* Accept only the next height this node would commit — bounded
         * by construction; anything else is noise or far drift. */
        uint64_t tip = 0;
        if (nodus_witness_v2_tip_height(w, &tip) != 0) return;
        if (height != tip + 1) return;
        /* A superseded pool gets one last assembly chance before reset. */
        if (w->v2_certpool.committed && !w->v2_certpool.qc_attached)
            (void)nodus_witness_v2_qc_try_attach(w);
        prod_pool_reset(w, height);
    }
    (void)prod_pool_insert(w, voter_id, block_id, sig);
    if (w->v2_certpool.committed)
        (void)nodus_witness_v2_qc_try_attach(w);
}

/* ── batch pre-check (the engine's seam, at the candidate height) ───── */

int nodus_witness_v2_produce_batch_check(nodus_witness_t *w,
                                         nodus_witness_mempool_entry_t **entries,
                                         int count,
                                         int *fail_index_out) {
    if (fail_index_out) *fail_index_out = 0;
    if (!w || !w->db || !w->v2_successor || !entries || count <= 0 ||
        count > NODUS_W_MAX_BLOCK_TXS)
        return -2;

    nodus_v2_envelope_t envs[NODUS_W_MAX_BLOCK_TXS];
    for (int i = 0; i < count; i++) {
        if (!entries[i] || entries[i]->tx_type != NODUS_W_TX_V2_ENVELOPE ||
            !entries[i]->tx_data || entries[i]->tx_len == 0) {
            if (fail_index_out) *fail_index_out = i;
            return -1;
        }
        envs[i].env_bytes = entries[i]->tx_data;
        envs[i].env_len   = entries[i]->tx_len;
    }

    /* Contextual ruleset table: one entry per distinct leg domain across
     * the batch, from the COMMITTED registry (the engine's authority),
     * sorted ascending as the seam requires. */
    dna_env_leg_ctx_t rulesets[DNA_ENV_MAX_LEGS];
    size_t n_rulesets = 0;
    for (int i = 0; i < count; i++) {
        dna_env_view_t view;
        if (dna_env_decode(envs[i].env_bytes, envs[i].env_len,
                           &view) != 0) {
            if (fail_index_out) *fail_index_out = i;
            return -1;
        }
        for (uint16_t l = 0; l < view.leg_count; l++) {
            uint32_t dom = view.leg[l].domain_id;
            size_t k = 0;
            while (k < n_rulesets && rulesets[k].domain_id < dom) k++;
            if (k < n_rulesets && rulesets[k].domain_id == dom) continue;
            if (n_rulesets >= DNA_ENV_MAX_LEGS) {
                if (fail_index_out) *fail_index_out = i;
                return -1;
            }
            dna_domain_manifest_t man;
            if (nodus_witness_domreg_get(w, dom, NULL, &man, NULL) != 0) {
                if (fail_index_out) *fail_index_out = i;
                return -1;                 /* unregistered domain        */
            }
            memmove(&rulesets[k + 1], &rulesets[k],
                    (n_rulesets - k) * sizeof(rulesets[0]));
            rulesets[k].domain_id       = dom;
            rulesets[k].ruleset_version = man.ruleset_version;
            memcpy(rulesets[k].ruleset_hash, man.ruleset_hash,
                   DNA_ENV_RULESET_HASH_LEN);
            n_rulesets++;
        }
    }
    if (n_rulesets == 0) return -1;

    uint64_t candidate = 0;
    if (nodus_witness_v2_tip_height(w, &candidate) != 0) return -2;
    candidate += 1;

    dna_env_preflight_t *pf =
        calloc((size_t)count, sizeof(dna_env_preflight_t));
    if (!pf) return -2;
    size_t fail_i = 0;
    dna_env_preflight_status_t pst = DNA_ENV_PF_OK;
    nodus_v2_env_status_t est = nodus_witness_v2_env_preflight_batch(
        w, candidate, rulesets, n_rulesets, envs, (size_t)count, pf,
        &fail_i, &pst);
    free(pf);
    if (est != NODUS_V2_ENV_OK) {
        if (fail_index_out)
            *fail_index_out = (int)(fail_i < (size_t)count ? fail_i : 0);
        QGP_LOG_WARN(LOG_TAG, "batch pre-check rejected entry %zu "
                     "(seam=%d pf=%d)", fail_i, (int)est, (int)pst);
        return -1;
    }
    return 0;
}

/* ── the commit handoff ─────────────────────────────────────────────── */

int nodus_witness_v2_produce_commit(nodus_witness_t *w,
                                    nodus_witness_mempool_entry_t **entries,
                                    int count,
                                    uint64_t height,
                                    uint64_t timestamp,
                                    const uint8_t *proposer_id,
                                    const uint8_t *expected_global_root,
                                    nodus_v2_produce_out_t *out) {
    if (!w || !w->db || !w->v2_successor || !entries || count <= 0 ||
        count > NODUS_W_MAX_BLOCK_TXS || !proposer_id || !out)
        return -2;
    memset(out, 0, sizeof(*out));

    nodus_v2_envelope_t envs[NODUS_W_MAX_BLOCK_TXS];
    for (int i = 0; i < count; i++) {
        nodus_witness_mempool_entry_t *e = entries[i];
        if (!e || e->tx_type != NODUS_W_TX_V2_ENVELOPE || !e->tx_data ||
            e->tx_len == 0)
            return -1;                      /* not a successor batch     */
        envs[i].env_bytes = e->tx_data;
        envs[i].env_len   = e->tx_len;
    }

    /* The engine block: identity is ENGINE-derived; the only header
     * material supplied is what it cannot derive (proposer, timestamp —
     * both agreed by the round, identical on every node). The follower
     * assertion channel carries the COMMIT frame's global root. */
    nodus_v2_block_t *blk = calloc(1, sizeof(*blk));
    if (!blk) return -2;
    blk->global_height = height;
    blk->epoch         = nodus_v2_epoch_for_height(height);
    memcpy(blk->proposer_id, proposer_id, 32);
    blk->timestamp     = timestamp;
    blk->envs          = envs;
    blk->n_envs        = (size_t)count;
    blk->expect_global_root = expected_global_root;

    int rc = nodus_witness_v2_apply_block(w, blk);

    if (rc == NODUS_V2_CONSENSUS_INVALID) {
        QGP_LOG_ERROR(LOG_TAG, "successor block %llu REJECTED by the "
                      "engine (deterministic verdict)",
                      (unsigned long long)height);
        free(blk);
        return -1;
    }
    if (rc != NODUS_V2_ACCEPTED && rc != NODUS_V2_ACCEPTED_PRECACHE) {
        /* -2 fault, -3 not-yet-linkable, retired/unsupported cannot
         * arise here — all: this NODE could not commit; stay silent.
         * NOTE the engine's rc 1 (idempotent replay) is UNREACHABLE on
         * this path by construction: it is unlocked only by an
         * expect_block_id assertion, which produce never supplies (the
         * round machinery's already-committed guards sit in front of
         * this call — bft.c handle_vote/handle_commit round checks). */
        QGP_LOG_ERROR(LOG_TAG, "successor block %llu did not commit "
                      "(engine rc=%d — node-local, no verdict)",
                      (unsigned long long)height, rc);
        free(blk);
        return -2;
    }

    const uint8_t *global_root = blk->out_global_root;

    for (int i = 0; i < count; i++) {
        entries[i]->committed_block_height = height;
        entries[i]->committed_tx_index     = (uint32_t)i;
    }

    memcpy(out->block_id, blk->out_block_id, 64);
    memcpy(out->global_root, global_root, 64);

    /* Pool: adopt this height (keeping any certs that raced ahead). */
    if (w->v2_certpool.height != height) {
        if (w->v2_certpool.committed && !w->v2_certpool.qc_attached)
            (void)nodus_witness_v2_qc_try_attach(w);
        prod_pool_reset(w, height);
    }
    w->v2_certpool.committed = true;
    memcpy(w->v2_certpool.local_block_id, blk->out_block_id, 64);
    memcpy(w->v2_certpool.vset_hash, blk->out_vset_hash, 64);

    /* Our own DNA.CERT.v2 certificate over the id we DERIVED. A signing
     * failure loses only our certificate — the block stays committed. */
    uint8_t my_voter[32];
    uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
    if (prod_my_voter_id(w, my_voter) == 0 &&
        dna_cert_v2_preimage(blk->out_block_id, my_voter, height,
                             w->v2_chain32, blk->out_vset_hash, pre) == 0) {
        uint8_t sig[NODUS_SIG_BYTES];
        size_t  siglen = 0;
        memset(sig, 0, sizeof(sig));
        if (qgp_dsa87_sign(sig, &siglen, pre, sizeof(pre),
                           w->server->identity.sk.bytes) == 0 &&
            siglen <= NODUS_SIG_BYTES) {
            memcpy(out->cert_sig, sig, NODUS_SIG_BYTES);
            out->have_cert = 1;
            (void)prod_pool_insert(w, my_voter, blk->out_block_id, sig);
        }
    }
    if (!out->have_cert)
        QGP_LOG_ERROR(LOG_TAG, "own QC cert signing failed at height "
                      "%llu — block committed, certificate missing",
                      (unsigned long long)height);

    (void)nodus_witness_v2_qc_try_attach(w);

    QGP_LOG_INFO(LOG_TAG, "successor block %llu committed through the V2 "
                 "engine (%d envelope(s))",
                 (unsigned long long)height, count);
    free(blk);
    return 0;
}
