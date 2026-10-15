/**
 * @file tcp_client.c
 * @brief DNAC witness client functions — Nodus SDK based
 *
 * All functions that previously used direct TCP connections to witnesses
 * now use the Nodus client SDK (nodus_client_dnac_*) which routes through
 * the authenticated Nodus TCP connection on port 4001.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "dnac/nodus.h"
#include "dnac/ledger.h"
#include "dnac/trusted_state.h"
#include "dnac/commitment.h"
#include "dnac/wallet.h"
#include "dnac/db.h"
#include "crypto/utils/qgp_log.h"
#include <dna/dna_engine.h>   /* dna_engine_get_signing_public_key */

/* Nodus client SDK (public API) */
#include "nodus/nodus.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

/* Nodus singleton access (not on DNAC include path, use extern) */
extern nodus_client_t *nodus_singleton_get(void);
extern void nodus_singleton_lock(void);
extern void nodus_singleton_unlock(void);

#define LOG_TAG "NODUS_TCP"

/* External wallet functions */
extern dna_engine_t *dnac_get_engine(dnac_context_t *ctx);
extern const char *dnac_get_owner_fingerprint(dnac_context_t *ctx);


/* ============================================================================
 * Ledger Query Functions (via Nodus SDK)
 * ========================================================================== */

int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    nodus_client_t *client = nodus_singleton_get();
    if (!client) return DNAC_ERROR_NOT_INITIALIZED;

    nodus_singleton_lock();

    nodus_dnac_supply_result_t result;
    int rc = nodus_client_dnac_supply(client, &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Supply query failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    if (genesis_out) *genesis_out = result.genesis_supply;
    if (burned_out) *burned_out = result.total_burned;
    if (current_out) *current_out = result.current_supply;

    /* Store chain_id in context for inbox key scoping */
    dnac_set_chain_id(ctx, result.chain_id);

    QGP_LOG_INFO(LOG_TAG, "Supply query: genesis=%llu, burned=%llu, "
                 "current=%llu",
                 (unsigned long long)result.genesis_supply,
                 (unsigned long long)result.total_burned,
                 (unsigned long long)result.current_supply);
    return DNAC_SUCCESS;
}

/* ============================================================================
 * UTXO Query Functions (via Nodus SDK)
 * ========================================================================== */

int dnac_wallet_recover_from_witnesses(dnac_context_t *ctx,
                                        int *recovered_count,
                                        uint64_t *total_amount) {
    if (!ctx) return DNAC_ERROR_INVALID_PARAM;

    if (recovered_count) *recovered_count = 0;
    if (total_amount) *total_amount = 0;

    /* Get our owner fingerprint */
    const char *fingerprint = dnac_get_owner_fingerprint(ctx);
    if (!fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "recover: owner fingerprint is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    sqlite3 *db = dnac_get_db(ctx);
    if (!db) {
        QGP_LOG_ERROR(LOG_TAG, "recover: db is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "recover: nodus singleton is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    size_t fplen = strlen(fingerprint);
    /* Checksum to bypass LogSanitizer redaction */
    uint32_t fp_cksum = 0;
    for (size_t i = 0; i < fplen; i++) fp_cksum = fp_cksum * 31 + (uint8_t)fingerprint[i];
    QGP_LOG_DEBUG(LOG_TAG, "recover: fp_len=%zu fp_cksum=%u fp[0..3]=%c%c%c%c",
                  fplen, fp_cksum, fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]);

    nodus_singleton_lock();

    nodus_dnac_utxo_result_t result;
    int rc = nodus_client_dnac_utxo(client, fingerprint,
                                      NODUS_DNAC_MAX_UTXO_RESULTS, &result);

    nodus_singleton_unlock();

    QGP_LOG_DEBUG(LOG_TAG, "recover: nodus_client_dnac_utxo rc=%d, result.count=%d",
                  rc, rc == 0 ? result.count : -1);

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "UTXO recovery failed: %d", rc);
        return DNAC_ERROR_NETWORK;
    }

    /* Step 1: Get current local unspent UTXOs */
    dnac_utxo_t *local_utxos = NULL;
    int local_count = 0;
    dnac_db_get_unspent_utxos(db, fingerprint, &local_utxos, &local_count);

    /* Step 2: Mark local UTXOs not in witness set as spent */
    for (int i = 0; i < local_count; i++) {
        bool found = false;
        for (int j = 0; j < result.count; j++) {
            if (memcmp(local_utxos[i].nullifier, result.entries[j].nullifier,
                       DNAC_NULLIFIER_SIZE) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            dnac_db_mark_utxo_spent(db, local_utxos[i].nullifier, NULL);
            QGP_LOG_INFO(LOG_TAG, "Marked stale UTXO as spent (amount=%llu)",
                         (unsigned long long)local_utxos[i].amount);
        }
    }
    free(local_utxos);

    /* Step 3: Store witness UTXOs that are missing locally */
    int count = 0;
    uint64_t total = 0;
    for (int i = 0; i < result.count; i++) {
        nodus_dnac_utxo_entry_t *e = &result.entries[i];
        if (total + e->amount < total) {
            QGP_LOG_ERROR(LOG_TAG, "UTXO total overflow at entry %d", i);
            break;  /* Stop accumulating on overflow */
        }
        total += e->amount;

        /* Build UTXO from witness data */
        dnac_utxo_t utxo = {0};
        utxo.version = 1;
        memcpy(utxo.tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        utxo.output_index = e->output_index;
        utxo.amount = e->amount;
        memcpy(utxo.nullifier, e->nullifier, DNAC_NULLIFIER_SIZE);
        snprintf(utxo.owner_fingerprint, sizeof(utxo.owner_fingerprint),
                 "%s", fingerprint);
        memcpy(utxo.token_id, e->token_id, DNAC_TOKEN_ID_SIZE);
        utxo.status = DNAC_UTXO_UNSPENT;
        utxo.received_at = (uint64_t)time(NULL);
        /* O15B §7 — carry the cooldown lock through to the wallet so coin
         * selection can honour Rule D. 0 from a pre-O15B witness that does
         * not send "ub"; see nodus_types.h for why that default is right. */
        utxo.unlock_block = e->unlock_block;
        /* Phase 12 Task 64b — anchored UTXO verification.
         *
         * Gated on:
         *   1. Trusted state installed (wallet init ran dnac_genesis_verify).
         *   2. Witness shipped a non-empty proof (proof_depth > 0).
         *   3. latest_verified_anchor's block_height matches the UTXO's
         *      block_height. Pre-hardfork the chain_id constant is still a
         *      placeholder, so bootstrap never installs a real anchor —
         *      in that case we simply leave verified=false (degraded mode,
         *      consistent with pre-Phase-12 behavior).
         *
         * A dedicated per-block anchor fetch path is out of scope for this
         * commit (would need a new nodus_client_dnac_block_anchor round-trip
         * with commit_cert). Falling back to "use latest verified anchor
         * only if height matches" is the smallest correct slice.
         */
        utxo.verified = false;
        const dnac_trusted_state_t *trust = dnac_current_trusted_state();
        if (trust && e->proof_depth > 0 && e->block_height > 0 &&
            e->proof_depth <= DNAC_MERKLE_MAX_DEPTH) {

            const dnac_block_anchor_t *anchor = NULL;
            if (trust->latest_verified_anchor.header.block_height ==
                e->block_height) {
                anchor = &trust->latest_verified_anchor;
            }

            if (anchor) {
                dnac_merkle_proof_t proof;
                memset(&proof, 0, sizeof(proof));

                /* Root-layout round K1: the leaf commits the coin's
                 * unlock_block too (set from the witness's "ub" above). */
                if (dnac_utxo_compute_leaf_hash(e->nullifier,
                                                  utxo.owner_fingerprint,
                                                  e->amount,
                                                  e->token_id,
                                                  e->tx_hash,
                                                  e->output_index,
                                                  proof.leaf_hash,
                                                  utxo.unlock_block) == 0) {
                    proof.proof_length = (int)e->proof_depth;
                    for (uint32_t si = 0; si < e->proof_depth; si++) {
                        memcpy(proof.siblings[si],
                               e->proof_siblings + si * NODUS_DNAC_PROOF_HASH_LEN,
                               NODUS_DNAC_PROOF_HASH_LEN);
                        proof.directions[si] =
                            (uint8_t)((e->proof_positions >> si) & 1u);
                    }
                    memcpy(proof.root, e->proof_root,
                           NODUS_DNAC_PROOF_HASH_LEN);

                    if (dnac_utxo_verify_anchored(&proof, anchor, trust)) {
                        utxo.verified = true;
                    } else {
                        QGP_LOG_WARN(LOG_TAG,
                            "UTXO proof verify failed (height=%llu, idx=%u)",
                            (unsigned long long)e->block_height,
                            e->output_index);
                    }
                }
            }
        }

        /* INSERT OR IGNORE — won't overwrite existing entries */
        rc = dnac_db_store_utxo(db, &utxo);
        if (rc == DNAC_SUCCESS) {
            count++;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Witness UTXO: amount=%llu, output_index=%u",
                      (unsigned long long)e->amount, e->output_index);
    }

    /* O15B §7 — commit the height from THIS response, after the coins it
     * described are stored. Reader and writer therefore see one consistent
     * observation: coin selection compares each coin's unlock_block against
     * the very height the witness reported alongside it. */
    dnac_db_set_observed_height(db, result.block_height);

    nodus_client_free_utxo_result(&result);

    if (recovered_count) *recovered_count = count;
    if (total_amount) *total_amount = total;

    if (count > 0) {
        QGP_LOG_INFO(LOG_TAG, "Witness recovery: stored %d new UTXOs, total: %llu",
                     count, (unsigned long long)total);
    }

    return DNAC_SUCCESS;
}

/* dnac_get_remote_history (the dnac_history RPC) is deleted with that RPC
 * (2026-10-15): it read committed_transactions / tx_outputs, which no
 * version-3 chain writes, so it always answered zero entries. */

/* ============================================================================
 * My Delegations (from Nodus witnesses)
 * ========================================================================== */

void dnac_free_delegations(dnac_delegation_t *list, int count) {
    (void)count;  /* Entries are plain POD, a single free() suffices. */
    free(list);
}

int dnac_get_my_delegations(dnac_context_t *ctx,
                              dnac_delegation_t **list_out,
                              int *count_out) {
    if (!ctx || !list_out || !count_out)
        return DNAC_ERROR_INVALID_PARAM;

    *list_out = NULL;
    *count_out = 0;

    /* The wire protocol sends the raw Dilithium5 pubkey (not fp) so the
     * witness can both authenticate the session AND compute the
     * delegator_hash PK column lookup in one place. dnac_context stores
     * only the fp — pull the live pubkey from the engine's signing
     * identity. Mirrors the stake.c / genesis.c / builder.c patterns. */
    dna_engine_t *engine = dnac_get_engine(ctx);
    if (!engine) {
        QGP_LOG_ERROR(LOG_TAG, "my_delegations: engine is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    /* Success returns pubkey size (positive); only negative is a failure.
     * Matches genesis.c:275 / stake.c:157 convention. Previously checked
     * rc != 0 which would have tripped on every successful call. */
    int pk_rc = dna_engine_get_signing_public_key(engine, pubkey,
                                                    sizeof(pubkey));
    if (pk_rc < 0) {
        QGP_LOG_ERROR(LOG_TAG,
                      "my_delegations: get_signing_public_key failed: %d",
                      pk_rc);
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client) {
        QGP_LOG_ERROR(LOG_TAG, "my_delegations: nodus singleton is NULL");
        return DNAC_ERROR_NOT_INITIALIZED;
    }

    nodus_singleton_lock();

    nodus_dnac_delegations_result_t result;
    int rc = nodus_client_dnac_delegations(client, pubkey, sizeof(pubkey),
                                             NODUS_DNAC_MAX_DELEGATIONS_RESULTS,
                                             &result);

    nodus_singleton_unlock();

    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "my_delegations: nodus query failed: %d",
                      rc);
        return DNAC_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "my_delegations: received %d entries from Nodus",
                 result.count);

    if (result.count > 0) {
        dnac_delegation_t *list = calloc((size_t)result.count,
                                           sizeof(dnac_delegation_t));
        if (!list) {
            nodus_client_free_delegations_result(&result);
            return DNAC_ERROR_OUT_OF_MEMORY;
        }

        for (int i = 0; i < result.count; i++) {
            const nodus_dnac_delegation_entry_t *src = &result.entries[i];
            dnac_delegation_t *dst = &list[i];

            /* validator_fp is already 128-hex + NUL on the wire; copy
             * defensively with bounds just in case a future schema
             * revision shortens DNAC_FINGERPRINT_SIZE. */
            strncpy(dst->validator_fp, src->validator_fp,
                    DNAC_FINGERPRINT_SIZE - 1);
            dst->validator_fp[DNAC_FINGERPRINT_SIZE - 1] = '\0';
            dst->amount_raw          = src->amount;
            dst->delegated_at_block  = src->delegated_at_block;
        }

        *list_out  = list;
        *count_out = result.count;
    }

    nodus_client_free_delegations_result(&result);
    return DNAC_SUCCESS;
}
