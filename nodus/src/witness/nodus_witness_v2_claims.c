/**
 * Nodus — Ledger V2 Season 6: witness-side manifest persistence, real
 * manifest_root / claims_root legs, distribution accounting and the
 * generic claim pipeline (INACTIVE). Contract: nodus_witness_v2_claims.h.
 *
 * Every reader follows the fail-closed shape of
 * nodus_chain_config_compute_root: the step loop's final rc is checked
 * against SQLITE_DONE, a malformed row fails the computation, and no leg
 * is ever replaced by a sentinel. An absent S6 table is distinguished
 * from a fault via sqlite_master (the epoch_state probe pattern) — a
 * probe fault is never reported as "empty".
 *
 * @file nodus_witness_v2_claims.c
 */

#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_domreg.h"

#include "dnac/block_v2.h"
#include "dnac/domain_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2CLAIMS"

/* 1 = table exists, 0 = not, -1 = fault (probe fault ≠ empty). */
static int table_exists(nodus_witness_t *w, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ── manifest_root ──────────────────────────────────────────────────── */

int nodus_witness_manifest_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_manifests");
    if (has < 0) return -1;
    if (has == 0)                       /* pre-S6 DB: honest empty leg   */
        return dna_v2_empty_root(DNA_V2_EMPTY_MANIFEST, out);

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT manifest_seq, manifest_hash FROM v2_manifests "
        "ORDER BY manifest_seq ASC", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;

    size_t cap = 4, n = 0;
    uint32_t *seqs = malloc(cap * sizeof(uint32_t));
    uint8_t (*hashes)[64] = malloc(cap * sizeof(*hashes));
    if (!seqs || !hashes) {
        free(seqs); free(hashes); sqlite3_finalize(st);
        return -1;
    }
    int fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            uint32_t *ns = realloc(seqs, nc * sizeof(uint32_t));
            uint8_t (*nh)[64] = realloc(hashes, nc * sizeof(*nh));
            if (!ns || !nh) {
                free(ns ? ns : seqs);
                free(nh ? nh : hashes);
                sqlite3_finalize(st);
                return -1;
            }
            seqs = ns; hashes = nh; cap = nc;
        }
        sqlite3_int64 seq = sqlite3_column_int64(st, 0);
        const void *h = sqlite3_column_blob(st, 1);
        if (seq < 0 || seq > (sqlite3_int64)UINT32_MAX ||
            !h || sqlite3_column_bytes(st, 1) != 64) {
            QGP_LOG_ERROR(LOG_TAG,
                          "manifest row %zu malformed — failing root", n);
            fail = 1;
            break;
        }
        seqs[n] = (uint32_t)seq;
        memcpy(hashes[n], h, 64);
        n++;
    }
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "manifest scan aborted mid-stream (rc=%d) "
                      "— failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    if (!fail)
        ret = dna_v2_manifest_root(seqs, hashes, n, out);
    free(seqs);
    free(hashes);
    return ret;
}

/* ── claims_root ────────────────────────────────────────────────────── */

int nodus_witness_claims_root_v2(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_claims_spent");
    if (has < 0) return -1;
    if (has == 0)                       /* pre-S6 DB: honest empty leg   */
        return dna_v2_empty_root(DNA_V2_EMPTY_CLAIMS, out);

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT nullifier, manifest_seq, leaf_index, amount, "
        "claimed_height FROM v2_claims_spent ORDER BY nullifier ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;

    size_t cap = 4, n = 0;
    dna_claims_entry_t *entries = malloc(cap * sizeof(*entries));
    if (!entries) { sqlite3_finalize(st); return -1; }
    int fail = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= cap) {
            size_t nc = cap * 2;
            dna_claims_entry_t *ne = realloc(entries, nc * sizeof(*ne));
            if (!ne) { free(entries); sqlite3_finalize(st); return -1; }
            entries = ne; cap = nc;
        }
        const void *nul = sqlite3_column_blob(st, 0);
        sqlite3_int64 seq = sqlite3_column_int64(st, 1);
        sqlite3_int64 idx = sqlite3_column_int64(st, 2);
        sqlite3_int64 amt = sqlite3_column_int64(st, 3);
        sqlite3_int64 hgt = sqlite3_column_int64(st, 4);
        if (!nul || sqlite3_column_bytes(st, 0) != 64 ||
            seq < 0 || seq > (sqlite3_int64)UINT32_MAX ||
            idx < 0 || amt < 1 || hgt < 0) {
            QGP_LOG_ERROR(LOG_TAG,
                          "claim row %zu malformed — failing root", n);
            fail = 1;
            break;
        }
        memcpy(entries[n].nullifier, nul, 64);
        entries[n].manifest_seq = (uint32_t)seq;
        entries[n].leaf_index = (uint64_t)idx;
        entries[n].amount = (uint64_t)amt;
        entries[n].claimed_height = (uint64_t)hgt;
        n++;
    }
    if (!fail && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "claims scan aborted mid-stream (rc=%d) — "
                      "failing root", rc);
        fail = 1;
    }
    sqlite3_finalize(st);

    int ret = -1;
    if (!fail)
        ret = dna_claims_root(entries, n, out);
    free(entries);
    return ret;
}

/* ── chain id ───────────────────────────────────────────────────────── */

int nodus_witness_v2_chain_id(nodus_witness_t *w,
                              uint8_t out[DNA_CHAIN_ID_LEN]) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = 0",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    int ret = -1;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        ret = dna_bh2_derive_chain_id(sqlite3_column_blob(st, 0), out);
    }
    /* SQLITE_DONE (no genesis) and any fault both fail: a chain without
     * a committed genesis has no identity to bind a claim to. */
    sqlite3_finalize(st);
    return ret;
}

/* ── manifest persistence ───────────────────────────────────────────── */

int nodus_witness_v2_manifest_commit(nodus_witness_t *w,
                                     const uint8_t *bytes, size_t len,
                                     uint32_t manifest_seq,
                                     uint64_t committed_height) {
    if (!w || !w->db || !bytes || len == 0) return -1;

    dna_gman_t m;
    if (dna_gman_decode(bytes, len, &m) != 0) return -1;

    /* The committed domain set must EXACTLY match the domain registry. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COUNT(*) FROM domain_registry", -1, &st, NULL)
            != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        sqlite3_int64 cnt = (rc == SQLITE_ROW)
                                ? sqlite3_column_int64(st, 0) : -1;
        sqlite3_finalize(st);
        if (cnt < 0 || (uint64_t)cnt != (uint64_t)m.domain_count) {
            QGP_LOG_ERROR(LOG_TAG, "manifest domain count %u != registry "
                          "count %lld", m.domain_count, (long long)cnt);
            return -1;
        }
    }
    for (uint16_t i = 0; i < m.domain_count; i++) {
        dna_domain_manifest_t dm;
        if (nodus_witness_domreg_get(w, m.domains[i].domain_id, NULL,
                                     &dm, NULL) != 0)
            return -1;
        uint8_t h[64];
        if (dna_domman_hash(&dm, h) != 0) return -1;
        if (memcmp(h, m.domains[i].manifest_hash, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "manifest domain %u hash mismatch "
                          "against registry", m.domains[i].domain_id);
            return -1;
        }
    }

    /* Genesis-supply cross-check (three-valued read honored). */
    {
        nodus_witness_supply_t sup;
        memset(&sup, 0, sizeof(sup));
        int rc = nodus_witness_supply_get(w, &sup);
        if (rc < 0) return -1;          /* DB error is never a value     */
        if (m.genesis_supply_raw != sup.genesis_supply) {
            QGP_LOG_ERROR(LOG_TAG, "manifest genesis supply %llu != "
                          "supply_tracking %llu",
                          (unsigned long long)m.genesis_supply_raw,
                          (unsigned long long)sup.genesis_supply);
            return -1;
        }
    }

    uint8_t mh[64];
    if (dna_gman_hash(&m, mh) != 0) return -1;

    /* Duplicate seq rejects via the PRIMARY KEY (plain INSERT). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_manifests (manifest_seq, manifest_hash, "
            "manifest, committed_height) VALUES (?1, ?2, ?3, ?4)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
    sqlite3_bind_blob(st, 2, mh, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, bytes, (int)len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)committed_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;

    if (m.dist_present == 1) {
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_dist_state (manifest_seq, remaining) "
                "VALUES (?1, ?2)", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)m.total_claimable);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }
    return 0;
}

int nodus_witness_v2_manifest_load(nodus_witness_t *w,
                                   uint32_t manifest_seq,
                                   dna_gman_t *out) {
    if (!w || !w->db || !out) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT manifest, manifest_hash FROM v2_manifests "
            "WHERE manifest_seq = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    int ret = -1;
    if (rc == SQLITE_ROW) {
        const void *bytes = sqlite3_column_blob(st, 0);
        int blen = sqlite3_column_bytes(st, 0);
        const void *sh = sqlite3_column_blob(st, 1);
        if (bytes && blen > 0 && sh && sqlite3_column_bytes(st, 1) == 64 &&
            dna_gman_decode(bytes, (size_t)blen, out) == 0) {
            uint8_t h[64];
            if (dna_gman_hash(out, h) == 0 && memcmp(h, sh, 64) == 0)
                ret = 0;                 /* stored bytes re-hash verified */
        }
    }
    sqlite3_finalize(st);
    return ret;
}

/* ── unclaimed-distribution total ───────────────────────────────────── */

int nodus_witness_v2_unclaimed_total(nodus_witness_t *w, uint64_t *out) {
    if (!w || !w->db || !out) return -1;

    int has = table_exists(w, "v2_dist_state");
    if (has < 0) return -1;
    if (has == 0) { *out = 0; return 0; }   /* honest pre-S6 zero        */

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT remaining FROM v2_dist_state ORDER BY manifest_seq",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    uint64_t sum = 0;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v < 0) { sqlite3_finalize(st); return -1; }
        if ((uint64_t)v > UINT64_MAX - sum) {       /* checked add       */
            sqlite3_finalize(st);
            return -1;
        }
        sum += (uint64_t)v;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;   /* mid-scan fault ≠ a value      */
    *out = sum;
    return 0;
}

/* ── claim pipeline ─────────────────────────────────────────────────── */

int nodus_witness_v2_claim_admit(nodus_witness_t *w,
                                 const dna_claim_t *c,
                                 uint64_t global_height,
                                 uint64_t *out_converted,
                                 uint8_t out_nullifier[64]) {
    if (!w || !w->db || !c || !out_converted || !out_nullifier) return -1;

    /* 1. structural validation */
    if (dna_claim_validate(c) != 0) return -1;

    /* 2. chain binding */
    uint8_t chain_id[DNA_CHAIN_ID_LEN];
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) return -1;
    if (memcmp(chain_id, c->chain_id, DNA_CHAIN_ID_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim chain_id mismatch — cross-chain "
                      "replay rejected");
        return -1;
    }

    /* 3. committed manifest */
    dna_gman_t m;
    int mrc = nodus_witness_v2_manifest_load(w, c->manifest_seq, &m);
    if (mrc != 0) return -1;            /* absent AND fault both reject  */
    if (m.dist_present != 1) return -1; /* no distribution to claim from */
    if (c->auth_mode != m.auth_mode) return -1;

    /* 4. height window (early and late both reject; v1 post-deadline
     *    policy RETAIN: nothing but the reject happens) */
    if (global_height < m.claim_start_height ||
        global_height > m.claim_end_height)
        return -1;

    /* 5. leaf membership */
    if (c->leaf_index >= m.leaf_count) return -1;
    dna_dist_leaf_t leaf;
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    uint8_t leaf_hash[64];
    if (dna_dist_leaf_hash(&leaf, leaf_hash) != 0) return -1;
    if (dna_dist_proof_verify(m.snapshot_root, leaf_hash, c->leaf_index,
                              m.leaf_count, c->siblings,
                              c->n_siblings) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "claim Merkle proof invalid");
        return -1;
    }

    /* 6. converted amount from COMMITTED parameters only */
    uint64_t converted = 0;
    if (dna_dist_converted(c->source_amount, m.conv_numerator,
                           m.conv_denominator, m.rounding_mode,
                           &converted) != 0)
        return -1;

    /* 7. DNA-native authorization (the only v1 mode; anything else was
     *    already rejected by validate + the manifest match above) */
    {
        uint8_t pk_hash[64];
        if (qgp_sha3_512(c->pubkey, DNA_CLAIM_PUBKEY_LEN, pk_hash) != 0)
            return -1;
        if (memcmp(pk_hash, c->dest_binding, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "claim key does not bind to the "
                          "leaf destination — substitution rejected");
            return -1;
        }
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0;
        if (dna_claim_preimage(c, pre, &pre_len) != 0) return -1;
        if (qgp_dsa87_verify(c->signature, DNA_CLAIM_SIG_LEN,
                             pre, pre_len, c->pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "claim signature invalid");
            return -1;
        }
    }

    /* 8. nullifier — already spent rejects */
    uint8_t nul[64];
    if (dna_claim_nullifier(c->chain_id, c->manifest_seq, c->source_id,
                            c->source_id_len, nul) != 0)
        return -1;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_claims_spent WHERE nullifier = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, nul, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) return -1;        /* already claimed       */
        if (rc != SQLITE_DONE) return -1;       /* fault ≠ "not spent"   */
    }

    /* 9. the distribution must cover it — a claim can never mint */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT remaining FROM v2_dist_state "
                "WHERE manifest_seq = ?1", -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)c->manifest_seq);
        int rc = sqlite3_step(st);
        sqlite3_int64 rem = (rc == SQLITE_ROW)
                                ? sqlite3_column_int64(st, 0) : -1;
        sqlite3_finalize(st);
        if (rc != SQLITE_ROW || rem < 0) return -1;
        if ((uint64_t)rem < converted) {
            QGP_LOG_ERROR(LOG_TAG, "claim exceeds remaining distribution "
                          "value — rejected (never mints)");
            return -1;
        }
    }

    *out_converted = converted;
    memcpy(out_nullifier, nul, 64);
    return 0;
}

int nodus_witness_v2_claim_spend_insert(nodus_witness_t *w,
                                        const dna_claim_t *c,
                                        const uint8_t nullifier[64],
                                        uint64_t converted,
                                        uint64_t global_height) {
    if (!w || !w->db || !c || !nullifier || converted == 0) return -1;
    uint8_t utxo_id[64];
    if (dna_claim_utxo_id(nullifier, utxo_id) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_claims_spent (nullifier, manifest_seq, "
            "leaf_index, amount, claimed_height, utxo_id) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6)", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)c->manifest_seq);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)c->leaf_index);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)converted);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)global_height);
    sqlite3_bind_blob(st, 6, utxo_id, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;  /* dup nullifier = PK constraint */
}

int nodus_witness_v2_claim_utxo_create(nodus_witness_t *w,
                                       const dna_claim_t *c,
                                       const uint8_t nullifier[64],
                                       uint64_t converted,
                                       uint64_t global_height) {
    if (!w || !w->db || !c || !nullifier || converted == 0) return -1;

    uint8_t utxo_id[64];
    if (dna_claim_utxo_id(nullifier, utxo_id) != 0) return -1;

    /* owner = the 128-char lowercase-hex form of dest_binding — the
     * existing DNA fingerprint discipline (wallet.c: exactly 128
     * lowercase hex chars). */
    char owner[129];
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        owner[i * 2]     = hexd[c->dest_binding[i] >> 4];
        owner[i * 2 + 1] = hexd[c->dest_binding[i] & 0x0f];
    }
    owner[128] = '\0';

    /* STRICT insert (the stock helper's INSERT OR IGNORE would silently
     * swallow a duplicate output). created_at is pinned to 0: a claim
     * output is a deterministic consensus artifact — a wall-clock byte
     * here would be node-divergent state. domain_id takes the schema
     * default 1 = DNA_CORE (the S5 single-owner column). */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO utxo_set (nullifier, owner, amount, token_id, "
            "tx_hash, output_index, block_height, created_at, "
            "unlock_block) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    static const uint8_t native_token[64] = {0};
    sqlite3_bind_blob(st, 1, utxo_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, owner, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)converted);
    sqlite3_bind_blob(st, 4, native_token, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, nullifier, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, (sqlite3_int64)global_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int nodus_witness_v2_claim_state_update(nodus_witness_t *w,
                                        uint32_t manifest_seq,
                                        uint64_t converted) {
    if (!w || !w->db || converted == 0) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT remaining FROM v2_dist_state WHERE manifest_seq = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)manifest_seq);
    int rc = sqlite3_step(st);
    sqlite3_int64 rem = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0)
                                           : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || rem < 0) return -1;
    if ((uint64_t)rem < converted) return -1;   /* checked underflow     */

    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_dist_state SET remaining = ?1 "
            "WHERE manifest_seq = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)((uint64_t)rem - converted));
    sqlite3_bind_int64(st, 2, (sqlite3_int64)manifest_seq);
    rc = sqlite3_step(st);
    int changed = sqlite3_changes(w->db);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE && changed == 1) ? 0 : -1;
}
