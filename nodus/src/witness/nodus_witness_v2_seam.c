/**
 * @file nodus_witness_v2_seam.c
 * @brief Ledger V2 O15C — deterministic successor-chain derivation.
 *
 * Contract and the migration accounting argument: the header. Every
 * byte written here is a pure function of committed legacy state; the
 * O15B.1 genesis-manifest-divergence check plus the derived-chain-id
 * identity (chain id = genesis BlockID = f(manifest, roots)) make two
 * nodes with the same terminal chain structurally unable to derive
 * different successors.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_seam.h"

#include "witness/nodus_witness_v2_activation.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_bundle.h"   /* O15E Faz D genesis bundle */
#include "nodus/nodus_chain_config.h"

#include "dnac/manifest_wire.h"
#include "dnac/domain_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/vset_wire.h"
#include "dnac/validator.h"   /* DNAC_VALIDATOR_ACTIVE / _ELIGIBLE (O15F T1) */

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

#define LOG_TAG "W_V2SEAM"

/* ── successor probe ─────────────────────────────────────────────────── */

int nodus_witness_v2_seam_is_successor(const char *db_path) {
    if (!db_path) return -1;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    int ret = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT manifest FROM v2_manifests WHERE committed_height = 0 "
            "ORDER BY manifest_seq ASC LIMIT 1", -1, &st, NULL)
        == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            const void *mb = sqlite3_column_blob(st, 0);
            int ml = sqlite3_column_bytes(st, 0);
            dna_gman_t m;
            if (mb && ml > 0 &&
                dna_gman_decode((const uint8_t *)mb, (size_t)ml, &m) == 0 &&
                m.dist_present == 1 &&
                m.source_tag_len == DNA_ACT_SOURCE_TAG_LEN &&
                memcmp(m.source_tag, DNA_ACT_SOURCE_TAG,
                       DNA_ACT_SOURCE_TAG_LEN) == 0)
                ret = 1;
        }
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return ret;
}

/* Remove every regular file in `dir` and the directory itself (the seam
 * scratch dir only ever holds sqlite files this module created). */
static void seam_scratch_clear(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char p[600];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            (void)unlink(p);
        }
        closedir(d);
    }
    (void)rmdir(dir);
}

/* Any successor db already in data_path? 1/0/-1. */
static int seam_successor_exists(const char *data_path) {
    DIR *dir = opendir(data_path);
    if (!dir) return -1;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(dir)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", data_path, e->d_name);
        if (nodus_witness_v2_seam_is_successor(path) == 1) { found = 1; break; }
    }
    closedir(dir);
    return found;
}

/* ── helpers ─────────────────────────────────────────────────────────── */

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* Owner fingerprint (128 lowercase hex) → 64 raw bytes. Strict. */
static int seam_fp_to_binding(const char *fp, uint8_t out[64]) {
    if (!fp || strlen(fp) != 128) return -1;
    for (int i = 0; i < 64; i++) {
        int hi = hexval(fp[i * 2]), lo = hexval(fp[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int seam_count(sqlite3 *db, const char *sql, sqlite3_int64 *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    *out = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return (*out >= 0) ? 0 : -1;
}

static int seam_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "exec failed: %s", err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── the derivation ──────────────────────────────────────────────────── */

int nodus_witness_v2_seam_maybe_derive(nodus_witness_t *w,
                                       uint8_t out_chain32[32]) {
    if (!w || !w->db) return -1;

    nodus_v2_act_record_t rec;
    int have = nodus_witness_v2_activation_get(w, &rec);
    if (have < 0) return -1;
    if (have == 1 || rec.state != DNA_ACT_STATE_ACTIVE) return 0;

    int se = seam_successor_exists(w->data_path);
    if (se < 0) return -1;
    if (se == 1) return 0;                     /* idempotent */

    QGP_LOG_INFO(LOG_TAG, "deriving Ledger V2 successor chain from "
                 "terminal legacy height %llu",
                 (unsigned long long)rec.activation_height);

    /* ── 1. Terminal binding ────────────────────────────────────────── */
    nodus_witness_block_t term;
    memset(&term, 0, sizeof(term));
    if (nodus_witness_block_get(w, rec.activation_height, &term) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "terminal block row unreadable");
        return -1;
    }
    uint8_t term_hash[64];
    nodus_witness_compute_block_hash(term.height, term.prev_hash,
                                     term.state_root, term.tx_root,
                                     term.tx_count, term.proposer_id,
                                     term_hash);
    uint8_t source_commit[DNA_ACT_SOURCE_COMMIT_LEN];
    if (dna_act_source_commit(w->chain_id, term_hash, term.state_root,
                              rec.activation_height, source_commit) != 0)
        return -1;

    /* ── 2. Fail-closed classification of non-migratable state ──────── */
    sqlite3_int64 n_tokens = 0, n_token_utxo = 0, n_zero = 0, n_utxo = 0;
    if (seam_count(w->db, "SELECT COUNT(*) FROM tokens", &n_tokens) != 0)
        return -1;
    if (seam_count(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE token_id != x'"
            "00000000000000000000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000"
            "0000000000000000'", &n_token_utxo) != 0)
        return -1;
    if (n_tokens > 0 || n_token_utxo > 0) {
        QGP_LOG_ERROR(LOG_TAG, "custom tokens present (%lld registry, "
                      "%lld utxo) — v1 migration is native-only, "
                      "ABORTING derivation (fail closed)",
                      (long long)n_tokens, (long long)n_token_utxo);
        return -1;
    }
    if (seam_count(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE amount = 0", &n_zero) != 0)
        return -1;
    if (n_zero > 0) {
        /* A zero-amount UTXO carries no value and cannot be a leaf
         * (leaf source_amount >= 1); skipping it loses nothing. Logged,
         * never silent. */
        QGP_LOG_WARN(LOG_TAG, "%lld zero-amount UTXO(s) skipped (no "
                     "value; not representable as claim leaves)",
                     (long long)n_zero);
    }
    if (seam_count(w->db,
            "SELECT COUNT(*) FROM utxo_set WHERE amount > 0", &n_utxo) != 0)
        return -1;
    if (n_utxo < 1 || (uint64_t)n_utxo > (uint64_t)1 << 20) {
        /* >2^20 leaves would be far outside any devnet/Testnet2 state;
         * refuse rather than allocate unbounded memory. */
        QGP_LOG_ERROR(LOG_TAG, "unmigratable UTXO count %lld",
                      (long long)n_utxo);
        return -1;
    }

    /* ── 3. Claim leaves from the spendable native UTXO set ─────────── */
    dna_dist_leaf_t *leaves = calloc((size_t)n_utxo, sizeof(*leaves));
    if (!leaves) return -1;
    size_t n_leaves = 0;
    uint64_t total = 0;
    {
        sqlite3_stmt *st = NULL;
        /* nullifier ASC IS the canonical leaf order (source_id =
         * nullifier, fixed 64 bytes → dna_dist_leaf_cmp degenerates to
         * memcmp; SQLite BLOB ordering is memcmp). */
        if (sqlite3_prepare_v2(w->db,
                "SELECT nullifier, owner, amount FROM utxo_set "
                "WHERE amount > 0 ORDER BY nullifier ASC",
                -1, &st, NULL) != SQLITE_OK) {
            free(leaves);
            return -1;
        }
        int rc;
        int bad = 0;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (n_leaves >= (size_t)n_utxo) { bad = 1; break; }
            const void *nul = sqlite3_column_blob(st, 0);
            const unsigned char *own = sqlite3_column_text(st, 1);
            sqlite3_int64 amt = sqlite3_column_int64(st, 2);
            if (!nul || sqlite3_column_bytes(st, 0) != 64 || !own ||
                amt <= 0) { bad = 1; break; }
            dna_dist_leaf_t *L = &leaves[n_leaves];
            L->leaf_version = DNA_DIST_VERSION;
            L->source_id_len = 64;
            memcpy(L->source_id, nul, 64);
            L->source_amount = (uint64_t)amt;
            if (seam_fp_to_binding((const char *)own,
                                   L->dest_binding) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "malformed owner fingerprint — ABORT");
                bad = 1;
                break;
            }
            if (total > UINT64_MAX - (uint64_t)amt) { bad = 1; break; }
            total += (uint64_t)amt;
            n_leaves++;
        }
        sqlite3_finalize(st);
        if (bad || rc != SQLITE_DONE || n_leaves == 0) {
            free(leaves);
            return -1;
        }
    }
    uint8_t snap_root[64];
    if (dna_dist_snapshot_root(leaves, n_leaves, snap_root) != 0 ||
        dna_dist_check_totals(leaves, n_leaves, 1, 1, DNA_DISTROUND_FLOOR,
                              total) != 0) {
        free(leaves);
        return -1;
    }
    free(leaves);

    /* ── 4. Successor database (provisional deterministic name) ─────── */
    uint8_t prov_full[64], prov16[16];
    if (qgp_sha3_512(source_commit, sizeof(source_commit), prov_full) != 0)
        return -1;
    memcpy(prov16, prov_full, 16);

    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    if (!w2) return -1;
    /* The successor is derived inside a SCRATCH SUBDIRECTORY:
     * nodus_witness_create_chain_db archives every OTHER witness_*.db in
     * its data_path (the EU-6 stale-chain discipline), which would
     * archive the live legacy database out from under this derivation.
     * Only a COMPLETE successor is renamed up into the real data_path. */
    snprintf(w2->data_path, sizeof(w2->data_path), "%s/v2seam.tmp",
             w->data_path);
    seam_scratch_clear(w2->data_path);         /* crashed prior attempt */
    if (mkdir(w2->data_path, 0700) != 0 && errno != EEXIST) {
        free(w2);
        return -1;
    }

    char prov_path[512];
    {
        char hex[33];
        for (int i = 0; i < 16; i++)
            snprintf(hex + i * 2, 3, "%02x", prov16[i]);
        snprintf(prov_path, sizeof(prov_path), "%s/witness_%s.db",
                 w2->data_path, hex);
    }

    int ok = -1;
    do {
        if (nodus_witness_create_chain_db(w2, prov16) != 0) break;
        /* O15F Task 1 — mark the provisional handle a successor BEFORE any
         * validator-set seeding. nodus_witness_vset_commit_genesis (below)
         * seeds the epoch-0/E snapshots through vset_target_for_epoch and
         * the writer guard, both gated on v2_successor; without this the
         * genesis snapshots would seed uncapped (D1#4). Deterministic local
         * act every node's seam performs identically. */
        w2->v2_successor = 1;
        /* O15F Task 4: successors derive at S12 so every block they ever
         * commit carries its canonical envelope bytes (v2_tx_bytes, S11)
         * AND its per-block claim bytes + count (v2_claim_bytes /
         * v2_claim_counts, S12). */
        if (nodus_witness_db_migrate_v2s12(w2) != 0) break;
        if (nodus_chain_config_db_migrate(w2) != 0) break;

        /* ── 5. Carry the committed SYSTEM state. The legacy file path
         * comes from the live sqlite handle itself — never re-derived
         * from a filename convention. ─────────────────────────────── */
        const char *legacy_file = sqlite3_db_filename(w->db, "main");
        if (!legacy_file || !legacy_file[0]) break;
        QGP_LOG_INFO(LOG_TAG, "carrying committed state from %s",
                     legacy_file);
        {
            char sql[700];
            snprintf(sql, sizeof(sql),
                     "ATTACH DATABASE '%s' AS legacy;", legacy_file);
            if (seam_exec(w2->db, sql) != 0) break;
            sqlite3_int64 nt = -1;
            (void)seam_count(w2->db,
                "SELECT COUNT(*) FROM legacy.sqlite_master "
                "WHERE type='table'", &nt);
            QGP_LOG_INFO(LOG_TAG, "attached legacy db: %lld tables",
                         (long long)nt);
        }
        if (seam_exec(w2->db,
                "BEGIN IMMEDIATE;"
                "INSERT INTO validators SELECT * FROM legacy.validators;"
                /* Attendance restarts in the successor's height domain:
                 * legacy watermarks are legacy heights and would freeze
                 * the V2 writer's monotonic guard for H_act blocks. */
                "UPDATE validators SET last_signed_block = 0,"
                "  signed_blocks_this_epoch = 0,"
                "  consecutive_missed_epochs = 0;"
                "DELETE FROM delegations;"
                "INSERT INTO delegations SELECT * FROM legacy.delegations;"
                "DELETE FROM validator_stats;"
                "INSERT INTO validator_stats "
                "  SELECT * FROM legacy.validator_stats;"
                "DELETE FROM epoch_state;"
                "INSERT INTO epoch_state SELECT * FROM legacy.epoch_state;"
                "DELETE FROM supply_tracking;"
                "INSERT INTO supply_tracking "
                "  SELECT * FROM legacy.supply_tracking;"
                "INSERT INTO chain_config_history "
                "  SELECT * FROM legacy.chain_config_history;"
                "COMMIT;"
                "DETACH DATABASE legacy;") != 0) {
            (void)seam_exec(w2->db, "ROLLBACK");
            break;
        }

        /* ── O15F Task 1 — successor active-set-maximum reconciliation ──
         * The successor set is transplanted from the terminal legacy set,
         * whose size is legal on the legacy lane [7..128] but inexpressible
         * on a max-30 successor. Enforce the bound BEFORE seeding the
         * genesis snapshots (below), fail-closed — refusing to derive is
         * the honest choice; silently seating a >30 set (or silently
         * clamping a carried target 31->30) is the substitution this tree
         * bans. Mirrors the token/attendance reconciliations above. */
        {
            char sql[192];
            sqlite3_int64 n_bonded = -1;
            snprintf(sql, sizeof(sql),
                     "SELECT COUNT(*) FROM validators WHERE status IN "
                     "(%d,%d)", (int)DNAC_VALIDATOR_ACTIVE,
                     (int)DNAC_VALIDATOR_ELIGIBLE);
            if (seam_count(w2->db, sql, &n_bonded) != 0) break;
            if (n_bonded > (sqlite3_int64)NODUS_V2_ACTIVE_SET_MAX) {
                QGP_LOG_ERROR(LOG_TAG, "terminal bonded set %lld exceeds "
                              "NODUS_V2_ACTIVE_SET_MAX (%d) — ABORTING "
                              "derivation (fail closed)",
                              (long long)n_bonded, NODUS_V2_ACTIVE_SET_MAX);
                break;
            }

            sqlite3_int64 cc_target = -1;
            snprintf(sql, sizeof(sql),
                     "SELECT COALESCE(MAX(new_value),0) FROM "
                     "chain_config_history WHERE param_id = %d",
                     (int)DNAC_CFG_TARGET_ACTIVE_COUNT);
            if (seam_count(w2->db, sql, &cc_target) != 0) break;
            if (cc_target > (sqlite3_int64)NODUS_V2_ACTIVE_SET_MAX) {
                QGP_LOG_ERROR(LOG_TAG, "carried TARGET_ACTIVE_COUNT %lld "
                              "exceeds NODUS_V2_ACTIVE_SET_MAX (%d) — "
                              "ABORTING derivation (fail closed)",
                              (long long)cc_target, NODUS_V2_ACTIVE_SET_MAX);
                break;
            }
        }

        /* ── 6. Authority + registry + manifest + genesis ─────────────
         * ORDER IS LOAD-BEARING (v2_genesis_fixture.h precedent): the
         * validator snapshots feed the SYSTEM payload root, and
         * domreg_init_genesis commits that root — genesis_ex re-runs it
         * and byte-compares, so the snapshots must exist FIRST. */
        {
            sqlite3_int64 n_snap = -1;
            if (seam_count(w2->db,
                    "SELECT COUNT(*) FROM validator_set_snapshots",
                    &n_snap) != 0) break;
            if (n_snap == 0 &&
                nodus_witness_vset_commit_genesis(w2, 1) != 0) break;
        }
        if (nodus_witness_domreg_init_genesis(w2) != 0) break;

        dna_domain_manifest_t dm;
        uint8_t sys_h[64], core_h[64];
        if (nodus_witness_domreg_get(w2, DNA_DOMAIN_SYSTEM, NULL, &dm,
                                     NULL) != 0) break;
        if (dna_domman_hash(&dm, sys_h) != 0) break;
        if (nodus_witness_domreg_get(w2, DNA_DOMAIN_CORE, NULL, &dm,
                                     NULL) != 0) break;
        if (dna_domman_hash(&dm, core_h) != 0) break;

        uint64_t gsupply = 0;
        {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w2->db,
                    "SELECT COALESCE(genesis_supply,0) FROM supply_tracking "
                    "WHERE id = 1", -1, &st, NULL) != SQLITE_OK)
                break;
            if (sqlite3_step(st) == SQLITE_ROW)
                gsupply = (uint64_t)sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }

        dna_gman_t m;
        memset(&m, 0, sizeof(m));
        m.manifest_version = DNA_GMAN_VERSION;
        m.genesis_supply_raw = gsupply;
        m.domain_count = 2;
        m.domains[0].domain_id = DNA_DOMAIN_SYSTEM;
        memcpy(m.domains[0].manifest_hash, sys_h, 64);
        m.domains[1].domain_id = DNA_DOMAIN_CORE;
        memcpy(m.domains[1].manifest_hash, core_h, 64);
        m.dist_present = 1;
        m.dist_version = DNA_DIST_VERSION;
        m.target_domain_id = DNA_DOMAIN_CORE;
        m.target_asset_len = 64;               /* native token id: zeros */
        m.source_tag_len = DNA_ACT_SOURCE_TAG_LEN;
        memcpy(m.source_tag, DNA_ACT_SOURCE_TAG, DNA_ACT_SOURCE_TAG_LEN);
        m.source_commit_len = DNA_ACT_SOURCE_COMMIT_LEN;
        memcpy(m.source_commit, source_commit, DNA_ACT_SOURCE_COMMIT_LEN);
        memcpy(m.snapshot_root, snap_root, 64);
        m.leaf_count = (uint64_t)n_leaves;
        m.conv_numerator = 1;
        m.conv_denominator = 1;
        m.rounding_mode = DNA_DISTROUND_FLOOR;
        m.excluded_amount = 0;
        m.total_claimable = total;
        m.claim_start_height = 0;
        m.claim_end_height = UINT64_MAX;
        m.auth_mode = DNA_CLAIMAUTH_DNA_NATIVE;
        m.fee_mode = DNA_CLAIMFEE_NONE;
        m.post_deadline_mode = DNA_POSTDL_RETAIN;

        uint8_t mbytes[8192];
        size_t mlen = 0;
        if (dna_gman_encode(&m, mbytes, sizeof(mbytes), &mlen) != 0) break;

        uint8_t vsh[DNA_VSET_HASH_LEN];
        {
            dna_vset_snapshot_t *s0 = NULL;
            uint32_t sn = 0, sq = 0;
            if (nodus_witness_v2_epoch_authority_for_height(w2, 0, &s0,
                                                            &sn, &sq) != 0 ||
                !s0) {
                dna_vset_free(&s0);
                break;
            }
            int hrc = dna_vset_hash(s0, vsh);
            dna_vset_free(&s0);
            if (hrc != 0) break;
        }

        if (nodus_witness_v2_genesis_ex(w2, NULL, vsh, 0,
                                        mbytes, mlen) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "successor V2 genesis FAILED");
            break;
        }

        /* ── 7. Post-conditions the season's accounting demands ─────── */
        sqlite3_int64 n_v2_utxo = -1;
        if (seam_count(w2->db, "SELECT COUNT(*) FROM utxo_set",
                       &n_v2_utxo) != 0 || n_v2_utxo != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "successor holds spendable UTXOs — ABORT");
            break;
        }
        {
            sqlite3_stmt *st = NULL;
            sqlite3_int64 remaining = -1;
            if (sqlite3_prepare_v2(w2->db,
                    "SELECT COALESCE(SUM(remaining), -1) FROM v2_dist_state",
                    -1, &st, NULL) != SQLITE_OK)
                break;
            if (sqlite3_step(st) == SQLITE_ROW)
                remaining = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if ((uint64_t)remaining != total) {
                QGP_LOG_ERROR(LOG_TAG, "claim reserve %lld != migratable "
                              "value %llu — ABORT", (long long)remaining,
                              (unsigned long long)total);
                break;
            }
        }

        uint8_t chain32[32];
        if (nodus_witness_v2_chain_id(w2, chain32) != 0) break;
        if (out_chain32) memcpy(out_chain32, chain32, 32);

        /* ── 7b. O15E Faz D — persist the canonical genesis bundle NOW,
         * while the base tables still hold their exact genesis-time
         * bytes (before any block mutates validators / chain_config).
         * A fresh joiner re-derives the genesis from these bytes and
         * proves it against its local pin. Fail-closed: a successor that
         * cannot serialize its own genesis is not a valid bootstrap
         * source and the whole derivation aborts. */
        if (nodus_witness_v2_bundle_persist(w2) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "genesis bundle persistence FAILED — ABORT");
            break;
        }

        /* ── 8. Land the real name in the REAL data_path (rename only
         * after a COMPLETE derivation — same filesystem, atomic). ───── */
        sqlite3_close(w2->db);
        w2->db = NULL;
        char real_path[512];
        {
            char hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(hex + i * 2, 3, "%02x", chain32[i]);
            snprintf(real_path, sizeof(real_path), "%s/witness_%s.db",
                     w->data_path, hex);
        }
        if (rename(prov_path, real_path) != 0) break;

        QGP_LOG_INFO(LOG_TAG, "successor V2 chain derived: %s "
                     "(reserve=%llu raw across %zu claim leaves)",
                     real_path, (unsigned long long)total, n_leaves);
        ok = 0;
    } while (0);

    if (w2->db) { sqlite3_close(w2->db); w2->db = NULL; }
    seam_scratch_clear(w2->data_path);         /* nothing partial */
    free(w2);
    return ok;
}
