/**
 * @file nodus_witness_v2_gen.c
 * @brief Ledger V2 O15J Faz 1 — the pure-V2 genesis builder.
 *
 * Contract, determinism argument, threat model and the six red-team
 * defects this module closes: the header. Every byte written here is a
 * pure function of the operator config; the derived-chain-id identity
 * (chain id = genesis BlockID = f(manifest, roots)) makes two nodes with
 * byte-identical configs structurally unable to derive different chains.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_gen.h"

#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/domain_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/manifest_wire.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>     /* INT64_MAX — the signed storage bound (R2-F8) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "W_V2GEN"

/* Compile-time agreement with the codecs this module feeds. A drift in
 * any of these would surface as a runtime reject; catching it here means
 * it cannot ship at all. */
_Static_assert(DNAC_COMMITTEE_SIZE <= NODUS_V2_GEN_MAX_VALIDATORS,
               "the exact-count genesis rule must fit the config array");
_Static_assert(NODUS_V2_GEN_MAX_VALIDATORS <= NODUS_V2_ACTIVE_SET_MAX,
               "a config set larger than the active-set maximum is "
               "inexpressible on the V2 lane");
_Static_assert(NODUS_V2_GEN_SOURCE_TAG_LEN >= 1 &&
                   NODUS_V2_GEN_SOURCE_TAG_LEN <= DNA_GMAN_SRCTAG_MAX,
               "source_tag must satisfy the manifest codec bound");
_Static_assert(NODUS_V2_GEN_SRCCOMMIT_LEN <= DNA_GMAN_SRCCOMMIT_MAX,
               "source_commit must fit the manifest codec bound");
_Static_assert(NODUS_V2_GEN_SRCID_LEN >= 1 &&
                   NODUS_V2_GEN_SRCID_LEN <= DNA_DIST_SRCID_MAX,
               "source_id must satisfy the distribution-leaf bound");
_Static_assert((uint64_t)NODUS_V2_GEN_MAX_ALLOCS <= DNA_DIST_MAX_LEAVES,
               "the allocation bound must fit the snapshot-tree bound");
_Static_assert(NODUS_V2_GEN_SRCCOMMIT_LEN == NODUS_T3_TX_HASH_LEN,
               "source_commit doubles as supply_tracking.last_tx_hash");

/* ── little helpers ──────────────────────────────────────────────────── */

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v;
}
static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

/* Checked add. 0 on success, -1 on overflow. */
static int add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (a > UINT64_MAX - b) return -1;
    *out = a + b;
    return 0;
}

static int gen_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "exec failed: %s", err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Single-integer query. 0 with *out set, -1 on any fault — a DB failure
 * is never reported as a value. */
static int gen_count(sqlite3 *db, const char *sql, sqlite3_int64 *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = v;
    return 0;
}

/* Remove every regular file in `dir` and the directory itself. The
 * scratch dir only ever holds sqlite files this module created; readdir
 * order is irrelevant because every entry is removed. */
/* O15J review R2-F6 — the directory really is removed now.
 * nodus_witness_create_chain_db unconditionally mkdir()s
 * "<data_path>/archive" before it inspects anything
 * (nodus_witness.c:684-691), and on this path data_path IS the scratch
 * dir. unlink() fails with EISDIR on that subdirectory and the trailing
 * rmdir() then fails with ENOTEMPTY, both return values discarded — so
 * every derivation left <real_data_path>/v2gen.tmp/archive/ behind and
 * the header's "the directory itself" post-condition was false.
 *
 * Deliberately NOT a general recursive delete: exactly one nested
 * directory is known to exist here, it is named, and it is cleared one
 * level deep. A recursive rm rooted at a path we computed is the shape
 * that turns a truncation bug into data loss (see R2-F3 above). */
static void gen_scratch_clear_files(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char p[600];
        int n = snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(p)) continue;
        (void)unlink(p);
    }
    closedir(d);
}

static void gen_scratch_clear(const char *dir) {
    gen_scratch_clear_files(dir);

    /* The one nested directory create_chain_db is known to create. */
    char arch[600];
    int n = snprintf(arch, sizeof(arch), "%s/archive", dir);
    if (n > 0 && (size_t)n < sizeof(arch)) {
        gen_scratch_clear_files(arch);
        (void)rmdir(arch);
    }

    if (rmdir(dir) != 0 && errno != ENOENT) {
        /* Not fatal — the caller's outcome does not depend on cleanup —
         * but it must not be silent: a scratch dir that survives is how
         * a later run inherits state it did not create. */
        QGP_LOG_WARN(LOG_TAG, "scratch directory %s not removed: %s",
                     dir, strerror(errno));
    }
}

/* ── the pure-V2 probe ───────────────────────────────────────────────── */

int nodus_witness_v2_gen_is_pure(const char *db_path) {
    if (!db_path) return -1;
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }
    /* O15J review R2-F4 — a PROBE FAILURE IS NOT AN ANSWER.
     * This used to initialise `ret = 0` and leave it there on a prepare
     * error, a mid-step SQLITE_IOERR/SQLITE_CORRUPT, or a manifest that
     * failed to decode — all reported as "this is not a pure chain",
     * indistinguishable from a clean no. `nodus/CLAUDE.md` bans exactly
     * that shape ("one error code meaning both absent and failed"), and
     * here it had teeth: gen_pure_exists would report "no chain here",
     * the idempotency short-circuit would not fire, and derive would
     * build a SECOND chain beside a damaged first one — a silent
     * two-chain state reached by one transient read error.
     *
     * A row that is absent, or present and decodes to a different
     * source tag, is a genuine 0. Everything else is -1. */
    int ret = -1;
    sqlite3_stmt *st = NULL;

    /* A TRANSIENT lock must not become a permanent verdict.
     *
     * This probe's -1 REFUSES the database at witness_post_open_gate —
     * deliberately stricter than the seam probe beside it, because a
     * chain whose role cannot be determined must not be opened as though
     * it had none. That strictness makes a momentary SQLITE_BUSY/LOCKED
     * indistinguishable from real corruption, and a node that cannot
     * open its chain does not come back on its own. nodus/BUGS.md
     * records the v0.18.19 near-miss of exactly this class: a new hard
     * -1 that would have bricked every joining node during its bootstrap
     * window.
     *
     * A busy handler is the honest fix: SQLite retries internally, so
     * BUSY can only reach us after the timeout has elapsed — by which
     * point it is a real, persistent lock and refusing IS correct. The
     * database is opened WAL before this runs (nodus_witness.c:317), so
     * readers do not block writers and this should never fire; the
     * timeout exists for the cases WAL does not cover (recovery,
     * checkpoint lock contention), not for the common path. */
    sqlite3_busy_timeout(db, 5000);

    /* Table existence is probed EXPLICITLY, not inferred from a prepare
     * failure: a legacy database simply has no v2_manifests table, and
     * that is a definitive "not a pure chain" (0), not a fault. Only a
     * genuine catalogue read failure is -1. Same three-valued shape as
     * table_exists() in nodus_witness_v2_claims.c:38. */
    {
        sqlite3_stmt *tq = NULL;
        if (sqlite3_prepare_v2(db,
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='v2_manifests'", -1, &tq, NULL) != SQLITE_OK) {
            sqlite3_close(db);
            return -1;
        }
        int trc = sqlite3_step(tq);
        sqlite3_finalize(tq);
        if (trc == SQLITE_DONE) { sqlite3_close(db); return 0; }
        if (trc != SQLITE_ROW)  {
            QGP_LOG_ERROR(LOG_TAG,
                "chain-role probe could not read the catalogue of %s "
                "after the busy timeout (sqlite rc=%d) — this is a "
                "persistent fault, not contention", db_path, trc);
            sqlite3_close(db);
            return -1;
        }
    }

    if (sqlite3_prepare_v2(db,
            "SELECT manifest FROM v2_manifests WHERE committed_height = 0 "
            "ORDER BY manifest_seq ASC LIMIT 1", -1, &st, NULL)
        == SQLITE_OK) {
        int rc = sqlite3_step(st);
        if (rc == SQLITE_DONE) {
            ret = 0;                    /* no genesis manifest: not ours */
        } else if (rc == SQLITE_ROW) {
            const void *mb = sqlite3_column_blob(st, 0);
            int ml = sqlite3_column_bytes(st, 0);
            dna_gman_t m;
            if (!mb || ml <= 0) {
                ret = -1;               /* NULL/empty blob: unreadable   */
            } else if (dna_gman_decode((const uint8_t *)mb, (size_t)ml, &m)
                       != 0) {
                ret = -1;               /* undecodable: cannot classify  */
            } else {
                ret = (m.dist_present == 1 &&
                       m.source_tag_len == NODUS_V2_GEN_SOURCE_TAG_LEN &&
                       memcmp(m.source_tag, NODUS_V2_GEN_SOURCE_TAG,
                              NODUS_V2_GEN_SOURCE_TAG_LEN) == 0) ? 1 : 0;
            }
        }
        /* rc is anything else (SQLITE_IOERR, SQLITE_CORRUPT, ...):
         * ret stays -1. */
        sqlite3_finalize(st);
    }
    /* prepare failed on a table we just proved exists: a real fault —
     * ret stays -1. */
    sqlite3_close(db);
    return ret;
}

/* Does `data_path` already hold a pure-V2 chain? 1/0/-1.
 * readdir order does not reach the answer: the result is a pure OR over
 * every entry, so any order produces the same boolean. */
/* Classify what `data_path` already holds:
 *   0  nothing — no witness_*.db at all
 *   1  a pure-V2 chain this builder produced (idempotent re-derive)
 *   2  a FOREIGN chain database (legacy V1, a seam successor, anything
 *      this builder did not make)
 *  -1  could not tell (probe fault, or a truncated path)
 *
 * O15J review R2-F1 — this used to ask only "is there a PURE chain
 * here?" and SKIP everything else, so `derive` would happily place a
 * second chain beside a legacy V1 database and return 0. Startup then
 * selects the lexicographically smallest filename
 * (nodus_witness.c:597-600), so on a 7-node fleet each node would
 * independently coin-flip which chain it booted — a silent split.
 *
 * The operating rule is that moving to V2 DELETES the V1 chain. That
 * rule now lives in the code: a foreign database makes the derivation
 * REFUSE, loudly, instead of creating the ambiguity. A forgotten
 * deletion is an error message, not a fork.
 *
 * readdir order does not reach the answer: FOREIGN dominates PURE
 * (both refuse the caller), and a probe fault dominates both, so the
 * result is order-independent — every entry is classified before the
 * function returns. */
static int gen_chain_db_scan(const char *data_path) {
    DIR *dir = opendir(data_path);
    if (!dir) return -1;
    struct dirent *e;
    int saw_pure = 0, saw_foreign = 0, saw_fault = 0;
    while ((e = readdir(dir)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        char path[600];
        int n = snprintf(path, sizeof(path), "%s/%s", data_path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) { saw_fault = 1; continue; }
        switch (nodus_witness_v2_gen_is_pure(path)) {
            case 1:  saw_pure    = 1; break;
            case 0:  saw_foreign = 1; break;
            default: saw_fault   = 1; break;
        }
    }
    closedir(dir);
    if (saw_fault)   return -1;
    if (saw_foreign) return 2;
    return saw_pure ? 1 : 0;
}

/* ── the validated, sorted derivation plan ───────────────────────────── */

/* Everything the derivation needs, computed ONCE from the config and
 * fully validated. Building this IS the config validation: a plan exists
 * only for a derivable config. */
typedef struct {
    uint16_t         val_idx[NODUS_V2_GEN_MAX_VALIDATORS]; /* pubkey ASC */
    dna_dist_leaf_t *leaves;         /* source_id ASC, n_leaves entries  */
    size_t           n_leaves;
    uint64_t         stake_total;    /* Σ self_stake                      */
    uint64_t         alloc_total;    /* Σ allocation amounts              */
    uint64_t         total_claimable;/* total_supply_raw − stake_total    */
} gen_plan_t;

static void gen_plan_free(gen_plan_t *p) {
    if (!p) return;
    free(p->leaves);
    p->leaves = NULL;
    p->n_leaves = 0;
}

/* qsort comparator over dna_dist_leaf_t. The key (source_id) is a strict
 * total order once duplicates are rejected, so qsort's instability
 * cannot influence the result. */
static int gen_leaf_qcmp(const void *a, const void *b) {
    return dna_dist_leaf_cmp((const dna_dist_leaf_t *)a,
                             (const dna_dist_leaf_t *)b);
}

static int gen_plan_build(const nodus_v2_gen_config_t *cfg, gen_plan_t *p) {
    if (!cfg || !p) return -1;
    memset(p, 0, sizeof(*p));

    if (cfg->config_version != NODUS_V2_GEN_CONFIG_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "config_version %u != %u — refusing",
                      (unsigned)cfg->config_version,
                      (unsigned)NODUS_V2_GEN_CONFIG_VERSION);
        return -1;
    }

    /* ── build identity (L1-F3 DETECTION, not removal) ────────────────
     * DNAC_EPOCH_LENGTH is -D-overridable and reaches the genesis
     * BlockID through the epoch-keyed vset snapshots
     * (nodus_witness_vset.c:720-721), so a harness build and a
     * production build reading the SAME config would otherwise derive
     * two different chain ids in silence. The config commits the value
     * it was written for; a build that disagrees refuses to derive. */
    if (cfg->epoch_length != (uint64_t)DNAC_EPOCH_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG, "config epoch_length %llu != the compiled "
                      "DNAC_EPOCH_LENGTH %llu — this build cannot derive "
                      "this config's chain (fail closed)",
                      (unsigned long long)cfg->epoch_length,
                      (unsigned long long)DNAC_EPOCH_LENGTH);
        return -1;
    }

    /* ── L2-F3: the claim window ──────────────────────────────────────
     * The manifest codec bounds the window only by start <= end
     * (shared/dnac/manifest_wire.c:152). The claim gate admits a claim
     * iff start <= h <= end (nodus_witness_v2_claims.c:478-480), and
     * genesis is height 0 and carries no claims — so [0,0] admits
     * NOTHING and strands the entire distribution forever while the
     * supply equation still balances (the stranded value is counted as
     * unclaimed distribution). Under DNA_POSTDL_RETAIN any window that
     * expires does the same, so the general "end >= 1" satisfiability
     * rule is not enough. The shipped seam pins [0, UINT64_MAX]
     * (nodus_witness_v2_seam.c:481-482) and so does this builder: the
     * fields are carried in the config (they are committed into
     * source_commit — no hidden defaults) but exactly one pair of
     * values is accepted. */
    if (cfg->claim_start_height != 0 ||
        cfg->claim_end_height != UINT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "claim window [%llu, %llu] is not the "
                      "pinned [0, UINT64_MAX] — a narrower window strands "
                      "the distribution while the supply equation still "
                      "balances (fail closed)",
                      (unsigned long long)cfg->claim_start_height,
                      (unsigned long long)cfg->claim_end_height);
        return -1;
    }

    /* ── L2-F6 Rule P.1 — EXACT initial validator count ───────────────
     * dnac/src/transaction/genesis.c:112-118 owns this on the legacy
     * path, which a pure-V2 chain never executes;
     * nodus_witness_v2_genesis_ex has no equivalent. */
    if (cfg->n_validators != (uint16_t)DNAC_COMMITTEE_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "n_validators=%u != %u (Rule P.1)",
                      (unsigned)cfg->n_validators,
                      (unsigned)DNAC_COMMITTEE_SIZE);
        return -1;
    }

    /* ── per-validator shape, and the L2-F4 graduation predicate ──────
     * An empty or short unstake_destination_fp passes genesis — the
     * validator merkle leaf legally hashes 128 zero bytes
     * (nodus_witness_merkle.c:1050-1066) — and then FAULTS -2 at the
     * first RETIRING graduation (nodus_witness_v2_epoch.c:347-352),
     * which is a deterministic chain halt with no recovery. The check
     * runs against the graduation's OWN exported predicate, not a copy
     * of it, so the two cannot drift apart. */
    for (uint16_t i = 0; i < cfg->n_validators; i++) {
        const nodus_v2_gen_validator_t *v = &cfg->validators[i];

        if (v->self_stake != DNAC_SELF_STAKE_AMOUNT) {
            QGP_LOG_ERROR(LOG_TAG, "validator[%u] self_stake %llu != the "
                          "exact genesis self-bond %llu", (unsigned)i,
                          (unsigned long long)v->self_stake,
                          (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
            return -1;
        }
        if (v->commission_bps > DNAC_COMMISSION_BPS_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "validator[%u] commission_bps %u > %u",
                          (unsigned)i, (unsigned)v->commission_bps,
                          (unsigned)DNAC_COMMISSION_BPS_MAX);
            return -1;
        }

        dnac_validator_record_t rec;
        memset(&rec, 0, sizeof(rec));
        memcpy(rec.pubkey, v->pubkey, DNAC_PUBKEY_SIZE);
        memcpy(rec.unstake_destination_pubkey, v->unstake_destination_pubkey,
               DNAC_PUBKEY_SIZE);
        memcpy(rec.unstake_destination_fp, v->unstake_destination_fp,
               DNAC_FINGERPRINT_SIZE);
        rec.self_stake         = v->self_stake;
        rec.commission_bps     = v->commission_bps;
        rec.status             = DNAC_VALIDATOR_ACTIVE;
        rec.active_since_block = 1ULL;
        if (!nodus_witness_v2_epoch_val_rec_ok(&rec)) {
            QGP_LOG_ERROR(LOG_TAG, "validator[%u] is not writable-shaped: "
                          "it would pass genesis and then HALT the chain "
                          "at the first graduation boundary (L2-F4)",
                          (unsigned)i);
            return -1;
        }

        if (add_u64(p->stake_total, v->self_stake, &p->stake_total) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "self-stake sum overflow");
            return -1;
        }
    }

    /* ── L2-F6 Rule P.3 — pairwise-distinct validator pubkeys ─────────
     * genesis.c:157-165's O(N²/2) loop. The validators table would
     * reject the second insert on its pubkey_hash primary key, but that
     * is an implementation accident of the storage layer; the RULE is
     * stated here, before anything is written. */
    for (uint16_t i = 0; i < cfg->n_validators; i++)
        for (uint16_t j = (uint16_t)(i + 1); j < cfg->n_validators; j++)
            if (memcmp(cfg->validators[i].pubkey,
                       cfg->validators[j].pubkey, DNAC_PUBKEY_SIZE) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "duplicate validator pubkey at "
                              "%u/%u (Rule P.3)", (unsigned)i, (unsigned)j);
                return -1;
            }

    /* ── canonical validator order: pubkey bytes ASC ──────────────────
     * A strict total order (P.3 above proved the keys distinct).
     * Insertion sort over an index array: N <= 30, no library
     * comparator state, identical on every platform.
     *
     * This order fixes the ENCODING order and the INSERT order (hence
     * the rowid order a whole-database digest sees). It does NOT and
     * cannot fix the committed validator_set_hash — that snapshot is
     * ordered stake DESC with a SHA3-512 tiebreak
     * (nodus_witness_validator.c:320, nodus_witness_committee.c:46-63),
     * and with the equal-stake composition enforced above all
     * validators form ONE tied group. */
    for (uint16_t i = 0; i < cfg->n_validators; i++) p->val_idx[i] = i;
    for (uint16_t i = 1; i < cfg->n_validators; i++) {
        uint16_t key = p->val_idx[i];
        int j = (int)i - 1;
        while (j >= 0 &&
               memcmp(cfg->validators[p->val_idx[j]].pubkey,
                      cfg->validators[key].pubkey, DNAC_PUBKEY_SIZE) > 0) {
            p->val_idx[j + 1] = p->val_idx[j];
            j--;
        }
        p->val_idx[j + 1] = key;
    }

    /* ── allocations ──────────────────────────────────────────────────*/
    if (cfg->n_allocs < 1 || cfg->n_allocs > NODUS_V2_GEN_MAX_ALLOCS ||
        !cfg->allocs) {
        QGP_LOG_ERROR(LOG_TAG, "allocation count %u out of range [1, %u]",
                      (unsigned)cfg->n_allocs,
                      (unsigned)NODUS_V2_GEN_MAX_ALLOCS);
        return -1;
    }

    p->leaves = calloc((size_t)cfg->n_allocs, sizeof(*p->leaves));
    if (!p->leaves) return -1;
    p->n_leaves = (size_t)cfg->n_allocs;
    for (size_t i = 0; i < p->n_leaves; i++) {
        dna_dist_leaf_t *L = &p->leaves[i];
        L->leaf_version  = DNA_DIST_VERSION;
        L->source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
        memcpy(L->source_id, cfg->allocs[i].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        /* O15J review R1-F4 — the header has always said `amount` MUST
         * be >= 1 (nodus_witness_v2_gen.h) and nothing enforced it. A
         * zero-amount leaf passes the P.2 supply sum (it contributes
         * nothing) and passes the duplicate check (dna_dist_leaf_cmp
         * compares source_id ONLY, shared/dnac/manifest_wire.c:331-339),
         * so nodus_witness_v2_gen_config_validate answered YES for a
         * config nodus_witness_v2_gen_derive then refused downstream in
         * dna_dist_leaf_hash. An oracle that disagrees with the thing it
         * is an oracle for is worse than no oracle. */
        if (cfg->allocs[i].amount < 1) {
            QGP_LOG_ERROR(LOG_TAG,
                          "allocation[%zu] amount is 0 — a distribution "
                          "leaf must carry at least 1 raw unit", i);
            gen_plan_free(p);
            return -1;
        }
        L->source_amount = cfg->allocs[i].amount;
        memcpy(L->dest_binding, cfg->allocs[i].dest_binding, 64);
        if (add_u64(p->alloc_total, L->source_amount,
                    &p->alloc_total) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "allocation sum overflow");
            gen_plan_free(p);
            return -1;
        }
    }

    /* Canonical leaf order: source_id ASC — the SAME order
     * dna_dist_snapshot_root accepts, and the only one it accepts, so
     * caller insertion order can never reach the snapshot root. */
    qsort(p->leaves, p->n_leaves, sizeof(*p->leaves), gen_leaf_qcmp);
    for (size_t i = 1; i < p->n_leaves; i++)
        if (dna_dist_leaf_cmp(&p->leaves[i - 1], &p->leaves[i]) >= 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "duplicate allocation source_id "
                          "— the distribution identity would collide");
            gen_plan_free(p);
            return -1;
        }

    /* ── L2-F6 Rule P.2 — the supply sum ──────────────────────────────
     * genesis.c:120-152: Σ outputs + Σ self-bond == the chain's
     * committed initial supply. Under- AND over-allocation both reject. */
    if (cfg->total_supply_raw < 1) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "total_supply_raw must be >= 1");
        gen_plan_free(p);
        return -1;
    }
    /* O15J review R2-F8 — bound it to what SQLite can store SIGNED.
     * nodus_witness_supply_init binds with sqlite3_bind_int64((int64_t)),
     * so a value above INT64_MAX is stored NEGATIVE, and the derivation's
     * own read-back comparison round-trips through the same signed cast
     * and therefore agrees with itself. The derivation does die further
     * downstream on the SUM(remaining) post-condition, but that is
     * fail-closed BY ACCIDENT of a later check rather than by the stated
     * overflow rule (G4). State the rule where it belongs. */
    if (cfg->total_supply_raw > (uint64_t)INT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG,
                      "total_supply_raw %llu exceeds INT64_MAX — it "
                      "cannot be stored without becoming negative",
                      (unsigned long long)cfg->total_supply_raw);
        gen_plan_free(p);
        return -1;
    }
    if (p->stake_total > cfg->total_supply_raw) {
        QGP_LOG_ERROR(LOG_TAG, "stake-lock %llu exceeds total_supply_raw "
                      "%llu (Rule P.2)",
                      (unsigned long long)p->stake_total,
                      (unsigned long long)cfg->total_supply_raw);
        gen_plan_free(p);
        return -1;
    }
    /* total_claimable is derived from the SUPPLY side, never from the
     * leaf sum — that is what makes the check_totals call below a real
     * cross-check rather than a restatement of its own input. */
    p->total_claimable = cfg->total_supply_raw - p->stake_total;

    {
        uint64_t sum = 0;
        if (add_u64(p->alloc_total, p->stake_total, &sum) != 0 ||
            sum != cfg->total_supply_raw) {
            QGP_LOG_ERROR(LOG_TAG, "Σ allocations %llu + Σ self-stake %llu "
                          "!= total_supply_raw %llu (Rule P.2)",
                          (unsigned long long)p->alloc_total,
                          (unsigned long long)p->stake_total,
                          (unsigned long long)cfg->total_supply_raw);
            gen_plan_free(p);
            return -1;
        }
    }

    /* ── L2-F2: total_claimable vs the leaves ─────────────────────────
     * dna_dist_check_totals had exactly ONE production caller and it was
     * inside the seam step this builder replaces
     * (nodus_witness_v2_seam.c:281-286) — so nothing on the new path
     * tied the manifest's total_claimable to the leaf set. It is tied
     * here, over the SAME conversion parameters the manifest commits
     * (1:1, FLOOR), so the committed field cannot lie about the leaves.
     * A zero-amount or unconvertible leaf dies inside dna_dist_converted
     * before any sum is compared. */
    if (dna_dist_check_totals(p->leaves, p->n_leaves, 1, 1,
                              DNA_DISTROUND_FLOOR,
                              p->total_claimable) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "the distribution leaves do not total the "
                      "claimable amount %llu (L2-F2)",
                      (unsigned long long)p->total_claimable);
        gen_plan_free(p);
        return -1;
    }

    return 0;
}

int nodus_witness_v2_gen_config_validate(const nodus_v2_gen_config_t *cfg) {
    gen_plan_t plan;
    int rc = gen_plan_build(cfg, &plan);
    gen_plan_free(&plan);
    return rc;
}

/* ── the canonical config encoding ───────────────────────────────────── */

/* Layout: the header's table, verbatim. */
#define GEN_VAL_ENC_LEN  (DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + \
                          DNAC_FINGERPRINT_SIZE + 8 + 2)
#define GEN_CFG_HEAD_LEN (NODUS_V2_GEN_CFG_TAG_LEN + 4 + 8 + 8 + 8 + 8 + 2)

static int gen_encode_planned(const nodus_v2_gen_config_t *cfg,
                              const gen_plan_t *plan,
                              uint8_t **out, size_t *out_len) {
    if (!cfg || !plan || !out || !out_len) return -1;

    const size_t alloc_enc_len = 2 + NODUS_V2_GEN_SRCID_LEN + 8 + 64;
    size_t need = GEN_CFG_HEAD_LEN +
                  (size_t)cfg->n_validators * GEN_VAL_ENC_LEN + 4 +
                  plan->n_leaves * alloc_enc_len;

    uint8_t *buf = calloc(1, need);
    if (!buf) return -1;
    uint8_t *p = buf;

    /* The tag is zero-padded to exactly NODUS_V2_GEN_CFG_TAG_LEN; the
     * buffer is calloc'd, so the pad bytes are zero by construction and
     * no uninitialised byte can reach the digest. */
    memcpy(p, NODUS_V2_GEN_CFG_TAG, sizeof(NODUS_V2_GEN_CFG_TAG) - 1);
    p += NODUS_V2_GEN_CFG_TAG_LEN;

    put_be32(p, cfg->config_version);      p += 4;
    put_be64(p, cfg->total_supply_raw);    p += 8;
    put_be64(p, cfg->epoch_length);        p += 8;
    put_be64(p, cfg->claim_start_height);  p += 8;
    put_be64(p, cfg->claim_end_height);    p += 8;
    put_be16(p, cfg->n_validators);        p += 2;

    for (uint16_t i = 0; i < cfg->n_validators; i++) {
        const nodus_v2_gen_validator_t *v =
            &cfg->validators[plan->val_idx[i]];
        memcpy(p, v->pubkey, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
        memcpy(p, v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
        memcpy(p, v->unstake_destination_fp, DNAC_FINGERPRINT_SIZE);
        p += DNAC_FINGERPRINT_SIZE;
        put_be64(p, v->self_stake);        p += 8;
        put_be16(p, v->commission_bps);    p += 2;
    }

    put_be32(p, (uint32_t)plan->n_leaves); p += 4;
    for (size_t i = 0; i < plan->n_leaves; i++) {
        const dna_dist_leaf_t *L = &plan->leaves[i];
        put_be16(p, L->source_id_len);     p += 2;
        memcpy(p, L->source_id, NODUS_V2_GEN_SRCID_LEN);
        p += NODUS_V2_GEN_SRCID_LEN;
        put_be64(p, L->source_amount);     p += 8;
        memcpy(p, L->dest_binding, 64);    p += 64;
    }

    if ((size_t)(p - buf) != need) {       /* internal invariant */
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = need;
    return 0;
}

int nodus_witness_v2_gen_config_encode(const nodus_v2_gen_config_t *cfg,
                                       uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;
    int rc = gen_encode_planned(cfg, &plan, out, out_len);
    gen_plan_free(&plan);
    return rc;
}

static int gen_source_commit_planned(const nodus_v2_gen_config_t *cfg,
                                     const gen_plan_t *plan,
                                     uint8_t out[NODUS_V2_GEN_SRCCOMMIT_LEN]) {
    uint8_t *buf = NULL;
    size_t len = 0;
    if (gen_encode_planned(cfg, plan, &buf, &len) != 0) return -1;
    int rc = qgp_sha3_512(buf, len, out);
    free(buf);
    return rc == 0 ? 0 : -1;
}

int nodus_witness_v2_gen_source_commit(
        const nodus_v2_gen_config_t *cfg,
        uint8_t out[NODUS_V2_GEN_SRCCOMMIT_LEN]) {
    if (!out) return -1;
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;
    int rc = gen_source_commit_planned(cfg, &plan, out);
    gen_plan_free(&plan);
    return rc;
}

/* ── step 5: seed the SYSTEM state from the config ───────────────────── */

static int gen_seed_state(nodus_witness_t *w2,
                          const nodus_v2_gen_config_t *cfg,
                          const gen_plan_t *plan,
                          const uint8_t source_commit[64]) {
    /* Validators, in the canonical pubkey ASC order. Written through the
     * production insert (nodus_validator_insert) — one writer, never a
     * parallel SQL shape. Every field is explicit: no schema default
     * decides a committed value.
     *
     * active_since_block = 1 mirrors the legacy genesis seeder
     * (nodus_witness_genesis_seed.c:116); the attendance watermarks are
     * 0 because a chain born at height 0 has no attendance history — the
     * same state the seam RESETS its transplanted rows to
     * (nodus_witness_v2_seam.c:361-363). */
    for (uint16_t i = 0; i < cfg->n_validators; i++) {
        const nodus_v2_gen_validator_t *v =
            &cfg->validators[plan->val_idx[i]];
        dnac_validator_record_t rec;
        memset(&rec, 0, sizeof(rec));
        memcpy(rec.pubkey, v->pubkey, DNAC_PUBKEY_SIZE);
        memcpy(rec.unstake_destination_pubkey, v->unstake_destination_pubkey,
               DNAC_PUBKEY_SIZE);
        memcpy(rec.unstake_destination_fp, v->unstake_destination_fp,
               DNAC_FINGERPRINT_SIZE);
        rec.self_stake                  = v->self_stake;
        rec.total_delegated             = 0;
        rec.external_delegated          = 0;
        rec.commission_bps              = v->commission_bps;
        rec.pending_commission_bps      = 0;
        rec.pending_effective_block     = 0;
        rec.status                      = DNAC_VALIDATOR_ACTIVE;
        rec.active_since_block          = 1ULL;
        rec.unstake_commit_block        = 0;
        rec.last_validator_update_block = 0;
        rec.consecutive_missed_epochs   = 0;
        rec.last_signed_block           = 0;
        rec.signed_blocks_this_epoch    = 0;
        if (nodus_validator_insert(w2, &rec) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "validator insert [%u] failed",
                          (unsigned)i);
            return -1;
        }
    }

    /* validator_stats.active_count — the row exists from
     * create_chain_db (nodus_witness.c:285, seeded 0); the legacy
     * genesis seeder UPDATEs it the same way
     * (nodus_witness_genesis_seed.c:139-149). Carried in the genesis
     * bundle since O15J L1-F1. */
    {
        char sql[160];
        snprintf(sql, sizeof(sql),
                 "UPDATE validator_stats SET value = %u "
                 "WHERE key = 'active_count'",
                 (unsigned)cfg->n_validators);
        if (gen_exec(w2->db, sql) != 0) return -1;
        if (sqlite3_changes(w2->db) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "validator_stats active_count row missing");
            return -1;
        }
    }

    /* supply_tracking — L2-F1's PRODUCER half. Written BEFORE genesis so
     * the conservation invariant has a row to evaluate from the very
     * first block, and so the manifest's genesis-supply cross-check
     * (nodus_witness_v2_claims.c manifest_commit) compares two real
     * values instead of 0 against 0.
     *
     * last_tx_hash is provenance-only (it reaches no consensus value)
     * but it must still be DETERMINISTIC: source_commit is the one
     * 64-byte value that identifies this genesis, so it is used rather
     * than an invented constant. */
    {
        int rc = nodus_witness_supply_init(w2, cfg->total_supply_raw,
                                           source_commit);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "supply_init failed (rc=%d)", rc);
            return -1;
        }
    }

    /* delegations, epoch_state and chain_config_history are EMPTY at a
     * pure-V2 genesis, and that emptiness is ASSERTED rather than
     * produced by a DELETE — a future create_chain_db that seeded a row
     * must fail loudly here, not be silently erased.
     *
     *   delegations           nothing has delegated yet.
     *   epoch_state           the V2 lane has no emission and no
     *                         settlement (L2-F5), so no pool accrues;
     *                         fabricating an epoch-0 row would mean
     *                         inventing a snapshot_hash that no V2
     *                         reader produces or consumes. The supply
     *                         invariant COALESCEs the absent sum to 0
     *                         (nodus_witness_v2_claims.c:851).
     *   chain_config_history  no governance change can precede genesis
     *                         (nodus_witness_vset.c:717-718). */
    {
        static const char *const must_be_empty[] = {
            "delegations", "epoch_state", "chain_config_history"
        };
        for (size_t i = 0; i < sizeof(must_be_empty) /
                               sizeof(must_be_empty[0]); i++) {
            char sql[96];
            sqlite3_int64 n = -1;
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s",
                     must_be_empty[i]);
            if (gen_count(w2->db, sql, &n) != 0) return -1;
            if (n != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s holds %lld rows before a pure-V2 "
                              "genesis — refusing", must_be_empty[i],
                              (long long)n);
                return -1;
            }
        }
    }
    return 0;
}

/* ── the derivation ──────────────────────────────────────────────────── */

int nodus_witness_v2_gen_derive(const char *data_path,
                                const nodus_v2_gen_config_t *cfg,
                                uint8_t out_chain32[32]) {
    if (!data_path || !data_path[0] || !cfg) return -1;

    /* ── 1. Validate the config COMPLETELY, before any filesystem or
     * database work. A plan exists only for a derivable config. ────── */
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;

    int pe = gen_chain_db_scan(data_path);
    if (pe < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "could not classify the chain databases already in the data "
            "path — refusing to derive (fail closed)");
        gen_plan_free(&plan);
        return -1;
    }
    if (pe == 2) {
        /* R2-F1. The V1 chain must be DELETED before the V2 chain is
         * created; two chain databases in one data path make startup
         * selection a filename coin-flip (nodus_witness.c:597-600). */
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "a FOREIGN chain database is already present in the data path "
            "— refusing to derive. Moving to Ledger V2 deletes the "
            "previous chain; remove it first. Deriving beside it would "
            "leave two chains and let each node boot a different one.");
        gen_plan_free(&plan);
        return -1;
    }
    if (pe == 1) {                              /* idempotent */
        QGP_LOG_INFO(LOG_TAG, "%s",
                     "a pure-V2 chain already exists — nothing to derive");
        gen_plan_free(&plan);
        return 0;
    }

    /* ── 2. The source binding. No terminal block, no legacy chain: the
     * config IS the source, and source_commit is its digest. ───────── */
    uint8_t source_commit[NODUS_V2_GEN_SRCCOMMIT_LEN];
    if (gen_source_commit_planned(cfg, &plan, source_commit) != 0) {
        gen_plan_free(&plan);
        return -1;
    }

    /* ── 3. The distribution snapshot root over the canonical leaves.
     * dna_dist_snapshot_root accepts ONLY strictly ascending source_id
     * order, so it re-proves the plan's ordering as a side effect. ── */
    uint8_t snap_root[64];
    if (dna_dist_snapshot_root(plan.leaves, plan.n_leaves,
                               snap_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "distribution snapshot root failed");
        gen_plan_free(&plan);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "deriving a pure Ledger V2 chain: %u validators, "
                 "%zu allocations, %llu raw claimable of %llu total",
                 (unsigned)cfg->n_validators, plan.n_leaves,
                 (unsigned long long)plan.total_claimable,
                 (unsigned long long)cfg->total_supply_raw);

    /* ── 4. Provisional database, deterministic name ─────────────────
     * Derived in a SCRATCH SUBDIRECTORY: nodus_witness_create_chain_db
     * archives every OTHER witness_*.db in its data_path (the stale-
     * chain discipline), which must not touch anything already in the
     * real data_path. Only a COMPLETE chain is renamed up. */
    uint8_t prov_full[64], prov16[16];
    if (qgp_sha3_512(source_commit, sizeof(source_commit), prov_full) != 0) {
        gen_plan_free(&plan);
        return -1;
    }
    memcpy(prov16, prov_full, 16);

    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    if (!w2) { gen_plan_free(&plan); return -1; }
    /* A calloc'd handle has cached_committee_epoch_start == 0, which the
     * committee cache reads as a VALID entry for epoch 0 holding zero
     * members (nodus_witness_committee.c:474-492). The vset builder used
     * on this path calls nodus_committee_compute_for_epoch directly and
     * bypasses the cache (nodus_witness_vset.c:341), so this is hygiene
     * rather than a load-bearing fix — but the invalid marker is
     * UINT64_MAX (nodus_witness.h:743) and every other constructor sets
     * it (nodus_witness.c:915, nodus_witness_v2_join.c:108). */
    w2->cached_committee_epoch_start = UINT64_MAX;
    /* O15J review R2-F3 — CHECK THE TRUNCATION. `data_path` is
     * char[256] (nodus_witness.h). This snprintf used to be unchecked,
     * so a long data path silently produced a PREFIX of itself: at
     * exactly 255 characters the "scratch" path IS the operator's real
     * witness directory, and gen_scratch_clear below unlinks every file
     * in whatever directory it is handed. A successful derivation would
     * then delete its own output and everything beside it, and still
     * return 0. Refuse instead — a path we cannot express is not a path
     * we may clear. */
    int pn = snprintf(w2->data_path, sizeof(w2->data_path), "%s/v2gen.tmp",
                      data_path);
    if (pn < 0 || (size_t)pn >= sizeof(w2->data_path)) {
        QGP_LOG_ERROR(LOG_TAG,
            "data path too long (%zu bytes) to form a scratch directory "
            "within %zu — refusing to derive rather than clearing a "
            "truncated path", strlen(data_path), sizeof(w2->data_path));
        free(w2);
        gen_plan_free(&plan);
        return -1;
    }
    gen_scratch_clear(w2->data_path);           /* crashed prior attempt */
    if (mkdir(w2->data_path, 0700) != 0 && errno != EEXIST) {
        free(w2);
        gen_plan_free(&plan);
        return -1;
    }

    char prov_path[600];
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
        /* Mark the handle a successor BEFORE any validator-set seeding:
         * nodus_witness_vset_commit_genesis seeds the epoch-0/E
         * snapshots through the writer guard, which is gated on
         * v2_successor; without this the genesis snapshots seed uncapped
         * (the seam's O15F Task 1, nodus_witness_v2_seam.c:328). A
         * deterministic local act every node performs identically. */
        w2->v2_successor = 1;
        /* S12: every block a pure-V2 chain commits carries its canonical
         * envelope bytes and its per-block claim bytes + count. */
        if (nodus_witness_db_migrate_v2s12(w2) != 0) break;
        if (nodus_chain_config_db_migrate(w2) != 0) break;

        /* ── 5. SYSTEM state, from the config ───────────────────────── */
        if (gen_seed_state(w2, cfg, &plan, source_commit) != 0) break;

        /* ── 6. Authority + registry + manifest + genesis ─────────────
         * ORDER IS LOAD-BEARING (the seam's step 6): the validator
         * snapshots feed the SYSTEM payload root, and
         * domreg_init_genesis commits that root — genesis_ex re-runs it
         * and byte-compares, so the snapshots must exist FIRST. The
         * argument to commit_genesis is the legacy BLOCK HEIGHT sentinel
         * (VSET_GENESIS_BLOCK_HEIGHT), not a count. */
        {
            sqlite3_int64 n_snap = -1;
            if (gen_count(w2->db,
                    "SELECT COUNT(*) FROM validator_set_snapshots",
                    &n_snap) != 0) break;
            if (n_snap != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a fresh database already "
                              "holds validator snapshots — refusing");
                break;
            }
            if (nodus_witness_vset_commit_genesis(w2, 1) != 0) break;
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

        /* The committed supply is read BACK from the row this
         * derivation wrote — three-valued, so a DB fault can never
         * become the value 0 in a hash preimage (the seam's L1-F7). */
        uint64_t gsupply = 0;
        {
            nodus_witness_supply_t sup;
            memset(&sup, 0, sizeof(sup));
            int src = nodus_witness_supply_get(w2, &sup);
            if (src != 0) {
                QGP_LOG_ERROR(LOG_TAG, "supply row unreadable after seeding "
                              "(rc=%d) — ABORT", src);
                break;
            }
            gsupply = sup.genesis_supply;
            if (gsupply != cfg->total_supply_raw) break;
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
        m.source_tag_len = (uint16_t)NODUS_V2_GEN_SOURCE_TAG_LEN;
        memcpy(m.source_tag, NODUS_V2_GEN_SOURCE_TAG,
               NODUS_V2_GEN_SOURCE_TAG_LEN);
        m.source_commit_len = (uint16_t)NODUS_V2_GEN_SRCCOMMIT_LEN;
        memcpy(m.source_commit, source_commit, NODUS_V2_GEN_SRCCOMMIT_LEN);
        memcpy(m.snapshot_root, snap_root, 64);
        m.leaf_count = (uint64_t)plan.n_leaves;
        m.conv_numerator = 1;
        m.conv_denominator = 1;
        m.rounding_mode = DNA_DISTROUND_FLOOR;
        m.excluded_amount = 0;
        m.total_claimable = plan.total_claimable;
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
            QGP_LOG_ERROR(LOG_TAG, "%s", "pure-V2 genesis FAILED");
            break;
        }

        /* ── 7. Post-conditions ─────────────────────────────────────── */

        /* No spendable value exists at genesis: the whole non-bonded
         * supply sits in the claim reserve. */
        sqlite3_int64 n_utxo = -1;
        if (gen_count(w2->db, "SELECT COUNT(*) FROM utxo_set",
                      &n_utxo) != 0 || n_utxo != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "a pure-V2 genesis holds spendable UTXOs — ABORT");
            break;
        }
        {
            sqlite3_stmt *st = NULL;
            sqlite3_int64 remaining = -1;
            if (sqlite3_prepare_v2(w2->db,
                    "SELECT COALESCE(SUM(remaining), -1) FROM v2_dist_state",
                    -1, &st, NULL) != SQLITE_OK)
                break;
            int rc = sqlite3_step(st);
            if (rc == SQLITE_ROW) remaining = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
            if (rc != SQLITE_ROW || remaining < 0 ||
                (uint64_t)remaining != plan.total_claimable) {
                QGP_LOG_ERROR(LOG_TAG, "claim reserve %lld != claimable "
                              "%llu — ABORT", (long long)remaining,
                              (unsigned long long)plan.total_claimable);
                break;
            }
        }

        /* Σ self_stake must be exactly what the config bonded. */
        {
            sqlite3_int64 bonded = -1;
            if (gen_count(w2->db,
                    "SELECT COALESCE(SUM(self_stake),0) FROM validators",
                    &bonded) != 0) break;
            if ((uint64_t)bonded != plan.stake_total) {
                QGP_LOG_ERROR(LOG_TAG, "committed self-stake %lld != %llu "
                              "— ABORT", (long long)bonded,
                              (unsigned long long)plan.stake_total);
                break;
            }
        }

        /* ── L2-F4, at the COMMITTED-ROW level ───────────────────────
         * The config was checked; this checks what actually LANDED. A
         * storage layer that truncated a fingerprint on the way in would
         * otherwise ship a chain that halts at its first graduation. */
        {
            int bad = 0;
            for (uint16_t i = 0; i < cfg->n_validators && !bad; i++) {
                dnac_validator_record_t got;
                if (nodus_validator_get(w2, cfg->validators[i].pubkey,
                                        &got) != 0 ||
                    !nodus_witness_v2_epoch_val_rec_ok(&got))
                    bad = 1;
            }
            if (bad) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "a COMMITTED validator row is "
                              "not writable-shaped — ABORT (L2-F4)");
                break;
            }
        }

        /* ── L2-F1, the producer half ────────────────────────────────
         * The seam never asserted this. The conservation invariant must
         * BALANCE on the derived chain before it is allowed to exist:
         *   genesis + 0 − 0 == 0 utxo + Σ self_stake + 0 delegated
         *                      + 0 pool + unclaimed + 0 shielded
         * A config whose numbers do not balance dies here even if every
         * rule above somehow admitted it. */
        if (nodus_witness_v2_supply_check(w2) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the supply equation does not "
                          "balance on the derived chain — ABORT");
            break;
        }

        uint8_t chain32[32];
        if (nodus_witness_v2_chain_id(w2, chain32) != 0) break;

        /* ── 7b. The canonical genesis bundle, persisted NOW while the
         * base tables still hold their exact genesis-time bytes. A
         * chain that cannot serialize its own genesis is not a valid
         * bootstrap source, so the whole derivation aborts. */
        if (nodus_witness_v2_bundle_persist(w2) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "genesis bundle persistence FAILED — ABORT");
            break;
        }

        /* ── 8. Land the real name in the REAL data_path — rename only
         * after a COMPLETE derivation (same filesystem, atomic). ───── */
        sqlite3_close(w2->db);
        w2->db = NULL;
        char real_path[600];
        {
            char hex[33];
            for (int i = 0; i < 16; i++)
                snprintf(hex + i * 2, 3, "%02x", chain32[i]);
            snprintf(real_path, sizeof(real_path), "%s/witness_%s.db",
                     data_path, hex);
        }
        if (rename(prov_path, real_path) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "rename to %s failed: %s", real_path,
                          strerror(errno));
            break;
        }

        if (out_chain32) memcpy(out_chain32, chain32, 32);
        QGP_LOG_INFO(LOG_TAG, "pure Ledger V2 chain derived: %s "
                     "(reserve=%llu raw across %zu claim leaves, "
                     "bonded=%llu)", real_path,
                     (unsigned long long)plan.total_claimable,
                     plan.n_leaves,
                     (unsigned long long)plan.stake_total);
        ok = 0;
    } while (0);

    if (w2->db) { sqlite3_close(w2->db); w2->db = NULL; }
    gen_scratch_clear(w2->data_path);           /* nothing partial */
    free(w2);
    gen_plan_free(&plan);
    return ok;
}
