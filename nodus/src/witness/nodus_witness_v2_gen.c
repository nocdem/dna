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
#include "witness/nodus_witness_emission.h"  /* DNAC_BLOCKS_PER_YEAR,
                                              * DNAC_DECIMAL_UNIT — the
                                              * committed schedule (2C)  */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_bundle.h"
#include "witness/nodus_witness_cmt_store.h" /* W2: the genesisDoc row   */
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"   /* the committed econ band
                                              * read-back (Block 2C)     */
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_schema.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/domain_wire.h"
#include "dnac/ledger_ids.h"
#include "dnac/manifest_wire.h"
#include "dnac/validator.h"
#include "dnac/vset_wire.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"    /* D7 — the payout-key ↔
                                              * fingerprint derivation,
                                              * the SAME converter the
                                              * legacy staking path uses
                                              * (nodus_witness_bft.c)   */
#include "crypto/utils/qgp_log.h"

/* O16A / D3 — for NODUS_PARTIAL_WIPE_GENESIS_MARKER only. This is a
 * MACRO, not a handle: the module still takes no nodus_server_t and no
 * nodus_witness_t from a caller, so the G1/G2 argument that nothing
 * network-supplied can reach a derived byte
 * (nodus_witness_v2_gen.h:362-364) is untouched. The joiner beside this
 * one includes the same header for the same reason
 * (nodus_witness_v2_join.c:20). */
#include "server/nodus_server.h"

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
/* Block 2C — the reserved econ band must stay OUTSIDE the governance
 * param space, or a committee vote could rewrite an economic parameter
 * that this builder committed once and for all. This is the compile-time
 * half of the guarantee; the runtime half is
 * nodus_chain_config_scalar_rules' allowlist. */
_Static_assert(NODUS_CC_ECON_PARAM_MIN > DNAC_CFG_PARAM_MAX_ID,
               "the reserved economic band overlaps the governance param "
               "space — a vote could rewrite a genesis economic parameter");
_Static_assert(NODUS_CC_ECON_PARAM_MAX <= 255u,
               "a param_id must fit the uint8_t the chain_config merkle "
               "leaf preimage stores");
/* source_commit is bound into chain_config_history.tx_hash, which the
 * schema declares NOT NULL and 64 bytes wide everywhere else. */
_Static_assert(NODUS_V2_GEN_SRCCOMMIT_LEN == 64,
               "the seeded econ rows bind source_commit as a 64-byte "
               "tx_hash");

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

/* The probe body. `nodus_witness_v2_gen_is_pure` is the public,
 * verdict-only face of this; the derivation additionally needs the
 * SOURCE COMMIT of a chain it found (D4), and reading it a second time
 * would mean opening the database twice and — worse — deciding the
 * verdict against one read and the identity against another.
 *
 * The three-valued contract is unchanged (1 pure / 0 not ours /
 * -1 could not tell). `out_commit` is optional and is written ONLY on a
 * 1; every other return leaves it untouched, so a caller cannot mistake
 * an unwritten buffer for a chain's identity. It is exactly
 * NODUS_V2_GEN_SRCCOMMIT_LEN wide because a manifest carrying any other
 * length is refused below rather than copied out. */
static int gen_probe_pure(const char *db_path,
                          uint8_t out_commit[NODUS_V2_GEN_SRCCOMMIT_LEN]) {
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
                /* D4 — carry the identity out with the verdict, from the
                 * SAME decoded manifest that produced it. A chain this
                 * builder made always carries a 64-byte source_commit
                 * (written at the derivation's manifest step); a
                 * shorter or absent one is a manifest this builder did
                 * not write, and answering "yes, pure" while being
                 * unable to say WHICH chain would hand D4 an empty
                 * comparison that trivially passes. Fail closed. */
                if (ret == 1 && out_commit) {
                    if (m.source_commit_len != NODUS_V2_GEN_SRCCOMMIT_LEN) {
                        QGP_LOG_ERROR(LOG_TAG,
                            "%s carries a pure-V2 genesis manifest whose "
                            "source_commit is %u bytes, not %u — its "
                            "identity cannot be compared",
                            db_path, (unsigned)m.source_commit_len,
                            (unsigned)NODUS_V2_GEN_SRCCOMMIT_LEN);
                        ret = -1;
                    } else {
                        memcpy(out_commit, m.source_commit,
                               NODUS_V2_GEN_SRCCOMMIT_LEN);
                    }
                }
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

int nodus_witness_v2_gen_is_pure(const char *db_path) {
    /* The verdict-only face. Passing NULL skips the identity extraction
     * entirely, so this function behaves exactly as it did before D4.
     *
     * ⚠ CORRECTED — an earlier version of this comment named
     * nodus_witness_v2_gate.c as a second caller. It is not one: that
     * file only MENTIONS this function in prose, and its own predicate
     * is v2_authority_present. The single production caller is the
     * post-open chain-role gate at nodus_witness.c:775. The tests call it
     * directly (test_v2_gate_pure.c, test_v2_gen.c) and are likewise
     * unaffected. Verified by grep, not by memory — the wrong version of
     * this sentence survived a review because it read plausibly. */
    return gen_probe_pure(db_path, NULL);
}

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
 * function returns.
 *
 * O16A / D4 — `out_commit` receives the found chain's source_commit and
 * is written ONLY on a 1. Two properties keep that order-independent
 * too:
 *   - the identity comes from the same decoded manifest as the verdict
 *     (gen_probe_pure), so there is no second read to disagree with;
 *   - MORE THAN ONE pure chain in the directory is a FAULT (-1), not a
 *     1: with two pure databases present, "which
 *     chain is here" has no answer, and returning the one readdir
 *     happened to hand over first would let filesystem order decide
 *     whether the derivation refuses. Same class as the R2-F1 coin-flip
 *     this function was written to close, so it gets the same verdict —
 *     the caller cannot tell, therefore it must not proceed.
 *
 * ⚠ THE EXTENSION MOVES THE EXISTING MEANINGS IN **TWO** PLACES, NOT ONE.
 * An earlier version of this comment claimed the multi-chain fault above
 * was the only one. It is not. The second:
 *
 *   - a SINGLE pure-tagged database whose genesis manifest carries a
 *     source_commit of any length other than 64 now returns -1 where it
 *     previously returned 1. gen_probe_pure refuses the length before it
 *     will hand an identity out, and this scan turns that into a fault.
 *     The input is constructible — source_commit_len is a wire field the
 *     codec bounds only by DNA_GMAN_SRCCOMMIT_MAX
 *     (shared/dnac/manifest_wire.c) — so the check is load-bearing, not
 *     decorative.
 *
 * Both new outcomes fail CLOSED, which is why the practical risk is low.
 * The point of recording them is that a future reader must not take "one
 * addition" on trust, as the previous sentence invited. */
static int gen_chain_db_scan(const char *data_path,
                             uint8_t out_commit[NODUS_V2_GEN_SRCCOMMIT_LEN]) {
    DIR *dir = opendir(data_path);
    if (!dir) return -1;
    struct dirent *e;
    int n_pure = 0, saw_foreign = 0, saw_fault = 0;
    uint8_t found_commit[NODUS_V2_GEN_SRCCOMMIT_LEN];
    memset(found_commit, 0, sizeof(found_commit));
    while ((e = readdir(dir)) != NULL) {
        if (strncmp(e->d_name, "witness_", 8) != 0) continue;
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".db") != 0) continue;
        char path[600];
        int n = snprintf(path, sizeof(path), "%s/%s", data_path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) { saw_fault = 1; continue; }
        uint8_t commit[NODUS_V2_GEN_SRCCOMMIT_LEN];
        memset(commit, 0, sizeof(commit));
        switch (gen_probe_pure(path, commit)) {
            case 1:
                n_pure++;
                /* Keep the FIRST one only so the buffer is written once;
                 * n_pure > 1 turns the whole call into a fault below, so
                 * which one it was never reaches a caller. */
                if (n_pure == 1)
                    memcpy(found_commit, commit, sizeof(found_commit));
                break;
            case 0:  saw_foreign = 1; break;
            default: saw_fault   = 1; break;
        }
    }
    closedir(dir);
    if (saw_fault)   return -1;
    if (saw_foreign) return 2;
    if (n_pure > 1) {
        QGP_LOG_ERROR(LOG_TAG, "%d pure-V2 chain databases are present in "
                      "the data path — which chain is here has no answer, "
                      "so this cannot be an idempotent re-derive. Remove "
                      "all but the intended one.", n_pure);
        return -1;
    }
    if (n_pure == 1) {
        if (out_commit)
            memcpy(out_commit, found_commit, NODUS_V2_GEN_SRCCOMMIT_LEN);
        return 1;
    }
    return 0;
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

/* tokenomics-v3 P2 (P2-1): the genesis reward reserve a config commits.
 * Every config gen_plan_build admits is a version-3 config (below), so
 * this is the field as written; it stays a function so the three sites
 * that read the reserve name it the same way. */
static uint64_t gen_reward_pool(const nodus_v2_gen_config_t *cfg) {
    return cfg->reward_pool_initial;
}

static int gen_plan_build(const nodus_v2_gen_config_t *cfg, gen_plan_t *p) {
    if (!cfg || !p) return -1;
    memset(p, 0, sizeof(*p));

    /* tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b, "the version-2
     * genesis path" is DELETED): the version-3 document is the only
     * config this build derives. A version-2 config used to be accepted
     * here and derived by nodus_witness_v2_gen_derive, which no longer
     * exists. */
    if (cfg->config_version != NODUS_V2_GEN_CONFIG_VERSION_V3) {
        QGP_LOG_ERROR(LOG_TAG, "config_version %u is not 3 — the version-3 "
                      "(cometbft) genesis document is the only config this "
                      "build derives; refusing",
                      (unsigned)cfg->config_version);
        return -1;
    }

    /* ── build identity: ALL THREE SCHEDULE CONSTANTS ─────────────────
     * DNAC_EPOCH_LENGTH, DNAC_BLOCKS_PER_YEAR and DNAC_DECIMAL_UNIT are
     * -D-overridable and every one of them reaches the state root —
     * epoch_length through the epoch-keyed vset snapshots
     * (nodus_witness_vset.c:720-721), the other two through the amount
     * emission mints at every height. The config commits the values it
     * was written for; a build that disagrees refuses to DERIVE.
     *
     * Block 2C — this is one of TWO guards, and they cover different
     * cases. This one stops a mismatched build from producing a chain it
     * would then mis-run. It does NOT protect a node that JOINED a chain
     * it never derived; that case is caught at the first block by
     * nodus_witness_v2_econ_params_load reading the committed rows
     * gen_seed_state writes below. Neither guard subsumes the other, so
     * both exist. (A single mutant removing either one therefore leaves
     * the other standing — the tests use a COMPOUND mutant and say so.) */
    if (cfg->epoch_length != (uint64_t)DNAC_EPOCH_LENGTH) {
        QGP_LOG_ERROR(LOG_TAG, "config epoch_length %llu != the compiled "
                      "DNAC_EPOCH_LENGTH %llu — this build cannot derive "
                      "this config's chain (fail closed)",
                      (unsigned long long)cfg->epoch_length,
                      (unsigned long long)DNAC_EPOCH_LENGTH);
        return -1;
    }
    if (cfg->blocks_per_year != (uint64_t)DNAC_BLOCKS_PER_YEAR) {
        QGP_LOG_ERROR(LOG_TAG, "config blocks_per_year %llu != the compiled "
                      "DNAC_BLOCKS_PER_YEAR %llu — this build cannot derive "
                      "this config's chain (fail closed)",
                      (unsigned long long)cfg->blocks_per_year,
                      (unsigned long long)DNAC_BLOCKS_PER_YEAR);
        return -1;
    }
    if (cfg->decimal_unit != (uint64_t)DNAC_DECIMAL_UNIT) {
        QGP_LOG_ERROR(LOG_TAG, "config decimal_unit %llu != the compiled "
                      "DNAC_DECIMAL_UNIT %llu — this build cannot derive "
                      "this config's chain (fail closed)",
                      (unsigned long long)cfg->decimal_unit,
                      (unsigned long long)DNAC_DECIMAL_UNIT);
        return -1;
    }

    /* ── the inflation start is RETIRED: it MUST be 0 ─────────────────
     * tokenomics-v3 P2 (P2-4; decision file §1 "Yeni token
     * basılmayacak", §3 S-4 "blok başı basım kodu SİLİNİR,
     * INFLATION_START parametresi (id 3) emekli"). There is no per-block
     * mint left for a start height to switch on, so the field has ONE
     * legal value — the claim window's rule below. It stays in the
     * config and in the version-3 document's encoding (the document
     * layout is unchanged by P2) but is no longer committed as a
     * chain_config_history row, and a nonzero value is REFUSED: a
     * document that says "emission starts at block K" on a chain that
     * cannot mint would be a document that lies. */
    if (cfg->inflation_start_block != 0) {
        QGP_LOG_ERROR(LOG_TAG, "config inflation_start_block %llu — the "
                      "per-block mint is retired (tokenomics-v3 P2), the "
                      "only legal value is 0",
                      (unsigned long long)cfg->inflation_start_block);
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
     * rule is not enough. So this builder pins [0, UINT64_MAX] — the
     * same window the (now removed) activation seam pinned: the fields
     * are carried in the config (they are committed into source_commit —
     * no hidden defaults) but exactly one pair of values is accepted. */
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
     * path, which a version-3 chain never executes; the engine genesis
     * (nodus_witness_v2_genesis_cmt) has no equivalent. */
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

        /* ── D7 / G7 — THE PAYOUT FINGERPRINT MUST DERIVE FROM THE
         * PAYOUT KEY ─────────────────────────────────────────────────
         * The predicate above validates the fingerprint's SHAPE. It
         * cannot validate its MEANING, and the meaning is where the
         * money is: retirement releases the locked self-bond to the
         * FINGERPRINT alone (v2ep_release_utxo takes
         * v.unstake_destination_fp, nodus_witness_v2_epoch.c:397); the
         * stored payout KEY is never consulted when choosing the
         * destination. A transcription error in the ceremony config
         * therefore sends DNAC_SELF_STAKE_AMOUNT to an address nobody
         * holds a key for — permanently, per validator, with no
         * on-chain recovery and no later block at which anyone could
         * notice.
         *
         * ⚠ ORDER IS PART OF THE SPEC: this runs AFTER
         * nodus_witness_v2_epoch_val_rec_ok, never before.
         * test_v2_gen.c:628-659 mutates the fingerprint four times to
         * prove the four SHAPE refusals (all-zero, short, uppercase,
         * missing NUL). Every one of those mutants ALSO fails the
         * derivation check — so if this ran first it would swallow all
         * four: they would still assert `!= 0` and still report PASS,
         * while no longer proving the thing their names claim. Running
         * second leaves each existing assertion meaning exactly what it
         * says.
         *
         * The derivation reuses the shared helpers rather than a local
         * hex loop, for the same reason the L2-F4 check calls the
         * graduation's own exported predicate: the legacy staking path
         * builds this field with exactly these two calls
         * (nodus_witness_bft.c:2505-2511), and a second implementation
         * is a second thing that can drift. */
        {
            uint8_t fp_raw[QGP_FP_RAW_BYTES];
            char    fp_want[QGP_FP_HEX_BUFFER];
            if (qgp_sha3_512(v->unstake_destination_pubkey,
                             DNAC_PUBKEY_SIZE, fp_raw) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "validator[%u] payout fingerprint "
                              "could not be derived — refusing", (unsigned)i);
                return -1;
            }
            qgp_fp_raw_to_hex(fp_raw, fp_want);
            /* All DNAC_FINGERPRINT_SIZE bytes, including the terminator:
             * the predicate above already proved index 128 is 0 on the
             * config side, and qgp_fp_raw_to_hex writes it on this side,
             * so a full-width compare is exact rather than optimistic. */
            if (memcmp(v->unstake_destination_fp, fp_want,
                       DNAC_FINGERPRINT_SIZE) != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                    "validator[%u] unstake_destination_fp does NOT derive "
                    "from unstake_destination_pubkey — refusing. This "
                    "validator's %llu raw self-bond would be released to an "
                    "address no key opens. config=%.128s derived=%.128s",
                    (unsigned)i,
                    (unsigned long long)DNAC_SELF_STAKE_AMOUNT,
                    (const char *)v->unstake_destination_fp, fp_want);
                return -1;
            }
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
     * Insertion sort over an index array: N <= NODUS_V2_GEN_MAX_VALIDATORS
     * (32 since tokenomics-v3 P3-7), no library
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
         * config the derivation then refused downstream in
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
     * committed initial supply. Under- AND over-allocation both reject.
     *
     * tokenomics-v3 P2 (P2-1): the reward reserve is part of the fixed
     * total supply (decision §1: 200M of the 1B "Konsensüs / validator
     * ödülleri", no minting), so the rule becomes
     *   Σ allocations + Σ self-stake + reward_pool_initial
     *     == total_supply_raw. */
    const uint64_t pool_init = gen_reward_pool(cfg);
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
    {
        uint64_t locked = 0;
        if (add_u64(p->stake_total, pool_init, &locked) != 0 ||
            locked > cfg->total_supply_raw) {
            QGP_LOG_ERROR(LOG_TAG, "stake-lock %llu + reward pool %llu "
                          "exceeds total_supply_raw %llu (Rule P.2)",
                          (unsigned long long)p->stake_total,
                          (unsigned long long)pool_init,
                          (unsigned long long)cfg->total_supply_raw);
            gen_plan_free(p);
            return -1;
        }
        /* total_claimable is derived from the SUPPLY side, never from
         * the leaf sum — that is what makes the check_totals call below
         * a real cross-check rather than a restatement of its own input.
         * The reserve is not claimable: it is the pool the distribution
         * pays from (supply_tracking.reward_pool). */
        p->total_claimable = cfg->total_supply_raw - locked;
    }

    {
        uint64_t sum = 0;
        if (add_u64(p->alloc_total, p->stake_total, &sum) != 0 ||
            add_u64(sum, pool_init, &sum) != 0 ||
            sum != cfg->total_supply_raw) {
            QGP_LOG_ERROR(LOG_TAG, "Σ allocations %llu + Σ self-stake %llu "
                          "+ reward_pool_initial %llu != total_supply_raw "
                          "%llu (Rule P.2)",
                          (unsigned long long)p->alloc_total,
                          (unsigned long long)p->stake_total,
                          (unsigned long long)pool_init,
                          (unsigned long long)cfg->total_supply_raw);
            gen_plan_free(p);
            return -1;
        }
    }

    /* ── L2-F2: total_claimable vs the leaves ─────────────────────────
     * dna_dist_check_totals had exactly ONE production caller, and it was
     * the activation seam's claim-leaf step — the step this builder
     * replaces, and which no longer exists — so nothing on the new path
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

/* ── the canonical config body ───────────────────────────────────────── */

/* Layout: the header's table, verbatim. This is the BODY of the version-3
 * genesis document; gen_v3_encode_planned appends the version-3 tail to
 * exactly these bytes. */
#define GEN_VAL_ENC_LEN  (DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + \
                          DNAC_FINGERPRINT_SIZE + 8 + 2)
/* tag + config_version(4) + total_supply_raw(8) + epoch_length(8) +
 * blocks_per_year(8) + decimal_unit(8) + inflation_start_block(8) +
 * claim_start_height(8) + claim_end_height(8) + validator_count(2).
 * The three middle u64s are Block 2C's economic parameters. */
#define GEN_CFG_HEAD_LEN (NODUS_V2_GEN_CFG_TAG_LEN + 4 + 8 + 8 + 8 + 8 + \
                          8 + 8 + 8 + 2)

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
    /* ── the economic parameters (Block 2C) ───────────────────────────
     * Written UNCONDITIONALLY and fixed-width, like every other field:
     * no presence byte, no default. Their presence here is what makes
     * source_commit — and therefore the genesis BlockID and the chain id
     * — a function of the economics the chain was built for. */
    put_be64(p, cfg->epoch_length);           p += 8;
    put_be64(p, cfg->blocks_per_year);        p += 8;
    put_be64(p, cfg->decimal_unit);           p += 8;
    put_be64(p, cfg->inflation_start_block);  p += 8;
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

/* tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b): the version-2 public
 * entries that stood here — nodus_witness_v2_gen_config_encode,
 * nodus_witness_v2_gen_source_commit and their shared static
 * gen_source_commit_planned — are DELETED with the version-2 derivation
 * they served. gen_encode_planned above is NOT theirs alone: it writes
 * the body of the version-3 document (gen_v3_encode_planned). */

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
     * 0 because a chain born at height 0 has no attendance history. (The
     * removed activation seam had to RESET these on the rows it
     * transplanted, for the same reason; here there is nothing to reset,
     * they are simply written as 0.) */
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
        /* tokenomics-v3 P1: last_signed_block / signed_blocks_this_epoch
         * are REMOVED from this record — attendance lives out-of-root in
         * v2_attendance (already zeroed by the memset above). */
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
     * than an invented constant.
     *
     * tokenomics-v3 P2 (P2-1): the row is seeded with the reward reserve
     * (supply_tracking.reward_pool = reward_pool_initial) — carved OUT of
     * total_supply_raw, which stays the genesis supply; Rule P.2 above
     * proved the pool fits. */
    {
        int rc = nodus_witness_supply_init(w2, cfg->total_supply_raw,
                                           gen_reward_pool(cfg),
                                           source_commit);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "supply_init failed (rc=%d)", rc);
            return -1;
        }
    }

    /* ── THE ECONOMIC PARAMETERS, COMMITTED (Block 2C) ────────────────
     * The chain_config_history table used to be ASSERTED EMPTY here, on
     * the reasoning that "no governance change can precede genesis". The
     * assertion was right about GOVERNANCE and wrong about the table: it
     * is the only store in this tree that is committed into a state root
     * (chain_config_root is a SYSTEM leg, nodus_witness_roots_v2.c:266,
     * :285), replicated to joiners (nodus_witness_v2_bundle.c:47) AND
     * readable by the runtime. So the economic parameters live here.
     *
     * Consequence, and it was the mirror-image defect: because the table
     * had to be empty, the emission gate's
     * nodus_chain_config_get_u64(..., 1ULL) fell to its default forever
     * and EVERY chain this builder produced minted from height 1, with no
     * way to configure that at genesis — only to repeal it by a later
     * governance vote. The inflation start is now expressible AT GENESIS.
     *
     * GOVERNANCE STILL CANNOT REACH THE BAND. Ids 200-202 are outside
     * 1..CC_PARAM_MAX_ID and have no case in the allowlist switch
     * (nodus_witness_chain_config.c), so no CHAIN_CONFIG tx can ever
     * insert or replace one.
     *
     * tokenomics-v3 P2 (P2-4): the inflation start (id 3) is NO LONGER
     * seeded. It was the fourth row here while a per-block mint existed;
     * the mint is deleted and id 3 is RETIRED (the scalar rules refuse
     * it), so a genesis row for it would be a committed value nothing
     * reads. gen_plan_build refuses a nonzero config value.
     *
     * EVERY COLUMN IS EXPLICIT AND DETERMINISTIC. `tx_hash` is NOT NULL
     * and carries source_commit — the one 64-byte value that identifies
     * this genesis, the same choice supply_init makes above and for the
     * same reason. `created_at_unix` is pinned to 0: a time(NULL) here
     * would differ per node, and although it reaches no merkle leaf
     * (nodus_witness_chain_config.c:386-391) it IS carried in the genesis
     * bundle and IS seen by a whole-database digest, so it would break
     * the determinism twin. commit_block and proposal_nonce are 0 — no
     * block committed these and no proposal produced them. */
    {
        static const struct { unsigned param; const char *name; } econ[] = {
            { NODUS_CC_ECON_BLOCKS_PER_YEAR,  "blocks_per_year"       },
            { NODUS_CC_ECON_DECIMAL_UNIT,     "decimal_unit"          },
            { NODUS_CC_ECON_EPOCH_LENGTH,     "epoch_length"          },
        };
        const uint64_t val[] = {
            cfg->blocks_per_year,
            cfg->decimal_unit,
            cfg->epoch_length,
        };
        const size_t n_econ = sizeof(econ) / sizeof(econ[0]);

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w2->db,
                "INSERT INTO chain_config_history (param_id, new_value, "
                "effective_block, commit_block, tx_hash, proposal_nonce, "
                "created_at_unix) VALUES (?1, ?2, ?3, 0, ?4, 0, 0)",
                -1, &st, NULL) != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "econ parameter insert could not be prepared");
            return -1;
        }
        /* Insertion order is the array order — a fixed literal, not a
         * query result — and the row SET is what every reader sorts
         * (compute_root ORDER BY, the bundle's param_id ASC), so this
         * loop cannot make two nodes disagree. */
        for (size_t i = 0; i < n_econ; i++) {
            sqlite3_reset(st);
            sqlite3_clear_bindings(st);
            sqlite3_bind_int64(st, 1, (sqlite3_int64)econ[i].param);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)val[i]);
            sqlite3_bind_int64(st, 3,
                               (sqlite3_int64)NODUS_CC_ECON_EFFECTIVE_BLOCK);
            sqlite3_bind_blob(st, 4, source_commit,
                              NODUS_V2_GEN_SRCCOMMIT_LEN, SQLITE_TRANSIENT);
            if (sqlite3_step(st) != SQLITE_DONE) {
                QGP_LOG_ERROR(LOG_TAG, "econ parameter %s (id %u) could not "
                              "be committed: %s", econ[i].name,
                              econ[i].param, sqlite3_errmsg(w2->db));
                sqlite3_finalize(st);
                return -1;
            }
        }
        sqlite3_finalize(st);

        /* The warm chain-config cache is invalidated explicitly: this
         * INSERT bypasses the mutate path that would do it
         * (nodus_witness_rt_native.c), and a cache warmed before the
         * INSERT must not outlive it. */
        w2->chain_config_cache_warm = false;

        /* POST-CONDITION: exactly these rows, and NOTHING else. An
         * exact-count assertion in place of the old emptiness one — a
         * future create_chain_db that seeded a row of its own must still
         * fail loudly here rather than ride along into the state root. */
        {
            sqlite3_int64 n = -1;
            if (gen_count(w2->db, "SELECT COUNT(*) FROM chain_config_history",
                          &n) != 0) return -1;
            if (n != (sqlite3_int64)n_econ) {
                QGP_LOG_ERROR(LOG_TAG, "chain_config_history holds %lld rows "
                              "after seeding %zu economic parameters — "
                              "refusing", (long long)n, n_econ);
                return -1;
            }
        }
        /* And they must READ BACK as what the config said. The committed
         * row is the thing the runtime will obey, so the derivation is
         * not allowed to ship a chain whose committed economics differ
         * from the config that was hashed into its identity. */
        {
            nodus_v2_econ_params_t chk;
            if (nodus_witness_v2_econ_params_load(w2, &chk) != 0 ||
                !chk.present ||
                chk.blocks_per_year != cfg->blocks_per_year ||
                chk.decimal_unit    != cfg->decimal_unit ||
                chk.epoch_length    != cfg->epoch_length) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the committed economic band "
                              "does not read back as the config — ABORT");
                return -1;
            }
        }
    }

    /* delegations is EMPTY at a pure-V2 genesis, and that emptiness is
     * ASSERTED rather than produced by a DELETE — a future
     * create_chain_db that seeded a row must fail loudly here, not be
     * silently erased.
     *
     *   delegations           nothing has delegated yet.
     *
     * chain_config_history is NO LONGER on this list — Block 2C commits
     * the economic parameters into it above, with its own exact-row
     * post-condition.
     *
     * tokenomics-v3 P2: two tables join the list: `v2_reward_accrual`
     * (nothing has been earned before the first boundary) and
     * `v2_balance_copy` (the engine genesis writes copy(0) itself,
     * nodus_witness_v2_apply.c, AFTER this seeder — a row here would
     * collide with it).
     *
     * Root-layout round (K2, 2026-09-25): `epoch_state` is OFF this list
     * because the table no longer exists — the schema stopped creating
     * it (nodus_witness.c), so a COUNT over it would fail the prepare
     * and abort every derivation. */
    {
        static const char *const must_be_empty[] = {
            "delegations", "v2_reward_accrual", "v2_balance_copy"
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

/* ══════════════════════════════════════════════════════════════════════
 * VERSION 3 — THE COMETBFT GENESIS DOCUMENT (D-18 rev 4, W2 / R3-C1b)
 *
 * The byte table, the two hash preimages and the reason they zero
 * different fields: the header. What is worth stating HERE is the one
 * structural property a reviewer should not have to take on trust:
 *
 *   THE BODY IS PRODUCED BY THE ONE BODY ENCODER. This layer calls
 *   `gen_encode_planned` — over the same plan the rules were checked
 *   against — and APPENDS the version-3 tail to what it returns, so the
 *   body cannot drift from the fields gen_plan_build validated.
 *
 * ── WHAT A PRODUCTION BINARY REACHES ──────────────────────────────────
 * The ceremony (nodus-server.c run_derive_v2_genesis) parses the config
 * file (nodus_v2_gen_config.c, which calls `_v3_defaults` and
 * `_v3_fill_comet_rows`) and derives with
 * `nodus_witness_v2_gen_derive_v3`; a running node reads its identity
 * through `nodus_witness_v2_gen_stored_chain_id` (the post-open gate,
 * nodus_witness.c) and its document through `_stored_doc`
 * (nodus_witness_cmt_node.c). The version-2 derivation that used to sit
 * above this banner — nodus_witness_v2_gen_derive, closed by R3 W3
 * (D-17 rev 10 (9)) — is DELETED by tokenomics-v3 P4 (OBLIGATION
 * atlas-dec-71525f3b); its steps live on in `_derive_v3` below.
 * ════════════════════════════════════════════════════════════════════ */

/* Compile-time agreement with the port's own types. Deliberately at the
 * END of this file: the assertion block at the top is line-cited, and a
 * new line there would move every citation into this module. */
_Static_assert(DNAC_PUBKEY_SIZE == CMT_PB_PUBKEY_LEN,
               "the container carries the RAW ML-DSA-87 key the port's "
               "PublicKey message carries");
_Static_assert(NODUS_V2_GEN_CHAIN_ID_LEN == CMT_PB_ADDRESS_MAX,
               "a Comet row's address is the port's 32-byte address");
_Static_assert(NODUS_V2_GEN_CHAIN_ID_LEN == CMT_PB_CHAINID_MAX,
               "the derived chain id must fit the port's chain-id field");
_Static_assert(NODUS_V2_GEN_APP_HASH_LEN == CMT_PB_HASH_MAX,
               "app_hash is the ledger's 64-byte global root and must fit "
               "the port's hash field");
_Static_assert(NODUS_V2_GEN_CMT_NAME_MAX == CMT_GENESIS_NAME_MAX,
               "name storage must match the port's genesis validator");
_Static_assert(NODUS_V2_GEN_CMT_NAME_LEN_MAX < NODUS_V2_GEN_CMT_NAME_MAX,
               "the longest carried name must leave room for the NUL");
_Static_assert(NODUS_V2_GEN_SRCCOMMIT_LEN == 64,
               "the version-3 source_commit is a bare SHA3-512 digest too");

/* Tokenomics v2 (atlas-dec-93ff0761d40f5bc16fbae607ab54f458, APPROVED):
 * a 200 000 000 NODUS reserve of the fixed 1 000 000 000 supply, paying
 * pool >> 16 at every epoch boundary, settled every 24 epochs. These are
 * the values `_v3_defaults` writes; they are COMMITTED GENESIS DATA, not
 * compiled policy — the chain obeys the number in its own document.
 * tokenomics-v3 P2: the divisor has ONE legal value
 * (NODUS_V2_GEN_REWARD_DIVISOR_LOG2, nodus_witness_v2_gen.h — refused
 * otherwise by nodus_witness_v2_gen_v3_validate); the interval default
 * is the header's, so the reader of a document-less chain
 * (nodus_witness_v2_payout_interval) and this default cannot drift. */
#define GEN_V3_REWARD_POOL_INITIAL     (200000000ULL * 100000000ULL)
#define GEN_V3_REWARD_DIVISOR_LOG2     \
        ((uint64_t)NODUS_V2_GEN_REWARD_DIVISOR_LOG2)
#define GEN_V3_PAYOUT_INTERVAL_EPOCHS  \
        ((uint64_t)NODUS_V2_GEN_PAYOUT_INTERVAL_EPOCHS_DEFAULT)

/* ── big-endian readers (the decoder's half of put_be*) ──────────────── */

static uint16_t get_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static uint32_t get_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* A bounded cursor. Every read goes through v3_take, so a truncated
 * document can never be read as a short one: the first read past the end
 * latches `err` and every later read returns NULL. */
typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         off;
    int            err;
} v3rd_t;

static const uint8_t *v3_take(v3rd_t *r, size_t n) {
    if (r->err) return NULL;
    if (n > r->len - r->off) { r->err = 1; return NULL; }
    const uint8_t *q = r->p + r->off;
    r->off += n;
    return q;
}
static uint16_t v3_u16(v3rd_t *r) {
    const uint8_t *q = v3_take(r, 2);
    return q ? get_be16(q) : 0;
}
static uint32_t v3_u32(v3rd_t *r) {
    const uint8_t *q = v3_take(r, 4);
    return q ? get_be32(q) : 0;
}
static uint64_t v3_u64(v3rd_t *r) {
    const uint8_t *q = v3_take(r, 8);
    return q ? get_be64(q) : 0;
}

/* ── the appended tail ───────────────────────────────────────────────── */

/* WRITABILITY, not validity. A field whose VALUE is wrong (a consensus
 * protocol this build does not implement, a zero genesis time, a Comet
 * row that disagrees with its stake entry) still has an encoding, and a
 * test that proves such a field reaches the chain id must be able to
 * produce it. Those are `nodus_witness_v2_gen_v3_validate`'s, and the
 * derivation runs that. What this refuses is a config whose bytes cannot
 * be written at all, or could be written two ways. */
static int gen_v3_shape_ok(const nodus_v2_gen_config_t *cfg) {
    if (!cfg) return -1;
    if (cfg->config_version != NODUS_V2_GEN_CONFIG_VERSION_V3) {
        QGP_LOG_ERROR(LOG_TAG, "config_version %u is not the version-3 "
                      "document's", (unsigned)cfg->config_version);
        return -1;
    }
    if (cfg->n_comet_validators > NODUS_V2_GEN_MAX_VALIDATORS) {
        QGP_LOG_ERROR(LOG_TAG, "%u comet validator rows exceeds the array "
                      "bound %u", (unsigned)cfg->n_comet_validators,
                      (unsigned)NODUS_V2_GEN_MAX_VALIDATORS);
        return -1;
    }
    for (uint16_t i = 0; i < cfg->n_comet_validators; i++) {
        const nodus_v2_gen_cmt_validator_t *r = &cfg->comet_validators[i];
        if (r->name_len > NODUS_V2_GEN_CMT_NAME_LEN_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "comet row %u name_len %u > %u",
                          (unsigned)i, (unsigned)r->name_len,
                          (unsigned)NODUS_V2_GEN_CMT_NAME_LEN_MAX);
            return -1;
        }
    }
    const cmt_validator_params_t *vp = &cfg->consensus_params.validator;
    if (vp->pub_key_types_len > CMT_PARAMS_MAX_PUBKEY_TYPES) {
        QGP_LOG_ERROR(LOG_TAG, "%zu public key types exceeds the bound %u",
                      vp->pub_key_types_len,
                      (unsigned)CMT_PARAMS_MAX_PUBKEY_TYPES);
        return -1;
    }
    for (size_t i = 0; i < vp->pub_key_types_len; i++) {
        size_t l = strnlen(vp->pub_key_types[i],
                           CMT_PARAMS_PUBKEY_TYPE_MAX);
        if (l >= CMT_PARAMS_PUBKEY_TYPE_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "public key type %zu is not "
                          "NUL-terminated within its storage", i);
            return -1;
        }
    }
    return 0;
}

/* The exact length of the appended tail, computed from the same fields
 * the writer walks — one formula, used by both, so the buffer cannot be
 * one byte short of what is written. */
static int gen_v3_tail_len(const nodus_v2_gen_config_t *cfg, size_t *out) {
    if (!cfg || !out) return -1;
    size_t n = 4 + 8 + 8;                    /* protocol, time, height   */
    n += 8 + 8;                              /* block params             */
    n += 8 + 8 + 8;                          /* evidence params          */
    n += 2;                                  /* key type count           */
    const cmt_validator_params_t *vp = &cfg->consensus_params.validator;
    for (size_t i = 0; i < vp->pub_key_types_len; i++)
        n += 2 + strnlen(vp->pub_key_types[i],
                         CMT_PARAMS_PUBKEY_TYPE_MAX - 1);
    n += 8;                                  /* version.app              */
    n += 8;                                  /* abci enable height       */
    n += 2;                                  /* comet validator count    */
    for (uint16_t i = 0; i < cfg->n_comet_validators; i++)
        n += NODUS_V2_GEN_CHAIN_ID_LEN + DNAC_PUBKEY_SIZE + 8 + 1 +
             (size_t)cfg->comet_validators[i].name_len;
    n += NODUS_V2_GEN_APP_HASH_LEN;
    n += NODUS_V2_GEN_CHAIN_ID_LEN;
    n += 8 + 8 + 8;                          /* the tokenomics fields    */
    *out = n;
    return 0;
}

/*
 * The whole version-3 encoding over an already-built plan.
 *
 * `zero_chain_id` / `zero_app_hash` write 32 / 64 ZERO bytes in place of
 * the field instead of its value — that IS the hash preimage rule, and
 * expressing it as a flag on the one encoder is what makes "the chain id
 * is the hash of the document with its own id blanked" impossible to get
 * wrong in one place and right in another. The buffer is calloc'd, so a
 * zeroed field is simply not written.
 */
static int gen_v3_encode_planned(const nodus_v2_gen_config_t *cfg,
                                 const gen_plan_t *plan,
                                 int zero_chain_id, int zero_app_hash,
                                 uint8_t **out, size_t *out_len) {
    if (!cfg || !plan || !out || !out_len) return -1;
    if (gen_v3_shape_ok(cfg) != 0) return -1;

    /* THE BODY is gen_encode_planned's output. It writes
     * cfg->config_version, which reads 3 here — D-18 rev 4's version-2
     * body differed only in that field (the version-2 encoder itself is
     * deleted, P4). */
    uint8_t *body = NULL;
    size_t   body_len = 0;
    if (gen_encode_planned(cfg, plan, &body, &body_len) != 0) return -1;

    size_t tail_len = 0;
    if (gen_v3_tail_len(cfg, &tail_len) != 0) { free(body); return -1; }

    uint8_t *buf = calloc(1, body_len + tail_len);
    if (!buf) { free(body); return -1; }
    memcpy(buf, body, body_len);
    free(body);

    uint8_t *p = buf + body_len;

    put_be32(p, cfg->consensus_protocol);                        p += 4;
    put_be64(p, cfg->genesis_time_ms);                           p += 8;
    put_be64(p, cfg->initial_height);                            p += 8;

    /* Four of the five parameters below ARE `int64` on the reference's
     * wire (proto/tendermint/types/params.proto:25, :28, :39, :52). The
     * fifth is NOT, and the distinction is worth the line: MaxAgeDuration
     * is a `google.protobuf.Duration` carrying
     * `(gogoproto.stdduration) = true` (params.proto:46-47), so the WIRE
     * form is a {seconds, nanos} message while the GO value gogoproto
     * generates is a `time.Duration`, i.e. an int64 count of
     * NANOSECONDS. What this container writes is that Go value — the
     * same int64 `cmt_evidence_params_t.max_age_duration_ns` holds
     * (shared/dnac/cmt_params.h:116-126) — never the proto encoding.
     * All five are written as 8-byte two's complement, so MaxGas -1 and
     * the 48-hour duration round-trip exactly. */
    const cmt_consensus_params_t *cp = &cfg->consensus_params;
    put_be64(p, (uint64_t)cp->block.max_bytes);                  p += 8;
    put_be64(p, (uint64_t)cp->block.max_gas);                    p += 8;
    put_be64(p, (uint64_t)cp->evidence.max_age_num_blocks);      p += 8;
    put_be64(p, (uint64_t)cp->evidence.max_age_duration_ns);     p += 8;
    put_be64(p, (uint64_t)cp->evidence.max_bytes);               p += 8;

    put_be16(p, (uint16_t)cp->validator.pub_key_types_len);      p += 2;
    for (size_t i = 0; i < cp->validator.pub_key_types_len; i++) {
        size_t l = strnlen(cp->validator.pub_key_types[i],
                           CMT_PARAMS_PUBKEY_TYPE_MAX - 1);
        put_be16(p, (uint16_t)l);                                p += 2;
        memcpy(p, cp->validator.pub_key_types[i], l);            p += l;
    }

    put_be64(p, cp->version.app);                                p += 8;
    put_be64(p, (uint64_t)cp->abci.vote_extensions_enable_height); p += 8;

    put_be16(p, cfg->n_comet_validators);                        p += 2;
    for (uint16_t i = 0; i < cfg->n_comet_validators; i++) {
        const nodus_v2_gen_cmt_validator_t *r = &cfg->comet_validators[i];
        memcpy(p, r->address, NODUS_V2_GEN_CHAIN_ID_LEN);
        p += NODUS_V2_GEN_CHAIN_ID_LEN;
        memcpy(p, r->pub_key, DNAC_PUBKEY_SIZE);
        p += DNAC_PUBKEY_SIZE;
        put_be64(p, (uint64_t)r->power);                         p += 8;
        *p++ = r->name_len;
        memcpy(p, r->name, r->name_len);
        p += r->name_len;
    }

    if (!zero_app_hash)
        memcpy(p, cfg->app_hash, NODUS_V2_GEN_APP_HASH_LEN);
    p += NODUS_V2_GEN_APP_HASH_LEN;
    if (!zero_chain_id)
        memcpy(p, cfg->chain_id, NODUS_V2_GEN_CHAIN_ID_LEN);
    p += NODUS_V2_GEN_CHAIN_ID_LEN;

    put_be64(p, cfg->reward_pool_initial);                       p += 8;
    put_be64(p, cfg->reward_divisor_log2);                       p += 8;
    put_be64(p, cfg->payout_interval_epochs);                    p += 8;

    if ((size_t)(p - buf) != body_len + tail_len) {  /* the invariant */
        free(buf);
        return -1;
    }
    *out = buf;
    *out_len = body_len + tail_len;
    return 0;
}

/* One entry for all three preimages: the document, the chain-id preimage
 * and the source-commit preimage differ ONLY by the two flags. */
static int gen_v3_encode_flags(const nodus_v2_gen_config_t *cfg,
                               int zero_chain_id, int zero_app_hash,
                               uint8_t **out, size_t *out_len) {
    if (!out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    if (!cfg || cfg->config_version != NODUS_V2_GEN_CONFIG_VERSION_V3)
        return -1;
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;
    int rc = gen_v3_encode_planned(cfg, &plan, zero_chain_id, zero_app_hash,
                                   out, out_len);
    gen_plan_free(&plan);
    return rc;
}

int nodus_witness_v2_gen_v3_encode(const nodus_v2_gen_config_t *cfg,
                                   uint8_t **out, size_t *out_len) {
    return gen_v3_encode_flags(cfg, 0, 0, out, out_len);
}

int nodus_witness_v2_gen_chain_id(const nodus_v2_gen_config_t *cfg,
                                  uint8_t out32[NODUS_V2_GEN_CHAIN_ID_LEN]) {
    if (!out32) return -1;
    uint8_t *buf = NULL;
    size_t   len = 0;
    if (gen_v3_encode_flags(cfg, /*zero_chain_id=*/1, /*zero_app_hash=*/0,
                            &buf, &len) != 0)
        return -1;
    uint8_t full[64];
    int rc = qgp_sha3_512(buf, len, full);
    free(buf);
    if (rc != 0) return -1;
    memcpy(out32, full, NODUS_V2_GEN_CHAIN_ID_LEN);
    return 0;
}

int nodus_witness_v2_gen_v3_source_commit(
        const nodus_v2_gen_config_t *cfg,
        uint8_t out[NODUS_V2_GEN_SRCCOMMIT_LEN]) {
    if (!out) return -1;
    uint8_t *buf = NULL;
    size_t   len = 0;
    if (gen_v3_encode_flags(cfg, /*zero_chain_id=*/1, /*zero_app_hash=*/1,
                            &buf, &len) != 0)
        return -1;
    int rc = qgp_sha3_512(buf, len, out);
    free(buf);
    return rc == 0 ? 0 : -1;
}

/* ── the strict decoder ──────────────────────────────────────────────── */

/*
 * STRICTER THAN THE ENCODER, deliberately. The encoder writes what is
 * writable; this reads what is a DOCUMENT. Everything the encoder can
 * emit but a genesis document may not contain — a consensus protocol
 * that is not cometbft, a zero genesis time, an empty key-type list — is
 * refused HERE, so a document that decodes is one whose fields a caller
 * may act on. The asymmetry is the point and is stated in the header.
 */
int nodus_witness_v2_gen_v3_decode(const uint8_t *buf, size_t len,
                                   nodus_v2_gen_config_t *cfg_out,
                                   nodus_v2_gen_alloc_t **allocs_out) {
    if (!buf || !cfg_out || !allocs_out) return -1;
    *allocs_out = NULL;
    memset(cfg_out, 0, sizeof(*cfg_out));

    v3rd_t r = { buf, len, 0, 0 };

    /* the 16-byte zero-padded domain tag */
    {
        const uint8_t *t = v3_take(&r, NODUS_V2_GEN_CFG_TAG_LEN);
        uint8_t want[NODUS_V2_GEN_CFG_TAG_LEN];
        memset(want, 0, sizeof(want));
        memcpy(want, NODUS_V2_GEN_CFG_TAG, sizeof(NODUS_V2_GEN_CFG_TAG) - 1);
        if (!t || memcmp(t, want, NODUS_V2_GEN_CFG_TAG_LEN) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "genesis document: wrong domain tag");
            return -1;
        }
    }

    cfg_out->config_version = v3_u32(&r);
    if (r.err) return -1;
    if (cfg_out->config_version != NODUS_V2_GEN_CONFIG_VERSION_V3) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: config_version %u is not "
                      "3 — a version-2 encoding is not a prefix of this "
                      "document", (unsigned)cfg_out->config_version);
        return -1;
    }

    cfg_out->total_supply_raw      = v3_u64(&r);
    cfg_out->epoch_length          = v3_u64(&r);
    cfg_out->blocks_per_year       = v3_u64(&r);
    cfg_out->decimal_unit          = v3_u64(&r);
    cfg_out->inflation_start_block = v3_u64(&r);
    cfg_out->claim_start_height    = v3_u64(&r);
    cfg_out->claim_end_height      = v3_u64(&r);
    cfg_out->n_validators          = v3_u16(&r);
    if (r.err) return -1;
    if (cfg_out->n_validators == 0 ||
        cfg_out->n_validators > NODUS_V2_GEN_MAX_VALIDATORS) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: validator count %u out of "
                      "[1, %u]", (unsigned)cfg_out->n_validators,
                      (unsigned)NODUS_V2_GEN_MAX_VALIDATORS);
        return -1;
    }
    for (uint16_t i = 0; i < cfg_out->n_validators; i++) {
        nodus_v2_gen_validator_t *v = &cfg_out->validators[i];
        const uint8_t *pk  = v3_take(&r, DNAC_PUBKEY_SIZE);
        const uint8_t *upk = v3_take(&r, DNAC_PUBKEY_SIZE);
        const uint8_t *fp  = v3_take(&r, DNAC_FINGERPRINT_SIZE);
        uint64_t stake = v3_u64(&r);
        uint16_t comm  = v3_u16(&r);
        if (r.err) return -1;
        memcpy(v->pubkey, pk, DNAC_PUBKEY_SIZE);
        memcpy(v->unstake_destination_pubkey, upk, DNAC_PUBKEY_SIZE);
        memcpy(v->unstake_destination_fp, fp, DNAC_FINGERPRINT_SIZE);
        v->self_stake     = stake;
        v->commission_bps = comm;
    }

    cfg_out->n_allocs = v3_u32(&r);
    if (r.err) return -1;
    if (cfg_out->n_allocs < 1 || cfg_out->n_allocs > NODUS_V2_GEN_MAX_ALLOCS) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: allocation count %u out of "
                      "[1, %u]", (unsigned)cfg_out->n_allocs,
                      (unsigned)NODUS_V2_GEN_MAX_ALLOCS);
        return -1;
    }
    nodus_v2_gen_alloc_t *allocs =
        calloc((size_t)cfg_out->n_allocs, sizeof(*allocs));
    if (!allocs) return -1;
    for (uint32_t i = 0; i < cfg_out->n_allocs; i++) {
        uint16_t sid_len = v3_u16(&r);
        if (!r.err && sid_len != (uint16_t)NODUS_V2_GEN_SRCID_LEN) {
            QGP_LOG_ERROR(LOG_TAG, "genesis document: allocation %u carries "
                          "source_id_len %u, not %u", (unsigned)i,
                          (unsigned)sid_len,
                          (unsigned)NODUS_V2_GEN_SRCID_LEN);
            free(allocs);
            return -1;
        }
        const uint8_t *sid = v3_take(&r, NODUS_V2_GEN_SRCID_LEN);
        uint64_t amount = v3_u64(&r);
        const uint8_t *db = v3_take(&r, 64);
        if (r.err) { free(allocs); return -1; }
        memcpy(allocs[i].source_id, sid, NODUS_V2_GEN_SRCID_LEN);
        allocs[i].amount = amount;
        memcpy(allocs[i].dest_binding, db, 64);
    }

    /* ── the appended version-3 tail ─────────────────────────────────── */
    cfg_out->consensus_protocol = v3_u32(&r);
    cfg_out->genesis_time_ms    = v3_u64(&r);
    cfg_out->initial_height     = v3_u64(&r);
    if (r.err) { free(allocs); return -1; }
    if (cfg_out->consensus_protocol != NODUS_V2_GEN_CONSENSUS_COMETBFT) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: consensus_protocol %u is "
                      "not cometbft (%u) — a genesis that does not name its "
                      "consensus has no validity rules",
                      (unsigned)cfg_out->consensus_protocol,
                      (unsigned)NODUS_V2_GEN_CONSENSUS_COMETBFT);
        free(allocs);
        return -1;
    }
    if (cfg_out->genesis_time_ms == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "genesis document: genesis_time is 0 — "
                      "the reference would fill it from a clock "
                      "(types/genesis.go:101-103), which a derivation may "
                      "not do");
        free(allocs);
        return -1;
    }
    if (cfg_out->initial_height > (uint64_t)INT64_MAX) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "genesis document: initial_height does "
                      "not fit the document's int64 field");
        free(allocs);
        return -1;
    }

    cmt_consensus_params_t *cp = &cfg_out->consensus_params;
    cp->block.max_bytes              = (int64_t)v3_u64(&r);
    cp->block.max_gas                = (int64_t)v3_u64(&r);
    cp->evidence.max_age_num_blocks  = (int64_t)v3_u64(&r);
    cp->evidence.max_age_duration_ns = (int64_t)v3_u64(&r);
    cp->evidence.max_bytes           = (int64_t)v3_u64(&r);
    uint16_t n_types = v3_u16(&r);
    if (r.err) { free(allocs); return -1; }
    if (n_types < 1 || n_types > CMT_PARAMS_MAX_PUBKEY_TYPES) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: %u public key types out of "
                      "[1, %u]", (unsigned)n_types,
                      (unsigned)CMT_PARAMS_MAX_PUBKEY_TYPES);
        free(allocs);
        return -1;
    }
    cp->validator.pub_key_types_len = n_types;
    for (uint16_t i = 0; i < n_types; i++) {
        uint16_t l = v3_u16(&r);
        if (r.err) { free(allocs); return -1; }
        if (l < 1 || l > CMT_PARAMS_PUBKEY_TYPE_MAX - 1) {
            QGP_LOG_ERROR(LOG_TAG, "genesis document: key type %u length %u "
                          "out of [1, %u]", (unsigned)i, (unsigned)l,
                          (unsigned)(CMT_PARAMS_PUBKEY_TYPE_MAX - 1));
            free(allocs);
            return -1;
        }
        const uint8_t *s = v3_take(&r, l);
        if (r.err) { free(allocs); return -1; }
        for (uint16_t k = 0; k < l; k++) {
            /* PRINTABLE ASCII. The layout says ASCII; a control byte in a
             * type name would travel into a log line and into a
             * membership comparison, and the reference's own names are
             * lowercase words (types/params.go:24-25). */
            if (s[k] < 0x20 || s[k] > 0x7E) {
                QGP_LOG_ERROR(LOG_TAG, "genesis document: key type %u "
                              "contains a non-printable byte", (unsigned)i);
                free(allocs);
                return -1;
            }
        }
        memcpy(cp->validator.pub_key_types[i], s, l);
        cp->validator.pub_key_types[i][l] = '\0';
    }
    cp->version.app                      = v3_u64(&r);
    cp->abci.vote_extensions_enable_height = (int64_t)v3_u64(&r);

    uint16_t n_rows = v3_u16(&r);
    if (r.err) { free(allocs); return -1; }
    if (n_rows != cfg_out->n_validators) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: %u comet validator rows "
                      "for %u validators — the committee IS the validator "
                      "set", (unsigned)n_rows,
                      (unsigned)cfg_out->n_validators);
        free(allocs);
        return -1;
    }
    cfg_out->n_comet_validators = n_rows;
    for (uint16_t i = 0; i < n_rows; i++) {
        nodus_v2_gen_cmt_validator_t *row = &cfg_out->comet_validators[i];
        const uint8_t *addr = v3_take(&r, NODUS_V2_GEN_CHAIN_ID_LEN);
        const uint8_t *pk   = v3_take(&r, DNAC_PUBKEY_SIZE);
        uint64_t power = v3_u64(&r);
        const uint8_t *nl = v3_take(&r, 1);
        if (r.err) { free(allocs); return -1; }
        if (*nl > NODUS_V2_GEN_CMT_NAME_LEN_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "genesis document: comet row %u name_len "
                          "%u > %u", (unsigned)i, (unsigned)*nl,
                          (unsigned)NODUS_V2_GEN_CMT_NAME_LEN_MAX);
            free(allocs);
            return -1;
        }
        const uint8_t *nm = v3_take(&r, *nl);
        if (r.err) { free(allocs); return -1; }
        memcpy(row->address, addr, NODUS_V2_GEN_CHAIN_ID_LEN);
        memcpy(row->pub_key, pk, DNAC_PUBKEY_SIZE);
        row->power    = (int64_t)power;   /* two's complement, as written */
        row->name_len = *nl;
        memcpy(row->name, nm, *nl);
        row->name[*nl] = '\0';
    }

    {
        const uint8_t *ah = v3_take(&r, NODUS_V2_GEN_APP_HASH_LEN);
        const uint8_t *ci = v3_take(&r, NODUS_V2_GEN_CHAIN_ID_LEN);
        if (r.err) { free(allocs); return -1; }
        memcpy(cfg_out->app_hash, ah, NODUS_V2_GEN_APP_HASH_LEN);
        memcpy(cfg_out->chain_id, ci, NODUS_V2_GEN_CHAIN_ID_LEN);
    }
    cfg_out->reward_pool_initial    = v3_u64(&r);
    cfg_out->reward_divisor_log2    = v3_u64(&r);
    cfg_out->payout_interval_epochs = v3_u64(&r);
    if (r.err) { free(allocs); return -1; }

    /* NO TRAILING BYTE. Two encodings of one document would be two chain
     * ids for one chain; a decoder that ignored a suffix would accept the
     * second of them. */
    if (r.off != r.len) {
        QGP_LOG_ERROR(LOG_TAG, "genesis document: %zu trailing byte(s)",
                      r.len - r.off);
        free(allocs);
        return -1;
    }

    cfg_out->allocs = allocs;
    *allocs_out = allocs;
    return 0;
}

/* ── the version-3 rules ─────────────────────────────────────────────── */

int nodus_witness_v2_gen_v3_defaults(nodus_v2_gen_config_t *cfg) {
    if (!cfg) return -1;
    cfg->config_version     = NODUS_V2_GEN_CONFIG_VERSION_V3;
    cfg->consensus_protocol = NODUS_V2_GEN_CONSENSUS_COMETBFT;
    /* The PORT's own constructor, not a copy of its values: the test that
     * compares the encoded parameters with cmt_default_consensus_params
     * then proves the ENCODING, not a transcription that could agree with
     * itself while both are wrong (params.go:86-94). */
    cmt_default_consensus_params(&cfg->consensus_params);
    cfg->reward_pool_initial    = GEN_V3_REWARD_POOL_INITIAL;
    cfg->reward_divisor_log2    = GEN_V3_REWARD_DIVISOR_LOG2;
    cfg->payout_interval_epochs = GEN_V3_PAYOUT_INTERVAL_EPOCHS;
    return 0;
}

/* address = SHA3-512(pubkey)[0..31], power = stake / decimal_unit.
 * ONE computation, used by the filler and by the equality rule, so the
 * rows a config carries and the rows it is checked against can never be
 * produced by two different formulas. */
static int gen_v3_row_derive(const nodus_v2_gen_config_t *cfg,
                             const nodus_v2_gen_validator_t *v,
                             uint8_t out_addr[NODUS_V2_GEN_CHAIN_ID_LEN],
                             int64_t *out_power) {
    if (!cfg || !v || !out_addr || !out_power) return -1;
    if (cfg->decimal_unit == 0) return -1;
    /* cmt_address_hash IS nodus_chain_config_derive_witness_id's
     * computation — SHA3-512 truncated to 32 bytes (cmt_tmhash.h:240-259
     * states the equality and why shared/ reproduces it rather than
     * calling into nodus/). */
    if (cmt_address_hash(v->pubkey, (size_t)DNAC_PUBKEY_SIZE,
                         out_addr) != CMT_OK)
        return -1;
    /* delegated is 0 at genesis — see the header for why that is a read
     * fact and not an assumption. */
    uint64_t whole = v->self_stake / cfg->decimal_unit;
    if (whole > (uint64_t)INT64_MAX) return -1;
    *out_power = (int64_t)whole;
    return 0;
}

int nodus_witness_v2_gen_v3_fill_comet_rows(nodus_v2_gen_config_t *cfg) {
    if (!cfg) return -1;
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;

    nodus_v2_gen_cmt_validator_t *rows =
        calloc(NODUS_V2_GEN_MAX_VALIDATORS, sizeof(*rows));
    if (!rows) { gen_plan_free(&plan); return -1; }

    int rc = 0;
    for (uint16_t i = 0; i < cfg->n_validators; i++) {
        const nodus_v2_gen_validator_t *v =
            &cfg->validators[plan.val_idx[i]];
        nodus_v2_gen_cmt_validator_t *row = &rows[i];
        memcpy(row->pub_key, v->pubkey, DNAC_PUBKEY_SIZE);
        if (gen_v3_row_derive(cfg, v, row->address, &row->power) != 0) {
            rc = -1;
            break;
        }
        /* Keep a name the caller already attached to THIS key. The scan
         * is over the existing rows in array order and takes the first
         * match, so it cannot depend on anything but the config. */
        for (uint16_t k = 0; k < cfg->n_comet_validators &&
                             k < NODUS_V2_GEN_MAX_VALIDATORS; k++) {
            if (memcmp(cfg->comet_validators[k].pub_key, v->pubkey,
                       DNAC_PUBKEY_SIZE) != 0)
                continue;
            if (cfg->comet_validators[k].name_len >
                NODUS_V2_GEN_CMT_NAME_LEN_MAX) {
                rc = -1;
                break;
            }
            row->name_len = cfg->comet_validators[k].name_len;
            memcpy(row->name, cfg->comet_validators[k].name, row->name_len);
            row->name[row->name_len] = '\0';
            break;
        }
        if (rc != 0) break;
    }
    if (rc == 0) {
        memcpy(cfg->comet_validators, rows,
               NODUS_V2_GEN_MAX_VALIDATORS * sizeof(*rows));
        cfg->n_comet_validators = cfg->n_validators;
    }
    free(rows);
    gen_plan_free(&plan);
    return rc;
}

int nodus_witness_v2_gen_v3_validate(const nodus_v2_gen_config_t *cfg) {
    if (!cfg) return -1;
    if (cfg->config_version != NODUS_V2_GEN_CONFIG_VERSION_V3) {
        QGP_LOG_ERROR(LOG_TAG, "config_version %u is not 3 — this is not a "
                      "version-3 config", (unsigned)cfg->config_version);
        return -1;
    }
    /* THE SHARED RULES FIRST, through their one authority. */
    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;

    int rc = -1;
    do {
        if (gen_v3_shape_ok(cfg) != 0) break;

        if (cfg->consensus_protocol != NODUS_V2_GEN_CONSENSUS_COMETBFT) {
            QGP_LOG_ERROR(LOG_TAG, "consensus_protocol %u is not cometbft "
                          "(%u)", (unsigned)cfg->consensus_protocol,
                          (unsigned)NODUS_V2_GEN_CONSENSUS_COMETBFT);
            break;
        }
        if (cfg->genesis_time_ms == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "genesis_time is 0 — the producer "
                          "supplies it; a derivation never reads a clock "
                          "(D-18 rev 4)");
            break;
        }
        if (cfg->initial_height > (uint64_t)INT64_MAX) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "initial_height does not fit the "
                          "document's int64 field");
            break;
        }
        /* tokenomics-v3 P2 — the two reward parameters the chain now
         * OBEYS (nodus_witness_v2_econ.c). Before P2 nothing read them
         * and nothing bounded them.
         *   reward_divisor_log2: the decision fixes the per-epoch payout
         *     at floor(pool / 65 536) (decision file §1 "Her epoch ödülü:
         *     floor(mevcut ödül havuzu / 65.536)"), so the field has ONE
         *     legal value — the claim window's rule. A document naming
         *     another divisor would describe a payout the chain does not
         *     make.
         *   payout_interval_epochs: the payday rule divides by it
         *     ((H / E) % interval); 0 has no meaning. Any positive value
         *     is a genuine config choice (the decision's 24 is the
         *     default; the harness uses a small one to reach a payday). */
        if (cfg->reward_divisor_log2 !=
            (uint64_t)NODUS_V2_GEN_REWARD_DIVISOR_LOG2) {
            QGP_LOG_ERROR(LOG_TAG, "reward_divisor_log2 %llu — the only "
                          "legal value is %u (payout = pool / 65 536)",
                          (unsigned long long)cfg->reward_divisor_log2,
                          (unsigned)NODUS_V2_GEN_REWARD_DIVISOR_LOG2);
            break;
        }
        if (cfg->payout_interval_epochs == 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "payout_interval_epochs is 0 — "
                          "the payday needs at least one epoch");
            break;
        }
        /* The reference's own parameter rules (types/params.go:145-206),
         * through the port, so there is one implementation of them. */
        if (cmt_consensus_params_validate_basic(&cfg->consensus_params)
            != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the consensus parameters fail the "
                          "reference's ValidateBasic");
            break;
        }
        if (cfg->n_comet_validators != cfg->n_validators) {
            QGP_LOG_ERROR(LOG_TAG, "%u comet rows for %u validators",
                          (unsigned)cfg->n_comet_validators,
                          (unsigned)cfg->n_validators);
            break;
        }

        /* ROW EQUALITY, in the CANONICAL validator order (pubkey ASC —
         * the order the encoding writes the validators in). Carrying the
         * rows lets a transmitted document be read by eye; requiring them
         * to equal the derived ones is what stops the document claiming a
         * committee the stake entries do not produce. */
        int bad = 0;
        for (uint16_t i = 0; i < cfg->n_validators && !bad; i++) {
            const nodus_v2_gen_validator_t *v =
                &cfg->validators[plan.val_idx[i]];
            const nodus_v2_gen_cmt_validator_t *row =
                &cfg->comet_validators[i];
            uint8_t want_addr[NODUS_V2_GEN_CHAIN_ID_LEN];
            int64_t want_power = 0;
            if (gen_v3_row_derive(cfg, v, want_addr, &want_power) != 0) {
                bad = 1;
                break;
            }
            if (memcmp(row->pub_key, v->pubkey, DNAC_PUBKEY_SIZE) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "comet row %u carries a key that is "
                              "not the validator at that position — the rows "
                              "must be in the canonical pubkey order",
                              (unsigned)i);
                bad = 1;
                break;
            }
            if (memcmp(row->address, want_addr,
                       NODUS_V2_GEN_CHAIN_ID_LEN) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "comet row %u address is not the "
                              "witness id of its key", (unsigned)i);
                bad = 1;
                break;
            }
            if (row->power != want_power) {
                QGP_LOG_ERROR(LOG_TAG, "comet row %u power %lld != the "
                              "derived %lld", (unsigned)i,
                              (long long)row->power, (long long)want_power);
                bad = 1;
                break;
            }
        }
        if (bad) break;
        rc = 0;
    } while (0);

    gen_plan_free(&plan);
    return rc;
}

/* ── the port's genesis document ─────────────────────────────────────── */

int nodus_witness_v2_gen_to_cmt_doc(const nodus_v2_gen_config_t *cfg,
                                    cmt_genesis_doc_t *out,
                                    cmt_genesis_validator_t *vals,
                                    size_t cap) {
    if (!cfg || !out || !vals) return -1;
    /* THE SHAPE GUARD EVERY SIBLING RUNS, and this one needs it most:
     * below, `row->name_len` bytes are copied into a char[64]. name_len
     * is a uint8_t, so a config built by hand — this is a PUBLIC
     * function, and nothing forces a caller to have gone through the
     * decoder or the validator — can carry 255 and overflow the
     * destination. gen_v3_shape_ok is the one authority on what is
     * WRITABLE (version 3, n_comet_validators <= the array bound, every
     * name_len <= NODUS_V2_GEN_CMT_NAME_LEN_MAX, key-type storage
     * NUL-terminated), so it is called here rather than restated.
     *
     * The reachable paths were already safe — the decoder refuses
     * name_len > 63 and n_comet_validators != n_validators, and
     * _v3_validate refuses more — but "no current caller can do it" is
     * not a bound, it is a coincidence, and this function is exported. */
    if (gen_v3_shape_ok(cfg) != 0) return -1;
    if ((size_t)cfg->n_comet_validators > cap) {
        QGP_LOG_ERROR(LOG_TAG, "%u comet rows do not fit %zu slots",
                      (unsigned)cfg->n_comet_validators, cap);
        return -1;
    }
    if (cfg->genesis_time_ms == 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "a zero genesis time would take the "
                      "reference's clock branch (types/genesis.go:101-103) "
                      "— refused here instead");
        return -1;
    }
    if (cfg->initial_height > (uint64_t)INT64_MAX) return -1;

    /* Milliseconds → {seconds, nanos}, then the RANGE CHECK. The
     * reference's ValidateAndComplete tests a time only for Go's zero
     * (:101), so an out-of-range instant would pass it and fail later
     * inside the codec; cmt_time_validate is the same predicate the
     * decoder applies (gogoproto validateTimestamp, cmt_time.h:144-150). */
    cmt_time_t t;
    t.seconds = (int64_t)(cfg->genesis_time_ms / 1000ULL);
    t.nanos   = (int32_t)((cfg->genesis_time_ms % 1000ULL) * 1000000ULL);
    if (cmt_time_validate(t) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "genesis_time %llu ms is outside the "
                      "representable range",
                      (unsigned long long)cfg->genesis_time_ms);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->genesis_time = t;
    memcpy(out->chain_id, cfg->chain_id, NODUS_V2_GEN_CHAIN_ID_LEN);
    out->chain_id_len = NODUS_V2_GEN_CHAIN_ID_LEN;
    out->initial_height = (int64_t)cfg->initial_height;
    out->has_consensus_params = true;
    out->consensus_params = cfg->consensus_params;
    out->validators = vals;
    out->validators_cap = cap;
    out->validators_len = cfg->n_comet_validators;
    for (uint16_t i = 0; i < cfg->n_comet_validators; i++) {
        const nodus_v2_gen_cmt_validator_t *row = &cfg->comet_validators[i];
        cmt_genesis_validator_t *g = &vals[i];
        memset(g, 0, sizeof(*g));
        memcpy(g->address, row->address, NODUS_V2_GEN_CHAIN_ID_LEN);
        g->address_len = NODUS_V2_GEN_CHAIN_ID_LEN;
        g->pub_key.present = true;
        memcpy(g->pub_key.key, row->pub_key, CMT_PB_PUBKEY_LEN);
        g->power = row->power;
        memcpy(g->name, row->name, row->name_len);
        g->name[row->name_len] = '\0';
    }
    memcpy(out->app_hash, cfg->app_hash, NODUS_V2_GEN_APP_HASH_LEN);
    out->app_hash_len = NODUS_V2_GEN_APP_HASH_LEN;

    /* types/genesis.go:69-106 — the reference's own validation and
     * completion, ported. `now` is NULL on purpose: the zero-time branch
     * is unreachable (refused above) and a NULL callback makes it a FAULT
     * rather than an invented time (cmt_genesis.h:191-194). */
    int rc = cmt_genesis_doc_validate_and_complete(out, NULL, NULL);
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "the port refused the genesis document "
                      "(rc=%d)", rc);
        return -1;
    }
    return 0;
}

/* ── the stored document ─────────────────────────────────────────────── */

/* Does `needle` occur in `hay`? Used ONLY by the derivation's
 * provisional-id post-condition; no consensus value depends on it. */
static int gen_v3_contains(const uint8_t *hay, size_t hn,
                           const uint8_t *needle, size_t nn) {
    if (!hay || !needle || nn == 0 || hn < nn) return 0;
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(hay + i, needle, nn) == 0) return 1;
    return 0;
}

/* Read the genesisDoc row into a caller-freed buffer. The store hands
 * back a pointer into a live statement, so the bytes are COPIED before
 * the statements are finalized. @return 0 found / -1 absent or fault. */
static int gen_v3_load_doc(nodus_witness_t *w, uint8_t **out, size_t *out_len) {
    if (!w || !w->db || !out || !out_len) return -1;
    *out = NULL;
    *out_len = 0;
    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) return -1;
    const uint8_t *val = NULL;
    size_t vlen = 0;
    int rc = -1;
    if (nodus_cmt_store_get(&s, /*state_table=*/true,
                            NODUS_V2_GEN_GENESIS_DOC_KEY, &val, &vlen)
        == CMT_OK && val && vlen > 0) {
        uint8_t *copy = malloc(vlen);
        if (copy) {
            memcpy(copy, val, vlen);
            *out = copy;
            *out_len = vlen;
            rc = 0;
        }
    }
    nodus_cmt_store_release(&s);
    return rc;
}

/* tokenomics-v3 P2 — the three-valued presence probe (contract:
 * nodus_witness_v2_gen.h). The claims invariant's own genesis probe
 * (nodus_witness_v2_claims.c, nodus_rt_core_invariant) is the shape:
 * table first, then the store; a probe fault is never "absent". */
int nodus_witness_v2_gen_stored_doc_present(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='cmt_state'", -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) return 0;          /* below S14: no store     */
    if (rc != SQLITE_ROW) return -1;

    nodus_cmt_store_t s;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) return -1;
    const uint8_t *val = NULL;
    size_t vlen = 0;
    int grc = nodus_cmt_store_get(&s, /*state_table=*/true,
                                  NODUS_V2_GEN_GENESIS_DOC_KEY, &val, &vlen);
    /* Evaluated BEFORE the release: `val` points into the store's own
     * copy buffer (nodus_witness_cmt_store.h). */
    int present = (grc == CMT_OK && val != NULL && vlen > 0);
    nodus_cmt_store_release(&s);
    if (grc != CMT_OK) return -1;
    return present ? 1 : 0;
}

int nodus_witness_v2_gen_stored_doc(nodus_witness_t *w,
                                    nodus_v2_gen_config_t *cfg_out,
                                    nodus_v2_gen_alloc_t **allocs_out) {
    if (!w || !cfg_out || !allocs_out) return -1;
    *allocs_out = NULL;
    uint8_t *doc = NULL;
    size_t   dlen = 0;
    if (gen_v3_load_doc(w, &doc, &dlen) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "no genesisDoc row — this chain has no "
                      "stored genesis document to take an identity from");
        return -1;
    }
    /* `cfg` is the CALLER's storage now; zeroing it here is what the
     * calloc of the pre-refactor body did, so the four checks below run
     * on exactly the same bytes they ran on before. */
    nodus_v2_gen_config_t *cfg = cfg_out;
    nodus_v2_gen_alloc_t  *allocs = NULL;
    int rc = -1;
    memset(cfg, 0, sizeof(*cfg));
    do {
        /* 1. STRICT DECODE — every bound, no trailing byte. */
        if (nodus_witness_v2_gen_v3_decode(doc, dlen, cfg, &allocs) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document does "
                          "not decode — this chain has no readable "
                          "identity");
            break;
        }
        /* 2. THE DOCUMENT'S CONTENT RULES MUST HOLD. The decoder checks
         * what the bytes ARE; this checks what they MEAN — the Comet
         * rows equal the rows the stake entries produce, the supply
         * equation balances, the claim window is the pinned one, every
         * validator is writable-shaped and its payout fingerprint
         * derives from its payout key.
         *
         * ⚠ IT DOES NOT CHECK ORDER, and believing it did is what let a
         * swapped-validator document through an earlier cut of this
         * function: gen_plan_build SORTS rather than refuses, so both
         * sides of the row comparison are normalised before they meet.
         * Order is check 3's, and check 3 exists because of that. It is
         * kept ahead of check 3 because it names the precise rule that
         * failed, which a byte comparison cannot. */
        if (nodus_witness_v2_gen_v3_validate(cfg) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document "
                          "decodes but breaks a genesis rule — refusing to "
                          "take an identity from it");
            break;
        }
        /* 3. THE STORED BYTES MUST BE THE CANONICAL FORM — re-encode the
         * decoded config and require the result to be IDENTICAL.
         *
         * WITHOUT THIS THE ACCESSOR IS NOT CANONICAL-STRICT, and the
         * reason is worth writing down because it defeated check 2:
         * gen_plan_build does not REFUSE an unsorted validator array, it
         * SORTS it (the insertion sort at gen.c:723-735 builds val_idx,
         * the pubkey-ASC permutation). The encoder writes through
         * val_idx (:919-921) and check 2 compares the Comet rows against
         * validators[val_idx[i]] (:2451) — so a document whose validator
         * entries are SWAPPED in the body decodes into a swapped array,
         * is normalised by the plan on both sides, passes check 2, and
         * re-hashes to the same id in check 4. It was accepted. The same
         * normalisation applies to the allocation list (the qsort at
         * :783), so the hole was not limited to validators.
         *
         * Comparing the BYTES is the exact statement D-18 rev 4 needs —
         * one document, one encoding, one id — and it subsumes every
         * normalisation the plan performs, including any added later. */
        {
            uint8_t *again = NULL;
            size_t   alen = 0;
            if (nodus_witness_v2_gen_v3_encode(cfg, &again, &alen) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document "
                              "could not be re-encoded — refusing");
                break;
            }
            int same = (alen == dlen && memcmp(again, doc, dlen) == 0);
            free(again);
            if (!same) {
                QGP_LOG_ERROR(LOG_TAG,
                    "the stored genesis document is NOT IN CANONICAL FORM "
                    "(stored %zu bytes, canonical %zu) — its fields decode "
                    "but its bytes are not the ones this builder would "
                    "write for them, so it is not a document this chain "
                    "could have produced", dlen, alen);
                break;
            }
        }

        /* 4. AND THE STORED FIELD MUST BE THE DOCUMENT'S OWN HASH.
         * Returning the field as read would make the identity a value
         * anyone who can write the row chooses; recomputing it makes the
         * row's 32 bytes a CHECKSUM of the other ~56 KB rather than an
         * assertion. A one-byte edit anywhere — including in the field
         * itself — is a refusal, not a different chain id. */
        uint8_t recomputed[NODUS_V2_GEN_CHAIN_ID_LEN];
        if (nodus_witness_v2_gen_chain_id(cfg, recomputed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document's "
                          "chain id could not be recomputed");
            break;
        }
        if (memcmp(recomputed, cfg->chain_id,
                   NODUS_V2_GEN_CHAIN_ID_LEN) != 0) {
            char have[QGP_FP_HEX_BUFFER], want[QGP_FP_HEX_BUFFER];
            uint8_t h64[64], w64[64];
            memset(h64, 0, sizeof(h64));
            memset(w64, 0, sizeof(w64));
            memcpy(h64, cfg->chain_id, NODUS_V2_GEN_CHAIN_ID_LEN);
            memcpy(w64, recomputed, NODUS_V2_GEN_CHAIN_ID_LEN);
            qgp_fp_raw_to_hex(h64, have);
            qgp_fp_raw_to_hex(w64, want);
            QGP_LOG_ERROR(LOG_TAG,
                "the stored genesis document's chain_id field does NOT "
                "hash to the document — the row has been altered. "
                "stored=%.64s recomputed=%.64s", have, want);
            break;
        }
        /* The document carries the recomputed id, which the comparison
         * above has just proved equal to the stored field; the wrapper
         * below returns these very bytes, so the value it yields is
         * byte-for-byte the one this function used to return. */
        memcpy(cfg->chain_id, recomputed, NODUS_V2_GEN_CHAIN_ID_LEN);
        rc = 0;
    } while (0);
    *allocs_out = allocs;     /* the caller frees it, success or not */
    free(doc);
    return rc;
}

int nodus_witness_v2_gen_stored_chain_id(
        nodus_witness_t *w, uint8_t out32[NODUS_V2_GEN_CHAIN_ID_LEN]) {
    if (!w || !out32) return -1;
    nodus_v2_gen_config_t *cfg = calloc(1, sizeof(*cfg));   /* ~240 KB */
    nodus_v2_gen_alloc_t  *allocs = NULL;
    int rc;
    if (!cfg) return -1;
    rc = nodus_witness_v2_gen_stored_doc(w, cfg, &allocs);
    if (rc == 0) {
        memcpy(out32, cfg->chain_id, NODUS_V2_GEN_CHAIN_ID_LEN);
    }
    free(allocs);
    free(cfg);
    return rc;
}

/* ── the version-3 derivation ────────────────────────────────────────── */

int nodus_witness_v2_gen_derive_v3(const char *data_path,
                                   const nodus_v2_gen_config_t *cfg,
                                   uint8_t out_chain32[NODUS_V2_GEN_CHAIN_ID_LEN]) {
    if (!data_path || !data_path[0] || !cfg) return -1;

    /* ── 1. The version-3 verdict — every shared rule AND every
     * version-3 rule, before any filesystem or database work. ───────── */
    if (nodus_witness_v2_gen_v3_validate(cfg) != 0) return -1;

    gen_plan_t plan;
    if (gen_plan_build(cfg, &plan) != 0) return -1;

    uint8_t present_commit[NODUS_V2_GEN_SRCCOMMIT_LEN];
    memset(present_commit, 0, sizeof(present_commit));
    int pe = gen_chain_db_scan(data_path, present_commit);
    if (pe < 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "could not classify the chain databases already in the data "
            "path — refusing to derive (fail closed)");
        gen_plan_free(&plan);
        return -1;
    }
    if (pe == 2) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
            "a FOREIGN chain database is already present in the data path "
            "— refusing to derive. Deriving beside it would leave two "
            "chains and let each node boot a different one.");
        gen_plan_free(&plan);
        return -1;
    }

    /* ── 2. The source binding: the document with chain_id AND app_hash
     * blanked — the genesis apply's INPUT. Computed before the
     * idempotency branch, because "a chain already exists" is a success
     * only if it is THIS config's chain (D4). ──────────────────────── */
    uint8_t source_commit[NODUS_V2_GEN_SRCCOMMIT_LEN];
    if (nodus_witness_v2_gen_v3_source_commit(cfg, source_commit) != 0) {
        gen_plan_free(&plan);
        return -1;
    }

    if (pe == 1) {
        if (memcmp(present_commit, source_commit,
                   NODUS_V2_GEN_SRCCOMMIT_LEN) == 0) {
            QGP_LOG_INFO(LOG_TAG, "%s",
                         "a chain derived from THIS config already exists — "
                         "nothing to derive");
            gen_plan_free(&plan);
            return 0;
        }
        {
            char have[QGP_FP_HEX_BUFFER], want[QGP_FP_HEX_BUFFER];
            qgp_fp_raw_to_hex(present_commit, have);
            qgp_fp_raw_to_hex(source_commit, want);
            QGP_LOG_ERROR(LOG_TAG,
                "the data path already holds a chain built from a DIFFERENT "
                "config — refusing to report success. present "
                "source_commit=%s config source_commit=%s", have, want);
        }
        gen_plan_free(&plan);
        return -1;
    }

    /* ── 3. The distribution snapshot root (re-proves the leaf order). */
    uint8_t snap_root[64];
    if (dna_dist_snapshot_root(plan.leaves, plan.n_leaves, snap_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "distribution snapshot root failed");
        gen_plan_free(&plan);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "deriving a cometbft (version 3) chain: %u "
                 "validators, %zu allocations, %llu raw claimable of %llu "
                 "total", (unsigned)cfg->n_validators, plan.n_leaves,
                 (unsigned long long)plan.total_claimable,
                 (unsigned long long)cfg->total_supply_raw);

    /* ── 4. Provisional database name. The chain id does not exist yet —
     * it is a hash of a document that does not exist until the apply has
     * produced app_hash — so the scratch database is named from the
     * source commit and RENAMED once the id is known. The provisional
     * value never reaches a stored byte; the post-conditions check it. */
    uint8_t prov_full[64], prov16[16];
    if (qgp_sha3_512(source_commit, sizeof(source_commit), prov_full) != 0) {
        gen_plan_free(&plan);
        return -1;
    }
    memcpy(prov16, prov_full, 16);

    /* A MUTABLE copy: app_hash and chain_id are OUTPUTS of this
     * derivation and the caller's config is const. The allocation array
     * is shared by pointer and is never written through. */
    nodus_v2_gen_config_t *work = calloc(1, sizeof(*work));
    nodus_witness_t *w2 = calloc(1, sizeof(*w2));
    if (!work || !w2) {
        free(work);
        free(w2);
        gen_plan_free(&plan);
        return -1;
    }
    memcpy(work, cfg, sizeof(*work));
    w2->cached_committee_epoch_start = UINT64_MAX;

    int pn = snprintf(w2->data_path, sizeof(w2->data_path), "%s/v2gen.tmp",
                      data_path);
    if (pn < 0 || (size_t)pn >= sizeof(w2->data_path)) {
        QGP_LOG_ERROR(LOG_TAG,
            "data path too long (%zu bytes) to form a scratch directory "
            "within %zu — refusing to derive rather than clearing a "
            "truncated path", strlen(data_path), sizeof(w2->data_path));
        free(work);
        free(w2);
        gen_plan_free(&plan);
        return -1;
    }
    gen_scratch_clear(w2->data_path);           /* crashed prior attempt */
    if (mkdir(w2->data_path, 0700) != 0 && errno != EEXIST) {
        free(work);
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

    uint8_t  chain32[NODUS_V2_GEN_CHAIN_ID_LEN];
    uint8_t *doc = NULL;
    size_t   doc_len = 0;
    int ok = -1;
    do {
        if (nodus_witness_create_chain_db(w2, prov16) != 0) break;
        /* Mark the handle a Ledger V2 chain BEFORE any validator-set
         * seeding. THE ORDER IS THE POINT: the writer guard that clamps
         * an active set to NODUS_V2_ACTIVE_SET_MAX is gated on
         * v2_successor (nodus_witness_vset.c), and
         * nodus_witness_vset_commit_genesis seeds the epoch-0/E snapshots
         * through that guard. Set the flag after seeding and the genesis
         * snapshots seed UNCAPPED — committed, and wrong. (This rule was
         * stated at step 4 of the deleted version-2 derivation; it is
         * this function's own now.) */
        w2->v2_successor = 1;
        /* R3 W3 (D-17 rev 10 (8)) — S14 FIRST, THEN THE LEDGER GENESIS.
         *
         * W2 built the ledger at S12 and climbed to S14 only afterwards,
         * because the ledger's genesis runs every registered runtime's
         * `state_init` hook (nodus_witness_domreg.c:326-340, generic
         * dispatch, no domain branch), and the CORE hook —
         * `nodus_rt_core_state_init`, nodus_witness_v2_pools.c — gated
         * itself on an equality list of schema versions that stopped at
         * S12: at S14 it returned -1 with no diagnosis, and that gate
         * belonged to the LIVE legacy lane, so W2 could not widen it
         * (D-17 rev 7 (7)). W3 widens it in the SAME commit
         * (nodus_witness_v2_pools.c, `nodus_rt_core_state_init` and
         * `nodus_witness_v2_pools_startup_check`) and narrows
         * `nodus_witness_v2_genesis_cmt`'s own gate back to S14 alone
         * (nodus_witness_v2_apply.c) — the three edits are one change.
         * With the pool gate now accepting S15 (tokenomics-v3 P1 moved
         * it from S14), there is no longer a reason to defer the climb:
         * the database migrates to S15 HERE, before
         * `nodus_chain_config_db_migrate`, the seeder or any genesis
         * step runs, exactly the order every other schema rung in this
         * derivation uses (migrate first, then act on it).
         * `nodus_witness_db_migrate_v2s15` cascades through S14, S13 and
         * S12 on its own (nodus_witness_v2_schema.c), so a freshly
         * created database reaches S15 in this one call.
         * tokenomics-v3 P2 moves the live rung S15 -> S16 (the reward
         * pool column and the two reward tables);
         * `nodus_witness_db_migrate_v2s16` cascades through S15 the same
         * way. */
        if (nodus_witness_db_migrate_v2s16(w2) != 0) break;
        if (nodus_chain_config_db_migrate(w2) != 0) break;

        /* ── 5. SYSTEM state, from the config — the SAME seeder. ────── */
        if (gen_seed_state(w2, cfg, &plan, source_commit) != 0) break;

        /* ── 6. Authority + registry + manifest + genesis ───────────── */
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
            /* tokenomics-v3 P2 (P2-1): and the reserve reads back as the
             * config's — the committed pool is the one the distribution
             * will pay from. */
            if (sup.reward_pool != gen_reward_pool(cfg)) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the committed reward pool does "
                              "not read back as the config — ABORT");
                break;
            }
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

        /* ── 7. THE COMET GENESIS APPLY. No height-0 block row; the
         * ledger's global root comes back as the document's app_hash. */
        uint8_t global_root[64];
        if (nodus_witness_v2_genesis_cmt(w2, vsh, mbytes, mlen,
                                         global_root) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "cometbft genesis FAILED");
            break;
        }

        /* ── 8. Complete the document: app_hash, then the chain id over
         * the completed document with its own id blanked. ORDER IS THE
         * SPEC — app_hash is inside the chain-id preimage and outside the
         * source-commit one. */
        memcpy(work->app_hash, global_root, NODUS_V2_GEN_APP_HASH_LEN);
        memset(work->chain_id, 0, NODUS_V2_GEN_CHAIN_ID_LEN);
        if (nodus_witness_v2_gen_chain_id(work, chain32) != 0) break;
        memcpy(work->chain_id, chain32, NODUS_V2_GEN_CHAIN_ID_LEN);

        if (nodus_witness_v2_gen_v3_encode(work, &doc, &doc_len) != 0) break;

        /* R3 W3 (D-17 rev 10 (8)) — the separate "climb to S14 after the
         * genesis" step that used to live here is GONE: the database is
         * already at S14 (migrated before step 4), so `cmt_state` has
         * been a valid table since before the ledger genesis ran, and
         * the document is stored directly below. What the S14 rung
         * demands of the database and why the three dropped v2_blocks
         * columns lose nothing (nodus_witness_v2_schema.c:1412-1590) is
         * unchanged by moving the call earlier — a migration's
         * post-conditions do not depend on how many other statements ran
         * before it in the same transaction sequence. */

        /* ── 9. Store the COMPLETED document under the reference's own
         * key (node/setup.go:551, saveGenesisDoc :606-611). `stateKey` is
         * NOT written: the State is made on the node's first start
         * (:581 LoadFromDBOrGenesisDoc), which is package C1c's. */
        {
            nodus_cmt_store_t s;
            if (nodus_cmt_store_init(&s, w2->db, false) != CMT_OK) break;
            int srv = nodus_cmt_store_set(&s, /*state_table=*/true,
                                          NODUS_V2_GEN_GENESIS_DOC_KEY,
                                          doc, doc_len);
            nodus_cmt_store_release(&s);
            if (srv != CMT_OK) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the genesis document could not "
                              "be stored — ABORT");
                break;
            }
        }

        /* ── 10. Post-conditions ─────────────────────────────────────
         *
         * ALL OF THEM RUN AT THE LIVE RUNG (S16 since tokenomics-v3 P2),
         * and that is checked, not assumed. A grep for
         * `nodus_witness_db_schema_version(` over nodus/src/witness finds
         * every schema-version GATE in the tree (re-derived for
         * tokenomics-v3 P4; the W3 list that stood here named the
         * old-lane sync2 block server, deleted by R3 W4). The migration
         * ladder inside nodus_witness_v2_schema.c reads its own starting
         * version at every rung and gates nothing else; excluding it,
         * the gates are, by function (tokenomics-v3 P4 deleted the
         * version-2 engine genesis and the legacy-lane block apply, the
         * two S9-S12 gates this list used to carry):
         *   v2_apply_block_body                 (Comet-lane block apply,
         *                                        S16 only)
         *   nodus_witness_v2_genesis_cmt        (this lane's genesis, S16
         *                                        only)
         *   nodus_witness_v2_pools_startup_check
         *   nodus_rt_core_state_init            (nodus_witness_v2_pools.c)
         *   nodus_witness_v2_preflight          (the equality gate)
         * None of them is on the path of anything below:
         * nodus_witness_v2_supply_check dispatches nodus_rt_core_invariant
         * (nodus_witness_v2_claims.c:868), nodus_validator_get
         * (nodus_witness_validator.c:197) and
         * nodus_witness_v2_bundle_persist
         * (nodus_witness_v2_bundle.c:313) are all plain queries with no
         * version gate. */

        /* (a) NO genesis block row — of any height. This is also what
         * makes the three columns the S14 rung dropped above carry no
         * committed value. */
        {
            sqlite3_int64 n_blk = -1;
            if (gen_count(w2->db, "SELECT COUNT(*) FROM v2_blocks",
                          &n_blk) != 0 || n_blk != 0) {
                QGP_LOG_ERROR(LOG_TAG, "v2_blocks holds %lld rows after a "
                              "cometbft genesis — ABORT", (long long)n_blk);
                break;
            }
        }

        /* (b) The stored row IS the document, it decodes STRICTLY, its
         * chain_id recomputes to itself, and its Comet rows still equal
         * the derived ones (v3_validate re-run on the DECODED config —
         * so a storage layer that mangled a byte cannot pass). */
        {
            uint8_t *back = NULL;
            size_t   blen = 0;
            if (gen_v3_load_doc(w2, &back, &blen) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the genesis document does not "
                              "read back — ABORT");
                break;
            }
            int same = (blen == doc_len && memcmp(back, doc, doc_len) == 0);
            nodus_v2_gen_config_t *dec = calloc(1, sizeof(*dec));
            nodus_v2_gen_alloc_t  *dec_allocs = NULL;
            int good = 0;
            if (same && dec &&
                nodus_witness_v2_gen_v3_decode(back, blen, dec,
                                               &dec_allocs) == 0) {
                uint8_t again[NODUS_V2_GEN_CHAIN_ID_LEN];
                good = (nodus_witness_v2_gen_chain_id(dec, again) == 0 &&
                        memcmp(again, chain32,
                               NODUS_V2_GEN_CHAIN_ID_LEN) == 0 &&
                        memcmp(dec->chain_id, chain32,
                               NODUS_V2_GEN_CHAIN_ID_LEN) == 0 &&
                        memcmp(dec->app_hash, global_root,
                               NODUS_V2_GEN_APP_HASH_LEN) == 0 &&
                        nodus_witness_v2_gen_v3_validate(dec) == 0);
            }
            free(dec_allocs);
            free(dec);
            /* (c) The provisional id must not have leaked into the stored
             * document. It is a name for a file, never an identity. */
            if (good && gen_v3_contains(back, blen, prov16, sizeof(prov16))) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the provisional database id "
                              "appears inside the stored genesis document — "
                              "ABORT");
                good = 0;
            }
            free(back);
            if (!good) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "the stored genesis document is "
                              "not the one this derivation produced — ABORT");
                break;
            }
        }
        if (gen_v3_contains(mbytes, mlen, prov16, sizeof(prov16))) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the provisional database id "
                          "appears inside the committed manifest — ABORT");
            break;
        }

        /* (d) The ledger post-conditions (carried over unchanged from
         * the deleted version-2 derivation): no spendable value, the
         * whole reserve claimable, exactly the configured bond, every
         * committed validator row writable-shaped (L2-F4 at the
         * committed-row level), and the conservation equation balancing
         * (L2-F1, the producer half). */
        sqlite3_int64 n_utxo = -1;
        if (gen_count(w2->db, "SELECT COUNT(*) FROM utxo_set",
                      &n_utxo) != 0 || n_utxo != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "a genesis holds spendable UTXOs — ABORT");
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
        if (nodus_witness_v2_supply_check(w2) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "the supply equation does not "
                          "balance on the derived chain — ABORT");
            break;
        }

        /* ── 12. The genesis bundle, persisted while the base tables
         * still hold their exact genesis-time bytes. The PRODUCER side
         * reads the committed manifest and the five base tables
         * (six before the root-layout round dropped epoch_state) — never
         * the height-0 block row — so it is carried unchanged here.
         *
         * Since R3 W3, `nodus_witness_v2_bundle_apply`
         * (nodus_witness_v2_bundle.c) runs `nodus_witness_v2_
         * genesis_cmt` on a version-3 chain — never the version-2
         * engine genesis this comment used to warn about — and requires
         * BOTH the stored document's `chain_id` to
         * equal the joiner's pin AND its `app_hash` to equal the root
         * that call just computed from the replanted tables
         * (nodus_witness_v2_bundle_apply): a bundle whose tables
         * were tampered but whose document still hashes to the pin is
         * refused there, not silently adopted. The obligation this
         * comment used to name (C1c/W3 routing the Comet lane's bundle
         * apply through the version-3 genesis) is CLOSED.
         */
        if (nodus_witness_v2_bundle_persist(w2) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "genesis bundle persistence FAILED — ABORT");
            break;
        }

        /* ── 13. Land the real name — rename only after a COMPLETE
         * derivation. The FILE NAME is a selection convention; the
         * identity is the document's chain_id (D-18 rev 4). */
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

        /* ── O16A — THE PARTIAL-WIPE MARKER IS NOT WRITTEN HERE. It means
         * "this node completed a normal boot with a chain", and this
         * builder creates only ONE of the three databases the gate
         * (nodus_server_check_partial_wipe) requires all-present; a
         * marker written here fails the next start of a freshly
         * provisioned host, whose printed remedy deletes the chain just
         * derived. The write lives in nodus_server_init
         * (nodus/docs/BOOTSTRAP.md, "Who writes .witness_db_seen"). This
         * note moved here from the deleted version-2 derivation, where
         * the original defect was found. */

        if (out_chain32)
            memcpy(out_chain32, chain32, NODUS_V2_GEN_CHAIN_ID_LEN);
        QGP_LOG_INFO(LOG_TAG, "cometbft (version 3) chain derived: %s "
                     "(reserve=%llu raw across %zu claim leaves, "
                     "bonded=%llu)", real_path,
                     (unsigned long long)plan.total_claimable,
                     plan.n_leaves,
                     (unsigned long long)plan.stake_total);
        ok = 0;
    } while (0);

    free(doc);
    if (w2->db) { sqlite3_close(w2->db); w2->db = NULL; }
    gen_scratch_clear(w2->data_path);           /* nothing partial */
    free(w2);
    free(work);
    gen_plan_free(&plan);
    return ok;
}
