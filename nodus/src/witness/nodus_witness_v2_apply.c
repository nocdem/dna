/**
 * @file nodus_witness_v2_apply.c
 * @brief Ledger V2 Season 5/6 — atomic global-block apply engine, V2
 *        genesis and the V2 supply gate (INACTIVE). Contract:
 *        nodus_witness_v2_apply.h.
 *
 * GENERICITY: the engine is domain-count agnostic. The domain set is
 * loaded from the domain registry (any registered IDs, any count up to
 * the engine bound); state roots, claim application and supply
 * invariants dispatch through the REGISTERED runtime hooks
 * (nodus_witness_runtime.h) — no branch in this file names a concrete
 * domain beyond "the mandatory SYSTEM protocol domain comes first",
 * which is a protocol rule, not a consumer rule.
 *
 * @file nodus_witness_v2_apply.c
 */

#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"                 /* DNAC_CFG_* */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2APPLY"

#define MAX_OPS 16      /* engine array bound; the GLOBAL tx cap (<= 10)
                         * is enforced separately from chain config      */
#define MAX_DOMS 64     /* engine bound on registered domains per DB —
                         * a resource bound, never a protocol maximum    */

static int exec_sql(nodus_witness_t *w, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(w->db, sql, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "SQL failed: %s", err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* Sum one u64 aggregate; fail-closed (D1: DB error is never a value). */
static int sum_q(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) { sqlite3_finalize(st); return -1; }
    sqlite3_int64 v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    if (v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

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

/* ── V2 supply gate: runtime-owned invariant DISPATCH ───────────────── */

int nodus_witness_v2_supply_check(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    /* The registered domain set is the authority. A database that has
     * no registry yet (pre-V2-genesis) dispatches the CONFIGURED native
     * runtime table instead — the initial configuration, not a
     * framework limit. */
    uint32_t dom_ids[MAX_DOMS];
    size_t n_dom = 0;
    int has = table_exists(w, "domain_registry");
    if (has < 0) return -1;
    if (has == 1) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT domain_id FROM domain_registry "
                "ORDER BY domain_id ASC", -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (n_dom >= MAX_DOMS) { sqlite3_finalize(st); return -1; }
            sqlite3_int64 v = sqlite3_column_int64(st, 0);
            if (v < 0 || v > (sqlite3_int64)UINT32_MAX) {
                sqlite3_finalize(st);
                return -1;
            }
            dom_ids[n_dom++] = (uint32_t)v;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;   /* mid-scan fault ≠ a value  */
    }

    if (n_dom == 0) {
        /* Pre-registry: the configured native runtimes check their own
         * invariants (NULL hook = no asset state declared). */
        const nodus_domain_runtime_t *table = w->v2_runtime_table;
        size_t n = w->v2_runtime_table_n;
        if (!table)
            table = nodus_runtime_builtin_table(&n);
        if (!table) return -1;
        for (size_t i = 0; i < n; i++)
            if (table[i].invariant &&
                table[i].invariant(&table[i], w) != 0)
                return -1;
        return 0;
    }

    for (size_t i = 0; i < n_dom; i++) {
        dna_domreg_record_t rec;
        if (nodus_witness_domreg_get(w, dom_ids[i], &rec, NULL, NULL)
            != 0)
            return -1;
        const nodus_domain_runtime_t *rt = NULL;
        if (nodus_witness_v2_runtime_for(w, dom_ids[i], 0, &rt) != 0) {
            if (rec.status == DNA_DOMST_ACTIVE) {
                /* An ACTIVE domain whose runtime this build cannot
                 * resolve holds UNKNOWN state — never "conserved". */
                QGP_LOG_ERROR(LOG_TAG, "SUPPLY V2: no runtime for ACTIVE "
                              "domain %u — failing the gate", dom_ids[i]);
                return -1;
            }
            continue;                   /* not active, no runtime: inert */
        }
        if (rt->invariant && rt->invariant(rt, w) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "SUPPLY V2: domain %u invariant violated", dom_ids[i]);
            return -1;
        }
    }
    return 0;
}

/* ── DomainHead persistence ─────────────────────────────────────────── */

static int head_store(nodus_witness_t *w, const dna_v2_domain_head_t *h) {
    uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN];
    if (dna_v2_domain_head_encode(h, enc) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT OR REPLACE INTO v2_domain_heads "
            "(domain_id, head, domain_height, last_updated_global) "
            "VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h->domain_id);
    sqlite3_bind_blob(st, 2, enc, DNA_V2_DOMHEAD_ENC_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)h->domain_height);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)h->last_updated_global_height);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Decode the 89-byte canonical head blob (layout: ledger_roots_v2.h). */
static void head_decode(const uint8_t enc[DNA_V2_DOMHEAD_ENC_LEN],
                        dna_v2_domain_head_t *h) {
    memset(h, 0, sizeof(*h));
    h->domain_id = ((uint32_t)enc[0] << 24) | ((uint32_t)enc[1] << 16) |
                   ((uint32_t)enc[2] << 8) | enc[3];
    memcpy(h->domain_state_root, enc + 4, 64);
    for (int i = 0; i < 8; i++)
        h->domain_height = (h->domain_height << 8) | enc[68 + i];
    for (int i = 0; i < 8; i++)
        h->last_updated_global_height =
            (h->last_updated_global_height << 8) | enc[76 + i];
    h->ruleset_version = ((uint32_t)enc[84] << 24) |
                         ((uint32_t)enc[85] << 16) |
                         ((uint32_t)enc[86] << 8) | enc[87];
    h->status = enc[88];
}

/* 0 found (validated blob + mirror agreement), 1 absent, -1 fault. */
static int head_load(nodus_witness_t *w, uint32_t domain_id,
                     dna_v2_domain_head_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT head, domain_height, last_updated_global "
            "FROM v2_domain_heads WHERE domain_id = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    int out_rc = -1;
    if (rc == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        dna_v2_domain_head_t h;
        head_decode(sqlite3_column_blob(st, 0), &h);
        uint64_t mh = (uint64_t)sqlite3_column_int64(st, 1);
        uint64_t ml = (uint64_t)sqlite3_column_int64(st, 2);
        if (h.domain_id == domain_id && h.domain_height == mh &&
            h.last_updated_global_height == ml) {
            *out = h;
            out_rc = 0;
        }
    }
    sqlite3_finalize(st);
    return out_rc;
}

/* Latest committed update hash for a domain (genesis sentinel if none). */
static int prev_update_hash(nodus_witness_t *w, uint32_t domain_id,
                            uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT upd_hash FROM v2_domain_updates WHERE domain_id = ?1 "
            "ORDER BY global_height DESC LIMIT 1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);
    int rc = sqlite3_step(st);
    int out_rc = -1;
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 0) == 64) {
            memcpy(out, sqlite3_column_blob(st, 0), 64);
            out_rc = 0;
        }
    } else if (rc == SQLITE_DONE) {
        out_rc = dna_dupd_prev_genesis(out);
    }
    sqlite3_finalize(st);
    return out_rc;
}

/* ── The registered-domain working set ──────────────────────────────── */

typedef struct {
    uint32_t domain_id;
    uint8_t  status;                    /* registry record status (this
                                         * scan's view)                  */
    uint8_t  pre_status;                /* status at BLOCK ENTRY — the
                                         * executability authority       */
    const nodus_domain_runtime_t *rt;   /* NULL = not locally resolvable */
    dna_domain_manifest_t man;          /* current manifest (quotas)     */
    int      has_head;                  /* persisted head row existed    */
    int      activated;                 /* head CREATED in this block    */
    dna_v2_domain_head_t head;          /* pre-block (or activation) head*/
    int      touched;
    uint8_t  tx_ids[MAX_OPS][64];       /* local order                   */
    uint32_t n_tx;
    uint32_t res_cost;                  /* checked accumulation          */
    int      root_known;
    uint8_t  root_now[64];
    dna_v2_domain_head_t newhead;
    dna_domain_update_t upd;
    uint8_t  upd_hash[64];
} dom_ctx_t;

/*
 * Load EVERY registered domain (ORDER BY domain_id ASC — fail-closed):
 * record + manifest + runtime resolution + persisted head. There is NO
 * head synthesis anywhere: a DomainHead exists ONLY from the exact
 * activation block onward (canonical lifecycle).
 *
 * strict_active enforces the ACTIVE-domain consensus preconditions
 * (every ACTIVE domain has exactly one persisted head AND resolves to
 * exactly one runtime — a witness that cannot execute an active domain
 * must not apply blocks). It is 0 only where activation heads are still
 * pending: the genesis constructor and the in-block lifecycle re-scan,
 * both of which apply the same rules explicitly afterwards.
 */
static int doms_load(nodus_witness_t *w, dom_ctx_t *doms, size_t *n_out,
                     int strict_active) {
    size_t n = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT domain_id FROM domain_registry ORDER BY domain_id ASC",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= MAX_DOMS) { sqlite3_finalize(st); return -1; }
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        if (v < 0 || v > (sqlite3_int64)UINT32_MAX) {
            sqlite3_finalize(st);
            return -1;
        }
        memset(&doms[n], 0, sizeof(doms[n]));
        doms[n].domain_id = (uint32_t)v;
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    if (n == 0) return -1;              /* V2 apply needs a registry     */

    for (size_t i = 0; i < n; i++) {
        dom_ctx_t *d = &doms[i];
        dna_domreg_record_t rec;
        if (nodus_witness_domreg_get(w, d->domain_id, &rec, &d->man,
                                     NULL) != 0)
            return -1;                  /* incl. UNKNOWN lifecycle values
                                         * — record validation is
                                         * fail-closed (1..5 only)       */
        switch (rec.status) {           /* defense in depth: never treat
                                         * an unknown value as any known
                                         * lifecycle state               */
            case DNA_DOMST_REGISTERED:
            case DNA_DOMST_SCHEDULED:
            case DNA_DOMST_ACTIVE:
            case DNA_DOMST_PAUSED:
            case DNA_DOMST_RETIRED:
                break;
            default:
                return -1;
        }
        d->status = rec.status;
        d->pre_status = rec.status;
        (void)nodus_witness_v2_runtime_for(w, d->domain_id, 0, &d->rt);

        int hrc = head_load(w, d->domain_id, &d->head);
        if (hrc < 0) return -1;
        d->has_head = (hrc == 0);
        if (!d->has_head) {
            memset(&d->head, 0, sizeof(d->head));
            d->head.domain_id = d->domain_id;
        }
        if (strict_active && d->status == DNA_DOMST_ACTIVE) {
            if (!d->rt) {
                QGP_LOG_ERROR(LOG_TAG, "ACTIVE domain %u has no locally "
                              "resolvable runtime — consensus failure",
                              d->domain_id);
                return -1;
            }
            if (!d->has_head) {
                QGP_LOG_ERROR(LOG_TAG, "ACTIVE domain %u has no committed "
                              "DomainHead — consensus failure (heads are "
                              "created ONLY at activation, never "
                              "synthesized)", d->domain_id);
                return -1;
            }
        }
    }
    *n_out = n;
    return 0;
}

/*
 * Canonical ACTIVATION DomainHead construction — the ONLY way a
 * DomainHead comes into existence, used identically by V2 genesis
 * (activation block = the genesis block) and by in-block activation of
 * a later-registered domain. Every field takes ONE exact value:
 *
 *   domain_id                  = the registry id
 *   domain_state_root          = the runtime's state root, evaluated in
 *                                the activation block. BINDING: the
 *                                runtime's ACTIVATION PAYLOAD root
 *                                (payload_root hook, or the state root
 *                                itself when the hook is NULL) MUST
 *                                equal the registry-committed
 *                                genesis_state_root — an activation
 *                                whose initial state does not match the
 *                                committed genesis root fails closed.
 *   domain_height              = 0
 *   last_updated_global_height = the activation block's global height
 *   ruleset_version            = the ACTIVE manifest's ruleset_version
 *   status                     = DNA_DOMST_ACTIVE
 *
 * Also appends the height-0 root-history row (upd_hash = the genesis
 * linkage sentinel — no DomainUpdate exists for an activation). Runs
 * INSIDE the caller's transaction. @return 0 / -1 (nothing partial).
 */
static int head_activate(nodus_witness_t *w, dom_ctx_t *d,
                         uint64_t global_height) {
    if (!d || !d->rt || d->status != DNA_DOMST_ACTIVE) return -1;

    uint8_t sr[64], chk[64];
    if (d->rt->state_root(d->rt, w, sr) != 0) return -1;
    if (d->rt->payload_root) {
        if (d->rt->payload_root(d->rt, w, chk) != 0) return -1;
    } else {
        memcpy(chk, sr, 64);
    }
    if (memcmp(chk, d->man.genesis_state_root, 64) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "domain %u activation root does not match "
                      "the registry-committed genesis_state_root — "
                      "rejected", d->domain_id);
        return -1;
    }

    memset(&d->head, 0, sizeof(d->head));
    d->head.domain_id = d->domain_id;
    memcpy(d->head.domain_state_root, sr, 64);
    d->head.domain_height = 0;
    d->head.last_updated_global_height = global_height;
    d->head.ruleset_version = d->man.ruleset_version;
    d->head.status = DNA_DOMST_ACTIVE;
    if (head_store(w, &d->head) != 0) return -1;

    uint8_t sentinel[64];
    if (dna_dupd_prev_genesis(sentinel) != 0) return -1;
    sqlite3_stmt *hs = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_root_history (domain_id, domain_height, "
            "global_height, state_root, upd_hash, ruleset_version, "
            "ruleset_hash) VALUES (?1, 0, ?2, ?3, ?4, ?5, ?6)",
            -1, &hs, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(hs, 1, (sqlite3_int64)d->domain_id);
    sqlite3_bind_int64(hs, 2, (sqlite3_int64)global_height);
    sqlite3_bind_blob(hs, 3, d->head.domain_state_root, 64,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(hs, 4, sentinel, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(hs, 5, (sqlite3_int64)d->man.ruleset_version);
    sqlite3_bind_blob(hs, 6, d->man.ruleset_hash, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(hs);
    sqlite3_finalize(hs);
    if (rc != SQLITE_DONE) return -1;

    d->has_head = 1;
    d->activated = 1;
    return 0;
}

static dom_ctx_t *dom_for(dom_ctx_t *doms, size_t n, uint32_t id) {
    for (size_t i = 0; i < n; i++)
        if (doms[i].domain_id == id) return &doms[i];
    return NULL;
}

/* ── V2 genesis ─────────────────────────────────────────────────────── */

int nodus_witness_v2_genesis(nodus_witness_t *w,
                             const uint8_t genesis_block_id[64],
                             const uint8_t vset_hash[64],
                             uint64_t epoch) {
    return nodus_witness_v2_genesis_ex(w, genesis_block_id, vset_hash,
                                       epoch, NULL, 0);
}

int nodus_witness_v2_genesis_ex(nodus_witness_t *w,
                                const uint8_t genesis_block_id[64],
                                const uint8_t vset_hash[64],
                                uint64_t epoch,
                                const uint8_t *manifest_bytes,
                                size_t manifest_len) {
    if (!w || !w->db || !genesis_block_id || !vset_hash) return -1;
    if ((manifest_bytes == NULL) != (manifest_len == 0)) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S6)
        return -1;

    /* Idempotency: a committed height-0 row decides. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            int same = (sqlite3_column_bytes(st, 0) == 64 &&
                        memcmp(sqlite3_column_blob(st, 0),
                               genesis_block_id, 64) == 0);
            sqlite3_finalize(st);
            return same ? 0 : -2;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    int ok = 0;
    dna_v2_domain_head_t *heads = NULL;
    do {
        /* Registry with REAL payload-root manifests (cycle break). The
         * seeded set is the CONFIGURED initial one; any domain a test
         * (or a future genesis procedure) registered beforehand simply
         * participates below — the loop is registry-driven. */
        if (nodus_witness_domreg_init_genesis(w) != 0) break;

        /* S6: commit the canonical genesis manifest (seq 0, height 0)
         * BEFORE the root computation — the SYSTEM head root below then
         * commits the REAL manifest_root. NON-CIRCULAR by construction:
         * the manifest commits the DomainManifest hashes, whose
         * genesis_state_root legs are the RUNTIME-OWNED payload roots
         * ("DNA.SYSPAYL.v1" — no registry/manifest leg), so
         *   payload → DomainManifest hash → GenesisManifest hash →
         *   manifest_root → FINAL system root
         * stays a DAG with no fixed point. */
        if (manifest_bytes &&
            nodus_witness_v2_manifest_commit(w, manifest_bytes,
                                             manifest_len, 0, 0) != 0)
            break;

        /* The genesis block IS the activation block of every domain the
         * registry holds ACTIVE: each head comes from the ONE canonical
         * activation constructor (state root via the runtime hook,
         * bound to the registry-committed genesis_state_root, height 0,
         * last_updated = 0, status ACTIVE, height-0 history row). A
         * registered-but-not-ACTIVE domain exists ONLY in the registry:
         * no head, absent from domains_root, cannot execute. */
        dom_ctx_t *doms = calloc(MAX_DOMS, sizeof(*doms));
        size_t n_dom = 0;
        if (!doms) break;
        if (doms_load(w, doms, &n_dom, /*strict_active=*/0) != 0) {
            free(doms);
            break;
        }
        if (n_dom < 1 || doms[0].domain_id != DNA_DOMAIN_SYSTEM ||
            doms[0].status != DNA_DOMST_ACTIVE) {
            free(doms);                 /* ACTIVE SYSTEM is mandatory    */
            break;
        }
        heads = calloc(n_dom, sizeof(*heads));
        if (!heads) { free(doms); break; }

        int all_ok = 1;
        size_t n_heads = 0;
        for (size_t i = 0; i < n_dom; i++) {
            if (doms[i].status != DNA_DOMST_ACTIVE) continue;
            if (doms[i].has_head) { all_ok = 0; break; }   /* impossible
                                         * pre-genesis — fail closed     */
            if (head_activate(w, &doms[i], 0) != 0) { all_ok = 0; break; }
            heads[n_heads++] = doms[i].head;
        }
        if (!all_ok || n_heads == 0) { free(doms); break; }

        uint8_t domains_root[64], global_root[64];
        if (dna_v2_domains_root(heads, n_heads, domains_root) != 0) {
            free(doms);
            break;
        }
        if (dna_v2_global_root(domains_root, global_root) != 0) {
            free(doms);
            break;
        }

        uint8_t tx_root[64], dupd_root[64];
        if (dna_v2_tx_batch_root(NULL, 0, tx_root) != 0) {
            free(doms);
            break;
        }
        if (dna_v2_domain_updates_root(NULL, 0, dupd_root) != 0) {
            free(doms);
            break;
        }

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count, qc) "
                "VALUES (0,?1,?2,?3,?4,?5,?6,?7,?8,0,NULL)",
                -1, &st, NULL) != SQLITE_OK) {
            free(doms);
            break;
        }
        uint8_t zero64[64];
        memset(zero64, 0, sizeof(zero64));
        sqlite3_bind_blob(st, 1, genesis_block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, zero64, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)epoch);
        sqlite3_bind_blob(st, 4, tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, domains_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, global_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, vset_hash, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        free(doms);
        if (rc != SQLITE_DONE) break;
        /* (height-0 root-history rows were written by head_activate —
         * the ONE canonical activation path.) */

        if (nodus_witness_v2_supply_check(w) != 0) break;
        ok = 1;
    } while (0);
    free(heads);

    if (!ok) { (void)exec_sql(w, "ROLLBACK"); return -1; }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    return 0;
}

/* ── Apply ──────────────────────────────────────────────────────────── */

#define FAIL_POINT(pt) \
    do { if (blk->fail_at == (pt)) goto fail; } while (0)

int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk) {
    if (!w || !w->db || !blk || (blk->n_ops > 0 && !blk->ops)) return -1;
    if (blk->n_ops > MAX_OPS) return -1;

    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S6)
        return -1;

    /* ── 0. replay / linkage (read-only, pre-transaction) ───────────── */
    {
        sqlite3_stmt *st = NULL;
        /* same height? */
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            int same = (sqlite3_column_bytes(st, 0) == 64 &&
                        memcmp(sqlite3_column_blob(st, 0), blk->block_id,
                               64) == 0);
            sqlite3_finalize(st);
            return same ? 1 : -1;       /* idempotent / conflicting      */
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -1;

        /* same BlockID at another height? */
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_blocks WHERE block_id = ?1", -1, &st,
                NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_blob(st, 1, blk->block_id, 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) return -1;
        if (rc != SQLITE_DONE) return -1;

        /* height continuity + prev linkage */
        uint64_t maxh = 0;
        if (sum_q(w, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
                  &maxh) != 0)
            return -1;
        uint64_t rows = 0;
        if (sum_q(w, "SELECT COUNT(*) FROM v2_blocks", &rows) != 0)
            return -1;
        if (rows == 0) return -1;       /* genesis must exist first      */
        if (blk->global_height != maxh + 1) return -1;   /* gap/behind   */

        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)maxh);
        rc = sqlite3_step(st);
        int prev_ok = (rc == SQLITE_ROW &&
                       sqlite3_column_bytes(st, 0) == 64 &&
                       memcmp(sqlite3_column_blob(st, 0),
                              blk->prev_block_id, 64) == 0);
        sqlite3_finalize(st);
        if (!prev_ok) return -1;
    }

    /* ── the registered domain working set (read-only, pre-txn) ───────
     * STRICT lifecycle preconditions: every ACTIVE domain must hold
     * exactly one persisted DomainHead and resolve exactly one runtime
     * — anything else is consensus failure, never repaired here. */
    dom_ctx_t *doms = calloc(MAX_DOMS, sizeof(*doms));
    if (!doms) return -1;
    size_t n_dom = 0;
    if (doms_load(w, doms, &n_dom, /*strict_active=*/1) != 0) {
        free(doms);
        return -1;
    }

#define RETURN_FAIL do { free(doms); return -1; } while (0)

    /* ── op classification + resource pre-scan (no mutation yet) ────── */
    uint8_t claim_nuls[MAX_OPS][64];
    /* duplicate tx_id in the block */
    for (size_t i = 0; i < blk->n_ops; i++)
        for (size_t j = i + 1; j < blk->n_ops; j++)
            if (memcmp(blk->ops[i].tx_id, blk->ops[j].tx_id, 64) == 0)
                RETURN_FAIL;

    uint64_t global_cost = 0;
    for (size_t i = 0; i < blk->n_ops; i++) {
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n == 0 || op->touched_n > DNA_TOUCHED_MAX)
            RETURN_FAIL;
        for (uint16_t t = 0; t < op->touched_n; t++) {
            if (t > 0 && op->touched[t - 1] >= op->touched[t])
                RETURN_FAIL;
            dom_ctx_t *d = dom_for(doms, n_dom, op->touched[t]);
            /* an op may touch only a REGISTERED domain with an ACTIVE,
             * locally resolvable runtime — fail-closed, never "the
             * engine knows domains 0 and 1" */
            if (!d || d->status != DNA_DOMST_ACTIVE || !d->rt)
                RETURN_FAIL;
            d->touched = 1;
            if (d->n_tx >= MAX_OPS) RETURN_FAIL;
            memcpy(d->tx_ids[d->n_tx++], op->tx_id, 64);
            /* the ONE canonical cross-domain rule: cost charged to EVERY
             * touched domain */
            uint64_t nc = (uint64_t)d->res_cost + op->verify_cost;
            if (nc > UINT32_MAX) RETURN_FAIL;
            d->res_cost = (uint32_t)nc;
        }
        if (op->verify_cost > UINT64_MAX - global_cost) RETURN_FAIL;
        global_cost += op->verify_cost;
    }

    /* global caps: MAX_TXS chain-config param + the verify budget */
    {
        uint64_t cap = nodus_chain_config_get_u64(w,
            DNAC_CFG_MAX_TXS_PER_BLOCK, blk->global_height,
            DNAC_CFG_MAX_TXS_HARD_CAP);
        if (cap == 0 || cap > DNAC_CFG_MAX_TXS_HARD_CAP)
            cap = DNAC_CFG_MAX_TXS_HARD_CAP;
        if ((uint64_t)blk->n_ops > cap) RETURN_FAIL;
        if (global_cost > NODUS_V2_GLOBAL_VERIFY_BUDGET) RETURN_FAIL;
    }

    /* per-domain quotas from the ACTIVE registry manifests (0 = the
     * global cap/budget governs — enforced just above, never
     * "unlimited") */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        if (!d->touched) continue;
        if (d->man.quota_tx_per_block != 0 &&
            d->n_tx > (uint32_t)d->man.quota_tx_per_block)
            RETURN_FAIL;
        if (d->man.quota_verify_cost != 0 &&
            d->res_cost > d->man.quota_verify_cost)
            RETURN_FAIL;
    }

    /* ── S6 claims: bounds + in-block duplicate nullifiers + touched
     * TARGET domains (pre-txn, read-only). The nullifier derives from
     * the COMMITTED manifest context, so the committed manifest is
     * loaded (read-only) here; an unknown manifest rejects exactly as
     * admit would. ─────────────────────────────────────────────────── */
    if (blk->n_claims > 0) {
        if (!blk->claims || blk->n_claims > MAX_OPS) RETURN_FAIL;
        for (size_t i = 0; i < blk->n_claims; i++) {
            const dna_claim_t *c = &blk->claims[i];
            if (dna_claim_validate(c) != 0) RETURN_FAIL;
            dna_gman_t m;
            if (nodus_witness_v2_manifest_load_by_hash(w,
                    c->manifest_hash, &m) != 0)
                RETURN_FAIL;
            if (m.dist_present != 1) RETURN_FAIL;
            dna_dist_leaf_t leaf;
            memset(&leaf, 0, sizeof(leaf));
            leaf.leaf_version = DNA_DIST_VERSION;
            leaf.source_id_len = c->source_id_len;
            memcpy(leaf.source_id, c->source_id, c->source_id_len);
            leaf.source_amount = c->source_amount;
            memcpy(leaf.dest_binding, c->dest_binding, 64);
            uint8_t leaf_hash[64];
            if (dna_dist_leaf_hash(&leaf, leaf_hash) != 0) RETURN_FAIL;
            if (dna_claim_nullifier(c->chain_id, c->manifest_hash,
                                    m.target_domain_id,
                                    m.target_asset_ref,
                                    m.target_asset_len, leaf_hash,
                                    claim_nuls[i]) != 0)
                RETURN_FAIL;
            for (size_t j = 0; j < i; j++)
                if (memcmp(claim_nuls[i], claim_nuls[j], 64) == 0) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "duplicate claim in one block — rejected");
                    RETURN_FAIL;
                }
            /* A claim IS a state transition of its COMMITTED target
             * domain — the block declares that domain touched by
             * carrying the claim. The engine never assumes a target. */
            dom_ctx_t *d = dom_for(doms, n_dom, m.target_domain_id);
            if (!d || d->status != DNA_DOMST_ACTIVE || !d->rt)
                RETURN_FAIL;
            d->touched = 1;
        }
    }

#undef RETURN_FAIL

    /* ── 1. THE transaction ─────────────────────────────────────────── */
    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) { free(doms); return -1; }
    FAIL_POINT(V2AP_FAIL_AFTER_BEGIN);

    /* 2. supply gate (pre-apply) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;

    /* 4-6. op execution in the canonical phase order */
    for (size_t i = 0; i < blk->n_ops; i++) {   /* SYSTEM-local          */
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n == 1 && op->touched[0] == DNA_DOMAIN_SYSTEM &&
            op->sql && exec_sql(w, op->sql) != 0)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_SYSTEM);
    for (size_t i = 0; i < blk->n_ops; i++) {   /* cross-domain          */
        const nodus_v2_op_t *op = &blk->ops[i];
        if (op->touched_n > 1 && op->sql && exec_sql(w, op->sql) != 0)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_CROSS);
    for (size_t di = 0; di < n_dom; di++) {     /* domain-local, id ASC  */
        dom_ctx_t *d = &doms[di];
        for (size_t i = 0; i < blk->n_ops; i++) {
            const nodus_v2_op_t *op = &blk->ops[i];
            if (op->touched_n == 1 &&
                op->touched[0] == d->domain_id &&
                d->domain_id != DNA_DOMAIN_SYSTEM &&
                op->sql && exec_sql(w, op->sql) != 0)
                goto fail;
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_DOMAIN_BATCH &&
            blk->fail_domain_batch == d->domain_id)
            goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_UTXO);

    /* 6b. S6 generic claims — routed to each claim's COMMITTED target
     * runtime inside THE txn. Sequential processing makes intra-block
     * accounting exact: a later claim's remaining-value check sees
     * every earlier decrement. */
    for (size_t i = 0; i < blk->n_claims; i++) {
        const dna_claim_t *c = &blk->claims[i];
        nodus_v2_claim_admit_t adm;
        if (nodus_witness_v2_claim_admit(w, c, blk->global_height, &adm)
            != 0)
            goto fail;
        if (memcmp(adm.nullifier, claim_nuls[i], 64) != 0) goto fail;
        uint8_t output_id[64];
        if (nodus_witness_v2_claim_output_create(w, c, &adm,
                                                 blk->global_height,
                                                 output_id) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_OUTPUT &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
        if (nodus_witness_v2_claim_spend_insert(w, c, &adm, output_id,
                                                blk->global_height) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_SPEND &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
        if (nodus_witness_v2_claim_state_update(w, adm.manifest_hash,
                                                adm.converted) != 0)
            goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_STATE &&
            blk->fail_claim_index == (uint32_t)i)
            goto fail;
    }

    /* 6c. LIFECYCLE re-scan: the block's SYSTEM/cross ops may have
     * registered domains or moved registry lifecycle states. Re-read
     * the registry and reconcile against the block-entry view:
     *   - a pre-block domain missing from the registry now: reject
     *     (a committed head must never silently drop from
     *     domains_root);
     *   - post-status ACTIVE without a head: this block IS the domain's
     *     activation block — the canonical constructor creates the ONE
     *     deterministic height-0 head (bound to the committed
     *     genesis_state_root) and it enters domains_root here;
     *   - post-status ACTIVE with a head (a PAUSED→ACTIVE resume or a
     *     domain that stayed ACTIVE): the head is CARRIED unchanged;
     *     fail closed unless the exact runtime tuple still resolves;
     *   - PAUSED / RETIRED / REGISTERED / SCHEDULED: head (if any)
     *     carried byte-unchanged, no execution was admitted (touched
     *     required block-entry ACTIVE), heights never advance;
     *   - unknown lifecycle values already failed closed in the scan.
     * Execution authority stays the BLOCK-ENTRY status: a domain
     * activated here executes nothing before its next block. */
    {
        dom_ctx_t *post = calloc(MAX_DOMS, sizeof(*post));
        size_t n_post = 0;
        if (!post) goto fail;
        if (doms_load(w, post, &n_post, /*strict_active=*/0) != 0) {
            free(post);
            goto fail;
        }
        for (size_t i = 0; i < n_post; i++) {
            dom_ctx_t *p = &post[i];
            dom_ctx_t *pre = dom_for(doms, n_dom, p->domain_id);
            if (pre) {
                p->pre_status = pre->status;
                p->touched = pre->touched;
                p->n_tx = pre->n_tx;
                memcpy(p->tx_ids, pre->tx_ids, sizeof(p->tx_ids));
                p->res_cost = pre->res_cost;
                /* RETIRED is TERMINAL: no reactivation, no other
                 * transition — fail closed. */
                if (pre->status == DNA_DOMST_RETIRED &&
                    p->status != DNA_DOMST_RETIRED) {
                    QGP_LOG_ERROR(LOG_TAG, "domain %u left RETIRED — "
                                  "terminal state, rejected",
                                  p->domain_id);
                    free(post);
                    goto fail;
                }
            } else {
                /* registered THIS block: no pre-entry, nothing could
                 * have touched it (fail-closed by the pre-scan). */
                p->pre_status = p->status;   /* non-ACTIVE by definition
                                              * of a fresh registration
                                              * path; ACTIVE handled as
                                              * activation below        */
                if (p->has_head) { free(post); goto fail; }
                if (p->status == DNA_DOMST_ACTIVE)
                    p->pre_status = DNA_DOMST_REGISTERED;
            }
            if (p->status == DNA_DOMST_ACTIVE) {
                if (!p->rt) { free(post); goto fail; }   /* incl. resume */
                if (!p->has_head) {
                    if (pre && pre->status == DNA_DOMST_ACTIVE) {
                        free(post);          /* pre-ACTIVE headless was
                                              * rejected already —
                                              * defensive fail-close    */
                        goto fail;
                    }
                    if (head_activate(w, p, blk->global_height) != 0) {
                        free(post);
                        goto fail;
                    }
                }
            }
        }
        /* every pre-block domain must still exist */
        for (size_t i = 0; i < n_dom; i++)
            if (!dom_for(post, n_post, doms[i].domain_id)) {
                free(post);
                goto fail;
            }
        free(doms);
        doms = post;
        n_dom = n_post;
    }

    /* 7. supply gate (post-stage) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;
    FAIL_POINT(V2AP_FAIL_AFTER_SUPPLY_MUT);

    /* 8. domain roots (runtime-dispatched) + untouched-domain guard.
     * Root recomputation covers the domains that were EXECUTABLE this
     * block (block-entry ACTIVE); a domain activated this block already
     * carries its canonical activation root; PAUSED/RETIRED heads are
     * carried without recomputation (no runtime execution required to
     * carry an opaque committed head). */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        d->root_known = 0;
        if (d->activated) {
            memcpy(d->root_now, d->head.domain_state_root, 64);
            d->root_known = 1;
            continue;
        }
        if (d->pre_status == DNA_DOMST_ACTIVE) {
            if (!d->rt) goto fail;      /* was executable — must verify */
            if (d->rt->state_root(d->rt, w, d->root_now) != 0) goto fail;
            d->root_known = 1;
        }
        if (d->touched && !d->root_known) goto fail;
        if (!d->touched && d->root_known && d->has_head &&
            memcmp(d->root_now, d->head.domain_state_root, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "domain %u mutated without being declared touched",
                d->domain_id);
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_DOMAIN_ROOTS);

    /* 9. DomainUpdates (touched only; a DECLARED no-op — post == pre —
     * rejects: no fake empty updates) */
    {
        size_t n_upd = 0;
        for (size_t i = 0; i < n_dom; i++) {
            dom_ctx_t *d = &doms[i];
            if (!d->touched) continue;
            if (memcmp(d->root_now, d->head.domain_state_root, 64) == 0)
                goto fail;               /* declared but changed nothing */
            memset(&d->upd, 0, sizeof(d->upd));
            d->upd.update_version = DNA_DUPD_VERSION;
            d->upd.domain_id = d->domain_id;
            d->upd.old_height = d->head.domain_height;
            d->upd.new_height = d->head.domain_height + 1;
            d->upd.global_height = blk->global_height;
            memcpy(d->upd.pre_root, d->head.domain_state_root, 64);
            memcpy(d->upd.post_root, d->root_now, 64);
            if (dna_v2_tx_batch_root(d->tx_ids, d->n_tx,
                                     d->upd.tx_batch_root) != 0)
                goto fail;
            d->upd.ruleset_version = d->man.ruleset_version;
            memcpy(d->upd.ruleset_hash, d->man.ruleset_hash, 64);
            d->upd.res_tx_count = d->n_tx;
            d->upd.res_verify_cost = d->res_cost;
            if (prev_update_hash(w, d->domain_id,
                                 d->upd.prev_update_hash) != 0)
                goto fail;
            if (dna_dupd_hash(&d->upd, d->upd_hash) != 0) goto fail;

            uint8_t enc[DNA_DUPD_ENC_LEN];
            if (dna_dupd_encode(&d->upd, enc) != 0) goto fail;
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_domain_updates (global_height, "
                    "domain_id, upd, upd_hash) VALUES (?1, ?2, ?3, ?4)",
                    -1, &st, NULL) != SQLITE_OK)
                goto fail;
            sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)d->domain_id);
            sqlite3_bind_blob(st, 3, enc, DNA_DUPD_ENC_LEN,
                              SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 4, d->upd_hash, 64, SQLITE_TRANSIENT);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) goto fail;
            n_upd++;
        }
        (void)n_upd;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_UPDATES);

    /* 10. heads */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        d->newhead = d->head;
        if (d->touched) {
            memcpy(d->newhead.domain_state_root, d->root_now, 64);
            d->newhead.domain_height = d->head.domain_height + 1;
            d->newhead.last_updated_global_height = blk->global_height;
            d->newhead.status = d->status;
            d->newhead.ruleset_version = d->man.ruleset_version;
            if (head_store(w, &d->newhead) != 0) goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_HEADS);

    /* 11. root history (touched only) */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        if (!d->touched) continue;
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_root_history (domain_id, domain_height, "
                "global_height, state_root, upd_hash, ruleset_version, "
                "ruleset_hash) VALUES (?1,?2,?3,?4,?5,?6,?7)", -1, &st,
                NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)d->domain_id);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)d->newhead.domain_height);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)blk->global_height);
        sqlite3_bind_blob(st, 4, d->newhead.domain_state_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, d->upd_hash, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)d->upd.ruleset_version);
        sqlite3_bind_blob(st, 7, d->upd.ruleset_hash, 64,
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_HISTORY);

    /* 12. transaction indices (global order = the phase order above) */
    {
        uint32_t gidx = 0;
        for (int phase = 0; phase < 3 /* sys, cross, local */; phase++) {
            for (size_t i = 0; i < blk->n_ops; i++) {
                const nodus_v2_op_t *op = &blk->ops[i];
                int is_sys = (op->touched_n == 1 &&
                              op->touched[0] == DNA_DOMAIN_SYSTEM);
                int is_cross = (op->touched_n > 1);
                int in_phase = (phase == 0 && is_sys) ||
                               (phase == 1 && is_cross) ||
                               (phase == 2 && !is_sys && !is_cross);
                if (!in_phase) continue;

                uint8_t tl[2 + 4 * DNA_TOUCHED_MAX];
                size_t tw = 0;
                if (dna_touched_encode(op->touched, op->touched_n, tl,
                                       sizeof(tl), &tw) != 0)
                    goto fail;
                uint32_t owner = (op->touched_n == 1)
                                     ? op->touched[0] : DNA_TX_OWNER_NONE;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "INSERT INTO v2_tx_index (global_height, "
                        "global_index, tx_id, owner_domain, touched, "
                        "wire_version) VALUES (?1,?2,?3,?4,?5,3)",
                        -1, &st, NULL) != SQLITE_OK)
                    goto fail;
                sqlite3_bind_int64(st, 1,
                                   (sqlite3_int64)blk->global_height);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
                sqlite3_bind_blob(st, 3, op->tx_id, 64, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)owner);
                sqlite3_bind_blob(st, 5, tl, (int)tw, SQLITE_TRANSIENT);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc != SQLITE_DONE) goto fail;   /* dup tx_id, etc.  */
                gidx++;

                /* deterministic local index per touched domain */
                for (uint16_t t = 0; t < op->touched_n; t++) {
                    dom_ctx_t *d = dom_for(doms, n_dom, op->touched[t]);
                    if (!d) goto fail;
                    uint32_t lidx = 0;
                    for (uint32_t k = 0; k < d->n_tx; k++)
                        if (memcmp(d->tx_ids[k], op->tx_id, 64) == 0) {
                            lidx = k;
                            break;
                        }
                    sqlite3_stmt *ls = NULL;
                    if (sqlite3_prepare_v2(w->db,
                            "INSERT INTO v2_tx_local_index (tx_id, "
                            "domain_id, domain_height, local_index) "
                            "VALUES (?1,?2,?3,?4)", -1, &ls, NULL)
                        != SQLITE_OK)
                        goto fail;
                    sqlite3_bind_blob(ls, 1, op->tx_id, 64,
                                      SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ls, 2,
                                       (sqlite3_int64)op->touched[t]);
                    sqlite3_bind_int64(ls, 3,
                        (sqlite3_int64)d->newhead.domain_height);
                    sqlite3_bind_int64(ls, 4, (sqlite3_int64)lidx);
                    rc = sqlite3_step(ls);
                    sqlite3_finalize(ls);
                    if (rc != SQLITE_DONE) goto fail;
                }
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_TX_INDEX);

    /* 13. block-level roots + expectation compare + metadata */
    {
        uint8_t all_ids[MAX_OPS][64];
        uint32_t n_all = 0;
        /* global order again (phase order) */
        for (int phase = 0; phase < 3; phase++)
            for (size_t i = 0; i < blk->n_ops; i++) {
                const nodus_v2_op_t *op = &blk->ops[i];
                int is_sys = (op->touched_n == 1 &&
                              op->touched[0] == DNA_DOMAIN_SYSTEM);
                int is_cross = (op->touched_n > 1);
                int in_phase = (phase == 0 && is_sys) ||
                               (phase == 1 && is_cross) ||
                               (phase == 2 && !is_sys && !is_cross);
                if (in_phase)
                    memcpy(all_ids[n_all++], op->tx_id, 64);
            }
        if (dna_v2_tx_batch_root(all_ids, n_all, blk->out_tx_root) != 0)
            goto fail;

        /* domain_updates_root over the touched updates (ASC by
         * construction — doms[] is ASC) */
        dna_domain_update_t upd_sorted[MAX_DOMS];
        size_t n_upd = 0;
        for (size_t i = 0; i < n_dom; i++)
            if (doms[i].touched)
                upd_sorted[n_upd++] = doms[i].upd;
        if (dna_v2_domain_updates_root(upd_sorted, n_upd,
                                       blk->out_dupd_root) != 0)
            goto fail;

        /* domains_root over the COMMITTED domain heads — head-driven,
         * never fixed to a count: every persisted head (any lifecycle
         * state — PAUSED and RETIRED heads stay committed unchanged,
         * a domain activated THIS block enters here). A registered but
         * never-activated domain has no head and is absent. Order is
         * ASC by construction. */
        dna_v2_domain_head_t root_heads[MAX_DOMS];
        size_t n_heads = 0;
        for (size_t i = 0; i < n_dom; i++)
            if (doms[i].has_head)
                root_heads[n_heads++] = doms[i].newhead;
        if (dna_v2_domains_root(root_heads, n_heads,
                                blk->out_domains_root) != 0)
            goto fail;
        if (dna_v2_global_root(blk->out_domains_root,
                               blk->out_global_root) != 0)
            goto fail;

        if (blk->expect_tx_root &&
            memcmp(blk->expect_tx_root, blk->out_tx_root, 64) != 0)
            goto fail;
        if (blk->expect_dupd_root &&
            memcmp(blk->expect_dupd_root, blk->out_dupd_root, 64) != 0)
            goto fail;
        if (blk->expect_domains_root &&
            memcmp(blk->expect_domains_root, blk->out_domains_root, 64)
                != 0)
            goto fail;
        if (blk->expect_global_root &&
            memcmp(blk->expect_global_root, blk->out_global_root, 64) != 0)
            goto fail;

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count, qc) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL)",
                -1, &st, NULL) != SQLITE_OK)
            goto fail;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        sqlite3_bind_blob(st, 2, blk->block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, blk->prev_block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)blk->epoch);
        sqlite3_bind_blob(st, 5, blk->out_tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, blk->out_dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, blk->out_domains_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, blk->out_global_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 9, blk->vset_hash, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)n_all);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_BLOCK_META);

    /* 14. supply gate (pre-commit) */
    if (nodus_witness_v2_supply_check(w) != 0) goto fail;
    FAIL_POINT(V2AP_FAIL_BEFORE_COMMIT);

    /* 15. COMMIT (or the simulated commit failure) */
    if (blk->fail_at == V2AP_FAIL_COMMIT) goto fail;
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        free(doms);
        return -1;
    }
    free(doms);
    if (blk->fail_at == V2AP_FAIL_AFTER_COMMIT)
        return 2;                        /* committed; pre-cache window  */
    return 0;

fail:
    (void)exec_sql(w, "ROLLBACK");
    free(doms);
    return -1;
}
