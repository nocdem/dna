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
#include "witness/nodus_witness_rt_native.h"   /* HF-4: the CheckTx OWNER
                                                * conflict key           */
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_v2_epoch.h"    /* O12 S2: the boundary  */
#include "witness/nodus_witness_v2_econ.h"     /* econ params (6f),
                                                * balance copy (genesis) */
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_cmt_store.h"   /* Nodus EVM §10: the tip block's
                                                * header time (CheckTx) */
#include "witness/nodus_witness_v2_gen.h"      /* the cometbft lane's
                                                * chain identity: the
                                                * STORED genesis document
                                                * (D-18 rev 4)           */
#include "witness/nodus_witness_committee.h"   /* capacity season: the
                                        * governing snapshot resolution */
#include "witness/nodus_witness_addr_index.h"  /* node-local address
                                        * index — out of every root     */
#include "witness/nodus_witness_emission.h"    /* HF-2: DNAC_DECIMAL_UNIT,
                                        * the voting-power unit          */
/* HF-1: nodus/nodus_chain_config.h is back (R3 W4-C delta 2 had dropped
 * it with the retired DNAC_CFG_MAX_TXS_PER_BLOCK read). Its uses here are
 * nodus_chain_config_get_u64 of DNAC_CFG_GAS_PRICE_RAW_PER_UNIT
 * (env_gas_price_check), — final pre-testnet wipe W-C — of
 * DNAC_CFG_TOKEN_CREATE_FEE_RAW (env_token_create_fee), — HF-2 — of
 * DNAC_CFG_HF2_ACTIVE (env_hf2_active) and — HF-3 — of
 * DNAC_CFG_HF3_ACTIVE (env_hf3_active). */
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"         /* NODUS_W_BASE_TX_FEE,
                                        * NODUS_W_TOKEN_CREATE_FEE       */
#ifdef NODUS_EVM_ENABLED
#include "witness/nodus_witness_rt_evm.h"  /* red-team-1 F6: the per-leg
                                        * trie batch (exec_evm_leg)      */
#endif

#include "dnac/dnac.h"                 /* DNAC_EPOCH_LENGTH (via apply.h,
                                        * kept explicit here too),
                                        * DNAC_MIN_FEE_RAW, DNAC_CFG_*  */
#include "dnac/ledger_ids.h"           /* DNA_DOMAIN_SYSTEM              */
#include "dnac/res_meter.h"            /* dna_ck_mul_u64                 */
#include "crypto/hash/qgp_sha3.h"      /* committee member fingerprints */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdarg.h>                    /* the refusal-reason formatter  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2APPLY"

/* (tokenomics-v3 P4: the file-local MAX_OPS alias of
 * NODUS_V2_APPLY_MAX_OPS lost its last use — the legacy lane's pool-batch
 * bound — and is deleted; the exported bound itself stays in the header,
 * where the Comet application's caps derive from it.) */
#define MAX_DOMS 64     /* engine bound on registered domains per DB —
                         * a resource bound, never a protocol maximum    */

/* The block-start context this engine hands out (nodus_witness_v2_env.h)
 * carries the ruleset table BY VALUE, so its array bound and this
 * engine's bound are the same number or the shared builder silently
 * truncates one caller's view of the domain set. Proven, not assumed. */
_Static_assert(NODUS_V2_BLOCK_CTX_MAX_DOMS == MAX_DOMS,
               "block-ctx domain bound drifted from the engine's MAX_DOMS");

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
         * invariants (NULL hook = no asset state declared). HF-4 (design
         * 2026-10-02-onchain-names-design.md rev 4 §1.1): GENERATION 1
         * only — nodus_runtime_builtin_table is the genesis generation;
         * a chain without a registry has never switched. */
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
    /* R3 W4 package C — HEAP, sized to the BLOCK's own `n_envs` and
     * allocated LAZILY, on this domain's first leg (the write site: the
     * Comet per-item loop). Bounded by `blk->n_envs` because a domain
     * cannot appear
     * twice in one envelope's leg list — env_wire.c:364-365 (decode) and
     * :276 (encode) both refuse a non-strictly-ascending domain_id — so
     * `n_tx` (LEGS naming this domain) can never exceed the number of
     * ENVELOPES in the block; a MAX_OPS-sized array (now up to 17 371
     * entries x 64 domains) would have been over four orders of
     * magnitude larger than this bound ever requires. NULL until first
     * touched, which is fine: `dna_v2_tx_batch_root` (domain_wire.c:545)
     * accepts (NULL, 0) by contract — a domain touched only by a claim
     * (n_tx stays 0) reads its own root over zero wire ids exactly as it
     * did when this was a fixed all-zero array. Ownership transfers
     * (never copies) across the phase-6c lifecycle re-scan — see the
     * `post`/`pre` loop below — and is freed by `doms_free`. */
    uint8_t  (*wire_ids)[64];
    uint32_t n_tx;
    uint64_t res_cost;                  /* checked accumulation of ACTUAL
                                         * consumed units (the
                                         * DomainUpdate res_verify_cost
                                         * field is u64 on the wire)     */
    int      root_known;
    uint8_t  root_now[64];
    dna_v2_domain_head_t newhead;
    dna_domain_update_t upd;
    uint8_t  upd_hash[64];
} dom_ctx_t;

/**
 * Free a `doms`/`post` array allocated by `calloc(MAX_DOMS, sizeof(*doms))`
 * — every per-domain heap sub-allocation (today: `wire_ids`) FIRST, then
 * the array itself. Always walks the FULL `MAX_DOMS` span, never just the
 * loaded count: the whole array was `calloc`'d (every unloaded entry's
 * `wire_ids` is therefore NULL, and `free(NULL)` is a no-op), so this is
 * correct at every early-exit call site regardless of how far `doms_load`
 * got before failing. NULL-safe (mirrors plain `free`). R3 W4 package C —
 * replaces the bare `free(doms)` this file used before `wire_ids` became
 * heap-owned. */
static void doms_free(dom_ctx_t *doms) {
    if (!doms) return;
    for (size_t i = 0; i < MAX_DOMS; i++) {
        free(doms[i].wire_ids);
    }
    free(doms);
}

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

    /* S7: the runtime's activation-time state initialization (if any)
     * runs BEFORE the roots are evaluated — deterministic, inside THE
     * transaction, idempotent when the genesis path already ran it.
     * Heads are still never synthesized: this initializes the
     * runtime's OWN domain state, then the ONE constructor below
     * builds the head from it. */
    if (d->rt->state_init &&
        d->rt->state_init(d->rt, (struct nodus_witness *)w,
                          global_height) != 0)
        return -1;

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

/* ── THE block-start execution context (ONE construction) ───────────── */

/*
 * Fill the frozen context from an ALREADY-LOADED domain set.
 *
 * This is THE body. The apply engine calls it with the doms[] it already
 * holds; the public nodus_witness_v2_block_ctx_build below calls it after
 * loading its own. There is deliberately no second implementation, and
 * that is the entire point of the extraction: the propose-time batch
 * check asks this exact question, and a leader whose ruleset table,
 * per-domain unit budgets or price policy differ from the engine's in any
 * detail proposes batches the engine then deterministically rejects — the
 * whole block dies and every client in it gets an error. A scratch global
 * budget alone would NOT do: it omits the per-domain quotas and the
 * SYSTEM-runtime policy, both of which decide admission.
 *
 * NOT consensus-visible: this only MOVES existing engine code. The set of
 * blocks the engine accepts is unchanged, byte for byte.
 *
 * HF-3 (design docs/plans/2026-10-01-hf3-comet-block-bounds-design.md rev
 * 3, D1/D2): `w` and `height` select the HF-3 switch — the committed
 * chain_config param 8 at the height of the block this context judges
 * (tip + 1 on every pre-commit path, the block's own height in
 * FinalizeBlock). It is resolved HERE, once per context, through the one
 * fail-closed reader env_hf3_active, and carried in ctx->hf3_active; when
 * it is 1 the global remainder and every domain slot that takes the
 * NODUS_V2_GLOBAL_UNIT_BUDGET literal (quota_verify_cost 0) are marked
 * unbounded (res_meter.h flags; §0 rules 2-3), while a non-zero quota
 * keeps its real budget (rule 4, decided: it stays a block bound). With
 * no param-8 row every field is what it was before HF-3.
 *
 * @return 0 / -1 chain-state verdict (SYSTEM unusable) / -2 node fault
 *         (including an unreadable or impossible param-8 row — read
 *         FIRST, so this node abstains before judging anything else).
 */
static int env_hf3_active(nodus_witness_t *w, uint64_t height,
                          uint8_t *on, char *reason, size_t reason_size);
static int env_evm_block_gas_limit(nodus_witness_t *w, uint64_t height,
                                   uint64_t *out, char *reason,
                                   size_t reason_size);

static int block_ctx_from_doms(nodus_witness_t *w, uint64_t height,
                               dom_ctx_t *doms, size_t n_dom,
                               nodus_witness_v2_block_ctx_t *ctx) {
    if (!w || !doms || !ctx) return -2;
    memset(ctx, 0, sizeof(*ctx));

    /* HF-3: the switch, once. A read that cannot be answered is a node
     * FAULT (the env_hf2_active discipline) — never "off". */
    {
        char why[192];

        why[0] = '\0';
        if (env_hf3_active(w, height, &ctx->hf3_active, why,
                           sizeof why) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "block context: %s", why);
            memset(ctx, 0, sizeof(*ctx));
            return -2;
        }
    }
    ctx->budget.global_unbounded = ctx->hf3_active;

    /* Contextual ruleset table: one entry per block-entry-ACTIVE,
     * runtime-backed domain, ascending by construction (doms[] is ASC).
     * A leg addressing any OTHER domain dies in the preflight seam
     * (ERR_CTX_MISSING) — the caller cannot widen this table.
     *
     * The engine-owned unit budgets are filled in the SAME walk, so the
     * two arrays can never disagree about which domains exist. Per-domain
     * budget = the committed manifest quota where non-zero (denominated
     * in units — the header's honest label), else the global constant. */
    ctx->budget.global_remaining = NODUS_V2_GLOBAL_UNIT_BUDGET;
    for (size_t i = 0; i < n_dom; i++) {
        if (doms[i].status != DNA_DOMST_ACTIVE || !doms[i].rt) continue;
        if (ctx->n_rulesets >= MAX_DOMS ||
            ctx->budget.n_domains >= DNA_METER_MAX_DOMAINS)
            return -2;                   /* engine bound — resource fault */
        ctx->rulesets[ctx->n_rulesets].domain_id = doms[i].domain_id;
        ctx->rulesets[ctx->n_rulesets].ruleset_version =
            doms[i].man.ruleset_version;
        memcpy(ctx->rulesets[ctx->n_rulesets].ruleset_hash,
               doms[i].man.ruleset_hash, DNA_ENV_RULESET_HASH_LEN);
        ctx->n_rulesets++;
        ctx->budget.dom[ctx->budget.n_domains].domain_id = doms[i].domain_id;
        ctx->budget.dom[ctx->budget.n_domains].remaining_units =
            doms[i].man.quota_verify_cost != 0
                ? (uint64_t)doms[i].man.quota_verify_cost
                : (uint64_t)NODUS_V2_GLOBAL_UNIT_BUDGET;
        /* HF-3 rule 3: the literal fallback is no bound from the HF-3
         * height (the remainder value stays and is simply not read —
         * res_meter.h); a non-zero committed quota stays one (rule 4). */
        ctx->budget.dom[ctx->budget.n_domains].unbounded =
            (ctx->hf3_active && doms[i].man.quota_verify_cost == 0) ? 1u
                                                                    : 0u;
        ctx->budget.n_domains++;
        /* Nodus EVM: the ONE ABI-2 (EVM) domain — the streamed leg and the
         * block gas sum key on it; a second would be a compiled table
         * this engine cannot meter (one streamed leg per envelope) */
        if (doms[i].rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2) {
            if (ctx->evm_active) return -2;
            ctx->evm_active = 1;
            ctx->evm_domain_id = doms[i].domain_id;
        }
    }
    /* Nodus EVM: the block gas limit at this height — read ONLY while the EVM
     * domain is ACTIVE, so a context built on any chain before the EVM
     * edge reads nothing it did not read before */
    if (ctx->evm_active) {
        char why[192];
        why[0] = '\0';
        if (env_evm_block_gas_limit(w, height, &ctx->evm_block_gas_limit,
                                    why, sizeof why) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "block context: %s", why);
            memset(ctx, 0, sizeof(*ctx));
            return -2;
        }
    }

    /* THE block metering policy: the resolved SYSTEM runtime's compiled
     * policy, verified against BOTH its seal and the descriptor-
     * committed identity digest. SYSTEM is the mandatory protocol
     * domain (genesis enforces it ACTIVE), so a block on a chain whose
     * SYSTEM is not executable is unappliable. A missing, unsealed,
     * mutated or digest-mismatched policy is a BROKEN COMPILED TABLE on
     * this node — a fault: this node must not vote, and it must
     * certainly not improvise a price table. */
    {
        dom_ctx_t *sys = dom_for(doms, n_dom, DNA_DOMAIN_SYSTEM);
        if (!sys || sys->status != DNA_DOMST_ACTIVE || !sys->rt)
            return -1;   /* chain state: SYSTEM not ACTIVE/backed        */
        uint8_t zero[DNA_DOM_HASH_LEN] = { 0 };
        uint8_t pd[64];
        if (!sys->rt->meter_policy ||
            memcmp(sys->rt->descriptor.meter_policy_digest, zero,
                   DNA_DOM_HASH_LEN) == 0 ||
            dna_meter_policy_check(sys->rt->meter_policy) != 0 ||
            dna_meter_policy_digest(sys->rt->meter_policy, pd) != 0 ||
            memcmp(pd, sys->rt->descriptor.meter_policy_digest, 64) != 0)
            return -2;
        ctx->policy = sys->rt->meter_policy;
    }

    return 0;
}

/* Contract: nodus_witness_v2_env.h. */
int nodus_witness_v2_block_ctx_build(nodus_witness_t *w, uint64_t height,
                                     nodus_witness_v2_block_ctx_t *ctx) {
    if (!w || !w->db || !ctx) return -2;
    memset(ctx, 0, sizeof(*ctx));

    /* MAX_DOMS × dom_ctx_t is multi-KB — heap, exactly as the engine's
     * own block-start load does it. */
    dom_ctx_t *doms = calloc(MAX_DOMS, sizeof(*doms));
    if (!doms) return -2;
    size_t n_dom = 0;
    /* strict_active=1 — the SAME preconditions the engine demands before
     * it will apply anything (every ACTIVE domain resolves to exactly one
     * runtime and has exactly one persisted head). A node that cannot
     * execute an ACTIVE domain has no business judging a batch against
     * it either, so an unmet precondition is a node FAULT here, never a
     * verdict about the batch. */
    int rc = (doms_load(w, doms, &n_dom, /*strict_active=*/1) != 0)
                 ? -2
                 : block_ctx_from_doms(w, height, doms, n_dom, ctx);
    doms_free(doms);
    if (rc != 0) memset(ctx, 0, sizeof(*ctx));
    return rc;
}

/* ── V2 genesis ─────────────────────────────────────────────────────────
 * tokenomics-v3 P4 (OBLIGATION atlas-dec-71525f3b): the version-2 engine
 * genesis (nodus_witness_v2_genesis / nodus_witness_v2_genesis_ex — a
 * height-0 v2_blocks row with a derived dna_bh2 genesis BlockID, schema
 * S9-S12) is DELETED with the legacy block lane that consumed it. The
 * one genesis is nodus_witness_v2_genesis_cmt, at the end of this file. */

/* ── Apply ──────────────────────────────────────────────────────────── */

/* ── WHY the engine refused: the diagnostic reason channel ────────────
 * Contract, in full, at nodus_v2_block_t.out_reason. The three rules
 * that matter while reading the code below:
 *
 *   1. NO VERDICT MOVES. Every macro here only writes characters into
 *      blk->out_reason. Not one of them returns, jumps, or evaluates a
 *      condition that a return depends on — the `goto`s and `return`s
 *      around them are exactly the ones that were there before, which is
 *      why they were deliberately left VISIBLE at every site instead of
 *      being folded into the reason macro. A reviewer can diff the set
 *      of `goto fail` / `goto fail_fault` / `return` statements and see
 *      that it is unchanged.
 *   2. THE CLASS TAG IS MECHANICAL. V2AP_VERDICT / V2AP_FAULT /
 *      V2AP_DEFER stamp the prefix; a site never types it. The macro
 *      used is paired with the exit taken, so a -2 exit cannot be
 *      labelled a verdict by a typo.
 *   3. ASCII AND BOUNDED. Format strings are engine literals. The only
 *      substitutions are integers, v2ap_hex8 output, and string literals
 *      the ENGINE picks (a ternary between two fixed phrases, or a
 *      stringified fault-point name). No block-, peer- or
 *      runtime-carried text is ever interpolated, so nothing an attacker
 *      controls reaches a log line as characters.
 */

/** Write one class-tagged refusal reason. Truncation is silent — a
 *  clipped diagnostic is strictly better than a branch on a length. */
__attribute__((format(printf, 4, 5)))
static void v2ap_reason(char *buf, size_t sz, const char *cls,
                        const char *fmt, ...) {
    if (!buf || sz == 0) return;
    int n = snprintf(buf, sz, "%s", cls);
    if (n < 0) { buf[0] = '\0'; return; }
    if ((size_t)n >= sz) return;             /* clipped at the tag alone */
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(buf + n, sz - (size_t)n, fmt, ap);
    va_end(ap);
}

/** The first 8 bytes of a 64-byte root/id as lowercase ASCII hex — just
 *  enough to tell two roots apart in a log without printing 128 chars.
 *  ASCII by construction, so interpolating it keeps the ASCII rule. */
static const char *v2ap_hex8(const uint8_t *b, char out[17]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hx[(b[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hx[b[i] & 0x0F];
    }
    out[16] = '\0';
    return out;
}

/* Inside nodus_witness_v2_apply_block, where `blk` is the writable
 * block. */
#define V2AP_VERDICT(...) \
    v2ap_reason(blk->out_reason, sizeof blk->out_reason, "VERDICT: ", \
                __VA_ARGS__)
#define V2AP_FAULT(...) \
    v2ap_reason(blk->out_reason, sizeof blk->out_reason, "FAULT: ", \
                __VA_ARGS__)
#define V2AP_DEFER(...) \
    v2ap_reason(blk->out_reason, sizeof blk->out_reason, "DEFER: ", \
                __VA_ARGS__)

/* Inside exec_one_env, where `blk` is const and the buffer arrives as
 * the (reason, reason_size) pair the caller aimed at blk->out_reason. */
#define V2AP_ENV_VERDICT(...) \
    v2ap_reason(reason, reason_size, "VERDICT: ", __VA_ARGS__)
#define V2AP_ENV_FAULT(...) \
    v2ap_reason(reason, reason_size, "FAULT: ", __VA_ARGS__)

/* Final pre-testnet wipe W-C (decision 2026-09-28-token-create-fee-
 * governance.md): the token-creation fee the CORE TOKEN_CREATE exec
 * enforces — the COMMITTED chain_config param 6 (TOKEN_CREATE_FEE_RAW)
 * active at `height`, the compiled NODUS_W_TOKEN_CREATE_FEE when no row is
 * active. The SAME read discipline as env_gas_price_check: the one
 * three-valued accessor over committed rows (cache ≡ DB), and a read that
 * cannot be answered is a node FAULT, never a default — a guessed fee
 * would let two nodes judge one TOKEN_CREATE differently. Filled into
 * every exec context the engine builds (env_authorize_legs, exec_one_env)
 * so the pure hooks never touch the database. `height` is the block being
 * applied — tip + 1 on the CheckTx dry run, which builds its block the
 * same way — so CheckTx and FinalizeBlock read the same row.
 * @return 0 (value in *out) / -2 fault (reason written). */
static int env_token_create_fee(nodus_witness_t *w, uint64_t height,
                                uint64_t *out,
                                char *reason, size_t reason_size)
{
    if (nodus_chain_config_get_u64(
            w, (uint8_t)DNAC_CFG_TOKEN_CREATE_FEE_RAW, height,
            NODUS_W_TOKEN_CREATE_FEE, out) < 0) {
        V2AP_ENV_FAULT("token-create fee: TOKEN_CREATE_FEE_RAW at height "
                       "%llu is unreadable on this node - refusing to "
                       "judge a TOKEN_CREATE against a guessed fee",
                       (unsigned long long)height);
        return -2;
    }
    return 0;
}

/* HF-2 (design docs/plans/2026-09-30-gov-weight-netzero-design.md rev 2;
 * decision 2026-09-30-governance-stake-weight-and-power-cap.md): is the
 * second height-activated hard fork ON at `height`? The COMMITTED
 * chain_config param 7 (HF2_ACTIVE) through the same three-valued
 * accessor and the same read discipline as env_token_create_fee: a read
 * that cannot be answered is a node FAULT, never a default — a guessed
 * answer would let two nodes judge one approval set, or one block, by
 * different rules. No active row = OFF (the default 0), which is what
 * keeps a chain without the vote byte-identical to the pre-HF-2 binary.
 * The only value a committed row can hold is DNAC_CFG_HF2_ACTIVE_ON (the
 * scalar rules refuse every other); any other stored value is this
 * node's storage disagreeing with every writer, so it is a FAULT too.
 * `height` is the block being applied — tip + 1 on the CheckTx dry run —
 * so CheckTx and FinalizeBlock read the same row.
 * @return 0 (*on = 0/1) / -2 fault (reason written). */
static int env_hf2_active(nodus_witness_t *w, uint64_t height,
                          uint8_t *on, char *reason, size_t reason_size)
{
    uint64_t v = 0;

    if (nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_HF2_ACTIVE, height,
                                   0ULL, &v) < 0) {
        V2AP_ENV_FAULT("HF-2: HF2_ACTIVE at height %llu is unreadable on "
                       "this node - refusing to judge under a guessed "
                       "rule set", (unsigned long long)height);
        return -2;
    }
    if (v != 0ULL && v != DNAC_CFG_HF2_ACTIVE_ON) {
        V2AP_ENV_FAULT("HF-2: HF2_ACTIVE at height %llu reads %llu, a value "
                       "no committed row can hold - this node's "
                       "chain_config storage is inconsistent",
                       (unsigned long long)height, (unsigned long long)v);
        return -2;
    }
    *on = (v == DNAC_CFG_HF2_ACTIVE_ON) ? 1u : 0u;
    return 0;
}

/* HF-3 (design docs/plans/2026-10-01-hf3-comet-block-bounds-design.md rev
 * 3; decision 2026-10-01-hf3-comet-only-block-bounds.md): is the third
 * height-activated hard fork ON at `height`? The env_hf2_active shape
 * above, statement for statement, over chain_config param 8
 * (HF3_ACTIVE): the one three-valued accessor over committed rows, an
 * unanswerable read is a node FAULT, never a default; no active row = OFF
 * (keeps a chain without the vote byte-identical to the pre-HF-3 binary);
 * a stored value other than 0/1 is this node's storage disagreeing with
 * every writer (the scalar rules admit only DNAC_CFG_HF3_ACTIVE_ON), a
 * FAULT too. ONE caller: block_ctx_from_doms, which resolves the switch
 * once per block-start context (D2) at the height that context judges.
 * @return 0 (*on = 0/1) / -2 fault (reason written). */
static int env_hf3_active(nodus_witness_t *w, uint64_t height,
                          uint8_t *on, char *reason, size_t reason_size)
{
    uint64_t v = 0;

    if (nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_HF3_ACTIVE, height,
                                   0ULL, &v) < 0) {
        V2AP_ENV_FAULT("HF-3: HF3_ACTIVE at height %llu is unreadable on "
                       "this node - refusing to judge under a guessed "
                       "rule set", (unsigned long long)height);
        return -2;
    }
    if (v != 0ULL && v != DNAC_CFG_HF3_ACTIVE_ON) {
        V2AP_ENV_FAULT("HF-3: HF3_ACTIVE at height %llu reads %llu, a value "
                       "no committed row can hold - this node's "
                       "chain_config storage is inconsistent",
                       (unsigned long long)height, (unsigned long long)v);
        return -2;
    }
    *on = (v == DNAC_CFG_HF3_ACTIVE_ON) ? 1u : 0u;
    return 0;
}

/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.2
 * rule (a)): has ANY chain_config param-9 (RULESET_GEN2) row been
 * committed — at any effective height? The one three-valued accessor at
 * current_block INT64_MAX: every committed effective_block is <=
 * INT64_MAX (the scalar rules' int64 bound), the cache path compares
 * `effective_block <= current_block` and the DB path binds the value as
 * an int64 — UINT64_MAX would bind as -1 and find nothing. An
 * unanswerable read is a node FAULT, never "no row". Read by the engine
 * (UNMETERED — not a mediated read) into ctx.ruleset_gen2_voted on every
 * ctx it builds, once per item, so a row an EARLIER item of the same
 * block wrote counts (the CHAIN_CONFIG adapter's mutate drops the lookup
 * cache, nodus_witness_rt_native.c). @return 0 (*voted = 0/1) / -2. */
static int env_ruleset_gen2_voted(nodus_witness_t *w, uint8_t *voted,
                                  char *reason, size_t reason_size)
{
    uint64_t v = 0;
    int rc = nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_RULESET_GEN2,
                                        (uint64_t)INT64_MAX, 0ULL, &v);

    if (rc < 0) {
        V2AP_ENV_FAULT("%s", "HF-4: the RULESET_GEN2 history is unreadable "
                       "on this node - refusing to judge a vote's single-"
                       "use rule against a guess");
        return -2;
    }
    *voted = (rc == 0) ? 1u : 0u;
    return 0;
}

/* Storage reward v1 (design docs/plans/2026-10-04-storage-reward-v1-
 * design.md rev 2.2 §6 — "voted like RULESET_GEN2"): has ANY chain_config
 * param-16 (RULESET_GEN_STORAGE) row been committed, at any effective
 * height? env_ruleset_gen2_voted's contract verbatim (the INT64_MAX
 * current_block, the three-valued accessor, a read fault = node FAULT,
 * UNMETERED, once per item) — into ctx.ruleset_gen_storage_voted.
 * @return 0 (*voted = 0/1) / -2. */
static int env_ruleset_gen_storage_voted(nodus_witness_t *w, uint8_t *voted,
                                         char *reason, size_t reason_size)
{
    uint64_t v = 0;
    int rc = nodus_chain_config_get_u64(w,
                                        (uint8_t)DNAC_CFG_RULESET_GEN_STORAGE,
                                        (uint64_t)INT64_MAX, 0ULL, &v);

    if (rc < 0) {
        V2AP_ENV_FAULT("%s", "storage reward: the RULESET_GEN_STORAGE "
                       "history is unreadable on this node - refusing to "
                       "judge a vote's single-use rule against a guess");
        return -2;
    }
    *voted = (rc == 0) ? 1u : 0u;
    return 0;
}

/* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §2
 * Price): the four NAME_REGISTER price tiers at `height` — chain_config
 * params 10..13 (NAME_PRICE_3P..6P), each the committed row active at
 * `height` or the compiled DNAC_NAME_PRICE_*_DEFAULT (no genesis row on
 * the testnet chain — the design's stated deviation). The
 * env_token_create_fee discipline: the one three-valued accessor, and an
 * unanswerable read is a node FAULT, never a default. A stored value
 * outside the votable range is this node's storage disagreeing with every
 * writer (the scalar rules admit only [10^8, 10^15]) — a FAULT too.
 * Filled into every exec ctx (both sites) so the pure CORE hook never
 * touches the database. @return 0 / -2 (reason written). */
static int env_name_prices(nodus_witness_t *w, uint64_t height,
                           uint64_t out[4], char *reason,
                           size_t reason_size)
{
    static const uint8_t ids[4] = {
        (uint8_t)DNAC_CFG_NAME_PRICE_3P, (uint8_t)DNAC_CFG_NAME_PRICE_4P,
        (uint8_t)DNAC_CFG_NAME_PRICE_5P, (uint8_t)DNAC_CFG_NAME_PRICE_6P };
    static const uint64_t dflt[4] = {
        DNAC_NAME_PRICE_3P_DEFAULT, DNAC_NAME_PRICE_4P_DEFAULT,
        DNAC_NAME_PRICE_5P_DEFAULT, DNAC_NAME_PRICE_6P_DEFAULT };

    for (int k = 0; k < 4; k++) {
        if (nodus_chain_config_get_u64(w, ids[k], height, dflt[k],
                                       &out[k]) < 0) {
            V2AP_ENV_FAULT("HF-4: NAME_PRICE param %u at height %llu is "
                           "unreadable on this node - refusing to judge a "
                           "registration against a guessed price",
                           (unsigned)ids[k], (unsigned long long)height);
            return -2;
        }
        if (out[k] < DNAC_CFG_MIN_NAME_PRICE ||
            out[k] > DNAC_CFG_MAX_NAME_PRICE) {
            V2AP_ENV_FAULT("HF-4: NAME_PRICE param %u at height %llu reads "
                           "%llu, a value no committed row can hold",
                           (unsigned)ids[k], (unsigned long long)height,
                           (unsigned long long)out[k]);
            return -2;
        }
    }
    return 0;
}

/* Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-design.md
 * rev 3 §8-§10): the EVM block gas limit in force at `height` — chain_config
 * param 15 (EVM_BLOCK_GAS_LIMIT), or the compiled
 * DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT when no row is active. The
 * env_token_create_fee discipline: an unreadable row, or a stored value
 * outside the votable range (no committed row can hold one), is a node
 * FAULT, never a default. @return 0 / -2 (reason written). */
static int env_evm_block_gas_limit(nodus_witness_t *w, uint64_t height,
                                   uint64_t *out, char *reason,
                                   size_t reason_size)
{
    if (nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_EVM_BLOCK_GAS_LIMIT,
                                   height, DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT,
                                   out) < 0) {
        V2AP_ENV_FAULT("Nodus EVM: EVM_BLOCK_GAS_LIMIT at height %llu is "
                       "unreadable on this node",
                       (unsigned long long)height);
        return -2;
    }
    if (*out < DNAC_CFG_MIN_EVM_BLOCK_GAS ||
        *out > DNAC_CFG_MAX_EVM_BLOCK_GAS) {
        V2AP_ENV_FAULT("Nodus EVM: EVM_BLOCK_GAS_LIMIT at height %llu reads %llu, "
                       "a value no committed row can hold",
                       (unsigned long long)height,
                       (unsigned long long)*out);
        return -2;
    }
    return 0;
}

/* Nodus EVM — the engine facts of the EVM_ACTIVE vote's stateful rules
 * (runtime.h nodus_rt_exec_ctx_t hf3_active / gas_price_on /
 * evm_active_voted) and the EVM block gas limit, filled on EVERY ctx the
 * engine builds (both sites — the HF-4 discipline: a hook never sees a
 * ctx whose engine facts are partly zero). UNMETERED: none is a mediated
 * read, so no committed block's gas_used moves. Every unreadable answer
 * is a node FAULT. "Any param-14 row" is read at INT64_MAX (the
 * env_ruleset_gen2_voted reasoning). @return 0 / -2. */
static int env_evm_facts(nodus_witness_t *w, uint64_t height,
                         nodus_rt_exec_ctx_t *ctx, char *reason,
                         size_t reason_size)
{
    uint64_t price = 0, v14 = 0;
    int      r14;

    if (env_hf3_active(w, height, &ctx->hf3_active, reason,
                       reason_size) != 0)
        return -2;
    if (nodus_witness_v2_gas_price_at(w, height, &price, reason,
                                      reason_size) != 0)
        return -2;
    ctx->gas_price_on = (price != 0) ? 1u : 0u;
    r14 = nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_EVM_ACTIVE,
                                     (uint64_t)INT64_MAX, 0ULL, &v14);
    if (r14 < 0) {
        V2AP_ENV_FAULT("%s", "Nodus EVM: the EVM_ACTIVE history is unreadable on "
                       "this node - refusing to judge a vote's single-use "
                       "rule against a guess");
        return -2;
    }
    ctx->evm_active_voted = (r14 == 0) ? 1u : 0u;
    /* red-team 1 F5: the chain's first height — the once-per-open cache
     * (nodus_witness.h v2_initial_height) on every gate-accepted handle,
     * so no per-item document read there; the same function derives it
     * from the document on a handle without the cache. Unreadable = FAULT
     * like every fact here. */
    if (nodus_witness_v2_chain_initial_height(w,
                                              &ctx->chain_initial_height)
            != 0) {
        V2AP_ENV_FAULT("%s", "Nodus EVM: the chain's initial height is "
                       "underivable on this node");
        return -2;
    }
    return env_evm_block_gas_limit(w, height, &ctx->evm_block_gas_limit,
                                   reason, reason_size);
}

/* Nodus EVM — contract: nodus_witness_v2_apply.h (the one read above). */
int nodus_witness_v2_evm_block_gas_limit(nodus_witness_t *w, uint64_t height,
                                         uint64_t *out,
                                         char *reason, size_t reason_size)
{
    if (!w || !out) return -2;
    return env_evm_block_gas_limit(w, height, out, reason, reason_size);
}

/* Red-team 1 F5 — contract: nodus_witness_v2_apply.h. The stored
 * genesis DOCUMENT is the one source (never the node's oldest row): its
 * initial_height as written, completed 0 → 1 the way the reference
 * completes a document (types/genesis.go:79-81) — the height the chain's
 * first block carries (nodus_witness_v2_gen.h initial_height). */
int nodus_witness_v2_chain_initial_height(nodus_witness_t *w, uint64_t *out)
{
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs = NULL;
    uint64_t               ih;
    int                    rc;

    if (!w || !w->db || !out) return -2;
    *out = 0;
    /* the once-per-open cache (nodus_witness.h v2_initial_height): filled
     * by the post-open gate through THIS function from the same document,
     * so a hit answers what the derivation below would (cache symmetry) */
    if (w->v2_chain32_valid && w->v2_initial_height != 0) {
        *out = w->v2_initial_height;
        return 0;
    }
    cfg = calloc(1, sizeof(*cfg));                         /* ~240 KB    */
    if (!cfg) return -2;
    rc = nodus_witness_v2_gen_stored_doc(w, cfg, &allocs);
    ih = cfg->initial_height;
    free(allocs);
    free(cfg);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "Nodus EVM: the stored genesis document does "
                      "not read back - the chain's initial height is "
                      "underivable on this node");
        return -2;
    }
    *out = ih == 0 ? 1u : ih;
    return 0;
}

/* Contract: nodus_witness_v2_apply.h. */
int nodus_witness_v2_tip_block_time(nodus_witness_t *w, uint64_t tip,
                                    uint64_t *out_secs)
{
    if (!w || !w->db || !out_secs || tip == 0 ||
        tip > (uint64_t)INT64_MAX)
        return -1;
    nodus_cmt_store_t      s;
    nodus_cmt_block_meta_t *meta = calloc(1, sizeof(*meta));
    bool                   found = false;
    int                    ret = -1;
    if (!meta) return -1;
    if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) {
        free(meta);
        return -1;
    }
    if (nodus_cmt_bs_load_block_meta(&s, (int64_t)tip, meta, &found) ==
            CMT_OK &&
        found && meta->header.height == (int64_t)tip &&
        meta->header.time.seconds >= 0) {
        *out_secs = (uint64_t)meta->header.time.seconds;
        ret = 0;
    }
    nodus_cmt_store_release(&s);
    free(meta);
    return ret;
}

/* A fault-injection point firing is a TEST harness event, not a real
 * defect — it says so in its own words rather than borrowing the words
 * of the check it stands in for. */
#define FAIL_POINT(pt)                                                  \
    do {                                                                \
        if (blk->fail_at == (pt)) {                                     \
            V2AP_VERDICT("fault-injection point %s fired (test "        \
                         "harness; no real check failed)", #pt);        \
            goto fail;                                                  \
        }                                                               \
    } while (0)

/* (tokenomics-v3 P4: the S7 pool-stage mapping — pool_fault_ctx_t /
 * pool_stage_fault, fault points 19-25 on `fail_pool_index` — is
 * deleted with the legacy lane's phase 6p, its only caller.) */

/* O12 S2: the same mapping for the epoch-boundary module's stages. The
 * per-graduate stages fire on candidate index 0 only — see the F40/F41
 * note on the fault enum (nodus_witness_v2_apply.h). */
static int epoch_stage_fault(void *ud, nodus_v2_epoch_stage_t s,
                             uint32_t graduate_index) {
    const nodus_v2_block_t *blk = (const nodus_v2_block_t *)ud;
    switch (s) {
        case NODUS_V2_EPST_COMMISSIONS:
            return blk->fail_at == V2AP_FAIL_AFTER_EPOCH_COMMISSIONS;
        case NODUS_V2_EPST_GRAD_RELEASE:
            return graduate_index == 0 &&
                   blk->fail_at == V2AP_FAIL_AFTER_FIRST_GRAD_RELEASE;
        case NODUS_V2_EPST_GRAD_APPLIED:
            return graduate_index == 0 &&
                   blk->fail_at == V2AP_FAIL_AFTER_FIRST_GRAD_APPLIED;
        case NODUS_V2_EPST_GRAD_BATCH:
            return blk->fail_at == V2AP_FAIL_AFTER_GRAD_BATCH;
        case NODUS_V2_EPST_BOUNDARY_FLIPS:
            return blk->fail_at == V2AP_FAIL_AFTER_BOUNDARY_FLIPS;
        case NODUS_V2_EPST_SNAPSHOT_BUILD:
            return blk->fail_at == V2AP_FAIL_AFTER_SNAPSHOT_BUILD;
        case NODUS_V2_EPST_SNAPSHOT_PERSIST:
            return blk->fail_at == V2AP_FAIL_AFTER_SNAPSHOT_PERSIST;
        case NODUS_V2_EPST_RULE_N:
            /* O15C — no dedicated injection point: the Rule N rows ride
             * the same ONE transaction, and the surrounding stages
             * (SETTLE_APPLIED before, BOUNDARY_FLIPS after) already
             * prove the rollback bracket for this region. */
            return 0;
        /* NODUS_V2_EPST_SETTLE_EMITTED / _APPLIED (9, 10) are RETIRED by
         * tokenomics-v3 P2 with the burning settlement; the module never
         * fires them, and an unexpected one lands in `default` (fail
         * closed). Their engine ids F50/F51 are retired with them. */
        case NODUS_V2_EPST_ATTENDANCE_DIGEST:
            return blk->fail_at == V2AP_FAIL_AFTER_ATTENDANCE_DIGEST;
        case NODUS_V2_EPST_ATTENDANCE_RESET:
            return blk->fail_at == V2AP_FAIL_AFTER_ATTENDANCE_RESET;
        /* tokenomics-v3 P2 — the reward stages, mapped BY NAME onto the
         * appended engine ids F55-F59. */
        case NODUS_V2_EPST_DIST_ACCRUED:
            return blk->fail_at == V2AP_FAIL_AFTER_DIST_ACCRUED;
        case NODUS_V2_EPST_DIST_APPLIED:
            return blk->fail_at == V2AP_FAIL_AFTER_DIST_APPLIED;
        case NODUS_V2_EPST_PAYDAY_EMITTED:
            return blk->fail_at == V2AP_FAIL_AFTER_PAYDAY_EMITTED;
        case NODUS_V2_EPST_PAYDAY_APPLIED:
            return blk->fail_at == V2AP_FAIL_AFTER_PAYDAY_APPLIED;
        case NODUS_V2_EPST_BALANCE_COPY:
            return blk->fail_at == V2AP_FAIL_AFTER_BALANCE_COPY;
        /* tokenomics-v3 P3-4 — the graduation's delegation release,
         * mapped BY NAME onto the appended engine id F60; first graduate
         * only, the F40/F41 convention. */
        case NODUS_V2_EPST_GRAD_DELEG_RELEASED:
            return graduate_index == 0 &&
                   blk->fail_at == V2AP_FAIL_AFTER_FIRST_GRAD_DELEG_RELEASE;
        default:
            return 1;                    /* unknown stage: fail closed   */
    }
}

/* ── The typed execution pipeline (contract: nodus_witness_v2_apply.h) ─
 *
 * FAULT vs VERDICT: every failure in this half of the file exits through
 * exactly one of two labels — `fail` (consensus VERDICT, rc -1) or
 * `fail_fault` (node-local FAULT, rc -2). Both roll the ONE transaction
 * back and abort every non-terminal meter; they differ only in what the
 * caller may conclude. Classification rule: a deterministic function of
 * (committed state, block bytes) is a verdict; storage/hash/alloc/
 * compiled-table failures are faults. HONEST LABEL: the S6 claim and S7
 * pool subpaths and the supply gate keep their pre-season conflated -1
 * helpers — inside them a database fault and a semantic rejection are
 * not yet distinguishable, so their failures conservatively exit
 * through `fail` exactly as before this season; precise classification
 * there is that surface's own migration. */

int nodus_witness_v2_local_index_find(const uint8_t ids[][64], uint32_t n,
                                      const uint8_t wire_id[64],
                                      uint32_t *lidx_out) {
    if (!ids || !wire_id || !lidx_out) return -1;
    for (uint32_t k = 0; k < n; k++)
        if (memcmp(ids[k], wire_id, 64) == 0) {
            *lidx_out = k;
            return 0;
        }
    return -1;   /* a MISS FAILS CLOSED — it never aliases index 0 */
}

/** Abort every meter still holding a reservation (RESERVED or ACTIVE).
 *  FINALIZED/ABORTED/ZERO meters are left alone — double release is a
 *  lifecycle violation, not cleanup. */
static void meters_abort_all(dna_meter_t *m, size_t n) {
    if (!m) return;
    for (size_t i = 0; i < n; i++)
        if (m[i].state == DNA_METER_ST_RESERVED ||
            m[i].state == DNA_METER_ST_ACTIVE)
            (void)dna_meter_abort(&m[i]);
}

/** Does the domain's COMMITTED ruleset own this runtime_op? The rule-id
 *  list of the checked-in descriptor is the ownership authority — the
 *  same list the ruleset_hash commits, so ownership can never drift
 *  from the identity every validator matched. Ascending list, early
 *  stop (the rt_owns_type shape). */
static int rt_owns_runtime_op(const nodus_domain_runtime_t *rt,
                              uint32_t runtime_op) {
    const dna_ruleset_desc_t *d = &rt->descriptor;
    for (size_t i = 0; i < d->rule_count; i++) {
        if (d->rule_ids[i] == runtime_op) return 1;
        if (d->rule_ids[i] > runtime_op) break;
    }
    return 0;
}

/** Nodus EVM (design §3): can this runtime execute envelope legs at all? An
 *  ABI-1 runtime needs its exec hook, an ABI-2 runtime its exec_evm hook;
 *  any other ABI executes nothing (fail-closed). For every ABI-1 runtime
 *  this is exactly the `rt->exec != NULL` test it replaces. */
static int rt_can_execute(const nodus_domain_runtime_t *rt) {
    if (rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V1)
        return rt->exec != NULL;
    if (rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2)
        return rt->exec_evm != NULL;
    return 0;
}

/** Nodus EVM: the streamed leg of an envelope for dna_meter_reserve_ex — 0
 *  when no leg's runtime is ABI 2 (every envelope on every chain today:
 *  no compiled production table carries an ABI-2 entry), else 1 + the
 *  index of the FIRST such leg (env_admit_legs refuses a second one). A
 *  leg whose domain has no resolvable runtime is not streamed; admission
 *  refuses it anyway. */
static uint16_t env_stream_leg(const dna_env_view_t *v, dom_ctx_t *doms,
                               size_t n_dom) {
    /* (Nodus EVM activation: the block context's evm_active / evm_domain_id
     * — nodus_witness_v2_ctx_stream_leg, the seam's and the pack's — are
     * built from the SAME doms walk, so both derive the same index.) */
    for (uint16_t l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        if (d && d->rt && d->rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2)
            return (uint16_t)(l + 1u);
    }
    return 0;
}

/** Canonical mediated-read request order: op_id ascending, then key
 *  bytes lexicographic (memcmp over the common prefix; shorter first;
 *  full equality = duplicate). Mirrors the effect-wire record order so
 *  ONE ordering discipline governs both request and result spaces.
 *  @return <0 / 0 (equal = duplicate) / >0. */
static int read_req_cmp(const nodus_rt_read_req_t *a,
                        const nodus_rt_read_req_t *b) {
    if (a->op_id != b->op_id) return a->op_id < b->op_id ? -1 : 1;
    uint16_t min = a->key_len < b->key_len ? a->key_len : b->key_len;
    int c = memcmp(a->key, b->key, min);
    if (c != 0) return c;
    if (a->key_len != b->key_len) return a->key_len < b->key_len ? -1 : 1;
    return 0;
}

/**
 * CHECKTX-P1 — the adapter's DECISION without its MUTATION: the generic
 * driver `nodus_witness_v2_effects_apply_ex` (nodus_witness_v2_adapter.c)
 * step for step — validate, then per effect op lookup → probe → the ONE
 * shipped precondition table (`nodus_adapter_precond_eval`) — stopping
 * short of `ad->mutate` and of the test-only stop index. The probe
 * coercion is the driver's: any probe answer other than OK is a
 * node-local STORAGE fault, so a precondition status can only come from
 * the shipped table. Used ONLY by the dry run; the apply path still calls
 * the driver itself.
 */
static nodus_adapter_status_t effects_probe_only(
        nodus_witness_t *w, const nodus_domain_runtime_t *rt,
        const dna_effect_view_t *ev, uint16_t *fail_index_out) {
    if (fail_index_out) *fail_index_out = 0;
    if (!w) return NODUS_ADAPTER_ERR_ARG;
    nodus_adapter_status_t st =
        nodus_witness_v2_effects_validate(rt, ev, fail_index_out);
    if (st != NODUS_ADAPTER_OK) return st;

    const nodus_domain_adapter_t *ad = rt->adapter;
    for (uint16_t i = 0; i < ev->effect_count; i++) {
        const dna_effect_hdr_t *h = &ev->eff[i];
        const nodus_adapter_op_t *op = nodus_adapter_op_lookup(ad, h->op_id);
        if (!op) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_UNKNOWN_OP;
        }
        nodus_adapter_row_facts_t facts;
        memset(&facts, 0, sizeof(facts));
        st = ad->probe(ad, w, rt->domain_id, op, ev->buf + ev->key_off[i],
                       h->key_len, &facts);
        if (st != NODUS_ADAPTER_OK) {
            if (fail_index_out) *fail_index_out = i;
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        }
        st = nodus_adapter_precond_eval(h->effect_kind, h->precond_tag,
                                        h->expected_version,
                                        h->expected_vhash, &facts);
        if (st != NODUS_ADAPTER_OK) {
            if (fail_index_out) *fail_index_out = i;
            return st;
        }
    }
    return NODUS_ADAPTER_OK;
}

/** CHECKTX-P1 — is this effect a ROW-IDENTITY claim (the apply.h
 *  `nodus_v2_dry_run_row_t` rule)? A DELETE (any precondition) or a
 *  PRE_ABSENT CREATE. Round 3: PRE_EXISTS_VHASH SETs are NOT claims —
 *  in a block each item re-reads the row after the earlier items'
 *  effects and derives its expected hash from that fresh read, so two
 *  such SETs of one row both apply. */
static int dry_run_row_claim(const dna_effect_hdr_t *h) {
    return h->effect_kind == DNA_EFFECT_DELETE ||
           h->precond_tag == DNA_EFFECT_PRE_ABSENT;
}

/** CHECKTX-P1 — append every row-identity effect of one decoded leg
 *  result to the dry run's row list (heap, grown per leg).
 *  @return 0 / -1 alloc. */
static int dry_run_note_rows(nodus_v2_env_dry_run_t *dry,
                             uint32_t domain_id,
                             const dna_effect_view_t *ev) {
    size_t add = 0;
    for (uint16_t i = 0; i < ev->effect_count; i++)
        if (dry_run_row_claim(&ev->eff[i])) add++;
    if (add == 0) return 0;
    nodus_v2_dry_run_row_t *grown =
        realloc(dry->rows, (dry->n_rows + add) * sizeof(*grown));
    if (!grown) return -1;
    dry->rows = grown;
    for (uint16_t i = 0; i < ev->effect_count; i++) {
        const dna_effect_hdr_t *h = &ev->eff[i];
        nodus_v2_dry_run_row_t *r;
        if (!dry_run_row_claim(h)) continue;
        if (h->key_len > DNA_EFFECT_MAX_KEY_LEN) return -1;  /* codec cap */
        r = &dry->rows[dry->n_rows++];
        memset(r, 0, sizeof(*r));
        r->domain_id = domain_id;
        r->op_id     = h->op_id;
        r->key_len   = h->key_len;
        memcpy(r->key, ev->buf + ev->key_off[i], h->key_len);
    }
    return 0;
}

/* ══ Nodus EVM: THE RUNTIME-ABI-2 LEG (design docs/plans/2026-10-04-nodus-evm-chain-
 * integration-design.md rev 3 §3, §4, §7) ══════════════════════════════
 *
 * An ABI-2 runtime reads committed state WHILE it executes, through the
 * engine-owned reader below, and hands back one canonical effect stream
 * (or, on a failed execution, its fixed failure effects). Everything here
 * is engine code: the runtime never sees this witness, the database or
 * the meter. Nothing here runs on a chain without an ABI-2 runtime — the
 * only caller is exec_one_env's ABI-2 branch, reached only for a leg whose
 * resolved runtime has runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2, and no
 * compiled production table carries one in this release. */

static int cmt_savepoint_release(nodus_witness_t *w, const char *name);

/** One cached logical read: (op, key) → the answer, for the life of ONE
 *  leg (design §3 I11: the overlay — and so this cache — is fresh per
 *  leg; nothing survives into the next leg, item or block). */
typedef struct {
    uint32_t op;
    uint16_t key_len;
    uint8_t  key[DNA_EFFECT_MAX_KEY_LEN];
    uint8_t  present;
    uint32_t value_len;
    uint8_t *value;                     /* heap, value_len bytes          */
} v2rd_entry_t;

/** The engine side of nodus_rt_v2_reader_t. */
typedef struct {
    nodus_witness_t              *w;
    const nodus_domain_runtime_t *rt;
    dna_meter_t                  *m;
    uint32_t                      domain_id;
    uint64_t                      global_height;
    int                           vm_leg;           /* 0 only for an EVM
                                                     * bridge op (no VM, no
                                                     * paid failure path);
                                                     * set from the leg's
                                                     * domain + runtime_op
                                                     * when the reader is
                                                     * created           */
    int                           gas_declared;
    uint64_t                      gas_limit;        /* declared          */
    uint64_t                      max_reads;        /* logical-read cap  */
    uint64_t                      n_reads;          /* charged reads     */
    uint64_t                      read_bytes;
    v2rd_entry_t                **ents;             /* sorted (op, key)  */
    size_t                        n_ents, cap_ents;
} v2rd_ctx_t;

static void v2rd_free(v2rd_ctx_t *c) {
    for (size_t i = 0; i < c->n_ents; i++) {
        free(c->ents[i]->value);
        free(c->ents[i]);
    }
    free(c->ents);
    c->ents = NULL;
    c->n_ents = c->cap_ents = 0;
}

/** (op, key) order — op first, then key bytes, shorter first (the
 *  mediated-read request order, read_req_cmp). */
static int v2rd_cmp(uint32_t op_a, const uint8_t *ka, uint16_t la,
                    uint32_t op_b, const uint8_t *kb, uint16_t lb) {
    if (op_a != op_b) return op_a < op_b ? -1 : 1;
    uint16_t mn = la < lb ? la : lb;
    int c = mn ? memcmp(ka, kb, mn) : 0;
    if (c != 0) return c;
    if (la != lb) return la < lb ? -1 : 1;
    return 0;
}

/** Binary search: *pos = the entry's index (return 1) or its insertion
 *  point (return 0). Lookup only — what is cached never changes WHAT is
 *  charged (design §3: one charge per logical key per leg). */
static int v2rd_find(const v2rd_ctx_t *c, uint32_t op, const uint8_t *key,
                     uint16_t key_len, size_t *pos) {
    size_t lo = 0, hi = c->n_ents;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const v2rd_entry_t *e = c->ents[mid];
        int r = v2rd_cmp(e->op, e->key, e->key_len, op, key, key_len);
        if (r == 0) { *pos = mid; return 1; }
        if (r < 0) lo = mid + 1; else hi = mid;
    }
    *pos = lo;
    return 0;
}

/** BLOCKHASH(n) for the block at `height` (design §3, §10): window
 *  [H-256, H-1]; outside it present = 0; a window height whose v2_blocks
 *  row is missing (or malformed) is a node FAULT — the reference always
 *  holds those 256 hashes. @return 0 / -2. */
static int v2rd_blockhash(nodus_witness_t *w, uint64_t height, uint64_t n,
                          nodus_rt_read_res_t *res) {
    memset(res, 0, sizeof(*res));
    if (n >= height || height - n > 256) return 0;       /* outside      */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)n);
    int rc = sqlite3_step(st);
    int ret = -2;
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) >= 32 &&
        sqlite3_column_blob(st, 0)) {
        memcpy(res->value, sqlite3_column_blob(st, 0), 32);
        res->present = 1;
        res->value_len = 32;
        ret = 0;
    } else if (rc == SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "Nodus EVM BLOCKHASH: height %llu is inside the "
                      "256-block window of %llu but has no v2_blocks row",
                      (unsigned long long)n, (unsigned long long)height);
    }
    sqlite3_finalize(st);
    return ret;
}

/* Nodus EVM — contract: nodus_witness_v2_apply.h (the §18 RPC simulation's
 * BLOCKHASH: the SAME window and FAULT rule as the engine's reader). */
int nodus_witness_v2_evm_blockhash(nodus_witness_t *w, uint64_t height,
                                   uint64_t n, nodus_rt_read_res_t *res) {
    if (!w || !w->db || !res) return -2;
    return v2rd_blockhash(w, height, n, res);
}

/* nodus_rt_v2_reader_t.read — contract: nodus_witness_runtime.h. */
static int v2rd_read(void *ctxp, uint32_t op, const uint8_t *key,
                     uint16_t key_len, nodus_rt_read_res_t *res) {
    v2rd_ctx_t *c = (v2rd_ctx_t *)ctxp;
    if (!c || !key || !res || key_len < 1 ||
        key_len > DNA_EFFECT_MAX_KEY_LEN)
        return -2;                       /* a compiled runtime's misuse  */
    memset(res, 0, sizeof(*res));

    size_t pos = 0;
    if (v2rd_find(c, op, key, key_len, &pos)) {
        const v2rd_entry_t *e = c->ents[pos];   /* repeat: free (§3 I2) */
        res->present = e->present;
        res->value_len = e->value_len;
        if (e->value_len) memcpy(res->value, e->value, e->value_len);
        return 0;
    }

    /* ── a NEW logical read: the caps, then the charge, THEN the read ─ */
    if (c->n_reads + 1 > c->max_reads) return NODUS_RT_V2_READ_BUDGET;
    if (c->vm_leg) {
        /* A VM leg (CALL / CREATE) keeps FAIL_RESERVE and the declared gas
         * units free: a read may never eat the units the failure path and
         * the gas charge need (design §4 — the failure path can never run
         * out; §8 "CALL/CREATE kabulü: res_max_total_units ≥ statik +
         * gas_limit × w_gas + FAIL_RESERVE"). A bridge op (DEPOSIT /
         * WITHDRAW / REDEEM) reserves nothing beyond the read itself: it
         * runs no code, has no paid failure path and declares no gas —
         * its failure is a refusal of the whole item (§4 "Köprü op'ları
         * (3-5) kod yürütmez: hepsi ön doğrulamadır; başarısızlık → -1"),
         * and its ceiling is the one the shared builder prices
         * (client/nodus_v2_evm.c nodus_v2_evm_min_units: static + reads ×
         * w_read). The meter charge below bounds its reads by the ceiling
         * either way. */
        uint64_t gas_units = 0, need = 0, room = 0;
        if (dna_ck_mul_u64(c->gas_limit, DNA_METER_EVM_W_GAS,
                           &gas_units) != 0 ||
            dna_ck_add_u64(c->m->plan.w_read, DNA_METER_EVM_FAIL_RESERVE,
                           &need) != 0 ||
            dna_ck_add_u64(need, gas_units, &need) != 0 ||
            dna_ck_sub_u64(c->m->g_reserved, c->m->g_consumed, &room) != 0)
            return NODUS_RT_V2_READ_BUDGET;
        if (need > room) return NODUS_RT_V2_READ_BUDGET;
    }
    dna_meter_status_t ms = dna_meter_charge_read(c->m, c->domain_id);
    if (ms == DNA_METER_ERR_FAULT) return -2;
    if (ms != DNA_METER_OK) return NODUS_RT_V2_READ_BUDGET;
    c->n_reads++;

    if (op == NODUS_RT_V2_OP_BLOCKHASH) {
        uint64_t n = 0;
        if (key_len != 8) return -2;
        for (int i = 0; i < 8; i++) n = (n << 8) | key[i];
        if (v2rd_blockhash(c->w, c->global_height, n, res) != 0) return -2;
    } else {
        nodus_rt_read_req_t req;
        memset(&req, 0, sizeof(req));
        req.op_id = op;
        req.key_len = key_len;
        memcpy(req.key, key, key_len);
        nodus_adapter_status_t ast =
            nodus_witness_v2_read_one(c->w, c->rt, &req, res);
        /* every non-OK answer is this node or a compiled runtime asking
         * for a key its own adapter cannot shape — never a verdict */
        if (ast != NODUS_ADAPTER_OK) return -2;
    }

    if (dna_ck_add_u64(c->read_bytes, res->value_len, &c->read_bytes) != 0 ||
        c->read_bytes > NODUS_RT_EVM_MAX_READ_BYTES)
        return NODUS_RT_V2_READ_BUDGET;

    /* cache it — the next request for (op, key) in this leg is free */
    if (c->n_ents == c->cap_ents) {
        size_t nc = c->cap_ents ? c->cap_ents * 2 : 64;
        v2rd_entry_t **g = realloc(c->ents, nc * sizeof(*g));
        if (!g) return -2;
        c->ents = g;
        c->cap_ents = nc;
    }
    v2rd_entry_t *e = calloc(1, sizeof(*e));
    if (!e) return -2;
    e->op = op;
    e->key_len = key_len;
    memcpy(e->key, key, key_len);
    e->present = res->present;
    e->value_len = res->value_len;
    if (res->value_len) {
        e->value = malloc(res->value_len);
        if (!e->value) { free(e); return -2; }
        memcpy(e->value, res->value, res->value_len);
    }
    memmove(&c->ents[pos + 1], &c->ents[pos],
            (c->n_ents - pos) * sizeof(*c->ents));
    c->ents[pos] = e;
    c->n_ents++;
    return 0;
}

/* nodus_rt_v2_reader_t.declare_gas — contract: nodus_witness_runtime.h. */
static int v2rd_declare_gas(void *ctxp, uint64_t gas_limit,
                            uint64_t n_access_keys) {
    v2rd_ctx_t *c = (v2rd_ctx_t *)ctxp;
    if (!c || c->gas_declared) return -2;   /* once per leg              */
    if (gas_limit > NODUS_RT_EVM_TX_GAS_CAP) return -1;
    /* design §8: res_max_total_units >= static + gas_limit × w_gas +
     * FAIL_RESERVE — the declared ceiling prices the gas */
    uint64_t gas_units = 0, need = 0;
    if (dna_ck_mul_u64(gas_limit, DNA_METER_EVM_W_GAS, &gas_units) != 0 ||
        dna_ck_add_u64(c->m->plan.static_total, gas_units, &need) != 0 ||
        dna_ck_add_u64(need, DNA_METER_EVM_FAIL_RESERVE, &need) != 0)
        return -1;
    if (need > c->m->plan.total_ceiling) return -1;
    /* the leg's declared effect ceilings must admit the fixed failure
     * result — a failed execution is always APPLIED and paid (design §4,
     * S1), so a declaration that could not carry it is refused here,
     * before anything executes */
    {
        int li = -1;
        for (uint16_t i = 0; i < c->m->plan.n_legs; i++)
            if (c->m->plan.leg[i].domain_id == c->domain_id) li = (int)i;
        if (li < 0) return -2;
        if (c->m->plan.leg[li].res_max_effects < DNA_METER_EVM_FAIL_EFFECTS ||
            c->m->plan.leg[li].res_max_effect_bytes < DNA_METER_EVM_FAIL_BYTES)
            return -1;
    }
    /* design §3 EVM_MAX_READS = ceil(cap / 2100) + 2 × keys + 2048 */
    uint64_t kk = 0, mr = 0;
    if (dna_ck_mul_u64(n_access_keys, 2, &kk) != 0 ||
        dna_ck_add_u64(NODUS_RT_EVM_READS_BASE, kk, &mr) != 0)
        return -1;
    c->gas_limit = gas_limit;
    c->max_reads = mr;
    c->gas_declared = 1;
    return 0;
}

/** The canonical length of ONE effect inside a result (record + blobs). */
static uint64_t v2evm_eff_len(const dna_effect_in_t *e) {
    return (uint64_t)DNA_EFFECT_RECORD_LEN + e->hdr.key_len +
           e->hdr.value_len;
}

/** The effect codec's total order (effect_wire.c eff_order_cmp): kind,
 *  then op, then key bytes (shorter first). */
static int v2evm_eff_cmp(const dna_effect_in_t *a, const dna_effect_in_t *b) {
    if (a->hdr.effect_kind != b->hdr.effect_kind)
        return a->hdr.effect_kind < b->hdr.effect_kind ? -1 : 1;
    return v2rd_cmp(a->hdr.op_id, a->key, a->hdr.key_len,
                    b->hdr.op_id, b->key, b->hdr.key_len);
}

/** qsort comparator over effect POINTERS by LOGICAL key (op, key) — the
 *  stream-wide uniqueness check sorts a pointer copy; the stream itself is
 *  never reordered. Keys are compared fully, so equal elements are true
 *  duplicates and the comparator is a total order. */
static int v2evm_logical_cmp(const void *pa, const void *pb) {
    const dna_effect_in_t *a = *(const dna_effect_in_t *const *)pa;
    const dna_effect_in_t *b = *(const dna_effect_in_t *const *)pb;
    return v2rd_cmp(a->hdr.op_id, a->key, a->hdr.key_len,
                    b->hdr.op_id, b->key, b->hdr.key_len);
}

/**
 * The stream the runtime handed back must be ONE canonical result cut in
 * pages: every effect inside the codec's per-effect caps, strictly
 * ascending under the codec's order across the WHOLE stream, every
 * logical key once. The runtime promises it; the engine checks it, and a
 * broken promise is a compiled-runtime defect on this node — a FAULT.
 * Also returns the stream's one-result canonical length.
 * @return 0 / -1 (broken).
 */
static int v2evm_stream_check(const dna_effect_in_t *e, uint32_t n,
                              uint64_t *bytes_out) {
    uint64_t bytes = DNA_EFFECT_FIXED_HEAD;
    for (uint32_t k = 0; k < n; k++) {
        if (e[k].hdr.key_len < 1 ||
            e[k].hdr.key_len > DNA_EFFECT_MAX_KEY_LEN ||
            e[k].hdr.value_len > DNA_EFFECT_MAX_VALUE_LEN ||
            !e[k].key || (e[k].hdr.value_len && !e[k].value))
            return -1;
        if (k > 0 && v2evm_eff_cmp(&e[k - 1], &e[k]) >= 0) return -1;
        bytes += v2evm_eff_len(&e[k]);   /* ≤ 2^32 × ~8.4 KB: no wrap   */
    }
    if (n > 1) {
        const dna_effect_in_t **p = malloc((size_t)n * sizeof(*p));
        if (!p) return -1;
        for (uint32_t k = 0; k < n; k++) p[k] = &e[k];
        qsort(p, n, sizeof(*p), v2evm_logical_cmp);
        int dup = 0;
        for (uint32_t k = 1; k < n && !dup; k++)
            if (v2evm_logical_cmp(&p[k - 1], &p[k]) == 0) dup = 1;
        free(p);
        if (dup) return -1;
    }
    *bytes_out = bytes;
    return 0;
}

/**
 * Apply effects [from, from + cnt) as ONE page: encode, strictly decode,
 * hand the page to the open stream (if any), then the adapter. Every
 * failure is a FAULT: the runtime's own output that its own adapter
 * refuses after the charge cannot happen on a healthy node (design §4,
 * "sayfa uygulaması başladıktan sonra … FAULT").
 * @return 0 / -2.
 */
static int v2evm_apply_page(nodus_witness_t *w,
                            const nodus_domain_runtime_t *rt,
                            const dna_meter_t *m, dna_meter_stream_t *s,
                            const dna_effect_in_t *e, uint16_t cnt,
                            uint8_t *resbuf, int probe_only,
                            char *reason, size_t reason_size) {
    size_t rl = 0;
    dna_effect_view_t *ev = calloc(1, sizeof(*ev));
    if (!ev) {
        V2AP_ENV_FAULT("%s", "Nodus EVM: page view allocation failed");
        return -2;
    }
    int ret = -2;
    do {
        if (dna_effect_result_encode(e, cnt, resbuf, DNA_EFFECT_MAX_TOTAL_LEN,
                                     &rl) != 0 ||
            dna_effect_result_decode(resbuf, rl, ev) != 0) {
            V2AP_ENV_FAULT("Nodus EVM: a %u-effect page of the runtime's stream "
                           "is not a canonical result", (unsigned)cnt);
            break;
        }
        if (s && dna_meter_charge_effects_page(m, s, ev) != DNA_METER_OK) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: the meter refused a page of the "
                           "charged stream (engine bookkeeping)");
            break;
        }
        uint16_t fidx = 0;
        /* Nodus EVM activation — the CheckTx dry run (design §4 "CheckTx
         * dry-run ... yalnız YOKLAR"): the SAME decision, no mutation */
        nodus_adapter_status_t ast = probe_only
            ? effects_probe_only(w, rt, ev, &fidx)
            : nodus_witness_v2_effects_apply_ex(w, rt, ev, &fidx,
                                                UINT32_MAX);
        if (ast != NODUS_ADAPTER_OK) {
            V2AP_ENV_FAULT("Nodus EVM: the EVM adapter refused effect %u of a "
                           "charged page (status %d) - the runtime's state "
                           "view and this node's storage disagree",
                           (unsigned)fidx, (int)ast);
            break;
        }
        ret = 0;
    } while (0);
    free(ev);
    return ret;
}

/** Write the node-local receipt / log index rows of one applied EVM leg
 *  (design §7: no root reads them; they go with the item's savepoint).
 *  @return 0 / -2. */
static int v2evm_index(nodus_witness_t *w, uint64_t height, size_t item,
                       const uint8_t intent_id[64], const uint8_t *rcpt,
                       size_t rcpt_len, const uint8_t digest[64],
                       const nodus_rt_v2_log_t *logs, uint32_t n_logs) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO evm_receipts (intent_id, global_height, item_index,"
            " receipt, digest) VALUES (?1, ?2, ?3, ?4, ?5)",
            -1, &st, NULL) != SQLITE_OK)
        return -2;
    sqlite3_bind_blob(st, 1, intent_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)item);
    sqlite3_bind_blob(st, 4, rcpt, (int)rcpt_len, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 5, digest, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -2;
    for (uint32_t k = 0; k < n_logs; k++) {
        if (!logs[k].addr || logs[k].n_topics > 4 ||
            (logs[k].n_topics && !logs[k].topics) ||
            (logs[k].data_len && !logs[k].data))
            return -2;
        st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO evm_logs (intent_id, log_index, global_height,"
                " addr, topics, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                -1, &st, NULL) != SQLITE_OK)
            return -2;
        sqlite3_bind_blob(st, 1, intent_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)k);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)height);
        sqlite3_bind_blob(st, 4, logs[k].addr, 32, SQLITE_TRANSIENT);
        if (logs[k].n_topics)
            sqlite3_bind_blob(st, 5, logs[k].topics,
                              (int)logs[k].n_topics * 32, SQLITE_TRANSIENT);
        else
            sqlite3_bind_zeroblob(st, 5, 0);
        if (logs[k].data_len)
            sqlite3_bind_blob(st, 6, logs[k].data, (int)logs[k].data_len,
                              SQLITE_TRANSIENT);
        else
            sqlite3_bind_zeroblob(st, 6, 0);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) return -2;
    }
    return 0;
}

/**
 * Execute ONE runtime-ABI-2 leg (design §3, §4, §7) inside the item's
 * savepoint. Order:
 *   1. the runtime runs over a fresh reader (pre-validation inside it:
 *      a refusal before anything executed is -1, the item rolls back);
 *   2. success: the WHOLE stream's count / canonical bytes are checked
 *      against the leg's declared ceilings, the stream caps and the unit
 *      budget (the gas units included) BEFORE any page — over is the
 *      deterministic failure path (or -1 for a non-failable leg), so page
 *      boundaries can never enter the outcome (§4 N2); within budget the
 *      stream is charged once, applied in pages inside an INNER savepoint
 *      nested in the item's, the gas units charged, the inner released;
 *   3. failure (execution failed, or the over-ceiling case): only the
 *      fixed failure effects are applied and gas_limit × w_gas charged;
 *   4. the receipt digest becomes the item's Data; the receipt and the
 *      logs go to the node-local index.
 * After step 1 there is no -1 for an executing leg: every check that can
 * fail after it is a FAULT (-2), except the documented bounded-budget
 * case below.
 * @return 0 applied / -1 refused (verdict) / -2 node fault.
 */
/* Nodus EVM activation — file one ABI-2 leg's conflict keys (design §8: the
 * synthetic (sender, nonce) / ticket keys, NEVER the leg's effect rows)
 * into the dry run's row list, under the leg's domain. The ONE derivation
 * (nodus_rt_evm_conflict_keys). @return 0 / -2 (alloc, or an underivable
 * key for a leg that already ran). */
_Static_assert(NODUS_RT_V2_KEY_MAX_LEN <= DNA_EFFECT_MAX_KEY_LEN,
               "an ABI-2 conflict key must fit a dry-run row");
static int dry_run_note_evm_keys(nodus_v2_env_dry_run_t *dry,
                                 uint32_t domain_id,
                                 const dna_env_view_t *v, uint16_t l,
                                 const nodus_rt_auth_verdict_t *av) {
    nodus_rt_v2_keys_t keys;
    if (nodus_rt_evm_conflict_keys(v, l, av, &keys) != 0) return -2;
    if (keys.n == 0) return 0;
    nodus_v2_dry_run_row_t *grown =
        realloc(dry->rows, (dry->n_rows + keys.n) * sizeof(*grown));
    if (!grown) return -2;
    dry->rows = grown;
    for (uint8_t k = 0; k < keys.n; k++) {
        nodus_v2_dry_run_row_t *r = &dry->rows[dry->n_rows++];
        memset(r, 0, sizeof(*r));
        r->domain_id = domain_id;
        r->op_id     = keys.k[k].op_id;
        r->key_len   = keys.k[k].key_len;
        memcpy(r->key, keys.k[k].key, keys.k[k].key_len);
    }
    return 0;
}

static int exec_evm_leg(nodus_witness_t *w, const nodus_v2_block_t *blk,
                        size_t env_index, uint16_t l, dom_ctx_t *d,
                        const nodus_rt_exec_ctx_t *ctx,
                        const dna_env_preflight_t *pf, dna_meter_t *m,
                        uint8_t *resbuf, nodus_v2_tx_result_t *res_out,
                        nodus_v2_env_dry_run_t *dry, int dry_novm,
                        char *reason, size_t reason_size) {
    const nodus_domain_runtime_t *rt = d->rt;
    const dna_env_view_t *v = &pf->view;
    v2rd_ctx_t rc;
    memset(&rc, 0, sizeof(rc));
    rc.w = w;
    rc.rt = rt;
    rc.m = m;
    rc.domain_id = d->domain_id;
    /* the headroom rule of v2rd_read is decided by the leg's own op, once,
     * here — the SAME for FinalizeBlock, the CheckTx dry run and its
     * VM-less recheck (all three create the reader here). Only an EVM
     * bridge op (3-5) is exempt; every other ABI-2 leg keeps the reserve
     * (the stricter rule is the default for an op this code does not
     * name). */
    rc.vm_leg = !(d->domain_id == DNA_DOMAIN_EVM &&
                  (v->leg[l].runtime_op == NODUS_RT_EVM_DEPOSIT ||
                   v->leg[l].runtime_op == NODUS_RT_EVM_WITHDRAW ||
                   v->leg[l].runtime_op == NODUS_RT_EVM_REDEEM));
    rc.global_height = blk->global_height;
    rc.max_reads = NODUS_RT_EVM_READS_BASE;   /* until declare_gas       */
    nodus_rt_v2_reader_t rdr = { &rc, v2rd_read, v2rd_declare_gas };

    nodus_rt_v2_out_t out;
    memset(&out, 0, sizeof(out));
    char sp[48];
    int inner_open = 0;
#ifdef NODUS_EVM_ENABLED
    int batch_open = 0;            /* the EVM adapter's per-leg trie batch */
#endif
    int ret = -2;

    /* ── Nodus EVM activation — the CheckTx admission, NEW and RECHECK alike
     * since red-team 1 F1 (design §8 "Recheck: VM YÜRÜTÜLMEZ", extended to
     * the new entry): ONLY the shared pre-validation (the same function
     * exec runs first), the reads it does charged on the dry run's meter,
     * then the conflict keys. Nothing executes, nothing is probed. */
    if (dry && dry_novm) {
        int prc = rt->prevalidate_evm
                      ? rt->prevalidate_evm(rt, v, l, ctx, &rdr, NULL)
                      : -2;
        if (prc == -2) {
            V2AP_ENV_FAULT("env %u leg %u domain %u: the ABI-2 pre-"
                           "validation backend failed", (unsigned)env_index,
                           (unsigned)l, (unsigned)d->domain_id);
        } else if (prc != 0) {
            V2AP_ENV_VERDICT("env %u leg %u domain %u op %u: the ABI-2 "
                             "pre-validation refused the leg (no-VM "
                             "admission)",
                             (unsigned)env_index, (unsigned)l,
                             (unsigned)d->domain_id,
                             (unsigned)v->leg[l].runtime_op);
            ret = -1;
        } else if (dry_run_note_evm_keys(dry, d->domain_id, v, l,
                                         ctx->auth) != 0) {
            V2AP_ENV_FAULT("env %u leg %u: the conflict keys of a "
                           "pre-validated EVM leg could not be filed",
                           (unsigned)env_index, (unsigned)l);
        } else {
            ret = 0;
        }
        v2rd_free(&rc);
        return ret;
    }

    int xrc = rt->exec_evm(rt, v, l, ctx, &rdr, &out);
    if (xrc == -2) {
        V2AP_ENV_FAULT("env %u leg %u domain %u op %u: exec_evm backend "
                       "failure", (unsigned)env_index, (unsigned)l,
                       (unsigned)d->domain_id,
                       (unsigned)v->leg[l].runtime_op);
        goto done;
    }
    if (xrc != 0) {
        V2AP_ENV_VERDICT("env %u leg %u domain %u op %u: the ABI-2 runtime "
                         "refused the leg before execution (rc %d)",
                         (unsigned)env_index, (unsigned)l,
                         (unsigned)d->domain_id,
                         (unsigned)v->leg[l].runtime_op, xrc);
        ret = -1;
        goto done;
    }
    if ((out.success != 0 && out.success != 1) ||
        (out.n_effects && !out.effects) ||
        (out.n_fail_effects && !out.fail_effects) ||
        !out.receipt || out.receipt_len == 0 ||
        (out.failable && (!out.fail_receipt || out.fail_receipt_len == 0 ||
                          out.n_fail_effects == 0)) ||
        (!out.success && !out.failable) ||
        out.gas_used > out.gas_limit ||
        out.gas_limit > NODUS_RT_EVM_TX_GAS_CAP ||
        (out.n_logs && !out.logs)) {
        V2AP_ENV_FAULT("env %u leg %u: the ABI-2 runtime returned an "
                       "out-of-contract result", (unsigned)env_index,
                       (unsigned)l);
        goto done;
    }

    int take_failure = !out.success;
    if (out.success) {
        uint64_t bytes = 0, extra = 0;
        if (v2evm_stream_check(out.effects, out.n_effects, &bytes) != 0) {
            V2AP_ENV_FAULT("env %u leg %u: the runtime's effect stream is "
                           "not canonical (order, uniqueness or caps)",
                           (unsigned)env_index, (unsigned)l);
            goto done;
        }
        if (dna_ck_mul_u64(out.gas_used, DNA_METER_EVM_W_GAS, &extra) != 0) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: gas units overflow");
            goto done;
        }
        dna_meter_stream_t s;
        memset(&s, 0, sizeof(s));
        dna_meter_status_t ms = dna_meter_charge_effects_begin(
            m, d->domain_id, out.n_effects, bytes, extra, &s);
        if (ms == DNA_METER_ERR_FAULT || ms == DNA_METER_ERR_ARG ||
            ms == DNA_METER_ERR_STATE || ms == DNA_METER_ERR_DOMAIN) {
            V2AP_ENV_FAULT("env %u leg %u: the meter refused to open the "
                           "stream (status %d)", (unsigned)env_index,
                           (unsigned)l, (int)ms);
            goto done;
        }
        if (ms != DNA_METER_OK) {
            /* LIMIT / CEILING / DOMAIN_BUDGET / OVERFLOW: deterministic —
             * decided over the WHOLE stream before any page (§4 N2) */
            if (!out.failable) {
                V2AP_ENV_VERDICT("env %u leg %u: %u effects / %llu bytes "
                                 "exceed the declared ceilings or the unit "
                                 "budget (meter status %d)",
                                 (unsigned)env_index, (unsigned)l,
                                 (unsigned)out.n_effects,
                                 (unsigned long long)bytes, (int)ms);
                ret = -1;
                goto done;
            }
            take_failure = 1;
        } else {
            /* the CheckTx dry run opens no savepoint (design §4 "CheckTx'te
             * savepoint açılmaz"): its pages are probed, never applied */
            if (!dry) {
                snprintf(sp, sizeof(sp), "cmt_evm_%llu",
                         (unsigned long long)env_index);
                if (nodus_witness_db_savepoint(w, sp) != 0) {
                    V2AP_ENV_FAULT("%s", "Nodus EVM: inner SAVEPOINT failed");
                    goto done;
                }
                inner_open = 1;
#ifdef NODUS_EVM_ENABLED
                /* red-team-1 F6: the pages' trie changes go to in-memory
                 * tries, committed once below (rt_evm.h leg batch) */
                if (rt->adapter == &NODUS_RT_EVM_ADAPTER) {
                    if (nodus_rt_evm_leg_begin((struct nodus_witness *)w)
                            != 0) {
                        V2AP_ENV_FAULT("%s", "Nodus EVM: the leg's trie batch "
                                       "could not be opened");
                        goto done;
                    }
                    batch_open = 1;
                }
#endif
            }
            uint32_t k = 0;
            while (k < out.n_effects) {
                uint16_t cnt = 0;
                uint64_t plen = DNA_EFFECT_FIXED_HEAD;
                while (k + cnt < out.n_effects && cnt < DNA_EFFECT_MAX_COUNT &&
                       plen + v2evm_eff_len(&out.effects[k + cnt]) <=
                           DNA_EFFECT_MAX_TOTAL_LEN) {
                    plen += v2evm_eff_len(&out.effects[k + cnt]);
                    cnt++;
                }
                if (cnt == 0) {             /* one effect never fits: the
                                             * per-effect caps say it does */
                    V2AP_ENV_FAULT("%s", "Nodus EVM: an effect fits no page");
                    goto done;
                }
                if (v2evm_apply_page(w, rt, m, &s, &out.effects[k], cnt,
                                     resbuf, dry != NULL, reason,
                                     reason_size) != 0)
                    goto done;
                k += cnt;
            }
            if (dna_meter_charge_effects_finish(m, &s) != DNA_METER_OK) {
                V2AP_ENV_FAULT("%s", "Nodus EVM: the applied pages do not add up "
                               "to the charged stream");
                goto done;
            }
            /* begin proved effects + this charge fit together */
            if (dna_meter_charge_evm_gas(m, d->domain_id, out.gas_used) !=
                    DNA_METER_OK) {
                V2AP_ENV_FAULT("%s", "Nodus EVM: the gas charge the stream begin "
                               "reserved did not fit");
                goto done;
            }
#ifdef NODUS_EVM_ENABLED
            if (batch_open) {
                /* every touched trie committed ONCE, inside the inner
                 * savepoint; the batch is closed whatever the result */
                batch_open = 0;
                if (nodus_rt_evm_leg_flush((struct nodus_witness *)w) != 0) {
                    V2AP_ENV_FAULT("%s", "Nodus EVM: the leg's trie batch could "
                                   "not be committed");
                    goto done;
                }
            }
#endif
            if (inner_open) {
                if (cmt_savepoint_release(w, sp) != 0) {
                    V2AP_ENV_FAULT("%s", "Nodus EVM: inner RELEASE failed");
                    goto done;
                }
                inner_open = 0;
            }
        }
    }

    if (take_failure) {
        /* design §4: the fixed failure effects only — sender nonce + 1 —
         * and gas_limit × w_gas. No page of the success stream was
         * applied (the over-ceiling decision came before any). */
        uint16_t nf = (uint16_t)out.n_fail_effects;
        uint64_t fbytes = 0;
        if (out.n_fail_effects > DNA_METER_EVM_FAIL_EFFECTS ||
            v2evm_stream_check(out.fail_effects, out.n_fail_effects,
                               &fbytes) != 0 ||
            fbytes > DNA_METER_EVM_FAIL_BYTES) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: the failure effects are not one "
                           "canonical result");
            goto done;
        }
        {
            /* the reserve the reads were kept away from must cover them */
            uint64_t fu = 0, t1 = 0, t2 = 0;
            if (dna_ck_mul_u64(m->plan.w_effect, nf, &t1) != 0 ||
                dna_ck_mul_u64(m->plan.w_effectbyte, fbytes, &t2) != 0 ||
                dna_ck_add_u64(t1, t2, &fu) != 0 ||
                fu > DNA_METER_EVM_FAIL_RESERVE) {
                V2AP_ENV_FAULT("Nodus EVM: the failure effects price above "
                               "FAIL_RESERVE (%u units)",
                               (unsigned)DNA_METER_EVM_FAIL_RESERVE);
                goto done;
            }
        }
        size_t rl = 0;
        dna_effect_view_t *ev = calloc(1, sizeof(*ev));
        if (!ev) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: failure view allocation failed");
            goto done;
        }
        if (dna_effect_result_encode(out.fail_effects, nf, resbuf,
                                     DNA_EFFECT_MAX_TOTAL_LEN, &rl) != 0 ||
            dna_effect_result_decode(resbuf, rl, ev) != 0) {
            free(ev);
            V2AP_ENV_FAULT("%s", "Nodus EVM: failure effects do not encode");
            goto done;
        }
        dna_meter_status_t ms = dna_meter_charge_effects(m, d->domain_id, ev);
        if (ms == DNA_METER_OK)
            ms = dna_meter_charge_evm_gas(m, d->domain_id, out.gas_limit);
        if (ms == DNA_METER_ERR_FAULT) {
            free(ev);
            V2AP_ENV_FAULT("%s", "Nodus EVM: meter fault on the failure path");
            goto done;
        }
        if (ms != DNA_METER_OK) {
            /* HONEST LABEL: reads keep FAIL_RESERVE and the gas units free
             * of the GLOBAL ceiling, but a BOUNDED per-domain budget (a
             * non-zero quota, or any domain before HF-3) can still be
             * spent by earlier items of the block. Design §8 makes the
             * EVM domain's budget unbounded (HF-3), where this cannot
             * happen; on a bounded one the item is refused whole —
             * deterministic, the same on every node. */
            free(ev);
            V2AP_ENV_VERDICT("env %u leg %u: the failure path does not fit "
                             "the domain's block budget (meter status %d)",
                             (unsigned)env_index, (unsigned)l, (int)ms);
            ret = -1;
            goto done;
        }
        uint16_t fidx = 0;
        nodus_adapter_status_t ast = dry
            ? effects_probe_only(w, rt, ev, &fidx)       /* CheckTx      */
            : nodus_witness_v2_effects_apply_ex(w, rt, ev, &fidx,
                                                UINT32_MAX);
        free(ev);
        if (ast != NODUS_ADAPTER_OK) {
            V2AP_ENV_FAULT("Nodus EVM: the EVM adapter refused failure effect %u "
                           "(status %d)", (unsigned)fidx, (int)ast);
            goto done;
        }
    }

    /* Nodus EVM activation — the CheckTx dry run ends here: no receipt index,
     * no Data; the conflict keys are the synthetic ones (design §8 —
     * the EVM effect rows are NOT keys) */
    if (dry) {
        if (dry_run_note_evm_keys(dry, d->domain_id, v, l, ctx->auth) != 0) {
            V2AP_ENV_FAULT("env %u leg %u: the conflict keys of an executed "
                           "EVM leg could not be filed", (unsigned)env_index,
                           (unsigned)l);
            goto done;
        }
        ret = 0;
        goto done;
    }

    /* the receipt of the outcome that was applied (design §7) */
    {
        const uint8_t *rcpt = take_failure ? out.fail_receipt : out.receipt;
        size_t rlen = take_failure ? out.fail_receipt_len : out.receipt_len;
        uint8_t dg[64];
        if (qgp_sha3_512(rcpt, rlen, dg) != 0) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: receipt hash backend failed");
            goto done;
        }
        /* item_index = the item's BLOCK position (red-team 1 F12; the
         * envelope ordinal when the caller supplied no map) — node-local
         * index data only */
        size_t item_pos = blk->env_block_pos
                              ? blk->env_block_pos[env_index] : env_index;
        if (v2evm_index(w, blk->global_height, item_pos, pf->intent_id,
                        rcpt, rlen, dg,
                        take_failure ? NULL : out.logs,
                        take_failure ? 0 : out.n_logs) != 0) {
            V2AP_ENV_FAULT("%s", "Nodus EVM: the node-local receipt index could "
                           "not be written");
            goto done;
        }
        if (res_out) {
            memcpy(res_out->data, dg, 64);
            res_out->data_len = 64;
        }
    }
    ret = 0;

done:
#ifdef NODUS_EVM_ENABLED
    /* a FAULT between begin and flush: the in-memory trie changes go;
     * nothing of them reached the database (the rows go with the inner
     * savepoint below) */
    if (batch_open) nodus_rt_evm_leg_discard((struct nodus_witness *)w);
#endif
    if (inner_open) {
        /* only a FAULT leaves it open; the item's own rollback discards
         * it too — undone here so the transaction's savepoint stack is
         * what the item loop expects */
        (void)nodus_witness_db_rollback_to_savepoint(w, sp);
        (void)cmt_savepoint_release(w, sp);
    }
    if (out.release) out.release(&out);
    v2rd_free(&rc);
    return ret;
}

/* Fires a native-auth-season per-leg fault point for THIS envelope. */
#define ENV_FAIL_POINT(pt)                                              \
    do {                                                                \
        if (blk->fail_at == (pt) &&                                     \
            blk->fail_env_index == (uint32_t)env_index) {               \
            V2AP_ENV_VERDICT("fault-injection point %s fired at env %u "\
                             "leg %u (test harness; no real check "     \
                             "failed)", #pt, (unsigned)env_index,       \
                             (unsigned)l);                              \
            return -1;                                                  \
        }                                                               \
    } while (0)

/**
 * Execute ONE preflighted, reserved, AUTH-VERIFIED envelope inside THE
 * transaction: activate → per leg (verified-verdict bind → reads →
 * native exec → strict decode → charge → adapter apply) → finalize →
 * per-domain consumed-unit accounting. `auths` is the engine-owned
 * verdict array the per-item authorization stage filled for THIS
 * envelope — indexed by leg alone (`auths[l]`), never
 * `env_index * DNA_ENV_MAX_LEGS + leg` (R3 W4 package C: one per-item,
 * DNA_ENV_MAX_LEGS-sized buffer).
 *
 * `reason`/`reason_size` are the caller's blk->out_reason (this `blk` is
 * const, so the buffer arrives separately). The CALLEE OWNS the reason:
 * every failing site here names its own check, and the call site must
 * not overwrite what it is handed — the inner site always knows more
 * than "envelope N failed".
 *
 * `dry` (CHECKTX-P1): NULL on the apply path. Non-NULL is the per-item
 * DRY RUN (nodus_witness_v2_env_dry_run): every step below runs
 * unchanged EXCEPT the adapter application, which is replaced by
 * `effects_probe_only` (validate → probe → the ONE precondition table,
 * no mutate), and every row-identity effect of the decoded result
 * (every DELETE and every PRE_ABSENT CREATE — `dry_run_row_claim`) is
 * recorded into `dry->rows`. The apply path's behaviour is byte-identical:
 * with `dry == NULL` the only new code is the branch that selects it.
 * Nodus EVM activation: an ABI-2 leg in the dry run runs probe-only (its
 * effect rows are NOT recorded; its synthetic conflict keys are), and
 * with `dry_novm` (CheckTx, NEW and RECHECK — red-team 1 F1) only its
 * shared pre-validation runs — no VM. `dry_novm` is ignored when `dry`
 * is NULL.
 *
 * @return 0 / -1 verdict / -2 node fault. On a verdict the caller rolls
 * the item's SAVEPOINT back (item code EXEC); on a fault it aborts the
 * whole block — there is no partial-envelope outcome.
 */
static int exec_one_env(nodus_witness_t *w, const nodus_v2_block_t *blk,
                        size_t env_index,
                        const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                        uint64_t epoch,
                        dom_ctx_t *doms, size_t n_dom,
                        const dna_env_preflight_t *pf, dna_meter_t *m,
                        const nodus_rt_auth_verdict_t *auths,
                        nodus_rt_read_res_t *reads, uint8_t *resbuf,
                        nodus_v2_env_dry_run_t *dry, int dry_novm,
                        nodus_v2_tx_result_t *res_out,
                        char *reason, size_t reason_size) {
    /* RESERVED → ACTIVE. The reservation covered the fixed work by
     * construction, so any failure here is an accounting invariant
     * fault of this node, never a budget verdict. */
    if (dna_meter_activate(m) != DNA_METER_OK) {
        V2AP_ENV_FAULT("env %u: meter RESERVED->ACTIVE failed (state %d)",
                       (unsigned)env_index, (int)m->state);
        return -2;
    }

    const dna_env_view_t *v = &pf->view;
    /* W-C: the governed token-creation fee at this block's height, read
     * ONCE per envelope (every leg judges against the same committed
     * row) — a read fault aborts, never defaults. */
    uint64_t tc_fee = 0;
    if (env_token_create_fee(w, blk->global_height, &tc_fee,
                             reason, reason_size) != 0)
        return -2;
    /* HF-2: the rule set in force at this block's height, read ONCE per
     * envelope with the same discipline (fault = abort, never default) */
    uint8_t hf2 = 0;
    if (env_hf2_active(w, blk->global_height, &hf2, reason,
                       reason_size) != 0)
        return -2;
    /* HF-4: "any param-9 row", read ONCE per envelope (= per item: one
     * item is live at a time), so a vote an earlier item of this block
     * committed counts — fault = abort, never default */
    uint8_t gen2_voted = 0;
    if (env_ruleset_gen2_voted(w, &gen2_voted, reason, reason_size) != 0)
        return -2;
    /* storage reward v1: "any param-16 row", the same discipline */
    uint8_t gen_storage_voted = 0;
    if (env_ruleset_gen_storage_voted(w, &gen_storage_voted, reason,
                                      reason_size) != 0)
        return -2;
    /* HF-4: the name price tiers at this block's height, once per item */
    uint64_t name_price[4];
    if (env_name_prices(w, blk->global_height, name_price, reason,
                        reason_size) != 0)
        return -2;
    /* Nodus EVM: the EVM_ACTIVE vote facts and the EVM block gas limit, once
     * per item (an earlier item's vote row counts — the HF-4 rule) */
    nodus_rt_exec_ctx_t evm_facts;
    memset(&evm_facts, 0, sizeof(evm_facts));
    if (env_evm_facts(w, blk->global_height, &evm_facts, reason,
                      reason_size) != 0)
        return -2;
    for (uint16_t l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        if (!d || !d->rt || !rt_can_execute(d->rt)) { /* admission-scan
                                         * invariant — defensive        */
            V2AP_ENV_FAULT("env %u leg %u domain %u: runtime/exec hook "
                           "absent inside the txn (admission-scan "
                           "invariant broken on this node)",
                           (unsigned)env_index, (unsigned)l,
                           (unsigned)v->leg[l].domain_id);
            return -2;
        }
        const nodus_domain_runtime_t *rt = d->rt;

        /* The ENGINE-owned verified verdict for THIS leg. The item's
         * authorization stage refused the item unless every leg
         * verified, so an empty slot here is an engine invariant broken
         * on this node — a fault, never a verdict.
         *
         * R3 W4 package C — `auths` is the one per-item buffer, which IS
         * this envelope's base since only one item is ever live at a
         * time, so this callee indexes by leg alone — no
         * `env_index * DNA_ENV_MAX_LEGS` multiplication. */
        const nodus_rt_auth_verdict_t *av = &auths[l];
        if (av->n_signers < 1) {
            V2AP_ENV_FAULT("env %u leg %u: empty authorization verdict "
                           "slot (item auth stage invariant broken on "
                           "this node)",
                           (unsigned)env_index, (unsigned)l);
            return -2;
        }

        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.chain_id            = chain_id;
        ctx.global_height       = blk->global_height;
        ctx.epoch               = epoch;
        ctx.wire_id             = pf->wire_id;
        ctx.intent_id           = pf->intent_id;
        ctx.auth_context_commit = pf->auth_context_commit;
        ctx.leg_auth_digest     = pf->auth_digest[l];
        ctx.auth                = av;
        ctx.token_create_fee    = tc_fee;
        ctx.hf2_active          = hf2;
        ctx.ruleset_gen2_voted  = gen2_voted;
        ctx.ruleset_gen_storage_voted = gen_storage_voted;
        memcpy(ctx.name_price, name_price, sizeof(ctx.name_price));
        /* Nodus EVM (design §10): the block environment an ABI-2 runtime
         * reads — the Comet header seconds and the EVM block gas limit
         * (chain_config param 15 at this height, the compiled default
         * without a row). No ABI-1 hook reads either. */
        ctx.block_time_s        = blk->timestamp;
        ctx.evm_block_gas_limit = evm_facts.evm_block_gas_limit;
        ctx.hf3_active          = evm_facts.hf3_active;
        ctx.gas_price_on        = evm_facts.gas_price_on;
        ctx.evm_active_voted    = evm_facts.evm_active_voted;
        ctx.chain_initial_height = evm_facts.chain_initial_height; /* F5 */

        /* ── Nodus EVM: a runtime-ABI-2 leg reads at RUN TIME through the
         * engine's reader and returns an effect STREAM (design §3/§4) —
         * its own path, exec_evm_leg. The executing dry run (`dry`,
         * novm 0) runs the SAME path probe-only on a fresh overlay with
         * no savepoint (design §4); the `dry_novm` form — what CheckTx
         * runs for every entry since red-team 1 F1 — runs only the shared
         * pre-validation (design §8 — no VM). */
        if (rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2) {
            int erc = exec_evm_leg(w, blk, env_index, l, d, &ctx, pf, m,
                                   resbuf, res_out, dry, dry_novm,
                                   reason, reason_size);
            if (erc != 0) return erc;
            continue;
        }

        /* ── mediated reads: request phase → engine-charged execution ─
         * TRUST NOTE: the count/length rejects below detect a hook that
         * LIES about how much it wrote; they cannot detect a compiled
         * hook that ignores the caps it was handed and scribbles past
         * its buffer — an in-process C function pointer is inside the
         * trust boundary by construction (nodus_witness_v2_adapter.h
         * "broken TRUSTED component"). The caps are the contract; the
         * checks are tamper-evidence, not memory safety. */
        uint16_t n_reads = 0;
        if (rt->read_plan) {
            nodus_rt_read_req_t reqs[NODUS_RT_MAX_READS];
            memset(reqs, 0, sizeof(reqs));
            uint16_t nr = 0;
            int prc = rt->read_plan(rt, v, l, &ctx, reqs,
                                    NODUS_RT_MAX_READS, &nr);
            if (prc == -2) {             /* hook backend: node fault     */
                V2AP_ENV_FAULT("env %u leg %u domain %u op %u: read_plan "
                               "hook backend failure",
                               (unsigned)env_index, (unsigned)l,
                               (unsigned)d->domain_id,
                               (unsigned)v->leg[l].runtime_op);
                return -2;
            }
            if (prc != 0) {              /* deterministic refusal        */
                V2AP_ENV_VERDICT("env %u leg %u domain %u op %u: "
                                 "read_plan refused (rc %d)",
                                 (unsigned)env_index, (unsigned)l,
                                 (unsigned)d->domain_id,
                                 (unsigned)v->leg[l].runtime_op, prc);
                return -1;
            }
            if (nr > NODUS_RT_MAX_READS) {            /* over-plan       */
                V2AP_ENV_VERDICT("env %u leg %u domain %u: read_plan "
                                 "over-planned %u reads (max %u)",
                                 (unsigned)env_index, (unsigned)l,
                                 (unsigned)d->domain_id, (unsigned)nr,
                                 (unsigned)NODUS_RT_MAX_READS);
                return -1;
            }
            for (uint16_t r = 0; r < nr; r++) {
                if (reqs[r].key_len < 1 ||
                    reqs[r].key_len > DNA_EFFECT_MAX_KEY_LEN) {
                    V2AP_ENV_VERDICT("env %u leg %u domain %u: read %u "
                                     "key_len %u out of range [1,%u]",
                                     (unsigned)env_index, (unsigned)l,
                                     (unsigned)d->domain_id, (unsigned)r,
                                     (unsigned)reqs[r].key_len,
                                     (unsigned)DNA_EFFECT_MAX_KEY_LEN);
                    return -1;
                }
                /* strictly ascending (op_id, key): duplicates AND
                 * disorder both reject — an ambiguous read list has no
                 * canonical charge order */
                if (r > 0 && read_req_cmp(&reqs[r - 1], &reqs[r]) >= 0) {
                    V2AP_ENV_VERDICT("env %u leg %u domain %u: read plan "
                                     "not strictly ascending at index %u "
                                     "(duplicate or disordered key)",
                                     (unsigned)env_index, (unsigned)l,
                                     (unsigned)d->domain_id, (unsigned)r);
                    return -1;
                }
            }
            ENV_FAIL_POINT(V2AP_FAIL_AFTER_READ_PLAN);
            for (uint16_t r = 0; r < nr; r++) {
                nodus_adapter_status_t ast =
                    nodus_witness_v2_read_one(w, rt, &reqs[r], &reads[r]);
                if (ast == NODUS_ADAPTER_ERR_STORAGE_FAULT ||
                    ast == NODUS_ADAPTER_ERR_ARG) {
                    V2AP_ENV_FAULT("env %u leg %u domain %u: mediated "
                                   "read %u storage/arg fault (adapter "
                                   "status %d)",
                                   (unsigned)env_index, (unsigned)l,
                                   (unsigned)d->domain_id, (unsigned)r,
                                   (int)ast);
                    return -2;           /* node fault, never "absent"   */
                }
                if (ast != NODUS_ADAPTER_OK) {
                    V2AP_ENV_VERDICT("env %u leg %u domain %u: mediated "
                                     "read %u refused (adapter status "
                                     "%d)",
                                     (unsigned)env_index, (unsigned)l,
                                     (unsigned)d->domain_id, (unsigned)r,
                                     (int)ast);
                    return -1;           /* NO_ADAPTER/UNKNOWN_OP/SHAPE:
                                          * deterministic verdict        */
                }
                /* exactly ONE w_read per executed read, from the sealed
                 * plan-pinned policy — the engine is the only charger */
                dna_meter_status_t ms =
                    dna_meter_charge_read(m, d->domain_id);
                if (ms == DNA_METER_ERR_FAULT) {
                    V2AP_ENV_FAULT("env %u leg %u domain %u: meter "
                                   "accounting fault charging read %u",
                                   (unsigned)env_index, (unsigned)l,
                                   (unsigned)d->domain_id, (unsigned)r);
                    return -2;
                }
                if (ms != DNA_METER_OK) {             /* budget verdict  */
                    V2AP_ENV_VERDICT("env %u leg %u domain %u: read %u "
                                     "exceeded the unit budget (meter "
                                     "status %d)",
                                     (unsigned)env_index, (unsigned)l,
                                     (unsigned)d->domain_id, (unsigned)r,
                                     (int)ms);
                    return -1;
                }
            }
            n_reads = nr;
            ENV_FAIL_POINT(V2AP_FAIL_AFTER_READS);
        }

        /* ── native compiled execution → canonical result bytes ─────── */
        size_t rl = 0;
        memset(resbuf, 0, DNA_EFFECT_MAX_TOTAL_LEN);
        {
            int xrc = rt->exec(rt, v, l, &ctx, reads, n_reads,
                               resbuf, DNA_EFFECT_MAX_TOTAL_LEN, &rl);
            if (xrc == -2) {             /* hook backend: node fault     */
                V2AP_ENV_FAULT("env %u leg %u domain %u op %u: exec hook "
                               "backend failure",
                               (unsigned)env_index, (unsigned)l,
                               (unsigned)d->domain_id,
                               (unsigned)v->leg[l].runtime_op);
                return -2;
            }
            if (xrc != 0) {              /* deterministic refusal        */
                V2AP_ENV_VERDICT("env %u leg %u domain %u op %u: runtime "
                                 "exec refused (rc %d)",
                                 (unsigned)env_index, (unsigned)l,
                                 (unsigned)d->domain_id,
                                 (unsigned)v->leg[l].runtime_op, xrc);
                return -1;
            }
        }
        if (rl > DNA_EFFECT_MAX_TOTAL_LEN) {
            V2AP_ENV_VERDICT("env %u leg %u domain %u: exec hook claimed "
                             "%llu result bytes (max %llu)",
                             (unsigned)env_index, (unsigned)l,
                             (unsigned)d->domain_id,
                             (unsigned long long)rl,
                             (unsigned long long)DNA_EFFECT_MAX_TOTAL_LEN);
            return -1;
        }
        ENV_FAIL_POINT(V2AP_FAIL_AFTER_EXEC_HOOK);

        /* exact-length strict decode: canonical order, logical-key
         * uniqueness, kind/precondition legality — all codec-enforced;
         * a malformed result from a compiled runtime is the same bytes
         * on every node, hence a VERDICT */
        dna_effect_view_t ev;
        if (dna_effect_result_decode(resbuf, rl, &ev) != 0) {
            V2AP_ENV_VERDICT("env %u leg %u domain %u: strict decode of "
                             "the %llu-byte runtime result failed "
                             "(non-canonical effect list)",
                             (unsigned)env_index, (unsigned)l,
                             (unsigned)d->domain_id,
                             (unsigned long long)rl);
            return -1;
        }
        ENV_FAIL_POINT(V2AP_FAIL_AFTER_EFFECT_DECODE);

        /* charge BEFORE mutation (the season's step order): w_effect ×
         * actual count + w_effectbyte × actual canonical bytes, gated
         * by the leg's declared ceilings */
        dna_meter_status_t ms = dna_meter_charge_effects(m, d->domain_id,
                                                         &ev);
        if (ms == DNA_METER_ERR_FAULT) {
            V2AP_ENV_FAULT("env %u leg %u domain %u: meter accounting "
                           "fault charging %u effects",
                           (unsigned)env_index, (unsigned)l,
                           (unsigned)d->domain_id,
                           (unsigned)ev.effect_count);
            return -2;
        }
        if (ms != DNA_METER_OK) {
            V2AP_ENV_VERDICT("env %u leg %u domain %u: %u effects "
                             "exceeded the declared ceiling / unit budget "
                             "(meter status %d)",
                             (unsigned)env_index, (unsigned)l,
                             (unsigned)d->domain_id,
                             (unsigned)ev.effect_count, (int)ms);
            return -1;
        }
        ENV_FAIL_POINT(V2AP_FAIL_AFTER_EFFECT_CHARGE);

        /* adapter application: validate → probe → the ONE precondition
         * decision table → mutate, all through the runtime's compiled
         * adapter, scoped by rt->domain_id and nothing else. Fault
         * point 37 (burn season) injects a MID-EFFECT-LIST stop after
         * the named applied effect; the ERR_INJECTED it produces rides
         * the ordinary deterministic-verdict abort below, so rollback
         * is proven through the same path every real rejection takes. */
        uint16_t fidx = 0;
        uint32_t stop_after = UINT32_MAX;
        if (blk->fail_at == V2AP_FAIL_AFTER_EFFECT_APPLY &&
            blk->fail_env_index == (uint32_t)env_index &&
            blk->fail_effect_index < ev.effect_count)
            stop_after = blk->fail_effect_index;
        nodus_adapter_status_t ast;
        if (dry) {
            /* CHECKTX-P1 dry run: the same decision, no mutation; the
             * row-identity rows are the mempool's conflict keys. */
            if (dry_run_note_rows(dry, d->domain_id, &ev) != 0) {
                V2AP_ENV_FAULT("env %u leg %u domain %u: allocation of the "
                               "dry run's row list failed",
                               (unsigned)env_index, (unsigned)l,
                               (unsigned)d->domain_id);
                return -2;
            }
            /* HF-4 (design §2 "Same owner, two names pending"): a CORE
             * NAME_REGISTER leg also claims a SYNTHETIC OWNER(owner) row,
             * so one node's mempool admits one registration per owner
             * (the effect rows key only NAME(name)). Mempool only: the
             * apply path never reaches this branch. */
            {
                uint32_t oop = 0;
                uint8_t  okey[64];
                int krc = nodus_rt_core_name_owner_key(v, l, av, &oop,
                                                       okey);
                if (krc < 0) {
                    V2AP_ENV_FAULT("env %u leg %u: the owner key of an "
                                   "executed registration is underivable "
                                   "(engine invariant broken on this "
                                   "node)", (unsigned)env_index,
                                   (unsigned)l);
                    return -2;
                }
                if (krc == 0) {
                    nodus_v2_dry_run_row_t *grown = realloc(
                        dry->rows, (dry->n_rows + 1) * sizeof(*grown));
                    if (!grown) {
                        V2AP_ENV_FAULT("env %u leg %u: allocation of the "
                                       "dry run's owner key failed",
                                       (unsigned)env_index, (unsigned)l);
                        return -2;
                    }
                    dry->rows = grown;
                    nodus_v2_dry_run_row_t *r = &dry->rows[dry->n_rows++];
                    memset(r, 0, sizeof(*r));
                    r->domain_id = d->domain_id;
                    r->op_id     = oop;
                    r->key_len   = 64;
                    memcpy(r->key, okey, 64);
                }
            }
            ast = effects_probe_only(w, rt, &ev, &fidx);
        } else {
            ast = nodus_witness_v2_effects_apply_ex(w, rt, &ev, &fidx,
                                                    stop_after);
        }
        if (ast == NODUS_ADAPTER_ERR_STORAGE_FAULT ||
            ast == NODUS_ADAPTER_ERR_ARG) {
            V2AP_ENV_FAULT("env %u leg %u domain %u: storage/arg fault "
                           "applying effect %u of %u (adapter status %d)",
                           (unsigned)env_index, (unsigned)l,
                           (unsigned)d->domain_id, (unsigned)fidx,
                           (unsigned)ev.effect_count, (int)ast);
            return -2;                   /* node fault                   */
        }
        if (ast != NODUS_ADAPTER_OK) {            /* precondition etc.   */
            V2AP_ENV_VERDICT("env %u leg %u domain %u: effect %u of %u "
                             "rejected by the adapter (status %d - "
                             "precondition/probe)",
                             (unsigned)env_index, (unsigned)l,
                             (unsigned)d->domain_id, (unsigned)fidx,
                             (unsigned)ev.effect_count, (int)ast);
            return -1;
        }

        /* F38 (O11): the leg at blk->fail_leg_index has now FULLY
         * applied every one of its effects, and the NEXT leg of the same
         * envelope has not started. This is the HALF-ENVELOPE point: for
         * a cross-domain staking envelope it fires between the SYSTEM
         * record leg's row writes and the CORE funding leg, so a test
         * can prove that a record without its funding (or funding
         * without its record) never survives. It rides the ordinary
         * deterministic-verdict abort, exactly like F37, so the rollback
         * it proves is the one every real rejection takes. */
        if (blk->fail_at == V2AP_FAIL_AFTER_LEG_APPLY &&
            blk->fail_env_index == (uint32_t)env_index &&
            blk->fail_leg_index == (uint32_t)l) {
            V2AP_ENV_VERDICT("fault-injection point "
                             "V2AP_FAIL_AFTER_LEG_APPLY fired at env %u "
                             "leg %u (test harness; no real check "
                             "failed)",
                             (unsigned)env_index, (unsigned)l);
            return -1;
        }
    }

    /* ACTIVE → FINALIZED: unused units return to the budgets. */
    if (dna_meter_finalize(m) != DNA_METER_OK) {
        V2AP_ENV_FAULT("env %u: meter ACTIVE->FINALIZED failed (state %d)",
                       (unsigned)env_index, (int)m->state);
        return -2;
    }

    /* Per-domain consumed-unit accounting for the DomainUpdate resource
     * fields (ACTUAL consumed units, not the reservation). Each item's
     * consumed units are bounded by its own declared ceiling (the
     * meter's CEILING gate) and are the real fixed work plus the real
     * effect counts / bytes and reads / writes × the policy weights.
     * Below the HF-3 height the block budgets also bound the sum; from
     * it the global and quota-0 budgets are unbounded (res_meter.h
     * flags), so nothing bounds the per-block SUM except the item count
     * — the checked add below is the guard: a wrap is a node FAULT,
     * never a silently wrong res_cost. */
    for (uint16_t l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        if (!d) {
            V2AP_ENV_FAULT("env %u leg %u: domain %u vanished from the "
                           "block-start snapshot during consumed-unit "
                           "accounting",
                           (unsigned)env_index, (unsigned)l,
                           (unsigned)v->leg[l].domain_id);
            return -2;
        }
        if (dna_ck_add_u64(d->res_cost, m->dom_consumed[l],
                           &d->res_cost) != 0) {
            V2AP_ENV_FAULT("env %u leg %u domain %u: consumed-unit "
                           "accumulator overflowed",
                           (unsigned)env_index, (unsigned)l,
                           (unsigned)d->domain_id);
            return -2;
        }
    }
    return 0;
}

/**
 * `RELEASE SAVEPOINT <name>`. The witness DB layer ships
 * `nodus_witness_db_savepoint` and
 * `nodus_witness_db_rollback_to_savepoint` (nodus_witness_db.h:486-487)
 * but no release, and a savepoint that is rolled back is still ACTIVE
 * until it is released — so the cometbft lane, which opens one per item,
 * needs this to avoid accumulating one nesting level per transaction in
 * the block.
 *
 * The name is ENGINE-GENERATED (`cmt_item_<n>`), never caller- or
 * peer-derived, which is what makes inlining it into the SQL safe — the
 * same contract the two shipped helpers state.
 *
 * @return 0 / -1.
 */
static int cmt_savepoint_release(nodus_witness_t *w, const char *name)
{
    char sql[96];

    snprintf(sql, sizeof(sql), "RELEASE SAVEPOINT %s", name);
    return exec_sql(w, sql);
}

/**
 * The GOVERNING COMMITTEE SNAPSHOT for a block at `height` — the
 * authority a committee-indexed (`auth_kind` 2) leg's approvals are
 * verified against.
 *
 * FACTORED OUT of the phase-0b block it used to be written inline in,
 * with the logic byte-for-byte unchanged: the same
 * `nodus_committee_get_for_block_alloc` at the same governing height
 * `height - 1` (the SAME authority the legacy chain-config apply
 * consults — nodus_witness_chain_config.c's lookup_height =
 * commit_block - 1), the same contract bound on the member count, the
 * same per-member fingerprint, the same set hash, the same epoch. It
 * became a function when two lanes had to resolve it (the legacy lane
 * is deleted since tokenomics-v3 P4); a drift here would make two
 * builds reach different authorization verdicts for the same bytes,
 * which is a chain split.
 *
 * The transaction can neither carry nor select the snapshot: nothing in
 * an envelope names an epoch, a height or a set hash; approvals merely
 * FAIL against the wrong one. An EMPTY committee is deterministic chain
 * state and flows into the view (the auth hook rejects kind-2 legs at
 * count 0).
 *
 * On success `*out_pubkeys` / `*out_fps` / `*out_powers` (HF-2: the
 * seats' voting powers, view->powers) receive heap buffers the CALLER
 * frees; on every failure they are left as they were.
 *
 * @return 0 resolved (possibly empty); 1 `height` is 0, so the governing
 *         height would be below genesis — the CALLER decides the class,
 *         because it differs by lane; -2 node-local fault, with the
 *         reason written into (reason, reason_size).
 */
static int committee_snapshot_for_height(nodus_witness_t *w, uint64_t height,
                                         nodus_rt_committee_t *view,
                                         uint8_t **out_pubkeys,
                                         uint8_t (**out_fps)[64],
                                         uint64_t **out_powers,
                                         char *reason, size_t reason_size)
{
    nodus_committee_member_t *mem = NULL;
    uint8_t                  *cm_pubkeys = NULL;
    uint8_t                 (*cm_fps)[64] = NULL;
    uint64_t                 *cm_powers = NULL;
    int                       cm_count = 0;

    if (height == 0) {
        return 1;                                    /* below genesis    */
    }
    if (nodus_committee_get_for_block_alloc(w, height - 1, &mem,
                                            &cm_count) != 0) {
        V2AP_ENV_FAULT("phase 0b: governing committee lookup at height "
                       "%llu failed on this node",
                       (unsigned long long)(height - 1));
        return -2;
    }
    if (cm_count < 0 || cm_count > DNA_MAX_ACTIVE_VALIDATORS) {
        free(mem);
        V2AP_ENV_FAULT("phase 0b: committee resolution returned %d "
                       "members, outside the contract [0,%u]",
                       cm_count, (unsigned)DNA_MAX_ACTIVE_VALIDATORS);
        return -2;                       /* out-of-contract resolution   */
    }
    if (cm_count > 0) {
        int ci;

        cm_pubkeys = malloc((size_t)cm_count * NODUS_CC_PUBKEY_SIZE);
        cm_fps = malloc((size_t)cm_count * 64);
        cm_powers = malloc((size_t)cm_count * sizeof(*cm_powers));
        if (!cm_pubkeys || !cm_fps || !cm_powers) {
            free(cm_pubkeys);
            free(cm_fps);
            free(cm_powers);
            free(mem);
            V2AP_ENV_FAULT("phase 0b: allocation for the %d-member "
                           "committee snapshot failed", cm_count);
            return -2;
        }
        for (ci = 0; ci < cm_count; ci++) {
            memcpy(cm_pubkeys + (size_t)ci * NODUS_CC_PUBKEY_SIZE,
                   mem[ci].pubkey, NODUS_CC_PUBKEY_SIZE);
            /* HF-2 (GW-1): the seat's VOTING POWER, copied out BEFORE
             * `mem` is freed below — floor(total_stake / DNAC_DECIMAL_
             * UNIT), the SAME derivation the block-commit validator set
             * uses (nodus_witness_cmt_app.c's FinalizeBlock
             * validator-update loop: `en->total_stake /
             * DNAC_DECIMAL_UNIT`), in the same seat order the approvals
             * index. */
            cm_powers[ci] = mem[ci].total_stake / DNAC_DECIMAL_UNIT;
            if (qgp_sha3_512(mem[ci].pubkey, NODUS_CC_PUBKEY_SIZE,
                             cm_fps[ci]) != 0) {
                free(cm_pubkeys);
                free(cm_fps);
                free(cm_powers);
                free(mem);
                V2AP_ENV_FAULT("phase 0b: hash backend failed on "
                               "committee member %d of %d", ci, cm_count);
                return -2;
            }
        }
        if (nodus_rt_committee_set_hash((const uint8_t (*)[64])cm_fps,
                                        (uint32_t)cm_count,
                                        view->set_hash) != 0) {
            free(cm_pubkeys);
            free(cm_fps);
            free(cm_powers);
            free(mem);
            V2AP_ENV_FAULT("phase 0b: committee set-hash over %d members "
                           "failed", cm_count);
            return -2;
        }
        view->pubkeys = cm_pubkeys;
        view->fps = (const uint8_t (*)[64])cm_fps;
        view->powers = cm_powers;
        *out_pubkeys = cm_pubkeys;
        *out_fps = cm_fps;
        *out_powers = cm_powers;
    }
    free(mem);
    view->count = (uint32_t)cm_count;
    view->epoch = nodus_v2_epoch_for_height(height - 1);
    return 0;
}

/**
 * THE ITEM'S REPLAY GUARD — the committed intent index, then the
 * committed wire index (the SQL the item loop has always run; CheckTx's
 * admission lane runs the intent half textually, nodus_witness_verify.c
 * "Committed-intent replay"). FACTORED OUT of the Comet item loop with
 * the statements and fault texts unchanged (CHECKTX-P1) so the dry run
 * asks the SAME question.
 *
 * @param item  the item index, for the fault text only.
 * @return 0 with `*hit` set (1 = replay); -2 a node-local fault, reason
 *         written into (reason, reason_size).
 *
 * HF-3 rule 6b (decision 2026-10-01-hf3-comet-only-block-bounds.md answer
 * 12): EXPORTED as nodus_witness_v2_replay_guard so the proposal seam
 * (nodus_witness_v2_produce.c) asks the SAME question from the HF-3
 * height; env_replay_guard below is a one-line wrapper, so the dry run
 * and the item loop run these statements unchanged.
 */
int nodus_witness_v2_replay_guard(nodus_witness_t *w,
                                  const dna_env_preflight_t *p,
                                  size_t item, int *hit,
                                  char *reason, size_t reason_size)
{
    static const char *const guard_sql[2] = {
        "SELECT 1 FROM v2_intent_index WHERE intent_id = ?1",
        "SELECT 1 FROM v2_tx_index WHERE tx_id = ?1"
    };
    const uint8_t *guard_id[2] = { p->intent_id, p->wire_id };
    int g;

    *hit = 0;
    for (g = 0; g < 2 && !*hit; g++) {
        sqlite3_stmt *st = NULL;
        int rc;

        if (sqlite3_prepare_v2(w->db, guard_sql[g], -1, &st, NULL)
            != SQLITE_OK) {
            V2AP_ENV_FAULT("cometbft item %llu: the replay guard could not "
                           "be prepared on this node",
                           (unsigned long long)item);
            return -2;
        }
        sqlite3_bind_blob(st, 1, guard_id[g], 64, SQLITE_TRANSIENT);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) {
            *hit = 1;
        } else if (rc != SQLITE_DONE) {
            V2AP_ENV_FAULT("cometbft item %llu: the replay guard failed to "
                           "step on this node (sqlite rc %d)",
                           (unsigned long long)item, rc);
            return -2;
        }
    }
    return 0;
}

static int env_replay_guard(nodus_witness_t *w, const dna_env_preflight_t *p,
                            size_t item, int *hit,
                            char *reason, size_t reason_size)
{
    return nodus_witness_v2_replay_guard(w, p, item, hit, reason,
                                         reason_size);
}

/**
 * THE ITEM'S PER-LEG ADMISSION — the resolved runtime exists and carries
 * exec + auth hooks, the leg is an INVOKE, the committed ruleset OWNS the
 * runtime_op, the auth_kind is on the runtime's allowlist, and the
 * domain's committed per-block quota has room. FACTORED OUT of the Comet
 * item loop with the predicate, the order and the classes unchanged
 * (CHECKTX-P1) so the dry run asks the SAME question.
 *
 * @param n_envs  the block's envelope count (1 for the dry run's
 *                one-item block) — the bound of the proven-unreachable
 *                n_tx FAULT below.
 * @param item    the item index, for the fault text only.
 * @return 0 admitted; -1 refused with `*code` set (ADMISSION or
 *         CAPACITY); -2 the one-leg-per-domain invariant broke on this
 *         node, reason written into (reason, reason_size).
 */
static int env_admit_legs(const dna_env_view_t *v, dom_ctx_t *doms,
                          size_t n_dom, uint64_t n_envs, size_t item,
                          uint32_t *code, char *reason, size_t reason_size)
{
    uint16_t l;
    unsigned n_abi2 = 0;

    for (l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        uint8_t ak = v->leg[l].auth_kind;

        /* Nodus EVM: at most ONE runtime-ABI-2 leg per envelope — the meter
         * carries one streamed leg (res_meter.h plan.stream_leg). Only
         * the EVM domain speaks ABI 2, and legs are one per domain, so a
         * second one cannot occur today; the check keeps it a refusal,
         * never an unmetered leg. */
        if (d && d->rt && d->rt->runtime_abi == NODUS_DOMAIN_RUNTIME_ABI_V2)
            n_abi2++;
        if (!d || !d->rt || !rt_can_execute(d->rt) || !d->rt->auth ||
            n_abi2 > 1 ||
            v->leg[l].access_mode != DNA_ENV_ACCESS_INVOKE ||
            !rt_owns_runtime_op(d->rt, v->leg[l].runtime_op) ||
            ak >= 32 ||
            (d->rt->allowed_auth_kinds & NODUS_RT_AUTHKIND_BIT(ak)) == 0) {
            *code = NODUS_V2_TX_ERR_ADMISSION;
            return -1;
        }
        /* R3 W4 package C — PROVEN, not policy, and split from the quota
         * check below (they used to share one `||` and one CAPACITY
         * verdict). A domain cannot appear twice in one envelope's leg
         * list (env_wire.c:364-365 decode / :276 encode both refuse a
         * domain_id that is not strictly ascending), so this domain's
         * `n_tx` — incremented once per LEG naming it — can never reach
         * the block's own `n_envs`. Reaching this branch means that
         * invariant broke on THIS node: a FAULT, never the CAPACITY
         * verdict the quota half below still is. */
        if (d->n_tx >= n_envs) {
            V2AP_ENV_FAULT("cometbft item %llu leg %u: domain %u's n_tx "
                           "reached the block's own n_envs (%llu) - the "
                           "one-leg-per-domain-per-envelope invariant "
                           "(env_wire.c:364-365) broke on this node",
                           (unsigned long long)item, (unsigned)l,
                           (unsigned)d->domain_id,
                           (unsigned long long)n_envs);
            return -2;
        }
        /* the committed manifest's own per-domain quota — CAPACITY,
         * because it is about what is LEFT, not about the bytes */
        if (d->man.quota_tx_per_block != 0 &&
            d->n_tx + 1 > (uint32_t)d->man.quota_tx_per_block) {
            *code = NODUS_V2_TX_ERR_CAPACITY;
            return -1;
        }
    }
    return 0;
}

/**
 * THE HF-1 GAS-PRICE FEE RULE (decision docs/plans/decisions/2026-09-25-
 * gas-price.md; design docs/plans/2026-09-26-hf1-gas-price-design.md
 * §2.2). ONE helper, two callers: the Comet item loop at the block's own
 * height and the CheckTx dry run at tip + 1 — both right after per-leg
 * admission and BEFORE the meter reservation, so a refused item has
 * reserved nothing.
 *
 *   price = the committed GAS_PRICE_RAW_PER_UNIT row active at `height`
 *           (nodus_chain_config_get_u64, default 0 — no row = 0).
 *   price 0            → the rule is OFF: return 0 before ANY other
 *                        test. No floor check here, no comparison — the
 *                        flat floors stay where they were (the CORE exec
 *                        hooks, nodus_witness_rt_native.c), so a chain
 *                        without a price row behaves byte-identically to
 *                        0.19.79 (design D3).
 *   all legs SYSTEM    → exempt (governance; its fee must be 0 anyway,
 *                        rt_native's CHAIN_CONFIG exec) — a vote can
 *                        always lower the price again (design G3).
 *   otherwise          → required = res_max_total_units × price, checked
 *                        u64 multiply. An overflow is a VERDICT, not a
 *                        fault: no u64 fee_amount can pay a product that
 *                        does not fit in u64, so "overflow ⇒ refuse" is
 *                        exactly the 128-bit comparison. Refuse when
 *                        fee_amount < max(required, the flat floor).
 *
 * DETERMINISM: the price is read ONLY from committed chain_config rows
 * at the caller's height (the cache and the DB fallback answer
 * identically, nodus_witness_chain_config.c); the exemption reads only
 * the envelope's leg domains; the comparison is total integer
 * arithmetic. No clock, no local setting, no mempool state.
 *
 * @return 0 pass (rule off, exempt, or paid); -1 refused with `*code` =
 *         NODUS_V2_TX_ERR_FEE; -2 the committed price could not be read
 *         on this node — a FAULT, never a verdict (the three-valued
 *         get_u64 contract, nodus_chain_config.h), reason written into
 *         (reason, reason_size).
 *
 * HF-3 (design 2026-10-01-hf3-comet-block-bounds-design.md §0.2): the body
 * is split into its two exported halves, nodus_witness_v2_gas_price_at
 * (the read) and nodus_witness_v2_gas_price_judge (the pure rule), so the
 * proposal seam can read the price ONCE per run and judge every envelope
 * with the SAME rule. env_gas_price_check (below the two) is exactly the
 * two in sequence — the same statements, the same order, the same answers
 * as before the split.
 */
int nodus_witness_v2_gas_price_at(nodus_witness_t *w, uint64_t height,
                                  uint64_t *price_out,
                                  char *reason, size_t reason_size)
{
    uint64_t price = 0;
    int      crc;

    crc = nodus_chain_config_get_u64(
        w, (uint8_t)DNAC_CFG_GAS_PRICE_RAW_PER_UNIT, height, 0ULL, &price);
    if (crc < 0) {
        V2AP_ENV_FAULT("gas price: GAS_PRICE_RAW_PER_UNIT at height %llu "
                       "is unreadable on this node - refusing to judge a "
                       "fee against a guessed price",
                       (unsigned long long)height);
        return -2;
    }
    *price_out = price;
    return 0;
}

int nodus_witness_v2_gas_price_judge(const dna_env_view_t *v, uint64_t price,
                                     uint32_t *code,
                                     char *reason, size_t reason_size)
{
    uint64_t required = 0, floor_fee;
    uint16_t l;
    int      all_system = 1;

    if (price == 0) {
        /* Operator decision D1 (docs/plans/decisions/2026-10-05-nodus-evm-
         * redteam1-operator.md): while the price in force is 0 the EVM
         * stops — a CALL, CREATE or DEPOSIT leg would buy gas for nothing
         * (w_gas units unpriced). The exits stay open: WITHDRAW and
         * REDEEM (fixed 21 000 gas, no code runs). Every other envelope
         * passes exactly as before; an EVM-domain leg never reaches this
         * judge on a chain without the EVM domain (admission / the
         * context table refuse it first — contract: apply.h). */
        for (l = 0; l < v->leg_count; l++) {
            uint32_t op = v->leg[l].runtime_op;

            if (v->leg[l].domain_id == DNA_DOMAIN_EVM &&
                (op == NODUS_RT_EVM_CALL || op == NODUS_RT_EVM_CREATE ||
                 op == NODUS_RT_EVM_DEPOSIT)) {
                V2AP_ENV_VERDICT("gas price: 0 in force - EVM leg %u op %u "
                                 "(CALL / CREATE / DEPOSIT) is refused while "
                                 "gas is unpriced (decision D1)",
                                 (unsigned)l, (unsigned)op);
                *code = NODUS_V2_TX_ERR_FEE;
                return -1;
            }
        }
        return 0;                        /* rule OFF: nothing else runs  */
    }
    for (l = 0; l < v->leg_count; l++) {
        if (v->leg[l].domain_id != DNA_DOMAIN_SYSTEM) {
            all_system = 0;
            break;
        }
    }
    if (all_system) {
        return 0;                        /* governance: exempt           */
    }
    if (dna_ck_mul_u64(v->res_max_total_units, price, &required) != 0) {
        V2AP_ENV_VERDICT("gas price: res_max_total_units %llu x price %llu "
                         "overflows u64 - no fee can pay it",
                         (unsigned long long)v->res_max_total_units,
                         (unsigned long long)price);
        *code = NODUS_V2_TX_ERR_FEE;
        return -1;
    }
    floor_fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                    ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    if (v->fee_amount < required || v->fee_amount < floor_fee) {
        V2AP_ENV_VERDICT("gas price: fee %llu < max(units %llu x price "
                         "%llu = %llu, floor %llu)",
                         (unsigned long long)v->fee_amount,
                         (unsigned long long)v->res_max_total_units,
                         (unsigned long long)price,
                         (unsigned long long)required,
                         (unsigned long long)floor_fee);
        *code = NODUS_V2_TX_ERR_FEE;
        return -1;
    }
    return 0;
}

static int env_gas_price_check(nodus_witness_t *w, const dna_env_view_t *v,
                               uint64_t height, uint32_t *code,
                               char *reason, size_t reason_size)
{
    uint64_t price = 0;

    if (nodus_witness_v2_gas_price_at(w, height, &price, reason,
                                      reason_size) != 0) {
        return -2;                       /* the reader wrote the reason  */
    }
    return nodus_witness_v2_gas_price_judge(v, price, code, reason,
                                            reason_size);
}

/* HF-3 rule 5 (decision 2026-10-01-hf3-comet-only-block-bounds.md answer
 * 10). Contract: nodus_witness_v2_apply.h. The caller has already decided
 * that HF-3 is on (its block-start context's hf3_active). */
int nodus_witness_v2_units_ceiling_check(const dna_env_view_t *v,
                                         uint32_t *code,
                                         char *reason, size_t reason_size)
{
    if (v->res_max_total_units > (uint64_t)INT64_MAX) {
        V2AP_ENV_VERDICT("HF-3: res_max_total_units %llu exceeds INT64_MAX "
                         "- the item's gas_wanted must fit the reference's "
                         "int64 gas",
                         (unsigned long long)v->res_max_total_units);
        *code = NODUS_V2_TX_ERR_CAPACITY;
        return -1;
    }
    return 0;
}

/**
 * THE PER-ENVELOPE AUTHORIZATION STAGE: every leg's authorization
 * COMMITMENT turned into a VERDICT by the resolved runtime's own `auth`
 * hook, against the ENGINE-DERIVED leg auth digest.
 *
 * This is the ONE implementation. The cometbft item loop calls it inside
 * the item's SAVEPOINT, and `nodus_witness_v2_env_dry_run` calls it for
 * the mempool (CheckTx) — because NOTHING ELSE in the tree verifies an
 * envelope's signatures. `dna_env_preflight` says so in its own honest
 * label (env_preflight.h:57-63: it decides nothing about "whether any
 * authorization is VALID"), and the admission lane
 * (`verify_v2_successor_tx`, nodus_witness_verify.c:674-784) runs only
 * the marker, the ruleset table, that preflight, a wire_id comparison
 * and the committed-intent guard. Without this stage at CheckTx a
 * transaction with a forged or corrupted signature is admitted to the
 * mempool and only refused when a block carrying it is applied.
 *
 * (The legacy lane's whole-batch authorization stage, which performed
 * the identical checks inline, is deleted since tokenomics-v3 P4.)
 *
 * `out_verdicts` receives DNA_ENV_MAX_LEGS verdicts (the engine-owned
 * array the exec context later reads); a caller that only wants the
 * yes/no may point it at scratch.
 *
 * `reuse` / `reused_out` (CHECKTX-P1, both NULL on the apply path): a
 * caller-held verdict for an auth_kind-1 or auth_kind-3 (general
 * multisig) leg whose digest equals the one derived here is taken
 * instead of re-running the hook — the recheck cache's light path.
 * auth_kind 2 never takes this branch.
 * `reused_out[l]` (DNA_ENV_MAX_LEGS slots) receives 1 for a reused leg.
 *
 * @return 0 every leg authorized; -1 a leg REFUSED (deterministic — the
 *         same bytes give the same answer on every node); -2 a node-local
 *         backend failure. The reason goes into (reason, reason_size).
 */
static int env_authorize_legs(nodus_witness_t *w,
                              const dna_env_preflight_t *p,
                              dom_ctx_t *doms, size_t n_dom,
                              const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                              uint64_t height, uint64_t epoch,
                              const nodus_rt_committee_t *cm,
                              const nodus_v2_auth_reuse_t *reuse,
                              uint8_t *reused_out,
                              nodus_rt_auth_verdict_t *out_verdicts,
                              char *reason, size_t reason_size)
{
    const dna_env_view_t *v = &p->view;
    uint16_t l;
    uint64_t tc_fee = 0;
    uint8_t  hf2 = 0;
    uint8_t  gen2_voted = 0;
    uint8_t  gen_storage_voted = 0;
    uint64_t name_price[4];

    /* W-C: every ctx the engine builds carries the committed
     * token-creation fee (runtime.h contract); no auth hook reads it
     * today, but a hook must never see a ctx whose engine facts are
     * partly zero. Same read, same fault rule as exec_one_env. HF-2's
     * switch rides along for the same reason (the auth hook computes the
     * power sums unconditionally and does not read it), and so do
     * HF-4's and the storage vote's single-use facts (no auth hook reads
     * either). */
    if (env_token_create_fee(w, height, &tc_fee, reason, reason_size) != 0)
        return -2;
    if (env_hf2_active(w, height, &hf2, reason, reason_size) != 0)
        return -2;
    if (env_ruleset_gen2_voted(w, &gen2_voted, reason, reason_size) != 0)
        return -2;
    if (env_ruleset_gen_storage_voted(w, &gen_storage_voted, reason,
                                      reason_size) != 0)
        return -2;
    if (env_name_prices(w, height, name_price, reason, reason_size) != 0)
        return -2;
    /* Nodus EVM: the EVM_ACTIVE facts and the EVM block gas limit ride along
     * like the facts above (no auth hook reads them) */
    nodus_rt_exec_ctx_t evm_facts;
    memset(&evm_facts, 0, sizeof(evm_facts));
    if (env_evm_facts(w, height, &evm_facts, reason, reason_size) != 0)
        return -2;
    for (l = 0; l < v->leg_count; l++) {
        dom_ctx_t          *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        nodus_rt_exec_ctx_t actx;
        int                 arc;

        if (!d || !d->rt || !d->rt->auth) {
            V2AP_ENV_FAULT("auth: domain %u lost its runtime or auth hook "
                           "between admission and verification (leg %u) - "
                           "engine invariant broken on this node",
                           (unsigned)v->leg[l].domain_id, (unsigned)l);
            return -2;
        }
        if (reused_out) {
            reused_out[l] = 0;
        }
        if (reuse && l < reuse->leg_count && reuse->present &&
            reuse->digest && reuse->verdict && reuse->present[l] &&
            (v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 ||
             v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1) &&
            memcmp(reuse->digest[l], p->auth_digest[l], 64) == 0 &&
            reuse->verdict[l].n_signers >= 1 &&
            reuse->verdict[l].n_signers <= NODUS_RT_AUTH_MAX_SIGNERS &&
            /* general multisig (F1.3): a kind-3 verdict carries its
             * descriptor facts, a kind-1 verdict none — the cache key
             * is the wire_id, which commits the auth bytes, so the
             * cached facts are the ones the hook would recompute */
            (v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_MSIG_V1
                 ? (reuse->verdict[l].n_msig >= 1 &&
                    reuse->verdict[l].n_msig <= NODUS_RT_MSIG_MAX_DESC)
                 : (reuse->verdict[l].n_msig == 0))) {
            out_verdicts[l] = reuse->verdict[l];
            if (reused_out) {
                reused_out[l] = 1;
            }
            continue;
        }
        memset(&actx, 0, sizeof(actx));
        actx.chain_id            = chain_id;
        actx.global_height       = height;
        actx.epoch               = epoch;
        actx.wire_id             = p->wire_id;
        actx.intent_id           = p->intent_id;
        actx.auth_context_commit = p->auth_context_commit;
        actx.leg_auth_digest     = p->auth_digest[l];
        actx.token_create_fee    = tc_fee;
        actx.hf2_active          = hf2;
        actx.ruleset_gen2_voted  = gen2_voted;
        actx.ruleset_gen_storage_voted = gen_storage_voted;
        memcpy(actx.name_price, name_price, sizeof(actx.name_price));
        /* Nodus EVM: the gas limit rides along like the facts above; the auth
         * stage has no block time (the dry run has no header) and no auth
         * hook reads either — block_time_s stays 0 here (runtime.h) */
        actx.evm_block_gas_limit = evm_facts.evm_block_gas_limit;
        actx.hf3_active          = evm_facts.hf3_active;
        actx.gas_price_on        = evm_facts.gas_price_on;
        actx.evm_active_voted    = evm_facts.evm_active_voted;
        actx.chain_initial_height = evm_facts.chain_initial_height;
        /* the resolved snapshot view, ONLY for the kind that consumes it
         * (runtime.h's ctx contract) */
        actx.committee =
            v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_CC_V1
                ? cm : NULL;
        arc = d->rt->auth(d->rt, v, l, &actx, &out_verdicts[l]);
        if (arc == -2) {
            V2AP_ENV_FAULT("auth: the verification backend failed for leg "
                           "%u domain %u auth_kind %u", (unsigned)l,
                           (unsigned)d->domain_id,
                           (unsigned)v->leg[l].auth_kind);
            return -2;
        }
        if (arc != 0) {
            V2AP_ENV_VERDICT("auth: leg %u domain %u auth_kind %u FAILED "
                             "verification against the engine-derived leg "
                             "digest (rc %d)", (unsigned)l,
                             (unsigned)d->domain_id,
                             (unsigned)v->leg[l].auth_kind, arc);
            return -1;
        }
    }
    return 0;
}

/**
 * ONE ENVELOPE'S JUDGEMENT CONTEXT at the candidate height — the
 * working set of the mempool-side entry `nodus_witness_v2_env_dry_run`:
 * the candidate height, the chain id, the domain snapshot, the
 * block-start context, the item's own preflight and the governing
 * committee. CHECKTX-P1 lifted it, statement for statement, out of the
 * former signature-only entry `nodus_witness_v2_env_authorize` (deleted
 * in round 2 — the dry run subsumes it).
 */
typedef struct {
    uint64_t                      height;
    uint8_t                       chain_id[DNA_CHAIN_ID_LEN];
    nodus_witness_v2_block_ctx_t *bctx;
    dom_ctx_t                    *doms;
    size_t                        n_dom;
    dna_env_preflight_t          *pf;
    uint8_t                      *cm_pubkeys;
    uint8_t                     (*cm_fps)[64];
    uint64_t                     *cm_powers;
    nodus_rt_committee_t          cmview;
} env_item_setup_t;

static void env_item_setup_free(env_item_setup_t *s)
{
    free(s->cm_pubkeys);
    free(s->cm_fps);
    free(s->cm_powers);
    free(s->pf);
    doms_free(s->doms);
    free(s->bctx);
    memset(s, 0, sizeof(*s));
}

/**
 * Build `s` for one envelope. The preflight classes follow the item
 * loop's: a decode failure or a leg outside the committed context table
 * is DECODE / CONTEXT; the preflight's own ERR_CTX_* is CONTEXT, every
 * other preflight refusal DECODE, and ERR_HASH is this node's hash
 * backend — a FAULT, never a verdict (env_preflight.h's rule, the item
 * loop's own routing).
 *
 * @return 0 built; -1 refused with `*code` set; -2 node-local fault.
 *         The reason goes into (reason, reason_size). `s` is always safe
 *         to pass to env_item_setup_free.
 */
static int env_item_setup(nodus_witness_t *w, const uint8_t *bytes,
                          size_t len, env_item_setup_t *s, uint32_t *code,
                          char *reason, size_t reason_size)
{
    dna_env_leg_ctx_t          lctx[DNA_ENV_MAX_LEGS];
    dna_env_view_t             probe;
    dna_env_preflight_status_t pfst;
    uint64_t                   tip = 0;
    uint16_t                   l;

    memset(s, 0, sizeof(*s));
    memset(&probe, 0, sizeof(probe));
    *code = NODUS_V2_TX_OK;

    /* The CANDIDATE height, exactly as the admission lane picks it
     * (nodus_witness_verify.c:735-741): an envelope is judged at the
     * height it would be INCLUDED in, not at the tip. The tip read is
     * the engine's own — the same statement phase 0 uses — so a chain
     * with no block rows at all (the cometbft lane's genesis) answers 0
     * and the candidate is 1, which is that lane's first block. */
    if (sum_q(w, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
              &tip) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the chain height is unreadable on this "
                       "node");
        return -2;
    }
    s->height = tip + 1;
    if (nodus_witness_v2_chain_id(w, s->chain_id) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the chain id is underivable on this "
                       "node");
        return -2;
    }
    s->bctx = calloc(1, sizeof(*s->bctx));
    s->doms = calloc(MAX_DOMS, sizeof(*s->doms));
    s->pf   = calloc(1, sizeof(*s->pf));
    if (!s->bctx || !s->doms || !s->pf) {
        V2AP_ENV_FAULT("%s", "auth: the working set could not be allocated");
        return -2;
    }
    if (doms_load(w, s->doms, &s->n_dom, /*strict_active=*/1) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the domain registry / heads / runtime "
                       "tuples are unreadable on this node");
        return -2;
    }
    /* HF-3 D1 (a): the context is built at the candidate height (tip + 1)
     * the whole dry run uses, so its switch is the one the item would be
     * judged under. */
    if (block_ctx_from_doms(w, s->height, s->doms, s->n_dom, s->bctx) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the block-start context could not be "
                       "built on this node");
        return -2;
    }
    /* the positional ruleset table, as the item loop builds it */
    if (dna_env_decode(bytes, len, &probe) != 0) {
        V2AP_ENV_VERDICT("%s", "auth: the envelope does not decode");
        *code = NODUS_V2_TX_ERR_DECODE;
        return -1;
    }
    for (l = 0; l < probe.leg_count; l++) {
        size_t k;
        int    found = 0;

        for (k = 0; k < s->bctx->n_rulesets; k++) {
            if (s->bctx->rulesets[k].domain_id == probe.leg[l].domain_id) {
                lctx[l] = s->bctx->rulesets[k];
                found = 1;
                break;
            }
        }
        if (!found) {
            V2AP_ENV_VERDICT("auth: leg %u names domain %u, which has no "
                             "entry in the committed context table",
                             (unsigned)l, (unsigned)probe.leg[l].domain_id);
            *code = NODUS_V2_TX_ERR_CONTEXT;
            return -1;
        }
    }
    pfst = dna_env_preflight(bytes, len, s->chain_id, s->height, lctx,
                             probe.leg_count, s->pf);
    if (pfst != DNA_ENV_PF_OK) {
        if (pfst == DNA_ENV_PF_ERR_HASH) {
            V2AP_ENV_FAULT("%s", "auth: the preflight's hash backend failed "
                           "on this node");
            return -2;
        }
        V2AP_ENV_VERDICT("%s", "auth: the envelope failed preflight");
        *code = (pfst == DNA_ENV_PF_ERR_CTX_COUNT ||
                 pfst == DNA_ENV_PF_ERR_CTX_DOMAIN ||
                 pfst == DNA_ENV_PF_ERR_CTX_VERSION)
                    ? NODUS_V2_TX_ERR_CONTEXT
                    : NODUS_V2_TX_ERR_DECODE;
        return -1;
    }
    /* the governing committee for the SAME candidate height the item
     * loop would use */
    {
        int crc = committee_snapshot_for_height(w, s->height, &s->cmview,
                                                &s->cm_pubkeys, &s->cm_fps,
                                                &s->cm_powers,
                                                reason, reason_size);
        if (crc != 0) {
            if (crc == 1) {
                V2AP_ENV_FAULT("%s", "auth: the governing committee height "
                               "would be below genesis");
            }
            return -2;                   /* the helper wrote the reason  */
        }
    }
    return 0;
}

void nodus_witness_v2_env_dry_run_free(nodus_v2_env_dry_run_t *out)
{
    if (!out) {
        return;
    }
    free(out->rows);
    out->rows   = NULL;
    out->n_rows = 0;
}

/* Contract: nodus_witness_v2_apply.h. The stage ORDER is the Comet item
 * loop's (v2_apply_block_body, "4-6b"): preflight → replay → admission →
 * gas price (HF-1) → reserve → authorization → execute. Every stage is
 * the item loop's own
 * helper; the one-item "block" the exec body is handed carries only the
 * candidate height and its epoch (no fault injection, no claims). */
int nodus_witness_v2_env_dry_run(nodus_witness_t *w, const uint8_t *bytes,
                                 size_t len,
                                 const nodus_v2_auth_reuse_t *reuse,
                                 nodus_v2_env_dry_run_t *out,
                                 char *reason, size_t reason_size)
{
    return nodus_witness_v2_env_dry_run_ex(w, bytes, len, reuse, 0, NULL,
                                           NULL, out, reason, reason_size);
}

/* Red-team 1 F1 — the pending-conflict probe of every ABI-2 leg, after
 * the authorization stage (the keys need the VERIFIED signer) and before
 * anything executes. The keys come from the ONE derivation
 * (nodus_rt_evm_conflict_keys) and are filed under the leg's domain the
 * way dry_run_note_evm_keys files them, so the probe sees exactly the
 * rows the caller later inserts. @return 0 / -1 verdict / -2 fault. */
static int dry_run_probe_evm(const dna_env_view_t *v, dom_ctx_t *doms,
                             size_t n_dom,
                             const nodus_rt_auth_verdict_t *verdicts,
                             nodus_v2_conflict_probe_fn probe,
                             void *probe_ctx,
                             char *reason, size_t reason_size)
{
    for (uint16_t l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        nodus_rt_v2_keys_t keys;
        nodus_v2_dry_run_row_t rows[NODUS_RT_V2_MAX_KEYS];
        int prc;

        if (!d || !d->rt || d->rt->runtime_abi != NODUS_DOMAIN_RUNTIME_ABI_V2)
            continue;
        if (nodus_rt_evm_conflict_keys(v, l, &verdicts[l], &keys) != 0) {
            /* the pre-validation's prologue refuses the same head / the
             * same signer count (rtevm_prologue: one codec) */
            V2AP_ENV_VERDICT("dry run: env leg %u: the EVM call head or its "
                             "signer does not yield conflict keys",
                             (unsigned)l);
            return -1;
        }
        if (keys.n > NODUS_RT_V2_MAX_KEYS) {
            V2AP_ENV_FAULT("dry run: leg %u: %u conflict keys exceed the "
                           "bound", (unsigned)l, (unsigned)keys.n);
            return -2;
        }
        for (uint8_t k = 0; k < keys.n; k++) {
            memset(&rows[k], 0, sizeof(rows[k]));
            rows[k].domain_id = d->domain_id;
            rows[k].op_id     = keys.k[k].op_id;
            rows[k].key_len   = keys.k[k].key_len;
            memcpy(rows[k].key, keys.k[k].key, keys.k[k].key_len);
        }
        prc = probe(probe_ctx, rows, keys.n);
        if (prc == -2) {
            V2AP_ENV_FAULT("dry run: leg %u: the pending-conflict probe "
                           "failed on this node", (unsigned)l);
            return -2;
        }
        if (prc != 0) {
            V2AP_ENV_VERDICT("dry run: leg %u: a pending mempool entry "
                             "already holds this EVM sender's nonce / this "
                             "ticket", (unsigned)l);
            return -1;
        }
    }
    return 0;
}

/* Contract: nodus_witness_v2_apply.h (Nodus EVM: `novm`; red-team 1 F1:
 * `probe`). */
int nodus_witness_v2_env_dry_run_ex(nodus_witness_t *w, const uint8_t *bytes,
                                    size_t len,
                                    const nodus_v2_auth_reuse_t *reuse,
                                    int novm,
                                    nodus_v2_conflict_probe_fn probe,
                                    void *probe_ctx,
                                    nodus_v2_env_dry_run_t *out,
                                    char *reason, size_t reason_size)
{
    env_item_setup_t     s;
    nodus_v2_block_t    *blk    = NULL;
    dna_meter_t         *meter  = NULL;
    nodus_rt_read_res_t *reads  = NULL;
    uint8_t             *resbuf = NULL;
    const dna_env_view_t *v;
    uint32_t             code = NODUS_V2_TX_OK;
    uint16_t             l;
    int                  ret;

    if (reason && reason_size) {
        reason[0] = '\0';
    }
    if (!out) {
        return -2;
    }
    memset(out, 0, sizeof(*out));
    if (!w || !w->db || !bytes || len == 0) {
        return -2;
    }

    /* ── preflight at tip + 1 (and the committee the auth stage reads) */
    ret = env_item_setup(w, bytes, len, &s, &code, reason, reason_size);
    if (ret != 0) {
        goto done;
    }
    v = &s.pf->view;
    memcpy(out->wire_id, s.pf->wire_id, 64);
    memcpy(out->intent_id, s.pf->intent_id, 64);
    out->leg_count = v->leg_count;
    for (l = 0; l < v->leg_count; l++) {
        out->auth_kind[l] = v->leg[l].auth_kind;
        memcpy(out->leg_digest[l], s.pf->auth_digest[l], 64);
    }

    /* ── replay: the committed intent / wire index ─────────────────── */
    {
        int hit = 0;

        ret = env_replay_guard(w, s.pf, 0, &hit, reason, reason_size);
        if (ret != 0) {
            goto done;
        }
        if (hit) {
            V2AP_ENV_VERDICT("%s", "dry run: the intent or the wire id is "
                             "already committed");
            code = NODUS_V2_TX_ERR_REPLAY;
            ret = -1;
            goto done;
        }
    }

    /* ── admission, per leg — a one-item block (n_envs 1) ──────────── */
    ret = env_admit_legs(v, s.doms, s.n_dom, 1, 0, &code, reason,
                         reason_size);
    if (ret == -1) {
        V2AP_ENV_VERDICT("dry run: per-leg admission refused the item "
                         "(code %u)", (unsigned)code);
    }
    if (ret != 0) {
        goto done;
    }

    /* ── HF-1 gas price at the SAME candidate height (tip + 1) the
     * preflight and the committee used — the item loop's own helper,
     * which writes its own verdict / fault text ─────────────────────── */
    ret = env_gas_price_check(w, v, s.height, &code, reason, reason_size);
    if (ret != 0) {
        goto done;
    }

    /* ── HF-3 rule 5: the declared ceiling fits int64 — from the HF-3
     * height only (the context's switch, built at the same tip + 1), the
     * item loop's own order: after the gas price, before the reserve ── */
    if (s.bctx->hf3_active) {
        ret = nodus_witness_v2_units_ceiling_check(v, &code, reason,
                                                   reason_size);
        if (ret != 0) {
            goto done;
        }
    }

    /* ── reserve against a FRESH block budget (the block-start context
     * this call built is untouched by anything else) ────────────────── */
    meter = calloc(1, sizeof(*meter));
    if (!meter) {
        V2AP_ENV_FAULT("%s", "dry run: the meter could not be allocated");
        ret = -2;
        goto done;
    }
    {
        /* Nodus EVM: an ABI-2 leg is reserved as a streamed leg — the item
         * loop's own rule (env_stream_leg is 0 on every chain without an
         * ABI-2 runtime, so this is dna_meter_reserve there) */
        dna_meter_status_t mst = dna_meter_reserve_ex(
            meter, s.bctx->policy, v, &s.bctx->budget,
            env_stream_leg(v, s.doms, s.n_dom));

        if (mst == DNA_METER_ERR_FAULT) {
            V2AP_ENV_FAULT("%s", "dry run: the meter reported an accounting "
                           "fault on this node");
            ret = -2;
            goto done;
        }
        if (mst != DNA_METER_OK) {
            V2AP_ENV_VERDICT("dry run: the reservation against a fresh "
                             "block budget refused the item (meter status "
                             "%d)", (int)mst);
            code = NODUS_V2_TX_ERR_CAPACITY;
            ret = -1;
            goto done;
        }
    }

    /* ── authorization: the ONE stage (reuse only for kind 1) ──────── */
    ret = env_authorize_legs(w, s.pf, s.doms, s.n_dom, s.chain_id, s.height,
                             nodus_v2_epoch_for_height(s.height), &s.cmview,
                             reuse, out->verdict_reused, out->verdict,
                             reason, reason_size);
    if (ret == -1) {
        code = NODUS_V2_TX_ERR_AUTH;
    }
    if (ret != 0) {
        goto done;
    }

    /* ── red-team 1 F1: the pending-conflict PROBE (non-mutating) of
     * every ABI-2 leg — after the authorization stage, before anything
     * executes or pre-validates; the caller inserts the keys only after
     * this whole run succeeded ─────────────────────────────────────── */
    if (probe) {
        ret = dry_run_probe_evm(v, s.doms, s.n_dom, out->verdict, probe,
                                probe_ctx, reason, reason_size);
        if (ret == -1) {
            code = NODUS_V2_TX_ERR_EXEC;
        }
        if (ret != 0) {
            goto done;
        }
    }

    /* ── execute: the per-envelope body, probe-only ─────────────────── */
    blk    = calloc(1, sizeof(*blk));
    reads  = calloc(NODUS_RT_MAX_READS, sizeof(*reads));
    resbuf = calloc(1, DNA_EFFECT_MAX_TOTAL_LEN);
    if (!blk || !reads || !resbuf) {
        V2AP_ENV_FAULT("%s", "dry run: the execution working set could not "
                       "be allocated");
        ret = -2;
        goto done;
    }
    blk->global_height = s.height;
    blk->epoch         = nodus_v2_epoch_for_height(s.height);
    blk->fail_at       = V2AP_FAIL_NONE;
    /* Nodus EVM (design §10 "CheckTx simülasyonu tip bloğunun zamanını
     * kullanır"): an ABI-2 (EVM) leg that EXECUTES sees TIMESTAMP = the
     * committed tip block's header seconds — the same read the §18 RPC
     * simulation uses. Only then: an ordinary envelope reads no block
     * store, and the `novm` mode runs no VM (its shared pre-validation
     * reads no block time — evm_tx.c tx_validate). Since red-team 1 F1
     * CheckTx runs `novm` for every entry, so this read serves only the
     * executing mode (novm 0 — nodus_witness_v2_env_dry_run's callers).
     * Unreadable = FAULT, like the other unreadable-tip paths here.
     * FinalizeBlock runs on the decided block's own header time. */
    if (!novm && env_stream_leg(v, s.doms, s.n_dom) != 0 &&
        nodus_witness_v2_tip_block_time(w, s.height - 1,
                                        &blk->timestamp) != 0) {
        V2AP_ENV_FAULT("dry run: the tip block's (height %llu) header "
                       "time is unreadable on this node",
                       (unsigned long long)(s.height - 1));
        ret = -2;
        goto done;
    }
    ret = exec_one_env(w, blk, 0, s.chain_id, blk->epoch, s.doms, s.n_dom,
                       s.pf, meter, out->verdict, reads, resbuf, out,
                       novm ? 1 : 0, NULL, reason, reason_size);
    if (ret == -1) {
        code = NODUS_V2_TX_ERR_EXEC;
    }

done:
    if (meter) {
        meters_abort_all(meter, 1);      /* a refused item's reservation */
    }
    out->code = (ret == -1) ? code : NODUS_V2_TX_OK;
    free(resbuf);
    free(reads);
    free(blk);
    free(meter);
    env_item_setup_free(&s);
    return ret;
}

/**
 * ONE CLAIM'S PRE-EXECUTION DERIVATION: shape, the committed manifest,
 * its distribution section, the distribution leaf hash and the canonical
 * NULLIFIER — the claim's semantic identity.
 *
 * FACTORED OUT of the legacy lane's pre-BEGIN claim scan (deleted with
 * that lane, tokenomics-v3 P4), logic unchanged: the cometbft lane runs
 * it for ONE claim inside that claim's own SAVEPOINT. It is a pure
 * function of
 * the claim's bytes and COMMITTED context — `dna_claim_validate`,
 * `nodus_witness_v2_manifest_load_by_hash`, `dna_dist_leaf_hash` and
 * `dna_claim_nullifier` (the "NDS.CLNUL.v1" preimage over chain,
 * manifest hash, target domain, target asset and leaf) — so moving WHEN
 * it runs cannot change WHAT it answers.
 *
 * ⚠ TRI-STATE, TV3-P0 item 2 — the conflation the engine's header used to
 * record is CLOSED here: `nodus_witness_v2_manifest_load_by_hash`'s own
 * contract already splits "not committed" (1, deterministic) from "local
 * read/corruption fault" (-1, node-local), and this function now maps
 * those two into ITS OWN -1 VERDICT / -2 FAULT rather than folding both
 * into one code the way its caller used to.
 *
 * @param out_target receives the manifest's target domain id.
 * @return 0 with `out_nul` and `out_target` filled; -1 VERDICT / -2 FAULT,
 *         with the reason written into (reason, reason_size).
 */
static int claim_prescan_one(nodus_witness_t *w, const dna_claim_t *c,
                             size_t idx, uint8_t out_nul[64],
                             uint32_t *out_target,
                             char *reason, size_t reason_size)
{
    dna_gman_t      m;
    dna_dist_leaf_t leaf;
    uint8_t         leaf_hash[64];
    int             mrc;

    if (dna_claim_validate(c) != 0) {
        V2AP_ENV_VERDICT("claim %llu failed dna_claim_validate "
                         "(malformed shape)", (unsigned long long)idx);
        return -1;
    }
    mrc = nodus_witness_v2_manifest_load_by_hash(w, c->manifest_hash, &m);
    if (mrc < 0) {
        char h[17];

        V2AP_ENV_FAULT("claim %llu: manifest %s lookup faulted on this "
                       "node (read/corruption)",
                       (unsigned long long)idx,
                       v2ap_hex8(c->manifest_hash, h));
        return -2;
    }
    if (mrc > 0) {
        char h[17];

        V2AP_ENV_VERDICT("claim %llu names manifest %s, which is not "
                         "committed here",
                         (unsigned long long)idx,
                         v2ap_hex8(c->manifest_hash, h));
        return -1;
    }
    if (m.dist_present != 1) {
        V2AP_ENV_VERDICT("claim %llu names a manifest with no distribution "
                         "section (dist_present %u)",
                         (unsigned long long)idx, (unsigned)m.dist_present);
        return -1;
    }
    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version  = DNA_DIST_VERSION;
    leaf.source_id_len = c->source_id_len;
    memcpy(leaf.source_id, c->source_id, c->source_id_len);
    leaf.source_amount = c->source_amount;
    memcpy(leaf.dest_binding, c->dest_binding, 64);
    if (dna_dist_leaf_hash(&leaf, leaf_hash) != 0) {
        V2AP_ENV_FAULT("claim %llu: distribution leaf hash backend failed",
                       (unsigned long long)idx);
        return -2;
    }
    if (dna_claim_nullifier(c->chain_id, c->manifest_hash,
                            m.target_domain_id, m.target_asset_ref,
                            m.target_asset_len, leaf_hash, out_nul) != 0) {
        V2AP_ENV_FAULT("claim %llu: nullifier hash backend failed for "
                       "target domain %u", (unsigned long long)idx,
                       (unsigned)m.target_domain_id);
        return -2;
    }
    *out_target = m.target_domain_id;
    return 0;
}

/* Contract: nodus_witness_v2_apply.h. The claim lane's own derivation,
 * `claim_prescan_one`, over the claim's decoded bytes. */
int nodus_witness_v2_claim_nullifier(nodus_witness_t *w, const uint8_t *bytes,
                                     size_t len, uint8_t out_nul[64])
{
    dna_claim_t *c;
    char         reason[NODUS_V2_APPLY_REASON_MAX];
    uint32_t     target = 0;
    int          rc;

    if (!w || !w->db || !bytes || len == 0 || !out_nul) {
        return -2;
    }
    c = calloc(1, sizeof(*c));                       /* large — heap     */
    if (!c) {
        return -2;
    }
    if (dna_claim_decode(bytes, len, c) != 0) {
        free(c);
        return -1;
    }
    reason[0] = '\0';
    rc = claim_prescan_one(w, c, 0, out_nul, &target, reason,
                           sizeof(reason));
    free(c);
    return rc;
}

/**
 * ONE CLAIM'S EXECUTION: admission, the derived-nullifier cross-check and
 * the three write stages — target-runtime output, spent-claim insert,
 * distribution-state decrement.
 *
 * FACTORED OUT of the legacy lane's phase 6b (deleted with that lane,
 * tokenomics-v3 P4), logic unchanged: the cometbft lane runs it for ONE
 * claim inside that claim's SAVEPOINT. The fault points fire exactly
 * where they did.
 *
 * ⚠ TRI-STATE, TV3-P0 item 2. `nodus_witness_v2_claim_admit` now answers
 * 0 / -1 VERDICT / -2 FAULT (header contract); this function propagates
 * that split. The three EXECUTE-stage helpers below it (output_create /
 * spend_insert / state_update) return 0 / -2 ONLY by their OWN header
 * contract — by EXECUTE time the verdict is already settled, so nothing
 * they can fail on is a new judgement about this claim.
 *
 * The three `blk->fail_at == V2AP_FAIL_AFTER_CLAIM_*` blocks are TEST
 * HARNESS fault-injection points, not real check failures, and are left
 * returning -1 unchanged so the existing F16/F17/F18 fault-point tests
 * keep pinning exactly the code path they always have.
 *
 * @return 0; -1 VERDICT / -2 FAULT, reason written into (reason,
 *         reason_size).
 */
static int claim_execute_one(nodus_witness_t *w, const nodus_v2_block_t *blk,
                             size_t idx, const uint8_t expect_nul[64],
                             char *reason, size_t reason_size)
{
    const dna_claim_t      *c = &blk->claims[idx];
    nodus_v2_claim_admit_t  adm;
    uint8_t                 output_id[64];
    int                     arc;

    arc = nodus_witness_v2_claim_admit(w, c, blk->global_height, &adm);
    if (arc == -2) {
        V2AP_ENV_FAULT("phase 6b: claim %llu admission faulted on this "
                       "node (chain id / manifest / spent-set / remaining-"
                       "cover read, runtime resolution, or a SHA3 backend "
                       "call)", (unsigned long long)idx);
        return -2;
    }
    if (arc != 0) {
        V2AP_ENV_VERDICT("phase 6b: claim %llu refused at admission",
                         (unsigned long long)idx);
        return -1;
    }
    if (memcmp(adm.nullifier, expect_nul, 64) != 0) {
        char a[17], p[17];

        V2AP_ENV_VERDICT("phase 6b: claim %llu nullifier %s from admission "
                         "disagrees with the derivation %s",
                         (unsigned long long)idx,
                         v2ap_hex8(adm.nullifier, a),
                         v2ap_hex8(expect_nul, p));
        return -1;
    }
    if (nodus_witness_v2_claim_output_create(w, c, &adm, blk->global_height,
                                             output_id) != 0) {
        V2AP_ENV_FAULT("phase 6b: claim %llu target-runtime output "
                       "creation faulted on this node",
                       (unsigned long long)idx);
        return -2;
    }
    if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_OUTPUT &&
        blk->fail_claim_index == (uint32_t)idx) {
        V2AP_ENV_VERDICT("fault-injection point V2AP_FAIL_AFTER_CLAIM_OUTPUT "
                         "fired after claim %llu (test harness; no real "
                         "check failed)", (unsigned long long)idx);
        return -1;
    }
    if (nodus_witness_v2_claim_spend_insert(w, c, &adm, output_id,
                                            blk->global_height) != 0) {
        V2AP_ENV_FAULT("phase 6b: claim %llu spent-claim insert faulted "
                       "on this node", (unsigned long long)idx);
        return -2;
    }
    if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_SPEND &&
        blk->fail_claim_index == (uint32_t)idx) {
        V2AP_ENV_VERDICT("fault-injection point V2AP_FAIL_AFTER_CLAIM_SPEND "
                         "fired after claim %llu (test harness; no real "
                         "check failed)", (unsigned long long)idx);
        return -1;
    }
    if (nodus_witness_v2_claim_state_update(w, adm.manifest_hash,
                                            adm.converted) != 0) {
        V2AP_ENV_FAULT("phase 6b: claim %llu distribution-state decrement "
                       "faulted on this node", (unsigned long long)idx);
        return -2;
    }
    if (blk->fail_at == V2AP_FAIL_AFTER_CLAIM_STATE &&
        blk->fail_claim_index == (uint32_t)idx) {
        V2AP_ENV_VERDICT("fault-injection point V2AP_FAIL_AFTER_CLAIM_STATE "
                         "fired after claim %llu (test harness; no real "
                         "check failed)", (unsigned long long)idx);
        return -1;
    }
    return 0;
}

/**
 * ONE APPLIED ITEM'S INDEX ROWS — the semantic index first
 * (`v2_intent_index`: intent_id PK + its ONE accepted wire realization),
 * then the wire index `v2_tx_index` (the `v2_tx_local_index` row follows
 * in phase 12, which alone knows the domain head height).
 *
 * FACTORED OUT of phase 12 with the logic unchanged: the cometbft lane
 * writes these rows INSIDE the item's own SAVEPOINT — so that a refused
 * item leaves none. (The legacy lane's whole-batch copy of this writer is
 * deleted since tokenomics-v3 P4.)
 *
 * `gidx` is the item's GLOBAL INDEX in the block: its position among the
 * APPLIED items, so a refused item consumes no index.
 *
 * A UNIQUE-constraint violation here means this node's replay guard and
 * this write disagree — an engine/storage fault on THIS node, never a
 * block property; every failure is therefore the caller's -2.
 *
 * @return 0; -1 with the reason written into (reason, reason_size).
 */
static int cmt_item_index(nodus_witness_t *w, uint64_t global_height,
                          const dna_env_preflight_t *p, dom_ctx_t *doms,
                          size_t n_dom, uint32_t gidx,
                          char *reason, size_t reason_size)
{
    const dna_env_view_t *v = &p->view;
    uint32_t touched_ids[DNA_ENV_MAX_LEGS];
    uint8_t  tl[2 + 4 * DNA_TOUCHED_MAX];   /* domain_wire.h:450, :500-505 */
    size_t   tw = 0;
    uint32_t owner;
    uint16_t t;
    sqlite3_stmt *st = NULL;
    int rc;

    /* v2_intent_index */
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_intent_index (intent_id, tx_id, "
            "global_height, global_index) VALUES (?1,?2,?3,?4)",
            -1, &st, NULL) != SQLITE_OK) {
        V2AP_ENV_FAULT("index: could not prepare the v2_intent_index "
                       "insert at global index %u", (unsigned)gidx);
        return -1;
    }
    sqlite3_bind_blob(st, 1, p->intent_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, p->wire_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)global_height);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)gidx);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        V2AP_ENV_FAULT("index: v2_intent_index insert at global index %u "
                       "failed (sqlite rc %d)", (unsigned)gidx, rc);
        return -1;
    }

    /* v2_tx_index. The touched list is built exactly as phase 12 builds
     * it: the leg domains in leg order (an envelope's legs are strictly
     * ascending by construction, which is what the canonical encoder
     * requires — domain_wire.h:502-505). */
    if (v->leg_count > DNA_TOUCHED_MAX) {
        V2AP_ENV_FAULT("index: the item at global index %u declares %u "
                       "legs; the touched-set encoding admits at most %u",
                       (unsigned)gidx, (unsigned)v->leg_count,
                       (unsigned)DNA_TOUCHED_MAX);
        return -1;
    }
    for (t = 0; t < v->leg_count; t++) {
        touched_ids[t] = v->leg[t].domain_id;
    }
    if (dna_touched_encode(touched_ids, (uint16_t)v->leg_count, tl,
                           sizeof(tl), &tw) != 0) {
        V2AP_ENV_FAULT("index: touched-set encoding for the item at "
                       "global index %u (%u legs) failed",
                       (unsigned)gidx, (unsigned)v->leg_count);
        return -1;
    }
    owner = (v->leg_count == 1) ? v->leg[0].domain_id : DNA_TX_OWNER_NONE;
    st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO v2_tx_index (global_height, global_index, "
            "tx_id, owner_domain, touched, wire_version) "
            "VALUES (?1,?2,?3,?4,?5,3)", -1, &st, NULL) != SQLITE_OK) {
        V2AP_ENV_FAULT("index: could not prepare the v2_tx_index insert "
                       "at global index %u", (unsigned)gidx);
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)global_height);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
    sqlite3_bind_blob(st, 3, p->wire_id, 64, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)owner);
    sqlite3_bind_blob(st, 5, tl, (int)tw, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        V2AP_ENV_FAULT("index: v2_tx_index insert at global index %u "
                       "failed (sqlite rc %d)", (unsigned)gidx, rc);
        return -1;
    }

    (void)doms;
    (void)n_dom;
    /* v2_tx_local_index is NOT written here, and cannot be: its
     * `domain_height` column is `d->newhead.domain_height` (phase 12's
     * own binding), a value the domain-head phase computes AFTER every
     * item has executed. In the Comet lane the local rows are therefore
     * written in phase 12 for the APPLIED items only — a refused item
     * never enters `d->wire_ids`, so it gets no local row there either,
     * and the two identity rows it did write went away with its
     * SAVEPOINT. */
    return 0;
}

/* The engine body. `nodus_witness_v2_apply_block` (below the body) is
 * the public entry and is where the cometbft lane's ONE global rule is
 * applied: a DECIDED block is never refused, so every -1 this body would
 * return becomes -2 there. Splitting it that way keeps each refusal site
 * below saying exactly WHY it refused — the reason text is unchanged —
 * while the CLASS is corrected in one auditable place. */
/*
 * PHASE 6b' — HF-4 RULE-SET GENERATION SWITCH (design docs/plans/
 * 2026-10-02-onchain-names-design.md rev 4 §1.3-§1.4; decision
 * docs/plans/decisions/2026-10-02-onchain-names.md).
 *
 * EDGE TRIGGER at block h (idempotent — replay of h switches exactly
 * once, because the host rolls a faulted block back whole):
 *   param 9 (RULESET_GEN2) present at h+1 AND absent at h — i.e. the
 *   committed row's effective height H is h+1 — and
 *     the registry's SYSTEM and CORE manifests are generation 1 → switch;
 *     the registry is anything else → node FAULT;
 *   otherwise → nothing.
 * Either read unanswerable → node FAULT, never "absent". The row's value
 * must be the compiled D2 (the scalar rules admit nothing else); another
 * value is this node's storage disagreeing with every writer → FAULT.
 *
 * WHY HERE: after the item/claim loop (every item of h ran under
 * generation 1) and BEFORE the 6c lifecycle re-scan, so 6c reloads the
 * generation-2 manifests and runtimes, phases 8-11 commit the rewritten
 * registry into SYSTEM's root, the heads and h's app_hash — and block H
 * starts under generation 2. Doing it after apply_block returns would
 * leave h's app_hash without the rewrite and stop every node at H.
 *
 * TOUCHED: SYSTEM (its root moves — domreg_root is a SYSTEM leg) and
 * CORE (its root does NOT move; phase 9 accepts that only while HF-2 is
 * on — guaranteed by the vote's stateful rule (b), HF-2 having no off
 * vote). Both are declared on the pre-6c working set, which 6c carries
 * over (the 6e pattern).
 *
 * The H-1 DomainUpdate / root-history rows therefore name generation 2
 * although h's items ran under generation 1 — outside the app hash,
 * stated in the design (§1.3) for explorers.
 *
 * STORAGE REWARD v1 (design docs/plans/2026-10-04-storage-reward-v1-
 * design.md rev 2.2 §6 / D5; decision docs/plans/decisions/2026-10-04-
 * storage-reward-approved.md; numbering in main merge order, Nodus EVM
 * first; K10 in 2026-10-05-storage-reward-is-for-archive.md): a SECOND
 * edge in this table, the same procedure — param 16
 * (RULESET_GEN_STORAGE, value DNAC_CFG_RULESET_GEN_STORAGE_D) switches
 * the registry from the EVM generation (NODUS_RT_GEN_STORAGE_BASE) to
 * GEN_STORAGE at the end of block H-1; the EVM domain's record is not
 * touched (EVM v1 unchanged). EVM-only: compiled under NODUS_EVM_ENABLED.
 * The EVM edge (2 -> GEN_EVM) is NOT a row here — it is phase 6b''
 * below, run after this one. The vote's stateful rule (d) (judged under
 * EXACTLY the EVM generation) is what makes "the registry is at the EVM
 * generation" true at the storage edge, and it keeps the two edges in
 * different blocks: every block up to and including the EVM edge block
 * is judged under the EVM base, so the storage vote is committed at or
 * after the EVM edge's H and its own H-1 lies strictly above the EVM
 * edge block. The edges are checked in this fixed order, each with
 * HF-4's exact reads, refusals and log text; the param-9 edge's
 * behaviour (and its log/fault wording) is byte-for-byte the HF-4 one.
 * Two more unmetered chain_config reads per block, no state effect when
 * no edge fires.
 *
 * @return 0 (switched or nothing to do) / -2 node FAULT (reason written).
 */
typedef struct {
    uint8_t     param_id;       /* the upgrade vote's chain_config id   */
    const char *param_name;     /* its name in fault text               */
    uint64_t    literal;        /* the compiled vote literal            */
    const char *literal_name;   /* the literal's name in fault/log text */
    uint32_t    from_gen;       /* the registry before the edge         */
    uint32_t    to_gen;         /* the registry after the edge          */
    const char *log_label;      /* the INFO line's prefix               */
} ruleset_edge_t;

static const ruleset_edge_t RULESET_EDGES[] = {
    { (uint8_t)DNAC_CFG_RULESET_GEN2, "RULESET_GEN2",
      (uint64_t)DNAC_CFG_RULESET_GEN2_D2, "D2",
      NODUS_RT_GEN_1, NODUS_RT_GEN_2, "HF-4" },
#ifdef NODUS_EVM_ENABLED
    /* K10: EVM-only like GEN_STORAGE itself; the EVM edge (2 -> GEN_EVM)
     * is NOT in this table — it is phase 6b'' below, which also
     * registers the EVM domain */
    { (uint8_t)DNAC_CFG_RULESET_GEN_STORAGE, "RULESET_GEN_STORAGE",
      (uint64_t)DNAC_CFG_RULESET_GEN_STORAGE_D, "storage vote literal",
      NODUS_RT_GEN_STORAGE_BASE, NODUS_RT_GEN_STORAGE, "storage reward" }
#endif
};

/* One edge: 0 (switched or not this edge) / -2 node FAULT. */
static int phase_6b_one_edge(nodus_witness_t *w, nodus_v2_block_t *blk,
                             dom_ctx_t *doms, size_t n_dom,
                             const ruleset_edge_t *e) {
    const uint64_t h = blk->global_height;
    uint64_t h_next = 0, v_next = 0, v_h = 0;
    int at_next, at_h, src;

    if (dna_ck_add_u64(h, 1u, &h_next) != 0 ||
        h_next > (uint64_t)INT64_MAX) {
        V2AP_FAULT("phase 6b': height %llu + 1 leaves the int64 range of "
                   "chain_config effective heights",
                   (unsigned long long)h);
        return -2;
    }
    at_next = nodus_chain_config_get_u64(w, e->param_id, h_next, 0ULL,
                                         &v_next);
    at_h = nodus_chain_config_get_u64(w, e->param_id, h, 0ULL, &v_h);
    if (at_next < 0 || at_h < 0) {
        V2AP_FAULT("phase 6b': %s at heights %llu/%llu is "
                   "unreadable on this node - refusing to decide the "
                   "generation switch on a guess", e->param_name,
                   (unsigned long long)h_next, (unsigned long long)h);
        return -2;
    }
    if (!(at_next == 0 && at_h == 1))
        return 0;                       /* not the H-1 edge: nothing     */
    if (v_next != e->literal) {
        V2AP_FAULT("phase 6b': the %s row effective at %llu reads "
                   "0x%016llx, not this build's %s 0x%016llx - a value no "
                   "committed row can hold here", e->param_name,
                   (unsigned long long)h_next, (unsigned long long)v_next,
                   e->literal_name, (unsigned long long)e->literal);
        return -2;
    }

    src = nodus_witness_domreg_generation_switch(w, e->from_gen, e->to_gen);
    if (src == 1) {
        V2AP_FAULT("phase 6b': the generation-%u vote reaches its edge at "
                   "height %llu but the registry is not generation %u",
                   (unsigned)e->to_gen, (unsigned long long)h,
                   (unsigned)e->from_gen);
        return -2;
    }
    if (src != 0) {
        V2AP_FAULT("phase 6b': the registry rewrite to generation %u failed "
                   "on this node at height %llu (read, precondition or "
                   "write)", (unsigned)e->to_gen, (unsigned long long)h);
        return -2;
    }

    {
        dom_ctx_t *dsys = dom_for(doms, n_dom, DNA_DOMAIN_SYSTEM);
        dom_ctx_t *dcore = dom_for(doms, n_dom, DNA_DOMAIN_CORE);
        if (!dsys || !dcore) {
            V2AP_FAULT("phase 6b': SYSTEM or CORE is absent from the "
                       "block-start working set at height %llu",
                       (unsigned long long)h);
            return -2;
        }
        dsys->touched = 1;
        dcore->touched = 1;
    }
    QGP_LOG_INFO(LOG_TAG, "%s: rule-set generation %u -> %u at the end of "
                 "height %llu (%s 0x%016llx); height %llu is judged under "
                 "generation %u", e->log_label, (unsigned)e->from_gen,
                 (unsigned)e->to_gen, (unsigned long long)h,
                 e->literal_name, (unsigned long long)e->literal,
                 (unsigned long long)h_next, (unsigned)e->to_gen);
    return 0;
}

static int phase_6b_ruleset_switch(nodus_witness_t *w, nodus_v2_block_t *blk,
                                   dom_ctx_t *doms, size_t n_dom) {
    for (size_t i = 0; i < sizeof(RULESET_EDGES) / sizeof(RULESET_EDGES[0]);
         i++)
        if (phase_6b_one_edge(w, blk, doms, n_dom, &RULESET_EDGES[i]) != 0)
            return -2;
    return 0;
}

/*
 * PHASE 6b'' — Nodus EVM: THE EVM ACTIVATION EDGE (design docs/plans/2026-10-
 * 04-nodus-evm-chain-integration-design.md rev 3 §9; operator decisions
 * 2026-10-04-nodus-evm-kurultay-k1.md / -k2-summary.md).
 *
 * EDGE TRIGGER at block h, the phase-6b' shape: chain_config param 14
 * (EVM_ACTIVE) present at h+1 AND absent at h — the committed row's
 * effective height H is h+1. Then, in this order, inside the block's
 * transaction:
 *   1. the row's value must be this build's DNAC_CFG_EVM_ACTIVE_D (the
 *      scalar rules admit nothing else; another value is this node's
 *      storage) and this build must carry the EVM generation — else FAULT;
 *   2. the schema must be S17 (the EVM tables, the CORE reserve row) —
 *      a node-local shape, so FAULT, never a verdict;
 *   3. SYSTEM and CORE switch from NODUS_RT_GEN_EVM_BASE to
 *      NODUS_RT_GEN_EVM (nodus_witness_domreg_generation_switch — the
 *      HF-4 procedure); "not at the base" is a FAULT (the vote's stateful
 *      rule refused every vote cast away from the base);
 *   4. the EVM domain's record is written DIRECTLY ACTIVE with NO head
 *      (nodus_witness_domreg_register_active), its manifest exactly the one
 *      the D literal hashed (genesis_state_root = the empty EVM root);
 *      an already-registered domain 2 is a FAULT;
 *   5. SYSTEM and CORE are declared touched (CORE's root moves: its supply
 *      leaf now commits the reserve, "NDS.SUPPLY.v3"; HF-2 is on by the
 *      vote's rule, so an unchanged root would be accepted too).
 * The 6c lifecycle re-scan right after then sees an ACTIVE domain with no
 * head and activates it through head_activate (state_init = the empty
 * tries and zero META, the root checked against the manifest's genesis
 * root, the height-0 history row) — so block H starts with three domains
 * under the EVM generation. Either chain_config read unanswerable → FAULT.
 * Not the edge → nothing (byte-inert on every block of every chain that
 * has no param-14 row).
 * @return 0 / -2 node FAULT (reason written).
 */
static int phase_6b_evm_activation(nodus_witness_t *w, nodus_v2_block_t *blk,
                                   dom_ctx_t *doms, size_t n_dom) {
    const uint64_t h = blk->global_height;
    uint64_t h_next = 0, v_next = 0, v_h = 0;
    int at_next, at_h;

    if (dna_ck_add_u64(h, 1u, &h_next) != 0 ||
        h_next > (uint64_t)INT64_MAX) {
        V2AP_FAULT("phase 6b'': height %llu + 1 leaves the int64 range of "
                   "chain_config effective heights", (unsigned long long)h);
        return -2;
    }
    at_next = nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_EVM_ACTIVE,
                                         h_next, 0ULL, &v_next);
    at_h = nodus_chain_config_get_u64(w, (uint8_t)DNAC_CFG_EVM_ACTIVE, h,
                                      0ULL, &v_h);
    if (at_next < 0 || at_h < 0) {
        V2AP_FAULT("phase 6b'': EVM_ACTIVE at heights %llu/%llu is "
                   "unreadable on this node - refusing to decide the EVM "
                   "edge on a guess", (unsigned long long)h_next,
                   (unsigned long long)h);
        return -2;
    }
    if (!(at_next == 0 && at_h == 1))
        return 0;                       /* not the H-1 edge: nothing     */
    if (v_next != (uint64_t)DNAC_CFG_EVM_ACTIVE_D) {
        V2AP_FAULT("phase 6b'': the EVM_ACTIVE row effective at %llu reads "
                   "0x%016llx, not this build's D 0x%016llx",
                   (unsigned long long)h_next, (unsigned long long)v_next,
                   (unsigned long long)DNAC_CFG_EVM_ACTIVE_D);
        return -2;
    }
#ifndef NODUS_EVM_ENABLED
    (void)doms;
    (void)n_dom;
    V2AP_FAULT("phase 6b'': the EVM activation edge is at height %llu but "
               "this build does not carry the EVM generation (built "
               "without NODUS_EVM_ENABLED)", (unsigned long long)h);
    return -2;
#else
    {
        uint32_t ver = 0;
        if (nodus_witness_db_schema_version(w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S17) {
            V2AP_FAULT("phase 6b'': the EVM edge needs schema S17; this "
                       "node's database is at %u", (unsigned)ver);
            return -2;
        }
    }
    dna_domain_manifest_t evm_man;
    {
        uint64_t d = 0;
        if (nodus_runtime_evm_activation_digest(&d, &evm_man) != 0 ||
            d != (uint64_t)DNAC_CFG_EVM_ACTIVE_D) {
            V2AP_FAULT("%s", "phase 6b'': the compiled EVM generation does "
                       "not re-derive this build's EVM_ACTIVE literal");
            return -2;
        }
    }
    int src = nodus_witness_domreg_generation_switch(w, NODUS_RT_GEN_EVM_BASE,
                                                     NODUS_RT_GEN_EVM);
    if (src == 1) {
        V2AP_FAULT("phase 6b'': the EVM vote reaches its edge at height "
                   "%llu but the registry is not at the base generation %u",
                   (unsigned long long)h, (unsigned)NODUS_RT_GEN_EVM_BASE);
        return -2;
    }
    if (src != 0) {
        V2AP_FAULT("phase 6b'': the registry rewrite to the EVM generation "
                   "failed on this node at height %llu",
                   (unsigned long long)h);
        return -2;
    }
    int rrc = nodus_witness_domreg_register_active(w, &evm_man);
    if (rrc != 0) {
        V2AP_FAULT("phase 6b'': the EVM domain record could not be written "
                   "at height %llu (%s)", (unsigned long long)h,
                   rrc == 1 ? "domain 2 is already registered"
                            : "invalid manifest or storage fault");
        return -2;
    }
    {
        dom_ctx_t *dsys = dom_for(doms, n_dom, DNA_DOMAIN_SYSTEM);
        dom_ctx_t *dcore = dom_for(doms, n_dom, DNA_DOMAIN_CORE);
        if (!dsys || !dcore) {
            V2AP_FAULT("phase 6b'': SYSTEM or CORE is absent from the "
                       "block-start working set at height %llu",
                       (unsigned long long)h);
            return -2;
        }
        dsys->touched = 1;
        dcore->touched = 1;
    }
    QGP_LOG_INFO(LOG_TAG, "Nodus EVM: rule-set generation %u -> %u and the EVM "
                 "domain registered ACTIVE at the end of height %llu (D "
                 "0x%016llx); height %llu is judged under the EVM "
                 "generation", (unsigned)NODUS_RT_GEN_EVM_BASE,
                 (unsigned)NODUS_RT_GEN_EVM, (unsigned long long)h,
                 (unsigned long long)DNAC_CFG_EVM_ACTIVE_D,
                 (unsigned long long)h_next);
    return 0;
#endif
}

static int v2_apply_block_body(nodus_witness_t *w, nodus_v2_block_t *blk) {
    /* A NULL/misused argument is a LOCAL programming fault, not a
     * statement about a block — there is no block here to judge.
     * Reporting it as a verdict would make a node with a caller bug vote
     * a perfectly valid block invalid. Same reasoning, and now the same
     * classification, as nodus_witness_v2_qc.c:24-30. (O14 review R2-F5:
     * this guard had returned -1 since S5, which contradicted the
     * convention the engine states in its own header.) */
    /* Split from the guard below ONLY so the reason buffer can be cleared
     * the instant `blk` is known non-NULL. Same operands, same
     * short-circuit order, same -2: this is the ONE exit in the engine
     * that cannot carry a reason, because there is no block to write it
     * into. */
    if (!w || !w->db || !blk) return -2;
    blk->out_reason[0] = '\0';
    if (blk->n_envs > 0 && !blk->envs) {
        V2AP_FAULT("caller passed n_envs=%llu with a NULL envs array",
                   (unsigned long long)blk->n_envs);
        return -2;
    }
    /* An over-large batch IS a property of the block: verdict. */
    if (blk->n_envs > NODUS_V2_ENV_BATCH_MAX) {
        V2AP_VERDICT("batch of %llu envelopes exceeds the engine bound %u",
                     (unsigned long long)blk->n_envs,
                     (unsigned)NODUS_V2_ENV_BATCH_MAX);
        return -1;
    }

    /* THIS NODE'S schema level is not a property of the block. A read
     * fault and a version mismatch are both node-local: the block may be
     * perfectly valid and every peer at the right schema will commit it.
     * Returning -1 here would make a lagging or mis-migrated node
     * declare a valid, quorum-certified block CONSENSUS-INVALID — and
     * deterministically, on every block, because the S9 migration
     * refuses a populated v2_blocks by design. Abstain instead.
     * (O14 review R2-F1; the -1 predates O14, but O14 is what gives the
     * code a production relay that re-exports it as a verdict.) */
    /* ── THE ONE LANE (tokenomics-v3 P4, OBLIGATION atlas-dec-71525f3b).
     * The legacy block lane — the engine owning its own BEGIN/COMMIT, a
     * whole-batch all-or-nothing verdict, the rc 1 idempotent replay,
     * the rc 2 post-commit window, the derived dna_bh2 identity and the
     * S9-S12 schema — is DELETED. A caller that does not set `cmt.on`
     * is asking for that lane; nothing about the block is judged. */
    if (!blk->cmt.on) {
        V2AP_FAULT("the legacy (non-cometbft) block lane is deleted - "
                   "this engine applies decided cometbft blocks only "
                   "(cmt.on); nothing about the block was judged");
        return -2;
    }
    uint32_t ver = 0;
    {
        /* ── THE COMETBFT LANE'S OWN PRECONDITIONS (D-23 rev 5) ───────
         * S16 ONLY (tokenomics-v3 P1 moved the live rung from S14 to
         * S15, P2 from S15 to S16): this lane writes a `v2_blocks` row
         * without `header`, `qc` or `commit_cert`, and at S12 `header`
         * is NOT NULL, so the insert could not even be expressed; below
         * S16 the reward tables the boundary writes are not guaranteed.
         * Nothing about the block is judged by either refusal — both are
         * this node's shape. Nodus EVM: S17 = S16 + the EVM domain's EMPTY
         * tables and the CORE EVM reserve row at 0
         * (nodus_witness_v2_schema.h), so the lane writes the same rows
         * at either rung; S17 is the live rung (every builder and the
         * at-open rung, nodus_witness.c, migrate to it). The EVM edge
         * itself (phase 6b'') FAULTs below S17. */
        if (nodus_witness_db_schema_version(w, &ver) != 0 ||
            (ver != NODUS_V2_SCHEMA_VERSION_S16 &&
             ver != NODUS_V2_SCHEMA_VERSION_S17)) {
            V2AP_FAULT("cometbft lane: this node's schema version is %u, "
                       "not %u or %u - the Comet block row cannot be "
                       "written here; nothing about the block was judged",
                       (unsigned)ver,
                       (unsigned)NODUS_V2_SCHEMA_VERSION_S16,
                       (unsigned)NODUS_V2_SCHEMA_VERSION_S17);
            return -2;
        }
        /* The HOST owns the transaction (D-23 rev 5 (5)): this entry
         * issues no BEGIN, no COMMIT and no ROLLBACK, so being called
         * outside one would silently autocommit every statement below
         * and make the block un-rollbackable. Node-local invariant. */
        if (sqlite3_get_autocommit(w->db)) {
            V2AP_FAULT("cometbft lane: called outside the host's "
                       "transaction - this entry never opens one");
            return -2;
        }
        if (blk->cmt.results == NULL ||
            blk->cmt.results_cap < blk->n_envs + blk->n_claims) {
            V2AP_FAULT("cometbft lane: the caller's result array holds "
                       "%llu of the %llu items this block carries",
                       (unsigned long long)blk->cmt.results_cap,
                       (unsigned long long)(blk->n_envs + blk->n_claims));
            return -2;
        }
        if (blk->expect_block_id || blk->expect_prev_block_id ||
            blk->expect_vset_hash) {
            V2AP_FAULT("cometbft lane: the identity assertions are the "
                       "legacy lane's - here the identity is the "
                       "caller's input, not a derivation to assert");
            return -2;
        }
        memset(blk->cmt.results, 0,
               (blk->n_envs + blk->n_claims) * sizeof(*blk->cmt.results));
        blk->cmt.results_len = 0;
    }

    /* ── epoch: DERIVED from the global block count, never trusted ────
     * blk->epoch is caller-carried block material; it MUST equal the
     * canonical derivation or the block is a lie about its own epoch.
     * No clock, no timestamp, no domain_height participates. */
    if (blk->epoch != nodus_v2_epoch_for_height(blk->global_height)) {
        V2AP_VERDICT("block at height %llu declares epoch %llu; the "
                     "canonical derivation is %llu",
                     (unsigned long long)blk->global_height,
                     (unsigned long long)blk->epoch,
                     (unsigned long long)
                         nodus_v2_epoch_for_height(blk->global_height));
        return -1;
    }

    /* ── 0. linkage (read-only) ──────────────────────────────────────
     * The block's identity is consensus's (phase 13 stores it
     * verbatim); what the ledger checks here is height continuity and
     * the parent row. (tokenomics-v3 P4: the legacy lane's rc-1
     * idempotent replay fast path — an asserted `expect_block_id`
     * matching the row already committed at this height — is deleted
     * with the lane; the entry gate refuses every identity assertion.)
     * The "same BlockID at another height" check is in phase 13. */
    {
        sqlite3_stmt *st = NULL;
        int rc;

        /* height continuity + prev linkage */
        uint64_t maxh = 0;
        if (sum_q(w, "SELECT COALESCE(MAX(global_height),0) FROM v2_blocks",
                  &maxh) != 0) {
            V2AP_FAULT("phase 0: could not read MAX(global_height) from "
                       "v2_blocks on this node");
            return -2;
        }
        uint64_t rows = 0;
        if (sum_q(w, "SELECT COUNT(*) FROM v2_blocks", &rows) != 0) {
            V2AP_FAULT("phase 0: could not read COUNT(*) from v2_blocks "
                       "on this node");
            return -2;
        }

        /* O15A — the linkage classes, in this order deliberately.
         *
         * Height 0 is tested FIRST: genesis has its own entry point
         * (nodus_witness_v2_genesis_cmt), so a height-0 block cannot be
         * applied through this path at all — and without this check an
         * EMPTY `v2_blocks` (the normal state of a fresh version-3 chain,
         * below) would let one through as the chain's "first" block. */
        if (blk->global_height == 0) {
            V2AP_VERDICT("phase 0: height 0 cannot be applied through "
                         "this path - genesis has its own entry point "
                         "(nodus_witness_v2_genesis_cmt)");
            return NODUS_V2_CONSENSUS_INVALID;
        }

        /* A version-3 chain writes NO height-0 `v2_blocks` row at all
         * (D-19 rev 6 withdrew the genesis block;
         * nodus_witness_v2_genesis_cmt, apply.h), so an EMPTY table is
         * the normal state of a freshly derived chain and the block
         * arriving here is simply its FIRST. Its `prev_block_id` is 64
         * zero bytes — block 1's LastBlockID is empty in the reference
         * too (D-18 rev 3). The genesis the ledger applied is still
         * proven to exist: the committed manifest and the domain heads
         * are what phase 0a reads, and a chain without them fails there.
         * (tokenomics-v3 P4: the legacy lane's "no genesis committed
         * here yet" deferral on an empty table is deleted with it.) */

        /* maxh + 1 would wrap at UINT64_MAX and make an impossible height
         * look like the expected next one. Checked before it is used. */
        if (maxh == UINT64_MAX) {
            V2AP_FAULT("phase 0: committed head height is UINT64_MAX - "
                       "maxh+1 would wrap, so no successor height can be "
                       "computed on this node");
            return NODUS_V2_INTERNAL_FAULT;
        }

        /* AHEAD of our chain: we cannot evaluate it yet, because the
         * predecessors it builds on are absent here. A node that is
         * merely behind reports this while synced peers accept the very
         * same bytes, so it must never be a verdict, must not commit,
         * must not advance a head and must not be held against the peer.
         * Fetching the gap is a SYNC concern and is deliberately not
         * implemented here. */
        if (blk->global_height > maxh + 1) {
            V2AP_DEFER("phase 0: height %llu is AHEAD of this node's head "
                       "%llu (next expected %llu) - predecessor state is "
                       "absent, NOTHING was judged",
                       (unsigned long long)blk->global_height,
                       (unsigned long long)maxh,
                       (unsigned long long)(maxh + 1));
            return NODUS_V2_NOT_YET_LINKABLE;
        }

        /* THE COMETBFT LANE'S FIRST BLOCK. With no committed row there
         * is no predecessor height to be continuous with: the chain's
         * `initial_height` is a field of the genesis DOCUMENT (D-18
         * rev 3) that this engine never reads, and consensus — which
         * owns the height — has already decided this block. So the
         * linkage checks below are skipped exactly once, and the
         * `prev_block_id` is the reference's empty LastBlockID: 64 zero
         * bytes. Every later Comet block takes the ordinary path. */
        if (rows == 0) {
            memset(blk->out_prev_block_id, 0, 64);
        } else {

        /* AT or BEHIND the head: a height already committed, or a hole
         * in the local chain. */
        if (blk->global_height != maxh + 1) {
            V2AP_VERDICT("phase 0: height %llu is at or below this node's "
                         "head %llu (next expected %llu) - evaluable now, "
                         "and it is not the successor",
                         (unsigned long long)blk->global_height,
                         (unsigned long long)maxh,
                         (unsigned long long)(maxh + 1));
            return NODUS_V2_CONSENSUS_INVALID;
        }

        /* prev_block_id is DERIVED from the previous committed row. */
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
                -1, &st, NULL) != SQLITE_OK) {
            V2AP_FAULT("phase 0: could not prepare the parent lookup for "
                       "height %llu", (unsigned long long)maxh);
            return -2;
        }
        sqlite3_bind_int64(st, 1, (sqlite3_int64)maxh);
        rc = sqlite3_step(st);
        int prev_ok = (rc == SQLITE_ROW &&
                       sqlite3_column_bytes(st, 0) == 64);
        if (prev_ok)
            memcpy(blk->out_prev_block_id, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        if (!prev_ok) {                 /* missing/malformed parent row  */
            V2AP_FAULT("phase 0: parent row at height %llu is missing or "
                       "malformed on this node (sqlite rc %d)",
                       (unsigned long long)maxh, rc);
            return -2;
        }
        }   /* end of the ordinary linkage path (see the first block
             * above) */
    }

    /* ── 0a. FROZEN BLOCK-START EXECUTION SNAPSHOT (read-only) ────────
     * Registered-domain working set (STRICT lifecycle preconditions),
     * contextual ruleset table, derived chain id, the SYSTEM-committed
     * metering policy and the unit budgets — built ONCE, before any
     * mutation, used by every transaction in the block. Nothing the
     * block executes can change what a later transaction in the SAME
     * block resolves. */
    dom_ctx_t *doms = calloc(MAX_DOMS, sizeof(*doms));
    if (!doms) {
        V2AP_FAULT("phase 0a: allocation of the %u-entry domain snapshot "
                   "failed", (unsigned)MAX_DOMS);
        return -2;
    }
    size_t n_dom = 0;
    if (doms_load(w, doms, &n_dom, /*strict_active=*/1) != 0) {
        doms_free(doms);
        V2AP_FAULT("phase 0a: the domain registry / heads / runtime "
                   "tuples are unreadable or broken on THIS node - never "
                   "a statement about the block");
        return -2;   /* registry/head/runtime state unreadable or broken
                      * on THIS node — never a statement about the block */
    }

    uint8_t chain_id[DNA_CHAIN_ID_LEN];
    /* ONE derivation of the chain identity: `nodus_witness_v2_chain_id`
     * answers from the STORED GENESIS DOCUMENT (nodus_witness_v2_claims.c;
     * a version-3 chain writes no genesis block row at all, D-19 rev 6 —
     * and since tokenomics-v3 P4 nothing does). */
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) {
        doms_free(doms);
        V2AP_FAULT("phase 0a: chain id underivable on this node - no "
                   "stored genesis document answered");
        return -2;   /* an underivable chain id is a node-local read
                      * failure, never a statement about the block       */
    }

    /* ── BLOCK-START VALIDATOR AUTHORITY (O14) ────────────────────────
     * The governing snapshot is resolved HERE — pre-BEGIN, before this
     * block mutates anything and in particular BEFORE the epoch boundary
     * runs commit_next. That ordering is the whole point: a block is
     * verified against the authority the chain had committed when the
     * block STARTED, so the snapshot a boundary block itself creates can
     * never be the snapshot that validates it. (The v2_blocks row's
     * `vset_hash` is the block's Comet ValidatorsHash, phase 13; what
     * this resolution gates is that a governing snapshot EXISTS.)
     *
     * An absent/unreadable snapshot is a NODE FAULT (-2), never a
     * verdict — the O12 resolver contract and the same reasoning
     * `nodus_witness_v2_qc.h` used to state before R3 W4 deleted it
     * with the closed consensus lane: a node that cannot know who was
     * permitted to sign must abstain, not declare a valid block
     * invalid. */
    {
        dna_vset_snapshot_t *snap = NULL;
        uint32_t vn = 0, vq = 0;
        if (nodus_witness_v2_epoch_authority_for_height(
                w, blk->global_height, &snap, &vn, &vq) != 0 || !snap) {
            dna_vset_free(&snap);
            doms_free(doms);
            V2AP_FAULT("phase 0a: no committed validator-set snapshot "
                       "governs height %llu on this node - cannot know "
                       "who was permitted to sign, so abstain",
                       (unsigned long long)blk->global_height);
            return -2;
        }
        int hrc = dna_vset_hash(snap, blk->out_vset_hash);
        dna_vset_free(&snap);
        if (hrc != 0) {
            doms_free(doms);
            V2AP_FAULT("phase 0a: hashing the governing validator-set "
                       "snapshot (%u members, quorum %u) failed",
                       (unsigned)vn, (unsigned)vq);
            return -2;
        }
    }

    /* Contextual ruleset table, per-domain unit budgets and THE committed
     * metering policy — built by the ONE shared body above, from the
     * doms[] this engine already loaded (no second registry scan). The
     * propose-time batch check reaches the SAME body through
     * nodus_witness_v2_block_ctx_build, which is what makes a leader's
     * pre-commit answer and this engine's answer the same answer.
     * ~5.7 KB, the same footprint the two locals it replaces had. */
    nodus_witness_v2_block_ctx_t bctx;
    {
        /* HF-3 D1 (d): the block's own height — the one FinalizeBlock
         * hands the engine (req->height); phase 0 above already
         * classified any mismatch with the local head. */
        int bcrc = block_ctx_from_doms(w, blk->global_height, doms, n_dom,
                                       &bctx);
        if (bcrc != 0) {
            /* The class follows the value the builder already chose —
             * the reason must never re-decide it. */
            if (bcrc == -1)
                V2AP_VERDICT("phase 0a: block context (ruleset table / "
                             "metering policy / unit budgets) rejected "
                             "the committed chain state across %llu "
                             "registered domains",
                             (unsigned long long)n_dom);
            else
                V2AP_FAULT("phase 0a: block context build failed on this "
                           "node (rc %d, %llu registered domains)",
                           bcrc, (unsigned long long)n_dom);
            doms_free(doms);
            return bcrc;    /* -1 chain-state verdict / -2 node fault,
                             * both unchanged from the inline original  */
        }
    }

    /* ── 0b. the item working set ─────────────────────────────────────
     * Heap allocations: the per-item preflight results are multi-KB each
     * (env_preflight.h size audit) and the read/result buffers are the
     * codec maxima — none of it belongs on the stack. */
    dna_env_preflight_t *pf = NULL;
    dna_meter_t *meters = NULL;
    nodus_rt_read_res_t *reads = NULL;
    uint8_t *resbuf = NULL;
    /* R3 W4 package C — auths is no longer sized `n_envs × DNA_ENV_MAX_LEGS`
     * (a fixed per-leg-cap multiplication): one item is ever live at a
     * time (its own SAVEPOINT), so ONE small reusable buffer sized
     * DNA_ENV_MAX_LEGS (never touching n_envs) serves every item in turn
     * — allocated in the item loop below. `exec_one_env` /
     * `env_authorize_legs` index `auths[l]`, never
     * `auths[env_index * DNA_ENV_MAX_LEGS + l]`. */
    nodus_rt_auth_verdict_t *auths = NULL;
    /* capacity season: the ENGINE-resolved governing committee snapshot
     * for auth_kind-2 legs — resolved lazily ONCE per block (heap: up to
     * 128 × 2592 B of pubkeys; never on the stack). */
    uint8_t *cm_pubkeys = NULL;
    uint8_t (*cm_fps)[64] = NULL;
    uint64_t *cm_powers = NULL;              /* HF-2: seat voting powers */
    nodus_rt_committee_t cmview;
    memset(&cmview, 0, sizeof(cmview));
    /* R3 W4 package C — HEAP, sized to the BLOCK's own n_claims, not the
     * engine's release bound (NODUS_V2_APPLY_MAX_OPS is now 17 371; a
     * `claim_nuls[MAX_OPS][64]` STACK array at that size would be a
     * ~907 KB frame). Allocated in the claim stage of the item loop
     * below — NULL/0 for a claim-free block is the always-safe starting
     * state. (tokenomics-v3 P4: the legacy lane's `auth_off` offset
     * table and `env_phase` phase-order array are deleted with it.) */
    uint8_t (*claim_nuls)[64] = NULL;

    if (blk->n_envs > 0) {
        pf        = calloc(blk->n_envs, sizeof(*pf));
        meters    = calloc(blk->n_envs, sizeof(*meters));
        reads     = calloc(NODUS_RT_MAX_READS, sizeof(*reads));
        resbuf    = calloc(1, DNA_EFFECT_MAX_TOTAL_LEN);
        if (!pf || !meters || !reads || !resbuf) {
            V2AP_FAULT("phase 0b: allocation of the preflight/meter/read/"
                       "result working set for %llu envelopes failed",
                       (unsigned long long)blk->n_envs);
            goto fail_fault_pre;
        }
    }

    /* ── 0c. Nodus EVM: THE EVM BLOCK GAS SUM, re-checked (design §8: "apply
     * aynı ayrıştırıcıyla FAULT olarak denetler"). The summed DECLARED gas
     * of every envelope's EVM leg (bridge ops count 21 000) — through the
     * ONE decoder and the ONE share rule ProcessProposal's seam and
     * PrepareProposal's pack apply (nodus_witness_v2_ctx_block_gas_add);
     * a refused or failing item keeps its share, an undecodable envelope
     * has none. ProcessProposal REJECTs a block over the limit, so a
     * decided one over it means honest validators did not decide it: this
     * node stops (FAULT), never a verdict. Inert before the EVM edge
     * (bctx.evm_active 0: the add is a no-op). */
    if (bctx.evm_active) {
        uint64_t gas_sum = 0;
        for (size_t i = 0; i < blk->n_envs; i++) {
            dna_env_view_t gv;
            memset(&gv, 0, sizeof(gv));
            if (dna_env_decode(blk->envs[i].env_bytes, blk->envs[i].env_len,
                               &gv) != 0)
                continue;                /* no declared share            */
            if (nodus_witness_v2_ctx_block_gas_add(&bctx, &gv,
                                                   &gas_sum) != 0) {
                V2AP_FAULT("phase 0c: the block's declared EVM gas exceeds "
                           "EVM_BLOCK_GAS_LIMIT %llu at envelope %llu - "
                           "ProcessProposal refuses such a block",
                           (unsigned long long)bctx.evm_block_gas_limit,
                           (unsigned long long)i);
                goto fail_fault_pre;
            }
        }
    }

    /* ── 1. THE transaction ─────────────────────────────────────────
     * The HOST owns it (D-23 rev 5 (5)): `apply_verified_block` opened
     * one before `FinalizeBlock` and `app.commit` will close it, so this
     * entry never opens, commits or rolls back anything. The entry gate
     * already refused to run outside a transaction, so one is open
     * here. (tokenomics-v3 P4: the legacy lane's own BEGIN, its whole-
     * batch pre-BEGIN stage — batch preflight + reserve, replay guard,
     * per-leg admission, committee snapshot, authorization, claim and
     * pool pre-scans — and its all-or-nothing verdicts are deleted with
     * the lane; the cometbft item loop below does the same work PER
     * ITEM.) */
    FAIL_POINT(V2AP_FAIL_AFTER_BEGIN);

    /* 2. supply gate (pre-apply) */
    if (nodus_witness_v2_supply_check(w) != 0) {
        V2AP_VERDICT("phase 2: PRE-APPLY supply gate failed - committed "
                     "state was already non-conserving before this block "
                     "touched anything (gate helper conflates a read "
                     "fault: honest label in the header)");
        goto fail;
    }

    /* ══ 4-6b, THE COMETBFT LANE: ONE ITEM AT A TIME ════════════════
     *
     * D-23 rev 4/5. A decided block is applied, never re-judged, so the
     * unit of failure is the ITEM, not the block. Each item runs inside
     * its own SAVEPOINT nested in the host's transaction; an
     * item-attributable refusal rolls that savepoint back — its
     * mutations, its fee and its index rows go with it — records a
     * nonzero `nodus_v2_tx_code_t`, and the block continues with the
     * next item. A NODE-LOCAL fault is never an item verdict: it aborts
     * the whole apply and the host rolls the block back.
     *
     * ORDER: the block's own order, envelopes then claims. (The deleted
     * legacy lane's SYSTEM → cross-domain → domain-local phase order was
     * that consensus's rule, never this one's.)
     *
     * WHAT IS REUSED, not re-implemented: `dna_env_preflight` (the same
     * derivation the batch seam runs, with the chain id passed in),
     * `dna_meter_reserve`/`dna_meter_abort`, the admission predicates
     * `dom_for` / `rt_owns_runtime_op`, the runtime's own `auth` hook,
     * and `exec_one_env` — the per-envelope body.
     */
    {
        uint32_t gidx = 0;          /* global index of the APPLIED items */

        /* The governing committee snapshot, resolved ONCE for the block.
         * It is resolved UNCONDITIONALLY (the deleted legacy lane
         * resolved it only when its batch scan saw a committee-indexed
         * leg): there is no batch scan here, and pre-decoding every item
         * just to learn whether one does would be the scan again. The
         * cost is one committed-state read per block; the alternative —
         * verifying a kind-2 leg against an empty view — would refuse
         * every chain-config transaction. A height-0 block cannot reach
         * here (phase 0 refused it), so the helper's "below genesis"
         * answer is a node-local invariant. */
        {
            int crc = committee_snapshot_for_height(
                w, blk->global_height, &cmview, &cm_pubkeys, &cm_fps,
                &cm_powers, blk->out_reason, sizeof blk->out_reason);

            if (crc != 0) {
                if (crc == 1) {
                    V2AP_FAULT("cometbft lane: the governing committee "
                               "height would be below genesis at block "
                               "height %llu",
                               (unsigned long long)blk->global_height);
                }
                goto fail_fault;
            }
        }

        /* R3 W4 package C — the Comet lane's own `auths`: ONE item is
         * ever live at a time (each runs inside its own SAVEPOINT, in
         * block order), so a single reusable buffer sized DNA_ENV_MAX_LEGS
         * — the per-envelope leg cap, independent of `n_envs` — serves
         * every item in turn. No offset table is needed: index `l` is
         * always relative to THIS item, and `env_authorize_legs` never
         * writes
         * past `v->leg_count <= DNA_ENV_MAX_LEGS` slots. */
        if (blk->n_envs > 0) {
            auths = calloc(DNA_ENV_MAX_LEGS, sizeof(*auths));
            if (!auths) {
                V2AP_FAULT("cometbft lane: allocation of the per-item "
                           "%u-slot auth-verdict scratch failed",
                           (unsigned)DNA_ENV_MAX_LEGS);
                goto fail_fault;
            }
        }

        for (size_t i = 0; i < blk->n_envs; i++) {
            nodus_v2_tx_result_t *res = &blk->cmt.results[i];
            const dna_env_view_t *v;
            dna_env_leg_ctx_t lctx[DNA_ENV_MAX_LEGS];
            dna_env_preflight_status_t pfst;
            char sp[48];
            uint32_t code = NODUS_V2_TX_OK;
            uint16_t l;
            int metered = 0;

            res->code = NODUS_V2_TX_OK;
            res->gas_wanted = 0;
            res->gas_used = 0;
            res->data_len = 0;          /* Nodus EVM: set only by an applied */
            memset(res->data, 0, sizeof(res->data));   /* EVM leg       */

            snprintf(sp, sizeof(sp), "cmt_item_%llu",
                     (unsigned long long)i);
            if (nodus_witness_db_savepoint(w, sp) != 0) {
                V2AP_FAULT("cometbft item %llu: SAVEPOINT failed on this "
                           "node", (unsigned long long)i);
                goto fail_fault;
            }

            /* ── the item's own contextual ruleset table, POSITIONAL ──
             * `dna_env_preflight` wants one entry per leg, in leg order
             * (env_preflight.h step 5). The block-start table is by
             * domain; a leg whose domain is absent from it is the
             * CONTEXT class. The decode has to happen first to know the
             * legs, and the codec is the same one preflight re-runs. */
            {
                dna_env_view_t probe;

                memset(&probe, 0, sizeof(probe));
                if (dna_env_decode(blk->envs[i].env_bytes,
                                   blk->envs[i].env_len, &probe) != 0) {
                    code = NODUS_V2_TX_ERR_DECODE;
                    goto cmt_item_failed;
                }
                for (l = 0; l < probe.leg_count; l++) {
                    size_t k;
                    int found = 0;

                    for (k = 0; k < bctx.n_rulesets; k++) {
                        if (bctx.rulesets[k].domain_id ==
                            probe.leg[l].domain_id) {
                            lctx[l] = bctx.rulesets[k];
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        code = NODUS_V2_TX_ERR_CONTEXT;
                        goto cmt_item_failed;
                    }
                }
                pfst = dna_env_preflight(blk->envs[i].env_bytes,
                                         blk->envs[i].env_len, chain_id,
                                         blk->global_height, lctx,
                                         probe.leg_count, &pf[i]);
                if (pfst != DNA_ENV_PF_OK) {
                    /* ERR_HASH is the hash backend failing on THIS node
                     * — never a statement about the bytes (the
                     * env_preflight.h ERR_HASH rule, engine-wide). */
                    if (pfst == DNA_ENV_PF_ERR_HASH) {
                        V2AP_FAULT("cometbft item %llu: the preflight's "
                                   "hash backend failed on this node",
                                   (unsigned long long)i);
                        (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                        (void)cmt_savepoint_release(w, sp);
                        goto fail_fault;
                    }
                    /* The ERR_CTX_* family says the envelope does not fit
                     * the COMMITTED CONTEXT it was handed — a wrong leg
                     * count, another domain, another ruleset version
                     * (env_preflight.h:92-94) — which is class 2, not a
                     * statement about the bytes. Everything else left
                     * here (ERR_ARG, ERR_DECODE, ERR_EXPIRED,
                     * env_preflight.h:89-91) is class 1. */
                    code = (pfst == DNA_ENV_PF_ERR_CTX_COUNT ||
                            pfst == DNA_ENV_PF_ERR_CTX_DOMAIN ||
                            pfst == DNA_ENV_PF_ERR_CTX_VERSION)
                               ? NODUS_V2_TX_ERR_CONTEXT
                               : NODUS_V2_TX_ERR_DECODE;
                    goto cmt_item_failed;
                }
            }
            v = &pf[i].view;

            /* ── REPLAY: the committed indices, then this block ───────
             * The intent guard, then the wire guard (the deleted legacy
             * lane ran the same two pre-BEGIN), here per item and
             * ALSO against the items this block already applied — an
             * earlier item's rows are visible inside the transaction, so
             * the committed check covers them, but an item that was
             * rolled back must not block a later duplicate either, which
             * is exactly what reading the live index gives.
             *
             * The intent query is textually the one CheckTx runs at
             * admission (verify_v2_successor_tx, nodus_witness_verify.c
             * "Committed-intent replay"), so a node admits nothing this
             * guard would refuse. Both indices are written ONLY by
             * cmt_item_index, inside an APPLIED item's savepoint (a
             * refused item leaves no row), so a byte-identical copy of an
             * applied envelope is refused REPLAY here — no state effect —
             * while a copy of a REFUSED one is judged afresh. */
            {
                int hit = 0;

                if (env_replay_guard(w, &pf[i], i, &hit, blk->out_reason,
                                     sizeof blk->out_reason) != 0) {
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;   /* the helper owns the reason     */
                }
                if (hit) {
                    code = NODUS_V2_TX_ERR_REPLAY;
                    goto cmt_item_failed;
                }
            }

            /* ── ADMISSION, per leg (env_admit_legs — the ONE predicate,
             * shared with the CheckTx dry run) ──────────────────────── */
            {
                int arc = env_admit_legs(v, doms, n_dom, blk->n_envs, i,
                                         &code, blk->out_reason,
                                         sizeof blk->out_reason);

                if (arc == -2) {
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;   /* the helper owns the reason     */
                }
                if (arc != 0) {
                    goto cmt_item_failed;
                }
            }

            /* ── HF-1 GAS PRICE at the block's own height (the ONE
             * helper, shared with the CheckTx dry run) — BEFORE the
             * reservation, so a refused item reserves nothing (code 9,
             * gas_wanted = gas_used = 0). Inert while no price row is
             * active. ─────────────────────────────────────────────── */
            {
                int grc = env_gas_price_check(w, v, blk->global_height,
                                              &code, blk->out_reason,
                                              sizeof blk->out_reason);

                if (grc == -2) {
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;   /* the helper owns the reason     */
                }
                if (grc != 0) {
                    goto cmt_item_failed;
                }
            }

            /* ── HF-3 RULE 5 (decision 2026-10-01-hf3-comet-only-block-
             * bounds.md answer 10): from the HF-3 height the declared
             * ceiling must fit int64 — it becomes gas_wanted below. After
             * the gas price, BEFORE the reservation, so a refused item
             * keeps gas_wanted = gas_used = 0 (metered stays 0). The
             * switch is the block-start context's (D2). ─────────────── */
            if (bctx.hf3_active &&
                nodus_witness_v2_units_ceiling_check(
                    v, &code, blk->out_reason,
                    sizeof blk->out_reason) != 0) {
                goto cmt_item_failed;
            }

            /* ── RESERVE against what is LEFT of the block's budget ──
             * Nodus EVM: an ABI-2 leg is the plan's streamed leg
             * (env_stream_leg — 0 on every chain without an ABI-2
             * runtime, which makes this dna_meter_reserve exactly). */
            {
                dna_meter_status_t mst =
                    dna_meter_reserve_ex(&meters[i], bctx.policy, v,
                                         &bctx.budget,
                                         env_stream_leg(v, doms, n_dom));

                if (mst == DNA_METER_ERR_FAULT) {
                    V2AP_FAULT("cometbft item %llu: the meter reported an "
                               "accounting fault on this node",
                               (unsigned long long)i);
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;
                }
                if (mst != DNA_METER_OK) {
                    code = NODUS_V2_TX_ERR_CAPACITY;
                    goto cmt_item_failed;
                }
                metered = 1;
                res->gas_wanted = meters[i].g_reserved;
            }

            /* ── AUTHORIZATION: the ONE stage, shared with CheckTx ──── */
            {
                int arc = env_authorize_legs(
                    w, &pf[i], doms, n_dom, chain_id, blk->global_height,
                    blk->epoch, &cmview, NULL, NULL, auths,
                    blk->out_reason, sizeof blk->out_reason);

                if (arc == -2) {
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;   /* the helper owns the reason     */
                }
                if (arc != 0) {
                    code = NODUS_V2_TX_ERR_AUTH;
                    goto cmt_item_failed;
                }
            }

            /* ── EXECUTE: the per-envelope body ─────────────────────── */
            {
                int rc = exec_one_env(w, blk, i, chain_id, blk->epoch,
                                      doms, n_dom, &pf[i], &meters[i],
                                      auths, reads, resbuf, NULL, 0, res,
                                      blk->out_reason,
                                      sizeof blk->out_reason);
                if (rc == -2) {
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;      /* exec_one_env owns the reason */
                }
                if (rc != 0) {
                    blk->out_reason[0] = '\0';   /* an ITEM's refusal is
                                                  * not the block's      */
                    code = NODUS_V2_TX_ERR_EXEC;
                    goto cmt_item_failed;
                }
                res->gas_used = meters[i].g_consumed;
            }

            /* ── the item's IDENTITY INDEX ROWS, inside its savepoint ─
             * Both identities or neither: a refused item's rows go away
             * with its SAVEPOINT, which is what makes "no index rows for
             * a failed item" true rather than merely intended. The LOCAL
             * index rows follow in phase 12 — see cmt_item_index. */
            if (cmt_item_index(w, blk->global_height, &pf[i], doms, n_dom,
                               gidx, blk->out_reason,
                               sizeof blk->out_reason) != 0) {
                (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                (void)cmt_savepoint_release(w, sp);
                goto fail_fault;       /* the helper owns the reason     */
            }

            /* ── the NODE-LOCAL address index rows, inside the same
             * savepoint (decision 2026-10-01-node-address-history-
             * index.md rev 2): a refused item never reaches here, and a
             * failed block takes them with the host's ROLLBACK. No root
             * reads them; a no-op unless the node flag is on. A write
             * failure is this node's FAULT, never a skipped row. */
            if (nodus_witness_addr_index_env(w, blk->global_height,
                                             (uint32_t)i, &pf[i], auths,
                                             blk->out_reason,
                                             sizeof blk->out_reason) != 0) {
                (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                (void)cmt_savepoint_release(w, sp);
                goto fail_fault;       /* the helper owns the reason     */
            }

            /* APPLIED. Only now does the item join the per-domain id
             * lists and the touched set: a rolled-back item must not
             * reach tx_root, a domain root or a local index. */
            for (l = 0; l < v->leg_count; l++) {
                dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);

                d->touched = 1;
                /* R3 W4 package C — HEAP, lazily, sized to the block's
                 * own n_envs (the admission-phase FAULT check above
                 * already proved n_tx < n_envs for this leg, so the write
                 * below is in-bounds by construction). */
                if (!d->wire_ids) {
                    d->wire_ids = calloc(blk->n_envs, sizeof(*d->wire_ids));
                    if (!d->wire_ids) {
                        V2AP_FAULT("cometbft item %llu leg %u: allocation "
                                   "of domain %u's %llu-entry wire-id "
                                   "scratch failed",
                                   (unsigned long long)i, (unsigned)l,
                                   (unsigned)d->domain_id,
                                   (unsigned long long)blk->n_envs);
                        (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                        (void)cmt_savepoint_release(w, sp);
                        goto fail_fault;
                    }
                }
                memcpy(d->wire_ids[d->n_tx++], pf[i].wire_id, 64);
            }
            gidx++;
            blk->cmt.results_len = i + 1;
            if (cmt_savepoint_release(w, sp) != 0) {
                V2AP_FAULT("cometbft item %llu: RELEASE SAVEPOINT failed "
                           "on this node", (unsigned long long)i);
                goto fail_fault;
            }
            continue;

cmt_item_failed:
            /* The item pays nothing and leaves nothing: its savepoint
             * carries away every mutation it made, its fee with them,
             * and its index rows were never written. The meter is
             * ABORTED, which restores the block budget byte-identically
             * (res_meter.h:506-509) so the NEXT item is judged against
             * the budget as if this one had never been reserved. */
            if (metered) {
                res->gas_used = meters[i].g_consumed;
                (void)dna_meter_abort(&meters[i]);
            }
            res->code = code;
            /* Nodus EVM: a refused item has no receipt — whatever an EVM leg
             * of it wrote here went away with its savepoint */
            res->data_len = 0;
            memset(res->data, 0, sizeof(res->data));
            blk->cmt.results_len = i + 1;
            blk->out_reason[0] = '\0';
            if (nodus_witness_db_rollback_to_savepoint(w, sp) != 0 ||
                cmt_savepoint_release(w, sp) != 0) {
                V2AP_FAULT("cometbft item %llu: its savepoint could not "
                           "be rolled back on this node",
                           (unsigned long long)i);
                goto fail_fault;
            }
        }

        /* ── POOL BATCHES ARE NOT ITEMS ──────────────────────────────
         * A block does not carry them: the block message declares
         * `pool_batch_count` must be zero (shared/dnac/blockmsg_v2.h),
         * and the S7 surface is an INACTIVE test/fixture input the
         * engine accepts only from a direct caller. A decided Comet
         * block that somehow carries one is therefore not something to
         * judge — it is this node being handed a shape consensus cannot
         * produce: stop. */
        if (blk->n_pool_muts > 0) {
            V2AP_FAULT("cometbft lane: this block carries %llu pool "
                       "batches; a block message cannot express one, so "
                       "this is a node-local shape, not a verdict",
                       (unsigned long long)blk->n_pool_muts);
            goto fail_fault;
        }

        /* ── THE CLAIM ARRAY'S BOUNDS ────────────────────────────────
         * Without this the loop below would write into a NULL
         * `claim_nuls`. R3 W4 package C: the array is heap, sized to
         * THIS block's own
         * n_claims, not a fixed MAX_OPS-sized (17 371-entry) frame — but
         * the engine still must not depend on ONE caller's arithmetic for
         * its own memory safety: a direct caller (every V2 test is one)
         * reaches this loop unfiltered, and an absurd n_claims must not
         * become an absurd allocation attempt either.
         *
         * Neither refusal is a judgement about anyone's block: an array
         * this engine cannot hold is this node's shape. */
        if (blk->n_claims > NODUS_V2_APPLY_MAX_CLAIMS ||
            (blk->n_claims > 0 && !blk->claims)) {
            V2AP_FAULT("cometbft lane: the block declares %llu claims "
                       "with %s array; this engine holds %zu",
                       (unsigned long long)blk->n_claims,
                       blk->claims ? "an over-long" : "a NULL",
                       NODUS_V2_APPLY_MAX_CLAIMS);
            goto fail_fault;
        }
        if (blk->n_claims > 0) {
            claim_nuls = calloc(blk->n_claims, sizeof(*claim_nuls));
            if (!claim_nuls) {
                V2AP_FAULT("cometbft lane: allocation of the %llu-entry "
                           "claim-nullifier scratch failed",
                           (unsigned long long)blk->n_claims);
                goto fail_fault;
            }
        }

        /* ── CLAIMS ARE ITEMS, and take the same discipline ───────────
         * Each claim runs in its own SAVEPOINT: the derivation
         * (`claim_prescan_one` — a pure
         * function of the claim bytes and committed context), the
         * in-block duplicate check against the claims this block has
         * ALREADY applied, the target-domain check, then
         * `claim_execute_one` (admission, the nullifier cross-check and
         * the three write stages). Any refusal is code CLAIM, the
         * savepoint is rolled back and the block continues.
         *
         * A claim reserves and consumes no metered units, so its
         * `gas_wanted`/`gas_used` are 0/0 — apply.h's contract. */
        for (size_t i = 0; i < blk->n_claims; i++) {
            nodus_v2_tx_result_t *res =
                &blk->cmt.results[blk->n_envs + i];
            uint32_t  target = 0;
            char      sp[48];
            uint32_t  code = NODUS_V2_TX_OK;
            dom_ctx_t *d;
            size_t    j;

            res->code = NODUS_V2_TX_OK;
            res->gas_wanted = 0;
            res->gas_used   = 0;
            res->data_len   = 0;        /* Nodus EVM: a claim carries no Data */
            memset(res->data, 0, sizeof(res->data));
            snprintf(sp, sizeof(sp), "cmt_claim_%llu",
                     (unsigned long long)i);
            if (nodus_witness_db_savepoint(w, sp) != 0) {
                V2AP_FAULT("cometbft claim %llu: SAVEPOINT failed on this "
                           "node", (unsigned long long)i);
                goto fail_fault;
            }
            {
                int prc = claim_prescan_one(w, &blk->claims[i], i,
                                            claim_nuls[i], &target,
                                            blk->out_reason,
                                            sizeof blk->out_reason);
                if (prc == -2) {
                    /* NODE-LOCAL: block FAULT, no item code. The host
                     * owns the whole-transaction ROLLBACK
                     * (nodus_witness_cmt_host.c apply_verified_block:
                     * BEGIN IMMEDIATE before finalize, plain ROLLBACK at
                     * its fail label), which subsumes this savepoint —
                     * it is still unwound here so the claim lane and
                     * the envelope lane (every in-savepoint
                     * `goto fail_fault` above) exit the same way. */
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;
                }
                if (prc != 0) {
                    code = NODUS_V2_TX_ERR_CLAIM;
                    goto cmt_claim_failed;
                }
            }
            for (j = 0; j < i; j++) {
                if (blk->cmt.results[blk->n_envs + j].code ==
                        NODUS_V2_TX_OK &&
                    memcmp(claim_nuls[i], claim_nuls[j], 64) == 0) {
                    code = NODUS_V2_TX_ERR_CLAIM;   /* duplicate in-block */
                    goto cmt_claim_failed;
                }
            }
            d = dom_for(doms, n_dom, target);
            if (!d || d->status != DNA_DOMST_ACTIVE) {
                code = NODUS_V2_TX_ERR_CLAIM;   /* deterministic: registry */
                goto cmt_claim_failed;
            }
            if (!d->rt) {
                /* TV3-P0 (ORCHESTRATOR delta, verifier N7): the
                 * runtime-resolution miss is NODE-LOCAL (a registry read
                 * fault or a compiled table lacking the tuple) and must
                 * not become item code
                 * CLAIM — that would write a build-local condition into
                 * LastResultsHash, the class this package closes.
                 * Unreachable in practice (phase 0a's doms_load already
                 * FAULTed), kept fail-closed in the same class. */
                V2AP_FAULT("cometbft claim %llu targets ACTIVE domain %u "
                           "whose runtime this node cannot resolve",
                           (unsigned long long)i, (unsigned)target);
                (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                (void)cmt_savepoint_release(w, sp);
                goto fail_fault;
            }
            {
                int erc = claim_execute_one(w, blk, i, claim_nuls[i],
                                            blk->out_reason,
                                            sizeof blk->out_reason);
                if (erc == -2) {
                    /* NODE-LOCAL, see above — unwound like the envelope
                     * lane, then the host's ROLLBACK. */
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;
                }
                if (erc != 0) {
                    code = NODUS_V2_TX_ERR_CLAIM;
                    goto cmt_claim_failed;
                }
            }
            /* the NODE-LOCAL address index row of the applied claim,
             * inside its savepoint (see the envelope lane above) */
            if (nodus_witness_addr_index_claim(
                    w, blk->global_height, (uint32_t)(blk->n_envs + i),
                    &blk->claims[i], claim_nuls[i], target,
                    blk->out_reason, sizeof blk->out_reason) != 0) {
                (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                (void)cmt_savepoint_release(w, sp);
                goto fail_fault;       /* the helper owns the reason     */
            }
            /* APPLIED: only now is the target domain touched, so a
             * refused claim moves no domain root. */
            d->touched = 1;
            blk->cmt.results_len = blk->n_envs + i + 1;
            blk->out_reason[0] = '\0';
            if (cmt_savepoint_release(w, sp) != 0) {
                V2AP_FAULT("cometbft claim %llu: RELEASE SAVEPOINT failed "
                           "on this node", (unsigned long long)i);
                goto fail_fault;
            }
            continue;

cmt_claim_failed:
            res->code = code;
            blk->cmt.results_len = blk->n_envs + i + 1;
            blk->out_reason[0] = '\0';   /* an ITEM's refusal is not the
                                          * block's                     */
            if (nodus_witness_db_rollback_to_savepoint(w, sp) != 0 ||
                cmt_savepoint_release(w, sp) != 0) {
                V2AP_FAULT("cometbft claim %llu: its savepoint could not "
                           "be rolled back on this node",
                           (unsigned long long)i);
                goto fail_fault;
            }
        }
    }
    /* (tokenomics-v3 P4: the legacy lane's phases 4-6p — SYSTEM-local,
     * cross-domain and domain-local envelope execution over the whole
     * batch, the batch claim execution and the S7 in-block pool batches
     * — are deleted with the lane. Pool batches cannot reach this engine
     * at all: the item loop above refuses a block carrying one as a node
     * FAULT.) */

    /* 6b'. HF-4 RULE-SET GENERATION SWITCH — at the end of block H-1 only
     * (phase_6b_ruleset_switch above: edge trigger, registry rewrite,
     * SYSTEM + CORE declared touched). BEFORE 6c, so the re-scan below
     * reloads the generation-2 manifests and runtimes. */
    if (phase_6b_ruleset_switch(w, blk, doms, n_dom) != 0)
        goto fail_fault;               /* the helper wrote the reason     */

    /* 6b''. Nodus EVM — the EVM ACTIVATION EDGE, at the end of block H-1 of the
     * EVM_ACTIVE vote only (phase_6b_evm_activation above): SYSTEM / CORE
     * to the EVM generation, the EVM record ACTIVE with no head. After 6b'
     * and BEFORE 6c, so the re-scan activates the EVM domain through
     * head_activate in this same block. */
    if (phase_6b_evm_activation(w, blk, doms, n_dom) != 0)
        goto fail_fault;               /* the helper wrote the reason     */

    /* 6c. LIFECYCLE re-scan (unchanged from S5/S6: canonical DomainHead
     * lifecycle; execution authority stays the BLOCK-ENTRY status). */
    {
        dom_ctx_t *post = calloc(MAX_DOMS, sizeof(*post));
        size_t n_post = 0;
        if (!post) {
            V2AP_FAULT("phase 6c: allocation of the post-block domain "
                       "snapshot failed");
            goto fail_fault;
        }
        if (doms_load(w, post, &n_post, /*strict_active=*/0) != 0) {
            doms_free(post);
            V2AP_FAULT("phase 6c: the domain registry became unreadable "
                       "on this node during the lifecycle re-scan");
            goto fail_fault;
        }
        for (size_t i = 0; i < n_post; i++) {
            dom_ctx_t *p = &post[i];
            dom_ctx_t *pre = dom_for(doms, n_dom, p->domain_id);
            if (pre) {
                p->pre_status = pre->status;
                p->touched = pre->touched;
                p->n_tx = pre->n_tx;
                /* TRANSFER, never copy: `wire_ids` is heap-owned and
                 * sized to `pre`'s own allocation (R3 W4 package C). `pre`
                 * (in the OLD `doms`) gives up ownership immediately so
                 * `doms_free(doms)` — reached later at the
                 * `doms_free(doms); doms = post;` pair closing this
                 * re-scan (:3986-3987) and at every failure label —
                 * cannot double-free what `post`
                 * (soon the function's `doms`) now owns. */
                p->wire_ids = pre->wire_ids;
                pre->wire_ids = NULL;
                p->res_cost = pre->res_cost;
                if (pre->status == DNA_DOMST_RETIRED &&
                    p->status != DNA_DOMST_RETIRED) {
                    QGP_LOG_ERROR(LOG_TAG, "domain %u left RETIRED — "
                                  "terminal state, rejected",
                                  p->domain_id);
                    /* Reason FIRST: p points into `post`, so reading it
                     * after free(post) is a use-after-free. */
                    V2AP_VERDICT("phase 6c: domain %u left the terminal "
                                 "RETIRED state (now status %u)",
                                 (unsigned)p->domain_id,
                                 (unsigned)p->status);
                    doms_free(post);
                    goto fail;
                }
            } else {
                p->pre_status = p->status;
                if (p->has_head) {
                    /* Reason FIRST — p points into `post`. */
                    V2AP_VERDICT("phase 6c: domain %u appeared during "
                                 "this block already carrying a "
                                 "committed head",
                                 (unsigned)p->domain_id);
                    doms_free(post);
                    goto fail;
                }
                if (p->status == DNA_DOMST_ACTIVE)
                    p->pre_status = DNA_DOMST_REGISTERED;
            }
            if (p->status == DNA_DOMST_ACTIVE) {
                if (!p->rt) {
                    /* Mid-block re-resolution failure (incl. resume).
                     * nodus_witness_v2_runtime_for conflates "tuple not
                     * carried" with a node-local domreg read fault, so
                     * this is classified NODE-LOCAL (the SAFE
                     * direction): a witness that cannot resolve must
                     * not vote — silence is tolerated, a confident
                     * reject is not. The deterministic unsupported-
                     * tuple case therefore also reads as -2 here; the
                     * deterministic VERDICTS live in the pre-BEGIN
                     * admission scan. */
                    /* Reason FIRST — p points into `post`. */
                    V2AP_FAULT("phase 6c: domain %u is ACTIVE but its "
                               "runtime tuple no longer resolves on this "
                               "node (conflated seam - classified "
                               "node-local, the SAFE direction)",
                               (unsigned)p->domain_id);
                    doms_free(post);
                    goto fail_fault;
                }
                if (!p->has_head) {
                    if (pre && pre->status == DNA_DOMST_ACTIVE) {
                        /* Reason FIRST — p points into `post`. */
                        V2AP_VERDICT("phase 6c: domain %u was ACTIVE at "
                                     "block entry yet has no committed "
                                     "head - heads are never synthesized "
                                     "here",
                                     (unsigned)p->domain_id);
                        doms_free(post);
                        goto fail;
                    }
                    if (head_activate(w, p, blk->global_height) != 0) {
                        /* Reason FIRST — p points into `post`. */
                        V2AP_VERDICT("phase 6c: activation head for "
                                     "domain %u could not be built at "
                                     "height %llu (runtime state root vs "
                                     "registry genesis_state_root)",
                                     (unsigned)p->domain_id,
                                     (unsigned long long)
                                         blk->global_height);
                        doms_free(post);
                        goto fail;
                    }
                }
            }
        }
        for (size_t i = 0; i < n_dom; i++)
            if (!dom_for(post, n_post, doms[i].domain_id)) {
                doms_free(post);
                V2AP_VERDICT("phase 6c: domain %u vanished from the "
                             "registry during this block",
                             (unsigned)doms[i].domain_id);
                goto fail;
            }
        doms_free(doms);
        doms = post;
        n_dom = n_post;
    }

    /* 6d-bis. tokenomics-v3 P1 (D-2, D-4, Q1) ATTENDANCE — the Rule N
     * source. Credits every COMMIT-flagged vote of cometbft's
     * `decided_last_commit` (`blk->cmt.votes_address` /
     * `.votes_block_id_flag`, copied verbatim by the app,
     * nodus_witness_v2_apply.h) INSIDE this one transaction, before the
     * boundary below and before every root phase (the O15B.1 ordering
     * invariant). Deterministic: a pure function of the request's own
     * bytes, so live application and replay through this same engine
     * write identical rows. Declares NO domain touched: `v2_attendance`
     * is OUT OF EVERY ROOT (D-4) — a credit here moves no state_root
     * byte until the epoch boundary's digest leg commits its SUMMARY of
     * the ended epoch (attendance_root, shared/dnac/ledger_roots_v2.c).
     * `votes_len == 0` (the initial height) is the legal empty case: the
     * writer no-ops. */
    if (nodus_witness_v2_attendance_credit(w, blk->global_height,
                                           blk->cmt.votes_address,
                                           blk->cmt.votes_block_id_flag,
                                           blk->cmt.votes_len) != 0) {
        V2AP_FAULT("phase 6d: attendance credit at height %llu failed on "
                   "this node", (unsigned long long)blk->global_height);
        goto fail_fault;
    }

    /* 6e. O12 S2 EPOCH BOUNDARY — engine-MANDATORY, not caller-declared.
     * A no-op on every non-boundary height, so it runs unconditionally
     * (including for a ZERO-envelope block: nothing earlier in this
     * function short-circuits an empty batch — every envelope stage is
     * guarded by `blk->n_envs > 0`). It sits AFTER the claim/pool phases
     * and the lifecycle re-scan (so `doms` is the post-scan working set)
     * and BEFORE the supply gate, so the gate covers the graduation's
     * self_stake → UTXO bucket move inside this very block.
     *
     * There is no verdict class at a boundary — its input is committed
     * state and the height alone — so any failure is a NODE FAULT
     * (contract: nodus_witness_v2_epoch.h). */
    {
        nodus_v2_epoch_result_t ep;
        if (nodus_witness_v2_epoch_boundary_apply(w, blk->global_height,
                                                  chain_id,
                                                  epoch_stage_fault, blk,
                                                  &ep) != 0) {
            V2AP_FAULT("phase 6e: epoch-boundary apply at height %llu "
                       "failed - a boundary has no verdict class, its "
                       "input is committed state and the height alone",
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }
        if (ep.fired) {
            /* TOUCHED DECLARATION. The boundary moves consensus state
             * that feeds domain roots: `validators` and
             * `validator_set_snapshots` are legs of system_state_root
             * (nodus_witness_roots_v2.c:279-311), and a graduation
             * release writes `utxo_set`, a leg of core_state_root. The
             * untouched-domain guard below would otherwise reject the
             * block. CORE is declared ONLY when a graduate actually
             * released — declaring it on a graduate-free boundary would
             * trip the "declared but changed nothing" reject instead. */
            dom_ctx_t *dsys = dom_for(doms, n_dom, DNA_DOMAIN_SYSTEM);
            if (!dsys) {                  /* a boundary mutated SYSTEM
                                           * state on a chain with no
                                           * SYSTEM domain: unresolvable
                                           * on THIS node, fail closed  */
                V2AP_FAULT("phase 6e: epoch boundary fired at height %llu "
                           "but SYSTEM domain %u is absent from the "
                           "working set",
                           (unsigned long long)blk->global_height,
                           (unsigned)DNA_DOMAIN_SYSTEM);
                goto fail_fault;
            }
            dsys->touched = 1;
            /* tokenomics-v3 P2 — CORE is touched by a graduation release
             * (utxo_set), by the reward distribution (v2_reward_accrual
             * and supply_tracking.reward_pool) and by the payday
             * (utxo_set and v2_reward_accrual) — all CORE state-root legs
             * (nodus_witness_roots_v2.c nodus_witness_core_root_v2). A
             * boundary that credits nothing and pays nothing moves none
             * of them and must NOT declare CORE: phase 9 rejects a
             * declared no-op as hard as phase 8 rejects an undeclared
             * mutation. The balance copy is out of every root. */
            /* General multisig (decision 2026-09-29-general-multisig.md)
             * withdrew W-A's genesis-seat refund into the Foundation
             * treasury pool: EVERY graduate again releases its bond as a
             * UTXO (a genesis seat's to the Foundation multisig
             * address), so a graduate is again proof that utxo_set — a
             * CORE leg — moved, and the graduate count is the input. */
            /* Archive reward (storage reward v1 rev 4, design rev 2.2
             * §5.6 "CORE when storage credit > 0 or an exit UTXO is
             * created"): the storage boundary's accrual credits and exit
             * release UTXOs are CORE legs too. */
            if (ep.n_graduates > 0 || ep.dist_accrued > 0 ||
                ep.n_payday_utxos > 0 || ep.storage_accrued > 0 ||
                ep.n_storage_releases > 0) {
                dom_ctx_t *dcore = dom_for(doms, n_dom, DNA_DOMAIN_CORE);
                if (!dcore) {
                    V2AP_FAULT("phase 6e: the boundary moved CORE state "
                               "(%u graduates, %llu accrued, %u payday "
                               "utxos) but CORE domain %u is absent from "
                               "the working set",
                               (unsigned)ep.n_graduates,
                               (unsigned long long)ep.dist_accrued,
                               (unsigned)ep.n_payday_utxos,
                               (unsigned)DNA_DOMAIN_CORE);
                    goto fail_fault;
                }
                dcore->touched = 1;
            }
        }
    }

    /* 6e+. The NODE-LOCAL address index closes the block (decision
     * 2026-10-01-node-address-history-index.md rev 2): every writer
     * above has run (items, claims, the boundary's payout and release
     * rows), so the block time — `blk->timestamp`, the Comet header's
     * time the host copied from RequestFinalizeBlock.time.seconds — is
     * stamped on this height's rows here, still inside the block
     * transaction, and the first-indexed-height marker advances. Out of
     * every root; a no-op unless the node flag is on; a failure is this
     * node's FAULT. */
    if (nodus_witness_addr_index_block_close(w, blk->global_height,
                                             blk->timestamp,
                                             blk->out_reason,
                                             sizeof blk->out_reason) != 0)
        goto fail_fault;               /* the helper owns the reason     */

    /* 6f. PER-BLOCK BUILD-IDENTITY CHECK (tokenomics-v3 P2, P2-4).
     *
     * This phase used to be the O15J per-block INFLATION EMISSION
     * (nodus_witness_v2_emission_apply). P2 deletes the mint (decision
     * file §1: "Yeni token basılmayacak"; §3 S-4), but the mint was also
     * the per-block caller of nodus_witness_v2_econ_params_load, whose
     * build-identity refusals must STILL run on every block: a node whose
     * compiled DNAC_EPOCH_LENGTH disagrees with the chain's committed one
     * would key its boundaries differently from its peers, and one whose
     * compiled DNAC_DECIMAL_UNIT disagrees would derive every voting power
     * (and the reward split's power) differently. This phase runs AFTER
     * 6e, so on a boundary block a mismatched node has already executed
     * its boundary in this transaction — the fault below rolls the whole
     * block back, boundary included, so nothing it computed commits.
     * That call is what remains here, with the same behaviour
     * the mint gave it: a fault is a node fault, never a fallback; an
     * absent band (present == 0, a chain built before Block 2C) keeps the
     * compiled constants. It moves no state and declares nothing. The
     * old F52 injection point (V2AP_FAIL_AFTER_EMISSION) is RETIRED with
     * the mint it bracketed. */
    {
        nodus_v2_econ_params_t econ;
        if (nodus_witness_v2_econ_params_load(w, &econ) != 0) {
            V2AP_FAULT("phase 6f: the committed economic parameters at "
                       "height %llu could not be established on this "
                       "node (unreadable band, partial band, or an "
                       "epoch_length or decimal_unit this build did not "
                       "compile)",
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }
    }

    /* 7. supply gate (post-stage) */
    if (nodus_witness_v2_supply_check(w) != 0) {
        V2AP_VERDICT("phase 7: POST-STAGE supply gate failed - a "
                     "registered runtime's conservation invariant does "
                     "not hold after this block's mutations (gate helper "
                     "conflates a read fault: honest label in the "
                     "header)");
        goto fail;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_SUPPLY_MUT);

    /* 8. domain roots (runtime-dispatched) + untouched-domain guard. */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        d->root_known = 0;
        if (d->activated) {
            memcpy(d->root_now, d->head.domain_state_root, 64);
            d->root_known = 1;
            continue;
        }
        if (d->pre_status == DNA_DOMST_ACTIVE) {
            if (!d->rt) {                /* was executable at block entry
                                         * (strict doms_load proved the
                                         * runtime) — losing it mid-block
                                         * is the conflated re-resolution
                                         * seam above: node-local, never
                                         * a verdict                     */
                V2AP_FAULT("phase 8: domain %u was executable at block "
                           "entry but its runtime no longer resolves on "
                           "this node", (unsigned)d->domain_id);
                goto fail_fault;
            }
            if (d->rt->state_root(d->rt, w, d->root_now) != 0) {
                V2AP_FAULT("phase 8: domain %u's runtime could not "
                           "compute its own state root",
                           (unsigned)d->domain_id);
                goto fail_fault;        /* the runtime could not compute
                                         * its own root — node fault    */
            }
            d->root_known = 1;
        }
        if (d->touched && !d->root_known) {
            V2AP_VERDICT("phase 8: domain %u is declared touched but its "
                         "root is unknowable (block-entry status %u, "
                         "current status %u)",
                         (unsigned)d->domain_id, (unsigned)d->pre_status,
                         (unsigned)d->status);
            goto fail;
        }
        if (!d->touched && d->root_known && d->has_head &&
            memcmp(d->root_now, d->head.domain_state_root, 64) != 0) {
            char n[17], o[17];
            QGP_LOG_ERROR(LOG_TAG,
                "domain %u mutated without being declared touched",
                d->domain_id);
            V2AP_VERDICT("phase 8: UNTOUCHED-DOMAIN GUARD - domain %u was "
                         "not declared touched yet its root moved %s -> "
                         "%s (cross-domain substitution)",
                         (unsigned)d->domain_id,
                         v2ap_hex8(d->head.domain_state_root, o),
                         v2ap_hex8(d->root_now, n));
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_DOMAIN_ROOTS);

    /* 9. DomainUpdates (touched only).
     *
     * A touched domain whose root this block left UNCHANGED (post == pre):
     *   - HF-2 OFF (below the HF-2 height; every chain without the
     *     chain_config param-7 row): a block VERDICT, as before HF-2 — "no
     *     fake empty updates". On this lane the verdict is a CMT_FAULT at
     *     FinalizeBlock, i.e. every node stops at the same block.
     *   - HF-2 ON (GW-2, nodus/BUGS.md ACİL-4): a LEGITIMATE outcome, not
     *     a fake update. Valid items can net to zero — a DELEGATE that
     *     creates a (delegator, validator) row and a full UNDELEGATE of the
     *     same pair in one block leave the SYSTEM root byte-identical — and
     *     a proposer who orders them into one block must not be able to
     *     stop every honest node. The DomainUpdate is written with
     *     pre_root == post_root exactly like a changed domain's (its
     *     tx_batch_root still names the items that ran), and phases 10-12
     *     treat the domain as touched. Treating it as UNTOUCHED instead
     *     would keep its head height, so phase 12's v2_tx_local_index
     *     rows (PRIMARY KEY domain_id, domain_height, local_index) would
     *     collide with the rows the block that last advanced the domain
     *     wrote at that height — a FAULT (design §4a F6).
     * The cometbft lane is the only lane (the entry refused !cmt.on), so
     * "Comet lane AND HF-2" reduces to HF-2 alone. The switch is read once
     * for the block at its own height, fault = abort (env_hf2_active). */
    {
        size_t n_upd = 0;
        uint8_t hf2 = 0;
        if (env_hf2_active(w, blk->global_height, &hf2, blk->out_reason,
                           sizeof blk->out_reason) != 0)
            goto fail_fault;          /* the helper wrote the reason      */
        for (size_t i = 0; i < n_dom; i++) {
            dom_ctx_t *d = &doms[i];
            if (!d->touched) continue;
            if (!hf2 &&
                memcmp(d->root_now, d->head.domain_state_root, 64) == 0) {
                char r[17];
                V2AP_VERDICT("phase 9: domain %u is declared touched but "
                             "its root is unchanged at %s - a DECLARED "
                             "no-op, no fake empty updates",
                             (unsigned)d->domain_id,
                             v2ap_hex8(d->root_now, r));
                goto fail;               /* declared but changed nothing */
            }
            memset(&d->upd, 0, sizeof(d->upd));
            d->upd.update_version = DNA_DUPD_VERSION;
            d->upd.domain_id = d->domain_id;
            d->upd.old_height = d->head.domain_height;
            d->upd.new_height = d->head.domain_height + 1;
            d->upd.global_height = blk->global_height;
            memcpy(d->upd.pre_root, d->head.domain_state_root, 64);
            memcpy(d->upd.post_root, d->root_now, 64);
            if (dna_v2_tx_batch_root(
                    (const uint8_t (*)[64])d->wire_ids, d->n_tx,
                    d->upd.tx_batch_root) != 0) {
                V2AP_FAULT("phase 9: tx_batch_root over domain %u's %u "
                           "wire ids could not be computed",
                           (unsigned)d->domain_id, (unsigned)d->n_tx);
                goto fail_fault;
            }
            d->upd.ruleset_version = d->man.ruleset_version;
            memcpy(d->upd.ruleset_hash, d->man.ruleset_hash, 64);
            d->upd.res_tx_count = d->n_tx;
            d->upd.res_verify_cost = d->res_cost;   /* ACTUAL consumed
                                         * units (env legs; claims/pools
                                         * ride their own accounting)   */
            if (prev_update_hash(w, d->domain_id,
                                 d->upd.prev_update_hash) != 0) {
                V2AP_FAULT("phase 9: previous DomainUpdate hash for "
                           "domain %u is unreadable on this node",
                           (unsigned)d->domain_id);
                goto fail_fault;
            }
            if (dna_dupd_hash(&d->upd, d->upd_hash) != 0) {
                V2AP_FAULT("phase 9: DomainUpdate hash for domain %u "
                           "could not be computed",
                           (unsigned)d->domain_id);
                goto fail_fault;
            }

            uint8_t enc[DNA_DUPD_ENC_LEN];
            if (dna_dupd_encode(&d->upd, enc) != 0) {
                V2AP_FAULT("phase 9: DomainUpdate for domain %u could not "
                           "be encoded", (unsigned)d->domain_id);
                goto fail_fault;
            }
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_domain_updates (global_height, "
                    "domain_id, upd, upd_hash) VALUES (?1, ?2, ?3, ?4)",
                    -1, &st, NULL) != SQLITE_OK) {
                V2AP_FAULT("phase 9: could not prepare the "
                           "v2_domain_updates insert for domain %u",
                           (unsigned)d->domain_id);
                goto fail_fault;
            }
            sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)d->domain_id);
            sqlite3_bind_blob(st, 3, enc, DNA_DUPD_ENC_LEN,
                              SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 4, d->upd_hash, 64, SQLITE_TRANSIENT);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) {
                V2AP_FAULT("phase 9: v2_domain_updates insert for domain "
                           "%u failed (sqlite rc %d)",
                           (unsigned)d->domain_id, rc);
                goto fail_fault;
            }
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
            if (head_store(w, &d->newhead) != 0) {
                V2AP_FAULT("phase 10: DomainHead write for domain %u "
                           "(domain height %llu) failed",
                           (unsigned)d->domain_id,
                           (unsigned long long)d->newhead.domain_height);
                goto fail_fault;
            }
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
                NULL) != SQLITE_OK) {
            V2AP_FAULT("phase 11: could not prepare the v2_root_history "
                       "insert for domain %u", (unsigned)d->domain_id);
            goto fail_fault;
        }
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
        if (rc != SQLITE_DONE) {
            V2AP_FAULT("phase 11: v2_root_history insert for domain %u "
                       "failed (sqlite rc %d)",
                       (unsigned)d->domain_id, rc);
            goto fail_fault;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_HISTORY);

    /* 12. transaction indices — DERIVED identities ONLY. TWO indices per
     * transaction (intent season): the SEMANTIC index (v2_intent_index —
     * intent_id PK + the ONE accepted wire realization) and the WIRE
     * indices (v2_tx_index / v2_tx_local_index from pf[i].wire_id).
     *
     * The two IDENTITY rows of every APPLIED item were already written
     * inside that item's own SAVEPOINT (cmt_item_index — so a refused
     * item left none), and only the LOCAL index rows are left: they
     * could not be written there because their `domain_height` column
     * is the head height phases 9-10 compute. The loop below writes them
     * over the APPLIED items in block order. (tokenomics-v3 P4: the
     * legacy lane's whole-batch identity inserts, in its phase order,
     * are deleted with the lane.) */
    for (size_t i = 0; i < blk->n_envs; i++) {
        const dna_env_view_t *v;
        uint16_t t;

        if (blk->cmt.results[i].code != NODUS_V2_TX_OK) {
            continue;                    /* refused: no rows at all      */
        }
        v = &pf[i].view;
        for (t = 0; t < v->leg_count; t++) {
            dom_ctx_t *d = dom_for(doms, n_dom, v->leg[t].domain_id);
            uint32_t lidx = 0;
            sqlite3_stmt *ls = NULL;
            int rc;

            if (!d) {
                V2AP_FAULT("phase 12: applied item %llu leg %u names "
                           "domain %u, absent from the working set at "
                           "index time",
                           (unsigned long long)i, (unsigned)t,
                           (unsigned)v->leg[t].domain_id);
                goto fail_fault;
            }
            if (nodus_witness_v2_local_index_find(
                    (const uint8_t (*)[64])d->wire_ids, d->n_tx,
                    pf[i].wire_id, &lidx) != 0) {
                V2AP_FAULT("phase 12: applied item %llu's wire id is "
                           "missing from domain %u's own %u-entry id "
                           "list - engine invariant broken on THIS node",
                           (unsigned long long)i, (unsigned)d->domain_id,
                           (unsigned)d->n_tx);
                goto fail_fault;
            }
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_tx_local_index (tx_id, domain_id, "
                    "domain_height, local_index) VALUES (?1,?2,?3,?4)",
                    -1, &ls, NULL) != SQLITE_OK) {
                V2AP_FAULT("phase 12: could not prepare the "
                           "v2_tx_local_index insert for applied item "
                           "%llu domain %u",
                           (unsigned long long)i, (unsigned)d->domain_id);
                goto fail_fault;
            }
            sqlite3_bind_blob(ls, 1, pf[i].wire_id, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(ls, 2, (sqlite3_int64)v->leg[t].domain_id);
            sqlite3_bind_int64(ls, 3,
                               (sqlite3_int64)d->newhead.domain_height);
            sqlite3_bind_int64(ls, 4, (sqlite3_int64)lidx);
            rc = sqlite3_step(ls);
            sqlite3_finalize(ls);
            if (rc != SQLITE_DONE) {
                V2AP_FAULT("phase 12: v2_tx_local_index insert for "
                           "applied item %llu domain %u (local index %u) "
                           "failed (sqlite rc %d)", (unsigned long long)i,
                           (unsigned)d->domain_id, (unsigned)lidx, rc);
                goto fail_fault;
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_TX_INDEX);

    /* (12b, the O15E Faz B `v2_tx_bytes` persistence of every carried
     * envelope's wire bytes, is DELETED — tokenomics-v3 P4 fix round.
     * It had no reader (its BlockMessage v1 consumer went with the
     * closed lane, R3 W4), it was out of every state root, and its
     * `tx_id UNIQUE` made a byte-identical envelope in a later block —
     * refused items were written too — fail the insert: a node FAULT on
     * every node, i.e. a chain halt any one proposer could trigger. The
     * table goes with it (nodus_witness_v2_schema.c, the S11 rung); F48
     * is retired.) */

    /* 12c. O15F Task 4 — per-block canonical claim byte availability.
     * For EVERY block (claims or not) the claim COUNT is recorded inside
     * the SAME block transaction, so a serving seam can tell "this block
     * had zero claims" from "this height predates S12" (the count row is
     * ABSENT pre-S12 — that height fails closed at the seam). When the
     * block carries claims, each claim's canonical dna_claim_encode bytes
     * — the SAME bytes admission verified and the engine re-executes — are
     * persisted in block claim order (claim_index = the position in
     * blk->claims), keyed with claim_hash = SHA3-512(bytes). Unlike
     * envelopes (bound DIRECTLY through tx_root) claims are bound only
     * TRANSITIVELY (claims_root leg), so these bytes are what a peer needs
     * to re-derive the claim. (The S12 schema guard this phase carried
     * for pre-S12 fixture databases is gone with the legacy lane: this
     * engine runs at S16 only.) */
    {
        {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_claim_counts (global_height, n_claims) "
                    "VALUES (?1,?2)", -1, &st, NULL) != SQLITE_OK) {
                V2AP_FAULT("phase 12c: could not prepare the "
                           "v2_claim_counts insert for height %llu",
                           (unsigned long long)blk->global_height);
                goto fail_fault;
            }
            sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)blk->n_claims);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) {
                V2AP_FAULT("phase 12c: v2_claim_counts insert for height "
                           "%llu (%llu claims) failed (sqlite rc %d)",
                           (unsigned long long)blk->global_height,
                           (unsigned long long)blk->n_claims, rc);
                goto fail_fault;
            }
        }
        for (size_t i = 0; i < blk->n_claims; i++) {
            /* the SAME canonical encoding admission verified — one
             * accepted encoding per claim; a re-encode failure here is an
             * engine invariant broken on THIS node (the claim already
             * validated + applied), so it is a node fault, not a verdict.
             * Exact-size heap buffer (worst claim ≈ 11.6 KB — kept off the
             * already-large apply frame). */
            size_t need = dna_claim_encoded_len(&blk->claims[i]);
            if (need == 0) {
                V2AP_FAULT("phase 12c: claim %llu re-encode length is 0 "
                           "although the claim already validated and "
                           "applied - engine invariant broken on THIS "
                           "node", (unsigned long long)i);
                goto fail_fault;
            }
            uint8_t *cbuf = (uint8_t *)malloc(need);
            if (!cbuf) {
                V2AP_FAULT("phase 12c: allocation of %llu bytes for claim "
                           "%llu re-encode failed",
                           (unsigned long long)need,
                           (unsigned long long)i);
                goto fail_fault;
            }
            size_t clen = 0;
            if (dna_claim_encode(&blk->claims[i], cbuf, need, &clen) != 0 ||
                clen != need) {
                free(cbuf);
                V2AP_FAULT("phase 12c: claim %llu re-encode produced %llu "
                           "bytes, expected %llu",
                           (unsigned long long)i,
                           (unsigned long long)clen,
                           (unsigned long long)need);
                goto fail_fault;
            }
            uint8_t chash[64];
            if (qgp_sha3_512(cbuf, clen, chash) != 0) {
                free(cbuf);
                V2AP_FAULT("phase 12c: hash backend failed over claim "
                           "%llu's %llu canonical bytes",
                           (unsigned long long)i,
                           (unsigned long long)clen);
                goto fail_fault;
            }
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_claim_bytes (global_height, "
                    "claim_index, claim_hash, claim) VALUES (?1,?2,?3,?4)",
                    -1, &st, NULL) != SQLITE_OK) {
                free(cbuf);
                V2AP_FAULT("phase 12c: could not prepare the "
                           "v2_claim_bytes insert for claim %llu",
                           (unsigned long long)i);
                goto fail_fault;
            }
            sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)i);
            sqlite3_bind_blob(st, 3, chash, 64, SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 4, cbuf, (int)clen, SQLITE_TRANSIENT);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            free(cbuf);
            if (rc != SQLITE_DONE) {
                V2AP_FAULT("phase 12c: v2_claim_bytes insert for claim "
                           "%llu failed (sqlite rc %d)",
                           (unsigned long long)i, rc);
                goto fail_fault;
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_CLAIM_BYTES);

    /* 13. block-level roots + expectation compare + metadata */
    {
        /* R3 W4 package C — HEAP, sized to the block's own n_envs (not
         * the release bound NODUS_V2_ENV_BATCH_MAX, which has moved
         * several times — 16 originally, 10 at delta 1, now 3 209 as a
         * derived memory ceiling since delta 2 — but the point stands
         * regardless of its value: this array's true size has always
         * been n_envs, never the engine's compile-time cap). Self-
         * contained: allocated and freed within this one nested block,
         * on every exit from it. */
        uint8_t (*all_ids)[64] = NULL;
        uint32_t n_all = 0;
        if (blk->n_envs > 0) {
            all_ids = calloc(blk->n_envs, sizeof(*all_ids));
            if (!all_ids) {
                V2AP_FAULT("phase 13: allocation of the %llu-entry "
                           "tx_root id scratch failed",
                           (unsigned long long)blk->n_envs);
                goto fail_fault;
            }
        }
        /* R3-C1a-7, and the ROW'S OWN RULE: `tx_root` commits the ids
         * of the items this block APPLIED, in block order, and
         * `tx_count` is the size of exactly that list. A refused item
         * contributes neither — its effects went away with its
         * SAVEPOINT, and committing its id would bind the block to a
         * transaction whose state changes were rolled back. (A refused
         * item's `pf[i]` is zeroed by the preflight's own reject path,
         * so including it would commit a run of zero bytes, which is
         * the same defect wearing a disguise.)
         *
         * This is NOT the block's `Data.Txs` count: that one is
         * consensus's, it counts every item the block carries, and it
         * lives in the Comet header's DataHash. The row's `tx_count` is
         * the LEDGER's, and the two differ exactly by the refused items
         * — by design. */
        for (size_t i = 0; i < blk->n_envs; i++)
            if (blk->cmt.results[i].code == NODUS_V2_TX_OK)
                memcpy(all_ids[n_all++], pf[i].wire_id, 64);
        if (dna_v2_tx_batch_root(
                n_all ? (const uint8_t (*)[64])all_ids : NULL, n_all,
                blk->out_tx_root) != 0) {
            V2AP_FAULT("phase 13: tx_root over %u derived ids could not "
                       "be computed", (unsigned)n_all);
            free(all_ids);
            goto fail_fault;
        }
        free(all_ids);

        dna_domain_update_t upd_sorted[MAX_DOMS];
        size_t n_upd = 0;
        for (size_t i = 0; i < n_dom; i++)
            if (doms[i].touched)
                upd_sorted[n_upd++] = doms[i].upd;
        if (dna_v2_domain_updates_root(n_upd ? upd_sorted : NULL, n_upd,
                                       blk->out_dupd_root) != 0) {
            V2AP_FAULT("phase 13: domain_updates_root over %llu updates "
                       "could not be computed",
                       (unsigned long long)n_upd);
            goto fail_fault;
        }

        dna_v2_domain_head_t root_heads[MAX_DOMS];
        size_t n_heads = 0;
        for (size_t i = 0; i < n_dom; i++)
            if (doms[i].has_head)
                root_heads[n_heads++] = doms[i].newhead;
        if (dna_v2_domains_root(root_heads, n_heads,
                                blk->out_domains_root) != 0) {
            V2AP_FAULT("phase 13: domains_root over %llu heads could not "
                       "be computed", (unsigned long long)n_heads);
            goto fail_fault;
        }
        if (dna_v2_global_root(blk->out_domains_root,
                               blk->out_global_root) != 0) {
            V2AP_FAULT("phase 13: global_root could not be computed from "
                       "domains_root");
            goto fail_fault;
        }

        /* The expectation compares. These are the follower/leader
         * assertion channel, and they are the most likely way a block
         * that every witness VOTED for still dies at commit — so each
         * one names the field and both values. */
        if (blk->expect_tx_root &&
            memcmp(blk->expect_tx_root, blk->out_tx_root, 64) != 0) {
            char e[17], d[17];
            V2AP_VERDICT("phase 13: tx_root mismatch - asserted %s, "
                         "engine derived %s over %u transactions at "
                         "height %llu",
                         v2ap_hex8(blk->expect_tx_root, e),
                         v2ap_hex8(blk->out_tx_root, d), (unsigned)n_all,
                         (unsigned long long)blk->global_height);
            goto fail;
        }
        if (blk->expect_dupd_root &&
            memcmp(blk->expect_dupd_root, blk->out_dupd_root, 64) != 0) {
            char e[17], d[17];
            V2AP_VERDICT("phase 13: domain_updates_root mismatch - "
                         "asserted %s, engine derived %s over %llu "
                         "updates at height %llu",
                         v2ap_hex8(blk->expect_dupd_root, e),
                         v2ap_hex8(blk->out_dupd_root, d),
                         (unsigned long long)n_upd,
                         (unsigned long long)blk->global_height);
            goto fail;
        }
        if (blk->expect_domains_root &&
            memcmp(blk->expect_domains_root, blk->out_domains_root, 64)
                != 0) {
            char e[17], d[17];
            V2AP_VERDICT("phase 13: domains_root mismatch - asserted %s, "
                         "engine derived %s over %llu heads at height "
                         "%llu",
                         v2ap_hex8(blk->expect_domains_root, e),
                         v2ap_hex8(blk->out_domains_root, d),
                         (unsigned long long)n_heads,
                         (unsigned long long)blk->global_height);
            goto fail;
        }
        if (blk->expect_global_root &&
            memcmp(blk->expect_global_root, blk->out_global_root, 64)
                != 0) {
            char e[17], d[17], dm[17];
            V2AP_VERDICT("phase 13: global_root mismatch at height %llu - "
                         "asserted %s, engine derived %s (domains_root "
                         "%s, %llu heads)",
                         (unsigned long long)blk->global_height,
                         v2ap_hex8(blk->expect_global_root, e),
                         v2ap_hex8(blk->out_global_root, d),
                         v2ap_hex8(blk->out_domains_root, dm),
                         (unsigned long long)n_heads);
            goto fail;
        }

        /* ── THE LEDGER DERIVES NO IDENTITY (D-17 rev 7 (6)) ──────────
         * The identity a validator signed is cometbft's header hash, and
         * consensus handed it to FinalizeBlock. The ledger stores it
         * verbatim and derives nothing of its own: header v3 is
         * withdrawn (D-19 rev 6), and the `header` column that would
         * hold it does not exist at S14. `vset_hash` is likewise the
         * block's Comet ValidatorsHash, passed in. The ledger's own
         * global root goes into `global_root` as always and is bound by
         * consensus as the NEXT header's AppHash. (tokenomics-v3 P4: the
         * legacy lane's own dna_bh2 header build, its derived BlockID
         * and the expect_block_id assertion against it — with the
         * F46/F47 injection points that bracketed them — are deleted
         * with the lane.) */
        memcpy(blk->out_block_id, blk->cmt.block_hash, 64);
        memcpy(blk->out_vset_hash, blk->cmt.validators_hash, 64);

        /* Same BlockID already committed at ANOTHER height? The UNIQUE
         * constraint backstops it; checking explicitly names the case.
         * The id is consensus's, so a duplicate means this node is being
         * asked to commit a block it already has — the wrapper turns the
         * verdict below into a fault. */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_blocks WHERE block_id = ?1", -1, &st,
                NULL) != SQLITE_OK) {
            V2AP_FAULT("phase 13: could not prepare the duplicate-BlockID "
                       "probe");
            goto fail_fault;
        }
        sqlite3_bind_blob(st, 1, blk->out_block_id, 64, SQLITE_TRANSIENT);
        int drc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (drc == SQLITE_ROW) {
            char d[17];
            V2AP_VERDICT("phase 13: block hash %s is already "
                         "committed at ANOTHER height",
                         v2ap_hex8(blk->out_block_id, d));
            goto fail;
        }
        if (drc != SQLITE_DONE) {
            V2AP_FAULT("phase 13: duplicate-BlockID probe failed to step "
                       "(sqlite rc %d)", drc);
            goto fail_fault;
        }

        st = NULL;
        /* THE ROW SHAPE. S14 drops `header`, `qc` and `commit_cert`
         * (D-17 rev 5/7): under cometbft the header lives in the block
         * store's BlockMeta, the seen commit under `SC:<h>` and the
         * canonical commit under `C:<h>` — none of them is the ledger's
         * to keep. So the insert names TEN columns. */
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                -1, &st, NULL) != SQLITE_OK) {
            V2AP_FAULT("phase 13: could not prepare the Comet v2_blocks "
                       "metadata insert for height %llu",
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }
        sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
        sqlite3_bind_blob(st, 2, blk->out_block_id, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 3, blk->out_prev_block_id, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)blk->epoch);
        sqlite3_bind_blob(st, 5, blk->out_tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, blk->out_dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, blk->out_domains_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, blk->out_global_root, 64,
                          SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 9, blk->out_vset_hash, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 10, (sqlite3_int64)n_all);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) {
            V2AP_FAULT("phase 13: v2_blocks metadata insert for height "
                       "%llu failed (sqlite rc %d)",
                       (unsigned long long)blk->global_height, rc);
            goto fail_fault;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_BLOCK_META);

    /* 14. supply gate (pre-commit) */
    if (nodus_witness_v2_supply_check(w) != 0) {
        V2AP_VERDICT("phase 14: PRE-COMMIT supply gate failed - a "
                     "registered runtime's conservation invariant does "
                     "not hold with every row this block wrote (gate "
                     "helper conflates a read fault: honest label in the "
                     "header)");
        goto fail;
    }
    FAIL_POINT(V2AP_FAIL_BEFORE_COMMIT);

    /* 15. THE ENGINE COMMITS NOTHING. The host opened the transaction
     * before FinalizeBlock and `app.commit` closes it (D-23 rev 5 (5)),
     * so this entry returns with the transaction still OPEN and every
     * row it wrote still uncommitted — which is exactly what lets
     * `SaveFinalizeBlockResponse` and `updateState` join it.
     * (tokenomics-v3 P4: the legacy lane's own COMMIT, its simulated
     * COMMIT failure F14 and its post-commit window F15 / rc 2 are
     * deleted with the lane.) */
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(claim_nuls);
    free(cm_pubkeys); free(cm_fps); free(cm_powers);
    doms_free(doms);
    return 0;

/* ── the two rejection exits (contract in the header) ────────────────
 * Meter/budget rollback: aborting every non-terminal meter restores the
 * engine-owned budget byte-identically (res_meter abort contract); the
 * budget itself is per-block and dies with this frame, so no residue
 * can reach a later block either way.
 *
 * Each label ends with the same belt-and-braces line: if the site that
 * jumped here recorded nothing, say SO — plainly, naming the label —
 * rather than letting a caller print an empty string or, worse, invent a
 * cause. Reading out_reason[0] here selects a string and nothing else;
 * no return code depends on it. */
fail:
    if (blk->out_reason[0] == '\0')
        V2AP_VERDICT("in-transaction rejection with no reason recorded "
                     "(`fail` label)");
    /* THE ROLLBACK IS THE TRANSACTION OWNER'S: the host owns it (D-23
     * rev 5 (5)) and rolls it back itself when this entry fails; issuing
     * one here would close a transaction the host still believes is
     * open. */
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(claim_nuls);
    free(cm_pubkeys); free(cm_fps); free(cm_powers);
    doms_free(doms);
    return -1;

fail_fault:
    /* the host's rollback, as at `fail` */
    if (blk->out_reason[0] == '\0')
        V2AP_FAULT("in-transaction node fault with no reason recorded "
                   "(`fail_fault` label)");
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(claim_nuls);
    free(cm_pubkeys); free(cm_fps); free(cm_powers);
    doms_free(doms);
    return -2;

/* the pre-transaction exit: the working-set allocation (nothing written
 * to the database yet) */
fail_fault_pre:
    if (blk->out_reason[0] == '\0')
        V2AP_FAULT("pre-transaction node fault with no reason recorded "
                   "(`fail_fault_pre` label)");
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(claim_nuls);
    free(cm_pubkeys); free(cm_fps); free(cm_powers);
    doms_free(doms);
    return -2;
}

int nodus_witness_v2_committed_global_root(nodus_witness_t *w,
                                           uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    dom_ctx_t    *doms = NULL;
    dna_v2_domain_head_t *heads = NULL;
    uint8_t       domains_root[64];
    size_t        n_dom = 0, n_heads = 0, i;
    int           rc, ret = -1;

    if (!w || !w->db || !out) {
        return -1;
    }
    /* (1) the TIP row, if there is one. ORDER BY ... DESC LIMIT 1 rather
     * than MAX(global_height) so the row and its column come from the
     * same read. */
    if (sqlite3_prepare_v2(w->db,
            "SELECT global_root FROM v2_blocks "
            "ORDER BY global_height DESC LIMIT 1", -1, &st, NULL)
        != SQLITE_OK) {
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        return -1;                       /* a read fault is not "empty"  */
    }

    /* (2) no block row — the cometbft lane's genesis state. Recompute
     * exactly as nodus_witness_v2_genesis_cmt composed it: the COMMITTED
     * heads of the ACTIVE domains, in domain_id order (doms_load's ORDER
     * BY), through the same two functions. */
    doms = calloc(MAX_DOMS, sizeof(*doms));
    if (!doms) {
        return -1;
    }
    if (doms_load(w, doms, &n_dom, /*strict_active=*/0) != 0) {
        doms_free(doms);
        return -1;
    }
    heads = calloc(n_dom ? n_dom : 1, sizeof(*heads));
    if (!heads) {
        doms_free(doms);
        return -1;
    }
    for (i = 0; i < n_dom; i++) {
        if (doms[i].status == DNA_DOMST_ACTIVE && doms[i].has_head) {
            heads[n_heads++] = doms[i].head;
        }
    }
    if (n_heads > 0 &&
        dna_v2_domains_root(heads, n_heads, domains_root) == 0 &&
        dna_v2_global_root(domains_root, out) == 0) {
        ret = 0;
    }
    free(heads);
    doms_free(doms);
    return ret;
}

int nodus_witness_v2_apply_block(nodus_witness_t *w, nodus_v2_block_t *blk) {
    int rc = v2_apply_block_body(w, blk);

    /* ── A DECIDED BLOCK IS NEVER REFUSED (D-23 rev 5 (6)) ────────────
     * In the cometbft lane the block reached this engine only AFTER a
     * quorum committed to it, and `ProcessProposal` ran the ledger's
     * whole-block check BEFORE that vote. So a refusal here is not a
     * judgement about the proposer — it is this node disagreeing with a
     * decision the network already made, which is a node defect. Every
     * class the body can still produce becomes INTERNAL_FAULT: the host
     * rolls the transaction back and the node stops, exactly as the
     * reference's `ApplyVerifiedBlock` error does (state.go:1783-1785,
     * `panic("failed to apply block; error %v")`; :1790 is
     * `recordMetrics`, and D-23 rev 5 carries the same wrong number).
     *
     * The body's REASON text is untouched, so an operator still reads
     * WHICH check refused — only the class changes, and it changes here,
     * once, rather than at fifty sites.
     *
     * ITEM-level verdicts are NOT affected: they never travel as a
     * return code. They live in `blk->cmt.results[i].code` and the block
     * committed around them.
     *
     * tokenomics-v3 P4: the body has ONE lane, so the fold is
     * unconditional; it maps negative returns only — 0 (applied) passes
     * through, and no positive return exists any more (the legacy rc 1
     * replay / rc 2 post-commit window are deleted with that lane). */
    if (rc < 0 && rc != NODUS_V2_INTERNAL_FAULT) {
        return NODUS_V2_INTERNAL_FAULT;
    }
    return rc;
}

/* ── the cometbft-lane genesis (FLEET-TM-R3 W2, R3-C1b) ───────────────
 *
 * Contract: the header (nodus_witness_v2_apply.h,
 * `nodus_witness_v2_genesis_cmt`). THE genesis since tokenomics-v3 P4:
 * the version-2 entry it was written beside (nodus_witness_v2_genesis_ex
 * — a height-0 v2_blocks row with a derived dna_bh2 BlockID, S9-S12,
 * idempotent on that row) is deleted with the legacy lane. The steps
 * below keep the order that entry had (domreg_init_genesis,
 * nodus_witness_v2_manifest_commit, doms_load, head_activate,
 * dna_v2_domains_root, dna_v2_global_root, the committed-authority
 * cross-check, nodus_witness_v2_supply_check, the epoch-0 balance copy);
 * the ":NNN —" line references in the step comments below point at that
 * deleted function's text in this file at a794910f, and are history
 * only.
 */
int nodus_witness_v2_genesis_cmt(nodus_witness_t *w,
                                 const uint8_t vset_hash[64],
                                 const uint8_t *manifest_bytes,
                                 size_t manifest_len,
                                 uint8_t out_global_root[64]) {
    if (!w || !w->db || !vset_hash || !out_global_root) return -1;
    /* The manifest is REQUIRED. It is the chain's committed source
     * binding; a genesis that cannot present it has no identity to bind
     * to the document that names it. */
    if (!manifest_bytes || manifest_len == 0) return -1;

    /* SCHEMA GATE (HISTORY): S12 OR S14 IN W2 — S14 ALONE FROM W3.
     * CURRENT (tokenomics-v3 P2): S16 alone (P1 round 5 had S15) — see the gate's
     * own check below and the paragraph's last sentence; everything
     * above this point in the comment is the W2/W3 history that led
     * here, not today's requirement.
     *
     * The destination is S14 and only S14: that is where the Comet
     * stores live (D-17 rev 6). S12 was accepted for ONE release window
     * in W2, for a reason that was not this function's: the ledger
     * genesis below runs every runtime's `state_init`
     * (nodus_witness_domreg.c:326-340), and the CORE hook gated itself
     * on an equality list ending at S12
     * (nodus_rt_core_state_init, nodus_witness_v2_pools.c:1176-1193 as
     * widened below), so a genesis applied at S14 failed there with no
     * diagnosis. That gate was one of the five D-17 rev 7 (7) moved to W3
     * together with the live S14 flip.
     *
     * R3 W3 (D-17 rev 10 (8)) NARROWS THIS BACK TO S14 in the same commit
     * that widens the pool gate (nodus_witness_v2_pools.c,
     * nodus_rt_core_state_init and nodus_witness_v2_pools_startup_check)
     * — the two edits belong together and neither is safe alone. With the
     * pool gate now accepting S14, the derivation migrates to S14 BEFORE
     * the ledger genesis runs (D-18 rev 5 (1)'s S12-then-climb order is
     * withdrawn), so this function is never reached at S12 on the live
     * path any more. (The version-2 entry's own S9-S12 gate is deleted
     * with that entry, tokenomics-v3 P4.)
     * tokenomics-v3 P1 moves this gate's accepted value S14 -> S15 (the
     * derivation now migrates to S15 before this point); tokenomics-v3
     * P2 moves it S15 -> S16 (the reward pool column and the two reward
     * tables; the derivation migrates to S16 first). Nodus EVM: every live
     * builder migrates to S17 first (the EVM tables, empty, and the CORE
     * EVM reserve row at 0 — nothing a generation-1 genesis reads), so the
     * gate accepts S17; S16 stays accepted because S17 is a pure
     * superset whose additions no genesis step touches (the S16 test
     * fixtures and an S16 scratch database produce the identical
     * genesis). */
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        (ver != NODUS_V2_SCHEMA_VERSION_S16 &&
         ver != NODUS_V2_SCHEMA_VERSION_S17)) {
        QGP_LOG_ERROR(LOG_TAG, "cometbft genesis needs schema S16 or S17, "
                      "the database is at %u — refusing", (unsigned)ver);
        return -1;
    }

    /* FAIL CLOSED ON AN EXISTING GENESIS. There is no height-0 row to
     * decide "already done" from, so the committed genesis MANIFEST is
     * the probe — and the verdict is a refusal, not an idempotent
     * success: a node that restarts VERIFIES its committed genesis
     * through InitChain (D-23 rev 5 (7)) and never re-applies it. A
     * probe fault is a refusal too; it is never read as "absent". */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 1 FROM v2_manifests WHERE committed_height = 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (rc == SQLITE_ROW) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "this database already carries a "
                          "committed genesis manifest — the cometbft "
                          "genesis is not idempotent and will not re-apply "
                          "it (fail closed)");
            return -1;
        }
        if (rc != SQLITE_DONE) return -1;
    }
    /* And no block may exist yet. */
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT COUNT(*) FROM v2_blocks",
                               -1, &st, NULL) != SQLITE_OK)
            return -1;
        int rc = sqlite3_step(st);
        sqlite3_int64 n = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0)
                                             : -1;
        sqlite3_finalize(st);
        if (rc != SQLITE_ROW || n != 0) {
            QGP_LOG_ERROR(LOG_TAG, "v2_blocks holds %lld rows before a "
                          "cometbft genesis — refusing", (long long)n);
            return -1;
        }
    }

    if (exec_sql(w, "BEGIN IMMEDIATE") != 0) return -1;
    int ok = 0;
    dna_v2_domain_head_t *heads = NULL;
    uint8_t global_root[64];
    memset(global_root, 0, sizeof(global_root));
    do {
        /* :699 — the registry with REAL payload-root manifests. */
        if (nodus_witness_domreg_init_genesis(w) != 0) break;

        /* :710-713 — the canonical genesis manifest at seq 0, height 0,
         * committed BEFORE the root computation. Non-circular for the
         * same reason stated there. */
        if (nodus_witness_v2_manifest_commit(w, manifest_bytes,
                                             manifest_len, 0, 0) != 0)
            break;

        /* :722-759 — one canonical activation head per ACTIVE domain,
         * built by the ONE activation constructor. An allocation failure
         * here is a NODE-LOCAL FAULT and is reported as one, never
         * folded into the generic refusal below (the rule this file
         * states at :724-732). */
        dom_ctx_t *doms = calloc(MAX_DOMS, sizeof(*doms));
        if (!doms) {
            (void)exec_sql(w, "ROLLBACK");
            free(heads);
            return NODUS_V2_INTERNAL_FAULT;
        }
        size_t n_dom = 0;
        if (doms_load(w, doms, &n_dom, /*strict_active=*/0) != 0) {
            doms_free(doms);
            break;
        }
        if (n_dom < 1 || doms[0].domain_id != DNA_DOMAIN_SYSTEM ||
            doms[0].status != DNA_DOMST_ACTIVE) {
            doms_free(doms);                 /* ACTIVE SYSTEM is mandatory    */
            break;
        }
        heads = calloc(n_dom, sizeof(*heads));
        if (!heads) {
            doms_free(doms);
            (void)exec_sql(w, "ROLLBACK");
            return NODUS_V2_INTERNAL_FAULT;
        }

        int all_ok = 1;
        size_t n_heads = 0;
        for (size_t i = 0; i < n_dom; i++) {
            if (doms[i].status != DNA_DOMST_ACTIVE) continue;
            if (doms[i].has_head) { all_ok = 0; break; }   /* impossible
                                         * pre-genesis — fail closed     */
            if (head_activate(w, &doms[i], 0) != 0) { all_ok = 0; break; }
            heads[n_heads++] = doms[i].head;
        }
        if (!all_ok || n_heads == 0) { doms_free(doms); break; }

        /* :761-769 — the roots, over the heads just activated and in the
         * order they were activated (domain_id ASC, doms_load's ORDER
         * BY). This is the value that becomes the document's app_hash. */
        uint8_t domains_root[64];
        if (dna_v2_domains_root(heads, n_heads, domains_root) != 0) {
            doms_free(doms);
            break;
        }
        if (dna_v2_global_root(domains_root, global_root) != 0) {
            doms_free(doms);
            break;
        }

        /* :816-857 — the committed-authority cross-check, verbatim in
         * intent: `vset_hash` is an ASSERTION, never a source. When a
         * genesis snapshot is already committed (the ordinary case: the
         * builder seeds epoch 0 before genesis) the parameter MUST equal
         * it; when none is committed there is nothing to check against
         * and the parameter stands, which is an honestly labelled
         * bootstrap gap rather than a silent one. A hash failure
         * allocates, so it is a NODE-LOCAL FAULT, not a judgement. */
        {
            dna_vset_snapshot_t *gsnap = NULL;
            uint32_t gn = 0, gq = 0;
            int garc = nodus_witness_v2_epoch_authority_for_height(
                           w, 0, &gsnap, &gn, &gq);
            if (garc == 0 && gsnap) {
                uint8_t committed_vsh[DNA_VSET_HASH_LEN];
                int ghrc = dna_vset_hash(gsnap, committed_vsh);
                dna_vset_free(&gsnap);
                if (ghrc != 0) {
                    doms_free(doms);
                    (void)exec_sql(w, "ROLLBACK");
                    free(heads);
                    return NODUS_V2_INTERNAL_FAULT;
                }
                if (memcmp(committed_vsh, vset_hash,
                           DNA_VSET_HASH_LEN) != 0) {
                    doms_free(doms);
                    break;      /* genesis named a foreign validator set */
                }
            } else {
                dna_vset_free(&gsnap);
                if (garc < 0) { doms_free(doms); break; }   /* read fault */
            }
        }

        doms_free(doms);

        /* NO v2_blocks INSERT. D-19 rev 6 withdrew the genesis block;
         * the height-0 root-history rows were already written by
         * head_activate — the ONE canonical activation path — so the
         * ledger's committed state is complete without it. */

        /* :906 — the conservation invariant must balance before this
         * genesis is allowed to exist. */
        if (nodus_witness_v2_supply_check(w) != 0) break;

        /* tokenomics-v3 P2 (P2-5) — the epoch-0 frozen balance copy: the
         * balances the first epoch starts from, read by the first
         * boundary's reward distribution (nodus_witness_v2_econ.c). Out
         * of every root, so written after every root above; written by
         * THE ENGINE, so every path that commits a genesis produces the
         * same rows. A write failure is a NODE-LOCAL FAULT. A
         * joiner reaches this same function (nodus_witness_v2_bundle.c)
         * over the bundle's validators/delegations, so it writes the
         * byte-identical rows the builder wrote. */
        if (nodus_witness_v2_balance_copy_write(w, 0) != 0) {
            (void)exec_sql(w, "ROLLBACK");
            free(heads);
            return NODUS_V2_INTERNAL_FAULT;
        }
        ok = 1;
    } while (0);
    free(heads);

    if (!ok) { (void)exec_sql(w, "ROLLBACK"); return -1; }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        return -1;
    }
    memcpy(out_global_root, global_root, 64);
    return 0;
}
