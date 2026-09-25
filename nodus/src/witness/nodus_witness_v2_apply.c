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
#include "witness/nodus_witness_v2_adapter.h"
#include "witness/nodus_witness_v2_epoch.h"    /* O12 S2: the boundary  */
#include "witness/nodus_witness_v2_econ.h"     /* econ params (6f),
                                                * balance copy (genesis) */
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_gen.h"      /* the cometbft lane's
                                                * chain identity: the
                                                * STORED genesis document
                                                * (D-18 rev 4)           */
#include "witness/nodus_witness_committee.h"   /* capacity season: the
                                        * governing snapshot resolution */
/* R3 W4-C delta 2: nodus/nodus_chain_config.h dropped — its only use in
 * this file was nodus_chain_config_get_u64(DNAC_CFG_MAX_TXS_PER_BLOCK),
 * deleted with the retired parameter (the global tx-count cap block,
 * "global tx-count cap (chain config) + per-domain tx quotas"). */

#include "dnac/dnac.h"                 /* DNAC_EPOCH_LENGTH (via apply.h,
                                        * kept explicit here too)       */
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
 * @return 0 / -1 chain-state verdict (SYSTEM unusable) / -2 node fault.
 */
static int block_ctx_from_doms(dom_ctx_t *doms, size_t n_dom,
                               nodus_witness_v2_block_ctx_t *ctx) {
    if (!doms || !ctx) return -2;
    memset(ctx, 0, sizeof(*ctx));

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
        ctx->budget.n_domains++;
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
int nodus_witness_v2_block_ctx_build(nodus_witness_t *w,
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
                 : block_ctx_from_doms(doms, n_dom, ctx);
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
                        nodus_v2_env_dry_run_t *dry,
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
    for (uint16_t l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        if (!d || !d->rt || !d->rt->exec) {          /* admission-scan
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
     * fields (ACTUAL consumed units, not the reservation). Bounded by
     * the block budgets, but checked anyway — one arithmetic
     * discipline. */
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
 * On success `*out_pubkeys` / `*out_fps` receive heap buffers the CALLER
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
                                         char *reason, size_t reason_size)
{
    nodus_committee_member_t *mem = NULL;
    uint8_t                  *cm_pubkeys = NULL;
    uint8_t                 (*cm_fps)[64] = NULL;
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
        if (!cm_pubkeys || !cm_fps) {
            free(cm_pubkeys);
            free(cm_fps);
            free(mem);
            V2AP_ENV_FAULT("phase 0b: allocation for the %d-member "
                           "committee snapshot failed", cm_count);
            return -2;
        }
        for (ci = 0; ci < cm_count; ci++) {
            memcpy(cm_pubkeys + (size_t)ci * NODUS_CC_PUBKEY_SIZE,
                   mem[ci].pubkey, NODUS_CC_PUBKEY_SIZE);
            if (qgp_sha3_512(mem[ci].pubkey, NODUS_CC_PUBKEY_SIZE,
                             cm_fps[ci]) != 0) {
                free(cm_pubkeys);
                free(cm_fps);
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
            free(mem);
            V2AP_ENV_FAULT("phase 0b: committee set-hash over %d members "
                           "failed", cm_count);
            return -2;
        }
        view->pubkeys = cm_pubkeys;
        view->fps = (const uint8_t (*)[64])cm_fps;
        *out_pubkeys = cm_pubkeys;
        *out_fps = cm_fps;
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
 */
static int env_replay_guard(nodus_witness_t *w, const dna_env_preflight_t *p,
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

    for (l = 0; l < v->leg_count; l++) {
        dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
        uint8_t ak = v->leg[l].auth_kind;

        if (!d || !d->rt || !d->rt->exec || !d->rt->auth ||
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
 * caller-held verdict for an auth_kind-1 leg whose digest equals the one
 * derived here is taken instead of re-running the hook — the recheck
 * cache's light path. auth_kind 2 never takes this branch.
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

    (void)w;
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
            v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_MULTI_V1 &&
            memcmp(reuse->digest[l], p->auth_digest[l], 64) == 0 &&
            reuse->verdict[l].n_signers >= 1 &&
            reuse->verdict[l].n_signers <= NODUS_RT_AUTH_MAX_SIGNERS) {
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
    nodus_rt_committee_t          cmview;
} env_item_setup_t;

static void env_item_setup_free(env_item_setup_t *s)
{
    free(s->cm_pubkeys);
    free(s->cm_fps);
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
    if (block_ctx_from_doms(s->doms, s->n_dom, s->bctx) != 0) {
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
 * reserve → authorization → execute. Every stage is the item loop's own
 * helper; the one-item "block" the exec body is handed carries only the
 * candidate height and its epoch (no fault injection, no claims). */
int nodus_witness_v2_env_dry_run(nodus_witness_t *w, const uint8_t *bytes,
                                 size_t len,
                                 const nodus_v2_auth_reuse_t *reuse,
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

    /* ── reserve against a FRESH block budget (the block-start context
     * this call built is untouched by anything else) ────────────────── */
    meter = calloc(1, sizeof(*meter));
    if (!meter) {
        V2AP_ENV_FAULT("%s", "dry run: the meter could not be allocated");
        ret = -2;
        goto done;
    }
    {
        dna_meter_status_t mst = dna_meter_reserve(meter, s.bctx->policy, v,
                                                   &s.bctx->budget);

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
    ret = exec_one_env(w, blk, 0, s.chain_id, blk->epoch, s.doms, s.n_dom,
                       s.pf, meter, out->verdict, reads, resbuf, out,
                       reason, reason_size);
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
 * `dna_claim_nullifier` (the "DNA.CLNUL.v1" preimage over chain,
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
         * this node's shape. */
        if (nodus_witness_db_schema_version(w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S16) {
            V2AP_FAULT("cometbft lane: this node's schema version is %u, "
                       "not %u - the Comet block row cannot be written "
                       "here; nothing about the block was judged",
                       (unsigned)ver,
                       (unsigned)NODUS_V2_SCHEMA_VERSION_S16);
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
        int bcrc = block_ctx_from_doms(doms, n_dom, &bctx);
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
                blk->out_reason, sizeof blk->out_reason);

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

            /* ── RESERVE against what is LEFT of the block's budget ── */
            {
                dna_meter_status_t mst =
                    dna_meter_reserve(&meters[i], bctx.policy, v,
                                      &bctx.budget);

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
                                      auths, reads, resbuf, NULL,
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
            if (ep.n_graduates > 0 || ep.dist_accrued > 0 ||
                ep.n_payday_utxos > 0) {
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

    /* 9. DomainUpdates (touched only; a DECLARED no-op — post == pre —
     * rejects: no fake empty updates) */
    {
        size_t n_upd = 0;
        for (size_t i = 0; i < n_dom; i++) {
            dom_ctx_t *d = &doms[i];
            if (!d->touched) continue;
            if (memcmp(d->root_now, d->head.domain_state_root, 64) == 0) {
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
    free(cm_pubkeys); free(cm_fps);
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
    free(cm_pubkeys); free(cm_fps);
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
    free(cm_pubkeys); free(cm_fps);
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
    free(cm_pubkeys); free(cm_fps);
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
     * tables; the derivation migrates to S16 first). */
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S16) {
        QGP_LOG_ERROR(LOG_TAG, "cometbft genesis needs schema S16, the "
                      "database is at %u — refusing", (unsigned)ver);
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
