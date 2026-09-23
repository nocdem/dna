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
#include "witness/nodus_witness_v2_econ.h"     /* O15J Faz 2: emission  */
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
#include "dnac/qc_v2.h"                /* DNA_QC_V2_MAX_ENC_LEN bound  */
#include "crypto/hash/qgp_sha3.h"      /* committee member fingerprints */
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdarg.h>                    /* the refusal-reason formatter  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2APPLY"

#define MAX_OPS NODUS_V2_APPLY_MAX_OPS  /* engine array bound — exported in
                         * the header (R3 W3) so the Comet application's
                         * PrepareProposal/ProcessProposal caps derive
                         * from it; the GLOBAL tx cap (<= 10) is enforced
                         * separately from chain config                  */
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
     * allocated LAZILY, on this domain's first leg (see the two write
     * sites: the legacy phase-0b admission scan and the Comet per-item
     * loop). Bounded by `blk->n_envs` because a domain cannot appear
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
    /* O14: `genesis_block_id` is an ASSERTION, not an input — NULL is
     * legal and means leader/derivation mode (the engine derives the id
     * and the caller reads it back from the committed row). It is never
     * the stored value in either mode. */
    if (!w || !w->db || !vset_hash) return -1;
    if ((manifest_bytes == NULL) != (manifest_len == 0)) return -1;
    /* O15A (reviewer NOTE): the manifest is required on EVERY path, not
     * just when creating a genesis. The fresh path already refuses a
     * no-manifest genesis because such a genesis has no defined identity
     * (see the fail-closed check before the header is built). Leaving the
     * idempotent path unguarded meant the manifest-divergence check could
     * be skipped simply by passing NULL, and the SAME call would then
     * return success against a committed chain while failing closed on a
     * fresh one. A caller that cannot present the manifest cannot assert
     * agreement with it, so it is refused rather than told "already
     * done". */
    if (!manifest_bytes || manifest_len == 0) return -1;
    /* The genesis epoch is DERIVED, not trusted: height 0 sits in epoch
     * nodus_v2_epoch_for_height(0) == 0 under the block-count rule. Any
     * other caller value is a rejection, never a stored lie. */
    if (epoch != nodus_v2_epoch_for_height(0)) return -1;
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        (ver != NODUS_V2_SCHEMA_VERSION_S9 &&
         ver != NODUS_V2_SCHEMA_VERSION_S10 &&
         ver != NODUS_V2_SCHEMA_VERSION_S11 &&
         ver != NODUS_V2_SCHEMA_VERSION_S12))
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
            /* Leader mode (no assertion) treats an existing genesis as
             * already done — the row IS the committed identity and no
             * caller value competes with it. */
            int same = (sqlite3_column_bytes(st, 0) == 64 &&
                        (genesis_block_id == NULL ||
                         memcmp(sqlite3_column_blob(st, 0),
                                genesis_block_id, 64) == 0));
            sqlite3_finalize(st);
            if (!same) return -2;

            /* ── O15A: THE MANIFEST MUST AGREE TOO ────────────────────
             * Deciding on the BlockID alone was a hole. In leader mode
             * `genesis_block_id` is NULL, so `same` above is
             * unconditionally true and this function returned SUCCESS
             * without ever looking at `manifest_bytes` — a node
             * re-running genesis with a COMPLETELY DIFFERENT manifest was
             * told it had succeeded. `epoch` and `vset_hash` were both
             * validated; the manifest, which the genesis identity is
             * derived FROM, was not.
             *
             * The committed bytes are authoritative: the presented
             * manifest must equal them exactly. A caller-provided
             * manifest never becomes the truth, and a mismatch fails
             * closed rather than being repaired or ignored. */
            if (manifest_bytes && manifest_len > 0) {
                sqlite3_stmt *ms = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "SELECT manifest FROM v2_manifests "
                        "WHERE committed_height = 0 "
                        "ORDER BY manifest_seq ASC LIMIT 1",
                        -1, &ms, NULL) != SQLITE_OK)
                    return -2;
                int mrc = sqlite3_step(ms);
                if (mrc != SQLITE_ROW) {
                    /* A committed genesis with no committed genesis
                     * manifest is malformed local state, not a verdict
                     * on the caller's bytes. */
                    sqlite3_finalize(ms);
                    return -2;
                }
                int          stored_len = sqlite3_column_bytes(ms, 0);
                const void  *stored     = sqlite3_column_blob(ms, 0);
                int agree = (stored != NULL &&
                             (size_t)stored_len == manifest_len &&
                             memcmp(stored, manifest_bytes,
                                    manifest_len) == 0);
                sqlite3_finalize(ms);
                if (!agree) {
                    QGP_LOG_ERROR(LOG_TAG, "%s",
                        "genesis manifest diverges from the committed one "
                        "— refusing (fail closed)");
                    return -2;
                }
            }
            return 0;
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
        /* O15A (reviewer R1): an allocation failure is a NODE-LOCAL
         * FAULT. `break` would fold it into the generic genesis -1
         * below and report running out of memory as a consensus
         * judgement — the exact defect this season closes in the QC
         * verifier, and the one the comment further down already names. */
        if (!doms) {
            (void)exec_sql(w, "ROLLBACK");
            return NODUS_V2_INTERNAL_FAULT;
        }
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
        /* Same class as `doms` above: allocation failure is a fault. */
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

        uint8_t domains_root[64], global_root[64];
        if (dna_v2_domains_root(heads, n_heads, domains_root) != 0) {
            doms_free(doms);
            break;
        }
        if (dna_v2_global_root(domains_root, global_root) != 0) {
            doms_free(doms);
            break;
        }

        uint8_t tx_root[64], dupd_root[64];
        if (dna_v2_tx_batch_root(NULL, 0, tx_root) != 0) {
            doms_free(doms);
            break;
        }
        if (dna_v2_domain_updates_root(NULL, 0, dupd_root) != 0) {
            doms_free(doms);
            break;
        }

        /* ── O14: THE ENGINE OWNS THE GENESIS IDENTITY TOO ─────────────
         * The genesis header is fully determined by committed material:
         * height 0, epoch 0, an ALL-ZERO chain_id (the id does not exist
         * yet — zeroing it in the preimage is what breaks the
         * circularity), an all-zero parent, the empty tx/update roots
         * computed just above, the derived global root, the governing
         * set hash, tx_count 0 and NO proposer (the engine stores none
         * for genesis, which is exactly why block_v2.c:133 declines to
         * constrain proposer_id).
         *
         * MANIFEST REQUIRED — labeled, fail-closed. The canonical
         * genesis preimage takes the manifest bytes as an EXPLICIT input
         * (block_v2.h:79-85; dna_bh2_genesis_block_id rejects a NULL or
         * empty manifest). A genesis with no manifest therefore has NO
         * defined identity under the O13 spec, and the engine will not
         * invent one — nor will it fall back to storing whatever id a
         * caller handed it, which is the whole point of this season.
         * The no-manifest convenience form now rejects. */
        if (!manifest_bytes || manifest_len == 0) {
            doms_free(doms);
            break;
        }

        uint8_t zero64[64];
        memset(zero64, 0, sizeof(zero64));

        dna_block_header_v2_t ghdr;
        memset(&ghdr, 0, sizeof(ghdr));
        ghdr.header_version = DNA_BH2_VERSION;
        /* chain_id, prev_block_id and proposer_id stay all-zero */
        ghdr.block_height = 0;
        ghdr.epoch        = 0;
        memcpy(ghdr.global_state_root,   global_root, 64);
        memcpy(ghdr.tx_root,             tx_root,     64);
        memcpy(ghdr.domain_updates_root, dupd_root,   64);
        /* validator_set_hash: an ASSERTION here too, not a source.
         * `vset_hash` arrives as a raw parameter, and binding it into
         * the genesis identity unchecked would make this the ONE header
         * field with two authoritative producers — derived from the
         * committed snapshot on the apply path, caller-chosen here —
         * contradicting the field-authority claim in the struct comment.
         * When genesis authority IS already committed (the ordinary
         * case: nodus_witness_vset_commit_genesis seeds epoch 0 before
         * genesis), require the parameter to equal it. If no snapshot is
         * committed yet, there is nothing to check against and the
         * parameter stands — an honestly labelled bootstrap gap, not a
         * silent one. (O14 review R1-F2.) */
        {
            dna_vset_snapshot_t *gsnap = NULL;
            uint32_t gn = 0, gq = 0;
            int garc = nodus_witness_v2_epoch_authority_for_height(
                           w, 0, &gsnap, &gn, &gq);
            if (garc == 0 && gsnap) {
                uint8_t committed_vsh[DNA_VSET_HASH_LEN];
                int ghrc = dna_vset_hash(gsnap, committed_vsh);
                dna_vset_free(&gsnap);
                /* O15A: dna_vset_hash allocates, so its failure is a
                 * NODE-LOCAL FAULT. Breaking here would fold it into the
                 * generic genesis -1 below and report an allocation
                 * failure as a consensus judgement — the same defect
                 * this season closes in the QC verifier. Genesis has no
                 * verdict-class input for this condition at all. */
                if (ghrc != 0) {
                    doms_free(doms);
                    (void)exec_sql(w, "ROLLBACK");
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
        memcpy(ghdr.validator_set_hash,  vset_hash,   64);
        ghdr.tx_count  = 0;
        ghdr.timestamp = 0;

        uint8_t gen_hdr_enc[DNA_BH2_ENC_SIZE];
        uint8_t derived_gid[DNA_BH2_ID_LEN];
        if (dna_bh2_encode(&ghdr, gen_hdr_enc) != 0) { doms_free(doms); break; }
        if (dna_bh2_genesis_block_id(&ghdr, manifest_bytes, manifest_len,
                                     derived_gid) != 0) {
            doms_free(doms);
            break;
        }
        /* The parameter is an ASSERTION, never the stored value. NULL =
         * leader mode: derive and commit, the caller reads it back. */
        if (genesis_block_id &&
            memcmp(genesis_block_id, derived_gid, 64) != 0) {
            doms_free(doms);
            break;
        }

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count, header, "
                "qc) "
                "VALUES (0,?1,?2,?3,?4,?5,?6,?7,?8,0,?9,NULL)",
                -1, &st, NULL) != SQLITE_OK) {
            doms_free(doms);
            break;
        }
        sqlite3_bind_blob(st, 1, derived_gid, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 2, zero64, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)epoch);
        sqlite3_bind_blob(st, 4, tx_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 5, dupd_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 6, domains_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 7, global_root, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 8, vset_hash, 64, SQLITE_TRANSIENT);
        sqlite3_bind_blob(st, 9, gen_hdr_enc, DNA_BH2_ENC_SIZE,
                          SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        doms_free(doms);
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

/* S7: map the pool module's mutation stages onto this engine's fault
 * points — a stage "fires" (aborts the batch, rolling the ONE block
 * transaction back) when the block requests the matching point for the
 * batch index being applied. */
typedef struct {
    const nodus_v2_block_t *blk;
    size_t index;
} pool_fault_ctx_t;

static int pool_stage_fault(void *ud, nodus_v2_pool_stage_t s) {
    const pool_fault_ctx_t *c = (const pool_fault_ctx_t *)ud;
    if (c->blk->fail_pool_index != (uint32_t)c->index) return 0;
    switch (s) {
        case NODUS_V2_POOL_STAGE_COMMITS:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_COMMITS;
        case NODUS_V2_POOL_STAGE_FRONTIER:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_FRONTIER;
        case NODUS_V2_POOL_STAGE_NULLS:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_NULLS;
        case NODUS_V2_POOL_STAGE_NULROOT:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_NULROOT;
        case NODUS_V2_POOL_STAGE_BALANCE:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_BALANCE;
        case NODUS_V2_POOL_STAGE_HISTORY:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_HISTORY;
        case NODUS_V2_POOL_STAGE_EVICT:
            return c->blk->fail_at == V2AP_FAIL_AFTER_POOL_EVICT;
        default:
            return 1;                    /* unknown stage: fail closed   */
    }
}

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
        case NODUS_V2_EPST_SETTLE_EMITTED:
            return blk->fail_at == V2AP_FAIL_AFTER_SETTLE_EMITTED;
        case NODUS_V2_EPST_SETTLE_APPLIED:
            return blk->fail_at == V2AP_FAIL_AFTER_SETTLE_APPLIED;
        case NODUS_V2_EPST_ATTENDANCE_DIGEST:
            return blk->fail_at == V2AP_FAIL_AFTER_ATTENDANCE_DIGEST;
        case NODUS_V2_EPST_ATTENDANCE_RESET:
            return blk->fail_at == V2AP_FAIL_AFTER_ATTENDANCE_RESET;
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
 * verdict array the pre-BEGIN (legacy) or per-item (Comet) authorization
 * stage filled, ALREADY ADVANCED to THIS envelope's own base — indexed
 * by leg alone (`auths[l]`), never `env_index * DNA_ENV_MAX_LEGS + leg`
 * (R3 W4 package C: the legacy lane sizes `auths` to the block's real
 * total leg count and passes `&auths[auth_off[env_index]]`; the Comet
 * lane passes its one per-item, DNA_ENV_MAX_LEGS-sized buffer directly).
 *
 * `reason`/`reason_size` are the caller's blk->out_reason (this `blk` is
 * const, so the buffer arrives separately). The CALLEE OWNS the reason:
 * every failing site here names its own check, and the three call sites
 * must not overwrite what they are handed — the inner site always knows
 * more than "envelope N failed".
 *
 * @return 0 / -1 verdict / -2 node fault. On ANY failure the caller
 * rolls the whole block back — there is no partial-envelope outcome.
 */
static int exec_one_env(nodus_witness_t *w, const nodus_v2_block_t *blk,
                        size_t env_index,
                        const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                        uint64_t epoch,
                        dom_ctx_t *doms, size_t n_dom,
                        const dna_env_preflight_t *pf, dna_meter_t *m,
                        const nodus_rt_auth_verdict_t *auths,
                        nodus_rt_read_res_t *reads, uint8_t *resbuf,
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

        /* The ENGINE-owned verified verdict for THIS leg. The pre-BEGIN
         * authorization stage rejected the block unless every leg
         * verified, so an empty slot here is an engine invariant broken
         * on this node — a fault, never a verdict.
         *
         * R3 W4 package C — `auths` arrives ALREADY ADVANCED to this
         * envelope's own base (the legacy lane passes `&auths[auth_off
         * [env_index]]`; the Comet lane passes its one per-item buffer
         * directly, which IS this envelope's base since only one item is
         * ever live at a time). This callee therefore indexes by leg
         * alone — no `env_index * DNA_ENV_MAX_LEGS` multiplication, which
         * would have been the wrong offset once callers stopped sizing
         * `auths` uniformly per envelope. */
        const nodus_rt_auth_verdict_t *av = &auths[l];
        if (av->n_signers < 1) {
            V2AP_ENV_FAULT("env %u leg %u: empty authorization verdict "
                           "slot (pre-BEGIN auth stage invariant broken "
                           "on this node)",
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
        nodus_adapter_status_t ast =
            nodus_witness_v2_effects_apply_ex(w, rt, &ev, &fidx,
                                              stop_after);
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
 * same per-member fingerprint, the same set hash, the same epoch. It is
 * a function now because BOTH lanes must resolve it and two copies could
 * drift — and a drift here would make two builds reach different
 * authorization verdicts for the same bytes, which is a chain split.
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
 * THE PER-ENVELOPE AUTHORIZATION STAGE: every leg's authorization
 * COMMITMENT turned into a VERDICT by the resolved runtime's own `auth`
 * hook, against the ENGINE-DERIVED leg auth digest.
 *
 * This is the ONE implementation. The cometbft item loop calls it inside
 * the item's SAVEPOINT, and `nodus_witness_v2_env_authorize` calls it
 * for the mempool — because NOTHING ELSE in the tree verifies an
 * envelope's signatures. `dna_env_preflight` says so in its own honest
 * label (env_preflight.h:57-63: it decides nothing about "whether any
 * authorization is VALID"), and the admission lane
 * (`verify_v2_successor_tx`, nodus_witness_verify.c:674-784) runs only
 * the marker, the ruleset table, that preflight, a wire_id comparison
 * and the committed-intent guard. Without this stage at CheckTx a
 * transaction with a forged or corrupted signature is admitted to the
 * mempool and only refused when a block carrying it is applied.
 *
 * The legacy batch stage (phase 0b) is NOT routed through here: its
 * refusal text names the envelope's BATCH INDEX, which a per-envelope
 * helper cannot know, and its behaviour is pinned by the shipped V2
 * tests. It performs the identical checks in the identical order.
 *
 * `out_verdicts` receives DNA_ENV_MAX_LEGS verdicts (the engine-owned
 * array the exec context later reads); a caller that only wants the
 * yes/no may point it at scratch.
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

int nodus_witness_v2_env_authorize(nodus_witness_t *w, const uint8_t *bytes,
                                   size_t len, char *reason,
                                   size_t reason_size)
{
    nodus_witness_v2_block_ctx_t *bctx = NULL;
    dom_ctx_t                    *doms = NULL;
    dna_env_preflight_t          *pf = NULL;
    nodus_rt_auth_verdict_t      *verdicts = NULL;
    uint8_t                      *cm_pubkeys = NULL;
    uint8_t                     (*cm_fps)[64] = NULL;
    nodus_rt_committee_t          cmview;
    dna_env_leg_ctx_t             lctx[DNA_ENV_MAX_LEGS];
    dna_env_view_t                probe;
    uint8_t                       chain_id[DNA_CHAIN_ID_LEN];
    uint64_t                      tip = 0, height;
    size_t                        n_dom = 0;
    uint16_t                      l;
    int                           ret = -2;

    if (reason && reason_size) {
        reason[0] = '\0';
    }
    if (!w || !w->db || !bytes || len == 0) {
        return -2;
    }
    memset(&cmview, 0, sizeof(cmview));
    memset(&probe, 0, sizeof(probe));

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
    height = tip + 1;
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the chain id is underivable on this "
                       "node");
        return -2;
    }
    bctx     = calloc(1, sizeof(*bctx));
    doms     = calloc(MAX_DOMS, sizeof(*doms));
    pf       = calloc(1, sizeof(*pf));
    verdicts = calloc(DNA_ENV_MAX_LEGS, sizeof(*verdicts));
    if (!bctx || !doms || !pf || !verdicts) {
        V2AP_ENV_FAULT("%s", "auth: the working set could not be allocated");
        goto done;
    }
    if (doms_load(w, doms, &n_dom, /*strict_active=*/1) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the domain registry / heads / runtime "
                       "tuples are unreadable on this node");
        goto done;
    }
    if (block_ctx_from_doms(doms, n_dom, bctx) != 0) {
        V2AP_ENV_FAULT("%s", "auth: the block-start context could not be "
                       "built on this node");
        goto done;
    }
    /* the positional ruleset table, as the item loop builds it */
    if (dna_env_decode(bytes, len, &probe) != 0) {
        V2AP_ENV_VERDICT("%s", "auth: the envelope does not decode");
        ret = -1;
        goto done;
    }
    for (l = 0; l < probe.leg_count; l++) {
        size_t k;
        int    found = 0;

        for (k = 0; k < bctx->n_rulesets; k++) {
            if (bctx->rulesets[k].domain_id == probe.leg[l].domain_id) {
                lctx[l] = bctx->rulesets[k];
                found = 1;
                break;
            }
        }
        if (!found) {
            V2AP_ENV_VERDICT("auth: leg %u names domain %u, which has no "
                             "entry in the committed context table",
                             (unsigned)l, (unsigned)probe.leg[l].domain_id);
            ret = -1;
            goto done;
        }
    }
    if (dna_env_preflight(bytes, len, chain_id, height, lctx,
                          probe.leg_count, pf) != DNA_ENV_PF_OK) {
        V2AP_ENV_VERDICT("%s", "auth: the envelope failed preflight");
        ret = -1;
        goto done;
    }
    /* the governing committee for the SAME candidate height the item
     * loop would use */
    {
        int crc = committee_snapshot_for_height(w, height, &cmview,
                                                &cm_pubkeys, &cm_fps,
                                                reason, reason_size);
        if (crc != 0) {
            if (crc == 1) {
                V2AP_ENV_FAULT("%s", "auth: the governing committee height "
                               "would be below genesis");
            }
            goto done;                   /* the helper wrote the reason  */
        }
    }
    ret = env_authorize_legs(w, pf, doms, n_dom, chain_id, height,
                             nodus_v2_epoch_for_height(height), &cmview,
                             verdicts, reason, reason_size);
done:
    free(cm_pubkeys);
    free(cm_fps);
    free(verdicts);
    free(pf);
    doms_free(doms);
    free(bctx);
    return ret;
}

/**
 * ONE CLAIM'S PRE-EXECUTION DERIVATION: shape, the committed manifest,
 * its distribution section, the distribution leaf hash and the canonical
 * NULLIFIER — the claim's semantic identity.
 *
 * FACTORED OUT of the pre-BEGIN claim scan, logic unchanged, because the
 * two lanes need it at different MOMENTS: the legacy lane runs it for the
 * whole block before the transaction opens, the cometbft lane runs it for
 * ONE claim inside that claim's own SAVEPOINT. It is a pure function of
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

/**
 * ONE CLAIM'S EXECUTION: admission, the derived-nullifier cross-check and
 * the three write stages — target-runtime output, spent-claim insert,
 * distribution-state decrement.
 *
 * FACTORED OUT of phase 6b, logic unchanged, for the same reason as the
 * pre-scan: the legacy lane runs it for the whole block inside the one
 * transaction, the cometbft lane runs it for ONE claim inside that
 * claim's SAVEPOINT. The fault points fire exactly where they did.
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
 * then the wire indices (`v2_tx_index` + `v2_tx_local_index`), exactly
 * as phase 12 writes them for the legacy lane.
 *
 * FACTORED OUT of phase 12 with the logic unchanged, for the same reason
 * as the committee snapshot: the cometbft lane writes these rows INSIDE
 * the item's own SAVEPOINT — so that a refused item leaves none — and
 * two copies of an index writer could drift into two different committed
 * index shapes.
 *
 * `gidx` is the item's GLOBAL INDEX in the block. In the legacy lane
 * that is its position in the phase order; in the Comet lane it is its
 * position among the APPLIED items, so a refused item consumes no index.
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
    uint32_t ver = 0;
    if (blk->cmt.on) {
        /* ── THE COMETBFT LANE'S OWN PRECONDITIONS (D-23 rev 5) ───────
         * S15 ONLY (tokenomics-v3 P1 moved the live rung from S14): this
         * lane writes a `v2_blocks` row without `header`, `qc` or
         * `commit_cert`, and at S12 `header` is NOT NULL, so the insert
         * could not even be expressed. Nothing about the block is judged
         * by either refusal — both are this node's shape. */
        if (nodus_witness_db_schema_version(w, &ver) != 0 ||
            ver != NODUS_V2_SCHEMA_VERSION_S15) {
            V2AP_FAULT("cometbft lane: this node's schema version is %u, "
                       "not %u - the Comet block row cannot be written "
                       "here; nothing about the block was judged",
                       (unsigned)ver,
                       (unsigned)NODUS_V2_SCHEMA_VERSION_S15);
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
    } else if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        (ver != NODUS_V2_SCHEMA_VERSION_S9 &&
         ver != NODUS_V2_SCHEMA_VERSION_S10 &&
         ver != NODUS_V2_SCHEMA_VERSION_S11 &&
         ver != NODUS_V2_SCHEMA_VERSION_S12)) {
        V2AP_FAULT("this node's schema version is %u - unreadable or not "
                   "in the supported set {%u,%u,%u,%u}; nothing about the "
                   "block was judged",
                   (unsigned)ver,
                   (unsigned)NODUS_V2_SCHEMA_VERSION_S9,
                   (unsigned)NODUS_V2_SCHEMA_VERSION_S10,
                   (unsigned)NODUS_V2_SCHEMA_VERSION_S11,
                   (unsigned)NODUS_V2_SCHEMA_VERSION_S12);
        return -2;
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

    /* ── 0. replay / linkage (read-only, pre-transaction) ─────────────
     * O14: the caller no longer supplies an identity. `expect_block_id`
     * is an ASSERTION, and the only thing it may unlock here is the
     * idempotent fast path — a caller that claims the id of the block
     * already committed at this height gets rc 1 and NO writes.
     *
     * LEADER/DERIVATION MODE (expect_block_id == NULL) has no id to
     * probe with, so it has no fast path: any row already at this height
     * is a conflict, caught by the height-continuity check below
     * (global_height != maxh + 1). The asymmetry is deliberate and
     * tested — see the header. It cannot produce divergent identities
     * because neither mode ever PERSISTS anything but the engine's own
     * phase-13 computation.
     *
     * The "same BlockID at another height" check moved to phase 13,
     * where the REAL id is known: checking a caller's claim here would
     * have been checking the wrong value in leader mode and no value at
     * all in the mode that matters. */
    {
        sqlite3_stmt *st = NULL;
        int rc;
        if (blk->expect_block_id) {
            if (sqlite3_prepare_v2(w->db,
                    "SELECT block_id, prev_block_id, header FROM v2_blocks "
                    "WHERE global_height = ?1",
                    -1, &st, NULL) != SQLITE_OK) {
                V2AP_FAULT("phase 0: could not prepare the replay probe "
                           "for height %llu",
                           (unsigned long long)blk->global_height);
                return -2;
            }
            sqlite3_bind_int64(st, 1, (sqlite3_int64)blk->global_height);
            rc = sqlite3_step(st);
            if (rc == SQLITE_ROW) {
                /* A malformed committed id is THIS NODE's corruption,
                 * not a statement about the incoming block — classify it
                 * with the other malformed-column checks below (-2), not
                 * as "conflicting" (-1). Otherwise a node with one bad
                 * local row declares a valid, quorum-certified block
                 * consensus-invalid while healthy peers return rc 1.
                 * (O14 review R1-F1.) */
                int idlen = sqlite3_column_bytes(st, 0);
                if (idlen != 64) {
                    sqlite3_finalize(st);   /* read the length BEFORE the
                                             * statement is finalized    */
                    V2AP_FAULT("phase 0: committed block_id at height "
                               "%llu is %d bytes, not 64 - local row "
                               "corruption, not a block property",
                               (unsigned long long)blk->global_height,
                               idlen);
                    return -2;
                }
                int same = (memcmp(sqlite3_column_blob(st, 0),
                                   blk->expect_block_id, 64) == 0);
                if (same) {
                    /* Serve the COMMITTED identity so the caller can
                     * still compare its certificate against the stored
                     * block without the engine re-executing anything. */
                    int pvlen = sqlite3_column_bytes(st, 1);
                    int hdlen = sqlite3_column_bytes(st, 2);
                    if (pvlen != 64 || hdlen != DNA_BH2_ENC_SIZE) {
                        sqlite3_finalize(st);
                        V2AP_FAULT("phase 0: committed row at height %llu "
                                   "is malformed (prev_block_id %d bytes, "
                                   "header %d bytes) - local corruption",
                                   (unsigned long long)blk->global_height,
                                   pvlen, hdlen);
                        return -2;      /* malformed committed row       */
                    }
                    memcpy(blk->out_block_id,
                           sqlite3_column_blob(st, 0), 64);
                    memcpy(blk->out_prev_block_id,
                           sqlite3_column_blob(st, 1), 64);
                    memcpy(blk->out_header,
                           sqlite3_column_blob(st, 2), DNA_BH2_ENC_SIZE);
                }
                sqlite3_finalize(st);
                if (!same)
                    V2AP_VERDICT("phase 0: a DIFFERENT block is already "
                                 "committed at height %llu; the asserted "
                                 "expect_block_id does not match it",
                                 (unsigned long long)blk->global_height);
                return same ? 1 : -1;   /* idempotent / conflicting      */
            }
            sqlite3_finalize(st);
            if (rc != SQLITE_DONE) {
                V2AP_FAULT("phase 0: replay probe for height %llu failed "
                           "to step (sqlite rc %d)",
                           (unsigned long long)blk->global_height, rc);
                return -2;
            }
        }

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
         * Height 0 is tested FIRST and is a VERDICT, not a deferral:
         * genesis has its own entry point (nodus_witness_v2_genesis_ex),
         * so a height-0 block arriving here is a statement about THIS
         * block — it cannot be applied through this path at all — and no
         * amount of waiting for predecessors would ever make it valid. */
        if (blk->global_height == 0) {
            V2AP_VERDICT("phase 0: height 0 cannot be applied through "
                         "this path - genesis has its own entry point "
                         "(nodus_witness_v2_genesis_ex)");
            return NODUS_V2_CONSENSUS_INVALID;
        }

        /* No genesis committed HERE yet. The block may be perfectly
         * valid; this node simply has no chain to link it onto. That is
         * absent predecessor state, not a defect in the block.
         *
         * NOT SO IN THE COMETBFT LANE: a version-3 chain writes NO
         * height-0 `v2_blocks` row at all (D-19 rev 6 withdrew the
         * genesis block; nodus_witness_v2_genesis_cmt, apply.h), so an
         * EMPTY table is the normal state of a freshly derived chain and
         * the block arriving here is simply its FIRST. Its
         * `prev_block_id` is 64 zero bytes — block 1's LastBlockID is
         * empty in the reference too (D-18 rev 3). The genesis the
         * ledger applied is still proven to exist: the committed
         * manifest and the domain heads are what phase 0a reads, and a
         * chain without them fails there. */
        if (rows == 0 && !blk->cmt.on) {
            V2AP_DEFER("phase 0: no genesis committed on this node, so "
                       "height %llu has no chain to link onto - NOTHING "
                       "was judged",
                       (unsigned long long)blk->global_height);
            return NODUS_V2_NOT_YET_LINKABLE;
        }

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
        if (blk->cmt.on && rows == 0) {
            memset(blk->out_prev_block_id, 0, 64);
        } else {

        /* AT or BEHIND the head: evaluable right now, so it gets a real
         * verdict. In follower mode a block at a committed height was
         * already resolved above as replay-or-conflict; reaching here
         * means a hole in the local chain or, in leader mode, a height
         * already committed — the source-pinned asymmetry documented at
         * the top of this block. */
        if (blk->global_height != maxh + 1) {
            V2AP_VERDICT("phase 0: height %llu is at or below this node's "
                         "head %llu (next expected %llu) - evaluable now, "
                         "and it is not the successor",
                         (unsigned long long)blk->global_height,
                         (unsigned long long)maxh,
                         (unsigned long long)(maxh + 1));
            return NODUS_V2_CONSENSUS_INVALID;
        }

        /* prev_block_id is DERIVED from the previous committed row — the
         * caller may only assert it. */
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
        if (blk->expect_prev_block_id &&
            memcmp(blk->expect_prev_block_id, blk->out_prev_block_id, 64)
                != 0) {                 /* asserted a foreign parent     */
            char e[17], d[17];
            V2AP_VERDICT("phase 0: asserted prev_block_id %s does not "
                         "match the committed parent %s at height %llu",
                         v2ap_hex8(blk->expect_prev_block_id, e),
                         v2ap_hex8(blk->out_prev_block_id, d),
                         (unsigned long long)maxh);
            return -1;
        }
        }   /* end of the ordinary linkage path (see the Comet first
             * block above) */
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
    /* ONE derivation of the chain identity, for both lanes.
     * `nodus_witness_v2_chain_id` answers from the committed height-0
     * block row where there is one and from the STORED GENESIS DOCUMENT
     * where there is not (nodus_witness_v2_claims.c:186-224), so a
     * version-3 chain — which writes no block row at all (D-19 rev 6) —
     * is served by the same call as every older chain. There is
     * deliberately no lane branch here: two sources for one identity is
     * how two builds end up binding different chains. */
    if (nodus_witness_v2_chain_id(w, chain_id) != 0) {
        doms_free(doms);
        V2AP_FAULT("phase 0a: chain id underivable on this node - neither "
                   "a committed genesis block row nor a stored genesis "
                   "document answered");
        return -2;   /* an underivable chain id is a node-local read
                      * failure, never a statement about the block       */
    }

    /* ── BLOCK-START VALIDATOR AUTHORITY (O14) ────────────────────────
     * The governing snapshot is resolved HERE — pre-BEGIN, before this
     * block mutates anything and in particular BEFORE the epoch boundary
     * runs commit_next. That ordering is the whole point: a block is
     * verified against the authority the chain had committed when the
     * block STARTED, so the snapshot a boundary block itself creates can
     * never be the snapshot that validates it. `validator_set_hash` is
     * derived from this and from nothing else; the caller may assert it
     * (expect_vset_hash) but cannot supply it.
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
        if (blk->expect_vset_hash &&
            memcmp(blk->expect_vset_hash, blk->out_vset_hash, 64) != 0) {
            char e[17], d[17];
            V2AP_VERDICT("phase 0a: asserted validator_set_hash %s does "
                         "not match the snapshot governing height %llu "
                         "(%s, %u members)",
                         v2ap_hex8(blk->expect_vset_hash, e),
                         (unsigned long long)blk->global_height,
                         v2ap_hex8(blk->out_vset_hash, d), (unsigned)vn);
            doms_free(doms);
            return -1;      /* asserted a foreign validator set          */
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

    /* ── 0b. envelope preflight + reservation (whole canonical batch) ─
     * Heap allocations: the preflight results are multi-KB each
     * (env_preflight.h size audit) and the read/result buffers are the
     * codec maxima — none of it belongs on the stack. */
    dna_env_preflight_t *pf = NULL;
    dna_meter_t *meters = NULL;
    nodus_rt_read_res_t *reads = NULL;
    uint8_t *resbuf = NULL;
    /* R3 W4 package C — auths is no longer sized `n_envs × DNA_ENV_MAX_LEGS`
     * (a fixed per-leg-cap multiplication). Each lane sizes and fills it
     * differently, both AFTER this point, once real leg counts are known:
     *   · LEGACY: sized to the SUM of every envelope's real leg count,
     *     with `auth_off[i]` the running per-envelope base offset into it
     *     (built right after the batch preflight succeeds — the "0b.
     *     envelope preflight" block below).
     *   · COMET: one item is ever live at a time (its own SAVEPOINT), so
     *     ONE small reusable buffer sized DNA_ENV_MAX_LEGS (never touching
     *     n_envs) serves every item in turn — see the `if (blk->cmt.on)`
     *     block.
     * Both call sites hand `exec_one_env`/`env_authorize_legs` a pointer
     * ALREADY ADVANCED to the envelope's own base, so neither callee
     * multiplies by DNA_ENV_MAX_LEGS any more (exec_one_env indexes
     * `auths[l]`, never `auths[env_index * DNA_ENV_MAX_LEGS + l]`). */
    nodus_rt_auth_verdict_t *auths = NULL;
    size_t *auth_off = NULL;                 /* LEGACY lane only          */
    /* capacity season: the ENGINE-resolved governing committee snapshot
     * for auth_kind-2 legs — resolved lazily ONCE per block (heap: up to
     * 128 × 2592 B of pubkeys; never on the stack). */
    uint8_t *cm_pubkeys = NULL;
    uint8_t (*cm_fps)[64] = NULL;
    nodus_rt_committee_t cmview;
    memset(&cmview, 0, sizeof(cmview));
    /* R3 W4 package C — HEAP, sized to the BLOCK's own n_claims/n_envs,
     * not the engine's release bound (NODUS_V2_APPLY_MAX_OPS is now
     * 17 371; a `claim_nuls[MAX_OPS][64]` STACK array at that size would
     * be a ~907 KB frame). Allocated where each lane first needs it (the
     * S6 claims block below, once for whichever lane runs) — NULL/0 for
     * a claim-free block is exactly the DNA_ENV_MAX_LEGS-independent,
     * always-safe starting state. */
    uint8_t (*claim_nuls)[64] = NULL;
    /* R3 W4 package C — HEAP, sized to blk->n_envs (LEGACY lane only; the
     * Comet lane never fills or reads this — its own item loop replaces
     * the legacy phase order entirely). NULL/0 for a zero-envelope or
     * Comet-lane block.
     *
     * R3 W4-C delta 5 (verifier finding E5, harmless, decided not fixed):
     * the allocation below is unconditional on `blk->n_envs > 0` — it
     * does NOT check `blk->cmt.on` first, so a Comet-lane block with
     * envelopes allocates and immediately wastes `n_envs * sizeof(int)`
     * bytes (this array is written only inside "PHASE 0b, THE LEGACY
     * LANE ONLY" below, e.g. :2862, which the Comet lane never reaches).
     * Left as-is rather than gated on the lane: `pf`, `meters`, `reads`
     * and `resbuf` in this same allocation block are ALSO unconditional
     * on the lane and cost far more per envelope (`dna_env_preflight_t`
     * alone is 15 096 B; `env_phase`'s waste is 4 B per envelope,
     * ~0.03% of that) — `env_phase` is consistent with its neighbors,
     * not an outlier, and a lane-conditional branch here would trade a
     * few bytes for a new branch in a per-block hot path for no
     * measurable gain. */
    int *env_phase = NULL;
    int need_committee = 0;              /* any leg carries auth_kind 2  */

    if (blk->n_envs > 0) {
        pf        = calloc(blk->n_envs, sizeof(*pf));
        meters    = calloc(blk->n_envs, sizeof(*meters));
        reads     = calloc(NODUS_RT_MAX_READS, sizeof(*reads));
        resbuf    = calloc(1, DNA_EFFECT_MAX_TOTAL_LEN);
        env_phase = calloc(blk->n_envs, sizeof(*env_phase));
        if (!pf || !meters || !reads || !resbuf || !env_phase) {
            V2AP_FAULT("phase 0b: allocation of the preflight/meter/read/"
                       "result/phase working set for %llu envelopes failed",
                       (unsigned long long)blk->n_envs);
            goto fail_fault_pre;
        }
    }

#define RET_VERDICT do { goto fail_verdict_pre; } while (0)

    /* ══ PHASE 0b, THE LEGACY LANE ONLY ══════════════════════════════
     * Preflight, reserve, replay guard, per-leg admission, the committee
     * snapshot and authorization all run here for the WHOLE batch,
     * before the transaction opens, and ANY refusal rejects the whole
     * block. That is the legacy consensus's contract: a block is voted
     * on before it is applied, so it must be all-or-nothing.
     *
     * The cometbft lane cannot use it. There a block is DECIDED before
     * it reaches the application, every item is executed, and a bad item
     * gets a nonzero code while the block goes on (D-23 rev 4/5). So the
     * same work happens there PER ITEM, inside the item's own SAVEPOINT,
     * in the Comet item loop below. Nothing here is duplicated: the loop
     * calls the same `dna_env_preflight`, the same `dna_meter_reserve`,
     * the same admission predicates and the same `exec_one_env`. */
    if (blk->cmt.on) {
        goto cmt_skip_batch_stage;
    }

    if (blk->n_envs > 0) {
        size_t fidx = 0;
        dna_env_preflight_status_t pfst = DNA_ENV_PF_OK;
        dna_meter_status_t mst = DNA_METER_OK;
        nodus_v2_env_status_t est = nodus_witness_v2_env_preflight_reserve_batch(
            w, blk->global_height, bctx.rulesets, bctx.n_rulesets,
            bctx.policy, &bctx.budget,
            blk->envs, blk->n_envs, pf, meters, &fidx, &pfst, &mst);
        if (est != NODUS_V2_ENV_OK) {
            /* FAULT vs VERDICT routing of the seam's rejection: an
             * ERR_HASH preflight and a meter accounting FAULT are this
             * node failing to compute; everything else — malformed
             * bytes, expiry, unregistered domain, derived-id duplicate,
             * budget misfit, absent op weight — is deterministic. */
            if ((est == NODUS_V2_ENV_ERR_PREFLIGHT &&
                 pfst == DNA_ENV_PF_ERR_HASH) ||
                (est == NODUS_V2_ENV_ERR_METER &&
                 mst == DNA_METER_ERR_FAULT) ||
                est == NODUS_V2_ENV_ERR_CHAIN) {
                V2AP_FAULT("phase 0b: preflight/reserve of envelope %llu "
                           "of %llu could not be computed on this node "
                           "(env status %d, preflight %d, meter %d)",
                           (unsigned long long)fidx,
                           (unsigned long long)blk->n_envs,
                           (int)est, (int)pfst, (int)mst);
                goto fail_fault_pre;
            }
            V2AP_VERDICT("phase 0b: envelope %llu of %llu rejected by "
                         "preflight/reserve (env status %d, preflight %d, "
                         "meter %d)",
                         (unsigned long long)fidx,
                         (unsigned long long)blk->n_envs,
                         (int)est, (int)pfst, (int)mst);
            RET_VERDICT;
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_ENV_RESERVE) {
            V2AP_VERDICT("fault-injection point "
                         "V2AP_FAIL_AFTER_ENV_RESERVE fired (test "
                         "harness; no real check failed)");
            RET_VERDICT;
        }

        /* R3 W4 package C — `auths`, sized to the SUM of every envelope's
         * REAL leg count, not `n_envs × DNA_ENV_MAX_LEGS`. Every envelope
         * in `pf[0..n_envs)` is now fully preflighted, so `view.leg_count`
         * is known for each; `auth_off[i]` is envelope i's running base
         * offset into the flat `auths` array (`auth_off[n_envs]` is the
         * total, kept for symmetry with a one-past-the-end bound). */
        {
            size_t total_legs = 0;
            auth_off = calloc(blk->n_envs + 1, sizeof(*auth_off));
            if (!auth_off) {
                V2AP_FAULT("phase 0b: allocation of the %llu-entry "
                           "auth-offset table failed",
                           (unsigned long long)blk->n_envs);
                goto fail_fault_pre;
            }
            for (size_t k = 0; k < blk->n_envs; k++) {
                auth_off[k] = total_legs;
                total_legs += pf[k].view.leg_count;
            }
            auth_off[blk->n_envs] = total_legs;
            auths = calloc(total_legs, sizeof(*auths));
            if (!auths) {
                V2AP_FAULT("phase 0b: allocation of the %zu-slot "
                           "(total real legs) auth-verdict scratch failed",
                           total_legs);
                goto fail_fault_pre;
            }
        }

        /* ── COMMITTED-IDENTITY REPLAY GUARD (intent season, pre-BEGIN,
         * read-only) ──────────────────────────────────────────────────
         * Deterministic VERDICTS against the committed indices, checked
         * per envelope in batch order — FIRST the intent (semantic
         * replay: the same requested execution may commit ONCE per
         * chain, no matter which valid authorization realizes it; a
         * matching intent is NEVER evidence of authorization — the
         * whole candidate block still rejects), THEN the wire id
         * (byte-identical resubmission in a NEW block — distinct from
         * phase-0 whole-block idempotent replay, which already returned
         * rc 1 before this point). Both fire through RET_VERDICT so the
         * batch reservation is released and the budget restored
         * byte-identically. The v2_intent_index / v2_tx_index UNIQUE
         * constraints remain the fail-closed database backstop behind
         * this guard. A storage error here is a node fault (a guard
         * that cannot read must not vote). */
        for (size_t i = 0; i < blk->n_envs; i++) {
            static const char *const guard_sql[2] = {
                "SELECT 1 FROM v2_intent_index WHERE intent_id = ?1",
                "SELECT 1 FROM v2_tx_index WHERE tx_id = ?1"
            };
            const uint8_t *guard_id[2] = { pf[i].intent_id,
                                           pf[i].wire_id };
            for (int g = 0; g < 2; g++) {
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db, guard_sql[g], -1, &st,
                                       NULL) != SQLITE_OK) {
                    V2AP_FAULT("phase 0b: could not prepare the %s replay "
                               "guard for envelope %llu",
                               g == 0 ? "intent_id" : "wire_id",
                               (unsigned long long)i);
                    goto fail_fault_pre;
                }
                sqlite3_bind_blob(st, 1, guard_id[g], 64, SQLITE_STATIC);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc == SQLITE_ROW) {              /* already committed */
                    char h[17];
                    V2AP_VERDICT("phase 0b: envelope %llu replays an "
                                 "already-committed %s %s",
                                 (unsigned long long)i,
                                 g == 0 ? "intent_id" : "wire_id",
                                 v2ap_hex8(guard_id[g], h));
                    RET_VERDICT;
                }
                if (rc != SQLITE_DONE) {
                    V2AP_FAULT("phase 0b: %s replay guard for envelope "
                               "%llu failed to step (sqlite rc %d)",
                               g == 0 ? "intent_id" : "wire_id",
                               (unsigned long long)i, rc);
                    goto fail_fault_pre;
                }
            }
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_INTENT_GUARD) {
            V2AP_VERDICT("fault-injection point "
                         "V2AP_FAIL_AFTER_INTENT_GUARD fired (test "
                         "harness; no real check failed)");
            RET_VERDICT;
        }

        /* Per-leg execution admission against the SNAPSHOT (block-entry
         * status is the executability authority): ACTIVE + runtime +
         * exec hook + INVOKE access + runtime_op OWNED by the committed
         * ruleset. Fills the per-domain derived-id lists — the ONLY
         * source the index/root phases consume. */
        for (size_t i = 0; i < blk->n_envs; i++) {
            const dna_env_view_t *v = &pf[i].view;
            int is_sys = (v->leg_count == 1 &&
                          v->leg[0].domain_id == DNA_DOMAIN_SYSTEM);
            env_phase[i] = is_sys ? 0 : (v->leg_count > 1 ? 1 : 2);
            for (uint16_t l = 0; l < v->leg_count; l++) {
                dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
                if (!d || d->pre_status != DNA_DOMST_ACTIVE || !d->rt) {
                    V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                 "names domain %u, which is %s at block "
                                 "entry",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)v->leg[l].domain_id,
                                 !d ? "not registered"
                                    : (!d->rt ? "registered with no "
                                                "resolvable runtime"
                                              : "registered but not "
                                                "ACTIVE"));
                    RET_VERDICT;
                }
                if (!d->rt->exec) {              /* no execution hook =
                                                  * leg fails closed     */
                    V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                 "domain %u has no exec hook - fails "
                                 "closed",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)d->domain_id);
                    RET_VERDICT;
                }
                if (!d->rt->auth) {              /* no authorization
                                                  * hook = leg fails
                                                  * closed (a commitment
                                                  * is not a verdict)    */
                    V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                 "domain %u has no auth hook - a "
                                 "commitment is not a verdict, fails "
                                 "closed",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)d->domain_id);
                    RET_VERDICT;
                }
                if (v->leg[l].access_mode != DNA_ENV_ACCESS_INVOKE) {
                    V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                 "domain %u carries access_mode %u; only "
                                 "INVOKE (%u) is admitted this season",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)d->domain_id,
                                 (unsigned)v->leg[l].access_mode,
                                 (unsigned)DNA_ENV_ACCESS_INVOKE);
                    RET_VERDICT;                 /* READ legs: later
                                                  * season (honest label)*/
                }
                if (!rt_owns_runtime_op(d->rt, v->leg[l].runtime_op)) {
                    V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                 "runtime_op %u is not owned by domain "
                                 "%u's committed ruleset (version %u)",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)v->leg[l].runtime_op,
                                 (unsigned)d->domain_id,
                                 (unsigned)d->man.ruleset_version);
                    RET_VERDICT;                 /* op not in the
                                                  * committed ruleset    */
                }
                /* capacity season: the runtime's auth-kind ALLOWLIST,
                 * enforced BEFORE any authorization work — a runtime
                 * that never consumes committee approvals cannot be
                 * made to carry (or pay for) an approval blob. The
                 * shift guard keeps kinds >= 32 out of UB; they are
                 * unsupported anyway. */
                {
                    uint8_t ak = v->leg[l].auth_kind;
                    if (ak >= 32 ||
                        (d->rt->allowed_auth_kinds &
                         NODUS_RT_AUTHKIND_BIT(ak)) == 0) {
                        V2AP_VERDICT("phase 0b admission: env %llu leg %u "
                                     "auth_kind %u is not in domain %u's "
                                     "runtime allowlist (0x%08x)",
                                     (unsigned long long)i, (unsigned)l,
                                     (unsigned)ak, (unsigned)d->domain_id,
                                     (unsigned)d->rt->allowed_auth_kinds);
                        RET_VERDICT;
                    }
                    if (ak == NODUS_RT_AUTHKIND_DSA87_CC_V1)
                        need_committee = 1;
                }
                d->touched = 1;
                /* R3 W4 package C — PROVEN, not policy: a domain cannot
                 * appear twice in one envelope's leg list (env_wire.c
                 * :364-365 decode / :276 encode both refuse a domain_id
                 * that is not strictly ascending), so this domain's
                 * `n_tx` — incremented once per LEG naming it — can never
                 * exceed the block's own `n_envs`. Reaching this branch
                 * means that invariant broke on THIS node: a FAULT, never
                 * a judgement about the block (the old MAX_OPS-sized
                 * array bound this used to be a VERDICT against no longer
                 * exists — `wire_ids` is heap, sized to `n_envs` below). */
                if (d->n_tx >= blk->n_envs) {
                    V2AP_FAULT("phase 0b admission: domain %u's n_tx "
                               "reached the block's own n_envs (%llu) - "
                               "the one-leg-per-domain-per-envelope "
                               "invariant (env_wire.c:364-365) broke on "
                               "this node",
                               (unsigned)d->domain_id,
                               (unsigned long long)blk->n_envs);
                    goto fail_fault_pre;
                }
                if (!d->wire_ids) {
                    d->wire_ids = calloc(blk->n_envs, sizeof(*d->wire_ids));
                    if (!d->wire_ids) {
                        V2AP_FAULT("phase 0b admission: allocation of "
                                   "domain %u's %llu-entry wire-id "
                                   "scratch failed",
                                   (unsigned)d->domain_id,
                                   (unsigned long long)blk->n_envs);
                        goto fail_fault_pre;
                    }
                }
                memcpy(d->wire_ids[d->n_tx++], pf[i].wire_id, 64);
            }
        }

        /* ── GOVERNING COMMITTEE SNAPSHOT (capacity season, pre-BEGIN) ─
         * Resolved ONCE per block, only when some leg carries the
         * committee-indexed carrier: nodus_committee_get_for_block at
         * the governing height H-1 — the SAME authority the legacy
         * chain-config apply consults (nodus_witness_chain_config.c
         * lookup_height = commit_block - 1). The transaction can
         * neither carry nor select it: nothing in the envelope names an
         * epoch, a height or a set hash — approvals merely FAIL against
         * the wrong snapshot. A lookup FAULT is node-local (-2, do not
         * vote); an EMPTY committee is deterministic chain state and
         * flows into the view (the auth hook rejects kind-2 legs on
         * count == 0). */
        if (need_committee) {
            int crc = committee_snapshot_for_height(
                w, blk->global_height, &cmview, &cm_pubkeys, &cm_fps,
                blk->out_reason, sizeof blk->out_reason);

            if (crc == 1) {                          /* below genesis    */
                V2AP_VERDICT("phase 0b: a leg carries a committee-indexed "
                             "authorization at height 0 - the governing "
                             "height would be below genesis");
                RET_VERDICT;
            }
            if (crc != 0) {
                goto fail_fault_pre;   /* the helper wrote the reason    */
            }
            if (blk->fail_at == V2AP_FAIL_AFTER_CC_SNAPSHOT) {
                V2AP_VERDICT("fault-injection point "
                             "V2AP_FAIL_AFTER_CC_SNAPSHOT fired (test "
                             "harness; no real check failed)");
                RET_VERDICT;
            }
        }

        /* ── VERIFIED AUTHORIZATION (pre-BEGIN, whole batch) ──────────
         * The engine turns every leg's authorization COMMITMENT into a
         * VERDICT before anything executes or mutates: the resolved
         * runtime's auth hook parses the leg's auth_data under its
         * auth_kind and verifies every signature against the
         * ENGINE-derived leg auth_digest. Verdicts live in the
         * engine-owned `auths` array — immutable for the rest of the
         * block — and are the ONLY authorization input exec ever sees
         * (ctx->auth). A rejection here is deterministic (same bytes,
         * same verdict on every node); a hook backend failure (-2) is a
         * node fault. No charge is taken: authorization work was priced
         * once by w_authbyte at reservation. */
        for (size_t i = 0; i < blk->n_envs; i++) {
            const dna_env_view_t *v = &pf[i].view;
            for (uint16_t l = 0; l < v->leg_count; l++) {
                dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
                if (!d || !d->rt || !d->rt->auth) {
                    V2AP_FAULT("phase 0b auth: domain %u lost its runtime "
                               "or auth hook between admission and "
                               "verification (env %llu leg %u) - engine "
                               "invariant broken on this node",
                               (unsigned)v->leg[l].domain_id,
                               (unsigned long long)i, (unsigned)l);
                    goto fail_fault_pre;
                }
                nodus_rt_exec_ctx_t actx;
                memset(&actx, 0, sizeof(actx));
                actx.chain_id            = chain_id;
                actx.global_height       = blk->global_height;
                actx.epoch               = blk->epoch;
                actx.wire_id             = pf[i].wire_id;
                actx.intent_id           = pf[i].intent_id;
                actx.auth_context_commit = pf[i].auth_context_commit;
                actx.leg_auth_digest     = pf[i].auth_digest[l];
                /* the resolved snapshot view, ONLY for the kind that
                 * consumes it (runtime.h ctx contract) */
                actx.committee =
                    v->leg[l].auth_kind == NODUS_RT_AUTHKIND_DSA87_CC_V1
                        ? &cmview : NULL;
                int arc = d->rt->auth(d->rt, v, l, &actx,
                                      &auths[auth_off[i] + l]);
                if (arc == -2) {
                    V2AP_FAULT("phase 0b auth: verification backend "
                               "failed for env %llu leg %u domain %u "
                               "auth_kind %u",
                               (unsigned long long)i, (unsigned)l,
                               (unsigned)d->domain_id,
                               (unsigned)v->leg[l].auth_kind);
                    goto fail_fault_pre;
                }
                if (arc != 0) {
                    V2AP_VERDICT("phase 0b auth: env %llu leg %u domain "
                                 "%u auth_kind %u FAILED verification "
                                 "against the engine-derived leg digest "
                                 "(rc %d)",
                                 (unsigned long long)i, (unsigned)l,
                                 (unsigned)d->domain_id,
                                 (unsigned)v->leg[l].auth_kind, arc);
                    RET_VERDICT;
                }
            }
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_AUTH) {
            V2AP_VERDICT("fault-injection point V2AP_FAIL_AFTER_AUTH "
                         "fired (test harness; no real check failed)");
            RET_VERDICT;
        }
    }

    /* R3 W4-C delta 2 (operator "kaldır" 2026-09-18;
     * atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1): the global
     * tx-count cap (chain-config MAX_TXS_PER_BLOCK) is DELETED — a
     * block's capacity is decided by cometbft's own Block.MaxBytes, the
     * meter policy's max_block_env_bytes and NODUS_V2_GLOBAL_UNIT_BUDGET
     * only. The pre-BEGIN `blk->n_envs > NODUS_V2_ENV_BATCH_MAX` gate
     * (this function's very first check) is the engine's own surviving
     * envelope-count ceiling — a derived MEMORY bound, never a consensus
     * parameter (nodus_witness_v2_apply.h). Per-domain tx quotas are
     * UNCHANGED — a committed manifest's own `quota_tx_per_block` is a
     * per-domain policy choice, not the retired global count cap. */
    for (size_t i = 0; i < n_dom; i++) {
        dom_ctx_t *d = &doms[i];
        if (!d->touched) continue;
        if (d->man.quota_tx_per_block != 0 &&
            d->n_tx > (uint32_t)d->man.quota_tx_per_block) {
            V2AP_VERDICT("domain %u carries %u transactions; its "
                         "committed manifest quota is %u per block",
                         (unsigned)d->domain_id, (unsigned)d->n_tx,
                         (unsigned)d->man.quota_tx_per_block);
            RET_VERDICT;
        }
    }

    /* ── S6 claims: bounds + in-block duplicate nullifiers + touched
     * TARGET domains (pre-txn, read-only). TV3-P0: the claim helpers no
     * longer conflate — they answer 0 / -1 VERDICT / -2 FAULT
     * (nodus_witness_v2_claims.h), and a -2 here leaves through
     * fail_fault_pre. ────────────────────────────────────────────────── */
    if (blk->n_claims > 0) {
        if (!blk->claims || blk->n_claims > NODUS_V2_APPLY_MAX_CLAIMS) {
            V2AP_VERDICT("block declares %llu claims with %s array (engine "
                         "bound %zu)",
                         (unsigned long long)blk->n_claims,
                         blk->claims ? "an over-long" : "a NULL",
                         NODUS_V2_APPLY_MAX_CLAIMS);
            RET_VERDICT;
        }
        /* R3 W4 package C — HEAP, sized to the BLOCK's own n_claims (the
         * bound above just proved it fits cometbft's own block-byte
         * ceiling; a MAX_OPS-sized (17 371-entry) array regardless of the
         * block's real count would have been wasteful and, before this
         * package, was a fixed STACK array of that same size — a
         * ~907 KB frame. */
        claim_nuls = calloc(blk->n_claims, sizeof(*claim_nuls));
        if (!claim_nuls) {
            V2AP_FAULT("phase 0b: allocation of the %llu-entry claim-"
                       "nullifier scratch failed",
                       (unsigned long long)blk->n_claims);
            goto fail_fault_pre;
        }
        for (size_t i = 0; i < blk->n_claims; i++) {
            uint32_t target = 0;
            int      prc;

            prc = claim_prescan_one(w, &blk->claims[i], i, claim_nuls[i],
                                    &target, blk->out_reason,
                                    sizeof blk->out_reason);
            if (prc == -2) {
                goto fail_fault_pre;    /* the helper owns the reason    */
            }
            if (prc != 0) {
                RET_VERDICT;         /* the helper owns the reason       */
            }
            for (size_t j = 0; j < i; j++)
                if (memcmp(claim_nuls[i], claim_nuls[j], 64) == 0) {
                    QGP_LOG_ERROR(LOG_TAG, "%s",
                        "duplicate claim in one block — rejected");
                    V2AP_VERDICT("claim %llu duplicates the nullifier of "
                                 "claim %llu in the same block",
                                 (unsigned long long)i,
                                 (unsigned long long)j);
                    RET_VERDICT;
                }
            dom_ctx_t *d = dom_for(doms, n_dom, target);
            if (!d || d->status != DNA_DOMST_ACTIVE) {
                V2AP_VERDICT("claim %llu targets domain %u, which is %s",
                             (unsigned long long)i, (unsigned)target,
                             !d ? "not registered"
                                : "registered but not ACTIVE");
                RET_VERDICT;
            }
            if (!d->rt) {
                /* TV3-P0 (ORCHESTRATOR delta, verifier N7): an ACTIVE
                 * domain whose runtime THIS node cannot resolve is a
                 * NODE-LOCAL condition (registry read fault or a compiled
                 * table lacking the tuple — doms_load discards
                 * runtime_for's return at :390), never a verdict about
                 * the claim. Unreachable in practice: doms_load's
                 * strict_active pass (:399-405) already refused this
                 * working set at phase 0a as a FAULT; kept fail-closed
                 * in the same class so the two sites cannot disagree. */
                V2AP_FAULT("claim %llu targets ACTIVE domain %u whose "
                           "runtime this node cannot resolve",
                           (unsigned long long)i, (unsigned)target);
                goto fail_fault_pre;
            }
            d->touched = 1;
        }
    }

    /* ── S7 pool batches: shape + canonical batch order + touched
     * owning domains (pre-txn, read-only) — unchanged from S7. ─────── */
    if (blk->n_pool_muts > 0) {
        if (!blk->pool_muts || blk->n_pool_muts > MAX_OPS) {
            V2AP_VERDICT("block declares %llu pool batches with %s array "
                         "(engine bound %u)",
                         (unsigned long long)blk->n_pool_muts,
                         blk->pool_muts ? "an over-long" : "a NULL",
                         (unsigned)MAX_OPS);
            RET_VERDICT;
        }
        for (size_t i = 0; i < blk->n_pool_muts; i++) {
            const nodus_v2_pool_mut_t *m = &blk->pool_muts[i];
            if (nodus_witness_v2_pool_mut_validate(m) != 0) {
                V2AP_VERDICT("pool batch %llu (domain %u pool %llu) failed "
                             "shape validation",
                             (unsigned long long)i, (unsigned)m->domain_id,
                             (unsigned long long)m->pool_id);
                RET_VERDICT;
            }
            if (i > 0) {
                const nodus_v2_pool_mut_t *p = &blk->pool_muts[i - 1];
                if (p->domain_id > m->domain_id ||
                    (p->domain_id == m->domain_id &&
                     p->pool_id >= m->pool_id)) {
                    V2AP_VERDICT("pool batch %llu (domain %u pool %llu) "
                                 "breaks the strictly ascending "
                                 "(domain_id, pool_id) order after "
                                 "(domain %u pool %llu)",
                                 (unsigned long long)i,
                                 (unsigned)m->domain_id,
                                 (unsigned long long)m->pool_id,
                                 (unsigned)p->domain_id,
                                 (unsigned long long)p->pool_id);
                    RET_VERDICT;
                }
            }
            dom_ctx_t *d = dom_for(doms, n_dom, m->domain_id);
            if (!d || d->status != DNA_DOMST_ACTIVE || !d->rt) {
                V2AP_VERDICT("pool batch %llu is owned by domain %u, "
                             "which is %s",
                             (unsigned long long)i, (unsigned)m->domain_id,
                             !d ? "not registered"
                                : (!d->rt ? "registered with no "
                                            "resolvable runtime"
                                          : "registered but not ACTIVE"));
                RET_VERDICT;
            }
            d->touched = 1;
        }
    }

cmt_skip_batch_stage:
#undef RET_VERDICT

    /* ── 1. THE transaction ─────────────────────────────────────────
     * The legacy lane OWNS it. The cometbft lane JOINS the host's
     * (D-23 rev 5 (5)): `apply_verified_block` opened one before
     * `FinalizeBlock` and `app.commit` will close it, so this entry
     * must not open, commit or roll back anything. The entry gate
     * already refused to run outside a transaction, so reaching here
     * with `cmt.on` means one is open. */
    if (!blk->cmt.on && exec_sql(w, "BEGIN IMMEDIATE") != 0) {
        V2AP_FAULT("phase 1: BEGIN IMMEDIATE failed on this node's "
                   "database");
        goto fail_fault_pre;
    }
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
     * ORDER: the block's own order, envelopes then claims. The legacy
     * lane's SYSTEM → cross-domain → domain-local phase order does NOT
     * apply here (it is the legacy consensus's rule), which is why the
     * two lanes can produce different roots for the same items — stated
     * in apply.h.
     *
     * WHAT IS REUSED, not re-implemented: `dna_env_preflight` (the same
     * derivation the batch seam runs, with the chain id passed in),
     * `dna_meter_reserve`/`dna_meter_abort`, the admission predicates
     * `dom_for` / `rt_owns_runtime_op`, the runtime's own `auth` hook,
     * and `exec_one_env` — the per-envelope body the legacy phases call.
     */
    if (blk->cmt.on) {
        uint32_t gidx = 0;          /* global index of the APPLIED items */

        /* The governing committee snapshot, resolved ONCE for the block
         * through the same function the legacy lane calls. It is
         * resolved UNCONDITIONALLY here, where the legacy lane resolves
         * it only when its batch scan saw a committee-indexed leg: that
         * scan does not exist in this lane, and pre-decoding every item
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
         * every item in turn. No offset table is needed here (unlike the
         * legacy lane's whole-batch `auths`): index `l` is always
         * relative to THIS item, and `env_authorize_legs` never writes
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
             * The same two guards the legacy lane runs pre-BEGIN
             * (:2064-2110 in the legacy region above), here per item and
             * ALSO against the items this block already applied — an
             * earlier item's rows are visible inside the transaction, so
             * the committed check covers them, but an item that was
             * rolled back must not block a later duplicate either, which
             * is exactly what reading the live index gives. */
            {
                static const char *const guard_sql[2] = {
                    "SELECT 1 FROM v2_intent_index WHERE intent_id = ?1",
                    "SELECT 1 FROM v2_tx_index WHERE tx_id = ?1"
                };
                const uint8_t *guard_id[2] = { pf[i].intent_id,
                                               pf[i].wire_id };
                int g, hit = 0;

                for (g = 0; g < 2 && !hit; g++) {
                    sqlite3_stmt *st = NULL;
                    int rc;

                    if (sqlite3_prepare_v2(w->db, guard_sql[g], -1, &st,
                                           NULL) != SQLITE_OK) {
                        V2AP_FAULT("cometbft item %llu: the replay guard "
                                   "could not be prepared on this node",
                                   (unsigned long long)i);
                        (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                        (void)cmt_savepoint_release(w, sp);
                        goto fail_fault;
                    }
                    sqlite3_bind_blob(st, 1, guard_id[g], 64,
                                      SQLITE_TRANSIENT);
                    rc = sqlite3_step(st);
                    sqlite3_finalize(st);
                    if (rc == SQLITE_ROW) {
                        hit = 1;
                    } else if (rc != SQLITE_DONE) {
                        V2AP_FAULT("cometbft item %llu: the replay guard "
                                   "failed to step on this node (sqlite "
                                   "rc %d)", (unsigned long long)i, rc);
                        (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                        (void)cmt_savepoint_release(w, sp);
                        goto fail_fault;
                    }
                }
                if (hit) {
                    code = NODUS_V2_TX_ERR_REPLAY;
                    goto cmt_item_failed;
                }
            }

            /* ── ADMISSION, per leg: the legacy scan's predicates ───── */
            for (l = 0; l < v->leg_count; l++) {
                dom_ctx_t *d = dom_for(doms, n_dom, v->leg[l].domain_id);
                uint8_t ak = v->leg[l].auth_kind;

                if (!d || !d->rt || !d->rt->exec || !d->rt->auth ||
                    v->leg[l].access_mode != DNA_ENV_ACCESS_INVOKE ||
                    !rt_owns_runtime_op(d->rt, v->leg[l].runtime_op) ||
                    ak >= 32 ||
                    (d->rt->allowed_auth_kinds &
                     NODUS_RT_AUTHKIND_BIT(ak)) == 0) {
                    code = NODUS_V2_TX_ERR_ADMISSION;
                    goto cmt_item_failed;
                }
                /* R3 W4 package C — PROVEN, not policy, and split from
                 * the quota check below (they used to share one `||` and
                 * one CAPACITY verdict). A domain cannot appear twice in
                 * one envelope's leg list (env_wire.c:364-365 decode /
                 * :276 encode both refuse a domain_id that is not
                 * strictly ascending), so this domain's `n_tx` —
                 * incremented once per LEG naming it — can never reach
                 * the block's own `n_envs`. Reaching this branch means
                 * that invariant broke on THIS node: a FAULT, never the
                 * CAPACITY verdict the quota half below still is. */
                if (d->n_tx >= blk->n_envs) {
                    V2AP_FAULT("cometbft item %llu leg %u: domain %u's "
                               "n_tx reached the block's own n_envs "
                               "(%llu) - the one-leg-per-domain-per-"
                               "envelope invariant (env_wire.c:364-365) "
                               "broke on this node",
                               (unsigned long long)i, (unsigned)l,
                               (unsigned)d->domain_id,
                               (unsigned long long)blk->n_envs);
                    (void)nodus_witness_db_rollback_to_savepoint(w, sp);
                    (void)cmt_savepoint_release(w, sp);
                    goto fail_fault;
                }
                /* the committed manifest's own per-domain quota —
                 * CAPACITY, because it is about what is LEFT, not about
                 * the bytes */
                if (d->man.quota_tx_per_block != 0 &&
                    d->n_tx + 1 > (uint32_t)d->man.quota_tx_per_block) {
                    code = NODUS_V2_TX_ERR_CAPACITY;
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
                    blk->epoch, &cmview, auths,
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

            /* ── EXECUTE: the same body the legacy phases call ──────── */
            {
                int rc = exec_one_env(w, blk, i, chain_id, blk->epoch,
                                      doms, n_dom, &pf[i], &meters[i],
                                      auths, reads, resbuf,
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
         * The legacy lane checks these before its transaction opens (the
         * `blk->n_claims > NODUS_V2_APPLY_MAX_CLAIMS` / NULL-array gate),
         * and that gate is inside the region this lane skips (this lane
         * never allocates `claim_nuls` there either) — so without this
         * the loop below would write into a NULL `claim_nuls`. R3 W4
         * package C: the array is heap now, sized to THIS block's own
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
         * Each claim runs in its own SAVEPOINT: the derivation the
         * legacy lane does pre-BEGIN (`claim_prescan_one` — a pure
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
                 * runtime-resolution miss is NODE-LOCAL (see the legacy
                 * prescan's twin comment) and must not become item code
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
        goto cmt_items_done;
    }

    /* 4-6. ENVELOPE EXECUTION in the canonical phase order: SYSTEM-
     * local first, then cross-domain, then domain-local ascending by
     * domain_id — intra-phase in batch order. Sequential execution
     * inside the ONE transaction is what makes a later envelope's
     * mediated reads observe an earlier envelope's canonical
     * mutations. */
    /* exec_one_env OWNS the reason on failure (it names the leg, the
     * domain, the op and the exact check); these call sites deliberately
     * do NOT overwrite it. */
    for (size_t i = 0; i < blk->n_envs; i++) {          /* SYSTEM-local  */
        if (env_phase[i] != 0) continue;
        int rc = exec_one_env(w, blk, i, chain_id, blk->epoch, doms,
                              n_dom, &pf[i], &meters[i], &auths[auth_off[i]],
                              reads, resbuf, blk->out_reason,
                              sizeof blk->out_reason);
        if (rc == -2) goto fail_fault;
        if (rc != 0) goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_ENV_EXEC &&
            blk->fail_env_index == (uint32_t)i) {
            V2AP_VERDICT("fault-injection point V2AP_FAIL_AFTER_ENV_EXEC "
                         "fired after SYSTEM-phase env %llu (test "
                         "harness; no real check failed)",
                         (unsigned long long)i);
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_SYSTEM);
    for (size_t i = 0; i < blk->n_envs; i++) {          /* cross-domain  */
        if (env_phase[i] != 1) continue;
        int rc = exec_one_env(w, blk, i, chain_id, blk->epoch, doms,
                              n_dom, &pf[i], &meters[i], &auths[auth_off[i]],
                              reads, resbuf, blk->out_reason,
                              sizeof blk->out_reason);
        if (rc == -2) goto fail_fault;
        if (rc != 0) goto fail;
        if (blk->fail_at == V2AP_FAIL_AFTER_ENV_EXEC &&
            blk->fail_env_index == (uint32_t)i) {
            V2AP_VERDICT("fault-injection point V2AP_FAIL_AFTER_ENV_EXEC "
                         "fired after cross-domain env %llu (test "
                         "harness; no real check failed)",
                         (unsigned long long)i);
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_CROSS);
    for (size_t di = 0; di < n_dom; di++) {     /* domain-local, id ASC  */
        dom_ctx_t *d = &doms[di];
        for (size_t i = 0; i < blk->n_envs; i++) {
            if (env_phase[i] != 2) continue;
            if (pf[i].view.leg[0].domain_id != d->domain_id) continue;
            int rc = exec_one_env(w, blk, i, chain_id, blk->epoch,
                                  doms, n_dom, &pf[i], &meters[i],
                                  &auths[auth_off[i]], reads, resbuf,
                                  blk->out_reason, sizeof blk->out_reason);
            if (rc == -2) goto fail_fault;
            if (rc != 0) goto fail;
            if (blk->fail_at == V2AP_FAIL_AFTER_ENV_EXEC &&
                blk->fail_env_index == (uint32_t)i) {
                V2AP_VERDICT("fault-injection point "
                             "V2AP_FAIL_AFTER_ENV_EXEC fired after "
                             "domain-local env %llu (domain %u) (test "
                             "harness; no real check failed)",
                             (unsigned long long)i,
                             (unsigned)d->domain_id);
                goto fail;
            }
        }
        if (blk->fail_at == V2AP_FAIL_AFTER_DOMAIN_BATCH &&
            blk->fail_domain_batch == d->domain_id) {
            V2AP_VERDICT("fault-injection point "
                         "V2AP_FAIL_AFTER_DOMAIN_BATCH fired after domain "
                         "%u's batch (test harness; no real check failed)",
                         (unsigned)d->domain_id);
            goto fail;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_UTXO);

    /* 6b. S6 generic claims — routed to each claim's COMMITTED target
     * runtime inside THE txn. The body is `claim_execute_one`, shared
     * with the cometbft lane, which runs it per claim inside that
     * claim's own SAVEPOINT. */
    for (size_t i = 0; i < blk->n_claims; i++) {
        int erc = claim_execute_one(w, blk, i, claim_nuls[i],
                                    blk->out_reason, sizeof blk->out_reason);
        if (erc == -2) {
            goto fail_fault;         /* the helper owns the reason      */
        }
        if (erc != 0) {
            goto fail;               /* the helper owns the reason      */
        }
    }

    /* 6p. S7 pool-state batches (unchanged from S7). */
    for (size_t i = 0; i < blk->n_pool_muts; i++) {
        pool_fault_ctx_t pfc = { blk, i };
        if (nodus_witness_v2_pool_apply(w, &blk->pool_muts[i],
                                        blk->global_height,
                                        pool_stage_fault, &pfc) != 0) {
            V2AP_VERDICT("phase 6p: pool batch %llu (domain %u pool %llu) "
                         "refused by the pool module (helper conflates a "
                         "read fault and the pool fault points - honest "
                         "label in the header)",
                         (unsigned long long)i,
                         (unsigned)blk->pool_muts[i].domain_id,
                         (unsigned long long)blk->pool_muts[i].pool_id);
            goto fail;
        }
    }

cmt_items_done:
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
     * `votes_len == 0` (the legacy lane, or the initial height) is the
     * legal empty case: the writer no-ops. */
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
            /* O15J Faz 2 — CORE is touched by a graduation release AND
             * by the settlement, which writes utxo_set and moves
             * supply_tracking (both CORE state-root legs,
             * nodus_witness_roots_v2.c:317-345). A boundary that settles
             * an EMPTY pool moves neither and must NOT declare CORE:
             * phase 9 rejects a declared no-op as hard as phase 8
             * rejects an undeclared mutation. */
            if (ep.n_graduates > 0 || ep.n_settle_utxos > 0 ||
                ep.settle_burned > 0) {
                dom_ctx_t *dcore = dom_for(doms, n_dom, DNA_DOMAIN_CORE);
                if (!dcore) {
                    V2AP_FAULT("phase 6e: the boundary moved CORE state "
                               "(%u graduates, %u settlement utxos, %llu "
                               "burned) but CORE domain %u is absent from "
                               "the working set",
                               (unsigned)ep.n_graduates,
                               (unsigned)ep.n_settle_utxos,
                               (unsigned long long)ep.settle_burned,
                               (unsigned)DNA_DOMAIN_CORE);
                    goto fail_fault;
                }
                dcore->touched = 1;
            }
        }
    }

    /* 6f. O15J Faz 2 — PER-BLOCK INFLATION EMISSION.
     *
     * The V1 order is transitions → emission → settlement
     * (nodus_witness_bft.c:3594, :3638, :3737). This lane keeps the
     * transitions-then-emission half literally; the settlement half moved
     * INSIDE the boundary above, one step before Rule N, because Rule N's
     * transplanted counter reset would otherwise destroy settlement's
     * attendance input (nodus_witness_v2_epoch.h, "WHY SETTLEMENT SITS
     * AT 2b"). The two are key-disjoint — at a boundary H the settlement
     * drains epoch H-E while the mint accrues into epoch H, and E > 0 —
     * so their relative order changes no committed byte.
     *
     * Engine-MANDATORY like the boundary: emission is a function of the
     * height and committed chain_config alone, never caller-declared, so
     * it runs unconditionally (a zero-envelope block still mints). It is
     * a no-op before DNAC_CFG_INFLATION_START_BLOCK.
     *
     * Placed AFTER the boundary and BEFORE the supply gate so that the
     * gate at phase 7 covers the mint this block performed — the same
     * reason the boundary sits where it does. */
    {
        uint64_t minted = 0;
        if (nodus_witness_v2_emission_apply(w, blk->global_height,
                                            &minted) != 0) {
            V2AP_FAULT("phase 6f: per-block emission at height %llu "
                       "failed - like a boundary it has no verdict class, "
                       "its input is committed state and the height alone",
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }
        if (minted > 0) {
            /* A mint moves supply_tracking (a CORE state-root leg,
             * nodus_witness_roots_v2.c:342-345) AND epoch_state (a SYSTEM
             * leg, :283-284). Both must be declared, and only when the
             * mint was non-zero. */
            dom_ctx_t *dcore_em = dom_for(doms, n_dom, DNA_DOMAIN_CORE);
            dom_ctx_t *dsys_em  = dom_for(doms, n_dom, DNA_DOMAIN_SYSTEM);
            if (!dcore_em || !dsys_em) {
                V2AP_FAULT("phase 6f: %llu minted at height %llu but "
                           "domain %u is absent from the working set",
                           (unsigned long long)minted,
                           (unsigned long long)blk->global_height,
                           (unsigned)(!dcore_em ? DNA_DOMAIN_CORE
                                                : DNA_DOMAIN_SYSTEM));
                goto fail_fault;
            }
            dcore_em->touched = 1;
            dsys_em->touched  = 1;
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_EMISSION);

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

    /* 12. transaction indices — DERIVED identities ONLY; global order =
     * the phase order above. TWO indices per transaction (intent
     * season): the SEMANTIC index first (v2_intent_index — intent_id PK
     * + the ONE accepted wire realization), then the WIRE indices
     * (v2_tx_index / v2_tx_local_index from pf[i].wire_id). All inside
     * the ONE block transaction, so either both identities commit or
     * neither does; the UNIQUE constraints are the fail-closed backstop
     * behind the pre-BEGIN replay guard (a violation here means the
     * guard's read and this write disagree — an engine/storage fault on
     * THIS node, not a block property).
     *
     * IN THE COMETBFT LANE the two IDENTITY rows of every APPLIED item
     * were already written inside that item's own SAVEPOINT (so a
     * refused item left none), and only the LOCAL index rows are left —
     * they could not be written there because their `domain_height`
     * column is the head height phases 9-10 compute. The loop below is
     * therefore entered in that lane too, over the APPLIED items in
     * block order, with the identity inserts skipped. */
    {
        uint32_t gidx = 0;
        if (blk->cmt.on) {
            uint32_t gi = 0;
            size_t   i;

            for (i = 0; i < blk->n_envs; i++) {
                const dna_env_view_t *v;
                uint16_t t;

                if (blk->cmt.results[i].code != NODUS_V2_TX_OK) {
                    continue;            /* refused: no rows at all      */
                }
                v = &pf[i].view;
                for (t = 0; t < v->leg_count; t++) {
                    dom_ctx_t *d = dom_for(doms, n_dom,
                                           v->leg[t].domain_id);
                    uint32_t lidx = 0;
                    sqlite3_stmt *ls = NULL;
                    int rc;

                    if (!d) {
                        V2AP_FAULT("phase 12: applied item %llu leg %u "
                                   "names domain %u, absent from the "
                                   "working set at index time",
                                   (unsigned long long)i, (unsigned)t,
                                   (unsigned)v->leg[t].domain_id);
                        goto fail_fault;
                    }
                    if (nodus_witness_v2_local_index_find(
                            (const uint8_t (*)[64])d->wire_ids, d->n_tx,
                            pf[i].wire_id, &lidx) != 0) {
                        V2AP_FAULT("phase 12: applied item %llu's wire id "
                                   "is missing from domain %u's own "
                                   "%u-entry id list - engine invariant "
                                   "broken on THIS node",
                                   (unsigned long long)i,
                                   (unsigned)d->domain_id,
                                   (unsigned)d->n_tx);
                        goto fail_fault;
                    }
                    if (sqlite3_prepare_v2(w->db,
                            "INSERT INTO v2_tx_local_index (tx_id, "
                            "domain_id, domain_height, local_index) "
                            "VALUES (?1,?2,?3,?4)", -1, &ls, NULL)
                        != SQLITE_OK) {
                        V2AP_FAULT("phase 12: could not prepare the "
                                   "v2_tx_local_index insert for applied "
                                   "item %llu domain %u",
                                   (unsigned long long)i,
                                   (unsigned)d->domain_id);
                        goto fail_fault;
                    }
                    sqlite3_bind_blob(ls, 1, pf[i].wire_id, 64,
                                      SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ls, 2,
                        (sqlite3_int64)v->leg[t].domain_id);
                    sqlite3_bind_int64(ls, 3,
                        (sqlite3_int64)d->newhead.domain_height);
                    sqlite3_bind_int64(ls, 4, (sqlite3_int64)lidx);
                    rc = sqlite3_step(ls);
                    sqlite3_finalize(ls);
                    if (rc != SQLITE_DONE) {
                        V2AP_FAULT("phase 12: v2_tx_local_index insert "
                                   "for applied item %llu domain %u "
                                   "(local index %u) failed (sqlite rc "
                                   "%d)", (unsigned long long)i,
                                   (unsigned)d->domain_id, (unsigned)lidx,
                                   rc);
                        goto fail_fault;
                    }
                }
                gi++;
            }
            (void)gi;
            goto cmt_index_done;
        }
        for (int phase = 0; phase < 3; phase++) {
            for (size_t i = 0; i < blk->n_envs; i++) {
                if (env_phase[i] != phase) continue;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "INSERT INTO v2_intent_index (intent_id, tx_id, "
                        "global_height, global_index) "
                        "VALUES (?1,?2,?3,?4)", -1, &st, NULL)
                    != SQLITE_OK) {
                    V2AP_FAULT("phase 12: could not prepare the "
                               "v2_intent_index insert for env %llu",
                               (unsigned long long)i);
                    goto fail_fault;
                }
                sqlite3_bind_blob(st, 1, pf[i].intent_id, 64,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_blob(st, 2, pf[i].wire_id, 64,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 3,
                                   (sqlite3_int64)blk->global_height);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)gidx);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc != SQLITE_DONE) {
                    V2AP_FAULT("phase 12: v2_intent_index insert for env "
                               "%llu (global index %u) failed (sqlite rc "
                               "%d) - the pre-BEGIN replay guard and this "
                               "write disagree",
                               (unsigned long long)i, (unsigned)gidx, rc);
                    goto fail_fault;
                }
                gidx++;
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_INTENT_INDEX);
    {
        uint32_t gidx = 0;
        for (int phase = 0; phase < 3; phase++) {
            for (size_t i = 0; i < blk->n_envs; i++) {
                if (env_phase[i] != phase) continue;
                const dna_env_view_t *v = &pf[i].view;

                uint32_t touched_ids[DNA_ENV_MAX_LEGS];
                for (uint16_t t = 0; t < v->leg_count; t++)
                    touched_ids[t] = v->leg[t].domain_id;
                uint8_t tl[2 + 4 * DNA_TOUCHED_MAX];
                size_t tw = 0;
                if (v->leg_count > DNA_TOUCHED_MAX) {
                    V2AP_VERDICT("phase 12: env %llu declares %u legs; "
                                 "the touched-set encoding admits at most "
                                 "%u",
                                 (unsigned long long)i,
                                 (unsigned)v->leg_count,
                                 (unsigned)DNA_TOUCHED_MAX);
                    goto fail;
                }
                if (dna_touched_encode(touched_ids,
                                       (uint16_t)v->leg_count, tl,
                                       sizeof(tl), &tw) != 0) {
                    V2AP_FAULT("phase 12: touched-set encoding for env "
                               "%llu (%u legs) failed",
                               (unsigned long long)i,
                               (unsigned)v->leg_count);
                    goto fail_fault;
                }
                uint32_t owner = (v->leg_count == 1)
                                     ? v->leg[0].domain_id
                                     : DNA_TX_OWNER_NONE;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "INSERT INTO v2_tx_index (global_height, "
                        "global_index, tx_id, owner_domain, touched, "
                        "wire_version) VALUES (?1,?2,?3,?4,?5,3)",
                        -1, &st, NULL) != SQLITE_OK) {
                    V2AP_FAULT("phase 12: could not prepare the "
                               "v2_tx_index insert for env %llu",
                               (unsigned long long)i);
                    goto fail_fault;
                }
                sqlite3_bind_int64(st, 1,
                                   (sqlite3_int64)blk->global_height);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
                sqlite3_bind_blob(st, 3, pf[i].wire_id, 64,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_int64(st, 4, (sqlite3_int64)owner);
                sqlite3_bind_blob(st, 5, tl, (int)tw, SQLITE_TRANSIENT);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc != SQLITE_DONE) {
                    V2AP_FAULT("phase 12: v2_tx_index insert for env %llu "
                               "(global index %u) failed (sqlite rc %d)",
                               (unsigned long long)i, (unsigned)gidx, rc);
                    goto fail_fault;
                }
                gidx++;

                /* deterministic local index per leg domain: the lookup
                 * FAILS CLOSED — a miss can never alias index 0
                 * (nodus_witness_v2_local_index_find), and because the
                 * id lists were filled from these same derived ids, a
                 * miss here is an engine invariant broken on THIS node,
                 * not a block property. */
                for (uint16_t t = 0; t < v->leg_count; t++) {
                    dom_ctx_t *d = dom_for(doms, n_dom,
                                           v->leg[t].domain_id);
                    if (!d) {
                        V2AP_FAULT("phase 12: env %llu leg %u names "
                                   "domain %u, absent from the working "
                                   "set at index time",
                                   (unsigned long long)i, (unsigned)t,
                                   (unsigned)v->leg[t].domain_id);
                        goto fail_fault;
                    }
                    uint32_t lidx = 0;
                    if (nodus_witness_v2_local_index_find(
                            (const uint8_t (*)[64])d->wire_ids, d->n_tx,
                            pf[i].wire_id, &lidx) != 0) {
                        V2AP_FAULT("phase 12: env %llu's wire id is "
                                   "missing from domain %u's own %u-entry "
                                   "id list - engine invariant broken on "
                                   "THIS node (a miss never aliases 0)",
                                   (unsigned long long)i,
                                   (unsigned)d->domain_id,
                                   (unsigned)d->n_tx);
                        goto fail_fault;
                    }
                    sqlite3_stmt *ls = NULL;
                    if (sqlite3_prepare_v2(w->db,
                            "INSERT INTO v2_tx_local_index (tx_id, "
                            "domain_id, domain_height, local_index) "
                            "VALUES (?1,?2,?3,?4)", -1, &ls, NULL)
                        != SQLITE_OK) {
                        V2AP_FAULT("phase 12: could not prepare the "
                                   "v2_tx_local_index insert for env %llu "
                                   "domain %u",
                                   (unsigned long long)i,
                                   (unsigned)d->domain_id);
                        goto fail_fault;
                    }
                    sqlite3_bind_blob(ls, 1, pf[i].wire_id, 64,
                                      SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ls, 2,
                        (sqlite3_int64)v->leg[t].domain_id);
                    sqlite3_bind_int64(ls, 3,
                        (sqlite3_int64)d->newhead.domain_height);
                    sqlite3_bind_int64(ls, 4, (sqlite3_int64)lidx);
                    rc = sqlite3_step(ls);
                    sqlite3_finalize(ls);
                    if (rc != SQLITE_DONE) {
                        V2AP_FAULT("phase 12: v2_tx_local_index insert "
                                   "for env %llu domain %u (local index "
                                   "%u) failed (sqlite rc %d)",
                                   (unsigned long long)i,
                                   (unsigned)d->domain_id, (unsigned)lidx,
                                   rc);
                        goto fail_fault;
                    }
                }
            }
        }
cmt_index_done:
        (void)gidx;
    }
    FAIL_POINT(V2AP_FAIL_AFTER_TX_INDEX);

    /* 12b. O15E Faz B — canonical envelope byte availability.
     * The exact WIRE bytes this engine just verified and executed are
     * persisted inside the SAME block transaction, in canonical batch
     * order, so a peer can later re-verify and re-apply this block
     * (BlockMessage v1 = stored header + stored QC + these bytes). The
     * bytes are the envelope's canonical wire encoding — the identical
     * bytes both the producer and a remote applier preflighted — never
     * a struct image. Guarded on the S11 schema: pre-S11 databases
     * (unit fixtures only; every real successor derives at S11) keep
     * the exact pre-O15E behavior, and their committed heights are
     * simply unavailable to serve (fail-closed at the serving seam). */
    if (ver >= NODUS_V2_SCHEMA_VERSION_S11) {
        uint32_t gidx = 0;
        for (int phase = 0; phase < 3; phase++) {
            for (size_t i = 0; i < blk->n_envs; i++) {
                if (env_phase[i] != phase) continue;
                sqlite3_stmt *st = NULL;
                if (sqlite3_prepare_v2(w->db,
                        "INSERT INTO v2_tx_bytes (global_height, "
                        "global_index, tx_id, env) VALUES (?1,?2,?3,?4)",
                        -1, &st, NULL) != SQLITE_OK) {
                    V2AP_FAULT("phase 12b: could not prepare the "
                               "v2_tx_bytes insert for env %llu",
                               (unsigned long long)i);
                    goto fail_fault;
                }
                sqlite3_bind_int64(st, 1,
                                   (sqlite3_int64)blk->global_height);
                sqlite3_bind_int64(st, 2, (sqlite3_int64)gidx);
                sqlite3_bind_blob(st, 3, pf[i].wire_id, 64,
                                  SQLITE_TRANSIENT);
                sqlite3_bind_blob(st, 4, blk->envs[i].env_bytes,
                                  (int)blk->envs[i].env_len,
                                  SQLITE_TRANSIENT);
                int rc = sqlite3_step(st);
                sqlite3_finalize(st);
                if (rc != SQLITE_DONE) {
                    V2AP_FAULT("phase 12b: v2_tx_bytes insert for env "
                               "%llu (%llu bytes) failed (sqlite rc %d)",
                               (unsigned long long)i,
                               (unsigned long long)blk->envs[i].env_len,
                               rc);
                    goto fail_fault;
                }
                gidx++;
            }
        }
    }
    FAIL_POINT(V2AP_FAIL_AFTER_ENV_BYTES);

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
     * to re-derive the claim. Guarded on the S12 schema: pre-S12 databases
     * (unit fixtures only; every real successor derives at S12) keep the
     * exact pre-O15F behavior. */
    if (ver >= NODUS_V2_SCHEMA_VERSION_S12) {
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
        if (blk->cmt.on) {
            /* R3-C1a-7, and the ROW'S OWN RULE: `tx_root` commits the
             * ids of the items this block APPLIED, in block order, and
             * `tx_count` is the size of exactly that list. A refused
             * item contributes neither — its effects went away with its
             * SAVEPOINT, and committing its id would bind the block to
             * a transaction whose state changes were rolled back. (A
             * refused item's `pf[i]` is zeroed by the preflight's own
             * reject path, so including it would commit a run of zero
             * bytes, which is the same defect wearing a disguise.)
             *
             * This is NOT the block's `Data.Txs` count: that one is
             * consensus's, it counts every item the block carries, and
             * it lives in the Comet header's DataHash. The row's
             * `tx_count` is the LEDGER's, and the two differ exactly by
             * the refused items — by design. */
            for (size_t i = 0; i < blk->n_envs; i++)
                if (blk->cmt.results[i].code == NODUS_V2_TX_OK)
                    memcpy(all_ids[n_all++], pf[i].wire_id, 64);
        } else {
            for (int phase = 0; phase < 3; phase++)
                for (size_t i = 0; i < blk->n_envs; i++)
                    if (env_phase[i] == phase)
                        memcpy(all_ids[n_all++], pf[i].wire_id, 64);
        }
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

        /* ── O14: THE ENGINE BUILDS THE HEADER AND OWNS THE BlockID ────
         * Every field below comes from a LOCALLY DERIVED result or from
         * committed pre-state — not one byte is copied from a caller
         * identity input, because no such input exists any more. The
         * caller's `expect_block_id` is compared AFTER the fact and can
         * only reject; it can never become the stored value. */
        dna_block_header_v2_t hdr;
        if (blk->cmt.on) {
            /* ── THE COMETBFT LANE DERIVES NO IDENTITY (D-17 rev 7 (6))
             * The identity a validator signed is cometbft's header hash,
             * and consensus handed it to FinalizeBlock. The ledger
             * stores it verbatim and derives nothing of its own: header
             * v3 is withdrawn (D-19 rev 6), and the `header` column that
             * would hold it does not exist at S14. `vset_hash` is
             * likewise the block's Comet ValidatorsHash, passed in. The
             * ledger's own global root goes into `global_root` as always
             * and is bound by consensus as the NEXT header's AppHash. */
            memcpy(blk->out_block_id, blk->cmt.block_hash, 64);
            memcpy(blk->out_vset_hash, blk->cmt.validators_hash, 64);
            memset(blk->out_header, 0, sizeof(blk->out_header));
            goto cmt_identity_done;
        }
        memset(&hdr, 0, sizeof(hdr));
        hdr.header_version = DNA_BH2_VERSION;
        memcpy(hdr.chain_id, chain_id, DNA_CHAIN_ID_LEN);
        hdr.block_height = blk->global_height;
        hdr.epoch        = blk->epoch;      /* verified vs the derivation
                                             * at function entry        */
        memcpy(hdr.prev_block_id,       blk->out_prev_block_id, 64);
        memcpy(hdr.global_state_root,   blk->out_global_root,   64);
        memcpy(hdr.tx_root,             blk->out_tx_root,       64);
        memcpy(hdr.domain_updates_root, blk->out_dupd_root,     64);
        memcpy(hdr.validator_set_hash,  blk->out_vset_hash,     64);
        hdr.tx_count = n_all;
        memcpy(hdr.proposer_id, blk->proposer_id, 32);
        hdr.timestamp = blk->timestamp;

        if (dna_bh2_encode(&hdr, blk->out_header) != 0) {
            V2AP_FAULT("phase 13: canonical header v%u encoding failed at "
                       "height %llu", (unsigned)DNA_BH2_VERSION,
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }
        FAIL_POINT(V2AP_FAIL_AFTER_HEADER_BUILD);

        if (dna_bh2_block_id(&hdr, blk->out_block_id) != 0) {
            V2AP_FAULT("phase 13: BlockID over the bound header bytes "
                       "could not be computed at height %llu",
                       (unsigned long long)blk->global_height);
            goto fail_fault;
        }

        /* The assertion, checked against the DERIVED id. A follower whose
         * proposer lied about ANY committed header field — a root, the
         * parent, the validator set, the tx count, the proposer — lands
         * here with a different id and the block dies before COMMIT. */
        if (blk->expect_block_id &&
            memcmp(blk->expect_block_id, blk->out_block_id, 64) != 0) {
            char e[17], d[17];
            V2AP_VERDICT("phase 13: BlockID mismatch at height %llu - "
                         "asserted %s, engine derived %s; the proposer "
                         "misreported at least one bound header field",
                         (unsigned long long)blk->global_height,
                         v2ap_hex8(blk->expect_block_id, e),
                         v2ap_hex8(blk->out_block_id, d));
            goto fail;
        }
        FAIL_POINT(V2AP_FAIL_AFTER_BLOCK_ID);

cmt_identity_done:
        /* Same BlockID already committed at ANOTHER height? Checked here,
         * on the REAL id, rather than pre-BEGIN on a caller's claim. The
         * UNIQUE constraint backstops it; doing it explicitly keeps the
         * classification a VERDICT instead of a constraint-shaped fault.
         * In the Comet lane the id is consensus's, so a duplicate means
         * this node is being asked to commit a block it already has —
         * the wrapper turns the verdict below into a fault there. */
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
            V2AP_VERDICT("phase 13: derived BlockID %s is already "
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
        /* THE ROW SHAPE, BY LANE. S14 drops `header`, `qc` and
         * `commit_cert` (D-17 rev 5/7): under cometbft the header lives
         * in the block store's BlockMeta, the seen commit under `SC:<h>`
         * and the canonical commit under `C:<h>` — none of them is the
         * ledger's to keep. So the Comet insert names TEN columns and
         * the legacy one twelve; a single statement cannot serve both,
         * because at S14 the two extra column NAMES do not resolve. */
        if (blk->cmt.on) {
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_blocks (global_height, block_id, "
                    "prev_block_id, epoch, tx_root, domain_updates_root, "
                    "domains_root, global_root, vset_hash, tx_count) "
                    "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    -1, &st, NULL) != SQLITE_OK) {
                V2AP_FAULT("phase 13: could not prepare the Comet "
                           "v2_blocks metadata insert for height %llu",
                           (unsigned long long)blk->global_height);
                goto fail_fault;
            }
        } else if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_blocks (global_height, block_id, "
                "prev_block_id, epoch, tx_root, domain_updates_root, "
                "domains_root, global_root, vset_hash, tx_count, header, "
                "qc) "
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                -1, &st, NULL) != SQLITE_OK) {
            V2AP_FAULT("phase 13: could not prepare the v2_blocks "
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
        if (blk->cmt.on) {
            goto cmt_bind_done;          /* ten columns, no header, no qc */
        }
        sqlite3_bind_blob(st, 11, blk->out_header, DNA_BH2_ENC_SIZE,
                          SQLITE_TRANSIENT);
        /* qc_len is unvalidated caller input at THIS boundary — the
         * engine stores the certificate opaquely and never parses it, so
         * nothing upstream has bounded it. An unchecked size_t → int
         * narrowing would hand sqlite3_bind_blob a negative length,
         * which is undefined. Bound it explicitly; anything larger than
         * a maximal QC cannot be a certificate. (O14 review R1-F5.) */
        if (blk->qc_bytes && blk->qc_len) {
            if (blk->qc_len > (size_t)DNA_QC_V2_MAX_ENC_LEN) {
                sqlite3_finalize(st);
                V2AP_VERDICT("phase 13: the block carries a %llu-byte "
                             "certificate; no QC can exceed %llu bytes",
                             (unsigned long long)blk->qc_len,
                             (unsigned long long)DNA_QC_V2_MAX_ENC_LEN);
                goto fail;
            }
            sqlite3_bind_blob(st, 12, blk->qc_bytes, (int)blk->qc_len,
                              SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_null(st, 12);
        }
cmt_bind_done:
        ;
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

    /* 15. COMMIT (or the simulated commit failure).
     *
     * THE COMETBFT LANE COMMITS NOTHING HERE. The host opened the
     * transaction before FinalizeBlock and `app.commit` closes it
     * (D-23 rev 5 (5)), so this entry returns with the transaction still
     * OPEN and every row it wrote still uncommitted — which is exactly
     * what lets `SaveFinalizeBlockResponse` and `updateState` join it. */
    if (blk->cmt.on) {
        free(pf); free(meters); free(reads); free(resbuf); free(auths);
        free(auth_off); free(claim_nuls); free(env_phase);
        free(cm_pubkeys); free(cm_fps);
        doms_free(doms);
        return 0;
    }
    if (blk->fail_at == V2AP_FAIL_COMMIT) {
        V2AP_VERDICT("fault-injection point V2AP_FAIL_COMMIT fired "
                     "(simulated COMMIT failure; no real check failed)");
        goto fail;
    }
    if (exec_sql(w, "COMMIT") != 0) {
        (void)exec_sql(w, "ROLLBACK");
        V2AP_FAULT("phase 15: COMMIT itself failed at height %llu - "
                   "rolled back; nothing about the block was judged",
                   (unsigned long long)blk->global_height);
        goto fail_fault_committed;      /* commit itself failed: node    */
    }
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(auth_off); free(claim_nuls); free(env_phase);
    free(cm_pubkeys); free(cm_fps);
    doms_free(doms);
    if (blk->fail_at == V2AP_FAIL_AFTER_COMMIT)
        return 2;                        /* committed; pre-cache window  */
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
    /* THE ROLLBACK IS THE TRANSACTION OWNER'S. In the cometbft lane the
     * host owns it (D-23 rev 5 (5)) and rolls it back itself when this
     * entry fails; issuing one here would close a transaction the host
     * still believes is open. */
    if (!blk->cmt.on) {
        (void)exec_sql(w, "ROLLBACK");
    }
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(auth_off); free(claim_nuls); free(env_phase);
    free(cm_pubkeys); free(cm_fps);
    doms_free(doms);
    return -1;

fail_fault:
    if (!blk->cmt.on) {
        (void)exec_sql(w, "ROLLBACK");   /* the owner's, as at `fail` */
    }
fail_fault_committed:
    /* Both the ROLLBACK path and the direct COMMIT-failure jump land
     * here, so the fallback lives at THIS label, not at `fail_fault`. */
    if (blk->out_reason[0] == '\0')
        V2AP_FAULT("in-transaction node fault with no reason recorded "
                   "(`fail_fault` label)");
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(auth_off); free(claim_nuls); free(env_phase);
    free(cm_pubkeys); free(cm_fps);
    doms_free(doms);
    return -2;

/* pre-transaction exits (nothing to roll back in the database) */
fail_verdict_pre:
    if (blk->out_reason[0] == '\0')
        V2AP_VERDICT("pre-transaction rejection with no reason recorded "
                     "(`fail_verdict_pre` label)");
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(auth_off); free(claim_nuls); free(env_phase);
    free(cm_pubkeys); free(cm_fps);
    doms_free(doms);
    return -1;

fail_fault_pre:
    if (blk->out_reason[0] == '\0')
        V2AP_FAULT("pre-transaction node fault with no reason recorded "
                   "(`fail_fault_pre` label)");
    meters_abort_all(meters, blk->n_envs);
    free(pf); free(meters); free(reads); free(resbuf); free(auths);
    free(auth_off); free(claim_nuls); free(env_phase);
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
     * committed around them. */
    if (blk && blk->cmt.on && rc < 0 && rc != NODUS_V2_INTERNAL_FAULT) {
        return NODUS_V2_INTERNAL_FAULT;
    }
    return rc;
}

/* ── the cometbft-lane genesis (FLEET-TM-R3 W2, R3-C1b) ───────────────
 *
 * Contract, and the ONE removal and ONE addition that separate it from
 * nodus_witness_v2_genesis_ex: the header
 * (nodus_witness_v2_apply.h, `nodus_witness_v2_genesis_cmt`).
 *
 * WHY THIS IS A SECOND FUNCTION AND NOT A BRANCH IN THE FIRST. The
 * version-2 entry is the LIVE path: the legacy BFT lane keeps producing
 * V2 blocks on schema S12 between W2 and W3, byte-unchanged (D-17
 * rev 7). A branch inside it would put a conditional on every live
 * genesis, and its idempotency probe — the height-0 row — is exactly
 * what this lane does not have. Nothing above this line is edited; every
 * step below calls the SAME static helpers the version-2 entry calls
 * (domreg_init_genesis, nodus_witness_v2_manifest_commit, doms_load,
 * head_activate, dna_v2_domains_root, dna_v2_global_root,
 * nodus_witness_v2_supply_check), in the same order, so there is one
 * implementation of each step and not two.
 */
int nodus_witness_v2_genesis_cmt(nodus_witness_t *w,
                                 const uint8_t vset_hash[64],
                                 const uint8_t *manifest_bytes,
                                 size_t manifest_len,
                                 uint8_t out_global_root[64]) {
    if (!w || !w->db || !vset_hash || !out_global_root) return -1;
    /* The manifest is REQUIRED — the same fail-closed rule the version-2
     * entry states at :599-609. It is the chain's committed source
     * binding; a genesis that cannot present it has no identity to bind
     * to the document that names it. */
    if (!manifest_bytes || manifest_len == 0) return -1;

    /* SCHEMA GATE (HISTORY): S12 OR S14 IN W2 — S14 ALONE FROM W3.
     * CURRENT (tokenomics-v3 P1 round 5): S15 alone — see the gate's
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
     * path any more. The version-2 entry's own gate at :620-623 (S9-S12)
     * is untouched — it belongs to the closed old lane.
     * tokenomics-v3 P1 moves this gate's accepted value S14 -> S15 (the
     * derivation now migrates to S15 before this point). */
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0 ||
        ver != NODUS_V2_SCHEMA_VERSION_S15) {
        QGP_LOG_ERROR(LOG_TAG, "cometbft genesis needs schema S15, the "
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
    /* And no block may exist yet, on either lane. */
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
