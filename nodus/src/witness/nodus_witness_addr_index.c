/**
 * @file nodus_witness_addr_index.c
 * @brief Node-local address history index (version-3 lane) and the
 *        `dnac_addr_history` answer builder. Contract, tables and the
 *        per-op row derivation: nodus_witness_addr_index.h. Governing
 *        record: docs/plans/decisions/2026-10-01-node-address-history-
 *        index.md (rev 2).
 *
 * Every function here is either a WRITER called from inside the block's
 * SQL transaction (a SQL failure is a FAULT that fails the block — never
 * a skipped row) or the READER behind the RPC (a store fault or a
 * malformed row is an error answer — never a truncated list). Nothing
 * here reads a clock, and nothing in any root, vote or validity path
 * reads what it writes.
 */

#include "witness/nodus_witness_addr_index.h"
#include "witness/nodus_witness_rt_native.h"
#include "witness/nodus_witness_v2_produce.h"   /* nodus_witness_v2_tip_height */
#include "server/nodus_server.h"                /* the node flag            */
#include "protocol/nodus_cbor.h"
#include "nodus/nodus.h"                        /* NODUS_DNAC_ADDR_HISTORY_* */
#include "nodus/nodus_types.h"                  /* NODUS_ERR_*              */
#include "dnac/ledger_ids.h"                    /* DNA_DOMAIN_*             */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "ADDR_INDEX"

/* Rows one envelope can produce: every created coin at most twice
 * (spend_out + spend_in), plus a BURN row, a SYSTEM record row and a
 * standalone fee row. */
#define AI_MAX_ROWS  (2u * NODUS_RT_DESC_MAX_OUT + 3u)

typedef struct {
    uint8_t     owner[64];
    const char *kind;
    uint64_t    amount;
    uint8_t     token[64];
    uint64_t    fee;
    bool        has_peer;
    uint8_t     peer[64];
} ai_row_t;

static const uint8_t AI_NATIVE[64] = {0};

static void ai_reason(char *reason, size_t cap, const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (!reason || cap == 0) return;
    n = snprintf(reason, cap, "FAULT: ");
    if (n < 0 || (size_t)n >= cap) return;
    va_start(ap, fmt);
    vsnprintf(reason + n, cap - (size_t)n, fmt, ap);
    va_end(ap);
}

bool nodus_witness_addr_index_enabled(const nodus_witness_t *w)
{
    return w && w->server && w->server->config.addr_history_index;
}

/* ══ schema ═══════════════════════════════════════════════════════════ */

int nodus_witness_addr_index_migrate(nodus_witness_t *w)
{
    if (!w || !w->db) return -1;

    static const char *const stmts[] = {
        "CREATE TABLE IF NOT EXISTS addr_history ("
        "    h       INTEGER NOT NULL,"
        "    i       INTEGER NOT NULL,"
        "    seq     INTEGER NOT NULL,"
        "    owner   BLOB    NOT NULL,"
        "    kind    TEXT    NOT NULL,"
        "    amount  INTEGER NOT NULL,"
        "    token   BLOB    NOT NULL,"
        "    fee     INTEGER NOT NULL,"
        "    peer    BLOB,"
        "    wire    BLOB,"
        "    ts      INTEGER,"
        "    PRIMARY KEY (h, i, seq)"
        ")",
        "CREATE INDEX IF NOT EXISTS idx_addr_history_owner "
        "ON addr_history (owner, h, i, seq)",
        "CREATE TABLE IF NOT EXISTS addr_history_mark ("
        "    id          INTEGER PRIMARY KEY CHECK (id = 1),"
        "    from_height INTEGER NOT NULL,"
        "    last_height INTEGER NOT NULL"
        ")"
    };

    for (size_t i = 0; i < sizeof(stmts) / sizeof(stmts[0]); i++) {
        char *err = NULL;
        int rc = sqlite3_exec(w->db, stmts[i], NULL, NULL, &err);
        if (rc != SQLITE_OK) {
            QGP_LOG_ERROR(LOG_TAG, "MIGRATION FAILURE: addr_history "
                          "migration stmt[%zu] sqlite error %d: %s",
                          i, rc, err ? err : "(null)");
            if (err) sqlite3_free(err);
            abort();
        }
        if (err) sqlite3_free(err);
    }
    return 0;
}

/* ══ writer helpers ═══════════════════════════════════════════════════ */

/* 128 lowercase hex → 64 raw bytes. @return 0 / -1 (not that shape). */
static int ai_hex_to_raw(const uint8_t *hex, uint8_t raw[64])
{
    for (int b = 0; b < 64; b++) {
        uint8_t v = 0;
        for (int k = 0; k < 2; k++) {
            uint8_t ch = hex[2 * b + k];
            uint8_t d;
            if (ch >= '0' && ch <= '9')      d = (uint8_t)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') d = (uint8_t)(ch - 'a' + 10);
            else return -1;
            v = (uint8_t)((v << 4) | d);
        }
        raw[b] = v;
    }
    return 0;
}

/* The next free seq of (h, i). @return 0 / -1. */
static int ai_next_seq(nodus_witness_t *w, uint64_t h, uint32_t pos,
                       uint32_t *out)
{
    sqlite3_stmt *st = NULL;
    int rc;

    if (sqlite3_prepare_v2(w->db,
            "SELECT COALESCE(MAX(seq) + 1, 0) FROM addr_history "
            "WHERE h = ?1 AND i = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)pos);
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(st);
        return -1;
    }
    {
        sqlite3_int64 v = sqlite3_column_int64(st, 0);
        int           t = sqlite3_column_type(st, 0);
        rc = sqlite3_step(st);
        sqlite3_finalize(st);
        if (t != SQLITE_INTEGER || v < 0 || v > (sqlite3_int64)UINT32_MAX ||
            rc != SQLITE_DONE)
            return -1;
        *out = (uint32_t)v;
    }
    return 0;
}

/* Insert `n` rows at (h, pos), seq continuing after what (h, pos) already
 * holds. `wire` NULL = no wire id. ts is left NULL for block_close.
 * @return 0 / -1 (a SQL failure or an amount the column cannot hold). */
static int ai_insert(nodus_witness_t *w, uint64_t h, uint32_t pos,
                     const ai_row_t *rows, size_t n, const uint8_t *wire)
{
    sqlite3_stmt *st = NULL;
    uint32_t      seq = 0;

    if (n == 0) return 0;
    if (h > (uint64_t)INT64_MAX) return -1;
    if (ai_next_seq(w, h, pos, &seq) != 0) return -1;
    if ((uint64_t)seq + n > (uint64_t)UINT32_MAX) return -1;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO addr_history (h, i, seq, owner, kind, amount, "
            "token, fee, peer, wire, ts) "
            "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    for (size_t r = 0; r < n; r++) {
        int rc;

        if (rows[r].amount > (uint64_t)INT64_MAX ||
            rows[r].fee > (uint64_t)INT64_MAX) {
            sqlite3_finalize(st);
            return -1;
        }
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
        sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)pos);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)(seq + (uint32_t)r));
        sqlite3_bind_blob(st, 4, rows[r].owner, 64, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 5, rows[r].kind, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 6, (sqlite3_int64)rows[r].amount);
        sqlite3_bind_blob(st, 7, rows[r].token, 64, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 8, (sqlite3_int64)rows[r].fee);
        if (rows[r].has_peer)
            sqlite3_bind_blob(st, 9, rows[r].peer, 64, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(st, 9);
        if (wire)
            sqlite3_bind_blob(st, 10, wire, 64, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(st, 10);
        rc = sqlite3_step(st);
        if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
            QGP_LOG_ERROR(LOG_TAG, "insert at (%llu, %u) failed (rc=%d): %s",
                          (unsigned long long)h, (unsigned)pos, rc,
                          sqlite3_errmsg(w->db));
            sqlite3_finalize(st);
            return -1;
        }
    }
    sqlite3_finalize(st);
    return 0;
}

static void ai_row(ai_row_t *r, const uint8_t owner[64], const char *kind,
                   uint64_t amount, const uint8_t token[64],
                   const uint8_t *peer)
{
    memset(r, 0, sizeof(*r));
    memcpy(r->owner, owner, 64);
    r->kind   = kind;
    r->amount = amount;
    memcpy(r->token, token, 64);
    if (peer) {
        r->has_peer = true;
        memcpy(r->peer, peer, 64);
    }
}

/* ══ envelope rows ════════════════════════════════════════════════════ */

/* The SELF set: exactly the ownership the native exec builds
 * (rtn_owners_init) — every verified signer, and every SATISFIED
 * multisig descriptor address. */
static bool ai_is_self(const nodus_rt_auth_verdict_t *av,
                       const uint8_t owner[64])
{
    for (uint16_t s = 0; s < av->n_signers; s++)
        if (memcmp(owner, av->signer_fp[s], 64) == 0) return true;
    for (uint16_t m = 0; m < av->n_msig; m++)
        if (av->msig_satisfied[m] && memcmp(owner, av->msig_addr[m], 64) == 0)
            return true;
    return false;
}

/* The payer (JUDGMENT, the header): the first satisfied multisig address,
 * else the first verified signer. @return NULL when the verdict names
 * neither. */
static const uint8_t *ai_payer(const nodus_rt_auth_verdict_t *av)
{
    for (uint16_t m = 0; m < av->n_msig; m++)
        if (av->msig_satisfied[m]) return av->msig_addr[m];
    if (av->n_signers >= 1) return av->signer_fp[0];
    return NULL;
}

int nodus_witness_addr_index_env(nodus_witness_t *w, uint64_t height,
                                 uint32_t item_pos,
                                 const dna_env_preflight_t *pf,
                                 const nodus_rt_auth_verdict_t *auths,
                                 char *reason, size_t reason_size)
{
    const dna_env_view_t *v;
    nodus_rt_leg_desc_t  *desc = NULL;
    const nodus_rt_leg_desc_t *core = NULL, *sys = NULL;
    const nodus_rt_auth_verdict_t *pav;
    const uint8_t *payer;
    ai_row_t *rows = NULL;
    size_t    n = 0;
    int       core_leg = -1;
    int       ret = -1;

    if (!nodus_witness_addr_index_enabled(w)) return 0;
    if (!w->db || !pf || !auths) {
        ai_reason(reason, reason_size, "addr index: item %u at height %llu: "
                  "missing input", (unsigned)item_pos,
                  (unsigned long long)height);
        return -1;
    }
    v = &pf->view;
    if (v->leg_count == 0 || v->leg_count > 2) {
        /* describe_leg's CORE / SYSTEM pairing is at most one of each */
        ai_reason(reason, reason_size, "addr index: item %u at height %llu "
                  "carries %u legs; this build describes at most one CORE "
                  "and one SYSTEM leg", (unsigned)item_pos,
                  (unsigned long long)height, (unsigned)v->leg_count);
        return -1;
    }
    desc = calloc(2, sizeof(*desc));
    rows = calloc(AI_MAX_ROWS, sizeof(*rows));
    if (!desc || !rows) {
        ai_reason(reason, reason_size, "addr index: allocation failed at "
                  "item %u", (unsigned)item_pos);
        goto done;
    }

    /* ── describe every leg (the exec's own decoders) ─────────────── */
    for (uint16_t l = 0; l < v->leg_count; l++) {
        uint32_t d = v->leg[l].domain_id;
        nodus_rt_leg_desc_t *slot;
        int drc;

        if (d == DNA_DOMAIN_CORE) {
            if (core) goto repeated;
            slot = &desc[0];
        } else if (d == DNA_DOMAIN_SYSTEM) {
            if (sys) goto repeated;
            slot = &desc[1];
        } else {
            ai_reason(reason, reason_size, "addr index: item %u leg %u "
                      "names domain %u, which this build cannot describe",
                      (unsigned)item_pos, (unsigned)l, (unsigned)d);
            goto done;
        }
        drc = nodus_rt_native_describe_leg(v, l, height, pf->intent_id, slot);
        if (drc != 0) {
            ai_reason(reason, reason_size, "addr index: item %u leg %u: %s",
                      (unsigned)item_pos, (unsigned)l,
                      drc == -2 ? "hash backend failed describing an "
                                  "applied leg"
                                : "this build cannot describe an applied "
                                  "leg");
            goto done;
        }
        if (d == DNA_DOMAIN_CORE) {
            core = slot;
            core_leg = (int)l;
        } else {
            sys = slot;
        }
        continue;
repeated:
        ai_reason(reason, reason_size, "addr index: applied item %u repeats "
                  "domain %u", (unsigned)item_pos, (unsigned)d);
        goto done;
    }

    pav   = &auths[core_leg >= 0 ? core_leg : 0];
    payer = ai_payer(pav);

    /* ── CORE effects ─────────────────────────────────────────────── */
    if (core) {
        const bool tc = (core->runtime_op == DNA_CORERULE_TOKEN_CREATE);

        for (uint8_t c = 0; c < core->n_created; c++) {
            const nodus_rt_desc_coin_t *coin = &core->created[c];
            uint8_t owner[64];

            if (ai_hex_to_raw(coin->owner_hex, owner) != 0) {
                ai_reason(reason, reason_size, "addr index: item %u coin %u "
                          "owner is not 128 lowercase hex",
                          (unsigned)item_pos, (unsigned)c);
                goto done;
            }
            if (tc && memcmp(coin->token_id, AI_NATIVE, 64) != 0) {
                const uint8_t *peer =
                    (payer && memcmp(owner, payer, 64) != 0) ? payer : NULL;
                ai_row(&rows[n++], owner, NODUS_ADDR_KIND_TOKEN_CREATE,
                       coin->amount, coin->token_id, peer);
                continue;
            }
            if (ai_is_self(pav, owner)) continue;          /* change    */
            if (!payer) goto no_payer;
            ai_row(&rows[n++], payer, NODUS_ADDR_KIND_SPEND_OUT,
                   coin->amount, coin->token_id, owner);
            ai_row(&rows[n++], owner, NODUS_ADDR_KIND_SPEND_IN,
                   coin->amount, coin->token_id, payer);
        }
        if (core->burned > 0) {
            if (!payer) goto no_payer;
            ai_row(&rows[n++], payer, NODUS_ADDR_KIND_BURN, core->burned,
                   AI_NATIVE, NULL);
        }
    }

    /* ── SYSTEM record ────────────────────────────────────────────── */
    if (sys) {
        switch (sys->rec) {
        case NODUS_RT_DESC_REC_STAKE:
            ai_row(&rows[n++], sys->rec_validator_fp, NODUS_ADDR_KIND_STAKE,
                   sys->rec_amount, AI_NATIVE, NULL);
            break;
        case NODUS_RT_DESC_REC_DELEGATE:
            ai_row(&rows[n++], sys->rec_delegator_fp,
                   NODUS_ADDR_KIND_DELEGATE, sys->rec_amount, AI_NATIVE,
                   sys->rec_validator_fp);
            break;
        case NODUS_RT_DESC_REC_UNDELEGATE:
            ai_row(&rows[n++], sys->rec_delegator_fp,
                   NODUS_ADDR_KIND_UNDELEGATE, sys->rec_amount, AI_NATIVE,
                   sys->rec_validator_fp);
            break;
        case NODUS_RT_DESC_REC_UNSTAKE:
            ai_row(&rows[n++], sys->rec_validator_fp,
                   NODUS_ADDR_KIND_UNSTAKE, 0, AI_NATIVE, NULL);
            break;
        case NODUS_RT_DESC_REC_VALIDATOR_UPDATE:
            ai_row(&rows[n++], sys->rec_validator_fp,
                   NODUS_ADDR_KIND_VALIDATOR_UPDATE, 0, AI_NATIVE, NULL);
            break;
        case NODUS_RT_DESC_REC_CHAIN_CONFIG:
        case NODUS_RT_DESC_REC_NONE:
        default:
            break;
        }
    }

    /* ── the fee, on the payer's first row ─────────────────────────── */
    if (v->fee_amount > 0) {
        size_t r;

        if (!payer) goto no_payer;
        for (r = 0; r < n; r++)
            if (memcmp(rows[r].owner, payer, 64) == 0) break;
        if (r == n)
            ai_row(&rows[n++], payer, NODUS_ADDR_KIND_FEE, 0, AI_NATIVE,
                   NULL);
        rows[r].fee = v->fee_amount;
    }

    if (ai_insert(w, height, item_pos, rows, n, pf->wire_id) != 0) {
        ai_reason(reason, reason_size, "addr index: rows of item %u at "
                  "height %llu could not be written",
                  (unsigned)item_pos, (unsigned long long)height);
        goto done;
    }
    ret = 0;
    goto done;

no_payer:
    ai_reason(reason, reason_size, "addr index: applied item %u at height "
              "%llu has an effect but its verdict names no payer",
              (unsigned)item_pos, (unsigned long long)height);
done:
    free(rows);
    free(desc);
    return ret;
}

/* ══ claim row ════════════════════════════════════════════════════════ */

int nodus_witness_addr_index_claim(nodus_witness_t *w, uint64_t height,
                                   uint32_t item_pos, const dna_claim_t *c,
                                   const uint8_t nullifier[64],
                                   uint32_t target_domain,
                                   char *reason, size_t reason_size)
{
    sqlite3_stmt *st = NULL;
    uint8_t      *cbuf = NULL;
    uint8_t       chash[64];
    size_t        need, clen = 0;
    ai_row_t      row;
    uint64_t      amount;
    int           rc;

    if (!nodus_witness_addr_index_enabled(w)) return 0;
    if (!w->db || !c || !nullifier) {
        ai_reason(reason, reason_size, "addr index: claim %u: missing input",
                  (unsigned)item_pos);
        return -1;
    }
    if (target_domain != DNA_DOMAIN_CORE) return 0;   /* the header      */

    /* the amount the apply recorded for THIS claim (v2_claims_spent,
     * written by claim_execute_one in this same transaction) */
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount, claimed_height FROM v2_claims_spent "
            "WHERE nullifier = ?1", -1, &st, NULL) != SQLITE_OK) {
        ai_reason(reason, reason_size, "addr index: claim %u: spent-claim "
                  "read could not be prepared", (unsigned)item_pos);
        return -1;
    }
    sqlite3_bind_blob(st, 1, nullifier, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW ||
        sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
        sqlite3_column_int64(st, 0) <= 0 ||
        (uint64_t)sqlite3_column_int64(st, 1) != height) {
        sqlite3_finalize(st);
        ai_reason(reason, reason_size, "addr index: applied claim %u has no "
                  "well-formed spent-claim row at height %llu",
                  (unsigned)item_pos, (unsigned long long)height);
        return -1;
    }
    amount = (uint64_t)sqlite3_column_int64(st, 0);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        ai_reason(reason, reason_size, "addr index: claim %u: spent-claim "
                  "read did not end cleanly (rc=%d)", (unsigned)item_pos, rc);
        return -1;
    }

    /* the claim's wire id = SHA3-512 of its canonical bytes — the SAME
     * derivation phase 12c stores as v2_claim_bytes.claim_hash */
    need = dna_claim_encoded_len(c);
    cbuf = need ? malloc(need) : NULL;
    if (!cbuf || dna_claim_encode(c, cbuf, need, &clen) != 0 ||
        clen != need || qgp_sha3_512(cbuf, clen, chash) != 0) {
        free(cbuf);
        ai_reason(reason, reason_size, "addr index: claim %u re-encode or "
                  "hash failed on this node", (unsigned)item_pos);
        return -1;
    }
    free(cbuf);

    ai_row(&row, c->dest_binding, NODUS_ADDR_KIND_CLAIM, amount, AI_NATIVE,
           NULL);
    if (ai_insert(w, height, item_pos, &row, 1, chash) != 0) {
        ai_reason(reason, reason_size, "addr index: the row of claim %u at "
                  "height %llu could not be written", (unsigned)item_pos,
                  (unsigned long long)height);
        return -1;
    }
    return 0;
}

/* ══ boundary rows ════════════════════════════════════════════════════ */

int nodus_witness_addr_index_boundary(nodus_witness_t *w, uint64_t height,
                                      const char *kind,
                                      const uint8_t *owner_hex,
                                      uint64_t amount)
{
    ai_row_t row;
    uint8_t  owner[64];

    if (!nodus_witness_addr_index_enabled(w)) return 0;
    if (!w->db || !kind || !owner_hex ||
        ai_hex_to_raw(owner_hex, owner) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "boundary %s row at height %llu: malformed "
                      "input", kind ? kind : "(null)",
                      (unsigned long long)height);
        return -2;
    }
    ai_row(&row, owner, kind, amount, AI_NATIVE, NULL);
    if (ai_insert(w, height, NODUS_ADDR_INDEX_BOUNDARY_POS, &row, 1, NULL)
        != 0) {
        QGP_LOG_ERROR(LOG_TAG, "boundary %s row at height %llu could not be "
                      "written", kind, (unsigned long long)height);
        return -2;
    }
    return 0;
}

/* ══ block close: the time stamp and the marker ═══════════════════════ */

int nodus_witness_addr_index_block_close(nodus_witness_t *w,
                                         uint64_t height,
                                         uint64_t block_time,
                                         char *reason, size_t reason_size)
{
    sqlite3_stmt *st = NULL;
    int           rc;
    bool          have = false;
    sqlite3_int64 from_h = 0, last_h = 0;

    if (!nodus_witness_addr_index_enabled(w)) return 0;
    if (!w->db || height == 0 || height > (uint64_t)INT64_MAX ||
        block_time > (uint64_t)INT64_MAX) {
        ai_reason(reason, reason_size, "addr index: block close at height "
                  "%llu: height or block time out of range",
                  (unsigned long long)height);
        return -1;
    }

    /* 1. the block time on every row of this height */
    if (sqlite3_prepare_v2(w->db,
            "UPDATE addr_history SET ts = ?1 WHERE h = ?2",
            -1, &st, NULL) != SQLITE_OK) {
        ai_reason(reason, reason_size, "addr index: time stamp at height "
                  "%llu could not be prepared", (unsigned long long)height);
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)block_time);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)height);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        ai_reason(reason, reason_size, "addr index: time stamp at height "
                  "%llu failed (rc=%d)", (unsigned long long)height, rc);
        return -1;
    }

    /* 2. the marker */
    if (sqlite3_prepare_v2(w->db,
            "SELECT from_height, last_height FROM addr_history_mark "
            "WHERE id = 1", -1, &st, NULL) != SQLITE_OK) {
        ai_reason(reason, reason_size, "addr index: marker read could not "
                  "be prepared");
        return -1;
    }
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER ||
            sqlite3_column_type(st, 1) != SQLITE_INTEGER) {
            sqlite3_finalize(st);
            ai_reason(reason, reason_size, "addr index: malformed marker "
                      "row");
            return -1;
        }
        from_h = sqlite3_column_int64(st, 0);
        last_h = sqlite3_column_int64(st, 1);
        have = true;
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) {
        ai_reason(reason, reason_size, "addr index: marker read failed "
                  "(rc=%d)", rc);
        return -1;
    }
    if (have && (from_h < 1 || last_h < from_h)) {
        ai_reason(reason, reason_size, "addr index: malformed marker row "
                  "(from %lld, last %lld)", (long long)from_h,
                  (long long)last_h);
        return -1;
    }
    if (have && (uint64_t)last_h >= height) {
        /* v2_blocks already holds this height in the same database; the
         * engine could not be applying it again */
        ai_reason(reason, reason_size, "addr index: height %llu is already "
                  "indexed (last %lld)", (unsigned long long)height,
                  (long long)last_h);
        return -1;
    }
    if (!have) {
        rc = sqlite3_prepare_v2(w->db,
                "INSERT INTO addr_history_mark (id, from_height, "
                "last_height) VALUES (1, ?1, ?1)", -1, &st, NULL);
    } else if ((uint64_t)last_h + 1u == height) {
        rc = sqlite3_prepare_v2(w->db,
                "UPDATE addr_history_mark SET last_height = ?1 "
                "WHERE id = 1", -1, &st, NULL);
    } else {
        QGP_LOG_WARN(LOG_TAG, "index gap: last indexed height %lld, now "
                     "%llu — the complete run restarts here",
                     (long long)last_h, (unsigned long long)height);
        rc = sqlite3_prepare_v2(w->db,
                "UPDATE addr_history_mark SET from_height = ?1, "
                "last_height = ?1 WHERE id = 1", -1, &st, NULL);
    }
    if (rc != SQLITE_OK) {
        ai_reason(reason, reason_size, "addr index: marker write could not "
                  "be prepared");
        return -1;
    }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)height);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE || sqlite3_changes(w->db) != 1) {
        ai_reason(reason, reason_size, "addr index: marker write at height "
                  "%llu failed (rc=%d)", (unsigned long long)height, rc);
        return -1;
    }
    return 0;
}

/* ══ the dnac_addr_history answer ═════════════════════════════════════ */

/* Per entry: map head 1 + "h" 2+9 + "i" 2+5 + "q" 2+5 + "kind" 5+1+16 +
 * "amount" 7+9 + "token" 6+2+64 + "fee" 4+9 + "peer" 5+2+128 +
 * "wire" 5+2+64 + "ts" 3+9 = 367 B; the T2 envelope + "r" framing + the
 * four top-level keys stay far below the header budget. */
#define AI_ENTRY_MAX_BYTES  400u
#define AI_HDR_MAX_BYTES    256u

_Static_assert((size_t)AI_HDR_MAX_BYTES +
                   (size_t)NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT *
                       AI_ENTRY_MAX_BYTES <
               (size_t)NODUS_MAX_FRAME_TCP,
               "a dnac_addr_history answer must fit the tier-2 frame");

static const char *const AI_KINDS[] = {
    NODUS_ADDR_KIND_SPEND_OUT, NODUS_ADDR_KIND_SPEND_IN,
    NODUS_ADDR_KIND_BURN, NODUS_ADDR_KIND_TOKEN_CREATE,
    NODUS_ADDR_KIND_CLAIM, NODUS_ADDR_KIND_STAKE,
    NODUS_ADDR_KIND_DELEGATE, NODUS_ADDR_KIND_UNDELEGATE,
    NODUS_ADDR_KIND_UNSTAKE, NODUS_ADDR_KIND_VALIDATOR_UPDATE,
    NODUS_ADDR_KIND_PAYOUT, NODUS_ADDR_KIND_RELEASE, NODUS_ADDR_KIND_FEE
};

/* @return the canonical kind string for a stored value, NULL when the
 * stored text is none of them. */
static const char *ai_kind_known(const unsigned char *txt, int len)
{
    if (!txt || len <= 0) return NULL;
    for (size_t k = 0; k < sizeof(AI_KINDS) / sizeof(AI_KINDS[0]); k++) {
        if (strlen(AI_KINDS[k]) == (size_t)len &&
            memcmp(AI_KINDS[k], txt, (size_t)len) == 0)
            return AI_KINDS[k];
    }
    return NULL;
}

static void ai_err(int *err_code, char *err_msg, size_t err_cap, int code,
                   const char *msg)
{
    if (err_code) *err_code = code;
    if (err_msg && err_cap) snprintf(err_msg, err_cap, "%s", msg);
}

typedef struct {
    uint64_t    h;
    uint32_t    i;
    uint32_t    q;
    const char *kind;
    uint64_t    amount;
    uint8_t     token[64];
    uint64_t    fee;
    bool        has_peer;
    uint8_t     peer[64];
    bool        has_wire;
    uint8_t     wire[64];
    uint64_t    ts;
} ai_entry_t;

/* A 64-byte BLOB column, or NULL when `nullable`. @return 1 present,
 * 0 NULL, -1 malformed. */
static int ai_col_b64(sqlite3_stmt *st, int col, bool nullable,
                      uint8_t out[64])
{
    int t = sqlite3_column_type(st, col);
    if (t == SQLITE_NULL) return nullable ? 0 : -1;
    if (t != SQLITE_BLOB || sqlite3_column_bytes(st, col) != 64) return -1;
    memcpy(out, sqlite3_column_blob(st, col), 64);
    return 1;
}

static int ai_col_u64(sqlite3_stmt *st, int col, uint64_t max,
                      uint64_t *out)
{
    sqlite3_int64 v;
    if (sqlite3_column_type(st, col) != SQLITE_INTEGER) return -1;
    v = sqlite3_column_int64(st, col);
    if (v < 0 || (uint64_t)v > max) return -1;
    *out = (uint64_t)v;
    return 0;
}

static void ai_hex(const uint8_t raw[64], char out[129])
{
    static const char hexd[] = "0123456789abcdef";
    for (int b = 0; b < 64; b++) {
        out[2 * b]     = hexd[raw[b] >> 4];
        out[2 * b + 1] = hexd[raw[b] & 0x0F];
    }
    out[128] = '\0';
}

/* The T2 response head — the shape of nodus_witness_handlers.c's static
 * enc_dnac_response, copied (7 lines) so the builder lives beside the
 * table it reads. */
static void ai_enc_response(cbor_encoder_t *enc, uint32_t txn_id,
                            size_t r_map_count)
{
    cbor_encode_map(enc, 4);
    cbor_encode_cstr(enc, "t");  cbor_encode_uint(enc, txn_id);
    cbor_encode_cstr(enc, "y");  cbor_encode_cstr(enc, "r");
    cbor_encode_cstr(enc, "q");  cbor_encode_cstr(enc, "dnac_addr_history");
    cbor_encode_cstr(enc, "r");
    cbor_encode_map(enc, r_map_count);
}

int nodus_witness_addr_history_build(nodus_witness_t *w, uint32_t txn_id,
                                     const uint8_t *session_fp,
                                     const char *owner,
                                     const nodus_witness_addr_cursor_t *before,
                                     uint32_t limit,
                                     uint8_t **out, size_t *out_len,
                                     int *err_code, char *err_msg,
                                     size_t err_cap)
{
    uint8_t       owner_raw[64];
    uint64_t      tip = 0, from_h = 0;
    ai_entry_t   *ent = NULL;
    size_t        n = 0;
    sqlite3_stmt *st = NULL;
    int           rc;
    uint8_t      *buf = NULL;

    if (err_code) *err_code = 0;
    if (err_msg && err_cap) err_msg[0] = '\0';
    if (!w || !owner || !out || !out_len) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
               "invalid arguments");
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    if (strnlen(owner, 129) != 128 ||
        ai_hex_to_raw((const uint8_t *)owner, owner_raw) != 0) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_PROTOCOL_ERROR,
               "owner must be 128 lowercase hex characters");
        return -1;
    }
    /* C11 (the dnac_history rule): only the authenticated owner may read
     * its own history */
    if (!session_fp) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_NOT_AUTHENTICATED,
               "session not authenticated");
        return -1;
    }
    if (memcmp(session_fp, owner_raw, 64) != 0) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_NOT_AUTHENTICATED,
               "owner must match authenticated session fingerprint");
        return -1;
    }
    if (limit < 1 || limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_PROTOCOL_ERROR,
               "limit must be 1..100");
        return -1;
    }
    if (before && before->h > (uint64_t)INT64_MAX) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_PROTOCOL_ERROR,
               "before out of range");
        return -1;
    }
    if (!w->v2_successor || !w->db) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_NOT_FOUND,
               "this node serves no version-3 chain");
        return -1;
    }
    if (nodus_witness_v2_tip_height(w, &tip) != 0) {
        ai_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
               "chain height unreadable");
        return -1;
    }

    /* the marker: from_height, 0 when nothing was ever indexed */
    if (sqlite3_prepare_v2(w->db,
            "SELECT from_height FROM addr_history_mark WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        goto internal;
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (ai_col_u64(st, 0, (uint64_t)INT64_MAX, &from_h) != 0 ||
            from_h == 0) {
            sqlite3_finalize(st);
            goto internal;
        }
        rc = sqlite3_step(st);
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) goto internal;

    ent = calloc(limit, sizeof(*ent));
    if (!ent) goto internal;
    if (sqlite3_prepare_v2(w->db, before
            ? "SELECT h, i, seq, kind, amount, token, fee, peer, wire, ts "
              "FROM addr_history WHERE owner = ?1 "
              "AND (h, i, seq) < (?2, ?3, ?4) "
              "ORDER BY h DESC, i DESC, seq DESC LIMIT ?5"
            : "SELECT h, i, seq, kind, amount, token, fee, peer, wire, ts "
              "FROM addr_history WHERE owner = ?1 "
              "ORDER BY h DESC, i DESC, seq DESC LIMIT ?5",
            -1, &st, NULL) != SQLITE_OK)
        goto internal;
    sqlite3_bind_blob(st, 1, owner_raw, 64, SQLITE_TRANSIENT);
    if (before) {
        sqlite3_bind_int64(st, 2, (sqlite3_int64)before->h);
        sqlite3_bind_int64(st, 3, (sqlite3_int64)before->i);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)before->q);
    }
    sqlite3_bind_int64(st, 5, (sqlite3_int64)limit);
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        ai_entry_t *e;
        uint64_t    iv = 0, qv = 0;

        if (n >= limit) goto bad_row;              /* LIMIT broken      */
        e = &ent[n];
        if (ai_col_u64(st, 0, (uint64_t)INT64_MAX, &e->h) != 0 ||
            ai_col_u64(st, 1, UINT32_MAX, &iv) != 0 ||
            ai_col_u64(st, 2, UINT32_MAX, &qv) != 0 ||
            sqlite3_column_type(st, 3) != SQLITE_TEXT ||
            !(e->kind = ai_kind_known(sqlite3_column_text(st, 3),
                                      sqlite3_column_bytes(st, 3))) ||
            ai_col_u64(st, 4, (uint64_t)INT64_MAX, &e->amount) != 0 ||
            ai_col_b64(st, 5, false, e->token) != 1 ||
            ai_col_u64(st, 6, (uint64_t)INT64_MAX, &e->fee) != 0 ||
            ai_col_u64(st, 9, (uint64_t)INT64_MAX, &e->ts) != 0)
            goto bad_row;
        e->i = (uint32_t)iv;
        e->q = (uint32_t)qv;
        {
            int p = ai_col_b64(st, 7, true, e->peer);
            int x = ai_col_b64(st, 8, true, e->wire);
            if (p < 0 || x < 0) goto bad_row;
            e->has_peer = (p == 1);
            e->has_wire = (x == 1);
        }
        if (e->h == 0 || e->h > tip) goto bad_row;
        n++;
    }
    sqlite3_finalize(st);
    st = NULL;
    if (rc != SQLITE_DONE) goto internal;

    {
        size_t cap = AI_HDR_MAX_BYTES + n * AI_ENTRY_MAX_BYTES;
        cbor_encoder_t enc;

        buf = malloc(cap);
        if (!buf) goto internal;
        cbor_encoder_init(&enc, buf, cap);
        ai_enc_response(&enc, txn_id, 4);
        cbor_encode_cstr(&enc, "count");
        cbor_encode_uint(&enc, (uint64_t)n);
        cbor_encode_cstr(&enc, "enabled");
        cbor_encode_bool(&enc, nodus_witness_addr_index_enabled(w));
        cbor_encode_cstr(&enc, "from_height");
        cbor_encode_uint(&enc, from_h);
        cbor_encode_cstr(&enc, "entries");
        cbor_encode_array(&enc, n);
        for (size_t k = 0; k < n; k++) {
            const ai_entry_t *e = &ent[k];
            char ph[129];

            cbor_encode_map(&enc, 10);
            cbor_encode_cstr(&enc, "h");      cbor_encode_uint(&enc, e->h);
            cbor_encode_cstr(&enc, "i");      cbor_encode_uint(&enc, e->i);
            cbor_encode_cstr(&enc, "q");      cbor_encode_uint(&enc, e->q);
            cbor_encode_cstr(&enc, "kind");   cbor_encode_cstr(&enc, e->kind);
            cbor_encode_cstr(&enc, "amount"); cbor_encode_uint(&enc, e->amount);
            cbor_encode_cstr(&enc, "token");
            cbor_encode_bstr(&enc, e->token, 64);
            cbor_encode_cstr(&enc, "fee");    cbor_encode_uint(&enc, e->fee);
            cbor_encode_cstr(&enc, "peer");
            if (e->has_peer) {
                ai_hex(e->peer, ph);
                cbor_encode_tstr(&enc, ph, 128);
            } else {
                cbor_encode_tstr(&enc, "", 0);
            }
            cbor_encode_cstr(&enc, "wire");
            cbor_encode_bstr(&enc, e->wire, e->has_wire ? 64 : 0);
            cbor_encode_cstr(&enc, "ts");     cbor_encode_uint(&enc, e->ts);
        }
        free(ent);
        ent = NULL;
        *out_len = cbor_encoder_len(&enc);
        if (*out_len == 0) {                 /* the size bound is broken  */
            free(buf);
            ai_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
                   "response buffer overflow");
            return -1;
        }
        *out = buf;
    }
    return 0;

bad_row:
    QGP_LOG_WARN(LOG_TAG, "dnac_addr_history owner=%.16s...: malformed "
                 "stored row", owner);
internal:
    if (st) sqlite3_finalize(st);
    free(ent);
    ai_err(err_code, err_msg, err_cap, NODUS_ERR_INTERNAL_ERROR,
           "address history unreadable");
    return -1;
}
