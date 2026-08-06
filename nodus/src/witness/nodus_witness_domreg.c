/**
 * @file nodus_witness_domreg.c
 * @brief Ledger V2 Season 4 — witness-side domain registry implementation
 *        (INACTIVE). See nodus_witness_domreg.h for the staged policy.
 *
 * @file nodus_witness_domreg.c
 */

#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_roots_v2.h"

#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "dnac/dnac.h"                 /* DNAC_EPOCH_LENGTH               */
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "W_DOMREG"

#define EPOCH_LEN ((uint64_t)DNAC_EPOCH_LENGTH)

/* ── Row I/O ────────────────────────────────────────────────────────── */

/* Load + fully validate one row. 0 found / 1 absent / -1 fault. */
static int row_load(nodus_witness_t *w, uint32_t domain_id,
                    dna_domreg_record_t *rec,
                    dna_domain_manifest_t *cur,
                    dna_domain_manifest_t *pend, int *has_pend) {
    if (!w || !w->db || !rec) return -1;
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT record, current_manifest, pending_manifest "
        "FROM domain_registry WHERE domain_id = ?1", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)domain_id);

    rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    if (rc != SQLITE_ROW)  { sqlite3_finalize(st); return -1; }

    int out = -1;
    do {
        const void *rb = sqlite3_column_blob(st, 0);
        int rl = sqlite3_column_bytes(st, 0);
        if (!rb || rl != DNA_DOMREG_REC_ENC_LEN) break;
        if (dna_domreg_record_decode((const uint8_t *)rb, (size_t)rl,
                                     rec) != 0) break;
        if (rec->domain_id != domain_id) break;

        const void *cb = sqlite3_column_blob(st, 1);
        int cl = sqlite3_column_bytes(st, 1);
        dna_domain_manifest_t cm;
        if (!cb || cl <= 0 ||
            dna_domman_decode((const uint8_t *)cb, (size_t)cl, &cm) != 0)
            break;
        uint8_t h[DNA_DOM_HASH_LEN];
        if (dna_domman_hash(&cm, h) != 0 ||
            memcmp(h, rec->current_manifest_hash, DNA_DOM_HASH_LEN) != 0)
            break;
        if (cm.domain_id != domain_id) break;

        const void *pb = sqlite3_column_blob(st, 2);
        int pl = sqlite3_column_bytes(st, 2);
        dna_domain_manifest_t pm;
        memset(&pm, 0, sizeof(pm));
        int hp = 0;
        if (rec->pending_present) {
            if (!pb || pl <= 0 ||
                dna_domman_decode((const uint8_t *)pb, (size_t)pl,
                                  &pm) != 0)
                break;
            if (dna_domman_hash(&pm, h) != 0 ||
                memcmp(h, rec->pending_manifest_hash,
                       DNA_DOM_HASH_LEN) != 0)
                break;
            if (pm.domain_id != domain_id) break;
            hp = 1;
        } else if (pb) {
            break;                     /* ghost pending blob = corruption  */
        }

        if (cur)  *cur = cm;
        if (pend) *pend = pm;
        if (has_pend) *has_pend = hp;
        out = 0;
    } while (0);

    sqlite3_finalize(st);
    return out;
}

/* Store (INSERT OR REPLACE) one fully validated row. */
static int row_store(nodus_witness_t *w, const dna_domreg_record_t *rec,
                     const dna_domain_manifest_t *cur,
                     const dna_domain_manifest_t *pend) {
    if (!w || !w->db || dna_domreg_record_validate(rec) != 0) return -1;
    if ((rec->pending_present != 0) != (pend != NULL)) return -1;

    uint8_t recb[DNA_DOMREG_REC_ENC_LEN];
    if (dna_domreg_record_encode(rec, recb) != 0) return -1;

    uint8_t curb[DNA_DOMMAN_MAX_ENC_LEN];
    size_t curl = 0;
    if (dna_domman_encode(cur, curb, sizeof(curb), &curl) != 0) return -1;
    uint8_t h[DNA_DOM_HASH_LEN];
    if (dna_domman_hash(cur, h) != 0 ||
        memcmp(h, rec->current_manifest_hash, DNA_DOM_HASH_LEN) != 0)
        return -1;

    uint8_t pendb[DNA_DOMMAN_MAX_ENC_LEN];
    size_t pendl = 0;
    if (pend) {
        if (dna_domman_encode(pend, pendb, sizeof(pendb), &pendl) != 0)
            return -1;
        if (dna_domman_hash(pend, h) != 0 ||
            memcmp(h, rec->pending_manifest_hash, DNA_DOM_HASH_LEN) != 0)
            return -1;
    }

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "INSERT OR REPLACE INTO domain_registry "
        "(domain_id, record, current_manifest, pending_manifest) "
        "VALUES (?1, ?2, ?3, ?4)", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)rec->domain_id);
    sqlite3_bind_blob(st, 2, recb, DNA_DOMREG_REC_ENC_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, curb, (int)curl, SQLITE_TRANSIENT);
    if (pend)
        sqlite3_bind_blob(st, 4, pendb, (int)pendl, SQLITE_TRANSIENT);
    else
        sqlite3_bind_null(st, 4);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int signals_delete(nodus_witness_t *w,
                          const uint8_t digest[DNA_DOM_HASH_LEN]) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "DELETE FROM domain_readiness WHERE proposal_digest = ?1",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, digest, DNA_DOM_HASH_LEN, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* 1 = a signal row exists for (digest, voter); 0 = none; -1 = fault. */
static int signal_exists(nodus_witness_t *w,
                         const uint8_t digest[DNA_DOM_HASH_LEN],
                         const uint8_t voter[DNA_DOM_VOTER_ID_LEN]) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT 1 FROM domain_readiness "
        "WHERE proposal_digest = ?1 AND voter_id = ?2", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, digest, DNA_DOM_HASH_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, voter, DNA_DOM_VOTER_ID_LEN, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return rc == SQLITE_DONE ? 0 : -1;
}

/* Mark every tx type owned by any domain except `exclude_id` (current AND
 * pending manifests — a pending upgrade's ownership becomes live at
 * activation, so collisions are rejected at the door). Fail-closed. */
static int owned_types_collect(nodus_witness_t *w, uint32_t exclude_id,
                               uint8_t used[256]) {
    memset(used, 0, 256);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT domain_id FROM domain_registry ORDER BY domain_id ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;

    int out = 0;
    uint32_t ids[64];
    size_t n = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= sizeof(ids) / sizeof(ids[0])) { out = -1; break; }
        ids[n++] = (uint32_t)sqlite3_column_int64(st, 0);
    }
    if (out == 0 && rc != SQLITE_DONE) out = -1;
    sqlite3_finalize(st);
    if (out != 0) return -1;

    for (size_t i = 0; i < n; i++) {
        if (ids[i] == exclude_id) continue;
        dna_domreg_record_t rec;
        dna_domain_manifest_t cur, pend;
        int hp = 0;
        if (row_load(w, ids[i], &rec, &cur, &pend, &hp) != 0) return -1;
        if (rec.status == DNA_DOMST_RETIRED) continue;
        for (size_t t = 0; t < cur.tx_type_count; t++)
            used[cur.tx_types[t]] = 1;
        if (hp)
            for (size_t t = 0; t < pend.tx_type_count; t++)
                used[pend.tx_types[t]] = 1;
    }
    return 0;
}

static int types_collide(const dna_domain_manifest_t *m,
                         const uint8_t used[256]) {
    for (size_t t = 0; t < m->tx_type_count; t++)
        if (used[m->tx_types[t]]) return 1;
    return 0;
}

static int member_index(const dna_vset_snapshot_t *snap,
                        const uint8_t voter[DNA_DOM_VOTER_ID_LEN]) {
    for (uint16_t i = 0; i < snap->active_count; i++)
        if (memcmp(snap->entries[i].voter_id, voter,
                   DNA_DOM_VOTER_ID_LEN) == 0)
            return (int)i;
    return -1;
}

static int membership_equal(const dna_vset_snapshot_t *a,
                            const dna_vset_snapshot_t *b) {
    if (a->active_count != b->active_count) return 0;
    for (uint16_t i = 0; i < a->active_count; i++)
        if (member_index(b, a->entries[i].voter_id) < 0) return 0;
    return 1;
}

/* ── Read side ──────────────────────────────────────────────────────── */

int nodus_witness_domreg_get(nodus_witness_t *w, uint32_t domain_id,
                             dna_domreg_record_t *rec_out,
                             dna_domain_manifest_t *cur_out,
                             dna_domain_manifest_t *pend_out) {
    dna_domreg_record_t rec;
    dna_domain_manifest_t cur, pend;
    int hp = 0;
    int rc = row_load(w, domain_id, &rec, &cur, &pend, &hp);
    if (rc != 0) return rc;
    if (rec_out)  *rec_out = rec;
    if (cur_out)  *cur_out = cur;
    if (pend_out) *pend_out = pend;
    return 0;
}

int nodus_witness_domreg_root(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT domain_id FROM domain_registry ORDER BY domain_id ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;

    dna_domreg_record_t *recs = NULL;
    size_t n = 0, cap = 0;
    int out_rc = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            dna_domreg_record_t *nr =
                realloc(recs, ncap * sizeof(*recs));
            if (!nr) { out_rc = -1; break; }
            recs = nr; cap = ncap;
        }
        uint32_t id = (uint32_t)sqlite3_column_int64(st, 0);
        /* full validation happens in row_load (record + both manifests) */
        if (row_load(w, id, &recs[n], NULL, NULL, NULL) != 0) {
            out_rc = -1;
            break;
        }
        n++;
    }
    if (out_rc == 0 && rc != SQLITE_DONE) out_rc = -1;
    sqlite3_finalize(st);

    if (out_rc == 0)
        out_rc = dna_domreg_root(recs, n, out);
    free(recs);
    return out_rc;
}

/* ── Genesis / registration ─────────────────────────────────────────── */

/* Build the initial manifest for one builtin runtime entry.
 * `genesis_payload_root` is the domain's RUNTIME-OWNED genesis payload
 * root (S5 cycle break — see dna_v2_system_payload_root): for SYSTEM the
 * five-leg payload root (native supply is a CORE commitment, not a
 * SYSTEM leg), for DNA_CORE the full core_state_root (no self-reference
 * exists, so its payload IS its state root). */
static void manifest_from_runtime(const nodus_domain_runtime_t *rt,
                                  const uint8_t genesis_payload_root[64],
                                  dna_domain_manifest_t *m) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = DNA_DOMMAN_VERSION;
    m->domain_id = rt->domain_id;
    memcpy(m->name, rt->descriptor.name, DNA_DOM_NAME_LEN);
    m->runtime_kind = rt->runtime_kind;
    m->runtime_abi = rt->runtime_abi;
    m->ruleset_version = rt->ruleset_version;
    memcpy(m->ruleset_hash, rt->ruleset_hash, DNA_DOM_HASH_LEN);
    memcpy(m->genesis_state_root, genesis_payload_root, DNA_DOM_HASH_LEN);
    m->tx_type_count = rt->descriptor.tx_type_count;
    memcpy(m->tx_types, rt->descriptor.tx_types,
           rt->descriptor.tx_type_count);
    m->fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m->quota_tx_per_block = 0;
    m->quota_verify_cost = 0;
    m->upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m->activation_epoch = 0;
    m->readiness_policy = DNA_RDYPOL_STAGED_V1;
}

int nodus_witness_domreg_init_genesis(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    if (nodus_witness_runtime_selfcheck() != 0) return -1;

    size_t n = 0;
    const nodus_domain_runtime_t *table = nodus_runtime_builtin_table(&n);
    if (!table || n != 2) return -1;

    /* S7: activation-time domain-state initialization runs FIRST —
     * inside the caller's genesis transaction, BEFORE the payload
     * roots below are evaluated and committed — so the registry's
     * genesis_state_root and the head_activate comparison see the
     * SAME initialized state (the CORE hook creates its configured
     * native shielded pool; the hook is idempotent-or-conflict, so
     * head_activate calling it again inside this transaction is a
     * no-op). Generic dispatch — no domain branch. */
    for (size_t i = 0; i < n; i++)
        if (table[i].state_init &&
            table[i].state_init(&table[i], (struct nodus_witness *)w, 0)
                != 0)
            return -1;

    /* Real genesis payload roots (S5 cycle break) — computed BEFORE any
     * registry row exists, from the runtime-owned state only. */
    uint8_t sys_payload[64], core_payload[64];
    if (nodus_witness_system_payload_root_v2(w, sys_payload) != 0) return -1;
    if (nodus_witness_core_root_v2(w, core_payload) != 0) return -1;

    for (size_t i = 0; i < n; i++) {
        dna_domain_manifest_t m;
        manifest_from_runtime(&table[i],
                              table[i].domain_id == DNA_DOMAIN_SYSTEM
                                  ? sys_payload : core_payload,
                              &m);

        dna_domreg_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.record_version = DNA_DOMREG_REC_VERSION;
        rec.domain_id = m.domain_id;
        rec.status = DNA_DOMST_ACTIVE;
        if (dna_domman_hash(&m, rec.current_manifest_hash) != 0) return -1;

        /* Idempotent-or-conflict, the vset_insert discipline. */
        dna_domreg_record_t old;
        int rc = row_load(w, m.domain_id, &old, NULL, NULL, NULL);
        if (rc == 0) {
            uint8_t a[DNA_DOMREG_REC_ENC_LEN], b[DNA_DOMREG_REC_ENC_LEN];
            if (dna_domreg_record_encode(&old, a) != 0 ||
                dna_domreg_record_encode(&rec, b) != 0)
                return -1;
            if (memcmp(a, b, sizeof(a)) != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "genesis registry CONFLICT for domain %u",
                              m.domain_id);
                return -2;
            }
            continue;                            /* byte-identical no-op   */
        }
        if (rc != 1) return -1;
        if (row_store(w, &rec, &m, NULL) != 0) return -1;
    }
    return 0;
}

int nodus_witness_domreg_op_register(nodus_witness_t *w,
                                     const dna_domain_manifest_t *m) {
    if (!w || !w->db || dna_domman_validate(m) != 0) return -1;

    dna_domreg_record_t existing;
    int rc = row_load(w, m->domain_id, &existing, NULL, NULL, NULL);
    if (rc == 0) return -1;                      /* already registered     */
    if (rc != 1) return -1;

    uint8_t used[256];
    if (owned_types_collect(w, m->domain_id, used) != 0) return -1;
    if (types_collide(m, used)) return -1;       /* one type, one owner    */

    dna_domreg_record_t rec;
    memset(&rec, 0, sizeof(rec));
    rec.record_version = DNA_DOMREG_REC_VERSION;
    rec.domain_id = m->domain_id;
    rec.status = DNA_DOMST_REGISTERED;
    if (dna_domman_hash(m, rec.current_manifest_hash) != 0) return -1;
    return row_store(w, &rec, m, NULL);
}

/* ── Proposal / readiness / scheduling ──────────────────────────────── */

int nodus_witness_domreg_op_propose(nodus_witness_t *w,
                                    const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                    uint32_t domain_id,
                                    const dna_domain_manifest_t *target,
                                    uint64_t proposal_nonce,
                                    uint64_t proposed_at_epoch) {
    if (!w || !w->db || !chain_id) return -1;

    dna_domreg_record_t rec;
    dna_domain_manifest_t cur;
    if (row_load(w, domain_id, &rec, &cur, NULL, NULL) != 0) return -1;

    const dna_domain_manifest_t *tgt = NULL;
    dna_domain_manifest_t pend;
    int with_pending = 0;

    if (rec.status == DNA_DOMST_REGISTERED) {
        if (target != NULL) return -1;   /* initial proposal = current    */
        tgt = &cur;
    } else if (rec.status == DNA_DOMST_ACTIVE) {
        if (dna_domman_validate(target) != 0) return -1;
        if (target->domain_id != domain_id) return -1;
        uint8_t th[DNA_DOM_HASH_LEN];
        if (dna_domman_hash(target, th) != 0) return -1;
        if (memcmp(th, rec.current_manifest_hash, DNA_DOM_HASH_LEN) == 0)
            return -1;                   /* upgrade must change something */
        uint8_t used[256];
        if (owned_types_collect(w, domain_id, used) != 0) return -1;
        if (types_collide(target, used)) return -1;
        pend = *target;
        tgt = &pend;
        with_pending = 1;
    } else {
        return -1;                       /* SCHEDULED/PAUSED/RETIRED: no  */
    }

    /* Replacing a live proposal kills the old signals first. */
    if (rec.proposal_present &&
        signals_delete(w, rec.proposal_digest) != 0)
        return -1;

    uint8_t th[DNA_DOM_HASH_LEN];
    if (dna_domman_hash(tgt, th) != 0) return -1;
    if (dna_domprop_digest(chain_id, domain_id, th, proposal_nonce,
                           proposed_at_epoch, rec.proposal_digest) != 0)
        return -1;
    rec.proposal_present = 1;
    rec.pending_present = (uint8_t)with_pending;
    if (with_pending)
        memcpy(rec.pending_manifest_hash, th, DNA_DOM_HASH_LEN);
    else
        memset(rec.pending_manifest_hash, 0, DNA_DOM_HASH_LEN);
    rec.scheduled_activation_epoch = 0;
    rec.readiness_deadline_epoch = 0;
    rec.postpone_count = 0;

    return row_store(w, &rec, &cur, with_pending ? &pend : NULL);
}

int nodus_witness_domreg_op_signal(nodus_witness_t *w,
                                   const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN],
                                   const dna_readiness_signal_t *sig,
                                   const dna_vset_snapshot_t *snap) {
    if (!w || !w->db || !expected_chain_id || !sig || !snap) return -1;
    if (memcmp(sig->chain_id, expected_chain_id, DNA_CHAIN_ID_LEN) != 0)
        return -1;                                       /* wrong chain    */

    dna_domreg_record_t rec;
    dna_domain_manifest_t cur, pend;
    int hp = 0;
    if (row_load(w, sig->domain_id, &rec, &cur, &pend, &hp) != 0)
        return -1;                                       /* wrong domain   */
    if (!rec.proposal_present ||
        memcmp(rec.proposal_digest, sig->proposal_digest,
               DNA_DOM_HASH_LEN) != 0)
        return -1;                       /* wrong/stale/cancelled proposal */

    const dna_domain_manifest_t *tgt = hp ? &pend : &cur;
    if (sig->runtime_kind != tgt->runtime_kind ||
        sig->runtime_abi != tgt->runtime_abi ||
        sig->ruleset_version != tgt->ruleset_version ||
        memcmp(sig->ruleset_hash, tgt->ruleset_hash, DNA_DOM_HASH_LEN) != 0)
        return -1;                       /* tuple must match EXACTLY       */

    if (sig->signal_epoch != snap->epoch) return -1;     /* freshness      */

    int mi = member_index(snap, sig->voter_id);
    if (mi < 0) return -1;                               /* not a member   */

    uint8_t pre[DNA_DOMRDY_PREIMAGE_LEN];
    if (dna_domrdy_preimage(sig, pre) != 0) return -1;
    if (qgp_dsa87_verify(sig->signature, DNA_DOM_SIG_LEN,
                         pre, sizeof(pre),
                         snap->entries[mi].pubkey) != 0)
        return -1;                                       /* bad signature  */

    uint8_t wire[DNA_DOMRDY_WIRE_LEN];
    if (dna_domrdy_encode(sig, wire) != 0) return -1;

    /* Deterministic duplicate handling: identical re-submission = no-op;
     * a different signal under the same key = first-wins conflict. */
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT signal FROM domain_readiness "
        "WHERE proposal_digest = ?1 AND voter_id = ?2", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, sig->proposal_digest, DNA_DOM_HASH_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, sig->voter_id, DNA_DOM_VOTER_ID_LEN,
                      SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const void *old = sqlite3_column_blob(st, 0);
        int ol = sqlite3_column_bytes(st, 0);
        int same = (old && ol == (int)sizeof(wire) &&
                    memcmp(old, wire, sizeof(wire)) == 0);
        sqlite3_finalize(st);
        return same ? 0 : -2;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;

    rc = sqlite3_prepare_v2(w->db,
        "INSERT INTO domain_readiness (proposal_digest, voter_id, signal) "
        "VALUES (?1, ?2, ?3)", -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, sig->proposal_digest, DNA_DOM_HASH_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, sig->voter_id, DNA_DOM_VOTER_ID_LEN,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, wire, sizeof(wire), SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int nodus_witness_domreg_readiness_count(nodus_witness_t *w,
                                         const uint8_t proposal_digest[DNA_DOM_HASH_LEN],
                                         const dna_vset_snapshot_t *snap,
                                         uint32_t *count_out) {
    if (!w || !w->db || !proposal_digest || !snap || !count_out) return -1;
    uint32_t count = 0;
    for (uint16_t i = 0; i < snap->active_count; i++) {
        int rc = signal_exists(w, proposal_digest,
                               snap->entries[i].voter_id);
        if (rc < 0) return -1;
        count += (uint32_t)rc;       /* one member, one vote — never stake */
    }
    *count_out = count;
    return 0;
}

int nodus_witness_domreg_op_schedule(nodus_witness_t *w,
                                     uint32_t domain_id,
                                     const uint8_t proposal_digest[DNA_DOM_HASH_LEN],
                                     uint64_t sched_epoch_start,
                                     uint64_t activation_epoch,
                                     const dna_vset_snapshot_t *snap) {
    if (!w || !w->db || !proposal_digest || !snap) return -1;
    if (sched_epoch_start % EPOCH_LEN != 0 ||
        activation_epoch % EPOCH_LEN != 0)
        return -1;
    /* Two-epoch readiness deadline; activation never precedes it. */
    uint64_t deadline = sched_epoch_start + 2 * EPOCH_LEN;
    if (deadline < sched_epoch_start) return -1;         /* overflow       */
    if (activation_epoch < deadline) return -1;

    dna_domreg_record_t rec;
    dna_domain_manifest_t cur, pend;
    int hp = 0;
    if (row_load(w, domain_id, &rec, &cur, &pend, &hp) != 0) return -1;
    if (!rec.proposal_present ||
        memcmp(rec.proposal_digest, proposal_digest, DNA_DOM_HASH_LEN) != 0)
        return -1;
    if (rec.scheduled_activation_epoch != 0) return -1;  /* already set    */
    if (rec.status != DNA_DOMST_REGISTERED &&
        rec.status != DNA_DOMST_ACTIVE)
        return -1;

    uint32_t ready = 0;
    if (nodus_witness_domreg_readiness_count(w, proposal_digest, snap,
                                             &ready) != 0)
        return -1;
    if (ready < dna_bft_quorum(snap->active_count))
        return -1;                       /* quorum SCHEDULES, nothing less */

    if (rec.status == DNA_DOMST_REGISTERED)
        rec.status = DNA_DOMST_SCHEDULED;
    rec.scheduled_activation_epoch = activation_epoch;
    rec.readiness_deadline_epoch = deadline;
    rec.postpone_count = 0;
    return row_store(w, &rec, &cur, hp ? &pend : NULL);
}

int nodus_witness_domreg_op_cancel(nodus_witness_t *w, uint32_t domain_id,
                                   const uint8_t proposal_digest[DNA_DOM_HASH_LEN]) {
    if (!w || !w->db || !proposal_digest) return -1;

    dna_domreg_record_t rec;
    dna_domain_manifest_t cur;
    if (row_load(w, domain_id, &rec, &cur, NULL, NULL) != 0) return -1;
    if (!rec.proposal_present ||
        memcmp(rec.proposal_digest, proposal_digest, DNA_DOM_HASH_LEN) != 0)
        return -1;

    if (signals_delete(w, rec.proposal_digest) != 0) return -1;

    if (rec.status == DNA_DOMST_SCHEDULED)
        rec.status = DNA_DOMST_REGISTERED;
    rec.proposal_present = 0;
    memset(rec.proposal_digest, 0, DNA_DOM_HASH_LEN);
    rec.pending_present = 0;
    memset(rec.pending_manifest_hash, 0, DNA_DOM_HASH_LEN);
    rec.scheduled_activation_epoch = 0;
    rec.readiness_deadline_epoch = 0;
    rec.postpone_count = 0;
    return row_store(w, &rec, &cur, NULL);
}

static int lifecycle_flip(nodus_witness_t *w, uint32_t domain_id,
                          uint8_t from, uint8_t to) {
    dna_domreg_record_t rec;
    dna_domain_manifest_t cur;
    if (row_load(w, domain_id, &rec, &cur, NULL, NULL) != 0) return -1;
    if (rec.proposal_present) return -1;     /* cancel first               */
    if (from != 0 && rec.status != from) return -1;
    if (from == 0 && rec.status == DNA_DOMST_RETIRED) return -1;
    rec.status = to;
    return row_store(w, &rec, &cur, NULL);
}

int nodus_witness_domreg_op_pause(nodus_witness_t *w, uint32_t domain_id) {
    return lifecycle_flip(w, domain_id, DNA_DOMST_ACTIVE, DNA_DOMST_PAUSED);
}
int nodus_witness_domreg_op_resume(nodus_witness_t *w, uint32_t domain_id) {
    return lifecycle_flip(w, domain_id, DNA_DOMST_PAUSED, DNA_DOMST_ACTIVE);
}
int nodus_witness_domreg_op_retire(nodus_witness_t *w, uint32_t domain_id) {
    return lifecycle_flip(w, domain_id, 0, DNA_DOMST_RETIRED);
}

/* ── Stage C — exclusions ───────────────────────────────────────────── */

int nodus_witness_domreg_exclusions_at(nodus_witness_t *w,
                                       uint64_t deadline_epoch_start,
                                       const dna_vset_snapshot_t *candidate,
                                       uint16_t min_count,
                                       uint8_t (*excl_out)[DNA_DOM_VOTER_ID_LEN],
                                       size_t cap, size_t *n_out) {
    if (!w || !w->db || !candidate || !excl_out || !n_out) return -1;
    *n_out = 0;

    /* Collect the deadline-bearing proposals (deterministic id order). */
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT domain_id FROM domain_registry ORDER BY domain_id ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    uint32_t ids[64];
    size_t n_ids = 0;
    int out = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n_ids >= sizeof(ids) / sizeof(ids[0])) { out = -1; break; }
        ids[n_ids++] = (uint32_t)sqlite3_column_int64(st, 0);
    }
    if (out == 0 && rc != SQLITE_DONE) out = -1;
    sqlite3_finalize(st);
    if (out != 0) return -1;

    /* A candidate member is unready if ANY deadline-bearing proposal has
     * no stored signal from it. Candidate order — deterministic. */
    size_t n_excl = 0;
    for (uint16_t i = 0; i < candidate->active_count; i++) {
        int unready = 0;
        for (size_t d = 0; d < n_ids && !unready; d++) {
            dna_domreg_record_t rec;
            if (row_load(w, ids[d], &rec, NULL, NULL, NULL) != 0)
                return -1;
            if (!rec.proposal_present ||
                rec.readiness_deadline_epoch != deadline_epoch_start)
                continue;
            int has = signal_exists(w, rec.proposal_digest,
                                    candidate->entries[i].voter_id);
            if (has < 0) return -1;
            if (has == 0) unready = 1;
        }
        if (unready) {
            if (n_excl >= cap) return -1;
            memcpy(excl_out[n_excl++], candidate->entries[i].voter_id,
                   DNA_DOM_VOTER_ID_LEN);
        }
    }

    /* Floor guard: shrinking below the configured minimum never happens —
     * the old rules continue and activation keeps postponing instead. */
    if (n_excl > 0 &&
        (size_t)candidate->active_count - n_excl < (size_t)min_count)
        return 2;
    *n_out = n_excl;
    return 0;
}

dna_vset_snapshot_t *
nodus_witness_domreg_filter_snapshot(const dna_vset_snapshot_t *in,
                                     const uint8_t (*excl)[DNA_DOM_VOTER_ID_LEN],
                                     size_t n_excl) {
    if (!in || (n_excl > 0 && !excl)) return NULL;
    if (n_excl >= in->active_count) return NULL;    /* never empties a set */

    uint16_t kept = 0;
    dna_vset_snapshot_t *out =
        dna_vset_alloc((uint16_t)(in->active_count - (uint16_t)n_excl));
    if (!out) return NULL;
    out->epoch = in->epoch;
    out->selection_ruleset = in->selection_ruleset;
    memcpy(out->sortition_seed, in->sortition_seed, DNA_VSET_SEED_LEN);

    for (uint16_t i = 0; i < in->active_count; i++) {
        int drop = 0;
        for (size_t e = 0; e < n_excl && !drop; e++)
            if (memcmp(in->entries[i].voter_id, excl[e],
                       DNA_DOM_VOTER_ID_LEN) == 0)
                drop = 1;
        if (drop) continue;
        if (kept >= out->active_count) { dna_vset_free(&out); return NULL; }
        out->entries[kept++] = in->entries[i];
    }
    if (kept != out->active_count) { dna_vset_free(&out); return NULL; }
    return out;
}

/* ── Stage D/E — boundary progression ───────────────────────────────── */

int nodus_witness_domreg_on_boundary(nodus_witness_t *w,
                                     uint64_t boundary_epoch_start,
                                     const dna_vset_snapshot_t *snap_now,
                                     const dna_vset_snapshot_t *snap_prev,
                                     uint32_t *activated_out,
                                     uint32_t *postponed_out) {
    if (!w || !w->db || !snap_now || !snap_prev) return -1;
    /* Historical-snapshot AUTHORITY pin: the caller must hand exactly the
     * snapshot governing this boundary and its predecessor — a current-set
     * substitution is structurally rejected, never silently accepted. */
    if (boundary_epoch_start % EPOCH_LEN != 0) return -1;
    if (snap_now->epoch != boundary_epoch_start) return -1;
    if (snap_prev->epoch + EPOCH_LEN != boundary_epoch_start) return -1;
    if (activated_out) *activated_out = 0;
    if (postponed_out) *postponed_out = 0;

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT domain_id FROM domain_registry ORDER BY domain_id ASC",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    uint32_t ids[64];
    size_t n_ids = 0;
    int out = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n_ids >= sizeof(ids) / sizeof(ids[0])) { out = -1; break; }
        ids[n_ids++] = (uint32_t)sqlite3_column_int64(st, 0);
    }
    if (out == 0 && rc != SQLITE_DONE) out = -1;
    sqlite3_finalize(st);
    if (out != 0) return -1;

    for (size_t d = 0; d < n_ids; d++) {
        dna_domreg_record_t rec;
        dna_domain_manifest_t cur, pend;
        int hp = 0;
        if (row_load(w, ids[d], &rec, &cur, &pend, &hp) != 0) return -1;
        if (!rec.proposal_present ||
            rec.scheduled_activation_epoch != boundary_epoch_start)
            continue;

        /* Stage E precheck: ALL-ACTIVE readiness (quorum is not enough)… */
        int all_ready = 1;
        for (uint16_t i = 0; i < snap_now->active_count && all_ready; i++) {
            int has = signal_exists(w, rec.proposal_digest,
                                    snap_now->entries[i].voter_id);
            if (has < 0) return -1;
            if (has == 0) all_ready = 0;
        }
        /* …and Stage D separation: no set change on this boundary. */
        int same_set = membership_equal(snap_now, snap_prev);

        if (all_ready && same_set) {
            /* ACTIVATE — one atomic row rewrite. */
            uint8_t digest[DNA_DOM_HASH_LEN];
            memcpy(digest, rec.proposal_digest, DNA_DOM_HASH_LEN);

            if (hp) {                                    /* upgrade        */
                memcpy(rec.current_manifest_hash, rec.pending_manifest_hash,
                       DNA_DOM_HASH_LEN);
                cur = pend;
            } else if (rec.status == DNA_DOMST_SCHEDULED) {
                rec.status = DNA_DOMST_ACTIVE;           /* initial        */
            } else {
                return -1;              /* proposal with nothing to do    */
            }
            rec.proposal_present = 0;
            memset(rec.proposal_digest, 0, DNA_DOM_HASH_LEN);
            rec.pending_present = 0;
            memset(rec.pending_manifest_hash, 0, DNA_DOM_HASH_LEN);
            rec.scheduled_activation_epoch = 0;
            rec.readiness_deadline_epoch = 0;
            rec.postpone_count = 0;
            if (row_store(w, &rec, &cur, NULL) != 0) return -1;
            if (signals_delete(w, digest) != 0) return -1;
            if (activated_out) (*activated_out)++;
        } else {
            /* POSTPONE by exactly one epoch. */
            uint64_t next = rec.scheduled_activation_epoch + EPOCH_LEN;
            if (next < rec.scheduled_activation_epoch) return -1;
            rec.scheduled_activation_epoch = next;
            rec.postpone_count += 1;
            if (row_store(w, &rec, &cur, hp ? &pend : NULL) != 0)
                return -1;
            if (postponed_out) (*postponed_out)++;
        }
    }
    return 0;
}

/* ── V2 semantic admission routing ──────────────────────────────────── */

int nodus_witness_domreg_admit_v2(nodus_witness_t *w,
                                  const uint8_t expected_chain_id[DNA_CHAIN_ID_LEN],
                                  const dna_exec_context_t *ctx,
                                  uint32_t used_tx_count,
                                  uint32_t used_verify_cost,
                                  uint32_t *cost_out) {
    if (!w || !w->db || !expected_chain_id || !ctx) return -1;

    /* 1-2. structural validity + chain binding */
    if (dna_exec_context_validate(ctx) != 0) return -1;
    if (memcmp(ctx->chain_id, expected_chain_id, DNA_CHAIN_ID_LEN) != 0)
        return -1;

    /* 3-4. domain exists and is ACTIVE */
    dna_domreg_record_t rec;
    dna_domain_manifest_t cur;
    if (row_load(w, ctx->domain_id, &rec, &cur, NULL, NULL) != 0) return -1;
    if (rec.status != DNA_DOMST_ACTIVE) return -1;

    /* 5. the context's ruleset must be the ACTIVE one — exactly */
    if (ctx->ruleset_version != cur.ruleset_version) return -1;

    /* 6. exact local runtime support (fail-closed: no runtime, no tx) */
    const nodus_domain_runtime_t *rt =
        nodus_runtime_lookup(cur.domain_id, cur.runtime_kind,
                             cur.runtime_abi, cur.ruleset_version,
                             cur.ruleset_hash);
    if (!rt) return -1;

    /* 7. type ownership (unique by registration — one type, one owner) */
    if (dna_domman_owns_type(&cur, ctx->tx_type) != 0) return -1;

    /* 8. statement_version is reserved for proof-bearing types; none is
     * admissible in S4 (type 11 rejects below), so nonzero always fails. */
    if (ctx->statement_version != 0) return -1;

    /* 9. runtime-level admission: pool legality + the C3 type-11 stop */
    if (rt->admit(rt, ctx->tx_type, ctx->pool_id) != 0) return -1;

    /* 10. quotas (0 = bounded only by the global block caps) */
    uint32_t cost = 0;
    if (rt->tx_cost(rt, ctx->tx_type, &cost) != 0) return -1;
    if (cur.quota_tx_per_block != 0 &&
        used_tx_count + 1 > (uint32_t)cur.quota_tx_per_block)
        return -1;
    if (cur.quota_verify_cost != 0) {
        uint64_t total = (uint64_t)used_verify_cost + (uint64_t)cost;
        if (total > (uint64_t)cur.quota_verify_cost) return -1;
    }

    if (cost_out) *cost_out = cost;
    return 0;
}

/* ── Signal builder ─────────────────────────────────────────────────── */

int nodus_witness_domreg_build_signal(nodus_witness_t *w,
                                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                      uint32_t domain_id,
                                      uint64_t snap_epoch,
                                      const uint8_t voter_id[DNA_DOM_VOTER_ID_LEN],
                                      const uint8_t *secret_key,
                                      dna_readiness_signal_t *out) {
    if (!w || !w->db || !chain_id || !voter_id || !secret_key || !out)
        return -1;

    dna_domreg_record_t rec;
    dna_domain_manifest_t cur, pend;
    int hp = 0;
    if (row_load(w, domain_id, &rec, &cur, &pend, &hp) != 0) return -1;
    if (!rec.proposal_present) return -1;
    const dna_domain_manifest_t *tgt = hp ? &pend : &cur;

    /* THE LOCAL-SUPPORT GATE: no exact compiled runtime, no signal. */
    if (nodus_runtime_lookup(tgt->domain_id, tgt->runtime_kind,
                             tgt->runtime_abi, tgt->ruleset_version,
                             tgt->ruleset_hash) == NULL) {
        QGP_LOG_WARN(LOG_TAG,
                     "refusing readiness for domain %u: no exact local "
                     "runtime for the proposed tuple", domain_id);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->msg_version = DNA_DOMRDY_MSG_VERSION;
    memcpy(out->chain_id, chain_id, DNA_CHAIN_ID_LEN);
    memcpy(out->voter_id, voter_id, DNA_DOM_VOTER_ID_LEN);
    out->domain_id = domain_id;
    out->runtime_kind = tgt->runtime_kind;
    out->runtime_abi = tgt->runtime_abi;
    out->ruleset_version = tgt->ruleset_version;
    memcpy(out->ruleset_hash, tgt->ruleset_hash, DNA_DOM_HASH_LEN);
    memcpy(out->proposal_digest, rec.proposal_digest, DNA_DOM_HASH_LEN);
    out->signal_epoch = snap_epoch;

    uint8_t pre[DNA_DOMRDY_PREIMAGE_LEN];
    if (dna_domrdy_preimage(out, pre) != 0) return -1;
    size_t siglen = 0;
    if (qgp_dsa87_sign(out->signature, &siglen, pre, sizeof(pre),
                       secret_key) != 0)
        return -1;
    if (siglen != DNA_DOM_SIG_LEN) return -1;
    return 0;
}
