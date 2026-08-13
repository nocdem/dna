/**
 * Nodus — Ledger V2 execution-season SHARED TEST FIXTURE (test-only).
 *
 * Provides what every engine-level test of the typed execution path
 * needs:
 *
 *   - SCRIPTED test runtimes: builtin-copied SYSTEM/CORE entries (same
 *     five-axis tuple, so the registry manifests the genesis committed
 *     still resolve them) extended with a deterministic read_plan/exec
 *     pair driven ENTIRELY by the envelope's call_data — the test
 *     writes the mediated-read request list and the exact canonical
 *     "DNA.EFFRES.v1" result bytes into call_data, so any effect shape
 *     (including malformed ones) is expressible from a test;
 *   - compiled TEST ADAPTERS over the same tables the retired raw-SQL
 *     ops used to mutate (utxo_set / supply_tracking / epoch_state /
 *     chain_config_history / domain_registry), probe+read+mutate, all
 *     scoped by the authoritative domain id they are handed;
 *   - envelope/call/effect builders.
 *
 * call_data layout (the "script"):
 *   [0..1]  n_reads u16 BE
 *   then n_reads × ( op_id u32 BE ‖ key_len u16 BE ‖ key bytes )
 *   then the canonical effect-result bytes, copied VERBATIM to the
 *   engine's result buffer by v2x_exec.
 *
 * Copyright (c) 2026 nocdem — SPDX-License-Identifier: MIT
 */

#ifndef NODUS_TESTS_V2_EXEC_FIXTURE_H
#define NODUS_TESTS_V2_EXEC_FIXTURE_H

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_v2_adapter.h"
#include "dnac/env_wire.h"
#include "dnac/effect_wire.h"
#include "crypto/hash/qgp_sha3.h"   /* v2x_auth pseudo-signer fp */

#include <sqlite3.h>
#include <stdint.h>
#include <string.h>

/* ── little BE helpers ─────────────────────────────────────────────── */
static void v2x_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static void v2x_put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t v2x_get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t v2x_get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static uint16_t v2x_get16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* ── generic SQL helpers (test-local, not engine code) ─────────────── */
static int v2x_q1(struct nodus_witness *wns, const char *sql,
                  uint64_t *out) {
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 1 : -1;
}

/* ── CORE test adapter: utxo_set + supply_tracking ─────────────────────
 * op 1 V2X_OP_UTXO   CREATE|SET over utxo_set rows: key = 64-byte
 *                    nullifier, value = 8-byte BE ABSOLUTE amount.
 *                    Probe facts: version = amount, value_hash over the
 *                    canonical 8-byte value.
 * op 2 V2X_OP_UTXDEL DELETE: key = nullifier, value empty.
 * op 3 V2X_OP_SUPPLY SET over the supply_tracking counters: key = 1
 *                    byte selector (1 = total_minted, 2 = total_burned),
 *                    value = 8-byte BE ABSOLUTE counter value.
 */
#define V2X_OP_UTXO   1u
#define V2X_OP_UTXDEL 2u
#define V2X_OP_SUPPLY 3u

static int v2x_utxo_row(struct nodus_witness *wns, uint32_t dom,
                        const uint8_t *key, uint16_t key_len,
                        int *exists, uint64_t *amount) {
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT amount FROM utxo_set WHERE nullifier=?1 AND "
            "domain_id=?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *exists = 1;
        *amount = (uint64_t)sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        return 0;
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) { *exists = 0; *amount = 0; return 0; }
    return -1;
}

static int v2x_supply_get(struct nodus_witness *wns, uint8_t sel,
                          int *exists, uint64_t *val) {
    const char *sql = sel == 1
        ? "SELECT total_minted FROM supply_tracking WHERE id=1"
        : "SELECT total_burned FROM supply_tracking WHERE id=1";
    uint64_t v = 0;
    int rc = v2x_q1(wns, sql, &v);
    if (rc < 0) return -1;
    *exists = (rc == 0);
    *val = v;
    return 0;
}

static nodus_adapter_status_t v2x_core_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad;
    int ex = 0;
    uint64_t val = 0;
    if (op->op_id == V2X_OP_UTXO || op->op_id == V2X_OP_UTXDEL) {
        if (v2x_utxo_row(w, dom, key, key_len, &ex, &val) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    } else if (op->op_id == V2X_OP_SUPPLY) {
        if (key_len != 1 || (key[0] != 1 && key[0] != 2))
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (v2x_supply_get(w, key[0], &ex, &val) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    f->exists = ex;
    if (ex) {
        uint8_t vb[8];
        v2x_put64(vb, val);
        f->version = val;
        if (dna_effect_value_hash(vb, 8, f->value_hash) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t v2x_core_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    nodus_adapter_row_facts_t f;
    memset(&f, 0, sizeof(f));
    nodus_adapter_status_t st = v2x_core_probe(ad, w, dom, op, key,
                                               key_len, &f);
    if (st != NODUS_ADAPTER_OK) return st;
    *present = f.exists;
    *vlen = 0;
    if (f.exists) {
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        v2x_put64(value, f.version);   /* the canonical 8-byte value */
        *vlen = 8;
    }
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t v2x_core_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    int rc = -1;
    if (op->op_id == V2X_OP_UTXO && kind == DNA_EFFECT_CREATE) {
        if (value_len != 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO utxo_set (nullifier, owner, amount, "
                "token_id, tx_hash, output_index, block_height, "
                "created_at, unlock_block, domain_id) VALUES (?1, 'fp', "
                "?2, zeroblob(64), zeroblob(63)||x'aa', 0, 1, 0, 0, ?3)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)v2x_get64(value));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)dom);
    } else if (op->op_id == V2X_OP_UTXO && kind == DNA_EFFECT_SET) {
        if (value_len != 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE utxo_set SET amount=?2 WHERE nullifier=?1 AND "
                "domain_id=?3", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)v2x_get64(value));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)dom);
    } else if (op->op_id == V2X_OP_UTXDEL && kind == DNA_EFFECT_DELETE) {
        if (sqlite3_prepare_v2(w->db,
                "DELETE FROM utxo_set WHERE nullifier=?1 AND "
                "domain_id=?2", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_blob(st, 1, key, key_len, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    } else if (op->op_id == V2X_OP_SUPPLY && kind == DNA_EFFECT_SET) {
        if (key_len != 1 || value_len != 8)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        const char *sql = key[0] == 1
            ? "UPDATE supply_tracking SET total_minted=?1 WHERE id=1"
            : "UPDATE supply_tracking SET total_burned=?1 WHERE id=1";
        if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get64(value));
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? NODUS_ADAPTER_OK
                             : NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static const nodus_adapter_op_t V2X_CORE_OPS[3] = {
    { V2X_OP_UTXO,
      (uint8_t)(NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE) |
                NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET)),
      NODUS_ADAPTER_PRECONDS_ALL, 64, 64, 8, 8 },
    { V2X_OP_UTXDEL,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_DELETE),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VHASH)),
      64, 64, 0, 0 },
    { V2X_OP_SUPPLY,
      NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION)),
      1, 1, 8, 8 }
};

static const nodus_domain_adapter_t V2X_CORE_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = V2X_CORE_OPS,
    .n_ops = 3,
    .probe = v2x_core_probe,
    .mutate = v2x_core_mutate,
    .read = v2x_core_read
};

/* ── SYSTEM test adapter: chain_config_history + epoch_state +
 *    domain_registry ──────────────────────────────────────────────────
 * op 1 V2X_OP_CC     CREATE: key = param_id u32 BE ‖ effective_block
 *                    u64 BE (12 bytes), value = new_value u64 BE.
 * op 2 V2X_OP_EPOCH  SET: key = epoch_start_height u64 BE, value =
 *                    ABSOLUTE epoch_pool_accum u64 BE.
 * op 3 V2X_OP_DOMREG SET: key = domain_id u32 BE, value = the encoded
 *                    DNA_DOMREG_REC_ENC_LEN registry record.
 */
#define V2X_OP_CC     1u
#define V2X_OP_EPOCH  2u
#define V2X_OP_DOMREG 3u

static nodus_adapter_status_t v2x_sys_probe(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        nodus_adapter_row_facts_t *f) {
    (void)ad; (void)dom;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (op->op_id == V2X_OP_CC) {
        if (key_len != 12) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "SELECT new_value FROM chain_config_history WHERE "
                "param_id=?1 AND effective_block=?2", -1, &st, NULL)
            != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get32(key));
        sqlite3_bind_int64(st, 2, (sqlite3_int64)v2x_get64(key + 4));
    } else if (op->op_id == V2X_OP_EPOCH) {
        if (key_len != 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "SELECT epoch_pool_accum FROM epoch_state WHERE "
                "epoch_start_height=?1", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get64(key));
    } else if (op->op_id == V2X_OP_DOMREG) {
        if (key_len != 4) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "SELECT 0 FROM domain_registry WHERE domain_id=?1",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get32(key));
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        f->exists = 1;
        f->version = (uint64_t)sqlite3_column_int64(st, 0);
        uint8_t vb[8];
        v2x_put64(vb, f->version);
        sqlite3_finalize(st);
        if (dna_effect_value_hash(vb, 8, f->value_hash) != 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        return NODUS_ADAPTER_OK;
    }
    sqlite3_finalize(st);
    if (rc == SQLITE_DONE) { f->exists = 0; return NODUS_ADAPTER_OK; }
    return NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static nodus_adapter_status_t v2x_sys_read(
        const nodus_domain_adapter_t *ad, struct nodus_witness *w,
        uint32_t dom, const nodus_adapter_op_t *op,
        const uint8_t *key, uint16_t key_len,
        int *present, uint8_t *value, uint32_t cap, uint32_t *vlen) {
    nodus_adapter_row_facts_t f;
    memset(&f, 0, sizeof(f));
    nodus_adapter_status_t st = v2x_sys_probe(ad, w, dom, op, key,
                                              key_len, &f);
    if (st != NODUS_ADAPTER_OK) return st;
    *present = f.exists;
    *vlen = 0;
    if (f.exists) {
        if (cap < 8) return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        v2x_put64(value, f.version);
        *vlen = 8;
    }
    return NODUS_ADAPTER_OK;
}

static nodus_adapter_status_t v2x_sys_mutate(
        const nodus_domain_adapter_t *ad, struct nodus_witness *wns,
        uint32_t dom, const nodus_adapter_op_t *op, uint8_t kind,
        const uint8_t *key, uint16_t key_len,
        const uint8_t *value, uint32_t value_len) {
    (void)ad; (void)dom; (void)kind;
    nodus_witness_t *w = (nodus_witness_t *)wns;
    sqlite3_stmt *st = NULL;
    if (op->op_id == V2X_OP_CC) {
        if (key_len != 12 || value_len != 8)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO chain_config_history (param_id, new_value, "
                "effective_block, commit_block, tx_hash, proposal_nonce, "
                "created_at_unix) VALUES (?1, ?2, ?3, 1, x'cc', ?4, 0)",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get32(key));
        sqlite3_bind_int64(st, 2, (sqlite3_int64)v2x_get64(value));
        sqlite3_bind_int64(st, 3, (sqlite3_int64)v2x_get64(key + 4));
        sqlite3_bind_int64(st, 4,
                           (sqlite3_int64)(v2x_get64(key + 4) & 0xffffff));
    } else if (op->op_id == V2X_OP_EPOCH) {
        if (key_len != 8 || value_len != 8)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE epoch_state SET epoch_pool_accum=?2 WHERE "
                "epoch_start_height=?1", -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get64(key));
        sqlite3_bind_int64(st, 2, (sqlite3_int64)v2x_get64(value));
    } else if (op->op_id == V2X_OP_DOMREG) {
        if (key_len != 4 || value_len == 0)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        if (sqlite3_prepare_v2(w->db,
                "UPDATE domain_registry SET record=?2 WHERE domain_id=?1",
                -1, &st, NULL) != SQLITE_OK)
            return NODUS_ADAPTER_ERR_STORAGE_FAULT;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)v2x_get32(key));
        sqlite3_bind_blob(st, 2, value, (int)value_len, SQLITE_TRANSIENT);
    } else {
        return NODUS_ADAPTER_ERR_STORAGE_FAULT;
    }
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? NODUS_ADAPTER_OK
                             : NODUS_ADAPTER_ERR_STORAGE_FAULT;
}

static const nodus_adapter_op_t V2X_SYS_OPS[3] = {
    { V2X_OP_CC, NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_CREATE),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_ABSENT), 12, 12, 8, 8 },
    { V2X_OP_EPOCH, NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      (uint8_t)(NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS) |
                NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS_VERSION)),
      8, 8, 8, 8 },
    { V2X_OP_DOMREG, NODUS_ADAPTER_KIND_BIT(DNA_EFFECT_SET),
      NODUS_ADAPTER_PRECOND_BIT(DNA_EFFECT_PRE_EXISTS),
      4, 4, 1, 256 }
};

static const nodus_domain_adapter_t V2X_SYS_ADAPTER = {
    .adapter_version = NODUS_DOMAIN_ADAPTER_V1,
    .ops = V2X_SYS_OPS,
    .n_ops = 3,
    .probe = v2x_sys_probe,
    .mutate = v2x_sys_mutate,
    .read = v2x_sys_read
};

/* ── scripted AUTH hook (native auth season) ─────────────────────────
 * The production entries now bind the REAL nodus_rt_auth_dsa87_v1; the
 * scripted table replaces it with a stub that accepts ANY non-empty
 * auth_data and reports one deterministic pseudo-signer (fp = SHA3-512
 * of the auth bytes), so the pre-auth-season scripted tests keep their
 * envelope shapes. Tests of the REAL boundary drive the builtin table
 * (test_v2_native.c), never this stub. */
static int v2x_auth(const nodus_domain_runtime_t *rt,
                    const dna_env_view_t *env, uint16_t leg,
                    const nodus_rt_exec_ctx_t *ctx,
                    nodus_rt_auth_verdict_t *out) {
    (void)rt; (void)ctx;
    memset(out, 0, sizeof(*out));
    if (leg >= env->leg_count || env->leg[leg].auth_len == 0) return -1;
    if (qgp_sha3_512(env->buf + env->auth_off[leg],
                     env->leg[leg].auth_len, out->signer_fp[0]) != 0)
        return -2;
    out->n_signers = 1;
    return 0;
}

/* ── the scripted read_plan / exec pair ────────────────────────────── */

/** Walk the call_data script's read section. @return 0 with *tail /
 *  *tail_len at the effect-result bytes, -1 on a malformed script. */
static int v2x_script_split(const uint8_t *call, uint32_t call_len,
                            nodus_rt_read_req_t *reqs, uint16_t max_reqs,
                            uint16_t *n_out,
                            const uint8_t **tail, size_t *tail_len) {
    if (!call || call_len < 2) return -1;
    uint16_t n = v2x_get16(call);
    size_t off = 2;
    if (n > max_reqs) return -1;
    for (uint16_t i = 0; i < n; i++) {
        if (off + 6 > call_len) return -1;
        uint32_t op = v2x_get32(call + off);
        uint16_t kl = v2x_get16(call + off + 4);
        off += 6;
        if (kl == 0 || kl > DNA_EFFECT_MAX_KEY_LEN) return -1;
        if (off + kl > call_len) return -1;
        if (reqs) {
            memset(&reqs[i], 0, sizeof(reqs[i]));
            reqs[i].op_id = op;
            reqs[i].key_len = kl;
            memcpy(reqs[i].key, call + off, kl);
        }
        off += kl;
    }
    *n_out = n;
    *tail = call + off;
    *tail_len = call_len - off;
    return 0;
}

static int v2x_read_plan(const nodus_domain_runtime_t *rt,
                         const dna_env_view_t *env, uint16_t leg,
                         const nodus_rt_exec_ctx_t *ctx,
                         nodus_rt_read_req_t *reqs, uint16_t max_reqs,
                         uint16_t *n_out) {
    (void)rt; (void)ctx;
    const uint8_t *call = env->buf + env->call_off[leg];
    const uint8_t *tail = NULL;
    size_t tl = 0;
    return v2x_script_split(call, env->leg[leg].call_len, reqs, max_reqs,
                            n_out, &tail, &tl);
}

static int v2x_exec(const nodus_domain_runtime_t *rt,
                    const dna_env_view_t *env, uint16_t leg,
                    const nodus_rt_exec_ctx_t *ctx,
                    const nodus_rt_read_res_t *reads, uint16_t n_reads,
                    uint8_t *res_out, size_t res_cap,
                    size_t *res_len_out) {
    (void)rt; (void)ctx; (void)reads; (void)n_reads;
    const uint8_t *call = env->buf + env->call_off[leg];
    const uint8_t *tail = NULL;
    size_t tl = 0;
    uint16_t nr = 0;
    if (v2x_script_split(call, env->leg[leg].call_len, NULL,
                         NODUS_RT_MAX_READS, &nr, &tail, &tl) != 0)
        return -1;
    if (tl > res_cap) return -1;
    memcpy(res_out, tail, tl);
    *res_len_out = tl;
    return 0;
}

/* ── scripted test runtime table (SYSTEM + CORE, builtin-copied) ─────
 * The five-axis tuples, descriptors, state_root/invariant/... hooks and
 * SYSTEM's committed meter policy all come from the builtin entries
 * VERBATIM (memcpy) — only the execution surface (read_plan / exec /
 * adapter) is added, which no identity commits. Genesis therefore
 * resolves the same registry manifests onto these entries. */
static nodus_domain_runtime_t g_v2x_table[2];

static int v2x_table_init(struct nodus_witness *wns) {
    nodus_witness_t *w = (nodus_witness_t *)wns;
    size_t n = 0;
    const nodus_domain_runtime_t *b = nodus_runtime_builtin_table(&n);
    if (!b || n != 2) return -1;
    memcpy(&g_v2x_table[0], &b[0], sizeof(b[0]));
    memcpy(&g_v2x_table[1], &b[1], sizeof(b[1]));
    g_v2x_table[0].auth = v2x_auth;
    g_v2x_table[0].read_plan = v2x_read_plan;
    g_v2x_table[0].exec = v2x_exec;
    g_v2x_table[0].adapter = &V2X_SYS_ADAPTER;
    g_v2x_table[1].auth = v2x_auth;
    g_v2x_table[1].read_plan = v2x_read_plan;
    g_v2x_table[1].exec = v2x_exec;
    g_v2x_table[1].adapter = &V2X_CORE_ADAPTER;
    w->v2_runtime_table = g_v2x_table;
    w->v2_runtime_table_n = 2;
    return 0;
}

/* ── envelope / call / effect builders ─────────────────────────────── */

/* Fixture envelope buffer — DELIBERATELY NOT DNA_ENV_MAX_TOTAL_LEN:
 * the capacity season grew the ceiling to 1 MiB, and sizing every
 * fixture envelope to it would put megabyte objects in test frames /
 * BSS ("avoid stack allocation proportional to the V2 maximum").
 * Fixture shapes are small; ceiling-boundary tests heap-allocate their
 * own buffers (test_v2_capacity.c). */
#define V2X_ENV_BUF_LEN 65536u

typedef struct {
    uint8_t bytes[V2X_ENV_BUF_LEN];
    size_t  len;
} v2x_env_t;

/** The compiled table's ruleset version for one domain (SYSTEM moved to
 *  v2 in the capacity season; a fixture envelope must name the version
 *  the genesis-committed registry manifest carries or die in preflight
 *  as ERR_CTX_VERSION). */
static uint32_t v2x_ruleset_version_for(uint32_t domain_id) {
    size_t n = 0;
    const nodus_domain_runtime_t *b = nodus_runtime_builtin_table(&n);
    for (size_t i = 0; b && i < n; i++)
        if (b[i].domain_id == domain_id) return b[i].ruleset_version;
    return 1;
}

typedef struct {
    uint32_t domain_id;
    uint32_t runtime_op;              /* must be OWNED by the ruleset  */
    const uint8_t *call;
    uint32_t call_len;
    uint32_t max_effects;
    uint32_t max_effect_bytes;
} v2x_leg_t;

/** Encode one envelope: expiry 0 (never), generous default ceiling,
 *  1-byte auth stub per leg (auth_kind 1). @return 0 / -1. */
static int v2x_env_build_ex(v2x_env_t *e, uint64_t ceiling,
                            uint64_t expiry, uint64_t fee,
                            const v2x_leg_t *legs, uint16_t n) {
    static const uint8_t auth_stub[1] = { 0xAA };
    dna_env_leg_in_t in[8];
    if (n > 8) return -1;
    memset(in, 0, sizeof(in));
    for (uint16_t i = 0; i < n; i++) {
        in[i].hdr.domain_id = legs[i].domain_id;
        in[i].hdr.runtime_op = legs[i].runtime_op;
        in[i].hdr.ruleset_version =
            v2x_ruleset_version_for(legs[i].domain_id);
        in[i].hdr.access_mode = DNA_ENV_ACCESS_INVOKE;
        in[i].hdr.auth_kind = 1;
        in[i].hdr.call_len = legs[i].call_len;
        in[i].hdr.auth_len = 1;
        in[i].hdr.res_max_effects = legs[i].max_effects;
        in[i].hdr.res_max_effect_bytes = legs[i].max_effect_bytes;
        in[i].call_data = legs[i].call;
        in[i].auth_data = auth_stub;
    }
    dna_env_in_t env;
    memset(&env, 0, sizeof(env));
    env.expiry_height = expiry;
    env.fee_amount = fee;
    env.res_max_total_units = ceiling;
    env.leg_count = n;
    env.legs = in;
    return dna_env_encode(&env, e->bytes, sizeof(e->bytes), &e->len);
}

static int v2x_env_build(v2x_env_t *e, const v2x_leg_t *legs, uint16_t n) {
    return v2x_env_build_ex(e, 200000, 0, 0, legs, n);
}

/** Build a script: read section + verbatim effect-result tail.
 *  reads may be NULL/0. @return total length or 0 on overflow. */
static uint32_t v2x_script_build(uint8_t *dst, size_t cap,
                                 const nodus_rt_read_req_t *reads,
                                 uint16_t n_reads,
                                 const uint8_t *res, size_t res_len) {
    size_t off = 2;
    if (cap < 2) return 0;
    dst[0] = (uint8_t)(n_reads >> 8);
    dst[1] = (uint8_t)n_reads;
    for (uint16_t i = 0; i < n_reads; i++) {
        if (off + 6 + reads[i].key_len > cap) return 0;
        v2x_put32(dst + off, reads[i].op_id);
        dst[off + 4] = (uint8_t)(reads[i].key_len >> 8);
        dst[off + 5] = (uint8_t)reads[i].key_len;
        memcpy(dst + off + 6, reads[i].key, reads[i].key_len);
        off += 6u + reads[i].key_len;
    }
    if (off + res_len > cap) return 0;
    if (res_len) memcpy(dst + off, res, res_len);
    return (uint32_t)(off + res_len);
}

/** Encode a canonical effect result from an input list. */
static int v2x_effres(uint8_t *dst, size_t cap,
                      const dna_effect_in_t *effs, uint16_t n,
                      size_t *len_out) {
    return dna_effect_result_encode(effs, n, dst, cap, len_out);
}

/** One-leg, one-effect, no-reads envelope in one call. */
static int v2x_env1(v2x_env_t *e, uint32_t domain_id, uint32_t runtime_op,
                    uint32_t eff_op, uint8_t kind, uint8_t pre,
                    const uint8_t *key, uint16_t key_len,
                    const uint8_t *val, uint32_t val_len) {
    dna_effect_in_t eff;
    memset(&eff, 0, sizeof(eff));
    eff.hdr.op_id = eff_op;
    eff.hdr.effect_kind = kind;
    eff.hdr.precond_tag = pre;
    eff.hdr.key_len = key_len;
    eff.hdr.value_len = val_len;
    eff.key = key;
    eff.value = val;
    uint8_t res[1024];
    size_t rl = 0;
    if (dna_effect_result_encode(&eff, 1, res, sizeof(res), &rl) != 0)
        return -1;
    uint8_t call[1200];
    uint32_t cl = v2x_script_build(call, sizeof(call), NULL, 0, res, rl);
    if (!cl) return -1;
    v2x_leg_t leg = { domain_id, runtime_op, call, cl, 4, 2048 };
    return v2x_env_build(e, &leg, 1);
}

/** One-effect convenience: kind/precond/op/key/value. */
static int v2x_eff1(uint8_t *dst, size_t cap, uint32_t op_id,
                    uint8_t kind, uint8_t pre,
                    const uint8_t *key, uint16_t key_len,
                    const uint8_t *val, uint32_t val_len,
                    size_t *len_out) {
    dna_effect_in_t e;
    memset(&e, 0, sizeof(e));
    e.hdr.op_id = op_id;
    e.hdr.effect_kind = kind;
    e.hdr.precond_tag = pre;
    e.hdr.key_len = key_len;
    e.hdr.value_len = val_len;
    e.key = key;
    e.value = val;
    return v2x_effres(dst, cap, &e, 1, len_out);
}

#endif /* NODUS_TESTS_V2_EXEC_FIXTURE_H */
