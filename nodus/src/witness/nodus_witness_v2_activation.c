/**
 * @file nodus_witness_v2_activation.c
 * @brief Ledger V2 O15C — committed activation authority implementation.
 *
 * Contract, state machine and dormancy argument: the header. Apply
 * functions mirror nodus_chain_config_apply's structure deliberately —
 * same offset walk, same committee-at-signing-height authority, same
 * dna_bft_quorum rule — so the two governance lanes cannot drift apart
 * in shape. Self-contained: no libdna symbols.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_activation.h"

#include "nodus/nodus_chain_config.h"   /* derive_witness_id, grace tiers  */
#include "nodus/nodus_types.h"          /* NODUS_TREE_TAG_ACTIVATION       */
#include "dnac/ledger_ids.h"            /* dna_bft_quorum                  */
#include "dnac/dnac.h"                  /* DNAC_EPOCH_LENGTH, tx header    */
#include "dnac/transaction.h"           /* DNAC_TX_HEADER_SIZE             */
#include "dnac/tx_wire.h"               /* DNAC_TXW_TYPE_V2_SCHEDULE/READY */
#include "dnac/block_v2.h"              /* DNA_BH2_VERSION (target digest) */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_runtime.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_v2_schema.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "W_V2ACT"

/* Wire-walk constants — the exact CC mirror set (drift = consensus break;
 * pinned in nodus_witness_chain_config.c against the dnac headers). */
#define ACT_TX_HEADER_SIZE   DNAC_TX_HEADER_SIZE          /* 82 */
#define ACT_NULLIFIER_LEN    64
#define ACT_TOKEN_ID_LEN     64
#define ACT_FINGERPRINT_LEN  129
#define ACT_SEED_LEN         32
#define ACT_MAX_ACTIVE       DNA_MAX_ACTIVE_VALIDATORS

_Static_assert(ACT_MAX_ACTIVE == DNA_ACT15_WIRE_MAX_SLOTS,
               "vote slot cap drift vs shared activation wire");
_Static_assert(DNA_ACT_PUBKEY_LEN == QGP_DSA87_PUBLICKEYBYTES,
               "activation pubkey width drift vs ML-DSA-87");
_Static_assert(DNA_ACT_SIG_LEN == QGP_DSA87_SIGNATURE_BYTES,
               "activation signature width drift vs ML-DSA-87");

static void act_be64(uint64_t v, uint8_t out[8]) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void act_be32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
}

/* ── DDL (single source — the v2 ladder's S10 migration calls this) ─── */

int nodus_witness_v2_activation_db_migrate(nodus_witness_t *w) {
    if (!w || !w->db) return -1;
    static const char *const ddl =
        "CREATE TABLE IF NOT EXISTS v2_activation ("
        "  id INTEGER PRIMARY KEY CHECK (id = 1),"
        "  record_version INTEGER NOT NULL,"
        "  state INTEGER NOT NULL,"
        "  chain_id BLOB NOT NULL,"
        "  target BLOB NOT NULL,"
        "  activation_height INTEGER NOT NULL,"
        "  original_height INTEGER NOT NULL,"
        "  deadline_height INTEGER NOT NULL,"
        "  schedule_digest BLOB NOT NULL,"
        "  proposal_nonce INTEGER NOT NULL,"
        "  commit_height INTEGER NOT NULL,"
        "  postpone_count INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS v2_activation_readiness ("
        "  schedule_digest BLOB NOT NULL,"
        "  voter_id BLOB NOT NULL,"
        "  signal_version INTEGER NOT NULL,"
        "  signal_epoch INTEGER NOT NULL,"
        "  pubkey BLOB NOT NULL,"
        "  signature BLOB NOT NULL,"
        "  PRIMARY KEY (schedule_digest, voter_id)"
        ");";
    char *err = NULL;
    if (sqlite3_exec(w->db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "activation DDL failed: %s",
                      err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }
    return 0;
}

/* ── Record load (fail-closed on any malformation) ───────────────────── */

int nodus_witness_v2_activation_get(nodus_witness_t *w,
                                    nodus_v2_act_record_t *out) {
    if (!w || !w->db || !out) return -1;
    memset(out, 0, sizeof(*out));

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT record_version, state, chain_id, target,"
            "       activation_height, original_height, deadline_height,"
            "       schedule_digest, proposal_nonce, commit_height,"
            "       postpone_count FROM v2_activation WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK) {
        /* Table absent (pre-v10 database): there IS no committed record.
         * The schema gate elsewhere (preflight issue 1 / required-table
         * scan) reports the un-migrated database — this reader only
         * answers "is a record committed", and on a database that cannot
         * hold one the honest answer is "no record". */
        return 1;
    }
    int rc = sqlite3_step(st);
    if (rc == SQLITE_DONE) { sqlite3_finalize(st); return 1; }
    if (rc != SQLITE_ROW)  { sqlite3_finalize(st); return -1; }

    int ret = -1;
    do {
        if (sqlite3_column_bytes(st, 2) != DNA_ACT_CHAIN_ID_LEN) break;
        if (sqlite3_column_bytes(st, 3) != DNA_ACT_HASH_LEN) break;
        if (sqlite3_column_bytes(st, 7) != DNA_ACT_HASH_LEN) break;

        out->record_version   = (uint32_t)sqlite3_column_int64(st, 0);
        out->state            = (uint8_t)sqlite3_column_int(st, 1);
        memcpy(out->chain_id, sqlite3_column_blob(st, 2),
               DNA_ACT_CHAIN_ID_LEN);
        memcpy(out->target, sqlite3_column_blob(st, 3), DNA_ACT_HASH_LEN);
        out->activation_height = (uint64_t)sqlite3_column_int64(st, 4);
        out->original_height   = (uint64_t)sqlite3_column_int64(st, 5);
        out->deadline_height   = (uint64_t)sqlite3_column_int64(st, 6);
        memcpy(out->schedule_digest, sqlite3_column_blob(st, 7),
               DNA_ACT_HASH_LEN);
        out->proposal_nonce   = (uint64_t)sqlite3_column_int64(st, 8);
        out->commit_height    = (uint64_t)sqlite3_column_int64(st, 9);
        out->postpone_count   = (uint32_t)sqlite3_column_int64(st, 10);

        /* Unknown version or state is a FAULT, never "no record" — a
         * future-versioned committed authority must stop this binary,
         * not be silently ignored (O15C-A §D.5 fail-closed rule). */
        if (out->record_version != DNA_ACT_RECORD_VERSION) break;
        if (out->state < DNA_ACT_STATE_SCHEDULED ||
            out->state > DNA_ACT_STATE_CANCELLED)
            break;
        ret = 0;
    } while (0);
    sqlite3_finalize(st);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s",
                      "malformed committed activation record — FAULT");
        memset(out, 0, sizeof(*out));
    }
    return ret;
}

/* ── activation_root (CC-style local RFC6962: 0x00 leaf / 0x01 inner) ── */

static int act_leaf_hash(const uint8_t *raw, size_t len, uint8_t out[64]) {
    /* SHA3-512(0x00 ‖ raw) — one-shot; the CC helpers use EVP, this
     * module uses the qgp one-shot for the same digest. */
    uint8_t *buf = malloc(1 + len);
    if (!buf) return -1;
    buf[0] = 0x00;
    memcpy(buf + 1, raw, len);
    int rc = qgp_sha3_512(buf, 1 + len, out);
    free(buf);
    return rc == 0 ? 0 : -1;
}

static int act_inner_hash(const uint8_t l[64], const uint8_t r[64],
                          uint8_t out[64]) {
    uint8_t buf[1 + 64 + 64];
    buf[0] = 0x01;
    memcpy(buf + 1, l, 64);
    memcpy(buf + 65, r, 64);
    return qgp_sha3_512(buf, sizeof(buf), out) == 0 ? 0 : -1;
}

static int act_merkle(uint8_t (*leaves)[64], size_t n, uint8_t out[64]) {
    if (n == 0) return -1;
    if (n == 1) { memcpy(out, leaves[0], 64); return 0; }
    size_t k = 1;
    while (k * 2 < n) k *= 2;
    uint8_t left[64], right[64];
    if (act_merkle(leaves, k, left) != 0) return -1;
    if (act_merkle(leaves + k, n - k, right) != 0) return -1;
    return act_inner_hash(left, right, out);
}

/* Canonical record leaf preimage: tag(16) ‖ ver ‖ state ‖ chain ‖ target
 * ‖ activation ‖ original ‖ deadline ‖ sched ‖ nonce ‖ commit ‖ postpone. */
static int act_record_leaf(const nodus_v2_act_record_t *r, uint8_t out[64]) {
    uint8_t raw[16 + 4 + 1 + 32 + 64 + 8 + 8 + 8 + 64 + 8 + 8 + 4];
    uint8_t *p = raw;
    memcpy(p, DNA_ACT_TAG_REC_LEAF, 16);              p += 16;
    act_be32(r->record_version, p);                   p += 4;
    *p++ = r->state;
    memcpy(p, r->chain_id, 32);                       p += 32;
    memcpy(p, r->target, 64);                         p += 64;
    act_be64(r->activation_height, p);                p += 8;
    act_be64(r->original_height, p);                  p += 8;
    act_be64(r->deadline_height, p);                  p += 8;
    memcpy(p, r->schedule_digest, 64);                p += 64;
    act_be64(r->proposal_nonce, p);                   p += 8;
    act_be64(r->commit_height, p);                    p += 8;
    act_be32(r->postpone_count, p);                   p += 4;
    return act_leaf_hash(raw, sizeof(raw), out);
}

int nodus_witness_v2_activation_root(nodus_witness_t *w, uint8_t out[64]) {
    if (!w || !w->db || !out) return -1;

    nodus_v2_act_record_t rec;
    int grc = nodus_witness_v2_activation_get(w, &rec);
    if (grc < 0) return -1;
    if (grc == 1)
        return nodus_merkle_empty_root(NODUS_TREE_TAG_ACTIVATION, out);

    size_t cap = 8, n = 0;
    uint8_t (*leaves)[64] = malloc(cap * 64);
    if (!leaves) return -1;
    if (act_record_leaf(&rec, leaves[n]) != 0) { free(leaves); return -1; }
    n++;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT schedule_digest, voter_id, signal_version, signal_epoch "
            "FROM v2_activation_readiness ORDER BY voter_id ASC",
            -1, &st, NULL) != SQLITE_OK) {
        free(leaves);
        return -1;
    }
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (sqlite3_column_bytes(st, 0) != DNA_ACT_HASH_LEN ||
            sqlite3_column_bytes(st, 1) != DNA_ACT_VOTER_ID_LEN) {
            sqlite3_finalize(st); free(leaves); return -1;
        }
        if (n == cap) {
            size_t nc = cap * 2;
            uint8_t (*tmp)[64] = realloc(leaves, nc * 64);
            if (!tmp) { sqlite3_finalize(st); free(leaves); return -1; }
            leaves = tmp; cap = nc;
        }
        uint8_t raw[16 + 64 + 32 + 4 + 8];
        uint8_t *p = raw;
        memcpy(p, DNA_ACT_TAG_RDY_LEAF, 16);                     p += 16;
        memcpy(p, sqlite3_column_blob(st, 0), 64);               p += 64;
        memcpy(p, sqlite3_column_blob(st, 1), 32);               p += 32;
        act_be32((uint32_t)sqlite3_column_int64(st, 2), p);      p += 4;
        act_be64((uint64_t)sqlite3_column_int64(st, 3), p);      p += 8;
        if (act_leaf_hash(raw, sizeof(raw), leaves[n]) != 0) {
            sqlite3_finalize(st); free(leaves); return -1;
        }
        n++;
    }
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) { free(leaves); return -1; }  /* v0.18.19 rule */

    int ret = act_merkle(leaves, n, out);
    free(leaves);
    return ret;
}

/* ── Compiled target digest D ────────────────────────────────────────── */

int nodus_witness_v2_activation_compiled_target(uint8_t out[DNA_ACT_HASH_LEN]) {
    if (!out) return -1;
    size_t n = 0;
    const nodus_domain_runtime_t *tab = nodus_runtime_builtin_table(&n);
    if (!tab || n < 1 || n > 16) return -1;

    dna_act_target_rt_t rts[16];
    memset(rts, 0, sizeof(rts));
    for (size_t i = 0; i < n; i++) {
        rts[i].domain_id       = tab[i].domain_id;
        rts[i].ruleset_version = tab[i].ruleset_version;
        memcpy(rts[i].ruleset_hash, tab[i].ruleset_hash, DNA_ACT_HASH_LEN);
    }
    /* Sort ascending by domain_id (insertion sort — n <= 16). */
    for (size_t i = 1; i < n; i++)
        for (size_t j = i; j > 0 &&
             rts[j - 1].domain_id > rts[j].domain_id; j--) {
            dna_act_target_rt_t t = rts[j - 1];
            rts[j - 1] = rts[j];
            rts[j] = t;
        }
    return dna_act_target_digest(DNA_ACT_TARGET_VERSION,
                                 (uint8_t)DNA_BH2_VERSION,
                                 NODUS_V2_SCHEMA_VERSION_S10,
                                 rts, n, out);
}

/* ── TX walk (the exact find_cc_appended_offset mirror) ──────────────── */

static int act_appended_offset(const uint8_t *tx_data, uint32_t tx_len,
                               size_t *off_out) {
    if (!tx_data || !off_out) return -1;
    if (tx_len < ACT_TX_HEADER_SIZE + 1) return -1;
    size_t off = ACT_TX_HEADER_SIZE;

    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    const size_t input_size = ACT_NULLIFIER_LEN + 8 + ACT_TOKEN_ID_LEN;
    if ((size_t)input_count * input_size > tx_len - off) return -1;
    off += (size_t)input_count * input_size;

    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        if (off + 1 + ACT_FINGERPRINT_LEN + 8 + ACT_TOKEN_ID_LEN +
                ACT_SEED_LEN + 1 > tx_len)
            return -1;
        off += 1 + ACT_FINGERPRINT_LEN + 8 + ACT_TOKEN_ID_LEN + ACT_SEED_LEN;
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
    }

    if (off >= tx_len) return -1;
    uint8_t witness_count = tx_data[off++];
    const size_t witness_size = 32 + DNA_ACT_SIG_LEN + 8 + DNA_ACT_PUBKEY_LEN;
    if ((size_t)witness_count * witness_size > tx_len - off) return -1;
    off += (size_t)witness_count * witness_size;

    if (off >= tx_len) return -1;
    uint8_t signer_count = tx_data[off++];
    if (signer_count == 0) return -1;
    const size_t signer_size = DNA_ACT_PUBKEY_LEN + DNA_ACT_SIG_LEN;
    if ((size_t)signer_count * signer_size > tx_len - off) return -1;
    off += (size_t)signer_count * signer_size;

    *off_out = off;
    return 0;
}

/* ── Quorum vote verification (shared by SCHEDULE and CANCEL) ────────── */

static int act_verify_quorum(nodus_witness_t *w,
                             const dna_act15_wire_t *f,
                             const uint8_t digest[64],
                             uint64_t block_height) {
    int ret = -1;
    nodus_committee_member_t *committee =
        calloc(ACT_MAX_ACTIVE, sizeof(*committee));
    if (!committee) return -1;

    int committee_count = 0;
    uint64_t lookup_height = (block_height == 0) ? 0 : block_height - 1;
    if (nodus_committee_get_for_block(w, lookup_height, committee,
                                      ACT_MAX_ACTIVE,
                                      &committee_count) != 0 ||
        committee_count <= 0 || committee_count > ACT_MAX_ACTIVE) {
        QGP_LOG_ERROR(LOG_TAG, "committee lookup failed at h=%llu",
                      (unsigned long long)lookup_height);
        goto out;
    }

    if ((int)f->vote_count > committee_count) {
        QGP_LOG_ERROR(LOG_TAG, "vote_count=%u > committee_count=%d",
                      (unsigned)f->vote_count, committee_count);
        goto out;
    }

    /* Pairwise-distinct witness_ids (one validator, one vote). */
    for (uint8_t i = 0; i < f->vote_count; i++)
        for (uint8_t j = (uint8_t)(i + 1); j < f->vote_count; j++)
            if (memcmp(f->votes[i].witness_id, f->votes[j].witness_id,
                       32) == 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "duplicate vote witness_id");
                goto out;
            }

    uint8_t (*ids)[32] = calloc((size_t)committee_count, 32);
    if (!ids) goto out;
    for (int c = 0; c < committee_count; c++)
        if (nodus_chain_config_derive_witness_id(committee[c].pubkey,
                                                 ids[c]) != 0) {
            free(ids);
            goto out;
        }

    int verified = 0;
    for (uint8_t v = 0; v < f->vote_count; v++) {
        int match = -1;
        for (int c = 0; c < committee_count; c++)
            if (memcmp(f->votes[v].witness_id, ids[c], 32) == 0) {
                match = c;
                break;
            }
        if (match < 0) {
            QGP_LOG_ERROR(LOG_TAG, "vote[%u] not in governing committee",
                          (unsigned)v);
            free(ids);
            goto out;
        }
        if (qgp_dsa87_verify(f->votes[v].signature, DNA_ACT_SIG_LEN,
                             digest, 64, committee[match].pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "vote[%u] signature invalid",
                          (unsigned)v);
            free(ids);
            goto out;
        }
        verified++;
    }
    free(ids);

    {
        uint32_t quorum = dna_bft_quorum((uint32_t)committee_count);
        if ((uint32_t)verified < quorum) {
            QGP_LOG_ERROR(LOG_TAG, "verified=%d < quorum=%u of %d",
                          verified, (unsigned)quorum, committee_count);
            goto out;
        }
    }
    ret = 0;
out:
    free(committee);
    return ret;
}

/* Minimum scheduling lead time: max(2 epochs, the SAFETY grace tier) —
 * O15C-A §D.2. The grace tier comes from the exported chain-config
 * authority (param 2 = BLOCK_INTERVAL_SEC, a SAFETY-class param), so the
 * Genesis Protocol harness's compile-time grace override applies here
 * identically. */
static uint64_t act_min_lead(void) {
    uint64_t two_epochs = 2ULL * (uint64_t)DNAC_EPOCH_LENGTH;
    uint64_t safety = nodus_chain_config_grace_for_param(2);
    return (safety > two_epochs) ? safety : two_epochs;
}

/* ── type-15 apply ───────────────────────────────────────────────────── */

int nodus_witness_v2_activation_apply(nodus_witness_t *w,
                                      const uint8_t *tx_data,
                                      uint32_t tx_len,
                                      uint64_t block_height) {
    if (!w || !w->db || !tx_data) return -1;
    if (tx_len < ACT_TX_HEADER_SIZE) return -1;
    if (tx_data[1] != DNAC_TXW_TYPE_V2_SCHEDULE) {
        QGP_LOG_ERROR(LOG_TAG, "apply: type_byte=%u != 15",
                      (unsigned)tx_data[1]);
        return -1;
    }

    size_t off = 0;
    if (act_appended_offset(tx_data, tx_len, &off) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "apply: malformed tx (offset walk)");
        return -1;
    }

    int rc = -1;
    dna_act15_wire_t *f = calloc(1, sizeof(*f));
    if (!f) return -1;

    do {
        size_t consumed = 0;
        if (dna_act15_wire_decode(tx_data + off, (size_t)(tx_len - off),
                                  f, &consumed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "apply: malformed appended fields");
            break;
        }
        if (f->record_version != DNA_ACT_RECORD_VERSION) {
            QGP_LOG_ERROR(LOG_TAG, "apply: record_version=%u unsupported",
                          (unsigned)f->record_version);
            break;
        }
        /* Signing/validity window shape (the CC scalar-rule shape). */
        if (f->signed_at_block == 0 ||
            f->valid_before_block <= f->signed_at_block) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "apply: window shape invalid");
            break;
        }
        if (block_height > f->valid_before_block) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "apply: stale (freshness)");
            break;
        }

        /* All-zero target rejects for BOTH ops (op2's target is the
         * schedule digest — also never all-zero). */
        {
            int nz = 0;
            for (int i = 0; i < DNA_ACT_HASH_LEN; i++)
                if (f->target[i]) { nz = 1; break; }
            if (!nz) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "apply: all-zero target");
                break;
            }
        }

        nodus_v2_act_record_t rec;
        int have = nodus_witness_v2_activation_get(w, &rec);
        if (have < 0) break;

        if (f->op == DNA_ACT_OP_SCHEDULE) {
            if (f->activation_height == 0 ||
                (f->activation_height % (uint64_t)DNAC_EPOCH_LENGTH) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "apply: H_act not an epoch boundary");
                break;
            }
            uint64_t lead = act_min_lead();
            if (f->activation_height < block_height ||
                f->activation_height - block_height < lead) {
                QGP_LOG_ERROR(LOG_TAG,
                              "apply: lead time — H_act=%llu commit=%llu "
                              "min_lead=%llu",
                              (unsigned long long)f->activation_height,
                              (unsigned long long)block_height,
                              (unsigned long long)lead);
                break;
            }
            /* Exactly one live schedule; a fresh one only from
             * UNSCHEDULED or CANCELLED, and (replay closure) with a
             * strictly increasing proposal_nonce once any record ever
             * existed — a cancelled schedule's exact bytes can never
             * re-commit. */
            if (have == 0 && rec.state != DNA_ACT_STATE_CANCELLED) {
                QGP_LOG_ERROR(LOG_TAG, "apply: live record in state %u",
                              (unsigned)rec.state);
                break;
            }
            if (have == 0 && f->proposal_nonce <= rec.proposal_nonce) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "apply: proposal_nonce not increasing");
                break;
            }

            uint8_t digest[64];
            if (dna_act_sched_digest(w->chain_id, f->record_version,
                                     f->target, f->activation_height,
                                     f->proposal_nonce, f->signed_at_block,
                                     f->valid_before_block, digest) != 0)
                break;
            if (act_verify_quorum(w, f, digest, block_height) != 0) break;

            uint64_t deadline = f->activation_height -
                                2ULL * (uint64_t)DNAC_EPOCH_LENGTH;
            sqlite3_stmt *up = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "INSERT INTO v2_activation (id, record_version, state,"
                    " chain_id, target, activation_height, original_height,"
                    " deadline_height, schedule_digest, proposal_nonce,"
                    " commit_height, postpone_count) "
                    "VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0) "
                    "ON CONFLICT(id) DO UPDATE SET"
                    " record_version=?1, state=?2, chain_id=?3, target=?4,"
                    " activation_height=?5, original_height=?6,"
                    " deadline_height=?7, schedule_digest=?8,"
                    " proposal_nonce=?9, commit_height=?10,"
                    " postpone_count=0",
                    -1, &up, NULL) != SQLITE_OK)
                break;
            sqlite3_bind_int64(up, 1, (int64_t)DNA_ACT_RECORD_VERSION);
            sqlite3_bind_int(up, 2, (int)DNA_ACT_STATE_SCHEDULED);
            sqlite3_bind_blob(up, 3, w->chain_id, DNA_ACT_CHAIN_ID_LEN,
                              SQLITE_STATIC);
            sqlite3_bind_blob(up, 4, f->target, DNA_ACT_HASH_LEN,
                              SQLITE_STATIC);
            sqlite3_bind_int64(up, 5, (int64_t)f->activation_height);
            sqlite3_bind_int64(up, 6, (int64_t)f->activation_height);
            sqlite3_bind_int64(up, 7, (int64_t)deadline);
            sqlite3_bind_blob(up, 8, digest, 64, SQLITE_STATIC);
            sqlite3_bind_int64(up, 9, (int64_t)f->proposal_nonce);
            sqlite3_bind_int64(up, 10, (int64_t)block_height);
            int urc = sqlite3_step(up);
            sqlite3_finalize(up);
            if (urc != SQLITE_DONE) break;

            /* A superseded digest's signals are never reusable. */
            sqlite3_stmt *del = NULL;
            if (sqlite3_prepare_v2(w->db,
                    "DELETE FROM v2_activation_readiness "
                    "WHERE schedule_digest != ?1", -1, &del, NULL)
                != SQLITE_OK)
                break;
            sqlite3_bind_blob(del, 1, digest, 64, SQLITE_STATIC);
            urc = sqlite3_step(del);
            sqlite3_finalize(del);
            if (urc != SQLITE_DONE) break;

            QGP_LOG_INFO(LOG_TAG,
                         "SCHEDULED Ledger V2 activation at h=%llu "
                         "(commit=%llu, deadline=%llu)",
                         (unsigned long long)f->activation_height,
                         (unsigned long long)block_height,
                         (unsigned long long)deadline);
            rc = 0;
        } else if (f->op == DNA_ACT_OP_CANCEL) {
            if (f->activation_height != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "apply: CANCEL carries a nonzero height");
                break;
            }
            if (have != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s", "apply: CANCEL with no record");
                break;
            }
            if (memcmp(f->target, rec.schedule_digest, 64) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "apply: CANCEL digest mismatch");
                break;
            }
            /* Irreversibility: a READY record entering its final epoch
             * before activation is immutable (O15C-A §D.2). A SCHEDULED
             * (incl. postponed) record is always cancellable. */
            if (rec.state == DNA_ACT_STATE_READY) {
                if (rec.activation_height <
                        (uint64_t)DNAC_EPOCH_LENGTH ||
                    block_height >=
                        rec.activation_height -
                        (uint64_t)DNAC_EPOCH_LENGTH) {
                    QGP_LOG_ERROR(LOG_TAG, "%s",
                                  "apply: CANCEL past irreversibility");
                    break;
                }
            } else if (rec.state != DNA_ACT_STATE_SCHEDULED) {
                QGP_LOG_ERROR(LOG_TAG, "apply: CANCEL in state %u",
                              (unsigned)rec.state);
                break;
            }

            uint8_t digest[64];
            if (dna_act_cancel_digest(w->chain_id, rec.schedule_digest,
                                      f->proposal_nonce, f->signed_at_block,
                                      f->valid_before_block, digest) != 0)
                break;
            if (act_verify_quorum(w, f, digest, block_height) != 0) break;

            char *err = NULL;
            if (sqlite3_exec(w->db,
                    "UPDATE v2_activation SET state = 4 WHERE id = 1;"
                    "DELETE FROM v2_activation_readiness;",
                    NULL, NULL, &err) != SQLITE_OK) {
                if (err) sqlite3_free(err);
                break;
            }
            QGP_LOG_INFO(LOG_TAG, "%s",
                         "Ledger V2 activation schedule CANCELLED");
            rc = 0;
        } else {
            QGP_LOG_ERROR(LOG_TAG, "apply: unknown op %u", (unsigned)f->op);
        }
    } while (0);

    free(f);
    return rc;
}

/* ── type-16 apply ───────────────────────────────────────────────────── */

int nodus_witness_v2_activation_apply_ready(nodus_witness_t *w,
                                            const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            uint64_t block_height) {
    if (!w || !w->db || !tx_data) return -1;
    if (tx_len < ACT_TX_HEADER_SIZE) return -1;
    if (tx_data[1] != DNAC_TXW_TYPE_V2_READY) {
        QGP_LOG_ERROR(LOG_TAG, "ready: type_byte=%u != 16",
                      (unsigned)tx_data[1]);
        return -1;
    }
    size_t off = 0;
    if (act_appended_offset(tx_data, tx_len, &off) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "ready: malformed tx (offset walk)");
        return -1;
    }

    int rc = -1;
    dna_act16_wire_t *f = calloc(1, sizeof(*f));
    if (!f) return -1;

    do {
        size_t consumed = 0;
        if (dna_act16_wire_decode(tx_data + off, (size_t)(tx_len - off),
                                  f, &consumed) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: malformed appended fields");
            break;
        }
        if (f->signal_version != DNA_ACT_SIGNAL_VERSION) {
            QGP_LOG_ERROR(LOG_TAG, "ready: signal_version=%u unsupported",
                          (unsigned)f->signal_version);
            break;
        }

        nodus_v2_act_record_t rec;
        if (nodus_witness_v2_activation_get(w, &rec) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: no committed schedule");
            break;
        }
        if (rec.state != DNA_ACT_STATE_SCHEDULED) {
            QGP_LOG_ERROR(LOG_TAG, "ready: record state %u is not "
                          "collecting", (unsigned)rec.state);
            break;
        }
        if (memcmp(f->schedule_digest, rec.schedule_digest, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: schedule digest mismatch");
            break;
        }
        if (memcmp(f->target, rec.target, 64) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: target mismatch");
            break;
        }

        /* Epoch freshness: the signal must be stamped with the epoch it
         * is committed in (the domreg op_signal rule). */
        uint64_t epoch_start =
            block_height - (block_height % (uint64_t)DNAC_EPOCH_LENGTH);
        if (f->signal_epoch != epoch_start) {
            QGP_LOG_ERROR(LOG_TAG, "ready: stale signal_epoch=%llu "
                          "(current=%llu)",
                          (unsigned long long)f->signal_epoch,
                          (unsigned long long)epoch_start);
            break;
        }

        /* voter_id must derive from the carried pubkey AND the pubkey
         * must be a member of the committee governing this height. */
        uint8_t derived[32];
        if (nodus_chain_config_derive_witness_id(f->pubkey, derived) != 0)
            break;
        if (memcmp(derived, f->voter_id, 32) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: voter_id != H(pubkey)");
            break;
        }
        {
            nodus_committee_member_t *committee =
                calloc(ACT_MAX_ACTIVE, sizeof(*committee));
            if (!committee) break;
            int count = 0, member = 0;
            if (nodus_committee_get_for_block(w, block_height, committee,
                                              ACT_MAX_ACTIVE, &count) != 0 ||
                count <= 0) {
                free(committee);
                QGP_LOG_ERROR(LOG_TAG, "%s", "ready: committee lookup failed");
                break;
            }
            for (int c = 0; c < count; c++)
                if (memcmp(committee[c].pubkey, f->pubkey,
                           DNA_ACT_PUBKEY_LEN) == 0) {
                    member = 1;
                    break;
                }
            free(committee);
            if (!member) {
                QGP_LOG_ERROR(LOG_TAG, "%s",
                              "ready: signer not in governing set");
                break;
            }
        }

        uint8_t digest[64];
        if (dna_act_ready_digest(f->signal_version, w->chain_id,
                                 f->schedule_digest, f->target,
                                 f->voter_id, f->signal_epoch,
                                 digest) != 0)
            break;
        if (qgp_dsa87_verify(f->signature, DNA_ACT_SIG_LEN, digest, 64,
                             f->pubkey) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "ready: signature invalid");
            break;
        }

        /* Duplicate handling: byte-identical re-submission is a no-op;
         * a DIFFERENT signal for the same (digest, voter) is first-wins
         * rejected (the domreg conflict rule, deterministic in block
         * order). */
        sqlite3_stmt *sel = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT signal_version, signal_epoch, pubkey, signature "
                "FROM v2_activation_readiness "
                "WHERE schedule_digest = ?1 AND voter_id = ?2",
                -1, &sel, NULL) != SQLITE_OK)
            break;
        sqlite3_bind_blob(sel, 1, f->schedule_digest, 64, SQLITE_STATIC);
        sqlite3_bind_blob(sel, 2, f->voter_id, 32, SQLITE_STATIC);
        int src = sqlite3_step(sel);
        if (src == SQLITE_ROW) {
            int identical =
                (uint32_t)sqlite3_column_int64(sel, 0) == f->signal_version &&
                (uint64_t)sqlite3_column_int64(sel, 1) == f->signal_epoch &&
                sqlite3_column_bytes(sel, 2) == DNA_ACT_PUBKEY_LEN &&
                memcmp(sqlite3_column_blob(sel, 2), f->pubkey,
                       DNA_ACT_PUBKEY_LEN) == 0 &&
                sqlite3_column_bytes(sel, 3) == DNA_ACT_SIG_LEN &&
                memcmp(sqlite3_column_blob(sel, 3), f->signature,
                       DNA_ACT_SIG_LEN) == 0;
            sqlite3_finalize(sel);
            if (identical) { rc = 0; break; }          /* idempotent */
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "ready: conflicting signal (first wins)");
            break;
        }
        sqlite3_finalize(sel);
        if (src != SQLITE_DONE) break;

        sqlite3_stmt *ins = NULL;
        if (sqlite3_prepare_v2(w->db,
                "INSERT INTO v2_activation_readiness (schedule_digest,"
                " voter_id, signal_version, signal_epoch, pubkey,"
                " signature) VALUES (?1,?2,?3,?4,?5,?6)",
                -1, &ins, NULL) != SQLITE_OK)
            break;
        sqlite3_bind_blob(ins, 1, f->schedule_digest, 64, SQLITE_STATIC);
        sqlite3_bind_blob(ins, 2, f->voter_id, 32, SQLITE_STATIC);
        sqlite3_bind_int64(ins, 3, (int64_t)f->signal_version);
        sqlite3_bind_int64(ins, 4, (int64_t)f->signal_epoch);
        sqlite3_bind_blob(ins, 5, f->pubkey, DNA_ACT_PUBKEY_LEN,
                          SQLITE_STATIC);
        sqlite3_bind_blob(ins, 6, f->signature, DNA_ACT_SIG_LEN,
                          SQLITE_STATIC);
        int irc = sqlite3_step(ins);
        sqlite3_finalize(ins);
        if (irc != SQLITE_DONE) break;

        QGP_LOG_INFO(LOG_TAG, "%s", "readiness signal committed");
        rc = 0;
    } while (0);

    free(f);
    return rc;
}

/* ── Readiness predicate helpers ─────────────────────────────────────── */

static int act_voter_has_signal(nodus_witness_t *w,
                                const uint8_t digest[64],
                                const uint8_t voter[32]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM v2_activation_readiness "
            "WHERE schedule_digest = ?1 AND voter_id = ?2",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, digest, 64, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, voter, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

int nodus_witness_v2_activation_readiness_count(nodus_witness_t *w,
        const uint8_t schedule_digest[DNA_ACT_HASH_LEN],
        const dna_vset_snapshot_t *snap, uint32_t *count_out) {
    if (!w || !w->db || !schedule_digest || !snap || !count_out) return -1;
    uint32_t n = 0;
    for (uint16_t i = 0; i < snap->active_count; i++) {
        int h = act_voter_has_signal(w, schedule_digest,
                                     snap->entries[i].voter_id);
        if (h < 0) return -1;
        n += (uint32_t)h;
    }
    *count_out = n;
    return 0;
}

/* complete = EVERY member of snap holds a stored signal. 1/0/-1. */
static int act_complete(nodus_witness_t *w,
                        const nodus_v2_act_record_t *rec,
                        const dna_vset_snapshot_t *snap) {
    for (uint16_t i = 0; i < snap->active_count; i++) {
        int h = act_voter_has_signal(w, rec->schedule_digest,
                                     snap->entries[i].voter_id);
        if (h < 0) return -1;
        if (h == 0) return 0;
    }
    return 1;
}

/* Same MEMBERSHIP (voter_id sets equal)? Both snapshots are canonically
 * ordered by the same total rule, but ranking can reorder on stake moves
 * — membership equality must be order-independent. 1/0/-1. */
static int act_same_members(const dna_vset_snapshot_t *a,
                            const dna_vset_snapshot_t *b) {
    if (a->active_count != b->active_count) return 0;
    for (uint16_t i = 0; i < a->active_count; i++) {
        int found = 0;
        for (uint16_t j = 0; j < b->active_count; j++)
            if (memcmp(a->entries[i].voter_id, b->entries[j].voter_id,
                       DNA_VSET_VOTER_ID_LEN) == 0) {
                found = 1;
                break;
            }
        if (!found) return 0;
    }
    return 1;
}

/* ── Boundary state machine ──────────────────────────────────────────── */

static int act_set_state(nodus_witness_t *w, uint8_t state) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_activation SET state = ?1 WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)state);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

static int act_postpone(nodus_witness_t *w,
                        const nodus_v2_act_record_t *rec) {
    if (rec->postpone_count >= DNA_ACT_MAX_POSTPONES) {
        /* Auto-cancel backstop: no immortal schedules. */
        char *err = NULL;
        if (sqlite3_exec(w->db,
                "UPDATE v2_activation SET state = 4 WHERE id = 1;"
                "DELETE FROM v2_activation_readiness;",
                NULL, NULL, &err) != SQLITE_OK) {
            if (err) sqlite3_free(err);
            return -1;
        }
        QGP_LOG_WARN(LOG_TAG, "%s",
                     "activation AUTO-CANCELLED (postpone cap)");
        return 0;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "UPDATE v2_activation SET state = 1,"
            " activation_height = activation_height + ?1,"
            " postpone_count = postpone_count + 1 WHERE id = 1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (int64_t)DNAC_EPOCH_LENGTH);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    QGP_LOG_WARN(LOG_TAG,
                 "activation POSTPONED to h=%llu (postpone %u)",
                 (unsigned long long)(rec->activation_height +
                                      (uint64_t)DNAC_EPOCH_LENGTH),
                 (unsigned)(rec->postpone_count + 1));
    return 0;
}

int nodus_witness_v2_activation_on_boundary(nodus_witness_t *w,
                                            uint64_t boundary_height,
                                            int *activated_out) {
    if (activated_out) *activated_out = 0;
    if (!w || !w->db) return -1;
    if (boundary_height == 0 ||
        (boundary_height % (uint64_t)DNAC_EPOCH_LENGTH) != 0)
        return 0;

    nodus_v2_act_record_t rec;
    int have = nodus_witness_v2_activation_get(w, &rec);
    if (have < 0) return -1;
    if (have == 1) return 0;
    if (rec.state == DNA_ACT_STATE_ACTIVE ||
        rec.state == DNA_ACT_STATE_CANCELLED)
        return 0;

    /* The governing snapshot for the epoch NOW STARTING. Frozen one
     * epoch earlier by commit_next — committed state, never a live
     * recompute. Absent = FAULT: a chain running this machine always
     * has snapshots (genesis seeds 0 and E). */
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_vset_get(w, boundary_height, &snap, NULL) != 0 ||
        !snap) {
        QGP_LOG_ERROR(LOG_TAG, "boundary %llu: governing snapshot absent",
                      (unsigned long long)boundary_height);
        dna_vset_free(&snap);
        return -1;
    }

    int ret = -1;
    do {
        int complete = act_complete(w, &rec, snap);
        if (complete < 0) break;

        if (boundary_height == rec.activation_height) {
            /* Stage E — the terminal decision. */
            int pass = 0;
            if (rec.state == DNA_ACT_STATE_READY && complete == 1) {
                dna_vset_snapshot_t *prev = NULL;
                if (boundary_height >= (uint64_t)DNAC_EPOCH_LENGTH &&
                    nodus_witness_vset_get(w,
                        boundary_height - (uint64_t)DNAC_EPOCH_LENGTH,
                        &prev, NULL) == 0 && prev) {
                    int same = act_same_members(snap, prev);
                    dna_vset_free(&prev);
                    if (same < 0) break;
                    pass = same;
                } else {
                    dna_vset_free(&prev);
                    /* No previous snapshot = cannot prove Stage D
                     * separation — postpone, never assume. */
                    pass = 0;
                }
            }
            if (pass) {
                if (act_set_state(w, DNA_ACT_STATE_ACTIVE) != 0) break;
                if (activated_out) *activated_out = 1;
                QGP_LOG_INFO(LOG_TAG,
                             "Ledger V2 activation COMMITTED at h=%llu — "
                             "this is the terminal legacy block",
                             (unsigned long long)boundary_height);
            } else {
                if (act_postpone(w, &rec) != 0) break;
            }
        } else if (boundary_height < rec.activation_height) {
            /* Re-evaluated at EVERY boundary while the record lives —
             * the convergence property (header). */
            uint8_t want = complete == 1 ? DNA_ACT_STATE_READY
                                         : DNA_ACT_STATE_SCHEDULED;
            if (want != rec.state && act_set_state(w, want) != 0) break;
            if (want != rec.state)
                QGP_LOG_INFO(LOG_TAG, "activation record -> %s",
                             want == DNA_ACT_STATE_READY ? "READY"
                                                         : "SCHEDULED");
        } else {
            /* boundary_height > activation_height with a live record:
             * structurally unreachable (every boundary is processed and
             * H_act is epoch-aligned) — refuse to invent semantics. */
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "boundary beyond live activation height — FAULT");
            break;
        }
        ret = 0;
    } while (0);

    dna_vset_free(&snap);
    return ret;
}

/* ── Terminal refusal ────────────────────────────────────────────────── */

int nodus_witness_v2_activation_refuses_height(nodus_witness_t *w,
                                               uint64_t height) {
    if (!w) return 1;                         /* fail closed */
    /* NO DATABASE = PRE-GENESIS. A committed activation record cannot
     * exist before the chain does, so there is nothing to refuse by —
     * refusing here blocked the GENESIS proposal itself (found live by
     * the O15C rehearsal: "refusing to propose block 1" on a fresh
     * cluster). Fail-closed still applies where a committed record COULD
     * exist but cannot be read: a malformed record (below) refuses. */
    if (!w->db) return 0;
    nodus_v2_act_record_t rec;
    int have = nodus_witness_v2_activation_get(w, &rec);
    if (have < 0) return 1;                   /* malformed: fail closed */
    if (have == 1) return 0;
    if (rec.state == DNA_ACT_STATE_ACTIVE &&
        height > rec.activation_height)
        return 1;
    return 0;
}

/* ── Stage C exclusions ──────────────────────────────────────────────── */

int nodus_witness_v2_activation_exclusions(nodus_witness_t *w,
        uint64_t boundary_height,
        const dna_vset_snapshot_t *candidate,
        uint16_t min_count,
        uint8_t (*excl_out)[DNA_ACT_VOTER_ID_LEN],
        size_t cap, size_t *n_out) {
    if (!w || !w->db || !candidate || !excl_out || !n_out) return -1;
    *n_out = 0;

    nodus_v2_act_record_t rec;
    int have = nodus_witness_v2_activation_get(w, &rec);
    if (have < 0) return -1;
    if (have == 1 || rec.state != DNA_ACT_STATE_SCHEDULED ||
        rec.deadline_height != boundary_height)
        return 1;                              /* not applicable */

    size_t n = 0;
    for (uint16_t i = 0; i < candidate->active_count; i++) {
        int h = act_voter_has_signal(w, rec.schedule_digest,
                                     candidate->entries[i].voter_id);
        if (h < 0) return -1;
        if (h == 0) {
            if (n >= cap) return -1;
            memcpy(excl_out[n], candidate->entries[i].voter_id,
                   DNA_ACT_VOTER_ID_LEN);
            n++;
        }
    }
    if (n == 0) return 0;
    if ((size_t)candidate->active_count - n < (size_t)min_count) {
        QGP_LOG_WARN(LOG_TAG,
                     "Stage C floor guard: excluding %zu of %u would "
                     "break the floor %u — no exclusion",
                     n, (unsigned)candidate->active_count,
                     (unsigned)min_count);
        *n_out = 0;
        return 2;
    }
    *n_out = n;
    return 0;
}
