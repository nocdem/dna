/**
 * @file nodus/tests/test_v2_finalize.c
 * @brief Ledger V2 O14 — the PRODUCTION block-acceptance seam.
 *
 * Drives `nodus_witness_v2_finalize_block` — the production entry point
 * that dispatches the header version, verifies the certificate against
 * COMMITTED authority through `nodus_witness_v2_qc_verify`, and only
 * then executes and commits the block.
 *
 * SHAPE: the leader/follower split, because that is how a real block is
 * produced. A block header commits roots that are only known AFTER
 * execution, so fixture A executes in LEADER mode to derive the
 * canonical header bytes and the BlockID; a quorum signs THAT id; and
 * the twin fixture B is handed the header + QC through the production
 * seam and must independently derive the same identity. A test that
 * invented a header would be testing nothing.
 *
 * Every rejection is checked against the §13 whole-database logical
 * digest (v2x_db_digest), not against a return code alone.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

/* mkdtemp is POSIX, not ISO C: declare the feature set explicitly so
 * this file is clean under -std=c11 -pedantic on its own, rather than
 * relying on the build's default glibc feature macros. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_finalize.h"
#include "witness/nodus_witness_v2_qc.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "nodus/nodus_chain_config.h"
#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "dnac/vset_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── deterministic keys ─────────────────────────────────────────────── */

#define N_KEYS 7

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];

static int make_keys(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        uint8_t full[64];
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

/* ── fixture ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];
    uint8_t          genesis_id[64];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK ? 0 : -1;
}

/** Seed the N_KEYS validators with their REAL Dilithium pubkeys, so the
 *  committed snapshot the engine resolves is the set we can sign with. */
static int seed_validators(fixture_t *fx) {
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < N_KEYS; i++) {
        dnac_validator_record_t v;
        memset(&v, 0, sizeof(v));
        memcpy(v.pubkey, g_ks[i].pk, DNAC_PUBKEY_SIZE);
        v.self_stake         = 0;   /* supply invariant counts self_stake */
        v.status             = DNAC_VALIDATOR_ACTIVE;
        v.active_since_block = 1;
        uint8_t fpr[64];
        if (qgp_sha3_512(g_ks[i].pk, DNAC_PUBKEY_SIZE, fpr) != 0) return -1;
        for (int b = 0; b < 64; b++) {
            v.unstake_destination_fp[2 * b]     = hexd[fpr[b] >> 4];
            v.unstake_destination_fp[2 * b + 1] = hexd[fpr[b] & 0xF];
        }
        v.unstake_destination_fp[128] = '\0';
        if (nodus_validator_insert(fx->w, &v) != 0) return -1;
    }
    return 0;
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB: never on the stack */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_final_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);

    uint8_t cid16[16];
    memset(cid16, 0x7E, sizeof(cid16));
    if (nodus_witness_create_chain_db(fx->w, cid16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    /* Supply must exist before genesis: the manifest commits it. */
    if (run_sql(fx->w->db,
            "INSERT INTO supply_tracking (id, genesis_supply, total_burned,"
            " total_minted, current_supply, last_tx_hash, last_sequence) "
            "VALUES (1, 0, 0, 0, 0, zeroblob(64), 0)") != 0)
        return -1;

    if (seed_validators(fx) != 0) return -1;
    if (nodus_witness_vset_commit_genesis(fx->w, 1) != 0) return -1;

    uint8_t vset[64];
    memset(vset, 0x77, sizeof(vset));
    if (v2x_genesis_min(fx->w, vset, fx->genesis_id, NULL) != 0) return -1;
    if (nodus_witness_v2_chain_id(fx->w, fx->chain_id) != 0) return -1;
    return 0;
}

static void fx_close(fixture_t *fx) {
    if (fx->w) {
        if (fx->w->db) sqlite3_close(fx->w->db);
        free(fx->w);
        fx->w = NULL;
    }
    if (fx->dir[0]) rmrf(fx->dir);
}

/* ── QC over an arbitrary certified context ─────────────────────────── */

static int cmp_cert(const void *a, const void *b) {
    return memcmp(((const dna_qc_v2_cert_t *)a)->voter_id,
                  ((const dna_qc_v2_cert_t *)b)->voter_id,
                  DNA_CERT_V2_VOTER_ID_LEN);
}

/** Encode a QC over `n` signers for the given certified context.
 *  Returns heap bytes (caller frees) and their length. */
static uint8_t *make_qc_bytes(int n, const uint8_t block_id[64],
                              uint64_t height, const uint8_t chain[32],
                              const uint8_t vsh[64], size_t *out_len) {
    dna_qc_v2_t *qc = dna_qc_v2_alloc((uint16_t)n);
    if (!qc) return NULL;
    for (int i = 0; i < n; i++) {
        memcpy(qc->certs[i].voter_id, g_ks[i].voter, DNA_CERT_V2_VOTER_ID_LEN);
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(block_id, g_ks[i].voter, height, chain,
                                 vsh, pre) != 0) {
            dna_qc_v2_free(&qc);
            return NULL;
        }
        size_t siglen = 0;
        if (qgp_dsa87_sign(qc->certs[i].sig, &siglen, pre, sizeof(pre),
                           g_ks[i].sk) != 0 ||
            siglen != DNA_CERT_V2_SIG_LEN) {
            dna_qc_v2_free(&qc);
            return NULL;
        }
    }
    qsort(qc->certs, (size_t)n, sizeof(qc->certs[0]), cmp_cert);

    size_t cap = DNA_QC_V2_MAX_ENC_LEN;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) { dna_qc_v2_free(&qc); return NULL; }
    size_t used = 0;
    int rc = dna_qc_v2_encode(qc, buf, cap, &used);
    dna_qc_v2_free(&qc);
    if (rc != 0) { free(buf); return NULL; }
    *out_len = used;
    return buf;
}

/* ── the leader/follower drive ──────────────────────────────────────── */

/** Execute an EMPTY block at `h` in leader mode, capturing the canonical
 *  header bytes, the derived id and the resolved set hash. */
static int leader_derive(fixture_t *fx, uint64_t h,
                         uint8_t hdr_out[DNA_BH2_ENC_SIZE],
                         uint8_t id_out[64], uint8_t vsh_out[64]) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    b.epoch         = nodus_v2_epoch_for_height(h);
    memset(b.proposer_id, 0x11, sizeof(b.proposer_id));
    b.timestamp     = 0x0102030405060708ULL;
    if (nodus_witness_v2_apply_block(fx->w, &b) != 0) return -1;
    memcpy(hdr_out, b.out_header, DNA_BH2_ENC_SIZE);
    memcpy(id_out,  b.out_block_id, 64);
    memcpy(vsh_out, b.out_vset_hash, 64);
    return 0;
}

/** Drive the production seam on the follower with a given header/QC. */
static int follower_finalize(fixture_t *fx, const uint8_t *hdr,
                             size_t hdr_len, const uint8_t *qc,
                             size_t qc_len, uint64_t h,
                             nodus_v2_block_t *out_blk) {
    nodus_v2_block_t b;
    memset(&b, 0, sizeof(b));
    b.global_height = h;
    /* epoch/proposer/timestamp are taken from the HEADER by the seam. */
    int rc = nodus_witness_v2_finalize_block(fx->w, hdr, hdr_len, qc,
                                             qc_len, &b);
    if (out_blk) *out_blk = b;
    return rc;
}

/* ── §1 happy path + identity equality ──────────────────────────────── */

static int t_accept(void) {
    printf("1: valid finalized block — seam accepts, ids agree\n");
    fixture_t a, b;
    CHECK(fx_open(&a, "acc_a") == 0, "fx a");
    CHECK(fx_open(&b, "acc_b") == 0, "fx b");
    /* twins: identical genesis ⇒ identical chain id */
    CHECK(memcmp(a.chain_id, b.chain_id, DNA_CHAIN_ID_LEN) == 0,
          "twin fixtures diverged at genesis"); OK();

    uint8_t hdr[DNA_BH2_ENC_SIZE], id[64], vsh[64];
    CHECK(leader_derive(&a, 1, hdr, id, vsh) == 0, "leader derive"); OK();

    size_t qlen = 0;
    uint8_t *qc = make_qc_bytes(5, id, 1, a.chain_id, vsh, &qlen);
    CHECK(qc != NULL, "qc build"); OK();

    nodus_v2_block_t fb;
    CHECK(follower_finalize(&b, hdr, sizeof(hdr), qc, qlen, 1, &fb) == 0,
          "production seam rejected a valid finalized block"); OK();
    CHECK(memcmp(fb.out_block_id, id, 64) == 0,
          "follower derived a DIFFERENT BlockID than the leader"); OK();
    CHECK(memcmp(fb.out_header, hdr, DNA_BH2_ENC_SIZE) == 0,
          "follower rebuilt DIFFERENT header bytes"); OK();

    /* the QC-certified id IS the stored id */
    uint8_t stored[64];
    CHECK(v2x_block_id_at(b.w, 1, stored) == 0, "stored id");
    CHECK(memcmp(stored, id, 64) == 0,
          "stored BlockID != the id the QC certified"); OK();

    /* the stored header bytes reproduce the stored id (restart property) */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(b.w->db,
                  "SELECT header FROM v2_blocks WHERE global_height=1",
                  -1, &st, NULL) == SQLITE_OK, "prep header");
        CHECK(sqlite3_step(st) == SQLITE_ROW &&
              sqlite3_column_bytes(st, 0) == DNA_BH2_ENC_SIZE,
              "stored header shape");
        dna_block_header_v2_t sh;
        uint8_t rid[64];
        CHECK(dna_bh2_decode((const uint8_t *)sqlite3_column_blob(st, 0),
                             DNA_BH2_ENC_SIZE, &sh) == 0, "decode stored");
        sqlite3_finalize(st);
        CHECK(dna_bh2_block_id(&sh, rid) == 0, "rehash stored");
        CHECK(memcmp(rid, stored, 64) == 0,
              "stored header bytes do not reproduce the stored id"); OK();
    }

    /* THE CERTIFICATE IS COMMITTED WITH THE BLOCK. The seam states this
     * as an invariant — "no committed block can ever exist without it" —
     * and nothing asserted it: the column is nullable, the engine binds
     * NULL whenever qc_bytes is absent (legitimate for leader mode), and
     * no test in the tree ever read the column back. Deleting the seam's
     * `blk->qc_bytes = qc_bytes` left the whole suite green.
     * (O14 review R3-F1.) */
    {
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(b.w->db,
                  "SELECT qc FROM v2_blocks WHERE global_height=1",
                  -1, &st, NULL) == SQLITE_OK, "prep qc");
        CHECK(sqlite3_step(st) == SQLITE_ROW, "qc row");
        CHECK(sqlite3_column_type(st, 0) != SQLITE_NULL,
              "committed block has NO certificate"); OK();
        CHECK((size_t)sqlite3_column_bytes(st, 0) == qlen &&
              memcmp(sqlite3_column_blob(st, 0), qc, qlen) == 0,
              "stored certificate differs from the one verified"); OK();
        sqlite3_finalize(st);
    }

    /* idempotent replay THROUGH the seam: rc 1, no writes, same id */
    uint8_t d0[64], d1[64];
    CHECK(v2x_db_digest(b.w, d0) == 0, "digest");
    nodus_v2_block_t rb;
    CHECK(follower_finalize(&b, hdr, sizeof(hdr), qc, qlen, 1, &rb) == 1,
          "replay through the seam is not idempotent"); OK();
    CHECK(v2x_db_digest(b.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "idempotent replay wrote state"); OK();
    CHECK(memcmp(rb.out_block_id, id, 64) == 0,
          "replay served a different identity"); OK();

    free(qc);
    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ── §2 the rejection matrix, each with a whole-DB side-effect proof ── */

static int t_reject_matrix(void) {
    printf("2: rejection matrix — verdict/fault classes, zero side "
           "effects\n");
    fixture_t a, b;
    CHECK(fx_open(&a, "rej_a") == 0, "fx a");
    CHECK(fx_open(&b, "rej_b") == 0, "fx b");

    uint8_t hdr[DNA_BH2_ENC_SIZE], id[64], vsh[64];
    CHECK(leader_derive(&a, 1, hdr, id, vsh) == 0, "leader derive"); OK();
    size_t qlen = 0;
    uint8_t *qc = make_qc_bytes(5, id, 1, a.chain_id, vsh, &qlen);
    CHECK(qc != NULL, "qc build"); OK();

    uint8_t d0[64], d1[64];
    CHECK(v2x_db_digest(b.w, d0) == 0, "entry digest");

#define REJECT(expr, want, label) do {                                    \
        int rc_ = (expr);                                                 \
        CHECK(rc_ == (want), label);                                      \
        CHECK(v2x_db_digest(b.w, d1) == 0 &&                              \
              memcmp(d0, d1, 64) == 0,                                    \
              label " left a database side effect");                      \
        OK();                                                             \
    } while (0)

    /* RETIRED version 2 — a class of its own, never reinterpreted. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[0] = DNA_BH2_VERSION_RETIRED;
        REJECT(follower_finalize(&b, bad, sizeof(bad), qc, qlen, 1, NULL),
               NODUS_V2_RETIRED_VERSION, "retired header version accepted");
    }
    /* UNKNOWN version — separately rejected. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[0] = (uint8_t)(DNA_BH2_VERSION + 7);
        /* O15A: a DIFFERENT class from the retired version above. The two
         * assertions together are what prove the seam can actually tell
         * "your software is too old for this block" from "too new" —
         * previously both were -1 and the distinction existed only in a
         * log line. */
        REJECT(follower_finalize(&b, bad, sizeof(bad), qc, qlen, 1, NULL),
               NODUS_V2_UNSUPPORTED_VERSION, "unknown header version accepted");
    }
    /* Truncated header — no size auto-detection. */
    REJECT(follower_finalize(&b, hdr, DNA_BH2_ENC_SIZE - 1, qc, qlen, 1,
                             NULL),
           -1, "truncated header accepted");
    /* Trailing bytes. */
    {
        uint8_t big[DNA_BH2_ENC_SIZE + 1];
        memcpy(big, hdr, DNA_BH2_ENC_SIZE);
        big[DNA_BH2_ENC_SIZE] = 0;
        REJECT(follower_finalize(&b, big, sizeof(big), qc, qlen, 1, NULL),
               -1, "trailing header bytes accepted");
    }
    /* A LIE about a committed root: the QC still certifies the mutated
     * header's id, so this is not a signature failure — it is the
     * engine's locally derived result disagreeing. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[113] ^= 1;                      /* global_state_root */
        dna_block_header_v2_t bh;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &bh) == 0, "decode mutated");
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&bh, bid) == 0, "id of mutated");
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, bid, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc for mutated");
        REJECT(follower_finalize(&b, bad, sizeof(bad), bqc, bl, 1, NULL),
               -1, "lied global_state_root accepted");
        free(bqc);
    }
    /* domain_updates_root — the commitment O13 exists to add. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[241] ^= 1;                      /* domain_updates_root */
        dna_block_header_v2_t bh;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &bh) == 0, "decode dupd");
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&bh, bid) == 0, "id of dupd");
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, bid, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc for dupd");
        REJECT(follower_finalize(&b, bad, sizeof(bad), bqc, bl, 1, NULL),
               -1, "lied domain_updates_root accepted");
        free(bqc);
    }
    /* tx_count — THE case that isolates the BlockID equality itself.
     * Every other lied field is ALSO covered by a dedicated root/parent/
     * set-hash assertion, so those die before the id is ever compared.
     * tx_count is engine-derived, bound into the BlockID, and asserted
     * NOWHERE else — so a header lying about it can only be caught by
     * "the id I derived must equal the id the QC certified". */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[369] ^= 0x07;                   /* tx_count u32 BE @369 */
        dna_block_header_v2_t bh;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &bh) == 0, "decode txcount");
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&bh, bid) == 0, "id of txcount");
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, bid, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc for txcount");
        REJECT(follower_finalize(&b, bad, sizeof(bad), bqc, bl, 1, NULL),
               -1, "lied tx_count accepted (BlockID equality bypassed)");
        free(bqc);
    }
    /* CROSS-CHAIN: a header naming another chain. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[1] ^= 0xFF;                     /* chain_id */
        dna_block_header_v2_t bh;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &bh) == 0, "decode xchain");
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&bh, bid) == 0, "id of xchain");
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, bid, 1, bh.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc for xchain");
        REJECT(follower_finalize(&b, bad, sizeof(bad), bqc, bl, 1, NULL),
               -1, "cross-chain header accepted");
        free(bqc);
    }
    /* The QC certifies a DIFFERENT id than the header describes. */
    {
        uint8_t other[64];
        memcpy(other, id, 64);
        other[0] ^= 1;
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, other, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc over other id");
        REJECT(follower_finalize(&b, hdr, sizeof(hdr), bqc, bl, 1, NULL),
               -1, "QC over a foreign BlockID accepted");
        free(bqc);
    }
    /* QUORUM: floor(2*7/3)+1 = 5, so 4 signers must fail. */
    {
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(4, id, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "sub-quorum qc");
        REJECT(follower_finalize(&b, hdr, sizeof(hdr), bqc, bl, 1, NULL),
               -1, "sub-quorum QC accepted");
        free(bqc);
    }
    /* Malformed certificate bytes. */
    {
        uint8_t junk[8];
        memset(junk, 0xAB, sizeof(junk));
        REJECT(follower_finalize(&b, hdr, sizeof(hdr), junk, sizeof(junk),
                                 1, NULL),
               -1, "malformed QC accepted");
    }
    /* Header height disagreeing with the block being applied. */
    REJECT(follower_finalize(&b, hdr, sizeof(hdr), qc, qlen, 2, NULL),
           -1, "header for another height accepted");

    /* NULL arguments are a node FAULT, never a verdict about a block. */
    {
        nodus_v2_block_t nb;
        memset(&nb, 0, sizeof(nb));
        REJECT(nodus_witness_v2_finalize_block(b.w, NULL, 0, qc, qlen, &nb),
               -2, "NULL header not classified as a fault");
        REJECT(nodus_witness_v2_finalize_block(b.w, hdr, sizeof(hdr), NULL,
                                               0, &nb),
               -2, "NULL qc not classified as a fault");
        REJECT(nodus_witness_v2_finalize_block(NULL, hdr, sizeof(hdr), qc,
                                               qlen, &nb),
               -2, "NULL witness not classified as a fault");
    }
#undef REJECT

    /* After the whole matrix the follower is still at genesis. */
    CHECK(v2x_block_id_at(b.w, 1, d1) != 0,
          "a rejected block was committed anyway"); OK();

    /* ── proposer_id: an ACCEPT, pinned on purpose ─────────────────────
     * Same isolation argument as tx_count — bound into the BlockID and
     * asserted by no separate field check — but the OPPOSITE verdict,
     * because the seam takes proposer_id FROM the header, so the engine
     * rebuilds the same id. Pinning it documents that proposer_id is
     * block INPUT rather than a commitment the engine can independently
     * check, and stops a future reader from "fixing" it into a reject.
     * Runs last: unlike everything above, this one commits. */
    {
        uint8_t bad[DNA_BH2_ENC_SIZE];
        memcpy(bad, hdr, sizeof(bad));
        bad[373] ^= 0xFF;                   /* proposer_id @373 */
        dna_block_header_v2_t bh;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &bh) == 0, "decode prop");
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&bh, bid) == 0, "id of prop");
        CHECK(memcmp(bid, id, 64) != 0,
              "proposer_id must change the BlockID"); OK();
        size_t bl = 0;
        uint8_t *bqc = make_qc_bytes(5, bid, 1, a.chain_id, vsh, &bl);
        CHECK(bqc != NULL, "qc for prop");
        nodus_v2_block_t pb;
        CHECK(follower_finalize(&b, bad, sizeof(bad), bqc, bl, 1, &pb) == 0,
              "proposer_id is block input — must be accepted"); OK();
        CHECK(memcmp(pb.out_block_id, bid, 64) == 0,
              "engine did not adopt the header's proposer_id"); OK();
        free(bqc);
    }

    free(qc);
    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ── §3 missing authority is a FAULT, not a verdict ─────────────────── */

static int t_missing_authority(void) {
    printf("3: absent committed authority is a FAULT (-2), never -1\n");
    fixture_t a, b;
    CHECK(fx_open(&a, "auth_a") == 0, "fx a");
    CHECK(fx_open(&b, "auth_b") == 0, "fx b");

    uint8_t hdr[DNA_BH2_ENC_SIZE], id[64], vsh[64];
    CHECK(leader_derive(&a, 1, hdr, id, vsh) == 0, "leader derive"); OK();
    size_t qlen = 0;
    uint8_t *qc = make_qc_bytes(5, id, 1, a.chain_id, vsh, &qlen);
    CHECK(qc != NULL, "qc build"); OK();

    /* Remove the committed snapshots: this node can no longer know who
     * was permitted to sign. It must ABSTAIN, not declare the block
     * invalid — silence is survivable at f=2, a confident wrong answer
     * forks the chain. */
    uint8_t d0[64], d1[64];
    CHECK(run_sql(b.w->db, "DELETE FROM validator_set_snapshots") == 0,
          "clear snapshots");
    CHECK(v2x_db_digest(b.w, d0) == 0, "digest");
    CHECK(follower_finalize(&b, hdr, sizeof(hdr), qc, qlen, 1, NULL) == -2,
          "absent authority must be a FAULT, not a verdict"); OK();
    CHECK(v2x_db_digest(b.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
          "fault path wrote state"); OK();

    free(qc);
    fx_close(&a);
    fx_close(&b);
    return 0;
}

/* ── §4 the seam's version firewall selfcheck ───────────────────────── */

static int t_selfcheck(void) {
    printf("4: production version-firewall selfcheck\n");
    fixture_t a;
    CHECK(fx_open(&a, "self") == 0, "fx");
    /* The very fact the fixture opened proves the selfcheck ran and
     * passed inside nodus_witness_create_chain_db — it refuses the
     * database otherwise. Call it directly too, so the LINK EDGE from a
     * test to the production entry point is named and asserted (this is
     * what kills the "make the seam unreachable" mutant). */
    CHECK(nodus_witness_v2_finalize_selfcheck(a.w) == 0,
          "version firewall selfcheck failed"); OK();
    CHECK(nodus_witness_v2_finalize_selfcheck(NULL) == -1,
          "selfcheck NULL handling"); OK();
    fx_close(&a);
    return 0;
}

/* ── §5 F46/F47: the identity seam's own fault points ───────────────── */

static int t_identity_faults(void) {
    printf("5: F46/F47 — interrupting between header build and BlockID\n");
    fixture_t a, b;
    CHECK(fx_open(&a, "flt_a") == 0, "fx a");
    CHECK(fx_open(&b, "flt_b") == 0, "fx b");

    uint8_t hdr[DNA_BH2_ENC_SIZE], id[64], vsh[64];
    CHECK(leader_derive(&a, 1, hdr, id, vsh) == 0, "leader derive"); OK();
    size_t qlen = 0;
    uint8_t *qc = make_qc_bytes(5, id, 1, a.chain_id, vsh, &qlen);
    CHECK(qc != NULL, "qc build"); OK();

    uint8_t d0[64], d1[64];
    CHECK(v2x_db_digest(b.w, d0) == 0, "entry digest");

    /* F46 fires with the canonical header fully reconstructed from
     * locally derived results and NOTHING hashed or written; F47 after
     * the final BlockID has been recomputed and checked, still before
     * the v2_blocks row exists. Together they bracket the exact window
     * in which an interrupt could otherwise leave a persisted id that no
     * execution result produced. */
    static const nodus_v2_apply_fail_t pts[2] = {
        V2AP_FAIL_AFTER_HEADER_BUILD, V2AP_FAIL_AFTER_BLOCK_ID
    };
    static const char *names[2] = { "F46 (header built)",
                                    "F47 (BlockID recomputed)" };
    for (int i = 0; i < 2; i++) {
        nodus_v2_block_t fb;
        memset(&fb, 0, sizeof(fb));
        fb.global_height = 1;
        fb.fail_at       = pts[i];
        CHECK(nodus_witness_v2_finalize_block(b.w, hdr, sizeof(hdr), qc,
                                              qlen, &fb) == -1,
              names[i]); OK();
        CHECK(v2x_db_digest(b.w, d1) == 0 && memcmp(d0, d1, 64) == 0,
              "identity fault point leaked database state"); OK();
        /* no block row, no half-written identity */
        uint8_t probe[64];
        CHECK(v2x_block_id_at(b.w, 1, probe) != 0,
              "a block row survived the identity fault"); OK();
    }

    /* CLEAN RETRY after the faults commits, and derives the SAME
     * identity — the header bytes and BlockID are a deterministic
     * function of committed state and block content, not of how many
     * times the attempt was interrupted. */
    nodus_v2_block_t ok_blk;
    CHECK(follower_finalize(&b, hdr, sizeof(hdr), qc, qlen, 1, &ok_blk)
              == 0, "clean retry after fault injection"); OK();
    CHECK(memcmp(ok_blk.out_block_id, id, 64) == 0,
          "retry derived a DIFFERENT BlockID"); OK();
    CHECK(memcmp(ok_blk.out_header, hdr, DNA_BH2_ENC_SIZE) == 0,
          "retry derived DIFFERENT header bytes"); OK();

    free(qc);
    fx_close(&a);
    fx_close(&b);
    return 0;
}

int main(void) {
    if (make_keys() != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    if (t_accept()) return 1;
    if (t_reject_matrix()) return 1;
    if (t_missing_authority()) return 1;
    if (t_selfcheck()) return 1;
    if (t_identity_faults()) return 1;
    printf("test_v2_finalize: %d checks passed\n", g_checks);
    return 0;
}
