/**
 * Nodus — Ledger V2 O13: QC verification bound to COMMITTED authority.
 *
 * Tests `nodus_witness_v2_qc_verify` (nodus_witness_v2_qc.h), the layer
 * that makes validator-set authority impossible to supply from outside.
 *
 * DIVISION OF LABOUR — this file deliberately does NOT re-test what is
 * already covered elsewhere, and says so rather than duplicating:
 *   · test_qc_v2      — the PURE verifier: codec, strict signer ordering,
 *                       duplicate/non-member signers, quorum arithmetic,
 *                       signature validity, the 216-byte preimage KATs.
 *   · test_v2_epoch   — the RESOLVER: quorum literals for N ∈ {1,2,3,4,6,
 *                       7,12,86,128}, the 128 ceiling, 129 rejection,
 *                       historical immunity, absence semantics.
 *   · test_block_v2   — the v3 header codec, BlockID binding, KATs.
 * What is unique HERE is the SEAM: that the wrapper derives every
 * authority input from committed state and accepts none from the caller.
 *
 * ── ON ROUND / VIEW / PHASE (§12 source-lock, GROUNDED) ───────────────
 * The shipped certificate model is a FINALIZATION certificate, not a
 * per-phase vote. Neither the live 144-byte preimage
 * (nodus_witness_cert.h:11-15 — tag ‖ block_hash ‖ voter_id ‖ height ‖
 * chain_id) nor the V2 216-byte preimage (qc_v2.h:23-28, which adds
 * validator_set_hash) binds a round, a view or a phase. BFT does carry
 * `round`/`view`/`NODUS_W_PHASE_*` (nodus_witness.h:136-142, 169-170),
 * but those are round-state for REACHING the decision; the certificate
 * attests to the decision itself, and under BFT safety at most one block
 * is committed per height. Binding a round would in fact break
 * aggregation across views.
 * Therefore "another-round replay" and "another-phase replay" are tested
 * as DOMAIN-SEPARATION and DIGEST-INPUT properties (§4 below), not as
 * mutations of fields that do not exist. Inventing such fields would be
 * a fabricated mechanism.
 *
 * @file test_v2_qc_authority.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dnac/block_v2.h"
#include "dnac/qc_v2.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_qc.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_cert.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* ── keys ───────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

#define N_KEYS 7

static void derive_voter(const uint8_t *pk, uint8_t out[32]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, 32);
}

/** Deterministic keys — no RNG anywhere in this file. */
static int make_keys(keyset_t *ks, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(ks[i].pk, ks[i].sk, seed) != 0) return -1;
        derive_voter(ks[i].pk, ks[i].voter);
    }
    return 0;
}

static dna_vset_snapshot_t *make_snapshot(const keyset_t *ks, int n,
                                          uint64_t epoch) {
    dna_vset_snapshot_t *s = dna_vset_alloc((uint16_t)n);
    if (!s) return NULL;
    s->epoch = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (int i = 0; i < n; i++) {
        memcpy(s->entries[i].voter_id, ks[i].voter, DNA_VSET_VOTER_ID_LEN);
        memcpy(s->entries[i].pubkey, ks[i].pk, DNA_VSET_PUBKEY_LEN);
        /* Entry 0 holds a DOMINANT majority of the set's stake (>2/3 on its
         * own). This is deliberate: a near-uniform distribution would let
         * the §6 "stake is never vote weight" assertion pass for COUNT
         * reasons without ever probing stake — the M16 mutation campaign
         * caught exactly that vacuity. With this shape, any stake-weighted
         * quorum rule would admit entry 0 alone, so §6 genuinely fails if
         * stake ever becomes weight. */
        s->entries[i].total_stake    = (i == 0) ? 900000000000000ULL
                                                : 1000000ULL + (uint64_t)i;
        s->entries[i].self_bond      = 1000000000000000ULL;
        s->entries[i].commission_bps = (uint16_t)(100 + i);
    }
    return s;
}

static int cmp_cert(const void *a, const void *b) {
    return memcmp(((const dna_qc_v2_cert_t *)a)->voter_id,
                  ((const dna_qc_v2_cert_t *)b)->voter_id,
                  DNA_CERT_V2_VOTER_ID_LEN);
}

/** QC over the listed key indices, signing the given context. */
static dna_qc_v2_t *make_qc(const keyset_t *ks, const int *idx, int n,
                            const uint8_t block_id[64], uint64_t height,
                            const uint8_t chain[32], const uint8_t vsh[64]) {
    dna_qc_v2_t *qc = dna_qc_v2_alloc((uint16_t)n);
    if (!qc) return NULL;
    for (int i = 0; i < n; i++) {
        const keyset_t *k = &ks[idx[i]];
        memcpy(qc->certs[i].voter_id, k->voter, DNA_CERT_V2_VOTER_ID_LEN);
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(block_id, k->voter, height, chain, vsh,
                                 pre) != 0) {
            dna_qc_v2_free(&qc); return NULL;
        }
        size_t siglen = 0;
        if (qgp_dsa87_sign(qc->certs[i].sig, &siglen, pre, sizeof(pre),
                           k->sk) != 0 || siglen != DNA_CERT_V2_SIG_LEN) {
            dna_qc_v2_free(&qc); return NULL;
        }
    }
    qsort(qc->certs, (size_t)n, sizeof(qc->certs[0]), cmp_cert);
    return qc;
}

/* ── fixture ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id16[16];
    uint8_t          chain_id[DNA_CHAIN_ID_LEN];  /* derived */
    uint8_t          genesis_id[64];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort cleanup */ }
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s\n  %s\n", err ? err : "?", sql);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

/** Insert one snapshot row in the EXACT shape nodus_witness_vset_get
 *  validates: blob, its true hash, and a row count/epoch that agree with
 *  the blob. Anything else is rejected there as corruption. */
static int seed_snapshot(fixture_t *fx, const dna_vset_snapshot_t *snap,
                         uint64_t epoch_start) {
    size_t len = dna_vset_encoded_len(snap);
    if (len == 0) return -1;
    uint8_t *blob = malloc(len);
    if (!blob) return -1;
    size_t written = 0;
    if (dna_vset_encode(snap, blob, len, &written) != 0 || written != len) {
        free(blob); return -1;
    }
    uint8_t hash[DNA_VSET_HASH_LEN];
    if (dna_vset_hash_bytes(blob, len, hash) != 0) { free(blob); return -1; }

    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(fx->w->db,
        "INSERT OR REPLACE INTO validator_set_snapshots "
        "(epoch_start, active_count, snapshot_hash, snapshot_blob, "
        " created_at_height) VALUES (?1, ?2, ?3, ?4, 0)", -1, &st, NULL);
    if (rc != SQLITE_OK) { free(blob); return -1; }
    sqlite3_bind_int64(st, 1, (sqlite3_int64)epoch_start);
    sqlite3_bind_int(st, 2, (int)snap->active_count);
    sqlite3_bind_blob(st, 3, hash, DNA_VSET_HASH_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, blob, (int)len, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    free(blob);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/** Genesis v2_blocks row — the ONLY thing this test needs from it is the
 *  block_id that nodus_witness_v2_chain_id derives the chain id from. */
static int seed_genesis_block(fixture_t *fx) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(fx->w->db,
        /* O14 schema v9 carries the canonical header bytes. This fixture
         * only needs a genesis ROW so the chain id derives; it never
         * reads the header back, so a well-sized placeholder is honest
         * here — the header/BlockID agreement itself is proven in
         * test_block_v2 and the apply-engine tests. */
        "INSERT INTO v2_blocks (global_height, block_id, prev_block_id, "
        " epoch, tx_root, domain_updates_root, domains_root, global_root, "
        " vset_hash, tx_count, header, qc) "
        "VALUES (0, ?1, zeroblob(64), 0, zeroblob(64), zeroblob(64), "
        " zeroblob(64), zeroblob(64), zeroblob(64), 0, zeroblob(413), NULL)",
        -1, &st, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_blob(st, 1, fx->genesis_id, 64, SQLITE_TRANSIENT);
    rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_v2_qcauth_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;

    /* A genesis id whose bytes are distinctive, so a chain-id mismatch is
     * obvious rather than accidentally zero. */
    for (int i = 0; i < 64; i++) fx->genesis_id[i] = (uint8_t)(0x11 + i * 3);
    if (seed_genesis_block(fx) != 0) return -1;
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

/** A header consistent with the fixture at `height`, committing `vsh`. */
static void mk_header(dna_block_header_v2_t *h, const fixture_t *fx,
                      uint64_t height, const uint8_t vsh[64]) {
    memset(h, 0, sizeof(*h));
    h->header_version = DNA_BH2_VERSION;
    memcpy(h->chain_id, fx->chain_id, DNA_CHAIN_ID_LEN);
    h->block_height = height;
    h->epoch = nodus_v2_epoch_for_height(height);
    memset(h->prev_block_id, 0xC0, 64);
    memset(h->global_state_root, 0xD0, 64);
    memset(h->tx_root, 0xE0, 64);
    memset(h->domain_updates_root, 0x55, 64);
    memcpy(h->validator_set_hash, vsh, 64);
    h->tx_count = 3;
    memset(h->proposer_id, 0x11, 32);
    h->timestamp = 0x0102030405060708ULL;
}

int main(void) {
    static keyset_t ks[N_KEYS];
    if (make_keys(ks, N_KEYS) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }

    fixture_t fx;
    if (fx_open(&fx, "main") != 0) {
        fprintf(stderr, "fixture setup failed\n");
        fx_close(&fx);
        return 1;
    }

    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t H = E + 3;                 /* inside epoch 1 */
    const uint64_t EPOCH_START = (H / E) * E;

    /* The governing snapshot for H, committed at its epoch key. N = 7, so
     * quorum = floor(2*7/3)+1 = 5 (dna_bft_quorum, ledger_ids.h). */
    dna_vset_snapshot_t *snap = make_snapshot(ks, N_KEYS, EPOCH_START);
    CHECK(snap != NULL, "snapshot alloc");
    CHECK(seed_snapshot(&fx, snap, EPOCH_START) == 0, "seed snapshot"); OK();

    uint8_t vsh[64];
    CHECK(dna_vset_hash(snap, vsh) == 0, "vset hash"); OK();

    /* Sanity: the resolver agrees with what we seeded, and derives N and
     * the quorum itself. */
    {
        uint32_t n = 0, quorum = 0;
        dna_vset_snapshot_t *rs = NULL;
        int rc = nodus_witness_v2_epoch_authority_for_height(fx.w, H, &rs,
                                                             &n, &quorum);
        CHECK(rc == 0, "resolver rc"); OK();
        CHECK(n == N_KEYS, "resolved N"); OK();
        CHECK(quorum == dna_bft_quorum(N_KEYS) && quorum == 5,
              "resolved quorum != 5 for N=7"); OK();
        dna_vset_free(&rs);
    }

    dna_block_header_v2_t hdr;
    mk_header(&hdr, &fx, H, vsh);
    uint8_t block_id[64];
    CHECK(dna_bh2_block_id(&hdr, block_id) == 0, "block id"); OK();

    /* ── §1 POSITIVE ────────────────────────────────────────────────── */
    {
        const int idx[5] = { 0, 1, 2, 3, 4 };          /* exactly quorum */
        dna_qc_v2_t *qc = make_qc(ks, idx, 5, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "qc build");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, qc) == 0,
              "exact-quorum QC rejected"); OK();
        dna_qc_v2_free(&qc);

        const int all7[7] = { 0, 1, 2, 3, 4, 5, 6 };
        qc = make_qc(ks, all7, 7, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "qc build all");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, qc) == 0,
              "all-N QC rejected"); OK();
        dna_qc_v2_free(&qc);

        /* quorum − 1 must fail even though every signature is valid. */
        const int four[4] = { 0, 1, 2, 3 };
        qc = make_qc(ks, four, 4, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "qc build 4");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, qc) == -1,
              "quorum-1 accepted"); OK();
        dna_qc_v2_free(&qc);
    }

    /* ── §2 THE HEADER CANNOT SUPPLY AUTHORITY ──────────────────────── */
    {
        const int idx[5] = { 0, 1, 2, 3, 4 };
        dna_qc_v2_t *qc = make_qc(ks, idx, 5, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "qc build");

        /* A header naming a DIFFERENT validator set. The QC is internally
         * consistent with that claim, so only re-deriving the authority
         * from committed state can catch it. */
        dna_vset_snapshot_t *other = make_snapshot(ks, 4, EPOCH_START);
        CHECK(other != NULL, "other snapshot");
        uint8_t other_vsh[64];
        CHECK(dna_vset_hash(other, other_vsh) == 0, "other hash");
        dna_block_header_v2_t lie;
        mk_header(&lie, &fx, H, other_vsh);
        uint8_t lie_id[64];
        CHECK(dna_bh2_block_id(&lie, lie_id) == 0, "lie id");
        dna_qc_v2_t *lie_qc = make_qc(ks, idx, 5, lie_id, H, fx.chain_id,
                                      other_vsh);
        CHECK(lie_qc != NULL, "lie qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &lie, lie_qc) == -1,
              "header named a foreign validator set and was believed"); OK();
        dna_qc_v2_free(&lie_qc);
        dna_vset_free(&other);

        /* Epoch field lie: a header claiming an epoch that does not match
         * its height must not select a different set. */
        dna_block_header_v2_t bad = hdr;
        bad.epoch = hdr.epoch + 1;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &bad, qc) == -1,
              "epoch field lie accepted"); OK();
        bad = hdr; bad.epoch = 0;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &bad, qc) == -1,
              "epoch 0 lie accepted"); OK();

        /* Chain-id lie — cross-chain replay. */
        bad = hdr; bad.chain_id[0] ^= 1;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &bad, qc) == -1,
              "cross-chain header accepted"); OK();

        /* Retired and unknown header versions. */
        bad = hdr; bad.header_version = DNA_BH2_VERSION_RETIRED;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &bad, qc) == -1,
              "retired header version accepted"); OK();
        bad = hdr; bad.header_version = 4;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &bad, qc) == -1,
              "unknown header version accepted"); OK();

        /* NULL arguments are node-local FAULTS (-2), not verdicts. There is
         * no block to judge, so a caller bug must make this node abstain,
         * never vote a valid block invalid. */
        CHECK(nodus_witness_v2_qc_verify(NULL, &hdr, qc) == -2, "null w"); OK();
        CHECK(nodus_witness_v2_qc_verify(fx.w, NULL, qc) == -2, "null hdr"); OK();
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, NULL) == -2, "null qc"); OK();

        dna_qc_v2_free(&qc);
    }

    /* ── §3 THE QC CERTIFIES THE COMPUTED BlockID ───────────────────── */
    {
        const int idx[5] = { 0, 1, 2, 3, 4 };

        /* Mutating ANY bound header field changes the id the wrapper
         * computes, so signatures gathered over the old id no longer
         * verify. domain_updates_root is the O13 addition — under v2 this
         * substitution was invisible to the certificate. */
        struct { const char *name; size_t off; } fields[] = {
            { "global_state_root",   offsetof(dna_block_header_v2_t,
                                              global_state_root) },
            { "tx_root",             offsetof(dna_block_header_v2_t,
                                              tx_root) },
            { "domain_updates_root", offsetof(dna_block_header_v2_t,
                                              domain_updates_root) },
            { "prev_block_id",       offsetof(dna_block_header_v2_t,
                                              prev_block_id) },
        };
        dna_qc_v2_t *qc = make_qc(ks, idx, 5, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "qc build");
        for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
            dna_block_header_v2_t m = hdr;
            ((uint8_t *)&m)[fields[i].off] ^= 1;
            CHECK(nodus_witness_v2_qc_verify(fx.w, &m, qc) == -1,
                  fields[i].name); OK();
        }

        /* Timestamp is NOT bound: the same QC must still verify. This is
         * the informational-field contract, asserted at the seam. */
        dna_block_header_v2_t ts = hdr;
        ts.timestamp ^= 0xFFFFULL;
        CHECK(nodus_witness_v2_qc_verify(fx.w, &ts, qc) == 0,
              "timestamp leaked into the certified identity"); OK();
        dna_qc_v2_free(&qc);
    }

    /* ── §4 DOMAIN SEPARATION (the round/view/phase argument) ───────── */
    {
        /* Signatures are bound to (block_id, voter, height, chain, set).
         * A cert minted for another HEIGHT cannot be replayed here — this
         * is the property that "another-round replay" reduces to in a
         * finalization-cert model, because a height has exactly one
         * committed block under BFT safety. */
        const int idx[5] = { 0, 1, 2, 3, 4 };
        dna_qc_v2_t *other_h = make_qc(ks, idx, 5, block_id, H + 1,
                                       fx.chain_id, vsh);
        CHECK(other_h != NULL, "other-height qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, other_h) == -1,
              "cert signed for another height replayed"); OK();
        dna_qc_v2_free(&other_h);

        /* A cert bound to another SET hash cannot be replayed under this
         * set, even with the same signers and the same block. */
        uint8_t foreign[64];
        memset(foreign, 0x5A, sizeof(foreign));
        dna_qc_v2_t *other_s = make_qc(ks, idx, 5, block_id, H, fx.chain_id,
                                       foreign);
        CHECK(other_s != NULL, "other-set qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, other_s) == -1,
              "cert bound to a foreign set replayed"); OK();
        dna_qc_v2_free(&other_s);

        /* The V2 cert tag is distinct from the LIVE legacy cert tag, so a
         * legacy 144-byte precommit signature can never satisfy a V2 QC:
         * the two preimages differ in tag, length and field order. */
        CHECK(DNA_CERT_V2_PREIMAGE_LEN != NODUS_WITNESS_CERT_PREIMAGE_LEN,
              "V2 and legacy cert preimages are the same length"); OK();
    }

    /* ── §5 ABSENT AUTHORITY IS A FAULT, NOT A VERDICT ──────────────── */
    {
        /* A height in an epoch with NO committed snapshot. The node cannot
         * know who was allowed to sign, so it must fall silent (-2) rather
         * than declare the block invalid (-1). Returning -1 here would let
         * a node with an incomplete database vote against valid blocks. */
        const uint64_t far_h = EPOCH_START + 100 * E;
        dna_block_header_v2_t fh;
        mk_header(&fh, &fx, far_h, vsh);
        uint8_t fid[64];
        CHECK(dna_bh2_block_id(&fh, fid) == 0, "far id");
        const int idx[5] = { 0, 1, 2, 3, 4 };
        dna_qc_v2_t *qc = make_qc(ks, idx, 5, fid, far_h, fx.chain_id, vsh);
        CHECK(qc != NULL, "far qc");
        int rc = nodus_witness_v2_qc_verify(fx.w, &fh, qc);
        CHECK(rc == -2, "absent snapshot must be a FAULT (-2), not a verdict");
        OK();
        dna_qc_v2_free(&qc);

        /* And the CURRENT set must never be substituted for the missing
         * historical one: a snapshot existing at another epoch does not
         * make the far height verifiable. */
        CHECK(rc != 0, "current set substituted for absent historical set");
        OK();
    }

    /* ── §6 STAKE IS NEVER VOTE WEIGHT ──────────────────────────────── */
    {
        /* The single highest-staked member alone must not satisfy quorum,
         * even though its stake exceeds the combined stake of the five
         * that legitimately do. */
        const int rich[1] = { 0 };
        dna_qc_v2_t *qc = make_qc(ks, rich, 1, block_id, H, fx.chain_id, vsh);
        CHECK(qc != NULL, "rich qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, qc) == -1,
              "stake bought a quorum"); OK();
        dna_qc_v2_free(&qc);
    }

    /* ── §7 TWO COMMITTED SETS — HISTORICAL IMMUNITY ────────────────── */
    /* Added because the M13 mutation campaign exposed that a single-snapshot
     * fixture cannot distinguish "wrong set" from "no set": re-keying the
     * resolver merely found nothing. With TWO different committed sets the
     * wrong-set path is exercised for real.
     *
     * Set B governs the NEXT epoch and is a strict subset (4 of the 7
     * members), so it has a different hash, a different N and a different
     * quorum — and keys 4..6 are members of A but NOT of B. */
    {
        const uint64_t EPOCH_B = EPOCH_START + E;
        const uint64_t HB = EPOCH_B + 1;
        dna_vset_snapshot_t *snapB = make_snapshot(ks, 4, EPOCH_B);
        CHECK(snapB != NULL, "snapshot B alloc");
        CHECK(seed_snapshot(&fx, snapB, EPOCH_B) == 0, "seed snapshot B");
        OK();
        uint8_t vshB[64];
        CHECK(dna_vset_hash(snapB, vshB) == 0, "vset hash B"); OK();
        CHECK(memcmp(vshB, vsh, 64) != 0, "A and B hash identically"); OK();

        /* The resolver must serve B — different N, different quorum. */
        {
            uint32_t n = 0, quorum = 0;
            dna_vset_snapshot_t *rs = NULL;
            CHECK(nodus_witness_v2_epoch_authority_for_height(fx.w, HB, &rs,
                                                              &n, &quorum) == 0,
                  "resolve B");
            CHECK(n == 4 && quorum == dna_bft_quorum(4) && quorum == 3,
                  "set B did not yield N=4 quorum=3"); OK();
            dna_vset_free(&rs);
        }

        dna_block_header_v2_t hb;
        mk_header(&hb, &fx, HB, vshB);
        uint8_t bid[64];
        CHECK(dna_bh2_block_id(&hb, bid) == 0, "B block id");

        /* Own-set acceptance: 3 of B's 4 members is exactly B's quorum. */
        const int b3[3] = { 0, 1, 2 };
        dna_qc_v2_t *qcb = make_qc(ks, b3, 3, bid, HB, fx.chain_id, vshB);
        CHECK(qcb != NULL, "B qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hb, qcb) == 0,
              "valid QC under its own committed set rejected"); OK();
        dna_qc_v2_free(&qcb);

        /* WRONG-SET REPLAY: a QC gathered under set A, presented at a height
         * governed by set B. Every signature is genuine and every signer is
         * a real validator — but not under the set that governs HB. This is
         * the assertion M13 must die on. */
        dna_block_header_v2_t hb_lie;
        mk_header(&hb_lie, &fx, HB, vsh);          /* header names set A */
        uint8_t lid[64];
        CHECK(dna_bh2_block_id(&hb_lie, lid) == 0, "B-lie id");
        const int a5[5] = { 0, 1, 2, 3, 4 };
        dna_qc_v2_t *qca = make_qc(ks, a5, 5, lid, HB, fx.chain_id, vsh);
        CHECK(qca != NULL, "A-set qc at B height");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hb_lie, qca) == -1,
              "set-A QC accepted at a height governed by set B"); OK();
        dna_qc_v2_free(&qca);

        /* NON-MEMBER OF B: keys 4..6 are in A but not in B. A quorum-sized
         * QC that includes one of them must fail under B even though the
         * signer is a legitimate validator in the other epoch. */
        const int mixed[3] = { 0, 1, 5 };
        dna_qc_v2_t *qcm = make_qc(ks, mixed, 3, bid, HB, fx.chain_id, vshB);
        CHECK(qcm != NULL, "mixed qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hb, qcm) == -1,
              "a validator from another epoch counted toward this quorum");
        OK();
        dna_qc_v2_free(&qcm);

        /* And the ORIGINAL height still verifies under set A — committing B
         * did not retroactively change who governed H. */
        const int a5b[5] = { 0, 1, 2, 3, 4 };
        dna_qc_v2_t *qch = make_qc(ks, a5b, 5, block_id, H, fx.chain_id, vsh);
        CHECK(qch != NULL, "H qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &hdr, qch) == 0,
              "a later committed set changed a historical verdict"); OK();
        dna_qc_v2_free(&qch);

        dna_vset_free(&snapB);
    }

    /* ── §8 GATE ISOLATION ──────────────────────────────────────────── */
    /* Independent review (R3) showed that §2's negatives do NOT isolate the
     * wrapper's own gates. Every field those gates guard (chain_id@1,
     * block_height@33, epoch@41, validator_set_hash@305) is ALSO bound into
     * the BlockID preimage, and the QC signs the BlockID — so a naive
     * negative is caught by the signature check even if the gate is deleted.
     * The suite would stay green with the gates removed.
     *
     * Each case below is built so that EVERYTHING the shared verifier
     * checks already agrees: the QC is signed over the BlockID computed
     * from the LYING header, using the DERIVED chain id and the RESOLVED
     * set hash — exactly the values the wrapper passes down. The signature
     * path therefore succeeds, and ONLY the wrapper's own gate can reject.
     * Delete the gate and the block is ACCEPTED — which is the bug these
     * assertions exist to catch. */
    {
        const int q5[5] = { 0, 1, 2, 3, 4 };

        /* E1 — isolates the epoch-field gate. */
        dna_block_header_v2_t e1;
        mk_header(&e1, &fx, H, vsh);
        e1.epoch = hdr.epoch + 1;                 /* inconsistent with H */
        uint8_t e1id[64];
        CHECK(dna_bh2_block_id(&e1, e1id) == 0, "e1 id");
        dna_qc_v2_t *q1 = make_qc(ks, q5, 5, e1id, H, fx.chain_id, vsh);
        CHECK(q1 != NULL, "e1 qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &e1, q1) == -1,
              "epoch gate not load-bearing: header epoch inconsistent with "
              "its height was accepted"); OK();
        dna_qc_v2_free(&q1);

        /* E2 — isolates the chain-binding gate. The QC is signed with the
         * chain id the WRAPPER derives, so only the gate can notice that
         * the header names a different chain. */
        dna_block_header_v2_t e2;
        mk_header(&e2, &fx, H, vsh);
        e2.chain_id[0] ^= 1;
        uint8_t e2id[64];
        CHECK(dna_bh2_block_id(&e2, e2id) == 0, "e2 id");
        dna_qc_v2_t *q2 = make_qc(ks, q5, 5, e2id, H, fx.chain_id, vsh);
        CHECK(q2 != NULL, "e2 qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &e2, q2) == -1,
              "chain gate not load-bearing: foreign-chain header accepted");
        OK();
        dna_qc_v2_free(&q2);

        /* E3 — isolates the validator-set COMMITMENT gate. This is the one
         * with real teeth: the QC is signed over the RESOLVED set hash, so
         * the shared verifier's own snapshot-vs-claim check is satisfied,
         * and every signer is a genuine member meeting quorum. Without the
         * wrapper's comparison, a block whose header LIES about which set
         * governs it verifies successfully. */
        dna_vset_snapshot_t *foreign = make_snapshot(ks, 4, EPOCH_START);
        CHECK(foreign != NULL, "e3 foreign snapshot");
        uint8_t foreign_vsh[64];
        CHECK(dna_vset_hash(foreign, foreign_vsh) == 0, "e3 foreign hash");
        CHECK(memcmp(foreign_vsh, vsh, 64) != 0, "e3 hashes collide");
        dna_block_header_v2_t e3;
        mk_header(&e3, &fx, H, foreign_vsh);      /* header names the lie */
        uint8_t e3id[64];
        CHECK(dna_bh2_block_id(&e3, e3id) == 0, "e3 id");
        /* signed over the RESOLVED hash — the shared verifier is happy */
        dna_qc_v2_t *q3 = make_qc(ks, q5, 5, e3id, H, fx.chain_id, vsh);
        CHECK(q3 != NULL, "e3 qc");
        CHECK(nodus_witness_v2_qc_verify(fx.w, &e3, q3) == -1,
              "validator-set commitment gate not load-bearing: a header "
              "lying about its governing set was accepted"); OK();
        dna_qc_v2_free(&q3);
        dna_vset_free(&foreign);
    }

    dna_vset_free(&snap);
    fx_close(&fx);
    printf("test_v2_qc_authority: %d checks OK\n", g_checks);
    return 0;
}
