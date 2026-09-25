/**
 * Nodus — Ledger V2 S3: QC V2 tests (INACTIVE layer).
 *
 * Sections:
 *   1. Preimage: exact 216-byte length + oracle-pinned prefix and digest
 *      (python3 hashlib.sha3_512 — same discipline as test_roots_v2.c).
 *   2. Quorum table: dna_bft_quorum at the sizes that matter, and the
 *      verify path's N == 0 / N > 128 snapshot rejects.
 *   3. QC codec: round-trip byte identity, exact length, and the
 *      count / sort / duplicate negatives.
 *   4. REAL-KEY adversarial suite over N=4 Dilithium5 validators:
 *      below/at/above quorum, over-N count, duplicate signer, non-member,
 *      unsorted, wrong block_id / height / chain_id / vset_hash, a
 *      different-snapshot verify, a cross-signer signature swap, and the
 *      key-rotation (pubkey-from-snapshot) case.
 *   5. N=30 verify benchmark — INFORMATIONAL ONLY, never asserted.
 *
 * Keys come from qgp_dsa87_keypair_derand with fixed seeds, so the whole
 * test is bit-reproducible: no run can pass or fail on key luck.
 *
 * @file test_qc_v2.c
 */

#include "dnac/qc_v2.h"
#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4]; out[2 * i + 1] = d[b[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* ── 1: preimage KAT ────────────────────────────────────────────────── */

static const char *KAT_PRE48 =
    "444e412e434552542e763200000000001111111111111111111111111111111111111111111111111111111111111111";
static const char *KAT_PRE_HASH =
    "34a15fe957df527f7456e483a676183ffa710c20b3536fb952ce110795d10b05"
    "ce6da939fa8584a9e0d4be07309160363600c6ebaef47d8a9e992027a3380489";

static int test_preimage(void) {
    uint8_t block_id[64], voter[32], chain[32], vsh[64];
    memset(block_id, 0x11, sizeof(block_id));
    memset(voter,    0x22, sizeof(voter));
    memset(chain,    0x33, sizeof(chain));
    memset(vsh,      0x44, sizeof(vsh));

    uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
    CHECK(DNA_CERT_V2_PREIMAGE_LEN == 216, "preimage length drifted"); OK();
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, pre) == 0,
          "preimage");

    char hex[2 * 48 + 1];
    to_hex(pre, 48, hex);
    CHECK(strcmp(hex, KAT_PRE48) == 0, "preimage prefix KAT"); OK();

    uint8_t h[64];
    CHECK(qgp_sha3_512(pre, sizeof(pre), h) == 0, "sha3");
    char hh[129];
    to_hex(h, 64, hh);
    CHECK(strcmp(hh, KAT_PRE_HASH) == 0, "preimage digest KAT"); OK();

    /* Every field is bound: change one input, the preimage must change. */
    uint8_t p2[DNA_CERT_V2_PREIMAGE_LEN];
    block_id[0] ^= 1;
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, p2) == 0 &&
          memcmp(pre, p2, sizeof(pre)) != 0, "block_id not bound"); OK();
    block_id[0] ^= 1;
    voter[0] ^= 1;
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, p2) == 0 &&
          memcmp(pre, p2, sizeof(pre)) != 0, "voter_id not bound"); OK();
    voter[0] ^= 1;
    CHECK(dna_cert_v2_preimage(block_id, voter, 43, chain, vsh, p2) == 0 &&
          memcmp(pre, p2, sizeof(pre)) != 0, "height not bound"); OK();
    chain[31] ^= 1;
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, p2) == 0 &&
          memcmp(pre, p2, sizeof(pre)) != 0, "chain_id not bound"); OK();
    chain[31] ^= 1;
    vsh[63] ^= 1;
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, p2) == 0 &&
          memcmp(pre, p2, sizeof(pre)) != 0, "vset_hash not bound"); OK();
    vsh[63] ^= 1;

    CHECK(dna_cert_v2_preimage(NULL, voter, 42, chain, vsh, p2) != 0,
          "NULL block_id"); OK();
    CHECK(dna_cert_v2_preimage(block_id, voter, 42, chain, vsh, NULL) != 0,
          "NULL out"); OK();
    return 0;
}

/* ── 2: quorum table ────────────────────────────────────────────────── */

static int test_quorum_table(void) {
    struct { uint32_t n, q; } t[] = {
        { 7, 5 }, { 8, 6 }, { 9, 7 }, { 15, 11 }, { 30, 21 }, { 128, 86 },
    };
    for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        CHECK(dna_bft_quorum(t[i].n) == t[i].q, "quorum table"); OK();
    }
    return 0;
}

/* ── Real-key harness ───────────────────────────────────────────────── */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[DNA_VSET_VOTER_ID_LEN];
} keyset_t;

/**
 * voter_id = SHA3-512(pubkey)[0..31] — the derivation shipped as
 * nodus_chain_config_derive_witness_id (nodus_witness_chain_config.c:498),
 * replicated locally so this test links only the shared layer. That the
 * production helper agrees with it is pinned in test_vset_persist.c.
 */
static void derive_voter(const uint8_t *pk, uint8_t out[32]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, 32);
}

/** Deterministic keys: seed = 0x40 + index, repeated 32×. */
static int make_keys(keyset_t *ks, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(ks[i].pk, ks[i].sk, seed) != 0) return -1;
        derive_voter(ks[i].pk, ks[i].voter);
    }
    return 0;
}

/** Snapshot over ks[0..n) — stake fields are set but must never matter. */
static dna_vset_snapshot_t *make_snapshot(const keyset_t *ks, int n,
                                          uint64_t epoch, uint64_t stake_base) {
    dna_vset_snapshot_t *s = dna_vset_alloc((uint16_t)n);
    if (!s) return NULL;
    s->epoch = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (int i = 0; i < n; i++) {
        memcpy(s->entries[i].voter_id, ks[i].voter, DNA_VSET_VOTER_ID_LEN);
        memcpy(s->entries[i].pubkey, ks[i].pk, DNA_VSET_PUBKEY_LEN);
        s->entries[i].total_stake    = stake_base - (uint64_t)i;
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

/**
 * Build a QC from the listed key indices. `sorted` selects canonical
 * (ascending) order; when 0 the list is reversed after sorting, which for
 * n >= 2 is strictly DESCENDING — the unsorted negative.
 */
static dna_qc_v2_t *make_qc(const keyset_t *ks, const int *idx, int n,
                            const uint8_t block_id[64], uint64_t height,
                            const uint8_t chain[32], const uint8_t vsh[64],
                            int sorted) {
    dna_qc_v2_t *qc = dna_qc_v2_alloc((uint16_t)n);
    if (!qc) return NULL;
    for (int i = 0; i < n; i++) {
        const keyset_t *k = &ks[idx[i]];
        memcpy(qc->certs[i].voter_id, k->voter, DNA_CERT_V2_VOTER_ID_LEN);
        uint8_t pre[DNA_CERT_V2_PREIMAGE_LEN];
        if (dna_cert_v2_preimage(block_id, k->voter, height, chain, vsh,
                                 pre) != 0) {
            dna_qc_v2_free(&qc);
            return NULL;
        }
        size_t siglen = 0;
        if (qgp_dsa87_sign(qc->certs[i].sig, &siglen, pre, sizeof(pre),
                           k->sk) != 0 ||
            siglen != DNA_CERT_V2_SIG_LEN) {
            dna_qc_v2_free(&qc);
            return NULL;
        }
    }
    qsort(qc->certs, (size_t)n, sizeof(qc->certs[0]), cmp_cert);
    if (!sorted) {
        for (int i = 0, j = n - 1; i < j; i++, j--) {
            dna_qc_v2_cert_t t = qc->certs[i];
            qc->certs[i] = qc->certs[j];
            qc->certs[j] = t;
        }
    }
    return qc;
}

/* ── 3: QC codec ────────────────────────────────────────────────────── */

static int test_qc_codec(const keyset_t *ks, const uint8_t block_id[64],
                         const uint8_t chain[32], const uint8_t vsh[64]) {
    int idx3[3] = { 0, 1, 2 };
    dna_qc_v2_t *qc = make_qc(ks, idx3, 3, block_id, 7, chain, vsh, 1);
    CHECK(qc != NULL, "make_qc");

    size_t need = dna_qc_v2_encoded_len(qc);
    CHECK(need == (size_t)DNA_QC_V2_HDR_LEN + 3u * DNA_QC_V2_CERT_LEN,
          "qc length"); OK();
    CHECK(DNA_QC_V2_CERT_LEN == 4659, "cert record drifted"); OK();

    uint8_t *b1 = malloc(need), *b2 = malloc(need);
    CHECK(b1 && b2, "alloc");
    size_t w = 0;
    CHECK(dna_qc_v2_encode(qc, b1, need, &w) == 0 && w == need, "encode");
    OK();

    dna_qc_v2_t *d = NULL;
    CHECK(dna_qc_v2_decode(b1, need, &d) == 0, "decode"); OK();
    CHECK(d->n_certs == 3, "n_certs"); OK();
    CHECK(dna_qc_v2_encode(d, b2, need, NULL) == 0 &&
          memcmp(b1, b2, need) == 0, "QC round-trip not byte-identical");
    OK();

    /* Exact length. */
    dna_qc_v2_t *x = NULL;
    CHECK(dna_qc_v2_decode(b1, need - 1, &x) != 0, "truncated decoded"); OK();
    uint8_t *bt = malloc(need + 1);
    CHECK(bt != NULL, "alloc");
    memcpy(bt, b1, need); bt[need] = 0;
    CHECK(dna_qc_v2_decode(bt, need + 1, &x) != 0, "trailing decoded"); OK();
    free(bt);
    CHECK(dna_qc_v2_decode(b1, 1, &x) != 0, "sub-header decoded"); OK();

    /* Count bounds — checked before allocation. */
    uint8_t hdr[DNA_QC_V2_HDR_LEN] = { 0, 0 };
    CHECK(dna_qc_v2_decode(hdr, sizeof(hdr), &x) != 0, "count 0 decoded");
    OK();
    CHECK(dna_qc_v2_alloc(0) == NULL, "alloc(0)"); OK();
    CHECK(dna_qc_v2_alloc(129) == NULL, "alloc(129)"); OK();
    {
        size_t n129 = (size_t)DNA_QC_V2_HDR_LEN + 129u * DNA_QC_V2_CERT_LEN;
        uint8_t *big = calloc(1, n129);
        CHECK(big != NULL, "alloc");
        big[0] = 0; big[1] = 129;
        CHECK(dna_qc_v2_decode(big, n129, &x) != 0, "count 129 decoded"); OK();
        free(big);
    }

    /* Unsorted encode must reject. */
    dna_qc_v2_t *un = make_qc(ks, idx3, 3, block_id, 7, chain, vsh, 0);
    CHECK(un != NULL, "make_qc unsorted");
    CHECK(dna_qc_v2_encode(un, b2, need, NULL) != 0, "encoded unsorted"); OK();
    CHECK(dna_qc_v2_encoded_len(un) == 0, "len(unsorted)"); OK();
    /* ...and the same bytes must not decode. */
    memcpy(b2, b1, need);
    {
        uint8_t tmp[DNA_QC_V2_CERT_LEN];
        uint8_t *c0 = b2 + DNA_QC_V2_HDR_LEN;
        uint8_t *c2 = c0 + 2 * DNA_QC_V2_CERT_LEN;
        memcpy(tmp, c0, DNA_QC_V2_CERT_LEN);
        memcpy(c0, c2, DNA_QC_V2_CERT_LEN);
        memcpy(c2, tmp, DNA_QC_V2_CERT_LEN);
        CHECK(dna_qc_v2_decode(b2, need, &x) != 0, "decoded swapped order");
        OK();
    }
    /* Duplicate signer on the wire (cert 1 := cert 0). */
    memcpy(b2, b1, need);
    memcpy(b2 + DNA_QC_V2_HDR_LEN + DNA_QC_V2_CERT_LEN,
           b2 + DNA_QC_V2_HDR_LEN, DNA_QC_V2_CERT_LEN);
    CHECK(dna_qc_v2_decode(b2, need, &x) != 0, "decoded duplicate signer");
    OK();

    dna_qc_v2_free(&un);
    dna_qc_v2_free(&d);
    dna_qc_v2_free(&qc);
    free(b1); free(b2);
    return 0;
}

/* ── 4: real-key adversarial suite ──────────────────────────────────── */

static int test_adversarial(void) {
    /* 4 members + 1 outsider. */
    keyset_t *ks = calloc(5, sizeof(*ks));
    CHECK(ks != NULL, "alloc keys");
    CHECK(make_keys(ks, 5) == 0, "keygen");

    uint8_t block_id[64], chain[32], vsh[64];
    memset(block_id, 0x5A, sizeof(block_id));
    memset(chain,    0x6B, sizeof(chain));
    const uint64_t height = 4096;

    dna_vset_snapshot_t *S = make_snapshot(ks, 4, 720, 5000000000000000ULL);
    CHECK(S != NULL, "snapshot");
    CHECK(dna_vset_hash(S, vsh) == 0, "vset hash");

    const uint32_t quorum = dna_bft_quorum(4);
    CHECK(quorum == 3, "quorum(4) != 3"); OK();

    if (test_qc_codec(ks, block_id, chain, vsh) != 0) return 1;

    int idx[5] = { 0, 1, 2, 3, 4 };

    /* -- count band: 2 reject, 3 accept, 4 accept ------------------- */
    {
        dna_qc_v2_t *q2 = make_qc(ks, idx, 2, block_id, height, chain, vsh, 1);
        CHECK(q2 != NULL, "qc2");
        CHECK(dna_qc_v2_verify(q2, block_id, height, chain, vsh, S) != 0,
              "below-quorum QC accepted"); OK();
        dna_qc_v2_free(&q2);

        dna_qc_v2_t *q3 = make_qc(ks, idx, 3, block_id, height, chain, vsh, 1);
        CHECK(q3 != NULL, "qc3");
        CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh, S) == 0,
              "exact-quorum QC rejected"); OK();

        dna_qc_v2_t *q4 = make_qc(ks, idx, 4, block_id, height, chain, vsh, 1);
        CHECK(q4 != NULL, "qc4");
        CHECK(dna_qc_v2_verify(q4, block_id, height, chain, vsh, S) == 0,
              "full-set QC rejected"); OK();

        /* -- 5 certs: more signers than the set has members ---------- */
        dna_qc_v2_t *q5 = make_qc(ks, idx, 5, block_id, height, chain, vsh, 1);
        CHECK(q5 != NULL, "qc5");
        CHECK(dna_qc_v2_verify(q5, block_id, height, chain, vsh, S) != 0,
              "over-N QC accepted"); OK();
        dna_qc_v2_free(&q5);

        /* -- non-member: the outsider replaces a member -------------- */
        int idx_out[3] = { 0, 1, 4 };
        dna_qc_v2_t *qo = make_qc(ks, idx_out, 3, block_id, height, chain,
                                  vsh, 1);
        CHECK(qo != NULL, "qc outsider");
        CHECK(dna_qc_v2_verify(qo, block_id, height, chain, vsh, S) != 0,
              "non-member QC accepted"); OK();
        dna_qc_v2_free(&qo);

        /* -- duplicate signer at quorum size ------------------------- */
        int idx_dup[3] = { 0, 0, 1 };
        dna_qc_v2_t *qd = make_qc(ks, idx_dup, 3, block_id, height, chain,
                                  vsh, 1);
        CHECK(qd != NULL, "qc dup");
        CHECK(dna_qc_v2_verify(qd, block_id, height, chain, vsh, S) != 0,
              "duplicate-signer QC accepted"); OK();
        dna_qc_v2_free(&qd);

        /* -- unsorted (strictly descending) -------------------------- */
        dna_qc_v2_t *qu = make_qc(ks, idx, 3, block_id, height, chain, vsh, 0);
        CHECK(qu != NULL, "qc unsorted");
        CHECK(dna_qc_v2_verify(qu, block_id, height, chain, vsh, S) != 0,
              "unsorted QC accepted"); OK();
        dna_qc_v2_free(&qu);

        /* -- wrong context: block_id / height / chain_id -------------
         * Full byte sweeps: no single byte of the bound context may be
         * changed without invalidating the whole QC. */
        for (int i = 0; i < 64; i++) {
            uint8_t bad[64];
            memcpy(bad, block_id, 64);
            bad[i] ^= 0x01;
            CHECK(dna_qc_v2_verify(q3, bad, height, chain, vsh, S) != 0,
                  "QC accepted under a mutated block_id"); OK();
        }
        for (int i = 0; i < 32; i++) {
            uint8_t bad[32];
            memcpy(bad, chain, 32);
            bad[i] ^= 0x01;
            CHECK(dna_qc_v2_verify(q3, block_id, height, bad, vsh, S) != 0,
                  "QC accepted under a mutated chain_id"); OK();
        }
        CHECK(dna_qc_v2_verify(q3, block_id, height + 1, chain, vsh, S) != 0,
              "QC accepted at height+1"); OK();
        CHECK(dna_qc_v2_verify(q3, block_id, height - 1, chain, vsh, S) != 0,
              "QC accepted at height-1"); OK();
        CHECK(dna_qc_v2_verify(q3, block_id, 0, chain, vsh, S) != 0,
              "QC accepted at height 0"); OK();

        /* -- wrong vset_hash: caught at step 1, because the supplied
         *    snapshot no longer hashes to the committed value. -------- */
        for (int i = 0; i < 64; i++) {
            uint8_t bad[64];
            memcpy(bad, vsh, 64);
            bad[i] ^= 0x01;
            CHECK(dna_qc_v2_verify(q3, block_id, height, chain, bad, S) != 0,
                  "QC accepted under a mutated vset_hash"); OK();
        }

        /* -- a DIFFERENT snapshot, verified against ITS OWN hash: this
         *    passes step 1, so the reject can only come from the
         *    preimage's validator_set_hash binding at step 6. --------- */
        {
            dna_vset_snapshot_t *S2 =
                make_snapshot(ks, 4, 720, 7777777777777777ULL);
            CHECK(S2 != NULL, "snapshot 2");
            uint8_t vsh2[64];
            CHECK(dna_vset_hash(S2, vsh2) == 0, "hash 2");
            CHECK(memcmp(vsh, vsh2, 64) != 0, "snapshots collided"); OK();
            CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh2, S2) != 0,
                  "QC replayed onto a different validator set"); OK();
            /* And the honest QC still verifies against its own set — the
             * rejects above are not a blanket failure. */
            CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh, S) == 0,
                  "honest QC broke"); OK();
            dna_vset_free(&S2);
        }

        /* -- cross-signer signature swap: cert i keeps its voter_id but
         *    carries cert j's signature. Proves the signature is bound to
         *    the voter_id in ITS OWN preimage. ------------------------- */
        {
            dna_qc_v2_t *qs = make_qc(ks, idx, 3, block_id, height, chain,
                                      vsh, 1);
            CHECK(qs != NULL, "qc swap");
            uint8_t tmp[DNA_CERT_V2_SIG_LEN];
            memcpy(tmp, qs->certs[0].sig, DNA_CERT_V2_SIG_LEN);
            memcpy(qs->certs[0].sig, qs->certs[1].sig, DNA_CERT_V2_SIG_LEN);
            memcpy(qs->certs[1].sig, tmp, DNA_CERT_V2_SIG_LEN);
            CHECK(dna_qc_v2_verify(qs, block_id, height, chain, vsh, S) != 0,
                  "QC accepted with swapped signatures"); OK();
            dna_qc_v2_free(&qs);
        }

        /* -- a single corrupted signature byte sinks the whole QC ---- */
        {
            dna_qc_v2_t *qb = make_qc(ks, idx, 4, block_id, height, chain,
                                      vsh, 1);
            CHECK(qb != NULL, "qc bitflip");
            qb->certs[3].sig[0] ^= 0x01;      /* the LAST cert checked */
            CHECK(dna_qc_v2_verify(qb, block_id, height, chain, vsh, S) != 0,
                  "one bad signature did not sink the QC"); OK();
            dna_qc_v2_free(&qb);
        }

        /* -- stake must never influence the decision ------------------
         * Rewriting the stake fields changes the snapshot hash, so the
         * honest comparison is: a snapshot with DIFFERENT stakes but the
         * same members, with certs re-signed over ITS hash, still needs
         * exactly quorum-many signers — never fewer, never more. */
        {
            dna_vset_snapshot_t *Sw =
                make_snapshot(ks, 4, 720, 9000000000000000ULL);
            CHECK(Sw != NULL, "snapshot w");
            /* One member gets an overwhelming stake; quorum is unmoved. */
            Sw->entries[0].total_stake = 0xFFFFFFFFFFFFFFFFULL;
            uint8_t vshw[64];
            CHECK(dna_vset_hash(Sw, vshw) == 0, "hash w");
            int one[1] = { 0 };
            dna_qc_v2_t *q1 = make_qc(ks, one, 1, block_id, height, chain,
                                      vshw, 1);
            CHECK(q1 != NULL, "qc1");
            CHECK(dna_qc_v2_verify(q1, block_id, height, chain, vshw, Sw) != 0,
                  "a single high-stake signer met quorum"); OK();
            dna_qc_v2_free(&q1);
            dna_qc_v2_t *q3w = make_qc(ks, idx, 3, block_id, height, chain,
                                       vshw, 1);
            CHECK(q3w != NULL, "qc3w");
            CHECK(dna_qc_v2_verify(q3w, block_id, height, chain, vshw, Sw) == 0,
                  "quorum QC rejected on the restaked set"); OK();
            dna_qc_v2_free(&q3w);
            dna_vset_free(&Sw);
        }

        /* -- key rotation / pubkey-from-snapshot ---------------------
         * S1 binds voter V to key K1; S2 binds the SAME voter_id to a
         * DIFFERENT key K2. A cert signed with K1 must verify against S1
         * and REJECT against S2.
         *
         * HONEST LABEL: in production voter_id is DERIVED from the key
         * (SHA3-512(pubkey)[0..31]), so this exact pair cannot arise on
         * chain. It is constructed deliberately, because it is the only
         * way to isolate the property under test — that verify reads the
         * pubkey COMMITTED IN THE SNAPSHOT ENTRY rather than deriving or
         * looking one up elsewhere. */
        {
            keyset_t *rot = calloc(4, sizeof(*rot));
            CHECK(rot != NULL, "alloc rot");
            memcpy(rot, ks, 4 * sizeof(*ks));
            /* S1: as-is. S2: member 0 keeps voter_id, gains key #4. */
            dna_vset_snapshot_t *S1 =
                make_snapshot(rot, 4, 900, 5000000000000000ULL);
            CHECK(S1 != NULL, "S1");
            uint8_t h1[64];
            CHECK(dna_vset_hash(S1, h1) == 0, "hash S1");

            dna_vset_snapshot_t *S2r =
                make_snapshot(rot, 4, 900, 5000000000000000ULL);
            CHECK(S2r != NULL, "S2r");
            memcpy(S2r->entries[0].pubkey, ks[4].pk, DNA_VSET_PUBKEY_LEN);
            uint8_t h2[64];
            CHECK(dna_vset_hash(S2r, h2) == 0, "hash S2r");
            CHECK(memcmp(h1, h2, 64) != 0, "rotation did not change the hash");
            OK();

            /* Certs signed with the ORIGINAL keys, over S1's hash. */
            dna_qc_v2_t *qr = make_qc(rot, idx, 3, block_id, height, chain,
                                      h1, 1);
            CHECK(qr != NULL, "qc rot");
            CHECK(dna_qc_v2_verify(qr, block_id, height, chain, h1, S1) == 0,
                  "historical QC rejected against its own snapshot"); OK();

            /* Re-sign over S2r's hash so step 1 and the preimage agree;
             * the ONLY thing left that can reject is member 0's key. */
            dna_qc_v2_t *qr2 = make_qc(rot, idx, 3, block_id, height, chain,
                                       h2, 1);
            CHECK(qr2 != NULL, "qc rot2");
            CHECK(dna_qc_v2_verify(qr2, block_id, height, chain, h2, S2r) != 0,
                  "QC accepted against a rotated key it never signed for");
            OK();

            dna_qc_v2_free(&qr2);
            dna_qc_v2_free(&qr);
            dna_vset_free(&S2r);
            dna_vset_free(&S1);
            free(rot);
        }

        /* -- NULL / degenerate snapshot guards ---------------------- */
        CHECK(dna_qc_v2_verify(NULL, block_id, height, chain, vsh, S) != 0,
              "NULL qc"); OK();
        CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh, NULL) != 0,
              "NULL snapshot"); OK();
        {
            /* N == 0 and N > 128 snapshots must reject. Both are
             * structurally impossible to encode, so they are built by
             * hand. HONEST NOTE on the mechanism: the reject actually
             * fires at verify step 1 (dna_vset_hash refuses to hash an
             * out-of-bounds snapshot), which means verify's own explicit
             * n_set bounds check is defence in depth rather than the
             * load-bearing gate. What this pins is the OUTCOME — no
             * degenerate snapshot can carry a QC. */
            dna_vset_snapshot_t z;
            memcpy(&z, S, sizeof(z));
            z.active_count = 0;
            CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh, &z) != 0,
                  "N==0 snapshot accepted"); OK();
            z.active_count = 129;
            CHECK(dna_qc_v2_verify(q3, block_id, height, chain, vsh, &z) != 0,
                  "N>128 snapshot accepted"); OK();
        }

        dna_qc_v2_free(&q4);
        dna_qc_v2_free(&q3);
    }

    dna_vset_free(&S);
    free(ks);
    return 0;
}

/* ── 5: N=30 benchmark (INFORMATIONAL) ──────────────────────────────── */

static int test_bench_30(void) {
    const int N = 30;
    keyset_t *ks = calloc((size_t)N, sizeof(*ks));
    CHECK(ks != NULL, "alloc 30 keys");
    CHECK(make_keys(ks, N) == 0, "keygen 30");

    uint8_t block_id[64], chain[32], vsh[64];
    memset(block_id, 0x7C, sizeof(block_id));
    memset(chain,    0x8D, sizeof(chain));

    dna_vset_snapshot_t *S = make_snapshot(ks, N, 1440, 3000000000000000ULL);
    CHECK(S != NULL, "snapshot 30");
    CHECK(dna_vset_hash(S, vsh) == 0, "hash 30");

    const uint32_t q = dna_bft_quorum((uint32_t)N);
    CHECK(q == 21, "quorum(30) != 21"); OK();

    int *idx = calloc((size_t)q, sizeof(int));
    CHECK(idx != NULL, "alloc idx");
    for (uint32_t i = 0; i < q; i++) idx[i] = (int)i;

    dna_qc_v2_t *qc = make_qc(ks, idx, (int)q, block_id, 20000, chain, vsh, 1);
    CHECK(qc != NULL, "qc 21");

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = dna_qc_v2_verify(qc, block_id, 20000, chain, vsh, S);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    CHECK(rc == 0, "N=30 quorum QC rejected"); OK();

    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 +
                (double)(t1.tv_nsec - t0.tv_nsec) / 1.0e6;
    printf("  [bench] N=30, %u certs verified in %.2f ms — INFORMATIONAL "
           "ARITHMETIC ONLY.\n", q, ms);
    printf("  [bench] This is one unloaded local measurement of one code "
           "path; it is NOT asserted, NOT a baseline, and NOT evidence of "
           "production readiness. Use nodus/tests/bench_run.sh for any\n"
           "  [bench] claim about throughput.\n");

    /* One under-quorum cert short must still reject at N=30. */
    dna_qc_v2_t *qshort = make_qc(ks, idx, (int)q - 1, block_id, 20000,
                                  chain, vsh, 1);
    CHECK(qshort != NULL, "qc 20");
    CHECK(dna_qc_v2_verify(qshort, block_id, 20000, chain, vsh, S) != 0,
          "quorum-1 QC accepted at N=30"); OK();

    dna_qc_v2_free(&qshort);
    dna_qc_v2_free(&qc);
    free(idx);
    dna_vset_free(&S);
    free(ks);
    return 0;
}

int main(void) {
    if (test_preimage() != 0) return 1;
    if (test_quorum_table() != 0) return 1;
    if (test_adversarial() != 0) return 1;
    if (test_bench_30() != 0) return 1;
    printf("test_qc_v2: %d checks OK\n", g_checks);
    return 0;
}
