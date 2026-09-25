/**
 * @file nodus/tests/test_v2_qc_alloc_fault.c
 * @brief O15A obligation 1 — an allocation failure anywhere in or beneath
 *        the V2 QC path must surface as INTERNAL_FAULT, never as a
 *        consensus verdict.
 *
 * ── WHY THIS TEST EXISTS ──────────────────────────────────────────────
 * `dna_qc_v2_verify` re-hashes the validator snapshot as a deliberate
 * redundant defence. That hash allocates. Before O15A the failure of that
 * allocation returned -1, and the witness wrapper collapsed every non-zero
 * return into -1 as well — so a node under memory pressure declared a
 * valid, quorum-certified block CONSENSUS-INVALID. Deterministically, and
 * differently from its peers: exactly the shape that splits a chain.
 *
 * The same function was already classified correctly as a fault forty
 * lines earlier in the wrapper, so one verification was reporting one
 * function two different ways.
 *
 * ── HOW THE INJECTION WORKS ───────────────────────────────────────────
 * `malloc` and `calloc` are interposed at LINK time (`-Wl,--wrap`), so the
 * code under test is the PRODUCTION code, unmodified — there is no
 * test-only hook compiled into the shipped library, and nothing about
 * production behaviour changes when this test is not built.
 *
 * The interposer is ARMED around the exact call under test and fails the
 * Nth allocation inside that window. Arming matters: SQLite and the
 * fixture allocate constantly, so an unarmed global failure would fire
 * somewhere irrelevant and prove nothing. Sweeping N across the window is
 * what covers every allocation site the path actually reaches, rather than
 * a site chosen by hand.
 *
 * The window is clean by construction: the per-cert loop allocates nothing
 * (stack preimage buffer, `dna_cert_v2_preimage` is pure byte layout, and
 * `qgp_dsa87_verify` wraps a stack-based reference implementation), so no
 * injected failure can masquerade as a signature verdict.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnac/qc_v2.h"
#include "dnac/vset_wire.h"
#include "witness/nodus_witness_v2_result.h"

static int checks;
#define CHECK(c, msg)                                                     \
    do {                                                                  \
        if (!(c)) {                                                       \
            printf("CHECK failed at %s:%d: %s\n", __FILE__, __LINE__,      \
                   msg);                                                  \
            exit(1);                                                      \
        }                                                                 \
        checks++;                                                         \
    } while (0)
#define OK() do { } while (0)

/* ── the link-time interposer ─────────────────────────────────────────── */

void *__real_malloc(size_t n);
void *__real_calloc(size_t n, size_t sz);

static int      g_armed;      /* 0 = pass everything through            */
static long     g_countdown;  /* fail the allocation that hits zero     */
static long     g_seen;       /* allocations observed while armed       */

void *__wrap_malloc(size_t n) {
    if (g_armed) {
        g_seen++;
        if (--g_countdown == 0) return NULL;
    }
    return __real_malloc(n);
}

void *__wrap_calloc(size_t n, size_t sz) {
    if (g_armed) {
        g_seen++;
        if (--g_countdown == 0) return NULL;
    }
    return __real_calloc(n, sz);
}

static void arm(long nth)  { g_seen = 0; g_countdown = nth; g_armed = 1; }
static long disarm(void)   { g_armed = 0; return g_seen; }

/* ── fixtures ─────────────────────────────────────────────────────────── */

/* A structurally valid QC encoding: 3 certs, strictly ascending voter ids.
 * The signatures are not real — every test below either fails before the
 * signature check or asserts a REJECT, so no valid quorum is needed. */
static size_t build_qc_bytes(uint8_t *out, size_t cap, uint16_t n) {
    size_t need = (size_t)DNA_QC_V2_HDR_LEN +
                  (size_t)n * (size_t)DNA_QC_V2_CERT_LEN;
    if (cap < need) return 0;
    memset(out, 0, need);
    out[0] = (uint8_t)(n >> 8);
    out[1] = (uint8_t)(n & 0xff);
    for (uint16_t i = 0; i < n; i++) {
        uint8_t *cert = out + DNA_QC_V2_HDR_LEN +
                        (size_t)i * (size_t)DNA_QC_V2_CERT_LEN;
        cert[DNA_CERT_V2_VOTER_ID_LEN - 1] = (uint8_t)(i + 1); /* ascending */
    }
    return need;
}

int main(void) {
    printf("=== O15A obligation 1 — allocation failure is a FAULT ===\n");

    uint8_t qcbuf[4096 * 8];
    size_t qclen = build_qc_bytes(qcbuf, sizeof(qcbuf), 3);
    CHECK(qclen > 0, "fixture qc encode"); OK();

    /* ── 1. Baseline: with no injection the decode SUCCEEDS. Without this
     * the rest could pass vacuously on a permanently broken fixture. */
    {
        dna_qc_v2_t *qc = NULL;
        int rc = dna_qc_v2_decode(qcbuf, qclen, &qc);
        CHECK(rc == 0 && qc != NULL, "baseline decode must succeed"); OK();
        dna_qc_v2_free(&qc);
    }

    /* ── 2. How many allocations does a decode perform? Measured, not
     * assumed — the sweep below has to cover exactly them. */
    long n_allocs;
    {
        dna_qc_v2_t *qc = NULL;
        arm(1000000);                    /* armed, but never trips       */
        (void)dna_qc_v2_decode(qcbuf, qclen, &qc);
        n_allocs = disarm();
        dna_qc_v2_free(&qc);
        CHECK(n_allocs >= 2, "decode should allocate the qc and its certs");
        OK();
    }

    /* ── 3. EVERY allocation inside decode, failed independently.
     * Each one must produce INTERNAL_FAULT — never CONSENSUS_INVALID,
     * which is what this line used to return. */
    for (long nth = 1; nth <= n_allocs; nth++) {
        dna_qc_v2_t *qc = NULL;
        arm(nth);
        int rc = dna_qc_v2_decode(qcbuf, qclen, &qc);
        disarm();
        CHECK(rc == NODUS_V2_INTERNAL_FAULT,
              "decode allocation failure must be INTERNAL_FAULT"); OK();
        CHECK(rc != NODUS_V2_CONSENSUS_INVALID,
              "decode allocation failure must never be a verdict"); OK();
        CHECK(qc == NULL, "decode must not hand back a QC on failure"); OK();
    }

    /* ── 4. THE CONVERSE, so section 3 cannot pass vacuously: with NO
     * injection armed, genuinely malformed bytes must still be a VERDICT.
     * If the implementation ever started reporting bad input as a fault,
     * section 3 alone would still be green — this is what catches it. */
    {
        dna_qc_v2_t *qc = NULL;
        uint8_t hdr_only[DNA_QC_V2_HDR_LEN] = { 0, 0 };   /* count 0 */
        int rc = dna_qc_v2_decode(hdr_only, sizeof(hdr_only), &qc);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "a zero cert count is a VERDICT, not a fault"); OK();

        uint8_t trunc[64];
        memcpy(trunc, qcbuf, sizeof(trunc));
        rc = dna_qc_v2_decode(trunc, sizeof(trunc), &qc);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "a truncated QC is a VERDICT, not a fault"); OK();
    }

    /* ── 5. The count is bounds-checked BEFORE any allocation, so an
     * over-large count can never reach the allocator and can never be
     * reported as a fault. Armed at the first allocation: if the guard
     * ever moved after the alloc, this would come back as a fault. */
    {
        dna_qc_v2_t *qc = NULL;
        uint8_t big[DNA_QC_V2_HDR_LEN] = { 0xff, 0xff };
        arm(1);
        int rc = dna_qc_v2_decode(big, sizeof(big), &qc);
        long seen = disarm();
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "an over-large cert count is a VERDICT"); OK();
        CHECK(seen == 0,
              "the count guard must reject BEFORE allocating"); OK();
    }

    /* ── 6. NULL arguments are a caller bug, not a bad certificate. */
    {
        dna_qc_v2_t *qc = NULL;
        CHECK(dna_qc_v2_decode(NULL, 10, &qc) == NODUS_V2_INTERNAL_FAULT,
              "NULL src must be a FAULT, not a verdict"); OK();
        CHECK(dna_qc_v2_decode(qcbuf, qclen, NULL) == NODUS_V2_INTERNAL_FAULT,
              "NULL out must be a FAULT, not a verdict"); OK();
        CHECK(dna_qc_v2_verify(NULL, NULL, 0, NULL, NULL, NULL)
                  == NODUS_V2_INTERNAL_FAULT,
              "verify NULL args must be a FAULT, not a verdict"); OK();
    }

    /* ── 7. dna_vset_hash — THE defect's actual origin. It allocates its
     * preimage buffer, and dna_qc_v2_verify recomputes it as a redundant
     * defence. Failing that allocation must be a fault at BOTH the direct
     * call and through verify; before O15A the second one said -1. */
    {
        dna_vset_snapshot_t *snap = dna_vset_alloc(3);
        CHECK(snap != NULL, "snapshot fixture"); OK();
        snap->epoch = 0;
        snap->active_count = 3;
        /* Ruleset 0 is INVALID by design, and the seed slot must stay
         * zero under TOPN_V1 (an unconsumed input must not enter the
         * hash) — so a snapshot is only hashable once both are right. */
        snap->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        /* Both voter_id AND pubkey must be pairwise distinct — a snapshot
         * with repeated members is rejected before it can be hashed. */
        for (uint16_t i = 0; i < 3; i++) {
            snap->entries[i].voter_id[DNA_VSET_VOTER_ID_LEN - 1] =
                (uint8_t)(i + 1);
            snap->entries[i].pubkey[DNA_VSET_PUBKEY_LEN - 1] =
                (uint8_t)(i + 1);
        }

        uint8_t h[DNA_VSET_HASH_LEN];
        arm(1000000);
        int hrc = dna_vset_hash(snap, h);
        long hash_allocs = disarm();
        CHECK(hrc == 0, "baseline vset hash must succeed"); OK();
        CHECK(hash_allocs >= 1, "dna_vset_hash must allocate"); OK();

        for (long nth = 1; nth <= hash_allocs; nth++) {
            arm(nth);
            int rc = dna_vset_hash(snap, h);
            disarm();
            CHECK(rc != 0, "injected allocation failure must fail the hash");
            OK();
        }

        /* Through the verifier: the SAME failure, and the class that
         * matters. A -1 here is the original defect. */
        dna_qc_v2_t *qc = NULL;
        CHECK(dna_qc_v2_decode(qcbuf, qclen, &qc) == 0, "decode for verify");
        OK();
        uint8_t block_id[DNA_CERT_V2_BLOCK_ID_LEN];
        uint8_t chain[DNA_CHAIN_ID_LEN];
        memset(block_id, 0x11, sizeof(block_id));
        memset(chain, 0x22, sizeof(chain));

        for (long nth = 1; nth <= hash_allocs; nth++) {
            arm(nth);
            int rc = dna_qc_v2_verify(qc, block_id, 1, chain, h, snap);
            disarm();
            CHECK(rc == NODUS_V2_INTERNAL_FAULT,
                  "verify: snapshot-hash allocation failure must be a FAULT");
            OK();
            CHECK(rc != NODUS_V2_CONSENSUS_INVALID,
                  "verify: an allocation failure must never be a verdict");
            OK();
        }

        /* CONVERSE for verify: unarmed, a snapshot that does not match the
         * committed hash is a genuine REJECT. Without this the section
         * above would pass even if verify returned -2 for everything. */
        {
            uint8_t wrong[DNA_VSET_HASH_LEN];
            memset(wrong, 0x5a, sizeof(wrong));
            int rc = dna_qc_v2_verify(qc, block_id, 1, chain, wrong, snap);
            CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
                  "a foreign set hash is a VERDICT, not a fault"); OK();
        }

        dna_qc_v2_free(&qc);
        dna_vset_free(&snap);
    }

    /* ── 8. The interposer itself must be inert when disarmed, or every
     * result above would be suspect. */
    {
        arm(1000000);
        void *p = malloc(32);
        long seen = disarm();
        CHECK(p != NULL && seen == 1, "interposer must observe and pass through");
        OK();
        free(p);
        void *q = malloc(32);
        CHECK(q != NULL, "disarmed interposer must be inert"); OK();
        free(q);
    }

    printf("test_v2_qc_alloc_fault: ALL %d checks passed\n", checks);
    return 0;
}
