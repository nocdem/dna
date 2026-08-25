/**
 * Nodus — O15G HIGH-2: genesis bound to the DISCOVER bootstrap anchor.
 *
 * The legacy genesis-sync leg used to verify block-1 certs against the DHT
 * transport roster with a SELF-DECLARED quorum from the synced genesis's own
 * chain_def (nodus_witness_sync.c). Because the genesis tx_hash does NOT cover
 * the chain_def trailer (shared/dnac/tx_wire.c:504-506), a partial eclipse
 * (sync-peer + roster sybils) could get a FORGED validator set adopted (§8.1).
 *
 * The fix binds a synced genesis to the DISCOVER-agreed chain_def hash
 * (w->g_quorum_cdh) and verifies block-1 certs against the ANCHORED chain_def's
 * OWN validator set — the roster is never consulted.
 * nodus_witness_sync_genesis_anchor_check is the extracted, directly-testable
 * primitive; this suite drives it with hand-built genesis TXs + chain_defs
 * carrying REAL ML-DSA-87 keys, so the property is pinned WITHOUT a replayable
 * genesis (no Rule P.2 supply equation / validator seeding fixture needed).
 *
 * @file test_sync_genesis_anchor.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnac/ledger_ids.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_v2_result.h"
#include "nodus/nodus_chain_config.h"
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
    uint8_t voter[NODUS_T3_WITNESS_ID_LEN];
} keyset_t;

#define N_KEYS 9

static void derive_voter(const uint8_t *pk, uint8_t out[NODUS_T3_WITNESS_ID_LEN]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, NODUS_T3_WITNESS_ID_LEN);
}

static int make_keys(keyset_t *ks, int n) {
    for (int i = 0; i < n; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(ks[i].pk, ks[i].sk, seed) != 0) return -1;
        derive_voter(ks[i].pk, ks[i].voter);
    }
    return 0;
}

/* Genesis certs sign the UNCHANGED 144-byte compute_cert_preimage with a ZERO
 * chain_id (the chain_id is derived only in commit_genesis, AFTER quorum), at
 * height 1. */
static int make_certs(const keyset_t *ks, const int *idx, int n,
                      const uint8_t block_hash[NODUS_T3_TX_HASH_LEN],
                      nodus_t3_sync_cert_t *out) {
    uint8_t chain_zero[32]; memset(chain_zero, 0, sizeof(chain_zero));
    for (int i = 0; i < n; i++) {
        const keyset_t *k = &ks[idx[i]];
        memcpy(out[i].voter_id, k->voter, NODUS_T3_WITNESS_ID_LEN);
        uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, k->voter, 1,
                                                chain_zero, pre) != 0)
            return -1;
        size_t siglen = 0;
        if (qgp_dsa87_sign(out[i].signature, &siglen, pre, sizeof(pre),
                           k->sk) != 0)
            return -1;
        if (siglen < NODUS_SIG_BYTES)
            memset(out[i].signature + siglen, 0, NODUS_SIG_BYTES - siglen);
    }
    return 0;
}

/* ── chain_def + genesis TX builders (pinned layouts) ────────────────── */

#define TCD_FIXED    297
#define TCD_IV_ENTRY ((size_t)QGP_DSA87_PUBLICKEYBYTES + 129 + 2 + 128)

/* Minimal genesis chain_def: 297 fixed bytes (witness_count @164 = 0), then
 * iv_count, then iv_count validator entries whose FIRST field is the pubkey. */
static size_t build_chain_def(const keyset_t *ks, const int *idx, int iv_count,
                              uint8_t *out, size_t out_cap) {
    size_t len = (size_t)TCD_FIXED + 1 + (size_t)iv_count * TCD_IV_ENTRY;
    if (len > out_cap) return 0;
    memset(out, 0, len);
    out[TCD_FIXED] = (uint8_t)iv_count;
    uint8_t *iv = out + TCD_FIXED + 1;
    for (int i = 0; i < iv_count; i++)
        memcpy(iv + (size_t)i * TCD_IV_ENTRY, ks[idx[i]].pk,
               QGP_DSA87_PUBLICKEYBYTES);
    return len;
}

/* Minimal genesis TX matching BOTH nodus_witness_extract_chain_def and
 * nodus_witness_genesis_derive_chain_id walks (DNAC_TX_HEADER_SIZE=82):
 *   [0..81]   header (content irrelevant; tx_hash is passed separately)
 *   [82]      in_count  = 0
 *   [83]      out_count = 1
 *   [84]      output version
 *   [85..213] fp (129) — a 128-char hex string + NUL
 *   [214..317] amount(8)+token(64)+seed(32)
 *   [318]     memo_len = 0
 *   [319]     witness_count = 0
 *   [320]     signer_count = 0
 *   [321]     has_chain_def
 *   [322..325] chain_def_len (u32 LE)
 *   [326..]   chain_def blob
 * `has_cd`=0 produces a genesis with no chain_def trailer (MALFORMED case). */
static size_t build_genesis_tx(const uint8_t *cd, size_t cdlen, int has_cd,
                               uint8_t *out, size_t cap) {
    size_t total = has_cd ? (326 + cdlen) : 322;
    if (total > cap) return 0;
    memset(out, 0, total);
    out[0] = 2;                          /* version (irrelevant) */
    /* in_count @82 = 0; out_count @83 = 1 */
    out[83] = 1;
    out[84] = 1;                         /* output version */
    memset(out + 85, 'a', 128);         /* fp: 128 hex chars; out[213]=NUL */
    /* memo_len @318 = 0, witness_count @319 = 0, signer_count @320 = 0 */
    if (has_cd) {
        out[321] = 1;                    /* has_chain_def */
        out[322] = (uint8_t)(cdlen & 0xff);
        out[323] = (uint8_t)((cdlen >> 8) & 0xff);
        out[324] = (uint8_t)((cdlen >> 16) & 0xff);
        out[325] = (uint8_t)((cdlen >> 24) & 0xff);
        memcpy(out + 326, cd, cdlen);
    } else {
        out[321] = 0;                    /* no chain_def trailer */
    }
    return total;
}

int main(void) {
    static keyset_t ks[N_KEYS];
    if (make_keys(ks, N_KEYS) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }

    printf("Genesis bootstrap-anchor tests\n");
    printf("==============================\n");

    /* Committee = keys 0..6. Sybil set (a DIFFERENT chain_def) = keys 2..8. */
    int committee[7] = {0, 1, 2, 3, 4, 5, 6};
    int sybils[7]    = {2, 3, 4, 5, 6, 7, 8};

    static uint8_t cd[TCD_FIXED + 1 + 7 * (size_t)(QGP_DSA87_PUBLICKEYBYTES + 129 + 2 + 128)];
    static uint8_t cd_forged[TCD_FIXED + 1 + 7 * (size_t)(QGP_DSA87_PUBLICKEYBYTES + 129 + 2 + 128)];
    size_t cdlen  = build_chain_def(ks, committee, 7, cd, sizeof(cd));
    size_t cflen  = build_chain_def(ks, sybils,    7, cd_forged, sizeof(cd_forged));
    CHECK(cdlen > 0 && cflen > 0, "build chain_defs"); OK();

    static uint8_t gtx[512 + sizeof(cd)];
    static uint8_t gtx_forged[512 + sizeof(cd_forged)];
    size_t gtxlen = build_genesis_tx(cd, cdlen, 1, gtx, sizeof(gtx));
    size_t gflen  = build_genesis_tx(cd_forged, cflen, 1, gtx_forged, sizeof(gtx_forged));
    CHECK(gtxlen > 0 && gflen > 0, "build genesis TXs"); OK();

    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN]; memset(tx_hash, 0x77, sizeof(tx_hash));
    uint8_t bh[NODUS_T3_TX_HASH_LEN];      memset(bh, 0x80, sizeof(bh));

    /* Derive the chain_id the honest genesis binds to (the value the joiner
     * bootstrapped onto), and the DISCOVER anchor SHA3-512(chain_def). */
    uint8_t chain_ok[32];
    CHECK(nodus_witness_genesis_derive_chain_id(gtx, (uint32_t)gtxlen, tx_hash,
                                                chain_ok) == 0, "derive chain_id"); OK();
    uint8_t anchor[64];
    CHECK(qgp_sha3_512(cd, cdlen, anchor) == 0, "hash anchor"); OK();

    /* Heap witness (multi-MB) — anchor_check touches NO DB, so no chain DB is
     * opened; only chain_id / g_quorum_cdh / roster are read. */
    nodus_witness_t *w = calloc(1, sizeof(*w));
    CHECK(w != NULL, "witness alloc"); OK();
    memcpy(w->chain_id, chain_ok, 32);
    memcpy(w->g_quorum_cdh, anchor, 64);
    w->g_quorum_cdh_set = true;

    nodus_t3_sync_cert_t certs[NODUS_T3_MAX_WITNESSES];

    /* §1 — happy path: an honest genesis anchored to the DISCOVER cdh, with a
     * quorum of the ANCHORED committee's certs → OK. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign quorum");
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_OK, "honest anchored genesis rejected"); OK();
    }

    /* §2 — ROSTER-SYBIL IMMUNITY (positive): a hostile roster full of sybils
     * does not change the verdict — the anchor check never consults w->roster.
     * The honest genesis + honest quorum still verifies. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign quorum");
        memset(&w->roster, 0, sizeof(w->roster));
        w->roster.n_witnesses = NODUS_T3_MAX_WITNESSES;
        for (int i = 0; i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(w->roster.witnesses[i].witness_id, ks[(i % 7) + 2].voter,
                   NODUS_T3_WITNESS_ID_LEN);   /* sybils = keys 2..8 */
            memcpy(w->roster.witnesses[i].pubkey, ks[(i % 7) + 2].pk, NODUS_PK_BYTES);
        }
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_OK,
              "a hostile roster changed the anchored verdict"); OK();
    }

    /* §3 — FORGED GENESIS (the core §8.1 attack): a sync peer serves a genesis
     * carrying a DIFFERENT (sybil) chain_def, and the roster is full of those
     * sybils. Its chain_def does not hash to the DISCOVER anchor ⇒
     * CDH_MISMATCH, rejected BEFORE any cert (signed by the sybils) can count.
     * This is exactly the partial-eclipse case the old roster path adopted. */
    {
        int idx[5] = {2, 3, 4, 5, 6};   /* sybil certs (would verify vs cd_forged) */
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign sybil quorum");
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx_forged, (uint32_t)gflen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_CDH_MISMATCH,
              "forged-chain_def genesis was NOT anchor-rejected"); OK();
    }

    /* §4 — CHAIN_ID mismatch (belt-and-braces): the honest gtx's chain_def
     * still hashes to the anchor (CDH passes), but we point w->chain_id at a
     * value the genesis does NOT derive to, so the CID check is what fires. */
    {
        uint8_t saved[32]; memcpy(saved, w->chain_id, 32);
        memset(w->chain_id, 0x33, 32);           /* != derive_chain_id(gtx) */
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign quorum");
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_CID_MISMATCH,
              "chain_id mismatch not caught"); OK();
        memcpy(w->chain_id, saved, 32);
    }

    /* §5 — CERT SHORTFALL: honest anchored genesis but only 4 valid certs (<
     * quorum 5 for the 7-member anchored set) ⇒ CERT_SHORT. */
    {
        int idx[4] = {0, 1, 2, 3};
        CHECK(make_certs(ks, idx, 4, bh, certs) == 0, "sign q-1");
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 4);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_CERT_SHORT, "shortfall not caught"); OK();
    }

    /* §6 — MALFORMED: a genesis TX with no chain_def trailer ⇒ MALFORMED. */
    {
        static uint8_t gtx_nocd[512];
        size_t nlen = build_genesis_tx(NULL, 0, 0, gtx_nocd, sizeof(gtx_nocd));
        CHECK(nlen == 322, "build no-cd genesis"); OK();
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign");
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx_nocd, (uint32_t)nlen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_MALFORMED, "no-cd genesis not MALFORMED"); OK();
    }

    /* §7 — anchor UNSET ⇒ FAULT (the caller must gate on g_quorum_cdh_set; the
     * function refuses to guess). */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign");
        w->g_quorum_cdh_set = false;
        int rc = nodus_witness_sync_genesis_anchor_check(
                     w, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 5);
        CHECK(rc == NODUS_W_GENESIS_ANCHOR_FAULT, "unset anchor not a FAULT"); OK();
        w->g_quorum_cdh_set = true;
    }

    /* §8 — NULL args ⇒ FAULT (node-local), never a genesis verdict. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, certs) == 0, "sign");
        CHECK(nodus_witness_sync_genesis_anchor_check(
                  NULL, gtx, (uint32_t)gtxlen, tx_hash, bh, certs, 5)
                  == NODUS_W_GENESIS_ANCHOR_FAULT, "NULL w not a FAULT"); OK();
        CHECK(nodus_witness_sync_genesis_anchor_check(
                  w, NULL, (uint32_t)gtxlen, tx_hash, bh, certs, 5)
                  == NODUS_W_GENESIS_ANCHOR_FAULT, "NULL tx_data not a FAULT"); OK();
    }

    free(w);
    printf("\nAll %d checks passed.\n", g_checks);
    return 0;
}
