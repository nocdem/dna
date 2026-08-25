/**
 * Nodus — O15G: cert verification bound to the COMMITTED committee snapshot.
 *
 * Tests `nodus_witness_verify_certs_snapshot` (nodus_witness_cert.h), the
 * verifier that resolves each precommit signer's pubkey and the verify quorum
 * from the committed validator-set snapshot for the block's height, NOT from
 * the transient transport roster `w->roster`. The old roster-based path silently
 * dropped a signer absent from the local roster; at N>7 that timing-dependence
 * wedged honest nodes on a cryptographically-valid quorum cert (the O15F 7→20
 * defect). This suite pins the properties that close it.
 *
 * The verdict is a PURE FUNCTION of committed state, so it can be exercised
 * with a witness DB seeded with committed snapshots and REAL ML-DSA-87 keys —
 * the same fixture shape as test_v2_qc_authority. The transport roster is set
 * to different, hostile states across runs to PROVE it is never consulted.
 *
 * Result algebra (nodus_witness_v2_result.h): success returns the unique valid
 * signer count (>= quorum); -1 CONSENSUS_INVALID (quorum shortfall vs a known
 * committee), -2 INTERNAL_FAULT (local authority corruption / must-exist hole),
 * -3 NOT_YET_LINKABLE (no committed authority yet, boundary not passed).
 *
 * NOT tested here (out of unit scope, covered elsewhere):
 *   · the sync-path retry state machine (peer rotation / bounded backoff) and
 *     the "zero transport peer" precondition — those live in sync_check /
 *     handle_rsp and are exercised by the Genesis Protocol harness + the 20-node
 *     rehearsal, not a pure-verifier unit;
 *   · the version gate (v3/v4 isolation) — nodus_witness.c dispatch, harness;
 *   · the codec's own duplicate-member/pubkey rejection — test_vset_wire (a
 *     duplicate reaches this verifier ONLY as a resolver fault, i.e. -2).
 *
 * @file test_cert_verify_snapshot.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dnac/vset_wire.h"
#include "dnac/ledger_ids.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_result.h"
#include "witness/nodus_witness_v2_schema.h"
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

#define N_KEYS 9   /* > 7 so the committee can be a proper subset */

/** The SAME derivation the verifier's Layer-A re-derivation uses
 *  (nodus_chain_config_derive_witness_id = SHA3-512(pubkey)[0..31]). */
static void derive_voter(const uint8_t *pk, uint8_t out[NODUS_T3_WITNESS_ID_LEN]) {
    uint8_t full[64];
    qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, full);
    memcpy(out, full, NODUS_T3_WITNESS_ID_LEN);
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

/** Build a snapshot over the FIRST n keys, stored voter_id = derive(pubkey). */
static dna_vset_snapshot_t *make_snapshot(const keyset_t *ks, int n,
                                          uint64_t epoch) {
    dna_vset_snapshot_t *s = dna_vset_alloc((uint16_t)n);
    if (!s) return NULL;
    s->epoch = epoch;
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
    for (int i = 0; i < n; i++) {
        memcpy(s->entries[i].voter_id, ks[i].voter, DNA_VSET_VOTER_ID_LEN);
        memcpy(s->entries[i].pubkey, ks[i].pk, DNA_VSET_PUBKEY_LEN);
        s->entries[i].total_stake    = 1000000ULL + (uint64_t)i;
        s->entries[i].self_bond      = 1000000000000000ULL;
        s->entries[i].commission_bps = (uint16_t)(100 + i);
    }
    return s;
}

/** Legacy 144-byte precommit certs over the given key indices. Signs the
 *  UNCHANGED nodus_witness_compute_cert_preimage — the exact preimage the
 *  live PRECOMMIT sign path uses. */
static int make_certs(const keyset_t *ks, const int *idx, int n,
                      const uint8_t block_hash[NODUS_T3_TX_HASH_LEN],
                      uint64_t height, const uint8_t chain[32],
                      nodus_t3_sync_cert_t *out) {
    for (int i = 0; i < n; i++) {
        const keyset_t *k = &ks[idx[i]];
        memcpy(out[i].voter_id, k->voter, NODUS_T3_WITNESS_ID_LEN);
        uint8_t pre[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(block_hash, k->voter, height,
                                                chain, pre) != 0)
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

/* ── ANCHORED chain_def authority (genesis) ──────────────────────────────
 * Build a minimal genesis chain_def blob in the PINNED layout
 * nodus_witness_verify_certs_chain_def parses (mirrors
 * nodus_witness_genesis_seed.c): 297 fixed bytes with witness_count (u32 LE
 * @164) = 0, then iv_count, then iv_count validator entries whose FIRST field
 * is the 2592-byte pubkey. Only the pubkeys matter to the cert verifier; the
 * fp/commission/endpoint tail is zero-filled. */
#define TCD_FIXED    297
#define TCD_IV_ENTRY ((size_t)QGP_DSA87_PUBLICKEYBYTES + 129 + 2 + 128)

static size_t build_chain_def(const keyset_t *ks, const int *idx, int iv_count,
                              uint8_t *out, size_t out_cap) {
    size_t len = (size_t)TCD_FIXED + 1 + (size_t)iv_count * TCD_IV_ENTRY;
    if (len > out_cap) return 0;
    memset(out, 0, len);
    /* witness_count @ 164 stays 0; iv_count @ 297. */
    out[TCD_FIXED] = (uint8_t)iv_count;
    uint8_t *iv = out + TCD_FIXED + 1;
    for (int i = 0; i < iv_count; i++)
        memcpy(iv + (size_t)i * TCD_IV_ENTRY, ks[idx[i]].pk,
               QGP_DSA87_PUBLICKEYBYTES);
    return len;
}

/* ── fixture ────────────────────────────────────────────────────────── */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain_id16[16];
} fixture_t;

static void rmrf(const char *path) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort cleanup */ }
}

/** Insert one snapshot row in the EXACT shape nodus_witness_vset_get
 *  validates (blob + true hash + agreeing count/epoch). `blob_override` (if
 *  non-NULL) lets a test seed a specific blob for integrity-fault cases. */
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

static int fx_open(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));   /* multi-MB struct — heap, never stack */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_certsnap_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain_id16, 0x4E, sizeof(fx->chain_id16));
    if (nodus_witness_create_chain_db(fx->w, fx->chain_id16) != 0) return -1;
    if (nodus_chain_config_db_migrate(fx->w) != 0) return -1;
    if (nodus_witness_db_migrate_v2s9(fx->w) != 0) return -1;
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

/* Convenience: run the verifier and report both rc and the out-quorum. */
static int verify(fixture_t *fx, const uint8_t *bh, uint64_t h,
                  const uint8_t *chain, const nodus_t3_sync_cert_t *certs,
                  uint32_t cc, uint32_t *out_q) {
    uint32_t q = 0;
    int rc = nodus_witness_verify_certs_snapshot(fx->w, bh, h, chain,
                                                 certs, cc, &q);
    if (out_q) *out_q = q;
    return rc;
}

/* A hostile roster: n garbage witnesses that overlap NONE of the committee.
 * Used to prove the verifier never consults w->roster. */
static void poison_roster(nodus_witness_t *w, int n) {
    memset(&w->roster, 0, sizeof(w->roster));
    if (n > NODUS_T3_MAX_WITNESSES) n = NODUS_T3_MAX_WITNESSES;
    w->roster.n_witnesses = (uint32_t)n;
    for (int i = 0; i < n; i++) {
        memset(w->roster.witnesses[i].witness_id, 0xAA - i,
               NODUS_T3_WITNESS_ID_LEN);
        memset(w->roster.witnesses[i].pubkey, 0xBB - i, NODUS_PK_BYTES);
    }
}

int main(void) {
    static keyset_t ks[N_KEYS];
    if (make_keys(ks, N_KEYS) != 0) {
        fprintf(stderr, "key generation failed\n");
        return 1;
    }

    const uint64_t E = (uint64_t)DNAC_EPOCH_LENGTH;
    const uint64_t H = E + 3;                    /* inside epoch 1 */
    const uint64_t EPOCH_START = (H / E) * E;    /* == E */
    const int      COMMITTEE_N = 7;              /* subset of the 9 keys */
    const uint32_t Q = dna_bft_quorum(COMMITTEE_N);  /* 5 */

    uint8_t chain[32];  memset(chain, 0xC0, sizeof(chain));
    uint8_t bh[NODUS_T3_TX_HASH_LEN]; memset(bh, 0x80, sizeof(bh));

    printf("Cert snapshot-authority verifier tests\n");
    printf("======================================\n");

    /* ── §0 — the LEGACY-lane verifier (w->v2_successor = false) ──────────
     * get_for_block serves the seeded snapshot. */
    fixture_t fx;
    CHECK(fx_open(&fx, "legacy") == 0, "fixture open");

    dna_vset_snapshot_t *snap = make_snapshot(ks, COMMITTEE_N, EPOCH_START);
    CHECK(snap != NULL, "snapshot alloc");
    CHECK(seed_snapshot(&fx, snap, EPOCH_START) == 0, "seed snapshot"); OK();
    CHECK(Q == 5, "quorum(7) == 5"); OK();

    nodus_t3_sync_cert_t certs[NODUS_T3_MAX_WITNESSES];

    /* §1 — happy path: an exact quorum of committee signers verifies, and the
     * return is the unique valid signer count. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign quorum");
        uint32_t q = 0;
        int rc = verify(&fx, bh, H, chain, certs, 5, &q);
        CHECK(rc == 5, "exact quorum should verify (count 5)"); OK();
        CHECK(q == Q, "out_quorum must be the resolver quorum"); OK();
    }

    /* §2 — arrival ORDER does not matter (legacy certs are unsorted). The same
     * signer set in reverse order yields the same verdict. */
    {
        int fwd[5] = {0, 1, 2, 3, 4};
        int rev[5] = {4, 3, 2, 1, 0};
        nodus_t3_sync_cert_t a[NODUS_T3_MAX_WITNESSES];
        nodus_t3_sync_cert_t b[NODUS_T3_MAX_WITNESSES];
        CHECK(make_certs(ks, fwd, 5, bh, H, chain, a) == 0, "sign fwd");
        CHECK(make_certs(ks, rev, 5, bh, H, chain, b) == 0, "sign rev");
        int ra = verify(&fx, bh, H, chain, a, 5, NULL);
        int rb = verify(&fx, bh, H, chain, b, 5, NULL);
        CHECK(ra == rb && ra == 5, "arrival order changed the verdict"); OK();
    }

    /* §3 — a DUPLICATE signer cannot inflate to reach quorum. 4 unique valid
     * signers + a duplicate of #0 → only 4 unique count → CONSENSUS_INVALID. */
    {
        int idx[5] = {0, 1, 2, 3, 0};   /* #0 twice */
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign dup");
        int rc = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "duplicate signer inflated quorum"); OK();
    }

    /* §4 — a NON-MEMBER signer does not count. 4 valid + key #8 (NOT in the
     * committee of 7) → 4 unique valid < quorum → CONSENSUS_INVALID. A single
     * garbage signer must never wedge an otherwise-valid batch into a FAULT. */
    {
        int idx[5] = {0, 1, 2, 3, 8};   /* #8 is outside the committee */
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign nonmember");
        int rc = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "non-member signer counted toward quorum"); OK();
    }

    /* §4b — a full quorum PLUS a trailing non-member is still ACCEPTED: the
     * garbage entry is dropped, not fatal (Security G-S2, liveness). */
    {
        int idx[6] = {0, 1, 2, 3, 4, 8};
        CHECK(make_certs(ks, idx, 6, bh, H, chain, certs) == 0, "sign q+garbage");
        int rc = verify(&fx, bh, H, chain, certs, 6, NULL);
        CHECK(rc == 5, "a trailing non-member wedged a valid quorum"); OK();
    }

    /* §5 — a BAD SIGNATURE is dropped (committee member, wrong sig). 4 good
     * + #4 with a corrupted sig → 4 < quorum → CONSENSUS_INVALID. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign badsig");
        certs[4].signature[0] ^= 0x01;   /* member, invalid sig */
        int rc = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID, "bad sig counted"); OK();
    }

    /* §6 — RESOLVER quorum is the ONLY quorum; w->bft_config.quorum is never
     * consulted. An absurd bft_config.quorum does not change the verdict. */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign q");
        fx.w->bft_config.quorum = 100;   /* would fail if it were used */
        int pass = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(pass == 5, "bft_config.quorum leaked into the accept path"); OK();

        int idx4[4] = {0, 1, 2, 3};
        CHECK(make_certs(ks, idx4, 4, bh, H, chain, certs) == 0, "sign q-1");
        fx.w->bft_config.quorum = 0;     /* would accept anything if used */
        int fail = verify(&fx, bh, H, chain, certs, 4, NULL);
        CHECK(fail == NODUS_V2_CONSENSUS_INVALID,
              "bft_config.quorum=0 leaked into the accept path"); OK();
        fx.w->bft_config.quorum = 5;     /* restore a plausible value */
    }

    /* ── §7 — ROSTER IMMUNITY / DETERMINISM TWIN ─────────────────────────
     * The whole point of O15G: the verdict is a pure function of committed
     * state, INDEPENDENT of the transient roster. Two hostile roster states,
     * ONE verdict — and it is ACCEPT even with an EMPTY roster (the exact
     * O15F regression: the old verifier dropped every signer here). */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign twin");

        memset(&fx.w->roster, 0, sizeof(fx.w->roster));   /* roster state A: empty */
        int ra = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(ra == 5, "empty roster must not block a snapshot quorum"); OK();

        poison_roster(fx.w, NODUS_T3_MAX_WITNESSES);       /* roster state B: hostile */
        int rb = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(rb == ra, "two roster states produced different verdicts"); OK();
    }

    /* §8 — the CONVERSE roster-immunity: a signer present in the roster but
     * NOT in the committee snapshot does not count. Roster full of key #8,
     * cert from #8, with 4 real members → still short of quorum. */
    {
        int idx[5] = {0, 1, 2, 3, 8};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign roster-only");
        memset(&fx.w->roster, 0, sizeof(fx.w->roster));
        fx.w->roster.n_witnesses = 1;
        memcpy(fx.w->roster.witnesses[0].witness_id, ks[8].voter,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(fx.w->roster.witnesses[0].pubkey, ks[8].pk, NODUS_PK_BYTES);
        int rc = verify(&fx, bh, H, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "a roster-only (non-committee) signer counted"); OK();
    }

    /* §9 — a cert signed over a DIFFERENT block_hash / chain is dropped as a
     * bad signature (the preimage no longer matches). */
    {
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign");
        uint8_t other_bh[NODUS_T3_TX_HASH_LEN]; memset(other_bh, 0x81, sizeof(other_bh));
        uint8_t other_ch[32];                   memset(other_ch, 0xEE, sizeof(other_ch));
        CHECK(verify(&fx, other_bh, H, chain, certs, 5, NULL)
                  == NODUS_V2_CONSENSUS_INVALID, "wrong block_hash accepted"); OK();
        CHECK(verify(&fx, bh, H, other_ch, certs, 5, NULL)
                  == NODUS_V2_CONSENSUS_INVALID, "wrong chain_id accepted"); OK();
    }

    fx_close(&fx);
    dna_vset_free(&snap);

    /* ── §10 — EPOCH-KEYED AUTHORITY / boundary off-by-one ───────────────
     * Two committed sets in two epochs. A cert signed by epoch-0's committee
     * cannot certify a block in epoch 1: those signers are non-members of the
     * epoch-1 committee that governs the block. */
    {
        fixture_t fx2;
        CHECK(fx_open(&fx2, "epoch") == 0, "fx2 open");

        /* epoch 0: keys 0..4 (5 members) ; epoch E: keys 2..8 (7 members) */
        dna_vset_snapshot_t *s0 = make_snapshot(ks, 5, 0);
        dna_vset_snapshot_t *sE = dna_vset_alloc(7);
        CHECK(s0 && sE, "alloc two snapshots");
        sE->epoch = EPOCH_START;
        sE->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
        for (int i = 0; i < 7; i++) {          /* keys 2..8 */
            memcpy(sE->entries[i].voter_id, ks[i + 2].voter, DNA_VSET_VOTER_ID_LEN);
            memcpy(sE->entries[i].pubkey, ks[i + 2].pk, DNA_VSET_PUBKEY_LEN);
            sE->entries[i].total_stake    = 1000000ULL + (uint64_t)i;
            sE->entries[i].self_bond      = 1000000000000000ULL;
            sE->entries[i].commission_bps = (uint16_t)(100 + i);
        }
        CHECK(seed_snapshot(&fx2, s0, 0) == 0, "seed s0"); OK();
        CHECK(seed_snapshot(&fx2, sE, EPOCH_START) == 0, "seed sE"); OK();

        /* Quorum-5 certs from epoch-0's committee (keys 0..4). At a height in
         * epoch 1, keys 0 and 1 are NOT in the governing set (keys 2..8); only
         * 2,3,4 overlap → 3 valid < quorum(7)=5 → CONSENSUS_INVALID. */
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign epoch0");
        int rc = verify(&fx2, bh, H, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
              "epoch-0 committee certified an epoch-1 block"); OK();

        /* Positive control: the epoch-1 committee's own quorum certifies it. */
        int idxE[5] = {2, 3, 4, 5, 6};   /* all in keys 2..8 */
        CHECK(make_certs(ks, idxE, 5, bh, H, chain, certs) == 0, "sign epoch1");
        CHECK(verify(&fx2, bh, H, chain, certs, 5, NULL) == 5,
              "epoch-1 committee quorum rejected under its own set"); OK();

        fx_close(&fx2);
        dna_vset_free(&s0);
        dna_vset_free(&sE);
    }

    /* ── §11 — SUCCESSOR path + snapshot-integrity + must-exist boundary ──
     * On a successor (w->v2_successor), Layer-A uses the strict epoch resolver
     * and cross-checks each stored voter_id against derive(pubkey). */
    {
        fixture_t fx3;
        CHECK(fx_open(&fx3, "succ") == 0, "fx3 open");
        fx3.w->v2_successor = true;

        /* §11a — a well-formed successor snapshot verifies (real keys). */
        dna_vset_snapshot_t *ss = make_snapshot(ks, COMMITTEE_N, EPOCH_START);
        CHECK(ss != NULL, "succ snapshot alloc");
        CHECK(seed_snapshot(&fx3, ss, EPOCH_START) == 0, "seed succ snapshot"); OK();
        int idx[5] = {0, 1, 2, 3, 4};
        CHECK(make_certs(ks, idx, 5, bh, H, chain, certs) == 0, "sign succ");
        CHECK(verify(&fx3, bh, H, chain, certs, 5, NULL) == 5,
              "successor snapshot quorum rejected"); OK();

        /* §11b — snapshot integrity: a stored voter_id that does NOT equal
         * derive(pubkey) is LOCAL_AUTHORITY_CORRUPT (a node fault, -2), never a
         * verdict. Seeded at its OWN epoch (2E, its own row) so no caching of the
         * §11a row can mask it; entry 0's stored voter_id is corrupted but kept
         * distinct so the codec still decodes it. The integrity check fires in
         * Layer-A before any cert is examined, so the certs here are never
         * reached (their height/content are irrelevant to this verdict). */
        dna_vset_snapshot_t *bad = make_snapshot(ks, COMMITTEE_N, 2 * E);
        CHECK(bad != NULL, "bad snapshot alloc");
        bad->entries[0].voter_id[0] ^= 0x80;   /* != derive(pubkey), still unique */
        CHECK(seed_snapshot(&fx3, bad, 2 * E) == 0, "seed corrupt"); OK();
        int rc = verify(&fx3, bh, 2 * E + 3, chain, certs, 5, NULL);
        CHECK(rc == NODUS_V2_INTERNAL_FAULT,
              "stored voter_id != derive(pubkey) not a FAULT"); OK();
        dna_vset_free(&bad);
        dna_vset_free(&ss);

        /* §11c — must-exist hole: NO snapshot for an epoch that is genesis-
         * seeded (epoch E, es <= E) is a FAULT (-2), never a deferral. */
        {
            fixture_t fx4;
            CHECK(fx_open(&fx4, "musthole") == 0, "fx4 open");
            fx4.w->v2_successor = true;
            /* height in [E, 2E): es == E <= E ⇒ must-exist. No snapshot seeded. */
            int r = verify(&fx4, bh, E + 3, chain, certs, 5, NULL);
            CHECK(r == NODUS_V2_INTERNAL_FAULT,
                  "missing genesis-seeded epoch snapshot not a FAULT"); OK();
            fx_close(&fx4);
        }

        /* §11d — not-yet-available: an epoch whose boundary has NOT passed on
         * this node (head 0, es = 2E, es-E = E > 0) with no snapshot is
         * NOT_YET_LINKABLE (-3) — sync prerequisites, do not fail closed. */
        {
            fixture_t fx5;
            CHECK(fx_open(&fx5, "notyet") == 0, "fx5 open");
            fx5.w->v2_successor = true;
            /* height in [2E, 3E): es == 2E, es-E == E, head == 0 ⇒ deferral. */
            int r = verify(&fx5, bh, 2 * E + 3, chain, certs, 5, NULL);
            CHECK(r == NODUS_V2_NOT_YET_LINKABLE,
                  "future-epoch missing snapshot not a DEFERRAL"); OK();
            fx_close(&fx5);
        }

        fx_close(&fx3);
    }

    /* §12 — NULL guards are FAULTS (node-local), never verdicts. */
    {
        fixture_t fx6;
        CHECK(fx_open(&fx6, "null") == 0, "fx6 open");
        CHECK(nodus_witness_verify_certs_snapshot(NULL, bh, H, chain, certs, 5, NULL)
                  == NODUS_V2_INTERNAL_FAULT, "NULL w not a fault"); OK();
        CHECK(nodus_witness_verify_certs_snapshot(fx6.w, NULL, H, chain, certs, 5, NULL)
                  == NODUS_V2_INTERNAL_FAULT, "NULL block_hash not a fault"); OK();
        CHECK(nodus_witness_verify_certs_snapshot(fx6.w, bh, H, NULL, certs, 5, NULL)
                  == NODUS_V2_INTERNAL_FAULT, "NULL chain not a fault"); OK();
        fx_close(&fx6);
    }

    /* ── §13 — ANCHORED chain_def cert verifier (O15G HIGH-2 genesis) ─────
     * nodus_witness_verify_certs_chain_def resolves the authority from the
     * genesis chain_def's OWN initial_validators[] — the ROSTER is never
     * consulted, and quorum is dna_bft_quorum(iv_count) from the ANCHORED
     * (not attacker-declared) validator count. Genesis signers use a ZERO
     * chain_id in the cert preimage. This verifier is pure (no DB fixture). */
    {
        printf("\n-- chain_def (genesis) authority verifier --\n");
        uint8_t g_zero[32]; memset(g_zero, 0, sizeof(g_zero));
        static uint8_t cd[TCD_FIXED + 1 + 7 * (size_t)(QGP_DSA87_PUBLICKEYBYTES + 129 + 2 + 128)];

        int committee[7] = {0, 1, 2, 3, 4, 5, 6};   /* committee = keys 0..6 */
        size_t cdlen = build_chain_def(ks, committee, 7, cd, sizeof(cd));
        CHECK(cdlen > 0, "build chain_def"); OK();
        const uint32_t Qcd = dna_bft_quorum(7);      /* 5 */

        /* §13a — happy path: a quorum of anchored validators verifies, and the
         * out_quorum is dna_bft_quorum(iv_count). */
        {
            int idx[5] = {0, 1, 2, 3, 4};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign cd q");
            uint32_t q = 0;
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 5, &q);
            CHECK(rc == 5, "anchored quorum should verify"); OK();
            CHECK(q == Qcd, "chain_def quorum must be dna_bft_quorum(iv_count)"); OK();
        }

        /* §13b — arrival order does not matter. */
        {
            int fwd[5] = {0, 1, 2, 3, 4};
            int rev[5] = {4, 3, 2, 1, 0};
            nodus_t3_sync_cert_t a[NODUS_T3_MAX_WITNESSES];
            nodus_t3_sync_cert_t b[NODUS_T3_MAX_WITNESSES];
            CHECK(make_certs(ks, fwd, 5, bh, 1, g_zero, a) == 0, "sign fwd");
            CHECK(make_certs(ks, rev, 5, bh, 1, g_zero, b) == 0, "sign rev");
            int ra = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, a, 5, NULL);
            int rb = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, b, 5, NULL);
            CHECK(ra == rb && ra == 5, "chain_def arrival order changed verdict"); OK();
        }

        /* §13c — a NON-MEMBER signer (key #7, outside the committee of 7) does
         * not count → 4 valid < quorum → CONSENSUS_INVALID. */
        {
            int idx[5] = {0, 1, 2, 3, 7};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign nonmember");
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 5, NULL);
            CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
                  "chain_def non-member counted toward quorum"); OK();
        }

        /* §13c2 — a full quorum PLUS a trailing non-member is still ACCEPTED
         * (garbage dropped, not fatal — Security G-S2 liveness). */
        {
            int idx[6] = {0, 1, 2, 3, 4, 8};
            CHECK(make_certs(ks, idx, 6, bh, 1, g_zero, certs) == 0, "sign q+junk");
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 6, NULL);
            CHECK(rc == 5, "trailing non-member wedged an anchored quorum"); OK();
        }

        /* §13d — a DUPLICATE signer cannot inflate to reach quorum. */
        {
            int idx[5] = {0, 1, 2, 3, 0};   /* #0 twice */
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign dup");
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 5, NULL);
            CHECK(rc == NODUS_V2_CONSENSUS_INVALID,
                  "chain_def duplicate signer inflated quorum"); OK();
        }

        /* §13e — a BAD SIGNATURE (member, corrupted sig) is dropped. */
        {
            int idx[5] = {0, 1, 2, 3, 4};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign badsig");
            certs[4].signature[0] ^= 0x01;
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 5, NULL);
            CHECK(rc == NODUS_V2_CONSENSUS_INVALID, "chain_def bad sig counted"); OK();
        }

        /* §13f — a chain_def with iv_count == 0 is INTERNAL_FAULT (the explicit
         * n==0 fail-closed guard; a zero-member authority is unverifiable). */
        {
            static uint8_t cd0[TCD_FIXED + 1];
            size_t l0 = build_chain_def(ks, committee, 0, cd0, sizeof(cd0));
            CHECK(l0 == TCD_FIXED + 1, "build zero-iv chain_def"); OK();
            int idx[5] = {0, 1, 2, 3, 4};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign");
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd0,
                        (uint32_t)l0, certs, 5, NULL);
            CHECK(rc == NODUS_V2_INTERNAL_FAULT,
                  "iv_count==0 chain_def not a FAULT"); OK();
        }

        /* §13g — a TRUNCATED chain_def is INTERNAL_FAULT (below the fixed
         * section; every peer serves the same bytes so rotation cannot help). */
        {
            int idx[5] = {0, 1, 2, 3, 4};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign");
            int rc = nodus_witness_verify_certs_chain_def(bh, 1, g_zero, cd,
                        100, certs, 5, NULL);
            CHECK(rc == NODUS_V2_INTERNAL_FAULT, "truncated chain_def not a FAULT"); OK();
        }

        /* §13h — NULL args are FAULTS (node-local), never verdicts. */
        {
            int idx[5] = {0, 1, 2, 3, 4};
            CHECK(make_certs(ks, idx, 5, bh, 1, g_zero, certs) == 0, "sign");
            CHECK(nodus_witness_verify_certs_chain_def(NULL, 1, g_zero, cd,
                        (uint32_t)cdlen, certs, 5, NULL) == NODUS_V2_INTERNAL_FAULT,
                  "NULL block_hash not a FAULT"); OK();
            CHECK(nodus_witness_verify_certs_chain_def(bh, 1, g_zero, NULL,
                        (uint32_t)cdlen, certs, 5, NULL) == NODUS_V2_INTERNAL_FAULT,
                  "NULL cd_blob not a FAULT"); OK();
        }
    }

    printf("\nAll %d checks passed.\n", g_checks);
    return 0;
}
