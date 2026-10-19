/**
 * Nodus — cometbft @v0.38.26 C port: `light/detector.go`
 * (shared/dnac/cmt_light_detector.{c,h}), through the light client
 * (cmt_light_client.c), the reference's mock provider
 * (light/provider/mock/mock.go, deadmock.go) and the SQLite light store.
 * Light client package 3, 2026-10-16 (Kurultay #25 item 2); no node path
 * calls any of it yet.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · a primary that forges a chain from 2/5 of an old validator set
 *     (lunatic), or with 4/5 of the current one (equivocation, sequential
 *     and skipping), is caught: the call returns LIGHT_CLIENT_ATTACK, the
 *     store does not change, and the LOCAL RECORD holds the reference's
 *     two evidences — conflicting block and common height exactly as
 *     detector_test.go asserts them — plus the byzantine validators, the
 *     total voting power and the block timestamp, computed here;
 *   · a forward lunatic attack (a forged block above every honest
 *     witness's head) is caught after the reference's wait (DD2: the
 *     first call returns WITNESS_BEHIND, the call after the wait finds
 *     the witness's newer block), and at once when the witness already
 *     has it; with a witness that never catches up, the forged block is
 *     TRUSTED after the wait, as in the reference (detector.go:193-195);
 *   · the wait is measured against the caller's `now`: one nanosecond
 *     short of 2*drift + lag is still WITNESS_BEHIND;
 *   · witnesses that do not answer are benign; a witness whose conflicting
 *     header cannot be verified, or that cannot back it with a trace, is
 *     removed — and when it is the last one the call fails with
 *     NO_WITNESSES (Q-D3);
 *   · a witness whose set has other proposer priorities stops the call
 *     with PROPOSER_PRIORITIES_DIVERGE, including (K25-3) a set that
 *     differs only in a NON-LAST validator, which the reference's
 *     ProposerPriorityHash (types/validator_set.go:387-399, replicated
 *     here only to show it) hashes identically;
 *   · a cap reached inside the detector fails closed: nothing saved, the
 *     witness kept, no record (DD5); one more step and the same fixture
 *     is an attack with no evidence against the witness (Q-D4);
 *   · newLightClientAttackEvidence's three branches (lunatic,
 *     equivocation, amnesia) on direct calls;
 *   · (BUGS Z-42, DD6/DD10) an equivocating block with one more COMMIT
 *     signature past the 2/3 point whose address is in no set still
 *     verifies, and the attack is still LIGHT_CLIENT_ATTACK with its
 *     record kept: four equivocators named, one unknown signer counted;
 *   · (DD2) witnesses found bad in a pass that ends WITNESS_BEHIND are
 *     removed before it returns (detector.go:98-100), and the same
 *     target is trusted after the wait;
 *   · (K25-10, DD9 / client D20) an attack LOCKS the client: Update,
 *     verify and Cleanup are refused, the record is in the store byte for
 *     byte, a restart stays locked, the operator's clear unlocks and keeps
 *     the record, a second attack writes a second record, and after a
 *     clear an honest primary's block is verified and saved;
 *   · (BUGS Z-41, client D21) a primary that advances between Update
 *     calls does not restart the wait: after it, the RECORDED block is
 *     verified and saved, the next Update moves to the latest; a primary
 *     that answers the recorded height with another block is refused.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, NO CLOCK — every time is a fixed value after the reference's
 * bTime (2006-01-02T15:04:05Z). Keys come from `qgp_dsa87_keypair_derand`
 * with fixed seeds. Every large fixture is heap-allocated.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success: each case makes a temporary SQLite file
 * `test_cmt_light_detector.XXXXXX` in the working directory and removes it
 * (and its journal). A crash mid-run can leave one behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE MOCK DOES NOT VALIDATE (package 2's rule): it returns what it
 *     holds; every check on an answer is the client's (D15).
 *  2. The reference's goroutine that adds the proof block two seconds
 *     into the sleep (detector_test.go:255-258) is a `mock_add` between
 *     two calls; the sleep is a later `now`. The rows prove the port's
 *     two-pass decision (DD2), not any timing.
 *  3. The step count the cap row pins (13 Verify calls to bisect the
 *     honest chain from 1 to 10) is derived by hand from verifySkipping
 *     (client.go:699-773, with Q1's double append) and the fixture's key
 *     rotation; the row fails if that derivation is wrong.
 *  4. Random keys (`genPrivKeys`, `Extend`) are fixed seeds, distinct for
 *     every key; `genMockNode` called twice for "different nodes" is two
 *     key ranges.
 *  5. The same mock passed as primary AND witness becomes two instances
 *     with the same data and two identities (item 9 counts identities).
 *  6. ML-DSA-87 signing is HEDGED; no signature is frozen.
 *  7. The unknown-signer row needs the foreign signature AFTER the 2/3
 *     point; it re-signs block 6 in the set's index order and checks that
 *     slot 4 was the absent one before replacing it. Its 64 signature
 *     bytes are a pattern, never verified (that is the point).
 *  8. The lock row's "restart" is close + re-open of the store file, not
 *     a power cut (durability itself is PRAGMA synchronous=FULL,
 *     cmt_light_store.h, and is not exercised).
 *  9. The moving-target row (15) shows that the wait is not restarted by
 *     the result of call 2 (still WITNESS_BEHIND) and by what call 3
 *     saves (10, not 11); it cannot observe that call 2 made no fetch.
 *
 * ── REFERENCE CASES (light/detector_test.go) ───────────────────────────
 * PORTED: TestLightClientAttackEvidence_Lunatic (:21-91),
 * _Equivocation (:93-174, both modes), _ForwardLunatic (:176-306),
 * TestClientDivergentTraces1-4 (:311-431), TestClientDivergentHeaders-
 * NoTraces (:433-496; ONE iteration — the reference repeats it 100 times
 * to hit a goroutine race the single-threaded client does not have),
 * TestClientDivergentProposerPriorities (:498-550; the hashes it compares
 * are replaced by the full vector, K25-3).
 * Evidence DELIVERY (`witness.HasEvidence`, `primary.HasEvidence`) is not
 * ported: nothing is sent (DD4). Each such assertion is checked on the
 * local record instead — the same two fields `HasEvidence` compares
 * (`LightClientAttackEvidence.Hash`, types/evidence.go:321-331: the
 * conflicting block's hash and the common height).
 * PROJECT-AUTHORED: the K25-3 non-last-validator row, the attack/cap
 * (bounds) row, the wait-gating row, the direct evidence-builder rows,
 * the unknown-signer row (12), the behind-removes-bad row (13), the
 * attack-lock rows (14, and the clear inside the forward-lunatic row),
 * the moving-target Update row (15).
 *
 * @file test_cmt_light_detector.c
 */

#include "dnac/cmt_light_detector.h"
#include "dnac/cmt_light_client.h"
#include "dnac/cmt_light_store.h"
#include "dnac/cmt_light_block.h"
#include "dnac/cmt_light_provider.h"
#include "dnac/cmt_light_verifier.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_time.h"
#include "dnac/cmt_tmhash.h"

#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks = 0;

#define T(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        goto out; \
    } \
    g_checks++; \
} while (0)

/*
 * Keys. genMockNodeWithKeys(chainID, n, 5, 2, bTime) (helpers_test.go:
 * 186-238) rotates two of five keys every second height: the set at
 * height h is K_{h/2} and its next set K_{(h+1)/2}, where K_j is keys
 * 2j .. 2j+4 of the chain's range (derived from :207-235: `totalVariation`
 * alternates 2, 0, 2, …). Ranges:
 *   chain A ("primary" chain)  0 .. 16  (K_0 .. K_6, heights 1-12)
 *   lunatic forged extras      17 .. 19 (K_2.ChangeKeys(3) = {7,8,17,18,19})
 *   forward-lunatic extras     20 .. 22 (K_5.ChangeKeys(3) = {13,14,20,21,22})
 *   chain B (another node)     23 .. 37
 *   bounds-row forged extras   38 .. 40 ({0,1,38,39,40}, PROJECT)
 */
#define NKEYS   41
#define VALSZ   5
#define BASE_A  0
#define BASE_B  23

#define SECOND ((int64_t)1000000000)
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)

/* client_test.go:32 — bTime = 2006-01-02T15:04:05Z = 1136214245 s. */
#define BTIME_SECONDS ((int64_t)1136214245)
/* The vote stamp the reference takes from `cmttime.Now()`
 * (helpers_test.go:111); inside no checked relation. */
#define VOTE_SECONDS  ((int64_t)1700000000)

static const char CHAIN[] = "test-chain";

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_addr[NKEYS][CMT_ADDRESS_SIZE];

static cmt_valset_scratch_t  *g_scratch;
static cmt_light_block_buf_t *g_out;

typedef struct {
    cmt_validator_t     storage[8];
    cmt_validator_set_t vs;
} tvals_t;

typedef struct {
    cmt_header_t        h;
    cmt_commit_sig_t    sigs[8];
    cmt_commit_t        c;
    cmt_signed_header_t sh;
} tsh_t;

#define HMAX 14   /* heights 1..13 (index = height) */

typedef struct {
    tvals_t vals[HMAX];   /* vals[h] = the set at h; vals[h+1] = its next */
    tsh_t   sh[HMAX];
} tchain_t;

typedef struct {
    tchain_t a;              /* chain A, heights 1-12                    */
    tchain_t b;              /* chain B, heights 1-10                    */
    tvals_t  lun_vals;       /* {7,8,17,18,19} ToValidators(2, 0)        */
    tsh_t    lun[HMAX];      /* forged 6..10                             */
    tsh_t    equ[HMAX];      /* equivocating 6..10                       */
    tvals_t  fwd_vals;       /* {13,14,20,21,22}                         */
    tsh_t    fwd12;          /* forged 12 at bTime + 11 min              */
    tvals_t  proof_vals;     /* K_5 ToValidators(2, 0)                   */
    tsh_t    proof11;        /* 11 at bTime + 12 min                     */
    tsh_t    div1, div2;     /* :445-455 divergent app hashes at 10      */
    tvals_t  prio10;         /* :517 vals[10].CopyIncrementProposerPriority(1) */
    tvals_t  k25_10;         /* PROJECT: vals[10], priority of #0 changed */
    tvals_t  bnd_vals;       /* {0,1,38,39,40}                           */
    tsh_t    bnd10;          /* PROJECT: forged 10 at bTime + 10 min     */
} tfix_t;

static tfix_t *F;

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static cmt_time_t t_at(int64_t ns_after_btime)
{
    cmt_time_t b;

    b.seconds = BTIME_SECONDS;
    b.nanos   = 0;
    return cmt_time_add_ns(b, ns_after_btime);
}

static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static int build_keys(void)
{
    uint8_t seed[32];
    int     i;

    for (i = 0; i < NKEYS; i++) {
        memset(seed, 0, sizeof(seed));
        seed[0] = 0xD7;                 /* this file's seed family */
        seed[1] = (uint8_t)i;
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0 ||
            cmt_pubkey_address(g_pk[i], g_addr[i]) != CMT_OK) {
            fprintf(stderr, "key %d failed\n", i);
            return 1;
        }
    }
    return 0;
}

static int key_of_address(const uint8_t *addr, size_t len)
{
    int i;

    if (len != (size_t)CMT_ADDRESS_SIZE) {
        return -1;
    }
    for (i = 0; i < NKEYS; i++) {
        if (memcmp(g_addr[i], addr, CMT_ADDRESS_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

/* K_j of a chain range: keys base+2j .. base+2j+4 (see "Keys"). */
static void kset(int base, int j, int out[VALSZ])
{
    int i;

    for (i = 0; i < VALSZ; i++) {
        out[i] = base + 2 * j + i;
    }
}

/* helpers_test.go:67-73 `ToValidators(init, inc)`. */
static int make_vals(tvals_t *out, const int *keys, size_t n,
                     int64_t init, int64_t inc)
{
    cmt_validator_t     list[8];
    cmt_pb_public_key_t pk;
    size_t              i;

    if (n > 8u) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[keys[i]], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, init + (int64_t)i * inc,
                              &list[i]) != CMT_OK) {
            return 1;
        }
    }
    if (cmt_validator_set_init(&out->vs, out->storage, 8) != CMT_OK ||
        cmt_validator_set_new(&out->vs, list, n, g_scratch) != CMT_OK) {
        return 1;
    }
    return 0;
}

static int vals_hash(cmt_validator_set_t *vs, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           *scratch;
    cmt_merkle_item_t  items[8];
    int                rc;

    scratch = (uint8_t *)malloc(8 * (size_t)CMT_VALIDATOR_BYTES_MAX);
    if (scratch == NULL) {
        return 1;
    }
    rc = cmt_validator_set_hash(vs, scratch, 8 * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                items, 8, out);
    free(scratch);
    return rc == CMT_OK ? 0 : 1;
}

static int sign_entry(cmt_commit_t *c, cmt_validator_set_t *vs, size_t idx)
{
    uint8_t           sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t            sb_len;
    size_t            siglen;
    cmt_commit_sig_t *cs = &c->signatures[idx];
    int               k;

    memset(cs, 0, sizeof(*cs));
    cs->block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    memcpy(cs->validator_address, vs->validators[idx].address,
           CMT_ADDRESS_SIZE);
    cs->validator_address_len = CMT_ADDRESS_SIZE;
    cs->timestamp.seconds     = VOTE_SECONDS;
    cs->timestamp.nanos       = 0;

    k = key_of_address(vs->validators[idx].address,
                       vs->validators[idx].address_len);
    if (k < 0 ||
        cmt_commit_vote_sign_bytes(c, (const uint8_t *)CHAIN, strlen(CHAIN),
                                   (int32_t)idx, sb, sizeof(sb),
                                   &sb_len) != CMT_OK ||
        qgp_dsa87_sign(cs->signature, &siglen, sb, sb_len, g_sk[k]) != 0) {
        fprintf(stderr, "sign entry %zu failed\n", idx);
        return 1;
    }
    cs->signature_len = siglen;
    return 0;
}

/*
 * helpers_test.go:135-177 — genHeader + signHeader + GenSignedHeader /
 * GenSignedHeaderLastBlockID. `keys` is `pkz` (nkeys entries); the commit
 * has one entry per key (:77), absent (:78-80) except the votes of
 * keys[first..last) (:88-91), at their index in `valset` (:105).
 * `last_hash` NULL is GenSignedHeader. `txs` NULL is `nil`. ADAPTED: the
 * PartSetHeader hash (32 random bytes, :84) is a 64-byte pattern.
 */
static int gen_sh(tsh_t *out, int64_t height, cmt_time_t btime,
                  const cmt_data_t *txs, tvals_t *valset, tvals_t *next_valset,
                  const int *keys, size_t nkeys, size_t first, size_t last,
                  const uint8_t *last_hash, const char *app)
{
    cmt_header_t *h = &out->h;
    size_t        i;

    if (nkeys > 8u) {
        return 1;
    }
    cmt_pb_header_init(h);
    h->version.block = CMT_BLOCK_PROTOCOL;                       /* :139 */
    h->version.app   = 0;
    memcpy(h->chain_id, CHAIN, strlen(CHAIN));                   /* :140 */
    h->chain_id_len  = strlen(CHAIN);
    h->height        = height;                                   /* :141 */
    h->time          = btime;                                    /* :142 */
    if (last_hash != NULL) {                                     /* :173 */
        memcpy(h->last_block_id.hash, last_hash, CMT_TMHASH_SIZE);
        h->last_block_id.hash_len = CMT_TMHASH_SIZE;
    }
    if (vals_hash(&valset->vs, h->validators_hash) != 0 ||       /* :145 */
        vals_hash(&next_valset->vs, h->next_validators_hash) != 0 ||
        cmt_data_hash(txs, h->data_hash) != CMT_OK ||            /* :147 */
        cmt_tmhash_sum((const uint8_t *)app, strlen(app),
                       h->app_hash) != CMT_OK ||                 /* :148 */
        cmt_tmhash_sum((const uint8_t *)"cons_hash", 9,
                       h->consensus_hash) != CMT_OK ||           /* :149 */
        cmt_tmhash_sum((const uint8_t *)"results_hash", 12,
                       h->last_results_hash) != CMT_OK) {        /* :150 */
        return 1;
    }
    h->validators_hash_len      = CMT_TMHASH_SIZE;
    h->next_validators_hash_len = CMT_TMHASH_SIZE;
    h->data_hash_len            = CMT_TMHASH_SIZE;
    h->app_hash_len             = CMT_TMHASH_SIZE;
    h->consensus_hash_len       = CMT_TMHASH_SIZE;
    h->last_results_hash_len    = CMT_TMHASH_SIZE;
    memcpy(h->proposer_address, valset->vs.validators[0].address,
           CMT_ADDRESS_SIZE);                                    /* :151 */
    h->proposer_address_len = CMT_ADDRESS_SIZE;

    cmt_pb_commit_init(&out->c);
    out->c.height         = height;                              /* :94 */
    out->c.round          = 1;                                   /* :95 */
    out->c.signatures     = out->sigs;
    out->c.signatures_cap = 8;
    out->c.signatures_len = nkeys;
    for (i = 0; i < nkeys; i++) {
        cmt_new_commit_sig_absent(&out->sigs[i]);                /* :79 */
    }
    if (cmt_header_hash(h, out->c.block_id.hash) != CMT_OK) {    /* :83 */
        return 1;
    }
    out->c.block_id.hash_len                 = CMT_TMHASH_SIZE;
    out->c.block_id.part_set_header.total    = 1u;               /* :84 */
    pat(out->c.block_id.part_set_header.hash, CMT_TMHASH_SIZE, 0x5C);
    out->c.block_id.part_set_header.hash_len = CMT_TMHASH_SIZE;

    for (i = first; i < last && i < nkeys; i++) {                /* :88 */
        int32_t idx = -1;

        if (cmt_validator_set_get_by_address(&valset->vs, g_addr[keys[i]],
                                             CMT_ADDRESS_SIZE, &idx,
                                             NULL) != CMT_OK ||
            idx < 0 || (size_t)idx >= nkeys ||
            sign_entry(&out->c, &valset->vs, (size_t)idx) != 0) {
            return 1;
        }
    }
    out->sh.header = &out->h;
    out->sh.commit = &out->c;
    return 0;
}

static int sh_hash(const tsh_t *s, uint8_t out[CMT_TMHASH_SIZE])
{
    return cmt_header_hash(&s->h, out) == CMT_OK ? 0 : 1;
}

/* helpers_test.go:186-238 — genMockNodeWithKeys(chainID, n, 5, 2, bTime)
 * over the key range at `base`: vals[h] = K_{h/2}, header h signed by all
 * of K_{h/2} at bTime + h min, next set K_{(h+1)/2}, LastBlockID = the
 * previous header's hash from height 2 (:225-228). */
static int build_chain(tchain_t *ch, int base, int64_t n)
{
    uint8_t hh[CMT_TMHASH_SIZE];
    int     k[VALSZ];
    int64_t h;

    if (n + 1 >= HMAX) {
        return 1;
    }
    for (h = 1; h <= n + 1; h++) {
        kset(base, (int)(h / 2), k);
        if (make_vals(&ch->vals[h], k, VALSZ, 2, 0) != 0) {
            return 1;
        }
    }
    for (h = 1; h <= n; h++) {
        kset(base, (int)(h / 2), k);
        if (h > 1 && sh_hash(&ch->sh[h - 1], hh) != 0) {
            return 1;
        }
        if (gen_sh(&ch->sh[h], h, t_at(h * MINUTE), NULL, &ch->vals[h],
                   &ch->vals[h + 1], k, VALSZ, 0, VALSZ,
                   h > 1 ? hh : NULL, "app_hash") != 0) {
            return 1;
        }
    }
    return 0;
}

static int build_fixture(tfix_t *f)
{
    static const int LUN[VALSZ] = { 7, 8, 17, 18, 19 };
    static const int FWD[VALSZ] = { 13, 14, 20, 21, 22 };
    static const int BND[VALSZ] = { 0, 1, 38, 39, 40 };
    cmt_pb_bytes_t   tx;
    cmt_data_t       txs;
    int              k[VALSZ];
    int64_t          h;

    if (build_chain(&f->a, BASE_A, 12) != 0 ||
        build_chain(&f->b, BASE_B, 10) != 0) {
        return 1;
    }

    /* detector_test.go:33-45 — forgedKeys = chainKeys[5].ChangeKeys(3),
     * forgedVals = ToValidators(2, 0); heights 6..10 GenSignedHeader
     * (no LastBlockID), all forged keys signing. */
    if (make_vals(&f->lun_vals, LUN, VALSZ, 2, 0) != 0) {
        return 1;
    }
    for (h = 6; h <= 10; h++) {
        if (gen_sh(&f->lun[h], h, t_at(h * MINUTE), NULL, &f->lun_vals,
                   &f->lun_vals, LUN, VALSZ, 0, VALSZ, NULL,
                   "app_hash") != 0) {
            return 1;
        }
    }

    /* :114-127 — chainKeys[h] (K_{h/2}) signs, with the first 4 of 5
     * keys, a header with txs "abcd" over the witness's sets. */
    tx.data      = (const uint8_t *)"abcd";
    tx.len       = 4;
    txs.txs      = &tx;
    txs.txs_cap  = 1;
    txs.txs_len  = 1;
    for (h = 6; h <= 10; h++) {
        kset(BASE_A, (int)(h / 2), k);
        if (gen_sh(&f->equ[h], h, t_at(h * MINUTE), &txs, &f->a.vals[h],
                   &f->a.vals[h + 1], k, VALSZ, 0, VALSZ - 1, NULL,
                   "app_hash") != 0) {
            return 1;
        }
    }

    /* :196-209 — forgedKeys = chainKeys[10].ChangeKeys(3), forged height
     * 12 at bTime + 11 min. */
    if (make_vals(&f->fwd_vals, FWD, VALSZ, 2, 0) != 0 ||
        gen_sh(&f->fwd12, 12, t_at(11 * MINUTE), NULL, &f->fwd_vals,
               &f->fwd_vals, FWD, VALSZ, 0, VALSZ, NULL, "app_hash") != 0) {
        return 1;
    }
    /* :239-254 — chainKeys[10] signs height 11 at bTime + 12 min. */
    kset(BASE_A, 5, k);
    if (make_vals(&f->proof_vals, k, VALSZ, 2, 0) != 0 ||
        gen_sh(&f->proof11, 11, t_at(12 * MINUTE), NULL, &f->proof_vals,
               &f->proof_vals, k, VALSZ, 0, VALSZ, NULL, "app_hash") != 0) {
        return 1;
    }

    /* :440-455 — keysAtH10 sign height 10 at primaryHeaders[10].Time with
     * valsAtH10 / nextValsAtH11 (= K_5) and a divergent app hash. */
    kset(BASE_A, 5, k);
    if (gen_sh(&f->div1, 10, t_at(10 * MINUTE), NULL, &f->a.vals[10],
               &f->a.vals[11], k, VALSZ, 0, VALSZ, NULL,
               "divergent_app_1") != 0 ||
        gen_sh(&f->div2, 10, t_at(10 * MINUTE), NULL, &f->a.vals[10],
               &f->a.vals[11], k, VALSZ, 0, VALSZ, NULL,
               "divergent_app_2") != 0) {
        return 1;
    }

    /* :517 — CopyIncrementProposerPriority(1). */
    if (cmt_validator_set_init(&f->prio10.vs, f->prio10.storage, 8) != CMT_OK ||
        cmt_validator_set_copy_increment_proposer_priority(&f->a.vals[10].vs,
                                                           &f->prio10.vs,
                                                           1) != CMT_OK) {
        return 1;
    }

    /* PROJECT (K25-3): vals[10] with ONLY validator #0's priority moved by
     * one — the hash, the proposer and every other priority unchanged. */
    if (cmt_validator_set_init(&f->k25_10.vs, f->k25_10.storage, 8) != CMT_OK ||
        cmt_validator_set_copy(&f->a.vals[10].vs, &f->k25_10.vs) != CMT_OK ||
        f->k25_10.vs.validators_len != VALSZ) {
        return 1;
    }
    f->k25_10.vs.validators[0].proposer_priority += 1;

    /* PROJECT (bounds/attack): a height-10 block signed by {0,1} of K_0
     * plus three foreign keys — the primary can skip 1 → 10 in ONE Verify
     * (2/5 of K_0 signed); bisecting the honest chain from 1 to 10 takes
     * 13 (how it can lie, 3). */
    if (make_vals(&f->bnd_vals, BND, VALSZ, 2, 0) != 0 ||
        gen_sh(&f->bnd10, 10, t_at(10 * MINUTE), NULL, &f->bnd_vals,
               &f->bnd_vals, BND, VALSZ, 0, VALSZ, NULL, "app_hash") != 0) {
        return 1;
    }
    return 0;
}

/* ══ the mock provider (light/provider/mock/mock.go, deadmock.go) ════ */

#define MOCK_MAX 16

typedef struct {
    const char                *chain_id;
    bool                       dead;
    int64_t                    heights[MOCK_MAX];
    const cmt_signed_header_t *headers[MOCK_MAX];
    cmt_validator_set_t       *vals[MOCK_MAX];
    size_t                     n;
    int64_t                    latest_height;
    size_t                     evidence_calls;   /* must stay 0 (DD4) */
} tmock_t;

static void mock_init(tmock_t *m)
{
    memset(m, 0, sizeof(*m));
    m->chain_id = CHAIN;
}

/* mock.go:27-43 New / :116-128 AddLightBlock — latestHeight is the
 * largest key. Replaces an existing height. */
static void mock_add(tmock_t *m, int64_t height, const tsh_t *sh,
                     cmt_validator_set_t *vs)
{
    size_t i;

    for (i = 0; i < m->n; i++) {
        if (m->heights[i] == height) {
            m->headers[i] = &sh->sh;
            m->vals[i]    = vs;
            return;
        }
    }
    if (m->n >= MOCK_MAX) {
        return;
    }
    m->heights[m->n] = height;
    m->headers[m->n] = &sh->sh;
    m->vals[m->n]    = vs;
    m->n++;
    if (height > m->latest_height) {
        m->latest_height = height;
    }
}

/* A chain's heights 1..n. */
static void mock_chain(tmock_t *m, tchain_t *ch, int64_t n)
{
    int64_t h;

    mock_init(m);
    for (h = 1; h <= n; h++) {
        mock_add(m, h, &ch->sh[h], &ch->vals[h].vs);
    }
}

static int mock_chain_id(void *ctx, const uint8_t **out, size_t *out_len)
{
    tmock_t *m = ctx;

    if (m == NULL || out == NULL || out_len == NULL) {
        return CMT_FAULT;
    }
    *out     = (const uint8_t *)m->chain_id;
    *out_len = strlen(m->chain_id);
    return CMT_OK;
}

static void prov_err(cmt_light_provider_error_t *err, int code)
{
    if (err != NULL) {
        err->code   = code;
        err->reason = CMT_OK;
    }
}

/* Copy what the mock holds AS IS — no validation (how it can lie, 1). */
static int mock_copy(cmt_light_block_buf_t *out, const cmt_signed_header_t *sh,
                     cmt_validator_set_t *vs)
{
    if (cmt_light_block_buf_reset(out) != CMT_OK) {
        return CMT_FAULT;
    }
    if (sh != NULL) {
        if (sh->header != NULL) {
            out->header               = *sh->header;
            out->signed_header.header = &out->header;
        }
        if (sh->commit != NULL) {
            if (sh->commit->signatures_len > (size_t)CMT_VALSET_MAX) {
                return CMT_FAULT;
            }
            out->commit                = *sh->commit;
            out->commit.signatures     = out->sigs;
            out->commit.signatures_cap = (size_t)CMT_VALSET_MAX;
            if (sh->commit->signatures_len > 0u) {
                memcpy(out->sigs, sh->commit->signatures,
                       sh->commit->signatures_len * sizeof(out->sigs[0]));
            }
            out->signed_header.commit = &out->commit;
        }
        out->lb.signed_header = &out->signed_header;
    }
    if (vs != NULL) {
        if (cmt_validator_set_copy(vs, &out->validator_set) != CMT_OK) {
            return CMT_FAULT;
        }
        out->lb.validator_set = &out->validator_set;
    }
    return CMT_OK;
}

/* mock.go:64-103 LightBlock; deadmock.go:23-25. */
static int mock_light_block(void *ctx, int64_t height,
                            cmt_light_block_buf_t *out,
                            cmt_light_provider_error_t *err)
{
    tmock_t *m = ctx;
    size_t   i;

    prov_err(err, CMT_LIGHT_PROVIDER_ERR_NONE);
    if (m == NULL || out == NULL || height < 0) {
        return CMT_FAULT;
    }
    (void)cmt_light_block_buf_reset(out);
    if (m->dead) {                                               /* deadmock.go:24 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE);
        return CMT_REJECT;
    }
    if (height > m->latest_height) {                             /* :77-79 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH);
        return CMT_REJECT;
    }
    if (height == 0 && m->n > 0u) {                              /* :81-83 */
        height = m->latest_height;
    }
    for (i = 0; i < m->n; i++) {                                 /* :85-92 */
        if (m->heights[i] == height) {
            return mock_copy(out, m->headers[i], m->vals[i]);    /* :102 */
        }
    }
    prov_err(err, CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND); /* :93-95 */
    return CMT_REJECT;
}

/* mock.go:105-108 — counted; the detector must never call it (DD4). */
static int mock_report_evidence(void *ctx, const cmt_pb_evidence_t *ev)
{
    tmock_t *m = ctx;

    (void)ev;
    if (m == NULL) {
        return CMT_FAULT;
    }
    m->evidence_calls++;
    return CMT_OK;
}

static cmt_light_client_peer_t peer_of(tmock_t *m, const char *id)
{
    cmt_light_client_peer_t p;

    memset(&p, 0, sizeof(p));
    p.provider.ctx             = m;
    p.provider.chain_id        = mock_chain_id;
    p.provider.light_block     = mock_light_block;
    p.provider.report_evidence = mock_report_evidence;
    p.id                       = (const uint8_t *)id;
    p.id_len                   = strlen(id);
    return p;
}

/* ══ the store, the client ════════════════════════════════════════════ */

typedef struct {
    char                  path[64];
    cmt_light_store_db_t *db;
    cmt_light_store_t     st;
} tstore_t;

static int store_open(tstore_t *s)
{
    int fd;

    memset(s, 0, sizeof(*s));
    memcpy(s->path, "test_cmt_light_detector.XXXXXX",
           sizeof("test_cmt_light_detector.XXXXXX"));
    fd = mkstemp(s->path);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed\n");
        return 1;
    }
    (void)close(fd);
    if (cmt_light_store_db_open(s->path, (const uint8_t *)CHAIN,
                                strlen(CHAIN), CMT_BLOCK_PROTOCOL,
                                &s->db) != CMT_OK) {
        (void)unlink(s->path);
        return 1;
    }
    cmt_light_store_db_bind(s->db, &s->st);
    return 0;
}

static void store_close(tstore_t *s)
{
    char journal[96];

    cmt_light_store_db_close(s->db);
    s->db = NULL;
    if (s->path[0] != '\0') {
        (void)unlink(s->path);
        (void)snprintf(journal, sizeof(journal), "%s-journal", s->path);
        (void)unlink(journal);
        s->path[0] = '\0';
    }
}

static int64_t last_h(tstore_t *s)
{
    int64_t h = -2;

    (void)cmt_light_store_db_last_light_block_height(s->db, &h);
    return h;
}

static void opts_default(cmt_light_client_options_t *o)
{
    cmt_light_client_options_default(o);
    o->max_trace_len       = 1000u;
    o->max_verify_steps    = 1000u;
    o->max_skipping_cache  = 1000u;
    o->max_backwards_steps = 1000u;
}

/* NewClient with TrustOptions{4 h, 1, hash of chain A's block 1}
 * (detector_test.go:51-55, :133-137, …). */
static int new_client(tmock_t *prim, const char *pid, tmock_t *ws,
                      const char *const *wids, size_t nw,
                      const cmt_light_client_options_t *o, tstore_t *s,
                      cmt_light_client_t **c, cmt_light_client_error_t *e)
{
    cmt_light_client_peer_t   pp, wp[4];
    cmt_light_trust_options_t t;
    uint8_t                   hh[CMT_TMHASH_SIZE];
    size_t                    i;

    if (nw > 4u || sh_hash(&F->a.sh[1], hh) != 0) {
        return CMT_FAULT;
    }
    t.period   = 4 * HOUR;
    t.height   = 1;
    t.hash     = hh;
    t.hash_len = CMT_TMHASH_SIZE;
    pp = peer_of(prim, pid);
    for (i = 0; i < nw; i++) {
        wp[i] = peer_of(&ws[i], wids[i]);
    }
    return cmt_light_client_new((const uint8_t *)CHAIN, strlen(CHAIN), &t,
                                &pp, wp, nw, &s->st, o, c, e);
}

/* `HasEvidence(ev)` compares ev.Hash() = H(ConflictingBlock.Hash(),
 * CommonHeight) (types/evidence.go:321-331): the same two fields here. */
static bool ev_is(const cmt_light_attack_evidence_t *ev, const tsh_t *conflicting,
                  int64_t common_height)
{
    uint8_t a[CMT_TMHASH_SIZE], b[CMT_TMHASH_SIZE];

    return ev->conflicting_block != NULL &&
           ev->conflicting_block->lb.signed_header != NULL &&
           ev->conflicting_block->lb.signed_header->header != NULL &&
           cmt_header_hash(ev->conflicting_block->lb.signed_header->header,
                           a) == CMT_OK &&
           sh_hash(conflicting, b) == 0 &&
           memcmp(a, b, CMT_TMHASH_SIZE) == 0 &&
           ev->common_height == common_height;
}

/* Every validator of `ev` is one of `keys`, and they are `n` in all. */
static bool byz_are(const cmt_light_attack_evidence_t *ev, const int *keys,
                    size_t n)
{
    size_t i, j;

    if (ev->n_byzantine != n) {
        return false;
    }
    for (i = 0; i < n; i++) {
        bool found = false;

        for (j = 0; j < n; j++) {
            if (ev->byzantine_validators[i].address_len == CMT_ADDRESS_SIZE &&
                memcmp(ev->byzantine_validators[i].address, g_addr[keys[j]],
                       CMT_ADDRESS_SIZE) == 0) {
                found = true;
            }
        }
        if (!found) {
            return false;
        }
    }
    /* ValidatorsByVotingPower: equal power → ascending address. */
    for (i = 1; i < n; i++) {
        if (memcmp(ev->byzantine_validators[i - 1].address,
                   ev->byzantine_validators[i].address, CMT_ADDRESS_SIZE) >= 0) {
            return false;
        }
    }
    return true;
}

static bool time_eq(cmt_time_t a, cmt_time_t b)
{
    return a.seconds == b.seconds && a.nanos == b.nanos;
}

/* ══ 1. TestLightClientAttackEvidence_Lunatic (detector_test.go:21-91) ═ */

static int t_lunatic(void)
{
    static const int BYZ_P[2] = { 7, 8 };      /* forged ∩ K_2 */
    static const int BYZ_W[3] = { 6, 7, 8 };   /* K_3 ∩ K_2   */
    tmock_t                          p, w[1];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    const cmt_light_attack_record_t *r;
    const char                      *wid[1] = { "witness" };
    int64_t                          h;
    int                              ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&w[0], &F->a, 10);                                /* :31-32 */
    mock_init(&p);                                               /* :36-46 */
    for (h = 1; h <= 10; h++) {
        if (h < 6) {
            mock_add(&p, h, &F->a.sh[h], &F->a.vals[h].vs);
        } else {
            mock_add(&p, h, &F->lun[h], &F->lun_vals.vs);
        }
    }
    opts_default(&o);
    o.max_retry_attempts = 1;                                    /* :60 */
    T(new_client(&p, "primary", w, wid, 1, &o, &s, &c, &e) == CMT_OK, "init");

    /* :64-68 — ErrLightClientAttack. */
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK &&
      e.witness_index == 0, "verify 10 → attack");
    T(last_h(&s) == 1, "nothing saved");

    r = cmt_light_client_attack_record(c);
    T(r != NULL, "a local record");
    /* :71-79 — against the primary: conflicting primary[10], common 4. */
    T(ev_is(&r->against_primary, &F->lun[10], 4), "against primary: 10 / 4");
    /* evidence.go:257-271 — lunatic: the forged commit's signers in the
     * common set K_2 = {4..8}; total = K_2's; timestamp = block 4's. */
    T(r->against_primary.attack == CMT_LIGHT_ATTACK_LUNATIC &&
      byz_are(&r->against_primary, BYZ_P, 2) &&
      r->against_primary.total_voting_power == 10 &&
      time_eq(r->against_primary.timestamp, t_at(4 * MINUTE)),
      "against primary: byzantine {7, 8}, power 10, time of 4");
    /* :81-90 — against the witness: conflicting witness[7], common 4. */
    T(r->has_against_witness && ev_is(&r->against_witness, &F->a.sh[7], 4),
      "against witness: 7 / 4");
    T(byz_are(&r->against_witness, BYZ_W, 3), "against witness: {6, 7, 8}");
    T(r->witness_index == 0 && r->witness_id_len == 7 &&
      memcmp(r->witness_id, "witness", 7) == 0 &&
      r->primary_id_len == 7 && memcmp(r->primary_id, "primary", 7) == 0 &&
      time_eq(r->now, t_at(HOUR)) && !r->commit_rounds_differ,
      "record: who, when");
    /* DD4 — nothing was sent to either provider. */
    T(p.evidence_calls == 0 && w[0].evidence_calls == 0, "nothing sent");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 2. TestLightClientAttackEvidence_Equivocation (:93-174) ═════════ */

static int equivocation_case(int mode)
{
    tmock_t                          p, w[1];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    const cmt_light_attack_record_t *r;
    const char                      *wid[1] = { "witness" };
    int64_t                          h;
    int                              ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&w[0], &F->a, 12);                                /* :111-112 */
    mock_init(&p);                                               /* :114-127 */
    for (h = 1; h <= 10; h++) {
        if (h < 6) {
            mock_add(&p, h, &F->a.sh[h], &F->a.vals[h].vs);
        } else {
            mock_add(&p, h, &F->equ[h], &F->a.vals[h].vs);
        }
    }
    opts_default(&o);
    o.verification_mode = mode;                                  /* :143 */
    T(new_client(&p, "primary", w, wid, 1, &o, &s, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK,
      "verify 10 → attack");                                     /* :148-151 */
    T(last_h(&s) == 1, "nothing saved");
    r = cmt_light_client_attack_record(c);
    T(r != NULL, "a local record");
    /* :156-163 — conflicting primary[6], common 6 (the sets are the
     * same: not a lunatic header, so the trusted block's height). */
    T(ev_is(&r->against_primary, &F->equ[6], 6), "against primary: 6 / 6");
    /* evidence.go:272-292 — same round: the four that signed both. */
    T(r->against_primary.attack == CMT_LIGHT_ATTACK_EQUIVOCATION &&
      r->against_primary.n_byzantine == 4 &&
      r->against_primary.total_voting_power == 10 &&
      time_eq(r->against_primary.timestamp, t_at(6 * MINUTE)),
      "against primary: 4 equivocators, power 10, time of 6");
    /* :165-172 — conflicting witness[6], common 6. */
    T(r->has_against_witness && ev_is(&r->against_witness, &F->a.sh[6], 6),
      "against witness: 6 / 6");
    T(p.evidence_calls == 0 && w[0].evidence_calls == 0, "nothing sent");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_equivocation(void)
{
    if (equivocation_case(CMT_LIGHT_CLIENT_MODE_SEQUENTIAL) != 0) {  /* :95 */
        fprintf(stderr, "equivocation: sequential\n");
        return 1;
    }
    if (equivocation_case(CMT_LIGHT_CLIENT_MODE_SKIPPING) != 0) {    /* :96 */
        fprintf(stderr, "equivocation: skipping\n");
        return 1;
    }
    return 0;
}

/* ══ 3. TestLightClientAttackEvidence_ForwardLunatic (:176-306) ══════ */

/* primary: chain A 1..10 and the forged 12 (:192-209). */
static void mock_fwd_primary(tmock_t *m)
{
    mock_chain(m, &F->a, 10);
    mock_add(m, 12, &F->fwd12, &F->fwd_vals.vs);
}

static int t_forward_lunatic(void)
{
    tmock_t                          p, ws[2];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    const cmt_light_attack_record_t *r;
    const char                      *wid[2] = { "witness", "accomplice" };
    cmt_time_t                       now = t_at(12 * MINUTE);    /* :262 */
    int64_t                          wait = 3 * SECOND;          /* 2*1 s + 1 s */
    bool                             adv = true;
    int                              ret = 1;

    memset(&s, 0, sizeof(s));
    if (store_open(&s) != 0) {
        return 1;
    }
    mock_fwd_primary(&p);
    mock_chain(&ws[0], &F->a, 10);                               /* :211 witness */
    mock_fwd_primary(&ws[1]);                                    /* :218 accomplice */
    opts_default(&o);
    o.max_clock_drift = SECOND;                                  /* :232 */
    o.max_block_lag   = SECOND;                                  /* :233 */
    T(new_client(&p, "primary", ws, wid, 2, &o, &s, &c, &e) == CMT_OK, "init");

    /* The reference's Update sleeps 3 s and, meanwhile, the witness gets
     * block 11 (:255-258). DD2: the first call says "behind". */
    T(cmt_light_client_update(c, now, g_out, &adv, &e) == CMT_REJECT && !adv &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "1st Update → behind");
    T(last_h(&s) == 1 && cmt_light_client_attack_record(c) == NULL,
      "behind: nothing saved, no record");
    mock_add(&ws[0], 11, &F->proof11, &F->proof_vals.vs);        /* :257 */
    /* :262-265 — after the wait: ErrLightClientAttack. */
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait), g_out, &adv,
                              &e) == CMT_REJECT && !adv &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK &&
      e.witness_index == 0, "Update after the wait → attack");
    T(last_h(&s) == 1, "nothing saved");
    r = cmt_light_client_attack_record(c);
    /* :268-275 — conflicting primary[12], common 10. */
    T(r != NULL && ev_is(&r->against_primary, &F->fwd12, 10),
      "against primary: 12 / 10");
    /* Q-D4 — the primary has no block 11: the reverse examine fails and
     * the attack stands without evidence against the witness. */
    T(!r->has_against_witness, "no evidence against the witness");

    /* K25-10 (DD9) — the attack locked the client: the reference's next
     * call (:277-283) is refused until the operator clears. */
    T(cmt_light_client_attack_locked(c) &&
      cmt_light_client_verify_light_block_at_height(c, 12, now, g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED, "locked → refused");
    T(cmt_light_client_attack_clear(c) == CMT_OK &&
      !cmt_light_client_attack_locked(c), "operator clear");
    /* :277-283 — the witness now has 11 at once: attack without a wait. */
    T(cmt_light_client_verify_light_block_at_height(c, 12, now, g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK, "verify 12 → attack");
    r = cmt_light_client_attack_record(c);
    T(r != NULL && ev_is(&r->against_primary, &F->fwd12, 10), "again 12 / 10");
    cmt_light_client_free(c);
    c = NULL;
    store_close(&s);

    /* :285-305 — a lagging witness that never gets block 11: after the
     * wait the forged block IS trusted (detector.go:193-196). */
    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&ws[0], &F->a, 10);                               /* :214 laggingWitness */
    mock_fwd_primary(&ws[1]);
    wid[0] = "lagging";
    T(new_client(&p, "primary", ws, wid, 2, &o, &s, &c, &e) == CMT_OK,
      "init (lagging)");
    T(cmt_light_client_update(c, now, g_out, &adv, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "lagging: behind");
    /* PROJECT — the wait is the caller's `now`: 1 ns short is still the
     * first pass. */
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait - 1), g_out, &adv,
                              &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "1 ns short → behind");
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait), g_out, &adv,
                              &e) == CMT_OK && adv &&
      g_out->lb.signed_header != NULL &&
      g_out->lb.signed_header->header->height == 12,
      "after the wait → NoError, 12 trusted (:304-305)");
    T(last_h(&s) == 12, "12 saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 4-7. TestClientDivergentTraces1-4 (:311-431) ════════════════════ */

static int t_divergent_traces(void)
{
    tmock_t                    p, ws[3];
    tstore_t                   s;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    const char                *wid[3];
    int64_t                    h;
    int                        ret = 1;

    memset(&s, 0, sizeof(s));
    opts_default(&o);
#define FRESH() do { cmt_light_client_free(c); c = NULL; store_close(&s); \
                     if (store_open(&s) != 0) goto out; } while (0)

    /* 1 (:311-333) — another node: init stops, "does not match primary"
     * (the item-9 rule, cmt_light_client.h R5). */
    FRESH();
    mock_chain(&p, &F->a, 10);
    mock_chain(&ws[0], &F->b, 10);
    wid[0] = "other-node";
    T(new_client(&p, "primary", ws, wid, 1, &o, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS, "1: init refused");

    /* 2 (:337-360) — two dead witnesses and one with the primary's data:
     * verified, all three remain. */
    FRESH();
    mock_chain(&p, &F->a, 10);
    mock_init(&ws[0]);
    ws[0].dead = true;
    mock_init(&ws[1]);
    ws[1].dead = true;
    mock_chain(&ws[2], &F->a, 10);
    wid[0] = "dead-1";
    wid[1] = "dead-2";
    wid[2] = "primary-copy";
    T(new_client(&p, "primary", ws, wid, 3, &o, &s, &c, &e) == CMT_OK, "2: init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_OK, "2: verified");
    T(cmt_light_client_witness_count(c) == 3, "2: three witnesses");

    /* 3 (:364-395) — the same first block, another chain after it: the
     * witness's trace does not verify → removed; it is the last one, so
     * the call fails (Q-D3) and the witness stays. */
    FRESH();
    mock_chain(&p, &F->a, 10);
    mock_chain(&ws[0], &F->b, 10);
    mock_add(&ws[0], 1, &F->a.sh[1], &F->a.vals[1].vs);         /* :372-373 */
    wid[0] = "fork-after-1";
    T(new_client(&p, "primary", ws, wid, 1, &o, &s, &c, &e) == CMT_OK, "3: init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NO_WITNESSES, "3: error");
    T(cmt_light_client_witness_count(c) == 1 && last_h(&s) == 1,
      "3: one witness, nothing saved");

    /* 4 (:399-431) — the primary's chain with another block 10: no trace
     * backs it → removed → last one → error. */
    FRESH();
    mock_chain(&p, &F->a, 10);
    mock_init(&ws[0]);
    for (h = 1; h <= 9; h++) {
        mock_add(&ws[0], h, &F->a.sh[h], &F->a.vals[h].vs);
    }
    mock_add(&ws[0], 10, &F->b.sh[10], &F->b.vals[10].vs);       /* :408-411 */
    wid[0] = "copy-with-other-10";
    T(new_client(&p, "primary", ws, wid, 1, &o, &s, &c, &e) == CMT_OK, "4: init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NO_WITNESSES, "4: error");
    T(cmt_light_client_witness_count(c) == 1 &&
      cmt_light_client_attack_record(c) == NULL, "4: one witness, no record");
#undef FRESH
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 8. TestClientDivergentHeadersNoTraces (:433-496) ════════════════ */

static int t_divergent_no_traces(void)
{
    tmock_t                    p, ws[2];
    tstore_t                   s;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    const char                *wid[2] = { "sparse-1", "sparse-2" };
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&p, &F->a, 10);
    /* :461-467 — makeSparseWitness: {1, 10 = divergent}. */
    mock_init(&ws[0]);
    mock_add(&ws[0], 1, &F->a.sh[1], &F->a.vals[1].vs);
    mock_add(&ws[0], 10, &F->div1, &F->a.vals[10].vs);
    mock_init(&ws[1]);
    mock_add(&ws[1], 1, &F->a.sh[1], &F->a.vals[1].vs);
    mock_add(&ws[1], 10, &F->div2, &F->a.vals[10].vs);
    opts_default(&o);
    T(new_client(&p, "primary", ws, wid, 2, &o, &s, &c, &e) == CMT_OK, "init");
    /* :491-494 — an error: neither witness can back its header (no block
     * at the trace's heights) → both marked for removal → removing both
     * would leave none → ErrNoWitnesses (Q-D3). */
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NO_WITNESSES, "error");
    T(last_h(&s) == 1, "nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 9. TestClientDivergentProposerPriorities (:498-550) + K25-3 ═════ */

/* types/validator_set.go:387-399 — the reference's ProposerPriorityHash,
 * reproduced HERE ONLY to show which divergence it misses (DD1): every
 * `binary.PutVarint(buf, …)` writes at offset 0. NOT used by the port. */
static int reference_priority_hash(const cmt_validator_set_t *vs,
                                   uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t buf[10 * 8];
    size_t  total = 0u, i;

    if (vs->validators_len == 0u || vs->validators_len > 8u) {
        return 1;
    }
    memset(buf, 0, sizeof(buf));
    for (i = 0; i < vs->validators_len; i++) {
        int64_t  x  = vs->validators[i].proposer_priority;
        uint64_t ux = (uint64_t)x << 1;                    /* encoding/binary */
        size_t   n  = 0u;

        if (x < 0) {
            ux = ~ux;
        }
        while (ux >= 0x80u) {
            buf[n++] = (uint8_t)(ux | 0x80u);              /* at offset 0 */
            ux >>= 7;
        }
        buf[n++] = (uint8_t)ux;
        total += n;
    }
    return cmt_tmhash_sum(buf, total, out) == CMT_OK ? 0 : 1;
}

static int priorities_case(const char *name, cmt_validator_set_t *wvals10)
{
    tmock_t                    p, ws[1];
    tstore_t                   s;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    const char                *wid[1] = { "witness" };
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&p, &F->a, 10);
    mock_chain(&ws[0], &F->a, 10);
    mock_add(&ws[0], 10, &F->a.sh[10], wvals10);                 /* :517 */
    opts_default(&o);
    o.max_retry_attempts = 1;                                    /* :538 */
    T(new_client(&p, "primary", ws, wid, 1, &o, &s, &c, &e) == CMT_OK, name);
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE &&
      e.witness_index == 0, name);                               /* :542-547 */
    T(cmt_light_client_witness_count(c) == 1 && last_h(&s) == 1,
      "the witness stays (Q-D2), nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_priorities(void)
{
    uint8_t ha[CMT_TMHASH_SIZE], hb[CMT_TMHASH_SIZE];
    uint8_t vh[CMT_TMHASH_SIZE], wh[CMT_TMHASH_SIZE];
    int     ret = 1;

    /* :517-523 — same header and set hash, other priorities. */
    T(vals_hash(&F->a.vals[10].vs, vh) == 0 &&
      vals_hash(&F->prio10.vs, wh) == 0 &&
      memcmp(vh, wh, CMT_TMHASH_SIZE) == 0, "prio: same set hash");
    T(!cmt_light_priorities_equal(&F->a.vals[10].vs, &F->prio10.vs),
      "prio: vectors differ");
    if (priorities_case("TestClientDivergentProposerPriorities",
                        &F->prio10.vs) != 0) {
        return 1;
    }

    /* PROJECT (K25-3) — only validator #0 (not the last) differs. The
     * reference's hash is IDENTICAL for the two sets (so the reference
     * would trust the witness); the full vector is not. */
    T(vals_hash(&F->k25_10.vs, wh) == 0 && memcmp(vh, wh, CMT_TMHASH_SIZE) == 0,
      "K25-3: same set hash");
    T(reference_priority_hash(&F->a.vals[10].vs, ha) == 0 &&
      reference_priority_hash(&F->k25_10.vs, hb) == 0 &&
      memcmp(ha, hb, CMT_TMHASH_SIZE) == 0,
      "K25-3: the reference's ProposerPriorityHash collides");
    T(!cmt_light_priorities_equal(&F->a.vals[10].vs, &F->k25_10.vs),
      "K25-3: the vectors differ");
    if (priorities_case("K25-3 non-last validator", &F->k25_10.vs) != 0) {
        return 1;
    }
    /* Length is part of the vector: the same storage seen as 4 of 5
     * validators (every compared priority equal) is not equal. */
    {
        cmt_validator_set_t shorter = F->a.vals[10].vs;

        shorter.validators_len = VALSZ - 1;
        T(!cmt_light_priorities_equal(&F->a.vals[10].vs, &shorter) &&
          cmt_light_priorities_equal(&F->a.vals[10].vs, &F->a.vals[10].vs),
          "length counts");
    }
    T(cmt_light_priorities_equal(NULL, NULL) &&
      !cmt_light_priorities_equal(&F->a.vals[10].vs, NULL), "NULL");
    ret = 0;
out:
    return ret;
}

/* ══ 10. PROJECT — an attack the cap stops first (DD5, bounds) ════════ */

static int bounds_case(uint64_t steps, bool want_attack)
{
    static const int BYZ[2] = { 0, 1 };
    tmock_t                          p, ws[1];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    const cmt_light_attack_record_t *r;
    const char                      *wid[1] = { "honest" };
    int                              ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_init(&p);
    mock_add(&p, 1, &F->a.sh[1], &F->a.vals[1].vs);
    mock_add(&p, 10, &F->bnd10, &F->bnd_vals.vs);
    mock_chain(&ws[0], &F->a, 10);
    opts_default(&o);
    o.max_verify_steps = steps;
    T(new_client(&p, "primary", ws, wid, 1, &o, &s, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT,
      "verify 10 refused");
    T(last_h(&s) == 1, "nothing saved");
    if (!want_attack) {
        T(e.code == CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS,
          "the examine's cap → CAP_VERIFY_STEPS");
        T(cmt_light_client_witness_count(c) == 1 &&
          cmt_light_client_attack_record(c) == NULL,
          "witness kept, no record (fail closed)");
    } else {
        T(e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK, "attack");
        r = cmt_light_client_attack_record(c);
        /* Lunatic against the root: common = block 1; the forged commit's
         * signers in K_0 are keys 0 and 1. */
        T(r != NULL && ev_is(&r->against_primary, &F->bnd10, 1) &&
          r->against_primary.attack == CMT_LIGHT_ATTACK_LUNATIC &&
          byz_are(&r->against_primary, BYZ, 2) &&
          r->against_primary.total_voting_power == 10 &&
          time_eq(r->against_primary.timestamp, t_at(MINUTE)),
          "record: 10 / 1, {0, 1}");
        /* Q-D4: the primary has no block 3 for the reverse examine. */
        T(!r->has_against_witness, "no evidence against the witness");
        T(p.evidence_calls == 0 && ws[0].evidence_calls == 0, "nothing sent");
    }
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_bounds(void)
{
    /* The primary needs 1 Verify; the examine needs 13 (how it can lie,
     * 3). 12 stops in the examine; 13 reaches the attack. */
    if (bounds_case(12, false) != 0) {
        fprintf(stderr, "bounds: 12 steps\n");
        return 1;
    }
    if (bounds_case(13, true) != 0) {
        fprintf(stderr, "bounds: 13 steps\n");
        return 1;
    }
    return 0;
}

/* ══ 11. PROJECT — newLightClientAttackEvidence directly ═════════════ */

static int t_evidence_build(void)
{
    cmt_light_block_t           conf, trusted, common;
    cmt_light_attack_evidence_t ev;
    tsh_t                      *amn = NULL;
    int                         ret = 1;

    memset(&ev, 0, sizeof(ev));
    /* Equivocation (detector.go:432-436, evidence.go:272-292). */
    conf.signed_header    = &F->equ[6].sh;
    conf.validator_set    = &F->a.vals[6].vs;
    trusted.signed_header = &F->a.sh[6].sh;
    trusted.validator_set = &F->a.vals[6].vs;
    common.signed_header  = &F->a.sh[5].sh;
    common.validator_set  = &F->a.vals[5].vs;
    T(!cmt_light_conflicting_header_is_invalid(&F->a.sh[6].h, &F->equ[6].h),
      "equivocation header is not invalid");
    T(cmt_light_attack_evidence_build(&conf, &trusted, &common, &ev) == CMT_OK &&
      ev.attack == CMT_LIGHT_ATTACK_EQUIVOCATION && ev.common_height == 6 &&
      ev.n_byzantine == 4 && time_eq(ev.timestamp, t_at(6 * MINUTE)),
      "equivocation: trusted height, 4");
    cmt_light_attack_evidence_release(&ev);
    T(ev.conflicting_block == NULL && ev.byzantine_validators == NULL,
      "released");

    /* Amnesia (evidence.go:294-297): same sets, other commit round. */
    amn = malloc(sizeof(*amn));
    T(amn != NULL, "alloc");
    *amn                   = F->equ[6];
    amn->c.signatures      = amn->sigs;
    amn->c.round           = 2;
    amn->sh.header         = &amn->h;
    amn->sh.commit         = &amn->c;
    conf.signed_header     = &amn->sh;
    T(cmt_light_attack_evidence_build(&conf, &trusted, &common, &ev) == CMT_OK &&
      ev.attack == CMT_LIGHT_ATTACK_AMNESIA && ev.n_byzantine == 0 &&
      ev.byzantine_validators == NULL && ev.common_height == 6,
      "amnesia: none named");
    cmt_light_attack_evidence_release(&ev);

    /* Lunatic (detector.go:428-431): the common block's height. */
    conf.signed_header = &F->lun[10].sh;
    conf.validator_set = &F->lun_vals.vs;
    trusted.signed_header = &F->a.sh[10].sh;
    trusted.validator_set = &F->a.vals[10].vs;
    common.signed_header  = &F->a.sh[4].sh;
    common.validator_set  = &F->a.vals[4].vs;
    T(cmt_light_conflicting_header_is_invalid(&F->a.sh[10].h, &F->lun[10].h),
      "lunatic header is invalid");
    T(cmt_light_attack_evidence_build(&conf, &trusted, &common, &ev) == CMT_OK &&
      ev.attack == CMT_LIGHT_ATTACK_LUNATIC && ev.common_height == 4 &&
      ev.n_byzantine == 2 && ev.total_voting_power == 10,
      "lunatic: common height, 2");
    cmt_light_attack_evidence_release(&ev);

    T(cmt_light_attack_evidence_build(NULL, &trusted, &common, &ev) == CMT_FAULT &&
      cmt_light_attack_evidence_build(&conf, &trusted, &common, NULL) == CMT_FAULT,
      "NULL → FAULT");
    cmt_light_attack_evidence_release(NULL);
    cmt_light_attack_record_free(NULL);
    T(!cmt_light_conflicting_header_is_invalid(NULL, &F->a.sh[1].h), "NULL header");
    ret = 0;
out:
    cmt_light_attack_evidence_release(&ev);
    free(amn);
    return ret;
}

/* ══ 12. PROJECT — an unknown signer past the 2/3 point (BUGS Z-42) ══ */

/*
 * PROVES: an equivocating primary whose block 6 carries, AFTER the 2/3
 * point, one more COMMIT signature whose address names no validator of
 * the set (a) still verifies — the commit check stops counting at more
 * than 2/3 (types/validation.go:401-403, cmt_validation.c:264-266) and
 * never looks at it — and (b) is still reported as LIGHT_CLIENT_ATTACK
 * with its record kept: the signature is skipped and counted
 * (n_unknown_signers = 1), the four real equivocators are named. Before
 * the Z-42 fix the evidence builder returned CMT_FAULT here and the call
 * discarded the record and returned a local fault.
 */
static int t_equivocation_unknown_signer(void)
{
    tmock_t                          p, w[1];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    const cmt_light_attack_record_t *r;
    const char                      *wid[1] = { "witness" };
    tsh_t                           *mod6;
    cmt_pb_bytes_t                   tx;
    cmt_data_t                       txs;
    cmt_commit_sig_t                *x;
    int                              keys[VALSZ];
    uint8_t                          ha[CMT_TMHASH_SIZE], hb[CMT_TMHASH_SIZE];
    int32_t                          idx40 = 0;
    size_t                           i;
    int64_t                          h;
    int                              ret = 1;

    memset(&s, 0, sizeof(s));
    mod6 = calloc(1, sizeof(*mod6));
    if (mod6 == NULL) {
        return 1;
    }
    if (store_open(&s) != 0) {
        free(mod6);
        return 1;
    }
    /* F->equ[6]'s header, re-signed with the keys in the SET's index
     * order: slots 0..3 sign, slot 4 (the last) is absent. Four of five
     * (power 8 of 10) is past 2/3 at slot 3, so slot 4 is never read. */
    for (i = 0; i < VALSZ; i++) {
        keys[i] = key_of_address(F->a.vals[6].vs.validators[i].address,
                                 F->a.vals[6].vs.validators[i].address_len);
        T(keys[i] >= 0, "a key of the set");
    }
    tx.data     = (const uint8_t *)"abcd";
    tx.len      = 4;
    txs.txs     = &tx;
    txs.txs_cap = 1;
    txs.txs_len = 1;
    T(gen_sh(mod6, 6, t_at(6 * MINUTE), &txs, &F->a.vals[6], &F->a.vals[7],
             keys, VALSZ, 0, VALSZ - 1, NULL, "app_hash") == 0, "build 6");
    T(sh_hash(mod6, ha) == 0 && sh_hash(&F->equ[6], hb) == 0 &&
      memcmp(ha, hb, CMT_TMHASH_SIZE) == 0, "the same header as equ[6]");
    x = &mod6->sigs[VALSZ - 1];
    T(x->block_id_flag == (int32_t)CMT_BLOCK_ID_FLAG_ABSENT, "slot 4 absent");
    /* Slot 4: a COMMIT signature from key 40, which is in no set here. */
    memset(x, 0, sizeof(*x));
    x->block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    memcpy(x->validator_address, g_addr[40], CMT_ADDRESS_SIZE);
    x->validator_address_len = CMT_ADDRESS_SIZE;
    x->timestamp.seconds     = VOTE_SECONDS;
    x->timestamp.nanos       = 0;
    pat(x->signature, 64u, 0xA5);
    x->signature_len         = 64u;
    T(cmt_validator_set_get_by_address(&F->a.vals[6].vs, g_addr[40],
                                       CMT_ADDRESS_SIZE, &idx40,
                                       NULL) == CMT_OK && idx40 < 0,
      "key 40 is not in the set");

    mock_chain(&w[0], &F->a, 12);
    mock_init(&p);
    for (h = 1; h <= 10; h++) {
        if (h < 6) {
            mock_add(&p, h, &F->a.sh[h], &F->a.vals[h].vs);
        } else if (h == 6) {
            mock_add(&p, h, mod6, &F->a.vals[h].vs);
        } else {
            mock_add(&p, h, &F->equ[h], &F->a.vals[h].vs);
        }
    }
    opts_default(&o);
    o.verification_mode = CMT_LIGHT_CLIENT_MODE_SEQUENTIAL;
    T(new_client(&p, "primary", w, wid, 1, &o, &s, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK,
      "verify 10 → attack, not a fault");
    T(last_h(&s) == 1, "nothing saved");
    r = cmt_light_client_attack_record(c);
    T(r != NULL && r->missing == 0u &&
      ev_is(&r->against_primary, &F->equ[6], 6), "record kept: 6 / 6");
    T(r->against_primary.attack == CMT_LIGHT_ATTACK_EQUIVOCATION &&
      r->against_primary.n_byzantine == 4 &&
      r->against_primary.n_unknown_signers == 1,
      "four equivocators named, one unknown signer skipped");
    T(cmt_light_client_attack_locked(c) && r->durable, "locked, durable");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    free(mod6);
    return ret;
}

/* ══ 13. PROJECT — bad witnesses go in a WITNESS_BEHIND pass ═════════ */

/*
 * PROVES: in a detection that ends WITNESS_BEHIND, a witness already
 * found bad in the same pass (here: a conflicting block 10 its own chain
 * cannot back, detector.go:74-75) is removed BEFORE the call returns, as
 * the reference removes it once its sleeping comparison returns
 * (detector.go:98-100) — while another witness remains. After the wait
 * the same target is trusted: the matching witness matches and the
 * behind one is benign (:196).
 */
static int t_behind_removes_bad(void)
{
    tmock_t                    p, ws[3];
    tstore_t                   s;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    const char                *wid[3] = { "bad-10", "behind", "match" };
    const uint8_t             *id = NULL;
    size_t                     id_len = 0u;
    cmt_time_t                 now = t_at(HOUR);
    int64_t                    wait;
    int64_t                    h;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&p, &F->a, 10);
    mock_init(&ws[0]);
    for (h = 1; h <= 9; h++) {
        mock_add(&ws[0], h, &F->a.sh[h], &F->a.vals[h].vs);
    }
    mock_add(&ws[0], 10, &F->b.sh[10], &F->b.vals[10].vs);
    mock_chain(&ws[1], &F->a, 9);
    mock_chain(&ws[2], &F->a, 10);
    opts_default(&o);
    wait = 2 * o.max_clock_drift + o.max_block_lag;
    T(new_client(&p, "primary", ws, wid, 3, &o, &s, &c, &e) == CMT_OK, "init");

    T(cmt_light_client_verify_light_block_at_height(c, 10, now, g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "1st pass → behind");
    T(last_h(&s) == 1, "behind: nothing saved");
    /* removeWitnesses swaps the last witness into the freed slot (Q7). */
    T(cmt_light_client_witness_count(c) == 2, "the bad witness is gone");
    T(cmt_light_client_witness_id(c, 0, &id, &id_len) == CMT_OK &&
      id_len == 5 && memcmp(id, "match", 5) == 0 &&
      cmt_light_client_witness_id(c, 1, &id, &id_len) == CMT_OK &&
      id_len == 6 && memcmp(id, "behind", 6) == 0, "match, behind remain");

    T(cmt_light_client_verify_light_block_at_height(c, 10,
            cmt_time_add_ns(now, wait), g_out, &e) == CMT_OK,
      "after the wait → verified");
    T(last_h(&s) == 10 && cmt_light_client_witness_count(c) == 2,
      "10 saved, both remain");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 15. PROJECT — Update keeps the target of a recorded wait (Z-41) ═ */

/*
 * PROVES (cmt_light_client.h D21, BUGS Z-41): the primary advances
 * between Update calls while one witness stays behind.
 *   call 1 — WITNESS_BEHIND, the latest block (10) becomes the recorded
 *            target;
 *   call 2 — the primary's latest is now 11, the wait has not run: still
 *            WITNESS_BEHIND, nothing saved (a fresh latest block does NOT
 *            restart the wait — before D21 every call did, forever);
 *   call 3 — the wait has run: block 10 (NOT the latest, 11) is verified
 *            through the matching witness, the behind one is benign
 *            (detector.go:196), 10 is saved;
 *   call 4 — the next Update moves to the latest block, 11.
 * Then a second client: after call 1 the primary answers the recorded
 * height with ANOTHER block 10 — the call after the wait is refused
 * (VERIFICATION_FAILED, TARGET_MISMATCH) and nothing is saved.
 */
static int t_update_moving_target(void)
{
    tmock_t                    p, ws[2];
    tstore_t                   s;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    const char                *wid[2] = { "behind", "match" };
    cmt_time_t                 now = t_at(HOUR);
    int64_t                    wait;
    bool                       adv = true;
    int                        ret = 1;

    memset(&s, 0, sizeof(s));
    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&p, &F->a, 10);
    mock_chain(&ws[0], &F->a, 9);
    mock_chain(&ws[1], &F->a, 10);
    opts_default(&o);
    wait = 2 * o.max_clock_drift + o.max_block_lag;
    T(new_client(&p, "primary", ws, wid, 2, &o, &s, &c, &e) == CMT_OK, "init");

    T(cmt_light_client_update(c, now, g_out, &adv, &e) == CMT_REJECT && !adv &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "call 1 → behind (10)");
    T(last_h(&s) == 1, "call 1: nothing saved");

    /* The primary (and the matching witness) produce block 11. */
    mock_add(&p, 11, &F->a.sh[11], &F->a.vals[11].vs);
    mock_add(&ws[1], 11, &F->a.sh[11], &F->a.vals[11].vs);
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait - 1), g_out, &adv,
                              &e) == CMT_REJECT && !adv &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND,
      "call 2, latest moved, wait not run → still behind");
    T(last_h(&s) == 1, "call 2: nothing saved");

    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait), g_out, &adv,
                              &e) == CMT_OK && adv &&
      g_out->lb.signed_header != NULL &&
      g_out->lb.signed_header->header->height == 10,
      "call 3, after the wait → the RECORDED block 10");
    T(last_h(&s) == 10, "call 3: 10 saved, not 11");

    /* The behind witness catches up; the next Update takes the latest. */
    mock_add(&ws[0], 10, &F->a.sh[10], &F->a.vals[10].vs);
    mock_add(&ws[0], 11, &F->a.sh[11], &F->a.vals[11].vs);
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait + SECOND), g_out,
                              &adv, &e) == CMT_OK && adv &&
      g_out->lb.signed_header != NULL &&
      g_out->lb.signed_header->header->height == 11,
      "call 4 → the latest, 11");
    T(last_h(&s) == 11, "call 4: 11 saved");
    cmt_light_client_free(c);
    c = NULL;
    store_close(&s);

    /* The primary changes its block at the recorded height. */
    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&p, &F->a, 10);
    mock_chain(&ws[0], &F->a, 9);
    mock_chain(&ws[1], &F->a, 10);
    T(new_client(&p, "primary", ws, wid, 2, &o, &s, &c, &e) == CMT_OK,
      "init (changed answer)");
    T(cmt_light_client_update(c, now, g_out, &adv, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_BEHIND, "behind (10)");
    mock_add(&p, 10, &F->div1, &F->a.vals[10].vs);   /* another block 10 */
    mock_add(&p, 11, &F->a.sh[11], &F->a.vals[11].vs);
    T(cmt_light_client_update(c, cmt_time_add_ns(now, wait), g_out, &adv,
                              &e) == CMT_REJECT && !adv &&
      e.code == CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED &&
      e.reason == CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH &&
      e.from == 1 && e.to == 10, "another hash at 10 → refused");
    T(last_h(&s) == 1, "nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 14. PROJECT — the attack lock and its durable records (K25-10) ═══ */

/* Close and re-open the same store file (a restart; nothing unlinked). */
static int store_reopen(tstore_t *s)
{
    cmt_light_store_db_close(s->db);
    s->db = NULL;
    if (cmt_light_store_db_open(s->path, (const uint8_t *)CHAIN, strlen(CHAIN),
                                CMT_BLOCK_PROTOCOL, &s->db) != CMT_OK) {
        return 1;
    }
    cmt_light_store_db_bind(s->db, &s->st);
    return 0;
}

static bool records_are(tstore_t *s, uint64_t total, uint64_t uncleared)
{
    uint64_t t = 99u, u = 99u;

    return cmt_light_store_db_attack_records(s->db, &t, &u) == CMT_OK &&
           t == total && u == uncleared;
}

/* The lunatic primary of TestLightClientAttackEvidence_Lunatic (:36-46). */
static void mock_lunatic_primary(tmock_t *m)
{
    int64_t h;

    mock_init(m);
    for (h = 1; h <= 10; h++) {
        if (h < 6) {
            mock_add(m, h, &F->a.sh[h], &F->a.vals[h].vs);
        } else {
            mock_add(m, h, &F->lun[h], &F->lun_vals.vs);
        }
    }
}

/*
 * PROVES (K25-10, cmt_light_detector.h DD9, cmt_light_client.h D20):
 *   · an attack LOCKS the client; while locked, Update, a verify of the
 *     attacked height, a verify of another height and Cleanup are all
 *     refused (ATTACK_LOCKED / CMT_REJECT) and the store is unchanged;
 *   · the record is in the store, byte-equal to its encoding, uncleared;
 *   · a RESTART (store closed and re-opened, a new client) stays locked:
 *     NewClient refuses, NewClientFromTrustedStore comes up locked;
 *   · the operator's clear unlocks and keeps the record (cleared); the
 *     same attacking primary is then caught AGAIN — a second durable
 *     record (two in all), the client locked again;
 *   · after a second clear, an honest primary's block is verified and
 *     saved: the client works again.
 */
static int t_attack_lock(void)
{
    tmock_t                          p, w[1];
    tstore_t                         s;
    cmt_light_client_options_t       o;
    cmt_light_client_t              *c = NULL;
    cmt_light_client_error_t         e;
    cmt_light_client_peer_t          pp, wp[1];
    const cmt_light_attack_record_t *r;
    const char                      *wid[1] = { "witness" };
    uint8_t                         *bz = NULL, *got = NULL;
    size_t                           bz_len = 0u, got_len = 0u;
    bool                             cleared = true, found = false, adv = true;
    int                              ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_chain(&w[0], &F->a, 10);
    mock_lunatic_primary(&p);
    opts_default(&o);
    T(new_client(&p, "primary", w, wid, 1, &o, &s, &c, &e) == CMT_OK, "init");
    T(!cmt_light_client_attack_locked(c) && records_are(&s, 0, 0),
      "unlocked, no record");

    /* The attack locks; the record is durable and byte-equal. */
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK, "attack");
    r = cmt_light_client_attack_record(c);
    T(r != NULL && r->durable && r->missing == 0u &&
      cmt_light_client_attack_locked(c), "locked, durable");
    T(records_are(&s, 1, 1), "one record, uncleared");
    T(cmt_light_attack_record_encode(r, &bz, &bz_len) == CMT_OK &&
      cmt_light_store_db_attack_record(s.db, 1, &got, &got_len, &cleared,
                                       &found) == CMT_OK &&
      found && !cleared && got_len == bz_len &&
      memcmp(got, bz, bz_len) == 0, "the stored bytes are the record's");
    free(got);
    got = NULL;

    /* Every later verification / save is refused and changes nothing. */
    T(cmt_light_client_update(c, t_at(HOUR), g_out, &adv, &e) == CMT_REJECT &&
      !adv && e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED, "Update refused");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED, "verify 10 refused");
    T(cmt_light_client_verify_light_block_at_height(c, 5, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED, "verify 5 refused");
    T(cmt_light_client_cleanup(c) == CMT_REJECT, "Cleanup refused");
    T(last_h(&s) == 1 && records_are(&s, 1, 1), "store unchanged");

    /* Restart: the lock is reloaded from the store. */
    cmt_light_client_free(c);
    c = NULL;
    T(store_reopen(&s) == 0, "re-open the store");
    T(new_client(&p, "primary", w, wid, 1, &o, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED && c == NULL,
      "NewClient refuses a locked store");
    pp    = peer_of(&p, "primary");
    wp[0] = peer_of(&w[0], "witness");
    T(cmt_light_client_new_from_trusted_store((const uint8_t *)CHAIN,
                                              strlen(CHAIN), 4 * HOUR, &pp,
                                              wp, 1, &s.st, &o, &c,
                                              &e) == CMT_OK &&
      cmt_light_client_attack_locked(c), "restarted client is locked");
    T(cmt_light_client_verify_light_block_at_height(c, 10, t_at(HOUR), g_out,
                                                    &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED, "still refused");

    /* Clear: unlocked, the record kept (cleared); the same primary is
     * caught again — a second durable record. */
    T(cmt_light_client_attack_clear(c) == CMT_OK &&
      !cmt_light_client_attack_locked(c) && records_are(&s, 1, 0),
      "clear: unlocked, one record, cleared");
    T(cmt_light_store_db_attack_record(s.db, 1, &got, &got_len, &cleared,
                                       &found) == CMT_OK && found && cleared,
      "record 1 kept, cleared");
    free(got);
    got = NULL;
    T(cmt_light_client_verify_light_block_at_height(c, 10,
            t_at(HOUR + MINUTE), g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_LIGHT_CLIENT_ATTACK, "second attack");
    T(cmt_light_client_attack_locked(c) && records_are(&s, 2, 1),
      "locked again, two records");

    /* Clear again, an honest primary: verified and saved. */
    T(cmt_light_client_attack_clear(c) == CMT_OK && records_are(&s, 2, 0),
      "second clear");
    mock_chain(&p, &F->a, 10);
    T(cmt_light_client_verify_light_block_at_height(c, 10,
            t_at(HOUR + 2 * MINUTE), g_out, &e) == CMT_OK &&
      last_h(&s) == 10, "works again: 10 saved");
    T(p.evidence_calls == 0 && w[0].evidence_calls == 0, "nothing sent");
    ret = 0;
out:
    free(bz);
    free(got);
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

int main(void)
{
    int rc = 1;

    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    g_out     = cmt_light_block_buf_new();
    F         = (tfix_t *)calloc(1, sizeof(*F));
    if (g_scratch == NULL || g_out == NULL || F == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    if (build_keys() != 0) goto out;
    if (build_fixture(F) != 0) {
        fprintf(stderr, "fixture failed\n");
        goto out;
    }
    if (t_lunatic() != 0) goto out;
    if (t_equivocation() != 0) goto out;
    if (t_forward_lunatic() != 0) goto out;
    if (t_divergent_traces() != 0) goto out;
    if (t_divergent_no_traces() != 0) goto out;
    if (t_priorities() != 0) goto out;
    if (t_bounds() != 0) goto out;
    if (t_evidence_build() != 0) goto out;
    if (t_equivocation_unknown_signer() != 0) goto out;
    if (t_behind_removes_bad() != 0) goto out;
    if (t_attack_lock() != 0) goto out;
    if (t_update_moving_target() != 0) goto out;

    printf("test_cmt_light_detector: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(F);
    cmt_light_block_buf_free(g_out);
    free(g_scratch);
    return rc;
}
