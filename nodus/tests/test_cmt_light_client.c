/**
 * Nodus — cometbft @v0.38.26 C port: `light/client.go` and
 * `light/trust_options.go` (shared/dnac/cmt_light_client.{c,h}), through
 * the reference's mock provider (light/provider/mock/mock.go,
 * deadmock.go) and the SQLite light store. Light client package 2,
 * 2026-10-16 (Kurultay #25); no node path calls any of it yet.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · TrustOptions.ValidateBasic refuses a non-positive period, a
 *     non-positive height and a hash of the wrong size;
 *   · initialisation refuses a first block with another hash, a missing
 *     first block and a first block whose set is not its header's, and
 *     accepts the trust root once at least two DISTINCT providers hold it
 *     (Kurultay #25 item 9): it stops on a witness with a different
 *     header or different proposer priorities, does not count a silent
 *     witness or one with the primary's identity, and removes a witness
 *     that sends an invalid block;
 *   · sequential and skipping verification reach the detector hook on
 *     every reference "good" row (the code DETECTOR_NOT_IMPLEMENTED with
 *     the expected trace ends — any earlier failure gives another code)
 *     and stop with a verification error, never the hook's code, on every
 *     "bad" row; the hook FAILS CLOSED: nothing is saved;
 *   · a benign provider error at a bisection pivot ends at the hook's
 *     short-trace refusal (quirk Q2, detector.go:29-31);
 *   · backwards verification saves the older blocks, refuses a primary
 *     whose header at the next height down is not the parent, and (D9)
 *     refuses a target the primary sent that is not the block the walk
 *     reaches;
 *   · restoring from the store, with the trust options at, above and
 *     below the stored height (rollback, re-root, cleanup), as the
 *     reference's three Startup tests;
 *   · a dead primary is replaced by the first witness in index order and
 *     kept as a witness;
 *   · the store is pruned after a save; Cleanup empties it;
 *   · every cap of D3 stops the operation with its own named error;
 *   · the constructor's option checks.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, NO CLOCK — every time is a fixed value after the reference's
 * bTime (2006-01-02T15:04:05Z). Keys come from `qgp_dsa87_keypair_derand`
 * with fixed seeds. Every large fixture (headers with their signatures,
 * validator sets, light-block buffers) is heap-allocated.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success: each case makes a temporary SQLite file
 * `test_cmt_light_client.XXXXXX` in the working directory and removes it
 * (and its journal). A crash mid-run can leave one behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. THE DETECTOR IS NOT PORTED (package 3). A reference row that
 *     expects a forward or between verification to SUCCEED is checked
 *     here as "reached the detector hook with the expected trace, and the
 *     store did not change". That proves the verification path ran to
 *     its end; it does not prove the block would be trusted once the
 *     detector exists.
 *  2. ML-DSA-87 signing is HEDGED; no signature is frozen. Header hashes
 *     depend only on header fields, so two headers generated from the
 *     same arguments share a hash, as in the reference.
 *  3. Reference fixtures this port cannot express are ADAPTED, each named
 *     at its site: random keys are fixed seeds; `RandValidatorSet(10,
 *     100)` is four fixed keys of power 100; the same mock passed as
 *     primary AND witness becomes two mock instances with the same data
 *     and two identities, because item 9 counts identities (passing one
 *     instance twice would be one identity and refused).
 *  4. The mock's 10 ms `time.After` and mutex (mock.go:68-73, :18) are not
 *     ported (no clock, one thread).
 *
 * ── REFERENCE CASES (light/client_test.go) ─────────────────────────────
 * PORTED: TestValidateTrustOptions (:73-116), TestMock (:118-121),
 * TestClient_SequentialVerification (:123-257, all 7 rows; "good" →
 * detector hook), TestClient_SkippingVerification (:259-381, all 4 rows),
 * TestClientLargeBisectionVerification (:383-408, → hook),
 * TestClient_Cleanup (:438-459), TestClientRestoresTrustedHeaderAfter-
 * Startup1/2/3 (:461-700), TestClient_Update (:702-721, → hook),
 * TestClientReplacesPrimaryWithWitnessIfPrimaryIsUnavailable (:764-782;
 * Update → hook, the provider assertions kept),
 * TestClient_BackwardsVerification (:784-888: steps 1-3 and rows 7-8; 4a
 * → hook), TestClient_NewClientFromTrustedStore (:890-910),
 * TestClientEnsureValidHeadersAndValSets (:1033-1102; row 0 → hook).
 * NOT PORTED, with the reason:
 *   · TestClientBisectionBetweenTrustedHeaders (:410-436) — needs a
 *     forward verification to be SAVED first; the detector is package 3.
 *   · TestClient_BackwardsVerification steps 4b and 5 (:823-833) — need
 *     step 4a (a forward verification) saved.
 *   · TestClient_Concurrency (:723-762) — goroutines; the client is
 *     single-threaded (D14), and it needs a forward verification saved.
 *   · TestClientRemovesWitnessIfItSendsUsIncorrectHeader (:912-971),
 *     TestClient_TrustedValidatorSet (:973-1008),
 *     TestClientErrorsDifferentProposerPriorities (:1161-1212) — what
 *     they assert happens in the detector (package 3). Their init part
 *     (witnesses agree / differ in priorities) is covered by the item-9
 *     rows below.
 *   · TestClientPrunesHeadersAndValidatorSets (:1010-1031) — needs Update
 *     to save; the pruning is checked through a backwards save instead
 *     (PROJECT row t_prune).
 *   · TestClientHandlesContexts (:1104-1159) — no context.Context.
 * PROJECT-AUTHORED: the item-9 rows (agree / disagree / silent / dedup /
 * bad witness / priorities), the fail-closed rows, the Q2 short-trace
 * row, the D9 row, the rollback-refused row, the cap rows and the option
 * rows.
 *
 * @file test_cmt_light_client.c
 */

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

/* A row: on failure print and leave through `out`. */
#define T(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        goto out; \
    } \
    g_checks++; \
} while (0)

/* keys 0-3: `keys` (genPrivKeys(4), client_test.go:30); 4-7: `newKeys`
 * (:124, :261); 8-10: the extension of `transitKeys` (:265); 4-6 also
 * genMockNode's three keys (helpers_test.go:202) — separate tests. */
#define NKEYS 12

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
    cmt_validator_t     storage[NKEYS];
    cmt_validator_set_t vs;
} tvals_t;

typedef struct {
    cmt_header_t        h;
    cmt_commit_sig_t    sigs[NKEYS];
    cmt_commit_t        c;
    cmt_signed_header_t sh;
} tsh_t;

#define LARGE_N 100

typedef struct {
    tvals_t vals, vals2, vals3, new_vals, transit_vals, different_vals, empty;
    tsh_t   h1, h2, h3;
    tsh_t   hdr1_alt;     /* GenSignedHeader(1, bTime+1h, vals, vals, 0, 4) */
    tsh_t   hdr2_alt;     /* GenSignedHeader(2, bTime+2h, vals, vals, 0, 4) */
    tsh_t   seq13_2;      /* (2, bTime+1h, vals, vals, 3, 4) — 1 of 4 signed */
    tsh_t   seq_3_full;   /* (3, bTime+2h, vals, vals, 0, 4) */
    tsh_t   seq_2_full;   /* (2, bTime+1h, vals, vals, 0, 4) */
    tsh_t   seq13_3;      /* (3, bTime+2h, vals, vals, 3, 4) */
    tsh_t   transit3;     /* transitKeys (3, bTime+2h, transitVals x2) */
    tsh_t   change2;      /* (2, bTime+1h, vals, newVals, 0, 4) */
    tsh_t   change3;      /* newKeys (3, bTime+2h, newVals, newVals) */
    tsh_t   nosig2;       /* (2, bTime+1h, vals, newVals, 0, 0) */
    tsh_t   bad_height2;  /* row 7: (1, bTime+30m, vals, vals) */
    tsh_t   bad_hash2;    /* row 8: (2, bTime+30m, app_hash2 ...) */
    tvals_t lvals;        /* genMockNode's ToValidators(2, 0) */
    tsh_t   large[LARGE_N + 1];   /* index = height */
    tsh_t   fake5;        /* D9: a height-5 header with another app hash */
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
        memset(seed, (uint8_t)(0x61 + i), sizeof(seed));
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

/* helpers_test.go:67-73 `ToValidators(init, inc)`. */
static int make_vals(tvals_t *out, const int *keys, size_t n,
                     int64_t init, int64_t inc)
{
    cmt_validator_t     list[NKEYS];
    cmt_pb_public_key_t pk;
    size_t              i;

    if (n > NKEYS) {
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
    if (cmt_validator_set_init(&out->vs, out->storage, NKEYS) != CMT_OK ||
        cmt_validator_set_new(&out->vs, list, n, g_scratch) != CMT_OK) {
        return 1;
    }
    return 0;
}

/* `vals.CopyIncrementProposerPriority(1)` (client_test.go:36, :40). */
static int copy_inc(tvals_t *dst, const tvals_t *src)
{
    if (cmt_validator_set_init(&dst->vs, dst->storage, NKEYS) != CMT_OK ||
        cmt_validator_set_copy_increment_proposer_priority(&src->vs, &dst->vs,
                                                           1) != CMT_OK) {
        return 1;
    }
    return 0;
}

static int vals_hash(cmt_validator_set_t *vs, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           *scratch;
    cmt_merkle_item_t  items[NKEYS];
    int                rc;

    scratch = (uint8_t *)malloc(NKEYS * (size_t)CMT_VALIDATOR_BYTES_MAX);
    if (scratch == NULL) {
        return 1;
    }
    rc = cmt_validator_set_hash(vs, scratch,
                                NKEYS * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                items, NKEYS, out);
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
 * helpers_test.go:135-177 — genHeader + signHeader +
 * GenSignedHeader(LastBlockID). `keys[0..nkeys)` is `pkz`; the commit has
 * one entry per key (:77), absent (:78-80) except the votes of
 * keys[first..last) (:88-91), at their index in `valset` (:105).
 * `last_hash` NULL is GenSignedHeader; otherwise LastBlockID{Hash}
 * (:167-174). ADAPTED: the PartSetHeader hash (32 random bytes, :84) is a
 * 64-byte pattern, since tmhash is 64 bytes here.
 */
static int gen_sh(tsh_t *out, int64_t height, cmt_time_t btime,
                  tvals_t *valset, tvals_t *next_valset, const int *keys,
                  size_t nkeys, size_t first, size_t last,
                  const uint8_t *last_hash,
                  const char *app, const char *cons, const char *res)
{
    cmt_header_t *h = &out->h;
    size_t        i;

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
        cmt_data_hash(NULL, h->data_hash) != CMT_OK ||           /* :147 */
        cmt_tmhash_sum((const uint8_t *)app, strlen(app),
                       h->app_hash) != CMT_OK ||                 /* :148 */
        cmt_tmhash_sum((const uint8_t *)cons, strlen(cons),
                       h->consensus_hash) != CMT_OK ||           /* :149 */
        cmt_tmhash_sum((const uint8_t *)res, strlen(res),
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
    out->c.signatures_cap = NKEYS;
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

#define STD "app_hash", "cons_hash", "results_hash"

static int sh_hash(const tsh_t *s, uint8_t out[CMT_TMHASH_SIZE])
{
    return cmt_header_hash(&s->h, out) == CMT_OK ? 0 : 1;
}

static const int K_KEYS[4]    = { 0, 1, 2, 3 };
static const int K_NEW[4]     = { 4, 5, 6, 7 };
static const int K_TRANSIT[7] = { 0, 1, 2, 3, 8, 9, 10 };
static const int K_LARGE[3]   = { 4, 5, 6 };

static int build_fixture(tfix_t *f)
{
    uint8_t hh[CMT_TMHASH_SIZE];
    int64_t h;

    /* client_test.go:30-71. */
    if (make_vals(&f->vals, K_KEYS, 4, 20, 10) != 0 ||           /* :31 */
        copy_inc(&f->vals2, &f->vals) != 0 ||                    /* :36 */
        copy_inc(&f->vals3, &f->vals2) != 0 ||                   /* :40 */
        make_vals(&f->new_vals, K_NEW, 4, 10, 1) != 0 ||         /* :125 */
        make_vals(&f->transit_vals, K_TRANSIT, 7, 10, 1) != 0 || /* :266 */
        /* :126 `types.RandValidatorSet(10, 100)` — ADAPTED: four fixed
         * keys of power 100, none in `vals`. */
        make_vals(&f->different_vals, K_NEW, 4, 100, 0) != 0 ||
        make_vals(&f->lvals, K_LARGE, 3, 2, 0) != 0) {           /* helpers :216 */
        return 1;
    }
    if (cmt_validator_set_init(&f->empty.vs, f->empty.storage, NKEYS) != CMT_OK) {
        return 1;                                                /* :1034-1037 */
    }

    if (gen_sh(&f->h1, 1, t_at(0), &f->vals, &f->vals, K_KEYS, 4, 0, 4,
               NULL, STD) != 0 ||                                /* :33-34 */
        sh_hash(&f->h1, hh) != 0 ||
        gen_sh(&f->h2, 2, t_at(30 * MINUTE), &f->vals2, &f->vals2, K_KEYS,
               4, 0, 4, hh, STD) != 0 ||                         /* :37-38 */
        sh_hash(&f->h2, hh) != 0 ||
        gen_sh(&f->h3, 3, t_at(HOUR), &f->vals3, &f->vals3, K_KEYS, 4, 0,
               4, hh, STD) != 0) {                               /* :41-42 */
        return 1;
    }
    if (gen_sh(&f->hdr1_alt, 1, t_at(HOUR), &f->vals, &f->vals, K_KEYS, 4,
               0, 4, NULL, STD) != 0 ||                          /* :146, :494, :569, :654 */
        gen_sh(&f->hdr2_alt, 2, t_at(2 * HOUR), &f->vals, &f->vals, K_KEYS,
               4, 0, 4, NULL, STD) != 0 ||                       /* :572, :657 */
        gen_sh(&f->seq13_2, 2, t_at(HOUR), &f->vals, &f->vals, K_KEYS, 4,
               3, 4, NULL, STD) != 0 ||                          /* :181-182 */
        gen_sh(&f->seq_3_full, 3, t_at(2 * HOUR), &f->vals, &f->vals,
               K_KEYS, 4, 0, 4, NULL, STD) != 0 ||               /* :184-185 */
        gen_sh(&f->seq_2_full, 2, t_at(HOUR), &f->vals, &f->vals, K_KEYS,
               4, 0, 4, NULL, STD) != 0 ||                       /* :197-198 */
        gen_sh(&f->seq13_3, 3, t_at(2 * HOUR), &f->vals, &f->vals, K_KEYS,
               4, 3, 4, NULL, STD) != 0 ||                       /* :200-201 */
        gen_sh(&f->transit3, 3, t_at(2 * HOUR), &f->transit_vals,
               &f->transit_vals, K_TRANSIT, 7, 0, 7, NULL, STD) != 0 || /* :292-293 */
        gen_sh(&f->change2, 2, t_at(HOUR), &f->vals, &f->new_vals, K_KEYS,
               4, 0, 4, NULL, STD) != 0 ||                       /* :309-310 */
        gen_sh(&f->change3, 3, t_at(2 * HOUR), &f->new_vals, &f->new_vals,
               K_NEW, 4, 0, 4, NULL, STD) != 0 ||                /* :312-313 */
        gen_sh(&f->nosig2, 2, t_at(HOUR), &f->vals, &f->new_vals, K_KEYS,
               4, 0, 0, NULL, STD) != 0 ||                       /* :329-330 */
        gen_sh(&f->bad_height2, 1, t_at(30 * MINUTE), &f->vals, &f->vals,
               K_KEYS, 4, 0, 4, NULL, STD) != 0 ||               /* :846-847 */
        gen_sh(&f->bad_hash2, 2, t_at(30 * MINUTE), &f->vals, &f->vals,
               K_KEYS, 4, 0, 4, NULL, "app_hash2", "cons_hash23",
               "results_hash30") != 0) {                         /* :859-860 */
        return 1;
    }

    /* helpers_test.go:186-256 genMockNode(chainID, N, 3, 0, bTime): with
     * valVariation 0 `ChangeKeys(0)` keeps the same keys (:179-182), so
     * every block is signed by the same three keys with ToValidators(2,
     * 0); height h at bTime + h minutes, LastBlockID = the previous hash.
     * The 10-block `largeFullNode` (client_test.go:70) is the first ten of
     * these: the construction is the same. */
    if (gen_sh(&f->large[1], 1, t_at(MINUTE), &f->lvals, &f->lvals,
               K_LARGE, 3, 0, 3, NULL, STD) != 0) {              /* :213-215 */
        return 1;
    }
    for (h = 2; h <= LARGE_N; h++) {                             /* :221-235 */
        if (sh_hash(&f->large[h - 1], hh) != 0 ||
            gen_sh(&f->large[h], h, t_at(h * MINUTE), &f->lvals, &f->lvals,
                   K_LARGE, 3, 0, 3, hh, STD) != 0) {
            return 1;
        }
    }
    /* D9: a second height-5 block whose parent link is right but whose
     * app hash differs — a valid block, not the chain's. PROJECT. */
    if (sh_hash(&f->large[4], hh) != 0 ||
        gen_sh(&f->fake5, 5, t_at(5 * MINUTE), &f->lvals, &f->lvals,
               K_LARGE, 3, 0, 3, hh, "app_hash_fake", "cons_hash",
               "results_hash") != 0) {
        return 1;
    }
    return 0;
}

/* ══ the mock provider (light/provider/mock/mock.go, deadmock.go) ════ */

#define MOCK_MAX (LARGE_N + 1)

/* mock.go:15-23 — the two maps keyed by height become one array; an entry
 * is a key of the `headers` map (its header may be NULL, its set may be
 * NULL — mock.go:85-98). `dead` is deadmock.go. `flip_*` (PROJECT, D9):
 * the first `flip_left` requests for `flip_height` get `flip_sh`. */
typedef struct {
    const char                *chain_id;
    bool                       dead;
    int64_t                    heights[MOCK_MAX];
    const cmt_signed_header_t *headers[MOCK_MAX];
    cmt_validator_set_t       *vals[MOCK_MAX];
    size_t                     n;
    int64_t                    latest_height;
    int64_t                    flip_height;
    const cmt_signed_header_t *flip_sh;
    cmt_validator_set_t       *flip_vals;
    int                        flip_left;
} tmock_t;

static void mock_init(tmock_t *m, const char *chain_id)
{
    memset(m, 0, sizeof(*m));
    m->chain_id = chain_id;
}

/* mock.go:27-43 New — latestHeight is the largest key (:30-35). */
static void mock_add(tmock_t *m, int64_t height, const tsh_t *sh,
                     cmt_validator_set_t *vs)
{
    if (m->n >= MOCK_MAX) {
        return;
    }
    m->heights[m->n] = height;
    m->headers[m->n] = sh != NULL ? &sh->sh : NULL;
    m->vals[m->n]    = vs;
    m->n++;
    if (height > m->latest_height) {
        m->latest_height = height;
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

static void prov_err(cmt_light_provider_error_t *err, int code, int reason)
{
    if (err != NULL) {
        err->code   = code;
        err->reason = reason;
    }
}

/* mock.go:64-103 LightBlock; deadmock.go:23-25. */
static int mock_light_block(void *ctx, int64_t height,
                            cmt_light_block_buf_t *out,
                            cmt_light_provider_error_t *err)
{
    tmock_t          *m = ctx;
    cmt_light_block_t lb;
    size_t            i;
    bool              have = false;
    uint8_t          *bz = NULL;
    size_t            bz_len = 0u;
    int               rc;

    prov_err(err, CMT_LIGHT_PROVIDER_ERR_NONE, CMT_OK);
    if (m == NULL || out == NULL || height < 0) {
        return CMT_FAULT;
    }
    (void)cmt_light_block_buf_reset(out);
    if (m->dead) {                                               /* deadmock.go:24 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE, CMT_OK);
        return CMT_REJECT;
    }
    if (height > m->latest_height) {                             /* :77-79 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH, CMT_OK);
        return CMT_REJECT;
    }
    if (height == 0 && m->n > 0u) {                              /* :81-83 */
        height = m->latest_height;
    }
    lb.signed_header = NULL;
    lb.validator_set = NULL;
    if (m->flip_left > 0 && height == m->flip_height) {          /* PROJECT, D9 */
        m->flip_left--;
        lb.signed_header = m->flip_sh;
        lb.validator_set = m->flip_vals;
        have = true;
    }
    for (i = 0; !have && i < m->n; i++) {                        /* :85-92 */
        if (m->heights[i] == height) {
            lb.signed_header = m->headers[i];
            lb.validator_set = m->vals[i];
            have = true;
        }
    }
    if (!have) {                                                 /* :93-95 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND, CMT_OK);
        return CMT_REJECT;
    }
    if (lb.signed_header == NULL || lb.validator_set == NULL ||  /* :96-98 */
        lb.signed_header->header == NULL) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK, CMT_REJECT);
        return CMT_REJECT;
    }
    rc = cmt_light_block_validate_basic(&lb,                     /* :99-101 */
                                        lb.signed_header->header->chain_id,
                                        lb.signed_header->header->chain_id_len,
                                        CMT_BLOCK_PROTOCOL);
    if (rc != CMT_OK) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK, rc);
        return CMT_REJECT;
    }
    rc = cmt_light_block_encode(&lb, &bz, &bz_len);
    if (rc == CMT_OK) {
        rc = cmt_light_block_decode(bz, bz_len, CMT_BLOCK_PROTOCOL, out);
    }
    free(bz);
    return rc == CMT_OK ? CMT_OK : CMT_FAULT;                    /* :102 */
}

/* mock.go:105-108 / deadmock.go:27-29 — no caller in package 2. */
static int mock_report_evidence(void *ctx, const cmt_pb_evidence_t *ev)
{
    tmock_t *m = ctx;

    (void)ev;
    if (m == NULL) {
        return CMT_FAULT;
    }
    return m->dead ? CMT_REJECT : CMT_OK;
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

/* A mock with the reference's `headerSet` / `valSet` (client_test.go:
 * 49-61) — `fullNode` (:64-68). */
static void mock_full_node(tmock_t *m)
{
    mock_init(m, CHAIN);
    mock_add(m, 1, &F->h1, &F->vals.vs);
    mock_add(m, 2, &F->h2, &F->vals2.vs);
    mock_add(m, 3, &F->h3, &F->vals3.vs);
}

/* genMockNode(chainID, n, 3, 0, bTime) (helpers_test.go:239-252). */
static void mock_large(tmock_t *m, int64_t n)
{
    int64_t h;

    mock_init(m, CHAIN);
    for (h = 1; h <= n; h++) {
        mock_add(m, h, &F->large[h], &F->lvals.vs);
    }
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
    memcpy(s->path, "test_cmt_light_client.XXXXXX",
           sizeof("test_cmt_light_client.XXXXXX"));
    fd = mkstemp(s->path);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed\n");
        return 1;
    }
    (void)close(fd);
    /* `dbs.New(dbm.NewMemDB(), chainID)` — a temporary file here. */
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

/* Save {sh, vs} into the store (`trustedStore.SaveLightBlock`). */
static int store_save(tstore_t *s, const tsh_t *sh, cmt_validator_set_t *vs)
{
    cmt_light_block_t lb;

    lb.signed_header = &sh->sh;
    lb.validator_set = vs;
    return cmt_light_store_db_save_light_block(s->db, &lb);
}

static int64_t last_h(tstore_t *s)
{
    int64_t h = -2;

    (void)cmt_light_store_db_last_light_block_height(s->db, &h);
    return h;
}

static bool stored(tstore_t *s, int64_t height)
{
    bool found = false;

    if (cmt_light_store_db_light_block(s->db, height, g_out, &found) != CMT_OK) {
        return false;
    }
    return found;
}

/* The test's caps — large enough for every reference row. */
static void opts_default(cmt_light_client_options_t *o)
{
    cmt_light_client_options_default(o);
    o->max_trace_len       = 1000u;
    o->max_verify_steps    = 1000u;
    o->max_skipping_cache  = 1000u;
    o->max_backwards_steps = 1000u;
}

static cmt_light_trust_options_t trust_of(int64_t period, int64_t height,
                                          const tsh_t *sh, uint8_t *hash_buf)
{
    cmt_light_trust_options_t t;

    (void)cmt_header_hash(&sh->h, hash_buf);
    t.period   = period;
    t.height   = height;
    t.hash     = hash_buf;
    t.hash_len = CMT_TMHASH_SIZE;
    return t;
}

static bool id_is(const cmt_light_client_t *c, bool primary, size_t i,
                  const char *id)
{
    const uint8_t *p = NULL;
    size_t         n = 0u;
    int            rc = primary ? cmt_light_client_primary_id(c, &p, &n)
                                : cmt_light_client_witness_id(c, i, &p, &n);

    return rc == CMT_OK && n == strlen(id) && memcmp(p, id, n) == 0;
}

static bool out_height_is(int64_t h)
{
    return g_out->lb.signed_header != NULL &&
           g_out->lb.signed_header->header != NULL &&
           g_out->lb.signed_header->header->height == h;
}

/* ══ 1. TestValidateTrustOptions (client_test.go:73-116) ═════════════ */

static int t_trust_options(void)
{
    uint8_t                   hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                       ret = 1;

    T(cmt_light_trust_options_validate_basic(&t) == CMT_OK, "#0 valid");
    t.period = -1 * HOUR;                                        /* :83-89 */
    T(cmt_light_trust_options_validate_basic(&t) == CMT_REJECT, "#1 period");
    t.period = 0;                                                /* :40 `<= 0` */
    T(cmt_light_trust_options_validate_basic(&t) == CMT_REJECT, "period 0");
    t.period = HOUR;
    t.height = 0;                                                /* :91-96 */
    T(cmt_light_trust_options_validate_basic(&t) == CMT_REJECT, "#2 height");
    t.height   = 1;
    t.hash     = (const uint8_t *)"incorrect hash";              /* :99-104 */
    t.hash_len = strlen("incorrect hash");
    T(cmt_light_trust_options_validate_basic(&t) == CMT_REJECT, "#3 hash");
    T(cmt_light_trust_options_validate_basic(NULL) == CMT_FAULT, "NULL");
    ret = 0;
out:
    return ret;
}

/* ══ 2. TestMock (client_test.go:118-121) ════════════════════════════ */

static int t_mock(void)
{
    tmock_t                    m;
    cmt_light_provider_error_t e;
    int                        ret = 1;

    mock_full_node(&m);
    T(mock_light_block(&m, 3, g_out, &e) == CMT_OK && out_height_is(3),
      "fullNode.LightBlock(3)");
    ret = 0;
out:
    return ret;
}

/* ══ 3. TestClient_SequentialVerification (client_test.go:123-257) ══ */

typedef struct {
    const char *name;
    int64_t     heights[3];
    const tsh_t *headers[3];
    cmt_validator_set_t *vals[3];
    size_t      n;
    bool        init_err;
    bool        verify_err;     /* else: the detector hook (how it can lie, 1) */
    /* verify_err rows: the exact error the port's trace of the row gives
     * (0 = not pinned); `want_to` checks ErrVerificationFailed.To. */
    int         want_code;
    int64_t     want_to;
} trow_t;

/* NewClient(primary = mock(row), witnesses = {mock(row)}) — ADAPTED: two
 * instances, two identities — then VerifyLightBlockAtHeight(3, now). */
static int run_row(const trow_t *r, int mode, cmt_time_t now,
                   int64_t want_trace_len)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh); /* :44-48 */
    size_t                     i;
    int                        rc, ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_init(&p, CHAIN);
    mock_init(&w, CHAIN);
    for (i = 0; i < r->n; i++) {
        mock_add(&p, r->heights[i], r->headers[i], r->vals[i]);
        mock_add(&w, r->heights[i], r->headers[i], r->vals[i]);
    }
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    o.verification_mode = mode;

    rc = cmt_light_client_new((const uint8_t *)CHAIN, strlen(CHAIN), &t, &pp,
                              &wp, 1, &s.st, &o, &c, &e);
    if (r->init_err) {
        T(rc == CMT_REJECT && c == NULL, r->name);
        T(last_h(&s) == -1, "init error saves nothing");
        ret = 0;
        goto out;
    }
    T(rc == CMT_OK && c != NULL, r->name);

    rc = cmt_light_client_verify_light_block_at_height(c, 3, now, g_out, &e);
    if (r->verify_err) {
        T(rc == CMT_REJECT &&
          e.code != CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED, r->name);
        T(r->want_code == 0 || e.code == r->want_code, r->name);
        T(r->want_to == 0 ||
          (e.to == r->want_to && e.reason == CMT_LIGHT_CLIENT_REASON_VERIFIER &&
           e.verify.code == CMT_LIGHT_ERR_INVALID_HEADER), r->name);
    } else {
        T(rc == CMT_REJECT &&
          e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED &&
          e.trace_from == 1 && e.trace_to == 3 &&
          e.trace_len == (size_t)want_trace_len, r->name);
    }
    /* Fail closed: block 3 is never saved. */
    T(last_h(&s) == 1 && !stored(&s, 3), "nothing saved past the root");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_sequential(void)
{
    trow_t rows[7];
    size_t i;

    memset(rows, 0, sizeof(rows));
    rows[0] = (trow_t){ "seq good", { 1, 2, 3 },                 /* :135-141 */
                        { &F->h1, &F->h2, &F->h3 },
                        { &F->vals.vs, &F->vals2.vs, &F->vals3.vs }, 3,
                        false, false, 0, 0 };
    rows[1] = (trow_t){ "seq bad: different first header", { 1 }, /* :142-154 */
                        { &F->hdr1_alt }, { &F->vals.vs }, 1, true, false, 0, 0 };
    rows[2] = (trow_t){ "seq bad: no first signed header", { 0 }, /* :155-163 */
                        { NULL }, { NULL }, 0, true, true, 0, 0 };
    rows[3] = (trow_t){ "seq bad: different first validator set", { 1 }, /* :164-174 */
                        { &F->h1 }, { &F->different_vals.vs }, 1, true, true, 0, 0 };
    rows[4] = (trow_t){ "seq bad: 1/3 signed interim header",    /* :175-190 */
                        { 1, 2, 3 }, { &F->h1, &F->seq13_2, &F->seq_3_full },
                        { &F->vals.vs, &F->vals2.vs, &F->vals3.vs }, 3,
                        false, true, 0, 0 };
    rows[5] = (trow_t){ "seq bad: 1/3 signed last header",       /* :191-206 */
                        { 1, 2, 3 }, { &F->h1, &F->seq_2_full, &F->seq13_3 },
                        { &F->vals.vs, &F->vals2.vs, &F->vals3.vs }, 3,
                        false, true, 0, 0 };
    rows[6] = (trow_t){ "seq bad: different validator set at height 3", /* :207-217 */
                        { 1, 2, 3 }, { &F->h1, &F->h2, &F->h3 },
                        { &F->vals.vs, &F->vals.vs, &F->new_vals.vs }, 3,
                        false, true, 0, 0 };
    /* The failure each bad row must stop at: interim 2 is not signed by
     * 2/3 (VerifyAdjacent → ErrInvalidHeader, To 2; the replacement fails
     * because the only witness cannot be removed, Q6); the last header is
     * not (To 3, returned at :651-655); block 3's set is not its header's
     * (both providers answer ErrBadLightBlock → lastError, :1126). */
    rows[4].want_code = CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED;
    rows[4].want_to   = 2;
    rows[5].want_code = CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED;
    rows[5].want_to   = 3;
    rows[6].want_code = CMT_LIGHT_CLIENT_ERR_PROVIDER;
    for (i = 0; i < 7; i++) {
        if (run_row(&rows[i], CMT_LIGHT_CLIENT_MODE_SEQUENTIAL,
                    t_at(3 * HOUR), 3) != 0) {                   /* :249 */
            return 1;
        }
    }
    return 0;
}

/* ══ 4. TestClient_SkippingVerification (client_test.go:259-381) ════ */

static int t_skipping(void)
{
    trow_t  rows[4];
    int64_t want[4] = { 2, 2, 3, 0 };
    size_t  i;

    memset(rows, 0, sizeof(rows));
    rows[0] = (trow_t){ "skip good", { 1, 3 },                   /* :275-286 */
                        { &F->h1, &F->h3 },
                        { &F->vals.vs, &F->vals3.vs }, 2, false, false, 0, 0 };
    rows[1] = (trow_t){ "skip good, val set changes by 2/3",     /* :287-302 */
                        { 1, 3 }, { &F->h1, &F->transit3 },
                        { &F->vals.vs, &F->transit_vals.vs }, 2, false, false, 0, 0 };
    rows[2] = (trow_t){ "skip good, val set changes 100% at 2",  /* :303-322 */
                        { 1, 2, 3 }, { &F->h1, &F->change2, &F->change3 },
                        { &F->vals.vs, &F->vals.vs, &F->new_vals.vs }, 3,
                        false, false, 0, 0 };
    rows[3] = (trow_t){ "skip bad: interim header has no signers", /* :323-342 */
                        { 1, 2, 3 }, { &F->h1, &F->nosig2, &F->change3 },
                        { &F->vals.vs, &F->vals.vs, &F->new_vals.vs }, 3,
                        false, true, 0, 0 };
    /* The pivot 2 has no signers: Verify(1, 2) → ErrInvalidHeader, To 2. */
    rows[3].want_code = CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED;
    rows[3].want_to   = 2;
    for (i = 0; i < 4; i++) {
        if (run_row(&rows[i], CMT_LIGHT_CLIENT_MODE_SKIPPING,
                    t_at(3 * HOUR), want[i]) != 0) {             /* :373 */
            return 1;
        }
    }
    return 0;
}

/* A client over (primary, witnesses) with options `o` and trust `t`. */
static int new_client(const cmt_light_trust_options_t *t,
                      cmt_light_client_peer_t *pp,
                      cmt_light_client_peer_t *ws, size_t nw, tstore_t *s,
                      const cmt_light_client_options_t *o,
                      cmt_light_client_t **c, cmt_light_client_error_t *e)
{
    return cmt_light_client_new((const uint8_t *)CHAIN, strlen(CHAIN), t, pp,
                                ws, nw, &s->st, o, c, e);
}

/* ══ 5. TestClientLargeBisectionVerification (client_test.go:383-408) */

static int t_large_bisection(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 5, &F->large[5], hh);
    bool                       adv = true;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_large(&p, LARGE_N);                                     /* :386 */
    mock_large(&w, LARGE_N);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);                                            /* :400 */
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init at 5");
    /* :403 Update(bTime + 100 min) → the hook, with the trace 5 → 100. */
    T(cmt_light_client_update(c, t_at(100 * MINUTE), g_out, &adv, &e) == CMT_REJECT &&
      !adv && e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED &&
      e.trace_from == 5 && e.trace_to == LARGE_N, "large bisection → hook");
    T(last_h(&s) == 5, "nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 6. TestClient_Cleanup (client_test.go:438-459) ══════════════════ */

static int t_cleanup(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_full_node(&p);
    mock_full_node(&w);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_trusted_light_block(c, 1, g_out, &e) == CMT_OK &&
      out_height_is(1), "trusted 1");                            /* :449-450 */
    T(cmt_light_client_cleanup(c) == CMT_OK, "cleanup");          /* :452-453 */
    T(cmt_light_client_trusted_light_block(c, 1, g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NO_HEADERS &&
      g_out->lb.signed_header == NULL, "no blocks after cleanup"); /* :456-458 */
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 7. TestClientRestoresTrustedHeaderAfterStartup1/2/3 (:461-700) ══ */

static bool out_hash_is(const tsh_t *sh)
{
    uint8_t a[CMT_TMHASH_SIZE], b[CMT_TMHASH_SIZE];

    return g_out->lb.signed_header != NULL &&
           g_out->lb.signed_header->header != NULL &&
           cmt_header_hash(g_out->lb.signed_header->header, a) == CMT_OK &&
           cmt_header_hash(&sh->h, b) == CMT_OK &&
           memcmp(a, b, CMT_TMHASH_SIZE) == 0;
}

/* Store `store_sh`, run NewClient over a primary (and a witness with the
 * same data) holding `prim_sh` at `prim_h` with valSet's sets
 * (:49-54), then check which heights are trusted; the FIRST present
 * height must hold `first_sh` (`assert.Equal(t, l.Hash(), …)`). */
static int startup_case(const char *name, const tsh_t *first_sh,
                        const tsh_t *const *store_sh,
                        cmt_validator_set_t *const *store_vs, size_t n_store,
                        const tsh_t *const *prim_sh, const int64_t *prim_h,
                        size_t n_prim, int64_t trust_h, const tsh_t *trust_sh,
                        const int64_t *want_present, size_t n_present,
                        const int64_t *want_absent, size_t n_absent)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, trust_h, trust_sh, hh);
    cmt_validator_set_t       *valset[4];
    size_t                     i;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    for (i = 0; i < n_store; i++) {
        T(store_save(&s, store_sh[i], store_vs[i]) == CMT_OK, "store save");
    }
    /* valSet (:49-54). */
    valset[0] = NULL;
    valset[1] = &F->vals.vs;
    valset[2] = &F->vals2.vs;
    valset[3] = &F->vals3.vs;
    mock_init(&p, CHAIN);
    mock_init(&w, CHAIN);
    for (i = 0; i < n_prim; i++) {
        mock_add(&p, prim_h[i], prim_sh[i], valset[prim_h[i]]);
        mock_add(&w, prim_h[i], prim_sh[i], valset[prim_h[i]]);
    }
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, name);
    for (i = 0; i < n_present; i++) {
        T(cmt_light_client_trusted_light_block(c, want_present[i], g_out,
                                               &e) == CMT_OK &&
          out_height_is(want_present[i]) &&
          (i != 0 || out_hash_is(first_sh)), name);
    }
    for (i = 0; i < n_absent; i++) {
        T(cmt_light_client_trusted_light_block(c, want_absent[i], g_out,
                                               &e) == CMT_REJECT &&
          g_out->lb.signed_header == NULL, name);
    }
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_startup(void)
{
    const tsh_t         *s_l1[1]     = { &F->h1 };
    cmt_validator_set_t *s_l1v[1]    = { &F->vals.vs };
    const tsh_t         *s_l12[2]    = { &F->h1, &F->h2 };
    cmt_validator_set_t *s_l12v[2]   = { &F->vals.vs, &F->vals2.vs };
    const tsh_t         *s_l1h2[2]   = { &F->h1, &F->hdr2_alt };
    cmt_validator_set_t *s_l1h2v[2]  = { &F->vals.vs, &F->vals.vs };
    const tsh_t         *full[3]     = { &F->h1, &F->h2, &F->h3 };
    const int64_t        full_h[3]   = { 1, 2, 3 };
    const tsh_t         *alt1[1]     = { &F->hdr1_alt };
    const int64_t        one[1]      = { 1 };
    const tsh_t         *alt12[2]    = { &F->hdr1_alt, &F->hdr2_alt };
    const int64_t        one_two[2]  = { 1, 2 };
    const int64_t        two[1]      = { 2 };
    const int64_t        two3[2]     = { 2, 3 };

    /* Startup1 case 1 (:463-485): same height, same hash. */
    if (startup_case("startup1 #1", &F->h1, s_l1,s_l1v, 1, full, full_h, 3, 1,
                     &F->h1, one, 1, NULL, 0) != 0) {
        return 1;
    }
    /* Startup1 case 2 (:487-527): same height, the primary has another
     * block 1 and the options name it → cleanup, re-root at header1. */
    if (startup_case("startup1 #2", &F->hdr1_alt, s_l1,s_l1v, 1, alt1, one, 1, 1,
                     &F->hdr1_alt, one, 1, NULL, 0) != 0) {
        return 1;
    }
    /* Startup2 case 1 (:532-559): options above the stored height; the
     * primary's block 1 matches; init at 2; block 1 is kept. */
    if (startup_case("startup2 #1", &F->h1, s_l1,s_l1v, 1, full, full_h, 3, 2,
                     &F->h2, one_two, 2, NULL, 0) != 0) {
        return 1;
    }
    /* Startup2 case 2 (:561-603): the primary's block 1 differs → the
     * stored block 1 is removed. */
    if (startup_case("startup2 #2", &F->hdr2_alt, s_l1,s_l1v, 1, alt12, one_two, 2, 2,
                     &F->hdr2_alt, two, 1, one, 1) != 0) {
        return 1;
    }
    /* Startup3 case 1 (:607-644): options below the stored latest → the
     * rollback (Q3: block 2 survives cleanupAfter) and the hash check
     * removes everything; init at 1 again; 2 and 3 are gone. */
    if (startup_case("startup3 #1", &F->h1, s_l12,s_l12v, 2, full, full_h, 3, 1,
                     &F->h1, one, 1, two3, 2) != 0) {
        return 1;
    }
    /* Startup3 case 2 (:646-699): stored {l1, header2}; the primary's
     * block 1 is header1 → swapped; the stored block 2 is gone. */
    if (startup_case("startup3 #2", &F->hdr1_alt, s_l1h2,s_l1h2v, 2, alt1, one, 1, 1,
                     &F->hdr1_alt, one, 1, two, 1) != 0) {
        return 1;
    }
    return 0;
}

/* PROJECT — Startup3 case 1 with a confirmation function that refuses
 * the rollback: the reference returns nil and keeps the store (:333-335). */
static bool confirm_no(void *ctx, int action, int64_t a, int64_t b)
{
    int *calls = ctx;

    (void)a;
    (void)b;
    if (calls != NULL && action == CMT_LIGHT_CLIENT_ACTION_ROLLBACK) {
        (*calls)++;
    }
    return false;
}

static int t_rollback_refused(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                        calls = 0, ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    T(store_save(&s, &F->h1, &F->vals.vs) == CMT_OK &&
      store_save(&s, &F->h2, &F->vals2.vs) == CMT_OK, "store");
    mock_full_node(&p);
    mock_full_node(&w);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    o.confirm     = confirm_no;
    o.confirm_ctx = &calls;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK && calls == 1,
      "rollback asked once, refused");
    T(stored(&s, 1) && stored(&s, 2) && last_h(&s) == 2, "store kept");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 8. TestClient_Update (client_test.go:702-721) — and fail closed ═ */

static int t_update(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    bool                       adv = true;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_full_node(&p);
    mock_full_node(&w);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init");
    /* :715 — "should result in downloading & verifying header #3":
     * skipping 1 → 3 reaches the hook, which refuses (D5). */
    T(cmt_light_client_update(c, t_at(2 * HOUR), g_out, &adv, &e) == CMT_REJECT &&
      !adv && e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED &&
      e.trace_len == 2 && e.trace_from == 1 && e.trace_to == 3,
      "Update → hook");
    /* FAIL CLOSED: nothing saved, block 3 is still unverified. */
    T(last_h(&s) == 1 && !stored(&s, 3), "store unchanged");
    T(cmt_light_client_trusted_light_block(c, 3, g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_UNVERIFIED_HEIGHT, "3 unverified");
    /* Twice: the hook never turns into a success. */
    T(cmt_light_client_verify_light_block_at_height(c, 3, t_at(2 * HOUR),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED &&
      g_out->lb.signed_header == NULL, "verify 3 → hook, out empty (D10)");
    /* compareWithLatestHeight (:412-431): 0 = the latest; Q8. */
    T(cmt_light_client_trusted_light_block(c, 0, g_out, &e) == CMT_OK &&
      out_height_is(1), "height 0 = latest");
    T(cmt_light_client_trusted_light_block(c, -1, g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT, "negative height");
    T(cmt_light_client_verify_light_block_at_height(c, 0, t_at(2 * HOUR),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_BAD_HEIGHT, "verify height 0");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* PROJECT — Q2: a benign provider error at a bisection pivot returns the
 * bare ErrNewValSetCantBeTrusted, which the reference sends to
 * detectDivergence with a nil trace (detector.go:29-31). */
static int t_short_trace(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_init(&p, CHAIN);
    mock_add(&p, 1, &F->h1, &F->vals.vs);
    mock_add(&p, 3, &F->change3, &F->new_vals.vs);   /* no block 2 */
    w = p;
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_verify_light_block_at_height(c, 3, t_at(3 * HOUR),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_SHORT_TRACE, "Q2 → short trace");
    T(last_h(&s) == 1, "nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 9. TestClientReplacesPrimaryWithWitnessIfPrimaryIsUnavailable ═══
 *     (client_test.go:764-782) */

static int t_replace_dead_primary(void)
{
    tmock_t                    dead, w1, w2;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, ws[2];
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    bool                       adv = true;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_init(&dead, CHAIN);
    dead.dead = true;                                            /* :769 deadNode */
    mock_full_node(&w1);                                         /* :770 {fullNode, fullNode} */
    mock_full_node(&w2);
    pp    = peer_of(&dead, "dead");
    ws[0] = peer_of(&w1, "full-1");
    ws[1] = peer_of(&w2, "full-2");
    opts_default(&o);
    o.max_retry_attempts = 1;                                    /* :773 (never read) */
    /* Init: the dead primary → findNewPrimary(1, remove = false) promotes
     * witness #0 (index order, D2) and keeps the dead one as a witness. */
    T(new_client(&t, &pp, ws, 2, &s, &o, &c, &e) == CMT_OK, "init");
    T(id_is(c, true, 0, "full-1"), "witness #0 promoted");
    T(cmt_light_client_witness_count(c) == 2, "two witnesses");
    /* :1028-1031 — slot 0 takes the last (the dead one, appended). */
    T(id_is(c, false, 0, "dead") && id_is(c, false, 1, "full-2"),
      "removeWitnesses order (Q7)");
    /* :777 Update → the hook (D5). */
    T(cmt_light_client_update(c, t_at(2 * HOUR), g_out, &adv, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED, "Update → hook");
    T(!id_is(c, true, 0, "dead"), "primary is not the dead node"); /* :780 */
    T(cmt_light_client_witness_count(c) == 2, "len(Witnesses) == 2"); /* :781 */
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 10. TestClient_BackwardsVerification (client_test.go:784-888) ══ */

static int t_backwards(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * MINUTE, 6, &F->large[6], hh);
    int                        row, ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_large(&p, 10);                                          /* :786 largeFullNode */
    mock_large(&w, 10);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init at 6");
    /* 1) before the trusted header (:802-807). */
    T(cmt_light_client_verify_light_block_at_height(c, 5, t_at(6 * MINUTE),
                                                    g_out, &e) == CMT_OK &&
      out_height_is(5), "1) backwards to 5");
    /* 2) the untrusted header is expired, the trusted one not (:809-812). */
    T(cmt_light_client_verify_light_block_at_height(c, 3, t_at(8 * MINUTE),
                                                    g_out, &e) == CMT_OK &&
      out_height_is(3), "2) backwards to 3");
    /* 3) already stored (:814-817). */
    T(cmt_light_client_verify_light_block_at_height(c, 5, t_at(6 * MINUTE),
                                                    g_out, &e) == CMT_OK &&
      out_height_is(5), "3) already stored");
    T(stored(&s, 3) && stored(&s, 4) == false && stored(&s, 5) &&
      stored(&s, 6), "3, 5, 6 stored; 4 was only walked");
    /* 4a) the latest (:819-821) → the hook (D5). */
    T(cmt_light_client_verify_light_block_at_height(c, 9, t_at(9 * MINUTE),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED, "4a) → hook");
    cmt_light_client_free(c);
    c = NULL;
    store_close(&s);

    /* 7) incorrect height, 8) incorrect hash (:836-887). */
    for (row = 7; row <= 8; row++) {
        cmt_light_trust_options_t t3 = trust_of(HOUR, 3, &F->h3, hh); /* :872-876 */

        if (store_open(&s) != 0) {
            return 1;
        }
        mock_init(&p, CHAIN);
        mock_add(&p, 1, &F->h1, &F->vals.vs);
        mock_add(&p, 2, row == 7 ? &F->bad_height2 : &F->bad_hash2,
                 &F->vals2.vs);
        mock_add(&p, 3, &F->h3, &F->vals3.vs);
        w  = p;
        pp = peer_of(&p, "primary");
        wp = peer_of(&w, "witness");
        T(new_client(&t3, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init at 3");
        T(cmt_light_client_verify_light_block_at_height(c, 2,
                t_at(HOUR + SECOND), g_out, &e) == CMT_REJECT && /* :884-885 */
          /* VerifyBackwards' ErrInvalidHeader, returned as is (:962/:969);
           * the replacement fails because the only witness cannot be
           * removed (Q6). */
          e.code == CMT_LIGHT_CLIENT_ERR_VERIFIER &&
          e.verify.code == CMT_LIGHT_ERR_INVALID_HEADER,
          row == 7 ? "7) incorrect height" : "8) incorrect hash");
        T(!stored(&s, 2) && !stored(&s, 1), "nothing saved below 3");
        cmt_light_client_free(c);
        c = NULL;
        store_close(&s);
    }
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* PROJECT — D9: the primary sends one height-5 block when asked for the
 * target and the chain's block when the walk asks; the walk reaches a
 * block that is not the target → refused, nothing saved. */
static int t_backwards_target_mismatch(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * MINUTE, 6, &F->large[6], hh);
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_large(&p, 10);
    mock_large(&w, 10);
    p.flip_height = 5;
    p.flip_sh     = &F->fake5.sh;
    p.flip_vals   = &F->lvals.vs;
    p.flip_left   = 1;
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init at 6");
    T(cmt_light_client_verify_light_block_at_height(c, 5, t_at(6 * MINUTE),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_VERIFICATION_FAILED &&
      e.reason == CMT_LIGHT_CLIENT_REASON_TARGET_MISMATCH && e.to == 5,
      "D9: the target is not the block reached");
    T(p.flip_left == 0 && !stored(&s, 5), "the fake was served, not saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* PROJECT — prune via the light store (adapted from
 * TestClientPrunesHeadersAndValidatorSets, client_test.go:1010-1031):
 * PruningSize(1), a backwards save, then only the newest block remains. */
static int t_prune(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * MINUTE, 6, &F->large[6], hh);
    uint64_t                   n = 0u;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_large(&p, 10);
    mock_large(&w, 10);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    o.pruning_size = 1u;                                         /* :1019 */
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init");
    T(cmt_light_client_verify_light_block_at_height(c, 5, t_at(6 * MINUTE),
                                                    g_out, &e) == CMT_OK,
      "verify 5");
    T(cmt_light_store_db_size(s.db, &n) == CMT_OK && n == 1u &&
      !stored(&s, 5) && stored(&s, 6), "pruned to the newest");
    T(cmt_light_client_trusted_light_block(c, 5, g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NOT_FOUND, "5 pruned");      /* :1029-1030 */
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 11. TestClient_NewClientFromTrustedStore (client_test.go:890-910) */

static int t_from_trusted_store(void)
{
    tmock_t                    dead1, dead2;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    T(store_save(&s, &F->h1, &F->vals.vs) == CMT_OK, "save l1"); /* :892-894 */
    mock_init(&dead1, CHAIN);
    dead1.dead = true;
    mock_init(&dead2, CHAIN);
    dead2.dead = true;
    pp = peer_of(&dead1, "dead-1");
    wp = peer_of(&dead2, "dead-2");
    opts_default(&o);
    T(cmt_light_client_new_from_trusted_store((const uint8_t *)CHAIN,
                                              strlen(CHAIN), 4 * HOUR, &pp,
                                              &wp, 1, &s.st, &o, &c,
                                              &e) == CMT_OK, "from store");
    T(cmt_light_client_trusted_light_block(c, 1, g_out, &e) == CMT_OK &&
      out_height_is(1), "block 1 from the store");               /* :907-909 */
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 12. TestClientEnsureValidHeadersAndValSets (client_test.go:1033-1102) */

static int t_ensure_valid(void)
{
    int row;

    for (row = 0; row < 4; row++) {
        tmock_t                    p, w1, w2;
        tstore_t                   s;
        cmt_light_client_peer_t    pp, ws[2];
        cmt_light_client_options_t o;
        cmt_light_client_t        *c = NULL;
        cmt_light_client_error_t   e;
        uint8_t                    hh[CMT_TMHASH_SIZE];
        cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
        int                        rc, ret = 1;

        if (store_open(&s) != 0) {
            return 1;
        }
        mock_init(&p, CHAIN);
        mock_add(&p, 1, &F->h1, &F->vals.vs);
        if (row == 2) {                                          /* :1058-1066 */
            mock_add(&p, 2, &F->h2, &F->vals2.vs);
            mock_add(&p, 3, NULL, &F->vals3.vs);
        } else {
            mock_add(&p, 2, &F->h2, row == 0 ? &F->vals2.vs : &F->vals.vs);
            mock_add(&p, 3, &F->h3,
                     row == 0 ? &F->vals3.vs                     /* :1044-1048 */
                     : row == 1 ? NULL                           /* :1049-1057 */
                     : &F->empty.vs);                            /* :1067-1075 */
        }
        /* ADAPTED: `{badNode, badNode}` — three instances, three ids. */
        w1 = p;
        w2 = p;
        pp    = peer_of(&p, "bad-0");
        ws[0] = peer_of(&w1, "bad-1");
        ws[1] = peer_of(&w2, "bad-2");
        opts_default(&o);
        T(new_client(&t, &pp, ws, 2, &s, &o, &c, &e) == CMT_OK, "init");
        rc = cmt_light_client_verify_light_block_at_height(c, 3,
                t_at(2 * HOUR), g_out, &e);                      /* :1095 */
        if (row == 0) {
            T(rc == CMT_REJECT &&
              e.code == CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED,
              "row 0 → hook");
        } else {
            /* Every provider answers ErrBadLightBlock → lastError (:1126). */
            T(rc == CMT_REJECT && e.code == CMT_LIGHT_CLIENT_ERR_PROVIDER &&
              e.provider.code == CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK,
              "invalid block 3 refused");
        }
        ret = 0;
    out:
        cmt_light_client_free(c);
        store_close(&s);
        if (ret != 0) {
            fprintf(stderr, "ensure-valid row %d\n", row);
            return 1;
        }
    }
    return 0;
}

/* ══ 13. PROJECT — the item-9 agreement rule at init ═════════════════ */

/* Init at h1 with `nw` witnesses; returns the constructor's rc. */
static int init_with(tmock_t *wm, const char *const *wid, size_t nw,
                     const char *pid, size_t min_agree, tstore_t *s,
                     cmt_light_client_t **c, cmt_light_client_error_t *e)
{
    static tmock_t             p;
    cmt_light_client_peer_t    pp, ws[4];
    cmt_light_client_options_t o;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    size_t                     i;

    mock_full_node(&p);
    pp = peer_of(&p, pid);
    for (i = 0; i < nw && i < 4; i++) {
        ws[i] = peer_of(&wm[i], wid[i]);
    }
    opts_default(&o);
    o.min_init_agreement = min_agree;
    return new_client(&t, &pp, ws, nw, s, &o, c, e);
}

static int t_init_agreement(void)
{
    tmock_t                  wm[4];
    tstore_t                 s;
    cmt_light_client_t      *c = NULL;
    cmt_light_client_error_t e;
    const char              *ids[4];
    int                      ret = 1;

    memset(&s, 0, sizeof(s));
#define FRESH() do { cmt_light_client_free(c); c = NULL; store_close(&s); \
                     if (store_open(&s) != 0) goto out; } while (0)

    /* AGREE: a distinct witness holds the root → 2 identities. */
    FRESH();
    mock_full_node(&wm[0]);
    ids[0] = "w-good";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_OK &&
      last_h(&s) == 1, "agree");

    /* ONE DISAGREES (R5): another header at the same height. */
    FRESH();
    mock_full_node(&wm[0]);
    mock_init(&wm[1], CHAIN);
    mock_add(&wm[1], 1, &F->hdr1_alt, &F->vals.vs);
    ids[0] = "w-good";
    ids[1] = "w-fork";
    T(init_with(wm, ids, 2, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      c == NULL && e.code == CMT_LIGHT_CLIENT_ERR_CONFLICTING_HEADERS &&
      e.witness_index == 1, "one disagrees → stop");
    T(last_h(&s) == -1, "nothing saved on a conflict");

    /* PRIORITIES (R3, R5, K25-3): the same header, vals2's priorities. */
    FRESH();
    mock_init(&wm[0], CHAIN);
    mock_add(&wm[0], 1, &F->h1, &F->vals2.vs);
    ids[0] = "w-prio";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_PROPOSER_PRIORITIES_DIVERGE &&
      e.witness_index == 0, "priorities diverge → stop");

    /* ONE SILENT (R4): alone it is not enough... */
    FRESH();
    mock_init(&wm[0], CHAIN);
    wm[0].dead = true;
    ids[0] = "w-dead";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT &&
      e.agreeing == 1, "silent only → short");
    T(last_h(&s) == -1, "nothing saved when short");
    /* ...with an agreeing witness beside it, it is. */
    FRESH();
    mock_init(&wm[0], CHAIN);
    wm[0].dead = true;
    mock_full_node(&wm[1]);
    ids[0] = "w-dead";
    ids[1] = "w-good";
    T(init_with(wm, ids, 2, "primary", 2, &s, &c, &e) == CMT_OK &&
      cmt_light_client_witness_count(c) == 2, "silent + good → ok, kept");

    /* NOT AT THE HEIGHT (R1, R4): a witness that is behind. */
    FRESH();
    mock_init(&wm[0], CHAIN);       /* empty: latest 0 → HEIGHT_TOO_HIGH */
    ids[0] = "w-behind";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT, "behind → short");

    /* DEDUP (R2): the primary's identity on a witness adds nothing. */
    FRESH();
    mock_full_node(&wm[0]);
    ids[0] = "primary";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT &&
      e.agreeing == 1, "witness = primary identity → short");
    /* Two witnesses with one identity count once (min 3). */
    FRESH();
    mock_full_node(&wm[0]);
    mock_full_node(&wm[1]);
    ids[0] = "w-same";
    ids[1] = "w-same";
    T(init_with(wm, ids, 2, "primary", 3, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT &&
      e.agreeing == 2, "duplicate identity counts once");
    /* Two distinct identities (min 3) → ok. */
    FRESH();
    mock_full_node(&wm[0]);
    mock_full_node(&wm[1]);
    ids[0] = "w-a";
    ids[1] = "w-b";
    T(init_with(wm, ids, 2, "primary", 3, &s, &c, &e) == CMT_OK, "min 3 ok");

    /* BAD WITNESS (R4): an invalid block → removed, not counted. */
    FRESH();
    mock_init(&wm[0], CHAIN);
    mock_add(&wm[0], 1, &F->h1, &F->new_vals.vs);   /* set ≠ header */
    mock_full_node(&wm[1]);
    ids[0] = "w-bad";
    ids[1] = "w-good";
    T(init_with(wm, ids, 2, "primary", 2, &s, &c, &e) == CMT_OK &&
      cmt_light_client_witness_count(c) == 1 && id_is(c, false, 0, "w-good"),
      "bad witness removed");
    /* Alone: not counted; it stays, since removing it would leave none
     * (removeWitnesses refuses, :1021-1023, logged at :1185-1187). */
    FRESH();
    mock_init(&wm[0], CHAIN);
    mock_add(&wm[0], 1, &F->h1, &F->new_vals.vs);
    ids[0] = "w-bad";
    T(init_with(wm, ids, 1, "primary", 2, &s, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT, "bad only → short");
#undef FRESH
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 14. PROJECT — the caps (D3) ═════════════════════════════════════ */

/* The "100% change at 2" fixture (client_test.go:303-322): skipping takes
 * Verify(1,3) → cannot trust → pivot 2 (cached twice, Q1) → Verify(1,2) →
 * Verify(2,3): 3 Verify calls, a cache of 3, a trace of 3. */
static int cap_case(const char *name, int mode, uint64_t trace,
                    uint64_t steps, uint64_t cache, int want_code)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_init(&p, CHAIN);
    if (mode == CMT_LIGHT_CLIENT_MODE_SKIPPING) {
        mock_add(&p, 1, &F->h1, &F->vals.vs);
        mock_add(&p, 2, &F->change2, &F->vals.vs);
        mock_add(&p, 3, &F->change3, &F->new_vals.vs);
    } else {
        mock_full_node(&p);
    }
    w  = p;
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    o.verification_mode  = mode;
    o.max_trace_len      = trace;
    o.max_verify_steps   = steps;
    o.max_skipping_cache = cache;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, name);
    T(cmt_light_client_verify_light_block_at_height(c, 3, t_at(3 * HOUR),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == want_code, name);
    T(last_h(&s) == 1, "nothing saved");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

static int t_caps(void)
{
    tmock_t                    p, w;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * MINUTE, 6, &F->large[6], hh);
    int                        ret = 1;
    const int                  SK = CMT_LIGHT_CLIENT_MODE_SKIPPING;
    const int                  SQ = CMT_LIGHT_CLIENT_MODE_SEQUENTIAL;
    const int                  HOOK = CMT_LIGHT_CLIENT_ERR_DETECTOR_NOT_IMPLEMENTED;

    if (cap_case("skip: exactly enough", SK, 3, 3, 3, HOOK) != 0 ||
        cap_case("skip: verify steps", SK, 3, 2, 3,
                 CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS) != 0 ||
        cap_case("skip: cache (Q1 doubles it)", SK, 3, 3, 2,
                 CMT_LIGHT_CLIENT_ERR_CAP_SKIPPING_CACHE) != 0 ||
        cap_case("skip: trace", SK, 2, 3, 3,
                 CMT_LIGHT_CLIENT_ERR_CAP_TRACE) != 0 ||
        cap_case("seq: exactly enough", SQ, 3, 2, 1, HOOK) != 0 ||
        cap_case("seq: trace, before any fetch", SQ, 2, 2, 1,
                 CMT_LIGHT_CLIENT_ERR_CAP_TRACE) != 0 ||
        cap_case("seq: verify steps", SQ, 3, 1, 1,
                 CMT_LIGHT_CLIENT_ERR_CAP_VERIFY_STEPS) != 0) {
        return 1;
    }

    /* Backwards: 6 → 3 fetches 5, 4, 3. */
    if (store_open(&s) != 0) {
        return 1;
    }
    mock_large(&p, 10);
    mock_large(&w, 10);
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    opts_default(&o);
    o.max_backwards_steps = 2u;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_OK, "init at 6");
    T(cmt_light_client_verify_light_block_at_height(c, 3, t_at(8 * MINUTE),
                                                    g_out, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_CAP_BACKWARDS_STEPS, "backwards cap");
    T(!stored(&s, 3), "nothing saved");
    T(cmt_light_client_verify_light_block_at_height(c, 4, t_at(8 * MINUTE),
                                                    g_out, &e) == CMT_OK,
      "two steps are within the cap");
    ret = 0;
out:
    cmt_light_client_free(c);
    store_close(&s);
    return ret;
}

/* ══ 15. PROJECT — the constructor's checks (client.go:209-264) ══════ */

static int t_options(void)
{
    tmock_t                    p, w, other;
    tstore_t                   s;
    cmt_light_client_peer_t    pp, wp, op, bad;
    cmt_light_client_options_t o;
    cmt_light_client_t        *c = NULL;
    cmt_light_client_error_t   e;
    uint8_t                    hh[CMT_TMHASH_SIZE];
    cmt_light_trust_options_t  t = trust_of(4 * HOUR, 1, &F->h1, hh);
    int                        ret = 1;

    if (store_open(&s) != 0) {
        return 1;
    }
    mock_full_node(&p);
    mock_full_node(&w);
    mock_full_node(&other);
    other.chain_id = "other-chain";
    pp = peer_of(&p, "primary");
    wp = peer_of(&w, "witness");
    op = peer_of(&other, "other");

    opts_default(&o);
    T(new_client(&t, &pp, &wp, 0, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_NO_WITNESSES, "zero witnesses (:242-244)");
    T(new_client(&t, &pp, &op, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_WITNESS_WRONG_CHAIN &&
      e.witness_index == 0, "witness on another chain (:246-252)");
    o.trust_level = (cmt_fraction_t){ 1u, 4u };
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_LEVEL, "trust 1/4 (:254-257)");
    opts_default(&o);
    o.max_backwards_steps = 0u;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS, "a zero cap (D3)");
    opts_default(&o);
    o.min_init_agreement = 1u;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS, "min agreement 1 (R6)");
    opts_default(&o);
    o.verification_mode = 7;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS, "unknown mode (:572)");
    opts_default(&o);
    bad = wp;
    bad.id_len = 0u;
    T(new_client(&t, &pp, &bad, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_OPTIONS, "empty identity (R2)");
    t.period = 0;
    T(new_client(&t, &pp, &wp, 1, &s, &o, &c, &e) == CMT_REJECT &&
      e.code == CMT_LIGHT_CLIENT_ERR_INVALID_TRUST_OPTIONS, "trust options (:183-185)");
    T(c == NULL && last_h(&s) == -1, "nothing made, nothing saved");
    ret = 0;
out:
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
    if (t_trust_options() != 0) goto out;
    if (t_mock() != 0) goto out;
    if (t_sequential() != 0) goto out;
    if (t_skipping() != 0) goto out;
    if (t_large_bisection() != 0) goto out;
    if (t_cleanup() != 0) goto out;
    if (t_startup() != 0) goto out;
    if (t_rollback_refused() != 0) goto out;
    if (t_update() != 0) goto out;
    if (t_short_trace() != 0) goto out;
    if (t_replace_dead_primary() != 0) goto out;
    if (t_backwards() != 0) goto out;
    if (t_backwards_target_mismatch() != 0) goto out;
    if (t_prune() != 0) goto out;
    if (t_from_trusted_store() != 0) goto out;
    if (t_ensure_valid() != 0) goto out;
    if (t_init_agreement() != 0) goto out;
    if (t_caps() != 0) goto out;
    if (t_options() != 0) goto out;

    printf("test_cmt_light_client: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(F);
    cmt_light_block_buf_free(g_out);
    free(g_scratch);
    return rc;
}
