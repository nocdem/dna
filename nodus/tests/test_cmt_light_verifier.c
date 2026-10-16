/**
 * Nodus — cometbft @v0.38.26 C port: `light/verifier.go`, the
 * `VerifyCommitLightTrusting` family of `types/validation.go` and
 * `types.SignedHeader.ValidateBasic` (types/light.go). Ported 2026-10-16
 * for the bandwidth / storage light clients; no node path calls them yet.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * With REAL ML-DSA-87 signatures over the bytes `Commit.VoteSignBytes`
 * produces and real header / validator-set hashes, that:
 *   · VerifyAdjacent accepts a correctly signed next header and refuses,
 *     with the reference's error CLASS: a non-adjacent height (unnamed),
 *     a foreign chain id / an earlier time / a time beyond now+drift / a
 *     ValidatorsHash that does not match the supplied set
 *     (ErrInvalidHeader), a ValidatorsHash that does not match the trusted
 *     NextValidatorsHash (unnamed — NOT ErrInvalidHeader), too little
 *     voting power (ErrInvalidHeader{ErrNotEnoughVotingPowerSigned{50,
 *     93}}) and an expired trusted header (ErrOldHeaderExpired, at the
 *     exact boundary expiry == now);
 *   · the future-time bound is STRICT and inclusive of now+drift-1ms;
 *   · VerifyNonAdjacent accepts when >= 1/3 of the trusted set and > 2/3
 *     of the new set signed, refuses too little new-set power as
 *     ErrInvalidHeader{50, 93} and too little trusted-set power as
 *     ErrNewValSetCantBeTrusted{20, 46};
 *   · Verify picks the non-adjacent path for equal heights;
 *   · ValidateTrustLevel accepts exactly [1/3, 1];
 *   · VerifyCommitLightTrusting exits early (a bad signature after the
 *     trust level is reached is not seen) and the AllSignatures form does
 *     not; a set with no overlap is refused ({0, 0} — `got <= needed`); a
 *     set that overlaps by more than 1/3 passes; `total * numerator`
 *     overflow is refused; a zero denominator is refused;
 *   · the ValidatorSet method forms answer identically;
 *   · SignedHeader.ValidateBasic refuses a missing header / commit, a
 *     height mismatch and a commit for another block, and VerifyBackwards
 *     accepts a real parent and refuses the three mismatches.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, NO CLOCK — every `now` is a fixed value. Keys come
 * from `qgp_dsa87_keypair_derand` with fixed seeds; the test draws no
 * randomness of its own. Safe under `ctest -j`. Every large fixture
 * (headers with their signatures, validator sets, the >1 MB set-change
 * scratch) is heap-allocated and freed in main.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. ML-DSA-87 signing is HEDGED, so no signature is frozen or compared;
 *     every real-key assertion is on a VERIFY OUTCOME.
 *  2. There is no frozen vector for the header hash, the set hash or the
 *     sign bytes here; this file trusts cmt_header_hash,
 *     cmt_validator_set_hash and cmt_commit_vote_sign_bytes, which their
 *     own tests pin. A self-consistent error in them would still pass
 *     here. This file proves the VERIFICATION LOGIC.
 *  3. The reference asserts most rejections by ERROR TEXT
 *     (`assert.Contains(err.Error(), ...)`). This port carries no text, so
 *     those rows assert CMT_REJECT plus the error CLASS the reference's
 *     code wraps them in (verifier.go:54, :113, :117-122). If two
 *     different checks of the same class were swapped, these rows would
 *     not notice; the rows are built so that only one check can fail.
 *  4. Reference fixtures that this port cannot express are ADAPTED, and
 *     each adaptation is named at its site: chain ids are bounded to 32
 *     bytes here (CMT_PB_CHAINID_MAX), tmhash is 64 bytes (so the
 *     PartSetHeader hash that the reference fills with 32 random bytes is
 *     a fixed 64-byte pattern), and vote timestamps that the reference
 *     takes from `cmttime.Now()` are a fixed constant.
 *  5. `TestVerifyReturnsErrorIfTrustLevelIsInvalid` (verifier_test.go:288-
 *     306) does NOT reach a trust-level check: `Verify` never calls
 *     `ValidateTrustLevel`. With the same header as both trusted and
 *     untrusted it fails on the height check (verifier.go:164), or — with
 *     the reference's `time.Now()` — on expiry. The port pins the height
 *     path with a fixed `now`; the name of the reference test is
 *     misleading and the row says so.
 *  6. VerifyCommitLightTrusting's MinInt64 / -1 division guard is
 *     unreachable through safeMul and is NOT exercised.
 *
 * ── REFERENCE CASES PORTED ─────────────────────────────────────────────
 * light/verifier_test.go: TestVerifyAdjacentHeaders #0-#10 (:19-170),
 * TestVerifyNonAdjacentHeaders #0-#5 (:172-286),
 * TestVerifyReturnsErrorIfTrustLevelIsInvalid (:288-306, see 5 above),
 * TestValidateTrustLevel #0-#8 (:308-335).
 * types/validation_test.go:
 * TestValidatorSet_VerifyCommitLightTrusting_ReturnsAsSoonAsTrustLevel-
 * SignedIffNotAllSigs (:216-253), TestValidatorSet_VerifyCommitLight-
 * Trusting #0-#2 (:255-295), TestValidatorSet_VerifyCommitLightTrusting-
 * ErrorsOnOverflow (:297-310).
 * PROJECT-AUTHORED (the reference ships none for them): the zero-
 * denominator and NULL rows of the Trusting family, the method-form
 * equivalence, and VerifyBackwards.
 * SignedHeader.ValidateBasic: the reference DOES ship a test for it —
 * types/light_test.go:113-166 TestSignedHeaderValidateBasic, three cases
 * (a valid signed header, a nil header, a nil commit). The first three
 * rows here are those three cases over this file's own fixture (the
 * reference's MaxInt64 timestamp / 4-byte chain id are not used); the
 * wrong block protocol, the height mismatch and the commit for another
 * block are PROJECT-AUTHORED.
 *
 * @file test_cmt_light_verifier.c
 */

#include "dnac/cmt_light_verifier.h"
#include "dnac/cmt_validation.h"
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

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Eight keys: the light tests use four (genPrivKeys(4)), the Trusting
 * tests six plus two (randVoteSet(…, 6, …) and RandValidatorSet(2, …)). */
#define NKEYS 8

#define SECOND      ((int64_t)1000000000)
#define MILLISECOND ((int64_t)1000000)
#define HOUR        (3600 * SECOND)

/* verifier_test.go:16 — `maxClockDrift = 10 * time.Second`. */
#define MAX_CLOCK_DRIFT (10 * SECOND)

/* verifier_test.go:30 — `time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")`
 * = 1136214245 Unix seconds (`date -u -d 2006-01-02T15:04:05Z +%s`). */
#define BTIME_SECONDS ((int64_t)1136214245)

/* The vote stamp the reference takes from `cmttime.Now()`
 * (helpers_test.go:111). It is inside no checked relation, so any fixed
 * value does; this file reads no clock. */
#define VOTE_SECONDS ((int64_t)1700000000)

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_addr[NKEYS][CMT_ADDRESS_SIZE];

static cmt_valset_scratch_t *g_scratch;

/* A validator set with its own storage. */
typedef struct {
    cmt_validator_t     storage[NKEYS];
    cmt_validator_set_t vs;
} tvals_t;

/* A SignedHeader with the header, commit and signatures it points at. */
typedef struct {
    cmt_header_t        h;
    cmt_commit_sig_t    sigs[NKEYS];
    cmt_commit_t        c;
    cmt_signed_header_t sh;
} tsh_t;

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
        memset(seed, (uint8_t)(0x31 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0 ||
            cmt_pubkey_address(g_pk[i], g_addr[i]) != CMT_OK) {
            fprintf(stderr, "key %d failed\n", i);
            return 1;
        }
    }
    return 0;
}

/* The key whose address this is, or -1. */
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

/* helpers_test.go:67-73 `ToValidators(init, inc)`: key keys[i] gets power
 * init + i*inc, then NewValidatorSet sorts the set by power DESC. */
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

/* Sign commit entry `idx` (a COMMIT entry for validator `vs[idx]`) over
 * `Commit.VoteSignBytes(chain, idx)` with the key of that validator. */
static int sign_entry(cmt_commit_t *c, cmt_validator_set_t *vs, size_t idx,
                      const char *chain)
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
        cmt_commit_vote_sign_bytes(c, (const uint8_t *)chain, strlen(chain),
                                   (int32_t)idx, sb, sizeof(sb),
                                   &sb_len) != CMT_OK ||
        qgp_dsa87_sign(cs->signature, &siglen, sb, sb_len, g_sk[k]) != 0) {
        fprintf(stderr, "sign entry %zu failed\n", idx);
        return 1;
    }
    cs->signature_len = siglen;
    return 0;
}

/* helpers_test.go:135-177 — genHeader + signHeader + GenSignedHeader.
 * `keys[0..nkeys)` is the reference's `pkz`; the commit has one entry per
 * key (:77), all ABSENT (:78-80) except the votes of keys[first..last)
 * (:88-91), each placed at its signer's index in `valset` (:105, :90). */
static int gen_signed_header(tsh_t *out, const char *chain, int64_t height,
                             cmt_time_t btime, tvals_t *valset,
                             tvals_t *next_valset, const int *keys,
                             size_t nkeys, size_t first, size_t last)
{
    cmt_header_t *h = &out->h;
    size_t        i;
    int           rc;

    if (strlen(chain) > (size_t)CMT_PB_CHAINID_MAX || nkeys > NKEYS) {
        return 1;
    }

    /* genHeader (:135-153). */
    cmt_pb_header_init(h);
    h->version.block = CMT_BLOCK_PROTOCOL;                       /* :139 */
    h->version.app   = 0;
    memcpy(h->chain_id, chain, strlen(chain));                   /* :140 */
    h->chain_id_len  = strlen(chain);
    h->height        = height;                                   /* :141 */
    h->time          = btime;                                    /* :142 */
    /* :143-144 LastBlockID and LastCommitHash stay zero. */
    if (vals_hash(&valset->vs, h->validators_hash) != 0 ||       /* :145 */
        vals_hash(&next_valset->vs, h->next_validators_hash) != 0 ||
        cmt_data_hash(NULL, h->data_hash) != CMT_OK ||           /* :147 */
        cmt_tmhash_sum((const uint8_t *)"app_hash", 8,
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

    /* signHeader (:76-99). */
    cmt_pb_commit_init(&out->c);
    out->c.height         = height;                              /* :94 */
    out->c.round          = 1;                                   /* :95 */
    out->c.signatures     = out->sigs;
    out->c.signatures_cap = NKEYS;
    out->c.signatures_len = nkeys;
    for (i = 0; i < nkeys; i++) {
        cmt_new_commit_sig_absent(&out->sigs[i]);                /* :79 */
    }
    /* :82-85 — BlockID{Hash: header.Hash(), PSH{Total 1, Hash 32 random
     * bytes}}. ADAPTED: tmhash is 64 bytes here, so the PSH hash must be
     * 64 bytes to pass ValidateHash, and it is a fixed pattern. */
    rc = cmt_header_hash(h, out->c.block_id.hash);
    if (rc != CMT_OK) {
        return 1;
    }
    out->c.block_id.hash_len                 = CMT_TMHASH_SIZE;
    out->c.block_id.part_set_header.total    = 1u;
    pat(out->c.block_id.part_set_header.hash, CMT_TMHASH_SIZE, 0x5C);
    out->c.block_id.part_set_header.hash_len = CMT_TMHASH_SIZE;

    for (i = first; i < last && i < nkeys; i++) {                /* :88 */
        int32_t idx = -1;

        if (cmt_validator_set_get_by_address(&valset->vs, g_addr[keys[i]],
                                             CMT_ADDRESS_SIZE, &idx,
                                             NULL) != CMT_OK ||
            idx < 0 || (size_t)idx >= nkeys) {
            return 1;
        }
        if (sign_entry(&out->c, &valset->vs, (size_t)idx, chain) != 0) {
            return 1;
        }
    }

    out->sh.header = &out->h;
    out->sh.commit = &out->c;
    return 0;
}

/* A commit at (height, round) in which EVERY member of `vs` signed for a
 * fixed BlockID — the shape of types/validation_test.go's
 * `randVoteSet` + `MakeExtCommit(...).ToCommit()`. */
static int make_full_commit(tsh_t *out, cmt_validator_set_t *vs,
                            int64_t height, int32_t round, const char *chain)
{
    size_t i;

    cmt_pb_commit_init(&out->c);
    out->c.height = height;
    out->c.round  = round;
    /* `makeBlockIDRandom()` — a fixed pattern here. */
    pat(out->c.block_id.hash, CMT_TMHASH_SIZE, 0x21);
    out->c.block_id.hash_len                 = CMT_TMHASH_SIZE;
    out->c.block_id.part_set_header.total    = 1000u;
    pat(out->c.block_id.part_set_header.hash, CMT_TMHASH_SIZE, 0x22);
    out->c.block_id.part_set_header.hash_len = CMT_TMHASH_SIZE;
    out->c.signatures     = out->sigs;
    out->c.signatures_cap = NKEYS;
    out->c.signatures_len = vs->validators_len;
    for (i = 0; i < vs->validators_len; i++) {
        if (sign_entry(&out->c, vs, i, chain) != 0) {
            return 1;
        }
    }
    return 0;
}

static const int K4[4] = { 0, 1, 2, 3 };

/* ══ 1. TestVerifyAdjacentHeaders (verifier_test.go:19-170) ═══════════ */

static int t_adjacent(void)
{
    static const char *chain = "TestVerifyAdjacentHeaders";
    tvals_t           *vals  = calloc(1, sizeof(*vals));
    tvals_t           *vals2 = calloc(1, sizeof(*vals2));   /* ToValidators(10, 1) */
    tsh_t             *trusted = calloc(1, sizeof(*trusted));
    tsh_t             *nh = calloc(1, sizeof(*nh));
    cmt_light_error_t  err;
    int                ret = 1;

    if (vals == NULL || vals2 == NULL || trusted == NULL || nh == NULL) {
        goto out;
    }
    /* :27-32 — 20, 30, 40, 50; the header at height 1 signed by all. */
    if (make_vals(vals, K4, 4, 20, 10) != 0 ||
        make_vals(vals2, K4, 4, 10, 1) != 0 ||
        gen_signed_header(trusted, chain, 1, t_at(0), vals, vals, K4, 4,
                          0, 4) != 0) {
        goto out;
    }

#define ADJ(hdr, nv, period, now) \
    cmt_light_verify_adjacent(&trusted->sh, &(hdr)->sh, &(nv)->vs, (period), \
                              (now), MAX_CLOCK_DRIFT, CMT_BLOCK_PROTOCOL, &err)

    /* #0 (:44-51) same header -> "headers must be adjacent in height". */
    if (ADJ(trusted, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_NONE) {
        fprintf(stderr, "#0\n"); goto out;
    }
    OK();

    /* #1 (:53-61) different chainID -> "header belongs to another chain",
     * inside ErrInvalidHeader (verifier.go:54/:113). */
    if (gen_signed_header(nh, "different-chainID", 2, t_at(1 * HOUR), vals,
                          vals, K4, 4, 0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "#1\n"); goto out;
    }
    OK();

    /* #2 (:63-71) new header's time before the old one's. */
    if (gen_signed_header(nh, chain, 2, t_at(-1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "#2\n"); goto out;
    }
    OK();

    /* #3 (:73-81) a time from the future. */
    if (gen_signed_header(nh, chain, 2, t_at(3 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "#3\n"); goto out;
    }
    OK();

    /* #4 (:83-92) future, but now + maxClockDrift - 1ms -> accepted. */
    if (gen_signed_header(nh, chain, 2,
                          t_at(2 * HOUR + MAX_CLOCK_DRIFT - MILLISECOND),
                          vals, vals, K4, 4, 0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_OK ||
        err.code != CMT_LIGHT_ERR_NONE) {
        fprintf(stderr, "#4\n"); goto out;
    }
    OK();
    /* PROJECT-AUTHORED: exactly now + maxClockDrift is refused — the
     * bound is `Before`, strict (verifier.go:176). */
    if (gen_signed_header(nh, chain, 2, t_at(2 * HOUR + MAX_CLOCK_DRIFT),
                          vals, vals, K4, 4, 0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "#4b\n"); goto out;
    }
    OK();

    /* #5 (:94-102) 3/3 signed. */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_OK) {
        fprintf(stderr, "#5\n"); goto out;
    }
    OK();

    /* #6 (:104-112) keys[1..4) signed: 30+40+50 = 120 > 93. */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          1, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_OK) {
        fprintf(stderr, "#6\n"); goto out;
    }
    OK();

    /* #7 (:114-122) only keys[3] (50) signed ->
     * ErrInvalidHeader{ErrNotEnoughVotingPowerSigned{Got: 50, Needed: 93}}. */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          3, 4) != 0 ||
        ADJ(nh, vals, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER ||
        err.reason.code != CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED ||
        err.reason.got != 50 || err.reason.needed != 93) {
        fprintf(stderr, "#7\n"); goto out;
    }
    OK();

    /* #8 (:124-132) the new header's set does not match the trusted
     * NextValidatorsHash -> the UNNAMED error of verifier.go:117-122. */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals2, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals2, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_NONE) {
        fprintf(stderr, "#8\n"); goto out;
    }
    OK();

    /* #9 (:134-142) supplied set inconsistent with the new header. */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals2, 3 * HOUR, t_at(2 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "#9\n"); goto out;
    }
    OK();

    /* #10 (:144-152) trusting period 1h, now = bTime + 1h -> expired at
     * the exact boundary (`!expirationTime.After(now)`, :209). */
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        ADJ(nh, vals2, 1 * HOUR, t_at(1 * HOUR)) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_OLD_HEADER_EXPIRED ||
        err.at.seconds != t_at(1 * HOUR).seconds ||
        err.now.seconds != t_at(1 * HOUR).seconds) {
        fprintf(stderr, "#10\n"); goto out;
    }
    OK();
#undef ADJ

    ret = 0;
out:
    free(vals);
    free(vals2);
    free(trusted);
    free(nh);
    CHECK(ret == 0, "TestVerifyAdjacentHeaders rows");
    return 0;
}

/* ══ 2. TestVerifyNonAdjacentHeaders (verifier_test.go:172-286) ═══════ */

static int t_non_adjacent(void)
{
    static const char *chain = "TestVerifyNonAdjacentHeaders";
    static const int   two_thirds[3]  = { 1, 2, 3 };   /* keys[1:]          */
    static const int   one_third[1]   = { 3 };         /* keys[len-1:]      */
    static const int   less_third[1]  = { 0 };         /* keys[0:1]         */
    tvals_t           *vals    = calloc(1, sizeof(*vals));
    tvals_t           *tt_vals = calloc(1, sizeof(*tt_vals));
    tvals_t           *ot_vals = calloc(1, sizeof(*ot_vals));
    tvals_t           *lt_vals = calloc(1, sizeof(*lt_vals));
    tsh_t             *trusted = calloc(1, sizeof(*trusted));
    tsh_t             *nh = calloc(1, sizeof(*nh));
    cmt_light_error_t  err;
    cmt_fraction_t     dtl = CMT_LIGHT_DEFAULT_TRUST_LEVEL;
    int                ret = 1;

    if (vals == NULL || tt_vals == NULL || ot_vals == NULL ||
        lt_vals == NULL || trusted == NULL || nh == NULL) {
        goto out;
    }
    if (make_vals(vals, K4, 4, 20, 10) != 0 ||               /* :181 */
        make_vals(tt_vals, two_thirds, 3, 30, 10) != 0 ||    /* :188 */
        make_vals(ot_vals, one_third, 1, 50, 10) != 0 ||     /* :192 */
        make_vals(lt_vals, less_third, 1, 20, 10) != 0 ||    /* :196 */
        gen_signed_header(trusted, chain, 1, t_at(0), vals, vals, K4, 4,
                          0, 4) != 0) {
        goto out;
    }
    CHECK(dtl.numerator == 1u && dtl.denominator == 3u,
          "DefaultTrustLevel is 1/3 (verifier.go:16)"); OK();

#define NONADJ(hdr, nv) \
    cmt_light_verify_non_adjacent(&trusted->sh, &vals->vs, &(hdr)->sh, \
                                  &(nv)->vs, 3 * HOUR, t_at(2 * HOUR), \
                                  MAX_CLOCK_DRIFT, dtl, CMT_BLOCK_PROTOCOL, \
                                  &err)

    /* #0 (:208-216) 3/3 new, 3/3 old. */
    if (gen_signed_header(nh, chain, 3, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        NONADJ(nh, vals) != CMT_OK) {
        fprintf(stderr, "#0\n"); goto out;
    }
    OK();

    /* #1 (:218-226) 2/3 new, 3/3 old. */
    if (gen_signed_header(nh, chain, 4, t_at(1 * HOUR), vals, vals, K4, 4,
                          1, 4) != 0 ||
        NONADJ(nh, vals) != CMT_OK) {
        fprintf(stderr, "#1\n"); goto out;
    }
    OK();

    /* #2 (:228-236) 1/3 new -> ErrInvalidHeader{{50, 93}}. The trusting
     * step passes first: 50 > 140/3 = 46. */
    if (gen_signed_header(nh, chain, 5, t_at(1 * HOUR), vals, vals, K4, 4,
                          3, 4) != 0 ||
        NONADJ(nh, vals) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER ||
        err.reason.code != CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED ||
        err.reason.got != 50 || err.reason.needed != 93) {
        fprintf(stderr, "#2\n"); goto out;
    }
    OK();

    /* #3 (:238-246) 3/3 new (30, 40, 50), 2/3 of the old present. */
    if (gen_signed_header(nh, chain, 5, t_at(1 * HOUR), tt_vals, tt_vals,
                          two_thirds, 3, 0, 3) != 0 ||
        NONADJ(nh, tt_vals) != CMT_OK) {
        fprintf(stderr, "#3\n"); goto out;
    }
    OK();

    /* #4 (:248-256) 3/3 new (50), 1/3 of the old present: 50 > 46. */
    if (gen_signed_header(nh, chain, 5, t_at(1 * HOUR), ot_vals, ot_vals,
                          one_third, 1, 0, 1) != 0 ||
        NONADJ(nh, ot_vals) != CMT_OK) {
        fprintf(stderr, "#4\n"); goto out;
    }
    OK();

    /* #5 (:258-266) 3/3 new (20), less than 1/3 of the old ->
     * ErrNewValSetCantBeTrusted{{Got: 20, Needed: 46}}. */
    if (gen_signed_header(nh, chain, 5, t_at(1 * HOUR), lt_vals, lt_vals,
                          less_third, 1, 0, 1) != 0 ||
        NONADJ(nh, lt_vals) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_NEW_VAL_SET_CANT_BE_TRUSTED ||
        err.reason.code != CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED ||
        err.reason.got != 20 || err.reason.needed != 46) {
        fprintf(stderr, "#5\n"); goto out;
    }
    OK();

    /* PROJECT-AUTHORED: Verify (verifier.go:145-150) dispatches #0's
     * non-adjacent header to the same answer, and an adjacent one to
     * VerifyAdjacent. */
    if (gen_signed_header(nh, chain, 3, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0 ||
        cmt_light_verify(&trusted->sh, &vals->vs, &nh->sh, &vals->vs,
                         3 * HOUR, t_at(2 * HOUR), MAX_CLOCK_DRIFT, dtl,
                         CMT_BLOCK_PROTOCOL, &err) != CMT_OK) {
        fprintf(stderr, "verify non-adjacent\n"); goto out;
    }
    OK();
    if (gen_signed_header(nh, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          3, 4) != 0 ||
        cmt_light_verify(&trusted->sh, &vals->vs, &nh->sh, &vals->vs,
                         3 * HOUR, t_at(2 * HOUR), MAX_CLOCK_DRIFT, dtl,
                         CMT_BLOCK_PROTOCOL, &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER ||
        err.reason.got != 50 || err.reason.needed != 93) {
        fprintf(stderr, "verify adjacent\n"); goto out;
    }
    OK();
    /* NonAdjacent refuses an adjacent height (verifier.go:42-44). */
    if (NONADJ(nh, vals) != CMT_REJECT || err.code != CMT_LIGHT_ERR_NONE) {
        fprintf(stderr, "non-adjacent refuses adjacent\n"); goto out;
    }
    OK();
#undef NONADJ

    ret = 0;
out:
    free(vals);
    free(tt_vals);
    free(ot_vals);
    free(lt_vals);
    free(trusted);
    free(nh);
    CHECK(ret == 0, "TestVerifyNonAdjacentHeaders rows");
    return 0;
}

/* ══ 3. TestVerifyReturnsErrorIfTrustLevelIsInvalid (:288-306) ════════ */

static int t_trust_level_invalid_verify(void)
{
    /* ADAPTED: the reference chain id
     * "TestVerifyReturnsErrorIfTrustLevelIsInvalid" is 44 bytes, over
     * this port's 32-byte bound (CMT_PB_CHAINID_MAX). */
    static const char *chain = "TestVerifyRetErrIfTrustLvlInvld";
    tvals_t           *vals   = calloc(1, sizeof(*vals));
    tsh_t             *header = calloc(1, sizeof(*header));
    cmt_light_error_t  err;
    cmt_fraction_t     bad = { 2u, 1u };
    int                rc  = CMT_FAULT;

    if (vals != NULL && header != NULL &&
        make_vals(vals, K4, 4, 20, 10) == 0 &&
        gen_signed_header(header, chain, 1, t_at(0), vals, vals, K4, 4,
                          0, 4) == 0) {
        /* :303-304 with a FIXED now (bTime + 1h) instead of time.Now():
         * equal heights take the non-adjacent path, the header has not
         * expired (2h period), and verifyNewHeaderAndVals refuses
         * `untrusted height <= trusted height` (verifier.go:164) — Verify
         * never calls ValidateTrustLevel, see "HOW IT CAN LIE" 5. */
        rc = cmt_light_verify(&header->sh, &vals->vs, &header->sh,
                              &vals->vs, 2 * HOUR, t_at(1 * HOUR),
                              MAX_CLOCK_DRIFT, bad, CMT_BLOCK_PROTOCOL,
                              &err);
    }
    free(vals);
    free(header);
    CHECK(rc == CMT_REJECT, "Verify with trust level 2/1 returns an error");
    OK();
    CHECK(err.code == CMT_LIGHT_ERR_INVALID_HEADER,
          "and the error is the height check's ErrInvalidHeader, not a "
          "trust-level error"); OK();
    CHECK(cmt_light_validate_trust_level(bad) == CMT_REJECT,
          "the trust level itself is refused only by ValidateTrustLevel");
    OK();
    return 0;
}

/* ══ 4. TestValidateTrustLevel (verifier_test.go:308-335) ═════════════ */

static int t_validate_trust_level(void)
{
    static const struct {
        uint64_t n, d;
        int      valid;
    } tc[] = {
        { 1, 1, 1 }, { 1, 3, 1 }, { 2, 3, 1 }, { 3, 3, 1 }, { 4, 5, 1 },  /* :314-318 */
        { 6, 5, 0 }, { 0, 1, 0 }, { 0, 0, 0 }, { 1, 0, 0 },               /* :321-324 */
    };
    size_t i;

    for (i = 0; i < sizeof(tc) / sizeof(tc[0]); i++) {
        cmt_fraction_t lvl;

        lvl.numerator   = tc[i].n;
        lvl.denominator = tc[i].d;
        CHECK((cmt_light_validate_trust_level(lvl) == CMT_OK) ==
              (tc[i].valid != 0), "ValidateTrustLevel row"); OK();
    }
    return 0;
}

/* ══ 5. the Trusting family (types/validation_test.go:216-310) ════════ */

static int t_trusting_early_exit(void)
{
    /* :216-253 — randVoteSet(h=3, round 0, precommit, 4 validators of
     * power 10); the full commit; then entry 2 re-signed for another
     * chain ("CentaurusA"). */
    static const char *chain = "test_chain_id";
    tvals_t           *vals = calloc(1, sizeof(*vals));
    tsh_t             *fx   = calloc(1, sizeof(*fx));
    cmt_fraction_t     third = { 1u, 3u };
    cmt_vs_error_t     err;
    int                ret = 1;

    if (vals == NULL || fx == NULL ||
        make_vals(vals, K4, 4, 10, 0) != 0 ||
        make_full_commit(fx, &vals->vs, 3, 0, chain) != 0) {
        goto out;
    }
    /* :227 require VerifyCommit OK. */
    if (cmt_verify_commit((const uint8_t *)chain, strlen(chain), &vals->vs,
                          &fx->c.block_id, 3, &fx->c, NULL) != CMT_OK) {
        fprintf(stderr, "VerifyCommit\n"); goto out;
    }
    OK();
    /* :229-234 */
    if (cmt_validator_set_verify_commit_light_trusting_all_signatures(
            &vals->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_OK) {
        fprintf(stderr, "all sigs, clean\n"); goto out;
    }
    OK();
    /* :236-243 — malleate entry 2. */
    if (sign_entry(&fx->c, &vals->vs, 2, "CentaurusA") != 0) {
        goto out;
    }
    /* :245-246 — 40 * 1/3 = 13; entries 0 and 1 make 20 > 13 before
     * entry 2 is looked at. */
    if (cmt_validator_set_verify_commit_light_trusting(
            &vals->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_OK) {
        fprintf(stderr, "early exit\n"); goto out;
    }
    OK();
    /* :247-252 — counting all signatures finds it. */
    if (cmt_validator_set_verify_commit_light_trusting_all_signatures(
            &vals->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_REJECT ||
        err.code != CMT_VS_ERR_NONE) {
        fprintf(stderr, "all sigs, malleated\n"); goto out;
    }
    OK();
    /* PROJECT-AUTHORED: the free functions answer as the methods do. */
    if (cmt_verify_commit_light_trusting((const uint8_t *)chain,
                                         strlen(chain), &vals->vs, &fx->c,
                                         third, NULL) != CMT_OK ||
        cmt_verify_commit_light_trusting_all_signatures(
            (const uint8_t *)chain, strlen(chain), &vals->vs, &fx->c, third,
            NULL) != CMT_REJECT) {
        fprintf(stderr, "free functions\n"); goto out;
    }
    OK();
    ret = 0;
out:
    free(vals);
    free(fx);
    CHECK(ret == 0, "VerifyCommitLightTrusting early exit rows");
    return 0;
}

static int t_trusting_overlap(void)
{
    /* :255-295 — randVoteSet(1, 1, precommit, 6 validators of power 1);
     * newValSet = RandValidatorSet(2, 1). */
    static const char *chain = "test_chain_id";
    static const int   orig_keys[6] = { 0, 1, 2, 3, 4, 5 };
    static const int   new_keys[2]  = { 6, 7 };
    static const int   mixed_keys[8] = { 6, 7, 0, 1, 2, 3, 4, 5 };
    tvals_t           *orig  = calloc(1, sizeof(*orig));
    tvals_t           *fresh = calloc(1, sizeof(*fresh));
    tvals_t           *mixed = calloc(1, sizeof(*mixed));
    tsh_t             *fx    = calloc(1, sizeof(*fx));
    cmt_fraction_t     third = { 1u, 3u };
    cmt_vs_error_t     err;
    int                ret = 1;

    if (orig == NULL || fresh == NULL || mixed == NULL || fx == NULL ||
        make_vals(orig, orig_keys, 6, 1, 0) != 0 ||
        make_vals(fresh, new_keys, 2, 1, 0) != 0 ||
        /* :97 NewValidatorSet(append(newValSet.Validators,
         * originalValset.Validators...)) */
        make_vals(mixed, mixed_keys, 8, 1, 0) != 0 ||
        make_full_commit(fx, &orig->vs, 1, 1, chain) != 0) {
        goto out;
    }
    /* #0 (:86-89) good. */
    if (cmt_validator_set_verify_commit_light_trusting(
            &orig->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_OK) {
        fprintf(stderr, "#0\n"); goto out;
    }
    OK();
    /* #1 (:90-94) no overlap: every signer is unknown and skipped
     * (validation.go:371-373); total 2 * 1/3 = 0, and got 0 <= 0. */
    if (cmt_validator_set_verify_commit_light_trusting(
            &fresh->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_REJECT ||
        err.code != CMT_VS_ERR_NOT_ENOUGH_VOTING_POWER_SIGNED ||
        err.got != 0 || err.needed != 0) {
        fprintf(stderr, "#1\n"); goto out;
    }
    OK();
    /* #2 (:95-99) 6 of 8 overlap: needed 8/3 = 2, got > 2. */
    if (cmt_validator_set_verify_commit_light_trusting(
            &mixed->vs, (const uint8_t *)chain, strlen(chain), &fx->c, third,
            &err) != CMT_OK) {
        fprintf(stderr, "#2\n"); goto out;
    }
    OK();

    /* PROJECT-AUTHORED: :162-164 a zero Denominator is refused, before
     * anything is counted; :159-161 / :165-167 nil set / commit are
     * CMT_FAULT (R1B-10). */
    {
        cmt_fraction_t zero_den = { 1u, 0u };

        if (cmt_verify_commit_light_trusting((const uint8_t *)chain,
                                             strlen(chain), &orig->vs,
                                             &fx->c, zero_den,
                                             &err) != CMT_REJECT ||
            err.code != CMT_VS_ERR_NONE) {
            fprintf(stderr, "zero denominator\n"); goto out;
        }
        OK();
        if (cmt_verify_commit_light_trusting((const uint8_t *)chain,
                                             strlen(chain), NULL, &fx->c,
                                             third, NULL) != CMT_FAULT ||
            cmt_verify_commit_light_trusting((const uint8_t *)chain,
                                             strlen(chain), &orig->vs,
                                             NULL, third,
                                             NULL) != CMT_FAULT) {
            fprintf(stderr, "NULL\n"); goto out;
        }
        OK();
    }
    ret = 0;
out:
    free(orig);
    free(fresh);
    free(mixed);
    free(fx);
    CHECK(ret == 0, "VerifyCommitLightTrusting overlap rows");
    return 0;
}

static int t_trusting_overflow(void)
{
    /* :297-310 — one validator of power MaxTotalVotingPower, trust level
     * 25/55: `total * 25` overflows int64 -> "int64 overflow". */
    static const char *chain = "test_chain_id";
    static const int   one_key[1] = { 0 };
    tvals_t           *vals = calloc(1, sizeof(*vals));
    tsh_t             *fx   = calloc(1, sizeof(*fx));
    cmt_fraction_t     lvl  = { 25u, 55u };
    cmt_vs_error_t     err;
    int                rc   = CMT_FAULT;

    if (vals != NULL && fx != NULL &&
        make_vals(vals, one_key, 1, (int64_t)CMT_MAX_TOTAL_VOTING_POWER,
                  0) == 0 &&
        make_full_commit(fx, &vals->vs, 1, 1, chain) == 0) {
        rc = cmt_validator_set_verify_commit_light_trusting(
                &vals->vs, (const uint8_t *)chain, strlen(chain), &fx->c,
                lvl, &err);
    }
    free(vals);
    free(fx);
    CHECK(rc == CMT_REJECT,
          "the voting-power overflow is an error (REJECT), not a fault");
    OK();
    CHECK(err.code == CMT_VS_ERR_NONE,
          "and not an ErrNotEnoughVotingPowerSigned"); OK();
    return 0;
}

/* ══ 6. SignedHeader.ValidateBasic and VerifyBackwards (project-authored) */

static int t_signed_header_and_backwards(void)
{
    static const char *chain = "TestSignedHeader";
    tvals_t           *vals   = calloc(1, sizeof(*vals));
    tsh_t             *h1     = calloc(1, sizeof(*h1));
    tsh_t             *h2     = calloc(1, sizeof(*h2));
    cmt_signed_header_t sh;
    cmt_light_error_t   err;
    bool                expired;
    int                 ret = 1;

    if (vals == NULL || h1 == NULL || h2 == NULL ||
        make_vals(vals, K4, 4, 20, 10) != 0 ||
        gen_signed_header(h1, chain, 1, t_at(0), vals, vals, K4, 4,
                          0, 4) != 0 ||
        gen_signed_header(h2, chain, 2, t_at(1 * HOUR), vals, vals, K4, 4,
                          0, 4) != 0) {
        goto out;
    }
    /* light.go:134-162. */
    if (cmt_signed_header_validate_basic(&h1->sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL) != CMT_OK) {
        fprintf(stderr, "valid signed header\n"); goto out;
    }
    OK();
    sh.header = NULL;
    sh.commit = &h1->c;
    if (cmt_signed_header_validate_basic(&sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL) != CMT_REJECT) {
        fprintf(stderr, "missing header\n"); goto out;   /* :135-137 */
    }
    OK();
    sh.header = &h1->h;
    sh.commit = NULL;
    if (cmt_signed_header_validate_basic(&sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL) != CMT_REJECT) {
        fprintf(stderr, "missing commit\n"); goto out;   /* :138-140 */
    }
    OK();
    if (cmt_signed_header_validate_basic(&h1->sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL + 1u) !=
        CMT_REJECT) {
        fprintf(stderr, "block protocol\n"); goto out;   /* :142-144 */
    }
    OK();
    sh.header = &h1->h;                                  /* :154-156 */
    sh.commit = &h2->c;
    if (cmt_signed_header_validate_basic(&sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL) != CMT_REJECT) {
        fprintf(stderr, "height mismatch\n"); goto out;
    }
    OK();
    h1->c.block_id.hash[0] ^= 0x01u;                     /* :157-159 */
    if (cmt_signed_header_validate_basic(&h1->sh, (const uint8_t *)chain,
                                         strlen(chain),
                                         CMT_BLOCK_PROTOCOL) != CMT_REJECT) {
        fprintf(stderr, "commit for another block\n"); goto out;
    }
    OK();
    h1->c.block_id.hash[0] ^= 0x01u;

    /* HeaderExpired (verifier.go:206-210) on both sides of the boundary. */
    if (cmt_light_header_expired(&h1->sh, 1 * HOUR,
                                 t_at(1 * HOUR - 1), &expired) != CMT_OK ||
        expired) {
        fprintf(stderr, "not yet expired\n"); goto out;
    }
    OK();
    if (cmt_light_header_expired(&h1->sh, 1 * HOUR, t_at(1 * HOUR),
                                 &expired) != CMT_OK || !expired) {
        fprintf(stderr, "expired at equality\n"); goto out;
    }
    OK();

    /* VerifyBackwards (verifier.go:212-245): h1 is h2's parent once h2's
     * LastBlockID hash is h1's hash. */
    if (cmt_header_hash(&h1->h, h2->h.last_block_id.hash) != CMT_OK) {
        goto out;
    }
    h2->h.last_block_id.hash_len = CMT_TMHASH_SIZE;
    if (cmt_light_verify_backwards(&h1->h, &h2->h, CMT_BLOCK_PROTOCOL,
                                   &err) != CMT_OK ||
        err.code != CMT_LIGHT_ERR_NONE) {
        fprintf(stderr, "backwards ok\n"); goto out;
    }
    OK();
    /* :230-235 — not strictly earlier (swap the roles). */
    if (cmt_light_verify_backwards(&h2->h, &h2->h, CMT_BLOCK_PROTOCOL,
                                   &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "backwards time\n"); goto out;
    }
    OK();
    /* :237-242 — hash mismatch. */
    h2->h.last_block_id.hash[0] ^= 0x01u;
    if (cmt_light_verify_backwards(&h1->h, &h2->h, CMT_BLOCK_PROTOCOL,
                                   &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "backwards hash\n"); goto out;
    }
    OK();
    h2->h.last_block_id.hash[0] ^= 0x01u;
    /* :226-228 — another chain. */
    h2->h.chain_id[0] ^= 0x01u;
    if (cmt_light_verify_backwards(&h1->h, &h2->h, CMT_BLOCK_PROTOCOL,
                                   &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_ERR_INVALID_HEADER) {
        fprintf(stderr, "backwards chain\n"); goto out;
    }
    OK();
    h2->h.chain_id[0] ^= 0x01u;
    /* Nil-dereference sites are FAULT. */
    if (cmt_light_verify_backwards(NULL, &h2->h, CMT_BLOCK_PROTOCOL,
                                   &err) != CMT_FAULT ||
        cmt_light_verify_adjacent(&h1->sh, NULL, &vals->vs, HOUR,
                                  t_at(0), MAX_CLOCK_DRIFT,
                                  CMT_BLOCK_PROTOCOL, &err) != CMT_FAULT) {
        fprintf(stderr, "NULL\n"); goto out;
    }
    OK();
    ret = 0;
out:
    free(vals);
    free(h1);
    free(h2);
    CHECK(ret == 0, "SignedHeader / VerifyBackwards rows");
    return 0;
}

int main(void)
{
    int rc = 1;

    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    if (g_scratch == NULL) {
        fprintf(stderr, "scratch allocation failed\n");
        return 1;
    }
    if (build_keys() != 0) goto out;
    if (t_adjacent() != 0) goto out;
    if (t_non_adjacent() != 0) goto out;
    if (t_trust_level_invalid_verify() != 0) goto out;
    if (t_validate_trust_level() != 0) goto out;
    if (t_trusting_early_exit() != 0) goto out;
    if (t_trusting_overlap() != 0) goto out;
    if (t_trusting_overflow() != 0) goto out;
    if (t_signed_header_and_backwards() != 0) goto out;

    printf("test_cmt_light_verifier: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(g_scratch);
    return rc;
}
