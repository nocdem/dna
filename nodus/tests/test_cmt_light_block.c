/**
 * Nodus — cometbft @v0.38.26 C port: `types.LightBlock` (types/light.go),
 * its SignedHeader / LightBlock proto3 codec (types.pb.go) and the
 * light/provider interface, through a port of the reference's mock
 * provider (light/provider/mock/mock.go). Light client package 1,
 * 2026-10-16 (Kurultay #25 item 1); no node path calls any of it yet.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · LightBlock.ValidateBasic accepts a consistent block and refuses a
 *     set whose hash is not the header's ValidatorsHash, a set whose
 *     proposer is not a member, and a signed header whose commit is for
 *     another block; a missing signed header / set is CMT_REJECT and a
 *     NULL light block CMT_FAULT;
 *   · the proto round trip (ToProto → Marshal → Unmarshal → FromProto →
 *     ToProto → Marshal) gives the SAME BYTES for a full light block, for
 *     one with an empty signed header and for the nil light block; an
 *     empty validator set and an empty light block encode but do not
 *     decode;
 *   · presence is on the wire as the generated encoder writes it: an
 *     empty SignedHeader is `0a 00`, an empty ValidatorSet `12 00`, the
 *     nil light block zero bytes (types.pb.go:2011-2041);
 *   · an unknown field is skipped, a truncated stream and a wrong wire
 *     type are refused;
 *   · the mock provider answers height 0 with the latest block, refuses a
 *     height above the latest (ErrHeightTooHigh), a missing height
 *     (ErrLightBlockNotFound) and an invalid block (ErrBadLightBlock), and
 *     records reported evidence.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, NO CLOCK — every time is a fixed value. Keys come
 * from `qgp_dsa87_keypair_derand` with fixed seeds; the test draws no
 * randomness of its own. Safe under `ctest -j`. Every large fixture
 * (light blocks with their signatures, validator sets, the >1 MB
 * set-change scratch, the decode buffers) is heap-allocated and freed.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. ML-DSA-87 signing is HEDGED, so no signature is frozen; and
 *     ValidateBasic never verifies one ("This does no verification of the
 *     signatures", light.go:20). The signatures only make the commits
 *     well formed.
 *  2. There is no frozen vector for the LightBlock bytes. The round trip
 *     compares the port's bytes with the port's bytes, so a SYMMETRIC
 *     error in the encoder and decoder would pass; the three literal
 *     presence rows (`0a 00`, `12 00`, empty) are the only bytes pinned
 *     to the reference's generated code, and the embedded Header /
 *     Commit / ValidatorSet bytes are trusted to cmt_pb's own tests.
 *  3. The reference asserts `assert.Equal(lightBlock, lb)` on the Go
 *     structs. This port has no deep struct equality; it compares the
 *     re-encoded bytes plus the presence of each member. A field the
 *     codec never writes would not be noticed.
 *  4. Reference fixtures that this port cannot express are ADAPTED, and
 *     each adaptation is named at its site: `randCommit` signs with 10
 *     random validators (block_test.go:438-447); here with this file's 8
 *     fixed keys. `cmtrand` heights, hashes and addresses are fixed
 *     patterns; tmhash is 64 bytes and an address 32.
 *  5. The mock's 10 ms `time.After` window and its mutex (mock.go:68-73,
 *     :18)
 *     are NOT ported (no clock, one thread); a context-cancellation path
 *     therefore does not exist and is not tested.
 *
 * ── REFERENCE CASES PORTED ─────────────────────────────────────────────
 * types/light_test.go: TestLightBlockValidateBasic #0-#3 (:15-58),
 * TestLightBlockProtobuf #0-#3 (:60-111).
 * light/provider/mock/mock.go: New / ChainID / LightBlock /
 * ReportEvidence / HasEvidence (:15-48, :64-113) as the test's own mock
 * — the reference ships no test of the mock itself.
 * PROJECT-AUTHORED: the NULL / missing-member rows, the literal presence
 * bytes, the unknown-field / truncated / wrong-wire-type rows and every
 * mock row.
 *
 * @file test_cmt_light_block.c
 */

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

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* light_test.go uses RandValidatorSet(5, 1) and RandValidatorSet(3, 1);
 * randCommit signs with its own set (ADAPTED to these 8 keys). */
#define NKEYS 8

/* A fixed time; the reference takes `time.Now()` (light_test.go:17). */
#define T_SECONDS    ((int64_t)1700000000)
#define VOTE_SECONDS ((int64_t)1700000001)

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_addr[NKEYS][CMT_ADDRESS_SIZE];

static cmt_valset_scratch_t *g_scratch;

/* A validator set with its own storage. */
typedef struct {
    cmt_validator_t     storage[NKEYS];
    cmt_validator_set_t vs;
} tvals_t;

/* A commit with its signature list. */
typedef struct {
    cmt_commit_sig_t sigs[NKEYS];
    cmt_commit_t     c;
} tcommit_t;

/* ══ fixtures ═════════════════════════════════════════════════════════ */

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
        memset(seed, (uint8_t)(0x41 + i), sizeof(seed));
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

/* `RandValidatorSet(n, 1)` over keys[first .. first+n): every member has
 * power 1; NewValidatorSet orders the set. */
static int make_vals(tvals_t *out, int first, size_t n)
{
    cmt_validator_t     list[NKEYS];
    cmt_pb_public_key_t pk;
    size_t              i;

    if ((size_t)first + n > NKEYS) {
        return 1;
    }
    for (i = 0; i < n; i++) {
        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[first + (int)i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, 1, &list[i]) != CMT_OK) {
            return 1;
        }
    }
    if (cmt_validator_set_init(&out->vs, out->storage, NKEYS) != CMT_OK ||
        cmt_validator_set_new(&out->vs, list, n, g_scratch) != CMT_OK) {
        return 1;
    }
    return 0;
}

static int vals_hash(const cmt_validator_set_t *vs, uint8_t out[CMT_TMHASH_SIZE])
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

/* A COMMIT entry for validator `vs[idx]`, signed over
 * `Commit.VoteSignBytes(chain, idx)`. */
static int sign_entry(cmt_commit_t *c, const cmt_validator_set_t *vs,
                      size_t idx, const char *chain)
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

/* block_test.go:438-447 `randCommit(now)`: a commit at height 2, round 1,
 * for a block id of its own, in which every member of `signers` signed.
 * ADAPTED: 8 fixed keys, not 10 random ones; `seed` picks the block id
 * pattern so two calls give two different commits. */
static int rand_commit(tcommit_t *out, const cmt_validator_set_t *signers,
                       const char *chain, uint8_t seed)
{
    size_t i;

    cmt_pb_commit_init(&out->c);
    out->c.height = 2;                                           /* :440-441 */
    out->c.round  = 1;
    pat(out->c.block_id.hash, CMT_TMHASH_SIZE, seed);            /* :439 */
    out->c.block_id.hash_len                 = CMT_TMHASH_SIZE;
    out->c.block_id.part_set_header.total    = 1000u;
    pat(out->c.block_id.part_set_header.hash, CMT_TMHASH_SIZE,
        (uint8_t)(seed + 1u));
    out->c.block_id.part_set_header.hash_len = CMT_TMHASH_SIZE;
    out->c.signatures     = out->sigs;
    out->c.signatures_cap = NKEYS;
    out->c.signatures_len = signers->validators_len;
    for (i = 0; i < signers->validators_len; i++) {
        if (sign_entry(&out->c, signers, i, chain) != 0) {
            return 1;
        }
    }
    return 0;
}

/* block_test.go:866-892 `makeRandHeader()`: chain "test", Version
 * {BlockProtocol, 1}, one random 64-byte value in every hash field and a
 * random address — fixed patterns here. */
static void make_rand_header(cmt_header_t *h, const char *chain)
{
    cmt_pb_header_init(h);
    h->version.block = CMT_BLOCK_PROTOCOL;                       /* :873 */
    h->version.app   = 1;
    memcpy(h->chain_id, chain, strlen(chain));                   /* :874 */
    h->chain_id_len  = strlen(chain);
    h->height        = 7;                                        /* :875 */
    h->time.seconds  = T_SECONDS;                                /* :876 */
    h->time.nanos    = 0;
    pat(h->last_commit_hash, CMT_TMHASH_SIZE, 0x10);             /* :878-887 */
    h->last_commit_hash_len = CMT_TMHASH_SIZE;
    pat(h->data_hash, CMT_TMHASH_SIZE, 0x10);
    h->data_hash_len = CMT_TMHASH_SIZE;
    pat(h->validators_hash, CMT_TMHASH_SIZE, 0x10);
    h->validators_hash_len = CMT_TMHASH_SIZE;
    pat(h->next_validators_hash, CMT_TMHASH_SIZE, 0x10);
    h->next_validators_hash_len = CMT_TMHASH_SIZE;
    pat(h->consensus_hash, CMT_TMHASH_SIZE, 0x10);
    h->consensus_hash_len = CMT_TMHASH_SIZE;
    pat(h->app_hash, CMT_TMHASH_SIZE, 0x10);
    h->app_hash_len = CMT_TMHASH_SIZE;
    pat(h->last_results_hash, CMT_TMHASH_SIZE, 0x10);
    h->last_results_hash_len = CMT_TMHASH_SIZE;
    pat(h->evidence_hash, CMT_TMHASH_SIZE, 0x10);
    h->evidence_hash_len = CMT_TMHASH_SIZE;
    pat(h->proposer_address, CMT_ADDRESS_SIZE, 0x30);            /* :888 */
    h->proposer_address_len = CMT_ADDRESS_SIZE;
}

/* The fixture both light_test.go tests build (:16-31 and :61-75). */
typedef struct {
    tvals_t             vals;     /* RandValidatorSet(5, 1)         */
    tvals_t             vals2;    /* RandValidatorSet(3, 1)         */
    tvals_t             vals3;    /* vals.Copy(), Proposer = {}     */
    tvals_t             signers;  /* randCommit's own set (ADAPTED) */
    tvals_t             empty;    /* &ValidatorSet{}                */
    tcommit_t           commit;
    tcommit_t           commit2;  /* a second randCommit            */
    cmt_header_t        header;
    cmt_signed_header_t sh;
    cmt_signed_header_t sh_bad;   /* {header, commit2}              */
    cmt_signed_header_t sh_empty; /* &SignedHeader{}                */
} tfix_t;

static const char *const CHAIN = "test";

static int build_fixture(tfix_t *f)
{
    if (make_vals(&f->vals, 0, 5) != 0 ||                        /* :18 */
        make_vals(&f->vals2, 5, 3) != 0 ||                       /* :23 */
        make_vals(&f->signers, 0, NKEYS) != 0) {
        return 1;
    }
    /* :24-25 — `vals3 := vals.Copy(); vals3.Proposer = &Validator{}`. */
    if (cmt_validator_set_init(&f->vals3.vs, f->vals3.storage, NKEYS) != CMT_OK ||
        cmt_validator_set_copy(&f->vals.vs, &f->vals3.vs) != CMT_OK) {
        return 1;
    }
    memset(&f->vals3.vs.proposer, 0, sizeof(f->vals3.vs.proposer));
    f->vals3.vs.has_proposer = true;
    /* `&ValidatorSet{}`. */
    if (cmt_validator_set_init(&f->empty.vs, f->empty.storage, NKEYS) != CMT_OK) {
        return 1;
    }

    make_rand_header(&f->header, CHAIN);                         /* :16 */
    if (rand_commit(&f->commit, &f->signers.vs, CHAIN, 0x51) != 0 ||  /* :17 */
        rand_commit(&f->commit2, &f->signers.vs, CHAIN, 0x61) != 0) { /* :42 */
        return 1;
    }
    f->header.height        = f->commit.c.height;                /* :19 */
    f->header.last_block_id = f->commit.c.block_id;              /* :20 */
    if (vals_hash(&f->vals.vs, f->header.validators_hash) != 0) {  /* :21 */
        return 1;
    }
    f->header.validators_hash_len = CMT_TMHASH_SIZE;
    f->header.version.block       = CMT_BLOCK_PROTOCOL;          /* :22 */
    /* :26 — `commit.BlockID.Hash = header.Hash()`. */
    if (cmt_header_hash(&f->header, f->commit.c.block_id.hash) != CMT_OK) {
        return 1;
    }
    f->commit.c.block_id.hash_len = CMT_TMHASH_SIZE;

    f->sh.header       = &f->header;                             /* :28-31 */
    f->sh.commit       = &f->commit.c;
    f->sh_bad.header   = &f->header;                             /* :42 */
    f->sh_bad.commit   = &f->commit2.c;
    f->sh_empty.header = NULL;
    f->sh_empty.commit = NULL;
    return 0;
}

/* ══ 1. TestLightBlockValidateBasic (light_test.go:15-58) ════════════ */

static int t_validate_basic(tfix_t *f)
{
    const uint8_t    *chain = (const uint8_t *)CHAIN;
    size_t            clen  = strlen(CHAIN);
    cmt_light_block_t lb;

    /* :39 "valid light block". */
    lb.signed_header = &f->sh;
    lb.validator_set = &f->vals.vs;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_OK,
          "valid light block");
    OK();

    /* :40 "hashes don't match". */
    lb.validator_set = &f->vals2.vs;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "hashes don't match");
    OK();

    /* :41 "invalid validator set" — the proposer is not a member. */
    lb.validator_set = &f->vals3.vs;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "invalid validator set");
    OK();

    /* :42 "invalid signed header" — the commit is for another block. */
    lb.signed_header = &f->sh_bad;
    lb.validator_set = &f->vals.vs;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "invalid signed header");
    OK();

    /* PROJECT-AUTHORED: :22-27 missing members are errors (REJECT); a
     * NULL light block is FAULT (R1B-10); another chain id fails
     * SignedHeader.ValidateBasic; the wrong block protocol fails
     * Header.ValidateBasic. */
    lb.signed_header = NULL;
    lb.validator_set = &f->vals.vs;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "missing signed header");
    lb.signed_header = &f->sh;
    lb.validator_set = NULL;
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "missing validator set");
    CHECK(cmt_light_block_validate_basic(NULL, chain, clen,
                                         CMT_BLOCK_PROTOCOL) == CMT_FAULT,
          "NULL light block");
    lb.validator_set = &f->vals.vs;
    CHECK(cmt_light_block_validate_basic(&lb, (const uint8_t *)"tesT", 4,
                                         CMT_BLOCK_PROTOCOL) == CMT_REJECT,
          "another chain");
    CHECK(cmt_light_block_validate_basic(&lb, chain, clen,
                                         CMT_BLOCK_PROTOCOL + 1u) == CMT_REJECT,
          "another block protocol");
    OK();
    return 0;
}

/* ══ 2. TestLightBlockProtobuf (light_test.go:60-111) ════════════════ */

/* ToProto + Marshal → Unmarshal + FromProto → ToProto + Marshal. Returns
 * the decode verdict; on CMT_OK also checks that the second encoding is
 * byte-identical to the first and that presence survived. */
static int round_trip(const cmt_light_block_t *lb, int *decode_rc,
                      size_t *enc_len)
{
    cmt_light_block_buf_t *buf = cmt_light_block_buf_new();
    uint8_t               *a   = NULL;
    uint8_t               *b   = NULL;
    size_t                 a_len = 0u;
    size_t                 b_len = 0u;
    int                    ret = 1;

    if (buf == NULL) {
        return 1;
    }
    if (cmt_light_block_encode(lb, &a, &a_len) != CMT_OK) {     /* toProtoErr false */
        fprintf(stderr, "encode failed\n");
        goto out;
    }
    *enc_len   = a_len;
    *decode_rc = cmt_light_block_decode(a, a_len, CMT_BLOCK_PROTOCOL, buf);
    if (*decode_rc != CMT_OK) {
        /* A failed decode leaves the empty light block. */
        if (buf->lb.signed_header != NULL || buf->lb.validator_set != NULL) {
            fprintf(stderr, "failed decode left a result\n");
            goto out;
        }
        ret = 0;
        goto out;
    }
    if ((buf->lb.signed_header == NULL) != (lb->signed_header == NULL) ||
        (buf->lb.validator_set == NULL) != (lb->validator_set == NULL)) {
        fprintf(stderr, "presence of a member changed\n");
        goto out;
    }
    if (lb->signed_header != NULL &&
        ((buf->lb.signed_header->header == NULL) !=
             (lb->signed_header->header == NULL) ||
         (buf->lb.signed_header->commit == NULL) !=
             (lb->signed_header->commit == NULL))) {
        fprintf(stderr, "presence inside the signed header changed\n");
        goto out;
    }
    if (cmt_light_block_encode(&buf->lb, &b, &b_len) != CMT_OK ||
        b_len != a_len || (a_len != 0u && memcmp(a, b, a_len) != 0)) {
        fprintf(stderr, "re-encoding differs\n");
        goto out;
    }
    ret = 0;
out:
    free(a);
    free(b);
    cmt_light_block_buf_free(buf);
    return ret;
}

static int t_protobuf(tfix_t *f)
{
    cmt_light_block_t lb;
    int               drc = CMT_FAULT;
    size_t            n   = 0u;

    /* :84 "valid light block" — both directions succeed. */
    lb.signed_header = &f->sh;
    lb.validator_set = &f->vals.vs;
    CHECK(round_trip(&lb, &drc, &n) == 0 && drc == CMT_OK,
          "valid light block");
    OK();

    /* :85 "empty signed header" — succeeds; the empty message survives. */
    lb.signed_header = &f->sh_empty;
    lb.validator_set = &f->vals.vs;
    CHECK(round_trip(&lb, &drc, &n) == 0 && drc == CMT_OK,
          "empty signed header");
    OK();

    /* :86 "empty validator set" — encodes, does not decode
     * (ValidatorSetFromProto refuses the set with no proposer). */
    lb.signed_header = &f->sh;
    lb.validator_set = &f->empty.vs;
    CHECK(round_trip(&lb, &drc, &n) == 0 && drc == CMT_REJECT,
          "empty validator set");
    OK();

    /* :87 "empty light block" — encodes, does not decode. */
    lb.signed_header = &f->sh_empty;
    lb.validator_set = &f->empty.vs;
    CHECK(round_trip(&lb, &drc, &n) == 0 && drc == CMT_REJECT,
          "empty light block");
    OK();

    /* PROJECT-AUTHORED: the nil light block (both members nil) is zero
     * bytes and decodes back to itself. */
    lb.signed_header = NULL;
    lb.validator_set = NULL;
    CHECK(round_trip(&lb, &drc, &n) == 0 && drc == CMT_OK && n == 0u,
          "nil light block");
    OK();
    return 0;
}

/* ══ 3. presence bytes and malformed streams (PROJECT-AUTHORED) ══════ */

static int t_wire(tfix_t *f)
{
    cmt_light_block_buf_t *buf = cmt_light_block_buf_new();
    cmt_light_block_t      lb;
    uint8_t               *a = NULL;
    uint8_t               *c = NULL;
    size_t                 a_len = 0u;
    int                    ret = 1;

    if (buf == NULL) {
        return 1;
    }

    /* types.pb.go:2028-2039 — a present, EMPTY SignedHeader is tag 0x0a
     * and length 0. */
    lb.signed_header = &f->sh_empty;
    lb.validator_set = NULL;
    if (cmt_light_block_encode(&lb, &a, &a_len) != CMT_OK || a_len != 2u ||
        a[0] != 0x0au || a[1] != 0x00u) {
        fprintf(stderr, "empty signed header bytes\n"); goto out;
    }
    free(a);
    a = NULL;
    OK();

    /* types.pb.go:2016-2027 with ValidatorSet.ToProto's empty message
     * (validator_set.go:933-935) — tag 0x12, length 0. */
    lb.signed_header = NULL;
    lb.validator_set = &f->empty.vs;
    if (cmt_light_block_encode(&lb, &a, &a_len) != CMT_OK || a_len != 2u ||
        a[0] != 0x12u || a[1] != 0x00u) {
        fprintf(stderr, "empty validator set bytes\n"); goto out;
    }
    free(a);
    a = NULL;
    OK();

    /* A full block, then three mutations of it. */
    lb.signed_header = &f->sh;
    lb.validator_set = &f->vals.vs;
    if (cmt_light_block_encode(&lb, &a, &a_len) != CMT_OK || a_len < 4u) {
        fprintf(stderr, "full encode\n"); goto out;
    }
    /* An unknown field (field 15, varint 1: tag 0x78) is skipped
     * (types.pb.go:4965-4978). */
    c = malloc(a_len + 2u);
    if (c == NULL) {
        goto out;
    }
    memcpy(c, a, a_len);
    c[a_len]      = 0x78u;
    c[a_len + 1u] = 0x01u;
    if (cmt_light_block_decode(c, a_len + 2u, CMT_BLOCK_PROTOCOL, buf) != CMT_OK ||
        buf->lb.signed_header == NULL || buf->lb.validator_set == NULL) {
        fprintf(stderr, "unknown field not skipped\n"); goto out;
    }
    OK();
    /* A truncated stream is refused (io.ErrUnexpectedEOF). */
    if (cmt_light_block_decode(a, a_len - 1u, CMT_BLOCK_PROTOCOL, buf) != CMT_REJECT ||
        buf->lb.signed_header != NULL || buf->lb.validator_set != NULL) {
        fprintf(stderr, "truncated stream\n"); goto out;
    }
    OK();
    /* Field 1 with wire type 0 is refused (types.pb.go:4894-4896). */
    c[0] = 0x08u;
    c[1] = 0x01u;
    if (cmt_light_block_decode(c, 2u, CMT_BLOCK_PROTOCOL, buf) != CMT_REJECT) {
        fprintf(stderr, "wrong wire type\n"); goto out;
    }
    OK();
    /* The wrong block protocol is refused by HeaderFromProto's
     * ValidateBasic (block.go:575). */
    if (cmt_light_block_decode(a, a_len, CMT_BLOCK_PROTOCOL + 1u, buf) != CMT_REJECT) {
        fprintf(stderr, "block protocol on decode\n"); goto out;
    }
    OK();
    /* NULL is FAULT (R1B-10). */
    {
        uint8_t *none     = NULL;
        size_t   none_len = 0u;

        if (cmt_light_block_decode(a, a_len, CMT_BLOCK_PROTOCOL, NULL) != CMT_FAULT ||
            cmt_light_block_encode(NULL, &none, &none_len) != CMT_FAULT ||
            none != NULL) {
            fprintf(stderr, "NULL\n"); goto out;
        }
    }
    OK();
    ret = 0;
out:
    free(a);
    free(c);
    cmt_light_block_buf_free(buf);
    CHECK(ret == 0, "wire rows");
    return 0;
}

/* ══ 4. the mock provider (light/provider/mock/mock.go) ══════════════ */

#define MOCK_MAX 4
#define MOCK_EV_MAX 4

/* mock.go:15-23 — `type Mock struct`. The two Go maps keyed by height
 * become one array of entries; `New` takes the max height (:30-35), which
 * does not depend on the order in which the entries are visited. The
 * mutex (:18) is not ported (one thread). */
typedef struct {
    const char                *chain_id;                   /* :16 */
    int64_t                    heights[MOCK_MAX];
    const cmt_signed_header_t *headers[MOCK_MAX];          /* :19 */
    cmt_validator_set_t       *vals[MOCK_MAX];             /* :20 */
    size_t                     n;
    uint8_t                   *evidence[MOCK_EV_MAX];      /* :21 hash => evidence */
    size_t                     evidence_len[MOCK_EV_MAX];
    size_t                     n_evidence;
    int64_t                    latest_height;              /* :22 */
} tmock_t;

/* mock.go:27-43 — `New`. */
static void mock_new(tmock_t *m, const char *chain_id, size_t n,
                     const int64_t *heights,
                     const cmt_signed_header_t *const *headers,
                     cmt_validator_set_t *const *vals)
{
    size_t i;

    memset(m, 0, sizeof(*m));
    m->chain_id = chain_id;
    for (i = 0; i < n && i < MOCK_MAX; i++) {
        m->heights[i] = heights[i];
        m->headers[i] = headers[i];
        m->vals[i]    = vals[i];
        if (heights[i] > m->latest_height) {                 /* :30-35 */
            m->latest_height = heights[i];
        }
    }
    m->n = i;
}

/* mock.go:45-48 — `ChainID()`. */
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

/* mock.go:64-103 — `LightBlock(ctx, height)`. The 10 ms `time.After`
 * window (:68-73) is not ported (no clock). The block is copied into the
 * caller's buffer through encode + decode — Go returns the mock's own
 * pointers. */
static int mock_light_block(void *ctx, int64_t height,
                            cmt_light_block_buf_t *out,
                            cmt_light_provider_error_t *err)
{
    tmock_t          *m = ctx;
    cmt_light_block_t lb;
    size_t            i;
    bool              have = false;
    uint8_t          *bz   = NULL;
    size_t            bz_len = 0u;
    int               rc;

    prov_err(err, CMT_LIGHT_PROVIDER_ERR_NONE, CMT_OK);
    if (m == NULL || out == NULL || height < 0) {
        return CMT_FAULT;   /* provider.go:19 "height must be >= 0" */
    }
    (void)cmt_light_block_buf_reset(out);

    if (height > m->latest_height) {                             /* :77-79 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH, CMT_OK);
        return CMT_REJECT;
    }
    if (height == 0 && m->n > 0u) {                              /* :81-83 */
        height = m->latest_height;
    }
    lb.signed_header = NULL;
    lb.validator_set = NULL;
    for (i = 0; i < m->n; i++) {                                 /* :85-92 */
        if (m->heights[i] == height) {
            lb.signed_header = m->headers[i];
            lb.validator_set = m->vals[i];
            have = true;
            break;
        }
    }
    if (!have) {                                                 /* :93-95 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND, CMT_OK);
        return CMT_REJECT;
    }
    if (lb.signed_header == NULL || lb.validator_set == NULL) {  /* :96-98 */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK, CMT_REJECT);
        return CMT_REJECT;
    }
    if (lb.signed_header->header == NULL) {
        /* :99 reads lb.ChainID through the embedded header — a Go panic
         * on a nil header; the mock refuses it as a bad block. */
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK, CMT_FAULT);
        return CMT_REJECT;
    }
    rc = cmt_light_block_validate_basic(&lb,
                                        lb.signed_header->header->chain_id,
                                        lb.signed_header->header->chain_id_len,
                                        CMT_BLOCK_PROTOCOL);     /* :99 */
    if (rc != CMT_OK) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK, rc); /* :100 */
        return CMT_REJECT;
    }
    rc = cmt_light_block_encode(&lb, &bz, &bz_len);
    if (rc == CMT_OK) {
        rc = cmt_light_block_decode(bz, bz_len, CMT_BLOCK_PROTOCOL, out);
    }
    free(bz);
    return rc == CMT_OK ? CMT_OK : CMT_FAULT;                    /* :102 */
}

/* mock.go:105-108 — `ReportEvidence`: kept by its bytes (the Go map is
 * keyed by `ev.Hash()`). */
static int mock_report_evidence(void *ctx, const cmt_pb_evidence_t *ev)
{
    tmock_t *m = ctx;
    uint8_t *bz;
    size_t   cap = 2u * (size_t)CMT_PB_SIG_MAX + 4096u;
    size_t   len = 0u;

    if (m == NULL || ev == NULL || m->n_evidence >= MOCK_EV_MAX) {
        return CMT_FAULT;
    }
    bz = malloc(cap);
    if (bz == NULL) {
        return CMT_FAULT;
    }
    if (cmt_pb_evidence_marshal(ev, bz, cap, &len) != CMT_OK) {
        free(bz);
        return CMT_REJECT;
    }
    m->evidence[m->n_evidence]     = bz;
    m->evidence_len[m->n_evidence] = len;
    m->n_evidence++;
    return CMT_OK;
}

/* mock.go:110-113 — `HasEvidence`. */
static bool mock_has_evidence(const tmock_t *m, const cmt_pb_evidence_t *ev)
{
    uint8_t *bz;
    size_t   cap = 2u * (size_t)CMT_PB_SIG_MAX + 4096u;
    size_t   len = 0u;
    size_t   i;
    bool     has = false;

    bz = malloc(cap);
    if (bz == NULL || cmt_pb_evidence_marshal(ev, bz, cap, &len) != CMT_OK) {
        free(bz);
        return false;
    }
    for (i = 0; i < m->n_evidence; i++) {
        if (m->evidence_len[i] == len &&
            memcmp(m->evidence[i], bz, len) == 0) {
            has = true;
        }
    }
    free(bz);
    return has;
}

static void mock_free(tmock_t *m)
{
    size_t i;

    for (i = 0; i < m->n_evidence; i++) {
        free(m->evidence[i]);
    }
    m->n_evidence = 0u;
}

static int t_mock(tfix_t *f)
{
    static const int64_t       heights[3] = { 2, 4, 5 };
    const cmt_signed_header_t *headers[3];
    cmt_validator_set_t       *vals[3];
    tmock_t                    m;
    cmt_light_provider_t       p;
    cmt_light_provider_error_t err;
    cmt_light_block_buf_t     *buf = cmt_light_block_buf_new();
    cmt_pb_evidence_t         *ev1 = calloc(1, sizeof(*ev1));
    cmt_pb_evidence_t         *ev2 = calloc(1, sizeof(*ev2));
    const uint8_t             *cid = NULL;
    size_t                     cid_len = 0u;
    int                        ret = 1;

    if (buf == NULL || ev1 == NULL || ev2 == NULL) {
        goto out;
    }
    /* Height 2 is the valid fixture block; height 4 has a set that does
     * not match its header; height 5 has no set. */
    headers[0] = &f->sh;  vals[0] = &f->vals.vs;
    headers[1] = &f->sh;  vals[1] = &f->vals2.vs;
    headers[2] = &f->sh;  vals[2] = NULL;
    mock_new(&m, CHAIN, 3, heights, headers, vals);

    p.ctx             = &m;
    p.chain_id        = mock_chain_id;
    p.light_block     = mock_light_block;
    p.report_evidence = mock_report_evidence;

    if (p.chain_id(p.ctx, &cid, &cid_len) != CMT_OK ||
        cid_len != strlen(CHAIN) || memcmp(cid, CHAIN, cid_len) != 0) {
        fprintf(stderr, "chain id\n"); goto out;
    }
    OK();
    /* height > latest (5) → ErrHeightTooHigh (:77-79). */
    if (p.light_block(p.ctx, 6, buf, &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH) {
        fprintf(stderr, "height too high\n"); goto out;
    }
    OK();
    /* A height the mock does not hold → ErrLightBlockNotFound (:93-95). */
    if (p.light_block(p.ctx, 3, buf, &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND) {
        fprintf(stderr, "not found\n"); goto out;
    }
    OK();
    /* A nil set → ErrBadLightBlock (:96-98). Height 0 is the latest (5). */
    if (p.light_block(p.ctx, 0, buf, &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK) {
        fprintf(stderr, "latest / nil set\n"); goto out;
    }
    OK();
    /* A set that is not the header's → ErrBadLightBlock{ValidateBasic}. */
    if (p.light_block(p.ctx, 4, buf, &err) != CMT_REJECT ||
        err.code != CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK ||
        err.reason != CMT_REJECT) {
        fprintf(stderr, "bad light block\n"); goto out;
    }
    OK();
    /* The valid block. */
    if (p.light_block(p.ctx, 2, buf, &err) != CMT_OK ||
        err.code != CMT_LIGHT_PROVIDER_ERR_NONE ||
        buf->lb.signed_header == NULL || buf->lb.validator_set == NULL ||
        buf->lb.signed_header->header == NULL ||
        buf->lb.signed_header->header->height != f->header.height ||
        buf->lb.validator_set->validators_len != f->vals.vs.validators_len) {
        fprintf(stderr, "valid block\n"); goto out;
    }
    OK();
    /* A negative height is the caller's error (provider.go:19). */
    if (p.light_block(p.ctx, -1, buf, &err) != CMT_FAULT) {
        fprintf(stderr, "negative height\n"); goto out;
    }
    OK();
    /* ReportEvidence / HasEvidence (:105-113). */
    cmt_pb_evidence_init(ev1);
    ev1->has_duplicate_vote_evidence = true;
    cmt_pb_duplicate_vote_evidence_init(&ev1->duplicate_vote_evidence);
    ev1->duplicate_vote_evidence.total_voting_power = 10;
    cmt_pb_evidence_init(ev2);
    ev2->has_duplicate_vote_evidence = true;
    cmt_pb_duplicate_vote_evidence_init(&ev2->duplicate_vote_evidence);
    ev2->duplicate_vote_evidence.total_voting_power = 11;
    if (p.report_evidence(p.ctx, ev1) != CMT_OK ||
        !mock_has_evidence(&m, ev1) || mock_has_evidence(&m, ev2)) {
        fprintf(stderr, "evidence\n"); goto out;
    }
    OK();
    ret = 0;
out:
    mock_free(&m);
    free(ev1);
    free(ev2);
    cmt_light_block_buf_free(buf);
    CHECK(ret == 0, "mock provider rows");
    return 0;
}

int main(void)
{
    tfix_t *f;
    int     rc = 1;

    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    f         = (tfix_t *)calloc(1, sizeof(*f));
    if (g_scratch == NULL || f == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    if (build_keys() != 0) goto out;
    if (build_fixture(f) != 0) {
        fprintf(stderr, "fixture failed\n");
        goto out;
    }
    if (t_validate_basic(f) != 0) goto out;
    if (t_protobuf(f) != 0) goto out;
    if (t_wire(f) != 0) goto out;
    if (t_mock(f) != 0) goto out;

    printf("test_cmt_light_block: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(f);
    free(g_scratch);
    return rc;
}
