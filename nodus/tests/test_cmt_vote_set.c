/**
 * Nodus — cometbft @709fd12b C port, wave R2-A: `types/vote_set.go`,
 * the `types/block.go` ToVoteSet family, and
 * `consensus/types/round_state.go` (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a VoteSet reaches a +2/3 majority exactly where cometbft's own
 * tests say it does, refuses exactly what cometbft refuses, and that the
 * one path a double-signing validator can use to get a second vote stored
 * is the one the reference opens. If this file failed, one of these would
 * be false:
 *   · a fresh set has no vote from anyone, no bit set and no majority,
 *     and one added vote flips exactly that validator's bit
 *     (vote_set_test.go:16-46 TestVoteSet_AddVote_Good);
 *   · a set refuses a second, conflicting vote from the same validator, a
 *     vote at the wrong height, at the wrong round, and of the wrong type
 *     (:48-122 TestVoteSet_AddVote_Bad);
 *   · with ten validators of power 1 the majority appears on the SEVENTH
 *     agreeing vote and not before — quorum = 10*2/3+1 = 7 (:124-172
 *     TestVoteSet_2_3Majority);
 *   · with a hundred validators the majority appears on the 67th
 *     agreeing vote, and four near-misses — a missing hash, a different
 *     part-set hash, a different part-set total, a different block hash —
 *     each count as a DIFFERENT block (:174-271
 *     TestVoteSet_2_3MajorityRedux);
 *   · a conflicting vote is stored, and can complete a majority, ONLY
 *     after a peer has claimed +2/3 for that block; a second, different
 *     claim from the same peer is refused (:273-400
 *     TestVoteSet_Conflicts);
 *   · MakeExtendedCommit refuses to build a commit without a majority,
 *     and with one produces exactly N entries, ABSENT where a validator
 *     did not vote or voted for another block (:402-477
 *     TestVoteSet_MakeCommit);
 *   · an extended set refuses a precommit with no extension signature and
 *     a plain set refuses one that carries extension data (:479-560
 *     TestVoteSet_VoteExtensionsEnabled);
 *   · the C-only bounds hold: the 129th distinct peer is refused, filling
 *     the block table to its derived capacity does not overrun it, and a
 *     FULL block table makes both call sites of `new_block_votes`
 *     (vote_set.go:299-300 and :362-363) return CMT_REJECT with
 *     CMT_VOTE_SET_ERR_BLOCK_CAPACITY rather than write past the end;
 *   · RoundStepType.IsValid is true exactly on 0x01..0x08 and
 *     RoundStepType.String returns the reference's eight strings
 *     byte-for-byte — the strings the WAL stores and replay.go:55
 *     compares (round_state.go:33-60);
 *   · Commit.ToVoteSet and ExtendedCommit.ToExtendedVoteSet rebuild a set
 *     whose majority and bit array are the commit's signers
 *     (block.go:1071-1117).
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A DEFAULT BUILD. No compile flags, no environment variables, no
 * network, no files, no clock. Keys come from `qgp_dsa87_keypair_derand`
 * with fixed seeds and every timestamp is a fixed constant, so the file
 * draws no randomness and reads no clock. Safe under `ctest -j`.
 * Every vote set, vote buffer, validator-set scratch (>1 MB) and vote
 * list is heap allocated. What DOES live on the stack: the `world_t`
 * fixture (~3 KB — it embeds a `cmt_validator_set_t`, whose by-value
 * `proposer.pub_key` is a 2592-byte ML-DSA-87 key) and one
 * `cmt_pb_public_key_t` (~2.6 KB) in `world_build`. Both are far below
 * any stack limit; the multi-hundred-KB objects are the ones that must
 * not be there, and none is (Delta A-4, verifier A).
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state. Every
 * `cmt_vote_set_new` is matched by a `cmt_vote_set_free`.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. EQUAL VOTING POWERS CANNOT DISTINGUISH WEIGHT FROM COUNT. Every
 *     scenario in the reference's own file uses power 1 (or 10 for all
 *     five validators at :515), so a port that summed VOTES instead of
 *     POWER would pass all of them. `t_unequal_powers` below is NOT from
 *     the reference: it is added here for exactly that reason, with its
 *     expected values derived in a comment.
 *  2. ML-DSA-87 signing is HEDGED — the same message signed twice gives
 *     different bytes. No signature is ever frozen or compared for
 *     equality; every real-key assertion is on a VERIFY OUTCOME.
 *  3. THE BLOCK-TABLE CAPACITY REFUSAL CANNOT BE REACHED THROUGH THE
 *     PUBLIC API: the derivation says at most CMT_VALSET_MAX +
 *     CMT_PEER_MAX distinct blocks can ever be created and the table is
 *     exactly that size, so a black-box test can only fill it to the brim
 *     (`t_block_table_capacity`). The refusal itself is therefore
 *     exercised WHITE-BOX in `t_block_table_exhausted`, which marks every
 *     slot occupied by hand. That proves the branch REFUSES rather than
 *     overruns; it does NOT prove the branch is reachable in production,
 *     and the derivation says it is not.
 *  4. The timestamps are constants where the reference calls
 *     `cmttime.Now()` (:36, :57, …). A timestamp changes the SIGN BYTES
 *     and nothing else, and no assertion here reads one; a port that
 *     mishandled timestamps would not be caught by this file.
 *  5. The chain id is 32 raw bytes, not the reference's "test_chain_id"
 *     (:518) — the approved substitution (umbrella rev 3, R1
 *     atlas-dec-9285f4a5…). No expected value here depends on its bytes.
 *  6. Nothing here exercises a REAL host: no reactor, no state machine,
 *     no WAL. A green says the vote set is right, not that anything uses
 *     it correctly.
 *
 * Reference test sources @709fd12b, SHA-256 verified before use:
 *   types/vote_set_test.go  622 lines
 *     4435df346d2f5305fa278228c22834ca1dfc6d00c4aa2e2843c88484dd48f8e3
 *   types/test_util.go      123 lines
 *     32333c3ef6fb373706e8d7d6b87723c08d9c5b35d0b23094eb42178a8ae8caf2
 *
 * @file test_cmt_vote_set.c
 */

#include "dnac/cmt_vote_set.h"
#include "dnac/cmt_round_state.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_params.h"

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

/* ══ fixtures ═════════════════════════════════════════════════════════ */

/* 100 is the widest reference scenario: TestVoteSet_2_3MajorityRedux
 * (vote_set_test.go:176) uses randVoteSet(..., 100, 1, false). */
#define MAXVALS 100

static uint8_t g_pk[MAXVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[MAXVALS][QGP_DSA87_SECRETKEYBYTES];

/* The chain id: 32 raw bytes, the approved substitution for the
 * reference's "test_chain_id" string. */
static uint8_t g_chain[CMT_PB_CHAINID_MAX];

/* A fixed stamp where the reference calls cmttime.Now(). See "how it can
 * lie" item 4. */
static const cmt_time_t G_TS = { 1700000000, 0 };

/* Scratch buffers big enough for any vote in this file. */
static cmt_vote_t *g_v;      /* the vote under construction               */
static cmt_vote_t *g_conf;   /* the conflicting vote AddVote hands back   */

typedef struct {
    size_t                n;
    cmt_validator_t      *storage;
    cmt_validator_set_t   vs;
    cmt_valset_scratch_t *scratch;
    /* set index -> index into g_pk/g_sk. cmt_validator_set_new sorts by
     * voting power DESCENDING and then by address (validator_set.go:851-856),
     * so with EQUAL powers the set's order is address order — which is
     * exactly what RandValidatorSet produces for the reference's tests
     * (validator_set.go:986 sorts privValidators by address), and is why
     * vote_set_test.go:562 can say "privValidators are in order". */
    int                   key_of_index[MAXVALS];
} world_t;

static void world_free(world_t *w)
{
    free(w->storage);
    free(w->scratch);
    w->storage = NULL;
    w->scratch = NULL;
}

static int world_build(world_t *w, size_t n, const int64_t *powers)
{
    cmt_validator_t *list;
    size_t           i;
    size_t           j;

    memset(w, 0, sizeof(*w));
    if (n > (size_t)MAXVALS) {
        return 1;
    }
    w->n       = n;
    w->storage = (cmt_validator_t *)calloc(n, sizeof(cmt_validator_t));
    w->scratch = (cmt_valset_scratch_t *)malloc(sizeof(cmt_valset_scratch_t));
    list       = (cmt_validator_t *)calloc(n, sizeof(cmt_validator_t));
    if (w->storage == NULL || w->scratch == NULL || list == NULL) {
        free(list);
        world_free(w);
        return 1;
    }
    for (i = 0; i < n; i++) {
        cmt_pb_public_key_t pk;

        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, powers[i], &list[i]) != CMT_OK) {
            free(list);
            world_free(w);
            return 1;
        }
    }
    if (cmt_validator_set_init(&w->vs, w->storage, n) != CMT_OK ||
        cmt_validator_set_new(&w->vs, list, n, w->scratch) != CMT_OK) {
        free(list);
        world_free(w);
        return 1;
    }
    free(list);
    for (i = 0; i < n; i++) {
        w->key_of_index[i] = -1;
        for (j = 0; j < n; j++) {
            uint8_t addr[CMT_ADDRESS_SIZE];

            if (cmt_pubkey_address(g_pk[j], addr) != CMT_OK) {
                world_free(w);
                return 1;
            }
            if (w->vs.validators[i].address_len == (size_t)CMT_ADDRESS_SIZE &&
                memcmp(w->vs.validators[i].address, addr,
                       CMT_ADDRESS_SIZE) == 0) {
                w->key_of_index[i] = (int)j;
                break;
            }
        }
        if (w->key_of_index[i] < 0) {
            world_free(w);
            return 1;
        }
    }
    return 0;
}

static int world_build_equal(world_t *w, size_t n, int64_t power)
{
    int64_t powers[MAXVALS];
    size_t  i;

    for (i = 0; i < n && i < (size_t)MAXVALS; i++) {
        powers[i] = power;
    }
    return world_build(w, n, powers);
}

/* ══ vote construction and signing ════════════════════════════════════ */

/* A BlockID with a 64-byte hash and a part-set header. 64 is
 * CMT_TMHASH_SIZE, the substitution for the reference's tmhash.Size 32. */
static void make_block_id(cmt_block_id_t *bid, uint8_t seed, uint32_t total,
                          uint8_t ps_seed)
{
    size_t i;

    cmt_pb_block_id_init(bid);
    for (i = 0; i < (size_t)CMT_TMHASH_SIZE; i++) {
        bid->hash[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
    bid->hash_len              = (size_t)CMT_TMHASH_SIZE;
    bid->part_set_header.total = total;
    for (i = 0; i < (size_t)CMT_TMHASH_SIZE; i++) {
        bid->part_set_header.hash[i] =
            (uint8_t)((ps_seed + 11u * (unsigned)i) & 0xFFu);
    }
    bid->part_set_header.hash_len = (size_t)CMT_TMHASH_SIZE;
}

/* vote_set_test.go:30-38 / :52-60 — the "voteProto" every scenario copies,
 * with the validator filled in (withValidator, :582-587). */
static void proto_vote(world_t *w, cmt_vote_t *v, int32_t set_index,
                       int64_t height, int32_t round, int32_t type,
                       const cmt_block_id_t *bid)
{
    cmt_pb_vote_init(v);
    v->type      = type;
    v->height    = height;
    v->round     = round;
    v->block_id  = *bid;
    v->timestamp = G_TS;
    memcpy(v->validator_address, w->vs.validators[set_index].address,
           (size_t)CMT_ADDRESS_SIZE);
    v->validator_address_len = (size_t)CMT_ADDRESS_SIZE;
    v->validator_index       = set_index;
}

struct signer_ctx {
    const uint8_t *sk;
};

/*
 * The host signer `cmt_sign_and_check_vote` calls, standing in for
 * `PrivValidator.SignVote` (types/vote.go:418).
 *
 * It must produce the signature always, and the EXTENSION signature
 * exactly when the vote is a non-nil precommit — that is what
 * SignAndCheckVote's own checks demand: :435 refuses an extension
 * signature on anything else, and :443 refuses its absence on a non-nil
 * precommit when extensions are enabled.
 */
static int real_sign(void *ctx, const uint8_t *chain_id, size_t chain_id_len,
                     cmt_pb_vote_t *v)
{
    const uint8_t *sk = ((struct signer_ctx *)ctx)->sk;
    uint8_t        sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t         n;
    size_t         siglen;

    if (cmt_vote_sign_bytes(chain_id, chain_id_len, v, sb, sizeof(sb), &n)
        != CMT_OK) {
        return CMT_REJECT;
    }
    if (qgp_dsa87_sign(v->signature, &siglen, sb, n, sk) != 0) {
        return CMT_FAULT;
    }
    v->signature_len           = siglen;
    v->extension_signature_len = 0u;

    if (v->type == (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT &&
        !cmt_block_id_is_zero(&v->block_id)) {
        uint8_t *scratch;
        size_t   cap = 80u + v->extension.len;

        scratch = (uint8_t *)malloc(cap);
        if (scratch == NULL) {
            return CMT_FAULT;
        }
        if (cmt_vote_extension_sign_bytes(chain_id, chain_id_len, v, scratch,
                                          cap, &n) != CMT_OK) {
            free(scratch);
            return CMT_REJECT;
        }
        if (qgp_dsa87_sign(v->extension_signature, &siglen, scratch, n, sk)
            != 0) {
            free(scratch);
            return CMT_FAULT;
        }
        v->extension_signature_len = siglen;
        free(scratch);
    }
    return CMT_OK;
}

/* cometbft@709fd12b types/test_util.go:47-55 — signAddVote(). The type
 * check of :48-50 happens BEFORE signing, which is why the reference's
 * "wrong type" case (vote_set_test.go:110-120) never reaches AddVote. */
static int sign_add_vote(world_t *w, int32_t set_index, cmt_vote_t *vote,
                         cmt_vote_set_t *vs, bool *added,
                         cmt_vote_set_err_t *err, cmt_vote_t *conflicting)
{
    struct signer_ctx sc;
    bool              recoverable;
    int               rc;

    if (added != NULL) {
        *added = false;
    }
    if (err != NULL) {
        *err = CMT_VOTE_SET_ERR_NONE;
    }
    if (vote->type != vs->signed_msg_type) {
        return CMT_REJECT;                            /* test_util.go:48-50 */
    }
    sc.sk = g_sk[w->key_of_index[set_index]];
    rc    = cmt_sign_and_check_vote(vote, real_sign, &sc, g_chain,
                                    sizeof(g_chain), vs->extensions_enabled,
                                    &recoverable);             /* :51 */
    if (rc != CMT_OK) {
        return rc;
    }
    return cmt_vote_set_add_vote(vs, vote, added, err, conflicting); /* :54 */
}

/* ══ 1. TestVoteSet_AddVote_Good — vote_set_test.go:16-46 ═════════════ */

static int t_add_vote_good(void)
{
    world_t          w;
    cmt_vote_set_t  *vs = NULL;
    cmt_block_id_t   nil_bid;
    const cmt_vote_t *got = NULL;
    cmt_bit_array_t  ba;
    cmt_block_id_t   maj;
    bool             ok;
    bool             added;
    int              rc;

    /* :18 — randVoteSet(1, 0, PrevoteType, 10, 1, false). */
    CHECK(world_build_equal(&w, 10u, 1) == 0, "build 10 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");

    /* :25-28 — nothing from val0, bit 0 clear, no majority. */
    CHECK(cmt_vote_set_get_by_address(vs, w.vs.validators[0].address,
                                      (size_t)CMT_ADDRESS_SIZE,
                                      &got) == CMT_OK && got == NULL,
          "GetByAddress is nil before the vote");
    CHECK(cmt_vote_set_bit_array(vs, &ba) == CMT_OK &&
          cmt_bits_get_index(&ba, 0) == 0, "bit 0 clear before the vote");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok &&
          cmt_block_id_is_zero(&maj), "there should be no 2/3 majority");
    OK();

    /* :30-40 — val0 votes for a nil BlockID. */
    cmt_pb_block_id_init(&nil_bid);
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &nil_bid);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, NULL, NULL);
    CHECK(rc == CMT_OK && added, "signAddVote succeeds");
    OK();

    /* :42-45 — now it is there, bit 0 is set, and one vote out of ten is
     * still short of the quorum 10*2/3+1 = 7. */
    CHECK(cmt_vote_set_get_by_address(vs, w.vs.validators[0].address,
                                      (size_t)CMT_ADDRESS_SIZE,
                                      &got) == CMT_OK && got != NULL,
          "GetByAddress is not nil after the vote");
    CHECK(cmt_vote_set_bit_array(vs, &ba) == CMT_OK &&
          cmt_bits_get_index(&ba, 0) == 1, "bit 0 set after the vote");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok &&
          cmt_block_id_is_zero(&maj), "there should be no 2/3 majority");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 2. TestVoteSet_AddVote_Bad — vote_set_test.go:48-122 ═════════════ */

static int t_add_vote_bad(void)
{
    world_t            w;
    cmt_vote_set_t    *vs = NULL;
    cmt_block_id_t     nil_bid;
    cmt_block_id_t     some_bid;
    bool               added;
    cmt_vote_set_err_t err;
    int                rc;

    CHECK(world_build_equal(&w, 10u, 1) == 0, "build 10 validators"); /* :50 */
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    cmt_pb_block_id_init(&nil_bid);
    make_block_id(&some_bid, 0x31, 1u, 0x32);

    /* :62-72 — val0 votes for nil: succeeds. */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &nil_bid);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_OK && added, "expected VoteSet.Add to succeed");
    OK();

    /* :74-84 — val0 votes AGAIN, for a block: conflicting, not added.
     * The reference's `withBlockHash(vote, cmtrand.Bytes(32))` is a
     * different BlockID, so addVerifiedVote takes :265 (conflict) and
     * then :292-295 (nothing tracks that block yet) → (false, conflict). */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &some_bid);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, &err, g_conf);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES,
          "expected VoteSet.Add to fail, conflicting vote.");
    /* The payload of NewConflictingVoteError(conflicting, vote) (:236):
     * VoteA is the vote already in the set, the nil one. */
    CHECK(cmt_block_id_is_zero(&g_conf->block_id),
          "the conflicting vote handed back is the first, nil vote");
    OK();

    /* :86-96 — val1 votes at height+1: wrong step. */
    proto_vote(&w, g_v, 1, 1 + 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
               &nil_bid);
    rc = sign_add_vote(&w, 1, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_UNEXPECTED_STEP,
          "expected VoteSet.Add to fail, wrong height");
    OK();

    /* :98-108 — val2 votes at round+1: wrong step. */
    proto_vote(&w, g_v, 2, 1, 0 + 1, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
               &nil_bid);
    rc = sign_add_vote(&w, 2, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_UNEXPECTED_STEP,
          "expected VoteSet.Add to fail, wrong round");
    OK();

    /* :110-120 — val3 votes with the wrong TYPE. In the reference this is
     * refused by signAddVote itself (test_util.go:48-50) and never
     * reaches AddVote; the C helper mirrors that, so the assertion is on
     * the helper. Adding it through AddVote directly would give
     * ErrVoteUnexpectedStep (:186), which the next check shows. */
    proto_vote(&w, g_v, 3, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
               &nil_bid);
    rc = sign_add_vote(&w, 3, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added, "expected VoteSet.Add to fail, wrong type");
    OK();

    /* The same vote pushed past the helper: :186 refuses on TYPE. It is
     * unsigned, and that does not matter — :184-190 runs before :216. */
    rc = cmt_vote_set_add_vote(vs, g_v, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_UNEXPECTED_STEP,
          "AddVote refuses the wrong type at vote_set.go:186");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 3. TestVoteSet_2_3Majority — vote_set_test.go:124-172 ════════════ */

static int t_2_3_majority(void)
{
    world_t         w;
    cmt_vote_set_t *vs = NULL;
    cmt_block_id_t  nil_bid;
    cmt_block_id_t  some_bid;
    cmt_block_id_t  maj;
    bool            ok;
    bool            added;
    int32_t         i;

    /* :126 — ten validators of power 1. Quorum = TotalVotingPower*2/3+1
     * = 10*2/3+1 = 6+1 = 7 (vote_set.go:306). */
    CHECK(world_build_equal(&w, 10u, 1) == 0, "build 10 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    cmt_pb_block_id_init(&nil_bid);
    make_block_id(&some_bid, 0x41, 1u, 0x42);

    /* :137-147 — 6 out of 10 vote for nil: 6 < 7, no majority. */
    for (i = 0; i < 6; i++) {
        proto_vote(&w, g_v, i, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                   &nil_bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "the first six nil votes are added");
    }
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok &&
          cmt_block_id_is_zero(&maj), "there should be no 2/3 majority");
    OK();

    /* :149-159 — the 7th validator votes for a BLOCK, so nil still has 6
     * and the block has 1: no majority. */
    proto_vote(&w, g_v, 6, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &some_bid);
    CHECK(sign_add_vote(&w, 6, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the seventh vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok &&
          cmt_block_id_is_zero(&maj), "there should be no 2/3 majority");
    OK();

    /* :161-171 — the 8th votes nil: nil reaches 7 = quorum. */
    proto_vote(&w, g_v, 7, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &nil_bid);
    CHECK(sign_add_vote(&w, 7, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the eighth vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && ok &&
          cmt_block_id_is_zero(&maj),
          "there should be 2/3 majority for nil");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 4. TestVoteSet_2_3MajorityRedux — vote_set_test.go:174-271 ═══════ */

static int t_2_3_majority_redux(void)
{
    world_t         w;
    cmt_vote_set_t *vs = NULL;
    cmt_block_id_t  bid;      /* the block everyone is voting for          */
    cmt_block_id_t  variant;  /* a near-miss                               */
    cmt_block_id_t  maj;
    bool            ok;
    bool            added;
    int32_t         i;

    /* :176 — one hundred validators of power 1. Quorum = 100*2/3+1
     * = 66+1 = 67. :179-180 — blockPartsTotal 123. */
    CHECK(world_build_equal(&w, 100u, 1) == 0, "build 100 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    make_block_id(&bid, 0x51, 123u, 0x52);

    /* :192-203 — 66 of 100 vote for the block: 66 < 67. */
    for (i = 0; i < 66; i++) {
        proto_vote(&w, g_v, i, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "the first 66 votes are added");
    }
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok,
          "there should be no 2/3 majority");
    OK();

    /* :205-216 — the 67th votes with NO BLOCK HASH but the same part-set
     * header (withBlockHash(vote, nil), :211). That is a different
     * blockKey, so the block still has 66. */
    variant          = bid;
    variant.hash_len = 0u;
    memset(variant.hash, 0, sizeof(variant.hash));
    proto_vote(&w, g_v, 66, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &variant);
    CHECK(sign_add_vote(&w, 66, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the hash-less vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok,
          "no 2/3 majority: last vote added was nil");
    OK();

    /* :218-230 — the 68th votes with a different part-set HASH. */
    make_block_id(&variant, 0x51, 123u, 0x99);
    proto_vote(&w, g_v, 67, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &variant);
    CHECK(sign_add_vote(&w, 67, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the different-PartSetHeader-hash vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok,
          "no 2/3 majority: last vote added had different PartSetHeader Hash");
    OK();

    /* :232-244 — the 69th votes with part-set TOTAL 124 = 123 + 1. */
    make_block_id(&variant, 0x51, 123u + 1u, 0x52);
    proto_vote(&w, g_v, 68, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &variant);
    CHECK(sign_add_vote(&w, 68, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the different-PartSetHeader-total vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok,
          "no 2/3 majority: last vote added had different PartSetHeader Total");
    OK();

    /* :246-257 — the 70th votes with a different BLOCK HASH. */
    make_block_id(&variant, 0x77, 123u, 0x52);
    proto_vote(&w, g_v, 69, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &variant);
    CHECK(sign_add_vote(&w, 69, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the different-BlockHash vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && !ok,
          "no 2/3 majority: last vote added had different BlockHash");
    OK();

    /* :259-270 — the 71st votes for the RIGHT block: 67 = quorum. */
    proto_vote(&w, g_v, 70, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
    CHECK(sign_add_vote(&w, 70, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the 71st vote is added");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && ok &&
          cmt_block_id_equals(&maj, &bid), "there should be 2/3 majority");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 5. TestVoteSet_Conflicts — vote_set_test.go:273-400 ══════════════ */

static int t_conflicts(void)
{
    world_t            w;
    cmt_vote_set_t    *vs = NULL;
    cmt_block_id_t     nil_bid;
    cmt_block_id_t     bh1;
    cmt_block_id_t     bh2;
    cmt_block_id_t     maj;
    cmt_peer_id_t      peer_a;
    cmt_peer_id_t      peer_b;
    bool               ok;
    bool               added;
    cmt_vote_set_err_t err;
    int                rc;

    /* :275 — FOUR validators of power 1. Quorum = 4*2/3+1 = 2+1 = 3, and
     * HasTwoThirdsAny is `sum > 4*2/3` = `sum > 2` (vote_set.go:458). */
    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    cmt_pb_block_id_init(&nil_bid);
    /* :276-277 — blockHash1 and blockHash2, with the zero PartSetHeader
     * the voteProto of :286 carries. */
    cmt_pb_block_id_init(&bh1);
    memset(bh1.hash, 0xA1, (size_t)CMT_TMHASH_SIZE);
    bh1.hash_len = (size_t)CMT_TMHASH_SIZE;
    cmt_pb_block_id_init(&bh2);
    memset(bh2.hash, 0xB2, (size_t)CMT_TMHASH_SIZE);
    bh2.hash_len = (size_t)CMT_TMHASH_SIZE;
    memset(&peer_a, 0xAA, sizeof(peer_a));
    memset(&peer_b, 0xBB, sizeof(peer_b));

    /* :293-300 — val0 votes for nil. */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &nil_bid);
    CHECK(sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL) == CMT_OK && added,
          "expected VoteSet.Add to succeed");
    OK();

    /* :302-308 — val0 votes again for blockHash1: refused, conflicting. */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh1);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES, "conflicting vote");
    OK();

    /* :310-312 — start tracking blockHash1 for peerA. */
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer_a, &bh1, &err) == CMT_OK,
          "SetPeerMaj23(peerA, blockHash1)");
    OK();

    /* :314-320 — val0 votes for blockHash1 again. ⚠ THE KEY ASSERTION OF
     * THIS SCENARIO: added is TRUE and there is STILL an error. The two
     * outputs are independent (vote_set.go:326 returns `true,
     * conflicting`; :236 turns that into the error). */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh1);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && added &&
          err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES,
          "called SetPeerMaj23(): added AND conflicting");
    OK();

    /* :322-324 — peerA now claims blockHash2: refused, it already spoke. */
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer_a, &bh2, &err) == CMT_REJECT &&
          err == CMT_VOTE_SET_ERR_PEER_MAJ23_CONFLICT,
          "attempt tracking blockHash2 fails, already set for peerA");
    OK();

    /* :326-332 — val0 votes for blockHash2: nothing tracks it, refused. */
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh2);
    rc = sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && !added &&
          err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES,
          "duplicate SetPeerMaj23() from peerA");
    OK();

    /* :334-344 — val1 votes for blockHash1: its first vote, so it is
     * canonical and sum becomes 2. */
    proto_vote(&w, g_v, 1, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh1);
    CHECK(sign_add_vote(&w, 1, g_v, vs, &added, &err, NULL) == CMT_OK && added,
          "expected VoteSet.Add to succeed");
    OK();

    /* :346-352 — blockHash1 has val0 and val1 = 2 < quorum 3, and
     * sum = 2 is not > 2. */
    CHECK(!cmt_vote_set_has_two_thirds_majority(vs),
          "we shouldn't have 2/3 majority yet");
    CHECK(cmt_vote_set_has_two_thirds_any(vs, &ok) == CMT_OK && !ok,
          "we shouldn't have 2/3 if any votes yet");
    OK();

    /* :354-364 — val2 votes for blockHash2: canonical, sum becomes 3. */
    proto_vote(&w, g_v, 2, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh2);
    CHECK(sign_add_vote(&w, 2, g_v, vs, &added, &err, NULL) == CMT_OK && added,
          "expected VoteSet.Add to succeed");
    OK();

    /* :366-372 — still no majority for one block, but sum = 3 > 2. */
    CHECK(!cmt_vote_set_has_two_thirds_majority(vs),
          "we shouldn't have 2/3 majority yet");
    CHECK(cmt_vote_set_has_two_thirds_any(vs, &ok) == CMT_OK && ok,
          "we should have 2/3 if any votes");
    OK();

    /* :374-376 — peerB claims blockHash1 too. Its blockVotes already has
     * peerMaj23 set, so :356-358 is "nothing to do" and it still
     * succeeds. */
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer_b, &bh1, &err) == CMT_OK,
          "now attempt tracking blockHash1");
    OK();

    /* :378-387 — val2 votes for blockHash1: conflicting with its own
     * blockHash2 vote, but blockHash1 is vouched for, so it is stored.
     * blockHash1 now has val0, val1, val2 = 3 = quorum. */
    proto_vote(&w, g_v, 2, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bh1);
    rc = sign_add_vote(&w, 2, g_v, vs, &added, &err, NULL);
    CHECK(rc == CMT_REJECT && added &&
          err == CMT_VOTE_SET_ERR_CONFLICTING_VOTES,
          "added, and still a conflicting vote");
    OK();

    /* :389-399 — the majority is blockHash1, and sum is still 3 > 2. */
    CHECK(cmt_vote_set_has_two_thirds_majority(vs),
          "we should have 2/3 majority for blockHash1");
    CHECK(cmt_vote_set_two_thirds_majority(vs, &maj, &ok) == CMT_OK && ok &&
          maj.hash_len == bh1.hash_len &&
          memcmp(maj.hash, bh1.hash, bh1.hash_len) == 0,
          "got the wrong 2/3 majority blockhash");
    CHECK(cmt_vote_set_has_two_thirds_any(vs, &ok) == CMT_OK && ok,
          "we should have 2/3 if any votes");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 6. TestVoteSet_MakeCommit — vote_set_test.go:402-477 ═════════════ */

static int t_make_commit(void)
{
    world_t                    w;
    cmt_vote_set_t            *vs = NULL;
    cmt_block_id_t             bid;
    cmt_block_id_t             other;
    cmt_block_id_t             nil_bid;
    cmt_extended_commit_sig_t *sigs;
    cmt_extended_commit_t      ec;
    cmt_abci_params_t          ap;
    bool                       added;
    int32_t                    i;
    size_t                     absent = 0u;
    size_t                     k;

    /* :404 — ten validators, PRECOMMIT, extEnabled = true, so the set is
     * a NewExtendedVoteSet. Quorum = 10*2/3+1 = 7. */
    CHECK(world_build_equal(&w, 10u, 1) == 0, "build 10 validators");
    CHECK(cmt_new_extended_vote_set(g_chain, sizeof(g_chain), 1, 0,
                                    (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                    &w.vs, &vs) == CMT_OK,
          "NewExtendedVoteSet");
    make_block_id(&bid, 0x61, 123u, 0x62);
    make_block_id(&other, 0x71, 123u, 0x72);
    cmt_pb_block_id_init(&nil_bid);
    sigs = (cmt_extended_commit_sig_t *)calloc(10u, sizeof(*sigs));
    CHECK(sigs != NULL, "sigs");

    /* :417-427 — 6 of 10 precommit the block. */
    for (i = 0; i < 6; i++) {
        proto_vote(&w, g_v, i, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "the first six precommits are added");
    }

    /* :429-431 — MakeExtendedCommit must refuse: no +2/3 for any block.
     * The reference PANICS (vote_set.go:644-646); the port returns
     * CMT_FAULT, the class this file's header explains. */
    ap.vote_extensions_enable_height = 1;                        /* :430 */
    CHECK(cmt_vote_set_make_extended_commit(vs, ap, sigs, 10u, &ec) ==
          CMT_FAULT, "Doesn't have +2/3 majority");
    OK();

    /* :433-444 — the 7th precommits a DIFFERENT block. */
    proto_vote(&w, g_v, 6, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &other);
    CHECK(sign_add_vote(&w, 6, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the seventh precommit is added");

    /* :446-454 — the 8th votes like everyone else: 7 = quorum. */
    proto_vote(&w, g_v, 7, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &bid);
    CHECK(sign_add_vote(&w, 7, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the eighth precommit is added");
    CHECK(cmt_vote_set_has_two_thirds_majority(vs), "majority at the 7th");
    OK();

    /* :456-466 — the 9th precommits NIL. A nil precommit carries no
     * extension signature (vote.go:443 requires one only for a non-nil
     * precommit), which is why this is legal in an extended set. */
    proto_vote(&w, g_v, 8, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
               &nil_bid);
    CHECK(sign_add_vote(&w, 8, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the nil precommit is added");
    OK();

    /* :468-476 — the commit has TEN entries and passes ValidateBasic. */
    CHECK(cmt_vote_set_make_extended_commit(vs, ap, sigs, 10u, &ec) == CMT_OK,
          "MakeExtendedCommit");
    CHECK(ec.extended_signatures_len == 10u, "Commit should have 10 elements");
    CHECK(cmt_extended_commit_validate_basic(&ec) == CMT_OK,
          "error in Commit.ValidateBasic()");
    OK();

    /* Derived, not from the reference: index 6 voted for `other` so
     * :653-655 replaced it with an ABSENT entry, and index 9 never voted
     * so :651 produced one — two ABSENT entries, seven COMMIT and one
     * NIL. This is the assertion that would fail if the maj23 filter were
     * dropped. */
    for (k = 0; k < 10u; k++) {
        if (sigs[k].commit_sig.block_id_flag ==
            (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT) {
            absent++;
        }
    }
    CHECK(absent == 2u, "exactly two ABSENT entries: index 6 and index 9");
    CHECK(sigs[6].commit_sig.block_id_flag ==
          (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT,
          "the validator that voted for another block is ABSENT");
    CHECK(sigs[8].commit_sig.block_id_flag ==
          (int32_t)CMT_PB_BLOCK_ID_FLAG_NIL, "the nil precommit is NIL");
    CHECK(sigs[9].commit_sig.block_id_flag ==
          (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT,
          "the validator that never voted is ABSENT (vote.go:129-131)");
    OK();

    free(sigs);
    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 7. TestVoteSet_VoteExtensionsEnabled — vote_set_test.go:479-560 ══ */

/* One row of the reference's table (:482-512). Its first two rows —
 * "no extension but expected" (:488-493) and "invalid extensions but not
 * expected" (:494-499) — carry IDENTICAL field values {true, false,
 * true} under different names, so they exercise one path; the table below
 * carries the three distinct rows. */
struct ext_case {
    const char *name;
    bool        require_extensions;
    bool        add_extension;
    bool        expect_error;
};

static int t_vote_extensions_enabled(void)
{
    static const struct ext_case cases[] = {
        /* :488-493 and :494-499 — the same row twice in the reference. */
        { "no extension but expected",        true,  false, true  },
        /* :500-505 */
        { "no extension and not expected",    false, false, false },
        /* :506-511 */
        { "extension and expected",           true,  true,  false },
    };
    world_t         w;
    cmt_block_id_t  bid;
    size_t          c;

    /* :515 — five validators of power 10. */
    CHECK(world_build_equal(&w, 5u, 10) == 0, "build 5 validators");
    make_block_id(&bid, 0x81, 123u, 0x82);

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        cmt_vote_set_t    *vs = NULL;
        struct signer_ctx  sc;
        bool               added = false;
        cmt_vote_set_err_t err   = CMT_VOTE_SET_ERR_NONE;
        int                rc;

        if (cases[c].require_extensions) {                       /* :517-518 */
            CHECK(cmt_new_extended_vote_set(g_chain, sizeof(g_chain), 1, 0,
                                            (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                            &w.vs, &vs) == CMT_OK,
                  "NewExtendedVoteSet");
        } else {                                                 /* :519-520 */
            CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                                   (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                   &w.vs, &vs) == CMT_OK, "NewVoteSet");
        }
        /* :532-548 — the reference builds and signs the vote BY HAND, not
         * through SignAndCheckVote, and then keeps the extension
         * signature only when the case says to. Mirrored exactly. */
        proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                   &bid);
        sc.sk = g_sk[w.key_of_index[0]];
        CHECK(real_sign(&sc, g_chain, sizeof(g_chain), g_v) == CMT_OK,
              "SignVote");
        if (!cases[c].add_extension) {                           /* :546-548 */
            g_v->extension_signature_len = 0u;
        }

        rc = cmt_vote_set_add_vote(vs, g_v, &added, &err, NULL); /* :550 */
        if (cases[c].expect_error) {                             /* :551-553 */
            /* An extended set with no extension signature: vote.go:249-251
             * "expected vote extension signature", which R1's verify
             * collapses to CMT_REJECT. */
            CHECK(rc == CMT_REJECT && !added &&
                  err == CMT_VOTE_SET_ERR_VERIFY_FAILED, cases[c].name);
        } else {                                                 /* :554-556 */
            CHECK(rc == CMT_OK && added, cases[c].name);
        }
        OK();
        cmt_vote_set_free(vs);
    }
    world_free(&w);
    return 0;
}

/* ══ 8. weight versus count — NOT from the reference ══════════════════ */

/*
 * Every scenario above gives every validator the same power, so a port
 * that counted VOTES instead of summing POWER would pass all of them.
 *
 * DERIVATION. Powers {7, 1, 1, 1}: TotalVotingPower = 10, quorum =
 * 10*2/3+1 = 6+1 = 7 (vote_set.go:306). cmt_validator_set_new sorts by
 * power DESCENDING (validator_set.go:851-856), so the power-7 validator
 * is at set index 0. ONE vote from it reaches the quorum where THREE
 * votes from the others (1+1+1 = 3) do not.
 */
static int t_unequal_powers(void)
{
    static const int64_t powers[4] = { 7, 1, 1, 1 };
    world_t              w;
    cmt_vote_set_t      *vs = NULL;
    cmt_block_id_t       bid;
    int64_t              total = 0;
    bool                 added;
    bool                 ok;
    int32_t              i;

    CHECK(world_build(&w, 4u, powers) == 0, "build 4 validators");
    CHECK(cmt_validator_set_total_voting_power(&w.vs, &total) == CMT_OK &&
          total == 10, "total voting power is 10");
    CHECK(w.vs.validators[0].voting_power == 7,
          "the power-7 validator sorts first");
    OK();

    /* The three power-1 validators vote: 3 < 7, no majority. */
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    make_block_id(&bid, 0x91, 5u, 0x92);
    for (i = 1; i < 4; i++) {
        proto_vote(&w, g_v, i, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "the three light votes are added");
    }
    CHECK(!cmt_vote_set_has_two_thirds_majority(vs),
          "three votes of power 1 are not a majority of 10");
    CHECK(cmt_vote_set_has_two_thirds_any(vs, &ok) == CMT_OK && !ok,
          "sum 3 is not > 10*2/3 = 6");
    OK();
    cmt_vote_set_free(vs);

    /* The power-7 validator alone reaches the quorum. */
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
    CHECK(sign_add_vote(&w, 0, g_v, vs, &added, NULL, NULL) == CMT_OK && added,
          "the heavy vote is added");
    CHECK(cmt_vote_set_has_two_thirds_majority(vs),
          "one vote of power 7 IS a majority of 10");
    CHECK(cmt_vote_set_has_two_thirds_any(vs, &ok) == CMT_OK && ok,
          "sum 7 is > 6");
    CHECK(cmt_vote_set_has_all(vs, &ok) == CMT_OK && !ok,
          "7 is not all of 10");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 9. the C-only capacity bounds ════════════════════════════════════ */

/*
 * CMT_PEER_MAX distinct peers may claim a majority; the next one is
 * refused. All of them name the SAME block here, so this exercises the
 * peer table alone: the block table gets exactly one entry.
 */
static int t_peer_maj23_capacity(void)
{
    world_t            w;
    cmt_vote_set_t    *vs = NULL;
    cmt_block_id_t     bid;
    cmt_peer_id_t      peer;
    cmt_vote_set_err_t err;
    int                i;

    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    make_block_id(&bid, 0xA5, 3u, 0xA6);

    for (i = 0; i < CMT_PEER_MAX; i++) {
        memset(&peer, 0, sizeof(peer));
        peer.id[0] = (uint8_t)(i & 0xFF);
        peer.id[1] = (uint8_t)((i >> 8) & 0xFF);
        /* i == 0 gives the all-zero id, which is the reference's "" (the
         * node's own messages, height_vote_set.go:132). It is stored and
         * looked up like any other key, which is the point. */
        CHECK(cmt_vote_set_set_peer_maj23(vs, peer, &bid, &err) == CMT_OK,
              "the first CMT_PEER_MAX peers are accepted");
    }
    memset(&peer, 0xEE, sizeof(peer));
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer, &bid, &err) == CMT_REJECT &&
          err == CMT_VOTE_SET_ERR_PEER_CAPACITY,
          "the 129th distinct peer is refused");
    OK();

    /* A repeat from a peer already in the table still works, and still
     * costs no slot (vote_set.go:345-347). */
    memset(&peer, 0, sizeof(peer));
    peer.id[0] = 5u;
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer, &bid, &err) == CMT_OK,
          "a repeat claim from a known peer is nothing to do");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/*
 * Fill the block table to its DERIVED capacity and check nothing
 * overruns. See "how it can lie" item 3: the CMT_REJECT branch cannot be
 * reached through the public API, because the capacity IS the reference's
 * own bound — CMT_PEER_MAX peer claims plus at most one first-vote block
 * per validator.
 */
static int t_block_table_capacity(void)
{
    world_t            w;
    cmt_vote_set_t    *vs = NULL;
    cmt_block_id_t     bid;
    cmt_peer_id_t      peer;
    cmt_vote_set_err_t err;
    bool               added;
    size_t             used = 0u;
    size_t             k;
    int                i;

    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");

    /* CMT_PEER_MAX peers, each naming a DIFFERENT block. */
    for (i = 0; i < CMT_PEER_MAX; i++) {
        memset(&peer, 0, sizeof(peer));
        peer.id[0] = (uint8_t)(i & 0xFF);
        peer.id[1] = (uint8_t)((i >> 8) & 0xFF);
        make_block_id(&bid, (uint8_t)i, (uint32_t)(i + 1), (uint8_t)(i + 3));
        CHECK(cmt_vote_set_set_peer_maj23(vs, peer, &bid, &err) == CMT_OK,
              "each peer's distinct block is tracked");
    }
    /* And four more from first votes. For a set of FOUR validators the
     * reference's bound (vote_set.go:44-57) is N + P = 4 + 128 = 132; the
     * table itself is CMT_VALSET_MAX + CMT_PEER_MAX = 256 slots, sized
     * for the largest set this port accepts, so 132 is the most this
     * particular set can ever reach. */
    for (i = 0; i < 4; i++) {
        make_block_id(&bid, (uint8_t)(200 + i), (uint32_t)(500 + i),
                      (uint8_t)(210 + i));
        proto_vote(&w, g_v, (int32_t)i, 1, 0,
                   (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
        CHECK(sign_add_vote(&w, (int32_t)i, g_v, vs, &added, &err, NULL) ==
              CMT_OK && added, "each validator's own first block is tracked");
    }
    for (k = 0; k < (size_t)CMT_VOTE_SET_MAX_BLOCKS; k++) {
        if (vs->votes_by_block[k].used) {
            used++;
        }
    }
    CHECK(used == (size_t)CMT_PEER_MAX + 4u,
          "132 blocks = 128 peer claims + one first-vote block per validator");
    CHECK(used <= (size_t)CMT_VOTE_SET_MAX_BLOCKS,
          "and the derived bound is inside the table");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/*
 * WHITE BOX. The two call sites of `new_block_votes` must REFUSE when the
 * table is full, never write past its end. The derivation says a real
 * peer cannot get the table there (see `t_block_table_capacity`), so the
 * table is filled BY HAND: every slot is marked occupied with a
 * zero-length key. `votes` is left NULL, which `cmt_vote_set_free`
 * handles (`free(NULL)`).
 *
 * ⚠ A ZERO-LENGTH KEY IS NOT AN IMPOSSIBLE KEY. `cmt_block_id_key` is the
 * hash bytes followed by the marshalled PartSetHeader (cmt_block.c:187-191,
 * block.go:1474-1483), and BOTH are empty for a nil BlockID — so the nil
 * block's key really is zero bytes, in this port and in the reference
 * (Go's `string(nil) + ""`). Every lookup in the caller below therefore
 * uses a NON-nil BlockID, whose key is at least the 64-byte hash; a nil
 * one would legitimately match a filled slot and take a different path.
 */
static int fill_block_table(cmt_vote_set_t *vs)
{
    size_t k;

    for (k = 0; k < (size_t)CMT_VOTE_SET_MAX_BLOCKS; k++) {
        vs->votes_by_block[k].used    = true;
        vs->votes_by_block[k].key_len = 0u;
    }
    return 0;
}

static int t_block_table_exhausted(void)
{
    world_t            w;
    cmt_vote_set_t    *vs = NULL;
    cmt_block_id_t     bid;
    cmt_peer_id_t      peer;
    cmt_vote_set_err_t err;
    bool               added;

    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    make_block_id(&bid, 0xF1, 21u, 0xF2);
    memset(&peer, 0x3C, sizeof(peer));

    /* Call site 1 — SetPeerMaj23's newBlockVotes (vote_set.go:362-363). */
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    CHECK(fill_block_table(vs) == 0, "fill");
    CHECK(cmt_vote_set_set_peer_maj23(vs, peer, &bid, &err) == CMT_REJECT &&
          err == CMT_VOTE_SET_ERR_BLOCK_CAPACITY,
          "SetPeerMaj23 refuses when the block table is full");
    OK();
    cmt_vote_set_free(vs);
    vs = NULL;

    /* Call site 2 — addVerifiedVote's newBlockVotes (vote_set.go:299-300),
     * on the no-conflict path. ⚠ The refusal happens AFTER `.votes` and
     * `.sum` were written (the reference cannot fail there), so the set is
     * left half-mutated and is discarded here — which is exactly what
     * cmt_vote_set.c's C-ONLY FAILURE MODE note tells the caller to do. */
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 1, 0,
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");
    CHECK(fill_block_table(vs) == 0, "fill");
    proto_vote(&w, g_v, 0, 1, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &bid);
    CHECK(sign_add_vote(&w, 0, g_v, vs, &added, &err, NULL) == CMT_REJECT &&
          !added && err == CMT_VOTE_SET_ERR_BLOCK_CAPACITY,
          "AddVote refuses when the block table is full");
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 10. the remaining accessors ══════════════════════════════════════ */

static int t_accessors(void)
{
    world_t           w;
    cmt_vote_set_t   *vs = NULL;
    cmt_block_id_t    bid;
    cmt_bit_array_t   ba;
    cmt_vote_t       *list;
    const cmt_vote_t *one = NULL;
    const uint8_t    *cid;
    size_t            cid_len = 0u;
    size_t            list_len = 0u;
    bool              added;
    bool              ok;
    int32_t           i;

    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 7, 3,
                           (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT, &w.vs,
                           &vs) == CMT_OK, "NewVoteSet");

    /* :110-144 — the five trivial accessors, and their nil answers. */
    cid = cmt_vote_set_chain_id(vs, &cid_len);
    CHECK(cid != NULL && cid_len == sizeof(g_chain) &&
          memcmp(cid, g_chain, cid_len) == 0, "ChainID");
    CHECK(cmt_vote_set_get_height(vs) == 7, "GetHeight");
    CHECK(cmt_vote_set_get_round(vs) == 3, "GetRound");
    CHECK(cmt_vote_set_type(vs) == (uint8_t)CMT_PB_MSG_TYPE_PRECOMMIT, "Type");
    CHECK(cmt_vote_set_size(vs) == 4, "Size");
    CHECK(cmt_vote_set_get_height(NULL) == 0, "GetHeight(nil) is 0");
    CHECK(cmt_vote_set_get_round(NULL) == -1, "GetRound(nil) is -1");
    CHECK(cmt_vote_set_type(NULL) == 0u, "Type(nil) is 0x00");
    CHECK(cmt_vote_set_size(NULL) == 0, "Size(nil) is 0");
    CHECK(!cmt_vote_set_has_two_thirds_majority(NULL),
          "HasTwoThirdsMajority(nil) is false");
    CHECK(!cmt_vote_set_is_commit(NULL), "IsCommit(nil) is false");
    OK();

    /* A precommit set with no majority is not a commit (:444-449). */
    CHECK(!cmt_vote_set_is_commit(vs), "no majority, not a commit");

    make_block_id(&bid, 0xC1, 9u, 0xC2);
    for (i = 0; i < 4; i++) {
        proto_vote(&w, g_v, i, 7, 3, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                   &bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "all four precommit");
    }
    /* Quorum = 4*2/3+1 = 3, so the majority arrived at the third vote and
     * all four make HasAll true. */
    CHECK(cmt_vote_set_is_commit(vs), "a precommit set with a majority IS a commit");
    CHECK(cmt_vote_set_has_all(vs, &ok) == CMT_OK && ok, "HasAll");
    OK();

    /* :370-390 — the two bit arrays. */
    CHECK(cmt_vote_set_bit_array(vs, &ba) == CMT_OK &&
          cmt_bits_size(&ba) == 4 &&
          cmt_bits_get_index(&ba, 0) == 1 && cmt_bits_get_index(&ba, 3) == 1,
          "BitArray has all four bits");
    CHECK(cmt_vote_set_bit_array_by_block_id(vs, &bid, &ba) == CMT_OK &&
          cmt_bits_get_index(&ba, 2) == 1, "BitArrayByBlockID");
    CHECK(cmt_vote_set_bit_array(NULL, &ba) == CMT_BITS_NIL,
          "BitArray(nil) is the reference's nil");
    {
        cmt_block_id_t untracked;

        make_block_id(&untracked, 0xD1, 11u, 0xD2);
        CHECK(cmt_vote_set_bit_array_by_block_id(vs, &untracked, &ba) ==
              CMT_BITS_NIL, "BitArrayByBlockID of an untracked block is nil");
    }
    OK();

    /* :392-401 — GetByIndex, and the C-only bound at an out-of-range one. */
    CHECK(cmt_vote_set_get_by_index(vs, 2, &one) == CMT_OK && one != NULL &&
          one->validator_index == 2, "GetByIndex(2)");
    CHECK(cmt_vote_set_get_by_index(vs, 4, &one) == CMT_REJECT,
          "GetByIndex past the end is refused, not undefined");
    CHECK(cmt_vote_set_get_by_index(vs, -1, &one) == CMT_REJECT,
          "GetByIndex(-1) is refused");
    OK();

    /* :403-415 — List. Heap, because four votes are ~38 KB. */
    list = (cmt_vote_t *)calloc(4u, sizeof(cmt_vote_t));
    CHECK(list != NULL, "list");
    CHECK(cmt_vote_set_list(vs, list, 4u, &list_len) == CMT_OK &&
          list_len == 4u, "List returns all four");
    CHECK(cmt_vote_set_list(vs, list, 3u, &list_len) == CMT_REJECT,
          "List refuses a short buffer");
    free(list);
    OK();

    /* :417-428 — GetByAddress with an address that is not a validator.
     * The reference panics; this port refuses. */
    {
        uint8_t stranger[CMT_ADDRESS_SIZE];

        memset(stranger, 0x5A, sizeof(stranger));
        CHECK(cmt_vote_set_get_by_address(vs, stranger, sizeof(stranger),
                                          &one) == CMT_REJECT,
              "GetByAddress of a non-validator is refused");
    }
    OK();

    /* :82-84 — height 0 is refused, where the reference panics. */
    {
        cmt_vote_set_t *bad = NULL;

        CHECK(cmt_vote_set_new(g_chain, sizeof(g_chain), 0, 0,
                               (int32_t)CMT_PB_MSG_TYPE_PREVOTE, &w.vs,
                               &bad) == CMT_REJECT,
              "Cannot make VoteSet for height == 0");
        CHECK(bad == NULL, "and nothing was allocated");
    }
    OK();

    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ 11. RoundStepType — round_state.go:33-60 ═════════════════════════ */

static int t_round_step(void)
{
    static const char *const expected[9] = {
        "RoundStepUnknown",         /* 0x00 — round_state.go:57-58 */
        "RoundStepNewHeight",       /* 0x01 — :41-42 */
        "RoundStepNewRound",        /* 0x02 — :43-44 */
        "RoundStepPropose",         /* 0x03 — :45-46 */
        "RoundStepPrevote",         /* 0x04 — :47-48 */
        "RoundStepPrevoteWait",     /* 0x05 — :49-50 */
        "RoundStepPrecommit",       /* 0x06 — :51-52 */
        "RoundStepPrecommitWait",   /* 0x07 — :53-54 */
        "RoundStepCommit",          /* 0x08 — :55-56 */
    };
    cmt_round_state_t rs;
    const char       *step = NULL;
    int64_t           h    = 0;
    int32_t           r    = 0;
    unsigned          i;

    /* :34-36 — IsValid is true exactly on 0x01..0x08. */
    for (i = 0; i <= 9u; i++) {
        bool want = (i >= 1u && i <= 8u);

        CHECK(cmt_round_step_is_valid((cmt_round_step_t)i) == want,
              "IsValid over 0..9");
    }
    OK();

    /* :39-59 — the eight strings, byte for byte. These go into the WAL
     * (types/events.go:92-97) and replay.go:55 compares them. */
    for (i = 0; i <= 8u; i++) {
        CHECK(strcmp(cmt_round_step_string((cmt_round_step_t)i),
                     expected[i]) == 0, "String over 0..8");
    }
    CHECK(strcmp(cmt_round_step_string((cmt_round_step_t)9u),
                 "RoundStepUnknown") == 0, "String(9) is the default");
    CHECK(strcmp(cmt_round_step_string((cmt_round_step_t)255u),
                 "RoundStepUnknown") == 0, "String(255) is the default");
    OK();

    /* :173-180 — RoundStateEvent hands out the three WAL fields. */
    cmt_round_state_init(&rs);
    CHECK(cmt_time_is_zero(rs.start_time) && cmt_time_is_zero(rs.commit_time),
          "a fresh RoundState carries Go's zero time, not the epoch");
    rs.height = 42;
    rs.round  = 3;
    rs.step   = CMT_ROUND_STEP_PRECOMMIT_WAIT;
    CHECK(cmt_round_state_event(&rs, &h, &r, &step) == CMT_OK && h == 42 &&
          r == 3 && strcmp(step, "RoundStepPrecommitWait") == 0,
          "RoundStateEvent");
    CHECK(cmt_round_state_event(NULL, &h, &r, &step) == CMT_FAULT,
          "RoundStateEvent(nil)");
    OK();

    return 0;
}

/* ══ 12. the ToVoteSet family — block.go:1071-1117 ════════════════════ */

static int t_to_vote_set(void)
{
    world_t                    w;
    cmt_vote_set_t            *vs  = NULL;
    cmt_vote_set_t            *out = NULL;
    cmt_block_id_t             bid;
    cmt_extended_commit_sig_t *esigs;
    cmt_commit_sig_t          *csigs;
    cmt_extended_commit_t      ec;
    cmt_commit_t               commit;
    cmt_abci_params_t          ap;
    cmt_bit_array_t            ba;
    cmt_block_id_t             maj;
    bool                       ok;
    bool                       added;
    int32_t                    i;

    CHECK(world_build_equal(&w, 4u, 1) == 0, "build 4 validators");
    CHECK(cmt_new_extended_vote_set(g_chain, sizeof(g_chain), 5, 2,
                                    (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                                    &w.vs, &vs) == CMT_OK,
          "NewExtendedVoteSet");
    make_block_id(&bid, 0xE1, 17u, 0xE2);
    esigs = (cmt_extended_commit_sig_t *)calloc(4u, sizeof(*esigs));
    csigs = (cmt_commit_sig_t *)calloc(4u, sizeof(*csigs));
    CHECK(esigs != NULL && csigs != NULL, "sig storage");

    /* Three of four precommit the block: quorum = 4*2/3+1 = 3. */
    for (i = 0; i < 3; i++) {
        proto_vote(&w, g_v, i, 5, 2, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                   &bid);
        CHECK(sign_add_vote(&w, i, g_v, vs, &added, NULL, NULL) == CMT_OK &&
              added, "three precommits");
    }
    ap.vote_extensions_enable_height = 5;
    CHECK(cmt_vote_set_make_extended_commit(vs, ap, esigs, 4u, &ec) == CMT_OK,
          "MakeExtendedCommit");

    /* block.go:1071-1079 — ToExtendedVoteSet rebuilds the set, extension
     * signatures and all. */
    CHECK(cmt_extended_commit_to_extended_vote_set(&ec, g_chain,
                                                   sizeof(g_chain), &w.vs,
                                                   &out) == CMT_OK,
          "ToExtendedVoteSet");
    CHECK(cmt_vote_set_has_two_thirds_majority(out),
          "the rebuilt extended set has the majority");
    CHECK(cmt_vote_set_two_thirds_majority(out, &maj, &ok) == CMT_OK && ok &&
          cmt_block_id_equals(&maj, &bid), "and it is the same block");
    CHECK(cmt_vote_set_bit_array(out, &ba) == CMT_OK &&
          cmt_bits_get_index(&ba, 0) == 1 && cmt_bits_get_index(&ba, 1) == 1 &&
          cmt_bits_get_index(&ba, 2) == 1 && cmt_bits_get_index(&ba, 3) == 0,
          "the bit array is exactly the three signers");
    OK();
    cmt_vote_set_free(out);
    out = NULL;

    /* block.go:1130-1143 — ToCommit is R1's cmt_extended_commit_to_commit
     * (cmt_block.h:603); this wave does not re-port it. Its output feeds
     * block.go:1098-1117 ToVoteSet, which drops the extensions, so the
     * rebuilt set must be a PLAIN one. */
    CHECK(cmt_extended_commit_to_commit(&ec, csigs, 4u, &commit) == CMT_OK,
          "ExtendedCommit.ToCommit");
    CHECK(cmt_commit_to_vote_set(&commit, g_chain, sizeof(g_chain), &w.vs,
                                 &out) == CMT_OK, "Commit.ToVoteSet");
    CHECK(cmt_vote_set_has_two_thirds_majority(out),
          "the rebuilt set has the majority");
    CHECK(cmt_vote_set_is_commit(out), "and it is a commit");
    CHECK(cmt_vote_set_bit_array(out, &ba) == CMT_OK &&
          cmt_bits_get_index(&ba, 0) == 1 && cmt_bits_get_index(&ba, 3) == 0,
          "the bit array is the commit's signers");
    OK();

    cmt_vote_set_free(out);
    free(esigs);
    free(csigs);
    cmt_vote_set_free(vs);
    world_free(&w);
    return 0;
}

/* ══ main ═════════════════════════════════════════════════════════════ */

int main(void)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_PB_CHAINID_MAX; i++) {
        g_chain[i] = (uint8_t)(0x40u + i);
    }
    for (i = 0; i < (size_t)MAXVALS; i++) {
        uint8_t seed[32];

        memset(seed, 0, sizeof(seed));
        seed[0] = (uint8_t)(i & 0xFFu);
        seed[1] = 0x5Au;
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) {
            fprintf(stderr, "keypair %zu failed\n", i);
            return 1;
        }
    }
    g_v    = (cmt_vote_t *)malloc(sizeof(cmt_vote_t));
    g_conf = (cmt_vote_t *)malloc(sizeof(cmt_vote_t));
    if (g_v == NULL || g_conf == NULL) {
        fprintf(stderr, "vote buffers failed\n");
        return 1;
    }

    if (t_add_vote_good() != 0)          { return 1; }
    if (t_add_vote_bad() != 0)           { return 1; }
    if (t_2_3_majority() != 0)           { return 1; }
    if (t_2_3_majority_redux() != 0)     { return 1; }
    if (t_conflicts() != 0)              { return 1; }
    if (t_make_commit() != 0)            { return 1; }
    if (t_vote_extensions_enabled() != 0){ return 1; }
    if (t_unequal_powers() != 0)         { return 1; }
    if (t_peer_maj23_capacity() != 0)    { return 1; }
    if (t_block_table_capacity() != 0)   { return 1; }
    if (t_block_table_exhausted() != 0)  { return 1; }
    if (t_accessors() != 0)              { return 1; }
    if (t_round_step() != 0)             { return 1; }
    if (t_to_vote_set() != 0)            { return 1; }

    free(g_v);
    free(g_conf);
    printf("test_cmt_vote_set: %d checks passed\n", g_checks);
    return 0;
}
