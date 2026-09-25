/**
 * Nodus — cometbft @709fd12b C port, wave R2-A:
 * `consensus/types/height_vote_set.go` (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a height's vote sets appear and disappear exactly where cometbft
 * says, and that a peer cannot make a node allocate rounds without bound.
 * If this file failed, one of these would be false:
 *   · a peer gets TWO catch-up rounds and no more — two votes at unknown
 *     rounds from the same peer are accepted, the third is refused with
 *     ErrGotVoteFromUnwantedRound, and the SAME third vote from a
 *     DIFFERENT peer is accepted (height_vote_set_test.go:26-56
 *     TestPeerCatchupRounds);
 *   · an extensions-enabled HeightVoteSet refuses a vote presented as
 *     extension-free, and a plain one refuses a vote presented as
 *     extension-carrying — the reference panics in both directions
 *     (:58-73 TestInconsistentExtensionData);
 *   · SetRound creates every round up to the one asked for AND, on the
 *     first call of a height, a round -1 — the reference's own arithmetic
 *     at height_vote_set.go:100/:104 with safemath.go:25-32, reproduced
 *     rather than corrected;
 *   · SetRound refuses to go backwards by more than one round (:101-103);
 *   · POLInfo answers -1 with a zero BlockID until a round has a +2/3
 *     prevote majority, and then that round and that block (:170-183);
 *   · Reset drops every round of the old height and leaves exactly round
 *     0 at round 0 (:71-82);
 *   · SetPeerMaj23 is silent about a round it does not track (:215-217)
 *     and refuses a type that is not a vote type (:211-213);
 *   · the C-only bound holds: the 129th distinct peer asking for a
 *     catch-up round is refused instead of growing an unbounded map.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A DEFAULT BUILD. No compile flags, no environment variables, no
 * network, no files, no clock. Keys come from `qgp_dsa87_keypair_derand`
 * with fixed seeds and every timestamp is a constant, so nothing here is
 * random or time-dependent. Safe under `ctest -j`.
 *
 * ⚠ PEAK MEMORY. `t_peer_catchup_capacity` deliberately drives 129
 * distinct peers to 129 distinct rounds, which is 129 × 2 vote sets. A
 * vote set's fixed tables (256 block slots and 128 peer slots) are about
 * 130 KB, so that section peaks near 35 MB before it frees. That is the
 * price of testing the bound at the bound; it is transient and the
 * section frees everything.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. Every validator has voting power 1, as the reference's own fixture
 *     does (height_vote_set_test.go:27, RandValidatorSet(10, 1)), so
 *     nothing here can tell weight from count. That distinction is
 *     covered in test_cmt_vote_set.c's `t_unequal_powers`, not here.
 *  2. ML-DSA-87 signing is HEDGED; no signature is frozen or compared.
 *  3. The timestamps are constants where the reference calls
 *     `cmttime.Now()` (:92). A timestamp changes the sign bytes and
 *     nothing else, and no assertion here reads one.
 *  4. `TestInconsistentExtensionData` checks that the port REFUSES where
 *     the reference PANICS. It cannot check that the process dies,
 *     because this port deliberately does not die; a green means "CMT_
 *     FAULT was returned", not "the node stopped".
 *  5. Nothing here runs a reactor or a state machine. A green says the
 *     height vote set is right, not that anything drives it correctly.
 *
 * Reference test source @709fd12b, SHA-256 verified before use:
 *   consensus/types/height_vote_set_test.go  99 lines
 *     d9868ce29207cf764bef5b281e0714ae7d979623d673fa8a16fbdec6e8143a84
 *   types/test_util.go                      123 lines
 *     32333c3ef6fb373706e8d7d6b87723c08d9c5b35d0b23094eb42178a8ae8caf2
 *
 * @file test_cmt_hvs.c
 */

#include "dnac/cmt_hvs.h"
#include "dnac/cmt_validator_set.h"

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

/* height_vote_set_test.go:27 — RandValidatorSet(10, 1). */
#define NVALS 10

static uint8_t g_pk[NVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NVALS][QGP_DSA87_SECRETKEYBYTES];

/* The chain id: 32 raw bytes, the approved substitution for the
 * reference's `test.DefaultTestChainID` string (:29). */
static uint8_t g_chain[CMT_PB_CHAINID_MAX];

/* A fixed stamp where the reference calls cmttime.Now() (:92). */
static const cmt_time_t G_TS = { 1700000000, 0 };

static cmt_validator_t      g_storage[NVALS];
static cmt_validator_set_t  g_vs;
static cmt_valset_scratch_t *g_scratch;
static int                  g_key_of_index[NVALS];
static cmt_vote_t          *g_v;

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static int build_set(void)
{
    cmt_validator_t *list;
    size_t           i;
    size_t           j;

    list = (cmt_validator_t *)calloc(NVALS, sizeof(cmt_validator_t));
    if (list == NULL) {
        return 1;
    }
    for (i = 0; i < (size_t)NVALS; i++) {
        cmt_pb_public_key_t pk;

        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, 1, &list[i]) != CMT_OK) {
            free(list);
            return 1;
        }
    }
    if (cmt_validator_set_init(&g_vs, g_storage, NVALS) != CMT_OK ||
        cmt_validator_set_new(&g_vs, list, NVALS, g_scratch) != CMT_OK) {
        free(list);
        return 1;
    }
    free(list);
    /* cmt_validator_set_new sorts by power then address; with equal
     * powers that is address order, which is the order RandValidatorSet
     * produces for the reference (validator_set.go:986). */
    for (i = 0; i < (size_t)NVALS; i++) {
        g_key_of_index[i] = -1;
        for (j = 0; j < (size_t)NVALS; j++) {
            uint8_t addr[CMT_ADDRESS_SIZE];

            if (cmt_pubkey_address(g_pk[j], addr) != CMT_OK) {
                return 1;
            }
            if (g_vs.validators[i].address_len == (size_t)CMT_ADDRESS_SIZE &&
                memcmp(g_vs.validators[i].address, addr,
                       CMT_ADDRESS_SIZE) == 0) {
                g_key_of_index[i] = (int)j;
                break;
            }
        }
        if (g_key_of_index[i] < 0) {
            return 1;
        }
    }
    return 0;
}

static void make_block_id(cmt_block_id_t *bid, uint8_t seed)
{
    size_t i;

    /* height_vote_set_test.go:91 — BlockID{Hash: randBytes, PartSetHeader{}}.
     * `randBytes` is `cmtrand.Bytes(tmhash.Size)`, 32 bytes there and
     * CMT_TMHASH_SIZE (64) here under the SHA3-512 substitution. It is a
     * FIXED pattern here, not random: a test must not draw randomness. */
    cmt_pb_block_id_init(bid);
    for (i = 0; i < (size_t)CMT_TMHASH_SIZE; i++) {
        bid->hash[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
    bid->hash_len = (size_t)CMT_TMHASH_SIZE;
}

struct signer_ctx {
    const uint8_t *sk;
};

/* Stands in for PrivValidator.SignVote (types/vote.go:418): the signature
 * always, and the extension signature exactly when the vote is a non-nil
 * precommit — what SignAndCheckVote's :435 and :443 demand. */
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

/*
 * cometbft@709fd12b consensus/types/height_vote_set_test.go:75-99 —
 * makeVoteHR(). Builds a PRECOMMIT for (height, round) from the validator
 * at `val_index`, signed through `types.MakeVote` (test_util.go:57-88),
 * whose `extensionsEnabled := step == PrecommitType` (:82) is true — so
 * the extension signature is kept.
 */
static int make_vote_hr(cmt_vote_t *v, int64_t height, int32_t val_index,
                        int32_t round, int32_t type, bool extensions_enabled,
                        uint8_t block_seed)
{
    struct signer_ctx sc;
    cmt_block_id_t    bid;
    bool              recoverable;

    make_block_id(&bid, block_seed);
    cmt_pb_vote_init(v);
    v->type      = type;
    v->height    = height;
    v->round     = round;
    v->block_id  = bid;
    v->timestamp = G_TS;
    memcpy(v->validator_address, g_vs.validators[val_index].address,
           (size_t)CMT_ADDRESS_SIZE);
    v->validator_address_len = (size_t)CMT_ADDRESS_SIZE;
    v->validator_index       = val_index;

    sc.sk = g_sk[g_key_of_index[val_index]];
    return cmt_sign_and_check_vote(v, real_sign, &sc, g_chain,
                                   sizeof(g_chain), extensions_enabled,
                                   &recoverable);
}

/* ══ 1. TestPeerCatchupRounds — height_vote_set_test.go:26-56 ═════════ */

static int t_peer_catchup_rounds(void)
{
    cmt_hvs_t         *hvs = NULL;
    cmt_peer_id_t      peer1;
    cmt_peer_id_t      peer2;
    bool               added;
    cmt_vote_set_err_t err;
    int                rc;

    memset(&peer1, 0, sizeof(peer1));
    peer1.id[0] = 0x01u;
    memset(&peer2, 0, sizeof(peer2));
    peer2.id[0] = 0x02u;

    /* :29 — NewExtendedHeightVoteSet(chainID, 1, valSet). */
    CHECK(cmt_new_extended_height_vote_set(g_chain, sizeof(g_chain), 1,
                                           &g_vs, &hvs) == CMT_OK,
          "NewExtendedHeightVoteSet");
    CHECK(cmt_hvs_height(hvs) == 1 && cmt_hvs_round(hvs) == 0,
          "Reset left height 1 at round 0");
    OK();

    /* :31-35 — a precommit at round 999 from peer1: the round is unknown,
     * so it becomes peer1's FIRST catch-up round. */
    CHECK(make_vote_hr(g_v, 1, 0, 999, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                       true, 0x11) == CMT_OK, "makeVoteHR(1, 0, 999)");
    rc = cmt_hvs_add_vote(hvs, g_v, peer1, true, &added, &err, NULL);
    CHECK(rc == CMT_OK && added,
          "Expected to successfully add vote from peer");
    OK();

    /* :37-41 — round 1000 from peer1: its SECOND catch-up round. */
    CHECK(make_vote_hr(g_v, 1, 0, 1000, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                       true, 0x12) == CMT_OK, "makeVoteHR(1, 0, 1000)");
    rc = cmt_hvs_add_vote(hvs, g_v, peer1, true, &added, &err, NULL);
    CHECK(rc == CMT_OK && added,
          "Expected to successfully add vote from peer");
    OK();

    /* :43-50 — round 1001 from peer1: THREE is too many. */
    CHECK(make_vote_hr(g_v, 1, 0, 1001, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                       true, 0x13) == CMT_OK, "makeVoteHR(1, 0, 1001)");
    rc = cmt_hvs_add_vote(hvs, g_v, peer1, true, &added, &err, NULL);
    CHECK(rc == CMT_REJECT &&
          err == CMT_VOTE_SET_ERR_GOT_VOTE_FROM_UNWANTED_ROUND,
          "expected GotVoteFromUnwantedRoundError");
    CHECK(!added,
          "Expected to *not* add vote from peer, too many catchup rounds.");
    OK();

    /* :52-55 — THE SAME VOTE from peer2 is accepted: the budget is per
     * peer, and round 1001 is still unknown, so peer2 spends its first. */
    rc = cmt_hvs_add_vote(hvs, g_v, peer2, true, &added, &err, NULL);
    CHECK(rc == CMT_OK && added,
          "Expected to successfully add vote from another peer");
    OK();

    /* Derived: the three rounds exist and round 1002 does not, and the
     * height's own round is still 0 — a catch-up round does not move it
     * (height_vote_set.go:145 calls addRound, never SetRound). */
    CHECK(cmt_hvs_precommits(hvs, 999) != NULL &&
          cmt_hvs_precommits(hvs, 1000) != NULL &&
          cmt_hvs_precommits(hvs, 1001) != NULL &&
          cmt_hvs_precommits(hvs, 1002) == NULL,
          "exactly the three catch-up rounds exist");
    CHECK(cmt_hvs_round(hvs) == 0, "the height's round is untouched");
    OK();

    cmt_hvs_free(hvs);
    return 0;
}

/* ══ 2. TestInconsistentExtensionData — height_vote_set_test.go:58-73 ═ */

static int t_inconsistent_extension_data(void)
{
    cmt_hvs_t    *hvs_e  = NULL;
    cmt_hvs_t    *hvs_no = NULL;
    cmt_peer_id_t peer1;

    memset(&peer1, 0, sizeof(peer1));
    peer1.id[0] = 0x01u;

    /* :61-66 — an EXTENDED set handed a vote declared extension-free.
     * The reference panics at height_vote_set.go:136-138; the port
     * returns CMT_FAULT, because the flag comes from the application's
     * own consensus params and not from the wire. */
    CHECK(cmt_new_extended_height_vote_set(g_chain, sizeof(g_chain), 1,
                                           &g_vs, &hvs_e) == CMT_OK,
          "NewExtendedHeightVoteSet");
    CHECK(make_vote_hr(g_v, 1, 0, 20, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                       true, 0x21) == CMT_OK, "makeVoteHR(1, 0, 20)");
    g_v->extension_signature_len = 0u;                           /* :63 */
    g_v->extension.len           = 0u;
    CHECK(cmt_hvs_add_vote(hvs_e, g_v, peer1, false, NULL, NULL, NULL) ==
          CMT_FAULT, "extensions enabled here, disabled there");
    OK();

    /* :68-72 — a PLAIN set handed a vote declared extension-carrying. */
    CHECK(cmt_new_height_vote_set(g_chain, sizeof(g_chain), 1, &g_vs,
                                  &hvs_no) == CMT_OK, "NewHeightVoteSet");
    CHECK(make_vote_hr(g_v, 1, 0, 20, (int32_t)CMT_PB_MSG_TYPE_PRECOMMIT,
                       true, 0x22) == CMT_OK, "makeVoteHR(1, 0, 20)");
    CHECK(cmt_hvs_add_vote(hvs_no, g_v, peer1, true, NULL, NULL, NULL) ==
          CMT_FAULT, "extensions disabled here, enabled there");
    OK();

    cmt_hvs_free(hvs_e);
    cmt_hvs_free(hvs_no);
    return 0;
}

/* ══ 3. SetRound, and the round -1 the reference really creates ══════ */

static int t_set_round(void)
{
    cmt_hvs_t *hvs = NULL;

    CHECK(cmt_new_height_vote_set(g_chain, sizeof(g_chain), 9, &g_vs,
                                  &hvs) == CMT_OK, "NewHeightVoteSet");

    /* :80-81 — Reset created round 0 and only round 0. */
    CHECK(cmt_hvs_prevotes(hvs, 0) != NULL &&
          cmt_hvs_precommits(hvs, 0) != NULL, "round 0 exists");
    CHECK(cmt_hvs_prevotes(hvs, -1) == NULL, "round -1 does not exist yet");
    CHECK(cmt_hvs_prevotes(hvs, 1) == NULL, "round 1 does not exist yet");
    OK();

    /* :97-111 — SetRound(1) with hvs.round == 0. newRound is
     * SafeSubInt32(0, 1) = -1 (safemath.go:25-32 subtracts and only
     * panics on int32 overflow), and the loop of :104 starts there, so
     * ROUND -1 IS CREATED. This is the reference's behaviour and the
     * reason the port stores rounds sparsely rather than by index. */
    CHECK(cmt_hvs_set_round(hvs, 1) == CMT_OK, "SetRound(1)");
    CHECK(cmt_hvs_round(hvs) == 1, "the round moved to 1");
    CHECK(cmt_hvs_prevotes(hvs, -1) != NULL,
          "round -1 was created, exactly as the reference creates it");
    CHECK(cmt_vote_set_get_round(cmt_hvs_prevotes(hvs, -1)) == -1,
          "and that vote set really carries round -1");
    CHECK(cmt_hvs_prevotes(hvs, 0) != NULL && cmt_hvs_prevotes(hvs, 1) != NULL,
          "rounds 0 and 1 exist");
    CHECK(cmt_hvs_prevotes(hvs, 2) == NULL, "round 2 does not");
    OK();

    /* SetRound(3) from 1: newRound = 0, so rounds 2 and 3 are added and
     * the existing 0 and 1 are skipped by :105-107. */
    CHECK(cmt_hvs_set_round(hvs, 3) == CMT_OK, "SetRound(3)");
    CHECK(cmt_hvs_prevotes(hvs, 2) != NULL && cmt_hvs_prevotes(hvs, 3) != NULL,
          "rounds 2 and 3 exist");
    CHECK(cmt_hvs_round(hvs) == 3, "the round moved to 3");
    OK();

    /* :101-103 — `hvs.round != 0 && round < newRound` panics. With
     * hvs.round == 3, newRound is 2, so SetRound(2) is allowed (2 < 2 is
     * false) and SetRound(1) is not. */
    CHECK(cmt_hvs_set_round(hvs, 2) == CMT_OK,
          "SetRound may step back by exactly one");
    CHECK(cmt_hvs_round(hvs) == 2, "and the round follows");
    CHECK(cmt_hvs_set_round(hvs, 0) == CMT_FAULT,
          "SetRound() must increment hvs.round");
    OK();

    /* :71-82 — Reset drops everything and starts again at round 0. */
    CHECK(cmt_hvs_reset(hvs, 10, &g_vs) == CMT_OK, "Reset");
    CHECK(cmt_hvs_height(hvs) == 10 && cmt_hvs_round(hvs) == 0,
          "Reset moved the height and zeroed the round");
    CHECK(cmt_hvs_prevotes(hvs, 3) == NULL && cmt_hvs_prevotes(hvs, -1) == NULL,
          "the old rounds are gone");
    CHECK(cmt_hvs_prevotes(hvs, 0) != NULL, "and round 0 is back");
    CHECK(cmt_vote_set_get_height(cmt_hvs_prevotes(hvs, 0)) == 10,
          "the new round 0 belongs to the new height");
    OK();

    cmt_hvs_free(hvs);
    return 0;
}

/* ══ 4. POLInfo and SetPeerMaj23 — height_vote_set.go:170-219 ════════ */

static int t_pol_info_and_maj23(void)
{
    cmt_hvs_t         *hvs = NULL;
    cmt_block_id_t     bid;
    cmt_block_id_t     pol;
    cmt_peer_id_t      peer;
    int32_t            pol_round = 0;
    cmt_vote_set_err_t err;
    bool               added;
    int32_t            i;

    memset(&peer, 0x77, sizeof(peer));
    make_block_id(&bid, 0x31);

    CHECK(cmt_new_height_vote_set(g_chain, sizeof(g_chain), 4, &g_vs,
                                  &hvs) == CMT_OK, "NewHeightVoteSet");
    CHECK(cmt_hvs_set_round(hvs, 1) == CMT_OK, "SetRound(1)");

    /* :172-183 — nothing yet. */
    CHECK(cmt_hvs_pol_info(hvs, &pol_round, &pol) == CMT_OK &&
          pol_round == -1 && cmt_block_id_is_zero(&pol),
          "POLInfo is -1 with a zero BlockID before any majority");
    OK();

    /* :200-219 — a round nobody tracks is not an error, and a type that
     * is not a vote type is. */
    CHECK(cmt_hvs_set_peer_maj23(hvs, 99, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                                 peer, &bid, &err) == CMT_OK,
          "SetPeerMaj23 on an untracked round is silent");
    CHECK(cmt_hvs_set_peer_maj23(hvs, 0, (int32_t)CMT_PB_MSG_TYPE_PROPOSAL,
                                 peer, &bid, &err) == CMT_REJECT &&
          err == CMT_VOTE_SET_ERR_INVALID_VOTE_TYPE,
          "setPeerMaj23: Invalid vote type");
    CHECK(cmt_hvs_set_peer_maj23(hvs, 1, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                                 peer, &bid, &err) == CMT_OK,
          "SetPeerMaj23 on a tracked round reaches the vote set");
    OK();

    /* Ten validators of power 1: quorum = 10*2/3+1 = 7. Seven prevotes at
     * ROUND 1 for the block give round 1 a POL. */
    for (i = 0; i < 7; i++) {
        cmt_peer_id_t self = cmt_peer_id_self();

        CHECK(make_vote_hr(g_v, 4, i, 1, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                           false, 0x31) == CMT_OK, "prevote for the block");
        CHECK(cmt_hvs_add_vote(hvs, g_v, self, false, &added, &err, NULL) ==
              CMT_OK && added, "the seven prevotes are added");
    }
    CHECK(cmt_hvs_pol_info(hvs, &pol_round, &pol) == CMT_OK &&
          pol_round == 1 && cmt_block_id_equals(&pol, &bid),
          "POLInfo finds round 1 and the block");
    OK();

    /* :175 walks DOWNWARD from hvs.round, so a later round's majority
     * wins over an earlier one. Move to round 2 and give IT a majority
     * for a different block; POLInfo must report round 2. */
    CHECK(cmt_hvs_set_round(hvs, 2) == CMT_OK, "SetRound(2)");
    for (i = 0; i < 7; i++) {
        cmt_peer_id_t self = cmt_peer_id_self();

        CHECK(make_vote_hr(g_v, 4, i, 2, (int32_t)CMT_PB_MSG_TYPE_PREVOTE,
                           false, 0x41) == CMT_OK, "prevote at round 2");
        CHECK(cmt_hvs_add_vote(hvs, g_v, self, false, &added, &err, NULL) ==
              CMT_OK && added, "the seven round-2 prevotes are added");
    }
    {
        cmt_block_id_t bid2;

        make_block_id(&bid2, 0x41);
        CHECK(cmt_hvs_pol_info(hvs, &pol_round, &pol) == CMT_OK &&
              pol_round == 2 && cmt_block_id_equals(&pol, &bid2),
              "POLInfo prefers the LATER round");
    }
    OK();

    cmt_hvs_free(hvs);
    return 0;
}

/* ══ 5. the C-only peer bound ═════════════════════════════════════════ */

/*
 * CMT_PEER_MAX distinct peers may each open a catch-up round; the next
 * one is refused instead of growing an unbounded map, which is the hazard
 * the reference's own comment names (height_vote_set.go:201-203).
 *
 * Each peer must ask for a DIFFERENT round: the second peer to ask for a
 * round that already exists never reaches the catch-up branch at all
 * (:143 only fires when getVoteSet returned nil).
 */
static int t_peer_catchup_capacity(void)
{
    cmt_hvs_t         *hvs = NULL;
    cmt_peer_id_t      peer;
    cmt_vote_set_err_t err;
    bool               added;
    int                i;

    CHECK(cmt_new_height_vote_set(g_chain, sizeof(g_chain), 2, &g_vs,
                                  &hvs) == CMT_OK, "NewHeightVoteSet");

    for (i = 0; i < CMT_PEER_MAX; i++) {
        memset(&peer, 0, sizeof(peer));
        peer.id[0] = (uint8_t)(i & 0xFF);
        peer.id[1] = (uint8_t)((i >> 8) & 0xFF);
        CHECK(make_vote_hr(g_v, 2, 0, (int32_t)(1000 + i),
                           (int32_t)CMT_PB_MSG_TYPE_PREVOTE, false,
                           0x51) == CMT_OK, "prevote at a fresh round");
        CHECK(cmt_hvs_add_vote(hvs, g_v, peer, false, &added, &err, NULL) ==
              CMT_OK && added, "each of the first 128 peers gets a round");
    }
    memset(&peer, 0xEE, sizeof(peer));
    CHECK(make_vote_hr(g_v, 2, 0, (int32_t)(1000 + CMT_PEER_MAX),
                       (int32_t)CMT_PB_MSG_TYPE_PREVOTE, false, 0x51) ==
          CMT_OK, "prevote at one more fresh round");
    CHECK(cmt_hvs_add_vote(hvs, g_v, peer, false, &added, &err, NULL) ==
          CMT_REJECT && !added && err == CMT_VOTE_SET_ERR_PEER_CAPACITY,
          "the 129th distinct peer is refused");
    CHECK(cmt_hvs_prevotes(hvs, (int32_t)(1000 + CMT_PEER_MAX)) == NULL,
          "and its round was never created");
    OK();

    cmt_hvs_free(hvs);
    return 0;
}

/* ══ 6. a vote type that is not a vote type — :139-141 ════════════════ */

static int t_invalid_vote_type(void)
{
    cmt_hvs_t         *hvs = NULL;
    cmt_peer_id_t      peer;
    cmt_vote_set_err_t err = CMT_VOTE_SET_ERR_NONE;
    bool               added = true;

    memset(&peer, 0x0Cu, sizeof(peer));
    CHECK(cmt_new_height_vote_set(g_chain, sizeof(g_chain), 3, &g_vs,
                                  &hvs) == CMT_OK, "NewHeightVoteSet");
    CHECK(make_vote_hr(g_v, 3, 0, 0, (int32_t)CMT_PB_MSG_TYPE_PREVOTE, false,
                       0x61) == CMT_OK, "a prevote");
    g_v->type = (int32_t)CMT_PB_MSG_TYPE_PROPOSAL;   /* not a vote type */

    /* :139-141 is a naked `return`: added is false and there is NO error.
     * A port that returned an error here would punish an honest peer. */
    CHECK(cmt_hvs_add_vote(hvs, g_v, peer, false, &added, &err, NULL) ==
          CMT_OK && !added && err == CMT_VOTE_SET_ERR_NONE,
          "a non-vote type is dropped silently");
    OK();

    cmt_hvs_free(hvs);
    return 0;
}

/* ══ main ═════════════════════════════════════════════════════════════ */

int main(void)
{
    size_t i;

    for (i = 0; i < (size_t)CMT_PB_CHAINID_MAX; i++) {
        g_chain[i] = (uint8_t)(0x40u + i);
    }
    for (i = 0; i < (size_t)NVALS; i++) {
        uint8_t seed[32];

        memset(seed, 0, sizeof(seed));
        seed[0] = (uint8_t)(i & 0xFFu);
        seed[1] = 0x5Au;
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) {
            fprintf(stderr, "keypair %zu failed\n", i);
            return 1;
        }
    }
    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(cmt_valset_scratch_t));
    g_v       = (cmt_vote_t *)malloc(sizeof(cmt_vote_t));
    if (g_scratch == NULL || g_v == NULL) {
        fprintf(stderr, "fixtures failed\n");
        return 1;
    }
    if (build_set() != 0) {
        fprintf(stderr, "NewValidatorSet failed\n");
        return 1;
    }

    if (t_peer_catchup_rounds() != 0)         { return 1; }
    if (t_inconsistent_extension_data() != 0) { return 1; }
    if (t_set_round() != 0)                   { return 1; }
    if (t_pol_info_and_maj23() != 0)          { return 1; }
    if (t_peer_catchup_capacity() != 0)       { return 1; }
    if (t_invalid_vote_type() != 0)           { return 1; }

    free(g_v);
    free(g_scratch);
    printf("test_cmt_hvs: %d checks passed\n", g_checks);
    return 0;
}
