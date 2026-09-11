/**
 * Nodus — cometbft @709fd12b C port, wave R1-D: `state/state.go`
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That a chain's initial state is what the reference builds from a genesis
 * document, and that BFT-time's median is the reference's walk. If this
 * file failed, one of these would be false:
 *   · `MedianTime` (state.go:269-286) weights each timestamp by its
 *     signer's VOTING POWER and runs time.go:36-56's walk — with three
 *     unit weights and times 10/20/30 s the answer is 10 s, NOT the middle
 *     one, because `median = total/2 = 1` and the first entry's weight
 *     already reaches it; with weights 1/2/1 it is 20 s;
 *   · an ABSENT entry is skipped (:274-276), and a signer the set does not
 *     contain is skipped AND excluded from the total (:277-282) — the
 *     latter changes the answer, which is how the skip is observable;
 *   · `MakeGenesisState` (:317-355) derives every validator address FROM
 *     THE KEY (:330), builds `NextValidators` as the same set after ONE
 *     proposer-priority increment (:333), leaves `LastValidators` EMPTY
 *     (:347), sets both "changed" heights to InitialHeight (:348, :351),
 *     sets LastBlockTime to the genesis time (:343), LastBlockHeight to 0
 *     (:341) and Version to {11, 0, software} (:30-36);
 *   · the set `MakeGenesisState` builds hashes to exactly what
 *     `GenesisDoc.ValidatorHash` (genesis.go:58-65) computes — two paths
 *     to the same root;
 *   · `Copy` (:83-106) is DEEP: mutating the copy's validators leaves the
 *     original untouched;
 *   · `IsEmpty` (:129-131) is true for a fresh state and FALSE for a
 *     genesis state, including one with NIL validators, whose set is
 *     empty-but-not-nil; and a document whose validator list is EMPTY
 *     BUT NOT NIL is refused (:324 tests `== nil`; :333 then panics on the
 *     empty set, validator_set.go:132-134 — REJECT here, Delta D-1);
 *   · `MakeBlock` (:234-263) stamps the block at `InitialHeight` with
 *     LastBlockTime and at every other height with the MedianTime of the
 *     commit it is given, and the block it returns passes
 *     `Block.ValidateBasic`;
 *   · `cmt_time_is_zero` — moved from cmt_genesis to cmt_time by this
 *     wave — still answers as it did: true for CMT_TIME_ZERO, false for a
 *     memset-zeroed time, false one nanosecond past zero.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files. Keys come from `qgp_dsa87_keypair_derand` with fixed seeds, so
 * no randomness is drawn. NO CLOCK IS READ: the genesis document always
 * carries a non-zero `genesis_time` (D-18 rev 2), so
 * `ValidateAndComplete`'s clock branch is never taken, and the callback
 * passed in is a counter that asserts it was never called. Safe under
 * `ctest -j`. SEVEN mallocs in `main`, every one of them for an object too
 * large to be a stack object and every one freed there: two
 * `cmt_state_storage_t`, one `cmt_valset_scratch_t`, one
 * `cmt_state_block_scratch_t`, one 128-entry `cmt_validator_t` array and
 * the leaf buffer plus item array that `cmt_validator_set_hash` needs.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes. Everything malloc'd is
 * freed in main.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The median values here are HAND-DERIVED from time.go:36-56 and shown
 *     step by step in the comments, not taken from a Go run. If the
 *     derivation were wrong in the same way the C is wrong, this file
 *     would agree with it. The reference's own vectors for the walk itself
 *     live in test_cmt_time.c (types/time/time_test.go:10-56).
 *  2. No block hash is pinned against an oracle here; test_cmt_block.c
 *     does that. This file proves which TIME and which HASHES go into the
 *     header, not that the header hashing is right.
 *  3. `MakeGenesisState` is exercised with 3 and with 0 validators. The
 *     128-validator capacity bound is never approached, and a green says
 *     nothing about it.
 *  4. The state's `Software` version string is asserted to equal the
 *     CMT_SOFTWARE_VERSION macro, which since 2026-09-10 is supplied by
 *     the BUILD (the Nodus version — atlas-dec-157739c22040e385e1096932-
 *     fc7d3a63) and no longer a literal in cmt_state.h. The assertion
 *     therefore proves that MakeGenesisState copies the macro through, and
 *     NOTHING about which string the build passed: run with a wrong -D and
 *     it still passes. The field is store-only and not consensus-critical
 *     (see CMT_SOFTWARE_VERSION in cmt_state.h).
 *
 * ── REFERENCE TEST CASES PORTED (state/state_test.go, UNPINNED) ────────
 * `TestStateCopy` (:56-72) — copy, mutate, original unchanged.
 * `TestMakeGenesisStateNilValidators` (:74-85) — a document with no
 * validators yields empty Validators and NextValidators and a zero total.
 * `TestStateMakeBlock` (:1002-1015) — the block MakeBlock returns carries
 * the proposer address it was given.
 * NOT ported: every row that needs the state STORE (`TestStateSaveLoad`,
 * the FinalizeBlockResponses pair, the ValidatorsSaveLoad family,
 * `TestStateProto`) — the store is taşınmadı, R2; and
 * `TestProposerFrequency` / `TestProposerPriority*` /
 * `TestLargeGenesisValidator`, whose subject is proposer priority and
 * which test_cmt_validator_set.c already covers.
 *
 * @file test_cmt_state.c
 */

#include "dnac/cmt_state.h"
#include "dnac/cmt_genesis.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_block.h"
#include "dnac/cmt_params.h"
#include "dnac/cmt_time.h"

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

#define NVALS 3
#define GENESIS_SECONDS 1700000000
#define LEAFBUF_LEN ((size_t)CMT_VALSET_MAX * (size_t)CMT_VALIDATOR_BYTES_MAX)

static uint8_t                 g_pk[NVALS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t                 g_sk[NVALS][QGP_DSA87_SECRETKEYBYTES];
static cmt_genesis_validator_t g_gvals[NVALS];
static cmt_valset_scratch_t   *g_scratch;
static cmt_state_storage_t    *g_stor_a;
static cmt_state_storage_t    *g_stor_b;
static cmt_state_block_scratch_t *g_bscratch;
static cmt_validator_t        *g_hashvals;
static uint8_t                *g_leafbuf;
static cmt_merkle_item_t      *g_items;

/* The clock callback exists ONLY to prove it is never called: this
 * chain's genesis_time is mandatory (D-18 rev 2), so the branch at
 * genesis.go:101-103 is never taken. */
static int g_now_calls;
static int never_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    g_now_calls++;
    *out = CMT_TIME_ZERO;
    return CMT_OK;
}

static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

/* A genesis document with `n` validators of the given powers. The
 * addresses are left EMPTY, so ValidateAndComplete fills them from the
 * keys (genesis.go:96-98) — the path this chain actually uses. */
static void make_doc(cmt_genesis_doc_t *g, size_t n, const int64_t *powers)
{
    size_t i;

    memset(g, 0, sizeof(*g));
    g->genesis_time.seconds = GENESIS_SECONDS;
    g->genesis_time.nanos   = 0;
    pat(g->chain_id, 32, 0x50);
    g->chain_id_len   = 32u;
    g->initial_height = 1;
    g->has_consensus_params = false;   /* defaulted by :83-84 */
    /* n == 0 is the reference's NIL slice (state.go:324) and is spelled
     * as a NULL list here; an EMPTY-BUT-NOT-NIL list is built by hand in
     * t_make_genesis, because the two are different Go values with
     * different outcomes (Delta D-1). */
    g->validators     = (n == 0u) ? NULL : g_gvals;
    g->validators_cap = NVALS;
    g->validators_len = n;
    for (i = 0; i < n; i++) {
        memset(&g_gvals[i], 0, sizeof(g_gvals[i]));
        g_gvals[i].pub_key.present = true;
        memcpy(g_gvals[i].pub_key.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        g_gvals[i].power       = powers[i];
        g_gvals[i].address_len = 0u;   /* filled in by :96-98 */
    }
}

/* ══ 0. the moved zero-time predicate ═════════════════════════════════ */

static int t_time_is_zero(void)
{
    cmt_time_t t;

    /* The same three cases test_cmt_genesis.c:178-187 asserts through the
     * old declaration; `cmt_time_is_zero` lives in cmt_time now and must
     * still answer identically. */
    t = CMT_TIME_ZERO;
    CHECK(cmt_time_is_zero(t), "CMT_TIME_ZERO is Go's zero time"); OK();

    memset(&t, 0, sizeof(t));
    CHECK(!cmt_time_is_zero(t),
          "a memset-zeroed cmt_time_t is the Unix epoch, NOT Go's zero");
    OK();

    t = CMT_TIME_ZERO;
    t.nanos = 1;
    CHECK(!cmt_time_is_zero(t), "one nanosecond past it is not zero"); OK();
    return 0;
}

/* ══ 1. MedianTime ════════════════════════════════════════════════════ */

/* Build a commit whose entry i names the validator at set index i and
 * carries `secs[i]` seconds. No signature is verified by MedianTime, so
 * the entries carry a plausible one and nothing more. */
static void fill_commit(cmt_commit_t *c, cmt_commit_sig_t *sigs,
                        const cmt_validator_set_t *vs,
                        const int64_t *secs, size_t n)
{
    size_t i;

    cmt_pb_commit_init(c);
    c->height          = 1;
    c->round           = 0;
    c->signatures      = sigs;
    c->signatures_cap  = NVALS + 1;
    c->signatures_len  = n;
    for (i = 0; i < n; i++) {
        memset(&sigs[i], 0, sizeof(sigs[i]));
        sigs[i].block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
        memcpy(sigs[i].validator_address, vs->validators[i].address, 32);
        sigs[i].validator_address_len = 32u;
        sigs[i].timestamp.seconds     = secs[i];
        sigs[i].timestamp.nanos       = 0;
        pat(sigs[i].signature, 64, (uint8_t)(0x60u + i));
        sigs[i].signature_len = 64u;
    }
}

static int t_median_time(void)
{
    static const int64_t equal_powers[NVALS] = { 1, 1, 1 };
    static const int64_t mixed_powers[NVALS] = { 1, 2, 1 };
    cmt_genesis_doc_t    doc;
    cmt_state_t          st;
    cmt_commit_sig_t     sigs[NVALS + 1];
    cmt_commit_t         commit;
    cmt_time_t           med;
    int64_t              secs[NVALS];
    size_t               i;
    size_t               pow2 = 0;

    /* ── three UNIT weights, times 10 / 20 / 30 seconds. ──
     *
     * The walk, from types/time/time.go:36-56:
     *   total = 3, median = 3 / 2 = 1 (truncating)
     *   sorted ascending: 10s(w1), 20s(w1), 30s(w1)
     *   entry 10s: is median(1) <= weight(1)?  YES  -> answer 10s
     *
     * ⚠ SO THE ANSWER IS THE FIRST TIME, NOT THE MIDDLE ONE. With unit
     * weights this "median" leans low, and that is the reference's
     * arithmetic, not an off-by-one here. D-20's closed form for unit
     * weights, sorted[max(0, floor(total/2) - 1)] = sorted[0], agrees. */
    make_doc(&doc, NVALS, equal_powers);
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_OK, "genesis"); OK();

    for (i = 0; i < NVALS; i++) {
        secs[i] = 10 + 10 * (int64_t)i;
    }
    fill_commit(&commit, sigs, &st.validators, secs, NVALS);
    CHECK(cmt_state_median_time(&commit, &st.validators, &med) == CMT_OK,
          "MedianTime"); OK();
    CHECK(med.seconds == 10 && med.nanos == 0,
          "three unit weights over 10/20/30 give 10 seconds"); OK();

    /* ── weights 1 / 2 / 1, with the DOUBLE weight on 20 seconds. ──
     *
     *   total = 4, median = 4 / 2 = 2
     *   sorted ascending: 10s(w1), 20s(w2), 30s(w1)
     *   entry 10s: 2 <= 1? no  -> median = 2 - 1 = 1
     *   entry 20s: 1 <= 2? YES -> answer 20s
     *
     * The set sorts by power DESCENDING, so the power-2 validator is at
     * index 0; the time is assigned by POWER, not by index, so that the
     * derivation above is the one being tested. */
    make_doc(&doc, NVALS, mixed_powers);
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_OK, "genesis"); OK();
    for (i = 0; i < NVALS; i++) {
        if (st.validators.validators[i].voting_power == 2) {
            pow2 = i;
        }
    }
    {
        int64_t next = 10;
        for (i = 0; i < NVALS; i++) {
            if (i == pow2) {
                secs[i] = 20;
            } else {
                secs[i] = next;
                next    = 30;
            }
        }
    }
    fill_commit(&commit, sigs, &st.validators, secs, NVALS);
    CHECK(cmt_state_median_time(&commit, &st.validators, &med) == CMT_OK,
          "MedianTime"); OK();
    CHECK(med.seconds == 20 && med.nanos == 0,
          "weights 1/2/1 put the answer on the heavy 20-second entry");
    OK();

    /* ── one ABSENT entry (:274-276): skipped, and its power leaves the
     * total. Making the 20-second entry absent leaves 10s(w1) and 30s(w1),
     * total 2, median 1; entry 10s: 1 <= 1 -> 10s. */
    memset(&sigs[pow2], 0, sizeof(sigs[pow2]));
    cmt_new_commit_sig_absent(&sigs[pow2]);
    CHECK(cmt_state_median_time(&commit, &st.validators, &med) == CMT_OK,
          "MedianTime with an absent entry"); OK();
    CHECK(med.seconds == 10,
          "an absent entry contributes neither a time nor its power"); OK();

    /* ── a signer NOT IN THE SET (:277-282): skipped, and excluded from
     * the total — which is the difference that makes the skip visible.
     * Rebuild the full commit, then give the heavy entry a stranger's
     * address: the remaining 10s(w1) and 30s(w1) give total 2, median 1,
     * answer 10s, exactly as the absent case. */
    fill_commit(&commit, sigs, &st.validators, secs, NVALS);
    pat(sigs[pow2].validator_address, 32, 0xEE);
    CHECK(cmt_state_median_time(&commit, &st.validators, &med) == CMT_OK,
          "MedianTime with an unknown signer"); OK();
    CHECK(med.seconds == 10,
          "a signer the set does not contain is skipped, total and all");
    OK();

    /* ── nothing selected: Go's ZERO time, not the Unix epoch. ── */
    commit.signatures_len = 0u;
    CHECK(cmt_state_median_time(&commit, &st.validators, &med) == CMT_OK,
          "MedianTime over an empty commit"); OK();
    CHECK(cmt_time_is_zero(med),
          "an empty commit gives Go's zero time (time.go:35 never assigns)");
    OK();

    CHECK(cmt_state_median_time(NULL, &st.validators, &med) == CMT_FAULT,
          "NULL commit"); OK();
    CHECK(cmt_state_median_time(&commit, NULL, &med) == CMT_FAULT,
          "NULL set"); OK();
    CHECK(g_now_calls == 0,
          "and NO CLOCK was read anywhere above"); OK();
    return 0;
}

/* ══ 2. MakeGenesisState ══════════════════════════════════════════════ */

static int t_make_genesis(void)
{
    static const int64_t powers[NVALS] = { 10, 20, 30 };
    cmt_genesis_doc_t    doc;
    cmt_state_t          st;
    uint8_t              vhash[CMT_TMHASH_SIZE];
    uint8_t              dochash[CMT_TMHASH_SIZE];
    uint8_t              nhash[CMT_TMHASH_SIZE];
    cmt_consensus_params_t defaults;
    size_t               i;

    make_doc(&doc, NVALS, powers);
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_is_empty(&st),
          "a freshly initialised state is EMPTY — the sets are unbound");
    OK();

    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_OK, "MakeGenesisState"); OK();
    CHECK(!cmt_state_is_empty(&st),
          "and a genesis state is not"); OK();
    CHECK(g_now_calls == 0,
          "genesis_time was given, so the clock branch was not taken"); OK();

    /* :337 — InitStateVersion. */
    CHECK(st.version.consensus.block == (uint64_t)CMT_BLOCK_PROTOCOL &&
          st.version.consensus.app == 0u,
          "Version.Consensus is {BlockProtocol 11, App 0}"); OK();
    CHECK(strcmp(st.version.software, CMT_SOFTWARE_VERSION) == 0,
          "and Software is the build's CMT_SOFTWARE_VERSION, copied through");
    OK();

    /* :338-343 — the immutable fields and the block-0 fields. */
    CHECK(st.chain_id_len == 32u &&
          memcmp(st.chain_id, doc.chain_id, 32) == 0, "ChainID"); OK();
    CHECK(st.initial_height == 1, "InitialHeight"); OK();
    CHECK(st.last_block_height == 0, "LastBlockHeight is 0 at genesis");
    OK();
    CHECK(cmt_block_id_is_zero(&st.last_block_id),
          "LastBlockID is the zero BlockID (:342)"); OK();
    CHECK(st.last_block_time.seconds == GENESIS_SECONDS,
          "LastBlockTime IS the genesis time (:343)"); OK();

    /* :348, :351 — both "changed" heights are InitialHeight. */
    CHECK(st.last_height_validators_changed == 1 &&
          st.last_height_consensus_params_changed == 1,
          "both changed-heights are InitialHeight"); OK();

    /* :350 — the consensus params, defaulted by ValidateAndComplete. */
    cmt_default_consensus_params(&defaults);
    CHECK(st.consensus_params.block.max_bytes == defaults.block.max_bytes,
          "ConsensusParams came from the completed document"); OK();

    /* :330-332 — the set, with every ADDRESS DERIVED FROM ITS KEY. */
    CHECK(cmt_validator_set_size(&st.validators) == NVALS, "three of them");
    OK();
    for (i = 0; i < NVALS; i++) {
        uint8_t derived[32];
        const cmt_validator_t *v = &st.validators.validators[i];

        CHECK(cmt_pub_key_address(&v->pub_key, derived) == CMT_OK, "addr");
        OK();
        CHECK(v->address_len == 32u && memcmp(v->address, derived, 32) == 0,
              "every address is the hash of its own key"); OK();
    }
    /* The set is in ValidatorsByVotingPower order: power DESCENDING. */
    CHECK(st.validators.validators[0].voting_power == 30 &&
          st.validators.validators[1].voting_power == 20 &&
          st.validators.validators[2].voting_power == 10,
          "and the set is ordered by power, descending"); OK();

    /* Two independent paths to the same root: the state's set, and
     * GenesisDoc.ValidatorHash (genesis.go:58-65). */
    CHECK(cmt_validator_set_hash(&st.validators, g_leafbuf, LEAFBUF_LEN,
                                 g_items, CMT_VALSET_MAX, vhash) == CMT_OK,
          "Validators.Hash"); OK();
    CHECK(cmt_genesis_doc_validator_hash(&doc, g_hashvals, CMT_VALSET_MAX,
                                         g_scratch, g_leafbuf, LEAFBUF_LEN,
                                         g_items, CMT_VALSET_MAX,
                                         dochash) == CMT_OK,
          "GenesisDoc.ValidatorHash"); OK();
    CHECK(memcmp(vhash, dochash, CMT_TMHASH_SIZE) == 0,
          "the two agree — MakeGenesisState builds the document's set");
    OK();

    /* :333 — NextValidators is that set after ONE increment, so it is the
     * SAME validators with different priorities and the SAME hash (the
     * leaf is {PubKey, VotingPower}; priorities are excluded,
     * validator.go:115-117). */
    CHECK(cmt_validator_set_size(&st.next_validators) == NVALS,
          "NextValidators has the same members"); OK();
    CHECK(cmt_validator_set_hash(&st.next_validators, g_leafbuf,
                                 LEAFBUF_LEN, g_items, CMT_VALSET_MAX,
                                 nhash) == CMT_OK, "NextValidators.Hash");
    OK();
    CHECK(memcmp(vhash, nhash, CMT_TMHASH_SIZE) == 0,
          "and hashes alike, because priorities are not in the leaf"); OK();
    {
        bool differ = false;
        for (i = 0; i < NVALS; i++) {
            if (st.validators.validators[i].proposer_priority !=
                st.next_validators.validators[i].proposer_priority) {
                differ = true;
            }
        }
        CHECK(differ,
              "but the PRIORITIES differ — the increment really happened");
        OK();
    }
    CHECK(st.next_validators.has_proposer,
          "so the proposer after genesis is already elected"); OK();

    /* :347 — LastValidators is EMPTY but not nil. */
    CHECK(cmt_validator_set_size(&st.last_validators) == 0u,
          "LastValidators is empty at genesis"); OK();
    CHECK(st.last_validators.validators != NULL,
          "but NOT nil — it is bound storage, which IsEmpty relies on");
    OK();

    /* :324-326 — a document with NO validators: two empty sets, and the
     * state is still not "empty" (TestMakeGenesisStateNilValidators). */
    make_doc(&doc, 0u, powers);
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_OK, "MakeGenesisState with no validators"); OK();
    CHECK(cmt_validator_set_size(&st.validators) == 0u &&
          cmt_validator_set_size(&st.next_validators) == 0u,
          "both sets are empty"); OK();
    CHECK(!cmt_state_is_empty(&st),
          "and the STATE is still not empty — empty-but-not-nil"); OK();

    /* :324 tests `== nil`, so an EMPTY BUT NOT NIL list takes the OTHER
     * branch, where :333 `CopyIncrementProposerPriority(1)` panics on an
     * empty set (validator_set.go:132-134). The C spells that list as a
     * non-NULL pointer with a zero count and REJECTS where the reference
     * panics (Delta D-1). */
    make_doc(&doc, 0u, powers);
    doc.validators = g_gvals;          /* non-NULL: the empty slice */
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_REJECT,
          "an EMPTY but non-nil validator list is refused where the "
          "reference panics"); OK();

    /* And a NULL list with a non-zero count is not a Go value at all. */
    make_doc(&doc, NVALS, powers);
    doc.validators = NULL;
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_FAULT, "a NULL list with a non-zero count is a FAULT"); OK();

    /* D-18 rev 2: a zero genesis time with no callback is a FAULT, and a
     * time is never invented. */
    make_doc(&doc, NVALS, powers);
    doc.genesis_time = CMT_TIME_ZERO;
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, NULL, NULL, g_scratch, &st) ==
          CMT_FAULT,
          "a zero genesis time with no clock callback is refused"); OK();
    return 0;
}

/* ══ 3. Copy and IsEmpty ══════════════════════════════════════════════ */

static int t_copy(void)
{
    static const int64_t powers[NVALS] = { 10, 20, 30 };
    cmt_genesis_doc_t    doc;
    cmt_state_t          a;
    cmt_state_t          b;
    int64_t              before;

    make_doc(&doc, NVALS, powers);
    CHECK(cmt_state_init(&a, g_stor_a) == CMT_OK, "init a"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &a) ==
          CMT_OK, "genesis"); OK();

    CHECK(cmt_state_init(&b, g_stor_b) == CMT_OK, "init b"); OK();
    CHECK(cmt_state_is_empty(&b), "b is empty before the copy"); OK();
    CHECK(cmt_state_copy(&a, &b) == CMT_OK, "Copy"); OK();
    CHECK(!cmt_state_is_empty(&b), "and not after it"); OK();

    /* Every scalar came across. */
    CHECK(b.initial_height == a.initial_height &&
          b.last_block_height == a.last_block_height &&
          b.last_block_time.seconds == a.last_block_time.seconds &&
          b.chain_id_len == a.chain_id_len &&
          memcmp(b.chain_id, a.chain_id, 32) == 0 &&
          b.last_height_validators_changed ==
              a.last_height_validators_changed,
          "the scalars are copied"); OK();
    CHECK(cmt_validator_set_size(&b.validators) == NVALS,
          "and the validators"); OK();

    /* THE DEEP COPY: mutating b must not touch a. */
    before = a.validators.validators[0].voting_power;
    b.validators.validators[0].voting_power = 999;
    CHECK(a.validators.validators[0].voting_power == before,
          "mutating the copy leaves the original alone"); OK();
    CHECK(b.validators.validators != a.validators.validators,
          "because the two sets sit in different storage"); OK();

    /* A copy into the SOURCE's storage is refused, and so is a copy of an
     * empty state — the reference would nil-dereference there. */
    {
        cmt_state_t same;

        CHECK(cmt_state_init(&same, g_stor_a) == CMT_OK, "init"); OK();
        CHECK(cmt_state_copy(&a, &same) == CMT_FAULT,
              "a copy sharing the source's storage is refused"); OK();
    }
    {
        /* `empty` deliberately borrows g_stor_a — NOT g_stor_b — so that
         * the source and the destination have DIFFERENT storage and the
         * refusal below can only be the is-empty one. `cmt_state_init`
         * touches the state, never the storage, so `a` is unaffected. */
        cmt_state_t empty;

        CHECK(cmt_state_init(&empty, g_stor_a) == CMT_OK, "init"); OK();
        CHECK(empty.storage != b.storage,
              "different storage, so the next refusal is not about that");
        OK();
        CHECK(cmt_state_copy(&empty, &b) == CMT_FAULT,
              "and copying an EMPTY state is refused, not invented"); OK();
        CHECK(a.validators.validators != NULL &&
              cmt_validator_set_size(&a.validators) == NVALS,
              "and `a` is still intact — init touched no storage"); OK();
    }
    CHECK(cmt_state_is_empty(NULL), "a NULL state is empty"); OK();
    CHECK(cmt_state_copy(NULL, &b) == CMT_FAULT, "NULL"); OK();
    return 0;
}

/* ══ 4. MakeBlock ═════════════════════════════════════════════════════ */

static int t_make_block(void)
{
    static const int64_t powers[NVALS] = { 10, 20, 30 };
    cmt_genesis_doc_t doc;
    cmt_state_t       st;
    cmt_block_t       blk;
    cmt_commit_t      empty_commit;
    cmt_commit_t      commit;
    cmt_commit_sig_t  sigs[NVALS + 1];
    cmt_time_t        med;
    uint8_t           proposer[32];
    int64_t           secs[NVALS];
    size_t            i;

    make_doc(&doc, NVALS, powers);
    CHECK(cmt_state_init(&st, g_stor_a) == CMT_OK, "init"); OK();
    CHECK(cmt_state_make_genesis(&doc, never_now, NULL, g_scratch, &st) ==
          CMT_OK, "genesis"); OK();
    memcpy(proposer, st.validators.validators[0].address, 32);

    /* ── height == InitialHeight: the timestamp is LastBlockTime, which
     * for a genesis state is the genesis time (:247-248). The LastCommit
     * is the EMPTY BUT NOT NIL commit of height 1 (D-19 rev 6 item 4). */
    cmt_pb_commit_init(&empty_commit);
    empty_commit.height         = 0;
    empty_commit.signatures     = NULL;
    empty_commit.signatures_cap = 0u;
    empty_commit.signatures_len = 0u;

    CHECK(cmt_state_make_block(&st, 1, NULL, &empty_commit, NULL,
                               proposer, 32u, g_bscratch, &blk) == CMT_OK,
          "MakeBlock at InitialHeight"); OK();
    CHECK(blk.header.height == 1, "the height is set"); OK();
    CHECK(blk.header.time.seconds == GENESIS_SECONDS &&
          blk.header.time.nanos == 0,
          "and the timestamp is LastBlockTime — the genesis time"); OK();
    CHECK(blk.header.proposer_address_len == 32u &&
          memcmp(blk.header.proposer_address, proposer, 32) == 0,
          "the proposer address is the one given (TestStateMakeBlock)");
    OK();
    CHECK(blk.header.version.block == (uint64_t)CMT_BLOCK_PROTOCOL &&
          blk.header.version.app == 0u,
          "Version comes from the STATE, not from a constant"); OK();
    CHECK(blk.header.chain_id_len == 32u &&
          memcmp(blk.header.chain_id, st.chain_id, 32) == 0, "ChainID");
    OK();
    CHECK(blk.header.validators_hash_len == (size_t)CMT_TMHASH_SIZE &&
          blk.header.next_validators_hash_len == (size_t)CMT_TMHASH_SIZE &&
          blk.header.consensus_hash_len == (size_t)CMT_TMHASH_SIZE,
          "the three state hashes are filled"); OK();
    {
        uint8_t vhash[CMT_TMHASH_SIZE];
        uint8_t chash[CMT_TMHASH_SIZE];

        CHECK(cmt_validator_set_hash(&st.validators, g_leafbuf, LEAFBUF_LEN,
                                     g_items, CMT_VALSET_MAX, vhash) ==
              CMT_OK, "hash"); OK();
        CHECK(memcmp(blk.header.validators_hash, vhash,
                     CMT_TMHASH_SIZE) == 0,
              "ValidatorsHash is the state's own set hash"); OK();
        CHECK(cmt_consensus_params_hash(&st.consensus_params, chash) ==
              CMT_OK, "hash"); OK();
        CHECK(memcmp(blk.header.consensus_hash, chash,
                     CMT_TMHASH_SIZE) == 0,
              "ConsensusHash is params.Hash()"); OK();
    }
    /* And the block the constructor returned is well-formed. */
    CHECK(cmt_block_validate_basic(&blk, CMT_BLOCK_PROTOCOL) == CMT_OK,
          "the block passes Block.ValidateBasic"); OK();

    /* ── height != InitialHeight: the timestamp is the MedianTime of the
     * commit it is given. A genesis state's LastValidators is EMPTY, so
     * every signer would be "not in the set" and the median would be the
     * ZERO time — the set has to be populated first, which is what the
     * real state machine does when it advances. */
    CHECK(cmt_validator_set_copy(&st.validators, &st.last_validators) ==
          CMT_OK, "populate LastValidators"); OK();
    for (i = 0; i < NVALS; i++) {
        secs[i] = 10 + 10 * (int64_t)i;
    }
    fill_commit(&commit, sigs, &st.last_validators, secs, NVALS);
    CHECK(cmt_state_median_time(&commit, &st.last_validators, &med) ==
          CMT_OK, "MedianTime"); OK();
    /* powers 30/20/10 by index, times 10/20/30: total 60, median 30;
     * sorted ascending 10s(w30), 20s(w20), 30s(w10); 30 <= 30 -> 10s. */
    CHECK(med.seconds == 10, "the hand-derived median is 10 seconds"); OK();

    CHECK(cmt_state_make_block(&st, 2, NULL, &commit, NULL, proposer, 32u,
                               g_bscratch, &blk) == CMT_OK,
          "MakeBlock above InitialHeight"); OK();
    CHECK(blk.header.time.seconds == med.seconds &&
          blk.header.time.nanos == med.nanos,
          "and its timestamp IS that median (:250)"); OK();

    /* A NULL LastCommit above InitialHeight would nil-dereference in the
     * reference; this refuses. */
    CHECK(cmt_state_make_block(&st, 2, NULL, NULL, NULL, proposer, 32u,
                               g_bscratch, &blk) == CMT_FAULT,
          "no LastCommit above InitialHeight is a FAULT"); OK();
    /* At InitialHeight it is fine: no median is needed. */
    CHECK(cmt_state_make_block(&st, 1, NULL, NULL, NULL, proposer, 32u,
                               g_bscratch, &blk) == CMT_OK,
          "at InitialHeight a NULL LastCommit is accepted"); OK();

    CHECK(cmt_state_make_block(NULL, 1, NULL, &empty_commit, NULL,
                               proposer, 32u, g_bscratch, &blk) ==
          CMT_FAULT, "NULL state"); OK();
    CHECK(g_now_calls == 0, "and no clock was read"); OK();
    return 0;
}

int main(void)
{
    uint8_t seed[32];
    int     rc = 1;
    int     i;

    g_scratch  = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    g_stor_a   = (cmt_state_storage_t *)malloc(sizeof(*g_stor_a));
    g_stor_b   = (cmt_state_storage_t *)malloc(sizeof(*g_stor_b));
    g_bscratch = (cmt_state_block_scratch_t *)malloc(sizeof(*g_bscratch));
    g_hashvals = (cmt_validator_t *)malloc((size_t)CMT_VALSET_MAX *
                                           sizeof(*g_hashvals));
    g_leafbuf  = (uint8_t *)malloc(LEAFBUF_LEN);
    g_items    = (cmt_merkle_item_t *)malloc((size_t)CMT_VALSET_MAX *
                                             sizeof(*g_items));
    if (g_scratch == NULL || g_stor_a == NULL || g_stor_b == NULL ||
        g_bscratch == NULL || g_hashvals == NULL || g_leafbuf == NULL ||
        g_items == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    for (i = 0; i < NVALS; i++) {
        memset(seed, (uint8_t)(0x01 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0) {
            fprintf(stderr, "keypair %d failed\n", i);
            goto out;
        }
    }

    if (t_time_is_zero() != 0) goto out;
    if (t_median_time() != 0) goto out;
    if (t_make_genesis() != 0) goto out;
    if (t_copy() != 0) goto out;
    if (t_make_block() != 0) goto out;

    printf("test_cmt_state: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(g_scratch);
    free(g_stor_a);
    free(g_stor_b);
    free(g_bscratch);
    free(g_hashvals);
    free(g_leafbuf);
    free(g_items);
    return rc;
}
