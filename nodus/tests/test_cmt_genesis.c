/**
 * Nodus — cometbft @709fd12b C port, wave R1-C: `types/genesis.go` tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That the genesis document's gate is the reference's. If this file
 * failed, one of these would be false:
 *   · ValidateAndComplete refuses an empty chain id, a chain id longer
 *     than MaxChainIDLen, a negative initial height and a validator with
 *     ZERO voting power, and it COMPLETES an initial height of 0 to 1,
 *     an absent consensus-parameter block to the defaults, and an empty
 *     validator address from that validator's public key;
 *   · an address that is PRESENT but does not belong to its key is
 *     REFUSED — a genesis document cannot assign one validator's identity
 *     to another's key;
 *   · a NEGATIVE power is deliberately NOT refused here. The reference
 *     tests only for zero (genesis.go:90), and Validator.ValidateBasic
 *     catches the negative case later. A port that "improved" on this
 *     would refuse a document the reference accepts;
 *   · ValidatorHash is the hash of the set BUILT FROM THE KEYS — the same
 *     root the validator-set test pins for the same three validators, in
 *     ValidatorsByVotingPower order rather than the document's order;
 *   · A ZERO GENESIS TIME IS 0001-01-01, NOT THE UNIX EPOCH. A
 *     memset-zeroed time is 1970 and is NOT the reference's zero, so it
 *     is left alone; only the year-one value takes the clock branch;
 *   · the clock branch goes through the caller's callback and NEVER
 *     invents a time: a zero time with no callback is a FAULT.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no
 * network, no files, NO CLOCK (the one clock read goes through a stub
 * this file supplies), no RNG. Safe under `ctest -j`. About 1.5 MB on the
 * heap, freed.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The one SHA3-512 root is a SELF-CONSISTENT FREEZE shared with
 *     test_cmt_validator_set, derived by cmt_vset_oracle.py rather than
 *     published by cometbft (which hashes with SHA-256).
 *  2. THE CLOCK BRANCH IS EXERCISED HERE BUT IS DEAD IN PRODUCTION. D-18
 *     rev 2 (atlas-dec-4e84dbb5629353b78af6d04d704bd744) makes
 *     genesis_time MANDATORY in this chain's genesis config precisely so
 *     that derivation stays deterministic, so the host never presents a
 *     zero time. A green run here says the branch is faithful, not that
 *     it is reachable.
 *  3. The JSON and file paths (SaveAs, FromJSON, FromFile) are HOST and
 *     are not ported, so nothing here says anything about parsing a
 *     genesis file.
 *  4. TWO chain id bounds are checked and only the STRICTER one can fire.
 *     MaxChainIDLen is 50 (the reference's, cmt_genesis.h:89) while this
 *     port's chain id buffer is 32 (cmt_pb.h:131), so the REFERENCE's
 *     check is unreachable — any id long enough to trip it is already
 *     refused by the buffer bound. What a green run below proves is that
 *     an over-long id is refused, NOT that this port agrees with the
 *     reference on ids of 33..50 bytes: for those two it disagrees on
 *     purpose, and the port is stricter. The case is reached only by
 *     writing a length field past the buffer, a synthetic input.
 *
 * @file test_cmt_genesis.c
 */

#include "dnac/cmt_genesis.h"
#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_tmhash.h"

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

/* The same root test_cmt_validator_set pins for (k0,10) (k1,30) (k2,20):
 * ValidatorHash goes through NewValidatorSet, so the leaves land in
 * ValidatorsByVotingPower order whatever order the document lists. */
static const uint8_t V_VSET_HASH_3[64] = {   /* Delta C-1 re-derivation */
    0x5f, 0x12, 0x74, 0x79, 0x70, 0x0e, 0xbb, 0x89, 0xbd, 0x04, 0x68, 0xa4,
    0xf2, 0x86, 0xdf, 0xde, 0x41, 0x5a, 0x60, 0xa0, 0xa0, 0x83, 0xdf, 0xa3,
    0x70, 0xb4, 0xaa, 0x8a, 0xae, 0xc2, 0xe5, 0x9f, 0x42, 0xa3, 0x91, 0x23,
    0xb7, 0xe9, 0xdf, 0xc7, 0xa0, 0xc0, 0x6b, 0xcd, 0xf3, 0x93, 0xe3, 0xfe,
    0x63, 0x5b, 0x7e, 0x3b, 0x77, 0xe8, 0x2b, 0xc5, 0xf8, 0xe4, 0x8d, 0x8c,
    0xa3, 0x0d, 0xd7, 0x89,
};

/* Key 0's address, SHA3-512(pat(2592, 0x11))[0..31]. */
static const uint8_t V_ADDR_0[32] = {
    0xc9, 0x0f, 0x0c, 0x07, 0x50, 0xd6, 0x75, 0xd1, 0xc4, 0xb5, 0x6c, 0x41,
    0xe0, 0x3f, 0xf6, 0x88, 0x1b, 0xa4, 0xae, 0xbe, 0x40, 0xd6, 0x86, 0xe4,
    0xa0, 0x9a, 0xed, 0xc7, 0x08, 0xd5, 0xa5, 0x3d,
};

/* ══ fixtures ═════════════════════════════════════════════════════════ */

static void fill_pat(uint8_t *dst, size_t n, unsigned seed)
{
    size_t i;
    for (i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static void make_key(cmt_pb_public_key_t *pk, unsigned seed)
{
    memset(pk, 0, sizeof(*pk));
    pk->present = true;
    fill_pat(pk->key, CMT_PB_PUBKEY_LEN, seed);
}

/** A stub `cmt_now_fn`. It returns a FIXED value and counts its calls, so
 *  the test is deterministic and can prove the branch was or was not
 *  taken. Nothing in this file reads a real clock. */
static int g_now_calls;
static int stub_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    g_now_calls++;
    out->seconds = 1700000000;
    out->nanos   = 123;
    return CMT_OK;
}
static int failing_now(void *ctx, cmt_time_t *out)
{
    (void)ctx;
    (void)out;
    g_now_calls++;
    return CMT_FAULT;
}

static cmt_genesis_validator_t g_gvals[4];
static cmt_valset_scratch_t   *g_scratch;
static cmt_validator_t        *g_store;
static uint8_t                *g_leafbuf;
static cmt_merkle_item_t      *g_items;

#define LEAFBUF_LEN ((size_t)CMT_VALSET_MAX * CMT_VALIDATOR_BYTES_MAX)

/** A well-formed document: chain id, three validators with derived
 *  addresses, an explicit genesis time. */
static void make_doc(cmt_genesis_doc_t *g, size_t n)
{
    const unsigned seeds[3] = { 0x11, 0x22, 0x33 };
    const int64_t  powers[3] = { 10, 30, 20 };
    size_t         i;

    memset(g, 0, sizeof(*g));
    memset(g_gvals, 0, sizeof(g_gvals));
    g->genesis_time.seconds = 1600000000;
    g->genesis_time.nanos   = 0;
    memset(g->chain_id, 0xAB, 32);
    g->chain_id_len   = 32;
    g->initial_height = 1;
    g->validators     = g_gvals;
    g->validators_cap = 4;
    g->validators_len = n;
    for (i = 0; i < n && i < 3; i++) {
        make_key(&g_gvals[i].pub_key, seeds[i]);
        g_gvals[i].power = powers[i];
        /* address deliberately LEFT EMPTY — ValidateAndComplete fills it. */
        g_gvals[i].address_len = 0;
    }
}

/* ══ 1. the zero-time predicate ═══════════════════════════════════════ */

static int t_zero_time(void)
{
    cmt_time_t t;

    /* ⚠ A memset-zeroed time is 1970, and it is NOT Go's zero time. */
    memset(&t, 0, sizeof(t));
    CHECK(!cmt_time_is_zero(t),
          "a memset-zeroed cmt_time_t is the Unix epoch, NOT Go's zero");

    t = CMT_TIME_ZERO;
    CHECK(cmt_time_is_zero(t), "CMT_TIME_ZERO is Go's zero time");
    CHECK(t.seconds == CMT_TIME_MIN_SECONDS && t.nanos == 0,
          "and it is 0001-01-01T00:00:00Z");

    t.nanos = 1;
    CHECK(!cmt_time_is_zero(t), "one nanosecond past it is not zero");
    return 0;
}

/* ══ 2. ValidateAndComplete — the completions ═════════════════════════ */

static int t_complete(void)
{
    cmt_genesis_doc_t g;

    /* initial_height 0 is COMPLETED to 1. */
    make_doc(&g, 3);
    g.initial_height = 0;
    g_now_calls = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "a valid document");
    CHECK(g.initial_height == 1, "an initial height of 0 is completed to 1");
    CHECK(g_now_calls == 0,
          "an explicit genesis time does NOT consult the clock");

    /* Absent consensus params are COMPLETED to the defaults. */
    make_doc(&g, 3);
    g.has_consensus_params = false;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "no consensus params");
    CHECK(g.has_consensus_params, "the defaults are filled in");
    CHECK(g.consensus_params.block.max_bytes == 22020096, "and they ARE the "
          "defaults");

    /* An EMPTY address is COMPLETED from the key. */
    make_doc(&g, 3);
    CHECK(g.validators[0].address_len == 0, "the fixture leaves it empty");
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "empty addresses");
    CHECK(g.validators[0].address_len == 32,
          "an empty address is filled in from the key");
    CHECK(memcmp(g.validators[0].address, V_ADDR_0, 32) == 0,
          "and it is SHA3-512(pubkey)[0..31]");

    /* An address that is PRESENT and CORRECT passes unchanged. */
    make_doc(&g, 3);
    memcpy(g.validators[0].address, V_ADDR_0, 32);
    g.validators[0].address_len = 32;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "a correct explicit address");

    /* ⚠ An address that is PRESENT and WRONG is refused — a genesis
     * document must not be able to hand one validator's identity to
     * another validator's key. */
    make_doc(&g, 3);
    memcpy(g.validators[0].address, V_ADDR_0, 32);
    g.validators[0].address[0] ^= 0x01;
    g.validators[0].address_len = 32;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "an address not derived from the key is refused");

    /* A short-but-present address is also wrong. */
    make_doc(&g, 3);
    memcpy(g.validators[0].address, V_ADDR_0, 31);
    g.validators[0].address_len = 31;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "a 31-byte address is refused");
    return 0;
}

/* ══ 3. ValidateAndComplete — the refusals ════════════════════════════ */

static int t_refusals(void)
{
    cmt_genesis_doc_t g;

    make_doc(&g, 3);
    g.chain_id_len = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "an empty chain id is refused");

    make_doc(&g, 3);
    g.chain_id_len = CMT_GENESIS_MAX_CHAIN_ID_LEN + 1;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "a chain id longer than MaxChainIDLen is refused");
    CHECK(CMT_GENESIS_MAX_CHAIN_ID_LEN == 50, "MaxChainIDLen is 50");

    make_doc(&g, 3);
    g.initial_height = -1;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "a negative initial height is refused");

    /* A ZERO power is refused... */
    make_doc(&g, 3);
    g.validators[1].power = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "a validator with no voting power is refused");

    /* ⚠ ...but a NEGATIVE power is NOT, here. The reference tests only
     * for zero (genesis.go:90); Validator.ValidateBasic catches the
     * negative case later, on the way through ValidatorHash. A port that
     * added the check would refuse a document the reference accepts. */
    make_doc(&g, 3);
    g.validators[1].power = -5;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "a NEGATIVE power passes ValidateAndComplete — the reference "
          "tests only for zero");

    /* Invalid consensus params are refused. */
    make_doc(&g, 3);
    g.has_consensus_params = true;
    cmt_default_consensus_params(&g.consensus_params);
    g.consensus_params.block.max_bytes = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "invalid consensus params are refused");

    /* A validator with no key has no address to derive. */
    make_doc(&g, 3);
    g.validators[0].pub_key.present = false;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL)
              == CMT_REJECT, "a validator with no public key is refused");

    CHECK(cmt_genesis_doc_validate_and_complete(NULL, stub_now, NULL)
              == CMT_FAULT, "NULL is a fault");

    /* A document with NO validators is accepted here — the reference has
     * no such check, and the emptiness is caught wherever a set is
     * actually built. */
    make_doc(&g, 0);
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "a document with no validators passes ValidateAndComplete");
    return 0;
}

/* ══ 4. the clock branch ══════════════════════════════════════════════ */

static int t_clock(void)
{
    cmt_genesis_doc_t g;

    /* A zero time TAKES the branch and uses the callback's value. */
    make_doc(&g, 3);
    g.genesis_time = CMT_TIME_ZERO;
    g_now_calls = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "a zero genesis time is completed");
    CHECK(g_now_calls == 1, "the callback was consulted exactly once");
    CHECK(g.genesis_time.seconds == 1700000000 && g.genesis_time.nanos == 123,
          "and the value came from the callback, not from anywhere else");

    /* ⚠ A ZERO TIME WITH NO CALLBACK IS A FAULT. A time is never
     * invented — that would make genesis derivation non-deterministic,
     * which is the whole reason D-18 rev 2 makes it mandatory. */
    make_doc(&g, 3);
    g.genesis_time = CMT_TIME_ZERO;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, NULL, NULL) == CMT_FAULT,
          "a zero genesis time with no clock is a FAULT, never a guess");
    CHECK(cmt_time_is_zero(g.genesis_time),
          "and the time is left as it was");

    /* A callback that cannot answer propagates its fault. */
    make_doc(&g, 3);
    g.genesis_time = CMT_TIME_ZERO;
    g_now_calls = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, failing_now, NULL)
              == CMT_FAULT, "a host with no usable clock is a fault");
    CHECK(g_now_calls == 1, "and the callback was reached");

    /* The Unix epoch is NOT zero and does NOT take the branch. */
    make_doc(&g, 3);
    g.genesis_time.seconds = 0;
    g.genesis_time.nanos   = 0;
    g_now_calls = 0;
    CHECK(cmt_genesis_doc_validate_and_complete(&g, stub_now, NULL) == CMT_OK,
          "the Unix epoch is a legitimate genesis time");
    CHECK(g_now_calls == 0, "and it does NOT take the clock branch");
    CHECK(g.genesis_time.seconds == 0, "it is left exactly as it was");
    return 0;
}

/* ══ 5. ValidatorHash ═════════════════════════════════════════════════ */

static int t_validator_hash(void)
{
    cmt_genesis_doc_t g;
    uint8_t           got[64];

    make_doc(&g, 3);
    CHECK(cmt_genesis_doc_validator_hash(&g, g_store, CMT_VALSET_MAX,
                                         g_scratch, g_leafbuf, LEAFBUF_LEN,
                                         g_items, CMT_VALSET_MAX, got)
              == CMT_OK, "ValidatorHash");
    CHECK(memcmp(got, V_VSET_HASH_3, 64) == 0,
          "the genesis validator hash is the set's hash for the same three");

    /* ⚠ IT IS INDEPENDENT OF THE DOCUMENT'S ORDER, because it goes
     * through NewValidatorSet, which sorts. Two genesis documents listing
     * the same validators differently produce the same hash. */
    {
        cmt_genesis_validator_t tmp = g_gvals[0];
        uint8_t                 other[64];
        g_gvals[0] = g_gvals[2];
        g_gvals[2] = tmp;
        CHECK(cmt_genesis_doc_validator_hash(&g, g_store, CMT_VALSET_MAX,
                                             g_scratch, g_leafbuf, LEAFBUF_LEN,
                                             g_items, CMT_VALSET_MAX, other)
                  == CMT_OK, "ValidatorHash of the reordered document");
        CHECK(memcmp(other, got, 64) == 0,
              "the document's listing order does not change the hash");
    }

    /* A negative power is refused HERE, by Validator.ValidateBasic on the
     * way through — the check ValidateAndComplete deliberately omits. */
    make_doc(&g, 3);
    g_gvals[1].power = -5;
    CHECK(cmt_genesis_doc_validator_hash(&g, g_store, CMT_VALSET_MAX,
                                         g_scratch, g_leafbuf, LEAFBUF_LEN,
                                         g_items, CMT_VALSET_MAX, got)
              != CMT_OK,
          "a negative power is refused by the set, not by the document");

    /* A keyless validator has no address to derive. */
    make_doc(&g, 3);
    g_gvals[1].pub_key.present = false;
    CHECK(cmt_genesis_doc_validator_hash(&g, g_store, CMT_VALSET_MAX,
                                         g_scratch, g_leafbuf, LEAFBUF_LEN,
                                         g_items, CMT_VALSET_MAX, got)
              == CMT_REJECT, "a keyless genesis validator is refused");

    /* Too many validators for the storage is refused, not truncated. */
    make_doc(&g, 3);
    CHECK(cmt_genesis_doc_validator_hash(&g, g_store, 2, g_scratch, g_leafbuf,
                                         LEAFBUF_LEN, g_items, CMT_VALSET_MAX,
                                         got) == CMT_REJECT,
          "storage too small for the validators is refused");
    return 0;
}

int main(void)
{
    int rc = 0;

    g_scratch = malloc(sizeof(*g_scratch));
    g_store   = calloc(CMT_VALSET_MAX, sizeof(*g_store));
    g_leafbuf = malloc(LEAFBUF_LEN);
    g_items   = calloc(CMT_VALSET_MAX, sizeof(*g_items));
    if (g_scratch == NULL || g_store == NULL || g_leafbuf == NULL ||
        g_items == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }

    if (rc == 0) { rc = t_zero_time();      }
    if (rc == 0) { rc = t_complete();       }
    if (rc == 0) { rc = t_refusals();       }
    if (rc == 0) { rc = t_clock();          }
    if (rc == 0) { rc = t_validator_hash(); }

    free(g_scratch);
    free(g_store);
    free(g_leafbuf);
    free(g_items);

    if (rc == 0) {
        printf("test_cmt_genesis: 5 groups OK\n");
    }
    return rc;
}
