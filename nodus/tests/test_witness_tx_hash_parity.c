/**
 * Nodus — Witness TX hash parity test
 *
 * Verifies nodus_witness_recompute_tx_hash() produces byte-identical
 * output to dnac_tx_compute_hash() (messenger tree) for every TX type
 * (SPEND + STAKE/DELEGATE/UNSTAKE/UNDELEGATE/CLAIM_REWARD/VALIDATOR_UPDATE).
 *
 * Since the nodus standalone build does NOT link libdna, we reimplement
 * the canonical preimage construction here byte-for-byte (mirroring
 * dnac/src/transaction/transaction.c::dnac_tx_compute_hash), hash it
 * with the same SHA3-512 backend (nodus_hash), and compare against the
 * witness recompute. If the two algorithms diverge, this test fails.
 *
 * The comparison is only meaningful because BOTH sides compute the
 * preimage from the SAME spec and BOTH hash with SHA3-512. A drift in
 * either side (wire format change, preimage layout change, chain_id
 * binding change) breaks this test.
 *
 * @file test_witness_tx_hash_parity.c
 */

#include "witness/nodus_witness_verify.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return -1; \
    } \
} while (0)

#define TX_HASH_LEN      64
#define NULLIFIER_LEN    64
#define TOKEN_ID_LEN     64
#define FP_LEN           129
#define SEED_LEN         32
#define PK_BYTES         NODUS_PK_BYTES
#define SIG_BYTES        NODUS_SIG_BYTES
#define CHAIN_ID_LEN     32

/* DNAC TX type codes (mirror dnac/include/dnac/transaction.h). */
#define TX_GENESIS              0
#define TX_SPEND                1
#define TX_BURN                 2
#define TX_TOKEN_CREATE         3
#define TX_STAKE                4
#define TX_DELEGATE             5
#define TX_UNSTAKE              6
#define TX_UNDELEGATE           7
#define TX_CLAIM_REWARD         8
#define TX_VALIDATOR_UPDATE     9

/* Purpose tag used by STAKE (matches DNAC_STAKE_PURPOSE_TAG). */
static const uint8_t PURPOSE_TAG[17] = "DNAC_VALIDATOR_v1";

static void be64_into(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; i--) { out[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

static void le64_into(uint64_t v, uint8_t out[8]) {
    memcpy(out, &v, 8);  /* wire format is native (LE on x86) */
}

/* ── Wire builder ─────────────────────────────────────────────────────
 * Builds a minimal wire-format TX. Caller supplies type-specific tail
 * bytes verbatim (already encoded per wire spec).
 * Layout:
 *   header(74) || inputs(1+N*136) || outputs(1+M*(235+memo)) ||
 *   witnesses(1+0) || signers(1+S*(pk+sig)) || type_specific_tail
 */
typedef struct {
    uint8_t type;
    uint64_t timestamp;

    int input_count;
    uint8_t inputs_null[4][NULLIFIER_LEN];
    uint64_t inputs_amt[4];
    uint8_t inputs_tok[4][TOKEN_ID_LEN];

    int output_count;
    uint8_t  outputs_version[4];
    uint8_t  outputs_fp[4][FP_LEN];
    uint64_t outputs_amt[4];
    uint8_t  outputs_tok[4][TOKEN_ID_LEN];
    uint8_t  outputs_seed[4][SEED_LEN];
    uint8_t  outputs_memo_len[4];
    uint8_t  outputs_memo[4][256];

    int signer_count;
    uint8_t  signer_pubkey[2][PK_BYTES];
    uint8_t  signer_sig[2][SIG_BYTES];

    /* Type-specific tail: caller fills + sets len. */
    size_t   tail_len;
    uint8_t  tail[4096];
} tx_t;

static size_t wire_size(const tx_t *t) {
    size_t s = 10 + TX_HASH_LEN;  /* header */
    s += 1 + (size_t)t->input_count * (NULLIFIER_LEN + 8 + TOKEN_ID_LEN);
    s += 1;
    for (int i = 0; i < t->output_count; i++) {
        s += 1 + FP_LEN + 8 + TOKEN_ID_LEN + SEED_LEN + 1 + t->outputs_memo_len[i];
    }
    s += 1;  /* witnesses count = 0 */
    s += 1 + (size_t)t->signer_count * (PK_BYTES + SIG_BYTES);
    s += t->tail_len;
    return s;
}

static uint8_t *build_wire(const tx_t *t, uint32_t *len_out) {
    size_t size = wire_size(t);
    uint8_t *buf = calloc(1, size);
    if (!buf) return NULL;
    uint8_t *p = buf;

    /* Header: version + type + timestamp (LE) + tx_hash placeholder */
    p[0] = 1;                /* version */
    p[1] = t->type;
    le64_into(t->timestamp, p + 2);
    p += 10;
    p += TX_HASH_LEN;        /* tx_hash zeros */

    /* Inputs */
    *p++ = (uint8_t)t->input_count;
    for (int i = 0; i < t->input_count; i++) {
        memcpy(p, t->inputs_null[i], NULLIFIER_LEN); p += NULLIFIER_LEN;
        le64_into(t->inputs_amt[i], p); p += 8;
        memcpy(p, t->inputs_tok[i], TOKEN_ID_LEN); p += TOKEN_ID_LEN;
    }

    /* Outputs */
    *p++ = (uint8_t)t->output_count;
    for (int i = 0; i < t->output_count; i++) {
        *p++ = t->outputs_version[i];
        memcpy(p, t->outputs_fp[i], FP_LEN); p += FP_LEN;
        le64_into(t->outputs_amt[i], p); p += 8;
        memcpy(p, t->outputs_tok[i], TOKEN_ID_LEN); p += TOKEN_ID_LEN;
        memcpy(p, t->outputs_seed[i], SEED_LEN); p += SEED_LEN;
        *p++ = t->outputs_memo_len[i];
        if (t->outputs_memo_len[i] > 0) {
            memcpy(p, t->outputs_memo[i], t->outputs_memo_len[i]);
            p += t->outputs_memo_len[i];
        }
    }

    /* Witnesses (always 0 for these tests) */
    *p++ = 0;

    /* Signers */
    *p++ = (uint8_t)t->signer_count;
    for (int i = 0; i < t->signer_count; i++) {
        memcpy(p, t->signer_pubkey[i], PK_BYTES); p += PK_BYTES;
        memcpy(p, t->signer_sig[i],    SIG_BYTES); p += SIG_BYTES;
    }

    /* Type-specific tail */
    if (t->tail_len > 0) {
        memcpy(p, t->tail, t->tail_len);
        p += t->tail_len;
    }

    *len_out = (uint32_t)(p - buf);
    return buf;
}

/* Reference hash: canonical preimage per design §2.3 (F-CRYPTO-10).
 * Must match dnac_tx_compute_hash() byte-for-byte. */
static int reference_hash(const tx_t *t, const uint8_t chain_id[CHAIN_ID_LEN],
                          uint8_t out[TX_HASH_LEN]) {
    /* Assemble preimage in a growable buffer. */
    size_t cap = 65536;
    uint8_t *buf = malloc(cap);
    if (!buf) return -1;
    size_t pos = 0;

    #define PUT(src, n) do { memcpy(buf + pos, (src), (n)); pos += (n); } while (0)

    uint8_t u8;
    uint8_t be8[8];
    uint8_t be2[2];

    /* header */
    u8 = 1; PUT(&u8, 1);          /* version */
    PUT(&t->type, 1);
    be64_into(t->timestamp, be8); PUT(be8, 8);
    PUT(chain_id, CHAIN_ID_LEN);

    /* inputs */
    for (int i = 0; i < t->input_count; i++) {
        PUT(t->inputs_null[i], NULLIFIER_LEN);
        be64_into(t->inputs_amt[i], be8); PUT(be8, 8);
        PUT(t->inputs_tok[i], TOKEN_ID_LEN);
    }

    /* outputs */
    for (int i = 0; i < t->output_count; i++) {
        PUT(&t->outputs_version[i], 1);
        PUT(t->outputs_fp[i], FP_LEN);
        be64_into(t->outputs_amt[i], be8); PUT(be8, 8);
        PUT(t->outputs_tok[i], TOKEN_ID_LEN);
        PUT(t->outputs_seed[i], SEED_LEN);
        PUT(&t->outputs_memo_len[i], 1);
        if (t->outputs_memo_len[i] > 0) {
            PUT(t->outputs_memo[i], t->outputs_memo_len[i]);
        }
    }

    /* signers: count + pubkeys (no signatures) */
    u8 = (uint8_t)t->signer_count; PUT(&u8, 1);
    for (int i = 0; i < t->signer_count; i++) {
        PUT(t->signer_pubkey[i], PK_BYTES);
    }

    /* type-specific */
    if (t->type == TX_STAKE) {
        /* commission_bps(u16 BE) || unstake_destination_fp(64) || purpose_tag(17)
         * — all taken verbatim from tail. */
        PUT(t->tail, t->tail_len);
    } else if (t->type == TX_DELEGATE) {
        PUT(t->tail, t->tail_len);  /* validator_pubkey(2592) */
    } else if (t->type == TX_UNDELEGATE) {
        PUT(t->tail, t->tail_len);  /* pubkey(2592) + amount(u64 BE) */
    } else if (t->type == TX_CLAIM_REWARD) {
        PUT(t->tail, t->tail_len);  /* target(2592) + max(u64 BE) + valid(u64 BE) */
    } else if (t->type == TX_VALIDATOR_UPDATE) {
        PUT(t->tail, t->tail_len);  /* new_bps(u16 BE) + signed_at(u64 BE) */
    }
    /* SPEND, UNSTAKE, GENESIS, BURN, TOKEN_CREATE: no type-specific tail. */

    (void)be2;

    nodus_key_t h;
    int rc = qgp_sha3_512(buf, pos, h.bytes);
    free(buf);
    if (rc != 0) return -1;
    memcpy(out, h.bytes, TX_HASH_LEN);
    return 0;
    #undef PUT
}

/* Fills a canonical SPEND-baseline tx_t (1 input, 1 output, 1 signer). */
static void populate_baseline(tx_t *t, uint8_t type) {
    memset(t, 0, sizeof(*t));
    t->type = type;
    t->timestamp = 0x1122334455667788ULL;

    t->input_count = 1;
    memset(t->inputs_null[0], 0xAA, NULLIFIER_LEN);
    t->inputs_amt[0] = 1000;
    /* token_id: all zeros = native */

    t->output_count = 1;
    t->outputs_version[0] = 1;
    memset(t->outputs_fp[0], 0x55, FP_LEN);
    t->outputs_amt[0] = 900;
    memset(t->outputs_seed[0], 0x33, SEED_LEN);
    t->outputs_memo_len[0] = 0;

    t->signer_count = 1;
    for (int i = 0; i < PK_BYTES; i++) t->signer_pubkey[0][i] = (uint8_t)(i & 0xff);
    /* signature zeros — not part of preimage */

    t->tail_len = 0;
}

/* Concatenate signer pubkeys as the witness recompute expects. */
static void flatten_signer_pubkeys(const tx_t *t, uint8_t *out) {
    for (int i = 0; i < t->signer_count; i++) {
        memcpy(out + (size_t)i * PK_BYTES, t->signer_pubkey[i], PK_BYTES);
    }
}

/* Runs one parity scenario. */
static int run_scenario(const char *name, const tx_t *t,
                         const uint8_t chain_id[CHAIN_ID_LEN]) {
    printf("  %-50s ", name);
    fflush(stdout);

    uint32_t wire_len = 0;
    uint8_t *wire = build_wire(t, &wire_len);
    CHECK(wire != NULL, "build_wire");

    uint8_t expect_hash[TX_HASH_LEN];
    CHECK(reference_hash(t, chain_id, expect_hash) == 0, "reference_hash");

    uint8_t signer_pks[2 * PK_BYTES];
    flatten_signer_pubkeys(t, signer_pks);

    uint8_t got_hash[TX_HASH_LEN];
    int rc = nodus_witness_recompute_tx_hash(chain_id, wire, wire_len,
                                              t->signer_count > 0 ? signer_pks : NULL,
                                              (uint8_t)t->signer_count,
                                              got_hash);
    CHECK(rc == 0, "witness recompute rc");

    if (memcmp(expect_hash, got_hash, TX_HASH_LEN) != 0) {
        printf("FAIL\n");
        fprintf(stderr, "    expect: ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", expect_hash[i]);
        fprintf(stderr, "...\n    got:    ");
        for (int i = 0; i < 16; i++) fprintf(stderr, "%02x", got_hash[i]);
        fprintf(stderr, "...\n");
        free(wire);
        return -1;
    }
    printf("PASS\n");
    free(wire);
    return 0;
}

int main(void) {
    printf("=== Witness TX Hash Parity Tests ===\n");
    int failed = 0;

    /* Non-zero chain_id to catch missing chain_id binding. */
    uint8_t chain_id[CHAIN_ID_LEN];
    for (int i = 0; i < CHAIN_ID_LEN; i++) chain_id[i] = (uint8_t)(0xC0 | (i & 0x3f));

    /* Scenario 1: SPEND (no type-specific tail) */
    {
        tx_t t; populate_baseline(&t, TX_SPEND);
        if (run_scenario("SPEND parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 2: STAKE — commission_bps + unstake_dest_fp + purpose_tag */
    {
        tx_t t; populate_baseline(&t, TX_STAKE);
        uint8_t *tp = t.tail;
        /* commission_bps = 0x1234 BE */
        *tp++ = 0x12; *tp++ = 0x34;
        /* unstake_destination_fp[64] */
        for (int i = 0; i < 64; i++) *tp++ = (uint8_t)(0x70 + (i & 0x0f));
        /* purpose_tag */
        memcpy(tp, PURPOSE_TAG, 17); tp += 17;
        t.tail_len = (size_t)(tp - t.tail);
        if (run_scenario("STAKE parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 3: DELEGATE — validator_pubkey[2592] */
    {
        tx_t t; populate_baseline(&t, TX_DELEGATE);
        for (int i = 0; i < PK_BYTES; i++) t.tail[i] = (uint8_t)((i * 7) & 0xff);
        t.tail_len = PK_BYTES;
        if (run_scenario("DELEGATE parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 4: UNSTAKE — no type-specific tail */
    {
        tx_t t; populate_baseline(&t, TX_UNSTAKE);
        /* UNSTAKE has no appended; tail_len = 0. */
        if (run_scenario("UNSTAKE parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 5: UNDELEGATE — pubkey(2592) + amount(u64 BE) */
    {
        tx_t t; populate_baseline(&t, TX_UNDELEGATE);
        uint8_t *tp = t.tail;
        for (int i = 0; i < PK_BYTES; i++) *tp++ = (uint8_t)((i * 11) & 0xff);
        uint8_t be8[8]; be64_into(5000000ULL, be8);
        memcpy(tp, be8, 8); tp += 8;
        t.tail_len = (size_t)(tp - t.tail);
        if (run_scenario("UNDELEGATE parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 6: CLAIM_REWARD — target(2592) + max(u64 BE) + valid(u64 BE) */
    {
        tx_t t; populate_baseline(&t, TX_CLAIM_REWARD);
        uint8_t *tp = t.tail;
        for (int i = 0; i < PK_BYTES; i++) *tp++ = (uint8_t)((i * 13) & 0xff);
        uint8_t be8[8];
        be64_into(100000ULL, be8); memcpy(tp, be8, 8); tp += 8;
        be64_into(999999ULL, be8); memcpy(tp, be8, 8); tp += 8;
        t.tail_len = (size_t)(tp - t.tail);
        if (run_scenario("CLAIM_REWARD parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 7: VALIDATOR_UPDATE — new_bps(u16 BE) + signed_at(u64 BE) */
    {
        tx_t t; populate_baseline(&t, TX_VALIDATOR_UPDATE);
        uint8_t *tp = t.tail;
        *tp++ = 0x01; *tp++ = 0xF4;  /* 500 bps = 5% */
        uint8_t be8[8]; be64_into(42ULL, be8);
        memcpy(tp, be8, 8); tp += 8;
        t.tail_len = (size_t)(tp - t.tail);
        if (run_scenario("VALIDATOR_UPDATE parity", &t, chain_id) != 0) failed++;
    }

    /* Scenario 8: chain_id binding — same TX, different chain_id ⇒ different hash */
    {
        tx_t t; populate_baseline(&t, TX_SPEND);
        uint8_t chain_id_2[CHAIN_ID_LEN];
        memcpy(chain_id_2, chain_id, CHAIN_ID_LEN);
        chain_id_2[0] ^= 0x01;

        uint32_t wire_len = 0;
        uint8_t *wire = build_wire(&t, &wire_len);
        CHECK(wire != NULL, "build_wire");

        uint8_t pks[PK_BYTES];
        flatten_signer_pubkeys(&t, pks);

        uint8_t h1[TX_HASH_LEN], h2[TX_HASH_LEN];
        int r1 = nodus_witness_recompute_tx_hash(chain_id,   wire, wire_len, pks, 1, h1);
        int r2 = nodus_witness_recompute_tx_hash(chain_id_2, wire, wire_len, pks, 1, h2);
        free(wire);

        printf("  %-50s ", "chain_id binding differentiates hash");
        if (r1 == 0 && r2 == 0 && memcmp(h1, h2, TX_HASH_LEN) != 0) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
            failed++;
        }
    }

    printf("\n=== %s: %d failed ===\n", failed == 0 ? "OK" : "FAIL", failed);
    return failed == 0 ? 0 : 1;
}
