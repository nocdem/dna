/**
 * Nodus — Ledger V2 S1: legacy transaction-hash KAT + 3-way identity.
 *
 * Purpose: prove the S1 codec unification changed NOTHING about the legacy
 * (wire v2 / shielded V4) transaction hash.
 *
 *   1. FIXED LITERALS: every fixture's hash is pinned to a hex literal
 *      CAPTURED FROM THE PRE-S1 ALGORITHM (this same file, compiled with
 *      -DTX_KAT_CAPTURE in a clean HEAD worktree BEFORE the rewire, printed
 *      the literals; they were pasted here verbatim). A mismatch means the
 *      refactor moved a byte.
 *   2. 3-WAY IDENTITY: client dnac_tx_compute_hash (struct walk pre-S1,
 *      serialize+shared post-S1) == witness nodus_witness_recompute_tx_hash
 *      == shared dnac_txw_legacy_tx_hash, for every fixture.
 *   3. Invariances the legacy preimage guarantees: genesis chain_def
 *      trailer excluded; shielded FRI blob excluded (statement included).
 *   4. Shared-codec negatives: truncation at section boundaries, bad
 *      counts, null args.
 *
 * Deterministic fixtures only — no RNG, no clock.
 *
 * @file test_tx_hash_kat.c
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#ifndef TX_KAT_CAPTURE
#include "dnac/tx_wire.h"
#endif
#include "witness/nodus_witness_verify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return -1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

/* Deterministic pattern fill. */
static void fill(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static void hex64(const uint8_t h[64], char out[129]) {
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = d[h[i] >> 4];
        out[2 * i + 1] = d[h[i] & 0xf];
    }
    out[128] = 0;
}

static const uint8_t CHAIN_ID[32] = {
    0xA0,0xA1,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xAB,0xAC,0xAD,0xAE,0xAF,
    0xB0,0xB1,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xBB,0xBC,0xBD,0xBE,0xBF
};

/* ── Fixture builders (heap-alloc: dnac_transaction_t is ~50 KB) ────── */

static dnac_transaction_t *tx_new(uint8_t type) {
    dnac_transaction_t *tx = calloc(1, sizeof(*tx));
    if (!tx) return NULL;
    tx->version       = DNAC_PROTOCOL_VERSION;
    tx->type          = (dnac_tx_type_t)type;
    tx->timestamp     = 0x0102030405060708ULL;
    tx->committed_fee = DNAC_MIN_FEE_RAW;
    memcpy(tx->chain_id, CHAIN_ID, 32);
    return tx;
}

static void add_in(dnac_transaction_t *tx, uint8_t seed, uint64_t amount) {
    dnac_tx_input_t *in = &tx->inputs[tx->input_count++];
    fill(in->nullifier, DNAC_NULLIFIER_SIZE, seed);
    in->amount = amount;
    /* native DNAC: token_id all zeros (calloc) */
}

static void add_out(dnac_transaction_t *tx, uint8_t seed, uint64_t amount,
                    const char *memo) {
    dnac_tx_output_internal_t *o = &tx->outputs[tx->output_count++];
    o->version = 1;
    fill((uint8_t *)o->owner_fingerprint, DNAC_FINGERPRINT_SIZE, seed);
    o->amount = amount;
    fill(o->nullifier_seed, 32, (uint8_t)(seed + 3));
    if (memo) {
        o->memo_len = (uint8_t)strlen(memo);
        memcpy(o->memo, memo, o->memo_len);
    }
}

static void add_signer(dnac_transaction_t *tx, uint8_t seed) {
    dnac_tx_signer_t *s = &tx->signers[tx->signer_count++];
    fill(s->pubkey, DNAC_PUBKEY_SIZE, seed);
    fill(s->signature, DNAC_SIGNATURE_SIZE, (uint8_t)(seed + 1));
}

enum { F_SPEND, F_GENESIS, F_BURN, F_TOKEN_CREATE, F_STAKE, F_DELEGATE,
       F_UNSTAKE, F_UNDELEGATE, F_VALIDATOR_UPDATE, F_CHAIN_CONFIG,
       F_SHIELDED, F_COUNT };

static dnac_transaction_t *build_fixture(int which) {
    dnac_transaction_t *tx = NULL;
    switch (which) {
    case F_SPEND:
        tx = tx_new(DNAC_TX_SPEND);
        if (!tx) return NULL;
        add_in(tx, 0x10, 5000000);
        add_in(tx, 0x20, 7000000);
        add_out(tx, 0x30, 4000000, "hi");
        add_out(tx, 0x40, 7000000, NULL);
        add_signer(tx, 0x50);
        break;
    case F_GENESIS:
        tx = tx_new(DNAC_TX_GENESIS);
        if (!tx) return NULL;
        tx->committed_fee = 0;
        add_out(tx, 0x31, 123456789, NULL);
        add_out(tx, 0x41, 987654321, NULL);
        add_signer(tx, 0x51);
        break;
    case F_BURN:
        tx = tx_new(DNAC_TX_BURN);
        if (!tx) return NULL;
        add_in(tx, 0x11, 2000000);
        add_out(tx, 0x32, 1000000, NULL);
        add_signer(tx, 0x52);
        break;
    case F_TOKEN_CREATE:
        tx = tx_new(DNAC_TX_TOKEN_CREATE);
        if (!tx) return NULL;
        add_in(tx, 0x12, 1000000000000000ULL);
        add_out(tx, 0x33, 42, NULL);
        add_signer(tx, 0x53);
        break;
    case F_STAKE:
        tx = tx_new(DNAC_TX_STAKE);
        if (!tx) return NULL;
        add_in(tx, 0x13, DNAC_SELF_STAKE_AMOUNT + DNAC_MIN_FEE_RAW);
        add_signer(tx, 0x54);
        tx->stake_fields.commission_bps = 0x1234;
        fill(tx->stake_fields.unstake_destination_fp,
             DNAC_STAKE_UNSTAKE_DEST_FP_SIZE, 0x60);
        break;
    case F_DELEGATE:
        tx = tx_new(DNAC_TX_DELEGATE);
        if (!tx) return NULL;
        add_in(tx, 0x14, 20000000000ULL);
        add_signer(tx, 0x55);
        fill(tx->delegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE, 0x61);
        tx->delegate_fields.delegation_amount = 10000000000ULL;
        break;
    case F_UNSTAKE:
        tx = tx_new(DNAC_TX_UNSTAKE);
        if (!tx) return NULL;
        add_signer(tx, 0x56);
        break;
    case F_UNDELEGATE:
        tx = tx_new(DNAC_TX_UNDELEGATE);
        if (!tx) return NULL;
        add_signer(tx, 0x57);
        fill(tx->undelegate_fields.validator_pubkey, DNAC_PUBKEY_SIZE, 0x62);
        tx->undelegate_fields.amount = 5000000000ULL;
        break;
    case F_VALIDATOR_UPDATE:
        tx = tx_new(DNAC_TX_VALIDATOR_UPDATE);
        if (!tx) return NULL;
        add_signer(tx, 0x58);
        tx->validator_update_fields.new_commission_bps = 0x0777;
        tx->validator_update_fields.signed_at_block = 424242;
        break;
    case F_CHAIN_CONFIG:
        tx = tx_new(DNAC_TX_CHAIN_CONFIG);
        if (!tx) return NULL;
        add_signer(tx, 0x59);
        tx->chain_config_fields.param_id = 1;
        tx->chain_config_fields.new_value = 8;
        tx->chain_config_fields.effective_block_height = 100000;
        tx->chain_config_fields.proposal_nonce = 0xDEADBEEF;
        tx->chain_config_fields.signed_at_block = 95000;
        tx->chain_config_fields.valid_before_block = 99000;
        tx->chain_config_fields.committee_sig_count = 5;
        for (int i = 0; i < 5; i++) {
            fill(tx->chain_config_fields.committee_votes[i].witness_id, 32,
                 (uint8_t)(0x70 + i));
            fill(tx->chain_config_fields.committee_votes[i].signature,
                 DNAC_SIGNATURE_SIZE, (uint8_t)(0x80 + i));
        }
        break;
    case F_SHIELDED: {
        tx = tx_new(DNAC_TX_SHIELDED);
        if (!tx) return NULL;
        /* D7.1: no transparent body, no signers. */
        dnac_tx_shielded_fields_t *sf = &tx->shielded_fields;
        for (int j = 0; j < DNAC_SHIELDED_LANES; j++)
            sf->anchor[j] = 1000 + (uint64_t)j;
        sf->num_input = 2;
        for (int s = 0; s < 2; s++)
            for (int j = 0; j < DNAC_SHIELDED_LANES; j++)
                sf->nf_set[s][j] = 2000 + (uint64_t)(s * 4 + j);
        sf->num_output = 1;
        for (int j = 0; j < DNAC_SHIELDED_LANES; j++)
            sf->output_commit[0][j] = 3000 + (uint64_t)j;
        sf->fee = DNAC_MIN_FEE_RAW;               /* == committed_fee (D7.2) */
        for (int j = 0; j < DNAC_SHIELDED_LANES; j++)
            sf->tx_binding[j] = 4000 + (uint64_t)j;
        sf->fri_proof_len = 8;
        sf->fri_proof = malloc(8);
        if (!sf->fri_proof) { free(tx); return NULL; }
        fill(sf->fri_proof, 8, 0x90);
        break;
    }
    default: return NULL;
    }
    return tx;
}

static const char *FIXTURE_NAME[F_COUNT] = {
    "SPEND", "GENESIS", "BURN", "TOKEN_CREATE", "STAKE", "DELEGATE",
    "UNSTAKE", "UNDELEGATE", "VALIDATOR_UPDATE", "CHAIN_CONFIG", "SHIELDED"
};

/* ── PINNED LITERALS — captured from the PRE-S1 algorithm (HEAD eda03c61
 * worktree, this file with -DTX_KAT_CAPTURE, client==witness asserted
 * during capture). DO NOT regenerate with the post-S1 code: that would
 * make the KAT circular. ─────────────────────────────────────────────── */
static const char *KAT_HEX[F_COUNT] = {
    /* SPEND            */ "fb4fea059553c67fb4e5d4961592c307f5b02ee8f26ac5acb52b4b3c08bb5d185085d427eb5723ce223582c81803325f4ae9495941a62c438fd48fc30f1215d0",
    /* GENESIS          */ "cea63b8db23afc53c7413406fb181c7b4bc80792b2e5b8135b05413cf198b5e96ba882c96294260c2dd296a120e930dd3f1bdfde0f6f616f41dfd5747f65efd6",
    /* BURN             */ "24c91d055ddc966ca76c536f46cd14bcf43e66a505686d169517215a7979c887bb3ab66cf6388c8f99b166babe8fae4aed0c4fb42b8922d6dccd39c188bc2197",
    /* TOKEN_CREATE     */ "f3087bbbcc3d9c422b76598435ea93898a9e4128a904ed44ff3163316483bd410af546c4679b124778f0bde69cfc127ee90030c8eef18467f68807f6ed48e889",
    /* STAKE            */ "431f5a060f182b2dd032779393916637e4badb72bddd192529856a15ba08d80dfee932a22b4f799e42960d7485be48feac2af4675ad1dd27f688168529bd3a3e",
    /* DELEGATE         */ "e2575f5a1e9c1e4c2237a446d01aaa5ea22e50340d9f513ec6bfb30a1ca4b9e47d62791cb58735f3804b27c4a2ce757158c6936e281ed33ae22b3a6dfdb98566",
    /* UNSTAKE          */ "adb604adea3b19ff1431c5fbe031d69ae0d12c6ecdea3d3ba8f03ee64b86a4dad5fda5642f22d93e045ab817030b5200e52c699f965803be4a9d90079a890472",
    /* UNDELEGATE       */ "6485a0ff07f84bd4b45611e8d5258b54003327ffd45fd9f5b387005072d47ce99bbc039edf93496484a2086f73330836812fe9d5f9c24d33b70c2d4c2e8022d2",
    /* VALIDATOR_UPDATE */ "152f5e7604472bef0ae54f9856a5a205123bd26a04e36fbeab4dfa13a102cdbd3d201c058f7b888d3f3bd86772b87d656f8caf9ce4bdb1cd5954064e192431e1",
    /* CHAIN_CONFIG     */ "9cdc2e0722307639453c7d77861656d6531b6f173337c5d2b44bfec3a5ec6e12b81eb8fa1bc8dddd0dc44584663a29244a95a06a7ad7085dcdc3332193d110e8",
    /* SHIELDED         */ "528c62611ad40a9ac35fff7dfa4de9286d3d6533f1b6f54d1cbcc9b7ee966a47044b55e6f6605c2d8e5bec824e33880b8ce19c72f3aa76fdf31796039a41f9d9",
};

/* Serialize a fixture and compute the witness-side hash. */
static int witness_hash_of(const dnac_transaction_t *tx,
                           uint8_t out[64],
                           uint8_t **wire_out, size_t *wire_len_out) {
    size_t need = 0;
    uint8_t probe;
    (void)dnac_tx_serialize(tx, &probe, 0, &need);
    if (need == 0) return -1;
    uint8_t *wire = malloc(need);
    if (!wire) return -1;
    size_t written = 0;
    if (dnac_tx_serialize(tx, wire, need, &written) != DNAC_SUCCESS) {
        free(wire);
        return -1;
    }
    uint8_t pks[DNAC_TX_MAX_SIGNERS * DNAC_PUBKEY_SIZE];
    for (int i = 0; i < tx->signer_count; i++)
        memcpy(pks + (size_t)i * DNAC_PUBKEY_SIZE, tx->signers[i].pubkey,
               DNAC_PUBKEY_SIZE);
    int rc = nodus_witness_recompute_tx_hash(CHAIN_ID, wire, (uint32_t)written,
                                             tx->signer_count ? pks : NULL,
                                             tx->signer_count, out);
    if (rc != 0) { free(wire); return -1; }
    if (wire_out) { *wire_out = wire; *wire_len_out = written; }
    else free(wire);
    return 0;
}

static int run_fixture(int which) {
    dnac_transaction_t *tx = build_fixture(which);
    CHECK(tx != NULL, "fixture alloc");

    uint8_t h_client[64], h_witness[64];
    CHECK(dnac_tx_compute_hash(tx, h_client) == DNAC_SUCCESS, "client hash");
    uint8_t *wire = NULL; size_t wire_len = 0;
    CHECK(witness_hash_of(tx, h_witness, &wire, &wire_len) == 0, "witness hash");
    CHECK(memcmp(h_client, h_witness, 64) == 0, "client != witness"); OK();

#ifndef TX_KAT_CAPTURE
    /* Shared codec direct call — third leg of the identity. */
    {
        uint8_t pks[DNAC_TX_MAX_SIGNERS * DNAC_PUBKEY_SIZE];
        for (int i = 0; i < tx->signer_count; i++)
            memcpy(pks + (size_t)i * DNAC_PUBKEY_SIZE, tx->signers[i].pubkey,
                   DNAC_PUBKEY_SIZE);
        uint8_t h_shared[64];
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wire_len,
                                      tx->signer_count ? pks : NULL,
                                      tx->signer_count, h_shared) == 0,
              "shared hash");
        CHECK(memcmp(h_shared, h_client, 64) == 0, "shared != client"); OK();
    }
    /* Pinned pre-S1 literal. */
    {
        char hex[129];
        hex64(h_client, hex);
        if (strcmp(hex, KAT_HEX[which]) != 0) {
            fprintf(stderr, "KAT mismatch for %s:\n  pinned: %s\n  got:    %s\n",
                    FIXTURE_NAME[which], KAT_HEX[which], hex);
            free(wire);
            dnac_tx_free(tx);
            return -1;
        }
        OK();
    }
#else
    {
        char hex[129];
        hex64(h_client, hex);
        printf("    /* %-16s */ \"%s\",\n", FIXTURE_NAME[which], hex);
    }
#endif

    free(wire);
    dnac_tx_free(tx);
    return 0;
}

/* Invariance + mutation + negative checks (post-S1 build only). */
static int run_extras(void) {
    /* Genesis chain_def trailer is NOT part of the preimage. */
    {
        dnac_transaction_t *tx = build_fixture(F_GENESIS);
        CHECK(tx != NULL, "alloc");
        uint8_t h_plain[64], h_cd[64];
        CHECK(dnac_tx_compute_hash(tx, h_plain) == DNAC_SUCCESS, "hash");
        tx->has_chain_def = true;
        memset(&tx->chain_def, 0, sizeof(tx->chain_def));
        snprintf(tx->chain_def.chain_name, sizeof(tx->chain_def.chain_name), "kat");
        tx->chain_def.protocol_version = 2;
        tx->chain_def.witness_count = 1;
        fill(tx->chain_def.witness_pubkeys[0], DNAC_PUBKEY_SIZE, 0x77);
        tx->chain_def.initial_supply_raw = 1;
        CHECK(dnac_tx_compute_hash(tx, h_cd) == DNAC_SUCCESS, "hash+cd");
        CHECK(memcmp(h_plain, h_cd, 64) == 0,
              "chain_def trailer leaked into preimage"); OK();
        dnac_tx_free(tx);
    }
#ifndef TX_KAT_CAPTURE
    /* Shielded FRI blob excluded; statement included. */
    {
        dnac_transaction_t *tx = build_fixture(F_SHIELDED);
        CHECK(tx != NULL, "alloc");
        uint8_t h1[64], h2[64], h3[64];
        CHECK(dnac_tx_compute_hash(tx, h1) == DNAC_SUCCESS, "hash");
        tx->shielded_fields.fri_proof[0] ^= 0xFF;      /* blob mutation */
        CHECK(dnac_tx_compute_hash(tx, h2) == DNAC_SUCCESS, "hash2");
        CHECK(memcmp(h1, h2, 64) == 0, "FRI blob leaked into preimage"); OK();
        tx->shielded_fields.anchor[0] ^= 1;            /* statement mutation */
        CHECK(dnac_tx_compute_hash(tx, h3) == DNAC_SUCCESS, "hash3");
        CHECK(memcmp(h1, h3, 64) != 0, "anchor mutation did not change hash"); OK();
        dnac_tx_free(tx);
    }
    /* Wire-level mutations change the shared hash (chain_id, timestamp,
     * fee, input amount, output byte). */
    {
        dnac_transaction_t *tx = build_fixture(F_SPEND);
        CHECK(tx != NULL, "alloc");
        uint8_t base[64];
        uint8_t *wire = NULL; size_t wl = 0;
        CHECK(witness_hash_of(tx, base, &wire, &wl) == 0, "base");
        uint8_t pks[DNAC_TX_MAX_SIGNERS * DNAC_PUBKEY_SIZE];
        for (int i = 0; i < tx->signer_count; i++)
            memcpy(pks + (size_t)i * DNAC_PUBKEY_SIZE, tx->signers[i].pubkey,
                   DNAC_PUBKEY_SIZE);

        uint8_t cid2[32];
        memcpy(cid2, CHAIN_ID, 32); cid2[0] ^= 1;
        uint8_t h[64];
        CHECK(dnac_txw_legacy_tx_hash(cid2, wire, wl, pks, 1, h) == 0, "cid");
        CHECK(memcmp(h, base, 64) != 0, "chain_id not bound"); OK();

        size_t offs[4] = { 2 /* timestamp */, 74 /* fee */,
                           (size_t)DNAC_TX_HEADER_SIZE + 1 + 64 /* in0 amount */,
                           (size_t)DNAC_TX_HEADER_SIZE + 1 /* in0 nullifier */ };
        for (int i = 0; i < 4; i++) {
            wire[offs[i]] ^= 1;
            CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wl, pks, 1, h) == 0,
                  "mut hash");
            CHECK(memcmp(h, base, 64) != 0, "field not bound"); OK();
            wire[offs[i]] ^= 1;
        }
        /* Signer pubkey binding (caller-supplied array). */
        pks[0] ^= 1;
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wl, pks, 1, h) == 0, "pk");
        CHECK(memcmp(h, base, 64) != 0, "signer pubkey not bound"); OK();
        pks[0] ^= 1;

        /* Truncation INSIDE any walked section rejects. wl-2 cuts into the
         * last signer's signature bytes → the signers length-walk fails. */
        size_t cuts[5] = { 10, 81, (size_t)DNAC_TX_HEADER_SIZE,
                           (size_t)DNAC_TX_HEADER_SIZE + 1 + 100, wl - 2 };
        for (int i = 0; i < 5; i++) {
            CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, cuts[i], pks, 1, h) != 0,
                  "truncated accepted");
            OK();
        }
        /* Legacy-preserved semantics: bytes AFTER the walked sections (here
         * the 1-byte has_chain_def trailer flag) are ignored — dropping
         * them still hashes, to the SAME value. This is the pre-S1 behavior
         * (the trailer was never part of the preimage) and the capture run
         * of this file confirmed it on the pre-S1 witness code. */
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wl - 1, pks, 1, h) == 0 &&
              memcmp(h, base, 64) == 0, "trailer-drop changed the hash"); OK();
        /* Null / bad-count args reject. */
        CHECK(dnac_txw_legacy_tx_hash(NULL, wire, wl, pks, 1, h) != 0, "null cid"); OK();
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, NULL, wl, pks, 1, h) != 0, "null tx"); OK();
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wl, NULL, 1, h) != 0, "null pks"); OK();
        CHECK(dnac_txw_legacy_tx_hash(CHAIN_ID, wire, wl, pks, 5, h) != 0, "count>4"); OK();

        free(wire);
        dnac_tx_free(tx);
    }
#endif
    return 0;
}

int main(void) {
#ifdef TX_KAT_CAPTURE
    printf("static const char *KAT_HEX[F_COUNT] = {\n");
#endif
    for (int f = 0; f < F_COUNT; f++) {
        if (run_fixture(f) != 0) {
            fprintf(stderr, "FIXTURE %s FAILED\n", FIXTURE_NAME[f]);
            return 1;
        }
    }
#ifdef TX_KAT_CAPTURE
    printf("};\n");
#endif
    if (run_extras() != 0) return 1;
    printf("test_tx_hash_kat: %d checks OK\n", g_checks);
    return 0;
}
