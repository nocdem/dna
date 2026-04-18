/* Hard-Fork v1 — CHAIN_CONFIG TX serialize/deserialize + hash-binding tests.
 *
 * Verifies:
 *   - Round-trip identity: serialize → deserialize → fields match
 *   - Unknown TX type (11+) rejected at deserialize (CC-AUDIT rejection path)
 *   - Compute_hash binds every chain_config_fields member (mutating any
 *     field changes tx_hash)
 *   - Committee_votes trailing padded slots are NOT hashed
 */

#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
        __FILE__, __LINE__, #cond); exit(1); } } while(0)

#define CHECK_OK(expr) do { \
    int _rc = (expr); \
    if (_rc != DNAC_SUCCESS) { \
        fprintf(stderr, "CHECK_OK fail at %s:%d: %s -> %d\n", \
            __FILE__, __LINE__, #expr, _rc); exit(1); } } while(0)

static void build_signed_chain_config(dnac_transaction_t *tx, uint8_t n_sigs) {
    memset(tx, 0, sizeof(*tx));
    tx->version = 1;
    tx->type = DNAC_TX_CHAIN_CONFIG;
    tx->timestamp = 1745000000ULL;
    for (int i = 0; i < 32; i++) tx->chain_id[i] = 0xC1;

    tx->signer_count = 1;
    for (int i = 0; i < DNAC_PUBKEY_SIZE; i++)
        tx->signers[0].pubkey[i] = (uint8_t)(i & 0xff);
    for (int i = 0; i < DNAC_SIGNATURE_SIZE; i++)
        tx->signers[0].signature[i] = (uint8_t)((i * 3) & 0xff);

    dnac_tx_chain_config_fields_t *cc = &tx->chain_config_fields;
    cc->param_id               = DNAC_CFG_MAX_TXS_PER_BLOCK;
    cc->new_value              = 7ULL;
    cc->effective_block_height = 10000ULL;
    cc->proposal_nonce         = 0x0123456789ABCDEFULL;
    cc->signed_at_block        = 9500ULL;
    cc->valid_before_block     = 10200ULL;
    cc->committee_sig_count    = n_sigs;
    for (uint8_t i = 0; i < n_sigs; i++) {
        for (int b = 0; b < 32; b++)
            cc->committee_votes[i].witness_id[b] = (uint8_t)((i * 7 + b) & 0xff);
        for (int b = 0; b < DNAC_SIGNATURE_SIZE; b++)
            cc->committee_votes[i].signature[b] = (uint8_t)((i * 11 + b) & 0xff);
    }
}

static void compute_hash_or_die(const dnac_transaction_t *tx, uint8_t out[DNAC_TX_HASH_SIZE]) {
    CHECK_OK(dnac_tx_compute_hash(tx, out));
}

int main(void) {
    /* ──────────────────────────────────────────────────────────────────
     * Part 1: round-trip for n_sigs ∈ {5, 6, 7}
     * ────────────────────────────────────────────────────────────────── */
    for (uint8_t n = 5; n <= 7; n++) {
        dnac_transaction_t tx;
        build_signed_chain_config(&tx, n);
        compute_hash_or_die(&tx, tx.tx_hash);

        /* Upper-bound buffer — oversized on purpose. */
        uint8_t buf[64 * 1024];
        size_t written = 0;
        CHECK_OK(dnac_tx_serialize(&tx, buf, sizeof(buf), &written));
        CHECK(written > 0);

        dnac_transaction_t *tx2 = NULL;
        CHECK_OK(dnac_tx_deserialize(buf, written, &tx2));
        CHECK(tx2 != NULL);

        CHECK(tx2->type == DNAC_TX_CHAIN_CONFIG);
        CHECK(tx2->signer_count == 1);
        const dnac_tx_chain_config_fields_t *a = &tx.chain_config_fields;
        const dnac_tx_chain_config_fields_t *b = &tx2->chain_config_fields;
        CHECK(a->param_id == b->param_id);
        CHECK(a->new_value == b->new_value);
        CHECK(a->effective_block_height == b->effective_block_height);
        CHECK(a->proposal_nonce == b->proposal_nonce);
        CHECK(a->signed_at_block == b->signed_at_block);
        CHECK(a->valid_before_block == b->valid_before_block);
        CHECK(a->committee_sig_count == b->committee_sig_count);
        for (uint8_t i = 0; i < n; i++) {
            CHECK(memcmp(a->committee_votes[i].witness_id,
                         b->committee_votes[i].witness_id, 32) == 0);
            CHECK(memcmp(a->committee_votes[i].signature,
                         b->committee_votes[i].signature,
                         DNAC_SIGNATURE_SIZE) == 0);
        }

        /* Tx-hash stable across serialize/deserialize.
         * chain_id is intentionally NOT serialized on the wire — witnesses
         * supply it from chain context (design §2.3, F-CRYPTO-10). Re-bind
         * before recomputing so both sides see the same preimage. */
        memcpy(tx2->chain_id, tx.chain_id, sizeof(tx.chain_id));
        uint8_t h2[DNAC_TX_HASH_SIZE];
        compute_hash_or_die(tx2, h2);
        CHECK(memcmp(tx.tx_hash, h2, DNAC_TX_HASH_SIZE) == 0);

        dnac_free_transaction(tx2);
    }

    /* ──────────────────────────────────────────────────────────────────
     * Part 2: hash binds every field. Mutate each in turn; hash MUST change.
     * ────────────────────────────────────────────────────────────────── */
    dnac_transaction_t base;
    build_signed_chain_config(&base, 5);
    uint8_t base_hash[DNAC_TX_HASH_SIZE];
    compute_hash_or_die(&base, base_hash);

    dnac_transaction_t m;
    uint8_t h[DNAC_TX_HASH_SIZE];

    /* param_id */
    m = base;
    m.chain_config_fields.param_id = DNAC_CFG_BLOCK_INTERVAL_SEC;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* new_value */
    m = base;
    m.chain_config_fields.new_value = base.chain_config_fields.new_value + 1;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* effective_block_height */
    m = base;
    m.chain_config_fields.effective_block_height += 1;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* proposal_nonce */
    m = base;
    m.chain_config_fields.proposal_nonce ^= 1ULL;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* signed_at_block */
    m = base;
    m.chain_config_fields.signed_at_block += 1;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* valid_before_block */
    m = base;
    m.chain_config_fields.valid_before_block += 1;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* committee_sig_count — same bytes but different count should differ */
    m = base;
    m.chain_config_fields.committee_sig_count = 6;
    /* Populate vote[5] so serialize buffer stays coherent; still a hash-input
     * mutation via count byte + the extra vote bytes. */
    for (int b = 0; b < 32; b++)
        m.chain_config_fields.committee_votes[5].witness_id[b] = (uint8_t)(0xA0 + b);
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* committee_votes[0].witness_id */
    m = base;
    m.chain_config_fields.committee_votes[0].witness_id[0] ^= 0xFF;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* committee_votes[0].signature */
    m = base;
    m.chain_config_fields.committee_votes[0].signature[100] ^= 0xFF;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) != 0);

    /* ──────────────────────────────────────────────────────────────────
     * Part 3: trailing padded slots (beyond committee_sig_count) are NOT
     * hashed. Mutating votes[5] or votes[6] when committee_sig_count == 5
     * must NOT change the hash.
     * ────────────────────────────────────────────────────────────────── */
    m = base;  /* committee_sig_count == 5 */
    m.chain_config_fields.committee_votes[5].witness_id[0] = 0xFF;
    m.chain_config_fields.committee_votes[6].signature[0]  = 0xFF;
    compute_hash_or_die(&m, h);
    CHECK(memcmp(base_hash, h, DNAC_TX_HASH_SIZE) == 0);

    /* ──────────────────────────────────────────────────────────────────
     * Part 4: deserialize rejects unknown TX type (type byte > 10).
     * ────────────────────────────────────────────────────────────────── */
    {
        dnac_transaction_t tx;
        build_signed_chain_config(&tx, 5);
        compute_hash_or_die(&tx, tx.tx_hash);
        uint8_t buf[64 * 1024];
        size_t written = 0;
        CHECK_OK(dnac_tx_serialize(&tx, buf, sizeof(buf), &written));
        /* Corrupt type byte — header layout: version(1) || type(1) || ... */
        buf[1] = (uint8_t)(DNAC_TX_CHAIN_CONFIG + 1);  /* 11 — unknown */
        dnac_transaction_t *bad = NULL;
        int rc = dnac_tx_deserialize(buf, written, &bad);
        CHECK(rc != DNAC_SUCCESS);
        CHECK(bad == NULL);
    }

    printf("test_chain_config_serialize: ALL CHECKS PASSED\n");
    return 0;
}
