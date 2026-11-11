/**
 * @file amm_eth_tx.c
 * @brief nodus-amm EIP-1559 transaction encoding and signing (see
 *        amm_eth_tx.h for the references of every rule).
 */
#include "amm_eth_tx.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/hash/keccak256.h"
#include "evm/trie/evm_trie_rlp.h"

#define TX_TYPE_FEE_MARKET 0x02    /* encode_transaction: b"\x02" + rlp  */

/* USDT transfer(address,uint256): THORChain direct_erc20_transfer.go:20
 * (`erc20TransferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}`). */
static const uint8_t TRANSFER_SELECTOR[4] = {0xa9, 0x05, 0x9c, 0xbb};

/* ── RLP pieces ───────────────────────────────────────────────────────── */

/* An integer as its minimal big-endian bytes (zero = the empty string),
 * ethereum_rlp rlp.py:77-78. */
static int put_be_min(evm_trie_rlp_buf *b, const uint8_t *be, size_t n) {
    size_t i = 0;
    while (i < n && be[i] == 0) i++;
    return evm_trie_rlp_put_bytes(b, be + i, n - i);
}

static int put_u64(evm_trie_rlp_buf *b, uint64_t v) {
    uint8_t be[8];
    for (int i = 0; i < 8; i++) be[i] = (uint8_t)(v >> (56 - 8 * i));
    return put_be_min(b, be, 8);
}

/* The nine signing fields (transactions.py:828-842), then, when `sig`, the
 * signature fields (the dataclass order, :189-205). One RLP list behind the
 * type byte. */
static int build(const amm_tx1559_t *tx, int sig, int y_parity,
                 const uint8_t r[32], const uint8_t s[32],
                 evm_trie_rlp_buf *b) {
    if (!tx || (tx->data_len > 0 && !tx->data) || tx->data_len > AMM_TX_DATA_MAX ||
        tx->n_access < 0 || tx->n_access > AMM_TX_ACCESS_MAX_ENTRIES ||
        (tx->n_access > 0 && !tx->access))
        return -1;
    for (int i = 0; i < tx->n_access; i++)
        if (tx->access[i].n_keys < 0 || tx->access[i].n_keys > AMM_TX_ACCESS_MAX_KEYS)
            return -1;
    const uint8_t type = TX_TYPE_FEE_MARKET;
    if (evm_trie_rlp_put_raw(b, &type, 1) != 0) return -1;
    const size_t list_start = 1;
    if (put_u64(b, tx->chain_id) != 0 || put_u64(b, tx->nonce) != 0 ||
        put_u64(b, tx->max_priority_fee_per_gas) != 0 ||
        put_u64(b, tx->max_fee_per_gas) != 0 || put_u64(b, tx->gas) != 0)
        return -1;
    /* to: Bytes0 | Address (an empty string or the 20 bytes) */
    if (evm_trie_rlp_put_bytes(b, tx->to, tx->has_to ? 20 : 0) != 0) return -1;
    if (put_be_min(b, tx->value, 32) != 0) return -1;
    if (evm_trie_rlp_put_bytes(b, tx->data, tx->data_len) != 0) return -1;
    /* access_list: Tuple[Access, ...]; Access = (account, slots) */
    size_t al = b->len;
    for (int i = 0; i < tx->n_access; i++) {
        size_t ent = b->len;
        if (evm_trie_rlp_put_bytes(b, tx->access[i].account, 20) != 0) return -1;
        size_t slots = b->len;
        for (int k = 0; k < tx->access[i].n_keys; k++)
            if (evm_trie_rlp_put_bytes(b, tx->access[i].keys[k], 32) != 0) return -1;
        if (evm_trie_rlp_wrap_list(b, slots) != 0) return -1;
        if (evm_trie_rlp_wrap_list(b, ent) != 0) return -1;
    }
    if (evm_trie_rlp_wrap_list(b, al) != 0) return -1;
    if (sig) {
        if ((y_parity != 0 && y_parity != 1) || !r || !s) return -1;
        const uint8_t yp = (uint8_t)y_parity;
        if (put_be_min(b, &yp, 1) != 0 || put_be_min(b, r, 32) != 0 ||
            put_be_min(b, s, 32) != 0) return -1;
    }
    if (evm_trie_rlp_wrap_list(b, list_start) != 0) return -1;
    return 0;
}

int amm_tx1559_signing_hash(const amm_tx1559_t *tx, uint8_t out[32]) {
    if (!out) return -1;
    evm_trie_rlp_buf b = {0};
    int rc = -1;
    if (build(tx, 0, 0, NULL, NULL, &b) == 0 &&
        keccak256(b.p, b.len, out) == 0) rc = 0;
    evm_trie_rlp_buf_free(&b);
    return rc;
}

int amm_tx1559_encode(const amm_tx1559_t *tx, int y_parity,
                      const uint8_t r[32], const uint8_t s[32],
                      uint8_t **raw, size_t *raw_len) {
    if (!raw || !raw_len) return -1;
    *raw = NULL;
    *raw_len = 0;
    evm_trie_rlp_buf b = {0};
    if (build(tx, 1, y_parity, r, s, &b) != 0) {
        evm_trie_rlp_buf_free(&b);
        return -1;
    }
    *raw = b.p;                 /* ownership moves to the caller (malloc'd) */
    *raw_len = b.len;
    return 0;
}

int amm_tx_hash(const uint8_t *raw, size_t raw_len, uint8_t out[32]) {
    if (!raw || raw_len == 0 || !out) return -1;
    return keccak256(raw, raw_len, out) == 0 ? 0 : -1;
}

/* ── signer ───────────────────────────────────────────────────────────── */

struct amm_signer {
    secp256k1_context *ctx;
    uint8_t sk[32];
    uint8_t addr[20];
};

static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* keccak256(uncompressed pubkey without the 0x04 prefix)[12..32], as the
 * ecrecover port does (evm_precompile.c:187-192). */
static int address_of(const secp256k1_context *ctx, const secp256k1_pubkey *pub,
                      uint8_t out[20]) {
    uint8_t ser[65], h[32];
    size_t n = sizeof(ser);
    if (!secp256k1_ec_pubkey_serialize(ctx, ser, &n, pub,
                                       SECP256K1_EC_UNCOMPRESSED) || n != 65)
        return -1;
    if (keccak256(ser + 1, 64, h) != 0) return -1;
    memcpy(out, h + 12, 20);
    return 0;
}

amm_signer_t *amm_signer_new(const uint8_t sk[32], const uint8_t blind[32]) {
    if (!sk) return NULL;
    amm_signer_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_pubkey pub;
    if (!s->ctx || !secp256k1_ec_seckey_verify(s->ctx, sk) ||
        (blind && !secp256k1_context_randomize(s->ctx, blind)) ||
        !secp256k1_ec_pubkey_create(s->ctx, &pub, sk) ||
        address_of(s->ctx, &pub, s->addr) != 0) {
        amm_signer_free(s);
        return NULL;
    }
    memcpy(s->sk, sk, 32);
    return s;
}

void amm_signer_free(amm_signer_t *s) {
    if (!s) return;
    if (s->ctx) secp256k1_context_destroy(s->ctx);
    wipe(s->sk, sizeof(s->sk));
    free(s);
}

void amm_signer_address(const amm_signer_t *s, uint8_t out[20]) {
    memcpy(out, s->addr, 20);
}

int amm_tx1559_sign(const amm_signer_t *s, const amm_tx1559_t *tx,
                    uint8_t **raw, size_t *raw_len, uint8_t hash_out[32]) {
    if (!s || !tx || !raw || !raw_len) return -1;
    *raw = NULL;
    *raw_len = 0;
    uint8_t sh[32], rs[64];
    int recid = -1;
    if (amm_tx1559_signing_hash(tx, sh) != 0) return -1;
    secp256k1_ecdsa_recoverable_signature sig;
    /* noncefp NULL = secp256k1_nonce_function_default (RFC 6979) */
    if (!secp256k1_ecdsa_sign_recoverable(s->ctx, &sig, sh, s->sk, NULL, NULL) ||
        !secp256k1_ecdsa_recoverable_signature_serialize_compact(s->ctx, rs,
                                                                 &recid, &sig))
        return -1;
    /* transactions.py:725-726: y_parity must be 0 or 1 */
    if (recid != 0 && recid != 1) return -1;
    /* the signature must recover to the signer, before anything leaves */
    secp256k1_pubkey rec;
    uint8_t raddr[20];
    if (!secp256k1_ecdsa_recover(s->ctx, &rec, &sig, sh) ||
        address_of(s->ctx, &rec, raddr) != 0 || memcmp(raddr, s->addr, 20) != 0)
        return -1;
    uint8_t *out = NULL;
    size_t n = 0;
    if (amm_tx1559_encode(tx, recid, rs, rs + 32, &out, &n) != 0) return -1;
    if (hash_out && amm_tx_hash(out, n, hash_out) != 0) {
        free(out);
        return -1;
    }
    *raw = out;
    *raw_len = n;
    return 0;
}

void amm_tx_transfer_calldata(const uint8_t to[20], uint64_t amount,
                              uint8_t out[AMM_TX_TRANSFER_DATA_LEN]) {
    memset(out, 0, AMM_TX_TRANSFER_DATA_LEN);
    memcpy(out, TRANSFER_SELECTOR, 4);
    memcpy(out + 4 + 12, to, 20);                 /* address word: 12 zeros first */
    for (int i = 0; i < 8; i++)                   /* uint256 word, big-endian     */
        out[36 + 24 + i] = (uint8_t)(amount >> (56 - 8 * i));
}
