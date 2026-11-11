/**
 * @file amm_eth_tx.h
 * @brief nodus-amm Ethereum transaction: EIP-1559 (type 2) encoding, signing
 *        hash and signing, and the USDT `transfer` call data.
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 4)
 * section 10 line 263 ("EIP-1559 fee-market transaction calling USDT
 * transfer(user, amount); structure and signing hash from execution-specs"),
 * section 2 (execution-specs a87891f7 pin), section 3 line 148 (in-tree
 * Keccak-256, pinned libsecp256k1 v0.8.0 with the recovery module).
 *
 * REFERENCES (every rule below is read, not remembered):
 *   structure       execution-specs a87891f7 src/ethereum/forks/osaka/
 *                   transactions.py:208-278 (FeeMarketTransaction: chain_id,
 *                   nonce, max_priority_fee_per_gas, max_fee_per_gas, gas, to
 *                   (Bytes0 | Address), value, data, access_list (Access =
 *                   account, slots; :115-130), y_parity, r, s)
 *   signing hash    transactions.py:822-844 signing_hash_1559:
 *                   keccak256(0x02 || rlp([chain_id, nonce, max_priority,
 *                   max_fee, gas, to, value, data, access_list]))
 *   wire form       transactions.py:498-517 encode_transaction:
 *                   0x02 || rlp(FeeMarketTransaction), i.e. the nine fields
 *                   above followed by y_parity, r, s
 *   transaction id  transactions.py:906-918 get_transaction_hash:
 *                   keccak256(the typed encoding)
 *   RLP             ethereum-rlp 0.1.6 (execution-specs' pin, uv.lock:1190),
 *                   src/ethereum_rlp/rlp.py encode :66-130 (an integer is
 *                   `encode(to_be_bytes())`, :77-78): the in-tree
 *                   encoder shared/evm/trie/evm_trie_rlp.c is conformity
 *                   tested against it (evm_trie.h:90-94); integers are
 *                   written as their minimal big-endian bytes, zero as the
 *                   empty string (the vector below shows it: nonce 0 = 0x80)
 *   signature       libsecp256k1 v0.8.0 (shared/evm/third_party/secp256k1/
 *                   PINNED.md): secp256k1_ecdsa_sign_recoverable with the
 *                   default nonce function (RFC 6979,
 *                   include/secp256k1_recovery.h:84-91, "If NULL,
 *                   secp256k1_nonce_function_default is used"); y_parity is
 *                   the recovery id (0 or 1: transactions.py:725-726 rejects
 *                   anything else, so a recovery id of 2 or 3 is refused);
 *                   s is low by construction of the library
 *   USDT call       transfer(address,uint256): selector a9059cbb (THORChain
 *                   direct_erc20_transfer.go:20, as amm_eth_watch.c) followed
 *                   by the recipient and the amount as two 32-byte words
 *                   (TetherToken.sol:336 `transfer(address _to, uint _value)`)
 *
 * KNOWN ANSWERS (test_amm_eth_tx): execution-specs a87891f7
 * packages/testing/src/execution_testing/test_types/tests/
 * test_transactions.py:182-204 (type 2, `to` = 0x..aa) and :205-227 (type 2,
 * `to` = None), both signed with base_types/constants.py:8-10 TestPrivateKey
 * (chain id 1: test_types/chain_config_types.py:7; default `to` AddrAA:
 * test_types/transaction_types.py:337), sender
 * 0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b.
 *
 * No clock, no randomness of its own: RFC 6979 is deterministic, so the same
 * transaction signed twice is the same bytes. A caller supplies the optional
 * 32 blinding bytes of the signing context (secp256k1.h:268-278 recommends
 * secp256k1_context_randomize for a context that signs); this module reads no
 * RNG.
 */
#ifndef AMM_ETH_TX_H
#define AMM_ETH_TX_H

#include <stdint.h>
#include <stddef.h>

#define AMM_TX_ACCESS_MAX_ENTRIES 4
#define AMM_TX_ACCESS_MAX_KEYS    4
/** The most the encoder accepts as call data (a payout carries 68 bytes). */
#define AMM_TX_DATA_MAX           1024
#define AMM_TX_TRANSFER_DATA_LEN  68

typedef struct {
    uint8_t account[20];
    int     n_keys;
    uint8_t keys[AMM_TX_ACCESS_MAX_KEYS][32];
} amm_tx_access_t;

/** FeeMarketTransaction without its signature. */
typedef struct {
    uint64_t chain_id;
    uint64_t nonce;
    uint64_t max_priority_fee_per_gas;
    uint64_t max_fee_per_gas;
    uint64_t gas;
    int      has_to;                 /* 0 = Bytes0 (contract creation)       */
    uint8_t  to[20];
    uint8_t  value[32];              /* wei, big-endian                      */
    const uint8_t *data;
    size_t   data_len;
    const amm_tx_access_t *access;
    int      n_access;
} amm_tx1559_t;

/** The signing hash of transactions.py:822-844. 0 / -1 (a field that does not
 *  fit its bound). */
int amm_tx1559_signing_hash(const amm_tx1559_t *tx, uint8_t out[32]);

/** The typed encoding 0x02 || rlp(tx fields, y_parity, r, s) of
 *  transactions.py:498-517 for a GIVEN signature. `*raw` is malloc'd (caller
 *  frees). y_parity must be 0 or 1. 0 / -1. */
int amm_tx1559_encode(const amm_tx1559_t *tx, int y_parity,
                      const uint8_t r[32], const uint8_t s[32],
                      uint8_t **raw, size_t *raw_len);

/** The transaction id: keccak256 of the typed encoding (transactions.py:
 *  906-918). 0 / -1. */
int amm_tx_hash(const uint8_t *raw, size_t raw_len, uint8_t out[32]);

/** A signing key: the secret key and a libsecp256k1 context that can sign. */
typedef struct amm_signer amm_signer_t;

/** `sk` is checked as a valid secret key (secp256k1_ec_seckey_verify).
 *  `blind` (NULL = none) is 32 caller-supplied bytes for
 *  secp256k1_context_randomize. NULL on failure. The secret key is kept in
 *  the object and wiped by amm_signer_free. */
amm_signer_t *amm_signer_new(const uint8_t sk[32], const uint8_t blind[32]);
void amm_signer_free(amm_signer_t *s);
/** The signer's Ethereum address: the last 20 bytes of keccak256 of the
 *  uncompressed public key without its 0x04 prefix (the rule the in-tree
 *  ecrecover port applies, shared/evm/evm_precompile.c:187-192). */
void amm_signer_address(const amm_signer_t *s, uint8_t out[20]);

/** Sign `tx` and return the typed encoding (`*raw`, malloc'd) and its
 *  transaction id. Before returning, the signature is recovered again and the
 *  recovered address must equal the signer's (a failure is -1 and nothing is
 *  returned). `hash_out` may be NULL. 0 / -1. */
int amm_tx1559_sign(const amm_signer_t *s, const amm_tx1559_t *tx,
                    uint8_t **raw, size_t *raw_len, uint8_t hash_out[32]);

/** The call data of USDT `transfer(to, amount)`: a9059cbb || word(to) ||
 *  word(amount), 68 bytes. */
void amm_tx_transfer_calldata(const uint8_t to[20], uint64_t amount,
                              uint8_t out[AMM_TX_TRANSFER_DATA_LEN]);

#endif /* AMM_ETH_TX_H */
