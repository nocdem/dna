/**
 * test_amm_eth_tx.c -- the nodus-amm EIP-1559 transaction (amm_eth_tx.c):
 * RLP encoding, signing hash, RFC 6979 signing with libsecp256k1 v0.8.0, the
 * USDT transfer call data.
 *
 * WHAT IT PROVES (plan docs/plans/2026-11-08-swap-bot-plan.nodus1.md rev. 4,
 * section 10 line 263):
 *   K1  KNOWN ANSWERS from the pinned execution-specs a87891f7
 *       (packages/testing/src/execution_testing/test_types/tests/
 *       test_transactions.py:182-204 and :205-227): the key
 *       base_types/constants.py:8-10 TestPrivateKey, the fields of the type-2
 *       transaction (chain id 1, nonce 0, max priority 5, max fee 10, gas
 *       21000, to 0x..aa or none, value 0, empty data, access list
 *       [(0x..0123, [0x..0456, 0x..0789])]) -> the signer address
 *       0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b, the serialized bytes, and
 *       the (y_parity, r, s) of the vector (the decimal r and s of the source
 *       converted to hex). This pins: the field order, the integer rule
 *       (zero = empty string), the access-list nesting, the `to` Bytes0
 *       branch, the type byte, AND the RFC 6979 low-s signature byte for byte;
 *   K2  the ENCODER alone: the vector's own signature fed to
 *       amm_tx1559_encode (no signing involved) gives the vector's bytes;
 *   K3  the SIGNING HASH alone: the in-tree ecrecover port
 *       (shared/evm/evm_precompile.c, address 0x01, called through
 *       evm_precompile_run) recovers 0xa94f..bf0b from the vector's
 *       signature and OUR signing hash -- a hash that differed by one byte
 *       from signing_hash_1559 would recover a different address;
 *   K4  our own signature: recovered with the same ecrecover port, the
 *       signer is the key's address (also for the payout-shaped transaction
 *       below);
 *   K5  determinism: the same transaction signed twice is the same bytes (RFC
 *       6979); the transaction id is keccak256 of the typed encoding;
 *   K6  the USDT call data: a9059cbb, the recipient left-padded to 32 bytes,
 *       the amount as a 32-byte big-endian word; the selector equals
 *       keccak256("transfer(address,uint256)")[0..4] computed by the in-tree
 *       ABI layer (the derivation rule is thereby checked on a pinned value:
 *       THORChain direct_erc20_transfer.go:20);
 *   K7  the payout-shaped transaction (chain 1, to = the USDT contract, 68
 *       bytes of call data, empty access list, value 0) decodes with the
 *       in-tree RLP decoder into the twelve fields it was built from (a
 *       self-consistency check, NOT a reference vector);
 *   K8  refusals: an invalid secret key (zero, the curve order), a y_parity
 *       of 2, too many access entries / keys, call data above the bound, a
 *       NULL data pointer with a length -> -1, nothing returned.
 * REFERENCE FOR THE VECTOR: only the two vectors above; no value in this file
 * was made up or taken from memory. The raw hex and the key are copied from
 * the cited lines; r and s are the decimals printed there, converted with
 * python3 (the conversion only).
 * FLAGS: a default build; no fault injection. LEAVES BEHIND: nothing.
 * HOW IT CAN LIE: a vector is a vector -- two transactions, one key. The
 * signing-hash check (K3) uses the ecrecover port, which is the repository's
 * own code (conformance-tested against the execution-specs ecrecover); the
 * encoder is checked by bytes, the signing hash by recovery, so an error in
 * both that cancelled out would need the vector's r and s to recover to the
 * vector's sender for a wrong hash, which it does not.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amm_eth_tx.h"
#include "crypto/hash/keccak256.h"
#include "evm/evm_internal.h"
#include "evm/trie/evm_trie_rlp.h"
#include "client/nodus_evm_abi.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/* hex text (optional 0x) -> bytes; returns the length or -1 */
static int unhex(const char *s, uint8_t *out, size_t cap) {
    if (s[0] == '0' && s[1] == 'x') s += 2;
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int a = hexval(s[2 * i]), b = hexval(s[2 * i + 1]);
        if (a < 0 || b < 0) return -1;
        out[i] = (uint8_t)(a * 16 + b);
    }
    return (int)(n / 2);
}

/* ── the pinned vectors (test_transactions.py) ──────────────────────── */

/* base_types/constants.py:8-10 TestPrivateKey */
#define KEY_HEX "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8"
/* test_transactions.py:197 / :221 expected_sender */
#define SENDER_HEX "a94f5374fce5edbc8e2a8697c15331677e6ebf0b"

/* test_transactions.py:198-203 expected_serialized (type 2, to = 0x..aa) */
#define RAW1_HEX \
    "02f8be0180050a8252089400000000000000000000000000000000000000aa8080f85bf8599400" \
    "00000000000000000000000000000000000123f842a0000000000000000000000000000000000000" \
    "0000000000000000000000000456a000000000000000000000000000000000000000000000000000" \
    "0000000000078980a0cad8994ac160fd7e167715bbe20212939abdd5cd5a1f6c4dd6e5612cd8b332" \
    "20a062a44d12b176bbd669d09d20d26281b5a693d8a52ab02a9d130201ee5db113dd"
/* the decimals of :194-195 as hex (python3: '%064x' % r) */
#define R1_HEX "cad8994ac160fd7e167715bbe20212939abdd5cd5a1f6c4dd6e5612cd8b33220"
#define S1_HEX "62a44d12b176bbd669d09d20d26281b5a693d8a52ab02a9d130201ee5db113dd"

/* test_transactions.py:222-226 expected_serialized (type 2, to = None) */
#define RAW2_HEX \
    "02f8aa0180050a825208808080f85bf859940000000000000000000000000000000000000123f8" \
    "42a00000000000000000000000000000000000000000000000000000000000000456a00000000000" \
    "00000000000000000000000000000000000000000000000000078980a0c7b07c5552829e585f68e2" \
    "eed4495ed6dfbe8cb1453edb2dc1e959d1087f5fe1a018a70ff379958b47e85172bc93fe5e47dc23" \
    "d13e3b0e4a800f1f3a0766a0af3a"
/* the decimals of :218-219 as hex */
#define R2_HEX "c7b07c5552829e585f68e2eed4495ed6dfbe8cb1453edb2dc1e959d1087f5fe1"
#define S2_HEX "18a70ff379958b47e85172bc93fe5e47dc23d13e3b0e4a800f1f3a0766a0af3a"

/* the vector's transaction fields: chain 1 (chain_config_types.py:7), nonce 0,
 * max priority 5, max fee 10, gas 21000, value 0, data empty, access list
 * [(0x123, [0x456, 0x789])] (the Transaction(...) arguments, :183-193) */
static amm_tx_access_t g_acc;

static void vector_tx(amm_tx1559_t *tx, int has_to) {
    memset(tx, 0, sizeof(*tx));
    memset(&g_acc, 0, sizeof(g_acc));
    g_acc.account[18] = 0x01; g_acc.account[19] = 0x23;          /* 0x123 */
    g_acc.n_keys = 2;
    g_acc.keys[0][30] = 0x04; g_acc.keys[0][31] = 0x56;          /* 0x456 */
    g_acc.keys[1][30] = 0x07; g_acc.keys[1][31] = 0x89;          /* 0x789 */
    tx->chain_id = 1;
    tx->nonce = 0;
    tx->max_priority_fee_per_gas = 5;
    tx->max_fee_per_gas = 10;
    tx->gas = 21000;
    tx->has_to = has_to;
    if (has_to) { tx->to[19] = 0xaa; }                           /* AddrAA */
    tx->access = &g_acc;
    tx->n_access = 1;
}

/* the in-tree ecrecover port, address 0x01 (evm_precompile.c pc_ecrecover):
 * input hash || v (32) || r || s, v = 27 + parity; output a 32-byte word. */
static int ecrecover_addr(const uint8_t h[32], int parity, const uint8_t r[32],
                          const uint8_t s[32], uint8_t out20[20]) {
    uint8_t in[128];
    memcpy(in, h, 32);
    memset(in + 32, 0, 32);
    in[63] = (uint8_t)(27 + parity);
    memcpy(in + 64, r, 32);
    memcpy(in + 96, s, 32);
    evm_addr a;
    memset(&a, 0, sizeof(a));
    a.b[31] = 1;
    uint64_t gas = 1000000;
    evm_pc_result_t res;
    uint8_t *out = NULL;
    size_t olen = 0;
    int rc = evm_precompile_run(&a, in, sizeof(in), &gas, &res, &out, &olen);
    int ok = (rc == 0 && res == EVM_PC_OK && olen == 32 && out != NULL);
    if (ok) memcpy(out20, out + 12, 20);
    free(out);
    return ok ? 0 : -1;
}

static int check_vector(int has_to, const char *raw_hex, const char *r_hex,
                        const char *s_hex, const char *name) {
    uint8_t key[32], want[256], r[32], s[32], sender[20];
    int wl = unhex(raw_hex, want, sizeof(want));
    unhex(KEY_HEX, key, 32);
    unhex(r_hex, r, 32);
    unhex(s_hex, s, 32);
    unhex(SENDER_HEX, sender, 20);
    char msg[160];

    amm_tx1559_t tx;
    vector_tx(&tx, has_to);
    amm_signer_t *sg = amm_signer_new(key, NULL);
    CHECK(sg != NULL, "K1 the pinned key is a valid secret key");
    if (!sg) return -1;
    uint8_t addr[20];
    amm_signer_address(sg, addr);
    snprintf(msg, sizeof(msg), "K1 %s: the key's address is the vector's sender", name);
    CHECK(memcmp(addr, sender, 20) == 0, msg);

    uint8_t *raw = NULL;
    size_t rl = 0;
    uint8_t id[32], id2[32];
    snprintf(msg, sizeof(msg), "K1 %s: signing succeeds", name);
    CHECK(amm_tx1559_sign(sg, &tx, &raw, &rl, id) == 0, msg);
    snprintf(msg, sizeof(msg), "K1 %s: the serialized bytes equal the vector's (RLP + RFC 6979 low-s signature)", name);
    CHECK(raw && wl > 0 && rl == (size_t)wl && memcmp(raw, want, rl) == 0, msg);
    snprintf(msg, sizeof(msg), "K5 %s: the transaction id is keccak256 of the typed encoding", name);
    CHECK(raw && keccak256(raw, rl, id2) == 0 && memcmp(id, id2, 32) == 0, msg);

    uint8_t *raw_b = NULL;
    size_t rl_b = 0;
    snprintf(msg, sizeof(msg), "K5 %s: signing twice gives the same bytes", name);
    CHECK(amm_tx1559_sign(sg, &tx, &raw_b, &rl_b, NULL) == 0 && raw && raw_b &&
          rl_b == rl && memcmp(raw, raw_b, rl) == 0, msg);
    free(raw_b);
    free(raw);

    /* K2: the encoder alone, with the vector's own signature */
    raw = NULL;
    rl = 0;
    snprintf(msg, sizeof(msg), "K2 %s: encoding the vector's own (0, r, s) gives the vector's bytes", name);
    CHECK(amm_tx1559_encode(&tx, 0, r, s, &raw, &rl) == 0 && raw &&
          rl == (size_t)wl && memcmp(raw, want, rl) == 0, msg);
    free(raw);

    /* K3: our signing hash against the vector's signature */
    uint8_t sh[32], rec[20];
    snprintf(msg, sizeof(msg), "K3 %s: the vector's signature over OUR signing hash recovers the vector's sender", name);
    CHECK(amm_tx1559_signing_hash(&tx, sh) == 0 &&
          ecrecover_addr(sh, 0, r, s, rec) == 0 && memcmp(rec, sender, 20) == 0, msg);
    uint8_t sh2[32];
    tx.nonce = 1;
    CHECK(amm_tx1559_signing_hash(&tx, sh2) == 0 && memcmp(sh, sh2, 32) != 0,
          "K3 a changed nonce changes the signing hash");
    tx.nonce = 0;

    amm_signer_free(sg);
    return 0;
}

/* ── K6 / K7: the payout shape ─────────────────────────────────────── */

static int dec_item(const uint8_t *p, size_t n, evm_trie_rlp_item *it, size_t *used) {
    if (evm_trie_rlp_decode_item(p, n, it) != 0) return -1;
    *used = it->total;
    return 0;
}

static void k6_k7(void) {
    uint8_t key[32], user[20], usdt[20], addr[20];
    unhex(KEY_HEX, key, 32);
    unhex("1111111111111111111111111111111111111111", user, 20);
    /* the USDT contract: plan section 5 / section 10 */
    unhex("dac17f958d2ee523a2206206994597c13d831ec7", usdt, 20);

    uint8_t cd[AMM_TX_TRANSFER_DATA_LEN];
    amm_tx_transfer_calldata(user, 0x0123456789abcdefULL, cd);
    uint8_t want[68];
    memset(want, 0, sizeof(want));
    want[0] = 0xa9; want[1] = 0x05; want[2] = 0x9c; want[3] = 0xbb;
    memset(want + 4 + 12, 0x11, 20);
    want[36 + 24] = 0x01; want[36 + 25] = 0x23; want[36 + 26] = 0x45; want[36 + 27] = 0x67;
    want[36 + 28] = 0x89; want[36 + 29] = 0xab; want[36 + 30] = 0xcd; want[36 + 31] = 0xef;
    CHECK(memcmp(cd, want, 68) == 0, "K6 transfer call data: selector, padded recipient, 32-byte amount word");

    uint8_t sel[4];
    CHECK(nodus_evm_abi_selector("transfer(address,uint256)", sel) == 0 &&
          memcmp(sel, cd, 4) == 0 && sel[0] == 0xa9 && sel[3] == 0xbb,
          "K6 the selector is keccak256(\"transfer(address,uint256)\")[0..4] = a9059cbb (pinned: THORChain direct_erc20_transfer.go:20)");

    amm_tx1559_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.chain_id = 1;
    tx.nonce = 7;
    tx.max_priority_fee_per_gas = 2000000000ULL;
    tx.max_fee_per_gas = 30000000000ULL;
    tx.gas = 65000;
    tx.has_to = 1;
    memcpy(tx.to, usdt, 20);
    tx.data = cd;
    tx.data_len = sizeof(cd);

    amm_signer_t *sg = amm_signer_new(key, NULL);
    uint8_t *raw = NULL;
    size_t rl = 0;
    CHECK(sg && amm_tx1559_sign(sg, &tx, &raw, &rl, NULL) == 0 && raw && rl > 0,
          "K7 the payout transaction signs");
    if (!sg || !raw) { amm_signer_free(sg); free(raw); return; }
    amm_signer_address(sg, addr);
    CHECK(raw[0] == 0x02, "K7 the typed encoding starts with the type byte 0x02");

    evm_trie_rlp_item top, it;
    size_t used;
    CHECK(evm_trie_rlp_decode_item(raw + 1, rl - 1, &top) == 0 && top.is_list &&
          top.total == rl - 1, "K7 one RLP list behind the type byte, nothing after it");
    const uint8_t *p = top.payload;
    size_t left = top.len;
    uint8_t f[12][80];
    size_t fl[12];
    int ok = 1;
    for (int i = 0; i < 12 && ok; i++) {
        if (left == 0 || dec_item(p, left, &it, &used) != 0 || (i != 8 && it.is_list) ||
            (i == 8 && !it.is_list)) { ok = 0; break; }
        fl[i] = it.len;
        if (it.len <= sizeof(f[i])) memcpy(f[i], it.payload, it.len);
        p += used;
        left -= used;
    }
    CHECK(ok && left == 0, "K7 twelve fields: nine signing fields, y_parity, r, s");
    if (ok) {
        CHECK(fl[0] == 1 && f[0][0] == 1, "K7 chain id 1");
        CHECK(fl[1] == 1 && f[1][0] == 7, "K7 nonce 7");
        CHECK(fl[2] == 4 && f[2][0] == 0x77 && f[2][1] == 0x35 && f[2][2] == 0x94 && f[2][3] == 0x00,
              "K7 max priority fee 2,000,000,000 as minimal big-endian bytes");
        CHECK(fl[3] == 5 && f[3][0] == 0x06 && f[3][1] == 0xfc && f[3][2] == 0x23 && f[3][3] == 0xac && f[3][4] == 0x00,
              "K7 max fee 30,000,000,000 = 0x06fc23ac00 as minimal big-endian bytes");
        CHECK(fl[4] == 2 && f[4][0] == 0xfd && f[4][1] == 0xe8,
              "K7 gas 65000 = 0xfde8");
        CHECK(fl[5] == 20 && memcmp(f[5], usdt, 20) == 0, "K7 to = the USDT contract");
        CHECK(fl[6] == 0, "K7 value 0 = the empty string");
        CHECK(fl[7] == 68 && memcmp(f[7], cd, 68) == 0, "K7 data = the transfer call data");
        CHECK(fl[8] == 0, "K7 an empty access list");
        CHECK(fl[9] == 0 || (fl[9] == 1 && f[9][0] == 1), "K7 y_parity is 0 (empty) or 1");
        CHECK(fl[10] <= 32 && fl[11] <= 32 && fl[10] >= 1 && fl[11] >= 1, "K7 r and s are minimal big-endian integers");
    }
    /* K4: recover our own signature */
    if (ok && fl[10] <= 32 && fl[11] <= 32) {
        uint8_t r[32] = {0}, s[32] = {0}, sh[32], rec[20];
        memcpy(r + 32 - fl[10], f[10], fl[10]);
        memcpy(s + 32 - fl[11], f[11], fl[11]);
        int parity = (int)(fl[9] == 1 ? f[9][0] : 0);
        CHECK(amm_tx1559_signing_hash(&tx, sh) == 0 &&
              ecrecover_addr(sh, parity, r, s, rec) == 0 && memcmp(rec, addr, 20) == 0,
              "K4 our own signature recovers (ecrecover port) to the key's address");
    }
    free(raw);
    amm_signer_free(sg);
}

/* ── K8: refusals ──────────────────────────────────────────────────── */

static void k8(void) {
    uint8_t zero[32] = {0};
    /* the order n of secp256k1 (an invalid secret key): FFFFFFFF...BAAEDCE6AF48A03BBFD25E8CD0364141 */
    uint8_t order[32];
    unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", order, 32);
    CHECK(amm_signer_new(zero, NULL) == NULL, "K8 the zero secret key is refused");
    CHECK(amm_signer_new(order, NULL) == NULL, "K8 a secret key equal to the curve order is refused");
    CHECK(amm_signer_new(NULL, NULL) == NULL, "K8 no key");

    uint8_t key[32], blind[32];
    unhex(KEY_HEX, key, 32);
    memset(blind, 0x5a, sizeof(blind));
    amm_signer_t *sg = amm_signer_new(key, blind);
    CHECK(sg != NULL, "K8 a caller-supplied blinding seed is accepted");

    amm_tx1559_t tx;
    vector_tx(&tx, 1);
    uint8_t *raw = NULL;
    size_t rl = 0;
    uint8_t r[32], s[32];
    unhex(R1_HEX, r, 32);
    unhex(S1_HEX, s, 32);
    CHECK(amm_tx1559_encode(&tx, 2, r, s, &raw, &rl) == -1 && raw == NULL, "K8 y_parity 2 is refused");
    tx.n_access = AMM_TX_ACCESS_MAX_ENTRIES + 1;
    CHECK(amm_tx1559_encode(&tx, 0, r, s, &raw, &rl) == -1 && raw == NULL, "K8 too many access entries");
    tx.n_access = 1;
    g_acc.n_keys = AMM_TX_ACCESS_MAX_KEYS + 1;
    CHECK(amm_tx1559_encode(&tx, 0, r, s, &raw, &rl) == -1 && raw == NULL, "K8 too many storage keys");
    g_acc.n_keys = 2;
    tx.data_len = AMM_TX_DATA_MAX + 1;
    static const uint8_t big[1];
    tx.data = big;
    CHECK(amm_tx1559_encode(&tx, 0, r, s, &raw, &rl) == -1 && raw == NULL, "K8 call data above the bound");
    tx.data = NULL;
    tx.data_len = 4;
    CHECK(amm_tx1559_encode(&tx, 0, r, s, &raw, &rl) == -1 && raw == NULL, "K8 a length with no data pointer");
    tx.data_len = 0;
    uint8_t h[32];
    CHECK(amm_tx1559_signing_hash(&tx, h) == 0, "K8 the repaired transaction hashes again");
    CHECK(amm_tx1559_sign(sg, &tx, &raw, &rl, NULL) == 0 && raw != NULL, "K8 a blinded signer still signs the same shape");
    free(raw);
    amm_signer_free(sg);
}

int main(void) {
    printf("test_amm_eth_tx\n");
    check_vector(1, RAW1_HEX, R1_HEX, S1_HEX, "type 2, to = 0x..aa");
    check_vector(0, RAW2_HEX, R2_HEX, S2_HEX, "type 2, to = none (Bytes0)");
    k6_k7();
    k8();
    printf("%d checks, %d failed\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
