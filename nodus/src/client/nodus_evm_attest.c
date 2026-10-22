/**
 * @file nodus/src/client/nodus_evm_attest.c
 * @brief The attested message and its signature (see nodus_evm_attest.h).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "client/nodus_evm_attest.h"
#include "client/nodus_evm_abi.h"

#include "crypto/hash/keccak256.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ATTEST_TAG_TEXT "nodus.evm.attest.message.v1"
#define ATTEST_HEADER_WORDS 7

static void set_err(char *err, size_t cap, const char *msg) {
    if (err && cap) snprintf(err, cap, "%s", msg);
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i]     = hx[b[i] >> 4];
        out[2 * i + 1] = hx[b[i] & 0x0F];
    }
    out[2 * n] = '\0';
}

int nodus_evm_attest_tag(uint8_t tag[32]) {
    return keccak256((const uint8_t *)ATTEST_TAG_TEXT,
                     strlen(ATTEST_TAG_TEXT), tag);
}

void nodus_evm_attest_msg_free(nodus_evm_attest_msg_t *m) {
    if (!m) return;
    free(m->message);
    memset(m, 0, sizeof(*m));
}

int nodus_evm_attest_build(const char *action,
                           const uint8_t chain32[32],
                           const uint8_t contract32[32],
                           const char *nonce_dec, const char *expiry_dec,
                           const uint8_t signer32[32],
                           char **vals, int n_vals,
                           nodus_evm_attest_msg_t *out,
                           char *err, size_t errcap) {
    if (err && errcap) err[0] = '\0';
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!action || !chain32 || !contract32 || !nonce_dec || !expiry_dec ||
        !signer32 || n_vals < 0 || (n_vals > 0 && !vals)) {
        set_err(err, errcap, "attest: a missing argument");
        return -1;
    }

    nodus_evm_abi_sig_t g;
    if (nodus_evm_abi_sig(action, &g, err, errcap) != 0) {
        if (!err || !errcap || !err[0])
            set_err(err, errcap, "attest: the action is not a valid "
                    "Name(t1,...,tn)");
        return -1;
    }
    if (g.is_ctor) {
        set_err(err, errcap, "attest: the action name is empty (it must be "
                "a Solidity identifier)");
        return -1;
    }
    if (g.has_out) {
        set_err(err, errcap, "attest: an action has no return list");
        return -1;
    }
    /* refused BEFORE the 7 + n tuple is filled */
    if (g.n_in > NODUS_EVM_ATTEST_MAX_PARAMS) {
        set_err(err, errcap, "attest: an action has at most 9 parameters");
        return -1;
    }
    if (n_vals != g.n_in) {
        set_err(err, errcap, "attest: the number of values differs from the "
                "action's parameter count");
        return -1;
    }

    /* nonce uint256; expiry must fit uint64 (the encoder's uint64 range
     * check is the same test; it is made here so the refusal names it) */
    uint8_t w[32];
    if (nodus_evm_u256_dec(nonce_dec, w) != 0) {
        set_err(err, errcap, "attest: the nonce is a decimal uint256");
        return -1;
    }
    if (nodus_evm_u256_dec(expiry_dec, w) != 0) {
        set_err(err, errcap, "attest: the expiry is a decimal number");
        return -1;
    }
    for (int i = 0; i < 24; i++) {
        if (w[i]) {
            set_err(err, errcap, "attest: the expiry does not fit uint64");
            return -1;
        }
    }

    uint8_t tag[32], at[32];
    if (nodus_evm_attest_tag(tag) != 0 ||
        keccak256((const uint8_t *)g.canon, strlen(g.canon), at) != 0) {
        set_err(err, errcap, "attest: keccak256 failed");
        return -1;
    }

    /* the 7 header words as the text the encoder takes, then the values */
    char tag_h[65], chain_dec[80], contract_h[65], at_h[65], signer_h[65];
    to_hex(tag, 32, tag_h);
    nodus_evm_u256_to_dec(chain32, chain_dec);
    to_hex(contract32, 32, contract_h);
    to_hex(at, 32, at_h);
    to_hex(signer32, 32, signer_h);

    nodus_evm_abi_type_t ts[NODUS_EVM_ABI_MAX_ARGS];
    char *tv[NODUS_EVM_ABI_MAX_ARGS];
    memset(ts, 0, sizeof(ts));
    ts[0].k = NODUS_EVM_ABI_FBYTES; ts[0].size = 32; tv[0] = tag_h;
    ts[1].k = NODUS_EVM_ABI_UINT;   ts[1].bits = 256; tv[1] = chain_dec;
    ts[2].k = NODUS_EVM_ABI_ADDR;   tv[2] = contract_h;
    ts[3].k = NODUS_EVM_ABI_FBYTES; ts[3].size = 32; tv[3] = at_h;
    ts[4].k = NODUS_EVM_ABI_UINT;   ts[4].bits = 256;
    tv[4] = (char *)(uintptr_t)nonce_dec;
    ts[5].k = NODUS_EVM_ABI_UINT;   ts[5].bits = 64;
    tv[5] = (char *)(uintptr_t)expiry_dec;
    ts[6].k = NODUS_EVM_ABI_ADDR;   tv[6] = signer_h;
    for (int i = 0; i < g.n_in; i++) {
        ts[ATTEST_HEADER_WORDS + i] = g.in[i];
        tv[ATTEST_HEADER_WORDS + i] = vals[i];
    }

    uint8_t *msg = NULL;
    size_t msg_len = 0;
    if (nodus_evm_abi_encode(ts, ATTEST_HEADER_WORDS + g.n_in, tv, &msg,
                             &msg_len, err, errcap) != 0) {
        if (err && errcap && !err[0])
            set_err(err, errcap, "attest: the message could not be encoded");
        return -1;
    }
    if (msg_len > NODUS_EVM_ATTEST_MSG_MAX) {
        free(msg);
        set_err(err, errcap, "attest: the message is over 65536 bytes (the "
                "precompile's bound)");
        return -1;
    }
    memcpy(out->canon, g.canon, sizeof(out->canon));
    memcpy(out->action_type, at, 32);
    out->message = msg;
    out->message_len = msg_len;
    return 0;
}

int nodus_evm_attest_sign(const uint8_t *msg, size_t msg_len,
                          const uint8_t *sk, const uint8_t *pk,
                          uint8_t sig[NODUS_EVM_ATTEST_SIG_LEN]) {
    if (!sig) return -1;
    memset(sig, 0, NODUS_EVM_ATTEST_SIG_LEN);
    if (!msg || !sk || !pk || msg_len > NODUS_EVM_ATTEST_MSG_MAX) return -1;
    size_t sl = 0;
    if (qgp_dsa87_sign_ctx(sig, &sl, msg, msg_len,
                           (const uint8_t *)NODUS_EVM_ATTEST_CTX,
                           NODUS_EVM_ATTEST_CTX_LEN, sk) != 0 ||
        sl != NODUS_EVM_ATTEST_SIG_LEN ||
        qgp_dsa87_verify_ctx(sig, sl, msg, msg_len,
                             (const uint8_t *)NODUS_EVM_ATTEST_CTX,
                             NODUS_EVM_ATTEST_CTX_LEN, pk) != 0) {
        memset(sig, 0, NODUS_EVM_ATTEST_SIG_LEN);
        return -1;
    }
    return 0;
}
