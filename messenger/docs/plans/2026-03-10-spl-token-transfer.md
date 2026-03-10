# SPL Token Transfer Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable sending SPL tokens (USDT, USDC, any mint) on Solana with automatic ATA creation, plus show SPL transfers in tx history and add USDC balance to all chains.

**Architecture:** SPL transfer builds a Solana transaction with Token Program instructions. If recipient has no Associated Token Account (ATA), the TX includes a CreateATA instruction (sender pays rent). The existing `blockchain_send_tokens_with_seed()` Solana case routes non-native tokens to the new `sol_spl_send()`.

**Tech Stack:** C, Solana JSON-RPC, Ed25519 signing (existing `sol_sign_message`), Token Program, Associated Token Program

**Design doc:** `messenger/docs/plans/2026-03-10-spl-token-transfer-design.md`

---

### Task 1: Add ATA derivation and transfer declarations to sol_spl.h

**Files:**
- Modify: `messenger/blockchain/solana/sol_spl.h`

**Step 1: Add new constants and function declarations**

After the existing `SOL_TOKEN_PROGRAM_ID` define (~line 36), add:

```c
/* Associated Token Program ID */
#define SOL_ASSOCIATED_TOKEN_PROGRAM_ID "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

/* Token account data size (for rent calculation) */
#define SOL_TOKEN_ACCOUNT_DATA_SIZE 165
```

After the existing `sol_spl_get_balance_by_symbol` declaration (~line 112), add:

```c
/* ============================================================================
 * ATA (ASSOCIATED TOKEN ACCOUNT) FUNCTIONS
 * ============================================================================ */

/**
 * Derive Associated Token Account (ATA) address
 *
 * Computes the PDA: SHA256("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
 *                          + owner + TOKEN_PROGRAM_ID + mint)
 * then finds off-curve point.
 *
 * @param owner_pubkey    Owner public key (32 bytes)
 * @param mint_pubkey     Token mint public key (32 bytes)
 * @param ata_pubkey_out  Output: ATA public key (32 bytes)
 * @return                0 on success, -1 on error
 */
int sol_spl_derive_ata(
    const uint8_t owner_pubkey[32],
    const uint8_t mint_pubkey[32],
    uint8_t ata_pubkey_out[32]
);

/**
 * Check if an ATA exists on-chain
 *
 * @param ata_address     ATA address (base58)
 * @param exists_out      Output: true if account exists with data
 * @return                0 on success, -1 on RPC error
 */
int sol_spl_check_ata(
    const char *ata_address,
    bool *exists_out
);

/* ============================================================================
 * TRANSFER FUNCTIONS
 * ============================================================================ */

/**
 * Send SPL tokens to an address
 *
 * High-level function that:
 * 1. Derives sender and recipient ATAs
 * 2. Checks if recipient ATA exists
 * 3. If not, includes CreateAssociatedTokenAccount instruction
 * 4. Builds, signs, and sends the transaction
 *
 * @param wallet          Source wallet (signer)
 * @param to_address      Recipient wallet address (base58, NOT ATA)
 * @param mint_address    Token mint address (base58)
 * @param amount          Amount as decimal string (e.g., "10.5")
 * @param decimals        Token decimals
 * @param signature_out   Output: transaction signature (base58)
 * @param sig_out_size    Size of signature output buffer
 * @return                0 success, -1 error, -2 insufficient token balance,
 *                        -3 insufficient SOL for rent/fees, -4 invalid mint
 */
int sol_spl_send(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *mint_address,
    const char *amount,
    uint8_t decimals,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Send SPL tokens by symbol (convenience wrapper)
 *
 * Looks up mint address and decimals from known token registry.
 * Falls back to mint_address parameter if symbol not in registry.
 *
 * @param wallet          Source wallet
 * @param to_address      Recipient address (base58)
 * @param symbol          Token symbol (e.g., "USDT") or mint address
 * @param amount          Amount as decimal string
 * @param signature_out   Output: transaction signature
 * @param sig_out_size    Size of signature output buffer
 * @return                0 success, -1 error, -2 insufficient balance,
 *                        -3 insufficient SOL, -4 unknown token
 */
int sol_spl_send_by_symbol(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *symbol,
    const char *amount,
    char *signature_out,
    size_t sig_out_size
);

/**
 * Estimate fee for SPL token transfer
 *
 * Checks if recipient ATA exists. Returns exact fee including
 * ATA creation rent if needed.
 *
 * @param owner_address   Sender address (base58)
 * @param to_address      Recipient address (base58)
 * @param mint_address    Token mint address (base58)
 * @param fee_lamports_out  Output: total fee in lamports
 * @param ata_exists_out    Output: whether recipient ATA exists
 * @return                  0 on success, -1 on error
 */
int sol_spl_estimate_fee(
    const char *owner_address,
    const char *to_address,
    const char *mint_address,
    uint64_t *fee_lamports_out,
    bool *ata_exists_out
);
```

**Step 2: Build to verify header compiles**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: compiles (declarations only, no missing implementations yet because nothing calls them)

**Step 3: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/blockchain/solana/sol_spl.h && \
git commit -m "feat(sol): add SPL token transfer declarations to sol_spl.h"
```

---

### Task 2: Implement ATA derivation (PDA computation)

**Files:**
- Modify: `messenger/blockchain/solana/sol_spl.c`

**Context:** Solana ATA is a Program Derived Address (PDA). The derivation is:
```
seeds = [owner_pubkey, TOKEN_PROGRAM_ID, mint_pubkey]
PDA = findProgramAddress(seeds, ASSOCIATED_TOKEN_PROGRAM_ID)
```
`findProgramAddress` tries bump seeds 255 down to 0, computing `SHA256(seeds + bump + program_id)` until the result is NOT on the Ed25519 curve.

**Step 1: Add ATA derivation implementation**

Add after `sol_spl_get_balance_by_symbol` function (end of file), before the closing:

```c
/* ============================================================================
 * ATA DERIVATION
 * ============================================================================ */

/**
 * Check if a 32-byte value is on the Ed25519 curve.
 * We use the existing Ed25519 implementation — if the point can be decoded,
 * it's on the curve.
 */
static bool is_on_curve(const uint8_t point[32]) {
    /*
     * Ed25519 check: try to decompress the y-coordinate.
     * A valid Ed25519 point has x^2 = (y^2 - 1) / (d*y^2 + 1) mod p
     * where p = 2^255 - 19.
     *
     * We use OpenSSL's EVP interface to attempt point decode.
     * If it fails, the point is off-curve (which is what we want for PDA).
     */
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, point, 32);
    if (pkey) {
        EVP_PKEY_free(pkey);
        return true;  /* On curve */
    }
    return false;  /* Off curve — valid PDA */
}

int sol_spl_derive_ata(
    const uint8_t owner_pubkey[32],
    const uint8_t mint_pubkey[32],
    uint8_t ata_pubkey_out[32]
) {
    if (!owner_pubkey || !mint_pubkey || !ata_pubkey_out) {
        return -1;
    }

    /* Decode program IDs from base58 */
    uint8_t token_program[32];
    uint8_t assoc_program[32];

    if (sol_address_to_pubkey(SOL_TOKEN_PROGRAM_ID, token_program) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode Token Program ID");
        return -1;
    }
    if (sol_address_to_pubkey(SOL_ASSOCIATED_TOKEN_PROGRAM_ID, assoc_program) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode Associated Token Program ID");
        return -1;
    }

    /*
     * findProgramAddress: try bump = 255 down to 0
     * hash = SHA256(owner + token_program + mint + [bump] + assoc_program + "ProgramDerivedAddress")
     */
    for (int bump = 255; bump >= 0; bump--) {
        uint8_t hash[32];
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) return -1;

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(ctx, owner_pubkey, 32) != 1 ||
            EVP_DigestUpdate(ctx, token_program, 32) != 1 ||
            EVP_DigestUpdate(ctx, mint_pubkey, 32) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }

        uint8_t bump_byte = (uint8_t)bump;
        if (EVP_DigestUpdate(ctx, &bump_byte, 1) != 1 ||
            EVP_DigestUpdate(ctx, assoc_program, 32) != 1 ||
            EVP_DigestUpdate(ctx, "ProgramDerivedAddress", 21) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }

        unsigned int hash_len = 32;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return -1;
        }
        EVP_MD_CTX_free(ctx);

        /* PDA must be OFF the Ed25519 curve */
        if (!is_on_curve(hash)) {
            memcpy(ata_pubkey_out, hash, 32);
            return 0;
        }
    }

    QGP_LOG_ERROR(LOG_TAG, "Failed to find valid PDA (all bumps on curve)");
    return -1;
}
```

Add required includes at the top of sol_spl.c (after existing includes):

```c
#include <openssl/evp.h>
#include "crypto/utils/base58.h"
```

**Step 2: Implement ATA existence check via RPC**

```c
int sol_spl_check_ata(
    const char *ata_address,
    bool *exists_out
) {
    if (!ata_address || !exists_out) return -1;
    *exists_out = false;

    const char *endpoint = sol_rpc_get_endpoint();
    if (!endpoint || endpoint[0] == '\0') return -1;

    sol_rpc_rate_limit_delay();

    /* Build getAccountInfo request */
    json_object *req = json_object_new_object();
    json_object_object_add(req, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(req, "id", json_object_new_int(1));
    json_object_object_add(req, "method", json_object_new_string("getAccountInfo"));

    json_object *params = json_object_new_array();
    json_object_array_add(params, json_object_new_string(ata_address));

    json_object *opts = json_object_new_object();
    json_object_object_add(opts, "encoding", json_object_new_string("jsonParsed"));
    json_object_array_add(params, opts);

    json_object_object_add(req, "params", params);

    const char *json_str = json_object_to_json_string(req);

    CURL *curl = curl_easy_init();
    if (!curl) {
        json_object_put(req);
        return -1;
    }

    struct response_buffer resp_buf = {0};
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp_buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);

    const char *ca_bundle = qgp_platform_ca_bundle_path();
    if (ca_bundle) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_object_put(req);

    if (res != CURLE_OK || !resp_buf.data) {
        free(resp_buf.data);
        return -1;
    }

    json_object *resp = json_tokener_parse(resp_buf.data);
    free(resp_buf.data);
    if (!resp) return -1;

    /* Check result.value — null means account doesn't exist */
    json_object *result_obj;
    if (json_object_object_get_ex(resp, "result", &result_obj)) {
        json_object *value_obj;
        if (json_object_object_get_ex(result_obj, "value", &value_obj)) {
            *exists_out = !json_object_is_type(value_obj, json_type_null);
        }
    }

    json_object_put(resp);
    return 0;
}
```

**Step 3: Build to verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: Compiles cleanly. Functions are implemented but not yet called from anywhere.

**Step 4: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/blockchain/solana/sol_spl.c && \
git commit -m "feat(sol): implement ATA derivation (PDA) and existence check"
```

---

### Task 3: Implement SPL token transfer TX building and sending

**Files:**
- Modify: `messenger/blockchain/solana/sol_spl.c`

**Context:** This is the core transfer logic. It builds a Solana transaction with:
- Optionally: `CreateAssociatedTokenAccount` instruction (if recipient ATA missing)
- `Token Program Transfer` instruction (instruction index 3, 8-byte LE amount)

The transaction uses the same signing mechanism as `sol_tx_build_transfer` (Ed25519 via `sol_sign_message`).

**Step 1: Add amount parsing helper**

```c
/* ============================================================================
 * TRANSFER IMPLEMENTATION
 * ============================================================================ */

/**
 * Parse decimal amount string to raw token units (no floating-point).
 * E.g., "10.5" with 6 decimals -> 10500000
 */
static int spl_parse_amount(const char *amount_str, uint8_t decimals, uint64_t *raw_out) {
    if (!amount_str || !raw_out) return -1;

    const char *p = amount_str;
    while (*p == ' ') p++;
    if (*p == '\0') return -1;

    const char *dot = strchr(p, '.');

    /* Parse whole part */
    uint64_t whole = 0;
    const char *end = dot ? dot : p + strlen(p);
    for (const char *c = p; c < end; c++) {
        if (*c < '0' || *c > '9') return -1;
        uint64_t prev = whole;
        whole = whole * 10 + (*c - '0');
        if (whole < prev) return -1;  /* overflow */
    }

    /* Parse fractional part */
    uint64_t frac = 0;
    if (dot) {
        const char *frac_start = dot + 1;
        int frac_digits = 0;
        for (const char *c = frac_start; *c && frac_digits < decimals; c++) {
            if (*c < '0' || *c > '9') return -1;
            frac = frac * 10 + (*c - '0');
            frac_digits++;
        }
        for (int i = frac_digits; i < decimals; i++) {
            frac *= 10;
        }
    }

    /* Compute multiplier */
    uint64_t multiplier = 1;
    for (int i = 0; i < decimals; i++) multiplier *= 10;

    if (whole > UINT64_MAX / multiplier) return -1;
    *raw_out = whole * multiplier + frac;
    return 0;
}
```

**Step 2: Implement the transfer TX builder and sender**

This is a large function. Key implementation details:
- Uses `encode_compact_u16` from sol_tx.c (declare as extern or duplicate static helper)
- Builds message with proper account key ordering
- Signs with `sol_sign_message`
- Sends via `sol_rpc_send_transaction`

```c
/* Compact-u16 encoder (same as sol_tx.c) */
static size_t spl_encode_compact_u16(uint16_t value, uint8_t *out) {
    if (value < 0x80) {
        out[0] = (uint8_t)value;
        return 1;
    } else if (value < 0x4000) {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(value >> 7);
        return 2;
    } else {
        out[0] = (uint8_t)((value & 0x7f) | 0x80);
        out[1] = (uint8_t)(((value >> 7) & 0x7f) | 0x80);
        out[2] = (uint8_t)(value >> 14);
        return 3;
    }
}

int sol_spl_send(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *mint_address,
    const char *amount,
    uint8_t decimals,
    char *signature_out,
    size_t sig_out_size
) {
    if (!wallet || !to_address || !mint_address || !amount ||
        !signature_out || sig_out_size == 0) {
        return -1;
    }

    /* Parse amount to raw token units */
    uint64_t raw_amount;
    if (spl_parse_amount(amount, decimals, &raw_amount) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid SPL amount: %s (decimals=%d)", amount, decimals);
        return -1;
    }

    if (raw_amount == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot send 0 tokens");
        return -1;
    }

    /* Decode addresses to pubkeys */
    uint8_t to_pubkey[32], mint_pubkey[32];
    if (sol_address_to_pubkey(to_address, to_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid recipient address: %s", to_address);
        return -1;
    }
    if (sol_address_to_pubkey(mint_address, mint_pubkey) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid mint address: %s", mint_address);
        return -4;
    }

    /* Derive sender ATA */
    uint8_t sender_ata[32];
    if (sol_spl_derive_ata(wallet->public_key, mint_pubkey, sender_ata) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive sender ATA");
        return -1;
    }

    /* Derive recipient ATA */
    uint8_t recipient_ata[32];
    if (sol_spl_derive_ata(to_pubkey, mint_pubkey, recipient_ata) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to derive recipient ATA");
        return -1;
    }

    /* Check if recipient ATA exists */
    char recipient_ata_addr[48];
    sol_pubkey_to_address(recipient_ata, recipient_ata_addr);

    bool ata_exists = false;
    if (sol_spl_check_ata(recipient_ata_addr, &ata_exists) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Failed to check recipient ATA, assuming it doesn't exist");
    }

    QGP_LOG_INFO(LOG_TAG, "SPL send: %s tokens (raw=%llu) to %s, ATA exists=%d",
                 amount, (unsigned long long)raw_amount, to_address, ata_exists);

    /* Decode program IDs */
    uint8_t token_program[32];
    uint8_t assoc_program[32];
    uint8_t system_program[32] = {0};  /* All zeros */

    sol_address_to_pubkey(SOL_TOKEN_PROGRAM_ID, token_program);
    sol_address_to_pubkey(SOL_ASSOCIATED_TOKEN_PROGRAM_ID, assoc_program);

    /* Get recent blockhash */
    uint8_t blockhash[32];
    if (sol_rpc_get_recent_blockhash(blockhash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get recent blockhash");
        return -1;
    }

    /* Build message */
    uint8_t message[1024];
    size_t msg_offset = 0;

    if (!ata_exists) {
        /*
         * Transaction with CreateATA + Transfer
         *
         * Account keys (8 unique):
         *   0: sender (signer, writable) — fee payer + token authority
         *   1: sender_ata (writable)
         *   2: recipient (readonly)
         *   3: recipient_ata (writable)
         *   4: mint (readonly)
         *   5: system_program (readonly)
         *   6: token_program (readonly)
         *   7: assoc_token_program (readonly)
         *
         * Header: 1 signer, 0 readonly-signed, 4 readonly-unsigned
         *
         * Instruction 1: CreateAssociatedTokenAccount
         *   program_id_index: 7 (assoc_token_program)
         *   accounts: [0, 3, 2, 4, 5, 6]
         *   data: [] (empty)
         *
         * Instruction 2: Token Transfer
         *   program_id_index: 6 (token_program)
         *   accounts: [1, 3, 0]
         *   data: [3 (u8 instruction), amount (u64 LE)]
         */

        /* Header */
        message[msg_offset++] = 1;  /* num_required_signatures */
        message[msg_offset++] = 0;  /* num_readonly_signed */
        message[msg_offset++] = 4;  /* num_readonly_unsigned: recipient, mint, sys, token, assoc */

        /* Account keys: 8 accounts */
        msg_offset += spl_encode_compact_u16(8, message + msg_offset);

        memcpy(message + msg_offset, wallet->public_key, 32); msg_offset += 32;  /* 0: sender */
        memcpy(message + msg_offset, sender_ata, 32); msg_offset += 32;          /* 1: sender_ata */
        memcpy(message + msg_offset, recipient_ata, 32); msg_offset += 32;       /* 2: recipient_ata */
        memcpy(message + msg_offset, to_pubkey, 32); msg_offset += 32;           /* 3: recipient */
        memcpy(message + msg_offset, mint_pubkey, 32); msg_offset += 32;         /* 4: mint */
        memcpy(message + msg_offset, system_program, 32); msg_offset += 32;      /* 5: system_program */
        memcpy(message + msg_offset, token_program, 32); msg_offset += 32;       /* 6: token_program */
        memcpy(message + msg_offset, assoc_program, 32); msg_offset += 32;       /* 7: assoc_program */

        /* Blockhash */
        memcpy(message + msg_offset, blockhash, 32); msg_offset += 32;

        /* Instructions: 2 */
        msg_offset += spl_encode_compact_u16(2, message + msg_offset);

        /* Instruction 1: CreateAssociatedTokenAccount */
        message[msg_offset++] = 7;  /* program_id_index: assoc_program */
        /* Account indices: [0(payer), 2(recipient_ata), 3(recipient), 4(mint), 5(system), 6(token)] */
        msg_offset += spl_encode_compact_u16(6, message + msg_offset);
        message[msg_offset++] = 0;  /* payer (sender) */
        message[msg_offset++] = 2;  /* recipient_ata */
        message[msg_offset++] = 3;  /* recipient (wallet owner) */
        message[msg_offset++] = 4;  /* mint */
        message[msg_offset++] = 5;  /* system_program */
        message[msg_offset++] = 6;  /* token_program */
        /* Data: empty */
        msg_offset += spl_encode_compact_u16(0, message + msg_offset);

        /* Instruction 2: Token Transfer */
        message[msg_offset++] = 6;  /* program_id_index: token_program */
        /* Account indices: [1(sender_ata), 2(recipient_ata), 0(authority)] */
        msg_offset += spl_encode_compact_u16(3, message + msg_offset);
        message[msg_offset++] = 1;  /* source (sender_ata) */
        message[msg_offset++] = 2;  /* destination (recipient_ata) */
        message[msg_offset++] = 0;  /* authority (sender) */
        /* Data: 1 byte instruction (3=Transfer) + 8 bytes LE amount */
        msg_offset += spl_encode_compact_u16(9, message + msg_offset);
        message[msg_offset++] = 3;  /* Transfer instruction */
        for (int i = 0; i < 8; i++) {
            message[msg_offset++] = (raw_amount >> (i * 8)) & 0xFF;
        }
    } else {
        /*
         * Transaction with Transfer only
         *
         * Account keys (4 unique):
         *   0: sender (signer, writable) — token authority
         *   1: sender_ata (writable)
         *   2: recipient_ata (writable)
         *   3: token_program (readonly)
         *
         * Header: 1 signer, 0 readonly-signed, 1 readonly-unsigned
         */

        /* Header */
        message[msg_offset++] = 1;  /* num_required_signatures */
        message[msg_offset++] = 0;  /* num_readonly_signed */
        message[msg_offset++] = 1;  /* num_readonly_unsigned: token_program */

        /* Account keys: 4 accounts */
        msg_offset += spl_encode_compact_u16(4, message + msg_offset);

        memcpy(message + msg_offset, wallet->public_key, 32); msg_offset += 32;  /* 0: sender */
        memcpy(message + msg_offset, sender_ata, 32); msg_offset += 32;          /* 1: sender_ata */
        memcpy(message + msg_offset, recipient_ata, 32); msg_offset += 32;       /* 2: recipient_ata */
        memcpy(message + msg_offset, token_program, 32); msg_offset += 32;       /* 3: token_program */

        /* Blockhash */
        memcpy(message + msg_offset, blockhash, 32); msg_offset += 32;

        /* Instructions: 1 */
        msg_offset += spl_encode_compact_u16(1, message + msg_offset);

        /* Instruction: Token Transfer */
        message[msg_offset++] = 3;  /* program_id_index: token_program */
        /* Account indices: [1(sender_ata), 2(recipient_ata), 0(authority)] */
        msg_offset += spl_encode_compact_u16(3, message + msg_offset);
        message[msg_offset++] = 1;  /* source */
        message[msg_offset++] = 2;  /* destination */
        message[msg_offset++] = 0;  /* authority */
        /* Data: 1 byte instruction (3=Transfer) + 8 bytes LE amount */
        msg_offset += spl_encode_compact_u16(9, message + msg_offset);
        message[msg_offset++] = 3;  /* Transfer instruction */
        for (int i = 0; i < 8; i++) {
            message[msg_offset++] = (raw_amount >> (i * 8)) & 0xFF;
        }
    }

    /* Sign the message */
    uint8_t signature[64];
    if (sol_sign_message(message, msg_offset,
                         wallet->private_key, wallet->public_key,
                         signature) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign SPL transfer transaction");
        return -1;
    }

    /* Build final transaction: signature count + signature + message */
    uint8_t tx_data[SOL_TX_MAX_SIZE];
    size_t tx_offset = 0;

    tx_offset += spl_encode_compact_u16(1, tx_data + tx_offset);
    memcpy(tx_data + tx_offset, signature, 64);
    tx_offset += 64;
    memcpy(tx_data + tx_offset, message, msg_offset);
    tx_offset += msg_offset;

    /* Encode as base64 */
    char tx_base64[2048];
    sol_base64_encode(tx_data, tx_offset, tx_base64);

    /* Send transaction */
    if (sol_rpc_send_transaction(tx_base64, signature_out, sig_out_size) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to send SPL transfer transaction");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "SPL transfer sent: %s", signature_out);
    return 0;
}

int sol_spl_send_by_symbol(
    const sol_wallet_t *wallet,
    const char *to_address,
    const char *symbol,
    const char *amount,
    char *signature_out,
    size_t sig_out_size
) {
    if (!wallet || !to_address || !symbol || !amount) return -1;

    /* Try known token registry first */
    sol_spl_token_t token;
    if (sol_spl_get_token(symbol, &token) == 0) {
        return sol_spl_send(wallet, to_address, token.mint, amount,
                           token.decimals, signature_out, sig_out_size);
    }

    /* If symbol looks like a mint address (32+ chars), try as raw mint */
    if (strlen(symbol) >= 32) {
        QGP_LOG_INFO(LOG_TAG, "Token '%s' not in registry, treating as mint address (decimals=9)", symbol);
        return sol_spl_send(wallet, to_address, symbol, amount,
                           9, signature_out, sig_out_size);
    }

    QGP_LOG_ERROR(LOG_TAG, "Unknown token: %s", symbol);
    return -4;
}

int sol_spl_estimate_fee(
    const char *owner_address,
    const char *to_address,
    const char *mint_address,
    uint64_t *fee_lamports_out,
    bool *ata_exists_out
) {
    if (!owner_address || !to_address || !mint_address || !fee_lamports_out) return -1;

    /* Derive recipient ATA */
    uint8_t to_pubkey[32], mint_pubkey[32];
    if (sol_address_to_pubkey(to_address, to_pubkey) != 0) return -1;
    if (sol_address_to_pubkey(mint_address, mint_pubkey) != 0) return -1;

    uint8_t ata_pubkey[32];
    if (sol_spl_derive_ata(to_pubkey, mint_pubkey, ata_pubkey) != 0) return -1;

    char ata_addr[48];
    sol_pubkey_to_address(ata_pubkey, ata_addr);

    /* Check ATA existence */
    bool exists = false;
    sol_spl_check_ata(ata_addr, &exists);

    if (ata_exists_out) *ata_exists_out = exists;

    if (exists) {
        /* Just TX fee */
        *fee_lamports_out = 5000;
    } else {
        /* TX fee + ATA rent */
        uint64_t rent = 0;
        if (sol_rpc_get_minimum_balance_for_rent(SOL_TOKEN_ACCOUNT_DATA_SIZE, &rent) != 0) {
            rent = 2039280;  /* Default fallback */
        }
        *fee_lamports_out = 5000 + rent;
    }

    return 0;
}
```

**Step 2: Build to verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: Compiles cleanly. Note: `SOL_TX_MAX_SIZE` and `sol_base64_encode` are in `sol_tx.h` — add `#include "sol_tx.h"` if not already included.

**Step 3: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/blockchain/solana/sol_spl.c && \
git commit -m "feat(sol): implement SPL token transfer with automatic ATA creation"
```

---

### Task 4: Wire SPL send into sol_chain.c and blockchain_wallet.c

**Files:**
- Modify: `messenger/blockchain/solana/sol_chain.c`
- Modify: `messenger/blockchain/blockchain_wallet.c`

**Step 1: Update sol_chain.c — add SPL support to get_balance and send**

In `sol_chain.c`, add include at top:
```c
#include "sol_spl.h"
```

Modify `sol_chain_get_balance` (~line 92-118) — replace the "SPL tokens not yet supported" block:

```c
static int sol_chain_get_balance(
    const char *address,
    const char *token,
    char *balance_out,
    size_t balance_out_size
) {
    if (!address || !balance_out || balance_out_size == 0) {
        return -1;
    }

    if (is_native_sol(token)) {
        /* Native SOL balance */
        uint64_t lamports;
        if (sol_rpc_get_balance(address, &lamports) != 0) {
            return -1;
        }
        double sol = (double)lamports / SOL_LAMPORTS_PER_SOL;
        snprintf(balance_out, balance_out_size, "%.9f", sol);
        return 0;
    }

    /* SPL token balance */
    return sol_spl_get_balance_by_symbol(address, token, balance_out, balance_out_size);
}
```

Modify `sol_chain_send` (~line 145-199) — replace the "SPL tokens not yet supported" block:

```c
static int sol_chain_send(
    const char *from_address,
    const char *to_address,
    const char *amount,
    const char *token,
    const uint8_t *private_key,
    size_t private_key_len,
    blockchain_fee_speed_t fee_speed,
    char *txhash_out,
    size_t txhash_out_size
) {
    (void)fee_speed;

    if (!from_address || !to_address || !amount || !private_key ||
        private_key_len != SOL_PRIVATE_KEY_SIZE) {
        return -1;
    }

    /* Create wallet from private key */
    sol_wallet_t wallet;
    memset(&wallet, 0, sizeof(wallet));
    memcpy(wallet.private_key, private_key, SOL_PRIVATE_KEY_SIZE);
    if (sol_address_to_pubkey(from_address, wallet.public_key) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid from_address");
        return -1;
    }
    strncpy(wallet.address, from_address, SOL_ADDRESS_SIZE);

    int ret;
    if (is_native_sol(token)) {
        /* Native SOL transfer */
        uint64_t lamports;
        if (sol_parse_amount_to_lamports(amount, &lamports) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Invalid SOL amount: %s", amount);
            sol_wallet_clear(&wallet);
            return -1;
        }
        ret = sol_tx_send_lamports(&wallet, to_address, lamports,
                                    txhash_out, txhash_out_size);
    } else {
        /* SPL token transfer */
        ret = sol_spl_send_by_symbol(&wallet, to_address, token, amount,
                                      txhash_out, txhash_out_size);
    }

    sol_wallet_clear(&wallet);
    return ret;
}
```

Modify `sol_chain_get_transactions` (~line 228-297) — remove the "SPL token history not yet supported" early return. Accept token parameter and handle SPL transactions:

```c
static int sol_chain_get_transactions(
    const char *address,
    const char *token,
    blockchain_tx_t **txs_out,
    int *count_out
) {
    if (!address || !txs_out || !count_out) {
        return -1;
    }

    *txs_out = NULL;
    *count_out = 0;

    /* Fetch ALL transactions (RPC already parses SPL token transfers) */
    sol_transaction_t *sol_txs = NULL;
    int sol_count = 0;

    if (sol_rpc_get_transactions(address, &sol_txs, &sol_count) != 0) {
        return -1;
    }

    if (sol_count == 0 || !sol_txs) {
        return 0;
    }

    /* Convert to blockchain_tx_t, filtering by token if specified */
    blockchain_tx_t *txs = calloc(sol_count, sizeof(blockchain_tx_t));
    if (!txs) {
        sol_rpc_free_transactions(sol_txs, sol_count);
        return -1;
    }

    int out_count = 0;
    bool filter_spl = (token != NULL && strlen(token) > 0 && !is_native_sol(token));

    for (int i = 0; i < sol_count; i++) {
        /* Apply token filter */
        if (filter_spl) {
            /* Only include SPL token transfers matching the requested token */
            if (!sol_txs[i].is_token_transfer) continue;

            /* Check if mint matches the requested token */
            sol_spl_token_t tok_info;
            if (sol_spl_get_token(token, &tok_info) == 0) {
                if (strcmp(sol_txs[i].token_mint, tok_info.mint) != 0) continue;
            }
        } else if (token == NULL || strlen(token) == 0 || is_native_sol(token)) {
            /* No filter or native SOL — include all transactions */
        }

        strncpy(txs[out_count].tx_hash, sol_txs[i].signature, sizeof(txs[out_count].tx_hash) - 1);

        if (sol_txs[i].is_token_transfer) {
            /* SPL token — find symbol from mint */
            sol_spl_token_t tok_info;
            bool found_symbol = false;
            for (size_t t = 0; t < NUM_KNOWN_TOKENS; t++) {
                if (sol_spl_get_token(known_tokens[t].symbol, &tok_info) == 0 &&
                    strcmp(sol_txs[i].token_mint, tok_info.mint) == 0) {
                    strncpy(txs[out_count].token, tok_info.symbol, sizeof(txs[out_count].token) - 1);
                    /* Format amount with token decimals */
                    uint64_t divisor = 1;
                    for (int d = 0; d < tok_info.decimals; d++) divisor *= 10;
                    uint64_t whole = sol_txs[i].lamports / divisor;
                    uint64_t frac = sol_txs[i].lamports % divisor;
                    snprintf(txs[out_count].amount, sizeof(txs[out_count].amount),
                             "%llu.%0*llu", (unsigned long long)whole,
                             tok_info.decimals, (unsigned long long)frac);
                    found_symbol = true;
                    break;
                }
            }
            if (!found_symbol) {
                /* Unknown token — show mint address as token name, raw amount */
                strncpy(txs[out_count].token, sol_txs[i].token_mint, sizeof(txs[out_count].token) - 1);
                snprintf(txs[out_count].amount, sizeof(txs[out_count].amount),
                         "%llu", (unsigned long long)sol_txs[i].lamports);
            }
        } else {
            /* Native SOL */
            txs[out_count].token[0] = '\0';
            double sol = (double)sol_txs[i].lamports / SOL_LAMPORTS_PER_SOL;
            snprintf(txs[out_count].amount, sizeof(txs[out_count].amount), "%.9f", sol);
        }

        snprintf(txs[out_count].timestamp, sizeof(txs[out_count].timestamp),
                 "%lld", (long long)sol_txs[i].block_time);
        txs[out_count].is_outgoing = sol_txs[i].is_outgoing;

        if (sol_txs[i].is_outgoing) {
            strncpy(txs[out_count].other_address, sol_txs[i].to,
                    sizeof(txs[out_count].other_address) - 1);
        } else {
            strncpy(txs[out_count].other_address, sol_txs[i].from,
                    sizeof(txs[out_count].other_address) - 1);
        }

        strncpy(txs[out_count].status,
                sol_txs[i].success ? "CONFIRMED" : "FAILED",
                sizeof(txs[out_count].status) - 1);

        out_count++;
    }

    sol_rpc_free_transactions(sol_txs, sol_count);

    if (out_count == 0) {
        free(txs);
        *txs_out = NULL;
        *count_out = 0;
    } else {
        *txs_out = txs;
        *count_out = out_count;
    }
    return 0;
}
```

**NOTE:** The `sol_chain_get_transactions` function references `known_tokens` and `NUM_KNOWN_TOKENS` from sol_spl.c. Since those are static in sol_spl.c, use `sol_spl_get_token()` to look up symbols instead. The implementation above already does this. Remove the direct `known_tokens` reference loop and instead iterate over a small array of known symbols: `{"USDT", "USDC"}`.

**Step 2: Update blockchain_wallet.c Solana send case**

In `blockchain_wallet.c`, around line 418-439, modify the `BLOCKCHAIN_SOLANA` case in `blockchain_send_tokens_with_seed()`:

```c
        case BLOCKCHAIN_SOLANA: {
            chain_name = "Solana";

            /* Derive SOL wallet on-demand */
            sol_wallet_t sol_wallet;
            if (sol_wallet_generate(master_seed, 64, &sol_wallet) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive SOL wallet");
                return -1;
            }

            if (token != NULL && token[0] != '\0' && strcasecmp(token, "SOL") != 0) {
                /* SPL token transfer */
                ret = sol_spl_send_by_symbol(&sol_wallet, to_address, token, amount,
                                              tx_hash_out, 128);
            } else {
                /* Native SOL transfer */
                uint64_t lamports;
                if (sol_str_to_lamports(amount, &lamports) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Invalid SOL amount: %s", amount);
                    sol_wallet_clear(&sol_wallet);
                    return -1;
                }
                ret = sol_tx_send_lamports(&sol_wallet, to_address, lamports, tx_hash_out, 128);
            }

            sol_wallet_clear(&sol_wallet);
            break;
        }
```

Add include at top of `blockchain_wallet.c`:
```c
#include "solana/sol_spl.h"
```

**Step 3: Build to verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: Compiles cleanly, no warnings.

**Step 4: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/blockchain/solana/sol_chain.c messenger/blockchain/blockchain_wallet.c && \
git commit -m "feat(sol): wire SPL token send + history into blockchain layer"
```

---

### Task 5: Add USDC balance to all chains

**Files:**
- Modify: `messenger/src/api/engine/dna_engine_wallet.c`

**Step 1: Update Solana balance section**

In `dna_handle_get_balances`, find the Solana section (~line 188-218). Change from 2 to 3 balance slots:

```c
    if (wallet_info->type == BLOCKCHAIN_SOLANA) {
        /* Solana: SOL + USDT (SPL) + USDC (SPL) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* Native SOL balance */
        strncpy(balances[0].token, "SOL", sizeof(balances[0].token) - 1);
        strncpy(balances[0].network, "Solana", sizeof(balances[0].network) - 1);
        strcpy(balances[0].balance, "0.0");

        blockchain_balance_t bc_balance;
        if (blockchain_get_balance(wallet_info->type, wallet_info->address, &bc_balance) == 0) {
            strncpy(balances[0].balance, bc_balance.balance, sizeof(balances[0].balance) - 1);
        }

        /* USDT (SPL) balance */
        strncpy(balances[1].token, "USDT", sizeof(balances[1].token) - 1);
        strncpy(balances[1].network, "Solana", sizeof(balances[1].network) - 1);
        strcpy(balances[1].balance, "0");

        char usdt_balance[64] = {0};
        if (sol_spl_get_balance_by_symbol(wallet_info->address, "USDT", usdt_balance, sizeof(usdt_balance)) == 0) {
            strncpy(balances[1].balance, usdt_balance, sizeof(balances[1].balance) - 1);
        }

        /* USDC (SPL) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Solana", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance[64] = {0};
        if (sol_spl_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance, sizeof(usdc_balance)) == 0) {
            strncpy(balances[2].balance, usdc_balance, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }
```

**Step 2: Update Ethereum balance section**

Find Ethereum section (~line 130-155). Change from 2 to 3 balance slots:

```c
    if (wallet_info->type == BLOCKCHAIN_ETHEREUM) {
        /* Ethereum: ETH + USDT (ERC-20) + USDC (ERC-20) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* ... existing ETH + USDT code stays the same ... */

        /* USDC (ERC-20) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Ethereum", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance[64] = {0};
        if (eth_erc20_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance, sizeof(usdc_balance)) == 0) {
            strncpy(balances[2].balance, usdc_balance, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }
```

**Step 3: Update TRON balance section**

Find TRON section (~line 157-186). Change from 2 to 3 balance slots:

```c
    if (wallet_info->type == BLOCKCHAIN_TRON) {
        /* TRON: TRX + USDT (TRC-20) + USDC (TRC-20) */
        balances = calloc(3, sizeof(dna_balance_t));
        if (!balances) {
            error = DNA_ERROR_INTERNAL;
            goto done;
        }
        count = 3;

        /* ... existing TRX + USDT code stays the same ... */

        /* USDC (TRC-20) balance */
        strncpy(balances[2].token, "USDC", sizeof(balances[2].token) - 1);
        strncpy(balances[2].network, "Tron", sizeof(balances[2].network) - 1);
        strcpy(balances[2].balance, "0");

        char usdc_balance[64] = {0};
        if (trx_trc20_get_balance_by_symbol(wallet_info->address, "USDC", usdc_balance, sizeof(usdc_balance)) == 0) {
            strncpy(balances[2].balance, usdc_balance, sizeof(balances[2].balance) - 1);
        }

        goto done;
    }
```

**Step 4: Check that TRC-20 and ERC-20 have USDC in their token registries**

Verify: `grep -i "USDC" messenger/blockchain/ethereum/eth_erc20.c messenger/blockchain/tron/trx_trc20.c`

If USDC is not in the ERC-20 or TRC-20 token registry, add it:
- ERC-20 USDC mint: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` (6 decimals)
- TRC-20 USDC mint: `TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8` (6 decimals)

**Step 5: Build to verify**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: Compiles cleanly.

**Step 6: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/src/api/engine/dna_engine_wallet.c && \
git commit -m "feat(wallet): add USDC balance to Solana, Ethereum, and TRON wallets"
```

---

### Task 6: Update documentation

**Files:**
- Modify: `messenger/docs/functions/blockchain.md`

**Step 1: Add SPL Token section to blockchain.md**

After section 17.3 (Solana DEX), add:

```markdown
### 17.4 SPL Token (`sol_spl.h`)

| Function | Description |
|----------|-------------|
| `int sol_spl_get_token(const char*, sol_spl_token_t*)` | Get token info by symbol |
| `bool sol_spl_is_supported(const char*)` | Check if token symbol is supported |
| `int sol_spl_get_balance(const char*, const char*, uint8_t, char*, size_t)` | Get SPL token balance |
| `int sol_spl_get_balance_by_symbol(const char*, const char*, char*, size_t)` | Get SPL token balance by symbol |
| `int sol_spl_derive_ata(const uint8_t*, const uint8_t*, uint8_t*)` | Derive Associated Token Account (PDA) |
| `int sol_spl_check_ata(const char*, bool*)` | Check if ATA exists on-chain |
| `int sol_spl_send(const sol_wallet_t*, const char*, const char*, const char*, uint8_t, char*, size_t)` | Send SPL tokens (with auto ATA creation) |
| `int sol_spl_send_by_symbol(const sol_wallet_t*, const char*, const char*, const char*, char*, size_t)` | Send SPL tokens by symbol |
| `int sol_spl_estimate_fee(const char*, const char*, const char*, uint64_t*, bool*)` | Estimate SPL transfer fee |
```

**Step 2: Commit**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add messenger/docs/functions/blockchain.md && \
git commit -m "docs: add SPL token transfer functions to blockchain reference"
```

---

### Task 7: Build verification and version bump

**Files:**
- Modify: `messenger/include/dna/version.h`

**Step 1: Full clean build**

Run: `cd messenger/build && cmake .. && make -j$(nproc)`
Expected: Zero warnings, zero errors.

**Step 2: Run tests**

Run: `cd messenger/build && ctest --output-on-failure`
Expected: All existing tests pass.

**Step 3: Bump version**

In `messenger/include/dna/version.h`, bump PATCH version (e.g., 0.9.30 -> 0.9.31).

**Step 4: Final commit with version**

```bash
GIT_AUTHOR_NAME="nocdem" GIT_AUTHOR_EMAIL="nocdem@cpunk.io" GIT_COMMITTER_NAME="nocdem" GIT_COMMITTER_EMAIL="nocdem@cpunk.io" \
git add -A && \
git commit -m "feat: SPL token transfer with auto ATA creation (v0.9.31)"
```

---

## Summary of Tasks

| Task | Description | Files |
|------|-------------|-------|
| 1 | SPL transfer declarations in sol_spl.h | sol_spl.h |
| 2 | ATA derivation (PDA) + existence check | sol_spl.c |
| 3 | SPL transfer TX building + sending | sol_spl.c |
| 4 | Wire into sol_chain.c + blockchain_wallet.c | sol_chain.c, blockchain_wallet.c |
| 5 | USDC balance for all chains | dna_engine_wallet.c |
| 6 | Documentation update | blockchain.md |
| 7 | Build verification + version bump | version.h |
