# DNA Messenger C Library — Security Assessment 2026-02-23

**Date:** 2026-02-23 | **Status:** MANUALLY VERIFIED (2-pass) | **Model:** Claude Opus 4.6

---

## Summary

| Severity | Agent Found | After Pass 1 | After Pass 2 (manual) | False Positives |
|----------|-------------|---------------|----------------------|-----------------|
| CRITICAL | 4 | 4 | **4** | 0 |
| HIGH | 12 | 12 | **12** (1 adjusted) | 0 |
| MEDIUM | 26 | 18 | **15** | 8 |
| LOW | 20 | 9 | **9** | 11 |
| **Total** | **62** | **43** | **40** | **19** |

**Final false positive rate: 31%** — 19 of 62 agent findings removed. 2 merged/duplicate.

**Pass 1:** Agent findings verified by security auditor subagents.
**Pass 2:** Every remaining finding manually re-verified by reading source code line-by-line.

---

## Verification Legend

- **VERIFIED** — Confirmed real by manually reading source code (2 passes)
- **FALSE POSITIVE** — Not a real issue; removed from report
- **ADJUSTED** — Real issue but description corrected

---

## CRITICAL Findings (4 verified)

### C1. Floating-Point Arithmetic for Financial Calculations (All Chains)
**Status:** VERIFIED (2 passes)
**Severity:** CRITICAL
**Files:** `blockchain/ethereum/eth_tx.c:512`, `eth_erc20.c:310`, `tron/trx_tx.c:498`, `solana/sol_tx.c:282`, `solana/sol_chain.c:141`

**Description:** All blockchain modules use `double` floating-point arithmetic to convert human-readable amounts to base units. IEEE 754 `double` has ~15.9 decimal digits of precision, but wei values require up to 18 decimal digits.

**Evidence:**
```c
// eth_tx.c:512
double eth_amount = strtod(amount_str, NULL);
uint64_t frac_wei = (uint64_t)(frac * 1000000000000000000.0);

// eth_erc20.c:310
double value = strtod(amount, NULL);
uint64_t raw_value = (uint64_t)(value * multiplier + 0.5);

// trx_tx.c:498-504
double trx = strtod(amount_str, NULL);
*sun_out = (uint64_t)(trx * TRX_SUN_PER_TRX + 0.5);

// sol_tx.c:282
uint64_t lamports = (uint64_t)(amount_sol * SOL_LAMPORTS_PER_SOL);

// sol_chain.c:141
double sol_amount = atof(amount);
```

**Impact:** Precision loss for amounts requiring >15 significant digits. For example, 0.123456789012345678 ETH loses the last 2-3 digits.

**Recommendation:** Use string-based decimal arithmetic. Split on `.` and handle whole/fractional parts as integers.

---

### C2. Wallet `_clear()` Functions Use `memset()` Instead of `qgp_secure_memzero()`
**Status:** VERIFIED (2 passes)
**Severity:** CRITICAL
**Files:** `blockchain/ethereum/eth_wallet_create.c:133`, `tron/trx_wallet_create.c:254`, `solana/sol_wallet.c:399`

**Description:** All three wallet clear functions use `memset()` which compilers may optimize away, leaving private keys in memory.

**Evidence:**
```c
// eth_wallet_create.c:131-135
void eth_wallet_clear(eth_wallet_t *wallet) {
    if (wallet) { memset(wallet, 0, sizeof(*wallet)); }
}
// Identical pattern in trx_wallet_create.c:252-256 and sol_wallet.c:397-401
```

**Recommendation:** Replace `memset()` with `qgp_secure_memzero()`.

---

### C3. Cellframe Wallet Uses `memset()` for Dilithium Key Material
**Status:** VERIFIED (2 passes)
**Severity:** CRITICAL
**File:** `blockchain/cellframe/cellframe_wallet_create.c:304-308`

**Description:** Dilithium5 serialized private key material wiped with `memset()`, not `qgp_secure_memzero()`. Comment says "Securely clear sensitive data" but implementation is insecure.

**Evidence:**
```c
// cellframe_wallet_create.c:302-308
cleanup:
    /* Securely clear sensitive data */
    if (serialized_privkey) {
        memset(serialized_privkey, 0, serialized_privkey_size);  // NOT secure!
        free(serialized_privkey);
    }
    if (serialized_pubkey) {
        memset(serialized_pubkey, 0, serialized_pubkey_size);    // NOT secure!
        free(serialized_pubkey);
    }
```

**Recommendation:** Replace with `qgp_secure_memzero()`.

---

### C4. Heap Buffer Over-Read in `messenger_restore_keys`
**Status:** VERIFIED (2 passes)
**Severity:** CRITICAL
**File:** `messenger/keygen.c:650-658`

**Description:** `sign_pubkey_size` is read from a key file header (4 bytes at offset 12) and used as an offset without validation. Only a minimum size check of 20 bytes exists (line 641), but no check that the buffer is large enough for the actual key data.

**Evidence:**
```c
// keygen.c:650-658
uint32_t sign_pubkey_size, enc_pubkey_size;
memcpy(&sign_pubkey_size, pubkey_data + 12, 4);  // From file — UNVALIDATED
memcpy(&enc_pubkey_size, pubkey_data + 16, 4);

memcpy(dilithium_pk, pubkey_data + 20, sizeof(dilithium_pk));          // 2592 bytes from offset 20
memcpy(kyber_pk, pubkey_data + 20 + sign_pubkey_size, sizeof(kyber_pk)); // attacker-controlled offset
```

**Impact:** Both `memcpy` calls can read past `pubkey_data` buffer. Line 657 reads 2592 bytes from offset 20 without checking `pubkey_data_size >= 20 + 2592`. Line 658 uses attacker-controlled `sign_pubkey_size` as offset.

**Recommendation:** Validate: `if (pubkey_data_size < 20 + 2592 + 1568) return -1;` and `if (sign_pubkey_size != 2592) return -1;`

---

## HIGH Findings (12 verified)

### H1. Decompression Bomb in DHT Chunked Transfer
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `dht/shared/dht_chunked.c:268-279`

**Description:** Expected size is capped at 100MB, but allocation is `expected_size * 2` = 200MB.

```c
// dht_chunked.c:268-279
if (expected_size > 100 * 1024 * 1024) { return -1; }
size_t buffer_size = expected_size * 2;  // 200MB possible
uint8_t *buf = (uint8_t *)malloc(buffer_size);
```

**Recommendation:** Cap `buffer_size` directly, or reduce the 2x multiplier.

---

### H2. Global Engine Pointer Without Mutex
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `src/api/dna_engine.c:1306`

**Description:** `g_dht_callback_engine = engine;` — direct pointer assignment without mutex. Accessed from DHT callback threads.

**Recommendation:** Use mutex or atomic operations.

---

### H3. Detached Backup Threads Hold Raw Engine Pointer
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `src/api/engine/dna_engine_backup.c:298-308, 397-407`

**Description:** Both backup and restore threads use `pthread_detach()` holding raw `engine` pointer. If engine is destroyed while thread runs, use-after-free occurs. Unlike main worker threads (which use join tracking), these are untracked.

```c
// dna_engine_backup.c:308
pthread_detach(backup_thread);  // Thread is now untrackable
// Also line 407 for restore thread
```

**Recommendation:** Track threads and join during `dna_engine_destroy()`, or use reference counting.

---

### H4. Integer Overflow in `hex_to_u64`
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/ethereum/eth_tx.c:149-170`

**Description:** No overflow check on `val = (val << 4) | d;`. Hex strings longer than 16 chars silently overflow `uint64_t`.

**Recommendation:** Check hex string length <= 16 (excluding "0x" prefix), or detect overflow before shift.

---

### H5. Solana Wallet File Read Without Size Limit
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/solana/sol_wallet.c:329-339`

**Description:** Wallet JSON file is read without checking file size. A multi-GB file causes correspondingly large allocation.

```c
// sol_wallet.c:335-339
fseek(f, 0, SEEK_END);
long fsize = ftell(f);
fseek(f, 0, SEEK_SET);
char *json_str = malloc(fsize + 1);  // No upper bound check
```

**Recommendation:** Add `if (fsize <= 0 || fsize > 65536) return -1;` (wallet JSON should be small).

---

### H6. Solana Wallet Hex Parsing — No Input Validation
**Status:** ADJUSTED (description corrected in Pass 2)
**Severity:** HIGH
**File:** `blockchain/solana/sol_wallet.c:378-391`

**Description:** The hex-to-bytes parsing loop does exactly 32 iterations, reading from `priv_hex + i*2`. If the input string is shorter than 64 characters or NULL, `sscanf` reads past the string end (undefined behavior). `json_object_get_string()` can return NULL.

```c
// sol_wallet.c:378-383
const char *priv_hex = json_object_get_string(priv_obj);  // Can be NULL
for (int i = 0; i < 32; i++) {
    unsigned int byte;
    sscanf(priv_hex + i * 2, "%02x", &byte);  // No NULL/length check
    wallet_out->private_key[i] = (uint8_t)byte;
}
```

**Note:** Original report claimed "oversized input causes stack buffer overflow." This is incorrect — the loop always writes exactly 32 bytes. The actual risk is undersized or NULL input causing reads past the string boundary.

**Recommendation:** Check `if (!priv_hex || strlen(priv_hex) < 64) return -1;`

---

### H7. Solana TX Fixed 512-Byte Message Buffer
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/solana/sol_tx.c:92-139`

**Description:** `uint8_t message[512]` with incrementing `msg_offset` that is never bounds-checked. Current simple transfer uses ~180 bytes (safe), but no defensive check exists.

**Recommendation:** Add `if (msg_offset + N > sizeof(message)) return -1;` before each write.

---

### H8. ETH CURL Write Callback Multiplication Overflow
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/ethereum/eth_tx.c:38-39`

**Description:** `size_t realsize = size * nmemb;` can overflow. Then `realloc(buf->data, buf->size + realsize + 1)` allocates small buffer, and `memcpy` overflows.

**Recommendation:** Add `if (nmemb && size > SIZE_MAX / nmemb) return 0;`

---

### H9. Cellframe RPC Over Plain HTTP (No Encryption)
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/cellframe/cellframe_rpc.h:18`, `cellframe_rpc.c:44-88`

**Description:** `#define CELLFRAME_RPC_ENDPOINT "http://rpc.cellframe.net/connect"` — plain HTTP. All blockchain RPC traffic (balance queries, transaction submissions) is unencrypted. No CURL SSL options are set because TLS is not used.

**Impact:** Network eavesdropping and MITM on financial operations.

**Recommendation:** Switch to HTTPS and enable certificate verification.

---

### H10. ETH Transaction Hash Hardcoded 66-Byte Copy
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `blockchain/ethereum/eth_tx.c:487-488`

**Description:** `strncpy(tx_hash_out, hash, 66); tx_hash_out[66] = '\0';` — requires caller to provide at least 67-byte buffer. No size parameter is passed.

**Recommendation:** Accept and use buffer size parameter.

---

### H11. NULL Dereference from `sqlite3_column_text` in Message Backup
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `message_backup.c:701-702`

**Description:** `sqlite3_column_text()` result passed directly to `strncpy()` without NULL check. SQL NULL column causes NULL dereference.

```c
strncpy(messages[idx].sender, (const char*)sqlite3_column_text(stmt, 1), 255);
strncpy(messages[idx].recipient, (const char*)sqlite3_column_text(stmt, 2), 255);
```

**Recommendation:** Check for NULL: `const char *val = ...; if (!val) val = "";`

---

### H12. `strdup(NULL)` in Message Backup Contact List
**Status:** VERIFIED (2 passes)
**Severity:** HIGH
**File:** `message_backup.c:1072`

**Description:** `contacts[idx] = strdup(contact)` where `contact` from `sqlite3_column_text()` can be NULL. `strdup(NULL)` is undefined behavior (segfault on Linux).

**Recommendation:** `contacts[idx] = contact ? strdup(contact) : strdup("");`

---

## MEDIUM Findings (15 verified)

### M1. BIP39 Entropy Not Wiped After Mnemonic Generation
**Status:** VERIFIED (2 passes)
**File:** `crypto/bip39/bip39.c:134-140`

**Description:** `uint8_t entropy[32]` filled with `get_random_bytes()` is not zeroed before the function returns at line 140.

**Recommendation:** Add `qgp_secure_memzero(entropy, sizeof(entropy));` before return.

---

### M2. BIP39 Hash Not Wiped After Checksum
**Status:** VERIFIED (2 passes)
**File:** `crypto/bip39/bip39.c:55-110`

**Description:** `uint8_t hash[32]` (SHA-256 of entropy) remains on stack after use.

**Recommendation:** Add `qgp_secure_memzero(hash, sizeof(hash));` before return.

---

### M3. BIP39 Entropy+Hash Not Wiped in Validation
**Status:** VERIFIED (2 passes)
**File:** `crypto/bip39/bip39.c:216-254`

**Description:** `uint8_t entropy[33]` and `uint8_t hash[32]` left on stack in `bip39_validate_mnemonic`.

**Recommendation:** Wipe both before returning.

---

### M4. Seed Derivation — Local Master Seed Copy Not Wiped When Returned to Caller
**Status:** VERIFIED (2 passes)
**File:** `crypto/bip39/seed_derivation.c:189-194`

**Description:** When `master_seed_out` is provided, the master seed is copied to the caller but the local stack copy is NOT wiped. The wipe only happens when `!master_seed_out`.

```c
// seed_derivation.c:189-192
if (!master_seed_out) {
    qgp_secure_memzero(master_seed, BIP39_SEED_SIZE);
}
// When master_seed_out IS provided, local copy stays on stack
```

**Recommendation:** Always wipe the local copy: `qgp_secure_memzero(master_seed, BIP39_SEED_SIZE);`

---

### M5. Unvalidated `public_key_size` from File Used in `malloc`
**Status:** VERIFIED (2 passes)
**File:** `crypto/utils/qgp_key.c:200-202`

**Description:** `header.public_key_size` and `header.private_key_size` from key files used directly in `QGP_MALLOC()`. A crafted file could specify gigabyte-sized keys.

```c
key->public_key_size = header.public_key_size;
key->public_key = QGP_MALLOC(key->public_key_size);  // Attacker-controlled size
```

**Recommendation:** Validate against known sizes (Dilithium5=2592/4880, Kyber1024=1568/3168).

---

### M6. Fingerprint Memory Leak in `messenger_init` Error Paths
**Status:** VERIFIED (2 passes)
**File:** `messenger/init.c:229-270`

**Description:** Three error paths free `ctx->identity` and `ctx` but skip `free(ctx->fingerprint)`:
- Line 234 (gek_init failure)
- Line 259 (group outbox init failure)
- Line 269 (dna_context_new failure)

Compare with line 243 (groups_init failure) which correctly includes `free(ctx->fingerprint)`.

**Recommendation:** Add `free(ctx->fingerprint);` before `free(ctx)` in all error paths.

---

### M7. `ftell()` Return Not Checked for Error
**Status:** VERIFIED (2 passes)
**File:** `messenger/init.c:415`

**Description:** `size_t file_size = ftell(f);` — `ftell()` returns -1L on error, which becomes `SIZE_MAX` when cast to `size_t`.

**Note:** The subsequent `fread` check (`read_bytes != (size_t)fsize`) would catch this case, but the huge `malloc(SIZE_MAX + 1)` attempt occurs first and could cause OOM issues.

**Recommendation:** `long pos = ftell(f); if (pos < 0) { fclose(f); return error; }`

---

### M8. Static `migration_attempted` Persists Across Identity Switches
**Status:** VERIFIED (2 passes)
**File:** `messenger/keys.c:272-278`

**Description:** `static bool migration_attempted = false;` in `messenger_load_contacts()` persists across identity switches. Second identity's contact migration is skipped.

**Recommendation:** Reset flag on identity change, or store per-identity.

---

### M9. Message Header Struct Packing Inconsistency
**Status:** VERIFIED (2 passes)
**Files:** `messenger/messages.c:59-67` vs `dna_api.c:58-73`

**Description:** `messenger_enc_header_t` in `messages.c` is NOT packed. `dna_enc_header_t` in `dna_api.c` IS packed with `__attribute__((packed))`. Same fields, different memory layouts on architectures with struct padding.

**Impact:** Message parsing failures when messages cross between code paths.

**Recommendation:** Add `__attribute__((packed))` to `messages.c` struct to match `dna_api.c`.

---

### M10. Decrypted Message Buffer Not Securely Wiped
**Status:** VERIFIED (2 passes)
**File:** `dna_api.c:616`

**Description:** `if (decrypted) free(decrypted);` — plaintext message freed without zeroing. Note: DEK on line 613 IS properly wiped with `qgp_secure_memzero`.

```c
if (dek) {
    qgp_secure_memzero(dek, 32);  // Good
    free(dek);
}
if (decrypted) free(decrypted);    // Bad - plaintext not wiped
```

**Recommendation:** `qgp_secure_memzero(decrypted, decrypted_len); free(decrypted);`

---

### M11. Integer Overflow in Offline Queue Serialization
**Status:** ADJUSTED (Pass 2 — lower risk than reported)
**File:** `dht/shared/dht_offline_queue.c:220-235`

**Description:** `total_size` accumulates message sizes without overflow check. However, this is **serialization of internal data** (not parsing external input), and on 64-bit systems overflow is practically impossible. On 32-bit systems, theoretical overflow with many large messages.

**Risk:** Very low in practice. Internal data serialization.

**Recommendation:** Add overflow check for defense-in-depth: `if (total_size + addition < total_size) return -1;`

---

### M14. Profile Signature Not Verified on DHT Fetch
**Status:** VERIFIED (2 passes)
**File:** `dht/shared/dht_profile.c:421-427`

**Description:** Dilithium signature is parsed but explicitly skipped with comment:
```c
// Note: We can't verify signature without public key
// Signature verification should be done by caller if needed
// For now, we trust DHT (signed puts provide some authenticity)
```

Profile data is deserialized and used without signature verification.

**Recommendation:** Verify Dilithium signature against profile owner's public key.

---

### M19. Dilithium5 Private Key Not Wiped in `gek_rotate_and_publish`
**Status:** VERIFIED (2 passes)
**File:** `messenger/gek.c:719-756`

**Description:** `uint8_t owner_privkey[4896]` (Dilithium5 private key) read from file, used for signing, but never wiped on any return path (success or error).

**Note:** The GEK symmetric keys themselves ARE properly wiped elsewhere (gek_encrypt, gek_decrypt). This finding is about the Dilithium5 signing key specifically.

**Recommendation:** Add `qgp_secure_memzero(owner_privkey, sizeof(owner_privkey));` before all returns.

---

### M22. Group Invitations Have No Expiration
**Status:** VERIFIED (2 passes)
**File:** `database/group_invitations.c:20-28`

**Description:** Schema has `invited_at INTEGER` but no expiry mechanism. Invitations remain pending indefinitely.

**Recommendation:** Add `expires_at` column or check `invited_at + TTL` when querying.

---

### M24. ERC-20 Token Decimals Not Validated — Integer Overflow
**Status:** VERIFIED (2 passes)
**File:** `blockchain/ethereum/eth_erc20.c:271-274`

**Description:** `uint8_t decimals` (0-255) used in `for` loop: `divisor *= 10;`. `uint64_t` overflows at `decimals > 19` (10^20 > UINT64_MAX).

```c
uint64_t divisor = 1;
for (int i = 0; i < decimals; i++) {
    divisor *= 10;  // Overflows silently at decimals > 19
}
```

**Recommendation:** Add `if (decimals > 19) return -1;`

---

## LOW Findings (9 verified)

### L4. Additional Resource Leaks in `messenger_init` Error Paths
**Status:** VERIFIED (2 passes)
**File:** `messenger/init.c:249-270`

**Description:** Beyond the fingerprint leak (M6), later error paths also fail to close previously initialized subsystems (group_database, gek) before returning.

**Recommendation:** Implement structured goto-chain cleanup.

---

### L9. Ethereum Nonce Fetched Per Transaction
**Status:** VERIFIED (informational — by design)
**File:** `blockchain/ethereum/eth_tx.c:176-194`

**Description:** Every transaction calls `eth_getTransactionCount` via RPC. No caching.

**Note:** Standard practice for non-high-throughput wallets. Querying "pending" nonce ensures correctness across devices.

---

### L12. Cellframe RPC Endpoint Hardcoded
**Status:** VERIFIED (2 passes)
**File:** `blockchain/cellframe/cellframe_rpc.h:18`

**Description:** `#define CELLFRAME_RPC_ENDPOINT` is compile-time constant. No runtime configuration for testnet.

---

### L13. Missing `default:` Case in Engine Task Dispatcher
**Status:** VERIFIED (2 passes)
**File:** `src/api/dna_engine.c:971-1181`

**Description:** 50+ case switch with no `default:` case. Unrecognized task types silently do nothing.

**Recommendation:** Add `default: QGP_LOG_WARN(LOG_TAG, "Unknown task type: %d", task->type);`

---

### L18. Missing Error Logging in `bip39.c`
**Status:** VERIFIED (2 passes)
**File:** `crypto/bip39/bip39.c`

**Description:** Zero `QGP_LOG` calls in entire file. All error paths return `-1` silently. Other crypto files (`bip32.c`, `qgp_key.c`) log errors properly.

**Recommendation:** Add `QGP_LOG_ERROR` to error return paths.

---

### L19. Detached Threads Without Cleanup Handlers
**Status:** VERIFIED (2 passes)
**File:** `src/api/engine/dna_engine_backup.c:298-308, 397-407`

**Description:** Backup/restore threads use `pthread_detach()` without `pthread_cleanup_push()`. Overlaps with H3 (same root cause — different aspect).

---

### L20. Keyserver Cache — TTL-Only Eviction, No Hard Size Limit
**Status:** VERIFIED (downgraded from MEDIUM)
**File:** `database/keyserver_cache.c`

**Description:** Has 7-day TTL (`DEFAULT_TTL_SECONDS = 604800`) with per-entry expiry checks on read (line 170) and bulk cleanup (`keyserver_cache_expire_old()` line 297). No hard row count limit.

**Risk:** Very low — bounded by unique contacts, with TTL preventing indefinite growth.

---

### L21. Profile Cache — TTL-Only Eviction, No Hard Size Limit
**Status:** VERIFIED (downgraded from MEDIUM)
**File:** `database/profile_cache.c`

**Description:** Has `PROFILE_CACHE_TTL_SECONDS` with `profile_cache_is_expired()` check. No hard row count limit. Same pattern as L20.

---

### L22. Feed Comment Content Not Sanitized
**Status:** VERIFIED (downgraded from MEDIUM)
**File:** `src/api/engine/dna_engine_feed.c:627-665`

**Description:** Comment body passed without sanitization. Very low risk in P2P context — data stored as serialized JSON in DHT (not SQL concatenation), and Flutter `Text()` widgets auto-escape rendering.

---

## FALSE POSITIVE Findings Removed (19 total)

| ID | Original Claim | Reason for Rejection |
|----|---------------|---------------------|
| M12 | Offline queue sender_len not bounds-checked | **Bounds checks exist.** Lines 427 and 441: `if (ptr + sender_len > end) goto truncated;` |
| M13 | Offline queue error cleanup uses wrong count | **Safe.** Array allocated with `calloc` (zero-init). Free function checks NULL (lines 165-171). Unparsed entries have NULL pointers. |
| M15 | Backup data not integrity-checked | Uses AES-256-GCM authenticated encryption + Dilithium pubkey verification during restore |
| M16 | Identity export writes sensitive data to disk | Function `identity_export` does not exist in codebase |
| M17 | strncpy without null termination for fingerprints | **All structs use `= {0}` initialization** (lines 1278, 1337, 307). `fingerprint[128]` is pre-zeroed. |
| M23 | Feed cache no size limit | Has 30-day eviction policy (`FEED_CACHE_EVICT_SECONDS`) |
| M25 | Cellframe RPC response buffer overflow | Uses dynamic `realloc`-based CURL write callback |
| M26 | Cellframe RPC no TLS cert verification | Duplicate of H9 (same root cause — plain HTTP) |
| L1 | Magic numbers in crypto code | Uses named constants, enums, and `#define` macros |
| L2 | bip39_generate return unchecked | All production callers check return value |
| L3 | Inconsistent error handling in bip32 | `bip32.c` has thorough `qgp_secure_memzero` on all error paths |
| L5 | Static buffer in `messenger_get_identity_dir` | Function does not exist |
| L6 | DHT client reconnect no backoff | File `dht_client.c` doesn't exist; DHT operations implement exponential backoff |
| L7 | Transport layer missing keepalive | Transport is DHT/UDP-based, not TCP |
| L8 | Database connections not pooled | Uses singleton `sqlite3*` globals — correct SQLite pattern |
| L10 | TRON bandwidth calculation imprecise | No bandwidth/energy calculations exist; TronGrid API handles this |
| L11 | Solana blockhash not refreshed | Blockhash fetched fresh each time — opposite of claim |
| L14 | Engine task queue unbounded | Queue is fixed ring buffer: `DNA_TASK_QUEUE_SIZE = 256` (line 638-642) |
| L16 | ETH gas price hardcoded | Gas price fetched from network via `eth_gasPrice` RPC |

**Unverifiable findings excluded:**
| ID | Reason |
|----|--------|
| L15 | Unused variables — requires compilation to verify |
| L17 | SOL compute budget hardcoded — functionality doesn't exist in code |
| L20 (original) | Implicit conversions — requires `-Wall -Wextra` build |

---

## Recommendations by Priority

### Immediate (CRITICAL — fix before next release)
1. **C4:** Validate `sign_pubkey_size` in `keygen.c` — heap buffer over-read
2. **C1:** Replace `double` arithmetic with string-based decimal parsing
3. **C2/C3:** Replace `memset()` with `qgp_secure_memzero()` in all wallet `_clear()` functions

### Short-Term (HIGH — fix within next few releases)
4. **H8:** CURL write callback multiplication overflow check
5. **H4:** `hex_to_u64` overflow detection
6. **H6:** Validate hex string length/NULL before Solana wallet parsing loop
7. **H7:** Bounds-check `msg_offset` against buffer size
8. **H9:** Switch Cellframe RPC to HTTPS
9. **H11/H12:** NULL-check `sqlite3_column_text()` results
10. **H2/H3:** Fix global pointer race + track detached threads

### Medium-Term (MEDIUM)
11. **M1-M4, M10, M19:** Systematic audit of crypto/key material for missing `qgp_secure_memzero()`
12. **M5:** Validate key sizes from files against known constants
13. **M14:** Implement Dilithium signature verification for DHT profiles
14. **M9:** Add `__attribute__((packed))` to `messages.c` struct
15. **M24:** Add `if (decimals > 19) return -1;` in ERC-20 parsing

---

## Systemic Patterns

**Pattern 1: `memset` vs `qgp_secure_memzero`** — 7 findings (C2, C3, M1-M4, M19)
The codebase has `qgp_secure_memzero()` available and uses it in some places (bip32.c, gek_encrypt/decrypt, DEK cleanup) but misses it in others. A codebase-wide audit for `memset.*0` on sensitive data buffers would catch all instances.

**Pattern 2: Unvalidated external sizes** — 5 findings (C4, H4, H5, M5, M24)
Sizes/lengths read from files or network are used in `malloc`, `memcpy`, or arithmetic without bounds checking. Adding validation against known expected ranges would eliminate this class.

**Pattern 3: sqlite3_column_text NULL** — 2 findings (H11, H12)
`sqlite3_column_text()` returns NULL for SQL NULL columns. All call sites should check for NULL.

---

*Two-pass verification completed 2026-02-23 by Claude Opus 4.6.*
*Pass 1: Security auditor subagents. Pass 2: Manual line-by-line source code review.*
*Each finding verified by reading exact file and line numbers.*
