# Cryptography Functions

Low-level cryptographic primitives, platform abstraction, and key derivation.

---

## 5. Cryptography Utilities

**Directory:** `crypto/utils/`

### 5.1 AES-256-GCM (`qgp_aes.h`)

| Function | Description |
|----------|-------------|
| `size_t qgp_aes256_encrypt_size(size_t plaintext_len)` | Calculate buffer size for encryption |
| `int qgp_aes256_encrypt(...)` | Encrypt data with AES-256-GCM (AEAD) |
| `int qgp_aes256_decrypt(...)` | Decrypt data with AES-256-GCM (AEAD) |

### 5.2 SHA3-512 Hashing (`qgp_sha3.h`)

| Function | Description |
|----------|-------------|
| `int qgp_sha3_512(const uint8_t*, size_t, uint8_t*)` | Compute SHA3-512 hash |
| `int qgp_sha3_512_hex(...)` | Compute SHA3-512 and return as hex string |
| `int qgp_sha3_512_fingerprint(...)` | Compute SHA3-512 fingerprint of public key |

### 5.3 Kyber1024 KEM (`qgp_kyber.h`)

| Function | Description |
|----------|-------------|
| `int qgp_kem1024_keypair(uint8_t *pk, uint8_t *sk)` | Generate KEM-1024 keypair |
| `int qgp_kem1024_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk)` | Generate shared secret and ciphertext |
| `int qgp_kem1024_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)` | Recover shared secret from ciphertext |

### 5.4 Dilithium5 DSA (`qgp_dilithium.h`)

| Function | Description |
|----------|-------------|
| `int qgp_dsa87_keypair(uint8_t *pk, uint8_t *sk)` | Generate DSA-87 keypair |
| `int qgp_dsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)` | Generate keypair from seed |
| `int qgp_dsa87_sign(uint8_t *sig, size_t *siglen, ...)` | Sign message (detached signature) |
| `int qgp_dsa87_verify(const uint8_t *sig, size_t siglen, ...)` | Verify signature |

### 5.5 Key Encryption (`key_encryption.h`)

| Function | Description |
|----------|-------------|
| `int key_encrypt(...)` | Encrypt key data with password (PBKDF2+AES-GCM) |
| `int key_decrypt(...)` | Decrypt key data with password |
| `int key_save_encrypted(...)` | Save encrypted key to file |
| `int key_load_encrypted(...)` | Load and decrypt key from file |
| `bool key_file_is_encrypted(const char *file_path)` | Check if key file is password-protected |
| `int key_change_password(...)` | Change password on encrypted key file |
| `int key_verify_password(...)` | Verify password against key file |

### 5.6 AES Key Wrap (`aes_keywrap.h`)

| Function | Description |
|----------|-------------|
| `int aes256_wrap_key(...)` | AES-256 key wrap (RFC 3394) |
| `int aes256_unwrap_key(...)` | AES-256 key unwrap (RFC 3394) |

### 5.7 Deterministic Kyber (`kyber_deterministic.h`)

| Function | Description |
|----------|-------------|
| `int crypto_kem_keypair_derand(unsigned char *pk, unsigned char *sk, const uint8_t *seed)` | Deterministic keypair from seed |

### 5.8 Random Number Generation (`qgp_random.h`)

| Function | Description |
|----------|-------------|
| `int qgp_randombytes(uint8_t *buf, size_t len)` | Generate cryptographically secure random bytes |

### 5.9 Base58 Encoding (`base58.h`)

| Function | Description |
|----------|-------------|
| `size_t base58_encode(const void *a_in, size_t a_in_size, char *a_out)` | Encode binary data to base58 string |
| `size_t base58_decode(const char *a_in, void *a_out)` | Decode base58 string to binary data |

### 5.10 Keccak-256 / Ethereum (`keccak256.h`)

| Function | Description |
|----------|-------------|
| `int keccak256(const uint8_t *data, size_t len, uint8_t hash_out[32])` | Compute Keccak-256 hash (Ethereum variant) |
| `int keccak256_hex(const uint8_t *data, size_t len, char hex_out[65])` | Compute Keccak-256 as hex string |
| `int eth_address_from_pubkey(const uint8_t pubkey[65], uint8_t addr[20])` | Derive Ethereum address from public key |
| `int eth_address_from_pubkey_hex(...)` | Derive checksummed address as hex string |
| `int eth_address_checksum(const char*, char[41])` | Apply EIP-55 checksum |
| `int eth_address_verify_checksum(const char *address)` | Validate Ethereum address checksum |

### 5.11 Seed Storage (`seed_storage.h`)

| Function | Description |
|----------|-------------|
| `int seed_storage_save(...)` | Save master seed encrypted with Kyber1024 KEM |
| `int seed_storage_load(...)` | Load master seed decrypted with Kyber1024 KEM |
| `bool seed_storage_exists(const char *identity_dir)` | Check if encrypted seed file exists |
| `int seed_storage_delete(const char *identity_dir)` | Delete encrypted seed file |
| `int mnemonic_storage_save(...)` | Save mnemonic encrypted with Kyber1024 KEM |
| `int mnemonic_storage_load(...)` | Load mnemonic decrypted with Kyber1024 KEM |
| `bool mnemonic_storage_exists(const char *identity_dir)` | Check if encrypted mnemonic file exists |

### 5.12 Platform Abstraction (`qgp_platform.h`)

| Function | Description |
|----------|-------------|
| `int qgp_platform_random(uint8_t *buf, size_t len)` | Generate cryptographically secure random bytes |
| `int qgp_platform_mkdir(const char *path)` | Create directory with secure permissions |
| `int qgp_platform_file_exists(const char *path)` | Check if file/directory exists |
| `int qgp_platform_is_directory(const char *path)` | Check if path is a directory |
| `int qgp_platform_rmdir_recursive(const char *path)` | Recursively delete directory |
| `const char* qgp_platform_home_dir(void)` | Get user's home directory |
| `char* qgp_platform_join_path(const char*, const char*)` | Join path components |
| `void qgp_secure_memzero(void *ptr, size_t len)` | Securely zero memory |
| `const char* qgp_platform_app_data_dir(void)` | Get application data directory |
| `const char* qgp_platform_cache_dir(void)` | Get application cache directory |
| `int qgp_platform_set_app_dirs(const char*, const char*)` | Set app directories (mobile) |
| `qgp_network_state_t qgp_platform_network_state(void)` | Get current network state |
| `void qgp_platform_set_network_callback(...)` | Set network state change callback |
| `const char* qgp_platform_ca_bundle_path(void)` | Get CA certificate bundle path |
| `int qgp_platform_sanitize_filename(const char *filename)` | Validate filename for path traversal safety |

### 5.13 QGP Types (`qgp_types.h`)

| Function | Description |
|----------|-------------|
| `qgp_key_t* qgp_key_new(qgp_key_type_t, qgp_key_purpose_t)` | Create new key structure |
| `void qgp_key_free(qgp_key_t *key)` | Free key structure |
| `qgp_signature_t* qgp_signature_new(...)` | Create new signature structure |
| `void qgp_signature_free(qgp_signature_t *sig)` | Free signature structure |
| `size_t qgp_signature_get_size(const qgp_signature_t*)` | Get signature size |
| `size_t qgp_signature_serialize(const qgp_signature_t*, uint8_t*)` | Serialize signature |
| `int qgp_signature_deserialize(...)` | Deserialize signature |
| `int qgp_key_save(const qgp_key_t*, const char*)` | Save key to file |
| `int qgp_key_load(const char*, qgp_key_t**)` | Load key from file |
| `int qgp_pubkey_save(const qgp_key_t*, const char*)` | Save public key to file |
| `int qgp_pubkey_load(const char*, qgp_key_t**)` | Load public key from file |
| `int qgp_key_save_encrypted(...)` | Save key with password encryption |
| `int qgp_key_load_encrypted(...)` | Load key with password decryption |
| `bool qgp_key_file_is_encrypted(const char*)` | Check if key file is encrypted |
| `void qgp_hash_from_bytes(qgp_hash_t*, const uint8_t*, size_t)` | Create hash from bytes |
| `void qgp_hash_to_hex(const qgp_hash_t*, char*, size_t)` | Convert hash to hex string |
| `char* qgp_base64_encode(const uint8_t*, size_t, size_t*)` | Encode to base64 |
| `uint8_t* qgp_base64_decode(const char*, size_t*)` | Decode from base64 |

### 5.14 Logging (`qgp_log.h`)

| Function | Description |
|----------|-------------|
| `void qgp_log_set_level(qgp_log_level_t level)` | Set minimum log level |
| `qgp_log_level_t qgp_log_get_level(void)` | Get current log level |
| `void qgp_log_set_filter_mode(qgp_log_filter_mode_t)` | Set filter mode (whitelist/blacklist) |
| `qgp_log_filter_mode_t qgp_log_get_filter_mode(void)` | Get current filter mode |
| `void qgp_log_enable_tag(const char *tag)` | Enable logging for tag |
| `void qgp_log_disable_tag(const char *tag)` | Disable logging for tag |
| `void qgp_log_clear_filters(void)` | Clear all tag filters |
| `bool qgp_log_should_log(qgp_log_level_t, const char*)` | Check if tag should be logged |
| `void qgp_log_print(qgp_log_level_t, const char*, const char*, ...)` | Print log message |
| `void qgp_log_ring_enable(bool enabled)` | Enable/disable ring buffer storage |
| `bool qgp_log_ring_is_enabled(void)` | Check if ring buffer is enabled |
| `int qgp_log_ring_get_entries(qgp_log_entry_t*, int)` | Get log entries from ring buffer |
| `int qgp_log_ring_count(void)` | Get entry count in ring buffer |
| `void qgp_log_ring_clear(void)` | Clear all ring buffer entries |
| `int qgp_log_export_to_file(const char *filepath)` | Export ring buffer to file |
| `void qgp_log_ring_add(qgp_log_level_t, const char*, const char*, ...)` | Add entry to ring buffer |
| `void qgp_log_file_enable(bool enabled)` | Enable/disable persistent file logging |
| `bool qgp_log_file_is_enabled(void)` | Check if file logging is enabled |
| `void qgp_log_file_set_options(int max_size_kb, int max_files)` | Set rotation options |
| `void qgp_log_file_close(void)` | Flush and close log file |
| `const char* qgp_log_file_get_path(void)` | Get current log file path |
| `void qgp_log_file_write(qgp_log_level_t, const char*, const char*, ...)` | Write entry to log file |

---

## 6. Cryptography KEM (Kyber Internals)

**Directory:** `crypto/kem/`

Internal Kyber1024 (ML-KEM-1024) implementation from pq-crystals reference.

### 6.1 KEM API (`kem.h`)

| Function | Description |
|----------|-------------|
| `int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)` | Generate KEM keypair |
| `int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)` | Encapsulate shared secret |
| `int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)` | Decapsulate shared secret |

### 6.2 IND-CPA (`indcpa.h`)

| Function | Description |
|----------|-------------|
| `void gen_matrix(polyvec*, const uint8_t seed[32], int)` | Generate matrix from seed |
| `void indcpa_keypair(uint8_t *pk, uint8_t *sk)` | IND-CPA keypair generation |
| `void indcpa_enc(uint8_t *c, const uint8_t *m, const uint8_t *pk, const uint8_t *coins)` | IND-CPA encryption |
| `void indcpa_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk)` | IND-CPA decryption |

### 6.3 Polynomial Operations (`poly_kyber.h`)

| Function | Description |
|----------|-------------|
| `void poly_compress(uint8_t*, poly*)` | Compress polynomial |
| `void poly_decompress(poly*, const uint8_t*)` | Decompress polynomial |
| `void poly_tobytes(uint8_t*, poly*)` | Serialize polynomial to bytes |
| `void poly_frombytes(poly*, const uint8_t*)` | Deserialize polynomial from bytes |
| `void poly_frommsg(poly*, const uint8_t*)` | Convert message to polynomial |
| `void poly_tomsg(uint8_t*, poly*)` | Convert polynomial to message |
| `void poly_getnoise_eta1(poly*, const uint8_t*, uint8_t)` | Sample noise polynomial (eta1) |
| `void poly_getnoise_eta2(poly*, const uint8_t*, uint8_t)` | Sample noise polynomial (eta2) |
| `void poly_ntt(poly*)` | Forward NTT transform |
| `void poly_invntt_tomont(poly*)` | Inverse NTT to Montgomery domain |
| `void poly_basemul_montgomery(poly*, const poly*, const poly*)` | Pointwise multiplication |
| `void poly_tomont(poly*)` | Convert to Montgomery representation |
| `void poly_reduce(poly*)` | Apply Barrett reduction |
| `void poly_csubq(poly*)` | Conditional subtraction of q |
| `void poly_add(poly*, const poly*, const poly*)` | Add polynomials |
| `void poly_sub(poly*, const poly*, const poly*)` | Subtract polynomials |

### 6.4 Polynomial Vector (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvec_compress(uint8_t*, polyvec*)` | Compress polynomial vector |
| `void polyvec_decompress(polyvec*, const uint8_t*)` | Decompress polynomial vector |
| `void polyvec_tobytes(uint8_t*, polyvec*)` | Serialize polynomial vector |
| `void polyvec_frombytes(polyvec*, const uint8_t*)` | Deserialize polynomial vector |
| `void polyvec_ntt(polyvec*)` | Forward NTT on vector |
| `void polyvec_invntt_tomont(polyvec*)` | Inverse NTT on vector |
| `void polyvec_pointwise_acc_montgomery(poly*, const polyvec*, const polyvec*)` | Inner product |
| `void polyvec_reduce(polyvec*)` | Reduce coefficients |
| `void polyvec_csubq(polyvec*)` | Conditional subtraction |
| `void polyvec_add(polyvec*, const polyvec*, const polyvec*)` | Add vectors |

### 6.5 NTT (`ntt_kyber.h`)

| Function | Description |
|----------|-------------|
| `void ntt(int16_t poly[256])` | Number Theoretic Transform |
| `void invntt(int16_t poly[256])` | Inverse NTT |
| `void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)` | Base multiplication |

### 6.6 CBD Sampling (`cbd.h`)

| Function | Description |
|----------|-------------|
| `void cbd_eta1(poly*, const uint8_t*)` | Centered binomial distribution (eta1) |
| `void cbd_eta2(poly*, const uint8_t*)` | Centered binomial distribution (eta2) |

### 6.7 Reduction (`reduce_kyber.h`)

| Function | Description |
|----------|-------------|
| `int16_t montgomery_reduce(int32_t a)` | Montgomery reduction |
| `int16_t barrett_reduce(int16_t a)` | Barrett reduction |
| `int16_t csubq(int16_t x)` | Conditional subtraction of q |

### 6.8 Verification (`verify.h`)

| Function | Description |
|----------|-------------|
| `int verify(const uint8_t *a, const uint8_t *b, size_t len)` | Constant-time comparison |
| `void cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)` | Constant-time conditional move |

### 6.9 Symmetric Primitives (`symmetric.h`, `fips202_kyber.h`)

| Function | Description |
|----------|-------------|
| `void kyber_shake128_absorb(keccak_state*, const uint8_t*, uint8_t, uint8_t)` | SHAKE128 absorb for Kyber |
| `void kyber_shake256_prf(uint8_t*, size_t, const uint8_t*, uint8_t)` | SHAKE256 PRF for Kyber |
| `void shake128_absorb(keccak_state*, const uint8_t*, size_t)` | SHAKE128 absorb |
| `void shake128_squeezeblocks(uint8_t*, size_t, keccak_state*)` | SHAKE128 squeeze blocks |
| `void shake256_absorb(keccak_state*, const uint8_t*, size_t)` | SHAKE256 absorb |
| `void shake256_squeezeblocks(uint8_t*, size_t, keccak_state*)` | SHAKE256 squeeze blocks |
| `void shake128(uint8_t*, size_t, const uint8_t*, size_t)` | SHAKE128 hash |
| `void shake256(uint8_t*, size_t, const uint8_t*, size_t)` | SHAKE256 hash |
| `void sha3_256(uint8_t h[32], const uint8_t*, size_t)` | SHA3-256 hash |
| `void sha3_512(uint8_t h[64], const uint8_t*, size_t)` | SHA3-512 hash |

### 6.10 SHA2 (`sha2.h`)

| Function | Description |
|----------|-------------|
| `void sha256(uint8_t out[32], const uint8_t*, size_t)` | SHA-256 hash |
| `void sha512(uint8_t out[64], const uint8_t*, size_t)` | SHA-512 hash |

---

## 7. Cryptography DSA (Dilithium Internals)

**Directory:** `crypto/dsa/`

Internal Dilithium5 (ML-DSA-87) implementation from pq-crystals reference.

### 7.1 Signature API (`sign.h`)

| Function | Description |
|----------|-------------|
| `int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)` | Generate signing keypair |
| `int crypto_sign_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)` | Generate keypair from 32-byte seed (deterministic, v0.3.0+) |
| `int crypto_sign_signature(uint8_t *sig, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Create detached signature |
| `int crypto_sign(uint8_t *sm, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Sign message (attached) |
| `int crypto_sign_verify(const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Verify detached signature |
| `int crypto_sign_open(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*)` | Verify and open signed message |
| `int crypto_sign_signature_internal(...)` | Internal signature with randomness |
| `int crypto_sign_verify_internal(...)` | Internal verification |

### 7.2 Level-Specific API (`api.h`)

| Function | Description |
|----------|-------------|
| `int pqcrystals_dilithium2_ref_keypair(uint8_t*, uint8_t*)` | Dilithium2 keypair |
| `int pqcrystals_dilithium2_ref_signature(...)` | Dilithium2 signature |
| `int pqcrystals_dilithium2_ref_verify(...)` | Dilithium2 verify |
| `int pqcrystals_dilithium3_ref_keypair(uint8_t*, uint8_t*)` | Dilithium3 keypair |
| `int pqcrystals_dilithium3_ref_signature(...)` | Dilithium3 signature |
| `int pqcrystals_dilithium3_ref_verify(...)` | Dilithium3 verify |
| `int pqcrystals_dilithium5_ref_keypair(uint8_t*, uint8_t*)` | Dilithium5 keypair |
| `int pqcrystals_dilithium5_ref_signature(...)` | Dilithium5 signature |
| `int pqcrystals_dilithium5_ref_verify(...)` | Dilithium5 verify |

### 7.3 Polynomial Operations (`poly.h`)

| Function | Description |
|----------|-------------|
| `void poly_reduce(poly*)` | Reduce polynomial coefficients |
| `void poly_caddq(poly*)` | Conditional add q |
| `void poly_add(poly*, const poly*, const poly*)` | Add polynomials |
| `void poly_sub(poly*, const poly*, const poly*)` | Subtract polynomials |
| `void poly_shiftl(poly*)` | Left shift polynomial |
| `void poly_ntt(poly*)` | Forward NTT |
| `void poly_invntt_tomont(poly*)` | Inverse NTT to Montgomery |
| `void poly_pointwise_montgomery(poly*, const poly*, const poly*)` | Pointwise multiplication |
| `void poly_power2round(poly*, poly*, const poly*)` | Power of 2 rounding |
| `void poly_decompose(poly*, poly*, const poly*)` | Decompose polynomial |
| `unsigned int poly_make_hint(poly*, const poly*, const poly*)` | Make hint polynomial |
| `void poly_use_hint(poly*, const poly*, const poly*)` | Apply hint polynomial |
| `int poly_chknorm(const poly*, int32_t)` | Check coefficient norm |
| `void poly_uniform(poly*, const uint8_t*, uint16_t)` | Sample uniform polynomial |
| `void poly_uniform_eta(poly*, const uint8_t*, uint16_t)` | Sample eta-bounded polynomial |
| `void poly_uniform_gamma1(poly*, const uint8_t*, uint16_t)` | Sample gamma1-bounded polynomial |
| `void poly_challenge(poly*, const uint8_t*)` | Generate challenge polynomial |
| `void polyeta_pack(uint8_t*, const poly*)` | Pack eta polynomial |
| `void polyeta_unpack(poly*, const uint8_t*)` | Unpack eta polynomial |
| `void polyt1_pack(uint8_t*, const poly*)` | Pack t1 polynomial |
| `void polyt1_unpack(poly*, const uint8_t*)` | Unpack t1 polynomial |
| `void polyt0_pack(uint8_t*, const poly*)` | Pack t0 polynomial |
| `void polyt0_unpack(poly*, const uint8_t*)` | Unpack t0 polynomial |
| `void polyz_pack(uint8_t*, const poly*)` | Pack z polynomial |
| `void polyz_unpack(poly*, const uint8_t*)` | Unpack z polynomial |
| `void polyw1_pack(uint8_t*, const poly*)` | Pack w1 polynomial |

### 7.4 Polynomial Vector L (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvecl_uniform_eta(polyvecl*, const uint8_t*, uint16_t)` | Sample uniform eta vector |
| `void polyvecl_uniform_gamma1(polyvecl*, const uint8_t*, uint16_t)` | Sample uniform gamma1 vector |
| `void polyvecl_reduce(polyvecl*)` | Reduce vector coefficients |
| `void polyvecl_add(polyvecl*, const polyvecl*, const polyvecl*)` | Add vectors |
| `void polyvecl_ntt(polyvecl*)` | Forward NTT on vector |
| `void polyvecl_invntt_tomont(polyvecl*)` | Inverse NTT on vector |
| `void polyvecl_pointwise_poly_montgomery(polyvecl*, const poly*, const polyvecl*)` | Pointwise multiply |
| `void polyvecl_pointwise_acc_montgomery(poly*, const polyvecl*, const polyvecl*)` | Inner product |
| `int polyvecl_chknorm(const polyvecl*, int32_t)` | Check vector norm |

### 7.5 Polynomial Vector K (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyveck_uniform_eta(polyveck*, const uint8_t*, uint16_t)` | Sample uniform eta vector |
| `void polyveck_reduce(polyveck*)` | Reduce vector coefficients |
| `void polyveck_caddq(polyveck*)` | Conditional add q |
| `void polyveck_add(polyveck*, const polyveck*, const polyveck*)` | Add vectors |
| `void polyveck_sub(polyveck*, const polyveck*, const polyveck*)` | Subtract vectors |
| `void polyveck_shiftl(polyveck*)` | Left shift vector |
| `void polyveck_ntt(polyveck*)` | Forward NTT on vector |
| `void polyveck_invntt_tomont(polyveck*)` | Inverse NTT on vector |
| `void polyveck_pointwise_poly_montgomery(polyveck*, const poly*, const polyveck*)` | Pointwise multiply |
| `int polyveck_chknorm(const polyveck*, int32_t)` | Check vector norm |
| `void polyveck_power2round(polyveck*, polyveck*, const polyveck*)` | Power of 2 rounding |
| `void polyveck_decompose(polyveck*, polyveck*, const polyveck*)` | Decompose vector |
| `unsigned int polyveck_make_hint(polyveck*, const polyveck*, const polyveck*)` | Make hint vector |
| `void polyveck_use_hint(polyveck*, const polyveck*, const polyveck*)` | Apply hint vector |
| `void polyveck_pack_w1(uint8_t*, const polyveck*)` | Pack w1 vector |

### 7.6 Matrix Operations (`polyvec.h`)

| Function | Description |
|----------|-------------|
| `void polyvec_matrix_expand(polyvecl mat[K], const uint8_t*)` | Expand matrix from seed |
| `void polyvec_matrix_pointwise_montgomery(polyveck*, const polyvecl mat[K], const polyvecl*)` | Matrix-vector multiply |

### 7.7 NTT (`ntt.h`)

| Function | Description |
|----------|-------------|
| `void ntt(int32_t a[N])` | Number Theoretic Transform |
| `void invntt_tomont(int32_t a[N])` | Inverse NTT to Montgomery |

### 7.8 Reduction (`reduce.h`)

| Function | Description |
|----------|-------------|
| `int32_t montgomery_reduce(int64_t a)` | Montgomery reduction |
| `int32_t reduce32(int32_t a)` | Reduce modulo q |
| `int32_t caddq(int32_t a)` | Conditional add q |
| `int32_t freeze(int32_t a)` | Freeze to positive representative |

### 7.9 Rounding (`rounding.h`)

| Function | Description |
|----------|-------------|
| `int32_t power2round(int32_t*, int32_t)` | Power of 2 rounding |
| `int32_t decompose(int32_t*, int32_t)` | Decompose for hint |
| `unsigned int make_hint(int32_t, int32_t)` | Make hint bit |
| `int32_t use_hint(int32_t, unsigned int)` | Apply hint bit |

### 7.10 Packing (`packing.h`)

| Function | Description |
|----------|-------------|
| `void pack_pk(uint8_t*, const uint8_t*, const polyveck*)` | Pack public key |
| `void pack_sk(uint8_t*, const uint8_t*, const uint8_t*, const uint8_t*, const polyveck*, const polyvecl*, const polyveck*)` | Pack secret key |
| `void pack_sig(uint8_t*, const uint8_t*, const polyvecl*, const polyveck*)` | Pack signature |
| `void unpack_pk(uint8_t*, polyveck*, const uint8_t*)` | Unpack public key |
| `void unpack_sk(uint8_t*, uint8_t*, uint8_t*, polyveck*, polyvecl*, polyveck*, const uint8_t*)` | Unpack secret key |
| `int unpack_sig(uint8_t*, polyvecl*, polyveck*, const uint8_t*)` | Unpack signature |

---

## 8. BIP39/BIP32 Key Derivation

**Directory:** `crypto/bip39/`, `crypto/bip32/`

BIP39 mnemonic generation and BIP32 hierarchical deterministic key derivation.

### 8.1 BIP39 Mnemonic (`bip39.h`)

| Function | Description |
|----------|-------------|
| `int bip39_mnemonic_from_entropy(...)` | Generate mnemonic from entropy bytes |
| `int bip39_generate_mnemonic(int word_count, char*, size_t)` | Generate random mnemonic (12-24 words) |
| `bool bip39_validate_mnemonic(const char *mnemonic)` | Validate mnemonic checksum and words |
| `int bip39_mnemonic_to_seed(const char*, const char*, uint8_t[64])` | Derive 512-bit seed from mnemonic |
| `const char** bip39_get_wordlist(void)` | Get BIP39 English wordlist (2048 words) |
| `int bip39_word_index(const char *word)` | Get word index in wordlist (0-2047) |
| `int bip39_pbkdf2_hmac_sha512(...)` | PBKDF2-HMAC-SHA512 for seed derivation |

### 8.2 QGP Seed Derivation (`bip39.h`)

| Function | Description |
|----------|-------------|
| `int qgp_derive_seeds_from_mnemonic(...)` | Derive signing, encryption, wallet seeds |
| `int qgp_derive_seeds_with_master(...)` | Derive seeds + 64-byte master seed |
| `void qgp_display_mnemonic(const char *mnemonic)` | Display mnemonic with word numbers |
| `void test_hmac_sha512(...)` | Test HMAC-SHA512 implementation |

### 8.3 BIP32 HD Derivation (`bip32.h`)

| Function | Description |
|----------|-------------|
| `int bip32_master_key_from_seed(const uint8_t*, size_t, bip32_extended_key_t*)` | Derive master key from BIP39 seed |
| `int bip32_derive_hardened(const bip32_extended_key_t*, uint32_t, bip32_extended_key_t*)` | Derive hardened child key |
| `int bip32_derive_normal(const bip32_extended_key_t*, uint32_t, bip32_extended_key_t*)` | Derive normal child key |
| `int bip32_derive_path(const uint8_t*, size_t, const char*, bip32_extended_key_t*)` | Derive key from path string |
| `int bip32_derive_ethereum(const uint8_t*, size_t, bip32_extended_key_t*)` | Derive Ethereum key (m/44'/60'/0'/0/0) |
| `int bip32_get_public_key(const bip32_extended_key_t*, uint8_t[65])` | Get uncompressed secp256k1 public key |
| `int bip32_get_public_key_compressed(const bip32_extended_key_t*, uint8_t[33])` | Get compressed public key |
| `void bip32_clear_key(bip32_extended_key_t*)` | Securely clear key from memory |
