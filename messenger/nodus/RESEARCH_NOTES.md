# OpenDHT Integration Research - `dna-nodus` Planning

**Date:** 2025-11-23
**Author:** DNA Messenger Team

---

## Current OpenDHT Setup

### Version
- **OpenDHT Version:** 3.5.5 (via pkg-config)
- **API Compatibility:** 2.x and 3.x

### Architecture

**DHT Runner:**
- Uses `dht::DhtRunner` class from `<opendht/dhtrunner.h>`
- Kademlia DHT implementation
- Bootstrapping to multiple nodes

**Identity System (RSA-2048):**
```cpp
struct dht_identity {
    dht::crypto::Identity identity;  // C++ OpenDHT Identity
};
```

**Current Crypto Layer:**
- **Public Key:** RSA-2048 (X.509 certificate via GnuTLS)
- **Private Key:** RSA-2048 (X.509 private key via GnuTLS)
- **Storage Format:** PEM files (.crt + .pem)
- **Signatures:** RSA-2048 signatures via GnuTLS

### Key GnuTLS Integration Points

**File:** `dht/core/dht_context.cpp`

**Identity Creation:**
- `dht::crypto::PrivateKey` wraps `gnutls_x509_privkey_t`
- `dht::crypto::Certificate` wraps `gnutls_x509_crt_t`
- `dht::crypto::Identity` = pair of (PrivateKey, Certificate)

**Save Identity** (lines 38-81):
```cpp
auto cert = id.second->cert;         // gnutls_x509_crt_t
auto privkey = id.first->x509_key;   // gnutls_x509_privkey_t

gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &cert_pem);
gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, &key_pem);
```

**Load Identity** (lines 84-129):
```cpp
gnutls_x509_crt_import(cert, &cert_datum, GNUTLS_X509_FMT_PEM);
gnutls_x509_privkey_import(privkey, &key_datum, GNUTLS_X509_FMT_PEM);

auto priv = std::make_shared<dht::crypto::PrivateKey>(privkey);
auto certificate = std::make_shared<dht::crypto::Certificate>(cert);
return dht::crypto::Identity(priv, certificate);
```

### ValueType System

**Custom Value Types:**
- `DNA_TYPE_7DAY` (0x1001) - 7-day TTL
- `DNA_TYPE_365DAY` (0x1002) - 365-day TTL
- Lambda-based storage callbacks (lines 154-221)

**Persistent Storage Integration:**
- Callbacks intercept incoming values
- Store to SQLite if `ctx->storage` available
- Metadata: key_hash, value_data, type, created_at, expires_at

---

## Required Modifications for Dilithium5

### 1. Replace Identity System

**Current (RSA-2048):**
- Public key: ~270 bytes (RSA-2048 in X.509)
- Private key: ~1700 bytes (RSA-2048 PKCS#8)
- Signature: ~256 bytes (RSA-2048)

**Target (Dilithium5):**
- Public key: 2592 bytes
- Private key: 4896 bytes
- Signature: 4627 bytes

### 2. Fork Locations

**OpenDHT Files to Modify:**
- `include/opendht/crypto.h` - Identity types
- `src/crypto.cpp` - Crypto implementations
- `include/opendht/dhtrunner.h` - Runner API
- `src/dhtrunner.cpp` - Put/get operations

### 3. Dilithium5 Integration Points

**Replace in OpenDHT fork:**
```cpp
// OLD: RSA-2048 via GnuTLS
class PrivateKey {
    gnutls_x509_privkey_t x509_key;
};

class Certificate {
    gnutls_x509_crt_t cert;
};

// NEW: Dilithium5 via crypto/dsa/
class PrivateKey {
    uint8_t dilithium_sk[4896];  // Dilithium5 secret key
};

class Certificate {
    uint8_t dilithium_pk[2592];  // Dilithium5 public key
};
```

**Signature Operations:**
```cpp
// OLD: RSA signing
gnutls_privkey_sign_data(...);

// NEW: Dilithium5 signing
pqcrystals_dilithium5_ref_signature(sig, &siglen, msg, msglen, ctx, ctxlen, sk);
```

### 4. Signed Put Enforcement

**Add to `src/dhtrunner.cpp`:**
```cpp
void DhtRunner::put(const InfoHash& key, Value&& value, ...) {
    if (!value.isSigned()) {
        std::cerr << "[NODUS] Dropping unsigned put (mandatory signatures)" << std::endl;
        return;  // Drop immediately
    }

    if (!verifySignature(value)) {
        std::cerr << "[NODUS] Invalid signature, dropping put" << std::endl;
        return;
    }

    // Proceed with signed put
    ...
}
```

---

## Implementation Strategy

### Phase 1: Fork OpenDHT
1. Fork `savoirfairelinux/opendht` (v3.5.5)
2. Create branch: `dilithium5-pq`
3. Add as submodule: `vendor/opendht-pq`

### Phase 2: Minimal Dilithium5 Integration
1. Replace `PrivateKey` class with Dilithium5 SK (4896 bytes)
2. Replace `Certificate` class with Dilithium5 PK (2592 bytes)
3. Update `Identity` to use Dilithium5 types
4. Implement save/load for Dilithium5 keys (binary format)

### Phase 3: Signature Enforcement
1. Add signature validation to `put()` operations
2. Drop unsigned values immediately
3. Add logging for dropped puts
4. Update `Value` class to enforce signature field

### Phase 4: dna-nodus Binary
1. Create `nodus/` directory structure
2. Build CLI wrapper around modified OpenDHT
3. Daemon implementation
4. Systemd service

---

## Key Differences: RSA vs Dilithium5

| Feature | RSA-2048 (Current) | Dilithium5 (Target) |
|---------|-------------------|---------------------|
| **Standard** | PKCS#1, X.509 | FIPS 204 (ML-DSA-87) |
| **Public Key** | ~270 bytes | 2592 bytes |
| **Private Key** | ~1700 bytes | 4896 bytes |
| **Signature** | ~256 bytes | 4627 bytes |
| **Security** | Classical | Post-Quantum (NIST Cat 5) |
| **Library** | GnuTLS | crypto/dsa/ (vendored) |
| **Format** | PEM (Base64) | Binary |

---

## Next Steps

1. ✅ Research complete
2. ⏭️ Fork OpenDHT repository
3. ⏭️ Implement Dilithium5 integration
4. ⏭️ Build dna-nodus binary
5. ⏭️ Deploy to VPS nodes

---

## References

- OpenDHT: https://github.com/savoirfairelinux/opendht
- FIPS 204: https://csrc.nist.gov/pubs/fips/204/final
- Current implementation: `dht/core/dht_context.cpp`
- Dilithium5 library: `crypto/dsa/`
