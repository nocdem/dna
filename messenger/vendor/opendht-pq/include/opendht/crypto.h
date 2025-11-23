/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "infohash.h"
#include "utils.h"
#include "rng.h"

// DILITHIUM5 INTEGRATION: Complete replacement of RSA-2048 with post-quantum signatures
// Using FIPS 204 (ML-DSA-87) from DNA Messenger crypto library
extern "C" {
#include "api.h"  // Dilithium5: pqcrystals_dilithium5_ref_* functions
}

#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <string_view>

#ifdef _WIN32
#include <iso646.h>
#endif

namespace dht {

/**
 * Contains all crypto primitives
 */
namespace crypto {

class OPENDHT_PUBLIC CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& str) : std::runtime_error(str) {};
    explicit CryptoException(const char* str) : std::runtime_error(str) {};
    CryptoException(const CryptoException& e) noexcept = default;
    CryptoException& operator=(const CryptoException&) noexcept = default;
};

/**
 * Exception thrown when a decryption error happened.
 */
class OPENDHT_PUBLIC DecryptError : public CryptoException {
public:
    explicit DecryptError(const std::string& str) : CryptoException(str) {};
    explicit DecryptError(const char* str) : CryptoException(str) {};
    DecryptError(const DecryptError& e) noexcept = default;
    DecryptError& operator=(const DecryptError&) noexcept = default;
};

struct PrivateKey;
struct Certificate;
class RevocationList;

using Identity = std::pair<std::shared_ptr<PrivateKey>, std::shared_ptr<Certificate>>;

/**
 * A public key - Dilithium5 (ML-DSA-87) post-quantum signature scheme
 * FIPS 204 compliant, NIST Category 5 security (256-bit quantum resistance)
 */
struct OPENDHT_PUBLIC PublicKey
{
    PublicKey();

    /**
     * Import Dilithium5 public key from raw bytes (2592 bytes)
     */
    PublicKey(const uint8_t* dat, size_t dat_size);
    PublicKey(const Blob& pk) : PublicKey(pk.data(), pk.size()) {}
    PublicKey(std::string_view pk) : PublicKey((const uint8_t*)pk.data(), pk.size()) {}

    // Copy constructor: safe since we're just copying a byte array
    PublicKey(const PublicKey& o)
        : valid_(o.valid_)
        , cachedId_(o.cachedId_)
        , cachedLongId_(o.cachedLongId_)
        , idCached_(o.idCached_.load())
        , longIdCached_(o.longIdCached_.load())
    {
        std::memcpy(dilithium_pk_, o.dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES);
    }

    PublicKey(PublicKey&& o) noexcept;

    ~PublicKey();

    explicit operator bool() const { return valid_; }

    bool operator ==(const PublicKey& o) const {
        return valid_ && o.valid_ && getLongId() == o.getLongId();
    }
    bool operator !=(const PublicKey& o) const {
        return !(*this == o);
    }

    // Copy assignment
    PublicKey& operator=(const PublicKey& o) {
        if (this != &o) {
            std::memcpy(dilithium_pk_, o.dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES);
            valid_ = o.valid_;
            cachedId_ = o.cachedId_;
            cachedLongId_ = o.cachedLongId_;
            idCached_.store(o.idCached_.load());
            longIdCached_.store(o.longIdCached_.load());
        }
        return *this;
    }

    PublicKey& operator=(PublicKey&& o) noexcept;

    /**
     * Get public key fingerprint (SHA3-512 of Dilithium5 pubkey, truncated to 160 bits)
     */
    const InfoHash& getId() const;

    /**
     * Get public key long fingerprint (full SHA3-512 of Dilithium5 pubkey)
     */
    const PkId& getLongId() const;

    /**
     * Verify Dilithium5 signature (4627 bytes)
     * @param data Message that was signed
     * @param data_len Message length
     * @param signature Dilithium5 signature
     * @param signature_len Signature length (must be 4627)
     * @return true if signature is valid, false otherwise
     */
    bool checkSignature(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t signature_len) const;

    inline bool checkSignature(const Blob& data, const Blob& signature) const {
        return checkSignature(data.data(), data.size(), signature.data(), signature.size());
    }

    // REMOVED: encrypt() - Dilithium5 is signature-only (use Kyber for encryption if needed)

    /**
     * Serialize Dilithium5 public key to raw binary (2592 bytes)
     */
    void pack(Blob& b) const;
    int pack(uint8_t* out, size_t* out_len) const;

    /**
     * Deserialize Dilithium5 public key from raw binary (2592 bytes)
     */
    void unpack(const uint8_t* dat, size_t dat_size);

    std::string toString() const;

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b;
        pack(b);
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(const msgpack::object& o);

    // REMOVED: getPreferredDigest() - Not applicable to Dilithium5

private:
    // Dilithium5 public key: 2592 bytes (FIPS 204 / ML-DSA-87)
    uint8_t dilithium_pk_[pqcrystals_dilithium5_PUBLICKEYBYTES];
    bool valid_ {false};

    // Cached fingerprints for performance
    mutable InfoHash cachedId_ {};
    mutable PkId cachedLongId_ {};
    mutable std::atomic_bool idCached_ {false};
    mutable std::atomic_bool longIdCached_ {false};
};

/**
 * A private key - Dilithium5 (ML-DSA-87) post-quantum signature scheme
 * Includes the corresponding public key
 * FIPS 204 compliant, NIST Category 5 security (256-bit quantum resistance)
 */
struct OPENDHT_PUBLIC PrivateKey
{
    PrivateKey();

    /**
     * Import Dilithium5 private key from raw bytes (4896 bytes)
     * Note: Password encryption not yet implemented for Dilithium5 keys
     */
    PrivateKey(const uint8_t* src, size_t src_size, const char* password = nullptr);
    PrivateKey(const Blob& src, const std::string& password = {}) : PrivateKey(src.data(), src.size(), password.c_str()) {}
    PrivateKey(std::string_view src, const std::string& password = {}) : PrivateKey((const uint8_t*)src.data(), src.size(), password.c_str()) {}

    PrivateKey(PrivateKey&& o) noexcept;
    PrivateKey& operator=(PrivateKey&& o) noexcept;

    ~PrivateKey();

    explicit operator bool() const { return valid_; }

    /**
     * Get the associated Dilithium5 public key
     */
    const PublicKey& getPublicKey() const;
    const std::shared_ptr<PublicKey>& getSharedPublicKey() const;

    /**
     * Set the cached public key (used when loading from file)
     * @param pk Public key to cache
     */
    void setPublicKeyCache(std::shared_ptr<PublicKey> pk);

    /**
     * Serialize Dilithium5 private key to raw binary (4896 bytes)
     * @param password Optional password for encryption (not yet implemented)
     */
    int serialize(uint8_t* out, size_t* out_len, const std::string& password = {}) const;
    Blob serialize(const std::string& password = {}) const;

    /**
     * Sign data with Dilithium5 (produces 4627-byte signature)
     * Uses FIPS 204 ML-DSA-87 signature algorithm
     * @param data Data to sign
     * @param data_len Data length
     * @returns Dilithium5 signature (4627 bytes)
     */
    Blob sign(const uint8_t* data, size_t data_len) const;
    inline Blob sign(std::string_view dat) const { return sign((const uint8_t*)dat.data(), dat.size()); }
    inline Blob sign(const Blob& dat) const { return sign(dat.data(), dat.size()); }

    // REMOVED: decrypt() - Dilithium5 is signature-only (use Kyber for encryption if needed)

    /**
     * Generate a new Dilithium5 key pair
     * Uses pqcrystals_dilithium5_ref_keypair() from FIPS 204
     * @returns New PrivateKey with generated Dilithium5 keypair
     */
    static PrivateKey generate();

private:
    // Dilithium5 secret key: 4896 bytes (FIPS 204 / ML-DSA-87)
    uint8_t dilithium_sk_[pqcrystals_dilithium5_SECRETKEYBYTES];
    bool valid_ {false};

    // Cached public key (extracted from secret key)
    mutable std::mutex publicKeyMutex_ {};
    mutable std::shared_ptr<PublicKey> publicKey_ {};

    PrivateKey(const PrivateKey&) = delete;
    PrivateKey& operator=(const PrivateKey&) = delete;
};

// REMOVED: RevocationList, CertificateRequest, OCSP classes - GnuTLS X.509 not needed for Dilithium5 DHT
#if 0
class OPENDHT_PUBLIC RevocationList
{
    using clock = std::chrono::system_clock;
    using time_point = clock::time_point;
    using duration = clock::duration;
public:
    RevocationList();
    RevocationList(const Blob& b);
    RevocationList(RevocationList&& o) noexcept : crl(o.crl) { o.crl = nullptr; }
    ~RevocationList();

    RevocationList& operator=(RevocationList&& o) { crl = o.crl; o.crl = nullptr; return *this; }

    void pack(Blob& b) const;
    void unpack(const uint8_t* dat, size_t dat_size);
    Blob getPacked() const {
        Blob b;
        pack(b);
        return b;
    }

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b = getPacked();
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(const msgpack::object& o);

    void revoke(const Certificate& crt, time_point t = time_point::min());

    bool isRevoked(const Certificate& crt) const;

    /**
     * Sign this revocation list using provided key and certificate.
     * Validity_period sets the duration until next update (default to no next update).
     */
    void sign(const PrivateKey&, const Certificate&, duration validity_period = {});
    void sign(const Identity& id) { sign(*id.first, *id.second); }

    bool isSignedBy(const Certificate& issuer) const;

    std::string toString() const;

    /**
     * Read the CRL number extension field.
     */
    Blob getNumber() const;

    /** Read CRL issuer Common Name (CN) */
    std::string getIssuerName() const;

    /** Read CRL issuer User ID (UID) */
    std::string getIssuerUID() const;

    time_point getUpdateTime() const;
    time_point getNextUpdateTime() const;

    gnutls_x509_crl_t get() { return crl; }
    gnutls_x509_crl_t getCopy() const {
        if (not crl)
            return nullptr;
        auto copy = RevocationList(getPacked());
        gnutls_x509_crl_t ret = copy.crl;
        copy.crl = nullptr;
        return ret;
    }

private:
    gnutls_x509_crl_t crl {};
    RevocationList(const RevocationList&) = delete;
    RevocationList& operator=(const RevocationList&) = delete;
};
#endif  // Disabled RevocationList

#if 0  // Disable NameType, CertificateRequest, OcspRequest, OcspResponse - not needed for Dilithium5
enum class NameType { UNKNOWN = 0, RFC822, DNS, URI, IP };

class OPENDHT_PUBLIC CertificateRequest {
public:
    CertificateRequest();
    CertificateRequest(const uint8_t* data, size_t size);
    CertificateRequest(std::string_view src) : CertificateRequest((const uint8_t*)src.data(), src.size()) {}
    CertificateRequest(const Blob& data) : CertificateRequest(data.data(), data.size()) {}

    CertificateRequest(CertificateRequest&& o) noexcept : request(std::move(o.request)) {
        o.request = nullptr;
    }
    CertificateRequest& operator=(CertificateRequest&& o) noexcept;

    ~CertificateRequest();

    void setName(const std::string& name);
    void setUID(const std::string& name);
    void setAltName(NameType type, const std::string& name);

    std::string getName() const;
    std::string getUID() const;

    void sign(const PrivateKey& key, const std::string& password = {});

    bool verify() const;

    Blob pack() const;
    std::string toString() const;

    gnutls_x509_crq_t get() const { return request; }
private:
    CertificateRequest(const CertificateRequest& o) = delete;
    CertificateRequest& operator=(const CertificateRequest& o) = delete;
    gnutls_x509_crq_t request {nullptr};
};

class OPENDHT_PUBLIC OcspRequest
{
public:
    OcspRequest(gnutls_ocsp_req_t r) : request(r) {}
    OcspRequest(const uint8_t* dat_ptr, size_t dat_size);
    OcspRequest(std::string_view dat): OcspRequest((const uint8_t*)dat.data(), dat.size()) {}
    ~OcspRequest();

    /*
     * Get OCSP Request in readable format.
     */
    std::string toString(const bool compact = true) const;

    Blob pack() const;
    Blob getNonce() const;
private:
    gnutls_ocsp_req_t request;
};

class OPENDHT_PUBLIC OcspResponse
{
public:
    OcspResponse(const uint8_t* dat_ptr, size_t dat_size);
    OcspResponse(std::string_view response) : OcspResponse((const uint8_t*)response.data(), response.size()) {}
    ~OcspResponse();

    Blob pack() const;
    /*
     * Get OCSP Response in readable format.
     */
    std::string toString(const bool compact = true) const;

    /*
     * Get OCSP response certificate status.
     * Return certificate status.
     * http://www.gnu.org/software/gnutls/reference/gnutls-ocsp.html#gnutls-ocsp-cert-status-t
     */
    gnutls_ocsp_cert_status_t getCertificateStatus() const;

    /*
     * Verify OCSP response and return OCSP status.
     * Throws CryptoException in case of error in the response.
     * http://www.gnu.org/software/gnutls/reference/gnutls-ocsp.html#gnutls-ocsp-verify-reason-t
     */
    gnutls_ocsp_cert_status_t verifyDirect(const Certificate& crt, const Blob& nonce);

private:
    gnutls_ocsp_resp_t response;
};
#endif  // Disabled NameType, CertificateRequest, OcspRequest, OcspResponse

/**
 * A certificate - Simplified wrapper for Dilithium5 public key
 * No X.509 complexity, just a Dilithium5 pubkey with optional metadata
 * FIPS 204 compliant
 */
struct OPENDHT_PUBLIC Certificate {
    Certificate() noexcept {}

    /**
     * Create certificate from Dilithium5 public key
     */
    Certificate(const PublicKey& pk);
    
    Certificate(Certificate&& o) noexcept;
    Certificate& operator=(Certificate&& o) noexcept;

    /**
     * Import certificate from serialized data (msgpack format)
     */
    Certificate(const uint8_t* dat, size_t dat_size);
    Certificate(const Blob& crt) : Certificate(crt.data(), crt.size()) {}
    Certificate(std::string_view crt) : Certificate((const uint8_t*)crt.data(), crt.size()) {}

    ~Certificate();

    explicit operator bool() const { return publicKey_ && *publicKey_; }

    const PublicKey& getPublicKey() const;
    const std::shared_ptr<PublicKey>& getSharedPublicKey() const;

    /** Same as getPublicKey().getId() */
    const InfoHash& getId() const;
    /** Same as getPublicKey().getLongId() */
    const PkId& getLongId() const;

    /**
     * Get certificate name (optional, defaults to fingerprint)
     */
    std::string getName() const;
    void setName(const std::string& name);

    /**
     * Get issuer name (optional, "self-signed" by default)
     */
    std::string getIssuerName() const;

    /**
     * Serialize certificate to msgpack format
     */
    void pack(Blob& b) const;
    void unpack(const uint8_t* dat, size_t dat_size);

    Blob getPacked() const {
        Blob b;
        pack(b);
        return b;
    }

    template <typename Packer>
    void msgpack_pack(Packer& p) const
    {
        Blob b;
        pack(b);
        p.pack_bin(b.size());
        p.pack_bin_body((const char*)b.data(), b.size());
    }

    void msgpack_unpack(const msgpack::object& o);

    std::string toString() const;

private:
    std::shared_ptr<PublicKey> publicKey_;
    std::string name_;            // Optional certificate name
    std::string issuer_;          // Issuer name (default: "self-signed")
    uint64_t not_before_ {0};     // Unix timestamp (optional)
    uint64_t not_after_ {0};      // Unix timestamp (optional)

    mutable InfoHash cachedId_ {};
    mutable PkId cachedLongId_ {};
    mutable std::atomic_bool idCached_ {false};
    mutable std::atomic_bool longIdCached_ {false};

    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;
};

#if 0  // Disable TrustList - X.509 trust chain not needed for Dilithium5 DHT
struct OPENDHT_PUBLIC TrustList
{
    struct VerifyResult {
        int ret;
        unsigned result;
        bool hasError() const { return ret < 0; }
        bool isValid() const { return !hasError() and !(result & GNUTLS_CERT_INVALID); }
        explicit operator bool() const { return isValid(); }
        OPENDHT_PUBLIC std::string toString() const;
        OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const VerifyResult& h);
    };

    TrustList();
    TrustList(TrustList&& o) noexcept : trust(std::move(o.trust)) {
        o.trust = nullptr;
    }
    TrustList& operator=(TrustList&& o) noexcept;
    ~TrustList();
    void add(const Certificate& crt);
    void add(const RevocationList& crl);
    void remove(const Certificate& crt, bool parents = true);
    VerifyResult verify(const Certificate& crt) const;

private:
    TrustList(const TrustList& o) = delete;
    TrustList& operator=(const TrustList& o) = delete;
    gnutls_x509_trust_list_t trust {nullptr};
};
#endif  // Disabled TrustList

#if 0  // Disable old RSA identity generation - will use Dilithium5 instead
/**
 * Generate an RSA key pair (4096 bits) and a certificate.
 * @param name the name used in the generated certificate
 * @param ca if set, the certificate authority that will sign the generated certificate.
 *           If not set, the generated certificate will be a self-signed CA.
 * @param key_length stength of the generated private key (bits).
 */
OPENDHT_PUBLIC Identity generateIdentity(const std::string& name, const Identity& ca, unsigned key_length, bool is_ca);
OPENDHT_PUBLIC Identity generateIdentity(const std::string& name = "dhtnode", const Identity& ca = {}, unsigned key_length = 4096);

OPENDHT_PUBLIC Identity generateEcIdentity(const std::string& name, const Identity& ca, bool is_ca);
OPENDHT_PUBLIC Identity generateEcIdentity(const std::string& name = "dhtnode", const Identity& ca = {});

OPENDHT_PUBLIC void saveIdentity(const Identity& id, const std::string& path, const std::string& privkey_password = {});
OPENDHT_PUBLIC Identity loadIdentity(const std::string &path,const std::string &privkey_password = {});
#endif  // Disabled old RSA identity generation

// NEW: Dilithium5 identity generation functions
OPENDHT_PUBLIC Identity generateDilithiumIdentity(const std::string& name = "dhtnode");
OPENDHT_PUBLIC void saveDilithiumIdentity(const Identity& id, const std::string& path);
OPENDHT_PUBLIC Identity loadDilithiumIdentity(const std::string& path);

/**
 * Performs SHA512, SHA256 or SHA1, depending on hash_length.
 * Attempts to choose an hash function with
 * output size of at least hash_length bytes, Current implementation
 * will use SHA1 for hash_length up to 20 bytes,
 * will use SHA256 for hash_length up to 32 bytes,
 * will use SHA512 for hash_length of 33 bytes and more.
 */
OPENDHT_PUBLIC Blob hash(const Blob& data, size_t hash_length = 512/8);

OPENDHT_PUBLIC void hash(const uint8_t* data, size_t data_length, uint8_t* hash, size_t hash_length);

/**
 * Generates an encryption key from a text password,
 * making the key longer to bruteforce.
 * The generated key also depends on a unique salt value of any size,
 * that can be transmitted in clear, and will be generated if
 * not provided (32 bytes).
 */
OPENDHT_PUBLIC Blob stretchKey(std::string_view password, Blob& salt, size_t key_length = 512/8);

/**
 * AES-GCM encryption. Key must be 128, 192 or 256 bits long (16, 24 or 32 bytes).
 */
OPENDHT_PUBLIC Blob aesEncrypt(const uint8_t* data, size_t data_length, const Blob& key);
OPENDHT_PUBLIC inline Blob aesEncrypt(const Blob& data, const Blob& key) {
    return aesEncrypt(data.data(), data.size(), key);
}
/**
 * AES-GCM encryption with argon2 key derivation.
 * This function uses `stretchKey` to generate an AES key from the password and a random salt.
 * The result is a bundle including the salt that can be decrypted with `aesDecrypt(data, password)`.
 * If needed, the salt or encrypted data can be individually extracted from the bundle with `aesGetSalt` and `aesGetEncrypted`.
 * @param data: data to encrypt
 * @param password: password to encrypt the data with
 * @param salt: optional salt to use for key derivation. If not provided, a random salt will be generated.
 */
OPENDHT_PUBLIC Blob aesEncrypt(const Blob& data, std::string_view password, const Blob& salt = {});

/**
 * AES-GCM decryption.
 */
OPENDHT_PUBLIC Blob aesDecrypt(const uint8_t* data, size_t data_length, const Blob& key);
OPENDHT_PUBLIC inline Blob aesDecrypt(const Blob& data, const Blob& key) { return aesDecrypt(data.data(), data.size(), key); }
OPENDHT_PUBLIC inline Blob aesDecrypt(std::string_view data, const Blob& key) { return aesDecrypt((uint8_t*)data.data(), data.size(), key); }

OPENDHT_PUBLIC Blob aesDecrypt(const uint8_t* data, size_t data_length, std::string_view password);
OPENDHT_PUBLIC inline Blob aesDecrypt(const Blob& data, std::string_view password) { return aesDecrypt(data.data(), data.size(), password); }
OPENDHT_PUBLIC inline Blob aesDecrypt(std::string_view data, std::string_view password) { return aesDecrypt((uint8_t*)data.data(), data.size(), password); }

/**
 * Get raw AES key from password and salt stored with the encrypted data.
 */
OPENDHT_PUBLIC Blob aesGetKey(const uint8_t* data, size_t data_length, std::string_view password);
OPENDHT_PUBLIC Blob inline aesGetKey(const Blob& data, std::string_view password) {
    return aesGetKey(data.data(), data.size(), password);
}
/** Get the salt part of data password-encrypted with `aesEncrypt(data, password)` */
OPENDHT_PUBLIC Blob aesGetSalt(const uint8_t* data, size_t data_length);
OPENDHT_PUBLIC Blob inline aesGetSalt(const Blob& data) {
    return aesGetSalt(data.data(), data.size());
}
/** Get the encrypted data (ciphertext) part of data password-encrypted with `aesEncrypt(data, password)` */
OPENDHT_PUBLIC std::string_view aesGetEncrypted(const uint8_t* data, size_t data_length);
OPENDHT_PUBLIC std::string_view inline aesGetEncrypted(const Blob& data) {
    return aesGetEncrypted(data.data(), data.size());
}

/** Build an encrypted bundle that can be decrypted with aesDecrypt(data, password).
 *  @param encryptedData: result of `aesEncrypt(data, key)` or `aesGetEncrypted`
 *  @param salt: should match the encryption key and password so that `stretchKey(password, salk) == key`.
 *  Can be obtained from an existing bundle with `aesGetSalt`.
 **/
OPENDHT_PUBLIC Blob aesBuildEncrypted(const uint8_t* encryptedData, size_t data_length, const Blob& salt);
OPENDHT_PUBLIC Blob inline aesBuildEncrypted(const Blob& encryptedData, const Blob& salt) {
    return aesBuildEncrypted(encryptedData.data(), encryptedData.size(), salt);
}
OPENDHT_PUBLIC Blob inline aesBuildEncrypted(std::string_view encryptedData, const Blob& salt) {
    return aesBuildEncrypted((const uint8_t*)encryptedData.data(), encryptedData.size(), salt);
}

}
}
