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

#include "crypto.h"
#include "rng.h"

// DILITHIUM5 INTEGRATION: Post-quantum signatures (FIPS 204 / ML-DSA-87)
extern "C" {
#include "api.h"  // Dilithium5 API from DNA Messenger crypto/dsa/

// Keep AES and hashing - still needed for encryption
#include <nettle/gcm.h>
#include <nettle/aes.h>

#include <argon2.h>

// GnuTLS - keep minimal subset for hashing/utility functions
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
}

#include <random>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <cassert>

#ifdef _WIN32
static std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
static std::uniform_int_distribution<uint8_t> rand_byte;
#endif

namespace dht {
namespace crypto {

static constexpr std::array<size_t, 3> AES_LENGTHS {{128/8, 192/8, 256/8}};
static constexpr size_t PASSWORD_SALT_LENGTH {16};

constexpr gnutls_digest_algorithm_t gnutlsHashAlgo(size_t min_res) {
    return (min_res > 256/8) ? GNUTLS_DIG_SHA512 : (
           (min_res > 160/8) ? GNUTLS_DIG_SHA256 : (
                               GNUTLS_DIG_SHA1));
}

constexpr size_t gnutlsHashSize(gnutls_digest_algorithm_t algo) {
    return (algo == GNUTLS_DIG_SHA512) ? 512/8 : (
           (algo == GNUTLS_DIG_SHA256) ? 256/8 : (
           (algo == GNUTLS_DIG_SHA1)   ? 160/8 : 0 ));
}

size_t aesKeySize(size_t max)
{
    size_t aes_key_len = 0;
    for (size_t s : AES_LENGTHS) {
        if (s <= max) aes_key_len = s;
        else break;
    }
    return aes_key_len;
}

bool aesKeySizeGood(size_t key_size)
{
    for (auto& i : AES_LENGTHS)
        if (key_size == i)
            return true;
    return false;
}

#if 0  // REMOVED: Spki class - GnuTLS X.509 specific
class Spki {
public:
    Spki() {
        gnutls_x509_spki_init(&spki);
    }
    Spki(gnutls_pubkey_t pubkey): Spki() {
        auto err = gnutls_pubkey_get_spki(pubkey, spki, 0);
        if (err < 0) {
            gnutls_x509_spki_deinit(spki);
            throw CryptoException(fmt::format("Unable to get SPKI from public key: {}", gnutls_strerror(err)));
        }
    }

    ~Spki() {
        gnutls_x509_spki_deinit(spki);
    }

    inline gnutls_x509_spki_t& get() {
        return spki;
    }

private:
    gnutls_x509_spki_t spki;
};
#endif  // Disabled Spki class

#ifndef GCM_DIGEST_SIZE
#define GCM_DIGEST_SIZE GCM_BLOCK_SIZE
#endif

Blob aesEncrypt(const uint8_t* data, size_t data_length, const Blob& key)
{
    if (not aesKeySizeGood(key.size()))
        throw DecryptError("Incorrect key size");

    Blob ret(data_length + GCM_IV_SIZE + GCM_DIGEST_SIZE);
    {
        std::random_device rdev;
        std::generate_n(ret.begin(), GCM_IV_SIZE, std::bind(rand_byte, std::ref(rdev)));
    }

    if (key.size() == AES_LENGTHS[0]) {
        struct gcm_aes128_ctx aes;
        gcm_aes128_set_key(&aes, key.data());
        gcm_aes128_set_iv(&aes, GCM_IV_SIZE, ret.data());
        gcm_aes128_encrypt(&aes, data_length, ret.data() + GCM_IV_SIZE, data);
        gcm_aes128_digest(&aes, GCM_DIGEST_SIZE, ret.data() + GCM_IV_SIZE + data_length);
    } else if (key.size() == AES_LENGTHS[1]) {
        struct gcm_aes192_ctx aes;
        gcm_aes192_set_key(&aes, key.data());
        gcm_aes192_set_iv(&aes, GCM_IV_SIZE, ret.data());
        gcm_aes192_encrypt(&aes, data_length, ret.data() + GCM_IV_SIZE, data);
        gcm_aes192_digest(&aes, GCM_DIGEST_SIZE, ret.data() + GCM_IV_SIZE + data_length);
    } else if (key.size() == AES_LENGTHS[2]) {
        struct gcm_aes256_ctx aes;
        gcm_aes256_set_key(&aes, key.data());
        gcm_aes256_set_iv(&aes, GCM_IV_SIZE, ret.data());
        gcm_aes256_encrypt(&aes, data_length, ret.data() + GCM_IV_SIZE, data);
        gcm_aes256_digest(&aes, GCM_DIGEST_SIZE, ret.data() + GCM_IV_SIZE + data_length);
    }

    return ret;
}

Blob aesEncrypt(const Blob& data, std::string_view password, const Blob& salt)
{
    Blob salt_actual = salt;
    Blob key = stretchKey(password, salt_actual, 256 / 8);
    return aesBuildEncrypted(aesEncrypt(data, key), salt_actual);
}

Blob aesDecrypt(const uint8_t* data, size_t data_length, const Blob& key)
{
    if (not aesKeySizeGood(key.size()))
        throw DecryptError("Incorrect key size");

    if (data_length <= GCM_IV_SIZE + GCM_DIGEST_SIZE)
        throw DecryptError("Incorrect data size");

    std::array<uint8_t, GCM_DIGEST_SIZE> digest;

    size_t data_sz = data_length - GCM_IV_SIZE - GCM_DIGEST_SIZE;
    Blob ret(data_sz);

    if (key.size() == AES_LENGTHS[0]) {
        struct gcm_aes128_ctx aes;
        gcm_aes128_set_key(&aes, key.data());
        gcm_aes128_set_iv(&aes, GCM_IV_SIZE, data);
        gcm_aes128_decrypt(&aes, data_sz, ret.data(), data + GCM_IV_SIZE);
        gcm_aes128_digest(&aes, GCM_DIGEST_SIZE, digest.data());
    } else if (key.size() == AES_LENGTHS[1]) {
        struct gcm_aes192_ctx aes;
        gcm_aes192_set_key(&aes, key.data());
        gcm_aes192_set_iv(&aes, GCM_IV_SIZE, data);
        gcm_aes192_decrypt(&aes, data_sz, ret.data(), data + GCM_IV_SIZE);
        gcm_aes192_digest(&aes, GCM_DIGEST_SIZE, digest.data());
    } else if (key.size() == AES_LENGTHS[2]) {
        struct gcm_aes256_ctx aes;
        gcm_aes256_set_key(&aes, key.data());
        gcm_aes256_set_iv(&aes, GCM_IV_SIZE, data);
        gcm_aes256_decrypt(&aes, data_sz, ret.data(), data + GCM_IV_SIZE);
        gcm_aes256_digest(&aes, GCM_DIGEST_SIZE, digest.data());
    }

    if (not std::equal(digest.begin(), digest.end(), data + data_length - GCM_DIGEST_SIZE)) {
        throw DecryptError("Unable to decrypt data");
    }

    return ret;
}

Blob aesDecrypt(const uint8_t* data, size_t data_length, std::string_view password)
{
    return aesDecrypt(
        aesGetEncrypted(data, data_length),
        aesGetKey(data, data_length, password)
    );
}

Blob aesGetSalt(const uint8_t* data, size_t data_length)
{
    if (data_length <= PASSWORD_SALT_LENGTH)
        throw DecryptError("Incorrect data size");
    return Blob {data, data+PASSWORD_SALT_LENGTH};
}

std::string_view aesGetEncrypted(const uint8_t* data, size_t data_length)
{
    if (data_length <= PASSWORD_SALT_LENGTH)
        throw DecryptError("Incorrect data size");
    return std::string_view((const char*)(data+PASSWORD_SALT_LENGTH), data_length - PASSWORD_SALT_LENGTH);
}

Blob aesBuildEncrypted(const uint8_t* data, size_t data_length, const Blob& salt)
{
    Blob ret;
    ret.reserve(data_length + salt.size());
    ret.insert(ret.end(), salt.begin(), salt.end());
    ret.insert(ret.end(), data, data + data_length);
    return ret;
}

Blob aesGetKey(const uint8_t* data, size_t data_length, std::string_view password)
{
    Blob salt = aesGetSalt(data, data_length);
    return stretchKey(password, salt, 256/8);
}

Blob stretchKey(std::string_view password, Blob& salt, size_t key_length)
{
    if (salt.empty()) {
        salt.resize(PASSWORD_SALT_LENGTH);
        std::random_device rdev;
        std::generate_n(salt.begin(), salt.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    Blob res;
    res.resize(32);
    auto ret = argon2i_hash_raw(16, 64*1024, 1, password.data(), password.size(), salt.data(), salt.size(), res.data(), res.size());
    if (ret != ARGON2_OK)
        throw CryptoException("Unable to compute Argon2i.");
    return hash(res, key_length);
}

Blob hash(const Blob& data, size_t hash_len)
{
    auto algo = gnutlsHashAlgo(hash_len);
    size_t res_size = gnutlsHashSize(algo);
    Blob res;
    res.resize(res_size);
    const gnutls_datum_t gdat {(uint8_t*)data.data(), (unsigned)data.size()};
    if (auto err = gnutls_fingerprint(algo, &gdat, res.data(), &res_size))
        throw CryptoException(std::string("Unable to compute hash: ") + gnutls_strerror(err));
    res.resize(std::min(hash_len, res_size));
    return res;
}

void hash(const uint8_t* data, size_t data_length, uint8_t* hash, size_t hash_length)
{
    auto algo = gnutlsHashAlgo(hash_length);
    size_t res_size = hash_length;
    const gnutls_datum_t gdat {(uint8_t*)data, (unsigned)data_length};
    if (auto err = gnutls_fingerprint(algo, &gdat, hash, &res_size))
        throw CryptoException(std::string("Unable to compute hash: ") + gnutls_strerror(err));
}

// DILITHIUM5: Default constructor - creates invalid/empty private key
PrivateKey::PrivateKey()
    : valid_(false)
{
    std::memset(dilithium_sk_, 0, pqcrystals_dilithium5_SECRETKEYBYTES);
}

// DILITHIUM5: Constructor from raw bytes (4896 bytes)
PrivateKey::PrivateKey(const uint8_t* src, size_t src_size, const char* /* password_ptr */)
    : PrivateKey()
{
    // Password parameter unused (Dilithium5 keys are raw binary)
    // TODO: Add password-based encryption if needed
    if (src_size != pqcrystals_dilithium5_SECRETKEYBYTES)
        throw CryptoException(fmt::format(
            "Invalid Dilithium5 secret key size: expected {} bytes, got {} bytes",
            pqcrystals_dilithium5_SECRETKEYBYTES, src_size));

    std::memcpy(dilithium_sk_, src, pqcrystals_dilithium5_SECRETKEYBYTES);
    valid_ = true;

    // Extract public key from secret key
    // Dilithium5 secret key contains the public key at a specific offset
    // TODO: Verify offset in Dilithium5 spec
    publicKey_ = std::make_shared<PublicKey>(dilithium_sk_ + pqcrystals_dilithium5_SECRETKEYBYTES - pqcrystals_dilithium5_PUBLICKEYBYTES,
                                               pqcrystals_dilithium5_PUBLICKEYBYTES);
}

// DILITHIUM5: Move constructor
PrivateKey::PrivateKey(PrivateKey&& o) noexcept
    : valid_(o.valid_)
    , publicKey_(std::move(o.publicKey_))
{
    std::memcpy(dilithium_sk_, o.dilithium_sk_, pqcrystals_dilithium5_SECRETKEYBYTES);
    o.valid_ = false;
}

// DILITHIUM5: Destructor - securely zero out secret key
PrivateKey::~PrivateKey()
{
    std::memset(dilithium_sk_, 0, pqcrystals_dilithium5_SECRETKEYBYTES);
}

// DILITHIUM5: Move assignment operator
PrivateKey&
PrivateKey::operator=(PrivateKey&& o) noexcept
{
    if (this != &o) {
        std::memcpy(dilithium_sk_, o.dilithium_sk_, pqcrystals_dilithium5_SECRETKEYBYTES);
        valid_ = o.valid_;
        publicKey_ = std::move(o.publicKey_);
        o.valid_ = false;
    }
    return *this;
}

// DILITHIUM5: Sign data with post-quantum signature (FIPS 204 / ML-DSA-87)
Blob
PrivateKey::sign(const uint8_t* data, size_t data_length) const
{
    if (!valid_)
        throw CryptoException("Unable to sign data: invalid private key");

    // Dilithium5 signatures are exactly 4627 bytes
    Blob signature(pqcrystals_dilithium5_BYTES);
    size_t sig_len = pqcrystals_dilithium5_BYTES;

    // Sign using Dilithium5 reference implementation
    int result = pqcrystals_dilithium5_ref_signature(
        signature.data(), &sig_len,  // Output signature
        data, data_length,            // Message to sign
        nullptr, 0,                   // Context (not used)
        dilithium_sk_                 // Secret key
    );

    if (result != 0)
        throw CryptoException("Dilithium5 signing failed");

    signature.resize(sig_len);
    return signature;
}

#if 0  // REMOVED: Dilithium5 is signature-only (no decryption support)
Blob
PrivateKey::decryptBloc(const uint8_t* src, size_t src_size) const
{
    const gnutls_datum_t dat {(uint8_t*)src, (unsigned)src_size};
    gnutls_datum_t out {nullptr, 0};
    int err = gnutls_privkey_decrypt_data(key, 0, &dat, &out);
    if (err != GNUTLS_E_SUCCESS)
        throw DecryptError(std::string("Unable to decrypt data: ") + gnutls_strerror(err));
    Blob ret {out.data, out.data+out.size};
    gnutls_free(out.data);
    return ret;
}

Blob
PrivateKey::decrypt(const uint8_t* cypher, size_t cypher_len) const
{
    if (!key)
        throw CryptoException("Unable to decrypt data without private key.");

    unsigned key_len = 0;
    int algo = gnutls_privkey_get_pk_algorithm(key, &key_len);
    if (algo < 0)
        throw CryptoException("Unable to read public key length.");
    if (algo != GNUTLS_PK_RSA
#if GNUTLS_VERSION_NUMBER >= 0x030804
         && algo != GNUTLS_PK_RSA_OAEP
#endif
    )
        throw CryptoException("Must be an RSA key");

    unsigned cypher_block_sz = key_len / 8;
    if (cypher_len < cypher_block_sz)
        throw DecryptError("Unexpected cipher length");
    else if (cypher_len == cypher_block_sz)
        return decryptBloc(cypher, cypher_block_sz);

    return aesDecrypt(cypher + cypher_block_sz, cypher_len - cypher_block_sz, decryptBloc(cypher, cypher_block_sz));
}
#endif  // Disabled decryption methods

// DILITHIUM5: Serialize secret key to binary blob (4896 bytes)
Blob
PrivateKey::serialize(const std::string& /* password */) const
{
    if (!valid_)
        return {};

    // Password parameter unused - TODO: Add password-based encryption if needed
    // For now, just return raw binary
    Blob buffer(dilithium_sk_, dilithium_sk_ + pqcrystals_dilithium5_SECRETKEYBYTES);
    return buffer;
}

// DILITHIUM5: Serialize to raw buffer
int
PrivateKey::serialize(uint8_t* out, size_t* out_len, const std::string& /* password */) const
{
    if (!valid_)
        return -1;

    if (*out_len < pqcrystals_dilithium5_SECRETKEYBYTES)
        return -2;  // Buffer too small

    // TODO: Add password-based encryption if needed
    std::memcpy(out, dilithium_sk_, pqcrystals_dilithium5_SECRETKEYBYTES);
    *out_len = pqcrystals_dilithium5_SECRETKEYBYTES;
    return 0;  // Success
}

// DILITHIUM5: Get public key reference
const PublicKey&
PrivateKey::getPublicKey() const
{
    return *getSharedPublicKey();
}

// DILITHIUM5: Get shared public key (cached)
const std::shared_ptr<PublicKey>&
PrivateKey::getSharedPublicKey() const
{
    if (not publicKey_)
        throw CryptoException("PrivateKey: public key cache not set (call setPublicKeyCache after loading)");
    return publicKey_;
}

// DILITHIUM5: Set cached public key (used when loading from file)
void
PrivateKey::setPublicKeyCache(std::shared_ptr<PublicKey> pk)
{
    std::lock_guard<std::mutex> lock(publicKeyMutex_);
    publicKey_ = std::move(pk);
}

// DILITHIUM5: Default constructor - creates invalid/empty public key
PublicKey::PublicKey()
    : valid_(false)
{
    std::memset(dilithium_pk_, 0, pqcrystals_dilithium5_PUBLICKEYBYTES);
}

// DILITHIUM5: Constructor from raw bytes (2592 bytes)
PublicKey::PublicKey(const uint8_t* dat, size_t dat_size)
    : PublicKey()
{
    unpack(dat, dat_size);
}

// DILITHIUM5: Move constructor
PublicKey::PublicKey(PublicKey&& o) noexcept
    : valid_(o.valid_)
    , cachedId_(o.cachedId_)
    , cachedLongId_(o.cachedLongId_)
    , idCached_(o.idCached_.load())
    , longIdCached_(o.longIdCached_.load())
{
    std::memcpy(dilithium_pk_, o.dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES);
    o.valid_ = false;
}

// DILITHIUM5: Destructor - no GnuTLS cleanup needed
PublicKey::~PublicKey()
{
    // Securely zero out the public key
    std::memset(dilithium_pk_, 0, pqcrystals_dilithium5_PUBLICKEYBYTES);
}

// DILITHIUM5: Move assignment operator
PublicKey&
PublicKey::operator=(PublicKey&& o) noexcept
{
    if (this != &o) {
        std::memcpy(dilithium_pk_, o.dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES);
        valid_ = o.valid_;
        cachedId_ = o.cachedId_;
        cachedLongId_ = o.cachedLongId_;
        idCached_ = o.idCached_.load();
        longIdCached_ = o.longIdCached_.load();
        o.valid_ = false;
    }
    return *this;
}

// DILITHIUM5: Serialize public key to binary blob (2592 bytes)
void
PublicKey::pack(Blob& b) const
{
    if (!valid_)
        throw CryptoException("Could not export public key: invalid key");

    // Dilithium5 public keys are exactly 2592 bytes
    b.insert(b.end(), dilithium_pk_, dilithium_pk_ + pqcrystals_dilithium5_PUBLICKEYBYTES);
}

// DILITHIUM5: Serialize to raw buffer
int
PublicKey::pack(uint8_t* out, size_t* out_len) const
{
    if (!valid_)
        return -1;  // Error

    if (*out_len < pqcrystals_dilithium5_PUBLICKEYBYTES)
        return -2;  // Buffer too small

    std::memcpy(out, dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES);
    *out_len = pqcrystals_dilithium5_PUBLICKEYBYTES;
    return 0;  // Success
}

// DILITHIUM5: Deserialize from raw bytes (must be exactly 2592 bytes)
void
PublicKey::unpack(const uint8_t* data, size_t data_size)
{
    if (data_size != pqcrystals_dilithium5_PUBLICKEYBYTES)
        throw CryptoException(fmt::format(
            "Invalid Dilithium5 public key size: expected {} bytes, got {} bytes",
            pqcrystals_dilithium5_PUBLICKEYBYTES, data_size));

    std::memcpy(dilithium_pk_, data, pqcrystals_dilithium5_PUBLICKEYBYTES);
    valid_ = true;

    // Invalidate cached fingerprints
    idCached_ = false;
    longIdCached_ = false;
}

// DILITHIUM5: toString - return hex representation of fingerprint
std::string
PublicKey::toString() const
{
    return getId().toString();
}

#if 0  // OLD: GnuTLS PEM export
std::string
PublicKey::toString() const
{
    if (not pk)
        throw CryptoException(std::string("Could not print public key: null key"));
    std::string ret;
    size_t sz = ret.size();
    int err = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_PEM, (void*)ret.data(), &sz);
    if (err ==  GNUTLS_E_SHORT_MEMORY_BUFFER) {
        ret.resize(sz);
        err = gnutls_pubkey_export(pk, GNUTLS_X509_FMT_PEM, (void*)ret.data(), &sz);
    }
    if (err != GNUTLS_E_SUCCESS)
        throw CryptoException(std::string("Could not print public key: ") + gnutls_strerror(err));
    return ret;
}
#endif

void
PublicKey::msgpack_unpack(const msgpack::object& o)
{
    if (o.type == msgpack::type::BIN)
        unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
    else {
        Blob dat = unpackBlob(o);
        unpack(dat.data(), dat.size());
    }
}

// DILITHIUM5: Verify post-quantum signature (FIPS 204 / ML-DSA-87)
bool PublicKey::checkSignature(const uint8_t* data, size_t data_len, const uint8_t* signature, size_t signature_len) const
{
    if (!valid_)
        return false;

    // Dilithium5 signatures are exactly 4627 bytes
    if (signature_len != pqcrystals_dilithium5_BYTES)
        return false;

    // Verify using Dilithium5 reference implementation
    // Returns 0 on success, -1 on failure
    int result = pqcrystals_dilithium5_ref_verify(
        signature, signature_len,  // Signature
        data, data_len,             // Message
        nullptr, 0,                 // Context (not used)
        dilithium_pk_               // Public key
    );

    return result == 0;
}

#if 0  // REMOVED: Dilithium5 is signature-only (no encryption support)
void
PublicKey::encryptBloc(const uint8_t* src, size_t src_size, uint8_t* dst, size_t dst_size) const
{
    const gnutls_datum_t key_dat {(uint8_t*)src, (unsigned)src_size};
    gnutls_datum_t encrypted {nullptr, 0};
    auto err = gnutls_pubkey_encrypt_data(pk, 0, &key_dat, &encrypted);
    if (err != GNUTLS_E_SUCCESS)
        throw CryptoException(std::string("Unable to encrypt data: ") + gnutls_strerror(err));
    if (encrypted.size != dst_size)
        throw CryptoException("Unexpected cypherblock size");
    std::copy_n(encrypted.data, encrypted.size, dst);
    gnutls_free(encrypted.data);
}

Blob
PublicKey::encrypt(const uint8_t* data, size_t data_len) const
{
    if (!pk)
        throw CryptoException("Unable to read public key.");

    unsigned key_len = 0;
    int algo = gnutls_pubkey_get_pk_algorithm(pk, &key_len);
    if (algo < 0)
        throw CryptoException("Unable to read public key length.");
    unsigned max_block_sz = 0;
    
    if (algo == GNUTLS_PK_RSA) {
        max_block_sz = key_len / 8 - 11;
    }
#if GNUTLS_VERSION_NUMBER >= 0x030804
    else if (algo == GNUTLS_PK_RSA_OAEP) {
        Spki spki(pk);
        gnutls_digest_algorithm_t dig;
        gnutls_datum_t label = {nullptr, 0};
        if (gnutls_x509_spki_get_rsa_oaep_params(spki.get(), &dig, &label) < 0) {
            throw CryptoException("Unable to get OAEP params");
        }
        size_t hash_size = gnutlsHashSize(dig);
        if (hash_size == 0) {
            throw CryptoException("Invalid digest algorithm for OAEP: GNUTLS_DIG_UNKNOWN");
        }
        max_block_sz = key_len / 8 - 2 * hash_size - 2 - label.size;
    }
#endif
    else {
        throw CryptoException("Must be an RSA key");
    }
    
    const unsigned cypher_block_sz = key_len / 8;
    /* Use plain RSA if the data is small enough */
    if (data_len <= max_block_sz) {
        Blob ret(cypher_block_sz);
        encryptBloc(data, data_len, ret.data(), cypher_block_sz);
        return ret;
    }

    /* Otherwise use RSA+AES-GCM,
       using the max. AES key size that can fit
       in a single RSA packet () */
    unsigned aes_key_sz = aesKeySize(max_block_sz);
    if (aes_key_sz == 0)
        throw CryptoException("Key is not long enough for AES128");
    Blob key(aes_key_sz);
    {
        std::random_device rdev;
        std::generate_n(key.begin(), key.size(), std::bind(rand_byte, std::ref(rdev)));
    }
    auto data_encrypted = aesEncrypt(data, data_len, key);

    Blob ret;
    ret.reserve(cypher_block_sz + data_encrypted.size());

    ret.resize(cypher_block_sz);
    encryptBloc(key.data(), key.size(), ret.data(), cypher_block_sz);
    ret.insert(ret.end(), data_encrypted.begin(), data_encrypted.end());
    return ret;
}
#endif  // Disabled encryption methods

// DILITHIUM5: Get InfoHash (160-bit fingerprint) from public key
const InfoHash&
PublicKey::getId() const
{
    if (valid_ and not idCached_.load()) {
        // Hash the Dilithium5 public key to get 160-bit ID
        // Use hash() function which supports SHA-1 (160 bits)
        InfoHash id;
        hash(dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES,
             id.data(), id.size());
        cachedId_ = id;
        idCached_.store(true);
    }
    return cachedId_;
}

// DILITHIUM5: Get PkId (256-bit fingerprint) from public key
const PkId&
PublicKey::getLongId() const
{
    if (valid_ and not longIdCached_.load()) {
        // Hash the Dilithium5 public key to get 256-bit ID
        // Use hash() function which will use SHA-256 for 256-bit output
        PkId h;
        hash(dilithium_pk_, pqcrystals_dilithium5_PUBLICKEYBYTES,
             h.data(), h.size());
        cachedLongId_ = h;
        longIdCached_.store(true);
    }
    return cachedLongId_;
}

#if 0  // REMOVED: getPreferredDigest() - not needed for Dilithium5
gnutls_digest_algorithm_t
PublicKey::getPreferredDigest() const
{
    gnutls_digest_algorithm_t dig;
    int result = gnutls_pubkey_get_preferred_hash_algorithm(pk, &dig, nullptr);
    if (result < 0)
        return GNUTLS_DIG_UNKNOWN;
    return dig;
}
#endif  // REMOVED: getPreferredDigest()

// Certificate Request

#if 0  // REMOVED: NameType and CertificateRequest - not needed for Dilithium5
static NameType
typeFromGnuTLS(gnutls_x509_subject_alt_name_t type)
{
    switch(type) {
    case GNUTLS_SAN_DNSNAME:
        return NameType::DNS;
    case GNUTLS_SAN_RFC822NAME:
        return NameType::RFC822;
    case GNUTLS_SAN_URI:
        return NameType::URI;
    case GNUTLS_SAN_IPADDRESS:
        return NameType::IP;
    default:
        return NameType::UNKNOWN;
    }
}

static gnutls_x509_subject_alt_name_t
GnuTLSFromType(NameType type)
{
    switch(type) {
    case NameType::DNS:
        return GNUTLS_SAN_DNSNAME;
    case NameType::RFC822:
        return GNUTLS_SAN_RFC822NAME;
    case NameType::URI:
        return GNUTLS_SAN_URI;
    case NameType::IP:
        return GNUTLS_SAN_IPADDRESS;
    default:
        return (gnutls_x509_subject_alt_name_t)0;
    }
}

static std::string
readDN(gnutls_x509_crq_t request, const char* oid)
{
    std::string dn;
    dn.resize(512);
    size_t dn_sz = dn.size();
    int ret = gnutls_x509_crq_get_dn_by_oid(request, oid, 0, 0, &(*dn.begin()), &dn_sz);
    if (ret != GNUTLS_E_SUCCESS)
        return {};
    dn.resize(dn_sz);
    return dn;
}

CertificateRequest::CertificateRequest()
{
    if (auto err = gnutls_x509_crq_init(&request))
        throw CryptoException(std::string("Unable to initialize certificate request: ") + gnutls_strerror(err));
}

CertificateRequest::CertificateRequest(const uint8_t* data, size_t size) : CertificateRequest()
{
    const gnutls_datum_t dat {(uint8_t*)data, (unsigned)size};
    if (auto err = gnutls_x509_crq_import(request, &dat, GNUTLS_X509_FMT_PEM))
        throw CryptoException(std::string("Unable to import certificate request: ") + gnutls_strerror(err));
}

CertificateRequest::~CertificateRequest()
{
    if (request) {
        gnutls_x509_crq_deinit(request);
        request = nullptr;
    }
}

CertificateRequest&
CertificateRequest::operator=(CertificateRequest&& o) noexcept
{
    if (request)
        gnutls_x509_crq_deinit(request);
    request = o.request;
    o.request = nullptr;
    return *this;
}

void
CertificateRequest::setAltName(NameType type, const std::string& name)
{
    gnutls_x509_crq_set_subject_alt_name(request, GnuTLSFromType(type), name.data(), name.size(), 0);
}

void
CertificateRequest::setName(const std::string& name)
{
    gnutls_x509_crq_set_dn_by_oid(request, GNUTLS_OID_X520_COMMON_NAME, 0, name.data(), name.length());
}

std::string
CertificateRequest::getName() const
{
    return readDN(request, GNUTLS_OID_X520_COMMON_NAME);
}

std::string
CertificateRequest::getUID() const
{
    return readDN(request, GNUTLS_OID_LDAP_UID);
}

void
CertificateRequest::setUID(const std::string& uid)
{
    gnutls_x509_crq_set_dn_by_oid(request, GNUTLS_OID_LDAP_UID, 0, uid.data(), uid.length());
}

void
CertificateRequest::sign(const PrivateKey& key, const std::string& password)
{
    gnutls_x509_crq_set_version(request, 1);
    if (not password.empty())
        gnutls_x509_crq_set_challenge_password(request, password.c_str());

    if (auto err = gnutls_x509_crq_set_key(request,  key.x509_key))
        throw CryptoException(std::string("Unable to set certificate request key: ") + gnutls_strerror(err));

#if GNUTLS_VERSION_NUMBER < 0x030601
    if (auto err = gnutls_x509_crq_privkey_sign(request, key.key, key.getPublicKey().getPreferredDigest(), 0))
        throw CryptoException(std::string("Unable to sign certificate request: ") + gnutls_strerror(err));
#else
    if (auto err = gnutls_x509_crq_privkey_sign(request, key.key, GNUTLS_DIG_UNKNOWN, 0))
        throw CryptoException(std::string("Unable to sign certificate request: ") + gnutls_strerror(err));
#endif
}

bool
CertificateRequest::verify() const
{
    return gnutls_x509_crq_verify(request, 0) >= 0;
}

Blob
CertificateRequest::pack() const
{
    gnutls_datum_t dat {nullptr, 0};
    if (auto err = gnutls_x509_crq_export2(request, GNUTLS_X509_FMT_PEM, &dat))
        throw CryptoException(std::string("Unable to export certificate request: ") + gnutls_strerror(err));
    Blob ret(dat.data, dat.data + dat.size);
    gnutls_free(dat.data);
    return ret;
}

std::string
CertificateRequest::toString() const
{
    gnutls_datum_t dat {nullptr, 0};
    if (auto err = gnutls_x509_crq_export2(request, GNUTLS_X509_FMT_PEM, &dat))
        throw CryptoException(std::string("Unable to export certificate request: ") + gnutls_strerror(err));
    std::string ret(dat.data, dat.data + dat.size);
    gnutls_free(dat.data);
    return ret;
}
#endif  // REMOVED: NameType and CertificateRequest

// Certificate

// DILITHIUM5: New simplified Certificate implementations

// Constructor from PublicKey
Certificate::Certificate(const PublicKey& pk)
    : publicKey_(std::make_shared<PublicKey>(pk))
    , name_("dhtnode")
    , issuer_("self-signed")
    , not_before_(std::time(nullptr))
    , not_after_(std::time(nullptr) + (365 * 24 * 3600))  // 1 year validity
{
}

// Constructor from raw bytes (deserialize msgpack)
Certificate::Certificate(const uint8_t* dat, size_t dat_size)
{
    unpack(dat, dat_size);
}

// Move constructor
Certificate::Certificate(Certificate&& o) noexcept
    : publicKey_(std::move(o.publicKey_))
    , name_(std::move(o.name_))
    , issuer_(std::move(o.issuer_))
    , not_before_(o.not_before_)
    , not_after_(o.not_after_)
    , cachedId_(o.cachedId_)
    , cachedLongId_(o.cachedLongId_)
    , idCached_(o.idCached_.load())
    , longIdCached_(o.longIdCached_.load())
{
}

// Move assignment operator
Certificate&
Certificate::operator=(Certificate&& o) noexcept
{
    if (this != &o) {
        publicKey_ = std::move(o.publicKey_);
        name_ = std::move(o.name_);
        issuer_ = std::move(o.issuer_);
        not_before_ = o.not_before_;
        not_after_ = o.not_after_;
        cachedId_ = o.cachedId_;
        cachedLongId_ = o.cachedLongId_;
        idCached_ = o.idCached_.load();
        longIdCached_ = o.longIdCached_.load();
    }
    return *this;
}

// Destructor
Certificate::~Certificate()
{
}

// Get public key
const PublicKey&
Certificate::getPublicKey() const
{
    if (!publicKey_)
        throw CryptoException("Certificate has no public key");
    return *publicKey_;
}

const std::shared_ptr<PublicKey>&
Certificate::getSharedPublicKey() const
{
    return publicKey_;
}

// Get ID (delegated to public key)
const InfoHash&
Certificate::getId() const
{
    return getPublicKey().getId();
}

const PkId&
Certificate::getLongId() const
{
    return getPublicKey().getLongId();
}

// Get/set name
std::string
Certificate::getName() const
{
    return name_.empty() ? getId().toString() : name_;
}

void
Certificate::setName(const std::string& name)
{
    name_ = name;
}

// Get issuer
std::string
Certificate::getIssuerName() const
{
    return issuer_;
}

// Pack to msgpack
void
Certificate::pack(Blob& b) const
{
    msgpack::sbuffer buffer;
    msgpack::packer<msgpack::sbuffer> pk(buffer);

    pk.pack_map(5);

    // Pack public key
    pk.pack("pubkey");
    Blob pk_data;
    publicKey_->pack(pk_data);
    pk.pack_bin(pk_data.size());
    pk.pack_bin_body((const char*)pk_data.data(), pk_data.size());

    // Pack name
    pk.pack("name");
    pk.pack(name_);

    // Pack issuer
    pk.pack("issuer");
    pk.pack(issuer_);

    // Pack validity timestamps
    pk.pack("not_before");
    pk.pack(not_before_);

    pk.pack("not_after");
    pk.pack(not_after_);

    b.insert(b.end(), buffer.data(), buffer.data() + buffer.size());
}

// Unpack from msgpack
void
Certificate::unpack(const uint8_t* dat, size_t dat_size)
{
    try {
        msgpack::object_handle oh = msgpack::unpack((const char*)dat, dat_size);
        msgpack::object obj = oh.get();

        if (obj.type != msgpack::type::MAP)
            throw CryptoException("Certificate: expected msgpack map");

        auto map = obj.via.map;
        for (uint32_t i = 0; i < map.size; i++) {
            std::string key;
            map.ptr[i].key.convert(key);

            if (key == "pubkey") {
                if (map.ptr[i].val.type == msgpack::type::BIN) {
                    auto& bin = map.ptr[i].val.via.bin;
                    publicKey_ = std::make_shared<PublicKey>((const uint8_t*)bin.ptr, bin.size);
                }
            } else if (key == "name") {
                map.ptr[i].val.convert(name_);
            } else if (key == "issuer") {
                map.ptr[i].val.convert(issuer_);
            } else if (key == "not_before") {
                map.ptr[i].val.convert(not_before_);
            } else if (key == "not_after") {
                map.ptr[i].val.convert(not_after_);
            }
        }

        if (!publicKey_)
            throw CryptoException("Certificate: missing public key");

    } catch (const msgpack::type_error& e) {
        throw CryptoException(std::string("Certificate unpack error: ") + e.what());
    }
}

// Msgpack unpack
void
Certificate::msgpack_unpack(const msgpack::object& o)
{
    if (o.type == msgpack::type::BIN) {
        unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
    } else {
        Blob dat = unpackBlob(o);
        unpack(dat.data(), dat.size());
    }
}

// ToString
std::string
Certificate::toString() const
{
    return fmt::format("Certificate: {} ({})", getName(), getId().toString());
}

#if 0  // OLD X.509 Certificate implementations - disabled
static std::string
readDN(gnutls_x509_crt_t cert, bool issuer = false)
{
    gnutls_datum_t dn;
    int err = issuer
            ? gnutls_x509_crt_get_issuer_dn3(cert, &dn, 0)
            : gnutls_x509_crt_get_dn3(       cert, &dn, 0);
    if (err != GNUTLS_E_SUCCESS)
        return {};
    std::string ret((const char*)dn.data, dn.size);
    gnutls_free(dn.data);
    return ret;
}

static std::string
readDN(gnutls_x509_crt_t cert, const char* oid, bool issuer = false)
{
    std::string dn;
    dn.resize(512);
    size_t dn_sz = dn.size();
    int ret = issuer
            ? gnutls_x509_crt_get_issuer_dn_by_oid(cert, oid, 0, 0, &(*dn.begin()), &dn_sz)
            : gnutls_x509_crt_get_dn_by_oid(       cert, oid, 0, 0, &(*dn.begin()), &dn_sz);
    if (ret != GNUTLS_E_SUCCESS)
        return {};
    dn.resize(dn_sz);
    return dn;
}

Certificate::Certificate(const Blob& certData)
{
    unpack(certData.data(), certData.size());
}

Certificate&
Certificate::operator=(Certificate&& o) noexcept
{
    if (cert)
        gnutls_x509_crt_deinit(cert);
    cert = o.cert;
    o.cert = nullptr;
    issuer = std::move(o.issuer);
    return *this;
}

void
Certificate::unpack(const uint8_t* dat, size_t dat_size)
{
    if (cert) {
        gnutls_x509_crt_deinit(cert);
        cert = nullptr;
    }
    gnutls_x509_crt_t* cert_list;
    unsigned cert_num;
    const gnutls_datum_t crt_dt {(uint8_t*)dat, (unsigned)dat_size};
    int err = gnutls_x509_crt_list_import2(&cert_list, &cert_num, &crt_dt, GNUTLS_X509_FMT_PEM, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (err != GNUTLS_E_SUCCESS)
        err = gnutls_x509_crt_list_import2(&cert_list, &cert_num, &crt_dt, GNUTLS_X509_FMT_DER, GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED);
    if (err != GNUTLS_E_SUCCESS || cert_num == 0) {
        cert = nullptr;
        throw CryptoException(std::string("Could not read certificate - ") + gnutls_strerror(err));
    }

    cert = cert_list[0];
    Certificate* crt = this;
    size_t i = 1;
    while (crt and i < cert_num) {
        crt->issuer = std::make_shared<Certificate>(cert_list[i++]);
        crt = crt->issuer.get();
    }
    gnutls_free(cert_list);
}

void
Certificate::msgpack_unpack(const msgpack::object& o)
{
    if (o.type == msgpack::type::BIN)
        unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
    else {
        Blob dat = unpackBlob(o);
        unpack(dat.data(), dat.size());
    }
}

void
Certificate::pack(Blob& b) const
{
    const Certificate* crt = this;
    while (crt) {
        std::string str;
        size_t buf_sz = 8192;
        str.resize(buf_sz);
        if (int err = gnutls_x509_crt_export(crt->cert, GNUTLS_X509_FMT_PEM, &(*str.begin()), &buf_sz)) {
            std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
            return;
        }
        str.resize(buf_sz);
        b.insert(b.end(), str.begin(), str.end());
        crt = crt->issuer.get();
    }
}

Certificate::~Certificate()
{
    if (cert) {
        gnutls_x509_crt_deinit(cert);
        cert = nullptr;
    }
}

const PublicKey&
Certificate::getPublicKey() const
{
    return *getSharedPublicKey();
}

const std::shared_ptr<PublicKey>&
Certificate::getSharedPublicKey() const
{
    std::lock_guard<std::mutex> lock(publicKeyMutex_);
    if (not publicKey_) {
        auto pk = std::make_shared<PublicKey>();
        if (auto err = gnutls_pubkey_import_x509(pk->pk, cert, 0))
            throw CryptoException(std::string("Unable to get certificate public key: ") + gnutls_strerror(err));
        publicKey_ = std::move(pk);
    }
    return publicKey_;
}

const InfoHash&
Certificate::getId() const
{
    if (cert and not idCached_.load()) {
        InfoHash id;
        size_t sz = id.size();
        if (auto err = gnutls_x509_crt_get_key_id(cert, 0, id.data(), &sz))
            throw CryptoException(std::string("Unable to get certificate public key ID: ") + gnutls_strerror(err));
        if (sz != id.size())
            throw CryptoException("Unable to get certificate public key ID: incorrect output length.");
        cachedId_ = id;
        idCached_.store(true);
    }
    return cachedId_;
}

const PkId&
Certificate::getLongId() const
{
    if (cert and not longIdCached_.load()) {
        PkId id;
        size_t sz = id.size();
        if (auto err = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA256, id.data(), &sz))
            throw CryptoException(std::string("Unable to get certificate 256-bit public key ID: ") + gnutls_strerror(err));
        if (sz != id.size())
            throw CryptoException("Unable to get certificate 256-bit public key ID: incorrect output length.");
        cachedLongId_ = id;
        longIdCached_.store(true);
    }
    return cachedLongId_;
}

Blob
Certificate::getSerialNumber() const
{
    if (not cert)
        return {};
    // extract from certificate
    unsigned char serial[64];
    auto size = sizeof(serial);
    gnutls_x509_crt_get_serial(cert, &serial, &size);
    return {serial, serial + size};
}

std::string
Certificate::getDN() const
{
    return readDN(cert);
}

std::string
Certificate::getName() const
{
    return readDN(cert, GNUTLS_OID_X520_COMMON_NAME);
}

std::string
Certificate::getUID() const
{
    return readDN(cert, GNUTLS_OID_LDAP_UID);
}

std::string
Certificate::getIssuerDN() const
{
    return readDN(cert, true);
}

std::string
Certificate::getIssuerName() const
{
    return readDN(cert, GNUTLS_OID_X520_COMMON_NAME, true);
}

std::string
Certificate::getIssuerUID() const
{
    return readDN(cert, GNUTLS_OID_LDAP_UID, true);
}

std::vector<std::pair<NameType, std::string>>
Certificate::getAltNames() const
{
    std::vector<std::pair<NameType, std::string>> names;
    unsigned i = 0;
    std::string name;
    while (true) {
        name.resize(512);
        size_t name_sz = name.size();
        unsigned type;
        int ret = gnutls_x509_crt_get_subject_alt_name2(cert, i++, &(*name.begin()), &name_sz, &type, nullptr);
        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
            break;
        name.resize(name_sz);
        names.emplace_back(typeFromGnuTLS((gnutls_x509_subject_alt_name_t)type), name);
    }
    return names;
}

bool
Certificate::isCA() const
{
    unsigned critical;
    bool ca_flag = gnutls_x509_crt_get_ca_status(cert, &critical) > 0;
    if (ca_flag) {
        unsigned usage;
        auto ret = gnutls_x509_crt_get_key_usage(cert, &usage, &critical);
        /* Conforming CAs MUST include this extension in certificates that
           contain public keys that are used to validate digital signatures on
           other public key certificates or CRLs. */
        if (ret < 0)
            return false;
        if (not critical)
            return true;
        return usage & GNUTLS_KEY_KEY_CERT_SIGN;
    }
    return false;
}

std::string
Certificate::toString(bool chain) const
{
    std::ostringstream ss;
    const Certificate* crt = this;
    while (crt) {
        std::string str;
        size_t buf_sz = 8192;
        str.resize(buf_sz);
        if (int err = gnutls_x509_crt_export(crt->cert, GNUTLS_X509_FMT_PEM, &(*str.begin()), &buf_sz)) {
            std::cerr << "Could not export certificate - " << gnutls_strerror(err) << std::endl;
            return {};
        }
        str.resize(buf_sz);
        ss << str;
        if (not chain)
            break;
        crt = crt->issuer.get();
    }
    return ss.str();
}

std::string
Certificate::print() const
{
    gnutls_datum_t out {nullptr, 0};
    gnutls_x509_crt_print(cert, GNUTLS_CRT_PRINT_FULL, &out);
    std::string ret(out.data, out.data+out.size);
    gnutls_free(out.data);
    return ret;
}

void
Certificate::revoke(const PrivateKey& key, const Certificate& to_revoke)
{
    if (revocation_lists.empty())
        revocation_lists.emplace(std::make_shared<RevocationList>());
    auto& list = *(*revocation_lists.begin());
    list.revoke(to_revoke);
    list.sign(key, *this);
}

void
Certificate::addRevocationList(RevocationList&& list)
{
    addRevocationList(std::make_shared<RevocationList>(std::forward<RevocationList>(list)));
}

void
Certificate::addRevocationList(std::shared_ptr<RevocationList> list)
{
    if (revocation_lists.find(list) != revocation_lists.end())
        return; // Already in the list
    if (not list->isSignedBy(*this))
        throw CryptoException("CRL is not signed by this certificate");
    revocation_lists.emplace(std::move(list));
}

std::chrono::system_clock::time_point
Certificate::getActivation() const
{
    auto t = gnutls_x509_crt_get_activation_time(cert);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

std::chrono::system_clock::time_point
Certificate::getExpiration() const
{
    auto t = gnutls_x509_crt_get_expiration_time(cert);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

gnutls_digest_algorithm_t
Certificate::getPreferredDigest() const
{
    return getPublicKey().getPreferredDigest();
}

std::pair<std::string, Blob>
Certificate::generateOcspRequest(gnutls_x509_crt_t& issuer)
{
    gnutls_ocsp_req_t rreq;
    int err = gnutls_ocsp_req_init(&rreq);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    std::unique_ptr<struct gnutls_ocsp_req_int, decltype(&gnutls_ocsp_req_deinit)> req(rreq, &gnutls_ocsp_req_deinit);
    err = gnutls_ocsp_req_add_cert(req.get(), GNUTLS_DIG_SHA1, issuer, cert);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    Blob noncebuf(32);
    gnutls_datum_t nonce = { noncebuf.data(), (unsigned)noncebuf.size() };
    err = gnutls_rnd(GNUTLS_RND_NONCE, nonce.data, nonce.size);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    err = gnutls_ocsp_req_set_nonce(req.get(), 0, &nonce);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    gnutls_datum_t rdata {nullptr, 0};
    err = gnutls_ocsp_req_export(req.get(), &rdata);
    if (err != 0)
        throw CryptoException(gnutls_strerror(err));
    std::string ret((char*)rdata.data, (char*)rdata.data + rdata.size);
    gnutls_free(rdata.data);
    return std::make_pair<std::string, Blob>(std::move(ret), std::move(noncebuf));
}
#endif  // REMOVED: OLD X.509 Certificate implementations

// PrivateKey

// DILITHIUM5: Generate new Dilithium5 key pair (FIPS 204 / ML-DSA-87)
PrivateKey
PrivateKey::generate()
{
    PrivateKey key;
    uint8_t pk[pqcrystals_dilithium5_PUBLICKEYBYTES];

    // Generate Dilithium5 key pair using reference implementation
    int result = pqcrystals_dilithium5_ref_keypair(pk, key.dilithium_sk_);
    if (result != 0)
        throw CryptoException("Dilithium5 key generation failed");

    key.valid_ = true;

    // Cache the public key
    key.publicKey_ = std::make_shared<PublicKey>(pk, pqcrystals_dilithium5_PUBLICKEYBYTES);

    return key;
}

#if 0  // REMOVED: Old RSA/EC key generation - now using Dilithium5
PrivateKey
PrivateKey::generate(unsigned key_length, gnutls_pk_algorithm_t algo)
{
    gnutls_x509_privkey_t key;
    if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS)
        throw CryptoException("Unable to initialize private key.");
    if (algo == GNUTLS_PK_RSA) {
        int err = gnutls_x509_privkey_generate(key, algo, key_length, 0);
        if (err != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(key);
            throw CryptoException(std::string("Unable to generate RSA key pair: ") + gnutls_strerror(err));
        }
    }
#if GNUTLS_VERSION_NUMBER >= 0x030804
    else if (algo == GNUTLS_PK_RSA_OAEP) {
        int err;
        Spki spki;
        err = gnutls_x509_spki_set_rsa_oaep_params(spki.get(), GNUTLS_DIG_SHA256, nullptr);
        if (err != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(key);
            throw CryptoException(std::string("Unable to set RSA-OAEP params: ") + gnutls_strerror(err));
        }
        /*gnutls_keygen_data_st params;
        params.type = GNUTLS_KEYGEN_SPKI;
        params.data = (uint8_t*)&spki.get();
        params.size = spki.size();*/
        err = gnutls_x509_privkey_generate2(key, algo, key_length, 0, nullptr, 0);
        if (err != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(key);
            throw CryptoException(std::string("Unable to generate RSA key pair: ") + gnutls_strerror(err));
        }
        err = gnutls_x509_privkey_set_spki(key, spki.get(), 0);
        if (err != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(key);
            throw CryptoException(std::string("Unable to set SPKI: ") + gnutls_strerror(err));
        }
    }
#endif
    else {
        gnutls_x509_privkey_deinit(key);
        throw CryptoException("Only RSA and RSA-OAEP keys are supported");
    }
    return PrivateKey{key};
}

PrivateKey
PrivateKey::generateEC()
{
    gnutls_x509_privkey_t key;
    if (gnutls_x509_privkey_init(&key) != GNUTLS_E_SUCCESS)
        throw CryptoException("Unable to initialize private key.");
    int err = gnutls_x509_privkey_generate(key, GNUTLS_PK_EC, gnutls_sec_param_to_pk_bits(GNUTLS_PK_EC, GNUTLS_SEC_PARAM_ULTRA), 0);
    if (err != GNUTLS_E_SUCCESS) {
        gnutls_x509_privkey_deinit(key);
        throw CryptoException(std::string("Unable to generate EC key pair: ") + gnutls_strerror(err));
    }
    return PrivateKey{key};
}
#endif  // Disabled old RSA/EC key generation

// DILITHIUM5: Generate new Dilithium5 identity (key pair + certificate)
Identity
generateDilithiumIdentity(const std::string& name)
{
    auto key = std::make_shared<PrivateKey>(PrivateKey::generate());
    auto cert = std::make_shared<Certificate>(key->getPublicKey());
    cert->setName(name);
    return {std::move(key), std::move(cert)};
}

// DILITHIUM5: Save identity to binary files (.dsa for secret key, .pub for public key, .cert for certificate)
void
saveDilithiumIdentity(const Identity& id, const std::string& path)
{
    // Save secret key (4896 bytes) to .dsa file
    {
        auto sk_data = id.first->serialize();
        std::ofstream sk_file(path + ".dsa", std::ios::binary);
        sk_file.write((char*)sk_data.data(), sk_data.size());
        if (!sk_file)
            throw CryptoException("Could not write Dilithium5 secret key file");
    }

    // Save public key (2592 bytes) to .pub file
    {
        Blob pk_data;
        id.second->getPublicKey().pack(pk_data);
        std::ofstream pk_file(path + ".pub", std::ios::binary);
        pk_file.write((char*)pk_data.data(), pk_data.size());
        if (!pk_file)
            throw CryptoException("Could not write Dilithium5 public key file");
    }

    // Save certificate (msgpack format) to .cert file
    {
        Blob cert_data;
        id.second->pack(cert_data);
        std::ofstream cert_file(path + ".cert", std::ios::binary);
        cert_file.write((char*)cert_data.data(), cert_data.size());
        if (!cert_file)
            throw CryptoException("Could not write Dilithium5 certificate file");
    }
}

// DILITHIUM5: Load identity from binary files (.dsa, .pub, and .cert)
Identity
loadDilithiumIdentity(const std::string& path)
{
    // Load secret key from .dsa file
    std::ifstream sk_stream(path + ".dsa", std::ios::in | std::ios::binary);
    if (!sk_stream)
        throw CryptoException("Could not open Dilithium5 secret key file");

    std::vector<uint8_t> sk_data((std::istreambuf_iterator<char>(sk_stream)),
                                  std::istreambuf_iterator<char>());
    auto key = std::make_shared<PrivateKey>(sk_data.data(), sk_data.size(), nullptr);
    sk_stream.close();

    // Load public key from .pub file
    std::ifstream pk_stream(path + ".pub", std::ios::in | std::ios::binary);
    if (!pk_stream)
        throw CryptoException("Could not open Dilithium5 public key file");

    std::vector<uint8_t> pk_data((std::istreambuf_iterator<char>(pk_stream)),
                                  std::istreambuf_iterator<char>());
    auto pubkey = std::make_shared<PublicKey>(pk_data.data(), pk_data.size());
    pk_stream.close();

    // Set the public key cache on the private key
    key->setPublicKeyCache(pubkey);

    // Load certificate from .cert file
    std::ifstream cert_stream(path + ".cert", std::ios::in | std::ios::binary);
    if (!cert_stream)
        throw CryptoException("Could not open Dilithium5 certificate file");

    std::vector<uint8_t> cert_data((std::istreambuf_iterator<char>(cert_stream)),
                                    std::istreambuf_iterator<char>());
    auto cert = std::make_shared<Certificate>();
    cert->unpack(cert_data.data(), cert_data.size());
    cert_stream.close();

    return {std::move(key), std::move(cert)};
}

#if 0  // REMOVED: Old RSA identity generation
Identity
generateIdentity(const std::string& name, const Identity& ca, unsigned key_length, bool is_ca)
{
    auto key = std::make_shared<PrivateKey>(PrivateKey::generate(key_length));
    auto cert = std::make_shared<Certificate>(Certificate::generate(*key, name, ca, is_ca));
    return {std::move(key), std::move(cert)};
}


Identity
generateIdentity(const std::string& name, const Identity& ca, unsigned key_length) {
    return generateIdentity(name, ca, key_length, !ca.first || !ca.second);
}

Identity
generateEcIdentity(const std::string& name, const Identity& ca, bool is_ca)
{
    auto key = std::make_shared<PrivateKey>(PrivateKey::generateEC());
    auto cert = std::make_shared<Certificate>(Certificate::generate(*key, name, ca, is_ca));
    return {std::move(key), std::move(cert)};
}

Identity
generateEcIdentity(const std::string& name, const Identity& ca) {
    return generateEcIdentity(name, ca, !ca.first || !ca.second);
}

void
saveIdentity(const Identity& id, const std::string& path, const std::string& privkey_password)
{
    {
        auto ca_key_data = id.first->serialize(privkey_password);
        std::ofstream key_file(path + ".pem");
        key_file.write((char*)ca_key_data.data(), ca_key_data.size());
        // Throw error if the file is not written
        if (!key_file)
            throw CryptoException("Could not write private key file");
    }
    {
        auto ca_key_data = id.second->getPacked();
        std::ofstream crt_file(path + ".crt");
        crt_file.write((char*)ca_key_data.data(), ca_key_data.size());
        // Throw error if the file is not written
        if (!crt_file)
            throw CryptoException("Could not write certificate file");
    }
}

Identity 
loadIdentity(const std::string &path,const std::string &privkey_password)
{
    std::ifstream pkStream(path + ".pem", std::ios::in | std::ios::binary);
    std::vector<uint8_t> pkContent((std::istreambuf_iterator<char>(pkStream)),
                                    std::istreambuf_iterator<char>());
    auto key = std::make_shared<PrivateKey>(pkContent, privkey_password);
    pkStream.close();
    // Create a certificate
    gnutls_x509_crt_t gnuCert;
    if (gnutls_x509_crt_init(&gnuCert))
        throw std::runtime_error("Failed to initialize gnutls certificate struct");
    gnutls_datum_t crtContent {nullptr, 0};

    // Read the certificate file
    int err = gnutls_load_file((path + ".crt").c_str(), &crtContent);
    if (err)
        throw CryptoException(gnutls_strerror(err));

    err = gnutls_x509_crt_import(gnuCert, &crtContent, GNUTLS_X509_FMT_PEM);
    if (err)
        throw CryptoException(gnutls_strerror(err));

    auto cert = std::make_shared<Certificate>(gnuCert);
    return {std::move(key), std::move(cert)};
}

void
setValidityPeriod(gnutls_x509_crt_t cert, int64_t validity)
{
    int64_t now = time(nullptr);
    /* 2038 bug: don't allow time wrap */
    auto boundTime = [](int64_t t) -> time_t {
        return std::min<int64_t>(t, std::numeric_limits<time_t>::max());
    };
    gnutls_x509_crt_set_activation_time(cert, boundTime(now));
    gnutls_x509_crt_set_expiration_time(cert, boundTime(now + validity));
}

void
setRandomSerial(gnutls_x509_crt_t cert)
{
    std::random_device rdev;
    std::uniform_int_distribution<int64_t> dist{1};
    int64_t cert_serial = dist(rdev);
    gnutls_x509_crt_set_serial(cert, &cert_serial, sizeof(cert_serial));
}

Certificate
Certificate::generate(const PrivateKey& key, const std::string& name, const Identity& ca, bool is_ca, int64_t validity)
{
    gnutls_x509_crt_t cert;
    if (not key.x509_key or gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
        return {};
    Certificate ret {cert};

    setValidityPeriod(cert, validity <= 0 ? 10 * 365 * 24 * 60 * 60 : validity);
    if (int err = gnutls_x509_crt_set_key(cert, key.x509_key)) {
        throw CryptoException(std::string("Error when setting certificate key ") + gnutls_strerror(err));
    }
    if (int err = gnutls_x509_crt_set_version(cert, 3)) {
        throw CryptoException(std::string("Error when setting certificate version ") + gnutls_strerror(err));
    }

    // TODO: compute the subject key using the recommended RFC method
    const auto& pk = key.getPublicKey();
    auto pk_id = pk.getId();
    const std::string uid_str = pk_id.toString();

    int err = gnutls_x509_crt_set_subject_key_id(cert, &pk_id, sizeof(pk_id));
    if(err) {
        throw CryptoException(std::string("Error when setting subject key id ") + gnutls_strerror(err));
    }

    err = gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, name.data(), name.length());
    if(err) {
        throw CryptoException(std::string("Error when setting subject key id ") + gnutls_strerror(err));
    }
    err = gnutls_x509_crt_set_dn_by_oid(cert, GNUTLS_OID_LDAP_UID, 0, uid_str.data(), uid_str.length());
    if(err) {
        throw CryptoException(std::string("Error when setting dn by oid ") + gnutls_strerror(err));
    }

    setRandomSerial(cert);

    unsigned key_usage = 0;
    if (is_ca) {
        err = gnutls_x509_crt_set_ca_status(cert, 1);
        if(err) {
            throw CryptoException(std::string("Error when setting ca status ") + gnutls_strerror(err));
        }
        key_usage |= GNUTLS_KEY_KEY_CERT_SIGN | GNUTLS_KEY_CRL_SIGN;
    } else {
        key_usage |= GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_DATA_ENCIPHERMENT;
    }
    err = gnutls_x509_crt_set_key_usage(cert, key_usage);
    if(err) {
        throw CryptoException(std::string("Error when setting ca status ") + gnutls_strerror(err));
    }

    if (ca.first && ca.second) {
        if (not ca.second->isCA()) {
            throw CryptoException("Signing certificate must be CA");
        }
        err = gnutls_x509_crt_privkey_sign(cert, ca.second->cert, ca.first->key, pk.getPreferredDigest(), 0);
        if (err) {
            throw CryptoException(std::string("Error when signing certificate ") + gnutls_strerror(err));
        }
        ret.issuer = ca.second;
    } else {
        err = gnutls_x509_crt_privkey_sign(cert, cert, key.key, pk.getPreferredDigest(), 0);
        if (err) {
            throw CryptoException(std::string("Error when signing certificate ") + gnutls_strerror(err));
        }
    }

    return ret.getPacked();
}

Certificate
Certificate::generate(const CertificateRequest& request, const Identity& ca, int64_t validity)
{
    gnutls_x509_crt_t cert;
    if (auto err = gnutls_x509_crt_init(&cert))
        throw CryptoException(std::string("Unable to initialize certificate: ") + gnutls_strerror(err));
    Certificate ret {cert};
    if (auto err = gnutls_x509_crt_set_crq(cert, request.get()))
        throw CryptoException(std::string("Unable to initialize certificate: ") + gnutls_strerror(err));

    if (auto err = gnutls_x509_crt_set_version(cert, 3)) {
        throw CryptoException(std::string("Unable to set certificate version: ") + gnutls_strerror(err));
    }

    setValidityPeriod(cert, validity <= 0 ? 10 * 365 * 24 * 60 * 60 : validity);
    setRandomSerial(cert);

    if (auto err = gnutls_x509_crt_privkey_sign(cert, ca.second->cert, ca.first->key, ca.second->getPreferredDigest(), 0)) {
        throw CryptoException(std::string("Unable to sign certificate: ") + gnutls_strerror(err));
    }
    ret.issuer = ca.second;

    return ret.getPacked();
}

void
Certificate::setValidity(const Identity& ca, int64_t validity)
{
    setValidityPeriod(cert, validity);
    setRandomSerial(cert);
    if (ca.first && ca.second) {
        if (not ca.second->isCA()) {
            throw CryptoException("Signing certificate must be CA");
        }
        if (int err = gnutls_x509_crt_privkey_sign(cert, ca.second->cert, ca.first->key, ca.second->getPreferredDigest(), 0)) {
            throw CryptoException(std::string("Error when signing certificate ") + gnutls_strerror(err));
        }
    }
}

void
Certificate::setValidity(const PrivateKey& key, int64_t validity)
{
    setValidityPeriod(cert, validity);
    setRandomSerial(cert);
    const auto& pk = key.getPublicKey();
    if (int err = gnutls_x509_crt_privkey_sign(cert, cert, key.key, pk.getPreferredDigest(), 0)) {
        throw CryptoException(std::string("Error when signing certificate ") + gnutls_strerror(err));
    }
}

std::vector<std::shared_ptr<RevocationList>>
Certificate::getRevocationLists() const
{
    std::vector<std::shared_ptr<RevocationList>> ret;
    ret.reserve(revocation_lists.size());
    for (const auto& crl : revocation_lists)
        ret.emplace_back(crl);
    return ret;
}

// OcspRequest

OcspRequest::OcspRequest(const uint8_t* dat_ptr, size_t dat_size)
{
    int ret = gnutls_ocsp_req_init(&request);
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    gnutls_datum_t dat = {(unsigned char*)dat_ptr,(unsigned int)dat_size};
    ret = gnutls_ocsp_req_import(request, &dat);
    if (ret < 0){
        gnutls_ocsp_req_deinit(request);
        throw CryptoException(gnutls_strerror(ret));
    }
}

OcspRequest::~OcspRequest()
{
    if (request) {
        gnutls_ocsp_req_deinit(request);
        request = nullptr;
    }
}

std::string
OcspRequest::toString(const bool compact) const
{
    int ret;
    gnutls_datum_t dat {nullptr, 0};
    ret = gnutls_ocsp_req_print(request, compact ? GNUTLS_OCSP_PRINT_COMPACT : GNUTLS_OCSP_PRINT_FULL, &dat);

    std::string str;
    if (ret == 0) {
        str = std::string((const char*)dat.data, (size_t)dat.size);
        gnutls_free(dat.data);
    } else
        throw CryptoException(gnutls_strerror(ret));
    return str;
}

Blob
OcspRequest::pack() const
{
    gnutls_datum_t dat {nullptr, 0};
    int err = gnutls_ocsp_req_export(request, &dat);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    Blob ret {dat.data, dat.data + dat.size};
    gnutls_free(dat.data);
    return ret;
}

Blob
OcspRequest::getNonce() const
{
    gnutls_datum_t dat {nullptr, 0};
    unsigned critical;
    int err = gnutls_ocsp_req_get_nonce(request, &critical, &dat);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    Blob ret {dat.data, dat.data + dat.size};
    gnutls_free(dat.data);
    return ret;
}

// OcspResponse

OcspResponse::OcspResponse(const uint8_t* dat_ptr, size_t dat_size)
{
    int ret = gnutls_ocsp_resp_init(&response);
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    gnutls_datum_t dat = {(unsigned char*)dat_ptr,(unsigned int)dat_size};
    ret = gnutls_ocsp_resp_import(response, &dat);
    if (ret < 0){
        gnutls_ocsp_resp_deinit(response);
        throw CryptoException(gnutls_strerror(ret));
    }
}

OcspResponse::~OcspResponse()
{
    gnutls_ocsp_resp_deinit(response);
}

Blob
OcspResponse::pack() const
{
    gnutls_datum_t dat {nullptr, 0};
    int err = gnutls_ocsp_resp_export(response, &dat);
    if (err < 0)
        throw CryptoException(gnutls_strerror(err));
    Blob ret {dat.data, dat.data + dat.size};
    gnutls_free(dat.data);
    return ret;
}

std::string
OcspResponse::toString(const bool compact) const
{
    int ret;
    std::string str;
    gnutls_datum_t dat {nullptr, 0};
    ret = gnutls_ocsp_resp_print(response, compact ? GNUTLS_OCSP_PRINT_COMPACT : GNUTLS_OCSP_PRINT_FULL, &dat);
    if (ret == 0)
        str = std::string((const char*)dat.data, (size_t)dat.size);
    gnutls_free(dat.data);
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    return str;
}


gnutls_ocsp_cert_status_t
OcspResponse::getCertificateStatus() const
{
    int ret;
    unsigned int status;
    // MSVC/vcpkg GnuTLS cast workaround
#if _WIN32 && (GNUTLS_VERSION_NUMBER == 0x030807)
    ret = gnutls_ocsp_resp_get_single(response, 
                                      0, 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      reinterpret_cast<gnutls_ocsp_cert_status_t*>(& status), 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      NULL);
#else
    ret = gnutls_ocsp_resp_get_single(response, 0, NULL, NULL, NULL, NULL, &status, NULL, NULL, NULL, NULL);
#endif
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    return (gnutls_ocsp_cert_status_t) status;
}

gnutls_ocsp_cert_status_t
OcspResponse::verifyDirect(const Certificate& crt, const Blob& nonce)
{
    // Check OCSP response
    int ret = gnutls_ocsp_resp_get_status(response);
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    gnutls_ocsp_resp_status_t status = (gnutls_ocsp_resp_status_t)ret;
    if (status != GNUTLS_OCSP_RESP_SUCCESSFUL)
        throw CryptoException("OCSP request unsuccessful: " + std::to_string(ret));

    if (not nonce.empty()) {
        // Ensure no replay attack has been done
        gnutls_datum_t rnonce {nullptr, 0};
        ret = gnutls_ocsp_resp_get_nonce(response, NULL, &rnonce);
        if (ret < 0)
            throw CryptoException(gnutls_strerror(ret));
        if (rnonce.size != nonce.size() || memcmp(nonce.data(), rnonce.data, nonce.size()) != 0){
            gnutls_free(rnonce.data);
            throw CryptoException(gnutls_strerror(GNUTLS_E_OCSP_RESPONSE_ERROR));
        }
        gnutls_free(rnonce.data);
    }

    // Verify signature of the Basic OCSP response against the public key in the issuer certificate.
    unsigned int verify = 0;
    ret = gnutls_ocsp_resp_verify_direct(response, crt.issuer->cert, &verify, 0);
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    if (verify) {
        if (verify & GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND)
            throw CryptoException("Signer cert not found");
        if (verify & GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR)
            throw CryptoException("Signer cert keyusage error");
        if (verify & GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER)
            throw CryptoException("Signer cert is not trusted");
        if (verify & GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM)
            throw CryptoException("Insecure algorithm");
        if (verify & GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE)
            throw CryptoException("Signature failure");
        if (verify & GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED)
            throw CryptoException("Signer cert not yet activated");
        if (verify & GNUTLS_OCSP_VERIFY_CERT_EXPIRED)
            throw CryptoException("Signer cert expired");
        throw CryptoException(gnutls_strerror(GNUTLS_E_OCSP_RESPONSE_ERROR));
    }

    // Check whether the OCSP response is about the provided certificate.
    if ((ret = gnutls_ocsp_resp_check_crt(response, 0, crt.cert)) < 0)
        throw CryptoException(gnutls_strerror(ret));

    // Check certificate revocation status
    unsigned int status_ocsp;
    // MSVC/vcpkg GnuTLS cast workaround
#if _WIN32 && (GNUTLS_VERSION_NUMBER == 0x030807)
    ret = gnutls_ocsp_resp_get_single(response, 
                                      0, 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      reinterpret_cast<gnutls_ocsp_cert_status_t*>(& status_ocsp), 
                                      NULL, 
                                      NULL, 
                                      NULL, 
                                      NULL);
#else
    ret = gnutls_ocsp_resp_get_single(response, 0, NULL, NULL, NULL, NULL, &status_ocsp, NULL, NULL, NULL, NULL);
#endif
    if (ret < 0)
        throw CryptoException(gnutls_strerror(ret));
    return (gnutls_ocsp_cert_status_t)status_ocsp;
}

// RevocationList

RevocationList::RevocationList()
{
    gnutls_x509_crl_init(&crl);
}

RevocationList::RevocationList(const Blob& b)
{
    gnutls_x509_crl_init(&crl);
    try {
        unpack(b.data(), b.size());
    } catch (const std::exception& e) {
        gnutls_x509_crl_deinit(crl);
        crl = nullptr;
        throw;
    }
}

RevocationList::~RevocationList()
{
    if (crl) {
        gnutls_x509_crl_deinit(crl);
        crl = nullptr;
    }
}

void
RevocationList::pack(Blob& b) const
{
    gnutls_datum_t gdat {nullptr, 0};
    if (auto err = gnutls_x509_crl_export2(crl, GNUTLS_X509_FMT_DER, &gdat)) {
        throw CryptoException(std::string("Unable to export CRL: ") + gnutls_strerror(err));
    }
    b.insert(b.end(), gdat.data, gdat.data + gdat.size);
    gnutls_free(gdat.data);
}

void
RevocationList::unpack(const uint8_t* dat, size_t dat_size)
{
    if (std::numeric_limits<unsigned>::max() < dat_size)
        throw CryptoException("Unable to load CRL: too large.");
    const gnutls_datum_t gdat {(uint8_t*)dat, (unsigned)dat_size};
    if (auto err_pem = gnutls_x509_crl_import(crl, &gdat, GNUTLS_X509_FMT_PEM))
        if (auto err_der = gnutls_x509_crl_import(crl, &gdat, GNUTLS_X509_FMT_DER)) {
            throw CryptoException(std::string("Unable to load CRL: PEM: ") + gnutls_strerror(err_pem)
                                                           + " DER: "  + gnutls_strerror(err_der));
        }
}

void
RevocationList::msgpack_unpack(const msgpack::object& o)
{
    try {
        if (o.type == msgpack::type::BIN)
            unpack((const uint8_t*)o.via.bin.ptr, o.via.bin.size);
        else {
            Blob dat = unpackBlob(o);
            unpack(dat.data(), dat.size());
        }
    } catch (...) {
        throw msgpack::type_error();
    }
}

bool
RevocationList::isRevoked(const Certificate& crt) const
{
    auto ret = gnutls_x509_crt_check_revocation(crt.cert, &crl, 1);
    if (ret < 0)
        throw CryptoException(std::string("Unable to check certificate revocation status: ") + gnutls_strerror(ret));
    return ret != 0;
}

void
RevocationList::revoke(const Certificate& crt, std::chrono::system_clock::time_point t)
{
    if (t == time_point::min())
        t = clock::now();
    if (auto err = gnutls_x509_crl_set_crt(crl, crt.cert, std::chrono::system_clock::to_time_t(t)))
        throw CryptoException(std::string("Unable to revoke certificate: ") + gnutls_strerror(err));
}

static std::string
getCRLIssuerDN(gnutls_x509_crl_t cert, const char* oid)
{
    std::string dn;
    dn.resize(512);
    size_t dn_sz = dn.size();
    int ret = gnutls_x509_crl_get_issuer_dn_by_oid(cert, oid, 0, 0, &(*dn.begin()), &dn_sz);
    if (ret != GNUTLS_E_SUCCESS)
        return {};
    dn.resize(dn_sz);
    return dn;
}

std::string
RevocationList::getIssuerName() const
{
    return getCRLIssuerDN(crl, GNUTLS_OID_X520_COMMON_NAME);
}

/** Read CRL issuer User ID (UID) */
std::string
RevocationList::getIssuerUID() const
{
    return getCRLIssuerDN(crl, GNUTLS_OID_LDAP_UID);
}

RevocationList::time_point
RevocationList::getNextUpdateTime() const
{
    auto t = gnutls_x509_crl_get_next_update(crl);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

RevocationList::time_point
RevocationList::getUpdateTime() const
{
    auto t = gnutls_x509_crl_get_this_update(crl);
    if (t == (time_t)-1)
        return std::chrono::system_clock::time_point::min();
    return std::chrono::system_clock::from_time_t(t);
}

enum class Endian : uint32_t
{
    LITTLE = 0,
    BIG = 1
};

template <typename T>
T endian(T w, Endian endian = Endian::BIG)
{
    // this gets optimized out into if (endian == host_endian) return w;
    union { uint64_t quad; uint32_t islittle; } t;
    t.quad = 1;
    if (t.islittle ^ (uint32_t)endian) return w;
    T r = 0;

    // decent compilers will unroll this (gcc)
    // or even convert straight into single bswap (clang)
    for (size_t i = 0; i < sizeof(r); i++) {
        r <<= 8;
        r |= w & 0xff;
        w >>= 8;
    }
    return r;
}

void
RevocationList::sign(const PrivateKey& key, const Certificate& ca, duration validity)
{
    if (auto err = gnutls_x509_crl_set_version(crl, 2))
        throw CryptoException(std::string("Unable to set CRL version: ") + gnutls_strerror(err));
    auto now = std::chrono::system_clock::now();
    auto next_update = (validity == duration{}) ? ca.getExpiration() : now + validity;
    if (auto err = gnutls_x509_crl_set_this_update(crl, std::chrono::system_clock::to_time_t(now)))
        throw CryptoException(std::string("Unable to set CRL update time: ") + gnutls_strerror(err));
    if (auto err = gnutls_x509_crl_set_next_update(crl, std::chrono::system_clock::to_time_t(next_update)))
        throw CryptoException(std::string("Unable to set CRL next update time: ") + gnutls_strerror(err));
    uint64_t number {0};
    size_t number_sz {sizeof(number)};
    unsigned critical {0};
    gnutls_x509_crl_get_number(crl, &number, &number_sz, &critical);
    if (number == 0) {
        // initialize to a random number
        number_sz = sizeof(number);
        std::random_device rdev;
        std::generate_n((uint8_t*)&number, sizeof(number), std::bind(rand_byte, std::ref(rdev)));
    } else
        number = endian(endian(number) + 1);
    if (auto err = gnutls_x509_crl_set_number(crl, &number, sizeof(number)))
        throw CryptoException(std::string("Unable to set CRL update time: ") + gnutls_strerror(err));
    if (auto err = gnutls_x509_crl_sign2(crl, ca.cert, key.x509_key, GNUTLS_DIG_SHA512, 0))
        throw CryptoException(std::string("Unable to sign certificate revocation list: ") + gnutls_strerror(err));
    // to be able to actually use the CRL we need to serialize/deserialize it
    auto packed = getPacked();
    unpack(packed.data(), packed.size());
}

bool
RevocationList::isSignedBy(const Certificate& issuer) const
{
    unsigned result {0};
    auto err = gnutls_x509_crl_verify(crl, &issuer.cert, 1, 0, &result);
    if (err < 0) {
        //std::cout << "Unable to verify CRL: " << err << " " << result << " " << gnutls_strerror(err) << std::endl;
        return false;
    }
    return result == 0;
}


Blob
RevocationList::getNumber() const
{
    Blob number(20);
    size_t number_sz {number.size()};
    unsigned critical {0};
    gnutls_x509_crl_get_number(crl, number.data(), &number_sz, &critical);
    if (number_sz != number.size())
        number.resize(number_sz);
    return number;
}

std::string
RevocationList::toString() const
{
    gnutls_datum_t out {nullptr, 0};
    gnutls_x509_crl_print(crl, GNUTLS_CRT_PRINT_FULL, &out);
    std::string ret(out.data, out.data+out.size);
    gnutls_free(out.data);
    return ret;
}

// TrustList

TrustList::TrustList() {
    gnutls_x509_trust_list_init(&trust, 0);
}

TrustList::~TrustList() {
    gnutls_x509_trust_list_deinit(trust, 1);
}

TrustList&
TrustList::operator=(TrustList&& o) noexcept
{
    if (trust)
        gnutls_x509_trust_list_deinit(trust, true);
    trust = o.trust;
    o.trust = nullptr;
    return *this;
}

void TrustList::add(const Certificate& crt)
{
    auto chain = crt.getChainWithRevocations(true);
    gnutls_x509_trust_list_add_cas(trust, chain.first.data(), chain.first.size(), GNUTLS_TL_NO_DUPLICATES);
    if (not chain.second.empty())
        gnutls_x509_trust_list_add_crls(
                trust,
                chain.second.data(), chain.second.size(),
                GNUTLS_TL_VERIFY_CRL | GNUTLS_TL_NO_DUPLICATES, 0);
}

void TrustList::add(const RevocationList& crl)
{
    auto copy = crl.getCopy();
    gnutls_x509_trust_list_add_crls(trust, &copy, 1, GNUTLS_TL_VERIFY_CRL | GNUTLS_TL_NO_DUPLICATES, 0);
}

void TrustList::remove(const Certificate& crt, bool parents)
{
    gnutls_x509_trust_list_remove_cas(trust, &crt.cert, 1);
    if (parents) {
        for (auto c = crt.issuer; c; c = c->issuer)
            gnutls_x509_trust_list_remove_cas(trust, &c->cert, 1);
    }
}

TrustList::VerifyResult
TrustList::verify(const Certificate& crt) const
{
    auto chain = crt.getChain();
    VerifyResult ret;
    ret.ret = gnutls_x509_trust_list_verify_crt2(
        trust,
        chain.data(), chain.size(),
        nullptr, 0,
        GNUTLS_PROFILE_TO_VFLAGS(GNUTLS_PROFILE_MEDIUM),
        &ret.result, nullptr);
    return ret;
}

std::string
TrustList::VerifyResult::toString() const
{
    std::ostringstream ss;
    ss << *this;
    return ss.str();
}

std::ostream& operator<< (std::ostream& o, const TrustList::VerifyResult& h)
{
    if (h.ret < 0) {
        o << "Error verifying certificate: " << gnutls_strerror(h.ret) << std::endl;
    } else if (h.result & GNUTLS_CERT_INVALID) {
        o << "Certificate check failed with code: " << h.result << std::endl;
        if (h.result & GNUTLS_CERT_SIGNATURE_FAILURE)
            o << "* The signature verification failed." << std::endl;
        if (h.result & GNUTLS_CERT_REVOKED)
            o << "* Certificate is revoked" << std::endl;
        if (h.result & GNUTLS_CERT_SIGNER_NOT_FOUND)
            o << "* Certificate's issuer is not known" << std::endl;
        if (h.result & GNUTLS_CERT_SIGNER_NOT_CA)
            o << "* Certificate's issuer not a CA" << std::endl;
        if (h.result & GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE)
            o << "* Certificate's signer constraints were violated" << std::endl;
        if (h.result & GNUTLS_CERT_INSECURE_ALGORITHM)
            o << "* Certificate was signed using an insecure algorithm" << std::endl;
        if (h.result & GNUTLS_CERT_NOT_ACTIVATED)
            o << "* Certificate is not yet activated" << std::endl;
        if (h.result & GNUTLS_CERT_EXPIRED)
            o << "* Certificate has expired" << std::endl;
        if (h.result & GNUTLS_CERT_UNEXPECTED_OWNER)
            o << "* The owner is not the expected one" << std::endl;
        if (h.result & GNUTLS_CERT_PURPOSE_MISMATCH)
            o << "* Certificate or an intermediate does not match the intended purpose" << std::endl;
        if (h.result & GNUTLS_CERT_MISMATCH)
            o << "* Certificate presented isn't the expected one" << std::endl;
    } else {
        o << "Certificate is valid" << std::endl;
    }
    return o;
}
#endif  // REMOVED: Old RSA identity generation (closes #if 0 at line 1567)

}
}
