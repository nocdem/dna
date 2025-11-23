#include "dht_identity.h"
#include <opendht/crypto.h>
#include <iostream>
#include <memory>
#include <cstring>

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Unix/Linux
#endif

// Need the full dht_identity struct definition
struct dht_identity {
    dht::crypto::Identity identity;
    dht_identity(const dht::crypto::Identity& id) : identity(id) {}
};

//=============================================================================
// DHT Identity Management (Dilithium5 post-quantum)
//=============================================================================

/**
 * Generate random DHT identity (Dilithium5 - ML-DSA-87)
 */
extern "C" int dht_identity_generate_dilithium5(dht_identity_t **identity_out) {
    if (!identity_out) {
        std::cerr << "[DHT Identity] ERROR: NULL output parameter" << std::endl;
        return -1;
    }

    try {
        // Generate Dilithium5 (ML-DSA-87) identity - FIPS 204 compliant
        auto id = dht::crypto::generateDilithiumIdentity("dht_node");

        *identity_out = new dht_identity(id);

        std::cout << "[DHT Identity] Generated Dilithium5 (ML-DSA-87) identity" << std::endl;
        std::cout << "[DHT Identity] FIPS 204 - NIST Category 5 (256-bit quantum)" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT Identity] Exception generating identity: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Export identity to buffer (binary format: Dilithium5 keys)
 *
 * Format: [key_size(4)][dilithium5_key][cert_size(4)][dilithium5_cert]
 * Binary format (not PEM) for Dilithium5 keys
 */
extern "C" int dht_identity_export_to_buffer(
    dht_identity_t *identity,
    uint8_t **buffer_out,
    size_t *buffer_size_out)
{
    if (!identity || !buffer_out || !buffer_size_out) {
        std::cerr << "[DHT Identity] ERROR: NULL parameter in export" << std::endl;
        return -1;
    }

    try {
        auto& id = identity->identity;

        // Serialize private key (Dilithium5 - 4896 bytes)
        auto key_data = id.first->serialize();

        // Serialize certificate (Dilithium5)
        auto cert_data = id.second->getPacked();

        // Calculate total size: 4 + key.size + 4 + cert.size
        size_t total_size = 4 + key_data.size() + 4 + cert_data.size();
        uint8_t *buffer = (uint8_t*)malloc(total_size);
        if (!buffer) {
            std::cerr << "[DHT Identity] Failed to allocate buffer" << std::endl;
            return -1;
        }

        uint8_t *ptr = buffer;

        // Write key_size (network byte order)
        uint32_t key_size = (uint32_t)key_data.size();
        uint32_t key_size_be = htonl(key_size);
        memcpy(ptr, &key_size_be, 4);
        ptr += 4;

        // Write key data
        memcpy(ptr, key_data.data(), key_data.size());
        ptr += key_data.size();

        // Write cert_size (network byte order)
        uint32_t cert_size = (uint32_t)cert_data.size();
        uint32_t cert_size_be = htonl(cert_size);
        memcpy(ptr, &cert_size_be, 4);
        ptr += 4;

        // Write cert data
        memcpy(ptr, cert_data.data(), cert_data.size());

        *buffer_out = buffer;
        *buffer_size_out = total_size;

        std::cout << "[DHT Identity] Exported to buffer (" << total_size << " bytes)" << std::endl;
        std::cout << "[DHT Identity] Dilithium5 key: " << key_data.size() << " bytes" << std::endl;
        std::cout << "[DHT Identity] Certificate: " << cert_data.size() << " bytes" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT Identity] Exception exporting: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Import identity from buffer (binary format: Dilithium5)
 */
extern "C" int dht_identity_import_from_buffer(
    const uint8_t *buffer,
    size_t buffer_size,
    dht_identity_t **identity_out)
{
    if (!buffer || !identity_out || buffer_size < 8) {
        std::cerr << "[DHT Identity] ERROR: Invalid parameters in import" << std::endl;
        return -1;
    }

    try {
        const uint8_t *ptr = buffer;

        // Read key_size
        uint32_t key_size_be;
        memcpy(&key_size_be, ptr, 4);
        uint32_t key_size = ntohl(key_size_be);
        ptr += 4;

        if (key_size > buffer_size - 8) {
            std::cerr << "[DHT Identity] Invalid key size in buffer" << std::endl;
            return -1;
        }

        // Read key data
        std::vector<uint8_t> key_data(ptr, ptr + key_size);
        ptr += key_size;

        // Read cert_size
        uint32_t cert_size_be;
        memcpy(&cert_size_be, ptr, 4);
        uint32_t cert_size = ntohl(cert_size_be);
        ptr += 4;

        if (cert_size > buffer_size - 8 - key_size) {
            std::cerr << "[DHT Identity] Invalid cert size in buffer" << std::endl;
            return -1;
        }

        // Read cert data
        std::vector<uint8_t> cert_data(ptr, ptr + cert_size);

        // Import private key (Dilithium5) - use 3-argument constructor (data, size, password)
        auto priv = std::make_shared<dht::crypto::PrivateKey>(key_data.data(), key_data.size(), nullptr);

        // Extract and cache public key from private key
        auto pubkey = std::make_shared<dht::crypto::PublicKey>(priv->getPublicKey());
        priv->setPublicKeyCache(pubkey);

        // Import certificate (Dilithium5) - use unpack() method
        auto certificate = std::make_shared<dht::crypto::Certificate>();
        certificate->unpack(cert_data.data(), cert_data.size());

        dht::crypto::Identity id(priv, certificate);

        *identity_out = new dht_identity(id);

        std::cout << "[DHT Identity] Imported from buffer (" << buffer_size << " bytes)" << std::endl;
        std::cout << "[DHT Identity] Dilithium5 key: " << key_size << " bytes" << std::endl;
        std::cout << "[DHT Identity] Certificate: " << cert_size << " bytes" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT Identity] Exception importing: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Free DHT identity
 */
extern "C" void dht_identity_free(dht_identity_t *identity) {
    if (identity) {
        delete identity;
    }
}

/**
 * Legacy RSA function - kept for backward compatibility, redirects to Dilithium5
 * DEPRECATED: Use dht_identity_generate_dilithium5() instead
 */
extern "C" int dht_identity_generate_random(dht_identity_t **identity_out) {
    std::cout << "[DHT Identity] WARNING: dht_identity_generate_random() is deprecated" << std::endl;
    std::cout << "[DHT Identity] Generating Dilithium5 identity instead of RSA" << std::endl;
    return dht_identity_generate_dilithium5(identity_out);
}
