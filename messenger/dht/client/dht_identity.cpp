#include "dht_identity.h"
#include <opendht/crypto.h>
#include <gnutls/x509.h>
#include <iostream>
#include <memory>
#include <cstring>

// Platform-specific network byte order functions
#ifdef _WIN32
    #include <winsock2.h>  // For htonl/ntohl on Windows
#else
    #include <arpa/inet.h>  // For htonl/ntohl on Unix/Linux
#endif

// Need the full dht_identity struct definition (from dht_context.cpp)
struct dht_identity {
    dht::crypto::Identity identity;
    dht_identity(const dht::crypto::Identity& id) : identity(id) {}
};

//=============================================================================
// DHT Identity Management (for encrypted backup system)
//=============================================================================

/**
 * Generate random DHT identity (RSA-2048)
 */
extern "C" int dht_identity_generate_random(dht_identity_t **identity_out) {
    if (!identity_out) {
        std::cerr << "[DHT Identity] ERROR: NULL output parameter" << std::endl;
        return -1;
    }

    try {
        // Generate random RSA-2048 identity (no CA, self-signed)
        auto id = dht::crypto::generateIdentity("dht_node");

        *identity_out = new dht_identity(id);

        std::cout << "[DHT Identity] Generated random RSA-2048 identity" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT Identity] Exception generating identity: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Export identity to buffer (PEM format: private key + certificate)
 *
 * Format: [key_pem_size(4)][key_pem][cert_pem_size(4)][cert_pem]
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

        // Get GNUTLS objects
        auto cert = id.second->cert;
        auto privkey = id.first->x509_key;

        // Export private key to PEM
        gnutls_datum_t key_pem;
        if (gnutls_x509_privkey_export2(privkey, GNUTLS_X509_FMT_PEM, &key_pem) != GNUTLS_E_SUCCESS) {
            std::cerr << "[DHT Identity] Failed to export private key" << std::endl;
            return -1;
        }

        // Export certificate to PEM
        gnutls_datum_t cert_pem;
        if (gnutls_x509_crt_export2(cert, GNUTLS_X509_FMT_PEM, &cert_pem) != GNUTLS_E_SUCCESS) {
            gnutls_free(key_pem.data);
            std::cerr << "[DHT Identity] Failed to export certificate" << std::endl;
            return -1;
        }

        // Calculate total size: 4 + key_pem.size + 4 + cert_pem.size
        size_t total_size = 4 + key_pem.size + 4 + cert_pem.size;
        uint8_t *buffer = (uint8_t*)malloc(total_size);
        if (!buffer) {
            gnutls_free(key_pem.data);
            gnutls_free(cert_pem.data);
            std::cerr << "[DHT Identity] Failed to allocate buffer" << std::endl;
            return -1;
        }

        uint8_t *ptr = buffer;

        // Write key_pem_size (network byte order)
        uint32_t key_size = (uint32_t)key_pem.size;
        uint32_t key_size_be = htonl(key_size);
        memcpy(ptr, &key_size_be, 4);
        ptr += 4;

        // Write key_pem
        memcpy(ptr, key_pem.data, key_pem.size);
        ptr += key_pem.size;

        // Write cert_pem_size (network byte order)
        uint32_t cert_size = (uint32_t)cert_pem.size;
        uint32_t cert_size_be = htonl(cert_size);
        memcpy(ptr, &cert_size_be, 4);
        ptr += 4;

        // Write cert_pem
        memcpy(ptr, cert_pem.data, cert_pem.size);

        gnutls_free(key_pem.data);
        gnutls_free(cert_pem.data);

        *buffer_out = buffer;
        *buffer_size_out = total_size;

        std::cout << "[DHT Identity] Exported to buffer (" << total_size << " bytes)" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[DHT Identity] Exception exporting: " << e.what() << std::endl;
        return -1;
    }
}

/**
 * Import identity from buffer (PEM format)
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

        // Read key_pem_size
        uint32_t key_size_be;
        memcpy(&key_size_be, ptr, 4);
        uint32_t key_size = ntohl(key_size_be);
        ptr += 4;

        if (key_size > buffer_size - 8) {
            std::cerr << "[DHT Identity] Invalid key size in buffer" << std::endl;
            return -1;
        }

        // Read key_pem
        std::string key_pem((const char*)ptr, key_size);
        ptr += key_size;

        // Read cert_pem_size
        uint32_t cert_size_be;
        memcpy(&cert_size_be, ptr, 4);
        uint32_t cert_size = ntohl(cert_size_be);
        ptr += 4;

        if (cert_size > buffer_size - 8 - key_size) {
            std::cerr << "[DHT Identity] Invalid cert size in buffer" << std::endl;
            return -1;
        }

        // Read cert_pem
        std::string cert_pem((const char*)ptr, cert_size);

        // Import private key
        gnutls_x509_privkey_t privkey;
        gnutls_x509_privkey_init(&privkey);
        gnutls_datum_t key_datum = { (unsigned char*)key_pem.data(), (unsigned int)key_pem.size() };
        if (gnutls_x509_privkey_import(privkey, &key_datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(privkey);
            std::cerr << "[DHT Identity] Failed to import private key" << std::endl;
            return -1;
        }

        // Import certificate
        gnutls_x509_crt_t cert;
        gnutls_x509_crt_init(&cert);
        gnutls_datum_t cert_datum = { (unsigned char*)cert_pem.data(), (unsigned int)cert_pem.size() };
        if (gnutls_x509_crt_import(cert, &cert_datum, GNUTLS_X509_FMT_PEM) != GNUTLS_E_SUCCESS) {
            gnutls_x509_privkey_deinit(privkey);
            gnutls_x509_crt_deinit(cert);
            std::cerr << "[DHT Identity] Failed to import certificate" << std::endl;
            return -1;
        }

        // Create Identity from GNUTLS objects
        auto priv = std::make_shared<dht::crypto::PrivateKey>(privkey);
        auto certificate = std::make_shared<dht::crypto::Certificate>(cert);
        dht::crypto::Identity id(priv, certificate);

        *identity_out = new dht_identity(id);

        std::cout << "[DHT Identity] Imported from buffer (" << buffer_size << " bytes)" << std::endl;
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
