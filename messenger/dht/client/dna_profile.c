/**
 * @file dna_profile.c
 * @brief DNA profile management implementation
 *
 * @author DNA Messenger Team
 * @date 2025-11-05
 */

#include "dna_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <json-c/json.h>

// Disallowed DNA names
static const char *DISALLOWED_NAMES[] = {
    "admin", "root", "system", "network", "cpunk", "demlabs",
    "cellframe", "moderator", "support", "help", "official",
    NULL
};

// ===== Memory Management =====

dna_profile_data_t* dna_profile_create(void) {
    dna_profile_data_t *profile = calloc(1, sizeof(dna_profile_data_t));
    return profile;
}

void dna_profile_free(dna_profile_data_t *profile) {
    if (profile) {
        free(profile);
    }
}

dna_unified_identity_t* dna_identity_create(void) {
    dna_unified_identity_t *identity = calloc(1, sizeof(dna_unified_identity_t));
    return identity;
}

void dna_identity_free(dna_unified_identity_t *identity) {
    if (identity) {
        free(identity);
    }
}

// ===== JSON Serialization Helpers =====

static json_object* wallets_to_json(const dna_wallets_t *wallets) {
    json_object *obj = json_object_new_object();

    // Cellframe networks
    if (wallets->backbone[0]) json_object_object_add(obj, "backbone",
        json_object_new_string(wallets->backbone));
    if (wallets->kelvpn[0]) json_object_object_add(obj, "kelvpn",
        json_object_new_string(wallets->kelvpn));
    if (wallets->riemann[0]) json_object_object_add(obj, "riemann",
        json_object_new_string(wallets->riemann));
    if (wallets->raiden[0]) json_object_object_add(obj, "raiden",
        json_object_new_string(wallets->raiden));
    if (wallets->mileena[0]) json_object_object_add(obj, "mileena",
        json_object_new_string(wallets->mileena));
    if (wallets->subzero[0]) json_object_object_add(obj, "subzero",
        json_object_new_string(wallets->subzero));
    if (wallets->cpunk_testnet[0]) json_object_object_add(obj, "cpunk_testnet",
        json_object_new_string(wallets->cpunk_testnet));

    // External blockchains
    if (wallets->btc[0]) json_object_object_add(obj, "btc",
        json_object_new_string(wallets->btc));
    if (wallets->eth[0]) json_object_object_add(obj, "eth",
        json_object_new_string(wallets->eth));
    if (wallets->sol[0]) json_object_object_add(obj, "sol",
        json_object_new_string(wallets->sol));
    if (wallets->qevm[0]) json_object_object_add(obj, "qevm",
        json_object_new_string(wallets->qevm));
    if (wallets->bnb[0]) json_object_object_add(obj, "bnb",
        json_object_new_string(wallets->bnb));

    return obj;
}

static int wallets_from_json(json_object *obj, dna_wallets_t *wallets) {
    memset(wallets, 0, sizeof(dna_wallets_t));

    json_object *val;
    #define PARSE_WALLET(field, key) \
        if (json_object_object_get_ex(obj, key, &val)) { \
            const char *str = json_object_get_string(val); \
            if (str) strncpy(wallets->field, str, sizeof(wallets->field) - 1); \
        }

    PARSE_WALLET(backbone, "backbone")
    PARSE_WALLET(kelvpn, "kelvpn")
    PARSE_WALLET(riemann, "riemann")
    PARSE_WALLET(raiden, "raiden")
    PARSE_WALLET(mileena, "mileena")
    PARSE_WALLET(subzero, "subzero")
    PARSE_WALLET(cpunk_testnet, "cpunk_testnet")
    PARSE_WALLET(btc, "btc")
    PARSE_WALLET(eth, "eth")
    PARSE_WALLET(sol, "sol")
    PARSE_WALLET(qevm, "qevm")
    PARSE_WALLET(bnb, "bnb")

    #undef PARSE_WALLET
    return 0;
}

static json_object* socials_to_json(const dna_socials_t *socials) {
    json_object *obj = json_object_new_object();

    if (socials->telegram[0]) json_object_object_add(obj, "telegram",
        json_object_new_string(socials->telegram));
    if (socials->x[0]) json_object_object_add(obj, "x",
        json_object_new_string(socials->x));
    if (socials->github[0]) json_object_object_add(obj, "github",
        json_object_new_string(socials->github));
    if (socials->facebook[0]) json_object_object_add(obj, "facebook",
        json_object_new_string(socials->facebook));
    if (socials->instagram[0]) json_object_object_add(obj, "instagram",
        json_object_new_string(socials->instagram));
    if (socials->linkedin[0]) json_object_object_add(obj, "linkedin",
        json_object_new_string(socials->linkedin));
    if (socials->google[0]) json_object_object_add(obj, "google",
        json_object_new_string(socials->google));

    return obj;
}

static int socials_from_json(json_object *obj, dna_socials_t *socials) {
    memset(socials, 0, sizeof(dna_socials_t));

    json_object *val;
    #define PARSE_SOCIAL(field, key) \
        if (json_object_object_get_ex(obj, key, &val)) { \
            const char *str = json_object_get_string(val); \
            if (str) strncpy(socials->field, str, sizeof(socials->field) - 1); \
        }

    PARSE_SOCIAL(telegram, "telegram")
    PARSE_SOCIAL(x, "x")
    PARSE_SOCIAL(github, "github")
    PARSE_SOCIAL(facebook, "facebook")
    PARSE_SOCIAL(instagram, "instagram")
    PARSE_SOCIAL(linkedin, "linkedin")
    PARSE_SOCIAL(google, "google")

    #undef PARSE_SOCIAL
    return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++) {
        sprintf(&hex_out[i * 2], "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';  // Null terminate
}

static int hex_to_bytes(const char *hex, uint8_t *bytes_out, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) return -1;

    for (size_t i = 0; i < bytes_len; i++) {
        unsigned int byte;
        if (sscanf(&hex[i * 2], "%02x", &byte) != 1) return -1;
        bytes_out[i] = (uint8_t)byte;
    }
    return 0;
}

// ===== Profile Data Serialization =====

char* dna_profile_to_json(const dna_profile_data_t *profile) {
    if (!profile) return NULL;

    json_object *root = json_object_new_object();

    // Wallets
    json_object *wallets_obj = wallets_to_json(&profile->wallets);
    json_object_object_add(root, "wallets", wallets_obj);

    // Socials
    json_object *socials_obj = socials_to_json(&profile->socials);
    json_object_object_add(root, "socials", socials_obj);

    // Bio and profile picture
    if (profile->bio[0]) json_object_object_add(root, "bio",
        json_object_new_string(profile->bio));
    if (profile->profile_picture_ipfs[0]) json_object_object_add(root,
        "profile_picture_ipfs", json_object_new_string(profile->profile_picture_ipfs));
    if (profile->avatar_base64[0]) json_object_object_add(root,
        "avatar_base64", json_object_new_string(profile->avatar_base64));

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);
    json_object_put(root);

    return result;
}

int dna_profile_from_json(const char *json, dna_profile_data_t **profile_out) {
    if (!json || !profile_out) return -1;

    json_object *root = json_tokener_parse(json);
    if (!root) return -1;

    dna_profile_data_t *profile = dna_profile_create();
    if (!profile) {
        json_object_put(root);
        return -1;
    }

    json_object *val;

    // Wallets
    if (json_object_object_get_ex(root, "wallets", &val)) {
        wallets_from_json(val, &profile->wallets);
    }

    // Socials
    if (json_object_object_get_ex(root, "socials", &val)) {
        socials_from_json(val, &profile->socials);
    }

    // Bio
    if (json_object_object_get_ex(root, "bio", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(profile->bio, str, sizeof(profile->bio) - 1);
    }

    // Profile picture
    if (json_object_object_get_ex(root, "profile_picture_ipfs", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(profile->profile_picture_ipfs, str,
                        sizeof(profile->profile_picture_ipfs) - 1);
    }

    // Avatar (base64)
    if (json_object_object_get_ex(root, "avatar_base64", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(profile->avatar_base64, str,
                        sizeof(profile->avatar_base64) - 1);
    }

    json_object_put(root);
    *profile_out = profile;
    return 0;
}

// ===== Identity Serialization =====

char* dna_identity_to_json(const dna_unified_identity_t *identity) {
    if (!identity) return NULL;

    json_object *root = json_object_new_object();

    // Fingerprint and public keys (hex encoded)
    json_object_object_add(root, "fingerprint",
        json_object_new_string(identity->fingerprint));

    // Allocate hex buffer on heap (too large for stack)
    // Max size: Dilithium5 signature (4627 bytes) → 9254 hex chars + 1 null = 9255 bytes
    char *hex = malloc(9255);
    if (!hex) {
        json_object_put(root);
        return NULL;
    }

    bytes_to_hex(identity->dilithium_pubkey, sizeof(identity->dilithium_pubkey), hex);
    json_object_object_add(root, "dilithium_pubkey", json_object_new_string(hex));

    bytes_to_hex(identity->kyber_pubkey, sizeof(identity->kyber_pubkey), hex);
    json_object_object_add(root, "kyber_pubkey", json_object_new_string(hex));

    // DNA name registration
    json_object_object_add(root, "has_registered_name",
        json_object_new_boolean(identity->has_registered_name));
    if (identity->has_registered_name) {
        json_object_object_add(root, "registered_name",
            json_object_new_string(identity->registered_name));
        json_object_object_add(root, "name_registered_at",
            json_object_new_int64(identity->name_registered_at));
        json_object_object_add(root, "name_expires_at",
            json_object_new_int64(identity->name_expires_at));
        json_object_object_add(root, "registration_tx_hash",
            json_object_new_string(identity->registration_tx_hash));
        json_object_object_add(root, "registration_network",
            json_object_new_string(identity->registration_network));
        json_object_object_add(root, "name_version",
            json_object_new_int(identity->name_version));
    }

    // Wallets
    json_object *wallets_obj = wallets_to_json(&identity->wallets);
    json_object_object_add(root, "wallets", wallets_obj);

    // Socials
    json_object *socials_obj = socials_to_json(&identity->socials);
    json_object_object_add(root, "socials", socials_obj);

    // Profile data (Phase 5: Extended fields)
    if (identity->display_name[0]) json_object_object_add(root, "display_name",
        json_object_new_string(identity->display_name));
    if (identity->bio[0]) json_object_object_add(root, "bio",
        json_object_new_string(identity->bio));
    if (identity->avatar_hash[0]) json_object_object_add(root, "avatar_hash",
        json_object_new_string(identity->avatar_hash));
    if (identity->profile_picture_ipfs[0]) json_object_object_add(root,
        "profile_picture_ipfs", json_object_new_string(identity->profile_picture_ipfs));
    if (identity->location[0]) json_object_object_add(root, "location",
        json_object_new_string(identity->location));
    if (identity->website[0]) json_object_object_add(root, "website",
        json_object_new_string(identity->website));

    // Metadata (Phase 5: Extended timestamps)
    if (identity->created_at) json_object_object_add(root, "created_at",
        json_object_new_int64(identity->created_at));
    if (identity->updated_at) json_object_object_add(root, "updated_at",
        json_object_new_int64(identity->updated_at));
    json_object_object_add(root, "timestamp",
        json_object_new_int64(identity->timestamp));
    json_object_object_add(root, "version",
        json_object_new_int(identity->version));

    // Signature
    bytes_to_hex(identity->signature, sizeof(identity->signature), hex);
    json_object_object_add(root, "signature", json_object_new_string(hex));

    free(hex);  // Done with hex buffer

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);
    json_object_put(root);

    return result;
}

int dna_identity_from_json(const char *json, dna_unified_identity_t **identity_out) {
    if (!json || !identity_out) return -1;

    json_object *root = json_tokener_parse(json);
    if (!root) return -1;

    dna_unified_identity_t *identity = dna_identity_create();
    if (!identity) {
        json_object_put(root);
        return -1;
    }

    json_object *val;

    // Fingerprint
    if (json_object_object_get_ex(root, "fingerprint", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->fingerprint, str, sizeof(identity->fingerprint) - 1);
    }

    // Public keys
    if (json_object_object_get_ex(root, "dilithium_pubkey", &val)) {
        const char *hex = json_object_get_string(val);
        if (hex) hex_to_bytes(hex, identity->dilithium_pubkey,
                             sizeof(identity->dilithium_pubkey));
    }

    if (json_object_object_get_ex(root, "kyber_pubkey", &val)) {
        const char *hex = json_object_get_string(val);
        if (hex) hex_to_bytes(hex, identity->kyber_pubkey,
                             sizeof(identity->kyber_pubkey));
    }

    // DNA name registration
    if (json_object_object_get_ex(root, "has_registered_name", &val)) {
        identity->has_registered_name = json_object_get_boolean(val);
    }

    if (identity->has_registered_name) {
        if (json_object_object_get_ex(root, "registered_name", &val)) {
            const char *str = json_object_get_string(val);
            if (str) strncpy(identity->registered_name, str,
                           sizeof(identity->registered_name) - 1);
        }
        if (json_object_object_get_ex(root, "name_registered_at", &val)) {
            identity->name_registered_at = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(root, "name_expires_at", &val)) {
            identity->name_expires_at = json_object_get_int64(val);
        }
        if (json_object_object_get_ex(root, "registration_tx_hash", &val)) {
            const char *str = json_object_get_string(val);
            if (str) strncpy(identity->registration_tx_hash, str,
                           sizeof(identity->registration_tx_hash) - 1);
        }
        if (json_object_object_get_ex(root, "registration_network", &val)) {
            const char *str = json_object_get_string(val);
            if (str) strncpy(identity->registration_network, str,
                           sizeof(identity->registration_network) - 1);
        }
        if (json_object_object_get_ex(root, "name_version", &val)) {
            identity->name_version = json_object_get_int(val);
        }
    }

    // Wallets
    if (json_object_object_get_ex(root, "wallets", &val)) {
        wallets_from_json(val, &identity->wallets);
    }

    // Socials
    if (json_object_object_get_ex(root, "socials", &val)) {
        socials_from_json(val, &identity->socials);
    }

    // Profile data (Phase 5: Extended fields)
    if (json_object_object_get_ex(root, "display_name", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->display_name, str, sizeof(identity->display_name) - 1);
    }

    if (json_object_object_get_ex(root, "bio", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->bio, str, sizeof(identity->bio) - 1);
    }

    if (json_object_object_get_ex(root, "avatar_hash", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->avatar_hash, str, sizeof(identity->avatar_hash) - 1);
    }

    if (json_object_object_get_ex(root, "profile_picture_ipfs", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->profile_picture_ipfs, str,
                        sizeof(identity->profile_picture_ipfs) - 1);
    }

    if (json_object_object_get_ex(root, "location", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->location, str, sizeof(identity->location) - 1);
    }

    if (json_object_object_get_ex(root, "website", &val)) {
        const char *str = json_object_get_string(val);
        if (str) strncpy(identity->website, str, sizeof(identity->website) - 1);
    }

    // Metadata (Phase 5: Extended timestamps)
    if (json_object_object_get_ex(root, "created_at", &val)) {
        identity->created_at = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "updated_at", &val)) {
        identity->updated_at = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "timestamp", &val)) {
        identity->timestamp = json_object_get_int64(val);
    }
    if (json_object_object_get_ex(root, "version", &val)) {
        identity->version = json_object_get_int(val);
    }

    // Signature
    if (json_object_object_get_ex(root, "signature", &val)) {
        const char *hex = json_object_get_string(val);
        if (hex) hex_to_bytes(hex, identity->signature, sizeof(identity->signature));
    }

    json_object_put(root);
    *identity_out = identity;
    return 0;
}

// ===== Validation Functions =====

int dna_profile_validate(const dna_profile_data_t *profile) {
    if (!profile) return -1;

    // Check bio length (max 512 chars, not including null terminator)
    size_t bio_len = strlen(profile->bio);
    if (bio_len > 512) return -2;

    // Validate IPFS CID if set
    if (profile->profile_picture_ipfs[0]) {
        if (!dna_validate_ipfs_cid(profile->profile_picture_ipfs)) return -3;
    }

    // Validate wallet addresses
    // (Skip empty addresses)
    #define VALIDATE_WALLET(field, network) \
        if (profile->wallets.field[0]) { \
            if (!dna_validate_wallet_address(profile->wallets.field, network)) return -4; \
        }

    VALIDATE_WALLET(backbone, "backbone")
    VALIDATE_WALLET(kelvpn, "kelvpn")
    VALIDATE_WALLET(riemann, "riemann")
    VALIDATE_WALLET(raiden, "raiden")
    VALIDATE_WALLET(mileena, "mileena")
    VALIDATE_WALLET(subzero, "subzero")
    VALIDATE_WALLET(cpunk_testnet, "cpunk_testnet")
    VALIDATE_WALLET(btc, "btc")
    VALIDATE_WALLET(eth, "eth")
    VALIDATE_WALLET(sol, "sol")
    VALIDATE_WALLET(qevm, "qevm")
    VALIDATE_WALLET(bnb, "bnb")

    #undef VALIDATE_WALLET

    return 0;
}

bool dna_validate_wallet_address(const char *address, const char *network) {
    if (!address || !address[0] || !network) return false;

    size_t len = strlen(address);

    // Cellframe networks (base58, 40-120 chars)
    if (dna_network_is_cellframe(network)) {
        if (len < 40 || len > 120) return false;

        // Check first character (network prefix)
        char first = address[0];
        if (first != 'R' && first != 'o' && first != 'j' && first != 'm') {
            return false;
        }

        // Check all characters are valid base58
        const char *base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (size_t i = 0; i < len; i++) {
            if (strchr(base58, address[i]) == NULL) return false;
        }
        return true;
    }

    // Bitcoin (legacy: 1/3 + 25-34 chars, SegWit: bc1 + 39-59 chars)
    if (strcmp(network, "btc") == 0) {
        if ((address[0] == '1' || address[0] == '3') && len >= 26 && len <= 35) {
            return true;
        }
        if (strncmp(address, "bc1", 3) == 0 && len >= 42 && len <= 62) {
            return true;
        }
        return false;
    }

    // Ethereum, QEVM, BNB (0x + 40 hex chars)
    if (strcmp(network, "eth") == 0 || strcmp(network, "qevm") == 0 ||
        strcmp(network, "bnb") == 0) {
        if (len != 42 || strncmp(address, "0x", 2) != 0) return false;
        for (size_t i = 2; i < len; i++) {
            if (!isxdigit(address[i])) return false;
        }
        return true;
    }

    // Solana (base58, 32-44 chars)
    if (strcmp(network, "sol") == 0) {
        if (len < 32 || len > 44) return false;
        const char *base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (size_t i = 0; i < len; i++) {
            if (strchr(base58, address[i]) == NULL) return false;
        }
        return true;
    }

    return false;
}

bool dna_validate_ipfs_cid(const char *cid) {
    if (!cid || !cid[0]) return false;

    size_t len = strlen(cid);
    if (len < 46 || len > 64) return false;

    // CIDv0 starts with 'Qm' (base58)
    if (len == 46 && strncmp(cid, "Qm", 2) == 0) {
        const char *base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (size_t i = 0; i < len; i++) {
            if (strchr(base58, cid[i]) == NULL) return false;
        }
        return true;
    }

    // CIDv1: 'b' prefix = base32, 'z' prefix = base58
    if (cid[0] == 'b') {
        // Base32 (lowercase a-z and digits 2-7)
        for (size_t i = 0; i < len; i++) {
            char c = cid[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'))) {
                return false;
            }
        }
        return true;
    }

    if (cid[0] == 'z') {
        // Base58
        const char *base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for (size_t i = 0; i < len; i++) {
            if (strchr(base58, cid[i]) == NULL) return false;
        }
        return true;
    }

    return false;
}

bool dna_validate_name(const char *name) {
    if (!name || !name[0]) return false;

    size_t len = strlen(name);
    if (len < 3 || len > 36) return false;

    // Check characters (alphanumeric + . _ -)
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!isalnum(c) && c != '.' && c != '_' && c != '-') {
            return false;
        }
    }

    // Check for disallowed names
    char lower_name[256];
    strncpy(lower_name, name, sizeof(lower_name) - 1);
    for (char *p = lower_name; *p; p++) *p = tolower(*p);

    for (const char **disallowed = DISALLOWED_NAMES; *disallowed; disallowed++) {
        if (strcmp(lower_name, *disallowed) == 0) return false;
    }

    return true;
}

// ===== Network Helpers =====

bool dna_network_is_cellframe(const char *network) {
    if (!network) return false;

    return (strcmp(network, "backbone") == 0 ||
            strcmp(network, "kelvpn") == 0 ||
            strcmp(network, "riemann") == 0 ||
            strcmp(network, "raiden") == 0 ||
            strcmp(network, "mileena") == 0 ||
            strcmp(network, "subzero") == 0 ||
            strcmp(network, "cpunk_testnet") == 0);
}

bool dna_network_is_external(const char *network) {
    if (!network) return false;

    return (strcmp(network, "btc") == 0 ||
            strcmp(network, "eth") == 0 ||
            strcmp(network, "sol") == 0 ||
            strcmp(network, "qevm") == 0 ||
            strcmp(network, "bnb") == 0);
}

void dna_network_normalize(char *network) {
    if (!network) return;

    for (char *p = network; *p; p++) {
        *p = tolower(*p);
    }
}

// ===== Wallet Getters/Setters =====

const char* dna_identity_get_wallet(const dna_unified_identity_t *identity,
                                     const char *network) {
    if (!identity || !network) return NULL;

    char normalized[32];
    strncpy(normalized, network, sizeof(normalized) - 1);
    dna_network_normalize(normalized);

    #define CHECK_WALLET(field, name) \
        if (strcmp(normalized, name) == 0) { \
            return identity->wallets.field; \
        }

    CHECK_WALLET(backbone, "backbone")
    CHECK_WALLET(kelvpn, "kelvpn")
    CHECK_WALLET(riemann, "riemann")
    CHECK_WALLET(raiden, "raiden")
    CHECK_WALLET(mileena, "mileena")
    CHECK_WALLET(subzero, "subzero")
    CHECK_WALLET(cpunk_testnet, "cpunk_testnet")
    CHECK_WALLET(btc, "btc")
    CHECK_WALLET(eth, "eth")
    CHECK_WALLET(sol, "sol")
    CHECK_WALLET(qevm, "qevm")
    CHECK_WALLET(bnb, "bnb")

    #undef CHECK_WALLET

    return NULL;
}

int dna_identity_set_wallet(dna_unified_identity_t *identity,
                             const char *network,
                             const char *address) {
    if (!identity || !network || !address) return -1;

    char normalized[32];
    strncpy(normalized, network, sizeof(normalized) - 1);
    dna_network_normalize(normalized);

    // Validate address format
    if (!dna_validate_wallet_address(address, normalized)) return -2;

    #define SET_WALLET(field, name) \
        if (strcmp(normalized, name) == 0) { \
            strncpy(identity->wallets.field, address, sizeof(identity->wallets.field) - 1); \
            return 0; \
        }

    SET_WALLET(backbone, "backbone")
    SET_WALLET(kelvpn, "kelvpn")
    SET_WALLET(riemann, "riemann")
    SET_WALLET(raiden, "raiden")
    SET_WALLET(mileena, "mileena")
    SET_WALLET(subzero, "subzero")
    SET_WALLET(cpunk_testnet, "cpunk_testnet")
    SET_WALLET(btc, "btc")
    SET_WALLET(eth, "eth")
    SET_WALLET(sol, "sol")
    SET_WALLET(qevm, "qevm")
    SET_WALLET(bnb, "bnb")

    #undef SET_WALLET

    return -1;  // Unknown network
}

// ===== Display Profile Extraction (Phase 5) =====

void dna_identity_to_display_profile(
    const dna_unified_identity_t *identity,
    dna_display_profile_t *display_out
) {
    if (!identity || !display_out) return;

    // Initialize to zero
    memset(display_out, 0, sizeof(dna_display_profile_t));

    // Copy basic profile fields
    strncpy(display_out->fingerprint, identity->fingerprint,
            sizeof(display_out->fingerprint) - 1);
    strncpy(display_out->display_name, identity->display_name,
            sizeof(display_out->display_name) - 1);
    strncpy(display_out->bio, identity->bio,
            sizeof(display_out->bio) - 1);
    strncpy(display_out->avatar_hash, identity->avatar_hash,
            sizeof(display_out->avatar_hash) - 1);
    strncpy(display_out->location, identity->location,
            sizeof(display_out->location) - 1);
    strncpy(display_out->website, identity->website,
            sizeof(display_out->website) - 1);

    // Copy selected social links (most popular)
    strncpy(display_out->telegram, identity->socials.telegram,
            sizeof(display_out->telegram) - 1);
    strncpy(display_out->x, identity->socials.x,
            sizeof(display_out->x) - 1);
    strncpy(display_out->github, identity->socials.github,
            sizeof(display_out->github) - 1);

    // Copy selected wallet addresses (for tipping)
    strncpy(display_out->backbone, identity->wallets.backbone,
            sizeof(display_out->backbone) - 1);
    strncpy(display_out->btc, identity->wallets.btc,
            sizeof(display_out->btc) - 1);
    strncpy(display_out->eth, identity->wallets.eth,
            sizeof(display_out->eth) - 1);

    // Copy timestamp
    display_out->updated_at = identity->updated_at;
}
