/*
 * wallet.c - Cellframe Wallet Reader for DNA Messenger
 *
 * Reads Cellframe wallet files (.dwallet format) for CF20 token operations.
 */

#include "cellframe_wallet.h"
#include "cellframe_addr.h"
#include "../../crypto/utils/qgp_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define stat _stat
#define popen _popen
#define pclose _pclose
#else
#include <dirent.h>
#include <unistd.h>
#endif

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

static bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

static long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (long)st.st_size;
}

static int ensure_directory(const char *path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0755);
#endif
}

static void get_dna_wallets_dir(char *path, size_t size) {
    const char *home = qgp_platform_home_dir();
    snprintf(path, size, "%s/.dna/wallets", home);
}

static int copy_file(const char *src, const char *dst) {
    FILE *src_file = fopen(src, "rb");
    if (!src_file) {
        return -1;
    }
    
    FILE *dst_file = fopen(dst, "wb");
    if (!dst_file) {
        fclose(src_file);
        return -1;
    }
    
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        if (fwrite(buffer, 1, bytes, dst_file) != bytes) {
            fclose(src_file);
            fclose(dst_file);
            return -1;
        }
    }
    
    fclose(src_file);
    fclose(dst_file);
    return 0;
}

// ============================================================================
// WALLET READING
// ============================================================================

int wallet_read_cellframe_path(const char *path, cellframe_wallet_t **wallet_out) {
    if (!path || !wallet_out) {
        return -1;
    }

    if (!file_exists(path)) {
        return -1;
    }

    long file_size = get_file_size(path);
    if (file_size < 0) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        fclose(fp);
        return -1;
    }

    if (fread(file_data, 1, file_size, fp) != (size_t)file_size) {
        free(file_data);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    cellframe_wallet_t *wallet = calloc(1, sizeof(cellframe_wallet_t));
    if (!wallet) {
        free(file_data);
        return -1;
    }

    // Extract filename
    const char *filename = strrchr(path, '/');
    if (!filename) {
        filename = strrchr(path, '\\');
    }
    filename = filename ? filename + 1 : path;

    strncpy(wallet->filename, filename, WALLET_NAME_MAX - 1);

    // Extract wallet name (remove .dwallet extension)
    strncpy(wallet->name, filename, WALLET_NAME_MAX - 1);
    char *ext = strstr(wallet->name, ".dwallet");
    if (ext) {
        *ext = '\0';
    }

    // Determine signature type from filename
    if (strstr(wallet->filename, "dilithium") || strstr(wallet->filename, "_dil")) {
        wallet->sig_type = WALLET_SIG_DILITHIUM;
    } else if (strstr(wallet->filename, "picnic")) {
        wallet->sig_type = WALLET_SIG_PICNIC;
    } else if (strstr(wallet->filename, "bliss")) {
        wallet->sig_type = WALLET_SIG_BLISS;
    } else if (strstr(wallet->filename, "tesla")) {
        wallet->sig_type = WALLET_SIG_TESLA;
    } else {
        wallet->sig_type = WALLET_SIG_UNKNOWN;
    }

    wallet->deprecated = false;

    // Read wallet file header to check if protected
    // Cellframe wallet file structure:
    // - Fixed header: 23 bytes
    //   - signature (8 bytes)
    //   - version (4 bytes) <- offset 0x08
    //   - type (1 byte)
    //   - padding (8 bytes)
    //   - wallet_len (2 bytes) <- offset 0x15
    // - Wallet name: variable length
    // - Cert header: 8 bytes
    // - Cert data: contains serialized public key (or encrypted if version 2)

    if (file_size < 23) {
//         fprintf(stderr, "[DEBUG] File too small to contain wallet header: %ld bytes\n", file_size);
        free(file_data);
        *wallet_out = wallet;
        return 0;
    }

    // Read version from file header (uint32_t at offset 0x08)
    uint32_t wallet_version;
    memcpy(&wallet_version, file_data + 0x08, 4);

    // Check if wallet is protected (version 2)
    // Version 1: Unprotected (plain certificate data)
    // Version 2: Protected (encrypted certificate data with GOST89)
    if (wallet_version == 2) {
        wallet->status = WALLET_STATUS_PROTECTED;
        wallet->address[0] = '\0';  // Cannot generate address without password
        // fprintf(stderr, "[DEBUG] Wallet %s is PROTECTED (version 2), password required for address\n",
        //         wallet->name);
        free(file_data);
        *wallet_out = wallet;
        return 0;
    }

    wallet->status = WALLET_STATUS_UNPROTECTED;

    // Read wallet_len from file header (uint16_t at offset 0x15, little-endian)
    uint16_t wallet_len;
    memcpy(&wallet_len, file_data + 0x15, 2);

    // Calculate offset to serialized public key:
    // Fixed header (23) + wallet_len + cert header (8) + offset into cert data (0x59)
    size_t serialized_offset = 23 + wallet_len + 8 + 0x59;

    // fprintf(stderr, "[DEBUG] Wallet: %s, version=%u, file_size=%ld, wallet_len=%u, calculated_offset=0x%zx\n",
    //         wallet->name, wallet_version, file_size, wallet_len, serialized_offset);

    if (file_size > (long)(serialized_offset + 8)) {
        // Read length field (first 8 bytes of serialized data)
        uint64_t serialized_len;
        memcpy(&serialized_len, file_data + serialized_offset, 8);

//         fprintf(stderr, "[DEBUG] serialized_len=%lu\n", serialized_len);

        // Validate length
        if (serialized_len > 0 && serialized_len <= (file_size - serialized_offset)) {
            wallet->public_key_size = serialized_len;
            wallet->public_key = malloc(wallet->public_key_size);
            if (wallet->public_key) {
                memcpy(wallet->public_key, file_data + serialized_offset, wallet->public_key_size);

                // Generate Cellframe address from serialized public key
                if (cellframe_addr_from_pubkey(wallet->public_key, wallet->public_key_size,
                                              CELLFRAME_NET_BACKBONE, wallet->address) != 0) {
                    // Address generation failed, set empty
//                     fprintf(stderr, "[DEBUG] Address generation FAILED for wallet: %s\n", wallet->name);
                    wallet->address[0] = '\0';
                } else {
//                     fprintf(stderr, "[DEBUG] Address generated successfully: %.50s...\n", wallet->address);
                }

                // Extract private key (follows immediately after public key)
                size_t privkey_offset = serialized_offset + serialized_len;
                if (file_size > (long)(privkey_offset + 8)) {
                    uint64_t privkey_serialized_len;
                    memcpy(&privkey_serialized_len, file_data + privkey_offset, 8);

                    // fprintf(stderr, "[DEBUG] Private key serialized_len=%lu at offset=0x%zx\n",
                    //         privkey_serialized_len, privkey_offset);

                    // Validate private key length
                    if (privkey_serialized_len > 0 &&
                        privkey_serialized_len <= (file_size - privkey_offset)) {
                        wallet->private_key_size = privkey_serialized_len;
                        wallet->private_key = malloc(wallet->private_key_size);
                        if (wallet->private_key) {
                            memcpy(wallet->private_key, file_data + privkey_offset,
                                   wallet->private_key_size);
                            // fprintf(stderr, "[DEBUG] Private key extracted: %zu bytes (with header)\n",
                            //         wallet->private_key_size);
                        } else {
//                             fprintf(stderr, "[DEBUG] malloc failed for private_key\n");
                            wallet->private_key_size = 0;
                        }
                    } else {
                        // fprintf(stderr, "[DEBUG] Invalid private key length: %lu\n",
                        //         privkey_serialized_len);
                    }
                } else {
                    // fprintf(stderr, "[DEBUG] File too small for private key: %ld bytes (need >= %zu)\n",
                    //         file_size, privkey_offset + 8);
                }

            } else {
//                 fprintf(stderr, "[DEBUG] malloc failed for public_key\n");
            }
        } else {
            // fprintf(stderr, "[DEBUG] Invalid serialized_len: %lu (file_size=%ld, offset=%zu)\n",
            //         serialized_len, file_size, serialized_offset);
        }
    } else {
        // fprintf(stderr, "[DEBUG] File too small: %ld bytes (need at least %zu)\n",
        //         file_size, serialized_offset + 8);
    }

    free(file_data);
    *wallet_out = wallet;
    return 0;
}

int wallet_read_cellframe(const char *filename, cellframe_wallet_t **wallet_out) {
    if (!filename || !wallet_out) {
        return -1;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", CELLFRAME_WALLET_PATH, filename);

    return wallet_read_cellframe_path(path, wallet_out);
}

int wallet_list_cellframe(wallet_list_t **list_out) {
    if (!list_out) {
        return -1;
    }

    if (!file_exists(CELLFRAME_WALLET_PATH)) {
        return -1;
    }

    wallet_list_t *list = calloc(1, sizeof(wallet_list_t));
    if (!list) {
        return -1;
    }

    size_t capacity = 10;
    list->wallets = calloc(capacity, sizeof(cellframe_wallet_t));
    if (!list->wallets) {
        free(list);
        return -1;
    }

#ifdef _WIN32
    WIN32_FIND_DATA find_data;
    char search_path[1024];
    snprintf(search_path, sizeof(search_path), "%s\\*.dwallet", CELLFRAME_WALLET_PATH);

    HANDLE hFind = FindFirstFile(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        free(list->wallets);
        free(list);
        *list_out = list;
        return 0;
    }

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe(find_data.cFileName, &wallet) == 0 && wallet) {
                if (list->count >= capacity) {
                    capacity *= 2;
                    cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                              capacity * sizeof(cellframe_wallet_t));
                    if (!new_wallets) {
                        wallet_free(wallet);
                        break;
                    }
                    list->wallets = new_wallets;
                }

                memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
                list->count++;
                free(wallet);
            }
        }
    } while (FindNextFile(hFind, &find_data));

    FindClose(hFind);
#else
    DIR *dir = opendir(CELLFRAME_WALLET_PATH);
    if (!dir) {
        free(list->wallets);
        free(list);
        *list_out = list;
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len < 8 || strcmp(entry->d_name + name_len - 8, ".dwallet") != 0) {
            continue;
        }

        cellframe_wallet_t *wallet = NULL;
        if (wallet_read_cellframe(entry->d_name, &wallet) == 0 && wallet) {
            if (list->count >= capacity) {
                capacity *= 2;
                cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                          capacity * sizeof(cellframe_wallet_t));
                if (!new_wallets) {
                    wallet_free(wallet);
                    break;
                }
                list->wallets = new_wallets;
            }

            memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
            list->count++;
            free(wallet);
        }
    }

    closedir(dir);
#endif

    *list_out = list;
    return 0;
}

int wallet_list_from_dna_dir(wallet_list_t **list_out) {
    if (!list_out) {
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    if (!home) {
        return -1;
    }

    char dna_dir[512];
    snprintf(dna_dir, sizeof(dna_dir), "%s/.dna", home);

    wallet_list_t *list = calloc(1, sizeof(wallet_list_t));
    if (!list) {
        return -1;
    }

    size_t capacity = 10;
    list->wallets = calloc(capacity, sizeof(cellframe_wallet_t));
    if (!list->wallets) {
        free(list);
        return -1;
    }

#ifdef _WIN32
    // Scan each identity directory in ~/.dna/
    WIN32_FIND_DATA identity_data;
    char identity_search[1024];
    snprintf(identity_search, sizeof(identity_search), "%s\\*", dna_dir);

    HANDLE hIdentity = FindFirstFile(identity_search, &identity_data);
    if (hIdentity == INVALID_HANDLE_VALUE) {
        *list_out = list;
        return 0;
    }

    do {
        if (!(identity_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(identity_data.cFileName, ".") == 0) continue;
        if (strcmp(identity_data.cFileName, "..") == 0) continue;

        // Check wallets subdirectory
        char wallets_dir[1024];
        snprintf(wallets_dir, sizeof(wallets_dir), "%s\\%s\\wallets", dna_dir, identity_data.cFileName);

        WIN32_FIND_DATA wallet_data;
        char wallet_search[1024];
        snprintf(wallet_search, sizeof(wallet_search), "%s\\*.dwallet", wallets_dir);

        HANDLE hWallet = FindFirstFile(wallet_search, &wallet_data);
        if (hWallet == INVALID_HANDLE_VALUE) continue;

        do {
            if (wallet_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s\\%s", wallets_dir, wallet_data.cFileName);

            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe_path(full_path, &wallet) == 0 && wallet) {
                if (list->count >= capacity) {
                    capacity *= 2;
                    cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                              capacity * sizeof(cellframe_wallet_t));
                    if (!new_wallets) {
                        wallet_free(wallet);
                        break;
                    }
                    list->wallets = new_wallets;
                }
                memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
                list->count++;
                free(wallet);
            }
        } while (FindNextFile(hWallet, &wallet_data));

        FindClose(hWallet);
    } while (FindNextFile(hIdentity, &identity_data));

    FindClose(hIdentity);
#else
    // Scan each identity directory in ~/.dna/
    DIR *base_dir = opendir(dna_dir);
    if (!base_dir) {
        *list_out = list;
        return 0;
    }

    struct dirent *identity_entry;
    while ((identity_entry = readdir(base_dir)) != NULL) {
        if (strcmp(identity_entry->d_name, ".") == 0) continue;
        if (strcmp(identity_entry->d_name, "..") == 0) continue;

        // Check wallets subdirectory
        char wallets_dir[1024];
        snprintf(wallets_dir, sizeof(wallets_dir), "%s/%s/wallets", dna_dir, identity_entry->d_name);

        DIR *wallet_dir = opendir(wallets_dir);
        if (!wallet_dir) continue;

        struct dirent *wallet_entry;
        while ((wallet_entry = readdir(wallet_dir)) != NULL) {
            size_t name_len = strlen(wallet_entry->d_name);
            if (name_len < 8 || strcmp(wallet_entry->d_name + name_len - 8, ".dwallet") != 0) {
                continue;
            }

            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", wallets_dir, wallet_entry->d_name);

            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe_path(full_path, &wallet) == 0 && wallet) {
                if (list->count >= capacity) {
                    capacity *= 2;
                    cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                              capacity * sizeof(cellframe_wallet_t));
                    if (!new_wallets) {
                        wallet_free(wallet);
                        break;
                    }
                    list->wallets = new_wallets;
                }
                memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
                list->count++;
                free(wallet);
            }
        }
        closedir(wallet_dir);
    }

    closedir(base_dir);
#endif

    *list_out = list;
    return 0;
}

/**
 * List wallets for a specific identity from ~/.dna/<fingerprint>/wallets/
 */
int wallet_list_for_identity(const char *fingerprint, wallet_list_t **list_out) {
    if (!fingerprint || !list_out) {
        return -1;
    }

    const char *home = qgp_platform_home_dir();
    if (!home) {
        return -1;
    }

    wallet_list_t *list = calloc(1, sizeof(wallet_list_t));
    if (!list) {
        return -1;
    }

    size_t capacity = 4;
    list->wallets = calloc(capacity, sizeof(cellframe_wallet_t));
    if (!list->wallets) {
        free(list);
        return -1;
    }

    // Build path: ~/.dna/<fingerprint>/wallets/
    char wallets_dir[1024];
    snprintf(wallets_dir, sizeof(wallets_dir), "%s/.dna/%s/wallets", home, fingerprint);

#ifdef _WIN32
    WIN32_FIND_DATA wallet_data;
    char wallet_search[1024];
    snprintf(wallet_search, sizeof(wallet_search), "%s\\*.dwallet", wallets_dir);

    HANDLE hWallet = FindFirstFile(wallet_search, &wallet_data);
    if (hWallet != INVALID_HANDLE_VALUE) {
        do {
            if (wallet_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s\\%s", wallets_dir, wallet_data.cFileName);

            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe_path(full_path, &wallet) == 0 && wallet) {
                if (list->count >= capacity) {
                    capacity *= 2;
                    cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                              capacity * sizeof(cellframe_wallet_t));
                    if (!new_wallets) {
                        wallet_free(wallet);
                        break;
                    }
                    list->wallets = new_wallets;
                }
                memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
                list->count++;
                free(wallet);
            }
        } while (FindNextFile(hWallet, &wallet_data));

        FindClose(hWallet);
    }
#else
    DIR *wallet_dir = opendir(wallets_dir);
    if (wallet_dir) {
        struct dirent *wallet_entry;
        while ((wallet_entry = readdir(wallet_dir)) != NULL) {
            size_t name_len = strlen(wallet_entry->d_name);
            if (name_len < 8 || strcmp(wallet_entry->d_name + name_len - 8, ".dwallet") != 0) {
                continue;
            }

            char full_path[1024];
            snprintf(full_path, sizeof(full_path), "%s/%s", wallets_dir, wallet_entry->d_name);

            cellframe_wallet_t *wallet = NULL;
            if (wallet_read_cellframe_path(full_path, &wallet) == 0 && wallet) {
                if (list->count >= capacity) {
                    capacity *= 2;
                    cellframe_wallet_t *new_wallets = realloc(list->wallets,
                                                              capacity * sizeof(cellframe_wallet_t));
                    if (!new_wallets) {
                        wallet_free(wallet);
                        break;
                    }
                    list->wallets = new_wallets;
                }
                memcpy(&list->wallets[list->count], wallet, sizeof(cellframe_wallet_t));
                list->count++;
                free(wallet);
            }
        }
        closedir(wallet_dir);
    }
#endif

    *list_out = list;
    return 0;
}

/**
 * Get wallet address (returns the address generated from public key)
 */
int wallet_get_address(const cellframe_wallet_t *wallet, const char *network_name, char *address_out) {
    if (!wallet || !network_name || !address_out) {
        return -1;
    }

    // Address was already generated when wallet was read
    if (wallet->address[0] == '\0') {
        return -1;  // No address available
    }

    strncpy(address_out, wallet->address, WALLET_ADDRESS_MAX - 1);
    address_out[WALLET_ADDRESS_MAX - 1] = '\0';

    return 0;
}

// ============================================================================
// CLEANUP FUNCTIONS
// ============================================================================

void wallet_free(cellframe_wallet_t *wallet) {
    if (!wallet) {
        return;
    }

    if (wallet->public_key) {
        memset(wallet->public_key, 0, wallet->public_key_size);
        free(wallet->public_key);
    }

    if (wallet->private_key) {
        memset(wallet->private_key, 0, wallet->private_key_size);
        free(wallet->private_key);
    }

    free(wallet);
}

void wallet_list_free(wallet_list_t *list) {
    if (!list) {
        return;
    }

    if (list->wallets) {
        for (size_t i = 0; i < list->count; i++) {
            if (list->wallets[i].public_key) {
                memset(list->wallets[i].public_key, 0, list->wallets[i].public_key_size);
                free(list->wallets[i].public_key);
            }
            if (list->wallets[i].private_key) {
                memset(list->wallets[i].private_key, 0, list->wallets[i].private_key_size);
                free(list->wallets[i].private_key);
            }
        }
        free(list->wallets);
    }

    free(list);
}

const char* wallet_sig_type_name(wallet_sig_type_t sig_type) {
    switch (sig_type) {
        case WALLET_SIG_DILITHIUM:
            return "sig_dil";
        case WALLET_SIG_PICNIC:
            return "sig_picnic";
        case WALLET_SIG_BLISS:
            return "sig_bliss";
        case WALLET_SIG_TESLA:
            return "sig_tesla";
        case WALLET_SIG_UNKNOWN:
        default:
            return "unknown";
    }
}
