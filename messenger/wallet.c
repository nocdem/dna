/*
 * wallet.c - Cellframe Wallet Reader for DNA Messenger
 *
 * Reads Cellframe wallet files (.dwallet format) from standard locations.
 */

#include "wallet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define stat _stat
#else
#include <dirent.h>
#include <unistd.h>
#endif

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Check if file exists
 */
static bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

/**
 * Get file size
 */
static long get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return (long)st.st_size;
}

// ============================================================================
// WALLET READING
// ============================================================================

/**
 * Read Cellframe wallet from full path
 */
int wallet_read_cellframe_path(const char *path, cellframe_wallet_t **wallet_out) {
    if (!path || !wallet_out) {
        fprintf(stderr, "wallet_read_cellframe_path: Invalid arguments\n");
        return -1;
    }

    if (!file_exists(path)) {
        fprintf(stderr, "wallet_read_cellframe_path: File not found: %s\n", path);
        return -1;
    }

    // Get file size
    long file_size = get_file_size(path);
    if (file_size < 0) {
        fprintf(stderr, "wallet_read_cellframe_path: Cannot get file size: %s\n", path);
        return -1;
    }

    // Read entire file
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "wallet_read_cellframe_path: Cannot open file: %s\n", path);
        return -1;
    }

    uint8_t *file_data = malloc(file_size);
    if (!file_data) {
        fprintf(stderr, "wallet_read_cellframe_path: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }

    if (fread(file_data, 1, file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "wallet_read_cellframe_path: Failed to read file\n");
        free(file_data);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    // Allocate wallet structure
    cellframe_wallet_t *wallet = calloc(1, sizeof(cellframe_wallet_t));
    if (!wallet) {
        fprintf(stderr, "wallet_read_cellframe_path: Memory allocation failed\n");
        free(file_data);
        return -1;
    }

    // Extract filename from path
    const char *filename = strrchr(path, '/');
    if (!filename) {
        filename = strrchr(path, '\\');  // Windows
    }
    filename = filename ? filename + 1 : path;

    strncpy(wallet->filename, filename, WALLET_NAME_MAX - 1);

    // Extract wallet name (remove .dwallet extension)
    strncpy(wallet->name, filename, WALLET_NAME_MAX - 1);
    char *ext = strstr(wallet->name, ".dwallet");
    if (ext) {
        *ext = '\0';
    }

    // Parse wallet file format
    // From hexdump analysis:
    // - Offset 0x0E-0x1C: Wallet name (null-terminated)
    // - After that: Key material

    // Try to extract wallet name from file data
    if (file_size > 0x1C) {
        // Look for wallet name string in file
        size_t offset = 0x0E;
        if (offset + strlen(wallet->name) < (size_t)file_size) {
            char file_name[WALLET_NAME_MAX];
            size_t i;
            for (i = 0; i < WALLET_NAME_MAX - 1 && offset + i < (size_t)file_size; i++) {
                uint8_t c = file_data[offset + i];
                if (c == 0 || c < 32 || c > 126) {
                    break;
                }
                file_name[i] = c;
            }
            file_name[i] = '\0';

            if (i > 0 && strstr(file_name, wallet->name) != NULL) {
                // Found wallet name in file
                strncpy(wallet->name, file_name, WALLET_NAME_MAX - 1);
            }
        }
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

    // Default to unprotected (we can enhance this later)
    wallet->status = WALLET_STATUS_UNPROTECTED;
    wallet->deprecated = false;

    // Store raw key data (entire file for now - we can parse this better later)
    // The key material starts after the header (around offset 0x90 from hexdump)
    size_t key_data_offset = 0x90;
    if (file_size > key_data_offset) {
        wallet->public_key_size = file_size - key_data_offset;
        wallet->public_key = malloc(wallet->public_key_size);
        if (wallet->public_key) {
            memcpy(wallet->public_key, file_data + key_data_offset, wallet->public_key_size);
        }
    }

    free(file_data);
    *wallet_out = wallet;
    return 0;
}

/**
 * Read a specific Cellframe wallet file from standard directory
 */
int wallet_read_cellframe(const char *filename, cellframe_wallet_t **wallet_out) {
    if (!filename || !wallet_out) {
        fprintf(stderr, "wallet_read_cellframe: Invalid arguments\n");
        return -1;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", CELLFRAME_WALLET_PATH, filename);

    return wallet_read_cellframe_path(path, wallet_out);
}

/**
 * List all Cellframe wallets in standard directory
 */
int wallet_list_cellframe(wallet_list_t **list_out) {
    if (!list_out) {
        fprintf(stderr, "wallet_list_cellframe: Invalid arguments\n");
        return -1;
    }

    // Check if wallet directory exists
    if (!file_exists(CELLFRAME_WALLET_PATH)) {
        fprintf(stderr, "wallet_list_cellframe: Wallet directory not found: %s\n", CELLFRAME_WALLET_PATH);
        return -1;
    }

    // Allocate list structure
    wallet_list_t *list = calloc(1, sizeof(wallet_list_t));
    if (!list) {
        fprintf(stderr, "wallet_list_cellframe: Memory allocation failed\n");
        return -1;
    }

    // Count .dwallet files
    size_t capacity = 10;
    list->wallets = calloc(capacity, sizeof(cellframe_wallet_t));
    if (!list->wallets) {
        fprintf(stderr, "wallet_list_cellframe: Memory allocation failed\n");
        free(list);
        return -1;
    }

#ifdef _WIN32
    // Windows: Use FindFirstFile/FindNextFile
    WIN32_FIND_DATA find_data;
    char search_path[1024];
    snprintf(search_path, sizeof(search_path), "%s\\*.dwallet", CELLFRAME_WALLET_PATH);

    HANDLE hFind = FindFirstFile(search_path, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        free(list->wallets);
        free(list);
        *list_out = list;  // Return empty list
        return 0;
    }

    do {
        if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            // Read wallet file
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
                free(wallet);  // Free structure but not contents (copied above)
            }
        }
    } while (FindNextFile(hFind, &find_data));

    FindClose(hFind);
#else
    // Linux/Unix: Use opendir/readdir
    DIR *dir = opendir(CELLFRAME_WALLET_PATH);
    if (!dir) {
        free(list->wallets);
        free(list);
        *list_out = list;  // Return empty list
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Check if file ends with .dwallet
        size_t name_len = strlen(entry->d_name);
        if (name_len < 8 || strcmp(entry->d_name + name_len - 8, ".dwallet") != 0) {
            continue;
        }

        // Read wallet file
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
            free(wallet);  // Free structure but not contents (copied above)
        }
    }

    closedir(dir);
#endif

    *list_out = list;
    return 0;
}

/**
 * Get wallet address for specific network
 */
int wallet_get_address(const cellframe_wallet_t *wallet, const char *network_name, char *address_out) {
    if (!wallet || !network_name || !address_out) {
        fprintf(stderr, "wallet_get_address: Invalid arguments\n");
        return -1;
    }

    // TODO: Implement address derivation for different networks
    // For now, just return placeholder
    snprintf(address_out, WALLET_ADDRESS_MAX, "%s:%s", network_name, wallet->name);
    return 0;
}

// ============================================================================
// CLEANUP FUNCTIONS
// ============================================================================

/**
 * Free a single wallet structure
 */
void wallet_free(cellframe_wallet_t *wallet) {
    if (!wallet) {
        return;
    }

    if (wallet->public_key) {
        // Securely wipe key material
        memset(wallet->public_key, 0, wallet->public_key_size);
        free(wallet->public_key);
    }

    if (wallet->private_key) {
        // Securely wipe key material
        memset(wallet->private_key, 0, wallet->private_key_size);
        free(wallet->private_key);
    }

    free(wallet);
}

/**
 * Free wallet list
 */
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

/**
 * Get signature type name as string
 */
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
