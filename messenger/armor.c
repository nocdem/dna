/*
 * pqsignum - ASCII Armor Functions
 *
 * Provides PGP-style ASCII armoring for signatures and encrypted files
 */

#include "qgp.h"
#include "qgp_types.h"  // For qgp_base64_encode/decode
#include <time.h>

#define ARMOR_LINE_LENGTH 64  // Standard base64 line length

/*
 * Check if a file is ASCII armored
 * Returns: true if file starts with armor header, false otherwise
 */
bool is_armored_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }

    char line[256];
    bool is_armored = false;

    if (fgets(line, sizeof(line), f)) {
        // Check for armor begin marker
        if (strncmp(line, "-----BEGIN QGP ", 15) == 0) {
            is_armored = true;
        }
    }

    fclose(f);
    return is_armored;
}

/*
 * Write ASCII-armored data to file
 *
 * Parameters:
 *   output_path - File path to write
 *   type - Armor type ("SIGNATURE", "ENCRYPTED FILE", "PUBLIC KEY")
 *   data - Binary data to armor
 *   data_size - Size of binary data
 *   headers - Array of header strings ("Key: Value" format)
 *   header_count - Number of headers
 *
 * Returns: 0 on success, -1 on error
 */
int write_armored_file(
    const char *output_path,
    const char *type,
    const uint8_t *data,
    size_t data_size,
    const char **headers,
    size_t header_count
) {
    FILE *f = NULL;
    char *b64_data = NULL;
    int ret = -1;

    // Open output file
    f = fopen(output_path, "w");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file for writing: %s\n", output_path);
        return -1;
    }

    // Write begin marker
    fprintf(f, "-----BEGIN QGP %s-----\n", type);

    // Write headers
    for (size_t i = 0; i < header_count; i++) {
        fprintf(f, "%s\n", headers[i]);
    }
    fprintf(f, "\n");  // Blank line after headers

    size_t encoded;
    b64_data = qgp_base64_encode(data, data_size, &encoded);

    if (!b64_data || encoded == 0) {
        fprintf(stderr, "Error: Base64 encoding failed\n");
        goto cleanup;
    }

    // Write base64 in 64-character lines
    for (size_t i = 0; i < encoded; i += ARMOR_LINE_LENGTH) {
        size_t line_len = (encoded - i > ARMOR_LINE_LENGTH) ? ARMOR_LINE_LENGTH : (encoded - i);
        fprintf(f, "%.*s\n", (int)line_len, b64_data + i);
    }

    // Write end marker
    fprintf(f, "-----END QGP %s-----\n", type);

    ret = 0;  // Success

cleanup:
    if (b64_data) {
        free(b64_data);
    }
    if (f) {
        fclose(f);
    }
    return ret;
}

/*
 * Read ASCII-armored data from file
 *
 * Parameters:
 *   input_path - File path to read
 *   type_out - Output: armor type (caller must free)
 *   data_out - Output: decoded binary data (caller must free)
 *   data_size_out - Output: size of decoded data
 *   headers_out - Output: array of header strings (caller must free each and array)
 *   header_count_out - Output: number of headers
 *
 * Returns: 0 on success, -1 on error
 */
int read_armored_file(
    const char *input_path,
    char **type_out,
    uint8_t **data_out,
    size_t *data_size_out,
    char ***headers_out,
    size_t *header_count_out
) {
    FILE *f = NULL;
    char line[1024];
    char *type = NULL;
    char **headers = NULL;
    size_t header_count = 0;
    size_t header_capacity = 16;
    char *b64_data = NULL;
    size_t b64_capacity = 65536;  // Start with 64KB
    size_t b64_length = 0;
    uint8_t *decoded_data = NULL;
    size_t decoded_size = 0;
    int ret = -1;
    bool in_headers = false;
    bool in_data = false;

    // Open file
    f = fopen(input_path, "r");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file: %s\n", input_path);
        return -1;
    }

    // Allocate initial buffers
    headers = (char**)calloc(header_capacity, sizeof(char*));
    b64_data = (char*)malloc(b64_capacity);
    if (!headers || !b64_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }

    // Parse file
    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
            len--;
        }
        if (len > 0 && line[len-1] == '\r') {
            line[len-1] = '\0';
            len--;
        }

        // Check for begin marker
        if (strncmp(line, "-----BEGIN QGP ", 15) == 0) {
            // Extract type
            const char *type_start = line + 15;
            const char *type_end = strstr(type_start, "-----");
            if (!type_end) {
                fprintf(stderr, "Error: Invalid armor begin marker\n");
                goto cleanup;
            }
            size_t type_len = type_end - type_start;
            type = (char*)malloc(type_len + 1);
            if (!type) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                goto cleanup;
            }
            strncpy(type, type_start, type_len);
            type[type_len] = '\0';
            in_headers = true;
            continue;
        }

        // Check for end marker
        if (strncmp(line, "-----END QGP ", 13) == 0) {
            break;
        }

        // Parse headers
        if (in_headers) {
            if (len == 0) {
                // Blank line marks end of headers
                in_headers = false;
                in_data = true;
                continue;
            }

            // Store header
            if (header_count >= header_capacity) {
                header_capacity *= 2;
                headers = (char**)realloc(headers, header_capacity * sizeof(char*));
                if (!headers) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    goto cleanup;
                }
            }
            headers[header_count] = strdup(line);
            header_count++;
            continue;
        }

        // Parse base64 data
        if (in_data) {
            // Grow buffer if needed
            if (b64_length + len + 1 > b64_capacity) {
                b64_capacity *= 2;
                b64_data = (char*)realloc(b64_data, b64_capacity);
                if (!b64_data) {
                    fprintf(stderr, "Error: Memory allocation failed\n");
                    goto cleanup;
                }
            }
            // Append line to base64 data
            strcpy(b64_data + b64_length, line);
            b64_length += len;
        }
    }

    decoded_data = qgp_base64_decode(b64_data, &decoded_size);

    if (!decoded_data || decoded_size == 0) {
        fprintf(stderr, "Error: Base64 decoding failed\n");
        goto cleanup;
    }

    size_t actual_decoded = decoded_size;

    // Return results
    *type_out = type;
    *data_out = decoded_data;
    *data_size_out = actual_decoded;
    *headers_out = headers;
    *header_count_out = header_count;

    ret = 0;  // Success
    type = NULL;  // Don't free, caller owns
    decoded_data = NULL;  // Don't free, caller owns
    headers = NULL;  // Don't free, caller owns

cleanup:
    if (f) {
        fclose(f);
    }
    if (b64_data) {
        free(b64_data);
    }
    if (type) {
        free(type);
    }
    if (decoded_data) {
        free(decoded_data);
    }
    if (headers) {
        for (size_t i = 0; i < header_count; i++) {
            free(headers[i]);
        }
        free(headers);
    }

    return ret;
}

/*
 * Get signature algorithm name for headers
 */
const char* get_signature_algorithm_name(const qgp_signature_t *signature) {
    if (!signature) {
        return "Unknown";
    }

    switch (signature->type) {
        case QGP_SIG_TYPE_DILITHIUM:
            return "Dilithium";
        default:
            return "Unknown";
    }
}

/*
 * Build headers for signature armor
 * Returns: number of headers created
 */
size_t build_signature_headers(const qgp_signature_t *signature, const char **headers, size_t max_headers) {
    size_t count = 0;
    static char header_buf[10][128];  // Static buffers for headers

    if (count < max_headers) {
        snprintf(header_buf[count], sizeof(header_buf[count]), "Version: qgp 1.1");
        headers[count] = header_buf[count];
        count++;
    }

    if (count < max_headers) {
        snprintf(header_buf[count], sizeof(header_buf[count]), "Algorithm: %s",
                 get_signature_algorithm_name(signature));
        headers[count] = header_buf[count];
        count++;
    }

    if (count < max_headers) {
        snprintf(header_buf[count], sizeof(header_buf[count]), "Hash: SHA3-256");
        headers[count] = header_buf[count];
        count++;
    }

    if (count < max_headers) {
        time_t now = time(NULL);
        struct tm *tm_info = gmtime(&now);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S UTC", tm_info);
        snprintf(header_buf[count], sizeof(header_buf[count]), "Created: %s", time_str);
        headers[count] = header_buf[count];
        count++;
    }

    return count;
}
