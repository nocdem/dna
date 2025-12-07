/**
 * @file avatar_utils.c
 * @brief Avatar image processing implementation
 *
 * Uses stb_image libraries for loading/resizing/encoding avatar images.
 * Converts to 64x64 PNG and encodes to base64 for DHT storage.
 */

#include "avatar_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define STB implementations (only in this file)
#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_RESIZE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#define STBI_ONLY_GIF

#include "../../vendor/stb/stb_image.h"
#include "../../vendor/stb/stb_image_resize2.h"
#include "../../vendor/stb/stb_image_write.h"
#include "qgp_log.h"

#define LOG_TAG "AVATAR"

// Base64 encoding table
static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * @brief Encode binary data to base64
 *
 * @param data Input binary data
 * @param len Length of input data
 * @param out Output buffer for base64 string
 * @param out_len Size of output buffer
 * @return 0 on success, -1 on error
 */
static int base64_encode(const unsigned char *data, size_t len, char *out, size_t out_len) {
    size_t encoded_len = ((len + 2) / 3) * 4;
    if (encoded_len >= out_len) {
        QGP_LOG_ERROR(LOG_TAG, "Base64 output buffer too small\n");
        return -1;
    }

    size_t i = 0, j = 0;
    unsigned char byte3[3];
    unsigned char byte4[4];

    while (len--) {
        byte3[i++] = *(data++);
        if (i == 3) {
            byte4[0] = (byte3[0] & 0xfc) >> 2;
            byte4[1] = ((byte3[0] & 0x03) << 4) + ((byte3[1] & 0xf0) >> 4);
            byte4[2] = ((byte3[1] & 0x0f) << 2) + ((byte3[2] & 0xc0) >> 6);
            byte4[3] = byte3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                out[j++] = base64_chars[byte4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (size_t k = i; k < 3; k++) {
            byte3[k] = '\0';
        }

        byte4[0] = (byte3[0] & 0xfc) >> 2;
        byte4[1] = ((byte3[0] & 0x03) << 4) + ((byte3[1] & 0xf0) >> 4);
        byte4[2] = ((byte3[1] & 0x0f) << 2) + ((byte3[2] & 0xc0) >> 6);

        for (size_t k = 0; k < i + 1; k++) {
            out[j++] = base64_chars[byte4[k]];
        }

        while (i++ < 3) {
            out[j++] = '=';
        }
    }

    out[j] = '\0';
    return 0;
}

/**
 * @brief Decode base64 character to 6-bit value
 *
 * @param c Base64 character
 * @return 6-bit value, or -1 if invalid
 */
static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -1;
    return -2; // Invalid character
}

/**
 * @brief Decode base64 string to binary data
 *
 * @param data Base64 string
 * @param out Output buffer for binary data (allocated by caller)
 * @param out_len Output parameter for decoded length
 * @return 0 on success, -1 on error
 */
static int base64_decode(const char *data, unsigned char **out, size_t *out_len) {
    size_t len = strlen(data);
    if (len % 4 != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid base64 length\n");
        return -1;
    }

    size_t padding = 0;
    if (len > 0 && data[len - 1] == '=') padding++;
    if (len > 1 && data[len - 2] == '=') padding++;

    size_t decoded_len = (len / 4) * 3 - padding;
    *out = (unsigned char*)malloc(decoded_len);
    if (!*out) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate decode buffer\n");
        return -1;
    }

    size_t i = 0, j = 0;
    unsigned char byte4[4];

    while (i < len) {
        for (size_t k = 0; k < 4; k++) {
            int val = base64_decode_char(data[i++]);
            if (val == -2) {
                QGP_LOG_ERROR(LOG_TAG, "Invalid base64 character\n");
                free(*out);
                *out = NULL;
                return -1;
            }
            byte4[k] = (val == -1) ? 0 : (unsigned char)val;
        }

        (*out)[j++] = (byte4[0] << 2) + ((byte4[1] & 0x30) >> 4);
        if (j < decoded_len) {
            (*out)[j++] = ((byte4[1] & 0xf) << 4) + ((byte4[2] & 0x3c) >> 2);
        }
        if (j < decoded_len) {
            (*out)[j++] = ((byte4[2] & 0x3) << 6) + byte4[3];
        }
    }

    *out_len = decoded_len;
    return 0;
}

/**
 * @brief JPEG/image output buffer structure
 */
typedef struct {
    unsigned char *data;
    int len;
    int capacity;
} png_buffer_t;

/**
 * @brief JPEG/image write callback for stbi_write functions
 */
static void png_write_callback(void *context, void *data, int size) {
    png_buffer_t *output = (png_buffer_t*)context;
    if (output->len + size > output->capacity) {
        int new_capacity = (output->capacity == 0) ? size * 2 : output->capacity * 2;
        while (new_capacity < output->len + size) {
            new_capacity *= 2;
        }
        output->data = (unsigned char*)realloc(output->data, new_capacity);
        output->capacity = new_capacity;
    }
    memcpy(output->data + output->len, data, size);
    output->len += size;
}

/**
 * @brief Load image from file, resize to 64x64, and encode to base64
 *
 * Supports common image formats (PNG, JPEG, BMP, GIF) via stb_image.
 * Automatically resizes to 64x64 and encodes as PNG base64.
 *
 * @param file_path Path to image file
 * @param base64_out Output buffer for base64 string (min 12288 bytes)
 * @param max_len Maximum length of output buffer
 * @return 0 on success, -1 on error
 */
int avatar_load_and_encode(const char *file_path, char *base64_out, size_t max_len) {
    if (!file_path || !base64_out || max_len < 12288) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return -1;
    }

    // Load image
    int width, height, channels;
    unsigned char *img = stbi_load(file_path, &width, &height, &channels, 4); // Force RGBA
    if (!img) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load image: %s\n", stbi_failure_reason());
        return -1;
    }

    // Resize to 64x64
    unsigned char *resized = (unsigned char*)malloc(64 * 64 * 4);
    if (!resized) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate resize buffer\n");
        stbi_image_free(img);
        return -1;
    }

    if (!stbir_resize_uint8_linear(img, width, height, 0,
                                    resized, 64, 64, 0,
                                    STBIR_RGBA)) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to resize image\n");
        free(resized);
        stbi_image_free(img);
        return -1;
    }

    stbi_image_free(img);

    // Encode to JPEG (in memory) with 85% quality for smaller file size
    png_buffer_t jpeg_output = {NULL, 0, 0};

    // Write JPEG to memory using callback (quality: 85 = good balance of size/quality)
    stbi_write_jpg_to_func(png_write_callback, &jpeg_output, 64, 64, 4, resized, 85);

    free(resized);

    if (!jpeg_output.data || jpeg_output.len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode JPEG\n");
        return -1;
    }
    
    QGP_LOG_INFO(LOG_TAG, "JPEG size: %d bytes\n", jpeg_output.len);
    
    // Check if base64 will fit (base64 is ~4/3 of original size)
    size_t estimated_base64_size = ((jpeg_output.len + 2) / 3) * 4;
    if (estimated_base64_size >= max_len) {
        QGP_LOG_ERROR(LOG_TAG, "Avatar too large: %zu bytes base64 (max: %zu)\n", 
                estimated_base64_size, max_len);
        QGP_LOG_ERROR(LOG_TAG, "Please use a simpler image with less detail\n");
        free(jpeg_output.data);
        return -1;
    }

    // Encode to base64
    int ret = base64_encode(jpeg_output.data, jpeg_output.len, base64_out, max_len);
    free(jpeg_output.data);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to encode base64\n");
        return -1;
    }
    
    QGP_LOG_INFO(LOG_TAG, "Base64 size: %zu bytes\n", strlen(base64_out));

    return 0;
}

/**
 * @brief Decode base64 avatar and get image data
 *
 * Decodes base64 string to raw RGBA pixel data (64x64).
 *
 * @param base64_str Base64 encoded avatar string
 * @param width_out Output: image width (always 64)
 * @param height_out Output: image height (always 64)
 * @param channels_out Output: number of channels (always 4 for RGBA)
 * @return Pointer to pixel data (caller must free), or NULL on error
 */
unsigned char* avatar_decode_base64(const char *base64_str,
                                    int *width_out,
                                    int *height_out,
                                    int *channels_out) {
    if (!base64_str || !width_out || !height_out || !channels_out) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters\n");
        return NULL;
    }

    // Decode base64 to PNG binary
    unsigned char *png_data = NULL;
    size_t png_len = 0;
    if (base64_decode(base64_str, &png_data, &png_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to decode base64\n");
        return NULL;
    }

    // Load PNG from memory
    int width, height, channels;
    unsigned char *img = stbi_load_from_memory(png_data, png_len, &width, &height, &channels, 4);
    free(png_data);

    if (!img) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to load PNG from memory: %s\n", stbi_failure_reason());
        return NULL;
    }

    *width_out = width;
    *height_out = height;
    *channels_out = 4; // Always RGBA

    return img;
}
