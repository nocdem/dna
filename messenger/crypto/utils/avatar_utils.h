/**
 * @file avatar_utils.h
 * @brief Avatar image processing utilities
 *
 * Provides functions for loading, resizing, and encoding avatar images
 * to base64 for storage in DNA profiles.
 */

#ifndef AVATAR_UTILS_H
#define AVATAR_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
int avatar_load_and_encode(const char *file_path, char *base64_out, size_t max_len);

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
                                    int *channels_out);

#ifdef __cplusplus
}
#endif

#endif /* AVATAR_UTILS_H */
