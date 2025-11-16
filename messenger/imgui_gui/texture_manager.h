/**
 * @file texture_manager.h
 * @brief OpenGL texture manager for avatar images
 *
 * Manages OpenGL textures for avatar display in ImGui.
 * Handles base64 decoding, texture upload, and caching.
 */

#ifndef TEXTURE_MANAGER_H
#define TEXTURE_MANAGER_H

#include <string>
#include <unordered_map>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <GL/gl.h>
// Define OpenGL 1.2+ constants not in Windows gl.h
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#else
#include <GL/gl.h>
#endif

/**
 * @brief Texture cache entry
 */
struct TextureEntry {
    GLuint texture_id;
    int width;
    int height;
};

/**
 * @brief OpenGL texture manager for avatars
 *
 * Features:
 * - Decodes base64 avatar strings to RGBA pixels
 * - Uploads to OpenGL texture (GL_TEXTURE_2D)
 * - Caches textures by key (fingerprint) to avoid reloading
 * - Provides ImGui-compatible texture IDs
 */
class TextureManager {
public:
    /**
     * @brief Get singleton instance
     */
    static TextureManager& getInstance();

    /**
     * @brief Load avatar from base64 and get texture ID
     *
     * Decodes base64 string, uploads to OpenGL, caches result.
     * If already cached, returns existing texture ID.
     *
     * @param key Cache key (usually fingerprint)
     * @param base64_data Base64 encoded avatar image
     * @param width_out Output: texture width (64)
     * @param height_out Output: texture height (64)
     * @return OpenGL texture ID, or 0 on error
     */
    GLuint loadAvatar(const std::string& key, const std::string& base64_data, int* width_out, int* height_out);

    /**
     * @brief Remove texture from cache and free OpenGL resources
     *
     * @param key Cache key
     */
    void removeTexture(const std::string& key);

    /**
     * @brief Clear all cached textures
     */
    void clearAll();

    /**
     * @brief Get cached texture ID (if exists)
     *
     * @param key Cache key
     * @return Texture ID, or 0 if not cached
     */
    GLuint getCachedTexture(const std::string& key, int* width_out, int* height_out);

private:
    TextureManager() = default;
    ~TextureManager();

    // Prevent copying
    TextureManager(const TextureManager&) = delete;
    TextureManager& operator=(const TextureManager&) = delete;

    std::unordered_map<std::string, TextureEntry> texture_cache_;
};

#endif /* TEXTURE_MANAGER_H */
