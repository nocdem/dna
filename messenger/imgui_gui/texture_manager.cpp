/**
 * @file texture_manager.cpp
 * @brief OpenGL texture manager implementation
 */

#include "texture_manager.h"
#include <cstdio>
#include <cstring>

extern "C" {
    #include "../crypto/utils/avatar_utils.h"
}

TextureManager& TextureManager::getInstance() {
    static TextureManager instance;
    return instance;
}

TextureManager::~TextureManager() {
    clearAll();
}

GLuint TextureManager::loadAvatar(const std::string& key, const std::string& base64_data, int* width_out, int* height_out) {
    if (base64_data.empty()) {
        fprintf(stderr, "[TextureManager] Empty base64 data\n");
        return 0;
    }

    // Check cache first
    auto it = texture_cache_.find(key);
    if (it != texture_cache_.end()) {
        printf("[TextureManager] Using cached texture for key: %s\n", key.substr(0, 10).c_str());
        if (width_out) *width_out = it->second.width;
        if (height_out) *height_out = it->second.height;
        return it->second.texture_id;
    }

    // Decode base64 to RGBA pixels
    int width = 0, height = 0, channels = 0;
    unsigned char* pixels = avatar_decode_base64(base64_data.c_str(), &width, &height, &channels);

    if (!pixels) {
        fprintf(stderr, "[TextureManager] Failed to decode avatar base64\n");
        return 0;
    }

    printf("[TextureManager] Decoded avatar: %dx%d, %d channels\n", width, height, channels);

    // Create OpenGL texture
    GLuint texture_id = 0;
    glGenTextures(1, &texture_id);
    glBindTexture(GL_TEXTURE_2D, texture_id);

    // Set texture parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    // Upload pixels to GPU
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixels);

    // Free CPU memory
    free(pixels);

    glBindTexture(GL_TEXTURE_2D, 0);

    // Check for OpenGL errors
    GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        fprintf(stderr, "[TextureManager] OpenGL error: 0x%x\n", error);
        glDeleteTextures(1, &texture_id);
        return 0;
    }

    // Cache the texture
    TextureEntry entry;
    entry.texture_id = texture_id;
    entry.width = width;
    entry.height = height;
    texture_cache_[key] = entry;

    printf("[TextureManager] Created and cached texture %u for key: %s\n", texture_id, key.substr(0, 10).c_str());

    if (width_out) *width_out = width;
    if (height_out) *height_out = height;

    return texture_id;
}

void TextureManager::removeTexture(const std::string& key) {
    auto it = texture_cache_.find(key);
    if (it != texture_cache_.end()) {
        glDeleteTextures(1, &it->second.texture_id);
        texture_cache_.erase(it);
        printf("[TextureManager] Removed texture for key: %s\n", key.substr(0, 10).c_str());
    }
}

void TextureManager::clearAll() {
    for (auto& pair : texture_cache_) {
        glDeleteTextures(1, &pair.second.texture_id);
    }
    texture_cache_.clear();
    printf("[TextureManager] Cleared all textures (%zu total)\n", texture_cache_.size());
}

GLuint TextureManager::getCachedTexture(const std::string& key, int* width_out, int* height_out) {
    auto it = texture_cache_.find(key);
    if (it != texture_cache_.end()) {
        if (width_out) *width_out = it->second.width;
        if (height_out) *height_out = it->second.height;
        return it->second.texture_id;
    }
    return 0;
}
