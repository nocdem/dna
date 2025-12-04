/*
 * DNA Engine Wrapper for ImGui GUI
 *
 * Provides a C++ interface to the DNA Engine API for GUI integration.
 * Handles engine lifecycle and provides convenience methods.
 */

#ifndef ENGINE_WRAPPER_H
#define ENGINE_WRAPPER_H

extern "C" {
#include "dna/dna_engine.h"
}

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace DNA {

/**
 * Synchronous result wrapper for async operations
 */
template<typename T>
struct SyncResult {
    int error;
    T data;
    bool completed;
};

/**
 * Engine Wrapper - C++ interface to DNA Engine
 *
 * Usage:
 *   EngineWrapper engine;
 *   if (!engine.init()) { handle error; }
 *   engine.loadIdentity(fingerprint, [](int err) { ... });
 */
class EngineWrapper {
public:
    EngineWrapper();
    ~EngineWrapper();

    // Non-copyable
    EngineWrapper(const EngineWrapper&) = delete;
    EngineWrapper& operator=(const EngineWrapper&) = delete;

    /**
     * Initialize engine
     * @param data_dir Optional data directory (nullptr for default ~/.dna)
     * @return true on success
     */
    bool init(const char* data_dir = nullptr);

    /**
     * Check if engine is initialized
     */
    bool isInitialized() const { return engine_ != nullptr; }

    /**
     * Check if identity is loaded
     */
    bool isIdentityLoaded() const { return identity_loaded_; }

    /**
     * Get current identity fingerprint
     */
    const char* getFingerprint() const;

    /**
     * Get underlying engine (for advanced usage)
     */
    dna_engine_t* getEngine() { return engine_; }

    /**
     * Get messenger context (backward compatibility)
     * WARNING: Use sparingly - prefer engine API
     */
    void* getMessengerContext();

    /**
     * Get DHT context (backward compatibility)
     * WARNING: Use sparingly - prefer engine API
     */
    void* getDhtContext();

    // ========================================================================
    // Identity Operations (async with callbacks)
    // ========================================================================

    using CompletionCallback = std::function<void(int error)>;
    using IdentitiesCallback = std::function<void(int error, const std::vector<std::string>& fingerprints)>;
    using IdentityCreatedCallback = std::function<void(int error, const std::string& fingerprint)>;
    using DisplayNameCallback = std::function<void(int error, const std::string& name)>;

    /**
     * List available identities (async)
     */
    dna_request_id_t listIdentities(IdentitiesCallback callback);

    /**
     * Load identity (async)
     */
    dna_request_id_t loadIdentity(const std::string& fingerprint, CompletionCallback callback);

    /**
     * Register name for current identity (async)
     */
    dna_request_id_t registerName(const std::string& name, CompletionCallback callback);

    /**
     * Get display name for fingerprint (async)
     */
    dna_request_id_t getDisplayName(const std::string& fingerprint, DisplayNameCallback callback);

    /**
     * Get registered name for current identity (async)
     */
    dna_request_id_t getRegisteredName(DisplayNameCallback callback);

    // ========================================================================
    // Synchronous convenience methods (blocks until complete)
    // ========================================================================

    /**
     * List identities synchronously
     * @param timeout_ms Timeout in milliseconds (0 = infinite)
     * @return Vector of fingerprints (empty on error)
     */
    std::vector<std::string> listIdentitiesSync(int timeout_ms = 5000);

    /**
     * Load identity synchronously
     * @return 0 on success, error code on failure
     */
    int loadIdentitySync(const std::string& fingerprint, int timeout_ms = 10000);

    /**
     * Get display name synchronously
     * @return Display name or empty string on error
     */
    std::string getDisplayNameSync(const std::string& fingerprint, int timeout_ms = 3000);

    // ========================================================================
    // P2P Operations
    // ========================================================================

    /**
     * Refresh presence in DHT (async)
     */
    dna_request_id_t refreshPresence(CompletionCallback callback);

    /**
     * Check if peer is online (synchronous, fast)
     */
    bool isPeerOnline(const std::string& fingerprint);

    /**
     * Sync contacts to DHT (async)
     */
    dna_request_id_t syncContactsToDht(CompletionCallback callback);

    /**
     * Sync contacts from DHT (async)
     */
    dna_request_id_t syncContactsFromDht(CompletionCallback callback);

    /**
     * Subscribe to contacts for push notifications (async)
     */
    dna_request_id_t subscribeToContacts(CompletionCallback callback);

private:
    dna_engine_t* engine_;
    std::atomic<bool> identity_loaded_;

    // Synchronous operation support
    std::mutex sync_mutex_;
    std::condition_variable sync_cv_;
};

/**
 * Global engine instance (singleton for GUI)
 */
EngineWrapper& GetEngine();

} // namespace DNA

#endif // ENGINE_WRAPPER_H
