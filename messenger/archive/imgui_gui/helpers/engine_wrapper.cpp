/*
 * DNA Engine Wrapper Implementation
 */

#include "engine_wrapper.h"
#include <chrono>
#include <cstring>

namespace DNA {

// Global engine instance
static EngineWrapper* g_engine = nullptr;

EngineWrapper& GetEngine() {
    if (!g_engine) {
        g_engine = new EngineWrapper();
    }
    return *g_engine;
}

// ============================================================================
// Constructor/Destructor
// ============================================================================

EngineWrapper::EngineWrapper()
    : engine_(nullptr)
    , identity_loaded_(false)
{
}

EngineWrapper::~EngineWrapper() {
    if (engine_) {
        dna_engine_destroy(engine_);
        engine_ = nullptr;
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool EngineWrapper::init(const char* data_dir) {
    if (engine_) {
        return true; // Already initialized
    }

    engine_ = dna_engine_create(data_dir);
    return engine_ != nullptr;
}

const char* EngineWrapper::getFingerprint() const {
    if (!engine_) return nullptr;
    return dna_engine_get_fingerprint(engine_);
}

void* EngineWrapper::getMessengerContext() {
    if (!engine_) return nullptr;
    return dna_engine_get_messenger_context(engine_);
}

void* EngineWrapper::getDhtContext() {
    if (!engine_) return nullptr;
    return dna_engine_get_dht_context(engine_);
}

// ============================================================================
// Callback Context Helpers
// ============================================================================

// Context structure for async callbacks
struct CallbackContext {
    EngineWrapper* wrapper;
    void* user_callback;

    // For sync operations
    std::mutex* sync_mutex;
    std::condition_variable* sync_cv;
    bool* completed;
    int* error_out;
    void* data_out;
};

// ============================================================================
// Identity Operations
// ============================================================================

static void identities_callback_wrapper(
    dna_request_id_t request_id,
    int error,
    char** fingerprints,
    int count,
    void* user_data
) {
    auto* ctx = static_cast<CallbackContext*>(user_data);
    auto callback = static_cast<EngineWrapper::IdentitiesCallback*>(ctx->user_callback);

    std::vector<std::string> fps;
    if (error == 0 && fingerprints) {
        fps.reserve(count);
        for (int i = 0; i < count; i++) {
            fps.push_back(fingerprints[i]);
        }
    }

    if (callback && *callback) {
        (*callback)(error, fps);
    }

    // For sync operations
    if (ctx->sync_mutex) {
        std::lock_guard<std::mutex> lock(*ctx->sync_mutex);
        if (ctx->error_out) *ctx->error_out = error;
        if (ctx->data_out) {
            auto* out = static_cast<std::vector<std::string>*>(ctx->data_out);
            *out = std::move(fps);
        }
        if (ctx->completed) *ctx->completed = true;
        ctx->sync_cv->notify_one();
    }

    delete callback;
    delete ctx;
}

dna_request_id_t EngineWrapper::listIdentities(IdentitiesCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new IdentitiesCallback(std::move(callback));
    ctx->sync_mutex = nullptr;
    ctx->sync_cv = nullptr;
    ctx->completed = nullptr;
    ctx->error_out = nullptr;
    ctx->data_out = nullptr;

    return dna_engine_list_identities(engine_, identities_callback_wrapper, ctx);
}

static void completion_callback_wrapper(
    dna_request_id_t request_id,
    int error,
    void* user_data
) {
    auto* ctx = static_cast<CallbackContext*>(user_data);
    auto callback = static_cast<EngineWrapper::CompletionCallback*>(ctx->user_callback);

    if (callback && *callback) {
        (*callback)(error);
    }

    // For sync operations
    if (ctx->sync_mutex) {
        std::lock_guard<std::mutex> lock(*ctx->sync_mutex);
        if (ctx->error_out) *ctx->error_out = error;
        if (ctx->completed) *ctx->completed = true;
        ctx->sync_cv->notify_one();
    }

    delete callback;
    delete ctx;
}

dna_request_id_t EngineWrapper::loadIdentity(const std::string& fingerprint, CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback([this, cb = std::move(callback)](int error) {
        if (error == 0) {
            identity_loaded_ = true;
        }
        if (cb) cb(error);
    });
    ctx->sync_mutex = nullptr;
    ctx->sync_cv = nullptr;
    ctx->completed = nullptr;
    ctx->error_out = nullptr;
    ctx->data_out = nullptr;

    return dna_engine_load_identity(engine_, fingerprint.c_str(), completion_callback_wrapper, ctx);
}

dna_request_id_t EngineWrapper::registerName(const std::string& name, CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_register_name(engine_, name.c_str(), completion_callback_wrapper, ctx);
}

static void display_name_callback_wrapper(
    dna_request_id_t request_id,
    int error,
    const char* display_name,
    void* user_data
) {
    auto* ctx = static_cast<CallbackContext*>(user_data);
    auto callback = static_cast<EngineWrapper::DisplayNameCallback*>(ctx->user_callback);

    std::string name = display_name ? display_name : "";

    if (callback && *callback) {
        (*callback)(error, name);
    }

    // For sync operations
    if (ctx->sync_mutex) {
        std::lock_guard<std::mutex> lock(*ctx->sync_mutex);
        if (ctx->error_out) *ctx->error_out = error;
        if (ctx->data_out) {
            auto* out = static_cast<std::string*>(ctx->data_out);
            *out = std::move(name);
        }
        if (ctx->completed) *ctx->completed = true;
        ctx->sync_cv->notify_one();
    }

    delete callback;
    delete ctx;
}

dna_request_id_t EngineWrapper::getDisplayName(const std::string& fingerprint, DisplayNameCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new DisplayNameCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_get_display_name(engine_, fingerprint.c_str(), display_name_callback_wrapper, ctx);
}

dna_request_id_t EngineWrapper::getRegisteredName(DisplayNameCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new DisplayNameCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_get_registered_name(engine_, display_name_callback_wrapper, ctx);
}

// ============================================================================
// Synchronous Methods
// ============================================================================

std::vector<std::string> EngineWrapper::listIdentitiesSync(int timeout_ms) {
    if (!engine_) return {};

    std::vector<std::string> result;
    bool completed = false;
    int error = -1;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new IdentitiesCallback(); // Empty callback
    ctx->sync_mutex = &sync_mutex_;
    ctx->sync_cv = &sync_cv_;
    ctx->completed = &completed;
    ctx->error_out = &error;
    ctx->data_out = &result;

    dna_request_id_t req = dna_engine_list_identities(engine_, identities_callback_wrapper, ctx);
    if (req == 0) return {};

    // Wait for completion
    std::unique_lock<std::mutex> lock(sync_mutex_);
    if (timeout_ms > 0) {
        sync_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&completed] { return completed; });
    } else {
        sync_cv_.wait(lock, [&completed] { return completed; });
    }

    return result;
}

int EngineWrapper::loadIdentitySync(const std::string& fingerprint, int timeout_ms) {
    if (!engine_) return DNA_ENGINE_ERROR_NOT_INITIALIZED;

    bool completed = false;
    int error = -1;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback([this](int err) {
        if (err == 0) identity_loaded_ = true;
    });
    ctx->sync_mutex = &sync_mutex_;
    ctx->sync_cv = &sync_cv_;
    ctx->completed = &completed;
    ctx->error_out = &error;
    ctx->data_out = nullptr;

    dna_request_id_t req = dna_engine_load_identity(engine_, fingerprint.c_str(), completion_callback_wrapper, ctx);
    if (req == 0) return DNA_ENGINE_ERROR_BUSY;

    // Wait for completion
    std::unique_lock<std::mutex> lock(sync_mutex_);
    if (timeout_ms > 0) {
        sync_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&completed] { return completed; });
    } else {
        sync_cv_.wait(lock, [&completed] { return completed; });
    }

    return error;
}

std::string EngineWrapper::getDisplayNameSync(const std::string& fingerprint, int timeout_ms) {
    if (!engine_) return "";

    std::string result;
    bool completed = false;
    int error = -1;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new DisplayNameCallback(); // Empty callback
    ctx->sync_mutex = &sync_mutex_;
    ctx->sync_cv = &sync_cv_;
    ctx->completed = &completed;
    ctx->error_out = &error;
    ctx->data_out = &result;

    dna_request_id_t req = dna_engine_get_display_name(engine_, fingerprint.c_str(), display_name_callback_wrapper, ctx);
    if (req == 0) return "";

    // Wait for completion
    std::unique_lock<std::mutex> lock(sync_mutex_);
    if (timeout_ms > 0) {
        sync_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&completed] { return completed; });
    } else {
        sync_cv_.wait(lock, [&completed] { return completed; });
    }

    return result;
}

// ============================================================================
// P2P Operations
// ============================================================================

dna_request_id_t EngineWrapper::refreshPresence(CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_refresh_presence(engine_, completion_callback_wrapper, ctx);
}

bool EngineWrapper::isPeerOnline(const std::string& fingerprint) {
    if (!engine_) return false;
    return dna_engine_is_peer_online(engine_, fingerprint.c_str());
}

dna_request_id_t EngineWrapper::syncContactsToDht(CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_sync_contacts_to_dht(engine_, completion_callback_wrapper, ctx);
}

dna_request_id_t EngineWrapper::syncContactsFromDht(CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_sync_contacts_from_dht(engine_, completion_callback_wrapper, ctx);
}

dna_request_id_t EngineWrapper::subscribeToContacts(CompletionCallback callback) {
    if (!engine_) return 0;

    auto* ctx = new CallbackContext();
    ctx->wrapper = this;
    ctx->user_callback = new CompletionCallback(std::move(callback));
    ctx->sync_mutex = nullptr;

    return dna_engine_subscribe_to_contacts(engine_, completion_callback_wrapper, ctx);
}

} // namespace DNA
