/**
 * DHT Listen API Implementation
 * C++ to C bridge for OpenDHT listen() functionality
 */

#include "dht_listen.h"
#include "dht_context.h"

#include <opendht/dhtrunner.h>
#include <opendht/infohash.h>

#include <map>
#include <mutex>
#include <memory>
#include <atomic>

// Unified logging (respects config log level)
extern "C" {
#include "crypto/utils/qgp_log.h"
}
#define LOG_TAG "DHT_LISTEN"

// Forward declarations
struct dht_value_storage;

// DHT context structure (from dht_context.cpp)
struct dht_context {
    dht::DhtRunner runner;
    dht_config_t config;
    bool running;
    dht_value_storage *storage;  // Value persistence (NULL for user nodes)

    // ValueTypes with lambda-captured context
    dht::ValueType type_7day;
    dht::ValueType type_30day;
    dht::ValueType type_365day;

    dht_context() : running(false), storage(nullptr),
                    type_7day(0, "", std::chrono::hours(0)),
                    type_30day(0, "", std::chrono::hours(0)),
                    type_365day(0, "", std::chrono::hours(0)) {
        memset(&config, 0, sizeof(config));
    }
};

// Token counter for generating unique listen tokens
static std::atomic<size_t> next_listen_token{1};

// Listener management structure
struct ListenerContext {
    dht_listen_callback_t callback;
    void *user_data;
    std::future<size_t> future_token;  // Future from dht::DhtRunner::listen()
    size_t opendht_token;  // Token from OpenDHT (for cancellation)
    bool active;
};

// Global map of active listeners (token -> context)
static std::map<size_t, std::shared_ptr<ListenerContext>> active_listeners;
static std::mutex listeners_mutex;

/**
 * Start listening for DHT values at the specified key
 */
extern "C" size_t dht_listen(
    dht_context_t *ctx,
    const uint8_t *key,
    size_t key_len,
    dht_listen_callback_t callback,
    void *user_data)
{
    if (!ctx || !key || key_len == 0 || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters");
        return 0;
    }

    try {
        // Convert C key to InfoHash
        dht::InfoHash hash = dht::InfoHash::get(key, key_len);
        std::string hash_str = hash.toString().substr(0, 16);

        QGP_LOG_DEBUG(LOG_TAG, "Starting subscription for key %s...", hash_str.c_str());

        // Generate unique token for this subscription
        size_t token = next_listen_token.fetch_add(1);

        // Create listener context
        auto listener_ctx = std::make_shared<ListenerContext>();
        listener_ctx->callback = callback;
        listener_ctx->user_data = user_data;
        listener_ctx->active = true;

        // Create C++ callback that wraps the C callback
        // We need to capture the token and listener_ctx by value (shared_ptr)
        auto cpp_callback = [token, listener_ctx](
            const std::vector<std::shared_ptr<dht::Value>>& values,
            bool expired
        ) -> bool {
            // Check if listener is still active
            std::lock_guard<std::mutex> lock(listeners_mutex);
            if (!listener_ctx->active) {
                QGP_LOG_DEBUG(LOG_TAG, "Token %zu is no longer active, stopping", token);
                return false;  // Stop listening
            }

            // Handle expiration notification
            if (expired) {
                QGP_LOG_DEBUG(LOG_TAG, "Token %zu received expiration notification", token);
                bool continue_listening = listener_ctx->callback(
                    nullptr, 0, true, listener_ctx->user_data
                );
                return continue_listening;
            }

            // Handle value notifications
            if (values.empty()) {
                return true;  // Continue listening (no values yet)
            }

            QGP_LOG_DEBUG(LOG_TAG, "Token %zu received %zu value(s)", token, values.size());

            // Invoke C callback for each value
            bool continue_listening = true;
            for (const auto& val : values) {
                if (!val || val->data.empty()) {
                    continue;
                }

                // Call C callback (thread-safe - callback must handle threading)
                bool result = listener_ctx->callback(
                    val->data.data(),
                    val->data.size(),
                    false,
                    listener_ctx->user_data
                );

                if (!result) {
                    QGP_LOG_DEBUG(LOG_TAG, "Token %zu callback returned false, stopping", token);
                    continue_listening = false;
                    break;
                }
            }

            return continue_listening;
        };

        // Start listening via OpenDHT
        // This returns a std::future<size_t> containing the OpenDHT token
        listener_ctx->future_token = ctx->runner.listen(hash, cpp_callback);

        // Wait for the OpenDHT token (may block briefly during DHT startup)
        try {
            listener_ctx->opendht_token = listener_ctx->future_token.get();

            QGP_LOG_DEBUG(LOG_TAG, "Subscription active for token %zu (OpenDHT: %zu)",
                          token, listener_ctx->opendht_token);
        } catch (const std::exception& e) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get OpenDHT token: %s", e.what());
            return 0;
        }

        // Store listener context in global map
        {
            std::lock_guard<std::mutex> lock(listeners_mutex);
            active_listeners[token] = listener_ctx;
        }

        return token;

    } catch (const std::exception& e) {
        QGP_LOG_ERROR(LOG_TAG, "Exception while starting listener: %s", e.what());
        return 0;
    }
}

/**
 * Cancel an active DHT listen subscription
 */
extern "C" void dht_cancel_listen(
    dht_context_t *ctx,
    size_t token)
{
    if (!ctx || token == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(listeners_mutex);

    auto it = active_listeners.find(token);
    if (it == active_listeners.end()) {
        QGP_LOG_DEBUG(LOG_TAG, "Token %zu not found (already cancelled or invalid)", token);
        return;
    }

    auto listener_ctx = it->second;

    if (!listener_ctx->active) {
        QGP_LOG_DEBUG(LOG_TAG, "Token %zu already marked as inactive", token);
        active_listeners.erase(it);
        return;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Cancelling subscription for token %zu (OpenDHT: %zu)",
                  token, listener_ctx->opendht_token);

    // Mark as inactive (stops callback from processing new values)
    listener_ctx->active = false;

    // Cancel the OpenDHT subscription
    // Note: OpenDHT's cancelListen() takes the token returned by listen()
    try {
        ctx->runner.cancelListen(
            dht::InfoHash(),  // Hash not needed for cancellation
            listener_ctx->opendht_token
        );
        QGP_LOG_DEBUG(LOG_TAG, "Subscription cancelled for token %zu", token);
    } catch (const std::exception& e) {
        QGP_LOG_ERROR(LOG_TAG, "Exception while cancelling listener: %s", e.what());
    }

    // Remove from active listeners map
    active_listeners.erase(it);
}

/**
 * Get the number of active listen subscriptions
 */
extern "C" size_t dht_get_active_listen_count(
    dht_context_t *ctx)
{
    if (!ctx) {
        return 0;
    }

    std::lock_guard<std::mutex> lock(listeners_mutex);
    return active_listeners.size();
}
