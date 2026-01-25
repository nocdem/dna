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
#include <chrono>
#include <future>

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

// Listener management structure (Phase 14: Extended with cleanup and key data)
struct ListenerContext {
    dht_listen_callback_t callback;
    void *user_data;
    dht_listen_cleanup_t cleanup;  // Phase 14: Cleanup callback (may be NULL)
    std::future<size_t> future_token;  // Future from dht::DhtRunner::listen()
    size_t opendht_token;  // Token from OpenDHT (for cancellation)
    bool active;

    // Phase 14: Store key data for resubscription after network loss
    std::vector<uint8_t> key_data;
    size_t key_len;
    dht_context_t *ctx;  // Store context for resubscription
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
    // Delegate to extended version with no cleanup callback
    // This ensures all listeners store key_data for network-change resilience
    return dht_listen_ex(ctx, key, key_len, callback, user_data, nullptr);
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

    // Phase 14: Call cleanup callback if provided
    if (listener_ctx->cleanup) {
        QGP_LOG_DEBUG(LOG_TAG, "Calling cleanup callback for token %zu", token);
        listener_ctx->cleanup(listener_ctx->user_data);
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

// ============================================================================
// Extended API (Phase 14)
// ============================================================================

/**
 * Start listening with cleanup callback support (Phase 14)
 */
extern "C" size_t dht_listen_ex(
    dht_context_t *ctx,
    const uint8_t *key,
    size_t key_len,
    dht_listen_callback_t callback,
    void *user_data,
    dht_listen_cleanup_t cleanup)
{
    if (!ctx || !key || key_len == 0 || !callback) {
        QGP_LOG_ERROR(LOG_TAG, "dht_listen_ex: Invalid parameters");
        return 0;
    }

    try {
        // Convert C key to InfoHash
        dht::InfoHash hash = dht::InfoHash::get(key, key_len);
        std::string hash_str = hash.toString().substr(0, 16);

        // Check listener limit
        {
            std::lock_guard<std::mutex> lock(listeners_mutex);
            if (active_listeners.size() >= DHT_MAX_LISTENERS) {
                QGP_LOG_ERROR(LOG_TAG, "Maximum listeners reached (%d)", DHT_MAX_LISTENERS);
                // Call cleanup to free user_data (consistent with other failure paths)
                if (cleanup) {
                    cleanup(user_data);
                }
                return 0;
            }
        }

        QGP_LOG_DEBUG(LOG_TAG, "Starting extended subscription for key %s...", hash_str.c_str());

        // Generate unique token for this subscription
        size_t token = next_listen_token.fetch_add(1);

        // Create listener context with cleanup and key data
        auto listener_ctx = std::make_shared<ListenerContext>();
        listener_ctx->callback = callback;
        listener_ctx->user_data = user_data;
        listener_ctx->cleanup = cleanup;
        listener_ctx->active = true;
        listener_ctx->ctx = ctx;

        // Store key data for resubscription
        listener_ctx->key_data.assign(key, key + key_len);
        listener_ctx->key_len = key_len;

        // Create C++ callback that wraps the C callback
        auto cpp_callback = [token, listener_ctx](
            const std::vector<std::shared_ptr<dht::Value>>& values,
            bool expired
        ) -> bool {
            QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Callback: token=%zu, values=%zu, expired=%d",
                         token, values.size(), expired);

            // Check if listener is still active
            std::lock_guard<std::mutex> lock(listeners_mutex);
            if (!listener_ctx->active) {
                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Token %zu inactive, stopping", token);
                return false;
            }

            // Handle expiration notification
            if (expired) {
                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Token %zu expired", token);
                bool continue_listening = listener_ctx->callback(
                    nullptr, 0, true, listener_ctx->user_data
                );
                return continue_listening;
            }

            // Handle value notifications
            if (values.empty()) {
                return true;  // No new data, continue listening
            }

            QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Token %zu: %zu value(s)", token, values.size());

            // Invoke C callback for each value
            bool continue_listening = true;
            for (const auto& val : values) {
                if (!val || val->data.empty()) {
                    continue;
                }

                QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Token %zu: id=%llu, seq=%llu, %zu bytes",
                             token,
                             (unsigned long long)val->id,
                             (unsigned long long)val->seq,
                             val->data.size());

                bool result = listener_ctx->callback(
                    val->data.data(),
                    val->data.size(),
                    false,
                    listener_ctx->user_data
                );

                if (!result) {
                    QGP_LOG_DEBUG(LOG_TAG, "[LISTEN-DHT] Token %zu: callback stopped", token);
                    continue_listening = false;
                    break;
                }
            }

            return continue_listening;
        };

        // Start listening via OpenDHT
        listener_ctx->future_token = ctx->runner.listen(hash, cpp_callback);

        // Wait for the OpenDHT token with timeout (avoid ANR on bad DHT state)
        try {
            auto status = listener_ctx->future_token.wait_for(std::chrono::seconds(5));
            if (status == std::future_status::timeout) {
                QGP_LOG_ERROR(LOG_TAG, "Timeout waiting for OpenDHT token (5s) - DHT may be in bad state");
                // CRITICAL: Mark listener as inactive BEFORE freeing user_data
                // The OpenDHT listener was already started at ctx->runner.listen() above.
                // Without this, the callback could fire with freed user_data → use-after-free!
                listener_ctx->active = false;
                if (cleanup) {
                    cleanup(user_data);
                }
                return 0;
            }
            listener_ctx->opendht_token = listener_ctx->future_token.get();
            QGP_LOG_DEBUG(LOG_TAG, "Extended subscription active for token %zu (OpenDHT: %zu)",
                          token, listener_ctx->opendht_token);
        } catch (const std::exception& e) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to get OpenDHT token: %s", e.what());
            // CRITICAL: Mark listener as inactive BEFORE freeing user_data
            // The OpenDHT listener was already started at ctx->runner.listen() above.
            listener_ctx->active = false;
            // Call cleanup if provided
            if (cleanup) {
                cleanup(user_data);
            }
            return 0;
        }

        // Store listener context
        {
            std::lock_guard<std::mutex> lock(listeners_mutex);
            active_listeners[token] = listener_ctx;
        }

        return token;

    } catch (const std::exception& e) {
        QGP_LOG_ERROR(LOG_TAG, "Exception in dht_listen_ex: %s", e.what());
        // Call cleanup if provided
        if (cleanup) {
            cleanup(user_data);
        }
        return 0;
    }
}

/**
 * Cancel all active listen subscriptions (Phase 14)
 */
extern "C" void dht_cancel_all_listeners(
    dht_context_t *ctx)
{
    if (!ctx) {
        return;
    }

    std::lock_guard<std::mutex> lock(listeners_mutex);

    QGP_LOG_INFO(LOG_TAG, "Cancelling all %zu active listeners", active_listeners.size());

    for (auto& [token, listener_ctx] : active_listeners) {
        if (!listener_ctx->active) {
            continue;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Cancelling listener token %zu", token);
        listener_ctx->active = false;

        // Cancel OpenDHT subscription
        try {
            ctx->runner.cancelListen(dht::InfoHash(), listener_ctx->opendht_token);
        } catch (const std::exception& e) {
            QGP_LOG_ERROR(LOG_TAG, "Exception cancelling listener %zu: %s", token, e.what());
        }

        // Call cleanup callback if provided
        if (listener_ctx->cleanup) {
            listener_ctx->cleanup(listener_ctx->user_data);
        }
    }

    active_listeners.clear();
    QGP_LOG_INFO(LOG_TAG, "All listeners cancelled");
}

/**
 * Suspend all active listeners (Phase 14)
 *
 * Cancels OpenDHT subscriptions but preserves listener contexts for resubscription.
 * Does NOT clear the map or call cleanup callbacks.
 */
extern "C" void dht_suspend_all_listeners(
    dht_context_t *ctx)
{
    std::lock_guard<std::mutex> lock(listeners_mutex);

    QGP_LOG_INFO(LOG_TAG, "Suspending %zu active listeners for reinit", active_listeners.size());

    for (auto& [token, listener_ctx] : active_listeners) {
        if (!listener_ctx->active) {
            continue;
        }

        QGP_LOG_DEBUG(LOG_TAG, "Suspending listener token %zu", token);
        listener_ctx->active = false;

        // Cancel OpenDHT subscription (only if context is valid)
        if (ctx) {
            try {
                ctx->runner.cancelListen(dht::InfoHash(), listener_ctx->opendht_token);
            } catch (const std::exception& e) {
                QGP_LOG_ERROR(LOG_TAG, "Exception suspending listener %zu: %s", token, e.what());
            }
        }

        // Do NOT call cleanup callback
        // Do NOT remove from map
    }

    QGP_LOG_INFO(LOG_TAG, "All listeners suspended (preserved for resubscription)");
}

/**
 * Resubscribe all active listeners (Phase 14)
 *
 * CRITICAL: This function must NOT hold listeners_mutex while calling OpenDHT.
 * OpenDHT may fire callbacks immediately, and those callbacks need the mutex.
 * Holding mutex during future.get() causes deadlock.
 *
 * Strategy:
 * 1. Collect listener info while holding mutex (fast)
 * 2. Release mutex
 * 3. Resubscribe each listener (slow, may block)
 * 4. Re-acquire mutex to update each entry
 */
extern "C" size_t dht_resubscribe_all_listeners(
    dht_context_t *ctx)
{
    if (!ctx) {
        return 0;
    }

    // Structure to hold listener info for resubscription (outside mutex)
    struct ResubInfo {
        size_t token;
        std::shared_ptr<ListenerContext> listener_ctx;
        std::vector<uint8_t> key_data;
        size_t key_len;
    };

    std::vector<ResubInfo> to_resubscribe;

    // Phase 1: Collect listener info while holding mutex (fast)
    {
        std::lock_guard<std::mutex> lock(listeners_mutex);
        QGP_LOG_INFO(LOG_TAG, "Resubscribing %zu listeners after network change", active_listeners.size());

        for (auto& [token, listener_ctx] : active_listeners) {
            // Skip listeners without key data (created with basic API)
            if (listener_ctx->key_data.empty()) {
                QGP_LOG_DEBUG(LOG_TAG, "Skipping token %zu (no key data)", token);
                continue;
            }

            // Copy info for resubscription outside mutex
            ResubInfo info;
            info.token = token;
            info.listener_ctx = listener_ctx;
            info.key_data = listener_ctx->key_data;  // Copy
            info.key_len = listener_ctx->key_len;
            to_resubscribe.push_back(std::move(info));
        }
    }
    // Mutex released here

    // Phase 2: Resubscribe each listener WITHOUT holding mutex
    // This allows OpenDHT callbacks to fire without deadlock
    size_t resubscribed = 0;

    for (auto& info : to_resubscribe) {
        try {
            // Recreate InfoHash from stored key data
            dht::InfoHash hash = dht::InfoHash::get(
                info.key_data.data(),
                info.key_len
            );

            // Capture shared_ptr by value (not reference) for thread safety
            auto listener_ctx = info.listener_ctx;
            size_t token = info.token;

            // Create new callback wrapper
            auto cpp_callback = [token, listener_ctx](
                const std::vector<std::shared_ptr<dht::Value>>& values,
                bool expired
            ) -> bool {
                std::lock_guard<std::mutex> lock(listeners_mutex);
                if (!listener_ctx->active) {
                    return false;
                }

                if (expired) {
                    return listener_ctx->callback(nullptr, 0, true, listener_ctx->user_data);
                }

                if (values.empty()) {
                    return true;
                }

                for (const auto& val : values) {
                    if (!val || val->data.empty()) continue;
                    if (!listener_ctx->callback(val->data.data(), val->data.size(),
                                                 false, listener_ctx->user_data)) {
                        return false;
                    }
                }
                return true;
            };

            // Resubscribe (may block, but mutex is NOT held)
            auto future = ctx->runner.listen(hash, cpp_callback);

            // Wait for token with timeout to avoid infinite hang
            auto status = future.wait_for(std::chrono::seconds(5));
            if (status == std::future_status::timeout) {
                QGP_LOG_ERROR(LOG_TAG, "Timeout resubscribing token %zu (5s)", token);
                continue;
            }

            size_t new_opendht_token = future.get();

            // Phase 3: Re-acquire mutex to update listener state
            {
                std::lock_guard<std::mutex> lock(listeners_mutex);
                // Verify listener still exists (might have been cancelled)
                auto it = active_listeners.find(token);
                if (it != active_listeners.end()) {
                    it->second->opendht_token = new_opendht_token;
                    it->second->active = true;
                    QGP_LOG_DEBUG(LOG_TAG, "Resubscribed token %zu (new OpenDHT: %zu)",
                                  token, new_opendht_token);
                    resubscribed++;
                }
            }

        } catch (const std::exception& e) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to resubscribe token %zu: %s", info.token, e.what());
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Resubscribed %zu/%zu listeners", resubscribed, to_resubscribe.size());
    return resubscribed;
}

/**
 * Check if a listener is currently active in the DHT layer
 */
extern "C" bool dht_is_listener_active(size_t token)
{
    if (token == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(listeners_mutex);
    auto it = active_listeners.find(token);
    if (it == active_listeners.end()) {
        return false;
    }
    return it->second->active;
}

/**
 * Get listener statistics for health monitoring
 */
extern "C" void dht_get_listener_stats(size_t *total, size_t *active, size_t *suspended)
{
    std::lock_guard<std::mutex> lock(listeners_mutex);

    size_t t = active_listeners.size();
    size_t a = 0;
    size_t s = 0;

    for (const auto& [token, ctx] : active_listeners) {
        if (ctx->active) {
            a++;
        } else {
            s++;
        }
    }

    if (total) *total = t;
    if (active) *active = a;
    if (suspended) *suspended = s;
}
