# Bootstrap Server Extensions - Plugin API

This directory is reserved for future extensible services that can be added to bootstrap nodes.

## Overview

Bootstrap nodes currently provide core DHT services (routing, keyserver, offline queue). The extension system allows new services to be added without modifying core bootstrap code.

## Planned Extensions (Phase 11+)

### 1. Name Registration Fees
- **Purpose:** CPUNK payment for DHT name registration (currently FREE in alpha)
- **Implementation:** Cellframe blockchain integration, payment verification
- **Files:** `name_payment/`

### 2. IPFS Gateway
- **Purpose:** Avatar and media pinning for popular content
- **Implementation:** IPFS HTTP gateway, local caching
- **Files:** `ipfs_gateway/`

### 3. Content Moderation
- **Purpose:** Spam filtering for wall posts, community voting
- **Implementation:** ML-based spam detection, reputation system
- **Files:** `content_moderation/`

### 4. P2P Relay Service
- **Purpose:** NAT traversal relay for blocked peers
- **Implementation:** TURN-like relay with Kyber1024 encryption
- **Files:** `p2p_relay/`

## Plugin API Design (Future)

When extensions are implemented, they will follow this API:

```c
// bootstrap/core/bootstrap_service.h

typedef struct {
    const char *service_name;          // Unique service identifier
    const char *version;               // Semantic version (e.g., "1.0.0")

    // Lifecycle callbacks
    int (*init)(dht_context_t *dht_ctx, void **service_ctx);
    int (*start)(void *service_ctx);
    void (*stop)(void *service_ctx);
    void (*cleanup)(void *service_ctx);

    // Monitoring
    void (*get_stats)(void *service_ctx, void *stats_out);

    // Optional: HTTP API endpoints
    int (*handle_http_request)(void *service_ctx,
                                const char *path,
                                const char *method,
                                const char *body,
                                char **response_out);
} bootstrap_service_t;
```

### Example: Registering a Service

```c
// In bootstrap_main.c

// 1. Include service headers
#include "services/keyserver_service.h"
#include "extensions/ipfs_gateway/ipfs_gateway_service.h"

// 2. Register services at startup
int main() {
    dht_context_t *dht_ctx = /* init DHT */;

    // Core services (always enabled)
    bootstrap_register_service(&keyserver_service);
    bootstrap_register_service(&offline_queue_service);

    // Extensions (conditionally enabled via config)
    if (config.enable_ipfs_gateway) {
        bootstrap_register_service(&ipfs_gateway_service);
    }

    // Start all services
    bootstrap_start_all_services(dht_ctx);

    // ... main loop ...

    // Cleanup on shutdown
    bootstrap_stop_all_services();
}
```

### Example: Implementing a Service

```c
// extensions/ipfs_gateway/ipfs_gateway_service.c

#include "../../core/bootstrap_service.h"
#include <ipfs_client.h>

typedef struct {
    dht_context_t *dht_ctx;
    ipfs_client_t *ipfs;
    // ... service state ...
} ipfs_gateway_ctx_t;

static int ipfs_init(dht_context_t *dht_ctx, void **service_ctx) {
    ipfs_gateway_ctx_t *ctx = calloc(1, sizeof(ipfs_gateway_ctx_t));
    ctx->dht_ctx = dht_ctx;
    ctx->ipfs = ipfs_client_new("http://127.0.0.1:5001");
    *service_ctx = ctx;
    return 0;
}

static int ipfs_start(void *service_ctx) {
    ipfs_gateway_ctx_t *ctx = (ipfs_gateway_ctx_t*)service_ctx;
    // Start background pinning thread
    return 0;
}

static void ipfs_stop(void *service_ctx) {
    // Stop pinning thread
}

static void ipfs_cleanup(void *service_ctx) {
    ipfs_gateway_ctx_t *ctx = (ipfs_gateway_ctx_t*)service_ctx);
    ipfs_client_free(ctx->ipfs);
    free(ctx);
}

static void ipfs_get_stats(void *service_ctx, void *stats_out) {
    // Return pinned content count, storage used, etc.
}

// Public service descriptor
const bootstrap_service_t ipfs_gateway_service = {
    .service_name = "ipfs-gateway",
    .version = "1.0.0",
    .init = ipfs_init,
    .start = ipfs_start,
    .stop = ipfs_stop,
    .cleanup = ipfs_cleanup,
    .get_stats = ipfs_get_stats,
    .handle_http_request = NULL  // Optional
};
```

## Configuration

Services can be enabled/disabled via config file:

```json
{
  "bootstrap": {
    "core_services": {
      "keyserver": true,
      "offline_queue": true
    },
    "extensions": {
      "ipfs_gateway": {
        "enabled": true,
        "ipfs_api": "http://127.0.0.1:5001",
        "max_pin_size": 10485760
      },
      "name_payment": {
        "enabled": false
      }
    }
  }
}
```

## Development Guidelines

When adding a new extension:

1. **Create subdirectory:** `extensions/<service_name>/`
2. **Implement service API:** Follow `bootstrap_service_t` interface
3. **Minimize dependencies:** Avoid pulling in heavy libraries
4. **Add to CMakeLists.txt:** Optional build flag
5. **Update documentation:** Add to this README
6. **Test isolation:** Service failure should not crash bootstrap node

## Why Plugins?

- **Extensibility:** Add new services without modifying core
- **Maintainability:** Clear separation of concerns
- **Optional features:** Users choose what to enable
- **Graceful degradation:** Service failure doesn't affect DHT routing

## Current Status

**This directory is currently empty.** The plugin API will be implemented in Phase 11+ after completing:
- Phase 10.2: DNA Board Alpha (wall posts)
- Phase 11: Post-Quantum Voice/Video Calls

For now, core services (keyserver, offline queue, value storage) are compiled directly into the bootstrap binary.

## Timeline

- **2025-Q4:** Plugin API design + documentation
- **2026-Q1:** IPFS gateway extension (Phase 10.3)
- **2026-Q2:** Name registration fees (Phase 11)
- **2026-Q3:** Content moderation (Phase 12)

## Contributing

If you want to propose a new bootstrap extension:
1. Open an issue on GitLab/GitHub with "Extension:" prefix
2. Describe the service purpose, API requirements, and dependencies
3. Discuss integration with DHT keyserver/offline queue
4. Submit PR with implementation following plugin API

---

**Note:** Until the plugin API is implemented, all services are statically compiled into `bootstrap/services/`. This directory is a placeholder for future extensibility.
