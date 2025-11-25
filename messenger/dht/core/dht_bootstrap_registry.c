/**
 * DHT Bootstrap Node Registry - Implementation
 */

#include "dht_bootstrap_registry.h"
#include "dht_context.h"
#include "../../crypto/utils/qgp_sha3.h"
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * Compute the well-known registry DHT key
 * Key = SHA3-512("dna:bootstrap:registry")
 */
void dht_bootstrap_registry_get_key(char *key_out) {
    const char *registry_id = "dna:bootstrap:registry";
    uint8_t hash[64];  // SHA3-512 = 64 bytes

    qgp_sha3_512((uint8_t*)registry_id, strlen(registry_id), hash);

    // Convert to hex string (128 chars)
    for (int i = 0; i < 64; i++) {
        sprintf(key_out + (i * 2), "%02x", hash[i]);
    }
    key_out[128] = '\0';
}

/**
 * Serialize registry to JSON
 */
char* dht_bootstrap_registry_to_json(const bootstrap_registry_t *registry) {
    if (!registry) return NULL;

    json_object *root = json_object_new_object();
    json_object *nodes_array = json_object_new_array();

    json_object_object_add(root, "version", json_object_new_int64(registry->registry_version));
    json_object_object_add(root, "node_count", json_object_new_int64(registry->node_count));

    for (size_t i = 0; i < registry->node_count; i++) {
        const bootstrap_node_entry_t *node = &registry->nodes[i];

        json_object *node_obj = json_object_new_object();
        json_object_object_add(node_obj, "ip", json_object_new_string(node->ip));
        json_object_object_add(node_obj, "port", json_object_new_int(node->port));
        json_object_object_add(node_obj, "node_id", json_object_new_string(node->node_id));
        json_object_object_add(node_obj, "version", json_object_new_string(node->version));
        json_object_object_add(node_obj, "last_seen", json_object_new_int64(node->last_seen));
        json_object_object_add(node_obj, "uptime", json_object_new_int64(node->uptime));

        json_object_array_add(nodes_array, node_obj);
    }

    json_object_object_add(root, "nodes", nodes_array);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);

    json_object_put(root);
    return result;
}

/**
 * Deserialize registry from JSON
 */
int dht_bootstrap_registry_from_json(const char *json_str, bootstrap_registry_t *registry) {
    if (!json_str || !registry) return -1;

    memset(registry, 0, sizeof(bootstrap_registry_t));

    json_object *root = json_tokener_parse(json_str);
    if (!root) {
        fprintf(stderr, "[REGISTRY] Failed to parse JSON\n");
        return -1;
    }

    // Parse version
    json_object *version_obj;
    if (json_object_object_get_ex(root, "version", &version_obj)) {
        registry->registry_version = json_object_get_int64(version_obj);
    }

    // Parse nodes array
    json_object *nodes_array;
    if (!json_object_object_get_ex(root, "nodes", &nodes_array)) {
        json_object_put(root);
        return -1;
    }

    size_t array_len = json_object_array_length(nodes_array);
    registry->node_count = (array_len < DHT_BOOTSTRAP_MAX_NODES) ? array_len : DHT_BOOTSTRAP_MAX_NODES;

    for (size_t i = 0; i < registry->node_count; i++) {
        json_object *node_obj = json_object_array_get_idx(nodes_array, i);
        bootstrap_node_entry_t *node = &registry->nodes[i];

        json_object *ip_obj, *port_obj, *node_id_obj, *ver_obj, *last_seen_obj, *uptime_obj;

        if (json_object_object_get_ex(node_obj, "ip", &ip_obj)) {
            strncpy(node->ip, json_object_get_string(ip_obj), sizeof(node->ip) - 1);
        }
        if (json_object_object_get_ex(node_obj, "port", &port_obj)) {
            node->port = json_object_get_int(port_obj);
        }
        if (json_object_object_get_ex(node_obj, "node_id", &node_id_obj)) {
            strncpy(node->node_id, json_object_get_string(node_id_obj), sizeof(node->node_id) - 1);
        }
        if (json_object_object_get_ex(node_obj, "version", &ver_obj)) {
            strncpy(node->version, json_object_get_string(ver_obj), sizeof(node->version) - 1);
        }
        if (json_object_object_get_ex(node_obj, "last_seen", &last_seen_obj)) {
            node->last_seen = json_object_get_int64(last_seen_obj);
        }
        if (json_object_object_get_ex(node_obj, "uptime", &uptime_obj)) {
            node->uptime = json_object_get_int64(uptime_obj);
        }
    }

    json_object_put(root);
    return 0;
}

/**
 * Register this bootstrap node in the DHT registry
 */
int dht_bootstrap_registry_register(
    dht_context_t *dht_ctx,
    const char *my_ip,
    uint16_t my_port,
    const char *node_id,
    const char *version,
    uint64_t uptime)
{
    if (!dht_ctx || !my_ip || !node_id || !version) return -1;

    printf("[REGISTRY] Registering bootstrap node: %s:%d\n", my_ip, my_port);

    // Step 1: Fetch existing registry
    bootstrap_registry_t registry;
    memset(&registry, 0, sizeof(registry));

    char dht_key[129];
    dht_bootstrap_registry_get_key(dht_key);

    uint8_t *existing_value = NULL;
    size_t existing_len = 0;

    if (dht_get(dht_ctx, (uint8_t*)dht_key, strlen(dht_key), &existing_value, &existing_len) == 0 && existing_value) {
        // Parse existing registry
        char *json_str = strndup((char*)existing_value, existing_len);
        if (dht_bootstrap_registry_from_json(json_str, &registry) != 0) {
            printf("[REGISTRY] Creating new registry (failed to parse existing)\n");
            memset(&registry, 0, sizeof(registry));
        }
        free(json_str);
        free(existing_value);
    } else {
        printf("[REGISTRY] Creating new registry (none found)\n");
    }

    // Step 2: Update or add this node
    uint64_t now = time(NULL);
    int found = -1;

    for (size_t i = 0; i < registry.node_count; i++) {
        if (strcmp(registry.nodes[i].node_id, node_id) == 0) {
            found = i;
            break;
        }
    }

    if (found >= 0) {
        // Update existing entry
        bootstrap_node_entry_t *node = &registry.nodes[found];
        strncpy(node->ip, my_ip, sizeof(node->ip) - 1);
        node->port = my_port;
        strncpy(node->version, version, sizeof(node->version) - 1);
        node->last_seen = now;
        node->uptime = uptime;
        printf("[REGISTRY] Updated existing entry (index %d)\n", found);
    } else {
        // Add new entry
        if (registry.node_count >= DHT_BOOTSTRAP_MAX_NODES) {
            fprintf(stderr, "[REGISTRY] Registry full, cannot add node\n");
            return -1;
        }

        bootstrap_node_entry_t *node = &registry.nodes[registry.node_count];
        strncpy(node->ip, my_ip, sizeof(node->ip) - 1);
        node->port = my_port;
        strncpy(node->node_id, node_id, sizeof(node->node_id) - 1);
        strncpy(node->version, version, sizeof(node->version) - 1);
        node->last_seen = now;
        node->uptime = uptime;

        registry.node_count++;
        printf("[REGISTRY] Added new entry (total: %zu nodes)\n", registry.node_count);
    }

    registry.registry_version++;

    // Step 3: Serialize and publish
    char *json = dht_bootstrap_registry_to_json(&registry);
    if (!json) {
        fprintf(stderr, "[REGISTRY] Failed to serialize registry\n");
        return -1;
    }

    printf("[REGISTRY] Publishing registry (%zu nodes, version %lu)\n",
           registry.node_count, registry.registry_version);

    // Use 7-day TTL, value_id=1 for replacement
    // Nodes refresh every 5 minutes, so 7 days is plenty
    unsigned int ttl_7days = 7 * 24 * 3600;
    int ret = dht_put_signed(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                             (uint8_t*)json, strlen(json), 1, ttl_7days);

    free(json);

    if (ret != 0) {
        fprintf(stderr, "[REGISTRY] Failed to publish registry to DHT\n");
        return -1;
    }

    printf("[REGISTRY] ✓ Successfully registered\n");
    return 0;
}

/**
 * Helper: Check if node already exists in registry (by IP:port)
 */
static int find_node_by_ip_port(const bootstrap_registry_t *reg, const char *ip, uint16_t port) {
    for (size_t i = 0; i < reg->node_count; i++) {
        if (strcmp(reg->nodes[i].ip, ip) == 0 && reg->nodes[i].port == port) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Fetch the bootstrap registry from DHT
 * Gets ALL values from all owners and merges them
 */
int dht_bootstrap_registry_fetch(dht_context_t *dht_ctx, bootstrap_registry_t *registry_out) {
    if (!dht_ctx || !registry_out) return -1;

    char dht_key[129];
    dht_bootstrap_registry_get_key(dht_key);

    printf("[REGISTRY] Fetching bootstrap registry from DHT (all owners)...\n");

    // Get ALL values at this key (from all owners/signers)
    uint8_t **values = NULL;
    size_t *values_len = NULL;
    size_t count = 0;

    if (dht_get_all(dht_ctx, (uint8_t*)dht_key, strlen(dht_key),
                    &values, &values_len, &count) != 0 || count == 0) {
        fprintf(stderr, "[REGISTRY] No registry found in DHT\n");
        return -1;
    }

    printf("[REGISTRY] Found %zu registry version(s) from different owners\n", count);

    // Initialize output registry
    memset(registry_out, 0, sizeof(bootstrap_registry_t));

    // Parse each registry JSON and merge nodes
    for (size_t i = 0; i < count; i++) {
        if (!values[i] || values_len[i] == 0) continue;

        char *json_str = strndup((char*)values[i], values_len[i]);
        if (!json_str) continue;

        bootstrap_registry_t temp_reg;
        memset(&temp_reg, 0, sizeof(temp_reg));

        if (dht_bootstrap_registry_from_json(json_str, &temp_reg) == 0) {
            // Merge nodes from temp_reg into registry_out
            for (size_t j = 0; j < temp_reg.node_count; j++) {
                bootstrap_node_entry_t *node = &temp_reg.nodes[j];
                int existing = find_node_by_ip_port(registry_out, node->ip, node->port);

                if (existing >= 0) {
                    // Update if this entry is newer
                    if (node->last_seen > registry_out->nodes[existing].last_seen) {
                        registry_out->nodes[existing] = *node;
                    }
                } else if (registry_out->node_count < DHT_BOOTSTRAP_MAX_NODES) {
                    // Add new node
                    registry_out->nodes[registry_out->node_count++] = *node;
                }
            }

            // Track highest version
            if (temp_reg.registry_version > registry_out->registry_version) {
                registry_out->registry_version = temp_reg.registry_version;
            }
        }

        free(json_str);
        free(values[i]);
    }

    free(values);
    free(values_len);

    printf("[REGISTRY] ✓ Merged registry: %zu unique nodes (version %lu)\n",
           registry_out->node_count, registry_out->registry_version);

    return (registry_out->node_count > 0) ? 0 : -1;
}

/**
 * Filter registry to only include active nodes (last_seen < 15 min)
 */
void dht_bootstrap_registry_filter_active(bootstrap_registry_t *registry) {
    if (!registry) return;

    uint64_t now = time(NULL);
    size_t active_count = 0;

    for (size_t i = 0; i < registry->node_count; i++) {
        if (now - registry->nodes[i].last_seen < DHT_BOOTSTRAP_STALE_TIMEOUT) {
            // Node is active, keep it
            if (i != active_count) {
                registry->nodes[active_count] = registry->nodes[i];
            }
            active_count++;
        }
    }

    size_t filtered = registry->node_count - active_count;
    registry->node_count = active_count;

    if (filtered > 0) {
        printf("[REGISTRY] Filtered %zu stale nodes (active: %zu)\n", filtered, active_count);
    }
}
