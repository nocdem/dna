/**
 * DHT Bootstrap Node Registry - Implementation
 *
 * Storage Model (Owner-Namespaced via Chunked):
 * - Each node's entry stored at: dna:bootstrap:node:node_id (chunked)
 * - Node index at: dna:bootstrap:nodes (multi-owner, small)
 */

#include "dht_bootstrap_registry.h"
#include "dht_context.h"
#include "../shared/dht_chunked.h"
#include "../../crypto/utils/qgp_sha3.h"
#include <json-c/json.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * Make base key for a node's entry
 * Format: dna:bootstrap:node:node_id
 */
static void make_node_base_key(const char *node_id, char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "dna:bootstrap:node:%s", node_id);
}

/**
 * Make key for node index (multi-owner, small)
 * Format: dna:bootstrap:nodes
 */
static void make_nodes_index_key(char *key_out, size_t key_out_size) {
    snprintf(key_out, key_out_size, "dna:bootstrap:nodes");
}

/**
 * Serialize single node entry to JSON
 */
static char* node_entry_to_json(const bootstrap_node_entry_t *node) {
    if (!node) return NULL;

    json_object *node_obj = json_object_new_object();
    json_object_object_add(node_obj, "ip", json_object_new_string(node->ip));
    json_object_object_add(node_obj, "port", json_object_new_int(node->port));
    json_object_object_add(node_obj, "node_id", json_object_new_string(node->node_id));
    json_object_object_add(node_obj, "version", json_object_new_string(node->version));
    json_object_object_add(node_obj, "last_seen", json_object_new_int64(node->last_seen));
    json_object_object_add(node_obj, "uptime", json_object_new_int64(node->uptime));

    const char *json_str = json_object_to_json_string_ext(node_obj, JSON_C_TO_STRING_PLAIN);
    char *result = strdup(json_str);

    json_object_put(node_obj);
    return result;
}

/**
 * Deserialize single node entry from JSON
 */
static int node_entry_from_json(const char *json_str, bootstrap_node_entry_t *node) {
    if (!json_str || !node) return -1;

    memset(node, 0, sizeof(bootstrap_node_entry_t));

    json_object *node_obj = json_tokener_parse(json_str);
    if (!node_obj) return -1;

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

    json_object_put(node_obj);
    return 0;
}

/**
 * Serialize registry to JSON (for compatibility)
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
 * Register this bootstrap node in the DHT registry (Owner-Namespaced)
 *
 * Storage:
 * - Node entry at: dna:bootstrap:node:node_id (chunked)
 * - Node index at: dna:bootstrap:nodes (multi-owner, small)
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

    printf("[REGISTRY] Registering bootstrap node: %s:%d (owner-namespaced)\n", my_ip, my_port);

    // Step 1: Create this node's entry
    bootstrap_node_entry_t node_entry;
    memset(&node_entry, 0, sizeof(node_entry));

    strncpy(node_entry.ip, my_ip, sizeof(node_entry.ip) - 1);
    node_entry.port = my_port;
    strncpy(node_entry.node_id, node_id, sizeof(node_entry.node_id) - 1);
    strncpy(node_entry.version, version, sizeof(node_entry.version) - 1);
    node_entry.last_seen = time(NULL);
    node_entry.uptime = uptime;

    // Step 2: Serialize and publish this node's entry via chunked
    char *json = node_entry_to_json(&node_entry);
    if (!json) {
        fprintf(stderr, "[REGISTRY] Failed to serialize node entry\n");
        return -1;
    }

    char node_key[256];
    make_node_base_key(node_id, node_key, sizeof(node_key));

    printf("[REGISTRY] Publishing node entry via chunked\n");
    int ret = dht_chunked_publish(dht_ctx, node_key,
                                   (uint8_t*)json, strlen(json),
                                   DHT_CHUNK_TTL_7DAY);
    free(json);

    if (ret != DHT_CHUNK_OK) {
        fprintf(stderr, "[REGISTRY] Failed to publish node entry: %s\n", dht_chunked_strerror(ret));
        return -1;
    }

    // Step 3: Register node_id in index (multi-owner, small)
    char index_key[256];
    make_nodes_index_key(index_key, sizeof(index_key));

    // Get unique value_id for this DHT identity (prevents overwrites between owners)
    uint64_t value_id = 1;
    dht_get_owner_value_id(dht_ctx, &value_id);

    printf("[REGISTRY] Registering node_id in index (value_id=%lu)\n", value_id);
    ret = dht_put_signed(dht_ctx, (uint8_t*)index_key, strlen(index_key),
                         (uint8_t*)node_id, strlen(node_id),
                         value_id, DHT_CHUNK_TTL_7DAY);

    if (ret != 0) {
        // Non-fatal - node entry is already stored
        fprintf(stderr, "[REGISTRY] Warning: Failed to register in nodes index\n");
    }

    printf("[REGISTRY] ✓ Successfully registered node %s\n", node_id);
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
 * Fetch the bootstrap registry from DHT (Owner-Namespaced)
 *
 * Gets node index → fetches each node's entry → merges
 */
int dht_bootstrap_registry_fetch(dht_context_t *dht_ctx, bootstrap_registry_t *registry_out) {
    if (!dht_ctx || !registry_out) return -1;

    printf("[REGISTRY] Fetching bootstrap registry (owner-namespaced)...\n");

    // Step 1: Get node index (multi-owner, small node_id list)
    char index_key[256];
    make_nodes_index_key(index_key, sizeof(index_key));

    uint8_t **index_values = NULL;
    size_t *index_lens = NULL;
    size_t index_count = 0;

    int ret = dht_get_all(dht_ctx, (uint8_t*)index_key, strlen(index_key),
                          &index_values, &index_lens, &index_count);

    // Collect unique node_ids
    char **node_ids = NULL;
    size_t num_node_ids = 0;

    if (ret == 0 && index_count > 0) {
        node_ids = calloc(index_count, sizeof(char *));
        if (node_ids) {
            for (size_t i = 0; i < index_count; i++) {
                if (index_values[i] && index_lens[i] > 0 && index_lens[i] < 256) {
                    char *nid = malloc(index_lens[i] + 1);
                    if (nid) {
                        memcpy(nid, index_values[i], index_lens[i]);
                        nid[index_lens[i]] = '\0';

                        // Dedup
                        bool duplicate = false;
                        for (size_t j = 0; j < num_node_ids; j++) {
                            if (strcmp(node_ids[j], nid) == 0) {
                                duplicate = true;
                                break;
                            }
                        }
                        if (!duplicate) {
                            node_ids[num_node_ids++] = nid;
                        } else {
                            free(nid);
                        }
                    }
                }
                free(index_values[i]);
            }
        }
        free(index_values);
        free(index_lens);
    }

    printf("[REGISTRY] Found %zu unique node_ids in index\n", num_node_ids);

    // Initialize output registry
    memset(registry_out, 0, sizeof(bootstrap_registry_t));

    // Step 2: Fetch each node's entry via chunked
    for (size_t n = 0; n < num_node_ids && registry_out->node_count < DHT_BOOTSTRAP_MAX_NODES; n++) {
        char node_key[256];
        make_node_base_key(node_ids[n], node_key, sizeof(node_key));

        uint8_t *data = NULL;
        size_t data_len = 0;

        ret = dht_chunked_fetch(dht_ctx, node_key, &data, &data_len);
        if (ret != DHT_CHUNK_OK || !data) {
            printf("[REGISTRY] Node %s: no data\n", node_ids[n]);
            continue;
        }

        // Parse node entry
        char *json_str = malloc(data_len + 1);
        if (!json_str) {
            free(data);
            continue;
        }
        memcpy(json_str, data, data_len);
        json_str[data_len] = '\0';
        free(data);

        bootstrap_node_entry_t node_entry;
        if (node_entry_from_json(json_str, &node_entry) == 0) {
            // Check if node already exists by IP:port
            int existing = find_node_by_ip_port(registry_out, node_entry.ip, node_entry.port);
            if (existing >= 0) {
                // Update if this entry is newer
                if (node_entry.last_seen > registry_out->nodes[existing].last_seen) {
                    registry_out->nodes[existing] = node_entry;
                }
            } else {
                // Add new node
                registry_out->nodes[registry_out->node_count++] = node_entry;
            }
        }
        free(json_str);
    }

    // Free node_ids
    for (size_t i = 0; i < num_node_ids; i++) free(node_ids[i]);
    free(node_ids);

    printf("[REGISTRY] ✓ Fetched registry: %zu nodes\n", registry_out->node_count);

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
