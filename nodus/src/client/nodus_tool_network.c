/**
 * Nodus — the native tools' network identity (DHT v2 package 3c)
 *
 * See nodus_tool_network.h for the file format and the decision.
 *
 * @file nodus_tool_network.c
 */

#include "client/nodus_tool_network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#ifdef NODUS_HAS_JSONC
#include <json-c/json.h>
#endif

#include "crypto/utils/qgp_safe_string.h"   /* unsafe-string poison guard */

#define TN_KEY_CHAIN  "chain_id"
#define TN_KEY_NODES  "nodes"
#define TN_KEY_IP     "ip"
#define TN_KEY_PORT   "port"
#define TN_KEY_FP     "fp"

/* A network file is a few KiB; refuse anything absurd before parsing. */
#define TN_FILE_MAX   (1024 * 1024)

/* Every function below names its error buffer `err` / `err_size`. */
#define TN_ERR(...) \
    do { if (err && err_size) snprintf(err, err_size, __VA_ARGS__); } while (0)
#define TN_ERR_CLEAR() \
    do { if (err && err_size) err[0] = '\0'; } while (0)

/* Exactly `nbytes` bytes as 2*nbytes LOWERCASE hex digits, not all zero. */
static int tn_hex(const char *s, size_t slen, uint8_t *out, size_t nbytes) {
    if (!s || slen != nbytes * 2 || strlen(s) != slen) return -1;
    uint8_t acc = 0;
    for (size_t i = 0; i < nbytes; i++) {
        int v[2];
        for (size_t k = 0; k < 2; k++) {
            char c = s[2 * i + k];
            if (c >= '0' && c <= '9') v[k] = c - '0';
            else if (c >= 'a' && c <= 'f') v[k] = c - 'a' + 10;
            else return -1;
        }
        out[i] = (uint8_t)((v[0] << 4) | v[1]);
        acc |= out[i];
    }
    return acc == 0 ? -1 : 0;
}

void nodus_tool_net_init(nodus_tool_net_t *t) {
    if (t) memset(t, 0, sizeof(*t));
}

static void tn_clear_file(nodus_tool_net_t *t) {
    t->has_file = false;
    t->node_count = 0;
    memset(t->chain, 0, sizeof(t->chain));
    memset(t->nodes, 0, sizeof(t->nodes));
}

#ifdef NODUS_HAS_JSONC
static int tn_parse_node(struct json_object *o, size_t idx,
                         nodus_tool_net_node_t *out,
                         char *err, size_t err_size) {
    if (!json_object_is_type(o, json_type_object)) {
        TN_ERR("node %zu is not an object", idx);
        return -1;
    }
    bool has_ip = false, has_port = false, has_fp = false;
    memset(out, 0, sizeof(*out));
    json_object_object_foreach(o, key, val) {
        if (strcmp(key, TN_KEY_IP) == 0) {
            if (!json_object_is_type(val, json_type_string)) {
                TN_ERR("node %zu: \"ip\" must be a string", idx);
                return -1;
            }
            const char *s = json_object_get_string(val);
            size_t sl = (size_t)json_object_get_string_len(val);
            struct in_addr a;
            if (sl == 0 || sl >= sizeof(out->ip) || strlen(s) != sl ||
                inet_pton(AF_INET, s, &a) != 1) {
                TN_ERR("node %zu: \"ip\" must be an IPv4 literal", idx);
                return -1;
            }
            memcpy(out->ip, s, sl + 1);
            has_ip = true;
        } else if (strcmp(key, TN_KEY_PORT) == 0) {
            if (!json_object_is_type(val, json_type_int)) {
                TN_ERR("node %zu: \"port\" must be an integer", idx);
                return -1;
            }
            int64_t p = json_object_get_int64(val);
            if (p < 1 || p > 65535) {
                TN_ERR("node %zu: \"port\" must be 1..65535", idx);
                return -1;
            }
            out->port = (uint16_t)p;
            has_port = true;
        } else if (strcmp(key, TN_KEY_FP) == 0) {
            const char *s = json_object_is_type(val, json_type_string)
                                ? json_object_get_string(val) : NULL;
            size_t sl = s ? (size_t)json_object_get_string_len(val) : 0;
            if (!s || tn_hex(s, sl, out->fp.bytes, NODUS_KEY_BYTES) != 0) {
                TN_ERR("node %zu: \"fp\" must be 128 lowercase hex digits, "
                       "not all zero", idx);
                return -1;
            }
            has_fp = true;
        } else {
            TN_ERR("node %zu: unknown key \"%s\" (allowed: ip, port, fp)",
                   idx, key);
            return -1;
        }
    }
    if (!has_ip || !has_port || !has_fp) {
        TN_ERR("node %zu: needs \"ip\", \"port\" and \"fp\"", idx);
        return -1;
    }
    return 0;
}

static int tn_validate(struct json_object *root, nodus_tool_net_t *t,
                       char *err, size_t err_size) {
    if (!json_object_is_type(root, json_type_object)) {
        TN_ERR("not a JSON object");
        return -1;
    }
    bool has_chain = false, has_nodes = false;
    json_object_object_foreach(root, key, val) {
        if (strcmp(key, TN_KEY_CHAIN) == 0) {
            const char *s = json_object_is_type(val, json_type_string)
                                ? json_object_get_string(val) : NULL;
            size_t sl = s ? (size_t)json_object_get_string_len(val) : 0;
            if (!s || tn_hex(s, sl, t->chain, NODUS_CLIENT_CHAIN_ID_SIZE)
                          != 0) {
                TN_ERR("\"chain_id\" must be 64 lowercase hex digits, not "
                       "all zero");
                return -1;
            }
            has_chain = true;
        } else if (strcmp(key, TN_KEY_NODES) == 0) {
            if (!json_object_is_type(val, json_type_array)) {
                TN_ERR("\"nodes\" must be an array");
                return -1;
            }
            size_t n = json_object_array_length(val);
            if (n == 0) {
                TN_ERR("\"nodes\" is empty");
                return -1;
            }
            if (n > NODUS_TOOL_NET_MAX_NODES) {
                TN_ERR("more than %d nodes", NODUS_TOOL_NET_MAX_NODES);
                return -1;
            }
            for (size_t i = 0; i < n; i++) {
                nodus_tool_net_node_t *nd = &t->nodes[i];
                if (tn_parse_node(json_object_array_get_idx(val, i), i, nd,
                                  err, err_size) != 0)
                    return -1;
                for (size_t j = 0; j < i; j++) {
                    if (t->nodes[j].port == nd->port &&
                        strcmp(t->nodes[j].ip, nd->ip) == 0) {
                        TN_ERR("node %zu: %s:%u listed twice", i, nd->ip,
                               (unsigned)nd->port);
                        return -1;
                    }
                }
            }
            t->node_count = (int)n;
            has_nodes = true;
        } else {
            TN_ERR("unknown key \"%s\" (allowed: chain_id, nodes)", key);
            return -1;
        }
    }
    if (!has_chain) { TN_ERR("\"chain_id\" is missing"); return -1; }
    if (!has_nodes) { TN_ERR("\"nodes\" is missing"); return -1; }
    return 0;
}
#endif /* NODUS_HAS_JSONC */

int nodus_tool_net_parse(nodus_tool_net_t *t, const char *text, size_t len,
                         char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t || !text) { TN_ERR("bad argument"); return -1; }
    tn_clear_file(t);
#ifdef NODUS_HAS_JSONC
    if (len == 0 || len > TN_FILE_MAX) {
        TN_ERR("network file is empty or too large");
        return -1;
    }
    struct json_tokener *tok = json_tokener_new();
    if (!tok) { TN_ERR("out of memory"); return -1; }
    json_tokener_set_flags(tok,
                           JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *root = json_tokener_parse_ex(tok, text, (int)len);
    enum json_tokener_error jerr = json_tokener_get_error(tok);
    size_t consumed = (size_t)tok->char_offset;
    json_tokener_free(tok);
    if (!root || jerr != json_tokener_success) {
        if (root) json_object_put(root);
        TN_ERR("not valid JSON");
        return -1;
    }
    /* Only whitespace may follow the document. */
    for (size_t i = consumed; i < len; i++) {
        char c = text[i];
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            json_object_put(root);
            TN_ERR("trailing characters after the JSON document");
            return -1;
        }
    }
    int rc = tn_validate(root, t, err, err_size);
    json_object_put(root);
    if (rc != 0) { tn_clear_file(t); return -1; }
    t->has_file = true;
    return 0;
#else
    (void)len;
    TN_ERR("this build has no json-c: a network file cannot be read, give "
           "--pin and --chain");
    return -1;
#endif
}

int nodus_tool_net_load_file(nodus_tool_net_t *t, const char *path,
                             char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t || !path || !path[0]) { TN_ERR("bad argument"); return -1; }
    FILE *f = fopen(path, "rb");
    if (!f) { TN_ERR("cannot open network file %s", path); return -1; }
    char *buf = malloc(TN_FILE_MAX + 1);
    if (!buf) { fclose(f); TN_ERR("out of memory"); return -1; }
    size_t n = fread(buf, 1, TN_FILE_MAX + 1, f);
    int bad = ferror(f);
    fclose(f);
    int rc = -1;
    if (bad) {
        TN_ERR("cannot read network file %s", path);
    } else if (n > TN_FILE_MAX) {
        TN_ERR("network file %s is larger than 1 MiB", path);
    } else {
        char why[NODUS_TOOL_NET_ERR_SIZE];
        rc = nodus_tool_net_parse(t, buf, n, why, sizeof(why));
        if (rc != 0) TN_ERR("network file %s: %s", path, why);
    }
    free(buf);
    return rc;
}

int nodus_tool_net_set_pin_hex(nodus_tool_net_t *t, const char *hex,
                               char *err, size_t err_size) {
    TN_ERR_CLEAR();
    nodus_key_t k;
    if (!t || !hex ||
        tn_hex(hex, strlen(hex), k.bytes, NODUS_KEY_BYTES) != 0) {
        TN_ERR("--pin must be 128 lowercase hex digits, not all zero");
        return -1;
    }
    t->pin_flag = k;
    t->has_pin_flag = true;
    return 0;
}

int nodus_tool_net_set_chain_hex(nodus_tool_net_t *t, const char *hex,
                                 char *err, size_t err_size) {
    TN_ERR_CLEAR();
    uint8_t c[NODUS_CLIENT_CHAIN_ID_SIZE];
    if (!t || !hex ||
        tn_hex(hex, strlen(hex), c, NODUS_CLIENT_CHAIN_ID_SIZE) != 0) {
        TN_ERR("--chain must be 64 lowercase hex digits, not all zero");
        return -1;
    }
    memcpy(t->chain_flag, c, sizeof(c));
    t->has_chain_flag = true;
    return 0;
}

int nodus_tool_net_open(nodus_tool_net_t *t, const char *network_path,
                        const char *pin_hex, const char *chain_hex,
                        char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t) { TN_ERR("bad argument"); return -1; }
    const char *path = network_path;
    if (!path || !path[0]) {
        const char *e = getenv(NODUS_TOOL_NET_ENV);
        path = (e && e[0]) ? e : NULL;
    }
    if (path && nodus_tool_net_load_file(t, path, err, err_size) != 0)
        return -1;
    if (pin_hex && nodus_tool_net_set_pin_hex(t, pin_hex, err, err_size) != 0)
        return -1;
    if (chain_hex &&
        nodus_tool_net_set_chain_hex(t, chain_hex, err, err_size) != 0)
        return -1;
    return 0;
}

int nodus_tool_net_resolve(const nodus_tool_net_t *t, const char *ip,
                           uint16_t port, nodus_key_t *pin_out,
                           uint8_t chain_out[NODUS_CLIENT_CHAIN_ID_SIZE],
                           char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t || !ip) { TN_ERR("bad argument"); return -1; }

    nodus_key_t pin;
    if (t->has_pin_flag) {
        pin = t->pin_flag;
    } else if (!t->has_file) {
        TN_ERR("no server pin for %s:%u: give --pin <fp hex>, or --network "
               "<file> / %s", ip, (unsigned)port, NODUS_TOOL_NET_ENV);
        return -1;
    } else {
        int found = -1;
        for (int i = 0; i < t->node_count; i++) {
            if (t->nodes[i].port == port && strcmp(t->nodes[i].ip, ip) == 0) {
                found = i;
                break;
            }
        }
        if (found < 0) {
            TN_ERR("%s:%u is not in the network file and no --pin was given",
                   ip, (unsigned)port);
            return -1;
        }
        pin = t->nodes[found].fp;
    }

    uint8_t chain[NODUS_CLIENT_CHAIN_ID_SIZE];
    if (t->has_chain_flag) {
        memcpy(chain, t->chain_flag, sizeof(chain));
    } else if (t->has_file) {
        memcpy(chain, t->chain, sizeof(chain));
    } else {
        TN_ERR("no chain id: give --chain <hex>, or --network <file> / %s",
               NODUS_TOOL_NET_ENV);
        return -1;
    }

    if (pin_out) *pin_out = pin;
    if (chain_out) memcpy(chain_out, chain, sizeof(chain));
    return 0;
}

/* The pin list a client holds is not copied by nodus_client_init, so the
 * tool keeps it in `t`. Find (or append) a run equal to run[0..n) in the
 * pool and return its start, or -1 when the pool is full. */
static int tn_pool_run(nodus_tool_net_t *t, const nodus_key_t *run, int n) {
    for (int s = 0; s + n <= t->pin_count; s++) {
        bool same = true;
        for (int k = 0; k < n && same; k++)
            same = nodus_key_cmp(&t->pins[s + k], &run[k]) == 0;
        if (same) return s;
    }
    int cap = (int)(sizeof(t->pins) / sizeof(t->pins[0]));
    if (t->pin_count + n > cap) return -1;
    int s = t->pin_count;
    for (int k = 0; k < n; k++) t->pins[s + k] = run[k];
    t->pin_count += n;
    return s;
}

int nodus_tool_net_fill(nodus_tool_net_t *t, nodus_client_config_t *cfg,
                        char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t || !cfg || cfg->server_count <= 0 ||
        cfg->server_count > NODUS_CLIENT_MAX_SERVERS) {
        TN_ERR("bad client config");
        return -1;
    }
    /* Resolve everything first; `cfg` and `t` change only when all pass. */
    nodus_key_t run[NODUS_CLIENT_MAX_SERVERS];
    int n = 0;
    uint8_t chain[NODUS_CLIENT_CHAIN_ID_SIZE];
    for (int i = 0; i < cfg->server_count; i++) {
        nodus_key_t pin;
        if (nodus_tool_net_resolve(t, cfg->servers[i].ip,
                                   cfg->servers[i].port, &pin, chain, err,
                                   err_size) != 0)
            return -1;
        bool have = false;
        for (int k = 0; k < n && !have; k++)
            have = nodus_key_cmp(&run[k], &pin) == 0;
        if (!have) run[n++] = pin;
    }
    int s = tn_pool_run(t, run, n);
    if (s < 0) { TN_ERR("too many distinct server pins"); return -1; }
    cfg->pinned_server_fps = &t->pins[s];
    cfg->pinned_server_fp_count = n;
    memcpy(cfg->expected_chain_id, chain, sizeof(chain));
    cfg->has_expected_chain_id = true;
    return 0;
}

int nodus_tool_net_fill_all(nodus_tool_net_t *t, nodus_client_config_t *cfg,
                            char *err, size_t err_size) {
    TN_ERR_CLEAR();
    if (!t || !cfg) { TN_ERR("bad argument"); return -1; }
    if (!t->has_file) {
        TN_ERR("no network file: give --network <file> / %s",
               NODUS_TOOL_NET_ENV);
        return -1;
    }
    int n = t->node_count < NODUS_CLIENT_MAX_SERVERS
                ? t->node_count : NODUS_CLIENT_MAX_SERVERS;
    nodus_server_endpoint_t saved[NODUS_CLIENT_MAX_SERVERS];
    int saved_count = cfg->server_count;
    memcpy(saved, cfg->servers, sizeof(saved));
    memset(cfg->servers, 0, sizeof(cfg->servers));
    for (int i = 0; i < n; i++) {
        snprintf(cfg->servers[i].ip, sizeof(cfg->servers[i].ip), "%s",
                 t->nodes[i].ip);
        cfg->servers[i].port = t->nodes[i].port;
    }
    cfg->server_count = n;
    if (nodus_tool_net_fill(t, cfg, err, err_size) != 0) {
        memcpy(cfg->servers, saved, sizeof(saved));
        cfg->server_count = saved_count;
        return -1;
    }
    return 0;
}
