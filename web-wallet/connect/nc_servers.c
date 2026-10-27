/* Nodus Connect thin core — the embedded server list (design rev 5 §1.6,
 * operator S9: validators of the checkpoint only in the first release; the
 * list format leaves room for a second, non-validator kind — §8 NC-F2).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"

#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

static int fail(char *why, size_t why_len, const char *msg) {
    if (why && why_len) snprintf(why, why_len, "%s", msg);
    return -1;
}

/* IPv4 dotted quad, each octet 0..255 without a leading zero — the form
 * nodus_tcp_connect resolves (inet_pton AF_INET) and the wallet's own
 * network settings accept (src/nodus/send-module.js IPV4). */
static int ipv4_ok(const char *s) {
    int parts = 0;
    while (*s) {
        int n = 0, digits = 0;
        if (s[0] == '0' && s[1] >= '0' && s[1] <= '9') return 0;
        while (*s >= '0' && *s <= '9') {
            n = n * 10 + (*s - '0');
            if (++digits > 3 || n > 255) return 0;
            s++;
        }
        if (digits == 0) return 0;
        parts++;
        if (*s == '.') { s++; if (!*s) return 0; }
        else if (*s) return 0;
    }
    return parts == 4;
}

static const char *str_field(json_object *o, const char *name) {
    json_object *v = NULL;
    if (!json_object_object_get_ex(o, name, &v) ||
        !json_object_is_type(v, json_type_string)) return NULL;
    return json_object_get_string(v);
}

int nc_servers_parse(const char *json, nc_servers_t *out,
                     char *why, size_t why_len) {
    if (!json || !out) return fail(why, why_len, "missing server list");
    memset(out, 0, sizeof(*out));

    json_object *root = json_tokener_parse(json);
    if (!root || !json_object_is_type(root, json_type_object)) {
        if (root) json_object_put(root);
        return fail(why, why_len, "server list is not a JSON object");
    }
    int rc = -1;
    const char *format = str_field(root, "format");
    json_object *ver = NULL, *entries = NULL;
    if (!format || strcmp(format, NC_SERVERS_FORMAT) != 0) {
        fail(why, why_len, "unknown server list format");
        goto done;
    }
    if (!json_object_object_get_ex(root, "version", &ver) ||
        !json_object_is_type(ver, json_type_int) ||
        json_object_get_int64(ver) != NC_SERVERS_VERSION) {
        fail(why, why_len, "unsupported server list version");
        goto done;
    }
    if (!json_object_object_get_ex(root, "entries", &entries) ||
        !json_object_is_type(entries, json_type_array)) {
        fail(why, why_len, "server list has no entries array");
        goto done;
    }

    size_t n = json_object_array_length(entries);
    for (size_t i = 0; i < n; i++) {
        json_object *e = json_object_array_get_idx(entries, i);
        if (!e || !json_object_is_type(e, json_type_object)) {
            fail(why, why_len, "a server entry is not an object");
            goto done;
        }
        const char *kind = str_field(e, "kind");
        if (!kind) { fail(why, why_len, "a server entry has no kind"); goto done; }
        if (strcmp(kind, NC_KIND_VALIDATOR) != 0) {
            out->skipped_kinds++;        /* a kind this build does not use */
            continue;
        }
        const char *pin = str_field(e, "pin");
        nodus_key_t k;
        if (!pin || nc_fp_parse(pin, &k) != 0) {
            fail(why, why_len, "a validator entry has no valid pin");
            goto done;
        }
        for (int j = 0; j < out->n_pins; j++) {
            if (memcmp(out->pins[j].bytes, k.bytes, NODUS_KEY_BYTES) == 0) {
                fail(why, why_len, "a pin is listed twice");
                goto done;
            }
        }
        if (out->n_pins >= NC_MAX_PINS) {
            fail(why, why_len, "too many pins");
            goto done;
        }
        out->pins[out->n_pins++] = k;

        json_object *jh = NULL, *jp = NULL;
        bool has_h = json_object_object_get_ex(e, "host", &jh);
        bool has_p = json_object_object_get_ex(e, "port", &jp);
        if (!has_h && !has_p) continue;       /* pinned, no WebSocket entry */
        if (!has_h || !has_p || !json_object_is_type(jh, json_type_string) ||
            !json_object_is_type(jp, json_type_int)) {
            fail(why, why_len, "a validator entry has a partial address");
            goto done;
        }
        const char *host = json_object_get_string(jh);
        int64_t port = json_object_get_int64(jp);
        if (!ipv4_ok(host) ||
            strlen(host) >= sizeof(out->endpoints[0].ip) ||
            port < 1 || port > 65535) {
            fail(why, why_len, "a validator entry has an invalid address");
            goto done;
        }
        if (out->n_endpoints >= NODUS_CLIENT_MAX_SERVERS) {
            fail(why, why_len, "too many endpoints");
            goto done;
        }
        nodus_server_endpoint_t *ep = &out->endpoints[out->n_endpoints++];
        memset(ep, 0, sizeof(*ep));
        memcpy(ep->ip, host, strlen(host));
        ep->port = (uint16_t)port;
    }
    if (out->n_endpoints == 0 || out->n_pins == 0) {
        fail(why, why_len, "server list has no usable validator");
        goto done;
    }
    rc = 0;

done:
    json_object_put(root);
    if (rc != 0) memset(out, 0, sizeof(*out));
    return rc;
}
