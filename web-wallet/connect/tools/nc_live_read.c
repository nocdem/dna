/**
 * Nodus Connect thin core — live READ-ONLY probe (package NC-3a; design
 * docs/plans/2026-09-24-web-connect-design.md rev 5 §1.4 R0-R5; thin-core
 * decision docs/plans/decisions/2026-09-30-nodus-connect-thin-core.md).
 *
 * Proves that the web thin core (web-wallet/connect/nc_*.c, compiled from the
 * same set as web-wallet/connect/tests/CMakeLists.txt) reads the records the
 * frozen app (dna-connect-cli / libdna) wrote to a live Nodus node. It only
 * READS, through the core's R0 read functions, and prints for each record its
 * classification (FOUND / EMPTY / UNREADABLE + reason) and a non-secret
 * summary.
 *
 * Usage:
 *   nc_live_read <words-file> [<peer fp, 128 lowercase hex>]
 *                --server <IPv4>:<port> [--server-fp <128 hex>]
 *
 *   <words-file>  the 24 BIP39 words; the file must be a regular file with
 *                 mode exactly 0600. The words are never printed.
 *   --server      a tier-2 TCP endpoint. The native client connects to an
 *                 IPv4 literal only (nodus_tcp.c inet_pton(AF_INET)).
 *   --server-fp   optional server-key pin: the client's own
 *                 pinned_server_fps (nodus.h) — the connection fails closed
 *                 unless the node's AUTH_OK carries a signed channel key
 *                 from a server key with this fingerprint AND a signed
 *                 ML-KEM-1024 key (a pinned session is ML-KEM-1024 only).
 *                 Without it the session trusts the node on first use.
 *
 * Reads, in order: own profile (R1), own contact list (R4), own contact
 * request inbox (R2); with a peer: the peer's profile (R1, needed for the
 * peer's keys), the salt agreement with the peer (R3), and today's outbox
 * bucket the peer wrote to this identity (R5). The outbox key requires a
 * salt (dm_outbox_codec.c dht_dm_outbox_make_key refuses NULL): the salt
 * agreement's salt is used when found, else the peer's salt from the own
 * contact list, else the outbox read is NOT RUN.
 *
 * Exit: 0 every read completed (any classification); 1 usage error (bad
 * arguments, words file refused, key derivation refused); 2 the client
 * could not connect.
 *
 * NEVER printed: the words, any key, any salt, any message body, any
 * request message or self-asserted sender name.
 *
 * FORBIDDEN — this file must never reference any function that writes to
 * the DHT. The orchestrator checks the object file with `nm -u`:
 *   nc_put, nc_profile_publish, nc_request_send, nc_request_accept,
 *   nc_request_cancel, nc_salt_sync, nc_contactlist_add, nc_outbox_publish,
 *   nc_ack_publish, nodus_client_put, nodus_client_put_ex, and any other
 *   *_publish / *_send / *_accept / *_cancel / *_add / *_sync function.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "nc_core.h"
#include "dht/shared/dht_dm_outbox.h"   /* dht_dm_outbox_get_day_bucket */
#include "crypto/utils/qgp_platform.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define WORDS_BUF 2048   /* the CLI's own mnemonic buffer, cli_commands.c */

static void usage(void) {
    printf("usage: nc_live_read <words-file> [<peer fp>] --server <IPv4>:<port> "
           "[--server-fp <128 hex>]\n");
}

/* Read the words file (regular, mode 0600) and rebuild the app's canonical
 * form: tokens joined by one space (cli_commands.c identity restore). The
 * mode is checked on the opened descriptor, not on the path. 0 / -1. */
static int read_words(const char *path, char *out, size_t out_len) {
    char raw[WORDS_BUF];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        printf("words file: cannot open (%s)\n", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        printf("words file: not a regular file\n");
        close(fd);
        return -1;
    }
    if ((st.st_mode & 0777) != 0600) {
        printf("words file: mode %03o refused (must be 0600)\n",
               (unsigned)(st.st_mode & 0777));
        close(fd);
        return -1;
    }
    size_t n = 0;
    for (;;) {
        ssize_t r = read(fd, raw + n, sizeof(raw) - 1 - n);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) break;
        n += (size_t)r;
        if (n >= sizeof(raw) - 1) break;
    }
    close(fd);
    if (n >= sizeof(raw) - 1) {
        printf("words file: too large\n");
        qgp_secure_memzero(raw, sizeof(raw));
        return -1;
    }
    raw[n] = '\0';

    size_t o = 0;
    size_t i = 0;
    int rc = 0;
    while (raw[i]) {
        while (raw[i] && isspace((unsigned char)raw[i])) i++;
        if (!raw[i]) break;
        if (o > 0) {
            if (o + 1 >= out_len) { rc = -1; break; }
            out[o++] = ' ';
        }
        while (raw[i] && !isspace((unsigned char)raw[i])) {
            if (o + 1 >= out_len) { rc = -1; break; }
            out[o++] = raw[i++];
        }
        if (rc != 0) break;
    }
    out[o < out_len ? o : out_len - 1] = '\0';
    qgp_secure_memzero(raw, sizeof(raw));
    if (rc != 0 || o == 0) {
        printf("words file: empty or too long\n");
        qgp_secure_memzero(out, out_len);
        return -1;
    }
    return 0;
}

/* "<IPv4>:<port>" -> endpoint. 0 / -1. */
static int parse_server(const char *s, nodus_server_endpoint_t *ep) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s || (size_t)(colon - s) >= sizeof(ep->ip))
        return -1;
    memset(ep, 0, sizeof(*ep));
    memcpy(ep->ip, s, (size_t)(colon - s));
    struct in_addr a;
    if (inet_pton(AF_INET, ep->ip, &a) != 1) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long port = strtoul(colon + 1, &end, 10);
    if (errno != 0 || !end || *end != '\0' || end == colon + 1 ||
        port == 0 || port > 65535)
        return -1;
    ep->port = (uint16_t)port;
    return 0;
}

static void print_read(const char *record, nc_outcome_t o, nc_why_t why,
                       int node_rc) {
    if (o == NC_UNREADABLE)
        printf("[%s] UNREADABLE (%s, rc=%d)\n", record, nc_why_str(why),
               node_rc);
    else
        printf("[%s] %s\n", record, o == NC_FOUND ? "FOUND" : "EMPTY");
}

static void print_lib_error(const char *record, int rc) {
    printf("[%s] UNREADABLE (library rc=%d)\n", record, rc);
}

static void print_profile_summary(const dna_unified_identity_t *id) {
    printf("  registered_name: %s\n",
           id->has_registered_name ? id->registered_name : "(none)");
    printf("  version: %u  has_mlkem: %s\n", (unsigned)id->version,
           id->has_mlkem_pubkey ? "yes" : "no");
    const dna_wallets_t *w = &id->wallets;
    const dna_socials_t *so = &id->socials;
    int wallets = w->backbone[0] || w->alvin[0] || w->eth[0] || w->sol[0] ||
                  w->trx[0] || w->bsc[0];
    int socials = so->telegram[0] || so->x[0] || so->github[0] ||
                  so->facebook[0] || so->instagram[0] || so->linkedin[0] ||
                  so->google[0];
    printf("  fields present:%s%s%s%s%s%s%s\n",
           id->display_name[0] ? " display_name" : "",
           id->bio[0] ? " bio" : "",
           id->location[0] ? " location" : "",
           id->website[0] ? " website" : "",
           id->avatar_base64[0] ? " avatar" : "",
           wallets ? " wallets" : "",
           socials ? " socials" : "");
}

/* R1: a profile read; fills `peer_out` (nullable) on FOUND. Returns true on
 * FOUND. */
static bool read_profile(const nc_ctx_t *ctx, const char *record,
                         const char *fp, nc_peer_t *peer_out) {
    nc_read_t raw;
    dna_unified_identity_t *id = NULL;
    nc_profile_read(ctx, fp, &raw, &id, peer_out);
    print_read(record, raw.outcome, raw.why, raw.node_rc);
    printf("  fp: %.16s...\n", fp);
    bool found = raw.outcome == NC_FOUND && id;
    if (found) print_profile_summary(id);
    if (id) dna_identity_free(id);
    nc_read_clear(&raw);
    return found;
}

int main(int argc, char **argv) {
    const char *words_path = NULL, *peer_fp = NULL, *server = NULL,
               *server_fp = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            server = argv[++i];
        } else if (strcmp(argv[i], "--server-fp") == 0 && i + 1 < argc) {
            server_fp = argv[++i];
        } else if (argv[i][0] == '-') {
            usage();
            return 1;
        } else if (!words_path) {
            words_path = argv[i];
        } else if (!peer_fp) {
            peer_fp = argv[i];
        } else {
            usage();
            return 1;
        }
    }
    if (!words_path || !server) { usage(); return 1; }

    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (parse_server(server, &cfg.servers[0]) != 0) {
        printf("--server: expected <IPv4>:<port>\n");
        return 1;
    }
    cfg.server_count = 1;
    /* connect / request timeouts 0 = the client's defaults
     * (nodus_client_init); auto_reconnect stays off (zeroed config). */

    /* The pin array is not copied by the client and must outlive it
     * (nodus.h pinned_server_fps). */
    static nodus_key_t pin;
    if (server_fp) {
        if (nc_fp_parse(server_fp, &pin) != 0) {
            printf("--server-fp: expected 128 lowercase hex\n");
            return 1;
        }
        cfg.pinned_server_fps = &pin;
        cfg.pinned_server_fp_count = 1;
    }

    nodus_key_t peer_key;
    if (peer_fp && nc_fp_parse(peer_fp, &peer_key) != 0) {
        printf("peer fp: expected 128 lowercase hex\n");
        return 1;
    }

    static char words[WORDS_BUF];
    if (read_words(words_path, words, sizeof(words)) != 0) return 1;
    nc_keys_t *keys = calloc(1, sizeof(*keys));
    if (!keys) {
        qgp_secure_memzero(words, sizeof(words));
        printf("out of memory\n");
        return 1;
    }
    int krc = nc_keys_from_words(words, keys);
    qgp_secure_memzero(words, sizeof(words));
    if (krc != NC_OK) {
        printf("words refused by key derivation (rc=%d)\n", krc);
        free(keys);
        return 1;
    }
    printf("identity fp: %.16s...\n", keys->fp);
    printf("server: %s:%u  pin: %s\n", cfg.servers[0].ip,
           (unsigned)cfg.servers[0].port, server_fp ? "set" : "none (TOFU)");

    nodus_client_t *c = calloc(1, sizeof(*c));
    bool inited = c && nodus_client_init(c, &cfg, &keys->id) == 0;
    if (!inited || nodus_client_connect(c) != 0 || !nodus_client_is_ready(c)) {
        printf("connect: FAILED\n");
        if (inited) nodus_client_close(c);
        free(c);
        nc_keys_wipe(keys);
        free(keys);
        return 2;
    }
    printf("connect: READY\n");

    static int cancel_flag;
    nc_ctx_t ctx = { .client = c, .keys = keys, .fresh = false,
                     .cancel = &cancel_flag };

    /* R1 own profile */
    read_profile(&ctx, "own profile", keys->fp, NULL);

    /* R4 own contact list */
    nc_contactlist_t list;
    nc_contactlist_read(&ctx, &list);
    print_read("own contact list", list.read.outcome, list.read.why,
               list.read.node_rc);
    bool list_salt_found = false;
    uint8_t list_salt[NC_SALT_LEN];
    memset(list_salt, 0, sizeof(list_salt));
    bool peer_in_list = false;
    if (list.read.outcome == NC_FOUND) {
        size_t with_salt = 0;
        for (size_t i = 0; i < list.count; i++)
            if (list.items[i].has_salt) with_salt++;
        printf("  contacts: %zu (with salt: %zu, invalid entries: %zu)\n",
               list.count, with_salt, list.invalid);
        for (size_t i = 0; i < list.count; i++) {
            printf("    %.16s...%s\n", list.items[i].fp,
                   list.items[i].has_salt ? " salt" : "");
            if (peer_fp && strcmp(list.items[i].fp, peer_fp) == 0) {
                peer_in_list = true;
                if (list.items[i].has_salt) {
                    memcpy(list_salt, list.items[i].salt, NC_SALT_LEN);
                    list_salt_found = true;
                }
            }
        }
    }
    if (list.items)
        qgp_secure_memzero(list.items, list.count * sizeof(*list.items));
    nc_contactlist_clear(&list);

    /* R2 own contact-request inbox */
    nc_requests_t rq;
    int rrc = nc_requests_fetch(&ctx, &rq);
    if (rrc != NC_OK) {
        print_lib_error("contact requests", rrc);
    } else {
        print_read("contact requests", rq.read.outcome, rq.read.why,
                   rq.read.node_rc);
        printf("  requests: %zu (bad: %zu, cancel markers: %zu, "
               "undecodable: %zu, bad_sig: %zu, wrong_key: %zu; "
               "a get_all answer is never complete)\n",
               rq.count, rq.bad_request, rq.cancelled, rq.read.undecodable,
               rq.read.bad_sig, rq.read.wrong_key);
        for (size_t i = 0; i < rq.count; i++)
            printf("    from %.16s...%s%s\n", rq.items[i].sender_fp,
                   rq.items[i].is_acceptance ? " acceptance" : "",
                   rq.items[i].has_salt ? " carries-salt" : "");
    }
    if (rq.items) qgp_secure_memzero(rq.items, rq.count * sizeof(*rq.items));
    nc_requests_clear(&rq);

    if (peer_fp) {
        printf("peer fp: %.16s...  in own contact list: %s\n", peer_fp,
               peer_in_list ? "yes" : "no");

        /* R1 peer profile: the peer's verified keys for R3 / R5 */
        nc_peer_t *peer = calloc(1, sizeof(*peer));
        bool have_peer = peer &&
                         read_profile(&ctx, "peer profile", peer_fp, peer);

        uint8_t agreed_salt[NC_SALT_LEN];
        bool agreed_found = false;
        memset(agreed_salt, 0, sizeof(agreed_salt));
        if (!have_peer) {
            printf("[salt agreement] NOT RUN (no verified peer profile)\n");
        } else {
            /* R3 salt agreement */
            nc_salt_read_t sr;
            int src = nc_salt_read(&ctx, peer, &sr);
            if (src != NC_OK) {
                print_lib_error("salt agreement", src);
            } else {
                print_read("salt agreement", sr.read.outcome, sr.read.why,
                           sr.read.node_rc);
                printf("  salt present: %s (packets authenticated: %zu, "
                       "values accepted: %zu, wrong_owner: %zu)\n",
                       sr.found ? "yes" : "no", sr.authenticated,
                       sr.read.count, sr.read.wrong_owner);
                if (sr.found) {
                    memcpy(agreed_salt, sr.salt, NC_SALT_LEN);
                    agreed_found = true;
                }
            }
            nc_salt_read_clear(&sr);
            if (agreed_found && list_salt_found)
                printf("  agreement salt == contact-list salt: %s\n",
                       memcmp(agreed_salt, list_salt, NC_SALT_LEN) == 0
                           ? "yes" : "no");
        }

        const uint8_t *salt = agreed_found ? agreed_salt
                            : list_salt_found ? list_salt : NULL;
        if (!have_peer) {
            printf("[outbox today] NOT RUN (no verified peer profile)\n");
        } else if (!salt) {
            printf("[outbox today] NOT RUN (no salt from agreement or "
                   "contact list)\n");
        } else {
            /* R5 today's bucket of the peer's outbox to this identity */
            uint64_t day = dht_dm_outbox_get_day_bucket();
            nc_inbox_t in;
            int orc = nc_outbox_fetch_day(&ctx, peer, salt, day, &in);
            if (orc != NC_OK) {
                print_lib_error("outbox today", orc);
            } else {
                print_read("outbox today", in.read.outcome, in.read.why,
                           in.read.node_rc);
                printf("  day %llu, salt source: %s, messages: %zu "
                       "(dropped: %zu)\n", (unsigned long long)day,
                       agreed_found ? "agreement" : "contact list",
                       in.count, in.dropped);
            }
            for (size_t i = 0; i < in.count; i++)
                qgp_secure_memzero(in.items[i].plaintext,
                                   in.items[i].plaintext_len);
            nc_inbox_clear(&in);
        }
        qgp_secure_memzero(agreed_salt, sizeof(agreed_salt));
        if (peer) qgp_secure_memzero(peer, sizeof(*peer));
        free(peer);
    }
    qgp_secure_memzero(list_salt, sizeof(list_salt));

    nodus_client_close(c);
    free(c);
    nc_keys_wipe(keys);
    free(keys);
    return 0;
}
