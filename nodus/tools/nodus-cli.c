/**
 * Nodus — CLI Tool
 *
 * Connect to a Nodus server, authenticate, perform DHT operations.
 *
 * Usage:
 *   nodus-cli -s <server_ip> [-p <port>] [-i <identity_dir>] <command> [args...]
 *
 * Commands:
 *   ping                       Ping the server
 *   put <key> <value>          Store a DHT value
 *   get <key>                  Retrieve a DHT value
 *   listen <key>               Subscribe to key changes
 *   whoami                     Show identity info
 */

#include "transport/nodus_tcp.h"
#include "protocol/nodus_tier2.h"
#include "protocol/nodus_wire.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"   /* S3: stake verb unstake-dest fp */
#include "crypto/nodus_identity.h"
#include "nodus/nodus.h"                    /* dnac_cc_collect + dnac_committee */
#include "nodus/nodus_types.h"
#include "nodus/nodus_chain_config.h"       /* Stage C vote primitives */
#include "protocol/nodus_cbor.h"
#include "dnac/cmt_p2p_netaddr.h"           /* P2P-PORT F6: whoami's P2P ID */
#include "dnac/ledger_ids.h"                /* dna_bft_quorum (witness)    */
#include "witness/nodus_witness_emission.h" /* HF-2: DNAC_DECIMAL_UNIT, the
                                             * voting-power unit          */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#ifdef NODUS_CLI_HAS_DNAC
/* Hard-Fork v1 Stage E.3 — chain-config propose verb.
 *
 * Depends on libdna for pure TX wire functions (dnac_tx_create / add_input /
 * add_output / compute_hash / serialize). No dna_engine / dnac_context
 * is initialized — nodus-cli uses tier-2 RPCs for UTXO query + dnac_spend
 * submit, and signs with the operator's nodus Dilithium5 sk directly.
 *
 * Tech debt (logged in memory): the libdna dependency is load-bearing only
 * for serialize + compute_hash. Moving those to shared/dnac/ retires the
 * dependency. See project_nodus_cli_libdna_decouple.md. */
#include "dnac/dnac.h"
#include "dnac/transaction.h"
#include "dnac/validator.h"   /* DNAC_VALIDATOR_* (v2-envelope unstake) */
#include "dnac/nodus.h"   /* DNAC_MAX_UTXO_QUERY_RESULTS, DNAC_MAX_TX_SIZE */
#include "crypto/sign/qgp_dilithium.h"      /* qgp_dsa87_sign (offline votes) */
/* O15D — `v2-envelope chain-config`: successor-chain envelope builder.
 * Everything is derived from the COMMITTED successor database (read-only
 * sqlite open) through the same production authorities the engine uses:
 * chain id, registry ruleset, committee snapshot, set hash, approval
 * digests. Offline-signed with operator key dirs (the O15C --keys
 * pattern); submitted through the ordinary tier-2 dnac_spend lane. */
#include <sqlite3.h>
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "dnac/msig_wire.h"                 /* general multisig (msig)   */
#include "dnac/ledger_ids.h"                /* DNA_DOMAIN_SYSTEM          */
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_v2_claims.h"   /* nodus_witness_v2_chain_id */
#include "witness/nodus_witness_v2_produce.h"  /* tip height                */
#include "witness/nodus_witness_v2_apply.h"    /* nodus_v2_epoch_for_height */
#include "witness/nodus_witness_runtime.h"     /* set-hash / approval digest */
#include "witness/nodus_witness_v2_gen.h"      /* NODUS_V2_GEN_SRCID_LEN     */
#include "nodus_v2_gen_config.h"               /* O16A: v2-claim --config    */
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_fingerprint.h"      /* O15F T6: fp raw<->hex      */
#include "nodus/nodus_v2_spend.h"              /* the shared SPEND builder   */
#include "client/nodus_v2_stake.h"             /* the shared stake builder   */
#include "client/nodus_v2_name.h"              /* the shared name builder    */
#include "client/nodus_v2_msig.h"              /* the shared msig library    */
#ifdef NODUS_EVM_ENABLED
#include "client/nodus_v2_evm.h"               /* Nodus EVM: the shared EVM
                                                 * envelope builder         */
#include "crypto/hash/keccak256.h"             /* Nodus EVM: ABI selectors  */
#include <sys/wait.h>                          /* Nodus EVM: --solc         */
#endif
#include "dnac/ledger_roots_v2.h"              /* storage status / segment   */
#endif

/* CHECKTX-P1 round 3 — the expiry every envelope this CLI builds carries:
 * tip + (NODUS_CMT_APP_MAX_EXPIRY_AHEAD − 10). CheckTx refuses an expiry
 * past ITS node's tip + 100 (nodus_types.h; decision
 * docs/plans/decisions/2026-09-25-mempool-policy.md 1), and the envelope
 * is judged by more than one node: the mempool reactor gossips a tx to
 * peers up to one block BEHIND its height (shared/dnac/cmt_memr.c:526-531
 * — a peer at height h−1 still receives it), and each of them applies
 * the rule against its own, lower, tip. A tip + 100 envelope would be
 * refused by every such peer. The 10-block margin covers that lag plus
 * the time between reading `tip` and the node receiving the submission.
 * A `tip` of 0 is never used: the node-reported sources answer 0 on a
 * read fault (nodus_witness_db.c nodus_witness_block_height, FAIL-OPEN),
 * and an expiry built on it would be dead on arrival — each builder
 * refuses a 0 tip before encoding. */
#define CLI_ENV_EXPIRY_AHEAD \
    ((uint64_t)NODUS_CMT_APP_MAX_EXPIRY_AHEAD - 10u)
/* HF-4: the expiry every builder uses — the margin above, capped at H-1
 * for an envelope built for rule-set generation 1 while a RULESET_GEN2
 * height H is committed; -1 (reason printed) when no valid expiry
 * remains (defined with cli_select_runtimes). */
static int cli_env_expiry(uint64_t tip, uint64_t *expiry_out);

/* ── Globals ─────────────────────────────────────────────────────── */

static nodus_identity_t identity;
static nodus_tcp_t transport;
static nodus_tcp_conn_t *server_conn = NULL;
static uint8_t session_token[NODUS_SESSION_TOKEN_LEN];
static bool authenticated = false;
static uint32_t next_txn = 1;
static volatile bool running = true;

/* Response state */
static nodus_tier2_msg_t last_response;
static bool response_ready = false;

/* Protocol message buffer */
static uint8_t proto_buf[32768];

/* ── Callbacks ───────────────────────────────────────────────────── */

static void on_frame(nodus_tcp_conn_t *conn, const uint8_t *payload,
                      size_t len, void *ctx) {
    (void)conn; (void)ctx;
    nodus_t2_msg_free(&last_response);
    memset(&last_response, 0, sizeof(last_response));
    if (nodus_t2_decode(payload, len, &last_response) == 0)
        response_ready = true;
}

static void on_disconnect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
    fprintf(stderr, "Disconnected from server\n");
    server_conn = NULL;
    running = false;
}

static void on_connect(nodus_tcp_conn_t *conn, void *ctx) {
    (void)conn; (void)ctx;
}

/* ── Helpers ─────────────────────────────────────────────────────── */

static void sighandler(int sig) {
    (void)sig;
    running = false;
}

static bool wait_response(int timeout_ms) {
    response_ready = false;
    int elapsed = 0;
    while (!response_ready && elapsed < timeout_ms && running) {
        nodus_tcp_poll(&transport, 50);
        elapsed += 50;
    }
    return response_ready;
}

static int do_auth(void) {
    /* Step 1: HELLO */
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_hello(txn, &identity.pk, &identity.node_id,
                    proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to HELLO\n");
        return -1;
    }

    if (strcmp(last_response.method, "challenge") != 0) {
        fprintf(stderr, "Expected challenge, got: %s\n", last_response.method);
        return -1;
    }

    /* Step 2: Sign nonce and send AUTH (C2: domain-tagged AUTH_CHALLENGE) */
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, last_response.nonce, &identity.sk);

    txn = next_txn++;
    nodus_t2_auth(txn, &sig, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to AUTH\n");
        return -1;
    }

    if (strcmp(last_response.method, "auth_ok") != 0) {
        if (last_response.type == 'e')
            fprintf(stderr, "Auth failed: %s\n", last_response.error_msg);
        else
            fprintf(stderr, "Expected auth_ok, got: %s\n", last_response.method);
        return -1;
    }

    memcpy(session_token, last_response.token, NODUS_SESSION_TOKEN_LEN);
    authenticated = true;
    return 0;
}

/* ── Commands ────────────────────────────────────────────────────── */

static int cmd_ping(void) {
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_ping(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No pong\n");
        return 1;
    }
    printf("pong (txn=%u)\n", last_response.txn_id);
    return 0;
}

static int cmd_put(const char *key_str, const char *value_str) {
    /* Hash the key */
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    /* Build sign payload: key + data + type + ttl + vid + seq */
    const uint8_t *data = (const uint8_t *)value_str;
    size_t data_len = strlen(value_str);

    /* Sign the value */
    nodus_value_t *val = NULL;
    nodus_value_create(&key, data, data_len,
                        NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                        1, 0, &identity.pk, &val);
    nodus_value_sign(val, &identity.sk);

    /* Send PUT */
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_put(txn, session_token, &key, data, data_len,
                  NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL,
                  1, 0, &val->signature,
                  proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);
    nodus_value_free(val);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to PUT\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "PUT error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("PUT ok (key=%s)\n", key_str);
    return 0;
}

static int cmd_get(const char *key_str) {
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_get(txn, session_token, &key, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to GET\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "GET error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    if (last_response.value) {
        printf("Value: %.*s\n", (int)last_response.value->data_len,
               (char *)last_response.value->data);
        printf("  seq=%lu vid=%lu type=%d\n",
               (unsigned long)last_response.value->seq,
               (unsigned long)last_response.value->value_id,
               last_response.value->type);
    } else {
        printf("(empty result)\n");
    }
    return 0;
}

/* P2P-PORT F6 — `witness`: the committee as THIS node's chain states it.
 *
 * It used to read the DHT key "nodus:pk", which nothing publishes any
 * more (the publisher and both readers were deleted with the 4004 T3
 * roster, p2p-port design §3 "Deleted"), so it could only ever print
 * "No witnesses registered". Rewritten on the dnac_committee RPC — the
 * committee that governs the NEXT block (tip + 1), in resolution order,
 * answered from the chain's own signed records (handle_dnac_committee_
 * query, nodus_witness_handlers.c). One nodus_client_t session, like
 * `chain-config propose`. Read-only: nothing is signed or submitted. */
static int cmd_witness(const char *server_ip, uint16_t server_port) {
    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", server_ip,
                (unsigned)server_port);
        nodus_client_close(&client);
        return 1;
    }

    int rc = 1;
    /* ~370 KB — heap, never stack (nodus_types.h) */
    nodus_dnac_committee_result_t *c = calloc(1, sizeof(*c));
    if (!c) { fprintf(stderr, "out of memory\n"); goto done; }
    if (nodus_client_dnac_committee(&client, c) != 0) {
        fprintf(stderr, "dnac_committee query failed\n");
        goto done;
    }

    printf("Committee for block %llu (epoch start %llu), from %s:%u\n",
           (unsigned long long)c->block_height,
           (unsigned long long)c->epoch_start, server_ip,
           (unsigned)server_port);
    printf("=====================================\n");
    for (int i = 0; i < c->count; i++) {
        const nodus_dnac_committee_entry_t *e = &c->entries[i];
        uint8_t fp[64];
        char p2p_id[CMT_P2P_ID_CAP];
        if (qgp_sha3_512(e->pubkey, sizeof(e->pubkey), fp) != 0 ||
            cmt_p2p_pubkey_to_id(e->pubkey, p2p_id) != CMT_OK) {
            fprintf(stderr, "seat %d: key hash failed\n", i);
            goto done;
        }
        printf("[%d]\n", i);
        printf("    fingerprint: ");
        for (int b = 0; b < 16; b++) printf("%02x", fp[b]);
        printf("...\n");
        printf("    p2p id:      %s\n", p2p_id);
        printf("    address:     %s\n", e->address[0] ? e->address
                                                     : "(unknown)");
        printf("    status:      %u\n", (unsigned)e->status);
        printf("    stake:       %llu\n", (unsigned long long)e->total_stake);
        printf("    commission:  %u bps\n", (unsigned)e->commission_bps);
    }
    printf("─────────────────────────────────\n");
    printf("Committee size:  %d\n", c->count);
    if (c->count > 0) {
        /* Two rules, stated as what they decide (HF-2, design docs/plans/
         * 2026-09-30-gov-weight-netzero-design.md rev 2):
         *   - block commit: more than 2/3 of VOTING POWER, always
         *     (shared/dnac/cmt_vote_set.c);
         *   - governance (chain-config) approval: SEATS,
         *     dna_bft_quorum(n), below the HF-2 height, and the same power
         *     rule as block commit from it (nodus_rt_system_exec).
         * Power = floor(stake / 10^8), the engine's derivation. This RPC
         * does not say whether HF-2 is active, so both are printed. */
        uint64_t total_power = 0;
        int      power_ok = 1;
        for (int i = 0; i < c->count; i++) {
            uint64_t p = c->entries[i].total_stake / DNAC_DECIMAL_UNIT;
            if (p > UINT64_MAX - total_power) { power_ok = 0; break; }
            total_power += p;
        }
        printf("Quorum (seats):  %u  (dna_bft_quorum — governance approval "
               "below the HF-2 height)\n",
               (unsigned)dna_bft_quorum((uint32_t)c->count));
        if (power_ok && total_power <= UINT64_MAX / 2)
            printf("Voting power:    %llu  (block commit, and governance "
                   "approval from the HF-2 height, need > %llu)\n",
                   (unsigned long long)total_power,
                   (unsigned long long)(total_power * 2 / 3));
        else
            printf("Voting power:    overflows u64 (the chain refuses "
                   "every power-weighted approval)\n");
    }
    rc = 0;

done:
    free(c);
    nodus_client_close(&client);
    return rc;
}

/* `addr-history [--before H] [--limit N]` — THIS identity's history from
 * the node's local address index (dnac_addr_history, nodus.h; decision
 * docs/plans/decisions/2026-10-01-node-address-history-index.md). The
 * owner is the CLI's own fingerprint: the node answers only the
 * authenticated session's own history (C11). Read-only. One page; the
 * next page is `--before H:I:Q` with the printed cursor (`--before H`
 * alone = every row below height H — it would skip the rest of a height
 * a page was cut inside). */
static int cmd_addr_history(const char *server_ip, uint16_t server_port,
                            int argc, char **argv, int optind_cmd) {
    nodus_dnac_addr_history_cursor_t cur;
    bool     have_before = false;
    unsigned long limit = 20;

    memset(&cur, 0, sizeof(cur));
    for (int a = optind_cmd + 1; a < argc; a++) {
        char *end = NULL;
        if (strcmp(argv[a], "--before") == 0 && a + 1 < argc) {
            const char *s = argv[++a];
            errno = 0;
            unsigned long long v = strtoull(s, &end, 10);
            if (errno || !end || end == s || v == 0) goto bad_before;
            cur.h = (uint64_t)v;
            if (*end == ':') {
                unsigned long iv, qv;
                s = end + 1;
                iv = strtoul(s, &end, 10);
                if (errno || end == s || *end != ':' || iv > UINT32_MAX)
                    goto bad_before;
                s = end + 1;
                qv = strtoul(s, &end, 10);
                if (errno || end == s || *end || qv > UINT32_MAX)
                    goto bad_before;
                cur.i = (uint32_t)iv;
                cur.q = (uint32_t)qv;
            } else if (*end) {
                goto bad_before;
            }
            have_before = true;
            continue;
bad_before:
            fprintf(stderr, "--before must be H or H:I:Q (H >= 1)\n");
            return 1;
        } else if (strcmp(argv[a], "--limit") == 0 && a + 1 < argc) {
            errno = 0;
            limit = strtoul(argv[++a], &end, 10);
            if (errno || !end || *end || limit < 1 ||
                limit > NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT) {
                fprintf(stderr, "--limit must be 1..%u\n",
                        (unsigned)NODUS_DNAC_ADDR_HISTORY_MAX_LIMIT);
                return 1;
            }
        } else {
            fprintf(stderr, "Usage: addr-history [--before H] [--limit N]\n");
            return 1;
        }
    }

    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", server_ip,
                (unsigned)server_port);
        nodus_client_close(&client);
        return 1;
    }

    nodus_dnac_addr_history_result_t r;
    int qrc = nodus_client_dnac_addr_history(&client, identity.fingerprint,
                                             have_before ? &cur : NULL,
                                             (uint32_t)limit, &r);
    if (qrc != 0) {
        fprintf(stderr, "dnac_addr_history failed (%d)\n", qrc);
        nodus_client_close(&client);
        return 1;
    }

    printf("Address history of %.16s... from %s:%u\n", identity.fingerprint,
           server_ip, (unsigned)server_port);
    printf("index %s, complete from height %llu\n",
           r.enabled ? "ON" : "OFF", (unsigned long long)r.from_height);
    for (size_t k = 0; k < r.count; k++) {
        const nodus_dnac_addr_history_entry_t *e = &r.entries[k];
        bool native = true;
        for (int b = 0; b < 64; b++)
            if (e->token_id[b]) { native = false; break; }
        printf("h=%llu i=%u q=%u ts=%llu %-16s amount=%llu%s fee=%llu",
               (unsigned long long)e->h, (unsigned)e->i, (unsigned)e->q,
               (unsigned long long)e->ts, e->kind,
               (unsigned long long)e->amount, native ? "" : " (token)",
               (unsigned long long)e->fee);
        if (e->peer[0]) printf(" peer=%.16s...", e->peer);
        printf("\n");
    }
    if (r.count == limit && r.count > 0) {
        const nodus_dnac_addr_history_entry_t *last = &r.entries[r.count - 1];
        printf("more may follow: --before %llu:%u:%u\n",
               (unsigned long long)last->h, (unsigned)last->i,
               (unsigned)last->q);
    }
    nodus_client_free_addr_history_result(&r);
    nodus_client_close(&client);
    return 0;
}

/* `coins` — THIS identity's unspent coins as the node lists them
 * (dnac_utxo, the same query `v2-envelope spend` selects from), plus the
 * node's committed tip. Read-only. The node answers only the
 * authenticated session's own owner (C11, handle_dnac_utxo). `id` is the
 * coin's utxo_set key: the output id SHA3-512(owner_hex ‖ seed)
 * (rtn_out_ids, nodus_witness_rt_native.c) — the value `v2-envelope
 * spend` prints as `out[k] id=` — and `bh` is the height of the block
 * that created it (rtn_utxo_create_eff writes the applying height). One
 * header line, then one line per coin:
 *   coins: owner=<fp16>... tip=<H> count=<n> native_total=<raw>
 *   coin id=<128hex> amount=<raw> bh=<H> ub=<H> token=native|<16hex>... */
static int cmd_coins(const char *server_ip, uint16_t server_port) {
    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", server_ip,
                (unsigned)server_port);
        nodus_client_close(&client);
        return 1;
    }

    nodus_dnac_utxo_result_t r;
    memset(&r, 0, sizeof(r));
    int qrc = nodus_client_dnac_utxo(&client, identity.fingerprint,
                                     NODUS_DNAC_MAX_UTXO_RESULTS, &r);
    if (qrc != 0) {
        fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", qrc);
        nodus_client_close(&client);
        return 1;
    }

    uint64_t native_total = 0;
    bool     total_ok = true;
    for (int i = 0; i < r.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &r.entries[i];
        bool native = true;
        for (int b = 0; b < 64; b++)
            if (e->token_id[b]) { native = false; break; }
        if (!native) continue;
        if (e->amount > UINT64_MAX - native_total) { total_ok = false; break; }
        native_total += e->amount;
    }
    printf("coins: owner=%.16s... tip=%llu count=%d native_total=",
           identity.fingerprint, (unsigned long long)r.block_height, r.count);
    if (total_ok) printf("%llu\n", (unsigned long long)native_total);
    else          printf("overflow\n");
    for (int i = 0; i < r.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &r.entries[i];
        bool native = true;
        for (int b = 0; b < 64; b++)
            if (e->token_id[b]) { native = false; break; }
        printf("coin id=");
        for (int b = 0; b < 64; b++) printf("%02x", e->nullifier[b]);
        printf(" amount=%llu bh=%llu ub=%llu token=",
               (unsigned long long)e->amount,
               (unsigned long long)e->block_height,
               (unsigned long long)e->unlock_block);
        if (native) {
            printf("native\n");
        } else {
            for (int b = 0; b < 8; b++) printf("%02x", e->token_id[b]);
            printf("...\n");
        }
    }
    if (r.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS)
        fprintf(stderr, "warning: the coin listing is capped at %d rows and "
                "came back full — coins beyond it are not shown\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);
    nodus_client_free_utxo_result(&r);
    nodus_client_close(&client);
    return 0;
}

static int cmd_listen(const char *key_str) {
    nodus_key_t key;
    nodus_hash((const uint8_t *)key_str, strlen(key_str), &key);

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_listen(txn, session_token, &key,
                     proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to LISTEN\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "LISTEN error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Listening on key '%s'. Press Ctrl+C to stop.\n", key_str);

    /* Wait for notifications */
    while (running) {
        response_ready = false;
        nodus_tcp_poll(&transport, 1000);

        if (response_ready) {
            if (strcmp(last_response.method, "value_changed") == 0 &&
                last_response.value) {
                printf("[notify] %.*s\n",
                       (int)last_response.value->data_len,
                       (char *)last_response.value->data);
            }
        }
    }

    return 0;
}

/* ── cluster-status (Phase 0 / Task 0.2) ─────────────────────────────
 *
 * Queries one or more nodes for their block_height, state_root,
 * chain_id, peer count, uptime and wall clock, then prints a side-by-
 * side table. Each target gets its own connect+auth+query+disconnect
 * cycle — there is no batch query because operators want explicit
 * per-node visibility (and we want one node failing to be a single row
 * rather than the entire query collapsing).
 */
typedef struct {
    char     target[280];   /* "host:port" — host up to 256, ":port" up to 6 */
    bool     reachable;
    uint64_t block_height;
    uint8_t  state_root[64];
    uint8_t  chain_id[32];
    uint32_t peer_count;
    uint64_t uptime_sec;
    uint64_t wall_clock;
    uint8_t  disk_free_pct;
} cluster_node_status_t;

static int cluster_status_query_one(const char *host, uint16_t port,
                                     cluster_node_status_t *out) {
    snprintf(out->target, sizeof(out->target), "%s:%u", host, port);
    out->reachable = false;

    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    server_conn = nodus_tcp_connect(&transport, host, port);
    if (!server_conn) goto done;

    for (int i = 0; i < 60 && server_conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);
    if (!server_conn || server_conn->state != NODUS_CONN_CONNECTED) goto done;

    if (do_auth() != 0) goto done;

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_status(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);
    if (!wait_response(5000)) goto done;
    if (last_response.type == 'e' || !last_response.has_status_info) goto done;

    out->reachable = true;
    out->block_height  = last_response.status_info.block_height;
    memcpy(out->state_root, last_response.status_info.state_root, 64);
    memcpy(out->chain_id,   last_response.status_info.chain_id,   32);
    out->peer_count    = last_response.status_info.peer_count;
    out->uptime_sec    = last_response.status_info.uptime_sec;
    out->wall_clock    = last_response.status_info.wall_clock;
    out->disk_free_pct = last_response.status_info.disk_free_pct;

done:
    nodus_t2_msg_free(&last_response);
    nodus_tcp_close(&transport);
    server_conn = NULL;
    authenticated = false;
    return out->reachable ? 0 : -1;
}

static void format_uptime(uint64_t sec, char *buf, size_t buf_len) {
    if (sec == 0)              { snprintf(buf, buf_len, "  -"); return; }
    if (sec < 60)              { snprintf(buf, buf_len, "%2us", (unsigned)sec); return; }
    if (sec < 3600)            { snprintf(buf, buf_len, "%2um", (unsigned)(sec/60)); return; }
    if (sec < 86400)           { snprintf(buf, buf_len, "%2uh", (unsigned)(sec/3600)); return; }
    snprintf(buf, buf_len, "%2ud", (unsigned)(sec/86400));
}

static int cmd_cluster_status(int argc, char **argv, int optind_cmd) {
    if (optind_cmd + 1 >= argc) {
        fprintf(stderr, "Usage: nodus-cli cluster-status <host[:port]> [host[:port] ...]\n");
        return 1;
    }

    int targets = argc - (optind_cmd + 1);
    cluster_node_status_t *rows = calloc((size_t)targets, sizeof(*rows));
    if (!rows) return 1;

    for (int i = 0; i < targets; i++) {
        const char *spec = argv[optind_cmd + 1 + i];
        char host[256];
        uint16_t port = NODUS_DEFAULT_TCP_PORT;
        const char *colon = strchr(spec, ':');
        if (colon) {
            size_t hl = (size_t)(colon - spec);
            if (hl >= sizeof(host)) hl = sizeof(host) - 1;
            memcpy(host, spec, hl);
            host[hl] = '\0';
            port = (uint16_t)atoi(colon + 1);
        } else {
            snprintf(host, sizeof(host), "%s", spec);
        }
        cluster_status_query_one(host, port, &rows[i]);
    }

    /* Print table */
    printf("%-24s  %-6s  %-12s  %-6s  %-8s  %-5s  %-12s  %s\n",
           "ADDR", "STATUS", "HEIGHT", "PEERS", "UPTIME", "DF%",
           "WALL_CLOCK", "STATE_ROOT");
    printf("%-24s  %-6s  %-12s  %-6s  %-8s  %-5s  %-12s  %s\n",
           "------------------------", "------", "------------",
           "------", "--------", "-----", "------------",
           "----------------");
    for (int i = 0; i < targets; i++) {
        if (!rows[i].reachable) {
            printf("%-24s  %-6s\n", rows[i].target, "DOWN");
            continue;
        }
        char up[16];
        format_uptime(rows[i].uptime_sec, up, sizeof(up));
        char df[8];
        if (rows[i].disk_free_pct == 255) snprintf(df, sizeof(df), " -");
        else                              snprintf(df, sizeof(df), "%3u%%", rows[i].disk_free_pct);
        char sr_short[17];
        for (int j = 0; j < 8; j++)
            snprintf(sr_short + j * 2, 3, "%02x", rows[i].state_root[j]);
        printf("%-24s  %-6s  %-12llu  %-6u  %-8s  %-5s  %-12llu  %s...\n",
               rows[i].target,
               "UP",
               (unsigned long long)rows[i].block_height,
               rows[i].peer_count,
               up,
               df,
               (unsigned long long)rows[i].wall_clock,
               sr_short);
    }

    int down = 0;
    for (int i = 0; i < targets; i++) if (!rows[i].reachable) down++;
    free(rows);
    return down == 0 ? 0 : 1;
}

static int cmd_servers(void) {
    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_servers(txn, session_token, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to servers request\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "servers error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Cluster servers (%d):\n", last_response.server_count);
    for (int i = 0; i < last_response.server_count; i++) {
        printf("  %s:%u\n",
               last_response.servers[i].ip,
               last_response.servers[i].tcp_port);
    }
    return 0;
}

static int hex_to_key(const char *hex, nodus_key_t *key) {
    if (strlen(hex) != 128) return -1;
    for (int i = 0; i < NODUS_KEY_BYTES; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        key->bytes[i] = (uint8_t)byte;
    }
    return 0;
}

static int cmd_presence(int argc, char **argv, int optind_cmd) {
    /* Build query: always include self, plus any extra fps from args */
    nodus_key_t fps[128];
    int fp_count = 0;

    /* Self */
    memcpy(&fps[fp_count++], &identity.node_id, sizeof(nodus_key_t));

    /* Extra fingerprints from command line */
    for (int i = optind_cmd + 1; i < argc && fp_count < 128; i++) {
        if (hex_to_key(argv[i], &fps[fp_count]) == 0) {
            fp_count++;
        } else {
            fprintf(stderr, "Invalid fingerprint (need 128 hex chars): %s\n", argv[i]);
        }
    }

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_presence_query(txn, session_token, fps, fp_count,
                              proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(server_conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to presence query\n");
        return 1;
    }

    if (last_response.type == 'e') {
        fprintf(stderr, "pq error: [%d] %s\n",
                last_response.error_code, last_response.error_msg);
        return 1;
    }

    printf("Queried %d fingerprints, %d online:\n", fp_count, last_response.pq_count);
    for (int i = 0; i < last_response.pq_count; i++) {
        char hex[NODUS_KEY_HEX_LEN];
        for (int j = 0; j < NODUS_KEY_BYTES; j++)
            snprintf(hex + j * 2, 3, "%02x", last_response.pq_fps[i].bytes[j]);
        printf("  ONLINE: %.32s... (peer=%d)\n", hex, last_response.pq_peers[i]);
    }

    /* Check which queried fps are online/offline */
    for (int q = 0; q < fp_count; q++) {
        char hex[NODUS_KEY_HEX_LEN];
        for (int j = 0; j < NODUS_KEY_BYTES; j++)
            snprintf(hex + j * 2, 3, "%02x", fps[q].bytes[j]);

        bool found = false;
        for (int i = 0; i < last_response.pq_count; i++) {
            if (nodus_key_cmp(&last_response.pq_fps[i], &fps[q]) == 0) {
                found = true;
                break;
            }
        }
        printf("  %s %.32s...\n", found ? "ONLINE " : "OFFLINE", hex);
    }

    return 0;
}

/* ── Channel listen: connect TCP 4003, subscribe, log incoming posts ── */

static int parse_uuid(const char *str, uint8_t out[NODUS_UUID_BYTES]) {
    /* Accept 32 hex chars or hyphenated UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) */
    char clean[33];
    int ci = 0;
    for (int i = 0; str[i] && ci < 32; i++) {
        if (str[i] == '-') continue;
        clean[ci++] = str[i];
    }
    clean[ci] = '\0';
    if (ci != 32) return -1;
    for (int i = 0; i < NODUS_UUID_BYTES; i++) {
        unsigned int byte;
        if (sscanf(clean + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

static void uuid_to_str(const uint8_t uuid[NODUS_UUID_BYTES], char out[37]) {
    snprintf(out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11],
        uuid[12], uuid[13], uuid[14], uuid[15]);
}

static int cmd_ch_listen(const char *server_ip, uint16_t ch_port,
                          const char *uuid_str, const char *log_path) {
    uint8_t ch_uuid[NODUS_UUID_BYTES];
    if (parse_uuid(uuid_str, ch_uuid) != 0) {
        fprintf(stderr, "Invalid UUID: %s\n", uuid_str);
        return 1;
    }

    /* Open log file (append) */
    FILE *logf = NULL;
    if (log_path) {
        logf = fopen(log_path, "a");
        if (!logf) {
            fprintf(stderr, "Cannot open log file: %s\n", log_path);
            return 1;
        }
    }

    /* Connect to TCP 4003 using global transport */
    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    printf("Connecting to %s:%u (channel port)...\n", server_ip, ch_port);
    fflush(stdout);

    nodus_tcp_conn_t *conn = nodus_tcp_connect(&transport, server_ip, ch_port);
    if (!conn) {
        fprintf(stderr, "Failed to connect to channel port\n");
        if (logf) fclose(logf);
        return 1;
    }

    /* Wait for connection */
    for (int i = 0; i < 100 && conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);
    if (conn->state != NODUS_CONN_CONNECTED) {
        fprintf(stderr, "Connection failed\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }
    printf("Connected to channel port.\n");

    /* Auth: hello → challenge → auth → auth_ok */
    server_conn = conn;

    size_t len = 0;
    uint32_t txn = next_txn++;
    nodus_t2_hello(txn, &identity.pk, &identity.node_id,
                    proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000) || strcmp(last_response.method, "challenge") != 0) {
        fprintf(stderr, "Auth failed: no challenge\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }

    /* C2: domain-tagged AUTH_CHALLENGE */
    nodus_sig_t sig;
    nodus_sign_auth_challenge(&sig, last_response.nonce, &identity.sk);
    txn = next_txn++;
    nodus_t2_auth(txn, &sig, proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000) || strcmp(last_response.method, "auth_ok") != 0) {
        fprintf(stderr, "Auth failed: %s\n",
                last_response.type == 'e' ? last_response.error_msg : last_response.method);
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }
    uint8_t ch_token[NODUS_SESSION_TOKEN_LEN];
    memcpy(ch_token, last_response.token, NODUS_SESSION_TOKEN_LEN);
    printf("Authenticated on channel port.\n");

    /* Subscribe */
    txn = next_txn++;
    nodus_t2_ch_subscribe(txn, ch_token, ch_uuid,
                            proto_buf, sizeof(proto_buf), &len);
    nodus_tcp_send(conn, proto_buf, len);

    if (!wait_response(5000)) {
        fprintf(stderr, "No response to ch_sub\n");
        nodus_tcp_close(&transport);
        if (logf) fclose(logf);
        return 1;
    }

    char uuid_pretty[37];
    uuid_to_str(ch_uuid, uuid_pretty);
    printf("Subscribed to channel %s\n", uuid_pretty);
    printf("Listening for posts... (Ctrl+C to stop)\n");
    if (logf) {
        fprintf(logf, "--- ch_listen started: %s ---\n", uuid_pretty);
        fflush(logf);
    }
    fflush(stdout);

    /* Main loop: stay connected, print incoming ch_post_notify */
    while (running) {
        response_ready = false;
        nodus_tcp_poll(&transport, 500);

        if (response_ready) {
            if (strcmp(last_response.method, "ch_ntf") == 0) {
                char post_uuid[37], author_hex[NODUS_KEY_HEX_LEN];
                uuid_to_str(last_response.post_uuid_ch, post_uuid);
                for (int i = 0; i < NODUS_KEY_BYTES; i++)
                    snprintf(author_hex + i * 2, 3, "%02x", last_response.fp.bytes[i]);

                /* ch_timestamp is Unix seconds (not ms) */
                time_t ts = (time_t)last_response.ch_timestamp;
                struct tm tm_buf;
                struct tm *tm = localtime_r(&ts, &tm_buf);
                char timebuf[32];
                strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);

                printf("[%s] %.16s...: %.*s\n",
                       timebuf, author_hex,
                       (int)last_response.data_len,
                       last_response.data ? (char *)last_response.data : "");
                fflush(stdout);

                if (logf) {
                    fprintf(logf, "[%s] post=%s author=%.16s... body=%.*s\n",
                            timebuf, post_uuid, author_hex,
                            (int)last_response.data_len,
                            last_response.data ? (char *)last_response.data : "");
                    fflush(logf);
                }
            }
        }
    }

    printf("Disconnected.\n");
    nodus_tcp_close(&transport);
    if (logf) {
        fprintf(logf, "--- ch_listen stopped ---\n");
        fclose(logf);
    }
    return 0;
}

/* Keep connected and print fingerprint, wait for Ctrl+C */
static int cmd_presence_hold(void) {
    printf("Identity online: %s\n", identity.fingerprint);
    printf("Holding connection (Ctrl+C to stop)...\n");
    fflush(stdout);
    while (running && server_conn) {
        /* Send ping every 15s to keep alive */
        size_t len = 0;
        uint32_t txn = next_txn++;
        nodus_t2_ping(txn, session_token, proto_buf, sizeof(proto_buf), &len);
        nodus_tcp_send(server_conn, proto_buf, len);
        for (int i = 0; i < 150 && running; i++)
            nodus_tcp_poll(&transport, 100);
    }
    printf("Disconnected.\n");
    return 0;
}

static void cmd_whoami(void) {
    printf("Fingerprint: %s\n", identity.fingerprint);
    printf("Node ID:     ");
    for (int i = 0; i < 8; i++) printf("%02x", identity.node_id.bytes[i]);
    printf("...\n");
    /* P2P-PORT F6 — the witness-port (4004) p2p ID of this identity:
     * cmt_p2p_pubkey_to_id (the reference's PubKeyToID, key.go:44), the
     * value a network file's "persistent_peers" entry "id@ip:port"
     * names. Printed in full: a harness or an operator writes it into
     * that file. */
    char p2p_id[CMT_P2P_ID_CAP];
    if (cmt_p2p_pubkey_to_id(identity.pk.bytes, p2p_id) == CMT_OK)
        printf("P2P ID:      %s\n", p2p_id);
    else
        fprintf(stderr, "P2P ID: derivation failed\n");
}

#ifdef NODUS_CLI_HAS_DNAC

/* ── D-16 rev 7 (W4-CC) — shared pre-auth SYSTEM-governance envelope
 * builder, extracted from `v2-envelope chain-config`'s two-pass build
 * so it and the networked `chain-config propose` below share ONE
 * encoder rather than two that could drift apart. Both callers build
 * the SAME shape: a single-leg SYSTEM CHAIN_CONFIG envelope (call v2 =
 * 41 bytes) under auth_kind 2, whose auth blob is zero-filled at its
 * FINAL length for pass 1 (deriving the leg auth_digest every signer
 * signs over) and re-encoded with the real bytes for pass 2 (a
 * self-check — same lengths, so the digest is unchanged by
 * construction, env_preflight.h's "auth_len IS committed" rule). */

typedef struct {
    dna_env_leg_in_t   leg;
    dna_env_in_t       env_in;
    dna_env_leg_ctx_t  lctx;
    uint8_t            call[41];
    uint8_t           *auth;      /* heap, caller frees via _free below */
    size_t             auth_len;
    uint8_t           *env_bytes; /* heap, caller frees via _free below */
    size_t             env_len;
} cc_appr_envelope_t;

/* PASS 1: build the call bytes + leg + env_in, allocate the auth blob
 * ZERO-FILLED at its FINAL length (1 submitter slot + n_appr approval
 * slots), encode, and preflight at candidate height tip+1 — deriving
 * pf->auth_digest[0], the value every signer (submitter and every
 * approver) signs over. @return 0 / -1. */
static int cc_appr_build_pass1(cc_appr_envelope_t *b, dna_env_preflight_t *pf,
                               const uint8_t chain32[32], uint64_t tip,
                               uint32_t sys_ruleset_version,
                               const uint8_t sys_ruleset_hash[64],
                               uint8_t param_id, uint64_t new_value,
                               uint64_t effective, uint64_t nonce,
                               uint64_t signed_at, uint64_t valid_before,
                               uint32_t n_appr) {
    memset(b, 0, sizeof(*b));
    b->call[0] = param_id;
    for (int i = 0; i < 8; i++) b->call[1 + i]  = (uint8_t)(new_value    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) b->call[9 + i]  = (uint8_t)(effective    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) b->call[17 + i] = (uint8_t)(nonce        >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) b->call[25 + i] = (uint8_t)(signed_at    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) b->call[33 + i] = (uint8_t)(valid_before >> (56 - 8 * i));

    if (n_appr == 0) return -1;
    b->auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                  (size_t)n_appr * NODUS_RT_AUTH_APPROVAL_LEN;
    b->auth = calloc(1, b->auth_len);
    if (!b->auth) return -1;

    b->leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    b->leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    b->leg.hdr.ruleset_version      = sys_ruleset_version;
    b->leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    b->leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_CC_V1;
    b->leg.hdr.call_len             = sizeof(b->call);
    b->leg.hdr.auth_len             = (uint32_t)b->auth_len;
    b->leg.hdr.res_max_effects      = 4;
    b->leg.hdr.res_max_effect_bytes = 4096;
    b->leg.call_data = b->call;
    b->leg.auth_data = b->auth;   /* pass 1: zero-filled                 */

    /* The mempool lifetime rule (docs/plans/decisions/2026-09-25-mempool-
     * policy.md 1; nodus_types.h NODUS_CMT_APP_MAX_EXPIRY_AHEAD): CheckTx
     * refuses expiry 0 and anything past tip + 100. CLI_ENV_EXPIRY_AHEAD
     * (90) keeps the gossip margin; the rest is the collection window —
     * the envelope is built, then every committee seat is asked over the
     * network (round 1, maybe round 2) before it is submitted, and 90
     * blocks at the 4 s commit timeout is ~6 minutes. The expiry is part
     * of the signed digest, so it is fixed here, before anyone signs. */
    if (tip == 0) return -1;     /* callers refuse a 0 tip first        */
    if (cli_env_expiry(tip, &b->env_in.expiry_height) != 0) return -1;
    b->env_in.fee_amount          = 0;   /* SYSTEM leg rule               */
    b->env_in.res_max_total_units = 200000;
    b->env_in.leg_count           = 1;
    b->env_in.legs                = &b->leg;

    if (dna_env_encoded_size(&b->leg, 1, &b->env_len) != 0) return -1;
    b->env_bytes = malloc(b->env_len);
    if (!b->env_bytes) return -1;

    b->lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    b->lctx.ruleset_version = sys_ruleset_version;
    memcpy(b->lctx.ruleset_hash, sys_ruleset_hash, 64);

    size_t used = 0;
    if (dna_env_encode(&b->env_in, b->env_bytes, b->env_len, &used) != 0 ||
        used != b->env_len)
        return -1;
    if (dna_env_preflight(b->env_bytes, b->env_len, chain32, tip + 1,
                          &b->lctx, 1, pf) != DNA_ENV_PF_OK)
        return -1;
    return 0;
}

/* PASS 2: re-encode with the NOW-SIGNED auth bytes (same lengths, so
 * the digest is unchanged by construction) and re-preflight as a
 * self-check before submission. @return 0 / -1. */
static int cc_appr_build_pass2(cc_appr_envelope_t *b, dna_env_preflight_t *pf,
                               const uint8_t chain32[32], uint64_t tip) {
    size_t used = 0;
    if (dna_env_encode(&b->env_in, b->env_bytes, b->env_len, &used) != 0 ||
        used != b->env_len)
        return -1;
    if (dna_env_preflight(b->env_bytes, b->env_len, chain32, tip + 1,
                          &b->lctx, 1, pf) != DNA_ENV_PF_OK)
        return -1;
    return 0;
}

static void cc_appr_envelope_free(cc_appr_envelope_t *b) {
    if (!b) return;
    free(b->auth);
    free(b->env_bytes);
}

/* One domain's ruleset identity (ruleset_version + ruleset_hash), read
 * from the LOCAL BINARY's compiled production table
 * (nodus_witness_runtime.c table_get, exported as
 * nodus_runtime_builtin_table) — the source every NETWORKED envelope
 * builder uses, because a remote client has no chain database to read
 * the domain registry from. A version-3 chain's registry is seeded from
 * this same compiled table at genesis (nodus_witness_domreg.c:319-380,
 * manifest_from_runtime copies ruleset_version/ruleset_hash at
 * :305-306), and CheckTx builds its contextual ruleset table from that
 * registry (nodus_witness_v2_apply.c block_ctx_from_doms), so the two
 * agree on every chain this binary can execute. A binary built for a
 * different ruleset fails closed at the node's preflight
 * (DNA_ENV_PF_ERR_CTX_VERSION / a call_commit mismatch) rather than
 * being silently accepted. Shared by `chain-config propose` (SYSTEM) and
 * `v2-envelope spend` (CORE).
 *
 * HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.1):
 * the compiled table is a list of rule-set GENERATIONS, so the lookup is
 * (domain, generation) — never "the first entry of this domain". A
 * chain runs generation 1 until its RULESET_GEN2 height; from it a
 * generation-1 envelope fails closed at the node's preflight
 * (ERR_CTX_VERSION — SYSTEM v6 != v7, CORE v4 != v5), never silently.
 * Every builder therefore asks the node, on its own session,
 * which generation it runs (cli_select_runtimes below — dnac_ruleset_info,
 * design §1.6) and builds with THAT generation; the lookups made before
 * the session exists use generation 1 only as a "the table is present"
 * check and are replaced after connect.
 * Storage reward v1: a generation need not carry every domain — GEN_STORAGE
 * has no EVM slot (the EVM domain's v1 entry stays the EVM generation's,
 * its registry record untouched by the switch) — so the answer is the
 * entry of the NEWEST generation <= `generation` that carries the domain;
 * SYSTEM and CORE are in every generation, so their answer is unchanged.
 * @return the runtime, or NULL. */
static const nodus_domain_runtime_t *cli_builtin_runtime(uint32_t domain_id,
                                                         uint32_t generation) {
    for (uint32_t g = generation; g >= NODUS_RT_GEN_1; g--) {
        const nodus_domain_runtime_t *rt =
            nodus_runtime_for_generation(g, domain_id);
        if (rt) return rt;
    }
    return NULL;
}

/* HF-4 — the node's last dnac_ruleset_info answer on this process's
 * session and the generation cli_select_runtimes picked from it (the
 * expiry cap below reads both). */
static nodus_dnac_ruleset_info_t g_cli_ri;
static int g_cli_ri_valid = 0;
static uint32_t g_cli_sel_gen = 0;
/* HF-4 — the same two facts read from a LOCAL committed database
 * (`v2-envelope chain-config --db`, no session): the registry's
 * generation and the earliest committed RULESET_GEN2 effective height. */
static int g_cli_local_valid = 0;
static uint32_t g_cli_local_gen = 0;
static uint64_t g_cli_local_h = 0;

/* HF-4 (design §1.6): ask the node which rule-set generation governs its
 * tip + 1 and pick the compiled generation whose (SYSTEM, CORE) tuple
 * EQUALS the answer — never by height. An older node (unknown method), a
 * failed query or no matching generation FAILS CLOSED: nothing is built.
 * `sys_rt` / `core_rt` (either may be NULL) receive that generation's
 * entries. @return 0 / -1 (reason printed). */
static int cli_select_runtimes(nodus_client_t *client,
                               const nodus_domain_runtime_t **sys_rt,
                               const nodus_domain_runtime_t **core_rt) {
    nodus_dnac_ruleset_info_t ri;
    int rc = nodus_client_dnac_ruleset_info(client, &ri);
    if (rc != 0) {
        fprintf(stderr, "dnac_ruleset_info failed (rc=%d) — the node is "
                "older than this CLI or did not answer; refusing to build "
                "an envelope for a rule-set generation it did not name\n",
                rc);
        return -1;
    }
    for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
        const nodus_domain_runtime_t *s =
            cli_builtin_runtime(DNA_DOMAIN_SYSTEM, g);
        const nodus_domain_runtime_t *c =
            cli_builtin_runtime(DNA_DOMAIN_CORE, g);
        if (!s || !c) continue;
        if (s->ruleset_version == ri.sys_version &&
            memcmp(s->ruleset_hash, ri.sys_hash, 64) == 0 &&
            c->ruleset_version == ri.core_version &&
            memcmp(c->ruleset_hash, ri.core_hash, 64) == 0) {
            if (sys_rt) *sys_rt = s;
            if (core_rt) *core_rt = c;
            g_cli_ri = ri;
            g_cli_ri_valid = 1;
            g_cli_sel_gen = g;
            return 0;
        }
    }
    fprintf(stderr, "the node runs a rule-set generation this CLI does not "
            "carry (generation %u: SYSTEM v%u, CORE v%u) — this CLI is out "
            "of date; rebuild it\n", (unsigned)ri.generation,
            (unsigned)ri.sys_version, (unsigned)ri.core_version);
    return -1;
}

/* HF-4: the compiled CORE entry an already-built envelope was made for —
 * the generation whose CORE ruleset_version equals the envelope's CORE
 * leg's (versions strictly increase across generations, runtime
 * selfcheck, so at most one matches). Offline paths (msig sign/combine)
 * judge an export with it. @return the entry or NULL. */
static const nodus_domain_runtime_t *
cli_core_runtime_for_env(const uint8_t *env, size_t env_len) {
    dna_env_view_t *v = calloc(1, sizeof(*v));
    const nodus_domain_runtime_t *hit = NULL;
    if (!v) return NULL;
    if (dna_env_decode(env, env_len, v) == 0) {
        for (uint16_t l = 0; l < v->leg_count && !hit; l++) {
            if (v->leg[l].domain_id != DNA_DOMAIN_CORE) continue;
            for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
                const nodus_domain_runtime_t *c =
                    cli_builtin_runtime(DNA_DOMAIN_CORE, g);
                if (c && c->ruleset_version == v->leg[l].ruleset_version) {
                    hit = c;
                    break;
                }
            }
        }
    }
    free(v);
    return hit;
}

/* HF-4 (design §1.6 "Expiry"): tip + CLI_ENV_EXPIRY_AHEAD, and — for an
 * envelope built for rule-set GENERATION 1 while a RULESET_GEN2 height H
 * is committed — never past H-1: a generation-1 envelope must not
 * outlive the last generation-1 block. The facts come from the session
 * (dnac_ruleset_info + the generation cli_select_runtimes picked) or,
 * with no session, from the local database (cli_local_ruleset_facts).
 * Validity is judged against the MOST CONSERVATIVE tip this process has:
 * the larger of `tip` (the builder's own) and the ruleset answer's tip —
 * if H-1 is not above it, no generation-1 expiry is valid and the build
 * is refused ("retry after H"). A generation-2 envelope, or no vote
 * (H = 0), takes the plain margin. @return 0 / -1 (reason printed). */
static int cli_env_expiry(uint64_t tip, uint64_t *expiry_out) {
    uint64_t e = tip + CLI_ENV_EXPIRY_AHEAD, H = 0, hi = tip;
    int gen1 = 0;
    if (g_cli_ri_valid) {
        H = g_cli_ri.gen2_height;
        gen1 = (g_cli_sel_gen == NODUS_RT_GEN_1);
        if (g_cli_ri.tip > hi) hi = g_cli_ri.tip;
    } else if (g_cli_local_valid) {
        H = g_cli_local_h;
        gen1 = (g_cli_local_gen == NODUS_RT_GEN_1);
    }
    if (gen1 && H != 0) {
        if (H - 1u < hi + 1u) {
            fprintf(stderr, "rule-set switch at height %llu: an envelope "
                    "for the current rule-set generation 1 cannot expire "
                    "at or before %llu while the tip is %llu — nothing "
                    "was built; retry after height %llu\n",
                    (unsigned long long)H, (unsigned long long)(H - 1u),
                    (unsigned long long)hi, (unsigned long long)H);
            return -1;
        }
        if (e > H - 1u) e = H - 1u;
    }
    *expiry_out = e;
    return 0;
}

/* HF-4 — the expiry facts of a LOCAL committed database (no session):
 * which compiled generation its SYSTEM registry row is, and the earliest
 * committed RULESET_GEN2 effective height (0 = no vote) — the same query
 * dnac_ruleset_info answers "H" with. @return 0 / -1 (reason printed). */
static int cli_local_ruleset_facts(nodus_witness_t *wr,
                                   const dna_domain_manifest_t *sys_man) {
    uint32_t gen = 0;
    for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
        const nodus_domain_runtime_t *s =
            cli_builtin_runtime(DNA_DOMAIN_SYSTEM, g);
        if (s && s->ruleset_version == sys_man->ruleset_version &&
            memcmp(s->ruleset_hash, sys_man->ruleset_hash, 64) == 0) {
            gen = g;
            break;
        }
    }
    if (gen == 0) {
        fprintf(stderr, "the database's SYSTEM registry is a rule-set "
                "generation this CLI does not carry (v%u) — rebuild it\n",
                (unsigned)sys_man->ruleset_version);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    int ok = 0;
    uint64_t H = 0;
    if (sqlite3_prepare_v2(wr->db,
            "SELECT MIN(effective_block) FROM chain_config_history "
            "WHERE param_id = ?1", -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_int(st, 1, (int)DNAC_CFG_RULESET_GEN2);
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_type(st, 0) == SQLITE_NULL) {
                ok = 1;
            } else {
                sqlite3_int64 v = sqlite3_column_int64(st, 0);
                if (v > 0) { H = (uint64_t)v; ok = 1; }
            }
        }
    }
    sqlite3_finalize(st);
    if (!ok) {
        fprintf(stderr, "RULESET_GEN2 history unreadable in the database\n");
        return -1;
    }
    g_cli_local_gen = gen;
    g_cli_local_h = H;
    g_cli_local_valid = 1;
    return 0;
}

/* ── Stage E.3 — chain-config propose ───────────────────────────── */

static int cc_param_name_to_id(const char *name, uint8_t *out_id) {
    /* R3 W4-C delta 2 (operator "kaldır" 2026-09-18): MAX_TXS_PER_BLOCK
     * (param id 1) is RETIRED from governance — removed from this name
     * table, so this CLI can no longer even NAME the proposal; the
     * witness-side scalar_rules refuses id 1 unconditionally as
     * defense in depth regardless. tokenomics-v3 P2 (P2-4): the same
     * for INFLATION_START_BLOCK (param id 3) — RETIRED with the
     * per-block mint, removed from this table, refused witness-side.
     * 0.20.3: BLOCK_INTERVAL_SEC (param id 2) is NOT READ by the running
     * consensus (dnac.h dnac_cfg_param_read_by_consensus) — removed from
     * this table for the same reason and refused witness-side; unlike ids
     * 1 and 3 it is not retired, and returns here when a consensus reads
     * it. This table names exactly the ids on that list. */
    static const struct { const char *n; uint8_t id; } map[] = {
        { "TARGET_ACTIVE_COUNT",  DNAC_CFG_TARGET_ACTIVE_COUNT },
        { "target_active_count",  DNAC_CFG_TARGET_ACTIVE_COUNT },
        /* HF-1 (decision 2026-09-25-gas-price.md) — param id 5 */
        { "GAS_PRICE_RAW_PER_UNIT", DNAC_CFG_GAS_PRICE_RAW_PER_UNIT },
        { "gas_price_raw_per_unit", DNAC_CFG_GAS_PRICE_RAW_PER_UNIT },
        /* final pre-testnet wipe W-C (decision 2026-09-28-token-create-
         * fee-governance.md) — param id 6 */
        { "TOKEN_CREATE_FEE_RAW", DNAC_CFG_TOKEN_CREATE_FEE_RAW },
        { "token_create_fee_raw", DNAC_CFG_TOKEN_CREATE_FEE_RAW },
        /* HF-2 (design docs/plans/2026-09-30-gov-weight-netzero-design.md
         * rev 2) — param id 7, value exactly 1 */
        { "HF2_ACTIVE",           DNAC_CFG_HF2_ACTIVE },
        { "hf2_active",           DNAC_CFG_HF2_ACTIVE },
        /* HF-3 (design docs/plans/2026-10-01-hf3-comet-block-bounds-
         * design.md rev 3) — param id 8, value exactly 1 */
        { "HF3_ACTIVE",           DNAC_CFG_HF3_ACTIVE },
        { "hf3_active",           DNAC_CFG_HF3_ACTIVE },
        /* HF-4 (design docs/plans/2026-10-02-onchain-names-design.md rev
         * 4 §1.2, §2) — param id 9, value exactly D2; ids 10-13, votable
         * once generation 2 judges the vote */
        { "RULESET_GEN2",         DNAC_CFG_RULESET_GEN2 },
        { "ruleset_gen2",         DNAC_CFG_RULESET_GEN2 },
        { "NAME_PRICE_3P",        DNAC_CFG_NAME_PRICE_3P },
        { "name_price_3p",        DNAC_CFG_NAME_PRICE_3P },
        { "NAME_PRICE_4P",        DNAC_CFG_NAME_PRICE_4P },
        { "name_price_4p",        DNAC_CFG_NAME_PRICE_4P },
        { "NAME_PRICE_5P",        DNAC_CFG_NAME_PRICE_5P },
        { "name_price_5p",        DNAC_CFG_NAME_PRICE_5P },
        { "NAME_PRICE_6P",        DNAC_CFG_NAME_PRICE_6P },
        { "name_price_6p",        DNAC_CFG_NAME_PRICE_6P },
        /* Nodus EVM (design docs/plans/2026-10-04-nodus-evm-chain-integration-
         * design.md rev 3 §8, §9) — param id 14, value exactly
         * DNAC_CFG_EVM_ACTIVE_D; id 15, the EVM block gas limit. Their
         * value / state rules are the witness's
         * (nodus_witness_chain_config.c), run here by the step-9
         * pre-check through the same nodus_chain_config_scalar_rules. */
        { "EVM_ACTIVE",           DNAC_CFG_EVM_ACTIVE },
        { "evm_active",           DNAC_CFG_EVM_ACTIVE },
        { "EVM_BLOCK_GAS_LIMIT",  DNAC_CFG_EVM_BLOCK_GAS_LIMIT },
        { "evm_block_gas_limit",  DNAC_CFG_EVM_BLOCK_GAS_LIMIT },
        /* storage reward v1 (design docs/plans/2026-10-04-storage-reward-
         * v1-design.md rev 2.2 §6, "voted like RULESET_GEN2") — param id
         * 16, value exactly DNAC_CFG_RULESET_GEN_STORAGE_D; votable only
         * while the EVM generation judges the vote */
        { "RULESET_GEN_STORAGE",  DNAC_CFG_RULESET_GEN_STORAGE },
        { "ruleset_gen_storage",  DNAC_CFG_RULESET_GEN_STORAGE },
        /* HF-8 (design docs/plans/2026-10-07-delegate-name-required-
         * design.md rev 2 §1) — param id 17, value exactly 1; votable
         * only while generation 2 or later judges the vote */
        { "DELEGATE_NAME_REQUIRED", DNAC_CFG_DELEGATE_NAME_REQUIRED },
        { "delegate_name_required", DNAC_CFG_DELEGATE_NAME_REQUIRED },
    };
    for (size_t i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        if (strcmp(name, map[i].n) == 0) { *out_id = map[i].id; return 0; }
    }
    return -1;
}

/* R3 W4-CC (ORCHESTRATOR, ORC-3): `cc_print_hex16` — the legacy
 * proposer's "your witness_id:" printer — lost its last caller when
 * cmd_chain_config_propose was rewritten; deleted (no dead code). */

static int cc_hex_to_bytes32(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        out[i] = (uint8_t)byte;
    }
    return 0;
}

/* Judge ONE seat's CCAPPR approval over the envelope whose leg
 * auth_digest is `auth_digest0`. This proposer's OWN seat is signed here,
 * locally, with no round trip (this CLI holds the node's key — the node
 * serves dnac_cc_collect to that key only — so the node skips its own
 * seat). Every other seat's answer comes from `res`, the node's
 * dnac_cc_collect reply (decision 2026-09-26-cc-approval-via-own-node.md
 * (4)), and is checked exactly as a direct reply was: the replied seat,
 * set_hash and epoch must equal this proposer's own locally computed
 * values (D-16 rev 7 (5): "every reply must be ok, sh==local,
 * ep==local") — a mismatch is a refusal, never silently accepted.
 *
 * ADDED with the relay: the signature itself is verified against the
 * seat's committee key and the locally computed approval digest. Since
 * P2P-FIX-2 a 0x71 reply carries its request id (`rq`, SHA3-512 of the
 * envelope — decision 2026-09-27-p2p-fix-2.md (2)) and the node takes
 * only answers naming the envelope it asked about, so a late answer to a
 * PREVIOUS collection no longer reaches this CLI. The check stays: the
 * id is a correlation value, not an authority — a signature that does
 * not bind THIS envelope's approval digest (a faulty or hostile seat) is
 * refused here instead of being carried into an envelope CheckTx
 * refuses.
 *
 * @return 0 accepted (sig_out filled), 1 refused (a line was already
 *         printed explaining why), -1 a local fault (sign/digest).
 */
static int cc_propose_judge_seat(int seat, int self_idx,
                                 const nodus_identity_t *identity,
                                 const nodus_dnac_committee_entry_t *ent,
                                 const nodus_dnac_cc_collect_result_t *res,
                                 const uint8_t local_set_hash[64],
                                 uint64_t local_epoch,
                                 const uint8_t auth_digest0[64],
                                 uint8_t sig_out[NODUS_SIG_BYTES]) {
    uint8_t adg[64];
    if (nodus_rt_cc_approval_digest(auth_digest0, local_set_hash,
                                    local_epoch, (uint16_t)seat, adg) != 0)
        return -1;

    if (seat == self_idx) {
        size_t sl = 0;
        if (qgp_dsa87_sign(sig_out, &sl, adg, 64, identity->sk.bytes) != 0)
            return -1;
        printf("Seat %d: self (approved)\n", seat);
        return 0;
    }

    printf("Seat %d", seat);
    if (ent->address[0]) printf(" (%s)", ent->address);
    printf(": ");

    const nodus_dnac_cc_collect_entry_t *r = NULL;
    for (int i = 0; i < res->count; i++) {
        if (res->entries[i].seat == (uint16_t)seat) { r = &res->entries[i]; break; }
    }
    if (!r) {
        printf("MISSING (the node reported no result for this seat)\n");
        return 1;
    }
    switch (r->status) {
    case NODUS_CC_COLLECT_ST_ANSWERED:
        break;
    case NODUS_CC_COLLECT_ST_NOT_CONNECTED:
        printf("SKIP (this node has no connection to the seat)\n");
        return 1;
    case NODUS_CC_COLLECT_ST_NO_ANSWER:
        printf("TIMEOUT\n");
        return 1;
    case NODUS_CC_COLLECT_ST_SEND_FAILED:
        printf("ERROR (the node could not send the request)\n");
        return 1;
    default:
        printf("ERROR (unknown status %u)\n", (unsigned)r->status);
        return 1;
    }
    if (!r->ok) {
        printf("REFUSED: %s\n", r->reason[0] ? r->reason : "(no reason given)");
        return 1;
    }
    if (r->rsp_seat != (uint16_t)seat) {
        printf("MISMATCH (replied seat %u != requested %d — refusing "
               "the signature)\n", (unsigned)r->rsp_seat, seat);
        return 1;
    }
    if (memcmp(r->set_hash, local_set_hash, 64) != 0 ||
        r->epoch != local_epoch) {
        printf("MISMATCH (peer's set_hash/epoch differ from this "
               "proposer's own — peer epoch=%llu, local epoch=%llu; "
               "refusing the signature)\n",
               (unsigned long long)r->epoch,
               (unsigned long long)local_epoch);
        return 1;
    }
    if (nodus_chain_config_verify_vote(ent->pubkey, adg, r->sig) != 0) {
        printf("BAD SIGNATURE (does not verify over this envelope's "
               "approval digest — refusing it)\n");
        return 1;
    }
    memcpy(sig_out, r->sig, NODUS_SIG_BYTES);
    printf("APPROVED\n");
    return 0;
}

/* One collection round over the envelope in `b` (whose leg auth_digest is
 * `pf->auth_digest[0]`): the node collects every other seat's answer in
 * ONE dnac_cc_collect call, then each seat with `want[seat]` (NULL = every
 * seat) is judged (cc_propose_judge_seat). @return the number accepted,
 * or -1 (a line was printed: the call failed or a local fault). */
static int cc_propose_round(nodus_client_t *client, int N, int self_idx,
                            const nodus_dnac_committee_result_t *committee,
                            const bool *want, const cc_appr_envelope_t *b,
                            const dna_env_preflight_t *pf,
                            const uint8_t set_hash[64], uint64_t epoch,
                            nodus_dnac_cc_collect_result_t *res,
                            bool *ok_out, uint8_t (*sigs_out)[NODUS_SIG_BYTES]) {
    printf("Collecting approvals through this node...\n");
    fflush(stdout);
    int crc = nodus_client_dnac_cc_collect(client, b->env_bytes, b->env_len, res);
    if (crc != 0) {
        fprintf(stderr, "dnac_cc_collect failed (rc=%d) — the node refused "
                        "or did not answer (busy, not this node's own "
                        "identity, or a timeout)\n", crc);
        return -1;
    }
    int accepted = 0;
    for (int seat = 0; seat < N; seat++) {
        if (want && !want[seat]) continue;
        int r = cc_propose_judge_seat(seat, self_idx, &identity,
                                      &committee->entries[seat], res,
                                      set_hash, epoch, pf->auth_digest[0],
                                      sigs_out[seat]);
        if (r == 0) { ok_out[seat] = true; accepted++; }
        else if (r < 0) {
            fprintf(stderr, "local fault at seat %d\n", seat);
            return -1;
        }
    }
    return accepted;
}

/* chain-config propose flow (D-16 rev 7, W4-CC — rebuilt on the
 * pre-auth SYSTEM-governance envelope; the legacy type-10
 * DNAC_TX_CHAIN_CONFIG body this command used to build is REJECTED at
 * CheckTx on a version-3 chain, nodus_witness_v2_classify_entry
 * produce.c:75-80, so it could never have committed anyway).
 *
 * Assumes the outer main() has already loaded `identity` from -i and has
 * the base transport/session open on server_ip:server_port (the short-lived
 * nodus_client_t created below is a separate connection scoped just to the
 * DNAC RPC calls this command needs; it stays open through the final
 * submit so the whole flow is one session).
 *
 * The chain id is read from THIS NODE via dnac_supply's additive
 * "chain_id32" key (operator ruling 2026-09-18, "kendisi alsın") — never
 * pasted by the operator. --chain-id, if given, is an EXPLICIT
 * cross-check: a mismatch aborts rather than silently using either
 * value.
 *
 * Round 1 asks EVERY committee seat: self signs locally (no round trip),
 * every other seat is asked by THIS NODE over its existing 4004
 * connections, in one dnac_cc_collect call (decision
 * 2026-09-26-cc-approval-via-own-node.md — this CLI never dials 4004).
 * If k refuse and the accepting set (N-k) still reaches quorum, round 2
 * REBUILDS the envelope with exactly that count (the approval COUNT is
 * bound into the leg auth_digest through auth_len — D-16 rev 7 (3) — so
 * round 1's signatures, including self's, are invalid under the new
 * auth_len and everyone accepting is re-asked) and any refusal there
 * aborts the whole proposal — there is no round 3. Round 2 first waits
 * out the responders' per-proposer cooldown (decision (6)). */
static int cmd_chain_config_propose(const char *server_ip, uint16_t server_port,
                                     int argc, char **argv, int cmd_start) {
    /* 1. Parse sub-flags --param / --value / --effective / [--nonce] /
     * [--chain-id]. */
    const char *param_name = NULL, *chain_id_hex = NULL;
    uint64_t new_value = 0, effective_block = 0, proposal_nonce = 0;
    int has_value = 0, has_effective = 0, has_nonce = 0;

    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--param") == 0 && i + 1 < argc) {
            param_name = argv[++i];
        } else if (strcmp(a, "--value") == 0 && i + 1 < argc) {
            new_value = strtoull(argv[++i], NULL, 10); has_value = 1;
        } else if (strcmp(a, "--effective") == 0 && i + 1 < argc) {
            effective_block = strtoull(argv[++i], NULL, 10); has_effective = 1;
        } else if (strcmp(a, "--nonce") == 0 && i + 1 < argc) {
            proposal_nonce = strtoull(argv[++i], NULL, 10); has_nonce = 1;
        } else if (strcmp(a, "--chain-id") == 0 && i + 1 < argc) {
            chain_id_hex = argv[++i];
        } else {
            fprintf(stderr, "Unknown arg: %s\n", a);
            return 1;
        }
    }
    if (!param_name || !has_value || !has_effective) {
        fprintf(stderr,
            "Usage: chain-config propose --param <NAME> --value <N> "
            "--effective <BLOCK> [--nonce <N>] [--chain-id <64-hex>]\n"
            "Params the running consensus reads (--value range):\n"
            "  TARGET_ACTIVE_COUNT    [%llu, %llu]   "
            "(active validator set; epoch-boundary effective)\n"
            "  GAS_PRICE_RAW_PER_UNIT [0, %llu]   "
            "(raw per declared gas unit; 0 = rule off)\n"
            "  TOKEN_CREATE_FEE_RAW   [%llu, %llu]   "
            "(raw fee of one token creation)\n"
            "  HF2_ACTIVE             exactly %llu   "
            "(HF-2 switch: power-weighted approvals + net-zero blocks "
            "from --effective on; one-way)\n"
            "  HF3_ACTIVE             exactly %llu   "
            "(HF-3 switch: blocks bounded by the consensus params only, "
            "proposal fee check, from --effective on; one-way)\n"
            "  RULESET_GEN2           exactly %llu   "
            "(HF-4 rule-set generation 2 from --effective on; once only; "
            "HF-2 must be active; --effective - 1 not an epoch boundary)\n"
            "  NAME_PRICE_3P..6P      [%llu, %llu]   "
            "(raw price of a 3/4/5/6+ character name; votable once "
            "generation 2 is in force)\n"
            "  EVM_ACTIVE             exactly %llu   "
            "(Nodus EVM: the EVM generation + domain from --effective on; once "
            "only; HF-2, HF-3 and a non-zero gas price active)\n"
            "  EVM_BLOCK_GAS_LIMIT    [%llu, %llu]   "
            "(Nodus EVM: the summed declared EVM gas one block may hold)\n"
            "  RULESET_GEN_STORAGE    exactly %llu   "
            "(storage-reward rule-set generation from --effective on; "
            "once only; the EVM generation must be in force; HF-2 must "
            "be active; --effective - 1 not an epoch boundary)\n"
            "  DELEGATE_NAME_REQUIRED exactly %llu   "
            "(HF-8 switch: from --effective on a delegation needs the "
            "delegator's on-chain name, self-delegation exempt; one-way; "
            "generation 2 must be in force)\n"
            "BLOCK_INTERVAL_SEC is not read by the running consensus "
            "and is refused.\n",
            (unsigned long long)DNAC_CFG_MIN_TARGET_ACTIVE,
            (unsigned long long)DNAC_CFG_MAX_TARGET_ACTIVE,
            (unsigned long long)DNAC_CFG_MAX_GAS_PRICE,
            (unsigned long long)DNAC_CFG_MIN_TOKEN_CREATE_FEE,
            (unsigned long long)DNAC_CFG_MAX_TOKEN_CREATE_FEE,
            (unsigned long long)DNAC_CFG_HF2_ACTIVE_ON,
            (unsigned long long)DNAC_CFG_HF3_ACTIVE_ON,
            (unsigned long long)DNAC_CFG_RULESET_GEN2_D2,
            (unsigned long long)DNAC_CFG_MIN_NAME_PRICE,
            (unsigned long long)DNAC_CFG_MAX_NAME_PRICE,
            (unsigned long long)DNAC_CFG_EVM_ACTIVE_D,
            (unsigned long long)DNAC_CFG_MIN_EVM_BLOCK_GAS,
            (unsigned long long)DNAC_CFG_MAX_EVM_BLOCK_GAS,
            (unsigned long long)DNAC_CFG_RULESET_GEN_STORAGE_D,
            (unsigned long long)DNAC_CFG_DELEGATE_NAME_REQUIRED_ON);
        return 1;
    }
    uint8_t param_id = 0;
    if (cc_param_name_to_id(param_name, &param_id) != 0) {
        fprintf(stderr, "Unknown param name: %s - accepted: "
                "TARGET_ACTIVE_COUNT | GAS_PRICE_RAW_PER_UNIT | "
                "TOKEN_CREATE_FEE_RAW | HF2_ACTIVE | HF3_ACTIVE | "
                "RULESET_GEN2 | NAME_PRICE_3P | NAME_PRICE_4P | "
                "NAME_PRICE_5P | NAME_PRICE_6P | EVM_ACTIVE | "
                "EVM_BLOCK_GAS_LIMIT | RULESET_GEN_STORAGE | "
                "DELEGATE_NAME_REQUIRED "
                "(the parameters the running consensus reads)\n",
                param_name);
        return 1;
    }
    if (!has_nonce) {
        nodus_random((uint8_t *)&proposal_nonce, sizeof(proposal_nonce));
        /* 63 bits: the chain refuses a nonce above INT64_MAX (decision
         * 2026-09-30-chain-config-int64-bounds.md), so a full 64-bit draw
         * would fail the step-9 pre-check below half of the time. */
        proposal_nonce &= (uint64_t)INT64_MAX;
    }
    uint8_t chain_id_arg[32];
    bool have_chain_id_arg = false;
    if (chain_id_hex) {
        if (cc_hex_to_bytes32(chain_id_hex, chain_id_arg) != 0) {
            fprintf(stderr, "--chain-id must be exactly 64 hex characters\n");
            return 1;
        }
        have_chain_id_arg = true;
    }

    /* 2. Open the session for the whole flow (queries + submit). */
    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client_connect failed\n");
        nodus_client_close(&client);
        return 1;
    }

    int rc = 1;
    nodus_dnac_committee_result_t *committee = NULL;  /* ~370 KB, heap  */
    bool           *ok    = NULL;   /* per-seat accepted-this-round      */
    uint8_t       (*sigs)[NODUS_SIG_BYTES] = NULL;   /* per-seat sig     */
    nodus_dnac_cc_collect_result_t *cres = NULL;     /* ~620 KB, heap    */
    dna_env_preflight_t *pf = NULL;
    cc_appr_envelope_t   b;
    memset(&b, 0, sizeof(b));

    /* 3. Chain id — read from THIS NODE, never pasted (D-16 rev 7 (5)). */
    uint8_t chain32[32];
    bool has_chain32 = false;
    if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
        !has_chain32) {
        fprintf(stderr,
            "this node is not on a version-3 chain (no chain_id32 in its "
            "dnac_supply reply) — chain-config propose needs a version-3 "
            "chain\n");
        goto done;
    }
    if (have_chain_id_arg && memcmp(chain_id_arg, chain32, 32) != 0) {
        fprintf(stderr,
            "--chain-id does not match this node's own derived chain id — "
            "refusing to proceed against a mismatched anchor\n");
        goto done;
    }

    /* 4. Committee query. block_height is the CANDIDATE inclusion height
     * (tip+1, nodus_witness_handlers.c handle_dnac_committee_query); the
     * governing committee height (H-1) is therefore block_height-1. The
     * array is already in committee RESOLUTION order (server emits
     * nodus_committee_get_for_block_alloc's own order, unsorted), which
     * is what the set-hash preimage requires. */
    committee = calloc(1, sizeof(*committee));
    if (!committee) { fprintf(stderr, "out of memory\n"); goto done; }
    if (nodus_client_dnac_committee(&client, committee) != 0) {
        fprintf(stderr, "committee query failed\n");
        goto done;
    }
    /* block_height is the server's FAIL-OPEN tip + 1
     * (nodus_witness_handlers.c handle_dnac_committee_query →
     * nodus_witness_block_height, 0 on a read fault), so 1 means "tip 0
     * or a faulted read" — neither yields a live expiry (CHECKTX-P1
     * round 3: refuse, never build on it). */
    if (committee->block_height <= 1) {
        fprintf(stderr, "committee query returned height %llu — the node's "
                        "tip is 0 or its height read faulted; refusing to "
                        "build an envelope whose expiry would be wrong\n",
                (unsigned long long)committee->block_height);
        goto done;
    }
    uint64_t tip = committee->block_height - 1;
    int      N   = committee->count;
    /* ⚠ HF-2 (design docs/plans/2026-09-30-gov-weight-netzero-design.md
     * rev 2): from the HF-2 height the chain weighs approvals by VOTING
     * POWER, not seats (nodus_rt_system_exec). This command talks to a
     * node over RPC only, and no RPC reports chain_config param 7
     * (dnac_fee_info carries params 5 and 6 only), so it cannot tell
     * which rule governs tip+1 and keeps the SEAT rule for its own
     * early abort and round-2 decision. The chain's verdict is
     * authoritative either way; the offline `v2-envelope chain-config`
     * builder reads param 7 from its database and follows it. OPEN:
     * reported, not invented (no new RPC in the HF-2 package). */
    uint32_t quorum = dna_bft_quorum((uint32_t)N);
    if (N < 1 || (uint32_t)N < quorum) {
        fprintf(stderr, "committee size %d cannot reach its own quorum "
                        "%u\n", N, quorum);
        goto done;
    }

    /* 5. Caller must be a committee member — found by PUBKEY, the same
     * comparison the responder uses to find its own seat. (The caller's
     * witness id this step also derived was the retired 4004 client's
     * sender id; the node now asks the seats with its own identity.) */
    int self_idx = -1;
    for (int i = 0; i < N; i++) {
        if (memcmp(committee->entries[i].pubkey, identity.pk.bytes,
                   NODUS_PK_BYTES) == 0) { self_idx = i; break; }
    }
    if (self_idx < 0) {
        fprintf(stderr, "Current identity is NOT in the committee — "
                        "chain-config propose requires a committee "
                        "operator key. Aborting.\n");
        goto done;
    }
    printf("Committee seat %d of %d (%.16s...).\n",
           self_idx, N, identity.fingerprint);

    /* 6. SYSTEM's ruleset_version/hash — read from the LOCAL BINARY's
     * compiled production table (nodus_witness_runtime.c table_get,
     * exported as nodus_runtime_builtin_table), never a DB: this client
     * has none. domreg resolution on ANY working version-3 chain already
     * requires the committed manifest to equal this same compiled table
     * (nodus_witness_domreg.c:324 resolves through it), so the two agree
     * on every chain SYSTEM is even resolvable on. A mismatched binary
     * version fails closed at preflight (ERR_CTX_VERSION) rather than
     * building a wrongly-keyed envelope. The lookup itself is the shared
     * cli_builtin_runtime (also used by `v2-envelope spend`). HF-4: the
     * generation is the one the node names (cli_select_runtimes). */
    const nodus_domain_runtime_t *sys_rt = NULL;
    if (cli_select_runtimes(&client, &sys_rt, NULL) != 0) goto done;
    if (!sys_rt) {
        fprintf(stderr, "SYSTEM runtime not found in the compiled "
                        "production table\n");
        goto done;
    }

    /* 7. Local set_hash + epoch, from the committee RPC's own pubkeys in
     * RPC (== resolution) order — the SAME preimage every responder
     * computes for itself, so a reply is compared against THIS, never
     * trusted blind. */
    uint8_t fps[DNA_MAX_ACTIVE_VALIDATORS][64];
    for (int i = 0; i < N; i++) {
        if (qgp_sha3_512(committee->entries[i].pubkey, NODUS_PK_BYTES,
                         fps[i]) != 0) {
            fprintf(stderr, "fingerprint hash failed\n");
            goto done;
        }
    }
    uint8_t set_hash[64];
    if (nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                    (uint32_t)N, set_hash) != 0) {
        fprintf(stderr, "set_hash compute failed\n");
        goto done;
    }
    uint64_t epoch = nodus_v2_epoch_for_height(tip);

    /* 8. Timing. signed_at must be nonzero (Rule CC-shape); tip itself
     * qualifies once the chain has produced at least one block, else 1 —
     * either way this is an ANCHOR the responder's own scalar_rules only
     * requires nonzero, not a specific value. valid_before gives slack
     * for the whole collect round trip using the safety grace period. */
    uint64_t signed_at    = tip > 0 ? tip : 1;
    uint64_t valid_before = tip + 1 + (uint64_t)DNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS;
    /* ORCHESTRATOR correction (W4-CC ORC-8): nodus_chain_config_scalar_rules
     * refuses `valid_before <= effective`, and the grace floor below
     * requires `effective >= tip+1+grace(param)` where every surviving
     * parameter's grace IS the safety period — so with valid_before left
     * at tip+1+SAFETY, EVERY proposal that passes the floor fails the
     * scalar rule and this command could never leave step 9 (found by
     * reading; the writer could not run the harness scenario). The
     * retired command carried exactly this adjustment (7e5d867e
     * nodus-cli.c:1028-1032, "Ensure Rule CC freshness math cannot
     * trivially fail"); restored verbatim. Harmless to freshness: the
     * chain's `H > valid_before` gate can never bind before the grace
     * floor does, since inclusion at H requires effective >= H+grace. */
    if (valid_before <= effective_block) {
        valid_before = effective_block +
                       (uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS;
    }

    /* 9. Local pre-checks — the SAME rules the responder (and the exec
     * hook) apply, checked here first so a doomed proposal never wastes
     * a network round trip. */
    if (nodus_chain_config_scalar_rules(param_id, new_value, signed_at,
                                        valid_before, effective_block,
                                        proposal_nonce) != 0) {
        fprintf(stderr, "scalar rules reject this (param, value, "
                        "effective) combination\n");
        goto done;
    }
    if (param_id == DNAC_CFG_TARGET_ACTIVE_COUNT &&
        new_value > NODUS_V2_ACTIVE_SET_MAX) {
        fprintf(stderr, "TARGET_ACTIVE_COUNT exceeds the V2 active-set "
                        "ceiling (%u)\n", (unsigned)NODUS_V2_ACTIVE_SET_MAX);
        goto done;
    }
    {
        uint64_t floor_h = tip + 1 +
                          nodus_chain_config_grace_for_param(param_id);
        if (effective_block < floor_h) {
            fprintf(stderr, "--effective (%llu) is below the grace floor "
                            "(%llu)\n", (unsigned long long)effective_block,
                            (unsigned long long)floor_h);
            goto done;
        }
    }

    /* 10. Round 1 — ask every seat (self signs locally, the node asks the
     * others). */
    pf = calloc(1, sizeof(*pf));
    ok = calloc((size_t)N, sizeof(*ok));
    sigs = calloc((size_t)N, sizeof(*sigs));
    cres = calloc(1, sizeof(*cres));
    if (!pf || !ok || !sigs || !cres) { fprintf(stderr, "out of memory\n"); goto done; }

    if (cc_appr_build_pass1(&b, pf, chain32, tip, sys_rt->ruleset_version,
                            sys_rt->ruleset_hash, (uint8_t)param_id,
                            new_value, effective_block, proposal_nonce,
                            signed_at, valid_before, (uint32_t)N) != 0) {
        fprintf(stderr, "round-1 envelope build/preflight failed\n");
        goto done;
    }
    int accepted = cc_propose_round(&client, N, self_idx, committee, NULL, &b,
                                    pf, set_hash, epoch, cres, ok, sigs);
    if (accepted < 0) goto done;
    printf("\nRound 1: %d/%d approved (need >= %u for quorum).\n",
           accepted, N, quorum);
    printf("Note: seat rule. From the HF-2 height the chain weighs approvals "
           "by voting power (> 2/3); this command cannot read whether HF-2 "
           "is active and does not apply that rule itself.\n");

    if (accepted < (int)quorum) {
        fprintf(stderr, "Quorum not reached. Aborting without submitting.\n");
        goto done;
    }

    if (accepted < N) {
        /* 11. Round 2 — rebuild with EXACTLY the accepting count (auth_len
         * changes, so round 1's signatures — including self's — are
         * invalid under the new digest) and re-ask ONLY the accepting
         * seats. Any refusal here aborts the whole proposal (no round 3,
         * D-16 rev 7 (5)). */
        int k = N - accepted;
        printf("Rebuilding with %d approver(s) (round 1 refused %d)...\n",
               accepted, k);
        /* Every seat this node asked in round 1 recorded this node's
         * identity in its per-proposer cooldown when the request ARRIVED
         * (nodus_cc_rate_limit_record, on every bonded attempt — so before
         * the node's reply reached this CLI) and would refuse the re-ask
         * as "rate-limited" for NODUS_CC_RATE_LIMIT_WINDOW_MS. Wait that
         * window out (decision 2026-09-26-cc-approval-via-own-node.md
         * (6)) PLUS CLI_CC_ROUND2_MARGIN_MS. Why a margin: the seat
         * measures the window on CLOCK_REALTIME (nodus_time_now_ms,
         * nodus_tcp.c:793-800) truncated to whole ms, and its test is
         * `elapsed < window` (nodus_cc_rate_limit_check). The sleep starts
         * after the seat's record, so nominally elapsed >= the sleep; what
         * can eat into that is the ms truncation on each side (< 2 ms) and
         * NTP slew of the seat's wall clock (<= 500 ppm → <= 2.5 ms over
         * 5 s) — about 5 ms, grounded. The rest of the 1000 ms is
         * JUDGMENT: headroom a human never notices next to a 5 s wait. No
         * margin covers a wall-clock STEP on a seat (a step backwards
         * reads as elapsed 0, chain_config.c's clock-skew rule); such a
         * seat refuses round 2 and the proposal aborts — retry it. The
         * envelope's expiry (CLI_ENV_EXPIRY_AHEAD blocks) covers the
         * wait. No reference counterpart (nodus governance tooling). */
        const uint32_t CLI_CC_ROUND2_MARGIN_MS = 1000u;
        const uint32_t wait_ms = NODUS_CC_RATE_LIMIT_WINDOW_MS +
                                 CLI_CC_ROUND2_MARGIN_MS;
        printf("Waiting %u ms for the seats' per-proposer cooldown before "
               "round 2...\n", (unsigned)wait_ms);
        fflush(stdout);
        {
            struct timespec ts;
            ts.tv_sec  = (time_t)(wait_ms / 1000u);
            ts.tv_nsec = (long)(wait_ms % 1000u) * 1000000L;
            while (nanosleep(&ts, &ts) != 0 && errno == EINTR) { }
        }
        cc_appr_envelope_free(&b);
        memset(&b, 0, sizeof(b));
        if (cc_appr_build_pass1(&b, pf, chain32, tip, sys_rt->ruleset_version,
                                sys_rt->ruleset_hash, (uint8_t)param_id,
                                new_value, effective_block, proposal_nonce,
                                signed_at, valid_before,
                                (uint32_t)accepted) != 0) {
            fprintf(stderr, "round-2 envelope build/preflight failed\n");
            goto done;
        }
        bool    *ok2   = calloc((size_t)N, sizeof(*ok2));
        uint8_t (*sigs2)[NODUS_SIG_BYTES] = calloc((size_t)N, sizeof(*sigs2));
        if (!ok2 || !sigs2) {
            free(ok2); free(sigs2);
            fprintf(stderr, "out of memory\n"); goto done;
        }
        /* The node asks every other seat again (its request carries only
         * the envelope); only the round-1 accepting seats are judged. */
        int accepted2 = cc_propose_round(&client, N, self_idx, committee, ok,
                                         &b, pf, set_hash, epoch, cres, ok2,
                                         sigs2);
        if (accepted2 < 0) {
            free(ok2); free(sigs2);
            goto done;
        }
        if (accepted2 != accepted) {
            fprintf(stderr, "Round 2: a previously-accepting seat refused "
                            "(%d/%d now) — aborting, no round 3.\n",
                            accepted2, accepted);
            free(ok2); free(sigs2);
            goto done;
        }
        free(ok); free(sigs);
        ok = ok2; sigs = sigs2;
        accepted = accepted2;
    }

    /* 12. Assemble: submitter (self) over auth_digest[0], then every
     * accepting seat's approval, ascending — committee order is already
     * ascending 0..N-1, so filtering by `ok[]` keeps that order. */
    {
        uint8_t *p = b.auth;
        p[0] = 1;
        memcpy(p + 1, identity.pk.bytes, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl,
                           pf->auth_digest[0], 64, identity.sk.bytes) != 0) {
            fprintf(stderr, "submitter sign failed\n");
            goto done;
        }
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)((uint32_t)accepted >> 8);
        p[1] = (uint8_t)accepted;
        p += 2;
        for (int seat = 0; seat < N; seat++) {
            if (!ok[seat]) continue;
            p[0] = (uint8_t)((uint16_t)seat >> 8);
            p[1] = (uint8_t)seat;
            memcpy(p + 2, sigs[seat], NODUS_SIG_BYTES);
            p += NODUS_RT_AUTH_APPROVAL_LEN;
        }
    }

    if (cc_appr_build_pass2(&b, pf, chain32, tip) != 0) {
        fprintf(stderr, "self-check preflight (pass 2) failed\n");
        goto done;
    }

    printf("\nenvelope built: %zu bytes, wire_id=", b.env_len);
    for (int i = 0; i < 8; i++) printf("%02x", pf->wire_id[i]);
    printf("...\n");

    /* 13. Submit through the ordinary tier-2 dnac_spend lane (SYSTEM legs
     * carry no fee). */
    {
        nodus_pubkey_t sender_pk;
        nodus_sig_t    sender_sig;
        memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);
        nodus_sign(&sender_sig, pf->wire_id, 64, &identity.sk);
        nodus_dnac_spend_result_t sres;
        memset(&sres, 0, sizeof(sres));
        int srv_rc = nodus_client_dnac_spend(&client, pf->wire_id,
                                             b.env_bytes, (uint32_t)b.env_len,
                                             &sender_pk, &sender_sig, 0,
                                             &sres);
        if (srv_rc != 0 || sres.status != NODUS_DNAC_APPROVED) {
            fprintf(stderr, "dnac_spend RPC failed (rc=%d status=%d)\n",
                    srv_rc, (int)sres.status);
            goto done;
        }
        printf("proposal accepted: mempool CheckTx approved (query "
              "dnac_tx for the eventual commit height)\n");
    }
    rc = 0;

done:
    if (pf) free(pf);
    cc_appr_envelope_free(&b);
    free(ok);
    free(sigs);
    free(cres);
    free(committee);
    nodus_client_close(&client);
    return rc;
}

/* ── Offline operator key loading (shared helper) ──────────────────
 *
 * Loads a CSV list of operator identity directories (--keys d1,d2,...)
 * so a verb can sign OFFLINE with keys it holds locally, instead of
 * needing a vote-collect RPC — the harness owns every node key, and the
 * witness verifies those signatures against the committee exactly as it
 * would networked ones. Used by `v2-envelope chain-config`, `v2-claim`
 * and `v2-envelope stake`.
 */
static int act_load_keys(const char *csv, nodus_identity_t *out, int cap) {
    int n = 0;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", csv);
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        if (n >= cap) return -1;
        if (nodus_identity_load(tok, &out[n]) != 0) {
            fprintf(stderr, "cannot load identity from %s\n", tok);
            return -1;
        }
        n++;
    }
    return n;
}

/* ── S3 — `stake` verb ─────────────────────────────────────────────
 *
 * Bonds THIS NODE's witness identity (-i dir) as a validator: builds a
 * DNAC_TX_STAKE whose signer is the node's Dilithium5 key, spending
 * UTXOs that already sit on the node identity's fingerprint (fund it
 * first, e.g. `dna send <node_fp> ...`). This is the ops/harness path
 * that lets a nodus-server join the validator set with the SAME key it
 * votes with — the wallet CLI's `dna stake` bonds the wallet identity,
 * which no server runs.
 *
 * --bond RAW (default DNAC_SELF_STAKE_AMOUNT) is the amount the envelope
 * locks: bond = Σin − Σchange − fee. Final pre-testnet wipe, W-B
 * (decision 2026-09-28-treasury-pools-and-exact-self-stake.md item 5):
 * the witness accepts EXACTLY DNAC_SELF_STAKE_AMOUNT (rtn_stake_exec), so
 * any other value is refused HERE rather than built into an envelope the
 * chain rejects; more weight is added by delegating to oneself. unstake
 * destination = this identity's own fingerprint. */
static int cmd_stake(const char *server_ip, uint16_t server_port,
                     int argc, char **argv, int cmd_start) {
    uint64_t commission_bps = 500;
    uint64_t bond_raw = DNAC_SELF_STAKE_AMOUNT;

    for (int i = cmd_start + 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--commission") == 0 && i + 1 < argc) {
            commission_bps = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(a, "--bond") == 0 && i + 1 < argc) {
            bond_raw = strtoull(argv[++i], NULL, 10);
        } else {
            fprintf(stderr, "Unknown arg: %s\n"
                    "Usage: stake [--commission BPS] [--bond %llu]\n",
                    a, (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
            return 1;
        }
    }
    /* the witness bound (tokenomics-v3 P3-8, rtn_stake_exec): refuse here
     * rather than build an envelope the chain rejects */
    if (commission_bps > (uint64_t)DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr, "--commission must be 0..%u\n",
                (unsigned)DNAC_COMMISSION_BPS_MAX);
        return 1;
    }
    if (bond_raw != DNAC_SELF_STAKE_AMOUNT) {
        fprintf(stderr, "--bond %llu != the self-bond %llu (the chain "
                "accepts exactly this amount; add more by delegating to "
                "yourself)\n", (unsigned long long)bond_raw,
                (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
        return 1;
    }

    nodus_client_t client;
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", server_ip);
    cfg.servers[0].port = server_port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;

    if (nodus_client_init(&client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return 1;
    }
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client_connect failed\n");
        nodus_client_close(&client);
        return 1;
    }

    int rc = 1;
    dnac_transaction_t *tx = NULL;
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    bool utxos_valid = false;

    /* Fee + chain_id. */
    nodus_dnac_fee_info_t fee_info;
    memset(&fee_info, 0, sizeof(fee_info));
    if (nodus_client_dnac_fee_info(&client, &fee_info) != 0) {
        fprintf(stderr, "fee info query failed\n");
        goto done;
    }
    uint64_t fee = fee_info.min_fee;

    nodus_dnac_supply_result_t supply;
    memset(&supply, 0, sizeof(supply));
    if (nodus_client_dnac_supply(&client, &supply) != 0) {
        fprintf(stderr, "supply query (for chain_id) failed\n");
        goto done;
    }

    /* UTXO selection: need bond + fee on the NODE identity's fp. */
    uint64_t need = bond_raw + fee;
    if (need < bond_raw) { fprintf(stderr, "overflow\n"); goto done; }

    if (nodus_client_dnac_utxo(&client, identity.fingerprint, 100,
                                 &utxos) != 0) {
        fprintf(stderr, "utxo query failed\n");
        goto done;
    }
    utxos_valid = true;
    if (utxos.count == 0) {
        fprintf(stderr, "No UTXOs on this node identity (%.16s…). Fund it "
                "first: dna send <node_fp> %llu ...\n",
                identity.fingerprint, (unsigned long long)need);
        goto done;
    }

    static const uint8_t stake_zero_token[DNAC_TOKEN_ID_SIZE] = {0};
    dnac_utxo_t selected[DNAC_MAX_UTXO_QUERY_RESULTS];
    int selected_count = 0;
    uint64_t total_input = 0;
    for (int i = 0; i < utxos.count && total_input < need; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        /* native DNAC only — same filter as the cc-propose verb above */
        if (memcmp(e->token_id, stake_zero_token, DNAC_TOKEN_ID_SIZE) != 0)
            continue;
        dnac_utxo_t *s = &selected[selected_count++];
        memset(s, 0, sizeof(*s));
        s->version = 1;
        memcpy(s->tx_hash, e->tx_hash, DNAC_TX_HASH_SIZE);
        s->output_index = e->output_index;
        s->amount       = e->amount;
        memcpy(s->nullifier, e->nullifier, DNAC_NULLIFIER_SIZE);
        snprintf(s->owner_fingerprint, sizeof(s->owner_fingerprint), "%s",
                 identity.fingerprint);
        total_input += e->amount;
    }
    if (total_input < need) {
        fprintf(stderr, "Insufficient native DNAC: have %llu raw, need %llu\n",
                (unsigned long long)total_input, (unsigned long long)need);
        goto done;
    }
    uint64_t change = total_input - need;

    /* Build the STAKE TX (mirrors dnac/src/transaction/stake.c). */
    tx = dnac_tx_create(DNAC_TX_STAKE);
    if (!tx) { fprintf(stderr, "tx_create failed\n"); goto done; }

    for (int i = 0; i < selected_count; i++) {
        if (dnac_tx_add_input(tx, &selected[i]) != DNAC_SUCCESS) {
            fprintf(stderr, "tx_add_input failed\n");
            goto done;
        }
    }
    if (change > 0) {
        uint8_t seed_unused[32];
        if (dnac_tx_add_output(tx, identity.fingerprint, change,
                                seed_unused) != DNAC_SUCCESS) {
            fprintf(stderr, "tx_add_output(change) failed\n");
            goto done;
        }
    }

    tx->stake_fields.commission_bps = (uint16_t)commission_bps;
    /* Unstake destination = this identity's own raw fingerprint
     * (SHA3-512 of the Dilithium5 pubkey — the same derivation the
     * hex identity.fingerprint encodes). */
    qgp_sha3_512(identity.pk.bytes, NODUS_PK_BYTES,
                 tx->stake_fields.unstake_destination_fp);

    memcpy(tx->chain_id, supply.chain_id, 32);
    tx->committed_fee = fee;

    memcpy(tx->signers[0].pubkey, identity.pk.bytes, DNAC_PUBKEY_SIZE);
    tx->signer_count = 1;

    if (dnac_tx_compute_hash(tx, tx->tx_hash) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_compute_hash failed\n");
        goto done;
    }

    nodus_sig_t sender_sig;
    nodus_sign(&sender_sig, tx->tx_hash, DNAC_TX_HASH_SIZE, &identity.sk);
    memcpy(tx->signers[0].signature, sender_sig.bytes, DNAC_SIGNATURE_SIZE);

    static uint8_t stake_tx_bytes[DNAC_MAX_TX_SIZE];
    size_t tx_len = 0;
    if (dnac_tx_serialize(tx, stake_tx_bytes, sizeof(stake_tx_bytes),
                            &tx_len) != DNAC_SUCCESS) {
        fprintf(stderr, "tx_serialize failed\n");
        goto done;
    }

    nodus_pubkey_t sender_pk;
    memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);

    nodus_dnac_spend_result_t spend_result;
    memset(&spend_result, 0, sizeof(spend_result));
    /* The RPC 'fee' parameter is the DECLARED input-output delta, not the
     * committed fee: the witness's Check 5 compares it against
     * Σin − Σout (nodus_witness_verify.c "fee mismatch"), and the wallet
     * declares exactly that (dnac/src/transaction/builder.c:352-355).
     * For STAKE the delta is bond + fee. */
    int srv_rc = nodus_client_dnac_spend(&client, tx->tx_hash, stake_tx_bytes,
                                           (uint32_t)tx_len, &sender_pk,
                                           &sender_sig, bond_raw + fee,
                                           &spend_result);
    if (srv_rc != 0) {
        fprintf(stderr, "dnac_spend RPC failed (rc=%d)\n", srv_rc);
        goto done;
    }

    printf("\nSTAKE submitted. hash=");
    for (int i = 0; i < 8; i++) printf("%02x", tx->tx_hash[i]);
    printf("... bond=%llu fee=%llu change=%llu commission=%llubps\n",
           (unsigned long long)bond_raw, (unsigned long long)fee,
           (unsigned long long)change, (unsigned long long)commission_bps);
    rc = 0;

done:
    if (tx) dnac_free_transaction(tx);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    nodus_client_close(&client);
    return rc;
}

/* ── O15D — `v2-envelope chain-config` (successor rehearsal driver) ──
 *
 * Builds the ONE envelope shape a fresh successor can execute: a
 * single-leg SYSTEM CHAIN_CONFIG (fee 0 — a SYSTEM leg has no fee sink)
 * under auth_kind 2 (submitter + committee approvals by SEAT against the
 * committed snapshot). Approvals bind epoch(H−1) + the resolved-set
 * hash; with every rehearsal height inside the first successor epoch the
 * snapshot row is the seam-frozen e_start-0 set, so offline approvals
 * stay valid at whichever height the block lands. Expiry is 0 = none
 * (env_preflight.h step 3), so an interleaved block cannot strand it.
 *
 * The two-pass auth build: auth_len IS committed (auth_context_commit),
 * so the envelope is first encoded with a zero-filled auth blob of the
 * EXACT final length, preflighted to derive the leg auth digest, signed,
 * re-encoded with the real bytes (same length ⇒ same digest), and
 * re-preflighted as a self-check before submission.
 */
static int cmd_v2_envelope(const char *server_ip, uint16_t server_port,
                           int argc, char **argv, int cmd_start) {
    const char *sub = (cmd_start + 1 < argc) ? argv[cmd_start + 1] : NULL;
    const char *db_path = NULL, *keys_csv = NULL;
    uint64_t param_id = 4;              /* DNAC_CFG_TARGET_ACTIVE_COUNT  */
    uint64_t new_value = 7;             /* == compiled default: inert    */
    uint64_t effective = 0, valid_before = 0, nonce = 1;

    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--db")    && i + 1 < argc) db_path  = argv[++i];
        else if (!strcmp(a, "--keys")  && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--param") && i + 1 < argc)
            param_id = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--value") && i + 1 < argc)
            new_value = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--effective") && i + 1 < argc)
            effective = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--valid-before") && i + 1 < argc)
            valid_before = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--nonce") && i + 1 < argc)
            nonce = strtoull(argv[++i], NULL, 10);
        else { sub = NULL; break; }
    }
    if (!sub || strcmp(sub, "chain-config") != 0 || !db_path || !keys_csv) {
        fprintf(stderr,
            "Usage: v2-envelope chain-config --db <successor.db> "
            "--keys <dir1,...,dirN>\n"
            "       [--param ID --value V --effective H --valid-before H "
            "--nonce N]\n");
        return 1;
    }

    int rc = 1;
    nodus_witness_t *wr = NULL;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    nodus_committee_member_t *committee = NULL;
    int cm_count = 0;
    uint8_t *fps = NULL;
    cc_appr_envelope_t b;
    memset(&b, 0, sizeof(b));
    dna_env_preflight_t *pf = NULL;

    keys = calloc(16, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 16);
    if (n_keys < 1) goto done;

    /* Minimal READ-ONLY witness view over the committed successor DB —
     * enough for the production authorities used below (they read
     * w->db and the committee cache). The cache sentinel MUST be
     * poisoned: a zeroed epoch_start would false-hit for e_start 0. */
    wr = calloc(1, sizeof(*wr));
    if (!wr) goto done;
    wr->cached_committee_epoch_start = UINT64_MAX;
    wr->cached_committee_count = -1;
    if (sqlite3_open_v2(db_path, &wr->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !wr->db) {
        fprintf(stderr, "cannot open %s read-only\n", db_path);
        goto done;
    }

    uint8_t chain32[32];
    uint64_t tip = 0;
    if (nodus_witness_v2_chain_id(wr, chain32) != 0 ||
        nodus_witness_v2_tip_height(wr, &tip) != 0) {
        fprintf(stderr, "not a committed successor V2 database\n");
        goto done;
    }
    if (tip == 0) {
        /* CHECKTX-P1 round 3: the envelope's expiry is tip-relative, and
         * a database with no committed block cannot anchor it. */
        fprintf(stderr, "the database has no committed block (tip 0) — "
                        "refusing to build an envelope whose expiry would "
                        "be wrong; wait for the first block\n");
        goto done;
    }

    dna_domain_manifest_t sys_man;
    if (nodus_witness_domreg_get(wr, DNA_DOMAIN_SYSTEM, NULL, &sys_man,
                                 NULL) != 0) {
        fprintf(stderr, "SYSTEM registry row unreadable\n");
        goto done;
    }
    /* HF-4 (design §1.6 "Expiry"): the H-1 cap the network builders take
     * from dnac_ruleset_info, read here from this database */
    if (cli_local_ruleset_facts(wr, &sys_man) != 0) goto done;

    /* The governing committee for inclusion height H = tip+1 is resolved
     * at H−1 = tip (the engine's expression). */
    if (nodus_committee_get_for_block_alloc(wr, tip, &committee,
                                            &cm_count) != 0 ||
        cm_count < 1) {
        fprintf(stderr, "committee resolution failed\n");
        goto done;
    }
    uint64_t appr_epoch = nodus_v2_epoch_for_height(tip);
    uint32_t quorum = dna_bft_quorum((uint32_t)cm_count);

    /* HF-2 (design docs/plans/2026-09-30-gov-weight-netzero-design.md
     * rev 2): which approval rule governs inclusion height H = tip+1 is
     * the committed chain_config param 7 at H — read here through the
     * SAME accessor the engine reads it with (nodus_chain_config_get_u64
     * over this read-only view; a fault or an impossible value refuses,
     * never guesses). Off: the first `quorum` keys approve (seat count,
     * as before). On: the keys approve IN THE ORDER GIVEN until their
     * seats' voting power exceeds 2/3 of the committee's power — the
     * engine's rule (nodus_rt_system_exec), power = floor(total_stake /
     * DNAC_DECIMAL_UNIT) as the engine derives it. */
    uint64_t hf2_raw = 0;
    if (nodus_chain_config_get_u64(wr, (uint8_t)DNAC_CFG_HF2_ACTIVE,
                                   tip + 1, 0ULL, &hf2_raw) < 0 ||
        (hf2_raw != 0ULL && hf2_raw != DNAC_CFG_HF2_ACTIVE_ON)) {
        fprintf(stderr, "chain_config HF2_ACTIVE at height %llu is "
                        "unreadable in this database — refusing to pick an "
                        "approval rule\n", (unsigned long long)(tip + 1));
        goto done;
    }
    int hf2_on = (hf2_raw == DNAC_CFG_HF2_ACTIVE_ON);
    uint32_t n_appr = quorum;
    if (hf2_on) {
        uint64_t total_power = 0, approved = 0, twice = 0;
        int ovf = 0;
        for (int s = 0; s < cm_count; s++) {
            uint64_t p = committee[s].total_stake / DNAC_DECIMAL_UNIT;
            if (p > UINT64_MAX - total_power) { ovf = 1; break; }
            total_power += p;
        }
        if (ovf || total_power == 0 || total_power > UINT64_MAX / 2) {
            fprintf(stderr, "HF-2 is active at height %llu and the committee's "
                            "voting power is %s — the chain refuses every "
                            "approval set\n",
                    (unsigned long long)(tip + 1),
                    total_power == 0 && !ovf ? "0" : "not weighable");
            goto done;
        }
        twice = total_power * 2;
        n_appr = 0;
        for (int k = 0; k < n_keys && approved <= twice / 3; k++) {
            int seat = -1;
            for (int s = 0; s < cm_count; s++) {
                if (memcmp(committee[s].pubkey, keys[k].pk.bytes,
                           DNAC_PUBKEY_SIZE) == 0) { seat = s; break; }
            }
            if (seat < 0) {
                fprintf(stderr, "key %d is not a committee member\n", k);
                goto done;
            }
            uint64_t p = committee[seat].total_stake / DNAC_DECIMAL_UNIT;
            if (p > UINT64_MAX - approved) {
                fprintf(stderr, "approver power sum overflows (a key "
                                "given twice?)\n");
                goto done;
            }
            approved += p;
            n_appr++;
        }
        if (!(approved > twice / 3)) {
            fprintf(stderr, "HF-2 is active: the %d approver keys given hold "
                            "voting power %llu of %llu, need > %llu\n",
                    n_keys, (unsigned long long)approved,
                    (unsigned long long)total_power,
                    (unsigned long long)(twice / 3));
            goto done;
        }
        printf("HF-2 active at height %llu: %u approver(s) hold voting "
               "power %llu of %llu (> %llu)\n",
               (unsigned long long)(tip + 1), (unsigned)n_appr,
               (unsigned long long)approved,
               (unsigned long long)total_power,
               (unsigned long long)(twice / 3));
    } else if ((uint32_t)(n_keys - 0) < quorum) {
        fprintf(stderr, "need >= %u approver keys (committee %d), got %d\n",
                (unsigned)quorum, cm_count, n_keys);
        goto done;
    }

    uint8_t set_hash[64];
    fps = malloc((size_t)cm_count * 64);
    if (!fps) goto done;
    for (int i = 0; i < cm_count; i++)
        if (qgp_sha3_512(committee[i].pubkey, DNAC_PUBKEY_SIZE,
                         fps + (size_t)i * 64) != 0)
            goto done;
    if (nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                    (uint32_t)cm_count, set_hash) != 0)
        goto done;

    /* Defaults derived from the committed tip: SAFETY grace floor is
     * H + grace at the (unknown) inclusion height — parked far beyond
     * the rehearsal window; valid_before must exceed effective. */
    if (effective == 0)    effective    = tip + 100000;
    if (valid_before == 0) valid_before = effective + 100000;

    /* auth blob: submitter(1 signer) ‖ approval_count u16 ‖ n_appr ×
     * (seat ‖ sig) — n_appr chosen above by the rule in force at tip+1 */
    pf = calloc(1, sizeof(*pf));
    if (!pf) goto done;

    if (cc_appr_build_pass1(&b, pf, chain32, tip,
                            sys_man.ruleset_version, sys_man.ruleset_hash,
                            (uint8_t)param_id, new_value, effective,
                            nonce, /*signed_at=*/1ULL, valid_before,
                            n_appr) != 0) {
        fprintf(stderr, "pass-1 build/preflight failed\n");
        goto done;
    }

    /* Sign: submitter (keys[0]) over the leg auth digest; each approver
     * over its 154-byte NDS.CCAPPR.v1 digest, sorted by SEAT. */
    {
        uint8_t *p = b.auth;
        p[0] = 1;
        memcpy(p + 1, keys[0].pk.bytes, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        if (qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl,
                           pf->auth_digest[0], 64, keys[0].sk.bytes) != 0)
            goto done;
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(n_appr >> 8);
        p[1] = (uint8_t)n_appr;
        p += 2;

        /* seat lookup per key, then emit in strictly ascending seats */
        int seat_of[16];
        for (int k = 0; k < (int)n_appr; k++) {
            seat_of[k] = -1;
            for (int s = 0; s < cm_count; s++) {
                if (memcmp(committee[s].pubkey, keys[k].pk.bytes,
                           DNAC_PUBKEY_SIZE) == 0) { seat_of[k] = s; break; }
            }
            if (seat_of[k] < 0) {
                fprintf(stderr, "key %d is not a committee member\n", k);
                goto done;
            }
        }
        /* simple selection sort of (seat, key) pairs */
        for (int a = 0; a < (int)n_appr; a++) {
            int best = a;
            for (int b2 = a + 1; b2 < (int)n_appr; b2++)
                if (seat_of[b2] < seat_of[best]) best = b2;
            int ts = seat_of[a]; seat_of[a] = seat_of[best]; seat_of[best] = ts;
            nodus_identity_t tk = keys[a]; keys[a] = keys[best]; keys[best] = tk;
        }
        for (int k = 0; k < (int)n_appr; k++) {
            if (k > 0 && seat_of[k] == seat_of[k - 1]) {
                fprintf(stderr, "duplicate committee seat among keys\n");
                goto done;
            }
            uint8_t adg[64];
            if (nodus_rt_cc_approval_digest(pf->auth_digest[0], set_hash,
                                            appr_epoch,
                                            (uint16_t)seat_of[k],
                                            adg) != 0)
                goto done;
            p[0] = (uint8_t)((uint16_t)seat_of[k] >> 8);
            p[1] = (uint8_t)seat_of[k];
            sl = 0;
            if (qgp_dsa87_sign(p + 2, &sl, adg, 64, keys[k].sk.bytes) != 0)
                goto done;
            p += NODUS_RT_AUTH_APPROVAL_LEN;
        }
    }

    if (cc_appr_build_pass2(&b, pf, chain32, tip) != 0) {
        fprintf(stderr, "pass-2 preflight failed\n");
        goto done;
    }

    printf("envelope built: %zu bytes, wire_id=", b.env_len);
    for (int i = 0; i < 8; i++) printf("%02x", pf->wire_id[i]);
    printf("... intent_id=");
    for (int i = 0; i < 8; i++) printf("%02x", pf->intent_id[i]);
    printf("...\n");

    /* Submit through the ordinary tier-2 dnac_spend lane. */
    {
        nodus_client_t client;
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s",
                 server_ip);
        cfg.servers[0].port = server_port;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &identity) != 0 ||
            nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed\n");
            nodus_client_close(&client);
            goto done;
        }
        nodus_pubkey_t sender_pk;
        nodus_sig_t sender_sig;
        memcpy(sender_pk.bytes, identity.pk.bytes, NODUS_PK_BYTES);
        nodus_sign(&sender_sig, pf->wire_id, 64, &identity.sk);
        nodus_dnac_spend_result_t sres;
        memset(&sres, 0, sizeof(sres));
        int srv_rc = nodus_client_dnac_spend(&client, pf->wire_id,
                                             b.env_bytes, (uint32_t)b.env_len,
                                             &sender_pk, &sender_sig, 0,
                                             &sres);
        nodus_client_close(&client);
        if (srv_rc != 0 || sres.status != NODUS_DNAC_APPROVED) {
            fprintf(stderr, "dnac_spend RPC failed (rc=%d status=%d)\n",
                    srv_rc, (int)sres.status);
            goto done;
        }
        /* R3 W4-C delta 5: same lie as t6_submit_on's old print, same
         * fix — sres.block_height/tx_index are always zero on a
         * version-3 chain (handle_dnac_spend sends no `bnr`/`ti`/`wsig`
         * on the CheckTx-immediate answer, nodus_witness_handlers.c:
         * 1836-1910); this path never routed through t6_submit_on (it
         * is its own inline connect/submit/close), so it needed its own
         * fix rather than inheriting delta 4's. */
        printf("accepted: mempool CheckTx approved (query dnac_tx for the "
               "eventual commit height)\n");
    }
    rc = 0;

done:
    if (pf) free(pf);
    cc_appr_envelope_free(&b);
    if (fps) free(fps);
    free(committee);
    if (wr) {
        if (wr->db) sqlite3_close(wr->db);
        free(wr);
    }
    if (keys) {
        for (int i = 0; i < 16; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── O15F Task 6 — submission-target parse + shared submit ──────────
 *
 * The O15D verbs submit to the outer -s server. T6's verbs additionally
 * accept `--submit ip:port` to name a target explicitly; when absent they
 * fall back to the outer -s server. This mirrors cmd_v2_envelope's
 * dnac_spend lane byte-for-byte (the classification into class 200 /
 * class 201 is SERVER-side: bytes beginning with the 16-byte envelope
 * family marker → 200, otherwise → 201, so a claim's canonical bytes —
 * which begin with claim_version u32 BE, never the marker — divert into
 * the claim lane without any wire flag). @return 0 / -1. */
static int t6_resolve_target(const char *submit, const char *def_ip,
                             uint16_t def_port, char ip_out[64],
                             uint16_t *port_out) {
    if (!submit) {
        if (!def_ip) return -1;
        snprintf(ip_out, 64, "%s", def_ip);
        *port_out = def_port;
        return 0;
    }
    const char *colon = strchr(submit, ':');
    if (colon) {
        size_t hlen = (size_t)(colon - submit);
        if (hlen == 0 || hlen >= 64) return -1;
        memcpy(ip_out, submit, hlen);
        ip_out[hlen] = '\0';
        *port_out = (uint16_t)atoi(colon + 1);
        if (*port_out == 0) return -1;
    } else {
        snprintf(ip_out, 64, "%s", submit);
        *port_out = def_port;
    }
    return 0;
}

/* R3 W4-C delta 4 — submit one transaction (claim bytes OR envelope
 * bytes) on an ALREADY-CONNECTED session: no connect/close, so a caller
 * submitting MANY items (cmd_v2_claim's --submit loop) can reuse one
 * session across the whole batch instead of paying a fresh Kyber1024
 * handshake + T2 auth per item. The caller owns the session's
 * lifecycle (open before, close after). `tx_hash` is the wire id the
 * server keys the transaction by (SHA3-512(claim bytes) for a claim;
 * the envelope wire_id for a stake).
 *
 * Distinguishes a per-item CheckTx refusal (return 1: the session
 * itself is fine, the caller can still try the next item) from an
 * RPC/session-level fault (return -1: something is wrong with the
 * connection, the caller should stop). @return 0 accepted / 1 refused
 * / -1 fault. */
/* The name of a CheckTx response code, as the node's application answers
 * it. THIS IS NOT nodus_v2_tx_code_t (the FinalizeBlock per-item space,
 * nodus_witness_v2_apply.h, where 1 = DECODE): the CheckTx space is its
 * own, defined in a .c the CLI does not link — copied here from
 * nodus_witness_cmt_app.c:748 (NODUS_CMT_APP_CODE_REJECTED = 1, "every
 * other refusal") and :771 (NODUS_CMT_APP_CODE_GENERATION = 100, the
 * envelope names a ruleset generation not in force), code space listed at
 * :774-781. Any other number is printed as code-N. */
static const char *cli_checktx_code_name(unsigned code, char *buf,
                                         size_t cap) {
    if (code == 1u)   return "REJECTED";
    if (code == 100u) return "GENERATION";
    snprintf(buf, cap, "code-%u", code);
    return buf;
}

/* One machine-greppable stderr line for a dnac_spend the node did not
 * take: the old "dnac_spend RPC failed (rc=N)" text stays as the prefix
 * (scripts grep it), then either
 *   refused: rc=N node="<node text>"[ checktx=<name>]
 * — the node answered with an error frame (its text; ` checktx=` when the
 * text is "CheckTx code N", nodus_witness_handlers.c handle_dnac_spend) —
 * or
 *   failed: rc=N node=""
 * — no error frame: no reply in time (rc 6 = NODUS_ERR_TIMEOUT), a reply
 * that could not be read, or a local failure. The node may still have
 * taken the transaction in that case; "failed" never means refused. */
static void cli_print_spend_refusal(int rc, const char *node_msg) {
    char nbuf[24];
    unsigned code = 0;
    const char *m = node_msg ? node_msg : "";
    fprintf(stderr, "dnac_spend RPC failed (rc=%d) %s: rc=%d node=\"%s\"",
            rc, m[0] ? "refused" : "failed", rc, m);
    if (sscanf(m, "CheckTx code %u", &code) == 1)
        fprintf(stderr, " checktx=%s",
                cli_checktx_code_name(code, nbuf, sizeof(nbuf)));
    fprintf(stderr, "\n");
}

static int t6_submit_on(nodus_client_t *client, nodus_identity_t *id,
                        const uint8_t tx_hash[64], const uint8_t *bytes,
                        uint32_t len) {
    nodus_pubkey_t spk;
    nodus_sig_t ssig;
    memcpy(spk.bytes, id->pk.bytes, NODUS_PK_BYTES);
    nodus_sign(&ssig, tx_hash, 64, &id->sk);
    nodus_dnac_spend_result_t sres;
    memset(&sres, 0, sizeof(sres));
    char node_msg[128];
    int rc = nodus_client_dnac_spend_ex(client, tx_hash, bytes, len, &spk,
                                        &ssig, 0, &sres, node_msg,
                                        sizeof(node_msg));
    if (rc != 0) {
        /* A CheckTx refusal arrives HERE (an error frame, rc 7), not as a
         * non-APPROVED status below — the -1 classification is unchanged
         * (v2-claim's batch loop reads it). */
        cli_print_spend_refusal(rc, node_msg);
        return -1;
    }
    if (sres.status != NODUS_DNAC_APPROVED) {
        fprintf(stderr, "dnac_spend refused (status=%d)\n",
                (int)sres.status);
        return 1;
    }
    /* R3 W4-C delta 4: on a version-3 chain this is the mempool's
     * CheckTx-IMMEDIATE answer, not a commit — handle_dnac_spend
     * (nodus_witness_handlers.c:1836-1910) sends no `bnr`/`ti`/`wsig`
     * on this lane ("there is no committed block yet to certify"), so
     * sres.block_height/tx_index stay at the memset-0 above; the OLD
     * "committed: height=... index=..." wording printed those zeros as
     * if they were a real commit position. Printed as what it actually
     * is: mempool admission, not inclusion. */
    printf("accepted: mempool CheckTx approved (query dnac_tx for the "
           "eventual commit height)\n");
    return 0;
}

/* (HF-1: the one-shot connect → t6_submit_on → close wrapper `t6_submit`
 * is DELETED — its last caller, `v2-envelope stake`, now opens its
 * session before the build to read the gas price and submits on it.) */

/* ── O15F Task 6 — `v2-claim` (successor GENESIS_CLAIM builder) ──────
 *
 * Re-derives the FULL distribution leaf set from the TERMINAL legacy
 * database with the SEAM'S EXACT query and leaf construction
 * (source_id = the 64-byte legacy nullifier, source_amount = amount,
 * dest_binding = owner fp → 64 raw bytes, version DNA_DIST_VERSION),
 * asserts the recomputed
 * dna_dist_snapshot_root EQUALS the successor manifest's committed
 * snapshot_root (proving leaf-set equivalence — a mismatch ABORTS and
 * never submits a bad proof), selects the caller's leaf(s) by
 * dest_binding == SHA3-512(pk), builds the Merkle proof, signs the claim
 * preimage (ML-DSA-87), emits canonical claim bytes and either self-checks
 * (--dry-run) or submits them (dnac_spend, class-201 server-side).
 *
 * Fail-closed leaf derivation (mirrors the seam): a malformed owner fp,
 * a mid-scan non-64-byte nullifier, a non-positive amount, or a
 * short/truncated scan ABORTS — a skipped row would shift every later
 * leaf_index and could never reproduce the committed root, but the abort
 * is explicit (the silent-substitution ban, root CLAUDE.md).
 */
static long claim_derive_legacy_leaves(sqlite3 *legacy,
                                       dna_dist_leaf_t **leaves_out) {
    *leaves_out = NULL;
    sqlite3_int64 n_utxo = 0;
    {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(legacy,
                "SELECT COUNT(*) FROM utxo_set WHERE amount > 0",
                -1, &st, NULL) != SQLITE_OK)
            return -1;
        if (sqlite3_step(st) == SQLITE_ROW)
            n_utxo = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    if (n_utxo <= 0 || (uint64_t)n_utxo > DNA_DIST_MAX_LEAVES) return -1;

    dna_dist_leaf_t *leaves = calloc((size_t)n_utxo, sizeof(*leaves));
    if (!leaves) return -1;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(legacy,
            "SELECT nullifier, owner, amount FROM utxo_set "
            "WHERE amount > 0 ORDER BY nullifier ASC",
            -1, &st, NULL) != SQLITE_OK) {
        free(leaves);
        return -1;
    }
    size_t n = 0;
    int rc, bad = 0;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n >= (size_t)n_utxo) { bad = 1; break; }
        const void *nul = sqlite3_column_blob(st, 0);
        const unsigned char *own = sqlite3_column_text(st, 1);
        sqlite3_int64 amt = sqlite3_column_int64(st, 2);
        if (!nul || sqlite3_column_bytes(st, 0) != 64 || !own || amt <= 0) {
            bad = 1; break;
        }
        dna_dist_leaf_t *L = &leaves[n];
        L->leaf_version  = DNA_DIST_VERSION;
        L->source_id_len = 64;
        memcpy(L->source_id, nul, 64);
        L->source_amount = (uint64_t)amt;
        /* seam_fp_to_binding: 128-char lowercase-hex owner → 64 raw. */
        if (qgp_fp_hex_to_raw((const char *)own, L->dest_binding) != 0) {
            bad = 1; break;
        }
        n++;
    }
    sqlite3_finalize(st);
    if (bad || rc != SQLITE_DONE || n == 0 || n != (size_t)n_utxo) {
        free(leaves);
        return -1;
    }
    *leaves_out = leaves;
    return (long)n;
}

/* qsort comparator over the canonical leaf order (source_id ASC).
 * dna_dist_leaf_cmp is the same predicate nodus_witness_v2_gen.c sorts
 * with; using it here rather than a hand-rolled memcmp is what keeps the
 * two orderings from drifting. */
static int claim_leaf_qcmp(const void *a, const void *b) {
    return dna_dist_leaf_cmp((const dna_dist_leaf_t *)a,
                             (const dna_dist_leaf_t *)b);
}

/* Rebuild the distribution leaves of a PURE V2 chain from its genesis
 * config file.
 *
 * ── WHY THIS EXISTS ─────────────────────────────────────────────────
 *
 * claim_derive_legacy_leaves above reads the TERMINAL LEGACY chain's
 * utxo_set: on the seam path, a V2 chain's distribution WAS the V1
 * chain's unspent outputs, so the leaf identity was (nullifier, owner,
 * amount). That was correct for as long as V2 was reached by migrating
 * a V1 chain.
 *
 * The 2026-08-27 cutover decision removed that path: a V2 chain is now
 * born from an operator config with its own allocation list, and the
 * leaf identity is (source_id, dest_binding, amount) — a different shape
 * from a different source. With only the legacy builder, `v2-claim`
 * required a --legacy-db that a hard cutover never produces, so on a
 * pure V2 chain NOBODY COULD CLAIM: the distribution root was committed
 * and unreachable, no coin outside the validators' locked self-bond
 * could move, and a chain that produces no block without a transaction
 * would have sat at its genesis height forever.
 *
 * ── WHAT MAKES A WRONG LEAF SET SAFE ────────────────────────────────
 *
 * Nothing here is trusted. The caller recomputes dna_dist_snapshot_root
 * over whatever this returns and compares it to the root the chain
 * COMMITTED at genesis; a mismatch aborts before a single proof is
 * built. So the failure mode of a wrong config or a wrong ordering is a
 * refusal, never a proof against a foreign tree.
 *
 * The construction below mirrors gen_plan_build
 * (nodus_witness_v2_gen.c) field for field, including the sort and the
 * amount >= 1 rule, because that is the tree the chain committed.
 *
 * @return leaf count, or -1. *out receives a malloc'd array.
 */
static long claim_derive_config_leaves(const char *conf_path,
                                       dna_dist_leaf_t **out) {
    *out = NULL;
    nodus_v2_gen_config_t *cfg = NULL;
    if (nodus_v2_gen_config_parse_file(conf_path, &cfg) != 0 || !cfg)
        return -1;                       /* the parser already said why */

    if (cfg->n_allocs < 1) {
        fprintf(stderr, "genesis config carries no allocation\n");
        nodus_v2_gen_config_free(cfg);
        return -1;
    }

    dna_dist_leaf_t *leaves = calloc((size_t)cfg->n_allocs, sizeof(*leaves));
    if (!leaves) { nodus_v2_gen_config_free(cfg); return -1; }

    for (uint32_t i = 0; i < cfg->n_allocs; i++) {
        dna_dist_leaf_t *L = &leaves[i];
        L->leaf_version  = DNA_DIST_VERSION;
        L->source_id_len = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
        memcpy(L->source_id, cfg->allocs[i].source_id,
               NODUS_V2_GEN_SRCID_LEN);
        if (cfg->allocs[i].amount < 1) {
            fprintf(stderr, "allocation[%u] amount is 0 — the builder "
                            "refuses such a config, so no chain can carry "
                            "this leaf\n", i);
            free(leaves); nodus_v2_gen_config_free(cfg); return -1;
        }
        L->source_amount = cfg->allocs[i].amount;
        memcpy(L->dest_binding, cfg->allocs[i].dest_binding, 64);
    }

    /* Canonical order: source_id ASC. The snapshot root accepts no
     * other, so file order cannot reach the tree. */
    qsort(leaves, (size_t)cfg->n_allocs, sizeof(*leaves), claim_leaf_qcmp);
    for (uint32_t i = 1; i < cfg->n_allocs; i++) {
        if (dna_dist_leaf_cmp(&leaves[i - 1], &leaves[i]) >= 0) {
            fprintf(stderr, "duplicate allocation source_id in the config\n");
            free(leaves); nodus_v2_gen_config_free(cfg); return -1;
        }
    }

    long n = (long)cfg->n_allocs;
    nodus_v2_gen_config_free(cfg);
    *out = leaves;
    return n;
}

static int cmd_v2_claim(const char *server_ip, uint16_t server_port,
                        int argc, char **argv, int cmd_start) {
    const char *legacy_db = NULL, *succ_db = NULL, *keys_csv = NULL;
    const char *conf_path = NULL;
    const char *submit = NULL;
    int dry_run = 0, bad_arg = 0;

    for (int i = cmd_start + 1; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--legacy-db") && i + 1 < argc) legacy_db = argv[++i];
        else if (!strcmp(a, "--config")    && i + 1 < argc) conf_path = argv[++i];
        else if (!strcmp(a, "--db")        && i + 1 < argc) succ_db   = argv[++i];
        else if (!strcmp(a, "--keys")      && i + 1 < argc) keys_csv  = argv[++i];
        else if (!strcmp(a, "--submit")    && i + 1 < argc) submit    = argv[++i];
        else if (!strcmp(a, "--dry-run"))                   dry_run   = 1;
        else { bad_arg = 1; break; }
    }
    /* Exactly one leaf source. Both would be a question with two answers
     * and no way to say which the chain committed; neither cannot build
     * a tree at all. */
    if (bad_arg || (!legacy_db && !conf_path) || (legacy_db && conf_path) ||
        !succ_db || !keys_csv || (!submit && !dry_run)) {
        fprintf(stderr,
            "Usage: v2-claim (--config <genesis.conf> | --legacy-db <terminal.db>)\n"
            "                --db <successor.db> --keys <keydir>\n"
            "                (--dry-run | --submit ip:port)\n"
            "\n"
            "  --config     a PURE V2 chain: leaves come from the genesis\n"
            "               config's allocation list. This is the hard-cutover\n"
            "               case and the one a fresh fleet needs.\n"
            "  --legacy-db  a SEAM chain: leaves are the terminal V1 chain's\n"
            "               unspent outputs. Only for a chain that was migrated\n"
            "               rather than born.\n"
            "\n"
            "Either way the rebuilt leaf set is checked against the snapshot\n"
            "root the chain committed; a mismatch refuses before any proof.\n");
        return 1;
    }

    int rc = 1;
    nodus_witness_t *wr = NULL;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    sqlite3 *legacy = NULL;
    dna_dist_leaf_t *leaves = NULL;
    uint8_t (*leaf_hashes)[64] = NULL;
    long n_leaves = 0;
    /* R3 W4-C delta 4: declared here (not at first use) and
     * zero-initialized so every earlier `goto done` in this function
     * reaches the cleanup label with a DEFINED value — a declaration
     * with an initializer further down would leave this indeterminate
     * on any goto that jumps over it, and `done:` unconditionally tests
     * it. */
    nodus_client_t sclient;
    int sclient_open = 0;

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 4);
    if (n_keys != 1) {
        fprintf(stderr, "v2-claim needs exactly one --keys identity\n");
        goto done;
    }

    /* Read-only successor view (cmd_v2_envelope pattern; poisoned cache). */
    wr = calloc(1, sizeof(*wr));
    if (!wr) goto done;
    wr->cached_committee_epoch_start = UINT64_MAX;
    wr->cached_committee_count = -1;
    if (sqlite3_open_v2(succ_db, &wr->db, SQLITE_OPEN_READONLY, NULL)
        != SQLITE_OK || !wr->db) {
        fprintf(stderr, "cannot open %s read-only\n", succ_db);
        goto done;
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip = 0;
    if (nodus_witness_v2_chain_id(wr, chain32) != 0 ||
        nodus_witness_v2_tip_height(wr, &tip) != 0) {
        fprintf(stderr, "not a committed successor V2 database\n");
        goto done;
    }

    /* The committed GENESIS manifest (locator 0 — nodus_witness_v2_apply.c
     * commits it at manifest_seq 0). Its snapshot_root is the equivalence
     * anchor and its distribution parameters drive the claim fields. */
    dna_gman_t m;
    if (nodus_witness_v2_manifest_load(wr, 0, &m) != 0) {
        fprintf(stderr, "successor genesis manifest unreadable\n");
        goto done;
    }
    if (!m.dist_present) {
        fprintf(stderr, "successor manifest carries no distribution\n");
        goto done;
    }
    uint8_t manifest_hash[64];
    if (dna_gman_hash(&m, manifest_hash) != 0) goto done;

    /* Re-derive the FULL leaf set — from whichever source this chain was
     * born with. Both paths are fail-closed, and both answer to the same
     * snapshot-root equivalence check a few lines below. */
    if (conf_path) {
        n_leaves = claim_derive_config_leaves(conf_path, &leaves);
        if (n_leaves < 1) {
            fprintf(stderr, "config leaf-set derivation failed "
                            "(fail-closed)\n");
            goto done;
        }
    } else {
        if (sqlite3_open_v2(legacy_db, &legacy, SQLITE_OPEN_READONLY, NULL)
            != SQLITE_OK || !legacy) {
            fprintf(stderr, "cannot open %s read-only\n", legacy_db);
            goto done;
        }
        n_leaves = claim_derive_legacy_leaves(legacy, &leaves);
        if (n_leaves < 1) {
            fprintf(stderr, "legacy leaf-set derivation failed "
                            "(fail-closed)\n");
            goto done;
        }
    }
    if ((uint64_t)n_leaves != m.leaf_count) {
        fprintf(stderr, "leaf count %ld != committed leaf_count %llu — "
                "ABORT (leaf-set mismatch)\n", n_leaves,
                (unsigned long long)m.leaf_count);
        goto done;
    }

    /* Equivalence assertion: the recomputed snapshot_root MUST equal the
     * committed one, else the leaves this build derived are not the leaves
     * the chain committed — refuse to submit a proof against a foreign
     * tree. */
    uint8_t snap_root[64];
    if (dna_dist_snapshot_root(leaves, (size_t)n_leaves, snap_root) != 0) {
        fprintf(stderr, "snapshot root recompute failed\n");
        goto done;
    }
    if (memcmp(snap_root, m.snapshot_root, 64) != 0) {
        fprintf(stderr, "recomputed snapshot_root != committed — ABORT "
                "(leaf-set not equivalent to the successor manifest)\n");
        goto done;
    }

    leaf_hashes = calloc((size_t)n_leaves, 64);
    if (!leaf_hashes) goto done;
    for (long i = 0; i < n_leaves; i++)
        if (dna_dist_leaf_hash(&leaves[i], leaf_hashes[i]) != 0) goto done;

    /* Caller binding = SHA3-512(pk). */
    uint8_t my_binding[64];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, my_binding) != 0)
        goto done;

    /* R3 W4-C delta 4: the submission client is now genuinely opened
     * ONCE here and reused for every matching leaf below (the comment
     * above already claimed this before delta 4, but the code actually
     * called t6_submit — connect + submit + close — per leaf; a 40-leaf
     * batch paid 40 Kyber1024 handshakes + T2 auths, tens of seconds
     * against a chain committing a block every ~1-5 s, so the batch
     * never accumulated in one block. Root cause read, not the engine:
     * genesis_protocol_v2.sh's test_cmt_claim_flood.sh run at
     * /tmp/stagef-20260917T231618Z carried 26:7, 27:16, 28:15, 29:2 —
     * spread over four blocks instead of landing together. */
    char sip[64];
    uint16_t sport = 0;
    if (!dry_run) {
        if (t6_resolve_target(submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target\n");
            goto done;
        }
        nodus_client_config_t scfg;
        memset(&scfg, 0, sizeof(scfg));
        snprintf(scfg.servers[0].ip, sizeof(scfg.servers[0].ip), "%s", sip);
        scfg.servers[0].port = sport;
        scfg.server_count    = 1;
        scfg.auto_reconnect  = false;
        if (nodus_client_init(&sclient, &scfg, &keys[0]) != 0 ||
            nodus_client_connect(&sclient) != 0) {
            fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
            nodus_client_close(&sclient);
            goto done;
        }
        sclient_open = 1;
    }

    int matched = 0, submitted = 0, accepted = 0, refused = 0, skipped = 0;
    for (long idx = 0; idx < n_leaves; idx++) {
        if (memcmp(leaves[idx].dest_binding, my_binding, 64) != 0) continue;
        matched++;

        dna_claim_t c;
        memset(&c, 0, sizeof(c));
        c.claim_version  = DNA_CLAIM_VERSION;
        memcpy(c.chain_id, chain32, DNA_CHAIN_ID_LEN);
        memcpy(c.manifest_hash, manifest_hash, 64);
        c.leaf_index     = (uint64_t)idx;
        c.source_id_len  = leaves[idx].source_id_len;
        memcpy(c.source_id, leaves[idx].source_id, leaves[idx].source_id_len);
        c.source_amount  = leaves[idx].source_amount;
        memcpy(c.dest_binding, leaves[idx].dest_binding, 64);
        c.auth_mode      = m.auth_mode;
        memcpy(c.pubkey, keys[0].pk.bytes, DNA_CLAIM_PUBKEY_LEN);
        if (dna_dist_proof_build((const uint8_t (*)[64])leaf_hashes,
                                 (size_t)n_leaves, (uint64_t)idx,
                                 c.siblings, &c.n_siblings) != 0) {
            fprintf(stderr, "proof build failed (leaf %ld)\n", idx);
            goto done;
        }

        /* Sign the tag-prefixed claim preimage (ML-DSA-87). */
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t pre_len = 0;
        if (dna_claim_preimage(&c, pre, &pre_len) != 0) goto done;
        size_t sl = 0;
        if (qgp_dsa87_sign(c.signature, &sl, pre, pre_len,
                           keys[0].sk.bytes) != 0 ||
            sl != DNA_CLAIM_SIG_LEN) {
            fprintf(stderr, "claim signature failed\n");
            goto done;
        }

        /* Canonical bytes + tx hash. */
        uint8_t bytes[DNA_CLAIM_MAX_WIRE];
        size_t blen = 0;
        if (dna_claim_encode(&c, bytes, sizeof(bytes), &blen) != 0) {
            fprintf(stderr, "claim encode failed\n");
            goto done;
        }
        uint8_t tx_hash[64];
        if (qgp_sha3_512(bytes, blen, tx_hash) != 0) goto done;

        uint8_t leafh[64], nul[64];
        if (dna_dist_leaf_hash(&leaves[idx], leafh) != 0 ||
            dna_claim_nullifier(chain32, manifest_hash, m.target_domain_id,
                                m.target_asset_ref, m.target_asset_len,
                                leafh, nul) != 0)
            goto done;

        if (dry_run) {
            printf("v2-claim leaf_index=%ld amount=%llu bytes=%zu\n",
                   idx, (unsigned long long)c.source_amount, blen);
            printf("  tx_hash=");
            for (int b = 0; b < 64; b++) printf("%02x", tx_hash[b]);
            printf("\n  nullifier=");
            for (int b = 0; b < 64; b++) printf("%02x", nul[b]);
            printf("\n");
            /* Local admission self-check through the REAL engine path. */
            nodus_v2_claim_admit_t adm;
            memset(&adm, 0, sizeof(adm));
            if (nodus_witness_v2_claim_admit(wr, &c, tip + 1, &adm) != 0) {
                fprintf(stderr, "  LOCAL ADMIT: REJECT (leaf %ld)\n", idx);
                goto done;
            }
            printf("  LOCAL ADMIT: OK (converted=%llu)\n",
                   (unsigned long long)adm.converted);
        } else {
            /* ── SKIP A LEAF THE CHAIN HAS ALREADY SETTLED ────────────
             *
             * Without this the verb re-submits every leaf this key owns
             * on every invocation, spent or not, because the loop above
             * selects purely on dest_binding. A second call therefore
             * hands the cluster transactions that can never commit.
             *
             * That is not a cosmetic waste. Until v0.19.45 a node that
             * refused such a claim at admission still FORWARDED it and
             * still counted it as live demand, arming a view change it
             * could not disseminate — one node escalated its target from
             * 2 to 318 at 1/14 for the best part of an hour (nodus/BUGS.md,
             * the N=20 entry). The chain no longer dies of it, but the
             * round and the client's 30-second wait are still burned, and
             * a harness using this verb as a block pump cannot tell
             * "nothing left to submit" from "the chain would not commit"
             * — which is exactly the confound that cost a full diagnosis.
             *
             * The check is the ENGINE'S OWN, the same call the --dry-run
             * branch above makes, against the same read-only view. Not a
             * private reimplementation: a second opinion about what is
             * spent is how the pre-check/apply divergence recorded in the
             * same bug file came about.
             *
             * SKIP, never abort: the other leaves this key owns may be
             * perfectly claimable, and one settled leaf must not hide
             * them. */
            nodus_v2_claim_admit_t adm;
            memset(&adm, 0, sizeof(adm));
            if (nodus_witness_v2_claim_admit(wr, &c, tip + 1, &adm) != 0) {
                skipped++;
                continue;
            }
            submitted++;
            int srv = t6_submit_on(&sclient, &keys[0], tx_hash, bytes,
                                   (uint32_t)blen);
            if (srv == 0) {
                accepted++;
            } else if (srv == 1) {
                refused++;
            } else {
                /* Session/RPC-level fault, not a per-item refusal — the
                 * remaining leaves cannot be tried on this session.
                 * Report the partial batch before leaving. */
                fprintf(stderr, "v2-claim: %d submitted (%d accepted, "
                        "%d refused), %d skipped (already-claimed) — "
                        "aborting after a session fault\n",
                        submitted, accepted, refused, skipped);
                goto done;
            }
        }
    }
    if (!matched) {
        fprintf(stderr, "no distribution leaf binds this key\n");
        goto done;
    }
    /* Say which of the two "nothing happened" cases this was, so a caller
     * driving blocks with this verb can tell them apart. */
    if (!dry_run && submitted == 0 && skipped > 0) {
        fprintf(stderr, "v2-claim: all %d leaf/leaves bound to this key are "
                "already claimed — nothing to submit\n", skipped);
        rc = 2;
        goto done;
    }
    /* R3 W4-C delta 4: per-batch summary — one session, every matching
     * leaf submitted through it, tallied by CheckTx outcome. */
    if (!dry_run)
        fprintf(stderr, "v2-claim: %d submitted (%d accepted, %d refused), "
                "%d skipped (already-claimed)\n",
                submitted, accepted, refused, skipped);
    rc = 0;

done:
    if (sclient_open) nodus_client_close(&sclient);
    free(leaf_hashes);
    free(leaves);
    if (legacy) sqlite3_close(legacy);
    if (wr) {
        if (wr->db) sqlite3_close(wr->db);
        free(wr);
    }
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── O15F Task 6 — `v2-envelope stake` (O11 two-leg STAKE builder) ───
 *
 * Builds the canonical O11 staking envelope from what the NODE reports
 * (P2P-PORT F6 / K3 — no local database; see cmd_v2_stake's own header)
 * and the operator key dir: leg0 = SYSTEM STAKE
 * (runtime_op 1, call = staker_pk[2592] ‖ commission u16 ‖ bond u64 ‖
 * dest_fp[64 RAW] = 2666, nodus_witness_rt_native.c:199-200), leg1 = CORE
 * SYSFUND (runtime_op 7, call = the SPEND transfer section funded from the
 * caller's CORE coins as dnac_utxo lists them). Conservation Σin ==
 * Σchange + fee + lock is enforced by the exec (the lock = bond derives
 * from the SYSTEM sibling); the CLI just supplies inputs summing to
 * bond + fee + change. fee = max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE),
 * raised under HF-1 to 400 000 units × the node's gas_price
 * (dnac_fee_info) — on both --dry-run and --submit. Each leg carries a
 * kind-1 single-signer auth blob (the staker) over the ENGINE-derived leg
 * auth_digest — the two-pass build cmd_v2_envelope uses (zero-fill →
 * preflight → sign → re-encode → re-preflight self-check).
 *
 * Reuses the compiled ruleset table (cli_builtin_runtime), the node's
 * chain id, dna_env_encode, dna_env_preflight self-check and the
 * dnac_spend lane — the `v2-envelope spend` sources.
 */
/* The transfer-section widths, the coin type, the output-record writer
 * and the one-key two-pass signature (nodus_v2_env_sign_one_key) live in
 * the shared SPEND builder (nodus/include/nodus/nodus_v2_spend.h — web
 * wallet package (c2)); `v2-envelope stake`, `spend`, `token-create` and
 * `spend --msig` call it from there. */

/* The one-key two-pass signature (nodus_v2_env_sign_one_key) against the
 * --keys identity, printing the reason of a refusal as the builders did
 * before the move. @return 0 / -1. */
static int cli_sign_one_key(const dna_env_in_t *env_in, uint8_t *const *auths,
                            const dna_env_leg_ctx_t *lctx,
                            const uint8_t chain32[DNA_CHAIN_ID_LEN],
                            uint64_t tip, const nodus_identity_t *key,
                            uint8_t **env_out, size_t *env_len_out,
                            dna_env_preflight_t *pf) {
    nodus_v2_spend_err_t e;
    memset(&e, 0, sizeof(e));
    int rc = nodus_v2_env_sign_one_key(env_in, auths, lctx, chain32, tip,
                                       key->pk.bytes, key->sk.bytes, env_out,
                                       env_len_out, pf, &e);
    if (rc == NODUS_V2_SPEND_ERR_PREFLIGHT1)
        fprintf(stderr, "pass-1 preflight failed\n");
    else if (rc == NODUS_V2_SPEND_ERR_SIGN)
        fprintf(stderr, "leg %d signature failed\n", e.leg);
    else if (rc == NODUS_V2_SPEND_ERR_PREFLIGHT2)
        fprintf(stderr, "pass-2 preflight (self-check) failed\n");
    return rc == NODUS_V2_SPEND_OK ? 0 : -1;
}

/* The shared builder's randomness source for this CLI: the platform
 * CSPRNG (nodus_random), exactly the source the builders drew output
 * seeds from before the move. */
static int cli_rand(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    return nodus_random(buf, len);
}

/* The CORE ruleset identity + the BLOCK metering policy for the shared
 * builder, from the compiled table (cli_builtin_runtime) — this binary's
 * source for every networked envelope. */
static void cli_ruleset_id(const nodus_domain_runtime_t *core_rt,
                           const nodus_domain_runtime_t *sys_rt,
                           nodus_v2_ruleset_id_t *out) {
    memset(out, 0, sizeof(*out));
    out->core_ruleset_version = core_rt->ruleset_version;
    memcpy(out->core_ruleset_hash, core_rt->ruleset_hash, 64);
    out->meter_policy = sys_rt->meter_policy;
}

/* Decode exactly `n` bytes from 2n LOWERCASE hex characters (the form
 * the genesis document and `xxd -p` print a public key in). @return 0 /
 * -1 on a wrong length or any other character. */
static int t6_hex_exact(const char *hex, uint8_t *out, size_t n) {
    if (!hex || strlen(hex) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            int d;
            if (c >= '0' && c <= '9')      d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else return -1;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* `v2-envelope unstake`: the name of a validator row's status byte
 * (dnac/validator.h dnac_validator_status_t). */
static const char *cli_validator_status_name(uint8_t st) {
    switch (st) {
    case DNAC_VALIDATOR_ACTIVE:       return "ACTIVE";
    case DNAC_VALIDATOR_RETIRING:     return "RETIRING";
    case DNAC_VALIDATOR_UNSTAKED:     return "UNSTAKED";
    case DNAC_VALIDATOR_AUTO_RETIRED: return "AUTO_RETIRED";
    case DNAC_VALIDATOR_ELIGIBLE:     return "ELIGIBLE";
    default:                          return "UNKNOWN";
    }
}

/* One page of the validator listing, and the most pages read before the
 * walk gives up: DNAC_MAX_VALIDATORS rows fit in one page, the bound only
 * stops a node that keeps answering full pages. */
#define CLI_VLIST_PAGE       DNAC_MAX_VALIDATORS
#define CLI_VLIST_MAX_PAGES  64

/* `v2-envelope unstake`: find `pk`'s row in the node's validator list
 * (dnac_validator_list_query, every status, paged by offset).
 * @return 1 found (*row filled) / 0 the listing ended without it /
 *         -1 the query failed or the walk did not end. */
static int cli_validator_row(nodus_client_t *client, const uint8_t *pk,
                             nodus_dnac_validator_list_entry_t *row) {
    int offset = 0;
    for (int page = 0; page < CLI_VLIST_MAX_PAGES; page++) {
        nodus_dnac_validator_list_result_t res;
        memset(&res, 0, sizeof(res));
        if (nodus_client_dnac_validator_list(client, -1, offset,
                                             CLI_VLIST_PAGE, &res) != 0)
            return -1;
        int found = 0;
        for (int i = 0; i < res.count && res.entries; i++) {
            if (memcmp(res.entries[i].pubkey, pk, DNAC_PUBKEY_SIZE) == 0) {
                *row = res.entries[i];
                found = 1;
                break;
            }
        }
        const int count = res.count, total = res.total;
        nodus_client_free_validator_list_result(&res);
        if (found) return 1;
        if (count <= 0) return 0;
        offset += count;
        if (offset >= total) return 0;
    }
    return -1;
}

/* P2P-PORT F6 (K3, decision 2026-09-26-witness-port-session.md): no
 * local database. Everything comes from the node over ONE session
 * authenticated AS THE STAKER, exactly as `v2-envelope spend`:
 *   - chain id: dnac_supply's chain_id32 (nodus_client_dnac_chain_id32);
 *   - SYSTEM / CORE ruleset: the compiled table (cli_builtin_runtime);
 *   - the funding coins + their unlock heights + the tip: dnac_utxo (the
 *     server lists CORE-domain coins only — nodus_witness_utxo_by_owner);
 *   - the gas price: dnac_fee_info.
 * So a candidate stakes without ever touching 4004 (K2's "a new
 * candidate is never stuck"). `--dry-run` therefore needs the node too:
 * it lists the coins and reads the gas price, builds and self-checks the
 * envelope, and submits nothing. Both paths print wire_id and intent_id;
 * intent_id commits expiry_height = tip + CLI_ENV_EXPIRY_AHEAD
 * (env_wire.h intent_id preimage), so a dry run and a later submit can
 * differ when a block lands in between — a caller that needs the
 * submitted envelope's intent_id reads it from the SUBMIT output.
 *
 * `v2-envelope delegate` (final pre-testnet wipe, W-B) is the SAME
 * two-leg builder with the SYSTEM leg swapped: leg0 = SYSTEM DELEGATE
 * (runtime_op 2, call = delegator_pk[2592] ‖ validator_pk[2592] ‖
 * amount u64 = 5192, nodus_witness_rt_native.c rtn_deleg_parse), leg1 =
 * the same CORE SYSFUND funding, whose lock the exec derives from the
 * DELEGATE call's amount exactly as it does from STAKE's bond. The
 * delegator is the --keys identity (it signs both legs and owns the
 * funding coins); the target is --validator, the validator's 2592-byte
 * public key as 5184 lowercase hex. Since W-B the target may be the
 * --keys identity itself (Rule S is gone — decision 2026-09-28-
 * treasury-pools-and-exact-self-stake.md item 6); that is how a
 * validator adds weight beyond its exact 10M self-bond. Every other
 * DELEGATE rule (a bonded target, the 100-NODUS minimum for a new row,
 * the per-validator delegator cap) is the chain's, decided at CheckTx —
 * the builder checks only what the call bytes alone decide
 * (1 <= amount <= total supply, rtn_delegate_exec's scalar rule).
 * HF-8 (design docs/plans/2026-10-07-delegate-name-required-design.md rev
 * 2 §1; chain_config param 17, inert until voted): from the activation
 * height on, a DELEGATE whose delegator is not the validator is refused
 * at CheckTx unless the delegator owns an on-chain name (CORE SYSFUND,
 * nodus_witness_rt_native.c rtn_sysfund_name_gate) — new delegations and
 * top-ups alike; CheckTx sees committed state only, so a `name register`
 * still in the mempool does not count yet. Such a funding leg carries at
 * most 14 inputs; the shared builder (nodus_v2_stake.c) caps every
 * non-self DELEGATE at 14 whether or not the rule is active.
 *
 * `v2-envelope undelegate` is the DELEGATE layout under runtime_op 4
 * (DNA_SYSRULE_UNDELEGATE, rtn_deleg_parse): the --keys identity withdraws
 * --amount of its delegation to --validator. Its funding leg pays the FEE
 * ONLY (rtn_sys_call_flow: lock 0, release = amount); the principal comes
 * back as a coin the chain creates in the same block, LOCKED for
 * DNAC_UNDELEGATE_LOCK_EPOCHS epochs (rtn_sysfund_exec). The row checks
 * (it exists, amount <= its amount, a partial withdrawal leaves 0 or >=
 * DNAC_MIN_DELEGATION) are the chain's (rtn_undelegate_exec).
 *
 * `v2-envelope unstake` retires the --keys identity as a validator:
 * leg0 = SYSTEM UNSTAKE (runtime_op 3, DNA_SYSRULE_UNSTAKE; call = the
 * validator's own 2592-byte key, RTN_SYS_UNSTAKE_CALL_LEN — the signer
 * must be that key, rtn_sys_stake_auth), leg1 = a fee-only SYSFUND
 * (rtn_sys_call_flow: lock 0, release 0). The exec moves the row to
 * RETIRING (rtn_unstake_exec); the bond and any delegations come back at
 * the graduation boundary (nodus_witness_v2_epoch.c). A validator WITH
 * delegators may exit (tokenomics-v3 P3-4, Rule A removed — decision
 * 2026-09-22-nodus-tokenomics-v3-operator.md §3 2026-09-24 (3)), so the
 * CLI refuses nothing on their account; it reads the validator's row from
 * the node's validator list (dnac_validator_list_query) and refuses only
 * a status the chain would reject (not ACTIVE / ELIGIBLE), otherwise it
 * prints what will happen to the delegations and the bond, and that an
 * ACTIVE validator keeps signing until the set that drops it takes effect
 * (same decision, 2026-09-23 graduation deferral).
 *
 * The envelope itself is built by the shared, I/O-free builder
 * (nodus/src/client/nodus_v2_stake.c, nodus_v2_stake_build) — the body
 * this function had before the move; this function does the I/O and the
 * printing. */
static int cmd_v2_stake(const char *server_ip, uint16_t server_port,
                        int argc, char **argv, int cmd_start) {
    const char *keys_csv = NULL, *dest_fp_hex = NULL;
    const char *validator_hex = NULL;
    const char *submit = NULL;
    uint64_t bond = 0;
    uint32_t commission = 0;
    int dry_run = 0, have_bond = 0, have_comm = 0, bad_arg = 0;
    /* "stake", "delegate", "unstake" or "undelegate" — the word after
     * "v2-envelope" (main's dispatch routes only those four here).
     * DELEGATE and UNDELEGATE share the call layout and so the arguments;
     * UNSTAKE takes none beyond the key (its call is the key itself). */
    const int is_unstake = !strcmp(argv[cmd_start + 1], "unstake");
    const int is_undeleg = !strcmp(argv[cmd_start + 1], "undelegate");
    const int is_deleg = is_undeleg ||
                         !strcmp(argv[cmd_start + 1], "delegate");
    const int is_stake = !is_deleg && !is_unstake;
    const char *verb = is_unstake ? "unstake"
                     : is_undeleg ? "undelegate"
                     : is_deleg   ? "delegate" : "stake";
    const nodus_v2_stake_op_t op = is_unstake ? NODUS_V2_STAKE_OP_UNSTAKE
                                 : is_undeleg ? NODUS_V2_STAKE_OP_UNDELEGATE
                                 : is_deleg   ? NODUS_V2_STAKE_OP_DELEGATE
                                              : NODUS_V2_STAKE_OP_STAKE;

    for (int i = cmd_start + 2; i < argc; i++) {   /* skip the verb word */
        const char *a = argv[i];
        if      (!strcmp(a, "--keys")       && i + 1 < argc) keys_csv = argv[++i];
        else if (is_stake && !strcmp(a, "--bond") && i + 1 < argc) {
            bond = strtoull(argv[++i], NULL, 10); have_bond = 1;
        } else if (is_deleg && !strcmp(a, "--amount") && i + 1 < argc) {
            bond = strtoull(argv[++i], NULL, 10); have_bond = 1;
        } else if (is_stake && !strcmp(a, "--commission") && i + 1 < argc) {
            commission = (uint32_t)strtoul(argv[++i], NULL, 10); have_comm = 1;
        } else if (is_stake && !strcmp(a, "--dest-fp") && i + 1 < argc)
            dest_fp_hex = argv[++i];
        else if (is_deleg && !strcmp(a, "--validator") && i + 1 < argc)
            validator_hex = argv[++i];
        else if (!strcmp(a, "--submit")     && i + 1 < argc) submit = argv[++i];
        else if (!strcmp(a, "--dry-run"))                    dry_run = 1;
        else { bad_arg = 1; break; }   /* incl. the retired --db */
    }
    if (bad_arg || !keys_csv || (!is_unstake && !have_bond) ||
        (!submit && !dry_run) ||
        (is_stake && (!dest_fp_hex || !have_comm)) ||
        (is_deleg && !validator_hex)) {
        fprintf(stderr,
            "Usage: v2-envelope stake --keys <keydir> --bond <raw> "
            "--commission <bps> --dest-fp <hex128>\n"
            "       (--dry-run | --submit ip:port)\n"
            "       v2-envelope delegate --keys <keydir> --validator "
            "<hex5184 pubkey> --amount <raw>\n"
            "       (--dry-run | --submit ip:port)\n"
            "       v2-envelope undelegate --keys <keydir> --validator "
            "<hex5184 pubkey> --amount <raw>\n"
            "       (--dry-run | --submit ip:port)\n"
            "       v2-envelope unstake --keys <keydir> "
            "(--dry-run | --submit ip:port)\n"
            "  Everything (chain id, coins, tip, gas price) is read from "
            "the node over ONE\n"
            "  session: --submit, or the outer -s server for --dry-run. No "
            "local database\n"
            "  (--db is retired). --dry-run builds and self-checks, submits "
            "nothing.\n"
            "  delegate: --validator may be the --keys identity's own key "
            "(self-delegation).\n"
            "  delegate: once the chain votes DELEGATE_NAME_REQUIRED (HF-8), "
            "the --keys\n"
            "  identity must own an on-chain name (`name register`, and wait "
            "until it is in\n"
            "  a block) to delegate or add more; self-delegation is exempt. "
            "A delegation to\n"
            "  another validator is funded by at most 14 coins (the chain "
            "reads the name too).\n"
            "  unstake: the --keys identity retires as a validator; its "
            "delegations are\n"
            "  returned to their delegators when it graduates (locked %d "
            "epochs), its bond\n"
            "  to its recorded unstake destination (locked %d epochs).\n",
            (int)DNAC_UNDELEGATE_LOCK_EPOCHS,
            (int)DNAC_VALIDATOR_UNBOND_EPOCHS);
        return 1;
    }
    uint8_t validator_pk[DNAC_PUBKEY_SIZE] = {0};
    if (is_deleg) {
        if (t6_hex_exact(validator_hex, validator_pk, DNAC_PUBKEY_SIZE) != 0) {
            fprintf(stderr, "--validator must be exactly %d lowercase hex "
                    "chars (the validator's public key)\n",
                    2 * DNAC_PUBKEY_SIZE);
            return 1;
        }
        /* the chain's scalar rule (rtn_delegate_exec) */
        if (bond < 1 || bond > DNAC_DEFAULT_TOTAL_SUPPLY) {
            fprintf(stderr, "--amount must be 1..%llu raw\n",
                    (unsigned long long)DNAC_DEFAULT_TOTAL_SUPPLY);
            return 1;
        }
    }
    /* the witness bound (tokenomics-v3 P3-8, rtn_stake_exec) — the u16
     * wire field alone would admit values the chain refuses */
    if (is_stake && commission > (uint32_t)DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr, "--commission must be 0..%u\n",
                (unsigned)DNAC_COMMISSION_BPS_MAX);
        return 1;
    }
    /* the witness rule (final pre-testnet wipe W-B, rtn_stake_exec): the
     * bond is EXACTLY DNAC_SELF_STAKE_AMOUNT — refused here with a reason
     * rather than left to the preflight self-check's bare VERDICT */
    if (is_stake && bond != DNAC_SELF_STAKE_AMOUNT) {
        fprintf(stderr, "--bond %llu != the self-bond %llu (the chain "
                "accepts exactly this amount; add more by delegating to "
                "yourself: v2-envelope delegate)\n",
                (unsigned long long)bond,
                (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
        return 1;
    }
    uint8_t dest_fp[64] = {0};
    if (is_stake && qgp_fp_hex_to_raw(dest_fp_hex, dest_fp) != 0) {
        fprintf(stderr, "--dest-fp must be exactly 128 lowercase hex chars\n");
        return 1;
    }

    int rc = 1;
    nodus_identity_t *keys = NULL;
    int n_keys = 0;
    nodus_v2_stake_coin_t *coins = NULL;
    nodus_v2_stake_built_t built;
    memset(&built, 0, sizeof(built));
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    int utxos_valid = 0;
    /* ONE node session for the whole flow (chain id, coins, gas price,
     * submission) — dry run included */
    nodus_client_t client;
    int connected = 0;
    memset(&client, 0, sizeof(client));

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    n_keys = act_load_keys(keys_csv, keys, 4);
    if (n_keys != 1) {
        fprintf(stderr, "v2-envelope %s needs exactly one --keys identity\n",
                verb);
        goto done;
    }

    /* SYSTEM + CORE ruleset from the compiled table — the registry a
     * version-3 chain is seeded with (cli_builtin_runtime's own comment). */
    const nodus_domain_runtime_t *sys_rt  = cli_builtin_runtime(DNA_DOMAIN_SYSTEM, NODUS_RT_GEN_1);
    const nodus_domain_runtime_t *core_rt = cli_builtin_runtime(DNA_DOMAIN_CORE, NODUS_RT_GEN_1);
    if (!sys_rt || !core_rt) {
        fprintf(stderr, "SYSTEM / CORE runtime not found in the compiled "
                "production table\n");
        goto done;
    }

    /* Staker fingerprint (128 lowercase hex) — the dnac_utxo owner key and
     * the change-output owner. */
    uint8_t staker_raw[64];
    char staker_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, staker_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(staker_raw, staker_fp);

    /* ── ONE session, authenticated as the staker ─────────────────── */
    {
        char sip[64];
        uint16_t sport = 0;
        if (t6_resolve_target(submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target (and no -s server)\n");
            goto done;
        }
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
        cfg.servers[0].port = sport;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &keys[0]) != 0) {
            fprintf(stderr, "client_init failed\n");
            goto done;
        }
        connected = 1;                      /* init succeeded: close owed */
        if (nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
            goto done;
        }
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    {
        bool has_chain32 = false;
        if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
            !has_chain32) {
            fprintf(stderr, "this node is not on a version-3 chain (no "
                    "chain_id32 in its dnac_supply reply) — v2-envelope "
                    "%s needs a version-3 chain\n", verb);
            goto done;
        }
    }
    /* HF-4: build for the generation the node names */
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;

    /* `unstake`: the validator's own row, read on this session. The chain
     * decides (rtn_unstake_exec); the CLI refuses only a status the chain
     * would reject, and never on account of delegations — a validator
     * with delegators may exit (tokenomics-v3 P3-4, Rule A removed). */
    if (is_unstake) {
        nodus_dnac_validator_list_entry_t vrow;
        memset(&vrow, 0, sizeof(vrow));
        const int vr = cli_validator_row(&client, keys[0].pk.bytes, &vrow);
        if (vr == 1 && vrow.status != (uint8_t)DNAC_VALIDATOR_ACTIVE &&
            vrow.status != (uint8_t)DNAC_VALIDATOR_ELIGIBLE) {
            fprintf(stderr, "this validator is %s — the chain accepts an "
                    "unstake only from an ACTIVE or ELIGIBLE validator (a "
                    "repeated unstake is rejected); nothing built\n",
                    cli_validator_status_name(vrow.status));
            goto done;
        }
        if (vr == 1)
            printf("validator %s, bond %llu raw\n",
                   cli_validator_status_name(vrow.status),
                   (unsigned long long)vrow.self_stake);
        else if (vr == 0)
            fprintf(stderr, "warning: this key has no row in the node's "
                    "validator list — the chain rejects an unstake from a "
                    "key that is not a validator\n");
        else
            fprintf(stderr, "warning: the node's validator list could not "
                    "be read — status and delegations not checked here; "
                    "the chain decides\n");
        if (vr == 1 && vrow.total_delegated == 0)
            printf("  - delegations: none to this validator\n");
        else if (vr == 1)
            printf("  - delegations: %llu raw delegated to this validator "
                   "(its own self-delegation included) is returned to the "
                   "delegators when it graduates, locked %d epochs\n",
                   (unsigned long long)vrow.total_delegated,
                   (int)DNAC_UNDELEGATE_LOCK_EPOCHS);
        else
            printf("  - delegations: any delegation to this validator is "
                   "returned to its delegator when it graduates, locked %d "
                   "epochs\n", (int)DNAC_UNDELEGATE_LOCK_EPOCHS);
        printf("  - bond: returned to the unstake destination recorded "
               "when it staked, locked %d epochs after it graduates\n",
               (int)DNAC_VALIDATOR_UNBOND_EPOCHS);
        printf("  - keep this node running until the exit takes effect: it "
               "stays in the validator set until the set change after it "
               "leaves, and graduates at the first epoch boundary whose "
               "new validator set no longer includes it\n");
        fflush(stdout);
    }

    /* HF-1 — the gas price (decision 2026-09-25-gas-price.md "HF-1 O4":
     * the CLI price source is dnac_fee_info's gas_price), read on this
     * session; the builder pays max(floor, NODUS_V2_STAKE_UNITS ×
     * gas_price). An older server sends no gas_price key → 0 → the flat
     * floor, exactly as before HF-1. A failed query is not "price 0":
     * refuse. */
    uint64_t gas_price = 0;
    {
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        int frc = nodus_client_dnac_fee_info(&client, &fi);
        if (frc != 0) {
            fprintf(stderr, "dnac_fee_info query failed (rc=%d) — the gas "
                    "price is unknown, refusing to size a fee\n", frc);
            goto done;
        }
        gas_price = fi.gas_price;
    }

    /* The staker's CORE coins and the committed tip (dnac_utxo answers
     * only for the session's own fingerprint, and CORE rows only —
     * nodus_witness_handlers.c handle_dnac_utxo, nodus_witness_db.c
     * nodus_witness_utxo_by_owner). */
    {
        int urc = nodus_client_dnac_utxo(&client, staker_fp,
                                         NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
        if (urc != 0) {
            fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
            goto done;
        }
        utxos_valid = 1;
    }
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        /* CHECKTX-P1 round 3: the envelope's expiry is tip-relative; the
         * server's height read is FAIL-OPEN (0 on a fault) — refuse. */
        fprintf(stderr, "the node reported tip 0 (a version-3 chain past "
                "its first block never does; its height read may have "
                "faulted) — refusing to build an envelope whose expiry "
                "would be wrong\n");
        goto done;
    }
    if (utxos.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS)
        fprintf(stderr, "warning: the coin listing is capped at %d rows and "
                "came back full — a node >= 0.25.2 lists the largest coins "
                "first (an older node in no order); smaller coins beyond the "
                "cap are invisible to this selection\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);

    /* The listed coins, as the builder takes them; it applies the filter
     * (zero amount, non-native, unlock_block > tip) and the selection. */
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    for (int i = 0; i < utxos.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        memcpy(coins[i].nul, e->nullifier, 64);
        coins[i].amount = e->amount;
        memcpy(coins[i].token, e->token_id, 64);
        coins[i].unlock_block = e->unlock_block;
    }

    nodus_v2_stake_ruleset_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.sys_ruleset_version  = sys_rt->ruleset_version;
    memcpy(rs.sys_ruleset_hash, sys_rt->ruleset_hash, 64);
    rs.core_ruleset_version = core_rt->ruleset_version;
    memcpy(rs.core_ruleset_hash, core_rt->ruleset_hash, 64);

    nodus_v2_stake_req_t sreq;
    memset(&sreq, 0, sizeof(sreq));
    sreq.rs             = &rs;
    sreq.op             = op;
    sreq.chain32        = chain32;
    sreq.tip            = tip;
    /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md 1):
     * expiry within (tip, tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD], with the
     * gossip margin (CLI_ENV_EXPIRY_AHEAD). `tip` is the node's own
     * committed tip from the dnac_utxo reply; a 0 tip was refused above. */
    if (cli_env_expiry(tip, &sreq.expiry_height) != 0) goto done;
    sreq.pk             = keys[0].pk.bytes;
    sreq.sk             = keys[0].sk.bytes;
    sreq.amount         = bond;
    sreq.commission_bps = commission;
    sreq.dest_fp        = is_stake ? dest_fp : NULL;
    sreq.validator_pk   = is_deleg ? validator_pk : NULL;
    sreq.gas_price      = gas_price;
    sreq.coins          = coins;
    sreq.n_coins        = utxos.count;

    /* Sign each leg's auth_digest with the staker sk (kind-1: count=1 ‖
     * pubkey ‖ sig). One key covers BOTH legs: it is the record identity
     * AND the owner of the funding inputs. */
    {
        nodus_v2_stake_err_t se;
        memset(&se, 0, sizeof(se));
        int brc = nodus_v2_stake_build(&sreq, &built, &se);
        if (brc == NODUS_V2_SPEND_ERR_INSUFFICIENT &&
            (is_undeleg || is_unstake)) {
            /* UNDELEGATE's and UNSTAKE's funding leg pays the fee only */
            fprintf(stderr, "insufficient native funding for the fee: have "
                    "%llu, need %llu over %d input(s)\n",
                    (unsigned long long)se.sum_in,
                    (unsigned long long)se.need, se.n_in);
            goto done;
        }
        if (brc == NODUS_V2_SPEND_ERR_INSUFFICIENT) {
            fprintf(stderr, "insufficient native funding: have %llu, need "
                    "%llu (%s %llu + fee %llu) over %d input(s)\n",
                    (unsigned long long)se.sum_in,
                    (unsigned long long)se.need,
                    is_deleg ? "amount" : "bond",
                    (unsigned long long)bond,
                    (unsigned long long)se.fee, se.n_in);
            goto done;
        }
        if (brc == NODUS_V2_SPEND_ERR_GAS_OVERFLOW) {
            fprintf(stderr, "units %llu x gas price %llu overflows u64 — "
                    "no fee can pay it\n", (unsigned long long)se.units,
                    (unsigned long long)se.gas_price);
            goto done;
        }
        if (brc != NODUS_V2_SPEND_OK) {
            const char *why =
                brc == NODUS_V2_SPEND_ERR_OVERFLOW   ? "bond+fee overflow"
              : brc == NODUS_V2_SPEND_ERR_INPUT_SUM  ? "the funding input sum "
                                                       "overflows u64"
              : brc == NODUS_V2_SPEND_ERR_PREFLIGHT1 ? "pass-1 preflight failed"
              : brc == NODUS_V2_SPEND_ERR_SIGN       ? "signature failed"
              : brc == NODUS_V2_SPEND_ERR_PREFLIGHT2 ? "pass-2 preflight "
                                                       "(self-check) failed"
              : brc == NODUS_V2_SPEND_ERR_DECODE     ? "the built envelope did "
                                                       "not read back as "
                                                       "requested"
              : brc == NODUS_V2_SPEND_ERR_EXPIRY     ? "expiry outside the "
                                                       "mempool window"
              : brc == NODUS_V2_STAKE_ERR_BOND       ? "the bond is not the "
                                                       "self-bond"
              : brc == NODUS_V2_STAKE_ERR_COMMISSION ? "commission above the "
                                                       "maximum"
              : brc == NODUS_V2_STAKE_ERR_AMOUNT     ? "amount out of range"
                                                     : "build failed";
            if (brc == NODUS_V2_SPEND_ERR_SIGN)
                fprintf(stderr, "leg %d %s\n", se.leg, why);
            else
                fprintf(stderr, "%s (rc=%d)\n", why, brc);
            goto done;
        }
    }

    /* Printed on BOTH paths (P2P-PORT F6): the submitted envelope's own
     * intent_id is what a caller waits for — a dry run's may differ (its
     * expiry is tip-relative, see this function's header). */
    if (is_unstake)
        printf("v2-envelope %s: %zu bytes, inputs=%d sum_in=%llu "
               "fee=%llu change=%llu tip=%llu\n", verb, built.env_len,
               built.n_in, (unsigned long long)built.sum_in,
               (unsigned long long)built.fee,
               (unsigned long long)built.change, (unsigned long long)tip);
    else
        printf("v2-envelope %s: %zu bytes, inputs=%d sum_in=%llu "
               "%s=%llu fee=%llu change=%llu tip=%llu\n", verb,
               built.env_len, built.n_in, (unsigned long long)built.sum_in,
               is_deleg ? "amount" : "bond",
               (unsigned long long)bond, (unsigned long long)built.fee,
               (unsigned long long)built.change, (unsigned long long)tip);
    printf("  wire_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.wire_id[b]);
    printf("\n  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.intent_id[b]);
    printf("\n");
    fflush(stdout);
    if (dry_run) {
        printf("  PREFLIGHT SELF-CHECK: OK (2 legs SYSTEM %s + CORE "
               "SYSFUND) — not submitted (--dry-run)\n",
               is_unstake ? "UNSTAKE" : is_undeleg ? "UNDELEGATE"
             : is_deleg   ? "DELEGATE" : "STAKE");
    } else {
        /* on the session the gas price and the coins were read from */
        if (t6_submit_on(&client, &keys[0], built.wire_id, built.env,
                         (uint32_t)built.env_len) != 0)
            goto done;
    }
    rc = 0;

done:
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    free(coins);
    nodus_v2_stake_built_free(&built);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── `storage register | exit | status` — storage reward v1, package
 *    B2b-CLI ─────────────────────────────────────────────────────────
 *
 * Decision docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (registration, the 1M bond and node-key authority STAY);
 * call bytes docs/plans/2026-10-04-storage-reward-bytes.md item 5.
 *
 * `register` / `exit` act for THIS NODE's identity (-i dir) — the key the
 * storage node runs with, as the validator-side `stake` verb does: the
 * exec binds the record to the single signer (rtn_sys_stake_auth, fp ==
 * SHA3-512(node_pk)), so the envelope is signed by the node key and is
 * funded from coins that key owns. They build through the shared builder
 * (nodus_v2_stake_build, ops 7 / 8 — decision 2026-09-25-web-wallet-nodus-
 * send-transport.md "İşlem kurucu": one C builder for CLI and wallet) and,
 * like every `v2-envelope` builder, need an explicit `--dry-run` (build
 * and self-check, submit nothing) or `--submit ip:port`.
 *   register: SYSTEM STORAGE_REGISTER (call node_pk ‖ bond ‖ payee_fp,
 *             bond EXACTLY DNAC_STORAGE_STAKE_MIN, payee = the node's own
 *             fp — the exec's pre-HF-5 rule) + a SYSFUND leg locking the
 *             bond and paying the fee;
 *   exit:     SYSTEM STORAGE_EXIT (call = the node key) + a fee-only
 *             SYSFUND leg; the bond comes back at the next epoch boundary
 *             as one coin to payee_fp, locked DNAC_STORAGE_EXIT_LOCK_EPOCHS
 *             epochs (nodus_witness_v2_storage.c step 3).
 * Both exist only from the GEN_STORAGE rule-set generation; the CLI builds
 * for the generation the node names and refuses below it. Before building
 * it reads the node's registry row (dnac_storage_status) and refuses only
 * what the chain would refuse (register: a row ACTIVE or EXITING; exit: no
 * row, or not ACTIVE); a failed query is a warning — the chain decides.
 *
 * `status [--fp <hex128>]` prints the dnac_storage_status answer for this
 * node's fp (or --fp): the registry row, the frozen-set membership for the
 * current epoch and the eligible segments. The last SETTLED outcome is not
 * recorded on chain (only its fail_streak trace) and is said so. */

static const char *cli_storage_status_name(uint8_t s) {
    return s == DNA_V2_STORAGE_ACTIVE   ? "ACTIVE"
         : s == DNA_V2_STORAGE_EXITING  ? "EXITING"
         : s == DNA_V2_STORAGE_RELEASED ? "RELEASED" : "UNKNOWN";
}

/* One authenticated session as THIS identity on `submit` (or -s).
 * @return 0 (*connected set: close owed) / -1 (reason printed). */
static int cli_storage_session(nodus_client_t *client, int *connected,
                               const char *submit, const char *server_ip,
                               uint16_t server_port) {
    char sip[64];
    uint16_t sport = 0;
    if (t6_resolve_target(submit, server_ip, server_port, sip, &sport) != 0) {
        fprintf(stderr, "invalid --submit target (and no -s server)\n");
        return -1;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
    cfg.servers[0].port = sport;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return -1;
    }
    *connected = 1;
    if (nodus_client_connect(client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
        return -1;
    }
    return 0;
}

static void cli_storage_status_print(const char *fp_hex,
                                     const nodus_dnac_storage_status_t *s) {
    printf("storage node %s\n", fp_hex);
    printf("  committed height %llu\n",
           (unsigned long long)s->committed_height);
    if (!s->found) {
        printf("  registry: not registered\n");
    } else {
        printf("  registry: %s, bond %llu raw, fail_streak %u, registered at "
               "%llu", cli_storage_status_name(s->status),
               (unsigned long long)s->bond, (unsigned)s->fail_streak,
               (unsigned long long)s->registered_height);
        if (s->exit_height != 0)
            printf(", exit requested at %llu",
                   (unsigned long long)s->exit_height);
        printf("\n  payee: %s\n", s->payee);
        if (s->grace_until == 0)
            printf("  grace_until: 0 (never in grace)\n");
        else
            printf("  grace_until: %llu — an epoch starting below it is a "
                   "grace epoch: the node fetches its new segments, is not "
                   "probed and earns nothing\n",
                   (unsigned long long)s->grace_until);
        if (s->epoch_start != 0 && s->epoch_start < s->grace_until)
            printf("  NOTE: IN GRACE this epoch (%llu < %llu) — not "
                   "probed, earns nothing, fail_streak unchanged; %llu "
                   "grace epoch(s) left, this one included\n",
                   (unsigned long long)s->epoch_start,
                   (unsigned long long)s->grace_until,
                   (unsigned long long)(
                       (s->grace_until - s->epoch_start) /
                           (uint64_t)DNAC_EPOCH_LENGTH +
                       ((s->grace_until - s->epoch_start) %
                            (uint64_t)DNAC_EPOCH_LENGTH != 0)));
        if (s->fail_streak >= DNA_V2_STORAGE_FAIL_LIMIT)
            printf("  NOTE: fail_streak >= %u — skipped for segment "
                   "placement until it recovers\n",
                   (unsigned)DNA_V2_STORAGE_FAIL_LIMIT);
    }
    if (s->epoch_start == 0) {
        printf("  frozen storage set: none yet (no epoch boundary)\n");
    } else if (!s->set_exists) {
        printf("  frozen storage set for epoch (%llu, %llu]: none (storage "
               "not active at that boundary)\n",
               (unsigned long long)s->epoch_start,
               (unsigned long long)(s->epoch_start +
                                    (uint64_t)DNAC_EPOCH_LENGTH));
    } else {
        printf("  frozen storage set for epoch (%llu, %llu]: %u member(s), "
               "this node %s\n", (unsigned long long)s->epoch_start,
               (unsigned long long)(s->epoch_start +
                                    (uint64_t)DNAC_EPOCH_LENGTH),
               (unsigned)s->set_count, s->member ? "IS a member"
                                                 : "is NOT a member");
    }
    if (s->member) {
        printf("  eligible segments this epoch: %llu (%llu blocks)",
               (unsigned long long)s->n_segments,
               (unsigned long long)(s->n_segments *
                                    (uint64_t)DNA_V2_SEGMENT_BLOCKS));
        for (size_t i = 0; i < s->n_listed; i++)
            printf("%s%llu", i == 0 ? ": " : ", ",
                   (unsigned long long)s->segments[i]);
        if (s->n_listed < s->n_segments) printf(", …");
        printf("\n");
    }
    printf("  last settled outcome: not recorded on chain — the settlement "
           "keeps no per-node verdict; fail_streak above is its only "
           "trace\n");
}

static int cmd_storage_status(const char *server_ip, uint16_t server_port,
                              int argc, char **argv, int cmd_start,
                              int have_identity) {
    const char *fp_arg = NULL;
    for (int i = cmd_start + 2; i < argc; i++) {
        if (!strcmp(argv[i], "--fp") && i + 1 < argc) fp_arg = argv[++i];
        else {
            fprintf(stderr, "Usage: storage status [--fp <hex128>]\n");
            return 1;
        }
    }
    char fp_hex[129];
    if (fp_arg) {
        uint8_t raw[64];
        if (strlen(fp_arg) != 128 || qgp_fp_hex_to_raw(fp_arg, raw) != 0) {
            fprintf(stderr, "--fp must be exactly 128 lowercase hex chars\n");
            return 1;
        }
        qgp_fp_raw_to_hex(raw, fp_hex);
    } else if (have_identity) {
        snprintf(fp_hex, sizeof(fp_hex), "%s", identity.fingerprint);
    } else {
        fprintf(stderr, "storage status needs the node identity (-i <dir>) "
                "or --fp <hex128>\n");
        return 1;
    }

    int rc = 1, connected = 0;
    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    if (cli_storage_session(&client, &connected, NULL, server_ip,
                            server_port) != 0)
        goto done;
    {
        nodus_dnac_ruleset_info_t ri;
        memset(&ri, 0, sizeof(ri));
        if (nodus_client_dnac_ruleset_info(&client, &ri) == 0)
            printf("rule-set generation %u (storage ops from generation "
                   "%u)\n", (unsigned)ri.generation,
                   (unsigned)NODUS_RT_GEN_STORAGE);
    }
    nodus_dnac_storage_status_t st;
    int qrc = nodus_client_dnac_storage_status(&client, fp_hex, &st);
    if (qrc != 0) {
        fprintf(stderr, "dnac_storage_status failed (rc=%d) — an older node "
                "does not answer it\n", qrc);
        goto done;
    }
    cli_storage_status_print(fp_hex, &st);
    rc = 0;
done:
    if (connected) nodus_client_close(&client);
    return rc;
}

static int cmd_storage_tx(const char *server_ip, uint16_t server_port,
                          int argc, char **argv, int cmd_start,
                          int is_exit) {
    const char *verb = is_exit ? "exit" : "register";
    const char *submit = NULL;
    int dry_run = 0;
    for (int i = cmd_start + 2; i < argc; i++) {
        if (!strcmp(argv[i], "--submit") && i + 1 < argc) submit = argv[++i];
        else if (!strcmp(argv[i], "--dry-run")) dry_run = 1;
        else { submit = NULL; dry_run = 0; break; }
    }
    if (dry_run == (submit != NULL)) {
        fprintf(stderr,
            "Usage: -i <node identity dir> storage %s "
            "(--dry-run | --submit ip:port)\n"
            "  register: bonds exactly %llu raw (1 000 000 NODUS) from coins "
            "the node key owns,\n"
            "            plus the fee; the reward is paid to the node's own "
            "fingerprint.\n"
            "  exit:     the bond comes back at the next epoch boundary, "
            "locked %d epochs.\n"
            "  --dry-run builds and self-checks, submits nothing.\n",
            verb, (unsigned long long)DNAC_STORAGE_STAKE_MIN,
            (int)DNAC_STORAGE_EXIT_LOCK_EPOCHS);
        return 1;
    }

    int rc = 1, connected = 0, utxos_valid = 0;
    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    nodus_v2_stake_coin_t *coins = NULL;
    nodus_v2_stake_built_t built;
    memset(&built, 0, sizeof(built));
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));

    /* the node fingerprint: the registry key, the payee (until HF-5) and
     * the owner of the funding coins */
    uint8_t node_fp[64];
    char node_fp_hex[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(identity.pk.bytes, DNAC_PUBKEY_SIZE, node_fp) != 0)
        return 1;
    qgp_fp_raw_to_hex(node_fp, node_fp_hex);

    if (cli_storage_session(&client, &connected, submit, server_ip,
                            server_port) != 0)
        goto done;

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    {
        bool has_chain32 = false;
        if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
            !has_chain32) {
            fprintf(stderr, "this node is not on a version-3 chain (no "
                    "chain_id32 in its dnac_supply reply)\n");
            goto done;
        }
    }
    /* build for the generation the node names; the storage ops exist only
     * from GEN_STORAGE (rtn_gen_storage) */
    const nodus_domain_runtime_t *sys_rt = NULL, *core_rt = NULL;
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;
    if (g_cli_sel_gen < NODUS_RT_GEN_STORAGE) {
        fprintf(stderr, "the node runs rule-set generation %u — storage "
                "registration exists only from generation %u (the storage "
                "vote has not taken effect); nothing built\n",
                (unsigned)g_cli_sel_gen, (unsigned)NODUS_RT_GEN_STORAGE);
        goto done;
    }

    /* the registry row: refuse only what the chain refuses */
    {
        nodus_dnac_storage_status_t st;
        int qrc = nodus_client_dnac_storage_status(&client, node_fp_hex, &st);
        if (qrc != 0) {
            fprintf(stderr, "warning: dnac_storage_status failed (rc=%d) — "
                    "the registry row is not checked here; the chain "
                    "decides\n", qrc);
        } else if (!is_exit && st.found &&
                   (st.status == DNA_V2_STORAGE_ACTIVE ||
                    st.status == DNA_V2_STORAGE_EXITING)) {
            fprintf(stderr, "this node is already registered (%s) — the "
                    "chain accepts a registration only for a new node or "
                    "one whose bond was RELEASED; nothing built\n",
                    cli_storage_status_name(st.status));
            goto done;
        } else if (is_exit && !st.found) {
            fprintf(stderr, "this node is not registered — nothing to exit; "
                    "nothing built\n");
            goto done;
        } else if (is_exit && st.status != DNA_V2_STORAGE_ACTIVE) {
            fprintf(stderr, "this node is %s — the chain accepts an exit "
                    "only from ACTIVE (a repeated exit is rejected); "
                    "nothing built\n", cli_storage_status_name(st.status));
            goto done;
        } else if (is_exit) {
            printf("storage node ACTIVE, bond %llu raw\n",
                   (unsigned long long)st.bond);
        }
    }

    /* HF-1 gas price (dnac_fee_info) — a failed query is not "price 0" */
    uint64_t gas_price = 0;
    {
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        int frc = nodus_client_dnac_fee_info(&client, &fi);
        if (frc != 0) {
            fprintf(stderr, "dnac_fee_info query failed (rc=%d) — the gas "
                    "price is unknown, refusing to size a fee\n", frc);
            goto done;
        }
        gas_price = fi.gas_price;
    }

    /* the node key's CORE coins and the committed tip */
    {
        int urc = nodus_client_dnac_utxo(&client, node_fp_hex,
                                         NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
        if (urc != 0) {
            fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
            goto done;
        }
        utxos_valid = 1;
    }
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        fprintf(stderr, "the node reported tip 0 (its height read may have "
                "faulted) — refusing to build an envelope whose expiry "
                "would be wrong\n");
        goto done;
    }
    if (utxos.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS)
        fprintf(stderr, "warning: the coin listing is capped at %d rows and "
                "came back full — coins beyond it are invisible to this "
                "selection\n", (int)NODUS_DNAC_MAX_UTXO_RESULTS);
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    for (int i = 0; i < utxos.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        memcpy(coins[i].nul, e->nullifier, 64);
        coins[i].amount = e->amount;
        memcpy(coins[i].token, e->token_id, 64);
        coins[i].unlock_block = e->unlock_block;
    }

    nodus_v2_stake_ruleset_t rs;
    memset(&rs, 0, sizeof(rs));
    rs.sys_ruleset_version  = sys_rt->ruleset_version;
    memcpy(rs.sys_ruleset_hash, sys_rt->ruleset_hash, 64);
    rs.core_ruleset_version = core_rt->ruleset_version;
    memcpy(rs.core_ruleset_hash, core_rt->ruleset_hash, 64);

    nodus_v2_stake_req_t sreq;
    memset(&sreq, 0, sizeof(sreq));
    sreq.rs        = &rs;
    sreq.op        = is_exit ? NODUS_V2_STAKE_OP_STORAGE_EXIT
                             : NODUS_V2_STAKE_OP_STORAGE_REGISTER;
    sreq.chain32   = chain32;
    sreq.tip       = tip;
    if (cli_env_expiry(tip, &sreq.expiry_height) != 0) goto done;
    sreq.pk        = identity.pk.bytes;
    sreq.sk        = identity.sk.bytes;
    sreq.amount    = is_exit ? 0 : DNAC_STORAGE_STAKE_MIN;
    sreq.dest_fp   = is_exit ? NULL : node_fp;   /* payee = own fp */
    sreq.gas_price = gas_price;
    sreq.coins     = coins;
    sreq.n_coins   = utxos.count;
    {
        nodus_v2_stake_err_t se;
        memset(&se, 0, sizeof(se));
        int brc = nodus_v2_stake_build(&sreq, &built, &se);
        if (brc == NODUS_V2_SPEND_ERR_INSUFFICIENT) {
            if (is_exit)
                fprintf(stderr, "insufficient native funding for the fee on "
                        "the node key: have %llu, need %llu over %d "
                        "input(s)\n", (unsigned long long)se.sum_in,
                        (unsigned long long)se.need, se.n_in);
            else
                fprintf(stderr, "insufficient native funding on the node key "
                        "%.16s…: have %llu, need %llu (bond %llu + fee %llu) "
                        "over %d input(s) — fund it first\n", node_fp_hex,
                        (unsigned long long)se.sum_in,
                        (unsigned long long)se.need,
                        (unsigned long long)DNAC_STORAGE_STAKE_MIN,
                        (unsigned long long)se.fee, se.n_in);
            goto done;
        }
        if (brc == NODUS_V2_SPEND_ERR_GAS_OVERFLOW) {
            fprintf(stderr, "units %llu x gas price %llu overflows u64 — "
                    "no fee can pay it\n", (unsigned long long)se.units,
                    (unsigned long long)se.gas_price);
            goto done;
        }
        if (brc != NODUS_V2_SPEND_OK) {
            const char *why =
                brc == NODUS_V2_SPEND_ERR_OVERFLOW   ? "bond+fee overflow"
              : brc == NODUS_V2_SPEND_ERR_INPUT_SUM  ? "the funding input sum "
                                                       "overflows u64"
              : brc == NODUS_V2_SPEND_ERR_PREFLIGHT1 ? "pass-1 preflight failed"
              : brc == NODUS_V2_SPEND_ERR_SIGN       ? "signature failed"
              : brc == NODUS_V2_SPEND_ERR_PREFLIGHT2 ? "pass-2 preflight "
                                                       "(self-check) failed"
              : brc == NODUS_V2_SPEND_ERR_DECODE     ? "the built envelope did "
                                                       "not read back as "
                                                       "requested"
              : brc == NODUS_V2_SPEND_ERR_EXPIRY     ? "expiry outside the "
                                                       "mempool window"
              : brc == NODUS_V2_STAKE_ERR_STORAGE_BOND ? "the bond is not the "
                                                       "storage bond"
              : brc == NODUS_V2_STAKE_ERR_PAYEE      ? "the payee is not the "
                                                       "node's own fingerprint"
                                                     : "build failed";
            if (brc == NODUS_V2_SPEND_ERR_SIGN)
                fprintf(stderr, "leg %d %s\n", se.leg, why);
            else
                fprintf(stderr, "%s (rc=%d)\n", why, brc);
            goto done;
        }
    }

    /* what will be sent */
    printf("storage %s for node %s\n", verb, node_fp_hex);
    if (is_exit) {
        printf("  - the node leaves the storage set at the next epoch "
               "boundary and earns nothing after it\n");
        printf("  - the bond is returned to the payee at that boundary as one "
               "coin, locked %d epochs\n", (int)DNAC_STORAGE_EXIT_LOCK_EPOCHS);
    } else {
        printf("  - bond: %llu raw (1 000 000 NODUS), locked until an exit "
               "is released\n", (unsigned long long)DNAC_STORAGE_STAKE_MIN);
        printf("  - payee: %s (the node's own fingerprint — the only payee "
               "the chain accepts before HF-5)\n", node_fp_hex);
        printf("  - the node joins the storage set frozen at the next epoch "
               "boundary; keep the archive (retain_blocks 0) and the 4004 "
               "connections to the validators\n");
    }
    printf("v2-envelope storage-%s: %zu bytes, inputs=%d sum_in=%llu "
           "fee=%llu change=%llu tip=%llu\n", verb, built.env_len,
           built.n_in, (unsigned long long)built.sum_in,
           (unsigned long long)built.fee, (unsigned long long)built.change,
           (unsigned long long)tip);
    printf("  wire_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.wire_id[b]);
    printf("\n  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.intent_id[b]);
    printf("\n");
    fflush(stdout);
    if (dry_run) {
        printf("  PREFLIGHT SELF-CHECK: OK (2 legs SYSTEM %s + CORE "
               "SYSFUND) — not submitted (--dry-run)\n",
               is_exit ? "STORAGE_EXIT" : "STORAGE_REGISTER");
    } else if (t6_submit_on(&client, &identity, built.wire_id, built.env,
                            (uint32_t)built.env_len) != 0) {
        goto done;
    }
    rc = 0;

done:
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    free(coins);
    nodus_v2_stake_built_free(&built);
    return rc;
}

/* ── `v2-envelope spend` — the CORE SPEND builder (nodus/BUGS.md, top
 *    entry: "TESTNET BLOCKER: no client can build a coin TRANSFER") ────
 *
 * Builds a single-leg DNA_CORE envelope, runtime_op 1
 * (DNA_CORERULE_SPEND), auth_kind 1 (the sender's ML-DSA-87 signature
 * over the leg auth digest), fee in the envelope. The chain side is the
 * SPECIFICATION (nodus_witness_rt_native.c): call v1 = in_count u8
 * (1..15) ‖ nullifiers strictly ascending ‖ out_count u8 (1..16) ‖
 * out_count × 232-byte records (rtn_xfer_section_parse :1098-1125,
 * rtn_spend_parse :1129-1138); exec (rtn_xfer_exec :1589-1702) requires
 * every input present and UNLOCKED (unlock_block < H, :1617), owned by a
 * verified signer (:1619-1623), per-token exact conservation with the
 * native token paying the fee (:1646-1656), the fee at or above BOTH
 * DNAC_MIN_FEE_RAW and NODUS_W_BASE_TX_FEE (:1642), and unique output
 * ids SHA3-512(owner_hex ‖ seed) (:1424-1446).
 *
 * EVERYTHING COMES FROM THE NETWORK, so a remote client can spend: the
 * whole flow runs on ONE session authenticated AS THE SENDER (dnac_utxo
 * answers only for the session's own fingerprint —
 * nodus_witness_handlers.c handle_dnac_utxo, "owner must match
 * authenticated session fingerprint"):
 *   - chain id: dnac_supply's chain_id32 (w->v2_chain32, the SAME value
 *     CheckTx's nodus_witness_v2_chain_id resolves on a version-3 chain);
 *   - CORE ruleset: the compiled table (cli_builtin_runtime — the
 *     `chain-config propose` precedent);
 *   - the sender's coins: dnac_utxo (nullifier, amount, token, "ub" =
 *     unlock_block) plus its block_height = the committed tip
 *     (nodus_witness_block_height reads v2_blocks on a version-3 chain).
 *
 * SELECTION is deterministic over what the RPC returned: coins with
 * unlock_block > tip are skipped (the chain rejects unlock >= H and
 * H >= tip + 1), then largest amount first, ties by nullifier ascending;
 * the chosen nullifiers are re-sorted ascending for the wire. A native
 * spend draws amount + fee from native coins; a --token spend draws the
 * amount from that token's coins and the fee from native coins. Change
 * goes back to the sender, one output per token that has any. Output
 * seeds are 32 fresh random bytes each (nodus_random) — client-side
 * only: consensus never derives a seed, it only hashes the one it is
 * given, and a duplicate output id is a deterministic reject
 * (rt_native.c:1443-1445), not a split.
 *
 * --count N plans N INDEPENDENT spends with DISJOINT input sets from ONE
 * coin listing and submits them on the same session — the only way one
 * identity can have more than one spend in flight at once, because the
 * RPC lists COMMITTED coins only and a second query before the first
 * spend commits would select the same coin again. Every envelope is
 * planned before anything is submitted, so a shortfall refuses the whole
 * batch without sending any of it.
 *
 * --shard I/M lets M SEPARATE sessions of the same identity keep spends
 * in flight at once without ever selecting the same coin. The shard is a
 * property of the COIN, not of its position in a listing: a coin belongs
 * to shard (first 8 nullifier bytes as a big-endian u64) mod M. A rank
 * in the selection order would NOT do — the listing is capped at 100 rows
 * (largest first since node 0.25.2, unordered before —
 * nodus_witness_db.c nodus_witness_utxo_by_owner), each
 * session lists at a different moment and from a different node, and
 * every committed spend replaces a coin with a smaller one under a fresh
 * nullifier, so the same rank names different coins in two listings. A
 * nullifier is SHA3-512(owner_hex ‖ seed) (rtn_out_ids,
 * nodus_witness_rt_native.c:1463-1475), so with --shard every output
 * this envelope creates has its seed re-drawn until its id lands in the
 * SAME shard (expected M draws; the seed is client-chosen and consensus
 * only hashes it) — each shard's coin set is then closed: a session
 * never sees, and can never select, a coin another shard's session
 * created or is spending.
 *
 * --amount all sends each selected coin's WHOLE value minus the fee:
 * exactly one native input and one output per spend, no change and no
 * dust, however unevenly the coins have shrunk. --count all (only with
 * --amount all) plans one such spend per eligible coin (native, unlocked,
 * in the shard, amount > fee); zero eligible coins prints a line saying
 * so and submits nothing (exit 0).
 *
 * Fee: default max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) — the stake
 * builder's rule — raised, once HF-1's gas price is active, to
 * units × gas_price of the batch's largest spend (gas_price read from
 * dnac_fee_info on the same session; decision 2026-09-25-gas-price.md).
 * An explicit --fee below that is refused, never raised. Per the
 * operator's tokenomics decision
 * (docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md §1)
 * fees belong to the reward pool, and since tokenomics-v3 P2 the chain
 * credits them there (rtn_xfer_exec's pool SET, nodus_witness_rt_native.c
 * rtn_supply_add_eff with RTN_SUPPLY_SEL_POOL). This client only pays
 * the fee; where it goes is the chain's rule, not this builder's.
 *
 * Resource fields: res_max_effects / res_max_effect_bytes are the EXACT
 * effect count and canonical result length THIS envelope's SPEND leg
 * emits (nodus_v2_spend_effect_decl — derived from rtn_xfer_exec and the
 * effect_wire.h layout, pinned by test_v2_native.c
 * test_spend_effect_decl), not the old flat 40 / 16 384 sized for the
 * 15-input maximum (16 384 of a 1-in/1-out spend's 23 946 units).
 * res_max_total_units is RIGHT-SIZED per envelope from that declaration
 * (nodus_v2_spend_ceiling), NOT a round number: PrepareProposal's capacity
 * seam reserves EVERY envelope's full ceiling against ONE block budget
 * at once, without finalizing in between (nodus_witness_cmt_app.c
 * app_seam_check → nodus_witness_v2_produce.c :269 →
 * nodus_witness_v2_env.c :382 "Step 5 — sequential reservation";
 * NODUS_V2_GLOBAL_UNIT_BUDGET = 2 097 152 — trial B, operator
 * 2026-09-24 — nodus_witness_v2_apply.h:298), so the ceiling IS the
 * per-block envelope count: 8 221 units for a 1-in/1-out spend
 * (ARITHMETIC, all weights 1) → at most 255 per block; a round 200 000
 * (the test precedent) would admit ten spends per block, 400 000 (the
 * stake builder) five. That is the rule BELOW the HF-3 height (chain_
 * config param 8, DNAC_CFG_HF3_ACTIVE): from it the global budget and
 * every quota-0 domain's budget are unbounded (res_meter.h unbounded
 * flags), so the ceiling no longer caps the per-block count — it stays
 * the fee base (units × price) and must be ≤ INT64_MAX.
 *
 * The plan and the build themselves are the shared SPEND builder
 * (nodus/src/client/nodus_v2_spend.c, web wallet package (c2)):
 * nodus_v2_spend_plan (selection + the gas-price fixed point) and
 * nodus_v2_spend_build (call, leg, units, two-pass signature, read-back).
 * This command reads the network, prints, and submits.
 */
static int cmd_v2_spend_msig(const char *server_ip, uint16_t server_port,
                             int argc, char **argv, int cmd_start);

static int cmd_v2_spend(const char *server_ip, uint16_t server_port,
                        int argc, char **argv, int cmd_start) {
    /* general multisig: `--msig <descriptor>` selects the offline M-of-N
     * builder (a different coin source and no signature here — see the
     * "General multisig" block below) */
    for (int i = cmd_start + 2; i < argc; i++)
        if (!strcmp(argv[i], "--msig"))
            return cmd_v2_spend_msig(server_ip, server_port, argc, argv,
                                     cmd_start);
    const char *keys_csv = NULL, *to_hex = NULL, *token_hex = NULL;
    const char *submit = NULL;
    uint64_t amount = 0, fee = 0;
    long count = 1;
    unsigned long shard_i = 0, shard_m = 1;          /* 1 = no sharding    */
    int dry_run = 0, have_amount = 0, have_fee = 0, bad_arg = 0;
    int amount_all = 0, count_all = 0, no_dust_sweep = 0;

    for (int i = cmd_start + 2; i < argc; i++) {   /* skip the "spend" word */
        const char *a = argv[i];
        if      (!strcmp(a, "--keys")   && i + 1 < argc) keys_csv  = argv[++i];
        else if (!strcmp(a, "--to")     && i + 1 < argc) to_hex    = argv[++i];
        else if (!strcmp(a, "--token")  && i + 1 < argc) token_hex = argv[++i];
        else if (!strcmp(a, "--submit") && i + 1 < argc) submit    = argv[++i];
        else if (!strcmp(a, "--amount") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "all")) amount_all = 1;
            else amount = strtoull(v, NULL, 10);
            have_amount = 1;
        } else if (!strcmp(a, "--fee") && i + 1 < argc) {
            fee = strtoull(argv[++i], NULL, 10); have_fee = 1;
        } else if (!strcmp(a, "--count") && i + 1 < argc) {
            const char *v = argv[++i];
            if (!strcmp(v, "all")) count_all = 1;
            else count = strtol(v, NULL, 10);
        } else if (!strcmp(a, "--shard") && i + 1 < argc) {
            /* strict "I/M": digits, one '/', digits, nothing else */
            const char *v = argv[++i];
            char *e1 = NULL, *e2 = NULL;
            if (v[0] < '0' || v[0] > '9') { bad_arg = 1; break; }
            shard_i = strtoul(v, &e1, 10);
            if (!e1 || *e1 != '/' || e1[1] < '0' || e1[1] > '9') {
                bad_arg = 1; break;
            }
            shard_m = strtoul(e1 + 1, &e2, 10);
            if (!e2 || *e2 != '\0') { bad_arg = 1; break; }
        } else if (!strcmp(a, "--dry-run")) {
            dry_run = 1;
        } else if (!strcmp(a, "--no-dust-sweep")) {
            no_dust_sweep = 1;
        } else { bad_arg = 1; break; }
    }
    if (bad_arg || !keys_csv || !to_hex || !have_amount) {
        fprintf(stderr,
            "Usage: v2-envelope spend --keys <keydir> --to <fp128hex> "
            "--amount <raw|all>\n"
            "       [--fee <raw>] [--token <hex128>] [--count <N|all>] "
            "[--shard <I>/<M>]\n"
            "       [--no-dust-sweep] [--submit ip:port] [--dry-run]\n"
            "  The whole flow (chain id, coin listing, submission) runs on "
            "ONE session\n"
            "  to --submit, or to the outer -s server when --submit is "
            "absent.\n"
            "  --dry-run still needs that node (it lists the coins); it "
            "builds and\n"
            "  self-checks every envelope and submits none.\n"
            "  --amount all   each spend sends ONE native coin's whole "
            "value minus the\n"
            "                 fee (1 input, 1 output, no change); not with "
            "--token.\n"
            "  --count all    one spend per eligible coin (needs --amount "
            "all); none\n"
            "                 eligible = nothing submitted, exit 0.\n"
            "  --shard I/M    select only coins whose nullifier's first 8 "
            "bytes (BE u64)\n"
            "                 mod M == I, and re-draw every output seed "
            "until the new\n"
            "                 coin's id lands in the same shard — M "
            "sessions of one\n"
            "                 identity with distinct I never share a coin "
            "(0 <= I < M <= %d).\n"
            "  --no-dust-sweep  a single spend adds NO extra small native "
            "coins and keeps\n"
            "                 a small change output (default: both on — the "
            "plan sweeps\n"
            "                 the smallest native coins in and drops change "
            "not worth\n"
            "                 spending; nodus_v2_spend_plan).\n"
            "  Every envelope declares the EXACT effects its SPEND leg "
            "emits: res_max_effects\n"
            "  = inputs + outputs + 1 (the reward-pool fee SET), "
            "res_max_effect_bytes =\n"
            "  116 + 148*inputs + 432*outputs; res_max_total_units is "
            "sized from that\n"
            "  (printed as effects= / effect_bytes= / units=).\n"
            "  Fee: default the chain floor; when the node reports a gas "
            "price > 0\n"
            "  (dnac_fee_info gas_price), max(floor, units x gas_price) of "
            "the batch's\n"
            "  largest spend. A --fee below that is refused.\n",
            (int)NODUS_DNAC_MAX_UTXO_RESULTS);
        return 1;
    }
    if (shard_m < 1 || shard_m > (unsigned long)NODUS_DNAC_MAX_UTXO_RESULTS ||
        shard_i >= shard_m) {
        fprintf(stderr, "--shard I/M needs 1 <= M <= %d and 0 <= I < M\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);
        return 1;
    }
    if (amount_all && token_hex) {
        fprintf(stderr, "--amount all spends whole NATIVE coins; it cannot "
                "be combined with --token\n");
        return 1;
    }
    if (count_all && !amount_all) {
        fprintf(stderr, "--count all needs --amount all (a fixed amount has "
                "no per-coin count)\n");
        return 1;
    }

    /* ── argument verdicts: refuse what the chain would refuse ────────── */
    uint8_t to_raw[64];
    if (qgp_fp_hex_to_raw(to_hex, to_raw) != 0) {
        fprintf(stderr, "--to must be exactly 128 lowercase hex chars (a "
                "fingerprint; the output owner field is checked by "
                "rtn_hex_lower_ok)\n");
        return 1;
    }
    if (!amount_all && amount == 0) {
        fprintf(stderr, "--amount must be >= 1 (a zero-value output is a "
                "deterministic reject on the chain)\n");
        return 1;
    }
    const uint64_t fee_floor = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                             ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
    if (!have_fee) fee = fee_floor;
    if (fee < DNAC_MIN_FEE_RAW || fee < NODUS_W_BASE_TX_FEE) {
        fprintf(stderr, "--fee %llu is below the chain's floor %llu "
                "(DNAC_MIN_FEE_RAW %llu, NODUS_W_BASE_TX_FEE %llu)\n",
                (unsigned long long)fee, (unsigned long long)fee_floor,
                (unsigned long long)DNAC_MIN_FEE_RAW,
                (unsigned long long)NODUS_W_BASE_TX_FEE);
        return 1;
    }
    /* A batch needs one listed coin per envelope at least, and the
     * listing is capped at NODUS_DNAC_MAX_UTXO_RESULTS rows. --count all
     * is resolved after the listing (below). */
    if (!count_all && (count < 1 || count > (long)NODUS_DNAC_MAX_UTXO_RESULTS)) {
        fprintf(stderr, "--count must be 1..%d\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);
        return 1;
    }
    static const uint8_t native_tok[64] = {0};
    uint8_t token[64];
    memset(token, 0, sizeof(token));
    if (token_hex && qgp_fp_hex_to_raw(token_hex, token) != 0) {
        /* same 64-byte lowercase-hex shape as a fingerprint */
        fprintf(stderr, "--token must be exactly 128 lowercase hex chars "
                "(a 64-byte token id)\n");
        return 1;
    }
    const int is_native = memcmp(token, native_tok, 64) == 0;
    if (is_native && amount > UINT64_MAX - fee) {
        fprintf(stderr, "amount + fee overflows u64\n");
        return 1;
    }

    int rc = 1;
    nodus_identity_t *keys = NULL;
    nodus_v2_coin_t *coins = NULL;
    nodus_v2_spend_plan_t *plans = NULL;
    nodus_v2_spend_built_t built;
    memset(&built, 0, sizeof(built));
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    int utxos_valid = 0, connected = 0;
    nodus_client_t client;
    memset(&client, 0, sizeof(client));

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    if (act_load_keys(keys_csv, keys, 4) != 1) {
        fprintf(stderr, "v2-envelope spend needs exactly one --keys identity\n");
        goto done;
    }

    /* Sender fingerprint (128 lowercase hex): the utxo_set owner form and
     * the dnac_utxo query key (the builder derives the same value for
     * every change output's owner from the same public key). */
    uint8_t sender_raw[64];
    char sender_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, sender_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(sender_raw, sender_fp);

    const nodus_domain_runtime_t *core_rt = cli_builtin_runtime(DNA_DOMAIN_CORE, NODUS_RT_GEN_1);
    const nodus_domain_runtime_t *sys_rt  = cli_builtin_runtime(DNA_DOMAIN_SYSTEM, NODUS_RT_GEN_1);
    if (!core_rt || !sys_rt || !sys_rt->meter_policy) {
        fprintf(stderr, "CORE runtime / SYSTEM block metering policy not "
                "found in the compiled production table\n");
        goto done;
    }
    nodus_v2_ruleset_id_t rs;
    cli_ruleset_id(core_rt, sys_rt, &rs);

    /* ── ONE session, authenticated as the sender ──────────────────── */
    char sip[64];
    uint16_t sport = 0;
    if (t6_resolve_target(submit, server_ip, server_port, sip, &sport) != 0) {
        fprintf(stderr, "invalid --submit target (and no -s server)\n");
        goto done;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
    cfg.servers[0].port = sport;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(&client, &cfg, &keys[0]) != 0) {
        fprintf(stderr, "client_init failed\n");
        goto done;
    }
    connected = 1;                          /* init succeeded: close owed */
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
        goto done;
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    bool has_chain32 = false;
    if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
        !has_chain32) {
        fprintf(stderr, "this node is not on a version-3 chain (no "
                "chain_id32 in its dnac_supply reply) — v2-envelope spend "
                "needs a version-3 chain\n");
        goto done;
    }
    /* HF-4: build for the generation the node names */
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;
    cli_ruleset_id(core_rt, sys_rt, &rs);

    /* HF-1 — the committed gas price at tip + 1, on the SAME session
     * (decision 2026-09-25-gas-price.md "HF-1 O4": the CLI price source
     * is dnac_fee_info's gas_price). An older server sends no key and
     * the decoder leaves 0 = the rule is off; the fee then stays exactly
     * what it was before HF-1. A failed query is not "price 0": refuse. */
    uint64_t gas_price = 0;
    {
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        int frc = nodus_client_dnac_fee_info(&client, &fi);
        if (frc != 0) {
            fprintf(stderr, "dnac_fee_info query failed (rc=%d) — the gas "
                    "price is unknown, refusing to size a fee\n", frc);
            goto done;
        }
        gas_price = fi.gas_price;
    }

    int urc = nodus_client_dnac_utxo(&client, sender_fp,
                                     NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
    if (urc != 0) {
        fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
        goto done;
    }
    utxos_valid = 1;
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        /* The server fills block_height from its FAIL-OPEN accessor
         * (nodus_witness_handlers.c handle_dnac_utxo →
         * nodus_witness_db.c nodus_witness_block_height: 0 on a read
         * fault). CHECKTX-P1 round 3: the envelope's expiry is anchored
         * on this tip, so a 0 would build an envelope every node refuses
         * (or that dies at once) — refuse instead of warning. */
        fprintf(stderr, "the node reported tip 0 (a version-3 chain past "
                "its first block never does; its height read may have "
                "faulted) — refusing to build an envelope whose expiry "
                "would be wrong\n");
        goto done;
    }
    if (utxos.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS)
        fprintf(stderr, "warning: the coin listing is capped at %d rows and "
                "came back full — a node >= 0.25.2 lists the largest coins "
                "first (an older node in no order); smaller coins beyond the "
                "cap are invisible to this selection\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);

    /* ── the spendable coin set, in the deterministic selection order ── */
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    int n_coins = 0, n_locked = 0, n_other_shard = 0;
    for (int i = 0; i < utxos.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        if (e->amount == 0) continue;         /* never selectable value   */
        if (shard_m > 1) {                    /* the coin's OWN shard     */
            uint64_t key = 0;
            for (int b = 0; b < 8; b++) key = (key << 8) | e->nullifier[b];
            if (key % shard_m != shard_i) { n_other_shard++; continue; }
        }
        if (e->unlock_block > tip) { n_locked++; continue; }
        nodus_v2_coin_t *c = &coins[n_coins++];
        memcpy(c->nul, e->nullifier, 64);
        c->amount = e->amount;
        if (memcmp(e->token_id, native_tok, 64) == 0) c->kind = 0;
        else if (!is_native && memcmp(e->token_id, token, 64) == 0) c->kind = 1;
        else c->kind = 2;
        c->used = 0;
    }

    /* ── plan EVERY envelope before submitting ANY — and, under HF-1,
     * find the fee the plan needs (nodus_v2_spend_plan: largest first,
     * ties by nullifier; the bounded gas-price fixed point, one fee for
     * the whole batch; gas_price 0 = one pass, nothing priced). An
     * explicit --fee is never raised: below what the plan needs, it is
     * refused here with the numbers, before anything is submitted. */
    {
        nodus_v2_spend_plan_req_t preq;
        memset(&preq, 0, sizeof(preq));
        preq.rs         = &rs;
        preq.order      = NODUS_V2_SPEND_ORDER_LARGEST_FIRST;
        preq.is_native  = is_native;
        preq.amount     = amount;
        preq.amount_all = amount_all;
        preq.fee        = fee;
        preq.fee_fixed  = have_fee;
        preq.gas_price  = gas_price;
        preq.count      = count;
        preq.count_all  = count_all;
        preq.no_dust_sweep = no_dust_sweep;
        nodus_v2_spend_err_t pe;
        long pcount = 0;
        int prc = nodus_v2_spend_plan(&preq, coins, n_coins, &plans, &pcount,
                                      &fee, &pe);
        if (pcount > 0) count = pcount;
        switch (prc) {
        case NODUS_V2_SPEND_OK:
            break;
        case NODUS_V2_SPEND_NONE_ELIGIBLE:
            printf("v2-envelope spend: 0 eligible coin(s) (shard %lu/%lu: "
                   "%d listed in shard, %d locked, %d in other shards; "
                   "listing %d row(s), tip %llu) — nothing to submit\n",
                   shard_i, shard_m, n_coins, n_locked, n_other_shard,
                   utxos.count, (unsigned long long)tip);
            rc = 0;
            goto done;
        case NODUS_V2_SPEND_ERR_OVERFLOW:
            fprintf(stderr, "amount + fee overflows u64\n");
            goto done;
        case NODUS_V2_SPEND_ERR_NO_COIN_ALL:
            fprintf(stderr, "insufficient coins for spend %ld/%ld "
                    "(--amount all): each spend needs its own native "
                    "coin above the fee %llu raw; %d spendable coin(s) "
                    "listed in shard %lu/%lu, %d locked, %d in other "
                    "shards — nothing was submitted\n", pe.k + 1, count,
                    (unsigned long long)pe.fee, n_coins, shard_i, shard_m,
                    n_locked, n_other_shard);
            goto done;
        case NODUS_V2_SPEND_ERR_MAX_INPUTS:
            fprintf(stderr, "spend %ld/%ld needs more than %u inputs "
                    "(the chain's RTN_SPEND_MAX_IN) — consolidate "
                    "coins first or send less\n", pe.k + 1, count,
                    (unsigned)NODUS_V2_SPEND_MAX_IN);
            goto done;
        case NODUS_V2_SPEND_ERR_INPUT_SUM:
            fprintf(stderr, "spend %ld/%ld: the selected input sum "
                    "overflows u64\n", pe.k + 1, count);
            goto done;
        case NODUS_V2_SPEND_ERR_INSUFFICIENT:
            fprintf(stderr, "insufficient funds for spend %ld/%ld: need "
                    "amount %llu raw (%s) + fee %llu raw (native); %d "
                    "spendable coin(s) listed, %d locked (unlock_block "
                    "> tip %llu), %d outside shard %lu/%lu — nothing "
                    "was submitted\n",
                    pe.k + 1, count, (unsigned long long)amount,
                    is_native ? "native" : "--token",
                    (unsigned long long)pe.fee, n_coins, n_locked,
                    (unsigned long long)tip, n_other_shard,
                    shard_i, shard_m);
            goto done;
        case NODUS_V2_SPEND_ERR_METER:
            fprintf(stderr, "could not size res_max_total_units for a "
                    "%d-in/%d-out spend (the metering plan refused "
                    "it)\n", pe.n_in, pe.n_out);
            goto done;
        case NODUS_V2_SPEND_ERR_GAS_OVERFLOW:
            fprintf(stderr, "units %llu x gas price %llu overflows u64 — no "
                    "fee can pay it\n", (unsigned long long)pe.units,
                    (unsigned long long)gas_price);
            goto done;
        case NODUS_V2_SPEND_ERR_FEE_BELOW_GAS:
            fprintf(stderr, "--fee %llu is below the chain's gas-price "
                    "requirement: %llu units x gas price %llu = %llu raw "
                    "(the largest spend of this batch) — nothing was "
                    "submitted\n", (unsigned long long)pe.fee,
                    (unsigned long long)pe.units,
                    (unsigned long long)gas_price,
                    (unsigned long long)pe.required);
            goto done;
        case NODUS_V2_SPEND_ERR_FEE_UNSETTLED:
            fprintf(stderr, "the gas-price fee did not settle after %d "
                    "planning passes (last: fee %llu, required %llu) — "
                    "nothing was submitted\n", pe.pass + 1,
                    (unsigned long long)pe.fee,
                    (unsigned long long)pe.required);
            goto done;
        default:
            fprintf(stderr, "spend planning failed (rc=%d)\n", prc);
            goto done;
        }
    }

    /* ── build, self-check and (unless --dry-run) submit each ────────── */
    for (long k = 0; k < count; k++) {
        const nodus_v2_spend_plan_t *p = &plans[k];
        nodus_v2_spend_build_req_t breq;
        memset(&breq, 0, sizeof(breq));
        breq.rs            = &rs;
        breq.chain32       = chain32;
        breq.tip           = tip;
        /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md
         * 1): expiry within (tip, tip + NODUS_CMT_APP_MAX_EXPIRY_AHEAD],
         * with the gossip margin (CLI_ENV_EXPIRY_AHEAD); a 0 tip was
         * refused above */
        if (cli_env_expiry(tip, &breq.expiry_height) != 0) goto done;
        breq.pk            = keys[0].pk.bytes;
        breq.sk            = keys[0].sk.bytes;
        breq.to_fp         = to_raw;
        breq.token         = is_native ? NULL : token;
        breq.amount        = amount;
        breq.amount_all    = amount_all;
        breq.fee           = fee;
        breq.gas_price     = gas_price;
        breq.coins         = coins;
        breq.plan          = p;
        breq.rand          = cli_rand;
        breq.rand_ctx      = NULL;
        breq.shard_m       = shard_m;
        breq.shard_i       = shard_i;

        nodus_v2_spend_built_free(&built);
        nodus_v2_spend_err_t be;
        int brc = nodus_v2_spend_build(&breq, &built, &be);
        if (brc != NODUS_V2_SPEND_OK) {
            if (brc == NODUS_V2_SPEND_ERR_RANDOM)
                fprintf(stderr, "random seed generation failed\n");
            else if (brc == NODUS_V2_SPEND_ERR_SHARD_DRAWS)
                fprintf(stderr, "no output seed landed in shard %lu/%lu "
                        "after %lu draws — the random source is "
                        "broken\n", shard_i, shard_m, be.draws);
            else if (brc == NODUS_V2_SPEND_ERR_METER)
                fprintf(stderr, "could not size res_max_total_units (the "
                        "metering plan refused the envelope)\n");
            else if (brc == NODUS_V2_SPEND_ERR_UNITS_OVER_FEE)
                fprintf(stderr, "spend %ld/%ld: %llu units x gas price %llu "
                        "exceeds the planned fee %llu — not submitted\n",
                        k + 1, count, (unsigned long long)be.units,
                        (unsigned long long)gas_price,
                        (unsigned long long)fee);
            else if (brc == NODUS_V2_SPEND_ERR_PREFLIGHT1)
                fprintf(stderr, "pass-1 preflight failed\n");
            else if (brc == NODUS_V2_SPEND_ERR_SIGN)
                fprintf(stderr, "leg %d signature failed\n", be.leg);
            else if (brc == NODUS_V2_SPEND_ERR_PREFLIGHT2)
                fprintf(stderr, "pass-2 preflight (self-check) failed\n");
            else
                fprintf(stderr, "spend %ld/%ld: build failed (rc=%d)\n",
                        k + 1, count, brc);
            goto done;
        }
        const nodus_v2_spend_decoded_t *d = &built.dec;

        printf("v2-envelope spend %ld/%ld: %zu bytes, inputs=%d "
               "native_in=%llu token_in=%llu amount=%llu fee=%llu "
               "native_change=%llu token_change=%llu effects=%u "
               "effect_bytes=%u units=%llu tip=%llu\n",
               k + 1, count, built.env_len, p->n_in,
               (unsigned long long)p->native_in,
               (unsigned long long)p->token_in,
               (unsigned long long)d->out_amount[0], (unsigned long long)fee,
               (unsigned long long)p->native_change,
               (unsigned long long)p->token_change,
               (unsigned)d->effects, (unsigned)d->effect_bytes,
               (unsigned long long)d->units, (unsigned long long)tip);
        printf("  wire_id=");
        for (int b = 0; b < 64; b++) printf("%02x", built.wire_id[b]);
        printf("\n  intent_id=");
        for (int b = 0; b < 64; b++) printf("%02x", built.intent_id[b]);
        printf("\n");
        for (int o = 0; o < d->n_out; o++) {
            printf("  out[%d] id=", o);
            for (int b = 0; b < 64; b++) printf("%02x", d->out_id[o][b]);
            printf(" owner=%.16s... amount=%llu\n", d->out_owner[o],
                   (unsigned long long)d->out_amount[o]);
        }
        fflush(stdout);

        if (dry_run) {
            printf("  PREFLIGHT SELF-CHECK: OK (1 leg CORE SPEND) — not "
                   "submitted (--dry-run)\n");
            continue;
        }
        if (t6_submit_on(&client, &keys[0], built.wire_id, built.env,
                         (uint32_t)built.env_len) != 0) {
            fprintf(stderr, "spend %ld/%ld was not accepted; %ld earlier "
                    "spend(s) of this batch were\n", k + 1, count, k);
            goto done;
        }
        fflush(stdout);
    }
    rc = 0;

done:
    nodus_v2_spend_built_free(&built);
    free(plans);
    free(coins);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ── `v2-envelope token-create` — the CORE TOKEN_CREATE builder ───────
 *
 * Builds a single-leg DNA_CORE envelope, runtime_op 3
 * (DNA_CORERULE_TOKEN_CREATE), auth_kind 1 (the creator's ML-DSA-87
 * signature over the leg auth digest), fee in the envelope. A TOOL: no
 * consensus rule is added or changed here. The chain side is the
 * SPECIFICATION (nodus_witness_rt_native.c); every rule below is mirrored
 * client-side so a refusal happens here, with the reason, not at CheckTx:
 *
 *   call v1 (rtn_tc_parse :1217-1265) = token_id[64] ‖ name_len u8 ‖ name
 *   ‖ sym_len u8 ‖ sym ‖ decimals u8 ‖ the SPEND transfer section
 *   (in_count 1..14, out_count 1..16, rtn_xfer_section_parse
 *   :1122-1149), exact length;
 *   - token_id never all-zero (:1226-1227);
 *   - name 1..32 (:1229), symbol 1..8 (:1235), both printable ASCII
 *     0x20..0x7e minus ':' (rtn_tc_text_ok :1199-1204);
 *   - decimals 0..18 (:1241);
 *   - output[0] IS the token genesis output: its token_id equals the
 *     declared one (:1250-1251), its amount (the registered supply) is
 *     >= 1 (:1146) and <= INT64_MAX (:1257-1258), and the registry row's
 *     creator_fp is output[0]'s owner (rtn_tc_exec :1904) — so `--to`
 *     names the CREATOR of record, not only the first holder;
 *   - every other output is NATIVE change (:1259-1263);
 *   - inputs: present, unlocked (unlock_block < H, :1821-1822), owned by
 *     the signer (:1823-1827), NATIVE only (:1828-1829), at most 14
 *     (RTN_TC_MAX_IN :375 — the read budget funds in + pool + registry);
 *   - fee >= ctx->token_create_fee (rtn_tc_exec; W-C: chain_config
 *     param 6 at the block's height) and
 *     Σnative_in == Σnative_out + fee exactly (:1852-1866); the token
 *     supply is NOT native value, so the inputs pay the fee alone;
 *   - the token id must not be registered yet (the registry read,
 *     :1809-1812) — this client cannot see the registry, so a reused id
 *     is refused by the chain, not here.
 * The fee goes to the reward pool (rtn_tc_exec's pool SET :1919-1927;
 * decision docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md
 * §1 names TOKEN_CREATE explicitly). The fee floor is the chain's
 * GOVERNED value since the final pre-testnet wipe W-C (chain_config
 * param 6 TOKEN_CREATE_FEE_RAW, decision docs/plans/decisions/
 * 2026-09-28-token-create-fee-governance.md): rtn_tc_exec enforces
 * fee >= the committed row at the block's height, and this builder
 * reads the same value at tip + 1 from dnac_fee_info
 * (`token_create_fee`); an older server that does not report it falls
 * back to the compiled NODUS_W_TOKEN_CREATE_FEE with a warning.
 *
 * Everything else is `v2-envelope spend`'s flow on ONE session
 * authenticated as the creator: chain id (dnac_supply chain_id32), gas
 * price (dnac_fee_info), coins + tip (dnac_utxo, unlocked native coins
 * only, largest first, ties by nullifier — nodus_v2_spend_sort_coins /
 * nodus_v2_spend_pick), the CORE ruleset from the compiled table, the
 * two-pass signature (nodus_v2_env_sign_one_key via cli_sign_one_key) and
 * submission (t6_submit_on). Output seeds are
 * 32 fresh random bytes (nodus_random, the spend precedent); a default
 * token id is 64 fresh random bytes from the same source.
 *
 * Resource fields: the leg declares the EXACT effects rtn_tc_exec emits
 * (t6_tc_effect_decl) and res_max_total_units is right-sized from that
 * declaration by the metering module itself (nodus_v2_spend_ceiling, with the
 * TOKEN_CREATE read count in + 2) — the same rule as the SPEND builder,
 * never a round number: PrepareProposal reserves every envelope's whole
 * ceiling against one block budget, and under the gas-price rule
 * (decision docs/plans/decisions/2026-09-25-gas-price.md) the fee must
 * cover units × gas_price, so an inflated ceiling would cost the creator
 * real fee once the rule is on. */
#define T6_TC_MAX_IN      14u   /* RTN_TC_MAX_IN, rt_native.c:375            */
#define T6_TC_MAX_OUTS    2u    /* the token genesis output + native change */
#define T6_TC_NAME_MAX    32u   /* RTN_TC_NAME_MAX, rt_native.c:377          */
#define T6_TC_SYM_MAX     8u    /* RTN_TC_SYM_MAX, rt_native.c:378           */
#define T6_TC_DEC_MAX     18u   /* RTN_TC_DECIMALS_MAX, rt_native.c:379      */
/* The registry record the op-4 CREATE carries: RTN_TOKEN_REC_LEN = 188
 * (rt_native.c:1080; file-local there, so restated with its citation —
 * the NODUS_V2_SPEND_MAX_IN / NODUS_V2_SPEND_OUT_LEN precedent in
 * nodus_v2_spend.h). */
#define T6_TOKEN_REC_LEN  188u

/* The EXACT per-leg effect declaration of ONE CORE TOKEN_CREATE leg with
 * n_in inputs and n_out outputs — what rtn_tc_exec
 * (nodus_witness_rt_native.c:1794-1940) emits:
 *   - n_out UTXO CREATEs (:1891-1897): key 64, value
 *     NODUS_RT_CORE_UTXO_REC_LEN (284);
 *   - ONE token-registry CREATE (:1898-1918): key 64 (the token id),
 *     value RTN_TOKEN_REC_LEN (188);
 *   - ONE reward-pool SET (:1922-1927): key 1, value 8;
 *   - n_in DELETEs (:1929-1934): key 64, value 0.
 * Bytes = the canonical encoded result length, the same effect_wire.h
 * layout nodus_v2_spend_effect_decl documents (23-byte head, 84 bytes per
 * record, then every key and value blob):
 *   effects = n_in + n_out + 2
 *   bytes   = 23 + 84·effects + n_out·(64 + 284) + (64 + 188) + (1 + 8)
 *             + n_in·64
 *           = 452 + 148·n_in + 432·n_out
 * Every term is a fixed-size field, so the bound is exact; the charge
 * gate rejects only actual > declared (res_meter.c). */
static void t6_tc_effect_decl(uint32_t n_in, uint32_t n_out,
                              uint32_t *effects_out, uint32_t *bytes_out) {
    const uint32_t effects = n_in + n_out + 2u;
    *effects_out = effects;
    *bytes_out = (uint32_t)DNA_EFFECT_FIXED_HEAD +
                 (uint32_t)DNA_EFFECT_RECORD_LEN * effects +
                 n_out * (64u + NODUS_RT_CORE_UTXO_REC_LEN) +
                 (64u + T6_TOKEN_REC_LEN) +
                 (1u + 8u) +
                 n_in * 64u;
}
/* The largest shape this builder emits (14 inputs, 2 outputs) stays
 * inside the metering plan's declaration caps (res_meter.h). */
_Static_assert(T6_TC_MAX_IN + T6_TC_MAX_OUTS + 2u <=
                   (unsigned)DNA_EFFECT_MAX_COUNT,
               "TOKEN_CREATE effect count exceeds the effect codec cap");
_Static_assert((unsigned)DNA_EFFECT_FIXED_HEAD +
                   (unsigned)DNA_EFFECT_RECORD_LEN *
                       (T6_TC_MAX_IN + T6_TC_MAX_OUTS + 2u) +
                   T6_TC_MAX_OUTS * (64u + NODUS_RT_CORE_UTXO_REC_LEN) +
                   (64u + T6_TOKEN_REC_LEN) + (1u + 8u) +
                   T6_TC_MAX_IN * 64u <= DNA_EFFECT_MAX_TOTAL_LEN,
               "TOKEN_CREATE result length exceeds the effect codec cap");
_Static_assert(T6_TC_MAX_IN <= NODUS_V2_SPEND_MAX_IN,
               "the TOKEN_CREATE plan reuses the SPEND plan's input array");

/* The registry text rule (rtn_tc_text_ok, rt_native.c:1199-1204):
 * printable ASCII 0x20..0x7e, never ':'. @return 1 ok / 0 refused. */
static int t6_tc_text_ok(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e || c == ':') return 0;
    }
    return 1;
}

static int cmd_v2_token_create(const char *server_ip, uint16_t server_port,
                               int argc, char **argv, int cmd_start) {
    const char *keys_csv = NULL, *name = NULL, *symbol = NULL;
    const char *to_hex = NULL, *token_hex = NULL, *submit = NULL;
    uint64_t supply = 0, fee = 0;
    unsigned long decimals = 0;
    int dry_run = 0, have_supply = 0, have_dec = 0, have_fee = 0;
    int bad_arg = 0;

    for (int i = cmd_start + 2; i < argc; i++) {  /* skip "token-create" */
        const char *a = argv[i];
        char *end = NULL;
        if      (!strcmp(a, "--keys")     && i + 1 < argc) keys_csv  = argv[++i];
        else if (!strcmp(a, "--name")     && i + 1 < argc) name      = argv[++i];
        else if (!strcmp(a, "--symbol")   && i + 1 < argc) symbol    = argv[++i];
        else if (!strcmp(a, "--to")       && i + 1 < argc) to_hex    = argv[++i];
        else if (!strcmp(a, "--token-id") && i + 1 < argc) token_hex = argv[++i];
        else if (!strcmp(a, "--submit")   && i + 1 < argc) submit    = argv[++i];
        else if (!strcmp(a, "--decimals") && i + 1 < argc) {
            const char *v = argv[++i];
            if (v[0] < '0' || v[0] > '9') { bad_arg = 1; break; }
            decimals = strtoul(v, &end, 10);
            if (!end || *end != '\0') { bad_arg = 1; break; }
            have_dec = 1;
        } else if (!strcmp(a, "--supply") && i + 1 < argc) {
            const char *v = argv[++i];
            if (v[0] < '0' || v[0] > '9') { bad_arg = 1; break; }
            errno = 0;
            supply = strtoull(v, &end, 10);
            if (!end || *end != '\0' || errno == ERANGE) { bad_arg = 1; break; }
            have_supply = 1;
        } else if (!strcmp(a, "--fee") && i + 1 < argc) {
            const char *v = argv[++i];
            if (v[0] < '0' || v[0] > '9') { bad_arg = 1; break; }
            errno = 0;
            fee = strtoull(v, &end, 10);
            if (!end || *end != '\0' || errno == ERANGE) { bad_arg = 1; break; }
            have_fee = 1;
        } else if (!strcmp(a, "--dry-run")) {
            dry_run = 1;
        } else { bad_arg = 1; break; }
    }
    if (bad_arg || !keys_csv || !name || !symbol || !have_dec ||
        !have_supply || (!submit && !dry_run)) {
        fprintf(stderr,
            "Usage: v2-envelope token-create --keys <keydir> --name <name> "
            "--symbol <sym>\n"
            "       --decimals <0..18> --supply <raw> [--to <fp128hex>] "
            "[--fee <raw>]\n"
            "       [--token-id <hex128>] (--dry-run | --submit ip:port)\n"
            "  One CORE TOKEN_CREATE envelope. The whole flow (chain id, gas "
            "price, coin\n"
            "  listing, submission) runs on ONE session to --submit, or to "
            "the outer -s\n"
            "  server for --dry-run (which builds and self-checks, submits "
            "nothing).\n"
            "  --name 1..%u and --symbol 1..%u chars, printable ASCII "
            "without ':'.\n"
            "  --supply   the whole supply, in the token's raw units "
            "(1..%lld); it is\n"
            "             minted as ONE output to --to.\n"
            "  --to       the genesis output's owner AND the registry's "
            "creator of record\n"
            "             (default: the --keys identity).\n"
            "  --fee      native raw; default the chain's creation fee "
            "(dnac_fee_info\n"
            "             token_create_fee; %llu raw from an older server "
            "that does\n"
            "             not report it), raised to units x gas_price when "
            "the node\n"
            "             reports a gas price above it. A --fee below either "
            "is refused,\n"
            "             never raised.\n"
            "  --token-id 64 bytes as 128 lowercase hex; default 64 fresh "
            "random bytes.\n"
            "             A token id already registered is refused by the "
            "chain.\n"
            "  Inputs are the creator's native coins only (at most %u); "
            "native change\n"
            "  returns to the creator. Prints token_id= (for "
            "`v2-envelope spend --token`)\n"
            "  and intent_id= (the tx_hash of the UTXOs it creates).\n",
            (unsigned)T6_TC_NAME_MAX, (unsigned)T6_TC_SYM_MAX,
            (long long)INT64_MAX,
            (unsigned long long)NODUS_W_TOKEN_CREATE_FEE,
            (unsigned)T6_TC_MAX_IN);
        return 1;
    }

    /* ── argument verdicts: refuse what the chain would refuse ────────── */
    const size_t name_len = strlen(name), sym_len = strlen(symbol);
    if (name_len < 1 || name_len > T6_TC_NAME_MAX ||
        !t6_tc_text_ok(name, name_len)) {
        fprintf(stderr, "--name must be 1..%u printable ASCII characters "
                "without ':' (rtn_tc_parse / rtn_tc_text_ok)\n",
                (unsigned)T6_TC_NAME_MAX);
        return 1;
    }
    if (sym_len < 1 || sym_len > T6_TC_SYM_MAX ||
        !t6_tc_text_ok(symbol, sym_len)) {
        fprintf(stderr, "--symbol must be 1..%u printable ASCII characters "
                "without ':' (rtn_tc_parse / rtn_tc_text_ok)\n",
                (unsigned)T6_TC_SYM_MAX);
        return 1;
    }
    if (decimals > T6_TC_DEC_MAX) {
        fprintf(stderr, "--decimals must be 0..%u\n", (unsigned)T6_TC_DEC_MAX);
        return 1;
    }
    if (supply < 1 || supply > (uint64_t)INT64_MAX) {
        fprintf(stderr, "--supply must be 1..%lld raw (a zero-value output "
                "is refused; the registry stores the supply as a signed "
                "64-bit integer)\n", (long long)INT64_MAX);
        return 1;
    }
    /* W-C: the creation fee is the chain's governed value (dnac_fee_info
     * `token_create_fee`, read on the session below); a --fee is judged
     * against it there, and the default is taken from it there. */
    uint8_t to_raw[64];
    if (to_hex && qgp_fp_hex_to_raw(to_hex, to_raw) != 0) {
        fprintf(stderr, "--to must be exactly 128 lowercase hex chars (a "
                "fingerprint; the output owner field is checked by "
                "rtn_hex_lower_ok)\n");
        return 1;
    }
    static const uint8_t native_tok[64] = {0};
    uint8_t token[64];
    if (token_hex) {
        /* same 64-byte lowercase-hex shape as a fingerprint */
        if (qgp_fp_hex_to_raw(token_hex, token) != 0) {
            fprintf(stderr, "--token-id must be exactly 128 lowercase hex "
                    "chars (a 64-byte token id)\n");
            return 1;
        }
    } else if (nodus_random(token, sizeof(token)) != 0) {
        fprintf(stderr, "random token id generation failed\n");
        return 1;
    }
    if (memcmp(token, native_tok, 64) == 0) {
        fprintf(stderr, "the token id is all-zero — that is the native "
                "coin's id, never a token\n");
        return 1;
    }
    char token_fp[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(token, token_fp);          /* printed, lowercase    */

    int rc = 1;
    nodus_identity_t *keys = NULL;
    nodus_v2_coin_t *coins = NULL;
    uint8_t *call = NULL, *auth = NULL, *env_bytes = NULL;
    dna_env_preflight_t *pf = NULL;
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    int utxos_valid = 0, connected = 0;
    nodus_client_t client;
    memset(&client, 0, sizeof(client));

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    if (act_load_keys(keys_csv, keys, 4) != 1) {
        fprintf(stderr, "v2-envelope token-create needs exactly one --keys "
                "identity\n");
        goto done;
    }

    /* Creator fingerprint (128 lowercase hex): the dnac_utxo query key,
     * the change owner and the default genesis-output owner. */
    uint8_t creator_raw[64];
    char creator_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, creator_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(creator_raw, creator_fp);
    char to_fp[QGP_FP_HEX_BUFFER];
    if (to_hex) qgp_fp_raw_to_hex(to_raw, to_fp);   /* canonical lowercase */
    else        snprintf(to_fp, sizeof(to_fp), "%s", creator_fp);

    const nodus_domain_runtime_t *core_rt = cli_builtin_runtime(DNA_DOMAIN_CORE, NODUS_RT_GEN_1);
    const nodus_domain_runtime_t *sys_rt  = cli_builtin_runtime(DNA_DOMAIN_SYSTEM, NODUS_RT_GEN_1);
    if (!core_rt || !sys_rt || !sys_rt->meter_policy) {
        fprintf(stderr, "CORE runtime / SYSTEM block metering policy not "
                "found in the compiled production table\n");
        goto done;
    }

    /* ── ONE session, authenticated as the creator ─────────────────── */
    char sip[64];
    uint16_t sport = 0;
    if (t6_resolve_target(submit, server_ip, server_port, sip, &sport) != 0) {
        fprintf(stderr, "invalid --submit target (and no -s server)\n");
        goto done;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
    cfg.servers[0].port = sport;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(&client, &cfg, &keys[0]) != 0) {
        fprintf(stderr, "client_init failed\n");
        goto done;
    }
    connected = 1;                          /* init succeeded: close owed */
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
        goto done;
    }

    uint8_t chain32[DNA_CHAIN_ID_LEN];
    bool has_chain32 = false;
    if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
        !has_chain32) {
        fprintf(stderr, "this node is not on a version-3 chain (no "
                "chain_id32 in its dnac_supply reply) — v2-envelope "
                "token-create needs a version-3 chain\n");
        goto done;
    }
    /* HF-4: build for the generation the node names */
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;

    /* HF-1 — the committed gas price at tip + 1, on the SAME session (the
     * spend builder's source, decision 2026-09-25-gas-price.md "HF-1
     * O4"). 0 = the rule is off; a failed query is not "price 0". */
    uint64_t gas_price = 0;
    {
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        int frc = nodus_client_dnac_fee_info(&client, &fi);
        if (frc != 0) {
            fprintf(stderr, "dnac_fee_info query failed (rc=%d) — the gas "
                    "price is unknown, refusing to size a fee\n", frc);
            goto done;
        }
        gas_price = fi.gas_price;

        /* W-C — the chain's token-creation fee: the committed
         * chain_config param 6 at tip + 1 (decision 2026-09-28-token-
         * create-fee-governance.md), the floor rtn_tc_exec enforces. An
         * older server sends no `token_create_fee` key (0 here): fall
         * back to the compiled NODUS_W_TOKEN_CREATE_FEE, which is what
         * such a chain enforces, and say so. */
        uint64_t chain_fee = fi.token_create_fee;
        if (chain_fee == 0) {
            chain_fee = NODUS_W_TOKEN_CREATE_FEE;
            fprintf(stderr, "warning: the node did not report "
                    "token_create_fee (an older server) — using the "
                    "compiled creation fee %llu raw\n",
                    (unsigned long long)chain_fee);
        }
        if (have_fee && fee < chain_fee) {
            fprintf(stderr, "--fee %llu is below the chain's token-creation "
                    "fee %llu raw (chain_config TOKEN_CREATE_FEE_RAW at tip "
                    "+ 1) — nothing was submitted\n",
                    (unsigned long long)fee, (unsigned long long)chain_fee);
            goto done;
        }
        if (!have_fee) fee = chain_fee;
    }

    int urc = nodus_client_dnac_utxo(&client, creator_fp,
                                     NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
    if (urc != 0) {
        fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
        goto done;
    }
    utxos_valid = 1;
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        /* the server's height read is FAIL-OPEN (0 on a fault) and the
         * envelope's expiry is anchored on it — refuse (the spend rule) */
        fprintf(stderr, "the node reported tip 0 (a version-3 chain past "
                "its first block never does; its height read may have "
                "faulted) — refusing to build an envelope whose expiry "
                "would be wrong\n");
        goto done;
    }
    if (utxos.count >= (int)NODUS_DNAC_MAX_UTXO_RESULTS)
        fprintf(stderr, "warning: the coin listing is capped at %d rows and "
                "came back full — a node >= 0.25.2 lists the largest coins "
                "first (an older node in no order); smaller coins beyond the "
                "cap are invisible to this selection\n",
                (int)NODUS_DNAC_MAX_UTXO_RESULTS);

    /* ── the spendable NATIVE coin set, in the selection order ───────── */
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    int n_coins = 0, n_locked = 0;
    for (int i = 0; i < utxos.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        if (e->amount == 0) continue;
        if (memcmp(e->token_id, native_tok, 64) != 0) continue; /* native only */
        if (e->unlock_block > tip) { n_locked++; continue; }
        nodus_v2_coin_t *c = &coins[n_coins++];
        memcpy(c->nul, e->nullifier, 64);
        c->amount = e->amount;
        c->kind   = 0;
        c->used   = 0;
    }
    if (nodus_v2_spend_sort_coins(coins, n_coins,
                                  NODUS_V2_SPEND_ORDER_LARGEST_FIRST) != 0)
        goto done;

    const uint32_t alen = 1u + NODUS_RT_AUTH_SIGNER_LEN;   /* kind-1, 1 sig */
    const size_t fixed_len = 64 + 1 + name_len + 1 + sym_len + 1;
    call = malloc(fixed_len + 2 + (size_t)T6_TC_MAX_IN * 64 +
                  (size_t)T6_TC_MAX_OUTS * NODUS_V2_SPEND_OUT_LEN);
    auth = calloc(1, alen);
    pf   = calloc(1, sizeof(*pf));
    if (!call || !auth || !pf) goto done;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_CORE;
    lctx.ruleset_version = core_rt->ruleset_version;
    memcpy(lctx.ruleset_hash, core_rt->ruleset_hash, 64);

    /* ── plan + build, under a bounded gas-price fixed point ────────────
     * The chain requires fee >= max(floor, units × gas_price) for a
     * non-SYSTEM envelope (nodus_witness_v2_apply.c env_gas_price_check);
     * the units depend on the input count, the input count on the fee.
     * Build the REAL leg at the current fee, price it, and if it needs
     * more raise the fee and re-plan from scratch — the spend builder's
     * loop. gas_price 0: one pass, the fee is the creation fee. An
     * explicit --fee is never raised. */
    nodus_v2_spend_plan_t plan;
    dna_env_leg_in_t leg;
    dna_env_in_t env_in;
    uint64_t units = 0, native_change = 0;
    int n_out = 0;
    uint8_t out_id[T6_TC_MAX_OUTS][64];
    for (int pass = 0; ; pass++) {
        memset(&plan, 0, sizeof(plan));
        for (int i = 0; i < n_coins; i++) coins[i].used = 0;
        int prc = nodus_v2_spend_pick(coins, n_coins, 0, fee, &plan,
                                &plan.native_in);
        if (prc == 0 && plan.n_in > (int)T6_TC_MAX_IN) prc = -2;
        if (prc != 0) {
            if (prc == -2)
                fprintf(stderr, "the fee %llu raw needs more than %u native "
                        "inputs (the chain's RTN_TC_MAX_IN; selection is "
                        "largest first, so no smaller set covers it) — "
                        "consolidate coins first\n",
                        (unsigned long long)fee, (unsigned)T6_TC_MAX_IN);
            else if (prc == -3)
                fprintf(stderr, "the selected input sum overflows u64\n");
            else
                fprintf(stderr, "insufficient native funds: the fee is %llu "
                        "raw; %d spendable native coin(s) listed, %d locked "
                        "(unlock_block > tip %llu) — nothing was "
                        "submitted\n", (unsigned long long)fee, n_coins,
                        n_locked, (unsigned long long)tip);
            goto done;
        }
        native_change = plan.native_in - fee;

        /* inputs: strictly ascending nullifiers on the wire (:1139-1142) */
        uint8_t nulls[NODUS_V2_SPEND_MAX_IN][64];
        for (int j = 0; j < plan.n_in; j++)
            memcpy(nulls[j], coins[plan.idx[j]].nul, 64);
        qsort(nulls, (size_t)plan.n_in, 64, nodus_v2_nul_cmp);

        size_t off = 0;
        memcpy(call + off, token, 64);                 off += 64;
        call[off++] = (uint8_t)name_len;
        memcpy(call + off, name, name_len);            off += name_len;
        call[off++] = (uint8_t)sym_len;
        memcpy(call + off, symbol, sym_len);           off += sym_len;
        call[off++] = (uint8_t)decimals;
        call[off++] = (uint8_t)plan.n_in;
        for (int j = 0; j < plan.n_in; j++) {
            memcpy(call + off, nulls[j], 64);
            off += 64;
        }
        /* output[0] = the token genesis output; [1] = native change */
        const char     *o_owner[T6_TC_MAX_OUTS];
        uint64_t        o_amt[T6_TC_MAX_OUTS];
        const uint8_t  *o_tok[T6_TC_MAX_OUTS];
        n_out = 0;
        o_owner[n_out] = to_fp; o_amt[n_out] = supply; o_tok[n_out] = token;
        n_out++;
        if (native_change > 0) {
            o_owner[n_out] = creator_fp; o_amt[n_out] = native_change;
            o_tok[n_out] = NULL; n_out++;
        }
        call[off++] = (uint8_t)n_out;
        for (int o = 0; o < n_out; o++) {
            uint8_t seed[32];
            if (nodus_random(seed, sizeof(seed)) != 0) {
                fprintf(stderr, "random seed generation failed\n");
                goto done;
            }
            nodus_v2_xfer_out_put(call + off, o_owner[o], o_amt[o], o_tok[o], seed);
            /* the output id the chain derives (rtn_out_ids :1467-1476) */
            uint8_t pre[160];
            memcpy(pre, call + off, 128);
            memcpy(pre + 128, seed, 32);
            if (qgp_sha3_512(pre, sizeof(pre), out_id[o]) != 0) goto done;
            off += NODUS_V2_SPEND_OUT_LEN;
        }
        /* two random seeds colliding into one output id is a
         * deterministic chain reject (rtn_out_ids :1486-1488) — refuse */
        if (n_out == 2 && memcmp(out_id[0], out_id[1], 64) == 0) {
            fprintf(stderr, "two outputs derived the same id — the random "
                    "source is broken\n");
            goto done;
        }

        memset(&leg, 0, sizeof(leg));
        leg.hdr.domain_id       = DNA_DOMAIN_CORE;
        leg.hdr.runtime_op      = DNA_CORERULE_TOKEN_CREATE;
        leg.hdr.ruleset_version = core_rt->ruleset_version;
        leg.hdr.access_mode     = DNA_ENV_ACCESS_INVOKE;
        leg.hdr.auth_kind       = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
        leg.hdr.call_len        = (uint32_t)off;
        leg.hdr.auth_len        = alen;
        t6_tc_effect_decl((uint32_t)plan.n_in, (uint32_t)n_out,
                          &leg.hdr.res_max_effects,
                          &leg.hdr.res_max_effect_bytes);
        leg.call_data = call;
        memset(auth, 0, alen);               /* pass 1 needs a zero blob */
        leg.auth_data = auth;

        memset(&env_in, 0, sizeof(env_in));
        /* the mempool lifetime rule (decision 2026-09-25-mempool-policy.md
         * 1), the spend builder's margin; a 0 tip was refused above */
        if (cli_env_expiry(tip, &env_in.expiry_height) != 0) goto done;
        env_in.fee_amount    = fee;
        env_in.leg_count     = 1;
        env_in.legs          = &leg;

        /* reads: in_count + the pool + the registry (read plan :1387) */
        if (nodus_v2_spend_ceiling(&env_in, sys_rt->meter_policy,
                             (uint32_t)plan.n_in + 2u, &units) != 0) {
            fprintf(stderr, "could not size res_max_total_units (the "
                    "metering plan refused the envelope)\n");
            goto done;
        }
        env_in.res_max_total_units = units;

        if (gas_price == 0) break;          /* rule off: one pass        */
        if (units > UINT64_MAX / gas_price) {
            fprintf(stderr, "units %llu x gas price %llu overflows u64 — no "
                    "fee can pay it\n", (unsigned long long)units,
                    (unsigned long long)gas_price);
            goto done;
        }
        const uint64_t required = units * gas_price;
        if (required <= fee) break;         /* the fee covers this leg   */
        if (have_fee) {
            fprintf(stderr, "--fee %llu is below the chain's gas-price "
                    "requirement: %llu units x gas price %llu = %llu raw — "
                    "nothing was submitted\n", (unsigned long long)fee,
                    (unsigned long long)units,
                    (unsigned long long)gas_price,
                    (unsigned long long)required);
            goto done;
        }
        if (pass >= 7) {
            fprintf(stderr, "the gas-price fee did not settle after %d "
                    "planning passes (last: fee %llu, required %llu) — "
                    "nothing was submitted\n", pass + 1,
                    (unsigned long long)fee, (unsigned long long)required);
            goto done;
        }
        fee = required;                     /* re-plan at the higher fee */
    }

    uint8_t *auths[1] = { auth };
    size_t env_len = 0;
    if (cli_sign_one_key(&env_in, auths, &lctx, chain32, tip, &keys[0],
                            &env_bytes, &env_len, pf) != 0)
        goto done;

    printf("v2-envelope token-create: %zu bytes, inputs=%d native_in=%llu "
           "fee=%llu native_change=%llu supply=%llu decimals=%lu "
           "effects=%u effect_bytes=%u units=%llu tip=%llu\n",
           env_len, plan.n_in, (unsigned long long)plan.native_in,
           (unsigned long long)fee, (unsigned long long)native_change,
           (unsigned long long)supply, decimals,
           (unsigned)leg.hdr.res_max_effects,
           (unsigned)leg.hdr.res_max_effect_bytes,
           (unsigned long long)units, (unsigned long long)tip);
    printf("  name=%s symbol=%s\n", name, symbol);
    printf("  token_id=%s\n", token_fp);
    printf("  wire_id=");
    for (int b = 0; b < 64; b++) printf("%02x", pf->wire_id[b]);
    printf("\n  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", pf->intent_id[b]);
    printf("\n");
    for (int o = 0; o < n_out; o++) {
        printf("  out[%d] id=", o);
        for (int b = 0; b < 64; b++) printf("%02x", out_id[o][b]);
        printf(" owner=%.16s... amount=%llu %s\n",
               o == 0 ? to_fp : creator_fp,
               (unsigned long long)(o == 0 ? supply : native_change),
               o == 0 ? "(token genesis)" : "(native change)");
    }
    fflush(stdout);

    if (dry_run) {
        printf("  PREFLIGHT SELF-CHECK: OK (1 leg CORE TOKEN_CREATE) — not "
               "submitted (--dry-run)\n");
    } else {
        if (t6_submit_on(&client, &keys[0], pf->wire_id, env_bytes,
                         (uint32_t)env_len) != 0)
            goto done;
    }
    fflush(stdout);
    rc = 0;

done:
    free(env_bytes);
    free(call);
    free(auth);
    free(pf);
    free(coins);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ══ HF-4 — on-chain names (design docs/plans/2026-10-02-onchain-names-
 *    design.md rev 4 §1.6, §2; decision 2026-10-02-onchain-names.md) ═══ */

/* The name normaliser (ASCII-only lower-casing + the consensus byte rule),
 * the price tier index, the effect declaration and the whole envelope
 * build live in the shared builder nodus/src/client/nodus_v2_name.{c,h}
 * (the web wallet's WASM module compiles the same file). */

/* One read-only session as the CLI's own identity. 0 / -1. */
static int t8_session(nodus_client_t *client, const char *ip, uint16_t port) {
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", ip);
    cfg.servers[0].port = port;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(client, &cfg, &identity) != 0) {
        fprintf(stderr, "client_init failed\n");
        return -1;
    }
    if (nodus_client_connect(client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", ip,
                (unsigned)port);
        nodus_client_close(client);
        return -1;
    }
    return 0;
}

/* `ruleset-info`: the generation the node runs, and whether this CLI
 * carries it. */
static int cmd_ruleset_info(const char *server_ip, uint16_t server_port) {
    nodus_client_t client;
    if (t8_session(&client, server_ip, server_port) != 0) return 1;
    nodus_dnac_ruleset_info_t ri;
    int qrc = nodus_client_dnac_ruleset_info(&client, &ri);
    nodus_client_close(&client);
    if (qrc != 0) {
        fprintf(stderr, "dnac_ruleset_info failed (rc=%d) — an older node "
                "does not know the method\n", qrc);
        return 1;
    }
    printf("tip=%llu generation=%u (governs tip+1)\n",
           (unsigned long long)ri.tip, (unsigned)ri.generation);
    printf("  SYSTEM v%u hash=", (unsigned)ri.sys_version);
    for (int b = 0; b < 64; b++) printf("%02x", ri.sys_hash[b]);
    printf("\n  CORE   v%u hash=", (unsigned)ri.core_version);
    for (int b = 0; b < 64; b++) printf("%02x", ri.core_hash[b]);
    printf("\n  policy digest=");
    for (int b = 0; b < 64; b++) printf("%02x", ri.policy_digest[b]);
    printf("\n  RULESET_GEN2 height H=%llu%s\n",
           (unsigned long long)ri.gen2_height,
           ri.gen2_height ? "" : " (no vote committed)");
    printf("  node D2=0x%016llx  this CLI D2=0x%016llx%s\n",
           (unsigned long long)ri.d2,
           (unsigned long long)DNAC_CFG_RULESET_GEN2_D2,
           ri.d2 == (uint64_t)DNAC_CFG_RULESET_GEN2_D2 ? "" : "  MISMATCH");
    int carried = 0;
    for (uint32_t g = 1; g <= nodus_runtime_generation_count(); g++) {
        const nodus_domain_runtime_t *s = cli_builtin_runtime(DNA_DOMAIN_SYSTEM, g);
        const nodus_domain_runtime_t *c = cli_builtin_runtime(DNA_DOMAIN_CORE, g);
        if (s && c && s->ruleset_version == ri.sys_version &&
            memcmp(s->ruleset_hash, ri.sys_hash, 64) == 0 &&
            c->ruleset_version == ri.core_version &&
            memcmp(c->ruleset_hash, ri.core_hash, 64) == 0) {
            printf("  this CLI carries it as compiled generation %u\n",
                   (unsigned)g);
            carried = 1;
        }
    }
    if (!carried)
        printf("  this CLI does NOT carry it — out of date, rebuild\n");
    return carried ? 0 : 1;
}

/* `name lookup <name>` / `name of <fp128>`. */
static int cmd_name_query(const char *server_ip, uint16_t server_port,
                          int is_of, const char *arg) {
    char lname[DNAC_NAME_MAX_LEN + 1];
    if (!is_of) {
        if (nodus_v2_name_normalize(arg, lname) != 0) {
            fprintf(stderr, "a name is 3-36 of a-z0-9 (an all-hex name of 8+ "
                    "characters is never a name)\n");
            return 1;
        }
    } else if (strlen(arg) != 128) {
        fprintf(stderr, "the owner is 128 hex characters (a fingerprint)\n");
        return 1;
    }
    char lowfp[129];
    if (is_of) {
        for (int i = 0; i < 128; i++) {
            char c = arg[i];
            lowfp[i] = (c >= 'A' && c <= 'F') ? (char)(c - 'A' + 'a') : c;
        }
        lowfp[128] = '\0';
    }
    nodus_client_t client;
    if (t8_session(&client, server_ip, server_port) != 0) return 1;
    nodus_dnac_name_result_t r;
    int qrc = is_of ? nodus_client_dnac_name_of(&client, lowfp, &r)
                    : nodus_client_dnac_name_lookup(&client, lname, &r);
    nodus_client_close(&client);
    if (qrc != 0) {
        fprintf(stderr, "%s failed (rc=%d)\n",
                is_of ? "dnac_name_of" : "dnac_name_lookup", qrc);
        return 1;
    }
    if (!r.found) {
        printf("%s: not registered (committed height %llu)\n",
               is_of ? lowfp : lname,
               (unsigned long long)r.committed_height);
        return 2;
    }
    if (is_of)
        printf("name=%s registered_height=%llu committed_height=%llu\n",
               r.name, (unsigned long long)r.registered_height,
               (unsigned long long)r.committed_height);
    else
        printf("owner=%s registered_height=%llu committed_height=%llu\n",
               r.owner, (unsigned long long)r.registered_height,
               (unsigned long long)r.committed_height);
    return 0;
}

/* `name register <name> --keys <dir> (--dry-run | --submit ip:port)
 *  [--fee <raw>]`: ONE CORE NAME_REGISTER envelope, owner = the --keys
 * identity (its one signature), paid from its own native coins. The
 * price comes from dnac_fee_info's "np" at tip + 1 and is declared in the
 * call; the network fee is the floor (or units × gas price). Generation 2
 * only: on a node still at generation 1 it refuses before building. */
static int cmd_name_register(const char *server_ip, uint16_t server_port,
                             int argc, char **argv, int cmd_start) {
    const char *keys_csv = NULL, *submit = NULL, *raw_name = NULL;
    uint64_t fee = 0;
    int dry_run = 0, have_fee = 0, bad_arg = 0;

    for (int i = cmd_start + 2; i < argc; i++) {  /* skip "name register" */
        const char *a = argv[i];
        char *end = NULL;
        if      (!strcmp(a, "--keys")   && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--submit") && i + 1 < argc) submit   = argv[++i];
        else if (!strcmp(a, "--fee")    && i + 1 < argc) {
            const char *v = argv[++i];
            if (v[0] < '0' || v[0] > '9') { bad_arg = 1; break; }
            errno = 0;
            fee = strtoull(v, &end, 10);
            if (!end || *end != '\0' || errno == ERANGE) { bad_arg = 1; break; }
            have_fee = 1;
        } else if (!strcmp(a, "--dry-run")) dry_run = 1;
        else if (a[0] != '-' && !raw_name) raw_name = a;
        else { bad_arg = 1; break; }
    }
    if (bad_arg || !keys_csv || !raw_name || (!submit && !dry_run)) {
        fprintf(stderr,
            "Usage: name register <name> --keys <keydir> "
            "(--dry-run | --submit ip:port) [--fee <raw>]\n"
            "  Registers <name> (3-36 of a-z0-9, lower-cased ASCII-only) to "
            "the --keys\n"
            "  identity: first come, one name per ID, permanent. Pays the "
            "price for the\n"
            "  name's length (dnac_fee_info) into the reward pool, plus the "
            "network fee.\n");
        return 1;
    }
    char name[DNAC_NAME_MAX_LEN + 1];
    if (nodus_v2_name_normalize(raw_name, name) != 0) {
        fprintf(stderr, "a name is 3-36 of a-z0-9 (an all-hex name of 8+ "
                "characters is never a name)\n");
        return 1;
    }
    const size_t name_len = strlen(name);

    int rc = 1, connected = 0, utxos_valid = 0;
    nodus_identity_t *keys = NULL;
    nodus_v2_name_coin_t *coins = NULL;
    nodus_v2_name_built_t built;
    memset(&built, 0, sizeof(built));
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));
    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    const nodus_domain_runtime_t *core_rt = NULL, *sys_rt = NULL;

    keys = calloc(4, sizeof(*keys));
    if (!keys) return 1;
    if (act_load_keys(keys_csv, keys, 4) != 1) {
        fprintf(stderr, "name register needs exactly one --keys identity\n");
        goto done;
    }
    uint8_t owner_raw[64];
    char owner_fp[QGP_FP_HEX_BUFFER];
    if (qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, owner_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(owner_raw, owner_fp);

    {
        char sip[64];
        uint16_t sport = 0;
        if (t6_resolve_target(submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target (and no -s server)\n");
            goto done;
        }
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
        cfg.servers[0].port = sport;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &keys[0]) != 0) goto done;
        connected = 1;
        if (nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
            goto done;
        }
    }
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    {
        bool has = false;
        if (nodus_client_dnac_chain_id32(&client, &has, chain32) != 0 ||
            !has) {
            fprintf(stderr, "this node is not on a version-3 chain\n");
            goto done;
        }
    }
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;
    if (core_rt->generation < NODUS_RT_GEN_2) {
        fprintf(stderr, "the node still runs rule-set generation %u — names "
                "open at its RULESET_GEN2 height%s; nothing was built\n",
                (unsigned)core_rt->generation,
                g_cli_ri.gen2_height ? "" : " (no vote committed yet)");
        goto done;
    }
    {
        nodus_dnac_name_result_t taken;
        int nrc = nodus_client_dnac_name_lookup(&client, name, &taken);
        if (nrc != 0) {
            fprintf(stderr, "dnac_name_lookup failed (rc=%d)\n", nrc);
            goto done;
        }
        if (taken.found) {
            fprintf(stderr, "%s is already registered (owner %.16s...) — "
                    "nothing was built\n", name, taken.owner);
            goto done;
        }
        nodus_dnac_name_result_t mine;
        nrc = nodus_client_dnac_name_of(&client, owner_fp, &mine);
        if (nrc != 0) {
            fprintf(stderr, "dnac_name_of failed (rc=%d)\n", nrc);
            goto done;
        }
        if (mine.found) {
            fprintf(stderr, "this ID already holds the name %s (one name per "
                    "ID) — nothing was built\n", mine.name);
            goto done;
        }
    }
    uint64_t price = 0, gas_price = 0;
    {
        nodus_dnac_name_prices_t np;
        int prc = nodus_client_dnac_name_prices(&client, &np);
        if (prc != 0) {
            fprintf(stderr, "dnac_fee_info carries no name prices (rc=%d) — "
                    "refusing to guess a price\n", prc);
            goto done;
        }
        if (nodus_v2_name_price_for(np.price, name_len, &price) != 0)
            goto done;
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        int frc = nodus_client_dnac_fee_info(&client, &fi);
        if (frc != 0) {
            fprintf(stderr, "dnac_fee_info failed (rc=%d)\n", frc);
            goto done;
        }
        gas_price = fi.gas_price;
        uint64_t floor_fee = DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                                 ? DNAC_MIN_FEE_RAW : NODUS_W_BASE_TX_FEE;
        if (have_fee && fee < floor_fee) {
            fprintf(stderr, "--fee %llu is below the network fee floor %llu "
                    "raw\n", (unsigned long long)fee,
                    (unsigned long long)floor_fee);
            goto done;
        }
        if (!have_fee) fee = floor_fee;
    }

    int urc = nodus_client_dnac_utxo(&client, owner_fp,
                                     NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
    if (urc != 0) {
        fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
        goto done;
    }
    utxos_valid = 1;
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        fprintf(stderr, "the node reported tip 0 — refusing to anchor an "
                "expiry on it\n");
        goto done;
    }
    /* the listed rows as they are; the shared builder applies the filter
     * (zero / non-native / locked at tip + 1), the largest-first
     * selection, the call layout and the fee fixed point */
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    for (int i = 0; i < utxos.count; i++) {
        const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
        memcpy(coins[i].nul, e->nullifier, 64);
        coins[i].amount = e->amount;
        memcpy(coins[i].token, e->token_id, 64);
        coins[i].unlock_block = e->unlock_block;
    }

    nodus_v2_ruleset_id_t rs;
    cli_ruleset_id(core_rt, sys_rt, &rs);
    nodus_v2_name_req_t req;
    memset(&req, 0, sizeof(req));
    if (cli_env_expiry(tip, &req.expiry_height) != 0) goto done;
    req.rs        = &rs;
    req.chain32   = chain32;
    req.tip       = tip;
    req.pk        = keys[0].pk.bytes;
    req.sk        = keys[0].sk.bytes;
    req.name      = name;
    req.price     = price;
    req.fee       = fee;
    req.fee_fixed = have_fee;
    req.gas_price = gas_price;
    req.coins     = coins;
    req.n_coins   = utxos.count;
    req.rand      = cli_rand;
    req.rand_ctx  = NULL;
    nodus_v2_name_err_t ne;
    int brc = nodus_v2_name_build(&req, &built, &ne);
    if (brc != NODUS_V2_SPEND_OK) {
        switch (brc) {
        case NODUS_V2_SPEND_ERR_INSUFFICIENT:
        case NODUS_V2_SPEND_ERR_MAX_INPUTS:
        case NODUS_V2_SPEND_ERR_INPUT_SUM:
            fprintf(stderr, "cannot fund price %llu + fee %llu raw from at "
                    "most %u unlocked native coin(s) (%d listed) — nothing "
                    "was submitted\n", (unsigned long long)price,
                    (unsigned long long)ne.fee, (unsigned)NODUS_V2_NAME_MAX_IN,
                    ne.n_eligible);
            break;
        case NODUS_V2_SPEND_ERR_OVERFLOW:
            fprintf(stderr, "fee + price overflows u64\n");
            break;
        case NODUS_V2_SPEND_ERR_METER:
            fprintf(stderr, "could not size res_max_total_units\n");
            break;
        case NODUS_V2_SPEND_ERR_FEE_BELOW_GAS:
            fprintf(stderr, "--fee %llu is below units %llu x gas price %llu "
                    "= %llu raw — nothing was submitted\n",
                    (unsigned long long)ne.fee, (unsigned long long)ne.units,
                    (unsigned long long)ne.gas_price,
                    (unsigned long long)ne.required);
            break;
        case NODUS_V2_NAME_ERR_FEE_FLOOR:
            fprintf(stderr, "--fee %llu is below the network fee floor %llu "
                    "raw\n", (unsigned long long)ne.fee,
                    (unsigned long long)ne.floor);
            break;
        case NODUS_V2_SPEND_ERR_PREFLIGHT1:
            fprintf(stderr, "pass-1 preflight failed\n");
            break;
        case NODUS_V2_SPEND_ERR_SIGN:
            fprintf(stderr, "leg %d signature failed\n", ne.leg);
            break;
        case NODUS_V2_SPEND_ERR_PREFLIGHT2:
            fprintf(stderr, "pass-2 preflight (self-check) failed\n");
            break;
        default:
            fprintf(stderr, "the name registration could not be built "
                    "(rc=%d) — nothing was submitted\n", brc);
            break;
        }
        goto done;
    }
    printf("name register: %s -> %.16s... price=%llu fee=%llu inputs=%d "
           "change=%llu units=%llu expiry=%llu generation=%u\n", name,
           owner_fp, (unsigned long long)built.price,
           (unsigned long long)built.fee, built.n_in,
           (unsigned long long)built.change, (unsigned long long)built.units,
           (unsigned long long)built.dec.expiry_height,
           (unsigned)core_rt->generation);
    printf("  wire_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.wire_id[b]);
    printf("\n  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.intent_id[b]);
    printf("\n");
    fflush(stdout);
    if (dry_run) {
        printf("  PREFLIGHT SELF-CHECK: OK (1 leg CORE NAME_REGISTER) — not "
               "submitted (--dry-run)\n");
    } else if (t6_submit_on(&client, &keys[0], built.wire_id, built.env,
                            (uint32_t)built.env_len) != 0) {
        goto done;
    }
    rc = 0;

done:
    nodus_v2_name_built_free(&built);
    free(coins);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* ══ General multisig — the offline M-of-N flow (design F6.1) ═══════════
 *
 * Decision docs/plans/decisions/2026-09-29-general-multisig.md; design
 * docs/plans/2026-09-29-general-multisig-design.md §7 rev 2. The chain
 * side is the SPECIFICATION: a coin owned by an M-of-N address
 * (SHA3-512 of a shared/dnac/msig_wire.h descriptor) is spent by a CORE
 * leg carrying auth_kind 3 = the kind-1 signer section ‖ dcount ‖
 * (dlen ‖ descriptor) (nodus_witness_rt_native.c rtn_auth_msig), with
 * >= M of the descriptor's keys among the verified signers
 * (rtn_input_owned). Every signer signs the SAME leg auth digest a
 * kind-1 signer would — there is no multisig signature preimage.
 *
 * Because auth_len is bound by the digest, the FINAL signer count K must
 * be fixed before anyone signs (runtime.h "COORDINATION NOTE"): the
 * builder writes it into the unsigned envelope (default K = M), and
 * `combine` refuses any other number of signatures.
 *
 * FOUR STEPS, three of them offline:
 *   1. msig address --m <M> --pubkey <file> ... [--descriptor-out <file>]
 *      prints the address (128 hex) of M-of-{the listed keys}; pubkey
 *      files are raw 2592-byte ML-DSA-87 keys (an identity's nodus.pk).
 *      The keys are sorted into the one canonical order; the operator
 *      never orders them by hand.
 *   2. v2-envelope spend --msig <descriptor> --keys <dir> --in <nul>:<amt>
 *      ... --to <fp> --amount <raw> --export <file>
 *      builds the UNSIGNED single-leg SPEND. The coins are named
 *      explicitly (--in nullifier:amount, native only): dnac_utxo answers
 *      only for the session's own fingerprint, so a multisig address's
 *      coins cannot be listed over a session — the chain checks every
 *      input anyway (present, unlocked, owned, conservation). --keys is
 *      ANY identity: it opens the session that reads the chain id, the
 *      tip and the gas price; it signs nothing. Change returns to the
 *      multisig address.
 *   3. msig sign --keys <dir> --in <export> --out <sigfile>
 *      (offline, each co-signer) re-derives the leg digest from the
 *      envelope bytes + chain id + the compiled CORE ruleset and REFUSES
 *      if it differs from the exported one, checks its key is in the
 *      descriptor, REFUSES a SPEND call whose length does not match its
 *      own counts, prints what it is signing (every input's full
 *      nullifier, every output's owner, amount and token id) with a
 *      WARNING that the input owners were NOT verified (no RPC answers
 *      an address's coins without its session key), and signs.
 *   4. msig combine --in <export> --sig <file> ... [--keys <dir>
 *      --submit ip:port] [--out <envelope file>]
 *      verifies every signature, assembles them in ascending pubkey
 *      order, runs the chain's OWN auth hook locally (the satisfied flag
 *      must be 1) and the preflight self-check, then submits (any
 *      session identity) or writes the envelope.
 * ════════════════════════════════════════════════════════════════════ */

/* The four steps' bodies — descriptor from keys, the unsigned build, the
 * export / signature texts, the read-back, the per-signature checks and
 * the assembly — live in the shared library nodus/src/client/
 * nodus_v2_msig.{c,h} (the web wallet's WASM module compiles the same
 * file). What stays here: argument parsing, file I/O, the session, the
 * messages, and the chain's own auth hook run on the assembled envelope
 * (witness code). */
#define MSIG_EXPORT_MAGIC NODUS_V2_MSIG_EXPORT_MAGIC
#define MSIG_SIG_MAGIC    NODUS_V2_MSIG_SIG_MAGIC

/* Read a whole file (at most `max` bytes). @return 0 / -1. */
static int msig_read_file(const char *path, uint8_t **out, size_t *len,
                          size_t max) {
    *out = NULL;
    *len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return -1; }
    uint8_t *buf = malloc(max + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, max + 1, f);
    fclose(f);
    if (n > max) {
        fprintf(stderr, "%s is larger than %zu bytes\n", path, max);
        free(buf);
        return -1;
    }
    *out = buf;
    *len = n;
    return 0;
}

/* Write `len` bytes of text to `path` (export / signature files).
 * @return 0 / -1 (message printed). */
static int msig_write_text(const char *path, const char *text, size_t len) {
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "cannot write %s\n", path); return -1; }
    int ok = fwrite(text, 1, len, f) == len;
    if (fclose(f) != 0) ok = 0;
    if (!ok) fprintf(stderr, "cannot write %s\n", path);
    return ok ? 0 : -1;
}

/* Read and parse an export file (nodus_v2_msig_export_parse). `x->env` is
 * heap (nodus_v2_msig_export_free). @return 0 / -1 (message printed). */
static int msig_export_read(const char *path, nodus_v2_msig_export_t *x) {
    memset(x, 0, sizeof(*x));
    uint8_t *raw = NULL;
    size_t rl = 0;
    /* hex doubles the envelope; a 1 MiB envelope is the chain's ceiling */
    if (msig_read_file(path, &raw, &rl,
                       2u * (size_t)DNA_ENV_MAX_TOTAL_LEN + 4096u) != 0)
        return -1;
    raw[rl] = '\0';
    int rc = -1;
    if (strncmp((const char *)raw, MSIG_EXPORT_MAGIC "\n",
                strlen(MSIG_EXPORT_MAGIC) + 1) != 0)
        fprintf(stderr, "%s is not a %s file\n", path, MSIG_EXPORT_MAGIC);
    else if (nodus_v2_msig_export_parse((const char *)raw, rl, x) !=
             NODUS_V2_SPEND_OK)
        fprintf(stderr, "%s: a missing or malformed chain_id, tip, signers, "
                "digest or envelope line\n", path);
    else
        rc = 0;
    free(raw);
    return rc;
}

/* The kind-3 leg of an export (nodus_v2_msig_leg_open). `v` is heap.
 * @return 0 / -1 (message printed). */
static int msig_leg_open(const nodus_v2_msig_export_t *x, dna_env_view_t *v,
                         nodus_v2_msig_leg_t *leg) {
    int rc = nodus_v2_msig_leg_open(x, v, leg);
    if (rc == NODUS_V2_MSIG_ERR_SHAPE)
        fprintf(stderr, "the export is not a one-leg CORE SPEND under "
                "auth_kind 3 carrying %u signer slots and ONE descriptor\n",
                (unsigned)x->signers);
    else if (rc != NODUS_V2_SPEND_OK)
        fprintf(stderr, "the carried descriptor is malformed\n");
    return rc == NODUS_V2_SPEND_OK ? 0 : -1;
}

/* HF-4: the export was built for ONE generation (cli_select_runtimes on
 * the exporter's session); its CORE leg names that ruleset_version.
 * @return the compiled CORE entry, or NULL (message printed). */
static const nodus_domain_runtime_t *
msig_core_rt(const nodus_v2_msig_export_t *x) {
    const nodus_domain_runtime_t *core_rt =
        cli_core_runtime_for_env(x->env, x->env_len);
    if (!core_rt)
        fprintf(stderr, "the exported envelope's CORE leg names a ruleset "
                "version this CLI does not carry\n");
    return core_rt;
}

/* The CORE leg digest of the exported envelope, re-derived
 * (nodus_v2_msig_digest). @return 0 / -1 (message printed). */
static int msig_digest(const nodus_v2_msig_export_t *x,
                       dna_env_preflight_t *pf) {
    const nodus_domain_runtime_t *core_rt = msig_core_rt(x);
    if (!core_rt) return -1;
    if (nodus_v2_msig_digest(x, core_rt->ruleset_version,
                             core_rt->ruleset_hash, pf) != NODUS_V2_SPEND_OK) {
        fprintf(stderr, "preflight of the exported envelope failed (wrong "
                "chain id, expired, or a different CORE ruleset)\n");
        return -1;
    }
    return 0;
}

/* `msig address` — offline. */
static int cmd_msig_address(int argc, char **argv, int cmd_start) {
    const char *pk_path[DNA_MSIG_MAX_N + 1];
    const char *desc_out = NULL;
    int n_pk = 0, bad = 0;
    long m = 0;
    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--m") && i + 1 < argc) m = strtol(argv[++i], NULL, 10);
        else if (!strcmp(a, "--pubkey") && i + 1 < argc) {
            if (n_pk > (int)DNA_MSIG_MAX_N) { bad = 1; break; }
            pk_path[n_pk++] = argv[++i];
        } else if (!strcmp(a, "--descriptor-out") && i + 1 < argc)
            desc_out = argv[++i];
        else { bad = 1; break; }
    }
    if (bad || n_pk < (int)DNA_MSIG_MIN_N || n_pk > (int)DNA_MSIG_MAX_N ||
        m < 1 || m > n_pk) {
        fprintf(stderr,
            "Usage: msig address --m <M> --pubkey <file> --pubkey <file> ... "
            "[--descriptor-out <file>]\n"
            "  2..%u raw 2592-byte ML-DSA-87 public keys (an identity's "
            "nodus.pk), 1 <= M <= N.\n"
            "  Prints the M-of-N address (128 hex) the chain derives: "
            "SHA3-512(\"NDS.MSIG.v1\" ‖ M ‖ N ‖ keys ascending).\n",
            (unsigned)DNA_MSIG_MAX_N);
        return 1;
    }
    uint8_t keys[DNA_MSIG_MAX_N * DNA_MSIG_PUBKEY_LEN];
    for (int i = 0; i < n_pk; i++) {
        uint8_t *b = NULL;
        size_t l = 0;
        if (msig_read_file(pk_path[i], &b, &l, DNA_MSIG_PUBKEY_LEN) != 0)
            return 1;
        if (l != DNA_MSIG_PUBKEY_LEN) {
            fprintf(stderr, "%s: %zu bytes, a public key is %u\n",
                    pk_path[i], l, (unsigned)DNA_MSIG_PUBKEY_LEN);
            free(b);
            return 1;
        }
        memcpy(keys + (size_t)i * DNA_MSIG_PUBKEY_LEN, b, DNA_MSIG_PUBKEY_LEN);
        free(b);
    }
    /* sorted into the one canonical order, encoded, hashed — the shared
     * library (the web wallet's vaults derive with the same call) */
    uint8_t desc[DNA_MSIG_MAX_DESC_LEN], addr[64];
    size_t dl = 0;
    int drc = nodus_v2_msig_desc_from_keys((uint8_t)m, (uint8_t)n_pk, keys,
                                           desc, sizeof(desc), &dl, addr);
    if (drc == NODUS_V2_MSIG_ERR_DESC) {
        fprintf(stderr, "refused: a duplicate key, or a key whose first 32 "
                "bytes are zero\n");
        return 1;
    }
    if (drc != NODUS_V2_SPEND_OK) return 1;
    char hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(addr, hex);
    printf("msig %ld-of-%d address %s\n", m, n_pk, hex);
    if (desc_out) {
        FILE *f = fopen(desc_out, "wb");
        if (!f || fwrite(desc, 1, dl, f) != dl) {
            fprintf(stderr, "cannot write %s\n", desc_out);
            if (f) fclose(f);
            return 1;
        }
        fclose(f);
        printf("descriptor (%zu bytes) written to %s\n", dl, desc_out);
    }
    return 0;
}

/* `v2-envelope spend --msig` — builds the UNSIGNED envelope + export. */
static int cmd_v2_spend_msig(const char *server_ip, uint16_t server_port,
                             int argc, char **argv, int cmd_start) {
    const char *desc_path = NULL, *keys_csv = NULL, *to_hex = NULL;
    const char *export_path = NULL, *submit = NULL;
    const char *in_arg[NODUS_V2_SPEND_MAX_IN];
    int n_in = 0, bad = 0, have_fee = 0;
    uint64_t amount = 0, fee = 0;
    long k_signers = 0;
    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--msig")   && i + 1 < argc) desc_path = argv[++i];
        else if (!strcmp(a, "--keys")   && i + 1 < argc) keys_csv  = argv[++i];
        else if (!strcmp(a, "--to")     && i + 1 < argc) to_hex    = argv[++i];
        else if (!strcmp(a, "--export") && i + 1 < argc) export_path = argv[++i];
        else if (!strcmp(a, "--submit") && i + 1 < argc) submit    = argv[++i];
        else if (!strcmp(a, "--amount") && i + 1 < argc)
            amount = strtoull(argv[++i], NULL, 10);
        else if (!strcmp(a, "--fee") && i + 1 < argc) {
            fee = strtoull(argv[++i], NULL, 10); have_fee = 1;
        } else if (!strcmp(a, "--signers") && i + 1 < argc)
            k_signers = strtol(argv[++i], NULL, 10);
        else if (!strcmp(a, "--in") && i + 1 < argc) {
            if (n_in >= (int)NODUS_V2_SPEND_MAX_IN) { bad = 1; break; }
            in_arg[n_in++] = argv[++i];
        } else { bad = 1; break; }
    }
    if (bad || !desc_path || !keys_csv || !to_hex || !export_path ||
        n_in < 1 || amount == 0) {
        fprintf(stderr,
            "Usage: v2-envelope spend --msig <descriptor-file> --keys <dir>\n"
            "         --in <nullifier128hex>:<amount> [--in ...] (1..%u native "
            "coins of the multisig address)\n"
            "         --to <fp128hex> --amount <raw> [--fee <raw>] "
            "[--signers <K>]\n"
            "         --export <file> [--submit ip:port]\n"
            "  Builds the UNSIGNED CORE SPEND (auth_kind 3) and writes the "
            "export file\n"
            "  for `msig sign`. --keys opens the session (chain id, tip, gas "
            "price) and\n"
            "  signs nothing. K (default M) is FINAL: combine needs exactly K "
            "signatures.\n"
            "  Change goes back to the multisig address.\n",
            (unsigned)NODUS_V2_SPEND_MAX_IN);
        return 1;
    }

    int rc = 1;
    uint8_t *dbuf = NULL;
    char *export_text = NULL;
    nodus_identity_t *keys = NULL;
    nodus_v2_msig_built_t built;
    memset(&built, 0, sizeof(built));
    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    int connected = 0, utxos_valid = 0;
    nodus_dnac_utxo_result_t utxos;
    memset(&utxos, 0, sizeof(utxos));

    size_t dlen = 0;
    uint8_t m = 0, n = 0, addr[64];
    if (msig_read_file(desc_path, &dbuf, &dlen, DNA_MSIG_MAX_DESC_LEN) != 0)
        goto done;
    if (dna_msig_desc_parse(dbuf, dlen, &m, &n, NULL) != 0 ||
        dna_msig_address(dbuf, dlen, addr) != 0) {
        fprintf(stderr, "%s is not a valid multisig descriptor\n", desc_path);
        goto done;
    }
    /* argv check before any session (the library refuses the same range,
     * NODUS_V2_MSIG_ERR_SIGNERS) */
    if (k_signers == 0) k_signers = m;
    if (k_signers < m || k_signers > n) {
        fprintf(stderr, "--signers must be in [M=%u, N=%u]\n",
                (unsigned)m, (unsigned)n);
        goto done;
    }
    char addr_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(addr, addr_hex);
    uint8_t to_raw[64];
    if (qgp_fp_hex_to_raw(to_hex, to_raw) != 0) {
        fprintf(stderr, "--to must be exactly 128 lowercase hex chars\n");
        goto done;
    }

    /* inputs: nullifier:amount (the library sorts them for the wire and
     * refuses a duplicate) */
    nodus_v2_coin_t ins[NODUS_V2_SPEND_MAX_IN];
    memset(ins, 0, sizeof(ins));
    uint64_t sum_in = 0;
    for (int i = 0; i < n_in; i++) {
        const char *c = strchr(in_arg[i], ':');
        if (!c || (size_t)(c - in_arg[i]) != 128) {
            fprintf(stderr, "--in must be <nullifier 128 hex>:<amount>\n");
            goto done;
        }
        char nh[129];
        memcpy(nh, in_arg[i], 128);
        nh[128] = '\0';
        if (t6_hex_exact(nh, ins[i].nul, 64) != 0) {
            fprintf(stderr, "--in nullifier is not 128 lowercase hex\n");
            goto done;
        }
        ins[i].amount = strtoull(c + 1, NULL, 10);
        if (ins[i].amount == 0 || sum_in > UINT64_MAX - ins[i].amount) {
            fprintf(stderr, "--in amount must be >= 1 (and the sum fit "
                    "u64)\n");
            goto done;
        }
        sum_in += ins[i].amount;
    }
    /* the fee floor max(DNAC_MIN_FEE_RAW, NODUS_W_BASE_TX_FEE) and a
     * duplicate --in are the library's refusals, reported after the build
     * below */

    const nodus_domain_runtime_t *core_rt = cli_builtin_runtime(DNA_DOMAIN_CORE, NODUS_RT_GEN_1);
    const nodus_domain_runtime_t *sys_rt  = cli_builtin_runtime(DNA_DOMAIN_SYSTEM, NODUS_RT_GEN_1);
    if (!core_rt || !sys_rt || !sys_rt->meter_policy) goto done;

    /* ── the session (chain id, tip, gas price) — it signs nothing ─── */
    keys = calloc(4, sizeof(*keys));
    if (!keys || act_load_keys(keys_csv, keys, 4) != 1) {
        fprintf(stderr, "--msig needs exactly one --keys identity (the "
                "session)\n");
        goto done;
    }
    char sip[64];
    uint16_t sport = 0;
    if (t6_resolve_target(submit, server_ip, server_port, sip, &sport) != 0) {
        fprintf(stderr, "invalid --submit target (and no -s server)\n");
        goto done;
    }
    nodus_client_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
    cfg.servers[0].port = sport;
    cfg.server_count    = 1;
    cfg.auto_reconnect  = false;
    if (nodus_client_init(&client, &cfg, &keys[0]) != 0) goto done;
    connected = 1;
    if (nodus_client_connect(&client) != 0) {
        fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
        goto done;
    }
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    bool has_chain32 = false;
    if (nodus_client_dnac_chain_id32(&client, &has_chain32, chain32) != 0 ||
        !has_chain32) {
        fprintf(stderr, "this node is not on a version-3 chain\n");
        goto done;
    }
    /* HF-4: build for the generation the node names */
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;
    uint64_t gas_price = 0;
    {
        nodus_dnac_fee_info_t fi;
        memset(&fi, 0, sizeof(fi));
        if (nodus_client_dnac_fee_info(&client, &fi) != 0) {
            fprintf(stderr, "dnac_fee_info query failed — the gas price is "
                    "unknown, refusing to size a fee\n");
            goto done;
        }
        gas_price = fi.gas_price;
    }
    /* the tip rides the session's own dnac_utxo reply (its coins are not
     * used) — the same source `v2-envelope spend` anchors expiry on */
    if (nodus_client_dnac_utxo(&client, keys[0].fingerprint, 1, &utxos) != 0) {
        fprintf(stderr, "dnac_utxo (tip) query failed\n");
        goto done;
    }
    utxos_valid = 1;
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        fprintf(stderr, "the node reported tip 0 — refusing\n");
        goto done;
    }

    /* ── build: the shared library (fee fixed point, at most 3 passes;
     *    pass-1 digest) ─────────────────────────────────────────────────── */
    uint64_t expiry = 0;
    if (cli_env_expiry(tip, &expiry) != 0) goto done;
    nodus_v2_ruleset_id_t rs;
    cli_ruleset_id(core_rt, sys_rt, &rs);
    nodus_v2_msig_build_req_t breq;
    memset(&breq, 0, sizeof(breq));
    breq.rs            = &rs;
    breq.chain32       = chain32;
    breq.tip           = tip;
    breq.expiry_height = expiry;
    breq.desc          = dbuf;
    breq.desc_len      = dlen;
    breq.coins         = ins;
    breq.n_coins       = n_in;
    breq.to_fp         = to_raw;
    breq.amount        = amount;
    breq.fee           = fee;
    breq.fee_fixed     = have_fee;
    breq.gas_price     = gas_price;
    breq.signers       = (uint32_t)k_signers;
    breq.rand          = cli_rand;
    nodus_v2_spend_err_t berr;
    int brc = nodus_v2_msig_build(&breq, &built, &berr);
    if (brc != NODUS_V2_SPEND_OK) {
        if (brc == NODUS_V2_SPEND_ERR_INSUFFICIENT)
            fprintf(stderr, "the inputs (%llu) do not cover amount %llu + "
                    "fee %llu\n", (unsigned long long)sum_in,
                    (unsigned long long)amount, (unsigned long long)berr.fee);
        else if (brc == NODUS_V2_MSIG_ERR_COIN)
            fprintf(stderr, "duplicate --in nullifier\n");
        else if (brc == NODUS_V2_MSIG_ERR_FEE_FLOOR)
            fprintf(stderr, "--fee is below the chain's floor %llu\n",
                    (unsigned long long)(DNAC_MIN_FEE_RAW > NODUS_W_BASE_TX_FEE
                                         ? DNAC_MIN_FEE_RAW
                                         : NODUS_W_BASE_TX_FEE));
        else if (brc == NODUS_V2_MSIG_ERR_SIGNERS)
            fprintf(stderr, "--signers must be in [M=%u, N=%u]\n",
                    (unsigned)m, (unsigned)n);
        else if (brc == NODUS_V2_SPEND_ERR_METER)
            fprintf(stderr, "could not size res_max_total_units\n");
        else if (brc == NODUS_V2_SPEND_ERR_FEE_BELOW_GAS)
            fprintf(stderr, "fee %llu is below the gas-price requirement "
                    "%llu (%llu units x %llu)\n",
                    (unsigned long long)berr.fee,
                    (unsigned long long)berr.required,
                    (unsigned long long)berr.units,
                    (unsigned long long)gas_price);
        else if (brc == NODUS_V2_SPEND_ERR_PREFLIGHT1)
            fprintf(stderr, "preflight of the exported envelope failed (wrong "
                    "chain id, expired, or a different CORE ruleset)\n");
        else
            fprintf(stderr, "building the multisig envelope failed (rc=%d)\n",
                    brc);
        goto done;
    }

    size_t export_len = 0;
    if (nodus_v2_msig_export_encode(chain32, tip, built.signers, built.digest,
                                    built.env, built.env_len, &export_text,
                                    &export_len) != NODUS_V2_SPEND_OK ||
        msig_write_text(export_path, export_text, export_len) != 0)
        goto done;

    printf("v2-envelope spend --msig: %u-of-%u address %.16s... inputs=%d "
           "sum_in=%llu amount=%llu fee=%llu change=%llu units=%llu "
           "signers=%ld expiry=%llu\n", (unsigned)built.m, (unsigned)built.n,
           addr_hex, built.n_in, (unsigned long long)built.sum_in,
           (unsigned long long)amount, (unsigned long long)built.fee,
           (unsigned long long)built.change, (unsigned long long)built.units,
           (long)built.signers, (unsigned long long)expiry);
    printf("  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", built.intent_id[b]);
    printf("\n  digest=");
    for (int b = 0; b < 64; b++) printf("%02x", built.digest[b]);
    printf("\n  export written to %s — next: `msig sign` by %ld co-signers, "
           "then `msig combine` before block %llu\n", export_path,
           (long)built.signers, (unsigned long long)expiry);
    rc = 0;

done:
    free(dbuf);
    free(export_text);
    nodus_v2_msig_built_free(&built);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* `msig sign` — offline, one co-signer. */
static int cmd_msig_sign(int argc, char **argv, int cmd_start) {
    const char *keys_csv = NULL, *in_path = NULL, *out_path = NULL;
    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--keys") && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--in")   && i + 1 < argc) in_path  = argv[++i];
        else if (!strcmp(a, "--out")  && i + 1 < argc) out_path = argv[++i];
        else { keys_csv = NULL; break; }
    }
    if (!keys_csv || !in_path || !out_path) {
        fprintf(stderr, "Usage: msig sign --keys <dir> --in <export> --out "
                "<sigfile>\n");
        return 1;
    }
    int rc = 1;
    nodus_identity_t *keys = calloc(4, sizeof(*keys));
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    nodus_v2_msig_review_t *rv = calloc(1, sizeof(*rv));
    nodus_v2_msig_export_t x;
    memset(&x, 0, sizeof(x));
    char *sig_text = NULL;
    if (!keys || !pf || !rv) goto done;
    if (act_load_keys(keys_csv, keys, 4) != 1) {
        fprintf(stderr, "msig sign needs exactly one --keys identity\n");
        goto done;
    }
    if (msig_export_read(in_path, &x) != 0) goto done;
    const nodus_domain_runtime_t *core_rt = msig_core_rt(&x);
    if (!core_rt) goto done;
    /* the read-back: shape, membership, the digest re-derived and EQUAL
     * (never sign a digest you did not derive yourself), the call's
     * lengths — the shared library, in the order this command had */
    int vrc = nodus_v2_msig_review(&x, core_rt->ruleset_version,
                                   core_rt->ruleset_hash, keys[0].pk.bytes,
                                   pf, rv);
    if (vrc != NODUS_V2_SPEND_OK) {
        if (vrc == NODUS_V2_MSIG_ERR_SHAPE)
            fprintf(stderr, "the export is not a one-leg CORE SPEND under "
                    "auth_kind 3 carrying %u signer slots and ONE "
                    "descriptor\n", (unsigned)x.signers);
        else if (vrc == NODUS_V2_MSIG_ERR_DESC)
            fprintf(stderr, "the carried descriptor is malformed\n");
        else if (vrc == NODUS_V2_MSIG_ERR_NOT_MEMBER)
            fprintf(stderr, "this key is not one of the descriptor's keys\n");
        else if (vrc == NODUS_V2_SPEND_ERR_PREFLIGHT1)
            fprintf(stderr, "preflight of the exported envelope failed (wrong "
                    "chain id, expired, or a different CORE ruleset)\n");
        else if (vrc == NODUS_V2_MSIG_ERR_DIGEST)
            fprintf(stderr, "REFUSED: the exported digest is not the digest "
                    "of the exported envelope on this chain\n");
        else if (vrc == NODUS_V2_MSIG_ERR_CALL)
            fprintf(stderr, "REFUSED: the exported CORE SPEND call is "
                    "malformed (its length does not match its inputs and "
                    "outputs, or an owner is not 128 lowercase hex)\n");
        else if (vrc == NODUS_V2_MSIG_ERR_EXPIRY)
            fprintf(stderr, "REFUSED: the export never expires, or expires "
                    "later than its tip %llu + %u blocks\n",
                    (unsigned long long)x.tip,
                    (unsigned)NODUS_V2_MSIG_EXPIRY_AHEAD);
        else
            fprintf(stderr, "the export could not be read back (rc=%d)\n",
                    vrc);
        goto done;
    }
    {
        char ah[QGP_FP_HEX_BUFFER];
        qgp_fp_raw_to_hex(rv->addr, ah);
        printf("signing a CORE SPEND from %u-of-%u address %s: "
               "%u input(s), fee %llu\n", (unsigned)rv->m, (unsigned)rv->n,
               ah, (unsigned)rv->n_in, (unsigned long long)rv->fee);
        printf("  valid until block %llu (built at tip %llu)\n",
               (unsigned long long)rv->expiry_height,
               (unsigned long long)rv->tip);
        for (int i = 0; i < rv->n_in; i++) {
            char nh[129];
            qgp_fp_raw_to_hex(rv->in_nul[i], nh);
            printf("  in[%u]  nullifier %s\n", (unsigned)i, nh);
        }
        for (int o = 0; o < rv->n_out; o++) {
            char th[129];
            qgp_fp_raw_to_hex(rv->out_token[o], th);
            printf("  out[%u] -> %.128s amount %llu token %s\n",
                   (unsigned)o, rv->out_owner[o],
                   (unsigned long long)rv->out_amount[o], th);
        }
        /* R1-5: the carried descriptor is not covered by the digest, and
         * no RPC answers a coin's owner for an address that has no
         * session key (dnac_utxo is gated to the session's own
         * fingerprint), so this tool cannot prove the inputs belong to
         * the address above. Say so on every signature. */
        printf("WARNING: the input owners were NOT verified. Sign only if "
               "you know every nullifier above is a coin of address %s.\n",
               ah);
    }
    uint8_t sig[DNAC_SIGNATURE_SIZE];
    size_t sl = 0;
    if (qgp_dsa87_sign(sig, &sl, x.digest, 64, keys[0].sk.bytes) != 0 ||
        sl != DNAC_SIGNATURE_SIZE) {
        fprintf(stderr, "signing failed\n");
        goto done;
    }
    size_t sig_len = 0;
    if (nodus_v2_msig_sig_encode(x.digest, keys[0].pk.bytes, sig, &sig_text,
                                 &sig_len) != NODUS_V2_SPEND_OK ||
        msig_write_text(out_path, sig_text, sig_len) != 0)
        goto done;
    printf("signature written to %s\n", out_path);
    rc = 0;
done:
    nodus_v2_msig_export_free(&x);
    free(sig_text);
    free(rv);
    free(pf);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

/* `msig combine` — assemble, self-check, submit or write. */
static int cmd_msig_combine(const char *server_ip, uint16_t server_port,
                            int argc, char **argv, int cmd_start) {
    const char *in_path = NULL, *keys_csv = NULL, *submit = NULL;
    const char *out_path = NULL;
    const char *sig_path[NODUS_RT_AUTH_MAX_SIGNERS];
    int n_sig = 0, bad = 0;
    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        if      (!strcmp(a, "--in")     && i + 1 < argc) in_path  = argv[++i];
        else if (!strcmp(a, "--keys")   && i + 1 < argc) keys_csv = argv[++i];
        else if (!strcmp(a, "--submit") && i + 1 < argc) submit   = argv[++i];
        else if (!strcmp(a, "--out")    && i + 1 < argc) out_path = argv[++i];
        else if (!strcmp(a, "--sig")    && i + 1 < argc) {
            if (n_sig >= (int)NODUS_RT_AUTH_MAX_SIGNERS) { bad = 1; break; }
            sig_path[n_sig++] = argv[++i];
        } else { bad = 1; break; }
    }
    if (bad || !in_path || n_sig < 1 || (!out_path && !keys_csv)) {
        fprintf(stderr,
            "Usage: msig combine --in <export> --sig <file> [--sig ...]\n"
            "         (--keys <dir> [--submit ip:port] | --out <envelope>)\n"
            "  Needs EXACTLY the export's K signatures. --keys is any "
            "identity (the\n"
            "  submitting session); --out only writes the signed envelope.\n");
        return 1;
    }
    int rc = 1;
    nodus_v2_msig_export_t x;
    memset(&x, 0, sizeof(x));
    nodus_identity_t *keys = NULL;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    dna_env_view_t *vp = calloc(1, sizeof(*vp));
    uint8_t (*spk)[DNAC_PUBKEY_SIZE] = calloc(NODUS_RT_AUTH_MAX_SIGNERS,
                                              DNAC_PUBKEY_SIZE);
    uint8_t (*ssig)[DNAC_SIGNATURE_SIZE] = calloc(NODUS_RT_AUTH_MAX_SIGNERS,
                                                  DNAC_SIGNATURE_SIZE);
    nodus_client_t client;
    memset(&client, 0, sizeof(client));
    int connected = 0;
    if (!pf || !vp || !spk || !ssig) goto done;
    if (msig_export_read(in_path, &x) != 0) goto done;
    nodus_v2_msig_leg_t leg;
    if (msig_leg_open(&x, vp, &leg) != 0) goto done;
    const uint8_t m = leg.m;
    if ((uint32_t)n_sig != x.signers) {
        fprintf(stderr, "the export fixed %u signers (auth_len is signed); "
                "%d signature file(s) given\n", (unsigned)x.signers, n_sig);
        goto done;
    }
    if (msig_digest(&x, pf) != 0 ||
        memcmp(pf->auth_digest[0], x.digest, 64) != 0) {
        fprintf(stderr, "the export's digest does not re-derive\n");
        goto done;
    }
    for (int i = 0; i < n_sig; i++) {
        uint8_t *raw = NULL;
        size_t rl = 0;
        if (msig_read_file(sig_path[i], &raw, &rl,
                           NODUS_V2_MSIG_SIG_TEXT_MAX) != 0)
            goto done;
        uint8_t dg[64];
        int ok = nodus_v2_msig_sig_parse((const char *)raw, rl, dg, spk[i],
                                         ssig[i]) == NODUS_V2_SPEND_OK;
        free(raw);
        if (!ok) { fprintf(stderr, "%s is malformed\n", sig_path[i]); goto done; }
        int src = nodus_v2_msig_sig_check(&x, &leg, dg, spk[i], ssig[i]);
        if (src == NODUS_V2_MSIG_ERR_SIG_DIGEST) {
            fprintf(stderr, "%s signs another digest\n", sig_path[i]);
            goto done;
        }
        if (src == NODUS_V2_MSIG_ERR_NOT_MEMBER) {
            fprintf(stderr, "%s: key not in the descriptor\n", sig_path[i]);
            goto done;
        }
        if (src != NODUS_V2_SPEND_OK) {
            fprintf(stderr, "%s: signature does not verify\n", sig_path[i]);
            goto done;
        }
    }
    /* ascending pubkey order (the ONE canonical signer encoding), no
     * duplicate key — the shared library */
    if (nodus_v2_msig_assemble(&x, vp,
                               (const uint8_t (*)[NODUS_V2_MSIG_PK_LEN])spk,
                               (const uint8_t (*)[NODUS_V2_MSIG_SIG_LEN])ssig,
                               n_sig) != NODUS_V2_SPEND_OK) {
        fprintf(stderr, "duplicate signer key among the signature "
                "files\n");
        goto done;
    }
    /* the chain's OWN auth hook, locally: >= M keys must be satisfied */
    {
        const nodus_domain_runtime_t *core_rt =
            cli_core_runtime_for_env(x.env, x.env_len);
        nodus_rt_auth_verdict_t av;
        nodus_rt_exec_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.chain_id = x.chain32;
        ctx.global_height = x.tip + 1;
        ctx.leg_auth_digest = x.digest;
        if (!core_rt || dna_env_decode(x.env, x.env_len, vp) != 0 ||
            nodus_rt_auth_dsa87_v1(core_rt, vp, 0, &ctx, &av) != 0 ||
            av.n_msig != 1 || !av.msig_satisfied[0]) {
            fprintf(stderr, "the assembled authorization does not satisfy "
                    "the descriptor (M=%u)\n", (unsigned)m);
            goto done;
        }
    }
    if (msig_digest(&x, pf) != 0) goto done;   /* pass-2 self-check     */
    printf("msig combine: %d signature(s) assembled, %zu bytes\n  wire_id=",
           n_sig, x.env_len);
    for (int b = 0; b < 64; b++) printf("%02x", pf->wire_id[b]);
    printf("\n  intent_id=");
    for (int b = 0; b < 64; b++) printf("%02x", pf->intent_id[b]);
    printf("\n");
    if (out_path) {
        FILE *f = fopen(out_path, "wb");
        if (!f || fwrite(x.env, 1, x.env_len, f) != x.env_len) {
            fprintf(stderr, "cannot write %s\n", out_path);
            if (f) fclose(f);
            goto done;
        }
        fclose(f);
        printf("  signed envelope written to %s\n", out_path);
    }
    if (keys_csv) {
        keys = calloc(4, sizeof(*keys));
        if (!keys || act_load_keys(keys_csv, keys, 4) != 1) {
            fprintf(stderr, "--keys must name exactly one identity\n");
            goto done;
        }
        char sip[64];
        uint16_t sport = 0;
        if (t6_resolve_target(submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target (and no -s server)\n");
            goto done;
        }
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
        cfg.servers[0].port = sport;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &keys[0]) != 0) goto done;
        connected = 1;
        if (nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
            goto done;
        }
        if (t6_submit_on(&client, &keys[0], pf->wire_id, x.env,
                         (uint32_t)x.env_len) != 0)
            goto done;
    }
    rc = 0;
done:
    nodus_v2_msig_export_free(&x);
    free(vp);
    free(pf);
    free(spk);
    free(ssig);
    if (connected) nodus_client_close(&client);
    if (keys) {
        for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
        free(keys);
    }
    return rc;
}

#ifdef NODUS_EVM_ENABLED
/* ══ Nodus EVM — `evm` (design docs/plans/2026-10-04-nodus-evm-chain-integration-
 *    design.md rev 3 §2, §5, §7, §8, §16, §18) ═════════════════════════
 *
 * Every envelope is built by the SHARED builder the web wallet builds
 * with (nodus/src/client/nodus_v2_evm.c — the call bytes are
 * shared/dnac/evm_call_wire.c, the codec the node decodes with), for the
 * rule-set generation the node names (cli_select_runtimes — it must be
 * the EVM generation, NODUS_RT_GEN_EVM), with the EVM leg's ruleset
 * identity from this binary's compiled table. A CALL / CREATE is priced
 * from the node's evm_estimate (ge, ue: client/nodus_v2_evm.h "UNITS");
 * the nonce is the sender's committed nonce (operator decision k2 #2: one
 * pending EVM transaction per sender — this command waits for the receipt
 * before it returns).
 *
 * ABI (web-wallet/src/evm/abi.js, the same rules): Solidity 0.8.30's
 * contract ABI with the Nodus difference that `address` is a full 32-byte
 * word (nodus/tools/evm/solc/README.md "Semantic rules" 1, 2, 10).
 * Supported argument / return types: uint<M>, int<M>, bool, address,
 * bytes<M>, bytes, string (no arrays, no tuples). A signature is
 * `name(t1,t2)` with an optional return list `name(t1,t2)(r1,r2)`; a
 * constructor's is `(t1,t2)`. Selector = keccak256(canonical)[0..4].
 * ════════════════════════════════════════════════════════════════════ */

#define EVM_ABI_MAX_ARGS     16
#define EVM_SOLC_DEFAULT     "/usr/local/bin/solc-nodus"
#define EVM_SOLC_OUT_MAX     ((size_t)32 * 1024 * 1024)
#define EVM_RECEIPT_POLL_S   2u
#define EVM_RECEIPT_POLL_MAX 900u          /* 30 minutes                 */
/* The local fee bound (red-team 1 F9): the fee is units × the gas price,
 * and BOTH come from the connected node (evm_estimate's ue, dnac_fee_info's
 * price). Above this the CLI asks before it submits, unless --yes or an
 * explicit --max-fee. 50 NODUS = 5 × 10^9 raw: a full-cap call
 * (EVM_TX_GAS_CAP 30 000 000 gas × w_gas 1 + EVM_READS_BASE 16 334 reads
 * × w_read 1 + FAIL_RESERVE 4 096 + the static units) costs ≈ 3.63 × 10^9
 * raw ≈ 36 NODUS at the genesis price of 121 raw / unit (decision
 * 2026-09-25-gas-price.md). A LOCAL bound, not a chain rule — kept at
 * 50 NODUS by the operator after the gas measurement (2026-10-07: the
 * costliest valid call ≈ 36.3 NODUS at 121); at prices above ≈ 166 raw / unit an
 * honest full-cap call needs --yes or --max-fee. */
#define EVM_FEE_CONFIRM_RAW  5000000000ull

/* ── 256-bit big-endian integers ─────────────────────────────────────── */

/* out = decimal string `s` (digits only). @return 0 / -1 (empty, a
 * non-digit, or above 2^256 - 1). */
static int evm_u256_dec(const char *s, uint8_t out[32]) {
    memset(out, 0, 32);
    if (!s || !*s) return -1;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        unsigned carry = (unsigned)(*p - '0');
        for (int i = 31; i >= 0; i--) {
            unsigned v = (unsigned)out[i] * 10u + carry;
            out[i] = (uint8_t)v;
            carry = v >> 8;
        }
        if (carry) return -1;
    }
    return 0;
}

/* out = "0x"-prefixed hex (1..64 digits), right-aligned. @return 0 / -1. */
static int evm_u256_hexnum(const char *s, uint8_t out[32]) {
    memset(out, 0, 32);
    if (!s || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    s += 2;
    size_t n = strlen(s);
    if (n == 0 || n > 64) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[n - 1 - i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        out[31 - i / 2] |= (uint8_t)(d << ((i % 2) * 4));
    }
    return 0;
}

/* Decimal text of a 32-byte big-endian unsigned value (out >= 80). */
static void evm_u256_to_dec(const uint8_t in[32], char *out) {
    uint8_t v[32];
    char tmp[80];
    size_t n = 0;
    memcpy(v, in, 32);
    for (;;) {
        unsigned rem = 0;
        int zero = 1;
        for (int i = 0; i < 32; i++) {
            unsigned cur = (rem << 8) | v[i];
            v[i] = (uint8_t)(cur / 10u);
            rem = cur % 10u;
            if (v[i]) zero = 0;
        }
        tmp[n++] = (char)('0' + rem);
        if (zero) break;
    }
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = '\0';
}

/* Wei as NODUS: 1 NODUS = 10^8 raw = 10^18 wei (q = 10^10, operator
 * decision k1 #3). */
static void evm_wei_to_nodus(const uint8_t wei[32], char *out, size_t cap) {
    char d[80];
    evm_u256_to_dec(wei, d);
    size_t n = strlen(d);
    if (n <= 18) {
        char frac[19];
        memset(frac, '0', 18);
        memcpy(frac + 18 - n, d, n);
        frac[18] = '\0';
        snprintf(out, cap, "0.%s", frac);
    } else {
        snprintf(out, cap, "%.*s.%s", (int)(n - 18), d, d + n - 18);
    }
}

/* Hex (optional 0x) → bytes. @return 0 / -1 (odd, a non-hex, too long). */
static int evm_hex_bytes(const char *hex, uint8_t *out, size_t cap,
                         size_t *len) {
    if (!hex) return -1;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int v = 0;
        for (int j = 0; j < 2; j++) {
            char c = hex[2 * i + (size_t)j];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
            else return -1;
            v = (v << 4) | d;
        }
        out[i] = (uint8_t)v;
    }
    *len = n / 2;
    return 0;
}

static void evm_print_hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

/* A 32-byte EVM address from text: 64 hex digits (optional 0x). Mixed
 * case must carry the Nodus 64-digit EIP-55 checksum (solc README rule
 * 4: keccak256 of the 64 lowercase hex characters; the i-th letter is
 * upper case iff the i-th nibble of the hash is >= 8). @return 0 / -1. */
static int evm_addr_parse(const char *s, uint8_t out[32]) {
    if (!s) return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (strlen(s) != 64) return -1;
    int lower = 0, upper = 0;
    char low[64];
    for (int i = 0; i < 64; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'F') { upper = 1; c = (char)(c - 'A' + 'a'); }
        else if (c >= 'a' && c <= 'f') lower = 1;
        else if (!(c >= '0' && c <= '9')) return -1;
        low[i] = c;
    }
    if (lower && upper) {
        uint8_t h[32];
        if (keccak256((const uint8_t *)low, 64, h) != 0) return -1;
        for (int i = 0; i < 64; i++) {
            if (low[i] < 'a') continue;            /* a digit */
            int nib = (h[i / 2] >> (i % 2 ? 0 : 4)) & 0x0F;
            int want_upper = nib >= 8;
            int is_upper = s[i] >= 'A' && s[i] <= 'F';
            if (want_upper != is_upper) return -1;
        }
    }
    size_t n = 0;
    char buf[65];
    memcpy(buf, low, 64);
    buf[64] = '\0';
    return evm_hex_bytes(buf, out, 32, &n) == 0 && n == 32 ? 0 : -1;
}

/* The EVM address of a Nodus key: SHA3-512(pk)[0..32] (design §2). */
static int evm_addr_of_pk(const uint8_t *pk, uint8_t out[32]) {
    uint8_t fp[64];
    if (qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, fp) != 0) return -1;
    memcpy(out, fp, 32);
    return 0;
}

/* ── ABI ─────────────────────────────────────────────────────────────── */

typedef enum {
    EVM_ABI_UINT, EVM_ABI_INT, EVM_ABI_BOOL, EVM_ABI_ADDR,
    EVM_ABI_FBYTES, EVM_ABI_BYTES, EVM_ABI_STRING
} evm_abi_kind_t;

typedef struct {
    evm_abi_kind_t k;
    unsigned       bits;      /* uint / int                             */
    unsigned       size;      /* bytes<M>                               */
} evm_abi_type_t;

static int evm_abi_dynamic(const evm_abi_type_t *t) {
    return t->k == EVM_ABI_BYTES || t->k == EVM_ABI_STRING;
}

/* One type name (n chars) → type + its canonical text. @return 0 / -1. */
static int evm_abi_type(const char *s, size_t n, evm_abi_type_t *t,
                        char *canon, size_t cap) {
    char name[24];
    if (n == 0 || n >= sizeof(name)) return -1;
    memcpy(name, s, n);
    name[n] = '\0';
    memset(t, 0, sizeof(*t));
    if (!strcmp(name, "address")) t->k = EVM_ABI_ADDR;
    else if (!strcmp(name, "bool")) t->k = EVM_ABI_BOOL;
    else if (!strcmp(name, "string")) t->k = EVM_ABI_STRING;
    else if (!strcmp(name, "bytes")) t->k = EVM_ABI_BYTES;
    else if (!strncmp(name, "uint", 4) || !strncmp(name, "int", 3)) {
        int is_u = name[0] == 'u';
        const char *num = name + (is_u ? 4 : 3);
        unsigned bits = 256;
        if (*num) {
            char *end = NULL;
            unsigned long b = strtoul(num, &end, 10);
            if (!end || *end || num[0] == '0') return -1;
            bits = (unsigned)b;
        }
        if (bits < 8 || bits > 256 || bits % 8) return -1;
        t->k = is_u ? EVM_ABI_UINT : EVM_ABI_INT;
        t->bits = bits;
        snprintf(canon, cap, "%s%u", is_u ? "uint" : "int", bits);
        return 0;
    } else if (!strncmp(name, "bytes", 5)) {
        char *end = NULL;
        unsigned long m = strtoul(name + 5, &end, 10);
        if (!end || *end || name[5] == '0' || m < 1 || m > 32) return -1;
        t->k = EVM_ABI_FBYTES;
        t->size = (unsigned)m;
    } else {
        return -1;                     /* arrays, tuples, function: refused */
    }
    snprintf(canon, cap, "%s", name);
    return 0;
}

/* "t1,t2" (n chars, may be empty) → types; appends the canonical list to
 * `canon`. @return the count, or -1. */
static int evm_abi_list(const char *s, size_t n, evm_abi_type_t *ts,
                        char *canon, size_t cap) {
    int cnt = 0;
    size_t i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && s[j] != ',') j++;
        size_t a = i, b = j;
        while (a < b && s[a] == ' ') a++;
        while (b > a && s[b - 1] == ' ') b--;
        char one[24];
        if (cnt >= EVM_ABI_MAX_ARGS ||
            evm_abi_type(s + a, b - a, &ts[cnt], one, sizeof(one)) != 0)
            return -1;
        size_t cl = strlen(canon);
        if (snprintf(canon + cl, cap - cl, "%s%s", cnt ? "," : "", one) >=
            (int)(cap - cl))
            return -1;
        cnt++;
        if (j == n) break;
        i = j + 1;
        if (i == n) return -1;          /* a trailing comma */
    }
    return cnt;
}

typedef struct {
    char           canon[512];          /* name(t1,t2)                  */
    evm_abi_type_t in[EVM_ABI_MAX_ARGS];
    int            n_in;
    evm_abi_type_t out[EVM_ABI_MAX_ARGS];
    int            n_out;
    int            has_out;
} evm_abi_sig_t;

/* `name(t1,..)[(r1,..)]`, or `(t1,..)` for a constructor. @return 0/-1. */
static int evm_abi_sig(const char *sig, evm_abi_sig_t *g) {
    memset(g, 0, sizeof(*g));
    const char *lp = strchr(sig, '(');
    if (!lp) return -1;
    const char *rp = strchr(lp, ')');
    if (!rp) return -1;
    size_t nl = (size_t)(lp - sig);
    for (size_t i = 0; i < nl; i++) {
        char c = sig[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '$'))
            return -1;
    }
    if (nl >= 128) return -1;
    memcpy(g->canon, sig, nl);
    g->canon[nl] = '(';
    g->canon[nl + 1] = '\0';
    int n = evm_abi_list(lp + 1, (size_t)(rp - lp - 1), g->in, g->canon,
                         sizeof(g->canon));
    if (n < 0) return -1;
    g->n_in = n;
    size_t cl = strlen(g->canon);
    if (cl + 2 > sizeof(g->canon)) return -1;
    g->canon[cl] = ')';
    g->canon[cl + 1] = '\0';
    const char *rest = rp + 1;
    if (*rest == '\0') return 0;
    if (*rest != '(') return -1;
    const char *rp2 = strchr(rest, ')');
    if (!rp2 || rp2[1] != '\0') return -1;
    char scratch[512] = "";
    n = evm_abi_list(rest + 1, (size_t)(rp2 - rest - 1), g->out, scratch,
                     sizeof(scratch));
    if (n < 0) return -1;
    g->n_out = n;
    g->has_out = 1;
    return 0;
}

static int evm_abi_selector(const char *canon, uint8_t sel[4]) {
    uint8_t h[32];
    if (keccak256((const uint8_t *)canon, strlen(canon), h) != 0) return -1;
    memcpy(sel, h, 4);
    return 0;
}

/* One static word of `t` from text `v`. @return 0 / -1. */
static int evm_abi_word(const evm_abi_type_t *t, const char *v,
                        uint8_t w[32]) {
    memset(w, 0, 32);
    switch (t->k) {
    case EVM_ABI_ADDR:
        return evm_addr_parse(v, w);
    case EVM_ABI_BOOL:
        if (!strcmp(v, "true") || !strcmp(v, "1")) { w[31] = 1; return 0; }
        if (!strcmp(v, "false") || !strcmp(v, "0")) return 0;
        return -1;
    case EVM_ABI_UINT: {
        if ((v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))
                ? evm_u256_hexnum(v, w) != 0 : evm_u256_dec(v, w) != 0)
            return -1;
        for (unsigned i = 0; i < (256u - t->bits) / 8u; i++)
            if (w[i]) return -1;                       /* out of range */
        return 0;
    }
    case EVM_ABI_INT: {
        int neg = v[0] == '-';
        uint8_t m[32];
        if (evm_u256_dec(v + neg, m) != 0) return -1;
        /* |v| < 2^(bits-1), or == 2^(bits-1) when negative */
        uint8_t lim[32];
        memset(lim, 0, sizeof(lim));
        unsigned bit = t->bits - 1u;
        lim[31 - bit / 8] = (uint8_t)(1u << (bit % 8));
        int c = memcmp(m, lim, 32);
        if (c > 0 || (c == 0 && !neg)) return -1;
        if (!neg) { memcpy(w, m, 32); return 0; }
        /* two's complement: ~m + 1 */
        unsigned carry = 1;
        for (int i = 31; i >= 0; i--) {
            unsigned x = (unsigned)(uint8_t)~m[i] + carry;
            w[i] = (uint8_t)x;
            carry = x >> 8;
        }
        return 0;
    }
    case EVM_ABI_FBYTES: {
        size_t n = 0;
        if (evm_hex_bytes(v, w, 32, &n) != 0 || n != t->size) return -1;
        return 0;
    }
    default:
        return -1;
    }
}

/* enc((v1..vn)) — the head/tail encoding of a sequence of values
 * (abi-spec "Formal Specification of the Encoding"). *out heap.
 * @return 0 / -1 (message printed). */
static int evm_abi_encode(const evm_abi_type_t *ts, int n, char **vals,
                          uint8_t **out, size_t *out_len) {
    *out = NULL;
    *out_len = 0;
    size_t head = (size_t)n * 32, tail = 0;
    uint8_t *dyn[EVM_ABI_MAX_ARGS];
    size_t   dyn_len[EVM_ABI_MAX_ARGS];
    memset(dyn, 0, sizeof(dyn));
    memset(dyn_len, 0, sizeof(dyn_len));
    int rc = -1;
    for (int i = 0; i < n; i++) {
        if (!evm_abi_dynamic(&ts[i])) continue;
        size_t blen = 0;
        uint8_t *b = NULL;
        if (ts[i].k == EVM_ABI_STRING) {
            blen = strlen(vals[i]);
            b = malloc(blen ? blen : 1);
            if (!b) goto done;
            memcpy(b, vals[i], blen);
        } else {
            size_t hl = strlen(vals[i]);
            b = malloc(hl / 2 + 1);
            if (!b || evm_hex_bytes(vals[i], b, hl / 2 + 1, &blen) != 0) {
                free(b);
                fprintf(stderr, "argument %d: bytes must be hex\n", i + 1);
                goto done;
            }
        }
        size_t padded = (blen + 31) / 32 * 32;
        dyn[i] = calloc(1, 32 + padded + 1);
        if (!dyn[i]) { free(b); goto done; }
        for (int k = 0; k < 8; k++)
            dyn[i][31 - k] = (uint8_t)((uint64_t)blen >> (8 * k));
        if (blen) memcpy(dyn[i] + 32, b, blen);
        free(b);
        dyn_len[i] = 32 + padded;
        tail += dyn_len[i];
    }
    uint8_t *buf = calloc(1, head + tail + 1);
    if (!buf) goto done;
    size_t toff = head;
    for (int i = 0; i < n; i++) {
        uint8_t *w = buf + (size_t)i * 32;
        if (evm_abi_dynamic(&ts[i])) {
            for (int k = 0; k < 8; k++)
                w[31 - k] = (uint8_t)((uint64_t)toff >> (8 * k));
            memcpy(buf + toff, dyn[i], dyn_len[i]);
            toff += dyn_len[i];
        } else if (evm_abi_word(&ts[i], vals[i], w) != 0) {
            fprintf(stderr, "argument %d (%s) is not a valid value of its "
                    "type\n", i + 1, vals[i]);
            free(buf);
            goto done;
        }
    }
    *out = buf;
    *out_len = head + tail;
    rc = 0;
done:
    for (int i = 0; i < n; i++) free(dyn[i]);
    return rc;
}

/* A word as an offset / length into `len` bytes. @return 0 / -1. */
static int evm_abi_usize(const uint8_t w[32], size_t len, size_t *out) {
    for (int i = 0; i < 24; i++)
        if (w[i]) return -1;
    uint64_t v = 0;
    for (int i = 24; i < 32; i++) v = (v << 8) | w[i];
    if (v > len) return -1;
    *out = (size_t)v;
    return 0;
}

/* Decode and print the return values of `ts` from `d` (strict: dirty
 * high bits, bad sign extension, a bool other than 0/1, non-zero padding
 * and any offset / length outside the data refuse). @return 0 / -1. */
static int evm_abi_print(const evm_abi_type_t *ts, int n, const uint8_t *d,
                         size_t len) {
    if ((size_t)n * 32 > len) return -1;
    for (int i = 0; i < n; i++) {
        const uint8_t *w = d + (size_t)i * 32;
        char dec[80];
        printf("  [%d] ", i);
        switch (ts[i].k) {
        case EVM_ABI_UINT:
            for (unsigned b = 0; b < (256u - ts[i].bits) / 8u; b++)
                if (w[b]) return -1;
            evm_u256_to_dec(w, dec);
            printf("%s\n", dec);
            break;
        case EVM_ABI_INT: {
            int neg = (w[(256u - ts[i].bits) / 8u] & 0x80) != 0;
            for (unsigned b = 0; b < (256u - ts[i].bits) / 8u; b++)
                if (w[b] != (neg ? 0xFF : 0x00)) return -1;
            uint8_t m[32];
            if (neg) {
                unsigned carry = 1;
                for (int b = 31; b >= 0; b--) {
                    unsigned x = (unsigned)(uint8_t)~w[b] + carry;
                    m[b] = (uint8_t)x;
                    carry = x >> 8;
                }
            } else {
                memcpy(m, w, 32);
            }
            evm_u256_to_dec(m, dec);
            printf("%s%s\n", neg ? "-" : "", dec);
            break;
        }
        case EVM_ABI_BOOL:
            for (int b = 0; b < 31; b++)
                if (w[b]) return -1;
            if (w[31] > 1) return -1;
            printf("%s\n", w[31] ? "true" : "false");
            break;
        case EVM_ABI_ADDR:
            printf("0x");
            evm_print_hex(w, 32);
            printf("\n");
            break;
        case EVM_ABI_FBYTES:
            for (unsigned b = ts[i].size; b < 32; b++)
                if (w[b]) return -1;
            printf("0x");
            evm_print_hex(w, ts[i].size);
            printf("\n");
            break;
        case EVM_ABI_BYTES:
        case EVM_ABI_STRING: {
            size_t off = 0, bl = 0;
            if (evm_abi_usize(w, len, &off) != 0 || len - off < 32 ||
                evm_abi_usize(d + off, len - off - 32, &bl) != 0)
                return -1;
            const uint8_t *p = d + off + 32;
            if (ts[i].k == EVM_ABI_BYTES) {
                printf("0x");
                evm_print_hex(p, bl);
                printf("\n");
            } else {
                putchar('"');
                for (size_t b = 0; b < bl; b++) {
                    if (p[b] == '"' || p[b] == '\\') printf("\\%c", p[b]);
                    else if (p[b] < 0x20 || p[b] == 0x7f) printf("\\x%02x", p[b]);
                    else putchar(p[b]);
                }
                printf("\"\n");
            }
            break;
        }
        }
    }
    return 0;
}

/* Print REVERT data: Error(string) / Panic(uint256) decoded (selectors
 * computed from their signatures), anything else as hex. */
static void evm_print_revert(const uint8_t *o, size_t n) {
    uint8_t es[4], ps[4];
    if (n == 0) {
        printf("  revert: (no data)\n");
        return;
    }
    if (n >= 4 && evm_abi_selector("Error(string)", es) == 0 &&
        memcmp(o, es, 4) == 0) {
        evm_abi_type_t t = { EVM_ABI_STRING, 0, 0 };
        printf("  revert: Error(string)\n");
        if (evm_abi_print(&t, 1, o + 4, n - 4) == 0) return;
    } else if (n >= 4 && evm_abi_selector("Panic(uint256)", ps) == 0 &&
               memcmp(o, ps, 4) == 0) {
        evm_abi_type_t t = { EVM_ABI_UINT, 256, 0 };
        printf("  revert: Panic(uint256)\n");
        if (evm_abi_print(&t, 1, o + 4, n - 4) == 0) return;
    }
    printf("  revert data: 0x");
    evm_print_hex(o, n);
    printf("\n");
}

/* ── solc (the Nodus 32-byte-address variant, nodus/tools/evm/solc) ── */

/* Run argv[0] with argv, capturing stdout (stderr passes through).
 * @return 0 (exit status 0, *out heap NUL-terminated) / -1. */
static int evm_run_capture(char *const argv[], char **out, size_t *out_len) {
    int fd[2];
    *out = NULL;
    *out_len = 0;
    if (pipe(fd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(fd[0]); close(fd[1]); return -1; }
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]);
        close(fd[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(fd[1]);
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap + 1);
    int ok = buf != NULL;
    while (ok) {
        if (n == cap) {
            if (cap >= EVM_SOLC_OUT_MAX) { ok = 0; break; }
            char *g = realloc(buf, cap * 2 + 1);
            if (!g) { ok = 0; break; }
            buf = g;
            cap *= 2;
        }
        ssize_t r = read(fd[0], buf + n, cap - n);
        if (r < 0) { if (errno == EINTR) continue; ok = 0; break; }
        if (r == 0) break;
        n += (size_t)r;
    }
    close(fd[0]);
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!ok || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        free(buf);
        return -1;
    }
    buf[n] = '\0';
    *out = buf;
    *out_len = n;
    return 0;
}

/* `--solc file.sol:Contract`: refuse a compiler that is not the Nodus
 * variant (its --version must carry "nodus.addr256" — a stock solc masks
 * every address to 20 bytes, solc README "Why"), then `solc --bin file`
 * and take the hex line after "======= <path>:<Contract> =======" (the
 * output shape nodus/tools/evm/solc/tests/check.sh parses).
 * @return 0 (*code heap) / -1 (message printed). */
static int evm_solc(const char *solc_bin, const char *spec, uint8_t **code,
                    size_t *code_len) {
    *code = NULL;
    *code_len = 0;
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec || !colon[1]) {
        fprintf(stderr, "--solc wants <file.sol>:<Contract>\n");
        return -1;
    }
    char file[1024], contract[256];
    size_t fl = (size_t)(colon - spec);
    if (fl >= sizeof(file) || strlen(colon + 1) >= sizeof(contract)) return -1;
    memcpy(file, spec, fl);
    file[fl] = '\0';
    snprintf(contract, sizeof(contract), "%s", colon + 1);

    char *out = NULL;
    size_t ol = 0;
    char *vargv[] = { (char *)solc_bin, "--version", NULL };
    if (evm_run_capture(vargv, &out, &ol) != 0) {
        fprintf(stderr, "cannot run %s --version (set $NODUS_SOLC or "
                "--solc-bin)\n", solc_bin);
        return -1;
    }
    if (!strstr(out, "nodus.addr256")) {
        fprintf(stderr, "%s is not the Nodus solc (no \"nodus.addr256\" in "
                "its --version): a stock solc truncates addresses to 20 "
                "bytes — refused (build nodus/tools/evm/solc)\n", solc_bin);
        free(out);
        return -1;
    }
    free(out);
    char *bargv[] = { (char *)solc_bin, "--bin", file, NULL };
    if (evm_run_capture(bargv, &out, &ol) != 0) {
        fprintf(stderr, "solc --bin %s failed\n", file);
        return -1;
    }
    int rc = -1, in_target = 0;
    char *save = NULL;
    for (char *line = strtok_r(out, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        size_t ll = strlen(line);
        if (ll > 16 && !strncmp(line, "======= ", 8) &&
            !strcmp(line + ll - 8, " =======")) {
            /* "======= <path>:<Contract> =======" */
            line[ll - 8] = '\0';
            const char *c = strrchr(line + 8, ':');
            in_target = c && !strcmp(c + 1, contract);
            continue;
        }
        if (!in_target || ll == 0) continue;
        int hexline = 1;
        for (size_t i = 0; i < ll && hexline; i++)
            if (!((line[i] >= '0' && line[i] <= '9') ||
                  (line[i] >= 'a' && line[i] <= 'f')))
                hexline = 0;
        if (!hexline) continue;
        *code = malloc(ll / 2 + 1);
        if (*code && evm_hex_bytes(line, *code, ll / 2 + 1, code_len) == 0 &&
            *code_len > 0)
            rc = 0;
        break;
    }
    free(out);
    if (rc != 0) {
        free(*code);
        *code = NULL;
        *code_len = 0;
        fprintf(stderr, "no bytecode for %s in solc's output (an abstract "
                "contract or an interface?)\n", contract);
    }
    return rc;
}

/* ── the session, the receipt ────────────────────────────────────────── */

/* Print a §18 receipt (the fields the node returned; the client SDK has
 * already re-checked its digest against those same fields). Everything here
 * is AS REPORTED BY THE CONNECTED NODE: the digest check shows the fields
 * and the digest agree, not that the chain committed them — binding the
 * digest to the next block's LastResultsHash is not implemented (red-team 1
 * F11). `h` is the inclusion height (design §18 rev 5). `expect_created`:
 * for a CREATE this CLI signed, the address computed from the signed
 * sender and nonce (nodus_v2_evm_create_address); NULL when unknown.
 * @return 0, or -1 when the reported contract address differs from it. */
static int evm_print_receipt(const nodus_evm_receipt_t *r,
                             const uint8_t *expect_created) {
    static const char *const ops[6] = { "?", "CALL", "CREATE", "DEPOSIT",
                                        "WITHDRAW", "REDEEM" };
    int rc = 0;
    printf("receipt (as reported by the connected node; not proven against "
           "the chain): %s %s, included at height %llu item %u\n",
           ops[r->op <= 5 ? r->op : 0],
           r->status ? "SUCCEEDED" : "FAILED (applied: fee paid, nonce "
                                     "consumed)",
           (unsigned long long)r->height, (unsigned)r->item);
    printf("  evm gas used: %llu\n", (unsigned long long)r->gas_used);
    if (r->has_created) {
        printf("  created contract: 0x");
        evm_print_hex(r->created, 32);
        printf("\n");
    }
    if (expect_created && r->status &&
        (!r->has_created || memcmp(r->created, expect_created, 32) != 0)) {
        printf("  WARNING: this deployment's contract address is 0x");
        evm_print_hex(expect_created, 32);
        printf(" (computed from the signed sender and nonce); the node "
               "reported %s — do not use the node's answer\n",
               r->has_created ? "a different one" : "none");
        rc = -1;
    }
    if (r->output_len) {
        printf("  output: 0x");
        evm_print_hex(r->output, r->output_len);
        printf("\n");
    }
    for (size_t i = 0; i < r->n_logs; i++) {
        const nodus_evm_log_t *l = &r->logs[i];
        printf("  log %zu: address 0x", i);
        evm_print_hex(l->addr, 32);
        printf("\n");
        for (uint8_t t = 0; t < l->n_topics; t++) {
            printf("    topic%u 0x", (unsigned)t);
            evm_print_hex(l->topics[t], 32);
            printf("\n");
        }
        printf("    data 0x");
        evm_print_hex(l->data, l->data_len);
        printf("\n");
    }
    {
        static const uint8_t z[32] = { 0 };
        if (memcmp(r->wei_destroyed, z, 32) != 0) {
            char dec[80];
            evm_u256_to_dec(r->wei_destroyed, dec);
            printf("  value destroyed (wei): %s\n", dec);
        }
    }
    for (size_t t = 0; t < r->n_tickets; t++) {
        printf("  withdrawal ticket: ");
        evm_print_hex(r->tickets[t], 64);
        printf("  (redeem it with: evm redeem <ticket>)\n");
    }
    printf("  receipt digest (Data, matches the fields above — not checked "
           "against the chain): ");
    evm_print_hex(r->digest, 64);
    printf("\n");
    return rc;
}

/* Poll evm_receipt until the item is included or the chain passes the
 * envelope's expiry (CLIENT-side wait; nothing on chain reads it).
 * @return 0 included (printed) / 1 not included / -1 RPC fault. */
static int evm_wait_receipt(nodus_client_t *client, const uint8_t intent[64],
                            const uint8_t self_addr[32], uint64_t expiry,
                            nodus_evm_receipt_t *rc_out) {
    printf("waiting for the receipt (one pending EVM transaction per "
           "sender; expiry height %llu)...\n", (unsigned long long)expiry);
    fflush(stdout);
    for (unsigned i = 0; i < EVM_RECEIPT_POLL_MAX && running; i++) {
        sleep(EVM_RECEIPT_POLL_S);
        int qrc = nodus_client_evm_receipt(client, intent, rc_out);
        if (qrc != 0) {
            fprintf(stderr, "evm_receipt failed (rc=%d)\n", qrc);
            return -1;
        }
        if (rc_out->found) return 0;
        nodus_evm_account_t a;
        if (nodus_client_evm_account(client, self_addr, &a) != 0) return -1;
        if (a.height > expiry) {
            printf("not included: the chain is at %llu, past the "
                   "envelope's expiry %llu\n",
                   (unsigned long long)a.height, (unsigned long long)expiry);
            return 1;
        }
    }
    printf("still not included — stopped waiting; check later with "
           "`evm receipt`\n");
    return 1;
}

/* ── one networked EVM build + submit (CALL / CREATE / bridge ops) ───── */

typedef struct {
    const char *keys_csv, *submit;
    int         dry_run, no_wait, force;
    int         yes;                    /* --yes: no fee confirmation     */
    int         has_max_fee;            /* --max-fee <raw> given          */
    uint64_t    max_fee;                /* refuse a built fee above it    */
    uint64_t    gas;                    /* 0 = the node's estimate        */
    uint8_t     value[32];
    int         has_value;
} evm_tx_opts_t;

/* Build (shared builder), self-check, print, and — unless --dry-run —
 * submit and wait for the receipt. `call` holds the op and its scalars
 * (+ data); nonce / gas are filled here. @return the process exit code. */
static int evm_tx_run(const char *server_ip, uint16_t server_port,
                      const evm_tx_opts_t *o, dna_evm_call_t *call) {
    int rc = 1, connected = 0, utxos_valid = 0;
    nodus_identity_t *keys = calloc(4, sizeof(*keys));
    nodus_v2_coin_t *coins = NULL;
    nodus_dnac_utxo_result_t utxos;
    nodus_v2_evm_built_t built;
    nodus_client_t client;
    memset(&utxos, 0, sizeof(utxos));
    memset(&built, 0, sizeof(built));
    memset(&client, 0, sizeof(client));
    if (!keys) return 1;
    if (!o->keys_csv || act_load_keys(o->keys_csv, keys, 4) != 1) {
        fprintf(stderr, "an EVM transaction needs exactly one --keys "
                "identity (it signs both legs and is the EVM sender)\n");
        goto done;
    }
    uint8_t self_addr[32], own_raw[64];
    char own_fp[QGP_FP_HEX_BUFFER];
    if (evm_addr_of_pk(keys[0].pk.bytes, self_addr) != 0 ||
        qgp_sha3_512(keys[0].pk.bytes, DNAC_PUBKEY_SIZE, own_raw) != 0)
        goto done;
    qgp_fp_raw_to_hex(own_raw, own_fp);
    {
        char sip[64];
        uint16_t sport = 0;
        if (t6_resolve_target(o->submit, server_ip, server_port, sip,
                              &sport) != 0) {
            fprintf(stderr, "invalid --submit target (and no -s server)\n");
            goto done;
        }
        nodus_client_config_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        snprintf(cfg.servers[0].ip, sizeof(cfg.servers[0].ip), "%s", sip);
        cfg.servers[0].port = sport;
        cfg.server_count    = 1;
        cfg.auto_reconnect  = false;
        if (nodus_client_init(&client, &cfg, &keys[0]) != 0) goto done;
        connected = 1;
        if (nodus_client_connect(&client) != 0) {
            fprintf(stderr, "client connect failed (%s:%u)\n", sip, sport);
            goto done;
        }
    }
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    {
        bool has = false;
        if (nodus_client_dnac_chain_id32(&client, &has, chain32) != 0 ||
            !has) {
            fprintf(stderr, "this node is not on a version-3 chain\n");
            goto done;
        }
    }
    const nodus_domain_runtime_t *sys_rt = NULL, *core_rt = NULL;
    if (cli_select_runtimes(&client, &sys_rt, &core_rt) != 0) goto done;
    if (core_rt->generation < NODUS_RT_GEN_EVM) {
        fprintf(stderr, "the node runs rule-set generation %u — smart "
                "contracts open with the EVM generation (%u, the "
                "EVM_ACTIVE vote); nothing was built\n",
                (unsigned)core_rt->generation, (unsigned)NODUS_RT_GEN_EVM);
        goto done;
    }
    const nodus_domain_runtime_t *evm_rt =
        cli_builtin_runtime(DNA_DOMAIN_EVM, core_rt->generation);
    if (!evm_rt) {
        fprintf(stderr, "this CLI carries no EVM runtime for generation "
                "%u — rebuild it\n", (unsigned)core_rt->generation);
        goto done;
    }

    /* the committed nonce (decision k2 #2: no pending-nonce queue) */
    nodus_evm_account_t acct;
    int qrc = nodus_client_evm_account(&client, self_addr, &acct);
    if (qrc != 0) {
        fprintf(stderr, "evm_account failed (rc=%d)%s\n", qrc,
                qrc == NODUS_ERR_NOT_FOUND ? " — the EVM domain is not "
                "active on this node" : "");
        goto done;
    }
    if (call->op != DNA_EVM_OP_REDEEM) call->nonce = acct.nonce;

    /* CALL / CREATE: the node's estimate (ge, ue) — refused when the
     * simulation fails, unless --force */
    uint64_t read_units = 0;
    const int is_vm = call->op == DNA_EVM_OP_CALL ||
                      call->op == DNA_EVM_OP_CREATE;
    if (is_vm) {
        nodus_evm_call_req_t er;
        nodus_evm_call_res_t es;
        memset(&er, 0, sizeof(er));
        er.from = self_addr;
        er.to = call->op == DNA_EVM_OP_CALL ? call->to : NULL;
        er.value = call->value_wei;
        er.data = call->data;
        er.data_len = call->data_len;
        er.gas = o->gas;
        qrc = nodus_client_evm_estimate(&client, &er, &es);
        if (qrc != 0) {
            fprintf(stderr, "evm_estimate failed (rc=%d) — the node refused "
                    "the call before execution (value above the balance, "
                    "intrinsic gas, ...)\n", qrc);
            goto done;
        }
        if (!es.success) {
            printf("simulation at height %llu: the call FAILS\n",
                   (unsigned long long)es.height);
            evm_print_revert(es.output, es.output_len);
            if (!o->force) {
                fprintf(stderr, "nothing was built (--force to send a "
                        "transaction that fails and still pays its fee)\n");
                nodus_evm_call_res_free(&es);
                goto done;
            }
        }
        /* the estimate is ONE node's answer: refused, never clamped, unless
         * used <= ge <= the gas asked for (o->gas, else the node's default
         * EVM_TX_GAS_CAP — nodus_witness_handlers.c evm_estimate) and its
         * read units fit the engine's read cap (red-team 1 F9) */
        const uint64_t asked = o->gas ? o->gas : NODUS_RT_EVM_TX_GAS_CAP;
        if (es.gas_used > es.gas_limit || es.gas_limit == 0 ||
            es.gas_limit > asked || es.gas_limit > NODUS_RT_EVM_TX_GAS_CAP) {
            fprintf(stderr, "the node's estimate is malformed (gas used %llu, "
                    "suggested gas %llu, asked %llu) — nothing was built\n",
                    (unsigned long long)es.gas_used,
                    (unsigned long long)es.gas_limit,
                    (unsigned long long)asked);
            nodus_evm_call_res_free(&es);
            goto done;
        }
        call->gas_limit = o->gas ? o->gas : es.gas_limit;
        uint64_t ref = 0;
        if (nodus_v2_evm_ref_units(sys_rt->meter_policy,
                                   core_rt->ruleset_version, call->op,
                                   call->data_len, es.gas_limit,
                                   &ref) != NODUS_V2_SPEND_OK) {
            fprintf(stderr, "could not price the reference shape\n");
            nodus_evm_call_res_free(&es);
            goto done;
        }
        /* 0 <= ue − ref <= (EVM_READS_BASE + 2 × access-list keys) ×
         * w_read: the engine's logical-read cap of one leg
         * (nodus_witness_rt_evm.c max_reads), each read charged w_read of
         * the SYSTEM policy the node's estimate used. This CLI never sends
         * an access list (cmd_evm leaves call->access unset), so the key
         * term is 0. */
        uint64_t cap_units = 0;
        if (es.units < ref ||
            dna_ck_mul_u64(NODUS_RT_EVM_READS_BASE,
                           sys_rt->meter_policy->w_read, &cap_units) != 0 ||
            es.units - ref > cap_units) {
            fprintf(stderr, "the node's estimate is malformed (units %llu, "
                    "reference shape %llu, read allowance %llu) — nothing "
                    "was built\n", (unsigned long long)es.units,
                    (unsigned long long)ref, (unsigned long long)cap_units);
            nodus_evm_call_res_free(&es);
            goto done;
        }
        read_units = es.units - ref;
        printf("estimate: gas %llu (used %llu), node-suggested units %llu, "
               "fee %llu raw\n", (unsigned long long)es.gas_limit,
               (unsigned long long)es.gas_used,
               (unsigned long long)es.units, (unsigned long long)es.fee);
        nodus_evm_call_res_free(&es);
    }

    /* coins: native, unlocked at tip + 1 */
    int urc = nodus_client_dnac_utxo(&client, own_fp,
                                     NODUS_DNAC_MAX_UTXO_RESULTS, &utxos);
    if (urc != 0) {
        fprintf(stderr, "dnac_utxo query failed (rc=%d)\n", urc);
        goto done;
    }
    utxos_valid = 1;
    const uint64_t tip = utxos.block_height;
    if (tip == 0) {
        fprintf(stderr, "the node reported tip 0 — refusing to anchor an "
                "expiry on it\n");
        goto done;
    }
    coins = calloc((size_t)(utxos.count > 0 ? utxos.count : 1),
                   sizeof(*coins));
    if (!coins) goto done;
    int n_coins = 0;
    {
        static const uint8_t native[64] = { 0 };
        for (int i = 0; i < utxos.count; i++) {
            const nodus_dnac_utxo_entry_t *e = &utxos.entries[i];
            if (e->amount == 0 || memcmp(e->token_id, native, 64) != 0 ||
                e->unlock_block > tip)
                continue;
            memcpy(coins[n_coins].nul, e->nullifier, 64);
            coins[n_coins].amount = e->amount;
            n_coins++;
        }
    }
    nodus_dnac_fee_info_t fi;
    memset(&fi, 0, sizeof(fi));
    if (nodus_client_dnac_fee_info(&client, &fi) != 0) {
        fprintf(stderr, "dnac_fee_info failed\n");
        goto done;
    }

    nodus_v2_ruleset_id_t rs;
    cli_ruleset_id(core_rt, sys_rt, &rs);
    nodus_v2_evm_req_t req;
    memset(&req, 0, sizeof(req));
    if (cli_env_expiry(tip, &req.expiry_height) != 0) goto done;
    req.rs                  = &rs;
    req.evm_ruleset_version = evm_rt->ruleset_version;
    req.evm_ruleset_hash    = evm_rt->ruleset_hash;
    req.chain32             = chain32;
    req.tip                 = tip;
    req.gas_price           = fi.gas_price;
    req.pk                  = keys[0].pk.bytes;
    req.sk                  = keys[0].sk.bytes;
    req.call                = *call;
    req.evm_read_units      = read_units;
    req.coins               = coins;
    req.n_coins             = n_coins;
    nodus_v2_evm_err_t ee;
    int brc = nodus_v2_evm_build(&req, &built, &ee);
    if (brc != NODUS_V2_SPEND_OK) {
        switch (brc) {
        case NODUS_V2_SPEND_ERR_INSUFFICIENT:
        case NODUS_V2_SPEND_ERR_MAX_INPUTS:
            fprintf(stderr, "cannot fund %llu raw (amount + fee %llu) from "
                    "at most %u unlocked native coins (%d listed)\n",
                    (unsigned long long)ee.need, (unsigned long long)ee.fee,
                    (unsigned)DNA_EVMFUND_MAX_IN, n_coins);
            break;
        case NODUS_V2_EVM_ERR_OP_WEIGHT:
            fprintf(stderr, "the generation's meter policy does not weigh "
                    "CORE op 9 — not the EVM generation\n");
            break;
        case NODUS_V2_EVM_ERR_GAS:
            fprintf(stderr, "gas must be 1..%llu\n",
                    (unsigned long long)NODUS_RT_EVM_TX_GAS_CAP);
            break;
        case NODUS_V2_EVM_ERR_MISMATCH:
            fprintf(stderr, "the built envelope does not read back as the "
                    "request — nothing was submitted\n");
            break;
        default:
            fprintf(stderr, "the EVM envelope could not be built (rc=%d, "
                    "meter %d) — nothing was submitted\n", brc,
                    ee.meter_status);
            break;
        }
        goto done;
    }
    printf("evm %s: sender 0x", call->op == DNA_EVM_OP_CALL ? "CALL" :
           call->op == DNA_EVM_OP_CREATE ? "CREATE" :
           call->op == DNA_EVM_OP_DEPOSIT ? "DEPOSIT" :
           call->op == DNA_EVM_OP_WITHDRAW ? "WITHDRAW" : "REDEEM");
    evm_print_hex(self_addr, 32);
    printf(" nonce=%llu gas=%llu units=%llu fee=%llu inputs=%d change=%llu "
           "expiry=%llu generation=%u\n",
           (unsigned long long)built.dec.nonce,
           (unsigned long long)built.dec.gas_limit,
           (unsigned long long)built.units, (unsigned long long)built.fee,
           built.n_in, (unsigned long long)built.change,
           (unsigned long long)req.expiry_height,
           (unsigned)core_rt->generation);
    printf("  intent_id=");
    evm_print_hex(built.intent_id, 64);
    printf("\n  wire_id=");
    evm_print_hex(built.wire_id, 64);
    printf("\n");
    fflush(stdout);
    /* the local fee bound on the FINAL fee (units and gas price both come
     * from the node — red-team 1 F9): --max-fee refuses above it, else
     * above EVM_FEE_CONFIRM_RAW the CLI asks unless --yes */
    if (o->has_max_fee && built.fee > o->max_fee) {
        fprintf(stderr, "the fee %llu raw is above --max-fee %llu — nothing "
                "was submitted\n", (unsigned long long)built.fee,
                (unsigned long long)o->max_fee);
        goto done;
    }
    if (!o->has_max_fee && !o->yes && built.fee > EVM_FEE_CONFIRM_RAW) {
        if (o->dry_run) {
            printf("  NOTE: the fee %llu raw is above the local bound %llu "
                   "raw; a submit would ask to confirm (or pass --yes / "
                   "--max-fee)\n", (unsigned long long)built.fee,
                   (unsigned long long)EVM_FEE_CONFIRM_RAW);
        } else {
            char answer[16];
            printf("the fee %llu raw is above the local bound %llu raw (the "
                   "units and the gas price are the node's). Type yes to "
                   "submit: ", (unsigned long long)built.fee,
                   (unsigned long long)EVM_FEE_CONFIRM_RAW);
            fflush(stdout);
            if (!fgets(answer, sizeof(answer), stdin) ||
                strcmp(answer, "yes\n") != 0) {
                fprintf(stderr, "not confirmed — nothing was submitted\n");
                goto done;
            }
        }
    }
    if (o->dry_run) {
        printf("  PREFLIGHT SELF-CHECK: OK (2 legs CORE EVMFUND + EVM) — "
               "not submitted (--dry-run)\n");
        rc = 0;
        goto done;
    }
    if (t6_submit_on(&client, &keys[0], built.wire_id, built.env,
                     (uint32_t)built.env_len) != 0)
        goto done;
    if (o->no_wait) { rc = 0; goto done; }
    nodus_evm_receipt_t r;
    int wrc = evm_wait_receipt(&client, built.intent_id, self_addr,
                               req.expiry_height, &r);
    if (wrc == 0) {
        /* a CREATE: the address it deploys to, from the SIGNED sender and
         * the nonce read back from the signed bytes (red-team 1 F11) */
        uint8_t expect[32];
        int have_expect = built.dec.op == DNA_EVM_OP_CREATE &&
            nodus_v2_evm_create_address(self_addr, built.dec.nonce,
                                        expect) == 0;
        int mismatch = evm_print_receipt(&r, have_expect ? expect : NULL);
        if (!r.status && is_vm) {
            /* a failed receipt carries no output (design §4): show what
             * the call reverts with NOW (the state may have moved) */
            nodus_evm_call_req_t er;
            nodus_evm_call_res_t es;
            memset(&er, 0, sizeof(er));
            er.from = self_addr;
            er.to = call->op == DNA_EVM_OP_CALL ? call->to : NULL;
            er.value = call->value_wei;
            er.data = call->data;
            er.data_len = call->data_len;
            er.gas = call->gas_limit;
            if (nodus_client_evm_call(&client, &er, &es) == 0) {
                if (!es.success) {
                    printf("  re-simulated at height %llu (state may have "
                           "changed since):\n",
                           (unsigned long long)es.height);
                    evm_print_revert(es.output, es.output_len);
                }
                nodus_evm_call_res_free(&es);
            }
        }
        rc = mismatch ? 4 : r.status ? 0 : 3;
        nodus_evm_receipt_free(&r);
    } else {
        rc = 2;
    }

done:
    nodus_v2_evm_built_free(&built);
    free(coins);
    if (utxos_valid) nodus_client_free_utxo_result(&utxos);
    if (connected) nodus_client_close(&client);
    for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
    free(keys);
    return rc;
}

/* ── `evm` dispatcher ────────────────────────────────────────────────── */

static void evm_usage(void) {
    fprintf(stderr,
        "Usage (smart contracts, the EVM domain):\n"
        "  evm address --keys <dir>                  this key's 32-byte EVM address (offline)\n"
        "  evm balance [<address>] [--keys <dir>]    nonce and balance\n"
        "  evm deploy (<bytecode-hex> | --solc <file.sol>:<Contract>)\n"
        "             [--solc-bin <path>] [--args \"(t1,t2)\" v1 v2 ...]\n"
        "  evm send <address> <sig> [args ...]       a state-changing call\n"
        "  evm call <address> <sig> [args ...] [--from <address> | --keys <dir>]\n"
        "                                            read-only (evm_call); sig may end\n"
        "                                            with a return list: f(t)(r1,r2)\n"
        "  evm deposit <raw>                         NODUS -> EVM balance\n"
        "  evm withdraw <raw> [--to <fp128>]         EVM balance -> NODUS (default: self)\n"
        "  evm redeem <ticket_id>                    pay out a contract's withdrawal ticket\n"
        "  evm receipt <intent_id>\n"
        "  evm logs --from-height <H> --to-height <H> [--address <a>]\n"
        "           [--topic0..3 <t>] [--limit 1..1000]   (at most 10 000 blocks)\n"
        "           [--cursor h:x:li]  resume a page (its \"more: next\" line)\n"
        "Transactions (deploy / send / deposit / withdraw / redeem) take\n"
        "  --keys <dir> (--dry-run | --submit ip:port) [--value <wei>] [--gas <N>]\n"
        "  [--no-wait] [--force]   (--force: send even when the simulation fails)\n"
        "  [--max-fee <raw>]       refuse a fee above it (no question asked)\n"
        "  [--yes]                 no question when the fee is above the local\n"
        "                          bound (5000000000 raw = 50 NODUS)\n"
        "  The node's estimate is refused when it is malformed (gas used above\n"
        "  the suggested gas, gas above the asked limit / the cap, read units\n"
        "  outside the engine's read cap). Receipts are as reported by the\n"
        "  connected node; a deployment's address is checked against the one\n"
        "  computed from the signed sender and nonce (exit 4 on a mismatch).\n"
        "  The solc is $NODUS_SOLC or --solc-bin (default " EVM_SOLC_DEFAULT ");\n"
        "  it must be the Nodus 32-byte-address variant (nodus/tools/evm/solc).\n"
        "ABI types: uint<M> int<M> bool address bytes<M> bytes string.\n"
        "1 NODUS = 10^8 raw = 10^18 wei.\n");
}

/* Strict u64 decimal. @return 0 / -1. */
static int evm_u64(const char *s, uint64_t *out) {
    if (!s || s[0] < '0' || s[0] > '9') return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || *end || errno == ERANGE) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int cmd_evm(const char *server_ip, uint16_t server_port, int argc,
                   char **argv, int cmd_start) {
    const char *sub = cmd_start + 1 < argc ? argv[cmd_start + 1] : "";
    evm_tx_opts_t o;
    memset(&o, 0, sizeof(o));
    const char *pos[EVM_ABI_MAX_ARGS + 4];
    int n_pos = 0;
    const char *solc_spec = NULL, *solc_bin = NULL, *args_sig = NULL;
    const char *from = NULL, *to_fp = NULL, *addr_f = NULL;
    const char *topic_f[4] = { NULL, NULL, NULL, NULL };
    const char *cursor_f = NULL;            /* evm logs --cursor h:x:li */
    uint64_t fh = 0, th = 0, lim = 100;
    int has_fh = 0, has_th = 0;

    /* options anywhere after the subcommand; the rest are positional */
    for (int i = cmd_start + 2; i < argc; i++) {
        const char *a = argv[i];
        int more = i + 1 < argc;
        if (!strcmp(a, "--keys") && more) o.keys_csv = argv[++i];
        else if (!strcmp(a, "--submit") && more) o.submit = argv[++i];
        else if (!strcmp(a, "--dry-run")) o.dry_run = 1;
        else if (!strcmp(a, "--no-wait")) o.no_wait = 1;
        else if (!strcmp(a, "--force")) o.force = 1;
        else if (!strcmp(a, "--yes")) o.yes = 1;
        else if (!strcmp(a, "--max-fee") && more) {
            if (evm_u64(argv[++i], &o.max_fee) != 0) {
                fprintf(stderr, "--max-fee wants a raw amount\n");
                return 1;
            }
            o.has_max_fee = 1;
        } else if (!strcmp(a, "--gas") && more) {
            if (evm_u64(argv[++i], &o.gas) != 0 || o.gas == 0) {
                fprintf(stderr, "--gas wants a positive integer\n");
                return 1;
            }
        } else if (!strcmp(a, "--value") && more) {
            if (evm_u256_dec(argv[++i], o.value) != 0) {
                fprintf(stderr, "--value wants a decimal wei amount\n");
                return 1;
            }
            o.has_value = 1;
        } else if (!strcmp(a, "--solc") && more) solc_spec = argv[++i];
        else if (!strcmp(a, "--solc-bin") && more) solc_bin = argv[++i];
        else if (!strcmp(a, "--args") && more) args_sig = argv[++i];
        else if (!strcmp(a, "--from") && more) from = argv[++i];
        else if (!strcmp(a, "--to") && more) to_fp = argv[++i];
        else if (!strcmp(a, "--address") && more) addr_f = argv[++i];
        else if (!strncmp(a, "--topic", 7) && a[7] >= '0' && a[7] <= '3' &&
                 a[8] == '\0' && more)
            topic_f[a[7] - '0'] = argv[++i];
        else if (!strcmp(a, "--from-height") && more) {
            if (evm_u64(argv[++i], &fh) != 0) return 1;
            has_fh = 1;
        } else if (!strcmp(a, "--to-height") && more) {
            if (evm_u64(argv[++i], &th) != 0) return 1;
            has_th = 1;
        } else if (!strcmp(a, "--limit") && more) {
            if (evm_u64(argv[++i], &lim) != 0) return 1;
        } else if (!strcmp(a, "--cursor") && more) {
            cursor_f = argv[++i];
        } else if (a[0] == '-' && a[1] == '-') {
            fprintf(stderr, "unknown option %s\n", a);
            evm_usage();
            return 1;
        } else {
            if (n_pos >= (int)(sizeof(pos) / sizeof(pos[0]))) {
                fprintf(stderr, "too many arguments\n");
                return 1;
            }
            pos[n_pos++] = a;
        }
    }

    /* ── offline ── */
    if (!strcmp(sub, "address")) {
        nodus_identity_t *keys = calloc(4, sizeof(*keys));
        int rc = 1;
        uint8_t a[32];
        if (keys && o.keys_csv && act_load_keys(o.keys_csv, keys, 4) == 1 &&
            evm_addr_of_pk(keys[0].pk.bytes, a) == 0) {
            printf("0x");
            evm_print_hex(a, 32);
            printf("\n");
            rc = 0;
        } else {
            fprintf(stderr, "evm address --keys <dir>\n");
        }
        if (keys) {
            for (int i = 0; i < 4; i++) nodus_identity_clear(&keys[i]);
            free(keys);
        }
        return rc;
    }

    /* ── transactions ── */
    if (!strcmp(sub, "deploy") || !strcmp(sub, "send") ||
        !strcmp(sub, "deposit") || !strcmp(sub, "withdraw") ||
        !strcmp(sub, "redeem")) {
        if (!o.dry_run && !o.submit) {
            fprintf(stderr, "--dry-run or --submit ip:port required\n");
            return 1;
        }
        dna_evm_call_t c;
        memset(&c, 0, sizeof(c));
        uint8_t *data = NULL;
        size_t data_len = 0;
        int rc = 1;
        if (!strcmp(sub, "deploy")) {
            uint8_t *code = NULL;
            size_t code_len = 0;
            if (solc_spec) {
                const char *bin = solc_bin ? solc_bin : getenv("NODUS_SOLC");
                if (!bin || !*bin) bin = EVM_SOLC_DEFAULT;
                if (evm_solc(bin, solc_spec, &code, &code_len) != 0) return 1;
            } else if (n_pos >= 1) {
                size_t hl = strlen(pos[0]);
                code = malloc(hl / 2 + 1);
                if (!code || evm_hex_bytes(pos[0], code, hl / 2 + 1,
                                           &code_len) != 0 || !code_len) {
                    free(code);
                    fprintf(stderr, "the bytecode must be hex\n");
                    return 1;
                }
            } else {
                evm_usage();
                return 1;
            }
            /* constructor arguments: --args "(t1,t2)" v1 v2 — positional
             * values after the bytecode (or all of them with --solc) */
            int first = solc_spec ? 0 : 1;
            uint8_t *enc = NULL;
            size_t enc_len = 0;
            if (args_sig) {
                evm_abi_sig_t g;
                if (evm_abi_sig(args_sig, &g) != 0 || g.has_out ||
                    g.canon[0] != '(') {
                    fprintf(stderr, "--args wants \"(t1,t2,...)\"\n");
                    free(code);
                    return 1;
                }
                if (n_pos - first != g.n_in) {
                    fprintf(stderr, "the constructor takes %d argument(s), "
                            "%d given\n", g.n_in, n_pos - first);
                    free(code);
                    return 1;
                }
                if (evm_abi_encode(g.in, g.n_in, (char **)(pos + first),
                                   &enc, &enc_len) != 0) {
                    free(code);
                    return 1;
                }
            } else if (n_pos > first) {
                fprintf(stderr, "constructor values need --args "
                        "\"(t1,...)\"\n");
                free(code);
                return 1;
            }
            data_len = code_len + enc_len;
            data = malloc(data_len ? data_len : 1);
            if (data) {
                memcpy(data, code, code_len);
                if (enc_len) memcpy(data + code_len, enc, enc_len);
            }
            free(code);
            free(enc);
            if (!data) return 1;
            if (data_len > DNA_EVM_MAX_INITCODE) {
                fprintf(stderr, "initcode is %zu bytes — over the %u-byte "
                        "EIP-3860 limit\n", data_len,
                        (unsigned)DNA_EVM_MAX_INITCODE);
                free(data);
                return 1;
            }
            c.op = DNA_EVM_OP_CREATE;
        } else if (!strcmp(sub, "send")) {
            evm_abi_sig_t g;
            if (n_pos < 2 || evm_addr_parse(pos[0], c.to) != 0 ||
                evm_abi_sig(pos[1], &g) != 0 || g.canon[0] == '(') {
                evm_usage();
                return 1;
            }
            if (n_pos - 2 != g.n_in) {
                fprintf(stderr, "%s takes %d argument(s), %d given\n",
                        g.canon, g.n_in, n_pos - 2);
                return 1;
            }
            uint8_t *enc = NULL;
            size_t enc_len = 0;
            if (evm_abi_encode(g.in, g.n_in, (char **)(pos + 2), &enc,
                               &enc_len) != 0)
                return 1;
            data_len = 4 + enc_len;
            data = malloc(data_len);
            if (!data || evm_abi_selector(g.canon, data) != 0) {
                free(enc);
                free(data);
                return 1;
            }
            if (enc_len) memcpy(data + 4, enc, enc_len);
            free(enc);
            c.op = DNA_EVM_OP_CALL;
        } else if (!strcmp(sub, "deposit") || !strcmp(sub, "withdraw")) {
            if (n_pos != 1 || evm_u64(pos[0], &c.amount_raw) != 0 ||
                c.amount_raw == 0) {
                fprintf(stderr, "evm %s <raw amount > 0>\n", sub);
                return 1;
            }
            c.op = !strcmp(sub, "deposit") ? DNA_EVM_OP_DEPOSIT
                                           : DNA_EVM_OP_WITHDRAW;
            if (c.op == DNA_EVM_OP_WITHDRAW) {
                nodus_identity_t *k = calloc(4, sizeof(*k));
                int ok = 0;
                if (to_fp) {
                    ok = qgp_fp_hex_to_raw(to_fp, c.dest_fp) == 0;
                } else if (k && o.keys_csv &&
                           act_load_keys(o.keys_csv, k, 4) == 1) {
                    ok = qgp_sha3_512(k[0].pk.bytes, DNAC_PUBKEY_SIZE,
                                      c.dest_fp) == 0;
                }
                if (k) {
                    for (int i = 0; i < 4; i++) nodus_identity_clear(&k[i]);
                    free(k);
                }
                if (!ok) {
                    fprintf(stderr, "--to wants a 128-hex Nodus address "
                            "(default: the --keys identity)\n");
                    return 1;
                }
            }
        } else {                                       /* redeem */
            size_t tl = 0;
            if (n_pos != 1 || evm_hex_bytes(pos[0], c.ticket_id, 64,
                                            &tl) != 0 || tl != 64) {
                fprintf(stderr, "evm redeem <ticket_id: 128 hex>\n");
                return 1;
            }
            /* the call must name the ticket EXACTLY (design §2): read it */
            nodus_client_t client;
            if (!server_ip && !o.submit) return 1;
            char sip[64];
            uint16_t sport = 0;
            if (t6_resolve_target(o.submit, server_ip, server_port, sip,
                                  &sport) != 0 ||
                t8_session(&client, sip, sport) != 0)
                return 1;
            nodus_evm_ticket_t t;
            int qrc = nodus_client_evm_ticket(&client, c.ticket_id, &t);
            nodus_client_close(&client);
            if (qrc != 0 || !t.pending) {
                fprintf(stderr, "%s\n", qrc ? "evm_ticket failed" :
                        "no such pending ticket (never created, or already "
                        "redeemed)");
                return 1;
            }
            c.op = DNA_EVM_OP_REDEEM;
            c.amount_raw = t.amount_raw;
            memcpy(c.dest_fp, t.dest_fp, 64);
            printf("ticket: %llu raw to ", (unsigned long long)t.amount_raw);
            evm_print_hex(t.dest_fp, 64);
            printf("\n");
        }
        if (o.has_value) {
            if (c.op != DNA_EVM_OP_CALL && c.op != DNA_EVM_OP_CREATE) {
                fprintf(stderr, "--value applies to deploy / send only\n");
                free(data);
                return 1;
            }
            memcpy(c.value_wei, o.value, 32);
        }
        c.data = data;
        c.data_len = (uint32_t)data_len;
        rc = evm_tx_run(server_ip, server_port, &o, &c);
        free(data);
        return rc;
    }

    /* ── reads (one session as -i / a random identity) ── */
    if (!server_ip) {
        fprintf(stderr, "Server required (-s <ip>)\n");
        return 1;
    }
    nodus_client_t client;
    if (!strcmp(sub, "balance")) {
        uint8_t a[32];
        if (n_pos == 1) {
            if (evm_addr_parse(pos[0], a) != 0) {
                fprintf(stderr, "an address is 64 hex characters\n");
                return 1;
            }
        } else {
            nodus_identity_t *k = calloc(4, sizeof(*k));
            int ok = k && o.keys_csv && act_load_keys(o.keys_csv, k, 4) == 1 &&
                     evm_addr_of_pk(k[0].pk.bytes, a) == 0;
            if (k) {
                for (int i = 0; i < 4; i++) nodus_identity_clear(&k[i]);
                free(k);
            }
            if (!ok) {
                fprintf(stderr, "evm balance <address> | --keys <dir>\n");
                return 1;
            }
        }
        if (t8_session(&client, server_ip, server_port) != 0) return 1;
        nodus_evm_account_t acc;
        int qrc = nodus_client_evm_account(&client, a, &acc);
        nodus_client_close(&client);
        if (qrc != 0) {
            fprintf(stderr, "evm_account failed (rc=%d)\n", qrc);
            return 1;
        }
        char wei[80], nod[96];
        evm_u256_to_dec(acc.balance_wei, wei);
        evm_wei_to_nodus(acc.balance_wei, nod, sizeof(nod));
        printf("address 0x");
        evm_print_hex(a, 32);
        printf("\n  height %llu\n  nonce %llu\n  balance %s wei (%s NODUS)\n"
               "  code %u bytes\n", (unsigned long long)acc.height,
               (unsigned long long)acc.nonce, wei, nod,
               (unsigned)acc.code_size);
        return 0;
    }
    if (!strcmp(sub, "call")) {
        evm_abi_sig_t g;
        uint8_t to[32], fromb[32];
        memset(fromb, 0, sizeof(fromb));
        if (n_pos < 2 || evm_addr_parse(pos[0], to) != 0 ||
            evm_abi_sig(pos[1], &g) != 0 || g.canon[0] == '(') {
            evm_usage();
            return 1;
        }
        if (n_pos - 2 != g.n_in) {
            fprintf(stderr, "%s takes %d argument(s), %d given\n", g.canon,
                    g.n_in, n_pos - 2);
            return 1;
        }
        if (from) {
            if (evm_addr_parse(from, fromb) != 0) {
                fprintf(stderr, "--from wants a 64-hex address\n");
                return 1;
            }
        } else if (o.keys_csv) {
            nodus_identity_t *k = calloc(4, sizeof(*k));
            int ok = k && act_load_keys(o.keys_csv, k, 4) == 1 &&
                     evm_addr_of_pk(k[0].pk.bytes, fromb) == 0;
            if (k) {
                for (int i = 0; i < 4; i++) nodus_identity_clear(&k[i]);
                free(k);
            }
            if (!ok) return 1;
        }
        uint8_t *enc = NULL, *data = NULL;
        size_t enc_len = 0;
        if (evm_abi_encode(g.in, g.n_in, (char **)(pos + 2), &enc,
                           &enc_len) != 0)
            return 1;
        data = malloc(4 + enc_len);
        if (!data || evm_abi_selector(g.canon, data) != 0) {
            free(enc);
            free(data);
            return 1;
        }
        if (enc_len) memcpy(data + 4, enc, enc_len);
        free(enc);
        if (t8_session(&client, server_ip, server_port) != 0) {
            free(data);
            return 1;
        }
        nodus_evm_call_req_t er;
        nodus_evm_call_res_t es;
        memset(&er, 0, sizeof(er));
        er.from = fromb;
        er.to = to;
        er.value = o.has_value ? o.value : NULL;
        er.data = data;
        er.data_len = 4 + enc_len;
        er.gas = o.gas;
        int qrc = nodus_client_evm_call(&client, &er, &es);
        nodus_client_close(&client);
        free(data);
        if (qrc != 0) {
            fprintf(stderr, "evm_call failed (rc=%d)\n", qrc);
            return 1;
        }
        printf("%s at height %llu, gas %llu\n",
               es.success ? "ok" : "REVERTED",
               (unsigned long long)es.height,
               (unsigned long long)es.gas_used);
        int rc = 0;
        if (!es.success) {
            evm_print_revert(es.output, es.output_len);
            rc = 3;
        } else if (g.has_out) {
            if (evm_abi_print(g.out, g.n_out, es.output,
                              es.output_len) != 0) {
                printf("  (the output does not decode as the return list) "
                       "0x");
                evm_print_hex(es.output, es.output_len);
                printf("\n");
                rc = 1;
            }
        } else {
            printf("  output: 0x");
            evm_print_hex(es.output, es.output_len);
            printf("\n");
        }
        nodus_evm_call_res_free(&es);
        return rc;
    }
    if (!strcmp(sub, "receipt")) {
        uint8_t id[64];
        size_t il = 0;
        if (n_pos != 1 || evm_hex_bytes(pos[0], id, 64, &il) != 0 ||
            il != 64) {
            fprintf(stderr, "evm receipt <intent_id: 128 hex>\n");
            return 1;
        }
        if (t8_session(&client, server_ip, server_port) != 0) return 1;
        nodus_evm_receipt_t r;
        int qrc = nodus_client_evm_receipt(&client, id, &r);
        nodus_client_close(&client);
        if (qrc != 0) {
            fprintf(stderr, "evm_receipt failed (rc=%d)\n", qrc);
            return 1;
        }
        if (!r.found) {
            printf("no receipt on this node (not included yet, or never)\n");
            return 2;
        }
        /* no signed transaction here: the contract address cannot be
         * re-derived (the receipt carries no sender / nonce) */
        evm_print_receipt(&r, NULL);
        nodus_evm_receipt_free(&r);
        return 0;
    }
    if (!strcmp(sub, "logs")) {
        nodus_evm_logs_req_t lq;
        uint8_t addr[32], tp[4][32];
        memset(&lq, 0, sizeof(lq));
        if (!has_fh || !has_th || lim < 1 || lim > NODUS_EVM_LOGS_MAX_LIMIT) {
            fprintf(stderr, "evm logs --from-height <H> --to-height <H> "
                    "[--limit 1..%u]\n", (unsigned)NODUS_EVM_LOGS_MAX_LIMIT);
            return 1;
        }
        lq.from_height = fh;
        lq.to_height = th;
        lq.limit = (uint32_t)lim;
        if (addr_f) {
            if (evm_addr_parse(addr_f, addr) != 0) return 1;
            lq.addr = addr;
        }
        for (int t = 0; t < 4; t++)
            if (topic_f[t]) {
                size_t tl = 0;
                if (evm_hex_bytes(topic_f[t], tp[t], 32, &tl) != 0 ||
                    tl != 32)
                    return 1;
                lq.topic[t] = tp[t];
            }
        nodus_evm_logs_cursor_t cur;
        if (cursor_f) {
            /* h:x:li — the "next" line a previous page printed */
            char part[3][24];
            const char *s = cursor_f;
            int ok = 1;
            for (int k = 0; k < 3 && ok; k++) {
                const char *e = strchr(s, ':');
                size_t pl = (k < 2) ? (e ? (size_t)(e - s) : 0) : strlen(s);
                if ((k < 2 && !e) || pl == 0 || pl >= sizeof(part[k])) {
                    ok = 0;
                    break;
                }
                memcpy(part[k], s, pl);
                part[k][pl] = '\0';
                s = (k < 2) ? e + 1 : s + pl;
            }
            if (!ok || evm_u64(part[0], &cur.height) != 0 ||
                evm_u64(part[1], &cur.item) != 0 ||
                evm_u64(part[2], &cur.log_index) != 0 ||
                cur.height < fh || cur.height > th ||
                cur.item > NODUS_EVM_LOGS_CURSOR_POS_MAX ||
                cur.log_index > NODUS_EVM_LOGS_CURSOR_POS_MAX) {
                fprintf(stderr, "--cursor wants h:x:li with --from-height "
                        "<= h <= --to-height (the \"next\" line of the "
                        "previous page)\n");
                return 1;
            }
            lq.cursor = &cur;
        }
        if (t8_session(&client, server_ip, server_port) != 0) return 1;
        nodus_evm_logs_res_t lr;
        int qrc = nodus_client_evm_logs(&client, &lq, &lr);
        nodus_client_close(&client);
        if (qrc != 0) {
            fprintf(stderr, "evm_logs failed (rc=%d)%s\n", qrc,
                    qrc == -1 ? " — at most 10 000 blocks per query" : "");
            return 1;
        }
        for (size_t i = 0; i < lr.n; i++) {
            const nodus_evm_log_t *l = &lr.logs[i];
            printf("h=%llu x=%u li=%u address=0x",
                   (unsigned long long)l->height, (unsigned)l->item,
                   (unsigned)l->log_index);
            evm_print_hex(l->addr, 32);
            printf(" tx=");
            evm_print_hex(l->intent_id, 64);
            printf("\n");
            for (uint8_t t = 0; t < l->n_topics; t++) {
                printf("  topic%u 0x", (unsigned)t);
                evm_print_hex(l->topics[t], 32);
                printf("\n");
            }
            printf("  data 0x");
            evm_print_hex(l->data, l->data_len);
            printf("\n");
        }
        printf("%zu log(s)\n", lr.n);
        if (lr.more && lr.has_cursor)
            /* the node stopped before --to-height: the same query with
             * this cursor resumes exactly where it stopped */
            printf("more: next --cursor %llu:%llu:%llu\n",
                   (unsigned long long)lr.cursor.height,
                   (unsigned long long)lr.cursor.item,
                   (unsigned long long)lr.cursor.log_index);
        nodus_evm_logs_free(&lr);
        return 0;
    }
    evm_usage();
    return 1;
}
#endif /* NODUS_EVM_ENABLED */
#endif /* NODUS_CLI_HAS_DNAC */

/* ── Usage ───────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr, "Nodus CLI v%s\n", NODUS_VERSION_STRING);
    fprintf(stderr, "Usage: %s -s <server> [-p <port>] [-i <identity_dir>] <command> [args]\n", prog);
    fprintf(stderr, "\nCommands:\n");
    fprintf(stderr, "  whoami           Show identity\n");
    fprintf(stderr, "  ping             Ping server\n");
    fprintf(stderr, "  put <key> <val>  Store DHT value\n");
    fprintf(stderr, "  get <key>        Retrieve DHT value\n");
    fprintf(stderr, "  listen <key>     Subscribe to key changes\n");
    fprintf(stderr, "  servers          List cluster servers\n");
    fprintf(stderr, "  presence [fp..]  Query presence (self + optional fps)\n");
    fprintf(stderr, "  hold             Stay connected (test presence visibility)\n");
    fprintf(stderr, "  witness          Show the committee for the next block\n");
    fprintf(stderr, "  addr-history [--before H[:I:Q]] [--limit N]\n");
    fprintf(stderr, "                   This identity's history from the node's local index\n");
    fprintf(stderr, "  coins            This identity's unspent coins (id, amount, bh, ub) and the tip\n");
    fprintf(stderr, "  ch_listen <uuid> [logfile]  Subscribe to channel on TCP 4003, log posts\n");
#ifdef NODUS_CLI_HAS_DNAC
    fprintf(stderr, "  ruleset-info     The rule-set generation the node runs (and if this CLI carries it)\n");
    fprintf(stderr, "  name register <name> --keys <dir> (--dry-run | --submit ip:port) [--fee <raw>]\n");
    fprintf(stderr, "  name lookup <name> | name of <fp128>   On-chain names (one node's answer)\n");
    fprintf(stderr, "  evm (address | balance | deploy | send | call | deposit | withdraw |\n");
    fprintf(stderr, "       redeem | receipt | logs) ...   Smart contracts (`evm` alone: usage)\n");
    fprintf(stderr, "  chain-config propose --param <NAME> --value <N> --effective <BLOCK>\n");
    fprintf(stderr, "  stake [--commission BPS] [--bond RAW = exactly 10M NODUS]   Bond this node identity as validator (S3)\n");
    fprintf(stderr, "                              [--nonce <N>]  (committee operator only)\n");
    fprintf(stderr, "                  NAME: TARGET_ACTIVE_COUNT | GAS_PRICE_RAW_PER_UNIT |\n");
    fprintf(stderr, "                        TOKEN_CREATE_FEE_RAW | HF2_ACTIVE |\n");
    fprintf(stderr, "                        HF3_ACTIVE | RULESET_GEN2 |\n");
    fprintf(stderr, "                        NAME_PRICE_3P | NAME_PRICE_4P |\n");
    fprintf(stderr, "                        NAME_PRICE_5P | NAME_PRICE_6P |\n");
    fprintf(stderr, "                        EVM_ACTIVE | EVM_BLOCK_GAS_LIMIT |\n");
    fprintf(stderr, "                        RULESET_GEN_STORAGE | DELEGATE_NAME_REQUIRED\n");
    fprintf(stderr, "                        (the parameters the running consensus reads)\n");
    fprintf(stderr, "                  run without --value for per-param ranges\n");
    fprintf(stderr, "  storage register (--dry-run | --submit ip:port)   Register THIS node (-i) as a storage node\n");
    fprintf(stderr, "                                   (bond exactly 1M NODUS from the node key's coins)\n");
    fprintf(stderr, "  storage exit (--dry-run | --submit ip:port)       Exit; bond back next boundary, locked %d epochs\n",
            (int)DNAC_STORAGE_EXIT_LOCK_EPOCHS);
    fprintf(stderr, "  storage status [--fp <hex128>]   Registry row, storage-set membership, eligible segments\n");
    fprintf(stderr, "  v2-claim --legacy-db <t.db> --db <s.db> --keys <dir>\n");
    fprintf(stderr, "           (--dry-run | --submit ip:port)   Successor GENESIS_CLAIM\n");
    fprintf(stderr, "  v2-envelope stake --keys <dir> --bond <raw = exactly 10M NODUS>\n");
    fprintf(stderr, "           --commission <bps> --dest-fp <hex128>\n");
    fprintf(stderr, "           (--dry-run | --submit ip:port)   O11 two-leg STAKE\n");
    fprintf(stderr, "  v2-envelope delegate --keys <dir> --validator <hex5184 pubkey>\n");
    fprintf(stderr, "           --amount <raw> (--dry-run | --submit ip:port)\n");
    fprintf(stderr, "                                   two-leg DELEGATE (own key = self-delegation)\n");
    fprintf(stderr, "                                   after HF-8: needs an on-chain name (self exempt)\n");
    fprintf(stderr, "  v2-envelope undelegate --keys <dir> --validator <hex5184 pubkey>\n");
    fprintf(stderr, "           --amount <raw> (--dry-run | --submit ip:port)\n");
    fprintf(stderr, "                                   two-leg UNDELEGATE (returned coin locked %d epochs)\n",
            (int)DNAC_UNDELEGATE_LOCK_EPOCHS);
    fprintf(stderr, "  v2-envelope unstake --keys <dir> (--dry-run | --submit ip:port)\n");
    fprintf(stderr, "                                   two-leg UNSTAKE: the --keys validator retires;\n");
    fprintf(stderr, "                                   bond back %d epochs after graduation,\n",
            (int)DNAC_VALIDATOR_UNBOND_EPOCHS);
    fprintf(stderr, "                                   delegations back to delegators, locked %d epochs\n",
            (int)DNAC_UNDELEGATE_LOCK_EPOCHS);
    fprintf(stderr, "  v2-envelope spend --keys <dir> --to <fp128hex> --amount <raw|all>\n");
    fprintf(stderr, "           [--fee <raw>] [--token <hex128>] [--count <N|all>]\n");
    fprintf(stderr, "           [--shard <I>/<M>] [--no-dust-sweep]\n");
    fprintf(stderr, "           [--submit ip:port] [--dry-run]   CORE SPEND (coin transfer)\n");
    fprintf(stderr, "  v2-envelope token-create --keys <dir> --name <n> --symbol <s>\n");
    fprintf(stderr, "           --decimals <0..18> --supply <raw> [--to <fp128hex>]\n");
    fprintf(stderr, "           [--fee <raw>] [--token-id <hex128>]\n");
    fprintf(stderr, "           (--dry-run | --submit ip:port)   CORE TOKEN_CREATE\n");
    fprintf(stderr, "  msig address --m <M> --pubkey <file> ... [--descriptor-out <f>]\n");
    fprintf(stderr, "                                   M-of-N multisig address (offline)\n");
    fprintf(stderr, "  v2-envelope spend --msig <descriptor> --keys <dir>\n");
    fprintf(stderr, "           --in <nul128hex>:<amount> ... --to <fp128hex> --amount <raw>\n");
    fprintf(stderr, "           [--fee <raw>] [--signers <K>] --export <file>\n");
    fprintf(stderr, "                                   UNSIGNED multisig spend + digest\n");
    fprintf(stderr, "  msig sign --keys <dir> --in <export> --out <sigfile>   (offline)\n");
    fprintf(stderr, "  msig combine --in <export> --sig <f> ... (--keys <dir>\n");
    fprintf(stderr, "           [--submit ip:port] | --out <envelope>)   assemble + submit\n");
#endif
}

/* ── Main ────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    const char *server_ip = NULL;
    uint16_t server_port = NODUS_DEFAULT_TCP_PORT;
    const char *identity_dir = NULL;
    int opt;

    /* Leading "+" makes getopt stop at the first non-option argument so
     * sub-command long options (e.g. `chain-config propose --param ...`)
     * are not consumed here and instead reach the command handler. */
    while ((opt = getopt(argc, argv, "+s:p:i:h")) != -1) {
        switch (opt) {
        case 's': {
            /* Support host:port format */
            char *colon = strchr(optarg, ':');
            if (colon) {
                static char host_buf[256];
                size_t hlen = (size_t)(colon - optarg);
                if (hlen >= sizeof(host_buf)) hlen = sizeof(host_buf) - 1;
                memcpy(host_buf, optarg, hlen);
                host_buf[hlen] = '\0';
                server_ip = host_buf;
                server_port = (uint16_t)atoi(colon + 1);
            } else {
                server_ip = optarg;
            }
            break;
        }
        case 'p': server_port = (uint16_t)atoi(optarg); break;
        case 'i': identity_dir = optarg; break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *command = argv[optind];

    /* Handle whoami without server */
    if (strcmp(command, "whoami") == 0) {
        if (identity_dir) {
            if (nodus_identity_load(identity_dir, &identity) != 0) {
                fprintf(stderr, "Failed to load identity from %s\n", identity_dir);
                return 1;
            }
        } else {
            fprintf(stderr, "No identity directory. Generating random.\n");
            nodus_identity_generate(&identity);
        }
        cmd_whoami();
        nodus_identity_clear(&identity);
        return 0;
    }

#ifdef NODUS_CLI_HAS_DNAC
    /* general multisig — `msig address` and `msig sign` are OFFLINE;
     * `msig combine` submits over its own --submit / -s session */
    if (strcmp(command, "msig") == 0) {
        const char *sub = optind + 1 < argc ? argv[optind + 1] : "";
        if (!strcmp(sub, "address"))
            return cmd_msig_address(argc, argv, optind);
        if (!strcmp(sub, "sign"))
            return cmd_msig_sign(argc, argv, optind);
        if (!strcmp(sub, "combine"))
            return cmd_msig_combine(server_ip, server_port, argc, argv,
                                    optind);
        fprintf(stderr, "Usage: msig (address | sign | combine) ...\n");
        return 1;
    }
#endif

#if defined(NODUS_CLI_HAS_DNAC) && defined(NODUS_EVM_ENABLED)
    /* Nodus EVM — `evm address` is OFFLINE (the --keys identity's address) */
    if (strcmp(command, "evm") == 0 && optind + 1 < argc &&
        strcmp(argv[optind + 1], "address") == 0)
        return cmd_evm(server_ip, server_port, argc, argv, optind);
#endif

    /* All other commands need a server, except cluster-status which
     * takes its target list as positional args. */
    if (!server_ip && strcmp(command, "cluster-status") != 0) {
        fprintf(stderr, "Server required (-s <ip>)\n");
        return 1;
    }

    signal(SIGINT, sighandler);
    signal(SIGPIPE, SIG_IGN);

    /* Load or generate identity */
    if (identity_dir) {
        if (nodus_identity_load(identity_dir, &identity) != 0) {
            fprintf(stderr, "Failed to load identity from %s\n", identity_dir);
            return 1;
        }
    } else {
        nodus_identity_generate(&identity);
        fprintf(stderr, "Using random identity: %s\n", identity.fingerprint);
    }

    /* cluster-status: drives its own per-target connect+auth+query loop,
     * does not use the default single-target connection below. */
    if (strcmp(command, "cluster-status") == 0) {
        int rc = cmd_cluster_status(argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* witness: its own nodus_client_t session (dnac_committee). */
    if (strcmp(command, "witness") == 0) {
        int rc = cmd_witness(server_ip, server_port);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* addr-history: its own nodus_client_t session (dnac_addr_history),
     * as THIS identity — the node answers only the session's own owner. */
    if (strcmp(command, "addr-history") == 0) {
        int rc = cmd_addr_history(server_ip, server_port, argc, argv,
                                  optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* coins: its own nodus_client_t session (dnac_utxo), as THIS
     * identity — the node answers only the session's own owner. */
    if (strcmp(command, "coins") == 0) {
        int rc = cmd_coins(server_ip, server_port);
        nodus_identity_clear(&identity);
        return rc;
    }

#ifdef NODUS_CLI_HAS_DNAC
    /* chain-config: drives its own nodus_client_t session, uses tier-2
     * DNAC RPCs + Stage E.2 tier-3 helper. Bypasses the outer
     * single-target connect+auth below. */
    if (strcmp(command, "chain-config") == 0) {
        if (optind + 1 >= argc || strcmp(argv[optind + 1], "propose") != 0) {
            fprintf(stderr, "Usage: chain-config propose --param <NAME> "
                             "--value <N> --effective <BLOCK> [--nonce <N>]\n");
            nodus_identity_clear(&identity);
            return 1;
        }
        int rc = cmd_chain_config_propose(server_ip, server_port,
                                            argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* S3 — stake: bond THIS node identity as a validator. */
    if (strcmp(command, "stake") == 0) {
        int rc = cmd_stake(server_ip, server_port, argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* storage reward v1 (B2b-CLI) — register / exit THIS node identity as
     * a storage node, or show a storage node's status. register / exit
     * sign with the node key: without -i the identity above is a random
     * key that owns no coin and no registry row, so they refuse. */
    if (strcmp(command, "storage") == 0) {
        int rc;
        const char *sub = optind + 1 < argc ? argv[optind + 1] : NULL;
        if (sub && (strcmp(sub, "register") == 0 ||
                    strcmp(sub, "exit") == 0)) {
            if (!identity_dir) {
                fprintf(stderr, "storage %s signs with the node identity: "
                        "give -i <node identity dir>\n", sub);
                rc = 1;
            } else {
                rc = cmd_storage_tx(server_ip, server_port, argc, argv,
                                    optind, strcmp(sub, "exit") == 0);
            }
        } else if (sub && strcmp(sub, "status") == 0) {
            rc = cmd_storage_status(server_ip, server_port, argc, argv,
                                    optind, identity_dir != NULL);
        } else {
            fprintf(stderr, "Usage: -i <node identity dir> storage "
                    "(register | exit) (--dry-run | --submit ip:port)\n"
                    "       storage status [--fp <hex128>]\n");
            rc = 1;
        }
        nodus_identity_clear(&identity);
        return rc;
    }

    /* O15D — v2-envelope: successor-chain envelope builder/submitter.
     * O15F T6 adds the `stake` subcommand (O11 two-leg STAKE); CLI-SPEND
     * adds `spend` (single-leg CORE SPEND, networked); `token-create`
     * builds a single-leg CORE TOKEN_CREATE the same way; W-B adds
     * `delegate` (two-leg DELEGATE, the stake builder's sibling);
     * `undelegate` and `unstake` are the same builder's ops 4 and 3. */
    if (strcmp(command, "v2-envelope") == 0) {
        int rc;
        if (optind + 1 < argc &&
            (strcmp(argv[optind + 1], "stake") == 0 ||
             strcmp(argv[optind + 1], "delegate") == 0 ||
             strcmp(argv[optind + 1], "unstake") == 0 ||
             strcmp(argv[optind + 1], "undelegate") == 0))
            rc = cmd_v2_stake(server_ip, server_port, argc, argv, optind);
        else if (optind + 1 < argc && strcmp(argv[optind + 1], "spend") == 0)
            rc = cmd_v2_spend(server_ip, server_port, argc, argv, optind);
        else if (optind + 1 < argc &&
                 strcmp(argv[optind + 1], "token-create") == 0)
            rc = cmd_v2_token_create(server_ip, server_port, argc, argv,
                                     optind);
        else
            rc = cmd_v2_envelope(server_ip, server_port, argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* HF-4 — the rule-set generation the node runs, and on-chain names */
    if (strcmp(command, "ruleset-info") == 0) {
        int rc = cmd_ruleset_info(server_ip, server_port);
        nodus_identity_clear(&identity);
        return rc;
    }
    if (strcmp(command, "name") == 0) {
        int rc;
        const char *sub = optind + 1 < argc ? argv[optind + 1] : NULL;
        if (sub && strcmp(sub, "register") == 0)
            rc = cmd_name_register(server_ip, server_port, argc, argv,
                                   optind);
        else if (sub && (strcmp(sub, "lookup") == 0 ||
                         strcmp(sub, "of") == 0) && optind + 2 < argc)
            rc = cmd_name_query(server_ip, server_port,
                                strcmp(sub, "of") == 0, argv[optind + 2]);
        else {
            fprintf(stderr, "Usage: name register <name> --keys <dir> "
                    "(--dry-run | --submit ip:port) [--fee <raw>]\n"
                    "       name lookup <name>\n"
                    "       name of <fp128>\n");
            rc = 1;
        }
        nodus_identity_clear(&identity);
        return rc;
    }

    /* O15F T6 — v2-claim: successor GENESIS_CLAIM builder/submitter. */
    if (strcmp(command, "v2-claim") == 0) {
        int rc = cmd_v2_claim(server_ip, server_port, argc, argv, optind);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* Nodus EVM — smart contracts: reads on their own session (-i identity),
     * transactions on a session as the --keys identity */
    if (strcmp(command, "evm") == 0) {
#ifdef NODUS_EVM_ENABLED
        int rc = cmd_evm(server_ip, server_port, argc, argv, optind);
#else
        fprintf(stderr, "this nodus-cli build carries no EVM (the "
                "standalone non-Windows nodus build does)\n");
        int rc = 1;
#endif
        nodus_identity_clear(&identity);
        return rc;
    }
#endif

    /* ch_listen: connects to TCP 4003 directly, bypasses TCP 4001 */
    if (strcmp(command, "ch_listen") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: ch_listen <uuid> [logfile]\n");
            nodus_identity_clear(&identity);
            return 1;
        }
        uint16_t ch_port = server_port + 2;  /* 4001 → 4003 */
        const char *lf = (optind + 2 < argc) ? argv[optind + 2] : NULL;
        int rc = cmd_ch_listen(server_ip, ch_port, argv[optind + 1], lf);
        nodus_identity_clear(&identity);
        return rc;
    }

    /* Remaining commands: connect to TCP 4001, authenticate */
    int rc = 1;

    /* Connect */
    nodus_tcp_init(&transport, -1);
    transport.on_frame = on_frame;
    transport.on_disconnect = on_disconnect;
    transport.on_connect = on_connect;

    printf("Connecting to %s:%u...\n", server_ip, server_port);
    fflush(stdout);
    server_conn = nodus_tcp_connect(&transport, server_ip, server_port);
    if (!server_conn) {
        fprintf(stderr, "Failed to connect\n");
        goto cleanup;
    }

    /* Wait for connection */
    for (int i = 0; i < 100 && server_conn->state == NODUS_CONN_CONNECTING; i++)
        nodus_tcp_poll(&transport, 50);

    if (!server_conn || server_conn->state != NODUS_CONN_CONNECTED) {
        fprintf(stderr, "Connection failed\n");
        goto cleanup;
    }
    printf("Connected.\n");
    fflush(stdout);

    /* Authenticate */
    printf("Authenticating...\n");
    fflush(stdout);
    if (do_auth() != 0) {
        fprintf(stderr, "Authentication failed\n");
        goto cleanup;
    }
    printf("Authenticated.\n");
    fflush(stdout);

    /* Dispatch command */
    rc = 0;
    if (strcmp(command, "ping") == 0) {
        rc = cmd_ping();
    } else if (strcmp(command, "servers") == 0) {
        rc = cmd_servers();
    } else if (strcmp(command, "put") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Usage: put <key> <value>\n");
            rc = 1;
        } else {
            rc = cmd_put(argv[optind + 1], argv[optind + 2]);
        }
    } else if (strcmp(command, "get") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: get <key>\n");
            rc = 1;
        } else {
            rc = cmd_get(argv[optind + 1]);
        }
    } else if (strcmp(command, "presence") == 0) {
        rc = cmd_presence(argc, argv, optind);
    } else if (strcmp(command, "hold") == 0) {
        rc = cmd_presence_hold();
    } else if (strcmp(command, "listen") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Usage: listen <key>\n");
            rc = 1;
        } else {
            rc = cmd_listen(argv[optind + 1]);
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        rc = 1;
    }

cleanup:
    nodus_t2_msg_free(&last_response);
    nodus_tcp_close(&transport);
    nodus_identity_clear(&identity);
    return rc;
}
