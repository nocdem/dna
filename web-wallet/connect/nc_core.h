/**
 * @file web-wallet/connect/nc_core.h
 * @brief Nodus Connect thin core — the read/write orchestration (R0-R5) of
 *        docs/plans/2026-09-24-web-connect-design.md rev 5 §1.4, package NC-2.
 *
 * Governing records (docs/plans/decisions/):
 *   2026-09-30-nodus-connect-thin-core.md — one single-threaded core shared
 *     with the wallet; only crypto / codecs / derivations come from the
 *     desktop code, the "which record, when" logic is rewritten here; every
 *     read has THREE outcomes and "could not read" never leads to a write
 *     (S3, S5); profile first publish AND every update EXCLUSIVE, a -2
 *     (NODUS_ERR_KEY_OWNED) = "profile address taken", never retried as an
 *     overwrite; Q1: only words generated in this session may CREATE a
 *     record; Q2 = a: the codecs are compiled verbatim from messenger/codec/.
 *   2026-09-25-web-wallet-nodus-send-transport.md — C->WASM, one thread,
 *     Asyncify, pinned server keys, ML-KEM only when pinned, one op queue.
 *
 * THIS IS A LIBRARY. It owns no session and no global state: every call
 * takes an nc_ctx_t the caller fills (the tier-2 client, the identity keys,
 * the cancel flag). web-wallet/connect/nc_wasm.c is the standalone module
 * entry that owns one; linking this library into the wallet's shared module
 * (one session per identity, design §1.1) is package NC-4.
 *
 * WHAT IS COMPILED VERBATIM (no copy of any wire format lives here):
 *   messenger/codec/ (all units) contact request codec + verify, offline
 *                                blob, outbox key, ACK key, 2-recipient Seal,
 *                                KEM-wrap, salt-packet parse helpers
 *   messenger/dna_api.c          Seal decode, authorship check
 *   messenger/dht/client/dna_profile.c  Anchor (profile) JSON codec
 *   nodus value / client / tier-2, shared/crypto
 * Byte layouts reproduced here, each with its citation and the reason no
 * callable function exists: the ACK value (8-byte BE unix time,
 * messenger/dht/shared/dht_offline_queue.c dht_publish_ack) and the contact
 * request signing preimage (taken as a prefix of the codec's own
 * serialisation and proven per call by the codec's verify — nc_requests.c).
 *
 * NOT HERE (blocked, see the NC-2 report): the contact list (R4) — its CLST
 * blob build and parse are inline in dht_contactlist.c, not extracted by
 * NC-1; the salt-agreement PUBLISH (R3) — its packet build is inline in
 * dht_salt_agreement.c. Neither is re-derived by hand (design §1.3).
 */

#ifndef NC_CORE_H
#define NC_CORE_H

#include "nodus/nodus.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/enc/qgp_mlkem.h"
#include "dht/client/dna_profile.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_FP_HEX_LEN     128
#define NC_SALT_LEN       32
#define NC_KYBER_PK_LEN   1568
#define NC_KYBER_SK_LEN   3168

/* The literal the frozen app sends as the message of a reciprocal request
 * and auto-approves on (messenger/src/api/engine/dna_engine_contacts.c
 * CONTACT_ACCEPTED_MSG, :27; approve path :690-751, the send :743-751;
 * auto-approve :555-581). */
#define NC_CONTACT_ACCEPTED_MSG "Contact request accepted"

/* ── Identity (design §1.5) ─────────────────────────────────────────── */

typedef struct {
    nodus_identity_t id;                          /* ML-DSA-87 = messaging
                                                   * identity = session key */
    char     fp[NC_FP_HEX_LEN + 1];               /* SHA3-512(pk), hex     */
    uint8_t  kyber_pk[NC_KYBER_PK_LEN];           /* round-3 Kyber1024     */
    uint8_t  kyber_sk[NC_KYBER_SK_LEN];
    uint8_t  mlkem_pk[QGP_MLKEM1024_PUBLICKEYBYTES];
    uint8_t  mlkem_sk[QGP_MLKEM1024_SECRETKEYBYTES];
} nc_keys_t;

/**
 * 24 (or 12..24) BIP39 words -> every key the frozen app derives, byte for
 * byte: qgp_derive_seeds_with_master(words, "") (passphrase "" as
 * messenger/messenger/init.c:122 and cli_commands.c:382), then
 * nodus_identity_from_seed(signing seed) (init.c:120-134 ->
 * nodus_identity.c:195), kyber_r3_keypair_derand(encryption seed)
 * (keygen.c:217), qgp_derive_mlkem1024_coins(master) +
 * qgp_mlkem1024_keypair_derand (keygen.c:288-289). Every intermediate seed
 * is wiped. 0 / -1.
 */
int  nc_keys_from_words(const char *words, nc_keys_t *out);
void nc_keys_wipe(nc_keys_t *k);

/* ── Context ───────────────────────────────────────────────────────── */

typedef struct {
    nodus_client_t     *client;     /* READY tier-2 session (caller owns)   */
    const nc_keys_t    *keys;
    /* Q1 (thin-core decision, "peki kaydet"): true ONLY for words this
     * session generated. A restored identity never creates a record. */
    bool                fresh;
    /* Checked before every network call; set by the caller's cancel/lock
     * (a synchronous export). A set flag makes the call return NC_ERR_CANCELLED
     * without touching the network. */
    volatile const int *cancel;
} nc_ctx_t;

/* Library return codes (negative) — distinct from the node's NODUS_ERR_*. */
#define NC_OK              0
#define NC_ERR_ARG        -1   /* bad input                                  */
#define NC_ERR_CANCELLED  -2   /* the cancel flag was set                    */
#define NC_ERR_INTERNAL   -3   /* allocation / crypto primitive failure       */

/* ── R0: the read primitive (design §1.4 R0, §2.1, §6.4 F1/F5) ──────── */

typedef enum {
    NC_FOUND      = 0,   /* a value that verified (and has the expected owner) */
    NC_EMPTY      = 1,   /* the node answered with no value — NOT proof of
                          * absence (design §2.1)                              */
    NC_UNREADABLE = 2    /* anything else: never leads to a write              */
} nc_outcome_t;

typedef enum {
    NC_WHY_NONE = 0,
    NC_WHY_CANCELLED,     /* the cancel flag was set before the request       */
    NC_WHY_NOT_CONNECTED, /* the client is not READY (-1 before any request)  */
    NC_WHY_TIMEOUT,       /* NODUS_ERR_TIMEOUT                                 */
    NC_WHY_NODE_ERROR,    /* an error reply (node_rc holds the code)           */
    NC_WHY_UNDECODABLE,   /* the node sent a value that did not decode (F1)    */
    NC_WHY_BAD_SIGNATURE, /* nodus_value_verify failed                         */
    NC_WHY_WRONG_KEY,     /* the value is signed for a different DHT key       */
    NC_WHY_WRONG_OWNER,   /* the value's owner is not the expected writer      */
    NC_WHY_BAD_RECORD     /* the value verified but its content did not
                           * (record decode / record signature / binding)     */
} nc_why_t;

const char *nc_why_str(nc_why_t why);
const char *nc_outcome_str(nc_outcome_t o);

typedef struct {
    nc_outcome_t   outcome;
    nc_why_t       why;
    int            node_rc;     /* the client's return code, kept for logs   */
    nodus_value_t *value;       /* FOUND only; freed by nc_read_clear        */
} nc_read_t;

void nc_read_clear(nc_read_t *r);

/**
 * Classify one GET answer. PURE: a function of (rc, value, key, owner) only —
 * no clock, no I/O (design §4 D4). Takes ownership of `value` (kept in
 * out->value on FOUND, freed otherwise). `expect_owner` NULL = any owner.
 *   rc 0 + value verifies + key_hash == key + owner ok   -> FOUND
 *   rc NODUS_ERR_NOT_FOUND                                -> EMPTY
 *   everything else                                       -> UNREADABLE(why)
 */
void nc_classify_one(int rc, nodus_value_t *value, const nodus_key_t *key,
                     const nodus_key_t *expect_owner, nc_read_t *out);

/** One strict GET (nodus_client_get_strict) + nc_classify_one. */
void nc_read_one(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *expect_owner, nc_read_t *out);

typedef struct {
    nc_outcome_t    outcome;     /* FOUND: >= 1 accepted value; EMPTY: the
                                  * node sent no item at all; UNREADABLE:
                                  * an error, or items but none accepted     */
    nc_why_t        why;         /* UNREADABLE only                          */
    int             node_rc;
    /* A get_all answer is NEVER complete (design §6.4 F5): a value missing
     * from `values` may exist. Always true when outcome == NC_FOUND.        */
    bool            partial;
    nodus_value_t **values;      /* accepted values, in reply order          */
    size_t          count;
    size_t          undecodable; /* items that did not decode (F1)           */
    size_t          bad_sig;     /* dropped: nodus_value_verify failed        */
    size_t          wrong_key;   /* dropped: signed for another key           */
    size_t          wrong_owner; /* dropped: owner not in the allowed list    */
} nc_read_all_t;

void nc_read_all_clear(nc_read_all_t *r);

/** Classify one GET_ALL answer. PURE, takes ownership of `vals`. `owners` /
 *  `n_owners` = the allowed writers (0 = any). */
void nc_classify_all(int rc, nodus_value_t **vals, size_t count,
                     size_t undecodable, const nodus_key_t *key,
                     const nodus_key_t *owners, size_t n_owners,
                     nc_read_all_t *out);

void nc_read_all(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *owners, size_t n_owners,
                 nc_read_all_t *out);

/**
 * One signed PUT under the own identity (the nodus_ops.c do_put shape,
 * :75-112): nodus_value_create + nodus_value_sign + nodus_client_put_ex,
 * seq = unix seconds (nodus_ops.c:93). The seq exists only because the
 * frozen app writes the same slots with the same rule; nothing in this core
 * assumes a node keeps the higher seq (design §6.4 F4: the entry node stores
 * a client PUT with INSERT OR REPLACE). Returns 0, the node's NODUS_ERR_*,
 * -1 (not connected / encode) or NC_ERR_CANCELLED / NC_ERR_INTERNAL.
 */
int nc_put(const nc_ctx_t *ctx, const nodus_key_t *key,
           const uint8_t *data, size_t data_len,
           nodus_value_type_t type, uint32_t ttl, uint64_t value_id);

/* ── DHT key derivations (design §1.4 R7) ──────────────────────────── */

/** SHA3-512 of a key STRING — what nodus_ops_*_str do (nodus_ops.c:69-71). */
void nc_key_str(const char *s, nodus_key_t *out);
/** SHA3-512 of raw key BYTES — what nodus_ops_put/get do (nodus_ops.c:64-66).
 *  Used on the already-hashed request-inbox and ACK keys (double hash). */
void nc_key_bytes(const uint8_t *b, size_t n, nodus_key_t *out);

/** 128 lowercase hex -> nodus_key_t. 0 / -1. */
int nc_fp_parse(const char *hex, nodus_key_t *out);

/* ── Peer keys (from a verified profile) ───────────────────────────── */

typedef struct {
    char    fp[NC_FP_HEX_LEN + 1];
    uint8_t dsa_pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t kyber_pk[NC_KYBER_PK_LEN];
    uint8_t mlkem_pk[QGP_MLKEM1024_PUBLICKEYBYTES];
    bool    has_mlkem;
} nc_peer_t;

/* ── R1: profile (Anchor record "<fp>:profile") ────────────────────── */

/**
 * Read and verify a profile: R0 with owner = fp, then the frozen app's
 * record checks (keyserver_lookup.c:95-150): dna_identity_from_json,
 * ML-DSA-87 signature over dna_identity_to_json_unsigned, and
 * SHA3-512(dilithium_pubkey) == fp. A value that passes R0 but fails a
 * record check is UNREADABLE(BAD_RECORD). On FOUND *identity_out is the
 * decoded record (dna_identity_free), and `peer_out` (nullable) is filled.
 */
void nc_profile_read(const nc_ctx_t *ctx, const char *fp, nc_read_t *raw,
                     dna_unified_identity_t **identity_out,
                     nc_peer_t *peer_out);

typedef enum {
    NC_PROFILE_PUBLISHED = 0,  /* PUT accepted                                */
    NC_PROFILE_WAIT      = 1,  /* read EMPTY for a restored identity, or
                                * UNREADABLE: nothing written, retry later    */
    NC_PROFILE_TAKEN     = 2,  /* NODUS_ERR_KEY_OWNED: the key is owned by
                                * someone else; terminal, never retried      */
    NC_PROFILE_FAILED    = 3,  /* the PUT itself failed (node error, timeout)
                                * — the next attempt re-reads first          */
    NC_PROFILE_BAD_PATCH = 4   /* the edit was refused before any I/O         */
} nc_profile_status_t;

typedef struct {
    nc_profile_status_t status;
    nc_read_t           read;         /* the read that decided (value freed) */
    int                 put_rc;       /* the PUT's return code, if any       */
    bool                created;      /* first publish (Q1 path)             */
    uint32_t            version;      /* record version written              */
} nc_profile_result_t;

/**
 * Update (or, under Q1, create) the own profile.
 * `patch_json`: a JSON object with any of: "bio", "location", "website",
 * "avatar_base64", "wallets": {backbone, eth, sol, trx, bsc},
 * "socials": {telegram, x, github, facebook, instagram, linkedin, google}.
 * Only the keys present change; every other field of the record read in the
 * SAME call (never a cached copy) is kept, including registered_name,
 * name_* fields, wallets.alvin and display_name (design §1.4 R1: the native
 * update wipes alvin, messenger/BUGS.md:36 — not carried).
 *   FOUND -> copy, apply patch, attach own mlkem_pubkey (outside the signed
 *            part, keyserver_profiles.c:121-124), timestamp, version++, sign
 *            dna_identity_to_json_unsigned, PUT dna_identity_to_json
 *            EXCLUSIVE, ttl 0, value_id = nodus_identity_value_id
 *            (operator decision 2026-09-30 "bu şekilde yapalım").
 *   EMPTY and ctx->fresh -> the first-time record of keyserver_profiles.c
 *            :43-75 without a name, then as above (created = true).
 *   EMPTY and !fresh, or UNREADABLE -> NC_PROFILE_WAIT, nothing written.
 *   PUT -> NODUS_ERR_KEY_OWNED -> NC_PROFILE_TAKEN.
 */
int nc_profile_publish(const nc_ctx_t *ctx, const char *patch_json,
                       nc_profile_result_t *res);

/* ── R2: contact requests ("<fp>:requests") ────────────────────────── */

/**
 * Build one signed contact request for `recipient_fp` exactly as
 * dht_send_contact_request (dht_contact_request.c:43-229) does: magic DNAR,
 * v2 when `salt` != NULL (v1 otherwise), timestamp = now, expiry = now +
 * DHT_CONTACT_REQUEST_DEFAULT_TTL, sender_name empty (the web registers no
 * name), message (<= 255 bytes, NULL = empty), ML-DSA-87 over the signing
 * preimage. The serialised bytes are checked with the codec's own
 * dht_deserialize_contact_request + dht_verify_contact_request (what the
 * frozen app runs on receipt, dht_contact_request.c:298-308) before they are
 * returned; a request that would not verify is never returned.
 */
int nc_request_build(const nc_keys_t *keys, const char *recipient_fp,
                     const char *message, const uint8_t *salt,
                     uint8_t **out, size_t *out_len);

/** Build + PUT to SHA3-512(SHA3-512("<recipient>:requests")), EPHEMERAL,
 *  ttl 604800, value_id = dht_fingerprint_to_value_id(own fp)
 *  (dht_contact_request.c:203-218; nodus_ops_put double hash). */
int nc_request_send(const nc_ctx_t *ctx, const char *recipient_fp,
                    const char *message, const uint8_t *salt);

/** ACCEPT (design §6.4 F3): the reciprocal request the frozen app sends on
 *  approve — message NC_CONTACT_ACCEPTED_MSG, the requester's salt echoed
 *  (NULL when the request carried none -> v1), dna_engine_contacts.c
 *  :690-751. */
int nc_request_accept(const nc_ctx_t *ctx, const char *requester_fp,
                      const uint8_t *salt_or_null);

/** CANCEL own request in `recipient_fp`'s inbox: 1 byte {0}, ttl 1,
 *  EPHEMERAL, same key and value_id (dht_cancel_contact_request,
 *  dht_contact_request.c:354-393; the app calls it after an auto-approve,
 *  dna_engine_contacts.c:580). */
int nc_request_cancel(const nc_ctx_t *ctx, const char *recipient_fp);

typedef struct {
    char     sender_fp[NC_FP_HEX_LEN + 1];
    char     sender_name[64];   /* SELF-ASSERTED: never shown as a name (G9) */
    char     message[256];
    uint64_t timestamp;
    uint64_t expiry;
    bool     has_salt;
    uint8_t  salt[NC_SALT_LEN];
    bool     is_acceptance;     /* message == NC_CONTACT_ACCEPTED_MSG. An
                                 * acceptance may be auto-approved ONLY when
                                 * this identity has a pending outgoing
                                 * request to sender_fp (HIGH-7 rule,
                                 * dna_engine_contacts.c:555-562) — the
                                 * caller holds that state.                   */
} nc_request_t;

typedef struct {
    nc_read_all_t  read;         /* values freed; counters kept             */
    nc_request_t  *items;
    size_t         count;
    size_t         bad_request;  /* dropped: codec decode / verify / expiry,
                                  * or the DHT owner is not the sender      */
    size_t         cancelled;    /* 1-byte cancel markers skipped           */
} nc_requests_t;

void nc_requests_clear(nc_requests_t *r);
/** get_all of the own inbox; PARTIAL by nature (F5). */
int  nc_requests_fetch(const nc_ctx_t *ctx, nc_requests_t *out);

/* ── R3: per-contact salt agreement (read + reconcile only) ────────── */

typedef struct {
    nc_read_all_t read;          /* counters; values freed                  */
    bool          found;         /* >= 1 authenticated, decryptable salt    */
    uint8_t       salt[NC_SALT_LEN];
    size_t        authenticated; /* packets whose signature verified        */
} nc_salt_read_t;

/**
 * get_all on SHA3-512(salt_agreement_make_key(me, peer)) (string hashed —
 * nodus_ops_get_all_str), DHT signature + owner in {me, peer}, then the
 * native parse and choice (dht_salt_agreement.c salt_agreement_fetch_internal
 * :217-349): version peek -> salt_agreement_packet_data_size_for_version,
 * salt_agreement_packet_verify_signature (either party), packet_decrypt_salt,
 * at most 16 salts, identical salts collapse, else the lowest SHA3-512 wins.
 * `found` false is NOT "no agreement exists" (F5) — no publish follows.
 */
int nc_salt_read(const nc_ctx_t *ctx, const nc_peer_t *peer,
                 nc_salt_read_t *out);
void nc_salt_read_clear(nc_salt_read_t *r);

typedef enum {
    NC_SALT_KEEP_LOCAL   = 0,   /* local only, or local == DHT, or local won */
    NC_SALT_TAKE_DHT     = 1,   /* no local, or the DHT salt won            */
    NC_SALT_NONE         = 2    /* neither                                  */
} nc_salt_choice_t;

/** The native reconcile rule (salt_agreement_verify :380-468) without its
 *  publishes: both present and different -> the salt whose SHA3-512 is
 *  lower wins, local on a tie. PURE. `republish_wanted` is set where the
 *  native path would publish (the web cannot: packet build not extracted). */
nc_salt_choice_t nc_salt_choose(const uint8_t *local_or_null,
                                const uint8_t *dht_or_null,
                                uint8_t chosen[NC_SALT_LEN],
                                bool *republish_wanted);

/* ── R5: 1:1 outbox (daily bucket) and ACK ─────────────────────────── */

typedef struct {
    uint64_t    seq;          /* the web's local id (design §1.4 R5)       */
    uint64_t    timestamp;    /* ORIGINAL send time, unix seconds          */
    const char *text;         /* UTF-8 plaintext (NUL-terminated)          */
} nc_outmsg_t;

#define NC_OUTBOX_MAX_MESSAGES 1000   /* the codec's reader cap,
                                       * offline_queue_codec.c:24,:225     */

/**
 * The whole day blob for one recipient, as messenger_flush_recipient_outbox
 * (messages.c:334-570) builds it: each message re-sealed with the
 * 2-recipient Seal (sender entry first, recipient second) and its original
 * timestamp; algorithm all-or-nothing — ML-KEM-1024 only when BOTH this
 * identity and the peer's record carry an ML-KEM key, else round-3 Kyber
 * (:411-446); seq = local id, expiry = timestamp + DNA_DM_OUTBOX_TTL;
 * dht_serialize_messages. `alg_out` (nullable) = 2 or 3.
 */
int nc_outbox_build(const nc_keys_t *keys, const nc_peer_t *peer,
                    const nc_outmsg_t *msgs, size_t n,
                    uint8_t **blob, size_t *blob_len, uint8_t *alg_out);

/** Build + PUT under SHA3-512(dht_dm_outbox_make_key(me, peer, day, salt))
 *  EPHEMERAL, ttl DNA_DM_OUTBOX_TTL, own value_id (messages.c:540-544).
 *  `day` = dht_dm_outbox_get_day_bucket() at the caller. */
int nc_outbox_publish(const nc_ctx_t *ctx, const nc_peer_t *peer,
                      const uint8_t salt[NC_SALT_LEN], uint64_t day,
                      const nc_outmsg_t *msgs, size_t n, uint8_t *alg_out);

typedef struct {
    uint64_t seq;
    uint64_t sender_timestamp;  /* the Seal's timestamp = sender's clock   */
    uint8_t *plaintext;         /* not NUL-terminated                       */
    size_t   plaintext_len;
} nc_inmsg_t;

typedef struct {
    nc_read_t   read;           /* value freed                              */
    nc_inmsg_t *items;
    size_t      count;
    size_t      dropped;        /* not decryptable / not authored by peer   */
} nc_inbox_t;

void nc_inbox_clear(nc_inbox_t *in);

/**
 * ONE day bucket of `peer`'s outbox to this identity (dht_dm_outbox_sync_day
 * :414-474 without the blob cache): strict GET, owner = peer, codec
 * deserialize, then per message dna_decrypt_message_raw_alg (own round-3 +
 * ML-KEM secret) and the authorship gate of messenger_transport.c:645-716:
 * the Seal's claimed sender must be the peer and dna_verify_seal_authorship
 * must pass under the peer's verified ML-DSA key; anything else is dropped.
 */
int nc_outbox_fetch_day(const nc_ctx_t *ctx, const nc_peer_t *peer,
                        const uint8_t salt[NC_SALT_LEN], uint64_t day,
                        nc_inbox_t *out);

/** ACK that this identity has STORED `peer`'s messages (G11: the caller
 *  calls this only after its store transaction completed). Key =
 *  SHA3-512(dht_generate_ack_key(me, peer, salt)), value = unix time 8 bytes
 *  BE, EPHEMERAL, ttl DHT_ACK_TTL, value_id 1 (dht_offline_queue.c
 *  dht_publish_ack :129-173 — value layout reproduced, not extracted). */
int nc_ack_publish(const nc_ctx_t *ctx, const char *peer_fp,
                   const uint8_t salt[NC_SALT_LEN]);

/** Read `peer`'s ACK for messages this identity sent (owner = peer, value
 *  exactly 8 bytes, dht_offline_queue.c ack_listen_callback :195-247). On
 *  FOUND *ack_ts is the peer's unix time: messages with timestamp <= it
 *  were delivered. */
void nc_ack_read(const nc_ctx_t *ctx, const char *peer_fp,
                 const uint8_t salt[NC_SALT_LEN], nc_read_t *raw,
                 uint64_t *ack_ts);

/* ── Embedded server list (design §1.6 S9) ─────────────────────────── */

#define NC_SERVERS_FORMAT   "nodus-connect-servers"
#define NC_SERVERS_VERSION  1
#define NC_KIND_VALIDATOR   "validator-checkpoint"
#define NC_MAX_PINS         64

typedef struct {
    nodus_server_endpoint_t endpoints[NODUS_CLIENT_MAX_SERVERS];
    int                     n_endpoints;
    nodus_key_t             pins[NC_MAX_PINS];
    int                     n_pins;
    int                     skipped_kinds;   /* entries of a kind this build
                                              * does not know (not used)    */
} nc_servers_t;

/**
 * Parse the embedded list:
 *   {"format":"nodus-connect-servers","version":1,
 *    "entries":[{"kind":"validator-checkpoint","pin":"<128 hex>",
 *                "host":"<IPv4>","port":443}, ...]}
 * Every entry has a "kind". Today only "validator-checkpoint" is read: its
 * "pin" is required (SHA3-512 of the node's ML-DSA-87 key); "host"/"port"
 * are optional (a pinned validator without a WebSocket entry). An entry of
 * another kind is skipped and counted — a later build adds the second kind
 * (design §8 NC-F2) without changing how validator entries are read.
 * Endpoints keep list order (design §4 D8). Refused: another format or
 * version, a malformed validator entry, a duplicate pin, more than
 * NODUS_CLIENT_MAX_SERVERS endpoints or NC_MAX_PINS pins, and a list with
 * no endpoint or no pin (an empty list connects nowhere). 0 / -1 (+ why).
 */
int nc_servers_parse(const char *json, nc_servers_t *out,
                     char *why, size_t why_len);

#ifdef __cplusplus
}
#endif

#endif /* NC_CORE_H */
