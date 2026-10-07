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
 * the cancel flag). web-wallet/connect/nc_wasm.c is the browser entry; it is
 * linked into the wallet's shared module and takes that module's session
 * (one session per identity, design §1.1; package NC-4b — see "Host" at the
 * end of this header).
 *
 * WHAT IS COMPILED VERBATIM (no copy of any wire format lives here):
 *   messenger/codec/ (all units) contact request codec + verify + signing
 *                                preimage, offline blob, outbox key, ACK key
 *                                + ACK value, 2-recipient Seal, KEM-wrap,
 *                                salt-packet build + parse helpers,
 *                                contact-list JSON + CLST blob
 *   messenger/dna_api.c          Seal encode/decode, authorship check
 *   messenger/dht/client/dna_profile.c  Anchor (profile) JSON codec
 *   nodus value / client / tier-2, shared/crypto
 * No byte layout is reproduced here: the four sequences NC-1 left inline in
 * the app's I/O functions (ACK value, contact-request signing preimage,
 * salt packet build, CLST blob build/parse) were moved into
 * messenger/codec/ by NC-1b, and the app calls the same functions.
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
     * without touching the network. The browser entry points it at the
     * wallet's cancel flag while Messages is open and, from nc_lock on, at a
     * flag that is always set (nc_wasm.c nc_lock): either stop reaches a
     * suspended gated write before its PUT. */
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
    NC_WHY_BAD_RECORD,    /* the value verified but its content did not
                           * (record decode / record signature / binding)     */
    NC_WHY_TOO_LARGE      /* an owner-filtered read still had pages left
                           * after NC_READ_MAX_PAGES: the owner's newest row
                           * may be among the unread ones (nc_read_all)       */
} nc_why_t;

const char *nc_why_str(nc_why_t why);
const char *nc_outcome_str(nc_outcome_t o);

typedef struct {
    nc_outcome_t   outcome;
    nc_why_t       why;
    int            node_rc;     /* the client's return code, kept for logs   */
    nodus_value_t *value;       /* FOUND only; freed by nc_read_clear        */
    size_t         foreign;     /* owner-filtered reads (nc_read_one with an
                                 * owner, nc_profile_read): verified values
                                 * of ANOTHER owner the node sent for the
                                 * key — never used, reported so the UI can
                                 * say someone is interfering. A node that
                                 * applies the owner filter sends none.
                                 * 0 for a read without an owner.            */
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

/**
 * One value at `key`.
 *   expect_owner NULL: one strict GET (nodus_client_get_strict) +
 *     nc_classify_one.
 *   expect_owner set: the owner-filtered paged read nc_read_all(key,
 *     [expect_owner]) and ONE row of it, picked with nc_row_before. A
 *     single GET is not used: the node's single GET returns the highest-seq
 *     row of ANY owner unless an EXCLUSIVE row exists (nodus_storage.c
 *     GET_SQL :43-46), so a stranger's newer row would shadow the owner's.
 *       >= 1 verified row of the owner, and no item that was undecodable /
 *         failed its signature / was signed for another key -> FOUND;
 *       an owner row plus such an item -> UNREADABLE with that why (the
 *         item may be the owner's newest row: fail closed);
 *       only rows of other owners -> UNREADABLE(WRONG_OWNER);
 *       no item at all -> EMPTY; error / too large -> UNREADABLE.
 *     out->foreign = rows of other owners the node sent, on every outcome.
 */
void nc_read_one(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *expect_owner, nc_read_t *out);

/** a before b in the node's single-GET order (nodus_storage.c GET_SQL
 *  :43-46: EXCLUSIVE first, then highest seq), plus a total tie-break on
 *  the lowest value_id so the choice never depends on reply order. Every
 *  field used is covered by the value signature. */
bool nc_row_before(const nodus_value_t *a, const nodus_value_t *b);

/* Pages one nc_read_all loop reads at most (per owner). One page is at most
 * NODUS_GET_ALL_PAGE_MAX_BYTES (2 MiB) of rows; 8 pages cover the 16 MiB a
 * single owner may store (NODUS_STORAGE_OWNER_MAX_BYTES). */
#define NC_READ_MAX_PAGES 8

typedef struct {
    nc_outcome_t    outcome;     /* FOUND: >= 1 accepted value; EMPTY: the
                                  * node sent no item at all; UNREADABLE:
                                  * an error, or items but none accepted     */
    nc_why_t        why;         /* UNREADABLE only                          */
    int             node_rc;
    /* A get_all answer is NEVER complete (design §6.4 F5): a value missing
     * from `values` may exist. Always true when outcome == NC_FOUND.        */
    bool            partial;
    /* Owner-less read only: the node still had pages after
     * NC_READ_MAX_PAGES; `values` holds what was read. (An owner-filtered
     * read in that state is UNREADABLE(TOO_LARGE) instead.) Kept by
     * nc_read_all_clear, like the counters.                                 */
    bool            truncated;
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

/**
 * Paged, owner-filtered GET_ALL (nodus_client_get_all_page_strict, DHT
 * Package A) + nc_classify_all.
 *   n_owners == 0: one paging loop over every owner;
 *   n_owners  > 0: one paging loop PER owner, with that owner's filter.
 * Each loop reads while the node says "more", at most NC_READ_MAX_PAGES
 * pages; the rows of every loop are concatenated (reply order) and the
 * undecodable counts summed, then classified exactly as one get_all answer
 * (rows of another key / owner and bad signatures are COUNTED, never
 * silently dropped — a node may ignore the filter). The cancel flag is
 * checked before every page.
 *   any page error -> UNREADABLE (why from the rc; NODUS_ERR_UNAVAILABLE =
 *     NODE_ERROR; an error is never EMPTY);
 *   a legacy reply (a node that predates paging: no "more") with no row ->
 *     UNREADABLE(NODE_ERROR), never EMPTY (node_rc NODUS_ERR_UNAVAILABLE);
 *   pages left after NC_READ_MAX_PAGES: owner-filtered ->
 *     UNREADABLE(TOO_LARGE); owner-less -> what was read, truncated = true
 *     (UNREADABLE(TOO_LARGE) when not one item was read — rows remain, so
 *     the answer is not EMPTY).
 */
void nc_read_all(const nc_ctx_t *ctx, const nodus_key_t *key,
                 const nodus_key_t *owners, size_t n_owners,
                 nc_read_all_t *out);

/* Keys one nc_read_owner_many call reads at most, and how many of their
 * first pages are in flight at once. The node's forwarded-lookup slots
 * (NODUS_BF_MAX_BATCHES, 16) are shared by every user of that node: one
 * reader takes at most 4 of them. */
#define NC_READ_MANY_MAX  8
#define NC_READ_PIPELINE  4

/**
 * nc_read_one(ctx, &keys[i], &owners[i], &outs[i]) for i < n (n <=
 * NC_READ_MANY_MAX), every key with its own owner — the SAME read per key
 * (the owner-filtered paged nc_read_all and one row of it, every rule of
 * nc_read_one above, fail closed), with the first pages PIPELINED: in waves
 * of NC_READ_PIPELINE keys, the first page request of every key of the
 * wave is sent before the first reply is awaited
 * (nodus_client_get_all_page_strict_many: one strict request per key,
 * never a batch request). A key whose answer has more pages continues
 * with its own sequential page requests, up to NC_READ_MAX_PAGES. The
 * cancel flag is checked before every wave and before every later page;
 * a key whose read ends cancelled is UNREADABLE(CANCELLED) as in
 * nc_read_one. outs[i] is exactly what nc_read_one would return for that
 * key; free each with nc_read_clear.
 * @return NC_OK, or NC_ERR_ARG (NULL arrays, n == 0, n > NC_READ_MANY_MAX)
 *         with nothing read.
 */
int nc_read_owner_many(const nc_ctx_t *ctx, const nodus_key_t *keys,
                       const nodus_key_t *owners, size_t n, nc_read_t *outs);

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
 * Read and verify a profile (own AND peer): R0 as a GET_ALL filtered to
 * owner = fp (nc_read_one with expect_owner = fp, i.e. the paged
 * nc_read_all with owners = [fp]) — NOT a single GET. The node's
 * single GET returns the highest-seq row of ANY owner unless an EXCLUSIVE
 * row exists (nodus_storage.c GET_SQL :43-46), so a stranger's newer
 * PERMANENT row at "<fp>:profile" would shadow the owner's record; get-all
 * returns every owner's row (atlas-dec-f6c5aca3: multi-writer locations are
 * read with get-all).
 *   >= 1 verified row of the owner, and no item that was undecodable /
 *     failed its signature / was signed for another key -> the owner's row
 *     chosen as the node's single GET orders (EXCLUSIVE first, then highest
 *     seq; tie: lowest value_id) -> the record checks below -> FOUND;
 *   an owner row plus an undecodable / bad-signature / wrong-key item ->
 *     UNREADABLE with that why (such an item cannot come from honest
 *     storage, its owner cannot be attributed, and it may be the owner's
 *     newest row — an older base would roll the version back);
 *   only rows of other owners -> UNREADABLE(WRONG_OWNER), as R0 maps a
 *     value of another writer (design rev 5 §1.4 R0);
 *   no item at all -> EMPTY; error -> UNREADABLE.
 * raw->foreign = verified rows of other owners, on every outcome.
 * Record checks (keyserver_lookup.c:95-150): dna_identity_from_json,
 * ML-DSA-87 signature over dna_identity_to_json_unsigned, and
 * SHA3-512(dilithium_pubkey) == fp. A value that passes R0 but fails a
 * record check is UNREADABLE(BAD_RECORD). On FOUND *identity_out is the
 * decoded record (dna_identity_free), and `peer_out` (nullable) is filled.
 */
void nc_profile_read(const nc_ctx_t *ctx, const char *fp, nc_read_t *raw,
                     dna_unified_identity_t **identity_out,
                     nc_peer_t *peer_out);

/**
 * The record checks of nc_profile_read alone, on bytes already in hand
 * (the value of a profile row, e.g. one the page kept from an earlier
 * FOUND read — the app's profile cache, profile_cache.h:40): decode,
 * ML-DSA-87 signature, SHA3-512(dilithium_pubkey) == fp. 0 = passed
 * (*identity_out set when non-NULL, `peer_out` filled when non-NULL),
 * -1 = refused (nothing set). No network.
 */
int nc_profile_check(const char *fp, const uint8_t *data, size_t len,
                     dna_unified_identity_t **identity_out,
                     nc_peer_t *peer_out);

/**
 * The app's registered-name check (dht_keyserver_reverse_lookup,
 * messenger/dht/keyserver/keyserver_lookup.c:186-283), owner-filtered:
 * `name` (the profile's registered_name) is VERIFIED only when the
 * "<name>:lookup" record written BY `fp` itself — or, if the name has upper
 * case, the "<lowercased name>:lookup" record (keyserver_names.c:121-126
 * writes that form; keyserver_publish.c:65 the name as given) — holds `fp`
 * in its first 128 bytes. Names the app's validator refuses
 * (dht_keyserver_is_valid_registered_name, keyserver_lookup.c:161-182) are
 * never verified. Design §1.9 G9: only a verified name is shown as a name.
 * Returns 1 verified, 0 not verified, -1 could not read (show the ID).
 */
int nc_name_verify(const nc_ctx_t *ctx, const char *fp, const char *name);

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

/* ── R3: per-contact salt agreement (read, reconcile, gated publish) ── */

typedef struct {
    nc_read_all_t read;          /* counters; values freed                  */
    bool          found;         /* >= 1 authenticated, decryptable salt    */
    uint8_t       salt[NC_SALT_LEN];
    size_t        authenticated; /* packets whose signature verified AND whose
                                  * two entries are exactly {me, peer}      */
    size_t        wrong_pair;    /* dropped: signature verified, but the
                                  * packet names another pair (a packet
                                  * signed for (me, Y) replayed at the
                                  * (me, peer) key)                         */
} nc_salt_read_t;

typedef enum {
    NC_SALT_PKT_OK         = 0,  /* salt_out holds this party's salt        */
    NC_SALT_PKT_BAD_SIZE   = 1,  /* unknown version / shorter than it says  */
    NC_SALT_PKT_BAD_SIG    = 2,  /* signed by neither party                 */
    NC_SALT_PKT_WRONG_PAIR = 3,  /* entries are not exactly {me, peer}      */
    NC_SALT_PKT_NO_ENTRY   = 4   /* this party's entry did not unwrap       */
} nc_salt_pkt_t;

/**
 * One salt packet, checked in this order (PURE, no I/O): version peek ->
 * salt_agreement_packet_data_size_for_version; signature under either
 * party's ML-DSA-87 key (salt_agreement_packet_verify_signature); the two
 * entry fingerprints (salt_agreement_packet_entry_fps) equal {me, peer} as
 * a set — any order, the native reader never required one; then this
 * party's entry unwraps (salt_agreement_packet_decrypt_salt). The pair
 * check is the web's addition: the native reader accepts any packet signed
 * by either party whose own entry decrypts, so a peer could republish a
 * packet this identity signed for someone else and pin the salt of that
 * other conversation onto this one.
 */
nc_salt_pkt_t nc_salt_packet_check(const nc_keys_t *keys, const nc_peer_t *peer,
                                   const uint8_t *data, size_t data_len,
                                   uint8_t salt_out[NC_SALT_LEN]);

/**
 * get_all on SHA3-512(salt_agreement_make_key(me, peer)) (string hashed —
 * nodus_ops_get_all_str), DHT signature + owner in {me, peer}, then per
 * value nc_salt_packet_check and the native choice (dht_salt_agreement.c
 * salt_agreement_fetch_internal :217-349): at most 16 salts, identical salts
 * collapse, else the lowest SHA3-512 wins.
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

/** The native reconcile rule (salt_agreement_verify) without its
 *  publishes: both present and different -> the salt whose SHA3-512 is
 *  lower wins, local on a tie. PURE. `republish_wanted` is set where the
 *  native path would publish (mismatch, or local only); nc_salt_sync does
 *  the publish under the fail-closed rules. */
nc_salt_choice_t nc_salt_choose(const uint8_t *local_or_null,
                                const uint8_t *dht_or_null,
                                uint8_t chosen[NC_SALT_LEN],
                                bool *republish_wanted);

/**
 * The packet the app publishes for (this identity, peer, salt):
 * salt_agreement_build_packet, v1 (round-3 Kyber for both parties, NULL
 * ML-KEM keys as salt_agreement_publish passes), signed with this
 * identity's ML-DSA-87 key. Before it is returned the bytes are read back
 * with the codec's own parse: announced data size, signature under this
 * identity, this party's entry unwraps to `salt`. *out malloc'd.
 */
int nc_salt_build(const nc_keys_t *keys, const nc_peer_t *peer,
                  const uint8_t salt[NC_SALT_LEN],
                  uint8_t **out, size_t *out_len);

typedef enum {
    NC_SALT_SYNC_NOTHING_TO_WRITE = 0, /* read decided, no publish wanted     */
    NC_SALT_SYNC_PUBLISHED        = 1, /* the winner was published           */
    NC_SALT_SYNC_WAIT             = 2, /* UNREADABLE; FOUND without a usable
                                        * salt; or EMPTY for a restored
                                        * identity (Q1): nothing written      */
    NC_SALT_SYNC_FAILED           = 3  /* the PUT failed (put_rc)            */
} nc_salt_sync_status_t;

typedef struct {
    nc_salt_sync_status_t status;
    nc_salt_read_t        read;        /* the read that decided (values freed) */
    nc_salt_choice_t      choice;      /* NONE when status is WAIT            */
    uint8_t               chosen[NC_SALT_LEN]; /* the salt to keep locally    */
    int                   put_rc;
} nc_salt_sync_t;

void nc_salt_sync_clear(nc_salt_sync_t *s);

/**
 * R3 with its write: nc_salt_read in the same call, then
 *   UNREADABLE, or FOUND without a usable salt        -> WAIT, no write;
 *   nc_salt_choose(local, dht) wants no publish        -> NOTHING_TO_WRITE;
 *   publish wanted with a DHT salt (mismatch)          -> publish the winner;
 *   publish wanted, EMPTY (local only): ctx->fresh     -> publish local,
 *                                       restored       -> WAIT (Q1).
 * Publish = nc_salt_build + PUT EPHEMERAL, SALT_AGREEMENT_TTL, value_id =
 * nodus_identity_value_id (salt_agreement_publish_internal ->
 * nodus_ops_put_str, key string hashed once). `local_or_null` all-zero
 * counts as unset (salt_agreement_verify). The caller stores `chosen`
 * unless the status is WAIT. Read + write in one call (design §6.4 F4).
 */
int nc_salt_sync(const nc_ctx_t *ctx, const nc_peer_t *peer,
                 const uint8_t *local_or_null, nc_salt_sync_t *res);

/* ── R4: own contact list ("<fp>:contactlist") ─────────────────────── */

typedef struct {
    char    fp[NC_FP_HEX_LEN + 1];
    bool    has_salt;
    uint8_t salt[NC_SALT_LEN];
} nc_contact_t;

typedef struct {
    nc_read_t     read;        /* value freed                               */
    nc_contact_t *items;       /* FOUND only, in stored order               */
    size_t        count;
    size_t        invalid;     /* stored entries that are not a 128-char
                                * lowercase-hex fingerprint (not in items)  */
    uint64_t      timestamp;   /* the list's JSON timestamp                 */
} nc_contactlist_t;

void nc_contactlist_clear(nc_contactlist_t *l);

/**
 * Read the own list: R0 on SHA3-512("<fp>:contactlist") (string hashed
 * once, nodus_ops_get_str; dht_contactlist.c make_base_key) with owner =
 * own fp, then what dht_contactlist_fetch does: dht_contactlist_blob_parse,
 * dna_decrypt_message_raw with the own round-3 key, sender fingerprint 64
 * bytes + dna_verify_seal_authorship under the own ML-DSA key,
 * dht_contactlist_deserialize_from_json. A value that passes R0 but fails
 * any of these is UNREADABLE(BAD_RECORD).
 */
void nc_contactlist_read(const nc_ctx_t *ctx, nc_contactlist_t *out);

/**
 * The value the app publishes for `items` (dht_contactlist_publish):
 * dht_contactlist_serialize_to_json(own fp, ...), ML-DSA-87 over the JSON,
 * dna_encrypt_message_raw to the own round-3 key (self-seal, Seal
 * timestamp = `timestamp`), dht_contactlist_blob_encode with expiry =
 * timestamp + DHT_CONTACTLIST_DEFAULT_TTL (the app passes ttl 0). The bytes
 * are decoded back with the read path before they are returned. *out
 * malloc'd.
 */
int nc_contactlist_build(const nc_keys_t *keys, const nc_contact_t *items,
                         size_t count, uint64_t timestamp,
                         uint8_t **out, size_t *out_len);

typedef enum {
    NC_LIST_PUBLISHED = 0,  /* PUT accepted                                  */
    NC_LIST_UNCHANGED = 1,  /* FOUND list already holds every entry: no PUT  */
    NC_LIST_WAIT      = 2,  /* UNREADABLE, or EMPTY for a restored identity */
    NC_LIST_TAKEN     = 3,  /* NODUS_ERR_KEY_OWNED: the key is owned by
                             * someone else; terminal                       */
    NC_LIST_FAILED    = 4,  /* the PUT failed; the next attempt re-reads     */
    NC_LIST_REFUSED   = 5   /* bad input, or the stored list has entries this
                             * core would not carry over (invalid > 0):
                             * nothing written                              */
} nc_list_status_t;

typedef struct {
    nc_list_status_t status;
    nc_outcome_t     read_outcome;
    nc_why_t         read_why;
    int              put_rc;
    bool             created;         /* first list (Q1 path)               */
    size_t           count_before;    /* entries in the list read           */
    size_t           count_after;     /* entries written (>= count_before)  */
    size_t           salt_kept;       /* entries present on both sides with
                                       * different salts: the stored salt
                                       * was kept                           */
} nc_list_result_t;

/**
 * Add contacts to the own list — MERGE ONLY, never fewer entries (design
 * R4; messenger/BUGS.md:38). The list read in the SAME call is the base:
 *   FOUND   -> stored entries in stored order, then each new fingerprint
 *              appended in `add` order; for a fingerprint already stored,
 *              a missing salt is filled from `add`, a present salt is kept
 *              (a different one counts in salt_kept);
 *   EMPTY   -> ctx->fresh: `add` becomes the first list (created = true);
 *              restored identity: WAIT (Q1);
 *   UNREADABLE -> WAIT.
 * Nothing new -> UNCHANGED (no PUT). PUT EXCLUSIVE, ttl 0, value_id =
 * nodus_identity_value_id (dht_contactlist_publish ->
 * nodus_ops_put_str_exclusive). Every `add` fingerprint must be 128
 * lowercase hex, no duplicates within `add`; n_add >= 1.
 */
int nc_contactlist_add(const nc_ctx_t *ctx, const nc_contact_t *add,
                       size_t n_add, nc_list_result_t *res);

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
    nc_inmsg_t *items;          /* chat text only (nc_plaintext_is_chat)    */
    size_t      count;
    size_t      dropped;        /* not decryptable / not authored by peer   */
    size_t      other;          /* authentic, but not chat text: the app's
                                 * control payloads (reaction, call signal,
                                 * group invite, delete) and the payloads
                                 * its chat screen draws as cards; never
                                 * returned, never shown as text            */
    uint8_t     blob[32];       /* SHA3-256 of the bucket value (FOUND)     */
    bool        unchanged;      /* blob == skip_blob: nothing was decoded   */
} nc_inbox_t;

void nc_inbox_clear(nc_inbox_t *in);

/**
 * Whether a decrypted, authentic 1:1 plaintext is chat text — the classes
 * the app's receiver tells apart (messenger/messenger_transport.c):
 *   - default CHAT (:604);
 *   - reaction {"target":"<64 hex>",...,"op":"add|remove"} (:733-749, the
 *     substring sniff of messenger/src/reaction/reaction_json.c, mirrored
 *     here because that file is not in this build);
 *   - a JSON object whose "type" (json_object_get_string) is "call_signal"
 *     (:757-771), "group_invite" / "groupinvite" (:773-775) or "delete"
 *     (:808-903);
 *   - and, as the app's chat screen draws them as cards instead of text
 *     (dna_messenger_flutter/lib/screens/chat/chat_screen.dart:2012-2046:
 *     jsonDecode as a Map, "type" == a string), "token_transfer",
 *     "media_ref", "image_attachment".
 * Everything but the default is NOT chat. The text is read up to its first
 * NUL, as the app's NUL-terminated copy is (:727-732).
 * Returns 1 chat, 0 not chat, -1 could not classify (empty input or no
 * memory): the caller counts -1 as dropped, never as "other" — "other"
 * does not hold the ACK back, so an unclassified chat message would be
 * acknowledged without being shown (Connect RT2 L2 F3).
 */
int nc_plaintext_is_chat(const uint8_t *pt, size_t len);

/**
 * ONE day bucket of `peer`'s outbox to this identity (dht_dm_outbox_sync_day
 * :414-474): strict GET, owner = peer. On FOUND out->blob is SHA3-256 of
 * the value; when `skip_blob` (nullable, 32 bytes) equals it the bucket is
 * the one the caller already processed and stored, so it is NOT decoded
 * (out->unchanged, no items) — the app's blob hash cache,
 * dht_dm_outbox.c:30-80, except that the CALLER keeps the hash and passes
 * it only after storing that bucket's messages. Otherwise codec
 * deserialize, then per message dna_decrypt_message_raw_alg (own round-3 +
 * ML-KEM secret) and the authorship gate of messenger_transport.c:645-716:
 * the Seal's claimed sender must be the peer and dna_verify_seal_authorship
 * must pass under the peer's verified ML-DSA key; anything else is dropped.
 * An authentic message that is not chat text (nc_plaintext_is_chat) is
 * counted in `other` and not returned.
 */
int nc_outbox_fetch_day(const nc_ctx_t *ctx, const nc_peer_t *peer,
                        const uint8_t salt[NC_SALT_LEN], uint64_t day,
                        const uint8_t *skip_blob, nc_inbox_t *out);

/** One day of nc_outbox_fetch_days: nc_outbox_fetch_day's `day` and
 *  `skip_blob` (nullable, 32 bytes). */
typedef struct {
    uint64_t       day;
    const uint8_t *skip_blob;
} nc_outbox_day_req_t;

/**
 * nc_outbox_fetch_day for up to NC_READ_MANY_MAX days of ONE peer's outbox
 * (same peer, same salt). The bucket reads go through nc_read_owner_many
 * (first pages pipelined, NC_READ_PIPELINE at once; each key read exactly
 * as nc_read_one reads it); every day's answer is then processed by the
 * SAME code as nc_outbox_fetch_day's (blob hash, skip_blob, codec,
 * decrypt, authorship gate, chat / other / dropped). outs[i] / rcs[i] are
 * what nc_outbox_fetch_day(ctx, peer, salt, days[i].day,
 * days[i].skip_blob, &outs[i]) would return (NC_ERR_ARG for a day whose key
 * does not derive, NC_ERR_INTERNAL on allocation failure). Free each
 * outs[i] with nc_inbox_clear.
 * @return NC_OK, or NC_ERR_ARG (bad arguments, n == 0,
 *         n > NC_READ_MANY_MAX; every rcs[i] NC_ERR_ARG when rcs is given)
 *         or NC_ERR_INTERNAL with nothing read.
 */
int nc_outbox_fetch_days(const nc_ctx_t *ctx, const nc_peer_t *peer,
                         const uint8_t salt[NC_SALT_LEN],
                         const nc_outbox_day_req_t *days, size_t n,
                         nc_inbox_t *outs, int *rcs);

/** ACK that this identity has STORED `peer`'s messages (G11: the caller
 *  calls this only after its store transaction completed). Key =
 *  SHA3-512(dht_generate_ack_key(me, peer, salt)), value =
 *  dht_ack_value_encode(ack_ts) (8 bytes BE unix seconds — the app's wire
 *  value, dht_offline_queue.c dht_publish_ack), EPHEMERAL, ttl DHT_ACK_TTL,
 *  value_id 1. `ack_ts` is NOT this device's clock (the app's :148): it is
 *  the newest SENDER timestamp this identity has durably stored from
 *  `peer`, so the ACK never covers a message that was not received. 0 is
 *  refused (nothing stored, nothing to acknowledge). */
int nc_ack_publish(const nc_ctx_t *ctx, const char *peer_fp,
                   const uint8_t salt[NC_SALT_LEN], uint64_t ack_ts);

/** Read `peer`'s ACK for messages this identity sent (owner = peer, value
 *  exactly 8 bytes, dht_ack_value_decode — dht_offline_queue.c
 *  ack_listen_callback). On FOUND *ack_ts is the ACK value: the app writes
 *  its own clock there, the web the newest of OUR timestamps it stored. It
 *  is a watermark, not a list: the caller treats a message as delivered
 *  only if it was in a blob published BEFORE this read and its timestamp
 *  is <= *ack_ts. */
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

/* ── Host of the browser entry (package NC-4b) ─────────────────────────
 *
 * nc_wasm.c (the JSON exports) owns no session. It is linked into the
 * wallet's ONE module (scripts/build-nodus-send-wasm.sh), whose file
 * crypto/nodus-send-wasm.c owns the tier-2 session, the op bracket and the
 * cancel flag, and implements the functions below — one session per
 * identity (design §1.1, nodus_auth.c:95-116), one bracket for every async
 * export of the module, one cancel flag for every wait. Not used natively.
 */

/** Enter the module's op bracket: 0, or -1 with the reason in
 *  nc_host_error() (locked, cancelled, another export running). */
int nc_host_begin(void);
/** Leave it: 0, or 1 when lock / cancel ran meanwhile. */
int nc_host_end(void);
const char *nc_host_error(void);
/** The session's client once the wallet is CONNECTED (nsw_connect /
 *  nsw_unlock: the pinned session is open and the node's chain id was
 *  checked), else NULL. */
nodus_client_t *nc_host_client(void);
/** The session identity (ML-DSA-87) once the wallet is IDENTIFIED
 *  (nsw_identify / nsw_unlock — no session needed: the Messages keys, the
 *  history key and kept-profile checks run before the network), else NULL
 *  (also after lock / cancel). */
const nodus_identity_t *nc_host_identity(void);
/** The wallet's own session check for an export about to SEND
 *  (nsw_session_ok): connected, the client ready, and after a reconnect to
 *  another pinned server that server's chain id checked again. Inside the
 *  op bracket; may wait on the network. 0, or -1 with the reason in
 *  nc_host_error(). */
int nc_host_session_ok(void);
/** The module's cancel flag (set by its cancel and lock). */
volatile const int *nc_host_cancel(void);
/** Provided by nc_wasm.c; the host's lock calls it: wipes every Messages
 *  secret and cache (keys, peer keys, history key, last result). */
void nc_session_wipe(void);

#ifdef __cplusplus
}
#endif

#endif /* NC_CORE_H */
