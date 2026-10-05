/**
 * @file web-wallet/connect/nc_group.h
 * @brief Nodus Connect groups — the CODEC layer (package G1): byte layouts,
 *        derivations, sealing / signing and strict parsers. No network, no
 *        UI, no storage, no clock.
 *
 * Governing records:
 *   docs/plans/2026-10-05-connect-groups-bytes.md items 1-7 AS AMENDED by
 *     its REV 2 (R2-1 ... R2-12; REV 2 wins on conflict) — APPROVED,
 *     docs/plans/decisions/2026-10-05-groups-apt-bytes-approved.md.
 *   docs/plans/2026-10-04-connect-groups-design.md rev 1.
 *   docs/plans/decisions/2026-10-04-connect-groups.md items 1-11.
 *   Vectors: web-wallet/test/fixtures/groups_oracle.py -> groups_kat.json
 *     (independent oracle; this file implements its 18 "readings", except
 *     reading 13's empty message text, overridden by decision 11 — see
 *     EMPTY TEXT).
 *
 * Layouts (all integers unsigned big-endian; every tag is the 16-byte
 * 0x00-right-padded ASCII form, also inside HKDF info and hash preimages):
 *
 *   salt_v  = HKDF-SHA3-256(salt = group_id, ikm = group_key_v,
 *                           info = tag(GSALT) || v(4))                 32 B
 *   K       = SHA3-512(tag(GADDR) || purpose(1) || group_id(32) ||
 *                      secret(32) || x(8)); key string "ncg:" || hex(K)
 *             purpose 1 HEAD (addr_secret, x = 0), 2 KEY PACKET
 *             (addr_secret, x = v), 3 RECORD (salt_v, x = v), 4 OUTBOX
 *             (salt_v, x = day).
 *   KEK     = HKDF-SHA3-256(salt = group_id, ikm = ss,
 *               info = tag(GKEK) || v(4) || member_fp(64) || owner_fp(64))
 *   packet  = tag(GKP) || group_id(32) || owner_fp(64) || v(4) ||
 *             prev_digest(64; zeros for v = 1) || record_digest(64) ||
 *             issued_at_ms(8) || count(2, 1..64) ||
 *             entry x count || sig_len(2) = 4627 || sig
 *             entry = kem_ct(1568) || AES-256-KW(KEK, group_key)(40),
 *             entries ordered by kem_ct ascending (memcmp), unique (R2-1);
 *             sig = ML-DSA-87(owner) over every byte before sig_len;
 *             digest(packet) = SHA3-512(every byte before sig_len) (R2-2).
 *   record  = tag(GREC) || group_id(32) || v(4) || nonce(12) || ct_len(4) ||
 *             ct || gcm_tag(16), AAD = the first 52 bytes; plaintext =
 *             name_len(1, <= 64) || name || count(2, 1..64) ||
 *             member_fp(64) x count (ascending, unique, owner included) ||
 *             created_at_ms(8) (<= 4,171 B, R2-8);
 *             record_digest = SHA3-512(the WHOLE record value).
 *   HEAD    = tag(GHEAD) || group_id(32) || owner_fp(64) || v(4) ||
 *             kp_digest(64) || issued_at_ms(8) || sig_len(2) = 4627 || sig,
 *             sig over the 188 bytes before sig_len, no trailing bytes.
 *   message H = tag(GMSG) || group_id(32) || v(4) || sender_fp(64) ||
 *             message_id(16) || timestamp_ms(8) || day(4) || nonce(12)
 *             (156 B); GCM AAD = H minus its last 12 bytes (R2-5); item =
 *             H || ct_len(4) || ct || gcm_tag(16) || sig_len(2) = 4627 ||
 *             sig, sig = ML-DSA-87(sender) over H || ct_len || ct || tag.
 *   bucket  = tag(GBKT) || count(2) || item x count (<= 100 items,
 *             <= 1 MiB, text <= 4,000 B).
 *   day     = floor(timestamp_ms / 86,400,000), refused when > 2^32 - 1.
 *
 * NONCES. qgp_aes256_encrypt draws the 12-byte nonce itself
 * (shared/crypto/enc/qgp_aes.c:59-62), so a seal cannot reproduce a fixed
 * vector: the AAD is built first, the nonce the call produced is then
 * placed into the bytes (record: after the 52-byte AAD; message: the last
 * 12 bytes of H). Opening takes the nonce from the bytes.
 *
 * EMPTY TEXT — decision 11 (docs/plans/decisions/2026-10-04-connect-groups.md
 * item 11, operator 2026-10-05): a group message text is >= 1 byte; empty
 * text is refused at seal AND at parse (bytes item 5 lower bound = 1).
 * The rule is checked explicitly on the ct_len field: nc_group_msg_seal
 * refuses text_len 0, nc_group_msg_parse refuses ct_len 0 (so bucket encode
 * / decode refuse an item that carries one) and nc_group_msg_open refuses it
 * again. qgp_aes256_encrypt / _decrypt would refuse it too
 * (qgp_aes.c:49-52, :135-138) — not relied upon. The oracle's reading 13
 * (messages[1] of groups_kat.json, written before the decision) calls an
 * empty text valid; this codec refuses it.
 *
 * KEY BINDING (stated): the verify functions take the signer's ML-DSA-87
 * public key AND the expected fingerprint as SEPARATE inputs; they do not
 * check SHA3-512(pk) == fp. That binding is done where the key is fetched:
 * nc_profile_read / nc_profile_check (nc_core.h) check
 * SHA3-512(dilithium_pubkey) == fp on the owner-filtered profile read
 * (bytes R2-11). A caller must pass a key obtained that way.
 *
 * SECRETS. group_key, ss, KEK, unwrapped keys and plaintexts are wiped with
 * qgp_secure_memzero on every path, including refusals.
 *
 * Return codes: functions returning int give NC_GROUP_OK (0),
 * NC_GROUP_REFUSED (-1: bad input / bytes refused) or NC_GROUP_FAULT
 * (-2: RNG, crypto library or allocation failure). The openers return the
 * status enums below.
 */

#ifndef NC_GROUP_H
#define NC_GROUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NC_GROUP_OK        0
#define NC_GROUP_REFUSED  (-1)
#define NC_GROUP_FAULT    (-2)

/* ── Sizes (bytes doc; R2-1, R2-4, R2-5, R2-8) ───────────────────────── */

#define NC_GROUP_TAG_LEN         16
#define NC_GROUP_ID_LEN          32
#define NC_GROUP_FP_LEN          64     /* SHA3-512 fingerprint           */
#define NC_GROUP_SECRET_LEN      32     /* addr_secret, salt_v            */
#define NC_GROUP_KEY_LEN         32     /* group_key_v, KEK               */
#define NC_GROUP_DIGEST_LEN      64     /* SHA3-512                       */
#define NC_GROUP_KEM_CT_LEN      1568   /* ML-KEM-1024 ciphertext         */
#define NC_GROUP_KEM_PK_LEN      1568   /* ML-KEM-1024 encapsulation key  */
#define NC_GROUP_KEM_SK_LEN      3168   /* ML-KEM-1024 decapsulation key  */
#define NC_GROUP_SS_LEN          32     /* ML-KEM shared secret           */
#define NC_GROUP_WRAPPED_LEN     40     /* RFC 3394 of a 32-byte key      */
#define NC_GROUP_ENTRY_LEN       (NC_GROUP_KEM_CT_LEN + NC_GROUP_WRAPPED_LEN)
#define NC_GROUP_SIG_LEN         4627   /* ML-DSA-87                      */
#define NC_GROUP_DSA_PK_LEN      2592
#define NC_GROUP_DSA_SK_LEN      4896
#define NC_GROUP_NONCE_LEN       12
#define NC_GROUP_GCM_TAG_LEN     16
#define NC_GROUP_MSG_ID_LEN      16
#define NC_GROUP_INVITE_ID_LEN   16

#define NC_GROUP_MAX_MEMBERS     64     /* decision item 3                 */
#define NC_GROUP_NAME_MAX        64
#define NC_GROUP_TEXT_MAX        4000
#define NC_GROUP_RECORD_PT_MAX   (1 + NC_GROUP_NAME_MAX + 2 + \
                                  NC_GROUP_MAX_MEMBERS * NC_GROUP_FP_LEN + 8)
#define NC_GROUP_BUCKET_MAX      (1u << 20)
#define NC_GROUP_BUCKET_ITEMS_MAX 100
#define NC_GROUP_MS_PER_DAY      86400000ull

#define NC_GROUP_KP_HEADER_LEN   254
#define NC_GROUP_REC_AAD_LEN     52
#define NC_GROUP_REC_HEADER_LEN  68     /* AAD || nonce || ct_len          */
#define NC_GROUP_HEAD_SIGNED_LEN 188
#define NC_GROUP_HEAD_LEN        (NC_GROUP_HEAD_SIGNED_LEN + 2 + NC_GROUP_SIG_LEN)
#define NC_GROUP_MSG_H_LEN       156
#define NC_GROUP_MSG_AAD_LEN     144
#define NC_GROUP_ADDR_STR_LEN    (4 + 2 * NC_GROUP_DIGEST_LEN)  /* "ncg:"+hex */

/* ── Tags ─────────────────────────────────────────────────────────────── */

typedef enum {
    NC_GROUP_TAG_GSALT = 0,   /* "NDS.GSALT.v1" */
    NC_GROUP_TAG_GADDR,       /* "NDS.GADDR.v1" */
    NC_GROUP_TAG_GKP,         /* "NDS.GKP.v1"   */
    NC_GROUP_TAG_GKEK,        /* "NDS.GKEK.v1"  */
    NC_GROUP_TAG_GREC,        /* "NDS.GREC.v1"  */
    NC_GROUP_TAG_GHEAD,       /* "NDS.GHEAD.v1" */
    NC_GROUP_TAG_GMSG,        /* "NDS.GMSG.v1"  */
    NC_GROUP_TAG_GBKT,        /* "NDS.GBKT.v1"  */
    NC_GROUP_TAG_COUNT
} nc_group_tag_id_t;

/** The 16-byte padded tag, or NULL for an unknown id. */
const uint8_t *nc_group_tag(nc_group_tag_id_t id);

/* ── Secrets / addresses (§ "Secrets per group", §1) ─────────────────── */

/** salt_v = HKDF-SHA3-256(group_id, group_key_v, tag(GSALT) || v). */
int nc_group_salt_v(const uint8_t group_id[NC_GROUP_ID_LEN],
                    const uint8_t group_key[NC_GROUP_KEY_LEN], uint32_t v,
                    uint8_t salt_out[NC_GROUP_SECRET_LEN]);

typedef enum {
    NC_GROUP_PURPOSE_HEAD       = 1,   /* secret = addr_secret, x = 0    */
    NC_GROUP_PURPOSE_KEY_PACKET = 2,   /* secret = addr_secret, x = v    */
    NC_GROUP_PURPOSE_RECORD     = 3,   /* secret = salt_v,      x = v    */
    NC_GROUP_PURPOSE_OUTBOX     = 4    /* secret = salt_v,      x = day  */
} nc_group_purpose_t;

/**
 * K = SHA3-512(tag(GADDR) || purpose || group_id || secret || x(8)).
 * Refused: an unknown purpose; HEAD with x != 0; KEY_PACKET / RECORD with
 * x == 0 or x > 2^32 - 1 (v is a u32 >= 1); OUTBOX with x > 2^32 - 1 (day
 * is a u32). `str_out` (nullable) = "ncg:" || lowercase hex(K), NUL
 * terminated. The DHT layer hashes that string once more (nc_key_str,
 * nc_read.c) — not done here.
 */
int nc_group_addr(nc_group_purpose_t purpose,
                  const uint8_t group_id[NC_GROUP_ID_LEN],
                  const uint8_t secret[NC_GROUP_SECRET_LEN], uint64_t x,
                  uint8_t k_out[NC_GROUP_DIGEST_LEN],
                  char str_out[NC_GROUP_ADDR_STR_LEN + 1]);

/** day = floor(timestamp_ms / 86,400,000); NC_GROUP_REFUSED when the day
 *  does not fit a u32 (timestamp_ms >= 2^32 * 86,400,000). */
int nc_group_day(uint64_t timestamp_ms, uint32_t *day_out);

/* ── Key packet (§2 + R2-1, R2-2, R2-3) ──────────────────────────────── */

/** KEK = HKDF-SHA3-256(group_id, ss, tag(GKEK) || v || member_fp || owner_fp). */
int nc_group_kek(const uint8_t ss[NC_GROUP_SS_LEN],
                 const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                 const uint8_t member_fp[NC_GROUP_FP_LEN],
                 const uint8_t owner_fp[NC_GROUP_FP_LEN],
                 uint8_t kek_out[NC_GROUP_KEY_LEN]);

/** wrapped = AES-256-KW(KEK, group_key) with KEK = nc_group_kek(...); the
 *  KEK is wiped before return. */
int nc_group_wrap(const uint8_t ss[NC_GROUP_SS_LEN],
                  const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                  const uint8_t member_fp[NC_GROUP_FP_LEN],
                  const uint8_t owner_fp[NC_GROUP_FP_LEN],
                  const uint8_t group_key[NC_GROUP_KEY_LEN],
                  uint8_t wrapped_out[NC_GROUP_WRAPPED_LEN]);

typedef struct {
    uint8_t  group_id[NC_GROUP_ID_LEN];
    uint8_t  owner_fp[NC_GROUP_FP_LEN];
    uint32_t v;                                  /* >= 1                  */
    uint8_t  prev_digest[NC_GROUP_DIGEST_LEN];   /* zeros for v = 1       */
    uint8_t  record_digest[NC_GROUP_DIGEST_LEN];
    uint64_t issued_at_ms;                       /* opaque, never trusted */
} nc_group_kp_hdr_t;

/**
 * The signed span of a packet from per-member KEM outputs: header, then
 * one entry per member (kem_ct[i], AES-256-KW under the KEK of
 * (ss[i], member_fps[i])), entries sorted by kem_ct ascending. The KEM
 * step is the caller's: nc_group_kp_build does a fresh
 * qgp_mlkem1024_encapsulate per member and calls this; tests pass fixed
 * (kem_ct, ss) pairs. Refused: count outside 1..64; member_fps not
 * strictly ascending (memcmp) or not containing hdr->owner_fp (R2-3:
 * entries for exactly the record's members); v == 0; v == 1 with a
 * non-zero prev_digest; two equal kem_ct. *pre_out malloc'd
 * (NC_GROUP_KP_HEADER_LEN + count * NC_GROUP_ENTRY_LEN bytes).
 */
int nc_group_kp_assemble(const nc_group_kp_hdr_t *hdr,
                         const uint8_t group_key[NC_GROUP_KEY_LEN],
                         const uint8_t (*member_fps)[NC_GROUP_FP_LEN],
                         const uint8_t (*kem_ct)[NC_GROUP_KEM_CT_LEN],
                         const uint8_t (*ss)[NC_GROUP_SS_LEN],
                         size_t count,
                         uint8_t **pre_out, size_t *pre_len);

/**
 * The owner's packet: for each member, qgp_mlkem1024_ek_check of
 * member_eks[i] (a refused key FAILS the whole build — never skipped,
 * design §3), then qgp_mlkem1024_encapsulate (fresh randomness), then
 * nc_group_kp_assemble, ML-DSA-87 over the span with owner_sk,
 * sig_len || sig appended. The result is read back with
 * nc_group_kp_parse and its signature verified under owner_pk before it is
 * returned. digest_out (nullable) = digest(packet) (R2-2). The owner
 * persists and republishes these exact bytes for the version. *out
 * malloc'd.
 */
int nc_group_kp_build(const nc_group_kp_hdr_t *hdr,
                      const uint8_t group_key[NC_GROUP_KEY_LEN],
                      const uint8_t (*member_fps)[NC_GROUP_FP_LEN],
                      const uint8_t (*member_eks)[NC_GROUP_KEM_PK_LEN],
                      size_t count,
                      const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                      const uint8_t owner_sk[NC_GROUP_DSA_SK_LEN],
                      uint8_t **out, size_t *out_len,
                      uint8_t digest_out[NC_GROUP_DIGEST_LEN]);

/**
 * Structure only, in the oracle's order: length >= header; tag; count in
 * 1..64; sig_len at the offset implied by count == 4627; exact total
 * length; v >= 1, v == 1 => prev_digest all zero; kem_ct strictly
 * ascending (equal = duplicate). hdr_out / count_out nullable.
 * 0 / NC_GROUP_REFUSED. No signature check.
 */
int nc_group_kp_parse(const uint8_t *data, size_t len,
                      nc_group_kp_hdr_t *hdr_out, size_t *count_out);

/** digest(packet) = SHA3-512(bytes before sig_len), after nc_group_kp_parse. */
int nc_group_kp_digest(const uint8_t *data, size_t len,
                       uint8_t digest_out[NC_GROUP_DIGEST_LEN]);

/** Decapsulation hook for nc_group_kp_open: 0 and ss filled, or -1. */
typedef int (*nc_group_decap_fn)(uint8_t ss[NC_GROUP_SS_LEN],
                                 const uint8_t ct[NC_GROUP_KEM_CT_LEN],
                                 void *user);

/** The production hook: qgp_mlkem1024_decapsulate with user = the
 *  member's ML-KEM-1024 decapsulation key (NC_GROUP_KEM_SK_LEN bytes). */
int nc_group_decap_mlkem(uint8_t ss[NC_GROUP_SS_LEN],
                         const uint8_t ct[NC_GROUP_KEM_CT_LEN], void *user);

typedef enum {
    NC_GROUP_KP_OK               = 0,
    NC_GROUP_KP_BAD_STRUCTURE    = 1,  /* nc_group_kp_parse refused        */
    NC_GROUP_KP_BAD_SIG          = 2,  /* not signed by the pinned owner    */
    NC_GROUP_KP_MISMATCH         = 3,  /* group_id / v / owner_fp differ
                                        * from what was asked              */
    NC_GROUP_KP_PREV_CONFLICT    = 4,  /* prev_digest != stored digest of
                                        * v-1: refuse, never replace       */
    NC_GROUP_KP_PREV_UNAVAILABLE = 5,  /* v > 1 and no stored digest of v-1:
                                        * walk forward from the high-water
                                        * mark first (R2-7), retry         */
    NC_GROUP_KP_NO_ENTRY         = 6,  /* no entry unwraps for this member */
    NC_GROUP_KP_FAULT            = 7   /* allocation / crypto failure      */
} nc_group_kp_status_t;

typedef struct {
    nc_group_kp_hdr_t hdr;
    size_t            count;                       /* entries = members  */
    uint8_t           digest[NC_GROUP_DIGEST_LEN]; /* R2-2               */
    uint8_t           group_key[NC_GROUP_KEY_LEN]; /* OK only; the caller
                                                    * wipes it            */
} nc_group_kp_open_t;

/**
 * Read a packet as a member, in this order (bytes §2 reader, design §2):
 *   1. strict structure (nc_group_kp_parse);
 *   2. ML-DSA-87 signature under owner_pk over the bytes before sig_len —
 *      FIRST, before any field is trusted or any decapsulation;
 *   3. group_id == expect_group_id, v == expect_v,
 *      owner_fp == expect_owner_fp;
 *   4. prev_digest: v == 1 -> zeros (already checked in 1); v > 1 ->
 *      stored_prev_digest NULL = PREV_UNAVAILABLE, equal = continue,
 *      different = PREV_CONFLICT;
 *   5. trial unwrap (R2-1): for each entry, decap(ss, kem_ct), KEK for
 *      (ss, my_fp), RFC 3394 unwrap; the integrity check rejects the
 *      others (aes_keywrap.c). A failed decap moves to the next entry.
 * `out` is filled with hdr/count/digest from step 3 on; group_key only on
 * OK, otherwise wiped. Decapsulation success authenticates nothing (FIPS
 * 203 implicit rejection): the signature and the unwrap integrity do.
 * owner_pk must come from the owner-filtered profile read (see KEY BINDING).
 */
nc_group_kp_status_t nc_group_kp_open(const uint8_t *data, size_t len,
                                      const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                                      const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                      const uint8_t expect_owner_fp[NC_GROUP_FP_LEN],
                                      uint32_t expect_v,
                                      const uint8_t *stored_prev_digest,
                                      const uint8_t my_fp[NC_GROUP_FP_LEN],
                                      nc_group_decap_fn decap, void *decap_user,
                                      nc_group_kp_open_t *out);

/**
 * nc_group_kp_open for the packet a new member is WELCOMED into (R2-7: the
 * welcome carries key_version N and kp_digest of N — the member's initial
 * high-water mark; it holds no packet of N-1). Steps 1-3 and 5 as
 * nc_group_kp_open; step 4 is replaced: the packet's digest (R2-2) must
 * equal expect_digest (the welcome's kp_digest), else PREV_CONFLICT — a
 * different packet for a version already pinned is a conflict, refused,
 * never taken (design §3). prev_digest is not checked: the member walks
 * forward from N (R2-7) and never reads below it (decision 12, no pre-join
 * history). A reader rule, no byte layout.
 */
nc_group_kp_status_t nc_group_kp_open_pinned(const uint8_t *data, size_t len,
                                             const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                                             const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                             const uint8_t expect_owner_fp[NC_GROUP_FP_LEN],
                                             uint32_t expect_v,
                                             const uint8_t expect_digest[NC_GROUP_DIGEST_LEN],
                                             const uint8_t my_fp[NC_GROUP_FP_LEN],
                                             nc_group_decap_fn decap, void *decap_user,
                                             nc_group_kp_open_t *out);

/* ── Record (§3 + R2-3, R2-8) ────────────────────────────────────────── */

typedef struct {
    uint8_t  name[NC_GROUP_NAME_MAX + 1];   /* raw UTF-8, NUL appended (not
                                             * part of the bytes); may hold
                                             * NULs — use name_len          */
    size_t   name_len;
    size_t   count;
    uint8_t  members[NC_GROUP_MAX_MEMBERS][NC_GROUP_FP_LEN]; /* ascending */
    uint64_t created_at_ms;
} nc_group_record_t;

/**
 * Plaintext only (reading 11): length <= 4,171; name_len <= 64; count in
 * 1..64; exact length 1 + name_len + 2 + 64 * count + 8; members strictly
 * ascending (equal = duplicate). The name is not normalised and its UTF-8
 * is not validated (the oracle's reading).
 */
int nc_group_record_pt_parse(const uint8_t *pt, size_t len,
                             nc_group_record_t *out);

/**
 * Seal a record: plaintext from (name, members, created_at_ms) — members
 * strictly ascending, owner_fp among them, 1..64, name <= 64 bytes — then
 * qgp_aes256_encrypt(group_key, pt, AAD = tag(GREC) || group_id || v), the
 * produced nonce placed after the AAD. digest_out (nullable) =
 * record_digest (SHA3-512 of the whole value). The bytes are opened back
 * before they are returned. *out malloc'd.
 */
int nc_group_record_seal(const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                         const uint8_t group_key[NC_GROUP_KEY_LEN],
                         const uint8_t owner_fp[NC_GROUP_FP_LEN],
                         const uint8_t *name, size_t name_len,
                         const uint8_t (*members)[NC_GROUP_FP_LEN], size_t count,
                         uint64_t created_at_ms,
                         uint8_t **out, size_t *out_len,
                         uint8_t digest_out[NC_GROUP_DIGEST_LEN]);

/** record_digest = SHA3-512(data). Refused only for NULL / empty input. */
int nc_group_record_digest(const uint8_t *data, size_t len,
                           uint8_t digest_out[NC_GROUP_DIGEST_LEN]);

typedef enum {
    NC_GROUP_REC_OK            = 0,
    NC_GROUP_REC_BAD_STRUCTURE = 1,  /* tag, length, ct_len over the cap   */
    NC_GROUP_REC_MISMATCH      = 2,  /* group_id / v differ                */
    NC_GROUP_REC_BAD_DIGEST    = 3,  /* != record_digest of the packet     */
    NC_GROUP_REC_BAD_AUTH      = 4,  /* GCM refused                        */
    NC_GROUP_REC_BAD_PLAINTEXT = 5,  /* nc_group_record_pt_parse refused   */
    NC_GROUP_REC_COUNT         = 6,  /* count != the packet's count        */
    NC_GROUP_REC_NO_OWNER      = 7,  /* owner_fp is not a member           */
    NC_GROUP_REC_FAULT         = 8
} nc_group_rec_status_t;

/**
 * Open a record read at RECORD(v), in this order: structure (length >= 84,
 * tag, ct_len <= 4,171 checked on the field BEFORE any allocation or
 * decryption — reading 10, exact length 68 + ct_len + 16); group_id /
 * v == expected; SHA3-512(data) == expect_digest (the packet's
 * record_digest, from a packet that passed nc_group_kp_open); GCM open
 * with the stored nonce; plaintext parse; count == expect_count (the
 * packet's count — §3, R2-3); owner_fp among the members. `out` is wiped
 * on every refusal.
 */
nc_group_rec_status_t nc_group_record_open(const uint8_t *data, size_t len,
                                           const uint8_t group_key[NC_GROUP_KEY_LEN],
                                           const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                           uint32_t expect_v,
                                           const uint8_t expect_digest[NC_GROUP_DIGEST_LEN],
                                           size_t expect_count,
                                           const uint8_t owner_fp[NC_GROUP_FP_LEN],
                                           nc_group_record_t *out);

/* ── HEAD (§4 + R2-4) ────────────────────────────────────────────────── */

typedef struct {
    uint8_t  group_id[NC_GROUP_ID_LEN];
    uint8_t  owner_fp[NC_GROUP_FP_LEN];
    uint32_t v;
    uint8_t  kp_digest[NC_GROUP_DIGEST_LEN];   /* digest(packet v), R2-2 */
    uint64_t issued_at_ms;
} nc_group_head_t;

/** The 188-byte signed span of a HEAD. v must be >= 1. */
int nc_group_head_preimage(const nc_group_head_t *h,
                           uint8_t pre_out[NC_GROUP_HEAD_SIGNED_LEN]);

/** span || 4627(2) || ML-DSA-87(owner_sk, span); verified under owner_pk
 *  before return. Exactly NC_GROUP_HEAD_LEN bytes. */
int nc_group_head_build(const nc_group_head_t *h,
                        const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                        const uint8_t owner_sk[NC_GROUP_DSA_SK_LEN],
                        uint8_t out[NC_GROUP_HEAD_LEN]);

/** Structure only: length == 4,817 exactly (via >= 190, tag, sig_len ==
 *  4627, exact length — the oracle's order); v >= 1. h_out nullable. */
int nc_group_head_parse(const uint8_t *data, size_t len, nc_group_head_t *h_out);

typedef enum {
    NC_GROUP_HEAD_OK            = 0,
    NC_GROUP_HEAD_BAD_STRUCTURE = 1,
    NC_GROUP_HEAD_BAD_SIG       = 2,
    NC_GROUP_HEAD_MISMATCH      = 3   /* group_id / owner_fp differ       */
} nc_group_head_status_t;

/**
 * Structure, then the signature under owner_pk over the 188-byte span,
 * then group_id / owner_fp == expected. The forward-only rule (v > the
 * stored high-water mark; kp_digest equal to the digest of the packet
 * fetched for v; the welcome's kp_digest for N, R2-7) is the caller's: it
 * holds that state. `out` is filled only on OK.
 */
nc_group_head_status_t nc_group_head_verify(const uint8_t *data, size_t len,
                                            const uint8_t owner_pk[NC_GROUP_DSA_PK_LEN],
                                            const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                                            const uint8_t expect_owner_fp[NC_GROUP_FP_LEN],
                                            nc_group_head_t *out);

/* ── Message (§5 + R2-5) ─────────────────────────────────────────────── */

/**
 * The first 144 bytes of H (= the GCM AAD, R2-5):
 * tag(GMSG) || group_id || v || sender_fp || message_id || timestamp_ms ||
 * day, day computed from timestamp_ms (refused when it does not fit a u32).
 * v must be >= 1.
 */
int nc_group_msg_aad(const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                     const uint8_t sender_fp[NC_GROUP_FP_LEN],
                     const uint8_t message_id[NC_GROUP_MSG_ID_LEN],
                     uint64_t timestamp_ms,
                     uint8_t aad_out[NC_GROUP_MSG_AAD_LEN]);

/**
 * Seal and sign one message item: message_id = 16 fresh random bytes
 * (written to message_id_out); AAD = nc_group_msg_aad; (ct, tag) =
 * qgp_aes256_encrypt(group_key, text, AAD); the produced nonce is placed
 * into H; sig = ML-DSA-87(sender_sk) over H || ct_len || ct || tag, checked
 * under sender_pk before return. text: 1..4,000 bytes (empty refused,
 * decision 11 — see EMPTY TEXT). *item_out malloc'd.
 */
int nc_group_msg_seal(const uint8_t group_key[NC_GROUP_KEY_LEN],
                      const uint8_t group_id[NC_GROUP_ID_LEN], uint32_t v,
                      const uint8_t sender_fp[NC_GROUP_FP_LEN],
                      uint64_t timestamp_ms,
                      const uint8_t *text, size_t text_len,
                      const uint8_t sender_pk[NC_GROUP_DSA_PK_LEN],
                      const uint8_t sender_sk[NC_GROUP_DSA_SK_LEN],
                      uint8_t message_id_out[NC_GROUP_MSG_ID_LEN],
                      uint8_t **item_out, size_t *item_len);

/** One parsed item; every pointer points into the parsed buffer. */
typedef struct {
    uint8_t        group_id[NC_GROUP_ID_LEN];
    uint32_t       v;
    uint8_t        sender_fp[NC_GROUP_FP_LEN];
    uint8_t        message_id[NC_GROUP_MSG_ID_LEN];
    uint64_t       timestamp_ms;     /* displayed, never trusted          */
    uint32_t       day;
    const uint8_t *h;                /* NC_GROUP_MSG_H_LEN bytes          */
    const uint8_t *ct;
    size_t         ct_len;
    const uint8_t *gcm_tag;
    const uint8_t *sig;              /* NC_GROUP_SIG_LEN bytes            */
    size_t         signed_len;       /* H || ct_len || ct || tag          */
    size_t         item_len;         /* signed_len + 2 + NC_GROUP_SIG_LEN */
} nc_group_msg_t;

/**
 * Parse ONE item at the start of data[0..len): tag; v >= 1; day ==
 * nc_group_day(timestamp_ms); ct_len in 1..4,000 (checked on the field
 * before anything else reads ct — R2-8; 0 refused, decision 11, see EMPTY
 * TEXT); sig_len == 4627; the item fits. `exact`: true = the item must
 * consume all of len.
 */
int nc_group_msg_parse(const uint8_t *data, size_t len, bool exact,
                       nc_group_msg_t *out);

typedef enum {
    NC_GROUP_MSG_OK        = 0,
    NC_GROUP_MSG_BAD_SIG   = 1,   /* not signed by sender_pk              */
    NC_GROUP_MSG_BAD_AUTH  = 2,   /* GCM refused (wrong key / tampered)   */
    NC_GROUP_MSG_REFUSED   = 3,   /* bad argument                          */
    NC_GROUP_MSG_FAULT     = 4
} nc_group_msg_status_t;

/**
 * Signature under sender_pk (the key of m->sender_fp, KEY BINDING) over
 * the signed span FIRST, then GCM open under group_key (the key of m->v)
 * with AAD = H minus its last 12 bytes and the nonce = those 12 bytes.
 * text_out must hold m->ct_len (<= NC_GROUP_TEXT_MAX) bytes; wiped on any
 * refusal. The other accept rules are NOT in here: nc_group_msg_accept
 * (membership) and the DHT value owner == m->sender_fp (the caller holds
 * the value; design §6).
 */
nc_group_msg_status_t nc_group_msg_open(const nc_group_msg_t *m,
                                        const uint8_t group_key[NC_GROUP_KEY_LEN],
                                        const uint8_t sender_pk[NC_GROUP_DSA_PK_LEN],
                                        uint8_t *text_out, size_t *text_len);

/**
 * The membership accept rule (design §6, decision 6): sender ∈
 * members_v (the record of the message's v) AND, when the receiver holds
 * a newer version N+1 (members_next != NULL), sender ∈ members_next. No
 * time check. A removed member's old-version message is dropped once
 * N+1 is held. Lists need not be sorted. false on NULL sender / list.
 */
bool nc_group_msg_accept(const uint8_t sender_fp[NC_GROUP_FP_LEN],
                         const uint8_t (*members_v)[NC_GROUP_FP_LEN], size_t n_v,
                         const uint8_t (*members_next)[NC_GROUP_FP_LEN], size_t n_next);

/* ── Bucket (§5 + R2-5, R2-8) ────────────────────────────────────────── */

/**
 * tag(GBKT) || count || items. Each item must parse exactly
 * (nc_group_msg_parse), all items carry the same group_id / v / day and
 * the same sender_fp (one sender's day bucket), message_ids are unique,
 * 1..100 items, total <= 1 MiB. *out malloc'd.
 */
int nc_group_bucket_encode(const uint8_t *const *items, const size_t *item_lens,
                           size_t n, uint8_t **out, size_t *out_len);

/**
 * Decode a bucket read at OUTBOX(salt_v, day): len <= 1 MiB; tag;
 * count <= 100 (0 is accepted: nothing to read); items parsed in sequence,
 * the last ending exactly at len; every item's group_id / v / day ==
 * expect_* (R2-5: the bucket's address inputs); all items from one
 * sender_fp; message_ids unique. *items_out malloc'd (count entries, may
 * be NULL when count is 0), pointing INTO data — keep data alive. The
 * caller then checks the DHT value owner == items[i].sender_fp, verifies
 * and opens each item (nc_group_msg_open) and applies
 * nc_group_msg_accept.
 */
int nc_group_bucket_decode(const uint8_t *data, size_t len,
                           const uint8_t expect_group_id[NC_GROUP_ID_LEN],
                           uint32_t expect_v, uint32_t expect_day,
                           nc_group_msg_t **items_out, size_t *count_out);

/* ── Invite / accept / welcome / leave JSON (§7 + R2-7, decision 13) ── */

typedef enum {
    NC_GROUP_JSON_INVITE  = 1,   /* "nodus_group_invite"  */
    NC_GROUP_JSON_ACCEPT  = 2,   /* "nodus_group_accept"  */
    NC_GROUP_JSON_WELCOME = 3,   /* "nodus_group_welcome" */
    NC_GROUP_JSON_LEAVE   = 4    /* "nodus_group_leave" — decision 13
                                  * (docs/plans/decisions/2026-10-04-connect-
                                  * groups.md item 13): member -> owner,
                                  * {"type","v","group_id"}, no invite_id   */
} nc_group_json_type_t;

typedef struct {
    nc_group_json_type_t type;
    uint8_t  group_id[NC_GROUP_ID_LEN];
    uint8_t  invite_id[NC_GROUP_INVITE_ID_LEN];   /* all zero for a leave   */
    /* invite + welcome */
    uint8_t  owner_fp[NC_GROUP_FP_LEN];
    /* invite */
    char     name[NC_GROUP_NAME_MAX + 1];      /* UTF-8, no NUL inside   */
    size_t   name_len;
    /* welcome — addr_secret is a SECRET: the caller wipes the struct */
    uint8_t  addr_secret[NC_GROUP_SECRET_LEN];
    uint32_t key_version;                      /* >= 1                    */
    uint8_t  kp_digest[NC_GROUP_DIGEST_LEN];
} nc_group_json_t;

/** Max accepted / produced JSON length (a welcome is ~520 bytes). */
#define NC_GROUP_JSON_MAX 2048

/**
 * Encoders: compact JSON (no whitespace), keys in the oracle's order
 * (reading 16), lowercase hex, UTF-8 not escaped, "/" not escaped.
 *   invite  = type, v, group_id, owner, name, invite_id
 *   accept  = type, v, group_id, invite_id
 *   welcome = type, v, group_id, owner, addr_secret, key_version,
 *             kp_digest, invite_id
 *   leave   = type, v, group_id   (decision 13, exactly its text:
 *             {"type":"nodus_group_leave","v":1,"group_id":"<64 hex>"})
 * *out malloc'd NUL-terminated (the welcome carries addr_secret: the
 * caller wipes it). The name: <= 64 bytes, no NUL.
 */
int nc_group_invite_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                           const uint8_t owner_fp[NC_GROUP_FP_LEN],
                           const char *name, size_t name_len,
                           const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                           char **out, size_t *out_len);
int nc_group_accept_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                           const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                           char **out, size_t *out_len);
int nc_group_welcome_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                            const uint8_t owner_fp[NC_GROUP_FP_LEN],
                            const uint8_t addr_secret[NC_GROUP_SECRET_LEN],
                            uint32_t key_version,
                            const uint8_t kp_digest[NC_GROUP_DIGEST_LEN],
                            const uint8_t invite_id[NC_GROUP_INVITE_ID_LEN],
                            char **out, size_t *out_len);
int nc_group_leave_encode(const uint8_t group_id[NC_GROUP_ID_LEN],
                          char **out, size_t *out_len);

/**
 * Strict parse of one decrypted 1:1 plaintext (len bytes, <= 2,048, no NUL
 * inside): one JSON object (json-c strict tokener, all of len consumed;
 * the first byte must be '{' and the last '}' — no surrounding whitespace);
 * "type" one of the four; EXACTLY that type's field set — no missing, no
 * extra and no duplicate key (a duplicate is detected by counting the
 * object's members in the text against the parsed object); "v" the JSON
 * integer 1; hex fields lowercase of the exact length; key_version a JSON
 * integer 1..2^32-1; name a string <= 64 bytes without NUL. Key order is
 * not required (reading 16). Who may send which (invite / welcome only
 * from the pinned owner == the authenticated 1:1 sender; accept only for a
 * pending invite_id of that contact, consumed once; leave only from a
 * current member, decision 13) is the caller's.
 * `out` is wiped on refusal.
 */
int nc_group_json_parse(const char *json, size_t len, nc_group_json_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NC_GROUP_H */
