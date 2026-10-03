/**
 * @file nodus/src/client/nodus_v2_msig.h
 * @brief The shared general-multisig (M-of-N) client library — descriptor
 *        from keys, the UNSIGNED vault SPEND + its export text, the
 *        co-signer's read-back, the signature text, and the combine.
 *        No I/O.
 *
 * Governing records: docs/plans/decisions/2026-09-29-general-multisig.md
 * (M-of-N address, at most 7 keys per address, at most 15 descriptor keys
 * per transaction, auth_kind 3, validity window tip + 90 blocks, the
 * NDS.MSIG.v1 tag) with design docs/plans/2026-09-29-general-multisig-
 * design.md §7 rev 2 (the approved layout), and docs/plans/decisions/
 * 2026-09-25-web-wallet-nodus-send-transport.md ("İşlem kurucu": the
 * wallet builds with the SAME C code nodus-cli uses — applied here to the
 * multisig flow as it was to the SPEND, staking and name builders).
 *
 * WHAT IT IS: the bodies of nodus-cli `msig address`, `v2-envelope spend
 * --msig`, `msig sign` and `msig combine` (nodus/tools/nodus-cli.c), moved
 * out unchanged in behaviour; nodus-cli now calls this file, and the web
 * wallet's WASM module (web-wallet/crypto/nodus-send-wasm.c) compiles the
 * same file. Pure functions over caller-supplied bytes: no socket, no
 * clock, no database, no stdio, no global RNG — the output seeds come from
 * the caller's `rand` callback (32 bytes per output per fee pass, exactly
 * where the CLI drew nodus_random). The descriptor codec and the address
 * derivation stay in shared/dnac/msig_wire.c (not restated here).
 *
 * WHAT STAYS WITH THE CALLER: the session (chain id, tip, gas price, the
 * rule-set generation the node runs), the expiry value (nodus-cli
 * cli_env_expiry / the wallet's nsw_expiry_for — the decision's tip + 90,
 * capped for a generation-1 envelope), the ruleset tuple an export is
 * judged against, printing, and nodus-cli's extra local check of the
 * assembled authorization with the chain's own auth hook
 * (nodus_rt_auth_dsa87_v1 — witness code a browser cannot link).
 *
 * THE CHAIN IS THE SPECIFICATION (nodus_witness_rt_native.c): a coin owned
 * by the address SHA3-512(descriptor) is spent by a CORE SPEND leg with
 * auth_kind 3 = count u8 ‖ count × (pk[2592] ‖ sig[4627]) (strictly
 * ascending pk) ‖ dcount u8 ‖ dcount × (dlen u16 BE ‖ descriptor), with
 * >= M of the descriptor's keys among the verified signers. Every signer
 * signs the SAME leg auth digest a kind-1 signer would. auth_len is bound
 * by the digest, so the FINAL signer count K (M <= K <= N) is fixed in the
 * unsigned envelope and the combine needs exactly K signatures.
 *
 * THE TWO TEXT FORMATS (nodus-cli's files, byte for byte):
 *   export:    "nodus-msig-export v1\n" "chain_id <64 hex>\n" "tip <dec>\n"
 *              "signers <dec>\n" "digest <128 hex>\n" "envelope <hex>\n"
 *   signature: "nodus-msig-sig v1\n" "digest <128 hex>\n"
 *              "pubkey <5184 hex>\n" "sig <9254 hex>\n"
 * A reader finds each "key " line anywhere after the magic line (the CLI's
 * msig_kv rule). The decimal fields are read STRICTLY here (digits only,
 * no leading zero, within u64 / the signer bound) — the pre-move CLI read
 * them with strtoull/strtoul, which also accepted trailing junk.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef NODUS_V2_MSIG_H
#define NODUS_V2_MSIG_H

#include <stdint.h>
#include <stddef.h>

#include "nodus/nodus_v2_spend.h"   /* rc values, coin, ruleset id, rand fn */
#include "dnac/msig_wire.h"         /* DNA_MSIG_* bounds                   */

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_V2_MSIG_EXPORT_MAGIC "nodus-msig-export v1"
#define NODUS_V2_MSIG_SIG_MAGIC    "nodus-msig-sig v1"

/** One ML-DSA-87 public key / signature (DNAC_PUBKEY_SIZE /
 *  DNAC_SIGNATURE_SIZE; the auth_kind 1/3 signer slot is pk ‖ sig). */
#define NODUS_V2_MSIG_PK_LEN     2592u
#define NODUS_V2_MSIG_SIG_LEN    4627u
/** The outputs the BUILDER writes: the recipient, then the change back to
 *  the vault. */
#define NODUS_V2_MSIG_BUILD_OUTS 2u
/** The outputs a READ-BACK accepts: the chain's SPEND ceiling
 *  (rt_native.c RTN_SPEND_MAX_OUT). A call with more is refused. */
#define NODUS_V2_MSIG_MAX_OUTS   16u
/** The validity window a co-signer accepts: the decision's tip + 90 — the
 *  mempool lifetime cap NODUS_CMT_APP_MAX_EXPIRY_AHEAD (100) minus the
 *  10-block gossip margin every builder uses (nodus-cli
 *  CLI_ENV_EXPIRY_AHEAD, the wallet's NSW_EXPIRY_AHEAD). An export whose
 *  expiry is 0 ("never") or beyond its own tip + this is refused by the
 *  read-back (fix round 2026-10-03, F3). */
#define NODUS_V2_MSIG_EXPIRY_AHEAD 90u
/** The largest signature text (3 magic/key lines + hex), with slack. */
#define NODUS_V2_MSIG_SIG_TEXT_MAX 32768u

/** Refusals of this module beyond the shared nodus_v2_spend_rc_t values it
 *  also returns (ERR_ARG, ERR_ALLOC, ERR_INPUT_SUM, ERR_INSUFFICIENT,
 *  ERR_METER, ERR_GAS_OVERFLOW, ERR_FEE_BELOW_GAS, ERR_RANDOM, ERR_ENCODE,
 *  ERR_PREFLIGHT1, ERR_PREFLIGHT2, ERR_DECODE). */
typedef enum {
    NODUS_V2_MSIG_ERR_DESC        = -60, /* invalid descriptor / key set   */
    NODUS_V2_MSIG_ERR_SIGNERS     = -61, /* K outside [M, N]               */
    NODUS_V2_MSIG_ERR_COIN        = -62, /* zero amount / duplicate coin   */
    NODUS_V2_MSIG_ERR_FEE_FLOOR   = -63, /* a fixed fee below the floor    */
    NODUS_V2_MSIG_ERR_FORMAT      = -64, /* export / signature text        */
    NODUS_V2_MSIG_ERR_SHAPE       = -65, /* not one CORE SPEND leg, kind 3,
                                          * K slots + ONE descriptor       */
    NODUS_V2_MSIG_ERR_DIGEST      = -66, /* exported digest != re-derived  */
    NODUS_V2_MSIG_ERR_NOT_MEMBER  = -67, /* key not in the descriptor      */
    NODUS_V2_MSIG_ERR_CALL        = -68, /* the SPEND call does not parse  */
    NODUS_V2_MSIG_ERR_SIG_DIGEST  = -69, /* a signature over another digest*/
    NODUS_V2_MSIG_ERR_SIG         = -70, /* a signature does not verify    */
    NODUS_V2_MSIG_ERR_COUNT       = -71, /* signatures != the export's K   */
    NODUS_V2_MSIG_ERR_DUP_SIGNER  = -72, /* one key signed twice           */
    NODUS_V2_MSIG_ERR_RULESET     = -73, /* no CORE leg version to judge   */
    NODUS_V2_MSIG_ERR_EXPIRY      = -74  /* expiry 0, or past the export's
                                          * tip + NODUS_V2_MSIG_EXPIRY_AHEAD*/
} nodus_v2_msig_rc_t;

/* ── 1. descriptor + address from keys (nodus-cli `msig address`) ────── */

/**
 * Sort `n` keys (any order, n × NODUS_V2_MSIG_PK_LEN contiguous bytes) into
 * the one canonical order (memcmp ascending), encode the descriptor
 * (dna_msig_desc_encode) and derive its address (dna_msig_address).
 * The caller's buffer is not modified.
 * @param desc_out  receives DNA_MSIG_DESC_LEN(n) bytes (cap >= that)
 * @return NODUS_V2_SPEND_OK / _ERR_ARG / NODUS_V2_MSIG_ERR_DESC (a bound,
 *         a duplicate key, a key whose first 32 bytes are zero) /
 *         NODUS_V2_SPEND_ERR_HASH.
 */
int nodus_v2_msig_desc_from_keys(uint8_t m, uint8_t n, const uint8_t *keys,
                                 uint8_t *desc_out, size_t desc_cap,
                                 size_t *desc_len_out,
                                 uint8_t addr_out[DNA_MSIG_ADDR_LEN]);

/* ── 2. the unsigned vault SPEND (`v2-envelope spend --msig`) ───────── */

/**
 * The UNSIGNED auth_kind-3 blob of a K-signer export: count K ‖ K × 7219
 * zero bytes ‖ dcount 1 ‖ dlen u16 BE ‖ descriptor. `out` receives
 * 1 + K × NODUS_RT_AUTH_SIGNER_LEN + 3 + desc_len bytes.
 * @return NODUS_V2_SPEND_OK / _ERR_ARG (bounds, cap).
 */
int nodus_v2_msig_unsigned_auth(uint32_t signers, const uint8_t *desc,
                                size_t desc_len, uint8_t *out, size_t cap,
                                size_t *len_out);

typedef struct {
    const nodus_v2_ruleset_id_t *rs;  /* the CORE tuple of the generation
                                       * the node runs + its SYSTEM meter
                                       * policy                            */
    const uint8_t *chain32;           /* DNA_CHAIN_ID_LEN bytes            */
    uint64_t       tip;               /* committed tip (>= 1); the digest
                                       * is preflighted at tip + 1         */
    uint64_t       expiry_height;     /* the caller's rule (CLI
                                       * cli_env_expiry / wallet
                                       * nsw_expiry_for)                   */
    const uint8_t *desc;              /* the vault's descriptor            */
    size_t         desc_len;
    const nodus_v2_coin_t *coins;     /* 1..NODUS_V2_SPEND_MAX_IN native
                                       * coins of the vault, any order —
                                       * the CHAIN checks ownership        */
    int            n_coins;
    const uint8_t *to_fp;             /* recipient, 64 raw bytes           */
    uint64_t       amount;            /* >= 1                              */
    uint64_t       fee;               /* fee_fixed only                    */
    int            fee_fixed;         /* 1 = never raised; refused below
                                       * the floor or units × gas price    */
    uint64_t       gas_price;         /* 0 = the rule is off               */
    uint32_t       signers;           /* K; 0 = M                          */
    nodus_v2_rand_fn rand;            /* output seeds                      */
    void            *rand_ctx;
} nodus_v2_msig_build_req_t;

typedef struct {
    uint8_t  *env;                    /* heap; nodus_v2_msig_built_free    */
    size_t    env_len;
    uint8_t   digest[64];             /* the leg auth digest to sign       */
    uint8_t   intent_id[64];
    uint8_t   addr[DNA_MSIG_ADDR_LEN];/* the vault address                 */
    uint8_t   m, n;
    uint32_t  signers;                /* K                                 */
    int       n_in, n_out;
    uint64_t  sum_in, fee, change, units;
} nodus_v2_msig_built_t;

/**
 * Build the UNSIGNED single-leg CORE SPEND (auth_kind 3, K zero slots, ONE
 * descriptor) from the named coins: inputs ascending by nullifier, out[0]
 * to `to_fp`, out[1] = the change back to the vault address (only when
 * non-zero); the fee fixed point of the CLI (at most 3 passes; a fixed fee
 * is never raised). The digest is the pass-1 preflight's leg auth digest.
 * @return NODUS_V2_SPEND_OK or a refusal (`err` may be NULL).
 */
int nodus_v2_msig_build(const nodus_v2_msig_build_req_t *req,
                        nodus_v2_msig_built_t *out,
                        nodus_v2_spend_err_t *err);

/** Free what nodus_v2_msig_build allocated inside `b`. NULL-safe. */
void nodus_v2_msig_built_free(nodus_v2_msig_built_t *b);

/* ── 3. the export text ─────────────────────────────────────────────── */

/** An export, parsed. `env` is heap (nodus_v2_msig_export_free). */
typedef struct {
    uint8_t  chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip;
    uint32_t signers;
    uint8_t  digest[64];
    uint8_t *env;
    size_t   env_len;
} nodus_v2_msig_export_t;

/** The export text (format above). *text_out is heap, NUL-terminated,
 *  *len_out excludes the NUL. @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  _ERR_ALLOC. */
int nodus_v2_msig_export_encode(const uint8_t chain32[DNA_CHAIN_ID_LEN],
                                uint64_t tip, uint32_t signers,
                                const uint8_t digest[64], const uint8_t *env,
                                size_t env_len, char **text_out,
                                size_t *len_out);

/** Parse an export text of `len` bytes (need not be NUL-terminated; at
 *  most 2 × DNA_ENV_MAX_TOTAL_LEN + 4096). On a refusal nothing is left
 *  allocated. @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC /
 *  NODUS_V2_MSIG_ERR_FORMAT. */
int nodus_v2_msig_export_parse(const char *text, size_t len,
                               nodus_v2_msig_export_t *x);

/** Free the envelope of a parsed export. NULL-safe. */
void nodus_v2_msig_export_free(nodus_v2_msig_export_t *x);

/* ── 4. the kind-3 leg of an export, and its digest ─────────────────── */

typedef struct {
    const uint8_t *desc;              /* points INTO the export's env      */
    size_t         desc_len;
    uint8_t        m, n;
    const uint8_t *keys;              /* points INTO desc                  */
} nodus_v2_msig_leg_t;

/** Exactly one CORE SPEND leg, auth_kind 3, `x->signers` signer slots and
 *  ONE valid descriptor filling the rest of the auth blob. `v` (heap it:
 *  dna_env_view_t is large) borrows x->env. @return NODUS_V2_SPEND_OK /
 *  _ERR_ARG / NODUS_V2_MSIG_ERR_SHAPE / NODUS_V2_MSIG_ERR_DESC. */
int nodus_v2_msig_leg_open(const nodus_v2_msig_export_t *x,
                           dna_env_view_t *v, nodus_v2_msig_leg_t *leg);

/** The CORE leg's ruleset_version of an envelope — the caller picks the
 *  CORE tuple of that version (nodus-cli cli_core_runtime_for_env; the
 *  wallet's pinned generations). @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  NODUS_V2_MSIG_ERR_RULESET. */
int nodus_v2_msig_core_version(const uint8_t *env, size_t env_len,
                               uint32_t *version_out);

/** The export's CORE leg digest, re-derived: dna_env_preflight on the
 *  export's envelope + chain id at tip + 1 with the given CORE tuple
 *  (heap `pf`). @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  NODUS_V2_SPEND_ERR_PREFLIGHT1 (wrong chain id, expired, another CORE
 *  ruleset). */
int nodus_v2_msig_digest(const nodus_v2_msig_export_t *x,
                         uint32_t core_version,
                         const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                         dna_env_preflight_t *pf);

/* ── 5. the co-signer's read-back (`msig sign`) ─────────────────────── */

/** What a co-signer is shown — every field READ BACK from the export's
 *  envelope bytes, never from anyone's description of them. */
typedef struct {
    uint8_t  addr[DNA_MSIG_ADDR_LEN]; /* the vault (address of the carried
                                       * descriptor)                       */
    uint8_t  m, n;
    uint32_t signers;
    uint64_t tip, expiry_height, fee;
    int      n_in;
    uint8_t  in_nul[NODUS_V2_SPEND_MAX_IN][64];
    int      n_out;
    char     out_owner[NODUS_V2_MSIG_MAX_OUTS][129];
    uint64_t out_amount[NODUS_V2_MSIG_MAX_OUTS];
    uint8_t  out_token[NODUS_V2_MSIG_MAX_OUTS][64];
    uint8_t  digest[64];
    uint8_t  intent_id[64];
} nodus_v2_msig_review_t;

/**
 * The checks `msig sign` makes before it signs, in its order: the leg
 * shape (nodus_v2_msig_leg_open); `signer_pk` (NULL = skip) is one of the
 * descriptor's keys; the digest re-derives (nodus_v2_msig_digest) and
 * EQUALS the exported one; the expiry is not 0 and not beyond the export's
 * tip + NODUS_V2_MSIG_EXPIRY_AHEAD (NODUS_V2_MSIG_ERR_EXPIRY); the SPEND
 * call is nin u8 (1..15) ‖ nin ×
 * nullifier ‖ nout u8 (1..NODUS_V2_MSIG_MAX_OUTS) ‖ nout × 232-byte
 * records with call_len exactly that — nothing is read before its length
 * is proved; every output owner is 128 lowercase hex characters.
 * `pf` is caller-provided heap scratch.
 * @return NODUS_V2_SPEND_OK / _ERR_ARG / NODUS_V2_MSIG_ERR_SHAPE / _DESC /
 *         _NOT_MEMBER / NODUS_V2_SPEND_ERR_PREFLIGHT1 / NODUS_V2_MSIG_ERR_
 *         DIGEST / _CALL / NODUS_V2_SPEND_ERR_HASH.
 */
int nodus_v2_msig_review(const nodus_v2_msig_export_t *x,
                         uint32_t core_version,
                         const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                         const uint8_t *signer_pk, dna_env_preflight_t *pf,
                         nodus_v2_msig_review_t *out);

/* ── 6. the signature text ──────────────────────────────────────────── */

/** The signature text (format above). *text_out heap, NUL-terminated.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC. */
int nodus_v2_msig_sig_encode(const uint8_t digest[64],
                             const uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                             const uint8_t sig[NODUS_V2_MSIG_SIG_LEN],
                             char **text_out, size_t *len_out);

/** Parse a signature text of `len` bytes (at most
 *  NODUS_V2_MSIG_SIG_TEXT_MAX). @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  _ERR_ALLOC / NODUS_V2_MSIG_ERR_FORMAT. */
int nodus_v2_msig_sig_parse(const char *text, size_t len, uint8_t digest[64],
                            uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                            uint8_t sig[NODUS_V2_MSIG_SIG_LEN]);

/* ── 7. the combine (`msig combine`) ────────────────────────────────── */

/** One signature against an opened export, in the CLI's per-file order:
 *  its digest equals the export's (else ERR_SIG_DIGEST), its key is one
 *  of the descriptor's (else ERR_NOT_MEMBER), it verifies (else ERR_SIG).
 *  @return NODUS_V2_SPEND_OK or that refusal / _ERR_ARG. */
int nodus_v2_msig_sig_check(const nodus_v2_msig_export_t *x,
                            const nodus_v2_msig_leg_t *leg,
                            const uint8_t digest[64],
                            const uint8_t pk[NODUS_V2_MSIG_PK_LEN],
                            const uint8_t sig[NODUS_V2_MSIG_SIG_LEN]);

/** Write the `n_sig` (== x->signers) CHECKED signatures into the export's
 *  signer slots in ascending pubkey order (the one canonical signer
 *  encoding); a key given twice is refused. `v` is the view of x->env
 *  from nodus_v2_msig_leg_open (the slots are written in place).
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / NODUS_V2_MSIG_ERR_COUNT /
 *          NODUS_V2_MSIG_ERR_DUP_SIGNER. */
int nodus_v2_msig_assemble(nodus_v2_msig_export_t *x,
                           const dna_env_view_t *v,
                           const uint8_t (*pks)[NODUS_V2_MSIG_PK_LEN],
                           const uint8_t (*sigs)[NODUS_V2_MSIG_SIG_LEN],
                           int n_sig);

/**
 * The whole combine for a caller that holds every signature: the exact-K
 * count, the leg, the digest re-derivation and equality, each signature
 * (nodus_v2_msig_sig_check, in order; *bad_index receives the failing
 * one, else -1), the assembly, and the pass-2 preflight self-check into
 * `pf` (its wire_id / intent_id are then the signed envelope's). On OK
 * x->env is the SIGNED envelope.
 * Does NOT run the chain's own auth hook (nodus-cli does that itself
 * after this call; a browser cannot link it): the node judges the
 * authorization again when the envelope arrives.
 */
int nodus_v2_msig_combine(nodus_v2_msig_export_t *x, uint32_t core_version,
                          const uint8_t core_hash[DNA_ENV_RULESET_HASH_LEN],
                          const uint8_t (*digests)[64],
                          const uint8_t (*pks)[NODUS_V2_MSIG_PK_LEN],
                          const uint8_t (*sigs)[NODUS_V2_MSIG_SIG_LEN],
                          int n_sig, dna_env_preflight_t *pf,
                          int *bad_index);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_MSIG_H */
