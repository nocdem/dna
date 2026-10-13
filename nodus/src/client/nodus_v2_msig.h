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
 * THE TWO v2 TEXT FORMATS (decision 2026-09-29-general-multisig.md, addendum
 * "çok bacaklı ortak imza dosyası v2", operator 2026-10-13 "1 ile devam
 * edelim") — ONLY for an envelope with >= 2 kind-3 legs (the HF-6 owner
 * operations: a SYSTEM record leg that proves the owner and a CORE SYSFUND
 * leg that spends the address's coins, each with its OWN leg auth digest,
 * shared/dnac/env_preflight.c step 8). The v1 formats above are unchanged
 * and stay the single-leg SPEND's:
 *   export v2: "nodus-msig-export v2\n" "chain_id <64 hex>\n" "tip <dec>\n"
 *              "signers <dec>\n" "digests <k>\n"
 *              k × "digest <leg_index> <128 hex>\n" (leg_index strictly
 *              ascending) "envelope <hex>\n"
 *   sig v2:    "nodus-msig-sig v2\n" "pubkey <5184 hex>\n"
 *              k × ("digest <leg_index> <128 hex>\n"
 *                   "sig <leg_index> <9254 hex>\n")
 * Unlike v1 (whose keys are looked up anywhere) a v2 file is read
 * STRICTLY in this line order — its "digest" key repeats — with nothing
 * before, between or after the lines and a final newline; decimals as v1.
 * A co-signer signs EVERY digest or nothing (one signature file carries
 * all k), and the combine re-derives every digest and assembles every
 * kind-3 leg.
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
#include "client/nodus_v2_stake.h"  /* v2: the owner operation read back
                                     * (nodus_v2_stake_decode)             */

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_V2_MSIG_EXPORT_MAGIC "nodus-msig-export v1"
#define NODUS_V2_MSIG_SIG_MAGIC    "nodus-msig-sig v1"
/* The v2 (multi-leg) magics — see "THE TWO v2 TEXT FORMATS". */
#define NODUS_V2_MSIG_EXPORT2_MAGIC "nodus-msig-export v2"
#define NODUS_V2_MSIG_SIG2_MAGIC    "nodus-msig-sig v2"
/** The digests a v2 file carries: one per kind-3 leg, at least 2 (one leg
 *  is the v1 shape) and at most the envelope's own leg bound. */
#define NODUS_V2_MSIG2_MIN_LEGS  2u
#define NODUS_V2_MSIG2_MAX_LEGS  ((uint32_t)DNA_ENV_MAX_LEGS)

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
/** The largest v2 signature text: magic + pubkey line + one digest line
 *  and one sig line per leg (each line bounded generously by 32 bytes of
 *  key, index and separators plus its hex). */
#define NODUS_V2_MSIG_SIG2_TEXT_MAX                                        \
    (32u + 2u * NODUS_V2_MSIG_PK_LEN + 32u +                              \
     NODUS_V2_MSIG2_MAX_LEGS * (2u * 32u + 128u + 2u * NODUS_V2_MSIG_SIG_LEN))
/** The largest v2 export text: the v1 bound plus the digest lines. */
#define NODUS_V2_MSIG_EXPORT2_TEXT_MAX                                     \
    (2u * (size_t)DNA_ENV_MAX_TOTAL_LEN + 4096u +                         \
     (size_t)NODUS_V2_MSIG2_MAX_LEGS * (32u + 128u))

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
    NODUS_V2_MSIG_ERR_EXPIRY      = -74, /* expiry 0, or past the export's
                                          * tip + NODUS_V2_MSIG_EXPIRY_AHEAD*/
    NODUS_V2_MSIG_ERR_HORIZON     = -75  /* judged against the NODE's
                                          * height (nodus_v2_msig_horizon):
                                          * expired, valid past node +
                                          * EXPIRY_AHEAD, or the node more
                                          * than EXPIRY_AHEAD behind the
                                          * export's tip                  */
} nodus_v2_msig_rc_t;

/**
 * The signing horizon judged against the height of the co-signer's OWN
 * node (2026-10-13, red-team round 3 — `msig sign` takes it from the
 * pinned session's dnac_msig_utxo answer, "block_height"), not against the
 * export's own `tip`, which its author chose. With H = node_height (the
 * last committed block; the envelope runs at H + 1 or later):
 *   expiry_height <= H                         → expired: nothing to sign
 *   expiry_height >  H + NODUS_V2_MSIG_EXPIRY_AHEAD
 *                                              → the signature would stay
 *     usable longer than any builder makes from the present — an export
 *     whose tip was set into the future (review / review2 check expiry
 *     only against that tip) would otherwise yield a signature that waits
 *     to be submitted later;
 *   export_tip    >  H + NODUS_V2_MSIG_EXPIRY_AHEAD
 *                                              → the node is that far
 *     behind the builder: its coin set (the input check) is not the one the
 *     export was built on.
 * (H − export_tip > EXPIRY_AHEAD needs no rule of its own: the export's
 * expiry is <= tip + EXPIRY_AHEAD < H, the first line.) One constant, the
 * read-back's own window (mempool cap 100 − the 10-block gossip margin),
 * so the node-side window and the export-side window are the same size.
 * Pure. @return NODUS_V2_SPEND_OK / NODUS_V2_MSIG_ERR_HORIZON /
 *         NODUS_V2_SPEND_ERR_ARG (a height near UINT64_MAX).
 */
int nodus_v2_msig_horizon(uint64_t export_tip, uint64_t expiry_height,
                          uint64_t node_height);

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
 * It does NOT prove that the inputs are the vault's coins (the descriptor
 * is outside the signed context — a descriptor of the same length can be
 * swapped in after signing): the caller checks every input against the
 * vault's own coin set before it signs (nodus-cli `msig sign`, through
 * dnac_msig_utxo — khan decision 2026-10-13-kurultay-18-summary.md item 5).
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
 *  from nodus_v2_msig_leg_open (the slots are written in place, so the
 *  leg's auth blob must already be at least 1 + n_sig ×
 *  NODUS_RT_AUTH_SIGNER_LEN bytes with its count byte == n_sig — else
 *  ERR_ARG, nothing written).
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

/* ══ v2 — the multi-leg kind-3 envelope (the HF-6 owner operations) ════
 * Decision 2026-09-29-general-multisig.md, addendum "çok bacaklı ortak
 * imza dosyası v2". The unsigned envelope comes from nodus_v2_stake_build
 * with req->msig_desc (client/nodus_v2_stake.h "KIND-3 OWNER"); its two
 * leg digests are out->leg_digest. Every function below refuses an
 * envelope in which any leg is NOT auth_kind 3 (such a leg needs its own
 * signer, which these files do not carry) or whose kind-3 legs do not all
 * carry the same K and the same ONE descriptor. */

/** A v2 export, parsed (or to encode). `env` is heap after a parse
 *  (nodus_v2_msig_export2_free). */
typedef struct {
    uint8_t  chain32[DNA_CHAIN_ID_LEN];
    uint64_t tip;
    uint32_t signers;                             /* K                    */
    uint32_t n_digests;                           /* k, one per kind-3 leg*/
    uint16_t leg_index[NODUS_V2_MSIG2_MAX_LEGS];  /* strictly ascending   */
    uint8_t  digest[NODUS_V2_MSIG2_MAX_LEGS][64];
    uint8_t *env;
    size_t   env_len;
} nodus_v2_msig_export2_t;

/** A v2 signature: ONE key's signature over EVERY digest of an export.
 *  Large (~300 KB at the leg bound): heap-allocate it. */
typedef struct {
    uint8_t  pk[NODUS_V2_MSIG_PK_LEN];
    uint32_t n;
    uint16_t leg_index[NODUS_V2_MSIG2_MAX_LEGS];
    uint8_t  digest[NODUS_V2_MSIG2_MAX_LEGS][64];
    uint8_t  sig[NODUS_V2_MSIG2_MAX_LEGS][NODUS_V2_MSIG_SIG_LEN];
} nodus_v2_msig_sig2_t;

/** The v2 export text. Refuses (ERR_ARG) k outside [NODUS_V2_MSIG2_MIN_LEGS,
 *  NODUS_V2_MSIG2_MAX_LEGS], a leg_index not strictly ascending or >=
 *  the leg bound, K outside [1, NODUS_RT_AUTH_MAX_SIGNERS], an empty or
 *  oversized envelope. *text_out heap, NUL-terminated, *len_out excludes
 *  the NUL. @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC. */
int nodus_v2_msig_export2_encode(const nodus_v2_msig_export2_t *x,
                                 char **text_out, size_t *len_out);

/** Parse exactly the v2 export text (strict line order, final newline,
 *  nothing else; the encoder's bounds). On a refusal nothing is left
 *  allocated. @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC /
 *  NODUS_V2_MSIG_ERR_FORMAT. */
int nodus_v2_msig_export2_parse(const char *text, size_t len,
                                nodus_v2_msig_export2_t *x);

/** Free the envelope of a v2 export. NULL-safe. */
void nodus_v2_msig_export2_free(nodus_v2_msig_export2_t *x);

/** The v2 signature text (same bounds as the export's k and indices).
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC. */
int nodus_v2_msig_sig2_encode(const nodus_v2_msig_sig2_t *s,
                              char **text_out, size_t *len_out);

/** Parse exactly the v2 signature text (at most
 *  NODUS_V2_MSIG_SIG2_TEXT_MAX bytes; strict line order). On a refusal `s`
 *  is zeroed. @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  NODUS_V2_MSIG_ERR_FORMAT. */
int nodus_v2_msig_sig2_parse(const char *text, size_t len,
                             nodus_v2_msig_sig2_t *s);

/** The kind-3 legs of a v2 export: EVERY leg is auth_kind 3; their indices
 *  are exactly x->leg_index (k = x->n_digests >= 2, == leg_count); each
 *  blob is K = x->signers slots ‖ dcount 1 ‖ dlen ‖ a descriptor that
 *  dna_msig_desc_parse accepts, consumed exactly, and every leg carries
 *  the SAME descriptor bytes. `leg` describes that descriptor (pointing
 *  into the first leg). `v` (heap) borrows x->env.
 *  @return NODUS_V2_SPEND_OK / _ERR_ARG / NODUS_V2_MSIG_ERR_SHAPE /
 *  NODUS_V2_MSIG_ERR_DESC. */
int nodus_v2_msig_legs_open2(const nodus_v2_msig_export2_t *x,
                             dna_env_view_t *v, nodus_v2_msig_leg_t *leg);

/** Every leg digest of the export, re-derived: dna_env_preflight on its
 *  envelope + chain id at tip + 1 with `lctx` (n_lctx entries, POSITIONAL
 *  per leg — env_preflight.h — the caller resolves each leg's (domain,
 *  ruleset_version) to its compiled or pinned tuple). Writes `pf`; the
 *  caller compares pf->auth_digest[leg_index]. @return NODUS_V2_SPEND_OK /
 *  _ERR_ARG / NODUS_V2_SPEND_ERR_PREFLIGHT1. */
int nodus_v2_msig_digests2(const nodus_v2_msig_export2_t *x,
                           const dna_env_leg_ctx_t *lctx, uint16_t n_lctx,
                           dna_env_preflight_t *pf);

/** What a v2 co-signer is shown — every field READ BACK from the envelope
 *  bytes (decision addendum: the SYSTEM call decoded — op, validator_id,
 *  owner, amount / commission / consensus key — and the CORE funding — inputs,
 *  outputs, fee). */
typedef struct {
    uint8_t  addr[DNA_MSIG_ADDR_LEN];   /* the owner multisig address     */
    uint8_t  m, n;
    uint32_t signers;
    uint64_t tip, expiry_height, fee;
    uint32_t n_digests;
    uint16_t leg_index[NODUS_V2_MSIG2_MAX_LEGS];
    uint8_t  digest[NODUS_V2_MSIG2_MAX_LEGS][64];
    uint8_t  intent_id[64];
    nodus_v2_stake_decoded_t op;        /* the owner operation: the SYSTEM
                                         * call and the CORE funding
                                         * (nodus_v2_stake_decode)        */
} nodus_v2_msig_review2_t;

/**
 * The checks `msig sign` makes on a v2 export before it signs, in order:
 * the legs (nodus_v2_msig_legs_open2); `signer_pk` (NULL = skip) is one
 * of the descriptor's keys (ERR_NOT_MEMBER); every digest re-derives and
 * EQUALS the exported one (ERR_DIGEST — never sign a digest you did not
 * derive); the expiry window of v1 (ERR_EXPIRY); the envelope reads back
 * as an owner operation of client/nodus_v2_stake.h — two legs, a
 * generation-4 layout, kind 3 on both, its owner the descriptor's address
 * (ERR_CALL otherwise: the only multi-leg kind-3 envelopes this library
 * signs are the HF-6 owner operations — op 10, the removed ROTATE, is
 * none), and a change output, if any, goes to that address (hex) — else
 * ERR_CALL (HF-6 D2). It does NOT prove that the funding inputs are the
 * vault's coins: the descriptor is outside the signed context, so the
 * caller must check every input against the vault's own coin set before
 * signing (nodus-cli `msig sign` does, through dnac_msig_utxo — khan
 * decision 2026-10-13-kurultay-18-summary.md item 5). `pf` is heap
 * scratch.
 * @return NODUS_V2_SPEND_OK / _ERR_ARG / _ERR_ALLOC / NODUS_V2_MSIG_ERR_SHAPE
 *         / _DESC / _NOT_MEMBER / NODUS_V2_SPEND_ERR_PREFLIGHT1 /
 *         NODUS_V2_MSIG_ERR_DIGEST / _EXPIRY / _CALL / NODUS_V2_SPEND_ERR_HASH.
 */
int nodus_v2_msig_review2(const nodus_v2_msig_export2_t *x,
                          const dna_env_leg_ctx_t *lctx, uint16_t n_lctx,
                          const uint8_t *signer_pk, dna_env_preflight_t *pf,
                          nodus_v2_msig_review2_t *out);

/** One v2 signature against an opened export: it carries exactly the
 *  export's leg indices and digests (else ERR_SIG_DIGEST — a file that
 *  signs some legs and not others is refused: all or nothing), its key is
 *  one of the descriptor's (else ERR_NOT_MEMBER), and every signature
 *  verifies over its digest (else ERR_SIG). @return NODUS_V2_SPEND_OK or
 *  that refusal / _ERR_ARG. */
int nodus_v2_msig_sig2_check(const nodus_v2_msig_export2_t *x,
                             const nodus_v2_msig_leg_t *leg,
                             const nodus_v2_msig_sig2_t *s);

/** Write the `n_sig` (== x->signers) signatures into EVERY kind-3 leg's
 *  slots, ascending by public key (the one canonical signer encoding),
 *  digest j's signature into leg x->leg_index[j]; a key given twice is
 *  refused. Like nodus_v2_msig_assemble it does not judge the signatures
 *  (nodus_v2_msig_sig2_check does). `v` is the view from
 *  nodus_v2_msig_legs_open2. Every target leg's auth blob must already
 *  be at least 1 + n_sig × NODUS_RT_AUTH_SIGNER_LEN bytes with its count
 *  byte == n_sig (the slots are written in place) — else ERR_ARG, nothing
 *  written. @return NODUS_V2_SPEND_OK / _ERR_ARG /
 *  NODUS_V2_MSIG_ERR_COUNT / NODUS_V2_MSIG_ERR_DUP_SIGNER. */
int nodus_v2_msig_assemble2(nodus_v2_msig_export2_t *x,
                            const dna_env_view_t *v,
                            const nodus_v2_msig_sig2_t *const *sigs,
                            int n_sig);

/**
 * The whole v2 combine: the legs, the exact-K count (ERR_COUNT), every
 * digest re-derived and equal (ERR_DIGEST), each signature
 * (nodus_v2_msig_sig2_check, in order; *bad_index receives the failing
 * one, else -1), the assembly, and the pass-2 preflight self-check into
 * `pf` (its wire_id / intent_id are then the signed envelope's). On OK
 * x->env is the SIGNED envelope. Does NOT run the chain's own auth hook
 * per leg (nodus-cli does, after this call; a browser cannot link it).
 */
int nodus_v2_msig_combine2(nodus_v2_msig_export2_t *x,
                           const dna_env_leg_ctx_t *lctx, uint16_t n_lctx,
                           const nodus_v2_msig_sig2_t *const *sigs,
                           int n_sig, dna_env_preflight_t *pf,
                           int *bad_index);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_V2_MSIG_H */
