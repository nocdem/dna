/**
 * @file shared/dnac/res_meter.h
 * @brief Ledger V2 — deterministic resource METERING + RESERVATION
 *        boundary (INACTIVE).
 *
 * This module turns an ENGINE-SUPPLIED metering-policy snapshot plus a
 * decoded envelope view into a typed, immutable RESERVATION PLAN, and
 * meters the transaction's ACTUAL resource consumption against that plan
 * through an explicit lifecycle state machine, with global and per-domain
 * block-budget accounting.
 *
 * ACTIVATION: INACTIVE. No live consensus path calls anything here. The
 * active chain keeps the legacy V2 wire, the v3 five-input state_root and
 * the V1 block hash byte-identical; Type 11 stays REJECT. This module
 * activates only with the Ledger V2 devnet reset.
 *
 * ── AUTHORITY MODEL (the whole point of the file) ─────────────────────
 *
 * 1. PRICES COME FROM THE POLICY SNAPSHOT, NOWHERE ELSE. Every unit
 *    charged or reserved is computed from an engine-supplied
 *    dna_meter_policy_t. No function in this header accepts a
 *    caller-provided cost value: there is no "units" parameter anywhere a
 *    transaction, an envelope byte, or a runtime could inject a price
 *    through. The envelope's resource fields (res_max_total_units,
 *    res_max_effects, res_max_effect_bytes — env_wire.h:52,64-65) are
 *    CEILINGS the signer is willing to reserve/permit, never prices; they
 *    bound the reservation, they do not choose the weights.
 *
 * 2. THE POLICY IS A BLOCK-START SNAPSHOT. It is intended to be derived,
 *    by a later season, from committed block-start chain configuration —
 *    the same immutable-snapshot discipline as the committee authority
 *    (nodus_witness_committee.c: per-epoch frozen snapshot, never a live
 *    recomputation). This season the engine hands an explicit policy
 *    object to the inactive seam; nothing loads it from consensus state
 *    yet, and nothing may populate it from transaction bytes ever.
 *
 * 3. THE POLICY IS SELF-CHECKING. dna_meter_policy_seal computes a
 *    SHA3-512 seal over the canonical serialization of every weight;
 *    dna_meter_policy_check recomputes and compares it. A policy mutated
 *    after sealing — by a runtime, a stray write, anything — fails the
 *    check and every consumer rejects. HONEST LABEL: the seal is a LOCAL
 *    INTEGRITY CHECKSUM. It is never serialized to any wire, never enters
 *    any consensus commitment, and claims nothing cryptographic beyond
 *    tamper-evidence of an in-memory struct. The CONSENSUS identity of a
 *    policy is the SEPARATE dna_meter_policy_digest below (its own tag,
 *    seal field excluded) — that digest, not the seal, is what a ruleset
 *    descriptor commits (domain_wire.h meter_policy_digest).
 *
 * 4. THE LEGACY tx_cost RUNTIME HOOK IS NOT AN AUTHORITY HERE. The
 *    nodus_rt_cost_fn hook (nodus_witness_runtime.h) declares
 *    per-tx-TYPE work units for the pre-envelope admission surface
 *    (nodus_witness_domreg.c admission — the raw-SQL op scaffold that
 *    also consumed it is retired). The envelope lane is keyed by
 *    runtime_op and priced ONLY by
 *    this policy's w_op table; tx_cost is never consulted by anything in
 *    this module, and this module never overrides tx_cost's inactive
 *    legacy surface. One lane, one authority each — the hook migration
 *    that retires tx_cost belongs to a later season.
 *
 * ── UNITS AND THE RESERVATION FORMULA (locked) ────────────────────────
 * Every weight is denominated in one abstract `unit` (u64). All
 * arithmetic is CHECKED u64 (dna_ck_*): overflow REJECTS with a typed
 * status — never wraps, never saturates, never clamps, never converts to
 * a signed or narrower type.
 *
 *   static_units(leg) =
 *         w_op[runtime_op]
 *       + w_callbyte   * call_len
 *       + w_authbyte   * auth_len
 *       + w_effect     * res_max_effects
 *       + w_effectbyte * res_max_effect_bytes
 *
 *   static_units(envelope) = w_base + Σ static_units(leg)
 *
 * Plan build REJECTS when: the policy fails its self-check; a leg's
 * runtime_op has no AUTHORITATIVE weight (presence is explicit — a
 * weight of 0 is a legal price, an absent weight is not); a declared
 * res_max_effects exceeds the effect codec's versioned count cap
 * (DNA_EFFECT_MAX_COUNT) or res_max_effect_bytes exceeds its versioned
 * total-size cap (DNA_EFFECT_MAX_TOTAL_LEN); any product or sum
 * overflows; or static_units(envelope) > res_max_total_units.
 *
 * ── GLOBAL vs PER-DOMAIN ACCOUNTING (the envelope-v1 limitation) ──────
 * res_max_total_units is the GLOBAL transaction reservation ceiling:
 * reserve takes the FULL ceiling from the global block budget, so every
 * later charge has deterministic headroom and the transaction's total
 * actual units can never exceed it.
 *
 * Envelope v1 carries NO per-leg total-unit ceiling (env_wire.h — adding
 * one would be a new envelope version, out of scope), so per-domain
 * dynamic read/write charges cannot be fully known at preflight. The
 * HONEST DETERMINISTIC RULE this module implements:
 *   - each leg's domain starts with exactly its static_units(leg)
 *     reservation, taken from that domain's block budget at reserve;
 *   - actual charges to a domain first consume that reserved amount;
 *   - a charge exceeding it claims the excess from the domain's
 *     REMAINING block budget at charge time — deterministically, and
 *     failure to claim is a typed rejection (the caller aborts);
 *   - unused reservation is released deterministically at finalize;
 *   - no domain ever borrows from another domain's budget;
 *   - the global ceiling bounds the sum regardless.
 * This is a documented limitation, not a hidden rule: no per-leg wire
 * field is invented and no slack-allocation heuristic exists.
 *
 * ── ACTUAL CHARGING (what is charged, from where) ─────────────────────
 *   activate (RESERVED → ACTIVE) charges the deterministic fixed work:
 *     w_base once per envelope       — GLOBAL only (no authoring domain);
 *     per leg, to that leg's domain: w_op + w_callbyte * call_len
 *                                    + w_authbyte * auth_len.
 *     Whole-envelope activation is equivalent to per-invoked-leg
 *     charging: an admitted envelope either executes all its legs or the
 *     transaction aborts and every reservation is restored — there is no
 *     partial-leg outcome in the apply engine's one-transaction model.
 *   charge_effects charges w_effect * ACTUAL effect_count plus
 *     w_effectbyte * the ACTUAL CANONICAL ENCODED RESULT LENGTH — the
 *     res_len of a strictly-decoded dna_effect_view_t, i.e. the full
 *     effect_wire encoding including its fixed head and records. That is
 *     THE pinned meaning of "effect bytes": deterministic, bounded by
 *     DNA_EFFECT_MAX_TOTAL_LEN, and identical on every node that decoded
 *     the same result. Declared per-leg ceilings gate it: actual count or
 *     bytes above the leg's declaration is a typed rejection. One result
 *     per leg — a second effect charge on the same leg rejects.
 *   charge_read / charge_write charge w_read / w_write once per call —
 *     the interfaces later mediated-read/adapter seasons will invoke;
 *     NOTHING wires them into any hook this season.
 *
 * Every charge names its authoring domain explicitly, updates global and
 * domain accounting together, fails BEFORE overflow or exhaustion (all
 * new values are computed into temporaries and committed atomically — a
 * failed charge leaves the meter AND the budget byte-identical), and no
 * charge path accepts a caller-supplied unit count.
 *
 * HONEST LABEL: a READ-access leg (DNA_ENV_ACCESS_READ) is priced by the
 * same formula as an INVOKE leg — this module prices framed declarations;
 * whether a READ leg may declare effects at all is an admission rule for
 * a later season, not a metering rule.
 *
 * ── LIFECYCLE STATE MACHINE (enforced, not commented) ─────────────────
 *
 *   ZERO ──reserve──▶ RESERVED ──activate──▶ ACTIVE ──finalize──▶ FINALIZED
 *                        │                     │
 *                        └───────abort─────────┴──abort──▶ ABORTED
 *
 *   - reserve requires a ZEROED meter (state ZERO); reserving twice,
 *     charging before reserve, finalizing or aborting from ZERO all
 *     reject with DNA_METER_ERR_STATE;
 *   - charges require ACTIVE; FINALIZED and ABORTED are terminal —
 *     charging, finalizing or aborting again all reject (no double
 *     release, no double refund, no charge-after-terminal);
 *   - finalize releases unused units back to the budgets:
 *     globally  total_ceiling − consumed;
 *     per domain (static + dynamic claims) − consumed;
 *   - abort restores EVERYTHING the transaction took from the budgets
 *     (the ceiling globally; static + dynamic claims per domain);
 *   - an accounting step that would underflow, or restore more than was
 *     taken, is DNA_METER_ERR_FAULT — an INVARIANT fault of this node's
 *     accounting, never a transaction verdict (the env_preflight.h
 *     ERR_HASH discipline), and it commits nothing.
 *
 * ── PURITY ────────────────────────────────────────────────────────────
 * No database, no allocation, no clock, no RNG, no environment, no
 * global or static state. The one non-arithmetic dependency is
 * qgp_sha3_512 for the policy seal. Two nodes handed the same policy,
 * the same envelope view and the same budget view produce byte-identical
 * plans, meters and budget mutations.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DNAC_RES_METER_H
#define SHARED_DNAC_RES_METER_H

#include <stdint.h>
#include <stddef.h>

#include "env_wire.h"
#include "effect_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Checked u64 arithmetic (the ONE shared discipline) ─────────────────
 * All three: 0 on success with *out written; -1 on overflow/underflow
 * with *out set to 0 FIRST (a failed result is never usable); -1 on a
 * NULL out. No wraparound, no saturation, no clamping, no signed or
 * narrowing conversion anywhere. */
int dna_ck_add_u64(uint64_t a, uint64_t b, uint64_t *out);
int dna_ck_mul_u64(uint64_t a, uint64_t b, uint64_t *out);
/** a - b; b > a is UNDERFLOW (-1). */
int dna_ck_sub_u64(uint64_t a, uint64_t b, uint64_t *out);

/* ── Policy snapshot ───────────────────────────────────────────────── */

/** Only policy version this release seals or accepts.
 *
 *  v2 (capacity season) APPENDS `max_block_env_bytes` — the ABSOLUTE
 *  per-block Ledger V2 envelope byte bound — to the struct and to both
 *  canonical preimages (seal + identity digest, field order below). v1
 *  is RETIRED, the RulesetDescriptor v2 precedent (domain_wire.h:264):
 *  Ledger V2 is inactive, no committed v1 policy digest exists anywhere,
 *  and an ambiguous dual-version decode would be a hidden reinterpration
 *  surface. A v1 struct no longer seals, checks or digests. */
#define DNA_METER_POLICY_VERSION  2

/** Weight-table index space == the envelope's accepted runtime_op range
 *  (DNA_ENV_MAX_RUNTIME_OP, env_wire.h — ops 0..255 inclusive; cited by
 *  symbol, not line: the header grows). */
#define DNA_METER_OP_SPACE        (DNA_ENV_MAX_RUNTIME_OP + 1)

/** Presence-mask words: DNA_METER_OP_SPACE bits in u64 words. */
#define DNA_METER_OP_MASK_WORDS   (DNA_METER_OP_SPACE / 64)
_Static_assert(DNA_METER_OP_SPACE % 64 == 0,
               "op presence mask requires a 64-divisible op space");

/**
 * The immutable block-start metering-policy snapshot.
 *
 * Populate every field, set the presence bit for every runtime_op that
 * has an AUTHORITATIVE weight (dna_meter_op_set), then SEAL. Consumers
 * verify the seal before pricing anything. An op whose presence bit is
 * clear has NO weight — not a zero one — and any envelope invoking it
 * rejects (fail-closed; a zeroed struct prices nothing).
 *
 * Weights are NOT production economics this season: activation-time
 * values are derived from committed chain configuration by a later
 * season. The interface, arithmetic and authority model are what this
 * release locks.
 */
typedef struct {
    uint32_t policy_version;                     /* DNA_METER_POLICY_VERSION */
    uint64_t w_base;                             /* once per envelope        */
    uint64_t w_callbyte;                         /* per call-data byte       */
    uint64_t w_authbyte;                         /* per auth-data byte       */
    uint64_t w_effect;                           /* per effect record        */
    uint64_t w_effectbyte;                       /* per canonical result byte*/
    uint64_t w_read;                             /* per mediated read        */
    uint64_t w_write;                            /* per mediated write       */
    /* v2 (capacity season): the ABSOLUTE per-block V2 envelope byte
     * bound — sum(env_len) of every envelope in one global block must
     * fit under it (INCLUSIVE), checked with dna_ck_add_u64 BEFORE any
     * reservation (nodus_witness_v2_env.c). NOT a unit weight and NOT a
     * substitute for the unit budget: it caps raw admitted WIRE BYTES so
     * a block cannot carry the 1 MiB envelope maximum
     * (DNA_ENV_MAX_TOTAL_LEN) repeatedly up to the transaction-count
     * cap, whatever the unit economics say. 0 is INVALID — a zeroed
     * struct admits no block (fail-closed); seal/check/digest all
     * reject it. */
    uint64_t max_block_env_bytes;
    uint64_t w_op[DNA_METER_OP_SPACE];           /* per-op weight            */
    uint64_t op_present[DNA_METER_OP_MASK_WORDS];/* authoritative-weight bits*/
    uint8_t  seal[64];                           /* SHA3-512, see seal()     */
} dna_meter_policy_t;

/** Declare runtime_op authoritative with weight w (pre-seal helper).
 *  @return 0 / -1 (NULL p, op out of range). */
int dna_meter_op_set(dna_meter_policy_t *p, uint32_t runtime_op, uint64_t w);

/**
 * Seal the policy: seal = SHA3-512( "DNA.METPOL.v1"(16, zero-padded)
 *   ‖ policy_version u32 BE ‖ w_base ‖ w_callbyte ‖ w_authbyte
 *   ‖ w_effect ‖ w_effectbyte ‖ w_read ‖ w_write
 *   ‖ max_block_env_bytes (u64 BE each — v2 appends the byte bound HERE,
 *   directly after the scalar weights, before the op table)
 *   ‖ w_op[0..255] (u64 BE each) ‖ op_present[0..3] (u64 BE each) ).
 * Preimage is exactly 16 + 4 + 8*8 + 256*8 + 4*8 = 2164 bytes, built in
 * a stack buffer. Rejects (-1): NULL p, policy_version not accepted,
 * max_block_env_bytes == 0 (an unbounded-block policy must not even
 * seal). The tag deliberately stays "DNA.METPOL.v1": the version FIELD
 * inside the preimage is the discriminator, and no v1 preimage was ever
 * committed anywhere (Ledger V2 inactive).
 * HONEST LABEL: local integrity checksum only — never wire-serialized,
 * never part of any consensus commitment.
 */
int dna_meter_policy_seal(dna_meter_policy_t *p);

/** Verify version + recompute the seal. @return 0 valid / -1 invalid. */
int dna_meter_policy_check(const dna_meter_policy_t *p);

/**
 * The policy IDENTITY digest — the value a consensus structure commits
 * when it binds itself to one exact metering policy (Ledger V2: the
 * RulesetDescriptor's meter_policy_digest field, domain_wire.h):
 *
 *   digest = SHA3-512( "DNA.METPOLID.v1"(16, zero-padded)
 *     ‖ policy_version u32 BE ‖ w_base ‖ w_callbyte ‖ w_authbyte
 *     ‖ w_effect ‖ w_effectbyte ‖ w_read ‖ w_write
 *     ‖ max_block_env_bytes (u64 BE each — the v2 field, same position
 *     as in the seal preimage) ‖ w_op[0..255] (u64 BE each)
 *     ‖ op_present[0..3] (u64 BE each) )
 *
 * Same canonical field serialization as the seal, DIFFERENT tag, and the
 * seal field is NOT part of the preimage: the digest identifies the
 * WEIGHTS, independently of whether or when the in-memory struct was
 * sealed. Two policies with identical weights have one identity; any
 * weight or presence-bit difference changes it. Unlike the seal, this
 * value MAY enter consensus commitments — committing it is exactly how
 * "two validators claiming the same ruleset identity cannot price
 * differently" becomes structural.
 *
 * Rejects (-1): NULL p or out, policy_version not accepted; `out` is
 * untouched on every reject this module decides (the dna_effect_value_hash
 * backend-fault caveat applies here too).
 * @return 0 / -1.
 */
int dna_meter_policy_digest(const dna_meter_policy_t *p, uint8_t out[64]);

/** Authoritative weight lookup. @return 0 with *w_out set; -1 when the
 *  op is out of range or its presence bit is clear (*w_out zeroed). */
int dna_meter_op_weight(const dna_meter_policy_t *p, uint32_t runtime_op,
                        uint64_t *w_out);

/* ── Block budget view ─────────────────────────────────────────────── */

/** Largest per-domain budget table. Mirrors the shipped per-transaction
 *  64-caps: DNA_ENV_MAX_LEGS (env_wire.h) and DNA_TOUCHED_MAX
 *  (domain_wire.h). */
#define DNA_METER_MAX_DOMAINS  DNA_ENV_MAX_LEGS

typedef struct {
    uint32_t domain_id;
    uint64_t remaining_units;
} dna_meter_domain_budget_t;

/**
 * The engine-owned remaining-budget view for one candidate block.
 * `dom` must be STRICTLY ascending by domain_id (duplicates and
 * descending both reject — a duplicate entry makes the authority for
 * that domain ambiguous, dna_meter_budget_check). Mutated ONLY by
 * reserve / finalize / abort, atomically.
 */
typedef struct {
    uint64_t global_remaining;
    uint16_t n_domains;                 /* 0 .. DNA_METER_MAX_DOMAINS    */
    dna_meter_domain_budget_t dom[DNA_METER_MAX_DOMAINS];
} dna_meter_budget_t;

/** Structural check: n_domains in range, strictly ascending domain_id.
 *  @return 0 / -1. */
int dna_meter_budget_check(const dna_meter_budget_t *b);

/* ── Typed statuses ────────────────────────────────────────────────── */
typedef enum {
    DNA_METER_OK                = 0,
    DNA_METER_ERR_ARG           = 1,  /* NULL/malformed argument          */
    DNA_METER_ERR_POLICY        = 2,  /* policy failed its self-check     */
    DNA_METER_ERR_OP_WEIGHT     = 3,  /* runtime_op has no authoritative
                                       * weight (presence bit clear)      */
    DNA_METER_ERR_DECL          = 4,  /* declared effect count/bytes
                                       * exceed the codec's versioned caps*/
    DNA_METER_ERR_OVERFLOW      = 5,  /* checked arithmetic overflow      */
    DNA_METER_ERR_CEILING       = 6,  /* static > declared ceiling, or an
                                       * actual charge would cross it     */
    DNA_METER_ERR_GLOBAL_BUDGET = 7,  /* ceiling > remaining global budget*/
    DNA_METER_ERR_DOMAIN_BUDGET = 8,  /* domain budget cannot cover the
                                       * static reservation / dyn claim   */
    DNA_METER_ERR_DOMAIN        = 9,  /* missing / duplicate / unknown
                                       * domain-budget entry              */
    DNA_METER_ERR_LIMIT         = 10, /* actual effects exceed the leg's
                                       * DECLARED ceilings                */
    DNA_METER_ERR_STATE         = 11, /* lifecycle transition violation   */
    DNA_METER_ERR_FAULT         = 12  /* accounting invariant broken —
                                       * NODE fault, never a tx verdict   */
} dna_meter_status_t;

/* ── Reservation plan ──────────────────────────────────────────────── */

typedef struct {
    uint32_t domain_id;
    uint32_t runtime_op;
    uint64_t static_units;         /* this leg's per-domain reservation  */
    uint64_t fixed_units;          /* w_op + w_callbyte*call_len
                                    * + w_authbyte*auth_len (activate)   */
    uint32_t res_max_effects;      /* declared per-leg ceilings, copied  */
    uint32_t res_max_effect_bytes; /* from the envelope (charge gates)   */
} dna_meter_leg_plan_t;

/**
 * The immutable reservation plan for ONE envelope. Self-contained: the
 * charge-time weights (w_effect / w_effectbyte / w_read / w_write) are
 * PINNED into the plan at build time, so no later policy mutation — and
 * no second policy — can reprice a transaction mid-flight.
 */
typedef struct {
    uint64_t total_ceiling;        /* res_max_total_units (global resv.) */
    uint64_t static_total;         /* base_units + Σ leg static_units    */
    uint64_t base_units;           /* w_base                             */
    uint64_t w_effect, w_effectbyte, w_read, w_write; /* pinned          */
    uint16_t n_legs;               /* 1 .. DNA_ENV_MAX_LEGS              */
    dna_meter_leg_plan_t leg[DNA_ENV_MAX_LEGS];
} dna_meter_plan_t;

/**
 * PURE reservation calculation: policy x decoded view -> plan. Touches
 * no budget and mutates nothing but *out. Rejects with the typed status
 * (ARG / POLICY / OP_WEIGHT / DECL / OVERFLOW / CEILING per the header
 * block above); on EVERY reject *out is fully zeroed. A zeroed view
 * (view->buf == NULL — the codec's rejected-decode marker) is ERR_ARG.
 */
dna_meter_status_t dna_meter_plan_build(const dna_meter_policy_t *pol,
                                        const dna_env_view_t *view,
                                        dna_meter_plan_t *out);

/* ── The transaction meter ─────────────────────────────────────────── */

typedef enum {
    DNA_METER_ST_ZERO      = 0,   /* uninitialized (zeroed memory)       */
    DNA_METER_ST_RESERVED  = 1,
    DNA_METER_ST_ACTIVE    = 2,
    DNA_METER_ST_FINALIZED = 3,
    DNA_METER_ST_ABORTED   = 4
} dna_meter_state_t;

/**
 * One transaction's meter. Create by ZEROING the struct, then reserve.
 * `budget` is BOUND at reserve and BORROWED (caller-owned; it must stay
 * alive and structurally unmodified until the meter reaches a terminal
 * state — the env_wire.h view-borrowing discipline). All other fields
 * are owned copies. Fields are readable for reporting; only the API
 * mutates them.
 */
typedef struct {
    uint8_t  state;                          /* dna_meter_state_t        */
    dna_meter_plan_t plan;                   /* immutable copy           */
    dna_meter_budget_t *budget;              /* BOUND at reserve         */
    uint64_t g_reserved;                     /* == plan.total_ceiling    */
    uint64_t g_consumed;                     /* Σ all charges            */
    uint64_t g_released;                     /* set at finalize          */
    uint64_t dom_dyn[DNA_ENV_MAX_LEGS];      /* dynamic claims, per leg  */
    uint64_t dom_consumed[DNA_ENV_MAX_LEGS];
    uint64_t dom_released[DNA_ENV_MAX_LEGS]; /* set at finalize          */
    uint8_t  effects_charged[DNA_ENV_MAX_LEGS];
} dna_meter_t;

/* Tripwire on careless growth (the env_preflight.h discipline). */
_Static_assert(sizeof(dna_meter_t) <= 4096,
               "dna_meter_t grew past its audited size ceiling");

/**
 * Reserve: build the plan (dna_meter_plan_build), verify the budget
 * (dna_meter_budget_check), then ATOMICALLY take the full global
 * ceiling from bud->global_remaining and each leg's static_units from
 * that leg's domain budget. ZERO -> RESERVED.
 *
 * Rejects: everything plan build rejects, plus ERR_STATE (meter not
 * ZERO), ERR_DOMAIN (budget malformed, or a leg's domain has no budget
 * entry), ERR_GLOBAL_BUDGET / ERR_DOMAIN_BUDGET (exact-fit passes;
 * one unit short rejects).
 *
 * REJECT OUTPUT — two distinct cases (the ZERO-state gate at the top of
 * res_meter.c dna_meter_reserve; pinned by test_res_meter's
 * "ERR_STATE leaves a live meter untouched" byte-compare):
 *   - ERR_STATE fires on a meter that is NOT in the ZERO state, and it
 *     leaves that meter — and any reservation it holds — UNTOUCHED.
 *     Zeroing a RESERVED or ACTIVE meter here would strand the budget
 *     units its reservation took (only finalize/abort may release them);
 *   - every reject PAST the ZERO-state gate re-zeroes the meter. The
 *     meter was in the ZERO state on entry, so the re-zero publishes
 *     nothing and releases nothing.
 * In both cases the budget is byte-identical to entry. This is the ONLY
 * path that debits a reservation — there is no second reserve
 * implementation.
 */
dna_meter_status_t dna_meter_reserve(dna_meter_t *m,
                                     const dna_meter_policy_t *pol,
                                     const dna_env_view_t *view,
                                     dna_meter_budget_t *bud);

/** RESERVED -> ACTIVE; charges the fixed work (header block above),
 *  fully in temporaries. Fits inside the static reservation by
 *  construction; an arithmetic failure is therefore ERR_FAULT, commits
 *  NOTHING, and leaves the meter RESERVED — abort stays available, so
 *  no reservation is ever stranded. The budget is never consulted:
 *  activation cannot need a dynamic claim. */
dna_meter_status_t dna_meter_activate(dna_meter_t *m);

/**
 * Charge one leg's ACTUAL typed-effect result. ACTIVE only.
 * `v` must be a strictly-decoded, non-rejected view (buf != NULL,
 * accepted result_version, count/len inside the codec caps and
 * mutually consistent) — a malformed or zeroed view is ERR_ARG and
 * charges nothing. `domain_id` selects the leg (one leg per domain by
 * envelope construction); no leg -> ERR_DOMAIN; second charge on the
 * same leg -> ERR_STATE. Actual count/bytes above the leg's DECLARED
 * ceilings -> ERR_LIMIT. Crossing the global ceiling -> ERR_CEILING.
 * A dynamic domain claim that the domain budget cannot cover ->
 * ERR_DOMAIN_BUDGET. Every failure leaves meter AND budget unchanged.
 */
dna_meter_status_t dna_meter_charge_effects(dna_meter_t *m,
                                            uint32_t domain_id,
                                            const dna_effect_view_t *v);

/** Charge ONE deterministic mediated read / write to `domain_id`.
 *  ACTIVE only; same failure semantics as charge_effects. These are the
 *  integration points for later seasons — nothing calls them from any
 *  hook this season. */
dna_meter_status_t dna_meter_charge_read(dna_meter_t *m, uint32_t domain_id);
dna_meter_status_t dna_meter_charge_write(dna_meter_t *m, uint32_t domain_id);

/** ACTIVE -> FINALIZED; releases unused units (header block above). */
dna_meter_status_t dna_meter_finalize(dna_meter_t *m);

/** RESERVED|ACTIVE -> ABORTED; restores everything taken. NOTE:
 *  g_released / dom_released stay ZERO on abort (they are finalize's
 *  outputs) — the "reserved == consumed + released" identity is
 *  readable only on a FINALIZED meter; on an ABORTED one the budget
 *  itself is the evidence (restored byte-identically). */
dna_meter_status_t dna_meter_abort(dna_meter_t *m);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DNAC_RES_METER_H */
