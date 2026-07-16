/**
 * @file shielded_domsep.h
 * @brief Domain-separator constants for the dual-mode shielded pool (S0.5).
 *
 * Each constant is `SHA3-512("<string>")[0:8]` interpreted BIG-ENDIAN as a
 * uint64, then verified canonical (`< GOLDILOCKS_P`). This is the exact pattern
 * already used for CONF_COMMIT_DOMSEP_VAL (conf_commit_air.h:60) and
 * CONF_ROOT_DOMSEP_ACC (conf_root_air.h:69) — reproduced here, and checked at
 * runtime by test_shielded_domsep.c so the literals can never silently drift
 * from their derivation strings (ANA HEDEF: KAFADAN KRİPTO YASAK — the value is
 * a function of a named string, not an invented number).
 *
 * Distinctness across ALL shielded DOMSEPs (and vs the two B1 constants) is a
 * REQUIRED security property — a shared tag between the note-commitment, the
 * nullifier CRH, and the nullifier PRF collapses domain separation and enables
 * cross-structure collisions (dm-c4 G5, dm-c1 §4c). The test asserts it.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_DOMSEP_H
#define DNAC_ZK_SHIELDED_DOMSEP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA3-512("DNAC note-commitment v1")[0:8] BE — note-commitment leaf sponge
 * (dm-c1 §4c.1). Verified < p and distinct. */
#define DNAC_DOMSEP_NOTE ((uint64_t)0xf5169f665f710593ULL)

/* SHA3-512("DNAC nullifier-rho v1")[0:8] BE — nullifier CRH ρ=CRH(cm,pos)
 * (dm-c4 §1). MUST differ from DNAC_DOMSEP_NF (domain confusion = Faerie-Gold). */
#define DNAC_DOMSEP_RHO ((uint64_t)0x79b6db2fd9e00ea6ULL)

/* SHA3-512("DNAC nullifier-prf v1")[0:8] BE — nullifier PRF nf=PRF(nk,ρ)
 * (dm-c4 §1, Orchard §5.4.1.10 analog). */
#define DNAC_DOMSEP_NF ((uint64_t)0x1179dd8e919f692aULL)

/* SHA3-512("DNAC shielded-address v1")[0:8] BE — addr_pub=Poseidon2(ak,nk)
 * (dm-c1 condition-3 / parent §1.3). */
#define DNAC_DOMSEP_ADDR ((uint64_t)0x15ffbd845695fb2dULL)

/* SHA3-512("DNAC note-merkle-compress v1")[0:8] BE — RESERVED, NOT absorbed by
 * note_merkle_compress() today.
 *
 * ⚠ HONEST leaf/internal separation status (red-team S0-M1/M2). Plonky3 gets
 * leaf-vs-internal separation STRUCTURALLY: leaves use a hasher H
 * (PaddingFreeSponge) and internal nodes a DIFFERENT compressor C
 * (TruncatedPermutation) — two distinct functions (merkle-tree/src/mmcs.rs). DNAC
 * v1 uses the SAME zero-IV PaddingFreeSponge for BOTH the leaf (note_commit, 8
 * elems incl. DOMSEP_NOTE) and the 2-to-1 node compress (8 child-digest elems, no
 * tag). So a leaf and an internal node can only differ by their preimage content:
 * a leaf's 8th element is DOMSEP_NOTE, an internal node's 8th is a Poseidon2
 * output — collision requires grinding right_child[3] == DOMSEP_NOTE, a ~2^64
 * event at the hash level ALONE. Full 2^128 leaf/internal separation for the
 * note tree is NOT achieved by this constant.
 *
 * ⚠ WHERE IT IS DISCHARGED (red-team C3-HIGH correction): the standalone C3
 * membership gate (conf_membership_air.c) does NOT close this — it takes the tree
 * depth D and the leaf as FREE inputs and never leaf-types level-0. The ~2^64
 * grinding gap is closed STRUCTURALLY at S4 COMPOSITION: (a) D pinned as a
 * compile-time / phase-schedule constant (a note at a wrong depth has no
 * shorter/longer path to prove), and (b) the C1 binding leaf == cm_carry (the
 * leaf is a real note commitment, whose 8th preimage element is DOMSEP_NOTE), so
 * an internal-node digest cannot be substituted for a leaf. C3 STANDALONE
 * provides NO leaf/internal typing — do not assume it does. This constant is
 * reserved for a future tagged-compress variant should S4 choose explicit domain
 * tagging instead. compression.rs:4-11 states only the tree
 * PseudoCompressionFunction contract (non-leaf preimages are compression
 * outputs); it does NOT itself provide leaf/internal typing. */
#define DNAC_DOMSEP_MERKLE ((uint64_t)0x388daa5546d4d985ULL)

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_DOMSEP_H */
